//! Pure, safe DNS reply/reactor truth tables reused by the async engine, with
//! no I/O: reply classification, search plans, server health, and verdicts.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Header-level summary of a DNS reply buffer.
pub struct ReplySummary {
    pub rcode: u8,
    pub ancount: u16,
    pub truncated: bool,
}

/// Classify a reply by its header fields alone. `default_rcode` applies when the
/// buffer is too short; the failover probe passes 0xff so garbage is not success.
pub fn summarize(buf: &[u8], default_rcode: u8) -> ReplySummary {
    ReplySummary {
        rcode: if buf.len() >= 4 { buf[3] & 0x0f } else { default_rcode },
        ancount: if buf.len() >= 8 { u16::from_be_bytes([buf[6], buf[7]]) } else { 0 },
        truncated: is_truncated(buf),
    }
}

pub fn is_truncated(buf: &[u8]) -> bool {
    buf.len() >= 4 && (buf[2] & 0x02) != 0
}

/// Responses and queries too short to compare QIDs are accepted (historical
/// behavior); `is_tcp` skips the 2-byte TCP length prefix on the query.
pub fn qid_matches(resp: &[u8], writebuf: &[u8], is_tcp: bool) -> bool {
    if resp.len() < 2 {
        return true;
    }
    let query_qid_offset = if is_tcp { 2 } else { 0 };
    if writebuf.len() < query_qid_offset + 2 {
        return true;
    }
    let resp_qid = u16::from_be_bytes([resp[0], resp[1]]);
    let query_qid = u16::from_be_bytes([writebuf[query_qid_offset], writebuf[query_qid_offset + 1]]);
    resp_qid == query_qid
}

/// RFC 6761: "localhost" or any name under ".localhost".
pub fn is_localhost(name: &str) -> bool {
    name.eq_ignore_ascii_case("localhost")
        || (name.len() >= 10 && name[name.len()-10..].eq_ignore_ascii_case(".localhost"))
}

/// RFC 7686: case-insensitive byte suffix match (no alloc/UTF-8 validation,
/// never panics on non-ASCII); tolerates a trailing dot and bare "onion".
pub fn is_onion_domain(name: &str) -> bool {
    let b = name.strip_suffix('.').unwrap_or(name).as_bytes();
    b.len() >= 6 && b[b.len() - 6..].eq_ignore_ascii_case(b".onion") || b.eq_ignore_ascii_case(b"onion")
}

/// Ordered names a lookup tries: current name, pending search domains, then a
/// bare-name fallback.
#[derive(Debug, Clone)]
pub struct SearchPlan {
    pub base_name: String,
    pub current: String,
    pub domains: Vec<String>,
}

impl SearchPlan {
    /// Trailing dot (or `no_search`) suppresses search; at or above `ndots` the
    /// bare name is tried first, below it the first search domain is appended.
    pub fn for_search(name_str: &str, ndots: u32, search: &[String], no_search: bool) -> Self {
        let has_trailing_dot = name_str.ends_with('.');
        let name_clean = name_str.strip_suffix('.').unwrap_or(name_str);
        let dot_count = name_clean.chars().filter(|&c| c == '.').count() as u32;

        let mut domains: Vec<String> = Vec::new();
        let mut current = name_clean.to_string();

        if !has_trailing_dot && !no_search && !search.is_empty() {
            if dot_count >= ndots {
                domains = search.to_vec();
            } else {
                domains = search.to_vec();
                let first_domain = domains.remove(0);
                current = format!("{}.{}", name_clean, first_domain);
            }
        }

        SearchPlan { base_name: name_clean.to_string(), current, domains }
    }

    /// Move to the next name; the bare base name is tried exactly once.
    pub fn advance(&mut self) -> Option<String> {
        if !self.domains.is_empty() {
            let next_domain = self.domains.remove(0);
            let new_hostname = format!("{}.{}", self.base_name, next_domain);
            self.current = new_hostname.clone();
            Some(new_hostname)
        } else if self.current != self.base_name && !self.base_name.is_empty() {
            let bare_name = self.base_name.clone();
            self.current = bare_name.clone();
            self.base_name = String::new(); // Prevent infinite recursion
            Some(bare_name)
        } else {
            None
        }
    }

    /// The full ordered candidate list (`current`, then each `advance`).
    pub fn into_names(mut self) -> Vec<String> {
        let mut names = vec![self.current.clone()];
        while let Some(n) = self.advance() {
            names.push(n);
        }
        names
    }
}

pub use libc::{AF_INET, AF_INET6};

/// A / AAAA query rtypes.
pub(crate) const RTYPE_A: u16 = 0x01;
pub(crate) const RTYPE_AAAA: u16 = 0x1c;

/// A server's stable identity on its channel: minted when the server enters the
/// server list and kept across server-list changes for as long as its address
/// and ports stay configured (upstream keeps the `ares_server_t`). It keys the
/// per-server state (`ServerHealth`, cookies, pools) and the channel's
/// endpoints. A distinct type so it cannot be swapped with the try counters and
/// ids it travels beside.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServerId(pub usize);

/// A server-state event for the application's callback (fired by `AsyncClient::notify`).
#[derive(Debug, PartialEq)]
pub enum ReactorAction {
    NotifyServerState { server: ServerId, ok: bool, tcp: bool },
}

/// Reactor-level verdict for a datagram that already passed QID matching.
#[derive(Debug, PartialEq)]
pub enum TaskVerdict {
    /// Server-error failover: resend to `server`, carrying `tries` onto the retry.
    RetryNextServer { server: ServerId, tries: u32 },
    /// Truncated UDP reply: resend over TCP to the same server.
    RetryTcp,
    Deliver,
}

/// Channel flags that change datagram handling (snapshotted per query).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplyPolicy {
    /// ARES_FLAG_IGNTC: accept a truncated UDP reply instead of retrying over TCP.
    pub ignore_tc: bool,
    /// ARES_FLAG_NOCHECKRESP: deliver SERVFAIL/NOTIMP/REFUSED responses.
    pub no_check_resp: bool,
}

/// Datagram policy, in upstream order: TC check (TCP retry, no health update),
/// then rcode failover/health, then delivery. The send budget is monotonic
/// (`nservers * attempts`), so a single server is retried in place.
pub fn on_datagram(
    summary: &ReplySummary,
    server: ServerId,
    is_tcp: bool,
    attempts: u32,
    tries: u32,
    policy: ReplyPolicy,
    health: &mut ServerHealth,
) -> (Vec<ReactorAction>, TaskVerdict) {
    let mut actions = Vec::new();

    // IGNTC: accept a truncated UDP reply as-is. TC is checked before rcode, so
    // an error rcode on a truncated UDP reply still triggers the TCP retry.
    if summary.truncated && !is_tcp && !policy.ignore_tc {
        return (actions, TaskVerdict::RetryTcp);
    }

    // NOCHECKRESP: pass server-error rcodes through (upstream still marks the
    // server good and delivers).
    let is_server_error =
        !policy.no_check_resp && matches!(summary.rcode, 2 | 4 | 5); // SERVFAIL, NOTIMP, REFUSED
    let nservers = health.len();

    if is_server_error {
        actions.push(ReactorAction::NotifyServerState { server, ok: false, tcp: is_tcp });
        health.record_failure(server);
        if (tries as usize + 1) < nservers * attempts as usize {
            let tries = tries + 1;
            return (actions, TaskVerdict::RetryNextServer { server: health.pick_next(), tries });
        }
    } else {
        actions.push(ReactorAction::NotifyServerState { server, ok: true, tcp: is_tcp });
        health.record_success(server);
    }

    (actions, TaskVerdict::Deliver)
}

/// Verdict for an expired (timed-out) task.
#[derive(Debug, PartialEq)]
pub enum TimeoutVerdict {
    Retry { server: ServerId },
    /// Out of attempts: deliver ARES_ETIMEOUT.
    Expire,
}

/// Retry until `attempts` are used up; a timeout counts as a failure and moves
/// to the next server only when there is more than one.
pub fn on_timeout(tries_done: u32, attempts: u32, server: ServerId, health: &mut ServerHealth) -> TimeoutVerdict {
    if tries_done < attempts {
        let server = if health.len() > 1 {
            health.record_failure(server);
            health.pick_next()
        } else {
            server
        };
        TimeoutVerdict::Retry { server }
    } else {
        TimeoutVerdict::Expire
    }
}

/// One server's failure bookkeeping.
#[derive(Clone, Copy, Debug, Default)]
struct ServerStats {
    failures: u32,
    last_failure: Option<Instant>,
    /// A probe to this server is in flight (upstream `probe_pending`).
    probing: bool,
}

/// Per-server failure bookkeeping and selection for failover/probing, keyed by
/// stable [`ServerId`] (like upstream's per-`ares_server_t` state): a server
/// that survives a server-list change keeps its stats. `order` is the current
/// list in config order; mutators on an ID that is no longer current (a lookup
/// from before a change) are no-ops.
#[derive(Default)]
pub struct ServerHealth {
    order: Vec<ServerId>,
    stats: HashMap<ServerId, ServerStats>,
}

impl ServerHealth {
    pub fn len(&self) -> usize {
        self.order.len()
    }

    #[allow(dead_code)] // clippy: len() without is_empty()
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Whether `server` is in the current server list.
    pub fn contains(&self, server: ServerId) -> bool {
        self.stats.contains_key(&server)
    }

    /// Adopt a new server list: kept IDs keep their stats, new ones start
    /// healthy, removed ones are dropped.
    pub fn sync(&mut self, order: &[ServerId]) {
        let mut stats = HashMap::with_capacity(order.len());
        for &id in order {
            stats.insert(id, self.stats.get(&id).copied().unwrap_or_default());
        }
        self.order = order.to_vec();
        self.stats = stats;
    }

    /// `ares_dup`: take `src`'s failure counts position by position (the copy
    /// has the same server list); timestamps and probe marks start cleared.
    pub fn copy_failures_from(&mut self, src: &ServerHealth) {
        for (id, src_id) in self.order.iter().zip(&src.order) {
            let failures = src.stats.get(src_id).map_or(0, |s| s.failures);
            if let Some(s) = self.stats.get_mut(id) {
                s.failures = failures;
            }
        }
    }

    fn failures(&self, server: ServerId) -> u32 {
        self.stats.get(&server).map_or(0, |s| s.failures)
    }

    /// Lowest failure count, tie broken by config order; the first server
    /// (or `ServerId::default()`) when empty.
    pub fn pick_next(&self) -> ServerId {
        let mut best: Option<(u32, ServerId)> = None;
        for &id in &self.order {
            let failures = self.failures(id);
            if best.is_none_or(|(best_f, _)| failures < best_f) {
                best = Some((failures, id));
            }
        }
        best.map(|(_, id)| id).unwrap_or_default()
    }

    /// Lowest-failure server whose failure timestamp expired past `retry_delay`,
    /// excluding `exclude` and servers with a probe already in flight.
    pub fn pick_probe(&self, retry_delay_ms: u64, exclude: ServerId) -> Option<ServerId> {
        let now = Instant::now();
        let retry_delay = Duration::from_millis(retry_delay_ms);
        let mut best: Option<(u32, ServerId)> = None;
        for &id in &self.order {
            let Some(s) = self.stats.get(&id) else { continue };
            if s.failures == 0 || id == exclude || s.probing {
                continue;
            }
            let Some(last_fail) = s.last_failure else { continue };
            if now.duration_since(last_fail) < retry_delay {
                continue; // Not yet expired
            }
            if best.is_none_or(|(best_f, _)| s.failures < best_f) {
                best = Some((s.failures, id));
            }
        }
        best.map(|(_, id)| id)
    }

    /// Count a failure against `server`; `false` when it is no longer current
    /// (server list changed under the query).
    pub fn record_failure(&mut self, server: ServerId) -> bool {
        let Some(s) = self.stats.get_mut(&server) else { return false };
        s.failures += 1;
        s.last_failure = Some(Instant::now());
        true
    }

    /// Mark a probe to `server` as in flight (or finished); unknown IDs are a no-op.
    pub fn set_probing(&mut self, server: ServerId, on: bool) {
        if let Some(s) = self.stats.get_mut(&server) {
            s.probing = on;
        }
    }

    /// Mark `server` healthy; `false` when it is no longer current.
    pub fn record_success(&mut self, server: ServerId) -> bool {
        let Some(s) = self.stats.get_mut(&server) else { return false };
        s.failures = 0;
        s.last_failure = None;
        true
    }
}

#[cfg(test)]
impl ServerHealth {
    /// A fresh healthy list `ServerId(0)..ServerId(n)`.
    pub fn reset(&mut self, n: usize) {
        self.sync(&(0..n).map(ServerId).collect::<Vec<_>>());
    }

    pub fn failure_counts(&self) -> Vec<u32> {
        self.order.iter().map(|&id| self.failures(id)).collect()
    }

    pub fn last_failure_of(&self, server: ServerId) -> Option<Instant> {
        self.stats.get(&server).and_then(|s| s.last_failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_short_buffers() {
        assert_eq!(summarize(&[], 0).rcode, 0);
        assert_eq!(summarize(&[], 0xff).rcode, 0xff);
        let hdr = [0x12, 0x34, 0x80, 0x03, 0, 1, 0, 2];
        let s = summarize(&hdr, 0);
        assert_eq!(s.rcode, 3);
        assert_eq!(s.ancount, 2);
        assert!(!s.truncated);
        assert!(is_truncated(&[0, 0, 0x02, 0]));
    }

    #[test]
    fn qid_match_rules() {
        let query = [0xab, 0xcd, 1, 0];
        assert!(qid_matches(&[0xab, 0xcd, 0, 0], &query, false));
        assert!(!qid_matches(&[0xab, 0xce, 0, 0], &query, false));
        // TCP query carries a 2-byte length prefix before the QID
        let tcp_query = [0x00, 0x04, 0xab, 0xcd, 1, 0];
        assert!(qid_matches(&[0xab, 0xcd, 0, 0], &tcp_query, true));
        assert!(!qid_matches(&[0xab, 0xce, 0, 0], &tcp_query, true));
        // Too-short response or query: accepted (historical behavior)
        assert!(qid_matches(&[0xab], &query, false));
        assert!(qid_matches(&[0xab, 0xcd], &[0x00], false));
    }

    fn reply(rcode: u8, ancount: u16) -> Vec<u8> {
        vec![0, 0, 0x80, rcode, 0, 1, (ancount >> 8) as u8, ancount as u8]
    }

    #[test]
    fn search_plan_low_dots_appends_first_domain() {
        let search = vec!["a.com".to_string(), "b.com".to_string()];
        let mut p = SearchPlan::for_search("www", 1, &search, false);
        assert_eq!(p.current, "www.a.com");
        assert_eq!(p.advance(), Some("www.b.com".to_string()));
        assert_eq!(p.advance(), Some("www".to_string())); // bare-name fallback
        assert_eq!(p.advance(), None);
    }

    #[test]
    fn search_plan_high_dots_tries_bare_first() {
        let search = vec!["a.com".to_string()];
        let mut p = SearchPlan::for_search("x.y", 1, &search, false);
        assert_eq!(p.current, "x.y");
        assert_eq!(p.advance(), Some("x.y.a.com".to_string()));
        // current != base ("x.y.a.com" vs "x.y") -> bare fallback fires once
        assert_eq!(p.advance(), Some("x.y".to_string()));
        assert_eq!(p.advance(), None);
    }

    #[test]
    fn search_plan_trailing_dot_suppresses_search() {
        let search = vec!["a.com".to_string()];
        let mut p = SearchPlan::for_search("www.example.", 1, &search, false);
        assert_eq!(p.current, "www.example");
        assert_eq!(p.advance(), None);
    }

    #[test]
    fn search_plan_no_search_uses_name_as_is() {
        let search = vec!["a.com".to_string()];
        let mut p = SearchPlan::for_search("www", 1, &search, true);
        assert_eq!(p.current, "www");
        assert_eq!(p.advance(), None);
    }

    #[test]
    fn pick_next_lowest_failures_then_index() {
        let mut h = ServerHealth::default();
        assert_eq!(h.pick_next(), ServerId(0)); // empty -> 0
        h.reset(3);
        assert_eq!(h.pick_next(), ServerId(0));
        h.record_failure(ServerId(0));
        assert_eq!(h.pick_next(), ServerId(1));
        h.record_failure(ServerId(1));
        h.record_failure(ServerId(1));
        assert_eq!(h.pick_next(), ServerId(2));
        h.record_success(ServerId(0));
        assert_eq!(h.pick_next(), ServerId(0));
    }

    #[test]
    fn pick_probe_requires_expired_failure() {
        let mut h = ServerHealth::default();
        h.reset(3);
        assert_eq!(h.pick_probe(0, ServerId(0)), None); // no failures anywhere
        h.record_failure(ServerId(1));
        // failure recorded just now: not yet expired for a long delay
        assert_eq!(h.pick_probe(60_000, ServerId(0)), None);
        // zero delay: immediately eligible
        assert_eq!(h.pick_probe(0, ServerId(0)), Some(ServerId(1)));
        // the primary server is excluded
        assert_eq!(h.pick_probe(0, ServerId(1)), None);
        // a server with a probe already in flight is not probed twice
        h.set_probing(ServerId(1), true);
        assert_eq!(h.pick_probe(0, ServerId(0)), None);
        h.set_probing(ServerId(1), false);
        assert_eq!(h.pick_probe(0, ServerId(0)), Some(ServerId(1)));
    }

    #[test]
    fn record_out_of_bounds_is_noop() {
        let mut h = ServerHealth::default();
        h.reset(1);
        assert!(!h.record_failure(ServerId(5)));
        assert!(!h.record_success(ServerId(5)));
        h.set_probing(ServerId(5), true); // no panic
        assert_eq!(h.failure_counts(), vec![0]);
    }

    #[test]
    fn on_datagram_truth_table() {
        let notify_fail = |s| ReactorAction::NotifyServerState { server: s, ok: false, tcp: false };
        let notify_ok = |s| ReactorAction::NotifyServerState { server: s, ok: true, tcp: false };

        // success rcode: notify-ok, reset failures, Deliver
        let mut h = ServerHealth::default();
        h.reset(2);
        h.record_failure(ServerId(0));
        let (a, v) = on_datagram(&summarize(&reply(0, 1), 0), ServerId(0), false, 2, 0, ReplyPolicy::default(), &mut h);
        assert_eq!(v, TaskVerdict::Deliver);
        assert_eq!(a, vec![notify_ok(ServerId(0))]);
        assert_eq!(h.failure_counts()[0], 0, "success resets failures");

        // SERVFAIL, 2 servers: fail over to the next server, notify fail.
        let mut h = ServerHealth::default();
        h.reset(2);
        let (a, v) = on_datagram(&summarize(&reply(2, 0), 0), ServerId(0), false, 2, 0, ReplyPolicy::default(), &mut h);
        assert_eq!(v, TaskVerdict::RetryNextServer { server: ServerId(1), tries: 1 });
        assert_eq!(a, vec![notify_fail(ServerId(0))]);
        assert_eq!(h.failure_counts()[0], 1);

        // SERVFAIL, single server: retried in place (pick_next returns the same
        // server), failure recorded, still notified.
        let mut h = ServerHealth::default();
        h.reset(1);
        let (a, v) = on_datagram(&summarize(&reply(2, 0), 0), ServerId(0), false, 2, 0, ReplyPolicy::default(), &mut h);
        assert_eq!(v, TaskVerdict::RetryNextServer { server: ServerId(0), tries: 1 });
        assert_eq!(a, vec![notify_fail(ServerId(0))]);
        assert_eq!(h.failure_counts()[0], 1);

        // budget exhausted: tries+1 >= nservers*attempts falls through to Deliver
        let mut h = ServerHealth::default();
        h.reset(2);
        let (_, v) = on_datagram(&summarize(&reply(2, 0), 0), ServerId(0), false, 2, 3, ReplyPolicy::default(), &mut h);
        assert_eq!(v, TaskVerdict::Deliver);

        // TC flag on UDP: RetryTcp; already-TCP never TC-retries.
        let tc = [0u8, 0, 0x02, 0, 0, 1, 0, 1];
        let mut h = ServerHealth::default();
        h.reset(1);
        let (_, v) = on_datagram(&summarize(&tc, 0), ServerId(0), false, 2, 0, ReplyPolicy::default(), &mut h);
        assert_eq!(v, TaskVerdict::RetryTcp);
        let (_, v) = on_datagram(&summarize(&tc, 0), ServerId(0), true, 2, 0, ReplyPolicy::default(), &mut h);
        assert_eq!(v, TaskVerdict::Deliver);
    }

    #[test]
    fn on_datagram_honors_igntc_and_nocheckresp() {
        let tc = [0u8, 0, 0x02, 0, 0, 1, 0, 1];

        // IGNTC: deliver the truncated UDP reply instead of retrying over TCP.
        let mut h = ServerHealth::default();
        h.reset(1);
        let (_, v) = on_datagram(
            &summarize(&tc, 0),
            ServerId(0),
            false,
            2,
            0,
            ReplyPolicy { ignore_tc: true, no_check_resp: false },
            &mut h,
        );
        assert_eq!(v, TaskVerdict::Deliver);

        // TC is checked before the rcode: a truncated SERVFAIL UDP reply goes
        // to TCP and must not mark the server good or bad.
        let tc_servfail = [0u8, 0, 0x02, 2, 0, 1, 0, 0];
        let mut h = ServerHealth::default();
        h.reset(1);
        let (a, v) = on_datagram(
            &summarize(&tc_servfail, 0),
            ServerId(0),
            false,
            2,
            0,
            ReplyPolicy::default(),
            &mut h,
        );
        assert_eq!(v, TaskVerdict::RetryTcp);
        assert!(a.is_empty());
        assert_eq!(h.failure_counts()[0], 0);
        assert_eq!(h.last_failure_of(ServerId(0)), None);

        // NOCHECKRESP: deliver SERVFAIL/NOTIMP/REFUSED, notifying success
        // (upstream's pass-through path marks the server good).
        for rcode in [2u8, 4, 5] {
            let mut h = ServerHealth::default();
            h.reset(2);
            let (a, v) = on_datagram(
                &summarize(&reply(rcode, 0), 0),
                ServerId(0),
                false,
                2,
                0,
                ReplyPolicy { ignore_tc: false, no_check_resp: true },
                &mut h,
            );
            assert_eq!(v, TaskVerdict::Deliver);
            assert_eq!(
                a,
                vec![ReactorAction::NotifyServerState { server: ServerId(0), ok: true, tcp: false }]
            );
            assert_eq!(h.failure_counts()[0], 0);
        }
    }

    #[test]
    fn on_timeout_policy() {
        // retries left, multiple servers: count a failure, move on
        let mut h = ServerHealth::default();
        h.reset(2);
        assert_eq!(on_timeout(1, 3, ServerId(0), &mut h), TimeoutVerdict::Retry { server: ServerId(1) });
        assert_eq!(h.failure_counts()[0], 1);
        // retries left, single server: same server, no failure counted
        let mut h = ServerHealth::default();
        h.reset(1);
        assert_eq!(on_timeout(1, 3, ServerId(0), &mut h), TimeoutVerdict::Retry { server: ServerId(0) });
        assert_eq!(h.failure_counts()[0], 0);
        // out of attempts
        assert_eq!(on_timeout(3, 3, ServerId(0), &mut h), TimeoutVerdict::Expire);
    }

    #[test]
    fn matches_onion_domains() {
        assert!(is_onion_domain("dontleak.onion"));
        assert!(is_onion_domain("DontLeak.ONION"));   // case-insensitive
        assert!(is_onion_domain("x.onion."));          // trailing-dot FQDN form
        assert!(is_onion_domain("onion"));             // bare single label
    }

    #[test]
    fn rejects_non_onion_domains() {
        assert!(!is_onion_domain("example.com"));
        assert!(!is_onion_domain("notonion"));          // suffix without the dot
        assert!(!is_onion_domain("onion.example.com")); // .onion not at the end
        assert!(!is_onion_domain(""));
    }

    #[test]
    fn non_ascii_names_do_not_panic() {
        // These byte sequences are exactly what made the old `name[len-6..]`
        // slice panic (len-6 lands inside a multibyte UTF-8 code point).
        assert!(!is_onion_domain("😀😀"));
        assert!(!is_onion_domain("café"));
        assert!(!is_onion_domain("日本語.example"));
        // A non-ASCII name that still ends in .onion is matched without panic.
        assert!(is_onion_domain("café.onion"));
    }

    #[test]
    fn localhost_names() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("LOCALHOST"));
        assert!(is_localhost("foo.localhost"));
        assert!(!is_localhost("localhost.example.com"));
        assert!(!is_localhost("notlocalhost"));
    }
}
