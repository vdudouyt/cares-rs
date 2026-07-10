//! The neutral DNS-reply/reactor truth tables the async engine reuses: pure,
//! safe Rust with no I/O. The executor (`async_runtime::executor`) drives one query's
//! socket lifecycle and consults these for its verdicts.
//!
//! # Map
//! - [`summarize`] / [`qid_matches`] — DNS reply header classification and
//!   transaction-ID matching
//! - [`is_localhost`] / [`is_onion_domain`] — special-name classification
//! - [`SearchPlan`] — the search-domain iteration for ares_search / getaddrinfo
//!   (ndots threshold, bare-name fallback), via [`SearchPlan::for_search`]
//!   (gethostbyname inlines its own simpler walk in `core::hostbyname`)
//! - [`ServerHealth`] — per-server failure accounting and the
//!   lowest-failures-first server selection for failover and probing
//! - [`on_datagram`] → [`TaskVerdict`] (failover / TC retry / deliver) and
//!   [`on_timeout`] → [`TimeoutVerdict`] (retry / expire): the per-query
//!   reactor policy `resolve_query` applies.

use std::time::{Duration, Instant};

/// Header-level summary of a DNS reply buffer.
pub struct ReplySummary {
    pub rcode: u8,
    pub ancount: u16,
    pub truncated: bool,
}

/// Classify a reply buffer by its DNS header fields alone.
/// `default_rcode` is used when the buffer is too short to carry an rcode
/// (regular flows pass 0; the failover probe passes 0xff so a garbage reply
/// is not mistaken for success).
pub fn summarize(buf: &[u8], default_rcode: u8) -> ReplySummary {
    ReplySummary {
        rcode: if buf.len() >= 4 { buf[3] & 0x0f } else { default_rcode },
        ancount: if buf.len() >= 8 { u16::from_be_bytes([buf[6], buf[7]]) } else { 0 },
        truncated: is_truncated(buf),
    }
}

/// TC (truncation) flag from the DNS header.
pub fn is_truncated(buf: &[u8]) -> bool {
    buf.len() >= 4 && (buf[2] & 0x02) != 0
}

/// Does the response transaction ID match the query's? Responses too short to
/// carry a QID (or queries too short to compare against) are accepted, matching
/// the historical behavior. `is_tcp` skips the 2-byte TCP length prefix on the
/// query buffer.
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

/// RFC 6761 section 6.3: "localhost" or any name under ".localhost"
pub fn is_localhost(name: &str) -> bool {
    name.eq_ignore_ascii_case("localhost")
        || (name.len() >= 10 && name[name.len()-10..].eq_ignore_ascii_case(".localhost"))
}

/// RFC 7686: does `name` name a `.onion` domain? Case-insensitive ASCII suffix
/// match on bytes (no alloc, no UTF-8 validation, never panics on non-ASCII).
/// Tolerates a trailing-dot FQDN and a bare "onion". Mirrors upstream c-ares.
pub fn is_onion_domain(name: &str) -> bool {
    let b = name.strip_suffix('.').unwrap_or(name).as_bytes();
    b.len() >= 6 && b[b.len() - 6..].eq_ignore_ascii_case(b".onion") || b.eq_ignore_ascii_case(b"onion")
}

/// The sequence of names a lookup tries: the current query name, the search
/// domains still to append, and a final bare-name fallback. This is the one
/// implementation of the domain-iteration logic that used to be duplicated
/// across the search/gethostbyname/getaddrinfo callbacks.
#[derive(Debug, Clone)]
pub struct SearchPlan {
    pub base_name: String,
    pub current: String,
    pub domains: Vec<String>,
}

impl SearchPlan {
    /// ares_search / ares_search_dnsrec style plan: a trailing dot suppresses
    /// search entirely; at or above `ndots` the bare name is tried first with
    /// the search domains as fallback; below `ndots` the first search domain
    /// is appended up front and the bare name becomes the last resort.
    pub fn for_search(name_str: &str, ndots: u32, search: &[String]) -> Self {
        let has_trailing_dot = name_str.ends_with('.');
        let name_clean = name_str.strip_suffix('.').unwrap_or(name_str);
        let dot_count = name_clean.chars().filter(|&c| c == '.').count() as u32;

        let mut domains: Vec<String> = Vec::new();
        let mut current = name_clean.to_string();

        if !has_trailing_dot && !search.is_empty() {
            if dot_count >= ndots {
                // High dots: try bare name first, then search domains as fallback
                domains = search.to_vec();
            } else {
                // Low dots: try search domains first, then bare name as fallback
                domains = search.to_vec();
                let first_domain = domains.remove(0);
                current = format!("{}.{}", name_clean, first_domain);
            }
        }

        SearchPlan { base_name: name_clean.to_string(), current, domains }
    }

    /// Move to the next name to try: the next search domain appended to the
    /// base name, then — exactly once — the bare base name, then exhaustion.
    pub fn advance(&mut self) -> Option<String> {
        if !self.domains.is_empty() {
            let next_domain = self.domains.remove(0);
            let new_hostname = format!("{}.{}", self.base_name, next_domain);
            self.current = new_hostname.clone();
            Some(new_hostname)
        } else if self.current != self.base_name && !self.base_name.is_empty() {
            // Try bare name as fallback
            let bare_name = self.base_name.clone();
            self.current = bare_name.clone();
            self.base_name = String::new(); // Prevent infinite recursion
            Some(bare_name)
        } else {
            None
        }
    }
}

pub use libc::{AF_INET, AF_INET6, AF_UNSPEC};

/// A / AAAA DNS record types (the query rtypes the async lifecycles build).
pub(crate) const RTYPE_A: u16 = 0x01;
pub(crate) const RTYPE_AAAA: u16 = 0x1c;

/// Reactor-level side effect (executed by ares_process).
#[derive(Debug, PartialEq)]
pub enum ReactorAction {
    NotifyServerState { server: usize, ok: bool, tcp: bool },
}

/// Reactor-level verdict for a datagram that already passed QID matching.
#[derive(Debug, PartialEq)]
pub enum TaskVerdict {
    /// SERVFAIL/NOTIMP/REFUSED failover: resend the same payload to this
    /// server; `tries` is the failover count to carry onto the retry task.
    RetryNextServer { server: usize, tries: u32 },
    /// Truncated UDP reply: resend the same payload over TCP to the same server.
    RetryTcp,
    /// Hand the reply to the task's callback.
    Deliver,
}

/// The process-level decisions for one received datagram, in the historical
/// order: rcode-based failover, server-health bookkeeping + notifications,
/// then the TC check. A failover retry preempts the TC check; everything else
/// falls through to it. `tries` is the task's failover count so far — the
/// budget is monotonic (`nservers * attempts` total sends), so a single server
/// is retried in place rather than skipped.
pub fn on_datagram(
    summary: &ReplySummary,
    server: usize,
    is_tcp: bool,
    attempts: u32,
    tries: u32,
    health: &mut ServerHealth,
) -> (Vec<ReactorAction>, TaskVerdict) {
    let mut actions = Vec::new();
    let is_server_error = matches!(summary.rcode, 2 | 4 | 5); // SERVFAIL, NOTIMP, REFUSED
    let nservers = health.len();

    if is_server_error {
        actions.push(ReactorAction::NotifyServerState { server, ok: false, tcp: is_tcp });
        health.record_failure(server);
        if (tries as usize + 1) < nservers * attempts as usize {
            let tries = tries + 1;
            return (actions, TaskVerdict::RetryNextServer { server: health.pick_next(), tries });
        }
    } else {
        // Success response — notify + reset failure counters
        actions.push(ReactorAction::NotifyServerState { server, ok: true, tcp: is_tcp });
        health.record_success(server);
    }

    if summary.truncated && !is_tcp {
        return (actions, TaskVerdict::RetryTcp);
    }
    (actions, TaskVerdict::Deliver)
}

/// Verdict for an expired (timed-out) task.
#[derive(Debug, PartialEq)]
pub enum TimeoutVerdict {
    /// Resend the same payload to this server (tries_done already counted).
    Retry { server: usize },
    /// Out of attempts: deliver ARES_ETIMEOUT.
    Expire,
}

/// Timeout policy: retry until `attempts` tries are used up, moving to the
/// next server (and counting a failure) only when there is more than one.
pub fn on_timeout(tries_done: u32, attempts: u32, server: usize, health: &mut ServerHealth) -> TimeoutVerdict {
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

/// Per-server failure bookkeeping and server selection for failover/probing.
/// Indices track `config.nameservers`; every mutator is bounds-checked so a
/// server list shrinking under an in-flight query cannot cause a panic.
#[derive(Default)]
pub struct ServerHealth {
    pub failures: Vec<u32>,
    pub last_failure: Vec<Option<Instant>>,
}

impl ServerHealth {
    /// Number of tracked servers.
    pub fn len(&self) -> usize {
        self.failures.len()
    }

    #[allow(dead_code)] // clippy: len() without is_empty()
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }

    /// Re-size for a fresh server list of `n` entries, all healthy.
    pub fn reset(&mut self, n: usize) {
        self.failures = vec![0; n];
        self.last_failure = vec![None; n];
    }

    pub fn clear(&mut self) {
        self.failures.clear();
        self.last_failure.clear();
    }

    /// Pick the best server to try next based on failure counts.
    /// Returns the server index with lowest (failure_count, original_index).
    pub fn pick_next(&self) -> usize {
        let mut best: Option<(u32, usize)> = None;
        for (i, &failures) in self.failures.iter().enumerate() {
            match best {
                None => best = Some((failures, i)),
                Some((best_f, best_i)) => {
                    if failures < best_f || (failures == best_f && i < best_i) {
                        best = Some((failures, i));
                    }
                }
            }
        }
        best.map(|(_, i)| i).unwrap_or(0)
    }

    /// Pick a server eligible for probing: has failures, failure timestamp expired past retry_delay.
    /// Returns the server with lowest (failure_count, index) among eligible, excluding `exclude_server`.
    pub fn pick_probe(&self, retry_delay_ms: u64, exclude_server: usize) -> Option<usize> {
        let now = Instant::now();
        let retry_delay = Duration::from_millis(retry_delay_ms);
        let mut best: Option<(u32, usize)> = None;
        for (i, &failures) in self.failures.iter().enumerate() {
            if failures == 0 || i == exclude_server {
                continue;
            }
            let Some(Some(last_fail)) = self.last_failure.get(i) else { continue };
            if now.duration_since(*last_fail) < retry_delay {
                continue; // Not yet expired
            }
            match best {
                None => best = Some((failures, i)),
                Some((bf, bi)) => {
                    if failures < bf || (failures == bf && i < bi) {
                        best = Some((failures, i));
                    }
                }
            }
        }
        best.map(|(_, i)| i)
    }

    /// Count a failed exchange against `idx`. Returns false when `idx` is out
    /// of bounds (server list changed under the query).
    pub fn record_failure(&mut self, idx: usize) -> bool {
        if idx >= self.failures.len() {
            return false;
        }
        self.failures[idx] += 1;
        if idx < self.last_failure.len() {
            self.last_failure[idx] = Some(Instant::now());
        }
        true
    }

    /// Refresh only the failure timestamp (probe error path: the probe itself
    /// failing is not counted as an additional server failure).
    pub fn record_failure_time(&mut self, idx: usize) {
        if idx < self.last_failure.len() {
            self.last_failure[idx] = Some(Instant::now());
        }
    }

    /// Mark `idx` healthy again. Returns false when `idx` is out of bounds.
    pub fn record_success(&mut self, idx: usize) -> bool {
        if idx >= self.failures.len() {
            return false;
        }
        self.failures[idx] = 0;
        if idx < self.last_failure.len() {
            self.last_failure[idx] = None;
        }
        true
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
        let mut p = SearchPlan::for_search("www", 1, &search);
        assert_eq!(p.current, "www.a.com");
        assert_eq!(p.advance(), Some("www.b.com".to_string()));
        assert_eq!(p.advance(), Some("www".to_string())); // bare-name fallback
        assert_eq!(p.advance(), None);
    }

    #[test]
    fn search_plan_high_dots_tries_bare_first() {
        let search = vec!["a.com".to_string()];
        let mut p = SearchPlan::for_search("x.y", 1, &search);
        assert_eq!(p.current, "x.y");
        assert_eq!(p.advance(), Some("x.y.a.com".to_string()));
        // current != base ("x.y.a.com" vs "x.y") -> bare fallback fires once
        assert_eq!(p.advance(), Some("x.y".to_string()));
        assert_eq!(p.advance(), None);
    }

    #[test]
    fn search_plan_trailing_dot_suppresses_search() {
        let search = vec!["a.com".to_string()];
        let mut p = SearchPlan::for_search("www.example.", 1, &search);
        assert_eq!(p.current, "www.example");
        assert_eq!(p.advance(), None);
    }


    #[test]
    fn pick_next_lowest_failures_then_index() {
        let mut h = ServerHealth::default();
        assert_eq!(h.pick_next(), 0); // empty -> 0
        h.reset(3);
        assert_eq!(h.pick_next(), 0);
        h.record_failure(0);
        assert_eq!(h.pick_next(), 1);
        h.record_failure(1);
        h.record_failure(1);
        assert_eq!(h.pick_next(), 2);
        h.record_success(0);
        assert_eq!(h.pick_next(), 0);
    }

    #[test]
    fn pick_probe_requires_expired_failure() {
        let mut h = ServerHealth::default();
        h.reset(3);
        assert_eq!(h.pick_probe(0, 0), None); // no failures anywhere
        h.record_failure(1);
        // failure recorded just now: not yet expired for a long delay
        assert_eq!(h.pick_probe(60_000, 0), None);
        // zero delay: immediately eligible
        assert_eq!(h.pick_probe(0, 0), Some(1));
        // the primary server is excluded
        assert_eq!(h.pick_probe(0, 1), None);
    }

    #[test]
    fn record_out_of_bounds_is_noop() {
        let mut h = ServerHealth::default();
        h.reset(1);
        assert!(!h.record_failure(5));
        assert!(!h.record_success(5));
        h.record_failure_time(5); // no panic
        assert_eq!(h.failures, vec![0]);
    }

    #[test]
    fn on_datagram_truth_table() {
        let notify_fail = |s| ReactorAction::NotifyServerState { server: s, ok: false, tcp: false };
        let notify_ok = |s| ReactorAction::NotifyServerState { server: s, ok: true, tcp: false };

        // success rcode: notify-ok, reset failures, Deliver
        let mut h = ServerHealth::default();
        h.reset(2);
        h.record_failure(0);
        let (a, v) = on_datagram(&summarize(&reply(0, 1), 0), 0, false, 2, 0, &mut h);
        assert_eq!(v, TaskVerdict::Deliver);
        assert_eq!(a, vec![notify_ok(0)]);
        assert_eq!(h.failures[0], 0, "success resets failures");

        // SERVFAIL, 2 servers: fail over to the next server, notify fail.
        let mut h = ServerHealth::default();
        h.reset(2);
        let (a, v) = on_datagram(&summarize(&reply(2, 0), 0), 0, false, 2, 0, &mut h);
        assert_eq!(v, TaskVerdict::RetryNextServer { server: 1, tries: 1 });
        assert_eq!(a, vec![notify_fail(0)]);
        assert_eq!(h.failures[0], 1);

        // SERVFAIL, single server: retried in place (pick_next returns the same
        // server), failure recorded, still notified.
        let mut h = ServerHealth::default();
        h.reset(1);
        let (a, v) = on_datagram(&summarize(&reply(2, 0), 0), 0, false, 2, 0, &mut h);
        assert_eq!(v, TaskVerdict::RetryNextServer { server: 0, tries: 1 });
        assert_eq!(a, vec![notify_fail(0)]);
        assert_eq!(h.failures[0], 1);

        // budget exhausted: tries+1 >= nservers*attempts falls through to Deliver
        let mut h = ServerHealth::default();
        h.reset(2);
        let (_, v) = on_datagram(&summarize(&reply(2, 0), 0), 0, false, 2, 3, &mut h);
        assert_eq!(v, TaskVerdict::Deliver);

        // TC flag on UDP: RetryTcp; already-TCP never TC-retries.
        let tc = [0u8, 0, 0x02, 0, 0, 1, 0, 1];
        let mut h = ServerHealth::default();
        h.reset(1);
        let (_, v) = on_datagram(&summarize(&tc, 0), 0, false, 2, 0, &mut h);
        assert_eq!(v, TaskVerdict::RetryTcp);
        let (_, v) = on_datagram(&summarize(&tc, 0), 0, true, 2, 0, &mut h);
        assert_eq!(v, TaskVerdict::Deliver);
    }

    #[test]
    fn on_timeout_policy() {
        // retries left, multiple servers: count a failure, move on
        let mut h = ServerHealth::default();
        h.reset(2);
        assert_eq!(on_timeout(1, 3, 0, &mut h), TimeoutVerdict::Retry { server: 1 });
        assert_eq!(h.failures[0], 1);
        // retries left, single server: same server, no failure counted
        let mut h = ServerHealth::default();
        h.reset(1);
        assert_eq!(on_timeout(1, 3, 0, &mut h), TimeoutVerdict::Retry { server: 0 });
        assert_eq!(h.failures[0], 0);
        // out of attempts
        assert_eq!(on_timeout(3, 3, 0, &mut h), TimeoutVerdict::Expire);
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
