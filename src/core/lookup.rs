//! Pure query-lifecycle logic shared by every lookup flow.
//!
//! This module is the single home for the DNS query state-machine building
//! blocks: reply classification ([`summarize`], [`qid_matches`],
//! [`extract_tcp_frame`]), name classification ([`is_localhost`],
//! [`is_onion_domain`]), and per-server failure tracking / server selection
//! ([`ServerHealth`]). The per-flow state machines (search, gethostbyname,
//! getaddrinfo) build on these and live here too. Everything in this module
//! is safe pure Rust — the FFI layer only converts C arguments and executes
//! the decisions made here.

use std::ffi::c_int;
use std::time::{Duration, Instant};

use crate::ffi::error::{
    ARES_ENODATA, ARES_ENOTFOUND, ARES_ENOTIMP, ARES_EREFUSED, ARES_ESERVFAIL, ARES_ETIMEOUT,
};

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

/// Pop one complete length-prefixed DNS message off a TCP receive buffer,
/// or `None` if a full frame hasn't accumulated yet.
pub fn extract_tcp_frame(rbuf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if rbuf.len() < 2 {
        return None;
    }
    let payload_len = u16::from_be_bytes([rbuf[0], rbuf[1]]) as usize;
    if rbuf.len() < 2 + payload_len {
        return None;
    }
    let msg = rbuf[2..2 + payload_len].to_vec();
    rbuf.drain(..2 + payload_len);
    Some(msg)
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

/// Input to a lookup state machine: a raw DNS reply or an I/O-level error
/// status (timeout, refused connection, cancellation...).
pub enum LookupEvent<'a> {
    Reply(&'a [u8]),
    Error(c_int),
}

/// What the search state machine wants done next. The FFI executor performs
/// the action (enqueue a query / call the C callback) — the machine only
/// decides.
#[derive(Debug, PartialEq)]
pub enum SearchAction {
    /// Issue the same query for this name.
    Send(String),
    /// Deliver the current reply buffer to the caller as success.
    DeliverSuccess,
    /// Deliver failure with this status.
    DeliverFail(c_int),
}

/// State machine for ares_search / ares_search_dnsrec: iterate the search
/// plan on NXDOMAIN/NODATA/timeout (and, for the dnsrec flavor only, on
/// SERVFAIL/NOTIMP/REFUSED), deliver otherwise. NXDOMAIN after an earlier
/// empty answer is reported as ENODATA, matching upstream.
#[derive(Debug)]
pub struct SearchSm {
    pub plan: SearchPlan,
    pub last_error: c_int,
    pub had_nodata: bool,
    /// dnsrec flavor also walks the search plan on server errors.
    pub retry_server_error: bool,
}

impl SearchSm {
    pub fn new(plan: SearchPlan, retry_server_error: bool) -> Self {
        SearchSm { plan, last_error: ARES_ENODATA, had_nodata: false, retry_server_error }
    }

    pub fn step(&mut self, ev: LookupEvent<'_>) -> SearchAction {
        match ev {
            LookupEvent::Reply(buf) => {
                let summary = summarize(buf, 0);
                match summary.rcode {
                    3 => { // NXDOMAIN
                        self.last_error = ARES_ENOTFOUND;
                    }
                    2 | 4 | 5 => { // SERVFAIL, NOTIMP, REFUSED
                        self.last_error = match summary.rcode {
                            2 => ARES_ESERVFAIL,
                            4 => ARES_ENOTIMP,
                            _ => ARES_EREFUSED,
                        };
                    }
                    0 => {
                        if summary.ancount == 0 {
                            self.had_nodata = true;
                            self.last_error = ARES_ENODATA;
                        } else {
                            // Success — deliver the raw response
                            return SearchAction::DeliverSuccess;
                        }
                    }
                    _ => {
                        self.had_nodata = true;
                        self.last_error = ARES_ENODATA;
                    }
                }
            }
            LookupEvent::Error(status) => {
                self.last_error = status;
            }
        }

        // Search domain iteration: on NXDOMAIN/ENODATA/ETIMEOUT — and for the
        // dnsrec flavor also on server errors — try the next name in the plan.
        let iterate = matches!(self.last_error, ARES_ENOTFOUND | ARES_ENODATA | ARES_ETIMEOUT)
            || (self.retry_server_error
                && matches!(self.last_error, ARES_ESERVFAIL | ARES_EREFUSED | ARES_ENOTIMP));
        if iterate {
            if let Some(next_name) = self.plan.advance() {
                return SearchAction::Send(next_name);
            }
        }

        // Finalize
        let mut status = self.last_error;
        if self.had_nodata && status == ARES_ENOTFOUND {
            status = ARES_ENODATA;
        }
        SearchAction::DeliverFail(status)
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

    #[test]
    fn tcp_frame_extraction() {
        let mut rbuf = vec![0x00, 0x03, 1, 2, 3, 0x00];
        assert_eq!(extract_tcp_frame(&mut rbuf), Some(vec![1, 2, 3]));
        assert_eq!(rbuf, vec![0x00]); // partial next frame stays buffered
        assert_eq!(extract_tcp_frame(&mut rbuf), None);
        rbuf.push(0x02);
        assert_eq!(extract_tcp_frame(&mut rbuf), None); // length known, payload missing
        rbuf.extend_from_slice(&[9, 8]);
        assert_eq!(extract_tcp_frame(&mut rbuf), Some(vec![9, 8]));
        assert!(rbuf.is_empty());
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
    fn search_sm_iterates_then_enodata_rewrite() {
        let search = vec!["a.com".to_string()];
        let mut sm = SearchSm::new(SearchPlan::for_search("www", 1, &search), false);
        // empty answer -> NODATA -> bare-name fallback
        assert_eq!(sm.step(LookupEvent::Reply(&reply(0, 0))), SearchAction::Send("www".into()));
        // NXDOMAIN after a NODATA earlier in the walk finalizes as ENODATA
        assert_eq!(sm.step(LookupEvent::Reply(&reply(3, 0))), SearchAction::DeliverFail(ARES_ENODATA));
    }

    #[test]
    fn search_sm_server_error_only_iterates_for_dnsrec() {
        let search = vec!["a.com".to_string()];
        let plan = SearchPlan::for_search("www", 1, &search);
        let mut plain = SearchSm::new(plan.clone(), false);
        assert_eq!(plain.step(LookupEvent::Reply(&reply(2, 0))), SearchAction::DeliverFail(ARES_ESERVFAIL));
        let mut dnsrec = SearchSm::new(plan, true);
        assert_eq!(dnsrec.step(LookupEvent::Reply(&reply(2, 0))), SearchAction::Send("www".into()));
    }

    #[test]
    fn search_sm_success_and_timeout() {
        let mut sm = SearchSm::new(SearchPlan::for_search("www.example.", 1, &[]), false);
        assert_eq!(sm.step(LookupEvent::Reply(&reply(0, 1))), SearchAction::DeliverSuccess);
        assert_eq!(sm.step(LookupEvent::Error(ARES_ETIMEOUT)), SearchAction::DeliverFail(ARES_ETIMEOUT));
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
