//! The query cache: a TTL-bounded map of raw DNS reply bytes keyed by
//! `(qname, qtype)`. Shared (via `Rc<RefCell<_>>`) between the async engine
//! (gethostbyname) and the classic reactor (the dnsrec post-delivery hook), so
//! both read/write one store. Neutral — no `Client`/`Transport`/FFI.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::core::response::ParsedResponse;

/// TTL-bounded reply cache. `max_ttl == 0` disables it.
#[derive(Default)]
pub struct QueryCache {
    map: HashMap<(String, u16), (Vec<u8>, Instant)>,
    max_ttl: u32,
}

impl QueryCache {
    pub fn set_max_ttl(&mut self, ttl: u32) {
        self.max_ttl = ttl;
    }
    pub fn max_ttl(&self) -> u32 {
        self.max_ttl
    }
    pub fn enabled(&self) -> bool {
        self.max_ttl > 0
    }

    /// Read a cached reply for `(name, qtype)`, evicting an expired entry.
    /// `None` when the cache is disabled, missing the key, or the entry expired.
    pub fn get(&mut self, name: &str, qtype: u16, now: Instant) -> Option<Vec<u8>> {
        if self.max_ttl == 0 {
            return None;
        }
        let key = (name.to_string(), qtype);
        match self.map.get(&key) {
            Some((buf, expires_at)) if now < *expires_at => Some(buf.clone()),
            Some(_) => {
                self.map.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Store one reply under every name, TTL-clamped to `min_item_ttl` and the
    /// channel limit (a no-op when the clamped TTL is 0 / the cache is disabled).
    pub fn store_names(&mut self, names: Vec<String>, rtype: u16, min_item_ttl: u32, buf: &[u8], now: Instant) {
        let ttl = std::cmp::min(min_item_ttl, self.max_ttl);
        if ttl > 0 {
            let expires = now + Duration::from_secs(ttl as u64);
            for name in names {
                self.map.insert((name, rtype), (buf.to_vec(), expires));
            }
        }
    }

    /// Store a reply keyed by its own `(qname, qtype)`, clamped to the minimum
    /// answer TTL. `from_buf` only parses a non-empty answer section, so the
    /// historical `ancount > 0` guard is implied.
    pub fn store_reply(&mut self, buf: &[u8], now: Instant) {
        if let Ok(parsed) = ParsedResponse::from_buf(buf) {
            let qname = parsed.query.name.join(".");
            let qtype = parsed.query.qtype;
            let min_ttl = parsed.answers.iter().map(|a| a.ttl).min().unwrap_or(0);
            self.store_names(vec![qname], qtype, min_ttl, buf, now);
        }
    }
}
