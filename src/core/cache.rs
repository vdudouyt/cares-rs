//! The query cache: a TTL-bounded map of raw DNS reply bytes keyed by the
//! upstream qcache tuple (`opcode`, RD/CD flags, qname, qtype, qclass). Shared
//! (via `Rc<RefCell<_>>`) between the async engine (gethostbyname) and the
//! classic reactor (the dnsrec post-delivery hook), so both read/write one
//! store. Neutral — no `Client`/`Transport`/FFI.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::core::response::ParsedResponse;

/// Upstream `ares_qcache_calc_key` tuple: opcode + RD/CD + each question's
/// (type, class, name). Kept as separate fields so a CHAOS, CD or NORECURSE
/// query can never collide with an ordinary IN/RD entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub opcode: u16,
    pub rd: bool,
    pub cd: bool,
}

impl CacheKey {
    /// Build a key; the trailing dot is presentation-only (upstream strips it
    /// before hashing) so `example.com.` and `example.com` share an entry.
    pub fn new(name: &str, qtype: u16, qclass: u16, opcode: u16, rd: bool, cd: bool) -> Self {
        CacheKey {
            name: name.strip_suffix('.').unwrap_or(name).to_string(),
            qtype,
            qclass,
            opcode,
            rd,
            cd,
        }
    }

    /// The same question/flags with a different (search-candidate) name.
    pub fn with_name(&self, name: &str) -> Self {
        CacheKey::new(name, self.qtype, self.qclass, self.opcode, self.rd, self.cd)
    }
}

/// TTL-bounded reply cache. `max_ttl == 0` disables it.
#[derive(Default)]
pub struct QueryCache {
    map: HashMap<CacheKey, (Vec<u8>, Instant)>,
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

    /// Drop every cached reply (ares_reinit flushes the query cache).
    pub fn flush(&mut self) {
        self.map.clear();
    }

    /// Read a cached reply for `key`, evicting an expired entry.
    /// `None` when the cache is disabled, missing the key, or the entry expired.
    pub fn get(&mut self, key: &CacheKey, now: Instant) -> Option<Vec<u8>> {
        if self.max_ttl == 0 {
            return None;
        }
        match self.map.get(key) {
            Some((buf, expires_at)) if now < *expires_at => Some(buf.clone()),
            Some(_) => {
                self.map.remove(key);
                None
            }
            None => None,
        }
    }

    /// Store one reply under every name, using `template` for the question
    /// type/class/opcode/flag parts of the key. TTL is clamped to
    /// `min_item_ttl` and the channel limit (a no-op when the clamped TTL is 0
    /// or the cache is disabled).
    pub fn store_names(
        &mut self,
        names: Vec<String>,
        template: &CacheKey,
        min_item_ttl: u32,
        buf: &[u8],
        now: Instant,
    ) {
        let ttl = std::cmp::min(min_item_ttl, self.max_ttl);
        if ttl > 0 {
            let expires = now + Duration::from_secs(ttl as u64);
            for name in names {
                self.map.insert(template.with_name(&name), (buf.to_vec(), expires));
            }
        }
    }

    /// Store a reply under the request's cache key (upstream keys on the
    /// outgoing query, not the echoed response header), clamped to the minimum
    /// answer TTL. `from_buf` only parses a non-empty answer section, so the
    /// historical `ancount > 0` guard is implied.
    pub fn store_reply(&mut self, request_key: &CacheKey, buf: &[u8], now: Instant) {
        if let Ok(parsed) = ParsedResponse::from_buf(buf) {
            let min_ttl = parsed.answers.iter().map(|a| a.ttl).min().unwrap_or(0);
            self.store_names(vec![request_key.name.clone()], request_key, min_ttl, buf, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::dns_record::ARES_CLASS_IN;

    #[test]
    fn cache_key_isolates_class_flags_and_opcode() {
        let mut cache = QueryCache::default();
        cache.set_max_ttl(3600);
        let now = Instant::now();
        let key = CacheKey::new("example.com", 1, ARES_CLASS_IN, 0, true, false);
        cache.store_names(vec!["example.com".into()], &key, 60, b"reply", now);
        assert_eq!(cache.get(&key, now).as_deref(), Some(&b"reply"[..]));

        // CHAOS must not hit the IN entry.
        assert!(cache
            .get(&CacheKey::new("example.com", 1, 3, 0, true, false), now)
            .is_none());
        // NORECURSE must not hit the RD entry.
        assert!(cache
            .get(&CacheKey::new("example.com", 1, ARES_CLASS_IN, 0, false, false), now)
            .is_none());
        // CD is part of upstream's key too.
        assert!(cache
            .get(&CacheKey::new("example.com", 1, ARES_CLASS_IN, 0, true, true), now)
            .is_none());
        // A trailing dot is presentation-only.
        assert!(cache
            .get(&CacheKey::new("example.com.", 1, ARES_CLASS_IN, 0, true, false), now)
            .is_some());
    }
}
