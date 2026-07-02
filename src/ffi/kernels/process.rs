//! Reactor-residue kernels for ffi/process.rs and the lookup executors:
//! query-cache stores, retry userdata rebuilds, TCP re-framing, pool
//! retention, and server-state string formatting.

use std::collections::HashMap;
use std::ffi::c_int;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::core::response::ParsedResponse;
use crate::ffi::channel::ChannelData;
use crate::ffi::lookups::{Callback, FFIData, SearchDelivery};

impl FFIData {
    /// A retry copy of this task's userdata aimed at `server_index`.
    pub(crate) fn retarget(&self, server_index: usize, timeouts: c_int) -> FFIData {
        FFIData {
            callback: self.callback.clone(),
            arg: self.arg,
            family: self.family,
            expected_record_type: self.expected_record_type,
            ip: self.ip,
            nameinfo_flags: self.nameinfo_flags,
            port: self.port,
            scope_id: self.scope_id,
            server_index,
            timeouts,
        }
    }
}

/// Whether a delivered reply should populate the query cache: plain dnsrec
/// queries and dnsrec-delivery searches. Reads SearchDelivery through a
/// transient RefCell borrow that is dropped at return.
pub(crate) fn wants_dnsrec_cache(cb: &Callback) -> bool {
    match cb {
        Callback::AresCallbackDnsRec(_) => true,
        Callback::Search(lookup) => {
            matches!(lookup.borrow().delivery, SearchDelivery::DnsRec { .. })
        }
        _ => false,
    }
}

/// Store a successful reply under (qname, qtype), clamped to the minimum
/// answer TTL and the channel limit. `from_buf` only succeeds with a
/// non-empty answer section, so the historical `ancount > 0` guard is
/// implied by the parse.
pub(crate) fn cache_reply(
    cache: &mut HashMap<(String, u16), (Vec<u8>, Instant)>,
    max_ttl: u32,
    buf: &[u8],
    now: Instant,
) {
    // Extract query name and type from the response buffer
    if let Ok(parsed) = ParsedResponse::from_buf(buf) {
        let qname = parsed.query.name.join(".");
        let qtype = parsed.query.qtype;
        // Find minimum TTL from answers
        let min_ttl = parsed.answers.iter().map(|a| a.ttl).min().unwrap_or(0);
        let cache_ttl = std::cmp::min(min_ttl, max_ttl);
        if cache_ttl > 0 {
            let expires = now + Duration::from_secs(cache_ttl as u64);
            cache.insert((qname, qtype), (buf.to_vec(), expires));
        }
    }
}

/// The HostAction::CacheStore arm: store one reply under every search name
/// it answered, clamped to the minimum record TTL and the channel limit.
pub(crate) fn cache_store_names(
    cache: &mut HashMap<(String, u16), (Vec<u8>, Instant)>,
    max_ttl: u32,
    names: Vec<String>,
    rtype: u16,
    min_item_ttl: u32,
    buf: &[u8],
    now: Instant,
) {
    let cache_ttl = std::cmp::min(min_item_ttl, max_ttl);
    if cache_ttl > 0 {
        let expires = now + Duration::from_secs(cache_ttl as u64);
        for name in names {
            cache.insert((name, rtype), (buf.to_vec(), expires));
        }
    }
}

/// Strip the 2-byte TCP length prefix when re-framing a write buffer for a
/// retry (enqueue re-frames for the target transport).
pub(crate) fn tcp_payload(writebuf: &[u8], was_tcp: bool) -> &[u8] {
    if was_tcp && writebuf.len() > 2 {
        &writebuf[2..]
    } else {
        writebuf
    }
}

/// Phase-4 pool cleanup: drop UDP sockets past their query budget and TCP
/// sockets no task references anymore (Rc::strong_count == 1 == pool-only).
pub(crate) fn retain_pools(channeldata: &mut ChannelData) {
    if channeldata.udp_max_queries > 0 {
        let limit = channeldata.udp_max_queries;
        channeldata.udp_connections.retain(|(_, rc, count)| {
            *count < limit || std::rc::Rc::strong_count(rc) > 1
        });
    }
    // Clean up TCP connections where no tasks reference the socket anymore
    channeldata.tcp_connections.retain(|(_, rc)| std::rc::Rc::strong_count(rc) > 1);
}

/// The `ip:port` string reported to the server-state callback (IPv6
/// bracketed); None when the index is stale.
pub(crate) fn server_state_string(
    channeldata: &ChannelData,
    server_index: usize,
    is_tcp: bool,
) -> Option<String> {
    let (ip, port) = channeldata.ares.config.nameservers.get(server_index)?;
    let port_val = port.unwrap_or(if is_tcp {
        channeldata.ares.default_tcp_port
    } else {
        channeldata.ares.default_udp_port
    });
    Some(match ip {
        IpAddr::V4(v4) => format!("{}:{}", v4, port_val),
        IpAddr::V6(v6) => format!("[{}]:{}", v6, port_val),
    })
}
