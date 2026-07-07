//! The self-contained async `ares_getnameinfo` lifecycle: the three-path
//! synchronous preflight (service-only / NUMERICHOST / DNS PTR), then a single
//! PTR query via [`resolve_query`] and [`assemble_nameinfo`]. Returns a
//! [`NameinfoReply`] — the FFI only fires the C callback.

use std::cell::RefCell;
use std::ffi::{c_int, CString};
use std::rc::Rc;

use crate::core::executor::{resolve_query, QueryIo, Resources};
use crate::core::preflight::{
    assemble_nameinfo, format_ip_with_scope, get_service_string, AddrInfo, NameinfoReply,
};
use crate::core::query_builder::dns_query_payload;
use crate::core::services::Services;
use crate::core::transport::rdns_name;
use crate::core::AresError;
use crate::ffi::error::{ARES_EBADFLAGS, ARES_ENOSERVER};
use crate::ffi::{
    ARES_NI_LOOKUPHOST, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD, ARES_NI_NUMERICHOST, ARES_SUCCESS,
    RECORD_TYPE_PTR,
};

/// Everything the async getnameinfo future owns. The preflight needs no channel
/// state beyond the socket resources — `Services` is lazy-loaded to a default
/// (the same default `assemble_nameinfo` uses).
pub(crate) struct NameinfoCtx {
    pub res: Resources,
}

/// The whole lifecycle, request to delivery. The three synchronous short-circuits
/// (service-only, NUMERICHOST, no-servers) have no `.await`, so they complete on
/// the spawn's first poll and fire re-entrantly (matching c-ares).
pub(crate) async fn getnameinfo(
    ctx: NameinfoCtx,
    io: Rc<RefCell<QueryIo>>,
    addr: AddrInfo,
    flags: c_int,
) -> NameinfoReply {
    // ===== preflight (synchronous) — order is behavior =====

    // Flag defaulting: if neither LOOKUPSERVICE nor LOOKUPHOST, default to LOOKUPHOST
    let flags = if (flags & ARES_NI_LOOKUPSERVICE) == 0 && (flags & ARES_NI_LOOKUPHOST) == 0 {
        flags | ARES_NI_LOOKUPHOST
    } else {
        flags
    };

    let want_host = (flags & ARES_NI_LOOKUPHOST) != 0;
    let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

    // Service-only: no DNS needed.
    if want_service && !want_host {
        let service = get_service_string(&Services::default(), addr.port, flags);
        return NameinfoReply { status: ARES_SUCCESS.into(), node: None, service, timeouts: 0 };
    }

    // NUMERICHOST: the address string is the answer.
    if (flags & ARES_NI_NUMERICHOST) != 0 {
        if (flags & ARES_NI_NAMEREQD) != 0 {
            return NameinfoReply { status: ARES_EBADFLAGS.into(), node: None, service: None, timeouts: 0 };
        }
        let node = CString::new(format_ip_with_scope(&addr.ip, addr.scope_id, flags)).unwrap();
        let service = if want_service {
            get_service_string(&Services::default(), addr.port, flags)
        } else {
            None
        };
        return NameinfoReply { status: ARES_SUCCESS.into(), node: Some(node), service, timeouts: 0 };
    }

    // No servers configured
    if ctx.res.endpoints.is_empty() {
        return NameinfoReply { status: ARES_ENOSERVER.into(), node: None, service: None, timeouts: 0 };
    }

    // ===== DNS phase: single PTR query =====
    let payload = dns_query_payload(&rdns_name(addr.ip), RECORD_TYPE_PTR);
    let (result, io_timeouts) = resolve_query(io.clone(), ctx.res.clone(), payload, false, None).await;

    let dns_result: Result<&[u8], AresError> = match result {
        Ok(ref buf) => Ok(&buf[..]),
        Err(status) => Err(AresError::from(status)),
    };
    let reply = assemble_nameinfo(dns_result, addr.ip, addr.scope_id, addr.port, flags, io_timeouts);
    // `assemble_nameinfo` carries io_timeouts in its `NameinfoReply.timeouts` —
    // we don't need the mailbox timeouts field for this op.
    io.borrow_mut().timeouts = reply.timeouts;
    reply
}
