//! The self-contained async `ares_gethostbyaddr` lifecycle: reverse-lookup
//! the hosts file, then a single PTR query via [`resolve_query`]. Returns
//! a [`Hostent`] — reuses `AsyncKind::Host` (same `Output` as gethostbyname).

use std::cell::RefCell;
use std::ffi::c_int;
use std::net::IpAddr;
use std::rc::Rc;

use crate::core::api;
use crate::core::executor::{resolve_query, QueryIo, Resources};
use crate::core::hostent::Hostent;
use crate::core::hostfile::Hosts;
use crate::core::AresError;
use crate::core::query_builder::dns_query_payload;
use crate::core::transport::rdns_name;
use crate::ffi::error::ARES_ENOSERVER;
use crate::ffi::RECORD_TYPE_PTR;

/// Everything the async gethostbyaddr future owns. Built from `Client`; the
/// future itself names no `Client`/`Transport`.
pub(crate) struct HostByAddrCtx {
    pub res: Resources,
    pub hosts: Rc<Hosts>,
}

/// The whole lifecycle — reverse-lookup then PTR query. The preflight has no
/// `.await`, so a synchronous hosts-file hit completes on the spawn's first
/// poll and fires re-entrantly (matching c-ares).
pub(crate) async fn gethostbyaddr(
    ctx: HostByAddrCtx,
    io: Rc<RefCell<QueryIo>>,
    ip: IpAddr,
    family: c_int,
) -> Result<Hostent, AresError> {
    // ===== preflight (synchronous) =====
    // family validation is done in the ffi shim (reads raw C args)

    // Hosts file reverse lookup.
    if let Some(lookup) = ctx.hosts.reverse_lookup(ip) {
        return Ok(Hostent::from_lookup(lookup));
    }

    // No servers configured
    if ctx.res.endpoints.is_empty() {
        return Err(ARES_ENOSERVER.into());
    }

    // ===== DNS phase: single PTR query =====
    let payload = dns_query_payload(&rdns_name(ip), RECORD_TYPE_PTR);
    let (result, io_timeouts) = resolve_query(io.clone(), ctx.res.clone(), payload, false, None).await;

    match result {
        Ok(buf) => {
            let hostent = api::on_host_reply(Ok(&buf), RECORD_TYPE_PTR, family, Some(ip))?;
            io.borrow_mut().timeouts = io_timeouts;
            Ok(hostent)
        }
        Err(status) => {
            io.borrow_mut().timeouts = io_timeouts;
            Err(AresError::from(status))
        }
    }
}
