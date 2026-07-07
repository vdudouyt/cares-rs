//! The self-contained async `ares_search` / `ares_search_dnsrec` lifecycle:
//! a name-iteration loop driven by [`SearchPlan`] (from `lookup.rs`), with the
//! classic `SearchSm::step` verdict logic inlined. Each iteration is one
//! [`resolve_query`]; a successful reply returns [`Delivery::Raw`], which the
//! FFI dispatches per `SearchDelivery::Raw` vs `SearchDelivery::DnsRec`.

use std::cell::RefCell;
use std::ffi::c_int;
use std::rc::Rc;

use crate::core::executor::{resolve_query, Delivery, QueryIo, Resources};
use crate::core::lookup::{summarize, SearchPlan};
use crate::core::query_builder::dns_query_payload;
use crate::core::AresError;
use crate::ffi::error::{
    ARES_ENODATA, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP, ARES_EREFUSED, ARES_ESERVFAIL,
    ARES_ETIMEOUT,
};

/// Everything the async search future owns. Built from `Client`; the future
/// itself names no `Client`/`Transport`.
pub(crate) struct SearchCtx {
    pub res: Resources,
    pub ndots: u32,
    pub search: Rc<[String]>,
    pub use_vc: bool,
}

/// The whole search lifecycle: iterate the search plan, retrying on
/// NXDOMAIN/NODATA/timeout (and, for the dnsrec flavor with
/// `retry_server_error`, also on SERVFAIL/REFUSED/NOTIMP). Returns `Delivery`
/// — the FFI dispatches raw reply bytes vs parsed dns record. The rcode→status
/// mapping and iteration rules mirror the classic `SearchSm::step`.
pub(crate) async fn search_lifecycle(
    ctx: SearchCtx,
    io: Rc<RefCell<QueryIo>>,
    name: String,
    dnstype: u16,
    retry_server_error: bool,
) -> Delivery {
    // ===== preflight (synchronous) =====
    if ctx.res.endpoints.is_empty() {
        return Delivery::Raw { result: Err(ARES_ENOSERVER), timeouts: 0 };
    }

    // ===== DNS phase =====
    let mut plan = SearchPlan::for_search(&name, ctx.ndots, &ctx.search);
    let mut had_nodata = false;
    let mut timeouts: c_int = 0;
    let mut first = true;

    loop {
        let payload = dns_query_payload(&plan.current, dnstype);
        // Only the first query of a lookup is eligible to spawn a failover probe.
        let probe_payload = if first { Some(dns_query_payload(&plan.current, dnstype)) } else { None };
        first = false;
        let (result, io_timeouts) = resolve_query(io.clone(), ctx.res.clone(), payload, ctx.use_vc, probe_payload).await;
        timeouts += io_timeouts;

        let last_error: AresError = match result {
            Ok(buf) => {
                let summary = summarize(&buf, 0);
                match summary.rcode {
                    3 => ARES_ENOTFOUND.into(),  // NXDOMAIN
                    2 => ARES_ESERVFAIL.into(),  // SERVFAIL
                    4 => ARES_ENOTIMP.into(),    // NOTIMP
                    5 => ARES_EREFUSED.into(),   // REFUSED
                    0 if summary.ancount > 0 => {
                        // Success — deliver the raw response.
                        io.borrow_mut().timeouts = timeouts;
                        return Delivery::Raw { result: Ok(buf), timeouts };
                    }
                    // NOERROR-with-no-answers, or any other rcode → NODATA.
                    _ => {
                        had_nodata = true;
                        ARES_ENODATA.into()
                    }
                }
            }
            Err(status) => AresError::from(status),
        };

        // Search-domain iteration: on NXDOMAIN/NODATA/TIMEOUT — and, for the
        // dnsrec flavor, also on server errors — try the next name in the plan.
        let code = last_error.code();
        let iterate = matches!(code, ARES_ENOTFOUND | ARES_ENODATA | ARES_ETIMEOUT)
            || (retry_server_error && matches!(code, ARES_ESERVFAIL | ARES_EREFUSED | ARES_ENOTIMP));
        if iterate && plan.advance().is_some() {
            continue;
        }

        // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
        let mut status = last_error;
        if had_nodata && status.code() == ARES_ENOTFOUND {
            status = ARES_ENODATA.into();
        }
        io.borrow_mut().timeouts = timeouts;
        return Delivery::Raw { result: Err(status.code()), timeouts };
    }
}
