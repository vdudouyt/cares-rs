//! Shared outcome types and the stateless helpers used by the resolver
//! methods on `Client` (see `core::client`, where the one-method-per-export
//! handlers now live) and by the ffi executors.
//!
//! `Operation`/`HostDelivery`/`SearchReplyDelivery`/`NameinfoResult`/
//! `AddrInfoResult` describe how an entry point or a settled task reports back
//! to C. `on_host_reply`, `clamp_timeout`/`nfds` and the `search_precheck`
//! re-export are the pure helpers that need no channel state (or take it only
//! by shared ref) and so stay free functions here.

use std::ffi::CString;
use std::net::IpAddr;

use crate::core::hostent::Hostent;
use crate::core::response::{addr_reply, push_synthetic_ptr, ReplyRequire};
use crate::core::AresError;
use crate::ffi::RECORD_TYPE_PTR;

/// How an `ares_*` entry point settled, uniformly across every handler. The
/// `Result` is the fail axis — `Err(status)` means "deliver this non-success
/// status now, with a NULL payload". For the handlers that can produce a
/// synchronous result, the `Ok` side is an `Operation`, the sync-vs-async axis:
/// * `Ok(Operation::Ready(v))` — settled synchronously; build the C result
///   from `v` and deliver SUCCESS. Always terminal (fires the callback once).
/// * `Ok(Operation::Pending)` — the query is on the wire; the reply path fires
///   the callback later.
///
/// The fire-and-forget entries (query/send/search) have no synchronous result,
/// so they return `Result<(), i32>` directly — `Ok(())` means "launched".
pub(crate) enum Operation<T> {
    Pending,
    Ready(T),
}

/// The synchronous result `ares_getnameinfo` can hand back: a service-only
/// answer, or a numeric-host answer. Both marshal straight to the C callback;
/// a PTR query on the wire is `Operation::Pending`, an error is `Err(status)`.
pub(crate) enum NameinfoResult {
    Service(Option<CString>),
    Numeric { node: CString, service: Option<CString> },
}

/// The synchronous address result `ares_getaddrinfo` can hand back — an
/// IP-literal or hosts-file hit. (An async A/AAAA batch is `Operation::Pending`;
/// an error, including every socket refused, is `Err(status)`.)
pub(crate) struct AddrInfoResult {
    pub addrs: Vec<IpAddr>,
    pub canonical: String,
}

/// ares_search's shim-side pre-check, re-exported so the shim's single
/// entry-ordering exception reads from the api layer.
pub(crate) use crate::core::preflight::search_name_check as search_precheck;

/// The plain host-callback path (ares_gethostbyaddr's direct PTR delivery):
/// parse under the flow's acceptance rule, add the synthetic record for the
/// queried address, and shape the hostent.
pub(crate) fn on_host_reply(res: Result<&[u8], AresError>, rtype: u16, family: i32, ip: Option<IpAddr>) -> Result<Hostent, AresError> {
    let buf = res?;
    let is_ptr = rtype == RECORD_TYPE_PTR;
    let require = if is_ptr { ReplyRequire::ItemsOrAliases } else { ReplyRequire::Items };
    let mut rrs = addr_reply(buf, rtype, require)?;
    if is_ptr {
        push_synthetic_ptr(&mut rrs, ip.expect("PTR flows carry the queried ip"));
    }
    Ok(Hostent::from_parsed(rrs, family))
}

/// What a settled search task owes its C callback (None: a follow-up query
/// went out and the lookup is still in flight).
pub(crate) enum SearchReplyDelivery {
    /// Deliver the (raw or parsed) reply buffer with SUCCESS.
    Success { timeouts: i32 },
    Fail { status: AresError, timeouts: i32 },
}

/// ares_timeout's clamp decision: nothing pending → report via maxtv;
/// otherwise write `ms` into tv and return whichever of tv/maxtv is sooner.
pub(crate) enum TimeoutChoice {
    NoTasks,
    Wait { ms: u128, use_max: bool },
}

pub(crate) fn clamp_timeout(wait: Option<u128>, maxtv_ms: Option<u128>) -> TimeoutChoice {
    match wait {
        None => TimeoutChoice::NoTasks,
        Some(ms) => TimeoutChoice::Wait { ms, use_max: maxtv_ms.is_some_and(|m| m < ms) },
    }
}

/// ares_fds' nfds tally: highest fd + 1 across the pollable set.
pub(crate) fn nfds(fds: &[(i32, bool)]) -> i32 {
    fds.iter().map(|(fd, _)| fd + 1).max().unwrap_or(0)
}
