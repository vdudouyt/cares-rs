//! Shared stateless helpers used by the ffi shims and the reply path:
//! `on_host_reply` (gethostbyaddr's PTR→hostent shaping), the `search_precheck`
//! re-export, and the `ares_timeout`/`ares_fds` tallies. Pure — no channel state.

use std::net::IpAddr;

use crate::core::hostent::Hostent;
use crate::core::response::{addr_reply, push_synthetic_ptr, ReplyRequire};
use crate::core::AresError;
use crate::ffi::RECORD_TYPE_PTR;

/// ares_search's shim-side pre-check, re-exported so the shim's single
/// entry-ordering exception reads from the api layer.
pub(crate) use crate::core::async_client::search_name_check as search_precheck;

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
