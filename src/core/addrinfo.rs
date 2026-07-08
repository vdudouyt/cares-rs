//! The self-contained async `ares_getaddrinfo` lifecycle: preflight
//! (empty/onion/IP-literal/hosts/no-servers), then per search-plan name a
//! **parallel A+AAAA batch** driven by [`ParallelQueries`], merging the
//! address records. Returns [`AddrInfoOut`]; the FFI builds the `ares_addrinfo`
//! node chain (the service port travels on the delivery tail).

use std::cell::RefCell;
use std::ffi::c_int;
use std::net::IpAddr;
use std::rc::Rc;

use crate::core::executor::{ParallelQueries, QueryIo, Resources};
use crate::core::hostfile::{AddressFamily, Hosts};
use crate::core::lookup::{is_onion_domain, summarize, SearchPlan, RTYPE_A, RTYPE_AAAA};
use crate::core::packets::AddrRecord;
use crate::core::query_builder::dns_query_payload;
use crate::core::response::{addr_reply, ReplyRequire};
use crate::core::AresError;
use crate::ffi::error::{
    ARES_ENODATA, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP, ARES_EREFUSED, ARES_ESERVFAIL,
    ARES_ETIMEOUT, ARES_SUCCESS,
};

/// Everything the async getaddrinfo future owns. Built from `Client`; the
/// future itself names no `Client`/`Transport`.
pub(crate) struct AddrInfoCtx {
    pub res: Resources,
    pub hosts: Rc<Hosts>,
    pub ndots: u32,
    pub search: Rc<[String]>,
    pub use_vc: bool,
    pub ai_family: c_int,
}

/// The safe result the FFI turns into an `ares_addrinfo`: the canonical name,
/// the merged address records (arrival order), and the status.
pub(crate) struct AddrInfoOut {
    pub name: String,
    pub records: Vec<AddrRecord>,
    pub status: AresError,
}

fn fail(status: c_int) -> AddrInfoOut {
    AddrInfoOut { name: String::new(), records: Vec::new(), status: status.into() }
}

/// The whole lifecycle. The preflight has no `.await`, so a synchronous hit
/// (IP literal / hosts file) completes on the spawn's first poll and fires
/// re-entrantly (matching c-ares). The DNS phase iterates the search plan,
/// launching A and AAAA in parallel per name.
pub(crate) async fn getaddrinfo_lifecycle(
    ctx: AddrInfoCtx,
    io: Rc<RefCell<QueryIo>>,
    hostname_raw: String,
) -> AddrInfoOut {
    // ===== preflight (synchronous) — order is behavior =====
    // The raw name keeps its trailing dot for the SearchPlan; the checks and the
    // delivered canonical name use the stripped form.
    let hostname = hostname_raw.strip_suffix('.').unwrap_or(&hostname_raw);

    if hostname.is_empty() || is_onion_domain(hostname) {
        return fail(ARES_ENOTFOUND);
    }

    // IP literal (a family mismatch fails — no fall-through).
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let matches = match ctx.ai_family {
            libc::AF_INET => ip.is_ipv4(),
            libc::AF_INET6 => ip.is_ipv6(),
            libc::AF_UNSPEC => true,
            _ => false,
        };
        if matches {
            return AddrInfoOut {
                name: hostname.to_string(),
                records: vec![AddrRecord { ip, ttl: u32::MAX }],
                status: ARES_SUCCESS.into(),
            };
        }
        return fail(ARES_ENOTFOUND);
    }

    // Hosts file.
    let family_filter = match ctx.ai_family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        _ => AddressFamily::Any,
    };
    if let Some(lookup) = ctx.hosts.lookup(hostname, family_filter) {
        if !lookup.addrs.is_empty() {
            return AddrInfoOut {
                name: hostname.to_string(),
                records: lookup.addrs.iter().map(|&ip| AddrRecord { ip, ttl: u32::MAX }).collect(),
                status: ARES_SUCCESS.into(),
            };
        }
    }

    if ctx.res.endpoints.is_empty() {
        return fail(ARES_ENOSERVER);
    }

    // ===== DNS phase: parallel A+AAAA per search-plan name =====
    let mut plan = SearchPlan::for_search(&hostname_raw, ctx.ndots, &ctx.search);
    let mut timeouts: c_int = 0;
    let mut last_error: AresError = ARES_ENODATA.into();
    let mut had_nodata = false;

    loop {
        let rtypes: Vec<u16> = match ctx.ai_family {
            libc::AF_INET => vec![RTYPE_A],
            libc::AF_INET6 => vec![RTYPE_AAAA],
            _ => vec![RTYPE_A, RTYPE_AAAA],
        };
        let payloads: Vec<_> =
            rtypes.iter().map(|&rt| (dns_query_payload(&plan.current, rt), ctx.use_vc)).collect();
        let a_idx = rtypes.iter().position(|&rt| rt == RTYPE_A);

        // Drive A+AAAA in parallel. Policy (here, not in the executor): once the
        // A/ipv4 query returns actual addresses, cancel the sibling AAAA query —
        // its retries stop so it isn't sent again. (ipv6 success does NOT cancel
        // A: an ipv4-only host may still need the A answer.)
        let mut par = ParallelQueries::new(io.clone(), ctx.res.clone(), payloads);
        while !par.all_done() {
            par.step().await;
            if let Some(ai) = a_idx {
                if let Some((Ok(buf), _)) = par.result(ai) {
                    let s = summarize(buf, 0);
                    if s.rcode == 0 && s.ancount > 0 {
                        for j in 0..rtypes.len() {
                            if j != ai {
                                par.cancel(j);
                            }
                        }
                    }
                }
            }
        }

        // Merge every family's records (arrival order); note the last error.
        // A cancelled query has no result — it contributes nothing.
        let mut records: Vec<AddrRecord> = Vec::new();
        let mut any_success = false;
        for (i, &rtype) in rtypes.iter().enumerate() {
            match par.result(i) {
                Some((Ok(buf), io_timeouts)) => {
                    timeouts += io_timeouts;
                    match addr_reply(buf, rtype, ReplyRequire::Items) {
                        Ok(mut rrs) => {
                            records.append(&mut rrs.items);
                            any_success = true;
                        }
                        Err(e) => {
                            if e.code() == ARES_ENODATA {
                                had_nodata = true;
                            }
                            last_error = e;
                        }
                    }
                }
                Some((Err(status), io_timeouts)) => {
                    timeouts += io_timeouts;
                    last_error = AresError::from(*status);
                }
                None => {}
            }
        }

        if any_success {
            io.borrow_mut().timeouts = timeouts;
            return AddrInfoOut { name: plan.current.clone(), records, status: ARES_SUCCESS.into() };
        }

        // All families failed for this name — try the next search domain.
        let code = last_error.code();
        let retryable = matches!(
            code,
            ARES_ENODATA | ARES_ENOTFOUND | ARES_ETIMEOUT | ARES_ESERVFAIL | ARES_ENOTIMP | ARES_EREFUSED
        );
        if retryable && plan.advance().is_some() {
            last_error = ARES_ENODATA.into();
            continue;
        }

        // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
        let status = if had_nodata && code == ARES_ENOTFOUND { ARES_ENODATA } else { code };
        io.borrow_mut().timeouts = timeouts;
        return fail(status);
    }
}
