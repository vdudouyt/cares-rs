//! One handler per ares_* export: each shim marshals its C arguments,
//! makes exactly one call in here (plus, where NULL-pointer ordering
//! demands, a documented pre-check), and dispatches the returned outcome.
//! Preflights, launch loops and cache policy are implementation details of
//! these functions — never seams the ffi layer composes itself.
//!
//! Userdata factories (`make_userdata`) exist because core mints the shared
//! state-machine handles but cannot construct the ffi userdata that carries
//! them; the closures must capture only Copy data and Rc clones — never a
//! RefCell borrow.

use std::cell::RefCell;
use std::ffi::CString;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Instant;

use bytes::BytesMut;

use crate::core::ares::{dns_query_payload, rdns_name, SocketSource};
use crate::core::channel::ChannelState;
use crate::core::hostfile::HostLookup;
use crate::core::launch::{
    drive_addrinfo, issue, issue_consented, launch_pooled, maybe_launch_probe, AddrInfoDelivery,
    AddrInfoSeed, Consent, HostTaskSeed, LaunchOutcome,
};
use crate::core::lookup::SearchSm;
use crate::core::packets::AddrRecord;
use crate::core::preflight::{
    cached_reply, getaddrinfo_preflight, gethostbyaddr_preflight, gethostbyname_preflight,
    getnameinfo_preflight, no_servers, search_start, AddrInfo, AddrInfoPreflight, AddrPreflight,
    HostPreflight, NameinfoPreflight,
};
use crate::core::response::ParsedRRs;
use crate::ffi::error::{ARES_EBADQUERY, ARES_ECONNREFUSED, ARES_ENOSERVER};
use crate::ffi::RECORD_TYPE_PTR;

/// How a fire-and-forget entry (query/send/search/…) settled: the query is
/// in flight, or `status` must be delivered with a NULL payload.
pub(crate) enum StartOutcome {
    InFlight,
    Deliver(i32),
}

/// ares_query: reject server-less channels, then enqueue.
pub(crate) fn query<T>(st: &mut ChannelState<T>, name: &str, qtype: u16, userdata: T) -> StartOutcome {
    if no_servers(st) {
        return StartOutcome::Deliver(ARES_ENOSERVER);
    }
    match issue(st, dns_query_payload(name, qtype), SocketSource::Udp, 0, userdata) {
        Ok(_) => StartOutcome::InFlight,
        Err(()) => StartOutcome::Deliver(ARES_ECONNREFUSED),
    }
}

/// ares_send: a pre-built packet must at least hold a DNS header.
pub(crate) fn send<T>(st: &mut ChannelState<T>, query_buf: &[u8], userdata: T) -> StartOutcome {
    if query_buf.len() < 12 {
        return StartOutcome::Deliver(ARES_EBADQUERY);
    }
    if no_servers(st) {
        return StartOutcome::Deliver(ARES_ENOSERVER);
    }
    match issue(st, BytesMut::from(query_buf), SocketSource::Udp, 0, userdata) {
        Ok(_) => StartOutcome::InFlight,
        Err(()) => StartOutcome::Deliver(ARES_ECONNREFUSED),
    }
}

/// ares_query_dnsrec's pre-send phase. A cache hit hands the raw reply back
/// for the shim to parse and deliver; a hit that fails to parse falls
/// through via [`query_dnsrec_uncached`]. (Once the record codec lives in
/// core, the parse — and with it the fall-through policy — folds in here.)
pub(crate) enum DnsrecStart {
    Deliver(i32),
    DeliverCached(Vec<u8>),
    InFlight,
}

/// ares_query_dnsrec: server guard, then the query cache (keyed without the
/// trailing dot), then a fresh query.
pub(crate) fn query_dnsrec<T>(
    st: &mut ChannelState<T>,
    name_raw: &str,
    qtype: u16,
    now: Instant,
    userdata: T,
) -> DnsrecStart {
    if no_servers(st) {
        return DnsrecStart::Deliver(ARES_ENOSERVER);
    }
    let name_clean = name_raw.strip_suffix('.').unwrap_or(name_raw);
    if let Some(cached_buf) = cached_reply(st, name_clean, qtype, now) {
        return DnsrecStart::DeliverCached(cached_buf);
    }
    match query_dnsrec_uncached(st, name_raw, qtype, userdata) {
        StartOutcome::InFlight => DnsrecStart::InFlight,
        StartOutcome::Deliver(status) => DnsrecStart::Deliver(status),
    }
}

/// The fresh-query tail of ares_query_dnsrec, also the fall-through when a
/// cached reply turned out unparseable.
pub(crate) fn query_dnsrec_uncached<T>(
    st: &mut ChannelState<T>,
    name_raw: &str,
    qtype: u16,
    userdata: T,
) -> StartOutcome {
    match issue(st, dns_query_payload(name_raw, qtype), SocketSource::Udp, 0, userdata) {
        Ok(_) => StartOutcome::InFlight,
        Err(()) => StartOutcome::Deliver(ARES_ECONNREFUSED),
    }
}

/// ares_search / ares_search_dnsrec: seed the search plan, mint the shared
/// state-machine handle, and issue the first query. The shim's userdata
/// factory receives the handle to wrap with its delivery tail.
///
/// NULL-pointer ordering note: the name sanity check runs in the shim (via
/// [`search_name_check`]) *before* the channel is dereferenced — a bad name
/// is reported even on a NULL channel, so it cannot live in here.
pub(crate) fn search<T>(
    st: &mut ChannelState<T>,
    name: &str,
    dnstype: u16,
    retry_server_error: bool,
    make_userdata: &mut dyn FnMut(Rc<RefCell<SearchSm>>) -> T,
) -> StartOutcome {
    let (sm, query_hostname) = match search_start(st, name, retry_server_error) {
        Ok(seed) => seed,
        Err(status) => return StartOutcome::Deliver(status),
    };
    let handle = Rc::new(RefCell::new(sm));
    let userdata = make_userdata(handle);
    match issue(st, dns_query_payload(&query_hostname, dnstype), SocketSource::Udp, 0, userdata) {
        Ok(_) => StartOutcome::InFlight,
        Err(()) => StartOutcome::Deliver(ARES_ECONNREFUSED),
    }
}

/// How ares_gethostbyaddr settled before/at send time.
pub(crate) enum HostByAddrStart {
    Deliver(i32),
    DeliverHost(HostLookup),
    InFlight,
}

/// ares_gethostbyaddr: preflight (family/length validation, hosts-file
/// reverse hit, no-servers), then the PTR query — whose sock callbacks may
/// veto it (veto pops the task and delivers ECONNREFUSED).
pub(crate) fn gethostbyaddr<T>(
    st: &mut ChannelState<T>,
    addrbuf: &[u8],
    family: i32,
    make_userdata: &mut dyn FnMut(IpAddr) -> T,
    consent: Consent<'_>,
) -> HostByAddrStart {
    let addr = match gethostbyaddr_preflight(st, addrbuf, family) {
        AddrPreflight::Fail(status) => return HostByAddrStart::Deliver(status),
        AddrPreflight::DeliverHost(lookup) => return HostByAddrStart::DeliverHost(lookup),
        AddrPreflight::StartPtr(addr) => addr,
    };
    let userdata = make_userdata(addr);
    match issue_consented(st, dns_query_payload(&rdns_name(addr), RECORD_TYPE_PTR), 0, userdata, false, consent) {
        Ok(()) => HostByAddrStart::InFlight,
        Err(()) => HostByAddrStart::Deliver(ARES_ECONNREFUSED),
    }
}

/// How ares_getnameinfo settled before/at send time. Fail and the Deliver*
/// variants marshal straight to the C callback; InFlight means the PTR
/// query is on the wire.
pub(crate) enum NameinfoStart {
    Fail(i32),
    DeliverService(Option<CString>),
    DeliverNumeric { node: CString, service: Option<CString> },
    InFlight,
}

/// ares_getnameinfo: flag defaulting + the numeric/service short-circuits,
/// then the PTR query (sock callbacks may veto → ECONNREFUSED). The shim's
/// userdata factory receives the (possibly defaulted) flags.
pub(crate) fn getnameinfo<T>(
    st: &mut ChannelState<T>,
    addr: &AddrInfo,
    flags: i32,
    make_userdata: &mut dyn FnMut(i32) -> T,
    consent: Consent<'_>,
) -> NameinfoStart {
    let flags = match getnameinfo_preflight(st, addr, flags) {
        NameinfoPreflight::Fail(status) => return NameinfoStart::Fail(status),
        NameinfoPreflight::DeliverService(service) => return NameinfoStart::DeliverService(service),
        NameinfoPreflight::DeliverNumeric { node, service } => {
            return NameinfoStart::DeliverNumeric { node, service }
        }
        NameinfoPreflight::StartPtr { flags } => flags,
    };
    let userdata = make_userdata(flags);
    match issue_consented(st, dns_query_payload(&rdns_name(addr.ip), RECORD_TYPE_PTR), 0, userdata, false, consent) {
        Ok(()) => NameinfoStart::InFlight,
        Err(()) => NameinfoStart::Fail(ARES_ECONNREFUSED),
    }
}

/// How ares_gethostbyname settled before/at send time.
pub(crate) enum HostStart {
    /// Deliver `status` with a NULL hostent.
    Deliver(i32),
    /// Synchronous hit (IP literal / hosts file / localhost).
    DeliverHost(HostLookup),
    /// Query-cache hit: sortlist already applied; the i32 is the hostent
    /// address family to emit.
    DeliverParsed(ParsedRRs<AddrRecord>, i32),
    InFlight,
}

/// ares_gethostbyname: the full pre-DNS cascade, then the pooled launch and
/// the failover probe. On exhaustion the probe still runs (its health
/// bookkeeping sees the launch failures), and ECONNREFUSED is delivered by
/// the shim afterwards.
pub(crate) fn gethostbyname<T>(
    st: &mut ChannelState<T>,
    hostname: &str,
    family: i32,
    now: Instant,
    make_userdata: &mut dyn FnMut(HostTaskSeed, usize) -> T,
    consent: Consent<'_>,
) -> HostStart {
    match gethostbyname_preflight(st, hostname, family, now) {
        HostPreflight::Fail(status) => HostStart::Deliver(status),
        HostPreflight::DeliverHost(lookup) => HostStart::DeliverHost(lookup),
        HostPreflight::DeliverParsed(rrs, hostent_family) => HostStart::DeliverParsed(rrs, hostent_family),
        HostPreflight::StartDns { sm, query_hostname, first_server, use_tcp } => {
            let (send_family, send_rtype) = (sm.current_family, sm.expected_rtype);
            let handle = Rc::new(RefCell::new(sm));
            let launched = launch_pooled(st, &query_hostname, send_family, send_rtype, use_tcp, first_server, &handle, make_userdata, consent);
            // Server failover probing: if enabled, probe an expired-failure
            // server in parallel with the primary query.
            maybe_launch_probe(st, &query_hostname, send_family, first_server, use_tcp, make_userdata, consent);
            match launched {
                LaunchOutcome::Launched => HostStart::InFlight,
                LaunchOutcome::Exhausted { .. } => HostStart::Deliver(ARES_ECONNREFUSED),
            }
        }
    }
}

/// How ares_getaddrinfo settled at entry: a synchronous delivery, or the
/// batch went out — possibly already producing a (failure) delivery when
/// every send was refused.
pub(crate) enum AddrInfoStart {
    Deliver(i32),
    DeliverAddrs { addrs: Vec<IpAddr>, canonical: String },
    Started(Vec<AddrInfoDelivery>),
}

/// ares_getaddrinfo: preflight (empty/onion/IP-literal/hosts/no-servers),
/// then mint the machine and drive the A/AAAA batch.
pub(crate) fn getaddrinfo<T>(
    st: &mut ChannelState<T>,
    hostname_raw: &str,
    ai_family: i32,
    make_userdata: &mut dyn FnMut(AddrInfoSeed, usize) -> T,
    consent: Consent<'_>,
) -> AddrInfoStart {
    match getaddrinfo_preflight(st, hostname_raw, ai_family) {
        AddrInfoPreflight::Fail(status) => AddrInfoStart::Deliver(status),
        AddrInfoPreflight::DeliverAddrs { addrs, canonical } => AddrInfoStart::DeliverAddrs { addrs, canonical },
        AddrInfoPreflight::StartDns { sm, first_server } => {
            let handle = Rc::new(RefCell::new(sm));
            let actions = handle.borrow_mut().begin_batch(first_server);
            AddrInfoStart::Started(drive_addrinfo(st, &handle, actions, make_userdata, consent))
        }
    }
}

/// ares_search's shim-side pre-check, re-exported so the shim's single
/// entry-ordering exception reads from the api layer.
pub(crate) use crate::core::preflight::search_name_check as search_precheck;

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
