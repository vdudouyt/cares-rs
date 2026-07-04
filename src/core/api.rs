//! One handler per ares_* export: each shim marshals its C arguments,
//! makes exactly one call in here (plus, where NULL-pointer ordering
//! demands, a documented pre-check), and dispatches the returned outcome.
//! Preflights, launch loops and cache policy are implementation details of
//! these functions — never seams the ffi layer composes itself.
//!
//! Handlers take the ffi userdata as a plain value (a `Callback` binding the
//! shim builds eagerly), not a factory closure: core owns the per-task data
//! (the state-machine handle on `Task.machine`, plus family/rtype/timeouts/
//! queried-ip), mints the machine, and clones the binding into each task —
//! so nothing here constructs a C userdata.

use std::cell::RefCell;
use std::ffi::CString;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Instant;

use bytes::BytesMut;

use crate::core::ares::{dns_query_payload, rdns_name, SocketSource};
use crate::core::channel::ChannelState;
use crate::core::launch::{
    drive_addrinfo, issue, launch_pooled, maybe_launch_probe, AddrInfoDelivery, LaunchOutcome,
};
use crate::core::ares::TaskMachine;
use crate::core::channel::cache_store_names;
use crate::core::hostent::Hostent;
use crate::core::hostfile::AddressFamily;
use crate::core::lookup::{
    is_localhost, is_onion_domain, is_truncated, AddrInfoSm, HostAction, HostByNameSm, HostEvent,
    LookupCfg, LookupEvent, SearchAction, SearchPlan, SearchSm, ServerHealth,
};
use crate::core::packets::{buf_to_ip, AddrRecord};
use crate::core::preflight::{
    cached_reply, format_ip_with_scope, get_service_string, hosts_file_lookup, no_servers,
    search_start, AddrInfo,
};
use crate::core::response::{addr_reply, push_synthetic_ptr, ParsedResponse, ParsedRRs, ReplyRequire};
use crate::core::sortlist::apply_sortlist;
use crate::core::AresError;
use crate::ffi::error::{
    ARES_EBADFLAGS, ARES_EBADNAME, ARES_EBADQUERY, ARES_ECONNREFUSED, ARES_EFILE, ARES_ENODATA,
    ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP,
};
use crate::ffi::{
    ARES_NI_LOOKUPHOST, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD, ARES_NI_NUMERICHOST, RECORD_TYPE_A,
    RECORD_TYPE_AAAA, RECORD_TYPE_PTR,
};

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

/// ares_query: reject server-less channels, then enqueue.
pub(crate) fn query<T>(st: &mut ChannelState<T>, name: &str, qtype: u16, userdata: T) -> Result<(), AresError> {
    if no_servers(st) {
        return Err(ARES_ENOSERVER.into());
    }
    issue(st, dns_query_payload(name, qtype), SocketSource::Udp, 0, userdata)?;
    Ok(())
}

/// ares_send: a pre-built packet must at least hold a DNS header.
pub(crate) fn send<T>(st: &mut ChannelState<T>, query_buf: &[u8], userdata: T) -> Result<(), AresError> {
    if query_buf.len() < 12 {
        return Err(ARES_EBADQUERY.into());
    }
    if no_servers(st) {
        return Err(ARES_ENOSERVER.into());
    }
    issue(st, BytesMut::from(query_buf), SocketSource::Udp, 0, userdata)?;
    Ok(())
}

/// ares_query_dnsrec: server guard, then the query cache (keyed without the
/// trailing dot; a cached reply that fails to parse falls through), then a
/// fresh query. A cache hit is parsed right here (`Ready`); the shim boxes the
/// record, delivers, and destroys.
pub(crate) fn query_dnsrec<T>(
    st: &mut ChannelState<T>,
    name_raw: &str,
    qtype: u16,
    now: Instant,
    userdata: T,
) -> Result<Operation<crate::core::dns_record::ares_dns_record_t>, AresError> {
    if no_servers(st) {
        return Err(ARES_ENOSERVER.into());
    }
    let name_clean = name_raw.strip_suffix('.').unwrap_or(name_raw);
    if let Some(cached_buf) = cached_reply(st, name_clean, qtype, now) {
        if let Ok(rec) = crate::core::dns_record::parse_record(&cached_buf) {
            return Ok(Operation::Ready(rec));
        }
    }
    issue(st, dns_query_payload(name_raw, qtype), SocketSource::Udp, 0, userdata)?;
    Ok(Operation::Pending)
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
    binding: T,
) -> Result<(), AresError> {
    let (sm, query_hostname) = search_start(st, name, retry_server_error)?;
    let handle = Rc::new(RefCell::new(sm));
    issue(st, dns_query_payload(&query_hostname, dnstype), SocketSource::Udp, 0, binding)?;
    if let Some(t) = st.ares.tasks.last_mut() { t.machine = TaskMachine::Search(handle); }
    Ok(())
}

/// ares_gethostbyname_file: the hosts-file-only lookup, shaped for C.
pub(crate) fn gethostbyname_file<T>(st: &mut ChannelState<T>, name: &str, family: i32) -> Result<Hostent, AresError> {
    hosts_file_lookup(st, name, family).map(Hostent::from_lookup)
}

/// ares_gethostbyaddr: preflight (family/length validation, hosts-file
/// reverse hit, no-servers), then the PTR query — whose fresh socket the
/// channel's socket callback may refuse (→ ECONNREFUSED).
///
/// The `userdata` is a plain value the shim built eagerly (no factory
/// closure): the only per-task datum core computes here — the queried
/// address — is recorded on the `Task` itself (`queried_ip`), not stamped
/// into the ffi userdata, and the reply reads it back from there.
pub(crate) fn gethostbyaddr<T>(
    st: &mut ChannelState<T>,
    addrbuf: &[u8],
    family: i32,
    userdata: T,
) -> Result<Operation<Hostent>, AresError> {
    // family-validate -> buf_to_ip -> hosts reverse lookup -> no-servers -> PTR.
    if family != libc::AF_INET && family != libc::AF_INET6 {
        return Err(ARES_ENOTIMP.into());
    }
    let addr = buf_to_ip(addrbuf).map_err(|_| ARES_ENOTIMP)?;
    // Check hosts file first
    if let Some(lookup) = st.ares.hosts().reverse_lookup(addr) {
        return Ok(Operation::Ready(Hostent::from_lookup(lookup)));
    }
    // No servers configured
    if st.ares.config.nameservers.is_empty() {
        return Err(ARES_ENOSERVER.into());
    }
    issue(st, dns_query_payload(&rdns_name(addr), RECORD_TYPE_PTR), SocketSource::fresh(false), 0, userdata)?;
    if let Some(t) = st.ares.tasks.last_mut() {
        t.queried_ip = Some(addr);
        t.family = family;
        t.rtype = RECORD_TYPE_PTR;
    }
    Ok(Operation::Pending)
}

/// The synchronous result `ares_getnameinfo` can hand back: a service-only
/// answer, or a numeric-host answer. Both marshal straight to the C callback;
/// a PTR query on the wire is `Operation::Pending`, an error is `Err(status)`.
pub(crate) enum NameinfoResult {
    Service(Option<CString>),
    Numeric { node: CString, service: Option<CString> },
}

/// ares_getnameinfo: flag defaulting + the numeric/service short-circuits,
/// then the PTR query (whose fresh socket the channel's socket callback may
/// refuse → ECONNREFUSED). `userdata` is built by the shim and passed by
/// value (no factory closure); it is consumed only on the PTR-query path.
/// The LOOKUPHOST default the handler applies here affects only the path
/// decision — never the reply — so the shim's raw-flag userdata is correct.
pub(crate) fn getnameinfo<T>(
    st: &mut ChannelState<T>,
    addr: &AddrInfo,
    flags: i32,
    userdata: T,
) -> Result<Operation<NameinfoResult>, AresError> {
    // Adjust flags: if neither LOOKUPSERVICE nor LOOKUPHOST, default to LOOKUPHOST
    let flags = if (flags & ARES_NI_LOOKUPSERVICE) == 0 && (flags & ARES_NI_LOOKUPHOST) == 0 {
        flags | ARES_NI_LOOKUPHOST
    } else {
        flags
    };

    let want_host = (flags & ARES_NI_LOOKUPHOST) != 0;
    let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

    // If only service lookup requested (no host), deliver immediately
    if want_service && !want_host {
        return Ok(Operation::Ready(NameinfoResult::Service(get_service_string(st.ares.services(), addr.port, flags))));
    }

    // Host lookup requested (guaranteed by the defaulting above).
    // Numeric host can be handled without DNS
    if (flags & ARES_NI_NUMERICHOST) != 0 {
        // ARES_NI_NUMERICHOST + ARES_NI_NAMEREQD is illegal (contradiction)
        if (flags & ARES_NI_NAMEREQD) != 0 {
            return Err(ARES_EBADFLAGS.into());
        }
        let node = CString::new(format_ip_with_scope(&addr.ip, addr.scope_id, flags)).unwrap();
        let service = if want_service {
            get_service_string(st.ares.services(), addr.port, flags)
        } else {
            None
        };
        return Ok(Operation::Ready(NameinfoResult::Numeric { node, service }));
    }

    // PTR lookup required.
    issue(st, dns_query_payload(&rdns_name(addr.ip), RECORD_TYPE_PTR), SocketSource::fresh(false), 0, userdata)?;
    Ok(Operation::Pending)
}

/// ares_gethostbyname: the full pre-DNS cascade, then the pooled launch and
/// the failover probe. On exhaustion the probe still runs (its health
/// bookkeeping sees the launch failures), and ECONNREFUSED is delivered by
/// the shim afterwards. A synchronous hit (IP literal / hosts file / localhost
/// / query cache) is `Ok(Operation::Ready(hostent))`.
pub(crate) fn gethostbyname<T: Copy + Default>(
    st: &mut ChannelState<T>,
    hostname: &str,
    family: i32,
    now: Instant,
    binding: T,
) -> Result<Operation<Hostent>, AresError> {
    // Check order is behavior (each stage may deliver before the next runs):
    // ascii -> onion -> family-validate -> IP literal -> hosts file ->
    // localhost -> HOSTALIASES (fs read; PermissionDenied => Deliver(EFILE)) ->
    // no-servers -> query cache (evict expired; parse; sortlist; a cache-hit
    // parse error falls through to DNS) -> DNS launch.

    // Reject non-ASCII names
    if !hostname.is_ascii() {
        return Err(ARES_EBADNAME.into());
    }

    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(hostname) {
        return Err(ARES_ENOTFOUND.into());
    }

    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => return Err(ARES_ENOTIMP.into()),
    };

    // Check IP literal first
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let matches = match family_filter {
            AddressFamily::Ipv4 => ip.is_ipv4(),
            AddressFamily::Ipv6 => ip.is_ipv6(),
            AddressFamily::Any => true,
        };
        if matches {
            return Ok(Operation::Ready(Hostent::new(hostname.to_string(), vec![ip])));
        }
    }

    // Check hosts file
    let hosts_result = st.ares.hosts().lookup(hostname, family_filter);
    if let Some(ref lookup) = hosts_result {
        if !lookup.addrs.is_empty() {
            return Ok(Operation::Ready(Hostent::from_lookup(lookup.clone())));
        }
    }

    // RFC 6761 section 6.3: recognize "localhost" and any name under ".localhost"
    // as special and always return the loopback address.
    if is_localhost(hostname) {
        let addrs = match family_filter {
            AddressFamily::Ipv4 => vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            AddressFamily::Ipv6 => vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
            AddressFamily::Any => vec![
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            ],
        };
        return Ok(Operation::Ready(Hostent::new(hostname.to_string(), addrs)));
    }

    // Check HOSTALIASES env var for single-label names
    let hostname_str = hostname.to_string();
    let resolved_name = if !hostname.contains('.') {
        if let Ok(aliases_path) = std::env::var("HOSTALIASES") {
            match std::fs::read_to_string(&aliases_path) {
                Ok(content) => {
                    let mut alias_found = None;
                    for line in content.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(hostname) {
                            alias_found = Some(parts[1].to_string());
                            break;
                        }
                    }
                    alias_found.unwrap_or_else(|| hostname_str.clone())
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(ARES_EFILE.into());
                }
                Err(_) => hostname_str.clone(),
            }
        } else {
            hostname_str.clone()
        }
    } else {
        hostname_str.clone()
    };

    // No servers configured — return ENOSERVER immediately
    if st.ares.config.nameservers.is_empty() {
        return Err(ARES_ENOSERVER.into());
    }

    // Check query cache
    if st.query_cache_max_ttl > 0 {
        let record_type = match family {
            libc::AF_INET => RECORD_TYPE_A,
            libc::AF_INET6 => RECORD_TYPE_AAAA,
            libc::AF_UNSPEC => RECORD_TYPE_AAAA,
            _ => RECORD_TYPE_A,
        };
        let cache_key = (resolved_name.clone(), record_type);
        if let Some((cached_buf, expires_at)) = st.query_cache.get(&cache_key) {
            if now < *expires_at {
                let cached_buf = cached_buf.clone();
                let parsed = (|| -> Result<ParsedRRs<AddrRecord>, AresError> {
                    let response = ParsedResponse::from_buf(&cached_buf)?;
                    let parsed_rrs = response.process_answers::<AddrRecord>(&cached_buf, record_type)?;
                    if parsed_rrs.items.is_empty() {
                        return Err(ARES_ENODATA.into());
                    }
                    Ok(parsed_rrs)
                })();
                // On a cache-hit parse error, fall through to a fresh DNS query.
                if let Ok(mut parsed_rrs) = parsed {
                    if !st.sortlist.is_empty() {
                        apply_sortlist(&st.sortlist, &mut parsed_rrs.items);
                    }
                    let current_family = match family {
                        libc::AF_INET => libc::AF_INET,
                        libc::AF_INET6 => libc::AF_INET6,
                        _ => libc::AF_INET6,
                    };
                    return Ok(Operation::Ready(Hostent::from_parsed(parsed_rrs, current_family)));
                }
            } else {
                st.query_cache.remove(&cache_key);
            }
        }
    }

    // Build the search plan + state machine, then the pooled launch and the
    // failover probe. On exhaustion the probe still runs (its health
    // bookkeeping sees the launch failures) and ECONNREFUSED is delivered.
    let use_tcp = st.ares.config.options.use_vc;
    let plan = SearchPlan::for_gethostbyname(
        &resolved_name,
        st.ares.config.options.ndots,
        &st.ares.config.search,
    );
    let query_hostname = plan.current.clone();
    let sm = HostByNameSm::new(plan, family, use_tcp);
    let first_server = st.server_health.pick_next();

    let (send_family, send_rtype) = (sm.current_family, sm.expected_rtype);
    let handle = Rc::new(RefCell::new(sm));
    let launched = launch_pooled(st, &query_hostname, send_family, send_rtype, use_tcp, first_server, &handle, binding);
    // Server failover probing: if enabled, probe an expired-failure
    // server in parallel with the primary query (its binding is T::default).
    maybe_launch_probe(st, &query_hostname, send_family, first_server, use_tcp);
    match launched {
        LaunchOutcome::Launched => Ok(Operation::Pending),
        LaunchOutcome::Exhausted { .. } => Err(ARES_ECONNREFUSED.into()),
    }
}

/// The synchronous address result `ares_getaddrinfo` can hand back — an
/// IP-literal or hosts-file hit. (An async A/AAAA batch is `Operation::Pending`;
/// an error, including every socket refused, is `Err(status)`.)
pub(crate) struct AddrInfoResult {
    pub addrs: Vec<IpAddr>,
    pub canonical: String,
}

/// ares_getaddrinfo: preflight (empty/onion/IP-literal/hosts/no-servers),
/// then mint the machine and drive the A/AAAA batch.
pub(crate) fn getaddrinfo<T: Copy>(
    st: &mut ChannelState<T>,
    hostname_raw: &str,
    ai_family: i32,
    binding: T,
) -> Result<Operation<AddrInfoResult>, AresError> {
    // Check order is behavior: empty-name -> onion -> IP literal (family
    // mismatch fails, no fall-through) -> hosts file -> no-servers -> DNS.
    // The raw name keeps its trailing dot for the SearchPlan; checks and the
    // delivered canonical name use the stripped form.

    // A synchronous (IP-literal / hosts-file) hit: only addresses of the
    // requested family reach the node list.
    let deliver = |mut addrs: Vec<IpAddr>, canonical: String| {
        addrs.retain(|ip| match ip {
            IpAddr::V4(_) => ai_family == libc::AF_UNSPEC || ai_family == libc::AF_INET,
            IpAddr::V6(_) => ai_family == libc::AF_UNSPEC || ai_family == libc::AF_INET6,
        });
        Ok(Operation::Ready(AddrInfoResult { addrs, canonical }))
    };

    let hostname = hostname_raw.strip_suffix('.').unwrap_or(hostname_raw);

    if hostname.is_empty() {
        return Err(ARES_ENOTFOUND.into());
    }

    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(hostname) {
        return Err(ARES_ENOTFOUND.into());
    }

    // IP literal check
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let matches = match ai_family {
            libc::AF_INET => ip.is_ipv4(),
            libc::AF_INET6 => ip.is_ipv6(),
            libc::AF_UNSPEC => true,
            _ => false,
        };
        if matches {
            return deliver(vec![ip], hostname.to_string());
        } else {
            return Err(ARES_ENOTFOUND.into());
        }
    }

    // Hosts file check
    let family_filter = match ai_family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        _ => AddressFamily::Any,
    };
    if let Some(lookup) = st.ares.hosts().lookup(hostname, family_filter) {
        if !lookup.addrs.is_empty() {
            return deliver(lookup.addrs, hostname.to_string());
        }
    }

    // No servers configured
    if st.ares.config.nameservers.is_empty() {
        return Err(ARES_ENOSERVER.into());
    }

    // DNS path: mint the machine and drive the parallel A/AAAA batch.
    // (the raw name carries the trailing dot the plan needs to see)
    let use_tcp = st.ares.config.options.use_vc;
    let plan = SearchPlan::for_search(
        hostname_raw,
        st.ares.config.options.ndots,
        &st.ares.config.search,
    );
    let first_server = st.server_health.pick_next();
    let sm = AddrInfoSm::new(plan, ai_family, use_tcp);

    let handle = Rc::new(RefCell::new(sm));
    let actions = handle.borrow_mut().begin_batch(first_server);
    // At entry the batch can only yield nothing (still in flight) or a single
    // all-sockets-refused failure — never a synchronous success, which needs a
    // reply. `Ready` is terminal; the async result arrives via the reply path.
    match drive_addrinfo(st, &handle, actions, binding).as_slice() {
        [] => Ok(Operation::Pending),
        [AddrInfoDelivery::Fail { status }] => Err(*status),
        _ => unreachable!("getaddrinfo entry yields nothing or a single ECONNREFUSED"),
    }
}

/// ares_search's shim-side pre-check, re-exported so the shim's single
/// entry-ordering exception reads from the api layer.
pub(crate) use crate::core::preflight::search_name_check as search_precheck;

/// One C-side effect a settled gethostbyname task owes its owner, in firing
/// order relative to the other deliveries.
pub(crate) enum HostDelivery {
    NotifyServerFail { server: usize, tcp: bool },
    /// Sortlist already applied and the hostent shaped; build, deliver, free.
    Success { hostent: Hostent, timeouts: i32 },
    Fail { status: AresError, timeouts: i32 },
}

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

/// A gethostbyname task settled (reply or error): parse, feed the machine,
/// perform its re-sends (pooled launch) and cache stores, apply the
/// sortlist, and return what the shim must deliver to C.
#[allow(clippy::too_many_arguments)] // reply-executor seam: the task's binding rides along
pub(crate) fn on_hostbyname_reply<T: Copy>(
    st: &mut ChannelState<T>,
    sm: &Rc<RefCell<HostByNameSm>>,
    res: Result<&[u8], AresError>,
    server: usize,
    io_timeouts: i32,
    now: Instant,
    binding: T,
) -> Vec<HostDelivery> {
    // Parse outside the machine; the machine sees only the outcome.
    let mut parsed_items: Option<ParsedRRs<AddrRecord>> = None;
    let ev = match res {
        Ok(buf) => {
            let expected_rtype = sm.borrow().expected_rtype;
            let outcome = match addr_reply(buf, expected_rtype, ReplyRequire::Items) {
                Ok(rrs) => {
                    parsed_items = Some(rrs);
                    Ok(())
                }
                Err(e) => Err(e),
            };
            HostEvent::Reply { truncated: is_truncated(buf), parse: outcome, io_timeouts, server }
        }
        Err(status) => HostEvent::Error { status },
    };

    let actions = {
        let cfg = LookupCfg {
            attempts: st.ares.config.options.attempts,
            ndots: st.ares.config.options.ndots,
            search: &st.ares.config.search,
        };
        let mut machine = sm.borrow_mut();
        machine.step(ev, &cfg, &mut st.server_health)
    };

    let mut deliveries = Vec::new();
    for action in actions {
        match action {
            HostAction::Send { name, family, rtype, tcp, server } => {
                if let LaunchOutcome::Exhausted { timeouts } =
                    launch_pooled(st, &name, family, rtype, tcp, server, sm, binding)
                {
                    deliveries.push(HostDelivery::Fail { status: ARES_ECONNREFUSED.into(), timeouts });
                }
            }
            HostAction::NotifyServerFail { server, tcp } => {
                deliveries.push(HostDelivery::NotifyServerFail { server, tcp });
            }
            HostAction::CacheStore { names, rtype } => {
                if st.query_cache_max_ttl > 0 {
                    if let (Ok(buf), Some(rrs)) = (&res, &parsed_items) {
                        let ttl = rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                        cache_store_names(&mut st.query_cache, st.query_cache_max_ttl, names, rtype, ttl, buf, now);
                    }
                }
            }
            HostAction::DeliverSuccess { family, timeouts } => {
                let Some(mut rrs) = parsed_items.take() else { continue };
                if !st.sortlist.is_empty() {
                    apply_sortlist(&st.sortlist, &mut rrs.items);
                }
                deliveries.push(HostDelivery::Success { hostent: Hostent::from_parsed(rrs, family), timeouts });
            }
            HostAction::DeliverFail { status, timeouts } => {
                deliveries.push(HostDelivery::Fail { status, timeouts });
            }
        }
    }
    deliveries
}

/// What a settled search task owes its C callback (None: a follow-up query
/// went out and the lookup is still in flight).
pub(crate) enum SearchReplyDelivery {
    /// Deliver the (raw or parsed) reply buffer with SUCCESS.
    Success { timeouts: i32 },
    Fail { status: AresError, timeouts: i32 },
}

/// A search task settled: feed the machine, re-issue the next plan name if
/// asked (a failed re-issue reports ECONNREFUSED with zero timeouts, as
/// historically), or hand the delivery back to the shim.
pub(crate) fn on_search_reply<T>(
    st: &mut ChannelState<T>,
    sm: &Rc<RefCell<SearchSm>>,
    res: Result<&[u8], AresError>,
    dnstype: u16,
    io_timeouts: i32,
    binding: T,
) -> Option<SearchReplyDelivery> {
    let ev = match res {
        Ok(buf) => LookupEvent::Reply(buf),
        Err(status) => LookupEvent::Error(status),
    };
    let action = sm.borrow_mut().step(ev);
    match action {
        SearchAction::Send(next_name) => {
            match issue(st, dns_query_payload(&next_name, dnstype), SocketSource::Udp, 0, binding) {
                Ok(_) => {
                    if let Some(t) = st.ares.tasks.last_mut() { t.machine = TaskMachine::Search(sm.clone()); }
                    None
                }
                Err(status) => Some(SearchReplyDelivery::Fail { status, timeouts: 0 }),
            }
        }
        SearchAction::DeliverSuccess => Some(SearchReplyDelivery::Success { timeouts: io_timeouts }),
        SearchAction::DeliverFail(status) => Some(SearchReplyDelivery::Fail { status, timeouts: io_timeouts }),
    }
}

/// A probe task settled: fold the reply's rcode into the server-health
/// accounting. Some(ok) asks the shim to fire the server-state callback.
pub(crate) fn on_probe_reply(res: Result<&[u8], AresError>, server: usize, health: &mut ServerHealth) -> Option<bool> {
    match res {
        Ok(buf) => {
            let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0xff };
            if rcode == 0 || rcode == 3 {
                // Success or NXDOMAIN — the server is alive again.
                health.record_success(server).then_some(true)
            } else {
                // SERVFAIL/NOTIMP/REFUSED — still failing.
                health.record_failure(server).then_some(false)
            }
        }
        Err(_) => {
            // Timeout or other error — update the failure timestamp only.
            health.record_failure_time(server);
            None
        }
    }
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
