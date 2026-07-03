//! Enqueue/consent primitives: the send-side building blocks the api layer
//! (and, until the launch loops finish moving, the ffi executors) compose.
//!
//! `Consent` is the one deliberately opaque hook: the shim wraps the
//! channel's C socket callbacks in a closure capturing only Copy data, so
//! core can run launch/retry policy without ever seeing a C pointer. A
//! consent closure must never hold a RefCell borrow — it runs while the
//! channel state is mutably borrowed and C callbacks may re-enter ares_*
//! only *after* these primitives return.

use std::cell::RefCell;
use std::rc::Rc;

use bytes::BytesMut;

use crate::core::ares::{dns_query_payload, qtype_of, Family, SocketSource, Status};
use crate::core::channel::ChannelState;
use crate::core::lookup::{AddrInfoAction, AddrInfoEvent, AddrInfoSm, HostByNameSm, LookupCfg};
use crate::ffi::error::ARES_ECONNREFUSED;
use crate::ffi::{RECORD_TYPE_A, RECORD_TYPE_AAAA};

/// "May this fresh socket (fd, is_tcp) proceed?" — the sock-create/config
/// callback verdict, injected by the shim.
pub(crate) type Consent<'a> = &'a mut dyn FnMut(i32, bool) -> bool;

/// What kind of task a gethostbyname flow enqueues; the shim's userdata
/// factory wraps it (plus the target server) into the task userdata.
pub(crate) enum HostTaskSeed {
    /// A lookup query feeding the shared machine.
    Lookup { sm: Rc<RefCell<HostByNameSm>>, family: i32, rtype: u16 },
    /// A failover probe: no user callback, only server-health effects.
    Probe { family: i32, rtype: u16 },
}

/// One send of a getaddrinfo batch, feeding the shared machine.
pub(crate) struct AddrInfoSeed {
    pub sm: Rc<RefCell<AddrInfoSm>>,
    pub family: i32,
    pub rtype: u16,
    pub timeouts: i32,
}

/// How a pooled launch (gethostbyname's send path) settled.
pub(crate) enum LaunchOutcome {
    Launched,
    /// Every attempt failed; `last_error` is already recorded on the machine
    /// and the accumulated timeout count rides along for the delivery.
    Exhausted { timeouts: i32 },
}

/// Send executor for the gethostbyname machine: reuse a pooled socket when
/// possible, otherwise create one — retrying across servers on socket-
/// creation or consent failure (the failure accounting is ServerHealth's).
#[allow(clippy::too_many_arguments)] // internal seam of api::gethostbyname / on_hostbyname_reply
pub(crate) fn launch_pooled<T>(
    st: &mut ChannelState<T>,
    hostname: &str,
    family: i32,
    rtype: u16,
    use_tcp: bool,
    server_index: usize,
    sm: &Rc<RefCell<HostByNameSm>>,
    make_userdata: &mut dyn FnMut(HostTaskSeed, usize) -> T,
    consent: Consent<'_>,
) -> LaunchOutcome {
    let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
    let max_tries = st.ares.config.options.attempts as usize;
    let nservers = st.server_health.len().max(1);
    let mut si = server_index;

    // TCP connection sharing: reuse an existing TCP connection to this server.
    if use_tcp {
        if let Some(idx) = st.tcp_connections.iter().position(|(s, _)| *s == si) {
            let shared_sock = st.tcp_connections[idx].1.clone();
            let userdata = make_userdata(HostTaskSeed::Lookup { sm: sm.clone(), family, rtype }, si);
            let _ = st.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::Shared(crate::core::ares::DnsSocket::Tcp(shared_sock)), si, userdata);
            return LaunchOutcome::Launched;
        }
        // No existing TCP connection — fall through to create one.
    }

    // UDP max queries: try to reuse an existing shared socket.
    if !use_tcp && st.udp_max_queries > 0 {
        let limit = st.udp_max_queries;
        if let Some(idx) = st.udp_connections.iter().position(|(s, _, c)| *s == si && *c < limit) {
            let shared_sock = st.udp_connections[idx].1.clone();
            st.udp_connections[idx].2 += 1;
            let userdata = make_userdata(HostTaskSeed::Lookup { sm: sm.clone(), family, rtype }, si);
            let _ = st.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::Shared(crate::core::ares::DnsSocket::Udp(shared_sock)), si, userdata);
            return LaunchOutcome::Launched;
        }
        // No reusable connection — create a fresh one, then pool it.
    }

    for _try in 0..max_tries {
        let userdata = make_userdata(HostTaskSeed::Lookup { sm: sm.clone(), family, rtype }, si);
        let issued = st.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), si, userdata).is_ok();
        if !issued {
            // Socket creation failed (e.g. fd exhaustion): treat as a server
            // failure and try the next server, like upstream c-ares.
            if nservers > 1 {
                st.server_health.record_failure(si);
                si = st.server_health.pick_next();
            }
            continue;
        }
        let fd = st.ares.tasks.last().expect("enqueue pushed").sock.as_raw_fd();
        if consent(fd, use_tcp) {
            // Add to the connection pool for reuse.
            if use_tcp {
                if let crate::core::ares::DnsSocket::Tcp(ref rc_sock) = st.ares.tasks.last().expect("just pushed").sock {
                    st.tcp_connections.push((si, rc_sock.clone()));
                }
            } else if st.udp_max_queries > 0 {
                if let crate::core::ares::DnsSocket::Udp(ref rc_sock) = st.ares.tasks.last().expect("just pushed").sock {
                    st.udp_connections.push((si, rc_sock.clone(), 1));
                }
            }
            return LaunchOutcome::Launched;
        }
        // Consent vetoed — close and remove the task, try the next server.
        st.ares.tasks.pop();
        if nservers > 1 {
            st.server_health.record_failure(si);
            si = st.server_health.pick_next();
        }
    }
    // All retries exhausted.
    let timeouts = {
        let mut machine = sm.borrow_mut();
        machine.last_error = ARES_ECONNREFUSED;
        machine.timeouts
    };
    LaunchOutcome::Exhausted { timeouts }
}

/// One delivery the getaddrinfo machine owes its C callback; the shim
/// marshals and fires them after the drive returns. Success carries the
/// machine's accumulated records (taken at emission), so the shim never
/// touches the machine.
pub(crate) enum AddrInfoDelivery {
    Success { name: String, records: Vec<crate::core::packets::AddrRecord> },
    Fail { status: i32 },
}

/// Drive the getaddrinfo machine's action queue: perform every Send (batch
/// sends honor the consent veto by completing the task and feeding
/// LaunchFailed back into the machine; re-sends run consent advisorily and
/// feed ResendFailed only on socket-creation failure), and collect the
/// Deliver* actions for the shim.
pub(crate) fn drive_addrinfo<T>(
    st: &mut ChannelState<T>,
    sm: &Rc<RefCell<AddrInfoSm>>,
    actions: Vec<AddrInfoAction>,
    make_userdata: &mut dyn FnMut(AddrInfoSeed, usize) -> T,
    consent: Consent<'_>,
) -> Vec<AddrInfoDelivery> {
    let mut deliveries = Vec::new();
    let mut queue: std::collections::VecDeque<AddrInfoAction> = actions.into();
    while let Some(action) = queue.pop_front() {
        match action {
            AddrInfoAction::Send { name, family, tcp, server, timeouts, batch } => {
                let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
                let rtype = if family == libc::AF_INET { RECORD_TYPE_A } else { RECORD_TYPE_AAAA };
                let userdata = make_userdata(AddrInfoSeed { sm: sm.clone(), family, rtype, timeouts }, server);
                let issued = st.ares.enqueue(dns_query_payload(&name, qtype_of(core_family)), SocketSource::fresh(tcp), server, userdata).is_ok();
                let failed = if !issued {
                    true
                } else if batch {
                    let fd = st.ares.tasks.last().expect("just pushed").sock.as_raw_fd();
                    if consent(fd, tcp) {
                        false
                    } else {
                        // Consent vetoed — mark the task completed with error.
                        st.ares.tasks.last_mut().expect("just pushed").status = Status::Completed;
                        true
                    }
                } else {
                    // TC/failover re-send: consent verdicts are ignored.
                    let fd = st.ares.tasks.last().expect("just pushed").sock.as_raw_fd();
                    consent(fd, tcp);
                    false
                };
                if failed {
                    let ev = if batch { AddrInfoEvent::LaunchFailed } else { AddrInfoEvent::ResendFailed };
                    let more = {
                        let cfg = LookupCfg {
                            attempts: st.ares.config.options.attempts,
                            ndots: st.ares.config.options.ndots,
                            search: &st.ares.config.search,
                        };
                        let mut machine = sm.borrow_mut();
                        machine.step(ev, &cfg, &mut st.server_health)
                    };
                    queue.extend(more);
                }
            }
            AddrInfoAction::DeliverSuccess { name } => {
                let records = std::mem::take(&mut sm.borrow_mut().addrs);
                deliveries.push(AddrInfoDelivery::Success { name, records });
            }
            AddrInfoAction::DeliverFail { status } => {
                deliveries.push(AddrInfoDelivery::Fail { status });
            }
        }
    }
    deliveries
}

/// Phase-1 TCP read path: accumulate stream bytes for this task's fd and
/// extract one length-prefixed frame if complete (which settles the task).
pub(crate) fn read_tcp_frame<T>(
    buffers: &mut std::collections::HashMap<i32, Vec<u8>>,
    task: &mut crate::core::ares::Task<T>,
    fd_readable: bool,
) -> Option<Vec<u8>> {
    let fd = task.sock.as_raw_fd();
    let rbuf = buffers.entry(fd).or_default();
    if fd_readable {
        let mut tmp = [0u8; 65535];
        match task.sock.recv(&mut tmp) {
            Ok((n, _)) if n > 0 => rbuf.extend_from_slice(&tmp[..n]),
            _ => {}
        }
    }
    let msg = crate::core::lookup::extract_tcp_frame(rbuf);
    if msg.is_some() {
        task.status = Status::Completed;
    }
    msg
}

/// Phase-2 timeout bookkeeping: count the expiry on the task, then take the
/// retry-or-fail verdict.
pub(crate) fn timeout_step<T>(
    task: &mut crate::core::ares::Task<T>,
    attempts: u32,
    server: usize,
    health: &mut crate::core::lookup::ServerHealth,
) -> crate::core::lookup::TimeoutVerdict {
    task.tries_remaining += 1;
    crate::core::lookup::on_timeout(task.tries_remaining, attempts, server, health)
}

/// Launch a probe query to an expired-failure server in parallel with the
/// primary query (no user callback; consent is advisory).
pub(crate) fn maybe_launch_probe<T>(
    st: &mut ChannelState<T>,
    hostname: &str,
    family: i32,
    primary_server: usize,
    use_tcp: bool,
    make_userdata: &mut dyn FnMut(HostTaskSeed, usize) -> T,
    consent: Consent<'_>,
) {
    if st.server_failover_retry_chance == 0 {
        return;
    }
    let probe_server = match st.server_health.pick_probe(st.server_failover_retry_delay, primary_server) {
        Some(s) => s,
        None => return,
    };
    let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
    let rtype = if family == libc::AF_INET { RECORD_TYPE_A } else { RECORD_TYPE_AAAA };
    let userdata = make_userdata(HostTaskSeed::Probe { family, rtype }, probe_server);
    // A probe has no user callback; if its socket can't be created, just skip it.
    if let Ok(fd) = issue(st, dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), probe_server, userdata) {
        consent(fd, use_tcp);
    }
}

/// Plain enqueue (no socket-callback involvement — ares_query/ares_send/
/// search flows). Ok(fd) of the task's socket.
pub(crate) fn issue<T>(
    st: &mut ChannelState<T>,
    payload: BytesMut,
    source: SocketSource,
    server: usize,
    userdata: T,
) -> Result<i32, ()> {
    st.ares.enqueue(payload, source, server, userdata).map_err(|_| ())?;
    Ok(st.ares.tasks.last().expect("enqueue pushed a task").sock.as_raw_fd())
}

/// Enqueue a fresh-socket query whose sock callbacks may veto it: a veto
/// pops the task and reports failure (the PTR entries gethostbyaddr /
/// getnameinfo deliver ECONNREFUSED on Err).
pub(crate) fn issue_consented<T>(
    st: &mut ChannelState<T>,
    payload: BytesMut,
    server: usize,
    userdata: T,
    is_tcp: bool,
    consent: Consent<'_>,
) -> Result<(), ()> {
    let fd = issue(st, payload, SocketSource::fresh(is_tcp), server, userdata)?;
    if !consent(fd, is_tcp) {
        st.ares.tasks.pop();
        return Err(());
    }
    Ok(())
}

/// Re-enqueue for a retry (TC upgrade, rcode failover, timeout): carries the
/// retry counter onto the new task and runs the sock callbacks advisorily —
/// their verdict is ignored for re-sends, as historically. False when the
/// socket could not be created (the caller delivers ECONNREFUSED).
pub(crate) fn reissue<T>(
    st: &mut ChannelState<T>,
    payload: BytesMut,
    source: SocketSource,
    server: usize,
    userdata: T,
    tries: u32,
    consent: Consent<'_>,
) -> bool {
    let Ok(fd) = issue(st, payload, source, server, userdata) else {
        return false;
    };
    let task = st.ares.tasks.last_mut().expect("issue pushed a task");
    task.tries_remaining = tries;
    let is_tcp = task.sock.is_tcp();
    consent(fd, is_tcp);
    true
}
