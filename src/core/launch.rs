//! Enqueue primitives: the send-side building blocks the api layer (and,
//! until the launch loops finish moving, the ffi executors) compose.
//!
//! Socket creation can fail — including when a channel's socket callback
//! refuses a fresh fd (the factory returns Err, matching upstream
//! ares_conn.c). These primitives surface that as ECONNREFUSED / server
//! failover, exactly like any other socket-creation error; core never sees
//! the C callback.

use std::cell::RefCell;
use std::rc::Rc;

use bytes::BytesMut;

use crate::core::ares::{dns_query_payload, qtype_of, Family, SocketSource, Status, TaskMachine};
use crate::core::channel::ChannelState;
use crate::core::lookup::{AddrInfoAction, AddrInfoEvent, AddrInfoSm, HostByNameSm, LookupCfg};
use crate::ffi::error::ARES_ECONNREFUSED;
use crate::ffi::{RECORD_TYPE_A, RECORD_TYPE_AAAA};

/// Stamp the core-owned per-task data onto the task `enqueue` just pushed:
/// the state-machine handle plus the query's family/record-type (and, for a
/// batch send, the accumulated timeout count). The ffi userdata carries none
/// of this now — the reply reads it from the `Task`.
fn stamp<T>(st: &mut ChannelState<T>, machine: TaskMachine, family: i32, rtype: u16, timeouts: i32) {
    if let Some(t) = st.ares.tasks.last_mut() {
        t.machine = machine;
        t.family = family;
        t.rtype = rtype;
        t.timeouts = timeouts;
    }
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
pub(crate) fn launch_pooled<T: Copy>(
    st: &mut ChannelState<T>,
    hostname: &str,
    family: i32,
    rtype: u16,
    use_tcp: bool,
    server_index: usize,
    sm: &Rc<RefCell<HostByNameSm>>,
    binding: T,
) -> LaunchOutcome {
    let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
    let max_tries = st.ares.config.options.attempts as usize;
    let nservers = st.server_health.len().max(1);
    let mut si = server_index;
    let machine = || TaskMachine::HostByName(sm.clone());

    // TCP connection sharing: reuse an existing TCP connection to this server.
    if use_tcp {
        if let Some(idx) = st.tcp_connections.iter().position(|(s, _)| *s == si) {
            let shared_sock = st.tcp_connections[idx].1.clone();
            let _ = st.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::Shared(crate::core::ares::DnsSocket::Tcp(shared_sock)), si, binding);
            stamp(st, machine(), family, rtype, 0);
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
            let _ = st.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::Shared(crate::core::ares::DnsSocket::Udp(shared_sock)), si, binding);
            stamp(st, machine(), family, rtype, 0);
            return LaunchOutcome::Launched;
        }
        // No reusable connection — create a fresh one, then pool it.
    }

    for _try in 0..max_tries {
        if st.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), si, binding).is_ok() {
            stamp(st, machine(), family, rtype, 0);
            // Add the fresh socket to the connection pool for reuse.
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
        // Socket creation failed — fd exhaustion, or a socket callback refused
        // the fd: treat as a server failure and try the next, like upstream.
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

/// Drive the getaddrinfo machine's action queue: perform every Send (a failed
/// socket — creation error or a callback-refused fd — feeds LaunchFailed for a
/// batch send, or ResendFailed for a re-send, back into the machine) and
/// collect the Deliver* actions for the shim.
pub(crate) fn drive_addrinfo<T: Copy>(
    st: &mut ChannelState<T>,
    sm: &Rc<RefCell<AddrInfoSm>>,
    actions: Vec<AddrInfoAction>,
    binding: T,
) -> Vec<AddrInfoDelivery> {
    let mut deliveries = Vec::new();
    let mut queue: std::collections::VecDeque<AddrInfoAction> = actions.into();
    while let Some(action) = queue.pop_front() {
        match action {
            AddrInfoAction::Send { name, family, tcp, server, timeouts, batch } => {
                let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
                let rtype = if family == libc::AF_INET { RECORD_TYPE_A } else { RECORD_TYPE_AAAA };
                let failed = st.ares.enqueue(dns_query_payload(&name, qtype_of(core_family)), SocketSource::fresh(tcp), server, binding).is_err();
                if !failed {
                    stamp(st, TaskMachine::AddrInfo(sm.clone()), family, rtype, timeouts);
                }
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
/// primary query (no user callback; a failed/refused socket just skips it).
pub(crate) fn maybe_launch_probe<T: Default>(
    st: &mut ChannelState<T>,
    hostname: &str,
    family: i32,
    primary_server: usize,
    use_tcp: bool,
) {
    if st.server_failover_retry_chance == 0 {
        return;
    }
    let probe_server = match st.server_health.pick_probe(st.server_failover_retry_delay, primary_server) {
        Some(s) => s,
        None => return,
    };
    let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
    // Best-effort: if the probe's socket can't be created (or is refused), skip it.
    // A probe has no user callback (T::default) and no state machine
    // (Task.machine stays None).
    let _ = issue(st, dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), probe_server, T::default());
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

/// Re-enqueue for a retry (TC upgrade, rcode failover, timeout): carries the
/// retry counter onto the new task. False when the socket could not be created
/// — including a callback-refused fd — in which case the caller delivers
/// ECONNREFUSED.
pub(crate) fn reissue<T>(
    st: &mut ChannelState<T>,
    payload: BytesMut,
    source: SocketSource,
    server: usize,
    userdata: T,
    tries: u32,
) -> bool {
    if issue(st, payload, source, server, userdata).is_err() {
        return false;
    }
    st.ares.tasks.last_mut().expect("issue pushed a task").tries_remaining = tries;
    true
}
