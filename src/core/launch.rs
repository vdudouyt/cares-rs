//! Reactor-side task helpers that operate on a single in-flight `Task`
//! (TCP frame reassembly and timeout bookkeeping), plus the two send-outcome
//! types the resolver methods on `Client` hand back to the ffi executors.
//!
//! The enqueue primitives and launch loops themselves are now methods on
//! `Client` (see `core::client`); only the `Task`-taking helpers and these
//! outcome types remain here.

use crate::core::transport::Status;
use crate::core::AresError;

/// One delivery the getaddrinfo machine owes its C callback; the shim
/// marshals and fires them after the drive returns. Success carries the
/// machine's accumulated records (taken at emission), so the shim never
/// touches the machine.
pub(crate) enum AddrInfoDelivery {
    Success { name: String, records: Vec<crate::core::packets::AddrRecord> },
    Fail { status: AresError },
}

/// Phase-1 TCP read path: accumulate stream bytes for this task's fd and
/// extract one length-prefixed frame if complete (which settles the task).
pub(crate) fn read_tcp_frame<T>(
    buffers: &mut std::collections::HashMap<i32, Vec<u8>>,
    task: &mut crate::core::transport::Task<T>,
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
    task: &mut crate::core::transport::Task<T>,
    attempts: u32,
    server: usize,
    health: &mut crate::core::lookup::ServerHealth,
) -> crate::core::lookup::TimeoutVerdict {
    task.tries_remaining += 1;
    crate::core::lookup::on_timeout(task.tries_remaining, attempts, server, health)
}
