//! Enqueue/consent primitives: the send-side building blocks the api layer
//! (and, until the launch loops finish moving, the ffi executors) compose.
//!
//! `Consent` is the one deliberately opaque hook: the shim wraps the
//! channel's C socket callbacks in a closure capturing only Copy data, so
//! core can run launch/retry policy without ever seeing a C pointer. A
//! consent closure must never hold a RefCell borrow — it runs while the
//! channel state is mutably borrowed and C callbacks may re-enter ares_*
//! only *after* these primitives return.

use bytes::BytesMut;

use crate::core::ares::SocketSource;
use crate::core::channel::ChannelState;

/// "May this fresh socket (fd, is_tcp) proceed?" — the sock-create/config
/// callback verdict, injected by the shim.
pub(crate) type Consent<'a> = &'a mut dyn FnMut(i32, bool) -> bool;

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
