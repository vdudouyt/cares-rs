//! The pure-IO reactor: a mailbox + await primitive + socket byte-pumps.
//!
//! This module knows **only** IO — file descriptors, readiness, deadlines, and
//! opaque bytes on a [`Socket`]. It has zero knowledge of what the bytes mean:
//! no DNS, no QID, no framing, no server health. A future publishes the fds it
//! is blocked on (+ an earliest deadline) into its [`QueryIo`] mailbox; the ffi
//! executor (driven by `ares_process`) sets which fds fired (or that the
//! deadline passed) and re-polls the one future. The waker is a no-op —
//! readiness is driven, not scheduled.
//!
//! The mailbox is generic over an opaque application-state type `A`
//! ([`QueryIo<A>`]); the reactor never inspects it. The DNS resolver lifecycle
//! that instantiates `A` and speaks these primitives lives in
//! `core::async_client`. Everything here is safe (`forbid(unsafe_code)`).

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Instant;

use crate::core::socket::Socket;

// ===== Mailbox + await primitive =====

/// One fd the future is blocked on, with the interest it awaits.
#[derive(Clone, Copy)]
pub(crate) struct Wait {
    pub fd: i32,
    pub writable: bool,
}

/// The mailbox shared (via `Rc<RefCell<_>>`) between one lifecycle future and
/// the ffi executor. The future publishes `waits`/`deadline` when it suspends;
/// the executor sets `fired`/`expired` before re-polling. Nothing here names
/// the channel, so polling the future borrows nothing of `ChannelData`. The
/// `app` field holds the application state the reactor treats as opaque.
#[derive(Default)]
pub(crate) struct QueryIo<A> {
    /// fds the future is currently blocked on (published on suspension).
    pub waits: Vec<Wait>,
    /// Earliest deadline the future wants to wake at.
    pub deadline: Option<Instant>,
    /// Which published-wait fds are ready now (set by the executor).
    pub fired: Vec<i32>,
    /// Whether the deadline passed (set by the executor).
    pub expired: bool,
    /// Application signals the reactor doesn't interpret (opaque to it).
    pub app: A,
}

/// The outcome of one [`wait_io`] await: which fds fired, and whether it timed out.
pub(crate) struct Woke {
    pub fds: Vec<i32>,
    pub expired: bool,
}

/// The await primitive: resolve once the executor reports readiness for the
/// currently published waits. Borrows the mailbox only inside `poll`, never
/// across `.await`.
struct Ready1<A> {
    io: Rc<RefCell<QueryIo<A>>>,
}

impl<A> Future for Ready1<A> {
    type Output = Woke;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Woke> {
        let mut io = self.io.borrow_mut();
        if io.fired.is_empty() && !io.expired {
            return Poll::Pending;
        }
        Poll::Ready(Woke { fds: std::mem::take(&mut io.fired), expired: io.expired })
    }
}

/// Publish the `waits` (+ `deadline`) into the mailbox — reusing its `waits`
/// allocation, so a per-await stack slice avoids a heap allocation — then await
/// readiness. Clears the published waits on return so a later await starts clean.
pub(crate) async fn wait_io<A>(io: &Rc<RefCell<QueryIo<A>>>, waits: &[Wait], deadline: Instant) -> Woke {
    {
        let mut m = io.borrow_mut();
        m.waits.clear();
        m.waits.extend_from_slice(waits);
        m.deadline = Some(deadline);
        m.fired.clear();
        m.expired = false;
    }
    let woke = Ready1 { io: io.clone() }.await;
    io.borrow_mut().waits.clear();
    woke
}

// ===== Sockets =====

thread_local! {
    /// One reused 64 KB receive scratch buffer (a fresh `[0u8; 65535]` per recv
    /// would zero 64 KB every call). Single-threaded engine, borrowed only for
    /// the synchronous span of one recv.
    static RECV_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 65_535]);
}

/// A receive outcome: a complete message, nothing yet (WouldBlock / incomplete
/// stream), or a dead socket (stream EOF / a hard recv error). Bytes are opaque.
pub(crate) enum Recv {
    Msg(Vec<u8>),
    Pending,
    Dead,
}

/// Await writability on `sock`, then send `bytes` once. Re-awaits on `WouldBlock`;
/// returns `false` on a hard error or on timeout before writable. Generic over the
/// mailbox app-state — the reactor never inspects `bytes`.
pub(crate) async fn send_when_writable<A>(
    io: &Rc<RefCell<QueryIo<A>>>,
    sock: &dyn Socket,
    bytes: &[u8],
    deadline: Instant,
) -> bool {
    let fd = sock.as_raw_fd();
    loop {
        let woke = wait_io(io, &[Wait { fd, writable: true }], deadline).await;
        if woke.expired && !woke.fds.contains(&fd) {
            return false; // timed out before writable
        }
        match sock.send(bytes) {
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {} // re-await writable
            Err(_) => return false,
        }
    }
}

/// Receive one self-delimiting datagram (UDP). `Msg` on any read (incl. a
/// zero-length datagram), `Pending` on `WouldBlock`, `Dead` on a hard error.
pub(crate) fn recv_datagram(sock: &dyn Socket) -> Recv {
    RECV_BUF.with(|scratch| {
        let mut tmp = scratch.borrow_mut();
        match sock.recv(&mut tmp) {
            Ok((n, _)) => Recv::Msg(tmp[..n].to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Recv::Pending,
            Err(_) => Recv::Dead,
        }
    })
}

/// Drain a stream socket (TCP) once, appending whatever bytes are available to
/// `buf`. Returns `false` if the connection died (EOF / hard error). Does **not**
/// de-frame — the caller owns framing.
pub(crate) fn recv_stream(sock: &dyn Socket, buf: &mut Vec<u8>) -> bool {
    RECV_BUF.with(|scratch| {
        let mut tmp = scratch.borrow_mut();
        match sock.recv(&mut tmp) {
            Ok((0, _)) => false, // peer closed
            Ok((n, _)) => {
                buf.extend_from_slice(&tmp[..n]);
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
            Err(_) => false,
        }
    })
}

// ===== Waker =====

/// Readiness is executor-driven, so waking need do nothing.
struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

thread_local! {
    static NOOP_WAKER: Waker = Waker::from(Arc::new(NoopWake));
}

/// A no-op `Waker` (safe: `std::task::Wake`, no `RawWaker`), cheaply cloned from
/// a cached instance.
pub(crate) fn noop_waker() -> Waker {
    NOOP_WAKER.with(|w| w.clone())
}
