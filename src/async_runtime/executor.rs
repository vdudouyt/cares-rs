//! The pure-IO reactor: a mailbox + await primitive + socket byte-pumps.
//!
//! This module knows **only** IO — file descriptors, readiness, timeouts, and
//! opaque bytes on a [`Socket`]. It has zero knowledge of what the bytes mean:
//! no DNS, no QID, no framing, no server health. A future publishes the fds it
//! is blocked on (+ an earliest timeout) into its [`QueryIo`] mailbox; the ffi
//! executor (driven by `ares_process`) sets which fds fired (or that the
//! timeout passed) and re-polls the one future. The waker is a no-op —
//! readiness is driven, not scheduled.
//!
//! The mailbox is generic over an opaque application-state type `A`
//! ([`QueryIo<A>`]); the reactor never inspects it. The DNS resolver lifecycle
//! that instantiates `A` and speaks these primitives lives in
//! `core::async_client`. Everything here is safe (`forbid(unsafe_code)`).

use std::cell::RefCell;
use std::future::{poll_fn, Future};
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Poll, Wake, Waker};
use std::time::Instant;

use futures_util::{select_biased, FutureExt};

use crate::async_runtime::socket::Socket;

// ===== Mailbox + await primitive =====

/// One fd the future is blocked on, with the interest it awaits.
#[derive(Clone, Copy)]
pub(crate) struct Wait {
    pub fd: i32,
    pub writable: bool,
}

/// The mailbox shared (via `Rc<RefCell<_>>`) between one lifecycle future and
/// the ffi executor. The future publishes `waits`/`timeout` when it suspends;
/// the executor sets `fired`/`expired` before re-polling. Nothing here names
/// the channel, so polling the future borrows nothing of `ChannelData`. The
/// `app` field holds the application state the reactor treats as opaque.
#[derive(Default)]
pub(crate) struct QueryIo<A> {
    /// fds the future is currently blocked on (published on suspension).
    pub waits: Vec<Wait>,
    /// Earliest timeout the future wants to wake at.
    pub timeout: Option<Instant>,
    /// Which published waits are ready now (set by the executor). Carries the
    /// interest (read vs write), not just the fd, so that when two arms share
    /// one fd with opposite interests a write-readiness isn't consumed by a
    /// read-arm (or vice versa).
    pub fired: Vec<Wait>,
    /// Application signals the reactor doesn't interpret (opaque to it).
    pub app: A,
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
/// `Err(TimedOut)` on timeout before writable, the socket's own error on a hard
/// send failure. The writable arm is polled first — a fd that fired in the same
/// cycle the timeout passed still sends (the historical wait_io preference).
/// Generic over the mailbox app-state — the reactor never inspects `bytes`.
pub(crate) async fn send_when_writable<A>(
    io: &Rc<RefCell<QueryIo<A>>>,
    sock: &dyn Socket,
    bytes: &[u8],
    timeout: Instant,
) -> std::io::Result<()> {
    let fd = sock.as_raw_fd();
    loop {
        {
            let mut writable = pin!(poll_fn(|_| poll_writable(io, fd)).fuse());
            let mut t = pin!(sleep_until(io, timeout).fuse());
            select_biased! {
                _ = writable => {}
                _ = t => return Err(std::io::ErrorKind::TimedOut.into()), // timed out before writable
            }
        }
        match sock.send(bytes) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {} // re-await writable
            Err(e) => return Err(e),
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

// ===== select: readiness-driven recv arms + a biased poll_fn combinator =====

/// A per-fd recv arm for use inside [`select2`]/[`select3`]. If `fd` fired this
/// cycle, consume **that fd's** readiness (`swap_remove`) and run `read` once;
/// a `WouldBlock` (`Recv::Pending`) re-registers read-interest and suspends (so a
/// sibling arm can still progress). Otherwise registers read-interest and
/// suspends. Resolves tokio-style: `Ok(bytes)` for a message, `Err(UnexpectedEof)`
/// for a dead socket. `read` yields opaque bytes — the reactor names nothing of
/// the app.
pub(crate) fn poll_recv<A>(
    io: &Rc<RefCell<QueryIo<A>>>,
    fd: i32,
    mut read: impl FnMut() -> Recv,
) -> Poll<std::io::Result<Vec<u8>>> {
    let fired = {
        let mut m = io.borrow_mut();
        match m.fired.iter().position(|w| w.fd == fd && !w.writable) {
            Some(pos) => {
                m.fired.swap_remove(pos);
                true
            }
            None => {
                m.waits.push(Wait { fd, writable: false });
                false
            }
        }
    };
    if !fired {
        return Poll::Pending;
    }
    match read() {
        Recv::Pending => {
            io.borrow_mut().waits.push(Wait { fd, writable: false });
            Poll::Pending
        }
        Recv::Msg(b) => Poll::Ready(Ok(b)),
        Recv::Dead => Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed",
        ))),
    }
}

/// A writability arm: if `fd` fired this cycle, consume **that fd's**
/// readiness; otherwise register write-interest and suspend.
fn poll_writable<A>(io: &Rc<RefCell<QueryIo<A>>>, fd: i32) -> Poll<()> {
    let mut m = io.borrow_mut();
    match m.fired.iter().position(|w| w.fd == fd && w.writable) {
        Some(pos) => {
            m.fired.swap_remove(pos);
            Poll::Ready(())
        }
        None => {
            m.waits.push(Wait { fd, writable: true });
            Poll::Pending
        }
    }
}

/// A timeout arm: resolves once wall-clock passes `timeout`; otherwise mins
/// `timeout` into the mailbox and suspends. Reads `Instant::now()` directly
/// so several timeout arms on one mailbox self-demux.
pub(crate) fn poll_timeout<A>(io: &Rc<RefCell<QueryIo<A>>>, timeout: Instant) -> Poll<()> {
    if Instant::now() >= timeout {
        return Poll::Ready(());
    }
    let mut m = io.borrow_mut();
    m.timeout = Some(m.timeout.map_or(timeout, |d| d.min(timeout)));
    Poll::Pending
}

/// Sleep until `timeout` (tokio-style), as a future usable directly as a
/// `select_biased!` arm.
pub(crate) fn sleep_until<A>(
    io: &Rc<RefCell<QueryIo<A>>>,
    timeout: Instant,
) -> impl Future<Output = ()> + '_ {
    poll_fn(move |_| poll_timeout(io, timeout))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    fn mailbox() -> Rc<RefCell<QueryIo<()>>> {
        Rc::new(RefCell::new(QueryIo::default()))
    }

    #[test]
    fn poll_recv_not_fired_registers_wait() {
        let io = mailbox();
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Recv::Msg(vec![1])
        });
        assert!(matches!(p, Poll::Pending));
        assert_eq!(calls.get(), 0); // read not attempted before readiness
        assert_eq!(io.borrow().waits.iter().map(|w| w.fd).collect::<Vec<_>>(), vec![7]);
    }

    fn rd(fd: i32) -> Wait {
        Wait { fd, writable: false }
    }

    #[test]
    fn poll_recv_fired_msg_consumes_only_its_fd() {
        let io = mailbox();
        io.borrow_mut().fired = vec![rd(3), rd(7), rd(9)];
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Recv::Msg(vec![42])
        });
        assert!(matches!(p, Poll::Ready(Ok(ref b)) if b == &[42]));
        assert_eq!(calls.get(), 1);
        // Only fd 7 consumed; siblings 3 and 9 remain for their own arms.
        let fds: Vec<i32> = io.borrow().fired.iter().map(|w| w.fd).collect();
        assert!(!fds.contains(&7) && fds.contains(&3) && fds.contains(&9));
    }

    #[test]
    fn poll_recv_ignores_a_write_readiness_on_its_fd() {
        // A read-arm must not consume a *write* readiness on the same fd (that
        // belongs to a sibling send-arm sharing the socket).
        let io = mailbox();
        io.borrow_mut().fired = vec![Wait { fd: 7, writable: true }];
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Recv::Msg(vec![1])
        });
        assert!(matches!(p, Poll::Pending));
        assert_eq!(calls.get(), 0); // did not read
        // The write readiness is left intact for the send-arm.
        assert!(io.borrow().fired.iter().any(|w| w.fd == 7 && w.writable));
    }

    #[test]
    fn poll_recv_wouldblock_reregisters_single_read() {
        let io = mailbox();
        io.borrow_mut().fired = vec![rd(7)];
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Recv::Pending
        });
        assert!(matches!(p, Poll::Pending));
        assert_eq!(calls.get(), 1); // read exactly once — no double recvfrom
        assert!(io.borrow().fired.is_empty()); // fd consumed
        assert_eq!(io.borrow().waits.iter().map(|w| w.fd).collect::<Vec<_>>(), vec![7]); // re-registered
    }

    #[test]
    fn poll_recv_dead() {
        let io = mailbox();
        io.borrow_mut().fired = vec![rd(7)];
        let p = poll_recv(&io, 7, || Recv::Dead);
        assert!(matches!(p, Poll::Ready(Err(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn poll_timeout_future_mins_and_pends() {
        let io = mailbox();
        let far = Instant::now() + Duration::from_secs(60);
        assert!(matches!(poll_timeout(&io, far), Poll::Pending));
        assert_eq!(io.borrow().timeout, Some(far));
        // A nearer timeout mins in.
        let near = Instant::now() + Duration::from_secs(1);
        assert!(matches!(poll_timeout(&io, near), Poll::Pending));
        assert_eq!(io.borrow().timeout, Some(near));
    }

    #[test]
    fn poll_timeout_past_ready() {
        let io = mailbox();
        let past = Instant::now() - Duration::from_secs(1);
        assert!(matches!(poll_timeout(&io, past), Poll::Ready(())));
    }
}
