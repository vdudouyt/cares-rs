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

// ===== select: readiness-driven recv arms + a biased poll_fn combinator =====

/// The outcome of a recv arm resolving. `WouldBlock` never escapes — the arm
/// re-registers and suspends instead. Bytes are opaque to the reactor.
pub(crate) enum RecvReady {
    Msg(Vec<u8>),
    Dead,
}

/// A per-fd recv arm for use inside [`select2`]/[`select3`]. If `fd` fired this
/// cycle, consume **that fd's** readiness (`swap_remove`) and run `read` once;
/// a `WouldBlock` (`Recv::Pending`) re-registers read-interest and suspends (so a
/// sibling arm can still progress). Otherwise registers read-interest and
/// suspends. `read` yields opaque bytes — the reactor names nothing of the app.
pub(crate) fn poll_recv<A>(
    io: &Rc<RefCell<QueryIo<A>>>,
    fd: i32,
    mut read: impl FnMut() -> Recv,
) -> Poll<RecvReady> {
    let fired = {
        let mut m = io.borrow_mut();
        match m.fired.iter().position(|&f| f == fd) {
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
        Recv::Msg(b) => Poll::Ready(RecvReady::Msg(b)),
        Recv::Dead => Poll::Ready(RecvReady::Dead),
    }
}

/// A deadline arm: resolves once wall-clock passes `deadline`; otherwise mins
/// `deadline` into the mailbox and suspends. Reads `Instant::now()` directly
/// (ignores `io.expired`) so several deadline arms self-demux.
pub(crate) fn poll_deadline<A>(io: &Rc<RefCell<QueryIo<A>>>, deadline: Instant) -> Poll<()> {
    if Instant::now() >= deadline {
        return Poll::Ready(());
    }
    let mut m = io.borrow_mut();
    m.deadline = Some(m.deadline.map_or(deadline, |d| d.min(deadline)));
    Poll::Pending
}

/// Which arm of a [`select2`] resolved.
pub(crate) enum Which2<A, B> {
    A(A),
    B(B),
}
/// Which arm of a [`select3`] resolved.
pub(crate) enum Which3<A, B, C> {
    A(A),
    B(B),
    C(C),
}

/// Race two arms over the single mailbox, **biased** to `a`. Clears the mailbox's
/// `waits`/`deadline` once at the top of each poll cycle; each pending arm
/// re-registers. The first arm to return `Ready` wins (the others aren't polled
/// further this cycle). Pending propagates up so the ffi re-polls on readiness.
pub(crate) async fn select2<St, RA, RB>(
    io: &Rc<RefCell<QueryIo<St>>>,
    mut a: impl FnMut(&Rc<RefCell<QueryIo<St>>>) -> Poll<RA>,
    mut b: impl FnMut(&Rc<RefCell<QueryIo<St>>>) -> Poll<RB>,
) -> Which2<RA, RB> {
    std::future::poll_fn(|_cx| {
        {
            let mut m = io.borrow_mut();
            m.waits.clear();
            m.deadline = None;
        }
        if let Poll::Ready(v) = a(io) {
            return Poll::Ready(Which2::A(v));
        }
        if let Poll::Ready(v) = b(io) {
            return Poll::Ready(Which2::B(v));
        }
        Poll::Pending
    })
    .await
}

/// Race three arms over the single mailbox, biased `a` → `b` → `c`. See [`select2`].
pub(crate) async fn select3<St, RA, RB, RC>(
    io: &Rc<RefCell<QueryIo<St>>>,
    mut a: impl FnMut(&Rc<RefCell<QueryIo<St>>>) -> Poll<RA>,
    mut b: impl FnMut(&Rc<RefCell<QueryIo<St>>>) -> Poll<RB>,
    mut c: impl FnMut(&Rc<RefCell<QueryIo<St>>>) -> Poll<RC>,
) -> Which3<RA, RB, RC> {
    std::future::poll_fn(|_cx| {
        {
            let mut m = io.borrow_mut();
            m.waits.clear();
            m.deadline = None;
        }
        if let Poll::Ready(v) = a(io) {
            return Poll::Ready(Which3::A(v));
        }
        if let Poll::Ready(v) = b(io) {
            return Poll::Ready(Which3::B(v));
        }
        if let Poll::Ready(v) = c(io) {
            return Poll::Ready(Which3::C(v));
        }
        Poll::Pending
    })
    .await
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

    #[test]
    fn poll_recv_fired_msg_consumes_only_its_fd() {
        let io = mailbox();
        io.borrow_mut().fired = vec![3, 7, 9];
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Recv::Msg(vec![42])
        });
        assert!(matches!(p, Poll::Ready(RecvReady::Msg(ref b)) if b == &[42]));
        assert_eq!(calls.get(), 1);
        // Only fd 7 consumed; siblings 3 and 9 remain for their own arms.
        let fired = io.borrow().fired.clone();
        assert!(!fired.contains(&7) && fired.contains(&3) && fired.contains(&9));
    }

    #[test]
    fn poll_recv_wouldblock_reregisters_single_read() {
        let io = mailbox();
        io.borrow_mut().fired = vec![7];
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
        io.borrow_mut().fired = vec![7];
        let p = poll_recv(&io, 7, || Recv::Dead);
        assert!(matches!(p, Poll::Ready(RecvReady::Dead)));
    }

    #[test]
    fn poll_deadline_future_mins_and_pends() {
        let io = mailbox();
        let far = Instant::now() + Duration::from_secs(60);
        assert!(matches!(poll_deadline(&io, far), Poll::Pending));
        assert_eq!(io.borrow().deadline, Some(far));
        // A nearer deadline mins in.
        let near = Instant::now() + Duration::from_secs(1);
        assert!(matches!(poll_deadline(&io, near), Poll::Pending));
        assert_eq!(io.borrow().deadline, Some(near));
    }

    #[test]
    fn poll_deadline_past_ready() {
        let io = mailbox();
        let past = Instant::now() - Duration::from_secs(1);
        assert!(matches!(poll_deadline(&io, past), Poll::Ready(())));
    }
}
