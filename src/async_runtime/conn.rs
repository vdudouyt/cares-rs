//! The async socket layer the resolver ops drive — tokio-style connections
//! over the executor's mailbox. This module knows sockets, framed streams,
//! and mux tags; it knows **zero** about its application: like the executor
//! it is generic over the mailbox's app-state `A`, and nothing in here names
//! a protocol or a wire format.
//!
//! - [`Conn`] — a query's connection. It owns its mailbox handle, so IO reads
//!   tokio-style: `conn.send(bytes, timeout).await` /
//!   `conn.recv(timeout).await`. The wire behind it is either an exclusively
//!   owned socket (a datagram socket, or a one-shot stream) or a checkout of a
//!   shared stream connection; the datagram-vs-demuxed-stream asymmetry is
//!   hidden behind the methods.
//! - [`TcpConn`] / [`TcpPool`] — shared stream connections, keyed by an opaque
//!   caller index so parallel queries to one peer share a socket. How the
//!   stream's bytes delimit messages is the application's business: the caller
//!   supplies the framer ([`FrameOf`]) that pops complete messages off the
//!   reassembly buffer, and the [`TagOf`] extractor that routes each message
//!   to a per-tag inbox slot. [`Conn::shared`] reserves a tag's slot and
//!   dropping the `Conn` releases it (RAII — no manual register/clear).
//!
//! The readiness-driven IO arms at the bottom are the plumbing between a
//! [`Socket`] and the mailbox: private here, they speak std vocabulary —
//! one non-blocking read/send attempt is a `Poll<io::Result<…>>`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Instant;

use futures_util::{select_biased, FutureExt};

use crate::async_runtime::executor::{sleep_until, Mailbox, Wait};
use crate::async_runtime::socket::{Socket, SocketFactory};

/// How a shared stream picks the inbox slot for an incoming frame: the frame's
/// mux tag. `None` = the frame is too short/malformed to carry one; it is
/// handed to any awaiting slot so the application can reject it.
pub type TagOf = fn(&[u8]) -> Option<u16>;

/// How a stream's bytes are cut into messages: pop one complete frame off the
/// reassembly buffer, or `None` until more bytes arrive. Message delimiting is
/// an application-protocol convention (a length prefix, a terminator, …) — TCP
/// itself has none and the runtime knows no wire format, so the caller
/// supplies this.
pub type FrameOf = fn(&mut Vec<u8>) -> Option<Vec<u8>>;

/// A shared stream connection to one peer, cooperatively driven by every
/// future that has an outstanding query on it: a per-connection reassembly
/// buffer plus the tag-demuxed inbox the futures share.
pub struct TcpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    rbuf: Vec<u8>,
    frame_of: FrameOf,
    tag_of: TagOf,
    /// tag -> reply slot: `None` = still awaited, `Some` = delivered, waiting
    /// to be taken by that future.
    inbox: HashMap<u16, Option<Vec<u8>>>,
}

impl TcpConn {
    /// Drain the socket, reassemble frames, and route each by its tag into
    /// `inbox` (frames with no registered waiter are dropped). Returns `false`
    /// if the connection died (EOF / hard error). Idempotent: a sibling future
    /// calling this after the socket is drained just no-ops.
    fn recv_and_route(&mut self) -> bool {
        let alive = recv_stream(&*self.sock, &mut self.rbuf);
        while let Some(frame) = (self.frame_of)(&mut self.rbuf) {
            if let Some(tag) = (self.tag_of)(&frame) {
                if let Some(slot) = self.inbox.get_mut(&tag) {
                    *slot = Some(frame);
                }
                // Unknown tag → drop (a stray/late frame).
            } else if let Some((_, slot)) = self.inbox.iter_mut().find(|(_, s)| s.is_none()) {
                // An untaggable frame: hand it to one awaiting waiter so the
                // application sees (and rejects) it.
                *slot = Some(frame);
            }
        }
        alive
    }
}

/// Shared stream connections keyed by an opaque caller index. A future
/// consults this before opening a stream socket so parallel queries to one
/// peer share a connection.
pub struct TcpPool {
    conns: HashMap<usize, Rc<RefCell<TcpConn>>>,
    frame_of: FrameOf,
    tag_of: TagOf,
}

impl TcpPool {
    pub fn new(frame_of: FrameOf, tag_of: TagOf) -> Self {
        TcpPool { conns: HashMap::new(), frame_of, tag_of }
    }

    pub fn clear(&mut self) {
        self.conns.clear();
    }

    /// Drop a dead connection so the next query to that peer reconnects.
    pub fn remove(&mut self, key: usize) {
        self.conns.remove(&key);
    }

    /// Reuse the live connection to `key`, else open one bound to `bind` and
    /// connect it to `to`.
    pub fn get_or_create(
        &mut self,
        key: usize,
        factory: &Rc<dyn SocketFactory>,
        bind: SocketAddr,
        to: SocketAddr,
    ) -> Result<Rc<RefCell<TcpConn>>, ()> {
        if let Some(c) = self.conns.get(&key) {
            return Ok(c.clone());
        }
        let sock = factory.create_tcp(bind).map_err(|_| ())?;
        let _ = sock.connect(to); // optimistic (EINPROGRESS → Ok)
        let fd = sock.as_raw_fd();
        let conn = Rc::new(RefCell::new(TcpConn {
            sock,
            fd,
            rbuf: Vec::new(),
            frame_of: self.frame_of,
            tag_of: self.tag_of,
            inbox: HashMap::new(),
        }));
        self.conns.insert(key, conn.clone());
        Ok(conn)
    }
}

/// A query's connection — the socket object the handler drives, tokio-style.
/// It **owns its mailbox** (`io`), so `send`/`recv` take no reactor handle:
/// `conn.send(bytes, timeout).await` / `conn.recv(timeout).await`, just
/// like `socket.recv(..).await`.
pub struct Conn<A> {
    io: Rc<RefCell<Mailbox<A>>>,
    wire: Wire,
}

/// The transport behind a [`Conn`]: an exclusively owned datagram socket, an
/// exclusively owned one-shot stream, or this query's tag on a shared stream
/// connection.
enum Wire {
    Datagram { sock: Rc<dyn Socket> },
    Stream { sock: Rc<dyn Socket>, rbuf: Vec<u8>, frame_of: FrameOf },
    Shared(Rc<RefCell<TcpConn>>, u16),
}

impl<A> Conn<A> {
    /// An owned datagram socket, already connected. One recv = one message.
    pub fn datagram(io: Rc<RefCell<Mailbox<A>>>, sock: Rc<dyn Socket>) -> Self {
        Conn { io, wire: Wire::Datagram { sock } }
    }

    /// An owned one-shot stream socket, already connected; `frame_of` cuts its
    /// bytes into messages.
    pub fn stream(io: Rc<RefCell<Mailbox<A>>>, sock: Rc<dyn Socket>, frame_of: FrameOf) -> Self {
        Conn { io, wire: Wire::Stream { sock, rbuf: Vec::new(), frame_of } }
    }

    /// A query's handle on a shared stream conn. Reserves `tag`'s inbox slot
    /// so a sibling future's read routes this query's reply here; the slot is
    /// released when the handle drops.
    pub fn shared(io: Rc<RefCell<Mailbox<A>>>, conn: Rc<RefCell<TcpConn>>, tag: u16) -> Self {
        conn.borrow_mut().inbox.insert(tag, None);
        Conn { io, wire: Wire::Shared(conn, tag) }
    }

    fn fd(&self) -> i32 {
        match &self.wire {
            Wire::Datagram { sock } | Wire::Stream { sock, .. } => sock.as_raw_fd(),
            Wire::Shared(c, _) => c.borrow().fd,
        }
    }

    pub fn is_tcp(&self) -> bool {
        !matches!(&self.wire, Wire::Datagram { .. })
    }

    /// Await writability, then send `bytes` once (WouldBlock re-awaits). The
    /// socket was connected at creation. Errors: the socket's own error on a
    /// hard send failure, `ErrorKind::TimedOut` on timeout before writable.
    pub async fn send(&self, bytes: &[u8], timeout: Instant) -> io::Result<()> {
        let sock: Rc<dyn Socket> = match &self.wire {
            Wire::Datagram { sock } | Wire::Stream { sock, .. } => sock.clone(),
            Wire::Shared(c, _) => c.borrow().sock.clone(),
        };
        send_when_writable(&self.io, &*sock, bytes, timeout).await
    }

    /// Take a message a **sibling** already routed into this tag's inbox slot
    /// (only possible on a shared conn: when two futures share one socket, the
    /// one that drains it routes the other's frames into their slots). Returns
    /// it without needing this conn's fd to fire — the draining sibling
    /// consumed the fd's readiness. `None` for owned conns (no sibling) or an
    /// empty slot.
    fn take_routed_slot(&mut self) -> Option<Vec<u8>> {
        match &self.wire {
            Wire::Shared(c, tag) => c.borrow_mut().inbox.get_mut(tag).and_then(|slot| slot.take()),
            _ => None,
        }
    }

    /// One non-blocking read of this conn's next message: a datagram, a framed
    /// one-shot stream message, or this tag's routed message off the shared
    /// conn. `Poll::Pending` = nothing yet (WouldBlock / incomplete).
    fn read(&mut self) -> Poll<io::Result<Vec<u8>>> {
        match &mut self.wire {
            Wire::Datagram { sock } => recv_datagram(&**sock),
            Wire::Stream { sock, rbuf, frame_of } => {
                // One-shot stream: drain bytes, then try to pop one frame. A
                // buffered frame delivers even on a dead socket; else a dead
                // socket errors, a live-but-incomplete is `Pending`.
                let alive = recv_stream(&**sock, rbuf);
                match frame_of(rbuf) {
                    Some(frame) => Poll::Ready(Ok(frame)),
                    None if !alive => Poll::Ready(Err(dead())),
                    None => Poll::Pending,
                }
            }
            Wire::Shared(c, tag) => {
                let mut conn = c.borrow_mut();
                let alive = conn.recv_and_route();
                match conn.inbox.get_mut(tag).and_then(|slot| slot.take()) {
                    Some(msg) => Poll::Ready(Ok(msg)),
                    None if !alive => Poll::Ready(Err(dead())),
                    None => Poll::Pending,
                }
            }
        }
    }

    /// Await this conn's next message with no timeout bound — usable directly
    /// as a `select_biased!` arm. On this conn's fd firing, does one
    /// non-blocking [`read`](Self::read) (a `WouldBlock` re-registers and
    /// suspends). Resolves `Ok(bytes)` or `Err(UnexpectedEof)` (dead socket).
    pub async fn recv_msg(&mut self) -> io::Result<Vec<u8>> {
        let fd = self.fd();
        let io = self.io.clone();
        poll_fn(move |_| {
            // A sibling sharing this socket may have already drained it and
            // routed our frame into our slot (consuming the fd's readiness in
            // the process); take it without waiting for our fd to fire again.
            if let Some(msg) = self.take_routed_slot() {
                return Poll::Ready(Ok(msg));
            }
            poll_recv(&io, fd, || self.read())
        })
        .await
    }

    /// tokio-style `conn.recv(timeout).await`: await this conn's next message,
    /// bounded by `timeout` (timeout arm first — the classic
    /// expiry-preempts-read order). Errors: `ErrorKind::TimedOut` on expiry,
    /// `ErrorKind::UnexpectedEof` on a dead socket (EOF / hard recv error).
    pub async fn recv(&mut self, timeout: Instant) -> io::Result<Vec<u8>> {
        let io = self.io.clone();
        let mut t = pin!(sleep_until(&io, timeout).fuse());
        let mut r = pin!(self.recv_msg().fuse());
        select_biased! {
            _ = t => Err(io::ErrorKind::TimedOut.into()),
            r = r => r,
        }
    }
}

/// Dropping a query's conn releases its shared-stream inbox slot (RAII — no
/// manual register/clear), so retries, delivery, and abandonment can't leak slots.
impl<A> Drop for Conn<A> {
    fn drop(&mut self) {
        if let Wire::Shared(c, tag) = &self.wire {
            c.borrow_mut().inbox.remove(tag);
        }
    }
}

// ===== Readiness-driven IO arms: the Socket ↔ mailbox plumbing =====

thread_local! {
    /// One reused 64 KB receive scratch buffer (a fresh `[0u8; 65535]` per recv
    /// would zero 64 KB every call). Single-threaded engine, borrowed only for
    /// the synchronous span of one recv.
    static RECV_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 65_535]);
}

/// The uniform dead-socket error (EOF / hard recv failure).
fn dead() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")
}

/// Await writability on `sock`, then send `bytes` once. Re-awaits on `WouldBlock`;
/// `Err(TimedOut)` on timeout before writable, the socket's own error on a hard
/// send failure. The writable arm is polled first — a fd that fired in the same
/// cycle the timeout passed still sends (writable preempts expiry).
async fn send_when_writable<A>(
    io: &Rc<RefCell<Mailbox<A>>>,
    sock: &dyn Socket,
    bytes: &[u8],
    timeout: Instant,
) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    loop {
        {
            let mut writable = pin!(poll_fn(|_| poll_writable(io, fd)).fuse());
            let mut t = pin!(sleep_until(io, timeout).fuse());
            select_biased! {
                _ = writable => {}
                _ = t => return Err(io::ErrorKind::TimedOut.into()), // timed out before writable
            }
        }
        match sock.send(bytes) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {} // re-await writable
            Err(e) => return Err(e),
        }
    }
}

/// One non-blocking receive of a self-delimiting datagram (UDP): `Ready(Ok)`
/// on any read (incl. a zero-length datagram), `Pending` on `WouldBlock`,
/// `Ready(Err)` on a hard error.
fn recv_datagram(sock: &dyn Socket) -> Poll<io::Result<Vec<u8>>> {
    RECV_BUF.with(|scratch| {
        let mut tmp = scratch.borrow_mut();
        match sock.recv(&mut tmp) {
            Ok((n, _)) => Poll::Ready(Ok(tmp[..n].to_vec())),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(_) => Poll::Ready(Err(dead())),
        }
    })
}

/// Drain a stream socket (TCP) once, appending whatever bytes are available to
/// `buf`. Returns `false` if the connection died (EOF / hard error). Does **not**
/// de-frame — the caller owns framing.
fn recv_stream(sock: &dyn Socket, buf: &mut Vec<u8>) -> bool {
    RECV_BUF.with(|scratch| {
        let mut tmp = scratch.borrow_mut();
        match sock.recv(&mut tmp) {
            Ok((0, _)) => false, // peer closed
            Ok((n, _)) => {
                buf.extend_from_slice(&tmp[..n]);
                true
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
            Err(_) => false,
        }
    })
}

/// The poll body of a recv arm (`conn.recv_msg()`, raced with `select_biased!`).
/// If `fd`'s **read** readiness fired this cycle, consume that entry
/// (`swap_remove`) and run `read` once; a `WouldBlock` (`Poll::Pending` from
/// `read`) re-registers read-interest and suspends (so a sibling arm can still
/// progress). Otherwise registers read-interest and suspends. Matches only
/// read-readiness, so a sibling send-arm's write-readiness on the same fd is
/// left alone. Resolves tokio-style: `Ok(bytes)` for a message,
/// `Err(UnexpectedEof)` for a dead socket. `read` yields opaque bytes — the
/// runtime names nothing of the app.
fn poll_recv<A>(
    io: &Rc<RefCell<Mailbox<A>>>,
    fd: i32,
    mut read: impl FnMut() -> Poll<io::Result<Vec<u8>>>,
) -> Poll<io::Result<Vec<u8>>> {
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
        Poll::Pending => {
            io.borrow_mut().waits.push(Wait { fd, writable: false });
            Poll::Pending
        }
        ready => ready,
    }
}

/// A writability arm: if `fd` fired this cycle, consume **that fd's**
/// readiness; otherwise register write-interest and suspend.
fn poll_writable<A>(io: &Rc<RefCell<Mailbox<A>>>, fd: i32) -> Poll<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::future::Future;
    use std::task::{Context, Waker};
    use std::time::Duration;

    fn mailbox() -> Rc<RefCell<Mailbox<()>>> {
        Rc::new(RefCell::new(Mailbox::default()))
    }

    fn rd(fd: i32) -> Wait {
        Wait { fd, writable: false }
    }

    #[test]
    fn poll_recv_not_fired_registers_wait() {
        let io = mailbox();
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Poll::Ready(Ok(vec![1]))
        });
        assert!(matches!(p, Poll::Pending));
        assert_eq!(calls.get(), 0); // read not attempted before readiness
        assert_eq!(io.borrow().waits.iter().map(|w| w.fd).collect::<Vec<_>>(), vec![7]);
    }

    #[test]
    fn poll_recv_fired_msg_consumes_only_its_fd() {
        let io = mailbox();
        io.borrow_mut().fired = vec![rd(3), rd(7), rd(9)];
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Poll::Ready(Ok(vec![42]))
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
            Poll::Ready(Ok(vec![1]))
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
            Poll::Pending
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
        let p = poll_recv(&io, 7, || Poll::Ready(Err(dead())));
        assert!(matches!(p, Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof));
    }

    /// A socket that always has a datagram waiting — so a recv arm that is
    /// polled goes `Ready(Ok(..))` immediately.
    struct AlwaysReadable {
        fd: i32,
    }
    impl Socket for AlwaysReadable {
        fn as_raw_fd(&self) -> i32 {
            self.fd
        }
        fn connect(&self, _addr: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            buf[..4].copy_from_slice(&[0xAB; 4]);
            Ok((4, None))
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }
    }

    /// `Conn::recv` must be **timeout-biased**: when a reply and the timeout are
    /// both ready in the same poll, expiry preempts the read. This guards the
    /// `select_biased!` in `recv` against being weakened to an unbiased
    /// `futures::select!` (which, given a datagram already waiting *and* an
    /// expired timeout, would pick the reply arm ~half the time). 100 trials
    /// make an accidental `select!` fail with probability `1 - 0.5^100` — i.e.
    /// deterministically for any real run — while `select_biased!` passes every
    /// trial. The scenario is constructed, not timing-raced, so this is stable.
    #[test]
    fn recv_is_timeout_biased_under_simultaneous_readiness() {
        for trial in 0..100 {
            let io = mailbox();
            // Both arms ready on the first poll: the read fd is fired (a datagram
            // is waiting) AND the deadline is already in the past.
            io.borrow_mut().fired = vec![rd(42)];
            let sock: Rc<dyn Socket> = Rc::new(AlwaysReadable { fd: 42 });
            let mut conn = Conn::datagram(io.clone(), sock);
            let past = Instant::now() - Duration::from_secs(1);

            let mut fut = pin!(conn.recv(past));
            let mut cx = Context::from_waker(Waker::noop());
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(r) => assert!(
                    r.is_err_and(|e| e.kind() == io::ErrorKind::TimedOut),
                    "trial {trial}: recv returned a reply while the timeout was \
                     also ready — Conn::recv must stay `select_biased!` \
                     (timeout arm first), not an unbiased `select!`",
                ),
                Poll::Pending => panic!("trial {trial}: both arms ready, must resolve"),
            }
        }
    }
}
