//! The DNS connection layer — framed/muxed connections the resolver
//! lifecycles drive, layered over `async_runtime`'s byte-level IO arms. This
//! is protocol business logic and deliberately lives in `core`, not in the
//! runtime: the runtime moves bytes on readiness; *this* module knows that a
//! TCP stream carries length-prefixed DNS messages ([`dns_frame`], RFC 1035
//! §4.2.2) and that concurrent queries share one connection per server,
//! demuxed by transaction id ([`dns_tag`]) — the upstream c-ares behavior the
//! gtest suite pins (32 parallel force-TCP lookups must create exactly one
//! socket).
//!
//! - [`Conn`] — a query's connection. It owns its mailbox handle, so IO reads
//!   tokio-style: `conn.send(bytes, timeout).await` /
//!   `conn.recv(timeout).await`. The wire behind it is either an exclusively
//!   owned socket (a datagram socket, or a one-shot stream) or a checkout of a
//!   shared stream connection; the datagram-vs-demuxed-stream asymmetry is
//!   hidden behind the methods.
//! - [`TcpConn`] / [`TcpPool`] — shared stream connections, keyed by server
//!   index so parallel queries to one server share a socket. Frames are
//!   reassembled per connection and routed by transaction id into a per-tag
//!   inbox slot. [`Conn::shared`] reserves a tag's slot and dropping the
//!   `Conn` releases it (RAII — no manual register/clear).

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

use crate::async_runtime::executor::sleep_until;
use crate::async_runtime::io::{dead, poll_recv, recv_datagram, recv_stream, send_when_writable};
use crate::async_runtime::socket::{Socket, SocketFactory};
use crate::core::async_client::DnsMailbox;

/// The mux tag of a DNS frame — its transaction ID (header bytes 0..2), the
/// demux key shared-TCP replies are routed by. `None` for a frame too short to
/// carry one: it is then handed to any awaiting waiter, which rejects it in
/// parsing (EBADRESP) — matching `qid_matches`'s acceptance of short buffers.
fn dns_tag(frame: &[u8]) -> Option<u16> {
    frame.get(0..2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// DNS-over-TCP message framing (RFC 1035 §4.2.2): each message is preceded
/// by a u16-BE length. Pop one complete message off a stream's reassembly
/// buffer, or `None` until it has accumulated. (`frame_tcp` in `async_client`
/// is the encode side.)
fn dns_frame(rbuf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if rbuf.len() < 2 {
        return None;
    }
    let payload_len = u16::from_be_bytes([rbuf[0], rbuf[1]]) as usize;
    if rbuf.len() < 2 + payload_len {
        return None;
    }
    let msg = rbuf[2..2 + payload_len].to_vec();
    rbuf.drain(..2 + payload_len);
    Some(msg)
}

/// A shared stream connection to one server, cooperatively driven by every
/// future that has an outstanding query on it: a per-connection reassembly
/// buffer plus the tag-demuxed inbox the futures share.
pub(crate) struct TcpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    rbuf: Vec<u8>,
    /// tag -> reply slot: `None` = still awaited, `Some` = delivered, waiting
    /// to be taken by that future.
    inbox: HashMap<u16, Option<Vec<u8>>>,
}

impl TcpConn {
    /// Drain the socket (via the reading lookup's `scratch`), reassemble
    /// frames, and route each by its tag into `inbox` (frames with no
    /// registered waiter are dropped). Returns `false` if the connection died
    /// (EOF / hard error). Idempotent: a sibling future calling this after the
    /// socket is drained just no-ops.
    fn recv_and_route(&mut self, scratch: &mut Vec<u8>) -> bool {
        let alive = recv_stream(&*self.sock, &mut self.rbuf, scratch);
        while let Some(frame) = dns_frame(&mut self.rbuf) {
            if let Some(tag) = dns_tag(&frame) {
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

/// Shared stream connections keyed by server index. A future consults this
/// before opening a stream socket so parallel queries to one server share a
/// connection (upstream: one `server->tcp_conn`, all queries pipelined on it).
pub(crate) struct TcpPool {
    conns: HashMap<usize, Rc<RefCell<TcpConn>>>,
}

impl TcpPool {
    pub fn new() -> Self {
        TcpPool { conns: HashMap::new() }
    }

    pub fn clear(&mut self) {
        self.conns.clear();
    }

    /// Drop a dead connection so the next query to that server reconnects.
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
            inbox: HashMap::new(),
        }));
        self.conns.insert(key, conn.clone());
        Ok(conn)
    }
}

/// A query's connection — the socket object the lifecycle drives, tokio-style.
/// It **owns its mailbox** (`io`), so `send`/`recv` take no reactor handle:
/// `conn.send(bytes, timeout).await` / `conn.recv(timeout).await`, just
/// like `socket.recv(..).await`.
pub(crate) struct Conn {
    io: Rc<RefCell<DnsMailbox>>,
    wire: Wire,
}

/// The transport behind a [`Conn`]: an exclusively owned datagram socket, an
/// exclusively owned one-shot stream, or this query's tag on a shared stream
/// connection.
enum Wire {
    Datagram { sock: Rc<dyn Socket> },
    Stream { sock: Rc<dyn Socket>, rbuf: Vec<u8> },
    Shared(Rc<RefCell<TcpConn>>, u16),
}

impl Conn {
    /// An owned datagram socket, already connected. One recv = one message.
    pub fn datagram(io: Rc<RefCell<DnsMailbox>>, sock: Rc<dyn Socket>) -> Self {
        Conn { io, wire: Wire::Datagram { sock } }
    }

    /// An owned one-shot stream socket, already connected; [`dns_frame`] cuts
    /// its bytes into messages.
    pub fn stream(io: Rc<RefCell<DnsMailbox>>, sock: Rc<dyn Socket>) -> Self {
        Conn { io, wire: Wire::Stream { sock, rbuf: Vec::new() } }
    }

    /// A query's handle on a shared stream conn. Reserves an inbox slot so a
    /// sibling future's read routes this query's reply here; the slot is
    /// released when the handle drops. `qid` is the query's current
    /// transaction id — if an in-flight sibling already owns that tag on this
    /// conn, fresh ids are drawn from `reroll` until one is free (≈ upstream
    /// `generate_unique_qid` in `ares_send.c`; without this the two queries
    /// would clobber one inbox slot and a reply would be lost). Returns the
    /// handle plus the tag actually reserved — on a re-roll the caller must
    /// re-stamp its payload with it.
    pub fn shared(
        io: Rc<RefCell<DnsMailbox>>,
        conn: Rc<RefCell<TcpConn>>,
        qid: u16,
        mut reroll: impl FnMut() -> u16,
    ) -> (Self, u16) {
        let tag = {
            let mut c = conn.borrow_mut();
            let mut tag = qid;
            while c.inbox.contains_key(&tag) {
                tag = reroll();
            }
            c.inbox.insert(tag, None);
            tag
        };
        (Conn { io, wire: Wire::Shared(conn, tag) }, tag)
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
    /// conn. `Poll::Pending` = nothing yet (WouldBlock / incomplete). The recv
    /// goes through this lookup's mailbox `scratch` (borrowed only for the
    /// synchronous span of the read).
    fn read(&mut self) -> Poll<io::Result<Vec<u8>>> {
        let mut m = self.io.borrow_mut();
        let scratch = &mut m.scratch;
        match &mut self.wire {
            Wire::Datagram { sock } => recv_datagram(&**sock, scratch),
            Wire::Stream { sock, rbuf } => {
                // One-shot stream: drain bytes, then try to pop one frame. A
                // buffered frame delivers even on a dead socket; else a dead
                // socket errors, a live-but-incomplete is `Pending`.
                let alive = recv_stream(&**sock, rbuf, scratch);
                match dns_frame(rbuf) {
                    Some(frame) => Poll::Ready(Ok(frame)),
                    None if !alive => Poll::Ready(Err(dead())),
                    None => Poll::Pending,
                }
            }
            Wire::Shared(c, tag) => {
                let mut conn = c.borrow_mut();
                let alive = conn.recv_and_route(scratch);
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
impl Drop for Conn {
    fn drop(&mut self) {
        if let Wire::Shared(c, tag) = &self.wire {
            c.borrow_mut().inbox.remove(tag);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_runtime::executor::Wait;
    use std::future::Future;
    use std::task::{Context, Waker};
    use std::time::Duration;

    #[test]
    fn dns_frame_extraction() {
        let mut rbuf = vec![0x00, 0x03, 1, 2, 3, 0x00];
        assert_eq!(dns_frame(&mut rbuf), Some(vec![1, 2, 3]));
        assert_eq!(rbuf, vec![0x00]); // partial next frame stays buffered
        assert_eq!(dns_frame(&mut rbuf), None);
        rbuf.push(0x02);
        assert_eq!(dns_frame(&mut rbuf), None); // length known, payload missing
        rbuf.extend_from_slice(&[9, 8]);
        assert_eq!(dns_frame(&mut rbuf), Some(vec![9, 8]));
        assert!(rbuf.is_empty());
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

    /// A colliding transaction id on a shared conn must be re-rolled until
    /// free (≈ upstream `generate_unique_qid`) — never clobber a sibling's
    /// inbox slot — and each handle's Drop must release only its own slot.
    #[test]
    fn shared_checkout_rerolls_colliding_qid() {
        let tc = Rc::new(RefCell::new(TcpConn {
            sock: Rc::new(AlwaysReadable { fd: 5 }),
            fd: 5,
            rbuf: Vec::new(),
            inbox: HashMap::new(),
        }));
        let io: Rc<RefCell<DnsMailbox>> = Rc::new(RefCell::new(DnsMailbox::default()));

        // First checkout: qid 7 is free — kept as-is, reroll never consulted.
        let (a, tag_a) = Conn::shared(io.clone(), tc.clone(), 7, || panic!("free qid must not reroll"));
        assert_eq!(tag_a, 7);

        // Second checkout collides on 7; the reroll may collide again (7)
        // before drawing a free id (9) — the loop must keep drawing.
        let rolls = RefCell::new(vec![9u16, 7u16]); // popped back-to-front: 7, then 9
        let (b, tag_b) = Conn::shared(io.clone(), tc.clone(), 7, || rolls.borrow_mut().pop().unwrap());
        assert_eq!(tag_b, 9);
        assert!(rolls.borrow().is_empty()); // both rolls consumed
        assert!(tc.borrow().inbox.contains_key(&7) && tc.borrow().inbox.contains_key(&9));

        // RAII: each handle releases exactly its own slot.
        drop(a);
        assert!(!tc.borrow().inbox.contains_key(&7));
        assert!(tc.borrow().inbox.contains_key(&9));
        drop(b);
        assert!(tc.borrow().inbox.is_empty());
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
            let io: Rc<RefCell<DnsMailbox>> = Rc::new(RefCell::new(DnsMailbox::default()));
            // Both arms ready on the first poll: the read fd is fired (a datagram
            // is waiting) AND the deadline is already in the past.
            io.borrow_mut().fired = vec![Wait { fd: 42, writable: false }];
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
