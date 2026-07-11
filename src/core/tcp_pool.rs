//! DNS-over-TCP connection pooling: one TCP connection per server, shared by
//! every concurrent query to that server and demuxed by transaction id — the
//! upstream c-ares behavior the gtest suite pins (32 parallel force-TCP
//! lookups must create exactly one socket).
//!
//! - [`TcpConn`] — a shared stream connection: a per-connection reassembly
//!   buffer plus the tag-demuxed inbox the querying futures share. Whoever
//!   drains the socket (`recv_and_route`) routes each reassembled frame to the
//!   waiter its transaction id (`dns_tag`) belongs to. A query reserves a free
//!   inbox tag (`reserve`, rerolling on collision ≈ upstream
//!   `generate_unique_qid`) and releases it when its `Conn` drops.
//! - [`TcpPool`] — the per-server table of live `TcpConn`s a lookup consults
//!   (`get_or_create`) before opening a stream socket.
//!
//! Message framing (`dns_frame`, RFC 1035 §4.2.2 length prefix) lives here too,
//! shared with `core::conn`'s one-shot stream path. The connection *facade*
//! (`Conn`) that drives one of these is in `core::conn`; this module owns only
//! the shared/pooled machinery.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::task::Poll;

use crate::async_runtime::io::{dead, recv_stream};
use crate::async_runtime::socket::{Socket, SocketFactory};

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
pub(crate) fn dns_frame(rbuf: &mut Vec<u8>) -> Option<Vec<u8>> {
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
/// buffer plus the tag-demuxed inbox the futures share. `core::conn::Conn`
/// drives this through the crate API below (`reserve`/`sock`/`fd`/`take`/
/// `poll_read`/`release`); the fields stay private to the pool.
pub(crate) struct TcpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    rbuf: Vec<u8>,
    /// tag -> reply slot: `None` = still awaited, `Some` = delivered, waiting
    /// to be taken by that future.
    inbox: HashMap<u16, Option<Vec<u8>>>,
}

impl TcpConn {
    /// Reserve a free inbox tag for a query. Starts from the query's current
    /// transaction id `qid`; if an in-flight sibling on this conn already owns
    /// it, fresh ids are drawn from `reroll` until one is free (≈ upstream
    /// `generate_unique_qid` in `ares_send.c` — without this the two queries
    /// would clobber one inbox slot and a reply would be lost). Returns the tag
    /// actually reserved; on a re-roll the caller must re-stamp its payload.
    pub(crate) fn reserve(&mut self, qid: u16, mut reroll: impl FnMut() -> u16) -> u16 {
        let mut tag = qid;
        while self.inbox.contains_key(&tag) {
            tag = reroll();
        }
        self.inbox.insert(tag, None);
        tag
    }

    /// Release `tag`'s inbox slot (called from `Conn`'s Drop — RAII, no manual
    /// clear). An unknown tag is a no-op.
    pub(crate) fn release(&mut self, tag: u16) {
        self.inbox.remove(&tag);
    }

    /// This connection's socket (for sending) — cheaply cloned.
    pub(crate) fn sock(&self) -> Rc<dyn Socket> {
        self.sock.clone()
    }

    /// This connection's fd (for readiness registration).
    pub(crate) fn fd(&self) -> i32 {
        self.fd
    }

    /// Take a reply a **sibling** already routed into `tag`'s slot, if any —
    /// without reading the socket (the draining sibling consumed the fd's
    /// readiness). `None` for an empty or unknown slot.
    pub(crate) fn take(&mut self, tag: u16) -> Option<Vec<u8>> {
        self.inbox.get_mut(&tag).and_then(|slot| slot.take())
    }

    /// Drain + route this cycle, then resolve `tag`'s next message: `Ready(Ok)`
    /// if a frame is now in its slot, `Ready(Err(UnexpectedEof))` if the
    /// connection died with nothing buffered, `Pending` otherwise.
    pub(crate) fn poll_read(&mut self, tag: u16, scratch: &mut Vec<u8>) -> Poll<io::Result<Vec<u8>>> {
        let alive = self.recv_and_route(scratch);
        match self.take(tag) {
            Some(msg) => Poll::Ready(Ok(msg)),
            None if !alive => Poll::Ready(Err(dead())),
            None => Poll::Pending,
        }
    }

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

#[cfg(test)]
impl TcpConn {
    /// A `TcpConn` around `sock` with an empty inbox — for `core::conn`'s
    /// checkout/RAII tests (its fields are private to this module).
    pub(crate) fn stub(sock: Rc<dyn Socket>) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(TcpConn { sock, fd: 5, rbuf: Vec::new(), inbox: HashMap::new() }))
    }

    /// Whether `tag` currently has a reserved inbox slot.
    pub(crate) fn has_waiter(&self, tag: u16) -> bool {
        self.inbox.contains_key(&tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A socket with no bytes waiting — enough to stand up a `TcpConn` for the
    /// tag-reservation tests (which never read it).
    struct DummySock;
    impl Socket for DummySock {
        fn as_raw_fd(&self) -> i32 {
            5
        }
        fn connect(&self, _addr: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            Ok((0, None))
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }
    }

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

    /// A colliding transaction id must be re-rolled until free (≈ upstream
    /// `generate_unique_qid`) — never clobber a sibling's inbox slot — and
    /// `release` frees only that tag.
    #[test]
    fn reserve_rerolls_colliding_tag() {
        let mut tc = TcpConn { sock: Rc::new(DummySock), fd: 5, rbuf: Vec::new(), inbox: HashMap::new() };

        // Free qid kept as-is; reroll never consulted.
        assert_eq!(tc.reserve(7, || panic!("free qid must not reroll")), 7);

        // Collision on 7: the reroll may collide again (7) before drawing a
        // free id (9) — the loop must keep drawing.
        let rolls = RefCell::new(vec![9u16, 7u16]); // popped back-to-front: 7, then 9
        assert_eq!(tc.reserve(7, || rolls.borrow_mut().pop().unwrap()), 9);
        assert!(rolls.borrow().is_empty()); // both rolls consumed
        assert!(tc.has_waiter(7) && tc.has_waiter(9));

        tc.release(7);
        assert!(!tc.has_waiter(7) && tc.has_waiter(9));
    }
}
