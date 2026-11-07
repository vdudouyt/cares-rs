//! DNS-over-TCP pooling: one shared, multiplexed connection per server (upstream:
//! one `server->tcp_conn`, all queries pipelined).

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::task::{Poll, Waker};

use crate::async_runtime::io::{dead, recv_stream};
use crate::async_runtime::socket::Socket;

/// Demux tag of a frame — its transaction id (header bytes 0..2). `None` for a
/// frame too short to carry one: it is handed to an awaiting waiter, which then
/// rejects it as EBADRESP.
pub(crate) fn dns_tag(frame: &[u8]) -> Option<u16> {
    frame.get(0..2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// DNS-over-TCP framing (RFC 1035 §4.2.2): a u16-BE length prefixes each
/// message. Pops one complete message off a reassembly buffer.
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

/// One tag's inbox slot: the routed reply plus the waiting task's waker, so a
/// sibling drain can wake a future with no fd readiness of its own.
struct InboxSlot {
    reply: Option<Vec<u8>>,
    waker: Option<Waker>,
}

impl InboxSlot {
    fn deliver(&mut self, frame: Vec<u8>) {
        self.reply = Some(frame);
        self.wake();
    }

    fn wake(&self) {
        if let Some(w) = &self.waker {
            w.wake_by_ref();
        }
    }
}

/// A shared stream connection to one server: a reassembly buffer plus the
/// tag-demuxed inbox every querying future shares.
pub(crate) struct TcpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    rbuf: Vec<u8>,
    inbox: HashMap<u16, InboxSlot>,
}

impl TcpConn {
    /// A fresh shared connection over `sock`, already created and connected by
    /// the caller outside any pool borrow so socket callbacks fire with no cell held.
    pub(crate) fn new(sock: Rc<dyn Socket>) -> Rc<RefCell<Self>> {
        let fd = sock.as_raw_fd();
        Rc::new(RefCell::new(TcpConn { sock, fd, rbuf: Vec::new(), inbox: HashMap::new() }))
    }

    /// Reserve a free inbox tag for a query. Rerolls from `qid` on collision (≈
    /// upstream `generate_unique_qid`, or two queries would clobber one slot);
    /// the caller must re-stamp its payload on a re-roll.
    pub(crate) fn reserve(
        &mut self,
        qid: u16,
        mut reroll: impl FnMut() -> u16,
    ) -> u16 {
        let mut tag = qid;
        while self.inbox.contains_key(&tag) {
            tag = reroll();
        }
        self.inbox.insert(tag, InboxSlot { reply: None, waker: None });
        tag
    }

    /// Remember the task waiting on `tag`, to be woken when a sibling routes its reply.
    pub(crate) fn register(&mut self, tag: u16, waker: &Waker) {
        if let Some(slot) = self.inbox.get_mut(&tag) {
            if !slot.waker.as_ref().is_some_and(|w| w.will_wake(waker)) {
                slot.waker = Some(waker.clone());
            }
        }
    }

    /// Release `tag`'s slot (RAII from `Conn`'s Drop; unknown tags are a no-op).
    pub(crate) fn release(&mut self, tag: u16) {
        self.inbox.remove(&tag);
    }

    pub(crate) fn sock(&self) -> Rc<dyn Socket> {
        self.sock.clone()
    }

    pub(crate) fn fd(&self) -> i32 {
        self.fd
    }

    /// Take a reply a **sibling** already routed into `tag`'s slot (it consumed
    /// the fd's readiness, so this must not read the socket).
    pub(crate) fn take(&mut self, tag: u16) -> Option<Vec<u8>> {
        self.inbox.get_mut(&tag).and_then(|slot| slot.reply.take())
    }

    /// Drain + route this cycle, then resolve `tag`: `Ready(Ok)` if a frame is now
    /// in its slot, `Ready(Err(UnexpectedEof))` if the connection died, else `Pending`.
    pub(crate) fn poll_read(&mut self, tag: u16, scratch: &mut Vec<u8>) -> Poll<io::Result<Vec<u8>>> {
        let alive = self.recv_and_route(scratch);
        match self.take(tag) {
            Some(msg) => Poll::Ready(Ok(msg)),
            None if !alive => Poll::Ready(Err(dead())),
            None => Poll::Pending,
        }
    }

    /// Drain the socket, reassemble frames, and route each by tag into `inbox`
    /// (unknown tags dropped); returns `false` if the connection died.
    fn recv_and_route(&mut self, scratch: &mut Vec<u8>) -> bool {
        let alive = recv_stream(&*self.sock, &mut self.rbuf, scratch);
        while let Some(frame) = dns_frame(&mut self.rbuf) {
            if let Some(tag) = dns_tag(&frame) {
                if let Some(slot) = self.inbox.get_mut(&tag) {
                    slot.deliver(frame);
                }
            } else if let Some(slot) = self.inbox.values_mut().find(|s| s.reply.is_none()) {
                // Untaggable frame: hand it to an awaiting waiter so the
                // application sees (and rejects) it.
                slot.deliver(frame);
            }
        }
        alive
    }
}

/// Shared stream connections per server (upstream: one `server->tcp_conn`, all
/// queries pipelined on it).
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

    pub fn remove(&mut self, key: usize) {
        self.conns.remove(&key);
    }

    /// The live connection to `key`. Callers clone the `Rc` so no pool borrow
    /// outlives this call: socket creation on a miss needs the pool unborrowed.
    pub fn get(&self, key: usize) -> Option<Rc<RefCell<TcpConn>>> {
        self.conns.get(&key).cloned()
    }

    pub fn insert(&mut self, key: usize, conn: Rc<RefCell<TcpConn>>) {
        self.conns.insert(key, conn);
    }
}

#[cfg(test)]
impl TcpConn {
    /// Whether `tag` has a reserved slot (fields are private to this module).
    pub(crate) fn has_waiter(&self, tag: u16) -> bool {
        self.inbox.contains_key(&tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// A socket with no bytes waiting, for tests that never read it.
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
    /// `generate_unique_qid`), and `release` frees only that tag.
    #[test]
    fn reserve_rerolls_colliding_tag() {
        let mut tc = TcpConn { sock: Rc::new(DummySock), fd: 5, rbuf: Vec::new(), inbox: HashMap::new() };
        assert_eq!(tc.reserve(7, || panic!("free qid must not reroll")), 7);

        // The reroll may collide again (7) before drawing a free id (9).
        let rolls = RefCell::new(vec![9u16, 7u16]); // popped back-to-front: 7, then 9
        assert_eq!(tc.reserve(7, || rolls.borrow_mut().pop().unwrap()), 9);
        assert!(rolls.borrow().is_empty());
        assert!(tc.has_waiter(7) && tc.has_waiter(9));

        tc.release(7);
        assert!(!tc.has_waiter(7) && tc.has_waiter(9));
    }
}
