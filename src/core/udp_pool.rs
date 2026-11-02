//! DNS-over-UDP connection pooling: one datagram socket per server (or a
//! small set of them when `ARES_OPT_UDP_MAX_QUERIES` caps how many queries may
//! share a socket), shared by every concurrent query and demuxed by
//! transaction id — the upstream c-ares behavior the gtest suite pins (32
//! parallel UDP lookups with a max of 8 must create exactly 4 sockets).
//!
//! - [`UdpConn`] — a shared connected datagram socket: the tag-demuxed inbox
//!   the querying futures share. Whoever drains the socket (`recv_and_route`)
//!   routes each datagram to the waiter its transaction id (`dns_tag`) belongs
//!   to. A query reserves a free inbox tag (`reserve`, rerolling on collision
//!   ≈ upstream `generate_unique_qid`) and releases it when its `Conn` drops.
//! - [`UdpPool`] — the per-server list of live `UdpConn`s a lookup consults
//!   (`pick_or_none`) before opening a datagram socket. Unlike TCP a server can
//!   have several UDP conns once the per-socket query cap is reached.
//!
//! Message framing is not needed for UDP (one datagram = one message); the
//! transaction tag is the first two header bytes, shared with the TCP demux
//! via [`crate::core::tcp_pool::dns_tag`]. The connection *facade* (`Conn`)
//! that drives one of these is in `core::conn`; this module owns only the
//! shared/pooled machinery.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::task::Poll;

use crate::async_runtime::io::{dead, recv_datagram};
use crate::async_runtime::socket::Socket;
use crate::core::tcp_pool::dns_tag;

/// A pooled datagram-connection handle.
pub(crate) type Conn = Rc<RefCell<UdpConn>>;

/// A checkout result: the selected conn (if any) plus idle conns pruned during
/// the lookup, both returned by value so the caller can drop retired sockets
/// after its pool borrow ends.
type Checkout = (Option<Conn>, Vec<Conn>);

/// A shared datagram connection to one server, cooperatively driven by every
/// future that has an outstanding query on it: the tag-demuxed inbox the
/// futures share. `core::conn::Conn` drives this through the crate API below
/// (`reserve`/`sock`/`fd`/`take`/`poll_read`/`release`); the fields stay
/// private to the pool.
pub(crate) struct UdpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    /// tag -> reply slot: `None` = still awaited, `Some` = delivered, waiting
    /// to be taken by that future.
    inbox: HashMap<u16, Option<Vec<u8>>>,
}

impl UdpConn {
    /// A fresh shared connection over `sock` — already created **and**
    /// connected by the caller, outside any pool borrow, so the C socket
    /// callbacks (asocket / create-cb / config-cb / aconnect) fire with no
    /// cell held.
    pub(crate) fn new(sock: Rc<dyn Socket>) -> Rc<RefCell<Self>> {
        let fd = sock.as_raw_fd();
        Rc::new(RefCell::new(UdpConn { sock, fd, inbox: HashMap::new() }))
    }

    /// Reserve a free inbox tag for a query. Starts from the query's current
    /// transaction id `qid`; if an in-flight sibling on this conn already owns
    /// it, fresh ids are drawn from `reroll` until one is free (≈ upstream
    /// `generate_unique_qid` in `ares_send.c`). Returns the tag actually
    /// reserved; on a re-roll the caller must re-stamp its payload.
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

    /// Drain + route every waiting datagram, then resolve `tag`'s next message:
    /// `Ready(Ok)` if a datagram is now in its slot, `Ready(Err(UnexpectedEof))`
    /// if the socket died with nothing buffered, `Pending` otherwise.
    pub(crate) fn poll_read(&mut self, tag: u16, scratch: &mut Vec<u8>) -> Poll<io::Result<Vec<u8>>> {
        let alive = self.recv_and_route(scratch);
        match self.take(tag) {
            Some(msg) => Poll::Ready(Ok(msg)),
            None if !alive => Poll::Ready(Err(dead())),
            None => Poll::Pending,
        }
    }

    /// Drain the socket until `WouldBlock`, routing each datagram by its tag
    /// into `inbox` (datagrams with no registered waiter are dropped). Returns
    /// `false` if the socket died (hard error). Idempotent: a sibling future
    /// calling this after the socket is drained just no-ops.
    fn recv_and_route(&mut self, scratch: &mut Vec<u8>) -> bool {
        let drain = self.sock.drain_safe();
        loop {
            match recv_datagram(&*self.sock, scratch) {
                Poll::Ready(Ok(frame)) => {
                    if let Some(tag) = dns_tag(&frame) {
                        if let Some(slot) = self.inbox.get_mut(&tag) {
                            *slot = Some(frame);
                        }
                        // Unknown tag → drop (a stray/late datagram).
                    } else if let Some((_, slot)) = self.inbox.iter_mut().find(|(_, s)| s.is_none()) {
                        // An untaggable datagram: hand it to one awaiting waiter
                        // so the application sees (and rejects) it.
                        *slot = Some(frame);
                    }
                    // A caller-supplied socket may be blocking; one datagram
                    // per readiness cycle is safe, and the next cycle picks up
                    // anything still queued.
                    if !drain {
                        return true;
                    }
                }
                Poll::Ready(Err(_)) => return false,
                Poll::Pending => return true,
            }
        }
    }

    /// How many queries currently own an inbox slot on this conn — the
    /// per-socket query count `ARES_OPT_UDP_MAX_QUERIES` caps.
    pub(crate) fn waiter_count(&self) -> usize {
        self.inbox.len()
    }

    /// No query currently owns this conn; an idle conn may be closed when
    /// `ARES_FLAG_STAYOPEN` is clear.
    pub(crate) fn is_empty(&self) -> bool {
        self.inbox.is_empty()
    }
}

/// Shared datagram connections keyed by server index. A future consults this
/// before opening a datagram socket so parallel queries to one server share a
/// connection (upstream: `server->connections`, capped by
/// `channel->udp_max_queries`).
pub(crate) struct UdpPool {
    conns: HashMap<usize, Vec<Conn>>,
}

impl UdpPool {
    pub fn new() -> Self {
        UdpPool { conns: HashMap::new() }
    }

    /// Drop every pooled connection, returning them so the caller can release
    /// the `Rc`s **after** its pool borrow ends (a socket close callback fires
    /// on the last drop).
    pub fn clear(&mut self) -> Vec<Conn> {
        let mut retired = Vec::new();
        for (_, mut list) in self.conns.drain() {
            retired.append(&mut list);
        }
        retired
    }

    /// Register a newly created connection for `server`.
    pub fn insert(&mut self, server: usize, conn: Conn) {
        self.conns.entry(server).or_default().push(conn);
    }

    /// Remove `conn` from `server`'s list (a dead socket / send failure). The
    /// removed handle is returned so the caller can drop it outside the pool
    /// borrow.
    pub fn remove(
        &mut self,
        server: usize,
        conn: &Conn,
    ) -> Vec<Conn> {
        let Some(list) = self.conns.get_mut(&server) else {
            return Vec::new();
        };
        let mut removed = Vec::new();
        list.retain(|c| {
            if Rc::ptr_eq(c, conn) {
                removed.push(c.clone());
                false
            } else {
                true
            }
        });
        if list.is_empty() {
            self.conns.remove(&server);
        }
        removed
    }

    /// Release an idle conn when `ARES_FLAG_STAYOPEN` is clear. Returns the
    /// removed handle for dropping after the pool borrow.
    pub fn release_if_idle(
        &mut self,
        server: usize,
        conn: &Conn,
        stayopen: bool,
    ) -> Vec<Conn> {
        if stayopen || !conn.borrow().is_empty() {
            return Vec::new();
        }
        self.remove(server, conn)
    }

    /// Check out a connection for a new query on `server`, or `None` when every
    /// existing conn already has `max_queries` waiters (`max_queries == 0` =
    /// unlimited) and the caller must create another socket. When `stayopen`
    /// is clear, idle conns are pruned first; the returned second vector holds
    /// any pruned handles, to be dropped after the pool borrow.
    pub fn pick_or_none(
        &mut self,
        server: usize,
        max_queries: usize,
        stayopen: bool,
    ) -> Checkout {
        let mut retired = Vec::new();
        let Some(list) = self.conns.get_mut(&server) else {
            return (None, retired);
        };
        if !stayopen {
            let mut kept = Vec::with_capacity(list.len());
            for conn in list.drain(..) {
                if conn.borrow().is_empty() {
                    retired.push(conn);
                } else {
                    kept.push(conn);
                }
            }
            *list = kept;
        }
        let picked = list
            .iter()
            .find(|conn| {
                let waiters = conn.borrow().waiter_count();
                max_queries == 0 || waiters < max_queries
            })
            .cloned();
        if list.is_empty() {
            self.conns.remove(&server);
        }
        (picked, retired)
    }
}

#[cfg(test)]
impl UdpConn {
    /// Whether `tag` currently has a reserved inbox slot (for checkout/RAII
    /// tests here and in `core::conn`; fields are private to this module).
    pub(crate) fn has_waiter(&self, tag: u16) -> bool {
        self.inbox.contains_key(&tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// A socket with no datagrams waiting — enough to stand up a `UdpConn` for
    /// the reservation/pool tests (which never read it).
    struct DummySock;
    impl Socket for DummySock {
        fn as_raw_fd(&self) -> i32 {
            5
        }
        fn connect(&self, _addr: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }
    }

    #[test]
    fn reserve_rerolls_colliding_tag() {
        let mut uc = UdpConn { sock: Rc::new(DummySock), fd: 5, inbox: HashMap::new() };

        assert_eq!(uc.reserve(7, || panic!("free qid must not reroll")), 7);
        let rolls = RefCell::new(vec![9u16, 7u16]); // popped back-to-front: 7, then 9
        assert_eq!(uc.reserve(7, || rolls.borrow_mut().pop().unwrap()), 9);
        assert!(rolls.borrow().is_empty());
        assert!(uc.has_waiter(7) && uc.has_waiter(9));

        uc.release(7);
        assert!(!uc.has_waiter(7) && uc.has_waiter(9));
        assert_eq!(uc.waiter_count(), 1);
    }

    #[test]
    fn pool_respects_max_queries_and_prunes_idle() {
        let mut pool = UdpPool::new();
        let conn = UdpConn::new(Rc::new(DummySock));
        conn.borrow_mut().reserve(1, || panic!("free qid must not reroll"));
        pool.insert(0, conn.clone());

        // max 1, one waiter -> full: no checkout.
        let (picked, retired) = pool.pick_or_none(0, 1, true);
        assert!(picked.is_none() && retired.is_empty());

        // max 2 -> reusable.
        let (picked, _) = pool.pick_or_none(0, 2, true);
        assert!(picked.is_some());

        // Idle conns are pruned when not staying open.
        conn.borrow_mut().release(1);
        let (picked, retired) = pool.pick_or_none(0, 2, false);
        assert!(picked.is_none());
        assert_eq!(retired.len(), 1);
    }
}
