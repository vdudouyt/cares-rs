//! DNS-over-UDP connection pooling: one datagram socket per server (or a
//! small set of them when `ARES_OPT_UDP_MAX_QUERIES` caps how many queries may
//! be sent on a socket), shared by every concurrent query and demuxed by
//! transaction id — the upstream c-ares behavior the gtest suite pins (32
//! parallel UDP lookups with a max of 8 must create exactly 4 sockets).
//!
//! - [`UdpConn`] — a shared connected datagram socket: the tag-demuxed inbox
//!   the querying futures share. Whoever drains the socket (`recv_and_route`)
//!   routes each datagram to the waiter its transaction id (`dns_tag`) belongs
//!   to. A query reserves a free inbox tag (`reserve`, rerolling on collision
//!   ≈ upstream `generate_unique_qid`) and releases it when its `Conn` drops.
//!   `total_queries` counts every query ever sent on the conn (upstream's
//!   per-connection cap, not just the currently outstanding waiters).
//! - [`UdpPool`] — the per-server list of live `UdpConn`s a lookup consults
//!   (`pick_or_none`) before opening a datagram socket. Unlike TCP a server can
//!   have several UDP conns once the per-socket query cap is reached.
//!
//! Message framing is not needed for UDP (one datagram = one message); the
//! transaction tag is the first two header bytes, shared with the TCP demux
//! via [`crate::core::tcp_pool::dns_tag`]. The connection *facade* (`Conn`)
//! that drives one of these is in `core::conn`; this module owns only the
//! shared/pooled machinery. It stays separate from `tcp_pool` because the
//! transports differ in framing, buffering, and lifecycle: TCP has one conn
//! per server with a reassembly buffer, while UDP has a list capped by
//! `total_queries` and retires sockets as they become exhausted.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::task::Poll;

use crate::async_runtime::io::{dead, recv_datagram};
use crate::async_runtime::socket::Socket;
use crate::core::async_client::DnsMailbox;
use crate::core::tcp_pool::dns_tag;

/// A pooled datagram-connection handle.
pub(crate) type Conn = Rc<RefCell<UdpConn>>;

/// A checkout result: the selected conn (if any) plus conns retired during the
/// lookup, both returned by value so the caller can drop retired sockets after
/// its pool borrow ends.
type Checkout = (Option<Conn>, Vec<Conn>);

/// One tag's inbox slot: the routed reply (once it arrives) plus the target
/// lookup's mailbox, flagged `routed` so a sibling drain wakes a future that
/// had already suspended with no fd readiness of its own.
struct InboxSlot {
    reply: Option<Vec<u8>>,
    notify: Rc<RefCell<DnsMailbox>>,
}

/// A shared datagram connection to one server, cooperatively driven by every
/// future that has an outstanding query on it: the tag-demuxed inbox the
/// futures share. `core::conn::Conn` drives this through the crate API below
/// (`reserve`/`sock`/`fd`/`take`/`poll_read`/`release`); the fields stay
/// private to the pool.
pub(crate) struct UdpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    /// tag -> reply slot (reply + target mailbox).
    inbox: HashMap<u16, InboxSlot>,
    /// Every query ever reserved on this conn. `ARES_OPT_UDP_MAX_QUERIES`
    /// caps this total (upstream `conn->total_queries`), so an exhausted conn
    /// is retired even if its current waiters later drain.
    total_queries: usize,
}

impl UdpConn {
    /// A fresh shared connection over `sock` — already created **and**
    /// connected by the caller, outside any pool borrow, so the C socket
    /// callbacks (asocket / create-cb / config-cb / aconnect) fire with no
    /// cell held.
    pub(crate) fn new(sock: Rc<dyn Socket>) -> Rc<RefCell<Self>> {
        let fd = sock.as_raw_fd();
        Rc::new(RefCell::new(UdpConn {
            sock,
            fd,
            inbox: HashMap::new(),
            total_queries: 0,
        }))
    }

    /// Reserve a free inbox tag for a query, registering `io` as the mailbox to
    /// flag when a sibling routes this tag's reply, and count the query against
    /// the per-conn total. Starts from the query's current transaction id
    /// `qid`; if an in-flight sibling on this conn already owns it, fresh ids
    /// are drawn from `reroll` until one is free (≈ upstream
    /// `generate_unique_qid` in `ares_send.c`). Returns the tag actually
    /// reserved; on a re-roll the caller must re-stamp its payload.
    pub(crate) fn reserve(
        &mut self,
        qid: u16,
        mut reroll: impl FnMut() -> u16,
        io: Rc<RefCell<DnsMailbox>>,
    ) -> u16 {
        let mut tag = qid;
        while self.inbox.contains_key(&tag) {
            tag = reroll();
        }
        self.inbox.insert(tag, InboxSlot { reply: None, notify: io });
        self.total_queries += 1;
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
        self.inbox.get_mut(&tag).and_then(|slot| slot.reply.take())
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
                            slot.reply = Some(frame);
                            slot.notify.borrow_mut().routed = true;
                        }
                        // Unknown tag → drop (a stray/late datagram).
                    } else if let Some(slot) = self.inbox.values_mut().find(|s| s.reply.is_none()) {
                        // An untaggable datagram: hand it to one awaiting waiter
                        // so the application sees (and rejects) it.
                        slot.reply = Some(frame);
                        slot.notify.borrow_mut().routed = true;
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

    /// How many queries currently own an inbox slot on this conn.
    #[cfg(test)]
    pub(crate) fn waiter_count(&self) -> usize {
        self.inbox.len()
    }

    /// Every query ever sent on this conn (the `ARES_OPT_UDP_MAX_QUERIES`
    /// counter).
    #[cfg(test)]
    pub(crate) fn total_queries(&self) -> usize {
        self.total_queries
    }

    /// No query currently owns this conn; an idle conn may be closed when
    /// `ARES_FLAG_STAYOPEN` is clear.
    pub(crate) fn is_empty(&self) -> bool {
        self.inbox.is_empty()
    }

    /// The per-conn cap is spent (`max_queries == 0` means unlimited).
    fn exhausted(&self, max_queries: usize) -> bool {
        max_queries != 0 && self.total_queries >= max_queries
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

    /// Retire a conn when its total-query cap is spent (regardless of open
    /// waiters, which keep it alive through their own handles) or when it is
    /// idle and `ARES_FLAG_STAYOPEN` is clear. Returns the removed handle for
    /// dropping after the pool borrow.
    pub fn release_if_done(
        &mut self,
        server: usize,
        conn: &Conn,
        stayopen: bool,
        max_queries: usize,
    ) -> Vec<Conn> {
        let exhausted = conn.borrow().exhausted(max_queries);
        let idle = conn.borrow().is_empty();
        if !exhausted && (stayopen || !idle) {
            return Vec::new();
        }
        self.remove(server, conn)
    }

    /// Check out a connection for a new query on `server`, or `None` when every
    /// existing conn is exhausted (`total_queries >= max_queries`; `0` =
    /// unlimited) and the caller must create another socket. Idle conns are
    /// pruned when `stayopen` is clear; exhausted conns are pruned regardless.
    /// The returned second vector holds retired handles, to be dropped after
    /// the pool borrow.
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
        let mut kept = Vec::with_capacity(list.len());
        for conn in list.drain(..) {
            let conn_state = conn.borrow();
            let retire = conn_state.exhausted(max_queries)
                || (!stayopen && conn_state.is_empty());
            drop(conn_state);
            if retire {
                retired.push(conn);
            } else {
                kept.push(conn);
            }
        }
        *list = kept;
        let picked = list.first().cloned();
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
    use std::collections::VecDeque;
    use std::net::SocketAddr;

    fn mailbox() -> Rc<RefCell<DnsMailbox>> {
        Rc::new(RefCell::new(DnsMailbox::default()))
    }

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

    /// A datagram socket backed by a queue, for the sibling-routing test.
    struct QueueSock {
        queued: RefCell<VecDeque<Vec<u8>>>,
    }
    impl Socket for QueueSock {
        fn as_raw_fd(&self) -> i32 {
            6
        }
        fn connect(&self, _addr: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            let Some(datagram) = self.queued.borrow_mut().pop_front() else {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            };
            buf[..datagram.len()].copy_from_slice(&datagram);
            Ok((datagram.len(), None))
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }
    }

    #[test]
    fn reserve_rerolls_colliding_tag() {
        let mut uc = UdpConn {
            sock: Rc::new(DummySock),
            fd: 5,
            inbox: HashMap::new(),
            total_queries: 0,
        };
        let io = mailbox();

        assert_eq!(uc.reserve(7, || panic!("free qid must not reroll"), io.clone()), 7);
        let rolls = RefCell::new(vec![9u16, 7u16]); // popped back-to-front: 7, then 9
        assert_eq!(uc.reserve(7, || rolls.borrow_mut().pop().unwrap(), io.clone()), 9);
        assert!(rolls.borrow().is_empty());
        assert!(uc.has_waiter(7) && uc.has_waiter(9));
        assert_eq!(uc.total_queries(), 2);

        uc.release(7);
        assert!(!uc.has_waiter(7) && uc.has_waiter(9));
        assert_eq!(uc.waiter_count(), 1);
    }

    #[test]
    fn pool_respects_total_queries_not_just_waiters() {
        let mut pool = UdpPool::new();
        let conn = UdpConn::new(Rc::new(DummySock));
        let io = mailbox();
        pool.insert(0, conn.clone());

        // Sequential reuse: max 2, first query reserves and releases. Use
        // STAYOPEN so the idle conn is eligible for reuse between queries.
        let (picked, retired) = pool.pick_or_none(0, 2, true);
        assert!(picked.is_some() && retired.is_empty());
        conn.borrow_mut().reserve(1, || panic!("free qid"), io.clone());
        conn.borrow_mut().release(1);
        assert_eq!(conn.borrow().total_queries(), 1);

        // Second query still reuses the same conn even though it is idle.
        let (picked, retired) = pool.pick_or_none(0, 2, true);
        assert!(picked.is_some() && retired.is_empty());
        conn.borrow_mut().reserve(2, || panic!("free qid"), io.clone());
        conn.borrow_mut().release(2);
        assert_eq!(conn.borrow().total_queries(), 2);

        // Third checkout: exhausted (total == max) -> pruned even with
        // STAYOPEN, and the caller must create a new conn.
        let (picked, retired) = pool.pick_or_none(0, 2, true);
        assert!(picked.is_none());
        assert_eq!(retired.len(), 1);
    }

    #[test]
    fn release_retires_exhausted_conn_even_when_stayopen() {
        let mut pool = UdpPool::new();
        let conn = UdpConn::new(Rc::new(DummySock));
        let io = mailbox();
        pool.insert(0, conn.clone());
        conn.borrow_mut().reserve(3, || panic!("free qid"), io);
        conn.borrow_mut().release(3);

        let retired = pool.release_if_done(0, &conn, true, 1);
        assert_eq!(retired.len(), 1);
    }

    /// A sibling that drains the socket must flag the target mailbox even when
    /// the target previously suspended Pending with no readiness of its own.
    #[test]
    fn sibling_routing_flags_target_mailbox() {
        let sock: Rc<dyn Socket> = Rc::new(QueueSock {
            queued: RefCell::new(VecDeque::from(vec![vec![0x12, 0x34, 0xAA]])),
        });
        let uc = UdpConn::new(sock);
        let a_io = mailbox();
        let b_io = mailbox();

        uc.borrow_mut().reserve(0x1111, || panic!("free qid"), a_io);
        uc.borrow_mut().reserve(0x1234, || panic!("free qid"), b_io.clone());
        assert!(!b_io.borrow().routed);

        // A drains: the datagram belongs to B, so it goes into B's slot and
        // flags B's mailbox (A gets Pending for its own tag).
        let mut scratch = Vec::new();
        assert!(matches!(uc.borrow_mut().poll_read(0x1111, &mut scratch), Poll::Pending));
        assert!(b_io.borrow().routed);
        assert!(uc.borrow_mut().take(0x1234).is_some());
    }
}
