//! DNS-over-UDP pooling: server-shared datagram sockets demuxed by transaction
//! tag; a server gets a new conn once the per-socket query cap is spent.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use crate::async_runtime::io::{dead, recv_datagram};
use crate::async_runtime::io::Async;
use crate::core::lookup::ServerId;
use crate::core::tcp_pool::dns_tag;

pub(crate) type Conn = Rc<RefCell<UdpConn>>;

/// Selected conn plus handles retired during the lookup, returned by value so
/// the caller can drop them after its pool borrow ends.
type Checkout = (Option<Conn>, Vec<Conn>);

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

/// A shared datagram connection to one server, driven cooperatively by every
/// future with an outstanding query on it (tag-demuxed inbox).
pub(crate) struct UdpConn {
    sock: Rc<Async>,
    inbox: HashMap<u16, InboxSlot>,
    /// Every query ever reserved, not just current waiters; `ARES_OPT_UDP_MAX_QUERIES`
    /// caps this total, so an exhausted conn retires even if its waiters later drain.
    total_queries: usize,
    /// Sticky hard-error flag: once the shared socket dies every waiter must see the error.
    dead: bool,
    /// When the socket died; event-driven channels keep a dead conn pooled briefly
    /// so concurrent retries join it and fail fast instead of opening fresh sockets.
    dead_since: Option<Instant>,
    event_driven: bool,
}

impl UdpConn {
    /// A fresh shared connection over `sock`, already created and connected by
    /// the caller outside any pool borrow so socket callbacks fire with no cell held.
    pub(crate) fn new(sock: Rc<Async>, event_driven: bool) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(UdpConn {
            sock,
            inbox: HashMap::new(),
            total_queries: 0,
            dead: false,
            dead_since: None,
            event_driven,
        }))
    }

    /// Open an inbox slot for a query's id and count it against
    /// `udp_max_queries`. Ids are unique channel-wide (`core::qid`), so the
    /// slot is never already taken.
    pub(crate) fn register_query(&mut self, qid: u16) {
        self.inbox.insert(qid, InboxSlot { reply: None, waker: None });
        self.total_queries += 1;
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

    pub(crate) fn sock(&self) -> Rc<Async> {
        self.sock.clone()
    }

    /// Whether a sibling has routed a reply into `tag`'s slot.
    pub(crate) fn has_reply(&self, tag: u16) -> bool {
        self.inbox.get(&tag).is_some_and(|slot| slot.reply.is_some())
    }

    /// Take a reply a **sibling** already routed into `tag`'s slot (it consumed
    /// the fd's readiness, so this must not read the socket).
    pub(crate) fn take(&mut self, tag: u16) -> Option<Vec<u8>> {
        self.inbox.get_mut(&tag).and_then(|slot| slot.reply.take())
    }

    /// Drain + route waiting datagrams, then resolve `tag`: `Ready(Ok)` if a
    /// message is now in its slot, `Ready(Err(UnexpectedEof))` if the socket died, else `Pending`.
    ///
    /// Takes the cell rather than `&mut self`: the socket is read with `conn`
    /// unborrowed, since a custom `arecvfrom` may re-enter the channel (and touch
    /// this conn, e.g. a new query joining it or a cancel releasing its slots).
    pub(crate) fn poll_read(conn: &RefCell<Self>, tag: u16) -> Poll<io::Result<Vec<u8>>> {
        let sock = {
            let this = conn.borrow();
            if this.dead {
                return Poll::Ready(Err(dead()));
            }
            this.sock.clone()
        };
        let (frames, alive) = read_datagrams(&sock);
        let mut this = conn.borrow_mut();
        for frame in frames {
            this.route(frame);
        }
        if !alive {
            // A hard error is sticky: wake every sibling waiter, since their
            // replies can never arrive now.
            this.dead = true;
            this.dead_since.get_or_insert_with(Instant::now);
            for slot in this.inbox.values() {
                slot.wake();
            }
        }
        match this.take(tag) {
            Some(msg) => Poll::Ready(Ok(msg)),
            None if this.dead => Poll::Ready(Err(dead())),
            None => Poll::Pending,
        }
    }

    /// Route one datagram by tag into `inbox` (unknown tags dropped).
    fn route(&mut self, frame: Vec<u8>) {
        if let Some(tag) = dns_tag(&frame) {
            if let Some(slot) = self.inbox.get_mut(&tag) {
                slot.deliver(frame);
            }
        } else if let Some(slot) = self.inbox.values_mut().find(|s| s.reply.is_none()) {
            // Untaggable datagram: hand it to an awaiting waiter so the
            // application sees (and rejects) it.
            slot.deliver(frame);
        }
    }

    #[cfg(test)]
    pub(crate) fn waiter_count(&self) -> usize {
        self.inbox.len()
    }

    #[cfg(test)]
    pub(crate) fn total_queries(&self) -> usize {
        self.total_queries
    }

    /// No query owns this conn (idle conns may be retired unless stay-open).
    pub(crate) fn is_empty(&self) -> bool {
        self.inbox.is_empty()
    }

    /// The shared socket hit a hard error; new queries should join it so they
    /// fail fast instead of opening a fresh socket that needs its own ICMP error.
    pub(crate) fn is_dead(&self) -> bool {
        self.dead
    }

    /// Mark the socket dead from a send failure, waking siblings immediately.
    pub(crate) fn mark_dead(&mut self) {
        self.dead = true;
        self.dead_since.get_or_insert_with(Instant::now);
        for slot in self.inbox.values() {
            slot.wake();
        }
    }

    /// A dead conn stays pooled for a short grace window so a burst of retries
    /// fails fast on the same socket instead of opening one fresh socket per query.
    fn dead_in_grace(&self) -> bool {
        self.event_driven
            && self.dead
            && self
                .dead_since
                .is_some_and(|t| t.elapsed() < Duration::from_millis(100))
    }

    /// The per-conn cap is spent (`max_queries == 0` means unlimited).
    fn exhausted(&self, max_queries: usize) -> bool {
        max_queries != 0 && self.total_queries >= max_queries
    }
}

/// Read the datagrams waiting on `sock` until `WouldBlock`; `false` if the
/// socket died (frames read before the error are still returned).
fn read_datagrams(sock: &Async) -> (Vec<Vec<u8>>, bool) {
    let drain = sock.get_ref().drain_safe();
    let mut frames = Vec::new();
    loop {
        match sock.read(|s, scratch| recv_datagram(s, scratch)) {
            Poll::Ready(Ok(frame)) => {
                frames.push(frame);
                // A caller-supplied socket may be blocking: one datagram per
                // readiness cycle is safe; the next cycle drains the rest.
                if !drain {
                    return (frames, true);
                }
            }
            Poll::Ready(Err(_)) => return (frames, false),
            Poll::Pending => return (frames, true),
        }
    }
}

/// Shared datagram connections per server, capped by `channel->udp_max_queries`
/// (upstream `server->connections`).
pub(crate) struct UdpPool {
    conns: HashMap<ServerId, Vec<Conn>>,
}

impl UdpPool {
    pub fn new() -> Self {
        UdpPool { conns: HashMap::new() }
    }

    /// Return every pooled conn for dropping after the pool borrow ends (a socket
    /// close callback fires on the last drop).
    pub fn clear(&mut self) -> Vec<Conn> {
        let mut retired = Vec::new();
        for (_, mut list) in self.conns.drain() {
            retired.append(&mut list);
        }
        retired
    }

    /// Return the conns of servers no longer in `keep` (a server-list change),
    /// for dropping after the pool borrow ends.
    #[must_use = "drop the evicted conns after releasing the pool borrow"]
    pub fn retain_servers(&mut self, keep: &[ServerId]) -> Vec<Conn> {
        let gone: Vec<ServerId> = self.conns.keys().filter(|id| !keep.contains(id)).copied().collect();
        gone.into_iter().filter_map(|id| self.conns.remove(&id)).flatten().collect()
    }

    pub fn insert(&mut self, server: ServerId, conn: Conn) {
        self.conns.entry(server).or_default().push(conn);
    }

    /// Any pooled conn for `server` hit a hard socket error, so a sibling's
    /// timeout is attributable to that failure rather than a genuine query timeout.
    pub fn has_dead(&self, server: ServerId) -> bool {
        self.conns
            .get(&server)
            .is_some_and(|list| list.iter().any(|c| c.borrow().is_dead()))
    }

    /// Remove `conn` from `server`'s list, returning it for dropping outside the borrow.
    pub fn remove(
        &mut self,
        server: ServerId,
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

    /// Retire a conn when its query cap is spent (regardless of open waiters,
    /// which keep it alive through their handles) or it is idle and not stay-open;
    /// returns the handle for dropping after the pool borrow.
    pub fn release_if_done(
        &mut self,
        server: ServerId,
        conn: &Conn,
        stayopen: bool,
        max_queries: usize,
    ) -> Vec<Conn> {
        let (exhausted, idle, dead, dead_grace) = {
            let c = conn.borrow();
            (c.exhausted(max_queries), c.is_empty(), c.is_dead(), c.dead_in_grace())
        };
        let retire = exhausted
            || (dead && idle && !dead_grace)
            || (!dead && !stayopen && idle);
        if !retire {
            return Vec::new();
        }
        self.remove(server, conn)
    }

    /// Check out a conn for a new query on `server`, or `None` when every conn is
    /// exhausted (`max_queries == 0` = unlimited) and the caller must open another.
    /// Idle conns are pruned unless stay-open; exhausted ones always are.
    pub fn pick_or_none(
        &mut self,
        server: ServerId,
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
            let retire = if conn_state.exhausted(max_queries) {
                true
            } else if conn_state.is_dead() {
                conn_state.is_empty() && !conn_state.dead_in_grace()
            } else {
                !stayopen && conn_state.is_empty()
            };
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
    /// Whether `tag` has a reserved slot (fields are private to this module).
    pub(crate) fn has_waiter(&self, tag: u16) -> bool {
        self.inbox.contains_key(&tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_runtime::reactor::Reactor;
    use crate::async_runtime::socket::Socket;
    use std::collections::VecDeque;
    use std::net::SocketAddr;

    fn sock(s: impl Socket + 'static) -> Rc<Async> {
        Async::new(Rc::new(s), &Reactor::new())
    }

    /// A waker that records whether it fired.
    struct Flag(std::sync::atomic::AtomicBool);
    impl std::task::Wake for Flag {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl Flag {
        fn fired(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A socket with no datagrams waiting, for tests that never read it.
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
    fn register_counts_queries_and_release_frees_only_its_slot() {
        let mut uc = UdpConn {
            sock: sock(DummySock),
            inbox: HashMap::new(),
            total_queries: 0,
            dead: false,
            dead_since: None,
            event_driven: false,
        };
        uc.register_query(7);
        uc.register_query(9);
        assert!(uc.has_waiter(7) && uc.has_waiter(9));
        assert_eq!(uc.total_queries(), 2);

        uc.release(7);
        assert!(!uc.has_waiter(7) && uc.has_waiter(9));
        assert_eq!(uc.waiter_count(), 1);
    }

    #[test]
    fn pool_respects_total_queries_not_just_waiters() {
        let mut pool = UdpPool::new();
        let conn = UdpConn::new(sock(DummySock), false);
        pool.insert(ServerId(0), conn.clone());

        let (picked, retired) = pool.pick_or_none(ServerId(0), 2, true);
        assert!(picked.is_some() && retired.is_empty());
        conn.borrow_mut().register_query(1);
        conn.borrow_mut().release(1);
        assert_eq!(conn.borrow().total_queries(), 1);

        let (picked, retired) = pool.pick_or_none(ServerId(0), 2, true);
        assert!(picked.is_some() && retired.is_empty());
        conn.borrow_mut().register_query(2);
        conn.borrow_mut().release(2);
        assert_eq!(conn.borrow().total_queries(), 2);

        // Exhausted even with STAYOPEN: pruned; caller must create a new conn.
        let (picked, retired) = pool.pick_or_none(ServerId(0), 2, true);
        assert!(picked.is_none());
        assert_eq!(retired.len(), 1);
    }

    #[test]
    fn release_retires_exhausted_conn_even_when_stayopen() {
        let mut pool = UdpPool::new();
        let conn = UdpConn::new(sock(DummySock), false);
        pool.insert(ServerId(0), conn.clone());
        conn.borrow_mut().register_query(3);
        conn.borrow_mut().release(3);

        let retired = pool.release_if_done(ServerId(0), &conn, true, 1);
        assert_eq!(retired.len(), 1);
    }

    /// A sibling that drains the socket must wake the target task even when
    /// the target previously suspended Pending with no readiness of its own.
    #[test]
    fn sibling_routing_wakes_target() {
        let uc = UdpConn::new(
            sock(QueueSock { queued: RefCell::new(VecDeque::from(vec![vec![0x12, 0x34, 0xAA]])) }),
            false,
        );
        let b = std::sync::Arc::new(Flag(Default::default()));

        uc.borrow_mut().register_query(0x1111);
        uc.borrow_mut().register_query(0x1234);
        uc.borrow_mut().register(0x1234, &Waker::from(b.clone()));
        assert!(!b.fired());

        // A drains: the datagram belongs to B, so it goes into B's slot and
        // wakes B (A gets Pending for its own tag).
        assert!(matches!(UdpConn::poll_read(&uc, 0x1111), Poll::Pending));
        assert!(b.fired());
        assert!(uc.borrow_mut().take(0x1234).is_some());
    }
}
