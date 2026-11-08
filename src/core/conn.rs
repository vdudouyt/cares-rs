//! The per-query DNS connection facade (`Conn`) over `async_runtime`'s
//! [`Async`] sockets. Pooling and QID multiplexing live in `tcp_pool`/`udp_pool`;
//! this module routes a `Conn` to the right transport and drives it.

use std::cell::RefCell;
use std::future::{poll_fn, Future};
use std::io;
use std::pin::pin;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Instant;

use futures_util::{select_biased, FutureExt};

use crate::async_runtime::io::{send_when_writable, Async};
use crate::async_runtime::reactor::Timer;
use crate::core::tcp_pool::TcpConn;
use crate::core::async_client::ChannelShared;
use crate::core::udp_pool::UdpConn;

/// A query's connection.
pub(crate) struct Conn {
    wire: Wire,
    /// Set only on shared-UDP checkouts, so dropping the last query can retire the conn.
    udp_lease: Option<UdpLease>,
}

struct UdpLease {
    shared: Rc<ChannelShared>,
    server: usize,
    stayopen: bool,
    max_queries: usize,
}

enum Wire {
    Shared(Rc<RefCell<TcpConn>>, u16),
    SharedUdp(Rc<RefCell<UdpConn>>, u16),
}

impl Conn {
    /// A query's handle on a shared stream conn: opens the inbox slot for its
    /// (channel-unique) `qid` and releases it on drop.
    pub fn shared(conn: Rc<RefCell<TcpConn>>, qid: u16) -> Self {
        conn.borrow_mut().register_query(qid);
        Conn { wire: Wire::Shared(conn, qid), udp_lease: None }
    }

    /// A query's handle on a shared datagram conn: opens the inbox slot for its
    /// (channel-unique) `qid` and releases it on drop.
    pub fn shared_udp(conn: Rc<RefCell<UdpConn>>, qid: u16) -> Self {
        conn.borrow_mut().register_query(qid);
        Conn { wire: Wire::SharedUdp(conn, qid), udp_lease: None }
    }

    /// Attach the pool lease for a shared-UDP checkout so the conn can retire
    /// when its queries finish.
    pub fn with_udp_lease(
        mut self,
        shared: Rc<ChannelShared>,
        server: usize,
        stayopen: bool,
        max_queries: usize,
    ) -> Self {
        self.udp_lease = Some(UdpLease { shared, server, stayopen, max_queries });
        self
    }

    /// The shared datagram handle behind this conn, if it is a shared-UDP checkout.
    pub fn shared_udp_handle(&self) -> Option<Rc<RefCell<UdpConn>>> {
        match &self.wire {
            Wire::SharedUdp(c, _) => Some(c.clone()),
            _ => None,
        }
    }

    /// Mark a shared-UDP socket dead on a send failure; no-op for other wires.
    pub fn mark_dead(&self) {
        if let Some(c) = self.shared_udp_handle() {
            c.borrow_mut().mark_dead();
        }
    }

    /// The registered socket under this conn.
    fn sock(&self) -> Rc<Async> {
        match &self.wire {
            Wire::Shared(c, _) => c.borrow().sock(),
            Wire::SharedUdp(c, _) => c.borrow().sock(),
        }
    }

    /// Await writability, then send `bytes` once (WouldBlock re-awaits);
    /// `TimedOut` if not writable before `timeout`.
    pub async fn send(&self, bytes: &[u8], timeout: Instant) -> io::Result<()> {
        send_when_writable(&self.sock(), bytes, timeout).await
    }

    /// Take a message a **sibling** already routed into this tag's slot,
    /// without this conn's fd firing again (the draining sibling consumed its
    /// readiness).
    fn take_routed_slot(&mut self) -> Option<Vec<u8>> {
        match &self.wire {
            Wire::Shared(c, tag) => c.borrow_mut().take(*tag),
            Wire::SharedUdp(c, tag) => c.borrow_mut().take(*tag),
        }
    }

    /// Whether a sibling has routed a reply into this conn's slot.
    fn has_routed_reply(&self) -> bool {
        match &self.wire {
            Wire::Shared(c, tag) => c.borrow().has_reply(*tag),
            Wire::SharedUdp(c, tag) => c.borrow().has_reply(*tag),
        }
    }

    /// Let a sibling's drain wake this task when it routes our reply.
    fn register_waker(&self, waker: &Waker) {
        match &self.wire {
            Wire::Shared(c, tag) => c.borrow_mut().register(*tag, waker),
            Wire::SharedUdp(c, tag) => c.borrow_mut().register(*tag, waker),
        }
    }

    /// One non-blocking read of this conn's next message (only after the
    /// caller reported the fd readable).
    fn read(&mut self) -> Poll<io::Result<Vec<u8>>> {
        // The shared conn owns the drain, route, and per-tag demux.
        match &mut self.wire {
            Wire::Shared(c, tag) => c.borrow_mut().poll_read(*tag),
            Wire::SharedUdp(c, tag) => c.borrow_mut().poll_read(*tag),
        }
    }

    /// A read bypassing wait registration, for the turn where `Conn::recv`'s
    /// timeout expired alongside socket readiness: a pending hard error (ICMP
    /// port-unreachable) must still be consumed before counting a timeout.
    pub fn try_recv(&mut self) -> Poll<io::Result<Vec<u8>>> {
        if let Some(msg) = self.take_routed_slot() {
            return Poll::Ready(Ok(msg));
        }
        // Read only when the caller reported this fd ready this turn: a pure
        // timeout must stay a timeout (custom socket tables can return
        // zero-length "datagrams" that must not be mistaken for readiness).
        if !self.sock().readable_this_turn() {
            return Poll::Pending;
        }
        self.read()
    }

    /// Await this conn's next message with no timeout bound: a reply a sibling
    /// routed into our slot, or one non-blocking [`read`](Self::read) each time
    /// the fd is reported readable. `Err(UnexpectedEof)` on a dead socket.
    pub async fn recv_msg(&mut self) -> io::Result<Vec<u8>> {
        let sock = self.sock();
        loop {
            if let Some(msg) = self.take_routed_slot() {
                return Ok(msg);
            }
            {
                let this = &*self;
                let mut ready = pin!(sock.readable());
                poll_fn(|cx| {
                    if this.has_routed_reply() {
                        return Poll::Ready(());
                    }
                    this.register_waker(cx.waker());
                    ready.as_mut().poll(cx)
                })
                .await;
            }
            if self.has_routed_reply() {
                continue;
            }
            if let Poll::Ready(r) = self.read() {
                return r;
            }
        }
    }

    /// `conn.recv(timeout).await`; the timeout arm is polled first so expiry
    /// preempts a read ready in the same poll. `TimedOut` on expiry.
    pub async fn recv(&mut self, timeout: Instant) -> io::Result<Vec<u8>> {
        let reactor = self.sock().reactor().clone();
        let mut t = pin!(Timer::at(&reactor, timeout).fuse());
        let mut r = pin!(self.recv_msg().fuse());
        select_biased! {
            _ = t => Err(io::ErrorKind::TimedOut.into()),
            r = r => r,
        }
    }
}

/// Dropping a conn releases its shared inbox slot (RAII).
impl Drop for Conn {
    fn drop(&mut self) {
        let retired = match (&self.wire, &self.udp_lease) {
            (Wire::Shared(c, tag), _) => {
                c.borrow_mut().release(*tag);
                Vec::new()
            }
            (Wire::SharedUdp(c, tag), Some(lease)) => {
                c.borrow_mut().release(*tag);
                let retired = lease.shared.udp_pool.borrow_mut().release_if_done(
                    lease.server,
                    c,
                    lease.stayopen,
                    lease.max_queries,
                );
                retired
            }
            (Wire::SharedUdp(c, tag), None) => {
                c.borrow_mut().release(*tag);
                Vec::new()
            }
        };
        // Drop retired handles after the pool borrow ends so socket close
        // callbacks fire with no pool cell held.
        drop(retired);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_runtime::reactor::Reactor;
    use crate::async_runtime::socket::Socket;
    use std::net::SocketAddr;
    use std::task::Context;
    use std::time::Duration;

    /// A socket that always has a datagram waiting, so a recv arm is immediately ready.
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

    /// Dropping a `Conn` frees exactly its own shared-conn slot (RAII).
    #[test]
    fn shared_conn_releases_slot_on_drop() {
        let reactor = Reactor::new();
        let tc = TcpConn::new(Async::new(Rc::new(AlwaysReadable { fd: 5 }), &reactor));

        let a = Conn::shared(tc.clone(), 7);
        let b = Conn::shared(tc.clone(), 9);
        assert!(tc.borrow().has_waiter(7) && tc.borrow().has_waiter(9));

        drop(a);
        assert!(!tc.borrow().has_waiter(7) && tc.borrow().has_waiter(9));
        drop(b);
        assert!(!tc.borrow().has_waiter(9));
    }

    /// `Conn::recv` must be **timeout-biased**: when a reply and the timeout are
    /// both ready in one poll, expiry preempts the read. Guards against weakening
    /// `select_biased!` to an unbiased `select!` (which would pick either arm).
    #[test]
    fn recv_is_timeout_biased_under_simultaneous_readiness() {
        // The deadline window must outlast the first poll; under Miri that can
        // take far longer than natively, so a window that expires before the
        // read arm registers is widened and the trial retried.
        let mut window = Duration::from_millis(3);
        let mut trial = 0;
        while trial < 20 {
            let reactor = Reactor::new();
            let sock: Rc<dyn Socket> = Rc::new(AlwaysReadable { fd: 42 });
            // Tag 0xABAB: the datagram AlwaysReadable yields routes to us.
            let mut conn = Conn::shared_udp(UdpConn::new(Async::new(sock, &reactor), false), 0xABAB);
            let mut cx = Context::from_waker(Waker::noop());
            // Register the read arm, report the fd readable, then let the
            // deadline pass: on the next poll both arms are ready.
            let deadline = Instant::now() + window;
            let mut fut = pin!(conn.recv(deadline));
            if fut.as_mut().poll(&mut cx).is_ready() {
                assert!(window < Duration::from_secs(60), "first poll never beat the deadline");
                window *= 4;
                continue;
            }
            reactor.dispatch(Instant::now(), true, |fd, w| fd == 42 && !w);
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(r) => assert!(
                    r.is_err_and(|e| e.kind() == io::ErrorKind::TimedOut),
                    "trial {trial}: recv returned a reply while the timeout was \
                     also ready — Conn::recv must stay `select_biased!` \
                     (timeout arm first), not an unbiased `select!`",
                ),
                Poll::Pending => panic!("trial {trial}: both arms ready, must resolve"),
            }
            trial += 1;
        }
    }
}
