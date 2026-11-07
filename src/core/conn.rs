//! The per-query DNS connection facade (`Conn`) over `async_runtime`'s byte-level
//! IO arms. Pooling and QID multiplexing live in `tcp_pool`/`udp_pool`; this
//! module routes a `Conn` to the right transport and drives it.

use std::cell::RefCell;
use std::future::poll_fn;
use std::io;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Instant;

use futures_util::{select_biased, FutureExt};

use crate::async_runtime::executor::sleep_until;
use crate::async_runtime::io::{dead, poll_recv, recv_datagram, recv_stream, send_when_writable};
use crate::async_runtime::socket::Socket;
use crate::core::async_client::DnsMailbox;
use crate::core::tcp_pool::{dns_frame, TcpConn};
use crate::core::udp_pool::{UdpConn, UdpPool};

/// A query's connection; it owns its mailbox (`io`) so `send`/`recv` take no
/// reactor handle.
pub(crate) struct Conn {
    io: Rc<RefCell<DnsMailbox>>,
    wire: Wire,
    /// Set only on shared-UDP checkouts, so dropping the last query can retire the conn.
    udp_lease: Option<UdpLease>,
}

struct UdpLease {
    pool: Rc<RefCell<UdpPool>>,
    server: usize,
    stayopen: bool,
    max_queries: usize,
}

enum Wire {
    Datagram { sock: Rc<dyn Socket> },
    Stream { sock: Rc<dyn Socket>, rbuf: Vec<u8> },
    Shared(Rc<RefCell<TcpConn>>, u16),
    SharedUdp(Rc<RefCell<UdpConn>>, u16),
}

impl Conn {
    /// An owned datagram socket, already connected (one recv = one message).
    pub fn datagram(io: Rc<RefCell<DnsMailbox>>, sock: Rc<dyn Socket>) -> Self {
        Conn { io, wire: Wire::Datagram { sock }, udp_lease: None }
    }

    /// An owned one-shot stream socket; [`dns_frame`] cuts its bytes into messages.
    pub fn stream(io: Rc<RefCell<DnsMailbox>>, sock: Rc<dyn Socket>) -> Self {
        Conn { io, wire: Wire::Stream { sock, rbuf: Vec::new() }, udp_lease: None }
    }

    /// A query's handle on a shared stream conn: reserves a tag (rerolling `qid`
    /// on collision — see [`TcpConn::reserve`]) and releases it on drop. Returns
    /// the handle and the tag actually reserved; the caller must re-stamp on a re-roll.
    pub fn shared(
        io: Rc<RefCell<DnsMailbox>>,
        conn: Rc<RefCell<TcpConn>>,
        qid: u16,
        reroll: impl FnMut() -> u16,
    ) -> (Self, u16) {
        let tag = conn.borrow_mut().reserve(qid, reroll, io.clone());
        (Conn { io, wire: Wire::Shared(conn, tag), udp_lease: None }, tag)
    }

    /// A query's handle on a shared datagram conn: reserves a tag (rerolling `qid`
    /// on collision — see [`UdpConn::reserve`]) and releases it on drop. Returns
    /// the handle and the tag actually reserved; the caller must re-stamp on a re-roll.
    pub fn shared_udp(
        io: Rc<RefCell<DnsMailbox>>,
        conn: Rc<RefCell<UdpConn>>,
        qid: u16,
        reroll: impl FnMut() -> u16,
    ) -> (Self, u16) {
        let tag = conn.borrow_mut().reserve(qid, reroll, io.clone());
        (Conn { io, wire: Wire::SharedUdp(conn, tag), udp_lease: None }, tag)
    }

    /// Attach the pool lease for a shared-UDP checkout so the conn can retire
    /// when its queries finish.
    pub fn with_udp_lease(
        mut self,
        pool: Rc<RefCell<UdpPool>>,
        server: usize,
        stayopen: bool,
        max_queries: usize,
    ) -> Self {
        self.udp_lease = Some(UdpLease { pool, server, stayopen, max_queries });
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

    fn fd(&self) -> i32 {
        match &self.wire {
            Wire::Datagram { sock } | Wire::Stream { sock, .. } => sock.as_raw_fd(),
            Wire::Shared(c, _) => c.borrow().fd(),
            Wire::SharedUdp(c, _) => c.borrow().fd(),
        }
    }

    pub fn is_tcp(&self) -> bool {
        matches!(&self.wire, Wire::Stream { .. } | Wire::Shared(..))
    }

    /// Await writability, then send `bytes` once (WouldBlock re-awaits);
    /// `TimedOut` if not writable before `timeout`.
    pub async fn send(&self, bytes: &[u8], timeout: Instant) -> io::Result<()> {
        let sock: Rc<dyn Socket> = match &self.wire {
            Wire::Datagram { sock } | Wire::Stream { sock, .. } => sock.clone(),
            Wire::Shared(c, _) => c.borrow().sock(),
            Wire::SharedUdp(c, _) => c.borrow().sock(),
        };
        send_when_writable(&self.io, &*sock, bytes, timeout).await
    }

    /// Take a message a **sibling** already routed into this tag's slot — only
    /// possible on a shared conn, and without this conn's fd firing again (the
    /// draining sibling consumed its readiness).
    fn take_routed_slot(&mut self) -> Option<Vec<u8>> {
        match &self.wire {
            Wire::Shared(c, tag) => c.borrow_mut().take(*tag),
            Wire::SharedUdp(c, tag) => c.borrow_mut().take(*tag),
            _ => None,
        }
    }

    /// One non-blocking read of this conn's next message. `scratch` is taken out
    /// of the mailbox for the read's span so the C recv callback fires with no
    /// mailbox borrow live.
    fn read(&mut self) -> Poll<io::Result<Vec<u8>>> {
        let mut scratch = std::mem::take(&mut self.io.borrow_mut().scratch);
        let r = match &mut self.wire {
            Wire::Datagram { sock } => recv_datagram(&**sock, &mut scratch),
            Wire::Stream { sock, rbuf } => {
                // One-shot stream: a buffered frame delivers even on a dead
                // socket; else a dead socket errors and an incomplete read is `Pending`.
                let alive = recv_stream(&**sock, rbuf, &mut scratch);
                match dns_frame(rbuf) {
                    Some(frame) => Poll::Ready(Ok(frame)),
                    None if !alive => Poll::Ready(Err(dead())),
                    None => Poll::Pending,
                }
            }
            // The shared conn owns the drain, route, and per-tag demux.
            Wire::Shared(c, tag) => c.borrow_mut().poll_read(*tag, &mut scratch),
            Wire::SharedUdp(c, tag) => c.borrow_mut().poll_read(*tag, &mut scratch),
        };
        self.io.borrow_mut().scratch = scratch;
        r
    }

    /// A read bypassing wait registration, for the cycle where `Conn::recv`'s
    /// timeout expired alongside socket readiness: a pending hard error (ICMP
    /// port-unreachable) must still be consumed before counting a timeout.
    pub fn try_recv(&mut self) -> Poll<io::Result<Vec<u8>>> {
        if let Some(msg) = self.take_routed_slot() {
            return Poll::Ready(Ok(msg));
        }
        // Consume only when the reactor reported this fd ready: a pure timeout
        // must stay a timeout (custom socket tables can return zero-length
        // "datagrams" that must not be mistaken for readiness).
        let fd = self.fd();
        let ready = self
            .io
            .borrow()
            .fired
            .iter()
            .any(|w| w.fd == fd && !w.writable);
        if !ready {
            return Poll::Pending;
        }
        self.read()
    }

    /// Await this conn's next message with no timeout bound. On this conn's fd
    /// firing, does one non-blocking [`read`](Self::read); `Err(UnexpectedEof)` on a dead socket.
    pub async fn recv_msg(&mut self) -> io::Result<Vec<u8>> {
        let fd = self.fd();
        let io = self.io.clone();
        poll_fn(move |_| {
            // A sibling may have already drained the socket and routed our frame
            // into our slot, consuming the fd's readiness; take it without waiting.
            if let Some(msg) = self.take_routed_slot() {
                return Poll::Ready(Ok(msg));
            }
            poll_recv(&io, fd, || self.read())
        })
        .await
    }

    /// `conn.recv(timeout).await`; the timeout arm is polled first so expiry
    /// preempts a read ready in the same poll. `TimedOut` on expiry.
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
                let retired = lease.pool.borrow_mut().release_if_done(
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
            _ => Vec::new(),
        };
        // Drop retired handles after the pool borrow ends so socket close
        // callbacks fire with no pool cell held.
        drop(retired);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_runtime::executor::Wait;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::task::{Context, Waker};
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

    /// `Conn::shared` propagates the reserved tag, and dropping a `Conn` frees
    /// exactly its own shared-conn slot (RAII).
    #[test]
    fn shared_conn_releases_slot_on_drop() {
        let tc = TcpConn::new(Rc::new(AlwaysReadable { fd: 5 }));
        let io: Rc<RefCell<DnsMailbox>> = Rc::new(RefCell::new(DnsMailbox::default()));

        let (a, ta) = Conn::shared(io.clone(), tc.clone(), 7, || panic!("free qid must not reroll"));
        assert_eq!(ta, 7);
        let (b, tb) = Conn::shared(io.clone(), tc.clone(), 7, || 9);
        assert_eq!(tb, 9);
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
        for trial in 0..100 {
            let io: Rc<RefCell<DnsMailbox>> = Rc::new(RefCell::new(DnsMailbox::default()));
            // Both arms ready on the first poll: a datagram waits and the deadline is past.
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
