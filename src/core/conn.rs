//! The per-query DNS connection facade (`Conn`) over `async_runtime`'s
//! byte-level IO arms. A `Conn` owns its mailbox handle, so IO reads
//! tokio-style: `conn.send(bytes, timeout).await` / `conn.recv(timeout).await`.
//!
//! The wire behind a `Conn` is one of three transports — an owned datagram
//! socket, an owned one-shot stream (framed by [`dns_frame`]), or a checkout of
//! a shared, multiplexed TCP connection ([`TcpConn`]) — and the
//! datagram-vs-demuxed-stream asymmetry is hidden behind the methods.
//! Connection pooling and QID multiplexing live in [`crate::core::tcp_pool`];
//! this module only routes a `Conn` to the right transport and drives it.

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
/// connection from the [`tcp_pool`](crate::core::tcp_pool).
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

    /// A query's handle on a shared stream conn. Reserves an inbox tag on the
    /// `TcpConn` (rerolling `qid` on collision — see [`TcpConn::reserve`]) so a
    /// sibling future's read routes this query's reply here; the slot is
    /// released when this handle drops. Returns the handle plus the tag
    /// actually reserved — on a re-roll the caller must re-stamp its payload.
    pub fn shared(
        io: Rc<RefCell<DnsMailbox>>,
        conn: Rc<RefCell<TcpConn>>,
        qid: u16,
        reroll: impl FnMut() -> u16,
    ) -> (Self, u16) {
        let tag = conn.borrow_mut().reserve(qid, reroll);
        (Conn { io, wire: Wire::Shared(conn, tag) }, tag)
    }

    fn fd(&self) -> i32 {
        match &self.wire {
            Wire::Datagram { sock } | Wire::Stream { sock, .. } => sock.as_raw_fd(),
            Wire::Shared(c, _) => c.borrow().fd(),
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
            Wire::Shared(c, _) => c.borrow().sock(),
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
            Wire::Shared(c, tag) => c.borrow_mut().take(*tag),
            _ => None,
        }
    }

    /// One non-blocking read of this conn's next message: a datagram, a framed
    /// one-shot stream message, or this tag's routed message off the shared
    /// conn. `Poll::Pending` = nothing yet (WouldBlock / incomplete). The recv
    /// goes through this lookup's mailbox `scratch`, taken OUT of the mailbox
    /// for the read's span (each `borrow_mut` ends at its `;`) so the C recv
    /// callback under `Socket::recv` fires with no mailbox borrow live.
    fn read(&mut self) -> Poll<io::Result<Vec<u8>>> {
        let mut scratch = std::mem::take(&mut self.io.borrow_mut().scratch);
        let r = match &mut self.wire {
            Wire::Datagram { sock } => recv_datagram(&**sock, &mut scratch),
            Wire::Stream { sock, rbuf } => {
                // One-shot stream: drain bytes, then try to pop one frame. A
                // buffered frame delivers even on a dead socket; else a dead
                // socket errors, a live-but-incomplete is `Pending`.
                let alive = recv_stream(&**sock, rbuf, &mut scratch);
                match dns_frame(rbuf) {
                    Some(frame) => Poll::Ready(Ok(frame)),
                    None if !alive => Poll::Ready(Err(dead())),
                    None => Poll::Pending,
                }
            }
            // The shared conn owns the drain+route+demux (per-tag inbox).
            Wire::Shared(c, tag) => c.borrow_mut().poll_read(*tag, &mut scratch),
        };
        self.io.borrow_mut().scratch = scratch; // put back (grown on first use)
        r
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
            c.borrow_mut().release(*tag);
        }
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

    /// `Conn::shared` propagates the reserved tag, and dropping a `Conn` frees
    /// exactly its own shared-conn slot (RAII). The reroll *loop* itself is
    /// covered in `tcp_pool`; here we check the `Conn` wiring around it.
    #[test]
    fn shared_conn_releases_slot_on_drop() {
        let tc = TcpConn::new(Rc::new(AlwaysReadable { fd: 5 }));
        let io: Rc<RefCell<DnsMailbox>> = Rc::new(RefCell::new(DnsMailbox::default()));

        let (a, ta) = Conn::shared(io.clone(), tc.clone(), 7, || panic!("free qid must not reroll"));
        assert_eq!(ta, 7);
        // Second checkout collides on 7 → rerolls to 9.
        let (b, tb) = Conn::shared(io.clone(), tc.clone(), 7, || 9);
        assert_eq!(tb, 9);
        assert!(tc.borrow().has_waiter(7) && tc.borrow().has_waiter(9));

        drop(a);
        assert!(!tc.borrow().has_waiter(7) && tc.borrow().has_waiter(9));
        drop(b);
        assert!(!tc.borrow().has_waiter(9));
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
