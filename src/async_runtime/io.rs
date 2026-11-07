//! Byte-level async sockets: [`Async`] (async-io's `Async<T>` over the host's
//! [`Socket`]) plus the non-blocking recv bodies. Knows bytes, not messages —
//! framing and demux are the application's business.
//!
//! Unlike async-io, I/O is attempted only **after** the caller reported
//! readiness: caller-supplied sockets may block, or return zero-length
//! "datagrams" that must not be mistaken for data.

use std::cell::Cell;
use std::io;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Instant;

use futures_util::{select_biased, FutureExt};

use crate::async_runtime::reactor::{Reactor, Ready, Source, Timer, READ, WRITE};
use crate::async_runtime::socket::Socket;

/// The uniform dead-socket error (EOF / hard recv failure).
pub(crate) fn dead() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")
}

/// A socket registered with the reactor; dropping it deregisters the fd before
/// the socket itself closes.
pub(crate) struct Async {
    source: Rc<Source>,
    reactor: Rc<Reactor>,
    /// Ticker value of the last read attempt, so a same-turn peek
    /// ([`readable_this_turn`](Self::readable_this_turn)) never re-reads a
    /// readiness report something already consumed.
    read_tick: Cell<Option<usize>>,
    sock: Rc<dyn Socket>,
}

impl Async {
    pub(crate) fn new(sock: Rc<dyn Socket>, reactor: &Rc<Reactor>) -> Rc<Self> {
        let source = reactor.insert_io(sock.as_raw_fd());
        Rc::new(Async { source, reactor: reactor.clone(), read_tick: Cell::new(None), sock })
    }

    pub(crate) fn get_ref(&self) -> &dyn Socket {
        &*self.sock
    }

    pub(crate) fn reactor(&self) -> &Rc<Reactor> {
        &self.reactor
    }

    /// Resolves on the next readable report for this fd.
    pub(crate) fn readable(&self) -> Ready {
        Ready::new(self.reactor.clone(), self.source.clone(), READ)
    }

    /// Resolves on the next writable report for this fd.
    pub(crate) fn writable(&self) -> Ready {
        Ready::new(self.reactor.clone(), self.source.clone(), WRITE)
    }

    /// The caller reported this fd readable in the current turn and nothing has
    /// read since — the peek for a timeout that expired alongside readiness.
    pub(crate) fn readable_this_turn(&self) -> bool {
        let now = self.reactor.ticker();
        self.source.tick(READ) == now && self.read_tick.get() != Some(now)
    }

    /// One read attempt with the reactor's scratch; marks this turn's readiness consumed.
    pub(crate) fn read<R>(&self, op: impl FnOnce(&dyn Socket, &mut Vec<u8>) -> R) -> R {
        self.read_tick.set(Some(self.reactor.ticker()));
        self.reactor.with_scratch(|scratch| {
            ensure_scratch(scratch);
            op(&*self.sock, scratch)
        })
    }
}

impl Drop for Async {
    fn drop(&mut self) {
        self.reactor.remove_io(&self.source);
    }
}

/// Grow the receive scratch to 64 KB on first use.
fn ensure_scratch(scratch: &mut Vec<u8>) {
    if scratch.is_empty() {
        scratch.resize(65_535, 0);
    }
}

/// Await writability, then send once. Writability is checked before expiry, so
/// a fd that fired in the same turn the timeout passed still sends.
pub(crate) async fn send_when_writable(sock: &Async, bytes: &[u8], timeout: Instant) -> io::Result<()> {
    loop {
        {
            let mut writable = pin!(sock.writable().fuse());
            let mut t = pin!(Timer::at(sock.reactor(), timeout).fuse());
            select_biased! {
                _ = writable => {}
                _ = t => return Err(io::ErrorKind::TimedOut.into()), // timed out before writable
            }
        }
        match sock.get_ref().send(bytes) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {} // re-await writable
            Err(e) => return Err(e),
        }
    }
}

/// One non-blocking datagram receive (UDP) into `scratch`: `Ready` on any read
/// including zero-length, `Pending` on `WouldBlock`, `Ready(Err)` on hard error.
pub(crate) fn recv_datagram(sock: &dyn Socket, scratch: &mut [u8]) -> Poll<io::Result<Vec<u8>>> {
    match sock.recv(scratch) {
        Ok((n, _)) => Poll::Ready(Ok(scratch[..n].to_vec())),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(_) => Poll::Ready(Err(dead())),
    }
}

/// Drain available stream bytes (TCP) into `buf`; `false` if the connection died.
pub(crate) fn recv_stream(sock: &dyn Socket, buf: &mut Vec<u8>, scratch: &mut [u8]) -> bool {
    match sock.recv(scratch) {
        Ok((0, _)) => false, // peer closed
        Ok((n, _)) => {
            buf.extend_from_slice(&scratch[..n]);
            true
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::task::{Context, Waker};

    struct Counting {
        reads: Cell<usize>,
    }
    impl Socket for Counting {
        fn as_raw_fd(&self) -> i32 {
            11
        }
        fn connect(&self, _addr: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            self.reads.set(self.reads.get() + 1);
            Ok((0, None))
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }
    }

    #[test]
    fn readable_this_turn_needs_a_report_and_is_consumed_by_a_read() {
        let r = Reactor::new();
        let sock = Rc::new(Counting { reads: Cell::new(0) });
        let a = Async::new(sock.clone(), &r);
        assert!(!a.readable_this_turn(), "no report yet (C1)");

        let mut rd = Box::pin(a.readable());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(rd.as_mut().poll(&mut cx).is_pending());
        r.dispatch(Instant::now(), true, |fd, w| fd == 11 && !w);
        assert!(a.readable_this_turn());

        let _ = a.read(|s, buf| recv_datagram(s, buf));
        assert_eq!(sock.reads.get(), 1);
        assert!(!a.readable_this_turn(), "a read consumes the report");

        r.dispatch(Instant::now(), true, |_, _| false);
        drop(rd);
        assert!(!a.readable_this_turn(), "readiness lasts one turn (C2)");
    }

    #[test]
    fn dropping_async_deregisters_its_fd() {
        let r = Reactor::new();
        let a = Async::new(Rc::new(Counting { reads: Cell::new(0) }), &r);
        let mut rd = Box::pin(a.writable());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(rd.as_mut().poll(&mut cx).is_pending());
        assert_eq!(r.interests(), vec![(11, true)]);
        drop(rd);
        drop(a);
        assert!(r.interests().is_empty());
    }

}
