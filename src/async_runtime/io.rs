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
use std::time::Instant;

use futures_util::{select_biased, FutureExt};

use crate::async_runtime::reactor::{Reactor, Ready, Source, Timer, READ, WRITE};
use crate::async_runtime::socket::Socket;

/// The uniform dead-socket error (EOF / hard recv failure).
pub fn dead() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")
}

/// A socket registered with the reactor; dropping it deregisters the fd before
/// the socket itself closes.
pub struct Async {
    source: Rc<Source>,
    reactor: Rc<Reactor>,
    /// Ticker value of the last read attempt, so a same-turn peek
    /// ([`readable_this_turn`](Self::readable_this_turn)) never re-reads a
    /// readiness report something already consumed.
    read_tick: Cell<Option<usize>>,
    sock: Rc<dyn Socket>,
}

impl Async {
    pub fn new(sock: Rc<dyn Socket>, reactor: &Rc<Reactor>) -> Rc<Self> {
        let source = reactor.insert_io(sock.as_raw_fd());
        Rc::new(Async { source, reactor: reactor.clone(), read_tick: Cell::new(None), sock })
    }

    pub fn get_ref(&self) -> &dyn Socket {
        &*self.sock
    }

    pub fn reactor(&self) -> &Rc<Reactor> {
        &self.reactor
    }

    /// Resolves on the next readable report for this fd.
    pub fn readable(&self) -> Ready {
        Ready::new(self.reactor.clone(), self.source.clone(), READ)
    }

    /// Resolves on the next writable report for this fd.
    pub fn writable(&self) -> Ready {
        Ready::new(self.reactor.clone(), self.source.clone(), WRITE)
    }

    /// The caller reported this fd readable in the current turn and nothing has
    /// read since — the peek for a timeout that expired alongside readiness.
    pub fn readable_this_turn(&self) -> bool {
        let now = self.reactor.ticker();
        self.source.tick(READ) == now && self.read_tick.get() != Some(now)
    }

    /// One non-blocking stream read, using the reactor scratch and marking this
    /// turn's readiness consumed. `Ok(None)` means `WouldBlock`;
    /// `Ok(Some(0))` means EOF; `Ok(Some(n))` appended `n` bytes to `out`.
    /// This is internal DNS-pool plumbing: generic callers use
    /// [`read`](Self::read).
    pub(crate) fn read_stream(&self, out: &mut Vec<u8>) -> io::Result<Option<usize>> {
        self.read_tick.set(Some(self.reactor.ticker()));
        self.reactor.with_scratch(|scratch| {
            ensure_scratch(scratch);
            match self.sock.recv(scratch) {
                Ok((n, _)) => {
                    out.extend_from_slice(&scratch[..n]);
                    Ok(Some(n))
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e),
            }
        })
    }

    /// One non-blocking datagram read, using the reactor scratch.
    /// `Ok(None)` means `WouldBlock`; `Ok(Some(frame))` is one datagram,
    /// including a valid zero-length one. Internal to the DNS pools.
    pub(crate) fn read_datagram(&self) -> io::Result<Option<Vec<u8>>> {
        self.read_tick.set(Some(self.reactor.ticker()));
        self.reactor.with_scratch(|scratch| {
            ensure_scratch(scratch);
            match self.sock.recv(scratch) {
                Ok((n, _)) => Ok(Some(scratch[..n].to_vec())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e),
            }
        })
    }

    /// Read once, waiting for readability if necessary. Returns the number of
    /// bytes read: `0` means end-of-stream for a TCP socket, or a valid
    /// zero-length datagram for UDP. `deadline` is an absolute `Instant`.
    pub async fn read(&self, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
        loop {
            let mut readable = pin!(self.readable().fuse());
            let mut t = pin!(Timer::at(&self.reactor, deadline).fuse());
            select_biased! {
                _ = readable => {}
                _ = t => return Err(io::ErrorKind::TimedOut.into()),
            }

            // Mark the turn before the syscall: a same-turn readiness peek must
            // not re-read data this attempt may have consumed.
            self.read_tick.set(Some(self.reactor.ticker()));
            match self.get_ref().recv(buf) {
                Ok((n, _)) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Spurious readiness; wait for the next report.
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Read exactly `buf.len()` bytes before `deadline`. Stream-only: a
    /// zero-length read is reported as `UnexpectedEof`.
    pub async fn read_exact(&self, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..], deadline).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            filled += n;
        }
        Ok(())
    }

    /// Write once, waiting for writability if the socket reports `WouldBlock`.
    /// Returns the number of bytes accepted, which may be less than
    /// `bytes.len()` on a stream socket. `deadline` is an absolute `Instant`.
    pub async fn write(&self, bytes: &[u8], deadline: Instant) -> io::Result<usize> {
        loop {
            match self.get_ref().send(bytes) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let mut writable = pin!(self.writable().fuse());
                    let mut t = pin!(Timer::at(&self.reactor, deadline).fuse());
                    select_biased! {
                        _ = writable => {}
                        _ = t => return Err(io::ErrorKind::TimedOut.into()),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Write every byte before `deadline`.
    ///
    /// This is the stream-friendly counterpart of [`write`](Self::write): it
    /// retries short writes and reports `WriteZero` if the socket accepts no
    /// more bytes. Datagram sockets normally accept the whole buffer on the
    /// first send.
    pub async fn write_all(&self, bytes: &[u8], deadline: Instant) -> io::Result<()> {
        let mut sent = 0;
        while sent < bytes.len() {
            let n = self.write(&bytes[sent..], deadline).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            sent += n;
        }
        Ok(())
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

        let _ = a.read_datagram();
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
