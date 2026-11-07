//! Byte-level, readiness-driven IO arms over [`Socket`] + [`Mailbox`]: knows
//! bytes, not messages — framing and demux are the application's business.

use std::cell::RefCell;
use std::future::poll_fn;
use std::io;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Instant;

use futures_util::{select_biased, FutureExt};

use crate::async_runtime::executor::{sleep_until, Mailbox, Wait};
use crate::async_runtime::socket::Socket;

/// The uniform dead-socket error (EOF / hard recv failure).
pub(crate) fn dead() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")
}

/// Grow the mailbox's receive scratch to 64 KB on first use (see `Mailbox::scratch`).
fn ensure_scratch(scratch: &mut Vec<u8>) {
    if scratch.is_empty() {
        scratch.resize(65_535, 0);
    }
}

/// Await writability, then send once. Writability is checked before expiry, so
/// a fd that fired in the same cycle the timeout passed still sends.
pub(crate) async fn send_when_writable<A>(
    io: &Rc<RefCell<Mailbox<A>>>,
    sock: &dyn Socket,
    bytes: &[u8],
    timeout: Instant,
) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    loop {
        {
            let mut writable = pin!(poll_fn(|_| poll_writable(io, fd)).fuse());
            let mut t = pin!(sleep_until(io, timeout).fuse());
            select_biased! {
                _ = writable => {}
                _ = t => return Err(io::ErrorKind::TimedOut.into()), // timed out before writable
            }
        }
        match sock.send(bytes) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {} // re-await writable
            Err(e) => return Err(e),
        }
    }
}

/// One non-blocking datagram receive (UDP) into `scratch`: `Ready` on any read
/// including zero-length, `Pending` on `WouldBlock`, `Ready(Err)` on hard error.
pub(crate) fn recv_datagram(sock: &dyn Socket, scratch: &mut Vec<u8>) -> Poll<io::Result<Vec<u8>>> {
    ensure_scratch(scratch);
    match sock.recv(scratch) {
        Ok((n, _)) => Poll::Ready(Ok(scratch[..n].to_vec())),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(_) => Poll::Ready(Err(dead())),
    }
}

/// Drain available stream bytes (TCP) into `buf`; `false` if the connection died.
pub(crate) fn recv_stream(sock: &dyn Socket, buf: &mut Vec<u8>, scratch: &mut Vec<u8>) -> bool {
    ensure_scratch(scratch);
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

/// Recv arm body. Consumes only read readiness for `fd` (leaving a sibling
/// send-arm's write readiness intact) and runs `read` once; a `WouldBlock`
/// re-registers read interest. `Ok(bytes)` for a message, `UnexpectedEof` when dead.
pub(crate) fn poll_recv<A>(
    io: &Rc<RefCell<Mailbox<A>>>,
    fd: i32,
    mut read: impl FnMut() -> Poll<io::Result<Vec<u8>>>,
) -> Poll<io::Result<Vec<u8>>> {
    let fired = {
        let mut m = io.borrow_mut();
        match m.fired.iter().position(|w| w.fd == fd && !w.writable) {
            Some(pos) => {
                m.fired.swap_remove(pos);
                true
            }
            None => {
                m.waits.push(Wait { fd, writable: false });
                false
            }
        }
    };
    if !fired {
        return Poll::Pending;
    }
    match read() {
        Poll::Pending => {
            io.borrow_mut().waits.push(Wait { fd, writable: false });
            Poll::Pending
        }
        ready => ready,
    }
}

/// Writability arm: consume `fd`'s write readiness or register interest.
fn poll_writable<A>(io: &Rc<RefCell<Mailbox<A>>>, fd: i32) -> Poll<()> {
    let mut m = io.borrow_mut();
    match m.fired.iter().position(|w| w.fd == fd && w.writable) {
        Some(pos) => {
            m.fired.swap_remove(pos);
            Poll::Ready(())
        }
        None => {
            m.waits.push(Wait { fd, writable: true });
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn mailbox() -> Rc<RefCell<Mailbox<()>>> {
        Rc::new(RefCell::new(Mailbox::default()))
    }

    fn rd(fd: i32) -> Wait {
        Wait { fd, writable: false }
    }

    #[test]
    fn poll_recv_not_fired_registers_wait() {
        let io = mailbox();
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Poll::Ready(Ok(vec![1]))
        });
        assert!(matches!(p, Poll::Pending));
        assert_eq!(calls.get(), 0); // read not attempted before readiness
        assert_eq!(io.borrow().waits.iter().map(|w| w.fd).collect::<Vec<_>>(), vec![7]);
    }

    #[test]
    fn poll_recv_fired_msg_consumes_only_its_fd() {
        let io = mailbox();
        io.borrow_mut().fired = vec![rd(3), rd(7), rd(9)];
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Poll::Ready(Ok(vec![42]))
        });
        assert!(matches!(p, Poll::Ready(Ok(ref b)) if b == &[42]));
        assert_eq!(calls.get(), 1);
        // Only fd 7 consumed; siblings 3 and 9 remain for their own arms.
        let fds: Vec<i32> = io.borrow().fired.iter().map(|w| w.fd).collect();
        assert!(!fds.contains(&7) && fds.contains(&3) && fds.contains(&9));
    }

    #[test]
    fn poll_recv_ignores_a_write_readiness_on_its_fd() {
        // A read-arm must not consume a *write* readiness on the same fd (that
        // belongs to a sibling send-arm sharing the socket).
        let io = mailbox();
        io.borrow_mut().fired = vec![Wait { fd: 7, writable: true }];
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Poll::Ready(Ok(vec![1]))
        });
        assert!(matches!(p, Poll::Pending));
        assert_eq!(calls.get(), 0); // did not read
        // The write readiness is left intact for the send-arm.
        assert!(io.borrow().fired.iter().any(|w| w.fd == 7 && w.writable));
    }

    #[test]
    fn poll_recv_wouldblock_reregisters_single_read() {
        let io = mailbox();
        io.borrow_mut().fired = vec![rd(7)];
        let calls = Cell::new(0);
        let p = poll_recv(&io, 7, || {
            calls.set(calls.get() + 1);
            Poll::Pending
        });
        assert!(matches!(p, Poll::Pending));
        assert_eq!(calls.get(), 1); // read exactly once — no double recvfrom
        assert!(io.borrow().fired.is_empty()); // fd consumed
        assert_eq!(io.borrow().waits.iter().map(|w| w.fd).collect::<Vec<_>>(), vec![7]); // re-registered
    }

    #[test]
    fn poll_recv_dead() {
        let io = mailbox();
        io.borrow_mut().fired = vec![rd(7)];
        let p = poll_recv(&io, 7, || Poll::Ready(Err(dead())));
        assert!(matches!(p, Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof));
    }
}
