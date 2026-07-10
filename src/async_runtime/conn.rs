//! The async socket layer the resolver ops drive — tokio-style connections
//! over the pure-IO reactor (`async_runtime::executor`). This module knows sockets,
//! framed streams, and mux tags; it knows **zero** about its application:
//! like the executor it is generic over the mailbox's app-state `A`, and
//! nothing in here names a protocol.
//!
//! - [`Conn`] — a query's connection. It owns its mailbox handle, so IO reads
//!   tokio-style: `conn.send(bytes, timeout).await` /
//!   `conn.recv(timeout).await`. The wire behind it is either an exclusively
//!   owned socket (a datagram socket, or a one-shot stream) or a checkout of a
//!   shared stream connection; the datagram-vs-demuxed-stream asymmetry is
//!   hidden behind the methods.
//! - [`TcpConn`] / [`TcpPool`] — shared stream connections, keyed by an opaque
//!   caller index so parallel queries to one peer share a socket. A stream
//!   carries u16-BE length-prefixed frames; each is routed to a per-tag inbox
//!   slot by the caller-supplied `tag_of` extractor. [`Conn::shared`] reserves
//!   a tag's slot and dropping the `Conn` releases it (RAII — no manual
//!   register/clear).

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::task::Poll;
use std::time::Instant;

use crate::async_runtime::executor::{
    poll_recv, poll_timeout, recv_datagram, recv_stream, select2, send_when_writable, QueryIo,
    Recv, Which2,
};
use crate::async_runtime::socket::{Socket, SocketFactory};

/// How a shared stream picks the inbox slot for an incoming frame: the frame's
/// mux tag. `None` = the frame is too short/malformed to carry one; it is
/// handed to any awaiting slot so the application can reject it.
pub type TagOf = fn(&[u8]) -> Option<u16>;

/// Pop one complete u16-BE length-prefixed frame off a stream receive buffer,
/// or `None` if a full frame hasn't accumulated yet.
pub fn extract_frame(rbuf: &mut Vec<u8>) -> Option<Vec<u8>> {
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

/// A shared stream connection to one peer, cooperatively driven by every
/// future that has an outstanding query on it: a per-connection reassembly
/// buffer plus the tag-demuxed inbox the futures share.
pub struct TcpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    rbuf: Vec<u8>,
    tag_of: TagOf,
    /// tag -> reply slot: `None` = still awaited, `Some` = delivered, waiting
    /// to be taken by that future.
    inbox: HashMap<u16, Option<Vec<u8>>>,
}

impl TcpConn {
    /// Drain the socket, reassemble frames, and route each by its tag into
    /// `inbox` (frames with no registered waiter are dropped). Returns `false`
    /// if the connection died (EOF / hard error). Idempotent: a sibling future
    /// calling this after the socket is drained just no-ops.
    fn recv_and_route(&mut self) -> bool {
        let alive = recv_stream(&*self.sock, &mut self.rbuf);
        while let Some(frame) = extract_frame(&mut self.rbuf) {
            if let Some(tag) = (self.tag_of)(&frame) {
                if let Some(slot) = self.inbox.get_mut(&tag) {
                    *slot = Some(frame);
                }
                // Unknown tag → drop (a stray/late frame).
            } else if let Some((_, slot)) = self.inbox.iter_mut().find(|(_, s)| s.is_none()) {
                // An untaggable frame: hand it to one awaiting waiter so the
                // application sees (and rejects) it.
                *slot = Some(frame);
            }
        }
        alive
    }
}

/// Shared stream connections keyed by an opaque caller index. A future
/// consults this before opening a stream socket so parallel queries to one
/// peer share a connection.
pub struct TcpPool {
    conns: HashMap<usize, Rc<RefCell<TcpConn>>>,
    tag_of: TagOf,
}

impl TcpPool {
    pub fn new(tag_of: TagOf) -> Self {
        TcpPool { conns: HashMap::new(), tag_of }
    }

    pub fn clear(&mut self) {
        self.conns.clear();
    }

    /// Drop a dead connection so the next query to that peer reconnects.
    pub fn remove(&mut self, key: usize) {
        self.conns.remove(&key);
    }

    /// Reuse the live connection to `key`, else open one bound to `bind` and
    /// connect it to `to`.
    pub fn get_or_create(
        &mut self,
        key: usize,
        factory: &Rc<dyn SocketFactory>,
        bind: SocketAddr,
        to: SocketAddr,
    ) -> Result<Rc<RefCell<TcpConn>>, ()> {
        if let Some(c) = self.conns.get(&key) {
            return Ok(c.clone());
        }
        let sock = factory.create_tcp(bind).map_err(|_| ())?;
        let _ = sock.connect(to); // optimistic (EINPROGRESS → Ok)
        let fd = sock.as_raw_fd();
        let conn = Rc::new(RefCell::new(TcpConn {
            sock,
            fd,
            rbuf: Vec::new(),
            tag_of: self.tag_of,
            inbox: HashMap::new(),
        }));
        self.conns.insert(key, conn.clone());
        Ok(conn)
    }
}

/// A query's connection — the socket object the handler drives, tokio-style.
/// It **owns its mailbox** (`io`), so `send`/`recv` take no reactor handle:
/// `conn.send(bytes, timeout).await` / `conn.recv(timeout).await`, just
/// like `socket.recv(..).await`.
pub struct Conn<A> {
    io: Rc<RefCell<QueryIo<A>>>,
    wire: Wire,
}

/// The transport behind a [`Conn`]: an exclusively owned socket (datagram, or
/// a one-shot stream), or this query's tag on a shared stream connection.
enum Wire {
    Owned { sock: Rc<dyn Socket>, is_tcp: bool, rbuf: Vec<u8> },
    Shared(Rc<RefCell<TcpConn>>, u16),
}

impl<A> Conn<A> {
    /// An owned socket (datagram, or a one-shot stream), already connected.
    pub fn owned(io: Rc<RefCell<QueryIo<A>>>, sock: Rc<dyn Socket>, is_tcp: bool) -> Self {
        Conn { io, wire: Wire::Owned { sock, is_tcp, rbuf: Vec::new() } }
    }

    /// A query's handle on a shared stream conn. Reserves `tag`'s inbox slot
    /// so a sibling future's read routes this query's reply here; the slot is
    /// released when the handle drops.
    pub fn shared(io: Rc<RefCell<QueryIo<A>>>, conn: Rc<RefCell<TcpConn>>, tag: u16) -> Self {
        conn.borrow_mut().inbox.insert(tag, None);
        Conn { io, wire: Wire::Shared(conn, tag) }
    }

    fn fd(&self) -> i32 {
        match &self.wire {
            Wire::Owned { sock, .. } => sock.as_raw_fd(),
            Wire::Shared(c, _) => c.borrow().fd,
        }
    }

    pub fn is_tcp(&self) -> bool {
        match &self.wire {
            Wire::Owned { is_tcp, .. } => *is_tcp,
            Wire::Shared(..) => true,
        }
    }

    /// Await writability, then send `bytes` once (WouldBlock re-awaits). The
    /// socket was connected at creation. Errors: the socket's own error on a
    /// hard send failure, `ErrorKind::TimedOut` on timeout before writable.
    pub async fn send(&self, bytes: &[u8], timeout: Instant) -> io::Result<()> {
        let sock: Rc<dyn Socket> = match &self.wire {
            Wire::Owned { sock, .. } => sock.clone(),
            Wire::Shared(c, _) => c.borrow().sock.clone(),
        };
        send_when_writable(&self.io, &*sock, bytes, timeout).await
    }

    /// One non-blocking read of this conn's next message: a datagram / one-shot
    /// stream frame (owned), or this tag's routed frame off the shared conn.
    /// `Recv::Pending` = nothing yet (WouldBlock / incomplete).
    fn read(&mut self) -> Recv {
        match &mut self.wire {
            Wire::Owned { sock, is_tcp, rbuf } => {
                if !*is_tcp {
                    return recv_datagram(&**sock);
                }
                // One-shot stream: drain bytes, then try to pop one frame. A
                // buffered frame delivers even on a dead socket; else a dead
                // socket is `Dead`, a live-but-incomplete is `Pending`.
                let alive = recv_stream(&**sock, rbuf);
                match extract_frame(rbuf) {
                    Some(frame) => Recv::Msg(frame),
                    None if !alive => Recv::Dead,
                    None => Recv::Pending,
                }
            }
            Wire::Shared(c, tag) => {
                let mut conn = c.borrow_mut();
                let alive = conn.recv_and_route();
                match conn.inbox.get_mut(tag).and_then(|slot| slot.take()) {
                    Some(msg) => Recv::Msg(msg),
                    None if !alive => Recv::Dead,
                    None => Recv::Pending,
                }
            }
        }
    }

    /// The readiness-driven recv arm for `select2`/`select3`: on this conn's fd
    /// firing, do one non-blocking [`read`](Self::read). Uses the conn's own
    /// mailbox. Resolves `Ok(bytes)` or `Err(UnexpectedEof)` (dead socket).
    pub fn recv_arm(&mut self) -> Poll<io::Result<Vec<u8>>> {
        let fd = self.fd();
        let io = self.io.clone();
        poll_recv(&io, fd, || self.read())
    }

    /// tokio-style `conn.recv(timeout).await`: await this conn's next message,
    /// bounded by `timeout` (a 2-arm select over the conn's own mailbox,
    /// timeout-biased to match the classic expiry-preempts-read order).
    /// Errors: `ErrorKind::TimedOut` on expiry, `ErrorKind::UnexpectedEof` on a
    /// dead socket (EOF / hard recv error).
    pub async fn recv(&mut self, timeout: Instant) -> io::Result<Vec<u8>> {
        let io = self.io.clone();
        match select2(&io, |io| poll_timeout(io, timeout), |_| self.recv_arm()).await {
            Which2::A(()) => Err(io::ErrorKind::TimedOut.into()),
            Which2::B(r) => r,
        }
    }
}

/// Dropping a query's conn releases its shared-stream inbox slot (RAII — no
/// manual register/clear), so retries, delivery, and abandonment can't leak slots.
impl<A> Drop for Conn<A> {
    fn drop(&mut self) {
        if let Wire::Shared(c, tag) = &self.wire {
            c.borrow_mut().inbox.remove(tag);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::extract_frame;

    #[test]
    fn frame_extraction() {
        let mut rbuf = vec![0x00, 0x03, 1, 2, 3, 0x00];
        assert_eq!(extract_frame(&mut rbuf), Some(vec![1, 2, 3]));
        assert_eq!(rbuf, vec![0x00]); // partial next frame stays buffered
        assert_eq!(extract_frame(&mut rbuf), None);
        rbuf.push(0x02);
        assert_eq!(extract_frame(&mut rbuf), None); // length known, payload missing
        rbuf.extend_from_slice(&[9, 8]);
        assert_eq!(extract_frame(&mut rbuf), Some(vec![9, 8]));
        assert!(rbuf.is_empty());
    }
}
