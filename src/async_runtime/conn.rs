//! The async socket layer the resolver ops drive — tokio-style connections
//! over the pure-IO reactor (`async_runtime::executor`). This module knows sockets,
//! framed streams, and mux tags; it knows **zero** about its application:
//! like the executor it is generic over the mailbox's app-state `A`, and
//! nothing in here names a protocol or a wire format.
//!
//! - [`Conn`] — a query's connection. It owns its mailbox handle, so IO reads
//!   tokio-style: `conn.send(bytes, timeout).await` /
//!   `conn.recv(timeout).await`. The wire behind it is either an exclusively
//!   owned socket (a datagram socket, or a one-shot stream) or a checkout of a
//!   shared stream connection; the datagram-vs-demuxed-stream asymmetry is
//!   hidden behind the methods.
//! - [`TcpConn`] / [`TcpPool`] — shared stream connections, keyed by an opaque
//!   caller index so parallel queries to one peer share a socket. How the
//!   stream's bytes delimit messages is the application's business: the caller
//!   supplies the framer ([`FrameOf`]) that pops complete messages off the
//!   reassembly buffer, and the [`TagOf`] extractor that routes each message
//!   to a per-tag inbox slot. [`Conn::shared`] reserves a tag's slot and
//!   dropping the `Conn` releases it (RAII — no manual register/clear).

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Instant;

use futures_util::{select_biased, FutureExt};

use crate::async_runtime::executor::{
    poll_recv, recv_datagram, recv_stream, send_when_writable, sleep_until, QueryIo, Recv,
};
use crate::async_runtime::socket::{Socket, SocketFactory};

/// How a shared stream picks the inbox slot for an incoming frame: the frame's
/// mux tag. `None` = the frame is too short/malformed to carry one; it is
/// handed to any awaiting slot so the application can reject it.
pub type TagOf = fn(&[u8]) -> Option<u16>;

/// How a stream's bytes are cut into messages: pop one complete frame off the
/// reassembly buffer, or `None` until more bytes arrive. Message delimiting is
/// an application-protocol convention (a length prefix, a terminator, …) — TCP
/// itself has none and the runtime knows no wire format, so the caller
/// supplies this.
pub type FrameOf = fn(&mut Vec<u8>) -> Option<Vec<u8>>;

/// A shared stream connection to one peer, cooperatively driven by every
/// future that has an outstanding query on it: a per-connection reassembly
/// buffer plus the tag-demuxed inbox the futures share.
pub struct TcpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    rbuf: Vec<u8>,
    frame_of: FrameOf,
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
        while let Some(frame) = (self.frame_of)(&mut self.rbuf) {
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
    frame_of: FrameOf,
    tag_of: TagOf,
}

impl TcpPool {
    pub fn new(frame_of: FrameOf, tag_of: TagOf) -> Self {
        TcpPool { conns: HashMap::new(), frame_of, tag_of }
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
            frame_of: self.frame_of,
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

/// The transport behind a [`Conn`]: an exclusively owned datagram socket, an
/// exclusively owned one-shot stream, or this query's tag on a shared stream
/// connection.
enum Wire {
    Datagram { sock: Rc<dyn Socket> },
    Stream { sock: Rc<dyn Socket>, rbuf: Vec<u8>, frame_of: FrameOf },
    Shared(Rc<RefCell<TcpConn>>, u16),
}

impl<A> Conn<A> {
    /// An owned datagram socket, already connected. One recv = one message.
    pub fn datagram(io: Rc<RefCell<QueryIo<A>>>, sock: Rc<dyn Socket>) -> Self {
        Conn { io, wire: Wire::Datagram { sock } }
    }

    /// An owned one-shot stream socket, already connected; `frame_of` cuts its
    /// bytes into messages.
    pub fn stream(io: Rc<RefCell<QueryIo<A>>>, sock: Rc<dyn Socket>, frame_of: FrameOf) -> Self {
        Conn { io, wire: Wire::Stream { sock, rbuf: Vec::new(), frame_of } }
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
            Wire::Datagram { sock } | Wire::Stream { sock, .. } => sock.as_raw_fd(),
            Wire::Shared(c, _) => c.borrow().fd,
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
            Wire::Shared(c, _) => c.borrow().sock.clone(),
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
            Wire::Shared(c, tag) => c.borrow_mut().inbox.get_mut(tag).and_then(|slot| slot.take()),
            _ => None,
        }
    }

    /// One non-blocking read of this conn's next message: a datagram, a framed
    /// one-shot stream message, or this tag's routed message off the shared
    /// conn. `Recv::Pending` = nothing yet (WouldBlock / incomplete).
    fn read(&mut self) -> Recv {
        match &mut self.wire {
            Wire::Datagram { sock } => recv_datagram(&**sock),
            Wire::Stream { sock, rbuf, frame_of } => {
                // One-shot stream: drain bytes, then try to pop one frame. A
                // buffered frame delivers even on a dead socket; else a dead
                // socket is `Dead`, a live-but-incomplete is `Pending`.
                let alive = recv_stream(&**sock, rbuf);
                match frame_of(rbuf) {
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
impl<A> Drop for Conn<A> {
    fn drop(&mut self) {
        if let Wire::Shared(c, tag) = &self.wire {
            c.borrow_mut().inbox.remove(tag);
        }
    }
}
