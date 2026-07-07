//! The fd-owning async resolver engine (standalone).
//!
//! Each migrated `ares_*` lifecycle (`query`/`send`/`gethostbyname`) is a linear
//! `async fn` that **owns and drives its own socket(s)**: create / connect /
//! send / recv / TCP reassembly / TC-retry / timeout-retry / server-failover /
//! QID-match, all expressed as ordinary control flow. A future publishes the
//! fds it is blocked on (+ an earliest deadline) into its [`QueryIo`] mailbox;
//! the ffi executor (driven by `ares_process`) sets which fds fired (or that the
//! deadline passed) and re-polls the one future. The waker is a no-op —
//! readiness is driven, not scheduled.
//!
//! This module is a **standalone subsystem**: it depends only on the neutral
//! core (`socket`, `lookup`, `packets`, `response`, `query_builder`) and never
//! on `client.rs`/`transport.rs` (the classic reactor, slated for removal). It
//! reuses the reactor truth tables [`on_datagram`]/[`on_timeout`] directly.
//! Everything is safe (`forbid(unsafe_code)`); the C-callback firing lives in
//! `src/ffi/`, fed by the `effects` the future emits.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_int;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use bytes::BytesMut;

use crate::core::hostent::Hostent;
use crate::core::lookup::{
    extract_tcp_frame, on_datagram, on_timeout, qid_matches, summarize, ReactorAction, ServerHealth,
    TaskKind, TaskVerdict, TimeoutVerdict,
};
use crate::core::query_builder::frame_tcp;
use crate::core::socket::{Socket, SocketFactory};
use crate::ffi::error::{ARES_ECONNREFUSED, ARES_ETIMEOUT};

// ===== Mailbox + await primitive =====

/// One fd the future is blocked on, with the interest it awaits.
#[derive(Clone, Copy)]
pub(crate) struct Wait {
    pub fd: i32,
    pub writable: bool,
}

/// A fire-and-forget side effect the ffi applies after a poll — the one thing a
/// `forbid(unsafe_code)` future cannot do itself: fire the C server-state
/// callback.
pub(crate) enum Effect {
    /// Fire the C server-state callback.
    NotifyServerState { server: usize, ok: bool, tcp: bool },
}

/// The mailbox shared (via `Rc<RefCell<_>>`) between one lifecycle future and
/// the ffi executor. The future publishes `waits`/`deadline` when it suspends;
/// the executor sets `fired`/`expired` before re-polling. Nothing here names
/// the channel, so polling the future borrows nothing of `ChannelData`.
#[derive(Default)]
pub(crate) struct QueryIo {
    /// fds the future is currently blocked on (published on suspension).
    pub waits: Vec<Wait>,
    /// Earliest deadline the future wants to wake at.
    pub deadline: Option<Instant>,
    /// Effects the executor drains + applies after every poll.
    pub effects: Vec<Effect>,
    /// Which published-wait fds are ready now (set by the executor).
    pub fired: Vec<i32>,
    /// Whether the deadline passed (set by the executor).
    pub expired: bool,
}

/// The outcome of one [`WaitFds`] await: which fds fired, and whether it timed out.
pub(crate) struct Woke {
    pub fds: Vec<i32>,
    pub expired: bool,
}

/// The await primitive: resolve once the executor reports readiness for the
/// currently published waits. Borrows the mailbox only inside `poll`, never
/// across `.await`.
struct Ready1 {
    io: Rc<RefCell<QueryIo>>,
}

impl Future for Ready1 {
    type Output = Woke;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Woke> {
        let mut io = self.io.borrow_mut();
        if io.fired.is_empty() && !io.expired {
            return Poll::Pending;
        }
        Poll::Ready(Woke { fds: std::mem::take(&mut io.fired), expired: io.expired })
    }
}

/// Publish the `waits` (+ `deadline`) into the mailbox — reusing its `waits`
/// allocation, so a per-await stack slice avoids a heap allocation — then await
/// readiness. Clears the published waits on return so a later await starts clean.
async fn wait_io(io: &Rc<RefCell<QueryIo>>, waits: &[Wait], deadline: Instant) -> Woke {
    {
        let mut m = io.borrow_mut();
        m.waits.clear();
        m.waits.extend_from_slice(waits);
        m.deadline = Some(deadline);
        m.fired.clear();
        m.expired = false;
    }
    let woke = Ready1 { io: io.clone() }.await;
    io.borrow_mut().waits.clear();
    woke
}

fn push_effect(io: &Rc<RefCell<QueryIo>>, e: Effect) {
    io.borrow_mut().effects.push(e);
}

fn notify(io: &Rc<RefCell<QueryIo>>, actions: Vec<ReactorAction>) {
    for a in actions {
        match a {
            ReactorAction::NotifyServerState { server, ok, tcp } => {
                push_effect(io, Effect::NotifyServerState { server, ok, tcp })
            }
        }
    }
}

// ===== Delivery (the future's Output) =====

/// What the executor delivers to C once a lifecycle future completes; the ffi
/// completion path maps each arm to the right C callback.
pub(crate) enum Delivery {
    /// ares_query / ares_send: raw reply bytes or a status code.
    Raw { result: Result<Vec<u8>, c_int>, timeouts: c_int },
    /// ares_gethostbyname: a finished hostent (sortlist already applied) or a
    /// status code — the ffi only builds the C hostent + fires.
    Host { result: Result<Hostent, c_int>, timeouts: c_int },
}

// ===== Owned resources (built by the channel, held by the future) =====

/// A server's connect targets, precomputed from the channel config at launch so
/// the future needs no `Transport`/`Client`.
#[derive(Clone)]
pub(crate) struct ServerEndpoint {
    pub udp_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    pub bind: SocketAddr,
}

/// The retry/timeout knobs a query needs, snapshotted at launch.
#[derive(Clone, Copy)]
pub(crate) struct QueryOpts {
    pub attempts: u32,
    pub timeout: Duration,
    pub failover_chance: u16,
    pub failover_delay: u64,
}

/// Everything an async lifecycle owns. Cloneable `Rc` handles + a config
/// snapshot; the future never borrows the channel.
#[derive(Clone)]
pub(crate) struct Resources {
    pub factory: Rc<dyn SocketFactory>,
    pub health: Rc<RefCell<ServerHealth>>,
    pub endpoints: Rc<Vec<ServerEndpoint>>,
    pub tcp_pool: Rc<RefCell<TcpPool>>,
    pub opts: QueryOpts,
}


/// Descriptor the ffi turns into a `raw_lifecycle` future (ares_query/ares_send).
pub(crate) struct RawLaunch {
    pub res: Resources,
    pub payload: BytesMut,
}

// ===== Sockets =====

thread_local! {
    /// One reused 64 KB receive scratch buffer (a fresh `[0u8; 65535]` per recv
    /// would zero 64 KB every call). Single-threaded engine, borrowed only for
    /// the synchronous span of one recv.
    static RECV_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 65_535]);
}

/// A receive outcome: a complete DNS message, nothing yet (WouldBlock /
/// incomplete TCP frame), or a dead socket (TCP EOF / a hard recv error).
enum Recv {
    Msg(Vec<u8>),
    Pending,
    Dead,
}

/// An owned socket (UDP, or a one-shot TCP probe) with its own TCP reassembly
/// buffer.
struct OwnedSock {
    sock: Rc<dyn Socket>,
    is_tcp: bool,
    rbuf: Vec<u8>,
}

impl OwnedSock {
    fn fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }
    fn recv_msg(&mut self) -> Recv {
        RECV_BUF.with(|scratch| {
            let mut tmp = scratch.borrow_mut();
            match self.sock.recv(&mut tmp) {
                // TCP peer closed the connection.
                Ok((0, _)) if self.is_tcp => Recv::Dead,
                Ok((n, _)) if self.is_tcp => {
                    self.rbuf.extend_from_slice(&tmp[..n]);
                    extract_tcp_frame(&mut self.rbuf).map_or(Recv::Pending, Recv::Msg)
                }
                Ok((n, _)) => Recv::Msg(tmp[..n].to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if self.is_tcp {
                        extract_tcp_frame(&mut self.rbuf).map_or(Recv::Pending, Recv::Msg)
                    } else {
                        Recv::Pending
                    }
                }
                Err(_) => Recv::Dead,
            }
        })
    }
}

/// A shared TCP connection to one server, cooperatively driven by every future
/// that has an outstanding query on it. Ports the classic reactor's per-fd
/// reassembly buffer + QID demux into an object the futures share.
pub(crate) struct TcpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    rbuf: Vec<u8>,
    /// qid -> reply slot: `None` = still awaited, `Some` = delivered, waiting to
    /// be taken by that future.
    inbox: HashMap<u16, Option<Vec<u8>>>,
}

impl TcpConn {
    /// Drain the socket, reassemble frames, and route each by its header QID
    /// into `inbox` (frames with no registered waiter are dropped). Returns
    /// `false` if the connection died (EOF / hard error). Idempotent: a sibling
    /// future calling this after the socket is drained just no-ops.
    fn recv_and_route(&mut self) -> bool {
        let alive = RECV_BUF.with(|scratch| {
            let mut tmp = scratch.borrow_mut();
            match self.sock.recv(&mut tmp) {
                Ok((0, _)) => false, // peer closed
                Ok((n, _)) => {
                    self.rbuf.extend_from_slice(&tmp[..n]);
                    true
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
                Err(_) => false,
            }
        });
        while let Some(frame) = extract_tcp_frame(&mut self.rbuf) {
            if frame.len() >= 2 {
                let qid = u16::from_be_bytes([frame[0], frame[1]]);
                if let Some(slot) = self.inbox.get_mut(&qid) {
                    *slot = Some(frame);
                }
                // Unknown qid → drop (a stray/late reply).
            } else if let Some((_, slot)) = self.inbox.iter_mut().find(|(_, s)| s.is_none()) {
                // A frame too short to carry a qid (malformed): hand it to one
                // awaiting waiter so it fails to parse (EBADRESP), matching
                // qid_matches's acceptance of short buffers.
                *slot = Some(frame);
            }
        }
        alive
    }
}

/// Per-server shared TCP connections. A future consults this before opening a
/// TCP socket so parallel lookups to one server share a connection.
#[derive(Default)]
pub(crate) struct TcpPool(HashMap<usize, Rc<RefCell<TcpConn>>>);

impl TcpPool {
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
    /// Drop a dead connection so the next query to that server reconnects.
    fn remove(&mut self, server: usize) {
        self.0.remove(&server);
    }
    /// Reuse the live connection to `server`, else open + connect one.
    fn get_or_create(
        &mut self,
        server: usize,
        factory: &Rc<dyn SocketFactory>,
        ep: &ServerEndpoint,
    ) -> Result<Rc<RefCell<TcpConn>>, ()> {
        if let Some(c) = self.0.get(&server) {
            return Ok(c.clone());
        }
        let sock = factory.create_tcp(ep.bind).map_err(|_| ())?;
        let _ = sock.connect(ep.tcp_addr); // optimistic (EINPROGRESS → Ok)
        let fd = sock.as_raw_fd();
        let conn = Rc::new(RefCell::new(TcpConn { sock, fd, rbuf: Vec::new(), inbox: HashMap::new() }));
        self.0.insert(server, conn.clone());
        Ok(conn)
    }
}

/// The primary query's connection: an owned UDP socket, or a shared TCP conn.
enum Primary {
    Udp(OwnedSock),
    Tcp(Rc<RefCell<TcpConn>>),
}

impl Primary {
    fn fd(&self) -> i32 {
        match self {
            Primary::Udp(s) => s.fd(),
            Primary::Tcp(c) => c.borrow().fd,
        }
    }
}

fn qid_of(payload: &[u8]) -> u16 {
    if payload.len() >= 2 {
        u16::from_be_bytes([payload[0], payload[1]])
    } else {
        0
    }
}

/// Create + connect the primary socket for `server`, retrying across servers on
/// creation failure (folds in the old `launch_pooled` create-retry loop and its
/// `record_failure`+`pick_next` accounting). Returns the connection and the
/// server it settled on, or `Err` if every attempt failed.
fn acquire_primary(res: &Resources, start: usize, use_tcp: bool) -> Result<(Primary, usize), ()> {
    let mut si = start;
    let attempts = res.opts.attempts.max(1);
    for _ in 0..attempts {
        let Some(ep) = res.endpoints.get(si) else {
            return Err(()); // stale server index (servers shrank mid-flight)
        };
        let made = if use_tcp {
            res.tcp_pool.borrow_mut().get_or_create(si, &res.factory, ep).map(Primary::Tcp)
        } else {
            res.factory
                .create_udp(ep.bind)
                .map_err(|_| ())
                .map(|sock| Primary::Udp(OwnedSock { sock, is_tcp: false, rbuf: Vec::new() }))
        };
        match made {
            Ok(p) => return Ok((p, si)),
            Err(()) => {
                // Retry the full `attempts` budget even with one server (each try
                // re-creates the socket, so a create/consent callback keeps
                // firing — SockFailCallback asserts sock_cb_count > 1); move to
                // the next server only when there is more than one.
                if res.health.borrow().len() > 1 {
                    res.health.borrow_mut().record_failure(si);
                    si = res.health.borrow().pick_next();
                }
            }
        }
    }
    Err(())
}

/// Send `framed` on the primary. Awaits **writability first** (so a freshly
/// created query reports write-interest to `ares_getsock`/`select` until the
/// caller drives it, matching the classic `Writing`→`Reading` flow and a
/// pending TCP connect). UDP connects before sending. Returns `false` on a hard
/// failure or timeout.
async fn send_primary(
    io: &Rc<RefCell<QueryIo>>,
    primary: &Primary,
    ep: &ServerEndpoint,
    framed: &[u8],
    deadline: Instant,
) -> bool {
    if let Primary::Udp(s) = primary {
        let _ = s.sock.connect(ep.udp_addr);
    }
    let fd = primary.fd();
    loop {
        let woke = wait_io(io, &[Wait { fd, writable: true }], deadline).await;
        if woke.expired && !woke.fds.contains(&fd) {
            return false; // timed out before writable
        }
        let sent = match primary {
            Primary::Udp(s) => s.sock.send(framed),
            Primary::Tcp(c) => c.borrow().sock.send(framed),
        };
        match sent {
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {} // re-await writable
            Err(_) => return false,
        }
    }
}

/// Receive one complete reply from the primary (UDP datagram, or a routed TCP
/// frame for `qid`), or report the socket dead / not-ready-yet.
fn recv_primary(primary: &mut Primary, qid: u16) -> Recv {
    match primary {
        Primary::Udp(s) => s.recv_msg(),
        Primary::Tcp(c) => {
            let mut conn = c.borrow_mut();
            let alive = conn.recv_and_route();
            match conn.inbox.get_mut(&qid).and_then(|slot| slot.take()) {
                Some(msg) => Recv::Msg(msg),
                None if !alive => Recv::Dead,
                None => Recv::Pending,
            }
        }
    }
}

/// A one-shot failover probe running alongside the primary query.
struct Probe {
    sock: OwnedSock,
    server: usize,
    deadline: Instant,
    payload: BytesMut, // framed form actually sent (for qid_matches)
}

/// Start a probe if enabled and a stale server is due one. Best-effort: any
/// socket/create failure yields `None`.
fn start_probe(res: &Resources, name_payload: &BytesMut, use_tcp: bool) -> Option<Probe> {
    if res.opts.failover_chance == 0 {
        return None;
    }
    let primary_server = res.health.borrow().pick_next();
    let pserver = res.health.borrow().pick_probe(res.opts.failover_delay, primary_server)?;
    let ep = res.endpoints.get(pserver)?;
    let sock = if use_tcp {
        let s = res.factory.create_tcp(ep.bind).ok()?;
        let _ = s.connect(ep.tcp_addr);
        OwnedSock { sock: s, is_tcp: true, rbuf: Vec::new() }
    } else {
        let s = res.factory.create_udp(ep.bind).ok()?;
        let _ = s.connect(ep.udp_addr);
        OwnedSock { sock: s, is_tcp: false, rbuf: Vec::new() }
    };
    let framed = if use_tcp { frame_tcp(name_payload) } else { name_payload.clone() };
    let _ = sock.sock.send(&framed);
    Some(Probe {
        sock,
        server: pserver,
        deadline: Instant::now() + res.opts.timeout,
        payload: framed,
    })
}

/// Fold a probe reply into server health (the old `on_probe_reply` verdict),
/// emitted as effects. `None` reply = the probe timed out (failure timestamp only).
fn settle_probe(io: &Rc<RefCell<QueryIo>>, res: &Resources, probe: &Probe, reply: Option<&[u8]>) {
    let mut health = res.health.borrow_mut();
    match reply {
        Some(buf) => {
            let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0xff };
            if rcode == 0 || rcode == 3 {
                if health.record_success(probe.server) {
                    drop(health);
                    push_effect(io, Effect::NotifyServerState { server: probe.server, ok: true, tcp: probe.sock.is_tcp });
                }
            } else if health.record_failure(probe.server) {
                drop(health);
                push_effect(io, Effect::NotifyServerState { server: probe.server, ok: false, tcp: probe.sock.is_tcp });
            }
        }
        None => health.record_failure_time(probe.server),
    }
}

// ===== resolve_query — one query name's full lifecycle =====

/// Drive one query payload to a settled reply (or a terminal error), owning the
/// socket(s): create / connect / send / recv / QID-match, with TC-retry, server
/// failover, and timeout-retry via the reused `on_datagram`/`on_timeout` truth
/// tables, plus the concurrent probe. Returns `(reply-or-status, timeout-count)`.
pub(crate) async fn resolve_query(
    io: Rc<RefCell<QueryIo>>,
    res: Resources,
    payload: BytesMut,
    mut use_tcp: bool,
    probe_payload: Option<BytesMut>,
) -> (Result<Vec<u8>, c_int>, c_int) {
    let mut timeouts: c_int = 0;
    let mut tries: u32 = 0; // timeout attempts used
    let mut failover_tries: u32 = 0;
    let qid = qid_of(&payload);
    let mut server = res.health.borrow().pick_next();
    let mut probe = probe_payload.and_then(|pp| start_probe(&res, &pp, use_tcp));

    'attempt: loop {
        let (mut primary, si) = match acquire_primary(&res, server, use_tcp) {
            Ok(v) => v,
            Err(()) => {
                return (Err(ARES_ECONNREFUSED), timeouts);
            }
        };
        server = si;
        let ep = res.endpoints[server].clone();
        // The wire buffer for this attempt's transport: TCP needs the framed
        // copy, UDP sends the payload as-is (borrowed — no clone).
        let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
        let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
        let deadline = Instant::now() + res.opts.timeout;

        // Register this qid on the shared TCP conn before sending, so a sibling
        // future's read routes our reply into our slot.
        if let Primary::Tcp(c) = &primary {
            c.borrow_mut().inbox.insert(qid, None);
        }
        if !send_primary(&io, &primary, &ep, wire, deadline).await {
            // Send failed (a hard socket error): recreate the socket and retry,
            // bounded by the attempt budget — mirrors the classic write_impl's
            // recreate-and-resend. (SetReplyAndFailSend fails one send, then the
            // retry succeeds.)
            clear_tcp_slot(&primary, qid);
            if use_tcp {
                res.tcp_pool.borrow_mut().remove(server);
            }
            if tries + 1 < res.opts.attempts.max(1) {
                tries += 1;
                if res.health.borrow().len() > 1 {
                    res.health.borrow_mut().record_failure(server);
                    server = res.health.borrow().pick_next();
                }
                continue 'attempt;
            }
            return (Err(ARES_ECONNREFUSED), timeouts);
        }

        // Await the primary reply, servicing the probe socket concurrently.
        loop {
            let primary_wait = Wait { fd: primary.fd(), writable: false };
            let wake_deadline = match &probe {
                Some(p) => deadline.min(p.deadline),
                None => deadline,
            };
            // Stack slice (1 or 2 waits) — no per-await heap allocation.
            let woke = match &probe {
                Some(p) => {
                    wait_io(&io, &[primary_wait, Wait { fd: p.sock.fd(), writable: false }], wake_deadline).await
                }
                None => wait_io(&io, &[primary_wait], wake_deadline).await,
            };

            // Probe readiness.
            let probe_ready = probe.as_ref().is_some_and(|p| woke.fds.contains(&p.sock.fd()));
            if probe_ready {
                match probe.as_mut().unwrap().sock.recv_msg() {
                    Recv::Msg(buf) => {
                        let p = probe.as_ref().unwrap();
                        if qid_matches(&buf, &p.payload, p.sock.is_tcp) {
                            let p_taken = probe.take().unwrap();
                            settle_probe(&io, &res, &p_taken, Some(&buf));
                        }
                    }
                    Recv::Dead => probe = None, // probe socket died — best-effort, drop it
                    Recv::Pending => {}
                }
            }

            if woke.expired {
                let now = Instant::now();
                if let Some(p) = &probe {
                    if now >= p.deadline {
                        let p_taken = probe.take().unwrap();
                        settle_probe(&io, &res, &p_taken, None);
                    }
                }
                if now >= deadline {
                    clear_tcp_slot(&primary, qid);
                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                    let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                    match verdict {
                        TimeoutVerdict::Retry { server: next } => {
                            tries += 1;
                            timeouts += 1;
                            server = next;
                            continue 'attempt;
                        }
                        TimeoutVerdict::Expire => return (Err(ARES_ETIMEOUT), timeouts),
                    }
                }
                continue; // probe-only expiry: keep awaiting the primary
            }

            if !woke.fds.contains(&primary.fd()) {
                continue; // only the probe fired
            }
            let buf = match recv_primary(&mut primary, qid) {
                Recv::Msg(buf) => buf,
                Recv::Pending => continue, // WouldBlock / incomplete frame — keep waiting
                Recv::Dead => {
                    // Connection died (TCP disconnect / hard recv error): drop a
                    // dead shared TCP conn and retry like a timeout.
                    clear_tcp_slot(&primary, qid);
                    if use_tcp {
                        res.tcp_pool.borrow_mut().remove(server);
                    }
                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                    let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                    match verdict {
                        TimeoutVerdict::Retry { server: next } => {
                            tries += 1;
                            timeouts += 1;
                            server = next;
                            continue 'attempt;
                        }
                        TimeoutVerdict::Expire => return (Err(ARES_ETIMEOUT), timeouts),
                    }
                }
            };
            if !qid_matches(&buf, wire, use_tcp) {
                continue; // stray datagram
            }

            let summary = summarize(&buf, 0);
            let (actions, verdict) = on_datagram(
                &summary,
                TaskKind::Other,
                server,
                use_tcp,
                res.opts.attempts,
                failover_tries,
                &mut res.health.borrow_mut(),
            );
            notify(&io, actions);
            match verdict {
                TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                    clear_tcp_slot(&primary, qid);
                    server = next;
                    failover_tries = ft;
                    continue 'attempt;
                }
                TaskVerdict::RetryTcp => {
                    use_tcp = true;
                    continue 'attempt;
                }
                TaskVerdict::Deliver => {
                    clear_tcp_slot(&primary, qid);
                    return (Ok(buf), timeouts);
                }
            }
        }
    }
}

/// Drop this future's slot on a shared TCP conn (on retry/deliver) so the
/// connection's inbox doesn't accumulate stale entries.
fn clear_tcp_slot(primary: &Primary, qid: u16) {
    if let Primary::Tcp(c) = primary {
        c.borrow_mut().inbox.remove(&qid);
    }
}

// ===== Lifecycles =====

/// ares_query / ares_send: one query, delivered raw. Keeps the historical
/// UDP-start behavior (server chosen by `pick_next`).
pub(crate) async fn raw_lifecycle(io: Rc<RefCell<QueryIo>>, launch: RawLaunch) -> Delivery {
    let (result, timeouts) = resolve_query(io, launch.res, launch.payload, false, None).await;
    Delivery::Raw { result, timeouts }
}

// ===== Waker =====

/// Readiness is executor-driven, so waking need do nothing.
struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

thread_local! {
    static NOOP_WAKER: Waker = Waker::from(Arc::new(NoopWake));
}

/// A no-op `Waker` (safe: `std::task::Wake`, no `RawWaker`), cheaply cloned from
/// a cached instance.
pub(crate) fn noop_waker() -> Waker {
    NOOP_WAKER.with(|w| w.clone())
}
