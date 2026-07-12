# Async socket API (`src/async_runtime/`, used by core/async_client.rs)

Layering: `async_runtime/executor.rs` (pure-IO reactor) → `async_runtime/conn.rs`
(async sockets: frames + mux tags, zero DNS) → `core/async_client.rs` (the DNS
resolver). The whole `src/async_runtime/` section is `#![forbid(unsafe_code)]`
and imports std + `futures-util` (the `select_biased!` macro and `FutureExt`
only) — no `crate::core`. The resolver ops
drive their sockets through `Conn<A>` — an async socket that owns its reactor
mailbox and, like the executor, is generic over the application state `A`.
Everything that does IO is `async`; the only sync points are socket
*construction* (allocating/connecting a fd never waits).

**Composition rule:** the reactor is waker-less (readiness is driven by
`ares_process`, not scheduled). Compose futures only with `select_biased!` or
plain `.await` — both re-poll every non-terminated arm each cycle. Waker-gated
combinators (`FuturesUnordered`, `for_each_concurrent`, …) poll once and wedge;
never use them here.

## Construction (sync — no IO wait)
```rust
trait SocketFactory {
    fn create_udp(&self, bind: SocketAddr) -> io::Result<Rc<dyn Socket>>;
    fn create_tcp(&self, bind: SocketAddr) -> io::Result<Rc<dyn Socket>>;
}
impl<A> Conn<A> {
    fn datagram(io, sock: Rc<dyn Socket>) -> Self;                    // UDP
    fn stream(io, sock: Rc<dyn Socket>, frame_of: FrameOf) -> Self;   // one-shot TCP (probe)
    fn shared(io, conn: Rc<RefCell<TcpConn>>, tag: u16) -> Self;      // pooled TCP checkout
}
impl TcpPool {                     // shared stream conns, keyed by an opaque index
    fn new(frame_of: FrameOf, tag_of: TagOf) -> Self;
    fn get_or_create(&mut self, key, factory, bind, to) -> Result<Rc<RefCell<TcpConn>>, ()>;
    fn remove(&mut self, key: usize);                            // drop a dead conn
}
type FrameOf = fn(&mut Vec<u8>) -> Option<Vec<u8>>; // pop one message off the stream buffer
type TagOf   = fn(&[u8]) -> Option<u16>;            // a frame's mux tag (demux key)
```
`Conn::shared` reserves `tag`'s inbox slot on the shared conn; **dropping the
`Conn` releases it** (RAII) — there is no manual register/clear.

## The async socket — `Conn<A>`
```rust
impl<A> Conn<A> {
    async fn send(&self, bytes: &[u8], timeout: Instant) -> io::Result<()>;
    async fn recv(&mut self, timeout: Instant) -> io::Result<Vec<u8>>;
    async fn recv_msg(&mut self) -> io::Result<Vec<u8>>;   // no timeout — as a select arm

    fn fd(&self) -> i32;
    fn is_tcp(&self) -> bool;
}
```
Standard `io::Result` error contract, tokio/std-style:
- `send`: `Ok(())` sent; the socket's own `io::Error` on a hard send failure;
  `ErrorKind::TimedOut` if not writable before `timeout`.
- `recv`: `Ok(bytes)` one message; `ErrorKind::TimedOut` on expiry;
  `ErrorKind::UnexpectedEof` ("connection closed") on a dead socket.
- `recv_msg`: the un-timed recv (`Ok(bytes)` / `UnexpectedEof`), so it can be a
  bare `select_biased!` arm. `recv` = `recv_msg` raced against `sleep_until`.

## Racing concurrent futures on one mailbox (probe / dual-family)
The mailbox is shared, so several whole-lifecycle futures can run on it at once —
`poll_recv` routes each reply by fd, so they self-demux. The DNS side uses this two
ways: a one-shot failover probe raced against the primary query, and getaddrinfo's
A+AAAA pair. Each peer does its own `recv`/`sleep_until` internally; the caller just
races the peers with `select_biased!`. `sleep_until` is the timeout as a bare arm:
```rust
fn sleep_until<A>(io, timeout: Instant) -> impl Future<Output = ()>;  // the timeout, as an arm
```

## Usage

### Send, then receive
```rust
let conn = Conn::datagram(io.clone(), sk);            // or Conn::shared(io.clone(), pooled, tag)
if conn.send(wire, timeout).await.is_err() {
    // send failed: recreate + retry, or give up with ECONNREFUSED
}
loop {
    match conn.recv(timeout).await {
        Ok(buf) => { /* app-level match? -> verdict */ }
        Err(e) if e.kind() == io::ErrorKind::TimedOut => { /* timeout verdict */ }
        Err(_) => { /* dead socket: drop conn (slot auto-released), retry */ }
    }
}
```

### Race peer futures (a probe alongside the primary)
```rust
// Each peer is self-contained: it does its own recv/timeout loop internally (the
// primary is one query lifecycle; the probe sends once, folds its reply into shared
// health, and terminates). Race the peers at the composition layer:
let mut primary = pin!(self.clone().request(payload, use_tcp).fuse());
let outcome = match probe_payload {
    Some(pp) => {
        let mut probe = pin!(self.clone().run_probe(pp, use_tcp).fuse());
        loop {
            select_biased! {           // biased: probe → primary
                _ = probe   => continue,   // probe settled; fused → skipped next poll
                r = primary => break r,    // primary delivered/failed → done
            }
        }
    }
    None => primary.await,
};
```
Inside such a future, race one socket's reply against its timeout (reply- or
timeout-biased as the caller needs):
```rust
let mut reply = pin!(conn.recv_msg().fuse());
let mut t     = pin!(sleep_until(&io, timeout).fuse());
select_biased! {            // reply-biased
    r = reply => { /* reply */ }
    _ = t     => { /* timeout */ }
}
```
(Pin with std's `pin!` — `futures::pin_mut!` expands to `unsafe`, forbidden here.)

---

*The byte-level recv/send are non-blocking syscalls done **inside** the conn
layer (the raw `Socket` trait mirrors the c-ares `ares_set_socket_functions` C
ABI); they never block and aren't part of this API. Stream message delimiting
and demux are the application's business: the DNS side supplies `dns_frame`
(RFC 1035 u16-BE length prefix) and `dns_tag` (tag = transaction ID), so
`conn.rs` itself names no protocol and parses no wire format.*
