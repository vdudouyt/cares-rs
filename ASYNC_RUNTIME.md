# The external-loop async runtime

`cares-rs` ships a small, protocol-agnostic async runtime under
`src/async_runtime/`, public as `cares::async_runtime`. It is the same machinery
the DNS resolver uses, but nothing in the module knows what DNS is: it provides
non-blocking sockets, readiness and timer futures, and a single-threaded task
executor. The application owns the event loop, just as a c-ares application owns
the loop around `ares_fds()` / `ares_timeout()` / `ares_process()`.

The runtime has **no hidden thread, no global reactor, no `block_on`, and no
signal handling**. All of its state lives in a per-application `Runtime`
handle, so several independent clients (or one per c-ares channel) can coexist
in the same process.

```
application loop                         runtime
----------------                         -------
Reactor::interests()                -->  which (fd, writable) pairs are awaited
Reactor::next_deadline()            -->  earliest timer
poll(2) / epoll_wait(2) / ...
Reactor::dispatch(now, ready)       -->  wake the matching Ready/Timer futures
Executor::pop_ready() / poll(id)    -->  run the woken tasks
```

## Mapping to the C API

| c-ares C API | Rust runtime |
|---|---|
| `ares_fds(channel, &rfds, &wfds)` | `Reactor::interests() -> Vec<(i32, bool)>` (`bool` = writable) |
| `ares_timeout(channel, NULL, &tv)` | `Reactor::next_deadline() -> Option<Instant>` |
| `select()` / `poll()` | the application's own wait |
| `ares_process(channel, &rfds, &wfds)` | `Reactor::dispatch(now, false, ready_fn)` |
| — (callbacks run inside `ares_process`) | `Executor::pop_ready()` + `Executor::poll(id)` |

The big difference is that `dispatch` does not guess from an `fd_set`: it takes
a closure `Fn(i32, bool) -> bool` (`fd`, `writable`) that reports whether the
application saw that direction ready. This also avoids `fd_set`'s
`FD_SETSIZE` ceiling on high-numbered custom-socket descriptors. If your backend
already returns an explicit list (`epoll_wait`, `kqueue`, `io_uring`), call
`Reactor::dispatch_events(now, skip_timeouts, [(fd, readable, writable)])`
instead; it finds sources through the reactor's fd index and costs O(ready fds)
rather than O(all sources). A persistent backend (like the built-in event
thread) can call `Reactor::enable_change_tracking()` once and then apply
`take_interest_changes()` deltas instead of re-scanning `interests()`.

## Layers

| File | Contents |
|---|---|
| `socket.rs` | `Socket` (one non-blocking fd: `connect`, `recv`, `send`, `as_raw_fd`, `drain_safe`) and `SocketFactory` (`create_udp`, `create_tcp`). |
| `reactor.rs` | `Reactor` (fd `Source`s, per-direction wakers, timers, receive scratch), `Ready` (readable/writable future), `Timer`, `Runtime` (reactor + detached-task queue + built-in system sockets), `InterestChanges` (for persistent event backends). |
| `io.rs` | `Async` (a `Socket` registered with a reactor), `readable()`, `writable()`, `read()`, `read_exact()`, `write()`, `write_all()`, `dead`. |
| `executor.rs` | `Executor` (`spawn`, `pop_ready`, `poll`, `deliver`, `has_ready`), one real `Waker` per task. |
| `system.rs` | The built-in system sockets behind `Runtime::create_tcp` / `create_udp`: std `UdpSocket::bind`, and std `TcpStream` over a `rustix`-created/bound fd. |

The whole module is `#![forbid(unsafe_code)]`. Unsafe code, if any, belongs in
the `Socket` implementation that talks to the OS or to a foreign network stack.

## A minimal loop

```rust
use std::time::Instant;
use cares::async_runtime::{Executor, Runtime};

fn drive(runtime: &Runtime, executor: &Executor) {
    loop {
        // 1. Interests and deadline, as ares_fds()/ares_timeout() would report.
        let interests = runtime.reactor().interests();
        let timeout_ms = if executor.has_ready() {
            0
        } else {
            match runtime.reactor().next_deadline() {
                Some(deadline) => deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(i32::MAX as u128) as i32,
                None => -1,
            }
        };

        // 2. Wait (poll/epoll/select/io_uring: the application's choice).
        let ready = wait_for_ready(&interests, timeout_ms);

        // 3. ares_process() equivalent: publish readiness, run woken tasks.
        runtime.reactor().dispatch(Instant::now(), false, |fd, writable| {
            ready.contains(&(fd, writable))
        });
        while let Some(id) = executor.pop_ready() {
            if executor.poll(id) {
                executor.deliver(id, None);
            }
        }

        // 4. Adopt tasks detached via Runtime::spawn.
        for fut in runtime.take_spawned() {
            let id = executor.spawn(fut, |_| {});
            if executor.poll(id) {
                executor.deliver(id, None);
            }
        }
    }
}
```

`wait_for_ready` is application code; see `examples/tcp_hello.rs` for a
complete `poll(2)` version, including the fd-deduplication and error/hangup
handling.

## Tasks

`Executor::spawn(fut, on)` registers a future but does **not** poll it. The host
kicks it once:

```rust
let id = executor.spawn(async { /* ... */ }, |result| {
    // Ok(value) on completion, Err(status) after cancel (the i32 is a c-ares
    // status such as ARES_EDESTRUCTION; application code can use any value).
});
if executor.poll(id) {
    executor.deliver(id, None);
}
```

After that, the task is woken by its `Waker` and becomes runnable via
`pop_ready()`. `poll(id)` returns `true` when the future completed; the host
must then call `deliver(id, None)` to run the delivery closure and reuse the
slot. `deliver(id, Some(status))` cancels a task and delivers `Err(status)`.
`has_ready()` tells the loop not to sleep before polling again. `ids()` and
`active_count()` are for bookkeeping; `deliver` on an already-reaped id is a
no-op.

`Runtime::spawn(fut)` is the detached-task equivalent (`tokio::spawn` with no
handle): it queues the future because the executor may be mid-poll. The host
moves it into the executor with `take_spawned()` and polls it as above.

The executor is `!Send`: tasks run only on the thread that owns the `Runtime`.
Nothing prevents a task from spawning another task; the loop adopts it on the
next pass. Cancelling a task while it is on the stack (e.g. from a callback it
invoked) is deferred until its poll returns.

## Sockets

`Socket` is the only OS boundary. It is deliberately small:

```rust
pub trait Socket {
    fn as_raw_fd(&self) -> i32;
    fn connect(&self, addr: SocketAddr) -> io::Result<()>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn send(&self, data: &[u8]) -> io::Result<usize>;
    fn drain_safe(&self) -> bool { true }
}
```

Contract:

- The fd is non-blocking. `connect` may return `EINPROGRESS`; report that as
  `Ok(())` and let the first writable event complete the connection.
- `recv` returns the number of bytes read. For a stream, `Ok(0)` is orderly
  EOF; for a datagram, `Ok(0)` is a valid zero-length datagram. `WouldBlock`
  is `Err` with `ErrorKind::WouldBlock`; the runtime only calls it after the
  host reported readability, so it normally does not happen.
- `send` returns the byte count or a `WouldBlock` error. Use
  `Async::write` for one attempt (returns the accepted byte count), or
  `Async::write_all` for a stream when every byte must be sent. A datagram
  socket uses one `write`; a short datagram is an error, not a continuation.
- `drain_safe()` should be `false` for caller-supplied sockets that may block,
  so a drain loop does not re-read them. Non-blocking descriptors return the
  default `true`.

`Runtime::create_tcp(bind)` / `create_udp(bind)` use the built-in system socket
implementation (stdlib/rustix) and need no factory. Applications that need
custom sockets pass their own factory per socket:

```rust
let sock = runtime.create_custom_socket(SocketKind::Tcp, bind, factory)?;
```

`SocketFactory::create_tcp` / `create_udp` receive the **local bind address**
(the resolver's local-IP/socket settings), not the peer. The runtime connects
separately through `Socket::connect`.

`Async` wraps a `Socket` and registers its fd with a reactor. Dropping it
deregisters the source before the socket closes, so a recycled fd number can
never inherit the old interest. `Async::read` is the readiness-gated one-shot
read returning the accepted byte count, and `Async::read_exact` is its
stream-only all-bytes variant. The DNS pools use internal `read_stream` /
`read_datagram` helpers that lend the reactor's 64 KB scratch buffer for one
non-blocking receive after readiness; they are not part of the public client
API.

## Readiness rules

These rules keep caller-supplied sockets safe (they may block or return
zero-length datagrams):

1. **Never perform I/O before the host reported readiness.** `Ready` only
   completes when a *newer* `dispatch` reported that direction.
2. **Readiness lasts one turn.** A report not consumed in that turn is not
   readiness later. The runtime's same-turn peek is used
   when a timeout expires alongside a report.
3. **Read and write are independent.** A writable event never wakes a read
   waiter, and vice versa.

## Timers

`Timer::at(&reactor, deadline)` resolves at a wall-clock `Instant` and is
registered on first `Pending`. It is deregistered on completion or drop. The
host must include `next_deadline()` in its wait, and normally passes `false` as
`skip_timeouts` to `dispatch`. A host that is running its own non-fd timers can
pass `true` to leave due timers for a later turn (c-ares does this for
`ARES_PROCESS_FLAG_SKIP_NON_FD`). A timer whose poll happens for another reason
still observes its expiry, because it reads the clock on every poll.

## Composing futures

Wakers are real (`Arc<impl Wake>` per task), so any `std` future combinator
works. The DNS engine still uses `futures_util::select_biased!` where arm order
is a correctness concern (timeout-first receive, probe-before-primary race).
For a straightforward client, `select_biased!` with a `Timer` is a convenient
timeout:

```rust
let mut op = pin!(some_future.fuse());
let mut timeout = pin!(Timer::at(rt.reactor(), deadline).fuse());
select_biased! {
    result = op      => { /* completed */ }
    _       = timeout => { /* timed out */ }
}
```

`Ready` and `Timer` are `!Unpin` on purpose (their state is in `Cell`s and they
are polled through shared references by `select_biased!`); pin them with
`std::pin::pin!`.

## The TCP example

`examples/tcp_hello.rs` implements a complete client:

1. `StreamFactory` creates a non-blocking `TcpStream` from a `rustix` socket
   and implements `Socket` for it.
2. `Runtime::create_tcp(local)` creates and registers the socket.
3. The task connects, waits for writability (non-blocking connect completes),
   sends `"<name>\n"`, and reads until `'\n'`.
4. `drive()` builds the `poll(2)` set from `Reactor::interests()`, uses
   `Reactor::next_deadline()` as the timeout, calls `Reactor::dispatch`, then
   polls the executor.

Run both halves:

```console
$ cargo run --example tcp_hello -- server 127.0.0.1:7878
listening on 127.0.0.1:7878
$ cargo run --example tcp_hello -- client 127.0.0.1:7878 Alice
Hello, Alice!
```

The server half uses blocking `std::net` on purpose; only the client
demonstrates the runtime. Replace `StreamFactory` with one backed by a custom
network stack, a TLS library, or the c-ares socket-function table and the same
loop works unchanged.

## What this runtime is not

- It is not a DNS-only API and does not expose DNS types. Use `Conn`/the
  resolver for that; use this runtime for arbitrary byte protocols.
- It does not frame messages, multiplex streams, or pool connections. Those
  are application concerns (the DNS side implements them in `core/conn.rs`,
  `tcp_pool.rs`, and `udp_pool.rs`).
- It does not run tasks on other threads and has no work stealing. One
  reactor/executor pair belongs to one thread and one loop.
- It does not call `poll` itself. That is the point: the application may use
  `poll`, `epoll`, `kqueue`, `select`, `io_uring`, a GUI toolkit, or a foreign
  event loop, and simply translate readiness into `dispatch`.
