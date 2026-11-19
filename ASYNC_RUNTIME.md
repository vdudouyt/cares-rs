# The external-loop async runtime

`cares-rs` ships a small, protocol-agnostic async runtime under
`src/async_runtime/`, public as `cares::async_runtime`. It is the same machinery
the DNS resolver uses, but nothing in the module knows what DNS is: it provides
non-blocking sockets, readiness and timer futures, and a single-threaded task
executor. The application owns the event loop, just as a c-ares application owns
the loop around `ares_fds()` / `ares_timeout()` / `ares_process()`.

The runtime has **no hidden thread, no global reactor, no `block_on`, and no
signal handling**. All of its state lives in a per-application `Runtime`
owner, so several independent clients (or one per c-ares channel) can coexist
in the same process.

```
application loop                         runtime
----------------                         -------
Runtime::interests()                -->  which (fd, writable) pairs are awaited
Runtime::timeout(now)               -->  runnable work or the next timer
poll(2) / epoll_wait(2) / ...
Runtime::process(now, ready)        -->  wake, poll tasks, deliver completions
```

## Mapping to the C API

| c-ares C API | Rust runtime |
|---|---|
| `ares_fds(channel, &rfds, &wfds)` | `Runtime::interests() -> Vec<(i32, bool)>` (`bool` = writable) |
| `ares_timeout(channel, NULL, &tv)` | `Runtime::timeout(now) -> Option<Duration>` |
| `select()` / `poll()` | the application's own wait |
| `ares_process(channel, &rfds, &wfds)` | `Runtime::process(now, ready_fn)` |
| `ares_cancel(channel)` | `Runtime::cancel_all(|| status)` |
| `ares_destroy(channel)` | `Runtime::shutdown(|| status)` |

`process` does not guess from an `fd_set`: it takes
a closure `Fn(i32, bool) -> bool` (`fd`, `writable`) that reports whether the
application saw that direction ready. This also avoids `fd_set`'s
`FD_SETSIZE` ceiling on high-numbered custom-socket descriptors. If your backend
already returns an explicit list (`epoll_wait`, `kqueue`, `io_uring`), call
`Runtime::process_events(now, [(fd, readable, writable)])`
instead; it finds sources through the reactor's fd index and costs O(ready fds)
rather than O(all sources). A persistent backend (like the built-in event
thread) can call `Runtime::enable_change_tracking()` once and then apply
`take_interest_changes()` deltas instead of re-scanning `interests()`.

## Layers

| File | Contents |
|---|---|
| `socket.rs` | `Socket` (one non-blocking fd: `connect`, `recv`, `send`, `as_raw_fd`, `drain_safe`) and `SocketFactory` (`create_udp`, `create_tcp`). |
| `runtime.rs` | Public `Runtime<E>`: owns the executor and reactor, schedules tasks, drives turns, delivers results, and manages cancellation. Non-owning handles use the same API. |
| `reactor.rs` | Private reactor (fd sources, per-direction wakers, timers, receive scratch), public `Ready`, `Timer`, and `InterestChanges`. |
| `io.rs` | `AsyncSocket` (a `Socket` registered with a reactor), `readable()`, `writable()`, `read()`, `read_exact()`, `write()`, `write_all()`, `dead`. |
| `executor.rs` | Private task registry and runnable queue, with one real `Waker` per task. |
| `system.rs` | The built-in system sockets behind `Runtime::create_tcp` / `create_udp`: std `UdpSocket::bind`, and std `TcpStream` over a `rustix`-created/bound fd. |

The whole module is `#![forbid(unsafe_code)]`. Unsafe code, if any, belongs in
the `Socket` implementation that talks to the OS or to a foreign network stack.

## A minimal loop

```rust
use std::time::Instant;
use cares::async_runtime::Runtime;

fn drive(runtime: &Runtime) {
    runtime.run_ready(); // Start tasks before the first wait.
    loop {
        let interests = runtime.interests();
        let timeout_ms = runtime.timeout(Instant::now())
            .map_or(-1, |delay| delay.as_millis().min(i32::MAX as u128) as i32);

        // 2. Wait (poll/epoll/select/io_uring: the application's choice).
        let ready = wait_for_ready(&interests, timeout_ms);

        // 3. ares_process() equivalent: publish readiness, run woken tasks.
        runtime.process(Instant::now(), |fd, writable| {
            ready.contains(&(fd, writable))
        });
    }
}
```

`wait_for_ready` is application code; see `examples/tcp_hello.rs` for a
complete `poll(2)` version, including the fd-deduplication and error/hangup
handling.

## Tasks

`Runtime<E>` is generic over the cancellation type; `E` is not tied to c-ares.
`Runtime::new()` creates `Runtime<()>`; c-ares uses `Runtime<c_int>::default()`.
There is one `spawn(future, callback)` API. It registers and schedules the task
without polling it inline:

```rust
runtime.spawn(async { /* ... */ }, |result| {
    // Ok(value) on completion, Err(status) after cancel (the i32 is a c-ares
    // status such as ARES_EDESTRUCTION; application code can use any value).
})?;
runtime.run_ready();
```

Use `|_| {}` for detached tasks. All tasks share one runnable queue; tasks
spawned while polling need no adoption or executor notification. The runtime
delivers completed results and reaps slots internally. Each turn has a polling
budget (`4 * active_tasks + 16`) to bound self-waking tasks; leftover work makes
`timeout(now)` return zero, even without fd interest. Reentrant driving leaves
polling to the outer turn.

`cancel_all(|| status)` cancels a snapshot of live tasks and keeps the runtime
usable. Tasks spawned by cancellation callbacks are new work; generation checks
keep a reused slot out of the old cancellation batch. `shutdown(|| status)`
first closes the runtime to new tasks, then cancels pending work. Spawning after
shutdown returns `RuntimeClosed` without invoking the rejected task's callback.
Cancellation during a task poll is delivered when that poll returns.

`Runtime::handle()` returns the same unified type with a non-owning task
reference. Use handles inside tasks and resolver lookup copies; the weak
references and upgrades are entirely internal to `async_runtime`. Dropping a
handle does not stop the owner. Dropping the owner releases its tasks, including
tasks that capture handles; call `shutdown` first to deliver cancellations.
Socket and timer futures own their I/O registrations separately.

The runtime is `!Send` and owns no loop or threads. The C channel owns its runtime
outside the mutable resolver state, so driving never holds that state borrowed
across callbacks. C query entry points start work internally, preserving the
existing `ares_fds` / `ares_timeout` / `ares_process` loop.

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
  `AsyncSocket::write` for one attempt (returns the accepted byte count), or
  `AsyncSocket::write_all` for a stream when every byte must be sent. A datagram
  socket uses one `write`; a short datagram is an error, not a continuation.
- `drain_safe()` should be `false` for caller-supplied sockets that may block,
  so a drain loop does not re-read them. Non-blocking descriptors return the
  default `true`.

`Runtime::create_tcp(bind)` / `create_udp(bind)` use the built-in system socket
implementation (stdlib/rustix) and need no factory.
`Runtime::connect_tcp(remote, deadline)` is the async TCP convenience: it
creates a socket with a kernel-chosen local address, starts a non-blocking
connect, waits for writability or the deadline, and returns the pending
`SO_ERROR` if the connection failed. Applications that need custom sockets pass
their own factory per socket:

```rust
let sock = runtime.create_custom_socket(SocketKind::Tcp, bind, factory)?;
```

`SocketFactory::create_tcp` / `create_udp` receive the **local bind address**
(the resolver's local-IP/socket settings), not the peer. The runtime connects
separately through `Socket::connect`.

`AsyncSocket` wraps a `Socket` and registers its fd with a reactor. Dropping it
deregisters the source before the socket closes, so a recycled fd number can
never inherit the old interest. `AsyncSocket::read` is the readiness-gated one-shot
read returning the accepted byte count, and `AsyncSocket::read_exact` is its
stream-only all-bytes variant. The DNS pools use internal `read_stream` /
`read_datagram` helpers that lend the reactor's 64 KB scratch buffer for one
non-blocking receive after readiness; they are not part of the public client
API.

## Readiness rules

These rules keep caller-supplied sockets safe (they may block or return
zero-length datagrams):

1. **Never perform I/O before the host reported readiness.** `Ready` only
   completes when a *newer* processing turn reported that direction.
2. **Readiness lasts one turn.** A report not consumed in that turn is not
   readiness later. The runtime's same-turn peek is used
   when a timeout expires alongside a report.
3. **Read and write are independent.** A writable event never wakes a read
   waiter, and vice versa.

## Timers

`runtime.timer_at(deadline)` resolves at a wall-clock `Instant` and is
registered on first `Pending`. It is deregistered on completion or drop. The
host uses `timeout(now)` for its wait and calls `process(now, ready)` each turn.
Passing `None` instead of `now` leaves due timers unwoken (c-ares does this for
`ARES_PROCESS_FLAG_SKIP_NON_FD`); `process_events` accepts the same choice.
A timer whose poll happens for another reason
still observes its expiry, because it reads the clock on every poll.

## Composing futures

Wakers are real (`Arc<impl Wake>` per task), so any `std` future combinator
works. The DNS engine still uses `futures_util::select_biased!` where arm order
is a correctness concern (timeout-first receive, probe-before-primary race).
For a straightforward client, `select_biased!` with a `Timer` is a convenient
timeout:

```rust
let mut op = pin!(some_future.fuse());
let mut timeout = pin!(rt.timer_at(deadline).fuse());
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

1. `Runtime::connect_tcp(server, deadline)` creates the default system socket,
   starts the non-blocking connect, and waits for completion.
2. The task sends `"<name>\n"` and reads until `'\n'`.
3. `drive()` builds the `poll(2)` set from `Runtime::interests()`, uses
   `Runtime::timeout()` for the wait, and calls `Runtime::process()` to drive tasks.

Run both halves:

```console
$ cargo run --example tcp_hello -- server 127.0.0.1:7878
listening on 127.0.0.1:7878
$ cargo run --example tcp_hello -- client 127.0.0.1:7878 Alice
Hello, Alice!
```

The server half uses blocking `std::net` on purpose; only the client
demonstrates the runtime. Use `Runtime::create_custom_socket` with a factory
backed by a custom network stack, a TLS library, or the c-ares socket-function
table and the same loop works unchanged.

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
  event loop, and simply translate readiness into `process` or `process_events`.
