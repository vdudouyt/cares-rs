# Plan: smol-shaped runtime with an external event loop (own executor)

Status: proposed, 2026-11-07. Branch: off `final-review`.

## Goal

Rebuild `async_runtime` in the shape of smol (`async-io` + `async-executor`),
keeping c-ares's caller-owned event loop. From core's point of view, the
runtime should read like smol code: sockets are `Async<_>` values with
`readable()`/`writable()`/`read_with()`, timeouts are `Timer`s, and lookups are
spawned on a `LocalExecutor`. Nothing per-task is passed around.

Today every lookup carries a `Rc<RefCell<Mailbox<DnsSignals>>>` (`AsyncClient.io`)
that does three unrelated jobs:

1. **Per-task reactor**: `waits`/`timeout`/`fired`, re-registered on every poll.
2. **Hand-rolled waker**: `routed`, set by `tcp_pool`/`udp_pool` when a sibling
   routes a reply, because the executor polls with `Waker::noop()`.
3. **Application side channel**: `app: DnsSignals` (`effects`, `timeouts`,
   `cancelled`, `qid`), plus the 64 KB receive `scratch`.

All three go away.

### Non-goals

- No smol (or tokio) dependency. `async-io` owns its event loop through a
  global reactor and the `polling` crate. Ours is driven by `ares_process*`,
  and I/O may go through the user's `ares_set_socket_functions` table.
- No DNS behavior changes. The 734-test gtest oracle must stay green after
  every step.
- No thread-locals or globals, no panics, and the unsafe ratchet must not grow.

## smol → cares-rs mapping

| smol (crate) | Here (`src/async_runtime/`) | Kept as-is | Deviation, and why |
|---|---|---|---|
| `async_io::Reactor` | `reactor.rs::Reactor` | `sources` slab, `timers: BTreeMap<(Instant, usize), Waker>`, `ticker`, per-direction tick bookkeeping | **D1.** One `Rc<Reactor>` per channel, not a global (CLAUDE.md: no global or thread-local state). **D2.** `react()` (blocks in `polling::Poller::wait`) is replaced by `dispatch(events, now, skip_timeouts)`, fed by `ares_process*`, which never blocks. Interest is reported out through `interests()`/`next_deadline()` instead of `poller.modify()`. |
| `async_io::Source` + `Direction { tick, ticks, waker, wakers }` | `reactor.rs::Source`, `Direction` | Same fields and the same tick algorithm. Many tasks can wait on one fd and direction (shared TCP/UDP conns); read and write are separate directions (C3). | none |
| `async_io::Ready` futures (`readable()`/`writable()`) | `reactor.rs::Ready` | Records `(reactor.ticker, dir.tick)` at registration and completes once `dir.tick` differs. **`Drop` removes its waker from the slab** (C4). | none |
| `async_io::Async<T>` | `io.rs::Async<Rc<dyn Socket>>` | `new` registers a `Source` and `Drop` removes it (C4). `readable()`, `writable()`, `read_with`, `write_with`. | **D3.** `read_with`/`write_with` **await readiness first**, then attempt the operation, re-awaiting on `WouldBlock`. smol attempts first. Caller-supplied sockets may be blocking and may return zero-length "datagrams" (C1). |
| `async_io::Timer` | `timer.rs::Timer` | `Timer::at(deadline)`. Registers `(deadline, id) → Waker` on first `Pending` and deregisters on `Drop` (C4). | D1: `Timer::at(&reactor, t)` takes the handle explicitly. |
| `async_executor::LocalExecutor` | `executor.rs::LocalExecutor` | `spawn`, `try_tick() -> bool`, a FIFO run queue, one waker per task that requeues it | **D4.** No `run().await`/`block_on`; the host calls `try_tick` in a loop once per turn. **D5.** `spawn(fut, on)` with a delivery closure and `cancel(id, status)`, not a `Task<T>` join handle. C callbacks need a status code on cancel (`ARES_EDESTRUCTION`, …), and nothing ever awaits a lookup. |
| `async_task::{Runnable, Task}` (raw vtable waker) | `executor.rs::TaskWaker` (`impl std::task::Wake`) | One waker per task. Waking queues the task once (`scheduled` flag ≈ async-task's `SCHEDULED` state bit). | **D6.** A safe `Arc<impl Wake>`, not async-task's raw `RawWaker` vtable, because `async_runtime` is `forbid(unsafe_code)`. A generation counter replaces async-task's refcounted header, so a stale waker can't poll a reused slot. |
| `smol::Executor` + `async_io::block_on` tick loop | `ChannelData::turn` (ffi) | dispatch → run woken tasks → idle | Driven by `ares_process*`, not by a thread. See "A turn" below. |
| `futures_lite::future::race`/`or` | keep `futures_util::select_biased!` | | The query engine depends on biased ordering: timeout-first recv, probe-first race. `race` picks at random. |

What's left of the old runtime that isn't smol-shaped is small, and each piece
exists because of the external loop:
- `dispatch` instead of `react`;
- `interests()`/`next_deadline()` instead of `poller.modify`;
- readiness-first `read_with`;
- the delivery-closure spawn.

## Constraints the design must preserve

| # | Constraint | Today | Under the smol shape |
|---|---|---|---|
| C1 | **Readiness-gated reads.** Never `recv` a fd the caller did not report readable. | `poll_recv` reads only when `fired` | D3: `read_with` awaits `readable()` first |
| C2 | **Readiness lasts one turn.** A report not consumed in its `ares_process*` call must not count as readiness later. | `fired` rewritten per drive | Tick algorithm: a `Ready` registered after the event never sees it. `Async::readable_this_turn()` (`dir.tick == reactor.ticker`) is the same-turn peek that `Conn::try_recv` needs. |
| C3 | Read and write readiness on one fd are separate. | `Wait { fd, writable }` | `Source.state[READ]`, `Source.state[WRITE]` |
| C4 | **`ares_fds`/`ares_getsock`/`ares_timeout` report exactly the live arms.** No interest from a dropped `select_biased!` loser or a closed socket. | waits cleared before each poll | `Drop` on `Ready`, `Timer` and `Async` (as in async-io) |
| C5 | `skip_timeouts` (`ARES_PROCESS_FLAG_SKIP_NON_FD`): timer expiry alone must not poll a task. | `drive_ready(.., skip_timeouts, ..)` | `dispatch` skips `process_timers` |
| C6 | Effects fire before completion: a task's `NotifyServerState` callbacks run before its completion callback. | `ChannelData::advance` | Drain the channel's effects queue after each task poll |
| C7 | **Re-entrancy.** Completion callbacks may re-enter `ares_*`, including `ares_process`. No `RefCell` borrow and no `Mutex` guard may be live when a C callback or a socket-table function runs. | CLAUDE.md | Wakers are collected under the reactor borrow and woken after it is released (as async-io's `react` does with its `wakers` Vec). The run-queue lock is released before `poll`. `scratch` is taken out and put back. |
| C8 | `ares_send` reports the final QID synchronously after the first poll. | `io.borrow().app.qid` | `Rc<Cell<u16>>` passed to `query_raw` |

## Target design

### `reactor.rs` (async-io's `reactor.rs`, minus `polling`)

```rust
pub(crate) struct Reactor {
    ticker: Cell<usize>,                                // bumped once per dispatch
    sources: RefCell<Slab<Rc<Source>>>,                 // key = Source::key
    timers: RefCell<BTreeMap<(Instant, usize), Waker>>, // + next timer id
    scratch: Cell<Vec<u8>>,                             // 64 KB recv buffer (C7)
}
pub(crate) struct Source { fd: i32, key: usize, state: RefCell<[Direction; 2]> }
struct Direction {
    tick: usize,                // ticker value of the last event (async-io)
    ticks: Option<(usize, usize)>,
    waker: Option<Waker>,       // the poll_readable/poll_writable slot
    wakers: Slab<Option<Waker>>,// Ready-future slots, removed on Drop
}
```

- **`dispatch(events, now, skip_timeouts)`**
  1. Bumps `ticker`.
  2. For each reported `(fd, dir)`, sets `dir.tick = ticker` and drains that
     direction's wakers into a local `Vec`.
  3. Unless `skip_timeouts`, splits off and drains timers with `deadline <= now`.
  4. Releases all borrows, then wakes everything collected (C7).
- **`interests()`** lists each `(fd, dir)` that has `waker.is_some() || !wakers.is_empty()`.
  This plays the role of async-io's `poller.modify(source, Event { readable, writable })`.
  **`next_deadline()`** is the first `timers` key. `ares_fds`,
  `ares_getsock`, `ares_timeout` and the event thread's `poll()` snapshot read
  only these two.
- **`Slab`**: a minimal in-house `Vec<Option<T>>` with a free list (~25 lines,
  safe), rather than a new `slab` dependency.

### `io.rs::Async<Rc<dyn Socket>>` (async-io's `Async<T>`)

```rust
impl Async {
    fn new(sock: Rc<dyn Socket>, reactor: &Rc<Reactor>) -> Self;   // insert_io
    fn readable(&self) -> Ready<'_>;  fn writable(&self) -> Ready<'_>;
    async fn read_with<R>(&self, op: impl FnMut(&dyn Socket, &mut Vec<u8>) -> io::Result<R>) -> io::Result<R>;
    async fn write_with<R>(&self, op: impl FnMut(&dyn Socket) -> io::Result<R>) -> io::Result<R>;
    fn readable_this_turn(&self) -> bool;                           // C2 peek for try_recv
}
impl Drop for Async { /* reactor.remove_io(&source) */ }
```

`read_with` lends the reactor's `scratch` to `op`. `recv_datagram`/`recv_stream`
stay as plain `op` bodies. `send_when_writable` becomes
`timer.or(async_sock.write_with(..))` using `select_biased!`, as today.

### `timer.rs::Timer` (async-io's `Timer`)

`Timer::at(&reactor, deadline)` is a `Future<Output = Instant>`.
- On the first `Pending` it inserts `(deadline, id) → waker`, and on later
  polls it refreshes the waker if `!will_wake`. `Drop` removes the entry.
- It checks `Instant::now() >= deadline` on every poll, so a task polled for
  another reason still sees its expiry. That matches today's `sleep_until`.

### `executor.rs::LocalExecutor` (async-executor's `LocalExecutor`)

```rust
pub(crate) struct LocalExecutor {
    slots: Vec<Option<Slot>>,                       // task + gen + Arc<TaskWaker>
    queue: Arc<Mutex<VecDeque<(usize, u32)>>>,      // the runnable queue
}
struct TaskWaker { id: usize, gen: u32, scheduled: AtomicBool, queue: Arc<Mutex<..>> }
impl Wake for TaskWaker { /* if !scheduled.swap(true) { queue.push((id, gen)) } */ }
```

- `std::task::Wake` needs `Send + Sync`, hence the `Arc`/`Mutex`/atomics. In
  practice everything runs under the channel lock on one thread. A poisoned
  lock is recovered with `unwrap_or_else(PoisonError::into_inner)`, so there
  is no panic path.
- **`spawn(fut, on) -> usize`** stores the task and schedules it, like smol's spawn.
- **`try_tick() -> Option<(usize, bool)>`**
  - Pops one runnable, skipping a stale `gen`.
  - Releases the queue lock, clears `scheduled`, and polls with the task's own waker.
  - Returns `(id, completed)` so the host can drain effects and then deliver (C6).
- **`cancel(id, status)`** takes the task out of its slot, then calls `on(Err(status))`
  outside any borrow (C7). `active_count()` is unchanged.
- **Removed:** `Waker::noop()`, `Mailbox<A>`, `drive_ready`, `poll_fds`,
  `next_timeout_ms`, `io(id)`, and `routed`. `executor.rs` is no longer generic.

### Runtime handle (D1: smol's implicit global, made explicit)

`#[derive(Clone)] struct Runtime { reactor: Rc<Reactor>, factory: Rc<dyn SocketFactory> }`
with:
- `udp(bind)`/`tcp(bind) -> io::Result<Async>`
- `timer_at(t) -> Timer`

`AsyncClient.factory` + `AsyncClient.io` become `AsyncClient.rt`. It is
channel-scoped: `derive()` clones it, and the channel-owned instance holds the
real one, so there is no inert mailbox. `apply_socket_factory` swaps `factory`,
and `ares_dup` builds a fresh `Reactor`.

### A turn (`ChannelData::turn`, used by `ares_process`/`_fd`/`_fds` and the event thread)

```
reactor.dispatch(events, now, skip_timeouts)          // wake io + expired timers
for _ in 0..budget:                                   // budget ≈ 4 × live tasks
    match executor.try_tick() { None => break,
        Some((id, done)) => { drain effects → server-state cb;  if done { deliver(id) } } }   // C6
```

This is smol's tick loop with the blocking wait cut out.
- Siblings woken by a shared-conn route during the turn run in the **same**
  turn. That matches upstream `read_answers`, and the event thread's
  `has_routed()` re-loop goes away.
- If the budget runs out with work queued, `ares_timeout` reports 0 and the
  event thread polls with a zero timeout.
- The `fd_set` path keeps its single `FD_ISSET` unsafe line, now building the
  `events` list.

### Core after the change

- **`Conn`** holds `Async`, plus its `Timer`s from `rt`.
  - `send` becomes `write_with` raced against a `Timer`.
  - `recv_msg` checks the routed slot, then `read_with`.
  - `try_recv` uses `readable_this_turn()`.
  - No constructor takes `io` anymore.
- **Pools.** `InboxSlot.notify: Rc<RefCell<DnsMailbox>>` becomes
  `waker: Option<Waker>`.
  - It is set from `cx.waker()` when `recv_msg` returns `Pending`.
  - Routing calls `wake_by_ref()`, and the UDP dead-socket broadcast wakes all.
  - `reserve` no longer takes a mailbox.
- **`DnsSignals` is split by owner:**
  - `effects` moves to a channel-level `Rc<RefCell<Vec<Effect>>>` on
    `AsyncClient`, shared by `derive()` like `cache`.
  - `cancelled` becomes a local `Rc<Cell<bool>>` in `query_families`, passed to
    `request(.., cancel: Option<&Cell<bool>>)`.
  - `timeouts` goes into the lifecycle outputs: `gethostbyname`/`gethostbyaddr`
    return `(Result<Hostent, _>, c_int)`, and `on_hostent_reply` loses `io`.
  - `qid` becomes a `Rc<Cell<u16>>` argument to `query_raw`, passed down to
    `connect_failover`.
- `ChannelData::spawn(fut, on)` loses `io`.

## Steps (each lands green: clippy `-D warnings`, `cargo test`, 734 gtests, fuzz corpora)

1. **`LocalExecutor` with real wakers, mailbox kept.**
   - `TaskWaker`, run queue, `try_tick`.
   - Pools store a `Waker` instead of setting `routed`.
   - `drive_ready` still gates on `fired`/timeouts but schedules through the queue.
   - The turn loops `try_tick`.

   This isolates the waker mechanics: generation, budget, C7 lock discipline.
2. **`Reactor`/`Source`/`Ready`/`Async`/`Timer`.**
   - async-io's structure with `dispatch`.
   - `scratch` moves into the reactor.
   - Delete `Mailbox.waits/timeout/fired/scratch`.
   - The tallies and the event-thread snapshot read `Reactor`.
   - Core still passes `io`, now only for `app`.
3. **Remove the mailbox.**
   - Split `DnsSignals`, delete `Mailbox`/`DnsMailbox`/`AsyncClient.io`, and add `Runtime`.
4. **Docs and gates.**
   - CLAUDE.md: the runtime bullet (smol-shaped; `FuturesUnordered` now works),
     plus the module map for `reactor.rs`/`timer.rs`.
   - `tools/unsafe_lines.py --update` if the count dropped. It must not rise.
   - ABI/exports baselines are unaffected.

## New tests

Unit tests in `async_runtime` use a fake `Socket` and no real fds, so they run
under Miri. Where possible they are ported from async-io's own reactor/timer
tests.

- **C1.** `read_with` does not call `op` before `dispatch` reports the fd, and
  a zero-length read without a report stays `Pending`.
- **C2.** A `Ready` registered after an event's tick does not complete, and
  `readable_this_turn()` is false in the next turn.
- **C3.** Write readiness does not complete `readable()`.
- **C4.** Dropping a pending `Ready`/`Timer` removes it from
  `interests()`/`next_deadline()`, for example when `select_biased!` picks the
  timer. Dropping `Async` removes its `Source`.
- **C5.** `skip_timeouts` leaves an expired `Timer` unwoken.
- **Shared fd.** Two tasks are registered on one fd and one report wakes both.
  The routed sibling completes in the same turn.
- **Stale waker.** A task is reaped and its slot reused; the old waker fires,
  and the new occupant is not polled.
- **Budget.** A self-waking task does not livelock a turn, and `ares_timeout`
  then reports 0.
- **C7.** Extend `tests/reentrant_callback.rs`: a completion callback calls
  `ares_process` mid-turn.

## Size estimate

Roughly the same as the non-smol variant: net +80–180 non-test lines on
~11,200, most of it moved. The smol shape costs about 30 extra lines for the
`Direction` tick bookkeeping and the in-house `Slab`.

| Area | Now | After |
|---|---|---|
| `executor.rs` | 167 | ~120 (`LocalExecutor`) |
| `reactor.rs` | — | ~170–210 (`Reactor`, `Source`, `Direction`, `Ready`, `Slab`) |
| `io.rs` | 103 | ~90 (`Async`, `read_with`/`write_with`) |
| `timer.rs` | — | ~40 |
| core plumbing (`io`/`app`/`routed`/`scratch`) | ~85 lines | ~25 |
| ffi (`channel.rs`, `lookups.rs`) | ~22 lines | fewer |

The unsafe count does not change (the `FD_ISSET` line stays) or drops slightly.

## Open questions

- **Budget value.** `4 × live tasks` is a guess. Check against the
  `MaxQueries`/parallel-TCP gtests.
- **Same-turn sibling completion (step 1).** Confirm no gtest depends on the
  current "next `ares_process` call" delay. If one does, check upstream
  `ares_process.c` before changing anything.
- **Effects ordering.** With a channel-level queue drained after each poll,
  confirm that task A's server-state callback can't land after task B's
  completion in the same turn.
- **Shared-fd reads (C1 tightening, optional).** Like today's per-task
  `fired`, one report lets *every* waiter on a shared fd attempt one read. For
  blocking caller-supplied sockets (`drain_safe() == false`), consider letting
  only the first `read_with` per tick read, with siblings that find nothing
  routed re-awaiting. This deviates from async-io, so it is left out unless a
  test shows the need.
