# Reentrancy and Thread Safety

## Default mode (no event thread)

The caller owns the channel and drives the event loop manually:

```
ares_gethostbyname(channel, ...)   // add query
ares_getsock(channel, ...)          // get fds to poll
select/poll(...)                    // wait for I/O
ares_process_fd(channel, r, w)      // process I/O, fire callbacks
```

In this mode there is **no locking**. The channel is not thread-safe.
The caller must ensure that no two threads access the same channel
concurrently. This matches the contract of the original c-ares library.

## Event thread mode (`ARES_OPT_EVENT_THREAD`)

When `ARES_OPT_EVENT_THREAD` is set in `ares_init_options`, a background
thread is spawned that drives the event loop automatically. Two threads
now access the channel:

1. **Caller thread** — issues queries (`ares_gethostbyname`, etc.)
2. **Event thread** — polls sockets and calls `ares_process_fd`

This requires mutual exclusion. Both sides participate:

### Event thread side (`src/ffi/event_thread.rs`)

The event thread runs a loop that acquires the mutex around channel access
but releases it during `poll()`:

```rust
// src/ffi/event_thread.rs:124-181
fn event_loop(channel: Channel, running: Arc<AtomicBool>, mutex: Arc<Mutex<()>>, wake_read: i32) {
    while running.load(Ordering::Relaxed) {
        // 1. Under lock: get active sockets
        let (socks, bitmask) = {
            let _guard = mutex.lock().unwrap();                          // <-- LOCK
            let bitmask = unsafe {
                crate::ffi::ares_getsock(channel, socks.as_mut_ptr(), 16)
            };
            (socks, bitmask)
        };                                                               // <-- UNLOCK

        // ... build pollfd array ...

        // 3. poll() — NO LOCK HELD, caller thread can add queries
        let n = unsafe { libc::poll(pollfds.as_mut_ptr(), ..., timeout_ms) };

        // 5. Under lock: process ready sockets
        let _guard = mutex.lock().unwrap();                              // <-- LOCK
        for pfd in &pollfds[1..] {
            unsafe { crate::ffi::ares_process_fd(channel, r, w); }
        }
    }                                                                    // <-- UNLOCK
}
```

### Caller side (`src/ffi/mod.rs`)

Every public API function that touches the channel acquires the same
mutex via a guard at the top:

```rust
// src/ffi/mod.rs:380-382
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, ...) {
    let _et_guard = event_thread::lock_if_active(channel);  // <-- LOCK (if ET active)
    let channeldata = unsafe { &mut *channel };
    // ... push task to channeldata.ares.tasks ...
}   // <-- guard drops, UNLOCK
```

The `lock_if_active` function (`src/ffi/event_thread.rs:98-109`) checks
whether an event thread exists and returns `None` (no-op) if not:

```rust
// src/ffi/event_thread.rs:98-109
pub(crate) fn lock_if_active(channel: Channel) -> Option<MutexGuard<'static, ()>> {
    if channel.is_null() { return None; }
    let channeldata = unsafe { &*channel };
    if channeldata.event_thread.is_null() { return None; }  // no ET = no lock
    let et = unsafe { &*(channeldata.event_thread as *const EventThread) };
    let mutex: &'static Mutex<()> = unsafe { std::mem::transmute(&*et.mutex) };
    Some(mutex.lock().unwrap())
}
```

This means the non-event-thread code path has zero locking overhead —
the `is_null()` check short-circuits immediately.

### Why both sides must lock

The lock cannot live on just one side. Consider what happens without
caller-side locking:

1. Event thread is in `poll()` at `event_thread.rs:156` — mutex **released**
2. Caller calls `ares_gethostbyname` at `mod.rs:382` — pushes a task to
   `channeldata.ares.tasks`
3. Event thread wakes from `poll()`, acquires mutex at `event_thread.rs:130`,
   calls `ares_getsock` at `event_thread.rs:134` which iterates
   `channeldata.ares.tasks`
4. **Data race**: step 2 writes to the task `Vec` while step 3 reads it

And without event-thread-side locking:

1. Event thread calls `ares_process_fd` at `event_thread.rs:178` —
   iterates tasks, modifies status, fires callbacks, may remove tasks
2. Caller calls `ares_gethostbyname` at `mod.rs:382` — pushes to the
   same task `Vec`
3. **Data race**: concurrent mutation of `channeldata.ares.tasks`

Both sides must acquire the same `Arc<Mutex<()>>` to ensure mutual
exclusion over `ChannelData`.

### Functions that lock

These functions acquire the event thread mutex when active (all in
`src/ffi/mod.rs`, pattern: `let _et_guard = event_thread::lock_if_active(channel)`):

| Function | Line |
|----------|------|
| `ares_cancel` | `mod.rs:352` |
| `ares_gethostbyname` | `mod.rs:381` |
| `ares_gethostbyaddr` | `mod.rs:649` |
| `ares_search` | `mod.rs:690` |
| `ares_query` | `mod.rs:763` |
| `ares_query_dnsrec` | `mod.rs:785` |
| `ares_search_dnsrec` | `mod.rs:826` |
| `ares_getnameinfo` | `mod.rs:919` |
| `ares_getaddrinfo` | `mod.rs:2860` |
| `ares_send` | `mod.rs:3831` |

### Functions that do NOT lock

These are called by the event thread itself under its own mutex.
Adding a lock guard would deadlock:

| Function | Called from |
|----------|-----------|
| `ares_getsock` | `event_thread.rs:134` (under `_guard` at line 130) |
| `ares_process_fd` | `event_thread.rs:168,178` (under `_guard` at line 167,173) |

External callers should not call `ares_getsock` or `ares_process_fd`
when the event thread is active — the event thread handles them. In
the non-event-thread path, no locking is needed.

### Wake mechanism

When the caller adds a query, the event thread may be blocked in `poll()`
at `event_thread.rs:156`. To avoid waiting up to the poll timeout, a
self-pipe is used:

```rust
// src/ffi/event_thread.rs:30-31 (creation)
let mut fds = [0i32; 2];
libc::pipe(fds.as_mut_ptr());

// src/ffi/event_thread.rs:111-113 (wake signal)
fn wake(et: &EventThread) {
    let buf = [1u8];
    unsafe { libc::write(et.wake_write, buf.as_ptr() as *const libc::c_void, 1); }
}

// src/ffi/event_thread.rs:142 (polled by event thread)
pollfds.push(libc::pollfd { fd: wake_read, events: libc::POLLIN, revents: 0 });

// src/ffi/event_thread.rs:161-163 (drained after wake)
if pollfds[0].revents & libc::POLLIN != 0 {
    drain_wake_pipe(wake_read);
}
```

### Shutdown

`ares_destroy` (`mod.rs:363`) stops the event thread before freeing
channel data by calling `event_thread::stop` (`event_thread.rs:67-82`):

```rust
// src/ffi/event_thread.rs:67-82
pub(crate) fn stop(channel: Channel) {
    // ...
    et.running.store(false, Ordering::Relaxed);  // 1. Signal stop
    wake(&et);                                    // 2. Wake poll()
    if let Some(handle) = et.thread {
        let _ = handle.join();                    // 3. Join thread
    }
    unsafe { libc::close(et.wake_write); }        // 4. Close pipe
}

// src/ffi/mod.rs:363-374
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    if !channel.is_null() {
        event_thread::stop(channel);              // Stop ET first
        let channeldata = unsafe { &mut *channel };
        for task in channeldata.ares.tasks.drain(..) {
            if task.status != Status::Completed {
                task.userdata.callback.run(Err(ARES_EDESTRUCTION), ...);
            }
        }
        unsafe { drop(Box::from_raw(channel)); }
    }
}
```

### Recursive locking

The mutex is a standard `std::sync::Mutex` (non-recursive). This is safe
because no public API function calls another public API function internally.
Callbacks are fired while the event thread holds the lock at
`event_thread.rs:173`, but callbacks are user code that should not re-enter
the channel (same restriction as original c-ares).
