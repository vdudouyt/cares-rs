//! The built-in event thread (`ARES_OPT_EVENT_THREAD`; upstream
//! `ares_event_thread.c` + `ares_event_wake_pipe.c`). Opt-in: a channel without
//! the option never starts one and the caller drives `ares_process*` itself.
//!
//! The thread is just another caller of the channel's reactor turn: it
//! drains the reactor's interest changes under the channel lock, waits on the
//! `ares_evsys_t` backend (`event_backend.rs`: epoll or poll) without holding
//! it, then re-locks to run `process_fd_events`. Callbacks therefore fire on this
//! thread, under the recursive lock (destroy inside one is unsupported).

use super::*;
use crate::ffi::event_backend::{Backend, WakePipe};
use crate::ffi::channel::{channel_access, ReentrantMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Upper bound on the event thread's wait; new work wakes it via the wake pipe.
const EVENT_MAX_WAIT_MS: u128 = 1000;

/// A running event thread, owned by its channel (`ChannelData::event`).
pub(crate) struct EventThread {
    stop: Arc<AtomicBool>,
    wake: Arc<WakePipe>,
    join: JoinHandle<()>,
}

impl EventThread {
    /// Interrupt the thread's `poll` so it picks up newly published fds/timers.
    pub(crate) fn wake(&self) {
        self.wake.wake();
    }
}

/// Start the event thread for `channel` and store it in `ChannelData::event`;
/// the thread only holds the raw address as `usize`, so `ChannelData` need not
/// be `Send`. False if the OS refuses a pipe or a thread.
pub(crate) fn start(channel: *mut ChannelData) -> bool {
    let Some(wake) = WakePipe::new().map(Arc::new) else { return false };
    let stop = Arc::new(AtomicBool::new(false));
    // SAFETY: the caller passes a freshly boxed, live channel; its lock Arc
    // outlives the thread (`stop` joins before the channel is freed).
    let lock: &'static ReentrantMutex = unsafe { &*((*channel).lock.as_ref() as *const ReentrantMutex) };
    let raw = channel as usize;
    // SAFETY: as above; done before the thread exists, so nothing races it.
    let evsys = unsafe { (*channel).begin_event_mode() };
    let (thread_stop, thread_wake) = (stop.clone(), wake.clone());
    let spawned = std::thread::Builder::new()
        .name("cares-event".to_string())
        .spawn(move || event_thread_main(raw, evsys, thread_stop, lock, thread_wake));
    let Ok(join) = spawned else { return false };
    // Stored under the channel lock: the thread may already be running a turn.
    let _guard = lock.lock();
    // SAFETY: as above; the lock excludes the thread's access to the channel.
    unsafe { (*channel).event = Some(EventThread { stop, wake, join }) };
    true
}

/// Stop and join `thread`. The caller must not hold the channel lock, which
/// the thread needs to finish its current turn.
pub(crate) fn stop(thread: EventThread) {
    thread.stop.store(true, Ordering::Release);
    thread.wake.wake();
    let _ = thread.join.join();
}

fn event_thread_main(channel: usize, evsys: c_int, stop: Arc<AtomicBool>, lock: &'static ReentrantMutex, wake: Arc<WakePipe>) {
    let mut backend = Backend::new(evsys);
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }

        // Drain what changed in the reactor while serialized (O(changes)); the
        // channel pointer stays valid until `ares_destroy` joins this thread.
        let (changes, next_timeout) = {
            let _guard = lock.lock();
            if stop.load(Ordering::Acquire) {
                break;
            }
            // SAFETY: the channel is alive for the lifetime of this thread and
            // the lock excludes every other access while we read it.
            let data = unsafe { &*(channel as *const ChannelData) };
            (data.take_interest_changes(), data.next_timeout_ms())
        };
        backend.apply(changes);

        let timeout_ms = match next_timeout {
            Some(ms) => ms.clamp(1, EVENT_MAX_WAIT_MS) as c_int,
            None => EVENT_MAX_WAIT_MS as c_int,
        };
        // A timeout/error just means no fd is ready; timeouts are still
        // processed below, so no extra sleep is needed.
        let ready = backend.wait(&wake, timeout_ms);
        if ready.woke {
            wake.drain();
        }
        let events = ready.events;

        {
            let _guard = lock.lock();
            if stop.load(Ordering::Acquire) {
                break;
            }
            // SAFETY: as above; the lock excludes all other channel access.
            let data = unsafe { &mut *(channel as *mut ChannelData) };
            data.process_fd_events(&events);
        }
    }
}

/// # Safety
/// `channel` must be NULL or a live channel handle.
#[no_mangle]
pub unsafe extern "C" fn ares_queue_wait_empty(channel: Channel, timeout_ms: c_int) -> c_int {
    wait_empty_impl(channel, timeout_ms)
}

/// Sleep-poll the executor's active count, releasing the channel lock between
/// checks so the event thread can finish the queries. Blocking by contract, like
/// upstream (which waits on a condvar instead); it never drives I/O itself, so it
/// only returns early when another thread (normally this event thread) runs turns.
fn wait_empty_impl(channel: *mut ChannelData, timeout_ms: c_int) -> c_int {
    let Some((guard, data)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
    if data.active_queries() == 0 { return ARES_SUCCESS; }
    drop(guard);
    let start = Instant::now();
    loop {
        let Some((guard, data)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
        if data.active_queries() == 0 { return ARES_SUCCESS; }
        drop(guard);
        if timeout_ms >= 0 && start.elapsed().as_millis() >= timeout_ms as u128 { return ARES_ETIMEOUT; }
        std::thread::sleep(Duration::from_millis(1));
    }
}
