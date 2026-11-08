//! The built-in event thread (`ARES_OPT_EVENT_THREAD`; upstream
//! `ares_event_thread.c` + `ares_event_wake_pipe.c`). Opt-in: a channel without
//! the option never starts one and the caller drives `ares_process*` itself.
//!
//! The thread is just another caller of the channel's reactor turn: it
//! snapshots the reactor's interests under the channel lock, `poll`s without
//! holding it, then re-locks to run `process_events`. Callbacks therefore fire
//! on this thread, under the recursive lock (destroy inside one is unsupported).
//! `ares_evsys_t` is accepted but ignored: the backend is always `poll()`.

use super::*;
use crate::ffi::ares_socket::{ares_fd_events_t, ARES_FD_EVENT_READ, ARES_FD_EVENT_WRITE};
use crate::ffi::channel::ReentrantMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Upper bound on the event thread's poll wait; new work wakes it via the wake pipe.
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
    let (thread_stop, thread_wake) = (stop.clone(), wake.clone());
    let spawned = std::thread::Builder::new()
        .name("cares-event".to_string())
        .spawn(move || event_thread_main(raw, thread_stop, lock, thread_wake));
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

fn event_thread_main(channel: usize, stop: Arc<AtomicBool>, lock: &'static ReentrantMutex, wake: Arc<WakePipe>) {
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }

        // Snapshot the reactor interests while serialized; the channel pointer
        // stays valid until `ares_destroy` joins this thread.
        let (waits, next_timeout) = {
            let _guard = lock.lock();
            if stop.load(Ordering::Acquire) {
                break;
            }
            // SAFETY: the channel is alive for the lifetime of this thread and
            // the lock excludes every other access while we read it.
            let data = unsafe { &*(channel as *const ChannelData) };
            (data.all_poll_fds(), data.next_timeout_ms())
        };

        // poll rather than select: no FD_SETSIZE ceiling. Slot 0 is the wake pipe.
        let mut pollfds: Vec<libc::pollfd> = Vec::with_capacity(waits.len() + 1);
        pollfds.push(libc::pollfd { fd: wake.read_fd(), events: libc::POLLIN, revents: 0 });
        pollfds.extend(waits.iter().map(|(fd, wants_write)| libc::pollfd {
            fd: *fd,
            events: if *wants_write { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        }));
        let timeout_ms = match next_timeout {
            Some(ms) => ms.clamp(1, EVENT_MAX_WAIT_MS) as libc::c_int,
            None => EVENT_MAX_WAIT_MS as libc::c_int,
        };
        // A timeout/error just means no fd is ready; timeouts are still
        // processed below, so no extra sleep is needed.
        let _count = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, timeout_ms) };

        let mut events: Vec<ares_fd_events_t> = Vec::new();
        let mut woke = false;
        for p in &pollfds {
            if p.fd == wake.read_fd() {
                woke = p.revents != 0;
                continue;
            }
            if p.revents == 0 {
                continue;
            }
            let mut flags = 0;
            // Errors/hangups wake both interests so a failed connect and a dead
            // read socket are driven without waiting for the timeout arm.
            if p.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                flags |= ARES_FD_EVENT_READ;
            }
            if p.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                flags |= ARES_FD_EVENT_WRITE;
            }
            events.push(ares_fd_events_t { fd: p.fd, events: flags });
        }
        if woke {
            wake.drain();
        }

        {
            let _guard = lock.lock();
            if stop.load(Ordering::Acquire) {
                break;
            }
            // SAFETY: as above; the lock excludes all other channel access.
            let data = unsafe { &mut *(channel as *mut ChannelData) };
            data.process_events(&events, false);
        }
    }
}

/// Event-thread self-pipe; `wake` is nonblocking (a full pipe means the thread is already runnable).
struct WakePipe {
    read_fd: libc::c_int,
    write_fd: libc::c_int,
}

impl WakePipe {
    fn new() -> Option<Self> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds points to two writable slots.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        for fd in fds {
            // SAFETY: fd is a freshly created valid descriptor.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            let fdflags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            let ok = flags != -1
                && fdflags != -1
                && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != -1
                && unsafe { libc::fcntl(fd, libc::F_SETFD, fdflags | libc::FD_CLOEXEC) } != -1;
            if !ok {
                for fd in fds {
                    unsafe { libc::close(fd) };
                }
                return None;
            }
        }
        Some(WakePipe { read_fd: fds[0], write_fd: fds[1] })
    }

    fn read_fd(&self) -> libc::c_int {
        self.read_fd
    }

    fn wake(&self) {
        let byte = 1u8;
        // SAFETY: one byte from a valid stack address to a valid descriptor.
        // EAGAIN (pipe full) and EINTR are benign: the thread is already awake.
        unsafe { libc::write(self.write_fd, &byte as *const u8 as *const libc::c_void, 1) };
    }

    fn drain(&self) {
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: buf is writable for its full length and the fd is valid.
            let n = unsafe { libc::read(self.read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
        }
    }
}

impl Drop for WakePipe {
    fn drop(&mut self) {
        // SAFETY: the fds are owned by this WakePipe and closed exactly once.
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}
