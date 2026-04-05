//! Event thread: spawns a background thread that drives the reactor loop
//! (poll + ares_process_fd) so callers don't need to manage select/poll themselves.
//! Activated via ARES_OPT_EVENT_THREAD in ares_init_options.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use crate::ffi::{Channel, ChannelData};
use crate::ffi::ares_socket::ares_socket_t;

const ARES_SOCKET_BAD: ares_socket_t = -1;

/// Recursive mutex wrapping pthread_mutex_t with PTHREAD_MUTEX_RECURSIVE.
/// Required because c-ares callbacks may re-enter the channel API (e.g.
/// a callback calling ares_cancel while the event thread holds the lock).
struct RecursiveMutex {
    inner: libc::pthread_mutex_t,
}

unsafe impl Send for RecursiveMutex {}
unsafe impl Sync for RecursiveMutex {}

impl RecursiveMutex {
    fn new() -> Self {
        unsafe {
            let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
            libc::pthread_mutexattr_init(&mut attr);
            libc::pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);
            let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
            libc::pthread_mutex_init(&mut mutex, &attr);
            libc::pthread_mutexattr_destroy(&mut attr);
            RecursiveMutex { inner: mutex }
        }
    }

    fn lock(&self) -> RecursiveMutexGuard<'_> {
        unsafe { libc::pthread_mutex_lock(&self.inner as *const _ as *mut _); }
        RecursiveMutexGuard { mutex: self }
    }
}

impl Drop for RecursiveMutex {
    fn drop(&mut self) {
        unsafe { libc::pthread_mutex_destroy(&mut self.inner); }
    }
}

struct RecursiveMutexGuard<'a> {
    mutex: &'a RecursiveMutex,
}

impl<'a> Drop for RecursiveMutexGuard<'a> {
    fn drop(&mut self) {
        unsafe { libc::pthread_mutex_unlock(&self.mutex.inner as *const _ as *mut _); }
    }
}

/// Opaque event thread state, stored as *mut c_void in channeldata.event_thread.
struct EventThread {
    thread: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
    mutex: Arc<RecursiveMutex>,
    wake_write: i32,
    wake_read: i32,
}

/// Start the event thread for a channel. Called from ares_init_options.
pub(crate) fn start(channel: Channel) {
    let channeldata = unsafe { &mut *channel };

    // Create self-pipe for waking the event thread
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return; // pipe creation failed, no event thread
    }
    let wake_read = fds[0];
    let wake_write = fds[1];

    // Set both ends non-blocking
    unsafe {
        let flags = libc::fcntl(wake_read, libc::F_GETFL);
        libc::fcntl(wake_read, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let flags = libc::fcntl(wake_write, libc::F_GETFL);
        libc::fcntl(wake_write, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let running = Arc::new(AtomicBool::new(true));
    let mutex = Arc::new(RecursiveMutex::new());

    let running_clone = running.clone();
    let mutex_clone = mutex.clone();
    let channel_ptr = channel as usize;

    let thread = thread::spawn(move || {
        event_loop(channel_ptr as Channel, &running_clone, &mutex_clone, wake_read);
        unsafe { libc::close(wake_read); }
    });

    let et = Box::new(EventThread {
        thread: Some(thread),
        running,
        mutex,
        wake_write,
        wake_read,
    });
    channeldata.event_thread = Box::into_raw(et) as *mut libc::c_void;
}

/// Stop the event thread. Called from ares_destroy.
pub(crate) fn stop(channel: Channel) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    if channeldata.event_thread.is_null() { return; }

    let mut et = unsafe { Box::from_raw(channeldata.event_thread as *mut EventThread) };
    channeldata.event_thread = std::ptr::null_mut();

    // Signal thread to stop and wake it
    et.running.store(false, Ordering::Release);
    wake(&et);

    // Join thread — must complete before dropping Arc clones
    let thread = std::mem::take(&mut et.thread);
    if let Some(handle) = thread {
        let _ = handle.join();
    }

    // Close write end of pipe (read end closed by thread on exit)
    let wake_write = et.wake_write;
    unsafe { libc::close(wake_write); }

    // Drop everything — thread has exited, Arc refcounts will reach 0
    drop(et);
}

/// Wake the event thread (called after adding queries).
pub(crate) fn wake_if_active(channel: Channel) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &*channel };
    if channeldata.event_thread.is_null() { return; }
    let et = unsafe { &*(channeldata.event_thread as *const EventThread) };
    wake(et);
}

/// Guard that holds the recursive mutex and wakes the event thread on drop.
pub(crate) struct EventThreadGuard {
    _mutex_guard: RecursiveMutexGuard<'static>,
    wake_fd: i32,
}

impl Drop for EventThreadGuard {
    fn drop(&mut self) {
        // Wake the event thread so it re-polls with updated socket state
        let buf = [1u8];
        unsafe { libc::write(self.wake_fd, buf.as_ptr() as *const libc::c_void, 1); }
    }
}

/// Lock the event thread mutex if active. Returns a guard that wakes the
/// event thread on drop (after the API call completes).
/// Uses a recursive mutex so callbacks can safely re-enter the API.
pub(crate) fn lock_if_active(channel: Channel) -> Option<EventThreadGuard> {
    if channel.is_null() { return None; }
    let channeldata = unsafe { &*channel };
    if channeldata.event_thread.is_null() { return None; }
    let et = unsafe { &*(channeldata.event_thread as *const EventThread) };
    let mutex: &'static RecursiveMutex = unsafe { std::mem::transmute(&*et.mutex) };
    Some(EventThreadGuard {
        _mutex_guard: mutex.lock(),
        wake_fd: et.wake_write,
    })
}

fn wake(et: &EventThread) {
    let buf = [1u8];
    unsafe { libc::write(et.wake_write, buf.as_ptr() as *const libc::c_void, 1); }
}

fn drain_wake_pipe(wake_read: i32) {
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(wake_read, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 { break; }
    }
}

fn event_loop(channel: Channel, running: &AtomicBool, mutex: &RecursiveMutex, wake_read: i32) {
    let mut pollfds: Vec<libc::pollfd> = Vec::with_capacity(17); // 16 socks + wake pipe

    while running.load(Ordering::Relaxed) {
        // 1. Under lock: get active sockets
        let (socks, bitmask) = {
            let _guard = mutex.lock();
            let mut socks = [ARES_SOCKET_BAD; 16];
            let channeldata = unsafe { &mut *channel };
            let bitmask = unsafe {
                crate::ffi::ares_getsock(channel, socks.as_mut_ptr(), 16)
            };
            (socks, bitmask)
        };

        // 2. Build pollfd array
        pollfds.clear();
        // Add wake pipe first
        pollfds.push(libc::pollfd { fd: wake_read, events: libc::POLLIN, revents: 0 });

        for i in 0..16 {
            if socks[i] == ARES_SOCKET_BAD { continue; }
            let mut events: i16 = 0;
            if (bitmask & (1 << i)) != 0 { events |= libc::POLLIN; }        // readable
            if (bitmask & (1 << (i + 16))) != 0 { events |= libc::POLLOUT; } // writable
            if events != 0 {
                pollfds.push(libc::pollfd { fd: socks[i], events, revents: 0 });
            }
        }

        // 3. poll() — no lock held, caller thread can add queries
        let timeout_ms = 50; // short timeout for responsiveness
        let n = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout_ms) };

        if !running.load(Ordering::Relaxed) { break; }

        // 4. Drain wake pipe if signaled
        if n > 0 && pollfds[0].revents & libc::POLLIN != 0 {
            drain_wake_pipe(wake_read);
        }

        // 5. Under lock: process ready sockets + handle timeouts
        let _guard = mutex.lock();
        if n > 0 {
            for pfd in &pollfds[1..] { // skip wake pipe
                let r = if pfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 { pfd.fd } else { ARES_SOCKET_BAD };
                let w = if pfd.revents & libc::POLLOUT != 0 { pfd.fd } else { ARES_SOCKET_BAD };
                if r != ARES_SOCKET_BAD || w != ARES_SOCKET_BAD {
                    unsafe { crate::ffi::ares_process_fd(channel, r, w); }
                }
            }
        }
        // Always call with BAD/BAD to handle timeouts and newly queued tasks
        unsafe { crate::ffi::ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD); }
    }
}

#[no_mangle]
pub extern "C" fn ares_threadsafety() -> i32 {
    1 // ARES_TRUE — we support event threads
}
