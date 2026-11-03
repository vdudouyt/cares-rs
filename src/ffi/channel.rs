//! Channel lifecycle and configuration: init/dup/destroy/cancel, server
//! lists, reactor fd/timeout accessors, and the channel-level callbacks.
//!
//! With `ARES_OPT_EVENT_THREAD` a background thread drives the reactor, so
//! every shim serializes on the channel lock. Completion callbacks fire while
//! that lock is held. The lock is recursive, so a completion callback may
//! re-enter the same channel on the same thread; a callback that calls
//! `ares_destroy` is still unsupported (destroy joins the event thread).

use super::*;
use crate::core::async_client::{getsock_mask, normalize_port, AsyncClient, ServerSpec};
use crate::core::async_client::{DnsMailbox, DnsSignals, Effect};
use crate::async_runtime::executor::Executor;
use crate::ffi::ares_options::{ares_sock_state_cb, ARES_OPT_SORTLIST};
use crate::ffi::ares_socket::SocketConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// Upper bound on the event thread's poll wait. New work wakes the thread
/// immediately through the wake pipe, so this only bounds idle wakeups (and
/// gives timers a hard ceiling).
const EVENT_MAX_WAIT_MS: u128 = 1000;

/// The C-visible channel: the pure core state plus the channel-level C
/// callbacks. Everything the shims marshal lives behind `.state`; the six
/// callback fields are the only C-tainted residents.
pub struct ChannelData {
    pub(crate) state: AsyncClient,
    /// Concrete handle to the same factory held as `Rc<dyn SocketFactory>`
    /// in `state`. The socket-state callbacks (create/configure) live in
    /// the factory; setters rebuild it copy-on-write. ares_dup deep-clones it
    /// so no `Rc` is ever shared between channels (each may have its own
    /// event thread).
    pub(crate) socket_factory: std::rc::Rc<CSocketFactory>,
    pub(crate) server_state_callback: ares_server_state_callback,
    pub(crate) server_state_callback_arg: *mut libc::c_void,
    /// Optional notification hook fired when a pending write drains. Our writes
    /// are awaited directly, so nothing currently invokes it; the fields exist
    /// for API parity and are copied by ares_dup.
    pub(crate) pending_write_cb: ares_pending_write_cb,
    pub(crate) pending_write_arg: *mut libc::c_void,
    /// ARES_OPT_SOCK_STATE_CB (stored here for ares_save_options; also copied
    /// into the socket factory that fires it).
    pub(crate) sock_state_cb: ares_sock_state_cb,
    pub(crate) sock_state_cb_data: *mut libc::c_void,
    /// The in-flight resolver ops — the executor's task set (each future owns
    /// its socket(s)).
    executor: Executor<DnsSignals>,
    /// True when ARES_OPT_EVENT_THREAD was supplied: a background thread owns
    /// the reactor loop and the channel is serialized by `lock`.
    pub(crate) event_mode: bool,
    /// Set by `ares_destroy` to ask the event thread to leave its loop.
    pub(crate) event_stop: Arc<AtomicBool>,
    /// Handle of the built-in event thread (present while `event_mode`).
    pub(crate) event_join: Option<JoinHandle<()>>,
    /// Per-channel serialization for every shim that touches channel state.
    /// The event thread also takes it around its process cycle; user callbacks
    /// fire while it is held. Recursive so a completion callback may re-enter
    /// the same channel on the same thread (destroy from a callback remains
    /// unsupported).
    pub(crate) lock: Arc<ReentrantMutex>,
    /// Event-thread wake pipe (None for non-event channels). Created when the
    /// event thread starts and closed by `WakePipe::drop` with the channel.
    pub(crate) event_wake: Option<Arc<WakePipe>>,
}

impl ChannelData {
    /// A fresh channel: pure state, no callbacks installed.
    pub(crate) fn new(state: AsyncClient, socket_factory: std::rc::Rc<CSocketFactory>) -> Self {
        ChannelData {
            state,
            socket_factory,
            server_state_callback: None,
            server_state_callback_arg: std::ptr::null_mut(),
            pending_write_cb: None,
            pending_write_arg: std::ptr::null_mut(),
            sock_state_cb: None,
            sock_state_cb_data: std::ptr::null_mut(),
            executor: Executor::default(),
            event_mode: false,
            event_stop: Arc::new(AtomicBool::new(false)),
            event_join: None,
            lock: Arc::new(ReentrantMutex::new()),
            event_wake: None,
        }
    }

    /// ares_dup: duplicate the pure state. The socket factory is deep-cloned
    /// rather than sharing its `Rc`: duplicated event channels each have their
    /// own thread, and `Rc` refcounts are not atomic.
    pub(crate) fn dup_from(&self) -> Self {
        let socket_factory = std::rc::Rc::new((*self.socket_factory).clone());
        let mut state = self.state.duplicate();
        state.factory = socket_factory.clone();
        ChannelData {
            state,
            socket_factory,
            server_state_callback: self.server_state_callback,
            server_state_callback_arg: self.server_state_callback_arg,
            pending_write_cb: self.pending_write_cb,
            pending_write_arg: self.pending_write_arg,
            sock_state_cb: self.sock_state_cb,
            sock_state_cb_data: self.sock_state_cb_data,
            executor: Executor::default(),
            event_mode: self.event_mode,
            event_stop: Arc::new(AtomicBool::new(false)),
            event_join: None,
            lock: Arc::new(ReentrantMutex::new()),
            event_wake: None,
        }
    }

    /// Wake the event thread (no-op for non-event channels). Safe to call with
    /// the channel lock held; a full pipe means the thread is already awake.
    pub(crate) fn wake(&self) {
        if let Some(wake) = &self.event_wake {
            wake.wake();
        }
    }

    /// True when a shared-socket sibling routed work into a mailbox that has
    /// not been re-polled yet (the event thread must run another cycle without
    /// waiting for fd readiness).
    fn has_routed(&self) -> bool {
        self.executor
            .ids()
            .any(|id| self.executor.io(id).is_some_and(|io| io.borrow().routed))
    }

    /// Push the channel's socket settings (buffers, local bind, state
    /// callback) into a rebuilt factory. Called after option/local setters.
    pub(crate) fn refresh_socket_config(&mut self) {
        let socket = SocketConfig {
            send_buf: self.state.socket_send_buffer_size,
            recv_buf: self.state.socket_receive_buffer_size,
            local_ip4: self.state.local_ip4,
            local_ip6: self.state.local_ip6,
            local_dev: self.state.local_dev.clone(),
            sock_state_cb: self.sock_state_cb,
            sock_state_cb_data: self.sock_state_cb_data,
        };
        let factory = self.socket_factory.with_config(socket);
        self.apply_socket_factory(factory);
    }

    /// A fresh channel with the default (libc) socket factory, before the
    /// no-nameserver fallback is applied (ares_init_options applies options
    /// first so ARES_FLAG_NO_DFLT_SVR and explicit servers win). `resolvconf`
    /// is the caller's ARES_OPT_RESOLVCONF path, if any.
    pub(crate) fn new_unfinalized(resolvconf: Option<&str>) -> Self {
        let factory = std::rc::Rc::new(CSocketFactory::default());
        let state = AsyncClient::from_sysconfig_path(factory.clone(), resolvconf);
        ChannelData::new(state, factory)
    }

    /// A fresh, fully initialized channel with the default (libc) socket factory.
    pub(crate) fn new_default() -> Self {
        let mut channel = ChannelData::new_unfinalized(None);
        channel.state.apply_defaults();
        channel
    }

    /// Install a rebuilt socket factory, keeping the concrete handle and the
    /// core's `Rc<dyn SocketFactory>` in sync (they are the same object).
    pub(crate) fn apply_socket_factory(&mut self, factory: std::rc::Rc<CSocketFactory>) {
        self.state.factory = factory.clone();
        self.socket_factory = factory;
    }

    /// The single spawn path: register a lifecycle `fut` + its mailbox + its C
    /// delivery closure `on` in a free slot and drive it once (issuing the initial
    /// send). Every ares_* entry shim calls here. `on` fires when the reactor later
    /// settles the query (or in place if it completes on this first poll).
    pub(crate) fn spawn<T: 'static>(
        &mut self,
        io: std::rc::Rc<std::cell::RefCell<DnsMailbox>>,
        fut: impl std::future::Future<Output = T> + 'static,
        on: impl FnOnce(Result<T, c_int>) + 'static,
    ) {
        let id = self.executor.spawn(io, fut, on);
        self.advance(id);
        // New fds/timers may have been published: wake the event thread now
        // rather than waiting for its idle poll to expire.
        self.wake();
    }

    /// Advance one task one step: poll it, apply the DNS effects it emitted
    /// (server-state notify), and on completion deliver its result. On `Pending` the
    /// future has published the fds it is now blocked on into its mailbox.
    fn advance(&mut self, id: usize) {
        let done = self.executor.poll(id);
        // Drain + apply the future's app-specific effects between poll and delivery
        // (server-state callbacks fire before the result). Scoped so the `executor`
        // borrow releases before the callbacks fire.
        let effects = match self.executor.io(id) {
            Some(io) => std::mem::take(&mut io.borrow_mut().app.effects),
            None => Vec::new(),
        };
        for effect in effects {
            match effect {
                Effect::NotifyServerState { server, ok, tcp } => {
                    self.invoke_server_state_callback(server, ok, tcp)
                }
            }
        }
        if done {
            self.executor.deliver(id, None);
        }
    }

    /// Drive every task whose published fd is ready (or whose timeout passed) this
    /// `ares_process` cycle: set its mailbox readiness via the `FD_ISSET` oracle
    /// (the sole unsafe here) and re-poll it.
    fn drive_fd_futures(
        &mut self,
        read_fds: &mut libc::fd_set,
        write_fds: &mut libc::fd_set,
        skip_timeouts: bool,
    ) {
        let now = Instant::now();
        let rf: &libc::fd_set = &*read_fds;
        let wf: &libc::fd_set = &*write_fds;
        let ready = self.executor.drive_ready(now, skip_timeouts, |fd, writable| {
            let set = if writable { wf } else { rf };
            unsafe { libc::FD_ISSET(fd, set as *const libc::fd_set as *mut libc::fd_set) }
        });
        for id in ready {
            self.advance(id);
        }
    }

    /// Fire `status` to every in-flight task (fire the terminal status + drop the
    /// future, which drops its owned sockets). The shared safe teardown for
    /// `ares_cancel` (ECANCELLED) / `ares_destroy` (EDESTRUCTION).
    pub(crate) fn abort_all(&mut self, status: c_int) {
        for id in self.executor.ids() {
            self.executor.deliver(id, Some(status));
        }
        // Drop any shared TCP/UDP connections the aborted futures held.
        self.state.tcp_pool.borrow_mut().clear();
        let retired = self.state.udp_pool.borrow_mut().clear();
        drop(retired);
    }

    /// Every (fd, wants_write) the caller should select on.
    fn all_poll_fds(&self) -> Vec<(i32, bool)> {
        self.executor.poll_fds()
    }

    /// The earliest timeout (ms) across in-flight tasks, or `None`.
    fn next_timeout_ms(&self) -> Option<u128> {
        self.executor.next_timeout_ms(Instant::now())
    }

    /// One `ares_process` cycle: drive every in-flight async future whose
    /// published socket is ready (or whose timeout passed) this cycle. Each
    /// future owns its socket(s) and applies its own verdicts; the only unsafe
    /// here is the `FD_ISSET` readiness check and the C-callback invokers.
    pub(crate) fn process_channel(
        &mut self,
        read_fds: &mut libc::fd_set,
        write_fds: &mut libc::fd_set,
        skip_timeouts: bool,
    ) {
        self.drive_fd_futures(read_fds, write_fds, skip_timeouts);
    }

    /// Drive one batch of explicit fd/event pairs without ever putting them in
    /// an `fd_set` (upstream `ares_process_fds` semantics). This avoids the
    /// `FD_SETSIZE` ceiling: a custom socket layer may legally return a high
    /// fd, and `libc::FD_SET` would index out of bounds and abort the process.
    pub(crate) fn process_events(
        &mut self,
        events: &[crate::ffi::ares_socket::ares_fd_events_t],
        skip_timeouts: bool,
    ) {
        use crate::ffi::ares_socket::{ARES_FD_EVENT_READ, ARES_FD_EVENT_WRITE};
        let now = Instant::now();
        let ready = self.executor.drive_ready(now, skip_timeouts, |fd, writable| {
            let bit = if writable { ARES_FD_EVENT_WRITE } else { ARES_FD_EVENT_READ };
            events.iter().any(|ev| ev.fd == fd && ev.events & bit != 0)
        });
        for id in ready {
            self.advance(id);
        }
    }

    /// Fire the server-state notification callback (if installed) for a server
    /// index; a stale index is silently skipped.
    pub(crate) fn invoke_server_state_callback(&self, server_index: usize, success: bool, is_tcp: bool) {
        if let Some(cb) = self.server_state_callback {
            let Some(server_str) = self.state.server_state_string(server_index, is_tcp) else {
                return;
            };
            let c_server_str = CString::new(server_str).unwrap_or_default();
            let success_int: c_int = if success { 1 } else { 0 };
            let flags: c_int = if is_tcp { 1 << 1 } else { 1 << 0 }; // ARES_SERV_STATE_TCP=2, UDP=1
            unsafe { cb(c_server_str.as_ptr(), success_int, flags, self.server_state_callback_arg) };
        }
    }
}

/// The event thread's self-pipe. `wake` is nonblocking (a full pipe simply
/// means the thread is already runnable); `drain` is called by the thread on
/// every wakeup.
pub(crate) struct WakePipe {
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
            // Both ends nonblocking and close-on-exec.
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

/// A per-channel recursive lock. Completion callbacks fire while the lock is
/// held, so the same thread must be able to re-enter a channel API (the
/// historical single-thread behavior). A different thread waits on `available`
/// until the owner fully unwinds.
pub(crate) struct ReentrantMutex {
    state: Mutex<LockState>,
    available: Condvar,
}

struct LockState {
    /// Non-allocating platform thread identity (see `thread_token`).
    owner: Option<usize>,
    depth: usize,
}

/// An opaque, allocation-free thread identity for the recursive lock.
fn thread_token() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: pthread_self has no preconditions and cannot fail.
        unsafe { libc::pthread_self() as usize }
    }
    #[cfg(not(unix))]
    {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        hasher.finish() as usize
    }
}

impl ReentrantMutex {
    fn new() -> Self {
        ReentrantMutex {
            state: Mutex::new(LockState { owner: None, depth: 0 }),
            available: Condvar::new(),
        }
    }

    fn lock(&self) -> ReentrantGuard<'_> {
        let me = thread_token();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match state.owner {
                None => {
                    state.owner = Some(me);
                    state.depth = 1;
                    break;
                }
                Some(owner) if owner == me => {
                    state.depth += 1;
                    break;
                }
                Some(_) => {
                    state = self.available.wait(state).unwrap_or_else(|e| e.into_inner());
                }
            }
        }
        drop(state);
        ReentrantGuard { lock: self }
    }
}

pub(crate) struct ReentrantGuard<'a> {
    lock: &'a ReentrantMutex,
}

impl Drop for ReentrantGuard<'_> {
    fn drop(&mut self) {
        let me = thread_token();
        let mut state = self.lock.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.owner != Some(me) {
            return;
        }
        if state.depth > 1 {
            state.depth -= 1;
            return;
        }
        state.depth = 0;
        state.owner = None;
        drop(state);
        self.lock.available.notify_one();
    }
}

/// The built-in event thread: snapshot the fds/timeout under the channel lock,
/// `poll` without holding it, then lock again and drive the futures whose fds
/// became ready (or whose timeout expired).
fn event_thread_main(channel: usize, stop: Arc<AtomicBool>, lock: &'static ReentrantMutex, wake: Arc<WakePipe>) {
    use crate::ffi::ares_socket::{ares_fd_events_t, ARES_FD_EVENT_READ, ARES_FD_EVENT_WRITE};
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }

        // Snapshot the reactor interests while serialized. The channel pointer
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

        // Poll rather than select: no FD_SETSIZE ceiling and no fd_set
        // marshalling in the loop. The readiness oracle handed to the executor
        // is the same one `ares_process_fds` uses. Slot 0 is the wake pipe.
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
            // Errors/hangups wake both interests so a failed connect (write)
            // and a dead read socket are both driven without waiting for the
            // timeout arm.
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
            let mut batch = events;
            loop {
                data.process_events(&batch, false);
                // A shared UDP socket that died flags every sibling mailbox;
                // re-poll them now instead of waiting for their timeouts.
                if !data.has_routed() {
                    break;
                }
                batch.clear();
            }
        }

    }
}

/// Lock a channel (recursively on the same thread) and hand back the guard
/// together with a mutable view of its state. `None` for a NULL handle. The
/// guard is `'static` because the channel owns its lock for as long as it
/// lives and `ares_destroy` joins the event thread before dropping the
/// channel; the caller must not retain the returned reference past its frame.
///
/// # Safety
/// `channel` must be NULL or a live channel handle.
pub(crate) unsafe fn channel_access<'a>(channel: *const ChannelData) -> Option<(ReentrantGuard<'static>, &'a mut ChannelData)> {
    if channel.is_null() { return None; }
    // SAFETY: caller guarantees a live channel; the lock Arc outlives this
    // borrow (destroy waits for the lock before freeing the channel).
    let lock: &'static ReentrantMutex = unsafe { &*((*channel).lock.as_ref() as *const ReentrantMutex) };
    Some((lock.lock(), unsafe { &mut *(channel as *mut ChannelData) }))
}

/// Start the built-in event thread for `channel`. The thread only owns a raw
/// address cast to `usize`, so `ChannelData` itself need not be `Send`.
/// Returns false when the OS refused the thread; the caller then treats init
/// as failed.
pub(crate) fn start_event_thread(channel: *mut ChannelData) -> bool {
    let Some(wake) = WakePipe::new().map(Arc::new) else { return false };
    // SAFETY: the caller passes a freshly boxed, live channel. The wake pipe is
    // owned by the channel and mirrored into the thread for its lifetime.
    let (stop, lock) = unsafe { ((*channel).event_stop.clone(), &*((*channel).lock.as_ref() as *const ReentrantMutex)) };
    unsafe { (*channel).event_wake = Some(wake.clone()) };
    let raw = channel as usize;
    match std::thread::Builder::new()
        .name("cares-event".to_string())
        .spawn(move || event_thread_main(raw, stop, lock, wake))
    {
        Ok(handle) => {
            // SAFETY: the thread never reads `event_join`.
            unsafe { (*channel).event_join = Some(handle) };
            true
        }
        Err(_) => false,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let channel = Box::into_raw(Box::new(ChannelData::new_default()));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dup(dest: *mut Channel, source: *const ChannelData) -> c_int {
    dup_impl(dest, source)
}

/// Safe body of ares_dup: copy under the source lock, then start the
/// duplicate's own event thread.
fn dup_impl(dest: *mut Channel, source: *const ChannelData) -> c_int {
    if dest.is_null() || source.is_null() { return ARES_ENOTINITIALIZED; }
    let lock = unsafe { (*source).lock.clone() };
    let guard = lock.lock();
    let channeldata = unsafe { &*source }.dup_from();
    drop(guard);
    let channel = Box::into_raw(Box::new(channeldata));
    let event_mode = unsafe { (*channel).event_mode };
    if event_mode && !start_event_thread(channel) {
        drop(unsafe { Box::from_raw(channel) });
        return ARES_ENOMEM;
    }
    unsafe { *dest = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_cancel(channel: Channel) {
    cancel_impl(channel)
}

/// Safe body of ares_cancel: abort every in-flight future.
fn cancel_impl(channel: *mut ChannelData) {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    channeldata.abort_all(ARES_ECANCELLED);
    channeldata.wake();
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    destroy_impl(channel)
}

/// Safe body of ares_destroy: stop and join the event thread (without holding
/// the lock across the join), abort every query, then free the channel. The
/// stop flag is followed by a wake-pipe write so the join is prompt.
fn destroy_impl(channel: *mut ChannelData) {
    if channel.is_null() { return; }
    let Some((guard, data)) = (unsafe { channel_access(channel) }) else { return; };
    let stop = data.event_stop.clone();
    let join = data.event_join.take();
    let wake = data.event_wake.clone();
    drop(guard);
    if let Some(handle) = join {
        stop.store(true, Ordering::Release);
        if let Some(wake) = wake {
            wake.wake();
        }
        let _ = handle.join();
    }
    let Some((guard, data)) = (unsafe { channel_access(channel) }) else { return; };
    data.abort_all(ARES_EDESTRUCTION);
    // Release the recursive lock before freeing the channel (and the lock).
    drop(guard);
    drop(unsafe { Box::from_raw(channel) });
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_fds(channel: *const ChannelData, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return 0; };
    unsafe { libc::FD_ZERO(write_fds); libc::FD_ZERO(read_fds) };

    let fds = channeldata.all_poll_fds();
    for (fd, wants_write) in &fds {
        unsafe { if *wants_write { libc::FD_SET(*fd, write_fds) } else { libc::FD_SET(*fd, read_fds) } };
    }
    crate::core::async_client::nfds(&fds)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_timeout(channel: Channel, maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval {
    // Upstream: NULL channel or output buffer -> return NULL.
    if tv.is_null() || channel.is_null() { return std::ptr::null_mut(); }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return std::ptr::null_mut(); };
    let maxtv_ms = (!maxtv.is_null())
        .then(|| unsafe { (*maxtv).tv_sec as u128 * 1000 + (*maxtv).tv_usec as u128 / 1000 });
    match crate::core::async_client::clamp_timeout(channeldata.next_timeout_ms(), maxtv_ms) {
        crate::core::async_client::TimeoutChoice::NoTasks => {
            if maxtv.is_null() { return std::ptr::null_mut(); }
            maxtv
        }
        crate::core::async_client::TimeoutChoice::Wait { ms, use_max } => {
            unsafe {
                (*tv).tv_sec = (ms / 1000) as i64;
                (*tv).tv_usec = 1000 * (ms % 1000) as i64;
            };
            if use_max { maxtv } else { tv }
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers(channel: Channel, head: *const ares_addr_node) -> c_int {
    let mut head = head;
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENODATA; };
    let mut servers = Vec::new();
    while !head.is_null() {
        let node = unsafe { &(*head) };
        match node.family {
            libc::AF_INET => {
                let oct4 = unsafe { node.addr.addr4 }.s_addr.to_ne_bytes();
                servers.push(ServerSpec { ip: IpAddr::from(oct4), udp_port: None, tcp_port: None });
            }
            libc::AF_INET6 => {
                let oct16 = unsafe { node.addr.addr6._S6_un._S6_u8 };
                servers.push(ServerSpec { ip: IpAddr::from(oct16), udp_port: None, tcp_port: None });
            }
            _ => {}
        }
        head = unsafe { (*head).next as *const ares_addr_node };
    }
    channeldata.state.set_servers(servers);
    channeldata.wake();
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports(channel: Channel, head: *const AresAddrPortNode) -> c_int {
    let mut head = head;
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENODATA; };
    let mut servers = Vec::new();
    while !head.is_null() {
        let node = unsafe { &*head };
        let udp_port = normalize_port(node.udp_port as u16);
        let tcp_port = normalize_port(node.tcp_port as u16);
        match node.family {
            libc::AF_INET => {
                let octets = unsafe { node.addr.addr4.s_addr.to_ne_bytes() };
                servers.push(ServerSpec { ip: IpAddr::from(octets), udp_port, tcp_port });
            }
            libc::AF_INET6 => {
                let octets = unsafe { node.addr.addr6._S6_un._S6_u8 };
                servers.push(ServerSpec { ip: IpAddr::from(octets), udp_port, tcp_port });
            }
            _ => {}
        }
        head = node.next as *const AresAddrPortNode;
    }
    channeldata.state.set_servers(servers);
    channeldata.wake();
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_ports(channel: *const ChannelData, out: *mut *mut AresAddrPortNode) -> c_int {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENODATA; };
    let Some(ptr) = get_servers_ports_ptr(channeldata) else { unsafe { *out = std::ptr::null_mut() }; return ARES_ENODATA; };
    unsafe { *out = ptr };
    ARES_SUCCESS
}

/// Build the ares_addr_port_node chain for ares_get_servers_ports.
fn get_servers_ports_ptr(channeldata: &ChannelData) -> Option<*mut AresAddrPortNode> {
    let mut data: Vec<AresAddrPortNode> = vec![];
    for (ip, udp_port, tcp_port) in channeldata.state.server_list() {
        let (family, addr) = match ip {
            IpAddr::V4(v4) => {
                let s_addr = u32::from_ne_bytes(v4.octets());
                (libc::AF_INET, AresAddrUnion { addr4: libc::in_addr { s_addr } })
            }
            IpAddr::V6(v6) => {
                (libc::AF_INET6, AresAddrUnion { addr6: ares_in6_addr::from_octets(v6.octets()) })
            }
        };
        data.push(AresAddrPortNode {
            next: std::ptr::null_mut(),
            family,
            addr,
            udp_port: udp_port as c_int,
            tcp_port: tcp_port as c_int,
        });
    }
    let replies = clinkedlist::chain_nodes(data)?;
    let aresdata: AresData<AresAddrPortNode> = AresData { data_type: AresAddrPortNode::datatype(), data: replies };
    let aresdata = Box::into_raw(Box::new(aresdata));
    // SAFETY: aresdata was just allocated and is owned by the caller.
    Some(unsafe { &mut (*aresdata).data })
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports_csv(channel: Channel, servers: *const c_char) -> c_int {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENODATA; };
    let status = unsafe { set_servers_ports_csv_impl(channeldata, servers) };
    channeldata.wake();
    status
}

/// Unlocked body of `ares_set_servers[_ports]_csv` (both public wrappers lock).
unsafe fn set_servers_ports_csv_impl(channeldata: &mut ChannelData, servers: *const c_char) -> c_int {
    // NULL or empty string clears servers
    if servers.is_null() {
        channeldata.state.clear_servers();
        return ARES_SUCCESS;
    }
    let Some(s) = (unsafe { cstr_opt(servers) }) else { return ARES_EBADSTR };
    if s.is_empty() {
        channeldata.state.clear_servers();
        return ARES_SUCCESS;
    }
    let mut cursor = Cursor::new(s);
    match servers_csv::parse_from_reader(&mut cursor) {
        Some(ns) => {
            channeldata.state.install_csv_servers(ns);
            ARES_SUCCESS
        }
        None => ARES_EBADSTR,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_csv(channel: Channel, servers: *const c_char) -> c_int {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENODATA; };
    let status = unsafe { set_servers_ports_csv_impl(channeldata, servers) };
    channeldata.wake();
    status
}

/// # Safety
/// `channel` must be a valid channel and `socks` must point to at least `numsocks` writable slots.
#[no_mangle]
pub unsafe extern "C" fn ares_getsock(channel: *const ChannelData, socks: *mut ares_socket_t, numsocks: c_int) -> c_int {
    // Upstream: NULL channel or non-positive numsocks -> return 0 (no sockets).
    if numsocks <= 0 || channel.is_null() { return 0; }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return 0; };
    let n = min(ARES_GETSOCK_MAXNUM, numsocks as usize);

    let fds = channeldata.all_poll_fds();
    for i in 0..n {
        let fd = fds.get(i).map(|(fd, _)| *fd).unwrap_or(ARES_SOCKET_BAD);
        unsafe { std::ptr::write(socks.add(i), fd) };
    }
    getsock_mask(&fds, n)
}

/// # Safety
/// `channel` must be NULL or a live channel handle.
#[no_mangle]
pub unsafe extern "C" fn ares_set_local_ip4(channel: Channel, local_ip: u32) {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    set_local_ip4_state(channeldata, local_ip);
}

/// # Safety
/// `channel` must be NULL or a live channel handle; `local_ip6` must be NULL
/// or point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ares_set_local_ip6(channel: Channel, local_ip6: *const u8) {
    if local_ip6.is_null() || channel.is_null() { return; }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    set_local_ip6_state(channeldata, unsafe { std::slice::from_raw_parts(local_ip6, 16) });
}

/// # Safety
/// `channel` must be NULL or a live channel handle; `local_dev_name` must be
/// NULL or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_set_local_dev(channel: Channel, local_dev_name: *const c_char) {
    if local_dev_name.is_null() || channel.is_null() { return; }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    if let Some(name) = unsafe { cstr_opt(local_dev_name) } {
        set_local_dev_state(channeldata, name);
    }
}

fn set_local_ip4_state(channeldata: &mut ChannelData, local_ip: u32) {
    channeldata.state.local_ip4 = local_ip;
    channeldata.refresh_socket_config();
}

fn set_local_ip6_state(channeldata: &mut ChannelData, bytes: &[u8]) {
    channeldata.state.local_ip6.copy_from_slice(bytes);
    channeldata.refresh_socket_config();
}

fn set_local_dev_state(channeldata: &mut ChannelData, name: &str) {
    // Upstream's local_dev_name buffer is 32 bytes including the NUL.
    channeldata.state.local_dev = name.chars().take(31).collect();
    channeldata.refresh_socket_config();
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_callback(channel: Channel, callback: ares_sock_create_callback, arg: *mut c_void) {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    let factory = channeldata.socket_factory.with_create_cb(callback, arg);
    channeldata.apply_socket_factory(factory);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers(channel: *const ChannelData, out: *mut *mut ares_addr_node) -> c_int {
    if out.is_null() { return ARES_ENODATA; }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENODATA; };
    let Some(ptr) = get_servers_ptr(channeldata) else { unsafe { *out = std::ptr::null_mut() }; return ARES_ENODATA; };
    unsafe { *out = ptr };
    ARES_SUCCESS
}

/// Build the ares_addr_node chain for ares_get_servers (an AresData wrapper so
/// the caller can free it with ares_free_data, the c-ares contract).
fn get_servers_ptr(channeldata: &ChannelData) -> Option<*mut ares_addr_node> {
    let mut data: Vec<ares_addr_node> = vec![];
    for (ip, _, _) in channeldata.state.server_list() {
        let (family, addr) = match ip {
            IpAddr::V4(v4) => {
                let s_addr = u32::from_ne_bytes(v4.octets());
                (libc::AF_INET, AresAddrUnion { addr4: libc::in_addr { s_addr } })
            }
            IpAddr::V6(v6) => (libc::AF_INET6, AresAddrUnion { addr6: ares_in6_addr::from_octets(v6.octets()) }),
        };
        data.push(ares_addr_node { next: std::ptr::null_mut(), family, addr });
    }
    let chain = clinkedlist::chain_nodes(data)?;
    let aresdata: AresData<ares_addr_node> = AresData { data_type: ares_addr_node::datatype(), data: chain };
    let aresdata = Box::into_raw(Box::new(aresdata));
    // SAFETY: aresdata was just allocated and is owned by the caller.
    Some(unsafe { &mut (*aresdata).data })
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_csv(channel: *const ChannelData) -> *mut c_char {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return std::ptr::null_mut(); };
    let csv = channeldata.state.servers_csv_string();
    // CSV of IP/port strings never contains a NUL; null return on OOM is the sentinel.
    unsafe { malloc_cstr(csv.as_bytes()) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_sortlist(channel: Channel, sortstr: *const c_char) -> c_int {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENODATA; };
    if sortstr.is_null() {
        channeldata.state.sortlist = Vec::new();
        // An explicit clear is still an explicit sortlist option, so reinit
        // must not repopulate it from resolv.conf and save_options reports it.
        channeldata.state.optmask |= ARES_OPT_SORTLIST;
        return ARES_SUCCESS;
    }
    let Some(s) = (unsafe { cstr_opt(sortstr) }) else { return ARES_EBADSTR };
    match parse_sortlist(s) {
        Ok(entries) => {
            channeldata.state.sortlist = entries;
            channeldata.state.optmask |= ARES_OPT_SORTLIST;
            ARES_SUCCESS
        }
        Err(e) => e.code(),
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_reinit(channel: Channel) -> c_int {
    if channel.is_null() {
        return ARES_EFORMERR;
    }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
    let status = reinit_channel(channeldata);
    channeldata.wake();
    status
}

/// Safe body of ares_reinit (the pointer deref stays in the shim).
fn reinit_channel(channeldata: &mut ChannelData) -> c_int {
    match channeldata.state.reinit() {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_configure_callback(channel: Channel, callback: ares_sock_config_callback, arg: *mut c_void) {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    let factory = channeldata.socket_factory.with_config_cb(callback, arg);
    channeldata.apply_socket_factory(factory);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_server_state_callback(channel: Channel, callback: ares_server_state_callback, arg: *mut c_void) {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    channeldata.server_state_callback = callback;
    channeldata.server_state_callback_arg = arg;
}

/// Number of in-flight executor tasks. A single host lookup is one task even
/// when it races A/AAAA sub-queries internally, so this counts user-visible
/// lookups rather than upstream's internal per-family query objects (a
/// documented minor semantic gap).
///
/// # Safety
/// `channel` must be null or a valid channel handle returned by
/// `ares_init`/`ares_init_options` and not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn ares_queue_active_queries(channel: *const ChannelData) -> libc::size_t {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return 0; };
    channeldata.executor.active_count()
}

/// Install the pending-write notification callback. Our writes are awaited
/// directly, so the callback is stored (and copied by ares_dup) but never
/// fired yet; the API surface matches upstream.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_pending_write_cb(
    channel: Channel,
    callback: ares_pending_write_cb,
    arg: *mut c_void,
) {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    channeldata.pending_write_cb = callback;
    channeldata.pending_write_arg = arg;
}

/// Process queued writes. Everything we write is awaited inline, so there is
/// nothing to drain; accepting NULL matches the upstream contract.
#[no_mangle]
pub extern "C" fn ares_process_pending_write(channel: Channel) {
    if channel.is_null() {}
}

/// # Safety
/// `channel` must be NULL or a live channel handle.
#[no_mangle]
pub unsafe extern "C" fn ares_queue_wait_empty(channel: Channel, timeout_ms: c_int) -> c_int {
    wait_empty_impl(channel, timeout_ms)
}

/// Safe body of ares_queue_wait_empty: poll the executor's active count,
/// releasing the channel lock while sleeping so the event thread can run.
fn wait_empty_impl(channel: *mut ChannelData, timeout_ms: c_int) -> c_int {
    let Some((guard, data)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
    if data.executor.active_count() == 0 { return ARES_SUCCESS; }
    drop(guard);
    let start = Instant::now();
    loop {
        let Some((guard, data)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
        if data.executor.active_count() == 0 { return ARES_SUCCESS; }
        drop(guard);
        if timeout_ms >= 0 && start.elapsed().as_millis() >= timeout_ms as u128 { return ARES_ETIMEOUT; }
        std::thread::sleep(Duration::from_millis(1));
    }
}
