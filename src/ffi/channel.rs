//! Channel lifecycle/config shims, the per-channel recursive lock, and the
//! reactor turn shared by `ares_process*` and the optional event thread
//! (`event_thread.rs`).

use super::*;
use crate::core::async_client::{getsock_mask, normalize_port, AsyncClient, ServerSpec};
use crate::core::async_client::Effect;
use crate::async_runtime::executor::Executor;
use crate::ffi::ares_options::{ares_sock_state_cb, ARES_OPT_SORTLIST};
use crate::ffi::ares_socket::SocketConfig;
use crate::ffi::event_thread::{self, EventThread};
use std::sync::{Arc, Condvar, Mutex};

/// The C-visible channel: core state plus the channel-level C callbacks.
pub struct ChannelData {
    pub(crate) state: AsyncClient,
    /// Concrete handle to the same factory held as `Rc<dyn SocketFactory>` in
    /// `state`; rebuilt copy-on-write. Deep-cloned by ares_dup (`Rc` isn't atomic).
    pub(crate) socket_factory: std::rc::Rc<CSocketFactory>,
    pub(crate) server_state_callback: ares_server_state_callback,
    pub(crate) server_state_callback_arg: *mut libc::c_void,
    pub(crate) pending_write_cb: ares_pending_write_cb,
    pub(crate) pending_write_arg: *mut libc::c_void,
    pub(crate) sock_state_cb: ares_sock_state_cb,
    pub(crate) sock_state_cb_data: *mut libc::c_void,
    executor: Executor,
    /// `ARES_OPT_EVENT_THREAD` was requested (carried over by `ares_dup`).
    pub(crate) event_mode: bool,
    /// The running event thread, when `event_mode` is set.
    pub(crate) event: Option<EventThread>,
    /// Per-channel recursive lock; user callbacks fire while it is held.
    pub(crate) lock: Arc<ReentrantMutex>,
}

impl ChannelData {
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
            event: None,
            lock: Arc::new(ReentrantMutex::new()),
        }
    }

    /// ares_dup: deep-clone the factory rather than sharing its `Rc` (duplicated
    /// event channels each have their own thread; `Rc` refcounts aren't atomic).
    pub(crate) fn dup_from(&self) -> Self {
        let socket_factory = std::rc::Rc::new((*self.socket_factory).clone());
        let mut state = self.state.duplicate();
        state.rt.set_factory(socket_factory.clone());
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
            event: None,
            lock: Arc::new(ReentrantMutex::new()),
        }
    }

    /// Wake the event thread; a full pipe means it is already awake.
    pub(crate) fn wake(&self) {
        if let Some(thread) = &self.event {
            thread.wake();
        }
    }

    /// Push socket settings into a rebuilt factory after option setters.
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

    /// Fresh channel before the no-nameserver fallback; options are applied
    /// first so ARES_FLAG_NO_DFLT_SVR and explicit servers win.
    pub(crate) fn new_unfinalized(resolvconf: Option<&str>) -> Self {
        let factory = std::rc::Rc::new(CSocketFactory::default());
        let state = AsyncClient::from_sysconfig_path(factory.clone(), resolvconf);
        ChannelData::new(state, factory)
    }

    pub(crate) fn new_default() -> Self {
        let mut channel = ChannelData::new_unfinalized(None);
        channel.state.apply_defaults();
        channel
    }

    /// Install a rebuilt factory, keeping the concrete handle and core `Rc` in sync.
    pub(crate) fn apply_socket_factory(&mut self, factory: std::rc::Rc<CSocketFactory>) {
        self.state.rt.set_factory(factory.clone());
        self.socket_factory = factory;
    }

    /// Spawn a task and drive it once; `on` may fire inline on this first poll.
    pub(crate) fn spawn<T: 'static>(
        &mut self,
        fut: impl std::future::Future<Output = T> + 'static,
        on: impl FnOnce(Result<T, c_int>) + 'static,
    ) {
        let id = self.executor.spawn(fut, on);
        self.advance(id);
        // New fds/timers may have been published: wake now rather than waiting
        // for the idle poll to expire.
        self.wake();
    }

    /// Advance one task; on `Pending` it has registered its interest with the reactor.
    fn advance(&mut self, id: usize) {
        let done = self.executor.poll(id);
        // Effects are drained before delivery so the callbacks fire first; taken
        // out so no `RefCell` borrow is live while they run.
        let effects = std::mem::take(&mut *self.state.effects.borrow_mut());
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

    fn drive_fd_futures(
        &mut self,
        read_fds: &mut libc::fd_set,
        write_fds: &mut libc::fd_set,
        skip_timeouts: bool,
    ) {
        let now = Instant::now();
        let rf: &libc::fd_set = &*read_fds;
        let wf: &libc::fd_set = &*write_fds;
        self.turn(now, skip_timeouts, |fd, writable| {
            let set = if writable { wf } else { rf };
            unsafe { libc::FD_ISSET(fd, set as *const libc::fd_set as *mut libc::fd_set) }
        });
    }

    /// One `ares_process*` turn: hand the caller's readiness to the reactor
    /// (waking io waiters and, unless skipped, due timers), then run every woken task.
    fn turn(&mut self, now: Instant, skip_timeouts: bool, ready: impl Fn(i32, bool) -> bool) {
        let reactor = self.state.rt.reactor().clone();
        reactor.dispatch(now, skip_timeouts, ready);
        self.run_ready();
    }

    /// Poll woken tasks until the run queue is empty (siblings woken by a
    /// shared-conn route run in this same turn). A budget bounds a self-waking
    /// task; leftovers make `next_timeout_ms` report 0 so the caller comes back.
    fn run_ready(&mut self) {
        let mut budget = 4 * self.executor.active_count() + 16;
        while budget > 0 {
            let Some(id) = self.executor.pop_ready() else { break };
            self.advance(id);
            budget -= 1;
        }
    }

    pub(crate) fn abort_all(&mut self, status: c_int) {
        for id in self.executor.ids() {
            self.executor.deliver(id, Some(status));
        }
        self.state.tcp_pool.borrow_mut().clear();
        let retired = self.state.udp_pool.borrow_mut().clear();
        drop(retired);
    }

    pub(crate) fn all_poll_fds(&self) -> Vec<(i32, bool)> {
        self.state.rt.reactor().interests()
    }

    /// Lookups still in flight (spawned, not yet delivered).
    pub(crate) fn active_queries(&self) -> usize {
        self.executor.active_count()
    }

    pub(crate) fn next_timeout_ms(&self) -> Option<u128> {
        if self.executor.has_ready() {
            return Some(0);
        }
        let now = Instant::now();
        self.state
            .rt
            .reactor()
            .next_deadline()
            .map(|d| d.saturating_duration_since(now).as_millis())
    }

    pub(crate) fn process_channel(
        &mut self,
        read_fds: &mut libc::fd_set,
        write_fds: &mut libc::fd_set,
        skip_timeouts: bool,
    ) {
        self.drive_fd_futures(read_fds, write_fds, skip_timeouts);
    }

    /// Drive explicit fd/event pairs without an `fd_set` (upstream
    /// `ares_process_fds` semantics): `FD_SET` would index out of bounds past
    /// `FD_SETSIZE` on a high custom-socket fd and abort the process.
    pub(crate) fn process_events(
        &mut self,
        events: &[crate::ffi::ares_socket::ares_fd_events_t],
        skip_timeouts: bool,
    ) {
        use crate::ffi::ares_socket::{ARES_FD_EVENT_READ, ARES_FD_EVENT_WRITE};
        let now = Instant::now();
        self.turn(now, skip_timeouts, |fd, writable| {
            let bit = if writable { ARES_FD_EVENT_WRITE } else { ARES_FD_EVENT_READ };
            events.iter().any(|ev| ev.fd == fd && ev.events & bit != 0)
        });
    }

    /// Fire the server-state callback if installed; a stale index is skipped.
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

/// Per-channel recursive lock: completion callbacks fire while it is held, so the
/// same thread must be able to re-enter a channel API.
pub(crate) struct ReentrantMutex {
    state: Mutex<LockState>,
    available: Condvar,
}

struct LockState {
    /// Non-allocating platform thread identity (see `thread_token`).
    owner: Option<usize>,
    depth: usize,
}

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

    pub(crate) fn lock(&self) -> ReentrantGuard<'_> {
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

/// Lock a channel and return the guard plus a mutable view; `None` for NULL.
/// The guard is `'static` because the channel can't be freed while locked
/// (`ares_destroy` joins the event thread first); don't outlive the frame.
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

fn dup_impl(dest: *mut Channel, source: *const ChannelData) -> c_int {
    if dest.is_null() || source.is_null() { return ARES_ENOTINITIALIZED; }
    let lock = unsafe { (*source).lock.clone() };
    let guard = lock.lock();
    let channeldata = unsafe { &*source }.dup_from();
    drop(guard);
    let channel = Box::into_raw(Box::new(channeldata));
    let event_mode = unsafe { (*channel).event_mode };
    if event_mode && !event_thread::start(channel) {
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

/// Stop and join the event thread without holding the lock across the join,
/// abort every query, then free the channel.
fn destroy_impl(channel: *mut ChannelData) {
    if channel.is_null() { return; }
    let Some((guard, data)) = (unsafe { channel_access(channel) }) else { return; };
    let thread = data.event.take();
    drop(guard);
    if let Some(thread) = thread {
        event_thread::stop(thread);
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

/// Build the ares_addr_node chain for ares_get_servers (wrapped in `AresData` so
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
        // An explicit clear is still an explicit sortlist option: reinit must not
        // repopulate it from resolv.conf, and save_options reports it.
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

/// In-flight executor tasks. One host lookup is one task even when it races
/// A/AAAA internally (upstream counts per-family query objects — a minor gap).
///
/// # Safety
/// `channel` must be null or a valid channel handle returned by
/// `ares_init`/`ares_init_options` and not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn ares_queue_active_queries(channel: *const ChannelData) -> libc::size_t {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return 0; };
    channeldata.active_queries()
}

/// Store the pending-write callback (copied by ares_dup) but never fire it:
/// writes are awaited inline, so this is upstream API parity only.
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

/// Everything is written inline, so there is nothing to drain; accepting NULL
/// matches the upstream contract.
#[no_mangle]
pub extern "C" fn ares_process_pending_write(channel: Channel) {
    if channel.is_null() {}
}
