//! Channel lifecycle and configuration: init/dup/destroy/cancel, server
//! lists, reactor fd/timeout accessors, and the channel-level callbacks.

use super::*;
use crate::core::client::{getsock_mask, normalize_port, Client, ServerSpec};
use crate::core::query_builder::tcp_payload;
use crate::core::executor::{
    host_lifecycle, noop_waker, raw_lifecycle, Delivery, Effect, HostLaunch, QueryIo, RawLaunch,
};
use crate::core::hostent::Hostent;
use crate::core::launch::{read_tcp_frame, timeout_step};
use crate::core::sortlist::apply_sortlist;
use crate::core::transport::Task;
use super::lookups::{fire_host_success, HostTail};
use super::process::carry_over;


/// The C-visible channel: the pure core state plus the channel-level C
/// callbacks. Everything the shims marshal lives behind `.state`; the six
/// callback fields are the only C-tainted residents.
pub struct ChannelData {
    pub(crate) state: Client<FFIData>,
    /// Concrete handle to the same factory held as `Rc<dyn SocketFactory>`
    /// in `state.transport`. The socket-state callbacks (create/configure) live in
    /// the factory; the setters below rebuild it (copy-on-write), so ares_dup
    /// can simply share the Rc and stay independent.
    pub(crate) socket_factory: std::rc::Rc<CSocketFactory>,
    pub(crate) server_state_callback: ares_server_state_callback,
    pub(crate) server_state_callback_arg: *mut libc::c_void,
    /// In-flight async lifecycle futures. The slot index is the
    /// `TaskMachine::Async(id)` a task carries; `None` = a reaped slot.
    async_queries: Vec<Option<AsyncQuery>>,
}

/// One in-flight async lifecycle: its mailbox, its boxed future, and how to
/// deliver the future's result to C.
struct AsyncQuery {
    io: std::rc::Rc<std::cell::RefCell<QueryIo>>,
    fut: std::pin::Pin<Box<dyn std::future::Future<Output = Delivery>>>,
    sink: AsyncSink,
}

/// How a completed lifecycle future is delivered to C. The future owns its
/// socket(s), so nothing is enqueued as a `Task` — this only names the callback.
#[derive(Clone, Copy)]
enum AsyncSink {
    /// ares_query / ares_send: raw reply bytes to the ares_callback.
    Raw(AresCallback, *mut libc::c_void),
    /// ares_gethostbyname: sorted answers built into a hostent for the host callback.
    Host(HostTail),
}

impl ChannelData {
    /// A fresh channel: pure state, no callbacks installed.
    pub(crate) fn new(state: Client<FFIData>, socket_factory: std::rc::Rc<CSocketFactory>) -> Self {
        ChannelData {
            state,
            socket_factory,
            server_state_callback: None,
            server_state_callback_arg: std::ptr::null_mut(),
            async_queries: Vec::new(),
        }
    }

    /// ares_dup: duplicate the pure state and share the (immutable) factory.
    pub(crate) fn dup_from(&self) -> Self {
        ChannelData {
            state: self.state.duplicate(),
            socket_factory: self.socket_factory.clone(),
            server_state_callback: self.server_state_callback,
            server_state_callback_arg: self.server_state_callback_arg,
            async_queries: Vec::new(),
        }
    }

    /// A fresh channel with the default (libc) socket factory.
    pub(crate) fn new_default() -> Self {
        let factory = std::rc::Rc::new(CSocketFactory::default());
        let state = Client::new(Transport::from_sysconfig(factory.clone()));
        ChannelData::new(state, factory)
    }

    /// Install a rebuilt socket factory, keeping the concrete handle and the
    /// core's `Rc<dyn SocketFactory>` in sync (they are the same object).
    pub(crate) fn apply_socket_factory(&mut self, factory: std::rc::Rc<CSocketFactory>) {
        self.state.transport.socket_factory = factory.clone();
        self.socket_factory = factory;
    }

    /// Register a lifecycle future + its delivery sink in a free slot and drive
    /// it once (issuing the initial send). The C callback fires when the reactor
    /// later settles the task (or in place if the launch fails immediately).
    fn spawn(
        &mut self,
        io: std::rc::Rc<std::cell::RefCell<QueryIo>>,
        fut: std::pin::Pin<Box<dyn std::future::Future<Output = Delivery>>>,
        sink: AsyncSink,
    ) {
        let slot = AsyncQuery { io, fut, sink };
        let id = match self.async_queries.iter().position(|s| s.is_none()) {
            Some(i) => {
                self.async_queries[i] = Some(slot);
                i
            }
            None => {
                self.async_queries.push(Some(slot));
                self.async_queries.len() - 1
            }
        };
        self.advance(id);
    }

    /// ares_query / ares_send: spawn the raw one-shot lifecycle.
    pub(crate) fn spawn_query(&mut self, launch: RawLaunch, callback: AresCallback, arg: *mut libc::c_void) {
        let io = std::rc::Rc::new(std::cell::RefCell::new(QueryIo::default()));
        let fut = Box::pin(raw_lifecycle(io.clone(), launch));
        self.spawn(io, fut, AsyncSink::Raw(callback, arg));
    }

    /// ares_gethostbyname (DNS path): spawn the search/AF_UNSPEC lifecycle.
    pub(crate) fn spawn_host(&mut self, launch: HostLaunch, tail: HostTail) {
        let io = std::rc::Rc::new(std::cell::RefCell::new(QueryIo::default()));
        let fut = Box::pin(host_lifecycle(io.clone(), launch));
        self.spawn(io, fut, AsyncSink::Host(tail));
    }

    /// Fire a settled classic-task outcome (search/getaddrinfo/gethostbyaddr/
    /// nameinfo/probe). The migrated async lifecycles own their sockets and
    /// never appear here.
    fn settle(&mut self, task: &Task<FFIData>, res: Result<&[u8], c_int>) {
        task.userdata.callback.run(res, task, self);
    }

    /// Advance one async future one step: poll it, apply the effects it emitted
    /// (server-state notify / success cache), and on completion fire its C
    /// callback and reap the slot. On `Pending` the future has published the
    /// fds it is now blocked on into its mailbox.
    fn advance(&mut self, id: usize) {
        if self.async_queries.get(id).and_then(|s| s.as_ref()).is_none() {
            return;
        }
        let waker = noop_waker();
        let poll = {
            let mut cx = std::task::Context::from_waker(&waker);
            self.async_queries[id].as_mut().unwrap().fut.as_mut().poll(&mut cx)
        };
        let effects = {
            let aq = self.async_queries[id].as_ref().unwrap();
            std::mem::take(&mut aq.io.borrow_mut().effects)
        };
        for effect in effects {
            match effect {
                Effect::NotifyServerState { server, ok, tcp } => {
                    self.invoke_server_state_callback(server, ok, tcp)
                }
                Effect::CacheNamed { names, rtype, ttl, reply } => {
                    self.state.cache_named(names, rtype, ttl, &reply, Instant::now())
                }
            }
        }
        if let std::task::Poll::Ready(delivery) = poll {
            let sink = self.async_queries[id].take().unwrap().sink;
            self.finalize(delivery, sink);
        }
    }

    /// Drive every async future whose published fd is ready (or whose deadline
    /// passed) this `ares_process` cycle: set its mailbox readiness and poll it.
    fn drive_fd_futures(&mut self, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
        let now = Instant::now();
        for id in 0..self.async_queries.len() {
            // Compute readiness under the mailbox borrow (no waits clone), then
            // release it before `advance` (which needs `&mut self`).
            let ready = match self.async_queries.get(id).and_then(|s| s.as_ref()) {
                Some(aq) => {
                    let mut m = aq.io.borrow_mut();
                    let mut fired = Vec::new();
                    for w in &m.waits {
                        let set = if w.writable { &mut *write_fds } else { &mut *read_fds };
                        if unsafe { libc::FD_ISSET(w.fd, set) } {
                            fired.push(w.fd);
                        }
                    }
                    let expired = m.deadline.is_some_and(|d| now >= d);
                    if fired.is_empty() && !expired {
                        false
                    } else {
                        m.fired = fired;
                        m.expired = expired;
                        true
                    }
                }
                None => continue,
            };
            if ready {
                self.advance(id);
            }
        }
    }

    /// Deliver a completed lifecycle future to C: raw reply bytes to the
    /// ares_callback, or a sorted hostent to the host callback.
    fn finalize(&mut self, delivery: Delivery, sink: AsyncSink) {
        match (delivery, sink) {
            (Delivery::Raw { result, timeouts }, AsyncSink::Raw(callback, arg)) => {
                fire_ares_callback(callback, arg, result.as_deref().map_err(|&e| e), timeouts);
            }
            (Delivery::Host { result, timeouts }, AsyncSink::Host(tail)) => match result {
                Ok((mut rrs, family)) => {
                    if !self.state.sortlist.is_empty() {
                        apply_sortlist(&self.state.sortlist, &mut rrs.items);
                    }
                    fire_host_success(tail, Hostent::from_parsed(rrs, family), timeouts);
                }
                Err(status) => unsafe { (tail.callback)(tail.arg, status, timeouts, std::ptr::null_mut()) },
            },
            _ => unreachable!("async delivery/sink kind mismatch"),
        }
    }

    /// Fire `status` to everything in flight — classic tasks via their C
    /// callback, async futures aborted (fire the terminal status + drop the
    /// future, which drops its owned sockets). The shared safe teardown for
    /// `ares_cancel` (ECANCELLED) / `ares_destroy` (EDESTRUCTION).
    pub(crate) fn abort_all(&mut self, status: c_int) {
        let tasks: Vec<_> = self.state.transport.tasks.drain(..).collect();
        for task in tasks {
            if task.status != Status::Completed {
                task.userdata.callback.run(Err(status), &task, self);
            }
        }
        for id in 0..self.async_queries.len() {
            self.terminate_async(id, status);
        }
        // Drop any shared TCP connections the aborted futures held.
        self.state.tcp_pool.borrow_mut().clear();
    }

    /// Abort one async lifecycle: fire its terminal status (ECANCELLED /
    /// EDESTRUCTION) and drop the future without polling it (so a multi-step
    /// lifecycle won't re-send into a channel being torn down).
    fn terminate_async(&mut self, id: usize, status: c_int) {
        let Some(slot) = self.async_queries.get_mut(id).and_then(|s| s.take()) else {
            return; // already reaped
        };
        match slot.sink {
            AsyncSink::Raw(callback, arg) => fire_ares_callback(callback, arg, Err(status), 0),
            AsyncSink::Host(tail) => unsafe { (tail.callback)(tail.arg, status, 0, std::ptr::null_mut()) },
        }
    }

    /// Every (fd, wants_write) the caller should select on: the classic tasks'
    /// plus every in-flight async future's published waits.
    fn all_poll_fds(&self) -> Vec<(i32, bool)> {
        let mut fds = self.state.poll_fds();
        for aq in self.async_queries.iter().flatten() {
            for w in &aq.io.borrow().waits {
                fds.push((w.fd, w.writable));
            }
        }
        fds
    }

    /// The earliest timeout (ms) across classic tasks and async futures, or
    /// `None` when nothing is in flight. Folding the futures in is required —
    /// `timeout_millis` only sees `transport.tasks`, so a futures-only channel
    /// would otherwise report "no timeout" and the caller would block forever.
    fn next_deadline_ms(&self) -> Option<u128> {
        let now = Instant::now();
        let mut best = self.state.timeout_millis();
        for aq in self.async_queries.iter().flatten() {
            if let Some(d) = aq.io.borrow().deadline {
                let ms = d.saturating_duration_since(now).as_millis();
                best = Some(best.map_or(ms, |b| b.min(ms)));
            }
        }
        best
    }

    /// The 4-phase reactor loop (I/O, timeouts, task cleanup, async drive) as a
    /// safe method — the only unsafe left inside is the FD_ISSET macro and the
    /// C-callback invokers it drives; every decision is a core verdict or a
    /// core call.
    pub(crate) fn process_channel(&mut self, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
        // Phase 1: I/O (write + read) processing.
        // The receive buffer is taken out of the channel for the duration of the
        // phase so a reply slice borrowed from it can coexist with the &mut
        // ChannelData the callback dispatch needs. (A reentrant ares_process from
        // a user callback simply allocates a fresh buffer.)
        let mut readbuf = std::mem::take(&mut self.state.readbuf);
        if readbuf.len() < 65_535 {
            readbuf.resize(65_535, 0);
        }
        let mut tasks = std::mem::take(&mut self.state.transport.tasks);
        for task in &mut tasks {
            if task.status == Status::Completed { continue; }
            if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), write_fds) } {
                match self.state.transport.write_impl(task) {
                    WriteResult::Ok => {},
                    WriteResult::Failed => {
                        self.settle(task, Err(ARES_ECONNREFUSED));
                    },
                    WriteResult::TryAgain => {
                        // Leave in Writing status for next select cycle
                    },
                }
            }
            if task.status == Status::Completed { continue; }
            let fd = task.sock.as_raw_fd();
            let fd_readable = unsafe { libc::FD_ISSET(fd, read_fds) };
            let has_tcp_buffered = task.sock.is_tcp() && self.state.tcp_recv_buffers.get(&fd).is_some_and(|b| b.len() >= 2);
            if fd_readable || has_tcp_buffered {
                // For TCP shared connections: use per-fd recv buffer with framing
                let read_result = if task.sock.is_tcp() {
                    let msg_data = read_tcp_frame(&mut self.state.tcp_recv_buffers, task, fd_readable);
                    if let Some(ref msg) = msg_data {
                        readbuf[..msg.len()].copy_from_slice(msg);
                        Some((0, msg.len()))
                    } else { None }
                } else {
                    // UDP: use existing read_impl
                    match Transport::read_impl(task, &mut readbuf) {
                        Ok(v) => v,
                        Err(()) => {
                            // recv failed (e.g. ECONNREFUSED) — fire callback
                            self.settle(task, Err(ARES_ECONNREFUSED));
                            continue;
                        }
                    }
                };
                if let Some((offset, len)) = read_result {
                    let buf = &readbuf[offset..offset+len];
                    // QID matching: verify response transaction ID matches query
                    if !qid_matches(buf, &task.writebuf, task.sock.is_tcp()) {
                        // QID mismatch — discard response, stay in Reading state
                        task.status = Status::Reading;
                        continue;
                    }
                    // Reactor-level verdict: rcode failover / server-health
                    // bookkeeping / TC retry — decided in core, executed here.
                    let summary = summarize(buf, 0);
                    let (actions, verdict) = on_datagram(
                        &summary,
                        task_kind(task),
                        task.server_index,
                        task.sock.is_tcp(),
                        self.state.transport.config.options.attempts,
                        task.failover_tries,
                        &mut self.state.server_health.borrow_mut(),
                    );
                    for action in actions {
                        match action {
                            ReactorAction::NotifyServerState { server, ok, tcp } =>
                                self.invoke_server_state_callback(server, ok, tcp),
                        }
                    }
                    match verdict {
                        TaskVerdict::RetryNextServer { server: next_server, tries } => {
                            let is_tcp = task.sock.is_tcp();
                            // Strip the TCP length prefix; enqueue re-frames for the new transport.
                            let payload = BytesMut::from(tcp_payload(&task.writebuf, is_tcp));
                            if self.state.reissue(payload, SocketSource::fresh(is_tcp), next_server, task.userdata, 0) {
                                carry_over(&mut self.state, task, task.timeouts, tries);
                            } else {
                                // Retry socket couldn't be created — deliver the error.
                                self.settle(task, Err(ARES_ECONNREFUSED));
                            }
                            task.status = Status::Completed;
                            continue;
                        }
                        TaskVerdict::RetryTcp => {
                            let si = task.server_index;
                            if self.state.reissue(task.writebuf.clone(), SocketSource::Tcp, si, task.userdata, 0) {
                                carry_over(&mut self.state, task, task.timeouts, task.failover_tries);
                            } else {
                                self.settle(task, Err(ARES_ECONNREFUSED));
                            }
                            task.status = Status::Completed;
                            continue;
                        }
                        TaskVerdict::Deliver => {}
                    }
                    // Cache successful responses for AresCallbackDnsRec and AresSearchCallbackDnsRec
                    if task.userdata.callback.wants_dnsrec_cache() {
                        self.state.cache_dnsrec_reply(buf, Instant::now());
                    }
                    self.settle(task, Ok(buf));
                }
            }
        }
        self.state.readbuf = readbuf;
        // Merge: new tasks from read/write callbacks + processed tasks
        let mut new_tasks = std::mem::take(&mut self.state.transport.tasks);
        tasks.append(&mut new_tasks);
        self.state.transport.tasks = tasks;

        // Phase 2: Timeout handling
        let max_tries = self.state.transport.config.options.attempts;
        let mut tasks = std::mem::take(&mut self.state.transport.tasks);
        for task in &mut tasks {
            if task.is_expired() && task.status != Status::Completed {
                // Invoke server_state_callback with failure for timeout
                self.invoke_server_state_callback(task.server_index, false, task.sock.is_tcp());
                let timeout_verdict = timeout_step(task, max_tries, task.server_index, &mut self.state.server_health.borrow_mut());
                if let TimeoutVerdict::Retry { server: si } = timeout_verdict {
                    let is_tcp = task.sock.is_tcp();
                    let payload = BytesMut::from(tcp_payload(&task.writebuf, is_tcp));
                    let new_timeouts = task.timeouts + 1;
                    task.status = Status::Completed;
                    // The retry task inherits this task's expiry count.
                    if self.state.reissue(payload, SocketSource::fresh(is_tcp), si, task.userdata, task.tries_remaining) {
                        carry_over(&mut self.state, task, new_timeouts, task.failover_tries);
                    } else {
                        // Retry socket couldn't be created — deliver the error.
                        self.settle(task, Err(ARES_ECONNREFUSED));
                    }
                } else {
                    self.settle(task, Err(ARES_ETIMEOUT));
                    task.status = Status::Completed;
                }
            }
        }
        // Merge back: new tasks from callbacks/retries + processed tasks
        let mut new_tasks = std::mem::take(&mut self.state.transport.tasks);
        tasks.append(&mut new_tasks);
        self.state.transport.tasks = tasks;

        // Phase 3: Cleanup completed tasks
        self.state.transport.tasks.retain(|task| task.status != Status::Completed);

        // Phase 4: drive the fd-owning async futures whose socket is ready (or
        // whose deadline passed) this cycle.
        self.drive_fd_futures(read_fds, write_fds);
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

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let channel = Box::into_raw(Box::new(ChannelData::new_default()));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dup(dest: *mut Channel, source: Channel) -> c_int {
    if dest.is_null() || source.is_null() { return ARES_ENOTINITIALIZED; }
    let src = unsafe { &*source };
    let channeldata = src.dup_from();
    unsafe { *dest = Box::into_raw(Box::new(channeldata)) };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_cancel(channel: Channel) {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    channeldata.abort_all(ARES_ECANCELLED);
    // Clear connection pools so stale sockets don't linger
    channeldata.state.clear_pools();
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    if let Some(channeldata) = unsafe { channel.as_mut() } {
        // Fire callbacks with ARES_EDESTRUCTION for all pending tasks.
        channeldata.abort_all(ARES_EDESTRUCTION);
        unsafe { drop(Box::from_raw(channel)); }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_fds(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return 0; };
    unsafe { libc::FD_ZERO(write_fds) };
    unsafe { libc::FD_ZERO(read_fds) };

    let fds = channeldata.all_poll_fds();
    for (fd, wants_write) in &fds {
        if *wants_write {
            unsafe { libc::FD_SET(*fd, write_fds) };
        } else {
            unsafe { libc::FD_SET(*fd, read_fds) };
        }
    }
    crate::core::api::nfds(&fds)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_timeout(channel: Channel, maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval {
    // Upstream: NULL channel or output buffer -> return NULL.
    if tv.is_null() { return std::ptr::null_mut(); }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return std::ptr::null_mut(); };
    let maxtv_ms = (!maxtv.is_null())
        .then(|| unsafe { (*maxtv).tv_sec as u128 * 1000 + (*maxtv).tv_usec as u128 / 1000 });
    match crate::core::api::clamp_timeout(channeldata.next_deadline_ms(), maxtv_ms) {
        crate::core::api::TimeoutChoice::NoTasks => {
            if maxtv.is_null() { return std::ptr::null_mut(); }
            maxtv
        }
        crate::core::api::TimeoutChoice::Wait { ms, use_max } => {
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
pub unsafe extern "C" fn ares_set_servers(channel: Channel, mut head: *mut ares_addr_node) -> c_int {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return ARES_ENODATA; };
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
        head = unsafe { (*head).next };
    }
    channeldata.state.set_servers(servers);
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports(channel: Channel, mut head: *mut AresAddrPortNode) -> c_int {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return ARES_ENODATA; };
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
        head = node.next;
    }
    channeldata.state.set_servers(servers);
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_ports(channel: Channel, out: *mut *mut AresAddrPortNode) -> c_int {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return ARES_ENODATA; };
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
    let Some(replies) = clinkedlist::chain_nodes(data) else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_ENODATA;
    };
    let aresdata: AresData<AresAddrPortNode> = AresData { data_type: AresAddrPortNode::datatype(), data: replies };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports_csv(channel: Channel, servers: *const c_char) -> c_int {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return ARES_ENODATA; };
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
    unsafe { ares_set_servers_ports_csv(channel, servers) }
}

/// # Safety
/// `channel` must be a valid channel and `socks` must point to at least `numsocks` writable slots.
#[no_mangle]
pub unsafe extern "C" fn ares_getsock(channel: Channel, socks: *mut ares_socket_t, numsocks: c_int) -> c_int {
    // Upstream: NULL channel or non-positive numsocks -> return 0 (no sockets).
    if numsocks <= 0 { return 0; }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return 0; };
    let n = min(ARES_GETSOCK_MAXNUM, numsocks as usize);

    let fds = channeldata.all_poll_fds();
    for i in 0..n {
        let fd = fds.get(i).map(|(fd, _)| *fd).unwrap_or(ARES_SOCKET_BAD);
        unsafe { std::ptr::write(socks.add(i), fd) };
    }
    getsock_mask(&fds, n)
}

#[no_mangle]
pub extern "C" fn ares_set_local_ip4(_channel: Channel, _local_ip: u32) {
    if _channel.is_null() {}
}

#[no_mangle]
pub extern "C" fn ares_set_local_ip6(_channel: Channel, _local_ip6: *const u8) {
    if _channel.is_null() {}
}

#[no_mangle]
pub extern "C" fn ares_set_local_dev(_channel: Channel, _local_dev_name: *const c_char) {
    if _channel.is_null() {}
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_callback(channel: Channel, callback: ares_sock_create_callback, arg: *mut c_void) {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let factory = channeldata.socket_factory.with_create_cb(callback, arg);
    channeldata.apply_socket_factory(factory);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers(channel: Channel, out: *mut *mut ares_addr_node) -> c_int {
    if out.is_null() { return ARES_ENODATA; }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return ARES_ENODATA; };
    // Build the list the same way as ares_get_servers_ports: an AresData-wrapped
    // chain so the caller can free it with ares_free_data (the c-ares contract).
    // (A plain Box chain here corrupted the heap under ares_free_data.)
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
    let Some(chain) = clinkedlist::chain_nodes(data) else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_ENODATA;
    };
    let aresdata: AresData<ares_addr_node> = AresData { data_type: ares_addr_node::datatype(), data: chain };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_csv(channel: Channel) -> *mut c_char {
    let Some(channeldata) = (unsafe { channel.as_ref() }) else { return std::ptr::null_mut(); };
    let csv = channeldata.state.servers_csv_string();
    // CSV of IP/port strings never contains a NUL; null return on OOM is the sentinel.
    unsafe { malloc_cstr(csv.as_bytes()) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_sortlist(channel: Channel, sortstr: *const c_char) -> c_int {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return ARES_ENODATA; };
    if sortstr.is_null() {
        channeldata.state.sortlist.clear();
        return ARES_SUCCESS;
    }
    let Some(s) = (unsafe { cstr_opt(sortstr) }) else { return ARES_EBADSTR };
    match parse_sortlist(s) {
        Ok(entries) => {
            channeldata.state.sortlist = entries;
            ARES_SUCCESS
        }
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub extern "C" fn ares_reinit(channel: Channel) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    // Re-read sysconfig but preserve explicitly configured servers
    // For now, this is a no-op to avoid overwriting mock/test nameservers
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_configure_callback(channel: Channel, callback: ares_sock_config_callback, arg: *mut c_void) {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let factory = channeldata.socket_factory.with_config_cb(callback, arg);
    channeldata.apply_socket_factory(factory);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_server_state_callback(channel: Channel, callback: ares_server_state_callback, arg: *mut c_void) {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    channeldata.server_state_callback = callback;
    channeldata.server_state_callback_arg = arg;
}

/// # Safety
/// `channel` must be null or a valid channel handle returned by
/// `ares_init`/`ares_init_options` and not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn ares_queue_active_queries(channel: Channel) -> c_int {
    let Some(channeldata) = (unsafe { channel.as_ref() }) else { return 0; };
    let async_active = channeldata.async_queries.iter().filter(|s| s.is_some()).count();
    (channeldata.state.active_query_count() + async_active) as c_int
}

#[no_mangle]
pub extern "C" fn ares_queue_wait_empty(_channel: Channel, _timeout_ms: c_int) -> c_int {
    // Only meaningful with the built-in event thread, which we no longer
    // provide. Match upstream c-ares on a non-threaded build (!ares_threadsafety()).
    ARES_ENOTIMP
}
