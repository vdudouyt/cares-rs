//! The reactor driver: ares_process/ares_process_fd and the socket/server
//! state notification callbacks it fires.

use super::*;
use crate::core::channel::{tcp_payload, ChannelState};
use crate::core::ares::Task;
use crate::core::launch::{read_tcp_frame, reissue, timeout_step};

/// Copy the core-owned per-task data (state machine, family/record-type,
/// queried ip) from a settled task onto the retry task `reissue` just pushed,
/// stamping the accumulated timeout count — so the eventual reply is
/// attributed just like the original send. (`enqueue` defaults these fields.)
fn carry_over(state: &mut ChannelState<FFIData>, old: &Task<FFIData>, timeouts: i32) {
    if let Some(t) = state.ares.tasks.last_mut() {
        t.machine = old.machine.clone();
        t.family = old.family;
        t.rtype = old.rtype;
        t.queried_ip = old.queried_ip;
        t.timeouts = timeouts;
    }
}



#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process_fd(channel: Channel, read_fd: c_int, write_fd: c_int) {
    if channel.is_null() { return; }
    unsafe {
        let mut read_fds: libc::fd_set = std::mem::zeroed();
        let mut write_fds: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut read_fds);
        libc::FD_ZERO(&mut write_fds);
        if read_fd != ARES_SOCKET_BAD {
            libc::FD_SET(read_fd, &mut read_fds);
        }
        if write_fd != ARES_SOCKET_BAD {
            libc::FD_SET(write_fd, &mut write_fds);
        }
        ares_process(channel, &mut read_fds, &mut write_fds);
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    process_channel(channeldata, read_fds, write_fds);
}

/// The 4-phase reactor loop (I/O, timeouts, task cleanup, pool cleanup) as a
/// safe fn — the only unsafe left inside is the FD_ISSET macro and the
/// C-callback invokers it drives; every decision is a core verdict or a
/// core call.
pub(crate) fn process_channel(channeldata: &mut ChannelData, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    // Phase 1: I/O (write + read) processing.
    // The receive buffer is taken out of the channel for the duration of the
    // phase so a reply slice borrowed from it can coexist with the &mut
    // ChannelData the callback dispatch needs. (A reentrant ares_process from
    // a user callback simply allocates a fresh buffer.)
    let mut readbuf = std::mem::take(&mut channeldata.state.readbuf);
    if readbuf.len() < 65_535 {
        readbuf.resize(65_535, 0);
    }
    let mut tasks = std::mem::take(&mut channeldata.state.ares.tasks);
    for task in &mut tasks {
        if task.status == Status::Completed { continue; }
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), write_fds) } {
            match channeldata.state.ares.write_impl(task) {
                WriteResult::Ok => {},
                WriteResult::Failed => {
                    task.userdata.callback.run(Err(ARES_ECONNREFUSED), task, channeldata);
                },
                WriteResult::TryAgain => {
                    // Leave in Writing status for next select cycle
                },
            }
        }
        if task.status == Status::Completed { continue; }
        let fd = task.sock.as_raw_fd();
        let fd_readable = unsafe { libc::FD_ISSET(fd, read_fds) };
        let has_tcp_buffered = task.sock.is_tcp() && channeldata.state.tcp_recv_buffers.get(&fd).is_some_and(|b| b.len() >= 2);
        if fd_readable || has_tcp_buffered {
            // For TCP shared connections: use per-fd recv buffer with framing
            let read_result = if task.sock.is_tcp() {
                let msg_data = read_tcp_frame(&mut channeldata.state.tcp_recv_buffers, task, fd_readable);
                if let Some(ref msg) = msg_data {
                    readbuf[..msg.len()].copy_from_slice(msg);
                    Some((0, msg.len()))
                } else { None }
            } else {
                // UDP: use existing read_impl
                match Ares::read_impl(task, &mut readbuf) {
                    Ok(v) => v,
                    Err(()) => {
                        // recv failed (e.g. ECONNREFUSED) — fire callback
                        task.userdata.callback.run(Err(ARES_ECONNREFUSED), task, channeldata);
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
                    channeldata.state.ares.config.options.attempts,
                    &mut channeldata.state.server_health,
                );
                for action in actions {
                    match action {
                        ReactorAction::NotifyServerState { server, ok, tcp } =>
                            invoke_server_state_callback(channeldata, server, ok, tcp),
                    }
                }
                match verdict {
                    TaskVerdict::RetryNextServer { server: next_server } => {
                        let is_tcp = task.sock.is_tcp();
                        // Strip the TCP length prefix; enqueue re-frames for the new transport.
                        let payload = BytesMut::from(tcp_payload(&task.writebuf, is_tcp));
                        if reissue(&mut channeldata.state, payload, SocketSource::fresh(is_tcp), next_server, task.userdata, 0) {
                            carry_over(&mut channeldata.state, task, task.timeouts);
                        } else {
                            // Retry socket couldn't be created — deliver the error.
                            task.userdata.callback.run(Err(ARES_ECONNREFUSED), task, channeldata);
                        }
                        task.status = Status::Completed;
                        continue;
                    }
                    TaskVerdict::RetryTcp => {
                        let si = task.server_index;
                        if reissue(&mut channeldata.state, task.writebuf.clone(), SocketSource::Tcp, si, task.userdata, 0) {
                            carry_over(&mut channeldata.state, task, task.timeouts);
                        } else {
                            task.userdata.callback.run(Err(ARES_ECONNREFUSED), task, channeldata);
                        }
                        task.status = Status::Completed;
                        continue;
                    }
                    TaskVerdict::Deliver => {}
                }
                // Cache successful responses for AresCallbackDnsRec and AresSearchCallbackDnsRec
                if task.userdata.callback.wants_dnsrec_cache() {
                    channeldata.state.cache_dnsrec_reply(buf, Instant::now());
                }
                (task.userdata.callback).run(Ok(buf), task, channeldata);
            }
        }
    }
    channeldata.state.readbuf = readbuf;
    // Merge: new tasks from read/write callbacks + processed tasks
    let mut new_tasks = std::mem::take(&mut channeldata.state.ares.tasks);
    tasks.append(&mut new_tasks);
    channeldata.state.ares.tasks = tasks;

    // Phase 2: Timeout handling
    let max_tries = channeldata.state.ares.config.options.attempts;
    let mut tasks = std::mem::take(&mut channeldata.state.ares.tasks);
    for task in &mut tasks {
        if task.is_expired() && task.status != Status::Completed {
            // Invoke server_state_callback with failure for timeout
            invoke_server_state_callback(channeldata, task.server_index, false, task.sock.is_tcp());
            let timeout_verdict = timeout_step(task, max_tries, task.server_index, &mut channeldata.state.server_health);
            if let TimeoutVerdict::Retry { server: si } = timeout_verdict {
                let is_tcp = task.sock.is_tcp();
                let payload = BytesMut::from(tcp_payload(&task.writebuf, is_tcp));
                let new_timeouts = task.timeouts + 1;
                task.status = Status::Completed;
                // The retry task inherits this task's expiry count.
                if reissue(&mut channeldata.state, payload, SocketSource::fresh(is_tcp), si, task.userdata, task.tries_remaining) {
                    carry_over(&mut channeldata.state, task, new_timeouts);
                } else {
                    // Retry socket couldn't be created — deliver the error.
                    task.userdata.callback.run(Err(ARES_ECONNREFUSED), task, channeldata);
                }
            } else {
                task.userdata.callback.run(Err(ARES_ETIMEOUT), task, channeldata);
                task.status = Status::Completed;
            }
        }
    }
    // Merge back: new tasks from callbacks/retries + processed tasks
    let mut new_tasks = std::mem::take(&mut channeldata.state.ares.tasks);
    tasks.append(&mut new_tasks);
    channeldata.state.ares.tasks = tasks;

    // Phase 3: Cleanup completed tasks
    channeldata.state.ares.tasks.retain(|task| task.status != Status::Completed);

    // Phase 4: Cleanup stale connection pool entries
    channeldata.state.retain_pools();
}

pub(crate) fn invoke_server_state_callback(channeldata: &ChannelData, server_index: usize, success: bool, is_tcp: bool) {
    if let Some(cb) = channeldata.server_state_callback {
        let Some(server_str) = channeldata.state.server_state_string(server_index, is_tcp) else {
            return;
        };
        let c_server_str = CString::new(server_str).unwrap_or_default();
        let success_int: c_int = if success { 1 } else { 0 };
        let flags: c_int = if is_tcp { 1 << 1 } else { 1 << 0 }; // ARES_SERV_STATE_TCP=2, UDP=1
        unsafe { cb(c_server_str.as_ptr(), success_int, flags, channeldata.server_state_callback_arg) };
    }
}
