//! The reactor driver: ares_process/ares_process_fd and the socket/server
//! state notification callbacks it fires.

use super::*;


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
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };

    // Phase 1: I/O (write + read) processing.
    // The receive buffer is taken out of the channel for the duration of the
    // phase so a reply slice borrowed from it can coexist with the &mut
    // ChannelData the callback dispatch needs. (A reentrant ares_process from
    // a user callback simply allocates a fresh buffer.)
    let mut readbuf = std::mem::take(&mut channeldata.readbuf);
    if readbuf.len() < 65_535 {
        readbuf.resize(65_535, 0);
    }
    let mut tasks = std::mem::take(&mut channeldata.ares.tasks);
    for task in &mut tasks {
        if task.status == Status::Completed { continue; }
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), write_fds) } {
            match channeldata.ares.write_impl(task) {
                WriteResult::Ok => {},
                WriteResult::Failed => {
                    task.userdata.callback.run(Err(ARES_ECONNREFUSED), &task.userdata, channeldata);
                },
                WriteResult::TryAgain => {
                    // Leave in Writing status for next select cycle
                },
            }
        }
        if task.status == Status::Completed { continue; }
        let fd = task.sock.as_raw_fd();
        let fd_readable = unsafe { libc::FD_ISSET(fd, read_fds) };
        let has_tcp_buffered = task.sock.is_tcp() && channeldata.tcp_recv_buffers.get(&fd).is_some_and(|b| b.len() >= 2);
        if fd_readable || has_tcp_buffered {
            // For TCP shared connections: use per-fd recv buffer with framing
            let read_result = if task.sock.is_tcp() {
                let msg_data: Option<Vec<u8>> = {
                    let rbuf = channeldata.tcp_recv_buffers.entry(fd).or_default();
                    if fd_readable {
                        let mut tmp = [0u8; 65535];
                        match task.sock.recv(&mut tmp) {
                            Ok((n, _)) if n > 0 => rbuf.extend_from_slice(&tmp[..n]),
                            _ => {},
                        }
                    }
                    let msg = extract_tcp_frame(rbuf);
                    if msg.is_some() {
                        task.status = Status::Completed;
                    }
                    msg
                };
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
                        task.userdata.callback.run(Err(ARES_ECONNREFUSED), &task.userdata, channeldata);
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
                // Check DNS rcode for server failover (rcode in lower 4 bits of byte 3)
                let summary = summarize(buf, 0);
                let is_server_error = matches!(summary.rcode, 2 | 4 | 5); // SERVFAIL, NOTIMP, REFUSED
                let nservers = channeldata.server_health.len();
                let is_addrinfo = matches!(task.userdata.callback, Callback::AddrInfo(_));
                let is_hostbyname = matches!(task.userdata.callback, Callback::HostByName(_));

                if is_server_error {
                    // Invoke server_state_callback with failure (skip for callbacks that manage their own)
                    if !is_addrinfo && !is_hostbyname {
                        invoke_server_state_callback(channeldata, task.userdata.server_index, false, task.sock.is_tcp());
                    }
                    if nservers > 1 && !is_addrinfo && !is_hostbyname {
                        let si = task.userdata.server_index;
                        channeldata.server_health.record_failure(si);
                        let max_attempts = nservers * channeldata.ares.config.options.attempts as usize;
                        if (si + 1) < max_attempts {
                            let next_server = channeldata.server_health.pick_next();
                            let new_ffidata = FFIData {
                                callback: task.userdata.callback.clone_for_retry(),
                                arg: task.userdata.arg,
                                family: task.userdata.family,
                                expected_record_type: task.userdata.expected_record_type,
                                ip: task.userdata.ip,
                                nameinfo_flags: task.userdata.nameinfo_flags,
                                port: task.userdata.port,
                                scope_id: task.userdata.scope_id,
                                server_index: next_server,
                                timeouts: task.userdata.timeouts,
                            };
                            let is_tcp = task.sock.is_tcp();
                            let payload: &[u8] = if is_tcp && task.writebuf.len() > 2 {
                                &task.writebuf[2..]
                            } else {
                                &task.writebuf[..]
                            };
                            let issued = channeldata.ares.enqueue(BytesMut::from(payload), SocketSource::fresh(is_tcp), next_server, new_ffidata).is_ok();
                            if issued {
                                let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                                let sock_type = if is_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                                invoke_sock_callbacks(channeldata, fd, sock_type);
                            } else {
                                // Retry socket couldn't be created — deliver the error.
                                task.userdata.callback.run(Err(ARES_ECONNREFUSED), &task.userdata, channeldata);
                            }
                            task.status = Status::Completed;
                            continue;
                        }
                    }
                } else {
                    // Success response - invoke server_state_callback with success, reset failures
                    if !is_addrinfo {
                        invoke_server_state_callback(channeldata, task.userdata.server_index, true, task.sock.is_tcp());
                    }
                    channeldata.server_health.record_success(task.userdata.server_index);
                }
                // Check TC (truncation) flag — retry over TCP if truncated and currently UDP
                if summary.truncated && !task.sock.is_tcp() && !is_addrinfo && !is_hostbyname {
                    let si = task.userdata.server_index;
                    let new_ffidata = FFIData {
                        callback: task.userdata.callback.clone_for_retry(),
                        arg: task.userdata.arg,
                        family: task.userdata.family,
                        expected_record_type: task.userdata.expected_record_type,
                        ip: task.userdata.ip,
                        nameinfo_flags: task.userdata.nameinfo_flags,
                        port: task.userdata.port,
                        scope_id: task.userdata.scope_id,
                        server_index: si,
                        timeouts: task.userdata.timeouts,
                    };
                    if channeldata.ares.enqueue(task.writebuf.clone(), SocketSource::Tcp, si, new_ffidata).is_ok() {
                        let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                        invoke_sock_callbacks(channeldata, fd, libc::SOCK_STREAM);
                    } else {
                        task.userdata.callback.run(Err(ARES_ECONNREFUSED), &task.userdata, channeldata);
                    }
                    task.status = Status::Completed;
                    continue;
                }
                // Cache successful responses for AresCallbackDnsRec and AresSearchCallbackDnsRec
                let is_dnsrec = match &task.userdata.callback {
                    Callback::AresCallbackDnsRec(_) => true,
                    Callback::Search(lookup) => matches!(lookup.borrow().delivery, SearchDelivery::DnsRec { .. }),
                    _ => false,
                };
                if channeldata.query_cache_max_ttl > 0 && is_dnsrec {
                        // Extract query name and type from the response buffer
                        if let Ok(parsed) = ParsedResponse::from_buf(buf) {
                            let qname = parsed.query.name.join(".");
                            let qtype = parsed.query.qtype;
                            if summary.ancount > 0 {
                                // Find minimum TTL from answers
                                let min_ttl = parsed.answers.iter().map(|a| a.ttl).min().unwrap_or(0);
                                let cache_ttl = std::cmp::min(min_ttl, channeldata.query_cache_max_ttl);
                                if cache_ttl > 0 {
                                    let expires = Instant::now() + Duration::from_secs(cache_ttl as u64);
                                    let cache_key = (qname, qtype);
                                    channeldata.query_cache.insert(cache_key, (buf.to_vec(), expires));
                                }
                            }
                        }
                    }
                (task.userdata.callback).run(Ok(buf), &task.userdata, channeldata);
            }
        }
    }
    channeldata.readbuf = readbuf;
    // Merge: new tasks from read/write callbacks + processed tasks
    let mut new_tasks = std::mem::take(&mut channeldata.ares.tasks);
    tasks.append(&mut new_tasks);
    channeldata.ares.tasks = tasks;

    // Phase 2: Timeout handling
    let max_tries = channeldata.ares.config.options.attempts;
    let mut tasks = std::mem::take(&mut channeldata.ares.tasks);
    for task in &mut tasks {
        if task.is_expired() && task.status != Status::Completed {
            task.tries_remaining += 1;
            // Invoke server_state_callback with failure for timeout
            invoke_server_state_callback(channeldata, task.userdata.server_index, false, task.sock.is_tcp());
            if task.tries_remaining < max_tries {
                let nservers = channeldata.server_health.len();
                let is_tcp = task.sock.is_tcp();
                let payload = if is_tcp && task.writebuf.len() > 2 {
                    BytesMut::from(&task.writebuf[2..])
                } else {
                    task.writebuf.clone()
                };
                // Pick next server on timeout when there are multiple servers
                let si = if nservers > 1 {
                    channeldata.server_health.record_failure(task.userdata.server_index);
                    channeldata.server_health.pick_next()
                } else {
                    task.userdata.server_index
                };
                let new_ffidata = FFIData {
                    callback: task.userdata.callback.clone_for_retry(),
                    arg: task.userdata.arg,
                    family: task.userdata.family,
                    expected_record_type: task.userdata.expected_record_type,
                    ip: task.userdata.ip,
                    nameinfo_flags: task.userdata.nameinfo_flags,
                    port: task.userdata.port,
                    scope_id: task.userdata.scope_id,
                    server_index: si,
                    timeouts: task.userdata.timeouts + 1,
                };
                task.status = Status::Completed;
                // Create new task via ares methods
                let issued = channeldata.ares.enqueue(payload, SocketSource::fresh(is_tcp), si, new_ffidata).is_ok();
                if issued {
                    // Set tries_remaining on the new task
                    if let Some(new_task) = channeldata.ares.tasks.last_mut() {
                        new_task.tries_remaining = task.tries_remaining;
                    }
                    let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                    let sock_type = if is_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                    invoke_sock_callbacks(channeldata, fd, sock_type);
                } else {
                    // Retry socket couldn't be created — deliver the error.
                    task.userdata.callback.run(Err(ARES_ECONNREFUSED), &task.userdata, channeldata);
                }
            } else {
                task.userdata.callback.run(Err(ARES_ETIMEOUT), &task.userdata, channeldata);
                task.status = Status::Completed;
            }
        }
    }
    // Merge back: new tasks from callbacks/retries + processed tasks
    let mut new_tasks = std::mem::take(&mut channeldata.ares.tasks);
    tasks.append(&mut new_tasks);
    channeldata.ares.tasks = tasks;

    // Phase 3: Cleanup completed tasks
    channeldata.ares.tasks.retain(|task| task.status != Status::Completed);

    // Phase 4: Cleanup stale connection pool entries
    if channeldata.udp_max_queries > 0 {
        let limit = channeldata.udp_max_queries;
        channeldata.udp_connections.retain(|(_, rc, count)| {
            *count < limit || std::rc::Rc::strong_count(rc) > 1
        });
    }
    // Clean up TCP connections where no tasks reference the socket anymore
    channeldata.tcp_connections.retain(|(_, rc)| {
        std::rc::Rc::strong_count(rc) > 1
    });
}

/// Call socket create + configure callbacks. Returns false if either callback fails.
pub(crate) unsafe fn invoke_sock_callbacks(channeldata: &ChannelData, fd: c_int, sock_type: c_int) -> bool {
    if let Some(cb) = channeldata.sock_create_callback {
        let ret = cb(fd, sock_type, channeldata.sock_create_callback_arg);
        if ret != 0 { return false; }
    }
    if let Some(cb) = channeldata.sock_config_callback {
        let ret = cb(fd, sock_type, channeldata.sock_config_callback_arg);
        if ret != 0 { return false; }
    }
    true
}

pub(crate) unsafe fn invoke_server_state_callback(channeldata: &ChannelData, server_index: usize, success: bool, is_tcp: bool) {
    if let Some(cb) = channeldata.server_state_callback {
        let server_str = if let Some((ip, port)) = channeldata.ares.config.nameservers.get(server_index) {
            let port_val = port.unwrap_or(if is_tcp { channeldata.ares.default_tcp_port } else { channeldata.ares.default_udp_port });
            match ip {
                IpAddr::V4(v4) => format!("{}:{}", v4, port_val),
                IpAddr::V6(v6) => format!("[{}]:{}", v6, port_val),
            }
        } else {
            return;
        };
        let c_server_str = CString::new(server_str).unwrap_or_default();
        let success_int: c_int = if success { 1 } else { 0 };
        let flags: c_int = if is_tcp { 1 << 1 } else { 1 << 0 }; // ARES_SERV_STATE_TCP=2, UDP=1
        cb(c_server_str.as_ptr(), success_int, flags, channeldata.server_state_callback_arg);
    }
}
