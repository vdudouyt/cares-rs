//! Transport pooling / socket-option semantics: UDP pool caps, STAYOPEN, shared
//! demux, local binding, socket buffers, state callback, extended socket adapters.

use std::ffi::{c_int, c_uint, c_void, CStr, CString};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::ptr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cares_rs::ares_options::{
    ares_destroy_options, ares_init_options, ares_options, ares_save_options, ARES_FLAG_STAYOPEN,
    ARES_OPT_FLAGS, ARES_OPT_SOCK_RCVBUF, ARES_OPT_SOCK_SNDBUF, ARES_OPT_SOCK_STATE_CB,
    ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES, ARES_OPT_UDP_MAX_QUERIES,
};
use cares_rs::ares_socket::{
    ares_set_socket_functions_ex, AresSocketFunctionsEx, ARES_SOCKET_OPT_RECVBUF_SIZE,
    ARES_SOCKET_OPT_SENDBUF_SIZE,
};
use cares_rs::dns_record::*;
use cares_rs::*;

const ARES_SUCCESS: c_int = 0;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Copy)]
enum ReplyKind {
    A([u8; 4]),
    /// Derive the A address from the first label (`qN` -> 10.0.0.N+1).
    NameA,
}

struct Mini {
    socket: UdpSocket,
    queries: Vec<Vec<u8>>,
    sources: Vec<SocketAddr>,
    reply: ReplyKind,
}

impl Mini {
    fn new(reply: ReplyKind) -> (Self, u16) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP mini server");
        socket.set_nonblocking(true).expect("UDP nonblocking");
        let port = socket.local_addr().expect("local addr").port();
        (
            Self {
                socket,
                queries: Vec::new(),
                sources: Vec::new(),
                reply,
            },
            port,
        )
    }

    fn pump(&mut self) {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = self.socket.recv_from(&mut buf) {
            let request = buf[..n].to_vec();
            let reply = make_reply(&request, self.reply);
            self.queries.push(request);
            self.sources.push(from);
            let _ = self.socket.send_to(&reply, from);
        }
    }
}

fn question_name(request: &[u8]) -> String {
    assert!(request.len() >= 12);
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = request[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        assert!(len & 0xC0 == 0, "compressed question name not supported");
        labels.push(String::from_utf8_lossy(&request[pos..pos + len]).into_owned());
        pos += len;
    }
    labels.join(".")
}

fn make_reply(request: &[u8], kind: ReplyKind) -> Vec<u8> {
    let addr = match kind {
        ReplyKind::A(addr) => addr,
        ReplyKind::NameA => {
            let qname = question_name(request);
            let first = qname.split('.').next().unwrap_or("q0");
            let idx = first
                .strip_prefix('q')
                .and_then(|n| n.parse::<u8>().ok())
                .unwrap_or(0);
            [10, 0, 0, idx.wrapping_add(1)]
        }
    };

    let mut reply = Vec::new();
    reply.extend_from_slice(&request[0..2]);
    reply.extend_from_slice(&[0x81, 0x80]);
    reply.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    reply.extend_from_slice(&request[12..]);
    reply.extend_from_slice(&[0xC0, 0x0C]);
    reply.extend_from_slice(&[0, 1, 0, 1]);
    reply.extend_from_slice(&[0, 0, 0, 60]);
    reply.push(0);
    reply.push(4);
    reply.extend_from_slice(&addr);
    reply
}

#[derive(Default)]
struct RawResult {
    done: bool,
    status: c_int,
    timeouts: c_int,
    data: Vec<u8>,
}

unsafe extern "C" fn raw_cb(
    arg: *mut c_void,
    status: c_int,
    timeouts: c_int,
    buf: *mut u8,
    len: c_int,
) {
    let result = unsafe { &mut *(arg as *mut RawResult) };
    result.done = true;
    result.status = status;
    result.timeouts = timeouts;
    if !buf.is_null() && len > 0 {
        result
            .data
            .extend_from_slice(unsafe { std::slice::from_raw_parts(buf, len as usize) });
    }
}

#[derive(Default)]
struct HostResult {
    done: bool,
    status: c_int,
}

unsafe extern "C" fn host_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    _host: *mut libc::hostent,
) {
    let result = unsafe { &mut *(arg as *mut HostResult) };
    result.done = true;
    result.status = status;
}

#[derive(Default)]
struct CreateCounter {
    created: Vec<(c_int, c_int)>,
    refuse: c_int,
}

unsafe extern "C" fn create_cb(fd: c_int, sock_type: c_int, arg: *mut c_void) -> c_int {
    let counter = unsafe { &mut *(arg as *mut CreateCounter) };
    counter.created.push((fd, sock_type));
    counter.refuse
}

#[derive(Default)]
struct StateEvents {
    events: Vec<(c_int, c_int, c_int)>,
}

extern "C" fn state_cb(data: *mut c_void, fd: c_int, readable: c_int, writable: c_int) {
    let events = unsafe { &mut *(data as *mut StateEvents) };
    events.events.push((fd, readable, writable));
}

fn base_options() -> ares_options {
    ares_options {
        timeout: 2000,
        tries: 1,
        ..ares_options::default()
    }
}

unsafe fn init_channel(options: &ares_options, mask: c_int) -> Channel {
    let mut channel: Channel = ptr::null_mut();
    let rc = unsafe { ares_init_options(&mut channel, options, mask) };
    assert_eq!(rc, ARES_SUCCESS, "ares_init_options");
    assert!(!channel.is_null());
    channel
}

unsafe fn use_server(channel: Channel, port: u16) {
    let csv = CString::new(format!("127.0.0.1:{port}")).unwrap();
    assert_eq!(
        unsafe { ares_set_servers_csv(channel, csv.as_ptr()) },
        ARES_SUCCESS
    );
}

fn pump_channel(channel: Channel) {
    let mut socks = [ARES_SOCKET_BAD; ARES_GETSOCK_MAXNUM];
    let bitmask =
        unsafe { ares_getsock(channel, socks.as_mut_ptr(), ARES_GETSOCK_MAXNUM as c_int) };
    if bitmask == 0 {
        unsafe { ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD) };
    }
    for &sock in socks.iter().filter(|&&sock| sock != ARES_SOCKET_BAD) {
        unsafe { ares_process_fd(channel, sock, sock) };
    }
}

fn drive(channel: Channel, mini: &mut Mini, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() && Instant::now() < deadline {
        mini.pump();
        pump_channel(channel);
        std::thread::sleep(Duration::from_millis(1));
    }
    mini.pump();
    pump_channel(channel);
}

unsafe fn run_query(channel: Channel, name: &CStr, mini: &mut Mini) -> RawResult {
    let mut result = RawResult::default();
    unsafe {
        ares_query(
            channel,
            name.as_ptr(),
            c_int::from(ARES_CLASS_IN),
            c_int::from(ARES_REC_TYPE_A),
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_query callback did not fire");
    result
}

fn last_octet(data: &[u8]) -> u8 {
    assert!(data.len() >= 4);
    data[data.len() - 1]
}

#[test]
fn parallel_lookups_create_exactly_max_queries_sockets() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::A([2, 3, 4, 5]));
    unsafe {
        let mut options = base_options();
        options.udp_max_queries = 8;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_UDP_MAX_QUERIES,
        );
        use_server(channel, port);
        let mut counter = CreateCounter::default();
        ares_set_socket_callback(
            channel,
            Some(create_cb),
            &mut counter as *mut _ as *mut c_void,
        );

        let name = CString::new("parallel.example").unwrap();
        let mut results: Vec<HostResult> = (0..32).map(|_| HostResult::default()).collect();
        for result in &mut results {
            ares_gethostbyname(
                channel,
                name.as_ptr(),
                libc::AF_INET,
                Some(host_cb),
                result as *mut _ as *mut c_void,
            );
        }
        drive(channel, &mut mini, || {
            results.iter().all(|result| result.done)
        });
        assert_eq!(counter.created.len(), 4, "32 queries / max 8 => 4 sockets");
        for result in &results {
            assert!(result.done);
            assert_eq!(result.status, ARES_SUCCESS);
        }
        ares_destroy(channel);
    }
}

#[test]
fn total_query_cap_retires_socket_even_when_stayopen() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::A([1, 1, 1, 1]));
    unsafe {
        let mut options = base_options();
        options.flags = ARES_FLAG_STAYOPEN;
        options.udp_max_queries = 2;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_UDP_MAX_QUERIES,
        );
        use_server(channel, port);
        let mut counter = CreateCounter::default();
        ares_set_socket_callback(
            channel,
            Some(create_cb),
            &mut counter as *mut _ as *mut c_void,
        );

        for idx in 0..3 {
            let name = CString::new(format!("cap-{idx}.example")).unwrap();
            assert_eq!(run_query(channel, &name, &mut mini).status, ARES_SUCCESS);
        }
        assert_eq!(counter.created.len(), 2, "third query needs a fresh socket");
        ares_destroy(channel);
    }
}

#[test]
fn stayopen_reuses_idle_socket_and_default_retires_it() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::A([4, 4, 4, 4]));
    unsafe {
        let mut keep_options = base_options();
        keep_options.flags = ARES_FLAG_STAYOPEN;
        let keep = init_channel(
            &keep_options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        use_server(keep, port);
        let mut keep_counter = CreateCounter::default();
        ares_set_socket_callback(
            keep,
            Some(create_cb),
            &mut keep_counter as *mut _ as *mut c_void,
        );
        for idx in 0..3 {
            let name = CString::new(format!("stay-{idx}.example")).unwrap();
            assert_eq!(run_query(keep, &name, &mut mini).status, ARES_SUCCESS);
        }
        assert_eq!(
            keep_counter.created.len(),
            1,
            "STAYOPEN keeps the idle socket"
        );
        ares_destroy(keep);

        let options = base_options();
        let churn = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        use_server(churn, port);
        let mut churn_counter = CreateCounter::default();
        ares_set_socket_callback(
            churn,
            Some(create_cb),
            &mut churn_counter as *mut _ as *mut c_void,
        );
        for idx in 0..3 {
            let name = CString::new(format!("churn-{idx}.example")).unwrap();
            assert_eq!(run_query(churn, &name, &mut mini).status, ARES_SUCCESS);
        }
        assert_eq!(
            churn_counter.created.len(),
            3,
            "without STAYOPEN each idle socket is replaced"
        );
        ares_destroy(churn);
    }
}

#[test]
fn shared_udp_demux_routes_each_answer_to_its_query() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::NameA);
    unsafe {
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        use_server(channel, port);
        let mut counter = CreateCounter::default();
        ares_set_socket_callback(
            channel,
            Some(create_cb),
            &mut counter as *mut _ as *mut c_void,
        );

        let mut results: Vec<RawResult> = (0..8).map(|_| RawResult::default()).collect();
        for (idx, result) in results.iter_mut().enumerate() {
            let name = CString::new(format!("q{idx}.demux.example")).unwrap();
            ares_query(
                channel,
                name.as_ptr(),
                c_int::from(ARES_CLASS_IN),
                c_int::from(ARES_REC_TYPE_A),
                Some(raw_cb),
                result as *mut _ as *mut c_void,
            );
        }
        drive(channel, &mut mini, || {
            results.iter().all(|result| result.done)
        });
        assert_eq!(
            counter.created.len(),
            1,
            "concurrent queries share one UDP socket"
        );
        for (idx, result) in results.iter().enumerate() {
            assert!(result.done);
            assert_eq!(result.status, ARES_SUCCESS);
            assert_eq!(
                last_octet(&result.data),
                (idx as u8).wrapping_add(1),
                "answer routed to the wrong waiter"
            );
        }
        ares_destroy(channel);
    }
}

#[test]
fn concurrent_batch_completes_without_waiting_for_timeouts() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::NameA);
    unsafe {
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        use_server(channel, port);
        let mut results: Vec<RawResult> = (0..16).map(|_| RawResult::default()).collect();
        let start = Instant::now();
        for (idx, result) in results.iter_mut().enumerate() {
            let name = CString::new(format!("q{idx}.wake.example")).unwrap();
            ares_query(
                channel,
                name.as_ptr(),
                c_int::from(ARES_CLASS_IN),
                c_int::from(ARES_REC_TYPE_A),
                Some(raw_cb),
                result as *mut _ as *mut c_void,
            );
        }
        drive(channel, &mut mini, || {
            results.iter().all(|result| result.done)
        });
        let elapsed = start.elapsed();
        for result in &results {
            assert!(result.done);
            assert_eq!(result.status, ARES_SUCCESS);
            assert_eq!(result.timeouts, 0, "a routed sibling woke the waiter");
        }
        assert!(
            elapsed < Duration::from_millis(1500),
            "batch should not wait for the 2s query timeout (took {elapsed:?})"
        );
        ares_destroy(channel);
    }
}

#[test]
fn local_ip4_binds_udp_source_address() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::A([6, 6, 6, 6]));
    unsafe {
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        use_server(channel, port);
        ares_set_local_ip4(channel, 0x7F00_0001);
        let dev = CString::new("lo").unwrap();
        ares_set_local_dev(channel, dev.as_ptr());

        let name = CString::new("local-bind.example").unwrap();
        assert_eq!(run_query(channel, &name, &mut mini).status, ARES_SUCCESS);
        assert!(!mini.sources.is_empty());
        for source in &mini.sources {
            assert_eq!(source.ip(), IpAddr::from([127, 0, 0, 1]));
        }
        ares_destroy(channel);
    }
}

#[test]
fn socket_buffer_options_are_accepted_and_saved() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::A([7, 7, 7, 7]));
    unsafe {
        let mut options = base_options();
        options.socket_send_buffer_size = 8192;
        options.socket_receive_buffer_size = 8192;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS
                | ARES_OPT_TIMEOUTMS
                | ARES_OPT_TRIES
                | ARES_OPT_SOCK_SNDBUF
                | ARES_OPT_SOCK_RCVBUF,
        );
        use_server(channel, port);
        let name = CString::new("buf.example").unwrap();
        assert_eq!(run_query(channel, &name, &mut mini).status, ARES_SUCCESS);

        let mut saved: ares_options = ares_options::default();
        let mut mask = 0;
        assert_eq!(
            ares_save_options(channel, &mut saved, &mut mask),
            ARES_SUCCESS
        );
        assert_ne!(mask & ARES_OPT_SOCK_SNDBUF, 0);
        assert_ne!(mask & ARES_OPT_SOCK_RCVBUF, 0);
        assert_eq!(saved.socket_send_buffer_size, 8192);
        assert_eq!(saved.socket_receive_buffer_size, 8192);
        ares_destroy_options(&mut saved);
        ares_destroy(channel);
    }
}

#[test]
fn socket_state_callback_reports_open_and_close() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::A([8, 8, 8, 8]));
    unsafe {
        let mut events = StateEvents::default();
        let mut options = base_options();
        options.sock_state_cb = Some(state_cb);
        options.sock_state_cb_data = &mut events as *mut _ as *mut c_void;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SOCK_STATE_CB,
        );
        use_server(channel, port);
        let name = CString::new("state-cb.example").unwrap();
        assert_eq!(run_query(channel, &name, &mut mini).status, ARES_SUCCESS);
        ares_destroy(channel);

        let open = events
            .events
            .iter()
            .find(|(_, readable, writable)| *readable == 1 && *writable == 0)
            .copied();
        let close = events
            .events
            .iter()
            .find(|(_, readable, writable)| *readable == 0 && *writable == 0)
            .copied();
        assert!(
            open.is_some(),
            "missing open notification: {:?}",
            events.events
        );
        assert!(
            close.is_some(),
            "missing close notification: {:?}",
            events.events
        );
        assert_eq!(open.unwrap().0, close.unwrap().0, "same fd for open/close");
    }
}

#[derive(Default)]
struct ExCalls {
    asocket: c_int,
    aclose: c_int,
    asetsockopt: c_int,
    aconnect: c_int,
    arecvfrom: c_int,
    asendto: c_int,
}

unsafe extern "C" fn ex_asocket(
    domain: c_int,
    sock_type: c_int,
    protocol: c_int,
    user: *mut c_void,
) -> c_int {
    let calls = unsafe { &mut *(user as *mut ExCalls) };
    calls.asocket += 1;
    let fd = unsafe { libc::socket(domain, sock_type, protocol) };
    if fd < 0 {
        return ARES_SOCKET_BAD;
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        unsafe { libc::close(fd) };
        return ARES_SOCKET_BAD;
    }
    fd
}

unsafe extern "C" fn ex_aclose(fd: c_int, user: *mut c_void) -> c_int {
    let calls = unsafe { &mut *(user as *mut ExCalls) };
    calls.aclose += 1;
    unsafe { libc::close(fd) }
}

unsafe extern "C" fn ex_asetsockopt(
    fd: c_int,
    opt: c_uint,
    val: *const c_void,
    len: libc::socklen_t,
    user: *mut c_void,
) -> c_int {
    let calls = unsafe { &mut *(user as *mut ExCalls) };
    calls.asetsockopt += 1;
    let name = match opt {
        ARES_SOCKET_OPT_SENDBUF_SIZE => libc::SO_SNDBUF,
        ARES_SOCKET_OPT_RECVBUF_SIZE => libc::SO_RCVBUF,
        _ => return 0,
    };
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, name, val, len) }
}

unsafe extern "C" fn ex_aconnect(
    fd: c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
    _flags: c_uint,
    user: *mut c_void,
) -> c_int {
    let calls = unsafe { &mut *(user as *mut ExCalls) };
    calls.aconnect += 1;
    unsafe { libc::connect(fd, addr, len) }
}

unsafe extern "C" fn ex_arecvfrom(
    fd: c_int,
    buf: *mut c_void,
    len: libc::size_t,
    flags: c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    user: *mut c_void,
) -> libc::ssize_t {
    let calls = unsafe { &mut *(user as *mut ExCalls) };
    calls.arecvfrom += 1;
    unsafe { libc::recvfrom(fd, buf, len, flags, addr, addrlen) }
}

unsafe extern "C" fn ex_asendto(
    fd: c_int,
    buf: *const c_void,
    len: libc::size_t,
    flags: c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
    user: *mut c_void,
) -> libc::ssize_t {
    let calls = unsafe { &mut *(user as *mut ExCalls) };
    calls.asendto += 1;
    if addr.is_null() {
        unsafe { libc::send(fd, buf, len, flags) }
    } else {
        unsafe { libc::sendto(fd, buf, len, flags, addr, addrlen) }
    }
}

#[test]
fn extended_socket_adapters_are_used_for_udp() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::A([9, 9, 9, 9]));
    unsafe {
        let mut calls = ExCalls::default();
        let mut funcs = AresSocketFunctionsEx {
            version: 1,
            flags: 0,
            asocket: Some(ex_asocket),
            aclose: Some(ex_aclose),
            asetsockopt: Some(ex_asetsockopt),
            aconnect: Some(ex_aconnect),
            arecvfrom: Some(ex_arecvfrom),
            asendto: Some(ex_asendto),
            agetsockname: None,
            abind: None,
            aif_nametoindex: None,
            aif_indextoname: None,
        };
        let mut options = base_options();
        options.socket_send_buffer_size = 4096;
        options.socket_receive_buffer_size = 4096;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS
                | ARES_OPT_TIMEOUTMS
                | ARES_OPT_TRIES
                | ARES_OPT_SOCK_SNDBUF
                | ARES_OPT_SOCK_RCVBUF,
        );
        assert_eq!(
            ares_set_socket_functions_ex(
                channel,
                &mut funcs as *mut _,
                &mut calls as *mut _ as *mut c_void,
            ),
            ARES_SUCCESS
        );
        use_server(channel, port);
        let name = CString::new("ex-sockfunc.example").unwrap();
        assert_eq!(run_query(channel, &name, &mut mini).status, ARES_SUCCESS);
        ares_destroy(channel);
        assert!(calls.asocket >= 1, "asocket not used");
        assert!(calls.asetsockopt >= 2, "asetsockopt not used");
        assert!(calls.aconnect >= 1, "aconnect not used");
        assert!(calls.arecvfrom >= 1, "arecvfrom not used");
        assert!(calls.asendto >= 1, "asendto not used");
        assert!(calls.aclose >= 1, "aclose not used");
    }
}

#[test]
fn unsafe_transport_setters_accept_null_channel() {
    let _serial = serial();
    unsafe {
        ares_set_local_ip4(ptr::null_mut(), 0);
        let v6 = [0u8; 16];
        ares_set_local_ip6(ptr::null_mut(), v6.as_ptr());
        ares_set_local_dev(ptr::null_mut(), ptr::null());
        cares_rs::ares_socket::ares_set_socket_functions(
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
        );
    }
}
