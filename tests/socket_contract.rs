//! Socket-function contracts from the c-ares audit: option payload shape,
//! callback ordering, event-thread exclusions, and the optional ex adapters.
//!
//! Loopback mock servers; global channel state is serialized with a Mutex.

use std::ffi::{c_int, c_uint, c_void, CStr, CString};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cares::ares_options::{
    ares_init_options, ares_options, ARES_FLAG_USEVC, ARES_OPT_EVENT_THREAD, ARES_OPT_FLAGS,
    ARES_OPT_SOCK_STATE_CB, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES,
};
use cares::ares_socket::{
    ares_set_socket_functions, ares_set_socket_functions_ex, AresSocketFunctions,
    AresSocketFunctionsEx, ARES_SOCKET_OPT_BIND_DEVICE, ARES_SOCKET_OPT_RECVBUF_SIZE,
    ARES_SOCKET_OPT_SENDBUF_SIZE,
};
use cares::dns_record::{ARES_CLASS_IN, ARES_REC_TYPE_A};
use cares::*;

const ARES_SUCCESS: c_int = 0;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One A answer echoing the question, for both UDP and framed TCP replies.
fn make_reply(request: &[u8]) -> Vec<u8> {
    let mut reply = Vec::with_capacity(request.len() + 16);
    reply.extend_from_slice(&request[0..2]);
    reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    reply.extend_from_slice(&request[12..]);
    reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 2, 0x58, 0, 4, 127, 1, 2, 3]);
    reply
}

/// A mock DNS server thread; used by the event-thread tests, which need the
/// server to answer while the test thread waits on `ares_queue_wait_empty`.
struct UdpServer {
    addr: String,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl UdpServer {
    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP server");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("UDP read timeout");
        let addr = format!(
            "127.0.0.1:{}",
            socket.local_addr().expect("UDP local addr").port()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let join = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while !flag.load(Ordering::Relaxed) {
                if let Ok((n, from)) = socket.recv_from(&mut buf) {
                    if n >= 12 {
                        let _ = socket.send_to(&make_reply(&buf[..n]), from);
                    }
                }
            }
        });
        Self {
            addr,
            stop,
            join: Some(join),
        }
    }
}

impl Drop for UdpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// A nonblocking TCP mock server, pumped from the test thread for the socket
/// state-callback test (which drives `ares_process_fd` itself).
struct TcpConn {
    stream: TcpStream,
    inbuf: Vec<u8>,
}

struct TcpMini {
    listener: TcpListener,
    conns: Vec<TcpConn>,
    queries: Vec<Vec<u8>>,
}

impl TcpMini {
    fn start() -> (Self, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP server");
        listener.set_nonblocking(true).expect("TCP nonblocking");
        let port = listener.local_addr().expect("TCP local addr").port();
        (
            Self {
                listener,
                conns: Vec::new(),
                queries: Vec::new(),
            },
            port,
        )
    }

    fn pump(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(true)
                        .expect("TCP stream nonblocking");
                    self.conns.push(TcpConn {
                        stream,
                        inbuf: Vec::new(),
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        let mut buf = [0u8; 4096];
        for conn in &mut self.conns {
            loop {
                match conn.stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => conn.inbuf.extend_from_slice(&buf[..n]),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            loop {
                if conn.inbuf.len() < 2 {
                    break;
                }
                let len = u16::from_be_bytes([conn.inbuf[0], conn.inbuf[1]]) as usize;
                if conn.inbuf.len() < 2 + len {
                    break;
                }
                let request = conn.inbuf[2..2 + len].to_vec();
                conn.inbuf.drain(..2 + len);
                let reply = make_reply(&request);
                self.queries.push(request);
                let mut framed = Vec::with_capacity(2 + reply.len());
                framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                framed.extend_from_slice(&reply);
                let _ = conn.stream.write_all(&framed);
            }
        }
    }
}

#[derive(Default)]
struct RawResult {
    done: bool,
    status: c_int,
}

unsafe extern "C" fn raw_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    _buf: *mut u8,
    _len: c_int,
) {
    let result = unsafe { &mut *(arg as *mut RawResult) };
    result.done = true;
    result.status = status;
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

unsafe fn use_server(channel: Channel, addr: &str) {
    let csv = CString::new(addr).unwrap();
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

fn drive(channel: Channel, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() && Instant::now() < deadline {
        pump_channel(channel);
        std::thread::sleep(Duration::from_millis(1));
    }
    pump_channel(channel);
}

fn drive_tcp(channel: Channel, mini: &mut TcpMini, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() && Instant::now() < deadline {
        mini.pump();
        pump_channel(channel);
        std::thread::sleep(Duration::from_millis(1));
    }
    mini.pump();
    pump_channel(channel);
}

unsafe fn start_query(channel: Channel, result: &mut RawResult) {
    let name = CString::new("socket-contract.example").unwrap();
    unsafe {
        ares_query(
            channel,
            name.as_ptr(),
            c_int::from(ARES_CLASS_IN),
            c_int::from(ARES_REC_TYPE_A),
            Some(raw_cb),
            result as *mut _ as *mut c_void,
        )
    };
}

// ---------------------------------------------------------------------------
// Shared extended-socket table that records every adapter call.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ExState {
    events: Vec<&'static str>,
    asocket: usize,
    aclose: usize,
    asetsockopt: usize,
    aconnect: usize,
    arecvfrom: usize,
    asendto: usize,
    agetsockname: usize,
    abind: usize,
    aif_nametoindex: usize,
    aif_indextoname: usize,
    bind_device_calls: usize,
    bind_device_nul_terminated: usize,
    bind_device_lengths: Vec<usize>,
}

unsafe extern "C" fn ex_asocket(
    domain: c_int,
    sock_type: c_int,
    protocol: c_int,
    user: *mut c_void,
) -> c_int {
    let state = unsafe { &mut *(user as *mut ExState) };
    state.asocket += 1;
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
    let state = unsafe { &mut *(user as *mut ExState) };
    state.aclose += 1;
    unsafe { libc::close(fd) }
}

unsafe extern "C" fn ex_asetsockopt(
    fd: c_int,
    opt: c_uint,
    val: *const c_void,
    len: libc::socklen_t,
    user: *mut c_void,
) -> c_int {
    let state = unsafe { &mut *(user as *mut ExState) };
    state.asetsockopt += 1;

    if opt == ARES_SOCKET_OPT_BIND_DEVICE {
        state.bind_device_calls += 1;
        state.bind_device_lengths.push(len as usize);
        if !val.is_null() && len > 0 {
            let bytes = unsafe { std::slice::from_raw_parts(val as *const u8, len as usize) };
            if bytes.contains(&0) {
                state.bind_device_nul_terminated += 1;
            }
        }
        // Treat device binding as accepted; this test inspects the payload.
        return 0;
    }

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
    let state = unsafe { &mut *(user as *mut ExState) };
    state.aconnect += 1;
    state.events.push("connect");
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
    let state = unsafe { &mut *(user as *mut ExState) };
    state.arecvfrom += 1;
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
    let state = unsafe { &mut *(user as *mut ExState) };
    state.asendto += 1;
    if addr.is_null() {
        unsafe { libc::send(fd, buf, len, flags) }
    } else {
        unsafe { libc::sendto(fd, buf, len, flags, addr, addrlen) }
    }
}

unsafe extern "C" fn ex_agetsockname(
    fd: c_int,
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
    user: *mut c_void,
) -> c_int {
    let state = unsafe { &mut *(user as *mut ExState) };
    state.agetsockname += 1;
    unsafe { libc::getsockname(fd, addr, len) }
}

unsafe extern "C" fn ex_abind(
    fd: c_int,
    _flags: c_uint,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
    user: *mut c_void,
) -> c_int {
    let state = unsafe { &mut *(user as *mut ExState) };
    state.abind += 1;
    unsafe { libc::bind(fd, addr, len) }
}

unsafe extern "C" fn ex_aif_nametoindex(
    ifname: *const libc::c_char,
    user: *mut c_void,
) -> c_uint {
    let state = unsafe { &mut *(user as *mut ExState) };
    state.aif_nametoindex += 1;
    unsafe { libc::if_nametoindex(ifname) }
}

unsafe extern "C" fn ex_aif_indextoname(
    ifindex: c_uint,
    ifname_buf: *mut libc::c_char,
    _ifname_buf_len: libc::size_t,
    user: *mut c_void,
) -> *const libc::c_char {
    let state = unsafe { &mut *(user as *mut ExState) };
    state.aif_indextoname += 1;
    unsafe { libc::if_indextoname(ifindex, ifname_buf) }
}

fn ex_funcs() -> AresSocketFunctionsEx {
    AresSocketFunctionsEx {
        version: 1,
        flags: 0,
        asocket: Some(ex_asocket),
        aclose: Some(ex_aclose),
        asetsockopt: Some(ex_asetsockopt),
        aconnect: Some(ex_aconnect),
        arecvfrom: Some(ex_arecvfrom),
        asendto: Some(ex_asendto),
        agetsockname: Some(ex_agetsockname),
        abind: Some(ex_abind),
        aif_nametoindex: None,
        aif_indextoname: None,
    }
}

fn ex_funcs_with_aif() -> AresSocketFunctionsEx {
    AresSocketFunctionsEx {
        aif_nametoindex: Some(ex_aif_nametoindex),
        aif_indextoname: Some(ex_aif_indextoname),
        ..ex_funcs()
    }
}

unsafe fn install_ex(channel: Channel, state: &mut ExState) {
    unsafe { install_ex_funcs(channel, state, &mut ex_funcs()) }
}

unsafe fn install_ex_with_aif(channel: Channel, state: &mut ExState) {
    unsafe { install_ex_funcs(channel, state, &mut ex_funcs_with_aif()) }
}

unsafe fn install_ex_funcs(
    channel: Channel,
    state: &mut ExState,
    funcs: &mut AresSocketFunctionsEx,
) {
    assert_eq!(
        unsafe {
            ares_set_socket_functions_ex(
                channel,
                funcs as *mut AresSocketFunctionsEx,
                state as *mut ExState as *mut c_void,
            )
        },
        ARES_SUCCESS
    );
}

unsafe extern "C" fn create_cb(_fd: c_int, _sock_type: c_int, arg: *mut c_void) -> c_int {
    let state = unsafe { &mut *(arg as *mut ExState) };
    state.events.push("create");
    0
}

// ---------------------------------------------------------------------------
// 1. ARES_SOCKET_OPT_BIND_DEVICE must carry a NUL-terminated value.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn bind_device_option_value_is_nul_terminated() {
    let _serial = serial();
    let server = UdpServer::start();
    unsafe {
        let mut state = ExState::default();
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        install_ex(channel, &mut state);
        use_server(channel, &server.addr);
        let dev = CString::new("lo").unwrap();
        ares_set_local_dev(channel, dev.as_ptr());

        let mut result = RawResult::default();
        start_query(channel, &mut result);
        drive(channel, || result.done);
        assert!(result.done, "query callback did not fire");
        assert_eq!(result.status, ARES_SUCCESS);
        ares_destroy(channel);

        assert!(
            state.bind_device_calls > 0,
            "ARES_SOCKET_OPT_BIND_DEVICE was never delivered to asetsockopt"
        );
        assert_eq!(
            state.bind_device_nul_terminated, state.bind_device_calls,
            "BIND_DEVICE value lacks a NUL within val_size (calls {}, lengths {:?})",
            state.bind_device_calls, state.bind_device_lengths
        );
    }
}

// ---------------------------------------------------------------------------
// 2. ares_set_socket_callback runs after the socket is connected.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn create_callback_runs_after_connect() {
    let _serial = serial();
    let server = UdpServer::start();
    unsafe {
        let mut state = ExState::default();
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        install_ex(channel, &mut state);
        ares_set_socket_callback(channel, Some(create_cb), &mut state as *mut _ as *mut c_void);
        use_server(channel, &server.addr);

        let mut result = RawResult::default();
        start_query(channel, &mut result);
        drive(channel, || result.done);
        assert!(result.done, "query callback did not fire");
        assert_eq!(result.status, ARES_SUCCESS);
        ares_destroy(channel);

        let first_connect = state
            .events
            .iter()
            .position(|event| *event == "connect")
            .expect("aconnect callback never observed");
        let first_create = state
            .events
            .iter()
            .position(|event| *event == "create")
            .expect("ares_set_socket_callback never observed");
        assert!(
            first_create > first_connect,
            "create callback ran before connect: {:?}",
            state.events
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Configure callback is ignored on an event-thread channel.
// ---------------------------------------------------------------------------

unsafe extern "C" fn counting_config_cb(
    _fd: c_int,
    _sock_type: c_int,
    arg: *mut c_void,
) -> c_int {
    let counter = unsafe { &*(arg as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
    0
}

#[test]
#[cfg_attr(miri, ignore = "real sockets and threads: Miri cannot run them")]
fn configure_callback_is_ignored_with_event_thread() {
    let _serial = serial();
    let server = UdpServer::start();
    let calls = AtomicUsize::new(0);
    unsafe {
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_EVENT_THREAD | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        ares_set_socket_configure_callback(
            channel,
            Some(counting_config_cb),
            &calls as *const AtomicUsize as *mut c_void,
        );
        use_server(channel, &server.addr);

        let mut result = RawResult::default();
        start_query(channel, &mut result);
        assert_eq!(
            ares_queue_wait_empty(channel, 5_000),
            ARES_SUCCESS,
            "event-thread query did not finish"
        );
        ares_destroy(channel);
        assert!(result.done, "query callback did not fire");
        assert_eq!(result.status, ARES_SUCCESS);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "ares_set_socket_configure_callback was installed on an event-thread channel"
    );
}

// ---------------------------------------------------------------------------
// 4. Legacy ares_set_socket_functions is ignored on an event-thread channel.
// ---------------------------------------------------------------------------

unsafe extern "C" fn counting_legacy_asocket(
    _domain: c_int,
    _sock_type: c_int,
    _protocol: c_int,
    arg: *mut c_void,
) -> c_int {
    let counter = unsafe { &*(arg as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
    ARES_SOCKET_BAD
}

#[test]
#[cfg_attr(miri, ignore = "real sockets and threads: Miri cannot run them")]
fn legacy_socket_functions_are_ignored_with_event_thread() {
    let _serial = serial();
    let server = UdpServer::start();
    let calls = AtomicUsize::new(0);
    unsafe {
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_EVENT_THREAD | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        let funcs = AresSocketFunctions {
            asocket: Some(counting_legacy_asocket),
            ..AresSocketFunctions::default()
        };
        ares_set_socket_functions(
            channel,
            &funcs as *const AresSocketFunctions,
            &calls as *const AtomicUsize as *mut c_void,
        );
        use_server(channel, &server.addr);

        let mut result = RawResult::default();
        start_query(channel, &mut result);
        assert_eq!(
            ares_queue_wait_empty(channel, 5_000),
            ARES_SUCCESS,
            "event-thread query did not finish"
        );
        ares_destroy(channel);
        assert!(result.done, "query callback did not fire");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "legacy ares_set_socket_functions was installed on an event-thread channel"
        );
        assert_eq!(
            result.status, ARES_SUCCESS,
            "query did not use the normal socket path"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Optional ex agetsockname adapter is used.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn ex_agetsockname_is_used() {
    let _serial = serial();
    let server = UdpServer::start();
    unsafe {
        let mut state = ExState::default();
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        install_ex(channel, &mut state);
        use_server(channel, &server.addr);

        let mut result = RawResult::default();
        start_query(channel, &mut result);
        drive(channel, || result.done);
        assert!(result.done, "query callback did not fire");
        assert_eq!(result.status, ARES_SUCCESS);
        ares_destroy(channel);

        assert!(
            state.agetsockname > 0,
            "extended agetsockname adapter was never called"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Optional ex abind adapter is used for a configured local address.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn ex_abind_is_used_for_local_ip4() {
    let _serial = serial();
    let server = UdpServer::start();
    unsafe {
        let mut state = ExState::default();
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        install_ex(channel, &mut state);
        use_server(channel, &server.addr);
        ares_set_local_ip4(channel, 0x7F00_0001);

        let mut result = RawResult::default();
        start_query(channel, &mut result);
        drive(channel, || result.done);
        assert!(result.done, "query callback did not fire");
        assert_eq!(result.status, ARES_SUCCESS);
        ares_destroy(channel);

        assert!(
            state.abind > 0,
            "extended abind adapter was never called for a local_ip4 bind"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. sock_state_cb reports a writable transition, not just open/close.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StateEvents {
    events: Vec<(c_int, c_int, c_int)>,
}

extern "C" fn state_cb(data: *mut c_void, fd: c_int, readable: c_int, writable: c_int) {
    let events = unsafe { &mut *(data as *mut StateEvents) };
    events.events.push((fd, readable, writable));
}

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn sock_state_cb_reports_writable_transition_for_tcp() {
    let _serial = serial();
    let (mut mini, port) = TcpMini::start();
    unsafe {
        let mut events = StateEvents::default();
        let mut options = base_options();
        options.flags = ARES_FLAG_USEVC;
        options.sock_state_cb = Some(state_cb);
        options.sock_state_cb_data = &mut events as *mut _ as *mut c_void;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS
                | ARES_OPT_TIMEOUTMS
                | ARES_OPT_TRIES
                | ARES_OPT_SOCK_STATE_CB,
        );
        use_server(channel, &format!("127.0.0.1:{port}"));

        let mut result = RawResult::default();
        start_query(channel, &mut result);
        drive_tcp(channel, &mut mini, || result.done);
        assert!(result.done, "query callback did not fire");
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(mini.queries.len(), 1, "TCP query was not sent once");
        ares_destroy(channel);

        let saw_writable = events
            .events
            .iter()
            .any(|(_, _readable, writable)| *writable == 1);
        let beyond_open_close = events.events.len() > 2;
        assert!(
            saw_writable || beyond_open_close,
            "sock_state_cb never reported a writable/transition state: {:?}",
            events.events
        );
    }
}

// ---------------------------------------------------------------------------
// 8. ares_set_pending_write_cb must fire when a TCP write is pending.
// ---------------------------------------------------------------------------

unsafe extern "C" fn counting_pending_write_cb(data: *mut c_void) {
    let counter = unsafe { &*(data as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
}

#[test]
#[cfg_attr(miri, ignore = "real sockets")]
fn pending_write_cb_fires_for_tcp_data() {
    let _serial = serial();
    let (mut mini, port) = TcpMini::start();
    let counter = AtomicUsize::new(0);
    unsafe {
        let mut options = base_options();
        options.flags = ARES_FLAG_USEVC;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        use_server(channel, &format!("127.0.0.1:{port}"));
        ares_set_pending_write_cb(
            channel,
            Some(counting_pending_write_cb),
            &counter as *const AtomicUsize as *mut c_void,
        );

        let mut result = RawResult::default();
        start_query(channel, &mut result);
        drive_tcp(channel, &mut mini, || result.done);
        assert!(result.done, "query callback did not fire");
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(mini.queries.len(), 1, "TCP query was not sent once");

        ares_process_pending_write(channel);
        ares_destroy(channel);
    }
    assert!(
        counter.load(Ordering::SeqCst) > 0,
        "ares_set_pending_write_cb callback never fired for TCP data"
    );
}

// ---------------------------------------------------------------------------
// 9. ares_process_pending_write is harmless without a callback or pending data.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "real sockets")]
fn process_pending_write_without_callback_is_harmless() {
    let _serial = serial();
    unsafe {
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        ares_process_pending_write(channel);
        ares_process_pending_write(channel);
        ares_destroy(channel);
    }
}

// ---------------------------------------------------------------------------
// 10. Optional ex aif_nametoindex/aif_indextoname adapters are used for
//     scoped IPv6 server specifications.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn ex_aif_adapters_are_used_for_scoped_ipv6_servers() {
    let _serial = serial();
    unsafe {
        let mut state = ExState::default();
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        install_ex_with_aif(channel, &mut state);

        let scoped = CString::new("[fe80::1%lo]:5353").unwrap();
        assert_eq!(
            ares_set_servers_csv(channel, scoped.as_ptr()),
            ARES_SUCCESS,
            "ares_set_servers_csv rejected a valid scoped IPv6 server"
        );
        assert!(
            state.aif_nametoindex > 0,
            "extended aif_nametoindex adapter was never called while parsing \
             a `[fe80::1%lo]:5353` server specification"
        );

        let csv = ares_get_servers_csv(channel);
        assert!(
            !csv.is_null(),
            "ares_get_servers_csv returned NULL for a configured scoped IPv6 server"
        );
        let text = CStr::from_ptr(csv).to_string_lossy().into_owned();
        ares_free_string(csv as *mut c_void);

        assert!(
            text.contains("fe80::1"),
            "server CSV lost the scoped IPv6 address: {text:?}"
        );
        assert!(
            text.contains('%'),
            "server CSV dropped the IPv6 scope: {text:?}"
        );
        assert!(
            text.contains("%lo") || text.contains("%1"),
            "server CSV does not carry either the interface name or index: {text:?}"
        );
        if text.contains("%lo") {
            assert!(
                state.aif_indextoname > 0,
                "server CSV names the scope as `%lo` but aif_indextoname was never called"
            );
        }

        let empty = CString::new("").unwrap();
        assert_eq!(
            ares_set_servers_csv(channel, empty.as_ptr()),
            ARES_SUCCESS,
            "clearing the server list failed"
        );
        let cleared = ares_get_servers_csv(channel);
        assert!(!cleared.is_null(), "ares_get_servers_csv returned NULL after clear");
        ares_free_string(cleared as *mut c_void);
        ares_destroy(channel);
    }
}
