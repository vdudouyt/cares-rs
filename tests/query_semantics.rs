//! Query semantics: wire class/flags, transports, reply policy, search/aliases,
//! validation, cache keys and reinit. Loopback servers; global state serialized.

use std::ffi::{c_int, c_uint, c_void, CStr, CString};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cares_rs::ares_options::{
    ares_init_options, ares_options, ARES_FLAG_IGNTC, ARES_FLAG_NOALIASES, ARES_FLAG_NOCHECKRESP,
    ARES_FLAG_NORECURSE, ARES_FLAG_NOSEARCH, ARES_FLAG_NO_DFLT_SVR, ARES_FLAG_USEVC,
    ARES_OPT_DOMAINS, ARES_OPT_FLAGS, ARES_OPT_NDOTS, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF,
    ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES,
};
use cares_rs::dns_record::*;
use cares_rs::*;

const ARES_SUCCESS: c_int = 0;
const ARES_EFORMERR: c_int = 2;
const ARES_ENOSERVER: c_int = 26;
const ARES_EBADQUERY: c_int = 7;
const ARES_EBADNAME: c_int = 8;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Copy)]
enum ReplyKind {
    A,
    Truncated,
    Rcode(u8),
    NxThenA,
}

struct TcpConn {
    stream: TcpStream,
    inbuf: Vec<u8>,
}

struct Mini {
    udp: Option<UdpSocket>,
    tcp: Option<TcpListener>,
    tcp_conns: Vec<TcpConn>,
    udp_queries: Vec<Vec<u8>>,
    tcp_queries: Vec<Vec<u8>>,
    udp_reply: ReplyKind,
    tcp_reply: ReplyKind,
}

impl Mini {
    fn udp(reply: ReplyKind) -> (Self, u16) {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind UDP mini server");
        udp.set_nonblocking(true).expect("UDP nonblocking");
        let port = udp.local_addr().expect("UDP local addr").port();
        (
            Self {
                udp: Some(udp),
                tcp: None,
                tcp_conns: Vec::new(),
                udp_queries: Vec::new(),
                tcp_queries: Vec::new(),
                udp_reply: reply,
                tcp_reply: reply,
            },
            port,
        )
    }

    fn tcp(reply: ReplyKind) -> (Self, u16) {
        let tcp = TcpListener::bind("127.0.0.1:0").expect("bind TCP mini server");
        tcp.set_nonblocking(true).expect("TCP nonblocking");
        let port = tcp.local_addr().expect("TCP local addr").port();
        (
            Self {
                udp: None,
                tcp: Some(tcp),
                tcp_conns: Vec::new(),
                udp_queries: Vec::new(),
                tcp_queries: Vec::new(),
                udp_reply: reply,
                tcp_reply: reply,
            },
            port,
        )
    }

    fn both(udp_reply: ReplyKind, tcp_reply: ReplyKind) -> (Self, u16) {
        for _ in 0..20 {
            let udp = UdpSocket::bind("127.0.0.1:0").expect("bind UDP mini server");
            udp.set_nonblocking(true).expect("UDP nonblocking");
            let port = udp.local_addr().expect("UDP local addr").port();
            if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)) {
                tcp.set_nonblocking(true).expect("TCP nonblocking");
                return (
                    Self {
                        udp: Some(udp),
                        tcp: Some(tcp),
                        tcp_conns: Vec::new(),
                        udp_queries: Vec::new(),
                        tcp_queries: Vec::new(),
                        udp_reply,
                        tcp_reply,
                    },
                    port,
                );
            }
        }
        panic!("could not bind UDP+TCP mini server on the same port");
    }

    fn pump(&mut self) {
        let mut buf = [0u8; 4096];
        if let Some(udp) = &self.udp {
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                let request = buf[..n].to_vec();
                let reply = make_reply(&request, self.udp_reply);
                self.udp_queries.push(request);
                let _ = udp.send_to(&reply, from);
            }
        }

        if let Some(listener) = &self.tcp {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(true)
                            .expect("TCP stream nonblocking");
                        self.tcp_conns.push(TcpConn {
                            stream,
                            inbuf: Vec::new(),
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }

        for conn in &mut self.tcp_conns {
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
                let reply = make_reply(&request, self.tcp_reply);
                self.tcp_queries.push(request);
                let mut framed = Vec::with_capacity(2 + reply.len());
                framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                framed.extend_from_slice(&reply);
                let _ = conn.stream.write_all(&framed);
            }
        }
    }

    fn last_udp(&self) -> &[u8] {
        self.udp_queries.last().expect("no UDP query captured")
    }
}

fn make_reply(request: &[u8], kind: ReplyKind) -> Vec<u8> {
    let (qname, _, _) = question_parts(request);
    let (rcode, truncated, answer) = match kind {
        ReplyKind::A => (0u8, false, true),
        ReplyKind::Truncated => (0u8, true, false),
        ReplyKind::Rcode(rcode) => (rcode, false, false),
        ReplyKind::NxThenA => {
            if qname.ends_with("second.test") {
                (0u8, false, true)
            } else {
                (3u8, false, false)
            }
        }
    };

    let mut reply = Vec::new();
    reply.extend_from_slice(&request[0..2]);
    let mut flags = 0x8180u16;
    if truncated {
        flags |= 0x0200;
    }
    flags |= u16::from(rcode);
    reply.extend_from_slice(&flags.to_be_bytes());
    reply.extend_from_slice(&[0, 1]);
    reply.extend_from_slice(&(u16::from(answer)).to_be_bytes());
    reply.extend_from_slice(&[0, 0, 0, 0]);
    reply.extend_from_slice(&request[12..]);
    if answer {
        reply.extend_from_slice(&[0xC0, 0x0C]);
        reply.extend_from_slice(&[0, 1, 0, 1]);
        reply.extend_from_slice(&[0, 0, 2, 0x58]);
        reply.extend_from_slice(&[0, 4, 127, 1, 2, 3]);
    }
    reply
}

fn question_parts(request: &[u8]) -> (String, u16, u16) {
    assert!(request.len() >= 12, "short DNS request");
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
    assert!(pos + 4 <= request.len());
    let qtype = u16::from_be_bytes([request[pos], request[pos + 1]]);
    let qclass = u16::from_be_bytes([request[pos + 2], request[pos + 3]]);
    (labels.join("."), qtype, qclass)
}

fn rd_bit(request: &[u8]) -> bool {
    request[2] & 0x01 != 0
}

fn cd_bit(request: &[u8]) -> bool {
    request[3] & 0x10 != 0
}

/// Return (UDP size/class, version, flags) for the first additional OPT RR.
fn additional_opt(request: &[u8]) -> Option<(u16, u8, u16)> {
    let arcount = u16::from_be_bytes([request[10], request[11]]);
    if arcount == 0 {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = request[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 1;
            break;
        }
        pos += len;
    }
    pos += 4;
    loop {
        let len = request[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 1;
            break;
        }
        pos += len;
    }
    assert!(pos + 10 <= request.len());
    let rtype = u16::from_be_bytes([request[pos], request[pos + 1]]);
    let rclass = u16::from_be_bytes([request[pos + 2], request[pos + 3]]);
    let ttl = u32::from_be_bytes([
        request[pos + 4],
        request[pos + 5],
        request[pos + 6],
        request[pos + 7],
    ]);
    if rtype != 41 {
        return None;
    }
    Some((rclass, (ttl >> 16) as u8, (ttl & 0xffff) as u16))
}

fn base_options(flags: c_int) -> ares_options {
    let mut opts: ares_options = unsafe { std::mem::zeroed() };
    opts.flags = flags;
    opts.timeout = 500;
    opts.tries = 1;
    opts
}

unsafe fn init_channels(opts: &ares_options, mask: c_int) -> Channel {
    let mut channel: Channel = ptr::null_mut();
    let rc = unsafe { ares_init_options(&mut channel, opts, mask) };
    assert_eq!(rc, ARES_SUCCESS, "ares_init_options");
    assert!(!channel.is_null());
    channel
}

unsafe fn init_flags(flags: c_int) -> Channel {
    let opts = base_options(flags);
    unsafe { init_channels(&opts, ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES) }
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
}

#[derive(Default)]
struct RawResult {
    done: bool,
    status: c_int,
    data: Vec<u8>,
}

#[derive(Default)]
struct DnsResult {
    done: bool,
    status: c_int,
}

#[derive(Default)]
struct HostResult {
    done: bool,
    status: c_int,
}

unsafe extern "C" fn raw_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    buf: *mut u8,
    len: c_int,
) {
    let result = unsafe { &mut *(arg as *mut RawResult) };
    result.done = true;
    result.status = status;
    if !buf.is_null() && len > 0 {
        result
            .data
            .extend_from_slice(unsafe { std::slice::from_raw_parts(buf, len as usize) });
    }
}

unsafe extern "C" fn dnsrec_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: usize,
    _rec: *const ares_dns_record_t,
) {
    let result = unsafe { &mut *(arg as *mut DnsResult) };
    result.done = true;
    result.status = status;
}

unsafe extern "C" fn host_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    _hostent: *mut libc::hostent,
) {
    let result = unsafe { &mut *(arg as *mut HostResult) };
    result.done = true;
    result.status = status;
}

unsafe fn run_query(channel: Channel, name: &CStr, class: u16, mini: &mut Mini) -> RawResult {
    let mut result = RawResult::default();
    unsafe {
        ares_query(
            channel,
            name.as_ptr(),
            c_int::from(class),
            c_int::from(ARES_REC_TYPE_A),
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_query callback did not fire");
    result
}

unsafe fn run_query_dnsrec(
    channel: Channel,
    name: &CStr,
    class: u16,
    mini: &mut Mini,
) -> DnsResult {
    let mut result = DnsResult::default();
    unsafe {
        ares_query_dnsrec(
            channel,
            name.as_ptr(),
            c_uint::from(class),
            u32::from(ARES_REC_TYPE_A),
            Some(dnsrec_cb),
            &mut result as *mut _ as *mut c_void,
            ptr::null_mut(),
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_query_dnsrec callback did not fire");
    result
}

unsafe fn run_search(channel: Channel, name: &CStr, class: u16, mini: &mut Mini) -> RawResult {
    let mut result = RawResult::default();
    unsafe {
        ares_search(
            channel,
            name.as_ptr(),
            c_int::from(class),
            c_int::from(ARES_REC_TYPE_A),
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_search callback did not fire");
    result
}

unsafe fn run_search_dnsrec(
    channel: Channel,
    rec: *const ares_dns_record_t,
    mini: &mut Mini,
) -> DnsResult {
    let mut result = DnsResult::default();
    unsafe {
        ares_search_dnsrec(
            channel,
            rec,
            Some(dnsrec_cb),
            &mut result as *mut _ as *mut c_void,
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_search_dnsrec callback did not fire");
    result
}

unsafe fn run_host(channel: Channel, name: &CStr, mini: &mut Mini) -> HostResult {
    let mut result = HostResult::default();
    unsafe {
        ares_gethostbyname(
            channel,
            name.as_ptr(),
            libc::AF_INET,
            Some(host_cb),
            &mut result as *mut _ as *mut c_void,
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_gethostbyname callback did not fire");
    result
}

fn push_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn build_query_wire(name: &str, class: u16, rd: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x1234u16.to_be_bytes());
    buf.extend_from_slice(&(if rd { 0x0100u16 } else { 0u16 }).to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    push_name(&mut buf, name);
    buf.extend_from_slice(&ARES_REC_TYPE_A.to_be_bytes());
    buf.extend_from_slice(&class.to_be_bytes());
    buf
}

unsafe fn make_query_record(name: &str, class: u16, flags: u16) -> *mut ares_dns_record_t {
    let mut rec = ptr::null_mut();
    assert_eq!(
        unsafe {
            ares_dns_record_create(
                &mut rec,
                0x1234,
                flags,
                u32::from(ARES_OPCODE_QUERY),
                u32::from(ARES_RCODE_NOERROR),
            )
        },
        ARES_SUCCESS
    );
    let cname = CString::new(name).unwrap();
    assert_eq!(
        unsafe {
            ares_dns_record_query_add(
                rec,
                cname.as_ptr(),
                u32::from(ARES_REC_TYPE_A),
                u32::from(class),
            )
        },
        ARES_SUCCESS
    );
    rec
}

unsafe fn run_send(channel: Channel, packet: &[u8], mini: &mut Mini) -> RawResult {
    let mut result = RawResult::default();
    unsafe {
        ares_send(
            channel,
            packet.as_ptr(),
            c_int::try_from(packet.len()).unwrap(),
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_send callback did not fire");
    result
}

unsafe fn run_send_dnsrec(
    channel: Channel,
    rec: *const ares_dns_record_t,
    mini: &mut Mini,
) -> DnsResult {
    let mut result = DnsResult::default();
    unsafe {
        ares_send_dnsrec(
            channel,
            rec,
            Some(dnsrec_cb),
            &mut result as *mut _ as *mut c_void,
            ptr::null_mut(),
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_send_dnsrec callback did not fire");
    result
}

unsafe fn get_servers_csv(channel: Channel) -> String {
    let raw = unsafe { ares_get_servers_csv(channel) };
    assert!(!raw.is_null());
    let text = unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    unsafe { ares_free_string(raw as *mut c_void) };
    text
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(contents: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cares-rs-query-semantics-{}-{nonce}.conf",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp file");
        Self { path }
    }

    fn rewrite(&self, contents: &str) {
        std::fs::write(&self.path, contents).expect("rewrite temp file");
    }

    fn cstring(&self) -> CString {
        CString::new(self.path.to_string_lossy().as_bytes()).unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct EnvGuard {
    key: &'static str,
    old: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
        let old = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.old {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

#[test]
fn query_apis_carry_class_and_norecurse() {
    let _serial = serial();
    let (mut mini, port) = Mini::udp(ReplyKind::A);

    unsafe {
        let channel = init_flags(0);
        use_server(channel, port);
        let name = CString::new("class-in.example").unwrap();
        let in_reply = run_query(channel, &name, ARES_CLASS_IN, &mut mini);
        assert_eq!(in_reply.status, ARES_SUCCESS);
        let (_, _, class) = question_parts(mini.last_udp());
        assert_eq!(class, ARES_CLASS_IN);
        assert!(rd_bit(mini.last_udp()));

        let chaos = CString::new("class-chaos.example").unwrap();
        let reply = run_query(channel, &chaos, ARES_CLASS_CHAOS, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        let (_, _, class) = question_parts(mini.last_udp());
        assert_eq!(class, ARES_CLASS_CHAOS);
        assert!(rd_bit(mini.last_udp()));

        let rec_name = CString::new("class-dnsrec.example").unwrap();
        let reply = run_query_dnsrec(channel, &rec_name, ARES_CLASS_CHAOS, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        let (_, _, class) = question_parts(mini.last_udp());
        assert_eq!(class, ARES_CLASS_CHAOS);
        assert!(rd_bit(mini.last_udp()));

        let search_name = CString::new("class-search.example.").unwrap();
        let reply = run_search(channel, &search_name, ARES_CLASS_CHAOS, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        let (_, _, class) = question_parts(mini.last_udp());
        assert_eq!(class, ARES_CLASS_CHAOS);
        assert!(rd_bit(mini.last_udp()));
        ares_destroy(channel);

        let channel = init_flags(ARES_FLAG_NORECURSE);
        use_server(channel, port);
        let reply = run_query(channel, &chaos, ARES_CLASS_CHAOS, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert!(!rd_bit(mini.last_udp()));
        let reply = run_query_dnsrec(channel, &rec_name, ARES_CLASS_CHAOS, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert!(!rd_bit(mini.last_udp()));
        let reply = run_search(channel, &search_name, ARES_CLASS_CHAOS, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert!(!rd_bit(mini.last_udp()));
        ares_destroy(channel);
    }
}

#[test]
fn usevc_uses_tcp_for_query_send_and_send_dnsrec() {
    let _serial = serial();
    let (mut mini, port) = Mini::tcp(ReplyKind::A);
    unsafe {
        let channel = init_flags(ARES_FLAG_USEVC);
        use_server(channel, port);
        let name = CString::new("usevc-query.example").unwrap();
        assert_eq!(
            run_query(channel, &name, ARES_CLASS_IN, &mut mini).status,
            ARES_SUCCESS
        );
        assert_eq!(mini.tcp_queries.len(), 1);
        assert!(mini.udp_queries.is_empty());

        let packet = build_query_wire("usevc-send.example", ARES_CLASS_IN, true);
        assert_eq!(run_send(channel, &packet, &mut mini).status, ARES_SUCCESS);
        assert_eq!(mini.tcp_queries.len(), 2);

        let rec = make_query_record("usevc-sendrec.example", ARES_CLASS_IN, ARES_FLAG_RD);
        let result = run_send_dnsrec(channel, rec, &mut mini);
        ares_dns_record_destroy(rec);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(mini.tcp_queries.len(), 3);
        assert!(mini.udp_queries.is_empty());
        for query in &mini.tcp_queries {
            let (_, _, class) = question_parts(query);
            assert_eq!(class, ARES_CLASS_IN);
        }
        ares_destroy(channel);
    }
}

#[test]
fn csv_explicit_port_usevc_connects_to_that_tcp_port() {
    let _serial = serial();
    let (mut mini, port) = Mini::tcp(ReplyKind::A);
    unsafe {
        let channel = init_flags(ARES_FLAG_USEVC);
        use_server(channel, port);
        assert_eq!(get_servers_csv(channel), format!("127.0.0.1:{port}"));
        let name = CString::new("csv-port.example").unwrap();
        assert_eq!(
            run_query(channel, &name, ARES_CLASS_IN, &mut mini).status,
            ARES_SUCCESS
        );
        assert_eq!(mini.tcp_queries.len(), 1);
        assert!(mini.udp_queries.is_empty());
        ares_destroy(channel);
    }
}

#[test]
fn igntc_delivers_truncated_udp_without_tcp_retry() {
    let _serial = serial();
    let (mut mini, port) = Mini::both(ReplyKind::Truncated, ReplyKind::A);
    unsafe {
        let channel = init_flags(ARES_FLAG_IGNTC);
        use_server(channel, port);
        let name = CString::new("truncated.example").unwrap();
        let reply = run_query(channel, &name, ARES_CLASS_IN, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert!(!reply.data.is_empty());
        assert_ne!(reply.data[2] & 0x02, 0, "TC bit must survive to the caller");
        assert_eq!(mini.udp_queries.len(), 1);
        assert!(mini.tcp_queries.is_empty(), "IGNTC must not retry over TCP");
        ares_destroy(channel);
    }
}

#[test]
fn nocheckresp_delivers_server_error_rcodes() {
    let _serial = serial();
    let (mut mini, port) = Mini::udp(ReplyKind::Rcode(2));
    unsafe {
        let channel = init_flags(ARES_FLAG_NOCHECKRESP);
        use_server(channel, port);
        for rcode in [2u8, 4, 5] {
            mini.udp_reply = ReplyKind::Rcode(rcode);
            let name = CString::new(format!("rcode-{rcode}.example")).unwrap();
            let reply = run_query(channel, &name, ARES_CLASS_IN, &mut mini);
            assert_eq!(
                reply.status, ARES_SUCCESS,
                "rcode {rcode} should be delivered"
            );
            assert!(!reply.data.is_empty());
            assert_eq!(reply.data[3] & 0x0F, rcode);
        }
        assert_eq!(mini.udp_queries.len(), 3);
        ares_destroy(channel);
    }
}

unsafe fn search_channel(flags: c_int, domains: &[&str], ndots: c_int) -> Channel {
    let c_domains: Vec<CString> = domains
        .iter()
        .map(|domain| CString::new(*domain).unwrap())
        .collect();
    let mut domain_ptrs: Vec<*mut std::ffi::c_char> = c_domains
        .iter()
        .map(|domain| domain.as_ptr() as *mut std::ffi::c_char)
        .collect();
    let mut opts = base_options(flags);
    opts.ndots = ndots;
    opts.ndomains = c_int::try_from(domain_ptrs.len()).unwrap();
    opts.domains = domain_ptrs.as_mut_ptr();
    unsafe {
        init_channels(
            &opts,
            ARES_OPT_FLAGS
                | ARES_OPT_TIMEOUTMS
                | ARES_OPT_TRIES
                | ARES_OPT_NDOTS
                | ARES_OPT_DOMAINS,
        )
    }
}

#[test]
fn nosearch_suppresses_search_suffixes() {
    let _serial = serial();
    let (mut mini, port) = Mini::udp(ReplyKind::A);
    unsafe {
        let channel = search_channel(ARES_FLAG_NOSEARCH, &["search.test"], 5);
        use_server(channel, port);
        let name = CString::new("shortname").unwrap();
        let reply = run_search(channel, &name, ARES_CLASS_IN, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        let (qname, _, _) = question_parts(mini.last_udp());
        assert_eq!(
            qname, "shortname",
            "NOSEARCH must not append search domains"
        );
        ares_destroy(channel);
    }
}

#[test]
fn noaliases_suppresses_hostaliases_lookup() {
    let _serial = serial();
    let aliases = TempFile::new("aliasname alias-target.example\n");
    let _env = EnvGuard::set("HOSTALIASES", aliases.path.as_os_str());
    let (mut mini, port) = Mini::udp(ReplyKind::A);

    unsafe {
        // ndots=1 keeps the alias target as-is, isolating HOSTALIASES from search expansion.
        let channel = search_channel(0, &["search.test"], 1);
        use_server(channel, port);
        let name = CString::new("aliasname").unwrap();
        let reply = run_host(channel, &name, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        let (qname, _, _) = question_parts(mini.last_udp());
        assert_eq!(qname, "alias-target.example", "HOSTALIASES target is used");
        ares_destroy(channel);

        let channel = search_channel(ARES_FLAG_NOALIASES, &["search.test"], 1);
        use_server(channel, port);
        let reply = run_host(channel, &name, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        let (qname, _, _) = question_parts(mini.last_udp());
        assert_eq!(
            qname, "aliasname.search.test",
            "NOALIASES must skip HOSTALIASES and allow search expansion"
        );
        ares_destroy(channel);
    }
}

#[test]
fn hostaliases_alias_suppresses_search_domains() {
    let _serial = serial();
    let aliases = TempFile::new("aliasname alias-target.example\n");
    let _env = EnvGuard::set("HOSTALIASES", aliases.path.as_os_str());
    let (mut mini, port) = Mini::udp(ReplyKind::A);

    unsafe {
        let channel = search_channel(0, &["search.test"], 5);
        use_server(channel, port);
        let name = CString::new("aliasname").unwrap();
        let reply = run_host(channel, &name, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        let (qname, _, _) = question_parts(mini.last_udp());
        assert_eq!(
            qname, "alias-target.example",
            "upstream ares_search_name_list uses a HOSTALIASES alias as-is and suppresses search"
        );
        ares_destroy(channel);
    }
}

#[test]
fn no_dflt_svr_leaves_no_servers_but_default_is_loopback() {
    let _serial = serial();
    let empty = TempFile::new("");
    let path = empty.cstring();

    unsafe {
        let mut opts = base_options(0);
        opts.resolvconf_path = path.as_ptr() as *mut std::ffi::c_char;
        let channel = init_channels(
            &opts,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_RESOLVCONF,
        );
        let csv = get_servers_csv(channel);
        assert_eq!(csv, "127.0.0.1:53");
        ares_destroy(channel);

        let mut opts = base_options(ARES_FLAG_NO_DFLT_SVR);
        opts.resolvconf_path = path.as_ptr() as *mut std::ffi::c_char;
        let channel = init_channels(
            &opts,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_RESOLVCONF,
        );
        let name = CString::new("no-servers.example").unwrap();
        let mut result = RawResult::default();
        ares_query(
            channel,
            name.as_ptr(),
            c_int::from(ARES_CLASS_IN),
            c_int::from(ARES_REC_TYPE_A),
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.done, "no-server query must fail synchronously");
        assert_eq!(result.status, ARES_ENOSERVER);
        ares_destroy(channel);
    }
}

#[test]
fn send_and_query_validation_is_synchronous() {
    let _serial = serial();
    unsafe {
        let channel = init_flags(0);
        let dummy = [0u8; 4];

        let mut result = RawResult::default();
        ares_send(
            channel,
            dummy.as_ptr(),
            11,
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.done);
        assert_eq!(result.status, ARES_EBADQUERY);

        let mut result = RawResult::default();
        ares_send(
            channel,
            dummy.as_ptr(),
            65536,
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.done);
        assert_eq!(result.status, ARES_EBADQUERY);

        let name = CString::new("bad-class.example").unwrap();
        let mut result = RawResult::default();
        ares_query(
            channel,
            name.as_ptr(),
            17,
            c_int::from(ARES_REC_TYPE_A),
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.done);
        assert_eq!(result.status, ARES_EFORMERR);

        let long_name = CString::new(format!("{}.com", "a".repeat(64))).unwrap();
        let mut result = RawResult::default();
        ares_query(
            channel,
            long_name.as_ptr(),
            c_int::from(ARES_CLASS_IN),
            c_int::from(ARES_REC_TYPE_A),
            Some(raw_cb),
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.done);
        assert_eq!(result.status, ARES_EBADNAME);

        ares_destroy(channel);
    }
}

#[test]
fn raw_out_of_range_class_is_rejected_synchronously() {
    let _serial = serial();
    unsafe {
        let channel = init_flags(0);
        let name = CString::new("wide-class.example").unwrap();

        // ares_query takes signed int; >u16 and -1 must fail before any wire request.
        for class in [0x10001, -1] {
            let mut result = RawResult::default();
            ares_query(
                channel,
                name.as_ptr(),
                class,
                c_int::from(ARES_REC_TYPE_A),
                Some(raw_cb),
                &mut result as *mut _ as *mut c_void,
            );
            assert!(result.done, "class {class} must fail synchronously");
            assert_eq!(result.status, ARES_EFORMERR, "class {class}");
        }

        // ares_query_dnsrec takes unsigned class; 0x10001 and u32::MAX must fail via the callback.
        for class in [0x10001u32, u32::MAX] {
            let mut result = DnsResult::default();
            let rc = ares_query_dnsrec(
                channel,
                name.as_ptr(),
                class,
                u32::from(ARES_REC_TYPE_A),
                Some(dnsrec_cb),
                &mut result as *mut _ as *mut c_void,
                ptr::null_mut(),
            );
            assert_eq!(rc, ARES_EFORMERR, "class {class} return");
            assert!(result.done, "class {class} must invoke the callback");
            assert_eq!(result.status, ARES_EFORMERR, "class {class}");
        }

        ares_destroy(channel);
    }
}

#[test]
fn cache_key_isolates_class_and_norecurse() {
    let _serial = serial();
    let (mut mini, port) = Mini::udp(ReplyKind::A);
    unsafe {
        let mut opts = base_options(0);
        opts.qcache_max_ttl = 3600;
        let channel = init_channels(
            &opts,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_QUERY_CACHE,
        );
        use_server(channel, port);
        let name = CString::new("cache-key.example").unwrap();

        let reply = run_query_dnsrec(channel, &name, ARES_CLASS_IN, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert_eq!(mini.udp_queries.len(), 1);

        // A CHAOS query must miss the IN/RD cache entry and reach the server.
        let reply = run_query_dnsrec(channel, &name, ARES_CLASS_CHAOS, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert_eq!(mini.udp_queries.len(), 2);

        // A NORECURSE record must miss the RD cache entry too.
        let rec = make_query_record("cache-key.example", ARES_CLASS_IN, 0);
        let reply = run_send_dnsrec(channel, rec, &mut mini);
        ares_dns_record_destroy(rec);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert_eq!(mini.udp_queries.len(), 3);
        assert!(!rd_bit(mini.last_udp()), "third query must clear RD");
        ares_destroy(channel);
    }
}

#[test]
fn search_dnsrec_preserves_template_class_flags_and_additional() {
    let _serial = serial();
    let (mut mini, port) = Mini::udp(ReplyKind::NxThenA);
    unsafe {
        let channel = search_channel(0, &["first.test", "second.test"], 5);
        use_server(channel, port);

        let rec = make_query_record("short", ARES_CLASS_CHAOS, ARES_FLAG_RD | ARES_FLAG_CD);
        let root = CString::new("").unwrap();
        let mut opt = ptr::null_mut();
        assert_eq!(
            ares_dns_record_rr_add(
                &mut opt,
                rec,
                ARES_SECTION_ADDITIONAL,
                root.as_ptr(),
                u32::from(ARES_REC_TYPE_OPT),
                u32::from(ARES_CLASS_IN),
                0,
            ),
            ARES_SUCCESS
        );
        assert_eq!(
            ares_dns_rr_set_u16(opt, ARES_RR_OPT_UDP_SIZE, 1232),
            ARES_SUCCESS
        );
        assert_eq!(
            ares_dns_rr_set_u8(opt, ARES_RR_OPT_VERSION, 2),
            ARES_SUCCESS
        );
        assert_eq!(
            ares_dns_rr_set_u16(opt, ARES_RR_OPT_FLAGS, 0x0456),
            ARES_SUCCESS
        );

        let reply = run_search_dnsrec(channel, rec, &mut mini);
        ares_dns_record_destroy(rec);
        assert_eq!(reply.status, ARES_SUCCESS);

        assert_eq!(mini.udp_queries.len(), 2);
        for (idx, query) in mini.udp_queries.iter().enumerate() {
            let (qname, _, class) = question_parts(query);
            let expected = if idx == 0 {
                "short.first.test"
            } else {
                "short.second.test"
            };
            assert_eq!(qname, expected);
            assert_eq!(class, ARES_CLASS_CHAOS);
            assert!(rd_bit(query));
            assert!(cd_bit(query));
            assert_eq!(additional_opt(query), Some((1232, 2, 0x0456)));
        }
        ares_destroy(channel);
    }
}

#[test]
fn reinit_reloads_resolvconf_and_flushes_cache() {
    let _serial = serial();
    let (mut mini, port) = Mini::udp(ReplyKind::A);
    let conf = TempFile::new("nameserver 127.0.0.1:1\n");
    let path = conf.cstring();

    unsafe {
        assert_eq!(ares_reinit(ptr::null_mut()), ARES_EFORMERR);

        let mut opts = base_options(0);
        opts.resolvconf_path = path.as_ptr() as *mut std::ffi::c_char;
        opts.qcache_max_ttl = 3600;
        let channel = init_channels(
            &opts,
            ARES_OPT_FLAGS
                | ARES_OPT_TIMEOUTMS
                | ARES_OPT_TRIES
                | ARES_OPT_RESOLVCONF
                | ARES_OPT_QUERY_CACHE,
        );

        conf.rewrite(&format!("nameserver 127.0.0.1:{port}\n"));
        assert_eq!(ares_reinit(channel), ARES_SUCCESS);

        let name = CString::new("reinit.example").unwrap();
        let reply = run_query_dnsrec(channel, &name, ARES_CLASS_IN, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert_eq!(mini.udp_queries.len(), 1);

        let reply = run_query_dnsrec(channel, &name, ARES_CLASS_IN, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert_eq!(
            mini.udp_queries.len(),
            1,
            "second query should be a cache hit"
        );

        conf.rewrite(&format!("# reloaded\nnameserver 127.0.0.1:{port}\n"));
        assert_eq!(ares_reinit(channel), ARES_SUCCESS);
        let reply = run_query_dnsrec(channel, &name, ARES_CLASS_IN, &mut mini);
        assert_eq!(reply.status, ARES_SUCCESS);
        assert_eq!(
            mini.udp_queries.len(),
            2,
            "reinit must flush the cache so the query reaches the server again"
        );

        ares_destroy(channel);
    }
}
