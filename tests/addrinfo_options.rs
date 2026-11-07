//! addrinfo/hosts/sortlist semantics against loopback mini DNS servers;
//! process-global environment and hosts files are serialized.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cares_rs::ares_options::{
    apattern, ares_destroy_options, ares_init_options, ares_options, ares_save_options,
    ARES_OPT_FLAGS, ARES_OPT_HOSTS_FILE, ARES_OPT_LOOKUPS, ARES_OPT_SORTLIST, ARES_OPT_TIMEOUTMS,
    ARES_OPT_TRIES,
};
use cares_rs::*;

const ARES_SUCCESS: c_int = 0;
const ARES_ESERVICE: c_int = 25;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Copy)]
enum ReplyKind {
    A([u8; 4]),
    CnameA { target: &'static str, addr: [u8; 4] },
}

struct Mini {
    socket: UdpSocket,
    queries: Vec<Vec<u8>>,
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
            let _ = self.socket.send_to(&reply, from);
        }
    }
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn make_reply(request: &[u8], kind: ReplyKind) -> Vec<u8> {
    let mut reply = Vec::new();
    reply.extend_from_slice(&request[0..2]);
    reply.extend_from_slice(&[0x81, 0x80]);
    reply.extend_from_slice(&[0, 1]);
    let ancount: u16 = match kind {
        ReplyKind::A(_) => 1,
        ReplyKind::CnameA { .. } => 2,
    };
    reply.extend_from_slice(&ancount.to_be_bytes());
    reply.extend_from_slice(&[0, 0, 0, 0]);
    reply.extend_from_slice(&request[12..]);

    match kind {
        ReplyKind::A(addr) => {
            reply.extend_from_slice(&[0xC0, 0x0C]);
            reply.extend_from_slice(&[0, 1, 0, 1]);
            reply.extend_from_slice(&[0, 0, 0, 60]);
            reply.push(0);
            reply.push(4);
            reply.extend_from_slice(&addr);
        }
        ReplyKind::CnameA { target, addr } => {
            reply.extend_from_slice(&[0xC0, 0x0C]);
            reply.extend_from_slice(&[0, 5, 0, 1]);
            reply.extend_from_slice(&[0, 0, 0, 60]);
            let mut rdata = Vec::new();
            encode_name(target, &mut rdata);
            reply.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            reply.extend_from_slice(&rdata);

            encode_name(target, &mut reply);
            reply.extend_from_slice(&[0, 1, 0, 1]);
            reply.extend_from_slice(&[0, 0, 0, 60]);
            reply.push(0);
            reply.push(4);
            reply.extend_from_slice(&addr);
        }
    }
    reply
}

#[derive(Default)]
struct AiNodeView {
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addr: Option<IpAddr>,
}

#[derive(Default)]
struct CnameView {
    alias: Option<String>,
    name: Option<String>,
    ttl: c_int,
}

#[derive(Default)]
struct AiResult {
    done: bool,
    status: c_int,
    name: Option<String>,
    cnames: Vec<CnameView>,
    nodes: Vec<AiNodeView>,
}

unsafe extern "C" fn ai_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    ai: *mut ares_addrinfo,
) {
    let result = unsafe { &mut *(arg as *mut AiResult) };
    result.done = true;
    result.status = status;
    if ai.is_null() {
        return;
    }

    let ai_ptr = ai;
    let ai = unsafe { &*ai_ptr };
    if !ai.name.is_null() {
        result.name = Some(
            unsafe { CStr::from_ptr(ai.name) }
                .to_string_lossy()
                .into_owned(),
        );
    }

    let mut cname = ai.cnames;
    while !cname.is_null() {
        let entry = unsafe { &*cname };
        result.cnames.push(CnameView {
            alias: (!entry.alias.is_null()).then(|| {
                unsafe { CStr::from_ptr(entry.alias) }
                    .to_string_lossy()
                    .into_owned()
            }),
            name: (!entry.name.is_null()).then(|| {
                unsafe { CStr::from_ptr(entry.name) }
                    .to_string_lossy()
                    .into_owned()
            }),
            ttl: entry.ttl,
        });
        cname = entry.next;
    }

    let mut node = ai.nodes;
    while !node.is_null() {
        let entry = unsafe { &*node };
        let addr = match entry.ai_family {
            libc::AF_INET => {
                let sa = unsafe { &*(entry.ai_addr as *const libc::sockaddr_in) };
                Some(IpAddr::V4(Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes())))
            }
            libc::AF_INET6 => {
                let sa = unsafe { &*(entry.ai_addr as *const libc::sockaddr_in6) };
                Some(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)))
            }
            _ => None,
        };
        result.nodes.push(AiNodeView {
            family: entry.ai_family,
            socktype: entry.ai_socktype,
            protocol: entry.ai_protocol,
            addr,
        });
        node = entry.ai_next;
    }

    unsafe { ares_freeaddrinfo(ai_ptr) };
}

#[derive(Default)]
struct HostResult {
    done: bool,
    status: c_int,
    name: Option<String>,
    addrs: Vec<IpAddr>,
}

unsafe extern "C" fn host_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    host: *mut libc::hostent,
) {
    let result = unsafe { &mut *(arg as *mut HostResult) };
    result.done = true;
    result.status = status;
    if host.is_null() {
        return;
    }
    let host = unsafe { &*host };
    if !host.h_name.is_null() {
        result.name = Some(
            unsafe { CStr::from_ptr(host.h_name) }
                .to_string_lossy()
                .into_owned(),
        );
    }
    if !host.h_addr_list.is_null() {
        let mut cursor = host.h_addr_list;
        while !unsafe { *cursor }.is_null() {
            let raw = unsafe { *cursor as *const u8 };
            match host.h_length {
                4 => {
                    let mut octets = [0u8; 4];
                    unsafe { ptr::copy_nonoverlapping(raw, octets.as_mut_ptr(), 4) };
                    result.addrs.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
                16 => {
                    let mut octets = [0u8; 16];
                    unsafe { ptr::copy_nonoverlapping(raw, octets.as_mut_ptr(), 16) };
                    result.addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
            cursor = unsafe { cursor.add(1) };
        }
    }
}

fn base_options() -> ares_options {
    ares_options {
        timeout: 500,
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

fn drive(channel: Channel, mini: Option<&mut Mini>, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut mini = mini;
    while !done() && Instant::now() < deadline {
        if let Some(server) = mini.as_mut() {
            server.pump();
        }
        pump_channel(channel);
        std::thread::sleep(Duration::from_millis(1));
    }
    if let Some(server) = mini.as_mut() {
        server.pump();
    }
}

unsafe fn getaddrinfo(
    channel: Channel,
    name: &CStr,
    service: Option<&CStr>,
    hints: Option<&ares_addrinfo_hints>,
    mini: Option<&mut Mini>,
) -> AiResult {
    let mut result = AiResult::default();
    unsafe {
        ares_getaddrinfo(
            channel,
            name.as_ptr(),
            service.map_or(ptr::null(), CStr::as_ptr),
            hints.map_or(ptr::null(), |h| h as *const ares_addrinfo_hints),
            Some(ai_cb),
            &mut result as *mut _ as *mut c_void,
        )
    };
    drive(channel, mini, || result.done);
    assert!(result.done, "ares_getaddrinfo callback did not fire");
    result
}

unsafe fn gethostbyname(channel: Channel, name: &CStr, mini: Option<&mut Mini>) -> HostResult {
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
            "cares-rs-addrinfo-{}-{nonce}.tmp",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp file");
        Self { path }
    }

    fn cstring(&self) -> CString {
        CString::new(self.path.to_string_lossy().as_bytes()).unwrap()
    }

    fn path(&self) -> &PathBuf {
        &self.path
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

fn node_addrs(result: &AiResult) -> Vec<IpAddr> {
    result.nodes.iter().filter_map(|node| node.addr).collect()
}

#[test]
fn hosts_file_merges_addresses_and_exposes_cnames() {
    let _serial = serial();
    let hosts = TempFile::new(
        "1.2.3.4 primary.example alias1 alias2\n\
         5.6.7.8 primary.example alias3\n\
         9.9.9.9 alias2 otheralias\n\
         1.2.3.4 ip-shared.example\n",
    );
    let path = hosts.cstring();
    unsafe {
        let mut options = base_options();
        options.hosts_path = path.as_ptr() as *mut c_char;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_HOSTS_FILE,
        );

        let name = CString::new("alias1").unwrap();
        let mut hints: ares_addrinfo_hints = std::mem::zeroed();
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_NOSORT;
        let result = getaddrinfo(channel, &name, None, Some(&hints), None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(
            node_addrs(&result),
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            ]
        );
        let cnames: Vec<(Option<String>, Option<String>)> = result
            .cnames
            .iter()
            .map(|entry| (entry.alias.clone(), entry.name.clone()))
            .collect();
        assert_eq!(
            cnames,
            vec![
                (Some("alias1".into()), Some("primary.example".into())),
                (Some("alias2".into()), Some("primary.example".into())),
                (Some("alias3".into()), Some("primary.example".into())),
                (Some("otheralias".into()), Some("primary.example".into())),
                (
                    Some("ip-shared.example".into()),
                    Some("primary.example".into())
                ),
            ]
        );
        ares_destroy(channel);
    }
}

#[test]
fn envhosts_uses_cares_hosts_only() {
    let _serial = serial();
    let channel_hosts = TempFile::new("9.9.9.9 envhost\n");
    let cares_hosts = TempFile::new("7.7.7.7 envhost env-alias-cares\n");
    let hostaliases = TempFile::new("envhost alias-from-hostaliases.example\n");
    let _cares = EnvGuard::set("CARES_HOSTS", cares_hosts.path().as_os_str());
    let _aliases = EnvGuard::set("HOSTALIASES", hostaliases.path().as_os_str());
    let path = channel_hosts.cstring();

    unsafe {
        let mut options = base_options();
        options.hosts_path = path.as_ptr() as *mut c_char;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_HOSTS_FILE,
        );
        let name = CString::new("envhost").unwrap();
        let mut hints: ares_addrinfo_hints = std::mem::zeroed();
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_flags = ARES_AI_ENVHOSTS | ARES_AI_CANONNAME | ARES_AI_NOSORT;
        let result = getaddrinfo(channel, &name, None, Some(&hints), None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(
            node_addrs(&result),
            vec![IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7))],
            "AI_ENVHOSTS must read CARES_HOSTS, not HOSTALIASES or the channel hosts path"
        );
        assert_eq!(result.name.as_deref(), Some("envhost"));
        assert_eq!(
            result
                .cnames
                .first()
                .and_then(|entry| entry.alias.as_deref()),
            Some("env-alias-cares")
        );

        hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_NOSORT;
        let result = getaddrinfo(channel, &name, None, Some(&hints), None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(
            node_addrs(&result),
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]
        );
        ares_destroy(channel);
    }
}

#[test]
fn getaddrinfo_sorts_rfc6724_and_ignores_channel_sortlist() {
    let _serial = serial();
    let hosts = TempFile::new("127.0.0.1 dual.example\n::1 dual.example\n");
    let path = hosts.cstring();
    unsafe {
        let mut options = base_options();
        options.hosts_path = path.as_ptr() as *mut c_char;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_HOSTS_FILE,
        );
        // Sortlist prefers IPv4, but getaddrinfo must ignore it.
        let sort = CString::new("127.0.0.0/8").unwrap();
        assert_eq!(ares_set_sortlist(channel, sort.as_ptr()), ARES_SUCCESS);

        let name = CString::new("dual.example").unwrap();
        let mut hints: ares_addrinfo_hints = std::mem::zeroed();
        hints.ai_family = libc::AF_UNSPEC;
        let result = getaddrinfo(channel, &name, None, Some(&hints), None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(
            result.nodes[0].family,
            libc::AF_INET6,
            "RFC 6724 loopback v6 first"
        );
        assert_eq!(result.nodes[1].family, libc::AF_INET);

        hints.ai_flags = ARES_AI_NOSORT;
        let result = getaddrinfo(channel, &name, None, Some(&hints), None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(
            result.nodes[0].family,
            libc::AF_INET,
            "AI_NOSORT preserves file order"
        );
        assert_eq!(result.nodes[1].family, libc::AF_INET6);
        ares_destroy(channel);
    }
}

#[test]
fn gethostbyname_applies_sortlist_to_hosts_results() {
    let _serial = serial();
    let hosts = TempFile::new(
        "192.0.2.1 sorted.example\n\
         192.0.2.2 sorted.example\n\
         192.0.2.3 sorted.example\n",
    );
    let path = hosts.cstring();
    unsafe {
        let mut options = base_options();
        options.hosts_path = path.as_ptr() as *mut c_char;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_HOSTS_FILE,
        );
        let sort = CString::new("192.0.2.3").unwrap();
        assert_eq!(ares_set_sortlist(channel, sort.as_ptr()), ARES_SUCCESS);

        let name = CString::new("sorted.example").unwrap();
        let result = gethostbyname(channel, &name, None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(result.addrs.len(), 3);
        assert_eq!(result.addrs[0], IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)));
        ares_destroy(channel);
    }
}

#[test]
fn sortlist_option_roundtrip_and_explicit_empty() {
    let _serial = serial();
    unsafe {
        let mut pattern = apattern {
            addr: ares_addr {
                family: libc::AF_INET,
                addr: AresAddrUnion {
                    addr4: libc::in_addr {
                        s_addr: u32::from_ne_bytes([192, 0, 2, 0]),
                    },
                },
            },
            mask: 24,
        };
        let mut options = base_options();
        options.sortlist = &mut pattern;
        options.nsort = 1;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SORTLIST,
        );

        let mut saved: ares_options = ares_options::default();
        let mut mask = 0;
        assert_eq!(
            ares_save_options(channel, &mut saved, &mut mask),
            ARES_SUCCESS
        );
        assert_ne!(mask & ARES_OPT_SORTLIST, 0);
        assert_eq!(saved.nsort, 1);
        assert!(!saved.sortlist.is_null());
        assert_eq!((*saved.sortlist).addr.family, libc::AF_INET);
        assert_eq!((*saved.sortlist).mask, 24);
        assert_eq!(
            (*saved.sortlist).addr.addr.addr4.s_addr,
            u32::from_ne_bytes([192, 0, 2, 0])
        );
        ares_destroy_options(&mut saved);
        ares_destroy(channel);

        // Explicit empty sortlist keeps the SORTLIST mask set with nsort == 0.
        let mut empty = base_options();
        empty.nsort = 0;
        empty.sortlist = ptr::null_mut();
        let channel = init_channel(
            &empty,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SORTLIST,
        );
        let mut saved: ares_options = ares_options::default();
        let mut mask = 0;
        assert_eq!(
            ares_save_options(channel, &mut saved, &mut mask),
            ARES_SUCCESS
        );
        assert_ne!(
            mask & ARES_OPT_SORTLIST,
            0,
            "explicit empty sortlist stays explicit"
        );
        assert_eq!(saved.nsort, 0);
        assert!(saved.sortlist.is_null());
        ares_destroy_options(&mut saved);
        ares_destroy(channel);
    }
}

#[test]
fn sortlist_zero_prefix_does_not_panic() {
    let _serial = serial();
    let hosts = TempFile::new("10.0.0.1 zero.example\n10.0.0.2 zero.example\n");
    let path = hosts.cstring();
    unsafe {
        let mut options = base_options();
        options.hosts_path = path.as_ptr() as *mut c_char;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_HOSTS_FILE,
        );
        let zero = CString::new("0.0.0.0/0").unwrap();
        assert_eq!(ares_set_sortlist(channel, zero.as_ptr()), ARES_SUCCESS);
        let name = CString::new("zero.example").unwrap();
        let result = gethostbyname(channel, &name, None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(result.addrs.len(), 2);
        ares_destroy(channel);
    }
}

#[test]
fn numericserv_rejects_text_and_socktype_protocol_are_set() {
    let _serial = serial();
    unsafe {
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        let name = CString::new("localhost").unwrap();
        let service = CString::new("http").unwrap();
        let mut hints: ares_addrinfo_hints = std::mem::zeroed();
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_flags = ARES_AI_NUMERICSERV;
        let result = getaddrinfo(channel, &name, Some(&service), Some(&hints), None);
        assert_eq!(result.status, ARES_ESERVICE);
        assert!(result.nodes.is_empty());

        let service = CString::new("80").unwrap();
        hints.ai_flags = ARES_AI_NOSORT;
        hints.ai_socktype = libc::SOCK_STREAM;
        hints.ai_protocol = libc::IPPROTO_TCP;
        let result = getaddrinfo(channel, &name, Some(&service), Some(&hints), None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert!(!result.nodes.is_empty());
        for node in &result.nodes {
            assert_eq!(node.socktype, libc::SOCK_STREAM);
            assert_eq!(node.protocol, libc::IPPROTO_TCP);
        }
        ares_destroy(channel);
    }
}

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn cname_chain_is_exposed_via_addrinfo() {
    let _serial = serial();
    let (mut mini, port) = Mini::new(ReplyKind::CnameA {
        target: "canonical.example",
        addr: [1, 2, 3, 4],
    });
    unsafe {
        let mut options = base_options();
        let lookups = CString::new("b").unwrap();
        options.lookups = lookups.as_ptr() as *mut c_char;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_LOOKUPS,
        );
        use_server(channel, port);
        let name = CString::new("alias.example").unwrap();
        let mut hints: ares_addrinfo_hints = std::mem::zeroed();
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_NOSORT;
        let result = getaddrinfo(channel, &name, None, Some(&hints), Some(&mut mini));
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(result.name.as_deref(), Some("canonical.example"));
        assert_eq!(
            node_addrs(&result),
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
        assert_eq!(result.cnames.len(), 1);
        assert_eq!(result.cnames[0].alias.as_deref(), Some("alias.example"));
        assert_eq!(result.cnames[0].name.as_deref(), Some("canonical.example"));
        assert_eq!(result.cnames[0].ttl, 60);
        ares_destroy(channel);
    }
}

#[test]
fn ai_canonname_for_ip_literal_and_localhost() {
    let _serial = serial();
    unsafe {
        let options = base_options();
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES,
        );
        let mut hints: ares_addrinfo_hints = std::mem::zeroed();
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_NOSORT;

        let literal = CString::new("127.0.0.1").unwrap();
        let result = getaddrinfo(channel, &literal, None, Some(&hints), None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(result.name.as_deref(), Some("127.0.0.1"));
        assert_eq!(result.cnames.len(), 1);
        assert_eq!(result.cnames[0].alias, None);
        assert_eq!(result.cnames[0].name.as_deref(), Some("127.0.0.1"));
        ares_destroy(channel);

        let hosts = TempFile::new("127.0.0.2 localhost\n");
        let path = hosts.cstring();
        let mut options = base_options();
        options.hosts_path = path.as_ptr() as *mut c_char;
        let lookups = CString::new("f").unwrap();
        options.lookups = lookups.as_ptr() as *mut c_char;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS
                | ARES_OPT_TIMEOUTMS
                | ARES_OPT_TRIES
                | ARES_OPT_HOSTS_FILE
                | ARES_OPT_LOOKUPS,
        );
        let localhost = CString::new("localhost").unwrap();
        let result = getaddrinfo(channel, &localhost, None, Some(&hints), None);
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(result.name.as_deref(), Some("localhost"));
        assert!(!result.cnames.is_empty());
        assert_eq!(result.cnames[0].name.as_deref(), Some("localhost"));
        ares_destroy(channel);
    }
}

fn channel_with_order(hosts_path: &CString, order: &CString, server_port: u16) -> Channel {
    unsafe {
        let mut options = base_options();
        options.hosts_path = hosts_path.as_ptr() as *mut c_char;
        options.lookups = order.as_ptr() as *mut c_char;
        let channel = init_channel(
            &options,
            ARES_OPT_FLAGS
                | ARES_OPT_TIMEOUTMS
                | ARES_OPT_TRIES
                | ARES_OPT_HOSTS_FILE
                | ARES_OPT_LOOKUPS,
        );
        use_server(channel, server_port);
        channel
    }
}

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn lookups_fb_prefers_hosts_and_bf_prefers_dns() {
    let _serial = serial();
    let hosts = TempFile::new("10.1.1.1 order.example\n");
    let hosts_path = hosts.cstring();
    let (mut mini, port) = Mini::new(ReplyKind::A([10, 2, 2, 2]));
    let name = CString::new("order.example").unwrap();
    unsafe {
        let fb = CString::new("fb").unwrap();
        let channel = channel_with_order(&hosts_path, &fb, port);
        let mut hints: ares_addrinfo_hints = std::mem::zeroed();
        hints.ai_family = libc::AF_INET;
        hints.ai_flags = ARES_AI_NOSORT;
        let result = getaddrinfo(channel, &name, None, Some(&hints), Some(&mut mini));
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(
            node_addrs(&result),
            vec![IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))]
        );
        assert!(mini.queries.is_empty(), "fb must answer from hosts first");
        ares_destroy(channel);

        let bf = CString::new("bf").unwrap();
        let channel = channel_with_order(&hosts_path, &bf, port);
        let result = getaddrinfo(channel, &name, None, Some(&hints), Some(&mut mini));
        assert_eq!(result.status, ARES_SUCCESS);
        assert_eq!(
            node_addrs(&result),
            vec![IpAddr::V4(Ipv4Addr::new(10, 2, 2, 2))]
        );
        assert_eq!(mini.queries.len(), 1, "bf must query DNS first");
        ares_destroy(channel);
    }
}
