mod ares_data;
mod ares_hostent;
mod ares_options;
mod cnullterminated;
mod cstr;
mod clinkedlist;
mod error;
mod offset_of;

use std::ffi::{ c_int, c_void, c_char };
use std::os::fd::{ AsRawFd };
use std::ffi::{ CString, CStr };
use std::io::Cursor;
use std::net::IpAddr;
use std::cmp::min;
use crate::core::packets::*;
use crate::core::ares::{ Ares, Status, Family };
use crate::core::servers_csv;
use crate::ffi::ares_hostent::*;
use crate::ffi::ares_data::*;
use crate::ffi::clinkedlist::*;
use crate::ffi::error::*;
use crate::cstr;

pub const ARES_SUCCESS: i32 = 0;
pub const ARES_ENODATA: i32 = 1;
pub const ARES_EFORMERR: i32 = 2;
pub const ARES_ESERVFAIL: i32 = 3;
pub const ARES_ENOTFOUND: i32 = 4;
pub const ARES_ETIMEOUT: i32 = 12;
pub const ARES_LIB_INIT_ALL: i32 = 1;

#[allow(non_camel_case_types)]
pub type ares_socket_t = c_int;

#[no_mangle]
pub extern "C" fn ares_library_init(_flags: c_int) -> c_int {
    ARES_SUCCESS
}

#[no_mangle]
pub extern "C" fn ares_library_cleanup() {
}

pub type Channel = *mut ChannelData;

pub struct ChannelData {
    ares: Ares<FFIData>,
    sock_create_callback: Option<AresSockCreateCallback>,
    sock_create_callback_arg: *mut libc::c_void,
}

#[derive(Debug)]
enum Callback {
    AresHostCallback(AresHostCallback),
    AresCallback(AresCallback),
}

impl Callback {
    fn run(&self, buf: Vec<u8>, result: DnsFrame, ffidata: &FFIData) {
        match self {
            Self::AresHostCallback(callback) => run_ares_host_callback(buf, result, *callback, ffidata.arg),
            Self::AresCallback(callback) => run_ares_callback(buf, result, *callback, ffidata.arg),
        }
    }
    fn run_error(&self, status: i32, arg: *mut c_void) {
        match self {
            Self::AresHostCallback(callback) => unsafe { callback(arg, status, 0, std::ptr::null_mut()) },
            Self::AresCallback(callback) => unsafe { callback(arg, status, 0, std::ptr::null_mut(), 0) },
        }
    }
}

#[derive(Debug)]
struct FFIData {
    callback: Callback,
    arg: *mut c_void,
}

#[repr(C)]
pub struct ares_addr_node {
    pub next: *mut ares_addr_node,
    pub family: c_int,
    pub data: [u8; 16], // enough to hold IPv6
}

#[repr(C)]
pub struct ares_addrttl {
    pub ipaddr: [u8; 4], // ipv4
    pub ttl: c_int,
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let ares = Ares::from_sysconfig();
    let channeldata = ChannelData { ares, sock_create_callback: None, sock_create_callback_arg: std::ptr::null_mut() };
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    unsafe { drop(Box::from_raw(channel)); }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, hostname: *const c_char, family: c_int, callback: AresHostCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    let family = match family {
        libc::AF_INET => Family::Ipv4,
        libc::AF_INET6 => Family::Ipv6,
        _ => panic!("unexpected family value: {}", family),
    };
    let hostname = unsafe { CStr::from_ptr(hostname).to_string_lossy() };
    let ffidata = FFIData { callback: Callback::AresHostCallback(callback), arg };
    let newtask = channeldata.ares.gethostbyname(&hostname, family, ffidata);
    if let Some(cb) = channeldata.sock_create_callback {
        cb(newtask.sock.as_raw_fd(), libc::SOCK_DGRAM, channeldata.sock_create_callback_arg);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: AresCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    let name = unsafe { CStr::from_ptr(name).to_string_lossy() };
    let ffidata = FFIData { callback: Callback::AresCallback(callback), arg };
    channeldata.ares.query(&name, dnsclass as u16, dnstype as u16, ffidata);
}

pub unsafe extern "C" fn ares_parse_data<T1, T2>(abuf: *const u8, alen: c_int, out: *mut *mut T2) -> c_int
where T1: Parser + IntoAresData<T2>, T2: CLinkedList + DataType
{
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let frame = DnsFrame::parse(&mut Cursor::new(buf)).unwrap();
    let replies: Vec<T1> = frame.answers.into_iter().map(|x| T1::parse(&mut Cursor::new(&x.data)).unwrap()).collect();
    let aresreplies: Vec<_> = replies.into_iter().map(|x| x.into_ares_data(&buf)).collect();
    let reply = clinkedlist::chain_nodes(aresreplies);
    let aresdata: AresData<T2> = AresData { data_type: T2::datatype(), data: reply };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_mx_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresMxReply) -> c_int {
    unsafe { ares_parse_data::<MxReply, AresMxReply>(abuf, alen, out) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReply) -> c_int {
    unsafe { ares_parse_data::<TxtReply, AresTxtReply>(abuf, alen, out) }
}

impl DnsLabel {
    pub fn build_cstring(&self, main_buf: &[u8]) -> Option<CString> {
        Some(CString::new(self.build_string(main_buf)?).ok()?)
    }
}


#[no_mangle]
pub unsafe extern "C" fn ares_parse_ns_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    let hostent = unsafe { parse_hostent(abuf, alen, HostentParseMode::Aliases).unwrap() };
    let hostent = Box::into_raw(Box::new(hostent));
    unsafe { *out = hostent };
    ARES_SUCCESS
}

const RECORD_TYPE_A: u16 = 0x01;
const RECORD_TYPE_AAAA: u16 = 0x1c;

fn get_addr_type(record_type: u16) -> c_int {
    match record_type {
        0x01 => libc::AF_INET,
        0x1c => libc::AF_INET6,
        0x02 => 0x02,
        _ => panic!("Unexpected DNS record type in answer: {record_type}"),
    }
}

fn buf_to_ip(buf: &[u8]) -> Result<IpAddr, &'static str> {
    match buf.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(buf).unwrap())),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(buf).unwrap())),
        _ => Err("invalid IP byte length"),
    }
}

/* A safe counterpart matching libc::hostent as close as possible */
#[derive(Debug)]
struct HostEnt {
    name: CString,
    aliases: Vec<CString>,
    addrtype: c_int,
    length: c_int,
    addrttls: Vec<(std::net::IpAddr, u32)>,
    addrlist: Vec<IpAddr>,
}

fn iplist_to_raw(addrlist: &[std::net::IpAddr], length: usize) -> Vec<*mut i8> {
    let mut ret: Vec<*mut i8> = vec![];
    for addr in addrlist {
        let t = match addr {
            IpAddr::V4(v4) => Box::new(v4.octets()) as Box<[u8]>,
            IpAddr::V6(v6) => Box::new(v6.octets()) as Box<[u8]>,
        };
        if t.len() == length {
            ret.push(Box::into_raw(t) as *mut i8);
        }
    }
    ret
}

impl HostEnt {
    pub fn from_buf(buf: &[u8], mode: HostentParseMode) -> Result<Self, c_int> {
        let Some(frame) = DnsFrame::parse(&mut Cursor::new(buf)) else {
            return Err(ARES_EBADRESP);
        };
        let Some(first_answer) = frame.answers.first() else {
            return Err(ARES_ENODATA);
        };
        let (expected_record_type, expected_length) = match mode {
            HostentParseMode::Addrs4 => (RECORD_TYPE_A, 4),
            HostentParseMode::Addrs6 => (RECORD_TYPE_AAAA, 16),
            _ => todo!(),
        };
        let name = first_answer.name.build_cstring(&buf).unwrap();
        let mut addrttls: Vec<(std::net::IpAddr, u32)> = vec![];
        let mut addrlist: Vec<std::net::IpAddr> = vec![];
        for answer in frame.answers {
            if answer.record_type != expected_record_type || answer.data.len() != expected_length {
                continue;
            }
        
            if let Ok(ip) = buf_to_ip(&answer.data) {
                addrlist.push(ip);
                addrttls.push((ip, answer.ttl));
            }
        }
        let hostent = Self {
            name,
            aliases: vec![],
            addrtype: get_addr_type(expected_record_type),
            addrttls,
            length: expected_length as c_int,
            addrlist
        };
        Ok(hostent)
    }
    fn parse_cname(answer: DnsAnswer) -> Self {
        todo!()
    }
    unsafe fn into_raw(self) -> *mut libc::hostent {
        let addrlist: Vec<*mut i8> = iplist_to_raw(&self.addrlist, self.length as usize);
        let aliases: Vec<*mut i8> = self.aliases.into_iter().map(|t| t.into_raw()).collect();
        let hostent = libc::hostent {
            h_name: self.name.into_raw(),
            h_aliases: unsafe { cnullterminated::from_vec(aliases) },
            h_addrtype: self.addrtype,
            h_length: self.length,
            h_addr_list: unsafe { cnullterminated::from_vec(addrlist) },
        };

        Box::into_raw(Box::new(hostent))
    }
}

unsafe fn fill_addrttls(host: &HostEnt, addrttls: *mut ares_addrttl, naddrttls: usize) -> usize {
    let mut i = 0;
    for (ip, ttl) in host.addrttls.iter() {
        if i >= naddrttls {
            break;
        }
        let IpAddr::V4(ipv4) = ip else {
            continue;
        };
        if !addrttls.is_null() {
            (*addrttls.add(i)).ipaddr = ipv4.octets();
            (*addrttls.add(i)).ttl = *ttl as c_int;
        }
        i += 1;
    }
    i
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_a_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addrttl, out_naddrttls: *mut c_int) -> c_int {
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let (ret_code, host_ptr, naddrttls) = match HostEnt::from_buf(buf, HostentParseMode::Addrs4) {
        Ok(host) => {
            let naddrttls = if !out_naddrttls.is_null() {
                let naddrttls = std::cmp::max(*out_naddrttls, 0);
                fill_addrttls(&host, addrttls, naddrttls as usize)
            } else {
                0
            };
            (ARES_SUCCESS, host.into_raw(), naddrttls)
        }
        Err(err) => (err, std::ptr::null_mut(), 0)
    };
    if !out.is_null() { *out = host_ptr; }
    if !out_naddrttls.is_null() { *out_naddrttls = naddrttls as i32; }
    ret_code
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_aaaa_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    let hostent = unsafe { parse_hostent(abuf, alen, HostentParseMode::Addrs6).unwrap() };
    let hostent = Box::into_raw(Box::new(hostent));
    unsafe { *out = hostent };
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_hostent(hostent: *mut libc::hostent) {
    unsafe { free_hostent(hostent) };
}

pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);
pub type AresCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int);
pub type AresSockCreateCallback = unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void);

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_fds(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    let channeldata = unsafe { &mut *channel };
    unsafe { libc::FD_ZERO(write_fds) };
    unsafe { libc::FD_ZERO(read_fds) };

    let mut nfds = 0;
    for task in &channeldata.ares.tasks {
        let fd = task.sock.as_raw_fd();
        match task.status {
            Status::Writing => unsafe { libc::FD_SET(fd, write_fds) },
            Status::Reading => unsafe { libc::FD_SET(fd, read_fds) },
            Status::Completed => continue,
        };
        if nfds < fd { nfds = fd + 1 }
    }
    nfds
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_timeout(channel: Channel, _maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval {
    let channeldata = unsafe { &mut *channel };
    let max_wait_time = channeldata.ares.max_wait_time().as_millis();
    unsafe {
        (*tv).tv_sec = (max_wait_time / 1000) as i64;
        (*tv).tv_usec = 1000 * (max_wait_time % 1000) as i64;
    };
    tv
}

fn run_ares_host_callback(buf: Vec<u8>, result: DnsFrame, callback: AresHostCallback, arg: *mut c_void) {
    let reply_code = result.flags & 0x0f;
    if reply_code > 0 {
        let status = match reply_code {
            3 => ARES_ENOTFOUND,
            _ => ARES_ESERVFAIL,
        };
        return unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
    }

    let hostent = unsafe { parse_hostent(buf.as_ptr(), buf.len() as i32, HostentParseMode::Addrs).unwrap() };
    let hostent = Box::into_raw(Box::new(hostent));
    unsafe { callback(arg, ARES_SUCCESS, 0, &mut *hostent) };
    unsafe { ares_free_hostent(hostent) };
}

fn run_ares_callback(buf: Vec<u8>, _result: DnsFrame, callback: AresCallback, arg: *mut c_void) {
    unsafe { callback(arg, ARES_SUCCESS, 0, buf.as_ptr() as *mut u8, buf.len() as i32) };
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    let channeldata = unsafe { &mut *channel };
    for task in &mut channeldata.ares.tasks {
        if task.is_expired() {
            let ffidata = &task.userdata;
            (ffidata.callback).run_error(ARES_ETIMEOUT, ffidata.arg);
            task.status = Status::Completed;
        }
    }
    channeldata.ares.remove_completed();

    let mut tasks = std::mem::take(&mut channeldata.ares.tasks);
    for task in &mut tasks {
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), write_fds) } {
            channeldata.ares.write_impl(task);
        }
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), read_fds) } {
            if let Some((buf, frame)) = channeldata.ares.read_impl(task) {
                (task.userdata.callback).run(buf, frame, &task.userdata);
            }
        }
    }
    channeldata.ares.tasks = tasks;
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers(channel: Channel, mut head: *mut ares_addr_node) {
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.config.nameservers.clear();
    while !head.is_null() {
        if unsafe { (*head).family } == libc::AF_INET {
            let node = unsafe { &(*head) };
            let oct4: [u8; 4] = node.data[0..4].try_into().unwrap();
            channeldata.ares.config.nameservers.push((IpAddr::from(oct4), None));
        }
        head = unsafe { (*head).next };
    }
}

fn ipv4_to_in_addr(ip: IpAddr) -> Option<AresAddrUnion> {
    match ip {
        IpAddr::V4(v4) => {
            let addr = u32::from_ne_bytes(v4.octets());
            Some(AresAddrUnion { addr4: libc::in_addr { s_addr: addr } })
        }
        IpAddr::V6(_) => None,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_ports(channel: Channel, out: *mut *mut AresAddrPortNode) -> c_int {
    let channeldata = unsafe { &mut *channel };
    let mut data: Vec<AresAddrPortNode> = vec![];
    for srv in &channeldata.ares.config.nameservers {
        data.push(AresAddrPortNode {
            next: std::ptr::null_mut(),
            family: libc::AF_INET,
            addr: ipv4_to_in_addr(srv.0).unwrap(),
            udp_port: srv.1.unwrap_or(channeldata.ares.default_udp_port) as c_int,
            tcp_port: srv.1.unwrap_or(channeldata.ares.default_tcp_port) as c_int,
        });
    }
    let data = clinkedlist::chain_nodes(data);
    let aresdata: AresData<AresAddrPortNode> = AresData { data_type: AresAddrPortNode::datatype(), data };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports_csv(channel: Channel, servers: *const c_char) -> c_int {
    let channeldata = unsafe { &mut *channel };
    let mut cursor = Cursor::new(CStr::from_ptr(servers).to_str().unwrap());
    channeldata.ares.config.nameservers = servers_csv::parse_from_reader(&mut cursor).unwrap();
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn ares_version(version: *mut c_int) -> *const c_char {
    let (major, minor, patch) = (1, 17, 1);
    let v = (major << 16) | (minor << 8) | patch;
    if !version.is_null() { unsafe { *version = v } }
    cstr!("1.17.1-rs")
}

pub const ARES_GETSOCK_MAXNUM: usize = 16; // per c-ares headers
pub const ARES_SOCKET_BAD: ares_socket_t = -1;

#[no_mangle]
pub unsafe extern "C" fn ares_getsock(channel: Channel, socks: *mut ares_socket_t, numsocks: c_int) -> c_int {
    let channeldata = unsafe { &mut *channel };
    let n = min(ARES_GETSOCK_MAXNUM, numsocks as usize);

    let mut mask: c_int = 0;
    for i in 0..n {
        let maybe_task = channeldata.ares.tasks.get(i);
        std::ptr::write(socks.add(i), maybe_task.map(|x| x.sock.as_raw_fd()).unwrap_or(ARES_SOCKET_BAD));

        if maybe_task.is_some() {
            mask |= 1 << i; // No need to wait ARES_GETSOCK_WRITABLE for UDP sockets
        }
    }

    mask
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_string(s: *mut libc::c_void) {
    drop(CString::from_raw(s as *mut c_char));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_callback(channel: Channel, callback: Option<AresSockCreateCallback>, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    channeldata.sock_create_callback = callback;
    channeldata.sock_create_callback_arg = arg;
}
