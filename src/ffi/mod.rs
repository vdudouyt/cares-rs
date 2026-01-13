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

trait AddrTTL {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()>;
}

#[repr(C)]
pub struct ares_addrttl {
    pub ipaddr: [u8; 4], // ipv4
    pub ttl: c_int,
}

impl AddrTTL for ares_addrttl {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()> {
        let IpAddr::V4(ipv4) = ip else { return None };
        (self.ipaddr, self.ttl) = (ipv4.octets(), ttl as c_int);
        Some(())
    }
}

#[repr(C)]
pub struct ares_addr6ttl {
    pub ipaddr: [u8; 16], // ipv6
    pub ttl: c_int,
}

impl AddrTTL for ares_addr6ttl {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()> {
        let IpAddr::V6(ipv6) = ip else { return None };
        (self.ipaddr, self.ttl) = (ipv6.octets(), ttl as c_int);
        Some(())
    }
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

pub unsafe extern "C" fn ares_parse_data<T1, T2>(abuf: *const u8, alen: c_int, out: *mut *mut T2, expected_record_type: u16) -> c_int
where T1: Parser + IntoAresData<T2>, T2: CLinkedList + DataType
{
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let Some(frame) = DnsFrame::parse(&mut Cursor::new(buf)) else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_EBADRESP;
    };
    let [ref query] = frame.queries[..] else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_EBADRESP;
    };
    if frame.answers.len() == 0 {
        return ARES_ENODATA;
    }
    let mut name = CString::new(query.name.join(".")).unwrap();

    let mut replies: Vec<T1> = vec![];
    let mut success = 0;
    for answer in &frame.answers {
        if answer.record_type != expected_record_type {
            success += 1;
            continue;
        }
        let Some(parsed) = T1::parse(&mut Cursor::new(&answer.data)) else {
            continue;
        };
        success += 1;
        if name != answer.name.build_cstring(&buf).unwrap() {
            continue;
        }
        replies.push(parsed);
    }

    let aresreplies: Vec<_> = replies.into_iter().map(|x| x.into_ares_data(&buf)).collect();
    let Some(reply) = clinkedlist::chain_nodes(aresreplies) else {
        unsafe { *out = std::ptr::null_mut() };
        return if success > 0 { ARES_SUCCESS } else { ARES_EBADRESP };
    };

    let aresdata: AresData<T2> = AresData { data_type: T2::datatype(), data: reply };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_mx_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresMxReply) -> c_int {
    unsafe { ares_parse_data::<MxReply, AresMxReply>(abuf, alen, out, RECORD_TYPE_MX) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReply) -> c_int {
    unsafe { ares_parse_data::<TxtReply, AresTxtReply>(abuf, alen, out, RECORD_TYPE_TXT) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_caa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresCaaReply) -> c_int {
    unsafe { ares_parse_data::<CaaReply, AresCaaReply>(abuf, alen, out, RECORD_TYPE_CAA) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_naptr_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresNaptrReply) -> c_int {
    unsafe { ares_parse_data::<NaptrReply, AresNaptrReply>(abuf, alen, out, RECORD_TYPE_NAPTR) }
}

impl DnsLabel {
    pub fn build_cstring(&self, main_buf: &[u8]) -> Option<CString> {
        Some(CString::new(self.build_string(main_buf)?).ok()?)
    }
}


#[no_mangle]
pub unsafe extern "C" fn ares_parse_ns_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    match HostEnt::from_buf(buf, RECORD_TYPE_NS) {
        Ok(hostent) => if !out.is_null() { *out = hostent.into_raw() },
        Err(err) => return err,
    }
    ARES_SUCCESS
}

const RECORD_TYPE_A: u16 = 0x01;
const RECORD_TYPE_NS: u16 = 0x02;
const RECORD_TYPE_CNAME: u16 = 0x05;
const RECORD_TYPE_AAAA: u16 = 0x1c;
const RECORD_TYPE_MX: u16 = 0x0f;
const RECORD_TYPE_TXT: u16 = 0x10;
const RECORD_TYPE_CAA: u16 = 0x101;
const RECORD_TYPE_NAPTR: u16 = 0x23;

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
    pub fn from_buf(buf: &[u8], expected_record_type: u16) -> Result<Self, c_int> {
        let Some(frame) = DnsFrame::parse(&mut Cursor::new(buf)) else {
            return Err(ARES_EBADRESP);
        };
        let [ref query] = frame.queries[..] else {
            return Err(ARES_EBADRESP);
        };
        let expected_length = match expected_record_type {
            RECORD_TYPE_A => 4,
            RECORD_TYPE_AAAA => 16,
            _ => 0,
        };
        let mut name = CString::new(query.name.join(".")).unwrap();
        let mut addrttls: Vec<(std::net::IpAddr, u32)> = vec![];
        let mut addrlist: Vec<std::net::IpAddr> = vec![];
        let mut aliases: Vec<CString> = vec![];
        let mut limit_ttl: Option<u32> = None;
        for mut answer in frame.answers {
            if answer.record_type == RECORD_TYPE_CNAME {
                let alias_of = DnsLabel::parse(&mut Cursor::new(&answer.data)).unwrap();
                let alias_of = alias_of.build_cstring(&buf).unwrap();
                aliases.push(name);
                name = alias_of;
                limit_ttl = Some(answer.ttl);
            }

            if answer.record_type != expected_record_type {
                continue;
            }

            if let Some(limit_ttl) = limit_ttl {
                if answer.ttl > limit_ttl {
                    answer.ttl = limit_ttl;
                }
            }
        
            if expected_length == 0 {
                let alias = DnsLabel::parse(&mut Cursor::new(&answer.data)).unwrap();
                let alias = alias.build_cstring(&buf).unwrap();
                aliases.push(alias);
            } else {
                if answer.data.len() != expected_length {
                    continue;
                }
                if let Ok(ip) = buf_to_ip(&answer.data) {
                    addrlist.push(ip);
                    addrttls.push((ip, answer.ttl));
                }
            }
        }
        if addrlist.len() == 0 && aliases.len() == 0 {
            return Err(ARES_ENODATA);
        }
        let hostent = Self {
            name,
            aliases,
            addrtype: get_addr_type(expected_record_type),
            addrttls,
            length: expected_length as c_int,
            addrlist
        };
        Ok(hostent)
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

unsafe fn fill_addrttls<T: AddrTTL>(host: &HostEnt, addrttls: *mut T, naddrttls: usize) -> usize {
    let mut i = 0;
    for (ip, ttl) in host.addrttls.iter() {
        if i >= naddrttls {
            break;
        }
        if (*addrttls.add(i)).set_addr_ttl(&ip, *ttl).is_some() {
            i += 1;
        }
    }
    i
}

unsafe fn parse_reply<T: AddrTTL>(expected_record_type: u16, abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut T, out_naddrttls: *mut c_int) -> c_int {
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let (ret_code, host_ptr, naddrttls) = match HostEnt::from_buf(buf, expected_record_type) {
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
pub unsafe extern "C" fn ares_parse_a_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addrttl, out_naddrttls: *mut c_int) -> c_int {
    parse_reply(RECORD_TYPE_A, abuf, alen, out, addrttls, out_naddrttls)
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_aaaa_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addr6ttl, out_naddrttls: *mut c_int) -> c_int {
    parse_reply(RECORD_TYPE_AAAA, abuf, alen, out, addrttls, out_naddrttls)
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
