mod ares_data;
mod ares_hostent;
mod cnullterminated;
mod cstr;
mod clinkedlist;
mod error;
mod offset_of;

use std::os::raw::{ c_int, c_void, c_char, c_ushort };
use std::os::fd::{ AsRawFd };
use std::ffi::{ CString, CStr };
use std::io::Cursor;
use std::net::{ Ipv4Addr, SocketAddr };
use crate::core::packets::*;
use crate::core::ares::{ Ares, Status, Family };
use crate::core::servers_csv;
use crate::ffi::ares_hostent::*;
use crate::ffi::ares_data::IntoAresData;
use crate::ffi::clinkedlist::*;
use crate::{ cstr, offset_of };

pub const ARES_SUCCESS: i32 = 0;
pub const ARES_ENODATA: i32 = 1;
pub const ARES_EFORMERR: i32 = 2;
pub const ARES_ESERVFAIL: i32 = 3;
pub const ARES_ENOTFOUND: i32 = 4;
pub const ARES_ETIMEOUT: i32 = 12;

pub const ARES_LIB_INIT_ALL: i32 = 1;

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

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let ares = Ares::from_sysconfig();
    let channeldata = ChannelData { ares };
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
    channeldata.ares.gethostbyname(&hostname, family, ffidata);
}

#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: AresCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    let name = unsafe { CStr::from_ptr(name).to_string_lossy() };
    let ffidata = FFIData { callback: Callback::AresCallback(callback), arg };
    channeldata.ares.query(&name, dnsclass as u16, dnstype as u16, ffidata);
}

#[repr(C)]
#[derive(Debug)]
pub enum AresDataType {
    MxReply,
    TxtReply,
}

#[repr(C)]
struct AresData<T> {
    data_type: AresDataType,
    data: T,
}

#[repr(C)]
#[derive(Debug)]
pub struct AresMxReply {
    next: *mut AresMxReply,
    host: *const c_char,
    priority: c_ushort,
}

#[repr(C)]
pub struct AresTxtReply {
    next: *mut AresTxtReply,
    txt: *const c_char,
    length: usize, // null termination excluded
}

impl Drop for AresMxReply {
    fn drop(&mut self) {
        drop(unsafe { CString::from_raw(self.host as *mut c_char) });
        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) })
        }
    }
}

impl Drop for AresTxtReply {
    fn drop(&mut self) {
        drop(unsafe { CString::from_raw(self.txt as *mut c_char) });
        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) })
        }
    }
}

impl CLinkedList for AresMxReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresTxtReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

pub trait DataType {
    fn datatype() -> AresDataType;
}

impl DataType for AresMxReply {
    fn datatype() -> AresDataType { AresDataType::MxReply }
}

impl DataType for AresTxtReply {
    fn datatype() -> AresDataType { AresDataType::TxtReply }
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

#[no_mangle]
pub unsafe extern "C" fn ares_parse_a_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    let hostent = unsafe { parse_hostent(abuf, alen, HostentParseMode::Addrs4).unwrap() };
    let hostent = Box::into_raw(Box::new(hostent));
    unsafe { *out = hostent };
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_aaaa_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    let hostent = unsafe { parse_hostent(abuf, alen, HostentParseMode::Addrs6).unwrap() };
    let hostent = Box::into_raw(Box::new(hostent));
    unsafe { *out = hostent };
    ARES_SUCCESS
}

unsafe fn restore_original_ptr(dataptr: *mut c_void) -> *mut c_void {
    dataptr.byte_sub(offset_of!(AresData<*mut c_void>, data))
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_data(dataptr: *mut c_void) {
    let aresdata = restore_original_ptr(dataptr) as *mut AresData<*mut c_void>;
    match (*aresdata).data_type {
        AresDataType::MxReply => drop(Box::from_raw(aresdata as *mut AresData<AresMxReply>)),
        AresDataType::TxtReply => drop(Box::from_raw(aresdata as *mut AresData<AresTxtReply>)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_hostent(hostent: *mut libc::hostent) {
    unsafe { free_hostent(hostent) };
}

pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);
pub type AresCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int);

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
            channeldata.ares.config.nameservers.push(SocketAddr::from((Ipv4Addr::from(oct4), 53)));
        }
        head = unsafe { (*head).next };
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    impl Default for AresMxReply {
        fn default() -> Self {
            AresMxReply { next: std::ptr::null_mut(), host: CString::new("default").unwrap().into_raw(), priority: 1 }
        }
    }

    impl Default for AresTxtReply {
        fn default() -> Self {
            AresTxtReply { next: std::ptr::null_mut(), txt: CString::new("default").unwrap().into_raw(), length: 0}
        }
    }

    #[test]
    fn test_restore_original_ptr() {
        test_restore_original_ptr_impl::<AresMxReply>();
        test_restore_original_ptr_impl::<AresTxtReply>();
    }

    fn test_restore_original_ptr_impl<T>() where T: Default + DataType {
        let data = T::default();
        let base: AresData<T> = AresData { data_type: T::datatype(), data };
        let dataptr = std::ptr::addr_of!(base.data) as *mut c_void;
        let restoredptr = unsafe { restore_original_ptr(dataptr) };
        assert_eq!(std::ptr::addr_of!(base) as *mut c_void, restoredptr);
    }
}


