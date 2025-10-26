use std::os::raw::{ c_int, c_void, c_char, c_ushort };
use std::os::fd::{ AsRawFd };
use std::ffi::{ CString, CStr };
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::mem::{ ManuallyDrop, offset_of };
use crate::core::packets::*;
use crate::core::ares::{ Ares, Status, Family };

pub const ARES_SUCCESS: i32 = 0;
pub const ARES_ENODATA: i32 = 1;
pub const ARES_EFORMERR: i32 = 2;
pub const ARES_ESERVFAIL: i32 = 3;
pub const ARES_ENOTFOUND: i32 = 4;
pub const ARES_ETIMEOUT: i32 = 12;

pub const ARES_LIB_INIT_ALL: i32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn ares_library_init(_flags: c_int) -> c_int {
    ARES_SUCCESS
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let ares = Ares::from_sysconfig();
    let channeldata = ChannelData { ares };
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    unsafe { drop(Box::from_raw(channel)); }
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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
pub union AresDataUnion {
    mxreply: std::mem::ManuallyDrop<AresMxReply>,
    txtreply: std::mem::ManuallyDrop<AresTxtReply>,
}

#[repr(C)]
struct AresData {
    data_type: AresDataType,
    data: AresDataUnion,
}

#[repr(C)]
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_parse_mx_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresMxReply) -> c_int {
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let frame = DnsFrame::parse(&mut Cursor::new(buf)).unwrap();
    let mut head = Box::into_raw(Box::new(AresMxReply { next: std::ptr::null_mut(), host: std::ptr::null_mut(), priority: 0 }));
    let mut res = head;
    for answer in &frame.answers {
        if !unsafe { (*res).host.is_null() } {
            (*res).next = Box::into_raw(Box::new(AresMxReply { next: res, host: std::ptr::null_mut(), priority: 0 }));
            res = (*res).next;
        }
        let mxreply = MxReply::parse(&mut Cursor::new(&answer.data)).unwrap();
        let mut name = mxreply.label.name.clone();
        if let Some(offset) = mxreply.label.offset {
            let mut label = DnsLabel::parse(&mut Cursor::new(&buf[offset as usize..])).unwrap();
            name.append(&mut label.name);
        }
        let name = name.join(".");
        let name = CString::new(name).unwrap();
        let raw_ptr = name.into_raw();
        unsafe {
            (*res).host = raw_ptr;
            (*res).priority = mxreply.priority;
        }
    }
    let mx = unsafe { *Box::from_raw(head) };
    let data = AresDataUnion { mxreply: ManuallyDrop::new(mx) };
    let aresdata = AresData { data_type: AresDataType::MxReply, data };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut *(*aresdata).data.mxreply };
    ARES_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_parse_txt_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReply) -> c_int {
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let frame = DnsFrame::parse(&mut Cursor::new(buf)).unwrap();
    let mut head = Box::into_raw(Box::new(AresTxtReply { next: std::ptr::null_mut(), txt: std::ptr::null_mut(), length: 0 }));
    let mut res = head;
    for answer in &frame.answers {
        if !unsafe { (*res).txt.is_null() } {
            (*res).next = Box::into_raw(Box::new(AresTxtReply { next: std::ptr::null_mut(), txt: std::ptr::null_mut(), length: 0 }));
            res = (*res).next;
        }
        let txtreply = TxtReply::parse(&mut Cursor::new(&answer.data)).unwrap();
        let length = txtreply.txt.len();
        let txt = CString::new(txtreply.txt).unwrap().into_raw();
        unsafe {
            (*res).txt = txt;
            (*res).length = length;
        }
    }
    let txt = unsafe { *Box::from_raw(head) };
    let data = AresDataUnion { txtreply: ManuallyDrop::new(txt) };
    let aresdata = AresData { data_type: AresDataType::TxtReply, data };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut *(*aresdata).data.txtreply };
    ARES_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_parse_ns_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let frame = DnsFrame::parse(&mut Cursor::new(buf)).unwrap();

    let Some(answer) = frame.answers.first() else { return ARES_ENODATA };
    let mut name = answer.name.name.clone();
    if let Some(offset) = answer.name.offset {
        let mut label = DnsLabel::parse(&mut Cursor::new(&buf[offset as usize..])).unwrap();
        name.append(&mut label.name);
    }
    let name = name.join(".");
    let name = CString::new(name).unwrap();

    let mut aliases: Vec<*mut c_char> = vec![];
    for answer in &frame.answers {
        let mut label = DnsLabel::parse(&mut Cursor::new(&answer.data)).unwrap();
        let mut name = label.name.clone();
        if let Some(offset) = label.offset {
            let mut label = DnsLabel::parse(&mut Cursor::new(&buf[offset as usize..])).unwrap();
            name.append(&mut label.name);
        }
        let nameserver = name.join(".");
        let nameserver = CString::new(nameserver).unwrap();
        aliases.push(nameserver.into_raw());
    }
    aliases.push(std::ptr::null_mut());
    let aliases_ptr = libc::calloc(aliases.len() + 1, std::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
    std::ptr::copy_nonoverlapping(aliases.as_ptr(), aliases_ptr, aliases.len() + 1);

    let addr_list: Vec<*mut c_char> = vec![std::ptr::null_mut()];
    let addr_list_ptr = libc::calloc(addr_list.len() + 1, std::mem::size_of::<*mut c_char>()) as *mut *mut c_char;

    let mut hostent = libc::hostent {
        h_name: name.into_raw(),
        h_aliases: aliases_ptr,
        h_addrtype: 0,
        h_length: answer.data.len() as c_int,
        h_addr_list: addr_list_ptr,
    };
    let hostent = Box::into_raw(Box::new(hostent));
    unsafe { *out = hostent };

    ARES_SUCCESS
}

static ARES_ERROR: &[u8] = b"ares error\0";
static ARES_ERROR_CSTR: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(ARES_ERROR) };

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_strerror(code: c_int) -> *const i8 {
    ARES_ERROR_CSTR.as_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_free_data(dataptr: *mut c_void) {
    let aresdata = unsafe { dataptr.byte_sub(offset_of!(AresData, data)) as *mut AresData };
    let mut aresdata = unsafe { Box::from_raw(aresdata) };
    match aresdata.data_type {
        AresDataType::MxReply => unsafe { ManuallyDrop::drop(&mut aresdata.data.mxreply) },
        AresDataType::TxtReply => unsafe { ManuallyDrop::drop(&mut aresdata.data.txtreply) },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_free_hostent(hostent: *mut libc::hostent) {
    let mut hostent = Box::from_raw(hostent);
    CString::from_raw((*hostent).h_name);

    let mut ptr: *mut *mut c_char = hostent.h_aliases;
    while !(*ptr).is_null() {
        CString::from_raw(*ptr);
        ptr = ptr.add(1);
    }
    libc::free(hostent.h_aliases as *mut c_void);

    let mut ptr: *mut *mut c_char = hostent.h_addr_list;
    while !(*ptr).is_null() {
        CString::from_raw(*ptr);
        ptr = ptr.add(1);
    }
    libc::free(hostent.h_addr_list as *mut c_void);
}

pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);
pub type AresCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int);

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

    let mut addr_list: Vec<*const u8> = vec![];
    for answer in &result.answers {
        addr_list.push(answer.data.as_ptr());
    }
    addr_list.push(std::ptr::null());

    let Some(answer) = result.answers.first() else { return };
    let mut name = answer.name.name.clone();
    if let Some(offset) = answer.name.offset {
        let mut label = DnsLabel::parse(&mut Cursor::new(&buf[offset as usize..])).unwrap();
        name.append(&mut label.name);
    }
    let name = name.join(".");
    let name = CString::new(name).unwrap();

    let aliases: Vec<*mut c_char> = vec![std::ptr::null_mut()];
    let h_addrtype = match answer.record_type {
        0x01 => libc::AF_INET,
        0x1c => libc::AF_INET6,
        _ => panic!("Unexpected DNS record type in answer: {}", answer.record_type),
    };
    let mut hostent = libc::hostent {
        h_name: name.as_ptr() as *mut c_char,
        h_aliases: aliases.as_ptr() as *mut *mut c_char,
        h_addrtype,
        h_length: answer.data.len() as c_int,
        h_addr_list: addr_list.as_ptr() as *mut *mut c_char,
    };
    unsafe { callback(arg, ARES_SUCCESS, 0, &mut hostent) };
}

fn run_ares_callback(buf: Vec<u8>, _result: DnsFrame, callback: AresCallback, arg: *mut c_void) {
    unsafe { callback(arg, ARES_SUCCESS, 0, buf.as_ptr() as *mut u8, buf.len() as i32) };
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers(channel: Channel, mut head: *mut ares_addr_node) {
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.config.nameservers.clear();
    while !head.is_null() {
        if unsafe { (*head).family } == libc::AF_INET {
            let node = unsafe { &(*head) };
            let oct4: [u8; 4] = node.data[0..4].try_into().unwrap();
            channeldata.ares.config.nameservers.push(Ipv4Addr::from(oct4).to_string());
        }
        head = unsafe { (*head).next };
    }
}
