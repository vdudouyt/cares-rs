use std::os::raw::{ c_int, c_void, c_char };
use std::os::fd::{ AsRawFd };
use std::ffi::{ CString, CStr };
use std::io::Cursor;
use crate::packets::*;
use crate::ares::{ Ares, Status, Family };
use std::net::Ipv4Addr;

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
struct FFIData {
    callback: AresHostCallback,
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
    let ffidata = FFIData { callback, arg };
    channeldata.ares.gethostbyname(&hostname, family, ffidata);
}

pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);

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

fn build_hostent(buf: Vec<u8>, result: DnsFrame, ffidata: &FFIData) {
    let reply_code = result.flags & 0x0f;
    if reply_code > 0 {
        let status = match reply_code {
            3 => ARES_ENOTFOUND,
            _ => ARES_ESERVFAIL,
        };
        return unsafe { (ffidata.callback)(ffidata.arg, status, 0, std::ptr::null_mut()) };
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
    unsafe { (ffidata.callback)(ffidata.arg, ARES_SUCCESS, 0, &mut hostent) };
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    let channeldata = unsafe { &mut *channel };
    for task in &mut channeldata.ares.tasks {
        if task.is_expired() {
            let ffidata = &task.userdata;
            unsafe { (ffidata.callback)(ffidata.arg, ARES_ETIMEOUT, 0, std::ptr::null_mut()) };
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
                build_hostent(buf, frame, &task.userdata);
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
