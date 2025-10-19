use std::os::raw::{ c_int, c_void, c_char };
use std::os::fd::{ AsRawFd };
use std::net::UdpSocket;
use std::ffi::{ CString, CStr };
use std::io::Cursor;
use bytes::BytesMut;
use rand::Rng;
use crate::packets::*;
use crate::sysconfig::SysConfig;
use crate::ares::Ares;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::task::Poll;

pub const ARES_SUCCESS: i32 = 0;
pub const ARES_ENODATA: i32 = 1;
pub const ARES_EFORMERR: i32 = 2;
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
    ares: Ares,
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
    let channeldata = ChannelData { ares: Ares::from_sysconfig() };
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    unsafe { drop(Box::from_raw(channel)); }
}

#[derive(Debug)]
struct FFIData {
    callback: AresHostCallback,
    arg: *mut c_void,
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, hostname: *const c_char, _family: c_int, callback: AresHostCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    let hostname = unsafe { CStr::from_ptr(hostname).to_string_lossy() };
    let ffidata = FFIData { callback, arg };
    channeldata.ares.gethostbyname(&hostname, Box::new(ffidata));
}

pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_fds(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    unsafe { libc::FD_ZERO(write_fds) };
    unsafe { libc::FD_ZERO(read_fds) };
    let channeldata = unsafe { &mut *channel };
    let mut nfds = 0;
    for task in &channeldata.ares.tasks {
        let Some(task) = task.upgrade() else { continue };
        let fd = task.sock.as_raw_fd();
        if task.is_writing() {
            libc::FD_SET(fd, write_fds);
            if nfds < fd { nfds = fd + 1 }
        } else if task.is_reading() {
            libc::FD_SET(fd, read_fds);
            if nfds < fd { nfds = fd + 1 }
        }
    }
    nfds
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_timeout(_channel: Channel, _maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval {
    // we do not have any retransmission support yet
    unsafe {
        (*tv).tv_sec = 3;
        (*tv).tv_usec = 0;
    };
    tv
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    let channeldata = unsafe { &mut *channel };
    let mut nfds = 0;
    for task in &channeldata.ares.tasks {
        let task = task.upgrade().unwrap();
        let ret = if task.is_writing() && unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), write_fds) } {
            Some(channeldata.ares.resume_task(&task))
        } else if task.is_reading() && unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), read_fds) } {
            Some(channeldata.ares.resume_task(&task))
        } else {
            None
        };
        if let Some(Poll::Ready((buf, frame))) = ret {
            let ffidata = task.userdata.downcast_ref::<FFIData>().unwrap();
            build_hostent(buf, frame, ffidata);
        }
    }
}

fn build_hostent(buf: Vec<u8>, result: DnsFrame, ffidata: &FFIData) {
    for answer in &result.answers {
        let mut name = answer.name.name.clone();
        if let Some(offset) = answer.name.offset {
            let mut label = DnsLabel::parse(&mut Cursor::new(&buf[offset as usize..])).unwrap();
            name.append(&mut label.name);
        }
        let name = name.join(".");
        /* construct hostent */
        let name = CString::new(name).unwrap();
        let aliases_vec: Vec<*mut c_char> = vec![std::ptr::null_mut()];
        let aliases: Box<[*mut c_char]> = aliases_vec.into_boxed_slice();
        let addr_ptr = answer.data.as_ptr();
        let addr_list = [ addr_ptr, std::ptr::null_mut() ];

        let mut hostent = libc::hostent {
            h_name: name.as_ptr() as *mut c_char,
            h_aliases: aliases.as_ptr() as *mut *mut c_char,
            h_addrtype: libc::AF_INET,
            h_length: answer.data.len() as c_int,
            h_addr_list: addr_list.as_ptr() as *mut *mut c_char,
        };
        unsafe { (ffidata.callback)(ffidata.arg, ARES_SUCCESS, 0, &mut hostent) };
    }
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
