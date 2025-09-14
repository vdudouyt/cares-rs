use std::os::raw::{ c_int, c_void, c_char };
use std::os::fd::{ AsRawFd };
use std::net::UdpSocket;
use std::ffi::{ CString, CStr };
use std::io::Cursor;
use bytes::BytesMut;
use rand::Rng;
use crate::packets::*;

pub const ARES_SUCCESS: i32 = 0;
pub const ARES_ENODATA: i32 = 1;
pub const ARES_EFORMERR: i32 = 2;

pub const ARES_LIB_INIT_ALL: i32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn ares_library_init(_flags: c_int) -> c_int {
    ARES_SUCCESS
}

pub type Channel = *mut ChannelData;

#[derive(PartialEq)]
enum Status { Writing, Reading, Completed }

struct Task {
    status: Status,
    sock: UdpSocket,
    writebuf: BytesMut,
    callback: AresHostCallback,
    arg: *mut c_void,
}

pub struct ChannelData {
    tasks: Vec<Task>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let channeldata = ChannelData { tasks: vec![] };
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    unsafe { drop(Box::from_raw(channel)); }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, hostname: *const c_char, family: c_int, callback: AresHostCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    let hostname = unsafe { CStr::from_ptr(hostname).to_string_lossy() };
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)) else {
        return; // TODO: trigger callback()
    };
    let _ = sock.set_nonblocking(true);
    let query = DnsQuery {
        name: hostname.split(".").map(str::to_owned).collect(),
        qtype: 1,
        qclass: 1,
    };
    let request = DnsFrame {
        transaction_id: rand::thread_rng().r#gen::<u16>(),
        queries: vec![query],
        answers: vec![],
    };
    let mut task = Task { status: Status::Writing, sock, writebuf: BytesMut::new(), callback, arg };
    request.write(&mut task.writebuf);
    channeldata.tasks.push(task);
}

type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_fds(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    let channeldata = unsafe { &mut *channel };
    unsafe { libc::FD_ZERO(write_fds) };
    unsafe { libc::FD_ZERO(read_fds) };

    let mut nfds = 0;
    for task in &channeldata.tasks {
        let fd = task.sock.as_raw_fd();
        match task.status {
            Status::Writing => unsafe { libc::FD_SET(fd, write_fds) },
            Status::Reading => unsafe { libc::FD_SET(fd, read_fds) },
            Status::Completed => continue,
        };
        if nfds < fd { nfds = fd + 1 }
    }
    return nfds;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_timeout(channel: Channel, _maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval {
    // we do not have any retransmission support yet
    unsafe {
        (*tv).tv_sec = 3;
        (*tv).tv_usec = 0;
    };
    return tv;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    let channeldata = unsafe { &mut *channel };
    for task in &mut channeldata.tasks {
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), write_fds) } {
            let len = task.sock.send_to(&task.writebuf, ("8.8.8.8", 53)).unwrap();
            task.status = Status::Reading;
        }
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), read_fds) } {
            let mut buf = vec![0u8; 65_535];
            let (len, src) = task.sock.recv_from(&mut buf).unwrap();
            task.status = Status::Completed;

            let mut cur = Cursor::new(&buf[0..len]);
            let frame = DnsFrame::parse(&mut cur).unwrap();
            for answer in &frame.answers {
                let mut name = answer.name.name.clone();
                if let Some(offset) = answer.name.offset {
                    let mut label = DnsLabel::parse(&mut Cursor::new(&buf[offset as usize..len])).unwrap();
                    name.append(&mut label.name);
                }
                let name = name.join(".");

                /* construct hostent */
                let name = CString::new(name).unwrap();
                let mut aliases_vec: Vec<*mut c_char> = vec![std::ptr::null_mut()];
                let aliases: Box<[*mut c_char]> = aliases_vec.into_boxed_slice();
                let addr_ptr = answer.data.as_ptr();
                let addr_list = vec![ addr_ptr, std::ptr::null_mut() ];

                let mut hostent = libc::hostent {
                    h_name: name.as_ptr() as *mut c_char,
                    h_aliases: aliases.as_ptr() as *mut *mut c_char,
                    h_addrtype: libc::AF_INET,
                    h_length: answer.data.len() as c_int,
                    h_addr_list: addr_list.as_ptr() as *mut *mut c_char,
                };

                let addr_ptr = answer.data.as_ptr();
                (task.callback)(task.arg, ARES_SUCCESS, 0, &mut hostent);
            }
        }
    }
    channeldata.tasks.retain(|t| t.status != Status::Completed);
}
