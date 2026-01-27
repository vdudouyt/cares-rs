use libc::{close, connect, fcntl, iovec, recvfrom, sockaddr, socket, socklen_t, writev, F_GETFL, F_SETFL, O_NONBLOCK};
use std::ffi::{c_int, c_void};
use crate::{Channel, ARES_SOCKET_BAD};

pub type ares_socket_t = c_int;
pub type ares_ssize_t = isize;

#[repr(C)]
pub struct AresSocketFunctions {
    pub asocket: Option<unsafe extern "C" fn(domain: c_int, c_int, c_int, user_data: *mut c_void) -> ares_socket_t>,
    pub aclose: Option<unsafe extern "C" fn(fd: ares_socket_t, user_data: *mut c_void) -> c_int>,
    pub aconnect: Option<unsafe extern "C" fn(fd: ares_socket_t, *const sockaddr, socklen_t, user_data: *mut c_void) -> c_int>,
    pub arecvfrom: Option<unsafe extern "C" fn(fd: ares_socket_t, *mut c_void, usize, c_int, *mut sockaddr, *mut socklen_t, user_data: *mut c_void) -> ares_ssize_t>,
    pub asendv: Option<unsafe extern "C" fn(fd: ares_socket_t, *const iovec, c_int, user_data: *mut c_void) -> ares_ssize_t>,
}

pub unsafe extern "C" fn ares_set_socket_functions(channel: Channel, funcs: *const AresSocketFunctions, user_data: *mut c_void) {
    todo!()
}

unsafe extern "C" fn default_asocket(domain: c_int, socket_type: c_int, protocol: c_int, _user_data: *mut c_void) -> ares_socket_t {
    let sock = socket(domain, socket_type, protocol);
    if sock == -1 {
        return ARES_SOCKET_BAD;
    }

    let flags = fcntl(sock, F_GETFL);
    if flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1 {
        close(sock);
        return ARES_SOCKET_BAD;
    }

    sock
}

unsafe extern "C" fn default_aclose(sock: ares_socket_t, _user_data: *mut c_void) -> c_int {
    close(sock)
}

unsafe extern "C" fn default_aconnect(sock: ares_socket_t, addr: *const sockaddr, addrlen: socklen_t, _user_data: *mut c_void) -> c_int {
    connect(sock, addr, addrlen)
}

unsafe extern "C" fn default_arecvfrom(sock: ares_socket_t, buf: *mut c_void, len: usize, flags: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t, _user_data: *mut c_void) -> ares_ssize_t {
    recvfrom(sock, buf, len, flags, addr, addrlen)
}

unsafe extern "C" fn default_asendv(sock: ares_socket_t, iov: *const iovec, iovcnt: c_int, _user_data: *mut c_void) -> ares_ssize_t {
    writev(sock, iov, iovcnt)
}

impl AresSocketFunctions {
    fn default() -> Self {
        AresSocketFunctions {
            asocket: Some(default_asocket),
            aclose: Some(default_aclose),
            aconnect: Some(default_aconnect),
            arecvfrom: Some(default_arecvfrom),
            asendv: Some(default_asendv),
        }
    }
}
