use libc::{close, connect, fcntl, iovec, recvfrom, sockaddr, socket, socklen_t, writev, F_GETFL, F_SETFL, O_NONBLOCK, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM};
use std::ffi::{c_int, c_uint, c_void};
use std::net::SocketAddr;
use std::rc::Rc;
use std::io;
use std::io::{Error, ErrorKind};
use crate::{Channel, ARES_SOCKET_BAD};

#[allow(non_camel_case_types)]
pub type ares_socket_t = c_int;
#[allow(non_camel_case_types)]
pub type ares_ssize_t = libc::ssize_t;

/// # Safety
/// `channel` must be a valid channel and `funcs` must be NULL or point to a valid function table.
#[no_mangle]
pub unsafe extern "C" fn ares_set_socket_functions(channel: Channel, funcs: *const AresSocketFunctions, user_data: *mut c_void) {
    if channel.is_null() || funcs.is_null() { return }
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.socket_factory = SocketFactory::new((unsafe { &*funcs }).clone(), user_data);
}

/// Extended socket functions (c-ares 1.34.6 API).
/// Maps to the basic AresSocketFunctions internally.
#[repr(C)]
pub struct AresSocketFunctionsEx {
    pub version: c_uint,
    pub flags: c_uint,
    pub asocket: Option<unsafe extern "C" fn(c_int, c_int, c_int, *mut c_void) -> ares_socket_t>,
    pub aclose: Option<unsafe extern "C" fn(ares_socket_t, *mut c_void) -> c_int>,
    pub asetsockopt: Option<unsafe extern "C" fn(ares_socket_t, c_int, *const c_void, socklen_t, *mut c_void) -> c_int>,
    pub aconnect: Option<unsafe extern "C" fn(ares_socket_t, *const sockaddr, socklen_t, c_uint, *mut c_void) -> c_int>,
    pub arecvfrom: Option<unsafe extern "C" fn(ares_socket_t, *mut c_void, libc::size_t, c_int, *mut sockaddr, *mut socklen_t, *mut c_void) -> ares_ssize_t>,
    pub asendto: Option<unsafe extern "C" fn(ares_socket_t, *const c_void, libc::size_t, c_int, *const sockaddr, socklen_t, *mut c_void) -> ares_ssize_t>,
    // Additional optional fields omitted — we only use the above
}

/// # Safety
/// `channel` must be a valid channel and `funcs` must be NULL or point to a valid function table.
#[no_mangle]
pub unsafe extern "C" fn ares_set_socket_functions_ex(channel: Channel, funcs: *const AresSocketFunctionsEx, user_data: *mut c_void) -> c_int {
    if channel.is_null() || funcs.is_null() { return 0; }
    let ex = unsafe { &*funcs };
    let basic = AresSocketFunctions {
        asocket: ex.asocket,
        aclose: ex.aclose,
        aconnect: None, // ex.aconnect has different signature (extra flags param)
        arecvfrom: ex.arecvfrom,
        asendv: None, // ex.asendto has different signature
    };
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.socket_factory = SocketFactory::new(basic, user_data);
    0 // ARES_SUCCESS
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct AresSocketFunctions {
    pub asocket: Option<unsafe extern "C" fn(domain: c_int, c_int, c_int, user_data: *mut c_void) -> ares_socket_t>,
    pub aclose: Option<unsafe extern "C" fn(fd: ares_socket_t, user_data: *mut c_void) -> c_int>,
    pub aconnect: Option<unsafe extern "C" fn(fd: ares_socket_t, *const sockaddr, socklen_t, user_data: *mut c_void) -> c_int>,
    pub arecvfrom: Option<unsafe extern "C" fn(fd: ares_socket_t, *mut c_void, libc::size_t, c_int, *mut sockaddr, *mut socklen_t, user_data: *mut c_void) -> ares_ssize_t>,
    pub asendv: Option<unsafe extern "C" fn(fd: ares_socket_t, *const iovec, c_int, user_data: *mut c_void) -> ares_ssize_t>,
}

unsafe extern "C" fn default_asocket(domain: c_int, socket_type: c_int, protocol: c_int, _user_data: *mut c_void) -> ares_socket_t {
    let sock = unsafe { socket(domain, socket_type, protocol) };
    if sock == -1 {
        return ARES_SOCKET_BAD;
    }

    let flags = unsafe { fcntl(sock, F_GETFL) };
    if flags == -1 || unsafe { fcntl(sock, F_SETFL, flags | O_NONBLOCK) } == -1 {
        unsafe { close(sock) };
        return ARES_SOCKET_BAD;
    }

    sock
}

unsafe extern "C" fn default_aclose(sock: ares_socket_t, _user_data: *mut c_void) -> c_int {
    unsafe { close(sock) }
}

unsafe extern "C" fn default_aconnect(sock: ares_socket_t, addr: *const sockaddr, addrlen: socklen_t, _user_data: *mut c_void) -> c_int {
    unsafe { connect(sock, addr, addrlen) }
}

unsafe extern "C" fn default_arecvfrom(sock: ares_socket_t, buf: *mut c_void, len: usize, flags: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t, _user_data: *mut c_void) -> ares_ssize_t {
    unsafe { recvfrom(sock, buf, len, flags, addr, addrlen) }
}

unsafe extern "C" fn default_asendv(sock: ares_socket_t, iov: *const iovec, iovcnt: c_int, _user_data: *mut c_void) -> ares_ssize_t {
    unsafe { writev(sock, iov, iovcnt) }
}

fn socket_addr_to_raw(addr: SocketAddr) -> (libc::sockaddr_storage, socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            let sockaddr = &mut storage as *mut _ as *mut sockaddr_in;
            unsafe {
                (*sockaddr).sin_family = AF_INET as u16;
                (*sockaddr).sin_port = v4.port().to_be();
                (*sockaddr).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            std::mem::size_of::<sockaddr_in>() as socklen_t
        }
        SocketAddr::V6(v6) => {
            let sockaddr = &mut storage as *mut _ as *mut sockaddr_in6;
            unsafe {
                (*sockaddr).sin6_family = AF_INET6 as u16;
                (*sockaddr).sin6_port = v6.port().to_be();
                (*sockaddr).sin6_addr.s6_addr = v6.ip().octets();
                (*sockaddr).sin6_flowinfo = v6.flowinfo();
                (*sockaddr).sin6_scope_id = v6.scope_id();
            }
            std::mem::size_of::<sockaddr_in6>() as socklen_t
        }
    };
    (storage, len)
}

fn raw_to_socket_addr(storage: &libc::sockaddr_storage, len: socklen_t) -> Option<SocketAddr> {
    if len == 0 {
        return None;
    }
    match storage.ss_family as c_int {
        AF_INET => {
            let sockaddr = storage as *const _ as *const sockaddr_in;
            let addr = unsafe {
                let ip = std::net::Ipv4Addr::from(u32::from_be((*sockaddr).sin_addr.s_addr));
                let port = u16::from_be((*sockaddr).sin_port);
                SocketAddr::from((ip, port))
            };
            Some(addr)
        }
        AF_INET6 => {
            let sockaddr = storage as *const _ as *const sockaddr_in6;
            let addr = unsafe {
                let ip = std::net::Ipv6Addr::from((*sockaddr).sin6_addr.s6_addr);
                let port = u16::from_be((*sockaddr).sin6_port);
                SocketAddr::from((ip, port))
            };
            Some(addr)
        }
        _ => None,
    }
}

/// The channel's socket source: the (user-replaceable) C function table.
/// Implements the core `TransportFactory` trait, so the engine never sees
/// the table or the user_data pointer.
pub struct SocketFactory {
    funcs: AresSocketFunctions,
    user_data: *mut c_void,
}

impl Default for SocketFactory {
    fn default() -> Self {
        SocketFactory { funcs: AresSocketFunctions::default(), user_data: std::ptr::null_mut() }
    }
}

/// One socket created from a snapshot of the factory's function table. The
/// snapshot (instead of a factory back-reference) keeps a replaced table
/// alive for sockets that outlive an ares_set_socket_functions() swap —
/// the same semantics the old per-socket Rc<SocketFactory> provided.
struct CSocket {
    fd: ares_socket_t,
    funcs: AresSocketFunctions,
    user_data: *mut c_void,
}

impl crate::core::transport::Transport for CSocket {
    fn as_raw_fd(&self) -> i32 {
        self.fd
    }

    fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let aconnect = self.funcs.aconnect.unwrap_or(default_aconnect);
        let (sockaddr, len) = socket_addr_to_raw(addr);
        let result = unsafe { aconnect(self.fd, &sockaddr as *const _ as *const sockaddr, len, self.user_data) };
        if result == -1 {
            let err = Error::last_os_error();
            if err.kind() == ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EINPROGRESS) {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        let arecvfrom = self.funcs.arecvfrom.unwrap_or(default_arecvfrom);
        let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_storage>() as socklen_t;
        let result = unsafe {
            arecvfrom(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, &mut addr as *mut _ as *mut sockaddr, &mut addrlen, self.user_data)
        };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        let sock_addr = raw_to_socket_addr(&addr, addrlen);
        Ok((result as usize, sock_addr))
    }

    fn send(&self, data: &[u8]) -> io::Result<usize> {
        let asendv = self.funcs.asendv.unwrap_or(default_asendv);
        let iovecs = [iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() }];
        let result = unsafe { asendv(self.fd, iovecs.as_ptr(), 1, self.user_data) };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        Ok(result as usize)
    }
}

impl Drop for CSocket {
    fn drop(&mut self) {
        let aclose = self.funcs.aclose.unwrap_or(default_aclose);
        unsafe { aclose(self.fd, self.user_data) };
    }
}

impl SocketFactory {
    pub fn new(funcs: AresSocketFunctions, user_data: *mut c_void) -> Rc<Self> {
        Rc::new(Self { funcs, user_data })
    }

    fn create(&self, addr: SocketAddr, socket_type: c_int) -> io::Result<Rc<dyn crate::core::transport::Transport>> {
        let domain = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        let asocket = self.funcs.asocket.unwrap_or(default_asocket);
        let fd = unsafe { asocket(domain, socket_type, 0, self.user_data) };
        if fd == ARES_SOCKET_BAD {
            return Err(Error::last_os_error());
        }
        Ok(Rc::new(CSocket { fd, funcs: self.funcs.clone(), user_data: self.user_data }))
    }
}

impl crate::core::transport::TransportFactory for SocketFactory {
    fn create_udp(&self, bind: SocketAddr) -> io::Result<Rc<dyn crate::core::transport::Transport>> {
        self.create(bind, SOCK_DGRAM)
    }

    fn create_tcp(&self, bind: SocketAddr) -> io::Result<Rc<dyn crate::core::transport::Transport>> {
        self.create(bind, SOCK_STREAM)
    }
}
