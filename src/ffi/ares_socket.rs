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

pub(crate) unsafe fn set_socket_functions(channel: Channel, funcs: *const AresSocketFunctions, user_data: *mut c_void) {
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

pub(crate) unsafe fn set_socket_functions_ex(channel: Channel, funcs: *const AresSocketFunctionsEx, user_data: *mut c_void) -> c_int {
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

// SocketFactory impl
pub struct SocketFactory {
    funcs: AresSocketFunctions,
    user_data: *mut c_void,
}

impl Default for SocketFactory {
    fn default() -> Self {
        SocketFactory { funcs: AresSocketFunctions::default(), user_data: std::ptr::null_mut() }
    }
}

pub struct UdpSocket {
    fd: ares_socket_t,
    factory: Rc<SocketFactory>,
}

impl UdpSocket {
    pub fn as_raw_fd(&self) -> ares_socket_t {
        self.fd
    }

    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.factory.aconnect(self.fd, addr)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        self.factory.arecvfrom(self.fd, buf)
    }

    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.factory.asendv(self.fd, &[data])
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.factory.aclose(self.fd);
    }
}

pub struct TcpSocket {
    fd: ares_socket_t,
    factory: Rc<SocketFactory>,
}

impl TcpSocket {
    pub fn as_raw_fd(&self) -> ares_socket_t {
        self.fd
    }

    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.factory.aconnect(self.fd, addr)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        self.factory.arecvfrom(self.fd, buf)
    }

    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.factory.asendv(self.fd, &[data])
    }
}

impl Drop for TcpSocket {
    fn drop(&mut self) {
        self.factory.aclose(self.fd);
    }
}

impl SocketFactory {
    pub fn new(funcs: AresSocketFunctions, user_data: *mut c_void) -> Rc<Self> {
        Rc::new(Self { funcs, user_data })
    }

    pub fn create_udp(self: &Rc<Self>, addr: SocketAddr) -> io::Result<UdpSocket> {
        let domain = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        let asocket = self.funcs.asocket.unwrap_or(default_asocket);
        let fd = unsafe { asocket(domain, SOCK_DGRAM, 0, self.user_data) };
        if fd == ARES_SOCKET_BAD {
            return Err(Error::last_os_error());
        }
        Ok(UdpSocket { fd, factory: Rc::clone(self) })
    }

    pub fn create_tcp(self: &Rc<Self>, addr: SocketAddr) -> io::Result<TcpSocket> {
        let domain = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        let asocket = self.funcs.asocket.unwrap_or(default_asocket);
        let fd = unsafe { asocket(domain, SOCK_STREAM, 0, self.user_data) };
        if fd == ARES_SOCKET_BAD {
            return Err(Error::last_os_error());
        }
        Ok(TcpSocket { fd, factory: Rc::clone(self) })
    }

    fn aclose(&self, fd: ares_socket_t) -> c_int {
        let aclose = self.funcs.aclose.unwrap_or(default_aclose);
        unsafe { aclose(fd, self.user_data) }
    }

    fn aconnect(&self, fd: ares_socket_t, addr: SocketAddr) -> io::Result<()> {
        let aconnect = self.funcs.aconnect.unwrap_or(default_aconnect);
        let (sockaddr, len) = socket_addr_to_raw(addr);
        let result = unsafe { aconnect(fd, &sockaddr as *const _ as *const sockaddr, len, self.user_data) };
        if result == -1 {
            let err = Error::last_os_error();
            if err.kind() == ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EINPROGRESS) {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    fn arecvfrom(&self, fd: ares_socket_t, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        let arecvfrom = self.funcs.arecvfrom.unwrap_or(default_arecvfrom);
        let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_storage>() as socklen_t;
        let result = unsafe {
            arecvfrom(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, &mut addr as *mut _ as *mut sockaddr, &mut addrlen, self.user_data)
        };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        let sock_addr = raw_to_socket_addr(&addr, addrlen);
        Ok((result as usize, sock_addr))
    }

    fn asendv(&self, fd: ares_socket_t, bufs: &[&[u8]]) -> io::Result<usize> {
        let asendv = self.funcs.asendv.unwrap_or(default_asendv);
        assert!(bufs.len() <= 4, "asendv: more than 4 buffers not supported");
        let mut iovecs = [iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 4];
        for (i, b) in bufs.iter().enumerate() {
            iovecs[i] = iovec { iov_base: b.as_ptr() as *mut c_void, iov_len: b.len() };
        }
        let result = unsafe { asendv(fd, iovecs.as_ptr(), bufs.len() as c_int, self.user_data) };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        Ok(result as usize)
    }
}
