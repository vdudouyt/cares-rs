use libc::{bind, close, connect, fcntl, iovec, recvfrom, setsockopt, sockaddr, socket, socklen_t, writev, F_GETFL, F_SETFL, O_NONBLOCK, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};
use std::cell::Cell;
use std::ffi::{c_int, c_uint, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::io;
use std::io::{Error, ErrorKind};
use crate::ffi::ares_options::ares_sock_state_cb;
use crate::ffi::channel::ChannelData;
use crate::ffi::channel::channel_access;
use crate::ffi::{ares_sock_config_callback, ares_sock_create_callback};
use crate::{Channel, ARES_SOCKET_BAD};

#[allow(non_camel_case_types)]
pub type ares_socket_t = c_int;
#[allow(non_camel_case_types)]
pub type ares_ssize_t = libc::ssize_t;

pub const ARES_FD_EVENT_NONE: c_uint = 0;
pub const ARES_FD_EVENT_READ: c_uint = 1 << 0;
pub const ARES_FD_EVENT_WRITE: c_uint = 1 << 1;

pub const ARES_PROCESS_FLAG_NONE: c_uint = 0;
pub const ARES_PROCESS_FLAG_SKIP_NON_FD: c_uint = 1 << 0;

/// One fd + event mask, used by ares_process_fds().
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct ares_fd_events_t {
    pub fd: ares_socket_t,
    pub events: c_uint,
}

pub const ARES_SOCKET_OPT_SENDBUF_SIZE: c_uint = 0;
pub const ARES_SOCKET_OPT_RECVBUF_SIZE: c_uint = 1;
pub const ARES_SOCKET_OPT_BIND_DEVICE: c_uint = 2;
pub const ARES_SOCKET_OPT_TCP_FASTOPEN: c_uint = 3;

pub const ARES_SOCKET_CONN_TCP_FASTOPEN: c_uint = 1 << 0;

pub const ARES_SOCKET_BIND_TCP: c_uint = 1 << 0;
pub const ARES_SOCKET_BIND_CLIENT: c_uint = 1 << 1;

pub const ARES_SOCKFUNC_FLAG_NONBLOCKING: c_uint = 1 << 0;

/// # Safety
/// `channel` must be a valid channel and `funcs` must be NULL or point to a valid function table.
#[no_mangle]
pub unsafe extern "C" fn ares_set_socket_functions(channel: Channel, funcs: *const AresSocketFunctions, user_data: *mut c_void) {
    if funcs.is_null() || channel.is_null() { return; }
    let funcs = unsafe { &*funcs };
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    install_socket_functions(channeldata, funcs, user_data);
}

fn install_socket_functions(
    channeldata: &mut ChannelData,
    funcs: &AresSocketFunctions,
    user_data: *mut c_void,
) {
    let factory = CSocketFactory::with_funcs(funcs.clone(), user_data, &channeldata.socket_factory);
    channeldata.apply_socket_factory(factory);
}

/// Extended socket functions (c-ares 1.34.6), mapped onto `AresSocketFunctions` internally.
#[repr(C)]
pub struct AresSocketFunctionsEx {
    pub version: c_uint,
    pub flags: c_uint,
    pub asocket: Option<unsafe extern "C" fn(c_int, c_int, c_int, *mut c_void) -> ares_socket_t>,
    pub aclose: Option<unsafe extern "C" fn(ares_socket_t, *mut c_void) -> c_int>,
    pub asetsockopt: Option<unsafe extern "C" fn(ares_socket_t, crate::ffi::ares_socket_opt_t, *const c_void, socklen_t, *mut c_void) -> c_int>,
    pub aconnect: Option<unsafe extern "C" fn(ares_socket_t, *const sockaddr, socklen_t, c_uint, *mut c_void) -> c_int>,
    pub arecvfrom: Option<unsafe extern "C" fn(ares_socket_t, *mut c_void, libc::size_t, c_int, *mut sockaddr, *mut socklen_t, *mut c_void) -> ares_ssize_t>,
    pub asendto: Option<unsafe extern "C" fn(ares_socket_t, *const c_void, libc::size_t, c_int, *const sockaddr, socklen_t, *mut c_void) -> ares_ssize_t>,
    pub agetsockname: Option<unsafe extern "C" fn(ares_socket_t, *mut sockaddr, *mut socklen_t, *mut c_void) -> c_int>,
    pub abind: Option<unsafe extern "C" fn(ares_socket_t, c_uint, *const sockaddr, socklen_t, *mut c_void) -> c_int>,
    pub aif_nametoindex: Option<unsafe extern "C" fn(*const libc::c_char, *mut c_void) -> c_uint>,
    pub aif_indextoname: Option<unsafe extern "C" fn(c_uint, *mut libc::c_char, libc::size_t, *mut c_void) -> *const libc::c_char>,
}

/// # Safety
/// `channel` must be a valid channel and `funcs` must be NULL or point to a valid function table.
#[no_mangle]
pub unsafe extern "C" fn ares_set_socket_functions_ex(channel: Channel, funcs: *const AresSocketFunctionsEx, user_data: *mut c_void) -> crate::ffi::ares_status_t {
    if channel.is_null() || funcs.is_null() {
        return crate::ffi::error::ARES_EFORMERR;
    }
    // SAFETY: the caller guarantees valid channel + function-table pointers.
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return crate::ffi::error::ARES_EFORMERR; };
    let ex = unsafe { &*funcs };
    install_socket_functions_ex(channeldata, ex, user_data)
}

/// Validate the extended ABI, then rebuild the channel's factory with both callback sets.
fn install_socket_functions_ex(
    channeldata: &mut ChannelData,
    ex: &AresSocketFunctionsEx,
    user_data: *mut c_void,
) -> crate::ffi::ares_status_t {
    // Version 1 is the only supported ABI; optional callbacks are getname/bind/ifname.
    if ex.version != 1
        || ex.asocket.is_none()
        || ex.aclose.is_none()
        || ex.asetsockopt.is_none()
        || ex.aconnect.is_none()
        || ex.arecvfrom.is_none()
        || ex.asendto.is_none()
    {
        return crate::ffi::error::ARES_EFORMERR;
    }
    let basic = AresSocketFunctions {
        asocket: ex.asocket,
        aclose: ex.aclose,
        aconnect: None, // ex.aconnect has a different signature (extra flags)
        arecvfrom: ex.arecvfrom,
        asendv: None, // ex.asendto has a different signature
    };
    let exfuncs = ExFuncs {
        asetsockopt: ex.asetsockopt,
        aconnect: ex.aconnect,
        asendto: ex.asendto,
    };
    let factory = CSocketFactory::with_ex_funcs(basic, exfuncs, user_data, &channeldata.socket_factory);
    channeldata.apply_socket_factory(factory);
    crate::ffi::error::ARES_SUCCESS
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

/// Callbacks only the extended table carries; kept out of the C-visible
/// `AresSocketFunctions` so the legacy struct's ABI is unchanged.
#[derive(Clone, Copy, Default)]
pub(crate) struct ExFuncs {
    pub asetsockopt: Option<unsafe extern "C" fn(ares_socket_t, crate::ffi::ares_socket_opt_t, *const c_void, socklen_t, *mut c_void) -> c_int>,
    pub aconnect: Option<unsafe extern "C" fn(ares_socket_t, *const sockaddr, socklen_t, c_uint, *mut c_void) -> c_int>,
    pub asendto: Option<unsafe extern "C" fn(ares_socket_t, *const c_void, libc::size_t, c_int, *const sockaddr, socklen_t, *mut c_void) -> ares_ssize_t>,
}

/// The per-channel socket settings applied to each freshly created fd.
#[derive(Clone)]
pub(crate) struct SocketConfig {
    pub send_buf: c_int,
    pub recv_buf: c_int,
    pub local_ip4: u32,
    pub local_ip6: [u8; 16],
    pub local_dev: String,
    pub sock_state_cb: ares_sock_state_cb,
    pub sock_state_cb_data: *mut c_void,
}

impl Default for SocketConfig {
    fn default() -> Self {
        SocketConfig {
            send_buf: 0,
            recv_buf: 0,
            local_ip4: 0,
            local_ip6: [0; 16],
            local_dev: String::new(),
            sock_state_cb: None,
            sock_state_cb_data: std::ptr::null_mut(),
        }
    }
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

/// Map an `ares_socket_opt_t` onto the platform `setsockopt` call.
fn default_setsockopt(fd: ares_socket_t, opt: c_uint, value: &[u8]) -> c_int {
    let (level, name) = match opt {
        ARES_SOCKET_OPT_SENDBUF_SIZE => (SOL_SOCKET, SO_SNDBUF),
        ARES_SOCKET_OPT_RECVBUF_SIZE => (SOL_SOCKET, SO_RCVBUF),
        ARES_SOCKET_OPT_BIND_DEVICE => {
            #[cfg(target_os = "linux")]
            {
                (SOL_SOCKET, libc::SO_BINDTODEVICE)
            }
            #[cfg(not(target_os = "linux"))]
            {
                return 0;
            }
        }
        _ => return 0,
    };
    let ptr = value.as_ptr() as *const c_void;
    let len = value.len() as socklen_t;
    unsafe { setsockopt(fd, level, name, ptr, len) }
}

/// The channel's socket source: the user-replaceable C function table, implementing
/// `SocketFactory` so the engine never sees the table or `user_data`.
#[derive(Clone)]
pub struct CSocketFactory {
    funcs: AresSocketFunctions,
    user_data: *mut c_void,
    // Socket-state callbacks, consulted per fresh fd: nonzero refuses the socket
    // (Err -> ARES_ECONNREFUSED). Immutable, so each setter rebuilds the factory
    // and channels sharing an Rc (ares_dup) stay independent.
    create_cb: ares_sock_create_callback,
    create_arg: *mut c_void,
    config_cb: ares_sock_config_callback,
    config_arg: *mut c_void,
    /// Extended-table callbacks, present only after `ares_set_socket_functions_ex`.
    ex: Option<ExFuncs>,
    /// True once the caller installed a custom socket table (legacy or ex).
    custom: bool,
    /// Socket-option / local-bind / state-callback settings, copied by every rebuild.
    socket: SocketConfig,
}

impl Default for CSocketFactory {
    fn default() -> Self {
        CSocketFactory {
            funcs: AresSocketFunctions::default(),
            user_data: std::ptr::null_mut(),
            create_cb: None,
            create_arg: std::ptr::null_mut(),
            config_cb: None,
            config_arg: std::ptr::null_mut(),
            ex: None,
            custom: false,
            socket: SocketConfig::default(),
        }
    }
}

/// One socket with a snapshot of the factory's function table, so a replaced
/// table stays alive for sockets that outlive an `ares_set_socket_functions()` swap.
struct CSocket {
    fd: ares_socket_t,
    funcs: AresSocketFunctions,
    ex: Option<ExFuncs>,
    user_data: *mut c_void,
    sock_state_cb: ares_sock_state_cb,
    sock_state_cb_data: *mut c_void,
    /// Caller-supplied sockets may be blocking, so the UDP drain must not loop on them.
    drain_safe: bool,
    /// Set once the open notification fired, avoiding a spurious close on failed creation.
    notified_open: Cell<bool>,
}

impl crate::async_runtime::socket::Socket for CSocket {
    fn as_raw_fd(&self) -> i32 {
        self.fd
    }

    fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let (sockaddr, len) = socket_addr_to_raw(addr);
        let result = if let Some(aconnect) = self.ex.and_then(|ex| ex.aconnect) {
            unsafe { aconnect(self.fd, &sockaddr as *const _ as *const sockaddr, len, 0, self.user_data) }
        } else {
            let aconnect = self.funcs.aconnect.unwrap_or(default_aconnect);
            unsafe { aconnect(self.fd, &sockaddr as *const _ as *const sockaddr, len, self.user_data) }
        };
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

    fn drain_safe(&self) -> bool {
        self.drain_safe
    }

    fn send(&self, data: &[u8]) -> io::Result<usize> {
        let result = if let Some(asendto) = self.ex.and_then(|ex| ex.asendto) {
            // Connected socket: NULL destination means "use the connected peer".
            let ptr = data.as_ptr() as *const c_void;
            let user = self.user_data;
            unsafe { asendto(self.fd, ptr, data.len(), 0, std::ptr::null(), 0, user) }
        } else {
            let asendv = self.funcs.asendv.unwrap_or(default_asendv);
            let iovecs = [iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() }];
            unsafe { asendv(self.fd, iovecs.as_ptr(), 1, self.user_data) }
        };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        Ok(result as usize)
    }
}

impl Drop for CSocket {
    fn drop(&mut self) {
        if self.notified_open.get() {
            if let Some(cb) = self.sock_state_cb {
                cb(self.sock_state_cb_data, self.fd, 0, 0);
            }
        }
        let aclose = self.funcs.aclose.unwrap_or(default_aclose);
        unsafe { aclose(self.fd, self.user_data) };
    }
}

impl CSocketFactory {
    /// New function table; socket-state callbacks are an independent setting, so carry them over.
    pub(crate) fn with_funcs(funcs: AresSocketFunctions, user_data: *mut c_void, prev: &CSocketFactory) -> Rc<Self> {
        Rc::new(Self {
            funcs,
            user_data,
            create_cb: prev.create_cb,
            create_arg: prev.create_arg,
            config_cb: prev.config_cb,
            config_arg: prev.config_arg,
            ex: None,
            custom: true,
            socket: prev.socket.clone(),
        })
    }

    /// Keep the extended callbacks the legacy table cannot express, alongside the basic ones.
    pub(crate) fn with_ex_funcs(
        funcs: AresSocketFunctions,
        ex: ExFuncs,
        user_data: *mut c_void,
        prev: &CSocketFactory,
    ) -> Rc<Self> {
        Rc::new(Self {
            funcs,
            user_data,
            create_cb: prev.create_cb,
            create_arg: prev.create_arg,
            config_cb: prev.config_cb,
            config_arg: prev.config_arg,
            ex: Some(ex),
            custom: true,
            socket: prev.socket.clone(),
        })
    }

    /// Copy socket-option / local-bind / state-callback settings into a rebuilt factory.
    pub(crate) fn with_config(&self, socket: SocketConfig) -> Rc<Self> {
        Rc::new(Self {
            funcs: self.funcs.clone(),
            user_data: self.user_data,
            create_cb: self.create_cb,
            create_arg: self.create_arg,
            config_cb: self.config_cb,
            config_arg: self.config_arg,
            ex: self.ex,
            custom: self.custom,
            socket,
        })
    }

    pub fn with_create_cb(&self, cb: ares_sock_create_callback, arg: *mut c_void) -> Rc<Self> {
        Rc::new(Self {
            funcs: self.funcs.clone(),
            user_data: self.user_data,
            create_cb: cb,
            create_arg: arg,
            config_cb: self.config_cb,
            config_arg: self.config_arg,
            ex: self.ex,
            custom: self.custom,
            socket: self.socket.clone(),
        })
    }

    pub fn with_config_cb(&self, cb: ares_sock_config_callback, arg: *mut c_void) -> Rc<Self> {
        Rc::new(Self {
            funcs: self.funcs.clone(),
            user_data: self.user_data,
            create_cb: self.create_cb,
            create_arg: self.create_arg,
            config_cb: cb,
            config_arg: arg,
            ex: self.ex,
            custom: self.custom,
            socket: self.socket.clone(),
        })
    }

    fn create(&self, addr: SocketAddr, socket_type: c_int) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
        let domain = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        let asocket = self.funcs.asocket.unwrap_or(default_asocket);
        let fd = unsafe { asocket(domain, socket_type, 0, self.user_data) };
        if fd == ARES_SOCKET_BAD {
            return Err(Error::last_os_error());
        }
        let sock = Rc::new(CSocket {
            fd,
            funcs: self.funcs.clone(),
            ex: self.ex,
            user_data: self.user_data,
            sock_state_cb: self.socket.sock_state_cb,
            sock_state_cb_data: self.socket.sock_state_cb_data,
            drain_safe: !self.custom,
            notified_open: Cell::new(false),
        });
        // Apply settings then callbacks; any failure drops `sock`, closing the fd
        // via CSocket::drop -> aclose and surfacing ECONNREFUSED.
        self.configure(fd, addr.is_ipv4())?;
        if !self.run_sock_callbacks(fd, socket_type == SOCK_STREAM) {
            return Err(Error::from_raw_os_error(libc::ECONNREFUSED));
        }
        // Approximation of upstream's state machine: report readable when live and
        // (0,0) on close; write-interest transitions are not modeled by this reactor.
        if let Some(cb) = self.socket.sock_state_cb {
            sock.notified_open.set(true);
            cb(self.socket.sock_state_cb_data, fd, 1, 0);
        }
        Ok(sock)
    }

    /// Apply buffer/device/local-address settings; a custom table owns its own addressing.
    fn configure(&self, fd: ares_socket_t, is_ipv4: bool) -> io::Result<()> {
        if self.socket.send_buf > 0 {
            self.setsockopt(fd, ARES_SOCKET_OPT_SENDBUF_SIZE, &self.socket.send_buf.to_ne_bytes())?;
        }
        if self.socket.recv_buf > 0 {
            self.setsockopt(fd, ARES_SOCKET_OPT_RECVBUF_SIZE, &self.socket.recv_buf.to_ne_bytes())?;
        }
        if !self.socket.local_dev.is_empty() {
            // Device-bind failure is ignored, matching prior c-ares behavior.
            let _ = self.setsockopt(
                fd,
                ARES_SOCKET_OPT_BIND_DEVICE,
                self.socket.local_dev.as_bytes(),
            );
        }
        if self.custom {
            return Ok(());
        }
        let local = if is_ipv4 && self.socket.local_ip4 != 0 {
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(self.socket.local_ip4)),
                0,
            ))
        } else if !is_ipv4 && self.socket.local_ip6 != [0; 16] {
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(self.socket.local_ip6)),
                0,
            ))
        } else {
            None
        };
        if let Some(addr) = local {
            let (storage, len) = socket_addr_to_raw(addr);
            let rv = unsafe { bind(fd, &storage as *const _ as *const sockaddr, len) };
            if rv != 0 {
                return Err(Error::from_raw_os_error(libc::ECONNREFUSED));
            }
        }
        Ok(())
    }

    /// `setsockopt` via the extended callback, else the platform default
    /// (ENOSYS is treated as success, as upstream does).
    fn setsockopt(&self, fd: ares_socket_t, opt: c_uint, value: &[u8]) -> io::Result<()> {
        let rv = if let Some(ex) = self.ex {
            match ex.asetsockopt {
                Some(cb) => {
                    let ptr = value.as_ptr() as *const c_void;
                    let len = value.len() as socklen_t;
                    let user = self.user_data;
                    unsafe { cb(fd, opt, ptr, len, user) }
                }
                None => 0,
            }
        } else if self.custom {
            0
        } else {
            default_setsockopt(fd, opt, value)
        };
        if rv != 0 {
            let err = Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOSYS) {
                return Ok(());
            }
            return Err(Error::from_raw_os_error(libc::ECONNREFUSED));
        }
        Ok(())
    }

    /// Run create then configure callbacks; false means refused.
    fn run_sock_callbacks(&self, fd: c_int, is_tcp: bool) -> bool {
        let sock_type = if is_tcp { SOCK_STREAM } else { SOCK_DGRAM };
        if let Some(cb) = self.create_cb {
            if unsafe { cb(fd, sock_type, self.create_arg) } != 0 { return false; }
        }
        if let Some(cb) = self.config_cb {
            if unsafe { cb(fd, sock_type, self.config_arg) } != 0 { return false; }
        }
        true
    }
}

impl crate::async_runtime::socket::SocketFactory for CSocketFactory {
    fn create_udp(&self, bind: SocketAddr) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
        self.create(bind, SOCK_DGRAM)
    }

    fn create_tcp(&self, bind: SocketAddr) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
        self.create(bind, SOCK_STREAM)
    }
}
