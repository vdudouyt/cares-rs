#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::{in_addr};
use crate::ffi::{ Channel, Ares };
use crate::ChannelData;
use std::net::{ IpAddr, Ipv4Addr };
use std::ffi::{c_char, c_int, c_uint, c_ushort, c_void, CStr};
use crate::ffi::error::*;
use crate::ares_socket_t;

#[repr(C)]
pub struct apattern {
    _private: [u8; 0],
}

pub type ares_evsys_t = c_int;

pub type ares_sock_state_cb =
    Option<extern "C" fn(data: *mut c_void, socket_fd: ares_socket_t, readable: c_int, writable: c_int)>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ares_server_failover_options {
    pub retry_chance: c_ushort, // probability (1/N); 0 disables retries
    pub retry_delay:  usize,    // minimum delay in milliseconds
}

// ------- The ares_options struct itself -------

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ares_options {
    pub flags: c_int,
    pub timeout: c_int,                      // seconds or millis depending on optmask
    pub tries: c_int,
    pub ndots: c_int,
    pub udp_port: c_ushort,                  // host byte order
    pub tcp_port: c_ushort,                  // host byte order
    pub socket_send_buffer_size: c_int,
    pub socket_receive_buffer_size: c_int,
    pub servers: *mut in_addr,               // IPv4 only; use ares_set_servers for v4/v6
    pub nservers: c_int,
    pub domains: *mut *mut c_char,
    pub ndomains: c_int,
    pub lookups: *mut c_char,
    pub sock_state_cb: ares_sock_state_cb,
    pub sock_state_cb_data: *mut c_void,
    pub sortlist: *mut apattern,             // opaque; only valid via ares_save_options
    pub nsort: c_int,
    pub ednspsz: c_int,
    pub resolvconf_path: *mut c_char,
    pub hosts_path: *mut c_char,
    pub udp_max_queries: c_int,
    pub maxtimeout: c_int,                   // milliseconds
    pub qcache_max_ttl: c_uint,              // seconds; 0 disables cache
    pub evsys: ares_evsys_t,                 // set to ARES_EVSYS_DEFAULT (0)
    pub server_failover_opts: ares_server_failover_options,
}

impl Default for ares_options {
    fn default() -> Self {
        Self {
            flags: 0,
            timeout: 0,
            tries: 0,
            ndots: 0,
            udp_port: 0,
            tcp_port: 0,
            socket_send_buffer_size: 0,
            socket_receive_buffer_size: 0,
            servers: core::ptr::null_mut(),
            nservers: 0,
            domains: core::ptr::null_mut(),
            ndomains: 0,
            lookups: core::ptr::null_mut(),
            sock_state_cb: None,
            sock_state_cb_data: core::ptr::null_mut(),
            sortlist: core::ptr::null_mut(),
            nsort: 0,
            ednspsz: 0,
            resolvconf_path: core::ptr::null_mut(),
            hosts_path: core::ptr::null_mut(),
            udp_max_queries: 0,
            maxtimeout: 0,
            qcache_max_ttl: 0,
            evsys: 0, // ARES_EVSYS_DEFAULT
            server_failover_opts: ares_server_failover_options {
                retry_chance: 0,
                retry_delay: 0,
            },
        }
    }
}

pub const ARES_OPT_FLAGS          : c_int = 1 << 0;
pub const ARES_OPT_TIMEOUT        : c_int = 1 << 1;
pub const ARES_OPT_TRIES          : c_int = 1 << 2;
pub const ARES_OPT_NDOTS          : c_int = 1 << 3;
pub const ARES_OPT_UDP_PORT       : c_int = 1 << 4;
pub const ARES_OPT_TCP_PORT       : c_int = 1 << 5;
pub const ARES_OPT_SERVERS        : c_int = 1 << 6;
pub const ARES_OPT_DOMAINS        : c_int = 1 << 7;
pub const ARES_OPT_LOOKUPS        : c_int = 1 << 8;
pub const ARES_OPT_SOCK_STATE_CB  : c_int = 1 << 9;
pub const ARES_OPT_SORTLIST       : c_int = 1 << 10;
pub const ARES_OPT_SOCK_SNDBUF    : c_int = 1 << 11;
pub const ARES_OPT_SOCK_RCVBUF    : c_int = 1 << 12;
pub const ARES_OPT_TIMEOUTMS      : c_int = 1 << 13;
pub const ARES_OPT_ROTATE         : c_int = 1 << 14;
pub const ARES_OPT_EDNSPSZ        : c_int = 1 << 15;
pub const ARES_OPT_NOROTATE       : c_int = 1 << 16;
pub const ARES_OPT_RESOLVCONF     : c_int = 1 << 17;
pub const ARES_OPT_HOSTS_FILE     : c_int = 1 << 18;
pub const ARES_OPT_UDP_MAX_QUERIES: c_int = 1 << 19;
pub const ARES_OPT_MAXTIMEOUTMS   : c_int = 1 << 20;
pub const ARES_OPT_QUERY_CACHE    : c_int = 1 << 21;
pub const ARES_OPT_EVENT_THREAD   : c_int = 1 << 22;
pub const ARES_OPT_SERVER_FAILOVER: c_int = 1 << 23;

#[no_mangle]
pub unsafe extern "C" fn ares_init_options(out_channel: *mut Channel, options: *const ares_options, optmask: c_int) -> c_int {
    let ares = Ares::from_sysconfig();
    let mut channeldata = ChannelData { ares, sock_create_callback: None, sock_create_callback_arg: std::ptr::null_mut(), readbuf: vec![0u8; 65_535], server_failures: vec![] };

    let options = unsafe { & *options };
    if optmask & ARES_OPT_SERVERS != 0 && !options.servers.is_null() {
        let servers = unsafe { std::slice::from_raw_parts(options.servers, options.nservers as usize) };
        for server in servers {
            let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(server.s_addr)));
            channeldata.ares.config.nameservers.push((ip, None));
            channeldata.ares.config.tcp_ports.push(None);
        }
    }
    if optmask & ARES_OPT_UDP_PORT != 0 {
        channeldata.ares.default_udp_port = options.udp_port;
    }
    if optmask & ARES_OPT_TCP_PORT != 0 {
        channeldata.ares.default_tcp_port = options.tcp_port;
    }
    if optmask & ARES_OPT_TIMEOUTMS != 0 {
        channeldata.ares.config.options.timeout_secs = std::cmp::max(1, (options.timeout as u32 + 999) / 1000);
    }
    if optmask & ARES_OPT_TIMEOUT != 0 {
        channeldata.ares.config.options.timeout_secs = options.timeout as u32;
    }
    if optmask & ARES_OPT_TRIES != 0 {
        channeldata.ares.config.options.attempts = options.tries as u32;
    }
    if optmask & ARES_OPT_NDOTS != 0 {
        channeldata.ares.config.options.ndots = options.ndots as u32;
    }
    if optmask & ARES_OPT_FLAGS != 0 {
        channeldata.ares.config.options.use_vc = (options.flags & ARES_FLAG_USEVC) != 0;
    }
    if optmask & ARES_OPT_DOMAINS != 0 && !options.domains.is_null() {
        let domains = std::slice::from_raw_parts(options.domains, options.ndomains as usize);
        channeldata.ares.config.search = domains.iter()
            .map(|&p| CStr::from_ptr(p).to_string_lossy().into_owned())
            .collect();
    }
    if optmask & ARES_OPT_NOROTATE != 0 {
        channeldata.ares.config.options.rotate = false;
    }
    if optmask & ARES_OPT_ROTATE != 0 {
        channeldata.ares.config.options.rotate = true;
    }
    channeldata.server_failures = vec![0; channeldata.ares.config.nameservers.len()];
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_save_options(channel: Channel, options: *mut ares_options, optmask: *mut c_int) -> c_int {
    if channel.is_null() || options.is_null() || optmask.is_null() {
        return ARES_ENODATA;
    }
    let channeldata = unsafe { &*channel };
    let config = &channeldata.ares.config;
    let opts = &config.options;

    let out = unsafe { &mut *options };
    *out = ares_options::default();

    let mut mask: c_int = 0;

    // flags
    let mut flags: c_int = 0;
    if opts.use_vc { flags |= ARES_FLAG_USEVC; }
    if opts.edns0 { flags |= ARES_FLAG_EDNS; }
    out.flags = flags;
    mask |= ARES_OPT_FLAGS;

    // timeout (in milliseconds)
    out.timeout = (opts.timeout_secs * 1000) as c_int;
    mask |= ARES_OPT_TIMEOUTMS;

    // tries
    out.tries = opts.attempts as c_int;
    mask |= ARES_OPT_TRIES;

    // ndots
    out.ndots = opts.ndots as c_int;
    mask |= ARES_OPT_NDOTS;

    // udp/tcp ports
    out.udp_port = channeldata.ares.default_udp_port;
    mask |= ARES_OPT_UDP_PORT;
    out.tcp_port = channeldata.ares.default_tcp_port;
    mask |= ARES_OPT_TCP_PORT;

    // servers (IPv4 only in ares_options)
    let v4_servers: Vec<in_addr> = config.nameservers.iter().filter_map(|(ip, _)| {
        match ip {
            IpAddr::V4(v4) => {
                Some(in_addr { s_addr: u32::from(*v4).to_be() })
            }
            _ => None,
        }
    }).collect();
    if !v4_servers.is_empty() {
        let count = v4_servers.len();
        let ptr = unsafe { libc::malloc(count * std::mem::size_of::<in_addr>()) as *mut in_addr };
        if !ptr.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(v4_servers.as_ptr(), ptr, count) };
            out.servers = ptr;
            out.nservers = count as c_int;
            mask |= ARES_OPT_SERVERS;
        }
    }

    // domains
    if !config.search.is_empty() {
        let count = config.search.len();
        let arr = unsafe { libc::malloc(count * std::mem::size_of::<*mut c_char>()) as *mut *mut c_char };
        if !arr.is_null() {
            for (i, domain) in config.search.iter().enumerate() {
                let cstr = std::ffi::CString::new(domain.as_str()).unwrap_or_default();
                unsafe { *arr.add(i) = cstr.into_raw() };
            }
            out.domains = arr;
            out.ndomains = count as c_int;
            mask |= ARES_OPT_DOMAINS;
        }
    }

    // rotate
    if opts.rotate {
        mask |= ARES_OPT_ROTATE;
    } else {
        mask |= ARES_OPT_NOROTATE;
    }

    unsafe { *optmask = mask };
    ARES_SUCCESS
}

const ARES_FLAG_USEVC: c_int = 1 << 0;
const ARES_FLAG_NOCHECKRESP: c_int = 1 << 7;
const ARES_FLAG_EDNS: c_int = 1 << 8;

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy_options(options: *mut ares_options) {
    if options.is_null() { return; }
    let opts = unsafe { &mut *options };

    // Free servers array
    if !opts.servers.is_null() {
        unsafe { libc::free(opts.servers as *mut c_void) };
        opts.servers = std::ptr::null_mut();
    }

    // Free domains array
    if !opts.domains.is_null() {
        for i in 0..opts.ndomains as usize {
            let ptr = unsafe { *opts.domains.add(i) };
            if !ptr.is_null() {
                drop(unsafe { std::ffi::CString::from_raw(ptr) });
            }
        }
        unsafe { libc::free(opts.domains as *mut c_void) };
        opts.domains = std::ptr::null_mut();
    }

    // Free lookups string
    if !opts.lookups.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(opts.lookups) });
        opts.lookups = std::ptr::null_mut();
    }

    // Free resolvconf_path
    if !opts.resolvconf_path.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(opts.resolvconf_path) });
        opts.resolvconf_path = std::ptr::null_mut();
    }

    // Free hosts_path
    if !opts.hosts_path.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(opts.hosts_path) });
        opts.hosts_path = std::ptr::null_mut();
    }
}
