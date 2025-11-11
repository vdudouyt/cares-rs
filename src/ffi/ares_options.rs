#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::{in_addr};
use crate::ffi::Channel;
use std::net::{ IpAddr, Ipv4Addr, SocketAddr };
use std::ffi::{c_char, c_int, c_uint, c_ushort, c_void};
use crate::ffi::error::*;

pub type ares_socket_t = c_int;

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
pub unsafe extern "C" fn ares_init_options(channel: Channel, options: *const ares_options, optmask: c_int) -> c_int {
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.config.nameservers.clear();
    let options = unsafe { & *options };
    if optmask & ARES_OPT_SERVERS != 0 && !options.servers.is_null() {
        let servers = unsafe { std::slice::from_raw_parts(options.servers, options.nservers as usize) };
        for server in servers {
            let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(server.s_addr)));
            channeldata.ares.config.nameservers.push((ip, None));
        }
    }
    if optmask & ARES_OPT_UDP_PORT != 0 {
        channeldata.ares.default_udp_port = options.udp_port;
    }
    if optmask & ARES_OPT_TCP_PORT != 0 {
        channeldata.ares.default_tcp_port = options.tcp_port;
    }
    ARES_SUCCESS
}
