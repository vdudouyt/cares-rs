pub mod ares_data;
mod ares_hostent;
pub mod ares_options;
pub mod ares_socket;
mod cnullterminated;
mod clinkedlist;
pub mod dns_record;
pub mod error;
mod offset_of;

use std::ffi::{ c_int, c_uint, c_void, c_char };
use std::ffi::{ CString, CStr };
use std::net::IpAddr;
use std::cmp::min;
use std::time::Instant;
use crate::core::packets::*;
use crate::core::servers_csv;
use crate::ffi::ares_hostent::*;
use crate::ffi::ares_data::*;
// Re-export the address union used by the public ares_addr_node structs.
pub use crate::ffi::ares_data::AresAddrUnion;
use crate::ffi::clinkedlist::*;
use crate::ffi::error::*;
pub use crate::ffi::ares_socket::{CSocketFactory, AresSocketFunctions};
use crate::core::sortlist::*;
use std::io::Cursor;

mod addrinfo;
mod convert;
mod channel;
mod lookups;
mod parsers;
mod process;
pub use addrinfo::*;
pub(crate) use convert::*;
pub use channel::*;
pub(crate) use channel::channel_access;
pub use lookups::*;
pub use parsers::*;
pub use process::*;

pub const ARES_SUCCESS: i32 = 0;
pub const ARES_ENODATA: i32 = 1;
pub const ARES_EFORMERR: i32 = 2;
pub const ARES_ESERVFAIL: i32 = 3;
pub const ARES_ENOTFOUND: i32 = 4;
pub const ARES_ETIMEOUT: i32 = 12;
pub const ARES_LIB_INIT_ALL: i32 = 1;

#[allow(non_camel_case_types)]
pub type ares_socket_t = c_int;

// c-ares spells many parameters/returns with named enum/typedef types. Keep
// `int`-based signatures but define the names so C consumers compile.
#[allow(non_camel_case_types)] pub type ares_status_t = c_int;
#[allow(non_camel_case_types)] pub type ares_bool_t = c_int;
#[allow(non_camel_case_types)] pub type ares_socklen_t = libc::socklen_t;
#[allow(non_camel_case_types)] pub type ares_dns_rec_type_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_class_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_section_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_opcode_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_rcode_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_flags_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_datatype_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_rr_key_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_opt_datatype_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_dns_parse_flags_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_tlsa_usage_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_tlsa_selector_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_tlsa_match_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_svcb_param_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_opt_param_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_socket_opt_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_socket_bind_flags_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_socket_connect_flags_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_sockfunc_flags_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_fd_eventflag_t = c_uint;
#[allow(non_camel_case_types)] pub type ares_process_flag_t = c_uint;

#[allow(non_camel_case_types)]
pub type ares_pending_write_cb = Option<unsafe extern "C" fn(data: *mut c_void)>;

#[no_mangle]
pub extern "C" fn ares_library_init(_flags: c_int) -> c_int {
    ARES_SUCCESS
}

/// `ares_library_init_mem`: allocator hooks are accepted but not used; the
/// library keeps using the system allocator.
#[no_mangle]
pub extern "C" fn ares_library_init_mem(
    flags: c_int,
    amalloc: Option<unsafe extern "C" fn(size: libc::size_t) -> *mut c_void>,
    afree: Option<unsafe extern "C" fn(ptr: *mut c_void)>,
    arealloc: Option<unsafe extern "C" fn(ptr: *mut c_void, size: libc::size_t) -> *mut c_void>,
) -> c_int {
    let _ = (flags, amalloc, afree, arealloc);
    ARES_SUCCESS
}

#[no_mangle]
pub extern "C" fn ares_library_cleanup() {
}

/// Report ARES_TRUE (1); every channel has its own event thread and lock.
#[no_mangle]
pub extern "C" fn ares_threadsafety() -> i32 {
    1
}

pub type Channel = *mut ChannelData;

// 16-byte IPv6 type matching upstream's `struct ares_in6_addr`, including the
// `_S6_un._S6_u8` field path consumers rely on.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct ares_in6_addr_un {
    pub _S6_u8: [u8; 16],
}
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct ares_in6_addr {
    pub _S6_un: ares_in6_addr_un,
}
impl ares_in6_addr {
    pub fn from_octets(octets: [u8; 16]) -> Self {
        ares_in6_addr { _S6_un: ares_in6_addr_un { _S6_u8: octets } }
    }
}

/// Single address + family for `ares_dns_pton()` / `ares_dns_addr_to_ptr()`.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ares_addr {
    pub family: c_int,
    pub addr: AresAddrUnion,
}

// Dual-role: caller-allocatable input to `ares_set_servers` and cares-rs-allocated
// output of `ares_get_servers`. Intentionally NO `Drop`, which would free
// caller-owned stack instances. See the ownership taxonomy in `ffi/ares_data.rs`.
#[repr(C)]
pub struct ares_addr_node {
    pub next: *mut ares_addr_node,
    pub family: c_int,
    pub addr: AresAddrUnion, // union { struct in_addr addr4; struct ares_in6_addr addr6; }
}

pub const RECORD_TYPE_A: u16 = 0x01;
pub const RECORD_TYPE_NS: u16 = 0x02;
pub const RECORD_TYPE_CNAME: u16 = 0x05;
pub const RECORD_TYPE_SOA: u16 = 0x06;
pub const RECORD_TYPE_PTR: u16 = 0x0c;
pub const RECORD_TYPE_AAAA: u16 = 0x1c;
pub const RECORD_TYPE_MX: u16 = 0x0f;
pub const RECORD_TYPE_TXT: u16 = 0x10;
pub const RECORD_TYPE_CAA: u16 = 0x101;
pub const RECORD_TYPE_SRV: u16 = 0x21;
pub const RECORD_TYPE_NAPTR: u16 = 0x23;
pub const RECORD_TYPE_URI: u16 = 0x100;

// Internal bare-fn callback aliases; excluded from the generated header (use the
// nullable `Option<...>` typedefs below in public signatures).
pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);
pub type AresCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int);
pub type AresCallbackDnsRec = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: usize, dnsrec: *const dns_record::ares_dns_record_t);
pub type AresSockCreateCallback = unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int;
pub type AresNameinfoCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, node: *mut c_char, service: *mut c_char);
pub type AresAddrInfoCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, res: *mut ares_addrinfo);

// C-ABI nullable callback typedefs for public signatures. Wrapping an INLINE
// `extern "C" fn` in `Option<...>` makes cbindgen emit a proper nullable C
// function pointer (it cannot do that for `Option<TypeAlias>`).
#[allow(non_camel_case_types)] pub type ares_host_callback = Option<unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent)>;
#[allow(non_camel_case_types)] pub type ares_callback = Option<unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int)>;
#[allow(non_camel_case_types)] pub type ares_callback_dnsrec = Option<unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: libc::size_t, dnsrec: *const dns_record::ares_dns_record_t)>;
#[allow(non_camel_case_types)] pub type ares_sock_create_callback = Option<unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int>;
#[allow(non_camel_case_types)] pub type ares_nameinfo_callback = Option<unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, node: *mut c_char, service: *mut c_char)>;
#[allow(non_camel_case_types)] pub type ares_addrinfo_callback = Option<unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, res: *mut ares_addrinfo)>;

pub const ARES_AI_CANONNAME: c_int = 1 << 0;
pub const ARES_AI_NUMERICHOST: c_int = 1 << 1;
pub const ARES_AI_PASSIVE: c_int = 1 << 2;
pub const ARES_AI_NUMERICSERV: c_int = 1 << 3;
pub const ARES_AI_V4MAPPED: c_int = 1 << 4;
pub const ARES_AI_ALL: c_int = 1 << 5;
pub const ARES_AI_ADDRCONFIG: c_int = 1 << 6;
pub const ARES_AI_NOSORT: c_int = 1 << 7;
pub const ARES_AI_ENVHOSTS: c_int = 1 << 8;
// Reserved for future use (upstream values; kept for source compatibility).
pub const ARES_AI_IDN: c_int = 1 << 10;
pub const ARES_AI_IDN_ALLOW_UNASSIGNED: c_int = 1 << 11;
pub const ARES_AI_IDN_USE_STD3_ASCII_RULES: c_int = 1 << 12;
pub const ARES_AI_CANONIDN: c_int = 1 << 13;

// ares_getnameinfo flags
pub const ARES_NI_NOFQDN: c_int = 1 << 0;
pub const ARES_NI_NUMERICHOST: c_int = 1 << 1;
pub const ARES_NI_NAMEREQD: c_int = 1 << 2;
pub const ARES_NI_NUMERICSERV: c_int = 1 << 3;
pub const ARES_NI_DGRAM: c_int = 1 << 4;
pub const ARES_NI_TCP: c_int = 0;
pub const ARES_NI_UDP: c_int = ARES_NI_DGRAM;
pub const ARES_NI_SCTP: c_int = 1 << 5;
pub const ARES_NI_DCCP: c_int = 1 << 6;
pub const ARES_NI_NUMERICSCOPE: c_int = 1 << 7;
pub const ARES_NI_LOOKUPHOST: c_int = 1 << 8;
pub const ARES_NI_LOOKUPSERVICE: c_int = 1 << 9;
// Reserved for future use (upstream values; kept for source compatibility).
pub const ARES_NI_IDN: c_int = 1 << 10;
pub const ARES_NI_IDN_ALLOW_UNASSIGNED: c_int = 1 << 11;
pub const ARES_NI_IDN_USE_STD3_ASCII_RULES: c_int = 1 << 12;

pub const ARES_LIB_INIT_NONE: c_int = 0;
pub const ARES_LIB_INIT_WIN32: c_int = 1 << 0;

pub const ARES_SERV_STATE_UDP: c_int = 1 << 0;
pub const ARES_SERV_STATE_TCP: c_int = 1 << 1;

pub const ARES_EVSYS_DEFAULT: c_int = 0;
pub const ARES_EVSYS_WIN32: c_int = 1;
pub const ARES_EVSYS_EPOLL: c_int = 2;
pub const ARES_EVSYS_KQUEUE: c_int = 3;
pub const ARES_EVSYS_POLL: c_int = 4;
pub const ARES_EVSYS_SELECT: c_int = 5;

/// # Safety
/// `version` must be null or a valid, writable pointer to a `c_int`.
#[no_mangle]
pub unsafe extern "C" fn ares_version(version: *mut c_int) -> *const c_char {
    let (major, minor, patch) = (1, 34, 6);
    let v = (major << 16) | (minor << 8) | patch;
    if !version.is_null() { unsafe { *version = v } }
    c"1.34.6".as_ptr()
}

pub const ARES_GETSOCK_MAXNUM: usize = 16; // per c-ares headers
pub const ARES_SOCKET_BAD: ares_socket_t = -1;

pub type AresSockConfigureCallback = unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int;
pub type AresServerStateCallback = unsafe extern "C" fn(server_string: *const c_char, success: c_int, flags: c_int, arg: *mut libc::c_void);
// C-ABI nullable forms.
#[allow(non_camel_case_types)] pub type ares_sock_config_callback = Option<unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int>;
#[allow(non_camel_case_types)] pub type ares_server_state_callback = Option<unsafe extern "C" fn(server_string: *const c_char, success: c_int, flags: c_int, arg: *mut libc::c_void)>;

#[no_mangle]
pub extern "C" fn ares_library_initialized() -> c_int {
    ARES_SUCCESS
}
