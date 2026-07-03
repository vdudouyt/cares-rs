pub mod ares_data;
mod ares_hostent;
pub mod ares_options;
pub mod ares_socket;
mod cnullterminated;
mod cstr;
mod clinkedlist;
pub mod dns_record;
pub mod error;
mod offset_of;

use std::ffi::{ c_int, c_uint, c_void, c_char };
use std::ffi::{ CString, CStr };
use std::net::IpAddr;
use std::cmp::min;
use std::time::Instant;
use bytes::BytesMut;
use crate::core::packets::*;
use crate::core::ares::{ Ares, Status, Family, WriteResult, SocketSource, DnsSocket, dns_query_payload, qtype_of, rdns_name };
use crate::core::servers_csv;
use crate::core::services::Services;
use crate::ffi::ares_hostent::*;
use crate::ffi::ares_data::*;
// Re-export the address union (a field type of the public ares_addr_node /
// ares_addr_port_node structs) so Rust consumers can construct those.
pub use crate::ffi::ares_data::AresAddrUnion;
use crate::ffi::clinkedlist::*;
use crate::ffi::error::*;
use crate::cstr;
pub use crate::ffi::ares_socket::{SocketFactory, AresSocketFunctions};
use crate::core::hostfile::HostLookup;
use crate::core::lookup::*;
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

// Upstream c-ares spells many parameters/returns with named enum/typedef types.
// We keep `int`-based signatures (C phase) but define the type NAMES so that C
// consumer source that declares e.g. `ares_status_t s = ares_parse_a_reply(...)`
// compiles against our header. (Phase 2 promotes these to real `#[repr(C)] enum`s
// for strict C++ compatibility.) These are force-emitted via cbindgen's
// `[export] include`.
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

#[no_mangle]
pub extern "C" fn ares_library_init(_flags: c_int) -> c_int {
    ARES_SUCCESS
}

#[no_mangle]
pub extern "C" fn ares_library_cleanup() {
}

/// We do not provide the built-in event thread, so the library is not
/// thread-safe. Report ARES_FALSE (0), matching c-ares on non-threaded builds.
#[no_mangle]
pub extern "C" fn ares_threadsafety() -> i32 {
    0
}

pub type Channel = *mut ChannelData;

// Custom 16-byte IPv6 address type matching upstream c-ares
// (`struct ares_in6_addr { union { unsigned char _S6_u8[16]; } _S6_un; }`), so
// consumer source using `addr._S6_un._S6_u8` and the `struct ares_in6_addr` type
// name compiles. A single-member inner struct is layout- and field-path-identical
// to upstream's single-member union, without Rust union ergonomics.
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

// Dual-role: caller-allocatable input to `ares_set_servers`, and cares-rs-allocated
// output of `ares_get_servers`. Intentionally NO `Drop` — a chain-walking Drop would
// free caller-owned stack instances. See the ownership taxonomy in `ffi/ares_data.rs`.
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

// Internal bare-fn callback aliases (used by the Callback enum, state structs and
// run_* dispatchers). Excluded from the generated header — see the C-ABI nullable
// typedefs below, which is what public signatures and cbindgen use.
pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);
pub type AresCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int);
pub type AresCallbackDnsRec = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: usize, dnsrec: *mut dns_record::ares_dns_record_t);
pub type AresSockCreateCallback = unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int;
pub type AresNameinfoCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, node: *mut c_char, service: *mut c_char);
pub type AresAddrInfoCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, res: *mut ares_addrinfo);

// C-ABI nullable callback typedefs used in the public FFI signatures. These wrap
// an INLINE `extern "C" fn` in `Option<...>` so cbindgen collapses them to proper
// nullable C function pointers with the upstream c-ares names (it cannot do this
// for `Option<TypeAlias>`). Signatures must mirror the bare aliases above.
#[allow(non_camel_case_types)] pub type ares_host_callback = Option<unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent)>;
#[allow(non_camel_case_types)] pub type ares_callback = Option<unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int)>;
#[allow(non_camel_case_types)] pub type ares_callback_dnsrec = Option<unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: libc::size_t, dnsrec: *mut dns_record::ares_dns_record_t)>;
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

/// # Safety
/// `version` must be null or a valid, writable pointer to a `c_int`.
#[no_mangle]
pub unsafe extern "C" fn ares_version(version: *mut c_int) -> *const c_char {
    let (major, minor, patch) = (1, 34, 6);
    let v = (major << 16) | (minor << 8) | patch;
    if !version.is_null() { unsafe { *version = v } }
    cstr!("1.34.6")
}

pub const ARES_GETSOCK_MAXNUM: usize = 16; // per c-ares headers
pub const ARES_SOCKET_BAD: ares_socket_t = -1;

pub type AresSockConfigureCallback = unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int;
pub type AresServerStateCallback = unsafe extern "C" fn(server_string: *const c_char, success: c_int, flags: c_int, arg: *mut libc::c_void);
// C-ABI nullable forms (see note by the other ares_*_callback typedefs).
#[allow(non_camel_case_types)] pub type ares_sock_config_callback = Option<unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int>;
#[allow(non_camel_case_types)] pub type ares_server_state_callback = Option<unsafe extern "C" fn(server_string: *const c_char, success: c_int, flags: c_int, arg: *mut libc::c_void)>;


#[no_mangle]
pub extern "C" fn ares_library_initialized() -> c_int {
    ARES_SUCCESS
}
