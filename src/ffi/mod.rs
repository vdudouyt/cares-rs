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
use std::time::{Instant, Duration};
use bytes::BytesMut;
use crate::core::packets::*;
use crate::core::ares::{ Ares, Status, Family, WriteResult, SocketSource, DnsSocket, dns_query_payload, qtype_of, rdns_name };
use crate::core::servers_csv;
use crate::core::services::Services;
use crate::ffi::ares_data::*;
// Re-export the address union (a field type of the public ares_addr_node /
// ares_addr_port_node structs) so Rust consumers can construct those.
pub use crate::ffi::ares_data::AresAddrUnion;
use crate::ffi::clinkedlist::*;
use crate::ffi::error::*;
use crate::cstr;
pub use crate::ffi::ares_socket::{SocketFactory, AresSocketFunctions};
use crate::core::hostfile::{AddressFamily, HostLookup};
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
pub(crate) use lookups::*;
pub use parsers::*;
pub(crate) use process::*;

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

// ============================================================================
// The complete C API surface: every #[no_mangle] export lives here as a
// thin delegator. Implementations: decision logic in src/core (safe);
// marshaling/delivery in the non-exporting ffi kernel modules.
// ============================================================================

// ----- channel -----

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    unsafe { channel::init(out_channel) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dup(dest: *mut Channel, source: Channel) -> c_int {
    unsafe { channel::dup(dest, source) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_cancel(channel: Channel) {
    unsafe { channel::cancel(channel) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    unsafe { channel::destroy(channel) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_fds(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    unsafe { channel::fds(channel, read_fds, write_fds) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_timeout(channel: Channel, maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval {
    unsafe { channel::timeout(channel, maxtv, tv) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers(channel: Channel, head: *mut ares_addr_node) -> c_int {
    unsafe { channel::set_servers(channel, head) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports(channel: Channel, head: *mut AresAddrPortNode) -> c_int {
    unsafe { channel::set_servers_ports(channel, head) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_ports(channel: Channel, out: *mut *mut AresAddrPortNode) -> c_int {
    unsafe { channel::get_servers_ports(channel, out) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports_csv(channel: Channel, servers: *const c_char) -> c_int {
    unsafe { channel::set_servers_ports_csv(channel, servers) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_csv(channel: Channel, servers: *const c_char) -> c_int {
    unsafe { channel::set_servers_csv(channel, servers) }
}

/// # Safety
/// `channel` must be a valid channel and `socks` must point to at least `numsocks` writable slots.
#[no_mangle]
pub unsafe extern "C" fn ares_getsock(channel: Channel, socks: *mut ares_socket_t, numsocks: c_int) -> c_int {
    unsafe { channel::getsock(channel, socks, numsocks) }
}

#[no_mangle]
pub extern "C" fn ares_set_local_ip4(_channel: Channel, _local_ip: u32) {
    channel::set_local_ip4(_channel, _local_ip)
}

#[no_mangle]
pub extern "C" fn ares_set_local_ip6(_channel: Channel, _local_ip6: *const u8) {
    channel::set_local_ip6(_channel, _local_ip6)
}

#[no_mangle]
pub extern "C" fn ares_set_local_dev(_channel: Channel, _local_dev_name: *const c_char) {
    channel::set_local_dev(_channel, _local_dev_name)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_callback(channel: Channel, callback: ares_sock_create_callback, arg: *mut c_void) {
    unsafe { channel::set_socket_callback(channel, callback, arg) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers(channel: Channel, out: *mut *mut ares_addr_node) -> c_int {
    unsafe { channel::get_servers(channel, out) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_csv(channel: Channel) -> *mut c_char {
    unsafe { channel::get_servers_csv(channel) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_sortlist(channel: Channel, sortstr: *const c_char) -> c_int {
    unsafe { channel::set_sortlist(channel, sortstr) }
}

#[no_mangle]
pub extern "C" fn ares_reinit(channel: Channel) -> c_int {
    channel::reinit(channel)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_configure_callback(channel: Channel, callback: ares_sock_config_callback, arg: *mut c_void) {
    unsafe { channel::set_socket_configure_callback(channel, callback, arg) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_server_state_callback(channel: Channel, callback: ares_server_state_callback, arg: *mut c_void) {
    unsafe { channel::set_server_state_callback(channel, callback, arg) }
}

/// # Safety
/// `channel` must be null or a valid channel handle returned by
/// `ares_init`/`ares_init_options` and not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn ares_queue_active_queries(channel: Channel) -> c_int {
    unsafe { channel::queue_active_queries(channel) }
}

#[no_mangle]
pub extern "C" fn ares_queue_wait_empty(_channel: Channel, _timeout_ms: c_int) -> c_int {
    channel::queue_wait_empty(_channel, _timeout_ms)
}

// ----- lookups -----

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, hostname: *const c_char, family: c_int, callback: ares_host_callback, arg: *mut c_void) {
    unsafe { lookups::gethostbyname(channel, hostname, family, callback, arg) }
}

/// # Safety
/// `channel` must be a valid channel, `name` a valid NUL-terminated C string, and `host` a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    unsafe { lookups::gethostbyname_file(channel, name, family, host) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyaddr(channel: Channel, addr: *mut c_void, addrlen: c_int, family: c_int, callback: ares_host_callback, arg: *mut c_void) {
    unsafe { lookups::gethostbyaddr(channel, addr, addrlen, family, callback, arg) }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_search(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    unsafe { lookups::search(channel, name, dnsclass, dnstype, callback, arg) }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, _dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    unsafe { lookups::query(channel, name, _dnsclass, dnstype, callback, arg) }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_query_dnsrec( channel: Channel, name: *const c_char, _dnsclass: c_int, dnstype: c_int, callback: ares_callback_dnsrec, arg: *mut c_void, _qid: *mut c_int ) {
    unsafe { lookups::query_dnsrec(channel, name, _dnsclass, dnstype, callback, arg, _qid) }
}

/// # Safety
/// `channel` must be a valid channel and `dnsrec` a valid `ares_dns_record_t` pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_search_dnsrec( channel: Channel, dnsrec: *mut dns_record::ares_dns_record_t, callback: ares_callback_dnsrec, arg: *mut c_void, ) {
    unsafe { lookups::search_dnsrec(channel, dnsrec, callback, arg) }
}

/// Looks up the node name and service name for a socket address.
///
/// This is the async equivalent of getnameinfo(3). It performs a reverse DNS lookup
/// (PTR record) to get the hostname, and looks up the service name from /etc/services.
///
/// # Arguments
/// * `channel` - The c-ares channel
/// * `sa` - Pointer to a sockaddr structure (sockaddr_in or sockaddr_in6)
/// * `salen` - Size of the sockaddr structure
/// * `flags` - Flags controlling the lookup behavior (ARES_NI_*)
/// * `callback` - Function to call with results
/// * `arg` - User data passed to callback
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_getnameinfo(channel: Channel, sa: *const libc::sockaddr, salen: libc::socklen_t, flags: c_int, callback: ares_nameinfo_callback, arg: *mut c_void) {
    unsafe { lookups::getnameinfo(channel, sa, salen, flags, callback, arg) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_getaddrinfo( channel: Channel, name: *const c_char, service: *const c_char, hints: *const ares_addrinfo_hints, callback: ares_addrinfo_callback, arg: *mut c_void, ) {
    unsafe { lookups::getaddrinfo(channel, name, service, hints, callback, arg) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_send(channel: Channel, qbuf: *const u8, qlen: c_int, callback: ares_callback, arg: *mut c_void) {
    unsafe { lookups::send(channel, qbuf, qlen, callback, arg) }
}

// ----- process -----

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process_fd(channel: Channel, read_fd: c_int, write_fd: c_int) {
    unsafe { process::process_fd(channel, read_fd, write_fd) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    unsafe { process::process(channel, read_fds, write_fds) }
}

// ----- parsers -----

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_mx_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresMxReply) -> c_int {
    unsafe { parsers::parse_mx_reply(abuf, alen, out) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReply) -> c_int {
    unsafe { parsers::parse_txt_reply(abuf, alen, out) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply_ext(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReplyExt) -> c_int {
    unsafe { parsers::parse_txt_reply_ext(abuf, alen, out) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_caa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresCaaReply) -> c_int {
    unsafe { parsers::parse_caa_reply(abuf, alen, out) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_naptr_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresNaptrReply) -> c_int {
    unsafe { parsers::parse_naptr_reply(abuf, alen, out) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_srv_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSrvReply) -> c_int {
    unsafe { parsers::parse_srv_reply(abuf, alen, out) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_uri_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresUriReply) -> c_int {
    unsafe { parsers::parse_uri_reply(abuf, alen, out) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_ns_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    unsafe { parsers::parse_ns_reply(abuf, alen, out) }
}

/// # Safety
/// `abuf` must be valid for `alen` bytes; `out`, `addrttls`, and `out_naddrttls` must be valid, writable pointers.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_a_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addrttl, out_naddrttls: *mut c_int) -> c_int {
    unsafe { parsers::parse_a_reply(abuf, alen, out, addrttls, out_naddrttls) }
}

/// # Safety
/// `abuf` must be valid for `alen` bytes; `out`, `addrttls`, and `out_naddrttls` must be valid, writable pointers.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_aaaa_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addr6ttl, out_naddrttls: *mut c_int) -> c_int {
    unsafe { parsers::parse_aaaa_reply(abuf, alen, out, addrttls, out_naddrttls) }
}

/// # Safety
/// `abuf` must be valid for `alen` bytes and `addr` for `addrlen` bytes; `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_ptr_reply(abuf: *const u8, alen: c_int, addr: *const c_void, addrlen: c_int, family: c_int, out: *mut *mut libc::hostent) -> c_int {
    unsafe { parsers::parse_ptr_reply(abuf, alen, addr, addrlen, family, out) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_soa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSoaReply) -> c_int {
    unsafe { parsers::parse_soa_reply(abuf, alen, out) }
}

/// # Safety
/// `hostent` must be NULL or a pointer previously returned by this library.
#[no_mangle]
pub unsafe extern "C" fn ares_free_hostent(hostent: *mut libc::hostent) {
    unsafe { parsers::free_hostent(hostent) }
}

/// # Safety
/// `s` must be NULL or a pointer previously returned by this library.
#[no_mangle]
pub unsafe extern "C" fn ares_free_string(s: *mut libc::c_void) {
    unsafe { parsers::free_string(s) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int {
    unsafe { parsers::inet_pton(af, src, dst) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_expand_name( encoded: *const u8, abuf: *const u8, alen: c_int, s: *mut *mut c_char, enclen: *mut libc::c_long, ) -> c_int {
    unsafe { parsers::expand_name(encoded, abuf, alen, s, enclen) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: libc::socklen_t) -> *const c_char {
    unsafe { parsers::inet_ntop(af, src, dst, size) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_expand_string( encoded: *const u8, abuf: *const u8, alen: c_int, s: *mut *mut u8, enclen: *mut libc::c_long, ) -> c_int {
    unsafe { parsers::expand_string(encoded, abuf, alen, s, enclen) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_create_query( name: *const c_char, dnsclass: c_int, qtype: c_int, id: c_int, rd: c_int, buf: *mut *mut u8, buflen: *mut c_int, max_udp_size: c_int, ) -> c_int {
    unsafe { parsers::create_query(name, dnsclass, qtype, id, rd, buf, buflen, max_udp_size) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_mkquery( name: *const c_char, dnsclass: c_int, qtype: c_int, id: c_int, rd: c_int, buf: *mut *mut u8, buflen: *mut c_int, ) -> c_int {
    unsafe { parsers::mkquery(name, dnsclass, qtype, id, rd, buf, buflen) }
}

// ----- addrinfo -----

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_freeaddrinfo(ai: *mut ares_addrinfo) {
    unsafe { addrinfo::freeaddrinfo(ai) }
}

// ----- ares_options -----

/// # Safety
/// `out_channel` must be non-null; `options` must be NULL or a valid `ares_options` consistent with `optmask`.
#[no_mangle]
pub unsafe extern "C" fn ares_init_options(out_channel: *mut Channel, options: *const ares_options::ares_options, optmask: c_int) -> c_int {
    unsafe { ares_options::init_options(out_channel, options, optmask) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_save_options(channel: Channel, options: *mut ares_options::ares_options, optmask: *mut c_int) -> c_int {
    unsafe { ares_options::save_options(channel, options, optmask) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy_options(options: *mut ares_options::ares_options) {
    unsafe { ares_options::destroy_options(options) }
}

// ----- ares_socket -----

/// # Safety
/// `channel` must be a valid channel and `funcs` must be NULL or point to a valid function table.
#[no_mangle]
pub unsafe extern "C" fn ares_set_socket_functions(channel: Channel, funcs: *const AresSocketFunctions, user_data: *mut c_void) {
    unsafe { ares_socket::set_socket_functions(channel, funcs, user_data) }
}

/// # Safety
/// `channel` must be a valid channel and `funcs` must be NULL or point to a valid function table.
#[no_mangle]
pub unsafe extern "C" fn ares_set_socket_functions_ex(channel: Channel, funcs: *const ares_socket::AresSocketFunctionsEx, user_data: *mut c_void) -> c_int {
    unsafe { ares_socket::set_socket_functions_ex(channel, funcs, user_data) }
}

// ----- ares_data -----

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_free_data(dataptr: *mut c_void) {
    unsafe { ares_data::free_data(dataptr) }
}

// ----- error -----

#[no_mangle]
pub extern "C" fn ares_strerror(code: c_int) -> *const c_char {
    error::strerror(code)
}

// ----- dns_record -----

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_create( dnsrec: *mut *mut dns_record::ares_dns_record_t, id: c_uint, flags: c_uint, opcode: c_uint, rcode: c_uint, ) -> c_int {
    unsafe { dns_record::dns_record_create(dnsrec, id, flags, opcode, rcode) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_destroy(dnsrec: *mut dns_record::ares_dns_record_t) {
    unsafe { dns_record::dns_record_destroy(dnsrec) }
}

/// Duplicate a DNS record via serialize/parse round-trip.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_duplicate( dnsrec: *const dns_record::ares_dns_record_t, ) -> *mut dns_record::ares_dns_record_t {
    unsafe { dns_record::dns_record_duplicate(dnsrec) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_get_id( dnsrec: *const dns_record::ares_dns_record_t, ) -> c_uint {
    unsafe { dns_record::dns_record_get_id(dnsrec) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_get_flags( dnsrec: *const dns_record::ares_dns_record_t, ) -> c_uint {
    unsafe { dns_record::dns_record_get_flags(dnsrec) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_get_opcode( dnsrec: *const dns_record::ares_dns_record_t, ) -> c_uint {
    unsafe { dns_record::dns_record_get_opcode(dnsrec) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_get_rcode( dnsrec: *const dns_record::ares_dns_record_t, ) -> c_uint {
    unsafe { dns_record::dns_record_get_rcode(dnsrec) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_set_id( dnsrec: *mut dns_record::ares_dns_record_t, id: c_uint, ) {
    unsafe { dns_record::dns_record_set_id(dnsrec, id) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_query_add( dnsrec: *mut dns_record::ares_dns_record_t, name: *const c_char, qtype: c_uint, qclass: c_uint, ) -> c_int {
    unsafe { dns_record::dns_record_query_add(dnsrec, name, qtype, qclass) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_query_cnt( dnsrec: *const dns_record::ares_dns_record_t, ) -> libc::size_t {
    unsafe { dns_record::dns_record_query_cnt(dnsrec) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_query_get( dnsrec: *const dns_record::ares_dns_record_t, idx: libc::size_t, name: *mut *const c_char, qtype: *mut c_uint, qclass: *mut c_uint, ) -> c_int {
    unsafe { dns_record::dns_record_query_get(dnsrec, idx, name, qtype, qclass) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_query_set_name( dnsrec: *mut dns_record::ares_dns_record_t, idx: libc::size_t, name: *const c_char, ) -> c_int {
    unsafe { dns_record::dns_record_query_set_name(dnsrec, idx, name) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_query_set_type( dnsrec: *mut dns_record::ares_dns_record_t, idx: libc::size_t, qtype: c_uint, ) -> c_int {
    unsafe { dns_record::dns_record_query_set_type(dnsrec, idx, qtype) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_rr_add( rr: *mut *mut dns_record::ares_dns_rr_t, dnsrec: *mut dns_record::ares_dns_record_t, sect: c_uint, name: *const c_char, rtype: c_uint, rclass: c_uint, ttl: c_uint, ) -> c_int {
    unsafe { dns_record::dns_record_rr_add(rr, dnsrec, sect, name, rtype, rclass, ttl) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_rr_cnt( dnsrec: *const dns_record::ares_dns_record_t, sect: c_uint, ) -> libc::size_t {
    unsafe { dns_record::dns_record_rr_cnt(dnsrec, sect) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_rr_get( dnsrec: *mut dns_record::ares_dns_record_t, sect: c_uint, idx: libc::size_t, ) -> *mut dns_record::ares_dns_rr_t {
    unsafe { dns_record::dns_record_rr_get(dnsrec, sect, idx) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_rr_get_const( dnsrec: *const dns_record::ares_dns_record_t, sect: c_uint, idx: libc::size_t, ) -> *const dns_record::ares_dns_rr_t {
    unsafe { dns_record::dns_record_rr_get_const(dnsrec, sect, idx) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_record_rr_del( dnsrec: *mut dns_record::ares_dns_record_t, sect: c_uint, idx: libc::size_t, ) -> c_int {
    unsafe { dns_record::dns_record_rr_del(dnsrec, sect, idx) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_name( rr: *const dns_record::ares_dns_rr_t, ) -> *const c_char {
    unsafe { dns_record::dns_rr_get_name(rr) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_type(rr: *const dns_record::ares_dns_rr_t) -> c_uint {
    unsafe { dns_record::dns_rr_get_type(rr) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_class(rr: *const dns_record::ares_dns_rr_t) -> c_uint {
    unsafe { dns_record::dns_rr_get_class(rr) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_ttl(rr: *const dns_record::ares_dns_rr_t) -> c_uint {
    unsafe { dns_record::dns_rr_get_ttl(rr) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_addr( rr: *const dns_record::ares_dns_rr_t, key: c_uint, ) -> *const libc::in_addr {
    unsafe { dns_record::dns_rr_get_addr(rr, key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_addr6( rr: *const dns_record::ares_dns_rr_t, key: c_uint, ) -> *const crate::ffi::ares_in6_addr {
    unsafe { dns_record::dns_rr_get_addr6(rr, key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_str( rr: *const dns_record::ares_dns_rr_t, key: c_uint, ) -> *const c_char {
    unsafe { dns_record::dns_rr_get_str(rr, key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_u8( rr: *const dns_record::ares_dns_rr_t, key: c_uint, ) -> u8 {
    unsafe { dns_record::dns_rr_get_u8(rr, key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_u16( rr: *const dns_record::ares_dns_rr_t, key: c_uint, ) -> u16 {
    unsafe { dns_record::dns_rr_get_u16(rr, key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_u32( rr: *const dns_record::ares_dns_rr_t, key: c_uint, ) -> u32 {
    unsafe { dns_record::dns_rr_get_u32(rr, key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_bin( rr: *const dns_record::ares_dns_rr_t, key: c_uint, len: *mut libc::size_t, ) -> *const u8 {
    unsafe { dns_record::dns_rr_get_bin(rr, key, len) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_set_addr( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, addr: *const libc::in_addr, ) -> c_int {
    unsafe { dns_record::dns_rr_set_addr(rr, key, addr) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_set_addr6( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, addr: *const crate::ffi::ares_in6_addr, ) -> c_int {
    unsafe { dns_record::dns_rr_set_addr6(rr, key, addr) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_set_str( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, val: *const c_char, ) -> c_int {
    unsafe { dns_record::dns_rr_set_str(rr, key, val) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_set_u8( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, val: u8, ) -> c_int {
    unsafe { dns_record::dns_rr_set_u8(rr, key, val) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_set_u16( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, val: u16, ) -> c_int {
    unsafe { dns_record::dns_rr_set_u16(rr, key, val) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_set_u32( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, val: u32, ) -> c_int {
    unsafe { dns_record::dns_rr_set_u32(rr, key, val) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_set_bin( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, val: *const u8, len: libc::size_t, ) -> c_int {
    unsafe { dns_record::dns_rr_set_bin(rr, key, val, len) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_set_opt( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, opt: c_uint, val: *const u8, val_len: libc::size_t, ) -> c_int {
    unsafe { dns_record::dns_rr_set_opt(rr, key, opt, val, val_len) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_opt_cnt( rr: *const dns_record::ares_dns_rr_t, key: c_uint, ) -> libc::size_t {
    unsafe { dns_record::dns_rr_get_opt_cnt(rr, key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_opt( rr: *const dns_record::ares_dns_rr_t, key: c_uint, idx: libc::size_t, opt: *mut c_uint, val: *mut *const u8, val_len: *mut libc::size_t, ) -> c_int {
    unsafe { dns_record::dns_rr_get_opt(rr, key, idx, opt, val, val_len) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_opt_byid( rr: *const dns_record::ares_dns_rr_t, key: c_uint, opt: c_uint, val: *mut *const u8, val_len: *mut libc::size_t, ) -> c_int {
    unsafe { dns_record::dns_rr_get_opt_byid(rr, key, opt, val, val_len) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_del_opt_byid( rr: *mut dns_record::ares_dns_rr_t, key: c_uint, opt: c_uint, ) -> c_int {
    unsafe { dns_record::dns_rr_del_opt_byid(rr, key, opt) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_parse( buf: *const u8, buf_len: libc::size_t, flags: c_uint, dnsrec: *mut *mut dns_record::ares_dns_record_t, ) -> c_int {
    unsafe { dns_record::dns_parse(buf, buf_len, flags, dnsrec) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_write( dnsrec: *const dns_record::ares_dns_record_t, buf: *mut *mut u8, buf_len: *mut libc::size_t, ) -> c_int {
    unsafe { dns_record::dns_write(dnsrec, buf, buf_len) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rec_type_tostr(rtype: c_uint) -> *const c_char {
    unsafe { dns_record::dns_rec_type_tostr(rtype) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rec_type_fromstr( rtype: *mut c_uint, str_ptr: *const c_char, ) -> c_int {
    unsafe { dns_record::dns_rec_type_fromstr(rtype, str_ptr) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_class_tostr(qclass: c_uint) -> *const c_char {
    unsafe { dns_record::dns_class_tostr(qclass) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_class_fromstr( str_ptr: *const c_char, qclass: *mut c_uint, ) -> c_int {
    unsafe { dns_record::dns_class_fromstr(str_ptr, qclass) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_key_tostr(key: c_uint) -> *const c_char {
    unsafe { dns_record::dns_rr_key_tostr(key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_keys( rtype: c_uint, cnt: *mut libc::size_t, ) -> *const c_uint {
    unsafe { dns_record::dns_rr_get_keys(rtype, cnt) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_key_datatype(key: c_uint) -> c_uint {
    unsafe { dns_record::dns_rr_key_datatype(key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_key_to_rec_type(key: c_uint) -> c_uint {
    unsafe { dns_record::dns_rr_key_to_rec_type(key) }
}

#[no_mangle]
pub extern "C" fn ares_dns_opcode_tostr(opcode: c_uint) -> *const c_char {
    dns_record::dns_opcode_tostr(opcode)
}

#[no_mangle]
pub extern "C" fn ares_dns_rcode_tostr(rcode: c_uint) -> *const c_char {
    dns_record::dns_rcode_tostr(rcode)
}

#[no_mangle]
pub extern "C" fn ares_dns_section_tostr(section: c_uint) -> *const c_char {
    dns_record::dns_section_tostr(section)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_abin_cnt( rr: *const dns_record::ares_dns_rr_t, key: c_uint, ) -> libc::size_t {
    unsafe { dns_record::dns_rr_get_abin_cnt(rr, key) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dns_rr_get_abin( rr: *const dns_record::ares_dns_rr_t, key: c_uint, idx: libc::size_t, len: *mut libc::size_t, ) -> *const u8 {
    unsafe { dns_record::dns_rr_get_abin(rr, key, idx, len) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_free(ptr: *mut c_void) {
    unsafe { dns_record::free(ptr) }
}

