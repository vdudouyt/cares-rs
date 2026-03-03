mod ares_data;
mod ares_hostent;
mod ares_options;
pub mod ares_socket;
mod cnullterminated;
mod cstr;
mod clinkedlist;
mod error;
mod offset_of;

use std::ffi::{ c_int, c_void, c_char };
use std::os::fd::{ AsRawFd };
use std::ffi::{ CString, CStr };
use std::net::IpAddr;
use std::cmp::min;
use crate::core::packets::*;
use crate::core::ares::{ Ares, Status, Family };
use crate::core::servers_csv;
use crate::core::services::Services;
use crate::ffi::ares_hostent::*;
use crate::ffi::ares_data::*;
use crate::ffi::clinkedlist::*;
use crate::ffi::error::*;
use crate::cstr;
pub use crate::ffi::ares_socket::{SocketFactory, AresSocketFunctions};
use crate::core::hostfile::AddressFamily;
use std::io::Cursor;

pub const ARES_SUCCESS: i32 = 0;
pub const ARES_ENODATA: i32 = 1;
pub const ARES_EFORMERR: i32 = 2;
pub const ARES_ESERVFAIL: i32 = 3;
pub const ARES_ENOTFOUND: i32 = 4;
pub const ARES_ETIMEOUT: i32 = 12;
pub const ARES_LIB_INIT_ALL: i32 = 1;

#[allow(non_camel_case_types)]
pub type ares_socket_t = c_int;

#[no_mangle]
pub extern "C" fn ares_library_init(_flags: c_int) -> c_int {
    ARES_SUCCESS
}

#[no_mangle]
pub extern "C" fn ares_library_cleanup() {
}

pub type Channel = *mut ChannelData;

pub struct ChannelData {
    ares: Ares<FFIData>,
    sock_create_callback: Option<AresSockCreateCallback>,
    sock_create_callback_arg: *mut libc::c_void,
    readbuf: Vec<u8>,
}

#[derive(Debug)]
enum Callback {
    AresHostCallback(AresHostCallback),
    AresCallback(AresCallback),
    AresNameinfoCallback(AresNameinfoCallback),
}

impl Callback {
    fn run(&self, buf: Result<&[u8], c_int>, ffidata: &FFIData) {
        match self {
            Self::AresHostCallback(callback) => run_ares_host_callback(buf, *callback, ffidata),
            Self::AresCallback(callback) => run_ares_callback(buf, *callback, ffidata),
            Self::AresNameinfoCallback(callback) => run_ares_nameinfo_callback(buf, *callback, ffidata),
        }
    }
}

#[derive(Debug)]
struct FFIData {
    callback: Callback,
    arg: *mut c_void,
    family: c_int,
    expected_record_type: c_int,
    ip: Option<IpAddr>,
    // nameinfo-specific fields
    nameinfo_flags: c_int,
    port: u16,
    scope_id: u32,
}

#[repr(C)]
pub struct ares_addr_node {
    pub next: *mut ares_addr_node,
    pub family: c_int,
    pub data: [u8; 16], // enough to hold IPv6
}

trait AddrTTL {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()>;
}

#[derive(Debug)]
struct AddrRecord {
    ip: IpAddr,
    ttl: u32,
}

impl RRParser<'_> for AddrRecord {
    fn parse_rr(answer: &DnsAnswer<'_>) -> Option<Self> {
        Some(Self { ip: buf_to_ip(answer.data).ok()?, ttl: answer.ttl })
    }
}

#[repr(C)]
pub struct ares_addrttl {
    pub ipaddr: [u8; 4], // ipv4
    pub ttl: c_int,
}

impl AddrTTL for ares_addrttl {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()> {
        let IpAddr::V4(ipv4) = ip else { return None };
        (self.ipaddr, self.ttl) = (ipv4.octets(), ttl as c_int);
        Some(())
    }
}

#[repr(C)]
pub struct ares_addr6ttl {
    pub ipaddr: [u8; 16], // ipv6
    pub ttl: c_int,
}

impl AddrTTL for ares_addr6ttl {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()> {
        let IpAddr::V6(ipv6) = ip else { return None };
        (self.ipaddr, self.ttl) = (ipv6.octets(), ttl as c_int);
        Some(())
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let ares = Ares::from_sysconfig();
    let channeldata = ChannelData { ares, sock_create_callback: None, sock_create_callback_arg: std::ptr::null_mut(), readbuf: vec![0u8; 65_535] };
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    unsafe { drop(Box::from_raw(channel)); }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, hostname: *const c_char, family: c_int, callback: AresHostCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    let hostname = unsafe { CStr::from_ptr(hostname).to_str().unwrap_or("") };
    let (expected_record_type, core_family) = match family {
        libc::AF_INET => (RECORD_TYPE_A, Family::Ipv4),
        libc::AF_INET6 => (RECORD_TYPE_AAAA, Family::Ipv6),
        _ => {
            unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
            return;
        }
    };

    let ffidata = FFIData { callback: Callback::AresHostCallback(callback), arg, family, expected_record_type: expected_record_type as c_int, ip: None, nameinfo_flags: 0, port: 0, scope_id: 0 };
    let newtask = channeldata.ares.gethostbyname(hostname, core_family, ffidata);
    if let Some(cb) = channeldata.sock_create_callback {
        cb(newtask.sock.as_raw_fd(), libc::SOCK_DGRAM, channeldata.sock_create_callback_arg);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    if channel.is_null() { return ARES_ENOTFOUND; }
    let channeldata = unsafe { &mut *channel };
    let name_str = unsafe { CStr::from_ptr(name).to_str().unwrap_or("") };

    // Convert C family constant to our Family enum
    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => {
            unsafe { *host = std::ptr::null_mut() };
            return ARES_ENOTFOUND;
        }
    };

    // Lookup in the hosts file cache
    let Some(lookup) = channeldata.ares.hosts().lookup(&name_str, family_filter) else {
        unsafe { *host = std::ptr::null_mut() };
        return ARES_ENOTFOUND;
    };

    if lookup.addrs.is_empty() {
        unsafe { *host = std::ptr::null_mut() };
        return ARES_ENOTFOUND;
    }

    // Determine h_addrtype and h_length from the first address
    let (h_addrtype, h_length) = match lookup.addrs[0] {
        IpAddr::V4(_) => (libc::AF_INET, 4),
        IpAddr::V6(_) => (libc::AF_INET6, 16),
    };

    // Build address list
    let addrlist: Vec<*mut i8> = iplist_to_raw(&lookup.addrs, h_length);

    // Build aliases list
    let aliases: Vec<*mut i8> = lookup
        .aliases
        .into_iter()
        .map(|s| CString::new(s).unwrap().into_raw())
        .collect();

    let hostent = libc::hostent {
        h_name: CString::new(lookup.canonical).unwrap().into_raw(),
        h_aliases: unsafe { cnullterminated::from_vec(aliases) },
        h_addrtype: h_addrtype,
        h_length: h_length as c_int,
        h_addr_list: unsafe { cnullterminated::from_vec(addrlist) },
    };

    unsafe { *host = Box::into_raw(Box::new(hostent)) };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyaddr(channel: Channel, addr: *mut c_void, addrlen: c_int, family: c_int, callback: AresHostCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    if family != libc::AF_INET && family != libc::AF_INET6 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    let addrbuf = unsafe { std::slice::from_raw_parts(addr as *mut u8, addrlen as usize) };
    let addr = match buf_to_ip(addrbuf) {
        Ok(ip) => ip,
        Err(_) => {
            unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
            return;
        }
    };
    let ffidata = FFIData { callback: Callback::AresHostCallback(callback), arg, family, expected_record_type: RECORD_TYPE_PTR as c_int, ip: Some(addr), nameinfo_flags: 0, port: 0, scope_id: 0 };
    let newtask = channeldata.ares.gethostbyaddr(addr, ffidata);
    if let Some(cb) = channeldata.sock_create_callback {
        cb(newtask.sock.as_raw_fd(), libc::SOCK_DGRAM, channeldata.sock_create_callback_arg);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: AresCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    let name = unsafe { CStr::from_ptr(name).to_str().unwrap_or("") };
    let ffidata = FFIData { callback: Callback::AresCallback(callback), arg, family: 0, expected_record_type: 0, ip: None, nameinfo_flags: 0, port: 0, scope_id: 0 };
    channeldata.ares.query(name, dnsclass as u16, dnstype as u16, ffidata);
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
pub unsafe extern "C" fn ares_getnameinfo(channel: Channel, sa: *const libc::sockaddr, salen: libc::socklen_t, flags: c_int, callback: AresNameinfoCallback, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };

    // Extract IP address and port from sockaddr
    let addr_info = match extract_addr_port(sa, salen) {
        Ok(result) => result,
        Err(status) => {
            // Call callback with error
            unsafe { callback(arg, status, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
            return;
        }
    };

    // Adjust flags: if neither LOOKUPSERVICE nor LOOKUPHOST, default to LOOKUPHOST
    let flags = if (flags & ARES_NI_LOOKUPSERVICE) == 0 && (flags & ARES_NI_LOOKUPHOST) == 0 {
        flags | ARES_NI_LOOKUPHOST
    } else {
        flags
    };

    let want_host = (flags & ARES_NI_LOOKUPHOST) != 0;
    let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

    // If only service lookup requested (no host), return immediately
    if want_service && !want_host {
        let service = get_service_string(channeldata.ares.services(), addr_info.port, flags);
        let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        unsafe { callback(arg, ARES_SUCCESS, 0, std::ptr::null_mut(), service_ptr) };
        return;
    }

    // Host lookup requested
    if want_host {
        // Numeric host can be handled without DNS
        if (flags & ARES_NI_NUMERICHOST) != 0 {
            // ARES_NI_NUMERICHOST + ARES_NI_NAMEREQD is illegal (contradiction)
            if (flags & ARES_NI_NAMEREQD) != 0 {
                unsafe { callback(arg, ARES_EBADFLAGS, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
                return;
            }

            let node = CString::new(format_ip_with_scope(&addr_info.ip, addr_info.scope_id, flags)).unwrap();
            let service = if want_service {
                get_service_string(channeldata.ares.services(), addr_info.port, flags)
            } else {
                None
            };
            let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, ARES_SUCCESS, 0, node.into_raw(), service_ptr) };
            return;
        }

        // DNS lookup is necessary
        let ffidata = FFIData {
            callback: Callback::AresNameinfoCallback(callback),
            arg,
            family: addr_info.family,
            expected_record_type: RECORD_TYPE_PTR as c_int,
            ip: Some(addr_info.ip),
            nameinfo_flags: flags,
            port: addr_info.port,
            scope_id: addr_info.scope_id,
        };

        // Start the PTR lookup
        let newtask = channeldata.ares.gethostbyaddr(addr_info.ip, ffidata);
        if let Some(cb) = channeldata.sock_create_callback {
            cb(newtask.sock.as_raw_fd(), libc::SOCK_DGRAM, channeldata.sock_create_callback_arg);
        }
    }
}

/// Format an IP address with scope ID for IPv6 (e.g., "fe80::1%0")
fn format_ip_with_scope(ip: &IpAddr, scope_id: u32, flags: c_int) -> String {
    match ip {
        IpAddr::V6(_) => {
            if flags & ARES_NI_NUMERICSCOPE != 0 || scope_id != 0 {
                format!("{}%{}", ip, scope_id)
            } else {
                format!("{}%{}", ip, scope_id)
            }
        }
        IpAddr::V4(_) => ip.to_string(),
    }
}

/// Extracted address info from sockaddr
struct AddrInfo {
    ip: IpAddr,
    port: u16,
    family: c_int,
    scope_id: u32, // Only meaningful for IPv6
}

/// Extract IP address and port from a sockaddr structure
fn extract_addr_port(sa: *const libc::sockaddr, salen: libc::socklen_t) -> Result<AddrInfo, c_int> {
    if sa.is_null() {
        return Err(ARES_ENOMEM);
    }

    let family = unsafe { (*sa).sa_family as c_int };

    match family {
        libc::AF_INET => {
            if (salen as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(ARES_ENOMEM);
            }
            let sa_in = sa as *const libc::sockaddr_in;
            let addr_bytes = unsafe { (*sa_in).sin_addr.s_addr.to_ne_bytes() };
            let ip = IpAddr::from(addr_bytes);
            let port = unsafe { u16::from_be((*sa_in).sin_port) };
            Ok(AddrInfo { ip, port, family: libc::AF_INET, scope_id: 0 })
        }
        libc::AF_INET6 => {
            if (salen as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(ARES_ENOMEM);
            }
            let sa_in6 = sa as *const libc::sockaddr_in6;
            let addr_bytes = unsafe { (*sa_in6).sin6_addr.s6_addr };
            let ip = IpAddr::from(addr_bytes);
            let port = unsafe { u16::from_be((*sa_in6).sin6_port) };
            let scope_id = unsafe { (*sa_in6).sin6_scope_id };
            Ok(AddrInfo { ip, port, family: libc::AF_INET6, scope_id })
        }
        _ => Err(ARES_ENOTIMP),
    }
}

/// Get the service string based on flags
fn get_service_string(services: &Services, port: u16, flags: c_int) -> Option<CString> {
    if port == 0 {
        return None;
    }

    if flags & ARES_NI_NUMERICSERV != 0 {
        // Return numeric port
        return Some(CString::new(port.to_string()).unwrap());
    }

    // Determine protocol preference based on flags
    let prefer_udp = (flags & ARES_NI_DGRAM) != 0;

    // Try to look up the service name
    if let Some(name) = services.lookup_any(port, prefer_udp) {
        Some(CString::new(name).unwrap())
    } else {
        // Fall back to numeric port
        Some(CString::new(port.to_string()).unwrap())
    }
}

#[derive(Debug)]
struct ParsedResponse<'a> {
    pub transaction_id: u16,
    pub query: DnsQuery<'a>,
    pub answers: Vec<DnsAnswer<'a>>,
}

#[derive(Debug)]
struct ParsedRRs<T> {
    items: Vec<T>,
    name: CString,
    aliases: Vec<CString>,
    limit_ttl: Option<u32>,
    success: usize,
}

impl ParsedRRs<AddrRecord> {
    unsafe fn into_raw_hostent(self, family: c_int) -> *mut libc::hostent {
        let length = match family {
            libc::AF_INET => 4,
            libc::AF_INET6 => 16,
            _ => 0,
        };
        let mut addrlist: Vec<*mut i8> = Vec::with_capacity(self.items.len());
        for record in &self.items {
            let raw: Box<[u8]> = match record.ip {
                IpAddr::V4(v4) if length == 4 => Box::new(v4.octets()),
                IpAddr::V6(v6) if length == 16 => Box::new(v6.octets()),
                _ => continue,
            };
            addrlist.push(Box::into_raw(raw) as *mut i8);
        }
        let mut aliases: Vec<*mut i8> = Vec::with_capacity(self.aliases.len());
        for a in self.aliases {
            aliases.push(a.into_raw());
        }
        let hostent = libc::hostent {
            h_name: self.name.into_raw(),
            h_aliases: unsafe { cnullterminated::from_vec(aliases) },
            h_addrtype: family,
            h_length: length as c_int,
            h_addr_list: unsafe { cnullterminated::from_vec(addrlist) },
        };

        Box::into_raw(Box::new(hostent))
    }
}

impl<'a> ParsedResponse<'a> {
    pub fn from_buf(buf: &'a [u8]) -> Result<Self, c_int> {
        let mut sbuf = SliceBuf::new(buf);
        let Some(header) = DnsHeader::parse(&mut sbuf) else {
            return Err(ARES_EBADRESP);
        };
        match header.flags & 0x0f {
            0 => {},
            3 => return Err(ARES_ENOTFOUND),
            _ => return Err(ARES_ESERVFAIL),
        };
        if header.qdcount != 1 {
            return Err(ARES_EBADRESP);
        }
        let Some(query) = DnsQuery::parse(&mut sbuf) else {
            return Err(ARES_EBADRESP);
        };
        let answer_count = header.ancount as usize;
        if answer_count == 0 {
            return Err(ARES_ENODATA);
        }
        let mut answers = Vec::with_capacity(answer_count);
        // Only parse answer section (ancount); authority and additional sections are skipped
        for _ in 0..answer_count {
            let Some(answer) = DnsAnswer::parse(&mut sbuf) else {
                return Err(ARES_EBADRESP);
            };
            answers.push(answer);
        }
        if answers.is_empty() {
            return Err(ARES_ENODATA);
        }
        Ok(Self {
            transaction_id: header.transaction_id,
            query,
            answers,
        })
    }

    pub fn process_answers<T: RRParser<'a>>(self, buf: &[u8], expected_record_type: u16) -> Result<ParsedRRs<T>, c_int> {
        let mut name = CString::new(self.query.name.join(".")).unwrap();
        let mut items: Vec<T> = Vec::with_capacity(self.answers.len());
        let mut success = 0;
        let mut aliases: Vec<CString> = vec![];
        let mut limit_ttl: Option<u32> = None;
        for mut answer in self.answers {
            if answer.record_type == RECORD_TYPE_CNAME {
                let mut cname_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut cname_buf).unwrap();
                let alias_of = alias_of.build_cstring(buf).ok_or(ARES_EBADRESP)?;
                if expected_record_type != RECORD_TYPE_PTR {
                    aliases.push(name);
                    name = alias_of;
                    limit_ttl = Some(answer.ttl);
                }
            }

            if answer.record_type != expected_record_type {
                success += 1;
                continue;
            }

            if answer.record_type == RECORD_TYPE_PTR || answer.record_type == RECORD_TYPE_NS {
                let mut ptr_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut ptr_buf).unwrap();
                let alias_of = alias_of.build_cstring(buf).unwrap();
                aliases.push(alias_of.clone());
                if answer.record_type == RECORD_TYPE_PTR { name = alias_of; }
                continue;
            }

            if expected_record_type == RECORD_TYPE_A || expected_record_type == RECORD_TYPE_AAAA {
                if let Some(limit_ttl) = limit_ttl {
                    if answer.ttl > limit_ttl {
                        answer.ttl = limit_ttl;
                    }
                }
            }

            let Some(parsed) = T::parse_rr(&answer) else {
                continue;
            };
            success += 1;
            items.push(parsed);
        }
        Ok(ParsedRRs { items, name, aliases, limit_ttl, success })
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_mx_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresMxReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresMxReply>(abuf, alen, out, RECORD_TYPE_MX) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresTxtReply>(abuf, alen, out, RECORD_TYPE_TXT) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply_ext(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReplyExt) -> c_int {
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let res = match ParsedResponse::from_buf(buf) {
        Ok(res) => res,
        Err(err) => return err,
    };

    let parsed_rrs = match res.process_answers::<Vec<TxtReplyExt>>(buf, RECORD_TYPE_TXT) {
        Ok(res) => res,
        Err(err) => return err,
    };

    let answers = parsed_rrs.items;
    let parsed_count = parsed_rrs.success;
    let answers: Vec<_> = answers.into_iter().flatten().collect();
    let aresreplies: Vec<_> = answers.into_iter().map(|x| x.into_ares_data(buf)).collect();

    let Some(reply) = clinkedlist::chain_nodes(aresreplies) else {
        unsafe { *out = std::ptr::null_mut() };
        return if parsed_count > 0 { ARES_SUCCESS } else { ARES_EBADRESP };
    };

    let aresdata: AresData<AresTxtReplyExt> = AresData { data_type: AresTxtReplyExt::datatype(), data: reply };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

unsafe fn parse_to_vec<'a, T1, T2>(buf: &'a [u8], expected_record_type: u16) -> Result<Vec<T2>, c_int>
where T1: RRParser<'a> + IntoAresData<T2>, T2: DataType
{
    let res = ParsedResponse::from_buf(buf)?;
    let parsed_rrs = res.process_answers::<T1>(buf, expected_record_type)?;
    Ok(parsed_rrs.items.into_iter().map(|x| x.into_ares_data(buf)).collect())
}

unsafe fn parse_to_singleptr<T2>(abuf: *const u8, alen: c_int, out: *mut *mut T2, expected_record_type: u16) -> c_int
where T2: DataType, for<'a> T2: FromParsedBuf<'a, T2>
{
    ares_fn_wrapper(out, || {
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let aresreplies = T2::parse_buf_to_vec(buf, expected_record_type)?;
        if aresreplies.len() > 1 {
            return Err(ARES_EBADRESP);
        }
        let reply = aresreplies.into_iter().next().ok_or(ARES_ENODATA)?;
        let aresdata: AresData<T2> = AresData { data_type: T2::datatype(), data: reply };
        let aresdata = Box::into_raw(Box::new(aresdata));
        Ok(&mut (*aresdata).data)
    })
}

/// Trait to bridge lifetime-carrying parsed types to the non-lifetime output type.
/// This avoids HRTB issues with parse_to_clinkedlist/parse_to_singleptr.
trait FromParsedBuf<'a, T2> {
    fn parse_buf_to_vec(buf: &'a [u8], expected_record_type: u16) -> Result<Vec<T2>, c_int>;
    fn parse_buf_to_clinkedlist_parts(buf: &'a [u8], expected_record_type: u16) -> Result<(Vec<T2>, usize), c_int>;
}

// Macro to implement FromParsedBuf for each (T1, T2) pair
macro_rules! impl_from_parsed_buf {
    ($t1:ty, $t2:ty) => {
        impl<'a> FromParsedBuf<'a, $t2> for $t2 {
            fn parse_buf_to_vec(buf: &'a [u8], expected_record_type: u16) -> Result<Vec<$t2>, c_int> {
                unsafe { parse_to_vec::<$t1, $t2>(buf, expected_record_type) }
            }
            fn parse_buf_to_clinkedlist_parts(buf: &'a [u8], expected_record_type: u16) -> Result<(Vec<$t2>, usize), c_int> {
                let res = ParsedResponse::from_buf(buf)?;
                let parsed_rrs = res.process_answers::<$t1>(buf, expected_record_type)?;
                let success = parsed_rrs.success;
                let aresreplies: Vec<_> = parsed_rrs.items.into_iter().map(|x| x.into_ares_data(buf)).collect();
                Ok((aresreplies, success))
            }
        }
    };
}

impl_from_parsed_buf!(MxReply<'a>, AresMxReply);
impl_from_parsed_buf!(CaaReply<'a>, AresCaaReply);
impl_from_parsed_buf!(TxtReply<'a>, AresTxtReply);
impl_from_parsed_buf!(NaptrReply<'a>, AresNaptrReply);
impl_from_parsed_buf!(SoaReply<'a>, AresSoaReply);
impl_from_parsed_buf!(SrvReply<'a>, AresSrvReply);
impl_from_parsed_buf!(UriReply<'a>, AresUriReply);

unsafe fn parse_to_clinkedlist<T2>(abuf: *const u8, alen: c_int, out: *mut *mut T2, expected_record_type: u16) -> c_int
where T2: CLinkedList + DataType, for<'a> T2: FromParsedBuf<'a, T2> {
    ares_fn_wrapper(out, || {
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let (aresreplies, success) = T2::parse_buf_to_clinkedlist_parts(buf, expected_record_type)?;
        let Some(reply) = clinkedlist::chain_nodes(aresreplies) else {
            return Err(if success > 0 { ARES_SUCCESS } else { ARES_EBADRESP });
        };

        let aresdata: AresData<T2> = AresData { data_type: T2::datatype(), data: reply };
        let aresdata = Box::into_raw(Box::new(aresdata));
        Ok(&mut (*aresdata).data)
    })
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_caa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresCaaReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresCaaReply>(abuf, alen, out, RECORD_TYPE_CAA) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_naptr_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresNaptrReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresNaptrReply>(abuf, alen, out, RECORD_TYPE_NAPTR) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_srv_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSrvReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresSrvReply>(abuf, alen, out, RECORD_TYPE_SRV) }
}

unsafe fn ares_fn_wrapper<T, F>(out: *mut *mut T, f: F) -> c_int
where F: FnOnce() -> Result<*mut T, c_int>
{
    if out.is_null() {
        return ARES_ENOMEM;
    }
    match f() {
        Ok(res) => {
            unsafe { *out = res };
            ARES_SUCCESS
        },
        Err(err) => err,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_uri_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresUriReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresUriReply>(abuf, alen, out, RECORD_TYPE_URI) }
}

impl DnsLabel<'_> {
    pub fn build_cstring(&self, main_buf: &[u8]) -> Option<CString> {
        Some(CString::new(self.build_string(main_buf)?).ok()?)
    }
}


#[no_mangle]
pub unsafe extern "C" fn ares_parse_ns_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    parse_to_hostent(RECORD_TYPE_NS, abuf, alen, out, std::ptr::null_mut::<ares_addrttl>(), std::ptr::null_mut(), 0)
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

fn buf_to_ip(buf: &[u8]) -> Result<IpAddr, &'static str> {
    match buf.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(buf).unwrap())),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(buf).unwrap())),
        _ => Err("invalid IP byte length"),
    }
}

fn iplist_to_raw(addrlist: &[std::net::IpAddr], length: usize) -> Vec<*mut i8> {
    let mut ret: Vec<*mut i8> = vec![];
    for addr in addrlist {
        let t = match addr {
            IpAddr::V4(v4) => Box::new(v4.octets()) as Box<[u8]>,
            IpAddr::V6(v6) => Box::new(v6.octets()) as Box<[u8]>,
        };
        if t.len() == length {
            ret.push(Box::into_raw(t) as *mut i8);
        }
    }
    ret
}

unsafe fn fill_addrttls<T: AddrTTL>(input: &Vec<AddrRecord>, addrttls: *mut T, naddrttls: usize) -> usize {
    let mut i = 0;
    for addr_record in input.iter() {
        if i >= naddrttls {
            break;
        }
        if (*addrttls.add(i)).set_addr_ttl(&addr_record.ip, addr_record.ttl).is_some() {
            i += 1;
        }
    }
    i
}

unsafe fn parse_to_hostent<T: AddrTTL>(expected_record_type: u16, abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, out_addrttls: *mut T, out_naddrttls: *mut c_int, family: c_int) -> c_int {
    let try_parse = || -> Result<ParsedRRs<AddrRecord>, c_int> {
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let res = ParsedResponse::from_buf(buf)?;
        let addr_records = res.process_answers::<AddrRecord>(buf, expected_record_type)?;
        if addr_records.items.is_empty() && addr_records.aliases.is_empty() {
            return Err(ARES_ENODATA);
        }
        Ok(addr_records)
    };
    let on_success = |res: ParsedRRs<AddrRecord>| -> c_int {
        if !out_addrttls.is_null() && !out_naddrttls.is_null() {
            *out_naddrttls = fill_addrttls(&res.items, out_addrttls, *out_naddrttls as usize) as c_int;
        }
        if !out.is_null() {
            *out = res.into_raw_hostent(family);
        }
        ARES_SUCCESS
    };
    let on_error = |status: c_int| -> c_int {
        if !out.is_null() { *out = std::ptr::null_mut(); }
        if !out_naddrttls.is_null() { *out_naddrttls = 0; }
        status
    };
    match try_parse() {
        Ok(res) => on_success(res),
        Err(err) => on_error(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_a_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addrttl, out_naddrttls: *mut c_int) -> c_int {
    parse_to_hostent(RECORD_TYPE_A, abuf, alen, out, addrttls, out_naddrttls, libc::AF_INET)
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_aaaa_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addr6ttl, out_naddrttls: *mut c_int) -> c_int {
    parse_to_hostent(RECORD_TYPE_AAAA, abuf, alen, out, addrttls, out_naddrttls, libc::AF_INET6)
}

impl RRParser<'_> for CString {
    fn parse_rr(answer: &DnsAnswer<'_>) -> Option<CString> {
        let mut buf = SliceBuf::new(answer.data);
        let name = DnsLabel::parse(&mut buf)?;
        Some(name.build_cstring(answer.data)?)
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_ptr_reply(abuf: *const u8, alen: c_int, addr: *const c_void, addrlen: c_int, family: c_int, out: *mut *mut libc::hostent) -> c_int {
    ares_fn_wrapper(out, || {
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let res = ParsedResponse::from_buf(buf)?;
        let mut addr_records = res.process_answers::<AddrRecord>(buf, RECORD_TYPE_PTR)?;
        if addr_records.aliases.is_empty() {
            return Err(ARES_ENODATA);
        }
        let ipbuf = unsafe { std::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
        let ip = buf_to_ip(ipbuf).map_err(|_| ARES_EBADRESP)?;
        addr_records.items.push(AddrRecord { ip, ttl: 0 });
        Ok(addr_records.into_raw_hostent(family))
    })
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_soa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSoaReply) -> c_int {
    let ret = parse_to_singleptr::<AresSoaReply>(abuf, alen, out, RECORD_TYPE_SOA);
    if ret == ARES_ENODATA { return ARES_EBADRESP; }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_hostent(hostent: *mut libc::hostent) {
    unsafe { free_hostent(hostent) };
}

pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);
pub type AresCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int);
pub type AresSockCreateCallback = unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void);
pub type AresNameinfoCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, node: *mut c_char, service: *mut c_char);

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

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_fds(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    let channeldata = unsafe { &mut *channel };
    unsafe { libc::FD_ZERO(write_fds) };
    unsafe { libc::FD_ZERO(read_fds) };

    let mut nfds = 0;
    for task in &channeldata.ares.tasks {
        let fd = task.sock.as_raw_fd();
        match task.status {
            Status::Writing => unsafe { libc::FD_SET(fd, write_fds) },
            Status::Reading => unsafe { libc::FD_SET(fd, read_fds) },
            Status::Completed => continue,
        };
        if nfds < fd { nfds = fd + 1 }
    }
    nfds
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_timeout(channel: Channel, _maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval {
    let channeldata = unsafe { &mut *channel };
    let max_wait_time = channeldata.ares.max_wait_time().as_millis();
    unsafe {
        (*tv).tv_sec = (max_wait_time / 1000) as i64;
        (*tv).tv_usec = 1000 * (max_wait_time % 1000) as i64;
    };
    tv
}

fn run_ares_host_callback(res: Result<&[u8], c_int>, callback: AresHostCallback, ffidata: &FFIData) {
    let res = (|| {
        let buf = res?;
        let res = ParsedResponse::from_buf(buf)?;
        let mut addr_records = res.process_answers::<AddrRecord>(buf, ffidata.expected_record_type as u16)?;
        if addr_records.items.is_empty() && addr_records.aliases.is_empty() {
            return Err(ARES_ENODATA);
        }
        if ffidata.expected_record_type as u16 == RECORD_TYPE_PTR {
            addr_records.items.push(AddrRecord { ip: ffidata.ip.unwrap(), ttl: 0 });
        }
        Ok(unsafe { addr_records.into_raw_hostent(ffidata.family) })
    })();
    match res {
        Ok(raw_hostent) => {
            unsafe { callback(ffidata.arg, ARES_SUCCESS, 0, &mut *raw_hostent) };
            unsafe { ares_free_hostent(raw_hostent) };
        },
        Err(err) => unsafe { callback(ffidata.arg, err, 0, std::ptr::null_mut()) },
    }
}

fn run_ares_callback(res: Result<&[u8], c_int>, callback: AresCallback, ffidata: &FFIData) {
    match res {
        Ok(buf) => unsafe { callback(ffidata.arg, ARES_SUCCESS, 0, buf.as_ptr() as *mut u8, buf.len() as c_int) },
        Err(err) => unsafe { callback(ffidata.arg, err, 0, std::ptr::null_mut(), 0) },
    }
}

fn run_ares_nameinfo_callback(res: Result<&[u8], c_int>, callback: AresNameinfoCallback, ffidata: &FFIData) {
    let services = Services::default();

    let want_service = (ffidata.nameinfo_flags & ARES_NI_LOOKUPSERVICE) != 0;

    let hostname_result = (|| -> Result<CString, c_int> {
        let buf = res?;
        let parsed = ParsedResponse::from_buf(buf)?;
        let ptr_records = parsed.process_answers::<CString>(buf, RECORD_TYPE_PTR)?;

        if ptr_records.aliases.is_empty() {
            return Err(ARES_ENOTFOUND);
        }

        let mut name = ptr_records.name;

        if ffidata.nameinfo_flags & ARES_NI_NOFQDN != 0 {
            let name_str = name.to_string_lossy();
            if let Some(dot_pos) = name_str.find('.') {
                name = CString::new(&name_str[..dot_pos]).map_err(|_| ARES_EBADSTR)?;
            }
        }

        Ok(name)
    })();

    let (status, hostname) = match hostname_result {
        Ok(name) => (ARES_SUCCESS, Some(name)),
        Err(err) => {
            if err == ARES_ENOTFOUND && (ffidata.nameinfo_flags & ARES_NI_NAMEREQD) == 0 {
                let ip_str = format_ip_with_scope(&ffidata.ip.unwrap(), ffidata.scope_id, ffidata.nameinfo_flags);
                match CString::new(ip_str) {
                    Ok(name) => (ARES_SUCCESS, Some(name)),
                    Err(_) => {
                        unsafe { callback(ffidata.arg, ARES_EBADSTR, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
                        return;
                    }
                }
            } else {
                unsafe { callback(ffidata.arg, err, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
                return;
            }
        }
    };

    let service = if want_service {
        get_service_string(&services, ffidata.port, ffidata.nameinfo_flags)
    } else {
        None
    };

    let hostname_ptr = hostname.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
    let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
    unsafe { callback(ffidata.arg, status, 0, hostname_ptr, service_ptr) };
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    let channeldata = unsafe { &mut *channel };
    for task in &mut channeldata.ares.tasks {
        if task.is_expired() {
            let ffidata = &task.userdata;
            (ffidata.callback).run(Err(ARES_ETIMEOUT), &task.userdata);
            task.status = Status::Completed;
        }
    }
    channeldata.ares.remove_completed();

    let mut tasks = std::mem::take(&mut channeldata.ares.tasks);
    for task in &mut tasks {
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), write_fds) } {
            channeldata.ares.write_impl(task);
        }
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), read_fds) } {
            if let Some(len) = Ares::read_impl(task, &mut channeldata.readbuf) {
                (task.userdata.callback).run(Ok(&channeldata.readbuf[..len]), &task.userdata);
            }
        }
    }
    channeldata.ares.tasks = tasks;
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers(channel: Channel, mut head: *mut ares_addr_node) -> c_int {
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.config.nameservers.clear();
    while !head.is_null() {
        if unsafe { (*head).family } == libc::AF_INET {
            let node = unsafe { &(*head) };
            let oct4: [u8; 4] = node.data[0..4].try_into().unwrap();
            channeldata.ares.config.nameservers.push((IpAddr::from(oct4), None));
        }
        head = unsafe { (*head).next };
    }
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports(channel: Channel, mut head: *mut AresAddrPortNode) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.config.nameservers.clear();
    while !head.is_null() {
        let node = unsafe { &*head };
        let port = node.udp_port as u16;
        let port = if port == 0 || port == 53 { None } else { Some(port) };
        match node.family {
            libc::AF_INET => {
                let octets = unsafe { node.addr.addr4.s_addr.to_ne_bytes() };
                channeldata.ares.config.nameservers.push((IpAddr::from(octets), port));
            }
            libc::AF_INET6 => {
                let octets = unsafe { node.addr.addr6.s6_addr };
                channeldata.ares.config.nameservers.push((IpAddr::from(octets), port));
            }
            _ => {}
        }
        head = node.next;
    }
    ARES_SUCCESS
}

fn ipv4_to_in_addr(ip: IpAddr) -> Option<AresAddrUnion> {
    match ip {
        IpAddr::V4(v4) => {
            let addr = u32::from_ne_bytes(v4.octets());
            Some(AresAddrUnion { addr4: libc::in_addr { s_addr: addr } })
        }
        IpAddr::V6(_) => None,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_ports(channel: Channel, out: *mut *mut AresAddrPortNode) -> c_int {
    let channeldata = unsafe { &mut *channel };
    let mut data: Vec<AresAddrPortNode> = vec![];
    for srv in &channeldata.ares.config.nameservers {
        let (family, addr) = match srv.0 {
            IpAddr::V4(v4) => {
                let s_addr = u32::from_ne_bytes(v4.octets());
                (libc::AF_INET, AresAddrUnion { addr4: libc::in_addr { s_addr } })
            }
            IpAddr::V6(v6) => {
                (libc::AF_INET6, AresAddrUnion { addr6: libc::in6_addr { s6_addr: v6.octets() } })
            }
        };
        data.push(AresAddrPortNode {
            next: std::ptr::null_mut(),
            family,
            addr,
            udp_port: srv.1.unwrap_or(channeldata.ares.default_udp_port) as c_int,
            tcp_port: srv.1.unwrap_or(channeldata.ares.default_tcp_port) as c_int,
        });
    }
    let Some(replies) = clinkedlist::chain_nodes(data) else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_ENODATA;
    };
    let aresdata: AresData<AresAddrPortNode> = AresData { data_type: AresAddrPortNode::datatype(), data: replies };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports_csv(channel: Channel, servers: *const c_char) -> c_int {
    let channeldata = unsafe { &mut *channel };
    let mut cursor = Cursor::new(CStr::from_ptr(servers).to_str().unwrap());
    channeldata.ares.config.nameservers = servers_csv::parse_from_reader(&mut cursor).unwrap();
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn ares_version(version: *mut c_int) -> *const c_char {
    let (major, minor, patch) = (1, 17, 1);
    let v = (major << 16) | (minor << 8) | patch;
    if !version.is_null() { unsafe { *version = v } }
    cstr!("1.17.1-rs")
}

pub const ARES_GETSOCK_MAXNUM: usize = 16; // per c-ares headers
pub const ARES_SOCKET_BAD: ares_socket_t = -1;

#[no_mangle]
pub unsafe extern "C" fn ares_getsock(channel: Channel, socks: *mut ares_socket_t, numsocks: c_int) -> c_int {
    let channeldata = unsafe { &mut *channel };
    let n = min(ARES_GETSOCK_MAXNUM, numsocks as usize);

    let mut mask: c_int = 0;
    for i in 0..n {
        let maybe_task = channeldata.ares.tasks.get(i);
        std::ptr::write(socks.add(i), maybe_task.map(|x| x.sock.as_raw_fd()).unwrap_or(ARES_SOCKET_BAD));

        if maybe_task.is_some() {
            mask |= 1 << i; // No need to wait ARES_GETSOCK_WRITABLE for UDP sockets
        }
    }

    mask
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_string(s: *mut libc::c_void) {
    drop(CString::from_raw(s as *mut c_char));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_callback(channel: Channel, callback: Option<AresSockCreateCallback>, arg: *mut c_void) {
    let channeldata = unsafe { &mut *channel };
    channeldata.sock_create_callback = callback;
    channeldata.sock_create_callback_arg = arg;
}
