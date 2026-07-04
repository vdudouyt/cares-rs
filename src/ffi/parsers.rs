//! Legacy ares_parse_*_reply parsers, hostent building, name expansion and
//! query construction (create_query/mkquery), and small buffer utilities.

use super::*;


/// A caller-array slot for one (address, ttl) pair; the wanted family and
/// the C field writes per flavor. Filtering/ordering is core's
/// (hostent::addrttl_fill) — this only transcribes.
pub(crate) trait AddrTTL {
    const WANT_V4: bool;
    fn write(&mut self, ip: &IpAddr, ttl: u32);
}

#[repr(C)]
pub struct ares_addrttl {
    pub ipaddr: libc::in_addr, // ipv4 (upstream: struct in_addr)
    pub ttl: c_int,
}

impl AddrTTL for ares_addrttl {
    const WANT_V4: bool = true;
    fn write(&mut self, ip: &IpAddr, ttl: u32) {
        if let IpAddr::V4(ipv4) = ip {
            self.ipaddr = libc::in_addr { s_addr: u32::from_ne_bytes(ipv4.octets()) };
            self.ttl = ttl as c_int;
        }
    }
}

#[repr(C)]
pub struct ares_addr6ttl {
    pub ip6addr: ares_in6_addr, // ipv6 (upstream: struct ares_in6_addr ip6addr)
    pub ttl: c_int,
}

impl AddrTTL for ares_addr6ttl {
    const WANT_V4: bool = false;
    fn write(&mut self, ip: &IpAddr, ttl: u32) {
        if let IpAddr::V6(ipv6) = ip {
            self.ip6addr = ares_in6_addr::from_octets(ipv6.octets());
            self.ttl = ttl as c_int;
        }
    }
}

pub use crate::core::response::{ParsedRRs, ParsedResponse};
use crate::core::hostent::{addrttl_fill, Hostent};
use crate::core::query_builder::build_query;
use crate::core::response::{
    addr_reply, empty_chain_status, expand_name_at, expand_string_at, push_synthetic_ptr,
    soa_status, txt_ext_items, ReplyRequire,
};
use crate::ffi::convert::malloc_bytes;

/// Build the C hostent graph from a core blueprint — pure transcription:
/// every inclusion/ordering/family decision was already made in core.
pub(crate) unsafe fn build_hostent(bp: Hostent) -> *mut libc::hostent {
    let addrlist: Vec<*mut i8> = bp
        .addrs
        .iter()
        .map(|ip| {
            let raw: Box<[u8]> = match ip {
                IpAddr::V4(v4) => Box::new(v4.octets()),
                IpAddr::V6(v6) => Box::new(v6.octets()),
            };
            Box::into_raw(raw) as *mut i8
        })
        .collect();
    let aliases: Vec<*mut i8> = bp.aliases.into_iter().map(|c| c.into_raw()).collect();
    let hostent = libc::hostent {
        h_name: bp.name.into_raw(),
        h_aliases: unsafe { cnullterminated::from_vec(aliases) },
        h_addrtype: bp.addrtype,
        h_length: bp.length as c_int,
        h_addr_list: unsafe { cnullterminated::from_vec(addrlist) },
    };
    Box::into_raw(Box::new(hostent))
}


/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_mx_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresMxReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresMxReply>(abuf, alen, out, RECORD_TYPE_MX) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresTxtReply>(abuf, alen, out, RECORD_TYPE_TXT) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply_ext(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReplyExt) -> c_int {
    if abuf.is_null() || alen < 0 {
        return ARES_EBADRESP;
    }
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let (answers, parsed_count) = match txt_ext_items(buf) {
        Ok(parts) => parts,
        Err(err) => return err.code(),
    };
    let Some(aresreplies) = answers.into_iter().map(|x| x.into_ares_data(buf)).collect::<Option<Vec<_>>>() else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_EBADRESP;
    };

    let Some(reply) = clinkedlist::chain_nodes(aresreplies) else {
        unsafe { *out = std::ptr::null_mut() };
        return empty_chain_status(parsed_count).code();
    };

    let aresdata: AresData<AresTxtReplyExt> = AresData { data_type: AresTxtReplyExt::datatype(), data: reply };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

pub(crate) unsafe fn parse_to_vec<'a, T1, T2>(buf: &'a [u8], expected_record_type: u16) -> Result<Vec<T2>, c_int>
where T1: RRParser<'a> + IntoAresData<T2>, T2: DataType
{
    let res = ParsedResponse::from_buf(buf).map_err(|e| e.code())?;
    let parsed_rrs = res.process_answers::<T1>(buf, expected_record_type).map_err(|e| e.code())?;
    parsed_rrs.items.into_iter().map(|x| x.into_ares_data(buf)).collect::<Option<Vec<_>>>().ok_or(ARES_EBADRESP)
}

pub(crate) unsafe fn parse_to_singleptr<T2>(abuf: *const u8, alen: c_int, out: *mut *mut T2, expected_record_type: u16) -> c_int
where T2: DataType, for<'a> T2: FromParsedBuf<'a, T2>
{
    let build = || {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let aresreplies = T2::parse_buf_to_vec(buf, expected_record_type)?;
        if aresreplies.len() > 1 {
            return Err(ARES_EBADRESP);
        }
        let reply = aresreplies.into_iter().next().ok_or(ARES_ENODATA)?;
        let aresdata: AresData<T2> = AresData { data_type: T2::datatype(), data: reply };
        let aresdata = Box::into_raw(Box::new(aresdata));
        unsafe { Ok(&mut (*aresdata).data as *mut _) }
    };
    unsafe { ares_fn_wrapper(out, build) }
}

/// Trait to bridge lifetime-carrying parsed types to the non-lifetime output type.
/// This avoids HRTB issues with parse_to_clinkedlist/parse_to_singleptr.
pub(crate) trait FromParsedBuf<'a, T2> {
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
                let res = ParsedResponse::from_buf(buf).map_err(|e| e.code())?;
                let parsed_rrs = res.process_answers::<$t1>(buf, expected_record_type).map_err(|e| e.code())?;
                let success = parsed_rrs.success;
                let aresreplies = parsed_rrs.items.into_iter().map(|x| x.into_ares_data(buf)).collect::<Option<Vec<_>>>().ok_or(ARES_EBADRESP)?;
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

pub(crate) unsafe fn parse_to_clinkedlist<T2>(abuf: *const u8, alen: c_int, out: *mut *mut T2, expected_record_type: u16) -> c_int
where T2: CLinkedList + DataType, for<'a> T2: FromParsedBuf<'a, T2> {
    let build = || {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let (aresreplies, success) = T2::parse_buf_to_clinkedlist_parts(buf, expected_record_type)?;
        let Some(reply) = clinkedlist::chain_nodes(aresreplies) else {
            return Err(empty_chain_status(success).code());
        };

        let aresdata: AresData<T2> = AresData { data_type: T2::datatype(), data: reply };
        let aresdata = Box::into_raw(Box::new(aresdata));
        unsafe { Ok(&mut (*aresdata).data as *mut _) }
    };
    unsafe { ares_fn_wrapper(out, build) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_caa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresCaaReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresCaaReply>(abuf, alen, out, RECORD_TYPE_CAA) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_naptr_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresNaptrReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresNaptrReply>(abuf, alen, out, RECORD_TYPE_NAPTR) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_srv_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSrvReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresSrvReply>(abuf, alen, out, RECORD_TYPE_SRV) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_uri_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresUriReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresUriReply>(abuf, alen, out, RECORD_TYPE_URI) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_ns_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    unsafe { parse_to_hostent(RECORD_TYPE_NS, abuf, alen, out, std::ptr::null_mut::<ares_addrttl>(), std::ptr::null_mut(), 0) }
}

pub(crate) unsafe fn parse_to_hostent<T: AddrTTL>(expected_record_type: u16, abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, out_addrttls: *mut T, out_naddrttls: *mut c_int, family: c_int) -> c_int {
    let try_parse = || -> Result<ParsedRRs<AddrRecord>, c_int> {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        addr_reply(buf, expected_record_type, ReplyRequire::ItemsOrAliases).map_err(|e| e.code())
    };
    let on_success = |res: ParsedRRs<AddrRecord>| -> c_int {
        if !out_addrttls.is_null() && !out_naddrttls.is_null() {
            let pairs = addrttl_fill(&res.items, T::WANT_V4, unsafe { *out_naddrttls } as usize);
            for (i, (ip, ttl)) in pairs.iter().enumerate() {
                unsafe { (*out_addrttls.add(i)).write(ip, *ttl) };
            }
            unsafe { *out_naddrttls = pairs.len() as c_int };
        }
        if !out.is_null() {
            unsafe { *out = build_hostent(Hostent::from_parsed(res, family)); }
        }
        ARES_SUCCESS
    };
    let on_error = |status: c_int| -> c_int {
        if !out.is_null() { unsafe { *out = std::ptr::null_mut(); } }
        if !out_naddrttls.is_null() { unsafe { *out_naddrttls = 0; } }
        status
    };
    match try_parse() {
        Ok(res) => on_success(res),
        Err(err) => on_error(err),
    }
}

/// # Safety
/// `abuf` must be valid for `alen` bytes; `out`, `addrttls`, and `out_naddrttls` must be valid, writable pointers.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_a_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addrttl, out_naddrttls: *mut c_int) -> c_int {
    unsafe { parse_to_hostent(RECORD_TYPE_A, abuf, alen, out, addrttls, out_naddrttls, libc::AF_INET) }
}

/// # Safety
/// `abuf` must be valid for `alen` bytes; `out`, `addrttls`, and `out_naddrttls` must be valid, writable pointers.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_aaaa_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addr6ttl, out_naddrttls: *mut c_int) -> c_int {
    unsafe { parse_to_hostent(RECORD_TYPE_AAAA, abuf, alen, out, addrttls, out_naddrttls, libc::AF_INET6) }
}

/// # Safety
/// `abuf` must be valid for `alen` bytes and `addr` for `addrlen` bytes; `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_ptr_reply(abuf: *const u8, alen: c_int, addr: *const c_void, addrlen: c_int, family: c_int, out: *mut *mut libc::hostent) -> c_int {
    let build = || {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let mut addr_records = addr_reply(buf, RECORD_TYPE_PTR, ReplyRequire::Aliases).map_err(|e| e.code())?;
        if addr.is_null() || addrlen < 0 {
            return Err(ARES_EBADRESP);
        }
        let ipbuf = unsafe { std::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
        let ip = buf_to_ip(ipbuf).map_err(|_| ARES_EBADRESP)?;
        push_synthetic_ptr(&mut addr_records, ip);
        unsafe { Ok(build_hostent(Hostent::from_parsed(addr_records, family))) }
    };
    unsafe { ares_fn_wrapper(out, build) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_soa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSoaReply) -> c_int {
    soa_status(unsafe { parse_to_singleptr::<AresSoaReply>(abuf, alen, out, RECORD_TYPE_SOA) }.into()).code()
}

/// # Safety
/// `hostent` must be NULL or a pointer previously returned by this library.
#[no_mangle]
pub unsafe extern "C" fn ares_free_hostent(hostent: *mut libc::hostent) {
    unsafe { free_hostent(hostent) };
}

/// # Safety
/// `s` must be NULL or a pointer previously returned by this library.
#[no_mangle]
pub unsafe extern "C" fn ares_free_string(s: *mut libc::c_void) {
    // All buffers handed to the caller (ares_create_query/mkquery/expand_name/
    // expand_string/get_servers_csv) are libc::malloc'd, so free with libc::free.
    if !s.is_null() {
        unsafe { libc::free(s) };
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int {
    let Some(s) = (unsafe { cstr_opt(src) }) else { return 0 };
    match af {
        libc::AF_INET => {
            let Ok(addr) = s.parse::<std::net::Ipv4Addr>() else { return 0 };
            unsafe { std::ptr::copy_nonoverlapping(addr.octets().as_ptr(), dst as *mut u8, 4) };
            1
        }
        libc::AF_INET6 => {
            let Ok(addr) = s.parse::<std::net::Ipv6Addr>() else { return 0 };
            unsafe { std::ptr::copy_nonoverlapping(addr.octets().as_ptr(), dst as *mut u8, 16) };
            1
        }
        _ => -1,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_expand_name(
    encoded: *const u8,
    abuf: *const u8,
    alen: c_int,
    s: *mut *mut c_char,
    enclen: *mut libc::c_long,
) -> c_int {
    if encoded.is_null() || abuf.is_null() || s.is_null() || enclen.is_null() || alen < 0 {
        return ARES_EBADNAME;
    }
    let full_buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let offset = unsafe { encoded.offset_from(abuf) };
    if offset < 0 || offset as usize >= full_buf.len() {
        return ARES_EBADNAME;
    }
    let Some((cname, consumed)) = expand_name_at(full_buf, offset as usize) else {
        return ARES_EBADNAME;
    };
    let out = unsafe { malloc_cstr(cname.as_bytes()) };
    if out.is_null() { return ARES_ENOMEM; }
    unsafe {
        *s = out;
        *enclen = consumed as libc::c_long;
    }
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: libc::socklen_t) -> *const c_char {
    if src.is_null() || dst.is_null() { return std::ptr::null(); }
    match af {
        libc::AF_INET => {
            let addr = unsafe { *(src as *const [u8; 4]) };
            let s = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
            if s.len() + 1 > size as usize { return std::ptr::null(); }
            let cs = CString::new(s).unwrap();
            let bytes = cs.as_bytes_with_nul();
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len()) };
            dst
        }
        libc::AF_INET6 => {
            let addr = unsafe { *(src as *const [u8; 16]) };
            let ip6 = std::net::Ipv6Addr::from(addr);
            let s = ip6.to_string();
            if s.len() + 1 > size as usize { return std::ptr::null(); }
            let cs = CString::new(s).unwrap();
            let bytes = cs.as_bytes_with_nul();
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len()) };
            dst
        }
        _ => std::ptr::null(),
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_expand_string(
    encoded: *const u8,
    abuf: *const u8,
    alen: c_int,
    s: *mut *mut u8,
    enclen: *mut libc::c_long,
) -> c_int {
    if encoded.is_null() || abuf.is_null() || s.is_null() || enclen.is_null() || alen < 0 {
        return ARES_EBADSTR;
    }
    let full_buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let offset = unsafe { encoded.offset_from(abuf) };
    if offset < 0 || offset as usize >= full_buf.len() {
        return ARES_EBADSTR;
    }
    let Some((str_data, encoded_len)) = expand_string_at(full_buf, offset as usize) else {
        return ARES_EBADSTR;
    };
    let out = unsafe { malloc_cstr(str_data) };
    if out.is_null() { return ARES_ENOMEM; }
    unsafe {
        *s = out as *mut u8;
        *enclen = encoded_len as libc::c_long; // length byte + string bytes
    }
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_create_query(
    name: *const c_char,
    dnsclass: c_int,
    qtype: c_int,
    id: c_int,
    rd: c_int,
    buf: *mut *mut u8,
    buflen: *mut c_int,
    max_udp_size: c_int,
) -> c_int {
    if name.is_null() {
        return ARES_EFORMERR;
    }
    if buf.is_null() || buflen.is_null() {
        return ARES_EFORMERR;
    }
    let Some(name_str) = (unsafe { cstr_opt(name) }) else { return ARES_EBADNAME };

    let packet = match build_query(name_str, dnsclass as u16, qtype as u16, id as u16, rd != 0, max_udp_size) {
        Ok(p) => p,
        Err(e) => return e.code(),
    };
    let ptr = unsafe { malloc_bytes(&packet) };
    if ptr.is_null() { return ARES_ENOMEM; }
    unsafe {
        *buf = ptr;
        *buflen = packet.len() as c_int;
    }
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_mkquery(
    name: *const c_char,
    dnsclass: c_int,
    qtype: c_int,
    id: c_int,
    rd: c_int,
    buf: *mut *mut u8,
    buflen: *mut c_int,
) -> c_int {
    unsafe { ares_create_query(name, dnsclass, qtype, id, rd, buf, buflen, 0) }
}
