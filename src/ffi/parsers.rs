//! Legacy ares_parse_*_reply parsers, hostent building, name expansion and
//! query construction (create_query/mkquery), and small buffer utilities.

use super::*;


pub(crate) trait AddrTTL {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()>;
}

#[repr(C)]
pub struct ares_addrttl {
    pub ipaddr: libc::in_addr, // ipv4 (upstream: struct in_addr)
    pub ttl: c_int,
}

impl AddrTTL for ares_addrttl {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()> {
        let IpAddr::V4(ipv4) = ip else { return None };
        self.ipaddr = libc::in_addr { s_addr: u32::from_ne_bytes(ipv4.octets()) };
        self.ttl = ttl as c_int;
        Some(())
    }
}

#[repr(C)]
pub struct ares_addr6ttl {
    pub ip6addr: ares_in6_addr, // ipv6 (upstream: struct ares_in6_addr ip6addr)
    pub ttl: c_int,
}

impl AddrTTL for ares_addr6ttl {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()> {
        let IpAddr::V6(ipv6) = ip else { return None };
        self.ip6addr = ares_in6_addr::from_octets(ipv6.octets());
        self.ttl = ttl as c_int;
        Some(())
    }
}

pub(crate) unsafe fn hostent_from_lookup(lookup: HostLookup) -> *mut libc::hostent {
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
        .filter_map(|s| CString::new(s).ok().map(|c| c.into_raw())) // drop NUL-containing aliases
        .collect();

    let hostent = libc::hostent {
        h_name: CString::new(lookup.canonical).unwrap_or_default().into_raw(),
        h_aliases: unsafe { cnullterminated::from_vec(aliases) },
        h_addrtype,
        h_length: h_length as c_int,
        h_addr_list: unsafe { cnullterminated::from_vec(addrlist) },
    };

    Box::into_raw(Box::new(hostent))
}

#[derive(Debug)]
pub(crate) struct ParsedResponse<'a> {
    pub query: DnsQuery<'a>,
    pub answers: Vec<DnsAnswer<'a>>,
}

#[derive(Debug)]
pub(crate) struct ParsedRRs<T> {
    pub(crate) items: Vec<T>,
    pub(crate) name: CString,
    pub(crate) aliases: Vec<CString>,
    pub(crate) _limit_ttl: Option<u32>,
    pub(crate) success: usize,
}

impl ParsedRRs<AddrRecord> {
    pub(crate) unsafe fn into_raw_hostent(self, family: c_int) -> *mut libc::hostent {
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
            1 => return Err(ARES_EFORMERR),
            2 => return Err(ARES_ESERVFAIL),
            3 => return Err(ARES_ENOTFOUND),
            4 => return Err(ARES_ENOTIMP),
            5 => return Err(ARES_EREFUSED),
            _ => return Err(ARES_ENODATA),
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
        // Grow on demand rather than pre-allocating `answer_count` (ancount is
        // attacker-controlled, up to 65535, and DnsAnswer is large, so a tiny
        // response could otherwise reserve tens of MB). The loop is self-bounding:
        // each DnsAnswer::parse consumes >= 11 bytes, so it stops when the buffer
        // is exhausted regardless of the claimed ancount.
        let mut answers = Vec::new();
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
            query,
            answers,
        })
    }

    pub fn process_answers<T: RRParser<'a>>(self, buf: &[u8], expected_record_type: u16) -> Result<ParsedRRs<T>, c_int> {
        // The echoed question name comes from the (untrusted) response and may
        // contain an embedded NUL byte; fail gracefully instead of panicking.
        let mut name = CString::new(self.query.name.join(".")).map_err(|_| ARES_EBADRESP)?;
        let mut items: Vec<T> = Vec::with_capacity(self.answers.len());
        let mut success = 0;
        let mut aliases: Vec<CString> = vec![];
        let mut limit_ttl: Option<u32> = None;
        for mut answer in self.answers {
            if answer.record_type == RECORD_TYPE_CNAME {
                let mut cname_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut cname_buf).ok_or(ARES_EBADRESP)?;
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
                let alias_of = DnsLabel::parse(&mut ptr_buf).ok_or(ARES_EBADRESP)?;
                let alias_of = alias_of.build_cstring(buf).ok_or(ARES_EBADRESP)?;
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
        Ok(ParsedRRs { items, name, aliases, _limit_ttl: limit_ttl, success })
    }
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
    let Some(aresreplies) = answers.into_iter().map(|x| x.into_ares_data(buf)).collect::<Option<Vec<_>>>() else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_EBADRESP;
    };

    let Some(reply) = clinkedlist::chain_nodes(aresreplies) else {
        unsafe { *out = std::ptr::null_mut() };
        return if parsed_count > 0 { ARES_SUCCESS } else { ARES_EBADRESP };
    };

    let aresdata: AresData<AresTxtReplyExt> = AresData { data_type: AresTxtReplyExt::datatype(), data: reply };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

pub(crate) unsafe fn parse_to_vec<'a, T1, T2>(buf: &'a [u8], expected_record_type: u16) -> Result<Vec<T2>, c_int>
where T1: RRParser<'a> + IntoAresData<T2>, T2: DataType
{
    let res = ParsedResponse::from_buf(buf)?;
    let parsed_rrs = res.process_answers::<T1>(buf, expected_record_type)?;
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
                let res = ParsedResponse::from_buf(buf)?;
                let parsed_rrs = res.process_answers::<$t1>(buf, expected_record_type)?;
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
            return Err(if success > 0 { ARES_SUCCESS } else { ARES_EBADRESP });
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

impl DnsLabel<'_> {
    pub fn build_cstring(&self, main_buf: &[u8]) -> Option<CString> {
        CString::new(self.build_string(main_buf)?).ok()
    }
}


/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_ns_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    unsafe { parse_to_hostent(RECORD_TYPE_NS, abuf, alen, out, std::ptr::null_mut::<ares_addrttl>(), std::ptr::null_mut(), 0) }
}

pub(crate) fn iplist_to_raw(addrlist: &[std::net::IpAddr], length: usize) -> Vec<*mut i8> {
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

pub(crate) unsafe fn fill_addrttls<T: AddrTTL>(input: &[AddrRecord], addrttls: *mut T, naddrttls: usize) -> usize {
    let mut i = 0;
    for addr_record in input.iter() {
        if i >= naddrttls {
            break;
        }
        if (unsafe { &mut *addrttls.add(i) }).set_addr_ttl(&addr_record.ip, addr_record.ttl).is_some() {
            i += 1;
        }
    }
    i
}

pub(crate) unsafe fn parse_to_hostent<T: AddrTTL>(expected_record_type: u16, abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, out_addrttls: *mut T, out_naddrttls: *mut c_int, family: c_int) -> c_int {
    let try_parse = || -> Result<ParsedRRs<AddrRecord>, c_int> {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
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
            unsafe { *out_naddrttls = fill_addrttls(&res.items, out_addrttls, *out_naddrttls as usize) as c_int; }
        }
        if !out.is_null() {
            unsafe { *out = res.into_raw_hostent(family); }
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

impl RRParser<'_> for CString {
    fn parse_rr(answer: &DnsAnswer<'_>) -> Option<CString> {
        let mut buf = SliceBuf::new(answer.data);
        let name = DnsLabel::parse(&mut buf)?;
        name.build_cstring(answer.data)
    }
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
        let res = ParsedResponse::from_buf(buf)?;
        let mut addr_records = res.process_answers::<AddrRecord>(buf, RECORD_TYPE_PTR)?;
        if addr_records.aliases.is_empty() {
            return Err(ARES_ENODATA);
        }
        if addr.is_null() || addrlen < 0 {
            return Err(ARES_EBADRESP);
        }
        let ipbuf = unsafe { std::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
        let ip = buf_to_ip(ipbuf).map_err(|_| ARES_EBADRESP)?;
        addr_records.items.push(AddrRecord { ip, ttl: 0 });
        unsafe { Ok(addr_records.into_raw_hostent(family)) }
    };
    unsafe { ares_fn_wrapper(out, build) }
}

/// # Safety
/// `abuf` must point to `alen` readable bytes and `out` must be a valid, writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_parse_soa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSoaReply) -> c_int {
    let ret = unsafe { parse_to_singleptr::<AresSoaReply>(abuf, alen, out, RECORD_TYPE_SOA) };
    if ret == ARES_ENODATA { return ARES_EBADRESP; }
    ret
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
    let start = offset as usize;
    let local_buf = &full_buf[start..];
    let mut sbuf = SliceBuf::new(local_buf);
    let Some(label) = DnsLabel::parse(&mut sbuf) else {
        return ARES_EBADNAME;
    };
    let consumed = sbuf.pos;
    let Some(name_str) = label.build_string(full_buf) else {
        return ARES_EBADNAME;
    };
    let cname = match CString::new(name_str) {
        Ok(c) => c,
        Err(_) => return ARES_EBADNAME,
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
    let start = offset as usize;
    let remaining = &full_buf[start..];
    if remaining.is_empty() {
        return ARES_EBADSTR;
    }
    let str_len = remaining[0] as usize;
    if str_len + 1 > remaining.len() {
        return ARES_EBADSTR;
    }
    let str_data = &remaining[1..1 + str_len];
    // The string body comes from the (untrusted) buffer and may contain an
    // embedded NUL; reject it (can't be represented as a C string) instead of
    // returning a buffer a strlen-based consumer would silently truncate.
    if str_data.contains(&0) {
        return ARES_EBADSTR;
    }
    let out = unsafe { malloc_cstr(str_data) };
    if out.is_null() { return ARES_ENOMEM; }
    unsafe {
        *s = out as *mut u8;
        *enclen = (str_len + 1) as libc::c_long; // length byte + string bytes
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

    // Check if trailing dot is an unescaped separator (not a literal escaped dot)
    let has_unescaped_trailing_dot = if let Some(prefix) = name_str.strip_suffix('.') {
        // Count consecutive backslashes before the trailing dot
        let backslash_count = prefix
            .as_bytes()
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        // Even number of backslashes means dot is unescaped (separator)
        backslash_count % 2 == 0
    } else {
        false
    };

    // Reject .onion domains
    let lower = name_str.to_lowercase();
    let check = if has_unescaped_trailing_dot {
        lower.strip_suffix('.').unwrap_or(&lower)
    } else {
        &lower
    };
    if check.ends_with(".onion") || check == "onion" {
        return ARES_ENOTFOUND;
    }

    // Validate name length
    let clean_name = if has_unescaped_trailing_dot {
        name_str.strip_suffix('.').unwrap_or(name_str)
    } else {
        name_str
    };
    if clean_name.len() > 253 {
        return ARES_EBADNAME;
    }

    // Check for escaped dots and handle them
    let labels: Vec<&str> = if clean_name.is_empty() {
        vec![] // root query
    } else {
        // Handle escaped dots: split only on unescaped dots
        let mut result = Vec::new();
        let mut current_start = 0;
        let bytes = clean_name.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2; // skip escaped char
            } else if bytes[i] == b'.' {
                result.push(&clean_name[current_start..i]);
                current_start = i + 1;
                i += 1;
            } else {
                i += 1;
            }
        }
        if current_start <= bytes.len() {
            let last = &clean_name[current_start..];
            if !last.is_empty() {
                result.push(last);
            }
        }
        result
    };

    // Validate label lengths and reject empty labels
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.is_empty() {
            return ARES_EBADNAME;
        }
        if unescaped.len() > 63 {
            return ARES_EBADNAME;
        }
    }

    // Build DNS packet
    let flags: u16 = if rd != 0 { 0x0100 } else { 0x0000 }; // RD flag
    let mut packet = Vec::with_capacity(512);
    // Header
    packet.extend_from_slice(&(id as u16).to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    packet.extend_from_slice(&0u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0u16.to_be_bytes()); // nscount
    let arcount: u16 = if max_udp_size > 0 { 1 } else { 0 };
    packet.extend_from_slice(&arcount.to_be_bytes()); // arcount

    // Question: encode labels
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.len() > 63 { return ARES_EBADNAME; }
        packet.push(unescaped.len() as u8);
        packet.extend_from_slice(&unescaped);
    }
    packet.push(0); // root label
    packet.extend_from_slice(&(qtype as u16).to_be_bytes());
    packet.extend_from_slice(&(dnsclass as u16).to_be_bytes());

    // OPT pseudo-RR for EDNS if max_udp_size > 0
    if max_udp_size > 0 {
        packet.push(0); // root name
        packet.extend_from_slice(&41u16.to_be_bytes()); // type OPT
        packet.extend_from_slice(&(max_udp_size as u16).to_be_bytes()); // class = UDP payload size
        packet.extend_from_slice(&0u32.to_be_bytes()); // TTL (extended RCODE + flags)
        packet.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    }

    let len = packet.len();
    // Use raw allocation since DNS packets can contain null bytes
    let ptr = unsafe { libc::malloc(len) as *mut u8 };
    if ptr.is_null() { return ARES_ENOMEM; }
    unsafe {
        std::ptr::copy_nonoverlapping(packet.as_ptr(), ptr, len);
        *buf = ptr;
        *buflen = len as c_int;
    }
    ARES_SUCCESS
}

pub(crate) fn unescape_label(label: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(label.len());
    let bytes = label.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // Check for numeric escape \DDD
            if i + 3 < bytes.len() && bytes[i+1].is_ascii_digit() && bytes[i+2].is_ascii_digit() && bytes[i+3].is_ascii_digit() {
                let val = (bytes[i+1] - b'0') as u16 * 100 + (bytes[i+2] - b'0') as u16 * 10 + (bytes[i+3] - b'0') as u16;
                result.push(val as u8);
                i += 4;
            } else {
                result.push(bytes[i+1]);
                i += 2;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    result
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
