use std::ffi::{ c_int, c_char };

pub const ARES_SUCCESS: c_int = 0;
pub const ARES_ENODATA: c_int = 1;
pub const ARES_EFORMERR: c_int = 2;
pub const ARES_ESERVFAIL: c_int = 3;
pub const ARES_ENOTFOUND: c_int = 4;
pub const ARES_ENOTIMP: c_int = 5;
pub const ARES_EREFUSED: c_int = 6;
pub const ARES_EBADQUERY: c_int = 7;
pub const ARES_EBADNAME: c_int = 8;
pub const ARES_EBADFAMILY: c_int = 9;
pub const ARES_EBADRESP: c_int = 10;
pub const ARES_ECONNREFUSED: c_int = 11;
pub const ARES_ETIMEOUT: c_int = 12;
pub const ARES_EOF: c_int = 13;
pub const ARES_EFILE: c_int = 14;
pub const ARES_ENOMEM: c_int = 15;
pub const ARES_EDESTRUCTION: c_int = 16;
pub const ARES_EBADSTR: c_int = 17;
pub const ARES_EBADFLAGS: c_int = 18;
pub const ARES_ENONAME: c_int = 19;
pub const ARES_EBADHINTS: c_int = 20;
pub const ARES_ENOTINITIALIZED: c_int = 21;
pub const ARES_ELOADIPHLPAPI: c_int = 22;
pub const ARES_EADDRGETNETWORKPARAMS: c_int = 23;
pub const ARES_ECANCELLED: c_int = 24;
pub const ARES_ESERVICE: c_int = 25;
pub const ARES_ENOSERVER: c_int = 26;

#[no_mangle]
pub extern "C" fn ares_strerror(code: c_int) -> *const c_char {
    match code {
        ARES_SUCCESS => c"Successful completion".as_ptr(),
        ARES_ENODATA => c"DNS server returned answer with no data".as_ptr(),
        ARES_EFORMERR => c"DNS server claims query was misformatted".as_ptr(),
        ARES_ESERVFAIL => c"DNS server returned general failure".as_ptr(),
        ARES_ENOTFOUND => c"Domain name not found".as_ptr(),
        ARES_ENOTIMP => c"DNS server does not implement requested operation".as_ptr(),
        ARES_EREFUSED => c"DNS server refused query".as_ptr(),
        ARES_EBADQUERY => c"Misformatted DNS query".as_ptr(),
        ARES_EBADNAME => c"Misformatted domain name".as_ptr(),
        ARES_EBADFAMILY => c"Unsupported address family".as_ptr(),
        ARES_EBADRESP => c"Misformatted DNS reply".as_ptr(),
        ARES_ECONNREFUSED => c"Could not contact DNS servers".as_ptr(),
        ARES_ETIMEOUT => c"Timeout while contacting DNS servers".as_ptr(),
        ARES_EOF => c"End of file".as_ptr(),
        ARES_EFILE => c"Error reading file".as_ptr(),
        ARES_ENOMEM => c"Out of memory".as_ptr(),
        ARES_EDESTRUCTION => c"Channel is being destroyed".as_ptr(),
        ARES_EBADSTR => c"Misformatted string".as_ptr(),
        ARES_EBADFLAGS => c"Illegal flags specified".as_ptr(),
        ARES_ENONAME => c"Given hostname is not numeric".as_ptr(),
        ARES_EBADHINTS => c"Illegal hints flags specified".as_ptr(),
        ARES_ENOTINITIALIZED => c"c-ares library initialization not yet performed".as_ptr(),
        ARES_ELOADIPHLPAPI => c"Error loading iphlpapi.dll".as_ptr(),
        ARES_EADDRGETNETWORKPARAMS => c"Could not find GetNetworkParams function".as_ptr(),
        ARES_ECANCELLED => c"DNS query cancelled".as_ptr(),
        ARES_ESERVICE => c"Invalid service name or number".as_ptr(),
        ARES_ENOSERVER => c"No DNS servers were configured".as_ptr(),
        _ => c"unknown".as_ptr(),
    }
}
