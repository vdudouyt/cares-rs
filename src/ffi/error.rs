use std::ffi::{ c_int, c_char };
use crate::cstr;

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
pub const ARES_ECANCELLED: c_int = 24;
pub const ARES_ESERVICE: c_int = 25;
pub const ARES_ENOSERVER: c_int = 26;

#[no_mangle]
pub extern "C" fn ares_strerror(code: c_int) -> *const c_char {
    match code {
        ARES_SUCCESS => cstr!("Successful completion"),
        ARES_ENODATA => cstr!("DNS server returned answer with no data"),
        ARES_EFORMERR => cstr!("DNS server claims query was misformatted"),
        ARES_ESERVFAIL => cstr!("DNS server returned general failure"),
        ARES_ENOTFOUND => cstr!("Domain name not found"),
        ARES_ENOTIMP => cstr!("DNS server does not implement requested operation"),
        ARES_EREFUSED => cstr!("DNS server refused query"),
        ARES_EBADQUERY => cstr!("Misformatted DNS query"),
        ARES_EBADNAME => cstr!("Misformatted domain name"),
        ARES_EBADFAMILY => cstr!("Unsupported address family"),
        ARES_EBADRESP => cstr!("Misformatted DNS reply"),
        ARES_ECONNREFUSED => cstr!("Could not contact DNS servers"),
        ARES_ETIMEOUT => cstr!("Timeout while contacting DNS servers"),
        ARES_EOF => cstr!("End of file"),
        ARES_EFILE => cstr!("Error reading file"),
        ARES_ENOMEM => cstr!("Out of memory"),
        ARES_EDESTRUCTION => cstr!("Channel is being destroyed"),
        ARES_EBADSTR => cstr!("Misformatted string"),
        ARES_EBADFLAGS => cstr!("Illegal flags specified"),
        ARES_ENONAME => cstr!("Given hostname is not numeric"),
        ARES_EBADHINTS => cstr!("Illegal hints flags specified"),
        ARES_ENOTINITIALIZED => cstr!("c-ares library initialization not yet performed"),
        ARES_ECANCELLED => cstr!("DNS query cancelled"),
        ARES_ESERVICE => cstr!("Invalid service name or number"),
        ARES_ENOSERVER => cstr!("No DNS servers were configured"),
        _ => cstr!("unknown"),
    }
}
