use std::ffi::CString;
use crate::ffi::cnullterminated;

pub unsafe fn free_hostent(hostent: *mut libc::hostent) {
    // Upstream ares_free_hostent treats a NULL host as a no-op (`if (!host) return;`).
    if hostent.is_null() { return; }
    unsafe {
        let hostent = Box::from_raw(hostent);
        drop(CString::from_raw(hostent.h_name));
        let vec = cnullterminated::into_vec(hostent.h_aliases);
        for v in vec { drop(CString::from_raw(v)); }
        let vec = cnullterminated::into_vec(hostent.h_addr_list);
        for v in vec { drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(v, hostent.h_length as usize))); }
    }
}
