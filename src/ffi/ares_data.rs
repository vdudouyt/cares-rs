// Thin c-ares C ABI shims; the documented c-ares API contract is the safety contract.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{ c_void, c_char, c_ushort, c_int, c_uint };
use crate::mem::CString;
use crate::core::packets::{ TxtReply, TxtReplyExt, MxReply, CaaReply, NaptrReply, SoaReply, SrvReply, UriReply };
use crate::ffi::clinkedlist::*;
use crate::offset_of;

// Ownership: `ares_free_data` frees every chain explicitly via `free_chain`; no `Drop`
// walks `next`. Reply types free only their own fields. Node types are caller-constructable
// too, so they must have NO `Drop` (one would free the caller's stack instances).

pub trait IntoAresData<T> {
    /// Materialize a borrowed record, distinguishing malformed strings from OOM.
    fn into_ares_data(self, main_buf: &[u8]) -> Result<T, c_int>;
}

impl IntoAresData<AresTxtReply> for TxtReply<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Result<AresTxtReply, c_int> {
        txt_reply_node(self.txt.as_bytes())
    }
}

/// Build one TXT reply node; `length` excludes the added NUL terminator.
pub(crate) fn txt_reply_node(data: &[u8]) -> Result<AresTxtReply, c_int> {
    let txt = unsafe { crate::ffi::convert::malloc_cstr(data) }.cast::<u8>();
    if txt.is_null() { return Err(crate::ffi::error::ARES_ENOMEM); }
    Ok(AresTxtReply { next: std::ptr::null_mut(), txt, length: data.len() })
}

/// EXT sibling of [`txt_reply_node`].
pub(crate) fn txt_ext_node(data: &[u8], record_start: bool) -> Result<AresTxtReplyExt, c_int> {
    let txt = unsafe { crate::ffi::convert::malloc_cstr(data) }.cast::<u8>();
    if txt.is_null() { return Err(crate::ffi::error::ARES_ENOMEM); }
    Ok(AresTxtReplyExt {
        next: std::ptr::null_mut(),
        txt,
        length: data.len(),
        record_start: record_start as u8,
    })
}

impl IntoAresData<AresTxtReplyExt> for TxtReplyExt<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Result<AresTxtReplyExt, c_int> {
        txt_ext_node(self.txt.as_bytes(), self.record_start)
    }
}

impl IntoAresData<AresMxReply> for MxReply<'_> {
    fn into_ares_data(self, main_buf: &[u8]) -> Result<AresMxReply, c_int> {
        let name = self.label.try_cstring(main_buf)?;
        let raw_ptr = name.into_raw();
        Ok(AresMxReply { next: std::ptr::null_mut(), host: raw_ptr, priority: self.priority })
    }
}

unsafe fn restore_original_ptr(dataptr: *mut c_void) -> *mut c_void {
    unsafe { dataptr.byte_sub(offset_of!(AresData<*mut c_void>, data)) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_data(dataptr: *mut c_void) {
    if dataptr.is_null() { return; }
    let aresdata = unsafe { restore_original_ptr(dataptr) as *mut AresData<*mut c_void> };
    // `free_chain` frees the boxed tail and inline head; a `Drop` frees only its own fields.
    unsafe {
        match (&*aresdata).data_type {
            AresDataType::MxReply => free_chain::<AresMxReply>(aresdata),
            AresDataType::CaaReply => free_chain::<AresCaaReply>(aresdata),
            AresDataType::TxtReply => free_chain::<AresTxtReply>(aresdata),
            AresDataType::TxtReplyExt => free_chain::<AresTxtReplyExt>(aresdata),
            AresDataType::NaptrReply => free_chain::<AresNaptrReply>(aresdata),
            AresDataType::SrvReply => free_chain::<AresSrvReply>(aresdata),
            AresDataType::UriReply => free_chain::<AresUriReply>(aresdata),
            AresDataType::AddrPortNode => free_chain::<AresAddrPortNode>(aresdata),
            AresDataType::AddrNode => free_chain::<super::ares_addr_node>(aresdata),
            // SOA is a single record (no `next` chain), so just free the one box.
            AresDataType::SoaReply => crate::mem::drop_box(aresdata as *mut AresData<AresSoaReply>),
        }
    }
}

/// Free a node chain: the boxed tail then the inline head; each `Drop` frees only
/// its own fields, never `next`, so no `Drop` walks into caller-owned memory.
pub(crate) unsafe fn free_chain<T: CLinkedList>(aresdata: *mut AresData<*mut c_void>) {
    let ad = aresdata as *mut AresData<T>;
    let mut node = unsafe { *(*ad).data.next() };
    while !node.is_null() {
        let next = unsafe { *(*node).next() };
        unsafe { crate::mem::drop_box(node) };
        node = next;
    }
    unsafe { crate::mem::drop_box(ad) };
}

#[repr(C)]
#[derive(Debug)]
pub enum AresDataType {
    MxReply,
    CaaReply,
    TxtReply,
    TxtReplyExt,
    NaptrReply,
    SoaReply,
    SrvReply,
    UriReply,
    AddrPortNode,
    AddrNode,
}

#[repr(C)]
pub struct AresData<T> {
    pub data_type: AresDataType,
    pub data: T,
}

#[repr(C)]
#[derive(Debug)]
pub struct AresMxReply {
    next: *mut AresMxReply,
    pub host: *mut c_char,
    pub priority: c_ushort,
}

#[repr(C)]
pub struct AresTxtReply {
    next: *mut AresTxtReply,
    pub txt: *mut u8,
    pub length: libc::size_t, // null termination excluded
}

#[repr(C)]
pub struct AresTxtReplyExt {
    next: *mut AresTxtReplyExt,
    pub txt: *mut u8,
    pub length: libc::size_t, // null termination excluded
    pub record_start: u8,
}

#[repr(C)]
pub struct AresCaaReply {
    next: *mut AresCaaReply,
    critical: c_int,
    property: *mut u8,
    plength: libc::size_t,
    value: *mut u8,
    length: libc::size_t,
}

impl IntoAresData<AresCaaReply> for CaaReply<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Result<AresCaaReply, c_int> {
        let plength = self.property.len();
        let length = self.value.len();

        // Build both CStrings before `into_raw` so a failure does not leak the first.
        let property = CString::new(self.property).map_err(|e| e.code())?;
        let value = CString::new(self.value).map_err(|e| e.code())?;

        Ok(AresCaaReply {
            next: std::ptr::null_mut(),
            critical: self.critical as c_int,
            property: property.into_raw() as *mut u8,
            plength,
            value: value.into_raw() as *mut u8,
            length,
        })
    }
}

impl Drop for AresCaaReply {
    fn drop(&mut self) {
        unsafe { crate::mem::free(self.property.cast()); crate::mem::free(self.value.cast()); }
    }
}

#[repr(C)]
pub struct AresSoaReply {
    nsname: *mut c_char,
    hostmaster: *mut c_char,
    serial: c_uint,
    refresh: c_uint,
    retry: c_uint,
    expire: c_uint,
    minttl: c_uint,
}

impl IntoAresData<AresSoaReply> for SoaReply<'_> {
    fn into_ares_data(self, main_buf: &[u8]) -> Result<AresSoaReply, c_int> {
        // Build both CStrings before `into_raw` so a failure does not leak the first.
        let nsname = self.nsname.try_cstring(main_buf)?;
        let hostmaster = self.hostmaster.try_cstring(main_buf)?;

        Ok(AresSoaReply {
            nsname: nsname.into_raw(),
            hostmaster: hostmaster.into_raw(),
            serial: self.serial as c_uint,
            refresh: self.refresh as c_uint,
            retry: self.retry as c_uint,
            expire: self.expire as c_uint,
            minttl: self.minttl as c_uint,
        })
    }
}

#[repr(C)]
pub union AresAddrUnion {
    pub addr4: libc::in_addr,
    pub addr6: crate::ffi::ares_in6_addr,
}

// Dual-role (caller input + our output), so intentionally no `Drop`.
#[repr(C)]
pub struct AresAddrPortNode {
    pub next: *mut AresAddrPortNode,
    pub family: c_int,
    pub addr: AresAddrUnion,
    pub udp_port: c_int,
    pub tcp_port: c_int,
}

impl Drop for AresMxReply {
    fn drop(&mut self) {
        unsafe { crate::mem::free(self.host.cast()) };
    }
}

impl Drop for AresTxtReply {
    fn drop(&mut self) {
        unsafe { crate::mem::free(self.txt.cast()) };
    }
}

impl Drop for AresTxtReplyExt {
    fn drop(&mut self) {
        unsafe { crate::mem::free(self.txt.cast()) };
    }
}

impl Drop for AresSrvReply {
    fn drop(&mut self) {
        unsafe { crate::mem::free(self.host.cast()) };
    }
}

impl CLinkedList for AresMxReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresCaaReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresTxtReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresTxtReplyExt {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresNaptrReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresSrvReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresUriReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresAddrPortNode {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

pub trait DataType {
    fn datatype() -> AresDataType;
}

impl DataType for AresMxReply {
    fn datatype() -> AresDataType { AresDataType::MxReply }
}

impl DataType for AresCaaReply {
    fn datatype() -> AresDataType { AresDataType::CaaReply }
}

impl DataType for AresTxtReply {
    fn datatype() -> AresDataType { AresDataType::TxtReply }
}

impl DataType for AresTxtReplyExt {
    fn datatype() -> AresDataType { AresDataType::TxtReplyExt }
}

impl DataType for AresNaptrReply {
    fn datatype() -> AresDataType { AresDataType::NaptrReply }
}

impl DataType for AresSoaReply {
    fn datatype() -> AresDataType { AresDataType::SoaReply }
}

impl DataType for AresSrvReply {
    fn datatype() -> AresDataType { AresDataType::SrvReply }
}

impl DataType for AresUriReply {
    fn datatype() -> AresDataType { AresDataType::UriReply }
}

impl DataType for AresAddrPortNode {
    fn datatype() -> AresDataType { AresDataType::AddrPortNode }
}

// `ares_addr_node` uses the same chain machinery and is also dual-role, so no `Drop`.
impl CLinkedList for super::ares_addr_node {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl DataType for super::ares_addr_node {
    fn datatype() -> AresDataType { AresDataType::AddrNode }
}

#[repr(C)]
pub struct AresNaptrReply {
    next: *mut AresNaptrReply,
    flags: *mut u8,
    service: *mut u8,
    regexp: *mut u8,
    replacement: *mut c_char,
    order: u16,
    preference: u16,
}

impl Drop for AresNaptrReply {
    fn drop(&mut self) {
        unsafe {
            crate::mem::free(self.flags.cast());
            crate::mem::free(self.service.cast());
            crate::mem::free(self.regexp.cast());
            crate::mem::free(self.replacement.cast());
        }
    }
}

impl Drop for AresSoaReply {
    fn drop(&mut self) {
        unsafe { crate::mem::free(self.nsname.cast()); crate::mem::free(self.hostmaster.cast()); }
    }
}

impl Drop for AresUriReply {
    fn drop(&mut self) {
        unsafe { crate::mem::free(self.uri.cast()) };
    }
}

impl IntoAresData<AresNaptrReply> for NaptrReply<'_> {
    fn into_ares_data(self, _buf: &[u8]) -> Result<AresNaptrReply, c_int> {
        // Build all CStrings before `into_raw` so a failure does not leak the earlier ones.
        let flags = CString::new(self.flags).map_err(|e| e.code())?;
        let service = CString::new(self.service).map_err(|e| e.code())?;
        let regexp = CString::new(self.regexp).map_err(|e| e.code())?;
        let replacement = CString::new(self.replacement).map_err(|e| e.code())?;

        Ok(AresNaptrReply {
            next: std::ptr::null_mut(),
            flags: flags.into_raw() as *mut u8,
            service: service.into_raw() as *mut u8,
            regexp: regexp.into_raw() as *mut u8,
            replacement: replacement.into_raw(),
            order: self.order,
            preference: self.preference,
        })
    }
}

#[repr(C)]
pub struct AresSrvReply {
    next: *mut AresSrvReply,
    host: *mut c_char,
    priority: c_ushort,
    weight: c_ushort,
    port: c_ushort,
}

impl IntoAresData<AresSrvReply> for SrvReply<'_> {
    fn into_ares_data(self, main_buf: &[u8]) -> Result<AresSrvReply, c_int> {
        Ok(AresSrvReply {
            next: std::ptr::null_mut(),
            host: self.host.try_cstring(main_buf)?.into_raw(),
            priority: self.priority as c_ushort,
            weight: self.weight as c_ushort,
            port: self.port as c_ushort,
        })
    }
}

#[repr(C)]
pub struct AresUriReply {
    next: *mut AresUriReply,
    priority: c_ushort,
    weight: c_ushort,
    uri: *mut c_char,
    ttl: c_int,
}

impl IntoAresData<AresUriReply> for UriReply<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Result<AresUriReply, c_int> {
        let uri = CString::new(self.uri).map_err(|e| e.code())?;

        Ok(AresUriReply {
            next: std::ptr::null_mut(),
            priority: self.priority as c_ushort,
            weight: self.weight as c_ushort,
            uri: uri.into_raw(),
            ttl: self.ttl as c_int
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Default for AresMxReply {
        fn default() -> Self {
            AresMxReply { next: std::ptr::null_mut(), host: CString::new("default").unwrap().into_raw(), priority: 1 }
        }
    }

    impl Default for AresTxtReply {
        fn default() -> Self {
            // Production path keeps txt at `length + 1` bytes to match the Drop size.
            TxtReply { txt: std::borrow::Cow::Borrowed("default"), length: 7 }
                .into_ares_data(&[])
                .unwrap()
        }
    }

    impl Default for AresSoaReply {
        fn default() -> Self {
            AresSoaReply {
                nsname: CString::new("").unwrap().into_raw(),
                hostmaster: CString::new("").unwrap().into_raw(),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minttl: 0,
            }
        }
    }

    impl Default for AresAddrPortNode {
        fn default() -> Self {
            let addr = AresAddrUnion { addr4: libc::in_addr { s_addr: 0 } };
            AresAddrPortNode { next: std::ptr::null_mut(), family: libc::AF_INET, addr, udp_port: 0, tcp_port: 0 }
        }
    }

    #[test]
    fn test_restore_original_ptr() {
        test_restore_original_ptr_impl::<AresMxReply>();
        test_restore_original_ptr_impl::<AresTxtReply>();
        test_restore_original_ptr_impl::<AresSoaReply>();
        test_restore_original_ptr_impl::<AresAddrPortNode>();
    }

    fn test_restore_original_ptr_impl<T>() where T: Default + DataType {
        let data = T::default();
        let base: AresData<T> = AresData { data_type: T::datatype(), data };
        let dataptr = std::ptr::addr_of!(base.data) as *mut c_void;
        let restoredptr = unsafe { restore_original_ptr(dataptr) };
        assert_eq!(std::ptr::addr_of!(base) as *mut c_void, restoredptr);
    }

    // `txt` is NUL-terminated with `length` excluding it, so C consumers do not
    // read past the allocation.
    #[test]
    fn txt_reply_is_nul_terminated() {
        let data = TxtReply { txt: std::borrow::Cow::Borrowed("abc"), length: 3 }
            .into_ares_data(&[]).unwrap();
        assert_eq!(data.length, 3, "length excludes the NUL terminator");
        unsafe {
            assert_eq!(std::slice::from_raw_parts(data.txt as *const u8, data.length), b"abc");
            assert_eq!(*data.txt.add(data.length), 0, "txt[length] must be the NUL terminator");
        }
        drop(data); // frees length+1 bytes; must be sound
    }

    #[test]
    fn txt_reply_ext_is_nul_terminated() {
        let data = TxtReplyExt { txt: "hi", length: 2, record_start: true }
            .into_ares_data(&[]).unwrap();
        assert_eq!(data.length, 2);
        unsafe {
            assert_eq!(std::slice::from_raw_parts(data.txt as *const u8, data.length), b"hi");
            assert_eq!(*data.txt.add(data.length), 0);
        }
        drop(data);
    }

    #[test]
    fn empty_txt_is_nul_terminated() {
        // length 0 -> a 1-byte allocation holding just the terminator.
        let data = TxtReply { txt: std::borrow::Cow::Borrowed(""), length: 0 }
            .into_ares_data(&[]).unwrap();
        assert_eq!(data.length, 0);
        unsafe { assert_eq!(*data.txt.add(0), 0); }
        drop(data);
    }
}
