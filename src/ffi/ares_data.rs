use std::ffi::{ CString, c_void, c_char, c_ushort, c_int, c_uint, c_short };
use crate::core::packets::{ TxtReply, TxtReplyExt, MxReply, CaaReply, NaptrReply, SoaReply, SrvReply, UriReply };
use crate::ffi::clinkedlist::*;
use crate::offset_of;

pub trait IntoAresData<T> {
    /// Convert a parsed record into its C reply struct. Returns `None` when a
    /// field cannot be represented as a C string (e.g. it contains an embedded
    /// NUL byte from a malformed response); callers map `None` to ARES_EBADRESP
    /// rather than panicking across the FFI boundary.
    fn into_ares_data(self, main_buf: &[u8]) -> Option<T>;
}

impl IntoAresData<AresTxtReply> for TxtReply<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Option<AresTxtReply> {
        let mut bytes = self.txt.into_owned().into_bytes();
        let length = bytes.len();
        bytes.push(0); // NUL terminator (not counted in `length`), matching upstream
        let txt = Box::into_raw(bytes.into_boxed_slice());
        Some(AresTxtReply { next: std::ptr::null_mut(), txt: txt as *const i8, length })
    }
}

impl IntoAresData<AresTxtReplyExt> for TxtReplyExt<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Option<AresTxtReplyExt> {
        let mut bytes = self.txt.as_bytes().to_vec();
        let length = bytes.len();
        bytes.push(0); // NUL terminator (not counted in `length`), matching upstream
        let txt = Box::into_raw(bytes.into_boxed_slice());
        Some(AresTxtReplyExt { next: std::ptr::null_mut(), txt: txt as *const i8, length, record_start: self.record_start as c_char })
    }
}

impl IntoAresData<AresMxReply> for MxReply<'_> {
    fn into_ares_data(self, main_buf: &[u8]) -> Option<AresMxReply> {
        let name = self.label.build_cstring(main_buf)?;
        let raw_ptr = name.into_raw();
        Some(AresMxReply { next: std::ptr::null_mut(), host: raw_ptr, priority: self.priority })
    }
}

unsafe fn restore_original_ptr(dataptr: *mut c_void) -> *mut c_void {
    dataptr.byte_sub(offset_of!(AresData<*mut c_void>, data))
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_data(dataptr: *mut c_void) {
    if dataptr.is_null() { return; }
    let aresdata = restore_original_ptr(dataptr) as *mut AresData<*mut c_void>;
    match (*aresdata).data_type {
        // Each type's Drop impl frees the node and walks its `next` chain.
        AresDataType::MxReply => drop(Box::from_raw(aresdata as *mut AresData<AresMxReply>)),
        AresDataType::CaaReply => drop(Box::from_raw(aresdata as *mut AresData<AresCaaReply>)),
        AresDataType::TxtReply => drop(Box::from_raw(aresdata as *mut AresData<AresTxtReply>)),
        AresDataType::TxtReplyExt => drop(Box::from_raw(aresdata as *mut AresData<AresTxtReplyExt>)),
        AresDataType::NaptrReply => drop(Box::from_raw(aresdata as *mut AresData<AresNaptrReply>)),
        AresDataType::SoaReply => drop(Box::from_raw(aresdata as *mut AresData<AresSoaReply>)),
        AresDataType::SrvReply => drop(Box::from_raw(aresdata as *mut AresData<AresSrvReply>)),
        AresDataType::AddrPortNode => drop(Box::from_raw(aresdata as *mut AresData<AresAddrPortNode>)),
        AresDataType::UriReply => drop(Box::from_raw(aresdata as *mut AresData<AresUriReply>)),
    }
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
    AddrPortNode
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
    pub host: *const c_char,
    pub priority: c_ushort,
}

#[repr(C)]
pub struct AresTxtReply {
    next: *mut AresTxtReply,
    pub txt: *const c_char,
    pub length: usize, // null termination excluded
}

#[repr(C)]
pub struct AresTxtReplyExt {
    next: *mut AresTxtReplyExt,
    pub txt: *const c_char,
    pub length: usize, // null termination excluded
    pub record_start: c_char,
}

#[repr(C)]
pub struct AresCaaReply {
    next: *mut AresCaaReply,
    critical: c_int,
    property: *const c_char,
    plength: usize,
    value: *const c_char,
    length: usize,
}

impl IntoAresData<AresCaaReply> for CaaReply<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Option<AresCaaReply> {
        let plength = self.property.len();
        let length = self.value.len();

        // Build both CStrings before calling into_raw, so a failure on the
        // second does not leak the first.
        let property = CString::new(self.property).ok()?;
        let value = CString::new(self.value).ok()?;

        Some(AresCaaReply {
            next: std::ptr::null_mut(),
            critical: self.critical as c_int,
            property: property.into_raw(),
            plength,
            value: value.into_raw(),
            length,
        })
    }
}

impl Drop for AresCaaReply {
    fn drop(&mut self) {
        drop(unsafe { CString::from_raw(self.property as *mut c_char) });
        drop(unsafe { CString::from_raw(self.value as *mut c_char) });

        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) });
        }
    }
}

#[repr(C)]
pub struct AresSoaReply {
    nsname: *const c_char,
    hostmaster: *const c_char,
    serial: c_uint,
    refresh: c_uint,
    retry: c_uint,
    expire: c_uint,
    minttl: c_uint,
}

impl IntoAresData<AresSoaReply> for SoaReply<'_> {
    fn into_ares_data(self, main_buf: &[u8]) -> Option<AresSoaReply> {
        // Build both CStrings before into_raw so a failure on the second
        // does not leak the first.
        let nsname = self.nsname.build_cstring(main_buf)?;
        let hostmaster = self.hostmaster.build_cstring(main_buf)?;

        Some(AresSoaReply {
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

// ares_addr_port_node

#[repr(C)]
pub union AresAddrUnion {
    pub addr4: libc::in_addr,
    pub addr6: libc::in6_addr,
}

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
        drop(unsafe { CString::from_raw(self.host as *mut c_char) });
        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) })
        }
    }
}

impl Drop for AresTxtReply {
    fn drop(&mut self) {
        // txt was allocated with length+1 bytes (data + NUL terminator).
        drop(unsafe { Vec::from_raw_parts(self.txt as *mut i8, self.length + 1, self.length + 1) });
        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) })
        }
    }
}

impl Drop for AresTxtReplyExt {
    fn drop(&mut self) {
        // txt was allocated with length+1 bytes (data + NUL terminator).
        drop(unsafe { Vec::from_raw_parts(self.txt as *mut i8, self.length + 1, self.length + 1) });
        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) })
        }
    }
}

impl Drop for AresSrvReply {
    fn drop(&mut self) {
        drop(unsafe { CString::from_raw(self.host as *mut c_char) });
        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) })
        }
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

#[repr(C)]
pub struct AresNaptrReply {
    next: *mut AresNaptrReply,
    flags: *const c_char,
    service: *const c_char,
    regexp: *const c_char,
    replacement: *const c_char,
    order: u16,
    preference: u16,
}

impl Drop for AresNaptrReply {
    fn drop(&mut self) {
        drop(unsafe { CString::from_raw(self.flags as *mut c_char) });
        drop(unsafe { CString::from_raw(self.service as *mut c_char) });
        drop(unsafe { CString::from_raw(self.regexp as *mut c_char) });
        drop(unsafe { CString::from_raw(self.replacement as *mut c_char) });

        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) });
        }
    }
}

impl Drop for AresSoaReply {
    fn drop(&mut self) {
        drop(unsafe { CString::from_raw(self.nsname as *mut c_char) });
        drop(unsafe { CString::from_raw(self.hostmaster as *mut c_char) });
    }
}

impl Drop for AresUriReply {
    fn drop(&mut self) {
        drop(unsafe { CString::from_raw(self.uri as *mut c_char) });
        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) })
        }
    }
}

impl IntoAresData<AresNaptrReply> for NaptrReply<'_> {
    fn into_ares_data(self, _buf: &[u8]) -> Option<AresNaptrReply> {
        // Build all CStrings before into_raw so a later failure does not leak
        // the earlier ones.
        let flags = CString::new(self.flags).ok()?;
        let service = CString::new(self.service).ok()?;
        let regexp = CString::new(self.regexp).ok()?;
        let replacement = CString::new(self.replacement).ok()?;

        Some(AresNaptrReply {
            next: std::ptr::null_mut(),
            flags: flags.into_raw(),
            service: service.into_raw(),
            regexp: regexp.into_raw(),
            replacement: replacement.into_raw(),
            order: self.order,
            preference: self.preference,
        })
    }
}

#[repr(C)]
pub struct AresSrvReply {
    next: *mut AresSrvReply,
    host: *const c_char,
    priority: c_ushort,
    weight: c_ushort,
    port: c_ushort,
}

impl IntoAresData<AresSrvReply> for SrvReply<'_> {
    fn into_ares_data(self, main_buf: &[u8]) -> Option<AresSrvReply> {
        Some(AresSrvReply {
            next: std::ptr::null_mut(),
            host: self.host.build_cstring(main_buf)?.into_raw(),
            priority: self.priority as c_ushort,
            weight: self.weight as c_ushort,
            port: self.port as c_ushort,
        })
    }
}

#[repr(C)]
pub struct AresUriReply {
    next: *mut AresUriReply,
    priority: c_short,
    weight: c_short,
    uri: *const c_char,
    ttl: c_int,
}

impl IntoAresData<AresUriReply> for UriReply<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Option<AresUriReply> {
        let uri = CString::new(self.uri).ok()?;

        Some(AresUriReply {
            next: std::ptr::null_mut(),
            priority: self.priority as c_short,
            weight: self.weight as c_short,
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
            // Build through the production path so txt is length+1 bytes (data +
            // NUL terminator) and the Drop impl frees the matching size.
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

    // The `txt` buffer must be NUL-terminated (data + a trailing 0) like upstream
    // c-ares, with `length` excluding the terminator, so a C consumer's
    // strlen/printf does not read past the allocation.
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
