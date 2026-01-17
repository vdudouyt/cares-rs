use std::ffi::{ CString, c_void, c_char, c_ushort, c_int, c_uint, c_short };
use crate::core::packets::{ TxtReply, MxReply, CaaReply, NaptrReply, SoaReply, SrvReply, UriReply };
use crate::ffi::clinkedlist::*;
use crate::offset_of;

pub trait IntoAresData<T> {
    fn into_ares_data(self, main_buf: &[u8]) -> T;
}

impl IntoAresData<AresTxtReply> for TxtReply {
    fn into_ares_data(self, _main_buf: &[u8]) -> AresTxtReply {
        let bytes = self.txt.into_bytes();
        let length = bytes.len();
        let txt = Box::into_raw(bytes.into_boxed_slice());
        AresTxtReply { next: std::ptr::null_mut(), txt: txt as *const i8, length }
    }
}

impl IntoAresData<AresMxReply> for MxReply {
    fn into_ares_data(self, main_buf: &[u8]) -> AresMxReply {
        let name = self.label.build_cstring(main_buf).unwrap();
        let raw_ptr = name.into_raw();
        AresMxReply { next: std::ptr::null_mut(), host: raw_ptr, priority: self.priority }
    }
}

unsafe fn restore_original_ptr(dataptr: *mut c_void) -> *mut c_void {
    dataptr.byte_sub(offset_of!(AresData<*mut c_void>, data))
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_data(dataptr: *mut c_void) {
    let aresdata = restore_original_ptr(dataptr) as *mut AresData<*mut c_void>;
    match (*aresdata).data_type {
        AresDataType::MxReply => drop(Box::from_raw(aresdata as *mut AresData<AresMxReply>)),
        AresDataType::CaaReply => drop(Box::from_raw(aresdata as *mut AresData<AresCaaReply>)),
        AresDataType::TxtReply => drop(Box::from_raw(aresdata as *mut AresData<AresTxtReply>)),
        AresDataType::NaptrReply => drop(Box::from_raw(aresdata as *mut AresData<AresNaptrReply>)),
        AresDataType::SoaReply => drop(Box::from_raw(aresdata as *mut AresData<AresSoaReply>)),
        AresDataType::SrvReply => drop(Box::from_raw(aresdata as *mut AresData<AresSrvReply>)),
        AresDataType::UriReply => drop(Box::from_raw(aresdata as *mut AresData<AresUriReply>)),
        AresDataType::AddrPortNode => drop(Box::from_raw(aresdata as *mut AresData<AresAddrPortNode>)),
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum AresDataType {
    MxReply,
    CaaReply,
    TxtReply,
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
pub struct AresCaaReply {
    next: *mut AresCaaReply,
    critical: c_int,
    property: *const c_char,
    plength: usize,
    value: *const c_char,
    length: usize,
}

impl IntoAresData<AresCaaReply> for CaaReply {
    fn into_ares_data(self, _main_buf: &[u8]) -> AresCaaReply {
        // NOTE: plength/length in your Rust CaaReply are the byte lengths excluding NUL.
        // For FFI, we store them as usize.
        let plength = self.property.len();
        let length = self.value.len();

        let property = CString::new(self.property).unwrap().into_raw();
        let value = CString::new(self.value).unwrap().into_raw();

        AresCaaReply {
            next: std::ptr::null_mut(),
            critical: self.critical as c_int,
            property,
            plength,
            value,
            length,
        }
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

impl IntoAresData<AresSoaReply> for SoaReply {
    fn into_ares_data(self, main_buf: &[u8]) -> AresSoaReply {
        let nsname = self.nsname.build_cstring(main_buf).unwrap().into_raw();
        let hostmaster = self.hostmaster.build_cstring(main_buf).unwrap().into_raw();

        AresSoaReply {
            nsname,
            hostmaster,
            serial: self.serial as c_uint,
            refresh: self.refresh as c_uint,
            retry: self.retry as c_uint,
            expire: self.expire as c_uint,
            minttl: self.minttl as c_uint,
        }
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
        drop(unsafe { Vec::from_raw_parts(self.txt as *mut i8, self.length, self.length) });
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
    }
}

impl IntoAresData<AresNaptrReply> for NaptrReply {
    fn into_ares_data(self, buf: &[u8]) -> AresNaptrReply {
        let flags = CString::new(self.flags).unwrap().into_raw();
        let service = CString::new(self.service).unwrap().into_raw();
        let regexp = CString::new(self.regexp).unwrap().into_raw();
        let replacement = CString::new(self.replacement).unwrap().into_raw();

        AresNaptrReply {
            next: std::ptr::null_mut(),
            flags,
            service,
            regexp,
            replacement,
            order: self.order,
            preference: self.preference,
        }
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

impl IntoAresData<AresSrvReply> for SrvReply {
    fn into_ares_data(self, main_buf: &[u8]) -> AresSrvReply {
        AresSrvReply {
            next: std::ptr::null_mut(),
            host: self.host.build_cstring(main_buf).unwrap().into_raw(),
            priority: self.priority as c_ushort,
            weight: self.weight as c_ushort,
            port: self.port as c_ushort,
        }
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

impl IntoAresData<AresUriReply> for UriReply {
    fn into_ares_data(self, _main_buf: &[u8]) -> AresUriReply {
        let uri = CString::new(self.uri).unwrap().into_raw();

        AresUriReply {
            next: std::ptr::null_mut(),
            priority: self.priority as c_short,
            weight: self.weight as c_short,
            uri,
            ttl: self.ttl as c_int
        }
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
            AresTxtReply { next: std::ptr::null_mut(), txt: CString::new("default").unwrap().into_raw(), length: 0}
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
}


