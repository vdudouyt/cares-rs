use std::ffi::{ CString, c_void, c_char, c_ushort, c_int };
use crate::core::packets::{ TxtReply, MxReply };
use crate::ffi::clinkedlist::*;
use crate::offset_of;

pub trait IntoAresData<T> {
    fn into_ares_data(self, main_buf: &[u8]) -> T;
}

impl IntoAresData<AresTxtReply> for TxtReply {
    fn into_ares_data(self, _main_buf: &[u8]) -> AresTxtReply {
        let length = self.txt.len();
        let txt = CString::new(self.txt).unwrap().into_raw();
        AresTxtReply { next: std::ptr::null_mut(), txt, length }
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
        AresDataType::TxtReply => drop(Box::from_raw(aresdata as *mut AresData<AresTxtReply>)),
        AresDataType::AddrPortNode => drop(Box::from_raw(aresdata as *mut AresData<AresAddrPortNode>)),
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum AresDataType {
    MxReply,
    TxtReply,
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
        drop(unsafe { CString::from_raw(self.txt as *mut c_char) });
        if !self.next.is_null() {
            drop(unsafe { Box::from_raw(self.next) })
        }
    }
}

impl CLinkedList for AresMxReply {
    fn next(&mut self) -> &mut *mut Self { &mut self.next }
}

impl CLinkedList for AresTxtReply {
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

impl DataType for AresTxtReply {
    fn datatype() -> AresDataType { AresDataType::TxtReply }
}

impl DataType for AresAddrPortNode {
    fn datatype() -> AresDataType { AresDataType::AddrPortNode }
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

    #[test]
    fn test_restore_original_ptr() {
        test_restore_original_ptr_impl::<AresMxReply>();
        test_restore_original_ptr_impl::<AresTxtReply>();
    }

    fn test_restore_original_ptr_impl<T>() where T: Default + DataType {
        let data = T::default();
        let base: AresData<T> = AresData { data_type: T::datatype(), data };
        let dataptr = std::ptr::addr_of!(base.data) as *mut c_void;
        let restoredptr = unsafe { restore_original_ptr(dataptr) };
        assert_eq!(std::ptr::addr_of!(base) as *mut c_void, restoredptr);
    }
}


