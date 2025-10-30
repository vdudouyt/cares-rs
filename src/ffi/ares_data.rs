use std::ffi::CString;
use crate::core::packets::{ TxtReply, MxReply };
use crate::ffi::{ AresTxtReply, AresMxReply };

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
