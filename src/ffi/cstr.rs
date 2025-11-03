#[macro_export]
macro_rules! cstr {
    ($s:literal) => {{
        const OUT: &'static std::ffi::CStr = match std::ffi::CStr::from_bytes_with_nul(concat!($s, "\0").as_bytes()) {
            Ok(s) => s,
            Err(_) => unreachable!(),
        };
        OUT.as_ptr()
    }};
}
