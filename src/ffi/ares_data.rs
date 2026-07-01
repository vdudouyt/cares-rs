// Thin c-ares C ABI shims: the safety contract is the documented c-ares API
// contract, so per-function `# Safety` docs would just be noise.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{ CString, c_void, c_char, c_ushort, c_int, c_uint };
use crate::core::packets::{ TxtReply, TxtReplyExt, MxReply, CaaReply, NaptrReply, SoaReply, SrvReply, UriReply };
use crate::ffi::clinkedlist::*;
use crate::offset_of;

// Ownership taxonomy for the `AresData`-managed types below.
//
// Freeing is uniform: `ares_free_data` frees every chain explicitly via `free_chain`
// (walk the boxed tail, then drop the inline-head box). NO type auto-walks its `next`
// chain in `Drop`; a `Drop` frees only that node's own heap fields. So a chain is freed
// exactly once, only when `ares_free_data` is called.
//
// * Reply types (`AresMxReply`, `AresTxtReply`, `AresSoaReply`, … — the results of
//   `ares_parse_*_reply`) are allocated ONLY by cares-rs; a consumer never constructs
//   one. They keep a `Drop` — but only to free their own heap fields (`CString`/`Vec`),
//   not the chain.
//
// * Node types (`ares_addr_node`, `AresAddrPortNode`) are DUAL-ROLE: the caller
//   constructs them (often on the stack) as INPUT to `ares_set_servers[_ports]`, and
//   cares-rs also allocates them as the OUTPUT of `ares_get_servers[_ports]`. Because a
//   Rust `Drop` fires for *every* value of a type, these must have NO `Drop` at all — one
//   would also free the caller's own stack instances (the `munmap_chunk` benchmark abort
//   that this arrangement fixes). They own no heap fields, so they need none; only the
//   cares-rs-allocated (`get_servers`) instances are freed, via `ares_free_data`.

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
        Some(AresTxtReply { next: std::ptr::null_mut(), txt: txt as *mut u8, length })
    }
}

impl IntoAresData<AresTxtReplyExt> for TxtReplyExt<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Option<AresTxtReplyExt> {
        let mut bytes = self.txt.as_bytes().to_vec();
        let length = bytes.len();
        bytes.push(0); // NUL terminator (not counted in `length`), matching upstream
        let txt = Box::into_raw(bytes.into_boxed_slice());
        Some(AresTxtReplyExt { next: std::ptr::null_mut(), txt: txt as *mut u8, length, record_start: self.record_start as u8 })
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
    // Every chained type is freed the same way: `free_chain` frees the boxed tail and
    // the inline head, and each node's `Drop` (if any) frees only its own fields. A
    // chain's `next` is therefore freed only here — never auto-freed by a type's `Drop`.
    match (*aresdata).data_type {
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
        AresDataType::SoaReply => drop(Box::from_raw(aresdata as *mut AresData<AresSoaReply>)),
    }
}

/// Free an `AresData`-wrapped node chain. The `chain_nodes`-boxed tail nodes are freed
/// here, then the box frees the inline head. Each node's `Drop` (if any) frees only its
/// own fields — never the `next` chain — so a chain is freed exactly once, only from
/// here, and no `Drop` can walk into caller-owned memory.
unsafe fn free_chain<T: CLinkedList>(aresdata: *mut AresData<*mut c_void>) {
    let ad = aresdata as *mut AresData<T>;
    let mut node = *(*ad).data.next();
    while !node.is_null() {
        let next = *(*node).next();
        drop(Box::from_raw(node));
        node = next;
    }
    drop(Box::from_raw(ad));
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
            property: property.into_raw() as *mut u8,
            plength,
            value: value.into_raw() as *mut u8,
            length,
        })
    }
}

impl Drop for AresCaaReply {
    fn drop(&mut self) {
        // Own fields only; the `next` chain is freed by ares_free_data's free_chain.
        drop(unsafe { CString::from_raw(self.property as *mut c_char) });
        drop(unsafe { CString::from_raw(self.value as *mut c_char) });
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
    pub addr6: crate::ffi::ares_in6_addr,
}

// Dual-role node type (caller-allocatable input + cares-rs-allocated output) — see the
// ownership taxonomy at the top of this file: intentionally NO `Drop`.
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
    }
}

impl Drop for AresTxtReply {
    fn drop(&mut self) {
        // txt was allocated with length+1 bytes (data + NUL terminator).
        drop(unsafe { Vec::from_raw_parts(self.txt as *mut i8, self.length + 1, self.length + 1) });
    }
}

impl Drop for AresTxtReplyExt {
    fn drop(&mut self) {
        // txt was allocated with length+1 bytes (data + NUL terminator).
        drop(unsafe { Vec::from_raw_parts(self.txt as *mut i8, self.length + 1, self.length + 1) });
    }
}

impl Drop for AresSrvReply {
    fn drop(&mut self) {
        drop(unsafe { CString::from_raw(self.host as *mut c_char) });
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

// NB: no `Drop` for AresAddrPortNode — it is a caller-constructable input to
// ares_set_servers_ports (callers build chains on the stack) and owns no heap fields.
// ares_free_data frees our own boxed chains explicitly via free_chain instead.

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

// `ares_addr_node` (returned by `ares_get_servers`, freed with `ares_free_data`)
// uses the same AresData-chain machinery as AresAddrPortNode. Like it, it has NO
// `Drop` — it is a caller-constructable input to ares_set_servers.
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
        drop(unsafe { CString::from_raw(self.flags as *mut c_char) });
        drop(unsafe { CString::from_raw(self.service as *mut c_char) });
        drop(unsafe { CString::from_raw(self.regexp as *mut c_char) });
        drop(unsafe { CString::from_raw(self.replacement as *mut c_char) });
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
    priority: c_ushort,
    weight: c_ushort,
    uri: *mut c_char,
    ttl: c_int,
}

impl IntoAresData<AresUriReply> for UriReply<'_> {
    fn into_ares_data(self, _main_buf: &[u8]) -> Option<AresUriReply> {
        let uri = CString::new(self.uri).ok()?;

        Some(AresUriReply {
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
