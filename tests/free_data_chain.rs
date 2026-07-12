//! Regression test (cares-rs-specific): freeing a multi-node `ares_addr_port_node`
//! chain returned by `ares_get_servers_ports` must free the WHOLE chain, not just
//! the head. The tail nodes are heap-boxed by `chain_nodes`, so a missing `next`
//! walk in `AresAddrPortNode`'s `Drop` leaked them (40 bytes per tail node).
//!
//! This path isn't covered by the ported upstream suite — upstream c-ares never
//! calls `ares_get_servers_ports` in its tests. Leak detection requires Valgrind:
//!   valgrind --leak-check=full --error-exitcode=1 <test-bin> get_servers_ports_chain_frees_fully

use std::ffi::{c_int, c_void, CString};
use std::ptr;

use cares_rs::*;

const ARES_SUCCESS: c_int = 0;

// `ares_free_data` lives in a private submodule and isn't re-exported at the
// crate root, but it's a `#[no_mangle]` symbol in the linked rlib.
extern "C" {
    fn ares_free_data(dataptr: *mut c_void);
}

#[test]
fn get_servers_ports_chain_frees_fully() {
    unsafe {
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut channel), ARES_SUCCESS);

        // Multiple servers -> a head node plus heap-boxed tail nodes.
        let csv = CString::new("1.2.3.4,2.3.4.5,3.4.5.6").unwrap();
        assert_eq!(ares_set_servers_csv(channel, csv.as_ptr()), ARES_SUCCESS);

        let mut servers: *mut c_void = ptr::null_mut();
        // `as *mut _` infers the `*mut *mut AresAddrPortNode` out-param type.
        let rc = ares_get_servers_ports(channel, &mut servers as *mut *mut c_void as *mut _);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!servers.is_null());

        // Frees head + entire chain via AresAddrPortNode::Drop; Valgrind-clean.
        ares_free_data(servers);

        ares_destroy(channel);
    }
}
