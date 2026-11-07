//! Freeing a multi-node `ares_addr_port_node` chain from
//! `ares_get_servers_ports` must free every node (tail leak caught by Valgrind).

use std::ffi::{c_int, c_void, CString};
use std::ptr;

use cares_rs::*;

const ARES_SUCCESS: c_int = 0;

// Not re-exported at the crate root, but a `#[no_mangle]` symbol in the linked rlib.
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

        ares_free_data(servers);

        ares_destroy(channel);
    }
}
