//! `ares_fds.3`: "File descriptors already set in read_fds and write_fds will
//! remain set; initialization of the file descriptor sets (using FD_ZERO) is
//! the responsibility of the caller."

use std::ffi::c_int;
use std::ptr;

use cares::*;

const ARES_SUCCESS: c_int = 0;

#[test]
fn ares_fds_preserves_caller_fd_sets() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
        assert!(!ch.is_null());

        let mut read_fds: libc::fd_set = std::mem::zeroed();
        let mut write_fds: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut read_fds);
        libc::FD_ZERO(&mut write_fds);
        libc::FD_SET(0, &mut read_fds);
        libc::FD_SET(1, &mut write_fds);

        // No active queries: ares_fds has no descriptors of its own to add.
        let _ = ares_fds(ch, &mut read_fds, &mut write_fds);

        assert!(
            libc::FD_ISSET(0, &read_fds),
            "ares_fds must not clear descriptors pre-set by the caller in read_fds"
        );
        assert!(
            libc::FD_ISSET(1, &write_fds),
            "ares_fds must not clear descriptors pre-set by the caller in write_fds"
        );

        ares_destroy(ch);
    }
}
