use std::ffi::{c_int, c_void, CString};
use std::ptr;

use cares_rs::*;

const ARES_SUCCESS: c_int = 0;

fn ares_getsock_readable(bitmask: c_int, idx: usize) -> bool {
    (bitmask & (1 << idx)) != 0
}

fn ares_getsock_writable(bitmask: c_int, idx: usize) -> bool {
    (bitmask & (1 << (idx + 16))) != 0
}

struct CallbackResult {
    done: bool,
    status: c_int,
}

unsafe extern "C" fn host_callback(arg: *mut c_void, status: c_int, _timeouts: c_int, _hostent: *mut libc::hostent) {
    let result = &mut *(arg as *mut CallbackResult);
    result.done = true;
    result.status = status;
}

#[test]
fn bad_socket_noop() {
    unsafe {
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut channel), ARES_SUCCESS);
        assert!(!channel.is_null());

        // Calling with ARES_SOCKET_BAD for both fds should be a no-op
        ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

        ares_destroy(channel);
    }
}

#[test]
fn resolves_localhost() {
    unsafe {
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut channel), ARES_SUCCESS);

        let mut result = CallbackResult { done: false, status: -1 };
        let name = CString::new("localhost").unwrap();
        ares_gethostbyname(
            channel,
            name.as_ptr(),
            libc::AF_INET,
            Some(host_callback),
            &mut result as *mut _ as *mut c_void,
        );

        // Drive the event loop using ares_getsock + select + ares_process_fd
        let mut iterations = 0;
        while !result.done && iterations < 100 {
            iterations += 1;

            let mut socks = [ARES_SOCKET_BAD; ARES_GETSOCK_MAXNUM];
            let bitmask = ares_getsock(channel, socks.as_mut_ptr(), ARES_GETSOCK_MAXNUM as c_int);

            if bitmask == 0 {
                // No sockets — might have resolved from /etc/hosts already
                ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
                continue;
            }

            // Build fd_sets for select
            let mut read_fds: libc::fd_set = std::mem::zeroed();
            let mut write_fds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut read_fds);
            libc::FD_ZERO(&mut write_fds);
            let mut max_fd: c_int = -1;

            for i in 0..ARES_GETSOCK_MAXNUM {
                if socks[i] == ARES_SOCKET_BAD {
                    continue;
                }
                if ares_getsock_readable(bitmask, i) {
                    libc::FD_SET(socks[i], &mut read_fds);
                    if socks[i] > max_fd { max_fd = socks[i]; }
                }
                if ares_getsock_writable(bitmask, i) {
                    libc::FD_SET(socks[i], &mut write_fds);
                    if socks[i] > max_fd { max_fd = socks[i]; }
                }
            }

            if max_fd == -1 {
                ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
                continue;
            }

            let mut tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
            let n = libc::select(max_fd + 1, &mut read_fds, &mut write_fds, ptr::null_mut(), &mut tv);
            if n < 0 { break; }

            // Call ares_process_fd for each ready socket
            for i in 0..ARES_GETSOCK_MAXNUM {
                if socks[i] == ARES_SOCKET_BAD {
                    continue;
                }
                let r = if libc::FD_ISSET(socks[i], &mut read_fds) { socks[i] } else { ARES_SOCKET_BAD };
                let w = if libc::FD_ISSET(socks[i], &mut write_fds) { socks[i] } else { ARES_SOCKET_BAD };
                if r != ARES_SOCKET_BAD || w != ARES_SOCKET_BAD {
                    ares_process_fd(channel, r, w);
                }
            }
        }

        assert!(result.done, "callback should have fired");
        assert_eq!(result.status, ARES_SUCCESS, "localhost should resolve successfully");

        ares_destroy(channel);
    }
}

#[test]
fn getsock_reports_writable_for_pending_query() {
    unsafe {
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut channel), ARES_SUCCESS);

        // Before any query, no sockets should be active
        let mut socks = [ARES_SOCKET_BAD; ARES_GETSOCK_MAXNUM];
        let bitmask = ares_getsock(channel, socks.as_mut_ptr(), ARES_GETSOCK_MAXNUM as c_int);
        assert_eq!(bitmask, 0, "no sockets before query");

        // Issue a query to an external domain (won't resolve from /etc/hosts)
        let mut result = CallbackResult { done: false, status: -1 };
        let name = CString::new("www.example.com.").unwrap();
        ares_gethostbyname(
            channel,
            name.as_ptr(),
            libc::AF_INET,
            Some(host_callback),
            &mut result as *mut _ as *mut c_void,
        );

        // Now getsock should report a socket with the writable bit set
        let mut socks = [ARES_SOCKET_BAD; ARES_GETSOCK_MAXNUM];
        let bitmask = ares_getsock(channel, socks.as_mut_ptr(), ARES_GETSOCK_MAXNUM as c_int);
        assert_ne!(bitmask, 0, "should have active sockets after query");
        assert_ne!(socks[0], ARES_SOCKET_BAD, "first socket should be valid");
        assert!(ares_getsock_writable(bitmask, 0), "pending query socket should be writable");

        ares_cancel(channel);
        ares_destroy(channel);
    }
}

#[test]
fn null_channel_noop() {
    unsafe {
        // Should not crash with null channel
        ares_process_fd(ptr::null_mut(), ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        ares_process_fd(ptr::null_mut(), 0, 0);
    }
}
