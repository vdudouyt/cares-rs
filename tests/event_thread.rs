use std::ffi::{c_int, c_void, CString};
use std::ptr;

use cares_rs::*;

const ARES_SUCCESS: c_int = 0;
const ARES_OPT_EVENT_THREAD: c_int = 1 << 22;

struct CallbackResult {
    done: bool,
    status: c_int,
}

unsafe extern "C" fn host_callback(arg: *mut c_void, status: c_int, _timeouts: c_int, _hostent: *mut libc::hostent) {
    let result = &mut *(arg as *mut CallbackResult);
    result.done = true;
    result.status = status;
}

fn init_with_event_thread() -> Channel {
    unsafe {
        let mut channel: Channel = ptr::null_mut();
        let mut opts: ares_options::ares_options = std::mem::zeroed();
        opts.evsys = 0;
        let rc = ares_options::ares_init_options(&mut channel, &opts, ARES_OPT_EVENT_THREAD);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!channel.is_null());
        channel
    }
}

#[test]
fn event_thread_resolves_localhost() {
    unsafe {
        let channel = init_with_event_thread();

        let mut result = CallbackResult { done: false, status: -1 };
        let name = CString::new("localhost").unwrap();
        ares_gethostbyname(
            channel,
            name.as_ptr(),
            libc::AF_INET,
            host_callback,
            &mut result as *mut _ as *mut c_void,
        );

        // Wait for callback — event thread drives the event loop
        for _ in 0..200 {
            if result.done { break; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(result.done, "callback should have fired via event thread");
        assert_eq!(result.status, ARES_SUCCESS, "localhost should resolve");

        ares_destroy(channel);
    }
}

#[test]
fn event_thread_destroy_with_pending() {
    unsafe {
        let channel = init_with_event_thread();

        let mut result = CallbackResult { done: false, status: -1 };
        let name = CString::new("www.example.com.").unwrap();
        ares_gethostbyname(
            channel,
            name.as_ptr(),
            libc::AF_INET,
            host_callback,
            &mut result as *mut _ as *mut c_void,
        );

        // Destroy immediately — should not crash
        ares_destroy(channel);
    }
}

#[test]
fn threadsafety_returns_true() {
    assert_eq!(unsafe { event_thread::ares_threadsafety() }, 1);
}
