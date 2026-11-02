//! The reactor driver entry shims (ares_process / ares_process_fd): they
//! marshal the C `fd_set`s and drive every in-flight async future whose socket
//! is ready (or whose timeout passed) via `ChannelData::process_channel`.

use super::*;

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process_fd(channel: Channel, read_fd: c_int, write_fd: c_int) {
    if channel.is_null() { return; }
    unsafe {
        let mut read_fds: libc::fd_set = std::mem::zeroed();
        let mut write_fds: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut read_fds);
        libc::FD_ZERO(&mut write_fds);
        if read_fd != ARES_SOCKET_BAD {
            libc::FD_SET(read_fd, &mut read_fds);
        }
        if write_fd != ARES_SOCKET_BAD {
            libc::FD_SET(write_fd, &mut write_fds);
        }
        ares_process(channel, &mut read_fds, &mut write_fds);
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    channeldata.process_channel(read_fds, write_fds, false);
}

/// Process a batch of fd events in one pass (upstream ares_process_fds()).
/// `events` may be NULL when `nevents == 0`, which still runs timeout
/// processing unless ARES_PROCESS_FLAG_SKIP_NON_FD is set.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ares_process_fds(
    channel: Channel,
    events: *const crate::ffi::ares_socket::ares_fd_events_t,
    nevents: libc::size_t,
    flags: c_uint,
) -> c_int {
    if channel.is_null() || (events.is_null() && nevents != 0) {
        return ARES_EFORMERR;
    }
    // SAFETY: the caller guarantees a live channel handle.
    let Some(channeldata) = (unsafe { channel.as_mut() }) else {
        return ARES_EFORMERR;
    };
    let mut read_fds: libc::fd_set = unsafe { std::mem::zeroed() };
    let mut write_fds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&mut read_fds);
        libc::FD_ZERO(&mut write_fds);
    }
    if !events.is_null() {
        // SAFETY: the caller guarantees `events` points to `nevents` entries.
        let events = unsafe { std::slice::from_raw_parts(events, nevents) };
        unsafe {
            for ev in events {
                if ev.fd == ARES_SOCKET_BAD {
                    continue;
                }
                if ev.events & crate::ffi::ares_socket::ARES_FD_EVENT_READ != 0 {
                    libc::FD_SET(ev.fd, &mut read_fds);
                }
                if ev.events & crate::ffi::ares_socket::ARES_FD_EVENT_WRITE != 0 {
                    libc::FD_SET(ev.fd, &mut write_fds);
                }
            }
        }
    }
    let skip = flags & crate::ffi::ares_socket::ARES_PROCESS_FLAG_SKIP_NON_FD != 0;
    channeldata.process_channel(&mut read_fds, &mut write_fds, skip);
    ARES_SUCCESS
}
