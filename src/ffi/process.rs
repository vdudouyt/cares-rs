//! Reactor driver shims (ares_process / ares_process_fd / ares_process_fds).

use super::*;
use crate::ffi::ares_socket::{
    ares_fd_events_t, ARES_FD_EVENT_READ, ARES_FD_EVENT_WRITE,
    ARES_PROCESS_FLAG_SKIP_NON_FD,
};

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process_fd(channel: Channel, read_fd: c_int, write_fd: c_int) {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    let mut events = [
        ares_fd_events_t { fd: ARES_SOCKET_BAD, events: 0 },
        ares_fd_events_t { fd: ARES_SOCKET_BAD, events: 0 },
    ];
    let mut n = 0usize;
    if read_fd != ARES_SOCKET_BAD {
        events[n] = ares_fd_events_t { fd: read_fd, events: ARES_FD_EVENT_READ };
        n += 1;
    }
    if write_fd != ARES_SOCKET_BAD {
        events[n] = ares_fd_events_t { fd: write_fd, events: ARES_FD_EVENT_WRITE };
        n += 1;
    }
    channeldata.process_events(&events[..n], false);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    channeldata.process_channel(read_fds, write_fds, false);
}

/// Process a batch of fd events in one pass. `events` may be NULL when
/// `nevents == 0`; timeouts still run unless ARES_PROCESS_FLAG_SKIP_NON_FD is set.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process_fds(
    channel: Channel,
    events: *const ares_fd_events_t,
    nevents: libc::size_t,
    flags: c_uint,
) -> c_int {
    if channel.is_null() || (events.is_null() && nevents != 0) {
        return ARES_EFORMERR;
    }
    // SAFETY: the caller guarantees a live channel handle.
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
    let events: &[ares_fd_events_t] = if events.is_null() {
        &[]
    } else {
        // SAFETY: the caller guarantees `events` points to `nevents` entries.
        unsafe { std::slice::from_raw_parts(events, nevents) }
    };
    let skip = flags & ARES_PROCESS_FLAG_SKIP_NON_FD != 0;
    channeldata.process_events(events, skip);
    ARES_SUCCESS
}
