//! The reactor driver entry shims (ares_process / ares_process_fd). The
//! 4-phase reactor loop itself and the server-state notification are
//! `ChannelData` methods (see `ffi::channel`); the `carry_over` retry helper
//! stays a free fn here.

use super::*;
use crate::core::client::Client;
use crate::core::transport::Task;

/// Copy the core-owned per-task data (state machine, family/record-type,
/// queried ip) from a settled task onto the retry task `reissue` just pushed,
/// stamping the accumulated timeout count — so the eventual reply is
/// attributed just like the original send. (`enqueue` defaults these fields.)
pub(crate) fn carry_over(state: &mut Client<FFIData>, old: &Task<FFIData>, timeouts: i32, failover_tries: u32) {
    if let Some(t) = state.transport.tasks.last_mut() {
        t.machine = old.machine.clone();
        t.family = old.family;
        t.rtype = old.rtype;
        t.queried_ip = old.queried_ip;
        t.timeouts = timeouts;
        t.failover_tries = failover_tries;
    }
}

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
    channeldata.process_channel(read_fds, write_fds);
}
