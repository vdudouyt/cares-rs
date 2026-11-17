//! `ares_save_options` / `ares_init_options` contract tests: saving must write
//! only the fields selected by the channel's optmask, newer option fields must
//! round-trip, and zero counts with non-NULL arrays must be accepted.

use std::ffi::{c_char, c_int};
use std::ptr;

use cares::ares_options::{
    ares_destroy_options, ares_init_options, ares_options, ares_save_options, ARES_OPT_DOMAINS,
    ARES_OPT_QUERY_CACHE, ARES_OPT_SERVER_FAILOVER, ARES_OPT_SERVERS, ARES_OPT_TIMEOUTMS,
    ARES_OPT_TRIES,
};
use cares::*;

const ARES_SUCCESS: c_int = 0;

/// `ares_save_options` may only write the scalar fields selected by the saved
/// mask (the channel's optmask plus documented defaults such as the query
/// cache).  Everything else must be left exactly as the caller initialized it,
/// because callers may have compiled against a smaller or differently
/// initialized `struct ares_options`.
#[test]
fn save_options_only_writes_options_selected_by_optmask() {
    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.timeout = 1000;
        opts.tries = 2;

        let init_mask = ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init_options(&mut ch, &opts, init_mask), ARES_SUCCESS);
        assert!(!ch.is_null());

        // Deliberately poison every byte, including fields the caller did not
        // ask c-ares to save.
        let mut saved: ares_options = std::mem::zeroed();
        ptr::write_bytes(&mut saved as *mut ares_options, 0xAA, 1);
        let mut mask: c_int = 0;
        let rc = ares_save_options(ch, &mut saved, &mut mask);
        assert_eq!(rc, ARES_SUCCESS);

        // Upstream reports the channel's optmask plus the documented query-cache
        // default: any non-NULL options struct gets a 3600 s TTL even when the
        // caller did not supply ARES_OPT_QUERY_CACHE.
        assert_eq!(
            mask,
            init_mask | ARES_OPT_QUERY_CACHE,
            "save mask must reflect the configured options plus the query-cache default"
        );

        // The selected fields are written; the query cache gets its default.
        assert_eq!(saved.timeout, 1000);
        assert_eq!(saved.tries, 2);
        assert_eq!(
            saved.qcache_max_ttl, 3600,
            "the documented query-cache default must be written when selected"
        );

        let aa_i32 = i32::from_ne_bytes([0xAA; 4]);
        let aa_u16 = u16::from_ne_bytes([0xAA; 2]);
        let aa_size = usize::from_ne_bytes([0xAA; std::mem::size_of::<usize>()]);

        // Every unselected scalar field must still carry the poison bytes.
        assert_eq!(saved.flags, aa_i32, "flags was not selected");
        assert_eq!(saved.ndots, aa_i32, "ndots was not selected");
        assert_eq!(saved.udp_port, aa_u16, "udp_port was not selected");
        assert_eq!(saved.tcp_port, aa_u16, "tcp_port was not selected");
        assert_eq!(
            saved.socket_send_buffer_size, aa_i32,
            "socket_send_buffer_size was not selected"
        );
        assert_eq!(
            saved.socket_receive_buffer_size, aa_i32,
            "socket_receive_buffer_size was not selected"
        );
        assert_eq!(saved.ednspsz, aa_i32, "ednspsz was not selected");
        assert_eq!(
            saved.udp_max_queries, aa_i32,
            "udp_max_queries was not selected"
        );
        assert_eq!(saved.maxtimeout, aa_i32, "maxtimeout was not selected");
        assert_eq!(saved.evsys, aa_i32, "evsys was not selected");
        assert_eq!(
            saved.server_failover_opts.retry_chance, aa_u16,
            "server_failover_opts.retry_chance was not selected"
        );
        assert_eq!(
            saved.server_failover_opts.retry_delay, aa_size,
            "server_failover_opts.retry_delay was not selected"
        );

        // Pointer fields are intentionally zeroed by ares_save_options so that
        // ares_destroy_options can safely free whatever was allocated; they are
        // not asserted here.
        ares_destroy_options(&mut saved);
        ares_destroy(ch);
    }
}

/// Newer options must survive a save/restore round-trip: both the mask bits and
/// the values need to be reported.
#[test]
fn save_options_roundtrips_query_cache_and_server_failover() {
    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.qcache_max_ttl = 3600;
        opts.server_failover_opts.retry_chance = 10;
        opts.server_failover_opts.retry_delay = 5000;

        let init_mask = ARES_OPT_QUERY_CACHE | ARES_OPT_SERVER_FAILOVER;
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init_options(&mut ch, &opts, init_mask), ARES_SUCCESS);
        assert!(!ch.is_null());

        let mut saved: ares_options = std::mem::zeroed();
        let mut mask: c_int = 0;
        assert_eq!(ares_save_options(ch, &mut saved, &mut mask), ARES_SUCCESS);

        assert_ne!(
            mask & ARES_OPT_QUERY_CACHE,
            0,
            "ARES_OPT_QUERY_CACHE must be reported after being configured"
        );
        assert_eq!(saved.qcache_max_ttl, 3600);

        assert_ne!(
            mask & ARES_OPT_SERVER_FAILOVER,
            0,
            "ARES_OPT_SERVER_FAILOVER must be reported after being configured"
        );
        assert_eq!(saved.server_failover_opts.retry_chance, 10);
        assert_eq!(saved.server_failover_opts.retry_delay, 5000);

        ares_destroy_options(&mut saved);
        ares_destroy(ch);
    }
}

/// Zero counts with non-NULL arrays are valid "nothing supplied" inputs and
/// must never drive a huge slice/loop.
#[test]
fn init_options_zero_counts_with_nonnull_arrays_are_accepted() {
    unsafe {
        let mut server = libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        };
        let domain = std::ffi::CString::new("example.com").unwrap();
        let mut domains = [domain.as_ptr() as *mut c_char];

        let mut opts: ares_options = std::mem::zeroed();
        opts.servers = &mut server;
        opts.nservers = 0;
        opts.domains = domains.as_mut_ptr();
        opts.ndomains = 0;

        let mask = ARES_OPT_SERVERS | ARES_OPT_DOMAINS;
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init_options(&mut ch, &opts, mask), ARES_SUCCESS);
        assert!(!ch.is_null());
        ares_destroy(ch);
    }
}
