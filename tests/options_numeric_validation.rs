//! Non-positive numeric `ares_init_options` values are documented to mean
//! "use the default".  They must not be cast to huge unsigned values or
//! overflow (a debug-build overflow aborts the host process across FFI).
//!
//! A panic inside an `extern "C"` function cannot be caught in-process: Rust
//! aborts.  To still get a per-case pass/fail report, each case runs in a child
//! copy of this test binary.  Miri cannot spawn processes, so there the cases
//! run directly in-process instead (they are not expected to panic).

use std::ffi::c_int;
#[cfg(not(miri))]
use std::process::Command;
use std::ptr;

use cares::ares_options::{
    ares_destroy_options, ares_init_options, ares_options, ares_save_options,
    ARES_OPT_MAXTIMEOUTMS, ARES_OPT_NDOTS, ARES_OPT_TIMEOUT, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES,
};
use cares::*;

const ARES_SUCCESS: c_int = 0;
#[cfg(not(miri))]
const CASE_ENV: &str = "CARES_RS_NUMERIC_OPTION_CASE";

const CASES: [&str; 5] = [
    "timeout_seconds",
    "timeout_ms",
    "tries",
    "ndots",
    "maxtimeout_ms",
];

fn run_case(name: &str) {
    let (mask, value) = match name {
        "timeout_seconds" => (ARES_OPT_TIMEOUT, -1),
        "timeout_ms" => (ARES_OPT_TIMEOUTMS, -1),
        "tries" => (ARES_OPT_TRIES, -1),
        "ndots" => (ARES_OPT_NDOTS, -1),
        "maxtimeout_ms" => (ARES_OPT_MAXTIMEOUTMS, -1),
        other => panic!("unknown case {other}"),
    };

    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        match name {
            "timeout_seconds" | "timeout_ms" => opts.timeout = value,
            "tries" => opts.tries = value,
            "ndots" => opts.ndots = value,
            "maxtimeout_ms" => opts.maxtimeout = value,
            _ => unreachable!(),
        }

        let mut ch: Channel = ptr::null_mut();
        let rc = ares_init_options(&mut ch, &opts, mask);
        assert_eq!(rc, ARES_SUCCESS, "{name}: ares_init_options failed");
        assert!(!ch.is_null(), "{name}: channel was not created");
        assert_eq!(ares_queue_active_queries(ch), 0, "{name}: channel unusable");

        // Upstream ignores non-positive values, dropping the option bit rather
        // than storing a huge or zero value.
        let mut saved: ares_options = std::mem::zeroed();
        let mut saved_mask: c_int = 0;
        assert_eq!(
            ares_save_options(ch, &mut saved, &mut saved_mask),
            ARES_SUCCESS,
            "{name}: ares_save_options failed"
        );
        assert_eq!(
            saved_mask & mask,
            0,
            "{name}: non-positive value must be dropped from the optmask"
        );
        ares_destroy_options(&mut saved);
        ares_destroy(ch);
    }
}

/// Child entry point: runs one case selected by `CASE_ENV`.  With no env var
/// (a normal `cargo test` run) it is simply a no-op.
#[cfg(not(miri))]
#[test]
fn numeric_option_case_child() {
    let Ok(name) = std::env::var(CASE_ENV) else {
        return;
    };
    run_case(&name);
}

/// Parent test: every non-positive numeric option must be accepted without
/// panicking/aborting and produce a usable channel.
#[cfg(not(miri))]
#[test]
fn init_options_nonpositive_numeric_options_do_not_abort() {
    let exe = std::env::current_exe().expect("test executable path");
    let mut failures = Vec::new();

    for name in CASES {
        let output = Command::new(&exe)
            .args([
                "--exact",
                "numeric_option_case_child",
                "--test-threads",
                "1",
                "--nocapture",
            ])
            .env(CASE_ENV, name)
            .env("RUST_BACKTRACE", "0")
            .output()
            .expect("spawn child test process");
        if !output.status.success() {
            failures.push(format!(
                "{name}: child exited with {}\n--- child stderr ---\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "non-positive option values caused a panic/abort or failure:\n\n{}",
        failures.join("\n\n")
    );
}

/// Miri variant: process spawning is unsupported, so run every case directly
/// in-process.  Any panic or abort still fails the run, just without the
/// per-case child isolation that native runs get.
#[cfg(miri)]
#[test]
fn init_options_nonpositive_numeric_options_do_not_abort() {
    for name in CASES {
        run_case(name);
    }
}
