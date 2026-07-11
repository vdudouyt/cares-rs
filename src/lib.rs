#![deny(unsafe_op_in_unsafe_fn)]
// Panic-safety wall: a panic in a C-ABI library aborts the host process, so
// production code must not contain any panic path — no exceptions. Unit tests
// (`cfg(test)`) are exempt: panicking is how they assert.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable
    )
)]
mod async_runtime;
mod core;
mod ffi;

pub use crate::ffi::*;
