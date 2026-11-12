#![deny(unsafe_op_in_unsafe_fn)]
// Panic-safety wall: a panic in a C-ABI library aborts the host process, so
// production code must stay panic-free. Tests are exempt.
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
mod plugins;

pub use crate::ffi::*;
