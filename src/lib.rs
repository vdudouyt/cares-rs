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
/// A small, single-threaded async runtime driven by the application's event
/// loop. See `ASYNC_RUNTIME.md` for the model and `examples/tcp_hello.rs` for
/// a full socket client.
pub mod async_runtime;
mod core;
mod ffi;
mod plugins;
mod mem;

pub use crate::ffi::*;
