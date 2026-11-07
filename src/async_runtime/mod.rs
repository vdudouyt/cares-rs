//! Protocol-agnostic async IO runtime in the shape of smol: socket traits, the
//! per-channel reactor (`Async` sockets, `Timer`s), and the executor — driven by
//! the host's `ares_process*` turns instead of a blocking event loop. Nothing here imports `crate::core`; unsafe-free.
#![forbid(unsafe_code)]

pub mod socket;
pub mod executor;
pub mod io;
pub mod reactor;
