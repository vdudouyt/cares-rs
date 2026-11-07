//! Protocol-agnostic async IO runtime: socket traits, the executor, and
//! readiness-driven IO arms. Nothing here imports `crate::core`; unsafe-free.
#![forbid(unsafe_code)]

pub mod socket;
pub mod executor;
pub mod io;
