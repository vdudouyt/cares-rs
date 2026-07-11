//! The async IO runtime: socket traits, the executor (mailbox + task set),
//! and byte-level readiness-driven IO arms — async IO and async/await
//! execution, nothing else. Protocol-agnostic by design: no framing, no
//! demux, no pooling (those are application business logic and live in
//! `core::conn`); the mailbox is generic over an opaque app-state `A` and
//! nothing imports `crate::core`. Compiler-enforced to stay unsafe-free,
//! like `core`.
#![forbid(unsafe_code)]

pub mod socket;
pub mod executor;
pub mod io;
