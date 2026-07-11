//! The async IO runtime: socket traits, the executor (mailbox + task set),
//! and tokio-style async connections. Protocol-agnostic — nothing in this
//! section names DNS (the mailbox is generic over an opaque app-state `A`)
//! and nothing imports `crate::core`. Compiler-enforced to stay unsafe-free,
//! like `core`.
#![forbid(unsafe_code)]

pub mod socket;
pub mod executor;
pub mod conn;
