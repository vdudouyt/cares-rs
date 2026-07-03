//! Safe pure-Rust core: DNS wire codec, transport engine, system config and
//! the query-lifecycle state machine. Compiler-enforced to stay unsafe-free —
//! everything that talks to raw pointers or the C ABI lives under `src/ffi/`.
#![forbid(unsafe_code)]

pub mod ares;
pub mod channel;
pub mod lookup;
pub mod transport;
pub mod packets;
pub mod preflight;
pub mod query_builder;
pub mod response;
pub mod sortlist;
pub mod sysconfig;
pub mod servers_csv;
pub mod hostfile;
pub mod services;
