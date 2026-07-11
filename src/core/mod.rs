//! Safe pure-Rust core: the resolver (`async_client`), DNS wire codec, and
//! system config. Compiler-enforced to stay unsafe-free — everything that
//! talks to raw pointers or the C ABI lives under `src/ffi/`.
#![forbid(unsafe_code)]

pub mod cache;
pub mod conn;
pub mod dns_record;
pub mod error;
pub mod async_client;
pub mod hostent;
pub mod lookup;
pub mod packets;
pub mod response;
pub mod sortlist;
pub mod sysconfig;
pub mod servers_csv;
pub mod hostfile;
pub mod services;
pub mod tcp_pool;

pub(crate) use error::AresError;
