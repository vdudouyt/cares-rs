//! Safe pure-Rust core; raw pointers and the C ABI live under `src/ffi/`.
#![forbid(unsafe_code)]

pub mod cache;
pub mod conn;
pub mod dns_record;
pub mod edns;
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
pub mod udp_pool;

pub(crate) use error::AresError;
