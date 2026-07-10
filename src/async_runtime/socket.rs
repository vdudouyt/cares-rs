//! Socket abstraction — the engine does socket I/O only through these
//! object-safe traits. The FFI layer implements them (delegating to the
//! user-replaceable C socket-function table), so nothing under `src/core`
//! names an fd table, a C callback, or a sockaddr struct.

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

/// One non-blocking socket, already created for the right address family;
/// the verbs mirror the BSD socket calls the reactor needs.
pub trait Socket {
    fn as_raw_fd(&self) -> i32;
    fn connect(&self, addr: SocketAddr) -> io::Result<()>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)>;
    fn send(&self, data: &[u8]) -> io::Result<usize>;
}

/// Creates fresh non-blocking sockets appropriate for a bind address.
pub trait SocketFactory {
    fn create_udp(&self, bind: SocketAddr) -> io::Result<Rc<dyn Socket>>;
    fn create_tcp(&self, bind: SocketAddr) -> io::Result<Rc<dyn Socket>>;
}
