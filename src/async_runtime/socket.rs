//! Socket abstraction: the engine does socket I/O only through these
//! object-safe traits, implemented by the FFI layer over the C socket table.

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

/// One non-blocking socket for a fixed address family.
pub trait Socket {
    fn as_raw_fd(&self) -> i32;
    fn connect(&self, addr: SocketAddr) -> io::Result<()>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)>;
    fn send(&self, data: &[u8]) -> io::Result<usize>;
    /// Whether repeated `recv` calls cannot block; draining loops must not
    /// re-read a caller-supplied socket that may be blocking.
    fn drain_safe(&self) -> bool {
        true
    }
}

/// Creates fresh non-blocking sockets for a bind address.
pub trait SocketFactory {
    fn create_udp(&self, bind: SocketAddr) -> io::Result<Rc<dyn Socket>>;
    fn create_tcp(&self, bind: SocketAddr) -> io::Result<Rc<dyn Socket>>;
}
