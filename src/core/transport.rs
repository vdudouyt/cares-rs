//! Transport abstraction — the engine does socket I/O only through these
//! object-safe traits. The FFI layer implements them (delegating to the
//! user-replaceable C socket-function table), so nothing under `src/core`
//! names an fd table, a C callback, or a sockaddr struct.

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

/// One non-blocking socket, already created for the right address family;
/// the verbs mirror the BSD socket calls the reactor needs.
pub trait Transport {
    fn as_raw_fd(&self) -> i32;
    fn connect(&self, addr: SocketAddr) -> io::Result<()>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)>;
    fn send(&self, data: &[u8]) -> io::Result<usize>;
}

/// Creates fresh non-blocking sockets appropriate for a bind address.
pub trait TransportFactory {
    fn create_udp(&self, bind: SocketAddr) -> io::Result<Rc<dyn Transport>>;
    fn create_tcp(&self, bind: SocketAddr) -> io::Result<Rc<dyn Transport>>;
}

/// In-memory transports for engine unit tests: no syscalls, so the tests
/// they back can run under Miri.
#[cfg(test)]
pub(crate) mod mock {
    use super::*;

    pub(crate) struct MockTransport;

    impl Transport for MockTransport {
        fn as_raw_fd(&self) -> i32 { 7 }
        fn connect(&self, _addr: SocketAddr) -> io::Result<()> { Ok(()) }
        fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> { Ok(data.len()) }
    }

    #[derive(Default)]
    pub(crate) struct MockFactory;

    impl TransportFactory for MockFactory {
        fn create_udp(&self, _bind: SocketAddr) -> io::Result<Rc<dyn Transport>> {
            Ok(Rc::new(MockTransport))
        }
        fn create_tcp(&self, _bind: SocketAddr) -> io::Result<Rc<dyn Transport>> {
            Ok(Rc::new(MockTransport))
        }
    }
}
