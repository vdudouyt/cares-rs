//! Default system sockets: the zero-configuration `SocketFactory` used by
//! [`Runtime::create_tcp`](crate::async_runtime::Runtime::create_tcp) and
//! [`Runtime::create_udp`](crate::async_runtime::Runtime::create_udp).
//!
//! Custom applications keep using [`SocketFactory`](super::socket::SocketFactory)
//! through `Runtime::create_custom_socket`; this module is only the built-in
//! std/rustix implementation.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::rc::Rc;

use rustix::net::{AddressFamily, SocketType};

use super::socket::{Socket, SocketKind};

enum SystemSocket {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Socket for SystemSocket {
    fn as_raw_fd(&self) -> i32 {
        match self {
            SystemSocket::Tcp(stream) => stream.as_raw_fd(),
            SystemSocket::Udp(socket) => socket.as_raw_fd(),
        }
    }

    fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        match self {
            SystemSocket::Tcp(stream) => match rustix::net::connect(stream, &addr) {
                Ok(()) => Ok(()),
                // Non-blocking TCP connect: completion is observed as
                // writability, exactly like c-ares custom socket functions.
                Err(rustix::io::Errno::INPROGRESS) | Err(rustix::io::Errno::WOULDBLOCK) => Ok(()),
                Err(e) => Err(e.into()),
            },
            SystemSocket::Udp(socket) => socket.connect(addr),
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            SystemSocket::Tcp(stream) => (&*stream).read(buf),
            SystemSocket::Udp(socket) => socket.recv(buf),
        }
    }

    fn send(&self, data: &[u8]) -> io::Result<usize> {
        match self {
            SystemSocket::Tcp(stream) => (&*stream).write(data),
            SystemSocket::Udp(socket) => socket.send(data),
        }
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        match self {
            SystemSocket::Tcp(stream) => stream.take_error(),
            SystemSocket::Udp(_) => Ok(None),
        }
    }
}

/// Create and bind one non-blocking system socket.
pub(crate) fn create(kind: SocketKind, bind: SocketAddr) -> io::Result<Rc<dyn Socket>> {
    let socket = match kind {
        // std has a bound datagram constructor.
        SocketKind::Udp => {
            let socket = UdpSocket::bind(bind)?;
            socket.set_nonblocking(true)?;
            SystemSocket::Udp(socket)
        }
        // std has no unconnected/bound TCP constructor: TcpStream only comes
        // from connect/connect_timeout/accept. Create the fd with rustix, bind
        // it, then hand it to std.
        SocketKind::Tcp => {
            let family = if bind.is_ipv4() {
                AddressFamily::INET
            } else {
                AddressFamily::INET6
            };
            let fd = rustix::net::socket(family, SocketType::STREAM, None)?;
            if !bind.ip().is_unspecified() || bind.port() != 0 {
                rustix::net::bind(&fd, &bind)?;
            }
            let stream = TcpStream::from(fd);
            stream.set_nonblocking(true)?;
            SystemSocket::Tcp(stream)
        }
    };
    Ok(Rc::new(socket))
}
