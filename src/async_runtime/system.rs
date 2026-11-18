//! Default system sockets: the zero-configuration `SocketFactory` used by
//! [`Runtime::create_tcp`](crate::async_runtime::Runtime::create_tcp) and
//! [`Runtime::create_udp`](crate::async_runtime::Runtime::create_udp).
//!
//! Custom applications keep using [`SocketFactory`](super::socket::SocketFactory)
//! through `Runtime::create_custom_socket`; this module is only the built-in
//! std/rustix implementation.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
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
}

/// Create and bind one non-blocking system socket.
pub(crate) fn create(kind: SocketKind, bind: SocketAddr) -> io::Result<Rc<dyn Socket>> {
    let family = if bind.is_ipv4() {
        AddressFamily::INET
    } else {
        AddressFamily::INET6
    };
    let socket_type = match kind {
        SocketKind::Tcp => SocketType::STREAM,
        SocketKind::Udp => SocketType::DGRAM,
    };

    let fd = rustix::net::socket(family, socket_type, None)?;
    if !bind.ip().is_unspecified() || bind.port() != 0 {
        bind_fd(&fd, bind)?;
    }

    let socket = match kind {
        SocketKind::Tcp => {
            let stream = TcpStream::from(fd);
            stream.set_nonblocking(true)?;
            SystemSocket::Tcp(stream)
        }
        SocketKind::Udp => {
            let socket = UdpSocket::from(fd);
            socket.set_nonblocking(true)?;
            SystemSocket::Udp(socket)
        }
    };
    Ok(Rc::new(socket))
}

fn bind_fd(fd: &OwnedFd, addr: SocketAddr) -> io::Result<()> {
    rustix::net::bind(fd, &addr)?;
    Ok(())
}
