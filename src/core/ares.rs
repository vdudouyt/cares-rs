use std::net::{ SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr };
use bytes::{ BytesMut, BufMut };
use rand::Rng;
use std::time::{ Instant, Duration };
use std::rc::Rc;

use crate::core::sysconfig::SysConfig;
use crate::core::hostfile::Hosts;
use crate::core::services::Services;
use crate::ffi::SocketFactory;
use crate::ffi::ares_socket;

const BIND_ADDR_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
const BIND_ADDR_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

/* TODO: reconcile ChannelData here */
pub struct Ares<T> {
    pub config: SysConfig,
    pub socket_factory: Rc<SocketFactory>,
    pub tasks: Vec<Task<T>>,
    hosts: Option<Hosts>,
    services: Option<Services>,
    pub default_udp_port: u16,
    pub default_tcp_port: u16,
    pub server_failures: Vec<u32>,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Family { Ipv4, Ipv6 }

pub enum DnsSocket {
    Udp(Rc<ares_socket::UdpSocket>),
    Tcp(Rc<ares_socket::TcpSocket>),
}

impl DnsSocket {
    pub fn as_raw_fd(&self) -> std::ffi::c_int {
        match self { Self::Udp(s) => s.as_raw_fd(), Self::Tcp(s) => s.as_raw_fd() }
    }
    pub fn connect(&self, addr: SocketAddr) -> std::io::Result<()> {
        match self { Self::Udp(s) => s.connect(addr), Self::Tcp(s) => s.connect(addr) }
    }
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, Option<SocketAddr>)> {
        match self { Self::Udp(s) => s.recv(buf), Self::Tcp(s) => s.recv(buf) }
    }
    pub fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        match self { Self::Udp(s) => s.send(data), Self::Tcp(s) => s.send(data) }
    }
    pub fn is_tcp(&self) -> bool { matches!(self, Self::Tcp(_)) }
}

/// How `enqueue` should obtain the socket for a query.
pub enum SocketSource {
    /// Create a fresh UDP socket bound for the target server.
    Udp,
    /// Create a fresh TCP socket and connect it to the target server.
    Tcp,
    /// Reuse an already-open (pooled) socket.
    Shared(DnsSocket),
}

impl SocketSource {
    /// `Tcp` when `use_tcp`, else `Udp` — collapses the common transport branch.
    pub fn fresh(use_tcp: bool) -> Self {
        if use_tcp { Self::Tcp } else { Self::Udp }
    }
}

/// Write a DNS query directly to the buffer from a hostname string,
/// avoiding intermediate Vec<String>, DnsQuery, and DnsFrame allocations.
fn write_dns_query_direct(buf: &mut BytesMut, hostname: &str, qtype: u16, transaction_id: u16) {
    // Header: 12 bytes
    buf.put_u16(transaction_id);
    buf.put_u16(0x0100); // flags: standard query, recursion desired
    buf.put_u16(1);      // qdcount
    buf.put_u16(0);      // ancount
    buf.put_u16(0);      // nscount
    buf.put_u16(0);      // arcount

    // Question: labels
    for label in hostname.split('.').filter(|t| !t.is_empty()) {
        buf.put_u8(label.len() as u8);
        buf.put_slice(label.as_bytes());
    }
    buf.put_u8(0); // root label
    buf.put_u16(qtype);
    buf.put_u16(1); // qclass: IN
}

/// A/AAAA query type for an address family.
pub fn qtype_of(family: Family) -> u16 {
    match family {
        Family::Ipv4 => 0x01, // A
        Family::Ipv6 => 0x1c, // AAAA
    }
}

/// Build a UDP-form DNS query payload (with a fresh random transaction id).
pub fn dns_query_payload(name: &str, qtype: u16) -> BytesMut {
    let transaction_id = rand::thread_rng().r#gen::<u16>();
    let mut buf = BytesMut::with_capacity(12 + name.len() + 2 + 4);
    write_dns_query_direct(&mut buf, name, qtype, transaction_id);
    buf
}

/// Wrap a DNS payload in the 2-byte big-endian length prefix used for TCP framing.
fn frame_tcp(payload: &[u8]) -> BytesMut {
    let mut framed = BytesMut::with_capacity(2 + payload.len());
    framed.put_u16(payload.len() as u16);
    framed.extend_from_slice(payload);
    framed
}

pub enum WriteResult {
    Ok,
    Failed,
    TryAgain,
}

impl<T> Ares<T> {
    pub fn new(config: SysConfig) -> Self {
        Ares {
            config,
            socket_factory: Rc::new(SocketFactory::default()),
            tasks: vec![],
            hosts: None,
            services: None,
            default_udp_port: 53,
            default_tcp_port: 53,
            server_failures: vec![],
        }
    }
    pub fn from_sysconfig() -> Self {
        Ares::new(build_sysconfig())
    }
    pub fn hosts(&mut self) -> &Hosts {
        self.hosts.get_or_insert_with(|| Hosts::from_path("/etc/hosts").unwrap_or_default())
    }
    pub fn services(&mut self) -> &Services {
        self.services.get_or_insert_with(Services::default)
    }
    fn bind_addr_for_server(&self, server_index: usize) -> SocketAddr {
        match self.config.nameservers.get(server_index) {
            Some((IpAddr::V6(_), _)) => BIND_ADDR_V6,
            _ => BIND_ADDR_V4,
        }
    }
    /// Resolve the TCP port for a server: its per-server override, else the default.
    /// Uses the raw index (returns the default past the end of `tcp_ports`).
    fn tcp_port_for_server(&self, server_index: usize) -> u16 {
        self.config.tcp_ports.get(server_index).copied().flatten().unwrap_or(self.default_tcp_port)
    }
    /// Issue a query: resolve the socket (a fresh UDP/TCP one or a pooled one),
    /// apply TCP framing when needed, and enqueue the task. The single entry point
    /// for every query the engine sends. Errs only if a fresh socket can't be
    /// created (the `Shared` arm is infallible).
    pub fn enqueue(&mut self, payload: BytesMut, socket: SocketSource, server_index: usize, userdata: T) -> Result<(), std::io::Error> {
        let sock = match socket {
            SocketSource::Udp => DnsSocket::Udp(Rc::new(self.socket_factory.create_udp(self.bind_addr_for_server(server_index))?)),
            SocketSource::Tcp => {
                let s = self.socket_factory.create_tcp(self.bind_addr_for_server(server_index))?;
                self.connect_tcp(&s, server_index);
                DnsSocket::Tcp(Rc::new(s))
            }
            SocketSource::Shared(ds) => ds,
        };
        // TCP needs the 2-byte length prefix; UDP sends the payload as-is.
        let writebuf = if sock.is_tcp() { frame_tcp(&payload) } else { payload };
        let expires_at = Instant::now() + Duration::from_millis(self.config.options.timeout_ms as u64);
        self.tasks.push(Task { status: Status::Writing, sock, writebuf, userdata, expires_at, server_index, tries_remaining: 0 });
        Ok(())
    }
    /// Connect a freshly-created TCP socket to the given server's address.
    fn connect_tcp(&self, sock: &ares_socket::TcpSocket, server_index: usize) {
        // Clamp the index for the (non-empty) nameservers list; the tcp_ports
        // lookup deliberately uses the raw index (returns None past the end).
        let idx = server_index.min(self.config.nameservers.len().saturating_sub(1));
        let ns_addr = &self.config.nameservers[idx];
        let tcp_port = self.tcp_port_for_server(server_index);
        let _ = sock.connect(SocketAddr::from((ns_addr.0, tcp_port)));
    }
    /// Create a fresh socket of the given transport, bound for `server_index` and
    /// connected to `addr` — used by `write_impl` to recover from a send failure.
    fn fresh_socket(&self, is_tcp: bool, server_index: usize, addr: SocketAddr) -> std::io::Result<DnsSocket> {
        let bind = self.bind_addr_for_server(server_index);
        let sock = if is_tcp {
            DnsSocket::Tcp(Rc::new(self.socket_factory.create_tcp(bind)?))
        } else {
            DnsSocket::Udp(Rc::new(self.socket_factory.create_udp(bind)?))
        };
        let _ = sock.connect(addr);
        Ok(sock)
    }
    pub fn write_impl(&mut self, task: &mut Task<T>) -> WriteResult {
        let server_index = task.server_index;
        // The server list can shrink under an in-flight task (e.g. ares_set_servers
        // mid-query); fail the write instead of indexing out of bounds.
        let Some(&(ns_ip, ns_port)) = self.config.nameservers.get(server_index) else {
            return WriteResult::Failed;
        };
        let is_tcp = task.sock.is_tcp();
        let socket_addr = if is_tcp {
            SocketAddr::from((ns_ip, self.tcp_port_for_server(server_index)))
        } else {
            SocketAddr::from((ns_ip, ns_port.unwrap_or(self.default_udp_port)))
        };
        // UDP connects before each send; TCP was already connected at issue time.
        if !is_tcp {
            let _ = task.sock.connect(socket_addr);
        }
        // Send; on a hard error, recreate the socket once and resend.
        let mut recreated = false;
        loop {
            match task.sock.send(&task.writebuf) {
                Ok(_) => { task.status = Status::Reading; return WriteResult::Ok; }
                // TCP treats a full send buffer as "wait for writable"; UDP recreates.
                Err(ref e) if is_tcp && e.kind() == std::io::ErrorKind::WouldBlock => return WriteResult::TryAgain,
                Err(_) if !recreated => {
                    recreated = true;
                    let Ok(s) = self.fresh_socket(is_tcp, server_index, socket_addr) else { break };
                    task.sock = s;
                }
                Err(_) => break,
            }
        }
        task.status = Status::Completed;
        WriteResult::Failed
    }
    /// Returns Ok(Some((offset, len))) on success, Ok(None) on WouldBlock, Err on fatal recv error.
    pub fn read_impl(task: &mut Task<T>, readbuf: &mut [u8]) -> Result<Option<(usize, usize)>, ()> {
        let (len, _src) = match task.sock.recv(readbuf) {
            Ok(result) => result,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data yet, stay in Reading status
                return Ok(None);
            }
            Err(_) => { task.status = Status::Completed; return Err(()); }
        };
        if task.sock.is_tcp() {
            if len < 2 { return Ok(None); }
            let payload_len = u16::from_be_bytes([readbuf[0], readbuf[1]]) as usize;
            if len < 2 + payload_len { return Ok(None); }
            task.status = Status::Completed;
            Ok(Some((2, payload_len)))
        } else {
            task.status = Status::Completed;
            Ok(Some((0, len)))
        }
    }
    pub fn max_wait_time(&self) -> Duration {
        self.tasks.iter().map(Task::time_remaining).min().unwrap()
    }
    pub fn remove_completed(&mut self) {
        self.tasks.retain(|task| !task.is_expired());
    }
}

pub fn rdns_name(ip: IpAddr) -> String {
    match ip {
        // decimal
        IpAddr::V4(v4) => v4.octets().into_iter().rev().map(|b| b.to_string())
            .collect::<Vec<_>>().join(".") + ".in-addr.arpa",
        // hex (low nibble first)
        IpAddr::V6(v6) => v6.octets().into_iter().flat_map(|b| [b >> 4, b & 0x0f]).map(|n| format!("{:x}", n))
            .collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".") + ".ip6.arpa",
    }
}

#[derive(PartialEq)]
pub enum Status { Writing, Reading, Completed }

pub struct Task<T> {
    pub status: Status,
    pub sock: DnsSocket,
    pub writebuf: BytesMut,
    pub userdata: T,
    pub expires_at: Instant,
    pub server_index: usize,
    pub tries_remaining: u32,
}

impl<T> Task<T> {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
    pub fn time_remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

pub fn build_sysconfig() -> SysConfig {
    let try_resolv_conf = || std::fs::read_to_string("/etc/resolv.conf").ok()?.parse::<SysConfig>().ok();
    let mut config = try_resolv_conf().unwrap_or_else(SysConfig::default);
    crate::core::sysconfig::apply_env_overrides(&mut config);
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_impl_stale_server_index_fails_gracefully() {
        // Issue a query (pushes a task bound to server 0), then shrink the server
        // list out from under the in-flight task — write_impl must fail gracefully
        // (WriteResult::Failed) rather than index nameservers out of bounds.
        let config = "nameserver 1.1.1.1\n".parse::<SysConfig>().unwrap();
        let mut ares: Ares<()> = Ares::new(config);
        ares.enqueue(dns_query_payload("example.com", qtype_of(Family::Ipv4)), SocketSource::Udp, 0, ()).unwrap();
        let mut task = ares.tasks.pop().expect("a task was pushed");
        ares.config.nameservers.clear(); // server list shrank under the in-flight task
        assert!(matches!(ares.write_impl(&mut task), WriteResult::Failed));
    }
}
