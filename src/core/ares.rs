use std::net::{ SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr };
use bytes::{ BytesMut, BufMut };
use rand::Rng;
use std::time::{ Instant, Duration };
use std::rc::Rc;

use crate::core::sysconfig::SysConfig;
use crate::core::hostfile::Hosts;
use crate::core::services::Services;
use crate::ffi::SocketFactory;
use crate::ffi::{ ares_socket, RECORD_TYPE_PTR };

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
fn qtype_of(family: Family) -> u16 {
    match family {
        Family::Ipv4 => 0x01, // A
        Family::Ipv6 => 0x1c, // AAAA
    }
}

/// Build a UDP-form DNS query payload (with a fresh random transaction id).
fn dns_query_payload(name: &str, qtype: u16) -> BytesMut {
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
    fn bind_addr(&self) -> SocketAddr {
        self.bind_addr_for_server(0)
    }
    /// Compute the expiry, build the task, and enqueue it — the single tail
    /// shared by every query-issuing method below.
    fn enqueue(&mut self, sock: DnsSocket, writebuf: BytesMut, userdata: T, server_index: usize) {
        let expires_at = Instant::now() + Duration::from_millis(self.config.options.timeout_ms as u64);
        self.tasks.push(Task { status: Status::Writing, sock, writebuf, userdata, expires_at, server_index, tries_remaining: 0 });
    }
    /// Connect a freshly-created TCP socket to the given server's address.
    fn connect_tcp(&self, sock: &ares_socket::TcpSocket, server_index: usize) {
        // Clamp the index for the (non-empty) nameservers list; the tcp_ports
        // lookup deliberately uses the raw index (returns None past the end).
        let idx = server_index.min(self.config.nameservers.len().saturating_sub(1));
        let ns_addr = &self.config.nameservers[idx];
        let tcp_port = self.config.tcp_ports.get(server_index).copied().flatten().unwrap_or(self.default_tcp_port);
        let _ = sock.connect(SocketAddr::from((ns_addr.0, tcp_port)));
    }
    pub fn gethostbyname(&mut self, hostname: &str, family: Family, userdata: T) -> Result<(), std::io::Error> {
        self.gethostbyname_to_server(hostname, family, userdata, 0)
    }
    pub fn gethostbyname_to_server(&mut self, hostname: &str, family: Family, userdata: T, server_index: usize) -> Result<(), std::io::Error> {
        let sock = self.socket_factory.create_udp(self.bind_addr_for_server(server_index))?;
        self.enqueue(DnsSocket::Udp(Rc::new(sock)), dns_query_payload(hostname, qtype_of(family)), userdata, server_index);
        Ok(())
    }
    pub fn gethostbyname_to_server_shared(&mut self, hostname: &str, family: Family, userdata: T, server_index: usize, shared_sock: Rc<ares_socket::UdpSocket>) -> &Task<T> {
        self.enqueue(DnsSocket::Udp(shared_sock), dns_query_payload(hostname, qtype_of(family)), userdata, server_index);
        self.tasks.last().unwrap()
    }
    pub fn send_raw_to_server_shared(&mut self, packet: &[u8], userdata: T, server_index: usize, shared_sock: Rc<ares_socket::UdpSocket>) {
        self.enqueue(DnsSocket::Udp(shared_sock), BytesMut::from(packet), userdata, server_index);
    }
    pub fn gethostbyname_tcp(&mut self, hostname: &str, family: Family, userdata: T) -> Result<(), std::io::Error> {
        self.gethostbyname_tcp_to_server(hostname, family, userdata, 0)
    }
    pub fn gethostbyname_tcp_to_server(&mut self, hostname: &str, family: Family, userdata: T, server_index: usize) -> Result<(), std::io::Error> {
        let sock = self.socket_factory.create_tcp(self.bind_addr_for_server(server_index))?;
        self.connect_tcp(&sock, server_index);
        let payload = dns_query_payload(hostname, qtype_of(family));
        self.enqueue(DnsSocket::Tcp(Rc::new(sock)), frame_tcp(&payload), userdata, server_index);
        Ok(())
    }
    pub fn gethostbyname_tcp_to_server_shared(&mut self, hostname: &str, family: Family, userdata: T, server_index: usize, shared_sock: Rc<ares_socket::TcpSocket>) -> &Task<T> {
        let payload = dns_query_payload(hostname, qtype_of(family));
        self.enqueue(DnsSocket::Tcp(shared_sock), frame_tcp(&payload), userdata, server_index);
        self.tasks.last().unwrap()
    }
    pub fn send_raw_tcp_to_server_shared(&mut self, packet: &[u8], userdata: T, server_index: usize, shared_sock: Rc<ares_socket::TcpSocket>) {
        self.enqueue(DnsSocket::Tcp(shared_sock), frame_tcp(packet), userdata, server_index);
    }
    pub fn gethostbyaddr(&mut self, addr: IpAddr, userdata: T) -> Result<(), std::io::Error> {
        let sock = self.socket_factory.create_udp(self.bind_addr())?;
        self.enqueue(DnsSocket::Udp(Rc::new(sock)), dns_query_payload(&rdns_name(addr), RECORD_TYPE_PTR), userdata, 0);
        Ok(())
    }
    pub fn query(&mut self, name: &str, _dnsclass: u16, dnstype: u16, userdata: T) -> Result<(), std::io::Error> {
        let sock = self.socket_factory.create_udp(self.bind_addr())?;
        self.enqueue(DnsSocket::Udp(Rc::new(sock)), dns_query_payload(name, dnstype), userdata, 0);
        Ok(())
    }
    pub fn send_raw(&mut self, packet: &[u8], userdata: T) -> Result<(), std::io::Error> {
        let sock = self.socket_factory.create_udp(self.bind_addr())?;
        self.enqueue(DnsSocket::Udp(Rc::new(sock)), BytesMut::from(packet), userdata, 0);
        Ok(())
    }
    pub fn send_raw_to_server(&mut self, packet: &[u8], userdata: T, server_index: usize) -> Result<(), std::io::Error> {
        let sock = self.socket_factory.create_udp(self.bind_addr_for_server(server_index))?;
        self.enqueue(DnsSocket::Udp(Rc::new(sock)), BytesMut::from(packet), userdata, server_index);
        Ok(())
    }
    pub fn send_raw_tcp_to_server(&mut self, packet: &[u8], userdata: T, server_index: usize) -> Result<(), std::io::Error> {
        let sock = self.socket_factory.create_tcp(self.bind_addr_for_server(server_index))?;
        self.connect_tcp(&sock, server_index);
        self.enqueue(DnsSocket::Tcp(Rc::new(sock)), frame_tcp(packet), userdata, server_index);
        Ok(())
    }
    pub fn write_impl(&mut self, task: &mut Task<T>) -> WriteResult {
        let server_index = task.server_index;
        // The server list can shrink under an in-flight task (e.g. ares_set_servers
        // mid-query); fail the write instead of indexing out of bounds.
        let Some(ns_addr) = self.config.nameservers.get(server_index) else {
            return WriteResult::Failed;
        };
        if task.sock.is_tcp() {
            // TCP: already connected, just send
            match task.sock.send(&task.writebuf) {
                Ok(_) => { task.status = Status::Reading; WriteResult::Ok }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => WriteResult::TryAgain,
                Err(_) => {
                    // TCP send failed — reconnect and retry once
                    let bind_addr = self.bind_addr_for_server(server_index);
                    if let Ok(new_sock) = self.socket_factory.create_tcp(bind_addr) {
                        let tcp_port = self.config.tcp_ports.get(server_index).copied().flatten().unwrap_or(self.default_tcp_port);
                        let socket_addr = SocketAddr::from((ns_addr.0, tcp_port));
                        let _ = new_sock.connect(socket_addr);
                        task.sock = DnsSocket::Tcp(Rc::new(new_sock));
                        match task.sock.send(&task.writebuf) {
                            Ok(_) => { task.status = Status::Reading; WriteResult::Ok }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => WriteResult::TryAgain,
                            Err(_) => { task.status = Status::Completed; WriteResult::Failed }
                        }
                    } else {
                        task.status = Status::Completed; WriteResult::Failed
                    }
                }
            }
        } else {
            let socket_addr = SocketAddr::from((ns_addr.0, ns_addr.1.unwrap_or(self.default_udp_port)));
            let _ = task.sock.connect(socket_addr);
            match task.sock.send(&task.writebuf) {
                Ok(_) => { task.status = Status::Reading; WriteResult::Ok }
                Err(_) => {
                    // UDP send failed — create new socket and retry once
                    let bind_addr = self.bind_addr_for_server(server_index);
                    if let Ok(new_sock) = self.socket_factory.create_udp(bind_addr) {
                        task.sock = DnsSocket::Udp(Rc::new(new_sock));
                        let _ = task.sock.connect(socket_addr);
                        match task.sock.send(&task.writebuf) {
                            Ok(_) => { task.status = Status::Reading; WriteResult::Ok }
                            Err(_) => { task.status = Status::Completed; WriteResult::Failed }
                        }
                    } else {
                        task.status = Status::Completed; WriteResult::Failed
                    }
                }
            }
        }
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

fn rdns_name(ip: IpAddr) -> String {
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
        ares.gethostbyname_to_server("example.com", Family::Ipv4, (), 0);
        let mut task = ares.tasks.pop().expect("a task was pushed");
        ares.config.nameservers.clear(); // server list shrank under the in-flight task
        assert!(matches!(ares.write_impl(&mut task), WriteResult::Failed));
    }
}
