use std::net::{ SocketAddr, IpAddr, Ipv4Addr };
use bytes::{ BytesMut, BufMut };
use rand::Rng;
use std::time::{ Instant, Duration };
use std::rc::Rc;

use crate::core::sysconfig::SysConfig;
use crate::core::hostfile::Hosts;
use crate::core::services::Services;
use crate::core::packets::*;
use crate::ffi::SocketFactory;
use crate::ffi::{ ares_socket, RECORD_TYPE_PTR };

const BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/* TODO: reconcile ChannelData here */
pub struct Ares<T> {
    pub config: SysConfig,
    pub socket_factory: Rc<SocketFactory>,
    pub tasks: Vec<Task<T>>,
    pub hosts: Hosts,
    pub services: Services,
    pub default_udp_port: u16,
    pub default_tcp_port: u16,
    readbuf: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Family { Ipv4, Ipv6 }

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

impl<T> Ares<T> {
    pub fn new(config: SysConfig) -> Self {
        Ares {
            config,
            socket_factory: Rc::new(SocketFactory::default()),
            tasks: vec![],
            hosts: Hosts::from_path("/etc/hosts").unwrap(),
            services: Services::default(),
            default_udp_port: 53,
            default_tcp_port: 53,
            readbuf: vec![0u8; 65_535],
        }
    }
    pub fn from_sysconfig() -> Self {
        Ares::new(build_sysconfig())
    }
    pub fn gethostbyname(&mut self, hostname: &str, family: Family, userdata: T) -> &Task<T> {
        let qtype = match family {
            Family::Ipv4 => 0x01, // A
            Family::Ipv6 => 0x1c, // AAAA
        };
        let sock = self.socket_factory.create_udp(BIND_ADDR).unwrap();
        let transaction_id = rand::thread_rng().r#gen::<u16>();
        let expires_at = Instant::now() + Duration::new(1, 0) * self.config.options.timeout_secs;
        let mut writebuf = BytesMut::with_capacity(12 + hostname.len() + 2 + 4);
        write_dns_query_direct(&mut writebuf, hostname, qtype, transaction_id);
        let task = Task { status: Status::Writing, sock, writebuf, userdata, expires_at };
        self.tasks.push(task);
        self.tasks.last().unwrap()
    }
    pub fn gethostbyaddr(&mut self, addr: IpAddr, userdata: T) -> &Task<T> {
        let rhostname = rdns_name(addr);
        let sock = self.socket_factory.create_udp(BIND_ADDR).unwrap();
        let transaction_id = rand::thread_rng().r#gen::<u16>();
        let expires_at = Instant::now() + Duration::new(1, 0) * self.config.options.timeout_secs;
        let mut writebuf = BytesMut::with_capacity(12 + rhostname.len() + 2 + 4);
        write_dns_query_direct(&mut writebuf, &rhostname, RECORD_TYPE_PTR, transaction_id);
        let task = Task { status: Status::Writing, sock, writebuf, userdata, expires_at };
        self.tasks.push(task);
        self.tasks.last().unwrap()
    }
    pub fn query(&mut self, name: &str, dnsclass: u16, dnstype: u16, userdata: T) {
        let sock = self.socket_factory.create_udp(BIND_ADDR).unwrap();
        let query = DnsQuery {
            name: name.split(".").map(str::to_owned).collect(),
            qtype: dnstype,
            qclass: dnsclass,
        };
        let request = DnsFrame {
            transaction_id: rand::thread_rng().r#gen::<u16>(),
            flags: 0x100,
            queries: vec![query],
            answers: vec![],
        };
        let expires_at = Instant::now() + Duration::new(1, 0) * self.config.options.timeout_secs;
        let mut task = Task { status: Status::Writing, sock, writebuf: BytesMut::with_capacity(12 + name.len() + 2 + 4), userdata, expires_at };
        request.write(&mut task.writebuf);
        self.tasks.push(task);
    }
    pub fn write_impl(&mut self, task: &mut Task<T>) {
        let ns_addr = self.config.nameservers.first().unwrap();
        let socket_addr = SocketAddr::from((ns_addr.0, ns_addr.1.unwrap_or(self.default_udp_port)));
        task.sock.connect(socket_addr);
        let _len = task.sock.send(&task.writebuf).unwrap();
        task.status = Status::Reading;
    }
    pub fn read_impl(&mut self, task: &mut Task<T>) -> Option<Vec<u8>> {
        let (len, _src) = task.sock.recv(&mut self.readbuf).unwrap();
        task.status = Status::Completed;
        Some(self.readbuf[..len].to_vec())
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
    pub sock: ares_socket::UdpSocket,
    pub writebuf: BytesMut,
    pub userdata: T,
    pub expires_at: Instant,
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
    try_resolv_conf().unwrap_or_else(SysConfig::default)
}
