use std::net::{ UdpSocket, SocketAddr };
use bytes::BytesMut;
use std::io::Cursor;
use rand::Rng;
use std::time::{ Instant, Duration };

use crate::core::sysconfig::SysConfig;
use crate::core::packets::*;

/* TODO: reconcile ChannelData here */
pub struct Ares<T> {
    pub config: SysConfig,
    pub tasks: Vec<Task<T>>,
    pub default_udp_port: u16,
    pub default_tcp_port: u16,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Family { Ipv4, Ipv6 }

impl<T> Ares<T> {
    pub fn new(config: SysConfig) -> Self {
        Ares { config, tasks: vec![], default_udp_port: 53, default_tcp_port: 53 }
    }
    pub fn from_sysconfig() -> Self {
        Ares::new(build_sysconfig())
    }
    pub fn gethostbyname(&mut self, hostname: &str, family: Family, userdata: T) -> &Task<T> {
        let qtype = match family {
            Family::Ipv4 => 0x01, // A
            Family::Ipv6 => 0x1c, // AAAA
        };
        let sock = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let _ = sock.set_nonblocking(true);
        let query = DnsQuery {
            name: hostname.split(".").map(str::to_owned).collect(),
            qtype,
            qclass: 1,
        };
        let request = DnsFrame {
            transaction_id: rand::thread_rng().r#gen::<u16>(),
            flags: 0x100,
            queries: vec![query],
            answers: vec![],
        };
        let expires_at = Instant::now() + Duration::new(1, 0) * self.config.options.timeout_secs;
        let mut task = Task { status: Status::Writing, sock, writebuf: BytesMut::new(), userdata, expires_at };
        request.write(&mut task.writebuf);
        self.tasks.push(task);
        self.tasks.last().unwrap()
    }
    pub fn query(&mut self, name: &str, dnsclass: u16, dnstype: u16, userdata: T) {
        let sock = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let _ = sock.set_nonblocking(true);
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
        let mut task = Task { status: Status::Writing, sock, writebuf: BytesMut::new(), userdata, expires_at };
        request.write(&mut task.writebuf);
        self.tasks.push(task);
    }
    pub fn write_impl(&mut self, task: &mut Task<T>) {
        let ns_addr = self.config.nameservers.first().unwrap();
        let socket_addr = SocketAddr::from((ns_addr.0, ns_addr.1.unwrap_or(self.default_udp_port)));
        let _len = task.sock.send_to(&task.writebuf, socket_addr).unwrap();
        task.status = Status::Reading;
    }
    pub fn read_impl(&mut self, task: &mut Task<T>) -> Option<(Vec<u8>, DnsFrame)> {
        let mut buf = vec![0u8; 65_535];
        let (len, _src) = task.sock.recv_from(&mut buf).unwrap();
        task.status = Status::Completed;

        let frame = DnsFrame::parse(&mut Cursor::new(&buf[0..len]))?;
        Some((buf, frame))
    }
    pub fn max_wait_time(&self) -> Duration {
        self.tasks.iter().map(Task::time_remaining).min().unwrap()
    }
    pub fn remove_completed(&mut self) {
        self.tasks.retain(|task| !task.is_expired());
    }
}

#[derive(PartialEq)]
pub enum Status { Writing, Reading, Completed }

pub struct Task<T> {
    pub status: Status,
    pub sock: UdpSocket,
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
