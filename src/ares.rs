use std::net::UdpSocket;
use bytes::BytesMut;
use std::io::Cursor;
use rand::Rng;

use crate::sysconfig::SysConfig;
use crate::packets::*;

/* TODO: reconcile ChannelData here */
pub struct Ares<T> {
    pub config: SysConfig,
    pub tasks: Vec<Task<T>>,
}

impl<T> Ares<T> {
    pub fn new(config: SysConfig) -> Self {
        Ares { config, tasks: vec![] }
    }
    pub fn from_sysconfig() -> Self {
        Ares::new(build_sysconfig())
    }
    pub fn gethostbyname(&mut self, hostname: &str, userdata: T) {
        let sock = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        let _ = sock.set_nonblocking(true);
        let query = DnsQuery {
            name: hostname.split(".").map(str::to_owned).collect(),
            qtype: 1,
            qclass: 1,
        };
        let request = DnsFrame {
            transaction_id: rand::thread_rng().r#gen::<u16>(),
            queries: vec![query],
            answers: vec![],
        };
        let mut task = Task { status: Status::Writing, sock, writebuf: BytesMut::new(), userdata };
        request.write(&mut task.writebuf);
        self.tasks.push(task);
    }
    pub fn write_impl(&mut self, task: &mut Task<T>) {
        let _len = task.sock.send_to(&task.writebuf, ("127.0.0.1", 53)).unwrap();
        task.status = Status::Reading;
    }
    pub fn read_impl(&mut self, task: &mut Task<T>) -> Option<(Vec<u8>, DnsFrame)> {
        let mut buf = vec![0u8; 65_535];
        let (len, _src) = task.sock.recv_from(&mut buf).unwrap();
        task.status = Status::Completed;

        let frame = DnsFrame::parse(&mut Cursor::new(&buf[0..len]))?;
        Some((buf, frame))
    }
}

#[derive(PartialEq)]
pub enum Status { Writing, Reading, Completed }

pub struct Task<T> {
    pub status: Status,
    pub sock: UdpSocket,
    pub writebuf: BytesMut,
    pub userdata: T,
}

pub fn build_sysconfig() -> SysConfig {
    let try_resolv_conf = || std::fs::read_to_string("/etc/resolv.conf").ok()?.parse::<SysConfig>().ok();
    try_resolv_conf().unwrap_or_else(SysConfig::default)
}
