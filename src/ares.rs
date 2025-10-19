use std::net::UdpSocket;
use std::rc::Rc;
use bytes::BytesMut;
use rand::Rng;
use std::net::ToSocketAddrs;
use std::task::{ Poll, Context };
use std::pin::Pin;
use std::io::Cursor;
use std::sync::atomic::{ AtomicBool, Ordering };
use std::rc::Weak;
use std::cell::RefCell;
use futures::task::{ noop_waker, Waker };
use futures::future::poll_fn;
use std::any::Any;

use crate::sysconfig::SysConfig;
use crate::packets::*;

/* TODO: reconcile ChannelData here */
pub struct Ares {
    pub config: SysConfig,
    pub tasks: Vec<Weak<Task>>,
    waker: Waker,
}

impl Ares {
    pub fn new(config: SysConfig) -> Ares {
        Ares { config, tasks: vec![], waker: noop_waker() }
    }
    pub fn from_sysconfig() -> Ares {
        Ares::new(build_sysconfig())
    }
    pub fn gethostbyname(&mut self, hostname: &str, userdata: Box<dyn Any>) {
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
        let mut task = Rc::new(Task { sock, status: RefCell::new(Status::Ready), fut: RefCell::new(None), userdata });
        let mut fut = Box::pin(task.clone().run(request));

        let mut ctx = Context::from_waker(&self.waker);
        fut.as_mut().poll(&mut ctx); // give a chance to set write flag

        *task.fut.borrow_mut() = Some(fut);
        self.tasks.push(Rc::downgrade(&task));
    }
    pub fn resume_task(&self, task: &Task) -> std::task::Poll<(Vec<u8>, DnsFrame)> {
        let mut guard = task.fut.borrow_mut();
        let fut = guard.as_mut().unwrap();
        task.set_status(Status::Ready);
        let mut ctx = Context::from_waker(&self.waker);
        fut.as_mut().poll(&mut ctx)
    }
}

#[derive(Debug, Clone, Copy)]
enum Status { Ready, Writing, Reading }

pub struct Task {
    pub sock: UdpSocket,
    status: RefCell<Status>,
    fut: RefCell<Option<Pin<Box<dyn Future<Output = (Vec<u8>, DnsFrame)>>>>>,
    pub userdata: Box<dyn Any>,
}

impl Task {
    async fn run(self: Rc<Self>, request: DnsFrame) -> (Vec<u8>, DnsFrame) {
        let mut writebuf = BytesMut::new();
        request.write(&mut writebuf);
        let len = self.send_to(&writebuf, ("8.8.8.8".to_owned(), 53)).await.unwrap();

        let mut readbuf = vec![0u8; 65_535];
        let (len, _sockaddr) = self.recv_from(&mut readbuf).await.unwrap();
        let mut cur = Cursor::new(&readbuf[0..len]);
        let frame = DnsFrame::parse(&mut cur).unwrap();
        readbuf.truncate(len);
        (readbuf, frame)
    }
    async fn wait_until_ready(&self) {
        poll_fn(|_| match self.status() {
            Status::Ready => Poll::Ready(()),
            _ => Poll::Pending,
        }).await;
    }
    async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> std::io::Result<usize> {
        self.set_status(Status::Writing);
        self.wait_until_ready().await;
        Ok(self.sock.send_to(buf, addr)?)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
        self.set_status(Status::Reading);
        self.wait_until_ready().await;
        Ok(self.sock.recv_from(buf)?)
    }
    pub fn is_reading(&self) -> bool {
        matches!(self.status(), Status::Reading)
    }
    pub fn is_writing(&self) -> bool {
        matches!(self.status(), Status::Writing)
    }
    fn status(&self) -> Status {
        *self.status.borrow_mut()
    }
    fn set_status(&self, status: Status) {
        *self.status.borrow_mut() = status;
    }
}

pub fn build_sysconfig() -> SysConfig {
    let try_resolv_conf = || Some(std::fs::read_to_string("/etc/resolv.conf").ok()?.parse::<SysConfig>().ok()?);
    try_resolv_conf().unwrap_or_else(|| SysConfig::default())
}
