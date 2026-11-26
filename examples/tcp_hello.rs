//! A tiny TCP client on top of the cares-rs async runtime.
//!
//! The client connects, sends a name, and prints the server's
//! `Hello, <name>!` reply. The runtime does **not** own a loop, threads, or a
//! `block_on`: this file plays the part that `ares_process()` plays for the C
//! API — it polls the fd interests the runtime publishes and hands readiness
//! back with `Runtime::process`.
//!
//! Run a demo server and client in two terminals:
//!
//! ```text
//! cargo run --example tcp_hello -- server 127.0.0.1:7878
//! cargo run --example tcp_hello -- client 127.0.0.1:7878 Alice
//! ```
//!
//! The server half deliberately uses plain blocking `std::net`; only the
//! client demonstrates the runtime.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::rc::Rc;
use std::time::{Duration, Instant};

use cares::async_runtime::{dead, Runtime};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REPLY: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// The client task
// ---------------------------------------------------------------------------

type Reply = Rc<RefCell<Option<io::Result<String>>>>;

async fn client_task(runtime: &Runtime, server: SocketAddr, name: String) -> io::Result<String> {
    let sock = runtime
        .connect_tcp(server, Instant::now() + CONNECT_TIMEOUT)
        .await?;

    // Application framing: one newline-terminated request.
    let request = format!("{name}\n");
    sock.write_all(request.as_bytes(), Instant::now() + IO_TIMEOUT).await?;

    // Read until the newline-terminated reply arrives.
    let mut reply = Vec::new();
    let mut chunk = [0u8; 4096];
    let reply_deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let n = sock.read(&mut chunk, reply_deadline).await?;
        if n == 0 {
            return Err(dead());
        }
        reply.extend_from_slice(&chunk[..n]);

        if let Some(end) = reply.iter().position(|&b| b == b'\n') {
            reply.truncate(end);
            return String::from_utf8(reply)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "server sent non-UTF-8"));
        }
        if reply.len() > MAX_REPLY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reply too long"));
        }
    }
}

// ---------------------------------------------------------------------------
// The external loop: this is the ares_process() half
// ---------------------------------------------------------------------------

/// One turn of the application's loop.
fn drive(runtime: &Runtime, done: &Cell<bool>) -> io::Result<()> {
    while !done.get() {
        // 1. What does the runtime want to be told about?
        let mut interests: Vec<(i32, bool)> = runtime.interests();
        interests.sort_unstable();

        // 2. How long may we sleep?
        let timeout_ms = runtime.timeout(Instant::now())
            .map_or(-1, |left| left.as_millis().min(i32::MAX as u128) as i32);
        if interests.is_empty() && timeout_ms < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Deadlock,
                "all tasks are parked but the runtime has no fd or timer interest",
            ));
        }

        // 3. Wait. A real application would use epoll/kqueue/io_uring here;
        //    poll(2) keeps the example to one syscall.
        let mut pollfds = poll_fds(&interests);
        let n = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        // 4. Hand readiness back. Errors and hangups wake both directions so
        //    the pending future observes EOF or gets a hard send error.
        let mut ready: Vec<(i32, bool)> = Vec::new();
        for pfd in &pollfds {
            let error = pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL);
            if error != 0 || pfd.revents & libc::POLLIN != 0 {
                ready.push((pfd.fd, false));
            }
            if error != 0 || pfd.revents & libc::POLLOUT != 0 {
                ready.push((pfd.fd, true));
            }
        }
        runtime.process(Instant::now(), |fd, writable| {
            ready.contains(&(fd, writable))
        });
    }
    Ok(())
}

fn poll_fds(interests: &[(i32, bool)]) -> Vec<libc::pollfd> {
    let mut by_fd: HashMap<i32, libc::pollfd> = HashMap::new();
    for &(fd, writable) in interests {
        let entry = by_fd.entry(fd).or_insert(libc::pollfd {
            fd,
            events: 0,
            revents: 0,
        });
        entry.events |= if writable { libc::POLLOUT } else { libc::POLLIN };
    }
    by_fd.into_values().collect()
}

fn run_client(server: SocketAddr, name: &str) -> io::Result<()> {
    let runtime = Runtime::new();
    let done = Rc::new(Cell::new(false));
    let reply: Reply = Rc::new(RefCell::new(None));

    let task_runtime = runtime.handle();
    let task_done = done.clone();
    let task_reply = reply.clone();
    let task_name = name.to_owned();
    runtime.spawn(
        async move {
            let result = client_task(&task_runtime, server, task_name).await;
            *task_reply.borrow_mut() = Some(result);
            task_done.set(true);
        },
        |_| {},
    ).map_err(io::Error::other)?;
    runtime.run_ready();

    drive(&runtime, &done)?;

    let result = match reply.borrow_mut().take() {
        Some(Ok(message)) => {
            println!("{message}");
            Ok(())
        }
        Some(Err(err)) => Err(err),
        None => Err(io::Error::other("client task produced no result")),
    };
    result
}

// ---------------------------------------------------------------------------
// Blocking demo server (standard library only)
// ---------------------------------------------------------------------------

fn run_server(addr: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("listening on {}", listener.local_addr()?);
    let (stream, peer) = listener.accept()?;
    println!("accepted {peer}");

    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let name = line.trim_end_matches(['\r', '\n']);
    writeln!(writer, "Hello, {name}!")?;
    writer.flush()
}

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "client".to_owned());
    let addr: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:7878".to_owned())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let name = args.next().unwrap_or_else(|| "Alice".to_owned());

    match mode.as_str() {
        "server" => run_server(addr),
        "client" => run_client(addr, &name),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: tcp_hello [server|client] [addr] [name]",
        )),
    }
}
