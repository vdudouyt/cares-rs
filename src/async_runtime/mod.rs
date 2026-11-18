//! Protocol-agnostic async IO runtime in the shape of smol: socket traits, the
//! per-channel reactor (`Async` sockets, `Timer`s), and the executor — driven by
//! the host's event loop instead of by a blocking runtime thread.
//!
//! The host owns the loop, exactly as a c-ares application owns the loop around
//! [`ares_fds`]/[`ares_timeout`]/[`ares_process`]:
//!
//! 1. Ask [`Reactor::interests`](crate::async_runtime::reactor::Reactor::interests) which
//!    `(fd, writable)` pairs are being waited on and
//!    [`Reactor::next_deadline`](crate::async_runtime::reactor::Reactor::next_deadline) for the next
//!    timer.
//! 2. Block in `poll`/`epoll`/`select`/`io_uring` until one fires.
//! 3. Hand the result to
//!    [`Reactor::dispatch`](crate::async_runtime::reactor::Reactor::dispatch), then poll the woken
//!    tasks with [`Executor::pop_ready`](crate::async_runtime::executor::Executor::pop_ready) and
//!    [`Executor::poll`](crate::async_runtime::executor::Executor::poll).
//!
//! Nothing here creates threads, installs signal handlers, or owns a global
//! reactor. All state hangs off the [`Runtime`](crate::async_runtime::reactor::Runtime) handle
//! (reactor + socket factory + detached-task queue), so several independent
//! applications, or one per channel, can coexist in a process.
//!
//! ```text
//!   application loop                  runtime
//!   ----------------                  -------
//!   interests()/next_deadline()  -->  Ready + Timer registrations
//!   poll(2), epoll_wait(2), ...       (no syscalls here)
//!   dispatch(now, ready)         -->  wake the matching futures
//!   pop_ready()/poll(id)         -->  run woken tasks
//! ```
//!
//! See `ASYNC_RUNTIME.md` for the full guide and `examples/tcp_hello.rs` for a
//! complete TCP client built on this module.
//!
//! [`ares_fds`]: crate::ares_fds
//! [`ares_timeout`]: crate::ares_timeout
//! [`ares_process`]: crate::ares_process
#![forbid(unsafe_code)]

pub mod socket;
pub mod executor;
pub mod io;
pub mod reactor;

pub use executor::Executor;
pub use io::Async;
pub use reactor::{Reactor, Ready, Runtime, Timer};
pub use socket::{Socket, SocketFactory};
