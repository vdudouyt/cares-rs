//! A single-threaded async I/O runtime driven by the host's event loop.
//!
//! [`Runtime`](crate::async_runtime::Runtime) owns tasks, socket registrations, and timers. Spawning schedules
//! a task automatically; the host only needs to drive the runtime:
//!
//! 1. Call [`Runtime::run_ready`](crate::async_runtime::Runtime::run_ready) to start queued tasks before the first wait.
//! 2. Read [`Runtime::interests`](crate::async_runtime::Runtime::interests) and
//!    [`Runtime::timeout`](crate::async_runtime::Runtime::timeout), then wait in the
//!    host's `poll`/`epoll`/`select` loop.
//! 3. Call [`Runtime::process`](crate::async_runtime::Runtime::process) with the reported readiness, then repeat.
//!
//! A zero timeout means tasks are runnable even if no descriptors are watched.
//! No threads, signal handlers, or global runtime state are created.
//!
//! The runtime created by `new` or `default` owns its tasks. Pass
//! [`Runtime::handle`](crate::async_runtime::Runtime::handle) into tasks for shared access without ownership cycles.
//! Handles expose the same API and keep weak task references internally.
//!
//! See `ASYNC_RUNTIME.md` for the runtime API and `examples/example.c` for the
//! C-facing `ares_*` select loop. The C API performs initial driving internally.
#![forbid(unsafe_code)]

pub mod socket;
mod executor;
mod io;
mod reactor;
mod runtime;
mod system;

pub use io::{dead, AsyncSocket};
pub use reactor::{InterestChanges, InterestUpdate, Ready, Timer};
pub use runtime::{Runtime, RuntimeClosed};
pub use socket::{Socket, SocketFactory, SocketKind};
