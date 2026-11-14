//! Readiness backends for the event thread (upstream `ares_event_poll.c` /
//! `ares_event_epoll.c` + `ares_event_wake_pipe.c`), written on `rustix`'s safe
//! syscall wrappers. The only `unsafe` is borrowing the raw fds the C side owns.
//!
//! A backend turns the reactor's interests — `(fd, wants_write, generation)` —
//! into "these fds are ready", level-triggered like upstream:
//! - **poll** rebuilds its `pollfd` array each wait (stateless);
//! - **epoll** keeps a persistent interest set and applies only the *changes*
//!   between waits. The generation (a reactor-unique id per registration) is
//!   what notices a closed fd number reused by a new socket: the kernel dropped
//!   the old registration with the close, so it has to be added afresh.
//!
//! `ARES_EVSYS_SELECT` maps to poll (same semantics, no `FD_SETSIZE` ceiling);
//! `KQUEUE`/`WIN32` don't exist on this platform and are rejected up front.

use super::*;
use crate::ffi::ares_socket::{ares_fd_events_t, ARES_FD_EVENT_READ, ARES_FD_EVENT_WRITE};
use rustix::buffer::spare_capacity;
use rustix::event::{epoll, poll, PollFd, PollFlags};
use rustix::fd::{BorrowedFd, OwnedFd, RawFd};
use rustix::io::Errno;
use rustix::pipe::{pipe_with, PipeFlags};
use std::collections::HashMap;

/// Whether `evsys` names a backend available here (upstream: otherwise `ARES_ENOTIMP`).
pub(crate) fn supported(evsys: c_int) -> bool {
    matches!(evsys, ARES_EVSYS_DEFAULT | ARES_EVSYS_EPOLL | ARES_EVSYS_POLL | ARES_EVSYS_SELECT)
}

/// Borrow a raw fd for one syscall.
fn borrow<'a>(fd: RawFd) -> BorrowedFd<'a> {
    // SAFETY: only ever handed straight to a syscall by value. A fd the owner
    // closed concurrently yields EBADF/POLLNVAL (handled as an error event),
    // never memory unsafety. Callers filter out negative fds first.
    unsafe { BorrowedFd::borrow_raw(fd) }
}

fn timespec(timeout_ms: i32) -> rustix::event::Timespec {
    let ms = timeout_ms.max(0) as i64;
    rustix::event::Timespec { tv_sec: ms / 1000, tv_nsec: ((ms % 1000) * 1_000_000) as _ }
}

/// Event-thread self-pipe; `wake` is nonblocking (a full pipe means the thread is already runnable).
pub(crate) struct WakePipe {
    read: OwnedFd,
    write: OwnedFd,
}

impl WakePipe {
    pub(crate) fn new() -> Option<Self> {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).ok()?;
        Some(WakePipe { read, write })
    }

    pub(crate) fn read_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.read.as_raw_fd()
    }

    pub(crate) fn wake(&self) {
        // EAGAIN (pipe full) and EINTR are benign: the thread is already awake.
        let _ = rustix::io::write(&self.write, &[1u8]);
    }

    pub(crate) fn drain(&self) {
        let mut buf = [0u8; 64];
        while matches!(rustix::io::read(&self.read, &mut buf[..]), Ok(n) if n > 0) {}
    }
}

/// The readiness backend an event thread waits with.
pub(crate) enum Backend {
    Poll,
    Epoll(EpollSet),
}

/// What one wait produced: ready fds, and whether the wake pipe fired.
pub(crate) struct Ready {
    pub(crate) events: Vec<ares_fd_events_t>,
    pub(crate) woke: bool,
}

impl Backend {
    /// The backend for a validated `evsys`; epoll falls back to poll if the
    /// kernel refuses an epoll instance (e.g. fd exhaustion).
    pub(crate) fn new(evsys: c_int) -> Backend {
        match evsys {
            ARES_EVSYS_DEFAULT | ARES_EVSYS_EPOLL => match EpollSet::new() {
                Some(set) => Backend::Epoll(set),
                None => Backend::Poll,
            },
            _ => Backend::Poll,
        }
    }

    /// Wait up to `timeout_ms` for any of `waits` (or the wake pipe) to be
    /// ready. Errors and timeouts just mean "nothing ready": the caller still
    /// runs its timers.
    pub(crate) fn wait(&mut self, wake: &WakePipe, waits: &[(i32, bool, u64)], timeout_ms: i32) -> Ready {
        match self {
            Backend::Poll => wait_poll(wake, waits, timeout_ms),
            Backend::Epoll(set) => set.wait(wake, waits, timeout_ms),
        }
    }
}

/// Fold per-direction interests into one `(want_read, want_write)` per fd.
fn fold(waits: &[(i32, bool, u64)]) -> HashMap<RawFd, (bool, bool, u64)> {
    let mut out: HashMap<RawFd, (bool, bool, u64)> = HashMap::with_capacity(waits.len());
    for &(fd, wants_write, generation) in waits.iter().filter(|w| w.0 >= 0) {
        let entry = out.entry(fd).or_insert((false, false, generation));
        if wants_write {
            entry.1 = true;
        } else {
            entry.0 = true;
        }
    }
    out
}

fn fd_event(fd: RawFd, read: bool, write: bool) -> ares_fd_events_t {
    let mut flags = 0;
    if read {
        flags |= ARES_FD_EVENT_READ;
    }
    if write {
        flags |= ARES_FD_EVENT_WRITE;
    }
    ares_fd_events_t { fd, events: flags }
}

fn wait_poll(wake: &WakePipe, waits: &[(i32, bool, u64)], timeout_ms: i32) -> Ready {
    let wanted = fold(waits);
    let wake_fd = wake.read_fd();
    let borrowed: Vec<(RawFd, BorrowedFd<'_>, PollFlags)> = std::iter::once((wake_fd, borrow(wake_fd), PollFlags::IN))
        .chain(wanted.iter().map(|(&fd, &(r, w, _))| {
            // Same rule as the interest model: a write waiter waits for OUT, otherwise IN.
            let mut flags = PollFlags::empty();
            if r {
                flags |= PollFlags::IN;
            }
            if w {
                flags |= PollFlags::OUT;
            }
            (fd, borrow(fd), flags)
        }))
        .collect();
    let mut pollfds: Vec<PollFd<'_>> = borrowed.iter().map(|(_, b, flags)| PollFd::new(b, *flags)).collect();
    let ts = timespec(timeout_ms);
    let _ = poll(&mut pollfds, Some(&ts));

    let mut ready = Ready { events: Vec::new(), woke: false };
    for ((fd, _, _), p) in borrowed.iter().zip(&pollfds) {
        let revents = p.revents();
        if revents.is_empty() {
            continue;
        }
        if *fd == wake_fd {
            ready.woke = true;
            continue;
        }
        // Errors/hangups wake both interests so a failed connect and a dead
        // read socket are driven without waiting for the timeout arm.
        let broken = revents.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL);
        ready.events.push(fd_event(*fd, broken || revents.contains(PollFlags::IN), broken || revents.contains(PollFlags::OUT)));
    }
    ready
}

/// What the epoll instance currently holds for one fd.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Registered {
    read: bool,
    write: bool,
    generation: u64,
}

pub(crate) struct EpollSet {
    epfd: OwnedFd,
    registered: HashMap<RawFd, Registered>,
    wake_registered: Option<RawFd>,
    buf: Vec<epoll::Event>,
}

fn epoll_flags(read: bool, write: bool) -> epoll::EventFlags {
    let mut flags = epoll::EventFlags::empty();
    if read {
        flags |= epoll::EventFlags::IN;
    }
    if write {
        flags |= epoll::EventFlags::OUT;
    }
    flags
}

impl EpollSet {
    fn new() -> Option<Self> {
        let epfd = epoll::create(epoll::CreateFlags::CLOEXEC).ok()?;
        Some(EpollSet { epfd, registered: HashMap::new(), wake_registered: None, buf: Vec::with_capacity(64) })
    }

    /// Bring the kernel's interest list in line with `wanted`. Returns the
    /// fds epoll cannot watch, as already-ready events — what `poll` reports
    /// for regular files (always ready) and closed fds (`POLLNVAL`).
    fn sync(&mut self, wanted: &HashMap<RawFd, (bool, bool, u64)>) -> Vec<ares_fd_events_t> {
        let epfd = &self.epfd;
        self.registered.retain(|&fd, _| {
            let keep = wanted.contains_key(&fd);
            if !keep {
                // The fd may already be closed (the kernel dropped it): ignore errors.
                let _ = epoll::delete(epfd, borrow(fd));
            }
            keep
        });

        let mut unwatchable = Vec::new();
        for (&fd, &(read, write, generation)) in wanted {
            let want = Registered { read, write, generation };
            let have = self.registered.get(&fd).copied();
            if have == Some(want) {
                continue;
            }
            let data = epoll::EventData::new_u64(fd as u64);
            let flags = epoll_flags(read, write);
            let b = borrow(fd);
            let result = match have {
                // Same registration, new interest.
                Some(old) if old.generation == generation => {
                    epoll::modify(epfd, b, data, flags).or_else(|e| if e == Errno::NOENT { epoll::add(epfd, b, data, flags) } else { Err(e) })
                }
                // A recycled fd number: whatever the kernel holds is stale.
                Some(_) => {
                    let _ = epoll::delete(epfd, b);
                    epoll::add(epfd, b, data, flags)
                }
                None => epoll::add(epfd, b, data, flags).or_else(|e| if e == Errno::EXIST { epoll::modify(epfd, b, data, flags) } else { Err(e) }),
            };
            match result {
                Ok(()) => {
                    self.registered.insert(fd, want);
                }
                Err(Errno::PERM) => {
                    // Not pollable (regular file): always ready, like poll(2).
                    self.registered.remove(&fd);
                    unwatchable.push(fd_event(fd, read, write));
                }
                Err(_) => {
                    // EBADF and friends: surface it so the owner sees the error.
                    self.registered.remove(&fd);
                    unwatchable.push(fd_event(fd, true, true));
                }
            }
        }
        unwatchable
    }

    fn wait(&mut self, wake: &WakePipe, waits: &[(i32, bool, u64)], timeout_ms: i32) -> Ready {
        let wake_fd = wake.read_fd();
        if self.wake_registered != Some(wake_fd) {
            let data = epoll::EventData::new_u64(wake_fd as u64);
            if epoll::add(&self.epfd, borrow(wake_fd), data, epoll::EventFlags::IN).is_ok() {
                self.wake_registered = Some(wake_fd);
            }
        }

        let wanted = fold(waits);
        let mut ready = Ready { events: self.sync(&wanted), woke: false };
        // Fds epoll can't watch are ready now: don't sleep.
        let timeout_ms = if ready.events.is_empty() { timeout_ms } else { 0 };
        let ts = timespec(timeout_ms);

        self.buf.clear();
        let _ = epoll::wait(&self.epfd, spare_capacity(&mut self.buf), Some(&ts));
        for ev in &self.buf {
            // `Event` is packed on x86-64: copy the fields out, never borrow them.
            let (flags, data) = (ev.flags, ev.data);
            let fd = data.u64() as RawFd;
            if fd == wake_fd {
                ready.woke = true;
                continue;
            }
            let broken = flags.intersects(epoll::EventFlags::ERR | epoll::EventFlags::HUP);
            ready.events.push(fd_event(fd, broken || flags.contains(epoll::EventFlags::IN), broken || flags.contains(epoll::EventFlags::OUT)));
        }
        ready
    }
}
