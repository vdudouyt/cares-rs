//! Readiness backends for the event thread (upstream `ares_event_poll.c` /
//! `ares_event_epoll.c` + `ares_event_wake_pipe.c`), written on `rustix`'s safe
//! syscall wrappers. The only `unsafe` is borrowing the raw fds the C side owns.
//!
//! Like upstream's backends, both keep a persistent interest set that the event
//! thread edits with explicit changes (the reactor's change log: sources
//! dropped, sources whose interest moved) and then wait on, level-triggered:
//! - **epoll** applies each change as one `epoll_ctl` and waits in O(ready fds);
//! - **poll** edits a map and rebuilds its `pollfd` array per wait, which is
//!   O(watched fds) because `poll(2)` itself is.
//!
//! Changes carry the reactor's registration generation. It is what notices a
//! closed fd number reused by a new socket (the kernel dropped the old epoll
//! registration with the close, so the new one must be added afresh) and what
//! lets a late removal of the old socket never undo the new one.
//!
//! An fd epoll refuses (`EPERM`, a closed fd) is simply left unwatched, as
//! upstream does: its query then ends by timeout rather than the thread
//! spinning on it.
//!
//! `ARES_EVSYS_SELECT` maps to poll (same semantics, no `FD_SETSIZE` ceiling);
//! `KQUEUE`/`WIN32` don't exist on this platform and are rejected up front.

use super::*;
use crate::async_runtime::reactor::{InterestChanges, InterestUpdate};
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

/// What a backend currently holds for one fd.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Registered {
    read: bool,
    write: bool,
    generation: u64,
}

/// What to do to the kernel/registry for one interest update.
enum Step {
    Keep,
    Insert,
    Update,
    /// A recycled fd number: the old registration is stale.
    Replace,
    Remove,
}

fn plan(have: Option<Registered>, update: &InterestUpdate) -> Step {
    let wants = update.read || update.write;
    match have {
        None if wants => Step::Insert,
        None => Step::Keep,
        Some(h) if h.generation == update.generation => {
            if !wants {
                Step::Remove
            } else if (h.read, h.write) == (update.read, update.write) {
                Step::Keep
            } else {
                Step::Update
            }
        }
        Some(h) if h.generation < update.generation && wants => Step::Replace,
        // A newer registration already owns this fd number: this one is stale.
        Some(_) => Step::Keep,
    }
}

fn is_current(registry: &HashMap<RawFd, Registered>, fd: RawFd, generation: u64) -> bool {
    registry.get(&fd).is_some_and(|r| r.generation == generation)
}

/// The readiness backend an event thread waits with.
pub(crate) enum Backend {
    Poll(HashMap<RawFd, Registered>),
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
                None => Backend::Poll(HashMap::new()),
            },
            _ => Backend::Poll(HashMap::new()),
        }
    }

    /// Edit the interest set: O(changes).
    pub(crate) fn apply(&mut self, changes: InterestChanges) {
        match self {
            Backend::Poll(registry) => apply_to_registry(registry, &changes),
            Backend::Epoll(set) => set.apply(&changes),
        }
    }

    /// Wait up to `timeout_ms` for a watched fd (or the wake pipe) to be ready.
    /// Errors and timeouts just mean "nothing ready": the caller still runs
    /// its timers.
    pub(crate) fn wait(&mut self, wake: &WakePipe, timeout_ms: i32) -> Ready {
        match self {
            Backend::Poll(registry) => wait_poll(registry, wake, timeout_ms),
            Backend::Epoll(set) => set.wait(wake, timeout_ms),
        }
    }
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

fn apply_to_registry(registry: &mut HashMap<RawFd, Registered>, changes: &InterestChanges) {
    for &(fd, generation) in &changes.removed {
        if is_current(registry, fd, generation) {
            registry.remove(&fd);
        }
    }
    for u in changes.updates.iter().filter(|u| u.fd >= 0) {
        let want = Registered { read: u.read, write: u.write, generation: u.generation };
        match plan(registry.get(&u.fd).copied(), u) {
            Step::Keep => {}
            Step::Insert | Step::Update | Step::Replace => {
                registry.insert(u.fd, want);
            }
            Step::Remove => {
                registry.remove(&u.fd);
            }
        }
    }
}

fn wait_poll(registry: &HashMap<RawFd, Registered>, wake: &WakePipe, timeout_ms: i32) -> Ready {
    let wake_fd = wake.read_fd();
    let borrowed: Vec<(RawFd, BorrowedFd<'_>, PollFlags)> = std::iter::once((wake_fd, borrow(wake_fd), PollFlags::IN))
        .chain(registry.iter().map(|(&fd, r)| {
            let mut flags = PollFlags::empty();
            if r.read {
                flags |= PollFlags::IN;
            }
            if r.write {
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

    /// One `epoll_ctl` per change. An fd the kernel refuses stays unwatched.
    fn apply(&mut self, changes: &InterestChanges) {
        let epfd = &self.epfd;
        for &(fd, generation) in &changes.removed {
            if is_current(&self.registered, fd, generation) {
                // The fd may already be closed (the kernel dropped it): ignore errors.
                let _ = epoll::delete(epfd, borrow(fd));
                self.registered.remove(&fd);
            }
        }
        for u in changes.updates.iter().filter(|u| u.fd >= 0) {
            let want = Registered { read: u.read, write: u.write, generation: u.generation };
            let data = epoll::EventData::new_u64(u.fd as u64);
            let flags = epoll_flags(u.read, u.write);
            let b = borrow(u.fd);
            let result = match plan(self.registered.get(&u.fd).copied(), u) {
                Step::Keep => continue,
                Step::Remove => {
                    let _ = epoll::delete(epfd, b);
                    self.registered.remove(&u.fd);
                    continue;
                }
                Step::Update => epoll::modify(epfd, b, data, flags).or_else(|e| if e == Errno::NOENT { epoll::add(epfd, b, data, flags) } else { Err(e) }),
                Step::Replace => {
                    let _ = epoll::delete(epfd, b);
                    epoll::add(epfd, b, data, flags)
                }
                Step::Insert => epoll::add(epfd, b, data, flags).or_else(|e| if e == Errno::EXIST { epoll::modify(epfd, b, data, flags) } else { Err(e) }),
            };
            match result {
                Ok(()) => {
                    self.registered.insert(u.fd, want);
                }
                Err(_) => {
                    self.registered.remove(&u.fd);
                }
            }
        }
    }

    fn wait(&mut self, wake: &WakePipe, timeout_ms: i32) -> Ready {
        let wake_fd = wake.read_fd();
        if self.wake_registered != Some(wake_fd) {
            let data = epoll::EventData::new_u64(wake_fd as u64);
            if epoll::add(&self.epfd, borrow(wake_fd), data, epoll::EventFlags::IN).is_ok() {
                self.wake_registered = Some(wake_fd);
            }
        }
        let ts = timespec(timeout_ms);
        let mut ready = Ready { events: Vec::new(), woke: false };

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    fn upd(fd: i32, generation: u64, read: bool, write: bool) -> InterestUpdate {
        InterestUpdate { fd, generation, read, write }
    }

    fn changes(updates: Vec<InterestUpdate>, removed: Vec<(i32, u64)>) -> InterestChanges {
        InterestChanges { removed, updates }
    }

    /// A UDP socket with one datagram already queued, so it is readable.
    fn readable_socket() -> UdpSocket {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(b"x", sock.local_addr().unwrap()).unwrap();
        sock
    }

    fn ready(backend: &mut Backend, wake: &WakePipe, ms: i32) -> Vec<i32> {
        let mut fds: Vec<i32> = backend.wait(wake, ms).events.iter().map(|e| e.fd).collect();
        fds.sort_unstable();
        fds
    }

    /// The kernel drops an epoll registration when its fd closes. If the number is
    /// recycled by a new socket, only the registration generation tells us to
    /// register it again — otherwise the new socket's events are never seen.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn recycled_fd_number_is_reregistered() {
        let wake = WakePipe::new().unwrap();
        let mut backend = Backend::new(ARES_EVSYS_EPOLL);
        assert!(matches!(backend, Backend::Epoll(_)));
        let mut reused = 0;
        for round in 1..=500u64 {
            let first = readable_socket();
            let fd = first.as_raw_fd();
            backend.apply(changes(vec![upd(fd, round * 2, true, false)], vec![]));
            assert_eq!(ready(&mut backend, &wake, 200), vec![fd]);
            drop(first); // closes fd; the kernel forgets the registration

            let second = readable_socket();
            if second.as_raw_fd() != fd {
                continue;
            }
            reused += 1;
            // The same number, registered again by a new source: a new generation,
            // and (as when the removal is still queued) no removal for the old one.
            backend.apply(changes(vec![upd(fd, round * 2 + 1, true, false)], vec![]));
            assert_eq!(ready(&mut backend, &wake, 200), vec![fd], "round {round}: recycled fd {fd} was not re-registered");
        }
        assert!(reused > 50, "fd numbers were not recycled ({reused}/500)");
    }

    /// The old source's removal arriving after the new source registered the same
    /// number must not unregister the new one.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn late_removal_of_old_generation_keeps_new_registration() {
        for evsys in [ARES_EVSYS_EPOLL, ARES_EVSYS_POLL] {
            let wake = WakePipe::new().unwrap();
            let mut backend = Backend::new(evsys);
            let sock = readable_socket();
            let fd = sock.as_raw_fd();
            backend.apply(changes(vec![upd(fd, 5, true, false)], vec![(fd, 4)]));
            assert_eq!(ready(&mut backend, &wake, 200), vec![fd], "evsys {evsys}");
        }
    }

    /// Interest edits and removal reach the kernel: read→write, then dropped.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn modify_and_remove_take_effect() {
        for evsys in [ARES_EVSYS_EPOLL, ARES_EVSYS_POLL] {
            let wake = WakePipe::new().unwrap();
            let mut backend = Backend::new(evsys);
            let idle = UdpSocket::bind("127.0.0.1:0").unwrap(); // nothing to read, always writable
            let fd = idle.as_raw_fd();
            backend.apply(changes(vec![upd(fd, 1, true, false)], vec![]));
            assert!(ready(&mut backend, &wake, 50).is_empty(), "evsys {evsys}: not readable yet");
            backend.apply(changes(vec![upd(fd, 1, false, true)], vec![]));
            assert_eq!(ready(&mut backend, &wake, 200), vec![fd], "evsys {evsys}: write interest");
            backend.apply(changes(vec![], vec![(fd, 1)]));
            assert!(ready(&mut backend, &wake, 50).is_empty(), "evsys {evsys}: removed");
            // `read == write == false` also means "watch nothing".
            backend.apply(changes(vec![upd(fd, 2, false, true)], vec![]));
            assert_eq!(ready(&mut backend, &wake, 200), vec![fd]);
            backend.apply(changes(vec![upd(fd, 2, false, false)], vec![]));
            assert!(ready(&mut backend, &wake, 50).is_empty(), "evsys {evsys}: no interest");
        }
    }

    /// Both backends see the same ready set under churn.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn interest_churn_matches_poll() {
        let wake = WakePipe::new().unwrap();
        let mut epoll = Backend::new(ARES_EVSYS_EPOLL);
        let mut poll = Backend::new(ARES_EVSYS_POLL);
        for round in 0..300usize {
            let socks: Vec<UdpSocket> = (0..4).map(|_| readable_socket()).collect();
            let updates: Vec<InterestUpdate> = socks
                .iter()
                .enumerate()
                .filter(|(i, _)| (i + round) % 3 != 0)
                .map(|(i, s)| upd(s.as_raw_fd(), (round * 10 + i) as u64 + 1, (i + round) % 2 != 0, (i + round) % 2 == 0))
                .collect();
            let removed: Vec<(i32, u64)> = updates.iter().map(|u| (u.fd, u.generation)).collect();
            epoll.apply(changes(updates.clone(), vec![]));
            poll.apply(changes(updates, vec![]));
            assert_eq!(ready(&mut epoll, &wake, 200), ready(&mut poll, &wake, 200), "round {round}: epoll and poll disagree");
            epoll.apply(changes(vec![], removed.clone()));
            poll.apply(changes(vec![], removed));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn wake_pipe_interrupts_wait() {
        for evsys in [ARES_EVSYS_EPOLL, ARES_EVSYS_POLL] {
            let wake = WakePipe::new().unwrap();
            let mut backend = Backend::new(evsys);
            wake.wake();
            let started = Instant::now();
            let r = backend.wait(&wake, 5000);
            assert!(r.woke && started.elapsed().as_millis() < 1000);
            wake.drain();
            assert!(!backend.wait(&wake, 10).woke);
        }
    }

    /// More ready fds than one wait returns: level-triggered epoll must keep
    /// handing out the rest on later waits, so none is starved.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn more_ready_fds_than_one_wait_returns() {
        let wake = WakePipe::new().unwrap();
        let mut backend = Backend::new(ARES_EVSYS_EPOLL);
        let socks: Vec<UdpSocket> = (0..200).map(|_| readable_socket()).collect();
        let updates = socks.iter().enumerate().map(|(i, s)| upd(s.as_raw_fd(), i as u64 + 1, true, false)).collect();
        backend.apply(changes(updates, vec![]));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.extend(backend.wait(&wake, 100).events.iter().map(|e| e.fd));
            if seen.len() == socks.len() {
                return;
            }
        }
        panic!("only {}/{} ready fds were ever reported", seen.len(), socks.len());
    }

    /// epoll refuses regular files (EPERM). Like upstream, such an fd is left
    /// unwatched — never a busy loop. (poll(2) itself reports it ready.)
    #[test]
    #[cfg_attr(miri, ignore)]
    fn unwatchable_fd_is_left_unwatched_not_spun_on() {
        let wake = WakePipe::new().unwrap();
        let file = std::fs::File::open("/proc/self/exe").unwrap();
        let fd = file.as_raw_fd();

        let mut epoll = Backend::new(ARES_EVSYS_EPOLL);
        epoll.apply(changes(vec![upd(fd, 1, true, false)], vec![]));
        let started = Instant::now();
        assert!(ready(&mut epoll, &wake, 150).is_empty());
        assert!(started.elapsed().as_millis() >= 100, "returned early: spinning on an unwatchable fd");

        let mut poll = Backend::new(ARES_EVSYS_POLL);
        poll.apply(changes(vec![upd(fd, 1, true, false)], vec![]));
        assert_eq!(ready(&mut poll, &wake, 150), vec![fd]);
    }
}
