//! Per-channel reactor, shaped after async-io's `Reactor`: fd [`Source`]s with
//! per-direction waker slabs and event ticks, plus a timer map. Where async-io
//! blocks in `polling::Poller::wait`, the host calls [`Reactor::dispatch`] with
//! the readiness the caller handed to `ares_process*`, and reads interest back
//! through [`Reactor::interests`] / [`Reactor::next_deadline`]. One reactor per
//! channel (no global): handles are passed explicitly via [`Runtime`].

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::Future;
use std::marker::PhantomPinned;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use crate::async_runtime::socket::{Socket, SocketFactory};

pub(crate) const READ: usize = 0;
pub(crate) const WRITE: usize = 1;

/// Minimal slab (stable keys, reused holes), as async-io uses the `slab` crate.
pub(crate) struct Slab<T> {
    entries: Vec<Option<T>>,
    free: Vec<usize>,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Slab { entries: Vec::new(), free: Vec::new() }
    }
}

impl<T> Slab<T> {
    /// The key the next `insert` will use.
    pub(crate) fn vacant_key(&self) -> usize {
        self.free.last().copied().unwrap_or(self.entries.len())
    }

    pub(crate) fn insert(&mut self, value: T) -> usize {
        match self.free.pop() {
            Some(key) => {
                if let Some(slot) = self.entries.get_mut(key) {
                    *slot = Some(value);
                }
                key
            }
            None => {
                self.entries.push(Some(value));
                self.entries.len() - 1
            }
        }
    }

    pub(crate) fn remove(&mut self, key: usize) -> Option<T> {
        let value = self.entries.get_mut(key)?.take();
        if value.is_some() {
            self.free.push(key);
        }
        value
    }

    pub(crate) fn get_mut(&mut self, key: usize) -> Option<&mut T> {
        self.entries.get_mut(key).and_then(Option::as_mut)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().flatten()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.entries.iter_mut().flatten()
    }
}

/// One direction (read or write) of a source: the tick of its last event and
/// the wakers of the [`Ready`] futures awaiting it (async-io's `Direction`).
#[derive(Default)]
struct Direction {
    tick: usize,
    wakers: Slab<Option<Waker>>,
}

impl Direction {
    fn has_waiters(&self) -> bool {
        self.wakers.iter().any(Option::is_some)
    }
}

/// A registered fd (async-io's `Source`). Removed from the reactor when its
/// [`Async`](crate::async_runtime::io::Async) is dropped.
pub(crate) struct Source {
    fd: i32,
    key: usize,
    state: RefCell<[Direction; 2]>,
}

impl Source {
    pub(crate) fn tick(&self, dir: usize) -> usize {
        self.state.borrow().get(dir).map_or(0, |d| d.tick)
    }
}

pub(crate) struct Reactor {
    /// Bumped once per `dispatch`; a direction's `tick` records the ticker
    /// value of its last event.
    ticker: Cell<usize>,
    sources: RefCell<Slab<Rc<Source>>>,
    timers: RefCell<BTreeMap<(Instant, usize), Waker>>,
    next_timer: Cell<usize>,
    /// Receive scratch (grown to 64 KB on first use), lent out for one
    /// synchronous recv at a time — avoids zeroing 64 KB per call.
    scratch: Cell<Vec<u8>>,
}

impl Reactor {
    pub(crate) fn new() -> Rc<Self> {
        Rc::new(Reactor {
            // Starts above every direction's initial tick (0), so a fresh
            // source never looks reported in the current turn.
            ticker: Cell::new(1),
            sources: RefCell::new(Slab::default()),
            timers: RefCell::new(BTreeMap::new()),
            next_timer: Cell::new(0),
            scratch: Cell::new(Vec::new()),
        })
    }

    pub(crate) fn ticker(&self) -> usize {
        self.ticker.get()
    }

    pub(crate) fn insert_io(&self, fd: i32) -> Rc<Source> {
        let mut sources = self.sources.borrow_mut();
        let source = Rc::new(Source { fd, key: sources.vacant_key(), state: RefCell::default() });
        sources.insert(source.clone());
        source
    }

    pub(crate) fn remove_io(&self, source: &Source) {
        let removed = self.sources.borrow_mut().remove(source.key);
        // Waker drops (and any socket they keep alive) run with no borrow live.
        drop(removed);
    }

    /// Feed one turn of caller-reported readiness (async-io's `react`, minus
    /// the wait): directions with waiters whose `(fd, writable)` is `ready` get
    /// this turn's tick and are woken; unless `skip_timeouts`, so are timers due
    /// by `now`. Wakers fire after every borrow is released.
    pub(crate) fn dispatch(&self, now: Instant, skip_timeouts: bool, ready: impl Fn(i32, bool) -> bool) {
        let tick = self.ticker.get().wrapping_add(1);
        self.ticker.set(tick);
        let mut wake = Vec::new();
        for source in self.sources.borrow().iter() {
            let mut state = source.state.borrow_mut();
            for (dir, d) in state.iter_mut().enumerate() {
                if d.has_waiters() && ready(source.fd, dir == WRITE) {
                    d.tick = tick;
                    wake.extend(d.wakers.iter_mut().filter_map(Option::take));
                }
            }
        }
        if !skip_timeouts {
            let mut timers = self.timers.borrow_mut();
            let later = timers.split_off(&(now + Duration::from_nanos(1), 0));
            let due = std::mem::replace(&mut *timers, later);
            wake.extend(due.into_values());
        }
        for w in wake {
            w.wake();
        }
    }

    /// Every `(fd, wants_write)` some live [`Ready`] is waiting on.
    pub(crate) fn interests(&self) -> Vec<(i32, bool)> {
        let mut out = Vec::new();
        for source in self.sources.borrow().iter() {
            let state = source.state.borrow();
            for (dir, d) in state.iter().enumerate() {
                if d.has_waiters() {
                    out.push((source.fd, dir == WRITE));
                }
            }
        }
        out
    }

    /// The earliest registered timer deadline.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.timers.borrow().keys().next().map(|(when, _)| *when)
    }

    fn insert_timer(&self, when: Instant, waker: &Waker) -> usize {
        let id = self.next_timer.get().wrapping_add(1);
        self.next_timer.set(id);
        self.timers.borrow_mut().insert((when, id), waker.clone());
        id
    }

    /// Refresh (or, after `dispatch` fired and removed it, re-insert) a timer's waker.
    fn update_timer(&self, when: Instant, id: usize, waker: &Waker) {
        let mut timers = self.timers.borrow_mut();
        match timers.get_mut(&(when, id)) {
            Some(w) if w.will_wake(waker) => {}
            Some(w) => *w = waker.clone(),
            None => {
                timers.insert((when, id), waker.clone());
            }
        }
    }

    fn remove_timer(&self, when: Instant, id: usize) {
        let removed = self.timers.borrow_mut().remove(&(when, id));
        drop(removed);
    }

    /// Run `f` with the shared receive scratch, taken out for the call so a
    /// re-entrant socket callback never finds it borrowed.
    pub(crate) fn with_scratch<R>(&self, f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
        let mut scratch = self.scratch.take();
        let r = f(&mut scratch);
        self.scratch.set(scratch);
        r
    }
}

/// Resolves once `dir` of `source` has an event newer than its registration
/// (async-io's `Ready`); dropping it removes its waker (so `interests` only
/// ever lists live waiters).
///
/// `!Unpin`, with its mutable state in `Cell`s and `poll` working through
/// `&Self`: it is pinned inside async state machines that `select_biased!`
/// reads through shared references, and a `&mut` to an `Unpin` type would be
/// treated as unique there (Tree Borrows), making the next self-write UB.
pub(crate) struct Ready {
    reactor: Rc<Reactor>,
    source: Rc<Source>,
    dir: usize,
    ticks: Cell<Option<(usize, usize)>>,
    index: Cell<Option<usize>>,
    _pin: PhantomPinned,
}

impl Ready {
    pub(crate) fn new(reactor: Rc<Reactor>, source: Rc<Source>, dir: usize) -> Self {
        Ready { reactor, source, dir, ticks: Cell::new(None), index: Cell::new(None), _pin: PhantomPinned }
    }
}

impl Future for Ready {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.into_ref().get_ref();
        let mut state = this.source.state.borrow_mut();
        let Some(d) = state.get_mut(this.dir) else { return Poll::Ready(()) };
        match this.ticks.get() {
            Some((a, b)) if d.tick != a && d.tick != b => {
                if let Some(i) = this.index.take() {
                    d.wakers.remove(i);
                }
                return Poll::Ready(());
            }
            Some(_) => {}
            None => this.ticks.set(Some((this.reactor.ticker(), d.tick))),
        }
        match this.index.get().and_then(|i| d.wakers.get_mut(i)) {
            Some(slot) => {
                if !slot.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                    *slot = Some(cx.waker().clone());
                }
            }
            None => this.index.set(Some(d.wakers.insert(Some(cx.waker().clone())))),
        }
        Poll::Pending
    }
}

impl Drop for Ready {
    fn drop(&mut self) {
        if let Some(i) = self.index.take() {
            let removed = self.source.state.borrow_mut().get_mut(self.dir).and_then(|d| d.wakers.remove(i));
            drop(removed);
        }
    }
}

/// Resolves at `when` (async-io's `Timer::at`). Registered on first `Pending`,
/// deregistered on completion or drop. Reads the clock on every poll, so a task
/// polled for another reason still observes its expiry. `!Unpin` with `Cell`
/// state, for the same reason as [`Ready`].
pub(crate) struct Timer {
    reactor: Rc<Reactor>,
    when: Instant,
    id: Cell<Option<usize>>,
    _pin: PhantomPinned,
}

impl Timer {
    pub(crate) fn at(reactor: &Rc<Reactor>, when: Instant) -> Self {
        Timer { reactor: reactor.clone(), when, id: Cell::new(None), _pin: PhantomPinned }
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.into_ref().get_ref();
        if Instant::now() >= this.when {
            if let Some(id) = this.id.take() {
                this.reactor.remove_timer(this.when, id);
            }
            return Poll::Ready(());
        }
        match this.id.get() {
            Some(id) => this.reactor.update_timer(this.when, id, cx.waker()),
            None => this.id.set(Some(this.reactor.insert_timer(this.when, cx.waker()))),
        }
        Poll::Pending
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.reactor.remove_timer(self.when, id);
        }
    }
}

/// A detached task waiting for the host to move it into the executor.
pub(crate) type SpawnedTask = Pin<Box<dyn Future<Output = ()>>>;

/// A channel's runtime handle — smol's implicit global reactor made explicit:
/// creates [`Async`](crate::async_runtime::io::Async) sockets and [`Timer`]s,
/// and spawns detached tasks.
#[derive(Clone)]
pub(crate) struct Runtime {
    reactor: Rc<Reactor>,
    factory: Rc<dyn SocketFactory>,
    /// Tasks from [`Runtime::spawn`], not yet taken by the host.
    spawned: Rc<RefCell<Vec<SpawnedTask>>>,
}

impl Runtime {
    pub(crate) fn new(factory: Rc<dyn SocketFactory>) -> Self {
        Runtime { reactor: Reactor::new(), factory, spawned: Rc::default() }
    }

    /// Spawn a detached task (≈ `tokio::spawn`): fire-and-forget, with no
    /// output, so the spawning task never waits for it. It runs until it
    /// completes or the channel aborts its tasks. The executor is busy polling
    /// the caller, so the task is queued here and the host moves it into the
    /// executor (see [`Runtime::take_spawned`]) once that poll returns.
    pub(crate) fn spawn(&self, fut: impl Future<Output = ()> + 'static) {
        self.spawned.borrow_mut().push(Box::pin(fut));
    }

    /// Take every task queued by [`Runtime::spawn`] since the last call.
    pub(crate) fn take_spawned(&self) -> Vec<SpawnedTask> {
        std::mem::take(&mut *self.spawned.borrow_mut())
    }

    pub(crate) fn reactor(&self) -> &Rc<Reactor> {
        &self.reactor
    }

    pub(crate) fn factory(&self) -> Rc<dyn SocketFactory> {
        self.factory.clone()
    }

    pub(crate) fn set_factory(&mut self, factory: Rc<dyn SocketFactory>) {
        self.factory = factory;
    }

    pub(crate) fn udp(&self, bind: SocketAddr) -> io::Result<Rc<crate::async_runtime::io::Async>> {
        let sock: Rc<dyn Socket> = self.factory.create_udp(bind)?;
        Ok(crate::async_runtime::io::Async::new(sock, &self.reactor))
    }

    pub(crate) fn tcp(&self, bind: SocketAddr) -> io::Result<Rc<crate::async_runtime::io::Async>> {
        let sock: Rc<dyn Socket> = self.factory.create_tcp(bind)?;
        Ok(crate::async_runtime::io::Async::new(sock, &self.reactor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::Wake;

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn counter() -> (Arc<Count>, Waker) {
        let c = Arc::new(Count(AtomicUsize::new(0)));
        (c.clone(), Waker::from(c))
    }
    fn poll<F: Future>(f: &mut Pin<Box<F>>, w: &Waker) -> Poll<F::Output> {
        f.as_mut().poll(&mut Context::from_waker(w))
    }

    #[test]
    fn ready_completes_only_after_a_newer_event() {
        let r = Reactor::new();
        let src = r.insert_io(7);
        let (count, w) = counter();
        let mut rd = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        assert!(poll(&mut rd, &w).is_pending());
        assert_eq!(r.interests(), vec![(7, false)]);

        // Write readiness does not complete a read waiter (C3).
        r.dispatch(Instant::now(), true, |fd, wr| fd == 7 && wr);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert!(poll(&mut rd, &w).is_pending());

        r.dispatch(Instant::now(), true, |fd, wr| fd == 7 && !wr);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(poll(&mut rd, &w).is_ready());
        assert!(r.interests().is_empty());
    }

    #[test]
    fn ready_registered_after_event_waits_for_next_turn() {
        let r = Reactor::new();
        let src = r.insert_io(7);
        let (_c, w) = counter();
        let mut first = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        assert!(poll(&mut first, &w).is_pending());
        r.dispatch(Instant::now(), true, |_, wr| !wr);
        // A waiter registered after this turn's event must not see it (C2).
        let mut late = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        assert!(poll(&mut late, &w).is_pending());
        assert!(poll(&mut first, &w).is_ready());
    }

    #[test]
    fn dropping_waiters_clears_interest_and_deadline() {
        let r = Reactor::new();
        let src = r.insert_io(9);
        let (_c, w) = counter();
        let mut rd = Box::pin(Ready::new(r.clone(), src.clone(), WRITE));
        let mut t = Box::pin(Timer::at(&r, Instant::now() + Duration::from_secs(60)));
        assert!(poll(&mut rd, &w).is_pending());
        assert!(poll(&mut t, &w).is_pending());
        assert_eq!(r.interests(), vec![(9, true)]);
        assert!(r.next_deadline().is_some());
        drop(rd);
        drop(t);
        assert!(r.interests().is_empty());
        assert!(r.next_deadline().is_none());
    }

    #[test]
    fn skip_timeouts_leaves_due_timer_unwoken() {
        let r = Reactor::new();
        let (count, w) = counter();
        // Far enough out that the real clock can't reach it even under Miri;
        // expiry is then driven by the synthetic `now` handed to `dispatch`.
        let when = Instant::now() + Duration::from_secs(60);
        let mut t = Box::pin(Timer::at(&r, when));
        assert!(poll(&mut t, &w).is_pending());
        let later = when + Duration::from_millis(5);
        r.dispatch(later, true, |_, _| false);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        r.dispatch(later, false, |_, _| false);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(r.next_deadline().is_none());
    }

    #[test]
    fn one_event_wakes_every_waiter_on_a_shared_fd() {
        let r = Reactor::new();
        let src = r.insert_io(4);
        let (ca, wa) = counter();
        let (cb, wb) = counter();
        let mut a = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        let mut b = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        assert!(poll(&mut a, &wa).is_pending());
        assert!(poll(&mut b, &wb).is_pending());
        assert_eq!(r.interests(), vec![(4, false)]);
        r.dispatch(Instant::now(), true, |_, _| true);
        assert_eq!(ca.0.load(Ordering::SeqCst) + cb.0.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn removed_source_reports_no_interest() {
        let r = Reactor::new();
        let src = r.insert_io(3);
        let (_c, w) = counter();
        let mut rd = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        assert!(poll(&mut rd, &w).is_pending());
        r.remove_io(&src);
        assert!(r.interests().is_empty());
    }
}
