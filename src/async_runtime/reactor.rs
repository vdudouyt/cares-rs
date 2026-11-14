//! Per-channel reactor, shaped after async-io's `Reactor`: fd [`Source`]s with
//! per-direction waker slabs and event ticks, plus a timer map. Where async-io
//! blocks in `polling::Poller::wait`, the host calls [`Reactor::dispatch`] with
//! the readiness the caller handed to `ares_process*`, and reads interest back
//! through [`Reactor::interests`] / [`Reactor::next_deadline`]. One reactor per
//! channel (no global): handles are passed explicitly via [`Runtime`].

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
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

    pub(crate) fn get(&self, key: usize) -> Option<&T> {
        self.entries.get(key).and_then(Option::as_ref)
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
/// `live` counts the wakers currently set, so "is anyone waiting" is O(1).
#[derive(Default)]
struct Direction {
    tick: usize,
    wakers: Slab<Option<Waker>>,
    live: usize,
}

impl Direction {
    fn has_waiters(&self) -> bool {
        self.live > 0
    }

    /// Set (or refresh) the waker at `index`, inserting a slot if there is none.
    /// Returns the slot and whether the direction just gained its first waiter.
    fn register(&mut self, index: Option<usize>, waker: &Waker) -> (usize, bool) {
        let was_waiting = self.has_waiters();
        let existing = index.filter(|&i| self.wakers.get_mut(i).is_some());
        let slot = match existing {
            Some(i) => {
                if let Some(slot) = self.wakers.get_mut(i) {
                    match slot {
                        Some(w) => {
                            if !w.will_wake(waker) {
                                *w = waker.clone();
                            }
                        }
                        // The slot was emptied by a dispatch; waiting again.
                        None => {
                            *slot = Some(waker.clone());
                            self.live += 1;
                        }
                    }
                }
                i
            }
            None => {
                self.live += 1;
                self.wakers.insert(Some(waker.clone()))
            }
        };
        (slot, !was_waiting && self.has_waiters())
    }

    /// Drop the slot at `index`. Returns its waker (to drop outside any borrow)
    /// and whether the direction just lost its last waiter.
    fn deregister(&mut self, index: usize) -> (Option<Waker>, bool) {
        let removed = self.wakers.remove(index).flatten();
        let had_waker = removed.is_some();
        if had_waker {
            self.live = self.live.saturating_sub(1);
        }
        (removed, had_waker && self.live == 0)
    }

    /// Move every set waker into `out`. Returns whether the direction just went idle.
    fn take_wakers(&mut self, out: &mut Vec<Waker>) -> bool {
        let was_waiting = self.has_waiters();
        for slot in self.wakers.iter_mut() {
            if let Some(w) = slot.take() {
                out.push(w);
            }
        }
        self.live = 0;
        was_waiting
    }
}

/// A registered fd (async-io's `Source`). Removed from the reactor when its
/// [`Async`](crate::async_runtime::io::Async) is dropped.
pub(crate) struct Source {
    fd: i32,
    key: usize,
    /// Reactor-unique, never reused: tells a fresh registration of a recycled
    /// fd number from the old one (see [`InterestUpdate::generation`]).
    generation: u64,
    /// Interest changed since the last [`Reactor::take_interest_changes`].
    dirty: Cell<bool>,
    state: RefCell<[Direction; 2]>,
}

/// One source's current interest, as of [`Reactor::take_interest_changes`].
/// `read == write == false` means "watch nothing".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InterestUpdate {
    pub(crate) fd: i32,
    /// Reactor-unique registration id; a recycled fd number gets a new one.
    pub(crate) generation: u64,
    pub(crate) read: bool,
    pub(crate) write: bool,
}

/// What changed since the host last asked: sources that were dropped, and
/// sources whose interest differs from (or may differ from) what it was.
#[derive(Default, Debug)]
pub(crate) struct InterestChanges {
    /// `(fd, generation)` of every dropped source.
    pub(crate) removed: Vec<(i32, u64)>,
    pub(crate) updates: Vec<InterestUpdate>,
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
    next_generation: Cell<u64>,
    /// fd → keys of its live sources, so a ready fd finds its waiters in O(1).
    by_fd: RefCell<HashMap<i32, Vec<usize>>>,
    /// Change log for a host that keeps a persistent interest set (the event
    /// thread). Off unless [`Reactor::enable_change_tracking`] ran, so channels
    /// driven by `ares_process*` never accumulate entries nobody drains.
    tracking: Cell<bool>,
    dirty: RefCell<Vec<usize>>,
    removed: RefCell<Vec<(i32, u64)>>,
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
            next_generation: Cell::new(0),
            by_fd: RefCell::new(HashMap::new()),
            tracking: Cell::new(false),
            dirty: RefCell::new(Vec::new()),
            removed: RefCell::new(Vec::new()),
            scratch: Cell::new(Vec::new()),
        })
    }

    pub(crate) fn ticker(&self) -> usize {
        self.ticker.get()
    }

    pub(crate) fn insert_io(&self, fd: i32) -> Rc<Source> {
        let mut sources = self.sources.borrow_mut();
        let generation = self.next_generation.get().wrapping_add(1);
        self.next_generation.set(generation);
        let key = sources.vacant_key();
        let source = Rc::new(Source { fd, key, generation, dirty: Cell::new(false), state: RefCell::default() });
        sources.insert(source.clone());
        self.by_fd.borrow_mut().entry(fd).or_default().push(key);
        source
    }

    pub(crate) fn remove_io(&self, source: &Source) {
        let removed = self.sources.borrow_mut().remove(source.key);
        {
            let mut by_fd = self.by_fd.borrow_mut();
            if let Some(keys) = by_fd.get_mut(&source.fd) {
                keys.retain(|&k| k != source.key);
                if keys.is_empty() {
                    by_fd.remove(&source.fd);
                }
            }
        }
        if removed.is_some() && self.tracking.get() {
            self.removed.borrow_mut().push((source.fd, source.generation));
        }
        // Waker drops (and any socket they keep alive) run with no borrow live.
        drop(removed);
    }

    /// Record that `source`'s interest may have changed (a direction gained its
    /// first waiter or lost its last one).
    fn interest_changed(&self, source: &Source) {
        if self.tracking.get() && !source.dirty.replace(true) {
            self.dirty.borrow_mut().push(source.key);
        }
    }

    /// Start logging interest changes for [`Reactor::take_interest_changes`];
    /// every source that already exists is reported by the first call.
    pub(crate) fn enable_change_tracking(&self) {
        self.tracking.set(true);
        for source in self.sources.borrow().iter() {
            self.interest_changed(source);
        }
    }

    /// The sources whose interest may have changed since the last call, with
    /// their interest *now* (an off-then-on blip inside one turn reads as
    /// unchanged), plus the sources dropped since. O(changes), not O(sources).
    pub(crate) fn take_interest_changes(&self) -> InterestChanges {
        let removed = std::mem::take(&mut *self.removed.borrow_mut());
        let keys = std::mem::take(&mut *self.dirty.borrow_mut());
        let sources = self.sources.borrow();
        let mut updates = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(source) = sources.get(key) else { continue };
            if !source.dirty.replace(false) {
                continue; // already reported (a stale or duplicate key)
            }
            let state = source.state.borrow();
            updates.push(InterestUpdate {
                fd: source.fd,
                generation: source.generation,
                read: state[READ].has_waiters(),
                write: state[WRITE].has_waiters(),
            });
        }
        InterestChanges { removed, updates }
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
                    if d.take_wakers(&mut wake) {
                        self.interest_changed(source);
                    }
                }
            }
        }
        self.finish_dispatch(now, skip_timeouts, wake);
    }

    /// [`dispatch`](Self::dispatch) for a host that already knows *which* fds are
    /// ready (the event thread): each `(fd, readable, writable)` finds its source
    /// through the fd index, so a turn costs O(ready fds), not O(sources).
    pub(crate) fn dispatch_events(&self, now: Instant, skip_timeouts: bool, events: impl IntoIterator<Item = (i32, bool, bool)>) {
        let tick = self.ticker.get().wrapping_add(1);
        self.ticker.set(tick);
        let mut wake = Vec::new();
        {
            let by_fd = self.by_fd.borrow();
            let sources = self.sources.borrow();
            for (fd, readable, writable) in events {
                let Some(keys) = by_fd.get(&fd) else { continue };
                for source in keys.iter().filter_map(|&key| sources.get(key)) {
                    let mut state = source.state.borrow_mut();
                    for (dir, hit) in [(READ, readable), (WRITE, writable)] {
                        let Some(d) = state.get_mut(dir) else { continue };
                        if hit && d.has_waiters() {
                            d.tick = tick;
                            if d.take_wakers(&mut wake) {
                                self.interest_changed(source);
                            }
                        }
                    }
                }
            }
        }
        self.finish_dispatch(now, skip_timeouts, wake);
    }

    /// Add the due timers' wakers (unless `skip_timeouts`) and fire everything,
    /// with every borrow released.
    fn finish_dispatch(&self, now: Instant, skip_timeouts: bool, mut wake: Vec<Waker>) {
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
                    let (_waker, idle) = d.deregister(i);
                    if idle {
                        this.reactor.interest_changed(&this.source);
                    }
                }
                return Poll::Ready(());
            }
            Some(_) => {}
            None => this.ticks.set(Some((this.reactor.ticker(), d.tick))),
        }
        let (slot, gained) = d.register(this.index.get(), cx.waker());
        this.index.set(Some(slot));
        if gained {
            this.reactor.interest_changed(&this.source);
        }
        Poll::Pending
    }
}

impl Drop for Ready {
    fn drop(&mut self) {
        if let Some(i) = self.index.take() {
            let (removed, idle) = match self.source.state.borrow_mut().get_mut(self.dir) {
                Some(d) => d.deregister(i),
                None => (None, false),
            };
            if idle {
                self.reactor.interest_changed(&self.source);
            }
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

    #[test]
    fn dispatch_events_wakes_only_the_named_fd_and_direction() {
        let r = Reactor::new();
        let (a, b) = (r.insert_io(5), r.insert_io(6));
        let (ca, wa) = counter();
        let (cb, wb) = counter();
        let mut ra = Box::pin(Ready::new(r.clone(), a.clone(), READ));
        let mut rb = Box::pin(Ready::new(r.clone(), b.clone(), READ));
        assert!(poll(&mut ra, &wa).is_pending());
        assert!(poll(&mut rb, &wb).is_pending());

        r.dispatch_events(Instant::now(), true, [(5, false, true)]); // write only: a read waiter stays
        r.dispatch_events(Instant::now(), true, [(99, true, true)]); // unknown fd
        assert_eq!((ca.0.load(Ordering::SeqCst), cb.0.load(Ordering::SeqCst)), (0, 0));

        r.dispatch_events(Instant::now(), true, [(6, true, false)]);
        assert_eq!((ca.0.load(Ordering::SeqCst), cb.0.load(Ordering::SeqCst)), (0, 1));
        assert!(poll(&mut rb, &wb).is_ready());
        assert!(poll(&mut ra, &wa).is_pending());
        assert_eq!(r.interests(), vec![(5, false)]);
    }

    #[test]
    fn change_log_is_off_until_enabled() {
        let r = Reactor::new();
        let src = r.insert_io(3);
        let (_c, w) = counter();
        let mut rd = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        assert!(poll(&mut rd, &w).is_pending());
        drop(rd);
        r.remove_io(&src);
        let c = r.take_interest_changes();
        assert!(c.updates.is_empty() && c.removed.is_empty(), "nothing may accumulate for hosts that never drain");
    }

    #[test]
    fn change_log_reports_current_interest_once() {
        let r = Reactor::new();
        r.enable_change_tracking();
        let src = r.insert_io(8);
        let (_c, w) = counter();
        let mut rd = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        let mut wr = Box::pin(Ready::new(r.clone(), src.clone(), WRITE));
        assert!(poll(&mut rd, &w).is_pending());
        assert!(poll(&mut wr, &w).is_pending());
        let c = r.take_interest_changes();
        assert_eq!(c.updates, vec![InterestUpdate { fd: 8, generation: src.generation, read: true, write: true }]);
        assert!(c.removed.is_empty());
        assert!(r.take_interest_changes().updates.is_empty(), "drained");

        // Off and on again inside one turn: the same interest, reported once.
        r.dispatch_events(Instant::now(), true, [(8, true, false)]);
        assert!(poll(&mut rd, &w).is_ready());
        let mut again = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        assert!(poll(&mut again, &w).is_pending());
        let c = r.take_interest_changes();
        assert_eq!(c.updates, vec![InterestUpdate { fd: 8, generation: src.generation, read: true, write: true }]);

        // Waiters gone: reported as no interest; dropping the source is a removal.
        drop(again);
        drop(wr);
        let c = r.take_interest_changes();
        assert_eq!(c.updates, vec![InterestUpdate { fd: 8, generation: src.generation, read: false, write: false }]);
        r.remove_io(&src);
        let c = r.take_interest_changes();
        assert_eq!(c.removed, vec![(8, src.generation)]);
        assert!(c.updates.is_empty());
    }

    #[test]
    fn enabling_the_log_reports_existing_sources() {
        let r = Reactor::new();
        let src = r.insert_io(2);
        let (_c, w) = counter();
        let mut rd = Box::pin(Ready::new(r.clone(), src.clone(), READ));
        assert!(poll(&mut rd, &w).is_pending());
        r.enable_change_tracking();
        let c = r.take_interest_changes();
        assert_eq!(c.updates, vec![InterestUpdate { fd: 2, generation: src.generation, read: true, write: false }]);
    }

    #[test]
    fn recycled_fd_number_gets_a_new_generation() {
        let r = Reactor::new();
        let first = r.insert_io(4);
        r.remove_io(&first);
        let second = r.insert_io(4);
        assert_ne!(first.generation, second.generation);
    }

    /// `cargo test --lib -- --ignored --nocapture dispatch_cost`: the closure-scanning
    /// `dispatch` is O(sources × events); `dispatch_events` is O(events).
    #[test]
    #[ignore]
    fn dispatch_cost_scales_with_ready_fds_not_sources() {
        let sources: i32 = 20_000;
        let ready_fds: i32 = 200;
        let r = Reactor::new();
        let (_c, w) = counter();
        let held: Vec<_> = (0..sources)
            .map(|fd| {
                let src = r.insert_io(fd);
                let mut f = Box::pin(Ready::new(r.clone(), src.clone(), READ));
                assert!(poll(&mut f, &w).is_pending());
                (src, f)
            })
            .collect();
        let events: Vec<(i32, bool, bool)> = (0..ready_fds).map(|fd| (fd, true, false)).collect();

        let started = Instant::now();
        r.dispatch(Instant::now(), true, |fd, wr| !wr && events.iter().any(|e| e.0 == fd));
        let scanning = started.elapsed();
        drop(held);

        let held: Vec<_> = (0..sources)
            .map(|fd| {
                let src = r.insert_io(100_000 + fd);
                let mut f = Box::pin(Ready::new(r.clone(), src.clone(), READ));
                assert!(poll(&mut f, &w).is_pending());
                (src, f)
            })
            .collect();
        let events: Vec<(i32, bool, bool)> = (0..ready_fds).map(|fd| (100_000 + fd, true, false)).collect();
        let started = Instant::now();
        r.dispatch_events(Instant::now(), true, events);
        let indexed = started.elapsed();
        drop(held);
        println!("{sources} sources, {ready_fds} ready: dispatch {scanning:?}, dispatch_events {indexed:?}");
        assert!(indexed * 20 < scanning, "dispatch_events should be far cheaper");
    }

    /// Randomized model check of the change log. A shadow registry, edited only by
    /// the drained `InterestChanges` (the way a backend is), must always equal the
    /// ground truth from a full scan (`interests()`) — through registering, waking,
    /// dropping, removing sources, recycled fd numbers, recycled slab keys, and
    /// tracking being switched on while sources already exist.
    #[test]
    fn change_log_never_loses_an_update() {
        struct Live {
            src: Rc<Source>,
            readers: Vec<Pin<Box<Ready>>>,
            writers: Vec<Pin<Box<Ready>>>,
        }

        struct Rng(u64);
        impl Rng {
            fn next(&mut self, bound: usize) -> usize {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                (self.0 % bound as u64) as usize
            }
        }

        // (read, write, generation) per fd, built only from drained changes.
        type Shadow = HashMap<i32, (bool, bool, u64)>;
        fn apply(shadow: &mut Shadow, c: InterestChanges) {
            for (fd, generation) in c.removed {
                if shadow.get(&fd).is_some_and(|e| e.2 == generation) {
                    shadow.remove(&fd);
                }
            }
            for u in c.updates {
                match (u.read || u.write, shadow.get(&u.fd).copied()) {
                    (true, Some((_, _, g))) if g > u.generation => {} // a newer source owns the fd
                    (true, _) => {
                        shadow.insert(u.fd, (u.read, u.write, u.generation));
                    }
                    (false, Some((_, _, g))) if g == u.generation => {
                        shadow.remove(&u.fd);
                    }
                    (false, _) => {}
                }
            }
        }
        fn truth(r: &Reactor, live: &[Live]) -> Shadow {
            let mut out = Shadow::new();
            for (fd, write) in r.interests() {
                let generation = live.iter().find(|l| l.src.fd == fd).map_or(0, |l| l.src.generation);
                let e = out.entry(fd).or_insert((false, false, generation));
                if write {
                    e.1 = true;
                } else {
                    e.0 = true;
                }
            }
            out
        }

        let (_c, w) = counter();
        // Miri is ~1000x slower: a few seeds still cover every operation under its checks.
        let (seeds, steps) = if cfg!(miri) { (6u64, 150) } else { (300, 400) };
        for seed in 1..=seeds {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let r = Reactor::new();
            let mut live: Vec<Live> = Vec::new();
            let mut shadow = Shadow::new();
            let enable_at = rng.next(steps / 6);

            for step in 0..steps {
                if step == enable_at {
                    r.enable_change_tracking();
                }
                match rng.next(9) {
                    0 | 1 => {
                        // A new source; a small fd range forces recycled numbers.
                        let fd = rng.next(6) as i32;
                        if !live.iter().any(|l| l.src.fd == fd) {
                            live.push(Live { src: r.insert_io(fd), readers: vec![], writers: vec![] });
                        }
                    }
                    2 | 3 if !live.is_empty() => {
                        let n = rng.next(live.len());
                        let l = &mut live[n];
                        let dir = rng.next(2);
                        let mut f = Box::pin(Ready::new(r.clone(), l.src.clone(), if dir == 0 { READ } else { WRITE }));
                        if f.as_mut().poll(&mut Context::from_waker(&w)).is_pending() {
                            if dir == 0 { l.readers.push(f) } else { l.writers.push(f) }
                        }
                    }
                    4 if !live.is_empty() => {
                        // Re-poll one (registers again after a wake; completes if an event came).
                        let n = rng.next(live.len());
                        let l = &mut live[n];
                        let dir = rng.next(2);
                        let list = if dir == 0 { &mut l.readers } else { &mut l.writers };
                        if !list.is_empty() {
                            let k = rng.next(list.len());
                            if list[k].as_mut().poll(&mut Context::from_waker(&w)).is_ready() {
                                list.remove(k);
                            }
                        }
                    }
                    5 if !live.is_empty() => {
                        let n = rng.next(live.len());
                        let l = &mut live[n];
                        let dir = rng.next(2);
                        let list = if dir == 0 { &mut l.readers } else { &mut l.writers };
                        if !list.is_empty() {
                            let k = rng.next(list.len());
                            drop(list.remove(k));
                        }
                    }
                    6 => {
                        let events: Vec<(i32, bool, bool)> =
                            (0..1 + rng.next(3)).map(|_| (rng.next(6) as i32, rng.next(2) == 0, rng.next(2) == 0)).collect();
                        r.dispatch_events(Instant::now(), true, events);
                    }
                    7 if !live.is_empty() => {
                        let n = rng.next(live.len());
                        let l = live.remove(n);
                        let Live { src, readers, writers } = l;
                        drop(readers);
                        drop(writers);
                        r.remove_io(&src);
                    }
                    _ => {}
                }
                if rng.next(4) == 0 && r.tracking.get() {
                    apply(&mut shadow, r.take_interest_changes());
                    assert_eq!(shadow, truth(&r, &live), "seed {seed} step {step}: change log diverged from a full scan");
                }
            }
        }
    }
}
