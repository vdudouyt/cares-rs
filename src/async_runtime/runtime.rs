//! Public owner of the executor and reactor; all host-loop coordination lives here.

use std::cell::Cell;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

use super::executor::Executor;
use super::reactor::Reactor;
use super::{AsyncSocket, InterestChanges, Socket, SocketFactory, SocketKind, Timer};

/// A task was rejected because the runtime has shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeClosed;

impl fmt::Display for RuntimeClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("runtime is shut down")
    }
}

impl std::error::Error for RuntimeClosed {}

/// A single-threaded runtime driven by an external event loop.
///
/// `E` is the cancellation status delivered by [`shutdown`](Self::shutdown).
/// Spawning schedules a task without polling it; [`run_ready`](Self::run_ready)
/// and [`process`](Self::process) poll tasks and deliver their results.
///
/// The runtime created by `new` or `default` owns its tasks. Use
/// [`handle`](Self::handle) inside tasks: it provides the same API without
/// keeping the task registry alive. Dropping the owner drops its tasks; call
/// `shutdown` first when pending tasks must receive cancellation callbacks.
/// Socket and timer futures own their registrations independently.
///
/// ```
/// use cares::async_runtime::Runtime;
/// use std::time::{Duration, Instant};
///
/// let runtime = Runtime::new();
/// let timer = runtime.timer_at(Instant::now() + Duration::from_secs(1));
/// runtime.spawn(timer, |_| {}).unwrap();
/// assert_eq!(runtime.timeout(Instant::now()), Some(Duration::ZERO));
/// runtime.run_ready();
/// // Wait using runtime.interests() and runtime.timeout(), then hand the
/// // reported readiness to runtime.process(now, |fd, writable| ...).
/// runtime.shutdown(|| ());
/// ```
pub struct Runtime<E = ()> {
    reactor: Rc<Reactor>,
    tasks: Tasks<E>,
}

enum Tasks<E> {
    Owner(Rc<TaskState<E>>),
    Handle(Weak<TaskState<E>>),
}

struct TaskState<E> {
    executor: Executor<E>,
    running: Cell<bool>,
    closed: Cell<bool>,
}

impl<E> Default for Runtime<E> {
    fn default() -> Self {
        Self {
            reactor: Reactor::new(),
            tasks: Tasks::Owner(Rc::new(TaskState {
                executor: Executor::default(),
                running: Cell::new(false),
                closed: Cell::new(false),
            })),
        }
    }
}

impl Runtime<()> {
    /// Create a runtime with `()` as its cancellation status.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<E: 'static> Runtime<E> {
    /// A non-owning handle with the same runtime API, suitable for capturing in
    /// tasks. Handles never keep the task registry alive; once the owner is
    /// dropped, spawning returns `RuntimeClosed` and driving is a no-op.
    pub fn handle(&self) -> Self {
        let tasks = match &self.tasks {
            Tasks::Owner(state) => Rc::downgrade(state),
            Tasks::Handle(state) => state.clone(),
        };
        Self { reactor: self.reactor.clone(), tasks: Tasks::Handle(tasks) }
    }

    fn task_state(&self) -> Option<Rc<TaskState<E>>> {
        match &self.tasks {
            Tasks::Owner(state) => Some(state.clone()),
            Tasks::Handle(state) => state.upgrade(),
        }
    }

    /// Schedule a task, delivering its result or cancellation to `on_complete`.
    /// Use `|_| {}` for a detached task. Tasks spawned during a poll or callback
    /// join the same ready queue, without any host adoption or notification.
    ///
    /// After shutdown, returns `RuntimeClosed` and drops both arguments without
    /// polling the future or calling the callback.
    pub fn spawn<T: 'static>(
        &self,
        future: impl Future<Output = T> + 'static,
        on_complete: impl FnOnce(Result<T, E>) + 'static,
    ) -> Result<(), RuntimeClosed> {
        let state = self.task_state().ok_or(RuntimeClosed)?;
        if state.closed.get() {
            return Err(RuntimeClosed);
        }
        state.executor.spawn(future, on_complete);
        Ok(())
    }

    /// Run scheduled tasks, delivering completed results exactly once. A
    /// per-turn budget bounds self-waking tasks; remaining work makes `timeout`
    /// return zero. Reentrant calls leave execution to the outer driver.
    pub fn run_ready(&self) {
        let Some(state) = self.task_state() else { return };
        if state.closed.get() || state.running.replace(true) {
            return;
        }
        struct Running<'a>(&'a Cell<bool>);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _running = Running(&state.running);
        let budget = state.executor.active_count().saturating_mul(4).saturating_add(16);
        for _ in 0..budget {
            if state.closed.get() {
                break;
            }
            let Some(id) = state.executor.pop_ready() else { break };
            if state.executor.poll(id) {
                state.executor.finish(id, Ok(()));
            }
        }
    }

    /// One host-loop turn: publish fd readiness, wake due timers, and execute
    /// scheduled tasks. `ready(fd, writable)` queries the host's readiness sets.
    /// Pass `None` for `now` to skip non-fd timers for this turn.
    pub fn process(&self, now: impl Into<Option<Instant>>, ready: impl Fn(i32, bool) -> bool) {
        let Some(state) = self.task_state() else { return };
        if state.closed.get() {
            return;
        }
        self.reactor.set_ready_fds_with(ready);
        if let Some(now) = now.into() {
            self.reactor.advance_timers(now);
        }
        self.run_ready();
    }

    /// Like [`process`](Self::process), using an indexed list of
    /// `(fd, readable, writable)` events instead of scanning all sources.
    pub fn process_events(&self, now: impl Into<Option<Instant>>, events: impl IntoIterator<Item = (i32, bool, bool)>) {
        let Some(state) = self.task_state() else { return };
        if state.closed.get() {
            return;
        }
        self.reactor.set_ready_fds(events);
        if let Some(now) = now.into() {
            self.reactor.advance_timers(now);
        }
        self.run_ready();
    }

    /// Every `(fd, wants_write)` that a live socket future is waiting on.
    pub fn interests(&self) -> Vec<(i32, bool)> {
        self.reactor.interests()
    }

    /// Time until the host should drive the runtime again. Runnable tasks always
    /// return zero, even before their first poll has registered any I/O or timer.
    /// `None` means no task is runnable and no timer is registered.
    pub fn timeout(&self, now: Instant) -> Option<Duration> {
        let state = self.task_state()?;
        if state.closed.get() {
            return None;
        }
        if state.executor.has_ready() {
            return Some(Duration::ZERO);
        }
        self.reactor.next_deadline().map(|when| when.saturating_duration_since(now))
    }

    /// Number of tasks that have not yet completed or been cancelled.
    pub fn active_count(&self) -> usize {
        self.task_state().map_or(0, |state| state.executor.active_count())
    }

    /// Permanently stop accepting tasks and cancel each pending task with a
    /// fresh status from `cancelled`. Repeated or reentrant shutdown is a no-op.
    /// A task currently being polled receives cancellation when its poll returns.
    pub fn shutdown(&self, cancelled: impl FnMut() -> E) {
        let Some(state) = self.task_state() else { return };
        if state.closed.replace(true) {
            return;
        }
        state.executor.cancel_all(cancelled);
    }

    /// Cancel the current tasks while keeping the runtime usable. Tasks spawned
    /// by cancellation callbacks are new work and are not part of this batch.
    pub fn cancel_all(&self, cancelled: impl FnMut() -> E) {
        let Some(state) = self.task_state() else { return };
        if !state.closed.get() {
            state.executor.cancel_all(cancelled);
        }
    }

    /// Enable incremental interest reporting for a persistent host poller.
    pub fn enable_change_tracking(&self) {
        self.reactor.enable_change_tracking();
    }

    /// Drain changes to socket interests since the previous call.
    pub fn take_interest_changes(&self) -> InterestChanges {
        self.reactor.take_interest_changes()
    }

    /// Create a timer that owns its registration and can be moved into a task.
    pub fn timer_at(&self, when: Instant) -> Timer {
        Timer::at(&self.reactor, when)
    }

    /// Register an existing socket with this runtime.
    pub fn register_socket(&self, sock: Rc<dyn Socket>) -> Rc<AsyncSocket> {
        AsyncSocket::new(sock, &self.reactor)
    }

    /// Create and register a UDP socket over the built-in system I/O.
    pub fn create_udp(&self, bind: SocketAddr) -> io::Result<Rc<AsyncSocket>> {
        Ok(self.register_socket(super::system::create(SocketKind::Udp, bind)?))
    }

    /// Create and register a TCP socket over the built-in system I/O.
    pub fn create_tcp(&self, bind: SocketAddr) -> io::Result<Rc<AsyncSocket>> {
        Ok(self.register_socket(super::system::create(SocketKind::Tcp, bind)?))
    }

    /// Connect a TCP socket by `deadline`, checking `SO_ERROR` after writability.
    /// Async tasks can call this through a non-owning runtime handle.
    pub async fn connect_tcp(
        &self,
        remote: SocketAddr,
        deadline: Instant,
    ) -> io::Result<Rc<AsyncSocket>> {
        let local = if remote.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let sock = self.create_tcp(local)?;
        sock.get_ref().connect(remote)?;
        self.reactor.wait_until(sock.writable(), deadline).await?;
        if let Some(err) = sock.get_ref().take_error()? {
            return Err(err);
        }
        Ok(sock)
    }

    /// Create and register a socket through a caller-supplied factory. The
    /// application chooses the factory per socket; the runtime stores none.
    pub fn create_custom_socket(
        &self,
        kind: SocketKind,
        bind: SocketAddr,
        factory: Rc<dyn SocketFactory>,
    ) -> io::Result<Rc<AsyncSocket>> {
        let sock = match kind {
            SocketKind::Tcp => factory.create_tcp(bind)?,
            SocketKind::Udp => factory.create_udp(bind)?,
        };
        Ok(self.register_socket(sock))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::future::{pending, poll_fn};
    use std::task::{Poll, Waker};

    #[test]
    fn spawn_schedules_and_completes_without_manual_polling() {
        let rt = Runtime::new();
        let result = Rc::new(Cell::new(None));
        let delivered = result.clone();
        rt.spawn(async { 42 }, move |value| delivered.set(Some(value))).unwrap();

        assert_eq!(result.get(), None, "spawn must not poll inline");
        assert_eq!(rt.active_count(), 1);
        assert_eq!(rt.timeout(Instant::now()), Some(Duration::ZERO));
        rt.process(Instant::now(), |_, _| false);
        assert_eq!(result.get(), Some(Ok(42)));
        assert_eq!(rt.active_count(), 0);
        assert_eq!(rt.timeout(Instant::now()), None);
        rt.run_ready(); // Completed futures must never be polled again.
    }

    #[test]
    fn nested_tasks_and_callback_tasks_run_in_the_same_turn() {
        let rt = Rc::new(Runtime::new());
        let weak = Rc::downgrade(&rt);
        let completed = Rc::new(Cell::new(0));
        let child_completed = completed.clone();
        let callback_rt = weak.clone();
        let callback_completed = completed.clone();
        rt.spawn(
            async move {
                let rt = weak.upgrade().unwrap();
                rt.spawn(
                    async move {
                        // A second generation of detached tasks must also run
                        // without another host event to adopt them.
                        let rt = weak.upgrade().unwrap();
                        rt.spawn(async {}, move |result| {
                            assert_eq!(result, Ok(()));
                            child_completed.set(child_completed.get() + 1);
                        }).unwrap();
                    },
                    |_| {},
                ).unwrap();
            },
            move |result| {
                assert_eq!(result, Ok(()));
                let rt = callback_rt.upgrade().unwrap();
                rt.spawn(async {}, move |result| {
                    assert_eq!(result, Ok(()));
                    callback_completed.set(callback_completed.get() + 1);
                }).unwrap();
                rt.run_ready();
            },
        ).unwrap();

        rt.run_ready();
        assert_eq!(completed.get(), 2);
        assert_eq!(rt.active_count(), 0);
        assert_eq!(rt.timeout(Instant::now()), None);
    }

    #[test]
    fn reentrant_driving_preserves_wakes_and_allows_slot_growth() {
        let rt = Rc::new(Runtime::new());
        let weak = Rc::downgrade(&rt);
        let polls = Rc::new(Cell::new(0));
        let polled = polls.clone();
        let completed = Rc::new(Cell::new(0));
        let children = completed.clone();
        rt.spawn(
            poll_fn(move |cx| {
                let count = polled.get() + 1;
                polled.set(count);
                if count == 2 {
                    return Poll::Ready(());
                }
                assert_eq!(count, 1);
                let rt = weak.upgrade().unwrap();
                // Grow the task table while the parent's future is on the
                // stack, and enqueue a wake for the currently running task.
                for _ in 0..64 {
                    let completed = children.clone();
                    rt.spawn(async {}, move |result| {
                        assert_eq!(result, Ok(()));
                        completed.set(completed.get() + 1);
                    }).unwrap();
                }
                cx.waker().wake_by_ref();
                cx.waker().wake_by_ref();
                rt.process(Instant::now(), |_, _| false);
                Poll::Pending
            }),
            |result| assert_eq!(result, Ok(())),
        ).unwrap();

        rt.run_ready();
        // A turn is bounded even when a task starts many children. Subsequent
        // turns need no fd event: the runtime reports an immediate timeout.
        while rt.timeout(Instant::now()) == Some(Duration::ZERO) {
            rt.run_ready();
        }
        assert_eq!(polls.get(), 2);
        assert_eq!(completed.get(), 64);
        assert_eq!(rt.active_count(), 0);
    }

    #[test]
    fn shutdown_during_poll_cancels_once_and_rejects_callback_spawns() {
        // Deliberately not Clone: each task gets its own cancellation value.
        #[derive(Debug, PartialEq)]
        struct Cancelled;

        let rt = Rc::new(Runtime::<Cancelled>::default());
        let weak = Rc::downgrade(&rt);
        let callbacks = Rc::new(Cell::new(0));
        let delivered = callbacks.clone();
        let callback_rt = weak.clone();
        rt.spawn(
            poll_fn(move |_| {
                weak.upgrade().unwrap().shutdown(|| Cancelled);
                Poll::Ready(42)
            }),
            move |result| {
                assert_eq!(result, Err(Cancelled), "cancellation wins over completion");
                delivered.set(delivered.get() + 1);
                let rt = callback_rt.upgrade().unwrap();
                assert_eq!(rt.spawn(async { panic!("rejected task polled") }, |_| {
                    panic!("rejected task callback called");
                }), Err(RuntimeClosed));
                rt.shutdown(|| panic!("reentrant shutdown"));
                rt.run_ready();
            },
        ).unwrap();
        let delivered = callbacks.clone();
        rt.spawn(async { panic!("cancelled task polled") }, move |result: Result<(), _>| {
            assert_eq!(result, Err(Cancelled));
            delivered.set(delivered.get() + 1);
        }).unwrap();

        rt.run_ready();
        rt.shutdown(|| panic!("repeated shutdown"));
        rt.process(Instant::now(), |_, _| panic!("closed runtime dispatched I/O"));
        assert_eq!(callbacks.get(), 2);
        assert_eq!(rt.active_count(), 0);
        assert_eq!(rt.timeout(Instant::now()), None);
    }

    #[test]
    fn stale_wakes_cannot_poll_a_replacement_task() {
        let rt = Runtime::new();
        let saved = Rc::new(RefCell::new(None::<Waker>));
        let waker = saved.clone();
        let mut first = true;
        rt.spawn(poll_fn(move |cx| {
            if first {
                first = false;
                *waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            } else {
                cx.waker().wake_by_ref(); // Also leaves a stale queued wake.
                Poll::Ready(())
            }
        }), |result| assert_eq!(result, Ok(()))).unwrap();
        rt.run_ready();
        let stale = saved.borrow_mut().take().unwrap();
        stale.wake_by_ref();
        rt.run_ready();

        let polls = Rc::new(Cell::new(0));
        let polled = polls.clone();
        rt.spawn(poll_fn(move |_| {
            polled.set(polled.get() + 1);
            Poll::<()>::Pending
        }), |_| {}).unwrap();
        rt.run_ready();
        stale.wake_by_ref();
        rt.run_ready();
        assert_eq!(polls.get(), 1);
        rt.shutdown(|| ());
    }

    struct TestSocket;

    impl Socket for TestSocket {
        fn as_raw_fd(&self) -> i32 {
            11
        }
        fn connect(&self, _: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            buf[0] = 42;
            Ok(1)
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }
    }

    #[test]
    fn process_drives_io_and_shutdown_removes_timer_registrations() {
        // Exercise both host readiness APIs with the same assertions.
        for indexed in [false, true] {
            let rt = Runtime::new();
            let now = Instant::now();
            let deadline = now + Duration::from_secs(60);
            let timer = rt.timer_at(deadline);
            let cancellations = Rc::new(Cell::new(0));
            let cancelled = cancellations.clone();
            rt.spawn(timer, move |result| {
                assert_eq!(result, Err(()));
                cancelled.set(cancelled.get() + 1);
            }).unwrap();

            let sock = rt.register_socket(Rc::new(TestSocket));
            let socket = Rc::downgrade(&sock);
            let received = Rc::new(Cell::new(None));
            let result = received.clone();
            rt.spawn(async move {
                let mut buf = [0];
                assert_eq!(sock.read(&mut buf, deadline).await.unwrap(), 1);
                buf[0]
            }, move |value| result.set(Some(value))).unwrap();
            rt.run_ready();
            assert_eq!(rt.interests(), vec![(11, false)]);
            assert_eq!(rt.timeout(now), Some(Duration::from_secs(60)));
            assert_eq!(received.get(), None);

            if indexed {
                rt.process_events(now, [(11, true, false)]);
            } else {
                rt.process(now, |fd, writable| fd == 11 && !writable);
            }
            assert_eq!(received.get(), Some(Ok(42)));
            assert!(rt.interests().is_empty());
            assert!(socket.upgrade().is_none());
            assert_eq!(rt.active_count(), 1);
            assert_eq!(rt.timeout(now), Some(Duration::from_secs(60)));

            rt.shutdown(|| ());
            assert_eq!(cancellations.get(), 1);
            assert!(rt.reactor.next_deadline().is_none());
            assert_eq!(rt.timeout(now), None);
        }
    }

    #[test]
    fn already_due_timer_completes_and_releases_its_task() {
        let rt = Runtime::new();
        let now = Instant::now();
        let completed = Rc::new(Cell::new(false));
        let result = completed.clone();
        rt.spawn(rt.timer_at(now), move |value| {
            assert_eq!(value, Ok(()));
            result.set(true);
        }).unwrap();
        rt.process(now, |_, _| false);
        assert!(completed.get());
        assert_eq!(rt.active_count(), 0);
        assert_eq!(rt.timeout(now), None);
    }

    #[test]
    fn dropping_runtime_releases_pending_tasks_and_their_io_state() {
        let rt = Runtime::new();
        let reactor = Rc::downgrade(&rt.reactor);
        let sock = rt.register_socket(Rc::new(TestSocket));
        let socket = Rc::downgrade(&sock);
        let timer = rt.timer_at(Instant::now() + Duration::from_secs(60));
        rt.spawn(async move {
            timer.await;
            drop(sock);
            pending::<()>().await;
        }, |_| panic!("drop does not deliver cancellation callbacks")).unwrap();
        rt.run_ready();
        assert!(socket.upgrade().is_some());
        drop(rt);
        assert!(socket.upgrade().is_none());
        assert!(reactor.upgrade().is_none(), "tasks must not keep the runtime alive");
    }

    #[test]
    fn handles_share_scheduling_without_retaining_the_owner() {
        let rt = Runtime::new();
        let handle = rt.handle();
        let child_handle = handle.handle();
        let state = Rc::downgrade(&rt.task_state().unwrap());
        let dropped = Rc::new(());
        let held = dropped.clone();
        handle.spawn(async move {
            let _held = held;
            child_handle.spawn(pending::<()>(), |_| {}).unwrap();
            pending::<()>().await;
        }, |_| panic!("drop must not call callbacks")).unwrap();
        handle.run_ready();
        assert_eq!(rt.active_count(), 2);
        drop(rt);
        assert!(state.upgrade().is_none(), "captured handles must not form a task cycle");
        assert_eq!(Rc::strong_count(&dropped), 1);
        assert_eq!(handle.spawn(async {}, |_| {}), Err(RuntimeClosed));
        handle.run_ready();
        assert_eq!(handle.active_count(), 0);
        assert_eq!(handle.timeout(Instant::now()), None);
    }

    #[test]
    fn cancellation_snapshot_survives_reentry_and_slot_reuse() {
        let rt = Runtime::<u8>::default();
        let handle = rt.handle();
        let results = Rc::new(RefCell::new(Vec::new()));
        let delivered = results.clone();
        rt.spawn(pending::<()>(), move |result| {
            delivered.borrow_mut().push((0, result));
            handle.cancel_all(|| 2);
            // Reuse all the slots from the outer cancellation snapshot.
            for id in 3..6 {
                let delivered = delivered.clone();
                handle.spawn(pending::<()>(), move |result| {
                    delivered.borrow_mut().push((id, result));
                }).unwrap();
            }
        }).unwrap();
        for id in 1..3 {
            let delivered = results.clone();
            rt.spawn(pending::<()>(), move |result| {
                delivered.borrow_mut().push((id, result));
            }).unwrap();
        }
        rt.cancel_all(|| 1);
        assert_eq!(*results.borrow(), vec![(0, Err(1)), (1, Err(2)), (2, Err(2))]);
        assert_eq!(rt.active_count(), 3, "new tasks must survive the outer cancel");
        rt.run_ready();
        rt.shutdown(|| 3);
        assert_eq!(&results.borrow()[3..], &[(3, Err(3)), (4, Err(3)), (5, Err(3))]);
    }

    #[test]
    fn self_waking_task_is_bounded_and_requests_an_immediate_next_turn() {
        let rt = Runtime::new();
        let polls = Rc::new(Cell::new(0));
        let polled = polls.clone();
        rt.spawn(poll_fn(move |cx| {
            polled.set(polled.get() + 1);
            cx.waker().wake_by_ref();
            Poll::<()>::Pending
        }), |_| {}).unwrap();
        rt.run_ready();
        assert_eq!(polls.get(), 20);
        assert_eq!(rt.timeout(Instant::now()), Some(Duration::ZERO));
        rt.run_ready();
        assert_eq!(polls.get(), 40);
        rt.cancel_all(|| ());
        rt.run_ready();
        assert_eq!(rt.timeout(Instant::now()), None);
    }

    #[test]
    fn process_can_skip_non_fd_timers() {
        for indexed in [false, true] {
            let rt = Runtime::new();
            let when = Instant::now() + Duration::from_secs(60);
            let mut timer = Box::pin(rt.timer_at(when));
            let polls = Rc::new(Cell::new(0));
            let polled = polls.clone();
            rt.spawn(poll_fn(move |cx| {
                polled.set(polled.get() + 1);
                timer.as_mut().poll(cx)
            }), |_| {}).unwrap();
            rt.run_ready();
            if indexed {
                rt.process_events(None, []);
            } else {
                rt.process(None, |_, _| false);
            }
            assert_eq!(polls.get(), 1, "skipped timers must not wake tasks");
            if indexed {
                rt.process_events(when, []);
            } else {
                rt.process(when, |_, _| false);
            }
            assert_eq!(polls.get(), 2, "normal turns must wake due timers");
        }
    }
}
