//! Readiness-driven, no-op-waker executor: arms re-register waits each poll, so
//! use only re-polling combinators (`select_biased!`, `.await`);
//! `FuturesUnordered`/`for_each_concurrent` wedge. No DNS/framing knowledge.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Instant;

/// One fd the future is blocked on, with the interest it awaits.
#[derive(Clone, Copy)]
pub(crate) struct Wait {
    pub fd: i32,
    pub writable: bool,
}

/// Mailbox shared (`Rc<RefCell<_>>`) between one lifecycle future and the
/// executor; `app` is opaque host state the reactor never inspects.
#[derive(Default)]
pub(crate) struct Mailbox<A> {
    pub waits: Vec<Wait>,
    pub timeout: Option<Instant>,
    /// Readiness set by the executor. Carries read vs write interest, so a
    /// sibling arm on the same fd with opposite interest doesn't consume it.
    pub fired: Vec<Wait>,
    /// Reusable receive scratch (grown to 64 KB by `conn`), borrowed only for
    /// one synchronous recv — avoids zeroing 64 KB per call.
    pub scratch: Vec<u8>,
    pub app: A,
}

/// Resolves once `timeout` passes; otherwise mins it into the mailbox and
/// suspends. Reads `Instant::now()` directly so arms on one mailbox self-demux.
fn poll_timeout<A>(io: &Rc<RefCell<Mailbox<A>>>, timeout: Instant) -> Poll<()> {
    if Instant::now() >= timeout {
        return Poll::Ready(());
    }
    let mut m = io.borrow_mut();
    m.timeout = Some(m.timeout.map_or(timeout, |d| d.min(timeout)));
    Poll::Pending
}

/// Sleep until `timeout`, usable as a `select_biased!` arm.
pub(crate) fn sleep_until<A>(
    io: &Rc<RefCell<Mailbox<A>>>,
    timeout: Instant,
) -> impl Future<Output = ()> + '_ {
    poll_fn(move |_| poll_timeout(io, timeout))
}

/// One in-flight task with its output type erased, so one `Executor` drives
/// futures of many output types side by side.
trait AbstractTask<A> {
    fn io(&self) -> &Rc<RefCell<Mailbox<A>>>;
    /// Poll once; on `Ready`, stash the output and return `true`.
    fn poll(&mut self, cx: &mut Context<'_>) -> bool;
    /// Consume the task, delivering the stashed output or a cancel status.
    fn deliver(self: Box<Self>, cancel: Option<i32>);
}

/// Concrete task: mailbox, future, and result-delivery closure (`Ok` on
/// completion, `Err(status)` on cancel).
struct Task<A, T> {
    io: Rc<RefCell<Mailbox<A>>>,
    fut: Pin<Box<dyn Future<Output = T>>>,
    out: Option<T>,
    on: Box<dyn FnOnce(Result<T, i32>)>,
}

impl<A, T> AbstractTask<A> for Task<A, T> {
    fn io(&self) -> &Rc<RefCell<Mailbox<A>>> {
        &self.io
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        match self.fut.as_mut().poll(cx) {
            Poll::Ready(v) => {
                self.out = Some(v);
                true
            }
            Poll::Pending => false,
        }
    }
    fn deliver(self: Box<Self>, cancel: Option<i32>) {
        let this = *self;
        let result = match (cancel, this.out) {
            (Some(status), _) => Err(status),
            (None, Some(out)) => Ok(out),
            // Unreachable by construction: the host only delivers `None` after
            // `poll` returned `true`; degrade rather than panic.
            (None, None) => return,
        };
        (this.on)(result);
    }
}

/// The runnable queue: `(slot, generation)` pairs pushed by wakers.
type RunQueue = Arc<Mutex<VecDeque<(usize, u32)>>>;

/// One task's waker (≈ async-task's header): waking queues the task once until
/// its next poll. `Send + Sync` only because `Wake` demands it; every wake
/// happens on the thread holding the channel lock.
struct TaskWaker {
    id: usize,
    gen: u32,
    scheduled: AtomicBool,
    queue: RunQueue,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if !self.scheduled.swap(true, Ordering::AcqRel) {
            self.queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back((self.id, self.gen));
        }
    }
}

struct Slot<A> {
    task: Box<dyn AbstractTask<A>>,
    flag: Arc<TaskWaker>,
    waker: Waker,
}

/// In-flight tasks in reused slots (`None` = reaped) plus the runnable queue
/// (≈ async-executor's `LocalExecutor`, ticked by the host instead of a thread).
pub(crate) struct Executor<A> {
    slots: Vec<Option<Slot<A>>>,
    queue: RunQueue,
    next_gen: u32,
}

impl<A> Default for Executor<A> {
    fn default() -> Self {
        Executor { slots: Vec::new(), queue: RunQueue::default(), next_gen: 0 }
    }
}

impl<A> Executor<A> {
    /// Register `fut` in a free slot and return its id; does not poll.
    pub(crate) fn spawn<T: 'static>(
        &mut self,
        io: Rc<RefCell<Mailbox<A>>>,
        fut: impl Future<Output = T> + 'static,
        on: impl FnOnce(Result<T, i32>) + 'static,
    ) -> usize
    where
        A: 'static,
    {
        let task: Box<dyn AbstractTask<A>> =
            Box::new(Task { io, fut: Box::pin(fut), out: None, on: Box::new(on) });
        let id = self.slots.iter().position(|s| s.is_none()).unwrap_or(self.slots.len());
        // A generation per spawn: a stale waker for a reaped occupant of this
        // slot must not poll the new one.
        self.next_gen = self.next_gen.wrapping_add(1);
        let flag = Arc::new(TaskWaker {
            id,
            gen: self.next_gen,
            scheduled: AtomicBool::new(false),
            queue: self.queue.clone(),
        });
        let waker = Waker::from(flag.clone());
        let slot = Some(Slot { task, flag, waker });
        match self.slots.get_mut(id) {
            Some(s) => *s = slot,
            None => self.slots.push(slot),
        }
        id
    }

    /// Pop the next runnable live task, skipping stale or reaped entries. The
    /// queue lock is released before returning, so the poll that follows may wake.
    pub(crate) fn pop_ready(&self) -> Option<usize> {
        loop {
            let (id, gen) = self.queue.lock().unwrap_or_else(PoisonError::into_inner).pop_front()?;
            if self.slots.get(id).and_then(|s| s.as_ref()).is_some_and(|s| s.flag.gen == gen) {
                return Some(id);
            }
        }
    }

    /// Whether any woken task is waiting to be polled.
    pub(crate) fn has_ready(&self) -> bool {
        !self.queue.lock().unwrap_or_else(PoisonError::into_inner).is_empty()
    }

    /// `waits`/`timeout` are valid only until the next poll (every pending arm
    /// re-registers), so clear them, then poll once. A reaped id yields `false`.
    pub(crate) fn poll(&mut self, id: usize) -> bool {
        let Some(slot) = self.slots.get_mut(id).and_then(|s| s.as_mut()) else {
            return false;
        };
        {
            let mut m = slot.task.io().borrow_mut();
            m.waits.clear();
            m.timeout = None;
        }
        // Cleared before the poll so a wake during it re-queues the task.
        slot.flag.scheduled.store(false, Ordering::Release);
        let mut cx = Context::from_waker(&slot.waker);
        slot.task.poll(&mut cx)
    }

    /// Task `id`'s mailbox, for the host to drain app-specific signals.
    pub(crate) fn io(&self, id: usize) -> Option<&Rc<RefCell<Mailbox<A>>>> {
        self.slots.get(id).and_then(|s| s.as_ref()).map(|s| s.task.io())
    }

    /// Reap `id` and deliver its output or cancel status; an already-reaped id
    /// is a no-op (a re-entrant abort cannot double-deliver).
    pub(crate) fn deliver(&mut self, id: usize, cancel: Option<i32>) {
        if let Some(slot) = self.slots.get_mut(id).and_then(|s| s.take()) {
            slot.task.deliver(cancel);
        }
    }

    /// Every `(fd, wants_write)` an in-flight future is blocked on.
    pub(crate) fn poll_fds(&self) -> Vec<(i32, bool)> {
        let mut fds = Vec::new();
        for t in self.slots.iter().flatten() {
            for w in &t.task.io().borrow().waits {
                fds.push((w.fd, w.writable));
            }
        }
        fds
    }

    /// The earliest timeout across in-flight futures, in ms from `now`.
    pub(crate) fn next_timeout_ms(&self, now: Instant) -> Option<u128> {
        let mut best: Option<u128> = None;
        for t in self.slots.iter().flatten() {
            if let Some(d) = t.task.io().borrow().timeout {
                let ms = d.saturating_duration_since(now).as_millis();
                best = Some(best.map_or(ms, |b| b.min(ms)));
            }
        }
        best
    }

    /// Set each mailbox's `fired` from `ready` and schedule tasks whose fds
    /// fired or whose timeout expired by `now`. Expiry gates the re-poll but is
    /// not stored — timeout arms read the clock directly.
    pub(crate) fn drive_ready(&mut self, now: Instant, skip_timeouts: bool, ready: impl Fn(i32, bool) -> bool) {
        for slot in self.slots.iter_mut().flatten() {
            let mut m = slot.task.io().borrow_mut();
            let fired: Vec<Wait> = m.waits.iter().copied().filter(|w| ready(w.fd, w.writable)).collect();
            let expired = !skip_timeouts && m.timeout.is_some_and(|d| now >= d);
            if fired.is_empty() && !expired {
                continue;
            }
            m.fired = fired;
            drop(m);
            slot.waker.wake_by_ref();
        }
    }

    /// The id range spanning every slot, live or reaped.
    pub(crate) fn ids(&self) -> std::ops::Range<usize> {
        0..self.slots.len()
    }

    /// Number of live tasks.
    pub(crate) fn active_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn mailbox() -> Rc<RefCell<Mailbox<()>>> {
        Rc::new(RefCell::new(Mailbox::default()))
    }

    #[test]
    fn poll_timeout_future_mins_and_pends() {
        let io = mailbox();
        let far = Instant::now() + Duration::from_secs(60);
        assert!(matches!(poll_timeout(&io, far), Poll::Pending));
        assert_eq!(io.borrow().timeout, Some(far));
        // A nearer timeout mins in.
        let near = Instant::now() + Duration::from_secs(1);
        assert!(matches!(poll_timeout(&io, near), Poll::Pending));
        assert_eq!(io.borrow().timeout, Some(near));
    }

    #[test]
    fn poll_timeout_past_ready() {
        let io = mailbox();
        let past = Instant::now() - Duration::from_secs(1);
        assert!(matches!(poll_timeout(&io, past), Poll::Ready(())));
    }

    /// A future that stores its waker on first poll and completes on the second.
    fn wake_later(slot: Rc<RefCell<Option<Waker>>>) -> impl Future<Output = ()> {
        let mut polled = false;
        poll_fn(move |cx| {
            if polled {
                return Poll::Ready(());
            }
            polled = true;
            *slot.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        })
    }

    #[test]
    fn waker_queues_task_once() {
        let mut ex = Executor::<()>::default();
        let w = Rc::new(RefCell::new(None));
        let id = ex.spawn(mailbox(), wake_later(w.clone()), |_| {});
        assert!(!ex.poll(id));
        let waker = w.borrow_mut().take().expect("registered waker");
        waker.wake_by_ref();
        waker.wake_by_ref(); // deduplicated until the next poll
        assert_eq!(ex.pop_ready(), Some(id));
        assert_eq!(ex.pop_ready(), None);
        assert!(ex.poll(id));
    }

    #[test]
    fn stale_waker_does_not_poll_reused_slot() {
        let mut ex = Executor::<()>::default();
        let w = Rc::new(RefCell::new(None));
        let id = ex.spawn(mailbox(), wake_later(w.clone()), |_| {});
        assert!(!ex.poll(id));
        let stale = w.borrow_mut().take().expect("registered waker");
        ex.deliver(id, Some(1));
        let id2 = ex.spawn(mailbox(), std::future::pending::<()>(), |_| {});
        assert_eq!(id, id2, "slot reused");
        stale.wake();
        assert_eq!(ex.pop_ready(), None, "stale generation must be skipped");
    }

    #[test]
    fn drive_ready_schedules_fired_and_expired() {
        let mut ex = Executor::<()>::default();
        let io = mailbox();
        let id = ex.spawn(io.clone(), std::future::pending::<()>(), |_| {});
        io.borrow_mut().waits.push(Wait { fd: 3, writable: false });
        ex.drive_ready(Instant::now(), true, |fd, w| fd == 3 && !w);
        assert_eq!(ex.pop_ready(), Some(id));
        assert_eq!(io.borrow().fired.len(), 1);
    }
}
