//! Single-threaded task executor (≈ async-executor's `LocalExecutor`, ticked
//! by the host once per `ares_process*` turn instead of by a thread). Tasks get
//! real wakers, so any `std` future combinator works. No DNS/framing knowledge.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};

/// One in-flight task with its output type erased, so one `Executor` drives
/// futures of many output types side by side.
trait AbstractTask<E> {
    /// Poll once; on `Ready`, stash the output and return `true`.
    fn poll(&mut self, cx: &mut Context<'_>) -> bool;
    /// Consume the task, delivering the stashed output or a cancel status.
    fn finish(self: Box<Self>, status: Result<(), E>);
}

/// Concrete task: future and result-delivery closure (`Ok` on completion,
/// `Err(status)` on cancel).
struct Task<T, E> {
    fut: Pin<Box<dyn Future<Output = T>>>,
    out: Option<T>,
    on: Box<dyn FnOnce(Result<T, E>)>,
}

impl<T, E> AbstractTask<E> for Task<T, E> {
    fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        match self.fut.as_mut().poll(cx) {
            Poll::Ready(v) => {
                self.out = Some(v);
                true
            }
            Poll::Pending => false,
        }
    }
    fn finish(self: Box<Self>, status: Result<(), E>) {
        let this = *self;
        let result = match (status, this.out) {
            (Err(status), _) => Err(status),
            (Ok(()), Some(out)) => Ok(out),
            // Unreachable by construction: the host only finishes with `Ok`
            // after `poll` returned `true`; degrade rather than panic.
            (Ok(()), None) => return,
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

struct Slot<E> {
    /// `None` while the task is being polled: [`Executor::poll`] moves it onto
    /// the stack, so nothing that runs during the poll can free or move it.
    task: Option<Box<dyn AbstractTask<E>>>,
    /// A cancel that arrived while the task was being polled, applied when the
    /// poll returns.
    cancel: Option<E>,
    flag: Arc<TaskWaker>,
    waker: Waker,
}

/// In-flight tasks in reused slots (`None` = reaped) plus the runnable queue
/// (≈ async-executor's `LocalExecutor`, ticked by the host instead of a thread).
///
/// Re-entrant use is safe: a C callback that fires during a poll may call back
/// into the channel, and so into this executor (`spawn` may grow `slots`,
/// `finish` may target the running task). The mutable state sits behind a
/// `RefCell` and no borrow is held across a future poll or a delivery callback,
/// so a re-entrant call always observes the current table; nothing caches a
/// pointer into `slots` that a re-entrant `spawn` could invalidate.
pub(super) struct Executor<E = ()> {
    inner: RefCell<ExecutorInner<E>>,
}

struct ExecutorInner<E> {
    slots: Vec<Option<Slot<E>>>,
    queue: RunQueue,
    next_gen: u32,
}

impl<E> Default for Executor<E> {
    fn default() -> Self {
        Executor { inner: RefCell::new(ExecutorInner::default()) }
    }
}

impl<E> Default for ExecutorInner<E> {
    fn default() -> Self {
        ExecutorInner { slots: Vec::new(), queue: RunQueue::default(), next_gen: 0 }
    }
}

#[cfg(test)]
impl Executor<()> {
    /// A default executor whose cancellation status is `()`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<E: 'static> Executor<E> {
    /// Register and schedule `fut` in a free slot; does not poll.
    pub fn spawn<T: 'static>(
        &self,
        fut: impl Future<Output = T> + 'static,
        on: impl FnOnce(Result<T, E>) + 'static,
    ) -> usize {
        let mut inner = self.inner.borrow_mut();
        let task: Box<dyn AbstractTask<E>> = Box::new(Task { fut: Box::pin(fut), out: None, on: Box::new(on) });
        let id = inner.slots.iter().position(|s| s.is_none()).unwrap_or(inner.slots.len());
        // A generation per spawn: a stale waker for a reaped occupant of this
        // slot must not poll the new one.
        inner.next_gen = inner.next_gen.wrapping_add(1);
        let flag = Arc::new(TaskWaker {
            id,
            gen: inner.next_gen,
            scheduled: AtomicBool::new(false),
            queue: inner.queue.clone(),
        });
        let waker = Waker::from(flag.clone());
        // The first poll uses the same queue as every subsequent wake. Tasks
        // spawned during a poll need no separate adoption or notification.
        waker.wake_by_ref();
        let slot = Some(Slot { task: Some(task), cancel: None, flag, waker });
        match inner.slots.get_mut(id) {
            Some(s) => *s = slot,
            None => inner.slots.push(slot),
        }
        id
    }

    /// Pop the next runnable live task, skipping stale or reaped entries. The
    /// queue lock is released before returning, so the poll that follows may wake.
    pub fn pop_ready(&self) -> Option<usize> {
        let inner = self.inner.borrow();
        loop {
            let (id, gen) = inner.queue.lock().unwrap_or_else(PoisonError::into_inner).pop_front()?;
            if inner.slots.get(id).and_then(|s| s.as_ref()).is_some_and(|s| s.flag.gen == gen) {
                return Some(id);
            }
        }
    }

    /// Whether any woken task is waiting to be polled.
    pub fn has_ready(&self) -> bool {
        !self.inner.borrow().queue.lock().unwrap_or_else(PoisonError::into_inner).is_empty()
    }

    /// Poll `id` once with its own waker; `true` when it completed. A reaped id
    /// yields `false`. If the task was cancelled during the poll, it is
    /// delivered with that status here and the call returns `false`.
    pub fn poll(&self, id: usize) -> bool {
        let (mut task, waker) = {
            let mut inner = self.inner.borrow_mut();
            let Some(slot) = inner.slots.get_mut(id).and_then(|s| s.as_mut()) else {
                return false;
            };
            let Some(task) = slot.task.take() else {
                // Already being polled further up the stack (a re-entrant turn):
                // re-queue it so this wake isn't lost.
                slot.flag.scheduled.store(false, Ordering::Release);
                slot.waker.wake_by_ref();
                return false;
            };
            // Cleared before the poll so a wake during it re-queues the task.
            slot.flag.scheduled.store(false, Ordering::Release);
            (task, slot.waker.clone())
        };
        // No borrow of `inner` is held here: the task may re-enter the channel,
        // spawning tasks that grow `slots` and delivering this very id.
        let done = task.poll(&mut Context::from_waker(&waker));
        // Re-read the table after the poll; a re-entrant spawn may have moved it.
        let status = {
            let mut inner = self.inner.borrow_mut();
            let Some(entry) = inner.slots.get_mut(id) else { return false };
            let Some(slot) = entry.as_mut() else { return false };
            match slot.cancel.take() {
                Some(status) => {
                    *entry = None;
                    Err(status)
                }
                None => {
                    slot.task = Some(task);
                    return done;
                }
            }
        };
        // The delivery callback may itself re-enter; call it unborrowed.
        task.finish(status);
        false
    }

    /// Reap `id` and deliver its output or cancel status; an already-reaped id
    /// is a no-op (a re-entrant cancel cannot double-deliver). A cancel aimed
    /// at a task that is being polled is recorded and applied when its poll
    /// returns.
    ///
    /// `Ok(())` means the task completed and its stashed output is delivered.
    /// `Err(status)` means cancel it; the callback receives `Err(status)`.
    pub fn finish(&self, id: usize, status: Result<(), E>) {
        let task = {
            let mut inner = self.inner.borrow_mut();
            let Some(entry) = inner.slots.get_mut(id) else { return };
            if let Some(slot) = entry.as_mut().filter(|slot| slot.task.is_none()) {
                if let Err(status) = status {
                    slot.cancel.get_or_insert(status);
                }
                return;
            }
            entry.take().and_then(|slot| slot.task)
        };
        // The delivery callback may itself re-enter; call it unborrowed.
        if let Some(task) = task {
            task.finish(status);
        }
    }

    /// Cancel a snapshot of live tasks. Generations prevent callbacks that
    /// cancel and reuse a slot from accidentally cancelling its new occupant.
    pub fn cancel_all(&self, mut cancelled: impl FnMut() -> E) {
        let tasks: Vec<_> = self.inner.borrow().slots.iter().enumerate()
            .filter_map(|(id, slot)| slot.as_ref().map(|s| (id, s.flag.gen)))
            .collect();
        for (id, gen) in tasks {
            let status = cancelled();
            let live = self.inner.borrow().slots.get(id).and_then(Option::as_ref)
                .is_some_and(|s| s.flag.gen == gen);
            if live {
                self.finish(id, Err(status));
            }
        }
    }

    /// Number of live tasks.
    pub fn active_count(&self) -> usize {
        self.inner.borrow().slots.iter().filter(|s| s.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use std::rc::Rc;

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
        let ex = Executor::new();
        let w = Rc::new(RefCell::new(None));
        let id = ex.spawn(wake_later(w.clone()), |_| {});
        assert_eq!(ex.pop_ready(), Some(id));
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
        let ex = Executor::<i32>::default();
        let w = Rc::new(RefCell::new(None));
        let id = ex.spawn(wake_later(w.clone()), |_| {});
        assert_eq!(ex.pop_ready(), Some(id));
        assert!(!ex.poll(id));
        let stale = w.borrow_mut().take().expect("registered waker");
        ex.finish(id, Err(1));
        let id2 = ex.spawn(std::future::pending::<()>(), |_| {});
        assert_eq!(id, id2, "slot reused");
        assert_eq!(ex.pop_ready(), Some(id2));
        stale.wake();
        assert_eq!(ex.pop_ready(), None, "stale generation must be skipped");
    }
}
