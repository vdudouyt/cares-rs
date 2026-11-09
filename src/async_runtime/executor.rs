//! Single-threaded task executor (≈ async-executor's `LocalExecutor`, ticked
//! by the host once per `ares_process*` turn instead of by a thread). Tasks get
//! real wakers, so any `std` future combinator works. No DNS/framing knowledge.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};

/// One in-flight task with its output type erased, so one `Executor` drives
/// futures of many output types side by side.
trait AbstractTask {
    /// Poll once; on `Ready`, stash the output and return `true`.
    fn poll(&mut self, cx: &mut Context<'_>) -> bool;
    /// Consume the task, delivering the stashed output or a cancel status.
    fn deliver(self: Box<Self>, cancel: Option<i32>);
}

/// Concrete task: future and result-delivery closure (`Ok` on completion,
/// `Err(status)` on cancel).
struct Task<T> {
    fut: Pin<Box<dyn Future<Output = T>>>,
    out: Option<T>,
    on: Box<dyn FnOnce(Result<T, i32>)>,
}

impl<T> AbstractTask for Task<T> {
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

struct Slot {
    /// `None` while the task is being polled: [`Executor::poll`] moves it onto
    /// the stack, so nothing that runs during the poll can free or move it.
    task: Option<Box<dyn AbstractTask>>,
    /// A cancel that arrived while the task was being polled, applied when the
    /// poll returns.
    cancel: Option<i32>,
    flag: Arc<TaskWaker>,
    waker: Waker,
}

/// In-flight tasks in reused slots (`None` = reaped) plus the runnable queue
/// (≈ async-executor's `LocalExecutor`, ticked by the host instead of a thread).
///
/// Re-entrant use is safe: a C callback that fires during a poll may call back
/// into the channel, and so into this executor (`spawn` may grow `slots`,
/// `deliver` may target the running task). The poll holds no reference into
/// `slots`, and a `deliver` aimed at the running task only records the cancel.
#[derive(Default)]
pub(crate) struct Executor {
    slots: Vec<Option<Slot>>,
    queue: RunQueue,
    next_gen: u32,
}

impl Executor {
    /// Register `fut` in a free slot and return its id; does not poll.
    pub(crate) fn spawn<T: 'static>(
        &mut self,
        fut: impl Future<Output = T> + 'static,
        on: impl FnOnce(Result<T, i32>) + 'static,
    ) -> usize {
        let task: Box<dyn AbstractTask> = Box::new(Task { fut: Box::pin(fut), out: None, on: Box::new(on) });
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
        let slot = Some(Slot { task: Some(task), cancel: None, flag, waker });
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

    /// Poll `id` once with its own waker; `true` when it completed. A reaped id
    /// yields `false`. If the task was cancelled during the poll, it is
    /// delivered with that status here and the call returns `false`.
    pub(crate) fn poll(&mut self, id: usize) -> bool {
        let Some(slot) = self.slots.get_mut(id).and_then(|s| s.as_mut()) else {
            return false;
        };
        let Some(mut task) = slot.task.take() else {
            // Already being polled further up the stack (a re-entrant turn):
            // re-queue it so this wake isn't lost.
            slot.flag.scheduled.store(false, Ordering::Release);
            slot.waker.wake_by_ref();
            return false;
        };
        // Cleared before the poll so a wake during it re-queues the task.
        slot.flag.scheduled.store(false, Ordering::Release);
        let waker = slot.waker.clone();
        let done = task.poll(&mut Context::from_waker(&waker));
        // Look the slot up again: a re-entrant spawn may have moved `slots`.
        // (A running slot is never reaped or reused, so it is still there.)
        let Some(entry) = self.slots.get_mut(id) else { return false };
        let Some(slot) = entry.as_mut() else { return false };
        if let Some(status) = slot.cancel.take() {
            *entry = None;
            task.deliver(Some(status));
            return false;
        }
        slot.task = Some(task);
        done
    }

    /// Reap `id` and deliver its output or cancel status; an already-reaped id
    /// is a no-op (a re-entrant abort cannot double-deliver). A cancel aimed at
    /// a task that is being polled is recorded and applied when its poll returns.
    pub(crate) fn deliver(&mut self, id: usize, cancel: Option<i32>) {
        let Some(entry) = self.slots.get_mut(id) else { return };
        if let Some(slot) = entry.as_mut().filter(|slot| slot.task.is_none()) {
            if let Some(status) = cancel {
                slot.cancel.get_or_insert(status);
            }
            return;
        }
        if let Some(task) = entry.take().and_then(|slot| slot.task) {
            task.deliver(cancel);
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
    use std::cell::RefCell;
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
        let mut ex = Executor::default();
        let w = Rc::new(RefCell::new(None));
        let id = ex.spawn(wake_later(w.clone()), |_| {});
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
        let mut ex = Executor::default();
        let w = Rc::new(RefCell::new(None));
        let id = ex.spawn(wake_later(w.clone()), |_| {});
        assert!(!ex.poll(id));
        let stale = w.borrow_mut().take().expect("registered waker");
        ex.deliver(id, Some(1));
        let id2 = ex.spawn(std::future::pending::<()>(), |_| {});
        assert_eq!(id, id2, "slot reused");
        stale.wake();
        assert_eq!(ex.pop_ready(), None, "stale generation must be skipped");
    }
}
