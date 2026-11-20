//! Single-threaded task executor (≈ async-executor's `LocalExecutor`, ticked
//! by the host once per `ares_process*` turn instead of by a thread). Tasks get
//! real wakers, so any `std` future combinator works. No DNS/framing knowledge.

use std::cell::RefCell;
use std::future::Future;
use std::task::Context;
use crate::mem::{ReadyFlag, Task, Vec};

struct Slot<E> {
    /// `None` while the task is being polled: [`Executor::poll`] moves it onto
    /// the stack, so nothing that runs during the poll can free or move it.
    task: Option<Task<E>>,
    /// A cancel that arrived while the task was being polled, applied when the
    /// poll returns.
    cancel: Option<E>,
    /// Selected by cancel_all; new/reused slots start unmarked.
    cancel_selected: bool,
    gen: u32,
    flag: ReadyFlag,
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
    next_ready: usize,
    next_gen: u32,
}

impl<E> Default for Executor<E> {
    fn default() -> Self {
        Executor { inner: RefCell::new(ExecutorInner::default()) }
    }
}

impl<E> Default for ExecutorInner<E> {
    fn default() -> Self {
        ExecutorInner { slots: Vec::new(), next_ready: 0, next_gen: 0 }
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
    pub fn spawn<T: 'static, C: FnOnce(Result<T, E>) + 'static>(
        &self,
        fut: impl Future<Output = T> + 'static,
        on: C,
    ) -> Result<usize, C> {
        let mut inner = self.inner.borrow_mut();
        let id = inner.slots.iter().position(|s| s.is_none()).unwrap_or(inner.slots.len());
        if id == inner.slots.len() && inner.slots.reserve(1).is_err() { return Err(on); }
        // A generation per spawn: a stale waker for a reaped occupant of this
        // slot must not poll the new one.
        inner.next_gen = inner.next_gen.wrapping_add(1);
        let Ok(flag) = ReadyFlag::new() else { return Err(on); };
        let task = Task::new(fut, on)?;
        let slot = Some(Slot { task: Some(task), cancel: None, cancel_selected: false, gen: inner.next_gen, flag });
        match inner.slots.get_mut(id) {
            Some(s) => *s = slot,
            None => { let _ = inner.slots.push(slot); } // Reserved above.
        }
        Ok(id)
    }

    /// Round-robin scan from the last ready slot. A complete idle scan is O(n);
    /// a dense ready batch visits each slot once. No ready queue can overflow.
    pub fn pop_ready(&self) -> Option<usize> {
        let mut inner = self.inner.borrow_mut();
        let len = inner.slots.len();
        for _ in 0..len {
            let id = inner.next_ready % len;
            inner.next_ready = id + 1;
            if inner.slots[id].as_ref().is_some_and(|s| s.flag.take()) {
                return Some(id);
            }
        }
        None
    }

    /// Whether any woken task is waiting to be polled.
    pub fn has_ready(&self) -> bool {
        self.inner.borrow().slots.iter().flatten().any(|s| s.flag.is_set())
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
                slot.flag.waker().wake_by_ref();
                return false;
            };
            // Cleared before the poll so a wake during it re-queues the task.
            slot.flag.clear();
            (task, slot.flag.waker().clone())
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
        let end = {
            let mut inner = self.inner.borrow_mut();
            for slot in inner.slots.iter_mut().flatten() { slot.cancel_selected = true; }
            inner.slots.len()
        };
        for id in 0..end {
            let gen = {
                let mut inner = self.inner.borrow_mut();
                let Some(slot) = inner.slots.get_mut(id).and_then(Option::as_mut) else { continue };
                if !std::mem::take(&mut slot.cancel_selected) { continue; }
                slot.gen
            };
            let status = cancelled();
            let live = self.inner.borrow().slots.get(id).and_then(Option::as_ref)
                .is_some_and(|s| s.gen == gen);
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
    use std::task::{Poll, Waker};
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
        let id = ex.spawn(wake_later(w.clone()), |_| {}).ok().unwrap();
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
        let id = ex.spawn(wake_later(w.clone()), |_| {}).ok().unwrap();
        assert_eq!(ex.pop_ready(), Some(id));
        assert!(!ex.poll(id));
        let stale = w.borrow_mut().take().expect("registered waker");
        ex.finish(id, Err(1));
        let id2 = ex.spawn(std::future::pending::<()>(), |_| {}).ok().unwrap();
        assert_eq!(id, id2, "slot reused");
        assert_eq!(ex.pop_ready(), Some(id2));
        stale.wake();
        assert_eq!(ex.pop_ready(), None, "stale generation must be skipped");
    }
}
