//! The in-flight task set: the futures the reactor drives to completion.
//!
//! Protocol-agnostic, like the rest of `async_runtime` — a task is a boxed future
//! plus a delivery closure, its output type erased behind [`PendingQuery`]. The
//! host (the ffi channel) owns a `Tasks<A>` and orchestrates it: it drives
//! readiness in (via the `drive_ready` oracle), polls, drains its own app-specific
//! signals from each mailbox between poll and delivery, and reaps completed slots.
//! Nothing here names DNS, a C callback, or a `fd_set`; the cancel status is a
//! plain `i32`.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Instant;

use super::executor::{noop_waker, QueryIo, Wait};

/// One in-flight query with its `Output` type erased: poll it to completion, then
/// hand the result — or a cancel status — to its delivery closure.
trait PendingQuery {
    /// Poll the future once; on `Ready`, stash the output and return `true`.
    fn poll(&mut self, cx: &mut Context<'_>) -> bool;
    /// Deliver: the stashed output (`cancel = None`) or a terminal cancel status
    /// (`cancel = Some(status)`); consumes the query (dropping the future — unpolled
    /// on the cancel path).
    fn deliver(self: Box<Self>, cancel: Option<i32>);
}

/// The concrete query: a future plus the single closure that forwards its result
/// (`Ok` on completion, `Err(status)` on cancel) to the host's delivery handler.
struct Query<T> {
    fut: Pin<Box<dyn Future<Output = T>>>,
    out: Option<T>,
    on: Box<dyn FnOnce(Result<T, i32>)>,
}

impl<T> PendingQuery for Query<T> {
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
        let result = match cancel {
            None => Ok(self.out.expect("delivered before ready")),
            Some(status) => Err(status),
        };
        (self.on)(result);
    }
}

/// One in-flight task: its reactor mailbox plus the erased query.
struct Task<A> {
    io: Rc<RefCell<QueryIo<A>>>,
    query: Box<dyn PendingQuery>,
}

/// The set of in-flight tasks, kept in a reused-slot free list (`None` = reaped).
/// Generic over the mailbox app-state `A` — the reactor never inspects it.
pub(crate) struct Tasks<A> {
    slots: Vec<Option<Task<A>>>,
}

impl<A> Default for Tasks<A> {
    fn default() -> Self {
        Tasks { slots: Vec::new() }
    }
}

impl<A> Tasks<A> {
    /// Register `fut` (with its mailbox `io` and delivery closure `on`) in a free
    /// slot and return its id. Does not poll — the host drives it via [`Self::poll`].
    pub(crate) fn spawn<T: 'static>(
        &mut self,
        io: Rc<RefCell<QueryIo<A>>>,
        fut: impl Future<Output = T> + 'static,
        on: impl FnOnce(Result<T, i32>) + 'static,
    ) -> usize {
        let task = Task {
            io,
            query: Box::new(Query { fut: Box::pin(fut), out: None, on: Box::new(on) }),
        };
        match self.slots.iter().position(|s| s.is_none()) {
            Some(i) => {
                self.slots[i] = Some(task);
                i
            }
            None => {
                self.slots.push(Some(task));
                self.slots.len() - 1
            }
        }
    }

    /// Clear the mailbox's published `waits`/`timeout` (the contract: they are valid
    /// only until the next poll; every pending arm re-registers), then poll the
    /// future once. Returns whether it completed (its output stashed, ready for
    /// [`Self::deliver`]). A reaped id polls to `false`.
    pub(crate) fn poll(&mut self, id: usize) -> bool {
        let Some(task) = self.slots.get_mut(id).and_then(|s| s.as_mut()) else {
            return false;
        };
        {
            let mut m = task.io.borrow_mut();
            m.waits.clear();
            m.timeout = None;
        }
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        task.query.poll(&mut cx)
    }

    /// Task `id`'s mailbox — for the host to drain its app-specific signals (opaque
    /// to the reactor) between poll and delivery.
    pub(crate) fn io(&self, id: usize) -> Option<&Rc<RefCell<QueryIo<A>>>> {
        self.slots.get(id).and_then(|s| s.as_ref()).map(|t| &t.io)
    }

    /// Reap slot `id` and deliver its result: the completion output (`cancel = None`)
    /// or a terminal cancel status (`cancel = Some(status)`). An already-reaped id is
    /// a no-op (so a re-entrant abort can't double-deliver).
    pub(crate) fn deliver(&mut self, id: usize, cancel: Option<i32>) {
        if let Some(task) = self.slots.get_mut(id).and_then(|s| s.take()) {
            task.query.deliver(cancel);
        }
    }

    /// Every `(fd, wants_write)` any in-flight future is currently blocked on.
    pub(crate) fn poll_fds(&self) -> Vec<(i32, bool)> {
        let mut fds = Vec::new();
        for t in self.slots.iter().flatten() {
            for w in &t.io.borrow().waits {
                fds.push((w.fd, w.writable));
            }
        }
        fds
    }

    /// The earliest timeout (ms from `now`) across in-flight futures, or `None`.
    pub(crate) fn next_timeout_ms(&self, now: Instant) -> Option<u128> {
        let mut best: Option<u128> = None;
        for t in self.slots.iter().flatten() {
            if let Some(d) = t.io.borrow().timeout {
                let ms = d.saturating_duration_since(now).as_millis();
                best = Some(best.map_or(ms, |b| b.min(ms)));
            }
        }
        best
    }

    /// For each in-flight future, set its mailbox `fired` from the `ready` oracle
    /// (and gate on timeout expiry vs `now`); return the ids that should be re-polled
    /// this cycle. Expiry gates the re-poll but isn't stored — the timeout arms read
    /// the clock directly.
    pub(crate) fn drive_ready(&mut self, now: Instant, ready: impl Fn(i32, bool) -> bool) -> Vec<usize> {
        let mut go = Vec::new();
        for (id, slot) in self.slots.iter_mut().enumerate() {
            let Some(t) = slot.as_mut() else { continue };
            let mut m = t.io.borrow_mut();
            let fired: Vec<Wait> = m.waits.iter().copied().filter(|w| ready(w.fd, w.writable)).collect();
            let expired = m.timeout.is_some_and(|d| now >= d);
            if fired.is_empty() && !expired {
                continue;
            }
            m.fired = fired;
            go.push(id);
        }
        go
    }

    /// The id range spanning every slot (live or reaped) — for aborting everything.
    pub(crate) fn ids(&self) -> std::ops::Range<usize> {
        0..self.slots.len()
    }

    /// Number of live (un-reaped) tasks.
    pub(crate) fn active_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}
