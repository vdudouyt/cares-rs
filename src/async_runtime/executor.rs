//! The executor: the per-lookup mailbox, the timeout arm, and the in-flight
//! task set driven to completion.
//!
//! This module knows **only** readiness — file descriptors, timeouts, and the
//! futures blocked on them. It has zero knowledge of what any bytes mean: no
//! DNS, no QID, no framing, no server health (the socket byte-pumps live in
//! `conn`). A future publishes the fds it is blocked on (+ an earliest
//! timeout) into its [`Mailbox`]; the host (driven by `ares_process`) sets
//! which waits fired via [`Executor::drive_ready`] and re-polls the one
//! future. The waker is a no-op — readiness is driven, not scheduled.
//!
//! **The mailbox contract (why the combinators here are hand-shaped):** the
//! executor clears `waits`/`timeout` right before each poll, and every pending
//! arm (`conn`'s recv/writable arms, [`poll_timeout`]) *re-registers* its
//! interest on every poll. So an arm is level-ish: polled repeatedly, it
//! republishes what it is blocked on each time.
//!
//! Because of the no-op waker, futures compose **only** with combinators that
//! re-poll every non-terminated child on every poll: `futures::select_biased!`
//! and plain sequential `.await` are safe. Waker-gated combinators
//! (`FuturesUnordered`, `StreamExt::for_each_concurrent`, anything that only
//! re-polls a child whose waker fired) will poll a child once and then wedge —
//! **do not use them here.** Parallel lookups fan out by running each
//! sub-future on the same shared mailbox and racing them with `select_biased!`
//! (see `core::async_client::getaddrinfo`), not by a stream combinator.
//!
//! Protocol-agnostic end to end: the mailbox is generic over an opaque
//! application-state type `A` the reactor never inspects, and each task's
//! output type is erased behind [`ErasedTask`], so one [`Executor`] drives
//! futures of many output types side by side. The host owns the `Executor`
//! and orchestrates it: drives readiness in, polls, drains its own
//! app-specific signals from each mailbox between poll and delivery, and
//! reaps completed slots. Nothing here names DNS, a C callback, or a
//! `fd_set`; the cancel status is a plain `i32`.

use std::cell::RefCell;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

// ===== Mailbox =====

/// One fd the future is blocked on, with the interest it awaits.
#[derive(Clone, Copy)]
pub(crate) struct Wait {
    pub fd: i32,
    pub writable: bool,
}

/// The mailbox shared (via `Rc<RefCell<_>>`) between one lifecycle future and
/// the executor. The future publishes `waits`/`timeout` when it suspends; the
/// executor sets `fired` before re-polling. Nothing here names the host, so
/// polling the future borrows nothing of it. The `app` field holds the
/// application state the reactor treats as opaque.
#[derive(Default)]
pub(crate) struct Mailbox<A> {
    /// fds the future is currently blocked on (published on suspension).
    pub waits: Vec<Wait>,
    /// Earliest timeout the future wants to wake at.
    pub timeout: Option<Instant>,
    /// Which published waits are ready now (set by the executor). Carries the
    /// interest (read vs write), not just the fd, so that when two arms share
    /// one fd with opposite interests a write-readiness isn't consumed by a
    /// read-arm (or vice versa).
    pub fired: Vec<Wait>,
    /// Application signals the reactor doesn't interpret (opaque to it).
    pub app: A,
}

// ===== Timeout arm =====

/// A timeout arm: resolves once wall-clock passes `timeout`; otherwise mins
/// `timeout` into the mailbox and suspends. Reads `Instant::now()` directly
/// so several timeout arms on one mailbox self-demux.
fn poll_timeout<A>(io: &Rc<RefCell<Mailbox<A>>>, timeout: Instant) -> Poll<()> {
    if Instant::now() >= timeout {
        return Poll::Ready(());
    }
    let mut m = io.borrow_mut();
    m.timeout = Some(m.timeout.map_or(timeout, |d| d.min(timeout)));
    Poll::Pending
}

/// Sleep until `timeout` (tokio-style), as a future usable directly as a
/// `select_biased!` arm.
pub(crate) fn sleep_until<A>(
    io: &Rc<RefCell<Mailbox<A>>>,
    timeout: Instant,
) -> impl Future<Output = ()> + '_ {
    poll_fn(move |_| poll_timeout(io, timeout))
}

// ===== The task set =====

/// One in-flight task with its future's `Output` type erased: its mailbox
/// (opaque generic `A`), the future, and the delivery closure. Poll it to
/// completion, then hand the result — or a cancel status — to that closure.
/// The executor holds these as `Box<dyn ErasedTask<A>>`, so one [`Executor`]
/// drives futures of many different output types side by side.
trait ErasedTask<A> {
    /// This task's mailbox (fds/timeout/fired + the host's app signals).
    fn io(&self) -> &Rc<RefCell<Mailbox<A>>>;
    /// Poll the future once; on `Ready`, stash the output and return `true`.
    fn poll(&mut self, cx: &mut Context<'_>) -> bool;
    /// Deliver: the stashed output (`cancel = None`) or a terminal cancel status
    /// (`cancel = Some(status)`); consumes the task (dropping the future — unpolled
    /// on the cancel path).
    fn deliver(self: Box<Self>, cancel: Option<i32>);
}

/// The concrete task: a mailbox, a future, and the single closure that forwards
/// its result (`Ok` on completion, `Err(status)` on cancel) to the host's
/// delivery handler. `T` (the future's output) is erased the moment it is
/// boxed into a slot.
struct Task<A, T> {
    io: Rc<RefCell<Mailbox<A>>>,
    fut: Pin<Box<dyn Future<Output = T>>>,
    out: Option<T>,
    on: Box<dyn FnOnce(Result<T, i32>)>,
}

impl<A, T> ErasedTask<A> for Task<A, T> {
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
        let result = match cancel {
            None => Ok(self.out.expect("delivered before ready")),
            Some(status) => Err(status),
        };
        (self.on)(result);
    }
}

/// The set of in-flight tasks, kept in a reused-slot free list (`None` =
/// reaped). Generic over the mailbox app-state `A` — never inspected here.
pub(crate) struct Executor<A> {
    slots: Vec<Option<Box<dyn ErasedTask<A>>>>,
}

impl<A> Default for Executor<A> {
    fn default() -> Self {
        Executor { slots: Vec::new() }
    }
}

impl<A> Executor<A> {
    /// Register `fut` (with its mailbox `io` and delivery closure `on`) in a free
    /// slot and return its id. Does not poll — the host drives it via [`Self::poll`].
    pub(crate) fn spawn<T: 'static>(
        &mut self,
        io: Rc<RefCell<Mailbox<A>>>,
        fut: impl Future<Output = T> + 'static,
        on: impl FnOnce(Result<T, i32>) + 'static,
    ) -> usize
    where
        A: 'static,
    {
        let task: Box<dyn ErasedTask<A>> =
            Box::new(Task { io, fut: Box::pin(fut), out: None, on: Box::new(on) });
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
            let mut m = task.io().borrow_mut();
            m.waits.clear();
            m.timeout = None;
        }
        let mut cx = Context::from_waker(Waker::noop());
        task.poll(&mut cx)
    }

    /// Task `id`'s mailbox — for the host to drain its app-specific signals (opaque
    /// to the reactor) between poll and delivery.
    pub(crate) fn io(&self, id: usize) -> Option<&Rc<RefCell<Mailbox<A>>>> {
        self.slots.get(id).and_then(|s| s.as_ref()).map(|t| t.io())
    }

    /// Reap slot `id` and deliver its result: the completion output (`cancel = None`)
    /// or a terminal cancel status (`cancel = Some(status)`). An already-reaped id is
    /// a no-op (so a re-entrant abort can't double-deliver).
    pub(crate) fn deliver(&mut self, id: usize, cancel: Option<i32>) {
        if let Some(task) = self.slots.get_mut(id).and_then(|s| s.take()) {
            task.deliver(cancel);
        }
    }

    /// Every `(fd, wants_write)` any in-flight future is currently blocked on.
    pub(crate) fn poll_fds(&self) -> Vec<(i32, bool)> {
        let mut fds = Vec::new();
        for t in self.slots.iter().flatten() {
            for w in &t.io().borrow().waits {
                fds.push((w.fd, w.writable));
            }
        }
        fds
    }

    /// The earliest timeout (ms from `now`) across in-flight futures, or `None`.
    pub(crate) fn next_timeout_ms(&self, now: Instant) -> Option<u128> {
        let mut best: Option<u128> = None;
        for t in self.slots.iter().flatten() {
            if let Some(d) = t.io().borrow().timeout {
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
            let mut m = t.io().borrow_mut();
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
}
