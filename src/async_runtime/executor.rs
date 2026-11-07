//! Readiness-driven, no-op-waker executor: arms re-register waits each poll, so
//! use only re-polling combinators (`select_biased!`, `.await`);
//! `FuturesUnordered`/`for_each_concurrent` wedge. No DNS/framing knowledge.

use std::cell::RefCell;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
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
    /// A sibling sharing this lookup routed a reply into our inbox after we
    /// last suspended; re-poll us even though no `waits` entry fired.
    pub routed: bool,
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

/// In-flight tasks in reused slots (`None` = reaped).
pub(crate) struct Executor<A> {
    slots: Vec<Option<Box<dyn AbstractTask<A>>>>,
}

impl<A> Default for Executor<A> {
    fn default() -> Self {
        Executor { slots: Vec::new() }
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

    /// `waits`/`timeout` are valid only until the next poll (every pending arm
    /// re-registers), so clear them, then poll once. A reaped id yields `false`.
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

    /// Task `id`'s mailbox, for the host to drain app-specific signals.
    pub(crate) fn io(&self, id: usize) -> Option<&Rc<RefCell<Mailbox<A>>>> {
        self.slots.get(id).and_then(|s| s.as_ref()).map(|t| t.io())
    }

    /// Reap `id` and deliver its output or cancel status; an already-reaped id
    /// is a no-op (a re-entrant abort cannot double-deliver).
    pub(crate) fn deliver(&mut self, id: usize, cancel: Option<i32>) {
        if let Some(task) = self.slots.get_mut(id).and_then(|s| s.take()) {
            task.deliver(cancel);
        }
    }

    /// Every `(fd, wants_write)` an in-flight future is blocked on.
    pub(crate) fn poll_fds(&self) -> Vec<(i32, bool)> {
        let mut fds = Vec::new();
        for t in self.slots.iter().flatten() {
            for w in &t.io().borrow().waits {
                fds.push((w.fd, w.writable));
            }
        }
        fds
    }

    /// The earliest timeout across in-flight futures, in ms from `now`.
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

    /// Set each mailbox's `fired` from `ready` and gate on timeout expiry vs
    /// `now`; returns ids to re-poll. Expiry gates the re-poll but is not stored
    /// — timeout arms read the clock directly.
    pub(crate) fn drive_ready(
        &mut self,
        now: Instant,
        skip_timeouts: bool,
        ready: impl Fn(i32, bool) -> bool,
    ) -> Vec<usize> {
        let mut go = Vec::new();
        for (id, slot) in self.slots.iter_mut().enumerate() {
            let Some(t) = slot.as_mut() else { continue };
            let mut m = t.io().borrow_mut();
            let fired: Vec<Wait> = m.waits.iter().copied().filter(|w| ready(w.fd, w.writable)).collect();
            let expired = !skip_timeouts && m.timeout.is_some_and(|d| now >= d);
            let routed = m.routed;
            if fired.is_empty() && !expired && !routed {
                continue;
            }
            m.fired = fired;
            m.routed = false;
            go.push(id);
        }
        go
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

    #[test]
    fn drive_ready_wakes_routed_mailbox_without_fd() {
        let mut ex = Executor::<()>::default();
        let io = mailbox();
        let id = ex.spawn(io.clone(), std::future::pending::<()>(), |_| {});
        io.borrow_mut().routed = true;

        let go = ex.drive_ready(Instant::now(), true, |_, _| false);

        assert_eq!(go, vec![id]);
        assert!(!io.borrow().routed, "routed wake must be consumed");
    }
}
