//! A tiny single-threaded executor for the async query lifecycle.
//!
//! A query-future emits send-requests into its mailbox (`QueryIo.outbox`) and
//! awaits the settled reply the reactor deposits back (`QueryIo.reply`). The
//! executor is driven by `ares_process` and polls only the futures whose task
//! the reactor just resolved, so the waker is a no-op — readiness is driven,
//! not scheduled. Pure/safe: the C-callback firing and the reactor wiring that
//! feed this live in `src/ffi/`.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use bytes::BytesMut;

use crate::core::transport::SocketSource;

/// One query the future asks the executor to send.
pub(crate) struct SendReq {
    pub payload: BytesMut,
    pub source: SocketSource,
    pub server: usize,
}

/// A settled send outcome: the reply bytes (or the C status code), plus the
/// timeout count to report to the callback.
pub(crate) type Settled = (Result<Vec<u8>, i32>, i32);

/// The mailbox shared (via `Rc<RefCell<_>>`) between one query-future and the
/// executor. The future only ever touches this — never the channel — so
/// polling it borrows nothing of `ChannelData`.
#[derive(Default)]
pub(crate) struct QueryIo {
    /// Send-requests the future emitted; the executor drains + enqueues them.
    pub outbox: Vec<SendReq>,
    /// The settled reply the reactor delivered; the future takes it.
    pub reply: Option<Settled>,
}

/// Future: emit one `SendReq` on the first poll, then await the settled reply.
/// (The building block; a multi-step lifecycle would `.await` several of these.)
pub(crate) struct SendAndAwait {
    io: Rc<RefCell<QueryIo>>,
    req: Option<SendReq>,
}

impl SendAndAwait {
    pub(crate) fn new(io: Rc<RefCell<QueryIo>>, req: SendReq) -> Self {
        SendAndAwait { io, req: Some(req) }
    }
}

impl Future for SendAndAwait {
    type Output = Settled;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut(); // SendAndAwait: Unpin (Rc + Option are Unpin)
        let mut io = this.io.borrow_mut();
        if let Some(req) = this.req.take() {
            io.outbox.push(req);
            return Poll::Pending;
        }
        match io.reply.take() {
            Some(settled) => Poll::Ready(settled),
            None => Poll::Pending,
        }
    }
}

/// Readiness is reactor-driven, so waking need do nothing.
struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

thread_local! {
    /// One process-wide no-op waker; cloning it is a refcount bump, not an
    /// allocation, so per-poll waker cost is zero after the first.
    static NOOP_WAKER: Waker = Waker::from(Arc::new(NoopWake));
}

/// A no-op `Waker` (safe: `std::task::Wake`, no `RawWaker`). Cheaply cloned
/// from a cached instance — no per-call heap allocation.
pub(crate) fn noop_waker() -> Waker {
    NOOP_WAKER.with(|w| w.clone())
}
