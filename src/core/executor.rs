//! A tiny single-threaded executor for the async query lifecycles.
//!
//! Each `ares_*` lifecycle is written as a linear `async fn` (below): it emits
//! send-requests into a mailbox (`QueryIo.outbox`) and awaits the settled reply
//! the reactor deposits back (`QueryIo.reply`), with search-domain iteration /
//! AF_UNSPEC fallback expressed as ordinary control flow instead of a
//! hand-rolled step machine. The executor is driven by `ares_process` and polls
//! only the one future whose task the reactor just resolved, so the waker is a
//! no-op — readiness is driven, not scheduled.
//!
//! Everything here is pure/safe (`forbid(unsafe_code)`): the C-callback firing,
//! the pooled socket launch, and the reactor wiring that feed this live in
//! `src/ffi/` (which owns the raw pointers), but the *decisions* are here.

use std::cell::RefCell;
use std::ffi::c_int;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use bytes::BytesMut;

use crate::core::lookup::{SearchPlan, AF_INET, AF_INET6, AF_UNSPEC, RTYPE_A, RTYPE_AAAA};
use crate::core::packets::AddrRecord;
use crate::core::response::{addr_reply, ParsedRRs, ReplyRequire};
use crate::core::transport::SocketSource;
use crate::core::AresError;
use crate::ffi::error::{ARES_ENODATA, ARES_ENOTFOUND, ARES_ETIMEOUT};

/// A send the executor performs on the future's behalf. The future never
/// touches the channel; it only names what it wants sent.
pub(crate) enum SendReq {
    /// ares_query / ares_send: a pre-built packet to a fixed server.
    Raw { payload: BytesMut, source: SocketSource, server: usize },
    /// ares_gethostbyname: a pooled launch (TCP/UDP socket reuse + per-server
    /// socket-creation retry). The server is chosen by the executor
    /// (`ServerHealth::pick_next`), matching the state-machine's per-send pick.
    Pooled { hostname: String, family: c_int, rtype: u16, use_tcp: bool },
}

/// A fire-and-forget side effect (no reply) the future asks the channel to do.
pub(crate) enum SideEffect {
    /// Cache the reply bytes under each of these names (gethostbyname success).
    Cache { names: Vec<String>, rtype: u16, ttl: u32, reply: Vec<u8> },
}

/// A settled send outcome the reactor hands back: the reply bytes (or the C
/// status code), plus the timeout count of the delivering task.
pub(crate) type Settled = (Result<Vec<u8>, c_int>, c_int);

/// What the executor delivers to C once a lifecycle future completes. The ffi
/// completion path maps each arm to the right C callback.
pub(crate) enum Delivery {
    /// ares_query / ares_send: raw reply bytes or a status code.
    Raw { result: Result<Vec<u8>, c_int>, timeouts: c_int },
    /// ares_gethostbyname: parsed answers (+ family) to sort & build a hostent
    /// from, or a status code.
    Host { result: Result<(ParsedRRs<AddrRecord>, c_int), c_int>, timeouts: c_int },
}

/// The mailbox shared (via `Rc<RefCell<_>>`) between one lifecycle future and
/// the executor. The future only ever touches this — never the channel — so
/// polling it borrows nothing of the channel.
#[derive(Default)]
pub(crate) struct QueryIo {
    /// Sends the future emitted; the executor drains + performs them.
    pub outbox: Vec<SendReq>,
    /// Fire-and-forget effects (cache stores) the executor drains + performs.
    pub effects: Vec<SideEffect>,
    /// The settled reply the reactor delivered; the future takes it.
    pub reply: Option<Settled>,
}

/// Future: emit one `SendReq` on the first poll, then await the settled reply.
/// The one await primitive every lifecycle is built from.
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

/// Emit one send and await its settled reply — the building block the linear
/// lifecycles below `.await`.
async fn send(io: &Rc<RefCell<QueryIo>>, req: SendReq) -> Settled {
    SendAndAwait::new(io.clone(), req).await
}

/// ares_query / ares_send: one send, one settled reply, done. The reactor owns
/// failover/TC/timeout, so this is a straight line.
pub(crate) async fn raw_lifecycle(io: Rc<RefCell<QueryIo>>, payload: BytesMut) -> Delivery {
    let (result, timeouts) = send(&io, SendReq::Raw { payload, source: SocketSource::Udp, server: 0 }).await;
    Delivery::Raw { result, timeouts }
}

/// ares_gethostbyname's DNS phase as a linear loop: query the current name,
/// await the settled reply, and on NXDOMAIN/NODATA walk the search plan, then
/// (for AF_UNSPEC) fall from AAAA to A, then finalize. The reactor already
/// collapsed each query's own failover/TC/timeout into the single settled reply
/// this awaits, so only the *new-query* decisions live here.
pub(crate) async fn hostbyname_lifecycle(
    io: Rc<RefCell<QueryIo>>,
    hostname: String,
    family: c_int,
    use_tcp: bool,
    ndots: u32,
    search: Vec<String>,
    cache: bool,
) -> Delivery {
    let mut plan = SearchPlan::for_gethostbyname(&hostname, ndots, &search);
    // AF_UNSPEC tries AAAA first, then A; AF_INET6 is AAAA-only, AF_INET A-only.
    let (mut current_family, mut rtype) = match family {
        AF_INET => (AF_INET, RTYPE_A),
        _ => (AF_INET6, RTYPE_AAAA),
    };
    let mut tried_aaaa = family == AF_UNSPEC;
    let mut timeouts: c_int = 0;
    let mut had_nodata = false;

    loop {
        let (result, io_timeouts) =
            send(&io, SendReq::Pooled { hostname: plan.current.clone(), family: current_family, rtype, use_tcp }).await;

        // This query's settled error (each iteration's is independent — the
        // reactor already folded in that query's own retries).
        let last_error: AresError = match result {
            Ok(buf) => match addr_reply(&buf, rtype, ReplyRequire::Items) {
                Ok(rrs) => {
                    // Success: cache under the query name (+ the pre-search base
                    // name when different), then deliver.
                    if cache {
                        let mut names = vec![plan.current.clone()];
                        if !plan.base_name.is_empty() && plan.base_name != plan.current {
                            names.push(plan.base_name.clone());
                        }
                        let ttl = rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                        io.borrow_mut().effects.push(SideEffect::Cache { names, rtype, ttl, reply: buf });
                    }
                    return Delivery::Host { result: Ok((rrs, current_family)), timeouts: timeouts + io_timeouts };
                }
                Err(e) => {
                    if e.code() == ARES_ENODATA {
                        had_nodata = true;
                    }
                    e
                }
            },
            Err(status) => {
                if status == ARES_ETIMEOUT {
                    timeouts += 1;
                }
                AresError::from(status)
            }
        };

        // Search-domain iteration on NXDOMAIN/NODATA: try the next plan name.
        if matches!(last_error.code(), ARES_ENOTFOUND | ARES_ENODATA) && plan.advance().is_some() {
            continue;
        }

        // AF_UNSPEC: AAAA round exhausted → restart the plan on A.
        if family == AF_UNSPEC && tried_aaaa && current_family == AF_INET6 {
            current_family = AF_INET;
            rtype = RTYPE_A;
            tried_aaaa = false;
            plan = if !plan.base_name.is_empty() {
                SearchPlan::for_gethostbyname(&plan.base_name, ndots, &search)
            } else {
                plan.domains.clear();
                plan
            };
            continue;
        }

        // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
        let status = if had_nodata && last_error.code() == ARES_ENOTFOUND {
            ARES_ENODATA
        } else {
            last_error.code()
        };
        return Delivery::Host { result: Err(status), timeouts };
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
