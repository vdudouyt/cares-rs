//! The single-query engine behind every lookup: `AsyncClient::request()` runs
//! attempts (connect with failover, send, listen) over a [`QueryState`] until a
//! named step reaches a verdict. A child of `async_client`, so it uses the
//! client's private fields and helpers directly.

use super::*;

impl AsyncClient {
    /// The single-query driver every lookup runs on: run attempts (connect with
    /// failover, send, listen) until one reaches a verdict. Starts on TCP iff
    /// ARES_FLAG_USEVC; `cancelled` (A-cancels-AAAA) stops retries but still
    /// delivers an in-flight reply. The query's id stays reserved until it ends.
    pub(super) async fn request(&self, query: ReservedQuery, cancelled: &Cell<bool>) -> QueryOutcome {
        // A packet over the 16-bit wire length cannot be framed; upstream's TCP
        // writer reports EBADQUERY rather than truncating the length prefix.
        if query.payload.len() > u16::MAX as usize {
            return (Err(ARES_EBADQUERY), 0);
        }
        let mut q = self.start_query(query);
        loop {
            if let Step::Done(result) = self.attempt(&mut q, cancelled).await {
                return (result, q.timeouts);
            }
        }
    }

    /// Per-query state before the first attempt: starting transport, DNS 0x20
    /// case randomization (once per UDP query, kept for retries and enforced on
    /// replies) and the first server.
    fn start_query(&self, query: ReservedQuery) -> QueryState {
        let use_tcp = self.config.options.use_vc;
        let mut payload = query.payload.to_vec();
        let dns0x20 = if self.flags & ARES_FLAG_DNS0x20 != 0 && !use_tcp {
            edns::randomize_question_name(&mut payload)
        } else {
            None
        };
        QueryState {
            opts: self.opts(),
            qid: query.lease,
            payload,
            use_tcp,
            server: self.health.borrow().pick_next(),
            dns0x20,
            tries: 0,
            try_count: 0,
            failover_tries: 0,
            cookie_tries: 0,
            timeouts: 0,
        }
    }

    /// One attempt: check out a conn (failing over past unreachable servers),
    /// send once, then listen until a reply, timeout or dead socket decides.
    async fn attempt(&self, q: &mut QueryState, cancelled: &Cell<bool>) -> Step {
        let Ok((mut conn, server)) = self.connect_failover(q.qid.id(), q.server, q.use_tcp) else {
            return Step::Done(Err(ARES_ECONNREFUSED));
        };
        q.server = server;
        // Cookies are re-evaluated per server/transport before every send: a
        // BADCOOKIE retry must pick up the learned server cookie, a TCP
        // upgrade must strip it. No OPT on the payload → untouched.
        let sent_cookie = match self.apply_cookie(&mut q.payload, server, q.use_tcp) {
            Ok(c) => c,
            Err(e) => return Step::Done(Err(e.code())),
        };
        let deadline = Instant::now()
            + calc_query_timeout(q.opts.timeout, q.try_count, self.endpoints.len(), q.opts.maxtimeout);
        let sent = if q.use_tcp {
            conn.send(&frame_tcp(&q.payload), deadline).await
        } else {
            conn.send(&q.payload, deadline).await
        };
        if sent.is_err() {
            return self.on_send_failed(q, &conn);
        }
        loop {
            let step = match recv_reply(&mut conn, deadline).await {
                Ok(buf) => self.on_reply(q, buf, sent_cookie.as_ref()),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => Some(self.on_timed_out(q, &conn, cancelled)),
                Err(_) => Some(self.on_dead_socket(q, &conn, cancelled)),
            };
            if let Some(step) = step {
                return step;
            }
        }
    }

    /// Judge one received message; `None` means it was not for us (stray,
    /// spoofed, or a cookie drop) and the attempt keeps listening.
    fn on_reply(&self, q: &mut QueryState, buf: Vec<u8>, sent_cookie: Option<&[u8; 8]>) -> Option<Step> {
        if !q.is_our_reply(&buf) {
            return None;
        }
        let summary = summarize(&buf, 0);
        let full_rcode = edns::extended_rcode(&buf, summary.rcode);
        match self.validate_cookie(&buf, sent_cookie, q.server, full_rcode) {
            CookieVerdict::Drop => return None,
            CookieVerdict::BadCookie => {
                q.cookie_tries += 1;
                // Persistent BADCOOKIE (e.g. AnyCast rotation): upgrade to TCP,
                // where cookies are not used.
                if q.cookie_tries >= 3 {
                    q.use_tcp = true;
                }
                return Some(Step::Retry);
            }
            CookieVerdict::Accept => {}
        }
        // FORMERR fallback: a server that does not understand EDNS answers the
        // OPT-bearing query with FORMERR. Strip the OPT (and cookie) and retry
        // the same server uncounted.
        if summary.rcode == 1 && edns::has_opt(&q.payload) && edns::strip_opt(&mut q.payload) {
            return Some(Step::Retry);
        }
        let policy = ReplyPolicy { ignore_tc: q.opts.ignore_tc, no_check_resp: q.opts.no_check_resp };
        let (actions, verdict) = on_datagram(
            &summary,
            q.server,
            q.use_tcp,
            q.opts.attempts,
            q.failover_tries,
            policy,
            &mut self.health.borrow_mut(),
        );
        self.notify(actions);
        Some(match verdict {
            TaskVerdict::RetryNextServer { server, tries } => {
                q.server = server;
                q.failover_tries = tries;
                q.try_count += 1;
                Step::Retry
            }
            TaskVerdict::RetryTcp => {
                q.use_tcp = true;
                Step::Retry
            }
            TaskVerdict::Deliver => Step::Done(Ok(buf)),
        })
    }

    /// The send itself failed: drop the conn and retry on the next server while
    /// the attempt budget lasts.
    fn on_send_failed(&self, q: &mut QueryState, conn: &Conn) -> Step {
        self.discard_conn(q, conn);
        if q.tries + 1 >= q.opts.attempts.max(1) {
            return Step::Done(Err(ARES_ECONNREFUSED));
        }
        q.tries += 1;
        q.try_count += 1;
        if self.health.borrow().len() > 1 {
            self.health.borrow_mut().record_failure(q.server);
            q.server = self.health.borrow().pick_next();
        }
        Step::Retry
    }

    /// No reply before the deadline.
    fn on_timed_out(&self, q: &mut QueryState, conn: &Conn, cancelled: &Cell<bool>) -> Step {
        // If any UDP socket to this server already died, a timeout is the same
        // unreachable condition (the kernel may rate-limit ICMP across parallel
        // sockets): mark dead and retry uncounted.
        if !q.use_tcp && self.optmask & ARES_OPT_EVENT_THREAD != 0 && self.udp_pool.borrow().has_dead(q.server) {
            conn.mark_dead();
            return self.fail_over(q, cancelled, false, ARES_ECONNREFUSED);
        }
        let server = q.server;
        let step = self.fail_over(q, cancelled, true, ARES_ETIMEOUT);
        if matches!(step, Step::Retry) && !q.use_tcp {
            self.retire_udp(server, conn);
        }
        step
    }

    /// Dead socket (EOF/hard error). For UDP this is ICMP port-unreachable
    /// (upstream issue #819): a critical failure, not a timeout, so the retry is
    /// uncounted and expiry reports ECONNREFUSED.
    fn on_dead_socket(&self, q: &mut QueryState, conn: &Conn, cancelled: &Cell<bool>) -> Step {
        self.discard_conn(q, conn);
        if q.use_tcp {
            self.fail_over(q, cancelled, true, ARES_ETIMEOUT)
        } else {
            self.fail_over(q, cancelled, false, ARES_ECONNREFUSED)
        }
    }

    /// Take a failed conn out of service: TCP leaves the pool; an event-thread
    /// UDP conn stays pooled but marked dead (so a burst of retries fails fast
    /// instead of each socket waiting for its own ICMP error); otherwise the UDP
    /// conn is retired.
    fn discard_conn(&self, q: &QueryState, conn: &Conn) {
        if q.use_tcp {
            self.tcp_pool.borrow_mut().remove(q.server);
        } else if self.optmask & ARES_OPT_EVENT_THREAD != 0 {
            conn.mark_dead();
        } else {
            self.retire_udp(q.server, conn);
        }
    }

    /// Shared tail of the failure paths: stop if cancelled, report the server
    /// down, then retry on the next server or expire with `expire`.
    /// `counts_timeout` decides whether this failure is reported in `timeouts`.
    fn fail_over(&self, q: &mut QueryState, cancelled: &Cell<bool>, counts_timeout: bool, expire: c_int) -> Step {
        if cancelled.get() {
            return Step::Done(Err(ARES_ETIMEOUT));
        }
        self.notify(vec![ReactorAction::NotifyServerState { server: q.server, ok: false, tcp: q.use_tcp }]);
        match on_timeout(q.tries, q.opts.attempts, q.server, &mut self.health.borrow_mut()) {
            TimeoutVerdict::Retry { server } => {
                q.tries += 1;
                q.try_count += 1;
                if counts_timeout {
                    q.timeouts += 1;
                }
                q.server = server;
                Step::Retry
            }
            TimeoutVerdict::Expire => Step::Done(Err(expire)),
        }
    }
}

/// Mutable state of one `request()` across its attempts (upstream `ares_query_t`).
struct QueryState {
    opts: QueryOpts,
    /// The channel-unique transaction id, reserved for the query's whole life.
    qid: QidLease,
    /// The query as sent; the FORMERR fallback may strip its OPT.
    payload: Vec<u8>,
    /// Starts at ARES_FLAG_USEVC; a TC reply or persistent BADCOOKIE upgrades.
    use_tcp: bool,
    server: usize,
    /// DNS 0x20: the randomized question name replies must echo (UDP only).
    dns0x20: Option<Vec<u8>>,
    /// Retries counted against `opts.attempts`.
    tries: u32,
    /// Upstream `query->try_count`: every retry across servers; drives backoff.
    try_count: u32,
    failover_tries: u32,
    cookie_tries: u32,
    /// Timed-out attempts, reported to the caller.
    timeouts: c_int,
}

impl QueryState {
    /// Same transaction id as the query, and (on UDP with 0x20) the exact
    /// randomized question case; anything else is a stray or spoofed message.
    fn is_our_reply(&self, buf: &[u8]) -> bool {
        if !qid_matches(buf, &self.payload, false) {
            return false;
        }
        match self.dns0x20.as_deref() {
            Some(expected) if !self.use_tcp => edns::question_matches_case(buf, expected),
            _ => true,
        }
    }
}

/// What one attempt (or one failure handler) concluded.
enum Step {
    Retry,
    Done(Result<Vec<u8>, c_int>),
}

/// Timeout-biased receive, with a last non-blocking read when the timer and
/// socket readiness land in the same reactor turn: a pending ICMP error must
/// not report as a timeout.
async fn recv_reply(conn: &mut Conn, deadline: Instant) -> io::Result<Vec<u8>> {
    match conn.recv(deadline).await {
        Err(e) if e.kind() == io::ErrorKind::TimedOut => match conn.try_recv() {
            Poll::Ready(result) => result,
            Poll::Pending => Err(e),
        },
        other => other,
    }
}
