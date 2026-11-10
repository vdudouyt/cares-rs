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
        self.maybe_probe(&q);
        loop {
            match self.attempt(&mut q).await {
                Step::Done(result) => return (result, q.timeouts),
                // A-cancels-AAAA: the sibling answered, so don't try again.
                Step::Retry if cancelled.get() => return (Err(ARES_ETIMEOUT), q.timeouts),
                Step::Retry => {}
            }
        }
    }

    /// Upstream `ares_probe_failed_server`, on a query's first send: with
    /// probability 1/`retry_chance`, duplicate it (fresh qid) to a failed server
    /// past its retry delay that has no probe in flight. The probe runs as its
    /// detached task, so this query never waits for it.
    fn maybe_probe(&self, q: &QueryState) {
        let chance = q.opts.failover_chance;
        if chance == 0 || !rand::thread_rng().r#gen::<u16>().is_multiple_of(chance) {
            return;
        }
        let Some(server) = self.shared.health.borrow().pick_probe(q.opts.failover_delay, q.server) else { return };
        let Ok(query) = self.reserve(BytesMut::from(&q.payload[..])) else { return };
        self.shared.health.borrow_mut().set_probing(server, true);
        let probe = Probe { query: Some(query), server, shared: self.shared.clone() };
        self.rt.spawn(self.copy().probe(probe));
    }

    /// Run a failover probe: one no-retry attempt to its server, whose outcome
    /// only feeds `ServerHealth` and the server-state callback (upstream sends it
    /// with `ARES_SEND_FLAG_NORETRY`). Dropping it clears the server's
    /// probe-in-flight mark.
    async fn probe(self, mut probe: Probe) {
        let Some(query) = probe.query.take() else { return };
        let mut q = self.start_query(query);
        q.server = probe.server;
        q.no_retry = true;
        while let Step::Retry = self.attempt(&mut q).await {}
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
            server: self.shared.health.borrow().pick_next(),
            dns0x20,
            tries: 0,
            try_count: 0,
            failover_tries: 0,
            cookie_tries: 0,
            timeouts: 0,
            no_retry: false,
        }
    }

    /// One attempt: check out a conn (failing over past unreachable servers),
    /// send once, then listen until a reply, timeout or dead socket decides.
    async fn attempt(&self, q: &mut QueryState) -> Step {
        let tries = if q.no_retry { 1 } else { q.opts.attempts };
        let Some((mut conn, server)) = self.connect_with_failover(q.qid.id(), q.server, q.use_tcp, tries) else {
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
                Err(e) if e.kind() == io::ErrorKind::TimedOut => Some(self.on_timed_out(q, &conn)),
                Err(_) => Some(self.on_dead_socket(q, &conn)),
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
            &mut self.shared.health.borrow_mut(),
        );
        self.notify(actions);
        Some(match verdict {
            // A probe never moves on: the verdict is already recorded in health.
            TaskVerdict::RetryNextServer { .. } if q.no_retry => Step::Done(Ok(buf)),
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
        if q.no_retry || q.tries + 1 >= q.opts.attempts.max(1) {
            return Step::Done(Err(ARES_ECONNREFUSED));
        }
        q.tries += 1;
        q.try_count += 1;
        if self.shared.health.borrow().len() > 1 {
            self.shared.health.borrow_mut().record_failure(q.server);
            q.server = self.shared.health.borrow().pick_next();
        }
        Step::Retry
    }

    /// No reply before the deadline.
    fn on_timed_out(&self, q: &mut QueryState, conn: &Conn) -> Step {
        // If any UDP socket to this server already died, a timeout is the same
        // unreachable condition (the kernel may rate-limit ICMP across parallel
        // sockets): mark dead and retry uncounted.
        if !q.use_tcp && self.optmask & ARES_OPT_EVENT_THREAD != 0 && self.shared.udp_pool.borrow().has_dead(q.server) {
            conn.mark_dead();
            return self.fail_over(q, false, ARES_ECONNREFUSED);
        }
        let server = q.server;
        let step = self.fail_over(q, true, ARES_ETIMEOUT);
        if matches!(step, Step::Retry) && !q.use_tcp {
            self.retire_udp(server, conn);
        }
        step
    }

    /// Dead socket (EOF/hard error). For UDP this is ICMP port-unreachable
    /// (upstream issue #819): a critical failure, not a timeout, so the retry is
    /// uncounted and expiry reports ECONNREFUSED.
    fn on_dead_socket(&self, q: &mut QueryState, conn: &Conn) -> Step {
        self.discard_conn(q, conn);
        if q.use_tcp {
            self.fail_over(q, true, ARES_ETIMEOUT)
        } else {
            self.fail_over(q, false, ARES_ECONNREFUSED)
        }
    }

    /// Take a failed conn out of service: TCP leaves the pool; an event-thread
    /// UDP conn stays pooled but marked dead (so a burst of retries fails fast
    /// instead of each socket waiting for its own ICMP error); otherwise the UDP
    /// conn is retired.
    fn discard_conn(&self, q: &QueryState, conn: &Conn) {
        if q.use_tcp {
            let evicted = self.shared.tcp_pool.borrow_mut().remove(q.server);
            drop(evicted); // after the borrow: closing may fire C callbacks
        } else if self.optmask & ARES_OPT_EVENT_THREAD != 0 {
            conn.mark_dead();
        } else {
            self.retire_udp(q.server, conn);
        }
    }

    /// Shared tail of the failure paths: report the server down, then retry on
    /// the next server or expire with `expire`. `counts_timeout` decides whether
    /// this failure is reported in `timeouts`.
    fn fail_over(&self, q: &mut QueryState, counts_timeout: bool, expire: c_int) -> Step {
        self.notify(vec![ReactorAction::NotifyServerState { server: q.server, ok: false, tcp: q.use_tcp }]);
        match on_timeout(q.tries, q.opts.attempts, q.server, &mut self.shared.health.borrow_mut()) {
            // A probe's failure is recorded (by `on_timeout`); it is not retried.
            TimeoutVerdict::Retry { .. } if q.no_retry => Step::Done(Err(expire)),
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
    server: ServerId,
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
    /// A failover probe: one server, no failover or retries.
    no_retry: bool,
}

/// A pending failover probe (see [`AsyncClient::maybe_probe`]): its packet,
/// target server, and the probe-in-flight mark it clears when dropped, whether
/// it ran to completion or was aborted with the channel.
struct Probe {
    query: Option<ReservedQuery>,
    server: ServerId,
    shared: Rc<ChannelShared>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.shared.health.borrow_mut().set_probing(self.server, false);
    }
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

// ---- Transport helpers: connection checkout, cookies, timeouts ----

impl AsyncClient {
    /// Snapshot per-server connect endpoints so a lookup never re-reads config.
    pub(super) fn endpoint_snapshot(&self) -> Vec<ServerEndpoint> {
        let default_udp = self.default_udp_port;
        let default_tcp = self.default_tcp_port;
        self.config
            .nameservers
            .iter()
            .enumerate()
            .map(|(i, &(ip, udp_override))| {
                let udp_port = udp_override.unwrap_or(default_udp);
                let tcp_port = self.config.tcp_ports.get(i).copied().flatten().unwrap_or(default_tcp);
                let bind = if ip.is_ipv6() {
                    SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
                } else {
                    SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
                };
                ServerEndpoint {
                    udp_addr: SocketAddr::from((ip, udp_port)),
                    tcp_addr: SocketAddr::from((ip, tcp_port)),
                    bind,
                }
            })
            .collect()
    }

    /// The retry/timeout knobs an async lifecycle needs.
    pub(super) fn opts(&self) -> QueryOpts {
        QueryOpts {
            attempts: self.config.options.attempts,
            timeout: Duration::from_millis(self.config.options.timeout_ms as u64),
            maxtimeout: (self.maxtimeout > 0)
                .then(|| Duration::from_millis(self.maxtimeout as u64)),
            failover_chance: self.server_failover_retry_chance,
            failover_delay: self.server_failover_retry_delay,
            ignore_tc: self.flags & ARES_FLAG_IGNTC != 0,
            no_check_resp: self.flags & ARES_FLAG_NOCHECKRESP != 0,
        }
    }

    /// Remove a dead/timed-out shared UDP conn so the next attempt opens a fresh
    /// socket. The `Rc` drops after the pool borrow ends (it may close a socket).
    fn retire_udp(&self, server: ServerId, conn: &Conn) {
        let Some(c) = conn.shared_udp_handle() else { return };
        let retired = self.shared.udp_pool.borrow_mut().remove(server, &c);
        drop(retired);
    }

    /// Grow the per-server cookie table to cover `server` and pass it to `f`.
    fn with_cookie<R>(&self, server: ServerId, f: impl FnOnce(&mut ServerCookie) -> R) -> Option<R> {
        let mut cookies = self.shared.cookies.borrow_mut();
        let needed = self.endpoints.len().max(server.0 + 1);
        if cookies.len() < needed {
            cookies.resize_with(needed, ServerCookie::default);
        }
        cookies.get_mut(server.0).map(f)
    }

    /// Attach the COOKIE option for this send (UDP only; removed on TCP). Returns
    /// the 8-byte client cookie placed on the wire, which the response must echo.
    /// `ARES_EFORMERR` means the rewrite would exceed the 16-bit DNS limit.
    fn apply_cookie(
        &self,
        payload: &mut Vec<u8>,
        server: ServerId,
        use_tcp: bool,
    ) -> Result<Option<[u8; 8]>, AresError> {
        if !edns::has_opt(payload) {
            return Ok(None);
        }
        if use_tcp {
            // Cookies are deliberately not used over TCP; strip a stale one
            // (e.g. after a BADCOOKIE-driven upgrade).
            if !edns::set_cookie_option(payload, None) {
                return Err(ARES_EFORMERR.into());
            }
            return Ok(None);
        }
        let cookie = self.with_cookie(server, ServerCookie::cookie_for_query).flatten();
        let Some(cookie) = cookie else {
            // Server is known to be unsupported: no cookie.
            if !edns::set_cookie_option(payload, None) {
                return Err(ARES_EFORMERR.into());
            }
            return Ok(None);
        };
        if cookie.len() < 8 {
            return Ok(None);
        }
        let mut client = [0u8; 8];
        client.copy_from_slice(&cookie[..8]);
        if !edns::set_cookie_option(payload, Some(&cookie)) {
            return Err(ARES_EFORMERR.into());
        }
        Ok(Some(client))
    }

    /// Validate a response's COOKIE option against this server's state.
    fn validate_cookie(
        &self,
        resp: &[u8],
        sent_client: Option<&[u8; 8]>,
        server: ServerId,
        rcode: u16,
    ) -> CookieVerdict {
        self.with_cookie(server, |cookie| {
            cookie.validate_response(resp, sent_client, rcode)
        })
        .unwrap_or(CookieVerdict::Accept)
    }

    /// Check out a pooled conn (or open one) to the `preferred` server, failing
    /// over to the healthiest other server when a socket cannot be created, for
    /// up to `tries` servers. Returns the conn and the server it reached, or
    /// `None` once the budget is spent. Shared conns open an inbox slot for `qid`.
    fn connect_with_failover(&self, qid: u16, preferred: ServerId, use_tcp: bool, tries: u32) -> Option<(Conn, ServerId)> {
        let stayopen = self.flags & ARES_FLAG_STAYOPEN != 0;
        let event_driven = self.optmask & ARES_OPT_EVENT_THREAD != 0;
        let mut s = preferred;
        for _ in 0..tries.max(1) {
            let Some(ep) = self.endpoints.get(s.0) else { break };
            let conn = if use_tcp {
                // Checkout-then-release: no pool guard is live while the C socket
                // callbacks fire during creation, nor while `Conn::shared` borrows.
                let pooled = self.shared.tcp_pool.borrow().get(s);
                let checked_out = pooled.or_else(|| {
                    let sock = self.rt.tcp(ep.bind).ok()?;
                    let _ = sock.get_ref().connect(ep.tcp_addr); // optimistic (EINPROGRESS → Ok)
                    let c = TcpConn::new(sock);
                    let replaced = self.shared.tcp_pool.borrow_mut().insert(s, c.clone());
                    drop(replaced); // after the borrow: closing may fire C callbacks
                    Some(c)
                });
                checked_out.map(|c| Conn::shared(c, qid))
            } else {
                // Checkout an existing shared datagram conn (pruning idle ones when
                // not staying open), or create one if `udp_max_queries` is hit.
                // Creation runs with the pool unborrowed so C callbacks fire cleanly.
                let (pooled, retired) = {
                    let mut pool = self.shared.udp_pool.borrow_mut();
                    pool.pick_or_none(s, self.udp_max_queries, stayopen)
                };
                drop(retired);
                let checked_out = pooled.or_else(|| {
                    let sk = self.rt.udp(ep.bind).ok()?;
                    let _ = sk.get_ref().connect(ep.udp_addr);
                    let c = UdpConn::new(sk, event_driven);
                    self.shared.udp_pool.borrow_mut().insert(s, c.clone());
                    Some(c)
                });
                checked_out.map(|c| {
                    Conn::shared_udp(c, qid).with_udp_lease(self.shared.clone(), s, stayopen, self.udp_max_queries)
                })
            };
            if let Some(conn) = conn {
                return Some((conn, s));
            }
            if self.shared.health.borrow().len() > 1 {
                self.shared.health.borrow_mut().record_failure(s);
                s = self.shared.health.borrow().pick_next();
            }
        }
        None
    }
}

/// A server's precomputed connect targets.
#[derive(Clone)]
pub(crate) struct ServerEndpoint {
    pub udp_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    pub bind: SocketAddr,
}

/// The retry/timeout knobs a query needs, snapshotted at launch.
#[derive(Clone, Copy)]
pub(crate) struct QueryOpts {
    pub attempts: u32,
    pub timeout: Duration,
    pub maxtimeout: Option<Duration>,
    pub failover_chance: u16,
    pub failover_delay: u64,
    pub ignore_tc: bool,
    pub no_check_resp: bool,
}

/// Upstream `ares_calc_query_timeout`: base timeout doubled per full server
/// round, capped by ARES_OPT_MAXTIMEOUTMS, jittered into [0.5, 1.0]× for retries.
/// Never below the base.
fn calc_query_timeout(
    base: Duration,
    try_count: u32,
    nservers: usize,
    maxtimeout: Option<Duration>,
) -> Duration {
    let mut timeout = base;
    let rounds = (try_count as usize)
        .checked_div(nservers)
        .unwrap_or(0);
    if rounds > 0 {
        let factor = 1u32.checked_shl(rounds as u32).unwrap_or(u32::MAX);
        timeout = timeout.saturating_mul(factor);
        if let Some(max) = maxtimeout.filter(|m| !m.is_zero()) {
            if timeout > max {
                timeout = max;
            }
        }
        // Jitter: r / u16::MAX * 0.5 subtracted (upstream float arithmetic).
        let r = rand::thread_rng().r#gen::<u16>();
        let delta_multiplier = (r as f64 / u16::MAX as f64) * 0.5;
        timeout = timeout.mul_f64(1.0 - delta_multiplier);
    }
    if timeout < base {
        timeout = base;
    }
    timeout
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qid_of(payload: &[u8]) -> u16 {
        u16::from_be_bytes([payload[0], payload[1]])
    }

    struct TestSock;
    impl crate::async_runtime::socket::Socket for TestSock {
        fn as_raw_fd(&self) -> i32 {
            21
        }
        fn connect(&self, _addr: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }
    }

    struct TestFactory;
    impl SocketFactory for TestFactory {
        fn create_udp(&self, _bind: SocketAddr) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
            Ok(Rc::new(TestSock))
        }
        fn create_tcp(&self, _bind: SocketAddr) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
            Ok(Rc::new(TestSock))
        }
    }

    /// Concurrent queries get distinct channel-wide ids stamped on their
    /// payloads, share one UDP socket without clashing, and free the id on drop.
    #[test]
    fn reserved_qids_are_unique_and_share_a_socket() {
        let config = SysConfig {
            nameservers: vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), None)],
            ..SysConfig::default()
        };
        let mut client = AsyncClient::build(config, Rc::new(TestFactory), 53, 53);
        client.endpoints = Rc::new(client.endpoint_snapshot());

        let payload = || BytesMut::from(&[0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        let first = client.reserve(payload()).expect("first reserve");
        let second = client.reserve(payload()).expect("second reserve");
        assert_ne!(first.qid(), second.qid());
        assert_eq!(qid_of(&first.payload), first.qid(), "the reserved id is stamped");
        assert_eq!(qid_of(&second.payload), second.qid());

        let (conn_a, _) = client.connect_with_failover(first.qid(), ServerId(0), false, 1).expect("first checkout");
        let (conn_b, _) = client.connect_with_failover(second.qid(), ServerId(0), false, 1).expect("second checkout");
        let shared = conn_a.shared_udp_handle().expect("pooled UDP");
        assert!(Rc::ptr_eq(&shared, &conn_b.shared_udp_handle().expect("pooled UDP")), "one shared socket");
        assert!(shared.borrow().has_waiter(first.qid()) && shared.borrow().has_waiter(second.qid()));

        drop(conn_a);
        drop(conn_b);
        assert_eq!(client.shared.qids.borrow().len(), 2, "ids stay reserved while the queries live");
        drop(first);
        assert_eq!(client.shared.qids.borrow().len(), 1);
    }

    #[test]
    fn query_timeout_doubles_per_round_and_caps() {
        let base = Duration::from_millis(100);
        // First attempt: exactly the base timeout.
        assert_eq!(calc_query_timeout(base, 0, 2, None), base);
        // After one full round: 2x, jittered into [1x, 2x].
        let t = calc_query_timeout(base, 2, 2, None);
        assert!(t >= Duration::from_millis(100) && t <= Duration::from_millis(200));
        // Two rounds: 4x, capped at 250ms, jittered into [125, 250].
        let t = calc_query_timeout(base, 4, 2, Some(Duration::from_millis(250)));
        assert!(t >= Duration::from_millis(125) && t <= Duration::from_millis(250));
        // A cap below the base never reduces the base timeout.
        let t = calc_query_timeout(base, 0, 1, Some(Duration::from_millis(10)));
        assert_eq!(t, base);
    }
}
