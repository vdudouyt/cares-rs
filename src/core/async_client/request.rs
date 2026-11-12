//! The single-query engine behind every lookup: `AsyncClient::run_reserved_query()`
//! runs attempts over a [`QueryState`] until one reaches a verdict. Each attempt
//! is a `request()` — connect with failover, send once, wait for this query's
//! response — which reports the server it reached and the [`Response`], takes a
//! failed conn out of service, and decides nothing else. `run_reserved_query()`
//! makes every decision (retry, fail over, deliver), performs its channel side
//! effects (health, server-state callback) and makes every change to the query
//! state, in one place. A failover probe runs the same attempts with its own copy of the
//! (no-retry) decisions in `probe()`. Protocol extensions are not handled
//! here: the registered [`Plugin`]s are run at each hook. A child of `async_client`, so it uses the client's private fields and
//! helpers directly.

use super::*;

impl AsyncClient {
    /// The single-query driver every lookup runs on: run attempts (connect with
    /// failover, send, listen) until one reaches a verdict. Starts on TCP iff
    /// ARES_FLAG_USEVC; `cancelled` (A-cancels-AAAA) stops retries but still
    /// delivers an in-flight reply. The query's id stays reserved until it ends.
    pub(super) async fn run_reserved_query(&self, query: ReservedQuery, cancelled: &Cell<bool>) -> QueryOutcome {
        // A packet over the 16-bit wire length cannot be framed; upstream's TCP
        // writer reports EBADQUERY rather than truncating the length prefix.
        if query.payload.len() > u16::MAX as usize {
            return (Err(ARES_EBADQUERY), 0);
        }
        let mut q = self.create_query_state(query);
        self.maybe_spawn_probe(&q);

        loop {
            // A-cancels-AAAA: the sibling answered, so don't (re)send. A reply
            // already in flight is still delivered: this runs between attempts.
            if cancelled.get() {
                return (Err(ARES_ETIMEOUT), q.timeouts);
            }
            let (server, response) = match self.request(&q).await {
                Ok(exchange) => exchange,
                Err(e) => return (Err(e), q.timeouts),
            };
            q.server = server;

            // A plugin may claim the reply as an uncounted re-send.
            let resend = self.plugins_on_reply(&mut q, &response);
            if matches!(response, Response::Rejected) {
                q.rejections += 1;
            }
            if let Some(resend) = resend {
                q.use_tcp |= resend == Resend::OverTcp;
                continue;
            }

            // Decide. A failure yields (counts as a timeout, error on expiry)
            // for the shared failover below; everything else returns or
            // retries right here.
            let (counts_timeout, expire) = match response {
                // Unclaimed: re-send uncounted.
                Response::Rejected => continue,
                Response::Answer(buf) => {
                    let summary = summarize(&buf, 0);
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
                    match verdict {
                        TaskVerdict::RetryNextServer { server, tries } => {
                            q.server = server;
                            q.failover_tries = tries;
                            q.try_count += 1;
                            continue;
                        }
                        TaskVerdict::RetryTcp => {
                            q.use_tcp = true;
                            continue;
                        }
                        TaskVerdict::Deliver => return (Ok(buf), q.timeouts),
                    }
                }
                // The send itself failed: retry on the next server while the
                // attempt budget lasts.
                Response::SendFailed => {
                    if q.tries + 1 >= q.opts.attempts.max(1) {
                        return (Err(ARES_ECONNREFUSED), q.timeouts);
                    }
                    q.tries += 1;
                    q.try_count += 1;
                    if self.shared.health.borrow().len() > 1 {
                        self.shared.health.borrow_mut().record_failure(q.server);
                        q.server = self.shared.health.borrow().pick_next();
                    }
                    continue;
                }
                Response::TimedOut => (true, ARES_ETIMEOUT),
                // A dead TCP conn is a counted timeout.
                Response::Unreachable if q.use_tcp => (true, ARES_ETIMEOUT),
                // UDP unreachable is ICMP port-unreachable (upstream issue
                // #819): a critical failure, not a timeout, so the retry is
                // uncounted and expiry reports ECONNREFUSED.
                Response::Unreachable => (false, ARES_ECONNREFUSED),
            };

            // Shared failover: report the server down, then retry on the next
            // server or expire with `expire`.
            self.notify(vec![ReactorAction::NotifyServerState { server: q.server, ok: false, tcp: q.use_tcp }]);
            match on_timeout(q.tries, q.opts.attempts, q.server, &mut self.shared.health.borrow_mut()) {
                TimeoutVerdict::Retry { server } => {
                    q.tries += 1;
                    q.try_count += 1;
                    if counts_timeout {
                        q.timeouts += 1;
                    }
                    q.server = server;
                }
                TimeoutVerdict::Expire => return (Err(expire), q.timeouts),
            }
        }
    }

    /// Upstream `ares_probe_failed_server`, on a query's first send: with
    /// probability 1/`retry_chance`, duplicate it (fresh qid) to a failed server
    /// past its retry delay that has no probe in flight. The probe runs as its
    /// detached task, so this query never waits for it.
    fn maybe_spawn_probe(&self, q: &QueryState) {
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
    /// with `ARES_SEND_FLAG_NORETRY`). The same decisions as
    /// `run_reserved_query()`, minus everything that moves on: no failover, no
    /// counted retry. It still re-sends when a plugin asks to and on a TC
    /// upgrade. Dropping it clears the server's probe-in-flight mark.
    async fn probe(self, mut probe: Probe) {
        let Some(query) = probe.query.take() else { return };
        let mut q = self.create_query_state(query);
        q.server = probe.server;
        q.no_retry = true;
        loop {
            let Ok((server, response)) = self.request(&q).await else { return };
            q.server = server;
            let resend = self.plugins_on_reply(&mut q, &response);
            if matches!(response, Response::Rejected) {
                q.rejections += 1;
            }
            if let Some(resend) = resend {
                q.use_tcp |= resend == Resend::OverTcp;
                continue;
            }
            match response {
                Response::Rejected => continue,
                Response::Answer(buf) => {
                    let summary = summarize(&buf, 0);
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
                    // The verdict is recorded in health; only a TC upgrade re-sends.
                    match verdict {
                        TaskVerdict::RetryTcp => q.use_tcp = true,
                        TaskVerdict::RetryNextServer { .. } | TaskVerdict::Deliver => return,
                    }
                }
                Response::SendFailed => return,
                // A failure is reported and recorded (by `on_timeout`), never retried.
                Response::TimedOut | Response::Unreachable => {
                    self.notify(vec![ReactorAction::NotifyServerState { server: q.server, ok: false, tcp: q.use_tcp }]);
                    let _ = on_timeout(q.tries, q.opts.attempts, q.server, &mut self.shared.health.borrow_mut());
                    return;
                }
            }
        }
    }

    /// Per-query state before the first attempt: starting transport, first
    /// server, and the packet as the plugins' `on_start` hooks leave it.
    fn create_query_state(&self, query: ReservedQuery) -> QueryState {
        let use_tcp = self.config.options.use_vc;
        let server = self.shared.health.borrow().pick_next();
        let mut payload = query.payload.to_vec();
        let cx = Ctx { client: self, server, use_tcp, rejections: 0 };
        for plugin in &self.plugins {
            plugin.on_start(&cx, &mut payload);
        }
        QueryState {
            opts: self.opts(),
            qid: query.lease,
            payload,
            use_tcp,
            server,
            tries: 0,
            try_count: 0,
            failover_tries: 0,
            rejections: 0,
            timeouts: 0,
            no_retry: false,
        }
    }

    /// Offer an accepted or rejected reply to the plugins; the first to claim
    /// it as a re-send wins (and may have rewritten the query packet).
    fn plugins_on_reply(&self, q: &mut QueryState, response: &Response) -> Option<Resend> {
        let reply = match response {
            Response::Rejected => Reply::Rejected,
            Response::Answer(buf) => Reply::Answer(buf),
            _ => return None,
        };
        let cx = Ctx { client: self, server: q.server, use_tcp: q.use_tcp, rejections: q.rejections };
        self.plugins.iter().find_map(|plugin| plugin.on_reply(&cx, reply, &mut q.payload))
    }

    /// One attempt: connect (with failover) to `q.server`, send once and wait
    /// for this query's response. Returns the server reached (it may differ from
    /// `q.server` after a connect failover) and the [`Response`]; `Err` only when
    /// no conn could be had. Reads the query state, never changes it.
    async fn request(&self, q: &QueryState) -> Result<(ServerId, Response), c_int> {
        let tries = if q.no_retry { 1 } else { q.opts.attempts };
        let (mut conn, server) =
            self.connect_with_failover(q.qid.id(), q.server, q.use_tcp, tries).ok_or(ARES_ECONNREFUSED)?;

        // The plugins rewrite this send's copy of the packet.
        let cx = Ctx { client: self, server, use_tcp: q.use_tcp, rejections: q.rejections };
        let mut wire = q.payload.clone();
        for plugin in &self.plugins {
            plugin.on_send(&cx, &mut wire)?;
        }
        let deadline = Instant::now()
            + calc_query_timeout(q.opts.timeout, q.try_count, self.servers.len(), q.opts.maxtimeout);
        let sent = if q.use_tcp {
            conn.send(&frame_tcp(&wire), deadline).await
        } else {
            conn.send(&wire, deadline).await
        };
        if sent.is_err() {
            self.discard_conn(server, q.use_tcp, &conn);
            return Ok((server, Response::SendFailed));
        }

        loop {
            match recv_reply(&mut conn, deadline).await {
                Ok(buf) => {
                    // Not this query's response (wrong id), or a plugin drops
                    // it as stray or spoofed: keep listening.
                    if !qid_matches(&buf, &q.payload, false) {
                        continue;
                    }
                    let screen = self
                        .plugins
                        .iter()
                        .map(|plugin| plugin.on_receive(&cx, &wire, &buf))
                        .find(|&screen| screen != Screen::Accept)
                        .unwrap_or(Screen::Accept);
                    match screen {
                        Screen::Drop => continue,
                        Screen::Reject => return Ok((server, Response::Rejected)),
                        Screen::Accept => return Ok((server, Response::Answer(buf))),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    if q.use_tcp {
                        return Ok((server, Response::TimedOut));
                    }
                    // If any UDP socket to this server already died, a timeout
                    // is the same unreachable condition (the kernel may
                    // rate-limit ICMP across parallel sockets).
                    if self.optmask & ARES_OPT_EVENT_THREAD != 0 && self.shared.udp_pool.borrow().has_dead(server) {
                        self.discard_conn(server, q.use_tcp, &conn);
                        return Ok((server, Response::Unreachable));
                    }
                    // A retry goes out on a fresh socket (new source port).
                    self.retire_udp(server, &conn);
                    return Ok((server, Response::TimedOut));
                }
                Err(_) => {
                    self.discard_conn(server, q.use_tcp, &conn);
                    return Ok((server, Response::Unreachable));
                }
            }
        }
    }

    /// Take a failed conn out of service: TCP leaves the pool; an event-thread
    /// UDP conn stays pooled but marked dead (so a burst of retries fails fast
    /// instead of each socket waiting for its own ICMP error); otherwise the UDP
    /// conn is retired.
    fn discard_conn(&self, server: ServerId, use_tcp: bool, conn: &Conn) {
        if use_tcp {
            let evicted = self.shared.tcp_pool.borrow_mut().remove(server);
            drop(evicted); // after the borrow: closing may fire C callbacks
        } else if self.optmask & ARES_OPT_EVENT_THREAD != 0 {
            conn.mark_dead();
        } else {
            self.retire_udp(server, conn);
        }
    }
}

/// How one `request()` ended.
enum Response {
    /// This query's answer, accepted by every plugin.
    Answer(Vec<u8>),
    /// A genuine reply a plugin rejected: re-send.
    Rejected,
    /// The send itself failed.
    SendFailed,
    /// No response before the deadline.
    TimedOut,
    /// The socket died: EOF or a hard error (for UDP, ICMP port-unreachable,
    /// also assumed on a timeout once a sibling socket to the server died).
    Unreachable,
}

/// State of one `run_reserved_query()` across its attempts (upstream
/// `ares_query_t`). `request()` only reads it; `run_reserved_query()` (and,
/// for a failover probe, `probe()`) changes it.
struct QueryState {
    opts: QueryOpts,
    /// The channel-unique transaction id, reserved for the query's whole life.
    qid: QidLease,
    /// The query as sent; plugins may rewrite it (on_start / on_reply).
    payload: Vec<u8>,
    /// Starts at ARES_FLAG_USEVC; a TC reply or a plugin upgrades.
    use_tcp: bool,
    server: ServerId,
    /// Retries counted against `opts.attempts`.
    tries: u32,
    /// Upstream `query->try_count`: every retry across servers; drives backoff.
    try_count: u32,
    failover_tries: u32,
    /// Replies a plugin rejected so far.
    rejections: u32,
    /// Timed-out attempts, reported to the caller.
    timeouts: c_int,
    /// A failover probe: one server, no failover or retries.
    no_retry: bool,
}

/// A pending failover probe (see [`AsyncClient::maybe_spawn_probe`]): its packet,
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

// ---- Transport helpers: connection checkout, timeouts ----

impl AsyncClient {
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

    /// Check out a pooled conn (or open one) to the `preferred` server, failing
    /// over to the healthiest other server when a socket cannot be created, for
    /// up to `tries` servers. Returns the conn and the server it reached, or
    /// `None` once the budget is spent. Shared conns open an inbox slot for `qid`.
    fn connect_with_failover(&self, qid: u16, preferred: ServerId, use_tcp: bool, tries: u32) -> Option<(Conn, ServerId)> {
        let stayopen = self.flags & ARES_FLAG_STAYOPEN != 0;
        let event_driven = self.optmask & ARES_OPT_EVENT_THREAD != 0;
        let mut s = preferred;
        for _ in 0..tries.max(1) {
            if !self.servers.contains(&s) {
                break;
            }
            // A lookup from before a server-list change may still reach a server
            // that left the list: use its conn unpooled, so none lingers there.
            let current = self.shared.health.borrow().contains(s);
            let conn = if use_tcp {
                // Checkout-then-release: no pool guard is live while the C socket
                // callbacks fire during creation, nor while `Conn::shared` borrows.
                let pooled = self.shared.tcp_pool.borrow().get(s);
                let checked_out = pooled.or_else(|| {
                    let sock = self.rt.tcp(s.bind_addr()).ok()?;
                    let _ = sock.get_ref().connect(s.tcp_addr()); // optimistic (EINPROGRESS → Ok)
                    let c = TcpConn::new(sock);
                    if current {
                        let replaced = self.shared.tcp_pool.borrow_mut().insert(s, c.clone());
                        drop(replaced); // after the borrow: closing may fire C callbacks
                    }
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
                    let sk = self.rt.udp(s.bind_addr()).ok()?;
                    let _ = sk.get_ref().connect(s.udp_addr());
                    let c = UdpConn::new(sk, event_driven);
                    if current {
                        self.shared.udp_pool.borrow_mut().insert(s, c.clone());
                    }
                    Some(c)
                });
                checked_out.map(|c| {
                    let conn = Conn::shared_udp(c, qid);
                    if current {
                        conn.with_udp_lease(self.shared.clone(), s, stayopen, self.udp_max_queries)
                    } else {
                        conn
                    }
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
    use std::net::SocketAddr;

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
        let client = AsyncClient::build(config, Rc::new(TestFactory), 53, 53);

        let payload = || BytesMut::from(&[0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        let first = client.reserve(payload()).expect("first reserve");
        let second = client.reserve(payload()).expect("second reserve");
        assert_ne!(first.qid(), second.qid());
        assert_eq!(qid_of(&first.payload), first.qid(), "the reserved id is stamped");
        assert_eq!(qid_of(&second.payload), second.qid());

        let (conn_a, _) = client.connect_with_failover(first.qid(), ServerId::test(0), false, 1).expect("first checkout");
        let (conn_b, _) = client.connect_with_failover(second.qid(), ServerId::test(0), false, 1).expect("second checkout");
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
