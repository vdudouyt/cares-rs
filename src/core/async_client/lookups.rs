//! The single-answer lookups: `query_raw` (`ares_query`/`ares_send`),
//! `gethostbyaddr`, `getnameinfo`, and the search-domain iteration behind
//! `ares_search`/`ares_search_dnsrec` (`search_plan`).

use super::*;

impl AsyncClient {
    /// ares_query / ares_send: the raw single query, wrapped into `Delivery::Raw`.
    /// The payload goes on the wire as given (`query_payload` already added EDNS;
    /// raw send APIs must not), under the id reserved with it.
    pub(crate) async fn query_raw(self, query: ReservedQuery) -> Delivery {
        let (result, timeouts) = self.run_reserved_query(query, &Cell::new(false)).await;
        Delivery::Raw { result, timeouts }
    }

    /// ares_gethostbyaddr: hosts-file reverse lookup, then a single PTR query.
    pub(crate) async fn gethostbyaddr(self, ip: IpAddr, family: c_int) -> HostReply {
        if let Some(lookup) = self.hostsfile().reverse_lookup(ip) {
            return (Ok(Hostent::from_lookup(lookup)), 0);
        }

        if self.endpoints.is_empty() {
            return (Err(ARES_ENOSERVER.into()), 0);
        }

        let payload = match dns_query_payload(
            &rdns_name(ip),
            u32::from(RECORD_TYPE_PTR),
            u32::from(ARES_CLASS_IN),
            self.recursion_desired(),
        )
        .and_then(|p| self.with_edns(p))
        .and_then(|p| self.reserve(p))
        {
            Ok(q) => q,
            Err(e) => return (Err(e), 0),
        };
        let (result, timeouts) = self.run_reserved_query(payload, &Cell::new(false)).await;
        let result = match result {
            Ok(buf) => on_host_reply(Ok(&buf), RECORD_TYPE_PTR, family, Some(ip)),
            Err(status) => Err(AresError::from(status)),
        };
        (result, timeouts)
    }

    /// ares_getnameinfo: three synchronous short-circuits (service-only /
    /// NUMERICHOST / no-servers), else a single PTR query + `assemble_nameinfo`.
    pub(crate) async fn getnameinfo(
        self,
        addr: AddrInfo,
        flags: c_int,
    ) -> NameinfoReply {
        let flags = if (flags & ARES_NI_LOOKUPSERVICE) == 0 && (flags & ARES_NI_LOOKUPHOST) == 0 {
            flags | ARES_NI_LOOKUPHOST
        } else {
            flags
        };

        let want_host = (flags & ARES_NI_LOOKUPHOST) != 0;
        let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

        if want_service && !want_host {
            let service = get_service_string(&Services::default(), addr.port, flags);
            return NameinfoReply { status: ARES_SUCCESS.into(), node: None, service, timeouts: 0 };
        }

        if (flags & ARES_NI_NUMERICHOST) != 0 {
            if (flags & ARES_NI_NAMEREQD) != 0 {
                return NameinfoReply { status: ARES_EBADFLAGS.into(), node: None, service: None, timeouts: 0 };
            }
            // IP strings never contain NUL; degrade to an empty node if violated.
            let node = CString::new(format_ip_with_scope(&addr.ip, addr.scope_id, flags)).unwrap_or_default();
            let service = if want_service {
                get_service_string(&Services::default(), addr.port, flags)
            } else {
                None
            };
            return NameinfoReply { status: ARES_SUCCESS.into(), node: Some(node), service, timeouts: 0 };
        }

        if self.endpoints.is_empty() {
            return NameinfoReply { status: ARES_ENOSERVER.into(), node: None, service: None, timeouts: 0 };
        }

        let payload = match dns_query_payload(
            &rdns_name(addr.ip),
            u32::from(RECORD_TYPE_PTR),
            u32::from(ARES_CLASS_IN),
            self.recursion_desired(),
        )
        .and_then(|p| self.with_edns(p))
        .and_then(|p| self.reserve(p))
        {
            Ok(q) => q,
            Err(e) => {
                return NameinfoReply {
                    status: e,
                    node: None,
                    service: None,
                    timeouts: 0,
                }
            }
        };
        let (result, io_timeouts) = self.run_reserved_query(payload, &Cell::new(false)).await;

        let dns_result: Result<&[u8], AresError> = match result {
            Ok(ref buf) => Ok(&buf[..]),
            Err(status) => Err(AresError::from(status)),
        };
        assemble_nameinfo(dns_result, addr.ip, addr.scope_id, addr.port, flags, io_timeouts)
    }

    /// ares_search (legacy): iterate the search plan with freshly built payloads
    /// carrying the caller's class/type.
    pub(crate) async fn search(
        self,
        name: String,
        dnsclass: u32,
        dnstype: u32,
        retry_server_error: bool,
    ) -> Delivery {
        if let Err(e) = validate_query_class_type(dnsclass, dnstype) {
            return Delivery::Raw { result: Err(e.code()), timeouts: 0 };
        }
        let rd = self.recursion_desired();
        self.search_plan(
            name,
            move |candidate| dns_query_payload(candidate, dnstype, dnsclass, rd),
            retry_server_error,
            true,
        )
        .await
    }

    /// ares_search_dnsrec: iterate the search plan over a duplicate of the
    /// caller's record, replacing only query[0]'s name.
    pub(crate) async fn search_dnsrec(
        self,
        template: ares_dns_record_t,
        retry_server_error: bool,
    ) -> Delivery {
        let name = match template.query_at(0) {
            Some((name, _, _)) => name.to_string_lossy().into_owned(),
            None => return Delivery::Raw { result: Err(ARES_EBADQUERY), timeouts: 0 },
        };
        self.search_plan(
            name,
            move |candidate| payload_from_template(&template, candidate),
            retry_server_error,
            // Upstream duplicates the record unchanged: never synthesize an OPT.
            false,
        )
        .await
    }

    /// Shared search-domain driver: retry NXDOMAIN/NODATA/timeout, plus (for the
    /// dnsrec flavor) SERVFAIL/REFUSED/NOTIMP when `retry_server_error`.
    async fn search_plan<F>(
        &self,
        name: String,
        make_payload: F,
        retry_server_error: bool,
        synthesize_edns: bool,
    ) -> Delivery
    where
        F: Fn(&str) -> Result<BytesMut, AresError>,
    {
        if self.endpoints.is_empty() {
            return Delivery::Raw { result: Err(ARES_ENOSERVER), timeouts: 0 };
        }

        let (search_name, alias_found) = match hostaliases_lookup(
            &name,
            self.flags & ARES_FLAG_NOALIASES != 0,
        ) {
            Ok(Some(alias)) => (alias, true),
            Ok(None) => (name, false),
            Err(status) => return Delivery::Raw { result: Err(status), timeouts: 0 },
        };
        let no_search = alias_found || self.flags & ARES_FLAG_NOSEARCH != 0;
        let mut plan =
            SearchPlan::for_search(&search_name, self.config.options.ndots, &self.config.search, no_search);
        let mut had_nodata = false;
        let mut timeouts: c_int = 0;
        let not_cancelled = Cell::new(false);

        loop {
            let payload = match make_payload(&plan.current)
                .and_then(|p| if synthesize_edns { self.with_edns(p) } else { Ok(p) })
                .and_then(|p| self.reserve(p))
            {
                Ok(q) => q,
                Err(e) => return Delivery::Raw { result: Err(e.code()), timeouts },
            };
            let (result, io_timeouts) = self.run_reserved_query(payload, &not_cancelled).await;
            timeouts += io_timeouts;

            let last_error: AresError = match result {
                Ok(buf) => {
                    let summary = summarize(&buf, 0);
                    match summary.rcode {
                        3 => ARES_ENOTFOUND.into(),  // NXDOMAIN
                        2 => ARES_ESERVFAIL.into(),  // SERVFAIL
                        4 => ARES_ENOTIMP.into(),    // NOTIMP
                        5 => ARES_EREFUSED.into(),   // REFUSED
                        0 if summary.ancount > 0 => {
                            return Delivery::Raw { result: Ok(buf), timeouts };
                        }
                        // NOERROR-with-no-answers, or any other rcode → NODATA.
                        _ => {
                            had_nodata = true;
                            ARES_ENODATA.into()
                        }
                    }
                }
                Err(status) => AresError::from(status),
            };

            // Search-domain iteration: NXDOMAIN/NODATA/TIMEOUT, plus server
            // errors for the dnsrec flavor.
            let code = last_error.code();
            let iterate = matches!(code, ARES_ENOTFOUND | ARES_ENODATA | ARES_ETIMEOUT)
                || (retry_server_error && matches!(code, ARES_ESERVFAIL | ARES_EREFUSED | ARES_ENOTIMP));
            if iterate && plan.advance().is_some() {
                continue;
            }

            // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
            let mut status = last_error;
            if had_nodata && status.code() == ARES_ENOTFOUND {
                status = ARES_ENODATA.into();
            }
            return Delivery::Raw { result: Err(status.code()), timeouts };
        }
    }
}

/// Empty/onion rejection shared by ares_search and ares_search_dnsrec — checked
/// before the channel is dereferenced (fires even on a NULL channel).
pub(crate) fn search_precheck(name_str: &str) -> Option<AresError> {
    if name_str.is_empty() {
        return Some(ARES_ENOTFOUND.into());
    }
    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(name_str) {
        return Some(ARES_ENOTFOUND.into());
    }
    None
}

/// ares_gethostbyaddr's direct PTR delivery: parse, add the synthetic record for
/// the queried address, and shape the hostent.
pub(crate) fn on_host_reply(res: Result<&[u8], AresError>, rtype: u16, family: i32, ip: Option<IpAddr>) -> Result<Hostent, AresError> {
    let buf = res?;
    let is_ptr = rtype == RECORD_TYPE_PTR;
    let require = if is_ptr { ReplyRequire::ItemsOrAliases } else { ReplyRequire::Items };
    let mut rrs = addr_reply(buf, rtype, require)?;
    // PTR flows always carry the ip; if that invariant broke, deliver without
    // the synthetic record rather than panic.
    if is_ptr {
        if let Some(ip) = ip {
            push_synthetic_ptr(&mut rrs, ip);
        }
    }
    Ok(Hostent::from_parsed(rrs, family))
}
