//! The address lookups: `gethostbyname` (preflight cascade, single-family
//! Hostent pick, cache store, sortlist) and `getaddrinfo`, sharing the
//! `resolve_addrinfo` DNS phase (search names x `query_families` A/AAAA race with
//! A-cancels-AAAA), mirroring upstream where `ares_gethostbyname` is a shell over
//! `ares_getaddrinfo`.

use super::*;

impl AsyncClient {
    /// ares_gethostbyname: the pre-DNS cascade (ASCII/onion/family/IP-literal/
    /// hosts/localhost/HOSTALIASES/no-servers/query-cache) then search-domain DNS.
    /// Preflight has no `.await`, so a sync hit fires re-entrantly on first poll.
    pub(crate) async fn gethostbyname(self, hostname: String, family: c_int) -> HostReply {
        let timeouts = Cell::new(0);
        let result = self.gethostbyname_inner(hostname, family, &timeouts).await;
        (result, timeouts.get())
    }

    async fn gethostbyname_inner(
        &self,
        hostname: String,
        family: c_int,
        timeouts: &Cell<c_int>,
    ) -> Result<Hostent, AresError> {
        if !hostname.is_ascii() {
            return Err(ARES_EBADNAME.into());
        }
        if is_onion_domain(&hostname) {
            return Err(ARES_ENOTFOUND.into());
        }
        let filter = AddressFamily::from_af(family).ok_or(ARES_ENOTIMP)?;

        // IP literal (a family mismatch falls through, not fails).
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            let matches = match filter {
                AddressFamily::Ipv4 => ip.is_ipv4(),
                AddressFamily::Ipv6 => ip.is_ipv6(),
                AddressFamily::Any => true,
            };
            if matches {
                return Ok(self.finalize_hostent(Hostent::new(hostname, vec![ip])));
            }
        }

        // Resolver order (`lookup` from resolv.conf, default "fb"): 'f' = hosts
        // file, 'b' = DNS; unknown chars ignored (upstream next_lookup).
        let order: Vec<char> = self.lookups.chars().collect();
        let mut last_error: AresError = ARES_ECONNREFUSED.into();
        for ch in order {
            match ch {
                'f' => {
                    if let Some(lookup) = self.hostsfile().lookup(&hostname, filter) {
                        if !lookup.addrs.is_empty() {
                            return Ok(self.finalize_hostent(Hostent::from_lookup(lookup)));
                        }
                    }

                    // RFC 6761: localhost / *.localhost → loopback (part of the
                    // upstream file lookup).
                    if is_localhost(&hostname) {
                        let addrs = match filter {
                            AddressFamily::Ipv4 => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                            AddressFamily::Ipv6 => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
                            AddressFamily::Any => vec![IpAddr::V6(Ipv6Addr::LOCALHOST), IpAddr::V4(Ipv4Addr::LOCALHOST)],
                        };
                        return Ok(self.finalize_hostent(Hostent::new(hostname, addrs)));
                    }
                }
                'b' => {
                    // RFC 6761: localhost names never reach the nameservers.
                    if is_localhost(&hostname) {
                        continue;
                    }

                    // HOSTALIASES (single-label names); NOALIASES disables it.
                    let (resolved, alias_found) = match hostaliases_lookup(
                        &hostname,
                        self.flags & ARES_FLAG_NOALIASES != 0,
                    ) {
                        Ok(Some(alias)) => (alias, true),
                        Ok(None) => (hostname.clone(), false),
                        Err(status) => return Err(status.into()),
                    };

                    if self.endpoints.is_empty() {
                        last_error = ARES_ENOSERVER.into();
                        continue;
                    }

                    let cache_rtype = if matches!(filter, AddressFamily::Ipv4) { RTYPE_A } else { RTYPE_AAAA };
                    let cache_family = if matches!(filter, AddressFamily::Ipv4) { AF_INET } else { AF_INET6 };
                    let cache_key = CacheKey::new(
                        &resolved,
                        cache_rtype,
                        ARES_CLASS_IN,
                        0,
                        self.recursion_desired(),
                        false,
                    );
                    let cached = self.shared.cache.borrow_mut().get(&cache_key, Instant::now());
                    if let Some(cached) = cached {
                        if let Ok(rrs) = addr_reply(&cached, cache_rtype, ReplyRequire::Items) {
                            return Ok(self.finalize_hostent(Hostent::from_parsed(rrs, cache_family)));
                        }
                    }

                    // Candidate names in order; trailing dots kept verbatim
                    // (unlike ares_search) so query/cache/store keys match.
                    let dots = resolved.chars().filter(|&c| c == '.').count() as u32;
                    let no_search = alias_found || self.flags & ARES_FLAG_NOSEARCH != 0;
                    let names: Vec<String> = if !no_search && dots < self.config.options.ndots && !self.config.search.is_empty() {
                        let mut v: Vec<String> = self.config.search.iter().map(|d| format!("{resolved}.{d}")).collect();
                        v.push(resolved.clone());
                        v
                    } else {
                        vec![resolved.clone()]
                    };
                    // AF_UNSPEC queries A+AAAA in parallel via the shared core;
                    // the Hostent holds one family, preferring IPv6.
                    let rtypes: Vec<u16> = match family {
                        AF_INET => vec![RTYPE_A],
                        AF_INET6 => vec![RTYPE_AAAA],
                        _ => vec![RTYPE_A, RTYPE_AAAA],
                    };
                    let lookup = self.resolve_addrinfo(&names, &rtypes).await;
                    timeouts.set(lookup.timeouts);
                    if lookup.replies.is_empty() {
                        last_error = lookup.status;
                        continue;
                    }
                    let pick = lookup.replies.iter().position(|f| f.rtype == RTYPE_AAAA).unwrap_or(0);
                    let Some(reply) = lookup.replies.into_iter().nth(pick) else {
                        last_error = ARES_ENODATA.into();
                        continue;
                    };
                    let hfamily = if reply.rtype == RTYPE_AAAA { AF_INET6 } else { AF_INET };

                    if self.shared.cache.borrow().enabled() {
                        let mut store = vec![lookup.name.clone()];
                        if resolved != lookup.name {
                            store.push(resolved.clone());
                        }
                        let ttl = reply.rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                        let template = CacheKey::new(
                            &lookup.name,
                            reply.rtype,
                            ARES_CLASS_IN,
                            0,
                            self.recursion_desired(),
                            false,
                        );
                        self.shared.cache.borrow_mut().store_names(store, &template, ttl, &reply.buf, Instant::now());
                    }
                    let rrs = reply.rrs;
                    return Ok(self.finalize_hostent(Hostent::from_parsed(rrs, hfamily)));
                }
                _ => {}
            }
        }
        Err(last_error)
    }

    fn finalize_hostent(&self, mut hostent: Hostent) -> Hostent {
        hostent.sort_addrs(&self.sortlist);
        hostent
    }

    /// Query `name` for each family concurrently on the shared mailbox (replies
    /// self-demux by fd). An A answer with real records sets `cancelled` so the AAAA
    /// sibling stops retrying; IPv6 success does NOT cancel A.
    async fn query_families(&self, name: &str, rtypes: &[u16]) -> Vec<QueryOutcome> {
        let rd = self.recursion_desired();
        let a_idx = rtypes.iter().position(|&rt| rt == RTYPE_A);
        // Shared by both families: an A answer cancels the AAAA sibling's retries.
        let cancelled = Cell::new(false);
        let mut results: Vec<Option<QueryOutcome>> = (0..rtypes.len()).map(|_| None).collect();

        let cancelled = &cancelled;
        let sub = |i: usize| {
            let payload = dns_query_payload(name, u32::from(rtypes[i]), u32::from(ARES_CLASS_IN), rd)
                .and_then(|p| self.with_edns(p))
                .and_then(|p| self.reserve(p));
            async move {
                match payload {
                    Ok(q) => self.request(q, cancelled).await,
                    Err(e) => (Err(e.code()), 0),
                }
            }
        };
        if rtypes.len() == 1 {
            results[0] = Some(sub(0).await);
        } else {
            let mut f0 = pin!(sub(0).fuse());
            let mut f1 = pin!(sub(1).fuse());
            while results.iter().any(Option::is_none) {
                select_biased! {
                    r = f0 => {
                        // A completed: cancel the AAAA sibling on a real answer.
                        if Some(0) == a_idx {
                            if let (Ok(buf), _) = &r {
                                let s = summarize(buf, 0);
                                if s.rcode == 0 && s.ancount > 0 {
                                    cancelled.set(true);
                                }
                            }
                        }
                        results[0] = Some(r);
                    }
                    r = f1 => { results[1] = Some(r); }
                }
            }
        }
        results.into_iter().flatten().collect()
    }

    /// Shared address-resolution DNS phase for `gethostbyname`/`getaddrinfo`: try
    /// each candidate name, querying its families. A name succeeds if any family
    /// yields records.
    async fn resolve_addrinfo(&self, names: &[String], rtypes: &[u16]) -> AddrLookup {
        let mut timeouts: c_int = 0;
        let mut last_error: AresError = ARES_ENODATA.into();
        let mut had_nodata = false;

        for (i, name) in names.iter().enumerate() {
            let results = self.query_families(name, rtypes).await;

            let mut replies: Vec<FamilyReply> = Vec::new();
            for (&rtype, (result, io_timeouts)) in rtypes.iter().zip(results) {
                match result {
                    Ok(buf) => match addr_reply(&buf, rtype, ReplyRequire::Items) {
                        Ok(rrs) => {
                            timeouts += io_timeouts;
                            replies.push(FamilyReply { rtype, buf, rrs });
                        }
                        Err(e) => {
                            if e.code() == ARES_ENODATA {
                                had_nodata = true;
                            }
                            last_error = e;
                        }
                    },
                    Err(status) => {
                        if status == ARES_ETIMEOUT {
                            timeouts += 1;
                        }
                        last_error = AresError::from(status);
                    }
                }
            }

            if !replies.is_empty() {
                return AddrLookup { name: name.clone(), replies, status: ARES_SUCCESS.into(), timeouts };
            }

            // Advance while the aggregate code is retryable.
            let code = last_error.code();
            let retryable = matches!(
                code,
                ARES_ENODATA | ARES_ENOTFOUND | ARES_ETIMEOUT | ARES_ESERVFAIL | ARES_ENOTIMP | ARES_EREFUSED
            );
            if !(retryable && i + 1 < names.len()) {
                break;
            }
            last_error = ARES_ENODATA.into();
        }

        // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
        let code = last_error.code();
        let status = if had_nodata && code == ARES_ENOTFOUND { ARES_ENODATA } else { code };
        let name = names.last().cloned().unwrap_or_default();
        AddrLookup { name, replies: Vec::new(), status: status.into(), timeouts }
    }

    /// ares_getaddrinfo: preflight, then the configured lookup order (hosts `f` /
    /// DNS `b`), merging family records, RFC 6724 sorting unless ARES_AI_NOSORT,
    /// and carrying the CNAME chain + canonical name.
    pub(crate) async fn getaddrinfo(
        self,
        hostname_raw: String,
        ai_family: c_int,
        ai_flags: c_int,
        socktype: c_int,
        protocol: c_int,
    ) -> AddrInfoOut {
        // The raw name keeps its trailing dot for the SearchPlan; checks and the
        // delivered canonical name use the stripped form.
        let hostname = hostname_raw.strip_suffix('.').unwrap_or(&hostname_raw);

        if !matches!(ai_family, libc::AF_INET | libc::AF_INET6 | libc::AF_UNSPEC) {
            return fail(ARES_ENOTIMP);
        }
        if hostname.is_empty() || is_onion_domain(hostname) {
            return fail(ARES_ENOTFOUND);
        }

        let can_name = ai_flags & crate::ffi::ARES_AI_CANONNAME != 0;
        let env_hosts = ai_flags & crate::ffi::ARES_AI_ENVHOSTS != 0;
        let no_sort = ai_flags & crate::ffi::ARES_AI_NOSORT != 0;

        // IP literal (a family mismatch fails — no fall-through).
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            let matches = match ai_family {
                libc::AF_INET => ip.is_ipv4(),
                libc::AF_INET6 => ip.is_ipv6(),
                libc::AF_UNSPEC => true,
                _ => false,
            };
            if matches {
                let cnames = if can_name {
                    vec![CnameEntry {
                        ttl: 0,
                        alias: None,
                        name: CString::new(hostname).ok(),
                    }]
                } else {
                    Vec::new()
                };
                return AddrInfoOut::success(
                    hostname.to_string(),
                    vec![AddrRecord { ip, ttl: 0 }],
                    cnames,
                    socktype,
                    protocol,
                );
            }
            return fail(ARES_ENOTFOUND);
        }

        let family_filter = AddressFamily::from_af(ai_family).unwrap_or(AddressFamily::Any);
        let order: Vec<char> = self.lookups.chars().collect();
        let mut last_error: AresError = ARES_ECONNREFUSED.into();

        for ch in order {
            match ch {
                'f' => {
                    // Hosts file, honouring ARES_AI_ENVHOSTS when requested.
                    if let Some(lookup) = self.hosts_lookup(hostname, family_filter, env_hosts) {
                        if !lookup.addrs.is_empty() {
                            let mut records: Vec<AddrRecord> = lookup
                                .addrs
                                .iter()
                                .map(|&ip| AddrRecord { ip, ttl: 0 })
                                .collect();
                            // Upstream merges the loopback fallback for localhost
                            // even when the hosts entry covered only one family.
                            if is_localhost(hostname) {
                                merge_loopback(&mut records, family_filter);
                            }
                            if !no_sort {
                                sort_addrinfo(&mut records);
                            }
                            let cnames = if can_name {
                                hosts_cnames(&lookup)
                            } else {
                                Vec::new()
                            };
                            return AddrInfoOut::success(
                                hostname.to_string(),
                                records,
                                cnames,
                                socktype,
                                protocol,
                            );
                        }
                    }

                    // RFC 6761 loopback fallback (also the whole answer when no
                    // hosts entry exists).
                    if is_localhost(hostname) {
                        let mut records: Vec<AddrRecord> = Vec::new();
                        merge_loopback(&mut records, family_filter);
                        if !no_sort {
                            sort_addrinfo(&mut records);
                        }
                        return AddrInfoOut::success(
                            hostname.to_string(),
                            records,
                            Vec::new(),
                            socktype,
                            protocol,
                        );
                    }
                }
                'b' => {
                    if is_localhost(hostname) {
                        continue;
                    }
                    if self.endpoints.is_empty() {
                        last_error = ARES_ENOSERVER.into();
                        continue;
                    }

                    let rtypes: Vec<u16> = match ai_family {
                        libc::AF_INET => vec![RTYPE_A],
                        libc::AF_INET6 => vec![RTYPE_AAAA],
                        _ => vec![RTYPE_A, RTYPE_AAAA],
                    };
                    let no_aliases = self.flags & ARES_FLAG_NOALIASES != 0;
                    let (search_name, alias_found) = match hostaliases_lookup(&hostname_raw, no_aliases) {
                        Ok(Some(alias)) => (alias, true),
                        Ok(None) => (hostname_raw.clone(), false),
                        Err(status) => return fail(status),
                    };
                    let no_search = alias_found || self.flags & ARES_FLAG_NOSEARCH != 0;
                    let names = SearchPlan::for_search(
                        &search_name,
                        self.config.options.ndots,
                        &self.config.search,
                        no_search,
                    )
                    .into_names();
                    let lookup = self.resolve_addrinfo(&names, &rtypes).await;
                    if lookup.replies.is_empty() {
                        last_error = lookup.status;
                        continue;
                    }
                    let mut cnames: Vec<CnameEntry> = Vec::new();
                    let mut records: Vec<AddrRecord> = Vec::new();
                    for reply in lookup.replies {
                        records.extend(reply.rrs.items);
                        cnames.extend(reply.rrs.cnames);
                    }
                    let name = cnames
                        .iter()
                        .rev()
                        .find_map(|c| c.name.clone())
                        .map(|c| c.to_string_lossy().into_owned())
                        .unwrap_or(lookup.name);
                    if !no_sort {
                        sort_addrinfo(&mut records);
                    }
                    return AddrInfoOut::success(name, records, cnames, socktype, protocol);
                }
                _ => {}
            }
        }
        fail(last_error.code())
    }
}

/// One family's reply within an address lookup: wire type, raw reply (kept for
/// the gethostbyname query cache), and parsed address records.
struct FamilyReply {
    rtype: u16,
    buf: Vec<u8>,
    rrs: ParsedRRs<AddrRecord>,
}

/// Outcome of [`AsyncClient::resolve_addrinfo`]: the name that produced records
/// (or the last tried), per-family replies, status, and timeout count.
struct AddrLookup {
    name: String,
    replies: Vec<FamilyReply>,
    status: AresError,
    timeouts: c_int,
}

/// The safe result the FFI turns into an `ares_addrinfo`.
pub(crate) struct AddrInfoOut {
    pub name: String,
    pub records: Vec<AddrRecord>,
    pub cnames: Vec<CnameEntry>,
    pub socktype: c_int,
    pub protocol: c_int,
    pub status: AresError,
}

impl AddrInfoOut {
    fn success(
        name: String,
        records: Vec<AddrRecord>,
        cnames: Vec<CnameEntry>,
        socktype: c_int,
        protocol: c_int,
    ) -> Self {
        AddrInfoOut {
            name,
            records,
            cnames,
            socktype,
            protocol,
            status: ARES_SUCCESS.into(),
        }
    }
}

fn fail(status: c_int) -> AddrInfoOut {
    AddrInfoOut {
        name: String::new(),
        records: Vec::new(),
        cnames: Vec::new(),
        socktype: 0,
        protocol: 0,
        status: status.into(),
    }
}

/// Add RFC 6761 loopback addresses for any requested family the hosts entry did
/// not provide. IPv6 before IPv4, matching upstream.
fn merge_loopback(records: &mut Vec<AddrRecord>, filter: AddressFamily) {
    let has_v4 = records.iter().any(|r| r.ip.is_ipv4());
    let has_v6 = records.iter().any(|r| r.ip.is_ipv6());
    if matches!(filter, AddressFamily::Any | AddressFamily::Ipv6) && !has_v6 {
        records.push(AddrRecord { ip: IpAddr::V6(Ipv6Addr::LOCALHOST), ttl: 0 });
    }
    if matches!(filter, AddressFamily::Any | AddressFamily::Ipv4) && !has_v4 {
        records.push(AddrRecord { ip: IpAddr::V4(Ipv4Addr::LOCALHOST), ttl: 0 });
    }
}

/// Hosts-file CNAME chain: each alias points at the entry's primary host; with
/// no aliases, a single alias-less entry names the primary.
fn hosts_cnames(lookup: &HostLookup) -> Vec<CnameEntry> {
    let primary = CString::new(lookup.canonical.as_str()).ok();
    if lookup.aliases.is_empty() {
        return vec![CnameEntry { ttl: 0, alias: None, name: primary }];
    }
    lookup
        .aliases
        .iter()
        .map(|alias| CnameEntry {
            ttl: 0,
            alias: CString::new(alias.as_str()).ok(),
            name: primary.clone(),
        })
        .collect()
}

/// HOSTALIASES for single-label names: `Ok(Some)` means use exactly that target
/// as the sole query name (no search-domain expansion); `Ok(None)` means normal
/// search applies. `PermissionDenied` → `ARES_EFILE`.
pub(super) fn hostaliases_lookup(hostname: &str, no_aliases: bool) -> Result<Option<String>, c_int> {
    if no_aliases || hostname.contains('.') {
        return Ok(None);
    }
    let Ok(aliases_path) = std::env::var("HOSTALIASES") else {
        return Ok(None);
    };
    match std::fs::read_to_string(&aliases_path) {
        Ok(content) => {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(hostname) {
                    return Ok(Some(parts[1].to_string()));
                }
            }
            Ok(None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(ARES_EFILE),
        Err(_) => Ok(None),
    }
}
