//! EDNS(0) for outgoing queries and their replies: OPT synthesis
//! (`ARES_FLAG_EDNS` / `ARES_OPT_EDNSPSZ`) and the per-server DNS cookie
//! exchange (RFC 7873/9018) — attaching the COOKIE option before each send and
//! validating the echoed one on each reply. The wire codec and the cookie state
//! machine live in `core::edns`; this child of `async_client` binds them to the
//! channel's flags and shared per-server cookie state.

use super::*;

impl AsyncClient {
    /// The OPT UDP payload size for constructed queries: `None` when EDNS is
    /// disabled, `Some(EDNS_PACKETSZ)` for zero, and `ARES_EFORMERR` when the
    /// value does not fit the 16-bit OPT CLASS field.
    pub(crate) fn edns_udp_size(&self) -> Result<Option<u16>, AresError> {
        if self.flags & ARES_FLAG_EDNS == 0 {
            return Ok(None);
        }
        let size = if self.ednspsz == 0 { EDNS_PACKETSZ as i32 } else { self.ednspsz };
        if !(1..=u16::MAX as i32).contains(&size) {
            return Err(ARES_EFORMERR.into());
        }
        Ok(Some(size as u16))
    }

    /// Append the channel's EDNS OPT (ARES_FLAG_EDNS) unless the query has one.
    pub(super) fn with_edns(&self, payload: BytesMut) -> Result<BytesMut, AresError> {
        if edns_wire::has_opt(&payload) {
            return Ok(payload);
        }
        // EDNSPSZ wider than the 16-bit OPT CLASS: rejected before any send.
        let Some(size) = self.edns_udp_size()? else { return Ok(payload) };
        let mut buf = payload.to_vec();
        if !edns_wire::append_opt(&mut buf, size) {
            return Err(ARES_EFORMERR.into());
        }
        Ok(BytesMut::from(buf.as_slice()))
    }

    /// Pass `server`'s cookie state to `f`; `None` once the server has left the
    /// list (a lookup from before a server-list change).
    fn with_cookie<R>(&self, server: ServerId, f: impl FnOnce(&mut ServerCookie) -> R) -> Option<R> {
        if !self.shared.health.borrow().contains(server) {
            return None;
        }
        let mut cookies = self.shared.cookies.borrow_mut();
        Some(f(cookies.entry(server).or_default()))
    }

    /// Attach the COOKIE option for this send (UDP only; removed on TCP). Returns
    /// the 8-byte client cookie placed on the wire, which the response must echo.
    /// `ARES_EFORMERR` means the rewrite would exceed the 16-bit DNS limit.
    pub(super) fn apply_cookie(
        &self,
        payload: &mut Vec<u8>,
        server: ServerId,
        use_tcp: bool,
    ) -> Result<Option<[u8; 8]>, AresError> {
        if !edns_wire::has_opt(payload) {
            return Ok(None);
        }
        if use_tcp {
            // Cookies are deliberately not used over TCP; strip a stale one
            // (e.g. after a BADCOOKIE-driven upgrade).
            if !edns_wire::set_cookie_option(payload, None) {
                return Err(ARES_EFORMERR.into());
            }
            return Ok(None);
        }
        let cookie = self.with_cookie(server, ServerCookie::cookie_for_query).flatten();
        let Some(cookie) = cookie else {
            // Server is known to be unsupported: no cookie.
            if !edns_wire::set_cookie_option(payload, None) {
                return Err(ARES_EFORMERR.into());
            }
            return Ok(None);
        };
        if cookie.len() < 8 {
            return Ok(None);
        }
        let mut client = [0u8; 8];
        client.copy_from_slice(&cookie[..8]);
        if !edns_wire::set_cookie_option(payload, Some(&cookie)) {
            return Err(ARES_EFORMERR.into());
        }
        Ok(Some(client))
    }

    /// Validate a response's COOKIE option against this server's state.
    pub(super) fn validate_cookie(
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
}
