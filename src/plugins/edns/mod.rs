//! EDNS(0) (RFC 6891) and DNS cookies (RFC 7873/9018):
//!
//! - OPT synthesis for constructed queries (`ARES_FLAG_EDNS` /
//!   `ARES_OPT_EDNSPSZ`), run at query build, before a query exists;
//! - [`EdnsPlugin`], the query plugin: attaches the server's COOKIE option
//!   before each send, validates the echoed one on each reply (re-sending on
//!   BADCOOKIE, over TCP once it persists), and falls back to a plain query when
//!   a server answers the OPT-bearing one with FORMERR.
//!
//! The wire codec and the cookie state machine live in [`wire`].

pub(crate) mod wire;

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_int;

use bytes::BytesMut;

use self::wire::{CookieVerdict, ServerCookie, EDNS_PACKETSZ};
use super::{Ctx, Plugin, Reply, Resend, ReceiveVerdict};
use crate::core::async_client::AsyncClient;
use crate::core::lookup::{summarize, ServerId};
use crate::core::AresError;
use crate::ffi::ares_options::ARES_FLAG_EDNS;
use crate::ffi::error::ARES_EFORMERR;

/// BADCOOKIE replies after which the query switches to TCP, where cookies are
/// not used (e.g. AnyCast rotation keeps invalidating the server cookie).
const MAX_BADCOOKIE: u32 = 3;

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
    pub(crate) fn with_edns(&self, payload: BytesMut) -> Result<BytesMut, AresError> {
        if wire::has_opt(&payload) {
            return Ok(payload);
        }
        // EDNSPSZ wider than the 16-bit OPT CLASS: rejected before any send.
        let Some(size) = self.edns_udp_size()? else { return Ok(payload) };
        let mut buf = payload.to_vec();
        if !wire::append_opt(&mut buf, size) {
            return Err(ARES_EFORMERR.into());
        }
        Ok(BytesMut::from(buf.as_slice()))
    }
}

/// The EDNS query plugin: per-server DNS cookie state for the channel, and the
/// BADCOOKIE / FORMERR re-send decisions.
#[derive(Default)]
pub(crate) struct EdnsPlugin {
    cookies: RefCell<HashMap<ServerId, ServerCookie>>,
}

impl EdnsPlugin {
    pub(crate) fn new() -> Self {
        EdnsPlugin::default()
    }

    /// Pass `server`'s cookie state to `f`; `None` once the server has left the
    /// list (a lookup from before a server-list change).
    fn with_cookie<R>(&self, cx: &Ctx, f: impl FnOnce(&mut ServerCookie) -> R) -> Option<R> {
        if !cx.client.shared.health.borrow().contains(cx.server) {
            return None;
        }
        let mut cookies = self.cookies.borrow_mut();
        Some(f(cookies.entry(cx.server).or_default()))
    }
}

impl Plugin for EdnsPlugin {
    /// Attach the COOKIE option for this send (UDP only; removed on TCP).
    /// Cookies are re-evaluated per server/transport before every send: a
    /// BADCOOKIE retry must pick up the learned server cookie, a TCP upgrade
    /// must strip it. No OPT on the packet → untouched. `ARES_EFORMERR` means
    /// the rewrite would exceed the 16-bit DNS limit.
    fn on_send(&self, cx: &Ctx, packet: &mut Vec<u8>) -> Result<(), c_int> {
        if !wire::has_opt(packet) {
            return Ok(());
        }
        // Cookies are deliberately not used over TCP: strip a stale one (e.g.
        // after a BADCOOKIE-driven upgrade). A server known not to support
        // them, or no longer in the list, gets none either.
        let cookie = if cx.use_tcp { None } else { self.with_cookie(cx, ServerCookie::cookie_for_query).flatten() };
        set_cookie(packet, cookie.as_deref())
    }

    /// Validate the reply's COOKIE option against this server's state and the
    /// client cookie that was sent (RFC 7873 §5.3: a mismatch is dropped as
    /// spoofed).
    fn on_receive(&self, cx: &Ctx, sent: &[u8], reply: &[u8]) -> ReceiveVerdict {
        let sent_client: Option<[u8; 8]> = if cx.use_tcp {
            None
        } else {
            wire::cookie_option(sent).and_then(|c| c.get(..8)).and_then(|c| c.try_into().ok())
        };
        let rcode = wire::extended_rcode(reply, summarize(reply, 0).rcode);
        let verdict = self.with_cookie(cx, |cookie| cookie.validate_response(reply, sent_client.as_ref(), rcode));
        match verdict.unwrap_or(CookieVerdict::Accept) {
            CookieVerdict::Accept => ReceiveVerdict::Accept,
            CookieVerdict::Drop => ReceiveVerdict::Drop,
            CookieVerdict::BadCookie => ReceiveVerdict::Reject,
        }
    }

    fn on_reply(&self, cx: &Ctx, reply: Reply, payload: &mut Vec<u8>) -> Option<Resend> {
        match reply {
            // BADCOOKIE: re-send with the learned server cookie; persistent
            // BADCOOKIE upgrades to TCP.
            Reply::Rejected if cx.rejections + 1 >= MAX_BADCOOKIE => Some(Resend::OverTcp),
            Reply::Rejected => Some(Resend::Same),
            // FORMERR fallback: a server that does not understand EDNS answers
            // the OPT-bearing query with FORMERR. Strip the OPT (and cookie)
            // and retry the same server uncounted.
            Reply::Answer(buf) => {
                let formerr = summarize(buf, 0).rcode == 1;
                (formerr && wire::has_opt(payload) && wire::strip_opt(payload)).then_some(Resend::Same)
            }
        }
    }

    fn on_servers_changed(&self, servers: &[ServerId]) {
        self.cookies.borrow_mut().retain(|id, _| servers.contains(id));
    }
}

/// Set (or remove) the packet's COOKIE option; `ARES_EFORMERR` when the
/// rewrite would exceed the 16-bit DNS limit.
fn set_cookie(packet: &mut Vec<u8>, cookie: Option<&[u8]>) -> Result<(), c_int> {
    if wire::set_cookie_option(packet, cookie) {
        Ok(())
    } else {
        Err(ARES_EFORMERR)
    }
}
