//! Query plugins: protocol extensions hooked into every query's life, kept out
//! of the query engine (`core::async_client::request`). A plugin is registered
//! once per channel with [`AsyncClient::add_plugin`]; the engine runs every
//! registered plugin, in registration order, at each hook:
//!
//! - [`Plugin::on_start`] — once, before the first attempt, on the query packet;
//! - [`Plugin::on_send`] — before each send, on that send's copy of the packet;
//! - [`Plugin::on_receive`] — on each reply carrying the query's id (the first
//!   verdict other than `Accept` wins);
//! - [`Plugin::on_reply`] — the decision step: may rewrite the query packet and
//!   claim the reply as an uncounted re-send (the first `Some` wins);
//! - [`Plugin::on_servers_changed`] — the channel's server list changed.
//!
//! Channel-level state lives inside the plugin (interior mutability: hooks take
//! `&self`); per-query facts come in the [`Ctx`]. Plugins: `edns` (EDNS(0) OPT
//! synthesis, DNS cookies, the FORMERR fallback) and `dns0x20` (question case
//! randomization).
#![forbid(unsafe_code)]

pub(crate) mod dns0x20;
pub(crate) mod edns;

use std::ffi::c_int;

use crate::core::async_client::AsyncClient;
use crate::core::lookup::ServerId;

/// What a plugin sees of the current query attempt.
pub(crate) struct Ctx<'a> {
    pub client: &'a AsyncClient,
    /// The server this attempt reached.
    pub server: ServerId,
    pub use_tcp: bool,
    /// Replies rejected (by a plugin's [`Screen::Reject`]) so far in this query.
    pub rejections: u32,
}

/// A plugin's verdict on a reply carrying the query's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Screen {
    Accept,
    /// Not a genuine reply (stray or spoofed): keep listening.
    Drop,
    /// A genuine reply that must not be used: re-send.
    Reject,
}

/// The reply offered to [`Plugin::on_reply`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum Reply<'a> {
    /// A plugin rejected the reply in [`Plugin::on_receive`].
    Rejected,
    /// An accepted answer.
    Answer(&'a [u8]),
}

/// How a plugin wants the query re-sent (uncounted, to the same server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resend {
    Same,
    /// Switch the query to TCP for good.
    OverTcp,
}

/// A protocol extension hooked into every query. Every hook defaults to a no-op.
pub(crate) trait Plugin {
    /// Once per query, before the first attempt: may rewrite the query packet.
    fn on_start(&self, _cx: &Ctx, _payload: &mut Vec<u8>) {}

    /// Before each send, on that send's copy of the packet. An error ends the
    /// query with that status.
    fn on_send(&self, _cx: &Ctx, _wire: &mut Vec<u8>) -> Result<(), c_int> {
        Ok(())
    }

    /// Each reply carrying the query's id; `sent` is the packet as sent.
    fn on_receive(&self, _cx: &Ctx, _sent: &[u8], _reply: &[u8]) -> Screen {
        Screen::Accept
    }

    /// The decision step: may rewrite the query packet and claim the reply as
    /// an uncounted re-send.
    fn on_reply(&self, _cx: &Ctx, _reply: Reply, _payload: &mut Vec<u8>) -> Option<Resend> {
        None
    }

    /// The channel's server list changed to `servers`.
    fn on_servers_changed(&self, _servers: &[ServerId]) {}
}
