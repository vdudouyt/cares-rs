//! Reactor-residue kernels tied to the ffi `Callback` enum: retry userdata
//! rebuilds and the dnsrec cache gate. (The pure channel-state helpers these
//! used to sit beside now live in core::channel.)

use std::ffi::c_int;

use crate::ffi::lookups::{Callback, FFIData, SearchDelivery};

impl FFIData {
    /// A retry copy of this task's userdata aimed at `server_index`.
    pub(crate) fn retarget(&self, server_index: usize, timeouts: c_int) -> FFIData {
        FFIData {
            callback: self.callback.clone(),
            arg: self.arg,
            family: self.family,
            expected_record_type: self.expected_record_type,
            ip: self.ip,
            nameinfo_flags: self.nameinfo_flags,
            port: self.port,
            scope_id: self.scope_id,
            server_index,
            timeouts,
        }
    }
}

/// Whether a delivered reply should populate the query cache: plain dnsrec
/// queries and dnsrec-delivery searches. Reads SearchDelivery through a
/// transient RefCell borrow that is dropped at return.
pub(crate) fn wants_dnsrec_cache(cb: &Callback) -> bool {
    match cb {
        Callback::AresCallbackDnsRec(_) => true,
        Callback::Search(lookup) => {
            matches!(lookup.borrow().delivery, SearchDelivery::DnsRec { .. })
        }
        _ => false,
    }
}
