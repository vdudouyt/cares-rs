//! Channel-wide DNS transaction ids (upstream `generate_unique_qid` +
//! `channel->queries_by_qid`): every in-flight query holds a distinct id,
//! reserved once at creation, kept across retries and released when the query
//! ends. Because a shared socket only ever carries this channel's queries, a
//! per-socket inbox keyed by qid can never see a clash.

use std::collections::HashSet;
use std::rc::Rc;

use bytes::BytesMut;

use crate::core::async_client::ChannelShared;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Random draws before falling back to a linear scan for a free id.
const RANDOM_TRIES: usize = 64;

/// The channel's in-flight transaction ids and the RNG they are drawn from
/// (channel-owned, like upstream's `channel->rand_state`).
pub(crate) struct QidRegistry {
    in_flight: HashSet<u16>,
    rng: StdRng,
}

impl QidRegistry {
    pub(crate) fn new() -> Self {
        QidRegistry { in_flight: HashSet::new(), rng: StdRng::from_entropy() }
    }

    /// Number of ids currently in flight.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.in_flight.len()
    }

    /// A draw from the channel RNG (also the failover-probe chance roll, as
    /// upstream draws both from `channel->rand_state`).
    pub(crate) fn random_u16(&mut self) -> u16 {
        self.rng.r#gen()
    }

    /// A fresh id not in flight; `None` only when all 65536 are taken.
    fn pick(&mut self) -> Option<u16> {
        for _ in 0..RANDOM_TRIES {
            let id = self.rng.r#gen::<u16>();
            if !self.in_flight.contains(&id) {
                return Some(id);
            }
        }
        (0..=u16::MAX).find(|id| !self.in_flight.contains(id))
    }
}

/// One reserved id; dropping it returns the id to the registry.
pub(crate) struct QidLease {
    id: u16,
    shared: Rc<ChannelShared>,
}

impl QidLease {
    /// Reserve a fresh id; `None` if every id is in flight.
    pub(crate) fn reserve(shared: &Rc<ChannelShared>) -> Option<Self> {
        let mut reg = shared.qids.borrow_mut();
        let id = reg.pick()?;
        reg.in_flight.insert(id);
        Some(QidLease { id, shared: shared.clone() })
    }

    pub(crate) fn id(&self) -> u16 {
        self.id
    }
}

impl Drop for QidLease {
    fn drop(&mut self) {
        self.shared.qids.borrow_mut().in_flight.remove(&self.id);
    }
}

/// A query packet stamped with its reserved id; the id stays reserved for as
/// long as this (or the request that consumes it) lives.
pub(crate) struct ReservedQuery {
    pub payload: BytesMut,
    pub lease: QidLease,
}

impl ReservedQuery {
    /// The transaction id on the wire.
    pub(crate) fn qid(&self) -> u16 {
        self.lease.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_leases_are_distinct_and_released_on_drop() {
        let sh = ChannelShared::new();
        let a = QidLease::reserve(&sh).unwrap();
        let b = QidLease::reserve(&sh).unwrap();
        assert_ne!(a.id(), b.id());
        assert_eq!(sh.qids.borrow().in_flight.len(), 2);
        let freed = a.id();
        drop(a);
        assert!(!sh.qids.borrow().in_flight.contains(&freed));
        assert_eq!(sh.qids.borrow().in_flight.len(), 1);
    }

    #[test]
    fn exhaustion_returns_none_and_a_release_makes_room() {
        let sh = ChannelShared::new();
        sh.qids.borrow_mut().in_flight.extend(0..=u16::MAX);
        assert!(QidLease::reserve(&sh).is_none());
        sh.qids.borrow_mut().in_flight.remove(&4242);
        let lease = QidLease::reserve(&sh).unwrap();
        assert_eq!(lease.id(), 4242, "the scan finds the only free id");
    }
}
