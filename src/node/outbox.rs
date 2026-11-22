//! Datagrams on their way out, and the copies MRP may ask for again.
//!
//! The runtime does no I/O: every datagram it builds — a reply, a report, a standalone
//! acknowledgement, the `CloseSession` an eviction owes — is queued here, and the integrator
//! sends whatever [`Runtime::transmit`](super::Runtime::transmit) hands out. One input can
//! produce several (a reply and an eviction report; a timer tick, a report per subscription),
//! which is why this is a queue rather than a return value.
//!
//! [`Resend`] is §4.12.2.1's other half. "Logical retransmission is of a given message as
//! identified by its message counter", so a retransmission is the *same bytes* — re-encoding
//! would draw a new counter and reuse a nonce. MRP keeps at most one reliable message in flight
//! per exchange, so one stored datagram per exchange is exact.

use heapless::{Deque, Vec};

use crate::config::MAX_UDP_MESSAGE;
use crate::exchange::ExchangeKey;
use crate::msg::SessionId;
use crate::platform::Peer;

/// One stored datagram.
type Datagram = Vec<u8, MAX_UDP_MESSAGE>;

/// `Q` datagrams waiting to be sent.
#[derive(Debug)]
pub(crate) struct Outbox<const Q: usize> {
    queue: Deque<(Peer, Datagram), Q>,
    /// The datagram [`Outbox::pop`] last handed out, kept so the caller can borrow it.
    current: Option<(Peer, Datagram)>,
}

impl<const Q: usize> Outbox<Q> {
    pub(crate) const fn new() -> Self {
        Self {
            queue: Deque::new(),
            current: None,
        }
    }

    /// Queues a datagram. `false` if the outbox is full, in which case nothing is queued — a
    /// reliable message is retransmitted by MRP, an unreliable one is lost as on a busy link.
    pub(crate) fn push(&mut self, peer: Peer, bytes: &[u8]) -> bool {
        let Ok(datagram) = Datagram::from_slice(bytes) else {
            return false;
        };
        self.queue.push_back((peer, datagram)).is_ok()
    }

    /// The next datagram, which stays valid until the next call.
    pub(crate) fn pop(&mut self) -> Option<(Peer, &[u8])> {
        self.current = self.queue.pop_front();
        self.current
            .as_ref()
            .map(|(peer, bytes)| (*peer, &bytes[..]))
    }

    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }
}

/// The last reliable datagram sent on each of up to `R` exchanges.
#[derive(Debug)]
pub(crate) struct Resend<const R: usize> {
    entries: Vec<(ExchangeKey, u32, Peer, Datagram), R>,
}

impl<const R: usize> Resend<R> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Keeps `bytes` as the reliable message in flight on `exchange`, replacing the previous
    /// one — MRP has one in flight per exchange, so a new send means the last was acknowledged.
    ///
    /// When every slot is taken the oldest is dropped: its retransmission is lost, which costs
    /// that exchange a timeout on a lossy link and nothing on a clean one.
    pub(crate) fn record(&mut self, exchange: ExchangeKey, counter: u32, peer: Peer, bytes: &[u8]) {
        if R == 0 {
            return;
        }
        self.forget(exchange);
        let Ok(datagram) = Datagram::from_slice(bytes) else {
            return;
        };
        if self.entries.is_full() {
            self.entries.remove(0);
        }
        let _ = self.entries.push((exchange, counter, peer, datagram));
    }

    /// The stored datagram for `exchange`, if its counter is the one MRP asked for.
    pub(crate) fn find(&self, exchange: ExchangeKey, counter: u32) -> Option<(Peer, &[u8])> {
        self.entries
            .iter()
            .find(|(k, c, _, _)| *k == exchange && *c == counter)
            .map(|(_, _, peer, bytes)| (*peer, &bytes[..]))
    }

    pub(crate) fn forget(&mut self, exchange: ExchangeKey) {
        self.entries.retain(|(k, _, _, _)| *k != exchange);
    }

    pub(crate) fn forget_session(&mut self, session: SessionId) {
        self.entries.retain(|(k, _, _, _)| k.session != session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::Role;
    use crate::msg::ExchangeId;
    use crate::platform::PeerAddr;

    const PEER: Peer = Peer::Udp(PeerAddr::new([0; 16]));

    fn key(id: u16) -> ExchangeKey {
        ExchangeKey {
            session: SessionId(1),
            id: ExchangeId(id),
            role: Role::Responder,
        }
    }

    #[test]
    fn a_full_outbox_refuses_rather_than_overwrites() {
        let mut outbox = Outbox::<2>::new();
        assert!(outbox.push(PEER, &[1]));
        assert!(outbox.push(PEER, &[2]));
        assert!(!outbox.push(PEER, &[3]));
        assert_eq!(outbox.pop().map(|(_, b)| b.to_vec()), Some(vec![1]));
        assert_eq!(outbox.pop().map(|(_, b)| b.to_vec()), Some(vec![2]));
        assert!(outbox.pop().is_none());
    }

    #[test]
    fn a_retransmission_is_found_only_by_its_own_counter() {
        let mut resend = Resend::<2>::new();
        resend.record(key(1), 10, PEER, &[0xAA]);
        assert_eq!(
            resend.find(key(1), 10).map(|(_, b)| b.to_vec()),
            Some(vec![0xAA])
        );
        assert!(resend.find(key(1), 11).is_none());
        // A second send on the exchange replaces the first.
        resend.record(key(1), 11, PEER, &[0xBB]);
        assert!(resend.find(key(1), 10).is_none());
        // The oldest is dropped when full.
        resend.record(key(2), 20, PEER, &[2]);
        resend.record(key(3), 30, PEER, &[3]);
        assert!(resend.find(key(1), 11).is_none());
        assert!(resend.find(key(3), 30).is_some());
    }
}
