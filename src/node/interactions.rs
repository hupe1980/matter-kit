//! What one interaction remembers between its own messages (§10.2.3).
//!
//! Per exchange, and that is the whole point. §10.2.3 makes a reply too large for one datagram a
//! *series*: "each data message requires a response before the next data message can be sent",
//! so the request outlives the message that carried it and the cursor remembers the position in
//! it. A node talks to more than one controller at a time — a certification run always does,
//! and a commissioned home does for as long as it has two hubs — and one copy of this state
//! shared between them resumes each controller's series wherever the *other* one left off.
//!
//! Nothing on the wire says so. Every message is well-formed, carries the right ids, and is
//! acknowledged; the data inside is simply someone else's — filtered for someone else's
//! privileges.

use heapless::Vec;

use crate::config::MAX_UDP_PAYLOAD;
use crate::exchange::{EXCHANGE_IDLE_TIMEOUT, ExchangeKey};
use crate::im::ReadCursor;
use crate::msg::SessionId;
use crate::platform::Instant;

/// A subscription whose priming report is going out (§8.5.2).
///
/// §8.5.2 makes the grant the *fourth* message of the exchange, not the first: the report goes
/// out, the subscriber acknowledges it, and only then is the id it will see confirmed. So the id
/// has to survive between two dispatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingSubscribe {
    pub(crate) id: u32,
    pub(crate) max_interval_s: u16,
    /// Whether the priming report chunked, in which case the acknowledgement asks for the rest
    /// (§10.2.3) and the response is still owed.
    pub(crate) more_chunks: bool,
}

/// One exchange's series state.
#[derive(Debug)]
pub(crate) struct Interaction {
    /// §10.2.3's position in the series.
    pub(crate) read_cursor: ReadCursor,
    /// The read request being served, kept because the continuation is served from the same
    /// bytes. A commissioner's first read is a wildcard over several clusters and never fits in
    /// one datagram, so this is the ordinary path and not an edge case.
    pub(crate) pending_read: Vec<u8, MAX_UDP_PAYLOAD>,
    /// A subscription whose priming report is still going out.
    pub(crate) pending_subscribe: Option<PendingSubscribe>,
}

impl Interaction {
    const fn new() -> Self {
        Self {
            read_cursor: ReadCursor::START,
            pending_read: Vec::new(),
            pending_subscribe: None,
        }
    }

    /// Whether nothing is part-way through, so the exchange may be closed.
    pub(crate) fn idle(&self) -> bool {
        self.pending_read.is_empty() && self.pending_subscribe.is_none()
    }
}

/// [`Interaction`] per open exchange, `I` of them.
#[derive(Debug)]
pub(crate) struct Interactions<const I: usize> {
    entries: Vec<(ExchangeKey, Instant, Interaction), I>,
}

impl<const I: usize> Interactions<I> {
    pub(crate) const fn new() -> Self {
        const {
            assert!(I > 0, "an interaction table must hold at least one series");
        }
        Self {
            entries: Vec::new(),
        }
    }

    /// This exchange's state, created empty on first use.
    ///
    /// An exchange the stack reclaimed (`EXCHANGE_IDLE_TIMEOUT`) leaves its entry behind, and
    /// exchange ids are the peer's to choose and to reuse. A stale `pending_read` under a reused
    /// id makes a *new* read look like a continuation of a dead one — the same cross-talk this
    /// type exists to prevent, arriving through the other door. So entries expire on the stack's
    /// own schedule.
    ///
    /// When every entry is live, the oldest is dropped: that series restarts rather than
    /// resuming, which is the safe direction — its next acknowledgement reads as a finished
    /// series and is answered with nothing, never with another series' data. `None` only if the
    /// table has no capacity at all, which `I > 0` rules out.
    pub(crate) fn get(&mut self, key: ExchangeKey, now: Instant) -> Option<&mut Interaction> {
        self.entries.retain(|(k, seen, _)| {
            *k == key || now.saturating_duration_since(*seen) <= EXCHANGE_IDLE_TIMEOUT
        });
        if !self.entries.iter().any(|(k, _, _)| *k == key) {
            if self.entries.is_full() {
                self.entries.remove(0);
            }
            self.entries.push((key, now, Interaction::new())).ok()?;
        }
        let entry = self.entries.iter_mut().find(|(k, _, _)| *k == key)?;
        entry.1 = now;
        Some(&mut entry.2)
    }

    /// This exchange's state, if it has any.
    pub(crate) fn find(&self, key: ExchangeKey) -> Option<&Interaction> {
        self.entries
            .iter()
            .find(|(k, _, _)| *k == key)
            .map(|(_, _, i)| i)
    }

    /// Whether this exchange has nothing part-way through. True for one never seen.
    pub(crate) fn idle(&self, key: ExchangeKey) -> bool {
        self.find(key).is_none_or(Interaction::idle)
    }

    /// Whether this subscription's priming report is still going out, on any exchange.
    ///
    /// Asked per subscription rather than "is anything priming", which would stop the whole node
    /// reporting whenever one controller subscribes.
    pub(crate) fn priming(&self, subscription: u32) -> bool {
        self.entries.iter().any(|(_, _, state)| {
            state
                .pending_subscribe
                .is_some_and(|p| p.id == subscription)
        })
    }

    /// Drops an exchange's state, which closing it makes unreachable.
    pub(crate) fn forget(&mut self, key: ExchangeKey) {
        self.entries.retain(|(k, _, _)| *k != key);
    }

    /// Drops every exchange's state on a session that has gone.
    pub(crate) fn forget_session(&mut self, session: SessionId) {
        self.entries.retain(|(k, _, _)| k.session != session);
    }

    /// How many exchanges this table holds state for.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::Role;
    use crate::msg::ExchangeId;
    use crate::platform::Duration;

    fn key(id: u16) -> ExchangeKey {
        ExchangeKey {
            session: SessionId(1),
            id: ExchangeId(id),
            role: Role::Responder,
        }
    }

    #[test]
    fn a_full_table_drops_the_oldest_series() {
        let mut table = Interactions::<2>::new();
        let now = Instant::ZERO;
        table
            .get(key(1), now)
            .unwrap()
            .pending_read
            .push(1)
            .unwrap();
        table
            .get(key(2), now)
            .unwrap()
            .pending_read
            .push(2)
            .unwrap();
        table
            .get(key(3), now)
            .unwrap()
            .pending_read
            .push(3)
            .unwrap();
        assert!(
            table.idle(key(1)),
            "the oldest series was dropped, not resumed"
        );
        assert_eq!(table.find(key(2)).unwrap().pending_read[..], [2]);
        assert_eq!(table.find(key(3)).unwrap().pending_read[..], [3]);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn an_expired_series_is_not_continued_on_a_reused_exchange_id() {
        let mut table = Interactions::<4>::new();
        table
            .get(key(7), Instant::ZERO)
            .unwrap()
            .pending_read
            .push(0xAA)
            .unwrap();
        // Another exchange arrives after the idle timeout: the stale entry goes, and a peer
        // reusing id 7 later starts afresh.
        let later = Instant::ZERO
            .saturating_add(EXCHANGE_IDLE_TIMEOUT)
            .saturating_add(Duration::from_secs(1));
        table.get(key(8), later);
        assert!(table.find(key(7)).is_none());
        assert!(table.get(key(7), later).unwrap().idle());
    }

    #[test]
    fn priming_is_asked_per_subscription() {
        let mut table = Interactions::<4>::new();
        table.get(key(1), Instant::ZERO).unwrap().pending_subscribe = Some(PendingSubscribe {
            id: 9,
            max_interval_s: 60,
            more_chunks: true,
        });
        assert!(table.priming(9));
        assert!(!table.priming(10));
        table.forget_session(SessionId(1));
        assert!(!table.priming(9));
    }
}
