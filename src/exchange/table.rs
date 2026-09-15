//! The set of open exchanges, sized by [`Config`].
//!
//! An exchange is identified by its id *and* by who initiated it (Core §4.10): two nodes
//! that each start an exchange may each pick the number 7, and they are two different
//! conversations. Keying the table on the pair is what keeps them apart — keying it on the
//! id alone is a bug that only appears when both ends are busy.

use core::marker::PhantomData;

use heapless::Vec;

use super::mrp::{Mrp, MrpParams};
use crate::config::{AssertValid, Config};
use crate::error::{Error, ErrorCode, Result};
use crate::msg::{ExchangeId, ProtocolId, SessionId};
use crate::platform::{Duration, Instant, Peer};

/// Which end of an exchange a node is (Core §4.4.3.1, the **I** flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// This node started the exchange, and sets the **I** flag on what it sends.
    Initiator,
    /// The peer started it.
    Responder,
}

impl Role {
    /// The role of whoever is on the other end.
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }

    /// Whether this node sets the **I** flag.
    #[must_use]
    pub const fn is_initiator(self) -> bool {
        matches!(self, Self::Initiator)
    }
}

/// What identifies an exchange within a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExchangeKey {
    /// The session it lives on.
    pub session: SessionId,
    /// The 16-bit exchange id.
    pub id: ExchangeId,
    /// Which end this node is. Part of the key, not a property: the peer may be using the
    /// same id for an exchange of its own.
    pub role: Role,
}

/// One open exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exchange {
    /// What identifies it.
    pub key: ExchangeKey,
    /// Which protocol is speaking over it.
    pub protocol: ProtocolId,
    /// Its reliability state.
    pub mrp: Mrp,
    /// Where the peer is, once a message has arrived from it or the caller has said.
    ///
    /// It decides two things: where a reply goes, and — per Core §4.12.4 — whether MRP runs
    /// on this exchange at all, since BTP and TCP carry their own reliability.
    pub peer: Option<Peer>,
    /// When it was opened.
    pub opened: Instant,
    /// When a message last arrived on it or went out on it.
    ///
    /// This, not [`Exchange::opened`], is what [`ExchangeTable::reap`] judges: a chunked read
    /// or a BDX transfer is legitimately long-lived, and reaping by age would cut it off
    /// mid-transfer. What must not survive is an exchange nothing is *using*.
    pub last_activity: Instant,
    /// Whether this is §4.10.5.2's *ephemeral* exchange.
    ///
    /// "Create an ephemeral exchange from the incoming message and send an immediate
    /// standalone acknowledgement … The message SHALL NOT be forwarded to the upper layer …
    /// The ephemeral exchange created for such duplicate or unknown messages with R Flag set
    /// is automatically closed in Standalone acknowledgement processing."
    ///
    /// It exists for exactly one reason: a reliable message this node cannot act on still owes
    /// its sender an acknowledgement, or the sender retransmits it five times. Holding a real
    /// exchange open to do that is what lets a stranger fill the table.
    pub ephemeral: bool,
}

impl Exchange {
    /// Opens an exchange.
    #[must_use]
    pub fn new(key: ExchangeKey, protocol: ProtocolId, params: MrpParams, now: Instant) -> Self {
        Self {
            key,
            protocol,
            mrp: Mrp::new(params),
            peer: None,
            opened: now,
            last_activity: now,
            ephemeral: false,
        }
    }

    /// The same exchange, marked ephemeral (§4.10.5.2).
    #[must_use]
    pub const fn ephemeral(mut self) -> Self {
        self.ephemeral = true;
        self
    }

    /// Records that a message arrived on this exchange or went out on it.
    pub const fn touch(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Whether nothing has used this exchange for `idle` and nothing is pending on it.
    ///
    /// §4.10.5.3 step 2 is the second half: "Wait for all pending retransmissions associated
    /// with the Exchange to complete. If the retransmission list for the Exchange is empty,
    /// remove the Exchange. Otherwise, leave the Exchange open and only close it once the
    /// retransmission list is empty." An exchange still trying to deliver something is not
    /// abandoned, however quiet the peer has been.
    #[must_use]
    pub fn is_abandoned(&self, now: Instant, idle: Duration) -> bool {
        // "the retransmission list" — a message still awaiting acknowledgement, not merely any
        // timer. An exchange can also hold a standalone acknowledgement it owes the peer, and
        // one still owed after the idle timeout means nobody drove the timers at all; letting
        // that pin an entry forever is the leak this is here to close.
        if self.mrp.is_awaiting_ack() {
            return false;
        }
        now.as_micros()
            .saturating_sub(self.last_activity.as_micros())
            > idle.as_micros()
    }

    /// The same exchange with its peer known from the start — what an initiator has, since
    /// it chose who to talk to.
    #[must_use]
    pub fn to_peer(mut self, peer: Peer) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Whether the transport underneath supplies its own reliability, so §4.12.4's "SHOULD
    /// NOT set the R Flag" applies.
    ///
    /// An exchange whose peer is not yet known is assumed to be on UDP: MRP is the default
    /// and the conservative choice, since an unnecessary acknowledgement costs a round trip
    /// while a missing one costs the message.
    #[must_use]
    pub fn is_transport_reliable(&self) -> bool {
        self.peer.is_some_and(|p| p.is_reliable())
    }
}

/// How long an exchange may sit with nothing happening on it before it is reclaimed.
///
/// The specification gives no figure — §4.10.5.3 leaves closing to "the application layer or a
/// fatal connection error" — but leaving that to the application is what makes an exchange
/// table a remotely exhaustible resource. Every unsecured message with the I Flag set opens an
/// exchange (§4.10.5.2), and an attacker who can reach the port can send them with any exchange
/// id it likes. Without reclamation, `N` datagrams costing nothing fill the table for good, and
/// a node that can no longer open an exchange can no longer establish a session — PASE or CASE,
/// for the rest of its uptime. Existing sessions keep working, which is what makes it hard to
/// notice.
///
/// Sixty seconds is taken from §5.5's bound on the one exchange most worth attacking: "a
/// Commissionee SHALL expect a PASE session to be established within 60 seconds of receiving
/// the initial request". An exchange idle for longer than the specification allows the whole
/// handshake is not one anybody is still using.
pub const EXCHANGE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The fixed-capacity set of open exchanges.
///
/// Capacity is `C::SESSIONS * C::EXCHANGES_PER_SESSION`, which is what
/// [`Config`] says the node was built for. A full table is
/// [`ErrorCode::NoSpace`] — a value the caller answers `BUSY` with, never an abort.
#[derive(Debug)]
pub struct ExchangeTable<C: Config, const N: usize> {
    open: Vec<Exchange, N>,
    /// The next exchange id to hand out. §4.4.3.3 only requires that an id not collide
    /// with a live exchange on the same session; a counter is the simplest thing that
    /// achieves it.
    next_id: u16,
    _config: PhantomData<C>,
}

impl<C: Config, const N: usize> Default for ExchangeTable<C, N> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<C: Config, const N: usize> ExchangeTable<C, N> {
    /// An empty table whose first exchange id is `first_id`.
    ///
    /// `first_id` should come from [`Rng`](crate::platform::Rng): starting at zero every
    /// boot makes a node's exchange ids predictable, and predictable ids make it cheaper
    /// for an off-path attacker to guess one that is live.
    #[must_use]
    pub fn new(first_id: u16) -> Self {
        // Instantiating the check is what makes a `Config` that breaks a specification
        // minimum a compile error at this line rather than a certification failure later.
        let () = AssertValid::<C>::CHECK;
        Self {
            open: Vec::new(),
            next_id: first_id,
            _config: PhantomData,
        }
    }

    /// How many exchanges are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether none are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// How many more will fit.
    #[must_use]
    pub fn capacity_remaining(&self) -> usize {
        N.saturating_sub(self.open.len())
    }

    /// Opens an exchange this node initiates, choosing an unused id.
    pub fn open_initiator(
        &mut self,
        session: SessionId,
        protocol: ProtocolId,
        params: MrpParams,
        peer: Option<Peer>,
        now: Instant,
    ) -> Result<ExchangeKey> {
        let id = self.allocate_id(session)?;
        let key = ExchangeKey {
            session,
            id,
            role: Role::Initiator,
        };
        let exchange = Exchange::new(key, protocol, params, now);
        self.insert(match peer {
            Some(peer) => exchange.to_peer(peer),
            None => exchange,
        })?;
        Ok(key)
    }

    /// Opens an exchange the peer initiated.
    ///
    /// Returns [`ErrorCode::InvalidState`] if one with that key is already open — a peer
    /// reusing a live id is either confused or hostile, and silently adopting the second
    /// one would let it hijack the first.
    pub fn open_responder(
        &mut self,
        session: SessionId,
        id: ExchangeId,
        protocol: ProtocolId,
        params: MrpParams,
        now: Instant,
    ) -> Result<ExchangeKey> {
        let key = ExchangeKey {
            session,
            id,
            role: Role::Responder,
        };
        if self.find(key).is_some() {
            return Err(Error::new(ErrorCode::InvalidState));
        }
        self.insert_under_pressure(Exchange::new(key, protocol, params, now), now)?;
        Ok(key)
    }

    /// Opens §4.10.5.2's ephemeral exchange: one that exists only to carry a standalone
    /// acknowledgement and is closed as soon as it has.
    pub fn open_ephemeral(
        &mut self,
        session: SessionId,
        id: ExchangeId,
        protocol: ProtocolId,
        params: MrpParams,
        now: Instant,
    ) -> Result<ExchangeKey> {
        let key = ExchangeKey {
            session,
            id,
            role: Role::Responder,
        };
        if let Some(existing) = self.find(key) {
            return Ok(existing.key);
        }
        self.insert_under_pressure(Exchange::new(key, protocol, params, now).ephemeral(), now)?;
        Ok(key)
    }

    /// Inserts, reclaiming abandoned entries first if the table is full.
    ///
    /// Reaping here as well as on the timer is what makes the bound hold for a node whose
    /// timers are slow or stopped: the pressure that would have refused a legitimate peer is
    /// the same pressure that proves some other entry has been idle too long.
    fn insert_under_pressure(&mut self, exchange: Exchange, now: Instant) -> Result<()> {
        if self.open.is_full() {
            self.reap(now, EXCHANGE_IDLE_TIMEOUT);
        }
        self.insert(exchange)
    }

    fn insert(&mut self, exchange: Exchange) -> Result<()> {
        self.open
            .push(exchange)
            .map_err(|_| Error::new(ErrorCode::NoSpace))
    }

    /// Closes every exchange nothing has used for `idle` and nothing is pending on.
    ///
    /// Returns how many went. [`Messaging::poll`](crate::messaging::Messaging::poll) calls
    /// this, so a node that drives its timers at all gets it without asking — which is the
    /// point: an exchange table that is only reclaimed when the application remembers to
    /// reclaim it is one an attacker reclaims on its behalf.
    pub fn reap(&mut self, now: Instant, idle: Duration) -> usize {
        let before = self.open.len();
        self.open.retain(|e| !e.is_abandoned(now, idle));
        before.saturating_sub(self.open.len())
    }

    /// When [`ExchangeTable::reap`] would next have something to do.
    #[must_use]
    pub fn reap_deadline(&self, idle: Duration) -> Option<Instant> {
        self.open
            .iter()
            .filter(|e| !e.mrp.is_awaiting_ack())
            .map(|e| e.last_activity.saturating_add(idle))
            .min()
    }

    fn allocate_id(&mut self, session: SessionId) -> Result<ExchangeId> {
        // Try every id once before giving up, so a table that is merely fragmented still
        // finds one.
        for _ in 0..=u16::MAX {
            let id = ExchangeId(self.next_id);
            self.next_id = self.next_id.wrapping_add(1);
            let key = ExchangeKey {
                session,
                id,
                role: Role::Initiator,
            };
            if self.find(key).is_none() {
                return Ok(id);
            }
        }
        Err(Error::new(ErrorCode::NoSpace))
    }

    /// The exchange with this key, if it is open.
    #[must_use]
    pub fn find(&self, key: ExchangeKey) -> Option<&Exchange> {
        self.open.iter().find(|e| e.key == key)
    }

    /// The exchange with this key, mutably.
    pub fn find_mut(&mut self, key: ExchangeKey) -> Option<&mut Exchange> {
        self.open.iter_mut().find(|e| e.key == key)
    }

    /// Finds the exchange an arriving message belongs to.
    ///
    /// `from_initiator` is the message's **I** flag. A message *from* the initiator
    /// belongs to the exchange in which this node is the **responder**, and the other way
    /// round — getting this inversion wrong is how a node answers its own request.
    #[must_use]
    pub fn find_for_message(
        &self,
        session: SessionId,
        id: ExchangeId,
        from_initiator: bool,
    ) -> Option<&Exchange> {
        let role = if from_initiator {
            Role::Responder
        } else {
            Role::Initiator
        };
        self.find(ExchangeKey { session, id, role })
    }

    /// Finds the exchange an arriving message belongs to, mutably.
    pub fn find_for_message_mut(
        &mut self,
        session: SessionId,
        id: ExchangeId,
        from_initiator: bool,
    ) -> Option<&mut Exchange> {
        let role = if from_initiator {
            Role::Responder
        } else {
            Role::Initiator
        };
        self.find_mut(ExchangeKey { session, id, role })
    }

    /// Closes an exchange, returning whether it was open.
    pub fn close(&mut self, key: ExchangeKey) -> bool {
        let Some(i) = self.open.iter().position(|e| e.key == key) else {
            return false;
        };
        if let Some(e) = self.open.get_mut(i) {
            e.mrp.close();
        }
        self.open.swap_remove(i);
        true
    }

    /// Closes every exchange on a session — what tearing the session down does.
    pub fn close_session(&mut self, session: SessionId) -> usize {
        let before = self.open.len();
        self.open.retain(|e| e.key.session != session);
        before.saturating_sub(self.open.len())
    }

    /// The earliest deadline across every open exchange, which is when the caller's run
    /// loop should next call [`ExchangeTable::on_timeout`].
    #[must_use]
    pub fn poll_deadline(&self) -> Option<Instant> {
        self.open.iter().filter_map(|e| e.mrp.poll_deadline()).min()
    }

    /// Hands a passed deadline to every exchange that has one, calling `on_action` for
    /// each thing that falls out.
    ///
    /// Returns how many actions were produced.
    pub fn on_timeout(
        &mut self,
        now: Instant,
        randomness: u32,
        mut on_action: impl FnMut(ExchangeKey, super::OnTimeout),
    ) -> usize {
        let mut count = 0usize;
        for exchange in &mut self.open {
            loop {
                let action = exchange.mrp.on_timeout(now, randomness);
                if matches!(action, super::OnTimeout::Nothing) {
                    break;
                }
                on_action(exchange.key, action);
                count = count.saturating_add(1);
            }
        }
        count
    }

    /// Every open exchange.
    pub fn iter(&self) -> impl Iterator<Item = &Exchange> {
        self.open.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultConfig;
    use crate::exchange::OnTimeout;

    type Table = ExchangeTable<DefaultConfig, 8>;

    #[test]
    fn an_initiated_exchange_gets_an_unused_id() {
        let mut t = Table::new(100);
        let a = t
            .open_initiator(
                SessionId(1),
                ProtocolId::INTERACTION_MODEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("open");
        let b = t
            .open_initiator(
                SessionId(1),
                ProtocolId::INTERACTION_MODEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("open");
        assert_ne!(a.id, b.id);
        assert_eq!(a.id, ExchangeId(100));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn the_same_id_in_both_roles_is_two_exchanges() {
        // Two nodes that each start an exchange may each choose 7. Keying on the id alone
        // would merge them, and this node would answer its own request.
        let mut t = Table::new(7);
        let mine = t
            .open_initiator(
                SessionId(1),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("mine");
        assert_eq!(mine.id, ExchangeId(7));
        let theirs = t
            .open_responder(
                SessionId(1),
                ExchangeId(7),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                Instant::ZERO,
            )
            .expect("theirs");
        assert_eq!(t.len(), 2, "two distinct exchanges");
        assert_ne!(mine, theirs);
        assert!(t.find(mine).is_some());
        assert!(t.find(theirs).is_some());
    }

    #[test]
    fn an_arriving_message_finds_the_opposite_role() {
        let mut t = Table::new(0);
        let mine = t
            .open_initiator(
                SessionId(1),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("open");
        // The peer's reply carries I = 0, because the peer is not the initiator.
        let found = t
            .find_for_message(SessionId(1), mine.id, false)
            .expect("the reply belongs to my exchange");
        assert_eq!(found.key, mine);
        // A message with I = 1 and the same id is a *different* exchange, which is not
        // open.
        assert!(t.find_for_message(SessionId(1), mine.id, true).is_none());
    }

    #[test]
    fn a_peer_reusing_a_live_id_is_refused() {
        let mut t = Table::new(0);
        t.open_responder(
            SessionId(1),
            ExchangeId(3),
            ProtocolId::SECURE_CHANNEL,
            MrpParams::default(),
            Instant::ZERO,
        )
        .expect("first");
        assert_eq!(
            t.open_responder(
                SessionId(1),
                ExchangeId(3),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                Instant::ZERO,
            )
            .unwrap_err()
            .code(),
            ErrorCode::InvalidState
        );
    }

    #[test]
    fn the_same_id_on_two_sessions_is_two_exchanges() {
        let mut t = Table::new(0);
        t.open_responder(
            SessionId(1),
            ExchangeId(5),
            ProtocolId::SECURE_CHANNEL,
            MrpParams::default(),
            Instant::ZERO,
        )
        .expect("session 1");
        t.open_responder(
            SessionId(2),
            ExchangeId(5),
            ProtocolId::SECURE_CHANNEL,
            MrpParams::default(),
            Instant::ZERO,
        )
        .expect("session 2");
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn a_full_table_is_a_value_not_an_abort() {
        let mut t = Table::new(0);
        for _ in 0..8 {
            t.open_initiator(
                SessionId(1),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("fits");
        }
        assert_eq!(t.capacity_remaining(), 0);
        assert_eq!(
            t.open_initiator(
                SessionId(1),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .unwrap_err()
            .code(),
            ErrorCode::NoSpace
        );
    }

    #[test]
    fn closing_a_session_closes_its_exchanges() {
        let mut t = Table::new(0);
        for session in [1u16, 1, 2] {
            t.open_initiator(
                SessionId(session),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("open");
        }
        assert_eq!(t.close_session(SessionId(1)), 2);
        assert_eq!(t.len(), 1);
        assert_eq!(t.close_session(SessionId(1)), 0);
    }

    #[test]
    fn close_reports_whether_it_did_anything() {
        let mut t = Table::new(0);
        let k = t
            .open_initiator(
                SessionId(1),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("open");
        assert!(t.close(k));
        assert!(!t.close(k));
        assert!(t.is_empty());
    }

    #[test]
    fn the_table_deadline_is_the_earliest_of_them() {
        let mut t = Table::new(0);
        let slow = t
            .open_initiator(
                SessionId(1),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("open");
        let fast = t
            .open_initiator(
                SessionId(1),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("open");

        assert_eq!(t.poll_deadline(), None, "nothing is in flight yet");
        if let Some(e) = t.find_mut(slow) {
            e.mrp.on_send(1, Instant::ZERO, 0).expect("send");
        }
        if let Some(e) = t.find_mut(fast) {
            // An active peer retries sooner: 330 ms against 550 ms.
            e.mrp.note_peer_activity(Instant::ZERO);
            e.mrp.on_send(2, Instant::ZERO, 0).expect("send");
        }
        let deadline = t.poll_deadline().expect("a deadline");
        assert_eq!(deadline.as_micros(), 330_000);
    }

    #[test]
    fn timeouts_are_reported_per_exchange() {
        let mut t = Table::new(0);
        let k = t
            .open_initiator(
                SessionId(1),
                ProtocolId::SECURE_CHANNEL,
                MrpParams::default(),
                None,
                Instant::ZERO,
            )
            .expect("open");
        if let Some(e) = t.find_mut(k) {
            e.mrp.on_send(9, Instant::ZERO, 0).expect("send");
        }
        let deadline = t.poll_deadline().expect("a deadline");

        let mut seen = heapless::Vec::<(ExchangeKey, u32), 4>::new();
        let n = t.on_timeout(deadline, 0, |key, action| {
            if let OnTimeout::Retransmit { counter, .. } = action {
                let _ = seen.push((key, counter));
            }
        });
        assert_eq!(n, 1);
        assert_eq!(&seen[..], &[(k, 9)]);
    }
}
