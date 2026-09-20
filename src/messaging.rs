//! Message processing: a datagram in, a protocol message out (Core §4.7).
//!
//! Everything below this module is sans-I/O and, until now, unconnected. [`msg`](crate::msg)
//! frames and encrypts, [`session`](crate::session) holds the keys, [`exchange`](crate::exchange)
//! holds the conversations and their reliability state — and nothing put the three together.
//! This is that seam, and it is the whole of §4.7.1 "Message Transmission" and §4.7.2 "Message
//! Reception".
//!
//! # Why it is a type and not a function
//!
//! Reception is not a pure decode. Three pieces of state change on the way through, and all
//! three are security-relevant:
//!
//! * the **session's** replay window (§4.6.5), which decides whether a counter is new;
//! * the **exchange's** MRP state (§4.12), which decides whether an acknowledgement is owed
//!   and whether a retransmission is still outstanding;
//! * the **exchange table** itself, since a message may open an exchange the peer initiated.
//!
//! A receiver that decoded without updating them would accept replays. One that updated them
//! before authenticating would let an unauthenticated sender move a window it has no key for
//! — which is why the order here is fixed: find the session, **decrypt**, and only then touch
//! any counter.
//!
//! # A duplicate is acknowledged and dropped
//!
//! §4.12.2.2 is emphatic, and it is the rule most easily got wrong in the direction that
//! looks like it works:
//!
//! > The receiver SHALL send an acknowledgment message to the sender for each instance of an
//! > authenticated, reliable message, including duplicates. The reliability layer SHALL only
//! > propagate the first instance of a message to the next higher layer.
//!
//! Drop a duplicate silently and the sender retransmits until it gives up; deliver it twice
//! and the application acts on it twice. [`Received::Duplicate`] is neither.

use crate::config::Config;
use crate::error::{Error, ErrorCode, Result, bail};
use crate::exchange::{EXCHANGE_IDLE_TIMEOUT, ExchangeKey, ExchangeTable, MrpParams, OnTimeout};
use crate::msg::{CounterKind, CounterWindow, MessageCounter, Verdict};
use crate::msg::{
    Destination, MessageHeader, NonceSource, ProtocolHeader, ProtocolId, SessionId, SessionType,
    preview, protect, unprotect,
};
use crate::platform::{Instant, Peer};
use crate::session::{SecureSession, SessionKind, SessionTable};

/// The largest a Protocol Header can be (§4.4.3): the exchange flags, the opcode, the
/// exchange id, a 32-bit protocol id and an acknowledged counter.
///
/// Only [`Messaging::acknowledge`] needs it: a standalone acknowledgement has no payload, so
/// the body it frames is the header on its own.
const PROTOCOL_HEADER_MAX: usize = 16;

/// What arrived, once the message has been authenticated and routed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Received<'a> {
    /// A group datagram (§4.16), which belongs to the group key store rather than here.
    ///
    /// Nothing about it has been decrypted or authenticated: a group message is keyed by an
    /// operational group key, and which key it is has to be found by trying every installed
    /// one whose session id matches (§4.17.3.6). Hand `buf` — unchanged — to
    /// [`group::wire::receive`](crate::group::wire::receive), which does that and returns the
    /// payload; a node that holds no group keys drops it.
    Group {
        /// The Group Session Id from the header, which selects the candidate keys.
        session_id: SessionId,
        /// Where it came from.
        from: Peer,
    },
    /// The peer closed the session, and this node has done the same (§4.11.1.4).
    ///
    /// The session, its keys and its exchanges are gone by the time this is returned — that
    /// is what "SHALL remove all state associated with the session" means, and it is done
    /// here rather than left to the caller because none of that state is the caller's.
    ///
    /// What *is* the caller's is everything keyed on a session above this layer: §8.5's
    /// subscriptions above all, which report on a session and have nowhere to go once it has
    /// gone, and the §5.5 commissioning channel, which a closed PASE session releases.
    SessionClosed {
        /// The session that was closed.
        session: SessionId,
    },
    /// A protocol message for the layer above.
    Message {
        /// The exchange it belongs to.
        exchange: ExchangeKey,
        /// The protocol header it carried.
        header: ProtocolHeader,
        /// Whether an acknowledgement is owed, which [`Messaging::acknowledge`] sends.
        needs_ack: bool,
        /// The application payload, decrypted in place.
        payload: &'a [u8],
    },
    /// An authenticated message this node has already seen (§4.12.2.2).
    ///
    /// Not delivered upward. Still acknowledged, because the sender's retransmission means
    /// its last acknowledgement was lost, not that its message was.
    Duplicate {
        /// The exchange it belongs to.
        exchange: ExchangeKey,
        /// Whether an acknowledgement is owed.
        needs_ack: bool,
    },
    /// A standalone acknowledgement, consumed entirely by the reliability layer.
    Acknowledged {
        /// The exchange it acknowledged.
        exchange: ExchangeKey,
    },
}

/// What a timer expiry asks the caller to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// Retransmit the message with this counter on this exchange (§4.12.2.1).
    ///
    /// "Logical retransmission is of a given message as identified by its message counter",
    /// so the caller resends the *same bytes*, not a re-encoding: a new counter would be a
    /// new message and would reuse a nonce.
    Retransmit {
        /// Which exchange.
        exchange: ExchangeKey,
        /// The counter of the message to resend.
        counter: u32,
    },
    /// An acknowledgement has waited long enough for a message to ride on (§4.12.5.2.2).
    ///
    /// [`Messaging::acknowledge`] writes it.
    Acknowledge {
        /// Which exchange owes it.
        exchange: ExchangeKey,
    },
    /// `MRP_MAX_TRANSMISSIONS` passed with no acknowledgement; the exchange is closed.
    Abandoned {
        /// Which exchange was given up on.
        exchange: ExchangeKey,
    },
}

/// Which protocols the upper layer will accept (§4.10.3.1).
///
/// "The Interaction Model layer indicates to the Exchange Layer which Protocols it will accept.
/// Any message for a Protocol ID that is not registered with the Exchange Layer SHALL be
/// dropped."
///
/// This is not bookkeeping. §4.10.5.2 opens an exchange for any unsolicited message with the
/// **I** flag, and on the unsecured session that is any datagram at all — so the set of
/// protocols a node answers is also the set an attacker can make it allocate for. A node that
/// registers only what it serves refuses the rest before the exchange table is touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Protocols(u8);

impl Protocols {
    const fn bit(protocol: ProtocolId) -> Option<u8> {
        if protocol.vendor.0 != crate::msg::VendorId::COMMON.0 {
            return None;
        }
        match protocol.id {
            0x0000..=0x0004 => Some(1u8 << protocol.id),
            _ => None,
        }
    }

    /// Nothing registered — every unsolicited message is dropped.
    pub const NONE: Self = Self(0);

    /// Secure Channel (§4.11). Every node needs it: it is how sessions are established.
    pub const SECURE_CHANNEL: Self = Self(1 << 0);
    /// The Interaction Model (ch. 8) — what a node that serves clusters registers.
    pub const INTERACTION_MODEL: Self = Self(1 << 1);
    /// BDX (§11.22), for a node that transfers files.
    pub const BDX: Self = Self(1 << 2);
    /// User Directed Commissioning (§5.3).
    pub const USER_DIRECTED_COMMISSIONING: Self = Self(1 << 3);
    /// The range reserved for testing.
    pub const FOR_TESTING: Self = Self(1 << 4);

    /// What an ordinary device registers: Secure Channel and the Interaction Model.
    pub const DEVICE: Self = Self(Self::SECURE_CHANNEL.0 | Self::INTERACTION_MODEL.0);

    /// Both of these, registered.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether `protocol` is registered.
    ///
    /// A vendor-specific protocol id is never registered: §4.10.3.1's registration is by
    /// identity, and this node serves none.
    #[must_use]
    pub const fn contains(self, protocol: ProtocolId) -> bool {
        match Self::bit(protocol) {
            Some(bit) => self.0 & bit != 0,
            None => false,
        }
    }
}

/// §4.13.2.1's Unsecured Session Context, reduced to what framing needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnsecuredPeer {
    /// The Ephemeral Initiator Node ID, whichever end chose it.
    ephemeral_initiator: crate::msg::NodeId,
    /// Whether *this* node is the initiator, which decides which header field carries it.
    we_initiated: bool,
}

/// A session that was evicted to make room for a new one (§4.11.1.1).
///
/// The session and its exchanges are already gone. What is left is the `CLOSE_SESSION`
/// status report the specification owes the evicted peer, framed and ready in the caller's
/// output buffer.
#[derive(Debug, Clone, Copy)]
#[must_use = "§4.11.1.1 step 2a owes the evicted peer a CloseSession status report"]
pub struct Evicted {
    /// The session that was removed.
    pub session: SessionId,
    /// Where its peer was, if the session knew — nothing to send to if it did not.
    pub peer: Option<Peer>,
    /// How many octets of the output buffer the report occupies. Zero if it could not be
    /// framed, which is not a reason to abandon the eviction.
    pub len: usize,
}

/// A node's message processing: sessions, exchanges, and the framing between them.
///
/// `S` sizes the session table and `X` the exchange table. Both default to a device-sized
/// node that satisfies every specification minimum for five fabrics, and
/// [`SessionTable::CHECK`](crate::session::SessionTable::CHECK) refuses an `S` that cannot.
#[derive(Debug)]
pub struct Messaging<C: Config, const S: usize = 16, const X: usize = 64> {
    sessions: SessionTable<C, S>,
    exchanges: ExchangeTable<C, X>,
    /// The counter for messages sent on the unsecured session (§4.6.1.2).
    unsecured_counter: MessageCounter,
    /// Duplicate detection for the unsecured session.
    ///
    /// §4.6.5 applies to unencrypted messages too, and this is the window that makes a PASE
    /// handshake replay-resistant before any key exists.
    unsecured_window: CounterWindow,
    /// §4.13.2.1's Unsecured Session Context: the **Ephemeral Initiator Node ID**, and which
    /// end of it this node is.
    ///
    /// "Randomly selected for each session by the initiator from the Operational Node ID range
    /// and enclosed by initiator as Source Node ID and responder as Destination Node ID."
    ///
    /// One context, not a table. §4.13.2.1 allows several, keyed by ephemeral id, but a device
    /// answers one session establishment at a time — which
    /// [`PaseAdmission`](crate::commissioning::PaseAdmission) now enforces — and a controller
    /// commissions one device at a time.
    unsecured_peer: Option<UnsecuredPeer>,
    /// Whether to apply §4.9's privacy processing to outgoing secure unicast messages.
    privacy: bool,
    /// §4.10.3.1's registered protocols.
    protocols: Protocols,
}

impl<C: Config, const S: usize, const X: usize> Messaging<C, S, X> {
    /// A node with no sessions and no exchanges.
    ///
    /// `first_session_id`, `first_exchange_id` and `initial_counter` should all come from
    /// [`Rng`](crate::platform::Rng). §4.6.1.1 requires the counter to start at random: one
    /// that always starts at zero leaks how many times a device has rebooted and makes nonce
    /// reuse across a factory reset far too easy. A full-width random number is what to pass —
    /// [`MessageCounter::new`](crate::msg::MessageCounter::new) narrows it to the twenty-eight
    /// bits §4.6.1.1 allows, so the caller does not have to know that it must.
    #[must_use]
    pub fn new(first_session_id: u16, first_exchange_id: u16, initial_counter: u32) -> Self {
        Self {
            sessions: SessionTable::new(first_session_id),
            exchanges: ExchangeTable::new(first_exchange_id),
            unsecured_counter: MessageCounter::new(initial_counter),
            unsecured_window: CounterWindow::new(CounterKind::Rollover),
            unsecured_peer: None,
            privacy: false,
            protocols: Protocols::DEVICE,
        }
    }

    /// Registers the protocols this node's upper layer will accept (§4.10.3.1).
    ///
    /// Defaults to [`Protocols::DEVICE`] — Secure Channel and the Interaction Model — which is
    /// what a node that serves clusters needs. A node that also transfers files registers
    /// [`Protocols::BDX`] on top; one that does neither registers less.
    pub const fn register(&mut self, protocols: Protocols) {
        self.protocols = protocols;
    }

    /// Which protocols are registered.
    #[must_use]
    pub const fn protocols(&self) -> Protocols {
        self.protocols
    }

    /// Applies §4.9's privacy processing to outgoing secure unicast messages.
    ///
    /// Off by default, and deliberately. The **P** flag is only *required* on group messages
    /// (§4.16.2 step 2c, §4.18): on a secure unicast session it is the sender's choice, and what it
    /// buys is hiding the message counter from a passive observer on the link — the counter
    /// is already authenticated, and anyone with the key can read it either way. What it
    /// costs is depending on every peer having exercised its deobfuscation path, which is
    /// not a bet worth making by default for a property this small.
    ///
    /// Receiving a private message never needs this: the flag is in the message, and
    /// [`Messaging::receive`] honours it whatever this is set to.
    pub const fn set_privacy(&mut self, privacy: bool) {
        self.privacy = privacy;
    }

    /// Opens §4.13.2.1's Unsecured Session Context as the **initiator**.
    ///
    /// `ephemeral` is the Ephemeral Initiator Node ID this node encloses as the Source Node ID
    /// of every unsecured message it sends, and which the responder will echo back as the
    /// Destination Node ID. §4.13.2.1: "Initiators SHALL select a new random ephemeral node ID
    /// for each unsecured session", from the Operational Node ID range — so it comes from
    /// [`Rng`](crate::platform::Rng) and is *not* the node's operational identity. A node that
    /// reused one identity across sessions would let a passive observer link them.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidArgument`] unless `ephemeral` is in the Operational Node ID range.
    pub fn open_unsecured_as_initiator(&mut self, ephemeral: crate::msg::NodeId) -> Result<()> {
        if !ephemeral.is_operational() {
            bail!(InvalidArgument)
        }
        self.unsecured_peer = Some(UnsecuredPeer {
            ephemeral_initiator: ephemeral,
            we_initiated: true,
        });
        Ok(())
    }

    /// Opens an unsecured exchange as the initiator, establishing §4.13.2.1's Unsecured Session
    /// Context in the same call.
    ///
    /// This is how a commissioner starts PASE, and how any node starts CASE: both handshakes
    /// run on the unsecured session before there is a key. The context is not optional —
    /// §4.13.2.1 has the initiator "enclose" its Ephemeral Initiator Node ID as the Source Node
    /// ID of every message, and a message with neither a Source nor a Destination is one the
    /// specification tells the responder to discard.
    ///
    /// `randomness` comes from the caller's [`Rng`](crate::platform::Rng) and becomes the
    /// ephemeral id, which is a *new* one for each unsecured session by §4.13.2.1.
    pub fn open_unsecured(
        &mut self,
        protocol: ProtocolId,
        now: Instant,
        randomness: u64,
    ) -> Result<ExchangeKey> {
        self.open_unsecured_as_initiator(crate::msg::NodeId::ephemeral(randomness))?;
        let params = self.mrp_params(SessionId::UNSECURED);
        self.exchanges
            .open_initiator(SessionId::UNSECURED, protocol, params, None, now)
    }

    /// Forgets the Unsecured Session Context, so the next handshake starts a new one.
    ///
    /// §4.13.2.1 requires a *new* ephemeral id per unsecured session, so a node that runs PASE
    /// and then CASE against the same peer closes the first context before opening the second.
    pub const fn close_unsecured(&mut self) {
        self.unsecured_peer = None;
    }

    /// The Ephemeral Initiator Node ID of the current Unsecured Session Context, if there is one.
    #[must_use]
    pub const fn unsecured_ephemeral_id(&self) -> Option<crate::msg::NodeId> {
        match self.unsecured_peer {
            Some(peer) => Some(peer.ephemeral_initiator),
            None => None,
        }
    }

    /// The session table.
    pub const fn sessions(&self) -> &SessionTable<C, S> {
        &self.sessions
    }

    /// The session table, mutably — for the fields a completed handshake fills in
    /// afterwards, such as §11.18.6.8 step 10a's accessing fabric.
    ///
    /// Installing a session goes through [`Messaging::install_session`] instead: a session
    /// and its exchanges are one lifetime, and this reference only reaches one of them.
    pub const fn sessions_mut(&mut self) -> &mut SessionTable<C, S> {
        &mut self.sessions
    }

    /// Installs the session a handshake produced, evicting one if there is no room
    /// (§4.11.1.1).
    ///
    /// A session table that answers `NoSpace` is a node that can be commissioned exactly
    /// as many times as the session table is long and then never again — and the failure appears at the
    /// *next* administrator, not at the one who filled it. §4.11.1.1 is explicit about the
    /// alternative and about its three steps, in order:
    ///
    /// 1. the least recently used session, by `SessionTimestamp`;
    /// 2. a `StatusReport(SUCCESS, SECURE_CHANNEL, CLOSE_SESSION)` **to that peer**, and
    ///    only then "remove all state associated with the session";
    /// 3. the new session's own establishment message, which the caller was sending anyway.
    ///
    /// Step 2's two halves are why this takes buffers and returns an [`Evicted`]: the report
    /// has to be framed while the session that encrypts it still exists, and put on the wire
    /// by whoever owns the socket. The removal has already happened when this returns; what
    /// is left is a datagram the caller sends to [`Evicted::peer`]. Dropping it costs the
    /// peer nothing worse than a session it believes in until its next message fails, which
    /// is why this is `must_use` rather than an error.
    ///
    /// `Ok(None)` is the ordinary case: there was room and nothing was evicted.
    pub fn install_session(
        &mut self,
        session: SecureSession,
        now: Instant,
        randomness: u32,
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<Option<Evicted>> {
        if self.sessions.len() < S {
            self.sessions.insert(session)?;
            return Ok(None);
        }
        let Some(victim) = self.sessions.least_recently_used() else {
            // No room and nothing to evict means `S == 0`, which `AssertValid` forbids.
            bail!(NoSpace)
        };
        let peer = self.sessions.find(victim).and_then(|s| s.peer);
        // Framed before the removal, because it is encrypted under the evicted session's own
        // keys: a report built afterwards has nothing to encrypt it with.
        let report = crate::sc::status::StatusReport {
            general: crate::sc::status::GeneralCode::Success,
            protocol: ProtocolId::SECURE_CHANNEL,
            protocol_code: crate::sc::status::SecureChannelCode::CloseSession as u16,
            data: &[],
        };
        let mut body = [0u8; 16];
        let len = report.encode(&mut body)?;
        let Some(body) = body.get(..len) else {
            bail!(BufferTooSmall)
        };
        let exchange = self.open(victim, ProtocolId::SECURE_CHANNEL, now)?;
        let framed = self
            .send(
                exchange,
                crate::sc::opcode::STATUS_REPORT,
                false,
                body,
                now,
                randomness,
                scratch,
                out,
            )
            .map(|(n, _)| n);
        // §4.13.3.1: "remove all state associated with the session" — the exchanges on it
        // included, and including the one just used to say goodbye.
        self.close_session(victim);
        self.sessions.insert(session)?;
        Ok(Some(Evicted {
            session: victim,
            peer,
            len: framed.unwrap_or(0),
        }))
    }

    /// Removes a session and everything associated with it (§4.13.3.1).
    ///
    /// Returns whether there was one. The exchanges on that session go with it: an exchange
    /// outlives its session only as an entry nothing can ever answer on, holding a slot in a
    /// fixed-capacity table until it times out.
    pub fn close_session(&mut self, session: SessionId) -> bool {
        self.exchanges.close_session(session);
        self.sessions.remove(session)
    }

    /// Removes every session on a fabric, and their exchanges — what `RemoveFabric`
    /// (§11.18.6.12) owes at the message layer.
    ///
    /// Returns how many sessions went. The clusters' half of the same command is
    /// [`Lifecycle::FabricRemoved`](crate::im::Lifecycle::FabricRemoved).
    pub fn remove_fabric(&mut self, fabric: crate::msg::FabricIndex) -> usize {
        let doomed: heapless::Vec<SessionId, S> = self
            .sessions
            .iter()
            .filter(|s| s.fabric_index == fabric)
            .map(|s| s.local_session_id)
            .collect();
        for session in &doomed {
            self.exchanges.close_session(*session);
        }
        self.sessions.remove_fabric(fabric)
    }

    /// The exchange table.
    pub const fn exchanges(&self) -> &ExchangeTable<C, X> {
        &self.exchanges
    }

    /// The exchange table, mutably.
    pub const fn exchanges_mut(&mut self) -> &mut ExchangeTable<C, X> {
        &mut self.exchanges
    }

    /// Opens an exchange this node initiates, to a peer it has not named yet.
    ///
    /// The peer is learned from the first message that comes back. Prefer
    /// [`Messaging::open_to`] where it is already known: until it is, this node assumes UDP
    /// and runs MRP, which is right for UDP and one wasted round trip on BTP.
    pub fn open(
        &mut self,
        session: SessionId,
        protocol: ProtocolId,
        now: Instant,
    ) -> Result<ExchangeKey> {
        // §4.13.2.1 gives an unsecured initiator one obligation before it sends anything: an
        // Unsecured Session Context, whose Ephemeral Initiator Node ID it "encloses as Source
        // Node ID". Without one, [`Messaging::send`] has no id to put in the header and emits a
        // message carrying neither a Source nor a Destination — which the specification tells
        // the receiver to discard, and which the CHIP SDK does. The message is built, counted
        // and dropped, and nothing anywhere says so.
        //
        // So an unsecured exchange is opened through [`Messaging::open_unsecured`], which
        // establishes the context in the same call, and this door is closed rather than left
        // to be remembered.
        if session == SessionId::UNSECURED && self.unsecured_peer.is_none() {
            bail!(InvalidState)
        }
        let params = self.mrp_params(session);
        // Where the peer last was, which is the only answer available and the right one: a
        // session exists because that peer authenticated itself from there. Opening with no
        // peer produces an exchange that cannot send — [`Stack::send`] builds the message and
        // [`Stack::peer`] then has no address to give the caller, so the message is built,
        // counted, and dropped, with no error anywhere. Use [`Stack::open_to`] to name a
        // different address, for a peer just rediscovered at a new one.
        let peer = self.sessions.find(session).and_then(|s| s.peer);
        self.exchanges
            .open_initiator(session, protocol, params, peer, now)
    }

    /// Opens an exchange to a peer this node has already found.
    ///
    /// Naming the transport is what lets §4.12.4 be honoured: a BLE peer's exchange never
    /// sets the **R** flag, because BTP has already delivered the message or closed the
    /// session trying.
    pub fn open_to(
        &mut self,
        session: SessionId,
        protocol: ProtocolId,
        peer: Peer,
        now: Instant,
    ) -> Result<ExchangeKey> {
        // The same obligation as [`Messaging::open`]: an unsecured initiator has to have
        // §4.13.2.1's context before it sends, or its message carries no Source Node ID and the
        // responder is told to discard it. [`Messaging::open_unsecured_to`] does both.
        if session == SessionId::UNSECURED && self.unsecured_peer.is_none() {
            bail!(InvalidState)
        }
        let params = self.mrp_params(session);
        self.exchanges
            .open_initiator(session, protocol, params, Some(peer), now)
    }

    /// [`Messaging::open_unsecured`], to a peer whose address is already known.
    ///
    /// What a commissioner uses: it found the device over BLE or mDNS, so it has somewhere to
    /// send before any session exists.
    pub fn open_unsecured_to(
        &mut self,
        protocol: ProtocolId,
        peer: Peer,
        now: Instant,
        randomness: u64,
    ) -> Result<ExchangeKey> {
        self.open_unsecured_as_initiator(crate::msg::NodeId::ephemeral(randomness))?;
        let params = self.mrp_params(SessionId::UNSECURED);
        self.exchanges
            .open_initiator(SessionId::UNSECURED, protocol, params, Some(peer), now)
    }

    /// Where an exchange's peer is, once it is known.
    #[must_use]
    pub fn peer(&self, exchange: ExchangeKey) -> Option<Peer> {
        self.exchanges.find(exchange).and_then(|e| e.peer)
    }

    fn mrp_params(&self, session: SessionId) -> MrpParams {
        self.sessions
            .find(session)
            .map_or_else(MrpParams::default, |s| s.mrp)
    }

    /// Closes an exchange.
    pub fn close(&mut self, exchange: ExchangeKey) -> bool {
        self.exchanges.close(exchange)
    }

    /// Processes one arriving datagram, in place (§4.7.2).
    ///
    /// `buf` is decrypted in place, so the returned payload borrows it. On any failure the
    /// contents of `buf` are unspecified — §3.6.2 says a failed tag check leaves the payload
    /// undefined — and nothing in this node's state has moved.
    pub fn receive<'b>(
        &mut self,
        buf: &'b mut [u8],
        from: Peer,
        now: Instant,
    ) -> Result<Received<'b>> {
        let head = preview(buf)?;
        if matches!(head.session_type, SessionType::Group) {
            // §4.16: a group message is keyed by an *operational group key* and belongs to no
            // session, so none of this function's machinery applies to it — there is no
            // session to find, no replay window of a session's to move, and no exchange, since
            // §4.16.2 step 2c sets only the P flag, so a group message is never
            // reliable and never acknowledged.
            //
            // It is handed back rather than refused. A device with a group key store routes it
            // to [`group::wire::receive`](crate::group::wire::receive), which is the same layer
            // as this one for keys it holds rather than sessions; a device without one drops
            // it. Answering `Unsupported` here made the two halves look like one missing one.
            return Ok(Received::Group {
                session_id: head.session_id,
                from,
            });
        }

        let (header, range) = if head.session_id == SessionId::UNSECURED {
            let (header, rest) = MessageHeader::decode(buf)?;
            if !header.is_unsecured() {
                bail!(MessageReserved)
            }
            let start = buf.len().saturating_sub(rest.len());
            (header, start..buf.len())
        } else {
            let session = self
                .sessions
                .find(head.session_id)
                .ok_or(Error::new(ErrorCode::NoSession))?;
            // §4.8.1.1's nonce depends on how the session was established, and getting it
            // wrong fails the tag rather than silently mis-decrypting — but naming it here
            // keeps the two readings from ever being confused.
            let nonce_source = match session.kind {
                SessionKind::Pase => NonceSource::Pase,
                SessionKind::Case => NonceSource::Case(session.peer_node_id),
            };
            let keys = session.keys.receiving(session.role).clone();
            unprotect(buf, &keys, nonce_source)?
        };

        // Authenticated. Only now may any counter move.
        let verdict = if header.is_unsecured() {
            self.unsecured_window.accept(header.message_counter)
        } else {
            let session = self
                .sessions
                .find_mut(head.session_id)
                .ok_or(Error::new(ErrorCode::NoSession))?;
            // Authenticated, so it is the peer and this is where it is. A node that opens an
            // exchange of its own — §8.5.3's subscription reports above all — has no other way
            // to learn the address, and an exchange with no peer sends nothing.
            session.peer = Some(from);
            session.accept_counter(header.message_counter, now)
        };

        let Some(payload) = buf.get(range) else {
            bail!(MessageTruncated)
        };
        let (protocol_header, body) = ProtocolHeader::decode(payload)?;

        // §4.13.2.1's context matching: "Else if the message carries a Source Node ID … Set
        // Session Role to responder … Record the incoming message's Source Node ID as Ephemeral
        // Initiator Node ID." Recorded here, before the exchange is routed, so that the very
        // first reply carries it back as the Destination Node ID.
        // §4.13.2.1 step 1c: "Else discard the message." A message that matches no context and
        // carries no Source Node ID belongs to no session, and accepting it is what let this
        // crate's own initiator get away with sending one — the two halves agreed with each
        // other and disagreed with the specification.
        if header.is_unsecured() && header.source.is_none() {
            let addressed_to_our_context = matches!(
                (self.unsecured_peer, header.destination),
                (Some(peer), Destination::Node(id)) if peer.ephemeral_initiator == id
            );
            if !addressed_to_our_context {
                bail!(NoSession)
            }
        }
        if header.is_unsecured()
            && let Some(source) = header.source
            && self
                .unsecured_peer
                .is_none_or(|peer| peer.ephemeral_initiator != source)
        {
            // §4.13.2.1 matches a context by Ephemeral Initiator Node ID and creates a *new*
            // one when no context matches. A different id is a different session — a second
            // commissioner, or the same one returning for CASE after PASE — so the context is
            // replaced rather than kept. Keeping the first would address every reply to a peer
            // that has gone, which the CHIP SDK drops as belonging to no session of its own.
            //
            // One context at a time is the simplification here; the specification allows
            // several. What makes it safe is that the *contents* are two header fields and a
            // replay window, and admitting a second handshake at all is refused a layer up by
            // `PaseAdmission`.
            self.unsecured_peer = Some(UnsecuredPeer {
                ephemeral_initiator: source,
                we_initiated: false,
            });
        }

        let duplicate = matches!(verdict, Verdict::Duplicate);
        let key = self.route(header.session_id, &protocol_header, duplicate, now)?;
        let Some(exchange) = self.exchanges.find_mut(key) else {
            bail!(NoExchange)
        };
        exchange.touch(now);
        // Where the reply goes, and — §4.12.4 — whether MRP runs on this exchange. A peer
        // that moved (a Thread node changing address, say) is followed here.
        exchange.peer = Some(from);
        exchange.mrp.note_peer_activity(now);

        // §4.12.1: an acknowledgement may ride on any message, so it is taken before the
        // message's own kind is considered.
        if let Some(acknowledged) = protocol_header.acknowledged_counter {
            exchange.mrp.on_ack(acknowledged, now);
        }

        if protocol_header.reliability {
            exchange
                .mrp
                .on_reliable_received(header.message_counter, now, duplicate);
        }
        let needs_ack = protocol_header.reliability;

        if duplicate {
            return Ok(Received::Duplicate {
                exchange: key,
                needs_ack,
            });
        }
        if protocol_header.protocol == ProtocolId::SECURE_CHANNEL
            && protocol_header.opcode == crate::sc::opcode::MRP_STANDALONE_ACK
        {
            // A standalone acknowledgement carries nothing above the reliability layer.
            return Ok(Received::Acknowledged { exchange: key });
        }

        // §4.11.1.4: "If a Node has either sent or received a CloseSession StatusReport, that
        // Node SHALL remove all state associated with the session." Both halves are the
        // message layer's, and this is the half a node is most likely to leave out — sending
        // one is a decision it makes, receiving one is something that happens to it.
        //
        // Handled here rather than handed upward because the rule is about *this* layer's
        // state: the session, its keys, its counters and its exchanges, including the exchange
        // this message arrived on. A node that passed it up would answer on a session the
        // specification says is already gone.
        if !header.is_unsecured()
            && protocol_header.protocol == ProtocolId::SECURE_CHANNEL
            && protocol_header.opcode == crate::sc::opcode::STATUS_REPORT
            && matches!(
                crate::sc::status::StatusReport::decode(body),
                Ok(report)
                    if report.protocol == ProtocolId::SECURE_CHANNEL
                        && report.protocol_code
                            == crate::sc::status::SecureChannelCode::CloseSession as u16
            )
        {
            let session = header.session_id;
            self.close_session(session);
            return Ok(Received::SessionClosed { session });
        }

        Ok(Received::Message {
            exchange: key,
            header: protocol_header,
            needs_ack,
            payload: body,
        })
    }

    /// Finds or opens the exchange a message belongs to (§4.10.5.2).
    ///
    /// The three rules are in order, and the order is what bounds the table:
    ///
    /// 1. "If the unsolicited message is not marked as having a duplicate message counter,
    ///    **has a registered Protocol ID**, and the I Flag is set: create a new exchange."
    /// 2. "Otherwise, if the message has the R Flag set: create an *ephemeral* exchange … and
    ///    send an immediate standalone acknowledgement. The message SHALL NOT be forwarded to
    ///    the upper layer."
    /// 3. "Otherwise, processing of the message SHALL stop."
    ///
    /// Rule 3 is the one that matters most and is the easiest to leave out: a message this
    /// node will never act on, and which is not even asking for an acknowledgement, must not
    /// cost a table entry. Without it every datagram that reaches the port allocates.
    fn route(
        &mut self,
        session: SessionId,
        header: &ProtocolHeader,
        duplicate: bool,
        now: Instant,
    ) -> Result<ExchangeKey> {
        if let Some(exchange) =
            self.exchanges
                .find_for_message(session, header.exchange_id, header.initiator)
        {
            return Ok(exchange.key);
        }
        // Only a message *from* an initiator may open an exchange. One claiming to be from a
        // responder with no exchange to respond to is answering a question nobody asked.
        if !header.initiator {
            bail!(NoExchange)
        }
        let params = self.mrp_params(session);
        if !duplicate && self.protocols.contains(header.protocol) {
            return self.exchanges.open_responder(
                session,
                header.exchange_id,
                header.protocol,
                params,
                now,
            );
        }
        if header.reliability {
            // Rule 2. The sender is owed an acknowledgement even though nothing here will
            // read its message — withholding it costs five retransmissions — but the entry
            // that carries it is closed as soon as it has been sent.
            return self.exchanges.open_ephemeral(
                session,
                header.exchange_id,
                header.protocol,
                params,
                now,
            );
        }
        // Rule 3.
        bail!(NoExchange)
    }

    /// Builds an outgoing message on an exchange (§4.7.1).
    ///
    /// `reliable` sets the MRP **R** flag; a reliable message is remembered for
    /// retransmission until it is acknowledged, and [`Messaging::poll`] is what resends it.
    /// `randomness` is the jitter draw of §4.12.2.1 and should come from
    /// [`Rng`](crate::platform::Rng).
    ///
    /// Returns how many octets of `out` the datagram occupies, and the counter it was sent
    /// with — which is what a retransmission is identified by.
    #[expect(
        clippy::too_many_arguments,
        reason = "every one is a distinct fact about the message; bundling them into a \
                  struct would only move the same list one line up"
    )]
    pub fn send(
        &mut self,
        exchange: ExchangeKey,
        opcode: u8,
        reliable: bool,
        payload: &[u8],
        now: Instant,
        randomness: u32,
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<(usize, u32)> {
        let Some(open) = self.exchanges.find(exchange) else {
            bail!(NoExchange)
        };
        let protocol = open.protocol;
        // §4.12.4: "Reliable messages sent over TCP, PAFTP, or BTP SHALL utilize the
        // underlying reliability mechanisms of those transports and SHOULD NOT set the R
        // Flag." Running MRP on top of BTP would retransmit a message BTP has already
        // guaranteed, and BTP would carry the duplicate faithfully.
        let reliable = reliable && !open.is_transport_reliable();
        let piggyback = self
            .exchanges
            .find_mut(exchange)
            .and_then(|e| e.mrp.take_piggyback());

        let protocol_header = ProtocolHeader {
            initiator: exchange.role.is_initiator(),
            acknowledged_counter: piggyback,
            reliability: reliable,
            exchange_id: exchange.id,
            protocol,
            opcode,
        };

        let counter = self.next_counter(exchange.session, now)?;
        let written = self.frame(
            exchange.session,
            counter,
            &protocol_header,
            payload,
            scratch,
            out,
        )?;

        if reliable && let Some(open) = self.exchanges.find_mut(exchange) {
            open.mrp.on_send(counter, now, randomness)?;
        }
        Ok((written, counter))
    }

    /// Sends the standalone acknowledgement a [`Received`] said was owed (§4.12.1).
    ///
    /// A standalone ack is *not* reliable — acknowledging an acknowledgement would never
    /// terminate — and carries no payload.
    pub fn acknowledge(
        &mut self,
        exchange: ExchangeKey,
        now: Instant,
        out: &mut [u8],
    ) -> Result<usize> {
        let Some(open) = self.exchanges.find_mut(exchange) else {
            bail!(NoExchange)
        };
        let ephemeral = open.ephemeral;
        let Some(acknowledged) = open.mrp.take_piggyback() else {
            // Nothing owed: the acknowledgement was already carried by an earlier message.
            if ephemeral {
                self.exchanges.close(exchange);
            }
            return Ok(0);
        };
        let protocol_header = ProtocolHeader {
            initiator: exchange.role.is_initiator(),
            acknowledged_counter: Some(acknowledged),
            reliability: false,
            exchange_id: exchange.id,
            // §4.12.7.1: "The Protocol ID SHALL be set to PROTOCOL_ID_SECURE_CHANNEL."
            //
            // Not the exchange's protocol, which is the natural thing to write and what this
            // did: the opcode is Secure Channel's, so sending it under the exchange's protocol
            // id produces a message that decodes as, say, Interaction Model opcode 0x10 — an
            // opcode the Interaction Model does not define. The CHIP SDK prints it as
            // `IM:----` and answers `Invalid message type`, which ends the interaction the
            // acknowledgement was supposed to keep alive.
            //
            // MRP is a property of the *exchange layer*, below the protocol running on it, and
            // this is where that shows on the wire.
            protocol: ProtocolId::SECURE_CHANNEL,
            opcode: crate::sc::opcode::MRP_STANDALONE_ACK,
        };
        let counter = self.next_counter(exchange.session, now)?;
        // A standalone acknowledgement carries no payload, so the body being joined is the
        // protocol header alone and the scratch never needs to be larger than one.
        let mut scratch = [0u8; PROTOCOL_HEADER_MAX];
        let written = self.frame(
            exchange.session,
            counter,
            &protocol_header,
            &[],
            &mut scratch,
            out,
        )?;
        // §4.12.5.2.2: "If the Exchange is marked as an ephemeral exchange the Exchange SHALL
        // be closed." It existed only to carry this acknowledgement, and holding it open is
        // what would make answering a stranger politely cost a table entry.
        if ephemeral {
            self.exchanges.close(exchange);
        }
        Ok(written)
    }

    /// Takes the next message counter for a session (§4.6.1).
    fn next_counter(&mut self, session: SessionId, now: Instant) -> Result<u32> {
        if session == SessionId::UNSECURED {
            self.unsecured_counter.take()
        } else {
            self.sessions
                .find_mut(session)
                .ok_or(Error::new(ErrorCode::NoSession))?
                .next_counter(now)
        }
    }

    /// Frames, and encrypts when the session is secure.
    fn frame(
        &self,
        session: SessionId,
        counter: u32,
        protocol_header: &ProtocolHeader,
        payload: &[u8],
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<usize> {
        // §4.8's AEAD needs the protocol header and the payload contiguous before it can
        // encrypt them, and this is where they are joined. The buffer is the caller's
        // because its size is the *transport's*: a datagram node needs
        // [`MAX_UDP_MESSAGE`](crate::config::MAX_UDP_MESSAGE) and nothing more, and a node on
        // TCP needs the framer's own `N` — §4.15.2.3's Maximum Message Size, which is the whole
        // reason §4.15 exists and is far too much to put on the stack of every node that
        // never opens a connection.
        let header_len = protocol_header.encode(scratch)?;
        let end = header_len
            .checked_add(payload.len())
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let Some(slot) = scratch.get_mut(header_len..end) else {
            bail!(BufferTooSmall)
        };
        slot.copy_from_slice(payload);
        let Some(body) = scratch.get(..end) else {
            bail!(BufferTooSmall)
        };

        if session == SessionId::UNSECURED {
            // §4.13.2.1: the Ephemeral Initiator Node ID is "enclosed by initiator as Source
            // Node ID and responder as Destination Node ID". Which field it goes in is decided
            // by which end of the context this node is, and a message carrying neither is one
            // the peer cannot associate with any session — the CHIP SDK drops it outright.
            let (source, destination) = match self.unsecured_peer {
                Some(peer) if peer.we_initiated => {
                    (Some(peer.ephemeral_initiator), Destination::None)
                }
                Some(peer) => (None, Destination::Node(peer.ephemeral_initiator)),
                None => (None, Destination::None),
            };
            let header = MessageHeader {
                session_id: SessionId::UNSECURED,
                message_counter: counter,
                source,
                destination,
                ..MessageHeader::default()
            };
            let header_len = header.encode(out)?;
            let total = header_len
                .checked_add(body.len())
                .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
            let Some(slot) = out.get_mut(header_len..total) else {
                bail!(BufferTooSmall)
            };
            slot.copy_from_slice(body);
            return Ok(total);
        }

        let found = self
            .sessions
            .find(session)
            .ok_or(Error::new(ErrorCode::NoSession))?;
        let header = MessageHeader {
            session_id: found.peer_session_id,
            message_counter: counter,
            // §4.4.1.5: the Source Node ID is elided on a secure unicast session, where the
            // session itself already says who is speaking.
            source: None,
            destination: Destination::None,
            // §4.9 is the sender's choice on a unicast session; see
            // [`Messaging::set_privacy`]. A PASE session is never private: it has no
            // operational identity to correlate, so there would be nothing to hide.
            privacy: self.privacy && matches!(found.kind, SessionKind::Case),
            ..MessageHeader::default()
        };
        let nonce_source = match found.kind {
            SessionKind::Pase => NonceSource::Pase,
            SessionKind::Case => NonceSource::Case(found.local_node_id),
        };
        let keys = found.keys.sending(found.role);
        protect(&header, nonce_source, body, keys, out)
    }

    /// When [`Messaging::poll`] next needs to be called.
    ///
    /// The earlier of a reliability deadline and the next moment an abandoned exchange could
    /// be reclaimed, so a node that honours this wake-up gets §4.10.5.3's cleanup without
    /// scheduling anything of its own.
    #[must_use]
    pub fn wake_at(&self) -> Option<Instant> {
        let reap = self.exchanges.reap_deadline(EXCHANGE_IDLE_TIMEOUT);
        match (self.exchanges.poll_deadline(), reap) {
            (Some(a), Some(b)) => Some(if a <= b { a } else { b }),
            (Some(a), None) => Some(a),
            (None, b) => b,
        }
    }

    /// Drives the reliability timers (§4.12.2.1) and reclaims abandoned exchanges (§4.10.5.3).
    ///
    /// Returns one action at a time; call until it returns `None`.
    ///
    /// Reaping happens here rather than in a method a node has to remember to call, because an
    /// exchange table reclaimed only on request is one an attacker fills at leisure: every
    /// unsecured datagram with the **I** flag opens an entry (§4.10.5.2), and `X` of them
    /// would otherwise deny every later session establishment for the node's whole uptime.
    pub fn poll(&mut self, now: Instant, randomness: u32) -> Option<Due> {
        self.exchanges.reap(now, EXCHANGE_IDLE_TIMEOUT);
        let expired = self
            .exchanges
            .iter()
            .find(|e| e.mrp.poll_deadline().is_some_and(|at| at <= now))
            .map(|e| e.key)?;
        let open = self.exchanges.find_mut(expired)?;
        match open.mrp.on_timeout(now, randomness) {
            OnTimeout::Retransmit { counter, .. } => Some(Due::Retransmit {
                exchange: expired,
                counter,
            }),
            // §4.12.5.2.2: nothing to piggyback on, so the acknowledgement goes on its own.
            OnTimeout::SendStandaloneAck { .. } => Some(Due::Acknowledge { exchange: expired }),
            OnTimeout::GiveUp { .. } => {
                self.exchanges.close(expired);
                Some(Due::Abandoned { exchange: expired })
            }
            OnTimeout::Nothing => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Capacity, DefaultConfig};
    use crate::exchange::Role;

    type Node = Messaging<DefaultConfig>;

    fn at(ms: u64) -> Instant {
        Instant::from_micros(ms.saturating_mul(1000))
    }

    const PEER: Peer = Peer::Udp(crate::platform::PeerAddr::new([
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]));

    fn keys() -> crate::session::EstablishedKeys {
        crate::session::EstablishedKeys::derive(b"shared secret", &[]).expect("derive")
    }

    fn session_on(id: u16, fabric: u8, now: Instant) -> SecureSession {
        let mut s = SecureSession::new(
            SessionId(id),
            SessionId(id.wrapping_add(100)),
            SessionKind::Case,
            crate::session::Role::Responder,
            keys(),
            1,
            now,
        );
        s.fabric_index = crate::msg::FabricIndex(fabric);
        s.peer = Some(PEER);
        s
    }

    /// §4.11.1.4: "The CloseSession StatusReport SHALL only be sent encrypted within an
    /// exchange associated with a PASE or CASE session." So one that arrives on the *unsecured*
    /// session closes nothing — otherwise anybody who can reach the port could end a
    /// commissioned node's sessions with a datagram costing them nothing to send.
    #[test]
    fn an_unsecured_close_session_report_closes_nothing() {
        let mut node = Node::new(1, 100, 7);
        let mut scratch = [0u8; 512];
        let mut wire = [0u8; 512];
        node.install_session(session_on(1, 1, at(0)), at(0), 0, &mut scratch, &mut wire)
            .expect("install");

        // A stranger's unsecured datagram carrying exactly the report a peer would send.
        let mut attacker = Node::new(2, 200, 9);
        let report = crate::sc::status::StatusReport {
            general: crate::sc::status::GeneralCode::Success,
            protocol: ProtocolId::SECURE_CHANNEL,
            protocol_code: crate::sc::status::SecureChannelCode::CloseSession as u16,
            data: &[],
        };
        let mut body = [0u8; 16];
        let len = report.encode(&mut body).expect("encode");
        let exchange = attacker
            .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0xE0E0_1234_5678_9ABC)
            .expect("open");
        let (sent, _) = attacker
            .send(
                exchange,
                crate::sc::opcode::STATUS_REPORT,
                false,
                body.get(..len).expect("body"),
                at(0),
                0,
                &mut scratch,
                &mut wire,
            )
            .expect("send");

        let received = node.receive(wire.get_mut(..sent).expect("wire"), PEER, at(1));
        assert!(
            matches!(received, Ok(Received::Message { .. })),
            "an unsecured status report is an ordinary message, got {received:?}"
        );
        assert!(
            node.sessions().find(SessionId(1)).is_some(),
            "no unauthenticated datagram may close a session"
        );
    }

    /// §4.16: a group datagram belongs to the group key store, and this layer says so rather
    /// than refusing it. Refusing made a node that holds group keys look like a node that
    /// cannot receive groupcast at all.
    #[test]
    fn a_group_datagram_is_handed_back_rather_than_refused() {
        let mut node = Node::new(1, 100, 7);
        // §4.4.1.2's session type bits: a group message names its Group Session Id and carries
        // the session type in the low bits of the security flags.
        let mut datagram = [0u8; 32];
        datagram[0] = 0b0000_0000; // message flags: no source, no destination
        datagram[1..3].copy_from_slice(&0x1234u16.to_le_bytes()); // group session id
        datagram[3] = 0b0000_0001; // security flags: session type = group
        datagram[4..8].copy_from_slice(&7u32.to_le_bytes()); // message counter

        let received = node.receive(&mut datagram, PEER, at(0));
        assert!(
            matches!(
                received,
                Ok(Received::Group { session_id, from })
                    if session_id == SessionId(0x1234) && from == PEER
            ),
            "expected a group hand-off, got {received:?}"
        );
        assert_eq!(
            node.exchanges().len(),
            0,
            "a group message opens nothing: §4.16.2 step 2c sets only the P flag"
        );
    }

    /// §4.11.1.4: "If a Node has either sent or received a CloseSession StatusReport, that
    /// Node SHALL remove all state associated with the session." The receiving half is the
    /// one a node leaves out, because sending one is a decision and receiving one is not.
    #[test]
    fn a_close_session_report_from_the_peer_closes_the_session_here_too() {
        let mut a = Node::new(1, 100, 7);
        let mut b = Node::new(2, 200, 9);
        let mut scratch = [0u8; 512];
        let mut wire = [0u8; 512];

        // The same keys at both ends, with opposite roles, is a session the two share.
        let mut left = SecureSession::new(
            SessionId(1),
            SessionId(2),
            SessionKind::Case,
            crate::session::Role::Initiator,
            keys(),
            1,
            at(0),
        );
        left.peer = Some(PEER);
        let mut right = SecureSession::new(
            SessionId(2),
            SessionId(1),
            SessionKind::Case,
            crate::session::Role::Responder,
            keys(),
            1,
            at(0),
        );
        right.peer = Some(PEER);
        a.install_session(left, at(0), 0, &mut scratch, &mut wire)
            .expect("install");
        b.install_session(right, at(0), 0, &mut scratch, &mut wire)
            .expect("install");
        b.open(SessionId(2), ProtocolId::INTERACTION_MODEL, at(0))
            .expect("an exchange that the close has to take with it");

        // A closes its end, which frames the report §4.11.1.4 owes the peer: a new exchange,
        // and no R flag.
        let report = crate::sc::status::StatusReport {
            general: crate::sc::status::GeneralCode::Success,
            protocol: ProtocolId::SECURE_CHANNEL,
            protocol_code: crate::sc::status::SecureChannelCode::CloseSession as u16,
            data: &[],
        };
        let mut body = [0u8; 16];
        let len = report.encode(&mut body).expect("encode");
        let exchange = a
            .open(SessionId(1), ProtocolId::SECURE_CHANNEL, at(0))
            .expect("open");
        let (sent, _) = a
            .send(
                exchange,
                crate::sc::opcode::STATUS_REPORT,
                false,
                body.get(..len).expect("body"),
                at(0),
                0,
                &mut scratch,
                &mut wire,
            )
            .expect("send");

        let received = b.receive(wire.get_mut(..sent).expect("wire"), PEER, at(1));
        assert!(
            matches!(received, Ok(Received::SessionClosed { session }) if session == SessionId(2)),
            "expected the session to be closed, got {received:?}"
        );
        assert!(b.sessions().find(SessionId(2)).is_none());
        assert_eq!(
            b.exchanges().len(),
            0,
            "§4.13.3.1: all state associated with the session"
        );
    }

    /// §4.11.1.1: a full session table evicts the least recently used session rather than
    /// refusing the handshake. Refusing it is a node that can be commissioned
    /// as many times as its session table is long, and never again.
    #[test]
    fn a_full_session_table_evicts_the_least_recently_used_session() {
        // Filled from the table's own capacity, so the test stays about *fullness* rather than
        // about a number that used to be the capacity.
        const CAP: u16 = SessionTable::<DefaultConfig, 16>::TOTAL as u16;
        let mut node = Node::new(1, 100, 7);
        let mut scratch = [0u8; 512];
        let mut out = [0u8; 512];
        for i in 0..CAP {
            let evicted = node
                .install_session(
                    session_on(i + 1, 1, at(u64::from(i))),
                    at(u64::from(i)),
                    0,
                    &mut scratch,
                    &mut out,
                )
                .expect("install");
            assert!(evicted.is_none(), "there was room for session {i}");
        }
        assert_eq!(node.sessions().len(), usize::from(CAP));

        let evicted = node
            .install_session(
                session_on(CAP + 1, 1, at(u64::from(CAP) + 1)),
                at(u64::from(CAP) + 1),
                0,
                &mut scratch,
                &mut out,
            )
            .expect("install")
            .expect("the table was full, so one had to go");

        // Step 1: the least recently used, which is the one installed first.
        assert_eq!(evicted.session, SessionId(1));
        // Step 2a: a datagram for its peer, framed before the session went away.
        assert_eq!(evicted.peer, Some(PEER));
        assert!(evicted.len > 0, "the CloseSession report was framed");
        // Step 2b: and the session itself is gone, with the new one in its place.
        assert!(node.sessions().find(SessionId(1)).is_none());
        assert!(node.sessions().find(SessionId(CAP + 1)).is_some());
        assert_eq!(node.sessions().len(), usize::from(CAP));
    }

    /// §4.13.3.1: closing a session removes "all state associated with" it, which includes
    /// the exchanges on it. An exchange that outlives its session can never be answered on,
    /// and holds a slot in a fixed-capacity table until it times out.
    #[test]
    fn closing_a_session_closes_its_exchanges() {
        let mut node = Node::new(1, 100, 7);
        let mut scratch = [0u8; 512];
        let mut out = [0u8; 512];
        node.install_session(session_on(1, 1, at(0)), at(0), 0, &mut scratch, &mut out)
            .expect("install");
        node.open(SessionId(1), ProtocolId::INTERACTION_MODEL, at(0))
            .expect("open");
        node.open(SessionId(1), ProtocolId::INTERACTION_MODEL, at(0))
            .expect("open");
        assert_eq!(node.exchanges().len(), 2);

        assert!(node.close_session(SessionId(1)));
        assert_eq!(node.exchanges().len(), 0, "the exchanges went with it");
        assert!(node.sessions().find(SessionId(1)).is_none());
    }

    /// §11.18.6.12: `RemoveFabric` takes the fabric's sessions — and their exchanges — while
    /// leaving every other fabric's alone.
    #[test]
    fn removing_a_fabric_takes_its_sessions_and_their_exchanges() {
        let mut node = Node::new(1, 100, 7);
        let mut scratch = [0u8; 512];
        let mut out = [0u8; 512];
        node.install_session(session_on(1, 1, at(0)), at(0), 0, &mut scratch, &mut out)
            .expect("install");
        node.install_session(session_on(2, 2, at(1)), at(1), 0, &mut scratch, &mut out)
            .expect("install");
        node.open(SessionId(1), ProtocolId::INTERACTION_MODEL, at(0))
            .expect("open");
        node.open(SessionId(2), ProtocolId::INTERACTION_MODEL, at(0))
            .expect("open");

        assert_eq!(node.remove_fabric(crate::msg::FabricIndex(1)), 1);
        assert!(node.sessions().find(SessionId(1)).is_none());
        assert!(node.sessions().find(SessionId(2)).is_some());
        assert_eq!(
            node.exchanges().len(),
            1,
            "only the removed fabric's exchange went"
        );
    }

    /// The unsecured session is what PASE runs over before any key exists.
    #[test]
    fn an_unsecured_message_round_trips_through_a_new_exchange() {
        let mut initiator = Node::new(1, 100, 7);
        let mut responder = Node::new(2, 200, 9);

        let key = initiator
            .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0xE0E0_1234_5678_9ABC)
            .expect("open");
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let (len, counter) = initiator
            .send(
                key,
                0x20,
                true,
                b"pbkdf-param-request",
                at(0),
                0,
                &mut scratch,
                &mut wire,
            )
            .expect("send");

        let received = responder
            .receive(&mut wire[..len], PEER, at(1))
            .expect("receive");
        let Received::Message {
            exchange,
            header,
            needs_ack,
            payload,
        } = received
        else {
            panic!("expected a message, got {received:?}");
        };
        assert_eq!(payload, b"pbkdf-param-request");
        assert_eq!(header.opcode, 0x20);
        assert!(needs_ack, "a reliable message owes an acknowledgement");
        // The responder opened its own half of the exchange, with the peer's id.
        assert_eq!(exchange.role, Role::Responder);
        assert_eq!(exchange.id, key.id);

        // ...and the acknowledgement it sends clears the initiator's retransmission.
        let mut ack = [0u8; 512];
        let ack_len = responder
            .acknowledge(exchange, at(1), &mut ack)
            .expect("ack");
        assert!(ack_len > 0);
        assert!(initiator.wake_at().is_some(), "waiting for the ack");
        let back = initiator
            .receive(&mut ack[..ack_len], PEER, at(2))
            .expect("receive ack");
        assert!(matches!(back, Received::Acknowledged { .. }));
        assert!(
            !initiator
                .exchanges()
                .find(key)
                .expect("still open")
                .mrp
                .is_awaiting_ack(),
            "acknowledged, so no retransmission is outstanding"
        );
        let _ = counter;
    }

    /// Builds one unsecured datagram from a stranger, with the exchange id and protocol of
    /// its choosing — which is everything an off-path attacker controls before any key exists.
    fn stranger_datagram(
        exchange_id: u16,
        protocol: ProtocolId,
        reliable: bool,
        counter: u32,
        out: &mut [u8],
    ) -> usize {
        let mut sender = Node::new(1, exchange_id, counter);
        sender.register(Protocols::SECURE_CHANNEL.with(Protocols::INTERACTION_MODEL));
        let key = sender
            .open_unsecured(protocol, at(0), 0xE0E0_1234_5678_9ABC)
            .expect("open");
        let mut scratch = [0u8; 512];
        let (len, _) = sender
            .send(key, 0x20, reliable, b"x", at(0), 0, &mut scratch, out)
            .expect("send");
        len
    }

    /// The exhaustion attack, and the shape CVE-2024-3297 had: every unsecured message with
    /// the **I** flag opens an exchange (§4.10.5.2), so a stranger who varies the exchange id
    /// fills the table. Without reclamation the node can never open another exchange — which
    /// means it can never establish another session, PASE or CASE, for the rest of its uptime.
    #[test]
    fn a_stranger_cannot_fill_the_exchange_table_for_good() {
        let mut node = Node::new(2, 200, 9);
        let mut wire = [0u8; 512];

        // The whole table, from the table rather than from a literal.
        const CAP: u16 = ExchangeTable::<DefaultConfig, 64>::TOTAL as u16;
        for id in 0..CAP {
            let len = stranger_datagram(
                id,
                ProtocolId::SECURE_CHANNEL,
                true,
                u32::from(id) + 1,
                &mut wire,
            );
            let _ = node.receive(&mut wire[..len], PEER, at(0));
        }
        assert_eq!(
            node.exchanges().len(),
            usize::from(CAP),
            "the table is full"
        );

        // A legitimate peer arrives while the attacker's entries are still fresh, and is
        // refused — which is correct, and is why the entries must not be permanent.
        let len = stranger_datagram(CAP + 1, ProtocolId::SECURE_CHANNEL, true, 900, &mut wire);
        assert!(node.receive(&mut wire[..len], PEER, at(1)).is_err());

        // A minute later nothing has happened on any of them, so they go.
        assert!(
            node.wake_at().is_some(),
            "the node knows it has something to reclaim"
        );
        node.poll(at(61_000), 0);
        assert_eq!(node.exchanges().len(), 0, "every abandoned entry reclaimed");

        // ...and the node answers again.
        let len = stranger_datagram(901, ProtocolId::SECURE_CHANNEL, true, 901, &mut wire);
        assert!(
            node.receive(&mut wire[..len], PEER, at(62_000)).is_ok(),
            "a node that cannot open an exchange can never establish a session again"
        );
    }

    /// Reclaiming on the timer is not enough on its own: a node whose timers are slow, or
    /// which is simply busy, must still not be refusing legitimate peers on behalf of entries
    /// that expired long ago.
    #[test]
    fn a_full_table_reclaims_before_refusing() {
        const FULL: usize = ExchangeTable::<DefaultConfig, 64>::TOTAL;
        let mut node = Node::new(2, 200, 9);
        let mut wire = [0u8; 512];
        for id in 0..FULL as u16 {
            let len = stranger_datagram(
                id,
                ProtocolId::SECURE_CHANNEL,
                true,
                u32::from(id) + 1,
                &mut wire,
            );
            let _ = node.receive(&mut wire[..len], PEER, at(0));
        }
        assert_eq!(node.exchanges().len(), FULL);

        // No `poll` in between — the pressure itself is the trigger.
        let len = stranger_datagram(
            FULL as u16 + 1,
            ProtocolId::SECURE_CHANNEL,
            true,
            900,
            &mut wire,
        );
        assert!(
            node.receive(&mut wire[..len], PEER, at(61_000)).is_ok(),
            "the entry that would have refused this one had been idle for a minute"
        );
    }

    /// §4.10.5.2 rule 1: "has a registered Protocol ID". An unregistered protocol is not
    /// something this node will ever act on, so it must not cost a table entry.
    #[test]
    fn an_unregistered_protocol_opens_no_exchange() {
        let mut node = Node::new(2, 200, 9);
        node.register(Protocols::SECURE_CHANNEL);
        let mut wire = [0u8; 512];

        // The Interaction Model is not registered on this node.
        let len = stranger_datagram(5, ProtocolId::INTERACTION_MODEL, false, 5, &mut wire);
        assert!(node.receive(&mut wire[..len], PEER, at(0)).is_err());
        assert_eq!(node.exchanges().len(), 0, "rule 3: processing SHALL stop");

        // Secure Channel is, so that one is answered.
        let len = stranger_datagram(6, ProtocolId::SECURE_CHANNEL, false, 6, &mut wire);
        assert!(node.receive(&mut wire[..len], PEER, at(0)).is_ok());
        assert_eq!(node.exchanges().len(), 1);
    }

    /// §4.10.5.2 rule 2: an unregistered protocol that *asks* for an acknowledgement still
    /// gets one — withholding it costs the sender five retransmissions — but on an ephemeral
    /// exchange that §4.12.5.2.2 closes as soon as the acknowledgement is sent.
    #[test]
    fn an_unregistered_reliable_message_is_acknowledged_on_an_ephemeral_exchange() {
        let mut node = Node::new(2, 200, 9);
        node.register(Protocols::SECURE_CHANNEL);
        let mut wire = [0u8; 512];
        let len = stranger_datagram(7, ProtocolId::BDX, true, 7, &mut wire);

        let received = node.receive(&mut wire[..len], PEER, at(0)).expect("routed");
        let Received::Message { exchange, .. } = received else {
            panic!("expected the ephemeral exchange, got {received:?}")
        };
        assert_eq!(node.exchanges().len(), 1);
        assert!(
            node.exchanges().find(exchange).is_some_and(|e| e.ephemeral),
            "it is ephemeral"
        );

        let mut ack = [0u8; 512];
        assert!(node.acknowledge(exchange, at(0), &mut ack).expect("ack") > 0);
        assert_eq!(
            node.exchanges().len(),
            0,
            "§4.12.5.2.2: the ephemeral exchange SHALL be closed once it has acknowledged"
        );
    }

    /// An exchange that is still trying to deliver something is not abandoned, however quiet
    /// the peer has been — §4.10.5.3 step 2b.
    #[test]
    fn an_exchange_with_a_pending_retransmission_is_never_reaped() {
        let mut node = Node::new(1, 100, 7);
        let key = node
            .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0xE0E0_1234_5678_9ABC)
            .expect("open");
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let _ = node
            .send(key, 0x20, true, b"x", at(0), 0, &mut scratch, &mut wire)
            .expect("send");

        // Far past the idle timeout, and never acknowledged.
        node.exchanges_mut()
            .reap(at(600_000), EXCHANGE_IDLE_TIMEOUT);
        assert_eq!(
            node.exchanges().len(),
            1,
            "a retransmission still pending keeps the exchange open"
        );
    }

    /// §4.13.2.1's Unsecured Session Context, and the rule that no test of this crate against
    /// itself could catch.
    ///
    /// > Ephemeral Initiator Node ID: Randomly selected for each session by the initiator from
    /// > the Operational Node ID range and **enclosed by initiator as Source Node ID and
    /// > responder as Destination Node ID.**
    ///
    /// Both halves have to hold, and a stack that encloses *neither* is self-consistent: two
    /// nodes built from it commission each other perfectly. The CHIP SDK drops such a message
    /// before it reaches any protocol — "Received malformed unsecure packet with source 0x0
    /// destination 0x0" — so the symptom is a device no certified controller can pair with,
    /// while every test passes.
    #[test]
    fn an_unsecured_response_carries_the_initiators_ephemeral_node_id() {
        const EPHEMERAL: crate::msg::NodeId = crate::msg::NodeId(0x0102_0304_0506_0708);

        let mut initiator = Node::new(1, 100, 7);
        initiator
            .open_unsecured_as_initiator(EPHEMERAL)
            .expect("an operational node id");
        let mut responder = Node::new(2, 200, 9);

        // `open` rather than `open_unsecured`, because the context is the one this test named.
        let key = initiator
            .open(SessionId::UNSECURED, ProtocolId::SECURE_CHANNEL, at(0))
            .expect("open");
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let (len, _) = initiator
            .send(
                key,
                0x20,
                true,
                b"request",
                at(0),
                0,
                &mut scratch,
                &mut wire,
            )
            .expect("send");

        // The initiator encloses it as the Source Node ID: flag bit 2 of octet 0, then eight
        // octets little-endian after the four-octet counter.
        assert_eq!(wire[0] & 0x04, 0x04, "S flag set");
        assert_eq!(
            u64::from_le_bytes(wire[8..16].try_into().expect("eight octets")),
            EPHEMERAL.0,
            "and it is the ephemeral id"
        );

        let received = responder
            .receive(&mut wire[..len], PEER, at(1))
            .expect("receive");
        let Received::Message { exchange, .. } = received else {
            panic!("expected a message, got {received:?}")
        };
        assert_eq!(
            responder.unsecured_ephemeral_id(),
            Some(EPHEMERAL),
            "the responder recorded it as the context's ephemeral initiator id"
        );

        // ...and encloses it as the *Destination* Node ID on the way back.
        let mut back = [0u8; 512];
        let (len, _) = responder
            .send(
                exchange,
                0x21,
                true,
                b"response",
                at(1),
                0,
                &mut scratch,
                &mut back,
            )
            .expect("send");
        assert_eq!(back[0] & 0x04, 0, "no S flag on the responder's message");
        assert_eq!(back[0] & 0x03, 0x01, "DSIZ = 1, a 64-bit Node ID");
        assert_eq!(
            u64::from_le_bytes(back[8..16].try_into().expect("eight octets")),
            EPHEMERAL.0,
            "the destination is the initiator's ephemeral id"
        );

        // The initiator accepts what comes back.
        let round = initiator
            .receive(&mut back[..len], PEER, at(2))
            .expect("the initiator accepts its own ephemeral id as the destination");
        assert!(matches!(round, Received::Message { .. }));
    }

    /// §4.13.2.1 matches a context by Ephemeral Initiator Node ID and creates a new one when
    /// none matches. A node that kept the first would answer a second initiator — the same
    /// commissioner coming back for CASE after PASE, most of the time — with replies addressed
    /// to a peer that has gone, which the CHIP SDK drops before any protocol sees them.
    #[test]
    fn a_second_initiator_replaces_the_unsecured_context() {
        const FIRST: crate::msg::NodeId = crate::msg::NodeId(0x1111_1111_1111_1111);
        const SECOND: crate::msg::NodeId = crate::msg::NodeId(0x2222_2222_2222_2222);

        let mut responder = Node::new(2, 200, 9);
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];

        for (n, (ephemeral, counter)) in [(FIRST, 1u32), (SECOND, 2u32)].into_iter().enumerate() {
            let mut initiator = Node::new(1, 100 + u16::try_from(n).expect("fits"), counter);
            initiator
                .open_unsecured_as_initiator(ephemeral)
                .expect("operational");
            let key = initiator
                .open(SessionId::UNSECURED, ProtocolId::SECURE_CHANNEL, at(0))
                .expect("open");
            let (len, _) = initiator
                .send(key, 0x20, true, b"x", at(0), 0, &mut scratch, &mut wire)
                .expect("send");
            let received = responder
                .receive(&mut wire[..len], PEER, at(1))
                .expect("receive");
            let Received::Message { exchange, .. } = received else {
                panic!("expected a message")
            };
            assert_eq!(
                responder.unsecured_ephemeral_id(),
                Some(ephemeral),
                "the newest initiator owns the context"
            );

            let mut back = [0u8; 512];
            let _ = responder
                .send(
                    exchange,
                    0x21,
                    true,
                    b"y",
                    at(1),
                    0,
                    &mut scratch,
                    &mut back,
                )
                .expect("send");
            assert_eq!(
                u64::from_le_bytes(back[8..16].try_into().expect("eight octets")),
                ephemeral.0,
                "and the reply is addressed to it"
            );
        }
    }

    /// §4.13.2.1 constrains the ephemeral id to the Operational Node ID range, because it is
    /// what the responder will put in a Destination Node ID field.
    #[test]
    fn an_ephemeral_id_outside_the_operational_range_is_refused() {
        let mut node = Node::new(1, 100, 7);
        assert!(
            node.open_unsecured_as_initiator(crate::msg::NodeId::UNSPECIFIED)
                .is_err()
        );
        assert!(
            node.open_unsecured_as_initiator(crate::msg::NodeId(1))
                .is_ok()
        );
    }

    /// §4.12.2.2: a duplicate is acknowledged and not delivered.
    #[test]
    fn a_duplicate_is_acknowledged_and_not_delivered_twice() {
        let mut initiator = Node::new(1, 100, 7);
        let mut responder = Node::new(2, 200, 9);
        let key = initiator
            .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0xE0E0_1234_5678_9ABC)
            .expect("open");

        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let (len, _) = initiator
            .send(key, 0x20, true, b"once", at(0), 0, &mut scratch, &mut wire)
            .expect("send");
        let copy = wire;

        let first = responder
            .receive(&mut wire[..len], PEER, at(1))
            .expect("first");
        assert!(matches!(first, Received::Message { .. }));

        let mut again = copy;
        let second = responder
            .receive(&mut again[..len], PEER, at(2))
            .expect("second");
        match second {
            Received::Duplicate { needs_ack, .. } => {
                assert!(needs_ack, "still acknowledged — the sender's ack was lost");
            }
            other => panic!("a repeat must not reach the application: {other:?}"),
        }
    }

    /// A message for a session this node does not have is refused, not guessed at.
    #[test]
    fn a_message_for_an_unknown_session_is_refused() {
        let mut node = Node::new(1, 100, 7);
        let mut wire = [0u8; 64];
        // Flags: version 0, no source/destination. Session id 0x1234, unicast.
        wire[0] = 0x00;
        wire[1] = 0x34;
        wire[2] = 0x12;
        wire[3] = 0x00;
        let err = node
            .receive(&mut wire, PEER, at(0))
            .expect_err("no session");
        assert_eq!(err.code(), ErrorCode::NoSession);
    }

    /// A response to an exchange that was never opened is refused (§4.4.3.1).
    #[test]
    fn a_message_from_a_responder_cannot_open_an_exchange() {
        let mut initiator = Node::new(1, 100, 7);
        let mut responder = Node::new(2, 200, 9);
        let key = initiator
            .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0xE0E0_1234_5678_9ABC)
            .expect("open");
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let (len, _) = initiator
            .send(
                key,
                0x20,
                false,
                b"hello",
                at(0),
                0,
                &mut scratch,
                &mut wire,
            )
            .expect("send");
        // Clear the I flag in the protocol header: now it claims to be a *response*.
        //
        // The offset is the *message* header's real length, which is not a constant: an
        // unsecured initiator encloses its Ephemeral Initiator Node ID (§4.13.2.1), so the
        // header is eight octets longer than a bare one. Decoding it is the only way to know.
        let (sent_header, _) = MessageHeader::decode(&wire[..len]).expect("decode");
        let header_len = sent_header.encoded_len();
        wire[header_len] &= !0x01;

        let err = responder
            .receive(&mut wire[..len], PEER, at(1))
            .expect_err("a response answers a question nobody asked");
        assert_eq!(err.code(), ErrorCode::NoExchange);
    }

    /// The retransmission timer fires, and names the counter to resend (§4.12.2.1).
    #[test]
    fn an_unacknowledged_message_is_retransmitted_with_its_own_counter() {
        let mut initiator = Node::new(1, 100, 7);
        let key = initiator
            .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0xE0E0_1234_5678_9ABC)
            .expect("open");
        let mut wire = [0u8; 512];
        let mut scratch = [0u8; 512];
        let (_, counter) = initiator
            .send(key, 0x20, true, b"lost", at(0), 0, &mut scratch, &mut wire)
            .expect("send");

        let deadline = initiator.wake_at().expect("a reliable send arms a timer");
        match initiator.poll(deadline, 0) {
            Some(Due::Retransmit {
                exchange,
                counter: again,
            }) => {
                assert_eq!(exchange, key);
                assert_eq!(
                    again, counter,
                    "the same counter: a new one would be a new message and a reused nonce"
                );
            }
            other => panic!("expected a retransmission, got {other:?}"),
        }
    }
}
