//! Secure sessions: what PASE and CASE produce, and what every later message rides on
//! (Core §4.13).
//!
//! A session is a pair of directional keys plus the bookkeeping that makes them safe to
//! use: a counter that never repeats, a replay window for the peer's counters, and the
//! identity the peer proved. Both PASE and CASE end by installing one.
//!
//! # Directional keys, and the trap in them
//!
//! Session establishment produces **two** keys — `I2RKey` for initiator-to-responder and
//! `R2IKey` for the other way — and which one a node encrypts with depends on which end it
//! was. §4.14.1: "The initiator SHALL use I2RKey to encrypt … and the R2IKey to decrypt …
//! The responder SHALL use R2IKey to encrypt … and the I2RKey to decrypt."
//!
//! Getting that backwards produces a node that cannot talk to anything and can talk
//! perfectly to *itself*, so it survives every test written against another instance of the
//! same bug. [`SecureSession::encrypt_keys`] and [`SecureSession::decrypt_keys`] pick from
//! the recorded [`Role`], so the choice is made once, in one place.

use core::marker::PhantomData;

use heapless::Vec;

use crate::config::{AssertValid, Config};
use crate::crypto::{SymmetricKey, kdf};
use crate::error::{Error, ErrorCode, Result};
use crate::exchange::MrpParams;
use crate::msg::{
    CounterKind, CounterWindow, FabricIndex, MessageCounter, NodeId, NonceSource, SessionId,
    SessionKeys, Verdict,
};
use crate::platform::Instant;

/// `SEKeys_Info` — "SessionKeys" (Core §4.14.1, §4.14.2.7).
pub const SESSION_KEYS_INFO: &[u8] = b"SessionKeys";

/// How a session was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKind {
    /// PASE — from a passcode, during commissioning. Has no fabric and no operational
    /// identity: the peer has proved it knows the passcode and nothing more.
    Pase,
    /// CASE — from operational certificates. The peer's Node ID is proved.
    Case,
}

/// Which end of session establishment this node was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// This node started it, and encrypts with `I2RKey`.
    Initiator,
    /// The peer started it, and this node encrypts with `R2IKey`.
    Responder,
}

/// The three keys session establishment derives (§4.14.1, §4.14.2.7).
///
/// `I2RKey || R2IKey || AttestationChallenge`, in one KDF call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedKeys {
    /// Initiator to responder.
    pub i2r: SessionKeys,
    /// Responder to initiator.
    pub r2i: SessionKeys,
    /// "SHALL only be used as a challenge during device attestation" (§6.2.3) — never as
    /// an encryption key, which is why it is a distinct field and not a third `SessionKeys`.
    pub attestation_challenge: SymmetricKey,
}

impl EstablishedKeys {
    /// The keys this node **encrypts** with, given which end of establishment it was.
    ///
    /// §4.14.2.7 names the two directions `I2RKey` and `R2IKey`, and which one a node uses
    /// depends entirely on its role. Swapping them does not fail loudly — it produces a
    /// message the peer cannot authenticate, which looks like a corrupt link rather than a
    /// key mix-up. Naming the two directions is what keeps the question from being asked at
    /// every call site.
    #[must_use]
    pub const fn sending(&self, role: Role) -> &crate::msg::SessionKeys {
        match role {
            Role::Initiator => &self.i2r,
            Role::Responder => &self.r2i,
        }
    }

    /// The keys this node **decrypts** with — the other direction from [`Self::sending`].
    #[must_use]
    pub const fn receiving(&self, role: Role) -> &crate::msg::SessionKeys {
        match role {
            Role::Initiator => &self.r2i,
            Role::Responder => &self.i2r,
        }
    }

    /// Derives all three from a shared secret and a salt, under `"SessionKeys"`.
    ///
    /// PASE passes an empty salt and `Ke`; CASE passes `IPK || TranscriptHash` and the
    /// ECDH shared secret. Both call the same KDF with the same info string, which is why
    /// this is one function rather than two that could drift apart.
    pub fn derive(shared_secret: &[u8], salt: &[u8]) -> Result<Self> {
        Self::derive_with_info(shared_secret, salt, SESSION_KEYS_INFO)
    }

    /// The same derivation under a different `Info`.
    ///
    /// CASE resumption uses `"SessionResumptionKeys"` (§4.14.2.6.7) — the same three keys,
    /// the same split, a different label, so that a resumed session's keys can never
    /// collide with a fresh one's even if a secret and salt were somehow repeated.
    pub fn derive_with_info(shared_secret: &[u8], salt: &[u8], info: &[u8]) -> Result<Self> {
        const KEY: usize = crate::crypto::SYMMETRIC_KEY_LENGTH_BYTES;
        let mut out = [0u8; 3 * KEY];
        kdf(shared_secret, salt, info, &mut out)?;

        let (Some(i2r), Some(r2i), Some(challenge)) = (
            out.get(..KEY),
            out.get(KEY..2 * KEY),
            out.get(2 * KEY..3 * KEY),
        ) else {
            return Err(Error::new(ErrorCode::Platform));
        };
        let keys = Self {
            i2r: SessionKeys::from_encryption_key(SymmetricKey::from_slice(i2r)?)?,
            r2i: SessionKeys::from_encryption_key(SymmetricKey::from_slice(r2i)?)?,
            attestation_challenge: SymmetricKey::from_slice(challenge)?,
        };

        use zeroize::Zeroize as _;
        out.zeroize();
        Ok(keys)
    }
}

/// One established secure session (§4.13.2).
#[derive(Debug)]
pub struct SecureSession {
    /// The id *this node* chose, and the one peers put in messages to it.
    pub local_session_id: SessionId,
    /// The id the *peer* chose, which this node puts in messages to it.
    pub peer_session_id: SessionId,
    /// PASE or CASE.
    pub kind: SessionKind,
    /// Which end this node was, which decides the key direction.
    pub role: Role,
    /// The peer's operational Node ID. Meaningless for PASE, where nothing has proved an
    /// identity yet, so it is [`NodeId::UNSPECIFIED`] there.
    pub peer_node_id: NodeId,
    /// The CASE Authenticated Tags the peer's operational certificate carried (§6.6.2.1.2).
    ///
    /// Kept on the session because §6.6.6.3 derives the access-control subject from *session
    /// metadata*, never from the message — and the certificate that proved them is gone by the
    /// time an interaction arrives. At most three: §6.5.6 allows a NOC no more.
    pub peer_cats: heapless::Vec<crate::msg::CaseAuthenticatedTag, 3>,
    /// This node's own Node ID on the session's fabric.
    pub local_node_id: NodeId,
    /// The fabric, or [`FabricIndex::NONE`] for PASE.
    pub fabric_index: FabricIndex,
    /// The keys, both directions.
    pub keys: EstablishedKeys,
    /// This node's outgoing counter for this session.
    pub counter: MessageCounter,
    /// The peer's counters already seen (§4.6.5).
    pub window: CounterWindow,
    /// The peer's MRP parameters, from discovery or session establishment.
    pub mrp: MrpParams,
    /// "A timestamp indicating the time at which the last message was sent or received."
    pub session_timestamp: Instant,
    /// "A timestamp indicating the time at which the last message was received." Drives
    /// `PeerActiveMode`.
    pub active_timestamp: Instant,
    /// Where the peer was when it last sent on this session.
    ///
    /// §4.12.4 needs the transport to decide whether MRP runs at all, and a node that starts
    /// an exchange of its own — a subscription report (§8.5.3), a BDX transfer, any command a
    /// controller sends — needs an address to send to. An exchange the *peer* opened learns
    /// this from the datagram that opened it; one this node opens has nothing to learn it
    /// from, so the session remembers.
    ///
    /// `None` until a message has arrived, which for a session established by this node's own
    /// handshake means the handshake's last message.
    pub peer: Option<crate::platform::Peer>,
}

impl SecureSession {
    /// Builds a session from what establishment produced.
    ///
    /// `initial_counter` is a full-width random word from [`Rng`](crate::platform::Rng);
    /// [`MessageCounter::new`] narrows it to the range §4.6.1.1 specifies, so no caller has to
    /// know that a message counter does not start just anywhere.
    #[must_use]
    pub fn new(
        local_session_id: SessionId,
        peer_session_id: SessionId,
        kind: SessionKind,
        role: Role,
        keys: EstablishedKeys,
        initial_counter: u32,
        now: Instant,
    ) -> Self {
        Self {
            local_session_id,
            peer_session_id,
            kind,
            role,
            peer_node_id: NodeId::UNSPECIFIED,
            peer_cats: heapless::Vec::new(),
            local_node_id: NodeId::UNSPECIFIED,
            fabric_index: FabricIndex::NONE,
            keys,
            counter: MessageCounter::new(initial_counter),
            // A secure unicast session's counter never rolls over (§4.6.5.2.1).
            window: CounterWindow::new(CounterKind::SecureUnicast),
            mrp: MrpParams::default(),
            session_timestamp: now,
            active_timestamp: now,
            peer: None,
        }
    }

    /// The keys this node encrypts with (§4.14.1).
    #[must_use]
    pub const fn encrypt_keys(&self) -> &SessionKeys {
        match self.role {
            Role::Initiator => &self.keys.i2r,
            Role::Responder => &self.keys.r2i,
        }
    }

    /// The keys this node decrypts with — the other direction.
    #[must_use]
    pub const fn decrypt_keys(&self) -> &SessionKeys {
        match self.role {
            Role::Initiator => &self.keys.r2i,
            Role::Responder => &self.keys.i2r,
        }
    }

    /// Where the AEAD nonce's Source Node ID comes from, for messages this node *sends*.
    ///
    /// §4.8.1.1: a PASE session always uses the Unspecified Node ID; a CASE session uses
    /// the operational Node ID of whoever protected the message, which for an outgoing
    /// message is this node.
    #[must_use]
    pub const fn send_nonce_source(&self) -> NonceSource {
        match self.kind {
            SessionKind::Pase => NonceSource::Pase,
            SessionKind::Case => NonceSource::Case(self.local_node_id),
        }
    }

    /// Where the nonce's Source Node ID comes from for messages this node *receives* — the
    /// peer protected those, so it is the peer's id.
    #[must_use]
    pub const fn recv_nonce_source(&self) -> NonceSource {
        match self.kind {
            SessionKind::Pase => NonceSource::Pase,
            SessionKind::Case => NonceSource::Case(self.peer_node_id),
        }
    }

    /// Takes the next outgoing message counter, and marks the session used.
    pub fn next_counter(&mut self, now: Instant) -> Result<u32> {
        self.session_timestamp = now;
        self.counter.take()
    }

    /// Judges an incoming counter and, if it is new, marks the session and peer active.
    pub fn accept_counter(&mut self, counter: u32, now: Instant) -> Verdict {
        let verdict = self.window.accept(counter);
        self.session_timestamp = now;
        self.active_timestamp = now;
        verdict
    }

    /// Whether the peer counts as active (§4.13.2, `PeerActiveMode`).
    #[must_use]
    pub fn peer_active(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.active_timestamp) < self.mrp.active_threshold
    }
}

/// The fixed-capacity set of established sessions.
#[derive(Debug)]
pub struct SessionTable<C: Config, const N: usize = 16> {
    sessions: Vec<SecureSession, N>,
    /// The next local session id to hand out.
    next_id: u16,
    _config: PhantomData<C>,
}

impl<C: Config, const N: usize> crate::config::Capacity for SessionTable<C, N> {
    const TOTAL: usize = N;
    /// §11.1.4.4's `CaseSessionsPerFabric`: the sessions this table guarantees each fabric.
    ///
    /// The whole table divided among the fabrics, with no rounding up. §4.14.2.8 sets the
    /// floor at three and [`SessionTable::CHECK`] refuses a smaller table at compile time, so
    /// this never has to be clamped — and clamping is what would turn a table that is too small
    /// into an attribute that lies about it.
    const PER_FABRIC: usize = N / C::FABRICS;
}

impl<C: Config, const N: usize> SessionTable<C, N> {
    /// Compile-time proof that this table can keep §4.14.2.8's promise.
    ///
    /// > A node SHALL support at least 3 CASE session contexts per fabric.
    ///
    /// Referenced by [`SessionTable::new`], so a table too small for the node's `Config` fails
    /// the build at the first place one is constructed.
    pub const CHECK: () = {
        let () = AssertValid::<C>::CHECK;
        assert!(
            N >= 3 * C::FABRICS,
            "SessionTable: Core §4.14.2.8 requires at least 3 CASE sessions per fabric — \
             raise the table's N, or lower Config::FABRICS"
        );
    };

    /// An empty table whose first session id is `first_id`.
    ///
    /// §4.13.2.4 requires a fresh local session id that does not collide with a live one;
    /// starting from a random value rather than 1 keeps a node's ids from being guessable
    /// across a reboot.
    #[must_use]
    pub fn new(first_id: u16) -> Self {
        let () = Self::CHECK;
        Self {
            sessions: Vec::new(),
            next_id: first_id,
            _config: PhantomData,
        }
    }

    /// How many sessions are established.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Allocates a local session id that no live session is using (§4.13.2.4).
    ///
    /// Session id 0 is never returned: with a unicast session type it means the *unsecured*
    /// session, so handing it out would make a secure session indistinguishable from no
    /// session at all.
    pub fn allocate_id(&mut self) -> Result<SessionId> {
        for _ in 0..=u16::MAX {
            let id = SessionId(self.next_id);
            self.next_id = self.next_id.wrapping_add(1);
            if id.0 != 0 && self.find(id).is_none() {
                return Ok(id);
            }
        }
        Err(Error::new(ErrorCode::NoSpace))
    }

    /// Installs a session.
    pub fn insert(&mut self, session: SecureSession) -> Result<()> {
        if self.find(session.local_session_id).is_some() {
            return Err(Error::new(ErrorCode::InvalidState));
        }
        self.sessions
            .push(session)
            .map_err(|_| Error::new(ErrorCode::NoSpace))
    }

    /// The session a message addressed to `local_session_id` belongs to.
    #[must_use]
    pub fn find(&self, local_session_id: SessionId) -> Option<&SecureSession> {
        self.sessions
            .iter()
            .find(|s| s.local_session_id == local_session_id)
    }

    /// The session, mutably.
    pub fn find_mut(&mut self, local_session_id: SessionId) -> Option<&mut SecureSession> {
        self.sessions
            .iter_mut()
            .find(|s| s.local_session_id == local_session_id)
    }

    /// Removes a session, returning whether one was there.
    pub fn remove(&mut self, local_session_id: SessionId) -> bool {
        let Some(i) = self
            .sessions
            .iter()
            .position(|s| s.local_session_id == local_session_id)
        else {
            return false;
        };
        self.sessions.swap_remove(i);
        true
    }

    /// Removes every session on a fabric — what `RemoveFabric` does.
    pub fn remove_fabric(&mut self, fabric: FabricIndex) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|s| s.fabric_index != fabric);
        before.saturating_sub(self.sessions.len())
    }

    /// The session that has gone unused longest, which is what §4.11.1.1 evicts when the
    /// table is full.
    #[must_use]
    pub fn least_recently_used(&self) -> Option<SessionId> {
        self.sessions
            .iter()
            .min_by_key(|s| s.session_timestamp)
            .map(|s| s.local_session_id)
    }

    /// Every session.
    pub fn iter(&self) -> impl Iterator<Item = &SecureSession> {
        self.sessions.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultConfig;

    // The specification's own minimum for five fabrics: §4.14.2.8's three CASE sessions each,
    // plus one for the PASE that commissions the next. `SessionTable::CHECK` refuses less.
    type Table = SessionTable<DefaultConfig>;

    fn keys() -> EstablishedKeys {
        EstablishedKeys::derive(b"shared secret", &[]).expect("derive")
    }

    /// `0` as the randomness, which §4.6.1.1's `Crypto_DRBG(len = 28) + 1` turns into a first
    /// counter of exactly 1 — the smallest a conforming session can have, and the one value
    /// that makes the assertions below readable.
    fn session(id: u16, role: Role) -> SecureSession {
        SecureSession::new(
            SessionId(id),
            SessionId(id.wrapping_add(100)),
            SessionKind::Pase,
            role,
            keys(),
            0,
            Instant::ZERO,
        )
    }

    #[test]
    fn the_three_keys_are_distinct() {
        let k = keys();
        assert_ne!(k.i2r.encryption, k.r2i.encryption);
        assert_ne!(k.i2r.encryption, k.attestation_challenge);
        assert_ne!(k.r2i.encryption, k.attestation_challenge);
        // And the privacy key differs from the encryption key it came from.
        assert_ne!(k.i2r.encryption, k.i2r.privacy);
    }

    #[test]
    fn derivation_is_deterministic_and_salt_sensitive() {
        assert_eq!(
            EstablishedKeys::derive(b"secret", &[]).expect("a"),
            EstablishedKeys::derive(b"secret", &[]).expect("b")
        );
        assert_ne!(
            EstablishedKeys::derive(b"secret", &[]).expect("a"),
            EstablishedKeys::derive(b"secret", b"salt").expect("b")
        );
        assert_ne!(
            EstablishedKeys::derive(b"secret", &[]).expect("a"),
            EstablishedKeys::derive(b"other", &[]).expect("b")
        );
    }

    #[test]
    fn the_two_ends_pick_opposite_keys() {
        // The whole point of recording the role. An initiator encrypts with what a
        // responder decrypts with, and the other way round.
        let initiator = session(1, Role::Initiator);
        let responder = session(1, Role::Responder);

        assert_eq!(initiator.encrypt_keys(), responder.decrypt_keys());
        assert_eq!(initiator.decrypt_keys(), responder.encrypt_keys());
        assert_ne!(initiator.encrypt_keys(), initiator.decrypt_keys());
    }

    #[test]
    fn a_pase_session_uses_the_unspecified_nonce_source() {
        let s = session(1, Role::Initiator);
        assert_eq!(s.send_nonce_source(), NonceSource::Pase);
        assert_eq!(s.recv_nonce_source(), NonceSource::Pase);
    }

    #[test]
    fn a_case_session_uses_the_right_end_for_each_direction() {
        let mut s = session(1, Role::Initiator);
        s.kind = SessionKind::Case;
        s.local_node_id = NodeId(11);
        s.peer_node_id = NodeId(22);
        // Outgoing messages are protected by this node, so the nonce carries its id.
        assert_eq!(s.send_nonce_source(), NonceSource::Case(NodeId(11)));
        // Incoming ones were protected by the peer.
        assert_eq!(s.recv_nonce_source(), NonceSource::Case(NodeId(22)));
    }

    #[test]
    fn session_ids_are_allocated_without_collision_and_never_zero() {
        let mut t = Table::new(0xFFFE);
        let a = t.allocate_id().expect("a");
        let b = t.allocate_id().expect("b");
        let c = t.allocate_id().expect("c");
        assert_eq!(a, SessionId(0xFFFE));
        assert_eq!(b, SessionId(0xFFFF));
        // Zero means the unsecured session, so it is skipped on the way round.
        assert_eq!(c, SessionId(1));
        assert_ne!(a, b);
    }

    #[test]
    fn an_allocated_id_avoids_live_sessions() {
        let mut t = Table::new(5);
        t.insert(session(5, Role::Initiator)).expect("insert");
        assert_eq!(t.allocate_id().expect("id"), SessionId(6));
    }

    #[test]
    fn a_duplicate_local_id_is_refused() {
        let mut t = Table::new(1);
        t.insert(session(7, Role::Initiator)).expect("first");
        assert_eq!(
            t.insert(session(7, Role::Responder)).unwrap_err().code(),
            ErrorCode::InvalidState
        );
    }

    #[test]
    fn a_full_table_is_a_value_not_an_abort() {
        // Driven by the table's own capacity rather than by a number typed here: the table is
        // sized by the specification's minimum for five fabrics, and a test that filled a
        // hard-coded four would stop testing fullness the moment that minimum moved.
        let capacity = <Table as crate::config::Capacity>::TOTAL;
        let mut t = Table::new(1);
        for id in 1..=capacity {
            t.insert(session(id as u16, Role::Initiator)).expect("fits");
        }
        assert_eq!(
            t.insert(session(capacity as u16 + 1, Role::Initiator))
                .unwrap_err()
                .code(),
            ErrorCode::NoSpace
        );
    }

    #[test]
    fn removing_a_fabric_removes_its_sessions() {
        let mut t = Table::new(1);
        for (id, fabric) in [(1u16, 1u8), (2, 1), (3, 2)] {
            let mut s = session(id, Role::Initiator);
            s.fabric_index = FabricIndex(fabric);
            t.insert(s).expect("insert");
        }
        assert_eq!(t.remove_fabric(FabricIndex(1)), 2);
        assert_eq!(t.len(), 1);
        assert!(t.find(SessionId(3)).is_some());
    }

    #[test]
    fn the_least_recently_used_session_is_the_eviction_candidate() {
        let mut t = Table::new(1);
        for (id, when) in [(1u16, 500u64), (2, 100), (3, 900)] {
            let mut s = session(id, Role::Initiator);
            s.session_timestamp = Instant::from_micros(when);
            t.insert(s).expect("insert");
        }
        assert_eq!(t.least_recently_used(), Some(SessionId(2)));
    }

    #[test]
    fn counters_and_timestamps_move_with_traffic() {
        let mut s = session(1, Role::Initiator);
        let t1 = Instant::from_micros(1_000);
        assert_eq!(s.next_counter(t1).expect("counter"), 1);
        assert_eq!(s.session_timestamp, t1);
        assert_eq!(s.active_timestamp, Instant::ZERO, "sending is not activity");

        let t2 = Instant::from_micros(2_000);
        assert_eq!(s.accept_counter(50, t2), Verdict::New);
        assert_eq!(s.active_timestamp, t2, "receiving is");
        assert_eq!(s.accept_counter(50, t2), Verdict::Duplicate);
    }

    #[test]
    fn a_peer_goes_idle_after_the_active_threshold() {
        let mut s = session(1, Role::Initiator);
        s.accept_counter(1, Instant::ZERO);
        assert!(s.peer_active(Instant::ZERO));
        let later = Instant::ZERO.saturating_add(s.mrp.active_threshold);
        assert!(!s.peer_active(later));
    }
}
