//! Passcode-Authenticated Session Establishment (Core §4.14.1).
//!
//! How a commissioner that knows a device's printed passcode gets its first encrypted
//! session with it. Five messages, all on the **unsecured** session — there is no key yet —
//! and all inside one exchange:
//!
//! ```text
//!  commissioner (initiator)                        commissionee (responder)
//!    PBKDFParamRequest   ──────────────────────▶   picks a salt and iteration count
//!                        ◀──────────────────────   PBKDFParamResponse
//!    w0,w1 = PBKDF(passcode)
//!    Pake1 (pA)          ──────────────────────▶
//!                        ◀──────────────────────   Pake2 (pB, cB)
//!    check cB
//!    Pake3 (cA)          ──────────────────────▶   check cA
//!                        ◀──────────────────────   PakeFinished (StatusReport)
//!    I2RKey ‖ R2IKey ‖ AttestationChallenge = KDF(Ke)
//! ```
//!
//! # Sans-I/O
//!
//! Neither state machine touches a socket, a clock or a random generator. Randomness is a
//! parameter — 32 octets for the SPAKE2+ ephemeral, 32 for the protocol random — so a test
//! can replay a failure exactly, and the caller's one [`Rng`](crate::platform::Rng) is the
//! only source of entropy in the process.
//!
//! # What has actually been proved when it finishes
//!
//! That the peer knew the passcode. Nothing else. A PASE session has no fabric, no
//! operational identity, and no access beyond what commissioning needs — which is why
//! [`SessionKind::Pase`](crate::session::SessionKind::Pase) is a distinct variant rather
//! than a flag on a CASE session.

use crate::crypto::{
    Confirmation, HASH_LEN_BYTES, PUBLIC_KEY_SIZE_BYTES, Spake2pProver, Spake2pVerifier,
    Spake2pVerifierData, context as spake_context, ct_eq,
};
use crate::error::{Error, ErrorCode, Result, bail};
use crate::msg::SessionId;
use crate::session::EstablishedKeys;
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use super::SessionParams;
use super::status::{SecureChannelCode, StatusReport};

/// Secure Channel opcodes for the PASE messages (Core Table 18).
pub mod opcode {
    /// `PBKDFParamRequest` — "The request for PBKDF parameters necessary to complete the
    /// PASE protocol."
    pub const PBKDF_PARAM_REQUEST: u8 = 0x20;
    /// `PBKDFParamResponse`.
    pub const PBKDF_PARAM_RESPONSE: u8 = 0x21;
    /// `PASE Pake1` — "The first PAKE message of the PASE protocol."
    pub const PAKE1: u8 = 0x22;
    /// `PASE Pake2`.
    pub const PAKE2: u8 = 0x23;
    /// `PASE Pake3`.
    pub const PAKE3: u8 = 0x24;
    /// `StatusReport`, which carries `PakeFinished`.
    pub const STATUS_REPORT: u8 = 0x40;
}

/// The length of the protocol randoms (§4.14.1.2).
pub const RANDOM_LEN: usize = 32;

/// "A value of 0 for the passcodeID SHALL correspond to the PAKE passcode verifier for the
/// currently-open commissioning window … Non-zero values are reserved for future use."
pub const PASSCODE_ID_COMMISSIONING: u16 = 0;

/// The PBKDF salt and iteration count (`Crypto_PBKDFParameterSet`, §3.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbkdfParameters {
    /// `CRYPTO_PBKDF_ITERATIONS_MIN <= iterations <= CRYPTO_PBKDF_ITERATIONS_MAX`.
    pub iterations: u32,
    /// "A random value per device of at least 16 bytes and at most 32 bytes".
    pub salt: heapless::Vec<u8, { crate::crypto::PBKDF_SALT_MAX_BYTES }>,
}

impl PbkdfParameters {
    /// Builds a parameter set, checking both constraints of §3.9.
    ///
    /// These arrive from a peer and go straight into a PBKDF2 that the device then spends
    /// real time on, so the bounds are enforced here rather than left to the primitive.
    pub fn new(iterations: u32, salt: &[u8]) -> Result<Self> {
        if !(crate::crypto::PBKDF_ITERATIONS_MIN..=crate::crypto::PBKDF_ITERATIONS_MAX)
            .contains(&iterations)
        {
            bail!(InvalidArgument)
        }
        let Ok(salt) = heapless::Vec::from_slice(salt) else {
            bail!(InvalidArgument)
        };
        if salt.len() < crate::crypto::PBKDF_SALT_MIN_BYTES {
            bail!(InvalidArgument)
        }
        Ok(Self { iterations, salt })
    }
}

/// `pbkdfparamreq-struct` (§4.14.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbkdfParamRequest {
    /// `InitiatorRandom` — 32 octets from a DRBG.
    pub initiator_random: [u8; RANDOM_LEN],
    /// The session id the initiator will listen on.
    pub initiator_session_id: SessionId,
    /// Which verifier to use; always [`PASSCODE_ID_COMMISSIONING`] today.
    pub passcode_id: u16,
    /// Whether the initiator already knows the salt and iteration count — from a QR code,
    /// typically. When true, "the responder SHALL NOT return the PBKDF parameters".
    pub has_pbkdf_parameters: bool,
    /// The initiator's MRP parameters, if it sent them.
    pub session_params: Option<SessionParams>,
}

impl PbkdfParamRequest {
    /// Writes the TLV encoding, "with an anonymous tag for the outermost struct".
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = TlvWriter::new(out);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), &self.initiator_random)?;
        w.unsigned(Tag::Context(2), u64::from(self.initiator_session_id.0))?;
        w.unsigned(Tag::Context(3), u64::from(self.passcode_id))?;
        w.bool(Tag::Context(4), self.has_pbkdf_parameters)?;
        if let Some(params) = &self.session_params {
            params.encode(&mut w, Tag::Context(5))?;
        }
        w.end_container()?;
        Ok(w.finish()?.len())
    }

    /// Reads the TLV encoding.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut out = Self {
            initiator_random: [0; RANDOM_LEN],
            initiator_session_id: SessionId(0),
            passcode_id: PASSCODE_ID_COMMISSIONING,
            has_pbkdf_parameters: false,
            session_params: None,
        };
        let mut seen_random = false;
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => {
                    let bytes = element.octets()?;
                    let Ok(arr) = <[u8; RANDOM_LEN]>::try_from(bytes) else {
                        bail!(InvalidArgument)
                    };
                    out.initiator_random = arr;
                    seen_random = true;
                }
                2 => out.initiator_session_id = SessionId(u16_of(element.unsigned()?)?),
                3 => out.passcode_id = u16_of(element.unsigned()?)?,
                4 => out.has_pbkdf_parameters = element.bool()?,
                5 => out.session_params = Some(SessionParams::decode(&mut fields)?),
                // "any context-specific tags not listed in the associated TLV schemas
                // SHALL be reserved for future use, and SHALL be silently ignored".
                _ => fields.skip(&element)?,
            }
        }
        if !seen_random {
            bail!(TlvNotFound)
        }
        Ok(out)
    }
}

/// `pbkdfparamresp-struct` (§4.14.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbkdfParamResponse {
    /// Echoed from the request, which is what binds the two messages together.
    pub initiator_random: [u8; RANDOM_LEN],
    /// `ResponderRandom` — 32 octets from a DRBG.
    pub responder_random: [u8; RANDOM_LEN],
    /// The session id the responder will listen on.
    pub responder_session_id: SessionId,
    /// Absent when the request said the initiator already had them.
    pub pbkdf_parameters: Option<PbkdfParameters>,
    /// The responder's MRP parameters, if it sent them.
    pub session_params: Option<SessionParams>,
}

impl PbkdfParamResponse {
    /// Writes the TLV encoding.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = TlvWriter::new(out);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), &self.initiator_random)?;
        w.octets(Tag::Context(2), &self.responder_random)?;
        w.unsigned(Tag::Context(3), u64::from(self.responder_session_id.0))?;
        // The parameter set is always present; it is *empty* when the initiator already
        // knows the values, which is what "SHALL NOT include the PBKDF parameters" means.
        w.start_structure(Tag::Context(4))?;
        if let Some(params) = &self.pbkdf_parameters {
            w.unsigned(Tag::Context(1), u64::from(params.iterations))?;
            w.octets(Tag::Context(2), &params.salt)?;
        }
        w.end_container()?;
        if let Some(params) = &self.session_params {
            params.encode(&mut w, Tag::Context(5))?;
        }
        w.end_container()?;
        Ok(w.finish()?.len())
    }

    /// Reads the TLV encoding.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut out = Self {
            initiator_random: [0; RANDOM_LEN],
            responder_random: [0; RANDOM_LEN],
            responder_session_id: SessionId(0),
            pbkdf_parameters: None,
            session_params: None,
        };
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => out.initiator_random = random_of(&element)?,
                2 => out.responder_random = random_of(&element)?,
                3 => out.responder_session_id = SessionId(u16_of(element.unsigned()?)?),
                4 => out.pbkdf_parameters = decode_pbkdf_parameters(&mut fields, &element)?,
                5 => out.session_params = Some(SessionParams::decode(&mut fields)?),
                _ => fields.skip(&element)?,
            }
        }
        Ok(out)
    }
}

fn decode_pbkdf_parameters(
    fields: &mut Fields<'_>,
    element: &crate::tlv::Element<'_>,
) -> Result<Option<PbkdfParameters>> {
    if element.value.container() != Some(ContainerKind::Structure) {
        bail!(TlvWrongType)
    }
    let mut iterations = None;
    let mut salt: Option<heapless::Vec<u8, { crate::crypto::PBKDF_SALT_MAX_BYTES }>> = None;
    while let Some((tag, inner)) = fields.next()? {
        match tag {
            1 => iterations = Some(u32_of(inner.unsigned()?)?),
            2 => {
                let Ok(v) = heapless::Vec::from_slice(inner.octets()?) else {
                    bail!(InvalidArgument)
                };
                salt = Some(v);
            }
            _ => fields.skip(&inner)?,
        }
    }
    match (iterations, salt) {
        // Both present: a real parameter set, checked against §3.9's bounds.
        (Some(iterations), Some(salt)) => Ok(Some(PbkdfParameters::new(iterations, &salt)?)),
        // Neither: the empty set the responder sends when the initiator already knows them.
        (None, None) => Ok(None),
        // One without the other is malformed; guessing the missing half would mean
        // running a PBKDF with a value nobody agreed on.
        _ => Err(Error::new(ErrorCode::InvalidArgument)),
    }
}

/// `pake-1-struct` — the initiator's SPAKE2+ share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pake1 {
    /// `pA`.
    pub pa: [u8; PUBLIC_KEY_SIZE_BYTES],
}

/// `pake-2-struct` — the responder's share and its confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pake2 {
    /// `pB`.
    pub pb: [u8; PUBLIC_KEY_SIZE_BYTES],
    /// `cB`.
    pub cb: Confirmation,
}

/// `pake-3-struct` — the initiator's confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pake3 {
    /// `cA`.
    pub ca: Confirmation,
}

impl Pake1 {
    /// Writes the TLV encoding.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = TlvWriter::new(out);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), &self.pa)?;
        w.end_container()?;
        Ok(w.finish()?.len())
    }

    /// Reads the TLV encoding.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut pa = None;
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => pa = Some(point_of(&element)?),
                _ => fields.skip(&element)?,
            }
        }
        Ok(Self {
            pa: pa.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

impl Pake2 {
    /// Writes the TLV encoding.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = TlvWriter::new(out);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), &self.pb)?;
        w.octets(Tag::Context(2), &self.cb)?;
        w.end_container()?;
        Ok(w.finish()?.len())
    }

    /// Reads the TLV encoding.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let (mut pb, mut cb) = (None, None);
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => pb = Some(point_of(&element)?),
                2 => cb = Some(confirmation_of(&element)?),
                _ => fields.skip(&element)?,
            }
        }
        Ok(Self {
            pb: pb.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            cb: cb.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

impl Pake3 {
    /// Writes the TLV encoding.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = TlvWriter::new(out);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), &self.ca)?;
        w.end_container()?;
        Ok(w.finish()?.len())
    }

    /// Reads the TLV encoding.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut ca = None;
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => ca = Some(confirmation_of(&element)?),
                _ => fields.skip(&element)?,
            }
        }
        Ok(Self {
            ca: ca.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

// --- The state machines -------------------------------------------------------------

/// What the commissionee needs before it can answer at all.
#[derive(Debug, Clone)]
pub struct ResponderConfig {
    /// The stored `(w0, L)` for the open commissioning window.
    pub verifier: Spake2pVerifierData,
    /// The salt and iteration count that verifier was computed with.
    pub parameters: PbkdfParameters,
    /// This node's MRP parameters, to advertise.
    pub session_params: Option<SessionParams>,
}

/// The commissionee's side of PASE.
#[derive(Debug)]
pub struct PaseResponder {
    config: ResponderConfig,
    local_session_id: SessionId,
    peer_session_id: SessionId,
    /// The exact octets of the two parameter messages, which the transcript hashes.
    request_bytes: heapless::Vec<u8, 256>,
    response_bytes: heapless::Vec<u8, 256>,
    verifier: Option<Spake2pVerifier>,
    expected_ca: Option<Confirmation>,
    keys: Option<EstablishedKeys>,
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingRequest,
    AwaitingPake1,
    AwaitingPake3,
    Established,
    Failed,
}

impl PaseResponder {
    /// A commissionee ready to receive a `PBKDFParamRequest`.
    ///
    /// `local_session_id` must not collide with any live session
    /// ([`SessionTable::allocate_id`](crate::session::SessionTable::allocate_id)).
    #[must_use]
    pub fn new(config: ResponderConfig, local_session_id: SessionId) -> Self {
        Self {
            config,
            local_session_id,
            peer_session_id: SessionId(0),
            request_bytes: heapless::Vec::new(),
            response_bytes: heapless::Vec::new(),
            verifier: None,
            expected_ca: None,
            keys: None,
            state: State::AwaitingRequest,
        }
    }

    /// The session id this node will listen on.
    #[must_use]
    pub const fn local_session_id(&self) -> SessionId {
        self.local_session_id
    }

    /// The session id the peer will listen on, once it has said.
    #[must_use]
    pub const fn peer_session_id(&self) -> SessionId {
        self.peer_session_id
    }

    /// Handles `PBKDFParamRequest`, writing `PBKDFParamResponse` into `out`.
    ///
    /// `responder_random` must be 32 octets from a cryptographically secure generator.
    pub fn on_pbkdf_param_request(
        &mut self,
        payload: &[u8],
        responder_random: &[u8; RANDOM_LEN],
        out: &mut [u8],
    ) -> Result<usize> {
        if self.state != State::AwaitingRequest {
            self.state = State::Failed;
            bail!(InvalidState)
        }
        let request = PbkdfParamRequest::decode(payload)?;

        // §4.14.1.2: "Verify passcodeID is set to 0."
        if request.passcode_id != PASSCODE_ID_COMMISSIONING {
            self.state = State::Failed;
            bail!(InvalidArgument)
        }
        self.peer_session_id = request.initiator_session_id;

        let response = PbkdfParamResponse {
            initiator_random: request.initiator_random,
            responder_random: *responder_random,
            responder_session_id: self.local_session_id,
            // "If hasPBKDFParameters is True the responder SHALL NOT include the PBKDF
            // parameters" — the initiator read them off the QR code.
            pbkdf_parameters: if request.has_pbkdf_parameters {
                None
            } else {
                Some(self.config.parameters.clone())
            },
            session_params: self.config.session_params,
        };
        let n = response.encode(out)?;

        // The transcript hashes these two messages verbatim, so they are kept as octets
        // rather than re-encoded later — a re-encoding that differed by one byte would
        // produce a context the peer does not share, and the failure would look like a
        // wrong passcode.
        self.request_bytes = copy_of(payload)?;
        self.response_bytes = copy_of(out.get(..n).unwrap_or(&[]))?;
        self.state = State::AwaitingPake1;
        Ok(n)
    }

    /// Handles `Pake1`, writing `Pake2` into `out`.
    ///
    /// `responder_ephemeral` must be 32 octets from a cryptographically secure generator —
    /// the SPAKE2+ scalar `y`.
    pub fn on_pake1(
        &mut self,
        payload: &[u8],
        responder_ephemeral: &[u8; 32],
        out: &mut [u8],
    ) -> Result<usize> {
        if self.state != State::AwaitingPake1 {
            self.state = State::Failed;
            bail!(InvalidState)
        }
        let pake1 = Pake1::decode(payload)?;
        let verifier = Spake2pVerifier::new(&self.config.verifier, responder_ephemeral)?;

        let context = spake_context(&self.request_bytes, &self.response_bytes);
        let (ca, cb, ke) = verifier.finish(&pake1.pa, &context)?;

        let n = Pake2 {
            pb: *verifier.pb(),
            cb,
        }
        .encode(out)?;

        // The keys exist now, but nothing may use them until cA is checked: an attacker
        // who guessed wrong would otherwise get a session.
        self.keys = Some(EstablishedKeys::derive(ke.as_bytes(), &[])?);
        self.expected_ca = Some(ca);
        self.verifier = Some(verifier);
        self.state = State::AwaitingPake3;
        Ok(n)
    }

    /// Handles `Pake3`, writing `PakeFinished` into `out` and returning the session keys.
    ///
    /// A `cA` that does not match is [`ErrorCode::IntegrityCheckFailed`] and leaves the
    /// responder permanently failed — §4.14.1.2 says to "perform no further processing",
    /// and letting the peer try again on the same exchange would turn one guess into many.
    pub fn on_pake3(&mut self, payload: &[u8], out: &mut [u8]) -> Result<(usize, EstablishedKeys)> {
        if self.state != State::AwaitingPake3 {
            self.state = State::Failed;
            bail!(InvalidState)
        }
        let pake3 = Pake3::decode(payload)?;
        let Some(expected) = self.expected_ca else {
            self.state = State::Failed;
            bail!(InvalidState)
        };
        if !ct_eq(&pake3.ca, &expected) {
            self.state = State::Failed;
            bail!(IntegrityCheckFailed)
        }
        let Some(keys) = self.keys.clone() else {
            self.state = State::Failed;
            bail!(InvalidState)
        };
        let n = StatusReport::secure_channel(SecureChannelCode::SessionEstablishmentSuccess)
            .encode(out)?;
        self.state = State::Established;
        Ok((n, keys))
    }

    /// Whether the exchange completed successfully.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, State::Established)
    }

    /// Whether the exchange failed and must be abandoned.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self.state, State::Failed)
    }
}

/// The commissioner's side of PASE.
#[derive(Debug)]
pub struct PaseInitiator {
    passcode: u32,
    local_session_id: SessionId,
    peer_session_id: SessionId,
    /// Parameters known up front, from a QR code.
    known_parameters: Option<PbkdfParameters>,
    session_params: Option<SessionParams>,
    /// Kept so the response's echo can be checked against it. Recovering it by re-parsing
    /// the request would work, but tying the check to a byte offset in an encoding is the
    /// sort of thing that survives until the encoding changes.
    initiator_random: [u8; RANDOM_LEN],
    request_bytes: heapless::Vec<u8, 256>,
    response_bytes: heapless::Vec<u8, 256>,
    prover: Option<Spake2pProver>,
    expected_cb: Option<Confirmation>,
    ca: Option<Confirmation>,
    keys: Option<EstablishedKeys>,
    state: State,
}

impl PaseInitiator {
    /// A commissioner that knows `passcode`.
    ///
    /// `known_parameters` is `Some` when the salt and iteration count came from the
    /// onboarding payload, which saves a round trip's worth of information but not a round
    /// trip: the request is sent either way.
    #[must_use]
    pub fn new(
        passcode: u32,
        local_session_id: SessionId,
        known_parameters: Option<PbkdfParameters>,
        session_params: Option<SessionParams>,
    ) -> Self {
        Self {
            passcode,
            local_session_id,
            peer_session_id: SessionId(0),
            known_parameters,
            session_params,
            initiator_random: [0; RANDOM_LEN],
            request_bytes: heapless::Vec::new(),
            response_bytes: heapless::Vec::new(),
            prover: None,
            expected_cb: None,
            ca: None,
            keys: None,
            state: State::AwaitingRequest,
        }
    }

    /// The session id this node will listen on.
    #[must_use]
    pub const fn local_session_id(&self) -> SessionId {
        self.local_session_id
    }

    /// The session id the peer will listen on, once it has said.
    #[must_use]
    pub const fn peer_session_id(&self) -> SessionId {
        self.peer_session_id
    }

    /// Writes the opening `PBKDFParamRequest`.
    ///
    /// `initiator_random` must be 32 octets from a cryptographically secure generator.
    pub fn start(&mut self, initiator_random: &[u8; RANDOM_LEN], out: &mut [u8]) -> Result<usize> {
        if self.state != State::AwaitingRequest {
            bail!(InvalidState)
        }
        let request = PbkdfParamRequest {
            initiator_random: *initiator_random,
            initiator_session_id: self.local_session_id,
            passcode_id: PASSCODE_ID_COMMISSIONING,
            has_pbkdf_parameters: self.known_parameters.is_some(),
            session_params: self.session_params,
        };
        let n = request.encode(out)?;
        self.initiator_random = *initiator_random;
        self.request_bytes = copy_of(out.get(..n).unwrap_or(&[]))?;
        self.state = State::AwaitingPake1;
        Ok(n)
    }

    /// Handles `PBKDFParamResponse`, writing `Pake1` into `out`.
    ///
    /// `initiator_ephemeral` must be 32 octets from a cryptographically secure generator —
    /// the SPAKE2+ scalar `x`. This is the call that runs PBKDF2, which on a constrained
    /// commissioner is the most expensive thing in the exchange.
    pub fn on_pbkdf_param_response(
        &mut self,
        payload: &[u8],
        initiator_ephemeral: &[u8; 32],
        out: &mut [u8],
    ) -> Result<usize> {
        if self.state != State::AwaitingPake1 {
            self.state = State::Failed;
            bail!(InvalidState)
        }
        let response = PbkdfParamResponse::decode(payload)?;

        // The echoed random binds this response to this request. Without the check, an
        // off-path attacker's response would be accepted into the transcript.
        if !ct_eq(&response.initiator_random, &self.initiator_random) {
            self.state = State::Failed;
            bail!(InvalidArgument)
        }
        self.peer_session_id = response.responder_session_id;

        // Whichever side supplied them, exactly one set must be available.
        let parameters = match (&self.known_parameters, &response.pbkdf_parameters) {
            (Some(known), None) => known.clone(),
            (None, Some(sent)) => sent.clone(),
            (Some(known), Some(_)) => {
                // The responder sent parameters that were not asked for. Using the known
                // ones keeps the exchange going and keeps this node's own QR code
                // authoritative.
                known.clone()
            }
            (None, None) => {
                self.state = State::Failed;
                bail!(InvalidArgument)
            }
        };

        let prover = Spake2pProver::new(
            self.passcode,
            &parameters.salt,
            parameters.iterations,
            initiator_ephemeral,
        )?;
        let n = Pake1 { pa: *prover.pa() }.encode(out)?;

        self.response_bytes = copy_of(payload)?;
        self.prover = Some(prover);
        self.state = State::AwaitingPake3;
        Ok(n)
    }

    /// Handles `Pake2`, checking `cB` and writing `Pake3` into `out`.
    ///
    /// A `cB` that does not match means the responder did not know the passcode — or is
    /// not the device the passcode belongs to. §4.14.1.2 says to stop, and this does.
    pub fn on_pake2(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        if self.state != State::AwaitingPake3 {
            self.state = State::Failed;
            bail!(InvalidState)
        }
        let pake2 = Pake2::decode(payload)?;
        let Some(prover) = &self.prover else {
            self.state = State::Failed;
            bail!(InvalidState)
        };

        let context = spake_context(&self.request_bytes, &self.response_bytes);
        let (ca, cb, ke) = prover.finish(&pake2.pb, &context)?;

        if !ct_eq(&pake2.cb, &cb) {
            self.state = State::Failed;
            bail!(IntegrityCheckFailed)
        }

        let n = Pake3 { ca }.encode(out)?;
        self.keys = Some(EstablishedKeys::derive(ke.as_bytes(), &[])?);
        self.expected_cb = Some(cb);
        self.ca = Some(ca);
        self.state = State::Established;
        Ok(n)
    }

    /// Handles `PakeFinished`, returning the session keys.
    ///
    /// §4.14.1.2: "The initiator SHALL NOT send any encrypted application data until it
    /// receives PakeFinished from the responder" — which is why the keys are handed over
    /// here and not at [`PaseInitiator::on_pake2`].
    pub fn on_pake_finished(&mut self, payload: &[u8]) -> Result<EstablishedKeys> {
        if self.state != State::Established {
            bail!(InvalidState)
        }
        let report = StatusReport::decode(payload)?;
        if !report.is_success()
            || report.secure_channel_code() != Some(SecureChannelCode::SessionEstablishmentSuccess)
        {
            self.state = State::Failed;
            bail!(InvalidState)
        }
        self.keys.clone().ok_or(Error::new(ErrorCode::InvalidState))
    }

    /// Whether `Pake2` has been accepted.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, State::Established)
    }

    /// Whether the exchange failed.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self.state, State::Failed)
    }
}

// --- TLV helpers ----------------------------------------------------------------------

/// A cursor over the members of an anonymous outer structure.
///
/// Every PASE message is "the TLV-encoded … struct with an anonymous tag for the outermost
/// struct", so all five decoders want the same thing: iterate the context-tagged members,
/// skip the ones this revision does not know.
pub(crate) struct Fields<'a> {
    reader: TlvReader<'a>,
    depth: usize,
}

impl<'a> Fields<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Result<Self> {
        let mut reader = TlvReader::new(buf);
        let Some(first) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if first.value.container() != Some(ContainerKind::Structure) {
            bail!(TlvWrongType)
        }
        Ok(Self { reader, depth: 1 })
    }

    /// The next member, or `None` at the end of the structure.
    pub(crate) fn next(&mut self) -> Result<Option<(u8, crate::tlv::Element<'a>)>> {
        let before = self.reader.depth();
        let Some(element) = self.reader.next_element()? else {
            return Ok(None);
        };
        if matches!(element.value, Value::EndOfContainer) {
            if self.reader.depth() < self.depth {
                return Ok(None);
            }
            return self.next();
        }
        let _ = before;
        let Some(tag) = element.tag.context() else {
            // A member of a Matter structure always has a context tag; the reader has
            // already refused an anonymous one.
            bail!(TlvInvalidTag)
        };
        Ok(Some((tag, element)))
    }

    /// Skips a member's value, including a whole container.
    pub(crate) fn skip(&mut self, element: &crate::tlv::Element<'a>) -> Result<()> {
        self.reader.skip_value(element)
    }
}

fn copy_of<const N: usize>(bytes: &[u8]) -> Result<heapless::Vec<u8, N>> {
    heapless::Vec::from_slice(bytes).map_err(|_| Error::new(ErrorCode::NoSpace))
}

fn u16_of(value: u64) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

fn u32_of(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

fn random_of(element: &crate::tlv::Element<'_>) -> Result<[u8; RANDOM_LEN]> {
    <[u8; RANDOM_LEN]>::try_from(element.octets()?)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument))
}

fn point_of(element: &crate::tlv::Element<'_>) -> Result<[u8; PUBLIC_KEY_SIZE_BYTES]> {
    <[u8; PUBLIC_KEY_SIZE_BYTES]>::try_from(element.octets()?)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument))
}

fn confirmation_of(element: &crate::tlv::Element<'_>) -> Result<Confirmation> {
    <[u8; HASH_LEN_BYTES]>::try_from(element.octets()?)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters() -> PbkdfParameters {
        PbkdfParameters::new(1_000, b"SPAKE2P Key Salt").expect("parameters")
    }

    fn round_trip<T, E, D>(value: &T, encode: E, decode: D)
    where
        T: core::fmt::Debug + PartialEq,
        E: Fn(&T, &mut [u8]) -> Result<usize>,
        D: Fn(&[u8]) -> Result<T>,
    {
        let mut buf = [0u8; 512];
        let n = encode(value, &mut buf).expect("encode");
        let decoded = decode(&buf[..n]).expect("decode");
        assert_eq!(&decoded, value);
        // And every truncation of it must be an error rather than a panic.
        for cut in 0..n {
            let _ = decode(&buf[..cut]);
        }
    }

    #[test]
    fn pbkdf_param_request_round_trips() {
        round_trip(
            &PbkdfParamRequest {
                initiator_random: [0xAB; RANDOM_LEN],
                initiator_session_id: SessionId(0x1234),
                passcode_id: PASSCODE_ID_COMMISSIONING,
                has_pbkdf_parameters: true,
                session_params: None,
            },
            |v, b| v.encode(b),
            PbkdfParamRequest::decode,
        );
        round_trip(
            &PbkdfParamRequest {
                initiator_random: [0x01; RANDOM_LEN],
                initiator_session_id: SessionId(1),
                passcode_id: PASSCODE_ID_COMMISSIONING,
                has_pbkdf_parameters: false,
                session_params: Some(SessionParams {
                    idle_interval_ms: Some(500),
                    active_interval_ms: Some(300),
                    active_threshold_ms: Some(4_000),
                }),
            },
            |v, b| v.encode(b),
            PbkdfParamRequest::decode,
        );
    }

    #[test]
    fn pbkdf_param_response_round_trips_with_and_without_parameters() {
        // With: the manual-pairing-code path, where the device must tell the commissioner.
        round_trip(
            &PbkdfParamResponse {
                initiator_random: [0x11; RANDOM_LEN],
                responder_random: [0x22; RANDOM_LEN],
                responder_session_id: SessionId(7),
                pbkdf_parameters: Some(parameters()),
                session_params: None,
            },
            |v, b| v.encode(b),
            PbkdfParamResponse::decode,
        );
        // Without: the QR-code path, where §4.14.1.2 says the responder "SHALL NOT return
        // the PBKDF parameters" — an *empty* parameter set, not an absent field.
        round_trip(
            &PbkdfParamResponse {
                initiator_random: [0x11; RANDOM_LEN],
                responder_random: [0x22; RANDOM_LEN],
                responder_session_id: SessionId(7),
                pbkdf_parameters: None,
                session_params: None,
            },
            |v, b| v.encode(b),
            PbkdfParamResponse::decode,
        );
    }

    #[test]
    fn the_pake_messages_round_trip() {
        round_trip(
            &Pake1 {
                pa: [0x04; PUBLIC_KEY_SIZE_BYTES],
            },
            |v, b| v.encode(b),
            Pake1::decode,
        );
        round_trip(
            &Pake2 {
                pb: [0x04; PUBLIC_KEY_SIZE_BYTES],
                cb: [0x77; HASH_LEN_BYTES],
            },
            |v, b| v.encode(b),
            Pake2::decode,
        );
        round_trip(
            &Pake3 {
                ca: [0x88; HASH_LEN_BYTES],
            },
            |v, b| v.encode(b),
            Pake3::decode,
        );
    }

    #[test]
    fn unknown_context_tags_are_skipped() {
        // §4.14.1.2: "any context-specific tags not listed in the associated TLV schemas
        // SHALL be reserved for future use, and SHALL be silently ignored if seen by a
        // recipient which cannot understand them." A node that refused them could not
        // talk to a newer peer.
        let mut buf = [0u8; 256];
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).expect("open");
        w.octets(Tag::Context(1), &[0xAB; RANDOM_LEN])
            .expect("random");
        w.unsigned(Tag::Context(2), 9).expect("session");
        w.unsigned(Tag::Context(3), 0).expect("passcode id");
        w.bool(Tag::Context(4), true).expect("flag");
        // A future scalar…
        w.unsigned(Tag::Context(99), 1234).expect("unknown scalar");
        // …and a future container, which has to be skipped whole.
        w.start_structure(Tag::Context(100)).expect("open");
        w.unsigned(Tag::Context(1), 1).expect("inner");
        w.start_array(Tag::Context(2)).expect("array");
        w.unsigned(Tag::Anonymous, 2).expect("item");
        w.end_container().expect("close array");
        w.end_container().expect("close struct");
        w.end_container().expect("close");
        let n = w.finish().expect("finish").len();

        let decoded = PbkdfParamRequest::decode(&buf[..n]).expect("decode");
        assert_eq!(decoded.initiator_session_id, SessionId(9));
        assert!(decoded.has_pbkdf_parameters);
    }

    #[test]
    fn a_missing_mandatory_field_is_refused() {
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).expect("open");
        w.unsigned(Tag::Context(2), 1).expect("session");
        w.end_container().expect("close");
        let n = w.finish().expect("finish").len();
        assert_eq!(
            PbkdfParamRequest::decode(&buf[..n]).unwrap_err().code(),
            ErrorCode::TlvNotFound
        );
    }

    #[test]
    fn pbkdf_parameters_enforce_section_3_9() {
        // Below the minimum iteration count, above the maximum, and a salt outside
        // 16..=32 octets are all things a peer can send and a device must refuse.
        assert!(PbkdfParameters::new(999, b"0123456789abcdef").is_err());
        assert!(PbkdfParameters::new(100_001, b"0123456789abcdef").is_err());
        assert!(PbkdfParameters::new(1_000, b"tooshort").is_err());
        assert!(PbkdfParameters::new(1_000, &[0u8; 33]).is_err());
        assert!(PbkdfParameters::new(1_000, &[0u8; 16]).is_ok());
        assert!(PbkdfParameters::new(100_000, &[0u8; 32]).is_ok());
    }

    #[test]
    fn half_a_parameter_set_is_refused() {
        // Iterations without a salt, or the other way round: guessing the missing half
        // would mean running a PBKDF with a value nobody agreed on.
        for (iterations, salt) in [(Some(1_000u32), None), (None, Some(&[0u8; 16]))] {
            let mut buf = [0u8; 256];
            let mut w = TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).expect("open");
            w.octets(Tag::Context(1), &[0x11; RANDOM_LEN]).expect("r1");
            w.octets(Tag::Context(2), &[0x22; RANDOM_LEN]).expect("r2");
            w.unsigned(Tag::Context(3), 1).expect("session");
            w.start_structure(Tag::Context(4)).expect("params");
            if let Some(i) = iterations {
                w.unsigned(Tag::Context(1), u64::from(i)).expect("iters");
            }
            if let Some(s) = salt {
                w.octets(Tag::Context(2), s).expect("salt");
            }
            w.end_container().expect("close params");
            w.end_container().expect("close");
            let n = w.finish().expect("finish").len();
            assert!(
                PbkdfParamResponse::decode(&buf[..n]).is_err(),
                "iterations={iterations:?} salt={:?}",
                salt.map(|s| s.len())
            );
        }
    }

    #[test]
    fn a_nonzero_passcode_id_is_refused() {
        // §4.14.1.2: "Verify passcodeID is set to 0."
        let verifier = Spake2pVerifierData::from_passcode(20_202_021, b"SPAKE2P Key Salt", 1_000)
            .expect("verifier");
        let mut device = PaseResponder::new(
            ResponderConfig {
                verifier,
                parameters: parameters(),
                session_params: None,
            },
            SessionId(1),
        );

        let mut buf = [0u8; 256];
        let n = PbkdfParamRequest {
            initiator_random: [0; RANDOM_LEN],
            initiator_session_id: SessionId(2),
            passcode_id: 1,
            has_pbkdf_parameters: true,
            session_params: None,
        }
        .encode(&mut buf)
        .expect("encode");

        let mut out = [0u8; 256];
        assert_eq!(
            device
                .on_pbkdf_param_request(&buf[..n], &[0; RANDOM_LEN], &mut out)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );
        assert!(device.is_failed());
    }

    #[test]
    fn messages_must_arrive_in_order() {
        // A peer that sends Pake1 before the parameters have been agreed has nothing to
        // build a transcript from.
        let verifier = Spake2pVerifierData::from_passcode(20_202_021, b"SPAKE2P Key Salt", 1_000)
            .expect("verifier");
        let mut device = PaseResponder::new(
            ResponderConfig {
                verifier,
                parameters: parameters(),
                session_params: None,
            },
            SessionId(1),
        );
        let mut out = [0u8; 256];
        let mut pake1 = [0u8; 256];
        let n = Pake1 {
            pa: [0x04; PUBLIC_KEY_SIZE_BYTES],
        }
        .encode(&mut pake1)
        .expect("encode");
        assert_eq!(
            device
                .on_pake1(&pake1[..n], &[1; 32], &mut out)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidState
        );
    }

    #[test]
    fn session_params_clamp_what_a_peer_sends() {
        // These decide how long this node waits before retransmitting, and they come from
        // a stranger.
        let hostile = SessionParams {
            idle_interval_ms: Some(u32::MAX),
            active_interval_ms: Some(u32::MAX),
            active_threshold_ms: Some(u16::MAX),
        };
        let mrp = hostile.to_mrp();
        assert_eq!(mrp.idle_interval.as_millis(), 3_600_000);
        assert_eq!(mrp.active_interval.as_millis(), 3_600_000);
        assert_eq!(mrp.active_threshold.as_millis(), 65_535);
    }

    #[test]
    fn absent_session_params_take_the_defaults() {
        let mrp = SessionParams::default().to_mrp();
        assert_eq!(mrp, crate::exchange::MrpParams::default());
    }
}
