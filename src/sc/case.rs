//! CASE — Certificate Authenticated Session Establishment (Core §4.14.2).
//!
//! PASE turns a printed passcode into one session, once, during commissioning. CASE turns
//! operational certificates into every session after that, and is the protocol a Matter
//! node spends its life speaking.
//!
//! # The shape of it
//!
//! CASE "mirrors the \[SIGMA\] protocol and uses the Identity Protection Key (IPK) to provide
//! better identity protection". Three messages, two round trips:
//!
//! ```text
//! initiator                                                    responder
//!   Sigma1  ──── random, session id, destinationId, ephemeral ──▶
//!          ◀──── random, session id, ephemeral, encrypted2 ──── Sigma2
//!   Sigma3  ──── encrypted3 ─────────────────────────────────▶
//!          ◀──── StatusReport(SESSION_ESTABLISHMENT_SUCCESS) ──
//! ```
//!
//! Each peer proves it holds its NOC's private key by *signing the two ephemeral public
//! keys together with its own certificate chain*. Signing the ephemerals is what binds the
//! identity to this particular exchange; signing them in that order — own key first — is
//! what stops a signature from Sigma2 being replayed as a Sigma3.
//!
//! The certificates themselves travel encrypted, under a key derived from the ECDH secret
//! and the IPK. That is the identity protection: an observer who does not hold the fabric's
//! IPK learns neither peer's identity, and cannot even tell which fabric they are on —
//! which is also what [`destination_identifier`](crate::fabric::destination_identifier) is
//! for.
//!
//! # Three keys, all from one secret
//!
//! `SharedSecret` is the ECDH of the two ephemerals. Everything else is an HKDF of it, and
//! what distinguishes the derivations is the *salt*, which always contains the running
//! transcript hash:
//!
//! | Key | Salt | Encrypts |
//! |---|---|---|
//! | S2K | `IPK ‖ responderRandom ‖ responderEphPubKey ‖ Hash(Msg1)` | Sigma2's `encrypted2` |
//! | S3K | `IPK ‖ Hash(Msg1 ‖ Msg2)` | Sigma3's `encrypted3` |
//! | session keys | `IPK ‖ Hash(Msg1 ‖ Msg2 ‖ Msg3)` | everything afterwards |
//!
//! Binding each key to the hash of everything said so far is what makes the exchange
//! tamper-evident: change any byte of any earlier message and the next key is different, so
//! the next decryption fails. There is no separate transcript MAC because the key *is* the
//! MAC.
//!
//! # Resumption
//!
//! A peer that remembers a previous session's `SharedSecret` can skip both signatures —
//! "dramatically reducing the computation required as well as reducing the number of
//! messages exchanged", which on a battery-powered device is the difference between a
//! session that costs milliseconds and one that costs hundreds. Resumption is
//! [`ResumptionState`] plus the `Sigma2_Resume` path.
//!
//! # What this module is not
//!
//! It does not own the network, a clock or a key: a [`CaseInitiator`] and a
//! [`CaseResponder`] consume and produce message bytes, and take randomness and signatures
//! as parameters. `tests/case_over_sim.rs` drives a full exchange between two of them over
//! the simulated network.

use crate::cert::{CERT_TLV_MAX, MatterCertificate, VerifiedIdentity, verify_chain};
use crate::crypto::{
    AEAD_MIC_LENGTH_BYTES, AEAD_NONCE_LENGTH_BYTES, GROUP_SIZE_BYTES, HASH_LEN_BYTES, Hasher,
    KeyHandle, KeyPurpose, KeyStore, PUBLIC_KEY_SIZE_BYTES, PublicKey, SIGNATURE_LEN_BYTES, Secret,
    Signature, SymmetricKey, aead_decrypt_in_place, aead_encrypt_in_place, ct_eq, kdf_key, verify,
};
use crate::error::{Error, ErrorCode, Result, bail};
use crate::fabric::{Fabric, INITIATOR_RANDOM_LEN};
use crate::msg::SessionId;
use crate::sc::status::{SecureChannelCode, StatusReport};
use crate::sc::{Fields, SessionParams};
use crate::tlv::{Tag, TlvWriter, set_once};

/// The Secure Channel opcodes CASE uses (§4.11, Table 18).
pub mod opcode {
    /// `CASE Sigma1` — "The first message of the CASE protocol."
    pub const SIGMA1: u8 = 0x30;
    /// `CASE Sigma2`.
    pub const SIGMA2: u8 = 0x31;
    /// `CASE Sigma3`.
    pub const SIGMA3: u8 = 0x32;
    /// `CASE Sigma2_Resume` — "The second resumption message of the CASE protocol."
    pub const SIGMA2_RESUME: u8 = 0x33;
    /// `StatusReport`, which carries `SigmaFinished`.
    pub const STATUS_REPORT: u8 = 0x40;
}

/// The length of `initiatorRandom` and `responderRandom` (§4.14.2.3).
pub const RANDOM_LEN: usize = INITIATOR_RANDOM_LEN;

/// The length of a resumption ID — `Crypto_DRBG(len = 16 * 8)`.
pub const RESUMPTION_ID_LEN: usize = 16;

// --- The `Info` strings of §4.14.2.6, spelled out as the specification spells them --------

/// `S2K_Info` — "Sigma2".
pub const S2K_INFO: &[u8] = b"Sigma2";
/// `S3K_Info` — "Sigma3".
pub const S3K_INFO: &[u8] = b"Sigma3";
/// `S1RK_Info` — "Sigma1_Resume".
pub const S1RK_INFO: &[u8] = b"Sigma1_Resume";
/// `S2RK_Info` — "Sigma2_Resume".
pub const S2RK_INFO: &[u8] = b"Sigma2_Resume";
/// `SEKeys_Info` — "SessionKeys", shared with PASE (§4.14.1.2).
pub const SESSION_KEYS_INFO: &[u8] = crate::session::SESSION_KEYS_INFO;
/// `RSEKeys_Info` — "SessionResumptionKeys".
pub const RESUMPTION_SESSION_KEYS_INFO: &[u8] = b"SessionResumptionKeys";

// --- The AEAD nonces of §4.14.2, which are constants rather than counters ------------------

/// `TBEData2_Nonce` — "NCASE_Sigma2N".
pub const SIGMA2_NONCE: [u8; AEAD_NONCE_LENGTH_BYTES] = *b"NCASE_Sigma2N";
/// `TBEData3_Nonce` — "NCASE_Sigma3N".
pub const SIGMA3_NONCE: [u8; AEAD_NONCE_LENGTH_BYTES] = *b"NCASE_Sigma3N";
/// `Resume1MIC_Nonce` — "NCASE_SigmaS1".
pub const RESUME1_NONCE: [u8; AEAD_NONCE_LENGTH_BYTES] = *b"NCASE_SigmaS1";
/// `Resume2MIC_Nonce` — "NCASE_SigmaS2".
pub const RESUME2_NONCE: [u8; AEAD_NONCE_LENGTH_BYTES] = *b"NCASE_SigmaS2";

/// TLV overhead for an octet string whose length needs two octets — a control octet, a context
/// tag, and the length. A certificate at §6.1.3's 400-octet cap is exactly such a string, and
/// the difference between this and the three-octet short form is what a slack-based estimate
/// gets wrong.
const LONG_STRING_HEADER: usize = 4;
/// The same for a string short enough to carry a one-octet length: a signature, a resumption
/// id, a public key.
const SHORT_STRING_HEADER: usize = 3;
/// A structure costs its opening control octet and its end-of-container octet.
const STRUCTURE_OVERHEAD: usize = 2;

/// The largest `sigma-2-tbedata` **before** encryption: two certificates at §6.1.3's cap, the
/// signature over the corresponding `tbsdata`, and the resumption id.
///
/// Written out term by term rather than as a sum plus slack, because the slack was wrong: the
/// previous estimate for `encrypted3` was five octets short of what two maximum-size
/// certificates actually need, which is a `BufferTooSmall` in the middle of a handshake and
/// only against a peer whose CA issues large certificates.
const MAX_TBEDATA2: usize = STRUCTURE_OVERHEAD
    + (2 * (LONG_STRING_HEADER + CERT_TLV_MAX))
    + (SHORT_STRING_HEADER + SIGNATURE_LEN_BYTES)
    + (SHORT_STRING_HEADER + RESUMPTION_ID_LEN);

/// The largest `sigma-3-tbedata`: the same without the resumption id.
const MAX_TBEDATA3: usize = STRUCTURE_OVERHEAD
    + (2 * (LONG_STRING_HEADER + CERT_TLV_MAX))
    + (SHORT_STRING_HEADER + SIGNATURE_LEN_BYTES);

/// The largest `encrypted2` this crate will build or accept — the plaintext plus the AEAD tag.
///
/// A responder that cannot fit this cannot complete CASE with a peer that uses an intermediate
/// CA and a CA that issues certificates at the size the specification permits.
pub const MAX_ENCRYPTED2: usize = MAX_TBEDATA2 + AEAD_MIC_LENGTH_BYTES;

/// The largest `encrypted3`.
pub const MAX_ENCRYPTED3: usize = MAX_TBEDATA3 + AEAD_MIC_LENGTH_BYTES;

/// The largest `sigma-2-tbsdata` or `sigma-3-tbsdata` this crate signs or verifies: two
/// certificates and the two ephemeral public keys.
pub const MAX_TBSDATA: usize = STRUCTURE_OVERHEAD
    + (2 * (LONG_STRING_HEADER + CERT_TLV_MAX))
    + (2 * (SHORT_STRING_HEADER + PUBLIC_KEY_SIZE_BYTES));

/// The largest `sigma-1-struct`: two randoms' worth of octet strings, a public key, a
/// resumption id and MIC, the session parameters, and a TLV header for each.
pub const MAX_SIGMA1: usize = RANDOM_LEN
    + HASH_LEN_BYTES
    + PUBLIC_KEY_SIZE_BYTES
    + RESUMPTION_ID_LEN
    + AEAD_MIC_LENGTH_BYTES
    + 64;

/// The largest `sigma-2-struct` this crate will build or accept.
///
/// It exists for the same reason [`MAX_SIGMA1`] does: a caller has to allocate the buffer the
/// message is encoded into, and a caller that guesses guesses low. The guess only fails
/// against a peer whose certificates are near §6.1.3's cap — so it survives every test written
/// against this crate's own certificates and fails at a certification event.
pub const MAX_SIGMA2: usize = STRUCTURE_OVERHEAD
    + (SHORT_STRING_HEADER + RANDOM_LEN)
    + 4
    + (SHORT_STRING_HEADER + PUBLIC_KEY_SIZE_BYTES)
    + (LONG_STRING_HEADER + MAX_ENCRYPTED2)
    + MAX_SESSION_PARAMS;

/// The largest `sigma-3-struct`: one field, and everything is inside it.
pub const MAX_SIGMA3: usize = STRUCTURE_OVERHEAD + LONG_STRING_HEADER + MAX_ENCRYPTED3;

/// The largest `session-parameter-struct` (§4.13.1): nine unsigned fields, each at most a
/// control octet, a tag and four octets of value.
pub const MAX_SESSION_PARAMS: usize = STRUCTURE_OVERHEAD + (9 * 6);

/// The bounds above, checked against the encoding rules at compile time.
///
/// They are `const` assertions rather than tests for the reason [`crate::Config`]'s minima
/// are: a buffer bound that is wrong is not a failing test, it is a node that cannot complete
/// a handshake with a conforming peer, and the cheapest place to say so is the build.
///
/// Each is the sum of what the field actually costs, recomputed here from the octet counts
/// rather than from the constants, so that a constant edited without its derivation fails. The
/// numbers they guard were both wrong before anyone looked: `MAX_ENCRYPTED3` was five octets
/// short of two certificates at §6.1.3's cap, and `MAX_SIGMA2` did not exist, so `examples/light`
/// used a round 1024 against a real Sigma2 of 1081.
const _: () = {
    // `sigma-2-tbedata` = { NOC, ICAC, signature, resumptionID }, sealed.
    assert!(
        MAX_ENCRYPTED2
            >= 2 + 2 * (4 + CERT_TLV_MAX)
                + (3 + SIGNATURE_LEN_BYTES)
                + (3 + RESUMPTION_ID_LEN)
                + AEAD_MIC_LENGTH_BYTES
    );
    // `sigma-3-tbedata` = the same without the resumption id.
    assert!(
        MAX_ENCRYPTED3
            >= 2 + 2 * (4 + CERT_TLV_MAX) + (3 + SIGNATURE_LEN_BYTES) + AEAD_MIC_LENGTH_BYTES
    );
    // `sigma-2-tbsdata` = { NOC, ICAC, both ephemeral public keys }, signed.
    assert!(MAX_TBSDATA >= 2 + 2 * (4 + CERT_TLV_MAX) + 2 * (3 + PUBLIC_KEY_SIZE_BYTES));
    // Nine unsigned fields, the widest 32 bits (§4.13.1).
    assert!(MAX_SESSION_PARAMS >= 2 + 9 * (1 + 1 + 4));
    // The whole `sigma-2-struct`, which is what a caller allocates for.
    assert!(
        MAX_SIGMA2
            >= 2 + (3 + RANDOM_LEN)
                + 4
                + (3 + PUBLIC_KEY_SIZE_BYTES)
                + (4 + MAX_ENCRYPTED2)
                + MAX_SESSION_PARAMS
    );
    assert!(MAX_SIGMA3 >= 2 + 4 + MAX_ENCRYPTED3);
    // CASE runs over MRP before there is any session to negotiate a larger transport on, so
    // every one of these has to fit Core §4.4.4's 1280-octet datagram with its headers.
    assert!(MAX_SIGMA2 + 64 <= crate::config::MAX_UDP_MESSAGE);
};

fn parse_error() -> Error {
    Error::new(ErrorCode::TlvWrongType)
}

/// Encrypts `len` octets in place and appends the MIC, returning ciphertext ‖ MIC.
///
/// Every CASE AEAD uses an empty AAD — "TBEData2_A[] = {}" and its siblings — because
/// everything that could usefully be bound in is already in the key's salt. The nonce is a
/// constant rather than a counter, which is safe only because each key is used exactly
/// once, for exactly one message.
fn seal<'b>(
    key: &SymmetricKey,
    nonce: &[u8; AEAD_NONCE_LENGTH_BYTES],
    buf: &'b mut [u8],
    len: usize,
) -> Result<&'b [u8]> {
    let end = len
        .checked_add(AEAD_MIC_LENGTH_BYTES)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
    if buf.len() < end {
        bail!(BufferTooSmall)
    }
    let (plaintext, rest) = buf.split_at_mut(len);
    let mut mic = [0u8; AEAD_MIC_LENGTH_BYTES];
    aead_encrypt_in_place(key, nonce, &[], plaintext, &mut mic)?;
    rest.get_mut(..AEAD_MIC_LENGTH_BYTES)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?
        .copy_from_slice(&mic);
    buf.get(..end)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))
}

/// Copies `sealed` into `buf`, verifies its MIC and decrypts in place, returning the
/// plaintext length.
///
/// The ciphertext is copied rather than decrypted where it lies because it arrived inside
/// the received message, which the caller still needs intact for the transcript hash.
fn open(
    key: &SymmetricKey,
    nonce: &[u8; AEAD_NONCE_LENGTH_BYTES],
    buf: &mut [u8],
    sealed: &[u8],
) -> Result<usize> {
    let len = sealed
        .len()
        .checked_sub(AEAD_MIC_LENGTH_BYTES)
        .ok_or_else(|| Error::new(ErrorCode::IntegrityCheckFailed))?;
    let (body, mic) = sealed.split_at(len);
    let mic = <[u8; AEAD_MIC_LENGTH_BYTES]>::try_from(mic)
        .map_err(|_| Error::new(ErrorCode::IntegrityCheckFailed))?;
    let slot = buf
        .get_mut(..len)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
    slot.copy_from_slice(body);
    aead_decrypt_in_place(key, nonce, &[], slot, &mic)?;
    Ok(len)
}

// --- Sigma1 --------------------------------------------------------------------------------

/// `sigma-1-struct` (§4.14.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sigma1<'a> {
    /// `initiatorRandom [1]`.
    pub initiator_random: [u8; RANDOM_LEN],
    /// `initiatorSessionId [2]` — the id *the initiator* will listen on.
    pub initiator_session_id: SessionId,
    /// `destinationId [3]` — which fabric and node this is for, without naming either.
    pub destination_id: [u8; HASH_LEN_BYTES],
    /// `initiatorEphPubKey [4]`.
    pub initiator_eph_pub_key: PublicKey,
    /// `initiatorSessionParams [5]`.
    pub session_params: Option<SessionParams>,
    /// `resumptionID [6]` — present only when resuming.
    pub resumption_id: Option<[u8; RESUMPTION_ID_LEN]>,
    /// `initiatorResumeMIC [7]` — present only when resuming.
    pub initiator_resume_mic: Option<[u8; AEAD_MIC_LENGTH_BYTES]>,
    /// A borrow of the encoded message, because every later key is salted with its hash and
    /// re-encoding it is not guaranteed to reproduce the peer's bytes.
    encoded: &'a [u8],
}

impl<'a> Sigma1<'a> {
    /// The bytes this message was decoded from — the `Msg1` of every transcript hash.
    #[must_use]
    pub const fn encoded(&self) -> &'a [u8] {
        self.encoded
    }

    /// Whether the message asks for resumption: "The nomenclature Sigma1 with Resumption …
    /// implies a Sigma1 message with **both** the optional resumptionID and
    /// initiatorResumeMIC fields populated."
    #[must_use]
    pub const fn is_resumption(&self) -> bool {
        self.resumption_id.is_some() && self.initiator_resume_mic.is_some()
    }

    /// Encodes a Sigma1.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), &self.initiator_random)?;
        w.unsigned(Tag::Context(2), u64::from(self.initiator_session_id.0))?;
        w.octets(Tag::Context(3), &self.destination_id)?;
        w.octets(Tag::Context(4), self.initiator_eph_pub_key.as_bytes())?;
        if let Some(params) = self.session_params {
            params.encode(&mut w, Tag::Context(5))?;
        }
        if let Some(id) = self.resumption_id.as_ref() {
            w.octets(Tag::Context(6), id)?;
        }
        if let Some(mic) = self.initiator_resume_mic.as_ref() {
            w.octets(Tag::Context(7), mic)?;
        }
        w.end_container()?;
        w.finish()
    }

    /// Decodes a Sigma1, keeping a borrow of `buf` for the transcript.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut initiator_random = None;
        let mut initiator_session_id = None;
        let mut destination_id = None;
        let mut initiator_eph_pub_key = None;
        let mut session_params = None;
        let mut resumption_id = None;
        let mut initiator_resume_mic = None;

        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => set_once(
                    &mut initiator_random,
                    fixed::<RANDOM_LEN>(element.octets()?)?,
                )?,
                2 => {
                    let id =
                        SessionId(u16::try_from(element.unsigned()?).map_err(|_| parse_error())?);
                    set_once(&mut initiator_session_id, id)?;
                }
                3 => set_once(
                    &mut destination_id,
                    fixed::<HASH_LEN_BYTES>(element.octets()?)?,
                )?,
                4 => set_once(
                    &mut initiator_eph_pub_key,
                    PublicKey::from_slice(element.octets()?)?,
                )?,
                5 => set_once(&mut session_params, SessionParams::decode(&mut fields)?)?,
                6 => set_once(
                    &mut resumption_id,
                    fixed::<RESUMPTION_ID_LEN>(element.octets()?)?,
                )?,
                7 => {
                    let mic = fixed::<AEAD_MIC_LENGTH_BYTES>(element.octets()?)?;
                    set_once(&mut initiator_resume_mic, mic)?;
                }
                // "Any context-specific tags not listed in the above TLV schemas SHALL be
                // reserved for future use, and SHALL be silently ignored if seen by a
                // responder which cannot understand them."
                _ => fields.skip(&element)?,
            }
        }

        Ok(Self {
            initiator_random: initiator_random.ok_or_else(parse_error)?,
            initiator_session_id: initiator_session_id.ok_or_else(parse_error)?,
            destination_id: destination_id.ok_or_else(parse_error)?,
            initiator_eph_pub_key: initiator_eph_pub_key.ok_or_else(parse_error)?,
            session_params,
            resumption_id,
            initiator_resume_mic,
            encoded: buf,
        })
    }
}

// --- Sigma2 --------------------------------------------------------------------------------

/// `sigma-2-struct` (§4.14.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sigma2<'a> {
    /// `responderRandom [1]`.
    pub responder_random: [u8; RANDOM_LEN],
    /// `responderSessionId [2]`.
    pub responder_session_id: SessionId,
    /// `responderEphPubKey [3]`.
    pub responder_eph_pub_key: PublicKey,
    /// `encrypted2 [4]` — `sigma-2-tbedata` under S2K.
    pub encrypted2: &'a [u8],
    /// `responderSessionParams [5]`.
    pub session_params: Option<SessionParams>,
    encoded: &'a [u8],
}

impl<'a> Sigma2<'a> {
    /// The bytes this message was decoded from — the `Msg2` of every transcript hash.
    #[must_use]
    pub const fn encoded(&self) -> &'a [u8] {
        self.encoded
    }

    /// Encodes a Sigma2.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), &self.responder_random)?;
        w.unsigned(Tag::Context(2), u64::from(self.responder_session_id.0))?;
        w.octets(Tag::Context(3), self.responder_eph_pub_key.as_bytes())?;
        w.octets(Tag::Context(4), self.encrypted2)?;
        if let Some(params) = self.session_params {
            params.encode(&mut w, Tag::Context(5))?;
        }
        w.end_container()?;
        w.finish()
    }

    /// Decodes a Sigma2.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut responder_random = None;
        let mut responder_session_id = None;
        let mut responder_eph_pub_key = None;
        let mut encrypted2 = None;
        let mut session_params = None;

        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => set_once(
                    &mut responder_random,
                    fixed::<RANDOM_LEN>(element.octets()?)?,
                )?,
                2 => {
                    let id =
                        SessionId(u16::try_from(element.unsigned()?).map_err(|_| parse_error())?);
                    set_once(&mut responder_session_id, id)?;
                }
                3 => set_once(
                    &mut responder_eph_pub_key,
                    PublicKey::from_slice(element.octets()?)?,
                )?,
                4 => set_once(&mut encrypted2, element.octets()?)?,
                5 => set_once(&mut session_params, SessionParams::decode(&mut fields)?)?,
                _ => fields.skip(&element)?,
            }
        }

        Ok(Self {
            responder_random: responder_random.ok_or_else(parse_error)?,
            responder_session_id: responder_session_id.ok_or_else(parse_error)?,
            responder_eph_pub_key: responder_eph_pub_key.ok_or_else(parse_error)?,
            encrypted2: encrypted2.ok_or_else(parse_error)?,
            session_params,
            encoded: buf,
        })
    }
}

// --- Sigma3 --------------------------------------------------------------------------------

/// `sigma-3-struct` — one field, because everything else is inside it (§4.14.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sigma3<'a> {
    /// `encrypted3 [1]` — `sigma-3-tbedata` under S3K.
    pub encrypted3: &'a [u8],
    encoded: &'a [u8],
}

impl<'a> Sigma3<'a> {
    /// The bytes this message was decoded from — the `Msg3` of the session-key transcript.
    #[must_use]
    pub const fn encoded(&self) -> &'a [u8] {
        self.encoded
    }

    /// Encodes a Sigma3.
    pub fn encode<'b>(encrypted3: &[u8], buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), encrypted3)?;
        w.end_container()?;
        w.finish()
    }

    /// Decodes a Sigma3.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut encrypted3 = None;
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => set_once(&mut encrypted3, element.octets()?)?,
                _ => fields.skip(&element)?,
            }
        }
        Ok(Self {
            encrypted3: encrypted3.ok_or_else(parse_error)?,
            encoded: buf,
        })
    }
}

/// `sigma-2-resume-struct` (§4.14.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sigma2Resume {
    /// `resumptionID [1]` — the id of the *new* session, not the one being resumed.
    pub resumption_id: [u8; RESUMPTION_ID_LEN],
    /// `sigma2ResumeMIC [2]`.
    pub sigma2_resume_mic: [u8; AEAD_MIC_LENGTH_BYTES],
    /// `responderSessionID [3]`.
    pub responder_session_id: SessionId,
    /// `responderSessionParams [4]`.
    pub session_params: Option<SessionParams>,
}

impl Sigma2Resume {
    /// Encodes a `Sigma2_Resume`.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), &self.resumption_id)?;
        w.octets(Tag::Context(2), &self.sigma2_resume_mic)?;
        w.unsigned(Tag::Context(3), u64::from(self.responder_session_id.0))?;
        if let Some(params) = self.session_params {
            params.encode(&mut w, Tag::Context(4))?;
        }
        w.end_container()?;
        w.finish()
    }

    /// Decodes a `Sigma2_Resume`.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut resumption_id = None;
        let mut sigma2_resume_mic = None;
        let mut responder_session_id = None;
        let mut session_params = None;
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => set_once(
                    &mut resumption_id,
                    fixed::<RESUMPTION_ID_LEN>(element.octets()?)?,
                )?,
                2 => {
                    let mic = fixed::<AEAD_MIC_LENGTH_BYTES>(element.octets()?)?;
                    set_once(&mut sigma2_resume_mic, mic)?;
                }
                3 => {
                    let id =
                        SessionId(u16::try_from(element.unsigned()?).map_err(|_| parse_error())?);
                    set_once(&mut responder_session_id, id)?;
                }
                4 => set_once(&mut session_params, SessionParams::decode(&mut fields)?)?,
                _ => fields.skip(&element)?,
            }
        }
        Ok(Self {
            resumption_id: resumption_id.ok_or_else(parse_error)?,
            sigma2_resume_mic: sigma2_resume_mic.ok_or_else(parse_error)?,
            responder_session_id: responder_session_id.ok_or_else(parse_error)?,
            session_params,
        })
    }
}

/// The `StatusReport` a peer sends when CASE fails (§4.14.2.3, Appendix D).
///
/// The specification names two, and they answer different questions:
///
/// * [`SecureChannelCode::NoSharedTrustRoots`] — "If there is no candidateDestinationId
///   matching the incoming destinationId, the responder SHALL send a status report" with
///   this code. It means *we are not on a fabric together*, and it is the only honest answer
///   a responder can give without revealing which fabrics it is on.
/// * [`SecureChannelCode::InvalidParameter`] — every other rejection: a decryption that
///   failed, a chain that did not verify, a signature that did not match, an identity that
///   was not the one addressed. Deliberately undiscriminating: telling a peer *which* check
///   it failed tells an attacker how far it got.
///
/// Every fallible entry point here returns a [`Result`], and a caller that wants to answer
/// rather than simply drop the exchange encodes one of these. Which one to send is the
/// caller's, because only the caller knows whether its fabric lookup came up empty.
///
/// ```
/// use matter_kit::sc::{SecureChannelCode, case};
///
/// let mut out = [0u8; 32];
/// let n = case::failure_report(SecureChannelCode::NoSharedTrustRoots, &mut out)?;
/// // Eight octets: GeneralCode(2) + ProtocolId(4) + ProtocolCode(2).
/// assert_eq!(n, 8);
/// # Ok::<(), matter_kit::Error>(())
/// ```
pub fn failure_report(code: SecureChannelCode, out: &mut [u8]) -> Result<usize> {
    StatusReport::secure_channel(code).encode(out)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| parse_error())
}

// --- The key schedule (§4.14.2.6) ------------------------------------------------------------

/// The running transcript hash, which every CASE key is salted with.
///
/// "TranscriptHash = Crypto_Hash(message = Msg1)", then `Msg1 ‖ Msg2`, then
/// `Msg1 ‖ Msg2 ‖ Msg3` — the same hash extended, not three separate ones. Keeping it
/// incremental means a node never has to hold all three messages at once, which matters:
/// with two certificate chains in flight they come to over a kilobyte.
#[derive(Debug, Clone)]
pub struct Transcript(Hasher);

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// An empty transcript.
    #[must_use]
    pub fn new() -> Self {
        Self(Hasher::new())
    }

    /// Appends a message's encoded bytes — exactly the bytes that went on the wire.
    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    /// The hash of everything appended so far, without consuming the transcript.
    #[must_use]
    pub fn hash(&self) -> [u8; HASH_LEN_BYTES] {
        self.0.clone().finish()
    }
}

/// The salt of an S2K derivation: `IPK ‖ responderRandom ‖ responderEphPubKey ‖ TranscriptHash`.
const S2K_SALT_LEN: usize =
    crate::crypto::SYMMETRIC_KEY_LENGTH_BYTES + RANDOM_LEN + PUBLIC_KEY_SIZE_BYTES + HASH_LEN_BYTES;

/// Derives S2K (§4.14.2.6.2).
pub fn sigma2_key(
    shared_secret: &Secret<GROUP_SIZE_BYTES>,
    ipk: &SymmetricKey,
    responder_random: &[u8; RANDOM_LEN],
    responder_eph_pub_key: &PublicKey,
    transcript_hash: &[u8; HASH_LEN_BYTES],
) -> Result<SymmetricKey> {
    let mut salt = [0u8; S2K_SALT_LEN];
    let mut at = 0usize;
    at = put(&mut salt, at, ipk.as_bytes())?;
    at = put(&mut salt, at, responder_random)?;
    at = put(&mut salt, at, responder_eph_pub_key.as_bytes())?;
    at = put(&mut salt, at, transcript_hash)?;
    let salt = salt.get(..at).ok_or_else(parse_error)?;
    kdf_key(shared_secret.as_bytes(), salt, S2K_INFO)
}

/// The salt of an S3K or session-key derivation: `IPK ‖ TranscriptHash`.
const IPK_TRANSCRIPT_SALT_LEN: usize = crate::crypto::SYMMETRIC_KEY_LENGTH_BYTES + HASH_LEN_BYTES;

fn ipk_transcript_salt(
    ipk: &SymmetricKey,
    transcript_hash: &[u8; HASH_LEN_BYTES],
) -> [u8; IPK_TRANSCRIPT_SALT_LEN] {
    let mut salt = [0u8; IPK_TRANSCRIPT_SALT_LEN];
    let (head, tail) = salt.split_at_mut(crate::crypto::SYMMETRIC_KEY_LENGTH_BYTES);
    head.copy_from_slice(ipk.as_bytes());
    tail.copy_from_slice(transcript_hash);
    salt
}

/// Derives S3K (§4.14.2.6.3).
pub fn sigma3_key(
    shared_secret: &Secret<GROUP_SIZE_BYTES>,
    ipk: &SymmetricKey,
    transcript_hash: &[u8; HASH_LEN_BYTES],
) -> Result<SymmetricKey> {
    kdf_key(
        shared_secret.as_bytes(),
        &ipk_transcript_salt(ipk, transcript_hash),
        S3K_INFO,
    )
}

/// The salt of a resumption derivation: `Sigma1.initiatorRandom ‖ ResumptionID`.
const RESUME_SALT_LEN: usize = RANDOM_LEN + RESUMPTION_ID_LEN;

fn resume_salt(
    initiator_random: &[u8; RANDOM_LEN],
    resumption_id: &[u8; RESUMPTION_ID_LEN],
) -> [u8; RESUME_SALT_LEN] {
    let mut salt = [0u8; RESUME_SALT_LEN];
    let (head, tail) = salt.split_at_mut(RANDOM_LEN);
    head.copy_from_slice(initiator_random);
    tail.copy_from_slice(resumption_id);
    salt
}

/// Derives S1RK (§4.14.2.6.4), where `resumption_id` is the **previous** session's.
pub fn sigma1_resume_key(
    shared_secret: &Secret<GROUP_SIZE_BYTES>,
    initiator_random: &[u8; RANDOM_LEN],
    resumption_id: &[u8; RESUMPTION_ID_LEN],
) -> Result<SymmetricKey> {
    kdf_key(
        shared_secret.as_bytes(),
        &resume_salt(initiator_random, resumption_id),
        S1RK_INFO,
    )
}

/// Derives S2RK (§4.14.2.6.5), where `resumption_id` is the **new** session's.
///
/// The two resumption keys differ only in their `Info` string and in which resumption ID
/// salts them — which is the whole reason the specification spells both out rather than
/// reusing one: the same secret, the same random, and two different keys.
pub fn sigma2_resume_key(
    shared_secret: &Secret<GROUP_SIZE_BYTES>,
    initiator_random: &[u8; RANDOM_LEN],
    resumption_id: &[u8; RESUMPTION_ID_LEN],
) -> Result<SymmetricKey> {
    kdf_key(
        shared_secret.as_bytes(),
        &resume_salt(initiator_random, resumption_id),
        S2RK_INFO,
    )
}

/// The three session keys a completed CASE produces (§4.14.2.6.6).
pub fn session_keys(
    shared_secret: &Secret<GROUP_SIZE_BYTES>,
    ipk: &SymmetricKey,
    transcript_hash: &[u8; HASH_LEN_BYTES],
) -> Result<crate::session::EstablishedKeys> {
    crate::session::EstablishedKeys::derive(
        shared_secret.as_bytes(),
        &ipk_transcript_salt(ipk, transcript_hash),
    )
}

/// The three session keys a completed *resumption* produces (§4.14.2.6.7).
///
/// A different `Info` and a salt with no transcript in it, because a resumption has no
/// transcript worth binding: its security comes from the shared secret of the session it
/// resumes.
pub fn resumption_session_keys(
    shared_secret: &Secret<GROUP_SIZE_BYTES>,
    initiator_random: &[u8; RANDOM_LEN],
    resumption_id: &[u8; RESUMPTION_ID_LEN],
) -> Result<crate::session::EstablishedKeys> {
    crate::session::EstablishedKeys::derive_with_info(
        shared_secret.as_bytes(),
        &resume_salt(initiator_random, resumption_id),
        RESUMPTION_SESSION_KEYS_INFO,
    )
}

fn put(buf: &mut [u8], at: usize, src: &[u8]) -> Result<usize> {
    let end = at
        .checked_add(src.len())
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
    let Some(slot) = buf.get_mut(at..end) else {
        bail!(BufferTooSmall)
    };
    slot.copy_from_slice(src);
    Ok(end)
}

// --- The signed and encrypted payloads ---------------------------------------------------

/// Encodes a `sigma-2-tbsdata` or `sigma-3-tbsdata` — the structure that is signed but never
/// transmitted (§4.14.2.3).
///
/// Both have the same shape: the signer's certificate chain, then its own ephemeral public
/// key, then the peer's. The order of the two ephemerals is what distinguishes a Sigma2
/// signature from a Sigma3 one, and is therefore what stops one being replayed as the
/// other.
pub fn encode_tbsdata<'b>(
    noc: &[u8],
    icac: Option<&[u8]>,
    own_eph_pub_key: &PublicKey,
    peer_eph_pub_key: &PublicKey,
    buf: &'b mut [u8],
) -> Result<&'b [u8]> {
    let mut w = TlvWriter::new(buf);
    w.start_structure(Tag::Anonymous)?;
    w.octets(Tag::Context(1), noc)?;
    if let Some(icac) = icac {
        w.octets(Tag::Context(2), icac)?;
    }
    w.octets(Tag::Context(3), own_eph_pub_key.as_bytes())?;
    w.octets(Tag::Context(4), peer_eph_pub_key.as_bytes())?;
    w.end_container()?;
    w.finish()
}

/// A decoded `sigma-2-tbedata` or `sigma-3-tbedata`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TbeData<'a> {
    /// `[1]` — the peer's NOC, in Matter TLV.
    pub noc: &'a [u8],
    /// `[2]` — the peer's ICAC, if its chain has one.
    pub icac: Option<&'a [u8]>,
    /// `[3]` — the signature over the corresponding `tbsdata`.
    pub signature: Signature,
    /// `[4]` — the resumption ID, present in a `sigma-2-tbedata` and absent from a
    /// `sigma-3-tbedata`.
    pub resumption_id: Option<[u8; RESUMPTION_ID_LEN]>,
}

impl<'a> TbeData<'a> {
    /// Encodes a `tbedata`.
    ///
    /// The certificate octets must be "byte-for-byte identical to the encoding in
    /// sigma-2-tbsdata" (§4.14.2.3), which is why this takes the same slices rather than a
    /// decoded certificate it might re-encode differently.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), self.noc)?;
        if let Some(icac) = self.icac {
            w.octets(Tag::Context(2), icac)?;
        }
        w.octets(Tag::Context(3), self.signature.as_bytes())?;
        if let Some(id) = self.resumption_id.as_ref() {
            w.octets(Tag::Context(4), id)?;
        }
        w.end_container()?;
        w.finish()
    }

    /// Decodes a `tbedata` from decrypted plaintext.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut fields = Fields::new(buf)?;
        let mut noc = None;
        let mut icac = None;
        let mut signature = None;
        let mut resumption_id = None;
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => set_once(&mut noc, element.octets()?)?,
                2 => set_once(&mut icac, element.octets()?)?,
                3 => set_once(&mut signature, Signature::from_slice(element.octets()?)?)?,
                4 => set_once(
                    &mut resumption_id,
                    fixed::<RESUMPTION_ID_LEN>(element.octets()?)?,
                )?,
                _ => fields.skip(&element)?,
            }
        }
        Ok(Self {
            noc: noc.ok_or_else(parse_error)?,
            icac,
            signature: signature.ok_or_else(parse_error)?,
            resumption_id,
        })
    }
}

// --- Resumption state (§4.14.2.2.1) ---------------------------------------------------------

/// What both peers must remember to resume a session later.
///
/// §4.14.2.2.1 lists exactly this: "SharedSecret, Local Fabric Index, Peer Node ID, Peer
/// CASE Authenticated Tags, ResumptionID". The CATs are part of the peer's identity, so
/// resuming without them would silently widen what the peer is allowed to do — they are
/// held in [`ResumptionState::identity`] rather than re-derived.
#[derive(Debug, Clone)]
pub struct ResumptionState {
    /// The ECDH secret of the session being resumed. "It SHALL be that SharedSecret that is
    /// used to compute the resumption ID."
    pub shared_secret: Secret<GROUP_SIZE_BYTES>,
    /// The identifier of that session.
    pub resumption_id: [u8; RESUMPTION_ID_LEN],
    /// This node's index for the fabric it was on.
    pub fabric_index: crate::msg::FabricIndex,
    /// Who the peer was, as the previous exchange established it.
    pub identity: VerifiedIdentity,
}

/// Everything a completed CASE hands back.
#[derive(Debug)]
pub struct CaseOutcome {
    /// The three session keys.
    pub keys: crate::session::EstablishedKeys,
    /// The peer's authenticated operational identity.
    pub peer: VerifiedIdentity,
    /// The session id the peer will listen on — what this node puts in outgoing messages.
    pub peer_session_id: SessionId,
    /// The MRP parameters the peer announced, if it announced any.
    pub peer_session_params: Option<SessionParams>,
    /// State for a later resumption, which the caller may keep or drop.
    pub resumption: ResumptionState,
}

impl CaseOutcome {
    /// Builds the operational session this handshake produced.
    ///
    /// Every identity a CASE session needs comes from exactly two places — this outcome and
    /// the fabric the handshake ran on — so taking both is the only way to be sure none is
    /// left at its default. Assembling a [`SecureSession`](crate::session::SecureSession)
    /// field by field is still possible and is still wrong more often than it is right.
    ///
    /// The field that makes this more than convenience is `local_node_id`. §4.9.2 builds the
    /// AEAD nonce from "the Security Flags, the Message Counter, and the Source Node ID of
    /// that message", and for a CASE session the source node id is the sender's operational
    /// node id — which never appears in the header, because both ends are supposed to know
    /// it from the session. A session left at
    /// [`NodeId::UNSPECIFIED`](crate::msg::NodeId::UNSPECIFIED) therefore encrypts every
    /// message with a nonce the peer will not reconstruct, and the peer discards them
    /// as unauthenticated. Nothing fails locally: this node sends, MRP retransmits into
    /// silence, and the exchange is abandoned with no error at either end that names the
    /// cause.
    ///
    /// `randomness` seeds the outgoing message counter (§4.6.2, which randomises it "on session
    /// establishment") and `now` timestamps the
    /// session, exactly as [`SecureSession::new`](crate::session::SecureSession::new) takes them.
    pub fn into_session(
        &self,
        local_session_id: SessionId,
        fabric: &Fabric,
        randomness: u32,
        now: crate::platform::Instant,
    ) -> crate::session::SecureSession {
        let mut session = crate::session::SecureSession::new(
            local_session_id,
            self.peer_session_id,
            crate::session::SessionKind::Case,
            crate::session::Role::Responder,
            self.keys.clone(),
            randomness,
            now,
        );
        session.role = crate::session::Role::Responder;
        session.local_node_id = fabric.node_id;
        session.peer_node_id = self.peer.node_id;
        session.fabric_index = fabric.index;
        // §6.5.6 allows a NOC at most three, and `peer_cats` is sized for exactly that, so
        // the push cannot overflow — but it is not worth a panic to say so.
        for cat in &self.peer.cats {
            let _ = session.peer_cats.push(*cat);
        }
        // "A Node SHALL use the provided default value for each parameter unless the message
        // recipient Node advertises an alternate value" (§4.13.1): what the peer announced in
        // Sigma1 governs how long this node waits before retransmitting to it.
        if let Some(params) = self.peer_session_params {
            session.mrp = params.to_mrp();
        }
        session
    }

    /// The same, for the node that *initiated* the handshake.
    ///
    /// The only difference is the role, and the role decides which of the two directional
    /// keys this node encrypts with (§4.14.1) — so getting it wrong is the same silent
    /// failure as getting `local_node_id` wrong.
    pub fn into_initiator_session(
        &self,
        local_session_id: SessionId,
        fabric: &Fabric,
        randomness: u32,
        now: crate::platform::Instant,
    ) -> crate::session::SecureSession {
        let mut session = self.into_session(local_session_id, fabric, randomness, now);
        session.role = crate::session::Role::Initiator;
        session
    }
}

// --- Responder --------------------------------------------------------------------------

/// The device side of CASE: receives Sigma1, answers Sigma2, accepts Sigma3 (§4.14.2.3).
#[derive(Debug)]
pub struct CaseResponder {
    session_id: SessionId,
    session_params: Option<SessionParams>,
    state: ResponderState,
}

/// The whole enum is as large as `AwaitingSigma3`, which is inherent: a responder mid-CASE
/// is holding a shared secret, an IPK, a hash state and two public keys, and there is
/// nowhere smaller to put them on a node with no allocator. It exists only between Sigma1
/// and Sigma3, so the cost is transient.
#[expect(
    clippy::large_enum_variant,
    reason = "no allocator, and the state is transient"
)]
#[derive(Debug)]
enum ResponderState {
    AwaitingSigma1,
    AwaitingSigma3(Box2),
    Done,
    Failed,
}

/// The responder's state between Sigma2 and Sigma3.
#[derive(Debug)]
struct Box2 {
    shared_secret: Secret<GROUP_SIZE_BYTES>,
    ipk: SymmetricKey,
    transcript: Transcript,
    fabric_index: crate::msg::FabricIndex,
    /// The fabric the destination identifier selected; §4.14.2.3's *Validate Sigma3* step 4a
    /// holds the initiator's NOC to it.
    fabric_id: crate::msg::FabricId,
    initiator_session_id: SessionId,
    initiator_session_params: Option<SessionParams>,
    initiator_eph_pub_key: PublicKey,
    responder_eph_pub_key: PublicKey,
    resumption_id: [u8; RESUMPTION_ID_LEN],
}

impl CaseResponder {
    /// A responder that will listen on `session_id` and announce `session_params`.
    #[must_use]
    pub fn new(session_id: SessionId, session_params: Option<SessionParams>) -> Self {
        Self {
            session_id,
            session_params,
            state: ResponderState::AwaitingSigma1,
        }
    }

    /// Handles a Sigma1 and writes the reply into `out`.
    ///
    /// `fabric` is the one whose `destinationId` matched — found with
    /// [`FabricTable::find_by_destination_identifier`](crate::fabric::FabricTable::find_by_destination_identifier),
    /// which is a search this function deliberately does not do: it needs the fabric table,
    /// and threading the whole table through here would make the protocol depend on how a
    /// node stores its fabrics.
    ///
    /// `ephemeral_random` is 32 octets of entropy for the ephemeral key pair,
    /// `resumption_random` 16 for the new resumption ID.
    #[expect(
        clippy::too_many_arguments,
        reason = "Sigma2 genuinely needs all of this, and bundling it into a struct would \
                  only move the list somewhere the reader has to go and look for it."
    )]
    pub fn handle_sigma1<K: KeyStore>(
        &mut self,
        sigma1: &Sigma1<'_>,
        fabric: &Fabric,
        noc: &[u8],
        icac: Option<&[u8]>,
        keys: &mut K,
        ephemeral_random: &[u8; GROUP_SIZE_BYTES],
        responder_random: &[u8; RANDOM_LEN],
        resumption_random: &[u8; RESUMPTION_ID_LEN],
        out: &mut [u8],
    ) -> Result<usize> {
        if !matches!(self.state, ResponderState::AwaitingSigma1) {
            self.state = ResponderState::Failed;
            bail!(InvalidState)
        }
        let result = self.build_sigma2(
            sigma1,
            fabric,
            noc,
            icac,
            keys,
            ephemeral_random,
            responder_random,
            resumption_random,
            out,
        );
        if result.is_err() {
            self.state = ResponderState::Failed;
        }
        result
    }

    #[expect(clippy::too_many_arguments, reason = "see handle_sigma1")]
    fn build_sigma2<K: KeyStore>(
        &mut self,
        sigma1: &Sigma1<'_>,
        fabric: &Fabric,
        noc: &[u8],
        icac: Option<&[u8]>,
        keys: &mut K,
        ephemeral_random: &[u8; GROUP_SIZE_BYTES],
        responder_random: &[u8; RANDOM_LEN],
        resumption_random: &[u8; RESUMPTION_ID_LEN],
        out: &mut [u8],
    ) -> Result<usize> {
        // The destination identifier must be for this fabric and this node. The caller
        // found the fabric by matching it, but re-checking here means a caller that
        // searched wrongly cannot establish a session on the wrong fabric.
        let expected = fabric.destination_identifier(&sigma1.initiator_random)?;
        if !ct_eq(&expected, &sigma1.destination_id) {
            bail!(CertPathInvalid)
        }

        // §4.14.2.3: an ephemeral key pair per exchange, never reused.
        let (eph_handle, responder_eph_pub_key) =
            keys.generate(KeyPurpose::Ephemeral, ephemeral_random)?;
        // An ECDH against a peer's public key can fail — the point may not be on the curve —
        // and a key store has a fixed number of slots, so a stranger who sends a stream of
        // bad Sigma1s must not be able to fill it. The ephemeral is destroyed either way.
        let shared_secret = keys.ecdh(eph_handle, &sigma1.initiator_eph_pub_key);
        keys.remove(eph_handle)?;
        let shared_secret = shared_secret?;

        let mut transcript = Transcript::new();
        transcript.update(sigma1.encoded());
        let s2k = sigma2_key(
            &shared_secret,
            &fabric.ipk,
            responder_random,
            &responder_eph_pub_key,
            &transcript.hash(),
        )?;

        // sigma-2-tbsdata: own chain, own ephemeral, then the peer's.
        let mut tbs = [0u8; MAX_TBSDATA];
        let tbsdata = encode_tbsdata(
            noc,
            icac,
            &responder_eph_pub_key,
            &sigma1.initiator_eph_pub_key,
            &mut tbs,
        )?;
        let signature = keys.sign(fabric.operational_key, tbsdata)?;

        let tbe = TbeData {
            noc,
            icac,
            signature,
            resumption_id: Some(*resumption_random),
        };
        let mut encrypted = [0u8; MAX_ENCRYPTED2];
        let plaintext_len = tbe.encode(&mut encrypted)?.len();
        // "TBEData2_A[] = {}" — no additional data, because everything that could be bound
        // in is already in S2K's salt.
        let encrypted2 = seal(&s2k, &SIGMA2_NONCE, &mut encrypted, plaintext_len)?;

        let sigma2 = Sigma2 {
            responder_random: *responder_random,
            responder_session_id: self.session_id,
            responder_eph_pub_key,
            encrypted2,
            session_params: self.session_params,
            encoded: &[],
        };
        let len = sigma2.encode(out)?.len();
        let encoded = out.get(..len).ok_or_else(parse_error)?;
        transcript.update(encoded);

        self.state = ResponderState::AwaitingSigma3(Box2 {
            shared_secret,
            ipk: fabric.ipk.clone(),
            transcript,
            fabric_index: fabric.index,
            fabric_id: fabric.fabric_id,
            initiator_session_id: sigma1.initiator_session_id,
            initiator_session_params: sigma1.session_params,
            initiator_eph_pub_key: sigma1.initiator_eph_pub_key,
            responder_eph_pub_key,
            resumption_id: *resumption_random,
        });
        Ok(len)
    }

    /// Validates a `Sigma3` against the root of the fabric `Sigma1` resolved, and writes the
    /// `SigmaFinished` status report (§4.14.2.3).
    ///
    /// `fabric` is the index [`accept_sigma1`] returned, and using any other is the mistake this
    /// exists to prevent: §4.14.2.3's Validate Sigma3 checks the initiator's certificate chain
    /// against *this fabric's* trusted root, and a chain that verifies against another root is a
    /// chain from another administrator. Taking whichever root the table lists first works
    /// perfectly on a node with one fabric and refuses every peer on the second — as
    /// `chain does not validate`, which reads like a bad certificate and is not one.
    ///
    /// `at` is the current Matter `epoch-s`, or `None` on a node without a clock (§6.4.5.1).
    #[cfg(feature = "rustcrypto")]
    pub fn accept_sigma3<C: crate::config::Config, const N: usize>(
        &mut self,
        sigma3: &Sigma3<'_>,
        fabrics: &crate::fabric::FabricTable<C, N>,
        fabric: crate::msg::FabricIndex,
        at: Option<u32>,
        out: &mut [u8],
    ) -> Result<(CaseOutcome, usize)> {
        let rcac = fabrics
            .find(fabric)
            .map(|f| f.credentials.rcac.clone())
            .ok_or(Error::new(ErrorCode::NoSession))?;
        let root = MatterCertificate::decode(&rcac)?;
        let outcome = self.handle_sigma3(sigma3, &root, at)?;
        let n = self.finished(out)?;
        Ok((outcome, n))
    }

    /// Handles a Sigma3, verifying the initiator's chain and establishing the session.
    ///
    /// `root` is the fabric's trusted root certificate; `at` the current Matter `epoch-s`,
    /// or `None` on a node without a clock (§6.4.5.1). Prefer
    /// [`accept_sigma3`](CaseResponder::accept_sigma3), which takes the root from the fabric the
    /// handshake is on rather than from the caller's memory.
    pub fn handle_sigma3(
        &mut self,
        sigma3: &Sigma3<'_>,
        root: &MatterCertificate<'_>,
        at: Option<u32>,
    ) -> Result<CaseOutcome> {
        let ResponderState::AwaitingSigma3(state) = &self.state else {
            self.state = ResponderState::Failed;
            bail!(InvalidState)
        };

        let mut plaintext = [0u8; MAX_ENCRYPTED3];
        let s3k = sigma3_key(&state.shared_secret, &state.ipk, &state.transcript.hash())?;
        let decrypted_len = match open(&s3k, &SIGMA3_NONCE, &mut plaintext, sigma3.encrypted3) {
            Ok(len) => len,
            Err(e) => {
                self.state = ResponderState::Failed;
                return Err(e);
            }
        };

        let outcome = (|| {
            let tbe = TbeData::decode(plaintext.get(..decrypted_len).ok_or_else(parse_error)?)?;
            let peer = verify_peer(
                &tbe,
                root,
                at,
                state.fabric_id,
                // A responder does not know which node is calling it.
                None,
                &state.initiator_eph_pub_key,
                &state.responder_eph_pub_key,
            )?;

            let mut transcript = state.transcript.clone();
            transcript.update(sigma3.encoded());
            let keys = session_keys(&state.shared_secret, &state.ipk, &transcript.hash())?;

            Ok(CaseOutcome {
                keys,
                peer: peer.clone(),
                peer_session_id: state.initiator_session_id,
                peer_session_params: state.initiator_session_params,
                resumption: ResumptionState {
                    shared_secret: state.shared_secret.clone(),
                    resumption_id: state.resumption_id,
                    fabric_index: state.fabric_index,
                    identity: peer,
                },
            })
        })();

        self.state = if outcome.is_ok() {
            ResponderState::Done
        } else {
            ResponderState::Failed
        };
        outcome
    }

    /// The `SigmaFinished` a responder sends once Sigma3 has been accepted (Appendix D).
    pub fn finished(&self, out: &mut [u8]) -> Result<usize> {
        if !matches!(self.state, ResponderState::Done) {
            bail!(InvalidState)
        }
        StatusReport::secure_channel(SecureChannelCode::SessionEstablishmentSuccess).encode(out)
    }

    /// Whether the exchange has failed and the responder must not be reused.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self.state, ResponderState::Failed)
    }
}

/// The three random values answering a `Sigma1` consumes (§4.14.2.3, §4.21).
///
/// Named rather than positional because they are three byte arrays of two different lengths
/// that a caller draws from one source: passed in the wrong order they still type-check where
/// the lengths agree, and the failure is a handshake that completes and a session nobody else
/// can address. Randomness is a parameter throughout this crate, so the caller draws them —
/// this only says which is which.
#[derive(Debug, Clone, Copy)]
pub struct Sigma2Randomness<'a> {
    /// The responder's ephemeral key material.
    pub ephemeral: &'a [u8; GROUP_SIZE_BYTES],
    /// `responderRandom`, which the transcript covers.
    pub responder: &'a [u8; RANDOM_LEN],
    /// The resumption id this session would be resumed by.
    pub resumption: &'a [u8; RESUMPTION_ID_LEN],
}

/// Answers a `Sigma1` from the node's fabric table (§4.14.2.3).
///
/// Two steps sit between a decoded `Sigma1` and [`CaseResponder::handle_sigma1`], and both are
/// easy to get wrong in a way that works perfectly on a node with one fabric:
///
/// 1. **Which fabric the initiator named.** §4.14.2.4.1's destination identifier is a MAC only
///    something holding that fabric's IPK and one of this node's identities on it could have
///    computed, so resolving it is the lookup and the admission check at once — and the scan
///    over the table is constant-time, so a near miss and a wild miss cost the same.
/// 2. **Which credentials to answer with** — the NOC and ICAC `AddNOC` stored *for that fabric*.
///
/// Returns the responder, the fabric it resolved and the length of the `Sigma2` written to
/// `out`. Keep the fabric index with the responder:
/// [`accept_sigma3`](CaseResponder::accept_sigma3) needs it.
///
/// [`ErrorCode::NoSession`] means no fabric matched, which is the ordinary answer to a `Sigma1`
/// meant for another node on the link rather than a fault.
pub fn accept_sigma1<C: crate::config::Config, const N: usize, K: KeyStore>(
    sigma1: &Sigma1<'_>,
    fabrics: &crate::fabric::FabricTable<C, N>,
    keys: &mut K,
    local: SessionId,
    session_params: Option<SessionParams>,
    randomness: &Sigma2Randomness<'_>,
    out: &mut [u8],
) -> Result<(CaseResponder, crate::msg::FabricIndex, usize)> {
    let Sigma2Randomness {
        ephemeral: ephemeral_random,
        responder: responder_random,
        resumption: resumption_random,
    } = randomness;
    let fabric = fabrics
        .find_by_destination_identifier(&sigma1.initiator_random, &sigma1.destination_id)?
        .ok_or(Error::new(ErrorCode::NoSession))?;
    let index = fabric.index;
    let noc = fabric.credentials.noc.clone();
    let icac = fabric.credentials.icac.clone();
    let fabric = fabric.clone();

    let mut responder = CaseResponder::new(local, session_params);
    let n = responder.handle_sigma1(
        sigma1,
        &fabric,
        &noc,
        icac.as_deref(),
        keys,
        ephemeral_random,
        responder_random,
        resumption_random,
        out,
    )?;
    Ok((responder, index, n))
}

// --- Initiator --------------------------------------------------------------------------

/// The commissioner or controller side of CASE (§4.14.2.3).
#[derive(Debug)]
pub struct CaseInitiator {
    session_id: SessionId,
    session_params: Option<SessionParams>,
    state: InitiatorState,
}

/// As with [`ResponderState`], the size is the state a half-finished exchange must hold.
#[expect(
    clippy::large_enum_variant,
    reason = "no allocator, and the state is transient"
)]
#[derive(Debug)]
enum InitiatorState {
    Start,
    AwaitingSigma2(Box1),
    Done,
    Failed,
}

/// The initiator's state between Sigma1 and Sigma2.
#[derive(Debug)]
struct Box1 {
    initiator_random: [u8; RANDOM_LEN],
    eph_handle: KeyHandle,
    initiator_eph_pub_key: PublicKey,
    ipk: SymmetricKey,
    fabric_index: crate::msg::FabricIndex,
    /// The fabric the Sigma1 was built for, so the responder's NOC can be held to it.
    fabric_id: crate::msg::FabricId,
    /// The node the destination identifier addressed. §4.14.2.3 step 5a requires the
    /// responder's NOC to be for exactly this node.
    peer_node_id: crate::msg::NodeId,
    transcript: Transcript,
}

impl CaseInitiator {
    /// An initiator that will listen on `session_id`.
    #[must_use]
    pub fn new(session_id: SessionId, session_params: Option<SessionParams>) -> Self {
        Self {
            session_id,
            session_params,
            state: InitiatorState::Start,
        }
    }

    /// Builds a Sigma1 addressed to `peer_node_id` on `fabric`.
    pub fn start<K: KeyStore>(
        &mut self,
        fabric: &Fabric,
        peer_node_id: crate::msg::NodeId,
        keys: &mut K,
        initiator_random: &[u8; RANDOM_LEN],
        ephemeral_random: &[u8; GROUP_SIZE_BYTES],
        out: &mut [u8],
    ) -> Result<usize> {
        if !matches!(self.state, InitiatorState::Start) {
            bail!(InvalidState)
        }
        // The destination identifier names the peer, not this node — that is the point:
        // the responder recognises itself in it without either end saying a node id aloud.
        let destination_id = crate::fabric::destination_identifier(
            &fabric.ipk,
            initiator_random,
            &fabric.root_public_key,
            fabric.fabric_id,
            peer_node_id,
        )?;
        let (eph_handle, initiator_eph_pub_key) =
            keys.generate(KeyPurpose::Ephemeral, ephemeral_random)?;

        let sigma1 = Sigma1 {
            initiator_random: *initiator_random,
            initiator_session_id: self.session_id,
            destination_id,
            initiator_eph_pub_key,
            session_params: self.session_params,
            resumption_id: None,
            initiator_resume_mic: None,
            encoded: &[],
        };
        let len = sigma1.encode(out)?.len();
        let mut transcript = Transcript::new();
        transcript.update(out.get(..len).ok_or_else(parse_error)?);

        self.state = InitiatorState::AwaitingSigma2(Box1 {
            initiator_random: *initiator_random,
            eph_handle,
            initiator_eph_pub_key,
            ipk: fabric.ipk.clone(),
            fabric_index: fabric.index,
            fabric_id: fabric.fabric_id,
            peer_node_id,
            transcript,
        });
        Ok(len)
    }

    /// Handles a Sigma2, verifies the responder, and writes a Sigma3.
    ///
    /// Returns the length of the Sigma3 and the established session — the initiator's keys
    /// are complete the moment it has sent Sigma3, before the `SigmaFinished` arrives,
    /// because the transcript is complete at that point.
    #[expect(
        clippy::too_many_arguments,
        reason = "see CaseResponder::handle_sigma1"
    )]
    pub fn handle_sigma2<K: KeyStore>(
        &mut self,
        sigma2: &Sigma2<'_>,
        fabric: &Fabric,
        root: &MatterCertificate<'_>,
        noc: &[u8],
        icac: Option<&[u8]>,
        keys: &mut K,
        at: Option<u32>,
        out: &mut [u8],
    ) -> Result<(usize, CaseOutcome)> {
        let result = self.build_sigma3(sigma2, fabric, root, noc, icac, keys, at, out);
        if result.is_err() {
            // The exchange is over either way, so the ephemeral must not outlive it: a key
            // store has a fixed number of slots and a controller that retries a failing
            // peer would otherwise exhaust them. `build_sigma3` destroys it on success.
            if let InitiatorState::AwaitingSigma2(state) = &self.state {
                let _ = keys.remove(state.eph_handle);
            }
            self.state = InitiatorState::Failed;
        }
        result
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "see CaseResponder::handle_sigma1"
    )]
    fn build_sigma3<K: KeyStore>(
        &mut self,
        sigma2: &Sigma2<'_>,
        fabric: &Fabric,
        root: &MatterCertificate<'_>,
        noc: &[u8],
        icac: Option<&[u8]>,
        keys: &mut K,
        at: Option<u32>,
        out: &mut [u8],
    ) -> Result<(usize, CaseOutcome)> {
        let InitiatorState::AwaitingSigma2(state) = &self.state else {
            bail!(InvalidState)
        };

        let shared_secret = keys.ecdh(state.eph_handle, &sigma2.responder_eph_pub_key)?;
        let s2k = sigma2_key(
            &shared_secret,
            &state.ipk,
            &sigma2.responder_random,
            &sigma2.responder_eph_pub_key,
            &state.transcript.hash(),
        )?;

        let mut plaintext = [0u8; MAX_ENCRYPTED2];
        let decrypted_len = open(&s2k, &SIGMA2_NONCE, &mut plaintext, sigma2.encrypted2)?;
        let tbe = TbeData::decode(plaintext.get(..decrypted_len).ok_or_else(parse_error)?)?;
        let peer = verify_peer(
            &tbe,
            root,
            at,
            state.fabric_id,
            Some(state.peer_node_id),
            &sigma2.responder_eph_pub_key,
            &state.initiator_eph_pub_key,
        )?;
        // A Sigma2 without a resumption ID cannot be resumed later, and the schema makes it
        // mandatory, so its absence is a malformed message rather than a missing option.
        let resumption_id = tbe.resumption_id.ok_or_else(parse_error)?;

        let mut transcript = state.transcript.clone();
        transcript.update(sigma2.encoded());

        // sigma-3-tbsdata: own chain, own ephemeral, then the peer's — the mirror of
        // Sigma2's, and the reason a Sigma2 signature cannot be replayed here.
        let mut tbs = [0u8; MAX_TBSDATA];
        let tbsdata = encode_tbsdata(
            noc,
            icac,
            &state.initiator_eph_pub_key,
            &sigma2.responder_eph_pub_key,
            &mut tbs,
        )?;
        let signature = keys.sign(fabric.operational_key, tbsdata)?;

        let tbe3 = TbeData {
            noc,
            icac,
            signature,
            resumption_id: None,
        };
        let mut encrypted = [0u8; MAX_ENCRYPTED3];
        let plaintext_len = tbe3.encode(&mut encrypted)?.len();
        let s3k = sigma3_key(&shared_secret, &state.ipk, &transcript.hash())?;
        let encrypted3 = seal(&s3k, &SIGMA3_NONCE, &mut encrypted, plaintext_len)?;

        let len = Sigma3::encode(encrypted3, out)?.len();
        transcript.update(out.get(..len).ok_or_else(parse_error)?);

        let session = session_keys(&shared_secret, &state.ipk, &transcript.hash())?;
        let fabric_index = state.fabric_index;

        keys.remove(state.eph_handle)?;
        self.state = InitiatorState::Done;

        Ok((
            len,
            CaseOutcome {
                keys: session,
                peer: peer.clone(),
                peer_session_id: sigma2.responder_session_id,
                peer_session_params: sigma2.session_params,
                resumption: ResumptionState {
                    shared_secret,
                    resumption_id,
                    fabric_index,
                    identity: peer,
                },
            },
        ))
    }

    /// Checks the responder's `SigmaFinished`.
    ///
    /// A `StatusReport` that is anything other than
    /// `SUCCESS`/`SESSION_ESTABLISHMENT_SUCCESS` means the responder rejected the Sigma3,
    /// and the session this node already derived keys for must be discarded.
    pub fn accept_finished(&mut self, report: &[u8]) -> Result<()> {
        let report = StatusReport::decode(report)?;
        if report.is_success()
            && report.secure_channel_code() == Some(SecureChannelCode::SessionEstablishmentSuccess)
        {
            Ok(())
        } else {
            self.state = InitiatorState::Failed;
            Err(Error::new(ErrorCode::InvalidState))
        }
    }

    /// Whether the exchange has failed.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self.state, InitiatorState::Failed)
    }
}

/// Verifies a peer's chain, its identity and its signature over the `tbsdata` it should have
/// signed.
///
/// `expected_fabric` is the fabric the destination identifier selected. `expected_node` is
/// set only for a Sigma2, and the asymmetry is the specification's:
///
/// * §4.14.2.3's *Validate Sigma2* step 5a — "The Fabric ID **and Node ID** SHALL match the
///   intended identity of the receiver Node, as included in the computation of the
///   Destination Identifier when generating Sigma1." Without this, any node holding a valid
///   NOC on the same fabric could answer in place of the one that was addressed, and the
///   initiator would establish a perfectly sound session with the wrong device.
/// * *Validate Sigma3* step 4a — "The **Fabric ID** SHALL match the Fabric ID matched during
///   processing of the Destination Identifier". A responder does not know which node is
///   calling it, so there is no node id to check; any node on the fabric may connect, and
///   what it is then allowed to do is `acl`'s decision.
///
/// The order matters: the chain is verified before the signature, so a forged chain is
/// rejected before its public key is trusted for anything.
fn verify_peer(
    tbe: &TbeData<'_>,
    root: &MatterCertificate<'_>,
    at: Option<u32>,
    expected_fabric: crate::msg::FabricId,
    expected_node: Option<crate::msg::NodeId>,
    signer_eph_pub_key: &PublicKey,
    peer_eph_pub_key: &PublicKey,
) -> Result<VerifiedIdentity> {
    let noc = MatterCertificate::decode(tbe.noc)?;
    let icac = match tbe.icac {
        Some(bytes) => Some(MatterCertificate::decode(bytes)?),
        None => None,
    };
    // `verify_chain` applies the DN encoding rules (step d), the fabric-id agreement between
    // the chain's certificates (step b) and the chain back to the trusted root (step c).
    let identity = verify_chain(&noc, icac.as_ref(), root, at)?;

    if identity.fabric_id != expected_fabric {
        bail!(CertPathInvalid)
    }
    if expected_node.is_some_and(|expected| identity.node_id != expected) {
        bail!(CertPathInvalid)
    }

    let mut tbs = [0u8; MAX_TBSDATA];
    let tbsdata = encode_tbsdata(
        tbe.noc,
        tbe.icac,
        signer_eph_pub_key,
        peer_eph_pub_key,
        &mut tbs,
    )?;
    if !verify(&noc.public_key, tbsdata, &tbe.signature)? {
        bail!(CertPathInvalid)
    }
    Ok(identity)
}

// --- Resumption (§4.14.2.2) ---------------------------------------------------------------

impl CaseInitiator {
    /// Builds a Sigma1 that asks to resume `previous` (§4.14.2.3).
    ///
    /// It is still a complete Sigma1: if the responder has forgotten the session, it
    /// "SHALL be processed as a Sigma1 message without any resumption fields", and the
    /// exchange falls through to the full protocol without a round trip lost. So the
    /// ephemeral key and the destination identifier are built exactly as
    /// [`CaseInitiator::start`] builds them, and the resumption fields are added on top.
    #[expect(
        clippy::too_many_arguments,
        reason = "see CaseResponder::handle_sigma1"
    )]
    pub fn start_resumption<K: KeyStore>(
        &mut self,
        fabric: &Fabric,
        peer_node_id: crate::msg::NodeId,
        previous: &ResumptionState,
        keys: &mut K,
        initiator_random: &[u8; RANDOM_LEN],
        ephemeral_random: &[u8; GROUP_SIZE_BYTES],
        out: &mut [u8],
    ) -> Result<usize> {
        let len = self.start(
            fabric,
            peer_node_id,
            keys,
            initiator_random,
            ephemeral_random,
            out,
        )?;

        // The MIC is an AEAD over *nothing* — "Resume1MIC_P[] = {}", "Resume1MIC_A[] = {}"
        // — so it proves only one thing, which is the thing that matters: that this peer
        // holds the previous session's shared secret.
        let s1rk = sigma1_resume_key(
            &previous.shared_secret,
            initiator_random,
            &previous.resumption_id,
        )?;
        let mut empty = [0u8; AEAD_MIC_LENGTH_BYTES];
        let mic = fixed::<AEAD_MIC_LENGTH_BYTES>(seal(&s1rk, &RESUME1_NONCE, &mut empty, 0)?)?;

        let mut sigma1 = Sigma1::decode(out.get(..len).ok_or_else(parse_error)?)?;
        sigma1.resumption_id = Some(previous.resumption_id);
        sigma1.initiator_resume_mic = Some(mic);

        // Re-encoding into the same buffer would alias the borrow the decode holds, so the
        // message is rebuilt beside it and copied back.
        let mut rebuilt = [0u8; MAX_SIGMA1];
        let encoded = sigma1.encode(&mut rebuilt)?;
        let new_len = encoded.len();
        out.get_mut(..new_len)
            .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?
            .copy_from_slice(encoded);

        // The transcript covers the message that actually went out, resumption fields and
        // all — it would be the wrong hash otherwise if the responder declines to resume.
        if let InitiatorState::AwaitingSigma2(state) = &mut self.state {
            state.transcript = Transcript::new();
            state
                .transcript
                .update(out.get(..new_len).ok_or_else(parse_error)?);
        }
        Ok(new_len)
    }

    /// Handles a `Sigma2_Resume`, completing a resumed session (§4.14.2.3).
    ///
    /// The peer's identity is carried over from `previous` rather than re-derived: a
    /// resumption proves possession of the old session's secret, which only the peer that
    /// authenticated then could hold, so the identity it established still stands.
    pub fn accept_resume<K: KeyStore>(
        &mut self,
        message: &Sigma2Resume,
        previous: &ResumptionState,
        keys: &mut K,
    ) -> Result<CaseOutcome> {
        let InitiatorState::AwaitingSigma2(state) = &self.state else {
            bail!(InvalidState)
        };
        let initiator_random = state.initiator_random;
        let eph_handle = state.eph_handle;
        let fabric_index = state.fabric_index;

        let s2rk = sigma2_resume_key(
            &previous.shared_secret,
            &initiator_random,
            &message.resumption_id,
        )?;
        let mut empty = [0u8; AEAD_MIC_LENGTH_BYTES];
        if let Err(e) = open(
            &s2rk,
            &RESUME2_NONCE,
            &mut empty,
            &message.sigma2_resume_mic,
        ) {
            // As in `handle_sigma2`: the ephemeral does not outlive the exchange.
            let _ = keys.remove(eph_handle);
            self.state = InitiatorState::Failed;
            return Err(e);
        }

        let session = resumption_session_keys(
            &previous.shared_secret,
            &initiator_random,
            &message.resumption_id,
        )?;
        // The ephemeral was generated for a full exchange that did not happen.
        keys.remove(eph_handle)?;
        self.state = InitiatorState::Done;

        Ok(CaseOutcome {
            keys: session,
            peer: previous.identity.clone(),
            peer_session_id: message.responder_session_id,
            peer_session_params: message.session_params,
            resumption: ResumptionState {
                // The secret carries over; only the identifier is new.
                shared_secret: previous.shared_secret.clone(),
                resumption_id: message.resumption_id,
                fabric_index,
                identity: previous.identity.clone(),
            },
        })
    }
}

impl CaseResponder {
    /// Handles a Sigma1 that asks for resumption, writing a `Sigma2_Resume` (§4.14.2.3).
    ///
    /// `previous` is the remembered state the message's `resumptionID` names — a lookup the
    /// caller does, for the same reason the fabric lookup is the caller's.
    ///
    /// If the MIC does not verify, this returns [`ErrorCode::IntegrityCheckFailed`] and the
    /// responder is **still usable**: the caller should fall back to
    /// [`CaseResponder::handle_sigma1`] with the same message, which is exactly what
    /// §4.14.2.2 requires — "the information included in the Sigma1 with Resumption message
    /// SHALL be processed as a Sigma1 message without any resumption fields."
    pub fn handle_sigma1_resumption(
        &mut self,
        sigma1: &Sigma1<'_>,
        previous: &ResumptionState,
        resumption_random: &[u8; RESUMPTION_ID_LEN],
        out: &mut [u8],
    ) -> Result<(usize, CaseOutcome)> {
        if !matches!(self.state, ResponderState::AwaitingSigma1) {
            bail!(InvalidState)
        }
        let (Some(offered), Some(mic)) = (sigma1.resumption_id, sigma1.initiator_resume_mic) else {
            // "If Msg1 contains either a resumptionID or an initiatorResumeMIC field but
            // not both" the responder does not resume.
            bail!(InvalidArgument)
        };
        if !ct_eq(&offered, &previous.resumption_id) {
            bail!(InvalidArgument)
        }

        let s1rk = sigma1_resume_key(
            &previous.shared_secret,
            &sigma1.initiator_random,
            &previous.resumption_id,
        )?;
        let mut empty = [0u8; AEAD_MIC_LENGTH_BYTES];
        // A failure here leaves the state machine untouched, so the caller can retry the
        // full path with the same Sigma1.
        open(&s1rk, &RESUME1_NONCE, &mut empty, &mic)?;

        let s2rk = sigma2_resume_key(
            &previous.shared_secret,
            &sigma1.initiator_random,
            resumption_random,
        )?;
        let mut mic_buf = [0u8; AEAD_MIC_LENGTH_BYTES];
        let sigma2_resume_mic =
            fixed::<AEAD_MIC_LENGTH_BYTES>(seal(&s2rk, &RESUME2_NONCE, &mut mic_buf, 0)?)?;

        let message = Sigma2Resume {
            resumption_id: *resumption_random,
            sigma2_resume_mic,
            responder_session_id: self.session_id,
            session_params: self.session_params,
        };
        let len = message.encode(out)?.len();

        let keys = resumption_session_keys(
            &previous.shared_secret,
            &sigma1.initiator_random,
            resumption_random,
        )?;
        self.state = ResponderState::Done;

        Ok((
            len,
            CaseOutcome {
                keys,
                peer: previous.identity.clone(),
                peer_session_id: sigma1.initiator_session_id,
                peer_session_params: sigma1.session_params,
                resumption: ResumptionState {
                    shared_secret: previous.shared_secret.clone(),
                    resumption_id: *resumption_random,
                    fabric_index: previous.fabric_index,
                    identity: previous.identity.clone(),
                },
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sc::SessionParams;

    fn a_public_key() -> PublicKey {
        let mut k = [0x11u8; PUBLIC_KEY_SIZE_BYTES];
        k[0] = 0x04;
        PublicKey::from_bytes(k)
    }

    fn full_sigma1() -> Sigma1<'static> {
        Sigma1 {
            initiator_random: [1; RANDOM_LEN],
            initiator_session_id: SessionId(0x1234),
            destination_id: [2; HASH_LEN_BYTES],
            initiator_eph_pub_key: a_public_key(),
            session_params: Some(SessionParams::announce(
                &crate::exchange::MrpParams::default(),
            )),
            resumption_id: Some([3; RESUMPTION_ID_LEN]),
            initiator_resume_mic: Some([4; AEAD_MIC_LENGTH_BYTES]),
            encoded: &[],
        }
    }

    #[test]
    fn a_nested_structure_does_not_swallow_the_fields_after_it() {
        // `session-parameter-struct` is tag 5 and the resumption fields are 6 and 7, so a
        // decoder for the nested structure that ran past its own end-of-container would
        // consume them. The symptom would be an initiator that announced its MRP parameters
        // silently losing its resumption request and falling back to a full handshake —
        // a failure with no error raised anywhere, on the path that exists to be fast.
        let sigma1 = full_sigma1();
        let mut buf = [0u8; MAX_SIGMA1];
        let len = sigma1.encode(&mut buf).expect("encode").len();
        let mut round = [0u8; MAX_SIGMA1];
        round[..len].copy_from_slice(buf.get(..len).expect("in range"));
        let decoded = Sigma1::decode(round.get(..len).expect("in range")).expect("decode");

        assert_eq!(decoded.session_params, sigma1.session_params);
        assert_eq!(decoded.resumption_id, sigma1.resumption_id);
        assert_eq!(decoded.initiator_resume_mic, sigma1.initiator_resume_mic);
        assert!(decoded.is_resumption());
    }

    #[test]
    fn a_sigma1_with_session_params_and_no_resumption_still_reads() {
        let mut sigma1 = full_sigma1();
        sigma1.resumption_id = None;
        sigma1.initiator_resume_mic = None;
        let mut buf = [0u8; MAX_SIGMA1];
        let len = sigma1.encode(&mut buf).expect("encode").len();
        let mut round = [0u8; MAX_SIGMA1];
        round[..len].copy_from_slice(buf.get(..len).expect("in range"));
        let decoded = Sigma1::decode(round.get(..len).expect("in range")).expect("decode");
        assert_eq!(decoded.session_params, sigma1.session_params);
        assert!(!decoded.is_resumption());
    }

    #[test]
    fn a_duplicate_tag_is_refused() {
        // Core §A.5.1: "All member elements within a structure SHALL have a unique tag."
        // Letting the last one win would mean two readers could disagree about a message
        // that is inside a transcript hash — and both readings would be over the same bytes,
        // so the disagreement survives every integrity check there is.
        let mut buf = [0u8; MAX_SIGMA1];
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).expect("start");
        w.octets(Tag::Context(1), &[1u8; RANDOM_LEN])
            .expect("random");
        w.unsigned(Tag::Context(2), 1).expect("session id");
        w.octets(Tag::Context(3), &[2u8; HASH_LEN_BYTES])
            .expect("destination");
        w.octets(Tag::Context(4), a_public_key().as_bytes())
            .expect("key");
        // A second initiatorRandom.
        w.octets(Tag::Context(1), &[9u8; RANDOM_LEN])
            .expect("duplicate");
        w.end_container().expect("end");
        let len = w.finish().expect("finish").len();

        let mut round = [0u8; MAX_SIGMA1];
        round[..len].copy_from_slice(buf.get(..len).expect("in range"));
        assert_eq!(
            Sigma1::decode(round.get(..len).expect("in range"))
                .map(|_| ())
                .unwrap_err()
                .code(),
            ErrorCode::TlvDuplicateTag
        );
    }

    #[test]
    fn an_unknown_tag_is_still_skipped() {
        // §4.14.2.3: "Any context-specific tags not listed in the above TLV schemas SHALL be
        // reserved for future use, and SHALL be silently ignored." Refusing duplicates must
        // not turn into refusing extensions.
        let mut buf = [0u8; MAX_SIGMA1];
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).expect("start");
        w.octets(Tag::Context(1), &[1u8; RANDOM_LEN])
            .expect("random");
        w.unsigned(Tag::Context(2), 1).expect("session id");
        w.octets(Tag::Context(3), &[2u8; HASH_LEN_BYTES])
            .expect("destination");
        w.octets(Tag::Context(4), a_public_key().as_bytes())
            .expect("key");
        w.unsigned(Tag::Context(200), 42)
            .expect("a tag from the future");
        w.end_container().expect("end");
        let len = w.finish().expect("finish").len();

        let mut round = [0u8; MAX_SIGMA1];
        round[..len].copy_from_slice(buf.get(..len).expect("in range"));
        let decoded = Sigma1::decode(round.get(..len).expect("in range")).expect("decode");
        assert_eq!(decoded.initiator_session_id, SessionId(1));
    }
}
