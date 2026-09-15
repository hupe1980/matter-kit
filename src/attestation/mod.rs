//! Device attestation: proving a device is what it says it is (Core §6.2, §6.3).
//!
//! Before a commissioner puts a device on a fabric it asks the device to prove two things:
//! that it was made by the manufacturer it claims, and that its device type passed
//! certification. §6.2.3: the procedure "serves to validate whether a particular device is
//! certified for Matter compliance and that it was legitimately produced by the certified
//! manufacturer."
//!
//! Those are two different proofs from two different authorities, and the distinction is the
//! whole design:
//!
//! * **Made by whom** is the **DAC** — a Device Attestation Certificate, burned in at
//!   manufacture and signed up a PKI rooted at a Product Attestation Authority. The device
//!   proves possession of its private key by signing the nonce the commissioner just sent.
//! * **Certified as what** is the **CD** — a Certification Declaration, signed by the CSA
//!   itself, naming the vendor, the products and the device type it covers ([`cd`]).
//!
//! Neither alone is enough. A DAC without a CD says a genuine device exists but not that it
//! was certified; a CD without a DAC is a public document anyone can copy.
//!
//! # The challenge is what stops a replay
//!
//! The signature is not over the attestation payload alone. §11.18.4.7:
//!
//! ```text
//! attestation_tbs = attestation_elements_message || attestation_challenge
//! ```
//!
//! and the challenge comes from the session — PASE's or CASE's third derived key, the one
//! that is never used to encrypt anything. So a recorded attestation response cannot be
//! replayed into a different session, because a different session has a different challenge
//! and the signature will not verify. §11.18.4.7 step 7 is explicit that the challenge
//! "SHALL NOT be included in any of the payloads conveyed" — it is proof of session
//! participation precisely because it never crosses the wire.

pub mod cd;
pub mod chain;
pub mod factory;
pub mod nocsr;
pub mod x509;

use crate::crypto::{
    HASH_LEN_BYTES, KeyHandle, KeyStore, PublicKey, Signature, SymmetricKey, verify,
};
use crate::error::{Error, ErrorCode, Result, bail};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value, set_once};

pub use cd::{CertificationElements, CertificationType, SignedData};
pub use chain::{DacChain, check_declaration_against_chain, verify_dac_chain};
pub use nocsr::{Csr, NocsrElements, build_csr, sign_nocsr, verify_nocsr};
pub use x509::{VidPid, X509Certificate};

/// "The Commissioner SHALL generate a random 32 byte attestation nonce" (§6.2.3).
pub const ATTESTATION_NONCE_LEN: usize = 32;

/// The `CSRNonce` of a NOCSR request is the same width (§11.18.4.8).
pub const CSR_NONCE_LEN: usize = 32;

/// The largest `attestation_elements_message` this crate builds or accepts.
///
/// §11.18.4.7 caps it at `RESP_MAX`, which is the interaction model's response limit. Until
/// the interaction model exists this is sized from its parts: a CD at [`cd::MAX_CD_LEN`], a
/// nonce, a timestamp, firmware information and room for the vendor-specific fields the
/// specification's own example carries.
pub const MAX_ATTESTATION_ELEMENTS: usize = cd::MAX_CD_LEN + 512;

/// `attestation-elements` (§11.18.4.6).
///
/// Vendor-specific fields are permitted — "Vendor specific information, if present, SHALL be
/// encoded using fully qualified tags" — and are *not* decoded into this structure, because
/// their meaning is the vendor's. A caller that needs them reads the TLV itself; what
/// matters here is that they survive, since they are inside the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationElements<'a> {
    /// `certification_declaration \[1\]` — "the DER-encoded octet string representation of a
    /// CMS(RFC5652)-encoded certification declaration".
    pub certification_declaration: &'a [u8],
    /// `attestation_nonce \[2\]` — "SHALL match the AttestationNonce field provided in the
    /// AttestationRequest Command that triggered the generation".
    pub attestation_nonce: [u8; ATTESTATION_NONCE_LEN],
    /// `timestamp \[3\]`, in `epoch-s`.
    pub timestamp: u32,
    /// `firmware_information \[4\]`, optional (§6.3.2).
    pub firmware_information: Option<&'a [u8]>,
}

impl<'a> AttestationElements<'a> {
    /// Encodes the elements, in the `[tag-order]` the schema requires.
    ///
    /// This produces no vendor-specific fields. A device that has them builds the TLV
    /// itself; the structure here is what a commissioner needs to *read*.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), self.certification_declaration)?;
        w.octets(Tag::Context(2), &self.attestation_nonce)?;
        w.unsigned(Tag::Context(3), u64::from(self.timestamp))?;
        if let Some(firmware) = self.firmware_information {
            w.octets(Tag::Context(4), firmware)?;
        }
        w.end_container()?;
        w.finish()
    }

    /// Decodes the elements, ignoring every field the schema does not name.
    ///
    /// "Any context-specific tags not listed in the above schema for Attestation Elements
    /// SHALL be reserved for future use, and SHALL be silently ignored if seen by a
    /// Commissioner which cannot understand them" — and the vendor-specific fields use
    /// fully-qualified tags, which are skipped the same way.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = TlvReader::new(buf);
        let Some(head) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if head.value.container() != Some(ContainerKind::Structure) || !head.tag.is_anonymous() {
            bail!(TlvWrongType)
        }

        let mut certification_declaration = None;
        let mut attestation_nonce = None;
        let mut timestamp = None;
        let mut firmware_information = None;

        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(1) => set_once(&mut certification_declaration, element.octets()?)?,
                Some(2) => {
                    let value = <[u8; ATTESTATION_NONCE_LEN]>::try_from(element.octets()?)
                        .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))?;
                    set_once(&mut attestation_nonce, value)?;
                }
                Some(3) => {
                    let value = u32::try_from(element.unsigned()?)
                        .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))?;
                    set_once(&mut timestamp, value)?;
                }
                Some(4) => set_once(&mut firmware_information, element.octets()?)?,
                // An unknown context tag, or a fully-qualified vendor tag.
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        Ok(Self {
            certification_declaration: certification_declaration
                .ok_or(Error::new(ErrorCode::TlvNotFound))?,
            attestation_nonce: attestation_nonce.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            timestamp: timestamp.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            firmware_information,
        })
    }
}

/// Signs an `attestation_elements_message` with the Device Attestation key (§11.18.4.7).
///
/// `elements` is the message **exactly as it will be sent** — not a re-encoding of it. The
/// signature covers those bytes, and a device whose encoder differs from this crate's by a
/// single octet would produce a response no commissioner could verify.
pub fn sign_attestation<K: KeyStore>(
    keys: &K,
    dac_key: KeyHandle,
    elements: &[u8],
    challenge: &SymmetricKey,
) -> Result<Signature> {
    with_tbs(elements, challenge, |tbs| keys.sign(dac_key, tbs))
}

/// Verifies an `attestation_signature` against the DAC's public key (§6.2.3.1).
pub fn verify_attestation(
    dac_public_key: &PublicKey,
    elements: &[u8],
    challenge: &SymmetricKey,
    signature: &Signature,
) -> Result<bool> {
    with_tbs(elements, challenge, |tbs| {
        verify(dac_public_key, tbs, signature)
    })
}

/// The SHA-256 of an `attestation_tbs`, which the specification's test vector states
/// separately from the signature.
///
/// Useful on its own: it is the one intermediate value that can be checked without a private
/// key, so it localises a disagreement to the concatenation rather than the signature.
pub fn attestation_tbs_hash(
    elements: &[u8],
    challenge: &SymmetricKey,
) -> Result<[u8; HASH_LEN_BYTES]> {
    with_tbs(elements, challenge, |tbs| Ok(crate::crypto::hash(tbs)))
}

/// Builds `attestation_elements_message || attestation_challenge` and hands it to `f`.
///
/// The concatenation is materialised in a stack buffer rather than fed to a streaming hash,
/// because [`KeyStore::sign`] takes a message: a key store backed by a secure element is
/// handed bytes, not a digest state.
pub(crate) fn with_tbs<T>(
    elements: &[u8],
    challenge: &SymmetricKey,
    f: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<T> {
    let key = challenge.as_bytes();
    let total = elements
        .len()
        .checked_add(key.len())
        .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
    let mut buf = [0u8; MAX_ATTESTATION_ELEMENTS + crate::crypto::SYMMETRIC_KEY_LENGTH_BYTES];
    let Some(slot) = buf.get_mut(..total) else {
        bail!(BufferTooSmall)
    };
    let (head, tail) = slot.split_at_mut(elements.len());
    head.copy_from_slice(elements);
    tail.copy_from_slice(key);
    f(slot)
}
