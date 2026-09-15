//! The Node Operational Certificate Signing Request (Core §6.4.6.1, §6.4.7, §11.18.4.8).
//!
//! Once a commissioner has attested a device, it needs the device to have an operational
//! identity on the fabric — which means the device generates an operational key pair and
//! asks for a certificate over its public half. The request is a PKCS#10
//! `CertificationRequest`, the same object every other PKI uses, and Matter wraps it in TLV
//! with a nonce and a second signature.
//!
//! # Two signatures, two different claims
//!
//! This trips people up, so it is worth being explicit. A `CSRResponse` carries two
//! signatures over two different things, made with two different keys:
//!
//! | Signature | Key | Claim |
//! |---|---|---|
//! | inside the CSR | the **new operational** key | "whoever asked for this certificate holds the private half of the key in it" |
//! | over `nocsr_tbs` | the **device attestation** key | "the genuine, attested device is the one asking, in *this* session" |
//!
//! The first is PKCS#10's proof of possession and stops a commissioner from being tricked
//! into certifying somebody else's public key. The second binds the request to the attested
//! device and to the live session, via the same attestation challenge that
//! [`super::verify_attestation`] uses — so a recorded `CSRResponse` cannot be replayed.
//!
//! §6.4.6.1's validation requires both: step 1 checks the outer signature, step 2 says "The
//! inner signature in the PKCS#10 csr sub-field … SHALL be verified, per the definition of
//! CSR signatures in PKCS #10."
//!
//! # The subject does not matter
//!
//! §6.4.6.1 step 2e: "The CSR's subject MAY be any value and the device SHOULD NOT expect
//! the final operational certificate to contain any of the CSR's subject DN attributes." The
//! commissioner's CA chooses the node id and fabric id; the CSR conveys a public key and
//! nothing else of consequence. [`CSR_SUBJECT_ORGANIZATION`] is what this crate writes,
//! matching the specification's own worked example.

use heapless::Vec;

use crate::crypto::{KeyHandle, KeyStore, PublicKey, Signature, SymmetricKey, verify};
use crate::der::{
    DerReader, DerWriter, OID_ECDSA_WITH_SHA256, OID_EXTENSION_REQUEST, OID_ORGANIZATION_NAME,
    TAG_BIT_STRING, TAG_INTEGER, TAG_SEQUENCE, TAG_SET, TAG_UTF8_STRING, context_constructed,
    ecdsa_sig_value_to_raw,
};
use crate::error::{Error, ErrorCode, Result, bail};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value, set_once};

use super::CSR_NONCE_LEN;

/// `attributes \[0\]` in a `CertificationRequestInfo`.
const TAG_ATTRIBUTES: u8 = context_constructed(0);

/// The subject this crate puts in a CSR: `O = CSA`, as Appendix F.3's example does.
///
/// Any value is legal (§6.4.6.1 step 2e) and none of it reaches the issued certificate, so
/// the only thing worth optimising for is that a commissioner's PKCS#10 tooling recognises
/// the shape.
pub const CSR_SUBJECT_ORGANIZATION: &str = "CSA";

/// The largest CSR this crate builds or accepts.
///
/// One P-256 key, a minimal subject, the empty `extensionRequest` attribute and a signature.
/// The specification's own example is 221 octets.
pub const MAX_CSR_LEN: usize = 320;

/// The largest `nocsr_elements_message`, sized from a CSR plus a nonce plus the three
/// vendor-reserved fields.
pub const MAX_NOCSR_ELEMENTS: usize = MAX_CSR_LEN + 256;

/// The most a `vendor_reserved` field may carry here.
pub const MAX_VENDOR_RESERVED: usize = 64;

fn malformed() -> Error {
    Error::new(ErrorCode::DerMalformed)
}

/// Builds and signs a PKCS#10 `CertificationRequest` for an operational key (RFC 2986).
///
/// The key never leaves the [`KeyStore`]: the `certificationRequestInfo` is built, handed to
/// [`KeyStore::sign`], and the signature written beside it. A device whose operational key
/// lives in a secure element produces a CSR without the key ever being in RAM.
pub fn build_csr<'b, K: KeyStore>(
    keys: &K,
    operational_key: KeyHandle,
    buf: &'b mut [u8],
) -> Result<&'b [u8]> {
    let public_key = keys.public_key(operational_key)?;

    // The tbs has to exist as bytes before it can be signed, and it is also the first field
    // of the output — so it is built into its own buffer and copied in.
    let mut tbs_buf = [0u8; MAX_CSR_LEN];
    let tbs = certification_request_info(&public_key, &mut tbs_buf)?;
    let signature = keys.sign(operational_key, tbs)?;

    let mut w = DerWriter::new(buf);
    let mark = w.mark();
    // Reverse order: signature, signatureAlgorithm, certificationRequestInfo.
    let sig_mark = w.mark();
    w.ecdsa_sig_value(signature.as_bytes())?;
    w.byte(0)?;
    w.header(TAG_BIT_STRING, sig_mark)?;
    w.algorithm_identifier(OID_ECDSA_WITH_SHA256)?;
    w.slice(tbs)?;
    w.header(TAG_SEQUENCE, mark)?;
    if w.len() > MAX_CSR_LEN {
        return Err(malformed());
    }
    Ok(w.finish())
}

/// Writes a `CertificationRequestInfo` — the part of a CSR that is signed.
///
/// ```text
/// CertificationRequestInfo ::= SEQUENCE {
///     version       INTEGER { v1(0) },
///     subject       Name,
///     subjectPKInfo SubjectPublicKeyInfo,
///     attributes    \[0\] IMPLICIT SET OF Attribute }
/// ```
///
/// `attributes` is not optional in PKCS#10, so an empty `extensionRequest` is written rather
/// than nothing — which is what the specification's example carries, and what makes the
/// encoding agree with it byte for byte.
fn certification_request_info<'b>(public_key: &PublicKey, buf: &'b mut [u8]) -> Result<&'b [u8]> {
    let mut w = DerWriter::new(buf);
    let mark = w.mark();

    // Reverse order, so read this block bottom-up against the ASN.1 above.
    let attrs = w.mark();
    let attr = w.mark();
    // Attribute ::= SEQUENCE { type OID, values SET OF ANY }, with one empty SEQUENCE.
    let values = w.mark();
    let empty = w.mark();
    w.header(TAG_SEQUENCE, empty)?;
    w.header(TAG_SET, values)?;
    w.primitive(crate::der::TAG_OID, OID_EXTENSION_REQUEST)?;
    w.header(TAG_SEQUENCE, attr)?;
    w.header(TAG_ATTRIBUTES, attrs)?;

    w.subject_public_key_info(public_key.as_bytes())?;

    // Name ::= SEQUENCE OF RDN, one RDN holding `organizationName = "CSA"`.
    let name = w.mark();
    let rdn = w.mark();
    let atv = w.mark();
    w.primitive(TAG_UTF8_STRING, CSR_SUBJECT_ORGANIZATION.as_bytes())?;
    w.primitive(crate::der::TAG_OID, OID_ORGANIZATION_NAME)?;
    w.header(TAG_SEQUENCE, atv)?;
    w.header(TAG_SET, rdn)?;
    w.header(TAG_SEQUENCE, name)?;

    // version v1 = 0.
    w.primitive(TAG_INTEGER, &[0])?;

    w.header(TAG_SEQUENCE, mark)?;
    Ok(w.finish())
}

/// A parsed PKCS#10 `CertificationRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Csr<'a> {
    /// The `certificationRequestInfo`, verbatim — the bytes the inner signature covers.
    pub tbs: &'a [u8],
    /// The `subjectPKInfo`'s key: the operational public key a NOC will be issued over.
    pub public_key: PublicKey,
    /// The inner signature, converted to the `r || s` of §3.5.3.
    pub signature: Signature,
}

impl<'a> Csr<'a> {
    /// Parses a CSR, accepting only the profile §6.4.7 describes.
    ///
    /// The subject is skipped rather than read: "The CSR's subject MAY be any value", so
    /// there is nothing here to constrain and nothing worth reporting.
    pub fn parse(der: &'a [u8]) -> Result<Self> {
        if der.len() > MAX_CSR_LEN {
            return Err(malformed());
        }
        let mut outer = DerReader::new(der);
        let mut request = outer.expect_sequence()?;
        outer.finish()?;

        let tbs_element = request.expect(TAG_SEQUENCE)?;
        let mut tbs = tbs_element.content_reader();
        if tbs.expect_uint()? != 0 {
            // PKCS#10 v1 is the only version.
            return Err(malformed());
        }
        // subject: any Name.
        let _ = tbs.expect(TAG_SEQUENCE)?;

        // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }.
        let mut spki = tbs.expect_sequence()?;
        let mut algo = spki.expect_sequence()?;
        algo.expect_oid(crate::der::OID_EC_PUBLIC_KEY)?;
        algo.expect_oid(crate::der::OID_PRIME256V1)?;
        algo.finish()?;
        let public_key = PublicKey::from_slice(spki.expect(TAG_BIT_STRING)?.bit_string_octets()?)?;
        spki.finish()?;

        // attributes [0] IMPLICIT SET OF Attribute — required by PKCS#10, contents ignored.
        let _ = tbs.take_if(TAG_ATTRIBUTES)?;
        tbs.finish()?;

        let mut sig_algo = request.expect_sequence()?;
        sig_algo.expect_oid(OID_ECDSA_WITH_SHA256)?;
        sig_algo.finish()?;

        let signature_der = request.expect(TAG_BIT_STRING)?.bit_string_octets()?;
        request.finish()?;
        let mut raw = [0u8; 64];
        ecdsa_sig_value_to_raw(signature_der, &mut raw)?;

        Ok(Self {
            tbs: tbs_element.raw,
            public_key,
            signature: Signature::from_bytes(raw),
        })
    }

    /// Verifies the CSR's own signature — PKCS#10's proof that the requester holds the
    /// private half of the key it is asking to have certified.
    ///
    /// §6.4.6.1 validation step 2. Without it a commissioner could be induced to issue a
    /// NOC over a public key belonging to somebody else, which would hand that somebody a
    /// certified identity on the fabric.
    pub fn verify(&self) -> Result<bool> {
        verify(&self.public_key, self.tbs, &self.signature)
    }
}

/// `nocsr-elements` (§11.18.4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NocsrElements<'a> {
    /// `csr \[1\]` — the DER of the PKCS#10 request.
    pub csr: &'a [u8],
    /// `CSRNonce \[2\]` — "SHALL match the CSR Nonce field in the corresponding CSRRequest".
    pub csr_nonce: [u8; CSR_NONCE_LEN],
    /// `vendor_reserved1 \[3\]`, `vendor_reserved2 [4]`, `vendor_reserved3 [5]` — vendor
    /// information a commissioner "MAY ignore", kept in order.
    pub vendor_reserved: Vec<(u8, &'a [u8]), 3>,
}

impl<'a> NocsrElements<'a> {
    /// The elements for a CSR and nonce, with no vendor-reserved fields.
    #[must_use]
    pub fn new(csr: &'a [u8], csr_nonce: [u8; CSR_NONCE_LEN]) -> Self {
        Self {
            csr,
            csr_nonce,
            vendor_reserved: Vec::new(),
        }
    }

    /// Adds a `vendor_reserved` field, whose tag must be 3, 4 or 5.
    pub fn with_vendor_reserved(mut self, tag: u8, value: &'a [u8]) -> Result<Self> {
        if !(3..=5).contains(&tag) || value.len() > MAX_VENDOR_RESERVED {
            bail!(InvalidArgument)
        }
        if self.vendor_reserved.iter().any(|(seen, _)| *seen == tag) {
            bail!(TlvDuplicateTag)
        }
        self.vendor_reserved
            .push((tag, value))
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        Ok(self)
    }

    /// Encodes the elements, in the `[tag-order]` the schema requires.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.octets(Tag::Context(1), self.csr)?;
        w.octets(Tag::Context(2), &self.csr_nonce)?;
        // `[tag-order]`: the vendor fields ascend, whatever order they were added in. Their
        // tags are unique — `with_vendor_reserved` and `decode` both refuse a repeat — so an
        // unstable sort cannot reorder equal keys, because there are none.
        let mut sorted = self.vendor_reserved.clone();
        sorted.sort_unstable_by_key(|(tag, _)| *tag);
        for (tag, value) in &sorted {
            w.octets(Tag::Context(*tag), value)?;
        }
        w.end_container()?;
        w.finish()
    }

    /// Decodes the elements.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = TlvReader::new(buf);
        let Some(head) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if head.value.container() != Some(ContainerKind::Structure) || !head.tag.is_anonymous() {
            bail!(TlvWrongType)
        }

        let mut csr = None;
        let mut csr_nonce = None;
        let mut vendor_reserved = Vec::new();

        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(1) => set_once(&mut csr, element.octets()?)?,
                Some(2) => {
                    let value = <[u8; CSR_NONCE_LEN]>::try_from(element.octets()?)
                        .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))?;
                    set_once(&mut csr_nonce, value)?;
                }
                Some(tag @ 3..=5) => {
                    // §A.5.1 again: `vendor_reserved1..3` are three named optional fields,
                    // not a repeated one, so a second instance of any of them is malformed.
                    if vendor_reserved.iter().any(|(seen, _)| *seen == tag) {
                        bail!(TlvDuplicateTag)
                    }
                    vendor_reserved
                        .push((tag, element.octets()?))
                        .map_err(|_| Error::new(ErrorCode::NoSpace))?;
                }
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        Ok(Self {
            csr: csr.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            csr_nonce: csr_nonce.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            vendor_reserved,
        })
    }

    /// The CSR inside, parsed.
    pub fn parse_csr(&self) -> Result<Csr<'a>> {
        Csr::parse(self.csr)
    }
}

/// Signs a `nocsr_elements_message` with the Device Attestation key (§11.18.4.9).
///
/// `nocsr_tbs = nocsr_elements_message || attestation_challenge`, exactly as the attestation
/// response is built — the same construction, a different payload, so the two cannot be
/// substituted for one another only because the payloads differ. That is worth noticing: the
/// separation rests on the TLV schemas, not on a domain separator.
pub fn sign_nocsr<K: KeyStore>(
    keys: &K,
    dac_key: KeyHandle,
    elements: &[u8],
    challenge: &SymmetricKey,
) -> Result<Signature> {
    super::with_tbs(elements, challenge, |tbs| keys.sign(dac_key, tbs))
}

/// Verifies the outer signature of a `CSRResponse` (§6.4.6.1 validation step 1).
pub fn verify_nocsr(
    dac_public_key: &PublicKey,
    elements: &[u8],
    challenge: &SymmetricKey,
    signature: &Signature,
) -> Result<bool> {
    super::with_tbs(elements, challenge, |tbs| {
        verify(dac_public_key, tbs, signature)
    })
}
