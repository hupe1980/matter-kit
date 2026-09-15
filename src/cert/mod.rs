//! Matter operational certificates (Core §6.1, §6.5).
//!
//! A Matter certificate is an X.509 certificate with everything Matter does not use taken
//! out, re-encoded as TLV. It is not a different certificate: "every Matter certificate can
//! be represented as a corresponding X.509 certificate. However, the converse is not true."
//! The point of the exercise is size — §6.1.3 caps a Matter certificate at
//! [`CERT_TLV_MAX`] octets against [`CERT_DER_MAX`] for the DER it stands for.
//!
//! # The signature is not over these bytes
//!
//! This is the one thing about the format that surprises everybody, and it is worth
//! knowing before reading any of the rest. §6.5.2:
//!
//! > The signature included in a Matter certificate is the signatureValue of the
//! > corresponding X.509 certificate, **not** a signature of the preceding Matter TLV data
//! > in the Matter certificate structure. Accordingly, validating the signature in a Matter
//! > certificate entails its logical conversion to the corresponding X.509 certificate to
//! > recover the original tbsCertificate.
//!
//! So verifying a certificate means regenerating DER, which is why the DN module keeps the
//! `UTF8String`/`PrintableString` distinction ([`dn`]) and why element order is preserved
//! rather than normalised: both change the DER, and a changed DER is a signature that does
//! not verify. Parsing and validating the *encoding* — what this module does — is
//! independent of that, and is a prerequisite for it.
//!
//! # What this module does
//!
//! [`MatterCertificate::decode`] parses, borrowing from the buffer; [`encode`] writes the
//! same certificate back; [`MatterCertificate::validate`] applies §6.5.6.3's DN rules and
//! §6.5.12's extension rules for the certificate's [`CertType`].
//!
//! # What survives a round trip, exactly
//!
//! Everything the DER depends on: the order of DN attributes, the order of extensions, the
//! `UTF8String`/`PrintableString` distinction, the serial number's leading zeros, and every
//! value. The specification's three worked examples re-encode byte for byte
//! (`tests/cert_vectors.rs`).
//!
//! One thing does not: **integer width**. Matter TLV lets the same value be encoded in 1, 2,
//! 4 or 8 octets, and [`encode`] always writes the narrowest — as every Matter
//! implementation does, and as all three published examples already are. A certificate that
//! arrived with a wider encoding therefore re-encodes to fewer bytes.
//!
//! That is safe, and the reason is worth being precise about: the signature is not over
//! these bytes. §6.5.2's DER is regenerated from the *values* — a `matter-node-id` becomes a
//! fixed 16-character hex string regardless of how many octets the TLV spent on it — so a
//! width change cannot alter the `tbsCertificate` and cannot affect verification. Nothing
//! else about the encoding is normalised, because everything else can.
//!
//! [`encode`]: MatterCertificate::encode

pub mod chain;
pub mod der;
pub mod dn;

use heapless::Vec;

pub use chain::{VerifiedIdentity, verify_chain, verify_self_signed};
pub use dn::{DistinguishedName, DnAttribute, DnAttributeKind, DnValue, MAX_NOC_CATS, MAX_RDNS};

use crate::crypto::{PUBLIC_KEY_SIZE_BYTES, PublicKey, SIGNATURE_LEN_BYTES, Signature};
use crate::error::{Error, ErrorCode, Result};
use crate::msg::{FabricId, NodeId};
use crate::tlv::{Tag, TlvReader, TlvWriter, Value};

/// "Wherever Matter Operational Certificate Encoding representation is used, all
/// certificates SHALL NOT be longer than 400 bytes in their TLV form" (§6.1.3).
pub const CERT_TLV_MAX: usize = 400;

/// "All certificates SHALL NOT be longer than 600 bytes in their uncompressed DER format"
/// (§6.1.3).
pub const CERT_DER_MAX: usize = 600;

/// "implementations SHALL admit serial numbers up to 20 octets in length" (§6.5.4).
pub const SERIAL_MAX: usize = 20;

/// A key identifier is "the 160-bit SHA-1 hash of the certificate's subject public key
/// value" — 20 octets, and §6.1.2 makes the length normative.
pub const KEY_ID_LEN: usize = 20;

/// Turns 20 arbitrary octets — a key identifier, a digest, a counter — into serial number
/// content a Matter certificate will accept.
///
/// §6.5.4's `serial-num` **is** the DER INTEGER's content, carried through unchanged, so a
/// digest handed straight to it is wrong twice:
///
/// - the top bit of the first octet is the INTEGER's *sign*, so half of all digests encode a
///   **negative** serial. §6.5.4 says a Matter certificate "follows the same limitation on
///   admissible serial numbers as in [RFC 5280]", and RFC 5280 §4.1.2.2 is where that
///   limitation is written: "The serial number MUST be a positive integer";
/// - DER requires the shortest two's-complement form, so `0x00` followed by an octet below
///   `0x80` — or `0xFF` followed by one at or above it — is a redundant sign octet and not
///   valid content at all. One digest in 256, so a chain that builds every time until it does
///   not.
///
/// Clearing the sign bit answers both, and lifting a resulting `0x00` to `0x01` keeps the
/// value out of the redundant-zero case.
///
/// ```
/// use matter_kit::cert::positive_serial;
///
/// // Negative: the sign bit is cleared.
/// assert_eq!(positive_serial([0xFF; 20])[0], 0x7F);
/// // Redundant leading zero: lifted out of it.
/// let mut digest = [0x00; 20];
/// digest[1] = 0x01;
/// assert_eq!(positive_serial(digest)[0], 0x01);
/// // Already valid: unchanged.
/// let mut digest = [0x00; 20];
/// digest[0] = 0x42;
/// assert_eq!(positive_serial(digest), digest);
/// ```
#[must_use]
pub const fn positive_serial(mut bytes: [u8; SERIAL_MAX]) -> [u8; SERIAL_MAX] {
    bytes[0] &= 0x7F;
    if bytes[0] == 0x00 {
        bytes[0] = 0x01;
    }
    bytes
}

/// How many extensions one certificate's list can hold here: the five defined ones plus
/// room for future extensions, which "MAY be more than one".
pub const MAX_EXTENSIONS: usize = 8;

/// How many `key-purpose-id` values an extended key usage array can hold: Table 93 defines
/// six, and the extension "SHALL NOT contain more than one instance".
pub const MAX_KEY_PURPOSES: usize = 6;

/// The `not-after` value that stands for X.509's `99991231235959Z` — "no well-defined
/// expiration date" (§6.5.7).
pub const NOT_AFTER_NEVER: u32 = 0;

// --- The small enumerations of §6.5.5, §6.5.8, §6.5.9 ------------------------------------

/// `signature-algorithm` (§6.5.5, Table 86).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    /// `ecdsa-with-sha256` — the only value, because §3.5.3 has only one signature scheme.
    EcdsaWithSha256 = 1,
}

/// `public-key-algorithm` (§6.5.8, Table 90).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PublicKeyAlgorithm {
    /// `ec-pub-key` — `id-ecPublicKey`.
    EcPubKey = 1,
}

/// `elliptic-curve-id` (§6.5.9, Table 91).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EllipticCurveId {
    /// `prime256v1` — NIST P-256, the curve of §3.5.1.
    Prime256V1 = 1,
}

/// `key-purpose-id` (§6.5.11.3, Table 93).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum KeyPurposeId {
    /// `id-kp-serverAuth`.
    ServerAuth = 1,
    /// `id-kp-clientAuth`.
    ClientAuth = 2,
    /// `id-kp-codeSigning`.
    CodeSigning = 3,
    /// `id-kp-emailProtection`.
    EmailProtection = 4,
    /// `id-kp-timeStamping`.
    TimeStamping = 5,
    /// `id-kp-OCSPSigning`.
    OcspSigning = 6,
}

impl KeyPurposeId {
    /// The value a TLV element carries, or `None` if it is outside Table 93 — which
    /// §6.5.14 lists as invalidating the certificate.
    #[must_use]
    pub const fn from_value(value: u64) -> Option<Self> {
        Some(match value {
            1 => Self::ServerAuth,
            2 => Self::ClientAuth,
            3 => Self::CodeSigning,
            4 => Self::EmailProtection,
            5 => Self::TimeStamping,
            6 => Self::OcspSigning,
            _ => return None,
        })
    }
}

bitflags::bitflags! {
    /// `key-usage-flag` (§6.5.11.2) — "derived as a logical OR of all key-usage-flag
    /// values that apply to the corresponding public key".
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KeyUsage: u16 {
        /// `digitalSignature`.
        const DIGITAL_SIGNATURE = 0x0001;
        /// `nonRepudiation`.
        const NON_REPUDIATION = 0x0002;
        /// `keyEncipherment`.
        const KEY_ENCIPHERMENT = 0x0004;
        /// `dataEncipherment`.
        const DATA_ENCIPHERMENT = 0x0008;
        /// `keyAgreement`.
        const KEY_AGREEMENT = 0x0010;
        /// `keyCertSign`.
        const KEY_CERT_SIGN = 0x0020;
        /// `CRLSign`.
        const CRL_SIGN = 0x0040;
        /// `encipherOnly`.
        const ENCIPHER_ONLY = 0x0080;
        /// `decipherOnly`.
        const DECIPHER_ONLY = 0x0100;
    }
}

/// `basic-constraints` (§6.5.11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConstraints {
    /// Whether the subject is a CA. "SHALL be encoded regardless of the value."
    pub is_ca: bool,
    /// The maximum depth of a path through this certificate. "MAY be present only when
    /// is-ca == true."
    pub path_len_constraint: Option<u8>,
}

/// One entry of a certificate's extensions list (§6.5.11).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Extension<'a> {
    /// `basic-cnstr [1]`.
    BasicConstraints(BasicConstraints),
    /// `key-usage [2]`.
    KeyUsage(KeyUsage),
    /// `extended-key-usage [3]`, in the order it appeared.
    ExtendedKeyUsage(Vec<KeyPurposeId, MAX_KEY_PURPOSES>),
    /// `subject-key-id [4]` — the SHA-1 of the subject public key (§6.5.11.4).
    SubjectKeyId([u8; KEY_ID_LEN]),
    /// `authority-key-id [5]` — the SHA-1 of the key that signed this certificate.
    AuthorityKeyId([u8; KEY_ID_LEN]),
    /// `future-extension [6]`, kept verbatim.
    ///
    /// An implementation that does not understand one still needs its bytes: they are part
    /// of the DER the signature was computed over. "If ignored extension is marked as
    /// critical then validation of the corresponding Matter certificate SHALL fail" — which
    /// is a decision for the DER layer, since criticality is not encoded here.
    Future(&'a [u8]),
}

impl Extension<'_> {
    /// The context tag this entry encodes under.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::BasicConstraints(_) => TAG_BASIC_CONSTRAINTS,
            Self::KeyUsage(_) => TAG_KEY_USAGE,
            Self::ExtendedKeyUsage(_) => TAG_EXTENDED_KEY_USAGE,
            Self::SubjectKeyId(_) => TAG_SUBJECT_KEY_ID,
            Self::AuthorityKeyId(_) => TAG_AUTHORITY_KEY_ID,
            Self::Future(_) => TAG_FUTURE_EXTENSION,
        }
    }
}

/// The extensions of a Matter certificate, **in the order they were encoded** (§6.5.11).
///
/// The order is not incidental. §6.5.12: "The extensions SHALL appear in the same order in
/// the Matter certificate and in the corresponding X.509 certificates" — and an X.509
/// certificate's extension order is the issuer's choice. Sorting them here would change the
/// DER regenerated from this certificate, and a changed DER is a signature that does not
/// verify. So this is a sequence with accessors, not a record with fields.
///
/// What *is* enforced is uniqueness: "The extensions list SHALL NOT contain more than one
/// instance of a particular extension", with `future-extension` excepted because "There MAY
/// be more than one".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extensions<'a> {
    entries: Vec<Extension<'a>, MAX_EXTENSIONS>,
}

impl<'a> Extensions<'a> {
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends an extension, refusing a second instance of anything but `future-extension`.
    pub fn push(&mut self, extension: Extension<'a>) -> Result<()> {
        let tag = extension.tag();
        if tag != TAG_FUTURE_EXTENSION && self.entries.iter().any(|e| e.tag() == tag) {
            return Err(invalid());
        }
        self.entries.push(extension).map_err(|_| invalid())
    }

    /// The entries, in encoding order.
    #[must_use]
    pub fn entries(&self) -> &[Extension<'a>] {
        &self.entries
    }

    /// The `basic-cnstr` extension, if present.
    #[must_use]
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        self.entries.iter().find_map(|e| match e {
            Extension::BasicConstraints(v) => Some(*v),
            _ => None,
        })
    }

    /// The `key-usage` extension, if present.
    #[must_use]
    pub fn key_usage(&self) -> Option<KeyUsage> {
        self.entries.iter().find_map(|e| match e {
            Extension::KeyUsage(v) => Some(*v),
            _ => None,
        })
    }

    /// The `extended-key-usage` array, if present, in its encoded order.
    #[must_use]
    pub fn extended_key_usage(&self) -> Option<&[KeyPurposeId]> {
        self.entries.iter().find_map(|e| match e {
            Extension::ExtendedKeyUsage(v) => Some(v.as_slice()),
            _ => None,
        })
    }

    /// The `subject-key-id`, if present.
    #[must_use]
    pub fn subject_key_id(&self) -> Option<[u8; KEY_ID_LEN]> {
        self.entries.iter().find_map(|e| match e {
            Extension::SubjectKeyId(v) => Some(*v),
            _ => None,
        })
    }

    /// The `authority-key-id`, if present.
    #[must_use]
    pub fn authority_key_id(&self) -> Option<[u8; KEY_ID_LEN]> {
        self.entries.iter().find_map(|e| match e {
            Extension::AuthorityKeyId(v) => Some(*v),
            _ => None,
        })
    }

    /// Every `future-extension`, in order.
    pub fn future(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.entries.iter().filter_map(|e| match e {
            Extension::Future(bytes) => Some(*bytes),
            _ => None,
        })
    }
}

/// What a certificate is, as its subject DN declares (§6.5.6.2, Table 89).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertType {
    /// A Node Operational Certificate: the subject carries a `matter-node-id`.
    Noc,
    /// An Intermediate CA Certificate: a `matter-icac-id`.
    Icac,
    /// A Root CA Certificate: a `matter-rcac-id`.
    Rcac,
    /// A Vendor Verification Signer Certificate: a `matter-vvs-id`.
    Vvsc,
    /// A firmware signing certificate: a `matter-firmware-signing-id`. Matter "doesn't
    /// specify how firmware images are signed", but the format has room for it.
    FirmwareSigning,
}

/// A decoded Matter certificate, borrowing from the buffer it was read from.
///
/// Fields appear in the tag order §6.5.2's `[tag-order]` requires, which is also the order
/// [`MatterCertificate::encode`] writes them in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatterCertificate<'a> {
    /// `serial-num [1]` — at most [`SERIAL_MAX`] octets, and not normalised: a leading zero
    /// is part of the DER.
    pub serial_number: &'a [u8],
    /// `sig-algo [2]`.
    pub signature_algorithm: SignatureAlgorithm,
    /// `issuer [3]`.
    pub issuer: DistinguishedName<'a>,
    /// `not-before [4]` — a Matter epoch-s time.
    pub not_before: u32,
    /// `not-after [5]`, where [`NOT_AFTER_NEVER`] means no expiry.
    pub not_after: u32,
    /// `subject [6]`.
    pub subject: DistinguishedName<'a>,
    /// `pub-key-algo [7]`.
    pub public_key_algorithm: PublicKeyAlgorithm,
    /// `ec-curve-id [8]`.
    pub elliptic_curve_id: EllipticCurveId,
    /// `ec-pub-key [9]` — an uncompressed SEC 1 point.
    pub public_key: PublicKey,
    /// `extensions [10]`.
    pub extensions: Extensions<'a>,
    /// `signature [11]` — `r || s`, and *not* a signature over this TLV; see the module
    /// documentation.
    pub signature: Signature,
}

// The context tags of §6.5.2.
const TAG_SERIAL_NUM: u8 = 1;
const TAG_SIG_ALGO: u8 = 2;
const TAG_ISSUER: u8 = 3;
const TAG_NOT_BEFORE: u8 = 4;
const TAG_NOT_AFTER: u8 = 5;
const TAG_SUBJECT: u8 = 6;
const TAG_PUB_KEY_ALGO: u8 = 7;
const TAG_EC_CURVE_ID: u8 = 8;
const TAG_EC_PUB_KEY: u8 = 9;
const TAG_EXTENSIONS: u8 = 10;
const TAG_SIGNATURE: u8 = 11;

// The context tags of §6.5.11's `extension` choice.
const TAG_BASIC_CONSTRAINTS: u8 = 1;
const TAG_KEY_USAGE: u8 = 2;
const TAG_EXTENDED_KEY_USAGE: u8 = 3;
const TAG_SUBJECT_KEY_ID: u8 = 4;
const TAG_AUTHORITY_KEY_ID: u8 = 5;
const TAG_FUTURE_EXTENSION: u8 = 6;

// The context tags of §6.5.11.1's `basic-constraints`.
const TAG_IS_CA: u8 = 1;
const TAG_PATH_LEN_CONSTRAINT: u8 = 2;

fn invalid() -> Error {
    Error::new(ErrorCode::CertInvalid)
}

impl<'a> MatterCertificate<'a> {
    /// Decodes a certificate from its TLV form.
    ///
    /// This checks the *encoding* — element order, types, ranges, and the enumerations of
    /// Tables 86, 90, 91 and 93 — which is §6.5.14's list of what invalidates a
    /// certificate. It does not check the DN or extension rules that depend on what kind of
    /// certificate this is; that is [`MatterCertificate::validate`], because the caller
    /// usually knows which kind it is expecting and a mismatch is a different error.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        if buf.len() > CERT_TLV_MAX {
            return Err(invalid());
        }
        let mut reader = TlvReader::new(buf);
        let Some(head) = reader.next_element()? else {
            return Err(invalid());
        };
        if head.value.container() != Some(crate::tlv::ContainerKind::Structure)
            || !head.tag.is_anonymous()
        {
            return Err(invalid());
        }

        let mut serial_number = None;
        let mut signature_algorithm = None;
        let mut issuer = None;
        let mut not_before = None;
        let mut not_after = None;
        let mut subject = None;
        let mut public_key_algorithm = None;
        let mut elliptic_curve_id = None;
        let mut public_key = None;
        let mut extensions = None;
        let mut signature = None;

        // `[tag-order]`: "Matter certificate elements are encoded in a wrong order" is one
        // of §6.5.14's invalidating errors, so the tags must ascend strictly.
        let mut previous_tag = 0u8;

        loop {
            let Some(element) = reader.next_element()? else {
                return Err(invalid());
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            let Some(tag) = element.tag.context() else {
                return Err(invalid());
            };
            if tag <= previous_tag {
                return Err(invalid());
            }
            previous_tag = tag;

            match tag {
                TAG_SERIAL_NUM => {
                    let octets = element.octets()?;
                    if octets.len() > SERIAL_MAX {
                        return Err(invalid());
                    }
                    serial_number = Some(octets);
                }
                TAG_SIG_ALGO => {
                    signature_algorithm = Some(match element.unsigned()? {
                        1 => SignatureAlgorithm::EcdsaWithSha256,
                        _ => return Err(invalid()),
                    });
                }
                TAG_ISSUER => {
                    expect_list(&element)?;
                    issuer = Some(DistinguishedName::decode(&mut reader)?);
                }
                TAG_NOT_BEFORE => not_before = Some(u32_of(&element)?),
                TAG_NOT_AFTER => not_after = Some(u32_of(&element)?),
                TAG_SUBJECT => {
                    expect_list(&element)?;
                    subject = Some(DistinguishedName::decode(&mut reader)?);
                }
                TAG_PUB_KEY_ALGO => {
                    public_key_algorithm = Some(match element.unsigned()? {
                        1 => PublicKeyAlgorithm::EcPubKey,
                        _ => return Err(invalid()),
                    });
                }
                TAG_EC_CURVE_ID => {
                    elliptic_curve_id = Some(match element.unsigned()? {
                        1 => EllipticCurveId::Prime256V1,
                        _ => return Err(invalid()),
                    });
                }
                TAG_EC_PUB_KEY => {
                    let octets = element.octets()?;
                    if octets.len() != PUBLIC_KEY_SIZE_BYTES {
                        return Err(invalid());
                    }
                    public_key = Some(PublicKey::from_slice(octets)?);
                }
                TAG_EXTENSIONS => {
                    expect_list(&element)?;
                    extensions = Some(decode_extensions(&mut reader)?);
                }
                TAG_SIGNATURE => {
                    let octets = element.octets()?;
                    if octets.len() != SIGNATURE_LEN_BYTES {
                        return Err(invalid());
                    }
                    signature = Some(Signature::from_slice(octets)?);
                }
                // "Matter certificate structure includes elements that are not defined in
                // this section" — §6.5.14.
                _ => return Err(invalid()),
            }
        }
        reader.finish()?;

        Ok(Self {
            serial_number: serial_number.ok_or_else(invalid)?,
            signature_algorithm: signature_algorithm.ok_or_else(invalid)?,
            issuer: issuer.ok_or_else(invalid)?,
            not_before: not_before.ok_or_else(invalid)?,
            not_after: not_after.ok_or_else(invalid)?,
            subject: subject.ok_or_else(invalid)?,
            public_key_algorithm: public_key_algorithm.ok_or_else(invalid)?,
            elliptic_curve_id: elliptic_curve_id.ok_or_else(invalid)?,
            public_key: public_key.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
            signature: signature.ok_or_else(invalid)?,
        })
    }

    /// Encodes the certificate back to TLV, returning the written bytes.
    ///
    /// The output is identical to the input a [`MatterCertificate::decode`] came from:
    /// tag order is fixed by the schema, integer widths are the minimum TLV would ever
    /// use, and nothing here normalises a value.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut writer = TlvWriter::new(buf);
        writer.start_structure(Tag::Anonymous)?;
        writer.octets(Tag::Context(TAG_SERIAL_NUM), self.serial_number)?;
        writer.unsigned(
            Tag::Context(TAG_SIG_ALGO),
            self.signature_algorithm as u8 as u64,
        )?;
        self.issuer.encode(&mut writer, Tag::Context(TAG_ISSUER))?;
        writer.unsigned(Tag::Context(TAG_NOT_BEFORE), u64::from(self.not_before))?;
        writer.unsigned(Tag::Context(TAG_NOT_AFTER), u64::from(self.not_after))?;
        self.subject
            .encode(&mut writer, Tag::Context(TAG_SUBJECT))?;
        writer.unsigned(
            Tag::Context(TAG_PUB_KEY_ALGO),
            self.public_key_algorithm as u8 as u64,
        )?;
        writer.unsigned(
            Tag::Context(TAG_EC_CURVE_ID),
            self.elliptic_curve_id as u8 as u64,
        )?;
        writer.octets(Tag::Context(TAG_EC_PUB_KEY), self.public_key.as_bytes())?;
        encode_extensions(&self.extensions, &mut writer)?;
        writer.octets(Tag::Context(TAG_SIGNATURE), self.signature.as_bytes())?;
        writer.end_container()?;
        let written = writer.finish()?;
        if written.len() > CERT_TLV_MAX {
            return Err(invalid());
        }
        Ok(written)
    }

    /// What kind of certificate this is, from the Matter-specific attribute in its subject
    /// DN (§6.5.6.2).
    ///
    /// `None` when the subject carries none of them, or more than one kind — both of which
    /// §6.5.14 lists as invalidating ("Certificate Subject DN encodes matter-node-id and
    /// matter-rcac-id, which contradict each other").
    #[must_use]
    pub fn cert_type(&self) -> Option<CertType> {
        use DnAttributeKind as K;
        let candidates = [
            (K::MatterNodeId, CertType::Noc),
            (K::MatterIcacId, CertType::Icac),
            (K::MatterRcacId, CertType::Rcac),
            (K::MatterVvsId, CertType::Vvsc),
            (K::MatterFirmwareSigningId, CertType::FirmwareSigning),
        ];
        let mut found = None;
        for (kind, cert_type) in candidates {
            match self.subject.count(kind) {
                0 => {}
                1 if found.is_none() => found = Some(cert_type),
                _ => return None,
            }
        }
        found
    }

    /// The subject's `matter-node-id`, for a NOC.
    #[must_use]
    pub fn node_id(&self) -> Option<NodeId> {
        self.subject.node_id()
    }

    /// The subject's `matter-fabric-id`, which a NOC always has and a CA certificate may.
    #[must_use]
    pub fn fabric_id(&self) -> Option<FabricId> {
        self.subject.fabric_id()
    }

    /// Whether this certificate is a CA — `basic-constraints.is-ca`.
    #[must_use]
    pub fn is_ca(&self) -> bool {
        self.extensions
            .basic_constraints()
            .is_some_and(|bc| bc.is_ca)
    }

    /// Whether `at` (Matter epoch-s) falls inside the validity window (§6.5.7).
    ///
    /// A `not-after` of [`NOT_AFTER_NEVER`] stands for `99991231235959Z`, so it never
    /// expires.
    #[must_use]
    pub const fn is_valid_at(&self, at: u32) -> bool {
        at >= self.not_before && (self.not_after == NOT_AFTER_NEVER || at <= self.not_after)
    }

    /// Applies the rules of §6.5.6.3 and §6.5.12 for this certificate's type.
    ///
    /// Separate from [`MatterCertificate::decode`] because the two answer different
    /// questions: decode asks whether these bytes are a certificate at all, validate asks
    /// whether the certificate they encode is one Matter would accept.
    pub fn validate(&self) -> Result<()> {
        let Some(cert_type) = self.cert_type() else {
            return Err(invalid());
        };
        self.validate_as(cert_type)
    }

    /// Applies the §6.5 rules for a *specific* expected type.
    ///
    /// Use this where the caller knows what it asked for — a trusted root, say — so that a
    /// certificate of the wrong kind is refused rather than validated on its own terms.
    pub fn validate_as(&self, cert_type: CertType) -> Result<()> {
        if self.cert_type() != Some(cert_type) {
            return Err(invalid());
        }
        self.validate_subject_dn(cert_type)?;
        self.validate_extensions(cert_type)
    }

    /// §6.5.6.3's per-type subject DN rules.
    fn validate_subject_dn(&self, cert_type: CertType) -> Result<()> {
        use DnAttributeKind as K;
        let dn = &self.subject;

        // "All implementations SHALL reject Matter certificates with more than 5 RDNs in a
        // single DN" — `DistinguishedName` cannot hold more, so this holds by
        // construction; the issuer is checked for emptiness the same way on decode.
        if dn.is_empty() || self.issuer.is_empty() {
            return Err(invalid());
        }

        // Rules shared by every type: nothing may carry an attribute another type owns.
        let forbidden: &[K] = match cert_type {
            CertType::Noc => &[K::MatterIcacId, K::MatterRcacId, K::MatterVvsId],
            CertType::Icac => &[
                K::MatterNodeId,
                K::MatterRcacId,
                K::MatterNocCat,
                K::MatterVvsId,
            ],
            CertType::Rcac => &[
                K::MatterNodeId,
                K::MatterIcacId,
                K::MatterNocCat,
                K::MatterVvsId,
            ],
            CertType::Vvsc => &[K::MatterNodeId, K::MatterFabricId, K::MatterNocCat],
            CertType::FirmwareSigning => &[],
        };
        for kind in forbidden {
            if dn.count(*kind) != 0 {
                return Err(invalid());
            }
        }

        match cert_type {
            CertType::Noc => {
                // "SHALL encode exactly one matter-node-id", in the Operational range.
                let Some(node_id) = dn.node_id() else {
                    return Err(invalid());
                };
                if !node_id.is_operational() {
                    return Err(invalid());
                }
                // "SHALL encode exactly one matter-fabric-id", not 0.
                let Some(fabric_id) = dn.fabric_id() else {
                    return Err(invalid());
                };
                if fabric_id.0 == 0 {
                    return Err(invalid());
                }
                validate_noc_cats(dn)?;
            }
            CertType::Icac | CertType::Rcac => {
                // "MAY encode at most one matter-fabric-id … SHALL NOT be 0."
                match dn.count(K::MatterFabricId) {
                    0 => {}
                    1 => {
                        if dn.fabric_id().is_none_or(|f| f.0 == 0) {
                            return Err(invalid());
                        }
                    }
                    _ => return Err(invalid()),
                }
            }
            CertType::Vvsc | CertType::FirmwareSigning => {}
        }
        Ok(())
    }

    /// §6.5.12's per-type extension rules.
    fn validate_extensions(&self, cert_type: CertType) -> Result<()> {
        let ext = &self.extensions;

        // Every type: both key identifiers "SHALL be present".
        let (Some(subject_key_id), Some(authority_key_id)) =
            (ext.subject_key_id(), ext.authority_key_id())
        else {
            return Err(invalid());
        };

        let Some(basic) = ext.basic_constraints() else {
            return Err(invalid());
        };
        // "The path-len-constraint MAY be present only when is-ca == true."
        if !basic.is_ca && basic.path_len_constraint.is_some() {
            return Err(invalid());
        }

        let Some(key_usage) = ext.key_usage() else {
            return Err(invalid());
        };

        let expected_eku: Option<&[KeyPurposeId]> = match cert_type {
            CertType::Noc => Some(&[KeyPurposeId::ServerAuth, KeyPurposeId::ClientAuth]),
            CertType::FirmwareSigning => Some(&[KeyPurposeId::CodeSigning]),
            // "For Matter ICA Certificate and Matter Root CA Certificate: the extended key
            // usage extension SHALL NOT be present." §6.5.12 says nothing about a VVSC's,
            // so it is not constrained either way.
            CertType::Icac | CertType::Rcac => Some(&[]),
            CertType::Vvsc => None,
        };

        match cert_type {
            CertType::Noc | CertType::Vvsc | CertType::FirmwareSigning => {
                if basic.is_ca {
                    return Err(invalid());
                }
                // "SHALL be encoded with exactly one flag: digitalSignature."
                if key_usage != KeyUsage::DIGITAL_SIGNATURE {
                    return Err(invalid());
                }
            }
            CertType::Icac | CertType::Rcac => {
                if !basic.is_ca {
                    return Err(invalid());
                }
                // "at least the two flags keyCertSign and CRLSign … MAY include a third
                // flag: digitalSignature. No additional flags are permitted."
                let required = KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN;
                let permitted = required | KeyUsage::DIGITAL_SIGNATURE;
                if !key_usage.contains(required) || !permitted.contains(key_usage) {
                    return Err(invalid());
                }
                // "For the Matter Root CA Certificate the authority key identifier
                // extension SHALL be equal to the subject key identifier extension."
                if cert_type == CertType::Rcac && authority_key_id != subject_key_id {
                    return Err(invalid());
                }
            }
        }

        if let Some(expected) = expected_eku {
            match (expected.is_empty(), ext.extended_key_usage()) {
                (true, None) => {}
                (true, Some(_)) => return Err(invalid()),
                (false, None) => return Err(invalid()),
                (false, Some(present)) => {
                    // The order is the X.509 certificate's, not a fixed one — the spec's
                    // own NOC example encodes [clientAuth, serverAuth] — so compare as
                    // sets of the required length.
                    if present.len() != expected.len()
                        || !expected.iter().all(|p| present.contains(p))
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(())
    }
}

/// "Multiple matter-cat-id with the same identifier value and different version numbers, or
/// any matter-cat-id with a version number of 0" invalidate a certificate (§6.5.14).
fn validate_noc_cats(dn: &DistinguishedName<'_>) -> Result<()> {
    // At most three, which the DN's own capacity does not bound — five RDNs could hold
    // four.
    if dn.count(DnAttributeKind::MatterNocCat) > MAX_NOC_CATS {
        return Err(invalid());
    }
    let cats = dn.noc_cats();
    for (index, cat) in cats.iter().enumerate() {
        if !cat.is_valid() {
            return Err(invalid());
        }
        // "Each matter-noc-cat attribute present, if any, SHALL encode a different CASE
        // Authenticated Tag identifier (upper 16 bits of value)".
        if cats.get(index.saturating_add(1)..).is_some_and(|rest| {
            rest.iter()
                .any(|other| other.identifier() == cat.identifier())
        }) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn expect_list(element: &crate::tlv::Element<'_>) -> Result<()> {
    if element.value.container() == Some(crate::tlv::ContainerKind::List) {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// "not-before or not-after field is longer than 32-bits" invalidates (§6.5.14).
fn u32_of(element: &crate::tlv::Element<'_>) -> Result<u32> {
    u32::try_from(element.unsigned()?).map_err(|_| invalid())
}

fn decode_extensions<'a>(reader: &mut TlvReader<'a>) -> Result<Extensions<'a>> {
    let mut out = Extensions::new();
    loop {
        let Some(element) = reader.next_element()? else {
            return Err(invalid());
        };
        if element.value == Value::EndOfContainer {
            break;
        }
        let Some(tag) = element.tag.context() else {
            return Err(invalid());
        };
        let extension = match tag {
            TAG_BASIC_CONSTRAINTS => {
                if element.value.container() != Some(crate::tlv::ContainerKind::Structure) {
                    return Err(invalid());
                }
                Extension::BasicConstraints(decode_basic_constraints(reader)?)
            }
            TAG_KEY_USAGE => {
                let raw = u16::try_from(element.unsigned()?).map_err(|_| invalid())?;
                // "key-usage field of the Key Usage Extension has undefined flags"
                // invalidates the certificate (§6.5.14).
                Extension::KeyUsage(KeyUsage::from_bits(raw).ok_or_else(invalid)?)
            }
            TAG_EXTENDED_KEY_USAGE => {
                if element.value.container() != Some(crate::tlv::ContainerKind::Array) {
                    return Err(invalid());
                }
                Extension::ExtendedKeyUsage(decode_key_purposes(reader)?)
            }
            TAG_SUBJECT_KEY_ID => Extension::SubjectKeyId(key_id(&element)?),
            TAG_AUTHORITY_KEY_ID => Extension::AuthorityKeyId(key_id(&element)?),
            TAG_FUTURE_EXTENSION => Extension::Future(element.octets()?),
            _ => return Err(invalid()),
        };
        // `push` is what refuses a duplicate and a list that is too long.
        out.push(extension)?;
    }
    Ok(out)
}

fn key_id(element: &crate::tlv::Element<'_>) -> Result<[u8; KEY_ID_LEN]> {
    // "subject-key-id or authority-key-id field is different from 20 octets" invalidates.
    <[u8; KEY_ID_LEN]>::try_from(element.octets()?).map_err(|_| invalid())
}

fn decode_basic_constraints(reader: &mut TlvReader<'_>) -> Result<BasicConstraints> {
    let mut is_ca = None;
    let mut path_len_constraint = None;
    let mut previous_tag = 0u8;
    loop {
        let Some(element) = reader.next_element()? else {
            return Err(invalid());
        };
        if element.value == Value::EndOfContainer {
            break;
        }
        let Some(tag) = element.tag.context() else {
            return Err(invalid());
        };
        if tag <= previous_tag {
            return Err(invalid());
        }
        previous_tag = tag;
        match tag {
            TAG_IS_CA => is_ca = Some(element.bool()?),
            TAG_PATH_LEN_CONSTRAINT => {
                path_len_constraint =
                    Some(u8::try_from(element.unsigned()?).map_err(|_| invalid())?);
            }
            _ => return Err(invalid()),
        }
    }
    Ok(BasicConstraints {
        // "The is-ca field SHALL be encoded regardless of the value."
        is_ca: is_ca.ok_or_else(invalid)?,
        path_len_constraint,
    })
}

fn decode_key_purposes(reader: &mut TlvReader<'_>) -> Result<Vec<KeyPurposeId, MAX_KEY_PURPOSES>> {
    let mut out = Vec::new();
    loop {
        let Some(element) = reader.next_element()? else {
            return Err(invalid());
        };
        if element.value == Value::EndOfContainer {
            break;
        }
        if !element.tag.is_anonymous() {
            return Err(invalid());
        }
        let purpose = KeyPurposeId::from_value(element.unsigned()?).ok_or_else(invalid)?;
        out.push(purpose).map_err(|_| invalid())?;
    }
    // `ARRAY [ length 1.. ]`.
    if out.is_empty() {
        return Err(invalid());
    }
    Ok(out)
}

fn encode_extensions(extensions: &Extensions<'_>, writer: &mut TlvWriter<'_>) -> Result<()> {
    writer.start_list(Tag::Context(TAG_EXTENSIONS))?;
    for extension in extensions.entries() {
        let tag = Tag::Context(extension.tag());
        match extension {
            Extension::BasicConstraints(basic) => {
                writer.start_structure(tag)?;
                writer.bool(Tag::Context(TAG_IS_CA), basic.is_ca)?;
                if let Some(path_len) = basic.path_len_constraint {
                    writer.unsigned(Tag::Context(TAG_PATH_LEN_CONSTRAINT), u64::from(path_len))?;
                }
                writer.end_container()?;
            }
            Extension::KeyUsage(key_usage) => {
                writer.unsigned(tag, u64::from(key_usage.bits()))?;
            }
            Extension::ExtendedKeyUsage(purposes) => {
                writer.start_array(tag)?;
                for purpose in purposes {
                    writer.unsigned(Tag::Anonymous, *purpose as u8 as u64)?;
                }
                writer.end_container()?;
            }
            Extension::SubjectKeyId(id) | Extension::AuthorityKeyId(id) => {
                writer.octets(tag, id)?;
            }
            Extension::Future(bytes) => writer.octets(tag, bytes)?,
        }
    }
    writer.end_container()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::CaseAuthenticatedTag;

    const KEY_A: [u8; KEY_ID_LEN] = [0xAA; KEY_ID_LEN];
    const KEY_B: [u8; KEY_ID_LEN] = [0xBB; KEY_ID_LEN];

    /// A P-256 point that is never parsed as one here — `decode` checks the length, and
    /// only the crypto layer checks the curve.
    fn a_public_key() -> PublicKey {
        let mut bytes = [0x11u8; PUBLIC_KEY_SIZE_BYTES];
        bytes[0] = 0x04;
        PublicKey::from_bytes(bytes)
    }

    fn extensions(entries: &[Extension<'static>]) -> Extensions<'static> {
        let mut out = Extensions::new();
        for entry in entries {
            out.push(entry.clone()).expect("fits");
        }
        out
    }

    /// A well-formed certificate of `cert_type`, which each test then breaks in one way.
    fn cert(cert_type: CertType) -> MatterCertificate<'static> {
        let mut subject = DistinguishedName::new();
        let mut ext = heapless::Vec::<Extension<'static>, MAX_EXTENSIONS>::new();
        let is_ca = matches!(cert_type, CertType::Icac | CertType::Rcac);

        match cert_type {
            CertType::Noc => {
                subject.push(DnAttribute::node_id(NodeId(1))).expect("push");
                subject
                    .push(DnAttribute::fabric_id(FabricId(0xFAB0_0000_0000_001D)))
                    .expect("push");
            }
            CertType::Icac => subject
                .push(DnAttribute::uint(DnAttributeKind::MatterIcacId, 3))
                .expect("push"),
            CertType::Rcac => subject
                .push(DnAttribute::uint(DnAttributeKind::MatterRcacId, 1))
                .expect("push"),
            CertType::Vvsc => subject
                .push(DnAttribute::uint(DnAttributeKind::MatterVvsId, 7))
                .expect("push"),
            CertType::FirmwareSigning => subject
                .push(DnAttribute::uint(
                    DnAttributeKind::MatterFirmwareSigningId,
                    9,
                ))
                .expect("push"),
        }

        ext.push(Extension::BasicConstraints(BasicConstraints {
            is_ca,
            path_len_constraint: None,
        }))
        .expect("fits");
        ext.push(Extension::KeyUsage(if is_ca {
            KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN
        } else {
            KeyUsage::DIGITAL_SIGNATURE
        }))
        .expect("fits");
        match cert_type {
            CertType::Noc => {
                let mut purposes = Vec::new();
                purposes.push(KeyPurposeId::ServerAuth).expect("fits");
                purposes.push(KeyPurposeId::ClientAuth).expect("fits");
                ext.push(Extension::ExtendedKeyUsage(purposes))
                    .expect("fits");
            }
            CertType::FirmwareSigning => {
                let mut purposes = Vec::new();
                purposes.push(KeyPurposeId::CodeSigning).expect("fits");
                ext.push(Extension::ExtendedKeyUsage(purposes))
                    .expect("fits");
            }
            _ => {}
        }
        ext.push(Extension::SubjectKeyId(KEY_A)).expect("fits");
        // A root is its own authority; everything else is signed by something above it.
        ext.push(Extension::AuthorityKeyId(if cert_type == CertType::Rcac {
            KEY_A
        } else {
            KEY_B
        }))
        .expect("fits");

        let mut issuer = DistinguishedName::new();
        issuer
            .push(DnAttribute::uint(DnAttributeKind::MatterRcacId, 1))
            .expect("push");

        MatterCertificate {
            serial_number: &[0x01, 0x02],
            signature_algorithm: SignatureAlgorithm::EcdsaWithSha256,
            issuer,
            not_before: 100,
            not_after: 200,
            subject,
            public_key_algorithm: PublicKeyAlgorithm::EcPubKey,
            elliptic_curve_id: EllipticCurveId::Prime256V1,
            public_key: a_public_key(),
            extensions: extensions(&ext),
            signature: Signature::from_bytes([0x22; SIGNATURE_LEN_BYTES]),
        }
    }

    #[test]
    fn the_built_certificates_are_valid_to_begin_with() {
        // Otherwise every rejection test below would pass for the wrong reason.
        for cert_type in [
            CertType::Noc,
            CertType::Icac,
            CertType::Rcac,
            CertType::Vvsc,
            CertType::FirmwareSigning,
        ] {
            let c = cert(cert_type);
            assert_eq!(c.cert_type(), Some(cert_type), "{cert_type:?}");
            c.validate()
                .unwrap_or_else(|e| panic!("{cert_type:?}: {e}"));
        }
    }

    #[test]
    fn a_noc_with_fabric_id_zero_is_refused() {
        // §6.5.6.3: "The matter-fabric-id attribute's value SHALL NOT be 0."
        let mut c = cert(CertType::Noc);
        c.subject = DistinguishedName::new();
        c.subject
            .push(DnAttribute::node_id(NodeId(1)))
            .expect("push");
        c.subject
            .push(DnAttribute::fabric_id(FabricId(0)))
            .expect("push");
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_noc_without_a_fabric_id_is_refused() {
        // "The subject DN SHALL encode exactly one matter-fabric-id attribute."
        let mut c = cert(CertType::Noc);
        c.subject = DistinguishedName::new();
        c.subject
            .push(DnAttribute::node_id(NodeId(1)))
            .expect("push");
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_noc_whose_node_id_is_not_operational_is_refused() {
        // A group Node ID is a legal 64-bit value and an illegal NOC subject.
        let mut c = cert(CertType::Noc);
        c.subject = DistinguishedName::new();
        c.subject
            .push(DnAttribute::node_id(NodeId(0xFFFF_FFFF_FFFF_0001)))
            .expect("push");
        c.subject
            .push(DnAttribute::fabric_id(FabricId(1)))
            .expect("push");
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_subject_that_claims_two_certificate_types_has_no_type() {
        // §6.5.14: "Certificate Subject DN encodes matter-node-id and matter-rcac-id,
        // which contradict each other."
        let mut c = cert(CertType::Noc);
        c.subject
            .push(DnAttribute::uint(DnAttributeKind::MatterRcacId, 1))
            .expect("push");
        assert_eq!(c.cert_type(), None);
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_ca_certificate_must_say_it_is_one() {
        // "CA certificate doesn't have Basic Constraints Extension is-ca field set to
        // 'true'" — §6.5.14.
        for cert_type in [CertType::Icac, CertType::Rcac] {
            let mut c = cert(cert_type);
            c.extensions = extensions(&[
                Extension::BasicConstraints(BasicConstraints {
                    is_ca: false,
                    path_len_constraint: None,
                }),
                Extension::KeyUsage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN),
                Extension::SubjectKeyId(KEY_A),
                Extension::AuthorityKeyId(KEY_A),
            ]);
            assert!(c.validate().is_err(), "{cert_type:?}");
        }
    }

    #[test]
    fn a_leaf_certificate_must_not_claim_to_be_a_ca() {
        let mut c = cert(CertType::Noc);
        c.extensions = extensions(&[
            Extension::BasicConstraints(BasicConstraints {
                is_ca: true,
                path_len_constraint: None,
            }),
            Extension::KeyUsage(KeyUsage::DIGITAL_SIGNATURE),
            Extension::SubjectKeyId(KEY_A),
            Extension::AuthorityKeyId(KEY_B),
        ]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_path_len_constraint_needs_is_ca() {
        // "The path-len-constraint MAY be present only when is-ca == true."
        let mut c = cert(CertType::Noc);
        c.extensions = extensions(&[
            Extension::BasicConstraints(BasicConstraints {
                is_ca: false,
                path_len_constraint: Some(0),
            }),
            Extension::KeyUsage(KeyUsage::DIGITAL_SIGNATURE),
            Extension::SubjectKeyId(KEY_A),
            Extension::AuthorityKeyId(KEY_B),
        ]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_roots_authority_key_id_must_equal_its_subject_key_id() {
        // §6.5.12, and the reason a root is recognisable as self-issued.
        let mut c = cert(CertType::Rcac);
        c.extensions = extensions(&[
            Extension::BasicConstraints(BasicConstraints {
                is_ca: true,
                path_len_constraint: None,
            }),
            Extension::KeyUsage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN),
            Extension::SubjectKeyId(KEY_A),
            Extension::AuthorityKeyId(KEY_B),
        ]);
        assert!(c.validate().is_err());
        // An ICAC's, by contrast, is expected to differ.
        cert(CertType::Icac).validate().expect("icac");
    }

    #[test]
    fn the_key_usage_flags_a_type_allows_are_exactly_those() {
        // A NOC: "exactly one flag: digitalSignature."
        for usage in [
            KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_AGREEMENT,
            KeyUsage::KEY_CERT_SIGN,
            KeyUsage::empty(),
        ] {
            let mut c = cert(CertType::Noc);
            let mut ext = Extensions::new();
            ext.push(Extension::BasicConstraints(BasicConstraints {
                is_ca: false,
                path_len_constraint: None,
            }))
            .expect("fits");
            ext.push(Extension::KeyUsage(usage)).expect("fits");
            let mut purposes = Vec::new();
            purposes.push(KeyPurposeId::ServerAuth).expect("fits");
            purposes.push(KeyPurposeId::ClientAuth).expect("fits");
            ext.push(Extension::ExtendedKeyUsage(purposes))
                .expect("fits");
            ext.push(Extension::SubjectKeyId(KEY_A)).expect("fits");
            ext.push(Extension::AuthorityKeyId(KEY_B)).expect("fits");
            c.extensions = ext;
            assert!(c.validate().is_err(), "{usage:?}");
        }
    }

    #[test]
    fn a_ca_may_add_digital_signature_but_nothing_else() {
        let base = KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN;
        for (usage, ok) in [
            (base, true),
            (base | KeyUsage::DIGITAL_SIGNATURE, true),
            (base | KeyUsage::KEY_AGREEMENT, false),
            (KeyUsage::KEY_CERT_SIGN, false),
            (KeyUsage::CRL_SIGN, false),
        ] {
            let mut c = cert(CertType::Icac);
            c.extensions = extensions(&[
                Extension::BasicConstraints(BasicConstraints {
                    is_ca: true,
                    path_len_constraint: None,
                }),
                Extension::KeyUsage(usage),
                Extension::SubjectKeyId(KEY_A),
                Extension::AuthorityKeyId(KEY_B),
            ]);
            assert_eq!(c.validate().is_ok(), ok, "{usage:?}");
        }
    }

    #[test]
    fn a_ca_must_not_carry_an_extended_key_usage() {
        // "For Matter ICA Certificate and Matter Root CA Certificate: the extended key
        // usage extension SHALL NOT be present."
        let mut c = cert(CertType::Icac);
        let mut purposes = Vec::new();
        purposes.push(KeyPurposeId::ServerAuth).expect("fits");
        c.extensions = extensions(&[
            Extension::BasicConstraints(BasicConstraints {
                is_ca: true,
                path_len_constraint: None,
            }),
            Extension::KeyUsage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN),
            Extension::ExtendedKeyUsage(purposes),
            Extension::SubjectKeyId(KEY_A),
            Extension::AuthorityKeyId(KEY_B),
        ]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_nocs_extended_key_usage_is_both_purposes_in_either_order() {
        // "exactly two key-purpose-id values: serverAuth and clientAuth" — and the spec's
        // own NOC example encodes them the other way round, so order is not the rule.
        for (purposes, ok) in [
            (
                &[KeyPurposeId::ServerAuth, KeyPurposeId::ClientAuth][..],
                true,
            ),
            (
                &[KeyPurposeId::ClientAuth, KeyPurposeId::ServerAuth][..],
                true,
            ),
            (&[KeyPurposeId::ServerAuth][..], false),
            (
                &[KeyPurposeId::ServerAuth, KeyPurposeId::CodeSigning][..],
                false,
            ),
            (
                &[
                    KeyPurposeId::ServerAuth,
                    KeyPurposeId::ClientAuth,
                    KeyPurposeId::CodeSigning,
                ][..],
                false,
            ),
        ] {
            let mut c = cert(CertType::Noc);
            let mut list = Vec::new();
            for p in purposes {
                list.push(*p).expect("fits");
            }
            c.extensions = extensions(&[
                Extension::BasicConstraints(BasicConstraints {
                    is_ca: false,
                    path_len_constraint: None,
                }),
                Extension::KeyUsage(KeyUsage::DIGITAL_SIGNATURE),
                Extension::ExtendedKeyUsage(list),
                Extension::SubjectKeyId(KEY_A),
                Extension::AuthorityKeyId(KEY_B),
            ]);
            assert_eq!(c.validate().is_ok(), ok, "{purposes:?}");
        }
    }

    #[test]
    fn a_missing_key_identifier_is_refused() {
        // Both "SHALL be present", for every type.
        for present in [
            &[Extension::SubjectKeyId(KEY_A)][..],
            &[Extension::AuthorityKeyId(KEY_B)][..],
            &[][..],
        ] {
            let mut c = cert(CertType::Icac);
            let mut ext = Extensions::new();
            ext.push(Extension::BasicConstraints(BasicConstraints {
                is_ca: true,
                path_len_constraint: None,
            }))
            .expect("fits");
            ext.push(Extension::KeyUsage(
                KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN,
            ))
            .expect("fits");
            for e in present {
                ext.push(e.clone()).expect("fits");
            }
            c.extensions = ext;
            assert!(c.validate().is_err());
        }
    }

    #[test]
    fn a_duplicate_extension_is_refused_on_push() {
        // "The extensions list SHALL NOT contain more than one instance of a particular
        // extension."
        let mut ext = Extensions::new();
        ext.push(Extension::KeyUsage(KeyUsage::DIGITAL_SIGNATURE))
            .expect("first");
        assert!(
            ext.push(Extension::KeyUsage(KeyUsage::CRL_SIGN)).is_err(),
            "a second key-usage"
        );
        // But "There MAY be more than one" future-extension.
        ext.push(Extension::Future(&[1])).expect("first future");
        ext.push(Extension::Future(&[2])).expect("second future");
        assert_eq!(ext.future().count(), 2);
    }

    #[test]
    fn noc_cats_must_be_versioned_and_distinct() {
        let cases: &[(&[u32], bool)] = &[
            (&[0xABCD_0002], true),
            (&[0xABCD_0004, 0xABCE_0018, 0xABCF_0002], true),
            // §6.5.14: "any matter-cat-id with a version number of 0".
            (&[0xABCD_0000], false),
            // "the same CASE Authenticated Tag value with two different version numbers".
            (&[0xABCD_0004, 0xABCD_0002], false),
        ];
        for (cats, ok) in cases {
            let mut c = cert(CertType::Noc);
            c.subject = DistinguishedName::new();
            c.subject
                .push(DnAttribute::node_id(NodeId(1)))
                .expect("push");
            c.subject
                .push(DnAttribute::fabric_id(FabricId(1)))
                .expect("push");
            for cat in *cats {
                c.subject
                    .push(DnAttribute::noc_cat(CaseAuthenticatedTag(*cat)))
                    .expect("push");
            }
            assert_eq!(c.validate().is_ok(), *ok, "{cats:02x?}");
        }
    }

    #[test]
    fn a_dn_refuses_a_sixth_attribute() {
        // "All implementations SHALL reject Matter certificates with more than 5 RDNs in a
        // single DN."
        let mut dn = DistinguishedName::new();
        for _ in 0..MAX_RDNS {
            dn.push(DnAttribute::string(DnAttributeKind::CommonName, "x"))
                .expect("fits");
        }
        assert!(
            dn.push(DnAttribute::string(DnAttributeKind::CommonName, "x"))
                .is_err()
        );
    }

    #[test]
    fn a_round_trip_survives_a_printable_string_attribute() {
        // The +0x80 marker has to come back, or the regenerated DER uses the wrong ASN.1
        // string type and the signature fails.
        let mut c = cert(CertType::Rcac);
        c.subject = DistinguishedName::new();
        c.subject
            .push(DnAttribute::uint(DnAttributeKind::MatterRcacId, 1))
            .expect("push");
        c.subject
            .push(DnAttribute::printable(
                DnAttributeKind::CommonName,
                "ROOT CA HOME 3",
            ))
            .expect("push");

        let mut buf = [0u8; CERT_TLV_MAX];
        let bytes = c.encode(&mut buf).expect("encode");
        // Tag 1 + 0x80 = 129, so the control octet's tag byte is 0x81.
        assert!(
            bytes.contains(&0x81),
            "the printable-string tag is on the wire"
        );

        let mut round = [0u8; CERT_TLV_MAX];
        round[..bytes.len()].copy_from_slice(bytes);
        let decoded = MatterCertificate::decode(&round[..bytes.len()]).expect("decode");
        let attribute = decoded.subject.attributes()[1];
        assert!(attribute.printable_string);
        assert_eq!(attribute.as_str(), Some("ROOT CA HOME 3"));
        assert_eq!(decoded.subject, c.subject);
    }

    #[test]
    fn the_printable_string_form_only_exists_where_table_87_defines_it() {
        // domain-component is an IA5String and the Matter-specific types are integers, so
        // neither has a +0x80 spelling.
        let mut dn = DistinguishedName::new();
        assert!(
            dn.push(DnAttribute::printable(
                DnAttributeKind::DomainComponent,
                "example"
            ))
            .is_err()
        );
        assert!(
            dn.push(DnAttribute {
                kind: DnAttributeKind::MatterNodeId,
                printable_string: true,
                value: DnValue::Uint(1),
            })
            .is_err()
        );
        // And a string type may not carry a scalar, nor a scalar type a string.
        assert!(
            dn.push(DnAttribute::uint(DnAttributeKind::CommonName, 1))
                .is_err()
        );
        assert!(
            dn.push(DnAttribute::string(DnAttributeKind::MatterNodeId, "x"))
                .is_err()
        );
    }

    #[test]
    fn a_noc_cat_above_32_bits_is_refused() {
        // Table 85 gives matter-noc-cat 4 octets; the others 8.
        let mut dn = DistinguishedName::new();
        assert!(
            dn.push(DnAttribute::uint(
                DnAttributeKind::MatterNocCat,
                0x1_0000_0000
            ))
            .is_err()
        );
        dn.push(DnAttribute::uint(
            DnAttributeKind::MatterNodeId,
            0x0123_4567_89AB_CDEF,
        ))
        .expect("64 bits is fine for a node id");
    }

    #[test]
    fn a_serial_number_longer_than_20_octets_is_refused() {
        // §6.5.4, and §6.5.14 lists it explicitly.
        let mut c = cert(CertType::Rcac);
        const LONG: [u8; SERIAL_MAX + 1] = [0x01; SERIAL_MAX + 1];
        c.serial_number = &LONG;
        let mut buf = [0u8; CERT_TLV_MAX];
        // The writer will happily emit it; the decoder is what must refuse it.
        let bytes = c.encode(&mut buf).expect("encode");
        let mut round = [0u8; CERT_TLV_MAX];
        round[..bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            MatterCertificate::decode(&round[..bytes.len()])
                .map(|_| ())
                .unwrap_err()
                .code(),
            ErrorCode::CertInvalid
        );
    }

    #[test]
    fn elements_out_of_order_are_refused() {
        // §6.5.2's `[tag-order]`, and §6.5.14's "Matter certificate elements are encoded in
        // a wrong order". Written by hand because the encoder cannot produce it.
        let mut buf = [0u8; 64];
        let mut writer = TlvWriter::new(&mut buf);
        writer.start_structure(Tag::Anonymous).expect("start");
        writer
            .unsigned(Tag::Context(TAG_SIG_ALGO), 1)
            .expect("sig-algo first");
        writer
            .octets(Tag::Context(TAG_SERIAL_NUM), &[1])
            .expect("serial second");
        writer.end_container().expect("end");
        let bytes = writer.finish().expect("finish");
        let mut round = [0u8; 64];
        round[..bytes.len()].copy_from_slice(bytes);
        assert!(MatterCertificate::decode(&round[..bytes.len()]).is_err());
    }

    #[test]
    fn an_undefined_algorithm_or_curve_is_refused() {
        // §6.5.14 lists each of these as invalidating.
        for (tag, value) in [
            (TAG_SIG_ALGO, 2u64),
            (TAG_PUB_KEY_ALGO, 2),
            (TAG_EC_CURVE_ID, 2),
        ] {
            let mut buf = [0u8; 64];
            let mut writer = TlvWriter::new(&mut buf);
            writer.start_structure(Tag::Anonymous).expect("start");
            writer.unsigned(Tag::Context(tag), value).expect("value");
            writer.end_container().expect("end");
            let bytes = writer.finish().expect("finish");
            let mut round = [0u8; 64];
            round[..bytes.len()].copy_from_slice(bytes);
            assert!(
                MatterCertificate::decode(&round[..bytes.len()]).is_err(),
                "tag {tag} value {value}"
            );
        }
    }

    #[test]
    fn undefined_key_usage_flags_are_refused() {
        // "key-usage field of the Key Usage Extension has undefined flags" — bit 9 and up
        // are not allocated.
        assert!(KeyUsage::from_bits(0x0200).is_none());
        assert_eq!(KeyUsage::from_bits(0x01FF).map(|k| k.bits()), Some(0x01FF));
    }

    #[test]
    fn a_certificate_larger_than_400_octets_is_refused() {
        // §6.1.3, which is what keeps a NOC chain inside a CASE message.
        let oversized = [0u8; CERT_TLV_MAX + 1];
        assert!(MatterCertificate::decode(&oversized).is_err());
    }

    #[test]
    fn a_not_after_of_zero_never_expires() {
        // §6.5.7: it stands for X.509's 99991231235959Z.
        let mut c = cert(CertType::Noc);
        c.not_after = NOT_AFTER_NEVER;
        assert!(c.is_valid_at(u32::MAX));
        assert!(!c.is_valid_at(c.not_before.saturating_sub(1)));
    }

    /// Does this serial survive the writer that has to encode it?
    ///
    /// The certificate is rebuilt per call so the borrow of `serial` ends with it; that is the
    /// only reason this is a function and not two lines in the loop below.
    fn encodes(serial: &[u8]) -> bool {
        let mut c = cert(CertType::Noc);
        c.serial_number = serial;
        let mut buf = [0u8; CERT_DER_MAX];
        der::tbs_certificate(&c, &mut buf).is_ok()
    }

    /// Every digest a key identifier could be, through the writer that has to encode it.
    ///
    /// The serial is the first 20 octets of SHA-256 over a public key, so its first two octets
    /// are uniformly distributed and the encoder's rules bite on exactly those two: the sign
    /// bit, and DER's shortest-form requirement. Sweeping all 65 536 prefixes is the whole
    /// space, so this is a proof rather than a sample — and it is the test that would have
    /// caught a device failing to generate its own attestation chain one boot in 256.
    #[test]
    fn a_normalised_digest_always_encodes_as_a_serial_number() {
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                let mut digest = [0x5Au8; SERIAL_MAX];
                digest[0] = first;
                digest[1] = second;
                let serial = positive_serial(digest);

                assert_ne!(serial[0] & 0x80, 0x80, "a serial is a *positive* integer");
                assert_ne!(serial[0], 0x00, "0x00 would be a redundant sign octet");
                assert!(encodes(&serial), "digest {first:#04x}{second:#04x}");
            }
        }
    }

    /// The other half of the same claim: the writer really does refuse what `positive_serial`
    /// removes, so the sweep above is not passing because nothing was ever checked.
    #[test]
    fn the_writer_refuses_a_redundant_sign_octet() {
        for raw in [
            // 0x00 followed by a value below 0x80: the zero says nothing.
            [0x00, 0x01],
            // 0xFF followed by one at or above it: likewise for a negative value.
            [0xFF, 0x80],
        ] {
            let mut digest = [0x5Au8; SERIAL_MAX];
            digest[..2].copy_from_slice(&raw);
            assert!(!encodes(&digest), "{raw:02x?}");
            assert!(encodes(&positive_serial(digest)), "{raw:02x?}");
        }
    }
}
