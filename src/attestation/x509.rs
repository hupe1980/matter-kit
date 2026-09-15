//! Reading the X.509 certificates of the Device Attestation PKI (Core §6.2.2).
//!
//! The DAC chain is the one place Matter uses certificates it cannot re-encode. An
//! operational certificate is Matter TLV that *stands for* an X.509 certificate
//! ([`cert`](crate::cert)); a DAC, PAI and PAA are X.509 certificates and nothing else,
//! burned in at manufacture by a CA this crate has no influence over. So they are read, not
//! modelled: [`X509Certificate`] borrows its fields from the DER and keeps the `tbsCertificate`
//! verbatim, because that is what the signature covers and re-encoding it would be a
//! guess about a CA's choices.
//!
//! The parser is deliberately narrow. §6.2.2.3 rule 12e permits "any other extension allowed
//! in RFC 5280 … These extensions insofar not defined in this specification SHALL be ignored
//! by commissioners", so unknown extensions are skipped rather than refused — but everything
//! the specification does constrain is checked, and anything structurally ambiguous is an
//! error.
//!
//! # Vendor ID and Product ID, two ways
//!
//! §6.2.2.2 allows a CA to put the VID and PID either in Matter-specific RDN attributes (the
//! "preferred method") or as `Mvid:FFF1` / `Mpid:8000` substrings inside the `commonName`
//! (the "fallback method", "present to support less flexible CA infrastructure").
//!
//! The two never mix within one field, and the rule for which applies is not "try both": if
//! either Matter OID appears anywhere in a field, "the presence of either of these OIDs …
//! SHALL cause the 'fallback method' to be skipped altogether for that field". So a
//! certificate with a Matter VID OID and a `Mpid:` substring has a VID and **no** PID, which
//! is a different certificate from one where both were read. [`VidPid::from_name`]
//! implements that, field by field.

use crate::crypto::{PublicKey, Signature, verify};
use crate::der::{
    DerReader, Element, OID_COMMON_NAME, OID_EC_PUBLIC_KEY, OID_ECDSA_WITH_SHA256,
    OID_MATTER_ATTESTATION_PREFIX, OID_PRIME256V1, TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER,
    TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, context_constructed, ecdsa_sig_value_to_raw,
    read_time,
};
use crate::error::{Error, ErrorCode, Result};
use crate::msg::VendorId;

/// `version \[0\] EXPLICIT`.
const TAG_VERSION: u8 = context_constructed(0);
/// `extensions \[3\] EXPLICIT`.
const TAG_EXTENSIONS: u8 = context_constructed(3);

/// `1.3.6.1.4.1.37244.2.1` — `matter-oid-vid` (§6.2.2.2, Table 85).
const OID_MATTER_VID_ARC: u8 = 1;
/// `1.3.6.1.4.1.37244.2.2` — `matter-oid-pid`.
const OID_MATTER_PID_ARC: u8 = 2;

/// The `Mvid:` prefix of the fallback method.
pub const FALLBACK_VID_PREFIX: &[u8] = b"Mvid:";
/// The `Mpid:` prefix of the fallback method.
pub const FALLBACK_PID_PREFIX: &[u8] = b"Mpid:";

/// "All certificates SHALL NOT be longer than 600 bytes in their uncompressed DER format …
/// This constraint SHALL apply to the entire DAC chain" (§6.1.3).
pub const MAX_DER_LEN: usize = 600;

/// A key identifier is 20 octets (§6.1.2).
pub const KEY_ID_LEN: usize = 20;

fn malformed() -> Error {
    Error::new(ErrorCode::DerMalformed)
}

fn invalid() -> Error {
    Error::new(ErrorCode::CertInvalid)
}

// --- Vendor ID and Product ID --------------------------------------------------------------

/// The Vendor ID and Product ID read out of one distinguished name (§6.2.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VidPid {
    /// The Vendor ID, if the field carries one.
    pub vendor_id: Option<VendorId>,
    /// The Product ID, if the field carries one.
    pub product_id: Option<u16>,
}

impl VidPid {
    /// Reads the VID and PID out of a `Name`'s DER, applying §6.2.2.2's method rules.
    ///
    /// A field either uses the Matter OIDs or the `commonName` fallback, never both: the
    /// presence of *either* Matter OID disables the fallback for the whole field.
    ///
    /// Returns [`ErrorCode::CertInvalid`] where the specification says a field is
    /// "incorrectly formatted" — a Matter OID whose value is not the exact hex width
    /// §6.1.1 requires, or an `Mvid:`/`Mpid:` prefix with no well-formed match anywhere in
    /// the `commonName`. Refusing rather than reporting absence matters: a commissioner that
    /// read "no PID" from a certificate whose PID is merely malformed would compare against
    /// the wrong thing.
    pub fn from_name(name: &[u8]) -> Result<Self> {
        let mut out = Self::default();
        let mut saw_matter_oid = false;
        let mut common_name: Option<&[u8]> = None;

        let mut rdns = DerReader::new(name);
        while !rdns.is_empty() {
            let mut rdn = rdns.expect_set()?;
            while !rdn.is_empty() {
                let mut atv = rdn.expect_sequence()?;
                let oid = atv.expect(TAG_OID)?.content;
                let value = atv.next_element()?;
                atv.finish()?;

                if let Some(arc) = matter_attestation_arc(oid) {
                    saw_matter_oid = true;
                    // §6.1.1: "encoded in network byte order as exactly twice their
                    // specified maximum octet length … without omitting any leading zeroes",
                    // so a VID or PID is exactly four uppercase hex characters.
                    let scalar = parse_hex4(value.content).ok_or_else(invalid)?;
                    match arc {
                        OID_MATTER_VID_ARC => out.vendor_id = Some(VendorId(scalar)),
                        OID_MATTER_PID_ARC => out.product_id = Some(scalar),
                        _ => {}
                    }
                } else if oid == OID_COMMON_NAME {
                    common_name = Some(value.content);
                }
            }
        }

        if saw_matter_oid {
            // "the presence of either of these OIDs as the type for any AttributeTypeAndValue
            // within any RelativeDistinguishedName of that field SHALL cause the 'fallback
            // method' to be skipped altogether for that field."
            return Ok(out);
        }
        if let Some(cn) = common_name {
            out.vendor_id = fallback_scalar(cn, FALLBACK_VID_PREFIX)?.map(VendorId);
            out.product_id = fallback_scalar(cn, FALLBACK_PID_PREFIX)?;
        }
        Ok(out)
    }
}

/// The final arc of a `1.3.6.1.4.1.37244.2.x` OID, if `oid` is one.
fn matter_attestation_arc(oid: &[u8]) -> Option<u8> {
    let rest = oid.strip_prefix(OID_MATTER_ATTESTATION_PREFIX)?;
    match rest {
        [arc] => Some(*arc),
        _ => None,
    }
}

/// Parses exactly four uppercase hex characters into a `u16`.
fn parse_hex4(text: &[u8]) -> Option<u16> {
    let [a, b, c, d] = <[u8; 4]>::try_from(text).ok()?;
    let mut value = 0u16;
    for byte in [a, b, c, d] {
        let digit = match byte {
            b'0'..=b'9' => byte.checked_sub(b'0')?,
            // Uppercase only: §6.2.2.2's own example calls `Mvid:fff1` invalid.
            b'A'..=b'F' => byte.checked_sub(b'A')?.checked_add(10)?,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(u16::from(digit))?;
    }
    Some(value)
}

/// Applies the fallback method to a `commonName` (§6.2.2.2).
///
/// "The leftmost match having a correct encoding SHALL be used, with other correct matches
/// discarded" — and, crucially, "if the prefix string is found on its own anywhere within
/// the commonName, but there is no fully correct match anywhere in the commonName, the field
/// SHALL be considered incorrectly formatted."
///
/// So this cannot simply return `None` when nothing parses: the specification's own example
/// `"… Mpid: Mvid:FFF1"` is an error, not a certificate without a product id.
fn fallback_scalar(common_name: &[u8], prefix: &[u8]) -> Result<Option<u16>> {
    let mut saw_prefix = false;
    let mut at = 0usize;
    while let Some(slice) = common_name.get(at..) {
        if slice.len() < prefix.len() {
            break;
        }
        if slice.starts_with(prefix) {
            saw_prefix = true;
            if let Some(digits) = slice.get(prefix.len()..prefix.len().saturating_add(4))
                && let Some(value) = parse_hex4(digits)
            {
                // The leftmost correct match wins; later ones are discarded.
                return Ok(Some(value));
            }
        }
        at = at.checked_add(1).ok_or_else(invalid)?;
    }
    if saw_prefix { Err(invalid()) } else { Ok(None) }
}

// --- The certificate --------------------------------------------------------------------------

bitflags::bitflags! {
    /// X.509's `KeyUsage` bits, numbered from the most significant bit of the first octet
    /// (RFC 5280 §4.2.1.3) — the *reverse* of Matter's own `key-usage-flag` numbering.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KeyUsage: u16 {
        /// `digitalSignature`.
        const DIGITAL_SIGNATURE = 1 << 0;
        /// `nonRepudiation`.
        const NON_REPUDIATION = 1 << 1;
        /// `keyEncipherment`.
        const KEY_ENCIPHERMENT = 1 << 2;
        /// `dataEncipherment`.
        const DATA_ENCIPHERMENT = 1 << 3;
        /// `keyAgreement`.
        const KEY_AGREEMENT = 1 << 4;
        /// `keyCertSign`.
        const KEY_CERT_SIGN = 1 << 5;
        /// `cRLSign`.
        const CRL_SIGN = 1 << 6;
        /// `encipherOnly`.
        const ENCIPHER_ONLY = 1 << 7;
        /// `decipherOnly`.
        const DECIPHER_ONLY = 1 << 8;
    }
}

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER
/// OPTIONAL }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BasicConstraints {
    /// Whether the subject is a CA.
    pub is_ca: bool,
    /// The maximum number of intermediates below this one.
    pub path_len: Option<u8>,
}

/// A parsed attestation certificate: a DAC, PAI or PAA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Certificate<'a> {
    /// The `tbsCertificate`, verbatim — the bytes the signature covers.
    pub tbs: &'a [u8],
    /// The `serialNumber`'s magnitude.
    pub serial_number: &'a [u8],
    /// The `issuer` `Name`, as DER. §6.2.2.3 rule 6 requires a byte-for-byte match against
    /// the issuer's `subject`, so it is kept encoded rather than parsed into a model.
    pub issuer: &'a [u8],
    /// The `subject` `Name`, as DER.
    pub subject: &'a [u8],
    /// The VID and PID of the issuer field.
    pub issuer_vid_pid: VidPid,
    /// The VID and PID of the subject field.
    pub subject_vid_pid: VidPid,
    /// `notBefore`, as a Matter `epoch-s`.
    pub not_before: u32,
    /// `notAfter`, or `None` for `99991231235959Z`.
    pub not_after: Option<u32>,
    /// The subject's P-256 public key.
    pub public_key: PublicKey,
    /// `basicConstraints`, absent in neither a DAC nor a CA here but optional in X.509.
    pub basic_constraints: Option<BasicConstraints>,
    /// `keyUsage`.
    pub key_usage: Option<KeyUsage>,
    /// `subjectKeyIdentifier`.
    pub subject_key_id: Option<[u8; KEY_ID_LEN]>,
    /// `authorityKeyIdentifier`'s `keyIdentifier`.
    pub authority_key_id: Option<[u8; KEY_ID_LEN]>,
    /// Whether the certificate carries an `extendedKeyUsage`, which §6.2.2 permits but does
    /// not constrain.
    pub has_extended_key_usage: bool,
    /// The signature, as the `r || s` of §3.5.3.
    pub signature: Signature,
}

impl<'a> X509Certificate<'a> {
    /// Parses an attestation certificate.
    pub fn parse(der: &'a [u8]) -> Result<Self> {
        if der.len() > MAX_DER_LEN {
            // §6.1.3, which is what keeps a DAC chain inside a `CertificateChainResponse`.
            return Err(invalid());
        }
        let mut outer = DerReader::new(der);
        let mut cert = outer.expect_sequence()?;
        outer.finish()?;

        let tbs_element = cert.expect(TAG_SEQUENCE)?;
        let mut tbs = tbs_element.content_reader();

        // version [0] EXPLICIT INTEGER. "The version field SHALL be set to 2 to indicate v3."
        let version = tbs.expect(TAG_VERSION)?;
        let mut version_reader = version.content_reader();
        if version_reader.expect_uint()? != 2 {
            return Err(invalid());
        }
        version_reader.finish()?;

        let serial_number = tbs.expect_unsigned()?;

        // signature AlgorithmIdentifier: "SHALL contain the identifier for signatureAlgorithm
        // ecdsa-with-SHA256".
        let mut signature_algo = tbs.expect_sequence()?;
        signature_algo.expect_oid(OID_ECDSA_WITH_SHA256)?;

        let issuer = tbs.expect(TAG_SEQUENCE)?.content;

        let mut validity = tbs.expect_sequence()?;
        let not_before = read_time(&validity.next_element()?)?.ok_or_else(invalid)?;
        let not_after = read_time(&validity.next_element()?)?;
        validity.finish()?;

        let subject = tbs.expect(TAG_SEQUENCE)?.content;

        // subjectPublicKeyInfo. "The algorithm field … SHALL be the object identifier for
        // prime256v1."
        let mut spki = tbs.expect_sequence()?;
        let mut key_algo = spki.expect_sequence()?;
        key_algo.expect_oid(OID_EC_PUBLIC_KEY)?;
        key_algo.expect_oid(OID_PRIME256V1)?;
        key_algo.finish()?;
        let public_key = PublicKey::from_slice(spki.expect(TAG_BIT_STRING)?.bit_string_octets()?)?;
        spki.finish()?;

        // issuerUniqueID [1] and subjectUniqueID [2] are v2 fields RFC 5280 deprecates; a
        // Matter attestation certificate has none, and skipping them keeps the extensions
        // lookup honest if one ever appears.
        let _ = tbs.take_if(context_constructed(1))?;
        let _ = tbs.take_if(context_constructed(2))?;

        let mut parsed = Extensions::default();
        if let Some(extensions) = tbs.take_if(TAG_EXTENSIONS)? {
            let mut explicit = extensions.content_reader();
            let mut list = explicit.expect_sequence()?;
            explicit.finish()?;
            while !list.is_empty() {
                parsed.absorb(&mut list.expect_sequence()?)?;
            }
        }
        tbs.finish()?;

        let mut sig_algo = cert.expect_sequence()?;
        sig_algo.expect_oid(OID_ECDSA_WITH_SHA256)?;
        sig_algo.finish()?;

        let signature_der = cert.expect(TAG_BIT_STRING)?.bit_string_octets()?;
        cert.finish()?;
        let mut raw = [0u8; 64];
        ecdsa_sig_value_to_raw(signature_der, &mut raw)?;

        Ok(Self {
            tbs: tbs_element.raw,
            serial_number,
            issuer,
            subject,
            issuer_vid_pid: VidPid::from_name(issuer)?,
            subject_vid_pid: VidPid::from_name(subject)?,
            not_before,
            not_after,
            public_key,
            basic_constraints: parsed.basic_constraints,
            key_usage: parsed.key_usage,
            subject_key_id: parsed.subject_key_id,
            authority_key_id: parsed.authority_key_id,
            has_extended_key_usage: parsed.has_extended_key_usage,
            signature: Signature::from_bytes(raw),
        })
    }

    /// Whether `at` (a Matter `epoch-s`) falls inside the validity window.
    #[must_use]
    pub const fn is_valid_at(&self, at: u32) -> bool {
        at >= self.not_before
            && match self.not_after {
                Some(end) => at <= end,
                None => true,
            }
    }

    /// Whether this certificate is a CA.
    #[must_use]
    pub fn is_ca(&self) -> bool {
        self.basic_constraints.is_some_and(|b| b.is_ca)
    }

    /// Verifies `subject`'s signature against this certificate's public key.
    pub fn verify_signature_of(&self, subject: &Self) -> Result<bool> {
        verify(&self.public_key, subject.tbs, &subject.signature)
    }
}

/// The extensions this module understands, gathered as they are walked.
#[derive(Debug, Default)]
struct Extensions {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    subject_key_id: Option<[u8; KEY_ID_LEN]>,
    authority_key_id: Option<[u8; KEY_ID_LEN]>,
    has_extended_key_usage: bool,
    /// Which `2.5.29.x` extensions have been seen, so a second instance is refused.
    ///
    /// RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of a particular
    /// extension." Overwriting silently would let a second `keyUsage` mask the first, so two
    /// implementations could read the same certificate differently.
    seen: u64,
}

impl Extensions {
    /// Reads one `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    /// extnValue OCTET STRING }`.
    fn absorb(&mut self, extension: &mut DerReader<'_>) -> Result<()> {
        let oid = extension.expect(TAG_OID)?.content;
        // `critical` is a DEFAULT FALSE boolean, so it is present only when TRUE.
        let critical = match extension.take_if(TAG_BOOLEAN)? {
            Some(element) => element.content == [0xFF],
            None => false,
        };
        let value = extension.expect(TAG_OCTET_STRING)?.content;
        extension.finish()?;

        // 2.5.29.x.
        let Some([arc]) = oid.strip_prefix(crate::der::OID_CE_PREFIX) else {
            // Not a standard extension — an authorityInfoAccess, say. §6.2.2.3 rule 12e:
            // "These extensions insofar not defined in this specification SHALL be ignored."
            return Ok(());
        };
        if let Some(bit) = 1u64.checked_shl(u32::from(*arc)) {
            if self.seen & bit != 0 {
                return Err(invalid());
            }
            self.seen |= bit;
        }

        let mut reader = DerReader::new(value);
        match *arc {
            14 => {
                // subjectKeyIdentifier ::= OCTET STRING
                self.subject_key_id = Some(key_id(&reader.expect(TAG_OCTET_STRING)?)?);
            }
            15 => {
                // keyUsage ::= BIT STRING, and §6.2.2.3 requires it critical.
                if !critical {
                    return Err(invalid());
                }
                self.key_usage = Some(read_key_usage(&reader.expect(TAG_BIT_STRING)?)?);
            }
            19 => {
                // basicConstraints, which §6.2.2.3 also requires critical.
                if !critical {
                    return Err(invalid());
                }
                let mut seq = reader.expect_sequence()?;
                let is_ca = match seq.take_if(TAG_BOOLEAN)? {
                    Some(element) => element.content == [0xFF],
                    None => false,
                };
                let path_len = match seq.take_if(TAG_INTEGER)? {
                    // `pathLenConstraint` is a small non-negative integer; anything wider
                    // than one octet is not a path length a Matter chain could satisfy.
                    Some(element) => match element.content {
                        [len] if *len < 0x80 => Some(*len),
                        _ => return Err(malformed()),
                    },
                    None => None,
                };
                seq.finish()?;
                // RFC 5280 §4.2.1.9: "CAs MUST NOT include the pathLenConstraint field
                // unless the cA boolean is asserted". A path length on a leaf is a
                // certificate nobody meant to issue.
                if !is_ca && path_len.is_some() {
                    return Err(invalid());
                }
                self.basic_constraints = Some(BasicConstraints { is_ca, path_len });
            }
            35 => {
                // authorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL, ... }
                let mut seq = reader.expect_sequence()?;
                if let Some(element) = seq.take_if(crate::der::context_primitive(0))? {
                    self.authority_key_id = Some(key_id(&element)?);
                }
                // authorityCertIssuer [1] and authorityCertSerialNumber [2] are optional and
                // "not supported by Matter certificates"; their presence changes nothing.
            }
            37 => self.has_extended_key_usage = true,
            _ => {}
        }
        Ok(())
    }
}

fn key_id(element: &Element<'_>) -> Result<[u8; KEY_ID_LEN]> {
    // §6.1.2: "the associated Key Identifier SHALL be of a length of 20 octets".
    <[u8; KEY_ID_LEN]>::try_from(element.content).map_err(|_| invalid())
}

/// Reads a `KeyUsage` BIT STRING into Matter's bit numbering.
///
/// X.509 numbers named bits from the most significant bit of the first octet; this crate's
/// flags are `1 << n` for bit `n`. So each octet is bit-reversed, which is the same
/// transformation [`cert::der`](crate::cert::der) applies in the writing direction.
fn read_key_usage(element: &Element<'_>) -> Result<KeyUsage> {
    let content = element.content;
    let (unused, octets) = content.split_first().ok_or_else(malformed)?;
    if *unused > 7 || octets.len() > 2 {
        return Err(malformed());
    }
    // DER requires the unused trailing bits to be zero. A non-zero one would read as a named
    // bit that is not really set — a `keyUsage` of `digitalSignature` that also claims
    // `encipherOnly`, say — so two parsers could disagree about what a CA authorised.
    if *unused > 0 {
        let last = octets.last().copied().unwrap_or(0);
        let mask = 0xFFu8
            .checked_shr(8u32.saturating_sub(u32::from(*unused)))
            .unwrap_or(0);
        if last & mask != 0 {
            return Err(malformed());
        }
    }
    let mut bits = 0u16;
    if let Some(first) = octets.first() {
        bits |= u16::from(first.reverse_bits());
    }
    if let Some(second) = octets.get(1) {
        bits |= u16::from(second.reverse_bits()) << 8;
    }
    KeyUsage::from_bits(bits).ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wraps a `keyUsage` BIT STRING body in enough DER to read it.
    fn key_usage_element(unused: u8, octets: &[u8]) -> heapless::Vec<u8, 8> {
        let mut out = heapless::Vec::new();
        let _ = out.push(TAG_BIT_STRING);
        let _ = out.push(u8::try_from(octets.len().saturating_add(1)).unwrap_or(0));
        let _ = out.push(unused);
        let _ = out.extend_from_slice(octets);
        out
    }

    fn read_usage(unused: u8, octets: &[u8]) -> Result<KeyUsage> {
        let bytes = key_usage_element(unused, octets);
        let element = DerReader::new(&bytes).next_element()?;
        read_key_usage(&element)
    }

    #[test]
    fn key_usage_bits_are_numbered_from_the_most_significant_bit() {
        // RFC 5280 §4.2.1.3 numbers named bits from the MSB of the first octet, which is the
        // reverse of Matter's own key-usage-flag numbering. Getting this backwards turns a
        // `digitalSignature` leaf into something claiming `encipherOnly`.
        assert_eq!(
            read_usage(7, &[0x80]).expect("ds"),
            KeyUsage::DIGITAL_SIGNATURE
        );
        assert_eq!(
            read_usage(1, &[0x06]).expect("ca"),
            KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN
        );
        // decipherOnly is bit 8, so it needs a second octet.
        assert_eq!(
            read_usage(7, &[0x00, 0x80]).expect("do"),
            KeyUsage::DECIPHER_ONLY
        );
    }

    #[test]
    fn a_bit_string_with_non_zero_unused_bits_is_refused() {
        // DER requires them zero. A parser that ignored them would read a named bit that is
        // not really set, so two implementations could disagree about what a CA authorised.
        assert!(
            read_usage(7, &[0x81]).is_err(),
            "bit 7 is not an unused zero"
        );
        assert!(read_usage(1, &[0x07]).is_err());
        // The same octets with the right unused count are fine.
        assert!(read_usage(0, &[0x81]).is_ok());
    }

    #[test]
    fn an_over_wide_key_usage_is_refused() {
        // Nine named bits fit in two octets; a third is not a KeyUsage.
        assert!(read_usage(0, &[0x00, 0x00, 0x00]).is_err());
        assert!(
            read_usage(8, &[0x00]).is_err(),
            "8 unused bits is not a thing"
        );
    }

    /// The `Name` DER for a single `commonName`, for the fallback-method tests.
    fn common_name(cn: &str) -> heapless::Vec<u8, 128> {
        let mut atv = heapless::Vec::<u8, 128>::new();
        let _ = atv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0C]);
        let _ = atv.push(u8::try_from(cn.len()).unwrap_or(0));
        let _ = atv.extend_from_slice(cn.as_bytes());

        let mut seq = heapless::Vec::<u8, 128>::new();
        let _ = seq.push(TAG_SEQUENCE);
        let _ = seq.push(u8::try_from(atv.len()).unwrap_or(0));
        let _ = seq.extend_from_slice(&atv);

        let mut set = heapless::Vec::<u8, 128>::new();
        let _ = set.push(crate::der::TAG_SET);
        let _ = set.push(u8::try_from(seq.len()).unwrap_or(0));
        let _ = set.extend_from_slice(&seq);
        set
    }

    #[test]
    fn the_leftmost_correct_match_wins_and_earlier_malformed_ones_do_not_count() {
        // §6.2.2.2: "The leftmost match having a correct encoding SHALL be used, with other
        // correct matches discarded." A malformed occurrence before a correct one is passed
        // over, not treated as the answer.
        let name = common_name("Mvid:zzzz and Mvid:ABCD");
        let parsed = VidPid::from_name(&name).expect("parse");
        assert_eq!(parsed.vendor_id, Some(VendorId(0xABCD)));
    }

    #[test]
    fn a_prefix_with_no_correct_match_anywhere_is_an_error_not_an_absence() {
        // "if the prefix string is found on its own anywhere within the commonName, but
        // there is no fully correct match anywhere … the field SHALL be considered
        // incorrectly formatted." Answering "no vendor id" would let a commissioner compare
        // against the wrong thing rather than refuse.
        let name = common_name("Mvid:zzzz");
        assert_eq!(
            VidPid::from_name(&name).map(|_| ()).unwrap_err().code(),
            ErrorCode::CertInvalid
        );
    }

    #[test]
    fn hex_must_be_exactly_four_uppercase_digits() {
        assert_eq!(parse_hex4(b"FFF1"), Some(0xFFF1));
        assert_eq!(parse_hex4(b"002A"), Some(0x002A));
        assert_eq!(parse_hex4(b"0000"), Some(0));
        // Lowercase is explicitly invalid per §6.2.2.2's own example.
        assert_eq!(parse_hex4(b"fff1"), None);
        assert_eq!(parse_hex4(b"FFF"), None);
        assert_eq!(parse_hex4(b"FFF12"), None);
        assert_eq!(parse_hex4(b"FFG1"), None);
    }

    #[test]
    fn the_matter_arc_is_matched_exactly() {
        // `1.3.6.1.4.1.37244.2.1` and `.2.2` are the attestation attributes; the operational
        // DN attributes live under `.1.x` and must not be mistaken for them.
        let mut vid = heapless::Vec::<u8, 16>::new();
        let _ = vid.extend_from_slice(OID_MATTER_ATTESTATION_PREFIX);
        let _ = vid.push(1);
        assert_eq!(matter_attestation_arc(&vid), Some(OID_MATTER_VID_ARC));

        // One arc too long is not one of these.
        let mut deeper = vid.clone();
        let _ = deeper.push(9);
        assert_eq!(matter_attestation_arc(&deeper), None);

        // And the operational prefix is a different arc entirely.
        assert_eq!(
            matter_attestation_arc(crate::der::OID_MATTER_DN_PREFIX),
            None
        );
    }

    #[test]
    fn a_field_using_the_matter_oids_ignores_a_common_name_fallback() {
        // §6.2.2.2: the presence of either Matter OID "SHALL cause the 'fallback method' to
        // be skipped altogether for that field". So this name has a vendor id and *no*
        // product id, even though `Mpid:` is right there.
        let mut atv = heapless::Vec::<u8, 128>::new();
        let _ = atv.push(TAG_OID);
        let _ = atv
            .push(u8::try_from(OID_MATTER_ATTESTATION_PREFIX.len().saturating_add(1)).unwrap_or(0));
        let _ = atv.extend_from_slice(OID_MATTER_ATTESTATION_PREFIX);
        let _ = atv.push(OID_MATTER_VID_ARC);
        let _ = atv.extend_from_slice(&[0x0C, 0x04, b'F', b'F', b'F', b'1']);

        let mut seq = heapless::Vec::<u8, 128>::new();
        let _ = seq.push(TAG_SEQUENCE);
        let _ = seq.push(u8::try_from(atv.len()).unwrap_or(0));
        let _ = seq.extend_from_slice(&atv);
        let mut rdn = heapless::Vec::<u8, 128>::new();
        let _ = rdn.push(crate::der::TAG_SET);
        let _ = rdn.push(u8::try_from(seq.len()).unwrap_or(0));
        let _ = rdn.extend_from_slice(&seq);

        // Append a second RDN carrying a commonName with an Mpid: substring.
        let cn = common_name("Matter Test Mpid:8000");
        let mut name = heapless::Vec::<u8, 256>::new();
        let _ = name.extend_from_slice(&rdn);
        let _ = name.extend_from_slice(&cn);

        let parsed = VidPid::from_name(&name).expect("parse");
        assert_eq!(parsed.vendor_id, Some(VendorId(0xFFF1)));
        assert_eq!(
            parsed.product_id, None,
            "the fallback is skipped for this field"
        );
    }
}
