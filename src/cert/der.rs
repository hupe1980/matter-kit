//! Regenerating the X.509 DER a Matter certificate stands for (Core §6.5.2).
//!
//! # Why this exists
//!
//! A Matter certificate's `signature` field is not a signature over the Matter certificate.
//! §6.5.2 is explicit:
//!
//! > The signature included in a Matter certificate is the signatureValue of the
//! > corresponding X.509 certificate, **not** a signature of the preceding Matter TLV data
//! > … validating the signature in a Matter certificate entails its logical conversion to
//! > the corresponding X.509 certificate to recover the original `tbsCertificate` of the
//! > basic syntax signed by the Certificate Authority.
//!
//! So there is no way to verify an operational certificate — and therefore no way to
//! complete CASE — without being able to rebuild the exact DER the CA signed. Not an
//! equivalent DER: the same bytes, because the hash is over those bytes. Every ordering and
//! string-type decision that [`super::dn`] preserves exists for this function.
//!
//! [`tbs_certificate`] produces the `tbsCertificate` for hashing; [`certificate`] produces
//! the whole certificate, for handing to something that expects DER.
//!
//! # Reading it bottom-up
//!
//! [`crate::der::DerWriter`] fills its buffer from the end backwards, so that a
//! length is known before its header is written without allocating or encoding twice. Every
//! function here therefore emits its fields in **reverse** order, which is flagged at each
//! site: reading one against the ASN.1 in §6.5 means reading the ASN.1 bottom-up.

use crate::cert::{
    CERT_DER_MAX, DistinguishedName, DnAttributeKind, DnValue, Extension, KeyUsage,
    MatterCertificate, NOT_AFTER_NEVER, SERIAL_MAX,
};
use crate::error::{Error, ErrorCode, Result};

use crate::der::{
    DerWriter, OID_CE_PREFIX, OID_DOMAIN_COMPONENT, OID_ECDSA_WITH_SHA256, OID_KP_PREFIX,
    OID_MATTER_DN_PREFIX, TAG_BIT_STRING, TAG_BOOLEAN, TAG_GENERALIZED_TIME, TAG_IA5_STRING,
    TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_PRINTABLE_STRING, TAG_SEQUENCE, TAG_SET,
    TAG_UTF8_STRING, context_constructed, context_primitive, write_time,
};

/// `\[0\]` constructed — `version [0] EXPLICIT`.
const TAG_VERSION: u8 = context_constructed(0);
/// `\[3\]` constructed — `extensions [3] EXPLICIT`.
const TAG_EXTENSIONS: u8 = context_constructed(3);
/// `\[0\]` primitive — the `keyIdentifier` inside an `AuthorityKeyIdentifier`.
const TAG_KEY_IDENTIFIER: u8 = context_primitive(0);

/// The prefix of every X.520 attribute type: `2.5.4` (Table 87).
const OID_X520_PREFIX: &[u8] = &[0x55, 0x04];

const CE_SUBJECT_KEY_IDENTIFIER: u8 = 14;
const CE_KEY_USAGE: u8 = 15;
const CE_BASIC_CONSTRAINTS: u8 = 19;
const CE_AUTHORITY_KEY_IDENTIFIER: u8 = 35;
const CE_EXTENDED_KEY_USAGE: u8 = 37;

/// The last X.520 arc for each standard DN attribute type, indexed by Matter tag - 1
/// (Table 87). `domain-component` is tag 16 and is not in this arc, so it is not here.
const X520_ARCS: [u8; 15] = [3, 4, 5, 6, 7, 8, 10, 11, 12, 41, 42, 43, 44, 46, 65];

fn invalid() -> Error {
    Error::new(ErrorCode::CertInvalid)
}

/// Writes the `tbsCertificate` — the bytes a CA's signature is computed over.
///
/// Returns a slice at the **end** of `buf`; the caller keeps the slice, not the buffer.
pub fn tbs_certificate<'b>(cert: &MatterCertificate<'_>, buf: &'b mut [u8]) -> Result<&'b [u8]> {
    let mut writer = DerWriter::new(buf);
    write_tbs(&mut writer, cert)?;
    Ok(writer.finish())
}

/// Writes the whole X.509 certificate: `SEQUENCE { tbsCertificate, signatureAlgorithm,
/// signatureValue }`.
pub fn certificate<'b>(cert: &MatterCertificate<'_>, buf: &'b mut [u8]) -> Result<&'b [u8]> {
    let mut writer = DerWriter::new(buf);
    let mark = writer.mark();
    // Reverse order: signatureValue, then signatureAlgorithm, then the tbsCertificate.
    write_signature_value(&mut writer, cert)?;
    write_algorithm_identifier(&mut writer)?;
    write_tbs(&mut writer, cert)?;
    writer.header(TAG_SEQUENCE, mark)?;
    if writer.len() > CERT_DER_MAX {
        // §6.1.3: "All certificates SHALL NOT be longer than 600 bytes in their
        // uncompressed DER format."
        return Err(invalid());
    }
    Ok(writer.finish())
}

fn write_tbs(writer: &mut DerWriter<'_>, cert: &MatterCertificate<'_>) -> Result<()> {
    let mark = writer.mark();
    // Reverse order of TBSCertificate's fields.
    write_extensions(writer, cert)?;
    write_subject_public_key_info(writer, cert)?;
    write_name(writer, &cert.subject)?;
    write_validity(writer, cert)?;
    write_name(writer, &cert.issuer)?;
    write_algorithm_identifier(writer)?;
    write_serial_number(writer, cert.serial_number)?;
    write_version(writer)?;
    writer.header(TAG_SEQUENCE, mark)
}

/// `version \[0\] EXPLICIT Version` — always v3, since "Matter certificates SHALL only
/// support version X.509 v3" (§6.5.3). v3 is the INTEGER 2.
fn write_version(writer: &mut DerWriter<'_>) -> Result<()> {
    let mark = writer.mark();
    writer.primitive(TAG_INTEGER, &[2])?;
    writer.header(TAG_VERSION, mark)
}

/// `serialNumber INTEGER`.
///
/// §6.5.4's `serial-num` octet string *is* the INTEGER's content, carried through
/// unchanged — which is why leading zeros matter and are preserved. A value that is not
/// valid DER INTEGER content would regenerate a certificate no CA ever signed, so it is
/// refused rather than corrected.
fn write_serial_number(writer: &mut DerWriter<'_>, serial: &[u8]) -> Result<()> {
    if serial.is_empty() || serial.len() > SERIAL_MAX {
        return Err(invalid());
    }
    // DER requires the shortest two's-complement form: a leading 0x00 is only allowed to
    // keep a positive value from looking negative, and a leading 0xFF likewise.
    if let ([first, second, ..], _) = (serial, ()) {
        let redundant_zero = *first == 0x00 && *second < 0x80;
        let redundant_ones = *first == 0xFF && *second >= 0x80;
        if redundant_zero || redundant_ones {
            return Err(invalid());
        }
    }
    writer.primitive(TAG_INTEGER, serial)
}

/// `AlgorithmIdentifier` for `ecdsa-with-SHA256`, which has **no** parameters — an
/// `AlgorithmIdentifier` with a NULL here would hash differently and fail every signature.
fn write_algorithm_identifier(writer: &mut DerWriter<'_>) -> Result<()> {
    writer.algorithm_identifier(OID_ECDSA_WITH_SHA256)
}

/// `Name ::= SEQUENCE OF RelativeDistinguishedName`, each RDN a `SET OF
/// AttributeTypeAndValue` with exactly one member — "The RDN in a Matter certificate SHALL
/// be always a single DN attribute" (§6.5.6.1).
fn write_name(writer: &mut DerWriter<'_>, dn: &DistinguishedName<'_>) -> Result<()> {
    if dn.is_empty() {
        return Err(invalid());
    }
    let mark = writer.mark();
    // Reverse order, so that the attributes come out in the order the DN holds them —
    // which §6.5.6.3 requires to match the Matter certificate's.
    for attribute in dn.attributes().iter().rev() {
        let set_mark = writer.mark();
        let seq_mark = writer.mark();
        // AttributeTypeAndValue, in reverse: value, then type.
        match attribute.value {
            DnValue::Str(text) => {
                let tag = if attribute.printable_string {
                    TAG_PRINTABLE_STRING
                } else if attribute.kind == DnAttributeKind::DomainComponent {
                    // Table 88: domain-component "is encoded as IA5String in X.509 form".
                    TAG_IA5_STRING
                } else {
                    TAG_UTF8_STRING
                };
                writer.primitive(tag, text.as_bytes())?;
            }
            DnValue::Uint(value) => {
                // §6.1.1: "encoded in network byte order as exactly twice their specified
                // maximum octet length, encoded as uppercase hexadecimal number format
                // without any separators or prefix, and without omitting any leading
                // zeroes."
                let octets = attribute.kind.scalar_octets().ok_or_else(invalid)?;
                let mut hex = [0u8; 16];
                let width = octets.checked_mul(2).ok_or_else(invalid)?;
                let digits = hex.get_mut(..width).ok_or_else(invalid)?;
                write_uppercase_hex(digits, value)?;
                writer.primitive(TAG_UTF8_STRING, digits)?;
            }
        }
        write_attribute_type_oid(writer, attribute.kind)?;
        writer.header(TAG_SEQUENCE, seq_mark)?;
        writer.header(TAG_SET, set_mark)?;
    }
    writer.header(TAG_SEQUENCE, mark)
}

fn write_attribute_type_oid(writer: &mut DerWriter<'_>, kind: DnAttributeKind) -> Result<()> {
    if kind == DnAttributeKind::DomainComponent {
        return writer.primitive(TAG_OID, OID_DOMAIN_COMPONENT);
    }
    if kind.is_matter_specific() {
        // 1.3.6.1.4.1.37244.1.<n>, where <n> counts from 1 at matter-node-id (tag 17).
        let arc = kind.tag().checked_sub(16).ok_or_else(invalid)?;
        return writer.oid_with_arc(OID_MATTER_DN_PREFIX, arc);
    }
    let index = usize::from(kind.tag()).checked_sub(1).ok_or_else(invalid)?;
    let arc = X520_ARCS.get(index).copied().ok_or_else(invalid)?;
    writer.oid_with_arc(OID_X520_PREFIX, arc)
}

/// Writes `value` as exactly `out.len()` uppercase hex digits, high nibble first.
fn write_uppercase_hex(out: &mut [u8], value: u64) -> Result<()> {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let width = out.len();
    // A value that does not fit the width its attribute type allows would silently lose its
    // top digits, which is a different identity.
    if width < 16 {
        let bits = u32::try_from(width).ok().and_then(|w| w.checked_mul(4));
        let limit = bits.and_then(|b| 1u64.checked_shl(b));
        if limit.is_some_and(|limit| value >= limit) {
            return Err(invalid());
        }
    }
    for (index, slot) in out.iter_mut().enumerate() {
        let from_end = width
            .checked_sub(index)
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(invalid)?;
        let shift = u32::try_from(from_end)
            .ok()
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(invalid)?;
        let nibble = usize::try_from((value >> shift) & 0x0F).map_err(|_| invalid())?;
        *slot = DIGITS.get(nibble).copied().ok_or_else(invalid)?;
    }
    Ok(())
}

/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`.
fn write_validity(writer: &mut DerWriter<'_>, cert: &MatterCertificate<'_>) -> Result<()> {
    let mark = writer.mark();
    // Reverse: notAfter, then notBefore.
    if cert.not_after == NOT_AFTER_NEVER {
        // §6.5.7: "Special value 0, when encoded in the not-after field, corresponds to the
        // X.509/RFC 5280 defined special time value 99991231235959Z."
        writer.primitive(TAG_GENERALIZED_TIME, b"99991231235959Z")?;
    } else {
        write_time(writer, cert.not_after)?;
    }
    write_time(writer, cert.not_before)?;
    writer.header(TAG_SEQUENCE, mark)
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey
/// BIT STRING }`, where the algorithm carries `prime256v1` as its parameter.
fn write_subject_public_key_info(
    writer: &mut DerWriter<'_>,
    cert: &MatterCertificate<'_>,
) -> Result<()> {
    writer.subject_public_key_info(cert.public_key.as_bytes())
}

/// `extensions \[3\] EXPLICIT Extensions`, in the certificate's own order — §6.5.12: "The
/// extensions SHALL appear in the same order in the Matter certificate and in the
/// corresponding X.509 certificates."
fn write_extensions(writer: &mut DerWriter<'_>, cert: &MatterCertificate<'_>) -> Result<()> {
    let entries = cert.extensions.entries();
    if entries.is_empty() {
        // The schema is `LIST [ length 1.. ]`, so an empty extensions list is not a
        // certificate that was ever signed.
        return Err(invalid());
    }
    let outer = writer.mark();
    let seq = writer.mark();
    for extension in entries.iter().rev() {
        write_extension(writer, extension)?;
    }
    writer.header(TAG_SEQUENCE, seq)?;
    writer.header(TAG_EXTENSIONS, outer)
}

/// `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET
/// STRING }`.
///
/// Criticality is not encoded in the Matter certificate — §6.5.11.1 and its siblings say
/// each extension "SHALL be treated as critical" or non-critical and that "The critical
/// field SHALL NOT be encoded in the Matter certificate structure" — so it is reconstructed
/// here from the extension's identity. DER omits a `DEFAULT FALSE` boolean entirely, which
/// is why the non-critical ones write nothing.
fn write_extension(writer: &mut DerWriter<'_>, extension: &Extension<'_>) -> Result<()> {
    let mark = writer.mark();
    // Reverse: extnValue, then critical, then extnID.
    let (arc, critical) = match extension {
        Extension::BasicConstraints(basic) => {
            let value = writer.mark();
            let inner = writer.mark();
            if let Some(path_len) = basic.path_len_constraint {
                writer.primitive(TAG_INTEGER, &[path_len])?;
            }
            // `cA BOOLEAN DEFAULT FALSE`: omitted when false, and DER's TRUE is 0xFF.
            if basic.is_ca {
                writer.primitive(TAG_BOOLEAN, &[0xFF])?;
            }
            writer.header(TAG_SEQUENCE, inner)?;
            writer.header(TAG_OCTET_STRING, value)?;
            (CE_BASIC_CONSTRAINTS, true)
        }
        Extension::KeyUsage(usage) => {
            let value = writer.mark();
            write_key_usage_bit_string(writer, *usage)?;
            writer.header(TAG_OCTET_STRING, value)?;
            (CE_KEY_USAGE, true)
        }
        Extension::ExtendedKeyUsage(purposes) => {
            if purposes.is_empty() {
                return Err(invalid());
            }
            let value = writer.mark();
            let inner = writer.mark();
            for purpose in purposes.iter().rev() {
                writer.oid_with_arc(OID_KP_PREFIX, *purpose as u8)?;
            }
            writer.header(TAG_SEQUENCE, inner)?;
            writer.header(TAG_OCTET_STRING, value)?;
            (CE_EXTENDED_KEY_USAGE, true)
        }
        Extension::SubjectKeyId(id) => {
            let value = writer.mark();
            writer.primitive(TAG_OCTET_STRING, id)?;
            writer.header(TAG_OCTET_STRING, value)?;
            (CE_SUBJECT_KEY_IDENTIFIER, false)
        }
        Extension::AuthorityKeyId(id) => {
            let value = writer.mark();
            let inner = writer.mark();
            // `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL, … }`.
            // §6.5.11.5 notes the issuer and serial fields "are not supported by Matter
            // certificates", so only the identifier is present.
            writer.primitive(TAG_KEY_IDENTIFIER, id)?;
            writer.header(TAG_SEQUENCE, inner)?;
            writer.header(TAG_OCTET_STRING, value)?;
            (CE_AUTHORITY_KEY_IDENTIFIER, false)
        }
        Extension::Future(der) => {
            // §6.5.11.6 makes this the one extension that needs no reconstruction at all:
            // "The future-extension field SHALL be encoded as OCTET STRING and it SHALL be an
            // exact copy of the DER encoded extension field (including the DER encoded ASN.1
            // OID of the extension) in the corresponding X.509 certificate."
            //
            // So the octets already *are* a complete `Extension ::= SEQUENCE { extnID,
            // critical DEFAULT FALSE, extnValue }`, OID and criticality included. Writing them
            // back is the whole job, and writing anything else would be wrong — this crate
            // cannot know the OID, and does not need to.
            //
            // Position is the other half of the rule: "These extension fields in a Matter
            // certificate SHALL be encoded in the same order as they appeared in the original
            // X.509 certificate." The caller walks the list in reverse into a writer that
            // prepends, so the original order comes back out, and this blob lands where it
            // was — which is what makes the regenerated DER byte-identical and the signature
            // verifiable (§6.5.2, R12).
            return writer.slice(der);
        }
    };
    if critical {
        writer.primitive(TAG_BOOLEAN, &[0xFF])?;
    }
    writer.oid_with_arc(OID_CE_PREFIX, arc)?;
    writer.header(TAG_SEQUENCE, mark)
}

/// `KeyUsage ::= BIT STRING`, whose bits are numbered from the **most** significant bit of
/// the first octet — the reverse of the `key-usage-flag` values of §6.5.11.2.
///
/// So Matter's `digitalSignature = 0x0001` is X.509 bit 0, which is `0x80` in the first
/// octet. Trailing zero bits are trimmed and counted, as DER requires for a named bit list.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a KeyUsage bit string is nine bits; §6.5.11.2 puts the low eight in one octet"
)]
fn write_key_usage_bit_string(writer: &mut DerWriter<'_>, usage: KeyUsage) -> Result<()> {
    let bits = usage.bits();
    if bits == 0 {
        // An empty key usage is not a thing a CA signs, and DER would need a special case.
        return Err(invalid());
    }
    let octets = [
        (bits as u8).reverse_bits(),
        ((bits >> 8) as u8).reverse_bits(),
    ];
    // The highest Matter flag set is the lowest-numbered X.509 bit from the end.
    let highest = 15u32.saturating_sub(bits.leading_zeros());
    let used = highest.saturating_add(1);
    let significant = used.div_ceil(8) as usize;
    let unused = u8::try_from(significant.saturating_mul(8))
        .ok()
        .and_then(|total| u8::try_from(used).ok().map(|u| total.wrapping_sub(u)))
        .ok_or_else(invalid)?;

    let mark = writer.mark();
    writer.slice(octets.get(..significant).ok_or_else(invalid)?)?;
    writer.byte(unused)?;
    writer.header(TAG_BIT_STRING, mark)
}

/// `signatureValue BIT STRING`, whose content is the DER `ECDSA-Sig-Value ::= SEQUENCE { r
/// INTEGER, s INTEGER }` — not the fixed-width `r || s` that §3.5.3 and the Matter
/// certificate use.
fn write_signature_value(writer: &mut DerWriter<'_>, cert: &MatterCertificate<'_>) -> Result<()> {
    let mark = writer.mark();
    writer.ecdsa_sig_value(cert.signature.as_bytes())?;
    // The signature is whole octets, so the BIT STRING has no unused bits. `bit_string`
    // cannot be used here: the value was written in place rather than handed over.
    writer.byte(0)?;
    writer.header(TAG_BIT_STRING, mark)
}
