//! Validating a Device Attestation certificate chain (Core §6.2.3.1).
//!
//! Three certificates, no more and no fewer. §6.2.3.1: "It is especially important to ensure
//! the entire chain has a length of exactly 3 elements (PAA certificate, PAI certificate,
//! Device Attestation Certificate) … to avoid unauthorized path chaining (e.g., through
//! multiple PAI certificates)."
//!
//! That fixed length is the point. A general X.509 path builder would happily accept a chain
//! with two intermediates, and a vendor whose PAI was compromised could then mint a PAI of
//! its own beneath it. Matter forecloses that by making the shape part of the rules rather
//! than a policy knob: the PAI's `pathLenConstraint` is 0, and this function only ever walks
//! two links.
//!
//! # When the chain is checked against
//!
//! Not "now". §6.2.3.1: "Chain validation SHALL be performed with respect to the notBefore
//! timestamp of the DAC to ensure that the DAC was valid when it was issued." A device
//! manufactured five years ago has a DAC issued under a PAI that may since have expired, and
//! rejecting it would brick perfectly good hardware. [`verify_dac_chain`] takes that
//! timestamp from the DAC itself, so the caller cannot get it wrong.
//!
//! # What is not here
//!
//! **Revocation.** §6.2.3.1 requires it — "Chain validation SHALL include revocation checks
//! of the DAC and PAI" — and §6.2.4 defines an interoperable way to obtain revocation sets.
//! That needs network access and a policy store, so it belongs to a commissioner rather than
//! to this function; [`DacChain`] exposes the key identifiers a revocation check needs.
//!
//! **PAA trust.** "The PAA SHALL be validated for presence in the Commissioner's trusted
//! root store, which SHOULD include at least the set of globally trusted PAA certificates
//! present in the Distributed Compliance Ledger." The caller supplies the PAA it already
//! trusts; this function does not decide what to trust.

use crate::attestation::cd::CertificationElements;
use crate::attestation::x509::{KeyUsage, X509Certificate};
use crate::error::{Error, ErrorCode, Result};
use crate::msg::VendorId;

fn path_invalid() -> Error {
    Error::new(ErrorCode::CertPathInvalid)
}

fn invalid() -> Error {
    Error::new(ErrorCode::CertInvalid)
}

/// The identity a validated DAC chain establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DacChain {
    /// The Vendor ID, which the DAC and PAI agree on.
    pub vendor_id: VendorId,
    /// The Product ID from the DAC's subject.
    pub product_id: u16,
    /// The PAA's Subject Key Identifier, which a Certification Declaration's
    /// `authorized_paa_list` is checked against and which a revocation set is keyed on.
    pub paa_key_id: Option<[u8; crate::attestation::x509::KEY_ID_LEN]>,
    /// The DAC's `notBefore`, which is the instant the whole chain was validated against.
    pub validated_at: u32,
}

/// Verifies a DAC against a PAI and a trusted PAA (§6.2.3.1).
///
/// `paa` must already be one the caller trusts; a PAA is a trust anchor and is not verified
/// against itself here, for the same reason an operational root is not
/// ([`cert::verify_chain`](crate::cert::verify_chain)).
pub fn verify_dac_chain(
    dac: &X509Certificate<'_>,
    pai: &X509Certificate<'_>,
    paa: &X509Certificate<'_>,
) -> Result<DacChain> {
    check_dac(dac)?;
    check_pai(pai)?;
    check_paa(paa)?;

    // "Chain validation SHALL be performed with respect to the notBefore timestamp of the
    // DAC to ensure that the DAC was valid when it was issued."
    let at = dac.not_before;
    if !pai.is_valid_at(at) || !paa.is_valid_at(at) {
        return Err(Error::new(ErrorCode::CertExpired));
    }

    // §6.2.2.3 rule 6: "The issuer field SHALL match, byte-for-byte, the subject field of the
    // PAI certificate for the PAI that issued this DAC." Byte-for-byte, not "equivalent":
    // two distinguished names that differ only in string type are different names as far as
    // the signature is concerned.
    if dac.issuer != pai.subject || pai.issuer != paa.subject {
        return Err(path_invalid());
    }
    if !pai.verify_signature_of(dac)? || !paa.verify_signature_of(pai)? {
        return Err(path_invalid());
    }

    // "The VendorID value found in the subject DN of the DAC SHALL match the VendorID value
    // in the subject DN of the PAI certificate."
    let vendor_id = dac.subject_vid_pid.vendor_id.ok_or_else(invalid)?;
    if pai.subject_vid_pid.vendor_id != Some(vendor_id) {
        return Err(path_invalid());
    }
    // "If the PAA certificate contains a VendorID value in its subject DN, its value SHALL
    // match the VendorID value in the subject DN of the PAI certificate."
    if paa
        .subject_vid_pid
        .vendor_id
        .is_some_and(|paa_vid| paa_vid != vendor_id)
    {
        return Err(path_invalid());
    }

    let product_id = dac.subject_vid_pid.product_id.ok_or_else(invalid)?;
    // §6.2.2.3 rule 9a: "If a ProductID value was present in the issuer field, the ProductID
    // value found in subject field SHALL match the value found in the issuer field."
    if dac
        .issuer_vid_pid
        .product_id
        .is_some_and(|issuer_pid| issuer_pid != product_id)
    {
        return Err(path_invalid());
    }
    // The PAI's own product id, if it has one, scopes which products it may issue for.
    if pai
        .subject_vid_pid
        .product_id
        .is_some_and(|pai_pid| pai_pid != product_id)
    {
        return Err(path_invalid());
    }

    Ok(DacChain {
        vendor_id,
        product_id,
        paa_key_id: paa.subject_key_id,
        validated_at: at,
    })
}

/// §6.2.2.3's constraints on a DAC.
fn check_dac(dac: &X509Certificate<'_>) -> Result<()> {
    // "Basic Constraint extension SHALL be marked critical and have the cA field set to
    // FALSE." The parser refuses a non-critical one, so reaching here means it was critical.
    let basic = dac.basic_constraints.ok_or_else(invalid)?;
    if basic.is_ca {
        return Err(invalid());
    }
    // "The KeyUsage bitstring SHALL only have the digitalSignature bit set. Other bits SHALL
    // NOT be set."
    if dac.key_usage != Some(KeyUsage::DIGITAL_SIGNATURE) {
        return Err(invalid());
    }
    // Rule 11c and 11d: both key identifiers SHALL be carried.
    if dac.subject_key_id.is_none() || dac.authority_key_id.is_none() {
        return Err(invalid());
    }
    // Rule 4: "The issuer field SHALL have exactly one VendorID value present."
    // Rules 8 and 9: the subject has exactly one of each.
    if dac.issuer_vid_pid.vendor_id.is_none()
        || dac.subject_vid_pid.vendor_id.is_none()
        || dac.subject_vid_pid.product_id.is_none()
    {
        return Err(invalid());
    }
    // Rule 8a: "The VendorID value present in the issuer field SHALL match the VendorID value
    // found in subject field."
    if dac.issuer_vid_pid.vendor_id != dac.subject_vid_pid.vendor_id {
        return Err(invalid());
    }
    Ok(())
}

/// §6.2.2.4's constraints on a PAI.
fn check_pai(pai: &X509Certificate<'_>) -> Result<()> {
    // "Basic Constraint extension SHALL be marked critical and have the cA field set to TRUE
    // and pathLen field set to 0." The pathLen is what forecloses a second intermediate.
    let basic = pai.basic_constraints.ok_or_else(invalid)?;
    if !basic.is_ca || basic.path_len != Some(0) {
        return Err(invalid());
    }
    // "Both the keyCertSign and cRLSign bits SHALL be set … Other bits SHALL NOT be set",
    // with digitalSignature permitted alongside.
    check_ca_key_usage(pai.key_usage)?;
    if pai.subject_key_id.is_none() || pai.authority_key_id.is_none() {
        return Err(invalid());
    }
    // Rule 7: "The subject field SHALL have exactly one VendorID value present."
    if pai.subject_vid_pid.vendor_id.is_none() {
        return Err(invalid());
    }
    Ok(())
}

/// §6.2.2.5's constraints on a PAA.
fn check_paa(paa: &X509Certificate<'_>) -> Result<()> {
    let basic = paa.basic_constraints.ok_or_else(invalid)?;
    // "the cA field set to TRUE. The 'pathLen' field MAY be set and if the 'pathLen' is field
    // is present it SHALL be set to 1."
    if !basic.is_ca || basic.path_len.is_some_and(|len| len != 1) {
        return Err(invalid());
    }
    check_ca_key_usage(paa.key_usage)?;
    // Rule 7: "The issuer and subject fields SHALL match exactly." A PAA is self-signed.
    if paa.issuer != paa.subject {
        return Err(invalid());
    }
    // Rule 8: "A ProductID value SHALL NOT be present in either the subject or issuer fields."
    if paa.subject_vid_pid.product_id.is_some() || paa.issuer_vid_pid.product_id.is_some() {
        return Err(invalid());
    }
    if paa.subject_key_id.is_none() {
        return Err(invalid());
    }
    Ok(())
}

fn check_ca_key_usage(usage: Option<KeyUsage>) -> Result<()> {
    let Some(usage) = usage else {
        return Err(invalid());
    };
    let required = KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN;
    let permitted = required | KeyUsage::DIGITAL_SIGNATURE;
    if !usage.contains(required) || !permitted.contains(usage) {
        return Err(invalid());
    }
    Ok(())
}

/// Checks a Certification Declaration against a validated DAC chain (§6.2.3.1).
///
/// This is the step that ties the two proofs together. The chain says "a genuine device made
/// by vendor V, product P"; the declaration says "the CSA certified vendor V', products
/// P'…". §6.2.3.1 spells out how V and P must relate to V' and P', and the relation depends
/// on whether the declaration carries the `dac_origin_*` fields:
///
/// * **With** them, the DAC's identity is compared against `dac_origin_vendor_id` and
///   `dac_origin_product_id`. This is the case where a product is manufactured under one
///   vendor's attestation PKI but certified under another's — an ODM arrangement.
/// * **Without** them, the DAC's identity is compared against `vendor_id` and the
///   `product_id_array`, which is the ordinary case.
///
/// `basic_information` is the `(VendorID, ProductID)` the device reports from its Basic
/// Information cluster, which the declaration must also match; pass `None` before that
/// cluster exists to check only what the certificates carry.
pub fn check_declaration_against_chain(
    cd: &CertificationElements<'_>,
    chain: &DacChain,
    pai_vendor_id: VendorId,
    pai_product_id: Option<u16>,
    basic_information: Option<(VendorId, u16)>,
) -> Result<()> {
    // "The Certification Declaration SHALL be considered valid only if it contains both or
    // neither of the dac_origin_vendor_id and dac_origin_product_id fields." The decoder
    // already refuses a declaration with one and not the other, so this is a re-statement
    // rather than a check — but the pairing is what the match below relies on.
    match (cd.dac_origin_vendor_id, cd.dac_origin_product_id) {
        (Some(origin_vid), Some(origin_pid)) => {
            // "The VendorID value from the subject DN in the DAC SHALL match the
            // dac_origin_vendor_id field", and the same for the PAI and for the product ids.
            if chain.vendor_id != origin_vid || pai_vendor_id != origin_vid {
                return Err(path_invalid());
            }
            if chain.product_id != origin_pid {
                return Err(path_invalid());
            }
            // "The ProductID value from the subject DN in the PAI, if such a ProductID value
            // appears, SHALL match the dac_origin_product_id field."
            if pai_product_id.is_some_and(|pid| pid != origin_pid) {
                return Err(path_invalid());
            }
        }
        (None, None) => {
            if chain.vendor_id != cd.vendor_id || pai_vendor_id != cd.vendor_id {
                return Err(path_invalid());
            }
            // "The ProductID value from the subject DN in the DAC SHALL be present in the
            // product_id_array field."
            if !cd.covers_product(chain.product_id) {
                return Err(path_invalid());
            }
            if pai_product_id.is_some_and(|pid| !cd.covers_product(pid)) {
                return Err(path_invalid());
            }
        }
        // Unreachable given the decoder, and an error rather than an assumption.
        _ => return Err(invalid()),
    }

    // "If the Certification Declaration contains the authorized_paa_list field … The Subject
    // Key Identifier (SKI) extension value of the PAA certificate, which is the root of trust
    // of the DAC, SHALL be present as one of the values."
    if cd.authorized_paas.is_some() {
        let Some(paa_key_id) = chain.paa_key_id else {
            return Err(path_invalid());
        };
        if !cd.authorizes_paa(&paa_key_id) {
            return Err(path_invalid());
        }
    }

    // "The vendor_id field in the Certification Declaration SHALL match the VendorID
    // attribute found in the Basic Information cluster", and the product id likewise.
    if let Some((reported_vid, reported_pid)) = basic_information
        && (cd.vendor_id != reported_vid || !cd.covers_product(reported_pid))
    {
        return Err(path_invalid());
    }

    Ok(())
}
