//! Validating an operational certificate chain (Core §6.4.5).
//!
//! A node presents a NOC, optionally preceded by an ICAC. The verifier already holds the
//! root: "A Root CA certificate is self-signed. They are not verified but rather trusted
//! because they were provisioned by a trusted Commissioner" — §6.4.5.3, which is the whole
//! reason the chain terminates somewhere.
//!
//! # What a chain check is, concretely
//!
//! Four things have to line up at every link, and each catches a different attack:
//!
//! | Check | What it stops |
//! |---|---|
//! | signature over the regenerated DER | a forged certificate |
//! | issuer DN equals the issuer's subject DN | a certificate spliced under the wrong CA |
//! | `is-ca`, key usage, path length | a leaf certificate used to sign others |
//! | `matter-fabric-id` agreement | a valid certificate from a *different* fabric |
//!
//! The signature check is the one that needs [`der`]: §6.4.5's "The signature
//! field of a certificate SHALL be calculated using the X.509v3 encoding of the
//! certificate", so the DER has to be rebuilt before anything can be hashed.
//!
//! # Time
//!
//! [`verify_chain`] takes an `Option<u32>` for now, because §6.4.5.1 permits omitting the
//! check: "For constrained or sleepy devices that lack accurate time, enforcement of an
//! NOC's validity period MAY be omitted." Passing `None` is that choice, made explicitly,
//! rather than a validity check that was quietly never written.

use crate::cert::{CERT_DER_MAX, CertType, DnAttributeKind, MatterCertificate, der};
use crate::crypto::verify;
use crate::error::{Error, ErrorCode, Result};
use crate::msg::{FabricId, NodeId};

/// The operational identity a validated chain establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The NOC's `matter-node-id`.
    pub node_id: NodeId,
    /// The `matter-fabric-id` shared by the chain.
    pub fabric_id: FabricId,
    /// Every `matter-noc-cat` the NOC carried (§6.6.2.1.2).
    ///
    /// Part of the *identity*, not a detail of the certificate: §6.6.6.3 builds the
    /// access-control subject from a CASE session's node id **and** its CATs, so dropping
    /// them here would leave every CAT-based access control entry unable to match anything —
    /// silently, and in the direction that denies rather than grants.
    pub cats: heapless::Vec<crate::msg::CaseAuthenticatedTag, { crate::cert::dn::MAX_NOC_CATS }>,
}

fn path_invalid() -> Error {
    Error::new(ErrorCode::CertPathInvalid)
}

/// Verifies a Node Operational Certificate against a trusted root, through an optional
/// intermediate.
///
/// `at` is the current time as a Matter `epoch-s`, or `None` on a node without a clock.
///
/// The root is assumed trusted and is **not** verified against itself: §6.4.5.3 says trust
/// in it comes from the commissioner that installed it, not from its own self-signature.
/// What *is* checked is that it is a well-formed RCAC, because a malformed one would let
/// every later check pass vacuously.
pub fn verify_chain(
    noc: &MatterCertificate<'_>,
    icac: Option<&MatterCertificate<'_>>,
    root: &MatterCertificate<'_>,
    at: Option<u32>,
) -> Result<VerifiedIdentity> {
    root.validate_as(CertType::Rcac)?;
    noc.validate_as(CertType::Noc)?;
    if let Some(icac) = icac {
        icac.validate_as(CertType::Icac)?;
    }

    // The issuer of the NOC is the ICAC when there is one, and the root otherwise —
    // §6.4.5.1: "issued by either a Root CA trusted within the Fabric or by an Intermediate
    // Certificate Authority whose ICA certificate is directly issued by such a Root CA."
    let noc_issuer = icac.unwrap_or(root);
    check_link(noc, noc_issuer, at)?;
    if let Some(icac) = icac {
        check_link(icac, root, at)?;
        // "An ICA certificate is directly issued by such a Root CA" — one level, so the
        // root's path length constraint, if any, must permit exactly this.
        if root
            .extensions
            .basic_constraints()
            .and_then(|b| b.path_len_constraint)
            .is_some_and(|limit| limit < 1)
        {
            return Err(path_invalid());
        }
    }
    if let Some(at) = at {
        check_validity(root, at)?;
    }

    // §6.5.6.3: "When any matter-fabric-id attributes are present in either the Matter Root
    // CA Certificate or the Matter ICA Certificate, the value SHALL match the one present
    // in the Matter Node Operational Certificate (NOC) within the same certificate chain."
    let fabric_id = noc.fabric_id().ok_or_else(path_invalid)?;
    for authority in [Some(root), icac].into_iter().flatten() {
        if authority.subject.count(DnAttributeKind::MatterFabricId) != 0
            && authority.fabric_id() != Some(fabric_id)
        {
            return Err(path_invalid());
        }
    }

    Ok(VerifiedIdentity {
        node_id: noc.node_id().ok_or_else(path_invalid)?,
        fabric_id,
        cats: noc.subject.noc_cats(),
    })
}

/// Checks one certificate against the one that issued it.
fn check_link(
    subject: &MatterCertificate<'_>,
    issuer: &MatterCertificate<'_>,
    at: Option<u32>,
) -> Result<()> {
    // The issuer has to be able to sign, which for an RCAC or ICAC its own `validate`
    // already established; asserting it here too makes this function safe to call on its
    // own.
    if !issuer.is_ca() {
        return Err(path_invalid());
    }
    if subject.issuer != issuer.subject {
        return Err(path_invalid());
    }
    // §6.5.11.5: the authority key identifier is "the 160-bit SHA-1 hash of the public key
    // used to verify the certificate's signature" — so it names the issuer's subject key
    // identifier. This is a cheap pre-filter, not a security check; the signature is.
    match (
        subject.extensions.authority_key_id(),
        issuer.extensions.subject_key_id(),
    ) {
        (Some(authority), Some(subject_key)) if authority == subject_key => {}
        _ => return Err(path_invalid()),
    }
    if let Some(at) = at {
        check_validity(subject, at)?;
    }

    let mut buf = [0u8; CERT_DER_MAX];
    let tbs = der::tbs_certificate(subject, &mut buf)?;
    if !verify(&issuer.public_key, tbs, &subject.signature)? {
        return Err(path_invalid());
    }
    Ok(())
}

fn check_validity(cert: &MatterCertificate<'_>, at: u32) -> Result<()> {
    if cert.is_valid_at(at) {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::CertExpired))
    }
}

/// Verifies that a root certificate's self-signature is consistent.
///
/// Not part of [`verify_chain`], and deliberately: §6.4.5.3 makes a root trusted by
/// provenance, not by its own signature, and a self-signature proves only that whoever made
/// the certificate held the key in it. It is worth running once when a root is *installed*
/// — `AddTrustedRootCertificate` — where it catches a corrupted or mis-transcribed root
/// before it is committed to the fabric table.
pub fn verify_self_signed(root: &MatterCertificate<'_>) -> Result<bool> {
    root.validate_as(CertType::Rcac)?;
    if root.issuer != root.subject {
        return Ok(false);
    }
    let mut buf = [0u8; CERT_DER_MAX];
    let tbs = der::tbs_certificate(root, &mut buf)?;
    verify(&root.public_key, tbs, &root.signature)
}
