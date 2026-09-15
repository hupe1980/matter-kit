//! A development attestation chain (Core §6.2.2) — PAA, PAI and DAC that a test or a
//! development device can actually use.
//!
//! Every Matter device carries a Device Attestation Certificate, provisioned in the factory and
//! chaining to a Product Attestation Authority the CSA has approved. A device without one
//! cannot be commissioned by a conformant commissioner without a warning, and a *test* device
//! without one cannot exercise §6.2.3's procedure at all — which is most of what makes
//! commissioning security rather than a handshake.
//!
//! So this builds one. It is the development counterpart of the real thing:
//!
//! ```text
//! PAA  self-signed, CA, path length 1      "Matter Development PAA"
//!  └── PAI  CA, path length 0, Mvid        "Matter Development PAI, Mvid:FFF1"
//!       └── DAC  not a CA, Mvid + Mpid     "Matter Development DAC, Mvid:FFF1 Mpid:8000"
//! ```
//!
//! # This is not a certification path
//!
//! A PAA here is one this code made up, and no commissioner should trust it. §6.2.2.1 makes the
//! trust decision the commissioner's — it holds the PAAs it accepts — so a chain from here is
//! useful exactly where the commissioner has been told to accept it: a test, a development
//! harness, a factory bring-up before the real credentials arrive. `0xFFF1`–`0xFFF4` are the
//! vendor ids the CSA reserves for exactly this, and [`DevelopmentChain`] defaults to the first.
//!
//! # The VID and PID go in the Common Name
//!
//! §6.2.2.2 gives two ways to carry them, and this uses the *fallback*: the text form inside the
//! Common Name, `"Mvid:FFF1 Mpid:8000"`. Not because it is better — §6.2.2.2 prefers the
//! Matter-specific RDN attributes — but because it is the form that needs no OID this crate's
//! certificate model does not already carry, and both are equally valid to a conformant
//! verifier. §6.2.2.2 is explicit that the fallback exists for exactly this reason.

use crate::cert::dn::{DistinguishedName, DnAttribute, DnAttributeKind};
use crate::cert::{
    BasicConstraints, CERT_DER_MAX, EllipticCurveId, Extension, Extensions, KEY_ID_LEN, KeyUsage,
    MatterCertificate, PublicKeyAlgorithm, SignatureAlgorithm, der,
};
use crate::crypto::{KeyHandle, KeyStore, PublicKey, Signature};
use crate::error::{Error, ErrorCode, Result};
use crate::msg::VendorId;

/// The longest Common Name this builds — a label, a VID and a PID.
const CN_MAX: usize = 64;

/// A vendor id the CSA reserves for test and development use.
///
/// §6.2.2.1 and the DCL both treat `0xFFF1`–`0xFFF4` as non-production. A device shipped with
/// one of these will not pass certification, which is the point: a development chain should be
/// visibly a development chain.
pub const TEST_VENDOR_ID: VendorId = VendorId(0xFFF1);

/// A development attestation authority.
///
/// Holds a key *handle*, never a key — the same argument as [`CertAuthority`](crate::ca::CertAuthority):
/// a factory that keeps its PAA in an HSM and a test that keeps it in RAM run the same code.
#[derive(Debug, Clone, Copy)]
pub struct DevelopmentChain {
    vendor_id: VendorId,
    /// §6.2.2.4's `not-before`/`not-after`, in seconds since the Matter epoch.
    not_before: u32,
    not_after: u32,
}

impl DevelopmentChain {
    /// A chain for [`TEST_VENDOR_ID`], valid from `not_before` for `years`.
    #[must_use]
    pub const fn new(not_before: u32, years: u32) -> Self {
        Self {
            vendor_id: TEST_VENDOR_ID,
            not_before,
            not_after: not_before.saturating_add(years.saturating_mul(31_557_600)),
        }
    }

    /// The same chain for a different vendor id.
    ///
    /// Anything outside `0xFFF1`–`0xFFF4` is refused: a development chain claiming a real
    /// vendor's id is a forgery, however well-intentioned, and §6.2.2 gives a commissioner no
    /// way to tell the two apart except the id.
    pub fn for_vendor(mut self, vendor_id: VendorId) -> Result<Self> {
        if !(0xFFF1..=0xFFF4).contains(&vendor_id.0) {
            return Err(Error::new(ErrorCode::InvalidArgument));
        }
        self.vendor_id = vendor_id;
        Ok(self)
    }

    /// The vendor id this chain attests to.
    #[must_use]
    pub const fn vendor_id(&self) -> VendorId {
        self.vendor_id
    }

    /// Writes a self-signed Product Attestation Authority certificate into `buf`.
    ///
    /// §6.2.2.4 rule 2: a PAA is a CA. `verify_dac_chain` additionally requires its path-length
    /// constraint to be absent or exactly 1 — one intermediate between it and a DAC, which is
    /// the shape §6.2.2 defines and no other.
    pub fn paa<'b, K: KeyStore>(
        &self,
        keys: &K,
        buf: &'b mut [u8],
        key: KeyHandle,
    ) -> Result<&'b [u8]> {
        let public_key = keys.public_key(key)?;
        let name = Name::plain("Matter Development PAA")?;
        self.sign(
            keys,
            buf,
            key,
            name.dn()?,
            name.dn()?,
            &public_key,
            &public_key,
            BasicConstraints {
                is_ca: true,
                path_len_constraint: Some(1),
            },
            KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN,
        )
    }

    /// Writes a Product Attestation Intermediate certificate into `buf`.
    ///
    /// §6.2.2.4 rule 5 puts the vendor id in the subject and rule 3 fixes the path length at 0:
    /// a PAI signs DACs and nothing else.
    pub fn pai<'b, K: KeyStore>(
        &self,
        keys: &K,
        buf: &'b mut [u8],
        paa_key: KeyHandle,
        pai_public: &PublicKey,
    ) -> Result<&'b [u8]> {
        let paa_public = keys.public_key(paa_key)?;
        let issuer = Name::plain("Matter Development PAA")?;
        let subject = Name::with_vid("Matter Development PAI", self.vendor_id)?;
        self.sign(
            keys,
            buf,
            paa_key,
            issuer.dn()?,
            subject.dn()?,
            pai_public,
            &paa_public,
            BasicConstraints {
                is_ca: true,
                path_len_constraint: Some(0),
            },
            KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN,
        )
    }

    /// Writes a Device Attestation Certificate into `buf`.
    ///
    /// §6.2.2.4 rule 8 and 9: the subject carries exactly one vendor id and exactly one product
    /// id, and rule 8a makes the vendor id match the issuer's — which is why the PAI's own name
    /// is rebuilt here from the same `vendor_id` rather than passed in.
    pub fn dac<'b, K: KeyStore>(
        &self,
        keys: &K,
        buf: &'b mut [u8],
        pai_key: KeyHandle,
        dac_public: &PublicKey,
        product_id: u16,
    ) -> Result<&'b [u8]> {
        let pai_public = keys.public_key(pai_key)?;
        let issuer = Name::with_vid("Matter Development PAI", self.vendor_id)?;
        let subject = Name::with_vid_pid("Matter Development DAC", self.vendor_id, product_id)?;
        self.sign(
            keys,
            buf,
            pai_key,
            issuer.dn()?,
            subject.dn()?,
            dac_public,
            &pai_public,
            BasicConstraints {
                is_ca: false,
                path_len_constraint: None,
            },
            // §6.2.2.4 rule 12: "The KeyUsage bitstring SHALL only have the digitalSignature
            // bit set." A DAC signs attestations; it is not a CA and does not do key agreement.
            KeyUsage::DIGITAL_SIGNATURE,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign<'b, K: KeyStore>(
        &self,
        keys: &K,
        buf: &'b mut [u8],
        signing_key: KeyHandle,
        issuer: DistinguishedName<'_>,
        subject: DistinguishedName<'_>,
        public_key: &PublicKey,
        authority_key: &PublicKey,
        constraints: BasicConstraints,
        key_usage: KeyUsage,
    ) -> Result<&'b [u8]> {
        let mut extensions = Extensions::new();
        extensions.push(Extension::BasicConstraints(constraints))?;
        extensions.push(Extension::KeyUsage(key_usage))?;
        extensions.push(Extension::SubjectKeyId(key_id(public_key)?))?;
        extensions.push(Extension::AuthorityKeyId(key_id(authority_key)?))?;

        // The subject key id doubles as the serial: a certificate is identified by (issuer,
        // serial), and deriving it from the key makes reissuing the same key the same
        // certificate rather than a second identity. `positive_serial` because §6.5.4 adopts
        // RFC 5280's limitation on serial numbers, RFC 5280 §4.1.2.2 requires a positive
        // integer, and a digest's top bit is the INTEGER's sign — and because one digest in 256
        // is a redundant sign octet, which is not valid content at all.
        let serial = crate::cert::positive_serial(key_id(public_key)?);
        let mut cert = MatterCertificate {
            serial_number: &serial,
            signature_algorithm: SignatureAlgorithm::EcdsaWithSha256,
            issuer,
            not_before: self.not_before,
            not_after: self.not_after,
            subject,
            public_key_algorithm: PublicKeyAlgorithm::EcPubKey,
            elliptic_curve_id: EllipticCurveId::Prime256V1,
            public_key: *public_key,
            extensions,
            signature: Signature::from_bytes([0u8; 64]),
        };
        let mut tbs_buf = [0u8; CERT_DER_MAX];
        let tbs = der::tbs_certificate(&cert, &mut tbs_buf)?;
        cert.signature = keys.sign(signing_key, tbs)?;
        // The *X.509* form, not the Matter TLV one: §6.2.2 attestation certificates travel as
        // DER, which is why `CertificateChainResponse` carries 600 octets and not 400.
        der::certificate(&cert, buf)
    }
}

/// A Common Name carrying §6.2.2.2's fallback VID/PID text.
struct Name {
    text: heapless::String<CN_MAX>,
}

impl Name {
    fn plain(label: &str) -> Result<Self> {
        let mut text = heapless::String::new();
        text.push_str(label)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument))?;
        Ok(Self { text })
    }

    fn with_vid(label: &str, vendor_id: VendorId) -> Result<Self> {
        let mut name = Self::plain(label)?;
        name.push(" Mvid:", vendor_id.0)?;
        Ok(name)
    }

    fn with_vid_pid(label: &str, vendor_id: VendorId, product_id: u16) -> Result<Self> {
        let mut name = Self::with_vid(label, vendor_id)?;
        name.push(" Mpid:", product_id)?;
        Ok(name)
    }

    /// §6.2.2.2's fallback encoding: "uppercase hexadecimal, exactly 4 characters".
    ///
    /// Uppercase because §6.2.2.2's own example calls `Mvid:fff1` invalid, and this crate's
    /// parser agrees — so a factory that wrote lowercase would produce a certificate its own
    /// verifier rejects.
    fn push(&mut self, prefix: &str, value: u16) -> Result<()> {
        self.text
            .push_str(prefix)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument))?;
        for shift in [12u32, 8, 4, 0] {
            let nibble = u8::try_from((value >> shift) & 0xF).unwrap_or(0);
            let digit = match nibble {
                0..=9 => b'0'.saturating_add(nibble),
                _ => b'A'.saturating_add(nibble.saturating_sub(10)),
            };
            self.text
                .push(char::from(digit))
                .map_err(|_| Error::new(ErrorCode::InvalidArgument))?;
        }
        Ok(())
    }

    fn dn(&self) -> Result<DistinguishedName<'_>> {
        let mut dn = DistinguishedName::new();
        dn.push(DnAttribute::string(
            DnAttributeKind::CommonName,
            self.text.as_str(),
        ))?;
        Ok(dn)
    }
}

/// The same 20-octet key identifier [`ca`](crate::ca) uses, and for the same reason: §6.2.2.4
/// rules 11c and 11d require both identifiers, and they are a chain-building hint rather than a
/// security check.
fn key_id(public_key: &PublicKey) -> Result<[u8; KEY_ID_LEN]> {
    let digest = crate::crypto::hash(public_key.as_bytes());
    let prefix = digest
        .get(..KEY_ID_LEN)
        .ok_or_else(|| Error::new(ErrorCode::InvalidState))?;
    <[u8; KEY_ID_LEN]>::try_from(prefix).map_err(|_| Error::new(ErrorCode::InvalidState))
}
