//! A fabric's certificate authority (Core §6.5) — issuing the identities a fabric is made of.
//!
//! Every Matter fabric is rooted in one self-signed certificate, and every node on it holds a
//! Node Operational Certificate chaining back to that root. §6.4.5.3 is blunt about what the
//! root's authority rests on:
//!
//! > Trust in the Root CA is established by provenance, not by the self-signature.
//!
//! So a root is trusted because a commissioner installed it, and the CA's real job is the
//! *other* two: issuing an ICAC when the deployment wants one, and issuing a NOC for each node
//! it commissions.
//!
//! # This is the administrator's half of commissioning
//!
//! §11.18 gives the device's half — it generates a key, signs a CSR, and takes back a NOC. The
//! CSR carries a public key and nothing else the CA is obliged to believe, which is the point:
//! the *commissioner* decides the node id, the fabric id and the CATs, and the device is told
//! what it has become. A CA that echoed a subject from the CSR would let a device name itself.
//!
//! # Keys stay in the store
//!
//! Nothing here takes a private key. [`CertAuthority`](crate::ca::CertAuthority) holds a [`KeyHandle`](crate::crypto::KeyHandle)
//! and signs through the [`KeyStore`](crate::crypto::KeyStore), so a deployment with the CA key in a secure element works the same way as
//! one with it in RAM — which is the case that matters, because this key is the fabric.
//!
//! ```rust,ignore
//! use matter_kit::ca::{CertAuthority, Validity};
//!
//! // A fabric's root, self-signed, valid for ten years.
//! let mut buf = [0u8; matter_kit::cert::CERT_TLV_MAX];
//! let root = ca.self_signed_root(&keys, &mut buf, Validity::years(epoch_now, 10))?;
//!
//! // ...and a node's operational certificate under it.
//! let mut buf = [0u8; matter_kit::cert::CERT_TLV_MAX];
//! let noc = ca.issue_noc(&keys, &mut buf, &Identity::new(fabric_id, node_id), &csr_key, validity)?;
//! ```

use crate::cert::dn::{DistinguishedName, DnAttribute, DnAttributeKind};
use crate::cert::{
    BasicConstraints, CERT_DER_MAX, EllipticCurveId, Extension, Extensions, KEY_ID_LEN,
    KeyPurposeId, KeyUsage, MatterCertificate, PublicKeyAlgorithm, SignatureAlgorithm, der,
};
use crate::crypto::{KeyHandle, KeyStore, PublicKey};
use crate::error::{Error, ErrorCode, Result};
use crate::msg::{CaseAuthenticatedTag, FabricId, NodeId};

/// §6.5.5's `not-before`/`not-after`, in seconds since the Matter epoch (2000-01-01 UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// `not-before`.
    pub not_before: u32,
    /// `not-after`. Zero is §6.5.5's "no well-defined expiration time".
    pub not_after: u32,
}

impl Validity {
    /// A window of `years` starting at `from`.
    ///
    /// §6.5.5 permits `not-after` to be zero, meaning "no well-defined expiration time", and
    /// this never produces one: a fabric certificate that cannot expire is one that cannot be
    /// rotated on a schedule, and the deployments that need that are rare enough to say so
    /// explicitly with [`Validity::forever`].
    #[must_use]
    pub const fn years(from: u32, years: u32) -> Self {
        Self {
            not_before: from,
            // 365.25 days, so a decade does not drift a fortnight early.
            not_after: from.saturating_add(years.saturating_mul(31_557_600)),
        }
    }

    /// §6.5.5's open-ended certificate — `not-after` of zero.
    #[must_use]
    pub const fn forever(from: u32) -> Self {
        Self {
            not_before: from,
            not_after: 0,
        }
    }
}

/// Who a NOC is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// The fabric.
    pub fabric_id: FabricId,
    /// The node.
    pub node_id: NodeId,
    /// §6.6.2.1.2's CASE Authenticated Tags, at most three (§6.5.6.3).
    pub cats: [Option<CaseAuthenticatedTag>; MAX_CATS],
}

/// §6.5.6.3, on a NOC's subject DN: "The subject DN MAY encode at most three matter-noc-cat
/// attributes."
pub const MAX_CATS: usize = 3;

impl Identity {
    /// A plain identity with no CATs.
    #[must_use]
    pub const fn new(fabric_id: FabricId, node_id: NodeId) -> Self {
        Self {
            fabric_id,
            node_id,
            cats: [None; MAX_CATS],
        }
    }

    /// The same identity carrying `cats`.
    ///
    /// Refuses more than [`MAX_CATS`], and refuses two tags with the same *identifier*: §6.6.2.1.2
    /// makes the low sixteen bits a version, so two tags sharing an identifier are two versions
    /// of one group, and an ACL matching on the higher would be silently satisfied by the lower.
    pub fn with_cats(mut self, cats: &[CaseAuthenticatedTag]) -> Result<Self> {
        if cats.len() > MAX_CATS {
            return Err(Error::new(ErrorCode::InvalidArgument));
        }
        for (index, tag) in cats.iter().enumerate() {
            if cats
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.identifier() == tag.identifier())
            {
                return Err(Error::new(ErrorCode::InvalidArgument));
            }
            if let Some(slot) = self.cats.get_mut(index) {
                *slot = Some(*tag);
            }
        }
        Ok(self)
    }
}

/// Which kind of authority a [`CertAuthority`] is.
///
/// It decides one thing that matters: which DN attribute goes in the `issuer` of everything it
/// signs. §6.5.6.3 gives a root `matter-rcac-id` and an intermediate `matter-icac-id`, and
/// [`verify_chain`](crate::cert::verify_chain) compares `subject.issuer` to the issuer's own
/// `subject` attribute for attribute — so getting this wrong produces a certificate that is
/// individually valid and chains to nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// A self-signed Root CA (§6.5.6.2), identified by `matter-rcac-id`.
    Root,
    /// An Intermediate CA (§6.5.6.2), identified by `matter-icac-id`.
    ///
    /// §6.4.5.1 permits exactly one level — "an Intermediate Certificate Authority whose ICA
    /// certificate is directly issued by such a Root CA" — so an intermediate may issue NOCs
    /// and nothing else. [`CertAuthority::issue_icac`] and
    /// [`CertAuthority::self_signed_root`] refuse on one.
    Intermediate,
}

/// A fabric's certificate authority.
///
/// Holds the CA's key *handle*, never the key. Signing goes through the [`KeyStore`], so a
/// deployment that keeps the fabric root in a secure element and one that keeps it in RAM use
/// the same code — and the first is the one that matters, because this key is the fabric.
#[derive(Debug, Clone, Copy)]
pub struct CertAuthority {
    key: KeyHandle,
    kind: Authority,
    /// The `matter-rcac-id` or `matter-icac-id` in this CA's own subject (§6.5.6.2).
    rcac_id: u64,
    /// The fabric the root is scoped to, when it is scoped at all.
    ///
    /// §6.5.6.3 permits a root with no `matter-fabric-id`, and then it may sign NOCs for any
    /// fabric. One *with* the attribute is pinned, and [`verify_chain`](crate::cert::verify_chain)
    /// enforces that every NOC under it names the same fabric.
    fabric_id: Option<FabricId>,
}

impl CertAuthority {
    /// A root CA over a key already in the store, identified by `rcac_id`.
    #[must_use]
    pub const fn new(key: KeyHandle, rcac_id: u64) -> Self {
        Self {
            key,
            kind: Authority::Root,
            rcac_id,
            fabric_id: None,
        }
    }

    /// An intermediate CA over a key already in the store, identified by `icac_id`.
    ///
    /// `icac_id` must be the one that went into the ICAC's subject — this is what the NOCs it
    /// signs name as their issuer, and `verify_chain` compares the two.
    #[must_use]
    pub const fn intermediate(key: KeyHandle, icac_id: u64) -> Self {
        Self {
            key,
            kind: Authority::Intermediate,
            rcac_id: icac_id,
            fabric_id: None,
        }
    }

    /// Which kind of authority this is.
    #[must_use]
    pub const fn kind(&self) -> Authority {
        self.kind
    }

    /// The same CA, pinned to one fabric (§6.5.6.3).
    #[must_use]
    pub const fn for_fabric(mut self, fabric_id: FabricId) -> Self {
        self.fabric_id = Some(fabric_id);
        self
    }

    /// The key handle this CA signs with.
    #[must_use]
    pub const fn key(&self) -> KeyHandle {
        self.key
    }

    /// Writes the fabric's self-signed root certificate (§6.5.6.2) into `buf`.
    ///
    /// The root is a CA with no path-length constraint, so it may sign an ICAC or a NOC
    /// directly — §6.4.5.1 permits both, and which one a deployment uses is its own choice.
    pub fn self_signed_root<'b, K: KeyStore>(
        &self,
        keys: &K,
        buf: &'b mut [u8],
        validity: Validity,
    ) -> Result<&'b [u8]> {
        if self.kind != Authority::Root {
            return Err(Error::new(ErrorCode::InvalidArgument));
        }
        let public_key = keys.public_key(self.key)?;
        let mut subject = DistinguishedName::new();
        subject.push(DnAttribute::uint(
            DnAttributeKind::MatterRcacId,
            self.rcac_id,
        ))?;
        if let Some(fabric_id) = self.fabric_id {
            subject.push(DnAttribute::uint(
                DnAttributeKind::MatterFabricId,
                fabric_id.0,
            ))?;
        }
        // §6.5.11.2: an RCAC's key usage is "keyCertSign and CRLSign" — no digitalSignature,
        // because the root signs certificates and revocation lists and nothing else. A root
        // that could also sign arbitrary messages would be usable for more than it is trusted
        // for.
        self.sign_into(
            keys,
            buf,
            &subject.clone(),
            &subject,
            &public_key,
            validity,
            Extension::BasicConstraints(BasicConstraints {
                is_ca: true,
                path_len_constraint: None,
            }),
            KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN,
            // §6.5.12: "For Matter ICA Certificate and Matter Root CA Certificate: the extended
            // key usage extension SHALL NOT be present." A CA is not an endpoint.
            &[],
            &public_key,
        )
    }

    /// Writes an intermediate CA certificate (§6.5.6.2) for `public_key` into `buf`.
    ///
    /// §6.4.5.1 allows exactly one level: "an Intermediate Certificate Authority whose ICA
    /// certificate is directly issued by such a Root CA", so this sets a path-length constraint
    /// of zero. Without it a compromised ICAC could mint further CAs and the chain would stop
    /// meaning what the root said it meant.
    pub fn issue_icac<'b, K: KeyStore>(
        &self,
        keys: &K,
        buf: &'b mut [u8],
        icac_id: u64,
        public_key: &PublicKey,
        validity: Validity,
    ) -> Result<&'b [u8]> {
        // §6.4.5.1 permits one level: "an Intermediate Certificate Authority whose ICA
        // certificate is directly issued by such a Root CA". An intermediate that could mint
        // further intermediates would make the chain's depth unbounded, and the path-length
        // constraint this very function writes says it must not.
        if self.kind != Authority::Root {
            return Err(Error::new(ErrorCode::InvalidArgument));
        }
        let root_key = keys.public_key(self.key)?;
        let mut subject = DistinguishedName::new();
        subject.push(DnAttribute::uint(DnAttributeKind::MatterIcacId, icac_id))?;
        if let Some(fabric_id) = self.fabric_id {
            subject.push(DnAttribute::uint(
                DnAttributeKind::MatterFabricId,
                fabric_id.0,
            ))?;
        }
        self.sign_into(
            keys,
            buf,
            &self.issuer()?,
            &subject,
            public_key,
            validity,
            Extension::BasicConstraints(BasicConstraints {
                is_ca: true,
                path_len_constraint: Some(0),
            }),
            KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN,
            &[],
            &root_key,
        )
    }

    /// Writes a Node Operational Certificate (§6.5.6.1) into `buf`.
    ///
    /// `public_key` is the one the node generated and put in its `CSRRequest` response
    /// (§11.18.6.5), and it is the *only* thing the CSR contributes: §6.5.6.1's subject is the
    /// authority's to choose. A CA that echoed a subject the device proposed would let a device
    /// name itself, and a device that could name itself could name itself as somebody else.
    pub fn issue_noc<'b, K: KeyStore>(
        &self,
        keys: &K,
        buf: &'b mut [u8],
        identity: &Identity,
        public_key: &PublicKey,
        validity: Validity,
    ) -> Result<&'b [u8]> {
        // §6.5.6.3: a root pinned to one fabric may only sign for that fabric. Catching it here
        // rather than at `verify_chain` means the CA never emits a certificate that cannot be
        // used, instead of the device discovering it at `AddNOC`.
        if self
            .fabric_id
            .is_some_and(|pinned| pinned != identity.fabric_id)
        {
            return Err(Error::new(ErrorCode::InvalidArgument));
        }
        // §6.5.6.1: "A Node Operational Certificate SHALL have exactly one matter-node-id and
        // exactly one matter-fabric-id attribute." And §2.5.5 forbids a group or an unspecified
        // node id as an operational identity.
        if !identity.node_id.is_operational() {
            return Err(Error::new(ErrorCode::InvalidArgument));
        }
        let root_key = keys.public_key(self.key)?;
        let mut subject = DistinguishedName::new();
        subject.push(DnAttribute::uint(
            DnAttributeKind::MatterFabricId,
            identity.fabric_id.0,
        ))?;
        subject.push(DnAttribute::uint(
            DnAttributeKind::MatterNodeId,
            identity.node_id.0,
        ))?;
        for cat in identity.cats.iter().flatten() {
            subject.push(DnAttribute::uint(
                DnAttributeKind::MatterNocCat,
                u64::from(cat.0),
            ))?;
        }
        // §6.5.11.2 and §6.5.11.3: a NOC signs and does key agreement for CASE, and is not a
        // CA. `id-kp-serverAuth` and `id-kp-clientAuth` because a node is both — it answers
        // interactions and initiates them.
        self.sign_into(
            keys,
            buf,
            &self.issuer()?,
            &subject,
            public_key,
            validity,
            Extension::BasicConstraints(BasicConstraints {
                is_ca: false,
                path_len_constraint: None,
            }),
            KeyUsage::DIGITAL_SIGNATURE,
            // §6.5.12: a NOC's extended key usage is "exactly two key-purpose-id values:
            // id-kp-serverAuth and id-kp-clientAuth". A node is both — it answers interactions
            // and initiates them — and a certificate carrying only one would be refused by
            // every conformant peer.
            &[KeyPurposeId::ServerAuth, KeyPurposeId::ClientAuth],
            &root_key,
        )
    }

    /// The issuer DN this CA writes into the certificates it signs.
    ///
    /// The same attributes as this CA's own subject — §6.5.6.3 makes the link, and
    /// [`verify_chain`](crate::cert::verify_chain) compares them attribute for attribute. A root
    /// is named by `matter-rcac-id` and an intermediate by `matter-icac-id`, so an authority
    /// that wrote the wrong one would produce certificates that are individually valid and
    /// chain to nothing.
    fn issuer(&self) -> Result<DistinguishedName<'static>> {
        let mut issuer = DistinguishedName::new();
        issuer.push(DnAttribute::uint(
            match self.kind {
                Authority::Root => DnAttributeKind::MatterRcacId,
                Authority::Intermediate => DnAttributeKind::MatterIcacId,
            },
            self.rcac_id,
        ))?;
        if let Some(fabric_id) = self.fabric_id {
            issuer.push(DnAttribute::uint(
                DnAttributeKind::MatterFabricId,
                fabric_id.0,
            ))?;
        }
        Ok(issuer)
    }

    /// Builds, signs and encodes a certificate.
    #[allow(clippy::too_many_arguments)]
    fn sign_into<'b, K: KeyStore>(
        &self,
        keys: &K,
        buf: &'b mut [u8],
        issuer: &DistinguishedName<'_>,
        subject: &DistinguishedName<'_>,
        public_key: &PublicKey,
        validity: Validity,
        constraints: Extension<'static>,
        key_usage: KeyUsage,
        extended_key_usage: &[KeyPurposeId],
        authority_key: &PublicKey,
    ) -> Result<&'b [u8]> {
        let mut extensions = Extensions::new();
        extensions.push(constraints)?;
        extensions.push(Extension::KeyUsage(key_usage))?;
        if !extended_key_usage.is_empty() {
            let purposes = heapless::Vec::from_slice(extended_key_usage)
                .map_err(|_| Error::new(ErrorCode::InvalidArgument))?;
            extensions.push(Extension::ExtendedKeyUsage(purposes))?;
        }
        // §6.5.11.4 and §6.5.11.5: both key identifiers are "the 160-bit SHA-1 hash", and this
        // crate has no SHA-1 — deliberately. §6.5.11.4 permits any method that produces a
        // distinct 20-octet value ("other methods of generating unique key identifiers are also
        // acceptable"), so these are the first 20 octets of SHA-256 over the public key, which
        // is what rs-matter and the CHIP SDK's test CA both do. The identifiers are a
        // *pre-filter* for chain building, never a security check — `verify_chain` says so and
        // then checks the signature.
        extensions.push(Extension::SubjectKeyId(key_id(public_key)?))?;
        extensions.push(Extension::AuthorityKeyId(key_id(authority_key)?))?;

        // §6.5.4: "A Matter certificate follows the same limitation on admissible serial
        // numbers as in [RFC 5280]", and RFC 5280 §4.1.2.2 is where "The serial number MUST be
        // a positive integer" lives — the Matter text delegates rather than restating it. The
        // subject key id is already unique per key, and a certificate is identified by
        // (issuer, serial) — so deriving it from the subject key makes two certificates for the
        // same key and issuer collide, which is what we want: reissuing is not a new identity.
        //
        // Through `positive_serial`, because a digest is not a positive integer: its top bit is
        // the INTEGER's sign, and one digest in 256 is not even valid DER content.
        let serial = crate::cert::positive_serial(key_id(public_key)?);
        let mut cert = MatterCertificate {
            serial_number: &serial,
            signature_algorithm: SignatureAlgorithm::EcdsaWithSha256,
            issuer: issuer.clone(),
            not_before: validity.not_before,
            not_after: validity.not_after,
            subject: subject.clone(),
            public_key_algorithm: PublicKeyAlgorithm::EcPubKey,
            elliptic_curve_id: EllipticCurveId::Prime256V1,
            public_key: *public_key,
            extensions,
            // Filled in below; the signature covers everything above it.
            signature: crate::crypto::Signature::from_bytes([0u8; 64]),
        };
        let mut der_buf = [0u8; CERT_DER_MAX];
        let tbs = der::tbs_certificate(&cert, &mut der_buf)?;
        cert.signature = keys.sign(self.key, tbs)?;
        cert.encode(buf)
    }
}

/// §6.5.11.4's key identifier: 20 octets derived from the public key.
fn key_id(public_key: &PublicKey) -> Result<[u8; KEY_ID_LEN]> {
    let digest = crate::crypto::hash(public_key.as_bytes());
    // Unreachable: SHA-256 is 32 octets and `KEY_ID_LEN` is 20. `InvalidState` rather than a
    // panic because the crate denies `panic` and a truncation that cannot happen should not
    // be the one place that could.
    let prefix = digest
        .get(..KEY_ID_LEN)
        .ok_or_else(|| Error::new(ErrorCode::InvalidState))?;
    <[u8; KEY_ID_LEN]>::try_from(prefix).map_err(|_| Error::new(ErrorCode::InvalidState))
}
