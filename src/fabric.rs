//! Fabrics: the ecosystems a node belongs to, and the identifiers derived from them
//! (Core §2.5.1, §4.3.2.2, §4.17.2, §11.18).
//!
//! A **fabric** is a set of nodes that trust one certificate authority. A node belongs to
//! several at once — five at minimum, by [`Config::FABRICS`] — and
//! almost nothing it does means anything outside the context of one: an access-control
//! entry, a group key, a subscription and a session are each scoped to a fabric.
//!
//! # Four derived values, and why each exists
//!
//! A full fabric reference is a 65-octet root public key plus a 64-bit Fabric ID, which is
//! more than fits in a DNS-SD instance name. So Matter derives shorter things from it:
//!
//! | Value | Derived from | What it is for |
//! |---|---|---|
//! | [`CompressedFabricId`] | root key + fabric id | 8 octets; names the fabric in `_matter._tcp` |
//! | [`operational_group_key`] | epoch key + compressed id | the key a group message is encrypted under |
//! | [`destination_identifier`] | IPK + randoms + identity | tells a CASE responder *which* fabric, without naming it |
//! | [`FabricIndex`] | nothing — a local counter | one octet; the same fabric has different indices on different nodes |
//!
//! The destination identifier is the subtle one. A CASE initiator has to say which fabric
//! it means without revealing it to a passive observer, because "this device is on the
//! Acme fabric" is exactly what a fabric would rather not broadcast. So it sends an HMAC
//! under a key only fabric members hold, and the responder tries each of its own fabrics
//! until one matches — or none does, and it answers `NO_SHARED_TRUST_ROOTS`.
//!
//! # Endianness, twice, differently
//!
//! The compressed fabric identifier salts with the Fabric ID **big-endian** and strips the
//! public key's `0x04` prefix. The destination identifier uses the Fabric ID and Node ID
//! **little-endian** and keeps the `0x04`. Both are quoted from the specification below.
//! Getting either backwards produces a value that simply never matches, with no other
//! symptom — which is why each has a test against the specification's own worked example.

use core::marker::PhantomData;

use heapless::{String, Vec};

use crate::config::{AssertValid, Config};
use crate::crypto::{
    HASH_LEN_BYTES, KeyHandle, PUBLIC_KEY_SIZE_BYTES, PublicKey, SymmetricKey, ct_eq, hmac, kdf,
    kdf_key,
};
use crate::error::{Error, ErrorCode, Result, bail};
use crate::msg::{FabricId, FabricIndex, NodeId, VendorId};

/// `CompressedFabricInfo` — the ASCII of `"CompressedFabric"` (§4.3.2.2).
pub const COMPRESSED_FABRIC_INFO: &[u8] = b"CompressedFabric";

/// The `Info` of the operational group key derivation (§4.17.2.1).
pub const GROUP_KEY_INFO: &[u8] = b"GroupKey v1.0";

/// The length of the `initiatorRandom` a destination identifier is computed over
/// (§4.14.2.4.1).
pub const INITIATOR_RANDOM_LEN: usize = 32;

/// The longest `Label` a fabric entry carries — §11.18.4.5's `max 32`.
pub const FABRIC_LABEL_MAX: usize = 32;

/// The longest operational certificate the specification admits — §11.18.4.4's `max 400`,
/// for `NOC`, `ICAC` and `VVSC` alike, and §11.18.6.13's `RootCACertificate`.
///
/// Fixed rather than a [`Config`] knob: a commissioner may legitimately send anything up to
/// this, so a device that reserved less would refuse certificates it is required to accept.
/// What it costs is real — three of these per fabric — and that is why [`Credentials`] holds
/// the ICAC and the VVSC as `Option`s and why a node that never needs them still pays for
/// the slot. Storing them in a [`KvStore`](crate::platform::KvStore) instead is the exchange
/// a very small device would make; the table would then be a cache rather than the truth.
pub const OPERATIONAL_CERT_MAX: usize = 400;

/// The length of a `VIDVerificationStatement` — §11.18.4.5's `85`, which §6.4.10.2 fixes as
/// `statement_version || vid_verification_signer_skid || signature` for the 1.0 cryptographic
/// primitives.
pub const VID_VERIFICATION_STATEMENT_LEN: usize = 85;

/// `statement_version` for the 1.0 cryptographic primitives (§6.4.10.1 step 12.a.i.A: "the
/// known value 0x21").
pub const VID_VERIFICATION_STATEMENT_VERSION: u8 = 0x21;

/// `fabric_binding_version` for the 1.0 cryptographic primitives (§11.18.6.16: "SHALL contain
/// value 0x01 for version 1.0").
pub const FABRIC_BINDING_VERSION: u8 = 0x01;

/// One fabric's operational credential chain, as the `NOCs` and `TrustedRootCertificates`
/// attributes serve it (§11.18.5.1, §11.18.5.5).
///
/// All three are Matter TLV certificates, not X.509 — §11.18.6.8 says "encoded using Matter
/// Certificate Encoding" — and they are kept verbatim. A re-encoding would be a different
/// octet string, and §6.5.2's signature rule means a round-tripped certificate is one whose
/// signature a peer may no longer be able to check.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    /// `NOC` — the node operational certificate for this fabric.
    pub noc: Vec<u8, OPERATIONAL_CERT_MAX>,
    /// `ICAC` — the intermediate, if the chain has one. §11.18.4.4: "If no ICAC is present in
    /// the chain, this field SHALL be set to null."
    pub icac: Option<Vec<u8, OPERATIONAL_CERT_MAX>>,
    /// The trusted root, from `AddTrustedRootCertificate`. Served through
    /// `TrustedRootCertificates` rather than through `NOCs`: §11.18.4.4 keeps it out of
    /// `NOCStruct` deliberately, because several fabrics may share one root.
    pub rcac: Vec<u8, OPERATIONAL_CERT_MAX>,
    /// `VVSC` — the Vendor Verification Signer Certificate (§11.18.4.4 field 3).
    ///
    /// "The VVSC field is mutually exclusive with the ICAC field": it exists for
    /// root-per-fabric deployments that have no intermediate to carry the signer, and
    /// [`Credentials::is_valid`] enforces the exclusion.
    pub vvsc: Option<Vec<u8, OPERATIONAL_CERT_MAX>>,
}

impl Credentials {
    /// A chain with a NOC and a root, and no intermediate.
    pub fn new(noc: &[u8], rcac: &[u8]) -> Result<Self> {
        Ok(Self {
            noc: copy_cert(noc)?,
            icac: None,
            rcac: copy_cert(rcac)?,
            vvsc: None,
        })
    }

    /// The same chain with an intermediate.
    pub fn with_icac(mut self, icac: &[u8]) -> Result<Self> {
        self.icac = Some(copy_cert(icac)?);
        Ok(self)
    }

    /// Sets or erases the `VVSC` — `SetVIDVerificationStatement` (§11.18.6.14).
    ///
    /// "If the length of the field's value is exactly 0, then the VVSC field … SHALL be
    /// erased and the field SHALL disappear from the NOCs entry."
    pub fn set_vvsc(&mut self, vvsc: &[u8]) -> Result<()> {
        if vvsc.is_empty() {
            self.vvsc = None;
            return Ok(());
        }
        if self.icac.is_some() {
            // §11.18.6.14: "If the VVSC field is present, but the ICAC field is already
            // present … the command SHALL fail with a status code of INVALID_COMMAND."
            bail!(InvalidArgument)
        }
        self.vvsc = Some(copy_cert(vvsc)?);
        Ok(())
    }

    /// Whether §11.18.4.4's mutual exclusion holds.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.noc.is_empty()
            && !self.rcac.is_empty()
            && !(self.icac.is_some() && self.vvsc.is_some())
    }
}

fn copy_cert(bytes: &[u8]) -> Result<Vec<u8, OPERATIONAL_CERT_MAX>> {
    Vec::from_slice(bytes).map_err(|_| Error::new(ErrorCode::NoSpace))
}

/// A compressed fabric reference: 64 bits standing in for a root key and a Fabric ID
/// (§4.3.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressedFabricId(pub u64);

impl CompressedFabricId {
    /// The big-endian octets, which is the order the KDF produces and DNS-SD prints.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// The sixteen uppercase hex characters a `_matter._tcp` instance name starts with
    /// (§4.3.2.1).
    #[must_use]
    pub fn to_hex(self) -> String<16> {
        let mut out = String::new();
        push_hex(&mut out, &self.to_bytes());
        out
    }

    /// The `_I<hhhh>` DNS-SD subtype that lets a browse be filtered to one fabric
    /// (§4.3.2.3).
    #[must_use]
    pub fn subtype(self) -> String<18> {
        let mut out = String::new();
        let _ = out.push_str("_I");
        let _ = out.push_str(&self.to_hex());
        out
    }
}

/// Appends the uppercase hex of `bytes`. Silently truncates if the string is too small,
/// which cannot happen for the two callers here — both are exactly sized.
fn push_hex<const N: usize>(out: &mut String<N>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0F] {
            let digit = DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'?');
            let _ = out.push(char::from(digit));
        }
    }
}

/// Computes the Compressed Fabric Identifier (§4.3.2.2).
///
/// Two details are easy to get wrong, and produce a node nobody can find:
///
/// * the root public key goes in **without its format marker** — "after removing the first
///   byte of the ec-pub-key field in the Operational Certificate's root";
/// * the Fabric ID is the salt, "a 64-bit unsigned integer scalar in **big-endian** byte
///   order", unlike most scalars in the protocol.
pub fn compressed_fabric_id(
    root_public_key: &PublicKey,
    fabric_id: FabricId,
) -> Result<CompressedFabricId> {
    let Some(raw) = root_public_key.as_bytes().get(1..) else {
        bail!(InvalidArgument)
    };
    let mut out = [0u8; 8];
    kdf(
        raw,
        &fabric_id.0.to_be_bytes(),
        COMPRESSED_FABRIC_INFO,
        &mut out,
    )?;
    Ok(CompressedFabricId(u64::from_be_bytes(out)))
}

/// Derives an operational group key from an epoch key (§4.17.2).
///
/// "Group membership is enforced by limiting access to the epoch keys. Only Nodes that
/// possess the input epoch key can derive a given operational key."
///
/// The Identity Protection Key is the group key of key set 0, so this is also how the IPK
/// that CASE and the destination identifier need comes about.
pub fn operational_group_key(
    epoch_key: &SymmetricKey,
    compressed: CompressedFabricId,
) -> Result<SymmetricKey> {
    kdf_key(epoch_key.as_bytes(), &compressed.to_bytes(), GROUP_KEY_INFO)
}

/// Computes a CASE destination identifier (§4.14.2.4.1).
///
/// `destinationMessage = initiatorRandom || rootPublicKey || fabricId || nodeId`, HMACed
/// under the IPK. Here the root public key keeps its `0x04` marker — "as an uncompressed
/// elliptic curve point as defined in section 2.3.3 of SEC 1" — and both 64-bit scalars are
/// little-endian. Both differ from [`compressed_fabric_id`]; see the module documentation.
pub fn destination_identifier(
    ipk: &SymmetricKey,
    initiator_random: &[u8; INITIATOR_RANDOM_LEN],
    root_public_key: &PublicKey,
    fabric_id: FabricId,
    node_id: NodeId,
) -> Result<[u8; HASH_LEN_BYTES]> {
    const LEN: usize = INITIATOR_RANDOM_LEN + PUBLIC_KEY_SIZE_BYTES + 8 + 8;
    let mut message = [0u8; LEN];
    {
        let mut at = 0usize;
        let mut put = |src: &[u8]| -> Result<()> {
            let end = at
                .checked_add(src.len())
                .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
            let Some(slot) = message.get_mut(at..end) else {
                bail!(BufferTooSmall)
            };
            slot.copy_from_slice(src);
            at = end;
            Ok(())
        };
        put(initiator_random)?;
        put(root_public_key.as_bytes())?;
        put(&fabric_id.0.to_le_bytes())?;
        put(&node_id.0.to_le_bytes())?;
    }
    hmac(ipk.as_bytes(), &message)
}

/// The longest `vendor_id_verification_tbs` this crate builds (§6.4.10.1 step 9).
///
/// `1 + 32 + 16 + 1` for the version, challenges and fabric index, `1 + 65 + 8 + 2` for the
/// `vendor_fabric_binding_message`, and 85 for an optional statement.
pub const VENDOR_ID_VERIFICATION_TBS_MAX: usize = 1
    + 32
    + crate::crypto::SYMMETRIC_KEY_LENGTH_BYTES
    + 1
    + (1 + PUBLIC_KEY_SIZE_BYTES + 8 + 2)
    + VID_VERIFICATION_STATEMENT_LEN;

/// `vendor_fabric_binding_message` (§6.4.10.1 step 8).
///
/// > For a fabric_binding_version version of 0x01, generate vendor_fabric_binding_message :=
/// > fabric_binding_version (0x01) || root_public_key || fabric_id || vendor_id
///
/// Both identifiers are big-endian "without omitting leading zeroes" — the opposite of the
/// destination identifier's little-endian encoding a few lines above, and the third
/// endianness convention in this one module. Each is the specification's.
pub fn vendor_fabric_binding_message(
    root_public_key: &PublicKey,
    fabric_id: FabricId,
    vendor_id: VendorId,
) -> [u8; 1 + PUBLIC_KEY_SIZE_BYTES + 8 + 2] {
    let mut out = [0u8; 1 + PUBLIC_KEY_SIZE_BYTES + 8 + 2];
    let mut at = 0usize;
    let mut put = |bytes: &[u8]| {
        if let Some(slot) = out.get_mut(at..at.saturating_add(bytes.len())) {
            slot.copy_from_slice(bytes);
        }
        at = at.saturating_add(bytes.len());
    };
    put(&[FABRIC_BINDING_VERSION]);
    put(root_public_key.as_bytes());
    put(&fabric_id.0.to_be_bytes());
    put(&vendor_id.0.to_be_bytes());
    out
}

/// What the verification signature binds a fabric to (§6.4.10.1 step 8).
///
/// A view of four fields of one `Fabrics` entry, so a *verifier* — which has only the
/// attribute values it read, not a [`Fabric`] — can build the same message the signer did.
#[derive(Debug, Clone, Copy)]
pub struct VendorIdBinding<'a> {
    /// The `RootPublicKey` field.
    pub root_public_key: &'a PublicKey,
    /// The `FabricID` field.
    pub fabric_id: FabricId,
    /// The `VendorID` field — the value under verification.
    pub vendor_id: VendorId,
    /// The `VIDVerificationStatement` field, "if it was present".
    pub statement: Option<&'a [u8; VID_VERIFICATION_STATEMENT_LEN]>,
}

/// `vendor_id_verification_tbs` (§6.4.10.1 step 9, §11.18.6.16).
///
/// > vendor_id_verification_tbs := fabric_binding_version || client_challenge ||
/// > attestation_challenge || fabric_index || vendor_fabric_binding_message ||
/// > &lt;vid_verification_statement&gt;
///
/// The `attestation_challenge` is what makes the signature mean something: it is the third
/// key a session derives and "SHALL NOT be included in any of the payloads conveyed", so a
/// response proves the signer is on *this* session rather than replaying one recorded from
/// another. `vid_verification_statement` is appended only "if present" — an absent one is
/// omitted, not zero-filled, which is a different message and therefore a different
/// signature.
///
/// Writes into `out` and returns the filled prefix, so nothing is allocated and the caller
/// controls where the challenge material lives.
pub fn vendor_id_verification_tbs<'b>(
    out: &'b mut [u8; VENDOR_ID_VERIFICATION_TBS_MAX],
    challenges: (&[u8; 32], &SymmetricKey),
    fabric_index: FabricIndex,
    binding: &VendorIdBinding<'_>,
) -> &'b [u8] {
    let (client_challenge, attestation_challenge) = challenges;
    let bound = vendor_fabric_binding_message(
        binding.root_public_key,
        binding.fabric_id,
        binding.vendor_id,
    );
    let mut at = 0usize;
    {
        let mut put = |bytes: &[u8]| {
            if let Some(slot) = out.get_mut(at..at.saturating_add(bytes.len())) {
                slot.copy_from_slice(bytes);
            }
            at = at.saturating_add(bytes.len());
        };
        put(&[FABRIC_BINDING_VERSION]);
        put(client_challenge);
        put(attestation_challenge.as_bytes());
        put(&[fabric_index.0]);
        put(&bound);
        if let Some(statement) = binding.statement {
            put(statement);
        }
    }
    out.get(..at).unwrap_or(&[])
}

/// Who a node is on one fabric — the part of a `Fabrics` entry that comes from the NOC and
/// from `AddNOC`, as opposed to the parts derived from it.
///
/// A struct rather than four parameters because the four travel together everywhere: they
/// come out of one certificate chain and one `AddNOC` invocation, and splitting them at a
/// call site is how a Fabric ID ends up where a Node ID belongs.
#[derive(Debug, Clone)]
pub struct FabricIdentity {
    /// The 64-bit identifier, from the NOC's `matter-fabric-id`.
    pub fabric_id: FabricId,
    /// This node's operational identity on the fabric, from the NOC's `matter-node-id`.
    pub node_id: NodeId,
    /// The root certificate authority's public key, uncompressed and 65 octets.
    pub root_public_key: PublicKey,
    /// The `AdminVendorID` of the administrator that commissioned this fabric.
    pub admin_vendor_id: VendorId,
}

/// One fabric a node belongs to — the state behind §11.18's `Fabrics` attribute, plus the
/// two derived values that attribute does not carry.
#[derive(Debug, Clone)]
pub struct Fabric {
    /// This node's index for the fabric. Purely local: "the Local Fabric Index and Peer
    /// Fabric Index … MAY differ in value, while still referring to the same Fabric."
    pub index: FabricIndex,
    /// The 64-bit identifier, from the NOC's `matter-fabric-id`.
    pub fabric_id: FabricId,
    /// This node's operational identity on the fabric, from the NOC's `matter-node-id`.
    pub node_id: NodeId,
    /// The root certificate authority's public key, uncompressed and 65 octets.
    pub root_public_key: PublicKey,
    /// The eight-octet name the fabric goes by in DNS-SD. Derived, not stored on the wire.
    pub compressed: CompressedFabricId,
    /// The Identity Protection Key — the operational group key of key set 0. Derived from
    /// the `IPKValue` of `AddNOC`, which is *not* itself retained.
    pub ipk: SymmetricKey,
    /// The `AdminVendorID` of the administrator that commissioned this fabric. §11.18.4.5
    /// warns clients to "consider the VendorID field value to be untrustworthy" until the
    /// verification procedure has run against it.
    pub admin_vendor_id: VendorId,
    /// The user-visible label, `""` until `UpdateFabricLabel` sets one.
    pub label: String<FABRIC_LABEL_MAX>,
    /// A handle to this node's operational private key, held by the
    /// [`KeyStore`](crate::crypto::KeyStore) — never the key itself.
    pub operational_key: KeyHandle,
    /// The certificate chain, as `NOCs` and `TrustedRootCertificates` serve it.
    pub credentials: Credentials,
    /// `VIDVerificationStatement` (§11.18.4.5 field 6), set by
    /// `SetVIDVerificationStatement`. Absent until an administrator installs one, and then
    /// exactly [`VID_VERIFICATION_STATEMENT_LEN`] octets.
    pub vid_verification_statement: Option<[u8; VID_VERIFICATION_STATEMENT_LEN]>,
}

impl Fabric {
    /// Builds a fabric entry, deriving the compressed identifier and the IPK.
    ///
    /// `ipk_epoch_key` is the value that arrives in `AddNOC`'s `IPKValue` field. What is
    /// kept is the *operational* key derived from it, because that is what every later
    /// computation uses and the epoch key has no further purpose here.
    pub fn new(
        index: FabricIndex,
        identity: FabricIdentity,
        ipk_epoch_key: &SymmetricKey,
        operational_key: KeyHandle,
        credentials: Credentials,
    ) -> Result<Self> {
        let FabricIdentity {
            fabric_id,
            node_id,
            root_public_key,
            admin_vendor_id,
        } = identity;
        if !index.is_some() {
            // 0 means "no fabric" and 0xFF is reserved (§7.5).
            bail!(InvalidArgument)
        }
        if fabric_id.0 == 0 {
            // §6.5.6.3: "The matter-fabric-id … SHALL NOT be 0".
            bail!(InvalidArgument)
        }
        if !node_id.is_operational() {
            // §6.5.6.3: a NOC's node id is in the Operational Node ID range.
            bail!(InvalidArgument)
        }
        if !credentials.is_valid() {
            // §11.18.4.4's mutual exclusion, and a chain with no NOC or no root is not a
            // chain: `NOCs` and `Fabrics` must have matching entries (§11.18.5.1).
            bail!(InvalidArgument)
        }
        let compressed = compressed_fabric_id(&root_public_key, fabric_id)?;
        let ipk = operational_group_key(ipk_epoch_key, compressed)?;
        Ok(Self {
            index,
            fabric_id,
            node_id,
            root_public_key,
            compressed,
            ipk,
            admin_vendor_id,
            label: String::new(),
            operational_key,
            credentials,
            vid_verification_statement: None,
        })
    }

    /// Sets the user-visible label — `UpdateFabricLabel` (§11.18.6.9).
    ///
    /// Returns [`ErrorCode::InvalidArgument`] for a label longer than
    /// [`FABRIC_LABEL_MAX`], which is the `CONSTRAINT_ERROR` that command answers with.
    pub fn set_label(&mut self, label: &str) -> Result<()> {
        let mut next = String::new();
        next.push_str(label)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument))?;
        self.label = next;
        Ok(())
    }

    /// The DNS-SD operational instance name: `<CompressedFabricId>-<NodeId>`, each sixteen
    /// uppercase hex characters (§4.3.2.1).
    #[must_use]
    pub fn instance_name(&self) -> String<33> {
        let mut out = String::new();
        let _ = out.push_str(&self.compressed.to_hex());
        let _ = out.push('-');
        push_hex(&mut out, &self.node_id.0.to_be_bytes());
        out
    }

    /// The four fields `vendor_fabric_binding_message` binds (§6.4.10.1 step 8).
    #[must_use]
    pub fn vendor_id_binding(&self) -> VendorIdBinding<'_> {
        VendorIdBinding {
            root_public_key: &self.root_public_key,
            fabric_id: self.fabric_id,
            vendor_id: self.admin_vendor_id,
            statement: self.vid_verification_statement.as_ref(),
        }
    }

    /// The message `SignVIDVerificationRequest` signs with this fabric's operational key
    /// (§11.18.6.16).
    ///
    /// The signature is made with the *operational* key, not the attestation key: the
    /// procedure proves that whoever holds this fabric's NOC agrees to the `VendorID` it
    /// claims, which is a statement about the fabric rather than about the hardware.
    pub fn vendor_id_verification_tbs<'b>(
        &self,
        out: &'b mut [u8; VENDOR_ID_VERIFICATION_TBS_MAX],
        client_challenge: &[u8; 32],
        attestation_challenge: &SymmetricKey,
    ) -> &'b [u8] {
        vendor_id_verification_tbs(
            out,
            (client_challenge, attestation_challenge),
            self.index,
            &self.vendor_id_binding(),
        )
    }

    /// The destination identifier a peer computes to reach *this* node on *this* fabric —
    /// §4.14.2.3.5's `candidateDestinationId`.
    pub fn destination_identifier(
        &self,
        initiator_random: &[u8; INITIATOR_RANDOM_LEN],
    ) -> Result<[u8; HASH_LEN_BYTES]> {
        destination_identifier(
            &self.ipk,
            initiator_random,
            &self.root_public_key,
            self.fabric_id,
            self.node_id,
        )
    }
}

/// The fixed-capacity set of fabrics a node belongs to (§11.18).
#[derive(Debug)]
pub struct FabricTable<C: Config, const N: usize> {
    fabrics: Vec<Fabric, N>,
    /// The last index handed out, so the next one is monotonically greater (§11.18.6.8).
    last_index: u8,
    _config: PhantomData<C>,
}

impl<C: Config, const N: usize> Default for FabricTable<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Config, const N: usize> FabricTable<C, N> {
    /// An empty table — what a factory-fresh node has.
    #[must_use]
    pub fn new() -> Self {
        let () = AssertValid::<C>::CHECK;
        Self {
            fabrics: Vec::new(),
            last_index: 0,
            _config: PhantomData,
        }
    }

    /// How many fabrics this node belongs to — the `CommissionedFabrics` attribute.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fabrics.len()
    }

    /// Whether the node is uncommissioned.
    ///
    /// This is what decides whether a device advertises itself as commissionable: an
    /// uncommissioned node always does, a commissioned one only while a window is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fabrics.is_empty()
    }

    /// The `SupportedFabrics` attribute. §11.18.5.3 constrains it to `5 to 254`, which
    /// [`AssertValid`] checks at compile time against [`Config::FABRICS`].
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Allocates the next fabric index, `1..=254`.
    ///
    /// §11.18.6.8 step 1: "taking the next valid fabric-index value in **monotonically
    /// incrementing order**, wrapping around from 254 (0xFE) to 1, since value 0 is reserved
    /// and using 255 (0xFF) would prevent cluster specifications from using nullable
    /// fabric-idx fields."
    ///
    /// Monotonic, *not* lowest-free, and the difference matters. A fabric index is what every
    /// fabric-scoped thing on the node is keyed by — access-control entries, group keys,
    /// bindings, subscriptions — and administrators cache it. Handing index 1 straight back
    /// out after a `RemoveFabric` would silently point a stale reference at a different
    /// administrator's fabric.
    ///
    /// Returns [`ErrorCode::NoSpace`] when every index is taken — unreachable while
    /// `N <= 254`, but a table is not the place to assume that.
    pub fn allocate_index(&mut self) -> Result<FabricIndex> {
        let mut candidate = self.last_index;
        for _ in 0..254u16 {
            candidate = if candidate >= 254 {
                1
            } else {
                candidate.saturating_add(1)
            };
            let index = FabricIndex(candidate);
            if self.find(index).is_none() {
                self.last_index = candidate;
                return Ok(index);
            }
        }
        Err(Error::new(ErrorCode::NoSpace))
    }

    /// Adds a fabric.
    ///
    /// Refuses a duplicate — the same compressed identifier *and* the same node id —
    /// because §11.18's `AddNOC` answers `FabricConflict` there rather than creating a
    /// second entry that peers cannot tell apart from the first.
    pub fn insert(&mut self, fabric: Fabric) -> Result<FabricIndex> {
        if self.find(fabric.index).is_some() {
            bail!(InvalidState)
        }
        if self
            .fabrics
            .iter()
            .any(|f| f.compressed == fabric.compressed && f.node_id == fabric.node_id)
        {
            bail!(AlreadyExists)
        }
        let index = fabric.index;
        self.fabrics
            .push(fabric)
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        Ok(index)
    }

    /// The fabric with this index.
    #[must_use]
    pub fn find(&self, index: FabricIndex) -> Option<&Fabric> {
        self.fabrics.iter().find(|f| f.index == index)
    }

    /// The fabric with this index, mutably — for `UpdateNOC` and `UpdateFabricLabel`.
    pub fn find_mut(&mut self, index: FabricIndex) -> Option<&mut Fabric> {
        self.fabrics.iter_mut().find(|f| f.index == index)
    }

    /// The fabric a compressed identifier names, which is how a DNS-SD record is attributed.
    #[must_use]
    pub fn find_by_compressed(&self, compressed: CompressedFabricId) -> Option<&Fabric> {
        self.fabrics.iter().find(|f| f.compressed == compressed)
    }

    /// Finds the fabric a CASE `destinationId` refers to (§4.14.2.3.5).
    ///
    /// "The responder SHALL traverse all its installed Node Operational Certificates …
    /// and SHALL generate a candidateDestinationId … The responder SHALL verify that the
    /// incoming destinationId matches one of the candidateDestinationId generated above."
    ///
    /// Every fabric is tried and the comparison is constant-time, so neither the number of
    /// iterations nor their duration tells an unauthenticated peer how close its guess was.
    pub fn find_by_destination_identifier(
        &self,
        initiator_random: &[u8; INITIATOR_RANDOM_LEN],
        destination_id: &[u8; HASH_LEN_BYTES],
    ) -> Result<Option<&Fabric>> {
        let mut found = None;
        for fabric in &self.fabrics {
            let candidate = fabric.destination_identifier(initiator_random)?;
            if ct_eq(&candidate, destination_id) {
                found = Some(fabric);
            }
        }
        Ok(found)
    }

    /// Removes a fabric — `RemoveFabric` (§11.18.6.12).
    ///
    /// The caller must also tear down everything scoped to it: sessions, subscriptions,
    /// access-control entries, group keys and bindings. The removed fabric is returned so
    /// that its key handle can be destroyed in the key store — the step most easily
    /// forgotten, and the one that matters most.
    pub fn remove(&mut self, index: FabricIndex) -> Option<Fabric> {
        let position = self.fabrics.iter().position(|f| f.index == index)?;
        Some(self.fabrics.swap_remove(position))
    }

    /// Every fabric, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &Fabric> {
        self.fabrics.iter()
    }
}

/// The `IPKValue` an `AddNOC` command carries: a 16-octet group epoch key, from which the
/// fabric's real IPK is derived.
pub type IpkEpochKey = SymmetricKey;

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::DefaultConfig;

    /// The root public key of the specification's worked examples, uncompressed with its
    /// `04` marker (§4.3.2.2, §4.14.2.4.1).
    const ROOT_PUBLIC_KEY: [u8; 65] = hex!(
        "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641c"
        "b8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfac"
        "fa"
    );

    /// The Fabric ID of those examples.
    const FABRIC: FabricId = FabricId(0x2906_C908_D115_D362);

    /// The IPK epoch key of the §4.14.2.4.1 example.
    const IPK_EPOCH: [u8; 16] = hex!("4a71cdd7b2a3ca9024f96f3c96a19dee");

    fn root_key() -> PublicKey {
        PublicKey::from_bytes(ROOT_PUBLIC_KEY)
    }

    #[test]
    fn the_compressed_fabric_id_matches_the_specs_worked_example() {
        // §4.3.2.2: "the CompressedFabricIdentifier to use in advertising would be
        // 87E1B004E235A130".
        let compressed = compressed_fabric_id(&root_key(), FABRIC).expect("derive");
        assert_eq!(compressed.to_bytes(), hex!("87e1b004e235a130"));
        assert_eq!(compressed.to_hex().as_str(), "87E1B004E235A130");
        // §4.3.2.3's browse subtype.
        assert_eq!(compressed.subtype().as_str(), "_I87E1B004E235A130");
    }

    #[test]
    fn the_operational_group_key_matches_the_specs_worked_example() {
        // §4.17.2: epoch key 235bf7e6…, compressed 87e1b004e235a130.
        let epoch = SymmetricKey::new(hex!("235bf7e62823d358dca4ba50b1535f4b"));
        let key =
            operational_group_key(&epoch, CompressedFabricId(0x87E1_B004_E235_A130)).expect("kdf");
        assert_eq!(key.as_bytes(), &hex!("a6f5306baf6d050af23ba4bd6b9dd960"));
    }

    #[test]
    fn the_ipk_matches_the_specs_worked_example() {
        // §4.14.2.4.1: the same derivation, applied to the IPK epoch key.
        let compressed = compressed_fabric_id(&root_key(), FABRIC).expect("derive");
        let ipk = operational_group_key(&SymmetricKey::new(IPK_EPOCH), compressed).expect("kdf");
        assert_eq!(ipk.as_bytes(), &hex!("9bc61cd9c62a2df6d64dfcaa9dc472d4"));
    }

    #[test]
    fn the_destination_identifier_matches_the_specs_worked_example() {
        // §4.14.2.4.1, the whole chain: epoch key → IPK → HMAC over the destination
        // message. This is the test that pins both endiannesses and the 04 marker.
        let compressed = compressed_fabric_id(&root_key(), FABRIC).expect("derive");
        let ipk = operational_group_key(&SymmetricKey::new(IPK_EPOCH), compressed).expect("kdf");

        let initiator_random =
            hex!("7e171231568dfa17206b3accf8faec2f4d21b580113196f47c7c4deb810a73dc");
        let id = destination_identifier(
            &ipk,
            &initiator_random,
            &root_key(),
            FABRIC,
            NodeId(0xCD55_44AA_7B13_EF14),
        )
        .expect("hmac");

        assert_eq!(
            id,
            hex!("dc35dd5fc9134cc5544538c9c3fc4297c1ec3370c839136a80e10796451d4c53")
        );
    }

    /// A minimal chain: the contents are opaque here, only their presence matters.
    fn example_credentials() -> Credentials {
        Credentials::new(b"noc", b"rcac").expect("fits")
    }

    fn example_fabric(index: u8, node: u64) -> Fabric {
        Fabric::new(
            FabricIndex(index),
            FabricIdentity {
                fabric_id: FABRIC,
                node_id: NodeId(node),
                root_public_key: root_key(),
                admin_vendor_id: VendorId(0xFFF1),
            },
            &SymmetricKey::new(IPK_EPOCH),
            KeyHandle(u32::from(index)),
            example_credentials(),
        )
        .expect("fabric")
    }

    #[test]
    fn a_fabric_derives_both_values_on_construction() {
        let fabric = example_fabric(1, 0xCD55_44AA_7B13_EF14);
        assert_eq!(fabric.compressed, CompressedFabricId(0x87E1_B004_E235_A130));
        assert_eq!(
            fabric.ipk.as_bytes(),
            &hex!("9bc61cd9c62a2df6d64dfcaa9dc472d4")
        );
        assert_eq!(fabric.label.as_str(), "", "§11.18.4.5's fallback");
    }

    #[test]
    fn the_instance_name_is_the_dns_sd_form() {
        // §4.3.2.1's own example: compressed 2906C908D115D362 and node 8FC7772401CD0696
        // give 2906C908D115D362-8FC7772401CD0696.
        let mut fabric = example_fabric(1, 0x8FC7_7724_01CD_0696);
        fabric.compressed = CompressedFabricId(0x2906_C908_D115_D362);
        assert_eq!(
            fabric.instance_name().as_str(),
            "2906C908D115D362-8FC7772401CD0696"
        );
    }

    #[test]
    fn a_fabric_refuses_the_identities_6_5_6_3_forbids() {
        let key = SymmetricKey::new([0; 16]);
        let cases = [
            ("fabric id 0", FabricIndex(1), FabricId(0), NodeId(1)),
            (
                "a group node id, not an operational one",
                FabricIndex(1),
                FabricId(1),
                NodeId(0xFFFF_FFFF_FFFF_0001),
            ),
            (
                "fabric index 0 means no fabric",
                FabricIndex(0),
                FabricId(1),
                NodeId(1),
            ),
        ];
        for (why, index, fabric_id, node_id) in cases {
            let built = Fabric::new(
                index,
                FabricIdentity {
                    fabric_id,
                    node_id,
                    root_public_key: root_key(),
                    admin_vendor_id: VendorId(1),
                },
                &key,
                KeyHandle(1),
                example_credentials(),
            );
            assert_eq!(
                built.map(|_| ()).unwrap_err().code(),
                ErrorCode::InvalidArgument,
                "{why}"
            );
        }
    }

    #[test]
    fn a_label_longer_than_32_is_a_constraint_error() {
        let mut fabric = example_fabric(1, 1);
        fabric.set_label("Living room").expect("fits");
        assert_eq!(fabric.label.as_str(), "Living room");
        assert_eq!(
            fabric.set_label(&"x".repeat(33)).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(fabric.label.as_str(), "Living room", "and nothing changed");
        fabric.set_label(&"x".repeat(32)).expect("exactly 32 fits");
    }

    type Table = FabricTable<DefaultConfig, 5>;

    #[test]
    fn indices_are_allocated_from_one_and_never_zero() {
        let mut t = Table::new();
        assert!(t.is_empty());
        assert_eq!(t.allocate_index().expect("a"), FabricIndex(1));
        t.insert(example_fabric(1, 1)).expect("insert");
        assert_eq!(t.allocate_index().expect("b"), FabricIndex(2));
        t.insert(example_fabric(2, 2)).expect("insert");

        // §11.18.6.8 step 1 allocates "in monotonically incrementing order", so removing a
        // fabric does *not* hand its index straight back out. An administrator's cached
        // reference to fabric 1 must not silently come to mean somebody else's fabric.
        t.remove(FabricIndex(1)).expect("removed");
        assert_eq!(t.allocate_index().expect("c"), FabricIndex(3));
    }

    #[test]
    fn fabric_indices_wrap_from_254_to_1_and_skip_what_is_in_use() {
        // "wrapping around from 254 (0xFE) to 1, since value 0 is reserved and using 255
        // (0xFF) would prevent cluster specifications from using nullable fabric-idx fields."
        let mut t = Table::new();
        t.insert(example_fabric(1, 1)).expect("insert");
        for _ in 0..253 {
            let index = t.allocate_index().expect("space");
            assert_ne!(index, FabricIndex(0));
            assert_ne!(index, FabricIndex(0xFF));
        }
        // Having walked all the way round, the next free index is the one *after* the
        // occupied 1 — the counter wrapped and stepped over it.
        assert_eq!(t.allocate_index().expect("wrapped"), FabricIndex(2));
    }

    #[test]
    fn a_duplicate_fabric_is_refused() {
        // Same root key, same fabric id, same node id: §11.18's FabricConflict.
        let mut t = Table::new();
        t.insert(example_fabric(1, 7)).expect("first");
        assert_eq!(
            t.insert(example_fabric(2, 7)).unwrap_err().code(),
            ErrorCode::AlreadyExists
        );
        // A different node id on the same fabric is a different identity, and is fine.
        t.insert(example_fabric(2, 8)).expect("different node");
        assert_eq!(t.len(), 2);
        // A reused index is a caller bug, and a different error.
        assert_eq!(
            t.insert(example_fabric(2, 9)).unwrap_err().code(),
            ErrorCode::InvalidState
        );
    }

    #[test]
    fn a_full_table_is_a_value_not_an_abort() {
        let mut t = Table::new();
        for i in 1..=5u8 {
            t.insert(example_fabric(i, u64::from(i))).expect("fits");
        }
        assert_eq!(
            t.insert(example_fabric(6, 6)).unwrap_err().code(),
            ErrorCode::NoSpace
        );
        assert_eq!(t.capacity(), 5);
    }

    #[test]
    fn a_destination_identifier_finds_its_fabric_and_only_its_fabric() {
        let mut t = Table::new();
        for i in 1..=3u8 {
            t.insert(example_fabric(i, u64::from(i))).expect("insert");
        }
        let random = [0x42u8; INITIATOR_RANDOM_LEN];

        for i in 1..=3u8 {
            let id = t
                .find(FabricIndex(i))
                .expect("fabric")
                .destination_identifier(&random)
                .expect("id");
            let found = t
                .find_by_destination_identifier(&random, &id)
                .expect("search")
                .expect("a match");
            assert_eq!(found.index, FabricIndex(i));
        }

        // An identifier for a fabric this node is not on matches nothing — which is what
        // makes the responder answer NO_SHARED_TRUST_ROOTS.
        assert!(
            t.find_by_destination_identifier(&random, &[0u8; HASH_LEN_BYTES])
                .expect("search")
                .is_none()
        );
    }

    #[test]
    fn a_different_initiator_random_gives_a_different_identifier() {
        // The random is what stops a destination identifier being a stable, trackable name
        // for a fabric — §4.14.2.4.1's "It hides which Fabric was chosen by the initiator".
        let fabric = example_fabric(1, 1);
        assert_ne!(
            fabric.destination_identifier(&[1; 32]).expect("a"),
            fabric.destination_identifier(&[2; 32]).expect("b")
        );
    }

    #[test]
    fn removing_a_fabric_hands_back_its_key_handle() {
        // So the caller can destroy the operational key, which RemoveFabric must do.
        let mut t = Table::new();
        t.insert(example_fabric(1, 1)).expect("insert");
        let removed = t.remove(FabricIndex(1)).expect("removed");
        assert_eq!(removed.operational_key, KeyHandle(1));
        assert!(t.is_empty());
        assert!(t.remove(FabricIndex(1)).is_none());
    }

    #[test]
    fn different_roots_and_different_fabric_ids_compress_differently() {
        // The compressed id is what distinguishes fabrics in DNS-SD, so two ecosystems
        // colliding here would be indistinguishable on the network.
        let mut other = ROOT_PUBLIC_KEY;
        other[1] ^= 0xFF;
        let a = compressed_fabric_id(&root_key(), FabricId(1)).expect("a");
        let b = compressed_fabric_id(&PublicKey::from_bytes(other), FabricId(1)).expect("b");
        let c = compressed_fabric_id(&root_key(), FabricId(2)).expect("c");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn find_by_compressed_picks_the_right_fabric() {
        let mut t = Table::new();
        t.insert(example_fabric(1, 1)).expect("insert");
        let found = t
            .find_by_compressed(CompressedFabricId(0x87E1_B004_E235_A130))
            .expect("found");
        assert_eq!(found.index, FabricIndex(1));
        assert!(t.find_by_compressed(CompressedFabricId(0)).is_none());
    }
}
