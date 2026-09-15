//! Joint Fabric Administrator, cluster `0x0753` (Core §11.25).
//!
//! The device side of §12.2.5's Joint Commissioning Method — the handshake by which one
//! ecosystem's administrator gets a cross-signed ICAC from another's, so that both end up
//! anchored to the same root.
//!
//! # Three commands, in one order, inside one fail-safe
//!
//! §11.25.6 is a sequence, and the sequence is the security:
//!
//! 1. `ICACCSRRequest` — "give me a certificate signing request for your intermediate CA". The
//!    server answers with a PKCS #10 CSR over a key it holds.
//! 2. The anchor signs it, having first run §6.4.10's Vendor ID Verification and checked that
//!    the peer really is an administrator on its own fabric (§12.2.5 step 4).
//! 3. `AddICAC` — "here is that ICAC, cross-signed". The server verifies the chain, the public
//!    key against the CSR it issued, and the DN.
//!
//! Every step of it is inside an armed fail-safe, and §11.25.6.1 and §11.25.6.3 both refuse
//! outright without one: everything a Joint Fabric adds is undone if the commissioner walks
//! away, and a half-joined fabric is one where two ecosystems disagree about who may administer
//! what.
//!
//! # The public key check is the whole point of the CSR
//!
//! §11.25.6.3 step 2: "The public key of the ICAC SHALL match the public key present in the last
//! ICACCSRResponse provided to the Administrator that sent the AddICAC command." Without it an
//! anchor could hand back an ICAC over a key of *its* choosing, and the joining ecosystem would
//! install an intermediate CA it does not hold the private key for — or worse, one the anchor
//! does.
//!
//! # What is not here
//!
//! The anchor *transfer* commands (§11.25.6.6–§11.25.6.8) are accepted and reported: moving the
//! anchor role between ecosystems needs user consent and a datastore quiesce, neither of which
//! is this cluster's to decide. [`AnchorTransfer`] is what the application answers with.

use core::cell::{Cell, RefCell};

use crate::clusters::generated::joint_fabric_administrator as spec_jf;
use crate::commissioning::failsafe::FailSafe;
use crate::commissioning::window::CommissioningWindow;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    ClusterHandler, ClusterId, CommandId, EndpointId, InteractionContext, Status, StatusIb,
};
use crate::msg::FabricIndex;
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::Cluster;

pub use spec_jf::attribute::ADMINISTRATOR_FABRIC_INDEX;
pub use spec_jf::command::{
    ADD_ICAC, ANNOUNCE_JOINT_FABRIC_ADMINISTRATOR, ICAC_RESPONSE, ICACCSR_REQUEST,
    ICACCSR_RESPONSE, OPEN_JOINT_COMMISSIONING_WINDOW, TRANSFER_ANCHOR_COMPLETE,
    TRANSFER_ANCHOR_REQUEST, TRANSFER_ANCHOR_RESPONSE,
};
pub use spec_jf::{
    ICACCSRResponseStatusCodeEnum, ICACResponseStatusEnum, ID, PICS, REVISION,
    TransferAnchorResponseStatusEnum,
};

/// §11.25.6.2's constraint on `ICACCSR`: "max 600".
pub const ICACCSR_MAX: usize = 600;

/// §11.25.6.3's constraint on `ICACValue`: "max 400".
pub const ICAC_MAX: usize = 400;

/// What the product does with the two halves of ICAC cross-signing.
///
/// Both are cryptography this cluster deliberately does not do itself: the key pair behind the
/// CSR is the node's own intermediate CA key, which may live in a secure element, and validating
/// a cross-signed ICAC is [`cert`](crate::cert)'s chain walk against a root only the application
/// knows it has.
pub trait JointFabricHooks {
    /// §11.25.6.1: writes a PKCS #10 CSR for this node's intermediate CA key.
    ///
    /// Returns how many octets it wrote. §11.25.6.2 caps it at [`ICACCSR_MAX`].
    fn write_icac_csr(&self, out: &mut [u8]) -> core::result::Result<usize, Status>;

    /// §11.25.6.3's three checks, in the specification's own order.
    ///
    /// The order is what makes the two statuses meaningful: `InvalidPublicKey` says "this is not
    /// the key I asked you to sign", and `InvalidICAC` says "this does not chain, or the DN is
    /// wrong". Collapsing them would leave an administrator unable to tell a mis-signed
    /// certificate from a mis-addressed one.
    fn validate_icac(&self, icac: &[u8], fabric: FabricIndex) -> ICACResponseStatusEnum;

    /// Installs a validated ICAC. §12.2.5: it becomes the intermediate every NOC this ecosystem
    /// issues chains through.
    fn install_icac(&self, icac: &[u8], fabric: FabricIndex) -> core::result::Result<(), Status>;

    /// §11.25.6.6: whether this node will give up the anchor role right now.
    ///
    /// §11.25.4.2 gives two reasons it might not, and both are the application's: the datastore
    /// is busy, or "User has not consented for Anchor Transfer".
    fn anchor_transfer(&self) -> AnchorTransfer {
        AnchorTransfer::Refused(TransferAnchorResponseStatusEnum::TransferAnchorStatusNoUserConsent)
    }

    /// §11.25.6.8: the transfer finished, and this node is no longer the anchor.
    fn anchor_transferred(&self) {}

    /// §11.25.6.9: a peer said where to find *its* Joint Fabric Administrator cluster.
    fn administrator_announced(&self, endpoint: EndpointId) {
        let _ = endpoint;
    }
}

/// What §11.25.6.6 is answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorTransfer {
    /// The node will transfer the anchor role.
    Accepted,
    /// It will not, and this is why.
    Refused(TransferAnchorResponseStatusEnum),
}

/// The Joint Fabric Administrator cluster (§11.25).
#[derive(Debug)]
pub struct JointFabricAdministrator<'a, H: JointFabricHooks> {
    hooks: &'a H,
    /// The node's fail-safe: §11.25.6.1 and §11.25.6.3 both require one armed.
    fail_safe: &'a RefCell<FailSafe>,
    /// The node's commissioning window, which `OpenJointCommissioningWindow` opens.
    window: &'a RefCell<CommissioningWindow>,
    /// §11.25.5.1's `AdministratorFabricIndex`, null until a fabric is the Joint Fabric's.
    administrator_fabric: Cell<Option<FabricIndex>>,
    /// Whether a CSR has been issued in this fail-safe period, and to which fabric.
    ///
    /// §11.25.6.3 step 2 compares the ICAC's public key against "the last ICACCSRResponse
    /// provided to the Administrator that sent the AddICAC command" — so the pairing is per
    /// administrator, not per node.
    csr_issued_to: Cell<Option<FabricIndex>>,
    /// §11.25.6.1 and §11.25.6.3: "If a prior AddICAC command was successfully executed within
    /// the fail-safe timer period, then this command SHALL fail with a CONSTRAINT_ERROR."
    icac_added: Cell<bool>,
}

impl<'a, H: JointFabricHooks> JointFabricAdministrator<'a, H> {
    /// The cluster on a node that is not yet part of a Joint Fabric.
    #[must_use]
    pub const fn new(
        hooks: &'a H,
        fail_safe: &'a RefCell<FailSafe>,
        window: &'a RefCell<CommissioningWindow>,
    ) -> Self {
        Self {
            hooks,
            fail_safe,
            window,
            administrator_fabric: Cell::new(None),
            csr_issued_to: Cell::new(None),
            icac_added: Cell::new(false),
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<1, 6, 3, 0>> {
        Conforming::new(&spec_jf::CLUSTER, feature_map, optional)
    }

    /// `AdministratorFabricIndex` (§11.25.5.1), null when no fabric is the Joint Fabric's.
    #[must_use]
    pub fn administrator_fabric(&self) -> Option<FabricIndex> {
        self.administrator_fabric.get()
    }

    /// Names the fabric this node administers the Joint Fabric through.
    ///
    /// §11.25.5.1: "the FabricIndex from the Endpoint 0's Operational Cluster Fabrics attribute
    /// … which is associated with the JointFabric". Until it is set, §11.25.6.1 and §11.25.6.5
    /// both refuse: there is no fabric to cross-sign into.
    pub fn set_administrator_fabric(&self, fabric: Option<FabricIndex>) {
        self.administrator_fabric.set(fabric);
    }

    /// Clears the per-fail-safe state, which a device does when the fail-safe expires or
    /// `CommissioningComplete` runs.
    ///
    /// §11.25.6.1's `CONSTRAINT_ERROR` and §11.25.6.3's are both scoped to "within the fail-safe
    /// timer period", so an abandoned attempt must not block the next one for ever.
    pub fn reset_fail_safe_state(&self) {
        self.csr_issued_to.set(None);
        self.icac_added.set(false);
    }

    /// Whether a fail-safe is armed, which §11.25.6.1 and §11.25.6.3 both require.
    fn fail_safe_armed(&self, ctx: &InteractionContext<'_>) -> bool {
        self.fail_safe.borrow().is_armed(ctx.now)
    }
}

impl<H: JointFabricHooks> ClusterHandler for JointFabricAdministrator<'_, H> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            ADMINISTRATOR_FABRIC_INDEX => match self.administrator_fabric.get() {
                Some(fabric) => full(w.unsigned(tag, u64::from(fabric.0))),
                // §11.25.5.1: "This field SHALL have the value of null if there is no fabric
                // associated with the JointFabric."
                None => full(w.null(tag)),
            },
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<Option<CommandId>, StatusIb> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        match resolved.command.id {
            ICACCSR_REQUEST => {
                let status = self.icac_csr_request(ctx);
                let mut buf = [0u8; ICACCSR_MAX];
                let csr = match status {
                    ICACCSRResponseStatusCodeEnum::OK => {
                        let written = self.hooks.write_icac_csr(&mut buf)?;
                        let csr = buf
                            .get(..written)
                            .filter(|csr| csr.len() <= ICACCSR_MAX)
                            .ok_or(StatusIb::from(Status::Failure))?;
                        // Only now is the CSR "provided", so only now may §11.25.6.3's pairing
                        // be recorded: a refused request must not license an `AddICAC`.
                        self.csr_issued_to.set(ctx.fabric_index);
                        Some(csr)
                    }
                    _ => None,
                };
                full(
                    spec_jf::ICACCSRResponseFields {
                        status_code: status,
                        // §11.25.6.2: the field's conformance is "StatusCode == OK, O", so a
                        // failure carries no CSR at all rather than an empty one.
                        icaccsr: csr,
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(ICACCSR_RESPONSE))
            }
            ADD_ICAC => {
                let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
                let decoded: spec_jf::AddICACFields<'_> = super::decode_fields(payload)?;
                let status = self.add_icac(&decoded, ctx)?;
                full(
                    spec_jf::ICACResponseFields {
                        status_code: status,
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(ICAC_RESPONSE))
            }
            OPEN_JOINT_COMMISSIONING_WINDOW => {
                let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
                let decoded: spec_jf::OpenJointCommissioningWindowFields<'_> =
                    super::decode_fields(payload)?;
                self.open_joint_window(&decoded, ctx)?;
                Ok(None)
            }
            TRANSFER_ANCHOR_REQUEST => {
                let status = match self.hooks.anchor_transfer() {
                    AnchorTransfer::Accepted => TransferAnchorResponseStatusEnum::OK,
                    AnchorTransfer::Refused(why) => why,
                };
                full(
                    spec_jf::TransferAnchorResponseFields {
                        status_code: status,
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(TRANSFER_ANCHOR_RESPONSE))
            }
            TRANSFER_ANCHOR_COMPLETE => {
                self.hooks.anchor_transferred();
                // §12.2.5: the anchor role has moved, so this node no longer administers the
                // Joint Fabric through the fabric it named.
                self.administrator_fabric.set(None);
                Ok(None)
            }
            ANNOUNCE_JOINT_FABRIC_ADMINISTRATOR => {
                let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
                let decoded: spec_jf::AnnounceJointFabricAdministratorFields =
                    super::decode_fields(payload)?;
                self.hooks.administrator_announced(decoded.endpoint_id);
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<H: JointFabricHooks> JointFabricAdministrator<'_, H> {
    /// §11.25.6.1's preconditions, in the order the specification lists them.
    ///
    /// Each has its own cluster-specific status because each tells the administrator a different
    /// thing to do: arm a fail-safe, run Vendor ID Verification, or set the fabric index first.
    fn icac_csr_request(&self, ctx: &InteractionContext<'_>) -> ICACCSRResponseStatusCodeEnum {
        if !self.fail_safe_armed(ctx) {
            // A `FAILSAFE_REQUIRED` interaction-model status, not a cluster one — but the
            // command has a response, so it is carried there. `Busy` is the closest the enum
            // comes and §11.25.4.3 does not define a fail-safe code, so the refusal is the
            // interaction model's; see `add_icac` for the same rule with a status code of its
            // own.
            return ICACCSRResponseStatusCodeEnum::Busy;
        }
        // "If the FabricFabric Table Vendor ID Verification Procedure has not been executed
        // against the initiator of this command, the command SHALL fail with a JfVidNotVerified
        // status code." The verification is §6.4.10's, run by the *peer* against this node's
        // fabric, and the application records it.
        if !ctx.vendor_id_verified {
            return ICACCSRResponseStatusCodeEnum::VIDNotVerified;
        }
        if self.administrator_fabric.get().is_none() {
            return ICACCSRResponseStatusCodeEnum::InvalidAdministratorFabricIndex;
        }
        // "If a prior AddICAC command was successfully executed within the fail-safe timer
        // period, then this command SHALL fail with a CONSTRAINT_ERROR status code." One ICAC
        // per fail-safe: a second CSR after a successful add would be a second intermediate CA
        // for the same join.
        if self.icac_added.get() {
            return ICACCSRResponseStatusCodeEnum::Busy;
        }
        ICACCSRResponseStatusCodeEnum::OK
    }

    /// §11.25.6.3.
    fn add_icac(
        &self,
        request: &spec_jf::AddICACFields<'_>,
        ctx: &InteractionContext<'_>,
    ) -> core::result::Result<ICACResponseStatusEnum, StatusIb> {
        // "This command SHALL be received over a CASE session otherwise it SHALL fail with an
        // INVALID_COMMAND status code." A PASE session has no accessing fabric, which is also
        // what makes the ICAC un-addressable.
        let Some(fabric) = ctx.fabric_index.filter(|f| f.0 != 0) else {
            return Err(Status::InvalidCommand.into());
        };
        if !self.fail_safe_armed(ctx) {
            return Err(Status::FailsafeRequired.into());
        }
        if self.icac_added.get() {
            return Err(Status::ConstraintError.into());
        }
        if request.icac_value.len() > ICAC_MAX {
            return Err(Status::ConstraintError.into());
        }
        // Step 2's pairing: the ICAC has to answer *this* administrator's CSR. Without a CSR
        // there is nothing for its public key to match, so there is nothing to install.
        if self.csr_issued_to.get() != Some(fabric) {
            return Ok(ICACResponseStatusEnum::InvalidPublicKey);
        }

        let status = self.hooks.validate_icac(request.icac_value, fabric);
        if status != ICACResponseStatusEnum::OK {
            // "If any of the above validation checks fail, the server SHALL immediately respond
            // to the client with an ICACResponse" — and nothing is installed.
            return Ok(status);
        }
        self.hooks.install_icac(request.icac_value, fabric)?;
        self.icac_added.set(true);
        // §12.2.5: the fabric this ICAC was cross-signed into is the one the node now
        // administers the Joint Fabric through.
        self.administrator_fabric.set(Some(fabric));
        Ok(ICACResponseStatusEnum::OK)
    }

    /// §11.25.6.5 — "an alias onto the OpenCommissioningWindow command".
    fn open_joint_window(
        &self,
        request: &spec_jf::OpenJointCommissioningWindowFields<'_>,
        ctx: &InteractionContext<'_>,
    ) -> core::result::Result<(), StatusIb> {
        // "This command SHALL fail with a InvalidAdministratorFabricIndex status code sent back
        // to the initiator if the AdministratorFabricIndex attribute has the value of null."
        // There would be no fabric for the joining ecosystem to be cross-signed into.
        if self.administrator_fabric.get().is_none() {
            return Err(StatusIb::cluster_failure(
                ICACCSRResponseStatusCodeEnum::InvalidAdministratorFabricIndex.value(),
            ));
        }
        // Everything else is §11.19.8.1's, unchanged — the alias is not a different window.
        let admin = crate::clusters::administrator_commissioning::AdministratorCommissioning::new(
            self.window,
            self.fail_safe,
            &|_| None,
        );
        admin.open_commissioning_window(
            &crate::clusters::administrator_commissioning::OpenWindowRequest {
                timeout_seconds: request.commissioning_timeout,
                verifier: request.pake_passcode_verifier,
                discriminator: request.discriminator,
                iterations: request.iterations,
                salt: request.salt,
            },
            ctx,
        )
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: JointFabricHooks> Cluster for JointFabricAdministrator<'_, H> {
    const ID: ClusterId = ID;
}
