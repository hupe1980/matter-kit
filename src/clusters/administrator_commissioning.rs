//! Administrator Commissioning cluster `0x003C` (Core §11.19) — letting a second
//! administrator in.
//!
//! > This cluster is used to trigger a Node to allow a new Administrator to commission it.
//!
//! A commissioned device does not accept PASE sessions. This cluster is how an administrator
//! that already has one opens a window during which it does — so a second ecosystem can
//! commission the same device without a factory reset.
//!
//! # Two methods, and why the passcode differs
//!
//! **Enhanced** (`OpenCommissioningWindow`, mandatory) carries "an ephemeral PAKE passcode
//! verifier … derived from an ephemeral passcode". The administrator generates a passcode,
//! shows it to the user, computes `(w0, L)` and sends *only that* — so the device never holds
//! a passcode, and the verifier "SHALL be deleted by the existing Administrator after sending
//! it to the Node".
//!
//! **Basic** (`OpenBasicCommissioningWindow`, optional, feature `BC`) opens the window against
//! the device's *own* factory passcode — the one printed on its label. That is why it is
//! optional and why §5.6.2 exists separately: anyone who has ever seen the label can use the
//! window, for as long as the device lives.
//!
//! # Cluster-specific status codes
//!
//! §11.19.6 defines three, and the commands have no response command to put them in — so they
//! travel in a `StatusIB`'s `ClusterStatus` field beside `FAILURE` (§10.6.17). `Busy` in
//! particular carries information no interaction-model status does: "it is likely that
//! concurrent commissioning operations from multiple separate Commissioners are about to take
//! place."
//!
//! # Every command is Timed
//!
//! §11.19.8's access column is `AT` — Administer **and Timed**. §8.7.4's Timed transaction is
//! what stops a recorded invocation being replayed later, and opening a commissioning window
//! is precisely the command where that matters: a replay would put a device back into
//! commissioning mode at a moment of the attacker's choosing. §8.8.2.3 step b.vi enforces it
//! before the command reaches this cluster.

use core::cell::RefCell;

use crate::commissioning::window::{
    CommissioningWindow, EphemeralVerifier, OpenWindow, PAKE_VERIFIER_LEN, WindowStatus,
};
use crate::crypto::Spake2pVerifierData;
use crate::dm::access::{Access, AccessQualities, Privilege};
use crate::dm::meta::{AttributeDescriptor, ClusterDescriptor, CommandDescriptor};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb,
};
use crate::msg::{FabricIndex, VendorId};
use crate::platform::{Duration, Instant};
use crate::sc::PbkdfParameters;
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, set_once};

use super::Cluster;

/// `0x003C` (§11.19.3).
pub const ID: ClusterId = 0x003C;

/// The only revision §11.19.1 defines.
pub const REVISION: u16 = 1;

/// `BC` (§11.19.4, bit 0) — "Node supports Basic Commissioning Method".
pub const FEATURE_BASIC: u32 = 1 << 0;

/// `WindowStatus` (§11.19.7.1) — `RV`, mandatory.
pub const WINDOW_STATUS: AttributeId = 0x0000;
/// `AdminFabricIndex` (§11.19.7.2) — nullable, `RV`, mandatory.
pub const ADMIN_FABRIC_INDEX: AttributeId = 0x0001;
/// `AdminVendorId` (§11.19.7.3) — nullable, `RV`, mandatory.
pub const ADMIN_VENDOR_ID: AttributeId = 0x0002;

/// `OpenCommissioningWindow` (§11.19.8.1) — access `AT`, mandatory.
pub const OPEN_COMMISSIONING_WINDOW: CommandId = 0x00;
/// `OpenBasicCommissioningWindow` (§11.19.8.2) — access `AT`, feature `BC`.
pub const OPEN_BASIC_COMMISSIONING_WINDOW: CommandId = 0x01;
/// `RevokeCommissioning` (§11.19.8.3) — access `AT`, mandatory.
pub const REVOKE_COMMISSIONING: CommandId = 0x02;

/// `StatusCodeEnum` (§11.19.6.1) — this cluster's own failure codes.
///
/// They travel in a `StatusIB`'s `ClusterStatus` beside `FAILURE`, because none of these
/// commands has a response command to put them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AdminStatus {
    /// `0x02` — "Could not be completed because another commissioning is in progress".
    Busy = 0x02,
    /// `0x03` — "Provided PAKE parameters were incorrectly formatted or otherwise invalid".
    PakeParameterError = 0x03,
    /// `0x04` — "No commissioning window was currently open".
    WindowNotOpen = 0x04,
}

impl AdminStatus {
    /// The value the `ClusterStatus` field carries.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// As a `StatusIB`: `FAILURE` with this code beside it.
    #[must_use]
    pub const fn as_status(self) -> StatusIb {
        StatusIb::cluster_failure(self.value())
    }
}

/// §5.4.2.3.1's floor: "a device SHALL NOT announce for a duration of less than 3 minutes
/// after announcement commences."
pub const COMMISSIONING_TIMEOUT_MIN_SECONDS: u16 = 180;

/// §5.4.2.3.1's ceiling for the rapid-interval phase: "a commissionable device SHALL NOT
/// announce with a rapid interval for a duration longer than 15 minutes".
pub const COMMISSIONING_TIMEOUT_MAX_SECONDS: u16 = 900;

// --- Descriptors -------------------------------------------------------------------------------

/// Every attribute is `RV`, and the last two are nullable.
const ATTRIBUTES: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_only(WINDOW_STATUS),
    AttributeDescriptor::read_only(ADMIN_FABRIC_INDEX)
        .with_qualities(crate::dm::meta::AttributeQualities::NULLABLE),
    AttributeDescriptor::read_only(ADMIN_VENDOR_ID)
        .with_qualities(crate::dm::meta::AttributeQualities::NULLABLE),
];

/// `AT` — Administer, and Timed. See the module documentation for why the `T` matters here
/// more than almost anywhere else.
const fn timed_admin(id: CommandId) -> CommandDescriptor {
    CommandDescriptor::new(id)
        .with_access(Access::invoke(Privilege::Administer).with_qualities(AccessQualities::TIMED))
}

/// Without the `BC` feature: the two mandatory commands.
const ENHANCED_COMMANDS: &[CommandDescriptor] = &[
    timed_admin(OPEN_COMMISSIONING_WINDOW),
    timed_admin(REVOKE_COMMISSIONING),
];

/// With `BC`: all three.
const ALL_COMMANDS: &[CommandDescriptor] = &[
    timed_admin(OPEN_COMMISSIONING_WINDOW),
    timed_admin(OPEN_BASIC_COMMISSIONING_WINDOW),
    timed_admin(REVOKE_COMMISSIONING),
];

/// The descriptor for a node that supports only the Enhanced Commissioning Method.
///
/// The common case, and the safer one: a Basic window runs against the passcode printed on the
/// device, so anyone who has ever seen the label can use it.
#[must_use]
pub const fn cluster() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: 0,
        attributes: ATTRIBUTES,
        accepted_commands: ENHANCED_COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// The descriptor for a node that also supports the Basic Commissioning Method.
#[must_use]
pub const fn cluster_with_basic() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: FEATURE_BASIC,
        attributes: ATTRIBUTES,
        accepted_commands: ALL_COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// What revoking a window left for the device to do (§11.19.8.3).
///
/// Every step here is outside a cluster's reach, and step 1 runs "regardless of current
/// commissioning window state" — so a device that only acted when the window had been open
/// would leave a PASE session alive after a revoke that answered `WindowNotOpen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoked {
    /// Step 1.b: "terminate any open PASE sessions or PASE sessions in the process of being
    /// established". Always true.
    pub close_pase_sessions: bool,
    /// Step 1.c: "immediately expire any fail-safe held by an open PASE session and perform
    /// the cleanup steps outlined in §11.10.7.2.2".
    ///
    /// `Some` when a fail-safe was armed and had no accessing fabric — which is what "held by
    /// an open PASE session" means.
    pub fail_safe_cleanup: Option<crate::commissioning::failsafe::Cleanup>,
    /// Step 3.b: "stop publishing the DNS-SD records associated with the advertising it was
    /// doing due to the open commissioning window".
    ///
    /// Only when a window was actually open — there is nothing to withdraw otherwise.
    pub stop_advertising: bool,
}

/// The Administrator Commissioning cluster.
pub struct AdministratorCommissioning<'a> {
    /// The node's commissioning window, shared with General Commissioning.
    pub window: &'a RefCell<CommissioningWindow>,
    /// The node's fail-safe. §11.19.8.1: "If the fail-safe timer is currently armed, this
    /// command SHALL fail with a cluster specific status code of Busy."
    pub fail_safe: &'a RefCell<crate::commissioning::failsafe::FailSafe>,
    /// Whether the `BC` feature is supported.
    pub basic_supported: bool,
    /// The fabric table, for looking up the opening administrator's `VendorID`.
    ///
    /// §11.19.7.3: the attribute "SHALL match the VendorID field of the Fabrics attribute list
    /// entry associated with the Administrator having opened the window, **at the time of
    /// window opening**" — so it is read once, here, and not again.
    vendor_of_fabric: &'a dyn Fn(FabricIndex) -> Option<VendorId>,
}

impl<'a> AdministratorCommissioning<'a> {
    /// The cluster for a node that supports only the Enhanced Commissioning Method.
    ///
    /// `vendor_of_fabric` answers §11.19.7.3's lookup — it is a closure rather than a fabric
    /// table reference so that this cluster does not need `Config` and `N` threaded through
    /// it for one field.
    #[must_use]
    pub fn new(
        window: &'a RefCell<CommissioningWindow>,
        fail_safe: &'a RefCell<crate::commissioning::failsafe::FailSafe>,
        vendor_of_fabric: &'a dyn Fn(FabricIndex) -> Option<VendorId>,
    ) -> Self {
        Self {
            window,
            fail_safe,
            basic_supported: false,
            vendor_of_fabric,
        }
    }

    /// The same cluster with the `BC` feature.
    #[must_use]
    pub fn with_basic(mut self) -> Self {
        self.basic_supported = true;
        self
    }

    /// The descriptor matching this instance's features.
    #[must_use]
    pub fn descriptor(&self) -> ClusterDescriptor<'static> {
        if self.basic_supported {
            cluster_with_basic()
        } else {
            cluster()
        }
    }

    /// The two refusals §11.19.8.1 and §11.19.8.2 share.
    fn may_open(&self, ctx: &InteractionContext<'_>) -> Result<(), StatusIb> {
        // "Only one commissioning window can be active at a time. If a Node receives another
        // open commissioning command when an Open Commissioning Window is already active, it
        // SHALL return a failure response."
        if self.window.borrow().open(ctx.now).is_some() {
            return Err(AdminStatus::Busy.as_status());
        }
        // "If the fail-safe timer is currently armed, this command SHALL fail with a cluster
        // specific status code of Busy, since it is likely that concurrent commissioning
        // operations from multiple separate Commissioners are about to take place."
        if self.fail_safe.borrow().is_armed(ctx.now) {
            return Err(AdminStatus::Busy.as_status());
        }
        Ok(())
    }

    /// `OpenCommissioningWindow` (§11.19.8.1) — the Enhanced Commissioning Method.
    pub fn open_commissioning_window(
        &self,
        request: &OpenWindowRequest<'_>,
        ctx: &InteractionContext<'_>,
    ) -> Result<(), StatusIb> {
        self.may_open(ctx)?;

        // "If any format or validity errors related to the PAKEPasscodeVerifier, Iterations or
        // Salt arguments arise, this command SHALL fail with a cluster specific status code of
        // PAKEParameterError."
        //
        // `Spake2pVerifierData::from_bytes` checks that `L` is a point on the curve and that
        // `w0` is a valid scalar — which is the whole of "otherwise invalid". A verifier that
        // merely looked the right length would fail much later, inside PASE, as an
        // inexplicable handshake failure.
        Spake2pVerifierData::from_bytes(request.verifier)
            .map_err(|_| AdminStatus::PakeParameterError.as_status())?;
        // §3.9's `Crypto_PBKDFParameterSet` bounds, which §11.19.8.1's table repeats:
        // iterations 1000 to 100000, salt 16 to 32 octets. Building the real
        // `PbkdfParameters` is the check — and what a PASE responder will answer a
        // `PBKDFParamRequest` with.
        let parameters = PbkdfParameters::new(request.iterations, request.salt)
            .map_err(|_| AdminStatus::PakeParameterError.as_status())?;
        let mut verifier = [0u8; PAKE_VERIFIER_LEN];
        verifier.copy_from_slice(request.verifier);

        self.install(
            WindowStatus::EnhancedOpen,
            request.timeout_seconds,
            request.discriminator,
            Some(EphemeralVerifier {
                verifier,
                iterations: parameters.iterations,
                salt: parameters.salt,
            }),
            ctx,
        )
    }

    /// `OpenBasicCommissioningWindow` (§11.19.8.2) — the Basic Commissioning Method.
    ///
    /// `discriminator` is the device's own, since the command carries none: a Basic window
    /// advertises under the discriminator printed on the device, alongside the passcode.
    pub fn open_basic_commissioning_window(
        &self,
        timeout_seconds: u16,
        discriminator: u16,
        ctx: &InteractionContext<'_>,
    ) -> Result<(), StatusIb> {
        if !self.basic_supported {
            return Err(Status::UnsupportedCommand.into());
        }
        self.may_open(ctx)?;
        self.install(
            WindowStatus::BasicOpen,
            timeout_seconds,
            discriminator,
            None,
            ctx,
        )
    }

    fn install(
        &self,
        status: WindowStatus,
        timeout_seconds: u16,
        discriminator: u16,
        ephemeral: Option<EphemeralVerifier>,
        ctx: &InteractionContext<'_>,
    ) -> Result<(), StatusIb> {
        // §5.4.2.3.1 bounds the announcement duration at both ends, and §11.19.8.1.1 defers to
        // it: "This timeout value SHALL follow guidance as specified in the initial
        // Announcement Duration." Out of range is "any other parameter error", which the
        // section makes `COMMAND_INVALID` rather than a cluster-specific code.
        if !(COMMISSIONING_TIMEOUT_MIN_SECONDS..=COMMISSIONING_TIMEOUT_MAX_SECONDS)
            .contains(&timeout_seconds)
        {
            return Err(Status::InvalidCommand.into());
        }
        // §11.19.8.1: the discriminator is `0 to 4095` — twelve bits.
        if discriminator > 0x0FFF {
            return Err(Status::ConstraintError.into());
        }

        let admin_fabric = ctx.fabric_index;
        let admin_vendor = admin_fabric.and_then(|fabric| (self.vendor_of_fabric)(fabric));
        let expires_at = ctx
            .now
            .saturating_add(Duration::from_secs(u64::from(timeout_seconds)));

        self.window.borrow_mut().install(OpenWindow {
            status,
            expires_at,
            admin_fabric,
            admin_vendor,
            discriminator,
            ephemeral,
        });
        Ok(())
    }

    /// `RevokeCommissioning` (§11.19.8.3).
    ///
    /// > This is an idempotent command.
    ///
    /// Step 1 runs "**regardless of current commissioning window state**", and only then does
    /// step 2 answer `WindowNotOpen` if there was nothing to close. So this returns the work
    /// to do *and* the status, rather than returning early on the error — a revoke against a
    /// closed window still terminates PASE sessions and still expires a PASE-held fail-safe.
    pub fn revoke_commissioning(
        &self,
        ctx: &InteractionContext<'_>,
    ) -> (Revoked, Result<(), StatusIb>) {
        let was_open = self.window.borrow().open(ctx.now).is_some();

        // Step 1.a: "(for ECM) delete the temporary PAKEPasscodeVerifier and associated data".
        // Dropping the window drops the verifier, which is `ZeroizeOnDrop`.
        self.window.borrow_mut().close();

        // Step 1.c: "immediately expire any fail-safe held by an open PASE session". A
        // fail-safe with no accessing fabric is one a PASE session armed — §11.10.7.2 starts
        // the context "at the accessing fabric index for the ArmFailSafe command", which a
        // PASE session does not have.
        let mut fail_safe = self.fail_safe.borrow_mut();
        let pase_held = fail_safe
            .armed(ctx.now)
            .is_some_and(|armed| armed.fabric_index.is_none());
        let cleanup = pase_held.then(|| fail_safe.expire(Instant::MAX)).flatten();
        drop(fail_safe);

        let revoked = Revoked {
            close_pase_sessions: true,
            fail_safe_cleanup: cleanup,
            stop_advertising: was_open,
        };
        let status = if was_open {
            Ok(())
        } else {
            // Step 2: "If the commissioning window was NOT open at the time of receipt, the
            // Node SHALL return a cluster specific status code of WindowNotOpen."
            Err(AdminStatus::WindowNotOpen.as_status())
        };
        (revoked, status)
    }
}

/// `OpenCommissioningWindow`'s fields (§11.19.8.1).
#[derive(Debug, Clone, Copy)]
pub struct OpenWindowRequest<'a> {
    /// `CommissioningTimeout [0]` — seconds, bounded by §5.4.2.3.1.
    pub timeout_seconds: u16,
    /// `PAKEPasscodeVerifier [1]` — `w0 || L`, exactly 97 octets.
    pub verifier: &'a [u8],
    /// `Discriminator [2]` — `0 to 4095`.
    pub discriminator: u16,
    /// `Iterations [3]` — `1000 to 100000`.
    pub iterations: u32,
    /// `Salt [4]` — 16 to 32 octets.
    pub salt: &'a [u8],
}

// --- The wire ----------------------------------------------------------------------------------

impl ClusterHandler for AdministratorCommissioning<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let window = self.window.borrow();
        let open = window.open(ctx.now);
        match resolved.attribute {
            WINDOW_STATUS => full(w.unsigned(tag, u64::from(window.status(ctx.now).value()))),
            // §11.19.7.2, §11.19.7.3: "When the WindowStatus attribute is set to
            // WindowNotOpen, this attribute SHALL be set to null." Null, not zero — zero is a
            // reserved fabric index and 0 is a real vendor id.
            ADMIN_FABRIC_INDEX => match open.and_then(|window| window.admin_fabric) {
                Some(fabric) => full(w.unsigned(tag, u64::from(fabric.0))),
                None => full(w.null(tag)),
            },
            ADMIN_VENDOR_ID => match open.and_then(|window| window.admin_vendor) {
                Some(vendor) => full(w.unsigned(tag, u64::from(vendor.0))),
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
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        // None of the three has a response command — §11.19.8's Response column is `Y`, so
        // success is a plain `SUCCESS` status and failure is a `StatusIB` with this cluster's
        // own code beside `FAILURE`.
        match resolved.command.id {
            OPEN_COMMISSIONING_WINDOW => {
                let request = decode_open_window(fields)?;
                self.open_commissioning_window(&request, ctx)?;
                Ok(None)
            }
            OPEN_BASIC_COMMISSIONING_WINDOW => {
                let timeout = decode_basic_window(fields)?;
                // The command carries no discriminator: a Basic window advertises under the
                // device's own, which is printed on it beside the passcode. A device that
                // wants a different one opens an Enhanced window instead.
                let discriminator = self
                    .window
                    .borrow()
                    .open(ctx.now)
                    .map_or(0, |window| window.discriminator);
                self.open_basic_commissioning_window(timeout, discriminator, ctx)?;
                Ok(None)
            }
            REVOKE_COMMISSIONING => {
                let (_, status) = self.revoke_commissioning(ctx);
                status?;
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl Cluster for AdministratorCommissioning<'_> {
    const ID: ClusterId = ID;
}

/// Walks a `CommandFields` structure, refusing a truncated or malformed one.
fn walk_fields<'a>(
    fields: Option<&'a [u8]>,
    mut on_field: impl FnMut(u8, &crate::tlv::Element<'a>) -> Result<bool, StatusIb>,
) -> Result<(), StatusIb> {
    let fields = fields.ok_or_else(|| StatusIb::new(Status::InvalidCommand))?;
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| StatusIb::new(Status::InvalidCommand))?
        .ok_or_else(|| StatusIb::new(Status::InvalidCommand))?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidCommand.into());
    }
    let start_depth = reader.depth();
    loop {
        let Some(field) = reader
            .next_element()
            .map_err(|_| StatusIb::new(Status::InvalidCommand))?
        else {
            return Err(Status::InvalidCommand.into());
        };
        if reader.depth() < start_depth {
            break;
        }
        let Tag::Context(number) = field.tag else {
            reader
                .skip_value(&field)
                .map_err(|_| StatusIb::new(Status::InvalidCommand))?;
            continue;
        };
        if !on_field(number, &field)? {
            reader
                .skip_value(&field)
                .map_err(|_| StatusIb::new(Status::InvalidCommand))?;
        }
    }
    Ok(())
}

fn decode_open_window(fields: Option<&[u8]>) -> Result<OpenWindowRequest<'_>, StatusIb> {
    let invalid = || StatusIb::new(Status::InvalidCommand);
    let mut timeout = None;
    let mut verifier = None;
    let mut discriminator = None;
    let mut iterations = None;
    let mut salt = None;
    walk_fields(fields, |number, element| {
        match number {
            0 => {
                let value = element.unsigned().map_err(|_| invalid())?;
                set_once(
                    &mut timeout,
                    u16::try_from(value).map_err(|_| StatusIb::new(Status::ConstraintError))?,
                )
            }
            1 => set_once(&mut verifier, element.octets().map_err(|_| invalid())?),
            2 => {
                let value = element.unsigned().map_err(|_| invalid())?;
                set_once(
                    &mut discriminator,
                    u16::try_from(value).map_err(|_| StatusIb::new(Status::ConstraintError))?,
                )
            }
            3 => {
                let value = element.unsigned().map_err(|_| invalid())?;
                set_once(
                    &mut iterations,
                    u32::try_from(value).map_err(|_| StatusIb::new(Status::ConstraintError))?,
                )
            }
            4 => set_once(&mut salt, element.octets().map_err(|_| invalid())?),
            _ => return Ok(false),
        }
        .map_err(|_| invalid())?;
        Ok(true)
    })?;
    let verifier = verifier.ok_or_else(invalid)?;
    // §11.19.8.1's table constrains the field to exactly 97 octets. A verifier of the wrong
    // length is a "format … error related to the PAKEPasscodeVerifier", which the section
    // gives a cluster-specific code of its own rather than `CONSTRAINT_ERROR`.
    if verifier.len() != PAKE_VERIFIER_LEN {
        return Err(AdminStatus::PakeParameterError.as_status());
    }
    Ok(OpenWindowRequest {
        timeout_seconds: timeout.ok_or_else(invalid)?,
        verifier,
        discriminator: discriminator.ok_or_else(invalid)?,
        iterations: iterations.ok_or_else(invalid)?,
        salt: salt.ok_or_else(invalid)?,
    })
}

fn decode_basic_window(fields: Option<&[u8]>) -> Result<u16, StatusIb> {
    let invalid = || StatusIb::new(Status::InvalidCommand);
    let mut timeout = None;
    walk_fields(fields, |number, element| {
        match number {
            0 => {
                let value = element.unsigned().map_err(|_| invalid())?;
                set_once(
                    &mut timeout,
                    u16::try_from(value).map_err(|_| StatusIb::new(Status::ConstraintError))?,
                )
                .map_err(|_| invalid())?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    timeout.ok_or_else(invalid)
}
