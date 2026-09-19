//! General Commissioning cluster `0x0030` (Core §11.10) — the commissioning lifecycle.
//!
//! > This cluster is used to manage basic commissioning lifecycle.
//!
//! Three commands carry the whole of it: `ArmFailSafe` opens a transaction, everything else
//! a commissioner does happens inside it, and `CommissioningComplete` closes it. If the
//! commissioner never gets that far, the fail-safe expires and the device goes back to what
//! it was — [`failsafe`](crate::commissioning::failsafe) is that state machine, and this
//! cluster is its wire surface.
//!
//! # What this cluster does not own
//!
//! `ArmFailSafe`'s expiry has eleven cleanup steps, and they touch the fabric table, the
//! session table, the key store and the network configuration. None of those belong to a
//! cluster, so expiry hands back a [`Cleanup`] and the device applies it. Two commands
//! therefore return work to be done rather than doing it:
//! [`ArmFailSafeOutcome::cleanup`] and [`Completion::cleanup`].
//!
//! That is not a limitation of the design — it is what keeps §11.10.7.2.2's eleven steps
//! auditable against the specification instead of buried across four modules.
//!
//! # `SetRegulatoryConfig` writes another cluster's attribute
//!
//! §11.10.7.4: the `CountryCode` field "SHALL be used to set the Location attribute reflected
//! by the Basic Information Cluster". So this cluster holds a reference to the same
//! [`Location`] cell Basic Information reads, and the two cannot disagree.
//!
//! Note the ordering §11.10.7.4 imposes, which reads like a mistake and is not: a country
//! code the device has no regulatory data for "SHALL still set the Location attribute … but
//! the SetRegulatoryConfigResponse replied SHALL have the ErrorCode field set to
//! ValueOutsideRange". The location lands, the error is reported anyway. A mismatched
//! `NewRegulatoryConfig`, by contrast, leaves `RegulatoryConfig` "unchanged".
//!
//! # Revision 2
//!
//! | Revision | Change |
//! |---|---|
//! | 1 | Initial revision |
//! | 2 | Add Enhanced Setup Flow |

use core::cell::{Cell, RefCell};

use crate::clusters::basic_information::Location;
use crate::commissioning::failsafe::{Cleanup, CommissioningError, FailSafe};
use crate::dm::Resolved;
use crate::dm::ResolvedCommand;
use crate::dm::access::{Access, AccessQualities, Privilege};
use crate::dm::meta::{
    AttributeDescriptor, AttributeQualities, ClusterDescriptor, CommandDescriptor,
};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb,
    WriteOp,
};
use crate::msg::FabricIndex;
use crate::platform::{Duration, Instant};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, set_once};

use super::Cluster;

/// `0x0030` (§11.10.3).
pub const ID: ClusterId = 0x0030;

/// The highest revision in §11.10.1's table.
pub const REVISION: u16 = 2;

/// `TC` (§11.10.4, bit 0) — Enhanced Setup Flow Terms & Conditions.
pub const FEATURE_TERMS_AND_CONDITIONS: u32 = 1 << 0;
/// `NR` (§11.10.4, bit 1) — Network Recovery. Provisional.
pub const FEATURE_NETWORK_RECOVERY: u32 = 1 << 1;

/// `Breadcrumb` (§11.10.6.1) — `uint64`, fallback 0, `RW VA`, mandatory.
pub const BREADCRUMB: AttributeId = 0x0000;
/// `BasicCommissioningInfo` (§11.10.6.2) — `F`, `RV`, mandatory.
pub const BASIC_COMMISSIONING_INFO: AttributeId = 0x0001;
/// `RegulatoryConfig` (§11.10.6.3) — `RV`, mandatory. Read-only on the wire: only
/// `SetRegulatoryConfig` changes it.
pub const REGULATORY_CONFIG: AttributeId = 0x0002;
/// `LocationCapability` (§11.10.6.4) — `F`, `RV`, mandatory.
pub const LOCATION_CAPABILITY: AttributeId = 0x0003;
/// `SupportsConcurrentConnection` (§11.10.6.5) — `F`, `RV`, mandatory.
pub const SUPPORTS_CONCURRENT_CONNECTION: AttributeId = 0x0004;

/// `RecoveryIdentifier` (§11.10.6.11) — `NR`, and provisional.
pub const RECOVERY_IDENTIFIER: AttributeId = 0x000A;

/// `NetworkRecoveryReason` (§11.10.6.12) — `NR`, nullable, and provisional.
pub const NETWORK_RECOVERY_REASON: AttributeId = 0x000B;

/// `ArmFailSafe` (§11.10.7.2) — access `A`.
pub const ARM_FAIL_SAFE: CommandId = 0x00;
/// `ArmFailSafeResponse` (§11.10.7.3).
pub const ARM_FAIL_SAFE_RESPONSE: CommandId = 0x01;
/// `SetRegulatoryConfig` (§11.10.7.4) — access `A`.
pub const SET_REGULATORY_CONFIG: CommandId = 0x02;
/// `SetRegulatoryConfigResponse` (§11.10.7.5).
pub const SET_REGULATORY_CONFIG_RESPONSE: CommandId = 0x03;
/// `CommissioningComplete` (§11.10.7.6) — access `AF`: fabric-scoped, and CASE only.
pub const COMMISSIONING_COMPLETE: CommandId = 0x04;
/// `CommissioningCompleteResponse` (§11.10.7.7).
pub const COMMISSIONING_COMPLETE_RESPONSE: CommandId = 0x05;

/// `RegulatoryLocationTypeEnum` (§11.10.5.2) — "possible radio usage".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RegulatoryLocation {
    /// `0` — indoor only.
    Indoor = 0,
    /// `1` — outdoor only.
    Outdoor = 1,
    /// `2` — indoor/outdoor. "For Nodes without radio network interfaces (e.g. Ethernet-only
    /// devices), the value IndoorOutdoor SHALL always be used."
    IndoorOutdoor = 2,
}

impl RegulatoryLocation {
    /// The value the enum encodes as.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Decodes a wire value, refusing anything §11.10.5.2 does not define.
    #[must_use]
    pub const fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Indoor),
            1 => Some(Self::Outdoor),
            2 => Some(Self::IndoorOutdoor),
            _ => None,
        }
    }
}

/// §5.9's Network Recovery state: how a node that has lost its network asks for a new one.
///
/// A node whose Wi-Fi password changed underneath it is not broken and not commissionable — it
/// still holds its fabric, its NOC and its ACL. §5.9 is the way back: advertise over BLE or
/// Wi-Fi PAF, let an administrator open a *CASE* session over that channel, and take new network
/// credentials through it.
///
/// Three rules carry the flow, and all three are here rather than in the application because
/// all three are about *timing* and are the ones a device gets wrong by being helpful:
///
/// * §5.9.3 step 3: a node "SHALL continue to attempt to connect to the operational network for
///   a duration of at least 120 seconds using its existing credentials" before it may advertise.
///   "Given that temporary network outages occur with some frequency, waiting before entering
///   Network Recovery mode and commencing announcement limits wireless spectrum
///   pollution/interference and helps to limit attack opportunities."
/// * §5.9.3 step 10: on the CASE session the node "SHALL autonomously arm the fail-safe timer
///   for a timeout of 60 seconds", against an administrator that connects and then wanders off.
/// * §5.9.3 step 16: "The Recovery Node SHALL reject the CommissioningComplete that is not
///   received over the operational network." Completing over the recovery channel would declare
///   success at the exact moment nothing had been proved to work.
#[derive(Debug)]
pub struct Recovery {
    /// §11.10.6.11's `RecoveryIdentifier`: "a random 64-bit value, that value SHALL be reset on
    /// factory reset and SHALL remain unchanged until a next factory reset".
    ///
    /// It is what an administrator matches an advertisement against, and §11.10.6.11 says why
    /// it is not the Node ID: the identifier lets an administrator "establish a Node's identity
    /// without revealing its Node ID" to everyone in radio range.
    identifier: u64,
    /// When connectivity was first lost, or `None` while the network is fine.
    lost_at: Cell<Option<Instant>>,
    /// Why, once the node has entered recovery. Null at every other time (§11.10.6.12).
    reason: Cell<Option<NetworkRecoveryReason>>,
    /// Whether the node is advertising for recovery.
    announcing: Cell<bool>,
}

/// §11.10.6.12's `NetworkRecoveryReasonEnum`: "the primary reason that triggered the Network
/// Recovery flow".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NetworkRecoveryReason {
    /// "Unspecified / unknown reason of network failure".
    Unspecified = 0,
    /// "Credentials for the configured operational network are not valid."
    Auth = 1,
    /// "Configured network cannot be found."
    Visibility = 2,
}

impl NetworkRecoveryReason {
    /// The wire value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}

/// §5.9.3 step 3's floor: "at least 120 seconds using its existing credentials".
pub const RECOVERY_HOLD_OFF: Duration = Duration::from_secs(120);

/// §5.9.3 step 10's autonomous fail-safe: 60 seconds from the CASE session being established.
pub const RECOVERY_FAIL_SAFE_SECONDS: u16 = 60;

impl Recovery {
    /// A node whose network is working, with the identifier it was given at factory reset.
    #[must_use]
    pub const fn new(identifier: u64) -> Self {
        Self {
            identifier,
            lost_at: Cell::new(None),
            reason: Cell::new(None),
            announcing: Cell::new(false),
        }
    }

    /// `RecoveryIdentifier` (§11.10.6.11).
    #[must_use]
    pub const fn identifier(&self) -> u64 {
        self.identifier
    }

    /// `NetworkRecoveryReason` (§11.10.6.12), null unless the node is in recovery.
    #[must_use]
    pub fn reason(&self) -> Option<NetworkRecoveryReason> {
        self.reason.get()
    }

    /// Whether the node is advertising for recovery.
    #[must_use]
    pub fn is_announcing(&self) -> bool {
        self.announcing.get()
    }

    /// The node cannot reach its operational network.
    ///
    /// Idempotent: the clock starts at the *first* failure, so a device that calls this on every
    /// retry does not keep pushing its own hold-off out.
    pub fn network_lost(&self, now: Instant, reason: NetworkRecoveryReason) {
        if self.lost_at.get().is_none() {
            self.lost_at.set(Some(now));
            self.reason.set(Some(reason));
        }
    }

    /// The network came back, or recovery finished.
    ///
    /// §11.10.6.12: the reason "SHALL be null when the Node is not undergoing a Network Recovery
    /// flow", so it goes with the state rather than lingering as a diagnostic.
    pub fn network_restored(&self) {
        self.lost_at.set(None);
        self.reason.set(None);
        self.announcing.set(false);
    }

    /// Whether §5.9.3 step 3's hold-off has elapsed, so announcement may begin.
    #[must_use]
    pub fn may_announce(&self, now: Instant) -> bool {
        self.lost_at
            .get()
            .is_some_and(|lost| now.saturating_duration_since(lost) >= RECOVERY_HOLD_OFF)
    }

    /// Begins announcing, if §5.9.3 step 3 allows it yet.
    ///
    /// Returns whether it did. A device that announced early would be advertising through every
    /// brief outage its access point has.
    pub fn begin_announcing(&self, now: Instant) -> bool {
        let allowed = self.may_announce(now);
        if allowed {
            self.announcing.set(true);
        }
        allowed
    }

    /// Whether a `CommissioningComplete` arriving over `operational_network` may be accepted
    /// (§5.9.3 step 16).
    ///
    /// Outside a recovery flow this is always true — an ordinary commissioning completes over
    /// whatever channel it ran on.
    #[must_use]
    pub fn may_complete(&self, over_operational_network: bool) -> bool {
        !self.announcing.get() || over_operational_network
    }
}

/// The attributes of §11.10.6 that are not gated on a feature.
///
/// `Breadcrumb` is the only writable one, at `RW VA`; `RegulatoryConfig` is `RV` even though
/// a command changes it, which is the specification's way of saying that the change must go
/// through `SetRegulatoryConfig` and pick up its regulatory checks.
const ATTRIBUTES: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_write(BREADCRUMB).with_access(Access::read_write_with(
        Privilege::View,
        Privilege::Administer,
    )),
    AttributeDescriptor::read_only(BASIC_COMMISSIONING_INFO)
        .with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(REGULATORY_CONFIG),
    AttributeDescriptor::read_only(LOCATION_CAPABILITY).with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(SUPPORTS_CONCURRENT_CONNECTION)
        .with_qualities(AttributeQualities::FIXED),
];

/// The same list with the two attributes §11.10.6 gates on the `NR` feature.
///
/// Everything unconditional is repeated rather than concatenated: a cluster descriptor is a
/// `const` slice in flash, and §7.3's conformance makes the *whole* list a function of the
/// feature map — so the two variants are two lists, checked against the specification's own
/// tables by [`tests/conformance.rs`].
///
/// `RecoveryIdentifier` is `F` — "SHALL remain unchanged until a next factory reset" — and both
/// are `RA`: only an administrator may read them, because together they say "this node has lost
/// its network, and here is the identifier it is advertising", which is not for everyone with a
/// session.
const RECOVERY_ATTRIBUTES: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_write(BREADCRUMB).with_access(Access::read_write_with(
        Privilege::View,
        Privilege::Administer,
    )),
    AttributeDescriptor::read_only(BASIC_COMMISSIONING_INFO)
        .with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(REGULATORY_CONFIG),
    AttributeDescriptor::read_only(LOCATION_CAPABILITY).with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(SUPPORTS_CONCURRENT_CONNECTION)
        .with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(RECOVERY_IDENTIFIER)
        .with_access(Access::read_only(Privilege::Administer))
        .with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(NETWORK_RECOVERY_REASON)
        .with_access(Access::read_only(Privilege::Administer))
        .with_qualities(AttributeQualities::NULLABLE),
];

/// §11.10.7's command table.
///
/// All three are `A` — Administer — because each of them can leave the device in a state it
/// cannot get out of. `CommissioningComplete` is additionally `F`: it is fabric-scoped, so
/// §8.8.2.3 step b.v refuses it over a session with no accessing fabric before it reaches
/// the handler at all.
const COMMANDS: &[CommandDescriptor] = &[
    CommandDescriptor::new(ARM_FAIL_SAFE)
        .with_access(Access::invoke(Privilege::Administer))
        .with_response(ARM_FAIL_SAFE_RESPONSE),
    CommandDescriptor::new(SET_REGULATORY_CONFIG)
        .with_access(Access::invoke(Privilege::Administer))
        .with_response(SET_REGULATORY_CONFIG_RESPONSE),
    CommandDescriptor::new(COMMISSIONING_COMPLETE)
        .with_access(
            Access::invoke(Privilege::Administer).with_qualities(AccessQualities::FABRIC_SCOPED),
        )
        .with_response(COMMISSIONING_COMPLETE_RESPONSE),
];

/// The cluster descriptor.
#[must_use]
pub const fn cluster() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: 0,
        attributes: ATTRIBUTES,
        accepted_commands: COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// The cluster descriptor for a node that implements §5.9's Network Recovery.
///
/// The feature bit and the two attributes move together: §7.3's conformance makes
/// `RecoveryIdentifier` and `NetworkRecoveryReason` mandatory exactly when `NR` is set, so a
/// descriptor that advertised one without the other would fail
/// [`dm::spec`](crate::dm::spec)'s own validation.
#[must_use]
pub const fn cluster_with_recovery() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: FEATURE_NETWORK_RECOVERY,
        attributes: RECOVERY_ATTRIBUTES,
        accepted_commands: COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// What `ArmFailSafe` produced, beyond its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmFailSafeOutcome {
    /// The `ErrorCode` that went into the `ArmFailSafeResponse`.
    pub error: CommissioningError,
    /// The cleanup steps of §11.10.7.2.2, when `ExpiryLengthSeconds` was zero and the
    /// fail-safe was disarmed on the spot.
    pub cleanup: Option<Cleanup>,
}

/// What `CommissioningComplete` produced.
///
/// §11.10.7.6's five actions on success: steps 1 and 5 (disarm, reset the breadcrumb) happen
/// inside the cluster; steps 2, 3 and 4 — close the commissioning window, revoke PASE
/// privileges, clear PASE sessions — are the device's, and [`Completion::cleanup`] says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    /// The `ErrorCode` that went into the response.
    pub error: CommissioningError,
    /// Set on success: steps 3 and 4 — revoke the temporary administrative privileges granted
    /// to any open PASE session, and clear its Secure Session Context.
    pub close_pase_sessions: bool,
    /// §11.10.7.2.2's cleanup steps, owed to a fail-safe context that had already lapsed when
    /// the command arrived. A successful completion is not a rollback and produces none.
    pub cleanup: Option<Cleanup>,
}

/// What a command left for the device to do, which a cluster cannot do itself.
///
/// Both variants touch the session table, the fabric table or the commissioning window — none
/// of which belong to a cluster. Keeping them as *reported work* rather than hidden effects
/// is what keeps §11.10.7.2.2's eleven steps auditable against the specification instead of
/// scattered across four modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aftermath {
    /// A fail-safe context ended without completing. Apply §11.10.7.2.2's steps.
    Rollback(Cleanup),
    /// `CommissioningComplete` succeeded. §11.10.7.6 steps 2 to 4: the commissioning window
    /// is closed (this cluster has already recorded that), the temporary administrative
    /// privileges granted to any open PASE session are revoked, and its Secure Session
    /// Context is cleared.
    Commissioned,
}

/// The General Commissioning cluster.
///
/// `location` is shared with [`BasicInformation`](super::BasicInformation) — see the module
/// documentation.
#[derive(Debug)]
pub struct GeneralCommissioning<'a> {
    /// The `Location` attribute of Basic Information, which `SetRegulatoryConfig` writes.
    pub location: &'a Location,
    /// `LocationCapability` (§11.10.6.4) — fixed by the manufacturer.
    pub location_capability: RegulatoryLocation,
    /// `SupportsConcurrentConnection` (§11.10.6.5).
    pub supports_concurrent_connection: bool,
    /// The node's fail-safe context.
    ///
    /// Borrowed, not owned: §11.18's `AddNOC`, `UpdateNOC`, `CSRRequest` and
    /// `AddTrustedRootCertificate` all consult and record against the *same* context this
    /// cluster arms, so it is node state that two clusters share — the same arrangement as
    /// [`Location`], and for the same reason.
    pub fail_safe: &'a RefCell<FailSafe>,
    regulatory_config: Cell<RegulatoryLocation>,
    /// The node's commissioning window, shared with Administrator Commissioning.
    ///
    /// §11.10.7.2 consults it to give a PASE commissioner priority over a CASE administrator,
    /// and §11.10.7.6 step 2 closes it on `CommissioningComplete`. Both are about the *same*
    /// window §11.19 opens, so it is node state rather than a flag each cluster keeps —
    /// two copies would be two answers to "is a window open", and the priority rule is
    /// precisely where they would disagree.
    pub window: &'a RefCell<crate::commissioning::window::CommissioningWindow>,
    /// §5.9's Network Recovery state, on a device that implements the `NR` feature.
    ///
    /// Optional because the feature is: a node without it has no `RecoveryIdentifier` to
    /// advertise, and §11.10.6.11's attribute is conformant only when `NR` is set.
    pub recovery: Option<&'a Recovery>,
    /// What the last command invoked through the interaction model left for the device.
    aftermath: Cell<Option<Aftermath>>,
}

impl<'a> GeneralCommissioning<'a> {
    /// The cluster for a device.
    ///
    /// `location_capability` is also the initial `RegulatoryConfig`: §11.10.6.4 says "The
    /// default value of the RegulatoryConfig attribute is the value of LocationCapability
    /// attribute. This means devices always have a safe default value."
    #[must_use]
    pub fn new(
        location: &'a Location,
        location_capability: RegulatoryLocation,
        fail_safe: &'a RefCell<FailSafe>,
        window: &'a RefCell<crate::commissioning::window::CommissioningWindow>,
    ) -> Self {
        Self {
            location,
            location_capability,
            supports_concurrent_connection: true,
            fail_safe,
            window,
            regulatory_config: Cell::new(location_capability),
            recovery: None,
            aftermath: Cell::new(None),
        }
    }

    /// The same cluster on a device that implements §5.9's Network Recovery.
    #[must_use]
    pub const fn with_recovery(mut self, recovery: &'a Recovery) -> Self {
        self.recovery = Some(recovery);
        self
    }

    /// The same cluster on a device that only supports the non-concurrent connection flow
    /// (§5.5).
    #[must_use]
    pub fn without_concurrent_connection(mut self) -> Self {
        self.supports_concurrent_connection = false;
        self
    }

    /// The fail-safe state machine, for a device driving expiry from its own timer.
    ///
    /// [`FailSafe::next_deadline`] says when to call [`FailSafe::expire`]; the [`Cleanup`] it
    /// returns is the device's to apply.
    #[must_use]
    pub fn fail_safe(&self) -> core::cell::Ref<'_, FailSafe> {
        self.fail_safe.borrow()
    }

    /// Mutable access to the fail-safe, for recording `AddNOC`, `UpdateNOC` and the rest
    /// ([`Progress`](crate::commissioning::failsafe::Progress)).
    #[must_use]
    pub fn fail_safe_mut(&self) -> core::cell::RefMut<'_, FailSafe> {
        self.fail_safe.borrow_mut()
    }

    /// `RegulatoryConfig` (§11.10.6.3).
    #[must_use]
    pub fn regulatory_config(&self) -> RegulatoryLocation {
        self.regulatory_config.get()
    }

    /// Whether a commissioning window is open as of `now` (§11.19.7.1).
    #[must_use]
    pub fn is_window_open(&self, now: crate::platform::Instant) -> bool {
        self.window.borrow().open(now).is_some()
    }

    /// Takes the work the last command invoked through the interaction model left behind.
    ///
    /// A device calls this after every invoke against this cluster. Forgetting to means a
    /// disarmed fail-safe leaves its fabric behind, or a completed commissioning leaves a
    /// PASE session open with administrative privileges — which is the one that matters:
    /// §11.10.7.6 steps 3 and 4 exist so that the passcode stops being a key to the device
    /// the moment commissioning ends.
    #[must_use]
    pub fn take_aftermath(&self) -> Option<Aftermath> {
        self.aftermath.take()
    }

    /// `ArmFailSafe` (§11.10.7.2).
    pub fn arm_fail_safe(
        &self,
        expiry_length_seconds: u16,
        breadcrumb: u64,
        accessing_fabric: Option<FabricIndex>,
        over_case: bool,
        now: crate::platform::Instant,
    ) -> ArmFailSafeOutcome {
        let result = self.fail_safe.borrow_mut().arm(
            expiry_length_seconds,
            breadcrumb,
            accessing_fabric,
            now,
            self.is_window_open(now) && over_case,
        );
        ArmFailSafeOutcome {
            error: result.outcome.error_code(),
            cleanup: result.cleanup,
        }
    }

    /// `SetRegulatoryConfig` (§11.10.7.4).
    ///
    /// The two failures are asymmetric on purpose, and the specification is explicit about
    /// both:
    ///
    /// * a `country_code` the device has no regulatory data for still sets `Location`, and
    ///   the response reports `ValueOutsideRange`;
    /// * a `new_config` that `LocationCapability` does not admit leaves `RegulatoryConfig`
    ///   "unchanged".
    ///
    /// The `Breadcrumb` "SHALL be used to atomically set the Breadcrumb attribute on success
    /// of this command … If the command fails, the Breadcrumb attribute SHALL be left
    /// unchanged."
    pub fn set_regulatory_config(
        &self,
        new_config: RegulatoryLocation,
        country_code: &str,
        breadcrumb: u64,
    ) -> CommissioningError {
        // "The CountryCode field SHALL … be used to set the Location attribute reflected by
        // the Basic Information Cluster" — before the capability check, because a device
        // that refuses the regulatory mode still learns where it is.
        if self.location.set(country_code).is_err() {
            return CommissioningError::ValueOutsideRange;
        }

        // "If the LocationCapability attribute is not Indoor/Outdoor and the
        // NewRegulatoryConfig value received does not match either the Indoor or Outdoor
        // fixed value in LocationCapability, then … ValueOutsideRange … and the
        // RegulatoryConfig attribute … SHALL remain unchanged."
        if self.location_capability != RegulatoryLocation::IndoorOutdoor
            && new_config != self.location_capability
        {
            return CommissioningError::ValueOutsideRange;
        }

        self.regulatory_config.set(new_config);
        self.fail_safe.borrow_mut().set_breadcrumb(breadcrumb);
        CommissioningError::Ok
    }

    /// `CommissioningComplete` (§11.10.7.6).
    pub fn commissioning_complete(
        &self,
        over_case: bool,
        accessing_fabric: Option<FabricIndex>,
        now: crate::platform::Instant,
    ) -> Completion {
        let result = self
            .fail_safe
            .borrow_mut()
            .complete(over_case, accessing_fabric, now);
        if result.error.is_ok() {
            // Step 2: "The commissioning window at the Server SHALL be closed." Closing it
            // here also destroys the ephemeral PAKE verifier §11.19.8.1 installed — "It SHALL
            // be deleted by the Node at the end of commissioning".
            self.window.borrow_mut().close();
        }
        Completion {
            error: result.error,
            close_pase_sessions: result.error.is_ok(),
            cleanup: result.cleanup,
        }
    }
}

impl ClusterHandler for GeneralCommissioning<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            BREADCRUMB => full(w.unsigned(tag, self.fail_safe.borrow().breadcrumb())),
            BASIC_COMMISSIONING_INFO => {
                let info = self.fail_safe.borrow().info();
                full(w.start_structure(tag))?;
                full(w.unsigned(Tag::Context(0), u64::from(info.expiry_length_seconds)))?;
                full(w.unsigned(Tag::Context(1), u64::from(info.max_cumulative_seconds)))?;
                full(w.end_container())
            }
            REGULATORY_CONFIG => {
                full(w.unsigned(tag, u64::from(self.regulatory_config.get().value())))
            }
            LOCATION_CAPABILITY => {
                full(w.unsigned(tag, u64::from(self.location_capability.value())))
            }
            SUPPORTS_CONCURRENT_CONNECTION => {
                full(w.bool(tag, self.supports_concurrent_connection))
            }
            RECOVERY_IDENTIFIER => {
                let recovery = self.recovery.ok_or(Status::UnsupportedAttribute)?;
                full(w.unsigned(tag, recovery.identifier()))
            }
            NETWORK_RECOVERY_REASON => {
                let recovery = self.recovery.ok_or(Status::UnsupportedAttribute)?;
                match recovery.reason() {
                    Some(reason) => full(w.unsigned(tag, u64::from(reason.value()))),
                    // §11.10.6.12: "This attribute SHALL be null when the Node is not
                    // undergoing a Network Recovery flow."
                    None => full(w.null(tag)),
                }
            }
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        _op: WriteOp,
        _ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        match resolved.attribute {
            BREADCRUMB => {
                // `Data` is the `AttributeDataIB`'s context-2 member, so it arrives tagged.
                let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
                let value = reader
                    .next_element()
                    .ok()
                    .flatten()
                    .and_then(|element| element.unsigned().ok())
                    .ok_or(Status::InvalidDataType)?;
                self.fail_safe.borrow_mut().set_breadcrumb(value);
                Ok(())
            }
            _ => Err(Status::UnsupportedWrite),
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        match resolved.command.id {
            ARM_FAIL_SAFE => {
                let request = ArmFailSafeRequest::decode(fields)?;
                let outcome = self.arm_fail_safe(
                    request.expiry_length_seconds,
                    request.breadcrumb,
                    ctx.fabric_index,
                    // §11.10.7.2's window rule turns on "the command was received over a CASE
                    // session". An accessing fabric is exactly what a CASE session has and a
                    // PASE session does not (§6.6.6.3).
                    ctx.fabric_index.is_some(),
                    ctx.now,
                );
                if let Some(cleanup) = outcome.cleanup {
                    self.aftermath.set(Some(Aftermath::Rollback(cleanup)));
                }
                write_error_response(w, tag, outcome.error)?;
                Ok(Some(ARM_FAIL_SAFE_RESPONSE))
            }
            SET_REGULATORY_CONFIG => {
                let request = SetRegulatoryConfigRequest::decode(fields)?;
                let error = self.set_regulatory_config(
                    request.new_config,
                    request.country_code,
                    request.breadcrumb,
                );
                write_error_response(w, tag, error)?;
                Ok(Some(SET_REGULATORY_CONFIG_RESPONSE))
            }
            COMMISSIONING_COMPLETE => {
                let completion = self.commissioning_complete(
                    // §8.8.2.3 step b.v has already refused this fabric-scoped command over a
                    // session with no accessing fabric, so reaching here with one means CASE.
                    ctx.fabric_index.is_some(),
                    ctx.fabric_index,
                    ctx.now,
                );
                match completion.cleanup {
                    Some(cleanup) => self.aftermath.set(Some(Aftermath::Rollback(cleanup))),
                    None if completion.close_pase_sessions => {
                        self.aftermath.set(Some(Aftermath::Commissioned));
                    }
                    None => {}
                }
                write_error_response(w, tag, completion.error)?;
                Ok(Some(COMMISSIONING_COMPLETE_RESPONSE))
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// `ArmFailSafe`'s fields (§11.10.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArmFailSafeRequest {
    expiry_length_seconds: u16,
    breadcrumb: u64,
}

impl ArmFailSafeRequest {
    fn decode(fields: Option<&[u8]>) -> Result<Self, Status> {
        let fields = fields.ok_or(Status::InvalidCommand)?;
        // `CommandFields` is §10.6.11's context-2 member of the `CommandDataIB`, so it
        // arrives tagged — read it as the fragment it is, not as a whole TLV document.
        let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidCommand)?
            .ok_or(Status::InvalidCommand)?;
        if element.value.container() != Some(ContainerKind::Structure) {
            return Err(Status::InvalidCommand);
        }
        // Both fields are mandatory, but `ExpiryLengthSeconds` has a fallback of 900 — a
        // client that omits it is asking for the default, not making a malformed request.
        let mut expiry: Option<u16> = None;
        let mut breadcrumb: Option<u64> = None;
        let start_depth = reader.depth();
        loop {
            // Two ways this loop must *not* end: a decode failure, and the buffer running
            // out before the structure closes. Either treated as an end of input would
            // accept a truncated ArmFailSafe and silently apply `ExpiryLengthSeconds`'
            // fallback of 900 — arming the fail-safe for fifteen minutes on garbage.
            let Some(field) = reader.next_element().map_err(|_| Status::InvalidCommand)? else {
                return Err(Status::InvalidCommand);
            };
            if reader.depth() < start_depth {
                break;
            }
            match field.tag {
                Tag::Context(0) => {
                    let value = field.unsigned().map_err(|_| Status::InvalidCommand)?;
                    set_once(
                        &mut expiry,
                        u16::try_from(value).map_err(|_| Status::ConstraintError)?,
                    )
                    .map_err(|_| Status::InvalidCommand)?;
                }
                Tag::Context(1) => {
                    let value = field.unsigned().map_err(|_| Status::InvalidCommand)?;
                    set_once(&mut breadcrumb, value).map_err(|_| Status::InvalidCommand)?;
                }
                _ => reader
                    .skip_value(&field)
                    .map_err(|_| Status::InvalidCommand)?,
            }
        }
        Ok(Self {
            expiry_length_seconds: expiry
                .unwrap_or(crate::commissioning::failsafe::DEFAULT_EXPIRY_SECONDS),
            breadcrumb: breadcrumb.ok_or(Status::InvalidCommand)?,
        })
    }
}

/// `SetRegulatoryConfig`'s fields (§11.10.7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetRegulatoryConfigRequest<'a> {
    new_config: RegulatoryLocation,
    country_code: &'a str,
    breadcrumb: u64,
}

impl<'a> SetRegulatoryConfigRequest<'a> {
    fn decode(fields: Option<&'a [u8]>) -> Result<Self, Status> {
        let fields = fields.ok_or(Status::InvalidCommand)?;
        // `CommandFields` is §10.6.11's context-2 member of the `CommandDataIB`, so it
        // arrives tagged — read it as the fragment it is, not as a whole TLV document.
        let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidCommand)?
            .ok_or(Status::InvalidCommand)?;
        if element.value.container() != Some(ContainerKind::Structure) {
            return Err(Status::InvalidCommand);
        }
        let mut new_config: Option<RegulatoryLocation> = None;
        let mut country_code: Option<&str> = None;
        let mut breadcrumb: Option<u64> = None;
        let start_depth = reader.depth();
        loop {
            // As above: a malformed or truncated remainder fails the command, and only the
            // structure's own end-of-container ends the loop.
            let Some(field) = reader.next_element().map_err(|_| Status::InvalidCommand)? else {
                return Err(Status::InvalidCommand);
            };
            if reader.depth() < start_depth {
                break;
            }
            match field.tag {
                Tag::Context(0) => {
                    let value = field.unsigned().map_err(|_| Status::InvalidCommand)?;
                    let value = u8::try_from(value).map_err(|_| Status::ConstraintError)?;
                    // §11.10.5.2 defines three values; anything else is a constraint error
                    // rather than a silently-clamped mode.
                    let location =
                        RegulatoryLocation::from_value(value).ok_or(Status::ConstraintError)?;
                    set_once(&mut new_config, location).map_err(|_| Status::InvalidCommand)?;
                }
                Tag::Context(1) => {
                    let text = field.utf8().map_err(|_| Status::InvalidCommand)?;
                    set_once(&mut country_code, text).map_err(|_| Status::InvalidCommand)?;
                }
                Tag::Context(2) => {
                    let value = field.unsigned().map_err(|_| Status::InvalidCommand)?;
                    set_once(&mut breadcrumb, value).map_err(|_| Status::InvalidCommand)?;
                }
                _ => reader
                    .skip_value(&field)
                    .map_err(|_| Status::InvalidCommand)?,
            }
        }
        Ok(Self {
            new_config: new_config.ok_or(Status::InvalidCommand)?,
            country_code: country_code.ok_or(Status::InvalidCommand)?,
            breadcrumb: breadcrumb.ok_or(Status::InvalidCommand)?,
        })
    }
}

/// The response shape all three commands share: `ErrorCode [0]`, `DebugText [1]`.
///
/// §11.10.7.1: `DebugText` "SHOULD NOT be presented directly in user interfaces. Its purpose
/// is to help developers in troubleshooting errors." It is mandatory with a fallback of `""`,
/// and a device that filled it would be leaking its internals to anyone who can invoke the
/// command — so this always writes the empty string.
fn write_error_response(
    w: &mut TlvWriter<'_>,
    tag: Tag,
    error: CommissioningError,
) -> Result<(), Status> {
    let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
    full(w.start_structure(tag))?;
    full(w.unsigned(Tag::Context(0), u64::from(error.value())))?;
    full(w.utf8(Tag::Context(1), ""))?;
    full(w.end_container())
}

impl Cluster for GeneralCommissioning<'_> {
    const ID: ClusterId = ID;
}
