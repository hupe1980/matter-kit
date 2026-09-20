//! ICD Management, cluster `0x0046` (Core §9.16).
//!
//! A device on a coin cell is asleep for almost all of its life. A client that wants to hear
//! from one registers here, and the device sends it a [Check-In
//! message](crate::icd::checkin) when it wakes and finds nobody subscribed.
//!
//! > ICD Management Cluster enables configuration of the ICD's behavior and ensuring that
//! > listed clients can be notified when an intermittently connected device, ICD, is available
//! > for communication.
//!
//! # Two node ids, and they are not the same thing
//!
//! §9.16.5.3's registration has both a `CheckInNodeID` and a `MonitoredSubject`, and the
//! difference is the point of the design. The **monitored subject** is what the device watches
//! for: if any subscription on this fabric matches it, the client is present and no check-in is
//! due. The **check-in node id** is where the message goes when it is. A phone app might be
//! monitored as a CAT shared by every phone in the household while check-ins go to one hub.
//!
//! Matching the monitored subject is not an equality test — "Matching SHALL be determined using
//! the subject_matches function defined in the Access Control Privilege Granting Algorithm", so
//! a CAT subject matches a subscriber holding that tag at an equal or higher version, exactly as
//! [`acl`](crate::acl) decides it. [`Registration::matches_subscriber`](crate::clusters::icd_management::Registration::matches_subscriber) is that function.
//!
//! # The verification key is what stops one manager evicting another's client
//!
//! `RegisterClient` and `UnregisterClient` both carry an optional `VerificationKey`, and
//! §9.16.7.1 makes it conditional on privilege rather than optional in practice:
//!
//! > The verification key SHALL be provided for clients with manage permissions. The
//! > verification key SHOULD NOT be provided by clients with administrator permissions for the
//! > server cluster. The verification key SHALL be ignored by the server if it is provided by
//! > a client with administrator permissions.
//!
//! So a manager may only touch a registration whose stored key it already knows — it must
//! prove it is the client it claims to be replacing. Without that check, any node with Manage
//! on this cluster could point another client's check-ins at itself, or simply delete them, and
//! the client would go silently unnotified: the symptom is a battery device that appears to
//! work and a client that never hears from it.
//!
//! # What this holds and what it does not
//!
//! The table, the timings, and the counter. **Not** the sleep schedule: when a device idles,
//! when it wakes, and what it does with `StayActiveRequest` are the application's and the
//! radio's, because nothing here can know a power budget.

use core::cell::RefCell;
use core::marker::PhantomData;

use crate::config::Config;
use crate::crypto::{SYMMETRIC_KEY_LENGTH_BYTES, SymmetricKey, ct_eq};
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Privilege, Resolved, ResolvedCommand};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb,
};
use crate::msg::{FabricIndex, NodeId};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use super::Cluster;

/// `0x0046` (§9.16.3).
pub const ID: ClusterId = 0x0046;

/// The revision §9.16.1's table ends on.
pub const REVISION: u16 = 3;

/// `IdleModeDuration` (§9.16.6.1) — `uint32`, seconds, `RV F`, mandatory.
pub const IDLE_MODE_DURATION: AttributeId = 0x0000;
/// `ActiveModeDuration` (§9.16.6.2) — `uint32`, milliseconds, `RV F`, mandatory.
pub const ACTIVE_MODE_DURATION: AttributeId = 0x0001;
/// `ActiveModeThreshold` (§9.16.6.3) — `uint16`, milliseconds, `RV F`, mandatory.
pub const ACTIVE_MODE_THRESHOLD: AttributeId = 0x0002;
/// `RegisteredClients` (§9.16.6.4) — `list[MonitoringRegistrationStruct]`, `RAF N`.
pub const REGISTERED_CLIENTS: AttributeId = 0x0003;
/// `ICDCounter` (§9.16.6.5) — `uint32`, `RA CN`.
pub const ICD_COUNTER: AttributeId = 0x0004;
/// `ClientsSupportedPerFabric` (§9.16.6.6) — `uint16`, `RV F`, min 1.
pub const CLIENTS_SUPPORTED_PER_FABRIC: AttributeId = 0x0005;
/// `UserActiveModeTriggerHint` (§9.16.6.7) — `UserActiveModeTriggerBitmap`, `RV F`.
pub const USER_ACTIVE_MODE_TRIGGER_HINT: AttributeId = 0x0006;
/// `UserActiveModeTriggerInstruction` (§9.16.6) — `string`, max 128, `RV F`.
pub const USER_ACTIVE_MODE_TRIGGER_INSTRUCTION: AttributeId = 0x0007;
/// `OperatingMode` (§9.16.6) — `OperatingModeEnum`, `RV`.
pub const OPERATING_MODE: AttributeId = 0x0008;
/// `MaximumCheckInBackoff` (§9.16.6) — `uint32`, seconds, `RV F`.
pub const MAXIMUM_CHECK_IN_BACKOFF: AttributeId = 0x0009;

/// `RegisterClient` (§9.16.7.1) — `MF`.
pub const REGISTER_CLIENT: CommandId = 0x00;
/// `RegisterClientResponse` (§9.16.7.2).
pub const REGISTER_CLIENT_RESPONSE: CommandId = 0x01;
/// `UnregisterClient` (§9.16.7.3) — `MF`.
pub const UNREGISTER_CLIENT: CommandId = 0x02;
/// `StayActiveRequest` (§9.16.7.4).
pub const STAY_ACTIVE_REQUEST: CommandId = 0x03;
/// `StayActiveResponse` (§9.16.7.5).
pub const STAY_ACTIVE_RESPONSE: CommandId = 0x04;

/// The global `FabricIndex` field of a fabric-scoped struct (§7.19.1.9).
pub const FABRIC_INDEX_FIELD: u8 = 254;

/// `IdleModeDuration`'s upper bound, 64800 seconds — eighteen hours (§9.16.6).
pub const IDLE_MODE_DURATION_MAX: u32 = 64_800;

bitflags::bitflags! {
    /// §9.16.5.1's `UserActiveModeTriggerBitmap`: how a person wakes the device.
    ///
    /// A client shows this to a user who is waiting for a sleepy device to answer, so the
    /// value is a *user interface* rather than a capability — which is why several bits carry
    /// a dependency on `UserActiveModeTriggerInstruction`: "Press the reset button for N
    /// seconds" is useless without N.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct UserActiveModeTrigger: u32 {
        /// Power-cycling the device wakes it.
        const POWER_CYCLE = 1 << 0;
        /// The device's own settings menu explains how.
        const SETTINGS_MENU = 1 << 1;
        /// `UserActiveModeTriggerInstruction` describes a custom way. Requires it.
        const CUSTOM_INSTRUCTION = 1 << 2;
        /// The device manual explains how.
        const DEVICE_MANUAL = 1 << 3;
        /// Actuating the sensor wakes it — opening the door, for a door sensor.
        const ACTUATE_SENSOR = 1 << 4;
        /// Actuating the sensor for N seconds. Requires the instruction.
        const ACTUATE_SENSOR_SECONDS = 1 << 5;
        /// Actuating the sensor N times. Requires the instruction.
        const ACTUATE_SENSOR_TIMES = 1 << 6;
        /// Actuating the sensor until a light blinks.
        const ACTUATE_SENSOR_LIGHTS_BLINK = 1 << 7;
        /// Pressing the reset button.
        const RESET_BUTTON = 1 << 8;
        /// Pressing the reset button until a light blinks.
        const RESET_BUTTON_LIGHTS_BLINK = 1 << 9;
        /// Pressing the reset button for N seconds. Requires the instruction.
        const RESET_BUTTON_SECONDS = 1 << 10;
        /// Pressing the reset button N times. Requires the instruction.
        const RESET_BUTTON_TIMES = 1 << 11;
        /// Pressing the setup button.
        const SETUP_BUTTON = 1 << 12;
        /// Pressing the setup button for N seconds. Requires the instruction.
        const SETUP_BUTTON_SECONDS = 1 << 13;
        /// Pressing the setup button until a light blinks.
        const SETUP_BUTTON_LIGHTS_BLINK = 1 << 14;
        /// Pressing the setup button N times. Requires the instruction.
        const SETUP_BUTTON_TIMES = 1 << 15;
        /// Pressing an application-defined button. Requires the instruction.
        const APP_DEFINED_BUTTON = 1 << 16;
    }
}

impl UserActiveModeTrigger {
    /// The bits §9.16.6.7 says require `UserActiveModeTriggerInstruction` to be present.
    ///
    /// Three bits that *depend* on the instruction do not *require* it —
    /// "ActuateSensorLightsBlink, ResetButtonLightsBlink and SetupButtonLightsBlink (i.e. bits
    /// 7, 9 and 14) have a dependency on the UserActiveModeTriggerInstruction attribute but do
    /// not require the attribute to be present" — because the instruction only adds the colour
    /// of the light. They are excluded here.
    pub const REQUIRE_INSTRUCTION: Self = Self::from_bits_truncate(
        Self::CUSTOM_INSTRUCTION.bits()
            | Self::ACTUATE_SENSOR_SECONDS.bits()
            | Self::ACTUATE_SENSOR_TIMES.bits()
            | Self::RESET_BUTTON_SECONDS.bits()
            | Self::RESET_BUTTON_TIMES.bits()
            | Self::SETUP_BUTTON_SECONDS.bits()
            | Self::SETUP_BUTTON_TIMES.bits()
            | Self::APP_DEFINED_BUTTON.bits(),
    );

    /// Whether this hint obliges the device to publish an instruction string.
    #[must_use]
    pub const fn needs_instruction(self) -> bool {
        self.intersects(Self::REQUIRE_INSTRUCTION)
    }
}

bitflags::bitflags! {
    /// §9.16.4's features.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Feature: u32 {
        /// `CIP` — the Check-In Protocol's attributes and commands.
        const CHECK_IN_PROTOCOL_SUPPORT = 1 << 0;
        /// `UAT` — "supported if and only if the device has a user active mode trigger".
        const USER_ACTIVE_MODE_TRIGGER = 1 << 1;
        /// `LITS` — the device can operate as a Long Idle Time ICD.
        const LONG_IDLE_TIME_SUPPORT = 1 << 2;
        /// `DSLS` — it can switch between SIT and LIT while a client is registered.
        const DYNAMIC_SIT_LIT_SUPPORT = 1 << 3;
    }
}

/// §9.16.5's `ClientTypeEnum` — how available the registered client is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum ClientType {
    /// "typically resident, always-on, fixed infrastructure in the home" — a hub.
    #[default]
    Permanent = 0,
    /// "mobile or non-resident or not always-on" — a phone that leaves the house.
    Ephemeral = 1,
}

impl ClientType {
    /// Reads a wire value; anything else is `CONSTRAINT_ERROR`.
    pub const fn from_value(value: u64) -> Result<Self, Status> {
        match value {
            0 => Ok(Self::Permanent),
            1 => Ok(Self::Ephemeral),
            _ => Err(Status::ConstraintError),
        }
    }
}

/// §9.16.5.2's `OperatingModeEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum OperatingMode {
    /// Short Idle Time: the device is reachable often enough for ordinary interaction.
    #[default]
    Sit = 0,
    /// Long Idle Time: it is not, and a client must expect to wait for a check-in.
    Lit = 1,
}

/// One registered client (§9.16.5.3's `MonitoringRegistrationStruct`), fabric-scoped.
///
/// The `Key` field of that struct is deprecated and never leaves the device — §9.16.5.3 marks
/// it `D`, and it is the shared secret [`checkin`](crate::icd::checkin) encrypts with. Reading
/// the list gives back everything *except* it, which is what makes the verification-key rule
/// mean anything: a client that could read the key would not have to prove it knew it.
#[derive(Debug, Clone)]
pub struct Registration {
    /// Where a Check-In message goes.
    pub check_in_node_id: NodeId,
    /// The subject whose subscription counts as "this client is present" (§6.6.6.2's
    /// `subject_matches`), so a Node ID or a CAT.
    pub monitored_subject: u64,
    /// How available the client says it is.
    pub client_type: ClientType,
    /// Which fabric registered it.
    pub fabric_index: FabricIndex,
    /// The ICDToken — "a 128-bit symmetric key shared by the ICD and the ICD Client, used to
    /// encrypt Check-In messages from this ICD to the MonitoredSubject".
    key: SymmetricKey,
}

/// A CAT subject: the operational node id range §6.6.2.1.2 reserves for them.
const CAT_PREFIX: u64 = 0xFFFF_FFFD_0000_0000;
const CAT_MASK: u64 = 0xFFFF_FFFF_0000_0000;

impl Registration {
    /// Records a client.
    #[must_use]
    pub const fn new(
        check_in_node_id: NodeId,
        monitored_subject: u64,
        client_type: ClientType,
        fabric_index: FabricIndex,
        key: SymmetricKey,
    ) -> Self {
        Self {
            check_in_node_id,
            monitored_subject,
            client_type,
            fabric_index,
            key,
        }
    }

    /// The key Check-In messages to this client are encrypted with.
    #[must_use]
    pub const fn key(&self) -> &SymmetricKey {
        &self.key
    }

    /// Whether a subscriber on this fabric satisfies the monitored subject.
    ///
    /// §9.16.5.3 defers to §6.6.6.2's `subject_matches`, and the CAT half is the part a
    /// direct comparison gets wrong:
    ///
    /// > if the MonitoredSubject has the value 0xFFFF_FFFD_AA12_0002, and one of the
    /// > subscribers … bears the CASE Authenticated TAG value 0xAA12 and the version 0x0002
    /// > **or higher** within its NOC, then the entry matches.
    ///
    /// Comparing CATs for equality instead makes every client appear absent the moment its
    /// tag version is bumped — and the device starts sending check-ins to a client that is
    /// sitting there subscribed.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "§9.16.5.2's monitored subject is matched against a CAT, which is 32 bits (§6.5.6.3)"
    )]
    pub fn matches_subscriber(&self, node: NodeId, cats: &[u32]) -> bool {
        if self.monitored_subject & CAT_MASK != CAT_PREFIX {
            return self.monitored_subject == node.0;
        }
        let wanted = self.monitored_subject as u32;
        let (wanted_tag, wanted_version) = (wanted >> 16, wanted & 0xFFFF);
        cats.iter().any(|&cat| {
            let (tag, version) = (cat >> 16, cat & 0xFFFF);
            tag == wanted_tag && version >= wanted_version
        })
    }

    /// Writes the struct as §9.16.5.3 defines it, without the deprecated `Key`.
    fn encode(&self, w: &mut TlvWriter<'_>) -> crate::error::Result<()> {
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(1), self.check_in_node_id.0)?;
        w.unsigned(Tag::Context(2), self.monitored_subject)?;
        w.unsigned(Tag::Context(4), self.client_type as u64)?;
        w.unsigned(
            Tag::Context(FABRIC_INDEX_FIELD),
            u64::from(self.fabric_index.0),
        )?;
        w.end_container()
    }
}

/// The fields of `RegisterClient` (§9.16.7.1).
#[derive(Debug, Clone)]
struct RegisterFields {
    check_in_node_id: NodeId,
    monitored_subject: u64,
    key: SymmetricKey,
    verification_key: Option<SymmetricKey>,
    client_type: ClientType,
}

/// Reads a 16-octet key field, refusing any other length.
///
/// §9.16.7.1 constrains both `Key` and `VerificationKey` to exactly 16. A shorter one padded
/// to length would be a weaker key that still worked.
fn key_field(bytes: &[u8]) -> Result<SymmetricKey, Status> {
    if bytes.len() != SYMMETRIC_KEY_LENGTH_BYTES {
        return Err(Status::ConstraintError);
    }
    SymmetricKey::from_slice(bytes).map_err(|_| Status::ConstraintError)
}

fn decode_register(fields: &[u8]) -> Result<RegisterFields, Status> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| Status::InvalidAction)?
        .ok_or(Status::InvalidAction)?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }

    let mut check_in_node_id = None;
    let mut monitored_subject = None;
    let mut key = None;
    let mut verification_key = None;
    let mut client_type = None;
    loop {
        let Some(field) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if field.value == Value::EndOfContainer {
            break;
        }
        match field.tag.context() {
            Some(0) => {
                check_in_node_id = Some(NodeId(
                    field.unsigned().map_err(|_| Status::ConstraintError)?,
                ));
            }
            Some(1) => {
                monitored_subject = Some(field.unsigned().map_err(|_| Status::ConstraintError)?);
            }
            Some(2) => {
                key = Some(key_field(
                    field.octets().map_err(|_| Status::ConstraintError)?,
                )?);
            }
            Some(3) => {
                verification_key = Some(key_field(
                    field.octets().map_err(|_| Status::ConstraintError)?,
                )?);
            }
            Some(4) => {
                client_type = Some(ClientType::from_value(
                    field.unsigned().map_err(|_| Status::ConstraintError)?,
                )?);
            }
            _ => {
                reader
                    .skip_value(&field)
                    .map_err(|_| Status::InvalidAction)?;
            }
        }
    }

    let (Some(check_in_node_id), Some(monitored_subject), Some(key), Some(client_type)) =
        (check_in_node_id, monitored_subject, key, client_type)
    else {
        // §8.8.2.3: a command missing a mandatory field is not a command.
        return Err(Status::InvalidCommand);
    };
    Ok(RegisterFields {
        check_in_node_id,
        monitored_subject,
        key,
        verification_key,
        client_type,
    })
}

/// The fields of `UnregisterClient` (§9.16.7.3).
fn decode_unregister(fields: &[u8]) -> Result<(NodeId, Option<SymmetricKey>), Status> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| Status::InvalidAction)?
        .ok_or(Status::InvalidAction)?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }
    let mut node = None;
    let mut verification_key = None;
    loop {
        let Some(field) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if field.value == Value::EndOfContainer {
            break;
        }
        match field.tag.context() {
            Some(0) => {
                node = Some(NodeId(
                    field.unsigned().map_err(|_| Status::ConstraintError)?,
                ))
            }
            Some(1) => {
                verification_key = Some(key_field(
                    field.octets().map_err(|_| Status::ConstraintError)?,
                )?);
            }
            _ => {
                reader
                    .skip_value(&field)
                    .map_err(|_| Status::InvalidAction)?;
            }
        }
    }
    node.map(|n| (n, verification_key))
        .ok_or(Status::InvalidCommand)
}

/// Reads `StayActiveRequest`'s single field (§9.16.7.4).
fn decode_stay_active(fields: &[u8]) -> Result<u32, Status> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| Status::InvalidAction)?
        .ok_or(Status::InvalidAction)?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }
    let mut duration = None;
    loop {
        let Some(field) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if field.value == Value::EndOfContainer {
            break;
        }
        if field.tag.context() == Some(0) {
            duration = Some(
                u32::try_from(field.unsigned().map_err(|_| Status::ConstraintError)?)
                    .map_err(|_| Status::ConstraintError)?,
            );
        } else {
            reader
                .skip_value(&field)
                .map_err(|_| Status::InvalidAction)?;
        }
    }
    duration.ok_or(Status::InvalidCommand)
}

/// The timings a device publishes about its own sleep (§9.16.6.1–9.16.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timings {
    /// `IdleModeDuration`, in **seconds**: "the maximum interval in seconds the server can
    /// stay in idle mode".
    pub idle_mode_duration: u32,
    /// `ActiveModeDuration`, in **milliseconds**: "the minimum interval in milliseconds the
    /// server typically will stay in active mode after initial transition out of idle mode".
    pub active_mode_duration: u32,
    /// `ActiveModeThreshold`, in **milliseconds**: how long it stays active after traffic.
    pub active_mode_threshold: u16,
    /// `MaximumCheckInBackoff`, in seconds, at least `IdleModeDuration`.
    pub maximum_check_in_backoff: u32,
}

impl Default for Timings {
    /// §9.16.6's fallbacks: one second idle, 300 ms active, 300 ms threshold.
    fn default() -> Self {
        Self {
            idle_mode_duration: 1,
            active_mode_duration: 300,
            active_mode_threshold: 300,
            maximum_check_in_backoff: 1,
        }
    }
}

impl Timings {
    /// Whether the four values satisfy §9.16.6's constraints.
    ///
    /// The units are the trap. `IdleModeDuration` is seconds and `ActiveModeDuration` is
    /// milliseconds, and "The IdleModeDuration SHALL NOT be smaller than the
    /// ActiveModeDuration" compares them as *durations* — so a device advertising one second
    /// idle and five seconds active is describing something impossible, and a check that
    /// compared the two numbers directly would pass it.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        if self.idle_mode_duration == 0 || self.idle_mode_duration > IDLE_MODE_DURATION_MAX {
            return false;
        }
        if self.maximum_check_in_backoff < self.idle_mode_duration
            || self.maximum_check_in_backoff > IDLE_MODE_DURATION_MAX
        {
            return false;
        }
        // Compare in milliseconds; `idle_mode_duration` is at most 64800, so this cannot
        // overflow a u32.
        self.idle_mode_duration.saturating_mul(1000) >= self.active_mode_duration
    }
}

/// The descriptor for an instance with these features.
///
/// Derived from the specification's own tables rather than written out, because the element
/// set *moves with the feature map*: without `UAT` there is no `UserActiveModeTriggerHint`,
/// without `LITS` no `OperatingMode` and no `StayActiveRequest`. A fixed list would advertise
/// all of them whatever the device claimed, and a client reading `AttributeList` would believe
/// it — then read an attribute the device answers `UNSUPPORTED_ATTRIBUTE` for.
///
/// `Optional` names the elements §9.16.6 leaves to the product. The storage lives in the
/// returned value, so a device holds one per cluster instance for as long as its node exists.
///
/// Returns [`ErrorCode::InvalidArgument`](crate::ErrorCode) for a feature this revision does
/// not define.
pub fn conforming(
    features: Feature,
    optional: &Optional<'_>,
) -> crate::error::Result<Conforming<12, 4, 2, 0>> {
    Conforming::new(
        &crate::clusters::generated::icd_management::CLUSTER,
        features.bits(),
        optional,
    )
}

/// What a device must do when `StayActiveRequest` arrives.
///
/// §9.16.7.4 makes the answer the device's, not the cluster's: the `PromisedActiveDuration`
/// is "the greater of" what the client asked for and "the server's planned remaining active
/// time based on the ActiveModeThreshold and **its internal resources and power budget**".
/// Nothing here knows a power budget, so the device supplies this and the cluster reports it.
pub trait StayActive {
    /// The duration in milliseconds this device promises to remain reachable, having been
    /// asked for `requested`.
    fn promise(&self, requested: u32) -> u32;
}

/// A device that simply grants what it is asked for.
///
/// Correct for a mains-powered node and a reasonable starting point for a battery one, since
/// §9.16.7.4 permits a server to "replace StayActiveDuration with Minimum Active Duration" —
/// but a device with a real power budget should say so rather than promise what it cannot keep.
#[derive(Debug, Clone, Copy, Default)]
pub struct GrantRequested;

impl StayActive for GrantRequested {
    fn promise(&self, requested: u32) -> u32 {
        requested
    }
}

/// The ICD Management cluster's state (§9.16.6).
///
/// `N` is the total number of registrations across every fabric, and
/// [`Config::ICD_CLIENTS_PER_FABRIC`] is what §9.16.6.6 publishes and what any one fabric may
/// use, so that the first fabric to register cannot leave a later one unable to.
/// [`IcdManagement::CHECK`] refuses at compile time an `N` too small for every fabric to have
/// its share — the attribute is a promise, and a promise the table cannot keep is the defect
/// this whole shape exists to stop.
#[derive(Debug)]
pub struct IcdManagement<'a, C: Config, const N: usize = 5, A: StayActive = GrantRequested> {
    clients: RefCell<heapless::Vec<Registration, N>>,
    counter: RefCell<u32>,
    timings: Timings,
    features: Feature,
    operating_mode: RefCell<OperatingMode>,
    trigger_hint: UserActiveModeTrigger,
    trigger_instruction: &'a str,
    stay_active: A,
    _config: PhantomData<C>,
}

impl<'a, C: Config, const N: usize> IcdManagement<'a, C, N, GrantRequested> {
    /// A cluster for a device that grants every `StayActiveRequest` in full.
    #[must_use]
    pub const fn new(features: Feature, timings: Timings) -> Self {
        Self::with_stay_active(features, timings, GrantRequested)
    }
}

impl<'a, C: Config, const N: usize, A: StayActive> IcdManagement<'a, C, N, A> {
    /// Compile-time proof that the registration table can keep §9.16.6.6's promise.
    ///
    /// > This attribute SHALL indicate the maximum number of entries that the server is able to
    /// > store for each fabric in the RegisteredClients attribute.
    ///
    /// "For each fabric", so the table needs `FABRICS × ICD_CLIENTS_PER_FABRIC` slots. Without
    /// this, `ClientsSupportedPerFabric` is a number a device states and a table that cannot
    /// honour it — and the fabric that finds out is the last one to register.
    pub const CHECK: () = {
        let () = crate::config::AssertValid::<C>::CHECK;
        assert!(
            N >= C::ICD_CLIENTS_PER_FABRIC * C::FABRICS,
            "IcdManagement: §9.16.6.6 promises ICD_CLIENTS_PER_FABRIC registrations to every \
             fabric, so the table must hold FABRICS × that many"
        );
    };

    /// A cluster whose device decides how long it can stay awake.
    #[must_use]
    pub const fn with_stay_active(features: Feature, timings: Timings, stay_active: A) -> Self {
        let () = Self::CHECK;
        Self {
            clients: RefCell::new(heapless::Vec::new()),
            counter: RefCell::new(0),
            timings,
            features,
            // §9.16.6: a device that does not support LIT is always SIT.
            operating_mode: RefCell::new(OperatingMode::Sit),
            trigger_hint: UserActiveModeTrigger::empty(),
            trigger_instruction: "",
            stay_active,
            _config: PhantomData,
        }
    }

    /// Declares how a person wakes this device (§9.16.6.7).
    ///
    /// Returns [`ErrorCode::InvalidArgument`](crate::ErrorCode) when the hint names a trigger
    /// that needs an instruction and none is given: "If the attribute indicates support for a
    /// trigger that is dependent on the UserActiveModeTriggerInstruction … the
    /// UserActiveModeTriggerInstruction attribute SHALL be implemented and SHALL provide the
    /// required information." A hint reading "press the button for N seconds" with no N is
    /// worse than no hint, because a client will display it.
    pub fn with_trigger(
        mut self,
        hint: UserActiveModeTrigger,
        instruction: &'a str,
    ) -> crate::error::Result<Self> {
        if instruction.len() > 128 {
            crate::error::bail!(InvalidArgument)
        }
        if hint.needs_instruction() && instruction.is_empty() {
            crate::error::bail!(InvalidArgument)
        }
        self.trigger_hint = hint;
        self.trigger_instruction = instruction;
        Ok(self)
    }

    /// The timings this device publishes.
    #[must_use]
    pub const fn timings(&self) -> Timings {
        self.timings
    }

    /// The current operating mode (§9.16.5.2).
    #[must_use]
    pub fn operating_mode(&self) -> OperatingMode {
        *self.operating_mode.borrow()
    }

    /// Switches between Short and Long Idle Time.
    ///
    /// §9.16.4.4: a device may do this while a client is registered only with `DSLS`. Without
    /// that feature a registered client has been promised the mode it saw, and changing it
    /// underneath means the client's polling assumptions are silently wrong.
    pub fn set_operating_mode(&self, mode: OperatingMode) -> Result<(), Status> {
        if !self.features.contains(Feature::LONG_IDLE_TIME_SUPPORT) {
            return Err(Status::UnsupportedAttribute);
        }
        if mode == OperatingMode::Lit
            && !self.features.contains(Feature::DYNAMIC_SIT_LIT_SUPPORT)
            && !self.clients.borrow().is_empty()
        {
            return Err(Status::InvalidInState);
        }
        *self.operating_mode.borrow_mut() = mode;
        Ok(())
    }

    /// The `ICDCounter` (§9.16.6.5) — the Check-In Counter for the next message.
    #[must_use]
    pub fn counter(&self) -> u32 {
        *self.counter.borrow()
    }

    /// Advances the counter and returns the value the next Check-In message must be
    /// encrypted with.
    ///
    /// It advances **first**, and that order is forced by §4.22.3.3 rather than chosen. A
    /// client stores the `ICDCounter` it was handed at registration as its *starting* value,
    /// and validation is `stored offset < received − start`: a check-in bearing the very
    /// value that was reported has an offset of zero and is rejected as a replay. Appendix
    /// F.4's Test 3 is exactly that message, and it decrypts perfectly — so a device that
    /// reported N and then checked in with N would look, from the client's side, like an
    /// attacker replaying an old message, with nothing anywhere explaining why.
    ///
    /// Each value is used once besides: reusing one reuses the nonce it derives
    /// ([`checkin`](crate::icd::checkin)), so this both advances and reads rather than
    /// offering the two separately.
    pub fn next_check_in_counter(&self) -> u32 {
        let mut counter = self.counter.borrow_mut();
        *counter = counter.wrapping_add(1);
        *counter
    }

    /// Restores the counter after a reboot, at exactly the value given.
    ///
    /// §4.6.3: "Nodes are required to persist the Check-In Counter in durable storage", and a
    /// counter that rewinds reuses a nonce. A device persisting this should store *ahead* of
    /// where it is — §4.6.3 describes the strategy — exactly as the message counters do.
    pub fn restore_counter(&self, value: u32) {
        *self.counter.borrow_mut() = value;
    }

    /// §4.6.3's factory-reset initialisation, from a full-width random word.
    ///
    /// "The device SHALL randomize the initial value of the counter on factory reset per
    /// Section 4.6.1.1" — the same `Crypto_DRBG(len = 28) + 1` as every other counter in the
    /// specification, so this goes through the same
    /// [`initial_counter`](crate::msg::initial_counter).
    ///
    /// A factory-fresh cluster starts at zero, because a `const fn` constructor has no
    /// randomness to draw on and inventing one would be worse than asking. Call this once, when
    /// the device has no persisted counter to restore; on every boot after that, call
    /// [`restore_counter`](Self::restore_counter) with what was stored. Starting from zero
    /// every time is what §4.6.3 forbids: the client validates a check-in as
    /// `stored offset < received − start`, so a counter that rewinds past a registered client's
    /// starting value makes every later check-in look like a replay, and the client stops
    /// waking for a device that is calling it.
    pub fn randomize_counter(&self, randomness: u32) {
        *self.counter.borrow_mut() = crate::msg::initial_counter(randomness);
    }

    /// Every registration, for a device about to persist them or send a check-in.
    #[must_use]
    pub fn clients(&self) -> core::cell::Ref<'_, heapless::Vec<Registration, N>> {
        self.clients.borrow()
    }

    /// How many registrations one fabric holds.
    #[must_use]
    pub fn len_of_fabric(&self, fabric: FabricIndex) -> usize {
        self.clients
            .borrow()
            .iter()
            .filter(|c| c.fabric_index == fabric)
            .count()
    }

    /// Removes every registration of one fabric — what `RemoveFabric` must do.
    pub fn remove_fabric(&self, fabric: FabricIndex) {
        self.clients
            .borrow_mut()
            .retain(|c| c.fabric_index != fabric);
    }

    /// §9.16.7.1's steps 1–5.
    fn register(
        &self,
        fields: RegisterFields,
        fabric: FabricIndex,
        administrator: bool,
    ) -> Result<(), StatusIb> {
        let mut clients = self.clients.borrow_mut();
        let existing = clients.iter().position(|c| {
            c.fabric_index == fabric && c.check_in_node_id == fields.check_in_node_id
        });

        match existing {
            // Step 1a → 2: an entry for this CheckInNodeID already exists, so this is a
            // *modification* and the verification key decides whether it is allowed.
            Some(position) => {
                let Some(entry) = clients.get_mut(position) else {
                    return Err(Status::Failure.into());
                };
                if !administrator {
                    // Steps 3a and 3b. `ct_eq` because a comparison that stops at the first
                    // differing octet tells an attacker how much of the key it has guessed.
                    let Some(verification) = fields.verification_key else {
                        return Err(Status::Failure.into());
                    };
                    if !ct_eq(verification.as_bytes(), entry.key.as_bytes()) {
                        return Err(Status::Failure.into());
                    }
                }
                // Step 4.
                entry.monitored_subject = fields.monitored_subject;
                entry.client_type = fields.client_type;
                entry.key = fields.key;
                Ok(())
            }
            // Step 1b, or 1c. Counted from the borrow already held: reaching for a second one
            // here is a panic, not a compile error, and `RefCell` is the only thing in this
            // crate that can still do that.
            None => {
                let used = clients.iter().filter(|c| c.fabric_index == fabric).count();
                if used >= C::ICD_CLIENTS_PER_FABRIC {
                    return Err(Status::ResourceExhausted.into());
                }
                clients
                    .push(Registration::new(
                        fields.check_in_node_id,
                        fields.monitored_subject,
                        fields.client_type,
                        fabric,
                        fields.key,
                    ))
                    .map_err(|_| StatusIb::from(Status::ResourceExhausted))
            }
        }
    }

    /// §9.16.7.3's steps 1–5.
    fn unregister(
        &self,
        node: NodeId,
        verification_key: Option<SymmetricKey>,
        fabric: FabricIndex,
        administrator: bool,
    ) -> Result<(), StatusIb> {
        let mut clients = self.clients.borrow_mut();
        let Some(position) = clients
            .iter()
            .position(|c| c.fabric_index == fabric && c.check_in_node_id == node)
        else {
            // Steps 1a and 2a are the same outcome from a client's point of view, and giving
            // them different ones would tell an unprivileged caller which node ids are
            // registered on a fabric it cannot read.
            return Err(Status::NotFound.into());
        };
        if !administrator {
            let Some(entry) = clients.get(position) else {
                return Err(Status::Failure.into());
            };
            let Some(verification) = verification_key else {
                return Err(Status::Failure.into());
            };
            if !ct_eq(verification.as_bytes(), entry.key.as_bytes()) {
                return Err(Status::Failure.into());
            }
        }
        clients.remove(position);
        Ok(())
    }

    /// Whether a fabric's entries belong in this read (§7.19.1.8.2).
    fn visible(ctx: &InteractionContext<'_>, index: FabricIndex) -> bool {
        !ctx.fabric_filtered || ctx.fabric_index == Some(index)
    }

    /// Whether the caller holds Administer over this cluster (§9.16.7.1 step 2).
    ///
    /// An unknown privilege is treated as *not* administrator, which is the cautious reading:
    /// the consequence is a manager-shaped rule applied to an administrator, which refuses a
    /// modification that had no verification key. The other default would let anyone who
    /// reached the command bypass the key check entirely.
    fn is_administrator(ctx: &InteractionContext<'_>) -> bool {
        ctx.privilege
            .is_some_and(|p| p.grants(Privilege::Administer))
    }
}

impl<C: Config, const N: usize, A: StayActive> ClusterHandler for IcdManagement<'_, C, N, A> {
    /// §9.16.6.4: registrations are per fabric, and each one holds a shared key. A
    /// registration that outlives its fabric is key material for somebody who has left.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        if let crate::im::Lifecycle::FabricRemoved(fabric) = event {
            self.remove_fabric(fabric);
        }
    }
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            IDLE_MODE_DURATION => full(w.unsigned(tag, u64::from(self.timings.idle_mode_duration))),
            ACTIVE_MODE_DURATION => {
                full(w.unsigned(tag, u64::from(self.timings.active_mode_duration)))
            }
            ACTIVE_MODE_THRESHOLD => {
                full(w.unsigned(tag, u64::from(self.timings.active_mode_threshold)))
            }
            REGISTERED_CLIENTS => {
                if !self.features.contains(Feature::CHECK_IN_PROTOCOL_SUPPORT) {
                    return Err(Status::UnsupportedAttribute);
                }
                let clients = self.clients.borrow();
                full(w.start_array(tag))?;
                for client in clients
                    .iter()
                    .filter(|c| Self::visible(ctx, c.fabric_index))
                {
                    full(client.encode(w))?;
                }
                full(w.end_container())
            }
            ICD_COUNTER => {
                if !self.features.contains(Feature::CHECK_IN_PROTOCOL_SUPPORT) {
                    return Err(Status::UnsupportedAttribute);
                }
                full(w.unsigned(tag, u64::from(self.counter())))
            }
            CLIENTS_SUPPORTED_PER_FABRIC => {
                if !self.features.contains(Feature::CHECK_IN_PROTOCOL_SUPPORT) {
                    return Err(Status::UnsupportedAttribute);
                }
                full(w.unsigned(tag, C::ICD_CLIENTS_PER_FABRIC as u64))
            }
            USER_ACTIVE_MODE_TRIGGER_HINT => {
                if !self.features.contains(Feature::USER_ACTIVE_MODE_TRIGGER) {
                    return Err(Status::UnsupportedAttribute);
                }
                full(w.unsigned(tag, u64::from(self.trigger_hint.bits())))
            }
            USER_ACTIVE_MODE_TRIGGER_INSTRUCTION => {
                if !self.features.contains(Feature::USER_ACTIVE_MODE_TRIGGER) {
                    return Err(Status::UnsupportedAttribute);
                }
                full(w.utf8(tag, self.trigger_instruction))
            }
            OPERATING_MODE => {
                if !self.features.contains(Feature::LONG_IDLE_TIME_SUPPORT) {
                    return Err(Status::UnsupportedAttribute);
                }
                full(w.unsigned(tag, self.operating_mode() as u64))
            }
            MAXIMUM_CHECK_IN_BACKOFF => {
                if !self.features.contains(Feature::CHECK_IN_PROTOCOL_SUPPORT) {
                    return Err(Status::UnsupportedAttribute);
                }
                full(w.unsigned(tag, u64::from(self.timings.maximum_check_in_backoff)))
            }
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
    ) -> Result<Option<CommandId>, StatusIb> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        match resolved.command.id {
            REGISTER_CLIENT => {
                if !self.features.contains(Feature::CHECK_IN_PROTOCOL_SUPPORT) {
                    return Err(Status::UnsupportedCommand.into());
                }
                // §8.8.2.3 step b.v: a fabric-scoped command with no accessing fabric has
                // nowhere to put its entry. A PASE session during commissioning is exactly
                // that case.
                let Some(fabric) = ctx.fabric_index else {
                    return Err(Status::UnsupportedAccess.into());
                };
                let fields =
                    decode_register(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                self.register(fields, fabric, Self::is_administrator(ctx))?;

                // §9.16.7.2: "The ICDCounter field SHALL be set to the ICDCounter attribute of
                // the server." The client stores it as the starting value its replay window is
                // measured from (§4.22.1.2), so it must be the counter the *next* check-in
                // will exceed rather than one already spent.
                full(w.start_structure(tag))?;
                full(w.unsigned(Tag::Context(0), u64::from(self.counter())))?;
                full(w.end_container())?;
                Ok(Some(REGISTER_CLIENT_RESPONSE))
            }
            UNREGISTER_CLIENT => {
                if !self.features.contains(Feature::CHECK_IN_PROTOCOL_SUPPORT) {
                    return Err(Status::UnsupportedCommand.into());
                }
                let Some(fabric) = ctx.fabric_index else {
                    return Err(Status::UnsupportedAccess.into());
                };
                let (node, verification_key) =
                    decode_unregister(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                self.unregister(node, verification_key, fabric, Self::is_administrator(ctx))?;
                Ok(None)
            }
            STAY_ACTIVE_REQUEST => {
                if !self.features.contains(Feature::LONG_IDLE_TIME_SUPPORT) {
                    return Err(Status::UnsupportedCommand.into());
                }
                let requested =
                    decode_stay_active(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                let promised = self.stay_active.promise(requested);
                full(w.start_structure(tag))?;
                full(w.unsigned(Tag::Context(0), u64::from(promised)))?;
                full(w.end_container())?;
                Ok(Some(STAY_ACTIVE_RESPONSE))
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<C: Config, const N: usize, A: StayActive> Cluster for IcdManagement<'_, C, N, A> {
    const ID: ClusterId = ID;
}
