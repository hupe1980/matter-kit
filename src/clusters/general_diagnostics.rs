//! General Diagnostics, cluster `0x0033` (Core §11.12).
//!
//! > The General Diagnostics Cluster attempts to centralize all metrics that are broadly
//! > relevant to the majority of Nodes.
//!
//! Mandatory on the root node of every device, which makes it the cluster most likely to be
//! read by a support engineer trying to work out why a light has stopped answering. What it
//! holds is a mixture of things this crate cannot know — how many times the device has
//! rebooted, what its interfaces are called, which of its radios is faulty — so almost all of
//! it comes from a [`Diagnostics`] the device implements.
//!
//! # The `EnableKey` is not authentication
//!
//! `TestEventTrigger` (§11.12.7.1) makes a device do things the specification deliberately
//! does not define: certification test plans do. It is gated on a 128-bit key the manufacturer
//! configures, and §11.12.7.1 is specific about what that means:
//!
//! > Devices not targeted towards going to a certification test event SHALL NOT have a
//! > non-zero EnableKey value configured, so that only devices in test environments are
//! > responsive to this command.
//!
//! So the key is a *shipping* control, not a credential — the command already required
//! Manage privilege to get this far. A device that ships with a key configured ships with an
//! undocumented back door, which is why [`Diagnostics::enable_key`] defaults to none and an
//! all-zero key is refused rather than matched: "The value of all zeroes is reserved to
//! indicate that no EnableKey is set."

use core::cell::RefCell;

use crate::crypto::{SYMMETRIC_KEY_LENGTH_BYTES, SymmetricKey, ct_eq};
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, CommandId, EventId, InteractionContext, Status,
    StatusIb,
};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use super::Cluster;

/// `0x0033` (§11.12.3).
pub const ID: ClusterId = 0x0033;

/// The revision §11.12.1's table ends on.
pub const REVISION: u16 = 3;

/// `DMTEST` (§11.12.4) — the extended Data Model testing commands.
///
/// "This feature SHALL be supported if the MaxPathsPerInvoke attribute of the Basic
/// Information Cluster has a value > 1."
pub const FEATURE_DATA_MODEL_TEST: u32 = 1 << 0;

/// `NetworkInterfaces` (§11.12.6.1) — `list[NetworkInterface]`, max 8, `RV`.
pub const NETWORK_INTERFACES: AttributeId = 0x0000;
/// `RebootCount` (§11.12.6.2) — `uint16`, `RV N`.
pub const REBOOT_COUNT: AttributeId = 0x0001;
/// `UpTime` (§11.12.6.3) — `uint64`, seconds, `RV C`.
pub const UP_TIME: AttributeId = 0x0002;
/// `TotalOperationalHours` (§11.12.6.4) — `uint32`, `RV CN`.
pub const TOTAL_OPERATIONAL_HOURS: AttributeId = 0x0003;
/// `BootReason` (§11.12.6.5) — `BootReasonEnum`, `RV`.
pub const BOOT_REASON: AttributeId = 0x0004;
/// `ActiveHardwareFaults` (§11.12.6.6) — `list[HardwareFaultEnum]`, max 11, `RV`.
pub const ACTIVE_HARDWARE_FAULTS: AttributeId = 0x0005;
/// `ActiveRadioFaults` (§11.12.6.7) — `list[RadioFaultEnum]`, max 7, `RV`.
pub const ACTIVE_RADIO_FAULTS: AttributeId = 0x0006;
/// `ActiveNetworkFaults` (§11.12.6.8) — `list[NetworkFaultEnum]`, max 4, `RV`.
pub const ACTIVE_NETWORK_FAULTS: AttributeId = 0x0007;
/// `TestEventTriggersEnabled` (§11.12.6) — `bool`, `RV`, mandatory.
pub const TEST_EVENT_TRIGGERS_ENABLED: AttributeId = 0x0008;
/// `DeviceLoadStatus` (§11.12.5.7) — `DeviceLoadStruct`, `RV C`, revision 3 and above.
pub const DEVICE_LOAD_STATUS: AttributeId = 0x000A;

/// `TestEventTrigger` (§11.12.7.1) — Manage, mandatory.
pub const TEST_EVENT_TRIGGER: CommandId = 0x00;
/// `TimeSnapshot` (§11.12.7.2) — Operate, mandatory.
pub const TIME_SNAPSHOT: CommandId = 0x01;
/// `TimeSnapshotResponse` (§11.12.7.3).
pub const TIME_SNAPSHOT_RESPONSE: CommandId = 0x02;
/// `PayloadTestRequest` (§11.12.7.4) — Manage, `DMTEST`.
pub const PAYLOAD_TEST_REQUEST: CommandId = 0x03;
/// `PayloadTestResponse` (§11.12.7.5).
pub const PAYLOAD_TEST_RESPONSE: CommandId = 0x04;

/// `HardwareFaultChange` (§11.12.8.1) — CRITICAL.
pub const HARDWARE_FAULT_CHANGE: EventId = 0x00;
/// `RadioFaultChange` (§11.12.8.2) — CRITICAL.
pub const RADIO_FAULT_CHANGE: EventId = 0x01;
/// `NetworkFaultChange` (§11.12.8.3) — CRITICAL.
pub const NETWORK_FAULT_CHANGE: EventId = 0x02;
/// `BootReason` (§11.12.8.4) — CRITICAL, mandatory.
pub const BOOT_REASON_EVENT: EventId = 0x03;

/// `PayloadTestRequest`'s `Count` constraint (§11.12.7.4).
pub const PAYLOAD_TEST_MAX: u16 = 2048;

/// §11.12.5.1's `HardwareFaultEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HardwareFault {
    /// An unspecified fault.
    Unspecified = 0,
    /// At least one radio.
    Radio = 1,
    /// At least one sensor.
    Sensor = 2,
    /// An over-temperature fault that can be reset.
    ResettableOverTemp = 3,
    /// One that cannot.
    NonResettableOverTemp = 4,
    /// At least one power source.
    PowerSource = 5,
    /// A visual display.
    VisualDisplayFault = 6,
    /// An audio output.
    AudioOutputFault = 7,
    /// A user interface.
    UserInterfaceFault = 8,
    /// Non-volatile memory.
    NonVolatileMemoryError = 9,
    /// "The Node has encountered disallowed physical tampering."
    TamperDetected = 10,
}

/// §11.12.5.2's `RadioFaultEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RadioFault {
    /// An unspecified radio fault.
    Unspecified = 0,
    /// The Wi-Fi radio.
    WiFiFault = 1,
    /// The cellular radio.
    CellularFault = 2,
    /// The 802.15.4 radio.
    ThreadFault = 3,
    /// The NFC radio.
    NfcFault = 4,
    /// The BLE radio.
    BleFault = 5,
    /// The Ethernet controller.
    EthernetFault = 6,
}

/// §11.12.5.3's `NetworkFaultEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NetworkFault {
    /// An unspecified fault.
    Unspecified = 0,
    /// A hardware failure.
    HardwareFailure = 1,
    /// A jammed network.
    NetworkJammed = 2,
    /// A failure to establish a connection.
    ConnectionFailed = 3,
}

/// §11.12.5.4's `InterfaceTypeEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum InterfaceType {
    /// An interface of an unspecified type.
    #[default]
    Unspecified = 0,
    /// Wi-Fi.
    WiFi = 1,
    /// Ethernet.
    Ethernet = 2,
    /// Cellular.
    Cellular = 3,
    /// Thread.
    Thread = 4,
}

/// §11.12.5.5's `BootReasonEnum` — why the node started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum BootReason {
    /// "unable to identify the Power-On reason as one of the other provided enumeration
    /// values".
    #[default]
    Unspecified = 0,
    /// Physical interaction with the device.
    PowerOnReboot = 1,
    /// A brown-out of the power supply.
    BrownOutReset = 2,
    /// A software watchdog timer.
    SoftwareWatchdogReset = 3,
    /// A hardware watchdog timer.
    HardwareWatchdogReset = 4,
    /// A completed software update.
    SoftwareUpdateCompleted = 5,
    /// A software-initiated reboot.
    SoftwareReset = 6,
}

/// One entry of `NetworkInterfaces` (§11.12.5.6).
///
/// The IP addresses are borrowed slices of wire-order octets — four each for IPv4, sixteen for
/// IPv6 — because a device already holds them somewhere and this cluster is a *view*.
#[derive(Debug, Clone, Copy)]
pub struct NetworkInterface<'a> {
    /// "a human-readable (displayable) name for the network interface, that is different
    /// from all other interfaces", at most 32 octets.
    pub name: &'a str,
    /// Whether the node is advertising operationally on it and can receive on it.
    pub is_operational: bool,
    /// Whether off-premise services are reachable over IPv4; `None` writes TLV null, which
    /// §11.12.5.6 requires when "the Node does not use such services or does not know".
    pub off_premise_ipv4: Option<bool>,
    /// The same for IPv6.
    pub off_premise_ipv6: Option<bool>,
    /// "the current link-layer address for a 802.3 or IEEE 802.11-2020 network interface …
    /// the current extended MAC address for a 802.15.4 interface", in wire byte order.
    pub hardware_address: &'a [u8],
    /// Up to four IPv4 addresses, four octets each.
    pub ipv4_addresses: &'a [[u8; 4]],
    /// Up to eight unicast IPv6 addresses. "This list SHALL include the Node's link-local
    /// address … SHALL NOT include any multicast group addresses."
    pub ipv6_addresses: &'a [[u8; 16]],
    /// What kind of interface it is.
    pub interface_type: InterfaceType,
}

impl NetworkInterface<'_> {
    fn encode(&self, w: &mut TlvWriter<'_>) -> crate::error::Result<()> {
        w.start_structure(Tag::Anonymous)?;
        w.utf8(Tag::Context(0), self.name)?;
        w.bool(Tag::Context(1), self.is_operational)?;
        match self.off_premise_ipv4 {
            Some(value) => w.bool(Tag::Context(2), value)?,
            None => w.null(Tag::Context(2))?,
        }
        match self.off_premise_ipv6 {
            Some(value) => w.bool(Tag::Context(3), value)?,
            None => w.null(Tag::Context(3))?,
        }
        w.octets(Tag::Context(4), self.hardware_address)?;
        w.start_array(Tag::Context(5))?;
        for address in self.ipv4_addresses.iter().take(4) {
            w.octets(Tag::Anonymous, address)?;
        }
        w.end_container()?;
        w.start_array(Tag::Context(6))?;
        for address in self.ipv6_addresses.iter().take(8) {
            w.octets(Tag::Anonymous, address)?;
        }
        w.end_container()?;
        w.unsigned(Tag::Context(7), self.interface_type as u64)?;
        w.end_container()
    }
}

/// §11.12.5.7's `DeviceLoadStruct` — how hard the node is working.
///
/// "For all the fields, the value SHALL remain at the maximum representable (clamp to max) if
/// the maximum value is reached." Saturating rather than wrapping, because a counter that
/// wraps reports a node under no load at the moment it is under the most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceLoad {
    /// Active subscriptions across every fabric.
    pub current_subscriptions: u16,
    /// Active subscriptions for the accessing fabric alone. "If no accessing fabric is
    /// available, this field SHALL be set to zero."
    pub current_subscriptions_for_fabric: u16,
    /// Subscriptions successfully established since start-up, across every fabric.
    pub total_subscriptions_established: u32,
    /// Interaction Model messages sent since start-up, "excluding any retries".
    pub total_im_messages_sent: u32,
    /// Interaction Model messages received since start-up, excluding retries.
    pub total_im_messages_received: u32,
}

impl DeviceLoad {
    fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> crate::error::Result<()> {
        w.start_structure(tag)?;
        w.unsigned(Tag::Context(0), u64::from(self.current_subscriptions))?;
        w.unsigned(
            Tag::Context(1),
            u64::from(self.current_subscriptions_for_fabric),
        )?;
        w.unsigned(
            Tag::Context(2),
            u64::from(self.total_subscriptions_established),
        )?;
        w.unsigned(Tag::Context(3), u64::from(self.total_im_messages_sent))?;
        w.unsigned(Tag::Context(4), u64::from(self.total_im_messages_received))?;
        w.end_container()
    }
}

/// What the device knows about itself, and this crate cannot.
///
/// Every method has a default, because §11.12.6's conformance column makes all but three of
/// these optional and a node that does not track them should say so rather than invent a
/// number. The defaults are the "I do not know" answers: no interfaces, no faults, boot reason
/// `Unspecified`.
pub trait Diagnostics {
    /// The node's network interfaces (§11.12.6.1). Each is passed to `emit` in turn, so a
    /// device can build them from whatever it holds without allocating a list.
    fn network_interfaces(&self, emit: &mut dyn FnMut(&NetworkInterface<'_>)) {
        let _ = emit;
    }

    /// "a best-effort count of the number of times the Node has rebooted" (§11.12.6.2).
    ///
    /// "SHALL NOT be incremented when a Node wakes from a low-power or sleep state", and
    /// "SHALL only be reset to 0 upon a factory reset" — so it is persisted, and a device
    /// that recomputed it from RAM would report 0 forever.
    fn reboot_count(&self) -> u16 {
        0
    }

    /// Seconds since the node's last reboot (§11.12.6.3).
    ///
    /// "SHALL be based on the same System Time source as those used to fulfill any usage of
    /// the systime-us and systime-ms data types" — the same clock the event log timestamps
    /// with, so that a client correlating an event with an uptime gets a consistent answer.
    fn up_time(&self) -> u64 {
        0
    }

    /// Hours the node has been operational, across reboots (§11.12.6.4). `None` omits the
    /// optional attribute.
    fn total_operational_hours(&self) -> Option<u32> {
        None
    }

    /// Why the node last started (§11.12.6.5).
    fn boot_reason(&self) -> BootReason {
        BootReason::Unspecified
    }

    /// The hardware faults currently raised (§11.12.6.6). "This list SHALL NOT contain more
    /// than one instance of a specific HardwareFaultEnum value."
    fn active_hardware_faults(&self, emit: &mut dyn FnMut(HardwareFault)) {
        let _ = emit;
    }

    /// The radio faults currently raised (§11.12.6.7).
    fn active_radio_faults(&self, emit: &mut dyn FnMut(RadioFault)) {
        let _ = emit;
    }

    /// The network faults currently raised (§11.12.6.8).
    fn active_network_faults(&self, emit: &mut dyn FnMut(NetworkFault)) {
        let _ = emit;
    }

    /// The node's current load (§11.12.5.7), or `None` to omit the attribute.
    fn device_load(&self, _ctx: &InteractionContext<'_>) -> Option<DeviceLoad> {
        None
    }

    /// The 128-bit `EnableKey` this device was provisioned with, if any (§11.12.7.1).
    ///
    /// `None` on anything that ships to a customer. A device with a key configured answers
    /// `TestEventTrigger`, and what that command does is defined by certification test
    /// literature rather than by the specification — so on a shipped product it is an
    /// undocumented mechanism with no documented effects.
    fn enable_key(&self) -> Option<&SymmetricKey> {
        None
    }

    /// Runs one test event trigger (§11.12.7.1), having already passed the key check.
    ///
    /// `false` is §11.12.7.1's "If the value of EventTrigger received is not supported by the
    /// receiving Node, this command SHALL fail with a status code of INVALID_COMMAND" — which
    /// is also the right answer for a device that supports none at all: "this command MAY
    /// always fail with the INVALID_COMMAND status, equivalent to the situation of receiving
    /// an unknown EventTrigger, for all possible EventTrigger values".
    ///
    /// Whatever it does "SHALL NOT cause any changes to the state of the device that persist
    /// after the last fabric is removed".
    fn test_event_trigger(&self, trigger: u64) -> bool {
        let _ = trigger;
        false
    }

    /// POSIX time in milliseconds, for `TimeSnapshotResponse` (§11.12.7.3).
    ///
    /// `None` is the correct answer unless the node implements Time Synchronization and its
    /// `UTCTime` is not null — those are the only two cases the specification allows a
    /// non-null value in, and the field is there so a client can align its own clock with the
    /// System Time that stamps this node's events.
    fn posix_time_ms(&self) -> Option<u64> {
        None
    }
}

/// A device that reports nothing it is not obliged to.
///
/// Every mandatory attribute still answers — `RebootCount` 0, `UpTime` 0, `BootReason`
/// `Unspecified`, no interfaces and no faults — which is a conformant, if uninformative,
/// General Diagnostics cluster. Useful for a node under test and as a starting point.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unknown;

impl Diagnostics for Unknown {}

/// The descriptor for an instance with these features.
///
/// Derived from the specification's own tables rather than written out. §11.12 gates
/// `PayloadTestRequest` and its response on `DMTEST`, and a fixed command list would advertise
/// them on every device — including the shipped ones, where §11.12.7.4 says the command must
/// not be answerable at all.
///
/// `Optional` names the elements §11.12.6 leaves to the product: `TotalOperationalHours`,
/// `BootReason`, the three fault lists and `DeviceLoadStatus`.
///
/// Returns [`ErrorCode::InvalidArgument`](crate::ErrorCode) for a feature this revision does
/// not define.
pub fn conforming(
    features: u32,
    optional: &Optional<'_>,
) -> crate::error::Result<Conforming<12, 4, 4, 4>> {
    Conforming::new(
        &crate::clusters::generated::general_diagnostics::CLUSTER,
        features,
        optional,
    )
}

/// Everything §11.12.6 makes optional, for a device that reports all of it.
pub const ALL_OPTIONAL: Optional<'static> = Optional {
    attributes: &[
        TOTAL_OPERATIONAL_HOURS,
        BOOT_REASON,
        ACTIVE_HARDWARE_FAULTS,
        ACTIVE_RADIO_FAULTS,
        ACTIVE_NETWORK_FAULTS,
        DEVICE_LOAD_STATUS,
    ],
    commands: &[],
    events: &[
        HARDWARE_FAULT_CHANGE,
        RADIO_FAULT_CHANGE,
        NETWORK_FAULT_CHANGE,
    ],
};

/// The General Diagnostics cluster (§11.12).
#[derive(Debug)]
pub struct GeneralDiagnostics<'a, D: Diagnostics> {
    device: &'a D,
    features: u32,
    /// `TestEventTriggersEnabled` (§11.12.6): whether this device is in a test environment.
    ///
    /// Mutable because a device may be told to leave test mode, and read by both
    /// `TestEventTrigger` and `PayloadTestRequest`.
    triggers_enabled: RefCell<bool>,
}

impl<'a, D: Diagnostics> GeneralDiagnostics<'a, D> {
    /// A cluster over a device's own diagnostics.
    ///
    /// `TestEventTriggersEnabled` starts **false** and stays false unless the device was
    /// provisioned with an `EnableKey`: §11.12.7.1's whole point is that a shipped product is
    /// unresponsive to these commands.
    #[must_use]
    pub fn new(device: &'a D, features: u32) -> Self {
        let enabled = device.enable_key().is_some();
        Self {
            device,
            features,
            triggers_enabled: RefCell::new(enabled),
        }
    }

    /// Whether test event triggers are currently answered (§11.12.6).
    #[must_use]
    pub fn triggers_enabled(&self) -> bool {
        *self.triggers_enabled.borrow()
    }

    /// Leaves or re-enters test mode.
    ///
    /// Enabling without a provisioned key is [`Status::ConstraintError`]: there would be
    /// nothing for a caller's `EnableKey` to match, and §11.12.7.1 reserves all-zeroes to mean
    /// "no EnableKey is set" rather than "the key is zero".
    pub fn set_triggers_enabled(&self, enabled: bool) -> Result<(), Status> {
        if enabled && self.device.enable_key().is_none() {
            return Err(Status::ConstraintError);
        }
        *self.triggers_enabled.borrow_mut() = enabled;
        Ok(())
    }

    /// §11.12.7.1's `EnableKey` check, shared by both gated commands.
    ///
    /// Three ways to fail, and all three are `CONSTRAINT_ERROR` rather than anything more
    /// specific — which is the specification's choice and a good one: distinguishing "no key
    /// configured" from "wrong key" would tell a caller whether the device is a test unit.
    fn check_enable_key(&self, offered: &[u8]) -> Result<(), StatusIb> {
        if !self.triggers_enabled() {
            return Err(Status::ConstraintError.into());
        }
        if offered.len() != SYMMETRIC_KEY_LENGTH_BYTES {
            return Err(Status::ConstraintError.into());
        }
        // "The value of all zeroes is reserved to indicate that no EnableKey is set.
        // Therefore, if the EnableKey field is received with all zeroes, this command SHALL
        // FAIL with a response status of CONSTRAINT_ERROR." Checked before the comparison, so
        // a device that somehow held a zero key still cannot be unlocked by one.
        if offered.iter().all(|&b| b == 0) {
            return Err(Status::ConstraintError.into());
        }
        let Some(configured) = self.device.enable_key() else {
            return Err(Status::ConstraintError.into());
        };
        // `ct_eq`: a comparison that returns at the first differing octet turns 2¹²⁸ into
        // 16 × 256 guesses.
        if !ct_eq(offered, configured.as_bytes()) {
            return Err(Status::ConstraintError.into());
        }
        Ok(())
    }
}

/// Reads the two fields of `TestEventTrigger` (§11.12.7.1).
fn decode_trigger(fields: &[u8]) -> Result<(heapless::Vec<u8, 32>, u64), Status> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| Status::InvalidAction)?
        .ok_or(Status::InvalidAction)?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }
    let mut key: Option<heapless::Vec<u8, 32>> = None;
    let mut trigger = None;
    loop {
        let Some(field) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if field.value == Value::EndOfContainer {
            break;
        }
        match field.tag.context() {
            Some(0) => {
                let bytes = field.octets().map_err(|_| Status::ConstraintError)?;
                key = Some(heapless::Vec::from_slice(bytes).map_err(|_| Status::ConstraintError)?);
            }
            Some(1) => trigger = Some(field.unsigned().map_err(|_| Status::ConstraintError)?),
            _ => {
                reader
                    .skip_value(&field)
                    .map_err(|_| Status::InvalidAction)?;
            }
        }
    }
    match (key, trigger) {
        (Some(key), Some(trigger)) => Ok((key, trigger)),
        _ => Err(Status::InvalidCommand),
    }
}

/// Reads the three fields of `PayloadTestRequest` (§11.12.7.4).
fn decode_payload_test(fields: &[u8]) -> Result<(heapless::Vec<u8, 32>, u8, u16), Status> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| Status::InvalidAction)?
        .ok_or(Status::InvalidAction)?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }
    let mut key: Option<heapless::Vec<u8, 32>> = None;
    let mut value = None;
    let mut count = None;
    loop {
        let Some(field) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if field.value == Value::EndOfContainer {
            break;
        }
        match field.tag.context() {
            Some(0) => {
                let bytes = field.octets().map_err(|_| Status::ConstraintError)?;
                key = Some(heapless::Vec::from_slice(bytes).map_err(|_| Status::ConstraintError)?);
            }
            Some(1) => {
                value = Some(
                    u8::try_from(field.unsigned().map_err(|_| Status::ConstraintError)?)
                        .map_err(|_| Status::ConstraintError)?,
                );
            }
            Some(2) => {
                let raw = field.unsigned().map_err(|_| Status::ConstraintError)?;
                let raw = u16::try_from(raw).map_err(|_| Status::ConstraintError)?;
                if raw > PAYLOAD_TEST_MAX {
                    return Err(Status::ConstraintError);
                }
                count = Some(raw);
            }
            _ => {
                reader
                    .skip_value(&field)
                    .map_err(|_| Status::InvalidAction)?;
            }
        }
    }
    match (key, value, count) {
        (Some(key), Some(value), Some(count)) => Ok((key, value, count)),
        _ => Err(Status::InvalidCommand),
    }
}

impl<D: Diagnostics> ClusterHandler for GeneralDiagnostics<'_, D> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            NETWORK_INTERFACES => {
                full(w.start_array(tag))?;
                // A write that fails part way cannot be reported from inside the closure, so
                // the first failure is remembered and returned after it.
                let mut failure = None;
                self.device.network_interfaces(&mut |interface| {
                    if failure.is_none()
                        && let Err(error) = interface.encode(w)
                    {
                        failure = Some(error);
                    }
                });
                if failure.is_some() {
                    return Err(Status::ResourceExhausted);
                }
                full(w.end_container())
            }
            REBOOT_COUNT => full(w.unsigned(tag, u64::from(self.device.reboot_count()))),
            UP_TIME => full(w.unsigned(tag, self.device.up_time())),
            TOTAL_OPERATIONAL_HOURS => {
                let Some(hours) = self.device.total_operational_hours() else {
                    return Err(Status::UnsupportedAttribute);
                };
                full(w.unsigned(tag, u64::from(hours)))
            }
            BOOT_REASON => full(w.unsigned(tag, self.device.boot_reason() as u64)),
            ACTIVE_HARDWARE_FAULTS => {
                full(w.start_array(tag))?;
                let mut failure = false;
                self.device.active_hardware_faults(&mut |fault| {
                    failure |= w.unsigned(Tag::Anonymous, fault as u64).is_err();
                });
                if failure {
                    return Err(Status::ResourceExhausted);
                }
                full(w.end_container())
            }
            ACTIVE_RADIO_FAULTS => {
                full(w.start_array(tag))?;
                let mut failure = false;
                self.device.active_radio_faults(&mut |fault| {
                    failure |= w.unsigned(Tag::Anonymous, fault as u64).is_err();
                });
                if failure {
                    return Err(Status::ResourceExhausted);
                }
                full(w.end_container())
            }
            ACTIVE_NETWORK_FAULTS => {
                full(w.start_array(tag))?;
                let mut failure = false;
                self.device.active_network_faults(&mut |fault| {
                    failure |= w.unsigned(Tag::Anonymous, fault as u64).is_err();
                });
                if failure {
                    return Err(Status::ResourceExhausted);
                }
                full(w.end_container())
            }
            TEST_EVENT_TRIGGERS_ENABLED => full(w.bool(tag, self.triggers_enabled())),
            DEVICE_LOAD_STATUS => {
                let Some(load) = self.device.device_load(ctx) else {
                    return Err(Status::UnsupportedAttribute);
                };
                full(load.encode(w, tag))
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
            TEST_EVENT_TRIGGER => {
                let (key, trigger) =
                    decode_trigger(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                self.check_enable_key(&key)?;
                // "If the value of EventTrigger received is not supported by the receiving
                // Node, this command SHALL fail with a status code of INVALID_COMMAND."
                if !self.device.test_event_trigger(trigger) {
                    return Err(Status::InvalidCommand.into());
                }
                Ok(None)
            }
            TIME_SNAPSHOT => {
                // "all fields SHALL be gathered as close together in time as possible, so that
                // the time jitter between the values is minimized" — which is why System Time
                // comes from the context's single instant rather than a fresh clock read.
                full(w.start_structure(tag))?;
                full(w.unsigned(Tag::Context(0), ctx.now.as_millis()))?;
                match self.device.posix_time_ms() {
                    Some(posix) => full(w.unsigned(Tag::Context(1), posix))?,
                    None => full(w.null(Tag::Context(1)))?,
                }
                full(w.end_container())?;
                Ok(Some(TIME_SNAPSHOT_RESPONSE))
            }
            PAYLOAD_TEST_REQUEST => {
                if self.features & FEATURE_DATA_MODEL_TEST == 0 {
                    return Err(Status::UnsupportedCommand.into());
                }
                let (key, value, count) =
                    decode_payload_test(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                self.check_enable_key(&key)?;

                // "If the response is too large to send, the server SHALL fail the command and
                // respond with a response status of RESOURCE_EXHAUSTED" — which is the whole
                // point of the command: it exists so a certification test can find the size at
                // which this device starts refusing.
                full(w.start_structure(tag))?;
                w.octets_fill(Tag::Context(0), usize::from(count), value)
                    .map_err(|_| StatusIb::from(Status::ResourceExhausted))?;
                full(w.end_container())?;
                Ok(Some(PAYLOAD_TEST_RESPONSE))
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<D: Diagnostics> Cluster for GeneralDiagnostics<'_, D> {
    const ID: ClusterId = ID;
}
