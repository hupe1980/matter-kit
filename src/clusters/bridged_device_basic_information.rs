//! Bridged Device Basic Information, cluster `0x0039` (Core §9.13).
//!
//! > This cluster provides attributes and events for determining basic information about
//! > Bridged Nodes.
//!
//! What a bridge says about a lamp it does not itself contain. It is Basic Information with
//! the *node's* facts taken out — §9.13.5 marks `DataModelRevision`, `Location`,
//! `LocalConfigDisabled`, `CapabilityMinima`, `SpecificationVersion` and `MaxPathsPerInvoke`
//! disallowed, because those describe the Matter node doing the bridging, not the Zigbee bulb
//! behind it.
//!
//! # Absent, not blank
//!
//! Almost everything here is optional, and §9.13 is unusually explicit about why:
//!
//! > For such cases where the information for a particular attribute is not available, the
//! > Bridge SHOULD NOT include the attribute in the cluster for this Bridged Device.
//!
//! And again per attribute: "If the manufacturer of a Bridged Device is known to the Bridge,
//! the Bridge SHALL provide this name (in attribute VendorName), otherwise it SHALL NOT
//! include this attribute." So [`BridgedDevice`]'s fields are `Option`, an absent one is left
//! out of `AttributeList` rather than reported as an empty string, and a client can tell "the
//! bridge does not know" from "the vendor is called nothing".
//!
//! # Where it may appear
//!
//! > This cluster SHALL NOT be used on an endpoint that is not in the Descriptor cluster
//! > PartsList of an endpoint with an Aggregator device type.
//!
//! A rule about the node's shape rather than about this cluster's data, so it is the
//! endpoint's `PartsList` that enforces it — see `examples/bridge`.

use core::cell::{Cell, RefCell};

use crate::clusters::generated::bridged_device_basic_information as spec_bridged;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::msg::VendorId;
use crate::platform::{Duration, Instant};
use crate::tlv::{Tag, TlvWriter};

use super::Cluster;

pub use spec_bridged::attribute::{
    CONFIGURATION_VERSION, HARDWARE_VERSION, HARDWARE_VERSION_STRING, MANUFACTURING_DATE,
    NODE_LABEL, PART_NUMBER, PRODUCT_LABEL, PRODUCT_NAME, PRODUCT_URL, REACHABLE, SERIAL_NUMBER,
    SOFTWARE_VERSION, SOFTWARE_VERSION_STRING, UNIQUE_ID, VENDOR_ID, VENDOR_NAME,
};
pub use spec_bridged::command::KEEP_ACTIVE;
pub use spec_bridged::event::{ACTIVE_CHANGED, REACHABLE_CHANGED};
pub use spec_bridged::{ID, PICS, REVISION, feature};

/// What the bridge knows about one bridged device.
///
/// Every field is optional because the bridge may simply not know: a Zigbee bulb has no
/// Matter product id, and §9.13.5.1 says "For bridged non-Matter devices, the ProductID
/// attribute SHALL NOT be included."
#[derive(Debug, Clone, Copy, Default)]
pub struct BridgedDevice<'a> {
    /// `VendorName` — the manufacturer, when the bridge knows it.
    pub vendor_name: Option<&'a str>,
    /// `VendorID` — the Alliance-assigned code, when the bridge knows it.
    pub vendor_id: Option<VendorId>,
    /// `ProductName`.
    pub product_name: Option<&'a str>,
    /// `ProductID` — only ever for a bridged *Matter* device.
    pub product_id: Option<u16>,
    /// `HardwareVersion` and its string form.
    pub hardware_version: Option<u16>,
    /// `HardwareVersionString`.
    pub hardware_version_string: Option<&'a str>,
    /// `SoftwareVersion`.
    pub software_version: Option<u32>,
    /// `SoftwareVersionString`.
    pub software_version_string: Option<&'a str>,
    /// `ManufacturingDate`, as §11.1.5.12's "YYYYMMDD" prefix.
    pub manufacturing_date: Option<&'a str>,
    /// `PartNumber`.
    pub part_number: Option<&'a str>,
    /// `ProductURL`.
    pub product_url: Option<&'a str>,
    /// `ProductLabel`.
    pub product_label: Option<&'a str>,
    /// `SerialNumber`.
    pub serial_number: Option<&'a str>,
    /// `UniqueID` (§9.13.5.3).
    ///
    /// > If the bridged device does not provide some unique id ... the bridge SHALL generate a
    /// > unique id on behalf of the bridged device.
    ///
    /// So a bridge that has one should always pass one: this is what lets a controller
    /// recognise the same bulb after the bridge renumbers its endpoints.
    pub unique_id: Option<&'a str>,
    /// `ConfigurationVersion` (§9.13.5.4) — bumped when the bridged device's configuration
    /// changes, so a client can tell a renamed device from a replaced one.
    pub configuration_version: Option<u32>,
}

/// What a `KeepActive` (§9.13.6.1) asks the bridge to do.
///
/// The bridge cannot do it synchronously: the device is asleep, by definition. So the
/// cluster records the *request* — merged per §9.13.6.1's rules — and the bridge acts on it
/// when the device next checks in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingActive {
    /// How long to hold the device awake, in milliseconds.
    pub stay_active_ms: u32,
    /// When the request lapses if the device does not appear.
    pub expires: Instant,
}

/// What a device labelled its `NodeLabel` (§11.1.5.6) — writable, max 32.
pub const NODE_LABEL_MAX: usize = 32;

/// Bridged Device Basic Information for one bridged device.
#[derive(Debug)]
pub struct BridgedDeviceBasicInformation<'a> {
    device: BridgedDevice<'a>,
    reachable: Cell<bool>,
    node_label: RefCell<heapless::String<NODE_LABEL_MAX>>,
    pending: Cell<Option<PendingActive>>,
    /// Event records the device turns into §7.14 events, drained by [`Self::take_events`].
    events: RefCell<heapless::Vec<Event, 8>>,
}

/// An event this cluster produced, for the device to record in its own store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// §9.13.7.1 `ReachableChanged`, carrying the new `ReachableNewValue`.
    ReachableChanged(bool),
    /// §9.13.7.2 `ActiveChanged`, carrying `PromisedActiveDuration` in milliseconds.
    ActiveChanged(u32),
}

impl<'a> BridgedDeviceBasicInformation<'a> {
    /// A cluster describing `device`, reachable or not.
    #[must_use]
    pub fn new(device: BridgedDevice<'a>, reachable: bool) -> Self {
        Self {
            device,
            reachable: Cell::new(reachable),
            node_label: RefCell::new(heapless::String::new()),
            pending: Cell::new(None),
            events: RefCell::new(heapless::Vec::new()),
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    ///
    /// The optional set is the *bridge's* to declare, and it is not a style choice: §9.13
    /// says an attribute the bridge cannot fill must be left out, so
    /// [`Self::optional_for`] derives it from what [`BridgedDevice`] actually holds.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<16, 1, 0, 2>> {
        Conforming::new(&spec_bridged::CLUSTER, feature_map, optional)
    }

    /// Which optional attributes this bridge can actually fill.
    ///
    /// `NodeLabel` is always served — it is the *user's* name for the device, which the bridge
    /// stores whether or not the device told it anything.
    #[must_use]
    pub fn optional_for(device: &BridgedDevice<'_>, buf: &'a mut [u32; 16]) -> Optional<'a> {
        let mut n = 0usize;
        let mut add = |id: u32, present: bool| {
            if present && n < buf.len() {
                if let Some(slot) = buf.get_mut(n) {
                    *slot = id;
                }
                n = n.saturating_add(1);
            }
        };
        add(VENDOR_NAME, device.vendor_name.is_some());
        add(VENDOR_ID, device.vendor_id.is_some());
        add(PRODUCT_NAME, device.product_name.is_some());
        add(NODE_LABEL, true);
        add(HARDWARE_VERSION, device.hardware_version.is_some());
        add(
            HARDWARE_VERSION_STRING,
            device.hardware_version_string.is_some(),
        );
        add(SOFTWARE_VERSION, device.software_version.is_some());
        add(
            SOFTWARE_VERSION_STRING,
            device.software_version_string.is_some(),
        );
        add(MANUFACTURING_DATE, device.manufacturing_date.is_some());
        add(PART_NUMBER, device.part_number.is_some());
        add(PRODUCT_URL, device.product_url.is_some());
        add(PRODUCT_LABEL, device.product_label.is_some());
        add(SERIAL_NUMBER, device.serial_number.is_some());
        add(UNIQUE_ID, device.unique_id.is_some());
        add(
            CONFIGURATION_VERSION,
            device.configuration_version.is_some(),
        );
        // `ProductID` is `desc` rather than `O`, so it is not an optional the caller may
        // switch on — a bridged Matter device gets it and a non-Matter one must not.
        Optional {
            attributes: buf.get(..n).unwrap_or(&[]),
            commands: &[],
            events: &[],
        }
    }

    /// Everything the `BridgedICDSupport` feature adds: `KeepActive`.
    pub const WITH_KEEP_ACTIVE: Optional<'static> = Optional {
        attributes: &[],
        commands: &[KEEP_ACTIVE],
        events: &[],
    };

    /// What the bridge knows about the device.
    #[must_use]
    pub const fn device(&self) -> &BridgedDevice<'a> {
        &self.device
    }

    /// `Reachable` (§9.13.5.2).
    #[must_use]
    pub fn reachable(&self) -> bool {
        self.reachable.get()
    }

    /// Reports that the bridged device became reachable, or stopped being.
    ///
    /// §9.13.7.1's `ReachableChanged` is "generated when the Reachable attribute changes" —
    /// on the change, so a bridge that re-polls every thirty seconds does not emit an event
    /// every thirty seconds. That matters more here than in most clusters: an event is a
    /// buffered record on a device with a fixed ring, and a chatty one pushes out everything
    /// else in the ring.
    pub fn set_reachable(&self, reachable: bool) {
        if self.reachable.replace(reachable) != reachable {
            self.push(Event::ReachableChanged(reachable));
        }
    }

    /// `NodeLabel` — the name a user gave the device through this bridge.
    #[must_use]
    pub fn node_label(&self) -> core::cell::Ref<'_, heapless::String<NODE_LABEL_MAX>> {
        self.node_label.borrow()
    }

    /// The `KeepActive` request outstanding, if any.
    #[must_use]
    pub fn pending_active(&self) -> Option<PendingActive> {
        self.pending.get()
    }

    /// Drops a `KeepActive` request whose `TimeoutMs` has run out (§9.13.6.1).
    ///
    /// > The server "pending active" state SHALL expire after the amount of time defined by
    /// > the TimeoutMs field ... if no subsequent KeepActive command is received.
    pub fn poll(&self, now: Instant) {
        if let Some(pending) = self.pending.get()
            && now >= pending.expires
        {
            self.pending.set(None);
        }
    }

    /// The bridge saw the device wake, so the outstanding request is satisfied.
    ///
    /// §9.13.6.1: "The server SHALL only keep the bridged device active once for a request.
    /// (The server SHALL only consider the operation performed if an associated ActiveChanged
    /// event was generated.)" — so the request is cleared here and nowhere else.
    pub fn became_active(&self) {
        if let Some(pending) = self.pending.take() {
            self.push(Event::ActiveChanged(pending.stay_active_ms));
        }
    }

    /// Takes the event records the cluster has produced.
    ///
    /// Draining rather than reading means a record is reported once, and a device that never
    /// drains cannot accumulate them forever — the buffer is fixed and its oldest records go,
    /// the same way §7.14.2's event ring drops its oldest.
    pub fn take_events(&self) -> heapless::Vec<Event, 8> {
        core::mem::take(&mut self.events.borrow_mut())
    }

    fn push(&self, event: Event) {
        let mut events = self.events.borrow_mut();
        if events.is_full() {
            events.remove(0);
        }
        let _ = events.push(event);
    }

    /// §9.13.6.1's merge: a second `KeepActive` never shortens the first.
    ///
    /// > the StayActiveDuration is updated to the greater of the new value and the previously
    /// > stored value, and the TimeoutMs is updated to the greater of the new value and the
    /// > remaining time until the prior "pending active" state expires.
    ///
    /// Two controllers each asking for the device to stay awake must not end with it awake
    /// for the shorter of the two.
    fn keep_active(&self, stay_active_ms: u32, timeout_ms: u32, now: Instant) {
        let expires = now.saturating_add(Duration::from_millis(u64::from(timeout_ms)));
        let merged = match self.pending.get() {
            Some(prior) => PendingActive {
                stay_active_ms: prior.stay_active_ms.max(stay_active_ms),
                expires: if prior.expires > expires {
                    prior.expires
                } else {
                    expires
                },
            },
            None => PendingActive {
                stay_active_ms,
                expires,
            },
        };
        self.pending.set(Some(merged));
    }
}

impl ClusterHandler for BridgedDeviceBasicInformation<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let device = &self.device;
        // An attribute the bridge cannot fill is not served at all — §9.13's "SHOULD NOT
        // include the attribute" — so the descriptor leaves it out and a path naming it
        // resolves to UNSUPPORTED_ATTRIBUTE before ever reaching here. This arm is the second
        // half of the same fact, for a handler used without that descriptor.
        fn text(value: Option<&str>) -> Result<&str, Status> {
            value.ok_or(Status::UnsupportedAttribute)
        }
        match resolved.attribute {
            REACHABLE => full(w.bool(tag, self.reachable.get())),
            NODE_LABEL => full(w.utf8(tag, self.node_label.borrow().as_str())),
            VENDOR_NAME => full(w.utf8(tag, text(device.vendor_name)?)),
            VENDOR_ID => full(w.unsigned(
                tag,
                u64::from(device.vendor_id.ok_or(Status::UnsupportedAttribute)?.0),
            )),
            PRODUCT_NAME => full(w.utf8(tag, text(device.product_name)?)),
            spec_bridged::attribute::PRODUCT_ID => full(w.unsigned(
                tag,
                u64::from(device.product_id.ok_or(Status::UnsupportedAttribute)?),
            )),
            HARDWARE_VERSION => full(
                w.unsigned(
                    tag,
                    u64::from(
                        device
                            .hardware_version
                            .ok_or(Status::UnsupportedAttribute)?,
                    ),
                ),
            ),
            HARDWARE_VERSION_STRING => full(w.utf8(tag, text(device.hardware_version_string)?)),
            SOFTWARE_VERSION => full(
                w.unsigned(
                    tag,
                    u64::from(
                        device
                            .software_version
                            .ok_or(Status::UnsupportedAttribute)?,
                    ),
                ),
            ),
            SOFTWARE_VERSION_STRING => full(w.utf8(tag, text(device.software_version_string)?)),
            MANUFACTURING_DATE => full(w.utf8(tag, text(device.manufacturing_date)?)),
            PART_NUMBER => full(w.utf8(tag, text(device.part_number)?)),
            PRODUCT_URL => full(w.utf8(tag, text(device.product_url)?)),
            PRODUCT_LABEL => full(w.utf8(tag, text(device.product_label)?)),
            SERIAL_NUMBER => full(w.utf8(tag, text(device.serial_number)?)),
            UNIQUE_ID => full(w.utf8(tag, text(device.unique_id)?)),
            CONFIGURATION_VERSION => full(
                w.unsigned(
                    tag,
                    u64::from(
                        device
                            .configuration_version
                            .ok_or(Status::UnsupportedAttribute)?,
                    ),
                ),
            ),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        _op: crate::im::WriteOp,
        _ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        // §11.1.5.6's `NodeLabel` is the one writable attribute: the user's name for the
        // device, which belongs to whoever is looking at it rather than to the bridge.
        if resolved.attribute != NODE_LABEL {
            return Err(Status::UnsupportedWrite);
        }
        let mut reader = crate::tlv::TlvReader::new_in(data, crate::tlv::ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;
        let crate::tlv::Value::Utf8(text) = element.value else {
            return Err(Status::InvalidDataType);
        };
        let mut label = heapless::String::new();
        label.push_str(text).map_err(|_| Status::ConstraintError)?;
        *self.node_label.borrow_mut() = label;
        Ok(())
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        if resolved.command.id != KEEP_ACTIVE {
            return Err(Status::UnsupportedCommand.into());
        }
        let decoded: spec_bridged::KeepActiveFields =
            super::decode_fields(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
        self.keep_active(decoded.stay_active_duration, decoded.timeout_ms, ctx.now);
        // §9.13.6's table gives the command response "Y": a plain status. The work is
        // best-effort and asynchronous by nature — the device is asleep — so success here
        // means "recorded", and `ActiveChanged` is what says it actually happened.
        Ok(None)
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl Cluster for BridgedDeviceBasicInformation<'_> {
    const ID: ClusterId = ID;
}
