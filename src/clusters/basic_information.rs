//! Basic Information cluster `0x0028` (Core §11.1) — who this node is.
//!
//! > This cluster provides attributes and events for determining basic information about
//! > Nodes, which supports both Commissioning and operational determination of Node
//! > characteristics, such as Vendor ID, Product ID and serial number, which apply to the
//! > whole Node.
//!
//! It lives on endpoint 0 and there is exactly one per node.
//!
//! # Almost all of it is `F` — fixed, and therefore `const`
//!
//! Sixteen of the nineteen attributes carry the `F` quality: their values are decided when
//! the product is built and never change. So [`Product`] is a `const` record the application
//! points at, held in flash, and only the three mutable attributes — `NodeLabel`,
//! `Location`, `LocalConfigDisabled` — cost RAM.
//!
//! `Location` is the interesting one of the three. §11.10.7.4 says `SetRegulatoryConfig`'s
//! `CountryCode` "SHALL be used to set the Location attribute reflected by the Basic
//! Information Cluster" — so the General Commissioning cluster writes an attribute of *this*
//! one, which is why [`Location`] is a separate shareable cell rather than a field.
//!
//! # Revision 6
//!
//! | Revision | Change |
//! |---|---|
//! | 1 | Initial revision |
//! | 2 | Added `ProductAppearance` |
//! | 3 | Added `SpecificationVersion` and `MaxPathsPerInvoke` |
//! | 4 | `UniqueID` conformance became mandatory |
//! | 5 | Added `ConfigurationVersion` as provisional |
//! | 6 | Extended `CapabilityMinimaStruct`; `ConfigurationVersion` no longer provisional |

use core::cell::Cell;

use crate::dm::Resolved;
use crate::dm::access::{Access, Privilege};
use crate::dm::meta::{
    AttributeDescriptor, AttributeQualities, ClusterDescriptor, EventDescriptor, EventPriority,
};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, EventId, InteractionContext, Status, WriteOp,
};
use crate::msg::VendorId;
use crate::tlv::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

use super::Cluster;

/// `0x0028` (§11.1.3).
pub const ID: ClusterId = 0x0028;

/// The highest revision in §11.1.1's table.
pub const REVISION: u16 = 6;

/// `SpecificationVersion` (§11.1.5.22) for Matter 1.6.
///
/// "The format of this number is segmented as its four component bytes": major, minor, dot,
/// reserved. So 1.6.0.0 is `0x01_06_00_00` — and §11.1.5.22 is explicit that "Comparison of
/// SpecificationVersion SHALL always include the total value over 32 bits, without masking
/// reserved parts", which is why this is one constant and not four.
pub const SPECIFICATION_VERSION: u32 = 0x0106_0000;

#[doc(inline)]
pub use crate::DATA_MODEL_REVISION;

/// `DataModelRevision` — `uint16`, `F`, `RV`, mandatory.
pub const DATA_MODEL_REVISION_ID: AttributeId = 0x0000;
/// `VendorName` — `string` max 32, `F`, `RV`, mandatory.
pub const VENDOR_NAME: AttributeId = 0x0001;
/// `VendorID` — `vendor-id`, `F`, `RV`, mandatory.
pub const VENDOR_ID: AttributeId = 0x0002;
/// `ProductName` — `string` max 32, `F`, `RV`, mandatory.
pub const PRODUCT_NAME: AttributeId = 0x0003;
/// `ProductID` — `uint16`, `F`, `RV`, mandatory.
pub const PRODUCT_ID: AttributeId = 0x0004;
/// `NodeLabel` — `string` max 32, `N`, fallback `""`, `RW VM`, mandatory.
pub const NODE_LABEL: AttributeId = 0x0005;
/// `Location` — `string` exactly 2, `N`, fallback `"XX"`, `RW VA`, mandatory.
pub const LOCATION: AttributeId = 0x0006;
/// `HardwareVersion` — `uint16`, `F`, `RV`, mandatory.
pub const HARDWARE_VERSION: AttributeId = 0x0007;
/// `HardwareVersionString` — `string` 1 to 64, `F`, `RV`, mandatory.
pub const HARDWARE_VERSION_STRING: AttributeId = 0x0008;
/// `SoftwareVersion` — `uint32`, `F`, `RV`, mandatory.
pub const SOFTWARE_VERSION: AttributeId = 0x0009;
/// `SoftwareVersionString` — `string` 1 to 64, `F`, `RV`, mandatory.
pub const SOFTWARE_VERSION_STRING: AttributeId = 0x000A;
/// `ManufacturingDate` — `string` 8 to 16, `F`, `RV`, optional.
pub const MANUFACTURING_DATE: AttributeId = 0x000B;
/// `PartNumber` — `string` max 32, `F`, `RV`, optional.
pub const PART_NUMBER: AttributeId = 0x000C;
/// `ProductURL` — `string` max 256, `F`, `RV`, optional.
pub const PRODUCT_URL: AttributeId = 0x000D;
/// `ProductLabel` — `string` max 64, `F`, `RV`, optional.
pub const PRODUCT_LABEL: AttributeId = 0x000E;
/// `SerialNumber` — `string` max 32, `F`, `RV`, optional.
pub const SERIAL_NUMBER: AttributeId = 0x000F;
/// `LocalConfigDisabled` — `bool`, `N`, fallback false, `RW VM`, optional.
pub const LOCAL_CONFIG_DISABLED: AttributeId = 0x0010;
/// `Reachable` — `bool`, fallback true, `RV`, optional.
pub const REACHABLE: AttributeId = 0x0011;
/// `UniqueID` — `string` max 32, `F`, `RV`, mandatory from revision 4.
pub const UNIQUE_ID: AttributeId = 0x0012;
/// `CapabilityMinima` — `CapabilityMinimaStruct`, `F`, `RV`, mandatory.
pub const CAPABILITY_MINIMA: AttributeId = 0x0013;
/// `ProductAppearance` — `ProductAppearanceStruct`, `F`, `RV`, optional from revision 2.
pub const PRODUCT_APPEARANCE: AttributeId = 0x0014;
/// `SpecificationVersion` — `uint32`, `F`, `RV`, mandatory from revision 3.
pub const SPECIFICATION_VERSION_ID: AttributeId = 0x0015;
/// `MaxPathsPerInvoke` — `uint16` min 1, `F`, `RV`, mandatory from revision 3.
pub const MAX_PATHS_PER_INVOKE: AttributeId = 0x0016;
/// `ConfigurationVersion` — `uint32` min 1, `N`, fallback 1, `RV`, mandatory from revision 6.
pub const CONFIGURATION_VERSION: AttributeId = 0x0018;

/// `StartUp` (§11.1.6.1) — CRITICAL, `V`, mandatory.
pub const START_UP: EventId = 0x00;
/// `ShutDown` (§11.1.6.2) — CRITICAL, `V`, optional.
pub const SHUT_DOWN: EventId = 0x01;
/// `Leave` (§11.1.6.3) — INFO, `V`, optional.
pub const LEAVE: EventId = 0x02;
/// `ReachableChanged` (§11.1.6.4) — INFO, `V`, conformance `Reachable`.
pub const REACHABLE_CHANGED: EventId = 0x03;

/// `ProductFinishEnum` (§11.1.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum ProductFinish {
    /// Some other finish not listed.
    Other = 0,
    /// A matte finish.
    Matte = 1,
    /// A satin finish.
    Satin = 2,
    /// A polished or shiny finish.
    Polished = 3,
    /// A rugged finish.
    Rugged = 4,
    /// A fabric finish.
    Fabric = 5,
}

/// `ProductAppearanceStruct` (§11.1.4.3) — "a description of the product's appearance".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductAppearance {
    /// `Finish [0]` — "the visible finish of the product".
    pub finish: ProductFinish,
    /// `PrimaryColor [1]` — a `ColorEnum`, nullable: "If the product has no representative
    /// color, the field SHALL be null."
    pub primary_color: Option<u8>,
}

/// `CapabilityMinimaStruct` (§11.1.4.4) — "the minimum guaranteed value for some system-wide
/// resource capabilities".
///
/// The last four fields arrived in cluster revision 6, where §11.1.4.4 makes them **mandatory**.
/// They are `Option` so that a node declaring an older `ClusterRevision` can omit them — this
/// crate declares revision 6, so its own defaults fill them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityMinima {
    /// `CaseSessionsPerFabric [0]` — 3 to 10000, fallback 3. "SHALL NOT be smaller than the
    /// required minimum indicated in Section 4.14.2.8".
    pub case_sessions_per_fabric: u16,
    /// `SubscriptionsPerFabric [1]` — 3 to 10000, fallback 3.
    pub subscriptions_per_fabric: u16,
    /// `SimultaneousInvocationsSupported [2]` — 1 to 10000, revision 6.
    pub simultaneous_invocations: Option<u16>,
    /// `SimultaneousWritesSupported [3]` — 1 to 10000, revision 6.
    pub simultaneous_writes: Option<u16>,
    /// `ReadPathsSupported [4]` — 9 to 10000, revision 6. §2.11.2.1's read limit.
    pub read_paths: Option<u16>,
    /// `SubscribePathsSupported [5]` — 3 to 10000, revision 6. §2.11.2.2's subscribe limit.
    pub subscribe_paths: Option<u16>,
}

impl CapabilityMinima {
    /// The values a node actually guarantees, taken from the tables that will answer for them.
    ///
    /// §11.1.4.4 says each field "SHALL indicate the **actual**" number the node supports, so
    /// every one of them has exactly one honest source: the table. `S` is the session table and
    /// `B` the subscription table, both of which publish their real capacity through
    /// [`Capacity`](crate::config::Capacity); `read_paths` is
    /// [`Config::READ_PATHS`](crate::config::Config::READ_PATHS), the one figure here that is a
    /// promise about work rather than storage.
    ///
    /// ```
    /// # #[cfg(feature = "rustcrypto")] fn main() {
    /// use matter_kit::clusters::basic_information::CapabilityMinima;
    /// use matter_kit::{DefaultConfig, im::SubscriptionTable, session::SessionTable};
    ///
    /// type Sessions = SessionTable<DefaultConfig, 16>;
    /// type Subs = SubscriptionTable<DefaultConfig>;
    /// let minima = CapabilityMinima::from_tables::<DefaultConfig, Sessions, Subs>();
    /// assert_eq!(minima.case_sessions_per_fabric, 3); // 16 sessions over 5 fabrics
    /// # }
    /// # #[cfg(not(feature = "rustcrypto"))] fn main() {}
    /// ```
    ///
    /// There is deliberately no `from_config`. A `Config` cannot size a table, so a figure
    /// derived from one describes whatever the integrator wrote next to it — and this attribute
    /// is read during certification.
    ///
    /// `SimultaneousInvocationsSupported` and `SimultaneousWritesSupported` take the
    /// specification's floor of 1: this crate serves one interaction at a time per exchange,
    /// and §8.8.2.3's `MaxPathsPerInvoke` — a separate attribute — is what bounds the paths
    /// inside one of them.
    #[must_use]
    pub const fn from_tables<C, S, B>() -> Self
    where
        C: crate::config::Config,
        S: crate::config::Capacity,
        B: crate::config::SubscriptionCapacity,
    {
        Self {
            case_sessions_per_fabric: saturate(S::PER_FABRIC),
            subscriptions_per_fabric: saturate(B::PER_FABRIC),
            simultaneous_invocations: Some(1),
            simultaneous_writes: Some(1),
            read_paths: Some(saturate(C::READ_PATHS)),
            subscribe_paths: Some(saturate(B::PATHS)),
        }
    }
}

/// `usize` to `uint16`, clamped rather than wrapped.
///
/// §11.1.4.4 caps every field at 10000, and a node that somehow held more would otherwise
/// report the low sixteen bits of it — a smaller number than the truth, which is the one
/// direction this attribute must never be wrong in.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the branch above is the truncation check — §11.1.4.4 caps every field at 10000"
)]
const fn saturate(n: usize) -> u16 {
    if n > 10_000 { 10_000 } else { n as u16 }
}

impl Default for CapabilityMinima {
    /// §11.1.4.4's fallbacks and floors, every field present.
    ///
    /// Revision 6's four fields are *not* left absent, because this cluster declares revision
    /// 6 and §11.1.4.4 makes them mandatory there — a struct that omits them describes an
    /// older node than the one sending it, which `TC_IDM_2_3` checks directly.
    fn default() -> Self {
        Self {
            case_sessions_per_fabric: 3,
            subscriptions_per_fabric: 3,
            simultaneous_invocations: Some(1),
            simultaneous_writes: Some(1),
            read_paths: Some(9),
            subscribe_paths: Some(3),
        }
    }
}

/// The `F`-quality attributes — everything a product knows about itself at build time.
///
/// A `const` record in flash. Every field the specification marks optional is an `Option`,
/// and `None` means the attribute is not served, which is exactly what an absent optional
/// attribute must look like: `UNSUPPORTED_ATTRIBUTE`, and absent from `AttributeList`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Product<'a> {
    /// `VendorName` (§11.1.5.2).
    pub vendor_name: &'a str,
    /// `VendorID` (§11.1.5.3).
    pub vendor_id: VendorId,
    /// `ProductName` (§11.1.5.4).
    pub product_name: &'a str,
    /// `ProductID` (§11.1.5.5).
    pub product_id: u16,
    /// `HardwareVersion` (§11.1.5.8).
    pub hardware_version: u16,
    /// `HardwareVersionString` (§11.1.5.9), 1 to 64 characters.
    pub hardware_version_string: &'a str,
    /// `SoftwareVersion` (§11.1.5.10).
    pub software_version: u32,
    /// `SoftwareVersionString` (§11.1.5.11), 1 to 64 characters.
    pub software_version_string: &'a str,
    /// `UniqueID` (§11.1.5.19) — mandatory from revision 4. "It SHALL NOT be identical to the
    /// SerialNumber attribute" and "SHALL NOT be printed on the product".
    pub unique_id: &'a str,
    /// `CapabilityMinima` (§11.1.5.20).
    pub capability_minima: CapabilityMinima,
    /// `MaxPathsPerInvoke` (§11.1.5.23), min 1.
    pub max_paths_per_invoke: u16,
    /// `ManufacturingDate` (§11.1.5.12) — `YYYYMMDD` plus up to 8 vendor-defined characters.
    pub manufacturing_date: Option<&'a str>,
    /// `PartNumber` (§11.1.5.13).
    pub part_number: Option<&'a str>,
    /// `ProductURL` (§11.1.5.14) — "SHALL use the https scheme".
    pub product_url: Option<&'a str>,
    /// `ProductLabel` (§11.1.5.15).
    pub product_label: Option<&'a str>,
    /// `SerialNumber` (§11.1.5.16).
    pub serial_number: Option<&'a str>,
    /// `ProductAppearance` (§11.1.5.21).
    pub appearance: Option<ProductAppearance>,
    /// `ConfigurationVersion` (§11.1.5.24), min 1 — revision 6. `N`, but it changes only
    /// with the node's configuration, so it is given rather than written.
    pub configuration_version: u32,
}

impl<'a> Product<'a> {
    /// A product with only the mandatory fixed attributes.
    #[must_use]
    pub const fn new(
        vendor_name: &'a str,
        vendor_id: VendorId,
        product_name: &'a str,
        product_id: u16,
        unique_id: &'a str,
    ) -> Self {
        Self {
            vendor_name,
            vendor_id,
            product_name,
            product_id,
            hardware_version: 0,
            hardware_version_string: "0",
            software_version: 0,
            software_version_string: "0",
            unique_id,
            // §11.1.4.4's own fallbacks and floors, all *present*: this cluster declares
            // revision 6, and fields 2 to 5 are mandatory from revision 6, so leaving them
            // absent describes a node of an older revision than the one it claims. A device
            // with real numbers uses `CapabilityMinima::from_config`.
            capability_minima: CapabilityMinima {
                case_sessions_per_fabric: 3,
                subscriptions_per_fabric: 3,
                simultaneous_invocations: Some(1),
                simultaneous_writes: Some(1),
                read_paths: Some(9),
                subscribe_paths: Some(3),
            },
            max_paths_per_invoke: 1,
            manufacturing_date: None,
            part_number: None,
            product_url: None,
            product_label: None,
            serial_number: None,
            appearance: None,
            configuration_version: 1,
        }
    }

    /// The same product with hardware version information.
    #[must_use]
    pub const fn with_hardware(mut self, version: u16, string: &'a str) -> Self {
        self.hardware_version = version;
        self.hardware_version_string = string;
        self
    }

    /// The same product with software version information.
    #[must_use]
    pub const fn with_software(mut self, version: u32, string: &'a str) -> Self {
        self.software_version = version;
        self.software_version_string = string;
        self
    }

    /// The same product with a serial number.
    #[must_use]
    pub const fn with_serial_number(mut self, serial_number: &'a str) -> Self {
        self.serial_number = Some(serial_number);
        self
    }

    /// The same product with `CapabilityMinima`.
    #[must_use]
    pub const fn with_capability_minima(mut self, minima: CapabilityMinima) -> Self {
        self.capability_minima = minima;
        self
    }

    /// The same product with a `MaxPathsPerInvoke`.
    #[must_use]
    pub const fn with_max_paths_per_invoke(mut self, max: u16) -> Self {
        self.max_paths_per_invoke = max;
        self
    }
}

/// `Location` (§11.1.5.7) — the node's ISO 3166-1 alpha-2 region code.
///
/// A cell of its own rather than a field of [`BasicInformation`], because two clusters write
/// it: a client writing the attribute directly at Administer, and §11.10.7.4's
/// `SetRegulatoryConfig`, whose `CountryCode` "SHALL be used to set the Location attribute
/// reflected by the Basic Information Cluster". Sharing one cell is what keeps the two in
/// agreement.
///
/// "The special value XX SHALL indicate that region-agnostic mode is used", which is the
/// fallback, and "The Location's region code SHALL be interpreted in a case-insensitive
/// manner".
#[derive(Debug, Default)]
pub struct Location(Cell<[u8; 2]>);

impl Location {
    /// The region-agnostic fallback, `"XX"`.
    #[must_use]
    pub const fn region_agnostic() -> Self {
        Self(Cell::new(*b"XX"))
    }

    /// A location from a two-character region code.
    ///
    /// Returns `None` for anything that is not exactly two characters, which is §11.1.5's
    /// `constraint 2` — a longer or shorter write is `CONSTRAINT_ERROR`, not a truncation.
    #[must_use]
    pub fn new(code: &str) -> Option<Self> {
        let bytes = code.as_bytes();
        match bytes {
            [a, b] if a.is_ascii() && b.is_ascii() => Some(Self(Cell::new([*a, *b]))),
            _ => None,
        }
    }

    /// The current region code.
    #[must_use]
    pub fn get(&self) -> [u8; 2] {
        self.0.get()
    }

    /// Sets the region code, refusing anything that is not two ASCII characters.
    pub fn set(&self, code: &str) -> Result<(), Status> {
        match code.as_bytes() {
            [a, b] if a.is_ascii() && b.is_ascii() => {
                self.0.set([*a, *b]);
                Ok(())
            }
            _ => Err(Status::ConstraintError),
        }
    }

    fn as_str(&self) -> heapless::String<2> {
        let bytes = self.0.get();
        let mut out = heapless::String::new();
        // Both bytes were checked ASCII on the way in, so this cannot fail.
        for byte in bytes {
            let _ = out.push(byte as char);
        }
        out
    }
}

/// The Basic Information cluster on endpoint 0.
///
/// Holds the fixed [`Product`] record by reference and the three mutable attributes in cells,
/// so the whole cluster is `&self`-usable from the interaction model without a lock.
#[derive(Debug)]
pub struct BasicInformation<'a> {
    /// The `F`-quality attributes.
    pub product: &'a Product<'a>,
    /// `Location` (§11.1.5.7), shared with General Commissioning.
    pub location: &'a Location,
    node_label: core::cell::RefCell<heapless::String<32>>,
    local_config_disabled: Cell<Option<bool>>,
    reachable: Cell<Option<bool>>,
}

impl<'a> BasicInformation<'a> {
    /// The cluster over a product and a location.
    #[must_use]
    pub fn new(product: &'a Product<'a>, location: &'a Location) -> Self {
        Self {
            product,
            location,
            node_label: core::cell::RefCell::new(heapless::String::new()),
            local_config_disabled: Cell::new(None),
            reachable: Cell::new(None),
        }
    }

    /// Serves `LocalConfigDisabled` (§11.1.5.17), starting at `initial`.
    ///
    /// Absent by default: the attribute is optional, and a node that does not have an on-node
    /// user interface has nothing to disable.
    #[must_use]
    pub fn with_local_config_disabled(self, initial: bool) -> Self {
        self.local_config_disabled.set(Some(initial));
        self
    }

    /// Serves `Reachable` (§11.1.5.18), starting at `initial`.
    ///
    /// "For a native Node this is implicitly True (and its use is optional). Its main use case
    /// is in the derived Bridged Device Basic Information cluster."
    #[must_use]
    pub fn with_reachable(self, initial: bool) -> Self {
        self.reachable.set(Some(initial));
        self
    }

    /// `NodeLabel` (§11.1.5.6).
    #[must_use]
    pub fn node_label(&self) -> heapless::String<32> {
        self.node_label.borrow().clone()
    }

    /// Sets `NodeLabel`, refusing anything longer than the `max 32` constraint.
    pub fn set_node_label(&self, label: &str) -> Result<(), Status> {
        let mut next = heapless::String::new();
        next.push_str(label).map_err(|_| Status::ConstraintError)?;
        *self.node_label.borrow_mut() = next;
        Ok(())
    }

    /// `Reachable` (§11.1.5.18), if served.
    #[must_use]
    pub fn reachable(&self) -> Option<bool> {
        self.reachable.get()
    }

    /// Sets `Reachable`, and says whether it changed — which is the trigger for the
    /// `ReachableChanged` event (§11.1.6.4). Does nothing if the attribute is not served.
    pub fn set_reachable(&self, reachable: bool) -> bool {
        match self.reachable.get() {
            Some(current) if current == reachable => false,
            Some(_) => {
                self.reachable.set(Some(reachable));
                true
            }
            None => false,
        }
    }

    /// Whether this instance serves `LocalConfigDisabled` (§11.1.5.17).
    #[must_use]
    pub fn serves_local_config_disabled(&self) -> bool {
        self.local_config_disabled.get().is_some()
    }

    /// Whether this instance serves `Reachable` (§11.1.5.18).
    #[must_use]
    pub fn serves_reachable(&self) -> bool {
        self.reachable.get().is_some()
    }
}

// Descriptors for the attributes, in ascending id order — the order `ClusterDescriptor`
// binary-searches and `AttributeList` is emitted in.

const fn fixed(id: AttributeId) -> AttributeDescriptor {
    AttributeDescriptor::read_only(id).with_qualities(AttributeQualities::FIXED)
}

/// `NodeLabel` is `RW VM` — a user-visible name, so Manage rather than Administer.
const NODE_LABEL_DESC: AttributeDescriptor = AttributeDescriptor::read_write(NODE_LABEL)
    .with_access(Access::read_write_with(Privilege::View, Privilege::Manage))
    .with_qualities(AttributeQualities::NON_VOLATILE);

/// `Location` is `RW VA` — it can change radio behaviour, so only an Administrator.
const LOCATION_DESC: AttributeDescriptor = AttributeDescriptor::read_write(LOCATION)
    .with_access(Access::read_write_with(
        Privilege::View,
        Privilege::Administer,
    ))
    .with_qualities(AttributeQualities::NON_VOLATILE);

const LOCAL_CONFIG_DISABLED_DESC: AttributeDescriptor =
    AttributeDescriptor::read_write(LOCAL_CONFIG_DISABLED)
        .with_access(Access::read_write_with(Privilege::View, Privilege::Manage))
        .with_qualities(AttributeQualities::NON_VOLATILE);

/// `StartUp` is mandatory; `ShutDown` and `Leave` are optional but universally useful, and
/// §7.13's `EventList` has conformance `D` and is not served — so this list feeds access
/// checks rather than a wire response.
///
/// `ReachableChanged` is absent: its conformance is `Reachable`, so it belongs only to a node
/// that serves that attribute — a bridge, not a device describing itself.
const EVENTS: &[EventDescriptor] = &[
    EventDescriptor::new(START_UP).with_priority(EventPriority::Critical),
    EventDescriptor::new(SHUT_DOWN).with_priority(EventPriority::Critical),
    EventDescriptor::new(LEAVE),
];

/// Every attribute §11.1.5 defines, at revision 6.
pub const MAX_ATTRIBUTES: usize = 24;

/// The attribute list for one node, derived from its [`Product`].
///
/// §7.13.3's `AttributeList` is read by every commissioner, and an entry for an attribute
/// that answers `UNSUPPORTED_ATTRIBUTE` — or a served attribute missing from the list — is a
/// certification failure. So the list is *computed* from the same record the handler reads
/// out of, and the two cannot drift.
///
/// A fixed array, not a `Vec`: a node has one of these for its whole life, and
/// [`Attributes::cluster`] borrows from it.
#[derive(Debug, Clone, Copy)]
pub struct Attributes {
    entries: [AttributeDescriptor; MAX_ATTRIBUTES],
    len: usize,
}

impl Attributes {
    /// The attributes a node serving `product` has, in ascending id order.
    ///
    /// `local_config_disabled` and `reachable` are the two optional attributes that are not
    /// decided by [`Product`], because they are state rather than product data — see
    /// [`BasicInformation::with_local_config_disabled`] and
    /// [`BasicInformation::with_reachable`].
    #[must_use]
    pub fn new(product: &Product<'_>, local_config_disabled: bool, reachable: bool) -> Self {
        let mut this = Self {
            entries: [fixed(DATA_MODEL_REVISION_ID); MAX_ATTRIBUTES],
            len: 0,
        };
        // Ascending by id, which is what `ClusterDescriptor` binary-searches and what
        // `AttributeList` is emitted in.
        this.push(fixed(DATA_MODEL_REVISION_ID));
        this.push(fixed(VENDOR_NAME));
        this.push(fixed(VENDOR_ID));
        this.push(fixed(PRODUCT_NAME));
        this.push(fixed(PRODUCT_ID));
        this.push(NODE_LABEL_DESC);
        this.push(LOCATION_DESC);
        this.push(fixed(HARDWARE_VERSION));
        this.push(fixed(HARDWARE_VERSION_STRING));
        this.push(fixed(SOFTWARE_VERSION));
        this.push(fixed(SOFTWARE_VERSION_STRING));
        this.push_if(
            product.manufacturing_date.is_some(),
            fixed(MANUFACTURING_DATE),
        );
        this.push_if(product.part_number.is_some(), fixed(PART_NUMBER));
        this.push_if(product.product_url.is_some(), fixed(PRODUCT_URL));
        this.push_if(product.product_label.is_some(), fixed(PRODUCT_LABEL));
        this.push_if(product.serial_number.is_some(), fixed(SERIAL_NUMBER));
        this.push_if(local_config_disabled, LOCAL_CONFIG_DISABLED_DESC);
        this.push_if(reachable, AttributeDescriptor::read_only(REACHABLE));
        this.push(fixed(UNIQUE_ID));
        this.push(fixed(CAPABILITY_MINIMA));
        this.push_if(product.appearance.is_some(), fixed(PRODUCT_APPEARANCE));
        this.push(fixed(SPECIFICATION_VERSION_ID));
        this.push(fixed(MAX_PATHS_PER_INVOKE));
        this.push(
            AttributeDescriptor::read_only(CONFIGURATION_VERSION)
                .with_qualities(AttributeQualities::NON_VOLATILE),
        );
        this
    }

    /// The attributes this node serves.
    #[must_use]
    pub fn as_slice(&self) -> &[AttributeDescriptor] {
        self.entries.get(..self.len).unwrap_or(&[])
    }

    /// The cluster descriptor for a node serving these attributes.
    #[must_use]
    pub fn cluster(&self) -> ClusterDescriptor<'_> {
        ClusterDescriptor {
            id: ID,
            revision: REVISION,
            feature_map: 0,
            attributes: self.as_slice(),
            accepted_commands: &[],
            generated_commands: &[],
            events: EVENTS,
        }
    }

    fn push(&mut self, descriptor: AttributeDescriptor) {
        // `MAX_ATTRIBUTES` is the count of every attribute §11.1.5 defines, so the array
        // cannot overflow; a silent drop would still be safer than a panic on a device.
        if let Some(slot) = self.entries.get_mut(self.len) {
            *slot = descriptor;
            self.len = self.len.saturating_add(1);
        }
    }

    fn push_if(&mut self, condition: bool, descriptor: AttributeDescriptor) {
        if condition {
            self.push(descriptor);
        }
    }
}

impl ClusterHandler for BasicInformation<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let product = self.product;
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            DATA_MODEL_REVISION_ID => full(w.unsigned(tag, u64::from(DATA_MODEL_REVISION))),
            VENDOR_NAME => full(w.utf8(tag, product.vendor_name)),
            VENDOR_ID => full(w.unsigned(tag, u64::from(product.vendor_id.0))),
            PRODUCT_NAME => full(w.utf8(tag, product.product_name)),
            PRODUCT_ID => full(w.unsigned(tag, u64::from(product.product_id))),
            NODE_LABEL => full(w.utf8(tag, self.node_label().as_str())),
            LOCATION => full(w.utf8(tag, self.location.as_str().as_str())),
            HARDWARE_VERSION => full(w.unsigned(tag, u64::from(product.hardware_version))),
            HARDWARE_VERSION_STRING => full(w.utf8(tag, product.hardware_version_string)),
            SOFTWARE_VERSION => full(w.unsigned(tag, u64::from(product.software_version))),
            SOFTWARE_VERSION_STRING => full(w.utf8(tag, product.software_version_string)),
            MANUFACTURING_DATE => optional_string(w, tag, product.manufacturing_date),
            PART_NUMBER => optional_string(w, tag, product.part_number),
            PRODUCT_URL => optional_string(w, tag, product.product_url),
            PRODUCT_LABEL => optional_string(w, tag, product.product_label),
            SERIAL_NUMBER => optional_string(w, tag, product.serial_number),
            LOCAL_CONFIG_DISABLED => {
                let value = self
                    .local_config_disabled
                    .get()
                    .ok_or(Status::UnsupportedAttribute)?;
                full(w.bool(tag, value))
            }
            REACHABLE => {
                let value = self.reachable.get().ok_or(Status::UnsupportedAttribute)?;
                full(w.bool(tag, value))
            }
            UNIQUE_ID => full(w.utf8(tag, product.unique_id)),
            CAPABILITY_MINIMA => write_capability_minima(w, tag, &product.capability_minima),
            PRODUCT_APPEARANCE => {
                let appearance = product.appearance.ok_or(Status::UnsupportedAttribute)?;
                full(w.start_structure(tag))?;
                full(w.unsigned(Tag::Context(0), appearance.finish as u64))?;
                match appearance.primary_color {
                    Some(color) => full(w.unsigned(Tag::Context(1), u64::from(color)))?,
                    None => full(w.null(Tag::Context(1)))?,
                }
                full(w.end_container())
            }
            SPECIFICATION_VERSION_ID => full(w.unsigned(tag, u64::from(SPECIFICATION_VERSION))),
            MAX_PATHS_PER_INVOKE => full(w.unsigned(tag, u64::from(product.max_paths_per_invoke))),
            CONFIGURATION_VERSION => {
                full(w.unsigned(tag, u64::from(product.configuration_version)))
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
        // The server has already checked access and the Timed quality; what is left is the
        // cluster's own constraints, which §8.7.3.3 makes `CONSTRAINT_ERROR`.
        match resolved.attribute {
            NODE_LABEL => self.set_node_label(read_utf8(data)?),
            LOCATION => self.location.set(read_utf8(data)?),
            LOCAL_CONFIG_DISABLED => {
                if self.local_config_disabled.get().is_none() {
                    return Err(Status::UnsupportedAttribute);
                }
                self.local_config_disabled.set(Some(read_bool(data)?));
                Ok(())
            }
            _ => Err(Status::UnsupportedWrite),
        }
    }
}

fn optional_string(w: &mut TlvWriter<'_>, tag: Tag, value: Option<&str>) -> Result<(), Status> {
    let value = value.ok_or(Status::UnsupportedAttribute)?;
    w.utf8(tag, value).map_err(|_| Status::ResourceExhausted)
}

fn write_capability_minima(
    w: &mut TlvWriter<'_>,
    tag: Tag,
    minima: &CapabilityMinima,
) -> Result<(), Status> {
    let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
    full(w.start_structure(tag))?;
    full(w.unsigned(Tag::Context(0), u64::from(minima.case_sessions_per_fabric)))?;
    full(w.unsigned(Tag::Context(1), u64::from(minima.subscriptions_per_fabric)))?;
    // Revision 6's four fields, each written only when present — an absent optional field
    // is absent from the structure, not null.
    for (field, value) in [
        (2, minima.simultaneous_invocations),
        (3, minima.simultaneous_writes),
        (4, minima.read_paths),
        (5, minima.subscribe_paths),
    ] {
        if let Some(value) = value {
            full(w.unsigned(Tag::Context(field), u64::from(value)))?;
        }
    }
    full(w.end_container())
}

/// Decodes one TLV UTF-8 string element — what §10.6.4.3 hands a cluster as `Data`.
///
/// `Data` is the `AttributeDataIB`'s context-2 member, so it arrives *tagged*: it is a
/// fragment of a structure, not a TLV document, and reading it as one would reject exactly
/// the bytes that are correct.
fn read_utf8(data: &[u8]) -> Result<&str, Status> {
    let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
    match reader.next_element() {
        Ok(Some(Element {
            value: Value::Utf8(text),
            ..
        })) => Ok(text),
        Ok(Some(_)) => Err(Status::InvalidDataType),
        _ => Err(Status::InvalidDataType),
    }
}

fn read_bool(data: &[u8]) -> Result<bool, Status> {
    let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
    match reader.next_element() {
        Ok(Some(Element {
            value: Value::Bool(value),
            ..
        })) => Ok(value),
        Ok(Some(_)) => Err(Status::InvalidDataType),
        _ => Err(Status::InvalidDataType),
    }
}

impl Cluster for BasicInformation<'_> {
    const ID: ClusterId = ID;
}
