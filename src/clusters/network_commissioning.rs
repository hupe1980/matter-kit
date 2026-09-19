//! Network Commissioning cluster `0x0031` (Core §11.9) — putting a device on a network.
//!
//! > The main goal of Network Commissioning Cluster is to associate a Node with or manage a
//! > Node's one or more network interfaces.
//!
//! One instance per interface: "An instance of the Network Commissioning Cluster only applies
//! to a single network interface instance present." A device with Wi-Fi and Ethernet has two,
//! on different endpoints, each with its own `Networks` list and its own feature bit.
//!
//! # Three clusters wearing one id
//!
//! §11.9.4's `WI`, `TH` and `ET` have conformance `O.a` — exactly one. What that bit selects
//! is not a detail: an Ethernet instance has **no commands at all** and its `Networks` list is
//! "automatically populated by the cluster server", while a Wi-Fi instance has seven commands
//! and a radio behind them. [`ethernet`] and [`wifi`]/[`thread`] therefore build different
//! descriptors, and [`NetworkCommissioning::new`] refuses a driver whose kind disagrees with
//! the descriptor it was given.
//!
//! # What the credentials never touch
//!
//! §11.9.7.3: "The Credentials associated with the network are not readable after execution of
//! this command, as they do not appear in the Networks attribute, for security reasons." So
//! `AddOrUpdateWiFiNetwork` hands them straight to the [`NetworkDriver`] and this module never
//! stores them. A `Networks` entry is an id and a boolean, and that is all it can ever be.
//!
//! # The list is ordered, and the order is the point
//!
//! §11.9.6.2: "The order of configurations in the list reflects precedence … the list SHALL be
//! stable over time." `ReorderNetwork` is the only command that permutes it, and §11.9.7.10
//! publishes two worked examples of what it must produce — both are tests.
//!
//! # Everything here is inside the fail-safe
//!
//! Every command requires an armed fail-safe, and §11.10.7.2.2 step 5 is "Reset the
//! configuration of all Network Commissioning Networks attribute to their state prior to the
//! Fail-Safe being armed". [`NetworkStore::snapshot`] and [`NetworkStore::restore`] are that
//! step — without them a commissioner that half-configured a network and walked away would
//! leave the device pointed at an access point it cannot reach.
//!
//! # Revision 2
//!
//! | Revision | Change |
//! |---|---|
//! | 1 | Initial revision |
//! | 2 | Wi-Fi and Thread capability attributes; directed Wi-Fi scanning |

use core::cell::{Cell, RefCell};

use heapless::Vec;

use crate::dm::access::{Access, Privilege};
use crate::dm::meta::{
    AttributeDescriptor, AttributeQualities, ClusterDescriptor, CommandDescriptor,
};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb,
    WriteOp,
};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, set_once};

use super::Cluster;

/// `0x0031` (§11.9.3).
pub const ID: ClusterId = 0x0031;

/// The highest revision in §11.9.1's table.
pub const REVISION: u16 = 2;

/// `WI` (§11.9.4, bit 0) — Wi-Fi related features.
pub const FEATURE_WIFI: u32 = 1 << 0;
/// `TH` (§11.9.4, bit 1) — Thread related features.
pub const FEATURE_THREAD: u32 = 1 << 1;
/// `ET` (§11.9.4, bit 2) — Ethernet related features.
pub const FEATURE_ETHERNET: u32 = 1 << 2;

/// `MaxNetworks` (§11.9.6.1) — `uint8` min 1, `F`, `RA`, mandatory.
pub const MAX_NETWORKS: AttributeId = 0x0000;
/// `Networks` (§11.9.6.2) — `list[NetworkInfoStruct]`, `RA`, mandatory.
pub const NETWORKS: AttributeId = 0x0001;
/// `ScanMaxTimeSeconds` (§11.9.6.3) — `uint8`, `F`, `RV`, `WI | TH`.
pub const SCAN_MAX_TIME_SECONDS: AttributeId = 0x0002;
/// `ConnectMaxTimeSeconds` (§11.9.6.4) — `uint8`, `F`, `RV`, `WI | TH`.
pub const CONNECT_MAX_TIME_SECONDS: AttributeId = 0x0003;
/// `InterfaceEnabled` (§11.9.6.5) — `bool`, `N`, fallback true, `RW VA`, mandatory.
pub const INTERFACE_ENABLED: AttributeId = 0x0004;
/// `LastNetworkingStatus` (§11.9.6.6) — nullable, `RA`, mandatory.
pub const LAST_NETWORKING_STATUS: AttributeId = 0x0005;
/// `LastNetworkID` (§11.9.6.7) — `octstr` 1 to 32, nullable, `RA`, mandatory.
pub const LAST_NETWORK_ID: AttributeId = 0x0006;
/// `LastConnectErrorValue` (§11.9.6.8) — `int32`, nullable, `RA`, mandatory.
pub const LAST_CONNECT_ERROR_VALUE: AttributeId = 0x0007;
/// `SupportedWiFiBands` (§11.9.6.9) — `list[WiFiBandEnum]` min 1, `F`, `RV`, `WI`.
pub const SUPPORTED_WIFI_BANDS: AttributeId = 0x0008;
/// `SupportedThreadFeatures` (§11.9.6.10) — `ThreadCapabilitiesBitmap`, `F`, `RV`, `TH`.
pub const SUPPORTED_THREAD_FEATURES: AttributeId = 0x0009;
/// `ThreadVersion` (§11.9.6.11) — `uint16`, `F`, `RV`, `TH`.
pub const THREAD_VERSION: AttributeId = 0x000A;

/// `ScanNetworks` (§11.9.7.1) — access `A`, `WI | TH`.
pub const SCAN_NETWORKS: CommandId = 0x00;
/// `ScanNetworksResponse` (§11.9.7.2).
pub const SCAN_NETWORKS_RESPONSE: CommandId = 0x01;
/// `AddOrUpdateWiFiNetwork` (§11.9.7.3) — access `A`, `WI`.
pub const ADD_OR_UPDATE_WIFI_NETWORK: CommandId = 0x02;
/// `AddOrUpdateThreadNetwork` (§11.9.7.4) — access `A`, `TH`.
pub const ADD_OR_UPDATE_THREAD_NETWORK: CommandId = 0x03;
/// `RemoveNetwork` (§11.9.7.6) — access `A`, `WI | TH`.
pub const REMOVE_NETWORK: CommandId = 0x04;
/// `NetworkConfigResponse` (§11.9.7.7).
pub const NETWORK_CONFIG_RESPONSE: CommandId = 0x05;
/// `ConnectNetwork` (§11.9.7.8) — access `A`, `WI | TH`.
pub const CONNECT_NETWORK: CommandId = 0x06;
/// `ConnectNetworkResponse` (§11.9.7.9).
pub const CONNECT_NETWORK_RESPONSE: CommandId = 0x07;
/// `ReorderNetwork` (§11.9.7.10) — access `A`, `WI | TH`.
pub const REORDER_NETWORK: CommandId = 0x08;

/// The longest `NetworkID` — §11.9.5.5's `1 to 32`.
///
/// "Every network is uniquely identified (for purposes of commissioning) by a NetworkID
/// mapping to … SSID for Wi-Fi, Extended PAN ID for Thread, Network interface instance name
/// at operating system … for Ethernet." So it is an *octet string*, not a name: §11.9.5.5
/// warns that an SSID's "text encoding … is not specified" and that implementations "must be
/// careful to support reporting byte strings without requiring a particular encoding".
pub const NETWORK_ID_MAX: usize = 32;

/// The longest Wi-Fi `Credentials` — §11.9.7.3's `max 64`, a WPA raw hex PSK.
pub const CREDENTIALS_MAX: usize = 64;

/// The longest Thread `OperationalDataset` — §11.9.7.4's `max 254`.
pub const OPERATIONAL_DATASET_MAX: usize = 254;

/// `NetworkCommissioningStatusEnum` (§11.9.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum NetworkStatus {
    /// `0` — OK, no error.
    Success = 0,
    /// `1` — value outside range.
    OutOfRange = 1,
    /// `2` — "A collection would exceed its size limit".
    BoundsExceeded = 2,
    /// `3` — "The NetworkID is not among the collection of added networks".
    NetworkIdNotFound = 3,
    /// `4` — "The NetworkID is already among the collection of added networks".
    DuplicateNetworkId = 4,
    /// `5` — "Cannot find AP: SSID Not found".
    NetworkNotFound = 5,
    /// `6` — "Cannot find AP: Mismatch on band/channels/regulatory domain / 2.4GHz vs 5GHz".
    RegulatoryError = 6,
    /// `7` — "Cannot associate due to authentication failure".
    AuthFailure = 7,
    /// `8` — "Cannot associate due to unsupported security mode".
    UnsupportedSecurity = 8,
    /// `9` — "Other association failure".
    OtherConnectionFailure = 9,
    /// `10` — "Failure to generate an IPv6 address".
    Ipv6Failed = 10,
    /// `11` — "Failure to bind Wi-Fi <-> IP interfaces".
    IpBindFailed = 11,
    /// `12` — unknown error.
    UnknownError = 12,
}

impl NetworkStatus {
    /// The value the enum encodes as.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Whether this is [`NetworkStatus::Success`].
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Which technology one cluster instance manages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkKind {
    /// `WI` — IEEE 802.11.
    WiFi,
    /// `TH` — IEEE 802.15.4 / Thread.
    Thread,
    /// `ET` — IEEE 802.3. No commands at all.
    Ethernet,
}

impl NetworkKind {
    /// The feature bit this kind sets in the `FeatureMap`.
    #[must_use]
    pub const fn feature(self) -> u32 {
        match self {
            Self::WiFi => FEATURE_WIFI,
            Self::Thread => FEATURE_THREAD,
            Self::Ethernet => FEATURE_ETHERNET,
        }
    }
}

/// `WiFiBandEnum` (§11.9.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum WiFiBand {
    /// `0` — 2.4GHz, 802.11b/g/n/ax.
    Band2G4 = 0,
    /// `1` — 3.65GHz, 802.11y.
    Band3G65 = 1,
    /// `2` — 5GHz, 802.11a/n/ac/ax.
    Band5G = 2,
    /// `3` — 6GHz, 802.11ax / Wi-Fi 6E.
    Band6G = 3,
    /// `4` — 60GHz, 802.11ad/ay.
    Band60G = 4,
    /// `5` — sub-1GHz, 802.11ah.
    Band1G = 5,
}

impl WiFiBand {
    /// The value the enum encodes as.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}

bitflags::bitflags! {
    /// `WiFiSecurityBitmap` (§11.9.5.1) — "the supported Wi-Fi security types present in the
    /// Security field of the WiFiInterfaceScanResultStruct".
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct WiFiSecurity: u8 {
        /// Bit 0 — unencrypted.
        const UNENCRYPTED = 1 << 0;
        /// Bit 1 — WEP.
        const WEP = 1 << 1;
        /// Bit 2 — WPA-Personal.
        const WPA_PERSONAL = 1 << 2;
        /// Bit 3 — WPA2-Personal.
        const WPA2_PERSONAL = 1 << 3;
        /// Bit 4 — WPA3-Personal.
        const WPA3_PERSONAL = 1 << 4;
    }

    /// `ThreadCapabilitiesBitmap` (§11.9.5.2).
    ///
    /// "The valid combinations of capabilities are restricted and dependent on Thread
    /// version", so nothing here validates a combination — the Thread stack is the authority.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ThreadCapabilities: u16 {
        /// Bit 0 — Thread Border Router functionality is present.
        const IS_BORDER_ROUTER_CAPABLE = 1 << 0;
        /// Bit 1 — router or REED mode is supported.
        const IS_ROUTER_CAPABLE = 1 << 1;
        /// Bit 2 — sleepy end-device mode is supported.
        const IS_SLEEPY_END_DEVICE_CAPABLE = 1 << 2;
        /// Bit 3 — a full Thread device, as opposed to a Minimal Thread Device.
        const IS_FULL_THREAD_DEVICE = 1 << 3;
        /// Bit 4 — synchronized sleepy end-device mode is supported.
        const IS_SYNCHRONIZED_SLEEPY_END_DEVICE_CAPABLE = 1 << 4;
    }
}

// --- The network store -------------------------------------------------------------------------

/// One entry of the `Networks` attribute (§11.9.5.5's `NetworkInfoStruct`).
///
/// Two fields, and deliberately no third: §11.9.7.3 keeps credentials out of this list "for
/// security reasons", so there is nowhere for them to leak to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    /// `NetworkID [0]` — 1 to 32 octets. An SSID, an Extended PAN ID, or an interface name.
    pub id: Vec<u8, NETWORK_ID_MAX>,
    /// `Connected [1]` — "currently linked to the network technology (e.g. Associated for a
    /// Wi-Fi network, media connected for an Ethernet network)".
    pub connected: bool,
}

impl NetworkInfo {
    /// An entry for `id`, not connected.
    ///
    /// Returns [`NetworkStatus::OutOfRange`] for an id outside §11.9.5.5's `1 to 32` — which
    /// is what §11.9.7.7 calls "Network identifier was invalid (e.g. empty, too long, etc)".
    pub fn new(id: &[u8]) -> Result<Self, NetworkStatus> {
        Ok(Self {
            id: copy_id(id)?,
            connected: false,
        })
    }
}

fn copy_id(id: &[u8]) -> Result<Vec<u8, NETWORK_ID_MAX>, NetworkStatus> {
    if id.is_empty() || id.len() > NETWORK_ID_MAX {
        return Err(NetworkStatus::OutOfRange);
    }
    Vec::from_slice(id).map_err(|_| NetworkStatus::OutOfRange)
}

/// The `Networks` attribute: an ordered, fixed-capacity list where **position is precedence**.
///
/// §11.9.6.2: "The order of configurations in the list reflects precedence. That is, any time
/// the Node attempts to connect to the network it SHALL attempt to do so using the
/// configurations in Networks Attribute in the order as they appear in the list. The order of
/// list items SHALL only be modified by the AddOrUpdateThreadNetwork, AddOrUpdateWiFiNetwork
/// and ReorderNetwork commands."
///
/// So this is a `Vec`, not a map: every operation states exactly what it does to the order,
/// and an implementation that sorted or re-hashed would silently change which access point a
/// device prefers.
///
/// `N` is `MaxNetworks` (§11.9.6.1), "the maximum number of network configuration entries that
/// can be added, based on available device resources".
#[derive(Debug, Clone)]
pub struct NetworkStore<const N: usize> {
    networks: Vec<NetworkInfo, N>,
    /// The list as it was when the fail-safe was armed — §11.10.7.2.2 step 5's "state prior to
    /// the Fail-Safe being armed".
    saved: Option<Vec<NetworkInfo, N>>,
}

impl<const N: usize> Default for NetworkStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> NetworkStore<N> {
    /// An empty store — what a factory-fresh Wi-Fi or Thread interface has.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            networks: Vec::new(),
            saved: None,
        }
    }

    /// `MaxNetworks` (§11.9.6.1).
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The entries, in precedence order.
    #[must_use]
    pub fn entries(&self) -> &[NetworkInfo] {
        &self.networks
    }

    /// The position of `id`, if it is configured.
    #[must_use]
    pub fn position(&self, id: &[u8]) -> Option<usize> {
        self.networks.iter().position(|n| n.id.as_slice() == id)
    }

    /// `AddOrUpdateWiFiNetwork` / `AddOrUpdateThreadNetwork`, as §11.9.7.5 defines them.
    ///
    /// > If validation of all parameters has succeeded, this command SHALL append the
    /// > configuration at the end of the existing list in the Networks attribute, making this
    /// > new network the one with least priority.
    ///
    /// and, for an update:
    ///
    /// > this command SHALL update the existing entry indexed by NetworkID in the Networks
    /// > attribute, **keeping existing position within the list**.
    ///
    /// Returns the 0-based index for the `NetworkConfigResponse`.
    pub fn add_or_update(&mut self, id: &[u8]) -> Result<u8, NetworkStatus> {
        let id = copy_id(id)?;
        if let Some(index) = self.position(&id) {
            // An update keeps its place: re-sorting here would silently change which network
            // the device prefers, which is the one thing §11.9.6.2 asks not to happen.
            return index_of(index);
        }
        // "If the Networks attribute is already full, the command SHALL immediately respond
        // with NetworkConfigResponse having NetworkingStatus status field set to
        // BoundsExceeded."
        if self.networks.len() >= N {
            return Err(NetworkStatus::BoundsExceeded);
        }
        self.networks
            .push(NetworkInfo {
                id,
                connected: false,
            })
            .map_err(|_| NetworkStatus::BoundsExceeded)?;
        index_of(self.networks.len().saturating_sub(1))
    }

    /// `RemoveNetwork` (§11.9.7.6).
    ///
    /// > The relative order of the entries in the Networks attribute SHALL remain unchanged,
    /// > except for the removal of the requested network configuration.
    ///
    /// Returns the index the entry *had*, which is what the response reports.
    pub fn remove(&mut self, id: &[u8]) -> Result<u8, NetworkStatus> {
        let index = self.position(id).ok_or(NetworkStatus::NetworkIdNotFound)?;
        // `remove` shifts the tail down, preserving relative order — `swap_remove` would not.
        self.networks.remove(index);
        index_of(index)
    }

    /// `ReorderNetwork` (§11.9.7.10).
    ///
    /// > The entry selected SHALL be inserted at the new position in the list. All other
    /// > entries, if any exist, SHALL be moved to allow the insertion, in a way that they all
    /// > retain their existing relative order between each other, with the exception of the
    /// > newly re-ordered entry.
    ///
    /// A remove-then-insert, which is exactly that sentence: everything between the old and
    /// new position shifts by one and nothing else changes. Re-ordering to the position an
    /// entry already holds "SHALL be considered as a success and yield no visible changes".
    pub fn reorder(&mut self, id: &[u8], to: u8) -> Result<u8, NetworkStatus> {
        let from = self.position(id).ok_or(NetworkStatus::NetworkIdNotFound)?;
        let to_index = usize::from(to);
        // "If the NetworkIndex field has a value larger or equal to the current number of
        // entries in the Networks attribute … OutOfRange."
        if to_index >= self.networks.len() {
            return Err(NetworkStatus::OutOfRange);
        }
        if from == to_index {
            return Ok(to);
        }
        let entry = self.networks.remove(from);
        self.networks
            .insert(to_index, entry)
            .map_err(|_| NetworkStatus::UnknownError)?;
        Ok(to)
    }

    /// Marks `id` connected and every other entry disconnected (§11.9.7.8).
    ///
    /// > On successful connection, the entry associated with the given Network configuration
    /// > in the Networks attribute SHALL indicate its Connected field set to true, and **all
    /// > other entries, if any exist, SHALL indicate their Connected field set to false**.
    pub fn set_connected(&mut self, id: &[u8]) -> Result<(), NetworkStatus> {
        if self.position(id).is_none() {
            return Err(NetworkStatus::NetworkIdNotFound);
        }
        for entry in &mut self.networks {
            entry.connected = entry.id.as_slice() == id;
        }
        Ok(())
    }

    /// Marks every entry disconnected — what a failed `ConnectNetwork` leaves behind.
    pub fn set_all_disconnected(&mut self) {
        for entry in &mut self.networks {
            entry.connected = false;
        }
    }

    /// Records the list as it stands, for §11.10.7.2.2 step 5.
    ///
    /// Called when the fail-safe is armed. Idempotent within one period: a second `ArmFailSafe`
    /// re-arms the *same* context, so the state to revert to is still the one from before the
    /// first.
    pub fn snapshot(&mut self) {
        if self.saved.is_none() {
            self.saved = Some(self.networks.clone());
        }
    }

    /// Reverts to the snapshot — §11.10.7.2.2 step 5, "Reset the configuration of all Network
    /// Commissioning Networks attribute to their state prior to the Fail-Safe being armed".
    ///
    /// Without this, a commissioner that half-configured a network and walked away leaves the
    /// device pointed at an access point it cannot reach, with no way back.
    pub fn restore(&mut self) {
        if let Some(saved) = self.saved.take() {
            self.networks = saved;
        }
    }

    /// Drops the snapshot, keeping the current list — what `CommissioningComplete` does.
    pub fn commit(&mut self) {
        self.saved = None;
    }

    /// Seeds the list with an entry that cannot be added or removed.
    ///
    /// §11.9.6.2: "Ethernet networks SHALL be automatically populated by the cluster server.
    /// Ethernet Network Commissioning Cluster instances SHALL always have exactly one
    /// NetworkInfoStruct instance in their Networks attribute. There SHALL be no way to add,
    /// update or remove Ethernet network configurations to those Cluster instances." The
    /// id is "Network interface instance name at operating system (or equivalent unique
    /// name)".
    pub fn seed(&mut self, id: &[u8], connected: bool) -> Result<(), NetworkStatus> {
        let id = copy_id(id)?;
        self.networks.clear();
        self.networks
            .push(NetworkInfo { id, connected })
            .map_err(|_| NetworkStatus::BoundsExceeded)
    }
}

fn index_of(index: usize) -> Result<u8, NetworkStatus> {
    u8::try_from(index).map_err(|_| NetworkStatus::OutOfRange)
}

/// The Extended PAN ID from a Thread Active Operational Dataset.
///
/// §11.9.7.4: "The XPAN ID in the OperationalDataset serves as the NetworkID for the network
/// configuration to be added or updated", and §11.9.5.5: "XPAN ID is a big-endian 64-bit
/// unsigned number, represented on the first 8 octets of the octet string."
///
/// The dataset is Thread's own TLV encoding — type, length, value, with a length of `0xFF`
/// introducing a 16-bit extended length. Type 2 is the Extended PAN ID and is always 8 octets.
/// Everything else is skipped without interpretation: the client "SHALL pass the
/// OperationalDataset as an opaque octet string", and this reads exactly the one field Matter
/// needs from it.
///
/// Returns `None` for a dataset that is malformed, truncated, or carries no Extended PAN ID —
/// all of which §11.9.7.5 makes "a value different than Success and consistent with the
/// error".
#[must_use]
pub fn thread_extended_pan_id(dataset: &[u8]) -> Option<[u8; 8]> {
    /// Thread's `Extended PAN ID` TLV type.
    const EXTENDED_PAN_ID: u8 = 2;
    /// A length of `0xFF` means the real length follows as a big-endian `u16`.
    const EXTENDED_LENGTH: u8 = 0xFF;

    let mut at = 0usize;
    loop {
        let kind = *dataset.get(at)?;
        let short = *dataset.get(at.checked_add(1)?)?;
        let (header, len) = if short == EXTENDED_LENGTH {
            let hi = u16::from(*dataset.get(at.checked_add(2)?)?);
            let lo = u16::from(*dataset.get(at.checked_add(3)?)?);
            (4usize, usize::from((hi << 8) | lo))
        } else {
            (2usize, usize::from(short))
        };
        let start = at.checked_add(header)?;
        let end = start.checked_add(len)?;
        let value = dataset.get(start..end)?;
        if kind == EXTENDED_PAN_ID {
            let bytes: [u8; 8] = value.try_into().ok()?;
            return Some(bytes);
        }
        at = end;
        if at >= dataset.len() {
            return None;
        }
    }
}

// --- The driver --------------------------------------------------------------------------------

/// One Wi-Fi scan result (§11.9.5.6's `WiFiInterfaceScanResultStruct`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WiFiScanResult<'a> {
    /// `Security [0]`.
    pub security: WiFiSecurity,
    /// `SSID [1]` — max 32 octets, of unspecified encoding.
    pub ssid: &'a [u8],
    /// `BSSID [2]` — exactly 6 octets.
    pub bssid: [u8; 6],
    /// `Channel [3]`.
    pub channel: u16,
    /// `WiFiBand [4]`, optional — "MAY be used to differentiate overlapping channel number
    /// values across different Wi-Fi frequency bands".
    pub band: Option<WiFiBand>,
    /// `RSSI [5]`, optional — "the signal strength in dBm of the associated scan result".
    pub rssi: Option<i8>,
}

/// One Thread scan result (§11.9.5.7's `ThreadInterfaceScanResultStruct`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadScanResult<'a> {
    /// `PanId [0]` — max 65534.
    pub pan_id: u16,
    /// `ExtendedPanId [1]`.
    pub extended_pan_id: u64,
    /// `NetworkName [2]` — 1 to 16 characters.
    pub network_name: &'a str,
    /// `Channel [3]`.
    pub channel: u16,
    /// `Version [4]`.
    pub version: u8,
    /// `ExtendedAddress [5]` — an IEEE 802.15.4 Extended Address.
    pub extended_address: [u8; 8],
    /// `RSSI [6]`.
    pub rssi: i8,
    /// `LQI [7]`.
    pub lqi: u8,
}

/// Where a [`NetworkDriver`] puts what it found.
///
/// A typed sink rather than a raw [`TlvWriter`], so the encoding stays in this module and a
/// driver cannot emit a structure the specification does not define. §11.9.7.2 asks for a
/// particular order — "Results SHOULD be reported in decreasing RSSI order … to maximize the
/// likelihood that most likely to be reachable elements are included within the size limits of
/// the response" — which is the driver's to honour, since only it knows the signal strengths.
pub struct ScanResults<'w, 'b> {
    w: &'w mut TlvWriter<'b>,
    count: usize,
    full: bool,
}

/// Enough for one scan result of either kind: a Wi-Fi struct is about 60 octets with a
/// 32-octet SSID, a Thread one about the same with a 16-character network name.
const ONE_RESULT_BYTES: usize = 128;

impl ScanResults<'_, '_> {
    /// Appends a Wi-Fi result.
    ///
    /// Returns [`NetworkStatus::BoundsExceeded`] once the response buffer is full, which is
    /// not a failure: §11.9.7.2 says the list "MAY contain a subset of possibilities, to avoid
    /// memory exhaustion on the cluster server and avoid crossing the maximum command response
    /// size supported".
    pub fn wifi(&mut self, result: &WiFiScanResult<'_>) -> Result<(), NetworkStatus> {
        self.append(|w| {
            w.start_structure(Tag::Anonymous)?;
            w.unsigned(Tag::Context(0), u64::from(result.security.bits()))?;
            w.octets(Tag::Context(1), result.ssid)?;
            w.octets(Tag::Context(2), &result.bssid)?;
            w.unsigned(Tag::Context(3), u64::from(result.channel))?;
            if let Some(band) = result.band {
                w.unsigned(Tag::Context(4), u64::from(band.value()))?;
            }
            if let Some(rssi) = result.rssi {
                w.signed(Tag::Context(5), i64::from(rssi))?;
            }
            w.end_container()
        })
    }

    /// Appends a Thread result.
    pub fn thread(&mut self, result: &ThreadScanResult<'_>) -> Result<(), NetworkStatus> {
        self.append(|w| {
            w.start_structure(Tag::Anonymous)?;
            w.unsigned(Tag::Context(0), u64::from(result.pan_id))?;
            w.unsigned(Tag::Context(1), result.extended_pan_id)?;
            w.utf8(Tag::Context(2), result.network_name)?;
            w.unsigned(Tag::Context(3), u64::from(result.channel))?;
            w.unsigned(Tag::Context(4), u64::from(result.version))?;
            w.octets(Tag::Context(5), &result.extended_address)?;
            w.signed(Tag::Context(6), i64::from(result.rssi))?;
            w.unsigned(Tag::Context(7), u64::from(result.lqi))?;
            w.end_container()
        })
    }

    /// Builds one result into its own buffer and splices it whole, or not at all.
    ///
    /// Writing straight into the response would leave a half-written structure behind the
    /// first field that did not fit — and a driver is free to ignore the error and keep
    /// going, which is exactly when that happens. Once the list is full it *stays* full, so a
    /// later, smaller result cannot slip in behind a larger one that was dropped and leave the
    /// array in an order the driver did not choose.
    fn append(
        &mut self,
        build: impl FnOnce(&mut TlvWriter<'_>) -> crate::error::Result<()>,
    ) -> Result<(), NetworkStatus> {
        if self.full {
            return Err(NetworkStatus::BoundsExceeded);
        }
        let mut scratch = [0u8; ONE_RESULT_BYTES];
        let encoded = {
            let mut one = TlvWriter::new_in(&mut scratch, ContainerKind::Array);
            build(&mut one).and_then(|()| one.finish())
        };
        let Ok(encoded) = encoded else {
            // One result that does not fit its own buffer is a driver bug, not a full
            // response — but dropping it is still the safe answer, and the list is allowed to
            // be a subset.
            self.full = true;
            return Err(NetworkStatus::BoundsExceeded);
        };
        if self.w.raw_element(encoded).is_err() {
            self.full = true;
            return Err(NetworkStatus::BoundsExceeded);
        }
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// How many results have been written.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether nothing was found — which is a legitimate `Success`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether the response filled up and later results are being dropped.
    ///
    /// A driver reporting in decreasing signal order, as §11.9.7.2 asks, can stop here.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.full
    }
}

/// What a `ConnectNetwork` attempt produced (§11.9.7.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectOutcome {
    /// `NetworkingStatus [0]`.
    pub status: NetworkStatus,
    /// `ErrorValue [2]` — nullable, and null on success.
    ///
    /// For Wi-Fi, §11.9.7.9 is specific: "the ErrorValue field SHALL be set to the Status Code
    /// value that was present in the last frame related to association where Status Code was
    /// not equal to zero" — an IEEE 802.11-2020 Table 9-50 code, which a diagnostic tool can
    /// name. Otherwise it is "an implementation-dependent value".
    pub error_value: Option<i32>,
}

impl ConnectOutcome {
    /// A successful connection: `Success`, and a null `ErrorValue`.
    ///
    /// §11.9.7.9: "Set the LastConnectErrorValue attribute value to the ErrorValue matching
    /// the response, **including setting it to null if the ErrorValue is not applicable**."
    #[must_use]
    pub const fn success() -> Self {
        Self {
            status: NetworkStatus::Success,
            error_value: None,
        }
    }

    /// A failure with no further detail.
    #[must_use]
    pub const fn failed(status: NetworkStatus) -> Self {
        Self {
            status,
            error_value: None,
        }
    }

    /// A failure carrying an implementation or 802.11 status code.
    #[must_use]
    pub const fn failed_with(status: NetworkStatus, error_value: i32) -> Self {
        Self {
            status,
            error_value: Some(error_value),
        }
    }
}

/// The radio behind a Network Commissioning instance.
///
/// Everything this cluster cannot do itself: scanning, associating, and remembering
/// credentials it is forbidden to store. `&self` throughout, because
/// [`ClusterHandler`] is — a driver with mutable state uses a [`Cell`] or a
/// [`RefCell`], the same as the clusters do.
///
/// An Ethernet instance needs none of it, which is why [`EthernetDriver`] exists and why its
/// methods are unreachable: §11.9.7's whole command table is `WI | TH`.
pub trait NetworkDriver {
    /// Which technology this interface is.
    fn kind(&self) -> NetworkKind;

    /// `ScanNetworks` (§11.9.7.1).
    ///
    /// `ssid` is a directed scan: "if a network identifier (e.g. Wi-Fi SSID) is provided …
    /// Directed scanning SHALL restrict the result set to the specified network only." Absent
    /// or null means "scanning of all BSSID in range", and it "SHALL be ignored for
    /// ScanNetworks invocations on non-Wi-Fi server instances".
    fn scan(&self, _ssid: Option<&[u8]>, _results: &mut ScanResults<'_, '_>) -> NetworkStatus {
        NetworkStatus::UnknownError
    }

    /// Remembers the credentials for a Wi-Fi network (§11.9.7.3).
    ///
    /// The credentials reach the driver and stop there — they are never put in the `Networks`
    /// attribute, and this crate keeps no copy. §11.9.7.3's valid lengths (0, 5, 8..=63, 64,
    /// and the hex forms) are "contextually interpreted based on the security type of the
    /// BSSID where connection will occur", so only the driver can judge them.
    fn add_or_update_wifi(&self, _ssid: &[u8], _credentials: &[u8]) -> NetworkStatus {
        NetworkStatus::UnknownError
    }

    /// Remembers a Thread Operational Dataset (§11.9.7.4).
    fn add_or_update_thread(&self, _dataset: &[u8]) -> NetworkStatus {
        NetworkStatus::UnknownError
    }

    /// Forgets whatever `add_or_update_*` remembered for `id`.
    fn forget(&self, _id: &[u8]) {}

    /// `ConnectNetwork` (§11.9.7.8) — associate with the network `id` names.
    fn connect(&self, _id: &[u8]) -> ConnectOutcome {
        ConnectOutcome::failed(NetworkStatus::UnknownError)
    }

    /// `InterfaceEnabled` (§11.9.6.5).
    ///
    /// "It MAY be possible to disable Ethernet interfaces but it is implementation-defined. If
    /// not supported, a write to this attribute with a value of false SHALL fail with a status
    /// of INVALID_ACTION."
    fn set_interface_enabled(&self, _enabled: bool) -> Result<(), Status> {
        Err(Status::InvalidAction)
    }
}

/// The driver for an Ethernet instance, which needs no radio.
///
/// §11.9.6.2 gives an Ethernet instance exactly one `Networks` entry, automatically populated
/// and not modifiable, and §11.9.7's command table is entirely `WI | TH` — so an Ethernet
/// instance accepts no commands at all and this driver implements none of them.
#[derive(Debug, Clone, Copy, Default)]
pub struct EthernetDriver;

impl NetworkDriver for EthernetDriver {
    fn kind(&self) -> NetworkKind {
        NetworkKind::Ethernet
    }

    fn set_interface_enabled(&self, enabled: bool) -> Result<(), Status> {
        // "On Ethernet-only Nodes, there SHALL always be at least one of the Network
        // Commissioning server cluster instances with InterfaceEnabled set to true." Refusing
        // to disable is the conservative reading, and §11.9.6.5 names the status for it.
        if enabled {
            Ok(())
        } else {
            Err(Status::InvalidAction)
        }
    }
}

// --- Descriptors -------------------------------------------------------------------------------

const fn fixed(id: AttributeId) -> AttributeDescriptor {
    AttributeDescriptor::read_only(id).with_qualities(AttributeQualities::FIXED)
}

/// `RA` — Administer to read. The network list is not something a View subject may enumerate:
/// it names the access points a home uses.
const fn administered(id: AttributeId) -> AttributeDescriptor {
    AttributeDescriptor::read_only(id).with_access(Access::read_only(Privilege::Administer))
}

/// The attributes every instance has, whatever its feature bit.
const COMMON: [AttributeDescriptor; 6] = [
    administered(MAX_NETWORKS).with_qualities(AttributeQualities::FIXED),
    administered(NETWORKS),
    // `RW VA`, `N` — an administrator may turn the interface off, and the choice survives a
    // reboot.
    AttributeDescriptor::read_write(INTERFACE_ENABLED)
        .with_access(Access::read_write_with(
            Privilege::View,
            Privilege::Administer,
        ))
        .with_qualities(AttributeQualities::NON_VOLATILE),
    administered(LAST_NETWORKING_STATUS).with_qualities(AttributeQualities::NULLABLE),
    administered(LAST_NETWORK_ID).with_qualities(AttributeQualities::NULLABLE),
    administered(LAST_CONNECT_ERROR_VALUE).with_qualities(AttributeQualities::NULLABLE),
];

/// Ethernet: the common six, in id order.
const ETHERNET_ATTRIBUTES: &[AttributeDescriptor] = &[
    COMMON[0], COMMON[1], COMMON[2], COMMON[3], COMMON[4], COMMON[5],
];

/// Wi-Fi: plus the two timing attributes (`WI | TH`) and `SupportedWiFiBands` (`WI`).
const WIFI_ATTRIBUTES: &[AttributeDescriptor] = &[
    COMMON[0],
    COMMON[1],
    fixed(SCAN_MAX_TIME_SECONDS),
    fixed(CONNECT_MAX_TIME_SECONDS),
    COMMON[2],
    COMMON[3],
    COMMON[4],
    COMMON[5],
    fixed(SUPPORTED_WIFI_BANDS),
];

/// Thread: plus the two timing attributes and the two capability attributes (`TH`).
const THREAD_ATTRIBUTES: &[AttributeDescriptor] = &[
    COMMON[0],
    COMMON[1],
    fixed(SCAN_MAX_TIME_SECONDS),
    fixed(CONNECT_MAX_TIME_SECONDS),
    COMMON[2],
    COMMON[3],
    COMMON[4],
    COMMON[5],
    fixed(SUPPORTED_THREAD_FEATURES),
    fixed(THREAD_VERSION),
];

const fn invoke_admin(id: CommandId) -> CommandDescriptor {
    CommandDescriptor::new(id).with_access(Access::invoke(Privilege::Administer))
}

/// The commands `WI | TH` share.
const SHARED_COMMANDS: [CommandDescriptor; 4] = [
    invoke_admin(SCAN_NETWORKS).with_response(SCAN_NETWORKS_RESPONSE),
    invoke_admin(REMOVE_NETWORK).with_response(NETWORK_CONFIG_RESPONSE),
    invoke_admin(CONNECT_NETWORK).with_response(CONNECT_NETWORK_RESPONSE),
    invoke_admin(REORDER_NETWORK).with_response(NETWORK_CONFIG_RESPONSE),
];

const WIFI_COMMANDS: &[CommandDescriptor] = &[
    SHARED_COMMANDS[0],
    invoke_admin(ADD_OR_UPDATE_WIFI_NETWORK).with_response(NETWORK_CONFIG_RESPONSE),
    SHARED_COMMANDS[1],
    SHARED_COMMANDS[2],
    SHARED_COMMANDS[3],
];

const THREAD_COMMANDS: &[CommandDescriptor] = &[
    SHARED_COMMANDS[0],
    invoke_admin(ADD_OR_UPDATE_THREAD_NETWORK).with_response(NETWORK_CONFIG_RESPONSE),
    SHARED_COMMANDS[1],
    SHARED_COMMANDS[2],
    SHARED_COMMANDS[3],
];

/// The descriptor for an Ethernet instance.
///
/// No commands: §11.9.7's whole table is `WI | TH`. An Ethernet interface is configured by
/// being plugged in, and the cluster exists so a commissioner can *see* that.
#[must_use]
pub const fn ethernet() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: FEATURE_ETHERNET,
        attributes: ETHERNET_ATTRIBUTES,
        accepted_commands: &[],
        generated_commands: &[],
        events: &[],
    }
}

/// The descriptor for a Wi-Fi instance.
#[must_use]
pub const fn wifi() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: FEATURE_WIFI,
        attributes: WIFI_ATTRIBUTES,
        accepted_commands: WIFI_COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// The descriptor for a Thread instance.
#[must_use]
pub const fn thread() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: FEATURE_THREAD,
        attributes: THREAD_ATTRIBUTES,
        accepted_commands: THREAD_COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// The fixed capabilities an instance reports, beyond its network list.
///
/// §11.9.6.3 and §11.9.6.4's timings are `WI | TH` and have no fallback, so a device has to
/// state them: `ScanMaxTimeSeconds` is "the maximum duration taken, in seconds, by the network
/// interface … to provide scan results", and `ConnectMaxTimeSeconds` the same for a
/// connection, accounting for "obtaining IP addresses, or the execution of necessary internal
/// retries". A commissioner sizes its fail-safe from them.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities<'a> {
    /// `ScanMaxTimeSeconds` (§11.9.6.3).
    pub scan_max_time_seconds: u8,
    /// `ConnectMaxTimeSeconds` (§11.9.6.4).
    pub connect_max_time_seconds: u8,
    /// `SupportedWiFiBands` (§11.9.6.9) — min 1 entry on a Wi-Fi instance.
    pub wifi_bands: &'a [WiFiBand],
    /// `SupportedThreadFeatures` (§11.9.6.10).
    pub thread_features: ThreadCapabilities,
    /// `ThreadVersion` (§11.9.6.11) — "the value mapping found in the 'Version TLV' section of
    /// Thread specification. For example, Thread 1.3.0 would have ThreadVersion set to 4."
    pub thread_version: u16,
}

impl Default for Capabilities<'_> {
    fn default() -> Self {
        Self {
            // Conservative and common: a scan takes a few seconds, a connection rather longer
            // once DHCP and retries are counted.
            scan_max_time_seconds: 10,
            connect_max_time_seconds: 30,
            wifi_bands: &[WiFiBand::Band2G4],
            thread_features: ThreadCapabilities::empty(),
            thread_version: 4,
        }
    }
}

// --- The cluster -------------------------------------------------------------------------------

/// One Network Commissioning instance: one interface, one `Networks` list, one driver.
///
/// The fail-safe is shared with General Commissioning and Operational Credentials, because it
/// is node state and because §11.10.7.2.2 step 5 reverts *this* list when it expires.
pub struct NetworkCommissioning<'a, D: NetworkDriver, const N: usize> {
    /// The interface's radio, or [`EthernetDriver`] for a wire.
    pub driver: &'a D,
    /// The node's fail-safe. Every command here requires it armed.
    pub fail_safe: &'a RefCell<crate::commissioning::failsafe::FailSafe>,
    /// The fixed capability values this instance reports.
    pub capabilities: Capabilities<'a>,
    store: RefCell<NetworkStore<N>>,
    enabled: Cell<bool>,
    last_status: Cell<Option<NetworkStatus>>,
    last_network_id: RefCell<Option<Vec<u8, NETWORK_ID_MAX>>>,
    last_connect_error: Cell<Option<i32>>,
}

impl<'a, D: NetworkDriver, const N: usize> NetworkCommissioning<'a, D, N> {
    /// An instance over a driver.
    ///
    /// The three `Last*` attributes start null: §11.9.6.6 says so — "If no such attempt was
    /// made, or no network configurations exist in the Networks attribute, then this attribute
    /// SHALL be set to null."
    #[must_use]
    pub fn new(
        driver: &'a D,
        fail_safe: &'a RefCell<crate::commissioning::failsafe::FailSafe>,
        capabilities: Capabilities<'a>,
    ) -> Self {
        Self {
            driver,
            fail_safe,
            capabilities,
            store: RefCell::new(NetworkStore::new()),
            // §11.9.6.5: "By default all network interfaces SHOULD be enabled during initial
            // commissioning (InterfaceEnabled set to true)."
            enabled: Cell::new(true),
            last_status: Cell::new(None),
            last_network_id: RefCell::new(None),
            last_connect_error: Cell::new(None),
        }
    }

    /// The descriptor matching this instance's driver.
    #[must_use]
    pub fn descriptor(&self) -> ClusterDescriptor<'static> {
        match self.driver.kind() {
            NetworkKind::WiFi => wifi(),
            NetworkKind::Thread => thread(),
            NetworkKind::Ethernet => ethernet(),
        }
    }

    /// The `Networks` list.
    #[must_use]
    pub fn store(&self) -> core::cell::Ref<'_, NetworkStore<N>> {
        self.store.borrow()
    }

    /// The `Networks` list, mutably — for an Ethernet instance's
    /// [`seed`](NetworkStore::seed), and for a driver reporting a link change.
    #[must_use]
    pub fn store_mut(&self) -> core::cell::RefMut<'_, NetworkStore<N>> {
        self.store.borrow_mut()
    }

    /// `InterfaceEnabled` (§11.9.6.5).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.get()
    }

    /// Reverts the list — §11.10.7.2.2 step 5. Call this when the fail-safe expires.
    pub fn on_fail_safe_expired(&self) {
        self.store.borrow_mut().restore();
    }

    /// Keeps the list — call this on `CommissioningComplete`.
    pub fn on_commissioning_complete(&self) {
        self.store.borrow_mut().commit();
    }

    /// §11.9.7.2, §11.9.7.7 and §11.9.7.9 each open with the same instruction: "Before
    /// generating a …Response, the server SHALL set the LastNetworkingStatus attribute value
    /// to the NetworkingStatus matching the response."
    ///
    /// So the three `Last*` attributes are written on the way *out*, together, and this is the
    /// one place that does it — a command that set only some of them would leave a
    /// commissioner reading a status from one attempt beside an id from another, which is
    /// precisely what §11.9.6.6 says they exist to prevent.
    fn record_outcome(&self, status: NetworkStatus, id: Option<&[u8]>, error: Option<i32>) {
        self.last_status.set(Some(status));
        if let Some(id) = id {
            *self.last_network_id.borrow_mut() = Vec::from_slice(id).ok();
        }
        self.last_connect_error.set(error);
    }

    /// The fail-safe must be armed, or every command here is `FAILSAFE_REQUIRED`.
    fn require_fail_safe(&self, ctx: &InteractionContext<'_>) -> Result<(), Status> {
        if self.fail_safe.borrow().is_armed(ctx.now) {
            Ok(())
        } else {
            Err(Status::FailsafeRequired)
        }
    }

    /// Takes §11.10.7.2.2 step 5's snapshot, and tells the fail-safe there is one to revert.
    ///
    /// Called before any mutation, and the snapshot is taken *lazily* — on the first change
    /// inside a fail-safe period rather than when the period opened. That is the same state,
    /// and it means this cluster needs no notification when `ArmFailSafe` runs: the fail-safe's
    /// own `changed_networks` flag, which is reset whenever a new context is created, says
    /// whether the current period has touched the list yet.
    ///
    /// Setting `changed_networks` is what makes
    /// [`Cleanup::restore_networks`](crate::commissioning::failsafe::Cleanup::restore_networks)
    /// fire on expiry. Without it the device would be told nothing needs reverting and would
    /// keep a half-configured network list.
    fn record_change(&self, ctx: &InteractionContext<'_>) {
        let already = self
            .fail_safe
            .borrow()
            .armed(ctx.now)
            .is_some_and(|armed| armed.progress.changed_networks);
        if !already {
            self.store.borrow_mut().snapshot();
        }
        let _ = self
            .fail_safe
            .borrow_mut()
            .record(ctx.now, |p| p.changed_networks = true);
    }

    /// Writes the `Breadcrumb` the command carried, if it carried one.
    ///
    /// §11.9.7.1.2: "The Breadcrumb field, if present, SHALL be used to atomically set the
    /// Breadcrumb attribute in the General Commissioning cluster **on success** of the
    /// associated command. If the command fails, the Breadcrumb attribute … SHALL be left
    /// unchanged."
    fn set_breadcrumb(&self, breadcrumb: Option<u64>, status: NetworkStatus) {
        if status.is_success()
            && let Some(breadcrumb) = breadcrumb
        {
            self.fail_safe.borrow_mut().set_breadcrumb(breadcrumb);
        }
    }
}

// --- The commands ------------------------------------------------------------------------------

impl<D: NetworkDriver, const N: usize> NetworkCommissioning<'_, D, N> {
    /// `ScanNetworks` (§11.9.7.1) → `ScanNetworksResponse` (§11.9.7.2).
    ///
    /// The results are built into `scratch` before anything is written to `w`, because the
    /// response's `NetworkingStatus` is field 0 and the results are fields 2 and 3 — and the
    /// status is not known until the driver has finished. Emitting the fields out of order
    /// would be a non-canonical structure (§A.2.4), and guessing the status and rewriting it
    /// would mean a half-written response on the failure path.
    pub fn scan(
        &self,
        ssid: Option<&[u8]>,
        breadcrumb: Option<u64>,
        ctx: &InteractionContext<'_>,
        scratch: &mut [u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        self.require_fail_safe(ctx)?;
        // "This field SHALL be ignored for ScanNetworks invocations on non-Wi-Fi server
        // instances." Dropping it here rather than in each driver keeps a Thread driver from
        // having to know the rule.
        let ssid = ssid.filter(|_| self.driver.kind() == NetworkKind::WiFi);
        // "OutOfRange: Network identifier was invalid (e.g. empty, too long, etc)."
        if let Some(ssid) = ssid
            && (ssid.is_empty() || ssid.len() > NETWORK_ID_MAX)
        {
            self.record_outcome(NetworkStatus::OutOfRange, Some(ssid), None);
            return write_scan_response(NetworkStatus::OutOfRange, None, w, tag);
        }

        // Field 2 for Wi-Fi, field 3 for Thread — an instance has one or the other, never
        // both, because §11.9.4's features are `O.a`.
        let results_tag = match self.driver.kind() {
            NetworkKind::Thread => Tag::Context(3),
            _ => Tag::Context(2),
        };
        let mut results = TlvWriter::new_in(scratch, ContainerKind::Structure);
        results
            .start_array(results_tag)
            .map_err(|_| Status::ResourceExhausted)?;
        let status = {
            let mut sink = ScanResults {
                w: &mut results,
                count: 0,
                full: false,
            };
            self.driver.scan(ssid, &mut sink)
        };
        results
            .end_container()
            .map_err(|_| Status::ResourceExhausted)?;
        let encoded = results.finish().map_err(|_| Status::ResourceExhausted)?;

        // §11.9.7.2: "Before generating a ScanNetworksResponse, the server SHALL set the
        // LastNetworkingStatus attribute value to the NetworkingStatus matching the response."
        self.record_outcome(status, ssid, None);
        self.set_breadcrumb(breadcrumb, status);

        // "Results are valid only if NetworkingStatus is Success" — so a failed scan reports
        // the status and nothing else, rather than an empty list a client might read as "no
        // networks in range".
        write_scan_response(status, status.is_success().then_some(encoded), w, tag)
    }

    /// `AddOrUpdateWiFiNetwork` (§11.9.7.3) → `NetworkConfigResponse`.
    ///
    /// The credentials go to the driver and stop there. §11.9.7.3: "The Credentials associated
    /// with the network are not readable after execution of this command, as they do not
    /// appear in the Networks attribute, for security reasons."
    pub fn add_or_update_wifi(
        &self,
        ssid: &[u8],
        credentials: &[u8],
        breadcrumb: Option<u64>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        self.require_fail_safe(ctx)?;
        if self.driver.kind() != NetworkKind::WiFi {
            return Err(Status::UnsupportedCommand);
        }
        self.record_change(ctx);
        let outcome = match self.driver.add_or_update_wifi(ssid, credentials) {
            NetworkStatus::Success => self.store.borrow_mut().add_or_update(ssid),
            other => Err(other),
        };
        self.finish_config(outcome, ssid, breadcrumb, w, tag)
    }

    /// `AddOrUpdateThreadNetwork` (§11.9.7.4) → `NetworkConfigResponse`.
    ///
    /// "The XPAN ID in the OperationalDataset serves as the NetworkID", so the dataset is
    /// parsed for exactly that one field and otherwise passed through opaque.
    pub fn add_or_update_thread(
        &self,
        dataset: &[u8],
        breadcrumb: Option<u64>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        self.require_fail_safe(ctx)?;
        if self.driver.kind() != NetworkKind::Thread {
            return Err(Status::UnsupportedCommand);
        }
        // "If any of the parameters in the OperationalDataset are invalid, the command SHALL
        // immediately respond with NetworkConfigResponse having NetworkingStatus status field
        // set to a value different than Success and consistent with the error." A dataset with
        // no Extended PAN ID has no NetworkID, so there is nothing to key the entry by.
        self.record_change(ctx);
        let Some(xpan) = thread_extended_pan_id(dataset) else {
            self.record_outcome(NetworkStatus::OutOfRange, None, None);
            return write_config_response(NetworkStatus::OutOfRange, None, w, tag);
        };
        let outcome = match self.driver.add_or_update_thread(dataset) {
            NetworkStatus::Success => self.store.borrow_mut().add_or_update(&xpan),
            other => Err(other),
        };
        self.finish_config(outcome, &xpan, breadcrumb, w, tag)
    }

    /// `RemoveNetwork` (§11.9.7.6) → `NetworkConfigResponse`.
    pub fn remove_network(
        &self,
        id: &[u8],
        breadcrumb: Option<u64>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        self.require_fail_safe(ctx)?;
        self.record_change(ctx);
        let outcome = self.store.borrow_mut().remove(id);
        if outcome.is_ok() {
            // The driver is told after the list, so a driver that refuses cannot leave an
            // entry the list no longer has.
            self.driver.forget(id);
        }
        self.finish_config(outcome, id, breadcrumb, w, tag)
    }

    /// `ReorderNetwork` (§11.9.7.10) → `NetworkConfigResponse`.
    pub fn reorder_network(
        &self,
        id: &[u8],
        index: u8,
        breadcrumb: Option<u64>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        self.require_fail_safe(ctx)?;
        self.record_change(ctx);
        let outcome = self.store.borrow_mut().reorder(id, index);
        self.finish_config(outcome, id, breadcrumb, w, tag)
    }

    /// `ConnectNetwork` (§11.9.7.8) → `ConnectNetworkResponse` (§11.9.7.9).
    pub fn connect_network(
        &self,
        id: &[u8],
        breadcrumb: Option<u64>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        self.require_fail_safe(ctx)?;
        // A connection changes the `Connected` flags, which are part of what step 5 reverts:
        // "Even after successfully connecting to a network, the configuration SHALL revert to
        // the prior state of configuration if the CommissioningComplete command is not
        // successfully invoked before expiry of the Fail-Safe timer" (§11.9.7.8).
        self.record_change(ctx);
        // "NetworkIdNotFound: The network identifier was not found among the added network
        // configurations in Networks attribute."
        if self.store.borrow().position(id).is_none() {
            self.record_outcome(NetworkStatus::NetworkIdNotFound, Some(id), None);
            return write_connect_response(
                ConnectOutcome::failed(NetworkStatus::NetworkIdNotFound),
                w,
                tag,
            );
        }

        let outcome = self.driver.connect(id);
        {
            let mut store = self.store.borrow_mut();
            if outcome.status.is_success() {
                let _ = store.set_connected(id);
            } else {
                // "On failure to connect, the entry associated with the given Network
                // configuration in the Networks attribute SHALL indicate its Connected field
                // set to false."
                store.set_all_disconnected();
            }
        }
        // §11.9.7.9 sets all three `Last*` attributes, including "setting it to null if the
        // ErrorValue is not applicable".
        self.record_outcome(outcome.status, Some(id), outcome.error_value);
        self.set_breadcrumb(breadcrumb, outcome.status);
        write_connect_response(outcome, w, tag)
    }

    fn finish_config(
        &self,
        outcome: Result<u8, NetworkStatus>,
        id: &[u8],
        breadcrumb: Option<u64>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let (status, index) = match outcome {
            Ok(index) => (NetworkStatus::Success, Some(index)),
            Err(status) => (status, None),
        };
        // §11.9.7.7: "Before generating a NetworkConfigResponse, the server SHALL set the
        // LastNetworkingStatus attribute … and the LastNetworkID attribute value to the
        // NetworkID that was used in the command".
        self.record_outcome(status, Some(id), None);
        self.set_breadcrumb(breadcrumb, status);
        write_config_response(status, index, w, tag)
    }
}

/// `ScanNetworksResponse` (§11.9.7.2): `NetworkingStatus [0]`, `DebugText [1]`, and the
/// results array already encoded with its own context tag.
fn write_scan_response(
    status: NetworkStatus,
    results: Option<&[u8]>,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> Result<(), Status> {
    let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
    full(w.start_structure(tag))?;
    full(w.unsigned(Tag::Context(0), u64::from(status.value())))?;
    // `DebugText` is optional and omitted: a device that filled it would be describing its
    // internals to anyone who can invoke the command.
    if let Some(results) = results {
        full(w.raw_element(results))?;
    }
    full(w.end_container())
}

/// `NetworkConfigResponse` (§11.9.7.7): `NetworkingStatus [0]`, `DebugText [1]`,
/// `NetworkIndex [2]`.
///
/// `NetworkIndex`'s conformance is `NetworkingStatus == Success`, so it is present exactly on
/// success and absent otherwise — not zero, which would name the first entry.
fn write_config_response(
    status: NetworkStatus,
    index: Option<u8>,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> Result<(), Status> {
    let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
    full(w.start_structure(tag))?;
    full(w.unsigned(Tag::Context(0), u64::from(status.value())))?;
    if let Some(index) = index {
        full(w.unsigned(Tag::Context(2), u64::from(index)))?;
    }
    full(w.end_container())
}

/// `ConnectNetworkResponse` (§11.9.7.9): `NetworkingStatus [0]`, `DebugText [1]`,
/// `ErrorValue [2]`.
///
/// `ErrorValue` is mandatory **and** nullable, so it is always present and null on success.
fn write_connect_response(
    outcome: ConnectOutcome,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> Result<(), Status> {
    let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
    full(w.start_structure(tag))?;
    full(w.unsigned(Tag::Context(0), u64::from(outcome.status.value())))?;
    match outcome.error_value {
        Some(value) => full(w.signed(Tag::Context(2), i64::from(value)))?,
        None => full(w.null(Tag::Context(2)))?,
    }
    full(w.end_container())
}

// --- The attributes ----------------------------------------------------------------------------

/// The scratch an invoke uses to build a `ScanNetworksResponse`'s result list.
///
/// Sized against §4.4.4's message limits rather than generously: a `ScanNetworksResponse` has
/// to fit in one message, and §11.9.7.2 explicitly permits reporting "a subset of
/// possibilities, to avoid memory exhaustion on the cluster server and avoid crossing the
/// maximum command response size supported". The driver sees the sink fill up and stops.
pub const SCAN_SCRATCH_BYTES: usize = 1024;

impl<D: NetworkDriver, const N: usize> ClusterHandler for NetworkCommissioning<'_, D, N> {
    /// The network list is the one thing the fail-safe stages that is not a fabric: §11.10.7.2.2
    /// step 5 reverts it on expiry, and §11.10.7.6 makes it permanent on
    /// `CommissioningComplete`. A node that never commits reverts to its *first* snapshot at
    /// the next expiry, whenever that is.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        match event {
            crate::im::Lifecycle::FailSafeExpired { .. } => self.on_fail_safe_expired(),
            crate::im::Lifecycle::CommissioningComplete(_) => self.on_commissioning_complete(),
            crate::im::Lifecycle::FabricRemoved(_) => {}
        }
    }
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            MAX_NETWORKS => {
                let capacity = u8::try_from(N).unwrap_or(u8::MAX);
                full(w.unsigned(tag, u64::from(capacity)))
            }
            NETWORKS => {
                let store = self.store.borrow();
                full(w.start_array(tag))?;
                for entry in store.entries() {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.octets(Tag::Context(0), &entry.id))?;
                    full(w.bool(Tag::Context(1), entry.connected))?;
                    full(w.end_container())?;
                }
                full(w.end_container())
            }
            SCAN_MAX_TIME_SECONDS => {
                full(w.unsigned(tag, u64::from(self.capabilities.scan_max_time_seconds)))
            }
            CONNECT_MAX_TIME_SECONDS => {
                full(w.unsigned(tag, u64::from(self.capabilities.connect_max_time_seconds)))
            }
            INTERFACE_ENABLED => full(w.bool(tag, self.enabled.get())),
            // The three `Last*` attributes are nullable and null until something has been
            // attempted — §11.9.6.6: "If no such attempt was made … this attribute SHALL be
            // set to null." A zero would name `Success`, which is a different claim.
            LAST_NETWORKING_STATUS => match self.last_status.get() {
                Some(status) => full(w.unsigned(tag, u64::from(status.value()))),
                None => full(w.null(tag)),
            },
            LAST_NETWORK_ID => match self.last_network_id.borrow().as_deref() {
                Some(id) => full(w.octets(tag, id)),
                None => full(w.null(tag)),
            },
            LAST_CONNECT_ERROR_VALUE => match self.last_connect_error.get() {
                Some(value) => full(w.signed(tag, i64::from(value))),
                None => full(w.null(tag)),
            },
            SUPPORTED_WIFI_BANDS => {
                full(w.start_array(tag))?;
                for band in self.capabilities.wifi_bands {
                    full(w.unsigned(Tag::Anonymous, u64::from(band.value())))?;
                }
                full(w.end_container())
            }
            SUPPORTED_THREAD_FEATURES => {
                full(w.unsigned(tag, u64::from(self.capabilities.thread_features.bits())))
            }
            THREAD_VERSION => full(w.unsigned(tag, u64::from(self.capabilities.thread_version))),
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
            INTERFACE_ENABLED => {
                let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
                let value = reader
                    .next_element()
                    .ok()
                    .flatten()
                    .and_then(|element| element.bool().ok())
                    .ok_or(Status::InvalidDataType)?;
                // §11.9.6.5: a driver that cannot disable its interface answers
                // INVALID_ACTION, and the attribute is left alone.
                self.driver.set_interface_enabled(value)?;
                self.enabled.set(value);
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
            SCAN_NETWORKS => {
                let request = ScanRequest::decode(fields)?;
                let mut scratch = [0u8; SCAN_SCRATCH_BYTES];
                self.scan(request.ssid, request.breadcrumb, ctx, &mut scratch, w, tag)?;
                Ok(Some(SCAN_NETWORKS_RESPONSE))
            }
            ADD_OR_UPDATE_WIFI_NETWORK => {
                let request = WiFiRequest::decode(fields)?;
                self.add_or_update_wifi(
                    request.ssid,
                    request.credentials,
                    request.breadcrumb,
                    ctx,
                    w,
                    tag,
                )?;
                Ok(Some(NETWORK_CONFIG_RESPONSE))
            }
            ADD_OR_UPDATE_THREAD_NETWORK => {
                let request = ThreadRequest::decode(fields)?;
                self.add_or_update_thread(request.dataset, request.breadcrumb, ctx, w, tag)?;
                Ok(Some(NETWORK_CONFIG_RESPONSE))
            }
            REMOVE_NETWORK => {
                let request = NetworkIdRequest::decode(fields)?;
                self.remove_network(request.id, request.breadcrumb, ctx, w, tag)?;
                Ok(Some(NETWORK_CONFIG_RESPONSE))
            }
            CONNECT_NETWORK => {
                let request = NetworkIdRequest::decode(fields)?;
                self.connect_network(request.id, request.breadcrumb, ctx, w, tag)?;
                Ok(Some(CONNECT_NETWORK_RESPONSE))
            }
            REORDER_NETWORK => {
                let request = ReorderRequest::decode(fields)?;
                self.reorder_network(request.id, request.index, request.breadcrumb, ctx, w, tag)?;
                Ok(Some(NETWORK_CONFIG_RESPONSE))
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<D: NetworkDriver, const N: usize> Cluster for NetworkCommissioning<'_, D, N> {
    const ID: ClusterId = ID;
}

// --- Command decoding --------------------------------------------------------------------------

/// Walks a `CommandFields` structure, refusing a truncated or malformed one.
///
/// The same contract as every other cluster's decoder: only the structure's own
/// end-of-container ends the walk, so a short buffer cannot be read as "these fields were
/// absent" and silently take a command's fallbacks.
fn walk_fields<'a>(
    fields: Option<&'a [u8]>,
    mut on_field: impl FnMut(u8, &crate::tlv::Element<'a>) -> Result<bool, Status>,
) -> Result<(), Status> {
    let fields = fields.ok_or(Status::InvalidCommand)?;
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| Status::InvalidCommand)?
        .ok_or(Status::InvalidCommand)?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidCommand);
    }
    let start_depth = reader.depth();
    loop {
        let Some(field) = reader.next_element().map_err(|_| Status::InvalidCommand)? else {
            return Err(Status::InvalidCommand);
        };
        if reader.depth() < start_depth {
            break;
        }
        let Tag::Context(number) = field.tag else {
            reader
                .skip_value(&field)
                .map_err(|_| Status::InvalidCommand)?;
            continue;
        };
        if !on_field(number, &field)? {
            reader
                .skip_value(&field)
                .map_err(|_| Status::InvalidCommand)?;
        }
    }
    Ok(())
}

struct ScanRequest<'a> {
    ssid: Option<&'a [u8]>,
    breadcrumb: Option<u64>,
}

impl<'a> ScanRequest<'a> {
    fn decode(fields: Option<&'a [u8]>) -> Result<Self, Status> {
        let mut ssid = None;
        let mut breadcrumb = None;
        walk_fields(fields, |number, element| {
            match number {
                // `SSID [0]` is optional *and* nullable, and both mean the same thing here:
                // "if the field is absent, or if it is null, this SHALL indicate scanning of
                // all BSSID in range".
                0 => {
                    if !element.value.is_null() {
                        set_once(
                            &mut ssid,
                            element.octets().map_err(|_| Status::InvalidCommand)?,
                        )
                        .map_err(|_| Status::InvalidCommand)?;
                    }
                }
                1 => set_once(
                    &mut breadcrumb,
                    element.unsigned().map_err(|_| Status::InvalidCommand)?,
                )
                .map_err(|_| Status::InvalidCommand)?,
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok(Self { ssid, breadcrumb })
    }
}

struct WiFiRequest<'a> {
    ssid: &'a [u8],
    credentials: &'a [u8],
    breadcrumb: Option<u64>,
}

impl<'a> WiFiRequest<'a> {
    fn decode(fields: Option<&'a [u8]>) -> Result<Self, Status> {
        let mut ssid = None;
        let mut credentials = None;
        let mut breadcrumb = None;
        walk_fields(fields, |number, element| {
            match number {
                0 => set_once(
                    &mut ssid,
                    element.octets().map_err(|_| Status::InvalidCommand)?,
                ),
                1 => set_once(
                    &mut credentials,
                    element.octets().map_err(|_| Status::InvalidCommand)?,
                ),
                2 => set_once(
                    &mut breadcrumb,
                    element.unsigned().map_err(|_| Status::InvalidCommand)?,
                ),
                _ => return Ok(false),
            }
            .map_err(|_| Status::InvalidCommand)?;
            Ok(true)
        })?;
        let ssid = ssid.ok_or(Status::InvalidCommand)?;
        let credentials = credentials.ok_or(Status::InvalidCommand)?;
        // §11.9.7.3's `max 32` and `max 64`. A longer value is a constraint error rather than
        // something to truncate: truncating a PSK produces a device that cannot associate and
        // cannot say why.
        if ssid.len() > NETWORK_ID_MAX || credentials.len() > CREDENTIALS_MAX {
            return Err(Status::ConstraintError);
        }
        Ok(Self {
            ssid,
            credentials,
            breadcrumb,
        })
    }
}

struct ThreadRequest<'a> {
    dataset: &'a [u8],
    breadcrumb: Option<u64>,
}

impl<'a> ThreadRequest<'a> {
    fn decode(fields: Option<&'a [u8]>) -> Result<Self, Status> {
        let mut dataset = None;
        let mut breadcrumb = None;
        walk_fields(fields, |number, element| {
            match number {
                0 => set_once(
                    &mut dataset,
                    element.octets().map_err(|_| Status::InvalidCommand)?,
                ),
                1 => set_once(
                    &mut breadcrumb,
                    element.unsigned().map_err(|_| Status::InvalidCommand)?,
                ),
                _ => return Ok(false),
            }
            .map_err(|_| Status::InvalidCommand)?;
            Ok(true)
        })?;
        let dataset = dataset.ok_or(Status::InvalidCommand)?;
        if dataset.len() > OPERATIONAL_DATASET_MAX {
            return Err(Status::ConstraintError);
        }
        Ok(Self {
            dataset,
            breadcrumb,
        })
    }
}

struct NetworkIdRequest<'a> {
    id: &'a [u8],
    breadcrumb: Option<u64>,
}

impl<'a> NetworkIdRequest<'a> {
    fn decode(fields: Option<&'a [u8]>) -> Result<Self, Status> {
        let mut id = None;
        let mut breadcrumb = None;
        walk_fields(fields, |number, element| {
            match number {
                0 => set_once(
                    &mut id,
                    element.octets().map_err(|_| Status::InvalidCommand)?,
                ),
                1 => set_once(
                    &mut breadcrumb,
                    element.unsigned().map_err(|_| Status::InvalidCommand)?,
                ),
                _ => return Ok(false),
            }
            .map_err(|_| Status::InvalidCommand)?;
            Ok(true)
        })?;
        Ok(Self {
            id: id.ok_or(Status::InvalidCommand)?,
            breadcrumb,
        })
    }
}

struct ReorderRequest<'a> {
    id: &'a [u8],
    index: u8,
    breadcrumb: Option<u64>,
}

impl<'a> ReorderRequest<'a> {
    fn decode(fields: Option<&'a [u8]>) -> Result<Self, Status> {
        let mut id = None;
        let mut index = None;
        let mut breadcrumb = None;
        walk_fields(fields, |number, element| {
            match number {
                0 => set_once(
                    &mut id,
                    element.octets().map_err(|_| Status::InvalidCommand)?,
                ),
                1 => {
                    let value = element.unsigned().map_err(|_| Status::InvalidCommand)?;
                    set_once(
                        &mut index,
                        u8::try_from(value).map_err(|_| Status::ConstraintError)?,
                    )
                }
                2 => set_once(
                    &mut breadcrumb,
                    element.unsigned().map_err(|_| Status::InvalidCommand)?,
                ),
                _ => return Ok(false),
            }
            .map_err(|_| Status::InvalidCommand)?;
            Ok(true)
        })?;
        Ok(Self {
            id: id.ok_or(Status::InvalidCommand)?,
            index: index.ok_or(Status::InvalidCommand)?,
            breadcrumb,
        })
    }
}
