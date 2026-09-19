//! Thread Network Diagnostics, cluster `0x0035` (Core §11.14).
//!
//! The largest of the three network diagnostics clusters — sixty-five attributes — and the same
//! shape as the other two: every number belongs to a radio and a Thread stack this crate does
//! not own, so the cluster is a [`ThreadDriver`] the integrator implements. It needs no radio to
//! compile or to test; the `openthread` crate is one source for the numbers, and nothing here
//! depends on it.
//!
//! # Three kinds of attribute, and three shapes in the trait
//!
//! * **The network's state** — `Channel`, `RoutingRole`, `NetworkName`, the timestamps — is
//!   mandatory and nullable. A driver returns [`Option`], where `None` is the specification's
//!   `null`: the Thread interface is not configured or operational. There is no third answer,
//!   because a Thread device reports these or is not a Thread device.
//! * **The tables** — `NeighborTable`, `RouteTable`, `ActiveNetworkFaultsList` — are mandatory
//!   lists, and empty is a perfectly good answer. A driver returns a slice, which is also the
//!   only list shape a `no_std` crate can hand over without allocating.
//! * **The counters** are conditional on §11.14.4's features *and* optional within them. They
//!   arrive as [`MacCounters`] and [`MleCounters`], one struct each, because that is how a
//!   Thread stack hands them over and because forty-two separate trait methods would be
//!   forty-two chances to wire one to the wrong attribute. A field left `None` is a counter the
//!   device does not keep, and it belongs out of the [`Optional`] list too.
//!
//!   `OverrunCount` is the exception: §11.14.6 makes it mandatory within `ERRCNT` and does not
//!   make it nullable, so it is a plain `u64` a device claiming `ERRCNT` has promised to count.
//!
//! ```
//! use matter_kit::clusters::thread_network_diagnostics::{
//!     RoutingRoleEnum, ThreadDriver, ThreadNetworkDiagnostics,
//! };
//!
//! struct Stack;
//! impl ThreadDriver for Stack {
//!     fn channel(&self) -> Option<u16> { Some(15) }
//!     fn routing_role(&self) -> Option<RoutingRoleEnum> { Some(RoutingRoleEnum::Router) }
//!     fn network_name(&self) -> Option<&str> { Some("matter-kit") }
//!     fn pan_id(&self) -> Option<u16> { Some(0x1234) }
//!     fn extended_pan_id(&self) -> Option<u64> { Some(0xDEAD_BEEF_0000_0001) }
//! }
//!
//! // No feature bits: this driver reports the network and counts nothing.
//! let cluster = ThreadNetworkDiagnostics::<_, 4>::new(&Stack, 0);
//! # let _ = cluster;
//! ```

use core::cell::RefCell;

use crate::dm::spec::{Conforming, Optional};
use crate::dm::{EventPriority, Resolved, ResolvedCommand};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, CommandId, EventId, InteractionContext, Status,
    StatusIb,
};
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::Cluster;
use crate::clusters::generated::thread_network_diagnostics as spec_thread;

pub use spec_thread::{
    ConnectionStatusEnum, ID, NeighborTableStruct, NetworkFaultEnum, OperationalDatasetComponents,
    PICS, REVISION, RouteTableStruct, RoutingRoleEnum, SecurityPolicy, feature,
};

use spec_thread::attribute::{
    ACTIVE_NETWORK_FAULTS_LIST, ACTIVE_TIMESTAMP, CHANNEL, CHANNEL_PAGE0_MASK, DATA_VERSION, DELAY,
    EXT_ADDRESS, EXTENDED_PAN_ID, LEADER_ROUTER_ID, MESH_LOCAL_PREFIX, NEIGHBOR_TABLE,
    NETWORK_NAME, OPERATIONAL_DATASET_COMPONENTS, OVERRUN_COUNT, PAN_ID, PARTITION_ID,
    PENDING_TIMESTAMP, RLOC16, ROUTE_TABLE, ROUTING_ROLE, SECURITY_POLICY, STABLE_DATA_VERSION,
    WEIGHTING,
};
use spec_thread::attribute::{
    ATTACH_ATTEMPT_COUNT, BETTER_PARTITION_ATTACH_ATTEMPT_COUNT, CHILD_ROLE_COUNT,
    DETACHED_ROLE_COUNT, LEADER_ROLE_COUNT, PARENT_CHANGE_COUNT, PARTITION_ID_CHANGE_COUNT,
    ROUTER_ROLE_COUNT,
};
use spec_thread::attribute::{
    RX_ADDRESS_FILTERED_COUNT, RX_BEACON_COUNT, RX_BEACON_REQUEST_COUNT, RX_BROADCAST_COUNT,
    RX_DATA_COUNT, RX_DATA_POLL_COUNT, RX_DEST_ADDR_FILTERED_COUNT, RX_DUPLICATED_COUNT,
    RX_ERR_FCS_COUNT, RX_ERR_INVALID_SRC_ADDR_COUNT, RX_ERR_NO_FRAME_COUNT, RX_ERR_OTHER_COUNT,
    RX_ERR_SEC_COUNT, RX_ERR_UNKNOWN_NEIGHBOR_COUNT, RX_OTHER_COUNT, RX_TOTAL_COUNT,
    RX_UNICAST_COUNT, TX_ACK_REQUESTED_COUNT, TX_ACKED_COUNT, TX_BEACON_COUNT,
    TX_BEACON_REQUEST_COUNT, TX_BROADCAST_COUNT, TX_DATA_COUNT, TX_DATA_POLL_COUNT,
    TX_DIRECT_MAX_RETRY_EXPIRY_COUNT, TX_ERR_ABORT_COUNT, TX_ERR_BUSY_CHANNEL_COUNT,
    TX_ERR_CCA_COUNT, TX_INDIRECT_MAX_RETRY_EXPIRY_COUNT, TX_NO_ACK_REQUESTED_COUNT,
    TX_OTHER_COUNT, TX_RETRY_COUNT, TX_TOTAL_COUNT, TX_UNICAST_COUNT,
};
use spec_thread::command::RESET_COUNTS;
pub use spec_thread::event::{CONNECTION_STATUS, NETWORK_FAULT_CHANGE};

/// The `MACCNT` counters of §11.14.6, as a Thread stack hands them over.
///
/// Every field is optional: §11.14.4's `MACCNT` says the device *may* report these, not that it
/// reports all of them. `None` is "this device does not keep that counter", and the same
/// counter must then be left out of the [`Optional`] list the descriptor is built from — a
/// value answered for an attribute that is not in `AttributeList` is a number no client asked
/// for and no client can find.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacCounters {
    /// `TxTotalCount` (§11.14.6.23).
    pub tx_total: Option<u32>,
    /// `TxUnicastCount` (§11.14.6.24).
    pub tx_unicast: Option<u32>,
    /// `TxBroadcastCount` (§11.14.6.25).
    pub tx_broadcast: Option<u32>,
    /// `TxAckRequestedCount` (§11.14.6.26).
    pub tx_ack_requested: Option<u32>,
    /// `TxAckedCount` (§11.14.6.27).
    pub tx_acked: Option<u32>,
    /// `TxNoAckRequestedCount` (§11.14.6.28).
    pub tx_no_ack_requested: Option<u32>,
    /// `TxDataCount` (§11.14.6.29).
    pub tx_data: Option<u32>,
    /// `TxDataPollCount` (§11.14.6.30).
    pub tx_data_poll: Option<u32>,
    /// `TxBeaconCount` (§11.14.6.31).
    pub tx_beacon: Option<u32>,
    /// `TxBeaconRequestCount` (§11.14.6.32).
    pub tx_beacon_request: Option<u32>,
    /// `TxOtherCount` (§11.14.6.33).
    pub tx_other: Option<u32>,
    /// `TxRetryCount` (§11.14.6.34).
    pub tx_retry: Option<u32>,
    /// `TxDirectMaxRetryExpiryCount` (§11.14.6.35).
    pub tx_direct_max_retry_expiry: Option<u32>,
    /// `TxIndirectMaxRetryExpiryCount` (§11.14.6.36).
    pub tx_indirect_max_retry_expiry: Option<u32>,
    /// `TxErrCcaCount` (§11.14.6.37).
    pub tx_err_cca: Option<u32>,
    /// `TxErrAbortCount` (§11.14.6.38).
    pub tx_err_abort: Option<u32>,
    /// `TxErrBusyChannelCount` (§11.14.6.39).
    pub tx_err_busy_channel: Option<u32>,
    /// `RxTotalCount` (§11.14.6.40).
    pub rx_total: Option<u32>,
    /// `RxUnicastCount` (§11.14.6.41).
    pub rx_unicast: Option<u32>,
    /// `RxBroadcastCount` (§11.14.6.42).
    pub rx_broadcast: Option<u32>,
    /// `RxDataCount` (§11.14.6.43).
    pub rx_data: Option<u32>,
    /// `RxDataPollCount` (§11.14.6.44).
    pub rx_data_poll: Option<u32>,
    /// `RxBeaconCount` (§11.14.6.45).
    pub rx_beacon: Option<u32>,
    /// `RxBeaconRequestCount` (§11.14.6.46).
    pub rx_beacon_request: Option<u32>,
    /// `RxOtherCount` (§11.14.6.47).
    pub rx_other: Option<u32>,
    /// `RxAddressFilteredCount` (§11.14.6.48).
    pub rx_address_filtered: Option<u32>,
    /// `RxDestAddrFilteredCount` (§11.14.6.49).
    pub rx_dest_addr_filtered: Option<u32>,
    /// `RxDuplicatedCount` (§11.14.6.50).
    pub rx_duplicated: Option<u32>,
    /// `RxErrNoFrameCount` (§11.14.6.51).
    pub rx_err_no_frame: Option<u32>,
    /// `RxErrUnknownNeighborCount` (§11.14.6.52).
    pub rx_err_unknown_neighbor: Option<u32>,
    /// `RxErrInvalidSrcAddrCount` (§11.14.6.53).
    pub rx_err_invalid_src_addr: Option<u32>,
    /// `RxErrSecCount` (§11.14.6.54).
    pub rx_err_sec: Option<u32>,
    /// `RxErrFcsCount` (§11.14.6.55).
    pub rx_err_fcs: Option<u32>,
    /// `RxErrOtherCount` (§11.14.6.56).
    pub rx_err_other: Option<u32>,
}

/// The `MLECNT` counters of §11.14.6 — how often this node changed role, re-attached, or
/// followed a better partition.
///
/// Optional in the same way [`MacCounters`] is, and for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MleCounters {
    /// `DetachedRoleCount` (§11.14.6.15).
    pub detached_role: Option<u16>,
    /// `ChildRoleCount` (§11.14.6.16).
    pub child_role: Option<u16>,
    /// `RouterRoleCount` (§11.14.6.17).
    pub router_role: Option<u16>,
    /// `LeaderRoleCount` (§11.14.6.18).
    pub leader_role: Option<u16>,
    /// `AttachAttemptCount` (§11.14.6.19).
    pub attach_attempt: Option<u16>,
    /// `PartitionIdChangeCount` (§11.14.6.20).
    pub partition_id_change: Option<u16>,
    /// `BetterPartitionAttachAttemptCount` (§11.14.6.21).
    pub better_partition_attach_attempt: Option<u16>,
    /// `ParentChangeCount` (§11.14.6.22).
    pub parent_change: Option<u16>,
}

/// What a device's Thread stack can report (§11.14.6).
///
/// Every method has a default, so an integrator implements only what the stack exposes. The
/// defaults are the conservative ones: `null` for the network state, empty for the tables, and
/// no counters at all.
pub trait ThreadDriver {
    /// `Channel` (§11.14.6.1) — the 802.15.4 channel in use.
    fn channel(&self) -> Option<u16> {
        None
    }

    /// `RoutingRole` (§11.14.6.2).
    ///
    /// [`RoutingRoleEnum::Unassigned`] and `null` are not the same answer: the first is a
    /// configured interface with no role yet, the second is no configured interface.
    fn routing_role(&self) -> Option<RoutingRoleEnum> {
        None
    }

    /// `NetworkName` (§11.14.6.3), at most sixteen octets.
    fn network_name(&self) -> Option<&str> {
        None
    }

    /// `PanId` (§11.14.6.4).
    fn pan_id(&self) -> Option<u16> {
        None
    }

    /// `ExtendedPanId` (§11.14.6.5).
    fn extended_pan_id(&self) -> Option<u64> {
        None
    }

    /// `MeshLocalPrefix` (§11.14.6.6) — an `ipv6pre`: one length octet, then the prefix.
    fn mesh_local_prefix(&self) -> Option<&[u8]> {
        None
    }

    /// `OverrunCount` (§11.14.6.7) — packets dropped for want of buffer memory. `ERRCNT`.
    ///
    /// The one counter here that is mandatory within its feature and not nullable, so it is a
    /// plain number: a device claiming `ERRCNT` has promised to count it.
    fn overrun_count(&self) -> u64 {
        0
    }

    /// `NeighborTable` (§11.14.6.8). Empty is a legitimate answer and `null` is not one.
    fn neighbors(&self) -> &[NeighborTableStruct] {
        &[]
    }

    /// `RouteTable` (§11.14.6.9).
    fn routes(&self) -> &[RouteTableStruct] {
        &[]
    }

    /// `PartitionId` (§11.14.6.10).
    fn partition_id(&self) -> Option<u32> {
        None
    }

    /// `Weighting` (§11.14.6.11) — the leader weight this node's partition is running at.
    fn weighting(&self) -> Option<u16> {
        None
    }

    /// `DataVersion` (§11.14.6.12).
    fn data_version(&self) -> Option<u16> {
        None
    }

    /// `StableDataVersion` (§11.14.6.13).
    fn stable_data_version(&self) -> Option<u16> {
        None
    }

    /// `LeaderRouterId` (§11.14.6.14).
    fn leader_router_id(&self) -> Option<u8> {
        None
    }

    /// The `MLECNT` counters (§11.14.6).
    fn mle_counters(&self) -> MleCounters {
        MleCounters::EMPTY
    }

    /// The `MACCNT` counters (§11.14.6).
    ///
    /// Called once per counter read, so a driver that has to ask the radio should cache: a
    /// wildcard read of this cluster asks for thirty-four of them in a row.
    fn mac_counters(&self) -> MacCounters {
        MacCounters::EMPTY
    }

    /// `ActiveTimestamp` (§11.14.6.57) of the Active Operational Dataset.
    fn active_timestamp(&self) -> Option<u64> {
        None
    }

    /// `PendingTimestamp` (§11.14.6.58) of the Pending Operational Dataset.
    fn pending_timestamp(&self) -> Option<u64> {
        None
    }

    /// `Delay` (§11.14.6.59) before a pending dataset is adopted, in milliseconds.
    fn delay(&self) -> Option<u32> {
        None
    }

    /// `SecurityPolicy` (§11.14.6.60).
    fn security_policy(&self) -> Option<SecurityPolicy> {
        None
    }

    /// `ChannelPage0Mask` (§11.14.6.61) — the channel mask as an octet string.
    fn channel_page0_mask(&self) -> Option<&[u8]> {
        None
    }

    /// `OperationalDatasetComponents` (§11.14.6.62) — which parts of the dataset are present.
    fn operational_dataset_components(&self) -> Option<OperationalDatasetComponents> {
        None
    }

    /// `ActiveNetworkFaultsList` (§11.14.6.63) — the faults currently detected, if any.
    fn active_network_faults(&self) -> &[NetworkFaultEnum] {
        &[]
    }

    /// `ExtAddress` (§11.14.6.64) — the node's IEEE 802.15.4 extended address.
    fn ext_address(&self) -> Option<u64> {
        None
    }

    /// `Rloc16` (§11.14.6.65) — the node's routing locator.
    fn rloc16(&self) -> Option<u16> {
        None
    }

    /// `ResetCounts` (§11.14.7.1): zero every counter this cluster reports.
    ///
    /// The default does nothing, which is correct for a driver that reports no counters. One
    /// that does must implement this, or a client's reset silently fails.
    fn reset_counts(&self) {}
}

impl MacCounters {
    /// A device that keeps none of them.
    pub const EMPTY: Self = Self {
        tx_total: None,
        tx_unicast: None,
        tx_broadcast: None,
        tx_ack_requested: None,
        tx_acked: None,
        tx_no_ack_requested: None,
        tx_data: None,
        tx_data_poll: None,
        tx_beacon: None,
        tx_beacon_request: None,
        tx_other: None,
        tx_retry: None,
        tx_direct_max_retry_expiry: None,
        tx_indirect_max_retry_expiry: None,
        tx_err_cca: None,
        tx_err_abort: None,
        tx_err_busy_channel: None,
        rx_total: None,
        rx_unicast: None,
        rx_broadcast: None,
        rx_data: None,
        rx_data_poll: None,
        rx_beacon: None,
        rx_beacon_request: None,
        rx_other: None,
        rx_address_filtered: None,
        rx_dest_addr_filtered: None,
        rx_duplicated: None,
        rx_err_no_frame: None,
        rx_err_unknown_neighbor: None,
        rx_err_invalid_src_addr: None,
        rx_err_sec: None,
        rx_err_fcs: None,
        rx_err_other: None,
    };
}

impl MleCounters {
    /// A device that keeps none of them.
    pub const EMPTY: Self = Self {
        detached_role: None,
        child_role: None,
        router_role: None,
        leader_role: None,
        attach_attempt: None,
        partition_id_change: None,
        better_partition_attach_attempt: None,
        parent_change: None,
    };
}

/// The driver for a device with no Thread metrics to report.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unknown;

impl ThreadDriver for Unknown {}

/// One of §11.14.8's events, as the Thread stack noticed it.
///
/// The cluster collects these and the device drains them into its own event store, because
/// the store belongs to the node and not to any one cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// §11.14.8.1 `ConnectionStatus`, on every transition between connected and not.
    ConnectionStatus(ConnectionStatusEnum),
    /// §11.14.8.2 `NetworkFaultChange`, carrying both sides of the change.
    NetworkFaultChange {
        /// `Current` — the faults detected now.
        current: heapless::Vec<NetworkFaultEnum, 4>,
        /// `Previous` — the faults detected before this change.
        previous: heapless::Vec<NetworkFaultEnum, 4>,
    },
}

impl Event {
    /// The event id this record is reported under.
    #[must_use]
    pub const fn id(&self) -> EventId {
        match self {
            Self::ConnectionStatus(_) => CONNECTION_STATUS,
            Self::NetworkFaultChange { .. } => NETWORK_FAULT_CHANGE,
        }
    }

    /// Both events in §11.14.8 are `INFO` priority.
    #[must_use]
    pub const fn priority(&self) -> EventPriority {
        EventPriority::Info
    }

    /// Writes the event's fields as an `EventDataIB`'s `Data` (§10.6.13).
    ///
    /// # Errors
    ///
    /// Whatever the writer returns when the buffer is too small.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> crate::error::Result<()> {
        w.start_structure(tag)?;
        match self {
            Self::ConnectionStatus(status) => {
                w.unsigned(Tag::Context(0), u64::from(status.value()))?;
            }
            Self::NetworkFaultChange { current, previous } => {
                faults(w, Tag::Context(0), current)?;
                faults(w, Tag::Context(1), previous)?;
            }
        }
        w.end_container()
    }
}

/// A `list[NetworkFaultEnum]`, which both `ActiveNetworkFaultsList` and `NetworkFaultChange`
/// are made of.
fn faults(w: &mut TlvWriter<'_>, tag: Tag, list: &[NetworkFaultEnum]) -> crate::error::Result<()> {
    w.start_array(tag)?;
    for fault in list {
        w.unsigned(Tag::Anonymous, u64::from(fault.value()))?;
    }
    w.end_container()
}

/// Builds a descriptor for a feature map and the optional elements a product implements.
///
/// The `Optional` list is doing real work here: forty-two of the sixty-five attributes are
/// optional within their feature, so this is where a product says which counters it actually
/// keeps. [`ALL_OPTIONAL`] is the everything-reported end of that range and a poor default for
/// a real device.
///
/// # Errors
///
/// [`ErrorCode::InvalidArgument`](crate::ErrorCode) for a feature this revision does not define,
/// or [`NoSpace`](crate::ErrorCode::NoSpace) if the selection does not fit.
pub fn conforming(
    features: u32,
    optional: &Optional<'_>,
) -> crate::error::Result<Conforming<70, 1, 0, 2>> {
    Conforming::new(&spec_thread::CLUSTER, features, optional)
}

/// Every counter §11.14.4's `MLECNT` and `MACCNT` features bring, each of which §11.14.6 leaves
/// optional within its feature.
///
/// A real product names the ones it actually keeps; this is the everything-reported end of the
/// range and a poor default for a device.
pub const COUNTERS: &[AttributeId] = &[
    DETACHED_ROLE_COUNT,
    CHILD_ROLE_COUNT,
    ROUTER_ROLE_COUNT,
    LEADER_ROLE_COUNT,
    ATTACH_ATTEMPT_COUNT,
    PARTITION_ID_CHANGE_COUNT,
    BETTER_PARTITION_ATTACH_ATTEMPT_COUNT,
    PARENT_CHANGE_COUNT,
    TX_TOTAL_COUNT,
    TX_UNICAST_COUNT,
    TX_BROADCAST_COUNT,
    TX_ACK_REQUESTED_COUNT,
    TX_ACKED_COUNT,
    TX_NO_ACK_REQUESTED_COUNT,
    TX_DATA_COUNT,
    TX_DATA_POLL_COUNT,
    TX_BEACON_COUNT,
    TX_BEACON_REQUEST_COUNT,
    TX_OTHER_COUNT,
    TX_RETRY_COUNT,
    TX_DIRECT_MAX_RETRY_EXPIRY_COUNT,
    TX_INDIRECT_MAX_RETRY_EXPIRY_COUNT,
    TX_ERR_CCA_COUNT,
    TX_ERR_ABORT_COUNT,
    TX_ERR_BUSY_CHANNEL_COUNT,
    RX_TOTAL_COUNT,
    RX_UNICAST_COUNT,
    RX_BROADCAST_COUNT,
    RX_DATA_COUNT,
    RX_DATA_POLL_COUNT,
    RX_BEACON_COUNT,
    RX_BEACON_REQUEST_COUNT,
    RX_OTHER_COUNT,
    RX_ADDRESS_FILTERED_COUNT,
    RX_DEST_ADDR_FILTERED_COUNT,
    RX_DUPLICATED_COUNT,
    RX_ERR_NO_FRAME_COUNT,
    RX_ERR_UNKNOWN_NEIGHBOR_COUNT,
    RX_ERR_INVALID_SRC_ADDR_COUNT,
    RX_ERR_SEC_COUNT,
    RX_ERR_FCS_COUNT,
    RX_ERR_OTHER_COUNT,
];

/// Every attribute, command and event §11.14 leaves to the product.
///
/// `ExtAddress` and `Rloc16` are absent, because 1.6 marks them provisional (Core §2.13) and the
/// default build here is the certifiable one. Under the `provisional` feature they are included.
#[cfg(not(feature = "provisional"))]
pub const ALL_OPTIONAL: Optional<'static> = Optional {
    attributes: COUNTERS,
    commands: &[],
    events: &[CONNECTION_STATUS, NETWORK_FAULT_CHANGE],
};

/// Every attribute, command and event §11.14 leaves to the product, including §2.13's two
/// provisional attributes.
#[cfg(feature = "provisional")]
pub const ALL_OPTIONAL: Optional<'static> = Optional {
    attributes: &WITH_PROVISIONAL,
    commands: &[],
    events: &[CONNECTION_STATUS, NETWORK_FAULT_CHANGE],
};

/// [`COUNTERS`] followed by the two provisional attributes, as one contiguous table.
#[cfg(feature = "provisional")]
#[allow(clippy::indexing_slicing)]
const WITH_PROVISIONAL: [AttributeId; 44] = {
    let mut all = [0; 44];
    let mut i = 0;
    while i < COUNTERS.len() {
        all[i] = COUNTERS[i];
        i += 1;
    }
    all[42] = EXT_ADDRESS;
    all[43] = RLOC16;
    all
};

/// The Thread Network Diagnostics cluster (§11.14).
///
/// `E` is how many events the cluster holds before the oldest is dropped. A stack that flaps
/// must not be able to grow this, and the device drains it every time round its own loop.
#[derive(Debug)]
pub struct ThreadNetworkDiagnostics<'a, D: ThreadDriver, const E: usize = 4> {
    driver: &'a D,
    features: u32,
    events: RefCell<heapless::Vec<Event, E>>,
}

impl<'a, D: ThreadDriver, const E: usize> ThreadNetworkDiagnostics<'a, D, E> {
    /// A cluster over a device's own Thread stack.
    #[must_use]
    pub fn new(driver: &'a D, features: u32) -> Self {
        Self {
            driver,
            features,
            events: RefCell::new(heapless::Vec::new()),
        }
    }

    /// Records one of §11.14.8's events for the device to drain.
    ///
    /// Public because both of them are the *stack's* to notice.
    pub fn record(&self, event: Event) {
        let mut events = self.events.borrow_mut();
        if events.is_full() {
            events.remove(0);
        }
        let _ = events.push(event);
    }

    /// Takes the events recorded since the last call.
    #[must_use]
    pub fn take_events(&self) -> heapless::Vec<Event, E> {
        core::mem::take(&mut self.events.borrow_mut())
    }

    const fn has(&self, bit: u32) -> bool {
        self.features & bit != 0
    }
}

/// Writes a mandatory nullable attribute: the value, or §11.14.6's `null`.
fn nullable<T>(
    value: Option<T>,
    w: &mut TlvWriter<'_>,
    tag: Tag,
    encode: impl FnOnce(&mut TlvWriter<'_>, Tag, T) -> crate::error::Result<()>,
) -> Result<(), Status> {
    match value {
        Some(v) => encode(w, tag, v),
        None => w.null(tag),
    }
    .map_err(|_| Status::ResourceExhausted)
}

/// A counter §11.14.4 makes conditional on a feature and §11.14.6 leaves optional within it.
///
/// Two different refusals, one status: the feature is not claimed, or it is claimed and this
/// device does not keep that particular counter. Both mean the attribute is not on this device,
/// which is what the descriptor says too — answering zero would be the stack asserting a
/// measurement it never made.
fn counter(
    claimed: bool,
    value: Option<u64>,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> Result<(), Status> {
    match (claimed, value) {
        (true, Some(v)) => w.unsigned(tag, v).map_err(|_| Status::ResourceExhausted),
        _ => Err(Status::UnsupportedAttribute),
    }
}

/// A `list[Struct]` attribute, written as the array it is.
fn list<T: ToTlv>(items: &[T], w: &mut TlvWriter<'_>, tag: Tag) -> Result<(), Status> {
    (|| {
        w.start_array(tag)?;
        for item in items {
            item.to_tlv(w, Tag::Anonymous)?;
        }
        w.end_container()
    })()
    .map_err(|_: crate::Error| Status::ResourceExhausted)
}

impl<D: ThreadDriver, const E: usize> ClusterHandler for ThreadNetworkDiagnostics<'_, D, E> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let mac = self.has(feature::MAC_COUNTS);
        let mle = self.has(feature::MLE_COUNTS);
        match resolved.attribute {
            CHANNEL => nullable(self.driver.channel(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            ROUTING_ROLE => nullable(self.driver.routing_role(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v.value()))
            }),
            NETWORK_NAME => nullable(self.driver.network_name(), w, tag, |w, tag, v| {
                w.utf8(tag, v)
            }),
            PAN_ID => nullable(self.driver.pan_id(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            EXTENDED_PAN_ID => nullable(self.driver.extended_pan_id(), w, tag, |w, tag, v| {
                w.unsigned(tag, v)
            }),
            MESH_LOCAL_PREFIX => nullable(self.driver.mesh_local_prefix(), w, tag, |w, tag, v| {
                w.octets(tag, v)
            }),
            // Mandatory within `ERRCNT` and not nullable, unlike every other counter here.
            OVERRUN_COUNT => {
                if !self.has(feature::ERROR_COUNTS) {
                    return Err(Status::UnsupportedAttribute);
                }
                w.unsigned(tag, self.driver.overrun_count())
                    .map_err(|_| Status::ResourceExhausted)
            }
            NEIGHBOR_TABLE => list(self.driver.neighbors(), w, tag),
            ROUTE_TABLE => list(self.driver.routes(), w, tag),
            PARTITION_ID => nullable(self.driver.partition_id(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            WEIGHTING => nullable(self.driver.weighting(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            DATA_VERSION => nullable(self.driver.data_version(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            STABLE_DATA_VERSION => {
                nullable(self.driver.stable_data_version(), w, tag, |w, tag, v| {
                    w.unsigned(tag, u64::from(v))
                })
            }
            LEADER_ROUTER_ID => nullable(self.driver.leader_router_id(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            DETACHED_ROLE_COUNT => counter(
                mle,
                self.driver.mle_counters().detached_role.map(u64::from),
                w,
                tag,
            ),
            CHILD_ROLE_COUNT => counter(
                mle,
                self.driver.mle_counters().child_role.map(u64::from),
                w,
                tag,
            ),
            ROUTER_ROLE_COUNT => counter(
                mle,
                self.driver.mle_counters().router_role.map(u64::from),
                w,
                tag,
            ),
            LEADER_ROLE_COUNT => counter(
                mle,
                self.driver.mle_counters().leader_role.map(u64::from),
                w,
                tag,
            ),
            ATTACH_ATTEMPT_COUNT => counter(
                mle,
                self.driver.mle_counters().attach_attempt.map(u64::from),
                w,
                tag,
            ),
            PARTITION_ID_CHANGE_COUNT => counter(
                mle,
                self.driver
                    .mle_counters()
                    .partition_id_change
                    .map(u64::from),
                w,
                tag,
            ),
            BETTER_PARTITION_ATTACH_ATTEMPT_COUNT => counter(
                mle,
                self.driver
                    .mle_counters()
                    .better_partition_attach_attempt
                    .map(u64::from),
                w,
                tag,
            ),
            PARENT_CHANGE_COUNT => counter(
                mle,
                self.driver.mle_counters().parent_change.map(u64::from),
                w,
                tag,
            ),
            TX_TOTAL_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_total.map(u64::from),
                w,
                tag,
            ),
            TX_UNICAST_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_unicast.map(u64::from),
                w,
                tag,
            ),
            TX_BROADCAST_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_broadcast.map(u64::from),
                w,
                tag,
            ),
            TX_ACK_REQUESTED_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_ack_requested.map(u64::from),
                w,
                tag,
            ),
            TX_ACKED_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_acked.map(u64::from),
                w,
                tag,
            ),
            TX_NO_ACK_REQUESTED_COUNT => counter(
                mac,
                self.driver
                    .mac_counters()
                    .tx_no_ack_requested
                    .map(u64::from),
                w,
                tag,
            ),
            TX_DATA_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_data.map(u64::from),
                w,
                tag,
            ),
            TX_DATA_POLL_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_data_poll.map(u64::from),
                w,
                tag,
            ),
            TX_BEACON_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_beacon.map(u64::from),
                w,
                tag,
            ),
            TX_BEACON_REQUEST_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_beacon_request.map(u64::from),
                w,
                tag,
            ),
            TX_OTHER_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_other.map(u64::from),
                w,
                tag,
            ),
            TX_RETRY_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_retry.map(u64::from),
                w,
                tag,
            ),
            TX_DIRECT_MAX_RETRY_EXPIRY_COUNT => counter(
                mac,
                self.driver
                    .mac_counters()
                    .tx_direct_max_retry_expiry
                    .map(u64::from),
                w,
                tag,
            ),
            TX_INDIRECT_MAX_RETRY_EXPIRY_COUNT => counter(
                mac,
                self.driver
                    .mac_counters()
                    .tx_indirect_max_retry_expiry
                    .map(u64::from),
                w,
                tag,
            ),
            TX_ERR_CCA_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_err_cca.map(u64::from),
                w,
                tag,
            ),
            TX_ERR_ABORT_COUNT => counter(
                mac,
                self.driver.mac_counters().tx_err_abort.map(u64::from),
                w,
                tag,
            ),
            TX_ERR_BUSY_CHANNEL_COUNT => counter(
                mac,
                self.driver
                    .mac_counters()
                    .tx_err_busy_channel
                    .map(u64::from),
                w,
                tag,
            ),
            RX_TOTAL_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_total.map(u64::from),
                w,
                tag,
            ),
            RX_UNICAST_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_unicast.map(u64::from),
                w,
                tag,
            ),
            RX_BROADCAST_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_broadcast.map(u64::from),
                w,
                tag,
            ),
            RX_DATA_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_data.map(u64::from),
                w,
                tag,
            ),
            RX_DATA_POLL_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_data_poll.map(u64::from),
                w,
                tag,
            ),
            RX_BEACON_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_beacon.map(u64::from),
                w,
                tag,
            ),
            RX_BEACON_REQUEST_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_beacon_request.map(u64::from),
                w,
                tag,
            ),
            RX_OTHER_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_other.map(u64::from),
                w,
                tag,
            ),
            RX_ADDRESS_FILTERED_COUNT => counter(
                mac,
                self.driver
                    .mac_counters()
                    .rx_address_filtered
                    .map(u64::from),
                w,
                tag,
            ),
            RX_DEST_ADDR_FILTERED_COUNT => counter(
                mac,
                self.driver
                    .mac_counters()
                    .rx_dest_addr_filtered
                    .map(u64::from),
                w,
                tag,
            ),
            RX_DUPLICATED_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_duplicated.map(u64::from),
                w,
                tag,
            ),
            RX_ERR_NO_FRAME_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_err_no_frame.map(u64::from),
                w,
                tag,
            ),
            RX_ERR_UNKNOWN_NEIGHBOR_COUNT => counter(
                mac,
                self.driver
                    .mac_counters()
                    .rx_err_unknown_neighbor
                    .map(u64::from),
                w,
                tag,
            ),
            RX_ERR_INVALID_SRC_ADDR_COUNT => counter(
                mac,
                self.driver
                    .mac_counters()
                    .rx_err_invalid_src_addr
                    .map(u64::from),
                w,
                tag,
            ),
            RX_ERR_SEC_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_err_sec.map(u64::from),
                w,
                tag,
            ),
            RX_ERR_FCS_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_err_fcs.map(u64::from),
                w,
                tag,
            ),
            RX_ERR_OTHER_COUNT => counter(
                mac,
                self.driver.mac_counters().rx_err_other.map(u64::from),
                w,
                tag,
            ),
            ACTIVE_TIMESTAMP => nullable(self.driver.active_timestamp(), w, tag, |w, tag, v| {
                w.unsigned(tag, v)
            }),
            PENDING_TIMESTAMP => nullable(self.driver.pending_timestamp(), w, tag, |w, tag, v| {
                w.unsigned(tag, v)
            }),
            DELAY => nullable(self.driver.delay(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            SECURITY_POLICY => nullable(self.driver.security_policy(), w, tag, |w, tag, v| {
                v.to_tlv(w, tag)
            }),
            CHANNEL_PAGE0_MASK => {
                nullable(self.driver.channel_page0_mask(), w, tag, |w, tag, v| {
                    w.octets(tag, v)
                })
            }
            OPERATIONAL_DATASET_COMPONENTS => nullable(
                self.driver.operational_dataset_components(),
                w,
                tag,
                |w, tag, v| v.to_tlv(w, tag),
            ),
            ACTIVE_NETWORK_FAULTS_LIST => faults(w, tag, self.driver.active_network_faults())
                .map_err(|_| Status::ResourceExhausted),
            EXT_ADDRESS => nullable(self.driver.ext_address(), w, tag, |w, tag, v| {
                w.unsigned(tag, v)
            }),
            RLOC16 => nullable(self.driver.rloc16(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        match resolved.command.id {
            // §11.14.7's conformance is `ERRCNT`, like Wi-Fi's and unlike Ethernet's
            // `PKTCNT | ERRCNT`.
            RESET_COUNTS => {
                if !self.has(feature::ERROR_COUNTS) {
                    return Err(StatusIb::new(Status::UnsupportedCommand));
                }
                self.driver.reset_counts();
                Ok(None)
            }
            _ => Err(StatusIb::new(Status::UnsupportedCommand)),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<D: ThreadDriver, const E: usize> Cluster for ThreadNetworkDiagnostics<'_, D, E> {
    const ID: ClusterId = ID;
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::im::AttributeId;

    const NEIGHBORS: &[NeighborTableStruct] = &[NeighborTableStruct {
        ext_address: 0x0011_2233_4455_6677,
        age: 12,
        rloc16: 0x4000,
        link_frame_counter: 7,
        mle_frame_counter: 9,
        lqi: 3,
        average_rssi: crate::tlv::Nullable::some(-70),
        last_rssi: crate::tlv::Nullable::null(),
        frame_error_rate: 0,
        message_error_rate: 0,
        rx_on_when_idle: true,
        full_thread_device: true,
        full_network_data: true,
        is_child: false,
    }];

    struct Stack;

    impl ThreadDriver for Stack {
        fn channel(&self) -> Option<u16> {
            Some(15)
        }
        fn routing_role(&self) -> Option<RoutingRoleEnum> {
            Some(RoutingRoleEnum::Router)
        }
        fn network_name(&self) -> Option<&str> {
            Some("matter-kit")
        }
        fn pan_id(&self) -> Option<u16> {
            Some(0x1234)
        }
        fn overrun_count(&self) -> u64 {
            5
        }
        fn neighbors(&self) -> &[NeighborTableStruct] {
            NEIGHBORS
        }
        fn active_network_faults(&self) -> &[NetworkFaultEnum] {
            &[NetworkFaultEnum::LinkDown]
        }
        fn mle_counters(&self) -> MleCounters {
            MleCounters {
                parent_change: Some(2),
                ..MleCounters::EMPTY
            }
        }
        fn mac_counters(&self) -> MacCounters {
            MacCounters {
                tx_total: Some(100),
                rx_total: Some(90),
                ..MacCounters::EMPTY
            }
        }
    }

    /// A Thread interface that is powered and not attached.
    struct Detached;

    impl ThreadDriver for Detached {}

    /// The optional set a product that keeps only `ParentChangeCount`, `TxTotalCount` and
    /// `RxTotalCount` would declare — which is what `Stack` above actually measures.
    const MEASURED: Optional<'static> = Optional {
        attributes: &[PARENT_CHANGE_COUNT, TX_TOTAL_COUNT, RX_TOTAL_COUNT],
        commands: &[],
        events: &[],
    };

    fn read<D: ThreadDriver>(
        cluster: &ThreadNetworkDiagnostics<'_, D>,
        attribute: AttributeId,
    ) -> Result<heapless::Vec<u8, 96>, Status> {
        let descriptor = conforming(cluster.features, &MEASURED).expect("descriptor");
        let cl = descriptor.descriptor();
        let resolved = Resolved {
            endpoint: 0,
            cluster: &cl,
            attribute,
        };
        let mut buf = [0u8; 96];
        let mut w = TlvWriter::new_in(&mut buf, crate::tlv::ContainerKind::Structure);
        cluster.read(
            &resolved,
            &InteractionContext::new(),
            &mut w,
            Tag::Context(0),
        )?;
        Ok(heapless::Vec::from_slice(w.finish().expect("finish")).expect("fits"))
    }

    fn advertises(features: u32, optional: &Optional<'_>, attribute: AttributeId) -> bool {
        conforming(features, optional)
            .expect("descriptor")
            .descriptor()
            .attributes
            .iter()
            .any(|a| a.id == attribute)
    }

    /// The whole specification table fits, which is the assertion that `conforming`'s bounds
    /// are not one short — the failure mode is `NoSpace` at construction and nowhere else.
    #[test]
    fn every_element_the_revision_defines_fits_at_once() {
        let all = conforming(
            feature::PACKET_COUNTS
                | feature::ERROR_COUNTS
                | feature::MLE_COUNTS
                | feature::MAC_COUNTS,
            &ALL_OPTIONAL,
        )
        .expect("the whole cluster fits");
        assert!(advertises(
            feature::MAC_COUNTS,
            &ALL_OPTIONAL,
            RX_ERR_OTHER_COUNT
        ));
        assert_eq!(all.descriptor().events.len(), 2);
    }

    /// §11.14.4's counters are conditional on a feature *and* optional within it, so there are
    /// two ways for one not to be on a device — and a product that claims `MACCNT` without
    /// keeping every counter is the normal case, not an edge one.
    #[test]
    fn a_counter_needs_both_its_feature_and_the_products_declaration() {
        assert!(!advertises(0, &MEASURED, TX_TOTAL_COUNT), "no MACCNT");
        assert!(advertises(feature::MAC_COUNTS, &MEASURED, TX_TOTAL_COUNT));
        assert!(
            !advertises(feature::MAC_COUNTS, &MEASURED, TX_RETRY_COUNT),
            "claimed the feature, does not keep this one"
        );

        let counting = ThreadNetworkDiagnostics::<_, 4>::new(&Stack, feature::MAC_COUNTS);
        assert_eq!(
            read(&counting, TX_TOTAL_COUNT).expect("tx"),
            [0x24, 0x00, 100]
        );
        assert_eq!(
            read(&counting, TX_RETRY_COUNT),
            Err(Status::UnsupportedAttribute),
            "a counter the driver left None is not answered as zero"
        );

        let silent = ThreadNetworkDiagnostics::<_, 4>::new(&Stack, 0);
        assert_eq!(
            read(&silent, TX_TOTAL_COUNT),
            Err(Status::UnsupportedAttribute)
        );
    }

    /// `OverrunCount` is the only counter §11.14.6 makes mandatory within its feature, so it is
    /// the only one that is a plain number rather than an `Option`.
    #[test]
    fn overrun_count_is_mandatory_within_its_feature() {
        let errors = ThreadNetworkDiagnostics::<_, 4>::new(&Stack, feature::ERROR_COUNTS);
        assert_eq!(
            read(&errors, OVERRUN_COUNT).expect("overrun"),
            [0x24, 0x00, 5]
        );
        assert!(advertises(
            feature::ERROR_COUNTS,
            &Optional::NONE,
            OVERRUN_COUNT
        ));

        let none = ThreadNetworkDiagnostics::<_, 4>::new(&Stack, 0);
        assert_eq!(
            read(&none, OVERRUN_COUNT),
            Err(Status::UnsupportedAttribute)
        );
        assert!(!advertises(0, &Optional::NONE, OVERRUN_COUNT));
    }

    /// A detached interface answers `null`, and the tables answer empty — which is a different
    /// thing, and the reason the tables are slices rather than `Option`s.
    #[test]
    fn a_detached_interface_is_null_and_its_tables_are_empty() {
        let detached = ThreadNetworkDiagnostics::<_, 4>::new(&Detached, 0);
        assert_eq!(read(&detached, CHANNEL).expect("channel"), [0x34, 0x00]);
        assert_eq!(read(&detached, ROUTING_ROLE).expect("role"), [0x34, 0x00]);
        assert_eq!(read(&detached, NETWORK_NAME).expect("name"), [0x34, 0x00]);
        // An empty array, not null: the node has a neighbor table and nothing is in it.
        assert_eq!(
            read(&detached, NEIGHBOR_TABLE).expect("neighbors"),
            [0x36, 0x00, 0x18]
        );
        assert_eq!(
            read(&detached, ACTIVE_NETWORK_FAULTS_LIST).expect("faults"),
            [0x36, 0x00, 0x18]
        );
    }

    #[test]
    fn values_round_trip_through_the_reader() {
        let stack = ThreadNetworkDiagnostics::<_, 4>::new(&Stack, feature::MLE_COUNTS);
        assert_eq!(read(&stack, CHANNEL).expect("channel"), [0x24, 0x00, 15]);
        // `RoutingRoleEnum::Router` is 5.
        assert_eq!(read(&stack, ROUTING_ROLE).expect("role"), [0x24, 0x00, 5]);
        assert_eq!(
            read(&stack, NETWORK_NAME).expect("name"),
            [
                0x2C, 0x00, 0x0A, b'm', b'a', b't', b't', b'e', b'r', b'-', b'k', b'i', b't'
            ]
        );
        assert_eq!(read(&stack, PAN_ID).expect("pan"), [0x25, 0x00, 0x34, 0x12]);
        assert_eq!(
            read(&stack, PARENT_CHANGE_COUNT).expect("parent changes"),
            [0x24, 0x00, 2]
        );
        // One fault, as a one-element array.
        assert_eq!(
            read(&stack, ACTIVE_NETWORK_FAULTS_LIST).expect("faults"),
            [0x36, 0x00, 0x04, 0x01, 0x18]
        );
        assert!(read(&stack, NEIGHBOR_TABLE).expect("neighbors").len() > 3);
    }

    /// §11.14.7's `ResetCounts` is `ERRCNT`, like Wi-Fi's and unlike Ethernet's.
    #[test]
    fn reset_counts_belongs_to_the_error_counts_feature() {
        assert!(
            conforming(feature::MAC_COUNTS, &Optional::NONE)
                .expect("descriptor")
                .descriptor()
                .accepted_commands
                .is_empty(),
            "counting MAC frames does not bring ResetCounts"
        );

        let descriptor = conforming(feature::ERROR_COUNTS, &Optional::NONE).expect("descriptor");
        let cl = descriptor.descriptor();
        let command = *cl
            .accepted_commands
            .iter()
            .find(|c| c.id == RESET_COUNTS)
            .expect("ERRCNT brings ResetCounts");
        let resolved = ResolvedCommand {
            endpoint: 0,
            cluster: &cl,
            command,
        };
        let mut buf = [0u8; 32];
        let mut w = TlvWriter::new(&mut buf);

        let mac = ThreadNetworkDiagnostics::<_, 4>::new(&Stack, feature::MAC_COUNTS);
        assert_eq!(
            mac.invoke(
                &resolved,
                None,
                &InteractionContext::new(),
                &mut w,
                Tag::Anonymous
            )
            .unwrap_err()
            .status,
            Status::UnsupportedCommand
        );

        let errors = ThreadNetworkDiagnostics::<_, 4>::new(&Stack, feature::ERROR_COUNTS);
        assert!(
            errors
                .invoke(
                    &resolved,
                    None,
                    &InteractionContext::new(),
                    &mut w,
                    Tag::Anonymous
                )
                .is_ok()
        );
    }

    #[test]
    fn a_fault_change_event_carries_both_sides() {
        let stack = ThreadNetworkDiagnostics::<_, 2>::new(&Stack, 0);
        stack.record(Event::ConnectionStatus(ConnectionStatusEnum::NotConnected));
        stack.record(Event::NetworkFaultChange {
            current: heapless::Vec::from_slice(&[NetworkFaultEnum::LinkDown]).expect("fits"),
            previous: heapless::Vec::new(),
        });
        let drained = stack.take_events();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[1].id(), NETWORK_FAULT_CHANGE);
        assert_eq!(
            drained[1].priority(),
            EventPriority::Info,
            "§11.14.8 gives both events INFO priority, which is what decides which of the event \
             store's three rings the record lands in"
        );

        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new_in(&mut buf, crate::tlv::ContainerKind::Structure);
        drained[1].encode(&mut w, Tag::Context(7)).expect("encode");
        assert_eq!(
            w.finish().expect("finish"),
            // struct ctx-7 { ctx-0 = [LinkDown], ctx-1 = [] }
            [
                0x35, 0x07, 0x36, 0x00, 0x04, 0x01, 0x18, 0x36, 0x01, 0x18, 0x18
            ]
        );
        assert!(stack.take_events().is_empty());
    }

    /// Core §2.13's provisional elements are off in the default build: a device that advertised
    /// `ExtAddress` today could be non-conformant after a 1.6.x revision moved it, and the
    /// certifiable build is the one you get without asking.
    #[test]
    fn the_two_provisional_attributes_are_behind_the_provisional_feature() {
        let advertised = advertises(0, &ALL_OPTIONAL, EXT_ADDRESS);
        assert_eq!(advertised, cfg!(feature = "provisional"));
        assert_eq!(
            advertises(0, &ALL_OPTIONAL, RLOC16),
            cfg!(feature = "provisional")
        );
        assert!(
            !COUNTERS.contains(&EXT_ADDRESS),
            "the counters table is counters, and nothing else"
        );
    }

    /// §11.14.4's features must not invent elements the revision does not define.
    #[test]
    fn an_undefined_feature_is_refused() {
        assert!(conforming(1 << 4, &Optional::NONE).is_err());
    }
}
