//! The Network Commissioning cluster against Core §11.9.
//!
//! Two things here are checkable against the specification's own text rather than against a
//! second copy of this crate's opinion:
//!
//! 1. **§11.9.7.10 publishes two worked examples of `ReorderNetwork`** — an initial list of
//!    four networks and what two different reorderings must produce. Both are tests, and
//!    they are what pins "all other entries … retain their existing relative order between
//!    each other" to something concrete.
//! 2. **The Thread Operational Dataset is Thread's TLV encoding**, and §11.9.7.4 makes its
//!    Extended PAN ID the `NetworkID`. The parse is exercised against well-formed, extended-
//!    length, truncated and absent-field datasets.
//!
//! Everything else is the command table as literals, and the ordering rules driven through
//! the interaction model.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use core::cell::{Cell, RefCell};

use matter_kit::clusters::network_commissioning::{
    self as netcomm, Capabilities, ConnectOutcome, EthernetDriver, NetworkCommissioning,
    NetworkDriver, NetworkKind, NetworkStatus, NetworkStore, ScanResults, ThreadCapabilities,
    ThreadScanResult, WiFiBand, WiFiScanResult, WiFiSecurity, thread_extended_pan_id,
};
use matter_kit::clusters::{Cluster, general_commissioning};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::im::{
    AccessControl, AttributePath, ClusterHandler, CommandData, CommandPath, InteractionContext,
    InvokeResponse, InvokeResponseMessage, Outcome, Server, Status,
};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

// --- The tables ------------------------------------------------------------------------------

#[test]
fn ids_and_revision_match_section_11_9() {
    assert_eq!(netcomm::ID, 0x0031);
    assert_eq!(netcomm::REVISION, 2);
    assert_eq!(netcomm::FEATURE_WIFI, 1 << 0);
    assert_eq!(netcomm::FEATURE_THREAD, 1 << 1);
    assert_eq!(netcomm::FEATURE_ETHERNET, 1 << 2);

    assert_eq!(netcomm::MAX_NETWORKS, 0x0000);
    assert_eq!(netcomm::NETWORKS, 0x0001);
    assert_eq!(netcomm::SCAN_MAX_TIME_SECONDS, 0x0002);
    assert_eq!(netcomm::CONNECT_MAX_TIME_SECONDS, 0x0003);
    assert_eq!(netcomm::INTERFACE_ENABLED, 0x0004);
    assert_eq!(netcomm::LAST_NETWORKING_STATUS, 0x0005);
    assert_eq!(netcomm::LAST_NETWORK_ID, 0x0006);
    assert_eq!(netcomm::LAST_CONNECT_ERROR_VALUE, 0x0007);
    assert_eq!(netcomm::SUPPORTED_WIFI_BANDS, 0x0008);
    assert_eq!(netcomm::SUPPORTED_THREAD_FEATURES, 0x0009);
    assert_eq!(netcomm::THREAD_VERSION, 0x000A);

    assert_eq!(netcomm::SCAN_NETWORKS, 0x00);
    assert_eq!(netcomm::SCAN_NETWORKS_RESPONSE, 0x01);
    assert_eq!(netcomm::ADD_OR_UPDATE_WIFI_NETWORK, 0x02);
    assert_eq!(netcomm::ADD_OR_UPDATE_THREAD_NETWORK, 0x03);
    assert_eq!(netcomm::REMOVE_NETWORK, 0x04);
    assert_eq!(netcomm::NETWORK_CONFIG_RESPONSE, 0x05);
    assert_eq!(netcomm::CONNECT_NETWORK, 0x06);
    assert_eq!(netcomm::CONNECT_NETWORK_RESPONSE, 0x07);
    assert_eq!(netcomm::REORDER_NETWORK, 0x08);
}

#[test]
fn status_values_match_section_11_9_5_4() {
    assert_eq!(NetworkStatus::Success.value(), 0);
    assert_eq!(NetworkStatus::OutOfRange.value(), 1);
    assert_eq!(NetworkStatus::BoundsExceeded.value(), 2);
    assert_eq!(NetworkStatus::NetworkIdNotFound.value(), 3);
    assert_eq!(NetworkStatus::DuplicateNetworkId.value(), 4);
    assert_eq!(NetworkStatus::NetworkNotFound.value(), 5);
    assert_eq!(NetworkStatus::RegulatoryError.value(), 6);
    assert_eq!(NetworkStatus::AuthFailure.value(), 7);
    assert_eq!(NetworkStatus::UnsupportedSecurity.value(), 8);
    assert_eq!(NetworkStatus::OtherConnectionFailure.value(), 9);
    assert_eq!(NetworkStatus::Ipv6Failed.value(), 10);
    assert_eq!(NetworkStatus::IpBindFailed.value(), 11);
    assert_eq!(NetworkStatus::UnknownError.value(), 12);

    // §11.9.5.3's WiFiBandEnum and §11.9.5.1's WiFiSecurityBitmap.
    assert_eq!(WiFiBand::Band2G4.value(), 0);
    assert_eq!(WiFiBand::Band3G65.value(), 1);
    assert_eq!(WiFiBand::Band5G.value(), 2);
    assert_eq!(WiFiBand::Band6G.value(), 3);
    assert_eq!(WiFiBand::Band60G.value(), 4);
    assert_eq!(WiFiBand::Band1G.value(), 5);
    assert_eq!(WiFiSecurity::UNENCRYPTED.bits(), 1 << 0);
    assert_eq!(WiFiSecurity::WEP.bits(), 1 << 1);
    assert_eq!(WiFiSecurity::WPA_PERSONAL.bits(), 1 << 2);
    assert_eq!(WiFiSecurity::WPA2_PERSONAL.bits(), 1 << 3);
    assert_eq!(WiFiSecurity::WPA3_PERSONAL.bits(), 1 << 4);
    // §11.9.5.2's ThreadCapabilitiesBitmap.
    assert_eq!(ThreadCapabilities::IS_BORDER_ROUTER_CAPABLE.bits(), 1 << 0);
    assert_eq!(ThreadCapabilities::IS_ROUTER_CAPABLE.bits(), 1 << 1);
    assert_eq!(
        ThreadCapabilities::IS_SLEEPY_END_DEVICE_CAPABLE.bits(),
        1 << 2
    );
    assert_eq!(ThreadCapabilities::IS_FULL_THREAD_DEVICE.bits(), 1 << 3);
    assert_eq!(
        ThreadCapabilities::IS_SYNCHRONIZED_SLEEPY_END_DEVICE_CAPABLE.bits(),
        1 << 4
    );
}

#[test]
fn an_ethernet_instance_has_no_commands_and_a_wifi_one_has_five() {
    // §11.9.7's whole command table is `WI | TH`, so an Ethernet interface accepts nothing.
    let ethernet = netcomm::ethernet();
    assert!(ethernet.accepted_commands.is_empty());
    assert_eq!(ethernet.feature_map, netcomm::FEATURE_ETHERNET);
    assert!(ethernet.is_well_formed());
    // …and it has neither timing attribute, both of which are `WI | TH`.
    assert!(
        !ethernet
            .attribute_ids()
            .any(|id| id == netcomm::SCAN_MAX_TIME_SECONDS)
    );

    let wifi = netcomm::wifi();
    assert_eq!(wifi.feature_map, netcomm::FEATURE_WIFI);
    assert!(wifi.is_well_formed());
    assert_eq!(wifi.accepted_commands.len(), 5);
    assert!(
        wifi.accepted_command(netcomm::ADD_OR_UPDATE_WIFI_NETWORK)
            .is_some()
    );
    assert!(
        wifi.accepted_command(netcomm::ADD_OR_UPDATE_THREAD_NETWORK)
            .is_none(),
        "AddOrUpdateThreadNetwork is `TH`, not `WI | TH`"
    );
    assert!(
        wifi.attribute_ids()
            .any(|id| id == netcomm::SUPPORTED_WIFI_BANDS)
    );
    assert!(
        !wifi.attribute_ids().any(|id| id == netcomm::THREAD_VERSION),
        "ThreadVersion is `TH`"
    );

    let thread = netcomm::thread();
    assert_eq!(thread.feature_map, netcomm::FEATURE_THREAD);
    assert!(thread.is_well_formed());
    assert_eq!(thread.accepted_commands.len(), 5);
    assert!(
        thread
            .accepted_command(netcomm::ADD_OR_UPDATE_THREAD_NETWORK)
            .is_some()
    );
    assert!(
        thread
            .accepted_command(netcomm::ADD_OR_UPDATE_WIFI_NETWORK)
            .is_none()
    );

    // Every command is Administer: a network list names a home's access points.
    for cluster in [wifi, thread] {
        for command in cluster.accepted_commands {
            assert_eq!(command.access.invoke, Some(Privilege::Administer));
        }
        // `Networks` and `MaxNetworks` are `RA`, not `RV`.
        for id in [netcomm::NETWORKS, netcomm::MAX_NETWORKS] {
            let attribute = cluster.attribute(id).expect("attribute");
            assert_eq!(attribute.access.read, Some(Privilege::Administer));
        }
    }
}

// --- §11.9.7.10's worked examples ---------------------------------------------------------------

/// The initial state §11.9.7.10 prints, "exemplary of a Wi-Fi device".
fn worked_example() -> NetworkStore<8> {
    let mut store = NetworkStore::new();
    for id in [
        &b"FancyCat"[..],
        &b"BlueDolphin"[..],
        &b"Home-Guest"[..],
        &b"WillowTree"[..],
    ] {
        store.add_or_update(id).expect("add");
    }
    store.set_connected(b"BlueDolphin").expect("connect");
    store
}

fn ids(store: &NetworkStore<8>) -> Vec<&[u8]> {
    store.entries().iter().map(|e| e.id.as_slice()).collect()
}

#[test]
fn reorder_moving_an_entry_up_matches_the_specs_first_example() {
    // "On receiving ReorderNetwork with NetworkID = Home-Guest, NetworkIndex = 0 … FancyCat
    // and BlueDolphin moved 'down' and Home-Guest became the highest priority network."
    let mut store = worked_example();
    assert_eq!(store.reorder(b"Home-Guest", 0).expect("reorder"), 0);
    assert_eq!(
        ids(&store),
        vec![
            &b"Home-Guest"[..],
            &b"FancyCat"[..],
            &b"BlueDolphin"[..],
            &b"WillowTree"[..],
        ]
    );
    // The Connected flags travel with their entries.
    assert!(
        store.entries()[2].connected,
        "BlueDolphin is still connected"
    );
    assert!(!store.entries()[0].connected);
}

#[test]
fn reorder_moving_an_entry_down_matches_the_specs_second_example() {
    // "On receiving ReorderNetwork with NetworkID = FancyCat, NetworkIndex = 3 … BlueDolphin,
    // Home-Guest and WillowTree moved 'up' and FancyCat became the lowest priority network."
    let mut store = worked_example();
    assert_eq!(store.reorder(b"FancyCat", 3).expect("reorder"), 3);
    assert_eq!(
        ids(&store),
        vec![
            &b"BlueDolphin"[..],
            &b"Home-Guest"[..],
            &b"WillowTree"[..],
            &b"FancyCat"[..],
        ]
    );
    assert!(store.entries()[0].connected);
}

#[test]
fn reorder_refuses_an_unknown_id_and_an_index_past_the_end() {
    let mut store = worked_example();
    // "If the Networks attribute does not contain a matching entry … NetworkIdNotFound."
    assert_eq!(
        store.reorder(b"Nothing", 0),
        Err(NetworkStatus::NetworkIdNotFound)
    );
    // "If the NetworkIndex field has a value larger or equal to the current number of entries
    // … OutOfRange." Four entries, so index 4 is out.
    assert_eq!(
        store.reorder(b"FancyCat", 4),
        Err(NetworkStatus::OutOfRange)
    );
    // Neither changed anything.
    assert_eq!(ids(&store)[0], b"FancyCat");
    // "Re-ordering to the same NetworkIndex as the current location SHALL be considered as a
    // success and yield no visible changes."
    assert_eq!(store.reorder(b"FancyCat", 0).expect("same place"), 0);
    assert_eq!(ids(&store)[0], b"FancyCat");
}

#[test]
fn an_update_keeps_its_position_and_an_addition_goes_last() {
    // §11.9.7.5: an addition "SHALL append the configuration at the end of the existing list …
    // making this new network the one with least priority"; an update "SHALL update the
    // existing entry indexed by NetworkID … keeping existing position within the list".
    let mut store = worked_example();
    assert_eq!(store.add_or_update(b"FancyCat").expect("update"), 0);
    assert_eq!(ids(&store)[0], b"FancyCat");
    assert_eq!(store.entries().len(), 4, "an update adds nothing");

    assert_eq!(store.add_or_update(b"NewNet").expect("add"), 4);
    assert_eq!(ids(&store)[4], b"NewNet");
}

#[test]
fn removing_preserves_the_relative_order_of_what_remains() {
    // §11.9.7.6: "The relative order of the entries in the Networks attribute SHALL remain
    // unchanged, except for the removal of the requested network configuration." A
    // `swap_remove` would be the fast way and would silently reshuffle precedence.
    let mut store = worked_example();
    assert_eq!(store.remove(b"BlueDolphin").expect("remove"), 1);
    assert_eq!(
        ids(&store),
        vec![&b"FancyCat"[..], &b"Home-Guest"[..], &b"WillowTree"[..]]
    );
    assert_eq!(
        store.remove(b"BlueDolphin"),
        Err(NetworkStatus::NetworkIdNotFound)
    );
}

#[test]
fn a_full_list_refuses_an_addition_with_bounds_exceeded() {
    // "If the Networks attribute is already full, the command SHALL immediately respond with
    // NetworkConfigResponse having NetworkingStatus status field set to BoundsExceeded."
    let mut store = NetworkStore::<2>::new();
    store.add_or_update(b"one").expect("one");
    store.add_or_update(b"two").expect("two");
    assert_eq!(
        store.add_or_update(b"three"),
        Err(NetworkStatus::BoundsExceeded)
    );
    // …but an *update* of something already there still works on a full list.
    assert_eq!(store.add_or_update(b"one").expect("update"), 0);
}

#[test]
fn a_network_id_must_be_one_to_thirty_two_octets() {
    // §11.9.5.5's `1 to 32`, which §11.9.7.7 calls "Network identifier was invalid (e.g.
    // empty, too long, etc)".
    let mut store = NetworkStore::<4>::new();
    assert_eq!(store.add_or_update(b""), Err(NetworkStatus::OutOfRange));
    assert_eq!(
        store.add_or_update(&[0x41; 33]),
        Err(NetworkStatus::OutOfRange)
    );
    store.add_or_update(&[0x41; 32]).expect("exactly 32 fits");
}

#[test]
fn connecting_marks_exactly_one_entry_connected() {
    // §11.9.7.8: "the entry associated with the given Network configuration … SHALL indicate
    // its Connected field set to true, and all other entries, if any exist, SHALL indicate
    // their Connected field set to false."
    let mut store = worked_example();
    store.set_connected(b"WillowTree").expect("connect");
    let connected: Vec<&[u8]> = store
        .entries()
        .iter()
        .filter(|e| e.connected)
        .map(|e| e.id.as_slice())
        .collect();
    assert_eq!(connected, vec![&b"WillowTree"[..]]);
}

#[test]
fn the_fail_safe_snapshot_reverts_the_whole_list() {
    // §11.10.7.2.2 step 5: "Reset the configuration of all Network Commissioning Networks
    // attribute to their state prior to the Fail-Safe being armed."
    let mut store = worked_example();
    store.snapshot();
    store.remove(b"FancyCat").expect("remove");
    store.add_or_update(b"Intruder").expect("add");
    store.reorder(b"Intruder", 0).expect("reorder");
    assert_eq!(ids(&store)[0], b"Intruder");

    store.restore();
    assert_eq!(
        ids(&store),
        vec![
            &b"FancyCat"[..],
            &b"BlueDolphin"[..],
            &b"Home-Guest"[..],
            &b"WillowTree"[..],
        ]
    );
    assert!(store.entries()[1].connected, "and the Connected flags too");
}

#[test]
fn re_arming_within_one_period_does_not_move_the_snapshot() {
    // `ArmFailSafe` may be called repeatedly inside one context. The state to revert to is
    // still the one from before the *first* arm — otherwise a commissioner could launder a
    // half-finished change into the baseline by re-arming after making it.
    let mut store = worked_example();
    store.snapshot();
    store.remove(b"FancyCat").expect("remove");
    store.snapshot(); // a second ArmFailSafe on the same context
    store.restore();
    assert_eq!(ids(&store)[0], b"FancyCat");
}

#[test]
fn commissioning_complete_keeps_the_list() {
    let mut store = worked_example();
    store.snapshot();
    store.remove(b"FancyCat").expect("remove");
    store.commit();
    store.restore(); // a later expiry has nothing to revert to
    assert_eq!(ids(&store)[0], b"BlueDolphin");
}

// --- The Thread dataset -------------------------------------------------------------------------

#[test]
fn the_extended_pan_id_is_read_out_of_a_thread_dataset() {
    // §11.9.7.4: "The XPAN ID in the OperationalDataset serves as the NetworkID". Thread's
    // TLV encoding is type, length, value; type 2 is the Extended PAN ID and is 8 octets.
    // Channel (type 0, 3 octets), then Extended PAN ID (type 2, 8 octets), then PAN ID
    // (type 1, 2 octets).
    let dataset = [
        0x00, 0x03, 0x00, 0x00, 0x0F, // Channel
        0x02, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, // Extended PAN ID
        0x01, 0x02, 0x12, 0x34, // PAN ID
    ];
    assert_eq!(
        thread_extended_pan_id(&dataset),
        Some([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03])
    );

    // A length of 0xFF introduces a 16-bit extended length, which has to be skipped correctly
    // or everything after it is read at the wrong offset.
    let mut extended = vec![0x05, 0xFF, 0x00, 0x10];
    extended.extend_from_slice(&[0xAA; 16]);
    extended.extend_from_slice(&[0x02, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    assert_eq!(
        thread_extended_pan_id(&extended),
        Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    );
}

#[test]
fn a_malformed_thread_dataset_yields_no_network_id() {
    // Each of these is "a value different than Success and consistent with the error" — a
    // dataset with no Extended PAN ID has no NetworkID to key an entry by.
    assert_eq!(thread_extended_pan_id(&[]), None);
    // A field that claims more bytes than are present.
    assert_eq!(thread_extended_pan_id(&[0x02, 0x08, 0x01, 0x02]), None);
    // An Extended PAN ID of the wrong length is not one.
    assert_eq!(
        thread_extended_pan_id(&[0x02, 0x04, 0x01, 0x02, 0x03, 0x04]),
        None
    );
    // A dataset with fields but no type 2.
    assert_eq!(
        thread_extended_pan_id(&[0x00, 0x03, 0x00, 0x00, 0x0F, 0x01, 0x02, 0x12, 0x34]),
        None
    );
    // A truncated extended-length header.
    assert_eq!(thread_extended_pan_id(&[0x05, 0xFF, 0x00]), None);
}

#[test]
fn a_thread_dataset_never_loops_on_any_input() {
    // The parse walks a length-prefixed chain, which is exactly the shape that loops forever
    // on a zero-length field if the cursor is not advanced past the header.
    for byte in 0u8..=255 {
        for len in [0u8, 1, 8, 0xFE, 0xFF] {
            let dataset = [byte, len, 0x00, 0x00, 0x00, 0x00];
            let _ = thread_extended_pan_id(&dataset);
        }
    }
}

// --- Through the interaction model ---------------------------------------------------------------

/// A Wi-Fi driver that remembers what it was told and answers what a test asks it to.
#[derive(Default)]
struct FakeWiFi {
    /// What `AddOrUpdateWiFiNetwork` handed over. The cluster must never store these itself.
    credentials: RefCell<Vec<(Vec<u8>, Vec<u8>)>>,
    connect: Cell<Option<ConnectOutcome>>,
    scan_status: Cell<Option<NetworkStatus>>,
    last_scan_ssid: RefCell<Option<Vec<u8>>>,
    scanned: Cell<bool>,
}

impl NetworkDriver for FakeWiFi {
    fn kind(&self) -> NetworkKind {
        NetworkKind::WiFi
    }

    fn scan(&self, ssid: Option<&[u8]>, results: &mut ScanResults<'_, '_>) -> NetworkStatus {
        self.scanned.set(true);
        *self.last_scan_ssid.borrow_mut() = ssid.map(<[u8]>::to_vec);
        let status = self.scan_status.get().unwrap_or(NetworkStatus::Success);
        if !status.is_success() {
            return status;
        }
        results
            .wifi(&WiFiScanResult {
                security: WiFiSecurity::WPA2_PERSONAL | WiFiSecurity::WPA3_PERSONAL,
                ssid: b"FancyCat",
                bssid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                channel: 11,
                band: Some(WiFiBand::Band2G4),
                rssi: Some(-52),
            })
            .expect("fits");
        status
    }

    fn add_or_update_wifi(&self, ssid: &[u8], credentials: &[u8]) -> NetworkStatus {
        self.credentials
            .borrow_mut()
            .push((ssid.to_vec(), credentials.to_vec()));
        NetworkStatus::Success
    }

    fn forget(&self, id: &[u8]) {
        self.credentials.borrow_mut().retain(|(ssid, _)| ssid != id);
    }

    fn connect(&self, _id: &[u8]) -> ConnectOutcome {
        self.connect.get().unwrap_or_else(ConnectOutcome::success)
    }

    fn set_interface_enabled(&self, _enabled: bool) -> Result<(), Status> {
        Ok(())
    }
}

/// A Thread driver that accepts every dataset.
#[derive(Default)]
struct FakeThread {
    datasets: RefCell<Vec<Vec<u8>>>,
}

impl NetworkDriver for FakeThread {
    fn kind(&self) -> NetworkKind {
        NetworkKind::Thread
    }

    fn scan(&self, _ssid: Option<&[u8]>, results: &mut ScanResults<'_, '_>) -> NetworkStatus {
        results
            .thread(&ThreadScanResult {
                pan_id: 0x1234,
                extended_pan_id: 0xDEAD_BEEF_0001_0203,
                network_name: "matter-kit",
                channel: 15,
                version: 4,
                extended_address: [1, 2, 3, 4, 5, 6, 7, 8],
                rssi: -60,
                lqi: 200,
            })
            .expect("fits");
        NetworkStatus::Success
    }

    fn add_or_update_thread(&self, dataset: &[u8]) -> NetworkStatus {
        self.datasets.borrow_mut().push(dataset.to_vec());
        NetworkStatus::Success
    }

    fn connect(&self, _id: &[u8]) -> ConnectOutcome {
        ConnectOutcome::success()
    }
}

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

fn armed_fail_safe() -> RefCell<FailSafe> {
    let mut fail_safe = FailSafe::new(BasicCommissioningInfo::default());
    fail_safe.arm(600, 0, None, at(0), false);
    RefCell::new(fail_safe)
}

fn fields(build: impl FnOnce(&mut TlvWriter<'_>)) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).expect("open");
    build(&mut w);
    w.end_container().expect("close");
    w.finish().expect("finish").to_vec()
}

const WIFI_CLUSTERS: &[ClusterDescriptor<'static>] = &[netcomm::wifi()];
const THREAD_CLUSTERS: &[ClusterDescriptor<'static>] = &[netcomm::thread()];
const ETHERNET_CLUSTERS: &[ClusterDescriptor<'static>] = &[netcomm::ethernet()];

fn node(clusters: &'static [ClusterDescriptor<'static>]) -> Node<'static> {
    // A `static` endpoint slice per shape, so the node outlives every borrow of it.
    static WIFI_EP: &[Endpoint<'static>] = &[Endpoint::new(0, WIFI_CLUSTERS)];
    static THREAD_EP: &[Endpoint<'static>] = &[Endpoint::new(0, THREAD_CLUSTERS)];
    static ETHERNET_EP: &[Endpoint<'static>] = &[Endpoint::new(0, ETHERNET_CLUSTERS)];
    if core::ptr::eq(clusters, WIFI_CLUSTERS) {
        Node::new(WIFI_EP)
    } else if core::ptr::eq(clusters, THREAD_CLUSTERS) {
        Node::new(THREAD_EP)
    } else {
        Node::new(ETHERNET_EP)
    }
}

/// Invokes one command and returns the response command id and its fields.
fn invoke<'b, D: NetworkDriver, const N: usize>(
    node: Node<'_>,
    cluster: &NetworkCommissioning<'_, D, N>,
    command: u32,
    payload: &'b [u8],
    ctx: &InteractionContext<'_>,
    buf: &'b mut [u8],
) -> Result<(u32, &'b [u8]), Status> {
    let data = CommandData {
        fields: Some(payload),
        ..CommandData::new(CommandPath::command(0, netcomm::ID, command))
    };
    let mut scratch = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(node, &access, &cluster, 8);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], ctx, false, &mut scratch, buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    match response
        .responses()
        .expect("responses")
        .next()
        .expect("one")
        .expect("decode")
    {
        InvokeResponse::Command(c) => Ok((
            c.path.command.expect("response id"),
            c.fields.unwrap_or(&[]),
        )),
        InvokeResponse::Status(s) => Err(s.status.status),
    }
}

/// The context-tagged fields of a response structure, as (tag, unsigned) pairs where they are
/// unsigned.
fn response_field(bytes: &[u8], tag: u8) -> Option<u64> {
    let mut reader = TlvReader::new_in(bytes, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    let depth = reader.depth();
    while let Some(element) = reader.next_element().expect("read") {
        if reader.depth() < depth {
            break;
        }
        if element.tag == Tag::Context(tag) {
            return element.unsigned().ok();
        }
        reader.skip_value(&element).expect("skip");
    }
    None
}

fn ctx(now: Instant) -> InteractionContext<'static> {
    InteractionContext {
        now,
        ..InteractionContext::default()
    }
}

#[test]
fn a_wifi_network_is_added_connected_and_removed() {
    let driver = FakeWiFi::default();
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(WIFI_CLUSTERS);
    let ctx = ctx(at(1));
    let mut buf = [0u8; 2048];

    let add = fields(|w| {
        w.octets(Tag::Context(0), b"FancyCat").expect("ssid");
        w.octets(Tag::Context(1), b"correcthorsebattery")
            .expect("credentials");
        w.unsigned(Tag::Context(2), 7).expect("breadcrumb");
    });
    let (id, response) = invoke(
        node,
        &cluster,
        netcomm::ADD_OR_UPDATE_WIFI_NETWORK,
        &add,
        &ctx,
        &mut buf,
    )
    .expect("add");
    assert_eq!(id, netcomm::NETWORK_CONFIG_RESPONSE);
    assert_eq!(response_field(response, 0), Some(0), "Success");
    assert_eq!(response_field(response, 2), Some(0), "NetworkIndex 0");

    // The credentials reached the driver and nothing else.
    assert_eq!(
        driver.credentials.borrow().as_slice(),
        &[(b"FancyCat".to_vec(), b"correcthorsebattery".to_vec())]
    );
    // §11.9.7.1.2: the Breadcrumb lands on success.
    assert_eq!(fail_safe.borrow().breadcrumb(), 7);

    // ConnectNetwork.
    let connect = fields(|w| {
        w.octets(Tag::Context(0), b"FancyCat").expect("id");
    });
    let (id, response) = invoke(
        node,
        &cluster,
        netcomm::CONNECT_NETWORK,
        &connect,
        &ctx,
        &mut buf,
    )
    .expect("connect");
    assert_eq!(id, netcomm::CONNECT_NETWORK_RESPONSE);
    assert_eq!(response_field(response, 0), Some(0));
    assert!(cluster.store().entries()[0].connected);

    // RemoveNetwork takes the credentials with it.
    let remove = fields(|w| {
        w.octets(Tag::Context(0), b"FancyCat").expect("id");
    });
    let (_, response) = invoke(
        node,
        &cluster,
        netcomm::REMOVE_NETWORK,
        &remove,
        &ctx,
        &mut buf,
    )
    .expect("remove");
    assert_eq!(response_field(response, 0), Some(0));
    assert!(cluster.store().entries().is_empty());
    assert!(
        driver.credentials.borrow().is_empty(),
        "removing a network must not leave its credentials behind"
    );
}

#[test]
fn every_command_needs_an_armed_fail_safe() {
    // §11.9.7.1, §11.9.7.3, §11.9.7.4 and §11.9.7.6 each say so: "If this command is received
    // without an armed fail-safe context … FAILSAFE_REQUIRED."
    let driver = FakeWiFi::default();
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(WIFI_CLUSTERS);
    let ctx = ctx(at(0));
    let mut buf = [0u8; 2048];

    let payloads = [
        (netcomm::SCAN_NETWORKS, fields(|_| {})),
        (
            netcomm::ADD_OR_UPDATE_WIFI_NETWORK,
            fields(|w| {
                w.octets(Tag::Context(0), b"x").expect("ssid");
                w.octets(Tag::Context(1), b"y").expect("credentials");
            }),
        ),
        (
            netcomm::REMOVE_NETWORK,
            fields(|w| {
                w.octets(Tag::Context(0), b"x").expect("id");
            }),
        ),
        (
            netcomm::CONNECT_NETWORK,
            fields(|w| {
                w.octets(Tag::Context(0), b"x").expect("id");
            }),
        ),
        (
            netcomm::REORDER_NETWORK,
            fields(|w| {
                w.octets(Tag::Context(0), b"x").expect("id");
                w.unsigned(Tag::Context(1), 0).expect("index");
            }),
        ),
    ];
    for (command, payload) in &payloads {
        assert_eq!(
            invoke(node, &cluster, *command, payload, &ctx, &mut buf).unwrap_err(),
            Status::FailsafeRequired,
            "command {command:#04x}"
        );
    }
    assert!(!driver.scanned.get(), "nothing reached the radio");
}

#[test]
fn a_scan_reports_its_results_and_a_failed_scan_reports_none() {
    // §11.9.7.2: "Results are valid only if NetworkingStatus is Success." A failed scan that
    // still emitted an empty array would be read as "nothing in range", which is a different
    // and wrong answer.
    let driver = FakeWiFi::default();
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(WIFI_CLUSTERS);
    let ctx = ctx(at(1));
    let mut buf = [0u8; 2048];

    let request = fields(|_| {});
    let (id, response) = invoke(
        node,
        &cluster,
        netcomm::SCAN_NETWORKS,
        &request,
        &ctx,
        &mut buf,
    )
    .expect("scan");
    assert_eq!(id, netcomm::SCAN_NETWORKS_RESPONSE);
    assert_eq!(response_field(response, 0), Some(0));

    // Field 2 is the Wi-Fi list; field 3 is Thread's, and a Wi-Fi instance never writes it.
    let mut reader = TlvReader::new_in(response, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    reader.next_element().expect("read").expect("status");
    let array = reader.next_element().expect("read").expect("results");
    assert_eq!(array.tag, Tag::Context(2));
    assert_eq!(array.value.container(), Some(ContainerKind::Array));
    let entry = reader.next_element().expect("read").expect("entry");
    assert_eq!(entry.value.container(), Some(ContainerKind::Structure));
    let security = reader.next_element().expect("read").expect("security");
    assert_eq!(security.tag, Tag::Context(0));
    assert_eq!(
        security.unsigned().expect("uint"),
        u64::from((WiFiSecurity::WPA2_PERSONAL | WiFiSecurity::WPA3_PERSONAL).bits())
    );

    // A failed scan: status only.
    driver.scan_status.set(Some(NetworkStatus::RegulatoryError));
    let (_, response) = invoke(
        node,
        &cluster,
        netcomm::SCAN_NETWORKS,
        &request,
        &ctx,
        &mut buf,
    )
    .expect("scan");
    assert_eq!(
        response_field(response, 0),
        Some(u64::from(NetworkStatus::RegulatoryError.value()))
    );
    let mut reader = TlvReader::new_in(response, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    reader.next_element().expect("read").expect("status");
    let next = reader.next_element().expect("read").expect("next");
    assert_eq!(
        next.value,
        matter_kit::tlv::Value::EndOfContainer,
        "a failed scan carries no results"
    );
}

#[test]
fn a_directed_scan_passes_the_ssid_and_a_thread_instance_ignores_it() {
    // §11.9.7.1: "Scanning for a specific network (i.e. directed scanning) takes place if a
    // network identifier … is provided", and "This field SHALL be ignored for ScanNetworks
    // invocations on non-Wi-Fi server instances."
    let driver = FakeWiFi::default();
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let ctx = ctx(at(1));
    let mut buf = [0u8; 2048];

    let directed = fields(|w| {
        w.octets(Tag::Context(0), b"FancyCat").expect("ssid");
    });
    invoke(
        node(WIFI_CLUSTERS),
        &cluster,
        netcomm::SCAN_NETWORKS,
        &directed,
        &ctx,
        &mut buf,
    )
    .expect("scan");
    assert_eq!(
        driver.last_scan_ssid.borrow().as_deref(),
        Some(&b"FancyCat"[..])
    );

    // A null SSID means "all BSSID in range", exactly as an absent one does.
    let null_ssid = fields(|w| {
        w.null(Tag::Context(0)).expect("null");
    });
    invoke(
        node(WIFI_CLUSTERS),
        &cluster,
        netcomm::SCAN_NETWORKS,
        &null_ssid,
        &ctx,
        &mut buf,
    )
    .expect("scan");
    assert_eq!(driver.last_scan_ssid.borrow().as_deref(), None);

    // The same directed request on a Thread instance: the field is dropped before the driver.
    let thread_driver = FakeThread::default();
    let thread_cluster =
        NetworkCommissioning::<_, 4>::new(&thread_driver, &fail_safe, Capabilities::default());
    let (_, response) = invoke(
        node(THREAD_CLUSTERS),
        &thread_cluster,
        netcomm::SCAN_NETWORKS,
        &directed,
        &ctx,
        &mut buf,
    )
    .expect("scan");
    assert_eq!(response_field(response, 0), Some(0));
    // …and the results land under field 3, not field 2.
    let mut reader = TlvReader::new_in(response, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    reader.next_element().expect("read").expect("status");
    let array = reader.next_element().expect("read").expect("results");
    assert_eq!(array.tag, Tag::Context(3));
}

#[test]
fn a_failed_connection_reports_its_error_value_and_leaves_nothing_connected() {
    // §11.9.7.9: the three `Last*` attributes are set together, and `ErrorValue` is mandatory
    // and nullable — present and null on success, present and set on an 802.11 failure.
    let driver = FakeWiFi::default();
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(WIFI_CLUSTERS);
    let ctx = ctx(at(1));
    let mut buf = [0u8; 2048];

    let add = fields(|w| {
        w.octets(Tag::Context(0), b"FancyCat").expect("ssid");
        w.octets(Tag::Context(1), b"hunter2hunter2").expect("creds");
    });
    invoke(
        node,
        &cluster,
        netcomm::ADD_OR_UPDATE_WIFI_NETWORK,
        &add,
        &ctx,
        &mut buf,
    )
    .expect("add");

    // IEEE 802.11-2020 Table 9-50 status 15: "Authentication rejected because of challenge
    // failure" — the kind of value §11.9.7.9 asks for.
    driver.connect.set(Some(ConnectOutcome::failed_with(
        NetworkStatus::AuthFailure,
        15,
    )));
    let connect = fields(|w| {
        w.octets(Tag::Context(0), b"FancyCat").expect("id");
        w.unsigned(Tag::Context(1), 99).expect("breadcrumb");
    });
    let (_, response) = invoke(
        node,
        &cluster,
        netcomm::CONNECT_NETWORK,
        &connect,
        &ctx,
        &mut buf,
    )
    .expect("connect");
    assert_eq!(
        response_field(response, 0),
        Some(u64::from(NetworkStatus::AuthFailure.value()))
    );
    assert!(!cluster.store().entries()[0].connected);
    // "If the command fails, the Breadcrumb attribute … SHALL be left unchanged."
    assert_eq!(fail_safe.borrow().breadcrumb(), 0);

    // The `Last*` attributes now describe the attempt.
    let read = |attribute: u32| -> Vec<u8> {
        let resolved = node.resolve(0, netcomm::ID, attribute).expect("path");
        let mut out = [0u8; 256];
        let mut w = TlvWriter::new(&mut out);
        cluster
            .read(&resolved, &ctx, &mut w, Tag::Anonymous)
            .expect("read");
        w.finish().expect("finish").to_vec()
    };
    let status = read(netcomm::LAST_NETWORKING_STATUS);
    let mut reader = TlvReader::new(&status);
    assert_eq!(
        reader
            .next_element()
            .expect("read")
            .expect("value")
            .unsigned()
            .expect("uint"),
        u64::from(NetworkStatus::AuthFailure.value())
    );
    let error = read(netcomm::LAST_CONNECT_ERROR_VALUE);
    let mut reader = TlvReader::new(&error);
    assert_eq!(
        reader
            .next_element()
            .expect("read")
            .expect("value")
            .signed()
            .expect("int"),
        15
    );
    let id = read(netcomm::LAST_NETWORK_ID);
    let mut reader = TlvReader::new(&id);
    assert_eq!(
        reader
            .next_element()
            .expect("read")
            .expect("value")
            .octets()
            .expect("octets"),
        b"FancyCat"
    );
}

#[test]
fn the_last_attributes_are_null_until_something_is_attempted() {
    // §11.9.6.6: "If no such attempt was made, or no network configurations exist in the
    // Networks attribute, then this attribute SHALL be set to null." Zero would mean
    // `Success`, which is a claim about an attempt that never happened.
    let driver = FakeWiFi::default();
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(WIFI_CLUSTERS);
    let ctx = ctx(at(0));

    for attribute in [
        netcomm::LAST_NETWORKING_STATUS,
        netcomm::LAST_NETWORK_ID,
        netcomm::LAST_CONNECT_ERROR_VALUE,
    ] {
        let resolved = node.resolve(0, netcomm::ID, attribute).expect("path");
        let mut out = [0u8; 64];
        let mut w = TlvWriter::new(&mut out);
        cluster
            .read(&resolved, &ctx, &mut w, Tag::Anonymous)
            .expect("read");
        let bytes = w.finish().expect("finish").to_vec();
        let mut reader = TlvReader::new(&bytes);
        assert!(
            reader
                .next_element()
                .expect("read")
                .expect("value")
                .value
                .is_null(),
            "{attribute:#06x} must be null before any attempt"
        );
    }
}

#[test]
fn a_thread_network_is_keyed_by_its_extended_pan_id() {
    let driver = FakeThread::default();
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(THREAD_CLUSTERS);
    let ctx = ctx(at(1));
    let mut buf = [0u8; 2048];

    let dataset = [
        0x00, 0x03, 0x00, 0x00, 0x0F, // Channel
        0x02, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, // Extended PAN ID
    ];
    let add = fields(|w| {
        w.octets(Tag::Context(0), &dataset).expect("dataset");
    });
    let (id, response) = invoke(
        node,
        &cluster,
        netcomm::ADD_OR_UPDATE_THREAD_NETWORK,
        &add,
        &ctx,
        &mut buf,
    )
    .expect("add");
    assert_eq!(id, netcomm::NETWORK_CONFIG_RESPONSE);
    assert_eq!(response_field(response, 0), Some(0));
    assert_eq!(
        cluster.store().entries()[0].id.as_slice(),
        &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03]
    );
    // The dataset reached the driver whole and opaque.
    assert_eq!(driver.datasets.borrow()[0], dataset.to_vec());

    // A dataset with no Extended PAN ID has no NetworkID.
    let bad = fields(|w| {
        w.octets(Tag::Context(0), &[0x00, 0x03, 0x00, 0x00, 0x0F])
            .expect("dataset");
    });
    let (_, response) = invoke(
        node,
        &cluster,
        netcomm::ADD_OR_UPDATE_THREAD_NETWORK,
        &bad,
        &ctx,
        &mut buf,
    )
    .expect("add");
    assert_eq!(
        response_field(response, 0),
        Some(u64::from(NetworkStatus::OutOfRange.value()))
    );
    assert_eq!(cluster.store().entries().len(), 1);
}

#[test]
fn a_wifi_instance_refuses_a_thread_command_and_the_reverse() {
    // The features are `O.a` — exactly one — and the commands follow. `UNSUPPORTED_COMMAND`
    // is what §8.8.2.3 gives for a command the cluster instance does not accept.
    let wifi = FakeWiFi::default();
    let thread = FakeThread::default();
    let fail_safe = armed_fail_safe();
    let wifi_cluster =
        NetworkCommissioning::<_, 4>::new(&wifi, &fail_safe, Capabilities::default());
    let thread_cluster =
        NetworkCommissioning::<_, 4>::new(&thread, &fail_safe, Capabilities::default());
    let ctx = ctx(at(1));
    let mut buf = [0u8; 2048];

    // The descriptor itself refuses first: the command is not in `AcceptedCommandList`.
    let thread_add = fields(|w| {
        w.octets(Tag::Context(0), &[0x02, 0x08, 0, 0, 0, 0, 0, 0, 0, 1])
            .expect("dataset");
    });
    assert_eq!(
        invoke(
            node(WIFI_CLUSTERS),
            &wifi_cluster,
            netcomm::ADD_OR_UPDATE_THREAD_NETWORK,
            &thread_add,
            &ctx,
            &mut buf
        )
        .unwrap_err(),
        Status::UnsupportedCommand
    );

    let wifi_add = fields(|w| {
        w.octets(Tag::Context(0), b"x").expect("ssid");
        w.octets(Tag::Context(1), b"y").expect("credentials");
    });
    assert_eq!(
        invoke(
            node(THREAD_CLUSTERS),
            &thread_cluster,
            netcomm::ADD_OR_UPDATE_WIFI_NETWORK,
            &wifi_add,
            &ctx,
            &mut buf
        )
        .unwrap_err(),
        Status::UnsupportedCommand
    );
}

#[test]
fn an_ethernet_instance_serves_one_network_and_refuses_to_be_disabled() {
    // §11.9.6.2: "Ethernet Network Commissioning Cluster instances SHALL always have exactly
    // one NetworkInfoStruct instance in their Networks attribute. There SHALL be no way to
    // add, update or remove Ethernet network configurations."
    let driver = EthernetDriver;
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 1>::new(&driver, &fail_safe, Capabilities::default());
    cluster.store_mut().seed(b"eth0", true).expect("seed");
    let node = node(ETHERNET_CLUSTERS);
    let ctx = ctx(at(1));

    let resolved = node
        .resolve(0, netcomm::ID, netcomm::NETWORKS)
        .expect("path");
    let mut out = [0u8; 256];
    let mut w = TlvWriter::new(&mut out);
    cluster
        .read(&resolved, &ctx, &mut w, Tag::Anonymous)
        .expect("read");
    let bytes = w.finish().expect("finish").to_vec();
    let mut reader = TlvReader::new(&bytes);
    reader.next_element().expect("read").expect("array");
    reader.next_element().expect("read").expect("struct");
    let id = reader.next_element().expect("read").expect("id");
    assert_eq!(id.octets().expect("octets"), b"eth0");
    let connected = reader.next_element().expect("read").expect("connected");
    assert!(connected.bool().expect("bool"));

    // §11.9.6.5: "If not supported, a write to this attribute with a value of false SHALL fail
    // with a status of INVALID_ACTION."
    let resolved = node
        .resolve(0, netcomm::ID, netcomm::INTERFACE_ENABLED)
        .expect("path");
    let write = |value: bool| {
        let mut buf = [0u8; 32];
        let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
        w.bool(Tag::Context(2), value).expect("bool");
        let encoded = w.finish().expect("finish").to_vec();
        cluster.write(&resolved, &encoded, matter_kit::im::WriteOp::Replace, &ctx)
    };
    assert_eq!(write(false), Err(Status::InvalidAction));
    assert!(cluster.is_enabled(), "and the attribute is left alone");
    assert_eq!(write(true), Ok(()));
}

#[test]
fn the_cluster_trait_id_matches_the_module_constant() {
    assert_eq!(
        <NetworkCommissioning<'_, EthernetDriver, 1> as Cluster>::ID,
        netcomm::ID
    );
    // The General Commissioning cluster is a different id on the same endpoint — the two are
    // adjacent in the specification and adjacent in every commissioning flow.
    assert_ne!(general_commissioning::ID, netcomm::ID);
}

#[test]
fn a_network_change_arms_the_fail_safes_rollback() {
    // §11.10.7.2.2 step 5 only fires if the fail-safe knows the list was touched. Nothing
    // else sets `changed_networks`, so a cluster that did not record it would leave the
    // device told that nothing needs reverting — and keep a half-configured network list
    // past the commissioner that abandoned it.
    let driver = FakeWiFi::default();
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(WIFI_CLUSTERS);
    let ctx = ctx(at(1));
    let mut buf = [0u8; 2048];

    assert!(
        !fail_safe
            .borrow()
            .armed(at(1))
            .expect("armed")
            .progress
            .changed_networks
    );

    let add = fields(|w| {
        w.octets(Tag::Context(0), b"FancyCat").expect("ssid");
        w.octets(Tag::Context(1), b"hunter2hunter2").expect("creds");
    });
    invoke(
        node,
        &cluster,
        netcomm::ADD_OR_UPDATE_WIFI_NETWORK,
        &add,
        &ctx,
        &mut buf,
    )
    .expect("add");

    assert!(
        fail_safe
            .borrow()
            .armed(at(1))
            .expect("armed")
            .progress
            .changed_networks,
        "the fail-safe must be told the list changed"
    );
    let cleanup = fail_safe
        .borrow_mut()
        .expire(Instant::MAX)
        .expect("expired");
    assert!(cleanup.restore_networks, "step 5 must be owed");

    // And applying it puts the list back the way a factory-fresh device had it.
    cluster.on_fail_safe_expired();
    assert!(cluster.store().entries().is_empty());
}

#[test]
fn the_snapshot_is_taken_once_per_fail_safe_period_not_once_per_command() {
    // The snapshot is lazy — taken on the first change of a period — so a second command must
    // not move the baseline. Otherwise a commissioner could launder a half-finished change
    // into the state the fail-safe would revert to.
    let driver = FakeWiFi::default();
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(WIFI_CLUSTERS);
    let ctx = ctx(at(1));
    let mut buf = [0u8; 2048];

    for ssid in [&b"One"[..], &b"Two"[..]] {
        let add = fields(|w| {
            w.octets(Tag::Context(0), ssid).expect("ssid");
            w.octets(Tag::Context(1), b"hunter2hunter2").expect("creds");
        });
        invoke(
            node,
            &cluster,
            netcomm::ADD_OR_UPDATE_WIFI_NETWORK,
            &add,
            &ctx,
            &mut buf,
        )
        .expect("add");
    }
    assert_eq!(cluster.store().entries().len(), 2);

    cluster.on_fail_safe_expired();
    assert!(
        cluster.store().entries().is_empty(),
        "both additions must be reverted, not just the second"
    );
}

/// A driver that keeps producing results and ignores the sink's refusals — which a real one
/// might, and which is exactly when a partial element would be written.
struct FloodingWiFi;

impl NetworkDriver for FloodingWiFi {
    fn kind(&self) -> NetworkKind {
        NetworkKind::WiFi
    }

    fn scan(&self, _ssid: Option<&[u8]>, results: &mut ScanResults<'_, '_>) -> NetworkStatus {
        for n in 0..200u8 {
            // Deliberately ignoring the error, which is the case under test.
            let _ = results.wifi(&WiFiScanResult {
                security: WiFiSecurity::WPA2_PERSONAL,
                ssid: &[n; 32],
                bssid: [n; 6],
                channel: u16::from(n),
                band: Some(WiFiBand::Band5G),
                rssi: Some(-40),
            });
        }
        NetworkStatus::Success
    }
}

#[test]
fn a_flooding_driver_produces_a_truncated_but_well_formed_list() {
    // §11.9.7.2 permits "a subset of possibilities, to avoid memory exhaustion on the cluster
    // server and avoid crossing the maximum command response size supported". What it does not
    // permit is a response a client cannot decode — so every result is spliced whole or not at
    // all, and once the list is full it stays full.
    let driver = FloodingWiFi;
    let fail_safe = armed_fail_safe();
    let cluster = NetworkCommissioning::<_, 4>::new(&driver, &fail_safe, Capabilities::default());
    let node = node(WIFI_CLUSTERS);
    let ctx = ctx(at(1));
    let mut buf = [0u8; 4096];

    let request = fields(|_| {});
    let (_, response) = invoke(
        node,
        &cluster,
        netcomm::SCAN_NETWORKS,
        &request,
        &ctx,
        &mut buf,
    )
    .expect("scan");
    assert_eq!(response_field(response, 0), Some(0), "Success");

    // Every entry decodes, and the array closes cleanly.
    let mut reader = TlvReader::new_in(response, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    reader.next_element().expect("read").expect("status");
    let array = reader.next_element().expect("read").expect("results");
    assert_eq!(array.value.container(), Some(ContainerKind::Array));
    let depth = reader.depth();
    let mut entries = 0usize;
    while let Some(element) = reader.next_element().expect("every element must decode") {
        if reader.depth() < depth {
            break;
        }
        assert_eq!(element.value.container(), Some(ContainerKind::Structure));
        reader.skip_value(&element).expect("a whole structure");
        entries += 1;
    }
    assert!(entries > 0, "some results fit");
    assert!(
        entries < 200,
        "and the rest were dropped rather than half-written"
    );
}
