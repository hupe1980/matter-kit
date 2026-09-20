//! A bridge's two new pieces: routing by endpoint, and Bridged Device Basic Information.
//!
//! A bridge is the first node where a cluster id stops being an address. Four endpoints serve
//! Descriptor; two serve On/Off. Everything below is about the consequences of that, plus the
//! one cluster §9.12 adds to describe a device the node does not contain.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use matter_kit::clusters::bridged_device_basic_information::{
    self as bdbi, BridgedDevice, BridgedDeviceBasicInformation, Event,
};
use matter_kit::clusters::generated::device_types::{AGGREGATOR, BRIDGED_NODE};
use matter_kit::clusters::on_off::{OnOff, OnOffHooks};
use matter_kit::clusters::{At, Descriptor, Endpoints, descriptor, validate_endpoint};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, DeviceType, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status, WriteOp,
};
use matter_kit::msg::{FabricIndex, VendorId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use core::cell::RefCell;

#[derive(Debug, Default)]
struct Lamp {
    on: RefCell<bool>,
}

impl OnOffHooks for Lamp {
    fn set(&self, on: bool) {
        *self.on.borrow_mut() = on;
    }
}

fn at(ms: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_millis(ms))
}

const KNOWN: BridgedDevice<'static> = BridgedDevice {
    vendor_name: Some("Example Lighting"),
    vendor_id: Some(VendorId(0xFFF1)),
    product_name: Some("Zigbee A19"),
    unique_id: Some("zb-0017880103a1b2c3"),
    serial_number: Some("A19-000123"),
    product_id: None,
    hardware_version: None,
    hardware_version_string: None,
    software_version: None,
    software_version_string: None,
    manufacturing_date: None,
    part_number: None,
    product_url: None,
    product_label: None,
    configuration_version: None,
};

/// A device the bridge knows almost nothing about.
const UNKNOWN: BridgedDevice<'static> = BridgedDevice {
    product_name: Some("Z-Wave Switch"),
    unique_id: Some("zw-generated-7f3a"),
    vendor_name: None,
    vendor_id: None,
    product_id: None,
    hardware_version: None,
    hardware_version_string: None,
    software_version: None,
    software_version_string: None,
    manufacturing_date: None,
    part_number: None,
    product_url: None,
    product_label: None,
    serial_number: None,
    configuration_version: None,
};

// --- Routing by endpoint ----------------------------------------------------------------------

struct Bridge<'a> {
    node: Node<'a>,
    lamps: &'a [Lamp; 2],
    on_offs: [OnOff<'a, Lamp>; 2],
    basics: [BridgedDeviceBasicInformation<'a>; 2],
}

fn bridge(lamps: &[Lamp; 2]) -> Bridge<'_> {
    let on_off = Box::leak(Box::new(
        OnOff::<Lamp>::conforming(0, &Optional::NONE).expect("sized"),
    ));
    let basic = Box::leak(Box::new(
        BridgedDeviceBasicInformation::conforming(0, &Optional::NONE).expect("sized"),
    ));
    let root: &'static [ClusterDescriptor<'static>] = Box::leak(Box::new([descriptor::cluster()]));
    let bridged: &'static [ClusterDescriptor<'static>] = Box::leak(Box::new([
        on_off.descriptor(),   // 0x0006
        descriptor::cluster(), // 0x001D
        basic.descriptor(),    // 0x0039
    ]));
    let types: &'static [DeviceType] = Box::leak(Box::new([DeviceType::new(0x0013, 3)]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([
        Endpoint::new(0, root),
        Endpoint::new(1, root),
        Endpoint::new(2, bridged).with_device_types(types),
        Endpoint::new(3, bridged).with_device_types(types),
    ]));
    Bridge {
        node: Node::new(endpoints),
        lamps,
        on_offs: [
            OnOff::new(&lamps[0], 0, None),
            OnOff::new(&lamps[1], 0, None),
        ],
        basics: [
            BridgedDeviceBasicInformation::new(KNOWN, true),
            BridgedDeviceBasicInformation::new(UNKNOWN, true),
        ],
    }
}

fn invoke(bridge: &Bridge<'_>, endpoint: u16, cluster: u32, command: u32) -> Status {
    let data = CommandData::new(CommandPath::command(endpoint, cluster, command));
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let handler = Endpoints((
        At::new(0, (Descriptor::new(bridge.node, 0).with_parts(&[1]),)),
        At::new(1, (Descriptor::new(bridge.node, 1).with_parts(&[2, 3]),)),
        At::new(
            2,
            (
                Descriptor::new(bridge.node, 2),
                &bridge.on_offs[0],
                &bridge.basics[0],
            ),
        ),
        At::new(
            3,
            (
                Descriptor::new(bridge.node, 3),
                &bridge.on_offs[1],
                &bridge.basics[1],
            ),
        ),
    ));
    let server = Server::new(bridge.node, &access, &handler, 8);
    let ctx = InteractionContext::new().with_fabric(FabricIndex(1));
    let (bytes, _) = server
        .serve_invoke([Ok(data)], &ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    match responses.next().expect("one response").expect("decode") {
        InvokeResponse::Status(status) => status.status.status,
        InvokeResponse::Command(_) => panic!("no response commands here"),
    }
}

#[test]
fn the_same_cluster_on_two_endpoints_is_two_instances() {
    // The whole reason `Endpoints`/`At` exists. A dispatcher keyed on the cluster id alone
    // would send both commands to whichever On/Off it found first, and a bridge would turn on
    // the wrong lamp — every time, silently.
    let lamps = [Lamp::default(), Lamp::default()];
    let bridge = bridge(&lamps);
    assert_eq!(
        invoke(&bridge, 2, matter_kit::clusters::on_off::ID, 0x01),
        Status::Success
    );
    assert!(*bridge.lamps[0].on.borrow());
    assert!(!*bridge.lamps[1].on.borrow(), "the wrong lamp came on");

    assert_eq!(
        invoke(&bridge, 3, matter_kit::clusters::on_off::ID, 0x01),
        Status::Success
    );
    assert!(*bridge.lamps[1].on.borrow());

    assert_eq!(
        invoke(&bridge, 2, matter_kit::clusters::on_off::ID, 0x00),
        Status::Success
    );
    assert!(!*bridge.lamps[0].on.borrow());
    assert!(*bridge.lamps[1].on.borrow(), "endpoint 3 was touched");
}

#[test]
fn an_endpoint_no_member_serves_is_unsupported_endpoint() {
    // Unreachable through the server, which resolves the path against the node first — so
    // this is the handler's own answer for a node whose descriptors list an endpoint nothing
    // implements. Reporting per path rather than panicking keeps that mistake survivable.
    let lamps = [Lamp::default(), Lamp::default()];
    let bridge = bridge(&lamps);
    let handler = Endpoints((
        At::new(2, (&bridge.on_offs[0],)),
        At::new(3, (&bridge.on_offs[1],)),
    ));
    let resolved = bridge
        .node
        .resolve(2, matter_kit::clusters::on_off::ID, 0x0000)
        .expect("OnOff");
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new(&mut buf);
    assert!(
        handler
            .read(
                &resolved,
                &InteractionContext::new(),
                &mut w,
                Tag::Anonymous
            )
            .is_ok()
    );

    let elsewhere = bridge
        .node
        .resolve(0, matter_kit::clusters::descriptor::ID, 0x0000);
    if let Ok(elsewhere) = elsewhere {
        let mut buf = [0u8; 32];
        let mut w = TlvWriter::new(&mut buf);
        assert_eq!(
            handler.read(
                &elsewhere,
                &InteractionContext::new(),
                &mut w,
                Tag::Anonymous
            ),
            Err(Status::UnsupportedEndpoint)
        );
    }
}

#[test]
fn the_parts_list_is_what_makes_an_endpoint_bridged() {
    // §9.13: "This cluster SHALL NOT be used on an endpoint that is not in the Descriptor
    // cluster PartsList of an endpoint with an Aggregator device type." The tree is the rule.
    let lamps = [Lamp::default(), Lamp::default()];
    let bridge = bridge(&lamps);
    let aggregator = Descriptor::new(bridge.node, 1).with_parts(&[2, 3]);
    let resolved = bridge
        .node
        .resolve(1, descriptor::ID, descriptor::PARTS_LIST)
        .expect("PartsList");
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    aggregator
        .read(
            &resolved,
            &InteractionContext::new(),
            &mut w,
            Tag::Anonymous,
        )
        .expect("read");
    let bytes = w.finish().unwrap();
    let mut reader = TlvReader::new(bytes);
    let array = reader.next_element().unwrap().unwrap();
    assert_eq!(array.value.container(), Some(ContainerKind::Array));
    let mut parts = Vec::new();
    loop {
        let entry = reader.next_element().unwrap().unwrap();
        if entry.value == Value::EndOfContainer {
            break;
        }
        if let Value::Unsigned(value) = entry.value {
            parts.push(value as u16);
        }
    }
    assert_eq!(parts, vec![2, 3]);
}

// --- Bridged Device Basic Information -----------------------------------------------------

#[test]
fn an_attribute_the_bridge_cannot_fill_is_absent_rather_than_blank() {
    // §9.13: "For such cases where the information for a particular attribute is not
    // available, the Bridge SHOULD NOT include the attribute" — and §9.13.5.1 turns that into
    // a SHALL per attribute. A client can then tell "the bridge does not know the vendor"
    // from "the vendor is called nothing", which an empty string cannot say.
    let mut known_buf = [0u32; 16];
    let mut unknown_buf = [0u32; 16];
    let known = BridgedDeviceBasicInformation::optional_for(&KNOWN, &mut known_buf);
    let unknown = BridgedDeviceBasicInformation::optional_for(&UNKNOWN, &mut unknown_buf);
    assert!(known.attributes.contains(&bdbi::VENDOR_ID));
    assert!(!unknown.attributes.contains(&bdbi::VENDOR_ID));
    assert!(!unknown.attributes.contains(&bdbi::SERIAL_NUMBER));

    // `NodeLabel` is always there: it is the *user's* name for the device, which the bridge
    // stores whether or not the device told it anything.
    assert!(known.attributes.contains(&bdbi::NODE_LABEL));
    assert!(unknown.attributes.contains(&bdbi::NODE_LABEL));

    let built = BridgedDeviceBasicInformation::conforming(0, &unknown).expect("sized");
    let descriptor = built.descriptor();
    assert!(
        descriptor
            .attributes
            .iter()
            .all(|a| a.id != bdbi::VENDOR_ID)
    );
    assert!(
        descriptor
            .attributes
            .iter()
            .any(|a| a.id == bdbi::REACHABLE)
    );
}

#[test]
fn the_cluster_matches_the_specification() {
    let spec = matter_kit::clusters::generated::find(bdbi::ID).expect("the cluster");
    let mut buf = [0u32; 16];
    let optional = BridgedDeviceBasicInformation::optional_for(&KNOWN, &mut buf);
    for (features, extra) in [
        (0u32, Optional::NONE),
        (
            bdbi::feature::BRIDGED_ICD_SUPPORT,
            BridgedDeviceBasicInformation::WITH_KEEP_ACTIVE,
        ),
    ] {
        let merged = Optional {
            attributes: optional.attributes,
            commands: extra.commands,
            events: extra.events,
        };
        let built = BridgedDeviceBasicInformation::conforming(features, &merged).expect("sized");
        let mut defects = Vec::new();
        spec.validate(&built.descriptor(), |defect| defects.push(defect));
        assert!(defects.is_empty(), "features {features:#x}: {defects:?}");
    }
}

#[test]
fn a_bridged_node_needs_this_cluster_and_nothing_else() {
    // §9.12's Bridged Node is a *utility* device type: it says what the endpoint is attached
    // to, not what it does. The doing comes from a second device type on the same endpoint.
    let clusters = [descriptor::cluster()];
    let bare = Endpoint::new(2, &clusters);
    let mut defects = Vec::new();
    validate_endpoint(&bare, &BRIDGED_NODE, |defect| defects.push(defect));
    assert!(
        defects
            .iter()
            .any(|d| format!("{d:?}").contains(&format!("{}", bdbi::ID))),
        "{defects:?}"
    );

    let built = BridgedDeviceBasicInformation::conforming(0, &Optional::NONE).expect("sized");
    let furnished_clusters = [descriptor::cluster(), built.descriptor()];
    let furnished = Endpoint::new(2, &furnished_clusters);
    let mut defects = Vec::new();
    validate_endpoint(&furnished, &BRIDGED_NODE, |defect| defects.push(defect));
    assert!(defects.is_empty(), "{defects:?}");

    // An Aggregator's clusters are all optional — a bare endpoint is a conformant one.
    let aggregator = Endpoint::new(1, &clusters);
    let mut defects = Vec::new();
    validate_endpoint(&aggregator, &AGGREGATOR, |defect| defects.push(defect));
    assert!(defects.is_empty(), "{defects:?}");
}

#[test]
fn reachable_changed_fires_on_the_change_and_not_on_the_poll() {
    // §9.13.7.1 is generated "when the Reachable attribute changes". A bridge that re-polls
    // its far side every thirty seconds must not emit an event every thirty seconds: the
    // event store is a fixed ring, and a chatty record pushes out everything else in it.
    let cluster = BridgedDeviceBasicInformation::new(KNOWN, true);
    assert!(cluster.reachable());
    assert!(cluster.take_events().is_empty());

    cluster.set_reachable(true);
    assert!(cluster.take_events().is_empty(), "no change, no event");

    cluster.set_reachable(false);
    assert_eq!(
        cluster.take_events().as_slice(),
        &[Event::ReachableChanged(false)]
    );
    assert!(!cluster.reachable());

    // Draining means a record is reported once.
    assert!(cluster.take_events().is_empty());

    cluster.set_reachable(true);
    assert_eq!(
        cluster.take_events().as_slice(),
        &[Event::ReachableChanged(true)]
    );
}

#[test]
fn a_second_keep_active_never_shortens_the_first() {
    // §9.13.6.1: "the StayActiveDuration is updated to the greater of the new value and the
    // previously stored value, and the TimeoutMs is updated to the greater of the new value
    // and the remaining time until the prior 'pending active' state expires."
    //
    // Two controllers each asking for the device to stay awake must not end with it awake for
    // the shorter of the two — the second request would then cancel most of the first.
    let cluster = BridgedDeviceBasicInformation::new(KNOWN, true);
    let built = BridgedDeviceBasicInformation::conforming(
        bdbi::feature::BRIDGED_ICD_SUPPORT,
        &BridgedDeviceBasicInformation::WITH_KEEP_ACTIVE,
    )
    .expect("sized");
    let clusters = [built.descriptor()];
    let endpoints = [Endpoint::new(2, &clusters)];
    let node = Node::new(&endpoints);

    keep_active(&node, &cluster, 30_000, 60_000, at(0));
    let first = cluster.pending_active().expect("a request");
    assert_eq!(first.stay_active_ms, 30_000);
    assert_eq!(first.expires, at(60_000));

    // A shorter second request changes neither field.
    keep_active(&node, &cluster, 10_000, 5_000, at(1_000));
    let merged = cluster.pending_active().expect("still a request");
    assert_eq!(merged.stay_active_ms, 30_000);
    assert_eq!(merged.expires, at(60_000));

    // A longer one extends both.
    keep_active(&node, &cluster, 45_000, 120_000, at(2_000));
    let merged = cluster.pending_active().expect("still a request");
    assert_eq!(merged.stay_active_ms, 45_000);
    assert_eq!(merged.expires, at(122_000));
}

#[test]
fn a_keep_active_request_lapses_and_is_satisfied_only_once() {
    let cluster = BridgedDeviceBasicInformation::new(KNOWN, true);
    let built = BridgedDeviceBasicInformation::conforming(
        bdbi::feature::BRIDGED_ICD_SUPPORT,
        &BridgedDeviceBasicInformation::WITH_KEEP_ACTIVE,
    )
    .expect("sized");
    let clusters = [built.descriptor()];
    let endpoints = [Endpoint::new(2, &clusters)];
    let node = Node::new(&endpoints);

    // §9.13.6.1: the pending state "SHALL expire after the amount of time defined by the
    // TimeoutMs field ... if no subsequent KeepActive command is received". A device that
    // never woke must not be held awake the next time it happens to appear, a week later.
    keep_active(&node, &cluster, 30_000, 5_000, at(0));
    cluster.poll(at(4_999));
    assert!(cluster.pending_active().is_some());
    cluster.poll(at(5_000));
    assert!(cluster.pending_active().is_none());
    cluster.became_active();
    assert!(cluster.take_events().is_empty(), "a lapsed request woke it");

    // And a live one is satisfied exactly once: "The server SHALL only keep the bridged device
    // active once for a request."
    keep_active(&node, &cluster, 30_000, 5_000, at(10_000));
    cluster.became_active();
    assert_eq!(
        cluster.take_events().as_slice(),
        &[Event::ActiveChanged(30_000)]
    );
    assert!(cluster.pending_active().is_none());
    cluster.became_active();
    assert!(cluster.take_events().is_empty());
}

fn keep_active(
    node: &Node<'_>,
    cluster: &BridgedDeviceBasicInformation<'_>,
    stay: u32,
    timeout: u32,
    now: Instant,
) {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(stay)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(timeout)).unwrap();
    w.end_container().unwrap();
    let fields = w.finish().unwrap().to_vec();
    let resolved = node
        .resolve_command(2, bdbi::ID, bdbi::KEEP_ACTIVE)
        .expect("KeepActive");
    let mut out = [0u8; 64];
    let mut writer = TlvWriter::new(&mut out);
    let ctx = InteractionContext::new()
        .with_fabric(FabricIndex(1))
        .at(now);
    cluster
        .invoke(&resolved, Some(&fields), &ctx, &mut writer, Tag::Anonymous)
        .expect("invoke");
}

#[test]
fn node_label_is_the_users_name_and_the_only_writable_attribute() {
    // §11.1.5.6. The bridge's facts about the device are the *device's*; the label is the
    // person's, and it is the one thing a controller may change through this cluster.
    let cluster = BridgedDeviceBasicInformation::new(KNOWN, true);
    let mut buf = [0u32; 16];
    let optional = BridgedDeviceBasicInformation::optional_for(&KNOWN, &mut buf);
    let built = BridgedDeviceBasicInformation::conforming(0, &optional).expect("sized");
    let clusters = [built.descriptor()];
    let endpoints = [Endpoint::new(2, &clusters)];
    let node = Node::new(&endpoints);

    let mut data = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut data, ContainerKind::Structure);
    w.utf8(Tag::Context(2), "Kitchen").unwrap();
    let encoded = w.finish().unwrap().to_vec();
    let resolved = node
        .resolve(2, bdbi::ID, bdbi::NODE_LABEL)
        .expect("NodeLabel");
    cluster
        .write(
            &resolved,
            &encoded,
            WriteOp::Replace,
            &InteractionContext::new(),
        )
        .expect("write");
    assert_eq!(cluster.node_label().as_str(), "Kitchen");

    // The bridge's own facts are not the controller's to rewrite.
    let resolved = node
        .resolve(2, bdbi::ID, bdbi::VENDOR_NAME)
        .expect("VendorName");
    assert_eq!(
        cluster.write(
            &resolved,
            &encoded,
            WriteOp::Replace,
            &InteractionContext::new()
        ),
        Err(Status::UnsupportedWrite)
    );
}

#[test]
fn a_label_longer_than_the_constraint_is_refused() {
    // §11.1.5.6's "max 32". A bridge that truncated silently would report a name the user did
    // not choose, and the user would have no way to tell.
    let cluster = BridgedDeviceBasicInformation::new(KNOWN, true);
    let mut buf = [0u32; 16];
    let optional = BridgedDeviceBasicInformation::optional_for(&KNOWN, &mut buf);
    let built = BridgedDeviceBasicInformation::conforming(0, &optional).expect("sized");
    let clusters = [built.descriptor()];
    let endpoints = [Endpoint::new(2, &clusters)];
    let node = Node::new(&endpoints);
    let mut data = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut data, ContainerKind::Structure);
    w.utf8(Tag::Context(2), &"x".repeat(33)).unwrap();
    let encoded = w.finish().unwrap().to_vec();
    let resolved = node
        .resolve(2, bdbi::ID, bdbi::NODE_LABEL)
        .expect("NodeLabel");
    assert_eq!(
        cluster.write(
            &resolved,
            &encoded,
            WriteOp::Replace,
            &InteractionContext::new()
        ),
        Err(Status::ConstraintError)
    );
    assert_eq!(cluster.node_label().as_str(), "");
}
