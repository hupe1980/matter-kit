//! The utility clusters against their specification tables.
//!
//! Chapters 9 and 11 publish no test vectors — what they publish is tables. So every id,
//! revision, feature bit and access quality here is a **literal transcribed from the table**,
//! and the behaviours are driven end-to-end through the interaction model, so what is asserted
//! is what a commissioner would actually see on the wire.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use core::cell::RefCell;
use matter_kit::clusters::basic_information::{
    self, Attributes, BasicInformation, CapabilityMinima, Location, Product,
};
use matter_kit::clusters::descriptor::{self, DeviceType};
use matter_kit::clusters::general_commissioning::{
    self, Aftermath, GeneralCommissioning, RegulatoryLocation,
};
use matter_kit::clusters::{Cluster, Descriptor};

use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::dm::{Endpoint, Node, Privilege, global};
use matter_kit::im::{
    AccessControl, AttributeData, AttributePath, ClusterHandler, CommandData, CommandPath,
    InteractionContext, Outcome, Status,
};
use matter_kit::msg::{FabricIndex, VendorId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

// --- The tables ------------------------------------------------------------------------------

#[test]
fn cluster_ids_and_revisions_match_the_specification() {
    // §9.5.3 and §9.5.1.
    assert_eq!(descriptor::ID, 0x001D);
    assert_eq!(descriptor::REVISION, 3);
    assert_eq!(descriptor::FEATURE_TAG_LIST, 1 << 0);

    // §11.1.3 and §11.1.1.
    assert_eq!(basic_information::ID, 0x0028);
    assert_eq!(basic_information::REVISION, 6);

    // §11.10.3 and §11.10.1.
    assert_eq!(general_commissioning::ID, 0x0030);
    assert_eq!(general_commissioning::REVISION, 2);
    assert_eq!(general_commissioning::FEATURE_TERMS_AND_CONDITIONS, 1 << 0);
    assert_eq!(general_commissioning::FEATURE_NETWORK_RECOVERY, 1 << 1);
}

#[test]
fn descriptor_attribute_ids_match_section_9_5_6() {
    assert_eq!(descriptor::DEVICE_TYPE_LIST, 0x0000);
    assert_eq!(descriptor::SERVER_LIST, 0x0001);
    assert_eq!(descriptor::CLIENT_LIST, 0x0002);
    assert_eq!(descriptor::PARTS_LIST, 0x0003);
    assert_eq!(descriptor::TAG_LIST, 0x0004);
    assert_eq!(descriptor::ENDPOINT_UNIQUE_ID, 0x0005);
}

#[test]
fn basic_information_attribute_and_event_ids_match_section_11_1() {
    assert_eq!(basic_information::DATA_MODEL_REVISION_ID, 0x0000);
    assert_eq!(basic_information::VENDOR_NAME, 0x0001);
    assert_eq!(basic_information::VENDOR_ID, 0x0002);
    assert_eq!(basic_information::PRODUCT_NAME, 0x0003);
    assert_eq!(basic_information::PRODUCT_ID, 0x0004);
    assert_eq!(basic_information::NODE_LABEL, 0x0005);
    assert_eq!(basic_information::LOCATION, 0x0006);
    assert_eq!(basic_information::HARDWARE_VERSION, 0x0007);
    assert_eq!(basic_information::HARDWARE_VERSION_STRING, 0x0008);
    assert_eq!(basic_information::SOFTWARE_VERSION, 0x0009);
    assert_eq!(basic_information::SOFTWARE_VERSION_STRING, 0x000A);
    assert_eq!(basic_information::MANUFACTURING_DATE, 0x000B);
    assert_eq!(basic_information::PART_NUMBER, 0x000C);
    assert_eq!(basic_information::PRODUCT_URL, 0x000D);
    assert_eq!(basic_information::PRODUCT_LABEL, 0x000E);
    assert_eq!(basic_information::SERIAL_NUMBER, 0x000F);
    assert_eq!(basic_information::LOCAL_CONFIG_DISABLED, 0x0010);
    assert_eq!(basic_information::REACHABLE, 0x0011);
    assert_eq!(basic_information::UNIQUE_ID, 0x0012);
    assert_eq!(basic_information::CAPABILITY_MINIMA, 0x0013);
    assert_eq!(basic_information::PRODUCT_APPEARANCE, 0x0014);
    assert_eq!(basic_information::SPECIFICATION_VERSION_ID, 0x0015);
    assert_eq!(basic_information::MAX_PATHS_PER_INVOKE, 0x0016);
    // 0x0017 is not assigned; §11.1.5 jumps straight to 0x0018.
    assert_eq!(basic_information::CONFIGURATION_VERSION, 0x0018);

    // §11.1.6.
    assert_eq!(basic_information::START_UP, 0x00);
    assert_eq!(basic_information::SHUT_DOWN, 0x01);
    assert_eq!(basic_information::LEAVE, 0x02);
    assert_eq!(basic_information::REACHABLE_CHANGED, 0x03);
}

#[test]
fn specification_version_is_matter_1_6() {
    // §11.1.5.22: "The format of this number is segmented as its four component bytes" —
    // major, minor, dot, reserved. The section's own worked example is 0x01040200 for 1.4.2.0
    // and it names 0x01030000 for 1.3.
    assert_eq!(basic_information::SPECIFICATION_VERSION, 0x0106_0000);
    let bytes = basic_information::SPECIFICATION_VERSION.to_be_bytes();
    assert_eq!(bytes, [1, 6, 0, 0]);
}

#[test]
fn general_commissioning_ids_match_section_11_10() {
    assert_eq!(general_commissioning::BREADCRUMB, 0x0000);
    assert_eq!(general_commissioning::BASIC_COMMISSIONING_INFO, 0x0001);
    assert_eq!(general_commissioning::REGULATORY_CONFIG, 0x0002);
    assert_eq!(general_commissioning::LOCATION_CAPABILITY, 0x0003);
    assert_eq!(
        general_commissioning::SUPPORTS_CONCURRENT_CONNECTION,
        0x0004
    );

    assert_eq!(general_commissioning::ARM_FAIL_SAFE, 0x00);
    assert_eq!(general_commissioning::ARM_FAIL_SAFE_RESPONSE, 0x01);
    assert_eq!(general_commissioning::SET_REGULATORY_CONFIG, 0x02);
    assert_eq!(general_commissioning::SET_REGULATORY_CONFIG_RESPONSE, 0x03);
    assert_eq!(general_commissioning::COMMISSIONING_COMPLETE, 0x04);
    assert_eq!(general_commissioning::COMMISSIONING_COMPLETE_RESPONSE, 0x05);

    // §11.10.5.2.
    assert_eq!(RegulatoryLocation::Indoor.value(), 0);
    assert_eq!(RegulatoryLocation::Outdoor.value(), 1);
    assert_eq!(RegulatoryLocation::IndoorOutdoor.value(), 2);
    assert_eq!(RegulatoryLocation::from_value(3), None);
}

#[test]
fn every_descriptor_is_well_formed() {
    // `ClusterDescriptor` binary-searches, so an unsorted slice silently fails to find
    // things — which on a device looks like an attribute that is simply not there.
    for cluster in [
        descriptor::cluster(),
        descriptor::cluster_with_tags(),
        descriptor::cluster_with_unique_id(),
        descriptor::cluster_full(),
        general_commissioning::cluster(),
    ] {
        assert!(cluster.is_well_formed(), "{:#06x}", cluster.id);
    }
    let product = sample_product();
    for (local, reachable) in [(false, false), (true, false), (false, true), (true, true)] {
        let attributes = Attributes::new(&product, local, reachable);
        assert!(attributes.cluster().is_well_formed());
    }
}

#[test]
fn access_qualities_match_the_tables() {
    // §11.1.5: NodeLabel is `RW VM`, Location is `RW VA`, and everything fixed is `RV`.
    let product = sample_product();
    let attributes = Attributes::new(&product, false, false);
    let cluster = attributes.cluster();

    let node_label = cluster.attribute(basic_information::NODE_LABEL).unwrap();
    assert!(node_label.access.is_writable());
    assert_eq!(node_label.access.write, Some(Privilege::Manage));
    assert_eq!(node_label.access.read, Some(Privilege::View));

    let location = cluster.attribute(basic_information::LOCATION).unwrap();
    assert_eq!(location.access.write, Some(Privilege::Administer));

    let vendor = cluster.attribute(basic_information::VENDOR_NAME).unwrap();
    assert!(!vendor.access.is_writable());

    // §11.10.6: Breadcrumb is `RW VA`; RegulatoryConfig is `RV` even though a command
    // changes it, because the change must go through SetRegulatoryConfig.
    let gc = general_commissioning::cluster();
    let breadcrumb = gc.attribute(general_commissioning::BREADCRUMB).unwrap();
    assert_eq!(breadcrumb.access.write, Some(Privilege::Administer));
    let regulatory = gc
        .attribute(general_commissioning::REGULATORY_CONFIG)
        .unwrap();
    assert!(!regulatory.access.is_writable());

    // §11.10.7: all three commands are Administer, and CommissioningComplete is `AF`.
    for id in [
        general_commissioning::ARM_FAIL_SAFE,
        general_commissioning::SET_REGULATORY_CONFIG,
        general_commissioning::COMMISSIONING_COMPLETE,
    ] {
        let command = gc.accepted_command(id).unwrap();
        assert_eq!(
            command.access.invoke,
            Some(Privilege::Administer),
            "{id:#04x}"
        );
    }
    let complete = gc
        .accepted_command(general_commissioning::COMMISSIONING_COMPLETE)
        .unwrap();
    assert!(complete.access.is_fabric_scoped());
    assert!(
        !gc.accepted_command(general_commissioning::ARM_FAIL_SAFE)
            .unwrap()
            .access
            .is_fabric_scoped(),
        "ArmFailSafe is `A`, not `AF` — it must work over PASE, before any fabric exists"
    );
}

#[test]
fn generated_command_list_is_derived_from_the_responses() {
    // §7.13.5: "For each command in this list that is a response to a client request command,
    // the request command SHALL be indicated in the AcceptedCommandList."
    let generated: Vec<u32> = general_commissioning::cluster()
        .generated_command_ids()
        .collect();
    assert_eq!(
        generated,
        vec![
            general_commissioning::ARM_FAIL_SAFE_RESPONSE,
            general_commissioning::SET_REGULATORY_CONFIG_RESPONSE,
            general_commissioning::COMMISSIONING_COMPLETE_RESPONSE,
        ]
    );
}

// --- Fixtures --------------------------------------------------------------------------------

const fn sample_product() -> Product<'static> {
    Product::new(
        "Test Vendor",
        VendorId(0xFFF1),
        "Test Product",
        0x8000,
        "0123456789abcdef",
    )
    .with_hardware(1, "v1")
    .with_software(0x0001_0000, "1.0")
    .with_serial_number("SN-1")
    .with_max_paths_per_invoke(3)
}

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

/// Reads one attribute through the handler directly, returning the encoded element.
fn read_attribute<H: ClusterHandler>(
    node: Node<'_>,
    handler: &H,
    endpoint: u16,
    cluster: u32,
    attribute: u32,
) -> Result<Vec<u8>, Status> {
    let resolved = node
        .resolve(endpoint, cluster, attribute)
        .expect("the path exists");
    let mut buf = [0u8; 1024];
    let mut w = TlvWriter::new(&mut buf);
    handler.read(
        &resolved,
        &InteractionContext::default(),
        &mut w,
        Tag::Anonymous,
    )?;
    Ok(w.finish().expect("finish").to_vec())
}

fn decode_u64(bytes: &[u8]) -> u64 {
    let mut reader = TlvReader::new(bytes);
    reader
        .next_element()
        .unwrap()
        .unwrap()
        .unsigned()
        .expect("an unsigned value")
}

fn decode_utf8(bytes: &[u8]) -> String {
    let mut reader = TlvReader::new(bytes);
    reader
        .next_element()
        .unwrap()
        .unwrap()
        .utf8()
        .expect("a string")
        .to_owned()
}

/// The members of a TLV array of unsigned values.
fn decode_u64_array(bytes: &[u8]) -> Vec<u64> {
    let mut reader = TlvReader::new(bytes);
    let array = reader.next_element().unwrap().unwrap();
    assert_eq!(array.value.container(), Some(ContainerKind::Array));
    let mut out = Vec::new();
    let depth = reader.depth();
    while let Some(element) = reader.next_element().unwrap() {
        if reader.depth() < depth {
            break;
        }
        out.push(element.unsigned().expect("unsigned member"));
    }
    out
}

// --- Descriptor ------------------------------------------------------------------------------

const DEVICE_TYPES: &[DeviceType] = &[DeviceType::new(0x0016, 3)];

#[test]
fn server_list_is_read_out_of_the_node_not_stored() {
    // §9.5.6.2: "This attribute SHALL list each cluster ID for the server clusters present on
    // the endpoint instance." A second hand-maintained copy is a copy that drifts, so this is
    // derived — and this test is what says so: the node's clusters decide the answer.
    let clusters = [descriptor::cluster(), general_commissioning::cluster()];
    let endpoints = [Endpoint::new(0, &clusters).with_device_types(DEVICE_TYPES)];
    let node = Node::new(&endpoints);
    node.validate().expect("well formed");

    let desc = Descriptor::new(node, 0);
    let bytes = read_attribute(node, &desc, 0, descriptor::ID, descriptor::SERVER_LIST).unwrap();
    assert_eq!(
        decode_u64_array(&bytes),
        vec![
            u64::from(descriptor::ID),
            u64::from(general_commissioning::ID)
        ]
    );
}

#[test]
fn device_type_list_carries_the_struct_of_section_9_5_5_1() {
    let clusters = [descriptor::cluster()];
    let endpoints = [Endpoint::new(0, &clusters).with_device_types(DEVICE_TYPES)];
    let node = Node::new(&endpoints);
    let desc = Descriptor::new(node, 0);
    let bytes =
        read_attribute(node, &desc, 0, descriptor::ID, descriptor::DEVICE_TYPE_LIST).unwrap();

    // array [ struct { 0: devtype-id, 1: revision } ]
    let mut reader = TlvReader::new(&bytes);
    reader.next_element().unwrap().unwrap(); // the array
    reader.next_element().unwrap().unwrap(); // the struct
    let device_type = reader.next_element().unwrap().unwrap();
    assert_eq!(device_type.tag, Tag::Context(0));
    assert_eq!(device_type.unsigned().unwrap(), 0x0016);
    let revision = reader.next_element().unwrap().unwrap();
    assert_eq!(revision.tag, Tag::Context(1));
    assert_eq!(revision.unsigned().unwrap(), 3);
}

#[test]
fn a_descriptor_refuses_to_answer_for_another_endpoint() {
    // One instance per endpoint. Answering a path on a different endpoint would report the
    // wrong endpoint's cluster list — and a commissioner would build its model from it.
    let clusters = [descriptor::cluster()];
    let endpoints = [
        Endpoint::new(0, &clusters).with_device_types(DEVICE_TYPES),
        Endpoint::new(1, &clusters),
    ];
    let node = Node::new(&endpoints);
    let desc = Descriptor::new(node, 0);
    assert_eq!(
        read_attribute(node, &desc, 1, descriptor::ID, descriptor::SERVER_LIST),
        Err(Status::UnsupportedEndpoint)
    );
}

#[test]
fn the_attribute_list_matches_what_the_instance_serves() {
    // §7.13.3's AttributeList is what a commissioner builds its model from: an entry for an
    // attribute that answers UNSUPPORTED_ATTRIBUTE is a certification failure, and so is a
    // served attribute missing from the list.
    let clusters = [descriptor::cluster_full()];
    let endpoints = [Endpoint::new(0, &clusters).with_device_types(DEVICE_TYPES)];
    let node = Node::new(&endpoints);
    let desc = Descriptor::new(node, 0).with_unique_id("endpoint-0");

    for id in desc.descriptor().attribute_ids() {
        if global::is_global(id) {
            continue;
        }
        let result = read_attribute(node, &desc, 0, descriptor::ID, id);
        assert!(result.is_ok(), "declared but not served: {id:#06x}");
    }
    // …and the converse: EndpointUniqueID is declared only because it was given.
    let plain = Descriptor::new(node, 0);
    assert!(
        !plain
            .descriptor()
            .attribute_ids()
            .any(|id| id == descriptor::ENDPOINT_UNIQUE_ID)
    );
    assert_eq!(
        read_attribute(
            node,
            &plain,
            0,
            descriptor::ID,
            descriptor::ENDPOINT_UNIQUE_ID
        ),
        Err(Status::UnsupportedAttribute)
    );
}

// --- Basic Information -----------------------------------------------------------------------

#[test]
fn basic_information_serves_its_product_record() {
    let product = sample_product();
    let attributes = Attributes::new(&product, false, false);
    let clusters = [attributes.cluster()];
    let endpoints = [Endpoint::new(0, &clusters)];
    let node = Node::new(&endpoints);
    let location = Location::region_agnostic();
    let info = BasicInformation::new(&product, &location);

    let read = |id: u32| read_attribute(node, &info, 0, basic_information::ID, id).unwrap();

    assert_eq!(
        decode_utf8(&read(basic_information::VENDOR_NAME)),
        "Test Vendor"
    );
    assert_eq!(decode_u64(&read(basic_information::VENDOR_ID)), 0xFFF1);
    assert_eq!(decode_u64(&read(basic_information::PRODUCT_ID)), 0x8000);
    assert_eq!(
        decode_u64(&read(basic_information::SOFTWARE_VERSION)),
        0x0001_0000
    );
    assert_eq!(decode_utf8(&read(basic_information::SERIAL_NUMBER)), "SN-1");
    assert_eq!(
        decode_u64(&read(basic_information::SPECIFICATION_VERSION_ID)),
        0x0106_0000
    );
    assert_eq!(
        decode_u64(&read(basic_information::MAX_PATHS_PER_INVOKE)),
        3
    );
    // §11.1.5.7: "The special value XX SHALL indicate that region-agnostic mode is used."
    assert_eq!(decode_utf8(&read(basic_information::LOCATION)), "XX");
    // The fallback for NodeLabel is "".
    assert_eq!(decode_utf8(&read(basic_information::NODE_LABEL)), "");
}

#[test]
fn optional_attributes_are_absent_unless_given() {
    let product = Product::new("V", VendorId(1), "P", 2, "u");
    let attributes = Attributes::new(&product, false, false);

    for id in [
        basic_information::SERIAL_NUMBER,
        basic_information::PART_NUMBER,
        basic_information::PRODUCT_URL,
        basic_information::PRODUCT_LABEL,
        basic_information::MANUFACTURING_DATE,
        basic_information::PRODUCT_APPEARANCE,
        basic_information::LOCAL_CONFIG_DISABLED,
        basic_information::REACHABLE,
    ] {
        assert!(
            !attributes.cluster().attribute_ids().any(|a| a == id),
            "{id:#06x} declared without a value"
        );
    }

    // …and the handler does not invent one either. A node whose descriptor over-declares —
    // the mistake the derived list exists to prevent — gets UNSUPPORTED_ATTRIBUTE, not an
    // empty string that a commissioner would record as the device's serial number.
    let over_declared = Attributes::new(&sample_product(), true, true);
    let clusters = [over_declared.cluster()];
    let endpoints = [Endpoint::new(0, &clusters)];
    let node = Node::new(&endpoints);
    let location = Location::region_agnostic();
    let info = BasicInformation::new(&product, &location);
    assert_eq!(
        read_attribute(
            node,
            &info,
            0,
            basic_information::ID,
            basic_information::SERIAL_NUMBER
        ),
        Err(Status::UnsupportedAttribute)
    );
    assert_eq!(
        read_attribute(
            node,
            &info,
            0,
            basic_information::ID,
            basic_information::REACHABLE
        ),
        Err(Status::UnsupportedAttribute)
    );
}

#[test]
fn capability_minima_omits_the_revision_6_fields_when_absent() {
    // §11.1.4.4's last four fields arrived in revision 6, where their conformance is
    // "Rev >= v6" — **mandatory**, not optional. This cluster declares revision 6, so the
    // default carries them; a struct that omitted them would describe an older node than the
    // one sending it, and `TC_IDM_2_3` says so directly:
    //
    //     ReadPathsSupported should be present when ClusterRevision >= 6
    //
    // What stays true is the *encoder's* rule: a field that is `None` is absent from the
    // structure — not null, and not a zero a client would read as a real limit. That is what a
    // node declaring an older revision needs, and it is what the rest of this test checks.
    let explicitly_absent = CapabilityMinima {
        simultaneous_invocations: None,
        simultaneous_writes: None,
        read_paths: None,
        subscribe_paths: None,
        ..CapabilityMinima::default()
    };
    let product = sample_product().with_capability_minima(explicitly_absent);
    let attributes = Attributes::new(&product, false, false);
    let clusters = [attributes.cluster()];
    let endpoints = [Endpoint::new(0, &clusters)];
    let node = Node::new(&endpoints);
    let location = Location::region_agnostic();
    let info = BasicInformation::new(&product, &location);
    let bytes = read_attribute(
        node,
        &info,
        0,
        basic_information::ID,
        basic_information::CAPABILITY_MINIMA,
    )
    .unwrap();

    let tags = struct_tags(&bytes);
    assert_eq!(tags, vec![0, 1]);

    // …and with them, all six.
    let product = sample_product().with_capability_minima(CapabilityMinima {
        case_sessions_per_fabric: 3,
        subscriptions_per_fabric: 3,
        simultaneous_invocations: Some(2),
        simultaneous_writes: Some(2),
        read_paths: Some(9),
        subscribe_paths: Some(3),
    });
    let info = BasicInformation::new(&product, &location);
    let bytes = read_attribute(
        node,
        &info,
        0,
        basic_information::ID,
        basic_information::CAPABILITY_MINIMA,
    )
    .unwrap();
    assert_eq!(struct_tags(&bytes), vec![0, 1, 2, 3, 4, 5]);
}

/// The context tag numbers of a TLV structure's members, in order.
fn struct_tags(bytes: &[u8]) -> Vec<u8> {
    let mut reader = TlvReader::new(bytes);
    reader.next_element().unwrap().unwrap();
    let depth = reader.depth();
    let mut tags = Vec::new();
    while let Some(element) = reader.next_element().unwrap() {
        if reader.depth() < depth {
            break;
        }
        if let Tag::Context(number) = element.tag {
            tags.push(number);
        }
        reader.skip_value(&element).unwrap();
    }
    tags
}

#[test]
fn writing_node_label_and_location_enforces_their_constraints() {
    let product = sample_product();
    let attributes = Attributes::new(&product, false, false);
    let clusters = [attributes.cluster()];
    let endpoints = [Endpoint::new(0, &clusters)];
    let node = Node::new(&endpoints);
    let location = Location::region_agnostic();
    let info = BasicInformation::new(&product, &location);
    let ctx = InteractionContext::default();

    let write = |id: u32, value: &str| {
        let resolved = node.resolve(0, basic_information::ID, id).unwrap();
        let mut buf = [0u8; 512];
        // The value reaches a handler as the encoded element, carrying §10.6.4.3's context
        // tag 2 — so that is what a test must hand it.
        let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
        w.utf8(Tag::Context(2), value).unwrap();
        let encoded = w.finish().unwrap().to_vec();
        info.write(&resolved, &encoded, matter_kit::im::WriteOp::Replace, &ctx)
    };

    assert_eq!(
        write(basic_information::NODE_LABEL, "Kitchen light"),
        Ok(())
    );
    assert_eq!(info.node_label().as_str(), "Kitchen light");
    // "max 32" — a 33-character label is CONSTRAINT_ERROR, not a truncation.
    assert_eq!(
        write(basic_information::NODE_LABEL, &"x".repeat(33)),
        Err(Status::ConstraintError)
    );
    assert_eq!(info.node_label().as_str(), "Kitchen light");

    // Location's constraint is "2" exactly.
    assert_eq!(write(basic_information::LOCATION, "DE"), Ok(()));
    assert_eq!(location.get(), *b"DE");
    assert_eq!(
        write(basic_information::LOCATION, "DEU"),
        Err(Status::ConstraintError)
    );
    assert_eq!(
        write(basic_information::LOCATION, "D"),
        Err(Status::ConstraintError)
    );
    assert_eq!(location.get(), *b"DE");

    // A fixed attribute is not writable at all.
    assert_eq!(
        write(basic_information::VENDOR_NAME, "Someone Else"),
        Err(Status::UnsupportedWrite)
    );
}

#[test]
fn reachable_changed_is_reported_only_on_an_actual_change() {
    // §11.1.6.4's ReachableChanged fires when the value changes, which is the trigger a
    // device needs — reporting on every write would wake every subscriber for nothing.
    let product = sample_product();
    let location = Location::region_agnostic();
    let info = BasicInformation::new(&product, &location).with_reachable(true);
    assert_eq!(info.reachable(), Some(true));
    assert!(!info.set_reachable(true));
    assert!(info.set_reachable(false));
    assert_eq!(info.reachable(), Some(false));

    // A node that does not serve the attribute has nothing to report.
    let plain = BasicInformation::new(&product, &location);
    assert_eq!(plain.reachable(), None);
    assert!(!plain.set_reachable(false));
}

// --- General Commissioning -------------------------------------------------------------------

struct Device<'a> {
    node: Node<'a>,
    gc: GeneralCommissioning<'a>,
}

fn gc_clusters() -> [matter_kit::dm::ClusterDescriptor<'static>; 1] {
    [general_commissioning::cluster()]
}

fn device<'a>(
    endpoints: &'a [Endpoint<'a>],
    location: &'a Location,
    capability: RegulatoryLocation,
    fail_safe: &'a RefCell<FailSafe>,
    window: &'a RefCell<CommissioningWindow>,
) -> Device<'a> {
    Device {
        node: Node::new(endpoints),
        gc: GeneralCommissioning::new(location, capability, fail_safe, window),
    }
}

/// A closed commissioning window, for a test that does not open one.
fn closed_window() -> RefCell<CommissioningWindow> {
    RefCell::new(CommissioningWindow::new())
}

/// Opens an Enhanced window, the way §11.19.8.1 would.
///
/// Driving the real cluster rather than fabricating the state is the point: §11.10.7.2's
/// priority rule and §11.19's window are now the same window, and a test that set a flag would
/// not notice if they came apart again.
#[cfg(feature = "rustcrypto")]
fn open_a_window(window: &RefCell<CommissioningWindow>, now: Instant) {
    use matter_kit::clusters::AdministratorCommissioning;
    use matter_kit::clusters::administrator_commissioning::OpenWindowRequest;
    use matter_kit::crypto::Spake2pVerifierData;

    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let no_vendor = |_: FabricIndex| None;
    let admin = AdministratorCommissioning::new(window, &fail_safe, &no_vendor);
    let verifier =
        Spake2pVerifierData::from_passcode(20_202_021, &[0x42; 16], 1000).expect("verifier");
    let bytes = verifier.to_bytes();
    admin
        .open_commissioning_window(
            &OpenWindowRequest {
                timeout_seconds: 300,
                verifier: &bytes,
                discriminator: 840,
                iterations: 1000,
                salt: &[0x42; 16],
            },
            &InteractionContext {
                now,
                ..InteractionContext::default()
            },
        )
        .expect("open");
}

/// A fail-safe with the specification's default timings, for a test that only needs one.
fn fresh_fail_safe() -> RefCell<FailSafe> {
    RefCell::new(FailSafe::new(BasicCommissioningInfo::default()))
}

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

/// Invokes one command through the full interaction model and returns the response's
/// `ErrorCode`, so what is asserted is what a commissioner would decode.
fn invoke_error(device: &Device<'_>, command: u32, fields: &[u8], ctx: &InteractionContext) -> u64 {
    use matter_kit::im::{InvokeResponse, InvokeResponseMessage, Server};

    let path = CommandPath::command(0, general_commissioning::ID, command);
    let data = CommandData {
        fields: Some(fields),
        ..CommandData::new(path)
    };
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.gc, 8);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    let first = responses.next().expect("one response").expect("decode");
    match first {
        InvokeResponse::Command(c) => {
            // §8.8.2.3: the response path keeps the request's endpoint and cluster and takes
            // the response command's id.
            assert_eq!(c.path.endpoint, Some(0));
            assert_eq!(c.path.cluster, Some(general_commissioning::ID));
            let fields = c.fields.expect("response fields");
            let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
            reader.next_element().unwrap().unwrap();
            let error = reader.next_element().unwrap().unwrap();
            assert_eq!(error.tag, Tag::Context(0));
            error.unsigned().expect("an ErrorCode")
        }
        InvokeResponse::Status(s) => panic!("expected a response command, got {:?}", s.status),
    }
}

/// `CommandFields` is the `CommandDataIB`'s context-1 member (§10.6.11), so a command's
/// fields are authored as a tagged fragment — which is what `TlvWriter::new_in` is for.
fn arm_fields(expiry: u16, breadcrumb: u64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(expiry)).unwrap();
    w.unsigned(Tag::Context(1), breadcrumb).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn regulatory_fields(config: RegulatoryLocation, country: &str, breadcrumb: u64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(config.value()))
        .unwrap();
    w.utf8(Tag::Context(1), country).unwrap();
    w.unsigned(Tag::Context(2), breadcrumb).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn empty_struct() -> Vec<u8> {
    let mut buf = [0u8; 8];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn over_pase(now: Instant) -> InteractionContext<'static> {
    InteractionContext {
        now,
        ..InteractionContext::default()
    }
}

fn over_case(fabric: u8, now: Instant) -> InteractionContext<'static> {
    InteractionContext {
        fabric_index: Some(FabricIndex(fabric)),
        now,
        ..InteractionContext::default()
    }
}

#[test]
fn a_commissioning_flow_arms_configures_and_completes() {
    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );

    // ArmFailSafe over PASE — the ordinary start of commissioning.
    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::ARM_FAIL_SAFE,
            &arm_fields(60, 1),
            &over_pase(at(0))
        ),
        0
    );
    assert!(device.gc.fail_safe().is_armed(at(0)));
    assert_eq!(device.gc.fail_safe().breadcrumb(), 1);

    // SetRegulatoryConfig sets the Basic Information Location attribute too (§11.10.7.4).
    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::SET_REGULATORY_CONFIG,
            &regulatory_fields(RegulatoryLocation::Indoor, "DE", 2),
            &over_pase(at(1))
        ),
        0
    );
    assert_eq!(location.get(), *b"DE");
    assert_eq!(device.gc.regulatory_config(), RegulatoryLocation::Indoor);
    assert_eq!(device.gc.fail_safe().breadcrumb(), 2);

    // AddNOC would happen here; the fail-safe records it and adopts the new fabric.
    device
        .gc
        .fail_safe_mut()
        .record(at(2), |p| p.added_noc = true)
        .unwrap();
    device
        .gc
        .fail_safe_mut()
        .adopt_fabric(FabricIndex(1), at(2))
        .unwrap();

    // CommissioningComplete over CASE on the new fabric.
    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::COMMISSIONING_COMPLETE,
            &empty_struct(),
            &over_case(1, at(3))
        ),
        0
    );
    assert!(!device.gc.fail_safe().is_armed(at(3)));
    assert_eq!(device.gc.fail_safe().breadcrumb(), 0);
    // §11.10.7.6 steps 3 and 4: the PASE session that commissioned the device must not
    // outlive the commissioning — the passcode stops being a key the moment it is done.
    assert_eq!(device.gc.take_aftermath(), Some(Aftermath::Commissioned));
}

#[test]
fn commissioning_complete_over_pase_is_refused_by_the_server_before_the_cluster() {
    // §11.10.7.6: the command is `AF` — fabric-scoped — so §8.8.2.3 step b.v refuses it over
    // a session with no accessing fabric, with UNSUPPORTED_ACCESS rather than an ErrorCode.
    use matter_kit::im::{InvokeResponse, InvokeResponseMessage, Server};

    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );
    device.gc.arm_fail_safe(60, 0, None, false, at(0));

    let fields = empty_struct();
    let data = CommandData {
        fields: Some(&fields),
        ..CommandData::new(CommandPath::command(
            0,
            general_commissioning::ID,
            general_commissioning::COMMISSIONING_COMPLETE,
        ))
    };
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.gc, 8);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], &over_pase(at(1)), false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).unwrap();
    let first = response.responses().unwrap().next().unwrap().unwrap();
    match first {
        InvokeResponse::Status(s) => assert_eq!(s.status.status, Status::UnsupportedAccess),
        InvokeResponse::Command(_) => panic!("a fabric-scoped command must not run over PASE"),
    }
    // …and the fail-safe is untouched.
    assert!(device.gc.fail_safe().is_armed(at(1)));
}

#[test]
fn set_regulatory_config_sets_location_even_when_the_mode_is_refused() {
    // §11.10.7.4, and this is the asymmetry worth a test of its own: a NewRegulatoryConfig
    // the device cannot honour leaves RegulatoryConfig "unchanged" — but the CountryCode
    // still lands, because a device that refuses the regulatory mode still learns where it is.
    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    // An indoor-only device: §11.10.6.4's "a Node which is 'Indoor Only' would not be
    // certified for outdoor use at all".
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::Indoor,
        &fail_safe,
        &window,
    );
    assert_eq!(device.gc.regulatory_config(), RegulatoryLocation::Indoor);

    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::SET_REGULATORY_CONFIG,
            &regulatory_fields(RegulatoryLocation::Outdoor, "NL", 9),
            &over_pase(at(0))
        ),
        1 // ValueOutsideRange
    );
    assert_eq!(device.gc.regulatory_config(), RegulatoryLocation::Indoor);
    assert_eq!(location.get(), *b"NL");
    // "If the command fails, the Breadcrumb attribute SHALL be left unchanged."
    assert_eq!(device.gc.fail_safe().breadcrumb(), 0);
}

#[test]
fn an_arm_fail_safe_conflict_is_reported_as_busy_with_other_admin() {
    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );

    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::ARM_FAIL_SAFE,
            &arm_fields(600, 1),
            &over_case(1, at(0))
        ),
        0
    );
    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::ARM_FAIL_SAFE,
            &arm_fields(600, 2),
            &over_case(2, at(1))
        ),
        4 // BusyWithOtherAdmin
    );
}

// Opening a real window needs a PAKE verifier, which is cryptography.
#[cfg(feature = "rustcrypto")]
#[test]
fn an_open_commissioning_window_reserves_the_failsafe_for_pase() {
    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );
    open_a_window(&window, at(0));

    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::ARM_FAIL_SAFE,
            &arm_fields(600, 1),
            &over_case(1, at(0))
        ),
        4 // BusyWithOtherAdmin
    );
    // The commissioner on PASE gets it.
    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::ARM_FAIL_SAFE,
            &arm_fields(600, 1),
            &over_pase(at(0))
        ),
        0
    );
}

#[test]
fn a_lapsed_failsafe_is_reaped_by_the_next_command() {
    // The hole a lazily-expiring fail-safe leaves: a device with no timer of its own would
    // otherwise adopt the previous context's half-commissioned state on the next ArmFailSafe.
    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );

    device.gc.arm_fail_safe(60, 1, None, false, at(0));
    device
        .gc
        .fail_safe_mut()
        .record(at(1), |p| p.added_noc = true)
        .unwrap();
    device
        .gc
        .fail_safe_mut()
        .adopt_fabric(FabricIndex(2), at(1))
        .unwrap();

    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::ARM_FAIL_SAFE,
            &arm_fields(60, 5),
            &over_pase(at(100))
        ),
        0
    );
    let Some(Aftermath::Rollback(cleanup)) = device.gc.take_aftermath() else {
        panic!("the lapsed context owed a rollback");
    };
    assert_eq!(cleanup.remove_fabric, Some(FabricIndex(2)));
}

#[test]
fn the_breadcrumb_round_trips_through_a_read_and_a_write() {
    use matter_kit::im::Server;

    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );
    let node = device.node;

    let path = AttributePath::attribute(
        0,
        general_commissioning::ID,
        general_commissioning::BREADCRUMB,
    );

    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.unsigned(Tag::Context(2), 0xDEAD_BEEF).unwrap();
    let encoded = w.finish().unwrap().to_vec();

    let access = AllowAll;
    let server = Server::new(node, &access, &device.gc, 8);
    let mut out = [0u8; 1024];
    server
        .serve_write(
            [Ok(AttributeData {
                data_version: None,
                path,
                data: &encoded,
            })],
            &InteractionContext::default(),
            false,
            &mut out,
        )
        .expect("write");
    assert_eq!(device.gc.fail_safe().breadcrumb(), 0xDEAD_BEEF);

    let bytes = read_attribute(
        node,
        &device.gc,
        0,
        general_commissioning::ID,
        general_commissioning::BREADCRUMB,
    )
    .unwrap();
    assert_eq!(decode_u64(&bytes), 0xDEAD_BEEF);
}

#[test]
fn basic_commissioning_info_carries_both_timers() {
    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );
    let bytes = read_attribute(
        device.node,
        &device.gc,
        0,
        general_commissioning::ID,
        general_commissioning::BASIC_COMMISSIONING_INFO,
    )
    .unwrap();

    let mut reader = TlvReader::new(&bytes);
    reader.next_element().unwrap().unwrap();
    let expiry = reader.next_element().unwrap().unwrap();
    assert_eq!(expiry.tag, Tag::Context(0));
    assert_eq!(expiry.unsigned().unwrap(), 900);
    let cumulative = reader.next_element().unwrap().unwrap();
    assert_eq!(cumulative.tag, Tag::Context(1));
    assert_eq!(cumulative.unsigned().unwrap(), 900);
}

// --- Dispatch --------------------------------------------------------------------------------

#[test]
fn a_tuple_of_clusters_dispatches_on_the_cluster_id() {
    let product = sample_product();
    let attributes = Attributes::new(&product, false, false);
    let location = Location::region_agnostic();
    let clusters = [
        descriptor::cluster(),
        attributes.cluster(),
        general_commissioning::cluster(),
    ];
    let endpoints = [Endpoint::new(0, &clusters).with_device_types(DEVICE_TYPES)];
    let node = Node::new(&endpoints);
    node.validate().expect("well formed");

    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let handler = (
        Descriptor::new(node, 0),
        BasicInformation::new(&product, &location),
        GeneralCommissioning::new(
            &location,
            RegulatoryLocation::IndoorOutdoor,
            &fail_safe,
            &window,
        ),
    );

    // Each member answers for its own id and none other.
    assert_eq!(
        decode_u64_array(
            &read_attribute(node, &handler, 0, descriptor::ID, descriptor::SERVER_LIST).unwrap()
        ),
        vec![
            u64::from(descriptor::ID),
            u64::from(basic_information::ID),
            u64::from(general_commissioning::ID),
        ]
    );
    assert_eq!(
        decode_utf8(
            &read_attribute(
                node,
                &handler,
                0,
                basic_information::ID,
                basic_information::VENDOR_NAME
            )
            .unwrap()
        ),
        "Test Vendor"
    );
    assert_eq!(
        decode_u64(
            &read_attribute(
                node,
                &handler,
                0,
                general_commissioning::ID,
                general_commissioning::LOCATION_CAPABILITY
            )
            .unwrap()
        ),
        2
    );
}

#[test]
fn the_cluster_trait_ids_agree_with_the_module_constants() {
    assert_eq!(<Descriptor<'_> as Cluster>::ID, descriptor::ID);
    assert_eq!(<BasicInformation<'_> as Cluster>::ID, basic_information::ID);
    assert_eq!(
        <GeneralCommissioning<'_> as Cluster>::ID,
        general_commissioning::ID
    );
}

#[test]
fn a_truncated_command_is_rejected_not_defaulted() {
    // `ExpiryLengthSeconds` has a fallback of 900, so a decoder that treats a *decode error*
    // as an end of input would accept a truncated `ArmFailSafe` and arm the fail-safe for
    // fifteen minutes on garbage. The two are different failures and must stay different.
    let clusters = gc_clusters();
    let endpoints = [Endpoint::new(0, &clusters)];
    let location = Location::region_agnostic();
    let fail_safe = fresh_fail_safe();
    let window = closed_window();
    let device = device(
        &endpoints,
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );

    let whole = arm_fields(60, 1);
    for cut in 1..whole.len() {
        let truncated = whole.get(..cut).expect("in range");
        let status = invoke_status(&device, general_commissioning::ARM_FAIL_SAFE, truncated);
        assert!(
            !device.gc.fail_safe().is_armed(at(0)),
            "a {cut}-octet ArmFailSafe armed the fail-safe: {status:?}"
        );
        // …and the breadcrumb, which every successful ArmFailSafe writes, is untouched.
        assert_eq!(device.gc.fail_safe().breadcrumb(), 0);
    }
    // The whole thing still works.
    assert_eq!(
        invoke_error(
            &device,
            general_commissioning::ARM_FAIL_SAFE,
            &whole,
            &over_pase(at(0))
        ),
        0
    );
}

/// Invokes a command and returns either the response command's id or the status.
fn invoke_status(device: &Device<'_>, command: u32, fields: &[u8]) -> Result<u32, Status> {
    use matter_kit::im::{InvokeResponse, InvokeResponseMessage, Server};

    let data = CommandData {
        fields: Some(fields),
        ..CommandData::new(CommandPath::command(0, general_commissioning::ID, command))
    };
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.gc, 8);
    let Ok((bytes, _)) =
        server.serve_invoke([Ok(data)], &over_pase(at(0)), false, &mut scratch, &mut buf)
    else {
        return Err(Status::InvalidAction);
    };
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    match response
        .responses()
        .expect("responses")
        .next()
        .expect("one")
        .expect("decode")
    {
        InvokeResponse::Command(c) => Ok(c.path.command.unwrap_or(0)),
        InvokeResponse::Status(s) => Err(s.status.status),
    }
}

#[test]
fn capability_minima_carries_the_revision_6_fields_by_default() {
    // §11.1.4.4 gives fields 2 to 5 the conformance "Rev >= v6", and this cluster declares
    // revision 6 — so they are mandatory, and a default that left them out described a node one
    // revision older than the one it claimed to be. `TC_IDM_2_3` reads
    // `CapabilityMinima` in its first step and fails on exactly that.
    let product = sample_product();
    let attributes = Attributes::new(&product, false, false);
    let clusters = [attributes.cluster()];
    let endpoints = [Endpoint::new(0, &clusters)];
    let node = Node::new(&endpoints);
    let location = Location::region_agnostic();
    let info = BasicInformation::new(&product, &location);
    let bytes = read_attribute(
        node,
        &info,
        0,
        basic_information::ID,
        basic_information::CAPABILITY_MINIMA,
    )
    .unwrap();
    assert_eq!(
        struct_tags(&bytes),
        vec![0, 1, 2, 3, 4, 5],
        "a revision-6 cluster sent a pre-revision-6 CapabilityMinimaStruct"
    );
}

// `session` is behind `rustcrypto`, and `CapabilityMinima` is derived from the session table.
#[cfg(feature = "rustcrypto")]
#[test]
fn capability_minima_reports_the_tables_it_describes() {
    // §11.1.4.4 says each field is "the **actual**" number the node supports, so every one of
    // them has exactly one honest source: the table that will have to honour it. A figure taken
    // from `Config` instead would describe whatever the integrator wrote beside it — and this
    // attribute is read once, at commissioning, by a client that believes it.
    use matter_kit::config::{Capacity, Config, DefaultConfig, SubscriptionCapacity};
    use matter_kit::im::SubscriptionTable;
    use matter_kit::session::SessionTable;

    type Sessions = SessionTable<DefaultConfig, 16>;
    type Subs = SubscriptionTable<DefaultConfig>;

    let minima = CapabilityMinima::from_tables::<DefaultConfig, Sessions, Subs>();
    assert_eq!(
        minima.read_paths,
        Some(DefaultConfig::READ_PATHS as u16),
        "ReadPathsSupported must be §2.11.2.1's real limit"
    );
    assert_eq!(
        minima.subscribe_paths,
        Some(<Subs as SubscriptionCapacity>::PATHS as u16),
        "SubscribePathsSupported must be the table's own path width"
    );
    assert_eq!(
        minima.subscriptions_per_fabric,
        <Subs as Capacity>::PER_FABRIC as u16
    );
    assert_eq!(
        minima.case_sessions_per_fabric,
        <Sessions as Capacity>::PER_FABRIC as u16,
        "CaseSessionsPerFabric is the session table divided among the fabrics, not a floor"
    );
    // §4.14.2.8's floor of three per fabric — which `SessionTable::CHECK` is what guarantees,
    // so this assertion can be about the real number rather than about a clamp.
    assert!(minima.case_sessions_per_fabric >= 3);
    assert!(minima.simultaneous_invocations.is_some_and(|n| n >= 1));
    assert!(minima.simultaneous_writes.is_some_and(|n| n >= 1));
}
