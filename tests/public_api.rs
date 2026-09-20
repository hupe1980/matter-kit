//! The public surface nothing else drives.
//!
//! `cargo xtask api` reports every `pub fn` with no caller in the crate, the tests, the examples
//! or the fuzz targets. Three of those turned out to be the missing half of a specification rule
//! rather than spare API — §11.10.7.6's network-list commit, §4.11.1.1's eviction candidate,
//! §4.13.3.1's exchange cleanup — and the rest are what this file is for: builders and queries an
//! integrator calls and nothing here did, which means nothing here checked them.
//!
//! The assertions are deliberately of one shape: **set something, then read it back through the
//! API an integrator would use.** A builder that assigns to the wrong field, a getter that
//! returns its neighbour, a default that is not what the documentation claims — all of them
//! compile, and none of them survives a round trip.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::Cell;

use matter_kit::clusters::level_control::{LevelControl, LevelControlHooks};
use matter_kit::clusters::{descriptor, level_control, on_off};
use matter_kit::dm::spec::Optional;

#[derive(Debug, Default)]
struct Dimmer {
    level: Cell<u8>,
}

impl LevelControlHooks for Dimmer {
    fn level(&self, level: Option<u8>) {
        self.level.set(level.unwrap_or(0));
    }
}

/// §1.6.6.3–4: the range is the device's, *unless* it has the Lighting feature — in which case
/// the specification fixes it at 1..=254 and a device that narrowed it would advertise a
/// `MinLevel` its own device type forbids.
#[test]
fn a_level_range_is_the_devices_to_set_and_lightings_to_refuse() {
    let dimmer = Dimmer::default();

    // A dimmer that is not a light: the range is whatever it says.
    let plain = LevelControl::new(&dimmer, 0).with_range(10, 200);
    assert_eq!(plain.min_level(), 10);
    assert_eq!(plain.max_level(), 200);

    // A lighting device: the same call changes nothing.
    let lighting = LevelControl::new(&dimmer, level_control::feature::LIGHTING).with_range(10, 200);
    assert_eq!(
        (lighting.min_level(), lighting.max_level()),
        (1, 254),
        "§1.6.6.3: with Lighting the range is the specification's"
    );

    // And a range given the wrong way round is refused rather than stored inverted.
    let inverted = LevelControl::new(&dimmer, 0).with_range(200, 10);
    assert!(inverted.min_level() <= inverted.max_level());
}

/// §1.6.6.7–8: the Frequency feature's own range, which is a different pair of attributes from
/// the level's — so setting one must not disturb the other.
#[test]
fn a_frequency_range_is_a_different_pair_from_the_level_range() {
    let dimmer = Dimmer::default();
    let cluster = LevelControl::new(&dimmer, 0)
        .with_range(5, 100)
        .with_frequency(50, 60_000);
    assert_eq!((cluster.min_level(), cluster.max_level()), (5, 100));
}

/// §9.5.6.3's `TagList`, which is how an endpoint says *which* of two identical outlets it is.
#[test]
fn a_descriptors_tag_list_is_the_one_it_was_given() {
    let clusters = [descriptor::cluster()];
    let endpoints = [matter_kit::dm::Endpoint::new(1, &clusters)];
    let node = matter_kit::dm::Node::new(&endpoints);

    static TAGS: &[descriptor::SemanticTag<'static>] = &[descriptor::SemanticTag {
        mfg_code: None,
        namespace_id: 0x08,
        tag: 0x01,
        label: Some("left"),
    }];
    // What a tag list changes is what the endpoint *advertises*: §9.5.4's `TAGLIST` feature and
    // the attribute that comes with it. A builder that stored the tags and left the descriptor
    // alone would produce a node serving an attribute its own `AttributeList` denies.
    let tagged = descriptor::Descriptor::new(node, 1).with_tags(TAGS);
    let plain = descriptor::Descriptor::new(node, 1);
    assert!(
        tagged.descriptor().feature_map != plain.descriptor().feature_map,
        "§9.5.4: a tag list is a feature, and the feature map has to say so"
    );
    assert!(
        tagged
            .descriptor()
            .attributes
            .iter()
            .any(|a| a.id == descriptor::TAG_LIST),
        "the attribute appears because the feature was claimed"
    );
}

/// §11.1.5.17: `LocalConfigDisabled` is optional, so it is absent unless a device says
/// otherwise — "a node that does not have an on-node user interface has nothing to disable".
#[test]
fn basic_informations_optional_attributes_are_absent_until_asked_for() {
    use matter_kit::clusters::basic_information::{BasicInformation, Location, Product};
    use matter_kit::msg::VendorId;

    const PRODUCT: Product<'static> = Product::new("V", VendorId(0xFFF1), "P", 0x8000, "S");
    let location = Location::region_agnostic();

    let bare = BasicInformation::new(&PRODUCT, &location);
    assert!(!bare.serves_local_config_disabled());
    assert!(!bare.serves_reachable());

    let configured = BasicInformation::new(&PRODUCT, &location)
        .with_local_config_disabled(true)
        .with_reachable(true);
    assert!(configured.serves_local_config_disabled());
    assert!(configured.serves_reachable());
}

/// §5.5: a device that cannot hold two networks at once tells the commissioner so, and the
/// commissioner then runs the non-concurrent flow — which is a different sequence, not a slower
/// one.
#[test]
fn a_non_concurrent_device_says_so_in_basic_commissioning_info() {
    use matter_kit::clusters::general_commissioning::{GeneralCommissioning, RegulatoryLocation};
    use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
    use matter_kit::commissioning::window::CommissioningWindow;
    let location = matter_kit::clusters::basic_information::Location::region_agnostic();
    let fail_safe = core::cell::RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let window = core::cell::RefCell::new(CommissioningWindow::new());

    let concurrent = GeneralCommissioning::new(
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );
    assert!(concurrent.supports_concurrent_connection);

    let sequential = GeneralCommissioning::new(
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    )
    .without_concurrent_connection();
    assert!(!sequential.supports_concurrent_connection);
}

/// §5.4.2.5.7: the C3 characteristic carries Additional Data, and the advertisement says whether
/// it is there. A commissioner that read the flag wrong would either miss the data or wait for
/// data that does not exist.
#[test]
fn a_ble_advertisement_carries_the_flags_it_was_built_with() {
    use matter_kit::msg::VendorId;
    use matter_kit::transport::ble::Advertisement;

    let payload = matter_kit::commissioning::OnboardingPayload::new(
        VendorId(0xFFF1),
        0x8000,
        0xF00,
        matter_kit::commissioning::Passcode::new(20_202_021).expect("a valid passcode"),
        matter_kit::commissioning::DiscoveryCapabilities::BLE,
        matter_kit::commissioning::CustomFlow::Standard,
    )
    .expect("a valid payload");
    let plain = Advertisement::for_onboarding(&payload);
    let extended = plain
        .with_extended_announcement(true)
        .with_additional_data(true);

    let mut plain_bytes = [0u8; 32];
    let mut extended_bytes = [0u8; 32];
    let a = plain.encode(&mut plain_bytes).expect("encode");
    let b = extended.encode(&mut extended_bytes).expect("encode");
    assert_ne!(
        plain_bytes[..a],
        extended_bytes[..b],
        "§5.4.2.5.6's flags are in the service data, so setting one has to change it"
    );
}

/// The On/Off cluster's own state, read back through the API a device uses to drive a lamp.
#[test]
fn on_off_reports_the_state_it_was_started_in() {
    use matter_kit::clusters::on_off::{OnOff, OnOffHooks};

    #[derive(Debug, Default)]
    struct Lamp(Cell<bool>);
    impl OnOffHooks for Lamp {
        fn set(&self, on: bool) {
            self.0.set(on);
        }
    }

    let lamp = Lamp::default();
    let cluster = OnOff::new(&lamp, on_off::feature::LIGHTING, None);
    cluster.start(true);
    assert!(cluster.is_on());
    assert!(lamp.0.get(), "starting the cluster drives the hook");

    let conforming =
        OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE).expect("descriptor");
    assert!(
        conforming
            .descriptor()
            .attributes
            .iter()
            .any(|a| a.id == on_off::START_UP_ON_OFF),
        "§1.5.6.5: StartUpOnOff exists because Lighting was claimed"
    );
}

/// §6.6.1's privilege chain, reduced to one answer for a cluster that needs one — with
/// ProxyView left out of it deliberately.
///
/// "Administer subsumes Manage subsumes Operate subsumes View", and ProxyView sits outside that
/// chain: it grants nothing the other four do. A `highest` that returned it would hand a cluster
/// a privilege §9.10.5.2 never meant as an answer to "what may this subject do here".
#[test]
fn the_highest_privilege_follows_the_subsumption_chain_and_skips_proxy_view() {
    use matter_kit::DefaultConfig;
    use matter_kit::acl::{Acl, AuthMode, Entry, SubjectDescriptor};
    use matter_kit::dm::{Endpoint, Node, Privilege};
    use matter_kit::msg::{FabricIndex, NodeId};

    const F1: FabricIndex = FabricIndex(1);
    const ADMIN: NodeId = NodeId(0x0000_0000_0001_0001);
    let clusters = [descriptor::cluster()];
    let endpoints = [Endpoint::new(1, &clusters)];
    let node = Node::new(&endpoints);

    let mut acl: Acl<DefaultConfig, 20, 4, 3> = Acl::new();
    let subject = SubjectDescriptor::case(F1, ADMIN);

    // Nothing granted: no answer at all.
    assert_eq!(acl.granted(&node, &subject, 1, 0x001D).highest(), None);

    // Administer subsumes the rest, so it is both "the" privilege and implies View.
    acl.add(
        Entry::case(F1, Privilege::Administer)
            .with_subject(ADMIN)
            .unwrap(),
    )
    .unwrap();
    let granted = acl.granted(&node, &subject, 1, 0x001D);
    assert_eq!(granted.highest(), Some(Privilege::Administer));
    assert!(
        granted.has(Privilege::View),
        "§6.6.1: Administer subsumes View"
    );

    // ProxyView alone: something was granted, and it is not an answer to "what may this do".
    let mut proxy_only: Acl<DefaultConfig, 20, 4, 3> = Acl::new();
    let mut subjects = heapless::Vec::new();
    subjects.push(ADMIN).unwrap();
    proxy_only
        .add(Entry {
            fabric_index: F1,
            privilege: Privilege::ProxyView,
            auth_mode: AuthMode::Case,
            subjects,
            targets: heapless::Vec::new(),
        })
        .unwrap();
    let granted = proxy_only.granted(&node, &subject, 1, 0x001D);
    assert!(!granted.is_empty(), "ProxyView was granted");
    assert_eq!(
        granted.highest(),
        None,
        "§9.10.5.2: ProxyView is outside the chain, so it is never `the` privilege"
    );
}

/// §6.6.5.1's target, narrowed. An ACL entry naming an endpoint *and* a cluster reaches one
/// cluster on one endpoint — and a builder that dropped the endpoint would widen the grant.
#[test]
fn narrowing_a_target_keeps_what_it_was_narrowed_from() {
    use matter_kit::acl::Target;

    let endpoint_only = Target::endpoint(1);
    assert_eq!(endpoint_only.endpoint, Some(1));
    assert_eq!(endpoint_only.cluster, None);

    let both = Target::endpoint(1).and_cluster(0x0006);
    assert_eq!(
        (both.endpoint, both.cluster),
        (Some(1), Some(0x0006)),
        "narrowing adds a condition and keeps the one it started with"
    );
    assert_eq!(both.device_type, None);
}

/// §11.22.5.2: which message opens a transfer, and which accepts it, depends on the direction —
/// and getting the pair the wrong way round is a transfer both ends wait on.
#[test]
fn a_bdx_direction_names_its_own_opcodes() {
    use matter_kit::bdx::message::MessageType;
    use matter_kit::bdx::transfer::Direction;

    assert_eq!(Direction::Upload.init(), MessageType::SendInit);
    assert_eq!(Direction::Download.init(), MessageType::ReceiveInit);
    assert_ne!(
        Direction::Upload.init(),
        Direction::Download.init(),
        "the two directions cannot share an opening message"
    );
}

/// RFC 1035 §3.1: a name is a sequence of length-prefixed labels, and building one from labels
/// has to produce the same thing reading one back does.
#[test]
fn a_dns_name_round_trips_through_its_labels() {
    use matter_kit::discovery::dns::Name;

    let name = Name::from_labels(&[b"_matter", b"_tcp", b"local"]).expect("a valid name");
    let labels: Vec<&[u8]> = name.labels().collect();
    assert_eq!(labels, vec![&b"_matter"[..], &b"_tcp"[..], &b"local"[..]]);
}
