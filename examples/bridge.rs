//! A bridge: one Matter node presenting devices it does not contain.
//!
//! ```text
//! cargo run --example bridge --features std
//! ```
//!
//! A Zigbee gateway, a Z-Wave hub, a cloud integration — anything that speaks Matter on one
//! side and something else on the other. From a commissioner's point of view it is a single
//! node with a lot of endpoints, and Core §9.12 spells out the shape:
//!
//! ```text
//! endpoint 0   Root Node        the node itself
//! endpoint 1   Aggregator       PartsList = [2, 3]
//! endpoint 2     Bridged Node + On/Off Light      "Kitchen"   (a Zigbee bulb)
//! endpoint 3     Bridged Node + On/Off Light      "Hallway"   (a Z-Wave switch)
//! ```
//!
//! Three things make this different from `examples/light`, and each is the subject of one
//! section below: routing by endpoint, the `PartsList` tree, and `Reachable`.
//!
//! This example has no sockets — `examples/light` is the one that owns an event loop, and
//! repeating it here would bury what is actually new. Instead it builds the node and reads it
//! the way a commissioner would, in process.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::too_many_lines
)]

use core::cell::RefCell;

use matter_kit::clusters::bridged_device_basic_information::{
    self as bdbi, BridgedDevice, BridgedDeviceBasicInformation,
};
use matter_kit::clusters::generated::device_types::{AGGREGATOR, BRIDGED_NODE, ON_OFF_LIGHT};
use matter_kit::clusters::groups::{self, Groups};
use matter_kit::clusters::identify::{
    EffectIdentifierEnum, EffectVariantEnum, Identify, IdentifyHooks, IdentifyTypeEnum,
};
use matter_kit::clusters::on_off::{self, OnOff, OnOffHooks};
use matter_kit::clusters::scenes::{self, ExtensionFieldSetStruct, SceneHooks, SceneTable, Scenes};
use matter_kit::clusters::{At, Descriptor, Endpoints, descriptor, validate_endpoint};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, DeviceType, Endpoint, Node, Privilege};
use matter_kit::im::{
    AttributePath, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Outcome, Server,
};
use matter_kit::msg::{FabricIndex, VendorId};
use matter_kit::tlv::{Pretty, Tag, TlvList, TlvWriter};

/// How many devices this bridge can present. A no-alloc node's endpoint set is fixed at build
/// time, which is not the limitation it sounds like — see "A bridge that loses a device".
const BRIDGED: usize = 2;

/// Sizing for each bridged device's Groups and Scenes tables.
const GROUP_SLOTS: usize = 8;
const GROUPS_PER_FABRIC: usize = 3;
const SCENE_SLOTS: usize = 16;
const SCENE_BYTES: usize = 96;
const FABRICS: usize = 5;

type Table = SceneTable<SCENE_SLOTS, SCENE_BYTES, FABRICS>;
type GroupTable<'a> = Groups<'a, GROUP_SLOTS, Identify<'a, Lamp>, Table>;
type SceneCluster<'a> = Scenes<'a, Lamp, GroupTable<'a>, SCENE_SLOTS, SCENE_BYTES, FABRICS>;

/// One device on the far side of the bridge.
///
/// It is not a Matter device: it is whatever the bridge talks to. All this example does with
/// it is print, which is exactly what a real bridge's hooks do differently and nothing else
/// about the assembly changes.
#[derive(Debug)]
struct Lamp {
    name: &'static str,
    on: RefCell<bool>,
}

impl Lamp {
    const fn new(name: &'static str) -> Self {
        Self {
            name,
            on: RefCell::new(false),
        }
    }
}

impl OnOffHooks for Lamp {
    fn set(&self, on: bool) {
        *self.on.borrow_mut() = on;
        println!(
            "    → {} is now {}",
            self.name,
            if on { "on" } else { "off" }
        );
    }
}

impl IdentifyHooks for Lamp {
    fn identifying(&self, on: bool) {
        println!(
            "    → {} {} identifying",
            self.name,
            if on { "started" } else { "stopped" }
        );
    }

    fn trigger_effect(&self, effect: EffectIdentifierEnum, variant: EffectVariantEnum) {
        println!("    → {}: {effect:?} / {variant:?}", self.name);
    }
}

impl SceneHooks for Lamp {
    fn capture(&self, w: &mut TlvWriter<'_>) -> matter_kit::error::Result<()> {
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(on_off::ID))?;
        w.start_array(Tag::Context(1))?;
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(on_off::ON_OFF))?;
        w.unsigned(Tag::Context(1), u64::from(*self.on.borrow()))?;
        w.end_container()?;
        w.end_container()?;
        w.end_container()
    }

    fn apply<'a>(&self, sets: TlvList<'a, ExtensionFieldSetStruct<'a>>, transition: u32) {
        for set in sets.iter() {
            let Ok(set) = set else { continue };
            if set.cluster_id != on_off::ID {
                continue;
            }
            for pair in set.attribute_value_list.iter() {
                let Ok(pair) = pair else { continue };
                if pair.attribute_id == on_off::ON_OFF {
                    println!("    → {} over {transition} ms", self.name);
                    self.set(pair.value_unsigned8.unwrap_or(0) != 0);
                }
            }
        }
    }
}

/// This example reads and invokes as a fully-privileged administrator; `examples/light` is the
/// one that shows the real ACL.
struct AllowAll;

impl matter_kit::im::AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

fn main() {
    println!("Matter bridge — one node, two devices it does not contain\n");

    // --- The far side ------------------------------------------------------------------------
    let lamps = [Lamp::new("Kitchen"), Lamp::new("Hallway")];

    // What the bridge knows about each. §9.13.5.1: an attribute the bridge cannot fill is
    // *left out*, not sent empty — so a controller can tell "the bridge does not know the
    // vendor" from "the vendor is called nothing". The Zigbee bulb reported a manufacturer
    // code; the Z-Wave switch did not, and it gets no `VendorID` at all.
    let known = [
        BridgedDevice {
            vendor_name: Some("Example Lighting"),
            vendor_id: Some(VendorId(0xFFF1)),
            product_name: Some("Zigbee A19"),
            unique_id: Some("zb-0017880103a1b2c3"),
            serial_number: Some("A19-000123"),
            ..BridgedDevice::default()
        },
        BridgedDevice {
            vendor_name: Some("Example Controls"),
            product_name: Some("Z-Wave Switch"),
            // §9.13.5.3: "If the bridged device does not provide some unique id ... the bridge
            // SHALL generate a unique id on behalf of the bridged device." This one is the
            // bridge's own invention, and it is what lets a controller recognise the same
            // switch after the bridge renumbers its endpoints.
            unique_id: Some("zw-generated-7f3a"),
            ..BridgedDevice::default()
        },
    ];

    // --- The clusters ------------------------------------------------------------------------
    //
    // Built as arrays rather than named one by one, because a bridge's per-device state is
    // uniform by construction and the borrows nest the same way every time: the Scene Table
    // first, then Identify, then Groups (which asks Identify whether the endpoint is
    // identifying, and the table what to purge), then Scenes (which asks Groups whether a
    // group exists).
    let tables: [Table; BRIDGED] = [Table::new(true), Table::new(true)];
    let identifies: [Identify<'_, Lamp>; BRIDGED] = [
        Identify::new(&lamps[0], IdentifyTypeEnum::LightOutput),
        Identify::new(&lamps[1], IdentifyTypeEnum::LightOutput),
    ];
    let group_clusters: [GroupTable<'_>; BRIDGED] = [
        Groups::with(GROUPS_PER_FABRIC, true, &identifies[0], &tables[0]),
        Groups::with(GROUPS_PER_FABRIC, true, &identifies[1], &tables[1]),
    ];
    let scene_clusters: [SceneCluster<'_>; BRIDGED] = [
        Scenes::new(&tables[0], &group_clusters[0], &lamps[0], true),
        Scenes::new(&tables[1], &group_clusters[1], &lamps[1], true),
    ];
    let on_offs: [OnOff<'_, Lamp>; BRIDGED] = [
        OnOff::new(&lamps[0], on_off::feature::LIGHTING, None),
        OnOff::new(&lamps[1], on_off::feature::LIGHTING, None),
    ];
    // Both start reachable. The Z-Wave switch will drop out below.
    let basics: [BridgedDeviceBasicInformation<'_>; BRIDGED] = [
        BridgedDeviceBasicInformation::new(known[0], true),
        BridgedDeviceBasicInformation::new(known[1], true),
    ];

    // --- The descriptors ---------------------------------------------------------------------
    //
    // Every one of these is derived from the specification's own tables: give it a feature map
    // and the optional elements the product implements, and the element set follows. Nothing
    // below lists an attribute by hand.
    let identify_d = Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT)
        .expect("the Identify set fits");
    let groups_d = Groups::<GROUP_SLOTS>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE)
        .expect("the Groups set fits");
    let on_off_d = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE)
        .expect("the On/Off Lighting set fits");
    let scenes_d =
        SceneCluster::conforming(scenes::feature::SCENE_NAMES, &SceneCluster::WITH_COPY_SCENE)
            .expect("the Scenes set fits");
    // §9.13's optional set is not a style choice: it is derived from what the bridge actually
    // knows, so the two bridged devices advertise *different* attribute lists.
    let mut optional_buf = [[0u32; 16], [0u32; 16]];
    let (first, rest) = optional_buf.split_at_mut(1);
    let bdbi_optional = [
        BridgedDeviceBasicInformation::optional_for(&known[0], &mut first[0]),
        BridgedDeviceBasicInformation::optional_for(&known[1], &mut rest[0]),
    ];
    let bdbi_d = [
        BridgedDeviceBasicInformation::conforming(0, &bdbi_optional[0]).expect("fits"),
        BridgedDeviceBasicInformation::conforming(0, &bdbi_optional[1]).expect("fits"),
    ];

    // --- The node ----------------------------------------------------------------------------
    //
    // Endpoint 0 is the node; endpoint 1 is the Aggregator, and its `PartsList` is what makes
    // endpoints 2 and 3 *bridged* rather than just present. §9.13: "This cluster SHALL NOT be
    // used on an endpoint that is not in the Descriptor cluster PartsList of an endpoint with
    // an Aggregator device type" — so the tree is the rule, not a convention.
    let root_clusters = [descriptor::cluster()];
    let aggregator_clusters = [descriptor::cluster()];
    let bridged_clusters: [[ClusterDescriptor<'_>; 6]; BRIDGED] = [
        bridged_set(&identify_d, &groups_d, &on_off_d, &scenes_d, &bdbi_d[0]),
        bridged_set(&identify_d, &groups_d, &on_off_d, &scenes_d, &bdbi_d[1]),
    ];

    const ROOT: &[DeviceType] = &[DeviceType::new(0x0016, 4)];
    const AGGREGATOR_TYPE: &[DeviceType] = &[DeviceType::new(0x000E, 2)];
    // Two device types on one endpoint, which is the normal case for a bridge: §9.12 says
    // *what it is attached to* (Bridged Node) and §4.1 says *what it does* (On/Off Light).
    const BRIDGED_LIGHT: &[DeviceType] = &[DeviceType::new(0x0013, 3), DeviceType::new(0x0100, 3)];
    const PARTS: &[u16] = &[2, 3];

    let endpoints = [
        Endpoint::new(0, &root_clusters).with_device_types(ROOT),
        Endpoint::new(1, &aggregator_clusters).with_device_types(AGGREGATOR_TYPE),
        Endpoint::new(2, &bridged_clusters[0]).with_device_types(BRIDGED_LIGHT),
        Endpoint::new(3, &bridged_clusters[1]).with_device_types(BRIDGED_LIGHT),
    ];
    let node = Node::new(&endpoints);
    node.validate().expect("the clusters are sorted by id");

    // --- Routing by endpoint -------------------------------------------------------------
    //
    // A tuple of clusters dispatches on the cluster id, which is all a one-endpoint device
    // needs. Here the id is not an address: four endpoints serve Descriptor, and two of them
    // serve On/Off. `At` supplies the missing half and `Endpoints` routes on it — endpoint
    // first, cluster second, which is the order a concrete path names them in.
    let handler = Endpoints((
        At::new(0, (Descriptor::new(node, 0).with_parts(&[1]),)),
        At::new(1, (Descriptor::new(node, 1).with_parts(PARTS),)),
        At::new(
            2,
            (
                Descriptor::new(node, 2),
                &identifies[0],
                &group_clusters[0],
                &on_offs[0],
                &basics[0],
                &scene_clusters[0],
            ),
        ),
        At::new(
            3,
            (
                Descriptor::new(node, 3),
                &identifies[1],
                &group_clusters[1],
                &on_offs[1],
                &basics[1],
                &scene_clusters[1],
            ),
        ),
    ));

    let access = AllowAll;
    let server = Server::new(node, &access, &handler, 24);

    // --- What a commissioner sees ---------------------------------------------------------
    println!("The node, as its descriptors report it:\n");
    for endpoint in &endpoints {
        let types: Vec<&str> = endpoint
            .device_types
            .iter()
            .map(|d| name_of(d.device_type))
            .collect();
        println!(
            "  endpoint {:<2} {:<34} {} cluster(s)",
            endpoint.id,
            types.join(" + "),
            endpoint.clusters.len()
        );
    }

    println!("\nAnd every endpoint's claim holds against the Device Library:\n");
    for endpoint in &endpoints {
        for claimed in endpoint.device_types {
            let Some(spec) = library(claimed.device_type) else {
                continue;
            };
            let mut defects = Vec::new();
            validate_endpoint(endpoint, spec, |defect| defects.push(defect));
            println!(
                "  endpoint {:<2} {:<26} {}",
                endpoint.id,
                spec.name,
                if defects.is_empty() {
                    "furnished".to_string()
                } else {
                    format!("{defects:?}")
                }
            );
            assert!(defects.is_empty(), "endpoint {}: {defects:?}", endpoint.id);
        }
    }

    // --- The PartsList tree ------------------------------------------------------------------
    println!("\nThe Aggregator's PartsList is what makes 2 and 3 bridged:\n");
    print_attribute(&server, 1, descriptor::ID, descriptor::PARTS_LIST);

    // --- Two endpoints, one cluster id ---------------------------------------------------
    println!("\nOn/Off on endpoint 2 and on endpoint 3 are different instances:\n");
    invoke(&server, 2, on_off::ID, on_off::ON);
    invoke(&server, 3, on_off::ID, on_off::TOGGLE);
    invoke(&server, 2, on_off::ID, on_off::OFF);

    // --- A bridge that loses a device ----------------------------------------------------
    //
    // A no-alloc node's endpoint set is fixed at build time, and §9.13.5.2 is why that is the
    // right shape rather than a limitation. When a bridged device goes away the endpoint does
    // *not* disappear: `Reachable` goes false, `ReachableChanged` is emitted, and a controller
    // that had a binding or a scene pointing at endpoint 3 still has one. An endpoint that
    // vanished and came back renumbered would break every one of them.
    println!("\nThe Z-Wave switch stops answering:\n");
    basics[1].set_reachable(false);
    for event in basics[1].take_events() {
        println!("  event on endpoint 3: {event:?}");
    }
    print_attribute(&server, 3, bdbi::ID, bdbi::REACHABLE);

    println!("\n...and comes back:\n");
    basics[1].set_reachable(true);
    for event in basics[1].take_events() {
        println!("  event on endpoint 3: {event:?}");
    }
    // §9.13.7.1 fires on the *change*. A bridge that re-polls every thirty seconds must not
    // emit an event every thirty seconds: the event store is a fixed ring, and a chatty
    // record pushes out everything else in it.
    basics[1].set_reachable(true);
    println!(
        "  re-asserting the same value emits {} further events",
        basics[1].take_events().len()
    );

    // --- What the two devices advertise --------------------------------------------------
    println!("\nThe bridge knows different things about each, and says only what it knows:\n");
    for (index, endpoint) in [(0usize, 2u16), (1, 3)] {
        let ids: Vec<String> = bdbi_d[index]
            .descriptor()
            .attributes
            .iter()
            .map(|a| format!("{:#06x}", a.id))
            .collect();
        println!("  endpoint {endpoint}: {}", ids.join(" "));
    }
    println!("\n  endpoint 2 has VendorID (0x0002); endpoint 3 does not, because the bridge");
    println!("  never learned one — §9.13.5.1 says leave it out rather than send a zero.");
}

/// One bridged endpoint's clusters, sorted by id as `Node::validate` requires.
fn bridged_set<'a>(
    identify: &'a matter_kit::dm::spec::Conforming<2, 2, 0, 0>,
    groups: &'a matter_kit::dm::spec::Conforming<1, 6, 4, 0>,
    on_off: &'a matter_kit::dm::spec::Conforming<5, 6, 0, 0>,
    scenes: &'a matter_kit::dm::spec::Conforming<2, 8, 7, 0>,
    basic: &'a matter_kit::dm::spec::Conforming<16, 1, 0, 2>,
) -> [ClusterDescriptor<'a>; 6] {
    [
        identify.descriptor(), // 0x0003
        groups.descriptor(),   // 0x0004
        on_off.descriptor(),   // 0x0006
        descriptor::cluster(), // 0x001D
        basic.descriptor(),    // 0x0039
        scenes.descriptor(),   // 0x0062
    ]
}

/// The Device Library entry for an id this example uses.
fn library(id: u32) -> Option<&'static matter_kit::dm::device::DeviceType> {
    match id {
        0x000E => Some(&AGGREGATOR),
        0x0013 => Some(&BRIDGED_NODE),
        0x0100 => Some(&ON_OFF_LIGHT),
        // The Root Node's own requirements are `examples/light`'s subject; this example builds
        // endpoint 0 with a Descriptor and nothing else, so checking it here would report the
        // commissioning clusters it deliberately leaves out.
        _ => None,
    }
}

fn name_of(id: u32) -> &'static str {
    library(id).map_or("Root Node", |d| d.name)
}

/// Reads one attribute through the interaction model and prints the TLV a client would get.
fn print_attribute(
    server: &Server<'_, AllowAll, impl ClusterHandler>,
    endpoint: u16,
    cluster: u32,
    attribute: u32,
) {
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 2048];
    let ctx = InteractionContext::new().with_fabric(FabricIndex(1));
    let (bytes, _) = server
        .serve(
            [Ok(AttributePath::attribute(endpoint, cluster, attribute))],
            &ctx,
            None,
            &mut scratch,
            &mut buf,
        )
        .expect("read");
    println!("{}", Pretty(bytes));
}

/// Invokes one command through the interaction model.
fn invoke(
    server: &Server<'_, AllowAll, impl ClusterHandler>,
    endpoint: u16,
    cluster: u32,
    command: u32,
) {
    let data = CommandData::new(CommandPath::command(endpoint, cluster, command));
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let ctx = InteractionContext::new().with_fabric(FabricIndex(1));
    let (bytes, _) = server
        .serve_invoke([Ok(data)], &ctx, false, &mut scratch, &mut buf)
        .expect("invoke");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    if let Some(Ok(InvokeResponse::Status(status))) = responses.next() {
        println!(
            "  endpoint {endpoint} command {command:#04x}: {:?}",
            status.status.status
        );
    }
}
