//! The hand-written clusters, checked against the specification's own tables.
//!
//! Every cluster in [`clusters`](matter_kit::clusters) was transcribed by hand from the
//! specification PDF. Every cluster in [`clusters::generated`] was produced by `matter-gen`
//! from the CSA's machine-readable data model — the same files the Test Harness reads. The two
//! were derived independently from the same source, so **where they disagree, one of them is
//! wrong**, and this is the test that says which.
//!
//! That is worth more than either alone. A hand-written descriptor can be internally
//! consistent, pass every test its own author wrote, and still claim a revision the
//! specification bumped or omit an attribute a feature bit makes mandatory. Nothing in the
//! device's own suite finds that; a certification lab does, months later.
//!
//! What is checked, per cluster:
//!
//! * the **cluster revision** — the single most commonly stale number in any implementation;
//! * every **mandatory element present** for the feature map the descriptor declares;
//! * every **disallowed element absent** — an attribute served without the feature that
//!   permits it;
//! * no **response command in the accepted list**, which would advertise that a client may
//!   invoke the server's own reply;
//! * no **feature bit the revision does not define**.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use matter_kit::clusters::generated;
use matter_kit::clusters::{
    access_control, administrator_commissioning, basic_information, binding, descriptor,
    general_commissioning, general_diagnostics, icd_management, label, network_commissioning,
    operational_credentials, software_diagnostics,
};
use matter_kit::dm::spec::{Defect, Element};
use matter_kit::dm::{ClusterDescriptor, Endpoint, device};

/// Reports every defect in a hand-written descriptor, or passes.
fn check(descriptor: &ClusterDescriptor<'_>) {
    let Some(spec) = generated::find(descriptor.id) else {
        panic!(
            "cluster {:#06X} has no generated definition — is it in the data model?",
            descriptor.id
        );
    };
    let mut defects = Vec::new();
    spec.validate(descriptor, |defect| defects.push(defect));
    assert!(
        defects.is_empty(),
        "{} ({:#06X}) disagrees with the specification: {}",
        spec.name,
        spec.id,
        defects
            .iter()
            .map(|defect| describe(spec, *defect))
            .collect::<Vec<_>>()
            .join("; ")
    );
}

fn describe(spec: &matter_kit::dm::spec::Cluster, defect: Defect) -> String {
    let named = |element: Element| -> String {
        match element {
            Element::Attribute(id) => spec.attributes.iter().find(|a| a.id == id).map_or_else(
                || format!("attribute {id:#06X}"),
                |a| format!("attribute {}", a.name),
            ),
            Element::Command(id) => spec.commands.iter().find(|c| c.id == id).map_or_else(
                || format!("command {id:#04X}"),
                |c| format!("command {}", c.name),
            ),
            Element::Event(id) => spec.events.iter().find(|e| e.id == id).map_or_else(
                || format!("event {id:#04X}"),
                |e| format!("event {}", e.name),
            ),
        }
    };
    match defect {
        Defect::Missing(element) => format!("{} is mandatory and absent", named(element)),
        Defect::Disallowed(element) => format!("{} is present and disallowed", named(element)),
        Defect::UnknownFeature(bit) => format!("feature bit {bit} is not defined"),
        Defect::WrongRevision { found, expected } => {
            format!("revision {found} but the specification says {expected}")
        }
        Defect::ResponseAccepted(id) => {
            format!("response command {id:#04X} is in the accepted list")
        }
        Defect::Provisional(element) => format!(
            "{} is provisional, and this build did not ask for provisional mechanisms",
            named(element)
        ),
        // `Defect` is `#[non_exhaustive]`: a kind added upstream should read as an unexplained
        // defect here rather than stop this file compiling.
        other => format!("{other:?}"),
    }
}

// --- Every hand-written cluster ------------------------------------------------------------

#[test]
fn the_descriptor_cluster_matches_the_specification() {
    check(&descriptor::cluster());
}

#[test]
fn basic_information_matches_the_specification() {
    // The one with the most attributes, and the one whose revision moves most often.
    const PRODUCT: basic_information::Product<'static> = basic_information::Product::new(
        "matter-kit",
        matter_kit::msg::VendorId(0xFFF1),
        "conformance",
        0x8000,
        "MK-CONFORMANCE-0001",
    );
    let attributes = basic_information::Attributes::new(&PRODUCT, false, false);
    check(&attributes.cluster());
}

#[test]
fn general_commissioning_matches_the_specification() {
    check(&general_commissioning::cluster());
    // §5.9's Network Recovery is a feature, and §7.3 makes two attributes mandatory exactly
    // when it is set — so the descriptor a recovery-capable node serves is a different list,
    // and it has to be checked as one. It is provisional (Core §2.13.6), so it exists only on a
    // build that asked for provisional mechanisms; on any other, furnishing it is itself the
    // defect `check` would report.
    #[cfg(feature = "provisional")]
    check(&general_commissioning::cluster_with_recovery());
}

#[test]
fn operational_credentials_matches_the_specification() {
    check(&operational_credentials::cluster());
}

#[test]
fn network_commissioning_matches_the_specification() {
    // Its element set depends heavily on the feature map: a Wi-Fi device and a Thread device
    // serve different attributes from the same cluster, and getting that wrong is exactly the
    // failure conformance encodes.
    check(&network_commissioning::wifi());
    check(&network_commissioning::thread());
    check(&network_commissioning::ethernet());
}

#[test]
fn administrator_commissioning_matches_the_specification() {
    check(&administrator_commissioning::cluster());
}

#[test]
fn access_control_matches_the_specification() {
    check(&access_control::cluster());
}

#[test]
fn binding_matches_the_specification() {
    check(&binding::cluster());
}

#[test]
fn the_label_clusters_match_the_specification() {
    check(&label::fixed_cluster());
    check(&label::user_cluster());
}

#[test]
fn icd_management_matches_the_specification() {
    use matter_kit::clusters::icd_management::Feature;
    use matter_kit::dm::spec::Optional;
    // Every combination a device can claim. A descriptor derived from the specification
    // cannot drift from it, which is the point — but the *sizing* can still be wrong, and
    // this is what finds a const parameter that is one short.
    for bits in 0..16u32 {
        let Some(features) = Feature::from_bits(bits) else {
            continue;
        };
        let Ok(built) = icd_management::conforming(features, &Optional::NONE) else {
            continue;
        };
        check(&built.descriptor());
    }
}

#[test]
fn the_diagnostics_clusters_match_the_specification() {
    use matter_kit::dm::spec::Optional;
    for features in [0, general_diagnostics::FEATURE_DATA_MODEL_TEST] {
        for optional in [&Optional::NONE, &general_diagnostics::ALL_OPTIONAL] {
            check(
                &general_diagnostics::conforming(features, optional)
                    .expect("sized")
                    .descriptor(),
            );
        }
    }
    for features in [0, software_diagnostics::FEATURE_WATERMARKS] {
        for optional in [&Optional::NONE, &software_diagnostics::ALL_OPTIONAL] {
            check(
                &software_diagnostics::conforming(features, optional)
                    .expect("sized")
                    .descriptor(),
            );
        }
    }
}

// --- The library itself ------------------------------------------------------------------

#[test]
fn the_generated_library_is_sorted_and_complete() {
    // 1.6 defines 128 cluster files; a few hold several ids. A count that dropped would mean
    // the parser silently skipped a file.
    assert!(
        generated::ALL.len() >= 120,
        "only {} clusters generated",
        generated::ALL.len()
    );
    let mut previous = 0u32;
    for cluster in generated::ALL {
        assert!(cluster.id > previous || previous == 0, "not sorted by id");
        previous = cluster.id;
        assert!(!cluster.name.is_empty());
        assert!(cluster.revision >= 1, "{} has revision 0", cluster.name);
        // Elements within a cluster are sorted too, which is what makes a diff of a
        // regenerated file readable.
        let mut last = None;
        for attribute in cluster.attributes {
            assert!(
                last.is_none_or(|previous| attribute.id > previous),
                "{}'s attributes are not sorted",
                cluster.name
            );
            last = Some(attribute.id);
        }
    }
    assert_eq!(generated::find(0x0006).expect("On/Off").name, "On/Off");
    assert!(generated::find(0xFFFF).is_none());
}

#[test]
fn on_off_reads_the_way_the_specification_prints_it() {
    // Application Cluster §1.5, transcribed by hand here and generated over there. A
    // disagreement means the generator mangled something, which no amount of internal
    // consistency in the generated output would reveal.
    let on_off = generated::find(0x0006).expect("On/Off");
    assert_eq!(on_off.revision, 6);
    assert_eq!(on_off.pics, "OO");
    assert_eq!(on_off.features.len(), 3);
    assert_eq!(on_off.feature("LT").expect("Lighting").bit, 0);
    assert_eq!(on_off.feature("DF").expect("DeadFront").bit, 1);
    assert_eq!(on_off.feature("OFFONLY").expect("OffOnly").bit, 2);

    let start_up = on_off
        .attributes
        .iter()
        .find(|a| a.id == 0x4003)
        .expect("StartUpOnOff");
    assert_eq!(start_up.name, "StartUpOnOff");
    assert_eq!(start_up.kind, "StartUpOnOffEnum");
    // `RW VM`, `X N` — nullable and non-volatile.
    assert_eq!(start_up.access.read, Some(matter_kit::dm::Privilege::View));
    assert_eq!(
        start_up.access.write,
        Some(matter_kit::dm::Privilege::Manage)
    );
    assert!(
        start_up
            .qualities
            .contains(matter_kit::dm::AttributeQualities::NULLABLE)
    );
    assert!(
        start_up
            .qualities
            .contains(matter_kit::dm::AttributeQualities::NON_VOLATILE)
    );

    // The `S` quality, which is what Scenes Management captures.
    let on_off_attribute = on_off
        .attributes
        .iter()
        .find(|a| a.id == 0x0000)
        .expect("OnOff");
    assert!(
        on_off_attribute
            .qualities
            .contains(matter_kit::dm::AttributeQualities::SCENE),
        "OnOff takes part in scenes"
    );
}

// --- Conformance is a statement about existence -------------------------------------------

/// Builds a minimal On/Off descriptor for a given feature map.
fn on_off_descriptor(
    feature_map: u32,
    attributes: &'static [matter_kit::dm::AttributeDescriptor],
    commands: &'static [matter_kit::dm::CommandDescriptor],
) -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: 0x0006,
        revision: 6,
        feature_map,
        attributes,
        accepted_commands: commands,
        generated_commands: &[],
        events: &[],
    }
}

const BASE_ATTRS: &[matter_kit::dm::AttributeDescriptor] =
    &[matter_kit::dm::AttributeDescriptor::read_only(0x0000)];
const LIGHTING_ATTRS: &[matter_kit::dm::AttributeDescriptor] = &[
    matter_kit::dm::AttributeDescriptor::read_only(0x0000),
    matter_kit::dm::AttributeDescriptor::read_only(0x4000),
    matter_kit::dm::AttributeDescriptor::read_write(0x4001),
    matter_kit::dm::AttributeDescriptor::read_write(0x4002),
    matter_kit::dm::AttributeDescriptor::read_write(0x4003),
];
const BASE_COMMANDS: &[matter_kit::dm::CommandDescriptor] = &[
    matter_kit::dm::CommandDescriptor::new(0x00),
    matter_kit::dm::CommandDescriptor::new(0x01),
    matter_kit::dm::CommandDescriptor::new(0x02),
];
const LIGHTING_COMMANDS: &[matter_kit::dm::CommandDescriptor] = &[
    matter_kit::dm::CommandDescriptor::new(0x00),
    matter_kit::dm::CommandDescriptor::new(0x01),
    matter_kit::dm::CommandDescriptor::new(0x02),
    matter_kit::dm::CommandDescriptor::new(0x40),
    matter_kit::dm::CommandDescriptor::new(0x41),
    matter_kit::dm::CommandDescriptor::new(0x42),
];

#[test]
fn an_attribute_a_feature_does_not_permit_is_a_defect_not_a_spare() {
    let on_off = generated::find(0x0006).expect("On/Off");

    // Without Lighting, the four `LT` attributes are *disallowed* — `[LT]` is a statement
    // about existence, not a hint that the attribute is optional.
    let plain = on_off_descriptor(0, BASE_ATTRS, BASE_COMMANDS);
    assert!(
        on_off.is_valid(&plain),
        "a plain On/Off server is conformant"
    );

    let over_furnished = on_off_descriptor(0, LIGHTING_ATTRS, BASE_COMMANDS);
    let mut defects = Vec::new();
    on_off.validate(&over_furnished, |defect| defects.push(defect));
    assert_eq!(
        defects.len(),
        4,
        "four Lighting attributes served without the feature: {defects:?}"
    );
    assert!(defects.contains(&Defect::Disallowed(Element::Attribute(0x4003))));

    // With Lighting, the same four become mandatory and the plain server is the defective one.
    let lighting = on_off_descriptor(
        matter_kit::clusters::generated::on_off::feature::LIGHTING,
        LIGHTING_ATTRS,
        LIGHTING_COMMANDS,
    );
    assert!(on_off.is_valid(&lighting));

    let under_furnished = on_off_descriptor(
        matter_kit::clusters::generated::on_off::feature::LIGHTING,
        BASE_ATTRS,
        BASE_COMMANDS,
    );
    let mut defects = Vec::new();
    on_off.validate(&under_furnished, |defect| defects.push(defect));
    assert!(
        defects.contains(&Defect::Missing(Element::Attribute(0x4003))),
        "StartUpOnOff is mandatory with Lighting: {defects:?}"
    );
}

#[test]
fn a_negated_feature_removes_a_command() {
    // On/Off's `On` and `Toggle` are mandatory *unless* `OffOnly` is set — the only clean
    // example in the library of a feature that takes elements away rather than adding them.
    let on_off = generated::find(0x0006).expect("On/Off");
    const OFF_ONLY_ATTRS: &[matter_kit::dm::AttributeDescriptor] =
        &[matter_kit::dm::AttributeDescriptor::read_only(0x0000)];
    const OFF_ONLY_COMMANDS: &[matter_kit::dm::CommandDescriptor] =
        &[matter_kit::dm::CommandDescriptor::new(0x00)];

    let off_only = on_off_descriptor(
        matter_kit::clusters::generated::on_off::feature::OFF_ONLY,
        OFF_ONLY_ATTRS,
        OFF_ONLY_COMMANDS,
    );
    assert!(
        on_off.is_valid(&off_only),
        "an OffOnly server serves Off and nothing else"
    );

    // Serving `On` anyway is a defect: a client that sees it in `AcceptedCommandList` will
    // send it, and the device has said it cannot turn on.
    let contradictory = on_off_descriptor(
        matter_kit::clusters::generated::on_off::feature::OFF_ONLY,
        OFF_ONLY_ATTRS,
        BASE_COMMANDS,
    );
    let mut defects = Vec::new();
    on_off.validate(&contradictory, |defect| defects.push(defect));
    assert!(defects.contains(&Defect::Disallowed(Element::Command(0x01))));
    assert!(defects.contains(&Defect::Disallowed(Element::Command(0x02))));
}

#[test]
fn a_stale_revision_is_found() {
    // The number most often left behind when a cluster gains an attribute, and the one a
    // commissioner uses to decide what it may ask for.
    let on_off = generated::find(0x0006).expect("On/Off");
    let mut stale = on_off_descriptor(0, BASE_ATTRS, BASE_COMMANDS);
    stale.revision = 4;
    let mut defects = Vec::new();
    on_off.validate(&stale, |defect| defects.push(defect));
    assert!(defects.contains(&Defect::WrongRevision {
        found: 4,
        expected: 6
    }));
}

#[test]
fn a_feature_bit_the_revision_does_not_define_is_found() {
    let on_off = generated::find(0x0006).expect("On/Off");
    let invented = on_off_descriptor(1 << 9, BASE_ATTRS, BASE_COMMANDS);
    let mut defects = Vec::new();
    on_off.validate(&invented, |defect| defects.push(defect));
    assert!(defects.contains(&Defect::UnknownFeature(9)));
}

// --- Device types --------------------------------------------------------------------------

#[test]
fn a_device_type_demands_the_clusters_its_library_entry_names() {
    // `DeviceTypeList` is a claim. A commissioner reading "On/Off Light" expects Identify,
    // Groups, On/Off and Scenes Management; a device that advertises the type without
    // furnishing it appears in an app and then does not work, which is a worse failure than
    // not appearing at all.
    let light = device::DeviceType {
        ..*generated::device_types::ALL
            .iter()
            .copied()
            .find(|d| d.name == "On/Off Light")
            .expect("the Device Library defines On/Off Light")
    };
    assert_eq!(light.id, 0x0100);
    assert_eq!(light.class, "simple");

    const BARE: &[matter_kit::dm::ClusterDescriptor<'static>] =
        &[matter_kit::dm::ClusterDescriptor {
            id: 0x0006,
            revision: 6,
            feature_map: 1,
            attributes: LIGHTING_ATTRS,
            accepted_commands: LIGHTING_COMMANDS,
            generated_commands: &[],
            events: &[],
        }];
    let endpoint = Endpoint::new(1, BARE);
    let mut defects = Vec::new();
    matter_kit::clusters::validate_endpoint(&endpoint, &light, |defect| defects.push(defect));
    assert!(
        defects.contains(&device::Defect::MissingCluster(0x0003)),
        "Identify is mandatory for an On/Off Light: {defects:?}"
    );
    assert!(
        !defects.contains(&device::Defect::MissingCluster(0x0406)),
        "Occupancy Sensing is a *client* cluster — a light binds to one, it does not serve one"
    );
}

#[test]
fn a_mandatory_client_cluster_is_demanded_of_the_client_list_not_the_server_list() {
    // An On/Off Light Switch requires On/Off on the *client* side — it is the thing that
    // sends `On`, not the thing that receives it. So the demand falls on §9.5.6.3's
    // `ClientList`, never on the clusters the endpoint serves: a validator that looked for an
    // On/Off *server* would make every switch author add one to a wall button.
    //
    // But it is a demand. On/Off is the only thing in the type that a switch is obliged to
    // consume, so a validator that skipped client entries could not tell a light from the
    // switch that controls it.
    let switch_type = generated::device_types::ALL
        .iter()
        .copied()
        .find(|d| d.name == "On/Off Light Switch")
        .expect("the Device Library defines On/Off Light Switch");
    assert!(
        switch_type
            .clusters
            .iter()
            .any(|c| c.id == 0x0006 && !c.server),
        "On/Off is a client cluster for a switch"
    );

    // An endpoint with only the clusters a switch actually *serves*, and no `ClientList`.
    const SWITCH: &[matter_kit::dm::ClusterDescriptor<'static>] = &[stub(0x0003, 5)];
    let endpoint = Endpoint::new(1, SWITCH);
    let mut defects = Vec::new();
    matter_kit::clusters::validate_endpoint(&endpoint, switch_type, |defect| defects.push(defect));
    assert!(
        !defects.contains(&device::Defect::MissingCluster(0x0006)),
        "a switch does not serve On/Off: {defects:?}"
    );
    assert!(
        defects.contains(&device::Defect::MissingClient(0x0006)),
        "...but it must bind to one: {defects:?}"
    );

    // Declaring the binding satisfies it. Identify is required on both sides for this type,
    // so the switch consumes that too.
    let declared = Endpoint::new(1, SWITCH).with_clients(&[0x0003, 0x0006]);
    let mut defects = Vec::new();
    matter_kit::clusters::validate_endpoint(&declared, switch_type, |defect| defects.push(defect));
    assert!(defects.is_empty(), "a furnished switch: {defects:?}");

    // An *optional* client entry is never demanded — Groups and Scenes Management are both
    // optional for a switch, and this one binds to neither.
    assert!(
        !defects.contains(&device::Defect::MissingClient(0x0004)),
        "an optional client cluster was demanded"
    );
}

#[test]
fn a_device_type_demands_a_feature_of_a_cluster_not_just_the_cluster() {
    // The part a cluster list alone cannot say: On/Off Light requires On/Off **with
    // Lighting**. A light that serves the cluster without the feature has no `StartUpOnOff`,
    // so it comes back on in whatever state it was in — the exact behaviour the device type
    // exists to rule out.
    let light = generated::device_types::ALL
        .iter()
        .copied()
        .find(|d| d.name == "On/Off Light")
        .expect("On/Off Light");

    const WITHOUT_LIGHTING: &[matter_kit::dm::ClusterDescriptor<'static>] = &[
        matter_kit::dm::ClusterDescriptor {
            id: 0x0003,
            revision: 5,
            feature_map: 0,
            attributes: &[],
            accepted_commands: &[],
            generated_commands: &[],
            events: &[],
        },
        matter_kit::dm::ClusterDescriptor {
            id: 0x0004,
            revision: 4,
            feature_map: 0,
            attributes: &[],
            accepted_commands: &[],
            generated_commands: &[],
            events: &[],
        },
        matter_kit::dm::ClusterDescriptor {
            id: 0x0006,
            revision: 6,
            feature_map: 0,
            attributes: BASE_ATTRS,
            accepted_commands: BASE_COMMANDS,
            generated_commands: &[],
            events: &[],
        },
        matter_kit::dm::ClusterDescriptor {
            id: 0x0062,
            revision: 1,
            feature_map: 0,
            attributes: &[],
            accepted_commands: &[],
            generated_commands: &[],
            events: &[],
        },
    ];
    let endpoint = Endpoint::new(1, WITHOUT_LIGHTING);
    let mut defects = Vec::new();
    matter_kit::clusters::validate_endpoint(&endpoint, light, |defect| defects.push(defect));
    assert!(
        defects.contains(&device::Defect::MissingFeature {
            cluster: 0x0006,
            code: "LT"
        }),
        "On/Off without Lighting is not an On/Off Light: {defects:?}"
    );
}

#[test]
fn a_furnished_endpoint_satisfies_the_device_type_it_claims() {
    // The positive case, so the validator is not only ever seen refusing things. An On/Off
    // Light needs four server clusters — On/Off with its Lighting feature — and two elements
    // its own clusters call optional: Identify's `TriggerEffect` and Scenes Management's
    // `CopyScene`, both of which §4.1 makes mandatory.
    //
    // `examples/light` claims this device type and furnishes exactly this set;
    // `tests/device_types.rs` runs the same check over the descriptors it actually builds.
    let light = generated::device_types::ALL
        .iter()
        .copied()
        .find(|d| d.name == "On/Off Light")
        .expect("On/Off Light");

    /// Identify's `TriggerEffect` (§1.2.6.2) and Scenes Management's `CopyScene` (§1.4.9.15)
    /// share command id `0x40`.
    const OPTIONAL_BUT_REQUIRED: &[matter_kit::dm::CommandDescriptor] =
        &[matter_kit::dm::CommandDescriptor::new(0x40)];
    const FURNISHED: &[matter_kit::dm::ClusterDescriptor<'static>] = &[
        matter_kit::dm::ClusterDescriptor {
            id: 0x0003,
            revision: 5,
            feature_map: 0,
            attributes: &[],
            accepted_commands: OPTIONAL_BUT_REQUIRED,
            generated_commands: &[],
            events: &[],
        },
        stub(0x0004, 4),
        matter_kit::dm::ClusterDescriptor {
            id: 0x0006,
            revision: 6,
            feature_map: 1,
            attributes: LIGHTING_ATTRS,
            accepted_commands: LIGHTING_COMMANDS,
            generated_commands: &[],
            events: &[],
        },
        matter_kit::dm::ClusterDescriptor {
            id: 0x0062,
            revision: 1,
            feature_map: 0,
            attributes: &[],
            accepted_commands: OPTIONAL_BUT_REQUIRED,
            generated_commands: &[],
            events: &[],
        },
    ];
    let endpoint = Endpoint::new(1, FURNISHED);
    let mut defects = Vec::new();
    matter_kit::clusters::validate_endpoint(&endpoint, light, |defect| defects.push(defect));
    assert!(defects.is_empty(), "a furnished light: {defects:?}");
    assert!(matter_kit::clusters::endpoint_satisfies(&endpoint, light));

    // ...and dropping either of the two optional-but-required commands is reported. A check
    // that compared only cluster ids would pass an endpoint whose app screen has a dead
    // button.
    const WITHOUT: &[matter_kit::dm::ClusterDescriptor<'static>] = &[
        stub(0x0003, 5),
        stub(0x0004, 4),
        matter_kit::dm::ClusterDescriptor {
            id: 0x0006,
            revision: 6,
            feature_map: 1,
            attributes: LIGHTING_ATTRS,
            accepted_commands: LIGHTING_COMMANDS,
            generated_commands: &[],
            events: &[],
        },
        stub(0x0062, 1),
    ];
    let bare = Endpoint::new(1, WITHOUT);
    let mut defects = Vec::new();
    matter_kit::clusters::validate_endpoint(&bare, light, |defect| defects.push(defect));
    assert!(
        defects.contains(&device::Defect::MissingElement {
            cluster: 0x0003,
            name: "TriggerEffect"
        }),
        "{defects:?}"
    );
    assert!(
        defects.contains(&device::Defect::MissingElement {
            cluster: 0x0062,
            name: "CopyScene"
        }),
        "{defects:?}"
    );
}

/// A cluster present on the endpoint, with no elements — enough for a device-type check,
/// which asks which clusters are there rather than what they hold.
const fn stub(id: u32, revision: u16) -> matter_kit::dm::ClusterDescriptor<'static> {
    matter_kit::dm::ClusterDescriptor {
        id,
        revision,
        feature_map: 0,
        attributes: &[],
        accepted_commands: &[],
        generated_commands: &[],
        events: &[],
    }
}

#[test]
fn the_device_library_is_complete() {
    assert!(
        generated::device_types::ALL.len() >= 85,
        "only {} device types generated",
        generated::device_types::ALL.len()
    );
    // The root node, which every node has on endpoint 0.
    let root = generated::device_types::find(0x0016).expect("Root Node");
    assert_eq!(root.name, "Root Node");
    assert_eq!(root.scope, "node");
    // It requires the clusters this crate spent M1 building. Descriptor (0x001D) is *not*
    // among them: §9.5 puts one on every endpoint, so no device type has to ask for it.
    for required in [0x001F, 0x0028, 0x0030, 0x0031, 0x003E] {
        assert!(
            root.clusters.iter().any(|c| c.id == required && c.server),
            "the Root Node requires {required:#06X}"
        );
    }
}
