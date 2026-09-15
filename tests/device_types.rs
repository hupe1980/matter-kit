//! Device types (Device Library §4) checked against what an endpoint actually serves.
//!
//! `DeviceTypeList` is a *promise*. A commissioner reads "On/Off Light" and lays out an app
//! screen with a power toggle, a name, a room and a scene button; if the node has On/Off and
//! nothing else, the screen appears and half of it does nothing. That is a worse failure than
//! not appearing at all, and it is invisible to every test that only exercises the clusters
//! the device does have.
//!
//! So the check runs here rather than on the device: an endpoint's furnishing is `const`, and
//! resolving the feature codes a device type names needs the whole generated cluster
//! library — about 131 KB of read-only data a device linking four clusters should never pay
//! for. Once this passes, running the same check at start-up proves nothing new.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use matter_kit::clusters::generated::device_types::{
    DIMMABLE_LIGHT, ON_OFF_LIGHT, ON_OFF_LIGHT_SWITCH, ROOT_NODE,
};
use matter_kit::clusters::groups::{self, Groups, NeverIdentifying};
use matter_kit::clusters::identify::Identify;
use matter_kit::clusters::level_control::{self, LevelControl, LevelControlHooks, NoOnOff};
use matter_kit::clusters::on_off::{self, EffectIdentifierEnum, OnOff, OnOffHooks};
use matter_kit::clusters::scenes::{self, ExtensionFieldSetStruct, SceneHooks, SceneTable, Scenes};
use matter_kit::clusters::{descriptor, validate_endpoint};
use matter_kit::dm::device::DeviceType as Spec;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{DeviceType, Endpoint};
use matter_kit::tlv::{TlvList, TlvWriter};

/// A lamp that implements every hook the three clusters need, and does nothing with any of
/// them — what is under test is the *furnishing*, not the behaviour.
#[derive(Debug, Default)]
struct Lamp;

impl OnOffHooks for Lamp {
    fn set(&self, _on: bool) {}
    fn off_with_effect(&self, _effect: EffectIdentifierEnum, _variant: u8) {}
}

impl matter_kit::clusters::identify::IdentifyHooks for Lamp {
    fn identifying(&self, _on: bool) {}
}

impl LevelControlHooks for Lamp {
    fn level(&self, _level: Option<u8>) {}
}

impl SceneHooks for Lamp {
    fn capture(&self, _w: &mut TlvWriter<'_>) -> matter_kit::error::Result<()> {
        Ok(())
    }
    fn apply<'a>(&self, _sets: TlvList<'a, ExtensionFieldSetStruct<'a>>, _transition: u32) {}
}

type Table = SceneTable<16, 128, 5>;
type Lamps<'a> = Scenes<'a, Lamp, Groups<'a, 16, NeverIdentifying, Table>, 16, 128, 5>;

fn defects(endpoint: &Endpoint<'_>, device_type: &Spec) -> Vec<String> {
    let mut found = Vec::new();
    validate_endpoint(endpoint, device_type, |defect| {
        found.push(format!("{defect:?}"));
    });
    found
}

/// The cluster list `examples/light.rs` builds for endpoint 1, assembled the same way.
///
/// Written out rather than imported, because an example is a binary: there is no way to reach
/// into one. Keeping the two in step is what this test is for — if the example drops a
/// cluster, this test still passes and the example stops building the list it documents, so
/// both are checked by `cargo clippy --all-targets`.
#[test]
fn the_light_example_furnishes_the_on_off_light_it_claims() {
    let identify = Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT).unwrap();
    let group = Groups::<16>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE).unwrap();
    let lamp = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE).unwrap();
    let scene = Lamps::conforming(scenes::feature::SCENE_NAMES, &Lamps::WITH_COPY_SCENE).unwrap();
    let clusters = [
        identify.descriptor(), // 0x0003
        group.descriptor(),    // 0x0004
        lamp.descriptor(),     // 0x0006
        descriptor::cluster(), // 0x001D
        scene.descriptor(),    // 0x0062
    ];
    let claimed = [DeviceType::new(ON_OFF_LIGHT.id, ON_OFF_LIGHT.revision)];
    let endpoint = Endpoint::new(1, &clusters).with_device_types(&claimed);
    assert_eq!(defects(&endpoint, &ON_OFF_LIGHT), Vec::<String>::new());
}

#[test]
fn dropping_any_one_cluster_is_reported() {
    // The check earns its keep only if it fails when it should. Each of the four is mandatory
    // for the type, so removing any one has to be visible.
    let identify = Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT).unwrap();
    let group = Groups::<16>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE).unwrap();
    let lamp = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE).unwrap();
    let scene = Lamps::conforming(scenes::feature::SCENE_NAMES, &Lamps::WITH_COPY_SCENE).unwrap();
    let all = [
        identify.descriptor(),
        group.descriptor(),
        lamp.descriptor(),
        descriptor::cluster(),
        scene.descriptor(),
    ];
    for (index, id) in [(0usize, 0x0003u32), (1, 0x0004), (2, 0x0006), (4, 0x0062)] {
        let mut kept = Vec::new();
        for (i, cluster) in all.iter().enumerate() {
            if i != index {
                kept.push(*cluster);
            }
        }
        let endpoint = Endpoint::new(1, &kept);
        let reported = defects(&endpoint, &ON_OFF_LIGHT);
        assert!(
            reported.iter().any(|d| d.contains(&format!("{id}"))),
            "dropping {id:#06x} went unreported: {reported:?}"
        );
    }
}

#[test]
fn an_optional_element_a_device_type_makes_mandatory_is_demanded() {
    // §4.1's On/Off Light lists Identify's `TriggerEffect` and Scenes Management's `CopyScene`
    // as mandatory even though both clusters call them optional. A device type may tighten
    // its clusters' conformance, and a check that only looked at cluster ids would miss it —
    // the app's scene button is exactly `CopyScene`.
    let identify = Identify::<Lamp>::conforming(&Optional::NONE).unwrap();
    let group = Groups::<16>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE).unwrap();
    let lamp = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE).unwrap();
    let scene = Lamps::conforming(scenes::feature::SCENE_NAMES, &Optional::NONE).unwrap();
    let clusters = [
        identify.descriptor(),
        group.descriptor(),
        lamp.descriptor(),
        descriptor::cluster(),
        scene.descriptor(),
    ];
    let endpoint = Endpoint::new(1, &clusters);
    let reported = defects(&endpoint, &ON_OFF_LIGHT);
    assert!(!reported.is_empty(), "the missing commands went unreported");
}

#[test]
fn on_off_without_its_lighting_feature_is_not_an_on_off_light() {
    // §4.1 makes the LT feature mandatory: an On/Off Light without it has no `StartUpOnOff`,
    // so it cannot be told what to do after a power cut — which is most of what makes a bulb
    // a light rather than a relay.
    let identify = Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT).unwrap();
    let group = Groups::<16>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE).unwrap();
    let lamp = OnOff::<Lamp>::conforming(0, &Optional::NONE).unwrap();
    let scene = Lamps::conforming(scenes::feature::SCENE_NAMES, &Lamps::WITH_COPY_SCENE).unwrap();
    let clusters = [
        identify.descriptor(),
        group.descriptor(),
        lamp.descriptor(),
        descriptor::cluster(),
        scene.descriptor(),
    ];
    let endpoint = Endpoint::new(1, &clusters);
    let reported = defects(&endpoint, &ON_OFF_LIGHT);
    assert!(
        reported.iter().any(|d| d.contains("Feature")),
        "the missing Lighting feature went unreported: {reported:?}"
    );
}

#[test]
fn a_light_is_not_a_light_switch() {
    // §4.1's On/Off Light and §6.1's On/Off Light Switch hold the *same* cluster, On/Off, on
    // opposite sides: the light serves it, the switch consumes it. An endpoint furnished as
    // one is not the other, and a check that ignored direction would call them
    // interchangeable.
    let identify = Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT).unwrap();
    let group = Groups::<16>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE).unwrap();
    let lamp = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE).unwrap();
    let scene = Lamps::conforming(scenes::feature::SCENE_NAMES, &Lamps::WITH_COPY_SCENE).unwrap();
    let clusters = [
        identify.descriptor(),
        group.descriptor(),
        lamp.descriptor(),
        descriptor::cluster(),
        scene.descriptor(),
    ];
    let endpoint = Endpoint::new(1, &clusters);
    assert!(defects(&endpoint, &ON_OFF_LIGHT).is_empty());
    assert!(
        !defects(&endpoint, &ON_OFF_LIGHT_SWITCH).is_empty(),
        "a light passed as a light switch"
    );
}

#[test]
fn the_root_node_is_checked_the_same_way() {
    // §9.5 puts Descriptor on every endpoint, and the Root Node (§2.1) adds the clusters a
    // commissioner needs before it knows what the node is.
    let clusters = [descriptor::cluster()];
    let endpoint = Endpoint::new(0, &clusters);
    assert!(
        !defects(&endpoint, &ROOT_NODE).is_empty(),
        "a bare endpoint passed as a Root Node"
    );
}

#[test]
fn a_dimmable_light_is_an_on_off_light_plus_level_control() {
    // §4.2's Dimmable Light adds one cluster to §4.1's, and demands three things of it that a
    // cluster list cannot express: the Lighting and On/Off *features*, and `MinLevel` and
    // `MaxLevel`, which Level Control itself calls optional.
    //
    // The features are not decoration. Without Lighting there is no `StartUpCurrentLevel`, so
    // the lamp comes back at whatever brightness it happened to be; without On/Off the 'with
    // On/Off' commands have nothing to turn on, and a dimmer with no separate switch cannot be
    // turned on at all.
    let identify = Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT).unwrap();
    let group = Groups::<16>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE).unwrap();
    let lamp = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE).unwrap();
    let scene = Lamps::conforming(scenes::feature::SCENE_NAMES, &Lamps::WITH_COPY_SCENE).unwrap();

    let dimming = level_control::feature::LIGHTING | level_control::feature::ON_OFF;
    let full = LevelControl::<Lamp, NoOnOff>::conforming(
        dimming,
        &LevelControl::<Lamp, NoOnOff>::WITH_RANGE,
    )
    .unwrap();
    let clusters = [
        identify.descriptor(), // 0x0003
        group.descriptor(),    // 0x0004
        lamp.descriptor(),     // 0x0006
        full.descriptor(),     // 0x0008
        descriptor::cluster(), // 0x001D
        scene.descriptor(),    // 0x0062
    ];
    let endpoint = Endpoint::new(1, &clusters);
    assert_eq!(defects(&endpoint, &DIMMABLE_LIGHT), Vec::<String>::new());

    // Without MinLevel and MaxLevel, the same endpoint is not a Dimmable Light — a controller
    // that could not read the range would have no idea what "50" means on this lamp.
    let bare = LevelControl::<Lamp, NoOnOff>::conforming(dimming, &Optional::NONE).unwrap();
    let clusters = [
        identify.descriptor(),
        group.descriptor(),
        lamp.descriptor(),
        bare.descriptor(),
        descriptor::cluster(),
        scene.descriptor(),
    ];
    let endpoint = Endpoint::new(1, &clusters);
    let reported = defects(&endpoint, &DIMMABLE_LIGHT);
    assert!(
        reported.iter().any(|d| d.contains("MinLevel")),
        "{reported:?}"
    );
    assert!(
        reported.iter().any(|d| d.contains("MaxLevel")),
        "{reported:?}"
    );

    // ...and without the two features it is not one either.
    let featureless =
        LevelControl::<Lamp, NoOnOff>::conforming(0, &LevelControl::<Lamp, NoOnOff>::WITH_RANGE)
            .unwrap();
    let clusters = [
        identify.descriptor(),
        group.descriptor(),
        lamp.descriptor(),
        featureless.descriptor(),
        descriptor::cluster(),
        scene.descriptor(),
    ];
    let endpoint = Endpoint::new(1, &clusters);
    let reported = defects(&endpoint, &DIMMABLE_LIGHT);
    assert!(
        reported.iter().any(|d| d.contains("\"LT\"")),
        "{reported:?}"
    );
    assert!(
        reported.iter().any(|d| d.contains("\"OO\"")),
        "{reported:?}"
    );

    // §4.1 lists Level Control as *optional* for an On/Off Light — but with both features
    // mandatory. So an endpoint that adds the cluster without them is not an On/Off Light
    // either: a device type's demands on a cluster apply the moment the cluster is there,
    // which is the only reading under which "optional" means anything at all.
    let reported = defects(&endpoint, &ON_OFF_LIGHT);
    assert!(
        reported.iter().any(|d| d.contains("\"LT\"")),
        "an optional cluster's mandatory features went undemanded: {reported:?}"
    );

    // With the features, the same endpoint is both: a Dimmable Light is a superset, and the
    // extra cluster is not a defect against the narrower type.
    let clusters = [
        identify.descriptor(),
        group.descriptor(),
        lamp.descriptor(),
        full.descriptor(),
        descriptor::cluster(),
        scene.descriptor(),
    ];
    let both = Endpoint::new(1, &clusters);
    assert!(defects(&both, &ON_OFF_LIGHT).is_empty());
    assert!(defects(&both, &DIMMABLE_LIGHT).is_empty());
}
