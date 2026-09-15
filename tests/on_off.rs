//! On/Off's state machine (Application Cluster §1.5.7), driven through the interaction model.
//!
//! The first cluster in this crate where the specification defines *behaviour* — and most of
//! §1.5.7 is not about turning a light on. `OnWithTimedOff` is a three-state machine with two
//! counters, and its guard exists for a situation the specification describes in plain words:
//!
//! > when leaving a room, the lights are turned off but an occupancy sensor detects the
//! > leaving person and attempts to turn the lights back on
//!
//! A device that gets that wrong turns the light back on behind the person who just left, and
//! does it every single time. That is the rule this file exists for; the rest is the
//! bookkeeping that makes it work.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::clusters::generated;
use matter_kit::clusters::on_off::{
    self, EffectIdentifierEnum, OnOff, OnOffControlBitmap, OnOffHooks, StartUpOnOffEnum, TICK,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status,
};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

/// A light that records what it was told, so the test can see what the cluster decided.
#[derive(Debug, Default)]
struct Lamp {
    on: RefCell<bool>,
    transitions: RefCell<Vec<bool>>,
    effects: RefCell<Vec<(u8, u8)>>,
    stored: RefCell<usize>,
    recalled: RefCell<usize>,
    /// What `recall_global_scene` answers — a real Scenes Management cluster would decide it.
    scene_on: RefCell<bool>,
}

impl OnOffHooks for Lamp {
    fn set(&self, on: bool) {
        *self.on.borrow_mut() = on;
        self.transitions.borrow_mut().push(on);
    }

    fn off_with_effect(&self, effect: EffectIdentifierEnum, variant: u8) {
        self.effects.borrow_mut().push((effect.value(), variant));
        self.set(false);
    }

    fn recall_global_scene(&self) -> bool {
        *self.recalled.borrow_mut() += 1;
        *self.scene_on.borrow()
    }

    fn store_global_scene(&self) {
        *self.stored.borrow_mut() += 1;
    }
}

fn at(tenths: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_millis(tenths * 100))
}

const LIGHTING: u32 = on_off::feature::LIGHTING;

/// The cluster and the node that serves it, furnished from the specification's tables.
struct Device<'a> {
    node: Node<'a>,
    cluster: OnOff<'a, Lamp>,
}

fn device(lamp: &Lamp, feature_map: u32, start_up: Option<StartUpOnOffEnum>) -> Device<'_> {
    let conforming = Box::leak(Box::new(
        OnOff::<Lamp>::conforming(feature_map, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: OnOff::new(lamp, feature_map, start_up),
    }
}

/// Invokes a command through the interaction model, as a client would.
fn invoke(device: &Device<'_>, command: u32, fields: Option<&[u8]>, now: Instant) -> Status {
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(1, on_off::ID, command))
    };
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let ctx = InteractionContext::new().at(now);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], &ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    match responses.next().expect("one response").expect("decode") {
        InvokeResponse::Status(status) => status.status.status,
        InvokeResponse::Command(_) => panic!("On/Off has no response commands"),
    }
}

fn timed_off_fields(control: u8, on_time: u16, off_wait: u16) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(control)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(on_time)).unwrap();
    w.unsigned(Tag::Context(2), u64::from(off_wait)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn effect_fields(effect: u8, variant: u8) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(effect)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(variant)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_cluster_matches_the_specification_for_every_feature_combination() {
    // Derived descriptors cannot drift from the tables, but the *sizing* can be wrong — and a
    // const parameter one short is a runtime error a device would meet at start-up.
    let spec = generated::find(on_off::ID).expect("On/Off");
    for bits in [
        0,
        on_off::feature::LIGHTING,
        on_off::feature::DEAD_FRONT_BEHAVIOR,
        on_off::feature::LIGHTING | on_off::feature::DEAD_FRONT_BEHAVIOR,
        on_off::feature::OFF_ONLY,
    ] {
        let built = OnOff::<Lamp>::conforming(bits, &Optional::NONE).expect("sized");
        let descriptor = built.descriptor();
        let mut defects = Vec::new();
        spec.validate(&descriptor, |defect| defects.push(defect));
        assert!(defects.is_empty(), "features {bits:#x}: {defects:?}");
    }
}

#[test]
fn a_plain_relay_serves_one_attribute_and_three_commands() {
    // Without Lighting there is no `OnTime`, no `OffWaitTime` and no timed-off machine at all
    // — which is exactly what a relay wants, and what §1.5's conformance says it gets.
    let built = OnOff::<Lamp>::conforming(0, &Optional::NONE).expect("sized");
    let descriptor = built.descriptor();
    assert_eq!(descriptor.attributes.len(), 1);
    assert_eq!(descriptor.attributes[0].id, on_off::ON_OFF);
    assert_eq!(descriptor.accepted_commands.len(), 3);

    // With Lighting, four more attributes and three more commands appear, and not one line of
    // that is written down anywhere in this crate.
    let built = OnOff::<Lamp>::conforming(LIGHTING, &Optional::NONE).expect("sized");
    assert_eq!(built.descriptor().attributes.len(), 5);
    assert_eq!(built.descriptor().accepted_commands.len(), 6);
}

// --- The commands -----------------------------------------------------------------------------

#[test]
fn on_off_and_toggle_do_what_they_say() {
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);

    assert_eq!(invoke(&device, on_off::ON, None, at(0)), Status::Success);
    assert!(*lamp.on.borrow());
    assert_eq!(invoke(&device, on_off::OFF, None, at(1)), Status::Success);
    assert!(!*lamp.on.borrow());
    assert_eq!(
        invoke(&device, on_off::TOGGLE, None, at(2)),
        Status::Success
    );
    assert!(*lamp.on.borrow());
    assert_eq!(
        invoke(&device, on_off::TOGGLE, None, at(3)),
        Status::Success
    );
    assert!(!*lamp.on.borrow());

    // The hook is told once per *transition*, not once per command: §8.6 would not report a
    // change that did not happen, and a device that re-drove its relay on every `On` would
    // click audibly for no reason.
    assert_eq!(*lamp.transitions.borrow(), vec![true, false, true, false]);
    assert_eq!(invoke(&device, on_off::OFF, None, at(4)), Status::Success);
    assert_eq!(lamp.transitions.borrow().len(), 4, "already off");
}

#[test]
fn an_off_only_device_refuses_to_turn_on() {
    // §1.5.7.2.1: "If the OffOnly feature is supported, on receipt of the On command, an
    // UNSUPPORTED_COMMAND failure status response SHALL be sent." The descriptor leaves `On`
    // out as well, so a conformant client never sends it — this is what happens when one does.
    let lamp = Lamp::default();
    let device = device(&lamp, on_off::feature::OFF_ONLY, None);
    assert_eq!(
        invoke(&device, on_off::ON, None, at(0)),
        Status::UnsupportedCommand
    );
    assert_eq!(
        invoke(&device, on_off::TOGGLE, None, at(0)),
        Status::UnsupportedCommand
    );
    assert!(!*lamp.on.borrow());
    // `Off` still works, which is the whole point of the feature.
    assert_eq!(invoke(&device, on_off::OFF, None, at(0)), Status::Success);

    // Those refusals came from the *descriptor*: the derived element list leaves `On` and
    // `Toggle` out, so the server rejects the path before the handler sees it. The handler's
    // own check is the second line of defence, and it is the one that matters for a device
    // that built its descriptor by hand — so it is exercised directly rather than trusted.
    const BY_HAND: matter_kit::dm::ClusterDescriptor<'static> = matter_kit::dm::ClusterDescriptor {
        id: on_off::ID,
        revision: on_off::REVISION,
        feature_map: on_off::feature::OFF_ONLY,
        attributes: &[],
        accepted_commands: &[matter_kit::dm::CommandDescriptor::new(on_off::ON)],
        generated_commands: &[],
        events: &[],
    };
    let resolved = matter_kit::dm::ResolvedCommand {
        endpoint: 1,
        cluster: &BY_HAND,
        command: matter_kit::dm::CommandDescriptor::new(on_off::ON),
    };
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    let outcome = device.cluster.invoke(
        &resolved,
        None,
        &InteractionContext::new(),
        &mut w,
        Tag::Anonymous,
    );
    assert_eq!(
        outcome.map(|_| ()).map_err(|e| e.status),
        Err(Status::UnsupportedCommand)
    );
    assert!(!*lamp.on.borrow(), "and the light stayed off");
}

// --- The timed-off machine ---------------------------------------------------------------------

#[test]
fn on_with_timed_off_turns_the_light_off_when_the_time_runs_out() {
    // §1.5.7.6.4: "the server SHALL then update these attributes every 1/10 second until both
    // the OnTime and OffWaitTime attributes are equal to 0".
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);

    let fields = timed_off_fields(0, 30, 0);
    assert_eq!(
        invoke(&device, on_off::ON_WITH_TIMED_OFF, Some(&fields), at(0)),
        Status::Success
    );
    assert!(*lamp.on.borrow());
    assert_eq!(device.cluster.on_time(), 30);

    // Three seconds of tenths.
    for tick in 1..=29 {
        device.cluster.poll(at(tick));
        assert!(*lamp.on.borrow(), "still on at tick {tick}");
    }
    device.cluster.poll(at(30));
    assert!(!*lamp.on.borrow(), "off after three seconds");
    assert_eq!(device.cluster.on_time(), 0);
    // "the server SHALL set the OffWaitTime and OnOff attributes to 0 and FALSE".
    assert_eq!(device.cluster.off_wait_time(), 0);
    assert_eq!(device.cluster.wake_at(), None, "and the timer stops");
}

#[test]
fn the_off_wait_guard_stops_an_occupancy_sensor_turning_the_lights_back_on() {
    // The rule this cluster's complexity exists for (§1.5.6.5). Someone leaves the room and
    // switches the lights off; the occupancy sensor sees them go and sends `OnWithTimedOff`.
    // Without the guard the lights come back on behind them, every time.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);

    // On for 10 tenths, with a 50-tenth guard afterwards.
    let fields = timed_off_fields(0, 10, 50);
    invoke(&device, on_off::ON_WITH_TIMED_OFF, Some(&fields), at(0));
    assert!(*lamp.on.borrow());

    // The person switches the lights off by hand before the timer expires.
    invoke(&device, on_off::OFF, None, at(5));
    assert!(!*lamp.on.borrow());
    assert_eq!(device.cluster.on_time(), 0, "§1.5.7.1 clears OnTime");
    assert_eq!(device.cluster.off_wait_time(), 50, "the guard is still up");

    // The sensor tries to turn them back on. The command is *accepted* — it is not an error —
    // and the light stays off.
    let sensor = timed_off_fields(0, 100, 50);
    assert_eq!(
        invoke(&device, on_off::ON_WITH_TIMED_OFF, Some(&sensor), at(6)),
        Status::Success
    );
    assert!(!*lamp.on.borrow(), "the guard held");

    // Once the guard runs out, the same command works.
    for tick in 7..=60 {
        device.cluster.poll(at(tick));
    }
    assert_eq!(device.cluster.off_wait_time(), 0, "the guard expired");
    assert_eq!(
        invoke(&device, on_off::ON_WITH_TIMED_OFF, Some(&sensor), at(61)),
        Status::Success
    );
    assert!(*lamp.on.borrow(), "and now the lights come on");
}

#[test]
fn a_second_timed_off_extends_the_period_rather_than_shortening_it() {
    // §1.5.7.6.4: "set the OnTime attribute to the maximum of the OnTime attribute and the
    // value specified in the OnTime field". A motion sensor re-triggering while the light is
    // on must not be able to cut the remaining time short.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);

    invoke(
        &device,
        on_off::ON_WITH_TIMED_OFF,
        Some(&timed_off_fields(0, 100, 0)),
        at(0),
    );
    assert_eq!(device.cluster.on_time(), 100);

    // A shorter one leaves the longer period in place.
    invoke(
        &device,
        on_off::ON_WITH_TIMED_OFF,
        Some(&timed_off_fields(0, 20, 0)),
        at(1),
    );
    assert_eq!(device.cluster.on_time(), 100);

    // A longer one extends it.
    invoke(
        &device,
        on_off::ON_WITH_TIMED_OFF,
        Some(&timed_off_fields(0, 200, 0)),
        at(2),
    );
    assert_eq!(device.cluster.on_time(), 200);
}

#[test]
fn accept_only_when_on_discards_the_command_when_the_light_is_off() {
    // §1.5.7.6.1.1: a sensor that only wants to *extend* an already-lit room sets this bit,
    // and the command is discarded rather than refused — the sensor has done nothing wrong.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);
    let only_when_on = OnOffControlBitmap::ACCEPT_ONLY_WHEN_ON.bits();

    let fields = timed_off_fields(only_when_on, 50, 0);
    assert_eq!(
        invoke(&device, on_off::ON_WITH_TIMED_OFF, Some(&fields), at(0)),
        Status::Success,
        "discarded, not refused"
    );
    assert!(!*lamp.on.borrow());
    assert_eq!(device.cluster.on_time(), 0);

    // With the light already on, the same command extends it.
    invoke(&device, on_off::ON, None, at(1));
    invoke(&device, on_off::ON_WITH_TIMED_OFF, Some(&fields), at(2));
    assert_eq!(device.cluster.on_time(), 50);
}

#[test]
fn a_missed_tick_still_turns_the_light_off_at_the_right_time() {
    // A sleepy device, or one whose loop was busy, polls late. Counting *calls* would leave
    // the light on for as long as the device was distracted; counting elapsed time does not.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);
    invoke(
        &device,
        on_off::ON_WITH_TIMED_OFF,
        Some(&timed_off_fields(0, 30, 0)),
        at(0),
    );

    // One poll, three seconds later.
    device.cluster.poll(at(30));
    assert!(!*lamp.on.borrow());
    assert_eq!(device.cluster.on_time(), 0);
}

#[test]
fn an_indefinite_timer_never_counts_down() {
    // §1.5.7.6.4 exempts 0xFFFF: "If the values of the OnTime and OffWaitTime attributes are
    // both not equal to 0xFFFF". A light set that way stays on until something says otherwise.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);
    invoke(
        &device,
        on_off::ON_WITH_TIMED_OFF,
        Some(&timed_off_fields(0, 100, 0)),
        at(0),
    );

    // A client writes `OnTime` to 0xFFFF — §1.5.6.4 says it "can be written at any time".
    let mut buf = [0u8; 32];
    // The value reaches a handler as the encoded element carrying §10.6.4.3's context tag 2.
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.unsigned(Tag::Context(2), u64::from(on_off::INDEFINITE))
        .unwrap();
    let data = w.finish().unwrap().to_vec();
    let resolved = device
        .node
        .resolve(1, on_off::ID, on_off::ON_TIME)
        .expect("OnTime");
    device
        .cluster
        .write(
            &resolved,
            &data,
            matter_kit::im::WriteOp::Replace,
            &InteractionContext::new(),
        )
        .expect("write");

    for tick in 1..=200 {
        device.cluster.poll(at(tick));
    }
    assert!(*lamp.on.borrow(), "an indefinite timer does not expire");
    assert_eq!(device.cluster.on_time(), on_off::INDEFINITE);
}

#[test]
fn a_command_may_not_ask_for_the_indefinite_value() {
    // The fields are "max 0xFFFE": 0xFFFF is the *attribute's* "stay like this", and a command
    // that could request it would be a client pinning a light on with no way back.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);
    assert_eq!(
        invoke(
            &device,
            on_off::ON_WITH_TIMED_OFF,
            Some(&timed_off_fields(0, on_off::INDEFINITE, 0)),
            at(0)
        ),
        Status::ConstraintError
    );
    // And a reserved bit in `OnOffControl` — "0 to 1" — is refused rather than ignored.
    assert_eq!(
        invoke(
            &device,
            on_off::ON_WITH_TIMED_OFF,
            Some(&timed_off_fields(0x02, 10, 0)),
            at(0)
        ),
        Status::ConstraintError
    );
}

// --- The global scene ---------------------------------------------------------------------------

#[test]
fn off_with_effect_stores_the_scene_once_and_recall_brings_it_back() {
    // §1.5.6.3's whole reason: "to prevent a second Off command storing the all-devices-off
    // situation as a global scene, and to prevent a second On command destroying the current
    // settings by going back to the global scene."
    let lamp = Lamp::default();
    *lamp.scene_on.borrow_mut() = true;
    let device = device(&lamp, LIGHTING, None);

    invoke(&device, on_off::ON, None, at(0));
    assert!(device.cluster.global_scene_control());

    // The first `OffWithEffect` stores the scene and clears the flag.
    let fields = effect_fields(EffectIdentifierEnum::DelayedAllOff.value(), 0);
    assert_eq!(
        invoke(&device, on_off::OFF_WITH_EFFECT, Some(&fields), at(1)),
        Status::Success
    );
    assert!(!*lamp.on.borrow());
    assert!(!device.cluster.global_scene_control());
    assert_eq!(*lamp.stored.borrow(), 1);
    assert_eq!(*lamp.effects.borrow(), vec![(0, 0)]);

    // A second one stores nothing — the flag is already false, and storing "everything off"
    // as the scene is what §1.5.6.3 exists to prevent.
    invoke(&device, on_off::OFF_WITH_EFFECT, Some(&fields), at(2));
    assert_eq!(*lamp.stored.borrow(), 1, "stored once, not twice");

    // `OnWithRecallGlobalScene` brings the scene back and sets the flag again.
    assert_eq!(
        invoke(&device, on_off::ON_WITH_RECALL_GLOBAL_SCENE, None, at(3)),
        Status::Success
    );
    assert!(*lamp.on.borrow());
    assert!(device.cluster.global_scene_control());

    // A second recall is *discarded*: §1.5.7.5 says so outright, because the flag being TRUE
    // means nothing stored a scene since the last recall — so the Scenes Management cluster is
    // never even asked. Counting transitions would not see this, since the light is already
    // on either way; counting the calls does.
    assert_eq!(*lamp.recalled.borrow(), 1);
    invoke(&device, on_off::ON_WITH_RECALL_GLOBAL_SCENE, None, at(4));
    assert_eq!(*lamp.recalled.borrow(), 1, "the second recall never asked");
}

#[test]
fn a_reserved_effect_identifier_is_refused() {
    // §1.5.7.4.1: "This field SHALL contain one of the non-reserved values listed in
    // EffectIdentifierEnum." Inventing a fade for an unknown value would make a device's
    // behaviour depend on what a future revision assigns.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);
    invoke(&device, on_off::ON, None, at(0));
    assert_eq!(
        invoke(
            &device,
            on_off::OFF_WITH_EFFECT,
            Some(&effect_fields(0x7F, 0)),
            at(1)
        ),
        Status::ConstraintError
    );
    assert!(*lamp.on.borrow(), "and the light did not change");

    // The *variant* is not checked: "If the server does not support the given variant, it
    // SHALL use the default variant", so an unknown one is the device's to shrug at.
    assert_eq!(
        invoke(
            &device,
            on_off::OFF_WITH_EFFECT,
            Some(&effect_fields(
                EffectIdentifierEnum::DyingLight.value(),
                0xEE
            )),
            at(2)
        ),
        Status::Success
    );
}

// --- Start-up ------------------------------------------------------------------------------------

#[test]
fn start_up_on_off_decides_what_the_light_does_when_power_returns() {
    // §1.5.6.6. The attribute a user sets so a lamp on a wall switch behaves the way they
    // expect, and the one an installer complains about when it is wrong.
    for (start_up, previous, expected) in [
        (None, true, true),
        (None, false, false),
        (Some(StartUpOnOffEnum::Off), true, false),
        (Some(StartUpOnOffEnum::On), false, true),
        (Some(StartUpOnOffEnum::Toggle), true, false),
        (Some(StartUpOnOffEnum::Toggle), false, true),
    ] {
        let lamp = Lamp::default();
        let device = device(&lamp, LIGHTING, start_up);
        device.cluster.start(previous);
        assert_eq!(*lamp.on.borrow(), expected, "{start_up:?} after {previous}");
    }
}

#[test]
fn start_up_on_off_reads_back_as_null_when_it_means_the_previous_value() {
    // §1.5.6.6: "If the value is null, the OnOff attribute is set to its previous value." Null
    // is a real answer here, not an absent one — a client reading zero would be told the lamp
    // comes back off.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);
    let resolved = device
        .node
        .resolve(1, on_off::ID, on_off::START_UP_ON_OFF)
        .expect("StartUpOnOff");
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new(&mut buf);
    device
        .cluster
        .read(
            &resolved,
            &InteractionContext::new(),
            &mut w,
            Tag::Anonymous,
        )
        .expect("read");
    let bytes = w.finish().expect("finish");
    let value = TlvReader::new(bytes).next_element().unwrap().unwrap();
    assert!(value.value.is_null());
}

#[test]
fn a_light_with_no_timer_needs_no_clock() {
    // What an intermittently connected device cares about: a lamp that is simply on, or
    // simply off, must not ask to be woken.
    let lamp = Lamp::default();
    let device = device(&lamp, LIGHTING, None);
    invoke(&device, on_off::ON, None, at(0));
    assert_eq!(device.cluster.wake_at(), None);
    invoke(&device, on_off::OFF, None, at(1));
    assert_eq!(device.cluster.wake_at(), None);

    // A timed one does, and says when.
    invoke(
        &device,
        on_off::ON_WITH_TIMED_OFF,
        Some(&timed_off_fields(0, 10, 0)),
        at(2),
    );
    assert_eq!(device.cluster.wake_at(), Some(at(2).saturating_add(TICK)));
}
