//! Identify (Application Cluster §1.2), driven through the interaction model.
//!
//! The cluster a person uses to answer "which one of these is it?" — and the reason
//! `AddGroupIfIdentifying` can work at all. Almost all of it is one countdown, and the two
//! things worth testing about a countdown are that it reaches zero exactly once and that it
//! reaches zero at the right moment even when nobody was watching.

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
use matter_kit::clusters::identify::{
    self, EffectIdentifierEnum, EffectVariantEnum, Identify, IdentifyHooks, IdentifyTypeEnum, TICK,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status, WriteOp,
};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

/// A light that records every transition and effect it was told about.
#[derive(Debug, Default)]
struct Lamp {
    transitions: RefCell<Vec<bool>>,
    effects: RefCell<Vec<(u8, u8)>>,
}

impl IdentifyHooks for Lamp {
    fn identifying(&self, on: bool) {
        self.transitions.borrow_mut().push(on);
    }

    fn trigger_effect(&self, effect: EffectIdentifierEnum, variant: EffectVariantEnum) {
        self.effects
            .borrow_mut()
            .push((effect.value(), variant.value()));
    }
}

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

struct Device<'a> {
    node: Node<'a>,
    cluster: Identify<'a, Lamp>,
}

fn device<'a>(lamp: &'a Lamp, optional: &Optional<'_>) -> Device<'a> {
    let conforming = Box::leak(Box::new(
        Identify::<Lamp>::conforming(optional).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: Identify::new(lamp, IdentifyTypeEnum::LightOutput),
    }
}

fn invoke(device: &Device<'_>, command: u32, fields: &[u8], now: Instant) -> Status {
    let data = CommandData {
        fields: Some(fields),
        ..CommandData::new(CommandPath::command(1, identify::ID, command))
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
        InvokeResponse::Command(_) => panic!("Identify defines no response commands"),
    }
}

fn one_field(field: u8, value: u64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(field), value).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn two_fields(a: u64, b: u64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), a).unwrap();
    w.unsigned(Tag::Context(1), b).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// Reads an attribute straight from the handler, as the server would.
fn read(device: &Device<'_>, attribute: u32) -> u64 {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    let resolved = device
        .node
        .resolve(1, identify::ID, attribute)
        .expect("attribute");
    device
        .cluster
        .read(
            &resolved,
            &InteractionContext::new(),
            &mut w,
            Tag::Anonymous,
        )
        .expect("read");
    let bytes = w.finish().unwrap();
    let mut reader = TlvReader::new(bytes);
    reader
        .next_element()
        .unwrap()
        .unwrap()
        .unsigned()
        .expect("unsigned")
}

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_cluster_matches_the_specification() {
    let spec = generated::find(identify::ID).expect("Identify");
    for optional in [Optional::NONE, Identify::<Lamp>::WITH_TRIGGER_EFFECT] {
        let built = Identify::<Lamp>::conforming(&optional).expect("sized");
        let descriptor = built.descriptor();
        let mut defects = Vec::new();
        spec.validate(&descriptor, |defect| defects.push(defect));
        assert!(defects.is_empty(), "{defects:?}");
    }
}

#[test]
fn trigger_effect_is_optional_and_absent_by_default() {
    // §1.2.6's conformance makes `TriggerEffect` optional. A device that advertised it and
    // then did nothing would be lying in its `AcceptedCommandList`.
    let plain = Identify::<Lamp>::conforming(&Optional::NONE).expect("sized");
    assert_eq!(plain.descriptor().accepted_commands.len(), 1);
    let with = Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT).expect("sized");
    assert_eq!(with.descriptor().accepted_commands.len(), 2);
}

// --- The countdown ---------------------------------------------------------------------------

#[test]
fn identify_counts_down_one_second_at_a_time() {
    let lamp = Lamp::default();
    let device = device(&lamp, &Optional::NONE);
    assert_eq!(
        invoke(&device, identify::IDENTIFY, &one_field(0, 3), at(0)),
        Status::Success
    );
    assert_eq!(*lamp.transitions.borrow(), vec![true]);
    assert_eq!(read(&device, identify::IDENTIFY_TIME), 3);

    for (elapsed, left) in [(1, 2), (2, 1)] {
        device.cluster.poll(at(elapsed));
        assert_eq!(read(&device, identify::IDENTIFY_TIME), left);
        // Still identifying, so still exactly one transition.
        assert_eq!(lamp.transitions.borrow().len(), 1);
    }

    device.cluster.poll(at(3));
    assert_eq!(read(&device, identify::IDENTIFY_TIME), 0);
    assert!(!device.cluster.is_identifying());
    assert_eq!(*lamp.transitions.borrow(), vec![true, false]);

    // Polling past the end changes nothing: the hook fires on the transition, not the tick.
    device.cluster.poll(at(9));
    assert_eq!(*lamp.transitions.borrow(), vec![true, false]);
}

#[test]
fn a_late_poll_catches_up_rather_than_losing_time() {
    // A sleepy device polls when it wakes, not every second. Counting *calls* rather than
    // elapsed time would leave it identifying long after it said it would stop — which for a
    // battery device means a light flashing for minutes because the radio was quiet.
    let lamp = Lamp::default();
    let device = device(&lamp, &Optional::NONE);
    device.cluster.set_time(30, at(0));
    device.cluster.poll(at(30));
    assert_eq!(device.cluster.remaining(), 0);
    assert_eq!(*lamp.transitions.borrow(), vec![true, false]);
}

#[test]
fn wake_at_is_the_next_tick_and_nothing_when_idle() {
    let lamp = Lamp::default();
    let device = device(&lamp, &Optional::NONE);
    assert_eq!(device.cluster.wake_at(), None);
    device.cluster.set_time(2, at(10));
    assert_eq!(device.cluster.wake_at(), Some(at(10).saturating_add(TICK)));
    device.cluster.poll(at(12));
    assert_eq!(device.cluster.wake_at(), None);
}

#[test]
fn identify_zero_stops_immediately() {
    // §1.2.6.1: the command sets `IdentifyTime`, and zero is how a commissioner says "stop" —
    // the same path a write takes, which is why there is only one place that decides.
    let lamp = Lamp::default();
    let device = device(&lamp, &Optional::NONE);
    device.cluster.set_time(60, at(0));
    assert_eq!(
        invoke(&device, identify::IDENTIFY, &one_field(0, 0), at(1)),
        Status::Success
    );
    assert!(!device.cluster.is_identifying());
    assert_eq!(*lamp.transitions.borrow(), vec![true, false]);
    assert_eq!(device.cluster.wake_at(), None);
}

#[test]
fn restarting_while_already_identifying_does_not_re_announce() {
    // The hook is a transition, not a heartbeat. §1.2.5.1 asks for a half-second blink; a
    // device re-armed every second would blink in lockstep with the tick instead.
    let lamp = Lamp::default();
    let device = device(&lamp, &Optional::NONE);
    device.cluster.set_time(5, at(0));
    device.cluster.set_time(10, at(1));
    assert_eq!(*lamp.transitions.borrow(), vec![true]);
    assert_eq!(device.cluster.remaining(), 10);
    // ...and the new time is measured from the restart, not from the original start.
    assert_eq!(device.cluster.wake_at(), Some(at(2)));
}

// --- Writes ----------------------------------------------------------------------------------

#[test]
fn writing_identify_time_starts_the_same_countdown_the_command_does() {
    let lamp = Lamp::default();
    let device = device(&lamp, &Optional::NONE);
    let mut buf = [0u8; 32];
    // The value reaches a handler as the encoded element carrying §10.6.4.3's context tag 2.
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.unsigned(Tag::Context(2), 4).unwrap();
    let data = w.finish().unwrap().to_vec();
    let resolved = device
        .node
        .resolve(1, identify::ID, identify::IDENTIFY_TIME)
        .expect("IdentifyTime");
    device
        .cluster
        .write(
            &resolved,
            &data,
            WriteOp::Replace,
            &InteractionContext::new().at(at(0)),
        )
        .expect("write");
    assert_eq!(device.cluster.remaining(), 4);
    assert_eq!(*lamp.transitions.borrow(), vec![true]);
}

#[test]
fn identify_type_is_read_only() {
    // §1.2.5.2 makes it a fixed property of the hardware. A client that could write it could
    // tell a commissioner to look for a flashing light on a device that only beeps.
    let lamp = Lamp::default();
    let device = device(&lamp, &Optional::NONE);
    assert_eq!(
        read(&device, identify::IDENTIFY_TYPE),
        u64::from(IdentifyTypeEnum::LightOutput.value())
    );
    let resolved = device
        .node
        .resolve(1, identify::ID, identify::IDENTIFY_TYPE)
        .expect("IdentifyType");
    assert_eq!(
        device
            .cluster
            .write(&resolved, &[], WriteOp::Replace, &InteractionContext::new()),
        Err(Status::UnsupportedWrite)
    );
}

// --- TriggerEffect ---------------------------------------------------------------------------

#[test]
fn trigger_effect_reaches_the_device_without_touching_the_countdown() {
    // §1.2.6.2: "it is not the same as and does not replace the identify mechanism used
    // during commissioning" — a green blink does not mean the endpoint is identifying.
    let lamp = Lamp::default();
    let device = device(&lamp, &Identify::<Lamp>::WITH_TRIGGER_EFFECT);
    assert_eq!(
        invoke(
            &device,
            identify::TRIGGER_EFFECT,
            &two_fields(
                u64::from(EffectIdentifierEnum::Okay.value()),
                u64::from(EffectVariantEnum::Default.value()),
            ),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(
        *lamp.effects.borrow(),
        vec![(
            EffectIdentifierEnum::Okay.value(),
            EffectVariantEnum::Default.value()
        )]
    );
    assert!(!device.cluster.is_identifying());
}

#[test]
fn a_reserved_effect_is_refused_rather_than_rounded() {
    // §1.2.6.2.1: "SHALL contain one of the non-reserved values". What a future revision
    // assigns must not decide what this device does today — so an unknown value is an error,
    // not the nearest effect this revision happens to know.
    let lamp = Lamp::default();
    let device = device(&lamp, &Identify::<Lamp>::WITH_TRIGGER_EFFECT);
    assert_eq!(
        invoke(
            &device,
            identify::TRIGGER_EFFECT,
            &two_fields(0x42, 0),
            at(0)
        ),
        Status::ConstraintError
    );
    assert!(lamp.effects.borrow().is_empty());
}

#[test]
fn a_command_missing_its_mandatory_field_is_refused() {
    let lamp = Lamp::default();
    let device = device(&lamp, &Optional::NONE);
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.end_container().unwrap();
    let empty = w.finish().unwrap().to_vec();
    assert_eq!(
        invoke(&device, identify::IDENTIFY, &empty, at(0)),
        Status::InvalidCommand
    );
}
