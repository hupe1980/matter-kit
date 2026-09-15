//! Level Control (Application Cluster §1.6), driven through the interaction model.
//!
//! The cluster is two nearly-identical sets of commands, and almost everything worth testing is
//! about what separates them:
//!
//! * a `MoveToLevel` to a light that is **off** does nothing, unless `ExecuteIfOff` is in force
//!   (§1.6.6.9) — otherwise a dimmer silently winds the lamp up while it is switched off, and
//!   turning it on later blinds somebody;
//! * a `MoveToLevelWithOnOff` to the same light turns it on *first* (§1.6.7.6), so the fade is
//!   visible rather than a snap at the end.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::{Cell, RefCell};

use matter_kit::clusters::generated;
use matter_kit::clusters::level_control::{
    self, LevelControl, LevelControlHooks, NoOnOff, OnOffState, OptionsBitmap, TICK,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status, WriteOp,
};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

/// A dimmer that records every level it was told.
#[derive(Debug, Default)]
struct Dimmer {
    level: Cell<Option<u8>>,
    seen: RefCell<Vec<Option<u8>>>,
    frequencies: RefCell<Vec<u16>>,
    /// Whether the device claims it can reach a requested frequency.
    can_tune: Cell<bool>,
}

impl LevelControlHooks for Dimmer {
    fn level(&self, level: Option<u8>) {
        self.level.set(level);
        self.seen.borrow_mut().push(level);
    }

    fn frequency(&self, frequency: u16) -> bool {
        self.frequencies.borrow_mut().push(frequency);
        self.can_tune.get()
    }
}

/// A stand-in for the On/Off cluster on the same endpoint.
#[derive(Debug)]
struct Switch {
    on: Cell<bool>,
    changes: RefCell<Vec<bool>>,
}

impl Switch {
    fn new(on: bool) -> Self {
        Self {
            on: Cell::new(on),
            changes: RefCell::new(Vec::new()),
        }
    }
}

impl OnOffState for Switch {
    fn is_on(&self) -> bool {
        self.on.get()
    }

    fn set_from_level(&self, on: bool) {
        self.on.set(on);
        self.changes.borrow_mut().push(on);
    }
}

fn at(tenths: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_millis(tenths * 100))
}

const LIGHTING: u32 = level_control::feature::LIGHTING;
const ON_OFF: u32 = level_control::feature::ON_OFF;

struct Device<'a> {
    node: Node<'a>,
    cluster: LevelControl<'a, Dimmer, Switch>,
}

fn device<'a>(dimmer: &'a Dimmer, switch: &'a Switch, feature_map: u32) -> Device<'a> {
    let conforming = Box::leak(Box::new(
        LevelControl::<Dimmer, Switch>::conforming(
            feature_map,
            &LevelControl::<Dimmer, Switch>::WITH_ALL_OPTIONAL,
        )
        .expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: LevelControl::with_on_off(dimmer, switch, feature_map),
    }
}

fn invoke(device: &Device<'_>, command: u32, fields: &[u8], now: Instant) -> Status {
    let data = CommandData {
        fields: Some(fields),
        ..CommandData::new(CommandPath::command(1, level_control::ID, command))
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
        InvokeResponse::Command(_) => panic!("Level Control has no response commands"),
    }
}

/// `MoveToLevel`-shaped fields: level, transition, mask, override.
fn move_to(level: u8, transition: Option<u16>, mask: u8, over: u8) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(level)).unwrap();
    match transition {
        Some(tenths) => w.unsigned(Tag::Context(1), u64::from(tenths)).unwrap(),
        None => w.null(Tag::Context(1)).unwrap(),
    }
    w.unsigned(Tag::Context(2), u64::from(mask)).unwrap();
    w.unsigned(Tag::Context(3), u64::from(over)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// `Move`-shaped fields: mode, rate, mask, override.
fn move_at(up: bool, rate: Option<u8>, mask: u8, over: u8) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(!up)).unwrap();
    match rate {
        Some(rate) => w.unsigned(Tag::Context(1), u64::from(rate)).unwrap(),
        None => w.null(Tag::Context(1)).unwrap(),
    }
    w.unsigned(Tag::Context(2), u64::from(mask)).unwrap();
    w.unsigned(Tag::Context(3), u64::from(over)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// `Step`-shaped fields: mode, size, transition, mask, override.
fn step(up: bool, size: u8, transition: Option<u16>, mask: u8, over: u8) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(!up)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(size)).unwrap();
    match transition {
        Some(tenths) => w.unsigned(Tag::Context(2), u64::from(tenths)).unwrap(),
        None => w.null(Tag::Context(2)).unwrap(),
    }
    w.unsigned(Tag::Context(3), u64::from(mask)).unwrap();
    w.unsigned(Tag::Context(4), u64::from(over)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn stop_fields(mask: u8, over: u8) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(mask)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(over)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn read(device: &Device<'_>, attribute: u32) -> u64 {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    let resolved = device
        .node
        .resolve(1, level_control::ID, attribute)
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

fn write(device: &Device<'_>, attribute: u32, value: Option<u64>) -> Result<(), Status> {
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    match value {
        Some(value) => w.unsigned(Tag::Context(2), value).unwrap(),
        None => w.null(Tag::Context(2)).unwrap(),
    }
    let data = w.finish().unwrap().to_vec();
    let resolved = device
        .node
        .resolve(1, level_control::ID, attribute)
        .expect("attribute");
    device.cluster.write(
        &resolved,
        &data,
        WriteOp::Replace,
        &InteractionContext::new(),
    )
}

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_cluster_matches_the_specification_for_every_feature_combination() {
    let spec = generated::find(level_control::ID).expect("Level Control");
    for bits in [
        0,
        ON_OFF,
        LIGHTING,
        ON_OFF | LIGHTING,
        ON_OFF | LIGHTING | level_control::feature::FREQUENCY,
    ] {
        for optional in [
            Optional::NONE,
            LevelControl::<Dimmer, NoOnOff>::WITH_RANGE,
            LevelControl::<Dimmer, NoOnOff>::WITH_ALL_OPTIONAL,
        ] {
            let built =
                LevelControl::<Dimmer, NoOnOff>::conforming(bits, &optional).expect("sized");
            let mut defects = Vec::new();
            spec.validate(&built.descriptor(), |defect| defects.push(defect));
            assert!(defects.is_empty(), "features {bits:#x}: {defects:?}");
        }
    }
}

#[test]
fn the_lighting_feature_brings_remaining_time_and_the_startup_level() {
    // §1.6.6's table: `RemainingTime` is `LT` and `StartUpCurrentLevel` is `LT`. A dimmer
    // without the feature has neither, and a validator that let it advertise them would be
    // describing a different product.
    let plain = LevelControl::<Dimmer, NoOnOff>::conforming(0, &Optional::NONE).expect("sized");
    let lit =
        LevelControl::<Dimmer, NoOnOff>::conforming(LIGHTING, &Optional::NONE).expect("sized");
    assert_eq!(
        lit.descriptor().attributes.len(),
        plain.descriptor().attributes.len() + 2
    );
}

// --- MoveToLevel -----------------------------------------------------------------------------

#[test]
fn a_move_to_level_fades_rather_than_jumping() {
    // §1.6.7.1.1: "The movement SHALL be as continuous as technically practical, i.e., not a
    // step function". A device that set the target and waited would be a step function with
    // extra steps.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));
    assert_eq!(device.cluster.level(), Some(100));

    // To 200 over two seconds — twenty ticks.
    assert_eq!(
        invoke(
            &device,
            level_control::MOVE_TO_LEVEL,
            &move_to(200, Some(20), 0, 0),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(read(&device, level_control::REMAINING_TIME), 20);

    device.cluster.poll(at(10));
    let halfway = device.cluster.level().expect("a level");
    assert!(
        (145..=155).contains(&halfway),
        "halfway through a 100→200 fade the level was {halfway}"
    );
    assert_eq!(read(&device, level_control::REMAINING_TIME), 10);

    device.cluster.poll(at(20));
    assert_eq!(device.cluster.level(), Some(200));
    assert_eq!(read(&device, level_control::REMAINING_TIME), 0);
    assert_eq!(device.cluster.wake_at(), None);
}

#[test]
fn a_level_outside_the_range_is_clipped_rather_than_refused() {
    // §1.6.7.1.1: "If the value of the Level field is below the MinLevel or above the MaxLevel
    // for the device, the value SHALL be clipped to the applicable boundary value." A client
    // that asks for 255 gets the brightest the lamp has, not an error.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));
    assert_eq!(
        invoke(
            &device,
            level_control::MOVE_TO_LEVEL,
            &move_to(255, Some(0), 0, 0),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(device.cluster.level(), Some(level_control::LIGHTING_MAX));
}

#[test]
fn a_null_transition_time_means_the_on_off_transition_time() {
    // §1.6.7.1.1: "If the TransitionTime field takes the value null then the time taken to move
    // to the new level SHALL instead be determined by the OnOffTransitionTime attribute."
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(1));
    write(&device, level_control::ON_OFF_TRANSITION_TIME, Some(30)).expect("write");
    invoke(
        &device,
        level_control::MOVE_TO_LEVEL,
        &move_to(254, None, 0, 0),
        at(0),
    );
    assert_eq!(read(&device, level_control::REMAINING_TIME), 30);
    device.cluster.poll(at(30));
    assert_eq!(device.cluster.level(), Some(254));
}

// --- The Options gate ------------------------------------------------------------------------

#[test]
fn a_command_without_on_off_does_nothing_while_the_light_is_off() {
    // §1.6.6.9's four criteria, all true. This is the rule that keeps a dimmer from winding a
    // lamp up while it is switched off, so that turning it on later blinds somebody.
    let dimmer = Dimmer::default();
    let switch = Switch::new(false);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(50));

    for (command, fields) in [
        (level_control::MOVE_TO_LEVEL, move_to(254, Some(0), 0, 0)),
        (level_control::MOVE, move_at(true, Some(10), 0, 0)),
        (level_control::STEP, step(true, 50, Some(0), 0, 0)),
    ] {
        assert_eq!(
            invoke(&device, command, &fields, at(0)),
            Status::Success,
            "the command still succeeds; it just does nothing"
        );
        assert_eq!(
            device.cluster.level(),
            Some(50),
            "command {command:#x} moved a light that is off"
        );
    }
    assert!(switch.changes.borrow().is_empty());
}

#[test]
fn execute_if_off_in_the_options_attribute_opens_the_gate() {
    let dimmer = Dimmer::default();
    let switch = Switch::new(false);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(50));
    write(
        &device,
        level_control::OPTIONS,
        Some(u64::from(OptionsBitmap::EXECUTE_IF_OFF.bits())),
    )
    .expect("write");
    invoke(
        &device,
        level_control::MOVE_TO_LEVEL,
        &move_to(200, Some(0), 0, 0),
        at(0),
    );
    assert_eq!(device.cluster.level(), Some(200));
    // ...and the light is still off: a command *without* On/Off never touches it.
    assert!(!switch.is_on());
}

#[test]
fn the_mask_and_override_fields_beat_the_attribute_both_ways() {
    // §1.6.7.1.1's temporary bitmap. A client can say "just this once" without writing an
    // attribute the specification calls "meant to be changed only during commissioning" —
    // and can also turn the bit *off* for one command when the attribute has it on.
    let dimmer = Dimmer::default();
    let switch = Switch::new(false);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(50));

    // Attribute clear, override sets it for this command.
    let bit = OptionsBitmap::EXECUTE_IF_OFF.bits();
    invoke(
        &device,
        level_control::MOVE_TO_LEVEL,
        &move_to(200, Some(0), bit, bit),
        at(0),
    );
    assert_eq!(device.cluster.level(), Some(200));

    // Attribute set, override clears it for this command.
    write(&device, level_control::OPTIONS, Some(u64::from(bit))).expect("write");
    invoke(
        &device,
        level_control::MOVE_TO_LEVEL,
        &move_to(10, Some(0), bit, 0),
        at(0),
    );
    assert_eq!(
        device.cluster.level(),
        Some(200),
        "the override was ignored"
    );
}

#[test]
fn an_endpoint_with_no_on_off_cluster_is_never_gated() {
    // §1.6.6.9's second criterion: "The On/Off cluster exists on the same endpoint as this
    // cluster." A volume control has no On/Off, so the gate cannot close — and a device that
    // treated "no cluster" as "off" would be deaf to every command it ever received.
    assert!(!NoOnOff.present());
    let dimmer = Dimmer::default();
    let cluster: LevelControl<'_, Dimmer, NoOnOff> = LevelControl::new(&dimmer, LIGHTING);
    cluster.start(Some(50));

    let built = LevelControl::<Dimmer, NoOnOff>::conforming(
        LIGHTING,
        &LevelControl::<Dimmer, NoOnOff>::WITH_ALL_OPTIONAL,
    )
    .expect("sized");
    let clusters = [built.descriptor()];
    let endpoints = [Endpoint::new(1, &clusters)];
    let node = Node::new(&endpoints);
    let resolved = node
        .resolve_command(1, level_control::ID, level_control::MOVE_TO_LEVEL)
        .expect("MoveToLevel");
    let fields = move_to(200, Some(0), 0, 0);
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    cluster
        .invoke(
            &resolved,
            Some(&fields),
            &InteractionContext::new().at(at(0)),
            &mut w,
            Tag::Anonymous,
        )
        .expect("invoke");
    assert_eq!(
        cluster.level(),
        Some(200),
        "a command was gated on an endpoint with no On/Off cluster"
    );
}

// --- 'with On/Off' ---------------------------------------------------------------------------

#[test]
fn with_on_off_turns_the_light_on_before_the_fade_not_after() {
    // §1.6.7.6: "Before commencing any command that has the effect of setting the CurrentLevel
    // attribute above the minimum level allowed by the device, the OnOff attribute ... SHALL be
    // set to TRUE." Before, so the fade is visible — a device that set it at the end would
    // snap on at full brightness.
    let dimmer = Dimmer::default();
    let switch = Switch::new(false);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(1));

    invoke(
        &device,
        level_control::MOVE_TO_LEVEL_WITH_ON_OFF,
        &move_to(254, Some(20), 0, 0),
        at(0),
    );
    assert!(switch.is_on(), "the light was not on when the fade started");
    assert_eq!(*switch.changes.borrow(), vec![true]);
    assert!(device.cluster.level().unwrap() < 254, "it snapped instead");

    device.cluster.poll(at(20));
    assert_eq!(device.cluster.level(), Some(254));
}

#[test]
fn with_on_off_turns_the_light_off_when_the_level_lands_on_the_minimum() {
    // The other half of §1.6.7.6: "If any command that has the effect of setting the
    // CurrentLevel attribute to the minimum level allowed by the device, the OnOff attribute
    // ... SHALL be set to FALSE ('Off')."
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(254));

    invoke(
        &device,
        level_control::MOVE_TO_LEVEL_WITH_ON_OFF,
        &move_to(1, Some(10), 0, 0),
        at(0),
    );
    assert!(switch.is_on(), "it went off before the fade finished");
    device.cluster.poll(at(10));
    assert_eq!(device.cluster.level(), Some(1));
    assert!(!switch.is_on());
    assert_eq!(*switch.changes.borrow(), vec![false]);
}

#[test]
fn a_plain_move_to_level_never_touches_the_on_off_attribute() {
    // §1.6.4.1.2: "The first set is used to maintain independence between the CurrentLevel and
    // OnOff attributes" — a volume control with a separate mute button. A device that aliased
    // the two sets would be the other product.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(254));
    invoke(
        &device,
        level_control::MOVE_TO_LEVEL,
        &move_to(1, Some(0), 0, 0),
        at(0),
    );
    assert_eq!(device.cluster.level(), Some(1));
    assert!(switch.is_on(), "a plain MoveToLevel turned the light off");
    assert!(switch.changes.borrow().is_empty());
}

// --- Move ------------------------------------------------------------------------------------

#[test]
fn a_move_runs_at_its_rate_until_a_boundary() {
    // §1.6.7.2.3: "Increase the device's level at the rate given in the Rate field. If the
    // level reaches the maximum allowed for the device, stop."
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));

    // 50 units per second, so five per tenth.
    invoke(
        &device,
        level_control::MOVE,
        &move_at(true, Some(50), 0, 0),
        at(0),
    );
    device.cluster.poll(at(2));
    assert_eq!(device.cluster.level(), Some(110));
    device.cluster.poll(at(10));
    assert_eq!(device.cluster.level(), Some(150));

    // ...and it stops at the top rather than wrapping.
    device.cluster.poll(at(100));
    assert_eq!(device.cluster.level(), Some(254));
    assert_eq!(device.cluster.wake_at(), None);
}

#[test]
fn a_rate_of_one_actually_moves() {
    // One unit per second is a tenth of a unit per tick. A device that rounded each tick to a
    // whole unit would round to zero every time and never move at all — the slowest fade a
    // client can ask for would be the one that does nothing.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));
    invoke(
        &device,
        level_control::MOVE,
        &move_at(true, Some(1), 0, 0),
        at(0),
    );
    device.cluster.poll(at(5));
    assert_eq!(
        device.cluster.level(),
        Some(100),
        "half a second is half a unit"
    );
    device.cluster.poll(at(10));
    assert_eq!(device.cluster.level(), Some(101));
    device.cluster.poll(at(30));
    assert_eq!(device.cluster.level(), Some(103));
}

#[test]
fn a_move_with_a_rate_of_zero_is_invalid() {
    // §1.6.7.2.3: "if the Rate field has a value of zero, the command has no effect and a
    // response SHALL be returned with the status code set to INVALID_COMMAND". Zero is not a
    // slow move; it is a move that never ends.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));
    assert_eq!(
        invoke(
            &device,
            level_control::MOVE,
            &move_at(true, Some(0), 0, 0),
            at(0)
        ),
        Status::InvalidCommand
    );
    assert_eq!(device.cluster.level(), Some(100));
}

#[test]
fn a_null_rate_means_the_default_move_rate() {
    // §1.6.7.2.2: "If the Rate field is null, then the value of the DefaultMoveRate attribute
    // SHALL be used if that attribute is supported and its value is not null."
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));
    write(&device, level_control::DEFAULT_MOVE_RATE, Some(20)).expect("write");
    invoke(
        &device,
        level_control::MOVE,
        &move_at(true, None, 0, 0),
        at(0),
    );
    device.cluster.poll(at(10));
    assert_eq!(device.cluster.level(), Some(120));
}

#[test]
fn a_null_rate_with_no_default_moves_as_fast_as_it_can() {
    // "If the Rate field is null and the DefaultMoveRate attribute is either not supported or
    // set to null, then the device SHOULD move as fast as it is able."
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));
    invoke(
        &device,
        level_control::MOVE,
        &move_at(true, None, 0, 0),
        at(0),
    );
    assert_eq!(device.cluster.level(), Some(254));
    assert_eq!(device.cluster.wake_at(), None);
}

// --- Step ------------------------------------------------------------------------------------

#[test]
fn a_step_that_hits_a_boundary_takes_proportionally_less_time() {
    // §1.6.7.3.4: "or until it reaches the minimum level allowed for the device if this reached
    // in the process. In the latter case, the transition time SHALL be proportionally
    // reduced." Without it, a dimmer stepped to the end crawls the last inch.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(244));

    // A step of 100 over 10 seconds, but only 10 units of headroom — so a tenth of the time.
    invoke(
        &device,
        level_control::STEP,
        &step(true, 100, Some(100), 0, 0),
        at(0),
    );
    assert_eq!(read(&device, level_control::REMAINING_TIME), 10);
    device.cluster.poll(at(10));
    assert_eq!(device.cluster.level(), Some(254));
}

#[test]
fn a_step_of_zero_is_invalid() {
    // §1.6.7.3.4, the same shape as `Move`'s zero rate.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));
    assert_eq!(
        invoke(
            &device,
            level_control::STEP,
            &step(true, 0, Some(0), 0, 0),
            at(0)
        ),
        Status::InvalidCommand
    );
}

#[test]
fn a_step_down_stops_at_the_minimum() {
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(10));
    invoke(
        &device,
        level_control::STEP,
        &step(false, 200, Some(0), 0, 0),
        at(0),
    );
    assert_eq!(device.cluster.level(), Some(level_control::LIGHTING_MIN));
}

// --- Stop ------------------------------------------------------------------------------------

#[test]
fn stop_leaves_the_level_where_it_was() {
    // §1.6.7.4.1: "The value of CurrentLevel SHALL be left at its value upon receipt of the
    // Stop command, and RemainingTime SHALL be set to zero." Not the target, and not the
    // level it started from.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(100));
    invoke(
        &device,
        level_control::MOVE,
        &move_at(true, Some(50), 0, 0),
        at(0),
    );
    device.cluster.poll(at(4));
    let caught = device.cluster.level().expect("a level");
    assert_eq!(caught, 120);

    assert_eq!(
        invoke(&device, level_control::STOP, &stop_fields(0, 0), at(4)),
        Status::Success
    );
    assert_eq!(read(&device, level_control::REMAINING_TIME), 0);
    assert_eq!(device.cluster.wake_at(), None);
    device.cluster.poll(at(100));
    assert_eq!(device.cluster.level(), Some(caught));
}

#[test]
fn a_stop_at_the_minimum_does_not_turn_the_light_off() {
    // The subtle half of §1.6.7.4.1: a `Stop` leaves the level alone, so nothing *commanded*
    // it to the minimum — and §1.6.7.6's rule is about a command that sets the level there.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(2));
    invoke(
        &device,
        level_control::MOVE_WITH_ON_OFF,
        &move_at(false, Some(10), 0, 0),
        at(0),
    );
    device.cluster.poll(at(10));
    assert_eq!(device.cluster.level(), Some(1));
    assert!(!switch.is_on(), "a move to the minimum should turn it off");

    // Now the sharp case: a Stop while the level *is* the minimum. §1.6.7.6's rule is about a
    // command that has "the effect of setting the CurrentLevel attribute to the minimum
    // level" — a Stop sets nothing, it only ends a move, so the light stays on.
    switch.on.set(true);
    switch.changes.borrow_mut().clear();
    device.cluster.start(Some(level_control::LIGHTING_MIN));
    invoke(
        &device,
        level_control::MOVE_WITH_ON_OFF,
        &move_at(true, Some(10), 0, 0),
        at(0),
    );
    assert_eq!(
        *switch.changes.borrow(),
        vec![true],
        "the move up turned it on"
    );
    assert_eq!(device.cluster.level(), Some(level_control::LIGHTING_MIN));

    invoke(
        &device,
        level_control::STOP_WITH_ON_OFF,
        &stop_fields(0, 0),
        at(0),
    );
    assert_eq!(device.cluster.level(), Some(level_control::LIGHTING_MIN));
    assert!(switch.is_on(), "a Stop at the minimum turned the light off");
    assert_eq!(*switch.changes.borrow(), vec![true]);
    device.cluster.poll(at(100));
    assert!(switch.is_on());
}

// --- StartUpCurrentLevel ---------------------------------------------------------------------

#[test]
fn the_startup_level_decides_what_a_power_cut_restores() {
    // §1.6.6.15's table, all three rows. This is the attribute a user sets so the kitchen
    // light comes back at 20% at three in the morning instead of full brightness.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);

    // null — the previous value.
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(77));
    assert_eq!(device.cluster.level(), Some(77));

    // 0 — the minimum.
    device.cluster.set_start_up_level(Some(0));
    device.cluster.start(Some(77));
    assert_eq!(device.cluster.level(), Some(level_control::LIGHTING_MIN));

    // anything else — that value.
    device.cluster.set_start_up_level(Some(50));
    device.cluster.start(Some(77));
    assert_eq!(device.cluster.level(), Some(50));

    // A device that remembers nothing reports the null level rather than inventing one.
    device.cluster.set_start_up_level(None);
    device.cluster.start(None);
    assert_eq!(device.cluster.level(), None);
}

// --- The On/Off coupling ---------------------------------------------------------------------

#[test]
fn an_on_command_fades_up_from_the_minimum_to_on_level() {
    // §1.6.4.1.1's table: "Set CurrentLevel to the minimum level allowed for the device. Change
    // CurrentLevel to OnLevel, or to the stored level if OnLevel is not defined, over the time
    // period OnOffTransitionTime." Starting at the minimum is the point — a lamp that jumped to
    // the target and then "faded" would show nothing.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    // Start *above* the target, so a device that skipped the reset to the minimum would fade
    // down to 180 and land in the same place — the only thing that tells the two apart is
    // where the fade began.
    device.cluster.start(Some(240));
    write(&device, level_control::ON_OFF_TRANSITION_TIME, Some(10)).expect("write");
    device.cluster.set_on_level(Some(180));

    device.cluster.on_off_changed(true, Some(90), at(0));
    assert_eq!(
        device.cluster.level(),
        Some(level_control::LIGHTING_MIN),
        "the fade did not start from the minimum"
    );
    device.cluster.poll(at(5));
    let halfway = device.cluster.level().expect("a level");
    assert!(
        (80..=100).contains(&halfway),
        "halfway up a 1→180 fade the level was {halfway}"
    );
    device.cluster.poll(at(10));
    assert_eq!(
        device.cluster.level(),
        Some(180),
        "OnLevel wins over the stored level"
    );
}

#[test]
fn without_on_level_an_on_command_restores_the_stored_level() {
    // "...or to the stored level if OnLevel is not defined". §1.6.6.11: "If the OnLevel
    // attribute is not implemented, or is set to the null value, it has no effect."
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(1));
    device.cluster.set_on_level(None);
    device.cluster.on_off_changed(true, Some(90), at(0));
    device.cluster.poll(at(10));
    assert_eq!(device.cluster.level(), Some(90));
}

#[test]
fn an_off_command_fades_down_to_the_minimum() {
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(200));
    write(&device, level_control::OFF_TRANSITION_TIME, Some(20)).expect("write");
    device.cluster.on_off_changed(false, Some(200), at(0));
    assert_eq!(read(&device, level_control::REMAINING_TIME), 20);
    device.cluster.poll(at(20));
    assert_eq!(device.cluster.level(), Some(level_control::LIGHTING_MIN));
}

// --- Writes ----------------------------------------------------------------------------------

#[test]
fn an_on_level_outside_the_range_is_refused() {
    // §1.6.6.11's constraint is "MinLevel to MaxLevel". A device that stored 0 would fade to a
    // level §1.6.4.2 says "SHALL NOT be used".
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    assert_eq!(
        write(&device, level_control::ON_LEVEL, Some(0)),
        Err(Status::ConstraintError)
    );
    // ...and null is accepted, because null "has no effect".
    assert_eq!(write(&device, level_control::ON_LEVEL, None), Ok(()));
    assert_eq!(device.cluster.on_level(), None);
}

#[test]
fn a_default_move_rate_of_zero_is_refused() {
    // §1.6.6.14's constraint is "min 1". Zero is not a slow move; the command form of it is
    // already `INVALID_COMMAND`, and the attribute form must not be a way round that.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    assert_eq!(
        write(&device, level_control::DEFAULT_MOVE_RATE, Some(0)),
        Err(Status::ConstraintError)
    );
}

#[test]
fn an_options_bit_the_revision_does_not_define_is_refused() {
    // §7.19.2. A device that stored an unknown bit would echo it back and look as though it
    // understood a feature it does not have.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    assert_eq!(
        write(&device, level_control::OPTIONS, Some(0x80)),
        Err(Status::ConstraintError)
    );
    assert_eq!(device.cluster.options(), OptionsBitmap::empty());
}

#[test]
fn current_level_is_not_writable() {
    // §1.6.6's access column is `RV` — read only. A client changes it with a command, which is
    // what makes transitions and the On/Off coupling possible at all.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    assert_eq!(
        write(&device, level_control::CURRENT_LEVEL, Some(50)),
        Err(Status::UnsupportedWrite)
    );
}

// --- Frequency -------------------------------------------------------------------------------

#[test]
fn a_frequency_the_device_cannot_reach_is_a_constraint_error() {
    // §1.6.7.5.1: "If the device cannot approximate the frequency, then it SHALL return a
    // default response with an error code of CONSTRAINT_ERROR. Determining if a requested
    // frequency can be approximated by a supported frequency is a manufacturer-specific
    // decision" — so the product answers, not the cluster.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(
        &dimmer,
        &switch,
        LIGHTING | ON_OFF | level_control::feature::FREQUENCY,
    );
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 500).unwrap();
    w.end_container().unwrap();
    let fields = w.finish().unwrap().to_vec();

    dimmer.can_tune.set(false);
    assert_eq!(
        invoke(
            &device,
            level_control::MOVE_TO_CLOSEST_FREQUENCY,
            &fields,
            at(0)
        ),
        Status::ConstraintError
    );
    assert_eq!(read(&device, level_control::CURRENT_FREQUENCY), 0);

    dimmer.can_tune.set(true);
    assert_eq!(
        invoke(
            &device,
            level_control::MOVE_TO_CLOSEST_FREQUENCY,
            &fields,
            at(0)
        ),
        Status::Success
    );
    assert_eq!(read(&device, level_control::CURRENT_FREQUENCY), 500);
    assert_eq!(*dimmer.frequencies.borrow(), vec![500, 500]);
}

// --- Catching up -----------------------------------------------------------------------------

#[test]
fn a_late_poll_arrives_where_it_promised() {
    // A sleepy device polls when it wakes, not every tenth of a second. Counting *calls* rather
    // than elapsed time would leave a fade unfinished for as long as the radio was quiet.
    let dimmer = Dimmer::default();
    let switch = Switch::new(true);
    let device = device(&dimmer, &switch, LIGHTING | ON_OFF);
    device.cluster.start(Some(1));
    invoke(
        &device,
        level_control::MOVE_TO_LEVEL,
        &move_to(254, Some(600), 0, 0),
        at(0),
    );
    assert_eq!(device.cluster.wake_at(), Some(at(0).saturating_add(TICK)));
    device.cluster.poll(at(600));
    assert_eq!(device.cluster.level(), Some(254));
    assert_eq!(device.cluster.wake_at(), None);
}
