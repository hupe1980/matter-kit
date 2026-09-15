//! Water Heater Management (Application Cluster §9.5), driven through the interaction model.
//!
//! A hot water tank is a battery that stores heat, and this cluster is how something else
//! decides when to charge it. The rules worth testing are the ones that stop a `Boost` from
//! becoming a tariff-blind immersion heater: every boost has a `Duration` and expires, the
//! appliance may refuse one it cannot ramp up for, and `TargetReheat` above `TargetPercentage`
//! is a loop that never closes.

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
use matter_kit::clusters::water_heater_management::{
    self as water, BoostStateEnum, Event, WaterHeaterBoostInfoStruct, WaterHeaterHeatSourceBitmap,
    WaterHeaterHooks, WaterHeaterManagement,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status,
};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

/// A tank whose minimum acceptable boost is five minutes — a heat pump's ramp.
#[derive(Debug)]
struct Tank {
    demand: Cell<u8>,
    tank_percentage: Cell<u8>,
    /// The shortest boost this appliance will accept, in seconds.
    minimum_boost: Cell<u32>,
    accepted: RefCell<Vec<WaterHeaterBoostInfoStruct>>,
    cancels: Cell<usize>,
}

impl Default for Tank {
    fn default() -> Self {
        Self {
            demand: Cell::new(0),
            tank_percentage: Cell::new(35),
            minimum_boost: Cell::new(300),
            accepted: RefCell::new(Vec::new()),
            cancels: Cell::new(0),
        }
    }
}

impl WaterHeaterHooks for Tank {
    fn heat_demand(&self) -> WaterHeaterHeatSourceBitmap {
        WaterHeaterHeatSourceBitmap::from_bits_truncate(self.demand.get())
    }

    fn tank_volume(&self) -> u16 {
        180
    }

    fn estimated_heat_required(&self) -> u64 {
        4_647_000
    }

    fn tank_percentage(&self) -> u8 {
        self.tank_percentage.get()
    }

    fn boost(&self, info: &WaterHeaterBoostInfoStruct) -> Result<(), Status> {
        // §9.5.8.1: "If the duration field is too short for the water heater to accept, for
        // example a heat pump may take several minutes to ramp up in operation, then the boost
        // command SHALL be rejected with a status of INVALID_IN_STATE."
        if info.duration < self.minimum_boost.get() {
            return Err(Status::InvalidInState);
        }
        self.accepted.borrow_mut().push(*info);
        Ok(())
    }

    fn cancel_boost(&self) {
        self.cancels.set(self.cancels.get() + 1);
    }
}

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

const EM: u32 = water::feature::ENERGY_MANAGEMENT;
const TP: u32 = water::feature::TANK_PERCENT;

struct Device<'a> {
    node: Node<'a>,
    cluster: WaterHeaterManagement<'a, Tank>,
}

fn device(tank: &Tank, feature_map: u32) -> Device<'_> {
    let conforming = Box::leak(Box::new(
        WaterHeaterManagement::<Tank>::conforming(feature_map, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: WaterHeaterManagement::new(
            tank,
            WaterHeaterHeatSourceBitmap::HEAT_PUMP
                | WaterHeaterHeatSourceBitmap::IMMERSION_ELEMENT1,
        ),
    }
}

fn invoke(device: &Device<'_>, command: u32, fields: Option<&[u8]>, now: Instant) -> Status {
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(1, water::ID, command))
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
        InvokeResponse::Command(_) => panic!("Water Heater Management has no response commands"),
    }
}

/// A `Boost` payload.
fn boost(
    duration: u32,
    one_shot: Option<bool>,
    target_percentage: Option<u8>,
    target_reheat: Option<u8>,
) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.start_structure(Tag::Context(0)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(duration)).unwrap();
    if let Some(one_shot) = one_shot {
        w.bool(Tag::Context(1), one_shot).unwrap();
    }
    if let Some(target) = target_percentage {
        w.unsigned(Tag::Context(4), u64::from(target)).unwrap();
    }
    if let Some(reheat) = target_reheat {
        w.unsigned(Tag::Context(5), u64::from(reheat)).unwrap();
    }
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn read(device: &Device<'_>, attribute: u32) -> u64 {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    let resolved = device
        .node
        .resolve(1, water::ID, attribute)
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
fn the_cluster_matches_the_specification_for_every_feature_combination() {
    let spec = generated::find(water::ID).expect("Water Heater Management");
    for bits in [0, EM, TP, EM | TP] {
        let built =
            WaterHeaterManagement::<Tank>::conforming(bits, &Optional::NONE).expect("sized");
        let mut defects = Vec::new();
        spec.validate(&built.descriptor(), |defect| defects.push(defect));
        assert!(defects.is_empty(), "features {bits:#x}: {defects:?}");
    }
}

#[test]
fn the_energy_management_feature_brings_the_two_estimation_attributes() {
    // §9.5.7's table: `TankVolume` and `EstimatedHeatRequired` are both `EM`. Without them an
    // energy manager cannot work out what heating the tank will cost, which is the entire
    // point of the feature.
    let plain = WaterHeaterManagement::<Tank>::conforming(0, &Optional::NONE).expect("sized");
    let managed = WaterHeaterManagement::<Tank>::conforming(EM, &Optional::NONE).expect("sized");
    assert_eq!(
        managed.descriptor().attributes.len(),
        plain.descriptor().attributes.len() + 2
    );
    let tp = WaterHeaterManagement::<Tank>::conforming(TP, &Optional::NONE).expect("sized");
    assert_eq!(
        tp.descriptor().attributes.len(),
        plain.descriptor().attributes.len() + 1
    );
}

// --- Boost -----------------------------------------------------------------------------------

#[test]
fn a_boost_activates_and_reports_its_terms() {
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Inactive);

    assert_eq!(
        invoke(
            &device,
            water::BOOST,
            Some(&boost(3600, None, None, None)),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Active);
    assert_eq!(
        read(&device, water::BOOST_STATE),
        u64::from(BoostStateEnum::Active.value())
    );
    assert_eq!(tank.accepted.borrow().len(), 1);

    // §9.5.9.1: "generated whenever a Boost command is accepted", carrying the fields.
    let events = device.cluster.take_events();
    assert_eq!(events.len(), 1);
    match events[0] {
        Event::BoostStarted(info) => assert_eq!(info.duration, 3600),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_boost_the_appliance_cannot_ramp_up_for_is_invalid_in_state() {
    // §9.5.8.1's named case. Only the appliance knows its own ramp — a heat pump takes
    // minutes — so the cluster never invents a minimum of its own.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    assert_eq!(
        invoke(
            &device,
            water::BOOST,
            Some(&boost(60, None, None, None)),
            at(0)
        ),
        Status::InvalidInState
    );
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Inactive);
    assert!(tank.accepted.borrow().is_empty());
    assert!(
        device.cluster.take_events().is_empty(),
        "a refused boost emitted an event"
    );
}

#[test]
fn a_boost_expires_when_its_duration_runs_out() {
    // §9.5.8.1: "or the boost command's duration times out after the specified Duration, then
    // BoostState transitions to Inactive. This SHALL cause the BoostEnded event to be
    // generated." A boost with no end is an immersion heater that ignores the tariff it was
    // installed to follow.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    invoke(
        &device,
        water::BOOST,
        Some(&boost(1800, None, None, None)),
        at(0),
    );
    device.cluster.take_events();

    assert_eq!(device.cluster.wake_at(), Some(at(1800)));
    device.cluster.poll(at(1799));
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Active);

    device.cluster.poll(at(1800));
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Inactive);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::BoostEnded]
    );
    assert_eq!(tank.cancels.get(), 1);
    assert_eq!(device.cluster.wake_at(), None);

    // ...and it ends exactly once.
    device.cluster.poll(at(9000));
    assert!(device.cluster.take_events().is_empty());
}

#[test]
fn a_second_boost_replaces_the_first_without_ending_it() {
    // §9.5.8.1: "If the Water Heater was already in the BoostState 'Active' when this command
    // is received, it SHALL continue in this BoostState, but SHALL discard the effect of the
    // values of the fields from the previous Boost commands ... A new BoostStarted event SHALL
    // be generated." Continue — so no `BoostEnded` in between, which a client would read as
    // the heating having stopped.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    invoke(
        &device,
        water::BOOST,
        Some(&boost(600, None, None, None)),
        at(0),
    );
    device.cluster.take_events();

    invoke(
        &device,
        water::BOOST,
        Some(&boost(7200, None, None, None)),
        at(100),
    );
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Active);
    let events = device.cluster.take_events();
    assert_eq!(
        events.len(),
        1,
        "a replacement emitted BoostEnded: {events:?}"
    );
    assert!(matches!(events[0], Event::BoostStarted(_)));

    // The new duration is measured from the new command, not the old one.
    assert_eq!(device.cluster.wake_at(), Some(at(7300)));
    device.cluster.poll(at(600));
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Active);
}

#[test]
fn cancelling_a_boost_that_is_not_running_succeeds() {
    // §9.5.8.2: "If the BoostState attribute value was already Inactive when this command is
    // received, the BoostState attribute value shall remain Inactive and the server SHALL
    // return SUCCESS." Cancelling nothing is the state the client asked for.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    assert_eq!(
        invoke(&device, water::CANCEL_BOOST, None, at(0)),
        Status::Success
    );
    assert!(
        device.cluster.take_events().is_empty(),
        "BoostEnded with no boost"
    );
    assert_eq!(tank.cancels.get(), 0);

    invoke(
        &device,
        water::BOOST,
        Some(&boost(3600, None, None, None)),
        at(0),
    );
    device.cluster.take_events();
    assert_eq!(
        invoke(&device, water::CANCEL_BOOST, None, at(10)),
        Status::Success
    );
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Inactive);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::BoostEnded]
    );
    assert_eq!(tank.cancels.get(), 1);
}

// --- Constraints -----------------------------------------------------------------------------

#[test]
fn a_boost_of_no_duration_is_refused() {
    // §9.5.6.3's constraint on `Duration` is "min 1". A boost for no time would expire on the
    // tick it started, which is a command with no effect dressed as one with an effect.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    assert_eq!(
        invoke(
            &device,
            water::BOOST,
            Some(&boost(0, None, None, None)),
            at(0)
        ),
        Status::ConstraintError
    );
}

#[test]
fn a_reheat_above_the_target_is_refused() {
    // §9.5.6.3.6: "This field SHALL be less than or equal to the TargetPercentage field."
    // Reheating to a level above the target is a loop that never closes: the tank would reach
    // 80%, notice it is below 90%, and start again.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    assert_eq!(
        invoke(
            &device,
            water::BOOST,
            Some(&boost(3600, None, Some(80), Some(90))),
            at(0)
        ),
        Status::ConstraintError
    );
    // Equal is allowed — "less than or equal".
    assert_eq!(
        invoke(
            &device,
            water::BOOST,
            Some(&boost(3600, None, Some(80), Some(80))),
            at(0)
        ),
        Status::Success
    );
}

#[test]
fn a_percentage_above_a_hundred_is_refused() {
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    assert_eq!(
        invoke(
            &device,
            water::BOOST,
            Some(&boost(3600, None, Some(120), None)),
            at(0)
        ),
        Status::ConstraintError
    );
}

// --- OneShot ---------------------------------------------------------------------------------

#[test]
fn one_shot_ends_the_boost_when_the_target_is_reached() {
    // §9.5.8.1: "If OneShot is specified then once the hot water has reached the set point
    // temperature ... or the TargetPercentage (if specified) ... BoostState transitions to
    // Inactive." Only the appliance knows it got there, so it says so.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    invoke(
        &device,
        water::BOOST,
        Some(&boost(7200, Some(true), Some(80), None)),
        at(0),
    );
    device.cluster.take_events();

    tank.tank_percentage.set(80);
    device.cluster.target_reached();
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Inactive);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::BoostEnded]
    );
}

#[test]
fn without_one_shot_reaching_the_target_is_not_the_end() {
    // The point of §9.5.6.3.6's `TargetReheat`: "after initial heating to 80% hot water, the
    // tank may have hot water drawn off until only 40% hot water remains. At this point the
    // heater will begin to heat back up to 80%". A boost that ended at the target the first
    // time would never do the second half.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    invoke(
        &device,
        water::BOOST,
        Some(&boost(7200, None, Some(80), Some(40))),
        at(0),
    );
    device.cluster.take_events();

    device.cluster.target_reached();
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Active);
    assert!(device.cluster.take_events().is_empty());

    // ...and the duration still ends it.
    device.cluster.poll(at(7200));
    assert_eq!(device.cluster.boost_state(), BoostStateEnum::Inactive);
}

// --- The read-only attributes -----------------------------------------------------------------

#[test]
fn the_estimation_attributes_come_from_the_appliance() {
    // §9.5.7.4 works the heat sum out in full and then notes that the *electrical* energy is a
    // different number entirely — a heat pump delivers 3 kWh of heat per kWh drawn — so the
    // cluster reports what the appliance computed and converts nothing.
    let tank = Tank::default();
    let device = device(&tank, EM | TP);
    assert_eq!(read(&device, water::TANK_VOLUME), 180);
    assert_eq!(read(&device, water::ESTIMATED_HEAT_REQUIRED), 4_647_000);
    assert_eq!(read(&device, water::TANK_PERCENTAGE), 35);
    assert_eq!(
        read(&device, water::HEATER_TYPES),
        u64::from(
            (WaterHeaterHeatSourceBitmap::HEAT_PUMP
                | WaterHeaterHeatSourceBitmap::IMMERSION_ELEMENT1)
                .bits()
        )
    );

    // `HeatDemand` is live: which sources are running right now, not which exist.
    assert_eq!(read(&device, water::HEAT_DEMAND), 0);
    tank.demand
        .set(WaterHeaterHeatSourceBitmap::HEAT_PUMP.bits());
    assert_eq!(
        read(&device, water::HEAT_DEMAND),
        u64::from(WaterHeaterHeatSourceBitmap::HEAT_PUMP.bits())
    );
}
