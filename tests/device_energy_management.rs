//! Device Energy Management (Application Cluster §9.2), driven through the interaction model.
//!
//! The cluster an energy manager talks to, and the one where the householder can say no. Four
//! rules carry most of the weight:
//!
//! * **The opt-out is per reason, not a switch** (§9.2.8.8). Someone who has opted out of grid
//!   optimisation may still want their own solar used, and a cluster that collapsed the two
//!   would take that away.
//! * **Overlapping adjustments do not each end** (§9.2.9.1.4) — a battery inverter retuned
//!   every five seconds would otherwise emit twelve events a minute.
//! * **A pause is extended, not replaced** (§9.2.9.4.3).
//! * **A stale `ForecastID` is refused** (§9.2.9.6.4): the EMS optimised a plan the appliance
//!   has already replaced.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::{Cell, RefCell};

use matter_kit::clusters::device_energy_management::{
    self as dem, AdjustmentCauseEnum, CauseEnum, ConstraintsStruct, DemHooks,
    DeviceEnergyManagement, ESAStateEnum, ESATypeEnum, Event, ForecastSummary, OptOutStateEnum,
    PowerAdjustReasonEnum, PowerAdjustStruct, SlotAdjustmentStruct,
};
use matter_kit::clusters::generated;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status,
};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

/// A battery inverter that can be retuned continuously, and a washing machine that cannot.
#[derive(Debug)]
struct Esa {
    base_state: Cell<ESAStateEnum>,
    opt_out: Cell<OptOutStateEnum>,
    forecast: Cell<Option<ForecastSummary>>,
    may_interrupt: Cell<bool>,
    ranges: Vec<PowerAdjustStruct>,
    adjusts: RefCell<Vec<(i64, u32, AdjustmentCauseEnum)>>,
    ends: RefCell<Vec<CauseEnum>>,
    pauses: RefCell<Vec<u32>>,
    resumes: Cell<usize>,
    modifications: RefCell<Vec<usize>>,
    constraints: RefCell<Vec<usize>>,
    cancels: Cell<usize>,
}

impl Default for Esa {
    fn default() -> Self {
        Self {
            base_state: Cell::new(ESAStateEnum::Online),
            opt_out: Cell::new(OptOutStateEnum::NoOptOut),
            forecast: Cell::new(Some(ForecastSummary {
                forecast_id: 42,
                start_time: 10_000,
                end_time: 17_200,
                earliest_start_time: Some(9_000),
                latest_end_time: Some(40_000),
                slot_is_pausable: true,
                min_pause_duration: 60,
                max_pause_duration: 600,
                adjusted: false,
            })),
            may_interrupt: Cell::new(true),
            ranges: vec![PowerAdjustStruct {
                min_power: 1_000_000,
                max_power: 7_000_000,
                min_duration: 30,
                max_duration: 3_600,
            }],
            adjusts: RefCell::new(Vec::new()),
            ends: RefCell::new(Vec::new()),
            pauses: RefCell::new(Vec::new()),
            resumes: Cell::new(0),
            modifications: RefCell::new(Vec::new()),
            constraints: RefCell::new(Vec::new()),
            cancels: Cell::new(0),
        }
    }
}

impl Esa {
    fn with_forecast(&self, edit: impl FnOnce(&mut ForecastSummary)) {
        let mut forecast = self.forecast.get().expect("a forecast");
        edit(&mut forecast);
        self.forecast.set(Some(forecast));
    }
}

impl DemHooks for Esa {
    fn esa_type(&self) -> ESATypeEnum {
        ESATypeEnum::BatteryStorage
    }

    fn can_generate(&self) -> bool {
        true
    }

    fn base_state(&self) -> ESAStateEnum {
        self.base_state.get()
    }

    fn abs_min_power(&self) -> i64 {
        0
    }

    fn abs_max_power(&self) -> i64 {
        7_000_000
    }

    fn opt_out_state(&self) -> OptOutStateEnum {
        self.opt_out.get()
    }

    fn power_adjust_ranges(&self) -> &[PowerAdjustStruct] {
        &self.ranges
    }

    fn forecast(&self) -> Option<ForecastSummary> {
        self.forecast.get()
    }

    fn power_adjust(
        &self,
        power_mw: i64,
        duration_s: u32,
        cause: AdjustmentCauseEnum,
    ) -> Result<(), Status> {
        self.adjusts
            .borrow_mut()
            .push((power_mw, duration_s, cause));
        Ok(())
    }

    fn may_interrupt_adjustment(&self) -> bool {
        self.may_interrupt.get()
    }

    fn end_power_adjust(&self, cause: CauseEnum) {
        self.ends.borrow_mut().push(cause);
    }

    fn adjust_start_time(
        &self,
        requested_start_time: u32,
        _cause: AdjustmentCauseEnum,
    ) -> Result<(), Status> {
        self.with_forecast(|f| {
            let span = f.end_time - f.start_time;
            f.start_time = requested_start_time;
            f.end_time = requested_start_time + span;
            f.adjusted = true;
        });
        Ok(())
    }

    fn pause(&self, duration_s: u32, _cause: AdjustmentCauseEnum) -> Result<(), Status> {
        self.pauses.borrow_mut().push(duration_s);
        Ok(())
    }

    fn resume(&self) -> Result<(), Status> {
        self.resumes.set(self.resumes.get() + 1);
        Ok(())
    }

    fn modify_forecast(
        &self,
        adjustments: &[SlotAdjustmentStruct],
        _cause: AdjustmentCauseEnum,
    ) -> Result<(), Status> {
        self.modifications.borrow_mut().push(adjustments.len());
        self.with_forecast(|f| {
            f.forecast_id += 1;
            f.adjusted = true;
        });
        Ok(())
    }

    fn constraint_based_forecast(
        &self,
        constraints: &[ConstraintsStruct],
        _cause: AdjustmentCauseEnum,
    ) -> Result<(), Status> {
        self.constraints.borrow_mut().push(constraints.len());
        self.with_forecast(|f| f.adjusted = true);
        Ok(())
    }

    fn cancel_adjustments(&self) -> Result<(), Status> {
        self.cancels.set(self.cancels.get() + 1);
        self.with_forecast(|f| f.adjusted = false);
        Ok(())
    }
}

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

const PA: u32 = dem::feature::POWER_ADJUSTMENT;
const PFR: u32 = dem::feature::POWER_FORECAST_REPORTING;
const STA: u32 = dem::feature::START_TIME_ADJUSTMENT;
const PAU: u32 = dem::feature::PAUSABLE;
const FA: u32 = dem::feature::FORECAST_ADJUSTMENT;
const CON: u32 = dem::feature::CONSTRAINT_BASED_ADJUSTMENT;
const ALL: u32 = PA | PFR | STA | PAU | FA | CON;

struct Device<'a> {
    node: Node<'a>,
    cluster: DeviceEnergyManagement<'a, Esa>,
}

fn device(esa: &Esa, feature_map: u32) -> Device<'_> {
    let conforming = Box::leak(Box::new(
        DeviceEnergyManagement::<Esa>::conforming(feature_map, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: DeviceEnergyManagement::new(esa, feature_map),
    }
}

fn invoke(device: &Device<'_>, command: u32, fields: Option<&[u8]>, now: Instant) -> Status {
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(1, dem::ID, command))
    };
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 4096];
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
        InvokeResponse::Command(_) => panic!("this cluster has no response commands"),
    }
}

fn power_adjust(power_mw: i32, duration: u32, cause: AdjustmentCauseEnum) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.signed(Tag::Context(0), i64::from(power_mw)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(duration)).unwrap();
    w.unsigned(Tag::Context(2), u64::from(cause.value()))
        .unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn two_fields(first: u64, cause: AdjustmentCauseEnum) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), first).unwrap();
    w.unsigned(Tag::Context(1), u64::from(cause.value()))
        .unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn modify_forecast(forecast_id: u32, slots: usize, cause: AdjustmentCauseEnum) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(forecast_id)).unwrap();
    w.start_array(Tag::Context(1)).unwrap();
    for index in 0..slots {
        w.start_structure(Tag::Anonymous).unwrap();
        w.unsigned(Tag::Context(0), index as u64).unwrap();
        w.unsigned(Tag::Context(2), 600).unwrap();
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.unsigned(Tag::Context(2), u64::from(cause.value()))
        .unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn constraints(count: usize, cause: AdjustmentCauseEnum) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.start_array(Tag::Context(0)).unwrap();
    for index in 0..count {
        w.start_structure(Tag::Anonymous).unwrap();
        w.unsigned(Tag::Context(0), 10_000 + index as u64).unwrap();
        w.unsigned(Tag::Context(1), 3_600).unwrap();
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.unsigned(Tag::Context(1), u64::from(cause.value()))
        .unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn read(device: &Device<'_>, attribute: u32) -> i64 {
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new(&mut buf);
    let resolved = device
        .node
        .resolve(1, dem::ID, attribute)
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
    // `power-mW` is signed — an ESA that generates reports a negative power — so a reader that
    // assumed unsigned would work until it met a solar inverter.
    match reader.next_element().unwrap().unwrap().value {
        Value::Unsigned(value) => value as i64,
        Value::Signed(value) => value,
        other => panic!("not a number: {other:?}"),
    }
}

const LOCAL: AdjustmentCauseEnum = AdjustmentCauseEnum::LocalOptimization;
const GRID: AdjustmentCauseEnum = AdjustmentCauseEnum::GridOptimization;

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_cluster_matches_the_specification_for_every_feature_combination() {
    let spec = generated::find(dem::ID).expect("Device Energy Management");
    for bits in [
        0,
        PA,
        PFR,
        PA | PFR,
        PFR | STA,
        PFR | PAU,
        PFR | FA,
        PFR | CON,
        ALL,
    ] {
        let built =
            DeviceEnergyManagement::<Esa>::conforming(bits, &Optional::NONE).expect("sized");
        let mut defects = Vec::new();
        spec.validate(&built.descriptor(), |defect| defects.push(defect));
        assert!(defects.is_empty(), "features {bits:#x}: {defects:?}");
    }
}

#[test]
fn each_feature_brings_exactly_its_own_commands() {
    // §9.2.4 splits flexibility into things an appliance may or may not physically offer:
    // "typically, appliances with a heating element cannot have their power consumption
    // adjusted and can only be paused or delayed". An EMS reads the feature map to know which
    // conversation it can have, so advertising a command the appliance cannot do wastes a
    // round trip and a decision.
    let plain = DeviceEnergyManagement::<Esa>::conforming(PFR, &Optional::NONE).expect("sized");
    assert_eq!(plain.descriptor().accepted_commands.len(), 0);

    let adjustable =
        DeviceEnergyManagement::<Esa>::conforming(PFR | PA, &Optional::NONE).expect("sized");
    assert_eq!(adjustable.descriptor().accepted_commands.len(), 2);

    let pausable =
        DeviceEnergyManagement::<Esa>::conforming(PFR | PAU, &Optional::NONE).expect("sized");
    assert_eq!(pausable.descriptor().accepted_commands.len(), 2);

    // `CancelRequest` is `STA | FA | CON` — it cancels whatever those three set.
    let delayable =
        DeviceEnergyManagement::<Esa>::conforming(PFR | STA, &Optional::NONE).expect("sized");
    assert_eq!(delayable.descriptor().accepted_commands.len(), 2);
}

#[test]
fn a_command_its_feature_does_not_permit_is_refused_by_the_handler_too() {
    // The descriptor already leaves the command out of `AcceptedCommandList`, so the server
    // refuses it first. This checks the handler's own answer, for a device assembled without
    // the derived descriptor — the feature map here and the one the descriptor came from are
    // two separate arguments, and they can be got out of step.
    let esa = Esa::default();
    let cluster = DeviceEnergyManagement::new(&esa, PFR);
    let full = DeviceEnergyManagement::<Esa>::conforming(ALL, &Optional::NONE).expect("sized");
    let clusters = [full.descriptor()];
    let endpoints = [Endpoint::new(1, &clusters)];
    let node = Node::new(&endpoints);

    for (command, fields) in [
        (
            dem::POWER_ADJUST_REQUEST,
            power_adjust(3_000_000, 300, LOCAL),
        ),
        (dem::PAUSE_REQUEST, two_fields(120, LOCAL)),
        (dem::START_TIME_ADJUST_REQUEST, two_fields(12_000, LOCAL)),
    ] {
        let resolved = node.resolve_command(1, dem::ID, command).expect("command");
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        let result = cluster.invoke(
            &resolved,
            Some(&fields),
            &InteractionContext::new().at(at(0)),
            &mut w,
            Tag::Anonymous,
        );
        assert_eq!(
            result.err().map(|e| e.status),
            Some(Status::UnsupportedCommand),
            "command {command:#x} ran without its feature"
        );
    }
    assert!(esa.adjusts.borrow().is_empty());
}

// --- The opt-out -----------------------------------------------------------------------------

#[test]
fn the_opt_out_is_per_reason_not_a_switch() {
    // §9.2.7.4: `LocalOptOut` is "opted out of local EMS optimizations only" and `GridOptOut`
    // is the mirror. Someone who has opted out of grid optimisation may still want their own
    // solar used, and a cluster that collapsed the two would take that away.
    let esa = Esa::default();
    let device = device(&esa, ALL);

    esa.opt_out.set(OptOutStateEnum::LocalOptOut);
    assert_eq!(
        invoke(
            &device,
            dem::POWER_ADJUST_REQUEST,
            Some(&power_adjust(3_000_000, 300, LOCAL)),
            at(0)
        ),
        Status::ConstraintError
    );
    assert_eq!(
        invoke(
            &device,
            dem::POWER_ADJUST_REQUEST,
            Some(&power_adjust(3_000_000, 300, GRID)),
            at(0)
        ),
        Status::Success
    );
    device.cluster.abort(CauseEnum::UserOptOut);
    device.cluster.take_events();

    esa.opt_out.set(OptOutStateEnum::GridOptOut);
    assert_eq!(
        invoke(
            &device,
            dem::POWER_ADJUST_REQUEST,
            Some(&power_adjust(3_000_000, 300, GRID)),
            at(0)
        ),
        Status::ConstraintError
    );
    assert_eq!(
        invoke(
            &device,
            dem::POWER_ADJUST_REQUEST,
            Some(&power_adjust(3_000_000, 300, LOCAL)),
            at(0)
        ),
        Status::Success
    );
    device.cluster.abort(CauseEnum::UserOptOut);
    device.cluster.take_events();

    esa.opt_out.set(OptOutStateEnum::OptOut);
    for cause in [LOCAL, GRID] {
        assert_eq!(
            invoke(
                &device,
                dem::POWER_ADJUST_REQUEST,
                Some(&power_adjust(3_000_000, 300, cause)),
                at(0)
            ),
            Status::ConstraintError
        );
    }
}

#[test]
fn the_opt_out_governs_every_adjusting_command() {
    // §9.2.9's commands each say "the OptOutState permits the specified AdjustmentCauseEnum".
    // A veto that only covered power adjustment would let an EMS delay the washing machine
    // instead, which is the same imposition by another route.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    esa.opt_out.set(OptOutStateEnum::OptOut);
    for (command, fields) in [
        (dem::START_TIME_ADJUST_REQUEST, two_fields(12_000, LOCAL)),
        (dem::PAUSE_REQUEST, two_fields(120, LOCAL)),
        (dem::MODIFY_FORECAST_REQUEST, modify_forecast(42, 1, LOCAL)),
        (
            dem::REQUEST_CONSTRAINT_BASED_FORECAST,
            constraints(1, LOCAL),
        ),
    ] {
        assert_eq!(
            invoke(&device, command, Some(&fields), at(0)),
            Status::ConstraintError,
            "command {command:#x} ignored the opt-out"
        );
    }
    assert!(esa.pauses.borrow().is_empty());
    assert!(esa.modifications.borrow().is_empty());
}

// --- PowerAdjustRequest ------------------------------------------------------------------------

#[test]
fn an_adjustment_within_the_advertised_range_is_accepted() {
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        invoke(
            &device,
            dem::POWER_ADJUST_REQUEST,
            Some(&power_adjust(3_000_000, 300, LOCAL)),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(device.cluster.state(), ESAStateEnum::PowerAdjustActive);
    assert_eq!(
        device.cluster.adjust_reason(),
        PowerAdjustReasonEnum::LocalOptimizationAdjustment
    );
    assert_eq!(*esa.adjusts.borrow(), vec![(3_000_000, 300, LOCAL)]);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::PowerAdjustStart]
    );

    // §9.2.9.1.4: "After the elapsed duration, the ESA SHALL revert to normal (or idle) power
    // levels ... with a cause code to indicate a 'Normal completion'."
    assert_eq!(device.cluster.wake_at(), Some(at(300)));
    device.cluster.poll(at(300));
    assert_eq!(device.cluster.state(), ESAStateEnum::Online);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::PowerAdjustEnd(CauseEnum::NormalCompletion)]
    );
    assert_eq!(*esa.ends.borrow(), vec![CauseEnum::NormalCompletion]);
}

#[test]
fn a_power_or_duration_outside_the_advertised_range_is_refused() {
    // §9.2.9.1.1: "This value SHALL be between the MinPower and MaxPower fields of the
    // PowerAdjustStruct in the PowerAdjustmentCapability attribute." The EMS is asking for
    // something the appliance has already said it cannot do.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    for (power, duration) in [
        (500_000, 300),
        (9_000_000, 300),
        (3_000_000, 5),
        (3_000_000, 7_200),
    ] {
        assert_eq!(
            invoke(
                &device,
                dem::POWER_ADJUST_REQUEST,
                Some(&power_adjust(power, duration, LOCAL)),
                at(0)
            ),
            Status::ConstraintError,
            "{power} mW for {duration} s was accepted"
        );
    }
    assert!(esa.adjusts.borrow().is_empty());
}

#[test]
fn an_appliance_that_is_not_online_refuses_an_adjustment() {
    // §9.2.9.1.4: "the ESAState is Online". An appliance in Fault cannot promise a power level.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    esa.base_state.set(ESAStateEnum::Fault);
    assert_eq!(
        invoke(
            &device,
            dem::POWER_ADJUST_REQUEST,
            Some(&power_adjust(3_000_000, 300, LOCAL)),
            at(0)
        ),
        Status::Failure
    );
    assert_eq!(device.cluster.state(), ESAStateEnum::Fault);
}

#[test]
fn overlapping_adjustments_emit_one_start_and_one_end() {
    // §9.2.9.1.4's worked example: "a battery inverter ESA may be sent a new request every 5
    // seconds ... Each command may have a 60 second duration, but this command is superseded
    // after 5 seconds by a new request." Twelve `PowerAdjustEnd` events a minute would push
    // everything else out of §7.14.2's fixed event ring.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    for tick in 0..12u64 {
        assert_eq!(
            invoke(
                &device,
                dem::POWER_ADJUST_REQUEST,
                Some(&power_adjust(3_000_000 + tick as i32 * 1_000, 60, LOCAL)),
                at(tick * 5)
            ),
            Status::Success
        );
        device.cluster.poll(at(tick * 5));
    }
    assert_eq!(esa.adjusts.borrow().len(), 12, "each was applied");
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::PowerAdjustStart],
        "a replacement emitted an event"
    );

    // Only the last one's duration ends it.
    device.cluster.poll(at(55 + 59));
    assert!(device.cluster.take_events().is_empty());
    device.cluster.poll(at(55 + 60));
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::PowerAdjustEnd(CauseEnum::NormalCompletion)]
    );
}

#[test]
fn an_appliance_that_will_not_be_interrupted_answers_busy() {
    // §9.2.9.1.4: "If the ESA does not permit this new PowerAdjustmentRequest command to
    // interrupt the adjustment that is in progress, it SHALL return BUSY." Distinct from
    // FAILURE, because the client should try again later rather than give up.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    invoke(
        &device,
        dem::POWER_ADJUST_REQUEST,
        Some(&power_adjust(3_000_000, 300, LOCAL)),
        at(0),
    );
    esa.may_interrupt.set(false);
    assert_eq!(
        invoke(
            &device,
            dem::POWER_ADJUST_REQUEST,
            Some(&power_adjust(4_000_000, 300, LOCAL)),
            at(5)
        ),
        Status::Busy
    );
    assert_eq!(esa.adjusts.borrow().len(), 1);
}

#[test]
fn cancelling_an_adjustment_that_is_not_running_is_invalid_in_state() {
    // §9.2.9.2.1: "If the ESAState is not PowerAdjustActive, then the command SHALL be rejected
    // with INVALID_IN_STATE."
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        invoke(&device, dem::CANCEL_POWER_ADJUST_REQUEST, None, at(0)),
        Status::InvalidInState
    );

    invoke(
        &device,
        dem::POWER_ADJUST_REQUEST,
        Some(&power_adjust(3_000_000, 300, LOCAL)),
        at(0),
    );
    device.cluster.take_events();
    assert_eq!(
        invoke(&device, dem::CANCEL_POWER_ADJUST_REQUEST, None, at(10)),
        Status::Success
    );
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::PowerAdjustEnd(CauseEnum::Cancelled)]
    );
    assert_eq!(device.cluster.state(), ESAStateEnum::Online);
    assert_eq!(device.cluster.wake_at(), None);
}

#[test]
fn a_user_opting_out_mid_adjustment_ends_it_with_the_right_cause() {
    // §9.2.9.1.4: "If during the power adjustment session a failure or other condition occurs
    // (such as the user deciding to opt-out by updating the OptOutState) then the ESA SHALL
    // generate a PowerAdjustEnd Event ... with the appropriate cause code." The cause is what
    // tells an EMS whether to try again in a minute or never.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    invoke(
        &device,
        dem::POWER_ADJUST_REQUEST,
        Some(&power_adjust(3_000_000, 3_600, LOCAL)),
        at(0),
    );
    device.cluster.take_events();

    esa.opt_out.set(OptOutStateEnum::OptOut);
    device.cluster.abort(CauseEnum::UserOptOut);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::PowerAdjustEnd(CauseEnum::UserOptOut)]
    );
    assert_eq!(device.cluster.state(), ESAStateEnum::Online);
}

// --- Pause and resume --------------------------------------------------------------------------

#[test]
fn a_pause_runs_for_its_duration_and_resumes_itself() {
    // §9.2.9.4.3: "When the Pause timer expires the ESA SHALL automatically resume operation.
    // When it does this, then it SHALL also generate a Resumed Event."
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        invoke(
            &device,
            dem::PAUSE_REQUEST,
            Some(&two_fields(300, LOCAL)),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(device.cluster.state(), ESAStateEnum::Paused);
    assert_eq!(device.cluster.take_events().as_slice(), &[Event::Paused]);
    assert_eq!(*esa.pauses.borrow(), vec![300]);

    device.cluster.poll(at(299));
    assert_eq!(device.cluster.state(), ESAStateEnum::Paused);
    device.cluster.poll(at(300));
    assert_eq!(device.cluster.state(), ESAStateEnum::Online);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::Resumed(CauseEnum::NormalCompletion)]
    );
    assert_eq!(esa.resumes.get(), 1);
}

#[test]
fn a_second_pause_extends_the_timer_rather_than_replacing_it() {
    // §9.2.9.4.3: "If the command is accepted the pause timer SHALL be extended by the new
    // Duration." Extended — a second request for two minutes on top of five must not shorten
    // the pause to two.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    invoke(
        &device,
        dem::PAUSE_REQUEST,
        Some(&two_fields(300, LOCAL)),
        at(0),
    );
    device.cluster.take_events();
    assert_eq!(
        invoke(
            &device,
            dem::PAUSE_REQUEST,
            Some(&two_fields(120, LOCAL)),
            at(10)
        ),
        Status::Success
    );
    // No second `Paused` event: the appliance never left the state.
    assert!(device.cluster.take_events().is_empty());
    device.cluster.poll(at(300));
    assert_eq!(
        device.cluster.state(),
        ESAStateEnum::Paused,
        "the timer was replaced"
    );
    device.cluster.poll(at(420));
    assert_eq!(device.cluster.state(), ESAStateEnum::Online);
}

#[test]
fn a_pause_outside_the_slots_range_is_refused() {
    // §9.2.9.4.3: "The ESA SHALL validate that the Duration field is within the range of
    // MinPauseDuration and MaxPauseDuration. If it is outside of this range then the command
    // SHALL be rejected with CONSTRAINT_ERROR."
    let esa = Esa::default();
    let device = device(&esa, ALL);
    for duration in [30u64, 900] {
        assert_eq!(
            invoke(
                &device,
                dem::PAUSE_REQUEST,
                Some(&two_fields(duration, LOCAL)),
                at(0)
            ),
            Status::ConstraintError,
            "{duration} s was accepted"
        );
    }
    assert!(esa.pauses.borrow().is_empty());
}

#[test]
fn an_unpausable_slot_refuses_with_failure_not_constraint_error() {
    // §9.2.9.4.3: "If the ESA SlotIsPausable field is false for the ActiveSlotNumber, then the
    // command SHALL be rejected with FAILURE." A spin cycle cannot be stopped half way; the
    // request was well formed, the appliance simply will not do it — which is a different
    // answer from "your numbers are wrong".
    let esa = Esa::default();
    let device = device(&esa, ALL);
    esa.with_forecast(|f| f.slot_is_pausable = false);
    assert_eq!(
        invoke(
            &device,
            dem::PAUSE_REQUEST,
            Some(&two_fields(300, LOCAL)),
            at(0)
        ),
        Status::Failure
    );
}

#[test]
fn resuming_when_not_paused_is_invalid_in_state() {
    // §9.2.9.5.1.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        invoke(&device, dem::RESUME_REQUEST, None, at(0)),
        Status::InvalidInState
    );

    invoke(
        &device,
        dem::PAUSE_REQUEST,
        Some(&two_fields(300, LOCAL)),
        at(0),
    );
    device.cluster.take_events();
    assert_eq!(
        invoke(&device, dem::RESUME_REQUEST, None, at(30)),
        Status::Success
    );
    assert_eq!(device.cluster.state(), ESAStateEnum::Online);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::Resumed(CauseEnum::Cancelled)]
    );
}

#[test]
fn a_fault_while_paused_is_reported_over_the_pause() {
    // §9.2.9.4.3: "If the ESA develops a fault whilst Paused, the ESAState SHALL be set to
    // Fault." A cluster that reported `Paused` over the top would hide it from the one client
    // that could do something about it.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    invoke(
        &device,
        dem::PAUSE_REQUEST,
        Some(&two_fields(300, LOCAL)),
        at(0),
    );
    esa.base_state.set(ESAStateEnum::Fault);
    assert_eq!(device.cluster.state(), ESAStateEnum::Fault);
    assert_eq!(
        read(&device, dem::ESA_STATE),
        i64::from(ESAStateEnum::Fault.value())
    );
}

// --- Forecast adjustment -----------------------------------------------------------------------

#[test]
fn a_start_time_outside_the_forecasts_window_is_refused() {
    // §9.2.9.3.1: "This value SHALL be after the EarliestStartTime in the Forecast attribute.
    // The new EndTime ... SHALL be before the LatestEndTime." A washing machine that finished
    // at four in the morning because an EMS moved it too late is the failure this prevents.
    let esa = Esa::default();
    let device = device(&esa, ALL);

    assert_eq!(
        invoke(
            &device,
            dem::START_TIME_ADJUST_REQUEST,
            Some(&two_fields(8_000, LOCAL)),
            at(0)
        ),
        Status::ConstraintError,
        "earlier than EarliestStartTime"
    );
    // The forecast runs 7 200 s; starting at 35 000 would end at 42 200, past LatestEndTime.
    assert_eq!(
        invoke(
            &device,
            dem::START_TIME_ADJUST_REQUEST,
            Some(&two_fields(35_000, LOCAL)),
            at(0)
        ),
        Status::ConstraintError,
        "ends after LatestEndTime"
    );

    assert_eq!(
        invoke(
            &device,
            dem::START_TIME_ADJUST_REQUEST,
            Some(&two_fields(20_000, LOCAL)),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(esa.forecast.get().unwrap().start_time, 20_000);
}

#[test]
fn a_stale_forecast_id_is_refused() {
    // §9.2.9.6.4: "otherwise if the ForecastID is valid ... SUCCESS, otherwise ... FAILURE."
    // A stale id means the EMS optimised a plan the appliance has already replaced, and
    // applying it would undo whatever replaced it.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        invoke(
            &device,
            dem::MODIFY_FORECAST_REQUEST,
            Some(&modify_forecast(41, 2, LOCAL)),
            at(0)
        ),
        Status::Failure
    );
    assert!(esa.modifications.borrow().is_empty());

    assert_eq!(
        invoke(
            &device,
            dem::MODIFY_FORECAST_REQUEST,
            Some(&modify_forecast(42, 2, LOCAL)),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(*esa.modifications.borrow(), vec![2]);
    // The appliance incremented its own id, so the same command a second time is now stale.
    assert_eq!(
        invoke(
            &device,
            dem::MODIFY_FORECAST_REQUEST,
            Some(&modify_forecast(42, 2, LOCAL)),
            at(0)
        ),
        Status::Failure
    );
}

#[test]
fn a_list_longer_than_ten_is_refused() {
    // §9.2.9.6's constraint on `SlotAdjustments` and §9.2.9.7's on `Constraints` are both
    // "max 10" — a bound on what a client may send, not on what this device happens to hold,
    // so it is CONSTRAINT_ERROR rather than RESOURCE_EXHAUSTED.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        invoke(
            &device,
            dem::MODIFY_FORECAST_REQUEST,
            Some(&modify_forecast(42, 11, LOCAL)),
            at(0)
        ),
        Status::ConstraintError
    );
    assert_eq!(
        invoke(
            &device,
            dem::REQUEST_CONSTRAINT_BASED_FORECAST,
            Some(&constraints(11, LOCAL)),
            at(0)
        ),
        Status::ConstraintError
    );
    assert_eq!(
        invoke(
            &device,
            dem::MODIFY_FORECAST_REQUEST,
            Some(&modify_forecast(42, 10, LOCAL)),
            at(0)
        ),
        Status::Success
    );
}

#[test]
fn a_constraint_based_forecast_reaches_the_appliance() {
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        invoke(
            &device,
            dem::REQUEST_CONSTRAINT_BASED_FORECAST,
            Some(&constraints(3, GRID)),
            at(0)
        ),
        Status::Success
    );
    assert_eq!(*esa.constraints.borrow(), vec![3]);
}

#[test]
fn cancelling_when_nothing_was_adjusted_is_invalid_in_state() {
    // §9.2.9.8.1: "If the ESA ForecastUpdateReason was already Internal Optimization, then the
    // command SHALL be rejected with INVALID_IN_STATE." There is nothing to cancel — the plan
    // is already the appliance's own.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        invoke(&device, dem::CANCEL_REQUEST, None, at(0)),
        Status::InvalidInState
    );

    invoke(
        &device,
        dem::MODIFY_FORECAST_REQUEST,
        Some(&modify_forecast(42, 1, LOCAL)),
        at(0),
    );
    assert_eq!(
        invoke(&device, dem::CANCEL_REQUEST, None, at(0)),
        Status::Success
    );
    assert_eq!(esa.cancels.get(), 1);
    // ...and once cancelled there is nothing to cancel again.
    assert_eq!(
        invoke(&device, dem::CANCEL_REQUEST, None, at(0)),
        Status::InvalidInState
    );
}

// --- Attributes ------------------------------------------------------------------------------

#[test]
fn the_power_adjustment_capability_carries_the_cluster_s_cause_and_the_devices_ranges() {
    // §9.2.9.1.4: "the PowerAdjustmentCapability attribute SHALL be updated to set the Cause
    // value from the Cause field of this command" — the cause belongs to the cluster, the
    // ranges to the appliance, and neither can write the other's half.
    let esa = Esa::default();
    let device = device(&esa, ALL);
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new(&mut buf);
    let resolved = device
        .node
        .resolve(1, dem::ID, dem::POWER_ADJUSTMENT_CAPABILITY)
        .expect("PowerAdjustmentCapability");
    device
        .cluster
        .read(
            &resolved,
            &InteractionContext::new(),
            &mut w,
            Tag::Anonymous,
        )
        .expect("read");
    let bytes = w.finish().unwrap().to_vec();
    assert!(
        bytes.len() > 4,
        "a capability with ranges should not encode as null"
    );

    invoke(
        &device,
        dem::POWER_ADJUST_REQUEST,
        Some(&power_adjust(3_000_000, 300, GRID)),
        at(0),
    );
    assert_eq!(
        device.cluster.adjust_reason(),
        PowerAdjustReasonEnum::GridOptimizationAdjustment
    );
}

#[test]
fn the_fixed_attributes_come_from_the_appliance() {
    let esa = Esa::default();
    let device = device(&esa, ALL);
    assert_eq!(
        read(&device, dem::ESA_TYPE),
        i64::from(ESATypeEnum::BatteryStorage.value())
    );
    assert_eq!(read(&device, dem::ABS_MAX_POWER), 7_000_000);
    assert_eq!(
        read(&device, dem::OPT_OUT_STATE),
        i64::from(OptOutStateEnum::NoOptOut.value())
    );
}
