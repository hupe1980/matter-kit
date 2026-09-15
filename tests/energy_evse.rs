//! Energy EVSE (Application Cluster §9.3), driven through the interaction model.
//!
//! A car is the largest controllable load in most houses and almost the only one that does not
//! care *when* it runs. Three rules make that safe rather than merely possible:
//!
//! * every enable has an **end** (§9.3.8.4), so a home energy manager that crashes leaves the
//!   car charging until its window runs out rather than for ever;
//! * charging and discharging are **two axes**, not three states (§9.3.9.2.4), so a charge
//!   window ending does not turn V2H off;
//! * a fault or an active self-diagnostic makes the EVSE **refuse** every enable (§9.3.9.2.4),
//!   because some J1772 faults can only be cleared by a person at the equipment.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::{Cell, RefCell};

use matter_kit::clusters::energy_evse::{
    self as evse, EnergyEvse, EnergyTransferStoppedReasonEnum, Event, EvseHooks, FaultStateEnum,
    StateEnum, SupplyStateEnum, TargetDayOfWeekBitmap,
};
use matter_kit::clusters::generated;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status,
};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

/// A wall box with a clock.
#[derive(Debug)]
struct WallBox {
    state: Cell<StateEnum>,
    fault: Cell<FaultStateEnum>,
    utc: Cell<Option<u32>>,
    user_maximum: Cell<i64>,
    diagnostics_ok: Cell<bool>,
    charge_limits: RefCell<Vec<(i64, i64)>>,
    discharge_limits: RefCell<Vec<i64>>,
    disables: Cell<usize>,
    target_changes: Cell<usize>,
}

impl Default for WallBox {
    fn default() -> Self {
        Self {
            state: Cell::new(StateEnum::NotPluggedIn),
            fault: Cell::new(FaultStateEnum::NoError),
            utc: Cell::new(Some(1_000)),
            user_maximum: Cell::new(0),
            diagnostics_ok: Cell::new(true),
            charge_limits: RefCell::new(Vec::new()),
            discharge_limits: RefCell::new(Vec::new()),
            disables: Cell::new(0),
            target_changes: Cell::new(0),
        }
    }
}

impl EvseHooks for WallBox {
    fn state(&self) -> Option<StateEnum> {
        Some(self.state.get())
    }

    fn fault(&self) -> FaultStateEnum {
        self.fault.get()
    }

    fn utc(&self) -> Option<u32> {
        self.utc.get()
    }

    fn circuit_capacity(&self) -> i64 {
        32_000
    }

    fn user_maximum_charge_current(&self) -> i64 {
        self.user_maximum.get()
    }

    fn session_id(&self) -> Option<u32> {
        Some(7)
    }

    fn session_duration(&self) -> Option<u32> {
        Some(1_234)
    }

    fn session_energy_charged(&self) -> Option<i64> {
        Some(9_500_000)
    }

    fn disable(&self) -> bool {
        self.disables.set(self.disables.get() + 1);
        true
    }

    fn enable_charging(&self, minimum_ma: i64, maximum_ma: i64) -> bool {
        self.charge_limits
            .borrow_mut()
            .push((minimum_ma, maximum_ma));
        true
    }

    fn enable_discharging(&self, maximum_ma: i64) -> bool {
        self.discharge_limits.borrow_mut().push(maximum_ma);
        true
    }

    fn start_diagnostics(&self) -> bool {
        self.diagnostics_ok.get()
    }

    fn targets_changed(&self) {
        self.target_changes.set(self.target_changes.get() + 1);
    }
}

const V2X: u32 = evse::feature::V2_X;
const PREF: u32 = evse::feature::CHARGING_PREFERENCES;

type Evse<'a> = EnergyEvse<'a, WallBox, 4>;

struct Device<'a> {
    node: Node<'a>,
    cluster: Evse<'a>,
}

fn device(box_: &WallBox, feature_map: u32) -> Device<'_> {
    let conforming = Box::leak(Box::new(
        Evse::conforming(feature_map, &Evse::WITH_ALL_OPTIONAL).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: EnergyEvse::new(box_, feature_map),
    }
}

/// What a command produced: a status, or a decoded `GetTargetsResponse`.
#[derive(Debug, PartialEq)]
enum Answer {
    Status(Status),
    /// `(day bitmap, target minutes)` per schedule, in the order the response listed them.
    Targets(Vec<(u8, Vec<u16>)>),
}

fn invoke(device: &Device<'_>, command: u32, fields: Option<&[u8]>) -> Answer {
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(1, evse::ID, command))
    };
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 4096];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    // §9.3.9's whole command table is `OT` — Operate *and Timed*. See
    // `every_command_needs_a_timed_transaction` for why that matters.
    let ctx = InteractionContext::new().timed();
    let (bytes, _) = server
        .serve_invoke([Ok(data)], &ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    match responses.next().expect("one response").expect("decode") {
        InvokeResponse::Status(status) => Answer::Status(status.status.status),
        InvokeResponse::Command(command) => {
            Answer::Targets(decode_targets(command.fields.expect("fields")))
        }
    }
}

fn decode_targets(fields: &[u8]) -> Vec<(u8, Vec<u16>)> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Structure));
    let array = reader.next_element().unwrap().unwrap();
    assert_eq!(array.value.container(), Some(ContainerKind::Array));
    let mut out = Vec::new();
    loop {
        let schedule = reader.next_element().unwrap().unwrap();
        if schedule.value == Value::EndOfContainer {
            break;
        }
        let mut days = 0u8;
        let mut minutes = Vec::new();
        loop {
            let field = reader.next_element().unwrap().unwrap();
            if field.value == Value::EndOfContainer {
                break;
            }
            match (field.tag.context(), &field.value) {
                (Some(0), Value::Unsigned(value)) => days = *value as u8,
                (Some(1), _) => loop {
                    let target = reader.next_element().unwrap().unwrap();
                    if target.value == Value::EndOfContainer {
                        break;
                    }
                    loop {
                        let inner = reader.next_element().unwrap().unwrap();
                        if inner.value == Value::EndOfContainer {
                            break;
                        }
                        if let (Some(0), Value::Unsigned(value)) =
                            (inner.tag.context(), &inner.value)
                        {
                            minutes.push(*value as u16);
                        } else {
                            reader.skip_value(&inner).unwrap();
                        }
                    }
                },
                _ => reader.skip_value(&field).unwrap(),
            }
        }
        out.push((days, minutes));
    }
    // Consume the outer end-of-container so a malformed response would be caught.
    let end = reader.next_element().unwrap().unwrap();
    assert_eq!(end.value, Value::EndOfContainer);
    out
}

fn enable_charging(until: Option<u32>, minimum: i32, maximum: i32) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    match until {
        Some(value) => w.unsigned(Tag::Context(0), u64::from(value)).unwrap(),
        None => w.null(Tag::Context(0)).unwrap(),
    }
    w.signed(Tag::Context(1), i64::from(minimum)).unwrap();
    w.signed(Tag::Context(2), i64::from(maximum)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn enable_discharging(until: Option<u32>, maximum: i32) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    match until {
        Some(value) => w.unsigned(Tag::Context(0), u64::from(value)).unwrap(),
        None => w.null(Tag::Context(0)).unwrap(),
    }
    w.signed(Tag::Context(1), i64::from(maximum)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// One day's worth of `(minutes past midnight, target SoC)` pairs.
type DayPlan = (u8, Vec<(u16, Option<u8>)>);

/// `SetTargets` from `(days, targets)` pairs.
fn set_targets(schedules: &[DayPlan]) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.start_array(Tag::Context(0)).unwrap();
    for (days, targets) in schedules {
        w.start_structure(Tag::Anonymous).unwrap();
        w.unsigned(Tag::Context(0), u64::from(*days)).unwrap();
        w.start_array(Tag::Context(1)).unwrap();
        for (minutes, soc) in targets {
            w.start_structure(Tag::Anonymous).unwrap();
            w.unsigned(Tag::Context(0), u64::from(*minutes)).unwrap();
            if let Some(soc) = soc {
                w.unsigned(Tag::Context(1), u64::from(*soc)).unwrap();
            }
            w.end_container().unwrap();
        }
        w.end_container().unwrap();
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn read(device: &Device<'_>, attribute: u32) -> i64 {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    let resolved = device
        .node
        .resolve(1, evse::ID, attribute)
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
    let element = reader.next_element().unwrap().unwrap();
    match element.value {
        Value::Unsigned(value) => value as i64,
        Value::Signed(value) => value,
        other => panic!("not a number: {other:?}"),
    }
}

const MONDAY: u8 = 0b0000_0010;
const TUESDAY: u8 = 0b0000_0100;
const SATURDAY: u8 = 0b0100_0000;

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_cluster_matches_the_specification_for_every_feature_combination() {
    let spec = generated::find(evse::ID).expect("Energy EVSE");
    for bits in [
        0,
        PREF,
        V2X,
        PREF | V2X,
        PREF | V2X | evse::feature::SO_C_REPORTING,
        PREF | V2X | evse::feature::SO_C_REPORTING | evse::feature::PLUG_AND_CHARGE,
    ] {
        for optional in [Optional::NONE, Evse::WITH_ALL_OPTIONAL] {
            let built = Evse::conforming(bits, &optional).expect("sized");
            let mut defects = Vec::new();
            spec.validate(&built.descriptor(), |defect| defects.push(defect));
            assert!(defects.is_empty(), "features {bits:#x}: {defects:?}");
        }
    }
}

#[test]
fn the_v2x_feature_brings_the_discharge_attributes_and_command() {
    // §9.3.8's table: `DischargingEnabledUntil`, `MaximumDischargeCurrent` and
    // `SessionEnergyDischarged` are all V2X, and so is `EnableDischarging`. A wall box without
    // the feature must not advertise the command — a client would be asking a one-way charger
    // to run the house off the car.
    let plain = Evse::conforming(0, &Optional::NONE).expect("sized");
    let v2x = Evse::conforming(V2X, &Optional::NONE).expect("sized");
    assert!(
        plain
            .descriptor()
            .accepted_commands
            .iter()
            .all(|c| c.id != evse::ENABLE_DISCHARGING)
    );
    assert!(
        v2x.descriptor()
            .accepted_commands
            .iter()
            .any(|c| c.id == evse::ENABLE_DISCHARGING)
    );
    assert_eq!(
        v2x.descriptor().attributes.len(),
        plain.descriptor().attributes.len() + 3
    );
}

#[test]
fn every_command_needs_a_timed_transaction() {
    // §9.3.9's access column is `OT` for every single command: Operate *and Timed*. §8.7.4's
    // Timed transaction is what stops a command being replayed or arriving late — and "late"
    // here means a car that starts charging at six in the evening because an `EnableCharging`
    // meant for two in the morning was delayed. A cluster whose commands all move energy is
    // exactly the case the quality exists for.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    let fields = enable_charging(None, 6_000, 32_000);
    let data = CommandData {
        fields: Some(&fields),
        ..CommandData::new(CommandPath::command(1, evse::ID, evse::ENABLE_CHARGING))
    };
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 4096];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let (bytes, _) = server
        .serve_invoke(
            [Ok(data)],
            &InteractionContext::new(),
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    match responses.next().unwrap().unwrap() {
        InvokeResponse::Status(status) => {
            assert_eq!(status.status.status, Status::NeedsTimedInteraction);
        }
        InvokeResponse::Command(_) => panic!("an untimed command was executed"),
    }
    assert!(
        wall.charge_limits.borrow().is_empty(),
        "an untimed EnableCharging reached the hardware"
    );
}

// --- Enable and disable ------------------------------------------------------------------------

#[test]
fn an_evse_starts_disabled() {
    // §9.3.8.2's safe starting point: an EVSE that came up enabled would start passing current
    // after a power cut without anybody asking it to.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(device.cluster.supply_state(), SupplyStateEnum::Disabled);
    assert_eq!(device.cluster.charging_enabled_until(), Some(0));
}

#[test]
fn enabling_charging_stores_the_window_and_the_limits() {
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_CHARGING,
            Some(&enable_charging(Some(5_000), 6_000, 32_000))
        ),
        Answer::Status(Status::Success)
    );
    assert_eq!(
        device.cluster.supply_state(),
        SupplyStateEnum::ChargingEnabled
    );
    assert_eq!(device.cluster.charging_enabled_until(), Some(5_000));
    assert_eq!(*wall.charge_limits.borrow(), vec![(6_000, 32_000)]);
    assert_eq!(read(&device, evse::MINIMUM_CHARGE_CURRENT), 6_000);
    assert_eq!(read(&device, evse::MAXIMUM_CHARGE_CURRENT), 32_000);
}

#[test]
fn a_null_window_enables_charging_indefinitely() {
    // §9.3.9.2.1: "A value in the past in this field SHALL disable the EVSE charging whereas a
    // null value SHALL enable it permanently."
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(None, 6_000, 32_000)),
    );
    assert_eq!(
        device.cluster.supply_state(),
        SupplyStateEnum::ChargingEnabled
    );
    wall.utc.set(Some(u32::MAX));
    device.cluster.poll();
    assert_eq!(
        device.cluster.supply_state(),
        SupplyStateEnum::ChargingEnabled
    );
}

#[test]
fn a_window_already_in_the_past_enables_nothing() {
    // The same sentence's other half. A client that computes a window from a stale clock must
    // not accidentally leave the car charging.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    wall.utc.set(Some(9_000));
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(Some(5_000), 6_000, 32_000)),
    );
    assert_eq!(device.cluster.supply_state(), SupplyStateEnum::Disabled);
}

#[test]
fn a_charge_window_expiring_leaves_discharging_alone() {
    // §9.3.9.2.4: "when this time expires then the EVSE SHALL ... update the SupplyState
    // attribute to Disabled (if DischargingEnabledUntil is also in the past) or
    // DischargingEnabled (if DischargingEnabledUntil is in the future or null)."
    //
    // Charging and discharging are two axes. A device that treated SupplyState as one mode
    // would turn vehicle-to-home off every time a charge window ended.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(Some(2_000), 6_000, 32_000)),
    );
    invoke(
        &device,
        evse::ENABLE_DISCHARGING,
        Some(&enable_discharging(None, 16_000)),
    );
    assert_eq!(device.cluster.supply_state(), SupplyStateEnum::Enabled);

    wall.utc.set(Some(2_500));
    device.cluster.poll();
    assert_eq!(
        device.cluster.supply_state(),
        SupplyStateEnum::DischargingEnabled,
        "the charge window's end took discharging with it"
    );
}

#[test]
fn both_windows_expiring_disables_the_supply() {
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(Some(2_000), 6_000, 32_000)),
    );
    invoke(
        &device,
        evse::ENABLE_DISCHARGING,
        Some(&enable_discharging(Some(3_000), 16_000)),
    );
    wall.utc.set(Some(3_500));
    wall.state.set(StateEnum::PluggedInCharging);
    device.cluster.poll();
    assert_eq!(device.cluster.supply_state(), SupplyStateEnum::Disabled);
    // Current was flowing, so a client reading the event log can see that it was the EVSE's
    // decision to stop rather than the car's.
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::EnergyTransferStopped(
            EnergyTransferStoppedReasonEnum::EVSEStopped
        )]
    );
}

#[test]
fn disable_zeroes_both_windows_and_reports_the_stop() {
    // §9.3.9.1.1: "the ChargingEnabledUntil and DischargingEnabledUntil attributes SHALL be set
    // to 0x0" — zero, not null, because null means *always* enabled and would re-enable the
    // EVSE on the next reboot.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(None, 6_000, 32_000)),
    );
    wall.state.set(StateEnum::PluggedInCharging);

    assert_eq!(
        invoke(&device, evse::DISABLE, None),
        Answer::Status(Status::Success)
    );
    assert_eq!(device.cluster.supply_state(), SupplyStateEnum::Disabled);
    assert_eq!(device.cluster.charging_enabled_until(), Some(0));
    assert_eq!(device.cluster.discharging_enabled_until(), Some(0));
    assert_eq!(wall.disables.get(), 1);
    assert_eq!(
        device.cluster.take_events().as_slice(),
        &[Event::EnergyTransferStopped(
            EnergyTransferStoppedReasonEnum::EVSEStopped
        )]
    );
}

#[test]
fn disabling_an_already_disabled_evse_succeeds_and_reports_no_stop() {
    // §9.3.9.1.1: "If the SupplyState attribute is already Disabled, a response with status of
    // SUCCESS SHALL be returned."
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(
        invoke(&device, evse::DISABLE, None),
        Answer::Status(Status::Success)
    );
    assert!(
        device.cluster.take_events().is_empty(),
        "a stop was reported with nothing flowing"
    );
}

#[test]
fn the_enable_windows_survive_a_reboot() {
    // §9.3.8.4: "This attribute SHALL be persisted, for example a temporary power failure
    // should not stop the vehicle from being charged." The device stores them; this cluster
    // puts SupplyState back where the two windows say it belongs.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    device.cluster.start(Some(9_000), None);
    assert_eq!(device.cluster.supply_state(), SupplyStateEnum::Enabled);
    assert_eq!(device.cluster.charging_enabled_until(), Some(9_000));
}

// --- Faults and diagnostics --------------------------------------------------------------------

#[test]
fn a_fault_outranks_everything_and_refuses_every_enable() {
    // §9.3.8.3: "When the SupplyState attribute is DisabledError, the FaultState attribute will
    // be one of the values listed in FaultStateEnum, except NoError." And §9.3.9.2.4: "If there
    // is currently an error present on the EVSE ... the command SHALL be ignored and a response
    // with a status of FAILURE SHALL be returned."
    //
    // §9.3 says why the network cannot clear it: some J1772 faults "may require clearing by an
    // operator by, for example, pressing a button on the equipment or breaker panel".
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    wall.fault.set(FaultStateEnum::GroundFault);
    assert_eq!(
        device.cluster.supply_state(),
        SupplyStateEnum::DisabledError
    );
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_CHARGING,
            Some(&enable_charging(None, 6_000, 32_000))
        ),
        Answer::Status(Status::Failure)
    );
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_DISCHARGING,
            Some(&enable_discharging(None, 16_000))
        ),
        Answer::Status(Status::Failure)
    );
    assert!(wall.charge_limits.borrow().is_empty());

    // Once the operator clears it, the EVSE takes commands again.
    wall.fault.set(FaultStateEnum::NoError);
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_CHARGING,
            Some(&enable_charging(None, 6_000, 32_000))
        ),
        Answer::Status(Status::Success)
    );
}

#[test]
fn diagnostics_run_only_from_disabled_and_block_enables_while_running() {
    // §9.3.9.4.1: "the EVSE SHALL enter a Diagnostics state only if the SupplyState attribute
    // is in the Disabled state" — running self-checks on a circuit passing current to a car is
    // not a thing to do.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(None, 6_000, 32_000)),
    );
    assert_eq!(
        invoke(&device, evse::START_DIAGNOSTICS, None),
        Answer::Status(Status::Failure)
    );

    invoke(&device, evse::DISABLE, None);
    assert_eq!(
        invoke(&device, evse::START_DIAGNOSTICS, None),
        Answer::Status(Status::Success)
    );
    assert_eq!(
        device.cluster.supply_state(),
        SupplyStateEnum::DisabledDiagnostics
    );

    // "Diagnostics are currently active, then the command SHALL be ignored".
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_CHARGING,
            Some(&enable_charging(None, 6_000, 32_000))
        ),
        Answer::Status(Status::Failure)
    );

    // "Upon completion of the diagnostics, the EVSE SHALL restore SupplyState to the Disabled
    // state" — the EVSE says when, because only it knows how long its checks take.
    device.cluster.diagnostics_complete();
    assert_eq!(device.cluster.supply_state(), SupplyStateEnum::Disabled);
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_CHARGING,
            Some(&enable_charging(None, 6_000, 32_000))
        ),
        Answer::Status(Status::Success)
    );
}

// --- Currents ------------------------------------------------------------------------------

#[test]
fn the_user_limit_can_only_lower_the_commanded_one() {
    // §9.3.9.2.3: "if the UserMaximumChargeCurrent attribute is adjusted below then this value,
    // and then later adjusted above this value, the resulting MaximumChargeCurrent attribute
    // will be limited to this value." A user cannot raise a ceiling an installer set — the
    // circuit does not care who asked.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(None, 6_000, 16_000)),
    );
    assert_eq!(read(&device, evse::MAXIMUM_CHARGE_CURRENT), 16_000);

    wall.user_maximum.set(10_000);
    assert_eq!(read(&device, evse::MAXIMUM_CHARGE_CURRENT), 10_000);

    wall.user_maximum.set(32_000);
    assert_eq!(
        read(&device, evse::MAXIMUM_CHARGE_CURRENT),
        16_000,
        "the user raised a ceiling the command set"
    );
}

#[test]
fn a_negative_or_inverted_current_is_refused() {
    // §9.3.9.2's constraint on both fields is "min 0", and a minimum above the maximum is a
    // window with nothing in it — the EVSE could satisfy neither bound.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_CHARGING,
            Some(&enable_charging(None, -1, 32_000))
        ),
        Answer::Status(Status::ConstraintError)
    );
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_CHARGING,
            Some(&enable_charging(None, 32_000, 6_000))
        ),
        Answer::Status(Status::ConstraintError)
    );
    assert_eq!(
        invoke(
            &device,
            evse::ENABLE_DISCHARGING,
            Some(&enable_discharging(None, -5))
        ),
        Answer::Status(Status::ConstraintError)
    );
    assert!(wall.charge_limits.borrow().is_empty());
}

// --- Charging targets -------------------------------------------------------------------------

#[test]
fn targets_are_stored_per_day_and_read_back() {
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(
        invoke(
            &device,
            evse::SET_TARGETS,
            Some(&set_targets(&[
                (MONDAY | TUESDAY, vec![(360, Some(80))]),
                (SATURDAY, vec![(600, None), (1_410, Some(100))]),
            ]))
        ),
        Answer::Status(Status::Success)
    );
    assert_eq!(wall.target_changes.get(), 1);

    // §9.3.9.7: one schedule per day that has targets, in day order; a day with none is
    // omitted, because an empty schedule is how `SetTargets` *clears* a day.
    assert_eq!(
        invoke(&device, evse::GET_TARGETS, None),
        Answer::Targets(vec![
            (MONDAY, vec![360]),
            (TUESDAY, vec![360]),
            (SATURDAY, vec![600, 1_410]),
        ])
    );
}

#[test]
fn set_targets_replaces_one_day_and_leaves_the_others() {
    // §9.3.9.5.2's worked example: "if the EVSE has 2 charging targets for every day of the
    // week and is sent a SetTargets command with one target for Saturday then the EVSE SHALL
    // remove both charging targets for Saturday and replace those with the updated charging
    // target but leave all other days unchanged."
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::SET_TARGETS,
        Some(&set_targets(&[(
            0b0111_1111,
            vec![(360, Some(80)), (1_200, Some(90))],
        )])),
    );
    invoke(
        &device,
        evse::SET_TARGETS,
        Some(&set_targets(&[(SATURDAY, vec![(480, Some(100))])])),
    );
    let Answer::Targets(targets) = invoke(&device, evse::GET_TARGETS, None) else {
        panic!("expected a response");
    };
    assert_eq!(targets.len(), 7);
    assert_eq!(targets[1], (MONDAY, vec![360, 1_200]), "Monday changed");
    assert_eq!(targets[6], (SATURDAY, vec![480]), "Saturday did not");
}

#[test]
fn an_empty_schedule_clears_that_days_targets() {
    // §9.3.9.5.2: "If a ChargingTargetSchedule is defined with no ChargingTargets then the
    // ChargingTargets are cleared for those days defined in the DayOfWeekForSequence."
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::SET_TARGETS,
        Some(&set_targets(&[(MONDAY | SATURDAY, vec![(360, Some(80))])])),
    );
    invoke(
        &device,
        evse::SET_TARGETS,
        Some(&set_targets(&[(MONDAY, vec![])])),
    );
    assert_eq!(
        invoke(&device, evse::GET_TARGETS, None),
        Answer::Targets(vec![(SATURDAY, vec![360])])
    );
    assert!(
        device
            .cluster
            .targets_for(TargetDayOfWeekBitmap::MONDAY)
            .is_empty()
    );
}

#[test]
fn a_day_in_two_schedules_is_refused() {
    // §9.3.9.5.2: "each day of the week is included in at most one of the ChargingTargetSchedule,
    // if they are not then the response SHALL be CONSTRAINT_ERROR." Two schedules claiming
    // Tuesday is a request with no single meaning.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(
        invoke(
            &device,
            evse::SET_TARGETS,
            Some(&set_targets(&[
                (MONDAY | TUESDAY, vec![(360, Some(80))]),
                (TUESDAY, vec![(600, Some(90))]),
            ]))
        ),
        Answer::Status(Status::ConstraintError)
    );
    // ...and nothing was stored: a half-applied schedule is worse than a refused one.
    assert_eq!(
        invoke(&device, evse::GET_TARGETS, None),
        Answer::Targets(vec![])
    );
    assert_eq!(wall.target_changes.get(), 0);
}

#[test]
fn a_target_outside_the_day_is_refused() {
    // §9.3.7.6's constraint is "max 1439" — one minute short of twenty-four hours, because
    // 1440 is midnight the *next* day and would silently mean "tomorrow".
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(
        invoke(
            &device,
            evse::SET_TARGETS,
            Some(&set_targets(&[(MONDAY, vec![(1_440, None)])]))
        ),
        Answer::Status(Status::ConstraintError)
    );
    assert_eq!(
        invoke(
            &device,
            evse::SET_TARGETS,
            Some(&set_targets(&[(MONDAY, vec![(1_439, None)])]))
        ),
        Answer::Status(Status::Success)
    );
}

#[test]
fn a_target_soc_above_a_hundred_is_refused() {
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(
        invoke(
            &device,
            evse::SET_TARGETS,
            Some(&set_targets(&[(MONDAY, vec![(360, Some(101))])]))
        ),
        Answer::Status(Status::ConstraintError)
    );
}

#[test]
fn more_targets_than_the_device_holds_is_resource_exhausted() {
    // §9.3.9.5.2: "When a command is received that requires a total number of charging targets
    // greater than the device supports, the status of the response SHALL be
    // RESOURCE_EXHAUSTED" — a distinct answer from CONSTRAINT_ERROR, because the client's
    // request was well formed and the device simply cannot hold it.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    let many: Vec<(u16, Option<u8>)> = (0..5).map(|n| (n * 60, Some(80))).collect();
    assert_eq!(
        invoke(
            &device,
            evse::SET_TARGETS,
            Some(&set_targets(&[(MONDAY, many)]))
        ),
        Answer::Status(Status::ResourceExhausted)
    );
}

#[test]
fn clear_targets_empties_every_day() {
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    invoke(
        &device,
        evse::SET_TARGETS,
        Some(&set_targets(&[(0b0111_1111, vec![(360, Some(80))])])),
    );
    assert_eq!(
        invoke(&device, evse::CLEAR_TARGETS, None),
        Answer::Status(Status::Success)
    );
    assert_eq!(
        invoke(&device, evse::GET_TARGETS, None),
        Answer::Targets(vec![])
    );
}

// --- Attributes ------------------------------------------------------------------------------

#[test]
fn the_session_attributes_come_from_the_hardware() {
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    assert_eq!(read(&device, evse::SESSION_ID), 7);
    assert_eq!(read(&device, evse::SESSION_DURATION), 1_234);
    assert_eq!(read(&device, evse::SESSION_ENERGY_CHARGED), 9_500_000);
    assert_eq!(read(&device, evse::CIRCUIT_CAPACITY), 32_000);
    assert_eq!(
        read(&device, evse::STATE),
        i64::from(StateEnum::NotPluggedIn.value())
    );
}

#[test]
fn an_evse_with_no_clock_never_expires_a_window_by_itself() {
    // A monotonic clock cannot compare `epoch-s` timestamps. Guessing would either cut a charge
    // short or run one past the hour the user was quoted, so an EVSE whose clock has never been
    // set leaves the window the client opened open.
    let wall = WallBox::default();
    let device = device(&wall, PREF | V2X);
    wall.utc.set(None);
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(Some(5_000), 6_000, 32_000)),
    );
    assert_eq!(
        device.cluster.supply_state(),
        SupplyStateEnum::ChargingEnabled
    );
    device.cluster.poll();
    assert_eq!(
        device.cluster.supply_state(),
        SupplyStateEnum::ChargingEnabled
    );

    // ...but an explicit zero still disables, because that is not a comparison.
    invoke(
        &device,
        evse::ENABLE_CHARGING,
        Some(&enable_charging(Some(0), 6_000, 32_000)),
    );
    assert_eq!(device.cluster.supply_state(), SupplyStateEnum::Disabled);
}
