//! The energy clusters, assembled into the device types an energy manager talks to.
//!
//! §9.2.5 is the reason this file exists rather than three separate ones:
//!
//! > This cluster does not report electrical power and electrical energy. Devices that use this
//! > cluster SHALL also support the Electrical Power Measurement and optionally support the
//! > Electrical Energy Measurement cluster to allow an energy management system to perform its
//! > role.
//!
//! Device Energy Management negotiates; the measurement clusters answer "did it work?"; the
//! appliance cluster does the thing. None of the three is usable alone, and the device-type
//! library is where that is written down.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::Cell;

use matter_kit::clusters::device_energy_management::{
    DemHooks, DeviceEnergyManagement, ESAStateEnum, ESATypeEnum,
};
use matter_kit::clusters::electrical_measurement::{
    ElectricalEnergyMeasurement, ElectricalPowerMeasurement, EnergyMeterHooks, PowerMeterHooks,
    PowerTopology, energy, power, topology,
};
use matter_kit::clusters::energy_evse::{self as evse, EnergyEvse, EvseHooks, StateEnum};
use matter_kit::clusters::generated::device_types::{ELECTRICAL_SENSOR, ENERGY_EVSE};
use matter_kit::clusters::generated::{energy_evse_mode, water_heater_mode};
use matter_kit::clusters::mode::{Mode, ModeHooks, ModeOptionStruct, status};
use matter_kit::clusters::water_heater_management::{
    WaterHeaterBoostInfoStruct, WaterHeaterHeatSourceBitmap, WaterHeaterHooks,
};
use matter_kit::clusters::{At, Endpoints, descriptor, validate_endpoint};
use matter_kit::dm::device::DeviceType as Spec;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, DeviceType, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status,
};
use matter_kit::tlv::{ContainerKind, Tag, TlvList, TlvReader, TlvWriter, Value};

// --- One appliance implementing everything ----------------------------------------------------

#[derive(Debug, Default)]
struct Appliance {
    active_power: Cell<Option<i64>>,
    mode: Cell<u8>,
    refuse_mode: Cell<bool>,
}

impl PowerMeterHooks for Appliance {
    fn accuracy(&self) -> &[power::MeasurementAccuracyStruct<'_>] {
        // One measurement type: active power, ±2% across the whole range. §2.13.5.3 makes this
        // mandatory because a clamp meter's 15 W reading is not the same number as a shunt's.
        const ACCURACY: &[power::MeasurementAccuracyStruct<'static>] =
            &[power::MeasurementAccuracyStruct {
                measurement_type: power::MeasurementTypeEnum::ActivePower,
                measured: true,
                min_measured_value: 0,
                max_measured_value: 7_000_000,
                accuracy_ranges: TlvList::from_members(&[]),
            }];
        ACCURACY
    }

    fn active_power(&self) -> Option<i64> {
        self.active_power.get()
    }
}

impl EnergyMeterHooks for Appliance {
    fn accuracy(&self) -> energy::MeasurementAccuracyStruct<'_> {
        energy::MeasurementAccuracyStruct {
            measurement_type: matter_kit::clusters::generated::electrical_energy_measurement::MeasurementTypeEnum::ElectricalEnergy,
            measured: true,
            min_measured_value: 0,
            max_measured_value: i64::MAX,
            accuracy_ranges: TlvList::from_members(&[]),
        }
    }

    fn cumulative_imported(&self) -> Option<energy::EnergyMeasurementStruct> {
        Some(energy::EnergyMeasurementStruct {
            energy: 12_345_000,
            start_timestamp: None,
            end_timestamp: Some(50_000),
            start_systime: None,
            end_systime: None,
            apparent_energy: None,
            reactive_energy: None,
        })
    }
}

impl DemHooks for Appliance {
    fn esa_type(&self) -> ESATypeEnum {
        ESATypeEnum::EVSE
    }

    fn base_state(&self) -> ESAStateEnum {
        ESAStateEnum::Online
    }

    fn abs_min_power(&self) -> i64 {
        0
    }

    fn abs_max_power(&self) -> i64 {
        7_000_000
    }
}

impl EvseHooks for Appliance {
    fn state(&self) -> Option<StateEnum> {
        Some(StateEnum::PluggedInCharging)
    }

    fn circuit_capacity(&self) -> i64 {
        32_000
    }

    fn session_id(&self) -> Option<u32> {
        Some(1)
    }

    fn session_duration(&self) -> Option<u32> {
        Some(0)
    }

    fn session_energy_charged(&self) -> Option<i64> {
        Some(0)
    }

    fn enable_charging(&self, _minimum_ma: i64, _maximum_ma: i64) -> bool {
        true
    }
}

impl WaterHeaterHooks for Appliance {
    fn heat_demand(&self) -> WaterHeaterHeatSourceBitmap {
        WaterHeaterHeatSourceBitmap::empty()
    }

    fn boost(&self, _info: &WaterHeaterBoostInfoStruct) -> Result<(), Status> {
        Ok(())
    }
}

impl ModeHooks for Appliance {
    fn change_to(&self, mode: u8) -> Result<(), (u8, &'static str)> {
        if self.refuse_mode.get() {
            // §1.10.7.1.1: "Have the Status set to a product-specific Status value representing
            // the error, or GenericFailure ... Provide a human readable string in the StatusText
            // field."
            return Err((status::GENERIC_FAILURE, "a vehicle is charging"));
        }
        self.mode.set(mode);
        Ok(())
    }
}

/// §9.4.5's Energy EVSE Mode tags: Manual is 0x4000, Time of Use 0x4001.
const EVSE_MODES: &[ModeOptionStruct<'static>] = &[
    ModeOptionStruct {
        label: "Manual",
        mode: 0,
        mode_tags: TlvList::from_members(&[]),
    },
    ModeOptionStruct {
        label: "Time of Use",
        mode: 1,
        // Distinct from the first by tag as well as by label and mode — §1.10.6.1 demands all
        // three, and the encoded members are one ModeTagStruct with `Value` = 0x4001.
        mode_tags: TlvList::from_members(&[0x15, 0x25, 0x01, 0x01, 0x40, 0x18]),
    },
];

// --- The device types -------------------------------------------------------------------------

fn defects(endpoint: &Endpoint<'_>, device_type: &Spec) -> Vec<String> {
    let mut found = Vec::new();
    validate_endpoint(endpoint, device_type, |defect| {
        found.push(format!("{defect:?}"));
    });
    found
}

#[test]
fn an_energy_evse_endpoint_is_furnished_from_these_clusters() {
    // §4.3's Energy EVSE device type: the EVSE cluster and its Mode cluster, both mandatory.
    // This is the shape `hems-drv/matter` talks to.
    let evse_d = EnergyEvse::<Appliance, 10>::conforming(
        evse::feature::CHARGING_PREFERENCES,
        &EnergyEvse::<Appliance, 10>::WITH_ALL_OPTIONAL,
    )
    .expect("sized");
    let mode_d = Mode::<Appliance, { energy_evse_mode::ID }>::conforming(
        &energy_evse_mode::CLUSTER,
        0,
        &Optional::NONE,
    )
    .expect("sized");
    let clusters = [
        descriptor::cluster(), // 0x001D
        evse_d.descriptor(),   // 0x0099
        mode_d.descriptor(),   // 0x009D
    ];
    let claimed = [DeviceType::new(ENERGY_EVSE.id, ENERGY_EVSE.revision)];
    let endpoint = Endpoint::new(1, &clusters).with_device_types(&claimed);
    assert_eq!(defects(&endpoint, &ENERGY_EVSE), Vec::<String>::new());

    // Without the Mode cluster it is not an Energy EVSE: a controller with no way to put the
    // charger into Time-of-Use mode cannot use the tariff it was installed for.
    let bare = [descriptor::cluster(), evse_d.descriptor()];
    let endpoint = Endpoint::new(1, &bare);
    assert!(
        defects(&endpoint, &ENERGY_EVSE)
            .iter()
            .any(|d| d.contains(&format!("{}", energy_evse_mode::ID))),
        "the missing Mode cluster went unreported"
    );
}

#[test]
fn an_electrical_sensor_endpoint_is_furnished_from_these_clusters() {
    // §2.x's Electrical Sensor: Power Topology is mandatory and the two measurement clusters
    // are optional — a meter that cannot say *what* it is measuring is a number with no scope.
    let topology_d = PowerTopology::conforming(topology::feature::NODE_TOPOLOGY, &Optional::NONE)
        .expect("sized");
    let power_d = ElectricalPowerMeasurement::<Appliance>::conforming(
        power::feature::ALTERNATING_CURRENT,
        &ElectricalPowerMeasurement::<Appliance>::WITH_BASIC_READINGS,
    )
    .expect("sized");
    let energy_d = ElectricalEnergyMeasurement::<Appliance>::conforming(
        energy::feature::IMPORTED_ENERGY | energy::feature::CUMULATIVE_ENERGY,
        &Optional::NONE,
    )
    .expect("sized");
    let clusters = [
        power_d.descriptor(),    // 0x0090
        energy_d.descriptor(),   // 0x0091
        topology_d.descriptor(), // 0x009C
        descriptor::cluster(),   // 0x001D
    ];
    let mut sorted = clusters;
    sorted.sort_by_key(|c| c.id);
    let claimed = [DeviceType::new(
        ELECTRICAL_SENSOR.id,
        ELECTRICAL_SENSOR.revision,
    )];
    let endpoint = Endpoint::new(2, &sorted).with_device_types(&claimed);
    assert_eq!(defects(&endpoint, &ELECTRICAL_SENSOR), Vec::<String>::new());

    // Power Topology is the mandatory one.
    let without = [power_d.descriptor(), descriptor::cluster()];
    let mut sorted = without;
    sorted.sort_by_key(|c| c.id);
    let endpoint = Endpoint::new(2, &sorted);
    assert!(
        defects(&endpoint, &ELECTRICAL_SENSOR)
            .iter()
            .any(|d| d.contains(&format!("{}", topology::ID))),
        "a meter with no scope passed as an Electrical Sensor"
    );
}

// --- Mode Base --------------------------------------------------------------------------------

#[test]
fn one_mode_implementation_serves_every_derived_cluster() {
    // §1.10 is a *shape*, not a cluster: about fifteen clusters in the library are "derived
    // from the Mode Base cluster and define additional mode tags". They differ in their id,
    // their PICS code and their tags — and in nothing else, which is why one implementation
    // does for all of them.
    let appliance = Appliance::default();
    let evse_mode = Mode::<Appliance, { energy_evse_mode::ID }>::new(
        &energy_evse_mode::CLUSTER,
        &appliance,
        EVSE_MODES,
        0,
    )
    .expect("valid");
    let water_mode = Mode::<Appliance, { water_heater_mode::ID }>::new(
        &water_heater_mode::CLUSTER,
        &appliance,
        EVSE_MODES,
        0,
    )
    .expect("valid");

    // Two different *types*, so a tuple dispatches to each by its own id — which matters for an
    // endpoint that has both.
    use matter_kit::clusters::Cluster;
    assert_eq!(
        <Mode<Appliance, { energy_evse_mode::ID }> as Cluster>::ID,
        0x009D
    );
    assert_eq!(
        <Mode<Appliance, { water_heater_mode::ID }> as Cluster>::ID,
        0x009E
    );
    assert_eq!(evse_mode.spec().pics, "EEVSEM");
    assert_eq!(water_mode.spec().pics, "WHM");
}

#[test]
fn a_mode_table_that_breaks_the_uniqueness_rules_is_refused() {
    // §1.10.6.1: every `Mode` unique, every `Label` unique, and every *set* of mode tags
    // distinct. A device that shipped two modes a controller could not tell apart would leave
    // the user picking between two identical entries in a list.
    let appliance = Appliance::default();
    const SAME_MODE: &[ModeOptionStruct<'static>] = &[
        ModeOptionStruct {
            label: "A",
            mode: 0,
            mode_tags: TlvList::from_members(&[]),
        },
        ModeOptionStruct {
            label: "B",
            mode: 0,
            mode_tags: TlvList::from_members(&[]),
        },
    ];
    const SAME_LABEL: &[ModeOptionStruct<'static>] = &[
        ModeOptionStruct {
            label: "A",
            mode: 0,
            mode_tags: TlvList::from_members(&[]),
        },
        ModeOptionStruct {
            label: "A",
            mode: 1,
            mode_tags: TlvList::from_members(&[]),
        },
    ];
    // Both empty, so the sets are equal — which §1.10.6.1 forbids even though the labels and
    // modes differ.
    const SAME_TAGS: &[ModeOptionStruct<'static>] = &[
        ModeOptionStruct {
            label: "A",
            mode: 0,
            mode_tags: TlvList::from_members(&[]),
        },
        ModeOptionStruct {
            label: "B",
            mode: 1,
            mode_tags: TlvList::from_members(&[]),
        },
    ];
    const ONE_MODE: &[ModeOptionStruct<'static>] = &[ModeOptionStruct {
        label: "A",
        mode: 0,
        mode_tags: TlvList::from_members(&[]),
    }];

    for (name, table) in [
        ("a repeated Mode", SAME_MODE),
        ("a repeated Label", SAME_LABEL),
        ("an identical tag set", SAME_TAGS),
        ("only one mode", ONE_MODE),
    ] {
        assert!(
            Mode::<Appliance, { energy_evse_mode::ID }>::new(
                &energy_evse_mode::CLUSTER,
                &appliance,
                table,
                0,
            )
            .is_err(),
            "{name} was accepted"
        );
    }

    // And the right table is accepted.
    assert!(
        Mode::<Appliance, { energy_evse_mode::ID }>::new(
            &energy_evse_mode::CLUSTER,
            &appliance,
            EVSE_MODES,
            0,
        )
        .is_ok()
    );
}

#[test]
fn a_mode_cluster_built_over_the_wrong_table_is_refused() {
    // The id and the table are two separate arguments, and a device that crossed them would
    // answer one cluster's paths with another's elements — silently, because both are valid
    // Mode Base tables.
    let appliance = Appliance::default();
    assert!(
        Mode::<Appliance, { energy_evse_mode::ID }>::new(
            &water_heater_mode::CLUSTER,
            &appliance,
            EVSE_MODES,
            0,
        )
        .is_err()
    );
}

#[test]
fn a_current_mode_the_table_does_not_list_is_refused() {
    // §1.10.6.2: "The value of this field SHALL match the Mode field of one of the entries in
    // the SupportedModes attribute." A device that came up in a mode it does not have would
    // report one a client cannot select or reason about.
    let appliance = Appliance::default();
    assert!(
        Mode::<Appliance, { energy_evse_mode::ID }>::new(
            &energy_evse_mode::CLUSTER,
            &appliance,
            EVSE_MODES,
            9,
        )
        .is_err()
    );
}

// --- ChangeToMode -------------------------------------------------------------------------------

struct ModeDevice<'a> {
    node: Node<'a>,
    cluster: Mode<'a, Appliance, { energy_evse_mode::ID }>,
}

fn mode_device(appliance: &Appliance) -> ModeDevice<'_> {
    let conforming = Box::leak(Box::new(
        Mode::<Appliance, { energy_evse_mode::ID }>::conforming(
            &energy_evse_mode::CLUSTER,
            0,
            &Mode::<Appliance, { energy_evse_mode::ID }>::WITH_START_UP_MODE,
        )
        .expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    ModeDevice {
        node: Node::new(endpoints),
        cluster: Mode::new(&energy_evse_mode::CLUSTER, appliance, EVSE_MODES, 0).expect("valid"),
    }
}

/// Invokes `ChangeToMode` and decodes the response's `(status, text)`.
fn change_to(device: &ModeDevice<'_>, new_mode: u8) -> (u8, String) {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(new_mode)).unwrap();
    w.end_container().unwrap();
    let fields = w.finish().unwrap().to_vec();

    let data = CommandData {
        fields: Some(&fields),
        ..CommandData::new(CommandPath::command(
            1,
            energy_evse_mode::ID,
            matter_kit::clusters::mode::CHANGE_TO_MODE,
        ))
    };
    let mut scratch = [0u8; 512];
    let mut out = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let (bytes, _) = server
        .serve_invoke(
            [Ok(data)],
            &InteractionContext::new(),
            false,
            &mut scratch,
            &mut out,
        )
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    let InvokeResponse::Command(command) = responses.next().unwrap().unwrap() else {
        panic!("ChangeToMode always answers with ChangeToModeResponse");
    };
    let mut reader = TlvReader::new_in(command.fields.expect("fields"), ContainerKind::Structure);
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Structure));
    let (mut code, mut text) = (0u8, String::new());
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        match (field.tag.context(), &field.value) {
            (Some(0), Value::Unsigned(value)) => code = *value as u8,
            (Some(1), Value::Utf8(value)) => text = (*value).to_string(),
            _ => reader.skip_value(&field).unwrap(),
        }
    }
    (code, text)
}

#[test]
fn an_unsupported_mode_is_reported_inside_the_response_not_as_a_status() {
    // §1.10.7.1.1: the status goes in the *response command*, with a `StatusText` a person can
    // read. An IM-level failure would lose the text — and the text is what tells a user why
    // their dishwasher would not switch to Heavy.
    let appliance = Appliance::default();
    let device = mode_device(&appliance);
    let (code, text) = change_to(&device, 9);
    assert_eq!(code, status::UNSUPPORTED_MODE);
    assert!(!text.is_empty(), "no StatusText for an unsupported mode");
    assert_eq!(device.cluster.current(), 0, "the mode changed anyway");
}

#[test]
fn a_mode_the_device_will_not_enter_carries_its_reason() {
    let appliance = Appliance::default();
    let device = mode_device(&appliance);
    appliance.refuse_mode.set(true);
    let (code, text) = change_to(&device, 1);
    assert_eq!(code, status::GENERIC_FAILURE);
    assert_eq!(text, "a vehicle is charging");
    assert_eq!(device.cluster.current(), 0);

    appliance.refuse_mode.set(false);
    let (code, _) = change_to(&device, 1);
    assert_eq!(code, status::SUCCESS);
    assert_eq!(device.cluster.current(), 1);
    assert_eq!(appliance.mode.get(), 1);
}

#[test]
fn changing_to_the_mode_already_current_succeeds_without_troubling_the_device() {
    // §1.10.7.1.1: "If the NewMode field is the same as the value of the CurrentMode attribute
    // the ChangeToModeResponse command SHALL have the Status field set to Success." Not a
    // transition — and a dishwasher asked to re-enter the cycle it is running should not
    // restart it.
    let appliance = Appliance::default();
    let device = mode_device(&appliance);
    appliance.refuse_mode.set(true);
    let (code, _) = change_to(&device, 0);
    assert_eq!(code, status::SUCCESS, "a no-op transition was refused");
    assert_eq!(appliance.mode.get(), 0);
}

#[test]
fn the_startup_mode_is_applied_at_power_up() {
    // §1.10.6.3: "If this attribute is not null, the CurrentMode attribute SHALL be set to the
    // StartUpMode value, when the server is powered up."
    let appliance = Appliance::default();
    let device = mode_device(&appliance);
    device
        .cluster
        .set_start_up_mode(Some(1))
        .expect("a listed mode");
    device.cluster.start(false);
    assert_eq!(device.cluster.current(), 1);

    // A mode the table does not list is refused, so the device cannot come up stuck.
    assert_eq!(
        device.cluster.set_start_up_mode(Some(9)),
        Err(Status::ConstraintError)
    );
    assert_eq!(device.cluster.start_up_mode(), Some(1));
}

#[test]
fn on_mode_moves_the_mode_only_when_the_light_turns_on() {
    // §1.10.6.4's table has four rows and only `OFF → ON` changes anything. A device that also
    // acted on `ON → ON` would jump out of whatever mode the user just chose every time an
    // `On` command was re-sent — which for a groupcast is every time anybody turns the room on.
    let appliance = Appliance::default();
    let device = mode_device(&appliance);
    device.cluster.set_on_mode(Some(1)).expect("a listed mode");

    device.cluster.on_off_changed(true, true);
    assert_eq!(device.cluster.current(), 0, "ON → ON changed the mode");
    device.cluster.on_off_changed(false, false);
    assert_eq!(device.cluster.current(), 0, "OFF → OFF changed the mode");
    device.cluster.on_off_changed(true, false);
    assert_eq!(device.cluster.current(), 0, "ON → OFF changed the mode");

    device.cluster.on_off_changed(false, true);
    assert_eq!(device.cluster.current(), 1);
}

#[test]
fn current_mode_is_not_writable() {
    // §1.10.6.2's access is `RV`. A client changes the mode with `ChangeToMode`, which is the
    // only path that can refuse with a reason a person can read.
    let appliance = Appliance::default();
    let device = mode_device(&appliance);
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.unsigned(Tag::Context(2), 1).unwrap();
    let data = w.finish().unwrap().to_vec();
    let resolved = device
        .node
        .resolve(
            1,
            energy_evse_mode::ID,
            matter_kit::clusters::mode::CURRENT_MODE,
        )
        .expect("CurrentMode");
    assert_eq!(
        device.cluster.write(
            &resolved,
            &data,
            matter_kit::im::WriteOp::Replace,
            &InteractionContext::new()
        ),
        Err(Status::UnsupportedWrite)
    );
}

// --- Power Topology ---------------------------------------------------------------------------

#[test]
fn an_active_endpoint_must_be_one_the_meter_declared() {
    // §2.14 makes the active set a subset of the available one. A meter that claimed to be
    // measuring an endpoint it had never declared would be reporting somebody else's power —
    // and an EMS balancing a house on that would be balancing it against the wrong circuit.
    const AVAILABLE: &[u16] = &[2, 3, 4];
    let topology = PowerTopology::new(AVAILABLE);
    assert_eq!(topology.active(), AVAILABLE);

    assert_eq!(topology.set_active(&[3, 4]), Ok(()));
    assert_eq!(topology.active(), &[3, 4]);

    assert_eq!(topology.set_active(&[5]), Err(Status::ConstraintError));
    assert_eq!(
        topology.active(),
        &[3, 4],
        "a refused set was applied anyway"
    );
}

// --- The whole assembly -------------------------------------------------------------------------

#[test]
fn an_evse_node_answers_on_every_endpoint_it_claims() {
    // The shape `hems-drv/matter` will see: endpoint 1 is the charger, endpoint 2 is its meter,
    // and they serve different clusters. Routing by endpoint is what makes that expressible.
    let appliance = Appliance::default();
    appliance.active_power.set(Some(6_900_000));

    let evse_d = EnergyEvse::<Appliance, 10>::conforming(0, &Optional::NONE).expect("sized");
    let mode_d = Mode::<Appliance, { energy_evse_mode::ID }>::conforming(
        &energy_evse_mode::CLUSTER,
        0,
        &Optional::NONE,
    )
    .expect("sized");
    let dem_d = DeviceEnergyManagement::<Appliance>::conforming(0, &Optional::NONE).expect("sized");
    let power_d =
        ElectricalPowerMeasurement::<Appliance>::conforming(0, &Optional::NONE).expect("sized");
    let topology_d = PowerTopology::conforming(topology::feature::NODE_TOPOLOGY, &Optional::NONE)
        .expect("sized");

    let charger = [
        descriptor::cluster(), // 0x001D
        dem_d.descriptor(),    // 0x0098
        evse_d.descriptor(),   // 0x0099
        mode_d.descriptor(),   // 0x009D
    ];
    let meter = [
        power_d.descriptor(),    // 0x0090
        descriptor::cluster(),   // 0x001D
        topology_d.descriptor(), // 0x009C
    ];
    let mut meter_sorted = meter;
    meter_sorted.sort_by_key(|c| c.id);
    let endpoints = [
        Endpoint::new(0, &charger[..1]),
        Endpoint::new(1, &charger),
        Endpoint::new(2, &meter_sorted),
    ];
    let node = Node::new(&endpoints);
    node.validate().expect("sorted by id");

    let evse_cluster: EnergyEvse<'_, Appliance, 10> = EnergyEvse::new(&appliance, 0);
    let dem_cluster = DeviceEnergyManagement::new(&appliance, 0);
    let mode_cluster = Mode::<Appliance, { energy_evse_mode::ID }>::new(
        &energy_evse_mode::CLUSTER,
        &appliance,
        EVSE_MODES,
        0,
    )
    .expect("valid");
    let power_cluster = ElectricalPowerMeasurement::new(&appliance);
    let topology_cluster = PowerTopology::new(&[]);

    let handler = Endpoints((
        At::new(
            0,
            (descriptor::Descriptor::new(node, 0).with_parts(&[1, 2]),),
        ),
        At::new(
            1,
            (
                descriptor::Descriptor::new(node, 1),
                &dem_cluster,
                &evse_cluster,
                &mode_cluster,
            ),
        ),
        At::new(
            2,
            (
                &power_cluster,
                descriptor::Descriptor::new(node, 2),
                &topology_cluster,
            ),
        ),
    ));
    let access = AllowAll;
    let server = Server::new(node, &access, &handler, 16);

    // The charger's state comes from endpoint 1...
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 4096];
    let ctx = InteractionContext::new().with_fabric(matter_kit::msg::FabricIndex(1));
    let (bytes, _) = server
        .serve(
            [Ok(matter_kit::im::AttributePath::attribute(
                1,
                evse::ID,
                evse::STATE,
            ))],
            &ctx,
            None,
            &mut scratch,
            &mut buf,
        )
        .expect("read");
    assert!(!bytes.is_empty());

    // ...and the power from endpoint 2, which serves a cluster endpoint 1 does not.
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 4096];
    let (bytes, _) = server
        .serve(
            [Ok(matter_kit::im::AttributePath::attribute(
                2,
                power::ID,
                power::ACTIVE_POWER,
            ))],
            &ctx,
            None,
            &mut scratch,
            &mut buf,
        )
        .expect("read");
    let text = format!("{}", matter_kit::tlv::Pretty(bytes));
    assert!(
        text.contains("6900000"),
        "the meter's reading was not served: {text}"
    );
}
