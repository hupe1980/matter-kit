//! Electrical Power Measurement (`0x0090`, §2.13) and Electrical Energy Measurement
//! (`0x0091`, §2.12) — what an appliance is drawing, and what it has drawn.
//!
//! Neither cluster has a command. They exist so that an energy manager can *see*, and §9.2.5
//! makes them a dependency of the cluster that acts:
//!
//! > This cluster does not report electrical power and electrical energy. Devices that use this
//! > cluster SHALL also support the Electrical Power Measurement and optionally support the
//! > Electrical Energy Measurement cluster to allow an energy management system to perform its
//! > role.
//!
//! So [`device_energy_management`](crate::clusters::device_energy_management) negotiates and
//! these two answer "did it work?".
//!
//! # Null is the honest reading
//!
//! Every measured value here is nullable, and the specification means it: a meter that has not
//! taken a reading yet, or whose sensor has failed, reports null rather than zero. Zero is a
//! measurement — it says the appliance is drawing nothing — and an energy manager that could
//! not tell the two apart would balance a house against a number nobody measured. That is why
//! every hook returns `Option`.
//!
//! # Accuracy is mandatory, and it is not decoration
//!
//! §2.13.5.3 makes `Accuracy` a mandatory list. A current-transformer clamp is worth ±2% above
//! a couple of amps and nearly nothing below; an EMS that treated a 15 W reading from one as
//! exact would chase noise all evening. The struct is the appliance's honest statement of what
//! its numbers are worth.

use crate::clusters::generated::electrical_energy_measurement as spec_energy;
use crate::clusters::generated::electrical_power_measurement as spec_power;
use crate::clusters::generated::power_topology as spec_topology;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::Cluster;

/// Electrical Power Measurement, cluster `0x0090`.
pub mod power {
    pub use super::spec_power::attribute::{
        ACCURACY, ACTIVE_CURRENT, ACTIVE_POWER, APPARENT_CURRENT, APPARENT_POWER, FREQUENCY,
        HARMONIC_CURRENTS, HARMONIC_PHASES, NEUTRAL_CURRENT, NUMBER_OF_MEASUREMENT_TYPES,
        POWER_FACTOR, POWER_MODE, RANGES, REACTIVE_CURRENT, REACTIVE_POWER, RMS_CURRENT, RMS_POWER,
        RMS_VOLTAGE, VOLTAGE,
    };
    pub use super::spec_power::event::MEASUREMENT_PERIOD_RANGES;
    pub use super::spec_power::{
        HarmonicMeasurementStruct, ID, MeasurementAccuracyRangeStruct, MeasurementAccuracyStruct,
        MeasurementRangeStruct, MeasurementTypeEnum, PICS, PowerModeEnum, REVISION, feature,
    };
}

/// Electrical Energy Measurement, cluster `0x0091`.
pub mod energy {
    pub use super::spec_energy::attribute::{
        ACCURACY, CUMULATIVE_ENERGY_EXPORTED, CUMULATIVE_ENERGY_IMPORTED, CUMULATIVE_ENERGY_RESET,
        PERIODIC_ENERGY_EXPORTED, PERIODIC_ENERGY_IMPORTED,
    };
    pub use super::spec_energy::event::{CUMULATIVE_ENERGY_MEASURED, PERIODIC_ENERGY_MEASURED};
    pub use super::spec_energy::{
        CumulativeEnergyResetStruct, EnergyMeasurementStruct, ID, MeasurementAccuracyStruct, PICS,
        REVISION, feature,
    };
}

/// What the meter reads.
///
/// Every value is an `Option`, and `None` is §7.19's null rather than zero — "the meter has no
/// reading" and "the appliance is drawing nothing" are different facts, and an energy manager
/// that confused them would balance a house against a number nobody measured.
pub trait PowerMeterHooks {
    /// `PowerMode` (§2.13.5.1) — AC, DC, or unknown.
    fn power_mode(&self) -> power::PowerModeEnum {
        power::PowerModeEnum::Unknown
    }

    /// `Accuracy` (§2.13.5.3) — what each measurement is worth.
    ///
    /// Mandatory, and `NumberOfMeasurementTypes` is derived from its length so the two cannot
    /// disagree: §2.13.5.2 defines that attribute as "the number of measurement types this
    /// server provides", which is exactly this list.
    fn accuracy(&self) -> &[power::MeasurementAccuracyStruct<'_>];

    /// `Ranges` (§2.13.5.4) — the extremes seen over the measurement period.
    fn ranges(&self) -> &[power::MeasurementRangeStruct] {
        &[]
    }

    /// `Voltage`, in mV.
    fn voltage(&self) -> Option<i64> {
        None
    }

    /// `ActiveCurrent`, in mA.
    fn active_current(&self) -> Option<i64> {
        None
    }

    /// `ReactiveCurrent`, in mA — the `ALTC` feature.
    fn reactive_current(&self) -> Option<i64> {
        None
    }

    /// `ApparentCurrent`, in mA.
    fn apparent_current(&self) -> Option<i64> {
        None
    }

    /// `ActivePower`, in mW — the one mandatory measurement, and the one an EMS acts on.
    ///
    /// Signed: an appliance that generates reports a negative power, which is how a solar
    /// inverter and a battery discharging are told apart from a load.
    fn active_power(&self) -> Option<i64>;

    /// `ReactivePower`, in mVAR.
    fn reactive_power(&self) -> Option<i64> {
        None
    }

    /// `ApparentPower`, in mVA.
    fn apparent_power(&self) -> Option<i64> {
        None
    }

    /// `RMSVoltage`, in mV.
    fn rms_voltage(&self) -> Option<i64> {
        None
    }

    /// `RMSCurrent`, in mA.
    fn rms_current(&self) -> Option<i64> {
        None
    }

    /// `RMSPower`, in mW.
    fn rms_power(&self) -> Option<i64> {
        None
    }

    /// `Frequency`, in mHz.
    fn frequency(&self) -> Option<i64> {
        None
    }

    /// `PowerFactor`, in hundredths of a percent.
    fn power_factor(&self) -> Option<i64> {
        None
    }

    /// `NeutralCurrent`, in mA — the `POLY` feature's imbalance reading.
    fn neutral_current(&self) -> Option<i64> {
        None
    }

    /// `HarmonicCurrents` and `HarmonicPhases` — the `HARM` and `PWRQ` features.
    fn harmonic_currents(&self) -> &[power::HarmonicMeasurementStruct] {
        &[]
    }

    /// `HarmonicPhases`.
    fn harmonic_phases(&self) -> &[power::HarmonicMeasurementStruct] {
        &[]
    }
}

/// Electrical Power Measurement over a meter.
#[derive(Debug)]
pub struct ElectricalPowerMeasurement<'a, H: PowerMeterHooks> {
    hooks: &'a H,
}

impl<'a, H: PowerMeterHooks> ElectricalPowerMeasurement<'a, H> {
    /// A cluster over `hooks`.
    #[must_use]
    pub const fn new(hooks: &'a H) -> Self {
        Self { hooks }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<19, 0, 0, 1>> {
        Conforming::new(&spec_power::CLUSTER, feature_map, optional)
    }

    /// The measurements a meter with a voltage and a current sensor can offer.
    pub const WITH_BASIC_READINGS: Optional<'static> = Optional {
        attributes: &[
            power::RANGES,
            power::VOLTAGE,
            power::ACTIVE_CURRENT,
            power::APPARENT_CURRENT,
        ],
        commands: &[],
        events: &[],
    };
}

impl<H: PowerMeterHooks> ClusterHandler for ElectricalPowerMeasurement<'_, H> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let measured = |w: &mut TlvWriter<'_>, value: Option<i64>| match value {
            Some(value) => full(w.signed(tag, value)),
            None => full(w.null(tag)),
        };
        let list = |w: &mut TlvWriter<'_>, items: &[power::HarmonicMeasurementStruct]| {
            full(w.start_array(tag))?;
            for item in items {
                full(item.to_tlv(w, Tag::Anonymous))?;
            }
            full(w.end_container())
        };
        match resolved.attribute {
            power::POWER_MODE => full(w.unsigned(tag, u64::from(self.hooks.power_mode().value()))),
            // §2.13.5.2 defines this as the length of `Accuracy`, so it is derived rather than
            // reported: a meter cannot claim a count its own accuracy list does not support.
            power::NUMBER_OF_MEASUREMENT_TYPES => full(w.unsigned(
                tag,
                u64::try_from(self.hooks.accuracy().len()).unwrap_or(u64::MAX),
            )),
            power::ACCURACY => {
                full(w.start_array(tag))?;
                for entry in self.hooks.accuracy() {
                    full(entry.to_tlv(w, Tag::Anonymous))?;
                }
                full(w.end_container())
            }
            power::RANGES => {
                full(w.start_array(tag))?;
                for entry in self.hooks.ranges() {
                    full(entry.to_tlv(w, Tag::Anonymous))?;
                }
                full(w.end_container())
            }
            power::VOLTAGE => measured(w, self.hooks.voltage()),
            power::ACTIVE_CURRENT => measured(w, self.hooks.active_current()),
            power::REACTIVE_CURRENT => measured(w, self.hooks.reactive_current()),
            power::APPARENT_CURRENT => measured(w, self.hooks.apparent_current()),
            power::ACTIVE_POWER => measured(w, self.hooks.active_power()),
            power::REACTIVE_POWER => measured(w, self.hooks.reactive_power()),
            power::APPARENT_POWER => measured(w, self.hooks.apparent_power()),
            power::RMS_VOLTAGE => measured(w, self.hooks.rms_voltage()),
            power::RMS_CURRENT => measured(w, self.hooks.rms_current()),
            power::RMS_POWER => measured(w, self.hooks.rms_power()),
            power::FREQUENCY => measured(w, self.hooks.frequency()),
            power::POWER_FACTOR => measured(w, self.hooks.power_factor()),
            power::NEUTRAL_CURRENT => measured(w, self.hooks.neutral_current()),
            power::HARMONIC_CURRENTS => list(w, self.hooks.harmonic_currents()),
            power::HARMONIC_PHASES => list(w, self.hooks.harmonic_phases()),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        _resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        // §2.13 defines no commands at all: this cluster only ever answers.
        Err(Status::UnsupportedCommand.into())
    }
}

impl<H: PowerMeterHooks> Cluster for ElectricalPowerMeasurement<'_, H> {
    const ID: ClusterId = power::ID;
}

/// What the energy meter has totalled.
pub trait EnergyMeterHooks {
    /// `Accuracy` (§2.12.6.1) — mandatory, the same argument as the power meter's.
    fn accuracy(&self) -> energy::MeasurementAccuracyStruct<'_>;

    /// `CumulativeEnergyImported`, in mWh — the `IMPE` and `CUME` features together.
    fn cumulative_imported(&self) -> Option<energy::EnergyMeasurementStruct> {
        None
    }

    /// `CumulativeEnergyExported` — `EXPE` and `CUME`.
    fn cumulative_exported(&self) -> Option<energy::EnergyMeasurementStruct> {
        None
    }

    /// `PeriodicEnergyImported` — `IMPE` and `PERE`.
    ///
    /// The reading an EMS actually uses moment to moment: a cumulative total says what the
    /// meter has ever seen, and the difference between two of them is arithmetic the client
    /// has to get right across a reset. This one carries its own window.
    fn periodic_imported(&self) -> Option<energy::EnergyMeasurementStruct> {
        None
    }

    /// `PeriodicEnergyExported` — `EXPE` and `PERE`.
    fn periodic_exported(&self) -> Option<energy::EnergyMeasurementStruct> {
        None
    }

    /// `CumulativeEnergyReset` (§2.12.6.6) — when the totals were last zeroed.
    ///
    /// Without it a client cannot tell a meter that has counted nothing from one that was
    /// reset a second ago, and would read the next sample as a vast negative.
    fn cumulative_reset(&self) -> Option<energy::CumulativeEnergyResetStruct> {
        None
    }
}

/// Electrical Energy Measurement over a meter.
#[derive(Debug)]
pub struct ElectricalEnergyMeasurement<'a, H: EnergyMeterHooks> {
    hooks: &'a H,
}

impl<'a, H: EnergyMeterHooks> ElectricalEnergyMeasurement<'a, H> {
    /// A cluster over `hooks`.
    #[must_use]
    pub const fn new(hooks: &'a H) -> Self {
        Self { hooks }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<6, 0, 0, 2>> {
        Conforming::new(&spec_energy::CLUSTER, feature_map, optional)
    }
}

impl<H: EnergyMeterHooks> ClusterHandler for ElectricalEnergyMeasurement<'_, H> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let reading =
            |w: &mut TlvWriter<'_>, value: Option<energy::EnergyMeasurementStruct>| match value {
                Some(value) => full(value.to_tlv(w, tag)),
                None => full(w.null(tag)),
            };
        match resolved.attribute {
            energy::ACCURACY => full(self.hooks.accuracy().to_tlv(w, tag)),
            energy::CUMULATIVE_ENERGY_IMPORTED => reading(w, self.hooks.cumulative_imported()),
            energy::CUMULATIVE_ENERGY_EXPORTED => reading(w, self.hooks.cumulative_exported()),
            energy::PERIODIC_ENERGY_IMPORTED => reading(w, self.hooks.periodic_imported()),
            energy::PERIODIC_ENERGY_EXPORTED => reading(w, self.hooks.periodic_exported()),
            energy::CUMULATIVE_ENERGY_RESET => match self.hooks.cumulative_reset() {
                Some(reset) => full(reset.to_tlv(w, tag)),
                None => full(w.null(tag)),
            },
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        _resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        Err(Status::UnsupportedCommand.into())
    }
}

impl<H: EnergyMeterHooks> Cluster for ElectricalEnergyMeasurement<'_, H> {
    const ID: ClusterId = energy::ID;
}

// --- Power Topology --------------------------------------------------------------------------

/// Power Topology, cluster `0x009C` (§2.14).
pub mod topology {
    pub use super::spec_topology::attribute::{ACTIVE_ENDPOINTS, AVAILABLE_ENDPOINTS};
    pub use super::spec_topology::{ID, PICS, REVISION, feature};
}

/// Power Topology — *what* the meter on this endpoint is measuring.
///
/// A measurement without a scope is a number with no meaning: 400 W could be the whole house,
/// one socket, or a circuit. §2.14's four features are the four answers, and they are mutually
/// exclusive by construction:
///
/// * `NODE` — "this endpoint provides or consumes power to/from the entire node";
/// * `TREE` — "itself and its child endpoints", which is the `PartsList` a bridge already has;
/// * `SET` — "a specified set of endpoints", listed in `AvailableEndpoints`;
/// * `DYPF` — that set can change, so `ActiveEndpoints` says which of them count right now.
///
/// The `NODE` and `TREE` forms serve no attributes at all: the answer is the node's own shape,
/// which a client already knows from the Descriptor cluster.
#[derive(Debug)]
pub struct PowerTopology<'a> {
    available: &'a [crate::im::EndpointId],
    active: core::cell::RefCell<&'a [crate::im::EndpointId]>,
}

impl<'a> PowerTopology<'a> {
    /// A topology over a fixed set of endpoints (`SET`), all of them active.
    ///
    /// `AvailableEndpoints` is `F` — fixed — so it is the product's `const` data; only
    /// `ActiveEndpoints` moves, and only when the `DYPF` feature says it may.
    #[must_use]
    pub const fn new(available: &'a [crate::im::EndpointId]) -> Self {
        Self {
            available,
            active: core::cell::RefCell::new(available),
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<2, 0, 0, 0>> {
        Conforming::new(&spec_topology::CLUSTER, feature_map, optional)
    }

    /// Narrows `ActiveEndpoints` to the ones drawing power now (`DYPF`).
    ///
    /// Refuses an endpoint `AvailableEndpoints` does not list: §2.14 makes the active set a
    /// subset of the available one, and a meter that claimed to measure an endpoint it had
    /// never declared would be reporting somebody else's power.
    pub fn set_active(&self, active: &'a [crate::im::EndpointId]) -> Result<(), Status> {
        if !active.iter().all(|id| self.available.contains(id)) {
            return Err(Status::ConstraintError);
        }
        *self.active.borrow_mut() = active;
        Ok(())
    }

    /// `ActiveEndpoints`.
    #[must_use]
    pub fn active(&self) -> &'a [crate::im::EndpointId] {
        *self.active.borrow()
    }
}

impl ClusterHandler for PowerTopology<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let endpoints = |w: &mut TlvWriter<'_>, ids: &[crate::im::EndpointId]| {
            full(w.start_array(tag))?;
            for id in ids {
                full(w.unsigned(Tag::Anonymous, u64::from(*id)))?;
            }
            full(w.end_container())
        };
        match resolved.attribute {
            topology::AVAILABLE_ENDPOINTS => endpoints(w, self.available),
            topology::ACTIVE_ENDPOINTS => endpoints(w, self.active()),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        _resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        Err(Status::UnsupportedCommand.into())
    }
}

impl Cluster for PowerTopology<'_> {
    const ID: ClusterId = topology::ID;
}
