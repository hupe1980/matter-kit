//! Water Heater Management, cluster `0x0094` (Application Cluster §9.5).
//!
//! > Heating of hot water is one of the main energy uses in homes, and when coupled with the
//! > Energy Management cluster, it can help consumers save cost (e.g. using power at cheaper
//! > times or from local solar PV generation).
//!
//! A hot water tank is a battery that stores heat, and this cluster is the interface that lets
//! something else decide *when* to charge it. Most of the time the tank runs itself off the
//! Thermostat cluster on the same endpoint (§9.5.5 requires one); this cluster adds the two
//! things an energy manager needs — a way to say "heat it now, whatever the schedule says",
//! and enough information to work out what that will cost.
//!
//! # Boost is an override with an end
//!
//! §9.5.8.1: a `Boost` heats the water "which may override other settings, for example, if the
//! Water Heater Mode is set to Off, or Timed and it is during one of the Off periods". Every
//! boost carries a `Duration`, and it stops when that runs out even if nothing else stops it.
//! A boost that could not expire would be a tariff-blind immersion heater with a network
//! interface.
//!
//! # The device may refuse
//!
//! > If the duration field is too short for the water heater to accept, for example a heat pump
//! > may take several minutes to ramp up in operation, then the boost command SHALL be
//! > rejected with a status of INVALID_IN_STATE.
//!
//! Only the appliance knows its own ramp, so [`WaterHeaterHooks::boost`] is what decides, and
//! this cluster never invents a minimum of its own.

use core::cell::{Cell, RefCell};

use crate::clusters::generated::water_heater_management as spec_water;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::platform::{Duration, Instant};
use crate::tlv::{Tag, TlvWriter};

use super::Cluster;

pub use spec_water::attribute::{
    BOOST_STATE, ESTIMATED_HEAT_REQUIRED, HEAT_DEMAND, HEATER_TYPES, TANK_PERCENTAGE, TANK_VOLUME,
};
pub use spec_water::command::{BOOST, CANCEL_BOOST};
pub use spec_water::event::{BOOST_ENDED, BOOST_STARTED};
pub use spec_water::{
    BoostStateEnum, ID, PICS, REVISION, WaterHeaterBoostInfoStruct, WaterHeaterHeatSourceBitmap,
    feature,
};

/// What §9.5.6.3's `Duration` is measured in.
pub const SECOND: Duration = Duration::from_secs(1);

/// What the appliance decides for itself.
pub trait WaterHeaterHooks {
    /// `HeatDemand` (§9.5.7.2) — which heat sources are running right now.
    ///
    /// > This attribute SHALL indicate if the water heater is heating water. If a bit is set
    /// > then the corresponding heat source is active.
    fn heat_demand(&self) -> WaterHeaterHeatSourceBitmap;

    /// `TankVolume` (§9.5.7.3), in litres — what the `EnergyManagement` feature adds.
    fn tank_volume(&self) -> u16 {
        0
    }

    /// `EstimatedHeatRequired` (§9.5.7.4), in mWh.
    ///
    /// The energy needed to bring the tank to its setpoint. §9.5.7.4 works the sum out in full
    /// — specific heat capacity, tank volume, temperature difference — and then notes that the
    /// *electrical* energy is a different number entirely: "Heat pumps can be produce 3kWh of
    /// heat output for 1kWh of electrical energy input. The conversion between heat energy and
    /// electrical energy is outside the scope of this cluster."
    fn estimated_heat_required(&self) -> u64 {
        0
    }

    /// `TankPercentage` (§9.5.7.5) — roughly how much of the tank is hot.
    ///
    /// Not a measurement so much as an estimate: hot water stratifies above cold, and §9.5.7.5
    /// gives an algorithm for a tank with a single probe and notes that "the accuracy of this
    /// attribute is manufacturer specific".
    fn tank_percentage(&self) -> u8 {
        0
    }

    /// §9.5.8.1: start heating on the terms in `info`.
    ///
    /// Return `Err(Status::InvalidInState)` when the appliance cannot honour it — §9.5.8.1
    /// names exactly that case: "If the duration field is too short for the water heater to
    /// accept, for example a heat pump may take several minutes to ramp up in operation". No
    /// other code is defined for a boost the appliance will not do.
    fn boost(&self, info: &WaterHeaterBoostInfoStruct) -> Result<(), Status>;

    /// §9.5.8.2: stop, and go back to whatever the Water Heater Mode says.
    fn cancel_boost(&self) {}
}

/// An event this cluster produced, for the device to record in its own store (§7.14).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Event {
    /// §9.5.9.1 — "generated whenever a Boost command is accepted", carrying the command's own
    /// fields so a client can see the terms that were accepted rather than the ones it sent.
    BoostStarted(WaterHeaterBoostInfoStruct),
    /// §9.5.9.2 — "generated whenever the BoostState transitions from Active to Inactive".
    BoostEnded,
}

/// Water Heater Management over a tank the device owns.
#[derive(Debug)]
pub struct WaterHeaterManagement<'a, H: WaterHeaterHooks> {
    hooks: &'a H,
    heater_types: WaterHeaterHeatSourceBitmap,
    boost: Cell<Option<WaterHeaterBoostInfoStruct>>,
    /// When the running boost's `Duration` runs out.
    expires: Cell<Option<Instant>>,
    events: RefCell<heapless::Vec<Event, 4>>,
}

impl<'a, H: WaterHeaterHooks> WaterHeaterManagement<'a, H> {
    /// A cluster over an appliance with the given heat sources.
    ///
    /// `heater_types` is `F` — fixed (§9.5.7.1) — because it is what the tank physically has:
    /// an immersion element, a heat pump, a boiler, or several.
    #[must_use]
    pub fn new(hooks: &'a H, heater_types: WaterHeaterHeatSourceBitmap) -> Self {
        Self {
            hooks,
            heater_types,
            boost: Cell::new(None),
            expires: Cell::new(None),
            events: RefCell::new(heapless::Vec::new()),
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<6, 2, 0, 2>> {
        Conforming::new(&spec_water::CLUSTER, feature_map, optional)
    }

    /// `HeaterTypes` (§9.5.7.1).
    #[must_use]
    pub const fn heater_types(&self) -> WaterHeaterHeatSourceBitmap {
        self.heater_types
    }

    /// `BoostState` (§9.5.7.6).
    #[must_use]
    pub fn boost_state(&self) -> BoostStateEnum {
        if self.boost.get().is_some() {
            BoostStateEnum::Active
        } else {
            BoostStateEnum::Inactive
        }
    }

    /// The terms of the boost currently running, if any.
    #[must_use]
    pub fn boost_info(&self) -> Option<WaterHeaterBoostInfoStruct> {
        self.boost.get()
    }

    /// When [`WaterHeaterManagement::poll`] next has something to do.
    #[must_use]
    pub fn wake_at(&self) -> Option<Instant> {
        self.expires.get()
    }

    /// Ends a boost whose `Duration` has run out.
    ///
    /// §9.5.8.1: "or the boost command's duration times out after the specified Duration, then
    /// BoostState transitions to Inactive". A boost with no end is an immersion heater that
    /// ignores the tariff it was installed to follow.
    pub fn poll(&self, now: Instant) {
        if let Some(expires) = self.expires.get()
            && now >= expires
        {
            self.end();
        }
    }

    /// The appliance reached the target by itself — a `OneShot` boost is over (§9.5.8.1).
    ///
    /// > If OneShot is specified then once the hot water has reached the set point temperature
    /// > (or the TemporarySetpoint temperature, if specified) or the TargetPercentage (if
    /// > specified) ... BoostState transitions to Inactive.
    ///
    /// Only the appliance knows it got there, so it says so; and without `OneShot` reaching the
    /// target is *not* the end, because §9.5.6.3.6's `TargetReheat` exists precisely so the
    /// tank keeps topping itself up until the duration runs out.
    pub fn target_reached(&self) {
        if self
            .boost
            .get()
            .is_some_and(|info| info.one_shot == Some(true))
        {
            self.end();
        }
    }

    /// Takes the event records the cluster has produced, for the device's own store.
    pub fn take_events(&self) -> heapless::Vec<Event, 4> {
        core::mem::take(&mut self.events.borrow_mut())
    }

    fn push(&self, event: Event) {
        let mut events = self.events.borrow_mut();
        if events.is_full() {
            events.remove(0);
        }
        let _ = events.push(event);
    }

    /// Transitions to Inactive, if it was not already.
    fn end(&self) {
        if self.boost.take().is_some() {
            self.expires.set(None);
            self.hooks.cancel_boost();
            self.push(Event::BoostEnded);
        }
    }
}

impl<H: WaterHeaterHooks> ClusterHandler for WaterHeaterManagement<'_, H> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            HEATER_TYPES => full(w.unsigned(tag, u64::from(self.heater_types.bits()))),
            HEAT_DEMAND => full(w.unsigned(tag, u64::from(self.hooks.heat_demand().bits()))),
            TANK_VOLUME => full(w.unsigned(tag, u64::from(self.hooks.tank_volume()))),
            ESTIMATED_HEAT_REQUIRED => full(w.unsigned(tag, self.hooks.estimated_heat_required())),
            TANK_PERCENTAGE => full(w.unsigned(tag, u64::from(self.hooks.tank_percentage()))),
            BOOST_STATE => full(w.unsigned(tag, u64::from(self.boost_state().value()))),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        match resolved.command.id {
            BOOST => {
                let decoded: spec_water::BoostFields =
                    super::decode_fields(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                let info = decoded.boost_info;
                // §9.5.6.3's constraint on `Duration` is "min 1": a boost for no time is not a
                // boost, and it would expire on the tick it started.
                if info.duration == 0 {
                    return Err(Status::ConstraintError.into());
                }
                // §9.5.6.3.6: "This field SHALL be less than or equal to the TargetPercentage
                // field." Reheating to a level above the target would never stop.
                if let (Some(target), Some(reheat)) = (info.target_percentage, info.target_reheat)
                    && reheat > target
                {
                    return Err(Status::ConstraintError.into());
                }
                // Both are percentages; §7.19.2's rule about values a type cannot hold applies
                // to a `percent` just as much as to an enumeration.
                if info.target_percentage.is_some_and(|p| p > 100)
                    || info.target_reheat.is_some_and(|p| p > 100)
                {
                    return Err(Status::ConstraintError.into());
                }
                // §9.5.8.1: the appliance may refuse, and `INVALID_IN_STATE` is the only code
                // the specification gives it.
                self.hooks.boost(&info).map_err(StatusIb::from)?;
                // "If the Water Heater was already in the BoostState 'Active' when this command
                // is received, it SHALL continue in this BoostState, but SHALL discard the
                // effect of the values of the fields from the previous Boost commands" — so a
                // second boost replaces the terms without an intervening `BoostEnded`.
                self.boost.set(Some(info));
                self.expires
                    .set(Some(ctx.now.saturating_add(
                        SECOND.saturating_mul(u64::from(info.duration)),
                    )));
                self.push(Event::BoostStarted(info));
                Ok(None)
            }
            CANCEL_BOOST => {
                // §9.5.8.2: "If the BoostState attribute value was already Inactive when this
                // command is received, the BoostState attribute value shall remain Inactive and
                // the server SHALL return SUCCESS." Not an error — cancelling nothing is the
                // state the client asked for.
                self.end();
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: WaterHeaterHooks> Cluster for WaterHeaterManagement<'_, H> {
    const ID: ClusterId = ID;
}
