//! Energy EVSE, cluster `0x0099` (Application Cluster §9.3).
//!
//! > Electric Vehicle Supply Equipment (EVSE) is equipment used to charge an Electric Vehicle
//! > (EV) or Plug-In Hybrid Electric Vehicle.
//!
//! A car is the largest controllable load in most houses, and almost the only one that does
//! not care *when* it runs so long as it is full by morning. That is what this cluster is for:
//! a client says how much current the EVSE may pass and until when, and the user says what the
//! car needs and by what time; something else decides the hours in between.
//!
//! # Enabled until a moment, not enabled
//!
//! §9.3.8.4: `ChargingEnabledUntil` is a timestamp, and "a value in the past or 0x0 indicates
//! that EVSE charging SHALL be disabled". So *every* enable has an end, and the ordinary
//! failure mode of a home energy manager — it crashes, or the Wi-Fi drops — leaves the car
//! charging until the window it was given runs out rather than for ever. §9.3.8.4 also makes
//! the attribute persistent, "for example a temporary power failure should not stop the
//! vehicle from being charged".
//!
//! The timestamps are `epoch-s`, in UTC. A monotonic clock cannot compare them, so
//! [`EvseHooks::utc`] is where they come from; an EVSE whose clock has not been set reports
//! `None` and this cluster then never expires a window on its own, because guessing would
//! either cut a charge short or run one past its end.
//!
//! # Charging and discharging are two axes, not three states
//!
//! §9.3.9.2.4 and §9.3.9.3.3 spell out a small state table: enabling charging from `Disabled`
//! gives `ChargingEnabled`, enabling it from `DischargingEnabled` gives `Enabled`, and each
//! window expiring drops back to whatever the other one still allows. A device that treated
//! `SupplyState` as a single mode would turn V2H off every time a charge window ended.
//!
//! # The EVSE may refuse, and says why with the state it is in
//!
//! §9.3.9.2.4: "If there is currently an error present on the EVSE, or Diagnostics are
//! currently active, then the command SHALL be ignored and a response with a status of FAILURE
//! SHALL be returned." Fault clearing is deliberately outside the network's reach — §9.3 notes
//! that some J1772 faults "may require clearing by an operator by, for example, pressing a
//! button on the equipment or breaker panel".

use core::cell::{Cell, RefCell};

use crate::clusters::generated::energy_evse as spec_evse;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::Cluster;

pub use spec_evse::attribute::{
    APPROXIMATE_EV_EFFICIENCY, BATTERY_CAPACITY, CHARGING_ENABLED_UNTIL, CIRCUIT_CAPACITY,
    DISCHARGING_ENABLED_UNTIL, FAULT_STATE, MAXIMUM_CHARGE_CURRENT, MAXIMUM_DISCHARGE_CURRENT,
    MINIMUM_CHARGE_CURRENT, NEXT_CHARGE_REQUIRED_ENERGY, NEXT_CHARGE_START_TIME,
    NEXT_CHARGE_TARGET_SO_C, NEXT_CHARGE_TARGET_TIME, RANDOMIZATION_DELAY_WINDOW, SESSION_DURATION,
    SESSION_ENERGY_CHARGED, SESSION_ENERGY_DISCHARGED, SESSION_ID, STATE, STATE_OF_CHARGE,
    SUPPLY_STATE, USER_MAXIMUM_CHARGE_CURRENT, VEHICLE_ID,
};
pub use spec_evse::command::{
    CLEAR_TARGETS, DISABLE, ENABLE_CHARGING, ENABLE_DISCHARGING, GET_TARGETS, GET_TARGETS_RESPONSE,
    SET_TARGETS, START_DIAGNOSTICS,
};
pub use spec_evse::event::{
    ENERGY_TRANSFER_STARTED, ENERGY_TRANSFER_STOPPED, EV_CONNECTED, EV_NOT_DETECTED, FAULT, RFID,
};
pub use spec_evse::{
    ChargingTargetScheduleStruct, ChargingTargetStruct, EnergyTransferStoppedReasonEnum,
    FaultStateEnum, ID, PICS, REVISION, StateEnum, SupplyStateEnum, TargetDayOfWeekBitmap, feature,
};

/// §9.3.9.5's constraint: "a list of up to 7 sets of daily charging targets".
pub const SCHEDULES_MAX: usize = 7;

/// §9.3.7.6's constraint on `TargetTimeMinutesPastMidnight`: "max 1439" — one minute short of
/// twenty-four hours, because 1440 is midnight the *next* day.
pub const MINUTES_MAX: u16 = 1439;

/// The days of the week, in `TargetDayOfWeekBitmap`'s bit order (§9.3.7.1).
const DAYS: [TargetDayOfWeekBitmap; 7] = [
    TargetDayOfWeekBitmap::SUNDAY,
    TargetDayOfWeekBitmap::MONDAY,
    TargetDayOfWeekBitmap::TUESDAY,
    TargetDayOfWeekBitmap::WEDNESDAY,
    TargetDayOfWeekBitmap::THURSDAY,
    TargetDayOfWeekBitmap::FRIDAY,
    TargetDayOfWeekBitmap::SATURDAY,
];

/// What the EVSE hardware knows and decides.
pub trait EvseHooks {
    /// `State` (§9.3.8.1) — what the pilot signal says. `None` when it cannot be determined.
    fn state(&self) -> Option<StateEnum>;

    /// `FaultState` (§9.3.8.3).
    ///
    /// §9.3.8.3 ties this to `SupplyState`: "For all values of SupplyState other than
    /// DisabledError, the FaultState attribute SHALL be NoError" — so an EVSE that reports a
    /// fault here is also telling this cluster to refuse every enable.
    fn fault(&self) -> FaultStateEnum {
        FaultStateEnum::NoError
    }

    /// The current time as `epoch-s` in UTC, or `None` if the clock has never been set.
    ///
    /// Every enable window is a UTC timestamp (§9.3.8.4), and a monotonic clock cannot say
    /// whether one has passed. An EVSE with no clock never expires a window here, which is the
    /// cautious half of the choice: the alternative is guessing, and a wrong guess either cuts
    /// a charge short or runs one past the hour the user was quoted.
    fn utc(&self) -> Option<u32> {
        None
    }

    /// `CircuitCapacity` (§9.3.8.6), in mA — what the supply circuit can carry.
    fn circuit_capacity(&self) -> i64;

    /// `UserMaximumChargeCurrent` (§9.3.8.10), in mA.
    fn user_maximum_charge_current(&self) -> i64 {
        0
    }

    /// `RandomizationDelayWindow` (§9.3.8.11), in seconds.
    ///
    /// A fleet of EVSEs that all started on the stroke of a cheap-rate boundary would be a
    /// step change on the local transformer; this is the window each spreads itself over.
    fn randomization_delay_window(&self) -> u32 {
        0
    }

    /// `SessionID` (§9.3.8.20) — increments once per plug-in.
    fn session_id(&self) -> Option<u32>;

    /// `SessionDuration` (§9.3.8.21), in seconds.
    fn session_duration(&self) -> Option<u32>;

    /// `SessionEnergyCharged` (§9.3.8.22), in mWh.
    fn session_energy_charged(&self) -> Option<i64>;

    /// `SessionEnergyDischarged` — the `V2X` feature's counterpart.
    fn session_energy_discharged(&self) -> Option<i64> {
        None
    }

    /// `StateOfCharge` (`SOC` feature) — what the vehicle reports, if it reports anything.
    fn state_of_charge(&self) -> Option<u8> {
        None
    }

    /// `BatteryCapacity` (`SOC` feature), in mWh.
    fn battery_capacity(&self) -> Option<i64> {
        None
    }

    /// `VehicleID` (`PNC` feature) — the identity a Plug-and-Charge session established.
    fn vehicle_id(&self) -> Option<&str> {
        None
    }

    /// `NextChargeStartTime`, `NextChargeTargetTime`, `NextChargeRequiredEnergy` and
    /// `NextChargeTargetSoC` (§9.3.8.12–§9.3.8.15), the `CHARGING_PREFERENCES` feature's
    /// answer to "when will you next charge, and to what".
    ///
    /// §9.3.9.5.2 puts the computation firmly on the EVSE: "The EVSE SHALL be responsible for
    /// updating the NextChargeEndTime, NextChargeRequiredEnergy and/or NextChargeTargetSoC
    /// attributes as it runs through its internal schedule."
    fn next_charge(&self) -> NextCharge {
        NextCharge::default()
    }

    /// `ApproximateEVEfficiency` (§9.3.8.16), in tenths of a mile per kWh.
    fn approximate_ev_efficiency(&self) -> Option<u16> {
        None
    }

    /// §9.3.9.1: stop any power flow. `false` becomes `FAILURE`.
    fn disable(&self) -> bool {
        true
    }

    /// §9.3.9.2: pass up to `maximum_ma`, down to `minimum_ma` in trickle. `false` is
    /// `FAILURE`.
    fn enable_charging(&self, minimum_ma: i64, maximum_ma: i64) -> bool;

    /// §9.3.9.3: accept up to `maximum_ma` back from the vehicle. `false` is `FAILURE`.
    fn enable_discharging(&self, maximum_ma: i64) -> bool {
        let _ = maximum_ma;
        false
    }

    /// §9.3.9.4: run self-diagnostics. `false` is `FAILURE`.
    ///
    /// "The diagnostics are at the discretion of the manufacturer and usually include internal
    /// checks. Upon completion of the diagnostics, the EVSE SHALL restore SupplyState to the
    /// Disabled state" — so the EVSE calls [`EnergyEvse::diagnostics_complete`] when it is
    /// done, and nothing here guesses how long that takes.
    fn start_diagnostics(&self) -> bool {
        false
    }

    /// The user's charging targets changed (§9.3.9.5.2).
    ///
    /// The schedule is stored by this cluster; acting on it is the EVSE's, and §9.3.9.5.2 is
    /// explicit that it may not do the arithmetic itself: "the EVSE may not be able to compute
    /// the schedules by itself, or may rely upon an EMS or other optimizer to do this."
    fn targets_changed(&self) {}
}

/// The four `CHARGING_PREFERENCES` attributes the EVSE computes (§9.3.8.12–§9.3.8.15).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NextCharge {
    /// `NextChargeStartTime` — `epoch-s`, or `None` for "no charge planned".
    pub start_time: Option<u32>,
    /// `NextChargeTargetTime` — `epoch-s`.
    pub target_time: Option<u32>,
    /// `NextChargeRequiredEnergy` — mWh.
    pub required_energy: Option<i64>,
    /// `NextChargeTargetSoC` — percent.
    pub target_soc: Option<u8>,
}

/// An event this cluster produced, for the device to record in its own store (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// §9.3.10.1 — a vehicle was plugged in, carrying the new `SessionID`.
    EvConnected(u32),
    /// §9.3.10.2 — the vehicle is gone.
    EvNotDetected,
    /// §9.3.10.3 — current started flowing.
    EnergyTransferStarted,
    /// §9.3.10.4 — current stopped, and why.
    EnergyTransferStopped(EnergyTransferStoppedReasonEnum),
    /// §9.3.10.5 — the fault state changed.
    Fault(FaultStateEnum),
}

/// One day's charging targets.
type DayTargets<const T: usize> = heapless::Vec<ChargingTargetStruct, T>;

/// Energy EVSE over one piece of supply equipment.
///
/// `T` is how many charging targets *one day* may hold. §9.3.9.5.2's resource rule is about
/// the total the device supports, and a per-day bound is the shape that makes "replace
/// Saturday and leave every other day alone" a local edit.
#[derive(Debug)]
pub struct EnergyEvse<'a, H: EvseHooks, const T: usize = 10> {
    hooks: &'a H,
    feature_map: u32,
    supply: Cell<SupplyStateEnum>,
    charging_until: Cell<Option<u32>>,
    discharging_until: Cell<Option<u32>>,
    minimum_charge_current: Cell<i64>,
    maximum_charge_current: Cell<i64>,
    maximum_discharge_current: Cell<i64>,
    /// One entry per day, in [`DAYS`] order.
    targets: RefCell<[DayTargets<T>; 7]>,
    events: RefCell<heapless::Vec<Event, 8>>,
}

impl<'a, H: EvseHooks, const T: usize> EnergyEvse<'a, H, T> {
    /// A cluster over `hooks`, starting `Disabled`.
    ///
    /// §9.3.8.2's starting point is the safe one: an EVSE that came up enabled would start
    /// passing current after a power cut without anybody asking it to.
    #[must_use]
    pub fn new(hooks: &'a H, feature_map: u32) -> Self {
        Self {
            hooks,
            feature_map,
            supply: Cell::new(SupplyStateEnum::Disabled),
            charging_until: Cell::new(Some(0)),
            discharging_until: Cell::new(Some(0)),
            minimum_charge_current: Cell::new(0),
            maximum_charge_current: Cell::new(0),
            maximum_discharge_current: Cell::new(0),
            targets: RefCell::new(core::array::from_fn(|_| heapless::Vec::new())),
            events: RefCell::new(heapless::Vec::new()),
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<23, 8, 1, 6>> {
        Conforming::new(&spec_evse::CLUSTER, feature_map, optional)
    }

    /// Everything §9.3 leaves to the product.
    pub const WITH_ALL_OPTIONAL: Optional<'static> = Optional {
        attributes: &[USER_MAXIMUM_CHARGE_CURRENT, RANDOMIZATION_DELAY_WINDOW],
        commands: &[START_DIAGNOSTICS],
        events: &[],
    };

    /// Restores the enable windows a reboot interrupted (§9.3.8.4).
    ///
    /// > This attribute SHALL be persisted, for example a temporary power failure should not
    /// > stop the vehicle from being charged.
    ///
    /// So the device hands back what it stored, and this cluster puts `SupplyState` where the
    /// two windows say it belongs rather than assuming `Disabled`.
    pub fn start(&self, charging_until: Option<u32>, discharging_until: Option<u32>) {
        self.charging_until.set(charging_until);
        self.discharging_until.set(discharging_until);
        self.resupply();
    }

    /// `SupplyState` (§9.3.8.2).
    #[must_use]
    pub fn supply_state(&self) -> SupplyStateEnum {
        // §9.3.8.3: a fault outranks everything the client asked for.
        if self.hooks.fault() != FaultStateEnum::NoError {
            return SupplyStateEnum::DisabledError;
        }
        self.supply.get()
    }

    /// `ChargingEnabledUntil` (§9.3.8.4) — `None` is null, "always enabled".
    #[must_use]
    pub fn charging_enabled_until(&self) -> Option<u32> {
        self.charging_until.get()
    }

    /// `DischargingEnabledUntil` (§9.3.8.5).
    #[must_use]
    pub fn discharging_enabled_until(&self) -> Option<u32> {
        self.discharging_until.get()
    }

    /// `MaximumChargeCurrent` (§9.3.8.8), in mA.
    ///
    /// §9.3.9.2.3: the command's value is the ceiling, and `UserMaximumChargeCurrent` may only
    /// lower it — "if the UserMaximumChargeCurrent attribute is adjusted below then this
    /// value, and then later adjusted above this value, the resulting MaximumChargeCurrent
    /// attribute will be limited to this value". The user cannot raise the limit an installer
    /// or a client set.
    #[must_use]
    pub fn maximum_charge_current(&self) -> i64 {
        let user = self.hooks.user_maximum_charge_current();
        let commanded = self.maximum_charge_current.get();
        if user > 0 {
            user.min(commanded)
        } else {
            commanded
        }
    }

    /// Whether current is flowing either way right now.
    #[must_use]
    pub fn transferring(&self) -> bool {
        matches!(
            self.hooks.state(),
            Some(StateEnum::PluggedInCharging | StateEnum::PluggedInDischarging)
        )
    }

    /// The charging targets stored for one day (§9.3.9.5).
    #[must_use]
    pub fn targets_for(
        &self,
        day: TargetDayOfWeekBitmap,
    ) -> heapless::Vec<ChargingTargetStruct, T> {
        let index = DAYS.iter().position(|d| *d == day);
        match index.and_then(|index| self.targets.borrow().get(index).cloned()) {
            Some(targets) => targets,
            None => heapless::Vec::new(),
        }
    }

    /// §9.3.9.4: the EVSE finished its self-diagnostics.
    ///
    /// > Upon completion of the diagnostics, the EVSE SHALL restore SupplyState to the Disabled
    /// > state.
    pub fn diagnostics_complete(&self) {
        if self.supply.get() == SupplyStateEnum::DisabledDiagnostics {
            self.supply.set(SupplyStateEnum::Disabled);
        }
    }

    /// Expires whichever enable windows have passed (§9.3.9.2.4, §9.3.9.3.3).
    ///
    /// > If the ChargingEnabledUntil time is not null, then when this time expires then the
    /// > EVSE SHALL stop charging ... and SHALL update the SupplyState attribute to Disabled
    /// > (if DischargingEnabledUntil is also in the past) or DischargingEnabled.
    pub fn poll(&self) {
        let before = self.supply.get();
        self.resupply();
        // The window ran out while current was flowing, so §9.3.9.1.1's rule applies just as
        // it does to an explicit Disable: the transfer stopped, and a client watching the
        // event log must be able to see that it was the EVSE's decision.
        if before != self.supply.get() && self.transferring() {
            self.record(Event::EnergyTransferStopped(
                EnergyTransferStoppedReasonEnum::EVSEStopped,
            ));
        }
    }

    /// Recomputes `SupplyState` from the two windows.
    fn resupply(&self) {
        // Diagnostics and a fault are not the windows' to override.
        if matches!(
            self.supply.get(),
            SupplyStateEnum::DisabledDiagnostics | SupplyStateEnum::DisabledError
        ) {
            return;
        }
        let charging = self.window_open(self.charging_until.get());
        let discharging = self.window_open(self.discharging_until.get()) && self.has(feature::V2_X);
        self.supply.set(match (charging, discharging) {
            (true, true) => SupplyStateEnum::Enabled,
            (true, false) => SupplyStateEnum::ChargingEnabled,
            (false, true) => SupplyStateEnum::DischargingEnabled,
            (false, false) => SupplyStateEnum::Disabled,
        });
    }

    /// Whether an `epoch-s` window is still open.
    ///
    /// `None` is null — §9.3.8.4's "always enabled". Zero, or a moment already past, is
    /// disabled. And when the EVSE has no clock, an open-ended reading is the only honest one:
    /// the window was opened by a client and nothing here can say it has closed.
    fn window_open(&self, until: Option<u32>) -> bool {
        match until {
            None => true,
            Some(0) => false,
            Some(until) => match self.hooks.utc() {
                Some(now) => until > now,
                None => true,
            },
        }
    }

    const fn has(&self, bit: u32) -> bool {
        self.feature_map & bit != 0
    }

    /// Records an event for the device's own store.
    ///
    /// Public because most of §9.3.10's events are the *hardware's* to notice — a vehicle
    /// plugged in, a fault detected — and only `EnergyTransferStopped` is ever this cluster's.
    pub fn record(&self, event: Event) {
        let mut events = self.events.borrow_mut();
        if events.is_full() {
            events.remove(0);
        }
        let _ = events.push(event);
    }

    /// Takes the event records the cluster has collected.
    pub fn take_events(&self) -> heapless::Vec<Event, 8> {
        core::mem::take(&mut self.events.borrow_mut())
    }

    /// §9.3.9.2.4 and §9.3.9.3.3's shared precondition.
    fn refuses_commands(&self) -> bool {
        self.hooks.fault() != FaultStateEnum::NoError
            || self.supply.get() == SupplyStateEnum::DisabledDiagnostics
    }

    /// §9.3.9.5.2's validation and store.
    fn set_targets(
        &self,
        schedules: crate::tlv::TlvList<'_, ChargingTargetScheduleStruct<'_>>,
    ) -> Status {
        let mut seen = TargetDayOfWeekBitmap::empty();
        let mut staged: [Option<DayTargets<T>>; 7] = core::array::from_fn(|_| None);
        let mut count = 0usize;
        for schedule in schedules.iter() {
            let Ok(schedule) = schedule else {
                return Status::ConstraintError;
            };
            count = count.saturating_add(1);
            if count > SCHEDULES_MAX {
                // §9.3.9.5's constraint is "max 7", which is also exactly the number of days:
                // an eighth schedule could only repeat one.
                return Status::ConstraintError;
            }
            // "each day of the week is included in at most one of the ChargingTargetSchedule,
            // if they are not then the response SHALL be CONSTRAINT_ERROR" — two schedules
            // claiming Tuesday is a request with no single meaning.
            if schedule.day_of_week_for_sequence.intersects(seen) {
                return Status::ConstraintError;
            }
            seen |= schedule.day_of_week_for_sequence;

            let mut targets: DayTargets<T> = heapless::Vec::new();
            for target in schedule.charging_targets.iter() {
                let Ok(target) = target else {
                    return Status::ConstraintError;
                };
                // §9.3.7.6's constraints: "max 1439" minutes, a percent, and "min 0" energy.
                if target.target_time_minutes_past_midnight > MINUTES_MAX
                    || target.target_so_c.is_some_and(|soc| soc > 100)
                    || target.added_energy.is_some_and(|energy| energy < 0)
                {
                    return Status::ConstraintError;
                }
                if targets.push(target).is_err() {
                    // §9.3.9.5.2: "When a command is received that requires a total number of
                    // charging targets greater than the device supports, the status of the
                    // response SHALL be RESOURCE_EXHAUSTED."
                    return Status::ResourceExhausted;
                }
            }
            for (index, day) in DAYS.iter().enumerate() {
                if schedule.day_of_week_for_sequence.contains(*day)
                    && let Some(slot) = staged.get_mut(index)
                {
                    *slot = Some(targets.clone());
                }
            }
        }
        // Staged first, applied second: a schedule that fails validation half way through must
        // not leave the user with three days of the new plan and four of the old.
        let mut stored = self.targets.borrow_mut();
        for (index, staged) in staged.into_iter().enumerate() {
            if let (Some(staged), Some(slot)) = (staged, stored.get_mut(index)) {
                *slot = staged;
            }
        }
        drop(stored);
        self.hooks.targets_changed();
        Status::Success
    }
}

impl<H: EvseHooks, const T: usize> ClusterHandler for EnergyEvse<'_, H, T> {
    #[allow(clippy::too_many_lines)]
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let epoch = |w: &mut TlvWriter<'_>, value: Option<u32>| match value {
            Some(value) => full(w.unsigned(tag, u64::from(value))),
            None => full(w.null(tag)),
        };
        let energy = |w: &mut TlvWriter<'_>, value: Option<i64>| match value {
            Some(value) => full(w.signed(tag, value)),
            None => full(w.null(tag)),
        };
        let next = self.hooks.next_charge();
        match resolved.attribute {
            STATE => match self.hooks.state() {
                Some(state) => full(w.unsigned(tag, u64::from(state.value()))),
                None => full(w.null(tag)),
            },
            SUPPLY_STATE => full(w.unsigned(tag, u64::from(self.supply_state().value()))),
            FAULT_STATE => full(w.unsigned(tag, u64::from(self.hooks.fault().value()))),
            CHARGING_ENABLED_UNTIL => epoch(w, self.charging_until.get()),
            DISCHARGING_ENABLED_UNTIL => epoch(w, self.discharging_until.get()),
            CIRCUIT_CAPACITY => full(w.signed(tag, self.hooks.circuit_capacity())),
            MINIMUM_CHARGE_CURRENT => full(w.signed(tag, self.minimum_charge_current.get())),
            MAXIMUM_CHARGE_CURRENT => full(w.signed(tag, self.maximum_charge_current())),
            MAXIMUM_DISCHARGE_CURRENT => full(w.signed(tag, self.maximum_discharge_current.get())),
            USER_MAXIMUM_CHARGE_CURRENT => {
                full(w.signed(tag, self.hooks.user_maximum_charge_current()))
            }
            RANDOMIZATION_DELAY_WINDOW => {
                full(w.unsigned(tag, u64::from(self.hooks.randomization_delay_window())))
            }
            NEXT_CHARGE_START_TIME => epoch(w, next.start_time),
            NEXT_CHARGE_TARGET_TIME => epoch(w, next.target_time),
            NEXT_CHARGE_REQUIRED_ENERGY => energy(w, next.required_energy),
            NEXT_CHARGE_TARGET_SO_C => match next.target_soc {
                Some(soc) => full(w.unsigned(tag, u64::from(soc))),
                None => full(w.null(tag)),
            },
            APPROXIMATE_EV_EFFICIENCY => match self.hooks.approximate_ev_efficiency() {
                Some(value) => full(w.unsigned(tag, u64::from(value))),
                None => full(w.null(tag)),
            },
            STATE_OF_CHARGE => match self.hooks.state_of_charge() {
                Some(soc) => full(w.unsigned(tag, u64::from(soc))),
                None => full(w.null(tag)),
            },
            BATTERY_CAPACITY => energy(w, self.hooks.battery_capacity()),
            VEHICLE_ID => match self.hooks.vehicle_id() {
                Some(id) => full(w.utf8(tag, id)),
                None => full(w.null(tag)),
            },
            SESSION_ID => epoch(w, self.hooks.session_id()),
            SESSION_DURATION => epoch(w, self.hooks.session_duration()),
            SESSION_ENERGY_CHARGED => energy(w, self.hooks.session_energy_charged()),
            SESSION_ENERGY_DISCHARGED => energy(w, self.hooks.session_energy_discharged()),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let payload = || fields.ok_or(StatusIb::from(Status::InvalidCommand));
        match resolved.command.id {
            DISABLE => {
                // §9.3.9.1.1: "If the SupplyState attribute is already Disabled, a response
                // with status of SUCCESS SHALL be returned." Not an error — the client asked
                // for a state it is already in.
                let transferring = self.transferring();
                if !self.hooks.disable() {
                    return Err(Status::Failure.into());
                }
                // "the ChargingEnabledUntil and DischargingEnabledUntil attributes SHALL be
                // set to 0x0" — zero, not null, because null means *always* enabled.
                self.charging_until.set(Some(0));
                self.discharging_until.set(Some(0));
                if self.supply.get() != SupplyStateEnum::DisabledDiagnostics {
                    self.supply.set(SupplyStateEnum::Disabled);
                }
                if transferring {
                    self.record(Event::EnergyTransferStopped(
                        EnergyTransferStoppedReasonEnum::EVSEStopped,
                    ));
                }
                Ok(None)
            }
            ENABLE_CHARGING => {
                let decoded: spec_evse::EnableChargingFields = super::decode_fields(payload()?)?;
                if self.refuses_commands() {
                    return Err(Status::Failure.into());
                }
                // §9.3.9.2's constraint on both currents is "min 0": an EVSE cannot pass a
                // negative current towards the vehicle, and a minimum above the maximum is a
                // window with nothing in it.
                if decoded.minimum_charge_current < 0
                    || decoded.maximum_charge_current < 0
                    || decoded.minimum_charge_current > decoded.maximum_charge_current
                {
                    return Err(Status::ConstraintError.into());
                }
                let minimum = i64::from(decoded.minimum_charge_current);
                let maximum = i64::from(decoded.maximum_charge_current);
                if !self.hooks.enable_charging(minimum, maximum) {
                    return Err(Status::Failure.into());
                }
                self.minimum_charge_current.set(minimum);
                self.maximum_charge_current.set(maximum);
                self.charging_until.set(decoded.charging_enabled_until.0);
                self.resupply();
                Ok(None)
            }
            ENABLE_DISCHARGING => {
                let decoded: spec_evse::EnableDischargingFields = super::decode_fields(payload()?)?;
                if self.refuses_commands() {
                    return Err(Status::Failure.into());
                }
                if decoded.maximum_discharge_current < 0 {
                    return Err(Status::ConstraintError.into());
                }
                let maximum = i64::from(decoded.maximum_discharge_current);
                if !self.hooks.enable_discharging(maximum) {
                    return Err(Status::Failure.into());
                }
                self.maximum_discharge_current.set(maximum);
                self.discharging_until
                    .set(decoded.discharging_enabled_until.0);
                self.resupply();
                Ok(None)
            }
            START_DIAGNOSTICS => {
                // §9.3.9.4.1: "the EVSE SHALL enter a Diagnostics state only if the SupplyState
                // attribute is in the Disabled state" — running self-checks on a circuit that
                // is passing current to a car is not a thing to do.
                if self.supply_state() != SupplyStateEnum::Disabled
                    || !self.hooks.start_diagnostics()
                {
                    return Err(Status::Failure.into());
                }
                self.supply.set(SupplyStateEnum::DisabledDiagnostics);
                Ok(None)
            }
            SET_TARGETS => {
                let decoded: spec_evse::SetTargetsFields<'_> = super::decode_fields(payload()?)?;
                match self.set_targets(decoded.charging_target_schedules) {
                    Status::Success => Ok(None),
                    other => Err(other.into()),
                }
            }
            GET_TARGETS => {
                // §9.3.9.7: one schedule per day that has targets. Days with none are omitted
                // rather than sent empty — an empty schedule is how `SetTargets` *clears* a
                // day, so echoing one back would read as an instruction.
                let full =
                    |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
                let targets = self.targets.borrow();
                full(w.start_structure(tag))?;
                full(w.start_array(Tag::Context(0)))?;
                for (index, day) in DAYS.iter().enumerate() {
                    let Some(day_targets) = targets.get(index) else {
                        continue;
                    };
                    if day_targets.is_empty() {
                        continue;
                    }
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), u64::from(day.bits())))?;
                    full(w.start_array(Tag::Context(1)))?;
                    for target in day_targets {
                        full(target.to_tlv(w, Tag::Anonymous))?;
                    }
                    full(w.end_container())?;
                    full(w.end_container())?;
                }
                full(w.end_container())?;
                full(w.end_container())?;
                Ok(Some(GET_TARGETS_RESPONSE))
            }
            CLEAR_TARGETS => {
                for day in self.targets.borrow_mut().iter_mut() {
                    day.clear();
                }
                self.hooks.targets_changed();
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: EvseHooks, const T: usize> Cluster for EnergyEvse<'_, H, T> {
    const ID: ClusterId = ID;
}
