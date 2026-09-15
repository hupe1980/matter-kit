//! Device Energy Management, cluster `0x0098` (Application Cluster §9.2).
//!
//! > For Energy Smart Appliances (ESA) the definition of being 'smart' mandates that they can
//! > report their current power adjustment capability and have an EMS request a temporary
//! > adjustment.
//!
//! The cluster an energy manager talks to. Everything else in the energy chapter says what an
//! appliance *is* — a car charger, a hot water tank — and this one says what it is willing to
//! have done to it: run at less power for a while, start later, pause, or re-plan around a
//! window of cheap wind.
//!
//! # Seven features, seven negotiating positions
//!
//! §9.2.4 splits flexibility into things an appliance may or may not be able to offer, and the
//! division is physical rather than arbitrary: "typically, appliances with a heating element
//! cannot have their power consumption adjusted and can only be paused or delayed". A washing
//! machine offers `STA` and `PAU`; an inverter-driven heat pump offers `PA`. An EMS reads the
//! feature map and knows which conversation it can have.
//!
//! # The user can always say no
//!
//! `OptOutState` (§9.2.8.8) is the householder's veto, and it is not advisory: every command
//! here carries an `AdjustmentCauseEnum`, and one the opt-out forbids is `CONSTRAINT_ERROR`
//! before anything else is considered. `LocalOptOut` refuses local optimisation and still
//! permits grid optimisation; `GridOptOut` is the mirror; `OptOut` refuses both.
//!
//! # Overlapping adjustments do not each end
//!
//! §9.2.9.1.4 is unusually specific about why:
//!
//! > a battery inverter ESA may be sent a new request every 5 seconds to adjust its discharge
//! > power based on real-time meter readings. Each command may have a 60 second duration, but
//! > this command is superseded after 5 seconds by a new request.
//!
//! So a replacement emits no `PowerAdjustEnd`; only the last one to expire does. A cluster that
//! ended each would fill the event ring twelve times a minute and push everything else out of
//! it.
//!
//! # What lives here and what does not
//!
//! The `Forecast` and `PowerAdjustmentCapability` attributes describe the appliance's own plan,
//! which this cluster cannot size or invent. [`DemHooks`] supplies both — the ranges as data,
//! because the cluster validates against them, and the forecast as TLV, because only the
//! appliance knows how many slots it has. §9.2.5 also puts the meter elsewhere: "This cluster
//! does not report electrical power and electrical energy. Devices that use this cluster SHALL
//! also support the Electrical Power Measurement ... cluster."

use core::cell::{Cell, RefCell};

use crate::clusters::generated::device_energy_management as spec_dem;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::platform::{Duration, Instant};
use crate::tlv::{Tag, TlvList, TlvWriter, ToTlv};

use super::Cluster;

pub use spec_dem::attribute::{
    ABS_MAX_POWER, ABS_MIN_POWER, ESA_CAN_GENERATE, ESA_STATE, ESA_TYPE, FORECAST, OPT_OUT_STATE,
    POWER_ADJUSTMENT_CAPABILITY,
};
pub use spec_dem::command::{
    CANCEL_POWER_ADJUST_REQUEST, CANCEL_REQUEST, MODIFY_FORECAST_REQUEST, PAUSE_REQUEST,
    POWER_ADJUST_REQUEST, REQUEST_CONSTRAINT_BASED_FORECAST, RESUME_REQUEST,
    START_TIME_ADJUST_REQUEST,
};
pub use spec_dem::event::{PAUSED, POWER_ADJUST_END, POWER_ADJUST_START, RESUMED};
pub use spec_dem::{
    AdjustmentCauseEnum, CauseEnum, ConstraintsStruct, ESAStateEnum, ESATypeEnum, ForecastStruct,
    ID, OptOutStateEnum, PICS, PowerAdjustReasonEnum, PowerAdjustStruct, REVISION,
    SlotAdjustmentStruct, feature,
};

/// §9.2.9.6's constraint on `SlotAdjustments`, and §9.2.9.7's on `Constraints`: "max 10".
pub const ADJUSTMENTS_MAX: usize = 10;

/// What the appliance must tell the cluster about the forecast it is running.
///
/// The `Forecast` attribute itself is a list of slots this cluster cannot size, so it is
/// written straight to the wire by [`DemHooks::write_forecast`]. These are the handful of
/// fields §9.2.9 makes the *cluster* check a command against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForecastSummary {
    /// `ForecastID` (§9.2.7.13.1) — what `ModifyForecastRequest` names.
    pub forecast_id: u32,
    /// `StartTime` and `EndTime`, as `epoch-s`.
    pub start_time: u32,
    /// `EndTime`.
    pub end_time: u32,
    /// `EarliestStartTime` (§9.2.7.13.5) — `None` when the forecast cannot be moved earlier.
    pub earliest_start_time: Option<u32>,
    /// `LatestEndTime` (§9.2.7.13.6).
    pub latest_end_time: Option<u32>,
    /// Whether the *active* slot may be paused (§9.2.7.14's `SlotIsPausable`).
    pub slot_is_pausable: bool,
    /// The active slot's `MinPauseDuration` and `MaxPauseDuration`, in seconds.
    pub min_pause_duration: u32,
    /// `MaxPauseDuration`.
    pub max_pause_duration: u32,
    /// `ForecastUpdateReason` (§9.2.7.13.9), which decides whether `CancelRequest` has
    /// anything to cancel.
    pub adjusted: bool,
}

/// What the appliance knows and decides.
pub trait DemHooks {
    /// `ESAType` (§9.2.8.1) — what kind of appliance this is.
    fn esa_type(&self) -> ESATypeEnum;

    /// `ESACanGenerate` (§9.2.8.2) — whether it can export as well as consume.
    fn can_generate(&self) -> bool {
        false
    }

    /// The appliance's own state, before this cluster overlays an adjustment or a pause.
    ///
    /// `Offline` and `Fault` are the appliance's to report and nothing here overrides them:
    /// §9.2.9.1.4 requires "the ESAState is Online" before an adjustment can start at all.
    fn base_state(&self) -> ESAStateEnum;

    /// `AbsMinPower` and `AbsMaxPower` (§9.2.8.3, §9.2.8.4), in mW.
    fn abs_min_power(&self) -> i64;

    /// `AbsMaxPower`.
    fn abs_max_power(&self) -> i64;

    /// `OptOutState` (§9.2.8.8) — the householder's veto.
    fn opt_out_state(&self) -> OptOutStateEnum {
        OptOutStateEnum::NoOptOut
    }

    /// The `PowerAdjustStruct` ranges currently on offer (§9.2.7.11).
    ///
    /// Data rather than TLV, because §9.2.9.1.4 makes this cluster check a request against
    /// them: "the ESA SHALL validate that the Power and Duration specified in the command are
    /// within the limits of its current operation and advertised PowerAdjustmentCapability
    /// attribute". An empty slice is §9.2.7.12's null — nothing is adjustable right now.
    fn power_adjust_ranges(&self) -> &[PowerAdjustStruct] {
        &[]
    }

    /// What the appliance is planning (§9.2.7.13), for the commands that check against it.
    fn forecast(&self) -> Option<ForecastSummary> {
        None
    }

    /// Writes the `Forecast` attribute.
    ///
    /// A forecast is a list of slots with a cost list inside each, which is a shape this
    /// cluster cannot size for every appliance that will ever exist. Writing it here keeps the
    /// slot table where it belongs — with the appliance that computed it.
    fn write_forecast(&self, w: &mut TlvWriter<'_>, tag: Tag) -> crate::error::Result<()> {
        w.null(tag)
    }

    /// §9.2.9.1: run at `power_mw` for `duration_s`. `Err` becomes the command's status.
    fn power_adjust(
        &self,
        power_mw: i64,
        duration_s: u32,
        cause: AdjustmentCauseEnum,
    ) -> Result<(), Status> {
        let _ = (power_mw, duration_s, cause);
        Err(Status::Failure)
    }

    /// Whether a *new* `PowerAdjustRequest` may interrupt one already running (§9.2.9.1.4).
    ///
    /// > If the ESA does not permit this new PowerAdjustmentRequest command to interrupt the
    /// > adjustment that is in progress, it SHALL return BUSY.
    fn may_interrupt_adjustment(&self) -> bool {
        true
    }

    /// The adjustment ended; go back to normal power.
    fn end_power_adjust(&self, cause: CauseEnum) {
        let _ = cause;
    }

    /// §9.2.9.3: shift the whole forecast to start at `requested_start_time`.
    fn adjust_start_time(
        &self,
        requested_start_time: u32,
        cause: AdjustmentCauseEnum,
    ) -> Result<(), Status> {
        let _ = (requested_start_time, cause);
        Err(Status::Failure)
    }

    /// §9.2.9.4: pause for `duration_s`.
    fn pause(&self, duration_s: u32, cause: AdjustmentCauseEnum) -> Result<(), Status> {
        let _ = (duration_s, cause);
        Err(Status::Failure)
    }

    /// §9.2.9.5: resume.
    ///
    /// > the ESA MAY decide not to resume immediately if the MinPauseDuration has not yet
    /// > elapsed. This behavior is manufacturer specific.
    fn resume(&self) -> Result<(), Status> {
        Ok(())
    }

    /// §9.2.9.6: apply the slot adjustments, or reject the whole list.
    ///
    /// > If for any reason the ESA cannot accept the entire requested forecast adjustments then
    /// > it SHALL reject the entire command.
    fn modify_forecast(
        &self,
        adjustments: &[SlotAdjustmentStruct],
        cause: AdjustmentCauseEnum,
    ) -> Result<(), Status> {
        let _ = (adjustments, cause);
        Err(Status::Failure)
    }

    /// §9.2.9.7: re-plan around the constraints.
    fn constraint_based_forecast(
        &self,
        constraints: &[ConstraintsStruct],
        cause: AdjustmentCauseEnum,
    ) -> Result<(), Status> {
        let _ = (constraints, cause);
        Err(Status::Failure)
    }

    /// §9.2.9.8: forget every adjustment and re-plan from the appliance's own preferences.
    fn cancel_adjustments(&self) -> Result<(), Status> {
        Ok(())
    }
}

/// An event this cluster produced, for the device to record in its own store (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// §9.2.10.1 — the adjustment began, carrying its power and duration.
    PowerAdjustStart,
    /// §9.2.10.2 — the adjustment ended, and why.
    PowerAdjustEnd(CauseEnum),
    /// §9.2.10.3 — the appliance paused.
    Paused,
    /// §9.2.10.4 — it resumed, however that came about.
    Resumed(CauseEnum),
}

/// Device Energy Management over one Energy Smart Appliance.
#[derive(Debug)]
pub struct DeviceEnergyManagement<'a, H: DemHooks> {
    hooks: &'a H,
    feature_map: u32,
    /// The reason a power adjustment is running, or `NoAdjustment` (§9.2.7.12.1).
    adjust_reason: Cell<PowerAdjustReasonEnum>,
    adjust_until: Cell<Option<Instant>>,
    paused_until: Cell<Option<Instant>>,
    events: RefCell<heapless::Vec<Event, 8>>,
}

impl<'a, H: DemHooks> DeviceEnergyManagement<'a, H> {
    /// A cluster over `hooks`.
    #[must_use]
    pub fn new(hooks: &'a H, feature_map: u32) -> Self {
        Self {
            hooks,
            feature_map,
            adjust_reason: Cell::new(PowerAdjustReasonEnum::NoAdjustment),
            adjust_until: Cell::new(None),
            paused_until: Cell::new(None),
            events: RefCell::new(heapless::Vec::new()),
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<8, 8, 0, 4>> {
        Conforming::new(&spec_dem::CLUSTER, feature_map, optional)
    }

    /// `ESAState` (§9.2.8.3).
    ///
    /// The appliance's own state wins whenever it is not simply running: §9.2.9.4.3 says that
    /// if "the ESA develops a fault whilst Paused, the ESAState SHALL be set to Fault", so a
    /// cluster that reported `Paused` over the top of a fault would hide it from the one client
    /// that could do something about it.
    #[must_use]
    pub fn state(&self) -> ESAStateEnum {
        let base = self.hooks.base_state();
        if base != ESAStateEnum::Online {
            return base;
        }
        if self.paused_until.get().is_some() {
            return ESAStateEnum::Paused;
        }
        if self.adjust_reason.get() != PowerAdjustReasonEnum::NoAdjustment {
            return ESAStateEnum::PowerAdjustActive;
        }
        ESAStateEnum::Online
    }

    /// `PowerAdjustmentCapability`'s `Cause` field (§9.2.7.12.1).
    #[must_use]
    pub fn adjust_reason(&self) -> PowerAdjustReasonEnum {
        self.adjust_reason.get()
    }

    /// When [`DeviceEnergyManagement::poll`] next has something to do.
    #[must_use]
    pub fn wake_at(&self) -> Option<Instant> {
        match (self.adjust_until.get(), self.paused_until.get()) {
            (Some(a), Some(p)) => Some(if a < p { a } else { p }),
            (Some(a), None) => Some(a),
            (None, Some(p)) => Some(p),
            (None, None) => None,
        }
    }

    /// Ends an adjustment or a pause whose duration has run out.
    pub fn poll(&self, now: Instant) {
        if let Some(until) = self.adjust_until.get()
            && now >= until
        {
            // §9.2.9.1.4: "After the elapsed duration, the ESA SHALL revert to normal (or idle)
            // power levels. The ESA SHALL also generate a PowerAdjustEnd Event with a cause
            // code to indicate a 'Normal completion'."
            self.finish_adjust(CauseEnum::NormalCompletion);
        }
        if let Some(until) = self.paused_until.get()
            && now >= until
        {
            // §9.2.9.4.3: "When the Pause timer expires the ESA SHALL automatically resume
            // operation. When it does this, then it SHALL also generate a Resumed Event."
            self.paused_until.set(None);
            let _ = self.hooks.resume();
            self.push(Event::Resumed(CauseEnum::NormalCompletion));
        }
    }

    /// The householder changed their mind, or the appliance failed (§9.2.9.1.4).
    ///
    /// > If during the power adjustment session a failure or other condition occurs (such as the
    /// > user deciding to opt-out by updating the OptOutState) then the ESA SHALL generate a
    /// > PowerAdjustEnd Event to indicate the end of the session, with the appropriate cause
    /// > code.
    pub fn abort(&self, cause: CauseEnum) {
        if self.paused_until.take().is_some() {
            // §9.2.9.4.3: "On change of ESAState (from Paused to another state), the ESA SHALL
            // generate a Resumed Event."
            self.push(Event::Resumed(cause));
        }
        self.finish_adjust(cause);
    }

    /// Takes the event records the cluster has collected.
    pub fn take_events(&self) -> heapless::Vec<Event, 8> {
        core::mem::take(&mut self.events.borrow_mut())
    }

    fn push(&self, event: Event) {
        let mut events = self.events.borrow_mut();
        if events.is_full() {
            events.remove(0);
        }
        let _ = events.push(event);
    }

    fn finish_adjust(&self, cause: CauseEnum) {
        if self.adjust_reason.get() == PowerAdjustReasonEnum::NoAdjustment {
            return;
        }
        self.adjust_reason.set(PowerAdjustReasonEnum::NoAdjustment);
        self.adjust_until.set(None);
        self.hooks.end_power_adjust(cause);
        self.push(Event::PowerAdjustEnd(cause));
    }

    /// §9.2.9 makes every command conditional on a feature: `PA` for the two power-adjust
    /// commands, `STA` for the start-time one, `PAU` for the pair, `FA` and `CON` for the
    /// forecast ones.
    ///
    /// The derived descriptor already leaves an unsupported command out of
    /// `AcceptedCommandList`, so the server refuses it before this handler sees it. This is
    /// the second half of the same fact, for a handler used without that descriptor — and it
    /// is not redundant, because the feature map here and the one the descriptor was derived
    /// from are two separate arguments a device can get out of step.
    const fn supports(&self, bit: u32) -> bool {
        self.feature_map & bit != 0
    }

    /// §9.2.8.8: whether `OptOutState` permits an adjustment made for `cause`.
    ///
    /// The householder's veto is per *reason*: someone who has opted out of grid optimisation
    /// may still want their own solar used, and a cluster that treated the opt-out as a single
    /// switch would take that away.
    fn permits(&self, cause: AdjustmentCauseEnum) -> bool {
        match (self.hooks.opt_out_state(), cause) {
            (OptOutStateEnum::NoOptOut, _) => true,
            (OptOutStateEnum::OptOut, _) => false,
            (OptOutStateEnum::LocalOptOut, cause) => {
                cause != AdjustmentCauseEnum::LocalOptimization
            }
            (OptOutStateEnum::GridOptOut, cause) => cause != AdjustmentCauseEnum::GridOptimization,
        }
    }
}

/// Reads at most `N` structures out of a list, refusing one that is longer or malformed.
fn collect<'a, T: crate::tlv::FromTlv<'a> + Copy, const N: usize>(
    list: TlvList<'a, T>,
) -> Result<heapless::Vec<T, N>, Status> {
    let mut out: heapless::Vec<T, N> = heapless::Vec::new();
    for entry in list.iter() {
        let entry = entry.map_err(|_| Status::ConstraintError)?;
        // §9.2.9.6's constraint is "max 10". A longer list is a request the specification does
        // not permit a client to send, not a device that ran out of room.
        out.push(entry).map_err(|_| Status::ConstraintError)?;
    }
    Ok(out)
}

impl<H: DemHooks> ClusterHandler for DeviceEnergyManagement<'_, H> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            ESA_TYPE => full(w.unsigned(tag, u64::from(self.hooks.esa_type().value()))),
            ESA_CAN_GENERATE => full(w.bool(tag, self.hooks.can_generate())),
            ESA_STATE => full(w.unsigned(tag, u64::from(self.state().value()))),
            ABS_MIN_POWER => full(w.signed(tag, self.hooks.abs_min_power())),
            ABS_MAX_POWER => full(w.signed(tag, self.hooks.abs_max_power())),
            POWER_ADJUSTMENT_CAPABILITY => {
                let ranges = self.hooks.power_adjust_ranges();
                // §9.2.7.12: null when the appliance is offering nothing right now, which is a
                // different thing from an empty list of ranges.
                if ranges.is_empty() {
                    return full(w.null(tag));
                }
                full(w.start_structure(tag))?;
                full(w.start_array(Tag::Context(0)))?;
                for range in ranges {
                    full(range.to_tlv(w, Tag::Anonymous))?;
                }
                full(w.end_container())?;
                // §9.2.9.1.4: "the PowerAdjustmentCapability attribute SHALL be updated to set
                // the Cause value from the Cause field of this command" — so the cause belongs
                // to the cluster, and the ranges to the appliance.
                full(w.unsigned(Tag::Context(1), u64::from(self.adjust_reason.get().value())))?;
                full(w.end_container())
            }
            FORECAST => self
                .hooks
                .write_forecast(w, tag)
                .map_err(|_| Status::ResourceExhausted),
            OPT_OUT_STATE => full(w.unsigned(tag, u64::from(self.hooks.opt_out_state().value()))),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let payload = || fields.ok_or(StatusIb::from(Status::InvalidCommand));
        match resolved.command.id {
            POWER_ADJUST_REQUEST => {
                if !self.supports(feature::POWER_ADJUSTMENT) {
                    return Err(Status::UnsupportedCommand.into());
                }
                let decoded: spec_dem::PowerAdjustRequestFields = super::decode_fields(payload()?)?;
                if !self.permits(decoded.cause) {
                    return Err(Status::ConstraintError.into());
                }
                // §9.2.9.1.4: "the ESAState is Online". `PowerAdjustActive` is the one exception
                // — that is the overlapping-request case below.
                let running = self.adjust_reason.get() != PowerAdjustReasonEnum::NoAdjustment;
                if self.hooks.base_state() != ESAStateEnum::Online {
                    return Err(Status::Failure.into());
                }
                // "the ESA SHALL validate that the Power and Duration specified in the command
                // are within the limits of its ... advertised PowerAdjustmentCapability".
                let power = i64::from(decoded.power);
                let fits = self.hooks.power_adjust_ranges().iter().any(|range| {
                    power >= i64::from(range.min_power)
                        && power <= i64::from(range.max_power)
                        && decoded.duration >= range.min_duration
                        && decoded.duration <= range.max_duration
                });
                if !fits {
                    return Err(Status::ConstraintError.into());
                }
                if running && !self.hooks.may_interrupt_adjustment() {
                    // §9.2.9.1.4: "If the ESA does not permit this new PowerAdjustmentRequest
                    // command to interrupt the adjustment that is in progress, it SHALL return
                    // BUSY."
                    return Err(Status::Busy.into());
                }
                self.hooks
                    .power_adjust(power, decoded.duration, decoded.cause)
                    .map_err(StatusIb::from)?;
                self.adjust_reason.set(match decoded.cause {
                    AdjustmentCauseEnum::LocalOptimization => {
                        PowerAdjustReasonEnum::LocalOptimizationAdjustment
                    }
                    AdjustmentCauseEnum::GridOptimization => {
                        PowerAdjustReasonEnum::GridOptimizationAdjustment
                    }
                });
                self.adjust_until
                    .set(Some(ctx.now.saturating_add(Duration::from_secs(
                        u64::from(decoded.duration),
                    ))));
                // "Note that if the new command is accepted, then the ESA SHALL NOT generate a
                // new PowerAdjustEnd Event until the new duration has elapsed" — and no new
                // *Start* either, or a battery inverter retuned every five seconds would emit
                // twelve events a minute and push everything else out of the event ring.
                if !running {
                    self.push(Event::PowerAdjustStart);
                }
                Ok(None)
            }
            CANCEL_POWER_ADJUST_REQUEST => {
                if !self.supports(feature::POWER_ADJUSTMENT) {
                    return Err(Status::UnsupportedCommand.into());
                }
                // §9.2.9.2.1: "If the ESAState is not PowerAdjustActive, then the command SHALL
                // be rejected with INVALID_IN_STATE."
                if self.adjust_reason.get() == PowerAdjustReasonEnum::NoAdjustment {
                    return Err(Status::InvalidInState.into());
                }
                self.finish_adjust(CauseEnum::Cancelled);
                Ok(None)
            }
            START_TIME_ADJUST_REQUEST => {
                if !self.supports(feature::START_TIME_ADJUSTMENT) {
                    return Err(Status::UnsupportedCommand.into());
                }
                let decoded: spec_dem::StartTimeAdjustRequestFields =
                    super::decode_fields(payload()?)?;
                if !self.permits(decoded.cause) {
                    return Err(Status::ConstraintError.into());
                }
                let Some(forecast) = self.hooks.forecast() else {
                    return Err(Status::Failure.into());
                };
                // §9.2.9.3.1: "This value SHALL be after the EarliestStartTime in the Forecast
                // attribute. The new EndTime, that can be computed from the RequestedStartTime
                // and the Forecast sequence duration, SHALL be before the LatestEndTime."
                let span = forecast.end_time.saturating_sub(forecast.start_time);
                let new_end = decoded.requested_start_time.saturating_add(span);
                let too_early = forecast
                    .earliest_start_time
                    .is_some_and(|earliest| decoded.requested_start_time < earliest);
                let too_late = forecast
                    .latest_end_time
                    .is_some_and(|latest| new_end > latest);
                if too_early || too_late {
                    return Err(Status::ConstraintError.into());
                }
                self.hooks
                    .adjust_start_time(decoded.requested_start_time, decoded.cause)
                    .map_err(StatusIb::from)?;
                Ok(None)
            }
            PAUSE_REQUEST => {
                if !self.supports(feature::PAUSABLE) {
                    return Err(Status::UnsupportedCommand.into());
                }
                let decoded: spec_dem::PauseRequestFields = super::decode_fields(payload()?)?;
                if !self.permits(decoded.cause) {
                    return Err(Status::ConstraintError.into());
                }
                let Some(forecast) = self.hooks.forecast() else {
                    return Err(Status::Failure.into());
                };
                // §9.2.9.4.3: "If the ESA SlotIsPausable field is false for the
                // ActiveSlotNumber, then the command SHALL be rejected with FAILURE." A spin
                // cycle cannot be stopped half way; a water-heating step can.
                if !forecast.slot_is_pausable {
                    return Err(Status::Failure.into());
                }
                // "The ESA SHALL validate that the Duration field is within the range of
                // MinPauseDuration and MaxPauseDuration. If it is outside of this range then
                // the command SHALL be rejected with CONSTRAINT_ERROR."
                if decoded.duration < forecast.min_pause_duration
                    || decoded.duration > forecast.max_pause_duration
                {
                    return Err(Status::ConstraintError.into());
                }
                // "the OptOutState is Online or PowerAdjustActive" — the specification names
                // `OptOutState` there, but the states it lists are `ESAState`'s, and an
                // appliance that is Offline or in Fault cannot be paused in any case.
                let state = self.state();
                if !matches!(
                    state,
                    ESAStateEnum::Online | ESAStateEnum::PowerAdjustActive | ESAStateEnum::Paused
                ) {
                    return Err(Status::Failure.into());
                }
                self.hooks
                    .pause(decoded.duration, decoded.cause)
                    .map_err(StatusIb::from)?;
                // "If a further Pause Request is received in the same forecast slot whilst
                // already in the paused state ... the pause timer SHALL be extended by the new
                // Duration" — extended, not replaced.
                let extra = Duration::from_secs(u64::from(decoded.duration));
                let already_paused = self.paused_until.get();
                self.paused_until.set(Some(match already_paused {
                    Some(until) => until.saturating_add(extra),
                    None => ctx.now.saturating_add(extra),
                }));
                if already_paused.is_none() {
                    self.push(Event::Paused);
                }
                Ok(None)
            }
            RESUME_REQUEST => {
                if !self.supports(feature::PAUSABLE) {
                    return Err(Status::UnsupportedCommand.into());
                }
                // §9.2.9.5.1: "the command SHALL be rejected with the response INVALID_IN_STATE
                // if the ESA is not currently Paused".
                if self.paused_until.get().is_none() {
                    return Err(Status::InvalidInState.into());
                }
                self.hooks.resume().map_err(StatusIb::from)?;
                self.paused_until.set(None);
                self.push(Event::Resumed(CauseEnum::Cancelled));
                Ok(None)
            }
            MODIFY_FORECAST_REQUEST => {
                if !self.supports(feature::FORECAST_ADJUSTMENT) {
                    return Err(Status::UnsupportedCommand.into());
                }
                let decoded: spec_dem::ModifyForecastRequestFields<'_> =
                    super::decode_fields(payload()?)?;
                if !self.permits(decoded.cause) {
                    return Err(Status::ConstraintError.into());
                }
                let adjustments: heapless::Vec<SlotAdjustmentStruct, ADJUSTMENTS_MAX> =
                    collect(decoded.slot_adjustments).map_err(StatusIb::from)?;
                // §9.2.9.6.4: "otherwise if the ForecastID is valid ... the command status
                // returned SHALL be SUCCESS, otherwise the command SHALL be rejected with
                // FAILURE". A stale id means the EMS optimised a plan the appliance has already
                // replaced, and applying it would undo whatever replaced it.
                let Some(forecast) = self.hooks.forecast() else {
                    return Err(Status::Failure.into());
                };
                if forecast.forecast_id != decoded.forecast_id {
                    return Err(Status::Failure.into());
                }
                self.hooks
                    .modify_forecast(&adjustments, decoded.cause)
                    .map_err(StatusIb::from)?;
                Ok(None)
            }
            REQUEST_CONSTRAINT_BASED_FORECAST => {
                if !self.supports(feature::CONSTRAINT_BASED_ADJUSTMENT) {
                    return Err(Status::UnsupportedCommand.into());
                }
                let decoded: spec_dem::RequestConstraintBasedForecastFields<'_> =
                    super::decode_fields(payload()?)?;
                if !self.permits(decoded.cause) {
                    return Err(Status::ConstraintError.into());
                }
                let constraints: heapless::Vec<ConstraintsStruct, ADJUSTMENTS_MAX> =
                    collect(decoded.constraints).map_err(StatusIb::from)?;
                self.hooks
                    .constraint_based_forecast(&constraints, decoded.cause)
                    .map_err(StatusIb::from)?;
                Ok(None)
            }
            CANCEL_REQUEST => {
                // §9.2.9's conformance for this one is `STA | FA | CON`: it cancels whatever
                // those three set, so an appliance with none of them has nothing to cancel.
                if !(self.supports(feature::START_TIME_ADJUSTMENT)
                    || self.supports(feature::FORECAST_ADJUSTMENT)
                    || self.supports(feature::CONSTRAINT_BASED_ADJUSTMENT))
                {
                    return Err(Status::UnsupportedCommand.into());
                }
                // §9.2.9.8.1: "If the ESA ForecastUpdateReason was already Internal
                // Optimization, then the command SHALL be rejected with INVALID_IN_STATE."
                // There is nothing to cancel: the plan is already the appliance's own.
                let adjusted = self.hooks.forecast().is_some_and(|f| f.adjusted);
                if !adjusted {
                    return Err(Status::InvalidInState.into());
                }
                self.hooks.cancel_adjustments().map_err(StatusIb::from)?;
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: DemHooks> Cluster for DeviceEnergyManagement<'_, H> {
    const ID: ClusterId = ID;
}
