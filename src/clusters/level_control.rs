//! Level Control, cluster `0x0008` (Application Cluster §1.6).
//!
//! > This command will move the device to the specified level.
//!
//! Dimming. Also volume, fan speed, and how far a blind is open — §1.6.6.2 is careful to say
//! "the meaning of 'level' is device dependent".
//!
//! # Two sets of commands, and the difference is the whole cluster
//!
//! `MoveToLevel` and `MoveToLevelWithOnOff` take identical fields and do nearly identical
//! things. §1.6.4.1.2 says what separates them:
//!
//! > The first set is used to maintain independence between the CurrentLevel and OnOff
//! > attributes ... As examples, this represents the behavior of a volume control with a
//! > separate mute button, or a 'turn to set level and press to turn on/off' light dimmer.
//! > The second set is used to link the CurrentLevel and OnOff attributes.
//!
//! A device that implemented one set and aliased the other would be one of those two products
//! pretending to be the other.
//!
//! # A command to a light that is off
//!
//! §1.6.6.9: a `Move`, `MoveToLevel`, `Step` or `Stop` — the ones *without* On/Off — does
//! nothing at all when the On/Off cluster on the same endpoint says the device is off, unless
//! `ExecuteIfOff` is set. This is the rule that keeps a dimmer from silently winding a lamp up
//! while it is switched off, so that turning it on later blinds somebody.
//!
//! The bit is not read from the attribute directly: every affected command carries
//! `OptionsMask` and `OptionsOverride`, and the value in force is the attribute with the
//! masked bits replaced. A client can therefore say "this once" without writing a
//! commissioning-time attribute.
//!
//! # What this cluster does not do
//!
//! Fade a lamp when the *On/Off* cluster is commanded. §1.6.4.1 is explicit that the coupling
//! is the product's choice — "dependencies MAY be introduced between them. Facilities are
//! provided to introduce dependencies if required" — so [`LevelControl::on_off_changed`] is
//! the facility, called by the device from its own `OnOffHooks::set`, and nothing happens
//! unless it does.

use core::cell::{Cell, RefCell};

use crate::clusters::generated::level_control as spec_level;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb, WriteOp,
};
use crate::platform::{Duration, Instant};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use super::Cluster;

pub use spec_level::attribute::{
    CURRENT_FREQUENCY, CURRENT_LEVEL, DEFAULT_MOVE_RATE, MAX_FREQUENCY, MAX_LEVEL, MIN_FREQUENCY,
    MIN_LEVEL, OFF_TRANSITION_TIME, ON_LEVEL, ON_OFF_TRANSITION_TIME, ON_TRANSITION_TIME, OPTIONS,
    REMAINING_TIME, START_UP_CURRENT_LEVEL,
};
pub use spec_level::command::{
    MOVE, MOVE_TO_CLOSEST_FREQUENCY, MOVE_TO_LEVEL, MOVE_TO_LEVEL_WITH_ON_OFF, MOVE_WITH_ON_OFF,
    STEP, STEP_WITH_ON_OFF, STOP, STOP_WITH_ON_OFF,
};
pub use spec_level::{ID, MoveModeEnum, OptionsBitmap, PICS, REVISION, StepModeEnum, feature};

/// §1.6.6.3's unit: `RemainingTime` and every `TransitionTime` field are in tenths of a second.
pub const TICK: Duration = Duration::from_millis(100);

/// §1.6.4.2's lighting range. `0x00` "SHALL NOT be used"; `0x01` is the minimum a device can
/// attain and `0xFE` the maximum.
pub const LIGHTING_MIN: u8 = 1;
/// The top of §1.6.4.2's range.
pub const LIGHTING_MAX: u8 = 254;

/// How many ticks one `poll` catches up on — an hour, bounded so a device that slept for a
/// week does not spin through a week of hundredth-second steps.
const MAX_CATCH_UP: u32 = 36_000;

/// What the device does when the level changes.
pub trait LevelControlHooks {
    /// The level changed.
    ///
    /// `None` is §1.6.4.2's null — "A value of null SHALL represent an undefined value" — which
    /// a device reports before it knows its own level, not as a synonym for zero.
    ///
    /// Called for every step of a transition, because a transition is what the hardware is for:
    /// §1.6.7.1.1 asks that "the movement SHALL be as continuous as technically practical, i.e.,
    /// not a step function".
    fn level(&self, level: Option<u8>);

    /// §1.6.7.5: change to `frequency`, or to the closest the device can generate.
    ///
    /// Returns whether it could. "If the device cannot approximate the frequency, then it SHALL
    /// return a default response with an error code of CONSTRAINT_ERROR. Determining if a
    /// requested frequency can be approximated by a supported frequency is a
    /// manufacturer-specific decision" — which is why it is the product's answer and not this
    /// cluster's. The default refuses, which is right for a device with no `Frequency` feature.
    fn frequency(&self, frequency: u16) -> bool {
        let _ = frequency;
        false
    }
}

/// What Level Control needs from the On/Off cluster on the same endpoint.
///
/// Two different questions, and §1.6 asks them at different moments: whether the device is on
/// (§1.6.6.9's gate, before a command without On/Off runs) and turning it on or off (§1.6.7.6,
/// as a 'with On/Off' command crosses the minimum level).
pub trait OnOffState {
    /// Whether an On/Off cluster exists on this endpoint at all.
    ///
    /// §1.6.6.9's gate needs all four of its criteria, and this is the second. An endpoint with
    /// no On/Off cluster never blocks a command, which is not the same as one whose lamp
    /// happens to be on.
    fn present(&self) -> bool {
        true
    }

    /// `OnOff`, as the cluster on this endpoint reports it.
    fn is_on(&self) -> bool;

    /// §1.6.7.6: set `OnOff` because the level crossed the minimum.
    ///
    /// §1.6.4.1.4 makes this update `GlobalSceneControl` too, which is why it is a distinct
    /// entry point rather than a plain setter: a level command that turns a light on is one of
    /// the commands §1.5.6.3 lists as marking the global scene stale.
    fn set_from_level(&self, on: bool);
}

/// An endpoint with no On/Off cluster.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOnOff;

impl OnOffState for NoOnOff {
    fn present(&self) -> bool {
        false
    }

    fn is_on(&self) -> bool {
        // There is no `OnOff` attribute to report, and saying "on" would be a convenient lie:
        // §1.6.6.9's gate is closed by *present and off*, so `present` is what has to carry
        // the fact. A second encoding of it here would mean an implementor who got `present`
        // wrong still behaved correctly, which is a rule nothing can test.
        false
    }

    fn set_from_level(&self, _on: bool) {}
}

/// What the level is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Motion {
    /// Nothing; `RemainingTime` is zero.
    Idle,
    /// §1.6.7.1 — a timed move to a level.
    Transition {
        from: u8,
        to: u8,
        /// Total duration in ticks (tenths of a second); zero means "as fast as it is able".
        ticks: u32,
        elapsed: u32,
        with_on_off: bool,
    },
    /// §1.6.7.2 — an open-ended move at a rate, until a boundary or a `Stop`.
    Move {
        up: bool,
        /// Units per second.
        rate: u8,
        /// Accumulated hundredths of a unit, so a slow rate still moves.
        fraction: u32,
        with_on_off: bool,
    },
}

#[derive(Debug)]
struct State {
    level: Option<u8>,
    motion: Motion,
    next_tick: Option<Instant>,
}

/// Level Control, with the device's hooks and whatever On/Off cluster shares the endpoint.
#[derive(Debug)]
pub struct LevelControl<'a, H: LevelControlHooks, O: OnOffState = NoOnOff> {
    hooks: &'a H,
    on_off: &'a O,
    feature_map: u32,
    min_level: u8,
    max_level: u8,
    state: RefCell<State>,
    options: Cell<OptionsBitmap>,
    on_off_transition_time: Cell<u16>,
    on_level: Cell<Option<u8>>,
    on_transition_time: Cell<Option<u16>>,
    off_transition_time: Cell<Option<u16>>,
    default_move_rate: Cell<Option<u8>>,
    start_up_current_level: Cell<Option<u8>>,
    frequency: Cell<u16>,
    min_frequency: u16,
    max_frequency: u16,
    /// Whether the motion in progress was started by a 'with On/Off' command, so that
    /// §1.6.7.6's "set OnOff to FALSE" applies when it lands on the minimum.
    with_on_off_pending: Cell<bool>,
}

impl<'a, H: LevelControlHooks> LevelControl<'a, H, NoOnOff> {
    /// A cluster on an endpoint with no On/Off — a volume control, say.
    #[must_use]
    pub fn new(hooks: &'a H, feature_map: u32) -> Self {
        Self::with_on_off(hooks, &NoOnOff, feature_map)
    }
}

impl<'a, H: LevelControlHooks, O: OnOffState> LevelControl<'a, H, O> {
    /// A cluster coupled to the On/Off cluster `on_off` on the same endpoint.
    #[must_use]
    pub fn with_on_off(hooks: &'a H, on_off: &'a O, feature_map: u32) -> Self {
        // §1.6.6.4 and §1.6.6.5: "This value is constrained by all lighting device types to 1
        // ... when the Lighting feature is supported this value SHALL be 1", and likewise 254
        // for the maximum. A device without Lighting may narrow them with `with_range`.
        let (min_level, max_level) = (LIGHTING_MIN, LIGHTING_MAX);
        Self {
            hooks,
            on_off,
            feature_map,
            min_level,
            max_level,
            state: RefCell::new(State {
                level: None,
                motion: Motion::Idle,
                next_tick: None,
            }),
            options: Cell::new(OptionsBitmap::empty()),
            on_off_transition_time: Cell::new(0),
            on_level: Cell::new(None),
            on_transition_time: Cell::new(None),
            off_transition_time: Cell::new(None),
            default_move_rate: Cell::new(None),
            start_up_current_level: Cell::new(None),
            frequency: Cell::new(0),
            min_frequency: 0,
            max_frequency: 0,
            with_on_off_pending: Cell::new(false),
        }
    }

    /// The same cluster over a narrower range (§1.6.6.4, §1.6.6.5).
    ///
    /// Only for a device *without* the Lighting feature: with it, the specification fixes the
    /// range at 1..=254, and a lighting device that narrowed it would report a `MinLevel` its
    /// own device type forbids.
    #[must_use]
    pub fn with_range(mut self, min_level: u8, max_level: u8) -> Self {
        if self.feature_map & feature::LIGHTING == 0 && min_level <= max_level {
            self.min_level = min_level;
            self.max_level = max_level;
        }
        self
    }

    /// The same cluster with the `Frequency` feature's range (§1.6.6.7, §1.6.6.8).
    #[must_use]
    pub const fn with_frequency(mut self, min: u16, max: u16) -> Self {
        self.min_frequency = min;
        self.max_frequency = max;
        self
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<14, 9, 0, 0>> {
        Conforming::new(&spec_level::CLUSTER, feature_map, optional)
    }

    /// Everything §1.6.6 leaves to the product.
    pub const WITH_ALL_OPTIONAL: Optional<'static> = Optional {
        attributes: &[
            MIN_LEVEL,
            MAX_LEVEL,
            ON_OFF_TRANSITION_TIME,
            ON_TRANSITION_TIME,
            OFF_TRANSITION_TIME,
            DEFAULT_MOVE_RATE,
        ],
        commands: &[],
        events: &[],
    };

    /// Just the two range attributes, which a lighting device type requires.
    pub const WITH_RANGE: Optional<'static> = Optional {
        attributes: &[MIN_LEVEL, MAX_LEVEL],
        commands: &[],
        events: &[],
    };

    /// §1.6.6.15's start-up behaviour.
    ///
    /// | `StartUpCurrentLevel` | what `CurrentLevel` becomes |
    /// |---|---|
    /// | 0 | the minimum the device permits |
    /// | null | `previous` — what it was before the power cut |
    /// | anything else | that value |
    ///
    /// `previous` is the device's to remember; this cluster persists nothing. A device that
    /// stores nothing passes `None`, which is the null level — honest for a lamp that does not
    /// know how bright it was.
    pub fn start(&self, previous: Option<u8>) {
        let level = match self.start_up_current_level.get() {
            Some(0) => Some(self.min_level),
            Some(other) => Some(other.clamp(self.min_level, self.max_level)),
            None => previous.map(|level| level.clamp(self.min_level, self.max_level)),
        };
        self.state.borrow_mut().level = level;
        self.hooks.level(level);
    }

    /// `CurrentLevel` (§1.6.6.2).
    #[must_use]
    pub fn level(&self) -> Option<u8> {
        self.state.borrow().level
    }

    /// `RemainingTime` (§1.6.6.3), in tenths of a second.
    #[must_use]
    pub fn remaining_time(&self) -> u16 {
        match self.state.borrow().motion {
            Motion::Idle => 0,
            Motion::Transition { ticks, elapsed, .. } => {
                u16::try_from(ticks.saturating_sub(elapsed)).unwrap_or(u16::MAX)
            }
            // §1.6.7.2 has no end: a Move runs to a boundary. The time to that boundary is
            // what remains, which is what a client asking "how long" wants to know.
            Motion::Move { up, rate, .. } => {
                let level = self.state.borrow().level.unwrap_or(self.min_level);
                let distance = if up {
                    u32::from(self.max_level.saturating_sub(level))
                } else {
                    u32::from(level.saturating_sub(self.min_level))
                };
                // Rounded up, so "one tenth left" never reports zero — a client polling
                // `RemainingTime` would otherwise see the move finish before it did.
                let rate = u32::from(rate);
                let Some(tenths) = distance
                    .saturating_mul(10)
                    .saturating_add(rate.saturating_sub(1))
                    .checked_div(rate)
                else {
                    return 0;
                };
                u16::try_from(tenths).unwrap_or(u16::MAX)
            }
        }
    }

    /// `MinLevel` (§1.6.6.4).
    #[must_use]
    pub const fn min_level(&self) -> u8 {
        self.min_level
    }

    /// `MaxLevel` (§1.6.6.5).
    #[must_use]
    pub const fn max_level(&self) -> u8 {
        self.max_level
    }

    /// `Options` (§1.6.6.9).
    #[must_use]
    pub fn options(&self) -> OptionsBitmap {
        self.options.get()
    }

    /// `OnLevel` (§1.6.6.11) — the level an `On` command restores, or null for none.
    #[must_use]
    pub fn on_level(&self) -> Option<u8> {
        self.on_level.get()
    }

    /// Sets `OnLevel` without a write interaction, for a device with a fixed one.
    pub fn set_on_level(&self, level: Option<u8>) {
        self.on_level.set(level);
    }

    /// Sets `StartUpCurrentLevel` (§1.6.6.15) without a write interaction.
    pub fn set_start_up_level(&self, level: Option<u8>) {
        self.start_up_current_level.set(level);
    }

    /// When [`LevelControl::poll`] next has something to do.
    ///
    /// `None` while nothing is moving, which is the ordinary case — a lamp sitting at a level
    /// needs no clock, and an intermittently connected device can sleep.
    #[must_use]
    pub fn wake_at(&self) -> Option<Instant> {
        self.state.borrow().next_tick
    }

    /// Advances whatever is in motion.
    ///
    /// Catches up on elapsed time rather than counting calls, so a device that polls late
    /// arrives at the level it promised rather than however many ticks behind.
    pub fn poll(&self, now: Instant) {
        let (level, finished) = {
            let mut state = self.state.borrow_mut();
            let Some(mut due) = state.next_tick else {
                return;
            };
            if now < due {
                return;
            }
            let mut ticks = 0u32;
            while now >= due && ticks < MAX_CATCH_UP && state.motion != Motion::Idle {
                ticks = ticks.saturating_add(1);
                due = due.saturating_add(TICK);
                self.advance(&mut state);
            }
            let finished = state.motion == Motion::Idle;
            state.next_tick = if finished { None } else { Some(due) };
            (state.level, finished)
        };
        self.hooks.level(level);
        if finished {
            self.settle(level);
        }
    }

    /// One tick of whatever is in motion. `state` is already borrowed.
    fn advance(&self, state: &mut State) {
        match &mut state.motion {
            Motion::Idle => {}
            Motion::Transition {
                from,
                to,
                ticks,
                elapsed,
                ..
            } => {
                *elapsed = elapsed.saturating_add(1);
                if *elapsed >= *ticks {
                    state.level = Some(*to);
                    state.motion = Motion::Idle;
                } else {
                    // §1.6.7.1.1: "as continuous as technically practical, i.e., not a step
                    // function" — so the level is interpolated every tenth of a second rather
                    // than jumped at the end.
                    let span = i32::from(*to).saturating_sub(i32::from(*from));
                    let moved = span
                        .saturating_mul(i32::try_from(*elapsed).unwrap_or(i32::MAX))
                        .checked_div(i32::try_from(*ticks).unwrap_or(1))
                        .unwrap_or(span);
                    let next = i32::from(*from).saturating_add(moved);
                    state.level = Some(u8::try_from(next.clamp(0, 255)).unwrap_or(*to));
                }
            }
            Motion::Move {
                up, rate, fraction, ..
            } => {
                // One tick is a tenth of a second, so a rate of R units/second moves R/10
                // units. Accumulating tenths rather than rounding each tick is what lets a
                // rate of 1 actually move: it would otherwise round to zero forever.
                *fraction = fraction.saturating_add(u32::from(*rate));
                let whole = *fraction / 10;
                *fraction %= 10;
                let level = state.level.unwrap_or(self.min_level);
                let next = if *up {
                    u32::from(level)
                        .saturating_add(whole)
                        .min(u32::from(self.max_level))
                } else {
                    u32::from(level)
                        .saturating_sub(whole)
                        .max(u32::from(self.min_level))
                };
                let next = u8::try_from(next).unwrap_or(level);
                state.level = Some(next);
                // §1.6.7.2.3: "If the level reaches the maximum allowed for the device, stop."
                if (*up && next >= self.max_level) || (!*up && next <= self.min_level) {
                    state.motion = Motion::Idle;
                }
            }
        }
    }

    /// §1.6.7.6's second half, applied when a motion ends.
    ///
    /// > If any command that has the effect of setting the CurrentLevel attribute to the
    /// > minimum level allowed by the device, the OnOff attribute of the On/Off cluster on the
    /// > same endpoint, if implemented, SHALL be set to FALSE ('Off').
    fn settle(&self, level: Option<u8>) {
        if !self.with_on_off_pending.get() {
            return;
        }
        self.with_on_off_pending.set(false);
        if level == Some(self.min_level) {
            self.on_off.set_from_level(false);
        }
    }
}

impl<H: LevelControlHooks, O: OnOffState> LevelControl<'_, H, O> {
    /// §1.6.7.1.1's temporary Options bitmap.
    ///
    /// > Each bit in the Options attribute SHALL determine the corresponding bit in the
    /// > temporary Options bitmap, unless the OptionsMask field is present and has the
    /// > corresponding bit set to 1, in which case the corresponding bit in the
    /// > OptionsOverride field SHALL determine the corresponding bit.
    ///
    /// So a client can say "just this once" without writing an attribute §1.6.6.9 calls
    /// "meant to be changed only during commissioning".
    fn effective(&self, mask: OptionsBitmap, override_bits: OptionsBitmap) -> OptionsBitmap {
        (self.options.get() & !mask) | (override_bits & mask)
    }

    /// §1.6.6.9's four criteria. All of them, or the command runs.
    fn blocked(&self, options: OptionsBitmap) -> bool {
        self.on_off.present()
            && !self.on_off.is_on()
            && !options.contains(OptionsBitmap::EXECUTE_IF_OFF)
    }

    /// §1.6.7.1.1: a null `TransitionTime` means `OnOffTransitionTime`, and an unimplemented
    /// `OnOffTransitionTime` means "as fast as it is able".
    fn transition_ticks(&self, requested: crate::tlv::Nullable<u16>) -> u32 {
        match requested.0 {
            Some(tenths) => u32::from(tenths),
            None => u32::from(self.on_off_transition_time.get()),
        }
    }

    /// Starts a timed move to `target`, clipped to the device's range.
    fn begin_transition(&self, target: u8, ticks: u32, with_on_off: bool, now: Instant) {
        // §1.6.7.1.1: "If the value of the Level field is below the MinLevel or above the
        // MaxLevel for the device, the value SHALL be clipped to the applicable boundary
        // value." Clipped, not refused — a client that asks for 255 gets the brightest the
        // lamp has.
        let target = target.clamp(self.min_level, self.max_level);
        // §1.6.7.6: "Before commencing any command that has the effect of setting the
        // CurrentLevel attribute above the minimum level allowed by the device, the OnOff
        // attribute ... SHALL be set to TRUE." Before, so the lamp is already on when the fade
        // starts rather than snapping on at the end of it.
        if with_on_off && target > self.min_level {
            self.on_off.set_from_level(true);
        }
        let level = {
            let mut state = self.state.borrow_mut();
            let from = state.level.unwrap_or(self.min_level);
            if ticks == 0 || from == target {
                state.level = Some(target);
                state.motion = Motion::Idle;
                state.next_tick = None;
            } else {
                state.motion = Motion::Transition {
                    from,
                    to: target,
                    ticks,
                    elapsed: 0,
                    with_on_off,
                };
                state.next_tick = Some(now.saturating_add(TICK));
            }
            state.level
        };
        self.with_on_off_pending.set(with_on_off);
        self.hooks.level(level);
        if self.state.borrow().motion == Motion::Idle {
            self.settle(level);
        }
    }

    /// Starts an open-ended move, or does nothing if the rate is unusable.
    fn begin_move(&self, up: bool, rate: u8, with_on_off: bool, now: Instant) {
        if with_on_off && up {
            self.on_off.set_from_level(true);
        }
        if rate == 0 {
            // "If the Rate field is null and the DefaultMoveRate attribute is either not
            // supported or set to null, then the device SHOULD move as fast as it is able."
            let target = if up { self.max_level } else { self.min_level };
            self.begin_transition(target, 0, with_on_off, now);
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            state.motion = Motion::Move {
                up,
                rate,
                fraction: 0,
                with_on_off,
            };
            state.next_tick = Some(now.saturating_add(TICK));
        }
        self.with_on_off_pending.set(with_on_off);
    }

    /// §1.6.7.4: stop whatever is moving, and leave the level where it is.
    fn stop(&self) {
        let level = {
            let mut state = self.state.borrow_mut();
            state.motion = Motion::Idle;
            state.next_tick = None;
            state.level
        };
        // "The value of CurrentLevel SHALL be left at its value upon receipt of the Stop
        // command" — so no `set_from_level(false)` here even if the level happens to be the
        // minimum: nothing *commanded* it there.
        self.with_on_off_pending.set(false);
        let _ = level;
    }

    /// §1.6.4.1.1's coupling, for a device that wants it.
    ///
    /// Called by the product from its own `OnOffHooks::set`, because §1.6.4.1 makes the whole
    /// dependency optional: "dependencies MAY be introduced between them. Facilities are
    /// provided to introduce dependencies if required."
    ///
    /// > **On.** Temporarily store CurrentLevel. Set CurrentLevel to the minimum level allowed
    /// > for the device. Change CurrentLevel to OnLevel, or to the stored level if OnLevel is
    /// > not defined, over the time period OnOffTransitionTime.
    ///
    /// `stored` is the level to return to — what the device remembers from before it was
    /// switched off. The specification's own note is the reason it is a parameter: "If another
    /// of these commands is received, before the transition is completed, the originally
    /// stored CurrentLevel SHALL be preserved and restored", and only the device knows which
    /// value that is across a power cut.
    pub fn on_off_changed(&self, on: bool, stored: Option<u8>, now: Instant) {
        let ticks = if on {
            u32::from(
                self.on_transition_time
                    .get()
                    .unwrap_or_else(|| self.on_off_transition_time.get()),
            )
        } else {
            u32::from(
                self.off_transition_time
                    .get()
                    .unwrap_or_else(|| self.on_off_transition_time.get()),
            )
        };
        if on {
            let target = self.on_level.get().or(stored).unwrap_or(self.max_level);
            // "Set CurrentLevel to the minimum level allowed for the device", then fade up
            // from there — the lamp must not jump to the target and then fade.
            self.state.borrow_mut().level = Some(self.min_level);
            self.begin_transition(target, ticks, false, now);
        } else {
            self.begin_transition(self.min_level, ticks, false, now);
        }
    }
}

impl<H: LevelControlHooks, O: OnOffState> ClusterHandler for LevelControl<'_, H, O> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let nullable = |w: &mut TlvWriter<'_>, value: Option<u16>| match value {
            Some(value) => full(w.unsigned(tag, u64::from(value))),
            None => full(w.null(tag)),
        };
        match resolved.attribute {
            CURRENT_LEVEL => match self.level() {
                Some(level) => full(w.unsigned(tag, u64::from(level))),
                None => full(w.null(tag)),
            },
            REMAINING_TIME => full(w.unsigned(tag, u64::from(self.remaining_time()))),
            MIN_LEVEL => full(w.unsigned(tag, u64::from(self.min_level))),
            MAX_LEVEL => full(w.unsigned(tag, u64::from(self.max_level))),
            OPTIONS => full(w.unsigned(tag, u64::from(self.options.get().bits()))),
            ON_OFF_TRANSITION_TIME => {
                full(w.unsigned(tag, u64::from(self.on_off_transition_time.get())))
            }
            ON_LEVEL => match self.on_level.get() {
                Some(level) => full(w.unsigned(tag, u64::from(level))),
                None => full(w.null(tag)),
            },
            ON_TRANSITION_TIME => nullable(w, self.on_transition_time.get()),
            OFF_TRANSITION_TIME => nullable(w, self.off_transition_time.get()),
            DEFAULT_MOVE_RATE => match self.default_move_rate.get() {
                Some(rate) => full(w.unsigned(tag, u64::from(rate))),
                None => full(w.null(tag)),
            },
            START_UP_CURRENT_LEVEL => match self.start_up_current_level.get() {
                Some(level) => full(w.unsigned(tag, u64::from(level))),
                None => full(w.null(tag)),
            },
            CURRENT_FREQUENCY => full(w.unsigned(tag, u64::from(self.frequency.get()))),
            MIN_FREQUENCY => full(w.unsigned(tag, u64::from(self.min_frequency))),
            MAX_FREQUENCY => full(w.unsigned(tag, u64::from(self.max_frequency))),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        _op: WriteOp,
        _ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;
        let number = |value: &Value<'_>| -> Result<Option<u64>, Status> {
            match value {
                Value::Unsigned(value) => Ok(Some(*value)),
                Value::Null => Ok(None),
                _ => Err(Status::InvalidDataType),
            }
        };
        let byte = |value: &Value<'_>| -> Result<Option<u8>, Status> {
            match number(value)? {
                Some(value) => Ok(Some(
                    u8::try_from(value).map_err(|_| Status::ConstraintError)?,
                )),
                None => Ok(None),
            }
        };
        let short = |value: &Value<'_>| -> Result<Option<u16>, Status> {
            match number(value)? {
                Some(value) => Ok(Some(
                    u16::try_from(value).map_err(|_| Status::ConstraintError)?,
                )),
                None => Ok(None),
            }
        };
        match resolved.attribute {
            OPTIONS => {
                let bits = byte(&element.value)?.ok_or(Status::InvalidDataType)?;
                // §7.19.2: a bit this revision does not define is refused rather than stored
                // and echoed back as if the device understood it.
                let options = OptionsBitmap::from_bits(bits).ok_or(Status::ConstraintError)?;
                self.options.set(options);
                Ok(())
            }
            ON_OFF_TRANSITION_TIME => {
                self.on_off_transition_time
                    .set(short(&element.value)?.ok_or(Status::InvalidDataType)?);
                Ok(())
            }
            ON_LEVEL => {
                // §1.6.6.11's constraint is "MinLevel to MaxLevel", and null "has no effect".
                let level = byte(&element.value)?;
                if let Some(level) = level
                    && (level < self.min_level || level > self.max_level)
                {
                    return Err(Status::ConstraintError);
                }
                self.on_level.set(level);
                Ok(())
            }
            ON_TRANSITION_TIME => {
                self.on_transition_time.set(short(&element.value)?);
                Ok(())
            }
            OFF_TRANSITION_TIME => {
                self.off_transition_time.set(short(&element.value)?);
                Ok(())
            }
            DEFAULT_MOVE_RATE => {
                // §1.6.6.14's constraint is "min 1": a rate of zero is not a slow move, it is
                // no move at all, and §1.6.7.2.3 already refuses it on the command.
                let rate = byte(&element.value)?;
                if rate == Some(0) {
                    return Err(Status::ConstraintError);
                }
                self.default_move_rate.set(rate);
                Ok(())
            }
            START_UP_CURRENT_LEVEL => {
                self.start_up_current_level.set(byte(&element.value)?);
                Ok(())
            }
            _ => Err(Status::UnsupportedWrite),
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
        let payload = || fields.ok_or(StatusIb::from(Status::InvalidCommand));
        let id = resolved.command.id;
        let with_on_off = matches!(
            id,
            MOVE_TO_LEVEL_WITH_ON_OFF | MOVE_WITH_ON_OFF | STEP_WITH_ON_OFF | STOP_WITH_ON_OFF
        );
        match id {
            MOVE_TO_LEVEL | MOVE_TO_LEVEL_WITH_ON_OFF => {
                let decoded: spec_level::MoveToLevelFields = super::decode_fields(payload()?)?;
                let options = self.effective(decoded.options_mask, decoded.options_override);
                // §1.6.6.9's gate applies only to the four commands *without* On/Off: the
                // 'with' variants exist precisely to turn the device on.
                if !with_on_off && self.blocked(options) {
                    return Ok(None);
                }
                let ticks = self.transition_ticks(decoded.transition_time);
                self.begin_transition(decoded.level, ticks, with_on_off, ctx.now);
                Ok(None)
            }
            MOVE | MOVE_WITH_ON_OFF => {
                let decoded: spec_level::MoveFields = super::decode_fields(payload()?)?;
                // §1.6.7.2.3: "if the Rate field has a value of zero, the command has no effect
                // and a response SHALL be returned with the status code set to
                // INVALID_COMMAND" — checked before the Options gate, because a zero rate is
                // malformed whether or not the lamp is on.
                if decoded.rate.0 == Some(0) {
                    return Err(Status::InvalidCommand.into());
                }
                let options = self.effective(decoded.options_mask, decoded.options_override);
                if !with_on_off && self.blocked(options) {
                    return Ok(None);
                }
                // §1.6.7.2.2: null means `DefaultMoveRate`, and an absent or null
                // `DefaultMoveRate` means as fast as the device can.
                let rate = decoded
                    .rate
                    .0
                    .or_else(|| self.default_move_rate.get())
                    .unwrap_or(0);
                self.begin_move(
                    decoded.move_mode == MoveModeEnum::Up,
                    rate,
                    with_on_off,
                    ctx.now,
                );
                Ok(None)
            }
            STEP | STEP_WITH_ON_OFF => {
                let decoded: spec_level::StepFields = super::decode_fields(payload()?)?;
                // §1.6.7.3.4: "if the StepSize field has a value of zero, the command has no
                // effect and a response SHALL be returned with the status code set to
                // INVALID_COMMAND".
                if decoded.step_size == 0 {
                    return Err(Status::InvalidCommand.into());
                }
                let options = self.effective(decoded.options_mask, decoded.options_override);
                if !with_on_off && self.blocked(options) {
                    return Ok(None);
                }
                let from = self.state.borrow().level.unwrap_or(self.min_level);
                let up = decoded.step_mode == StepModeEnum::Up;
                let unclipped = if up {
                    u32::from(from).saturating_add(u32::from(decoded.step_size))
                } else {
                    u32::from(from).saturating_sub(u32::from(decoded.step_size))
                };
                let target = u8::try_from(unclipped.min(u32::from(self.max_level)))
                    .unwrap_or(self.max_level)
                    .clamp(self.min_level, self.max_level);
                // §1.6.7.3.4: "or until it reaches the minimum level allowed for the device if
                // this reached in the process. In the latter case, the transition time SHALL be
                // proportionally reduced." A step that is half clipped takes half the time —
                // otherwise a stepped-to-the-end dimmer crawls the last inch.
                let requested = self.transition_ticks(decoded.transition_time);
                let actual = u32::from(from.abs_diff(target));
                let ticks = if decoded.step_size == 0 {
                    0
                } else {
                    requested
                        .saturating_mul(actual)
                        .checked_div(u32::from(decoded.step_size))
                        .unwrap_or(requested)
                };
                self.begin_transition(target, ticks, with_on_off, ctx.now);
                Ok(None)
            }
            STOP | STOP_WITH_ON_OFF => {
                let decoded: spec_level::StopFields = super::decode_fields(payload()?)?;
                let options = self.effective(decoded.options_mask, decoded.options_override);
                if !with_on_off && self.blocked(options) {
                    return Ok(None);
                }
                self.stop();
                Ok(None)
            }
            MOVE_TO_CLOSEST_FREQUENCY => {
                let decoded: spec_level::MoveToClosestFrequencyFields =
                    super::decode_fields(payload()?)?;
                if self.hooks.frequency(decoded.frequency) {
                    self.frequency.set(decoded.frequency);
                    Ok(None)
                } else {
                    Err(Status::ConstraintError.into())
                }
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: LevelControlHooks, O: OnOffState> Cluster for LevelControl<'_, H, O> {
    const ID: ClusterId = ID;
}
