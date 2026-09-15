//! On/Off, cluster `0x0006` (Application Cluster §1.5).
//!
//! The cluster every Matter demonstration starts with, and the first one in this crate where
//! the specification defines *behaviour* rather than a table. §1.5.7 is a state machine, and
//! most of it is not about turning a light on:
//!
//! ```text
//!                        OnWithTimedOff(X, Y)
//!         ┌──────┐  ──────────────────────────▶  ┌──────────┐
//!         │ Off  │                               │ Timed On │  OnTime ticks down
//!         └──────┘  ◀──────────────────────────  └──────────┘
//!             ▲          OnTime reaches 0             │
//!             │                                       │ Off
//!             │         ┌─────────────┐               │
//!             └─────────│ Delayed Off │◀──────────────┘
//!   OffWaitTime → 0     └─────────────┘  OffWaitTime guards against
//!                                        another OnWithTimedOff
//! ```
//!
//! # What the guard is for
//!
//! §1.5.6.5 gives the reason `OffWaitTime` exists, and it is a real room rather than a
//! protocol abstraction: "when leaving a room, the lights are turned off but an occupancy
//! sensor detects the leaving person and attempts to turn the lights back on". A device that
//! ignores the guard turns the light back on behind the person who just left, every time.
//!
//! # Where the device comes in
//!
//! This is a **pattern B1** cluster: the specification owns the state machine and the
//! application owns the light. [`OnOffHooks`] is that seam — it is told what the cluster
//! decided, and it makes the hardware agree. Nothing here drives a pin, and nothing in a
//! device has to reimplement §1.5.7.
//!
//! The descriptor is derived from the generated tables ([`OnOff::conforming`]), so a device that
//! claims `Lighting` serves `StartUpOnOff` and one that does not cannot accidentally
//! advertise it.

use core::cell::RefCell;

use crate::clusters::generated::on_off as spec_on_off;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::platform::{Duration, Instant};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use super::Cluster;

pub use spec_on_off::attribute::{
    GLOBAL_SCENE_CONTROL, OFF_WAIT_TIME, ON_OFF, ON_TIME, START_UP_ON_OFF,
};
pub use spec_on_off::command::{
    OFF, OFF_WITH_EFFECT, ON, ON_WITH_RECALL_GLOBAL_SCENE, ON_WITH_TIMED_OFF, TOGGLE,
};
pub use spec_on_off::feature;
pub use spec_on_off::{
    DelayedAllOffEffectVariantEnum, DyingLightEffectVariantEnum, EffectIdentifierEnum, ID,
    OnOffControlBitmap, PICS, REVISION, StartUpOnOffEnum,
};

/// The tick §1.5.7.6.4 counts in: "the server SHALL then update these attributes every 1/10
/// second".
///
/// A device polls [`OnOff::poll`] at least this often while a timer runs; less often and the
/// light stays on past its time, which is what a user notices.
pub const TICK: Duration = Duration::from_millis(100);

/// The value §1.5.7.6.4 exempts from counting: "If the values of the OnTime and OffWaitTime
/// attributes are both not equal to 0xFFFF" — so `0xFFFF` means "stay like this".
pub const INDEFINITE: u16 = 0xFFFF;

/// What the application does when the cluster decides the light has changed.
///
/// The cluster owns §1.5.7's state machine and calls this; the device owns the hardware. A
/// hook is not asked whether it agrees — the attribute has already changed and a client may
/// already have been told — so the only correct implementation is one that makes the world
/// match.
pub trait OnOffHooks {
    /// The light is now on, or off.
    ///
    /// Called for every transition, however it arose: a command, a timer expiring, a startup
    /// value being applied. Not called when a command sets the attribute to what it already
    /// was, because §8.6's reporting would not report that either.
    fn set(&self, on: bool);

    /// §1.5.7.4's fading effect, if the device has one.
    ///
    /// The default ends in the same place as an ordinary Off, which is what the specification
    /// requires of a device with no fade: the effect is "enhanced ways of fading", and a
    /// device without any still turns off. `variant` is advisory — "If the server does not
    /// support the given variant, it SHALL use the default variant."
    fn off_with_effect(&self, effect: EffectIdentifierEnum, variant: u8) {
        let _ = (effect, variant);
        self.set(false);
    }

    /// §1.5.7.5: recall the global scene the last `OffWithEffect` stored.
    ///
    /// "the Scenes Management cluster server on the same endpoint SHALL recall its global
    /// scene, updating the OnOff attribute accordingly" — so the answer is whatever the scene
    /// says, and a device with no Scenes Management returns `true`, which is the behaviour of
    /// a light that simply comes back on.
    fn recall_global_scene(&self) -> bool {
        true
    }

    /// §1.5.7.4: store the current settings as the global scene, before turning off.
    ///
    /// Empty by default. A device without Scenes Management has nothing to store, and
    /// `recall_global_scene` correspondingly has nothing to restore.
    fn store_global_scene(&self) {}
}

/// The cluster's state (§1.5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    on: bool,
    global_scene_control: bool,
    on_time: u16,
    off_wait_time: u16,
    /// When the next 1/10-second tick is due, while either timer is running.
    next_tick: Option<Instant>,
}

/// On/Off, with the device's hooks.
///
/// `H` is the application. `feature_map` decides which half of the cluster exists: without
/// `Lighting` there is no `OnTime`, no `OffWaitTime` and therefore no timed-off state machine
/// at all, which is exactly what a plain relay wants.
#[derive(Debug)]
pub struct OnOff<'a, H: OnOffHooks> {
    hooks: &'a H,
    feature_map: u32,
    state: RefCell<State>,
    start_up: Option<StartUpOnOffEnum>,
}

impl<'a, H: OnOffHooks> OnOff<'a, H> {
    /// A cluster over `hooks`, with these features.
    ///
    /// `start_up` is §1.5.6.6's `StartUpOnOff`: `None` means "the previous value", which is
    /// the fallback the specification gives and the one a device implements by restoring the
    /// persisted `OnOff` before calling [`OnOff::start`].
    #[must_use]
    pub fn new(hooks: &'a H, feature_map: u32, start_up: Option<StartUpOnOffEnum>) -> Self {
        Self {
            hooks,
            feature_map,
            state: RefCell::new(State {
                on: false,
                // §1.5.6.3: TRUE after anything that turns the device on, FALSE after
                // `OffWithEffect`. A device that has never been told otherwise has not stored
                // a global scene, so there is nothing for `OnWithRecallGlobalScene` to recall
                // and the attribute starts TRUE.
                global_scene_control: true,
                on_time: 0,
                off_wait_time: 0,
                next_tick: None,
            }),
            start_up,
        }
    }

    /// Whether the cluster supports the Lighting feature's timing attributes.
    const fn lighting(&self) -> bool {
        self.feature_map & feature::LIGHTING != 0
    }

    /// Whether the device refuses to turn on (§1.5.4).
    const fn off_only(&self) -> bool {
        self.feature_map & feature::OFF_ONLY != 0
    }

    /// The descriptor for an instance with these features.
    ///
    /// Derived from the specification's own tables, so the element set follows the feature
    /// map: `StartUpOnOff` and its three companions appear with `Lighting` and cannot appear
    /// without it.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<5, 6, 0, 0>> {
        Conforming::new(&spec_on_off::CLUSTER, feature_map, optional)
    }

    /// Applies §1.5.6.6's `StartUpOnOff` — what the light does when power returns.
    ///
    /// `previous` is the `OnOff` value the device persisted, which is what a null
    /// `StartUpOnOff` means: "If the value is null, the OnOff attribute is set to its previous
    /// value."
    ///
    /// > This behavior does not apply to reboots associated with OTA. After an OTA restart,
    /// > the OnOff attribute SHALL return to its value prior to the restart.
    ///
    /// So a device restarting for an update passes `None` for `start_up` when constructing, or
    /// simply does not call this.
    pub fn start(&self, previous: bool) {
        let on = match self.start_up {
            None => previous,
            Some(StartUpOnOffEnum::Off) => false,
            Some(StartUpOnOffEnum::On) => true,
            Some(StartUpOnOffEnum::Toggle) => !previous,
        };
        self.set(on);
    }

    /// Whether the light is on.
    #[must_use]
    pub fn is_on(&self) -> bool {
        self.state.borrow().on
    }

    /// `OnTime`, in tenths of a second.
    #[must_use]
    pub fn on_time(&self) -> u16 {
        self.state.borrow().on_time
    }

    /// `OffWaitTime`, in tenths of a second.
    #[must_use]
    pub fn off_wait_time(&self) -> u16 {
        self.state.borrow().off_wait_time
    }

    /// `GlobalSceneControl` (§1.5.6.3).
    #[must_use]
    pub fn global_scene_control(&self) -> bool {
        self.state.borrow().global_scene_control
    }

    /// Sets the state and tells the device, if anything changed.
    fn set(&self, on: bool) {
        let changed = {
            let mut state = self.state.borrow_mut();
            let changed = state.on != on;
            state.on = on;
            changed
        };
        if changed {
            self.hooks.set(on);
        }
    }

    /// When [`OnOff::poll`] next has something to do.
    ///
    /// `None` when neither timer is running, which is the ordinary case — a light that is
    /// simply on or simply off needs no clock at all, and an intermittently connected device
    /// can sleep.
    #[must_use]
    pub fn wake_at(&self) -> Option<Instant> {
        self.state.borrow().next_tick
    }

    /// Runs §1.5.7.6.4's tenth-of-a-second update.
    ///
    /// Call it whenever [`OnOff::wake_at`] comes round. It catches up on missed ticks rather
    /// than counting calls, so a device that polls late — or was asleep — still turns the
    /// light off at the right *time* rather than the right number of wake-ups later.
    pub fn poll(&self, now: Instant) {
        let mut turn_off = false;
        {
            let mut state = self.state.borrow_mut();
            let Some(mut due) = state.next_tick else {
                return;
            };
            // "If the values of the OnTime and OffWaitTime attributes are both not equal to
            // 0xFFFF" — either being indefinite stops the countdown entirely.
            if state.on_time == INDEFINITE || state.off_wait_time == INDEFINITE {
                state.next_tick = None;
                return;
            }
            let mut ticks = 0u32;
            while now >= due && ticks < MAX_CATCH_UP {
                ticks = ticks.saturating_add(1);
                due = due.saturating_add(TICK);

                if state.on && state.on_time > 0 {
                    state.on_time = state.on_time.saturating_sub(1);
                    if state.on_time == 0 {
                        // "the server SHALL set the OffWaitTime and OnOff attributes to 0 and
                        // FALSE, respectively."
                        state.off_wait_time = 0;
                        turn_off = true;
                        state.next_tick = None;
                        break;
                    }
                } else if !state.on && state.off_wait_time > 0 {
                    state.off_wait_time = state.off_wait_time.saturating_sub(1);
                    if state.off_wait_time == 0 {
                        // "the server SHALL terminate the update."
                        state.next_tick = None;
                        break;
                    }
                } else {
                    // Neither timer applies in this state; nothing left to count.
                    state.next_tick = None;
                    break;
                }
            }
            if state.next_tick.is_some() {
                state.next_tick = Some(due);
            }
        }
        if turn_off {
            self.set(false);
        }
    }

    /// Arms the tick if either timer is running and both are finite.
    fn arm(&self, now: Instant) {
        let mut state = self.state.borrow_mut();
        let counting = state.on_time != INDEFINITE
            && state.off_wait_time != INDEFINITE
            && (state.on_time > 0 || state.off_wait_time > 0);
        state.next_tick = counting.then(|| now.saturating_add(TICK));
    }
}

/// How many missed ticks one `poll` catches up on.
///
/// A minute's worth. A device that has been asleep longer than the timer it set should finish
/// the transition rather than spin through six hundred iterations to reach the same place, and
/// the loop's own exit conditions get there in one step once a timer hits zero.
const MAX_CATCH_UP: u32 = 600;

impl<H: OnOffHooks> OnOff<'_, H> {
    /// §1.5.7.1's `Off`.
    fn command_off(&self, now: Instant) {
        self.set(false);
        if self.lighting() {
            // §1.5.7.1: "the server SHALL set the OnTime attribute to 0."
            self.state.borrow_mut().on_time = 0;
            self.arm(now);
        }
    }

    /// §1.5.7.2's `On`.
    fn command_on(&self, now: Instant) {
        self.set(true);
        if self.lighting() {
            let mut state = self.state.borrow_mut();
            state.global_scene_control = true;
            if state.on_time == 0 {
                state.off_wait_time = 0;
            }
            drop(state);
            self.arm(now);
        }
    }

    /// §1.5.7.3's `Toggle`.
    fn command_toggle(&self, now: Instant) {
        if self.is_on() {
            self.command_off(now);
        } else {
            self.command_on(now);
        }
    }

    /// §1.5.7.6.4's `OnWithTimedOff`.
    fn command_on_with_timed_off(&self, control: u8, on_time: u16, off_wait: u16, now: Instant) {
        let accept_only_when_on = control & OnOffControlBitmap::ACCEPT_ONLY_WHEN_ON.bits() != 0;
        // "if the AcceptOnlyWhenOn sub-field of the OnOffControl field is set to 1, and the
        // value of the OnOff attribute is equal to FALSE, the command SHALL be discarded."
        if accept_only_when_on && !self.is_on() {
            return;
        }

        let turn_on = {
            let mut state = self.state.borrow_mut();
            // "If the value of the OffWaitTime attribute is greater than zero and the value of
            // the OnOff attribute is equal to FALSE" — the guard of §1.5.6.5, the one that
            // stops an occupancy sensor turning the lights back on behind the person who just
            // left the room.
            if state.off_wait_time > 0 && !state.on {
                state.off_wait_time = state.off_wait_time.min(off_wait);
                false
            } else {
                // "set the OnTime attribute to the maximum of the OnTime attribute and the
                // value specified in the OnTime field" — so a second command extends the
                // period rather than shortening it.
                state.on_time = state.on_time.max(on_time);
                state.off_wait_time = off_wait;
                true
            }
        };
        if turn_on {
            self.set(true);
        }
        self.arm(now);
    }

    /// §1.5.7.4's `OffWithEffect`.
    fn command_off_with_effect(&self, effect: EffectIdentifierEnum, variant: u8, now: Instant) {
        let store = {
            let mut state = self.state.borrow_mut();
            let store = state.global_scene_control;
            if store {
                state.global_scene_control = false;
            }
            store
        };
        if store {
            // "the server SHALL store its settings in its global scene then set the
            // GlobalSceneControl attribute to FALSE" — in that order, because the scene must
            // capture the state the light is *in*, not the state it is about to be in.
            self.hooks.store_global_scene();
        }
        self.hooks.off_with_effect(effect, variant);
        self.set(false);
        if self.lighting() {
            self.state.borrow_mut().on_time = 0;
            self.arm(now);
        }
    }

    /// §1.5.7.5's `OnWithRecallGlobalScene`.
    fn command_on_with_recall_global_scene(&self, now: Instant) {
        // "if the GlobalSceneControl attribute is equal to TRUE, the server SHALL discard the
        // command" — there is no stored scene to recall, because nothing turned the light off
        // with an effect.
        if self.global_scene_control() {
            return;
        }
        let on = self.hooks.recall_global_scene();
        self.set(on);
        let mut state = self.state.borrow_mut();
        state.global_scene_control = true;
        if state.on_time == 0 {
            state.off_wait_time = 0;
        }
        drop(state);
        self.arm(now);
    }
}

/// Reads `OnWithTimedOff`'s three fields (§1.5.7.6).
fn decode_timed_off(fields: &[u8]) -> Result<(u8, u16, u16), Status> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| Status::InvalidAction)?
        .ok_or(Status::InvalidAction)?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }
    let (mut control, mut on_time, mut off_wait) = (None, None, None);
    loop {
        let Some(field) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if field.value == Value::EndOfContainer {
            break;
        }
        let value = field.unsigned().map_err(|_| Status::ConstraintError)?;
        match field.tag.context() {
            Some(0) => {
                // "0 to 1": the only bit defined is `AcceptOnlyWhenOn`.
                let bits = u8::try_from(value).map_err(|_| Status::ConstraintError)?;
                if OnOffControlBitmap::from_bits(bits).is_none() {
                    return Err(Status::ConstraintError);
                }
                control = Some(bits);
            }
            Some(1) | Some(2) => {
                let ticks = u16::try_from(value).map_err(|_| Status::ConstraintError)?;
                // "max 0xFFFE" on both fields — 0xFFFF is reserved for the *attribute*'s
                // "indefinite", and a command may not ask for it.
                if ticks == INDEFINITE {
                    return Err(Status::ConstraintError);
                }
                if field.tag.context() == Some(1) {
                    on_time = Some(ticks);
                } else {
                    off_wait = Some(ticks);
                }
            }
            _ => {
                reader
                    .skip_value(&field)
                    .map_err(|_| Status::InvalidAction)?;
            }
        }
    }
    match (control, on_time, off_wait) {
        (Some(control), Some(on_time), Some(off_wait)) => Ok((control, on_time, off_wait)),
        _ => Err(Status::InvalidCommand),
    }
}

/// Reads `OffWithEffect`'s two fields (§1.5.7.4).
fn decode_effect(fields: &[u8]) -> Result<(EffectIdentifierEnum, u8), Status> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()
        .map_err(|_| Status::InvalidAction)?
        .ok_or(Status::InvalidAction)?;
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }
    let (mut effect, mut variant) = (None, None);
    loop {
        let Some(field) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if field.value == Value::EndOfContainer {
            break;
        }
        let value = u8::try_from(field.unsigned().map_err(|_| Status::ConstraintError)?)
            .map_err(|_| Status::ConstraintError)?;
        match field.tag.context() {
            // "This field SHALL contain one of the non-reserved values listed in
            // EffectIdentifierEnum" — a reserved one is `CONSTRAINT_ERROR`, not a fade the
            // device invents.
            Some(0) => {
                effect =
                    Some(EffectIdentifierEnum::from_value(value).ok_or(Status::ConstraintError)?);
            }
            // The variant is *not* checked: "If the server does not support the given variant,
            // it SHALL use the default variant", so an unknown one is the device's to shrug at.
            Some(1) => variant = Some(value),
            _ => {
                reader
                    .skip_value(&field)
                    .map_err(|_| Status::InvalidAction)?;
            }
        }
    }
    match (effect, variant) {
        (Some(effect), Some(variant)) => Ok((effect, variant)),
        _ => Err(Status::InvalidCommand),
    }
}

impl<H: OnOffHooks> ClusterHandler for OnOff<'_, H> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            ON_OFF => full(w.bool(tag, self.is_on())),
            GLOBAL_SCENE_CONTROL if self.lighting() => {
                full(w.bool(tag, self.global_scene_control()))
            }
            ON_TIME if self.lighting() => full(w.unsigned(tag, u64::from(self.on_time()))),
            OFF_WAIT_TIME if self.lighting() => {
                full(w.unsigned(tag, u64::from(self.off_wait_time())))
            }
            START_UP_ON_OFF if self.lighting() => match self.start_up {
                // §1.5.6.6: null means "its previous value", which is a real answer rather
                // than an absent one.
                None => full(w.null(tag)),
                Some(value) => full(w.unsigned(tag, u64::from(value.value()))),
            },
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        _op: crate::im::WriteOp,
        _ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        if !self.lighting() {
            return Err(Status::UnsupportedWrite);
        }
        let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;
        match resolved.attribute {
            // §1.5.6.4 and §1.5.6.5: "can be written at any time, but writing a value only has
            // effect when in the Timed On state" — so the write always lands, and the state
            // machine decides whether it matters.
            ON_TIME | OFF_WAIT_TIME => {
                let value = u16::try_from(element.unsigned().map_err(|_| Status::ConstraintError)?)
                    .map_err(|_| Status::ConstraintError)?;
                let mut state = self.state.borrow_mut();
                if resolved.attribute == ON_TIME {
                    state.on_time = value;
                } else {
                    state.off_wait_time = value;
                }
                Ok(())
            }
            START_UP_ON_OFF => Err(Status::UnsupportedWrite),
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
        let now = ctx.now;
        match resolved.command.id {
            OFF => {
                self.command_off(now);
                Ok(None)
            }
            // §1.5.7.2.1 and §1.5.7.3.1: "If the OffOnly feature is supported … an
            // UNSUPPORTED_COMMAND failure status response SHALL be sent." The descriptor
            // already leaves these out, so this is the second line of defence — and the one
            // that matters if a device built its descriptor by hand.
            ON if !self.off_only() => {
                self.command_on(now);
                Ok(None)
            }
            TOGGLE if !self.off_only() => {
                self.command_toggle(now);
                Ok(None)
            }
            OFF_WITH_EFFECT if self.lighting() => {
                let (effect, variant) =
                    decode_effect(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                self.command_off_with_effect(effect, variant, now);
                Ok(None)
            }
            ON_WITH_RECALL_GLOBAL_SCENE if self.lighting() => {
                self.command_on_with_recall_global_scene(now);
                Ok(None)
            }
            ON_WITH_TIMED_OFF if self.lighting() => {
                let (control, on_time, off_wait) =
                    decode_timed_off(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                self.command_on_with_timed_off(control, on_time, off_wait, now);
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: OnOffHooks> Cluster for OnOff<'_, H> {
    const ID: ClusterId = ID;
}
