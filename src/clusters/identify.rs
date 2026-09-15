//! Identify, cluster `0x0003` (Application Cluster §1.2).
//!
//! > This cluster supports an endpoint identification state (e.g., flashing a light), that
//! > indicates to an observer (e.g., an installer) which of several nodes and/or endpoints it
//! > is.
//!
//! Small, mandatory on almost every device type, and the one a commissioner uses to ask "which
//! of these four identical bulbs am I about to name". A device that does not implement it is a
//! device an installer cannot tell apart from its neighbour.
//!
//! # The attribute that deliberately does not report
//!
//! `IdentifyTime` counts down every second, and §1.2.5.1 says a subscriber must *not* be told
//! about it:
//!
//! > Changes to this attribute SHALL only be marked as reportable in the following cases:
//! > when it changes from 0 to any other value and vice versa, or when it is written by a
//! > client, or when the value is set by an Identify command.
//!
//! That is §7.12's `Q` quality — quieter reporting — and the reason is arithmetic: a
//! thirty-second identify would otherwise send thirty reports to every subscriber, for a
//! number the client already knows how to compute. [`Identify::poll`] therefore reports the
//! *transition* and not the tick, and a client is told so plainly: "clients SHOULD NOT rely on
//! the reporting of this attribute in order to keep track of the remaining duration".

use core::cell::RefCell;

use crate::clusters::generated::identify as spec_identify;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::platform::{Duration, Instant};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

use super::Cluster;

pub use spec_identify::attribute::{IDENTIFY_TIME, IDENTIFY_TYPE};
pub use spec_identify::command::{IDENTIFY, TRIGGER_EFFECT};
pub use spec_identify::{
    EffectIdentifierEnum, EffectVariantEnum, ID, IdentifyTypeEnum, PICS, REVISION,
};

/// §1.2.5.1's countdown: "The IdentifyTime attribute SHALL be decremented every second".
pub const TICK: Duration = Duration::from_secs(1);

/// What the device does while it is identifying itself.
///
/// The cluster owns the countdown; the hardware is the application's. §1.2.5.1 recommends
/// "flashing a light with a period of 0.5 seconds", but what an endpoint actually has —
/// [`IdentifyTypeEnum`] ranges from a lighting output to a beep to a window blind — is
/// something only the product knows.
pub trait IdentifyHooks {
    /// The endpoint has started or stopped identifying itself.
    ///
    /// Called on the *transition* only, which is the same rule §1.2.5.1 gives for reporting:
    /// a device that re-armed its blink every second would blink in lockstep with the tick
    /// rather than at the half-second the specification asks for.
    fn identifying(&self, on: bool);

    /// §1.2.6.2's `TriggerEffect` — a one-off piece of feedback, not the identify state.
    ///
    /// "it is not the same as and does not replace the identify mechanism used during
    /// commissioning": this is the green flash when a light joins a network. The default does
    /// nothing, because a device with no way to show an effect is not obliged to invent one —
    /// and the command is optional.
    fn trigger_effect(&self, effect: EffectIdentifierEnum, variant: EffectVariantEnum) {
        let _ = (effect, variant);
    }
}

/// Identify, with the device's hooks.
#[derive(Debug)]
pub struct Identify<'a, H: IdentifyHooks> {
    hooks: &'a H,
    kind: IdentifyTypeEnum,
    state: RefCell<State>,
}

#[derive(Debug, Clone, Copy)]
struct State {
    remaining: u16,
    next_tick: Option<Instant>,
}

impl<'a, H: IdentifyHooks> Identify<'a, H> {
    /// A cluster over `hooks`, presenting itself the way `kind` says.
    ///
    /// §1.2.5.2: "The value None SHALL NOT be used if the device is capable of presenting its
    /// identification state using one of the other methods" — a device that can flash a light
    /// and says `None` has told a commissioner not to bother asking, which is the opposite of
    /// what the cluster is for.
    #[must_use]
    pub const fn new(hooks: &'a H, kind: IdentifyTypeEnum) -> Self {
        Self {
            hooks,
            kind,
            state: RefCell::new(State {
                remaining: 0,
                next_tick: None,
            }),
        }
    }

    /// The descriptor for an instance, derived from the specification's own tables.
    pub fn conforming(optional: &Optional<'_>) -> crate::error::Result<Conforming<2, 2, 0, 0>> {
        Conforming::new(&spec_identify::CLUSTER, 0, optional)
    }

    /// Everything §1.2.6 leaves to the product: `TriggerEffect`.
    pub const WITH_TRIGGER_EFFECT: Optional<'static> = Optional {
        attributes: &[],
        commands: &[TRIGGER_EFFECT],
        events: &[],
    };

    /// `IdentifyTime` — seconds remaining.
    #[must_use]
    pub fn remaining(&self) -> u16 {
        self.state.borrow().remaining
    }

    /// Whether the endpoint is identifying itself.
    #[must_use]
    pub fn is_identifying(&self) -> bool {
        self.remaining() > 0
    }

    /// How this endpoint presents itself.
    #[must_use]
    pub const fn kind(&self) -> IdentifyTypeEnum {
        self.kind
    }

    /// Sets `IdentifyTime`, starting or stopping the state (§1.2.5.1).
    ///
    /// The one place the hook is called, so a write from a client and an `Identify` command
    /// cannot behave differently — which they would if each did its own bookkeeping.
    pub fn set_time(&self, seconds: u16, now: Instant) {
        let transition = {
            let mut state = self.state.borrow_mut();
            let was = state.remaining > 0;
            state.remaining = seconds;
            state.next_tick = (seconds > 0).then(|| now.saturating_add(TICK));
            let is = seconds > 0;
            (was != is).then_some(is)
        };
        if let Some(on) = transition {
            self.hooks.identifying(on);
        }
    }

    /// When [`Identify::poll`] next has something to do.
    #[must_use]
    pub fn wake_at(&self) -> Option<Instant> {
        self.state.borrow().next_tick
    }

    /// Runs §1.2.5.1's one-second countdown.
    ///
    /// Catches up on elapsed time rather than counting calls, so a device that polls late —
    /// or was asleep — stops identifying when it said it would rather than however many
    /// wake-ups later.
    pub fn poll(&self, now: Instant) {
        let stopped = {
            let mut state = self.state.borrow_mut();
            let Some(mut due) = state.next_tick else {
                return;
            };
            let mut ticks = 0u32;
            while now >= due && state.remaining > 0 && ticks < MAX_CATCH_UP {
                ticks = ticks.saturating_add(1);
                due = due.saturating_add(TICK);
                state.remaining = state.remaining.saturating_sub(1);
            }
            if state.remaining == 0 {
                state.next_tick = None;
                true
            } else {
                state.next_tick = Some(due);
                false
            }
        };
        if stopped {
            self.hooks.identifying(false);
        }
    }
}

/// How many missed seconds one `poll` catches up on — an hour's worth, which is longer than
/// `IdentifyTime`'s useful range and bounded so a device that slept for a week does not spin.
const MAX_CATCH_UP: u32 = 3600;

impl<H: IdentifyHooks> ClusterHandler for Identify<'_, H> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            IDENTIFY_TIME => full(w.unsigned(tag, u64::from(self.remaining()))),
            IDENTIFY_TYPE => full(w.unsigned(tag, u64::from(self.kind.value()))),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        _op: crate::im::WriteOp,
        ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        if resolved.attribute != IDENTIFY_TIME {
            return Err(Status::UnsupportedWrite);
        }
        let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;
        let seconds = u16::try_from(element.unsigned().map_err(|_| Status::ConstraintError)?)
            .map_err(|_| Status::ConstraintError)?;
        self.set_time(seconds, ctx.now);
        Ok(())
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let fields = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
        match resolved.command.id {
            IDENTIFY => {
                let decoded: spec_identify::IdentifyFields = super::decode_fields(fields)?;
                self.set_time(decoded.identify_time, ctx.now);
                Ok(None)
            }
            TRIGGER_EFFECT => {
                // §1.2.6.2.1: "SHALL contain one of the non-reserved values" — a reserved one
                // is refused rather than shown as whichever effect is nearest, because what a
                // future revision assigns must not decide what this device does today. The
                // generated enumeration's `from_tlv` is what enforces it.
                let decoded: spec_identify::TriggerEffectFields = super::decode_fields(fields)?;
                self.hooks
                    .trigger_effect(decoded.effect_identifier, decoded.effect_variant);
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// §1.3.7.6's `AddGroupIfIdentifying` asks the endpoint whether it is identifying; this is
/// the answer when the endpoint has an Identify cluster.
impl<H: IdentifyHooks> crate::clusters::groups::Identifying for Identify<'_, H> {
    fn is_identifying(&self) -> bool {
        Self::is_identifying(self)
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: IdentifyHooks> Cluster for Identify<'_, H> {
    const ID: ClusterId = ID;
}
