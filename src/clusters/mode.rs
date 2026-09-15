//! Mode Base (Application Cluster §1.10) — one implementation for every cluster derived from
//! it.
//!
//! §1.10 is not a cluster a device serves. It is a *shape*: about fifteen clusters in the 1.6
//! library are "derived from the Mode Base cluster and define additional mode tags and
//! namespaced enumerated values" — Energy EVSE Mode, Water Heater Mode, Dishwasher Mode,
//! Laundry Washer Mode, and so on. They differ in their id, their PICS code and the mode tags
//! they define, and in nothing else at all.
//!
//! So [`Mode`] takes the derived cluster's table as an argument and serves it. A device gains
//! a new mode cluster by naming one, not by writing one.
//!
//! # A mode is a list the product writes, not an enumeration
//!
//! `SupportedModes` is `F` — fixed — and §1.10.6.1 constrains it hard: every entry's `Mode`
//! must be unique, every `Label` must be unique, and the *sets* of mode tags must be distinct
//! from one another. [`Mode::new`] checks all three, because a device that shipped two modes
//! with the same tag set would give a controller no way to tell them apart and no way to know
//! that it could not.
//!
//! # `ChangeToMode` answers in its response, not in its status
//!
//! §1.10.7.1.1 is careful about this: an unsupported mode is `SUCCESS` at the interaction
//! layer with `UnsupportedMode` *inside* the `ChangeToModeResponse`, alongside a human-readable
//! `StatusText`. The command was delivered and understood; the mode was refused. A cluster
//! that answered with an IM status instead would lose the text, which §1.10.7.1.1 exists to
//! carry: "Provide a human readable string in the StatusText field."

use core::cell::Cell;

use crate::clusters::generated::energy_evse_mode as spec_mode;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb, WriteOp,
};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, ToTlv, Value};

use super::Cluster;

pub use spec_mode::attribute::{CURRENT_MODE, ON_MODE, START_UP_MODE, SUPPORTED_MODES};
pub use spec_mode::command::{CHANGE_TO_MODE, CHANGE_TO_MODE_RESPONSE};
pub use spec_mode::{ModeOptionStruct, ModeTagStruct, feature};

/// §1.10.7.1.1's `Status` values, as the ChangeToModeResponse carries them.
///
/// > Have the Status set to a product-specific Status value representing the error, or
/// > GenericFailure if a more specific error cannot be provided.
pub mod status {
    /// The transition happened.
    pub const SUCCESS: u8 = 0x00;
    /// "the NewMode field doesn't match the Mode field of any entry of the SupportedModes list".
    pub const UNSUPPORTED_MODE: u8 = 0x01;
    /// The mode exists but the device will not go there, and has nothing more specific to say.
    pub const GENERIC_FAILURE: u8 = 0x02;
    /// The first value a derived cluster may define for itself (§1.10.7.2.1).
    pub const MANUFACTURER_SPECIFIC: u8 = 0x40;
}

/// §1.10.6.1's constraint on `SupportedModes`: "2 to 255".
///
/// Two is the floor because a cluster with one mode offers no choice, and a client that could
/// not change anything would be reading a constant dressed as a control.
pub const MODES_MIN: usize = 2;

/// What the product does when the mode changes.
pub trait ModeHooks {
    /// §1.10.7.1.1: go to `mode`.
    ///
    /// Return `Err((status, text))` to refuse: the status is `GenericFailure` or one of the
    /// derived cluster's own values, and the text is what a person reads. A dishwasher that
    /// will not switch to Heavy mid-cycle has a reason, and this is where it says it.
    fn change_to(&self, mode: u8) -> Result<(), (u8, &'static str)>;
}

/// One cluster derived from Mode Base.
///
/// `CLUSTER` is the derived cluster's id — a const parameter rather than a field, because
/// [`Cluster::ID`] is an associated constant and that is what lets a tuple of clusters
/// dispatch to this one. One implementation therefore serves fifteen *distinct types*, which
/// is exactly right: an endpoint with both an Energy EVSE Mode and a Water Heater Mode has two
/// clusters, not one cluster twice.
///
/// The `SupportedModes` list is borrowed rather than copied — §1.10.6.1 makes it `F`, fixed,
/// so it is the product's `const` data.
#[derive(Debug)]
pub struct Mode<'a, H: ModeHooks, const CLUSTER: ClusterId> {
    spec: &'static crate::dm::spec::Cluster,
    hooks: &'a H,
    supported: &'a [ModeOptionStruct<'a>],
    current: Cell<u8>,
    start_up: Cell<Option<u8>>,
    on_mode: Cell<Option<u8>>,
}

impl<'a, H: ModeHooks, const CLUSTER: ClusterId> Mode<'a, H, CLUSTER> {
    /// A mode cluster over `spec` — one of the generated derived tables.
    ///
    /// ```rust,ignore
    /// use matter_kit::clusters::generated::energy_evse_mode;
    /// use matter_kit::clusters::mode::Mode;
    ///
    /// let mode = Mode::<_, { energy_evse_mode::ID }>::new(
    ///     &energy_evse_mode::CLUSTER, &hooks, SUPPORTED, 0,
    /// )?;
    /// ```
    ///
    /// Fails when `spec` is not the table for `CLUSTER` — the two are separate arguments and a
    /// device that crossed them would answer one cluster's paths with another's elements — or
    /// when `supported` breaks §1.10.6.1: fewer than two entries, a repeated `Mode`, a repeated
    /// `Label`, or two entries whose mode-tag *sets* are equal. A controller shown two modes it
    /// cannot tell apart has no way to know that it cannot.
    pub fn new(
        spec: &'static crate::dm::spec::Cluster,
        hooks: &'a H,
        supported: &'a [ModeOptionStruct<'a>],
        current: u8,
    ) -> crate::error::Result<Self> {
        if spec.id != CLUSTER {
            return Err(crate::Error::new(crate::ErrorCode::InvalidArgument));
        }
        if supported.len() < MODES_MIN {
            return Err(crate::Error::new(crate::ErrorCode::InvalidArgument));
        }
        for (index, entry) in supported.iter().enumerate() {
            for other in supported.iter().skip(index.saturating_add(1)) {
                if entry.mode == other.mode
                    || entry.label == other.label
                    || same_tags(entry, other)?
                {
                    return Err(crate::Error::new(crate::ErrorCode::InvalidArgument));
                }
            }
        }
        if !supported.iter().any(|entry| entry.mode == current) {
            // §1.10.6.2: "The value of this field SHALL match the Mode field of one of the
            // entries in the SupportedModes attribute."
            return Err(crate::Error::new(crate::ErrorCode::InvalidArgument));
        }
        Ok(Self {
            spec,
            hooks,
            supported,
            current: Cell::new(current),
            start_up: Cell::new(None),
            on_mode: Cell::new(None),
        })
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        spec: &'static crate::dm::spec::Cluster,
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<4, 1, 1, 0>> {
        Conforming::new(spec, feature_map, optional)
    }

    /// Everything §1.10.6 leaves to the product: `StartUpMode`.
    pub const WITH_START_UP_MODE: Optional<'static> = Optional {
        attributes: &[START_UP_MODE],
        commands: &[],
        events: &[],
    };

    /// The specification table this instance serves.
    #[must_use]
    pub const fn spec(&self) -> &'static crate::dm::spec::Cluster {
        self.spec
    }

    /// `CurrentMode` (§1.10.6.2).
    #[must_use]
    pub fn current(&self) -> u8 {
        self.current.get()
    }

    /// `SupportedModes` (§1.10.6.1).
    #[must_use]
    pub const fn supported(&self) -> &'a [ModeOptionStruct<'a>] {
        self.supported
    }

    /// `StartUpMode` (§1.10.6.3), `None` for null.
    #[must_use]
    pub fn start_up_mode(&self) -> Option<u8> {
        self.start_up.get()
    }

    /// Sets `StartUpMode` without a write interaction.
    ///
    /// Refuses a mode `SupportedModes` does not list, the same as a write does.
    pub fn set_start_up_mode(&self, mode: Option<u8>) -> Result<(), Status> {
        self.checked(mode)?;
        self.start_up.set(mode);
        Ok(())
    }

    /// Sets `OnMode` (§1.10.6.4) without a write interaction.
    pub fn set_on_mode(&self, mode: Option<u8>) -> Result<(), Status> {
        self.checked(mode)?;
        self.on_mode.set(mode);
        Ok(())
    }

    /// §1.10.6.3's start-up behaviour.
    ///
    /// > If this attribute is not null, the CurrentMode attribute SHALL be set to the
    /// > StartUpMode value, when the server is powered up, except in the case when the OnMode
    /// > attribute overrides the StartUpMode attribute.
    ///
    /// `start_up_on_off` is On/Off's `StartUpOnOff` where the endpoint has one: §1.10.6.4.1
    /// makes `OnMode` win when the device is configured to come up *on*, because the endpoint
    /// is then doing the thing `OnMode` describes.
    pub fn start(&self, start_up_on_off_is_on: bool) {
        let chosen = if start_up_on_off_is_on {
            self.on_mode.get().or_else(|| self.start_up.get())
        } else {
            self.start_up.get()
        };
        if let Some(mode) = chosen
            && self.supported.iter().any(|entry| entry.mode == mode)
        {
            self.current.set(mode);
        }
    }

    /// §1.10.6.4's table: the On/Off cluster on this endpoint changed.
    ///
    /// Only `OFF → ON` moves the mode. A device that also acted on `ON → ON` would jump out of
    /// whatever mode a user had just chosen every time an `On` command was re-sent, which for
    /// a groupcast is every time anybody turns the room on.
    pub fn on_off_changed(&self, was_on: bool, is_on: bool) {
        if was_on || !is_on {
            return;
        }
        if let Some(mode) = self.on_mode.get()
            && self.hooks.change_to(mode).is_ok()
        {
            self.current.set(mode);
        }
    }

    /// Whether `mode` is null or one `SupportedModes` lists.
    fn checked(&self, mode: Option<u8>) -> Result<(), Status> {
        match mode {
            None => Ok(()),
            Some(mode) if self.supported.iter().any(|entry| entry.mode == mode) => Ok(()),
            // §1.10.6.3: "The value of this field SHALL match the Mode field of one of the
            // entries in the SupportedModes attribute." A start-up mode the device does not
            // have would leave it stuck at power-up with nothing to report.
            Some(_) => Err(Status::ConstraintError),
        }
    }
}

/// Whether two entries carry the same *set* of mode tags (§1.10.6.1).
///
/// > This comparison SHALL NOT depend on the order of the ModeTags in the lists. Two sets SHALL
/// > be considered distinct if one of them contains an element that the other one does not.
fn same_tags(a: &ModeOptionStruct<'_>, b: &ModeOptionStruct<'_>) -> crate::error::Result<bool> {
    let contains = |list: &crate::tlv::TlvList<'_, ModeTagStruct>,
                    tag: &ModeTagStruct|
     -> crate::error::Result<bool> {
        for entry in list.iter() {
            let entry = entry?;
            if entry.value == tag.value && entry.mfg_code == tag.mfg_code {
                return Ok(true);
            }
        }
        Ok(false)
    };
    for tag in a.mode_tags.iter() {
        if !contains(&b.mode_tags, &tag?)? {
            return Ok(false);
        }
    }
    for tag in b.mode_tags.iter() {
        if !contains(&a.mode_tags, &tag?)? {
            return Ok(false);
        }
    }
    Ok(true)
}

impl<H: ModeHooks, const CLUSTER: ClusterId> ClusterHandler for Mode<'_, H, CLUSTER> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let nullable = |w: &mut TlvWriter<'_>, value: Option<u8>| match value {
            Some(value) => full(w.unsigned(tag, u64::from(value))),
            None => full(w.null(tag)),
        };
        match resolved.attribute {
            SUPPORTED_MODES => {
                full(w.start_array(tag))?;
                for entry in self.supported {
                    full(entry.to_tlv(w, Tag::Anonymous))?;
                }
                full(w.end_container())
            }
            CURRENT_MODE => full(w.unsigned(tag, u64::from(self.current.get()))),
            START_UP_MODE => nullable(w, self.start_up.get()),
            ON_MODE => nullable(w, self.on_mode.get()),
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
        let mode = match element.value {
            Value::Unsigned(value) => {
                Some(u8::try_from(value).map_err(|_| Status::ConstraintError)?)
            }
            Value::Null => None,
            _ => return Err(Status::InvalidDataType),
        };
        match resolved.attribute {
            START_UP_MODE => self.set_start_up_mode(mode),
            ON_MODE => self.set_on_mode(mode),
            // §1.10.6.2's access is `RV`: a client changes the mode with `ChangeToMode`, which
            // is the only path that can refuse with a reason a person can read.
            _ => Err(Status::UnsupportedWrite),
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
        if resolved.command.id != CHANGE_TO_MODE {
            return Err(Status::UnsupportedCommand.into());
        }
        let decoded: spec_mode::ChangeToModeFields =
            super::decode_fields(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
        let (code, text) = if !self
            .supported
            .iter()
            .any(|entry| entry.mode == decoded.new_mode)
        {
            // §1.10.7.1.1: "the ChangeToModeResponse command's Status field SHALL indicate
            // UnsupportedMode and the StatusText field SHALL be included".
            (status::UNSUPPORTED_MODE, "no such mode")
        } else if decoded.new_mode == self.current.get() {
            // "If the NewMode field is the same as the value of the CurrentMode attribute the
            // ChangeToModeResponse command SHALL have the Status field set to Success" — not a
            // transition, and the hooks are not troubled with it.
            (status::SUCCESS, "")
        } else {
            match self.hooks.change_to(decoded.new_mode) {
                Ok(()) => {
                    self.current.set(decoded.new_mode);
                    (status::SUCCESS, "")
                }
                Err((code, text)) => (code, text),
            }
        };
        spec_mode::ChangeToModeResponseFields {
            status: code,
            status_text: text,
        }
        .to_tlv(w, tag)
        .map_err(|_| StatusIb::from(Status::ResourceExhausted))?;
        Ok(Some(CHANGE_TO_MODE_RESPONSE))
    }
}

/// So a tuple of clusters can dispatch to it by id — a different type per derived cluster.
impl<H: ModeHooks, const CLUSTER: ClusterId> Cluster for Mode<'_, H, CLUSTER> {
    const ID: ClusterId = CLUSTER;
}
