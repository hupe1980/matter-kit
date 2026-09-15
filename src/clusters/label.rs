//! Fixed Label `0x0040` and User Label `0x0041` (Core §9.7–9.9).
//!
//! Both are instances of §9.7's Label cluster, which "provides a feature to tag an endpoint
//! with zero or more labels" and is a *base* cluster — it has no cluster id of its own and
//! exists only through the two derived ones. They differ in exactly one thing, and it is the
//! access quality:
//!
//! | | id | `LabelList` access |
//! |---|---|---|
//! | [`FixedLabel`] | `0x0040` | `RV` — read-only, the manufacturer's |
//! | [`UserLabel`]  | `0x0041` | `RW VM` — writable at Manage, the owner's |
//!
//! That is the whole distinction and it is worth stating plainly: a fixed label is what the
//! factory burned in ("serial", "model"), and a user label is what somebody with a phone
//! typed ("room": "kitchen"). Making the fixed one writable would let a commissioner rewrite
//! a device's identity; making the user one read-only would leave every ecosystem unable to
//! name the thing it just commissioned.
//!
//! # Why they share a file
//!
//! §9.7.4.1's `LabelStruct` is the same in both, and so is the encoding. Two files would
//! mean two copies of the same TLV, which is two places for the max-16 constraint to be got
//! wrong.

use core::cell::RefCell;

use crate::dm::{
    Access, AttributeDescriptor, AttributeQualities, ClusterDescriptor, CommandDescriptor,
    Privilege, Resolved,
};
use crate::im::{AttributeId, ClusterHandler, ClusterId, InteractionContext, Status, WriteOp};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use super::Cluster;

/// `0x0040` (§9.8.3).
pub const FIXED_LABEL_ID: ClusterId = 0x0040;
/// `0x0041` (§9.9.3).
pub const USER_LABEL_ID: ClusterId = 0x0041;

/// The revision both derived clusters are at (§9.8.1, §9.9.1).
pub const REVISION: u16 = 1;

/// `LabelList` (§9.7.5.1) — the only attribute either cluster has.
pub const LABEL_LIST: AttributeId = 0x0000;

/// The longest a `Label` or a `Value` may be (§9.7.4.1: "max 16").
pub const LABEL_MAX: usize = 16;

/// One `LabelStruct` (§9.7.4.1): "a string tuple with strings that are user defined".
///
/// The specification declines to give either half a meaning — "The Label or Value semantic is
/// not defined here" — and offers `"room":"bedroom 2"` and `"orientation":"North"` as
/// examples. So this is deliberately two strings and no interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Label<'a> {
    /// `Label [0]` — the key. "room", "zone", "direction".
    pub label: &'a str,
    /// `Value [1]` — "a discriminator for a Label that may have multiple instances".
    pub value: &'a str,
}

impl<'a> Label<'a> {
    /// A label, or `None` if either half exceeds §9.7.4.1's 16 characters.
    ///
    /// Checked here rather than at write time so a `const` device model cannot declare a
    /// label it would be unable to report.
    #[must_use]
    pub const fn new(label: &'a str, value: &'a str) -> Option<Self> {
        if label.len() > LABEL_MAX || value.len() > LABEL_MAX {
            return None;
        }
        Some(Self { label, value })
    }

    fn encode(&self, w: &mut TlvWriter<'_>) -> crate::error::Result<()> {
        w.start_structure(Tag::Anonymous)?;
        w.utf8(Tag::Context(0), self.label)?;
        w.utf8(Tag::Context(1), self.value)?;
        w.end_container()
    }
}

/// An owned label, for the list a [`UserLabel`] holds.
///
/// Owned rather than borrowed because a user label arrives over the wire and has to outlive
/// the message it came in — which a `&str` into the receive buffer would not.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OwnedLabel {
    label: heapless::String<LABEL_MAX>,
    value: heapless::String<LABEL_MAX>,
}

impl OwnedLabel {
    /// The key half.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The value half.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Borrows it as a [`Label`].
    #[must_use]
    pub fn as_label(&self) -> Label<'_> {
        Label {
            label: &self.label,
            value: &self.value,
        }
    }

    /// Builds one, refusing anything past §9.7.4.1's 16 characters.
    pub fn new(label: &str, value: &str) -> Result<Self, Status> {
        let mut out = Self::default();
        out.label
            .push_str(label)
            .map_err(|_| Status::ConstraintError)?;
        out.value
            .push_str(value)
            .map_err(|_| Status::ConstraintError)?;
        Ok(out)
    }
}

/// Writes a `LabelList` as the array §9.7.5.1 describes.
fn write_list<'a>(
    labels: impl Iterator<Item = Label<'a>>,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> Result<(), Status> {
    let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
    full(w.start_array(tag))?;
    for label in labels {
        full(label.encode(w))?;
    }
    full(w.end_container())
}

/// Reads one `LabelStruct` whose opening structure the caller has taken.
fn decode_label(reader: &mut TlvReader<'_>) -> Result<OwnedLabel, Status> {
    let mut label = None;
    let mut value = None;
    loop {
        let Some(element) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if element.value == Value::EndOfContainer {
            break;
        }
        match element.tag.context() {
            Some(0) => label = Some(element.utf8().map_err(|_| Status::InvalidAction)?),
            Some(1) => value = Some(element.utf8().map_err(|_| Status::InvalidAction)?),
            _ => reader
                .skip_value(&element)
                .map_err(|_| Status::InvalidAction)?,
        }
    }
    // §9.7.4.1 gives both fields a fallback of "empty", so an absent one is the empty string
    // rather than a malformed struct.
    OwnedLabel::new(label.unwrap_or_default(), value.unwrap_or_default())
}

// --- Fixed Label -------------------------------------------------------------------------------

/// §9.8.5's one attribute: `RV`, and `N` because a fixed label survives a reboot by definition.
const FIXED_ATTRIBUTES: &[AttributeDescriptor] =
    &[AttributeDescriptor::read_only(LABEL_LIST).with_qualities(AttributeQualities::NON_VOLATILE)];

const NO_COMMANDS: &[CommandDescriptor] = &[];

/// The descriptor for Fixed Label.
#[must_use]
pub const fn fixed_cluster() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: FIXED_LABEL_ID,
        revision: REVISION,
        feature_map: 0,
        attributes: FIXED_ATTRIBUTES,
        accepted_commands: NO_COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// Fixed Label `0x0040` (§9.8): the labels the manufacturer burned in.
///
/// Read-only over the wire — §9.8.5 gives `LabelList` access `RV` — so the list is `&'static`
/// data alongside the rest of the device's `const` model, and there is no path by which a
/// commissioner could rewrite it.
#[derive(Debug, Clone, Copy)]
pub struct FixedLabel<'a> {
    labels: &'a [Label<'a>],
}

impl<'a> FixedLabel<'a> {
    /// A cluster over the manufacturer's labels.
    #[must_use]
    pub const fn new(labels: &'a [Label<'a>]) -> Self {
        Self { labels }
    }

    /// The labels it reports.
    #[must_use]
    pub const fn labels(&self) -> &'a [Label<'a>] {
        self.labels
    }
}

impl ClusterHandler for FixedLabel<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        if resolved.attribute != LABEL_LIST {
            return Err(Status::UnsupportedAttribute);
        }
        write_list(self.labels.iter().copied(), w, tag)
    }
}

impl Cluster for FixedLabel<'_> {
    const ID: ClusterId = FIXED_LABEL_ID;
}

// --- User Label --------------------------------------------------------------------------------

/// §9.9.5's one attribute: `RW VM`, writable at Manage, and `N`.
///
/// Manage rather than Operate is the point: renaming a device is configuration, not use, so
/// §9.9.5 puts it above the privilege an ordinary occupant holds.
const USER_ATTRIBUTES: &[AttributeDescriptor] = &[AttributeDescriptor::read_write(LABEL_LIST)
    .with_access(Access::read_write_with(Privilege::View, Privilege::Manage))
    .with_qualities(AttributeQualities::NON_VOLATILE)];

/// The descriptor for User Label.
#[must_use]
pub const fn user_cluster() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: USER_LABEL_ID,
        revision: REVISION,
        feature_map: 0,
        attributes: USER_ATTRIBUTES,
        accepted_commands: NO_COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// User Label `0x0041` (§9.9): the labels the owner set.
///
/// `N` is a claim this type cannot make good on its own — §9.9.5 says the list survives a
/// reboot, and nothing here writes to storage. [`UserLabel::labels`] is what a device
/// persists, and [`UserLabel::restore`] is how it comes back.
#[derive(Debug)]
pub struct UserLabel<const N: usize> {
    labels: RefCell<heapless::Vec<OwnedLabel, N>>,
}

impl<const N: usize> Default for UserLabel<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> UserLabel<N> {
    /// A cluster with no labels — a factory-fresh device's empty list (§9.9.5's fallback).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            labels: RefCell::new(heapless::Vec::new()),
        }
    }

    /// The labels, for a device about to persist them.
    #[must_use]
    pub fn labels(&self) -> core::cell::Ref<'_, heapless::Vec<OwnedLabel, N>> {
        self.labels.borrow()
    }

    /// Restores the list a device persisted.
    pub fn restore(&self, labels: impl IntoIterator<Item = OwnedLabel>) -> Result<(), Status> {
        let mut held = self.labels.borrow_mut();
        held.clear();
        for label in labels {
            held.push(label).map_err(|_| Status::ResourceExhausted)?;
        }
        Ok(())
    }
}

impl<const N: usize> ClusterHandler for UserLabel<N> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        if resolved.attribute != LABEL_LIST {
            return Err(Status::UnsupportedAttribute);
        }
        let labels = self.labels.borrow();
        write_list(labels.iter().map(OwnedLabel::as_label), w, tag)
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        op: WriteOp,
        _ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        if resolved.attribute != LABEL_LIST {
            return Err(Status::UnsupportedWrite);
        }
        let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;

        match op {
            // §10.6.4.3.1's REPLACE: the array is the new contents of the list.
            WriteOp::Replace => {
                if element.value.container() != Some(ContainerKind::Array) {
                    return Err(Status::InvalidAction);
                }
                let mut replacement: heapless::Vec<OwnedLabel, N> = heapless::Vec::new();
                loop {
                    let Some(item) = reader.next_element().map_err(|_| Status::InvalidAction)?
                    else {
                        return Err(Status::InvalidAction);
                    };
                    if item.value == Value::EndOfContainer {
                        break;
                    }
                    if item.value.container() != Some(ContainerKind::Structure) {
                        return Err(Status::InvalidAction);
                    }
                    replacement
                        .push(decode_label(&mut reader)?)
                        .map_err(|_| Status::ResourceExhausted)?;
                }
                *self.labels.borrow_mut() = replacement;
            }
            // §10.6.4.3.1's ADD: one more label.
            WriteOp::Append => {
                if element.value.container() != Some(ContainerKind::Structure) {
                    return Err(Status::InvalidAction);
                }
                let label = decode_label(&mut reader)?;
                self.labels
                    .borrow_mut()
                    .push(label)
                    .map_err(|_| Status::ResourceExhausted)?;
            }
        }
        Ok(())
    }
}

impl<const N: usize> Cluster for UserLabel<N> {
    const ID: ClusterId = USER_LABEL_ID;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_longer_than_sixteen_is_refused_when_the_model_is_built() {
        assert!(Label::new("room", "kitchen").is_some());
        assert!(Label::new("room", "seventeen chars!!").is_none());
        assert!(Label::new("a-seventeen-char!", "x").is_none());
        // Exactly sixteen is the limit, not one short of it.
        assert!(Label::new("sixteen-chars-ok", "sixteen-chars-ok").is_some());
    }

    #[test]
    fn the_two_clusters_differ_only_in_whether_the_list_can_be_written() {
        // The whole point of there being two derived clusters. A writable fixed label would
        // let a commissioner rewrite a device's identity; a read-only user label would leave
        // every ecosystem unable to name what it just commissioned.
        let fixed = fixed_cluster();
        let user = user_cluster();
        assert_eq!(fixed.id, 0x0040);
        assert_eq!(user.id, 0x0041);

        let fixed_list = fixed.attribute(LABEL_LIST).expect("LabelList");
        assert_eq!(fixed_list.access.read, Some(Privilege::View));
        assert_eq!(fixed_list.access.write, None, "§9.8.5 gives it `RV`");

        let user_list = user.attribute(LABEL_LIST).expect("LabelList");
        assert_eq!(user_list.access.read, Some(Privilege::View));
        assert_eq!(
            user_list.access.write,
            Some(Privilege::Manage),
            "§9.9.5 gives it `RW VM` — renaming is configuration, not use"
        );
        // Both survive a reboot.
        assert!(
            fixed_list
                .qualities
                .contains(AttributeQualities::NON_VOLATILE)
        );
        assert!(
            user_list
                .qualities
                .contains(AttributeQualities::NON_VOLATILE)
        );
    }

    #[test]
    fn a_user_label_list_is_bounded_by_its_capacity() {
        let cluster = UserLabel::<2>::new();
        cluster
            .restore([
                OwnedLabel::new("room", "kitchen").expect("fits"),
                OwnedLabel::new("floor", "1").expect("fits"),
            ])
            .expect("two fit");
        assert_eq!(
            cluster
                .restore([
                    OwnedLabel::new("a", "1").expect("fits"),
                    OwnedLabel::new("b", "2").expect("fits"),
                    OwnedLabel::new("c", "3").expect("fits"),
                ])
                .unwrap_err(),
            Status::ResourceExhausted,
            "§9.6.1's rule for a full list, and the only honest answer without an allocator"
        );
    }

    #[test]
    fn an_over_long_label_is_a_constraint_error_not_a_truncation() {
        // Truncating would store something the client never asked for and report success.
        assert_eq!(
            OwnedLabel::new("this-label-is-far-too-long", "x").unwrap_err(),
            Status::ConstraintError
        );
    }
}
