//! Access Control, cluster `0x001F` (Core §9.10).
//!
//! The cluster an administrator uses to say who may do what. Its own access quality is the
//! point of the design: §9.10.5.7 requires "the Administer privilege to observe and modify
//! the Access Control Cluster itself", so the only subject that can widen a node's
//! permissions is one that already holds the widest.
//!
//! The decision logic is not here — it is [`acl`](crate::acl), because §6.6.6's algorithm is
//! consulted on every interaction while this cluster is consulted only when someone edits the
//! list. This is the *editing* half: the `ACL` attribute's read, its write, and the event that
//! records the change.
//!
//! # Why the write is the interesting part
//!
//! `ACL` is a **list**, and §10.6.4.3.1 gives a client two ways to write one: replace the
//! whole list, or append one entry at a time. An administrator writing four entries sends an
//! empty array followed by four appends, so a cluster that treated every block as a
//! replacement would end up holding one entry and report `SUCCESS` for all five blocks. That
//! is why [`ClusterHandler::write`] takes a [`WriteOp`] — and why this cluster is the one
//! that would have been hurt most by its absence.
//!
//! # Fabric scoping is enforced twice
//!
//! `ACL` is `F`, so a read reports only the accessing fabric's entries (§7.19.1.8.2) and a
//! write replaces only the accessing fabric's. Neither is a filter applied for tidiness: an
//! administrator on fabric 2 that could see or overwrite fabric 1's entries would be able to
//! take the node away from the administrator that commissioned it.

use core::cell::RefCell;

use crate::acl::{Acl, AuthMode, Entry, Target};
use crate::config::Config;
use crate::dm::{
    Access, AccessQualities, AttributeDescriptor, ClusterDescriptor, CommandDescriptor,
    EventDescriptor, EventPriority, Privilege, Resolved,
};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, EventId, InteractionContext, Status, WriteOp,
};
use crate::msg::{FabricIndex, NodeId};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use super::Cluster;

/// `0x001F` (§9.10.3).
pub const ID: ClusterId = 0x001F;

/// The revision §9.10.1's table ends on.
pub const REVISION: u16 = 3;

/// `ACL` (§9.10.6) — `list[AccessControlEntryStruct]`, `RW A F`, mandatory.
pub const ACL: AttributeId = 0x0000;
/// `Extension` (§9.10.6) — `list[AccessControlExtensionStruct]`, `RW A F`, `EXTS`.
pub const EXTENSION: AttributeId = 0x0001;
/// `SubjectsPerAccessControlEntry` (§9.10.6.5) — `uint16` `4 to 65534`, `F`, `RV`.
pub const SUBJECTS_PER_ENTRY: AttributeId = 0x0002;
/// `TargetsPerAccessControlEntry` (§9.10.6.6) — `uint16` `3 to 65534`, `F`, `RV`.
pub const TARGETS_PER_ENTRY: AttributeId = 0x0003;
/// `AccessControlEntriesPerFabric` (§9.10.6.7) — `uint16` `4 to 65534`, `F`, `RV`.
pub const ENTRIES_PER_FABRIC: AttributeId = 0x0004;

/// `AccessControlEntryChanged` (§9.10.9.1).
pub const ACCESS_CONTROL_ENTRY_CHANGED: EventId = 0x0000;

/// The global `FabricIndex` field of a fabric-scoped struct (§7.19.1.9).
pub const FABRIC_INDEX_FIELD: u8 = 254;

/// `ChangeTypeEnum` (§9.10.5.1).
///
/// A list attribute's entry is identified by its index — §10.6.4.3.1 edits by index — so a
/// whole-list write is compared position by position: a position present before and after was
/// *changed*, one only in the new list *added*, one only in the old list *removed*. A replace
/// is not a wipe and a refill, and reporting it as one tells a controller it has lost entries
/// it still has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeType {
    /// `0` — "Entry or extension was changed".
    Changed = 0,
    /// `1` — "Entry or extension was added".
    Added = 1,
    /// `2` — "Entry or extension was removed".
    Removed = 2,
}

/// §9.10.6's attributes, in id order.
///
/// `ACL` is the only writable one, and it needs Administer for *both* directions — §9.10.5.7:
/// "The Access Control Cluster SHALL require the Administer privilege to observe and modify
/// the Access Control Cluster itself." A `View` subject cannot even read the list, which is
/// what stops it enumerating who else has access.
const ATTRIBUTES: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_write(ACL).with_access(
        Access::read_write_with(Privilege::Administer, Privilege::Administer)
            .with_qualities(AccessQualities::FABRIC_SCOPED),
    ),
    AttributeDescriptor::read_only(SUBJECTS_PER_ENTRY),
    AttributeDescriptor::read_only(TARGETS_PER_ENTRY),
    AttributeDescriptor::read_only(ENTRIES_PER_FABRIC),
];

const NO_COMMANDS: &[CommandDescriptor] = &[];

/// §9.10.9's events. `AccessControlEntryChanged` is `INFO` priority and fabric-sensitive.
const EVENTS: &[EventDescriptor] =
    &[EventDescriptor::new(ACCESS_CONTROL_ENTRY_CHANGED).with_priority(EventPriority::Info)];

/// The descriptor for this cluster.
#[must_use]
pub const fn cluster() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: 0,
        attributes: ATTRIBUTES,
        accepted_commands: NO_COMMANDS,
        generated_commands: &[],
        events: EVENTS,
    }
}

/// How many [`EntryChanged`] records the cluster holds before the device drains them.
///
/// One write can produce several: §9.10.9.1 asks for an event per entry, and a replace is a
/// removal of everything that was there followed by an addition of everything that now is. The
/// bound is what a device is expected to drain between interactions, not a list capacity — a
/// device that drains after every write never reaches it, and §9.10.6 requires only four ACL
/// entries per fabric, so eight covers a full replace of a conforming fabric's list.
const PENDING: usize = 8;

/// What one change to the `ACL` attribute should be recorded as (§9.10.9.1).
///
/// The server "SHALL generate AccessControlEntryChanged events whenever its ACL attribute
/// data is changed by an Administrator", and the event names *who*: "Exactly one of
/// AdminNodeID and AdminPasscodeID SHALL be set, depending on whether the change occurred via
/// a CASE or PASE session". Reported rather than logged here, because §7.14's event store is
/// the device's and this cluster does not own one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryChanged<const S: usize, const T: usize> {
    /// The administrator's node id, when the change came over CASE.
    pub admin_node_id: Option<NodeId>,
    /// The passcode id, when it came over PASE. Always `Some(0)` in practice: "Non-zero
    /// values are reserved for future use".
    pub admin_passcode_id: Option<u16>,
    /// What happened.
    pub change_type: ChangeType,
    /// `LatestValue [4]` — "The latest value of the changed entry", which for a removal is the
    /// entry as it stood when it was removed.
    ///
    /// `None` is the field's null, which §9.10.9.1 permits only as a concession: "This field
    /// SHOULD be set if resources are adequate for it; otherwise it SHALL be set to NULL if
    /// resources are scarce." An audit trail of *when* the list changed and never *to what* is
    /// most of the way to no audit trail, so this carries the entry wherever one is available.
    pub latest_value: Option<Entry<S, T>>,
    /// The fabric whose list changed.
    pub fabric_index: FabricIndex,
}

impl<const S: usize, const T: usize> EntryChanged<S, T> {
    /// The record for a change made on `ctx`'s session.
    #[must_use]
    pub fn for_session(
        ctx: &InteractionContext<'_>,
        change_type: ChangeType,
        latest_value: Option<Entry<S, T>>,
    ) -> Self {
        // §6.6.6.3 derives the administrator's identity from the *session*, never from
        // anything the message claimed.
        let (admin_node_id, admin_passcode_id) = match ctx.peer_node_id {
            Some(node_id) => (Some(node_id), None),
            None => (None, Some(0)),
        };
        let fabric_index = ctx.fabric_index.unwrap_or(FabricIndex(0));
        Self {
            admin_node_id,
            admin_passcode_id,
            change_type,
            latest_value,
            fabric_index,
        }
    }

    /// The same record, attributed to a fabric the session does not yet carry.
    ///
    /// §11.18.6.8 step 7 adds the administrator entry for a fabric *during* `AddNOC`, over a
    /// PASE session whose accessing fabric is bound only at step 10a — so at the moment of the
    /// change `ctx.fabric_index` is still none, and the event would be attributed to fabric 0
    /// and visible to nobody. §7.14.4 makes a fabric-sensitive event readable only by its own
    /// fabric, which for this one means the fabric it just created.
    #[must_use]
    pub fn for_fabric(mut self, fabric_index: FabricIndex) -> Self {
        self.fabric_index = fabric_index;
        self
    }

    /// Writes the event's fields (§9.10.9.1).
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> crate::error::Result<()> {
        w.start_structure(tag)?;
        match self.admin_node_id {
            Some(id) => w.unsigned(Tag::Context(1), id.0)?,
            None => w.null(Tag::Context(1))?,
        }
        match self.admin_passcode_id {
            Some(id) => w.unsigned(Tag::Context(2), u64::from(id))?,
            None => w.null(Tag::Context(2))?,
        }
        w.unsigned(Tag::Context(3), self.change_type as u64)?;
        match &self.latest_value {
            Some(entry) => write_entry(w, Tag::Context(4), entry)?,
            None => w.null(Tag::Context(4))?,
        }
        w.unsigned(
            Tag::Context(FABRIC_INDEX_FIELD),
            u64::from(self.fabric_index.0),
        )?;
        w.end_container()
    }
}

/// One `AccessControlEntryStruct` (§9.10.5.7), as the `ACL` attribute and the
/// `AccessControlEntryChanged` event both need it.
///
/// One encoder rather than two: an event whose `LatestValue` disagreed with the attribute it
/// reports a change to would be worse than no event, and two copies of this drift in exactly
/// the fields — the null-as-wildcard ones — that are easiest to get wrong.
fn write_entry<const S: usize, const T: usize>(
    w: &mut TlvWriter<'_>,
    tag: Tag,
    entry: &Entry<S, T>,
) -> crate::error::Result<()> {
    w.start_structure(tag)?;
    w.unsigned(Tag::Context(1), privilege_value(entry.privilege))?;
    w.unsigned(Tag::Context(2), entry.auth_mode as u64)?;
    // §9.10.5.7's Subjects and Targets are both `X` — nullable — and an empty list is written
    // as null rather than as an empty array, because null is the wildcard the algorithm reads
    // and an empty array would say "matches nothing".
    if entry.subjects.is_empty() {
        w.null(Tag::Context(3))?;
    } else {
        w.start_array(Tag::Context(3))?;
        for subject in &entry.subjects {
            w.unsigned(Tag::Anonymous, subject.0)?;
        }
        w.end_container()?;
    }
    if entry.targets.is_empty() {
        w.null(Tag::Context(4))?;
    } else {
        w.start_array(Tag::Context(4))?;
        for target in &entry.targets {
            w.start_structure(Tag::Anonymous)?;
            match target.cluster {
                Some(id) => w.unsigned(Tag::Context(0), u64::from(id))?,
                None => w.null(Tag::Context(0))?,
            }
            match target.endpoint {
                Some(id) => w.unsigned(Tag::Context(1), u64::from(id))?,
                None => w.null(Tag::Context(1))?,
            }
            match target.device_type {
                Some(id) => w.unsigned(Tag::Context(2), u64::from(id))?,
                None => w.null(Tag::Context(2))?,
            }
            w.end_container()?;
        }
        w.end_container()?;
    }
    w.unsigned(
        Tag::Context(FABRIC_INDEX_FIELD),
        u64::from(entry.fabric_index.0),
    )?;
    w.end_container()
}

/// The Access Control cluster over a node's [`Acl`].
///
/// The list is borrowed rather than owned, because §6.6.6 consults it on every interaction
/// while this cluster only edits it — the same table has to be visible to both, and a copy
/// would be a second answer to "who may do what".
#[derive(Debug)]
pub struct AccessControl<'a, C: Config, const N: usize, const S: usize, const T: usize> {
    acl: &'a RefCell<Acl<C, N, S, T>>,
    /// What the last write recorded, for the device to turn into §7.14 events.
    pending: RefCell<heapless::Vec<EntryChanged<S, T>, PENDING>>,
}

impl<'a, C: Config, const N: usize, const S: usize, const T: usize> AccessControl<'a, C, N, S, T> {
    /// A cluster over a node's access control list.
    #[must_use]
    pub fn new(acl: &'a RefCell<Acl<C, N, S, T>>) -> Self {
        Self {
            acl,
            pending: RefCell::new(heapless::Vec::new()),
        }
    }

    /// The list this cluster edits.
    #[must_use]
    pub const fn acl(&self) -> &'a RefCell<Acl<C, N, S, T>> {
        self.acl
    }

    /// §11.18.6.8 step 7's administrator entry, added through the cluster so that it is
    /// recorded like any other change.
    ///
    /// `AddNOC` creates exactly one ACL entry — "there would be no way for the caller on its
    /// given Fabric to eventually add another Access Control Entry for CASE authentication
    /// mode" without it — and it is the *only* entry on a freshly commissioned fabric. Added
    /// straight to the [`Acl`] it is invisible to §9.10.9.1: the cluster never sees it, so the
    /// audit trail of an Access Control cluster begins by omitting the one entry that granted
    /// everything else. That is what the Test Harness reads first, and it is what an auditor
    /// would want first.
    ///
    /// `ctx` is the `AddNOC` interaction, which is a PASE session — so the event names an
    /// `AdminPasscodeID` and a null `AdminNodeID`, as §9.10.9.1 requires of a change made over
    /// PASE. `fabric` is passed separately because §11.18.6.8 binds the accessing fabric to the
    /// session only at step 10a, *after* this: taking it from `ctx` would attribute the event
    /// to fabric 0, where §7.14.4's fabric sensitivity would hide it from everybody.
    pub fn add_admin_for_fabric(
        &self,
        fabric: FabricIndex,
        subject: NodeId,
        ctx: &InteractionContext<'_>,
    ) -> crate::error::Result<()> {
        self.acl
            .borrow_mut()
            .add_admin_for_fabric(fabric, subject)?;
        // The entry just added, which `Acl::add` appends: the last one on this fabric.
        let entry = self.acl.borrow().of_fabric(fabric).last().cloned();
        self.record(EntryChanged::for_session(ctx, ChangeType::Added, entry).for_fabric(fabric));
        Ok(())
    }

    /// Takes the [`EntryChanged`] records the last writes produced (§9.10.9.1).
    ///
    /// The device turns these into events in its own store. Draining rather than reading
    /// means a record is reported once, and a device that never drains cannot silently
    /// accumulate them forever — the buffer is fixed and the oldest records are dropped,
    /// the same way §7.14.2's event ring drops its oldest.
    pub fn take_changes(&self) -> heapless::Vec<EntryChanged<S, T>, PENDING> {
        core::mem::take(&mut self.pending.borrow_mut())
    }

    fn record(&self, change: EntryChanged<S, T>) {
        let mut pending = self.pending.borrow_mut();
        if pending.is_full() {
            // Dropping the oldest matches §7.14.2's event ring: the most recent change is the
            // one an auditor needs first.
            let _ = pending.remove(0);
        }
        let _ = pending.push(change);
    }

    /// Whether a fabric's entries belong in this read (§7.19.1.8.2).
    fn visible(ctx: &InteractionContext<'_>, index: FabricIndex) -> bool {
        !ctx.fabric_filtered || ctx.fabric_index == Some(index)
    }

    fn read_acl(
        &self,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let acl = self.acl.borrow();
        full(w.start_array(tag))?;
        for entry in acl.entries().filter(|e| Self::visible(ctx, e.fabric_index)) {
            full(write_entry(w, Tag::Anonymous, entry))?;
        }
        full(w.end_container())
    }
}

/// §9.10.5.2's wire values, which are not this crate's enum discriminants.
///
/// The specification numbers `View` 1 and `ProxyView` 2; [`Privilege`] orders them by what
/// they grant, so `ProxyView` sorts *below* `View`. The two orders disagree on purpose and
/// this is where they are reconciled — encoding the discriminant directly would silently
/// swap View and ProxyView on the wire.
const fn privilege_value(privilege: Privilege) -> u64 {
    match privilege {
        Privilege::View => 1,
        Privilege::ProxyView => 2,
        Privilege::Operate => 3,
        Privilege::Manage => 4,
        Privilege::Administer => 5,
    }
}

const fn privilege_from_value(value: u64) -> Option<Privilege> {
    match value {
        1 => Some(Privilege::View),
        2 => Some(Privilege::ProxyView),
        3 => Some(Privilege::Operate),
        4 => Some(Privilege::Manage),
        5 => Some(Privilege::Administer),
        _ => None,
    }
}

/// Reads one `AccessControlEntryStruct` (§9.10.5.7) whose opening structure has been taken.
fn decode_entry<const S: usize, const T: usize>(
    reader: &mut TlvReader<'_>,
    fabric_index: FabricIndex,
) -> Result<Entry<S, T>, Status> {
    let mut privilege = None;
    let mut auth_mode = None;
    let mut subjects = heapless::Vec::new();
    let mut targets = heapless::Vec::new();

    loop {
        let Some(element) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if element.value == Value::EndOfContainer {
            break;
        }
        match element.tag.context() {
            Some(1) => {
                let value = element.unsigned().map_err(|_| Status::ConstraintError)?;
                privilege = Some(privilege_from_value(value).ok_or(Status::ConstraintError)?);
            }
            Some(2) => {
                let value = element.unsigned().map_err(|_| Status::ConstraintError)?;
                let narrowed = u8::try_from(value).map_err(|_| Status::ConstraintError)?;
                auth_mode = Some(AuthMode::from_value(narrowed).ok_or(Status::ConstraintError)?);
            }
            Some(3) => {
                if element.value.is_null() {
                    continue;
                }
                if element.value.container() != Some(ContainerKind::Array) {
                    return Err(Status::InvalidAction);
                }
                loop {
                    let Some(item) = reader.next_element().map_err(|_| Status::InvalidAction)?
                    else {
                        return Err(Status::InvalidAction);
                    };
                    if item.value == Value::EndOfContainer {
                        break;
                    }
                    let id = item.unsigned().map_err(|_| Status::ConstraintError)?;
                    subjects
                        .push(NodeId(id))
                        .map_err(|_| Status::ResourceExhausted)?;
                }
            }
            Some(4) => {
                if element.value.is_null() {
                    continue;
                }
                if element.value.container() != Some(ContainerKind::Array) {
                    return Err(Status::InvalidAction);
                }
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
                    targets
                        .push(decode_target(reader)?)
                        .map_err(|_| Status::ResourceExhausted)?;
                }
            }
            // The FabricIndex a client sends is ignored: §7.19.1.9's field is set by the
            // server from the accessing fabric, so a client cannot write into another's list
            // by naming it.
            _ => reader
                .skip_value(&element)
                .map_err(|_| Status::InvalidAction)?,
        }
    }

    Ok(Entry {
        fabric_index,
        privilege: privilege.ok_or(Status::InvalidAction)?,
        auth_mode: auth_mode.ok_or(Status::InvalidAction)?,
        subjects,
        targets,
    })
}

/// Reads one `AccessControlTargetStruct` (§9.10.5.6) whose opening structure has been taken.
fn decode_target(reader: &mut TlvReader<'_>) -> Result<Target, Status> {
    let mut target = Target::default();
    loop {
        let Some(element) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if element.value == Value::EndOfContainer {
            break;
        }
        if element.value.is_null() {
            continue;
        }
        let value = element.unsigned().map_err(|_| Status::ConstraintError)?;
        match element.tag.context() {
            Some(0) => {
                target.cluster = Some(u32::try_from(value).map_err(|_| Status::ConstraintError)?);
            }
            Some(1) => {
                target.endpoint = Some(u16::try_from(value).map_err(|_| Status::ConstraintError)?);
            }
            Some(2) => {
                target.device_type =
                    Some(u32::try_from(value).map_err(|_| Status::ConstraintError)?);
            }
            _ => {}
        }
    }
    if !target.is_valid() {
        return Err(Status::ConstraintError);
    }
    Ok(target)
}

impl<C: Config, const N: usize, const S: usize, const T: usize> ClusterHandler
    for AccessControl<'_, C, N, S, T>
{
    /// §9.10.5.3: every ACL entry carries a `FabricIndex`, and §11.18.6.12 removes them with
    /// the fabric. An entry that survives grants the *next* holder of that index whatever it
    /// granted — the one case in this file that is an escalation rather than a leak.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        if let crate::im::Lifecycle::FabricRemoved(fabric) = event {
            self.acl.borrow_mut().remove_fabric(fabric);
        }
    }
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            ACL => self.read_acl(ctx, w, tag),
            // §9.10.6.5–7 report the *minimum* the server supports, and every one of the three
            // comes from the list that will have to honour it: `S` and `T` are the entry's own
            // widths, and `PER_FABRIC` is the quota `Acl::insert` enforces. `Acl::CHECK` is what
            // makes the third of those a promise the list can keep — without it this attribute
            // is a number typed next to a table of a different size.
            SUBJECTS_PER_ENTRY => full(w.unsigned(tag, S as u64)),
            TARGETS_PER_ENTRY => full(w.unsigned(tag, T as u64)),
            ENTRIES_PER_FABRIC => full(w.unsigned(
                tag,
                <Acl<C, N, S, T> as crate::config::Capacity>::PER_FABRIC as u64,
            )),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        op: WriteOp,
        ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        if resolved.attribute != ACL {
            return Err(Status::UnsupportedWrite);
        }
        // §7.19.1.8.1: a write to a fabric-scoped list needs an accessing fabric to scope it
        // to. A PASE session has none, so it cannot edit the list even though it holds
        // Administer — there is no fabric for its entries to belong to.
        let Some(fabric_index) = ctx.fabric_index else {
            return Err(Status::UnsupportedAccess);
        };

        let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;

        let mut acl = self.acl.borrow_mut();
        match op {
            WriteOp::Replace => {
                // §10.6.4.3.1's REPLACE: "Data SHALL contain new values that will replace the
                // existing contents of the list", so an empty array clears it — which is how
                // the item-by-item encoding begins.
                if element.value.container() != Some(ContainerKind::Array) {
                    return Err(Status::InvalidAction);
                }
                let mut replacement: heapless::Vec<Entry<S, T>, N> = heapless::Vec::new();
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
                        .push(decode_entry(&mut reader, fabric_index)?)
                        .map_err(|_| Status::ResourceExhausted)?;
                }
                // §9.10.9.1 wants "the latest value of the changed entry" in every event, and
                // a replace removes entries as well as adding them — so the outgoing list is
                // copied out before it stops existing. `PENDING` because a record beyond that
                // many would be dropped by `record` anyway; copying further would buy nothing.
                let removed: heapless::Vec<Entry<S, T>, PENDING> =
                    acl.of_fabric(fabric_index).take(PENDING).cloned().collect();
                // A replace that fails partway leaves the fabric's list partly rebuilt. That
                // is not a defect to hide: §10.6.4.3.1 says so directly — "clients that
                // receive an error status for a write action to a list attribute SHOULD NOT
                // assume that the list contents are unchanged" — and pretending otherwise
                // would mean buffering a second copy of the whole list to roll back to.
                acl.replace_fabric(fabric_index, replacement)
                    .map_err(|_| Status::ConstraintError)?;
                let added: heapless::Vec<Entry<S, T>, PENDING> =
                    acl.of_fabric(fabric_index).take(PENDING).cloned().collect();
                drop(acl);
                // §9.10.9.1 gives three change types and a replace can produce all three, so
                // the two lists are compared **position by position**:
                //
                //   - a position that existed before and exists now was *changed*;
                //   - a position only in the new list was *added*;
                //   - a position only in the old list was *removed*.
                //
                // A list attribute's entry is identified by its index — §10.6.4.3.1 edits by
                // index — so rewriting the same value at the same position is still a write of
                // that entry and is still a Changed. A controller replacing `[admin]` with
                // `[admin, operator]` therefore gets one Changed and one Added, not a Removed
                // and two Addeds.
                //
                // The legacy list encoding falls out of the same rule rather than needing one
                // of its own: a client that clears the list and appends to it sends a replace
                // with an empty list — every position removed — and then one append per entry.
                let mut old_entries = removed.into_iter();
                let mut new_entries = added.into_iter();
                loop {
                    let (change_type, entry) = match (new_entries.next(), old_entries.next()) {
                        (Some(entry), Some(_)) => (ChangeType::Changed, entry),
                        (Some(entry), None) => (ChangeType::Added, entry),
                        (None, Some(entry)) => (ChangeType::Removed, entry),
                        (None, None) => break,
                    };
                    self.record(EntryChanged::for_session(ctx, change_type, Some(entry)));
                }
            }
            WriteOp::Append => {
                // §10.6.4.3.1's ADD: "Data containing the new value of the list item that
                // will be added to the list."
                if element.value.container() != Some(ContainerKind::Structure) {
                    return Err(Status::InvalidAction);
                }
                let entry = decode_entry::<S, T>(&mut reader, fabric_index)?;
                let recorded = entry.clone();
                acl.add(entry).map_err(|e| match e.code() {
                    crate::ErrorCode::NoSpace => Status::ResourceExhausted,
                    _ => Status::ConstraintError,
                })?;
                drop(acl);
                self.record(EntryChanged::for_session(
                    ctx,
                    ChangeType::Added,
                    Some(recorded),
                ));
            }
        }
        Ok(())
    }
}

impl<C: Config, const N: usize, const S: usize, const T: usize> Cluster
    for AccessControl<'_, C, N, S, T>
{
    const ID: ClusterId = ID;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultConfig;

    type TestAcl = Acl<DefaultConfig>;

    #[test]
    fn the_wire_values_are_section_9_10_5_2s_and_not_the_enums_order() {
        // `Privilege` orders by what it grants, so ProxyView sorts below View; §9.10.5.2
        // numbers View 1 and ProxyView 2. Encoding the discriminant would swap them.
        assert_eq!(privilege_value(Privilege::View), 1);
        assert_eq!(privilege_value(Privilege::ProxyView), 2);
        assert_eq!(privilege_value(Privilege::Operate), 3);
        assert_eq!(privilege_value(Privilege::Administer), 5);
        for value in 1..=5u64 {
            let privilege = privilege_from_value(value).expect("defined");
            assert_eq!(privilege_value(privilege), value, "round trips");
        }
        assert!(privilege_from_value(0).is_none());
        assert!(privilege_from_value(6).is_none());
    }

    #[test]
    fn the_descriptor_needs_administer_in_both_directions() {
        // §9.10.5.7: "The Access Control Cluster SHALL require the Administer privilege to
        // observe and modify the Access Control Cluster itself." A View subject that could
        // read the list would learn who else has access to the node.
        let descriptor = cluster();
        let acl = descriptor.attribute(ACL).expect("ACL attribute");
        assert_eq!(acl.access.read, Some(Privilege::Administer));
        assert_eq!(acl.access.write, Some(Privilege::Administer));
        assert!(acl.access.is_fabric_scoped());
    }

    #[test]
    fn the_minima_are_reported_from_the_list_that_holds_them() {
        // §9.10.6.5, §9.10.6.6 and §9.10.6.7 are constrained to `4..`, `3..` and `4..`, and all
        // three are answered from the list rather than from a constant beside it —
        // `Acl::CHECK` is what refuses a list too narrow or too short to mean them.
        let acl = RefCell::new(TestAcl::new());
        let cluster_impl = AccessControl::<_, 20, 4, 3>::new(&acl);
        assert_eq!(cluster_impl.acl().borrow().len(), 0);
        assert_eq!(<TestAcl as crate::config::Capacity>::PER_FABRIC, 4);
        const {
            assert!(
                <TestAcl as crate::config::Capacity>::TOTAL
                    >= <TestAcl as crate::config::Capacity>::PER_FABRIC * DefaultConfig::FABRICS
            );
        }
    }
}
