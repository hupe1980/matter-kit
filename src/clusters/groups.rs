//! Groups, cluster `0x0004` (Application Cluster §1.3).
//!
//! > The Groups cluster manages, per endpoint, the content of the node-wide Group Table that
//! > is part of the underlying interaction layer.
//!
//! What makes "turn off the kitchen" one message rather than six. An endpoint joins a group,
//! and a groupcast to that group reaches every member at once.
//!
//! # The table is per endpoint and scoped to a fabric
//!
//! Two scopes at once, and both matter. **Per endpoint**, because a two-gang switch has two
//! endpoints and they belong to different rooms. **Per fabric**, because §1.3 says so —
//! "group IDs referenced by attributes or other elements of this cluster are scoped to the
//! accessing fabric" — and a device that let one ecosystem see or remove another's groups
//! would leak the layout of somebody's house to whoever commissioned it second.
//!
//! # A groupcast gets no answer
//!
//! Every command here says the same thing: "If the ... command was received as a groupcast,
//! the server SHALL NOT generate a ... Response command." Six lights answering one multicast
//! is six unicasts the client did not ask for, arriving at once — the classic broadcast storm,
//! and the reason [`Groups::invoke`] consults [`InteractionContext`]'s group destination
//! rather than always replying.
//!
//! # What this cluster is not
//!
//! It does not route anything. §1.3: "configuration of group addresses for outgoing commands
//! is achieved using the Message Layer mechanisms where the Group Table is not involved."
//! This is the *membership* list; delivering a groupcast is [`crate::msg`]'s.

use core::cell::RefCell;

use crate::clusters::generated::groups as spec_groups;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::msg::{FabricIndex, GroupId};
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::Cluster;
use super::scenes::{NoScenes, ScenePurge};

/// What the Scenes Management cluster needs from the Group Table (§1.4.9's step 1).
///
/// Every Scenes command begins the same way: "If the value of the GroupID field is non-zero,
/// the server verifies that the endpoint has an entry for that GroupID in the Group Table."
/// A trait, so an endpoint may hold its memberships somewhere other than [`Groups`] — a
/// bridge, for instance, whose group table lives on the far side.
pub trait GroupMembership {
    /// Whether the endpoint is in `group` on `fabric`.
    fn is_group_member(&self, fabric: FabricIndex, group: GroupId) -> bool;
}

pub use spec_groups::attribute::NAME_SUPPORT;
pub use spec_groups::command::{
    ADD_GROUP, ADD_GROUP_IF_IDENTIFYING, ADD_GROUP_RESPONSE, GET_GROUP_MEMBERSHIP,
    GET_GROUP_MEMBERSHIP_RESPONSE, REMOVE_ALL_GROUPS, REMOVE_GROUP, REMOVE_GROUP_RESPONSE,
    VIEW_GROUP, VIEW_GROUP_RESPONSE,
};
pub use spec_groups::{ID, NameSupportBitmap, PICS, REVISION, feature};

/// §1.3.7.1's constraint on `GroupName`: "max 16".
pub const NAME_MAX: usize = 16;

/// One membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Membership {
    /// The group. §1.3.7.1.1's constraint is "min 1": zero is the null group.
    pub group: GroupId,
    /// Which fabric's group this is.
    pub fabric: FabricIndex,
    name: [u8; NAME_MAX],
    name_len: usize,
}

impl Membership {
    /// The group's name, empty when the device does not store names.
    #[must_use]
    pub fn name(&self) -> &str {
        // Written from a `&str`, so the prefix is always valid UTF-8.
        core::str::from_utf8(self.name.get(..self.name_len).unwrap_or(&[])).unwrap_or("")
    }
}

/// What the endpoint must tell the cluster for `AddGroupIfIdentifying` to work.
///
/// §1.3.7.6 makes that command conditional on the *Identify* cluster's state on the same
/// endpoint, which is the only coupling this cluster has. A device without Identify answers
/// `false` and the command is silently ignored — which is what the specification asks for.
pub trait Identifying {
    /// Whether the endpoint is identifying itself right now.
    fn is_identifying(&self) -> bool;
}

/// A device with no Identify cluster, for which `AddGroupIfIdentifying` never applies.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverIdentifying;

impl Identifying for NeverIdentifying {
    fn is_identifying(&self) -> bool {
        false
    }
}

/// The Groups cluster's table.
///
/// `N` is the total across every fabric. §1.3 gives no minimum, but a device type usually
/// does, and `per_fabric` is what stops the first ecosystem to commission filling the table
/// and leaving the second unable to make a single group.
#[derive(Debug)]
pub struct Groups<'a, const N: usize, I: Identifying = NeverIdentifying, S: ScenePurge = NoScenes> {
    memberships: RefCell<heapless::Vec<Membership, N>>,
    per_fabric: usize,
    names: bool,
    identifying: &'a I,
    scenes: &'a S,
}

impl<const N: usize> Groups<'static, N, NeverIdentifying, NoScenes> {
    /// A table for an endpoint with neither an Identify nor a Scenes Management cluster.
    #[must_use]
    pub const fn new(per_fabric: usize, names: bool) -> Self {
        Self::with(per_fabric, names, &NeverIdentifying, &NoScenes)
    }
}

impl<'a, const N: usize, I: Identifying, S: ScenePurge> Groups<'a, N, I, S> {
    /// A table for an endpoint whose Identify cluster `identifying` reports and whose scenes
    /// live in `scenes`.
    ///
    /// Both are what the *rest of the endpoint* contributes: §1.3.7.6 makes
    /// `AddGroupIfIdentifying` conditional on Identify, and §1.3.7.4 makes `RemoveGroup`
    /// remove that group's scenes. Pass [`NeverIdentifying`] or [`NoScenes`] for an endpoint
    /// that has neither — they compile to nothing.
    #[must_use]
    pub const fn with(per_fabric: usize, names: bool, identifying: &'a I, scenes: &'a S) -> Self {
        Self {
            memberships: RefCell::new(heapless::Vec::new()),
            per_fabric,
            names,
            identifying,
            scenes,
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<1, 6, 4, 0>> {
        Conforming::new(&spec_groups::CLUSTER, feature_map, optional)
    }

    /// `NameSupport` (§1.3.6.1).
    ///
    /// "The most significant bit, bit 7 (GroupNames), SHALL be equal to bit 0 of the FeatureMap
    /// attribute (GN Feature). All other bits SHALL be 0." A legacy view of one feature bit,
    /// kept in step here so the two cannot disagree.
    #[must_use]
    pub fn name_support(&self) -> NameSupportBitmap {
        if self.names {
            NameSupportBitmap::GROUP_NAMES
        } else {
            NameSupportBitmap::empty()
        }
    }

    /// The `FeatureMap` this instance should declare.
    #[must_use]
    pub const fn feature_map(&self) -> u32 {
        if self.names { feature::GROUP_NAMES } else { 0 }
    }

    /// Every membership, for a device about to persist them.
    #[must_use]
    pub fn memberships(&self) -> core::cell::Ref<'_, heapless::Vec<Membership, N>> {
        self.memberships.borrow()
    }

    /// Whether the endpoint is in a group, on a fabric.
    #[must_use]
    pub fn is_member(&self, fabric: FabricIndex, group: GroupId) -> bool {
        self.memberships
            .borrow()
            .iter()
            .any(|m| m.fabric == fabric && m.group == group)
    }

    /// How many groups one fabric holds on this endpoint.
    #[must_use]
    pub fn len_of_fabric(&self, fabric: FabricIndex) -> usize {
        self.memberships
            .borrow()
            .iter()
            .filter(|m| m.fabric == fabric)
            .count()
    }

    /// §1.3.7.9.1's `Capacity`: how many more groups this fabric may add.
    #[must_use]
    pub fn capacity(&self, fabric: FabricIndex) -> u8 {
        let used = self.len_of_fabric(fabric);
        let free = self.per_fabric.saturating_sub(used);
        // "0xFE - At least 1 further group MAY be added (exact number is unknown)" is for a
        // device that cannot count; this one can, so it says the number.
        u8::try_from(free.min(0xFD)).unwrap_or(0xFD)
    }

    /// Removes every membership of one fabric — what `RemoveFabric` must do.
    ///
    /// The fabric's scenes go with them: §1.4.6 says "Upon leaving a fabric with the
    /// RemoveFabric command ... all scenes data for the associated fabric SHALL be removed",
    /// and a group's scenes outliving the group is the same leak `RemoveGroup` avoids.
    pub fn remove_fabric(&self, fabric: FabricIndex) {
        self.memberships.borrow_mut().retain(|m| m.fabric != fabric);
        self.scenes.remove_grouped_scenes(fabric);
    }

    /// §1.3.7.1's steps 1–5.
    fn add(&self, fabric: FabricIndex, group: GroupId, name: &str) -> Status {
        // Step 1. "min 1": group 0 is the null group and is not a group to join.
        if group.0 == 0 || name.len() > NAME_MAX {
            return Status::ConstraintError;
        }
        let mut stored = [0u8; NAME_MAX];
        // "If the server does not support group names, the GroupName field SHALL be ignored."
        let kept = if self.names { name } else { "" };
        let len = kept.len().min(NAME_MAX);
        if let (Some(slot), Some(source)) = (stored.get_mut(..len), kept.as_bytes().get(..len)) {
            slot.copy_from_slice(source);
        }

        let mut memberships = self.memberships.borrow_mut();
        // Step 3: already a member — update the name and succeed. Not an error, because a
        // client re-sending `AddGroup` is how §1.3.7.1.3's step 5a renames a group.
        if let Some(existing) = memberships
            .iter_mut()
            .find(|m| m.fabric == fabric && m.group == group)
        {
            existing.name = stored;
            existing.name_len = len;
            return Status::Success;
        }
        // Step 4.
        if memberships.iter().filter(|m| m.fabric == fabric).count() >= self.per_fabric {
            return Status::ResourceExhausted;
        }
        // Step 5.
        match memberships.push(Membership {
            group,
            fabric,
            name: stored,
            name_len: len,
        }) {
            Ok(()) => Status::Success,
            Err(_) => Status::ResourceExhausted,
        }
    }

    /// §1.3.7.4's steps 1–3.
    fn remove(&self, fabric: FabricIndex, group: GroupId) -> Status {
        if group.0 == 0 {
            return Status::ConstraintError;
        }
        let removed = {
            let mut memberships = self.memberships.borrow_mut();
            let before = memberships.len();
            memberships.retain(|m| !(m.fabric == fabric && m.group == group));
            memberships.len() != before
        };
        if !removed {
            return Status::NotFound;
        }
        // §1.3.7.4: "if the Scenes Management cluster is supported on the same endpoint,
        // scenes associated with the indicated group SHALL be removed on that endpoint." A
        // rule about the Scene Table, written in this cluster's chapter — and a device that
        // skipped it would keep scenes addressed to a group it has left.
        self.scenes.remove_group_scenes(fabric, group);
        Status::Success
    }
}

impl<const N: usize, I: Identifying, S: ScenePurge> ClusterHandler for Groups<'_, N, I, S> {
    /// §1.3: group membership is fabric-scoped, and §1.3.7.4's rule that a group's scenes go
    /// with the group applies here too — `remove_fabric` takes both.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        if let crate::im::Lifecycle::FabricRemoved(fabric) = event {
            self.remove_fabric(fabric);
        }
    }
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        if resolved.attribute != NAME_SUPPORT {
            return Err(Status::UnsupportedAttribute);
        }
        w.unsigned(tag, u64::from(self.name_support().bits()))
            .map_err(|_| Status::ResourceExhausted)
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        // §1.3.7.*: "If the ... command was received as a groupcast, the server SHALL NOT
        // generate a ... Response command." Six lights answering one multicast at once is the
        // storm the rule exists to prevent.
        let answer = ctx.group.is_none();
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        // §1.3: "All commands defined in this cluster SHALL only affect groups scoped to the
        // accessing fabric." Without one there is nothing to scope to.
        let Some(fabric) = ctx.fabric_index else {
            return Err(Status::UnsupportedAccess.into());
        };

        match resolved.command.id {
            ADD_GROUP_IF_IDENTIFYING => {
                let decoded: spec_groups::AddGroupIfIdentifyingFields<'_> =
                    super::decode_fields(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                // §1.3.7.6: the conditional form does nothing at all unless the endpoint is
                // identifying itself, and says nothing either way — the specification defines
                // no response command for it, so even a unicast gets only a status.
                if self.identifying.is_identifying() {
                    self.add(fabric, decoded.group_id, decoded.group_name);
                }
                Ok(None)
            }
            ADD_GROUP => {
                let decoded: spec_groups::AddGroupFields<'_> =
                    super::decode_fields(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                let status = self.add(fabric, decoded.group_id, decoded.group_name);
                if !answer {
                    return Ok(None);
                }
                full(
                    spec_groups::AddGroupResponseFields {
                        status: status.value(),
                        group_id: decoded.group_id,
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(ADD_GROUP_RESPONSE))
            }
            VIEW_GROUP => {
                let decoded: spec_groups::ViewGroupFields =
                    super::decode_fields(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                let memberships = self.memberships.borrow();
                let found = memberships
                    .iter()
                    .find(|m| m.fabric == fabric && m.group == decoded.group_id);
                let status = match (decoded.group_id.0, found) {
                    (0, _) => Status::ConstraintError,
                    (_, Some(_)) => Status::Success,
                    (_, None) => Status::NotFound,
                };
                let name = found.map_or("", Membership::name);
                if !answer {
                    return Ok(None);
                }
                full(
                    spec_groups::ViewGroupResponseFields {
                        status: status.value(),
                        group_id: decoded.group_id,
                        group_name: name,
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(VIEW_GROUP_RESPONSE))
            }
            GET_GROUP_MEMBERSHIP => {
                let decoded: spec_groups::GetGroupMembershipFields<'_> =
                    super::decode_fields(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                // A groupcast gets nothing back — including the "no match" case §1.3.7.3
                // singles out ("the server SHALL only respond if the command is unicast"),
                // which this covers by never reaching the writer at all.
                if !answer {
                    return Ok(None);
                }
                // §1.3.7.3.1: "If the GroupList field is empty, the server SHALL respond with
                // all group IDs indicating the groups of which the server endpoint is a
                // member"; otherwise the intersection. Both readings are one pass over the
                // table, with the request's list re-read per candidate rather than copied into
                // a buffer this cluster would then have to size — a client may name more
                // groups than the endpoint could ever hold.
                let everything = decoded.group_list.is_empty();
                let memberships = self.memberships.borrow();
                full(w.start_structure(tag))?;
                full(w.unsigned(Tag::Context(0), u64::from(self.capacity(fabric))))?;
                full(w.start_array(Tag::Context(1)))?;
                for membership in memberships.iter().filter(|m| m.fabric == fabric) {
                    if !everything {
                        let mut asked = false;
                        for entry in decoded.group_list.iter() {
                            let group: GroupId =
                                entry.map_err(|_| StatusIb::from(Status::ConstraintError))?;
                            if group == membership.group {
                                asked = true;
                                break;
                            }
                        }
                        if !asked {
                            continue;
                        }
                    }
                    full(w.unsigned(Tag::Anonymous, u64::from(membership.group.0)))?;
                }
                full(w.end_container())?;
                full(w.end_container())?;
                Ok(Some(GET_GROUP_MEMBERSHIP_RESPONSE))
            }
            REMOVE_GROUP => {
                let decoded: spec_groups::RemoveGroupFields =
                    super::decode_fields(fields.ok_or(StatusIb::from(Status::InvalidCommand))?)?;
                let status = self.remove(fabric, decoded.group_id);
                if !answer {
                    return Ok(None);
                }
                full(
                    spec_groups::RemoveGroupResponseFields {
                        status: status.value(),
                        group_id: decoded.group_id,
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(REMOVE_GROUP_RESPONSE))
            }
            REMOVE_ALL_GROUPS => {
                // §1.3.7.5: every membership *for this fabric*. A device that cleared the
                // whole table would remove another ecosystem's groups on a command it has no
                // business acting on.
                self.memberships.borrow_mut().retain(|m| m.fabric != fabric);
                // "all scenes, except for scenes associated with group ID 0, SHALL be
                // removed" — group 0's scenes were never reachable through a group, so
                // leaving every group has not stranded them.
                self.scenes.remove_grouped_scenes(fabric);
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<const N: usize, I: Identifying, S: ScenePurge> GroupMembership for Groups<'_, N, I, S> {
    fn is_group_member(&self, fabric: FabricIndex, group: GroupId) -> bool {
        self.is_member(fabric, group)
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<const N: usize, I: Identifying, S: ScenePurge> Cluster for Groups<'_, N, I, S> {
    const ID: ClusterId = ID;
}
