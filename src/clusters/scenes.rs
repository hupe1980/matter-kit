//! Scenes Management, cluster `0x0062` (Application Cluster §1.4).
//!
//! > Each scene corresponds to a set of stored values of specified attributes for one or more
//! > clusters on the same end point as the Scenes Management cluster.
//!
//! "Movie night" — the lights at 15%, warm, and the blind down — stored once and recalled with
//! one command. What a scene actually holds is an *extension field set* per cluster: a list of
//! attribute ids and values, restricted to attributes carrying §7.13's Scenes ("S") quality.
//!
//! # The table is shared with Groups
//!
//! §1.3.7.4 makes `RemoveGroup` remove that group's scenes, and §1.3.7.5 makes
//! `RemoveAllGroups` remove every scene but group 0's. That is a rule about *this* cluster's
//! data written in *that* cluster's chapter, so the Scene Table is a value of its own —
//! [`SceneTable`] — that the device gives to both clusters, rather than state hidden inside
//! one of them. A device that skipped the wiring would accumulate scenes addressed to groups
//! it has left: storage nobody can reach and nobody can reclaim.
//!
//! # Half the table, per fabric
//!
//! §1.4.6: "The Scene Table capacity for a given fabric SHALL be less than half (rounded down
//! towards 0) of the Scene Table entries". Not a nicety — without it the first ecosystem to
//! commission can fill the table and the second cannot store a single scene.
//!
//! # What the cluster does not know
//!
//! Which attributes have the Scenes quality, and what setting them means. That lives with the
//! clusters that own them, behind [`SceneHooks`]: this cluster stores bytes and hands them
//! back in the right order.

use core::cell::RefCell;

use crate::clusters::generated::scenes_management as spec_scenes;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::msg::{FabricIndex, GroupId};
use crate::tlv::{Tag, TlvList, TlvWriter, ToTlv};

use super::Cluster;
use super::groups::GroupMembership;

pub use spec_scenes::attribute::{FABRIC_SCENE_INFO, SCENE_TABLE_SIZE};
pub use spec_scenes::command::{
    ADD_SCENE, ADD_SCENE_RESPONSE, COPY_SCENE, COPY_SCENE_RESPONSE, GET_SCENE_MEMBERSHIP,
    GET_SCENE_MEMBERSHIP_RESPONSE, RECALL_SCENE, REMOVE_ALL_SCENES, REMOVE_ALL_SCENES_RESPONSE,
    REMOVE_SCENE, REMOVE_SCENE_RESPONSE, STORE_SCENE, STORE_SCENE_RESPONSE, VIEW_SCENE,
    VIEW_SCENE_RESPONSE,
};
pub use spec_scenes::{
    AttributeValuePairStruct, CopyModeBitmap, ExtensionFieldSetStruct, ID, PICS, REVISION, feature,
};

/// §1.4.7.5's constraint on `SceneName`: "max 16".
pub const NAME_MAX: usize = 16;

/// §1.4.9.1: "The scene identifier 0, when used with group identifier 0, is reserved for the
/// global scene used by the On/Off cluster."
pub const GLOBAL_SCENE: u8 = 0;

/// §1.4.7.2.2's "undefined scene identifier", which `CurrentScene` reports before any recall.
pub const UNDEFINED_SCENE: u8 = 0xFF;

/// §1.4.7.5's constraint on `SceneID`: "max 254". 255 is [`UNDEFINED_SCENE`].
pub const SCENE_MAX: u8 = 254;

/// §1.4.9.2's constraint on `TransitionTime`: "max 60000000" milliseconds — a little over
/// sixteen hours, which is the longest fade the specification admits.
pub const TRANSITION_MAX: u32 = 60_000_000;

/// §1.4.7.2.5's constraint on `RemainingCapacity`: "max 253".
pub const CAPACITY_MAX: u8 = 253;

/// One row of §1.4.7.5's logical Scene Table.
#[derive(Debug, Clone)]
struct Entry<const EFS: usize> {
    fabric: FabricIndex,
    group: GroupId,
    scene: u8,
    name: [u8; NAME_MAX],
    name_len: usize,
    transition: u32,
    /// The encoded members of the `ExtensionFieldSetStructs` array, exactly as they arrived.
    ///
    /// Kept as bytes rather than decoded, because what they *mean* belongs to the clusters
    /// that own the attributes — and because re-encoding a structure this cluster does not
    /// interpret is a chance to change it.
    fields: heapless::Vec<u8, EFS>,
}

impl<const EFS: usize> Entry<EFS> {
    fn name(&self) -> &str {
        core::str::from_utf8(self.name.get(..self.name_len).unwrap_or(&[])).unwrap_or("")
    }
}

/// §1.4.7.2's `SceneInfoStruct`, per fabric.
#[derive(Debug, Clone, Copy)]
struct FabricInfo {
    fabric: FabricIndex,
    current_scene: u8,
    current_group: GroupId,
    valid: bool,
}

/// The Scene Table (§1.4.7.5), shared by the Scenes Management and Groups clusters.
///
/// `N` is the number of entries across every fabric — §1.4.8.1 sets the minimum at 16 — `EFS`
/// the bytes one scene's extension field sets may occupy, and `F` the fabrics whose
/// `SceneInfoStruct` is tracked. §1.4.8.2: "The number of list entries for this attribute
/// SHALL NOT exceed the number of supported fabrics by the device."
#[derive(Debug)]
pub struct SceneTable<const N: usize, const EFS: usize, const F: usize = 5> {
    entries: RefCell<heapless::Vec<Entry<EFS>, N>>,
    info: RefCell<heapless::Vec<FabricInfo, F>>,
    names: bool,
}

impl<const N: usize, const EFS: usize, const F: usize> SceneTable<N, EFS, F> {
    /// An empty table. `names` is the `SceneNames` feature.
    #[must_use]
    pub const fn new(names: bool) -> Self {
        Self {
            entries: RefCell::new(heapless::Vec::new()),
            info: RefCell::new(heapless::Vec::new()),
            names,
        }
    }

    /// `SceneTableSize` (§1.4.8.1) — the total across all fabrics.
    #[must_use]
    pub const fn size(&self) -> u16 {
        // A table larger than 65 535 cannot be reported, so it is not a table this cluster
        // can honestly serve; saturating says the largest number it can.
        if N > u16::MAX as usize {
            u16::MAX
        } else {
            N as u16
        }
    }

    /// §1.4.6's per-fabric ceiling: "less than half (rounded down towards 0) of the Scene
    /// Table entries ... with a maximum of 253".
    ///
    /// The point of the rule is that no single fabric can take enough of the table to leave
    /// another with nothing, so the bound is half rather than some tuned fraction.
    #[must_use]
    pub const fn per_fabric(&self) -> usize {
        let half = N / 2;
        if half > CAPACITY_MAX as usize {
            CAPACITY_MAX as usize
        } else {
            half
        }
    }

    /// How many scenes one fabric holds.
    #[must_use]
    pub fn len_of_fabric(&self, fabric: FabricIndex) -> usize {
        self.entries
            .borrow()
            .iter()
            .filter(|e| e.fabric == fabric)
            .count()
    }

    /// §1.4.7.2.5's `RemainingCapacity` for one fabric.
    #[must_use]
    pub fn capacity(&self, fabric: FabricIndex) -> u8 {
        // Bounded by whichever runs out first: this fabric's share, or the table itself.
        let mine = self.per_fabric().saturating_sub(self.len_of_fabric(fabric));
        let whole = N.saturating_sub(self.entries.borrow().len());
        u8::try_from(mine.min(whole).min(CAPACITY_MAX as usize)).unwrap_or(CAPACITY_MAX)
    }

    /// Whether a scene exists.
    #[must_use]
    pub fn contains(&self, fabric: FabricIndex, group: GroupId, scene: u8) -> bool {
        self.find(fabric, group, scene).is_some()
    }

    fn find(&self, fabric: FabricIndex, group: GroupId, scene: u8) -> Option<usize> {
        self.entries
            .borrow()
            .iter()
            .position(|e| e.fabric == fabric && e.group == group && e.scene == scene)
    }

    /// How many scenes the table holds in total.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Whether the table holds no scenes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// §1.4.7.2.4: an S-quality attribute on this endpoint changed, so no fabric's
    /// `CurrentScene` describes the endpoint any more.
    ///
    /// The device calls this from the cluster that changed — turning a light on by hand
    /// invalidates the scene just as surely as recalling a different one does.
    pub fn invalidate(&self) {
        for info in self.info.borrow_mut().iter_mut() {
            info.valid = false;
        }
    }

    /// Records that `fabric` just recalled or stored `group`/`scene`.
    ///
    /// §1.4.7.2.4 makes this invalidate *every other* fabric's view: the endpoint now matches
    /// one fabric's idea of the scene, and by construction not the others'.
    fn note(&self, fabric: FabricIndex, group: GroupId, scene: u8) {
        let mut info = self.info.borrow_mut();
        for entry in info.iter_mut() {
            if entry.fabric == fabric {
                entry.current_scene = scene;
                entry.current_group = group;
                entry.valid = true;
            } else {
                entry.valid = false;
            }
        }
        if !info.iter().any(|e| e.fabric == fabric) {
            // A full info list is not a reason to refuse the recall: the scene was applied,
            // and only the bookkeeping §1.4.8.2 caps is lost.
            let _ = info.push(FabricInfo {
                fabric,
                current_scene: scene,
                current_group: group,
                valid: true,
            });
        }
    }

    /// §1.4.9.2's steps 3 and 4 — add or replace, honouring the per-fabric ceiling.
    fn put(
        &self,
        fabric: FabricIndex,
        group: GroupId,
        scene: u8,
        name: &str,
        transition: u32,
        fields: &[u8],
    ) -> Status {
        let mut stored = [0u8; NAME_MAX];
        let kept = if self.names { name } else { "" };
        let len = kept.len().min(NAME_MAX);
        if let (Some(slot), Some(source)) = (stored.get_mut(..len), kept.as_bytes().get(..len)) {
            slot.copy_from_slice(source);
        }
        let Ok(fields) = heapless::Vec::from_slice(fields) else {
            // The scene is larger than this device reserved for one. §1.4.9.2.6 has no code
            // for "too big to hold", and RESOURCE_EXHAUSTED is what step 3 says when the
            // table cannot take the scene — which is the truth here too.
            return Status::ResourceExhausted;
        };

        let mut entries = self.entries.borrow_mut();
        if let Some(index) = entries
            .iter()
            .position(|e| e.fabric == fabric && e.group == group && e.scene == scene)
        {
            // Step 3: "the already existing scene entry SHALL be replaced".
            if let Some(existing) = entries.get_mut(index) {
                existing.name = stored;
                existing.name_len = len;
                existing.transition = transition;
                existing.fields = fields;
            }
            return Status::Success;
        }
        if entries.iter().filter(|e| e.fabric == fabric).count() >= self.per_fabric() {
            return Status::ResourceExhausted;
        }
        match entries.push(Entry {
            fabric,
            group,
            scene,
            name: stored,
            name_len: len,
            transition,
            fields,
        }) {
            Ok(()) => Status::Success,
            Err(_) => Status::ResourceExhausted,
        }
    }

    /// Removes every scene a fabric owns — what `RemoveFabric` must do (§1.4.6).
    pub fn remove_fabric(&self, fabric: FabricIndex) {
        self.entries.borrow_mut().retain(|e| e.fabric != fabric);
        self.info.borrow_mut().retain(|i| i.fabric != fabric);
    }
}

/// What the Groups cluster needs from a Scene Table when a group goes away.
///
/// A trait rather than a direct call, so that a device with no Scenes Management cluster
/// carries none of it: [`NoScenes`] is the default and compiles to nothing.
pub trait ScenePurge {
    /// §1.3.7.4: "scenes associated with the indicated group SHALL be removed".
    fn remove_group_scenes(&self, fabric: FabricIndex, group: GroupId);

    /// §1.3.7.5: "all scenes, except for scenes associated with group ID 0, SHALL be removed".
    fn remove_grouped_scenes(&self, fabric: FabricIndex);
}

impl<const N: usize, const EFS: usize, const F: usize> ScenePurge for SceneTable<N, EFS, F> {
    fn remove_group_scenes(&self, fabric: FabricIndex, group: GroupId) {
        self.entries
            .borrow_mut()
            .retain(|e| !(e.fabric == fabric && e.group == group));
    }

    fn remove_grouped_scenes(&self, fabric: FabricIndex) {
        // Group 0's scenes survive: they were never reachable through a group in the first
        // place, so leaving every group has not made them unreachable.
        self.entries
            .borrow_mut()
            .retain(|e| !(e.fabric == fabric && e.group.0 != 0));
    }
}

/// An endpoint with no Scenes Management cluster, for which nothing has to be purged.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoScenes;

impl ScenePurge for NoScenes {
    fn remove_group_scenes(&self, _fabric: FabricIndex, _group: GroupId) {}
    fn remove_grouped_scenes(&self, _fabric: FabricIndex) {}
}

/// What the endpoint's other clusters contribute to a scene.
///
/// §1.4.7.5.5: "A Scene Table Extension SHALL only use attributes with the Scene quality."
/// Which attributes those are is the *other* clusters' knowledge, not this one's — On/Off
/// contributes `OnOff`, Level Control contributes `CurrentLevel`, and a device that wired the
/// mapping into Scenes Management would have to change this cluster every time it gained one.
pub trait SceneHooks {
    /// Writes the endpoint's current S-quality state as the members of an
    /// `ExtensionFieldSetStructs` array — one structure per cluster, no array header.
    ///
    /// Called by `StoreScene` (§1.4.9.10), which stores "the current state of other clusters
    /// on the same endpoint" rather than anything the client sent.
    fn capture(&self, w: &mut TlvWriter<'_>) -> crate::error::Result<()>;

    /// Applies a stored scene's extension field sets over `transition` milliseconds.
    ///
    /// §1.4.9.12.4: "If there is no extension field set for a cluster, the state of that
    /// cluster SHALL remain unchanged... If an extension field set would cause an unknown or
    /// missing attribute to be set for any reason, that attribute SHALL be skipped." Both are
    /// the implementer's to honour, because both are about clusters this one cannot see.
    ///
    /// Sets arrive in the order they were stored, so where a client sent the same cluster
    /// twice, §1.4.9.2.6 step 4c's "the last one within the list SHALL be the one recorded"
    /// falls out of applying them in order.
    fn apply<'a>(&self, sets: TlvList<'a, ExtensionFieldSetStruct<'a>>, transition: u32);
}

/// Scenes Management over a shared [`SceneTable`].
#[derive(Debug)]
pub struct Scenes<
    'a,
    H: SceneHooks,
    G: GroupMembership,
    const N: usize,
    const EFS: usize,
    const F: usize = 5,
> {
    table: &'a SceneTable<N, EFS, F>,
    groups: &'a G,
    hooks: &'a H,
    copy_scene: bool,
}

impl<'a, H: SceneHooks, G: GroupMembership, const N: usize, const EFS: usize, const F: usize>
    Scenes<'a, H, G, N, EFS, F>
{
    /// A cluster over `table`, checking group membership against `groups`.
    ///
    /// §1.4.5: "Any endpoint that implements the Scenes Management server cluster SHALL also
    /// implement the Groups server cluster" — so the dependency is a constructor argument
    /// rather than an option, and an endpoint cannot be assembled without it.
    #[must_use]
    pub const fn new(
        table: &'a SceneTable<N, EFS, F>,
        groups: &'a G,
        hooks: &'a H,
        copy_scene: bool,
    ) -> Self {
        Self {
            table,
            groups,
            hooks,
            copy_scene,
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<2, 8, 7, 0>> {
        Conforming::new(&spec_scenes::CLUSTER, feature_map, optional)
    }

    /// Everything §1.4.9 leaves to the product: `CopyScene`.
    pub const WITH_COPY_SCENE: Optional<'static> = Optional {
        attributes: &[],
        commands: &[COPY_SCENE],
        events: &[],
    };

    /// The table this cluster serves, for a device persisting it or wiring it into Groups.
    #[must_use]
    pub const fn table(&self) -> &'a SceneTable<N, EFS, F> {
        self.table
    }

    /// §1.4.9's step 1, shared by every command: a non-zero group must be one this endpoint
    /// has actually joined, or the command names a group it cannot act for.
    fn group_known(&self, fabric: FabricIndex, group: GroupId) -> bool {
        group.0 == 0 || self.groups.is_group_member(fabric, group)
    }
}

/// Writes a `(Status, GroupID, SceneID)` response — the shape `AddSceneResponse`,
/// `RemoveSceneResponse` and `StoreSceneResponse` share.
fn status_response(
    w: &mut TlvWriter<'_>,
    tag: Tag,
    status: Status,
    group: GroupId,
    scene: u8,
) -> crate::error::Result<()> {
    spec_scenes::AddSceneResponseFields {
        status: status.value(),
        group_id: group,
        scene_id: scene,
    }
    .to_tlv(w, tag)
}

impl<H: SceneHooks, G: GroupMembership, const N: usize, const EFS: usize, const F: usize>
    ClusterHandler for Scenes<'_, H, G, N, EFS, F>
{
    /// §1.4.6: the Scene Table is fabric-scoped, so a removed fabric's scenes go with it —
    /// including the ones stored against its groups.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        if let crate::im::Lifecycle::FabricRemoved(fabric) = event {
            self.table.remove_fabric(fabric);
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
            SCENE_TABLE_SIZE => full(w.unsigned(tag, u64::from(self.table.size()))),
            FABRIC_SCENE_INFO => {
                // §1.4.6: "Any attribute read ... when no accessing fabric is available SHALL
                // fail with a status code of UNSUPPORTED_ACCESS."
                let fabric = ctx.fabric_index.ok_or(Status::UnsupportedAccess)?;
                full(w.start_array(tag))?;
                let info = self.table.info.borrow();
                for entry in info.iter() {
                    // §7.19.1.8.2: a filtered read reports only the accessing fabric's
                    // entries; an unfiltered one reports all, each carrying its FabricIndex.
                    if ctx.fabric_filtered && entry.fabric != fabric {
                        continue;
                    }
                    let count = u8::try_from(self.table.len_of_fabric(entry.fabric))
                        .unwrap_or(CAPACITY_MAX);
                    full(
                        spec_scenes::SceneInfoStruct {
                            scene_count: count,
                            current_scene: entry.current_scene,
                            current_group: entry.current_group,
                            scene_valid: entry.valid,
                            remaining_capacity: self.table.capacity(entry.fabric),
                            fabric_index: entry.fabric,
                        }
                        .to_tlv(w, Tag::Anonymous),
                    )?;
                }
                full(w.end_container())
            }
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        // §1.4.9: every command's last step is "If the ... command was received as a unicast,
        // the server SHALL then generate a ... Response". A groupcast gets none.
        let answer = ctx.group.is_none();
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        // §1.4.6: "Any attribute read, attribute write or command invoked on the server when
        // no accessing fabric is available SHALL fail with a status code of
        // UNSUPPORTED_ACCESS."
        let Some(fabric) = ctx.fabric_index else {
            return Err(Status::UnsupportedAccess.into());
        };
        let payload = || fields.ok_or(StatusIb::from(Status::InvalidCommand));

        match resolved.command.id {
            ADD_SCENE => {
                let decoded: spec_scenes::AddSceneFields<'_> = super::decode_fields(payload()?)?;
                let status = if !self.group_known(fabric, decoded.group_id) {
                    // Step 1.
                    Status::InvalidCommand
                } else if decoded.scene_id > SCENE_MAX || decoded.transition_time > TRANSITION_MAX {
                    Status::ConstraintError
                } else if decoded
                    .extension_field_set_structs
                    .iter()
                    .any(|set| set.is_err())
                {
                    // Step 2: "If the ExtensionFieldSetStructs list is formatted in a way
                    // deemed invalid ... the status SHALL be INVALID_COMMAND". Checked here
                    // rather than at recall, so a scene that cannot be applied is never
                    // stored — a device that discovered it at recall would fail silently, at
                    // the one moment the person is watching.
                    Status::InvalidCommand
                } else {
                    self.table.put(
                        fabric,
                        decoded.group_id,
                        decoded.scene_id,
                        decoded.scene_name,
                        decoded.transition_time,
                        decoded.extension_field_set_structs.members(),
                    )
                };
                if !answer {
                    return Ok(None);
                }
                full(status_response(
                    w,
                    tag,
                    status,
                    decoded.group_id,
                    decoded.scene_id,
                ))?;
                Ok(Some(ADD_SCENE_RESPONSE))
            }
            VIEW_SCENE => {
                let decoded: spec_scenes::ViewSceneFields = super::decode_fields(payload()?)?;
                let index = self.table.find(fabric, decoded.group_id, decoded.scene_id);
                let status = if !self.group_known(fabric, decoded.group_id) {
                    Status::InvalidCommand
                } else if index.is_none() {
                    Status::NotFound
                } else {
                    Status::Success
                };
                if !answer {
                    return Ok(None);
                }
                let entries = self.table.entries.borrow();
                let found = index
                    .filter(|_| status == Status::Success)
                    .and_then(|i| entries.get(i));
                full(
                    spec_scenes::ViewSceneResponseFields {
                        status: status.value(),
                        group_id: decoded.group_id,
                        scene_id: decoded.scene_id,
                        // §1.4.9.5's last three fields are conformant on "Status == SUCCESS",
                        // so a failure omits them rather than sending zeroes a client might
                        // mistake for a scene.
                        transition_time: found.map(|e| e.transition),
                        scene_name: found.map(Entry::name),
                        extension_field_set_structs: found
                            .map(|e| TlvList::from_members(&e.fields)),
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(VIEW_SCENE_RESPONSE))
            }
            REMOVE_SCENE => {
                let decoded: spec_scenes::RemoveSceneFields = super::decode_fields(payload()?)?;
                let status = if !self.group_known(fabric, decoded.group_id) {
                    Status::InvalidCommand
                } else {
                    match self.table.find(fabric, decoded.group_id, decoded.scene_id) {
                        None => Status::NotFound,
                        Some(index) => {
                            self.table.entries.borrow_mut().remove(index);
                            Status::Success
                        }
                    }
                };
                if !answer {
                    return Ok(None);
                }
                full(status_response(
                    w,
                    tag,
                    status,
                    decoded.group_id,
                    decoded.scene_id,
                ))?;
                Ok(Some(REMOVE_SCENE_RESPONSE))
            }
            REMOVE_ALL_SCENES => {
                let decoded: spec_scenes::RemoveAllScenesFields = super::decode_fields(payload()?)?;
                let status = if self.group_known(fabric, decoded.group_id) {
                    self.table
                        .entries
                        .borrow_mut()
                        .retain(|e| !(e.fabric == fabric && e.group == decoded.group_id));
                    Status::Success
                } else {
                    Status::InvalidCommand
                };
                if !answer {
                    return Ok(None);
                }
                full(
                    spec_scenes::RemoveAllScenesResponseFields {
                        status: status.value(),
                        group_id: decoded.group_id,
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(REMOVE_ALL_SCENES_RESPONSE))
            }
            STORE_SCENE => {
                let decoded: spec_scenes::StoreSceneFields = super::decode_fields(payload()?)?;
                let status = self.store(fabric, decoded.group_id, decoded.scene_id);
                if !answer {
                    return Ok(None);
                }
                full(status_response(
                    w,
                    tag,
                    status,
                    decoded.group_id,
                    decoded.scene_id,
                ))?;
                Ok(Some(STORE_SCENE_RESPONSE))
            }
            RECALL_SCENE => {
                let decoded: spec_scenes::RecallSceneFields = super::decode_fields(payload()?)?;
                if !self.group_known(fabric, decoded.group_id) {
                    return Err(Status::InvalidCommand.into());
                }
                let Some(index) = self.table.find(fabric, decoded.group_id, decoded.scene_id)
                else {
                    return Err(Status::NotFound.into());
                };
                // §1.4.9.12.4: "If the TransitionTime data field is present in the command and
                // its value is not equal to null, this field SHALL indicate the transition
                // time... In all other cases... the SceneTransitionTime field of the Scene
                // Table entry" — absent and explicitly null mean the same thing.
                let (sets, stored) = {
                    let entries = self.table.entries.borrow();
                    let Some(entry) = entries.get(index) else {
                        return Err(Status::NotFound.into());
                    };
                    (entry.fields.clone(), entry.transition)
                };
                let transition = decoded.transition_time.and_then(|t| t.0).unwrap_or(stored);
                self.hooks.apply(TlvList::from_members(&sets), transition);
                // §1.4.7.2.4: the endpoint now matches this fabric's scene, and no other's.
                self.table.note(fabric, decoded.group_id, decoded.scene_id);
                // §1.4.9's command table gives RecallScene response "Y" — a plain status, no
                // response command of its own.
                Ok(None)
            }
            GET_SCENE_MEMBERSHIP => {
                let decoded: spec_scenes::GetSceneMembershipFields =
                    super::decode_fields(payload()?)?;
                let known = self.group_known(fabric, decoded.group_id);
                if !answer {
                    return Ok(None);
                }
                let status = if known {
                    Status::Success
                } else {
                    Status::InvalidCommand
                };
                full(w.start_structure(tag))?;
                full(w.unsigned(Tag::Context(0), u64::from(status.value())))?;
                full(w.unsigned(Tag::Context(1), u64::from(self.table.capacity(fabric))))?;
                decoded
                    .group_id
                    .to_tlv(w, Tag::Context(2))
                    .map_err(|_| StatusIb::from(Status::Failure))?;
                // §1.4.9.14.4: "If the status is not SUCCESS then this field SHALL be
                // omitted".
                if known {
                    full(w.start_array(Tag::Context(3)))?;
                    for entry in self.table.entries.borrow().iter() {
                        if entry.fabric == fabric && entry.group == decoded.group_id {
                            full(w.unsigned(Tag::Anonymous, u64::from(entry.scene)))?;
                        }
                    }
                    full(w.end_container())?;
                }
                full(w.end_container())?;
                Ok(Some(GET_SCENE_MEMBERSHIP_RESPONSE))
            }
            COPY_SCENE if self.copy_scene => {
                let decoded: spec_scenes::CopySceneFields = super::decode_fields(payload()?)?;
                let status = self.copy(fabric, &decoded);
                if !answer {
                    return Ok(None);
                }
                full(
                    spec_scenes::CopySceneResponseFields {
                        status: status.value(),
                        group_identifier_from: decoded.group_identifier_from,
                        scene_identifier_from: decoded.scene_identifier_from,
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(COPY_SCENE_RESPONSE))
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<H: SceneHooks, G: GroupMembership, const N: usize, const EFS: usize, const F: usize>
    Scenes<'_, H, G, N, EFS, F>
{
    /// §1.4.9.10.3's steps 1–3.
    fn store(&self, fabric: FabricIndex, group: GroupId, scene: u8) -> Status {
        if !self.group_known(fabric, group) {
            return Status::InvalidCommand;
        }
        if scene > SCENE_MAX {
            return Status::ConstraintError;
        }
        // Step 3: the stored scene is "the current state of other clusters on the same
        // endpoint" — nothing the client sent.
        let mut scratch = [0u8; EFS];
        let mut w = TlvWriter::new_in(&mut scratch, crate::tlv::ContainerKind::Array);
        if self.hooks.capture(&mut w).is_err() {
            return Status::ResourceExhausted;
        }
        let Ok(captured) = w.finish() else {
            return Status::ResourceExhausted;
        };
        let existing = self.table.find(fabric, group, scene);
        let status = match existing {
            // "the ExtensionFieldSets of the stored scene SHALL be replaced ... and the other
            // fields of the scene table entry SHALL remain unchanged" — the name and
            // transition time a prior AddScene set are not the client's to lose here.
            Some(index) => {
                let mut entries = self.table.entries.borrow_mut();
                match entries.get_mut(index) {
                    Some(entry) => match heapless::Vec::from_slice(captured) {
                        Ok(fields) => {
                            entry.fields = fields;
                            Status::Success
                        }
                        Err(_) => Status::ResourceExhausted,
                    },
                    None => Status::NotFound,
                }
            }
            // "a new entry SHALL be added ... with SceneTransitionTime set to 0, with
            // SceneName set to the empty string".
            None => self.table.put(fabric, group, scene, "", 0, captured),
        };
        if status == Status::Success {
            self.table.note(fabric, group, scene);
        }
        status
    }

    /// §1.4.9.15.6's steps 1–4.
    fn copy(&self, fabric: FabricIndex, command: &spec_scenes::CopySceneFields) -> Status {
        if !self.group_known(fabric, command.group_identifier_from)
            || !self.group_known(fabric, command.group_identifier_to)
        {
            return Status::InvalidCommand;
        }
        let all = command.mode.contains(CopyModeBitmap::COPY_ALL_SCENES);
        if !all {
            // Step 2: one named scene must exist.
            if self
                .table
                .find(
                    fabric,
                    command.group_identifier_from,
                    command.scene_identifier_from,
                )
                .is_none()
            {
                return Status::NotFound;
            }
        }
        // Snapshotting first keeps the copy from reading entries it is in the middle of
        // writing — copying a group onto itself would otherwise grow without end.
        let source: heapless::Vec<Entry<EFS>, N> = self
            .table
            .entries
            .borrow()
            .iter()
            .filter(|e| {
                e.fabric == fabric
                    && e.group == command.group_identifier_from
                    && (all || e.scene == command.scene_identifier_from)
            })
            .cloned()
            .collect();
        for entry in &source {
            let scene = if all {
                entry.scene
            } else {
                command.scene_identifier_to
            };
            let status = self.table.put(
                fabric,
                command.group_identifier_to,
                scene,
                entry.name(),
                entry.transition,
                &entry.fields,
            );
            if status != Status::Success {
                return status;
            }
        }
        Status::Success
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: SceneHooks, G: GroupMembership, const N: usize, const EFS: usize, const F: usize> Cluster
    for Scenes<'_, H, G, N, EFS, F>
{
    const ID: ClusterId = ID;
}
