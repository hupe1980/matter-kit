//! Joint Fabric Datastore, cluster `0x0752` (Core §11.24).
//!
//! What every administrator of a Joint Fabric agrees is on it. Several ecosystems share one
//! fabric (ch. 12), so "which nodes exist, which groups they are in, what keys they hold and who
//! may reach them" cannot live in any one ecosystem's cloud — and §11.24 is the shared copy.
//!
//! # Two phases, and the second one is the point
//!
//! §11.24.4.1 is the rule the whole cluster is shaped around:
//!
//! > before completing the commissioning process, the Commissioner SHALL invoke the
//! > AddPendingNode command … After completion of commissioning and associated configuration,
//! > the Commissioner SHALL invoke the RefreshNode command … By performing this work in two
//! > steps (first pending status, then committed status), the design can prevent error scenarios
//! > where a node is brought onto a fabric without appearing in the Datastore.
//!
//! A node that commissioned successfully but never reached the datastore would be invisible to
//! every *other* ecosystem on the fabric — reachable, administrable, and unknown. Recording it
//! first and committing after means the failure mode is a `Pending` entry somebody can clean up,
//! rather than a device nobody can see.
//!
//! [`DatastoreStateEnum`] is that state, and §11.24.4.3 has the datastore "periodically review
//! its data in a Pending and PendingDeletion state and attempt to reach the corresponding Node".
//!
//! # Nothing is removed while something still refers to it
//!
//! §11.24.7.3 and §11.24.7.6 are the same rule twice: a key set a node still holds, or a group a
//! node is still in, cannot be removed — `CONSTRAINT_ERROR`. The exception is an entry already
//! marked `DeletePending`, which is a removal in progress rather than a live reference.
//!
//! Without it, removing a group would leave nodes holding a group key for a group that no longer
//! exists, and the datastore would no longer describe the fabric it is the description of.

use core::cell::RefCell;

use heapless::{String, Vec};

use crate::clusters::generated::joint_fabric_datastore as spec_ds;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    ClusterHandler, ClusterId, CommandId, EndpointId, InteractionContext, Status, StatusIb,
};
use crate::msg::{CaseAuthenticatedTag, GroupId, NodeId, VendorId};
use crate::tlv::{Tag, TlvWriter};

use super::Cluster;

pub use spec_ds::attribute::{
    ADMIN_LIST, ANCHOR_NODE_ID, ANCHOR_ROOT_CA, ANCHOR_VENDOR_ID, ENDPOINT_BINDING_LIST,
    ENDPOINT_GROUP_ID_LIST, FRIENDLY_NAME, GROUP_KEY_SET_LIST, GROUP_LIST, NODE_ACL_LIST,
    NODE_ENDPOINT_LIST, NODE_KEY_SET_LIST, NODE_LIST, STATUS,
};
pub use spec_ds::command::{
    ADD_ACL_TO_NODE, ADD_ADMIN, ADD_BINDING_TO_ENDPOINT_FOR_NODE, ADD_GROUP,
    ADD_GROUP_ID_TO_ENDPOINT_FOR_NODE, ADD_KEY_SET, ADD_PENDING_NODE, REFRESH_NODE,
    REMOVE_ACL_FROM_NODE, REMOVE_ADMIN, REMOVE_BINDING_FROM_ENDPOINT_FOR_NODE, REMOVE_GROUP,
    REMOVE_GROUP_ID_FROM_ENDPOINT_FOR_NODE, REMOVE_KEY_SET, REMOVE_NODE, UPDATE_ADMIN,
    UPDATE_ENDPOINT_FOR_NODE, UPDATE_GROUP, UPDATE_KEY_SET, UPDATE_NODE,
};
pub use spec_ds::{
    DatastoreAccessControlEntryPrivilegeEnum, DatastoreStateEnum, ID, PICS, REVISION,
};

/// §11.24.5's constraint on every `FriendlyName`: "max 32".
pub const FRIENDLY_NAME_MAX: usize = 32;

/// §11.24.7.3: "Attempt to remove the IPK, which has GroupKeySetID of 0, SHALL fail with
/// response CONSTRAINT_ERROR."
pub const IPK_KEY_SET: u16 = 0;

/// §11.24.7.4's constraint on `GroupCAT`: "GroupCAT values SHALL fall within the range 1 to
/// 65534", which excludes the Joint Fabric's own two reserved identifiers.
pub const GROUP_CAT_MIN: u16 = 1;
/// The other end of it.
pub const GROUP_CAT_MAX: u16 = 65534;

/// A name short enough for §11.24.5's "max 32".
pub type FriendlyName = String<FRIENDLY_NAME_MAX>;

/// §11.24.5.2's `DatastoreStatusEntryStruct`: where one managed thing has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusEntry {
    /// "the current state of the target device operation".
    pub state: DatastoreStateEnum,
    /// "the timestamp of the last update", in UTC seconds.
    pub updated_at: u32,
    /// "the Status Code of the last failed operation where the State field is set to
    /// CommitFailure".
    pub failure: Option<Status>,
}

impl StatusEntry {
    /// A freshly recorded, not-yet-applied change (§11.24.4.1).
    #[must_use]
    pub const fn pending(now: u32) -> Self {
        Self {
            state: DatastoreStateEnum::Pending,
            updated_at: now,
            failure: None,
        }
    }

    /// Whether this entry still refers to something.
    ///
    /// §11.24.7.3 and §11.24.7.6 both exempt `DeletePending`: a reference on its way out is not
    /// one that blocks a removal, or the two halves of a removal would deadlock each other.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        !matches!(self.state, DatastoreStateEnum::DeletePending)
    }
}

/// One node the datastore knows about (§11.24.5.14).
#[derive(Debug, Clone)]
pub struct NodeEntry {
    /// Its Node ID on the Joint Fabric.
    pub node: NodeId,
    /// "the friendly name for the node".
    pub friendly_name: FriendlyName,
    /// Where its commissioning has got to — §11.24.4.1's two phases.
    pub commissioning: StatusEntry,
}

/// One group (§11.24.5.5's `DatastoreGroupInformationEntryStruct`).
#[derive(Debug, Clone)]
pub struct GroupEntry {
    /// Its Group ID.
    pub group: GroupId,
    /// "the friendly name for the group".
    pub friendly_name: FriendlyName,
    /// Which key set secures it.
    pub key_set: Option<u16>,
    /// "the CAT value for this group", 1 to 65534.
    pub cat: Option<u16>,
    /// "the current version number for this CAT".
    pub cat_version: Option<u16>,
    /// "the permission level associated with ACL entries for this group".
    pub permission: DatastoreAccessControlEntryPrivilegeEnum,
}

/// One administrator node (§11.24.7.7).
#[derive(Debug, Clone)]
pub struct AdminEntry {
    /// Its Node ID.
    pub node: NodeId,
    /// Its friendly name.
    pub friendly_name: FriendlyName,
    /// "the Vendor ID for the admin node", which is what a user is shown when an ecosystem
    /// joins (§12.2.5 step 4d).
    pub vendor: VendorId,
    /// Its ICAC, cross-signed by the anchor. §11.24.7.7 caps it at 400 octets, which is the
    /// Matter certificate encoding's own limit.
    pub icac_len: usize,
}

/// One `(node, key set)` association (§11.24.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeKeySet {
    /// The node holding it.
    pub node: NodeId,
    /// The key set it holds.
    pub key_set: u16,
    /// Whether it is applied, pending, or on its way out.
    pub status: StatusEntry,
}

/// One `(node, endpoint, group)` membership (§11.24.5.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointGroup {
    /// The node.
    pub node: NodeId,
    /// The endpoint on it.
    pub endpoint: EndpointId,
    /// The group that endpoint is in.
    pub group: GroupId,
    /// Whether it is applied, pending, or on its way out.
    pub status: StatusEntry,
}

/// The Joint Fabric Datastore's tables (§11.24.6).
///
/// `N`, `G`, `K`, `A` and `M` size the node, group, key-set, administrator and membership lists.
/// §11.24.4 says what a full one does: "The RESOURCE_EXHAUSTED error MAY be used by the
/// Datastore to indicate that a storage capacity limit … has been reached and SHALL notify the
/// user of this condition using proprietary means outside of this specification."
#[derive(Debug)]
pub struct Datastore<const N: usize, const G: usize, const K: usize, const A: usize, const M: usize>
{
    nodes: Vec<NodeEntry, N>,
    groups: Vec<GroupEntry, G>,
    key_sets: Vec<u16, K>,
    admins: Vec<AdminEntry, A>,
    node_key_sets: Vec<NodeKeySet, M>,
    endpoint_groups: Vec<EndpointGroup, M>,
    anchor: Option<(NodeId, VendorId)>,
    friendly_name: FriendlyName,
}

impl<const N: usize, const G: usize, const K: usize, const A: usize, const M: usize> Default
    for Datastore<N, G, K, A, M>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const G: usize, const K: usize, const A: usize, const M: usize>
    Datastore<N, G, K, A, M>
{
    /// An empty datastore.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            groups: Vec::new(),
            key_sets: Vec::new(),
            admins: Vec::new(),
            node_key_sets: Vec::new(),
            endpoint_groups: Vec::new(),
            anchor: None,
            friendly_name: String::new(),
        }
    }

    /// `AnchorNodeID` and `AnchorVendorID` (§11.24.6), and the fabric's own name.
    pub fn set_anchor(&mut self, node: NodeId, vendor: VendorId, name: &str) -> Result<(), Status> {
        self.anchor = Some((node, vendor));
        self.friendly_name = FriendlyName::try_from(name).map_err(|_| Status::ConstraintError)?;
        Ok(())
    }

    /// The anchor, if one has been recorded.
    #[must_use]
    pub const fn anchor(&self) -> Option<(NodeId, VendorId)> {
        self.anchor
    }

    /// `NodeList` (§11.24.6).
    #[must_use]
    pub fn nodes(&self) -> &[NodeEntry] {
        &self.nodes
    }

    /// `GroupList` (§11.24.6).
    #[must_use]
    pub fn groups(&self) -> &[GroupEntry] {
        &self.groups
    }

    /// `AdminList` (§11.24.6).
    #[must_use]
    pub fn admins(&self) -> &[AdminEntry] {
        &self.admins
    }

    /// `GroupKeySetList` (§11.24.6) — the ids, since the keys themselves are §11.2's.
    #[must_use]
    pub fn key_sets(&self) -> &[u16] {
        &self.key_sets
    }

    /// `NodeKeySetList` (§11.24.6).
    #[must_use]
    pub fn node_key_sets(&self) -> &[NodeKeySet] {
        &self.node_key_sets
    }

    /// `EndpointGroupIDList` (§11.24.6).
    #[must_use]
    pub fn endpoint_groups(&self) -> &[EndpointGroup] {
        &self.endpoint_groups
    }

    /// §11.24.7.1's `AddKeySet`.
    pub fn add_key_set(&mut self, key_set: u16) -> Result<(), Status> {
        // "Ensure there are no KeySets in the KeySetList attribute with the given
        // GroupKeySetID. If a match is found, then this command SHALL fail with a
        // CONSTRAINT_ERROR status code."
        if self.key_sets.contains(&key_set) {
            return Err(Status::ConstraintError);
        }
        self.key_sets
            .push(key_set)
            .map_err(|_| Status::ResourceExhausted)
    }

    /// §11.24.7.3's `RemoveKeySet`.
    pub fn remove_key_set(&mut self, key_set: u16) -> Result<(), Status> {
        // "Attempt to remove the IPK, which has GroupKeySetID of 0, SHALL fail with response
        // CONSTRAINT_ERROR." The IPK is the fabric's own identity key; a datastore that let it
        // be removed would be describing a fabric nothing could CASE into.
        if key_set == IPK_KEY_SET {
            return Err(Status::ConstraintError);
        }
        if !self.key_sets.contains(&key_set) {
            return Err(Status::NotFound);
        }
        // Step 2: "If the NodeKeySetList list contains an entry with the given GroupKeySetID,
        // and the entry does NOT have Status DeletePending, then this command SHALL fail."
        if self
            .node_key_sets
            .iter()
            .any(|entry| entry.key_set == key_set && entry.status.is_live())
        {
            return Err(Status::ConstraintError);
        }
        self.key_sets.retain(|id| *id != key_set);
        Ok(())
    }

    /// §11.24.7.4's `AddGroup`.
    pub fn add_group(&mut self, entry: GroupEntry) -> Result<(), Status> {
        // "GroupCAT values SHALL fall within the range 1 to 65534" *and* "Attempts to add a
        // group with a GroupCAT value of Administrator CAT or Anchor CAT SHALL fail with
        // CONSTRAINT_ERROR."
        //
        // Two rules, and the second is not implied by the first: the Administrator CAT is
        // `0xFFFF`, which the range already excludes — but the Anchor CAT is `0xFFFE`, which is
        // the *top of the range*. A check that tested only the bounds would let a group claim
        // the identifier that grants Administer on every administrator of the Joint Fabric.
        if let Some(cat) = entry.cat
            && (!(GROUP_CAT_MIN..=GROUP_CAT_MAX).contains(&cat) || is_reserved_cat(cat))
        {
            return Err(Status::ConstraintError);
        }
        if self.groups.iter().any(|g| g.group == entry.group) {
            return Err(Status::ConstraintError);
        }
        // A group keyed to a key set the datastore does not have describes nothing.
        if let Some(key_set) = entry.key_set
            && !self.key_sets.contains(&key_set)
        {
            return Err(Status::NotFound);
        }
        self.groups
            .push(entry)
            .map_err(|_| Status::ResourceExhausted)
    }

    /// §11.24.7.6's `RemoveGroup`.
    pub fn remove_group(&mut self, group: GroupId) -> Result<(), Status> {
        let Some(entry) = self.groups.iter().find(|g| g.group == group) else {
            return Err(Status::NotFound);
        };
        // "Attempts to remove a group with GroupCAT value set to Administrator CAT or Anchor CAT
        // SHALL fail with CONSTRAINT_ERROR." A datastore that had one anyway — from an earlier
        // revision, or a peer that did not check — must not be the thing that removes it.
        if entry.cat.is_some_and(is_reserved_cat) {
            return Err(Status::ConstraintError);
        }
        // Step 2: a group with live members is not empty, and removing it would leave those
        // nodes holding a key for a group that no longer exists.
        if self
            .endpoint_groups
            .iter()
            .any(|m| m.group == group && m.status.is_live())
        {
            return Err(Status::ConstraintError);
        }
        self.groups.retain(|g| g.group != group);
        Ok(())
    }

    /// §11.24.7.10's `AddPendingNode` — the first half of §11.24.4.1's two-step.
    pub fn add_pending_node(
        &mut self,
        node: NodeId,
        friendly_name: &str,
        now: u32,
    ) -> Result<(), Status> {
        // "If a DatastoreNodeInformationEntryStruct exists for the given NodeID, then this
        // command SHALL fail with a INVALID_CONSTRAINT status code."
        if self.nodes.iter().any(|n| n.node == node) {
            return Err(Status::ConstraintError);
        }
        let friendly_name =
            FriendlyName::try_from(friendly_name).map_err(|_| Status::ConstraintError)?;
        self.nodes
            .push(NodeEntry {
                node,
                friendly_name,
                // "set the status … to Pending": the node is in the datastore before it is on
                // the fabric, which is the point of doing it in two steps.
                commissioning: StatusEntry::pending(now),
            })
            .map_err(|_| Status::ResourceExhausted)
    }

    /// §11.24.7.11's `RefreshNode` — the second half.
    ///
    /// The specification has the datastore *read* the node's endpoints here and reconcile them.
    /// That is an interaction with the node, which this table cannot make; what it does is what
    /// §11.24.7.11 steps 1 and 2 say, and the caller supplies the outcome.
    pub fn refresh_node(&mut self, node: NodeId, now: u32) -> Result<(), Status> {
        let Some(entry) = self.nodes.iter_mut().find(|n| n.node == node) else {
            // Step 1: "if not, then this command SHALL fail with a NOT_FOUND status code."
            return Err(Status::NotFound);
        };
        // Step 2: "Update the CommissioningStatusEntry … to Pending" — the refresh is itself an
        // operation that can fail, so it starts pending and the caller commits it.
        entry.commissioning = StatusEntry::pending(now);
        Ok(())
    }

    /// Records the outcome of a refresh (§11.24.7.11 steps 3 onwards).
    ///
    /// `Ok` commits the entry; an error records `CommitFailed` and the status, which
    /// §11.24.4.3's periodic review is what retries.
    pub fn node_refreshed(&mut self, node: NodeId, outcome: Result<(), Status>, now: u32) {
        if let Some(entry) = self.nodes.iter_mut().find(|n| n.node == node) {
            entry.commissioning = match outcome {
                Ok(()) => StatusEntry {
                    state: DatastoreStateEnum::Committed,
                    updated_at: now,
                    failure: None,
                },
                Err(status) => StatusEntry {
                    state: DatastoreStateEnum::CommitFailed,
                    updated_at: now,
                    failure: Some(status),
                },
            };
        }
    }

    /// §11.24.7.13's `RemoveNode`.
    pub fn remove_node(&mut self, node: NodeId) -> Result<(), Status> {
        if !self.nodes.iter().any(|n| n.node == node) {
            return Err(Status::NotFound);
        }
        self.nodes.retain(|n| n.node != node);
        // Everything hanging off the node goes with it: leaving a membership behind would make
        // §11.24.7.6's "ensure there are no Nodes in this group" true of a node that is gone,
        // and the group could never be removed.
        self.node_key_sets.retain(|e| e.node != node);
        self.endpoint_groups.retain(|e| e.node != node);
        Ok(())
    }

    /// §11.24.7.7's `AddAdmin`.
    pub fn add_admin(&mut self, entry: AdminEntry) -> Result<(), Status> {
        if self.admins.iter().any(|a| a.node == entry.node) {
            return Err(Status::ConstraintError);
        }
        self.admins
            .push(entry)
            .map_err(|_| Status::ResourceExhausted)
    }

    /// §11.24.7.9's `RemoveAdmin`.
    pub fn remove_admin(&mut self, node: NodeId) -> Result<(), Status> {
        if !self.admins.iter().any(|a| a.node == node) {
            return Err(Status::NotFound);
        }
        self.admins.retain(|a| a.node != node);
        Ok(())
    }

    /// Associates a key set with a node, pending application (§11.24.5.3).
    pub fn add_node_key_set(&mut self, node: NodeId, key_set: u16, now: u32) -> Result<(), Status> {
        if !self.nodes.iter().any(|n| n.node == node) {
            return Err(Status::NotFound);
        }
        if !self.key_sets.contains(&key_set) {
            return Err(Status::NotFound);
        }
        if self
            .node_key_sets
            .iter()
            .any(|e| e.node == node && e.key_set == key_set)
        {
            return Err(Status::ConstraintError);
        }
        self.node_key_sets
            .push(NodeKeySet {
                node,
                key_set,
                status: StatusEntry::pending(now),
            })
            .map_err(|_| Status::ResourceExhausted)
    }

    /// §11.24.7.15's `AddGroupIDToEndpointForNode`.
    pub fn add_group_to_endpoint(
        &mut self,
        node: NodeId,
        endpoint: EndpointId,
        group: GroupId,
        now: u32,
    ) -> Result<(), Status> {
        if !self.nodes.iter().any(|n| n.node == node) {
            return Err(Status::NotFound);
        }
        // A membership in a group the datastore does not have would be invisible to the removal
        // check that is supposed to protect it.
        if !self.groups.iter().any(|g| g.group == group) {
            return Err(Status::NotFound);
        }
        if self
            .endpoint_groups
            .iter()
            .any(|m| m.node == node && m.endpoint == endpoint && m.group == group)
        {
            return Err(Status::ConstraintError);
        }
        self.endpoint_groups
            .push(EndpointGroup {
                node,
                endpoint,
                group,
                status: StatusEntry::pending(now),
            })
            .map_err(|_| Status::ResourceExhausted)
    }

    /// §11.24.7.16's `RemoveGroupIDFromEndpointForNode`.
    ///
    /// The removal is *marked*, not done: §11.24.4.3 has the datastore reach the node to apply
    /// it, and until it has, the membership is `DeletePending` — which §11.24.7.6 then stops
    /// treating as a live reference.
    pub fn remove_group_from_endpoint(
        &mut self,
        node: NodeId,
        endpoint: EndpointId,
        group: GroupId,
        now: u32,
    ) -> Result<(), Status> {
        let Some(entry) = self
            .endpoint_groups
            .iter_mut()
            .find(|m| m.node == node && m.endpoint == endpoint && m.group == group)
        else {
            return Err(Status::NotFound);
        };
        entry.status = StatusEntry {
            state: DatastoreStateEnum::DeletePending,
            updated_at: now,
            failure: None,
        };
        Ok(())
    }

    /// Applies a pending deletion, once the node has acknowledged it.
    pub fn deletion_applied(&mut self, node: NodeId, endpoint: EndpointId, group: GroupId) {
        self.endpoint_groups.retain(|m| {
            !(m.node == node && m.endpoint == endpoint && m.group == group && !m.status.is_live())
        });
    }

    /// §11.24.4.3's periodic review: everything still waiting to reach its node.
    ///
    /// > The Datastore SHALL periodically review its data in a Pending and PendingDeletion state
    /// > and attempt to reach the corresponding Node in order to apply these updates.
    ///
    /// Returns the nodes with outstanding work, each once.
    pub fn nodes_needing_review<const R: usize>(&self) -> Vec<NodeId, R> {
        let mut out: Vec<NodeId, R> = Vec::new();
        let note = |node: NodeId, out: &mut Vec<NodeId, R>| {
            if !out.contains(&node) {
                let _ = out.push(node);
            }
        };
        for entry in &self.nodes {
            if matches!(
                entry.commissioning.state,
                DatastoreStateEnum::Pending
                    | DatastoreStateEnum::DeletePending
                    | DatastoreStateEnum::CommitFailed
            ) {
                note(entry.node, &mut out);
            }
        }
        for entry in &self.node_key_sets {
            if entry.status.state != DatastoreStateEnum::Committed {
                note(entry.node, &mut out);
            }
        }
        for entry in &self.endpoint_groups {
            if entry.status.state != DatastoreStateEnum::Committed {
                note(entry.node, &mut out);
            }
        }
        out
    }
}

/// The Joint Fabric Datastore cluster (§11.24).
#[derive(Debug)]
pub struct JointFabricDatastore<
    'a,
    const N: usize,
    const G: usize,
    const K: usize,
    const A: usize,
    const M: usize,
> {
    store: &'a RefCell<Datastore<N, G, K, A, M>>,
}

impl<'a, const N: usize, const G: usize, const K: usize, const A: usize, const M: usize>
    JointFabricDatastore<'a, N, G, K, A, M>
{
    /// A cluster over a datastore.
    #[must_use]
    pub const fn new(store: &'a RefCell<Datastore<N, G, K, A, M>>) -> Self {
        Self { store }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<14, 20, 0, 0>> {
        Conforming::new(&spec_ds::CLUSTER, feature_map, optional)
    }

    /// The tables this cluster serves.
    #[must_use]
    pub const fn store(&self) -> &'a RefCell<Datastore<N, G, K, A, M>> {
        self.store
    }
}

impl<const N: usize, const G: usize, const K: usize, const A: usize, const M: usize> ClusterHandler
    for JointFabricDatastore<'_, N, G, K, A, M>
{
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let store = self.store.borrow();
        match resolved.attribute {
            ANCHOR_NODE_ID => match store.anchor() {
                Some((node, _)) => full(w.unsigned(tag, node.0)),
                None => full(w.null(tag)),
            },
            ANCHOR_VENDOR_ID => match store.anchor() {
                Some((_, vendor)) => full(w.unsigned(tag, u64::from(vendor.0))),
                None => full(w.null(tag)),
            },
            FRIENDLY_NAME => full(w.utf8(tag, &store.friendly_name)),
            GROUP_KEY_SET_LIST => {
                full(w.start_array(tag))?;
                for key_set in store.key_sets() {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), u64::from(*key_set)))?;
                    full(w.end_container())?;
                }
                full(w.end_container())
            }
            NODE_LIST => {
                full(w.start_array(tag))?;
                for entry in store.nodes() {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), entry.node.0))?;
                    full(w.utf8(Tag::Context(1), &entry.friendly_name))?;
                    full(encode_status(&entry.commissioning, w, Tag::Context(2)))?;
                    full(w.end_container())?;
                }
                full(w.end_container())
            }
            GROUP_LIST => {
                full(w.start_array(tag))?;
                for entry in store.groups() {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), u64::from(entry.group.0)))?;
                    full(w.utf8(Tag::Context(1), &entry.friendly_name))?;
                    match entry.key_set {
                        Some(key_set) => full(w.unsigned(Tag::Context(2), u64::from(key_set)))?,
                        None => full(w.null(Tag::Context(2)))?,
                    }
                    match entry.cat {
                        Some(cat) => full(w.unsigned(Tag::Context(3), u64::from(cat)))?,
                        None => full(w.null(Tag::Context(3)))?,
                    }
                    match entry.cat_version {
                        Some(v) => full(w.unsigned(Tag::Context(4), u64::from(v)))?,
                        None => full(w.null(Tag::Context(4)))?,
                    }
                    full(w.unsigned(Tag::Context(5), u64::from(entry.permission.value())))?;
                    full(w.end_container())?;
                }
                full(w.end_container())
            }
            ADMIN_LIST => {
                full(w.start_array(tag))?;
                for entry in store.admins() {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), entry.node.0))?;
                    full(w.utf8(Tag::Context(1), &entry.friendly_name))?;
                    full(w.unsigned(Tag::Context(2), u64::from(entry.vendor.0)))?;
                    full(w.end_container())?;
                }
                full(w.end_container())
            }
            NODE_KEY_SET_LIST => {
                full(w.start_array(tag))?;
                for entry in store.node_key_sets() {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), entry.node.0))?;
                    full(w.unsigned(Tag::Context(1), u64::from(entry.key_set)))?;
                    full(encode_status(&entry.status, w, Tag::Context(2)))?;
                    full(w.end_container())?;
                }
                full(w.end_container())
            }
            ENDPOINT_GROUP_ID_LIST => {
                full(w.start_array(tag))?;
                for entry in store.endpoint_groups() {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), entry.node.0))?;
                    full(w.unsigned(Tag::Context(1), u64::from(entry.endpoint)))?;
                    full(w.unsigned(Tag::Context(2), u64::from(entry.group.0)))?;
                    full(encode_status(&entry.status, w, Tag::Context(3)))?;
                    full(w.end_container())?;
                }
                full(w.end_container())
            }
            _ => Err(Status::UnsupportedAttribute),
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
        // §11.24.7's commands all act "of the accessing fabric": on a Joint Fabric there is one,
        // and a command with none has no datastore to address.
        if ctx.fabric_index.filter(|f| f.0 != 0).is_none() {
            return Err(Status::UnsupportedAccess.into());
        }
        let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
        // The datastore's clock is the fabric's: every `StatusEntry` carries an epoch-second
        // `UpdateTimestamp`, and §11.24.4.3's review compares against it.
        let now = u32::try_from(ctx.now.as_micros() / 1_000_000).unwrap_or(u32::MAX);
        let mut store = self.store.borrow_mut();
        match resolved.command.id {
            ADD_KEY_SET => {
                let decoded: spec_ds::AddKeySetFields<'_> = super::decode_fields(payload)?;
                store.add_key_set(decoded.group_key_set.group_key_set_id)?;
            }
            REMOVE_KEY_SET => {
                let decoded: spec_ds::RemoveKeySetFields = super::decode_fields(payload)?;
                store.remove_key_set(decoded.group_key_set_id)?;
            }
            ADD_GROUP => {
                let decoded: spec_ds::AddGroupFields<'_> = super::decode_fields(payload)?;
                store.add_group(GroupEntry {
                    group: decoded.group_id,
                    friendly_name: FriendlyName::try_from(decoded.friendly_name)
                        .map_err(|_| StatusIb::from(Status::ConstraintError))?,
                    key_set: decoded.group_key_set_id.0,
                    cat: decoded.group_cat.0,
                    cat_version: decoded.group_cat_version.0,
                    permission: decoded.group_permission,
                })?;
            }
            REMOVE_GROUP => {
                let decoded: spec_ds::RemoveGroupFields = super::decode_fields(payload)?;
                store.remove_group(decoded.group_id)?;
            }
            ADD_ADMIN => {
                let decoded: spec_ds::AddAdminFields<'_> = super::decode_fields(payload)?;
                store.add_admin(AdminEntry {
                    node: decoded.node_id,
                    friendly_name: FriendlyName::try_from(decoded.friendly_name)
                        .map_err(|_| StatusIb::from(Status::ConstraintError))?,
                    vendor: decoded.vendor_id,
                    icac_len: decoded.icac.len(),
                })?;
            }
            REMOVE_ADMIN => {
                let decoded: spec_ds::RemoveAdminFields = super::decode_fields(payload)?;
                store.remove_admin(decoded.node_id)?;
            }
            ADD_PENDING_NODE => {
                let decoded: spec_ds::AddPendingNodeFields<'_> = super::decode_fields(payload)?;
                store.add_pending_node(decoded.node_id, decoded.friendly_name, now)?;
            }
            REFRESH_NODE => {
                let decoded: spec_ds::RefreshNodeFields = super::decode_fields(payload)?;
                store.refresh_node(decoded.node_id, now)?;
            }
            REMOVE_NODE => {
                let decoded: spec_ds::RemoveNodeFields = super::decode_fields(payload)?;
                store.remove_node(decoded.node_id)?;
            }
            ADD_GROUP_ID_TO_ENDPOINT_FOR_NODE => {
                let decoded: spec_ds::AddGroupIDToEndpointForNodeFields =
                    super::decode_fields(payload)?;
                store.add_group_to_endpoint(
                    decoded.node_id,
                    decoded.endpoint_id,
                    decoded.group_id,
                    now,
                )?;
            }
            REMOVE_GROUP_ID_FROM_ENDPOINT_FOR_NODE => {
                let decoded: spec_ds::RemoveGroupIDFromEndpointForNodeFields =
                    super::decode_fields(payload)?;
                store.remove_group_from_endpoint(
                    decoded.node_id,
                    decoded.endpoint_id,
                    decoded.group_id,
                    now,
                )?;
            }
            _ => return Err(Status::UnsupportedCommand.into()),
        }
        Ok(None)
    }
}

/// Whether a `GroupCAT` names one of ch. 12's two reserved identifiers (§12.2.4).
///
/// Separate from the range check because only one of them is outside the range: `0xFFFF` is, and
/// `0xFFFE` — the Anchor CAT — is the largest value the range allows.
const fn is_reserved_cat(cat: u16) -> bool {
    cat == CaseAuthenticatedTag::ADMINISTRATOR_IDENTIFIER
        || cat == CaseAuthenticatedTag::ANCHOR_IDENTIFIER
}

/// §11.24.5.2's `DatastoreStatusEntryStruct`.
fn encode_status(
    status: &StatusEntry,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> crate::error::Result<()> {
    w.start_structure(tag)?;
    w.unsigned(Tag::Context(0), u64::from(status.state.value()))?;
    w.unsigned(Tag::Context(1), u64::from(status.updated_at))?;
    // "the Status Code of the last failed operation where the State field is set to
    // CommitFailure" — and nothing, legibly, when there has been no failure.
    match status.failure {
        Some(failure) => w.unsigned(Tag::Context(2), u64::from(failure.value()))?,
        None => w.unsigned(Tag::Context(2), 0)?,
    }
    w.end_container()
}

/// So a tuple of clusters can dispatch to it by id.
impl<const N: usize, const G: usize, const K: usize, const A: usize, const M: usize> Cluster
    for JointFabricDatastore<'_, N, G, K, A, M>
{
    const ID: ClusterId = ID;
}
