//! Groupcast, cluster `0x0065` (Core §11.27). **Provisional.**
//!
//! > The Groupcast Cluster defines a unified, simpler, and more scalable mechanism for
//! > configuring, managing, and using groups in Matter. It is designed to replace the legacy
//! > Groups cluster.
//!
//! One cluster where there used to be three. §1.3's Groups held the membership, §11.2's Group
//! Key Management held the keys and the map between them, and an administrator had to drive
//! both in the right order on every endpoint. `JoinGroup` does all of it in one command: the
//! group, the endpoints, the key set and — optionally — the key itself.
//!
//! # One multicast address instead of one per group
//!
//! §11.27.5.1's `IanaAddr` is the change that makes this scale. Every group uses `FF05::FA`, and
//! a node "will then filter this traffic at the message layer by attempting decryption with its
//! available group keys" — which is [`group`](crate::group)'s job anyway, because §4.17.3.6's
//! Group Session ID never decided the key on its own.
//!
//! The alternative is there for the nodes that need it: `PerGroup` gives a group its own
//! §2.5.6.2 address so a sleepy listener's radio filters the traffic instead of its CPU. §11.27.5.1
//! says when: "groups with listener members that require extra filtering at the network layer,
//! such as low power devices", and groups with pre-Groupcast members.
//!
//! # Sender and listener are different devices
//!
//! §11.27.4: `LN` and `SD` are separate features, and "being a sender does not imply the ability
//! to listen to messages sent to those multicast addresses". A wall switch joins groups with an
//! *empty* endpoint list — it has nothing to receive on — and a bulb joins with the endpoint the
//! light is on. Getting that backwards is `CONSTRAINT_ERROR` on the command rather than a group
//! that silently never works.
//!
//! # What is not here
//!
//! `GroupcastTesting` (§11.27.7.6) and its event, which exist so the Test Harness can make a
//! node emit a groupcast on demand. It is a certification instrument rather than a product
//! feature, and a device that shipped it would give any administrator a way to make it transmit.

use core::cell::RefCell;

use crate::clusters::generated::groupcast as spec_gc;
use crate::crypto::{SYMMETRIC_KEY_LENGTH_BYTES, SymmetricKey};
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::group::keys::{EpochKey, GroupKeySecurityPolicy, GroupKeySet, GroupKeys, KeySetId};
use crate::im::{
    ClusterHandler, ClusterId, CommandId, EndpointId, InteractionContext, Status, StatusIb,
};
use crate::msg::{FabricIndex, GroupId};
use crate::tlv::{Tag, TlvWriter};

use super::Cluster;

pub use spec_gc::attribute::{
    FABRIC_UNDER_TEST, MAX_MCAST_ADDR_COUNT, MAX_MEMBERSHIP_COUNT, MEMBERSHIP,
    USED_MCAST_ADDR_COUNT,
};
pub use spec_gc::command::{
    CONFIGURE_AUXILIARY_ACL, JOIN_GROUP, LEAVE_GROUP, LEAVE_GROUP_RESPONSE, UPDATE_GROUP_KEY,
};
pub use spec_gc::{ID, MulticastAddrPolicyEnum, PICS, REVISION};

/// `LN` (§11.27.4.1) — the node can join groups and receive what is sent to them.
pub const FEATURE_LISTENER: u32 = 1 << 0;

/// `SD` (§11.27.4.2) — the node can send to groups it belongs to.
pub const FEATURE_SENDER: u32 = 1 << 1;

/// `PGA` (§11.27.4.3) — the node can use §2.5.6.2's per-group multicast addresses.
pub const FEATURE_PER_GROUP_ADDRESS: u32 = 1 << 2;

/// §11.27.7.1: "For Listeners, this field SHALL list at least 1 endpoint and up to 20
/// endpoints."
pub const MAX_JOIN_ENDPOINTS: usize = 20;

/// §11.27.6.2: `MaxMembershipCount` has a constraint of "min 10".
pub const MIN_MEMBERSHIP_COUNT: u16 = 10;

/// Every element of §11.27 this crate serves, for the [`Optional`] a device declares.
///
/// The whole cluster is provisional (§2.13), so §7.3 marks *every* element `P` — which
/// [`dm::spec`](crate::dm::spec) treats as optional, "a decision the product makes rather than
/// one the conformance makes for it". A node that implements the cluster implements all of it,
/// so this is that decision written once.
///
/// `ConfigureAuxiliaryACL` is in the list unconditionally: its conformance is `P, LN`, so on a
/// sender-only node it is disallowed and naming it changes nothing. `GroupcastTesting` is not
/// in it, for the reason the module documentation gives.
pub const OPTIONAL: Optional<'static> = Optional {
    attributes: &[
        MEMBERSHIP,
        MAX_MEMBERSHIP_COUNT,
        MAX_MCAST_ADDR_COUNT,
        USED_MCAST_ADDR_COUNT,
        FABRIC_UNDER_TEST,
    ],
    commands: &[
        JOIN_GROUP,
        LEAVE_GROUP,
        LEAVE_GROUP_RESPONSE,
        UPDATE_GROUP_KEY,
        CONFIGURE_AUXILIARY_ACL,
    ],
    events: &[],
};

/// One group this node belongs to (§11.27.5.4's `MembershipStruct`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership<const E: usize> {
    /// The fabric it is scoped to.
    pub fabric_index: FabricIndex,
    /// "an identifier for the multicast group within the fabric", never zero.
    pub group: GroupId,
    /// The endpoints that receive the group's messages. Empty means sender-only.
    pub endpoints: heapless::Vec<EndpointId, E>,
    /// Which key set secures it — "maps directly to the GroupKeySetID as defined in the Group
    /// Key Management cluster".
    pub key_set: KeySetId,
    /// Whether §11.27.10's auxiliary ACL entries were generated for it.
    pub has_auxiliary_acl: bool,
    /// How §2.5.6.2's address is built for it.
    pub policy: MulticastAddrPolicyEnum,
}

/// The Groupcast cluster (§11.27).
///
/// `M` bounds the memberships and `E` the endpoints in one of them. The key material itself is
/// [`GroupKeys`]'s, shared with
/// [`group_key_management`](super::group_key_management) — §11.27.7.1's `Key` field creates a
/// key set there, and §11.27.6.1 has the two attributes mirror each other.
#[derive(Debug)]
pub struct Groupcast<'a, const M: usize, const E: usize, const K: usize, const G: usize> {
    keys: &'a RefCell<GroupKeys<K, G>>,
    memberships: RefCell<heapless::Vec<Membership<E>, M>>,
    feature_map: u32,
    max_membership: u16,
    max_addresses: u16,
    fabric_under_test: core::cell::Cell<FabricIndex>,
}

impl<'a, const M: usize, const E: usize, const K: usize, const G: usize> Groupcast<'a, M, E, K, G> {
    /// A cluster with no memberships, over the node's group keys.
    ///
    /// `feature_map` says which of `LN`, `SD` and `PGA` this node implements, and §11.27.4's
    /// `O.a+` requires at least one of the first two — a node that is neither a listener nor a
    /// sender has no business having the cluster.
    #[must_use]
    pub const fn new(keys: &'a RefCell<GroupKeys<K, G>>, feature_map: u32) -> Self {
        Self {
            keys,
            memberships: RefCell::new(heapless::Vec::new()),
            feature_map,
            max_membership: if M > u16::MAX as usize {
                u16::MAX
            } else {
                M as u16
            },
            max_addresses: 1,
            fabric_under_test: core::cell::Cell::new(FabricIndex(0)),
        }
    }

    /// How many §2.5.6.2 per-group addresses the node's radio can subscribe to
    /// (§11.27.6.3's `MaxMcastAddrCount`, "min 1").
    ///
    /// One is the floor because `FF05::FA` alone is enough for every `IanaAddr` group; more is
    /// what `PGA` needs.
    #[must_use]
    pub const fn with_max_addresses(mut self, max: u16) -> Self {
        self.max_addresses = max;
        self
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<5, 6, 1, 1>> {
        Conforming::new(&spec_gc::CLUSTER, feature_map, optional)
    }

    /// Every membership, for a device about to persist them or to subscribe to their addresses.
    #[must_use]
    pub fn memberships(&self) -> core::cell::Ref<'_, heapless::Vec<Membership<E>, M>> {
        self.memberships.borrow()
    }

    /// Whether this node listens for group messages (§11.27.4.1).
    #[must_use]
    pub const fn is_listener(&self) -> bool {
        self.feature_map & FEATURE_LISTENER != 0
    }

    /// Whether this node sends them (§11.27.4.2).
    #[must_use]
    pub const fn is_sender(&self) -> bool {
        self.feature_map & FEATURE_SENDER != 0
    }

    /// §11.27.6.1's per-fabric ceiling: "the server SHALL limit the total number of GroupIDs
    /// used across all entries in the Membership attribute to no more than half (rounded down)
    /// of the MaxMembershipCount value."
    ///
    /// Half, so that one fabric cannot fill the table and leave a second ecosystem unable to
    /// form a single group.
    #[must_use]
    pub const fn per_fabric_limit(&self) -> usize {
        (self.max_membership / 2) as usize
    }

    /// Forgets every group one fabric joined — what `RemoveFabric` must do.
    pub fn remove_fabric(&self, fabric: FabricIndex) {
        self.memberships
            .borrow_mut()
            .retain(|m| m.fabric_index != fabric);
    }

    fn count_groups(&self, fabric: FabricIndex) -> usize {
        self.memberships
            .borrow()
            .iter()
            .filter(|m| m.fabric_index == fabric)
            .count()
    }
}

impl<const M: usize, const E: usize, const K: usize, const G: usize> ClusterHandler
    for Groupcast<'_, M, E, K, G>
{
    /// §11.27.6.1: memberships are fabric-scoped, and a stale one keeps this node listening
    /// on a multicast address for a fabric it has left.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        if let crate::im::Lifecycle::FabricRemoved(fabric) = event {
            self.remove_fabric(fabric);
        }
    }
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            MAX_MEMBERSHIP_COUNT => full(w.unsigned(tag, u64::from(self.max_membership))),
            MAX_MCAST_ADDR_COUNT => full(w.unsigned(tag, u64::from(self.max_addresses))),
            USED_MCAST_ADDR_COUNT => {
                // §11.27.6.4: how many addresses are actually subscribed. Every `IanaAddr` group
                // shares `FF05::FA`, so the count is one for all of them together plus one per
                // `PerGroup` group — which is the whole argument for `IanaAddr`.
                let memberships = self.memberships.borrow();
                let per_group = memberships
                    .iter()
                    .filter(|m| m.policy == MulticastAddrPolicyEnum::PerGroup)
                    .count();
                let iana = usize::from(
                    memberships
                        .iter()
                        .any(|m| m.policy == MulticastAddrPolicyEnum::IanaAddr),
                );
                full(w.unsigned(tag, (per_group.saturating_add(iana)) as u64))
            }
            FABRIC_UNDER_TEST => full(w.unsigned(tag, u64::from(self.fabric_under_test.get().0))),
            MEMBERSHIP => {
                let memberships = self.memberships.borrow();
                full(w.start_array(tag))?;
                for entry in memberships
                    .iter()
                    .filter(|m| !ctx.fabric_filtered || ctx.fabric_index == Some(m.fabric_index))
                {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), u64::from(entry.group.0)))?;
                    if self.is_listener() {
                        full(w.start_array(Tag::Context(1)))?;
                        for endpoint in &entry.endpoints {
                            full(w.unsigned(Tag::Anonymous, u64::from(*endpoint)))?;
                        }
                        full(w.end_container())?;
                    }
                    full(w.unsigned(Tag::Context(2), u64::from(entry.key_set)))?;
                    if self.is_listener() {
                        full(w.bool(Tag::Context(3), entry.has_auxiliary_acl))?;
                    }
                    full(w.unsigned(Tag::Context(4), u64::from(entry.policy.value())))?;
                    full(w.unsigned(Tag::Context(254), u64::from(entry.fabric_index.0)))?;
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
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<Option<CommandId>, StatusIb> {
        // §11.27.7: every command is `F`.
        let fabric = ctx
            .fabric_index
            .filter(|f| f.0 != 0)
            .ok_or(StatusIb::from(Status::UnsupportedAccess))?;
        let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
        match resolved.command.id {
            JOIN_GROUP => self.join(fabric, payload, ctx),
            LEAVE_GROUP => self.leave(fabric, payload, w, tag),
            UPDATE_GROUP_KEY => self.update_key(fabric, payload),
            CONFIGURE_AUXILIARY_ACL => self.configure_auxiliary_acl(fabric, payload),
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<const M: usize, const E: usize, const K: usize, const G: usize> Groupcast<'_, M, E, K, G> {
    /// §11.27.7.1, in the order the specification lists the steps.
    fn join(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        ctx: &InteractionContext<'_>,
    ) -> core::result::Result<Option<CommandId>, StatusIb> {
        let decoded: spec_gc::JoinGroupFields<'_> = super::decode_fields(payload)?;
        // §11.27.5.4: `GroupID` has a constraint of "min 1", and §11.27.7.2 gives 0 a different
        // meaning entirely — "all groups on the node for this fabric".
        if decoded.group_id.0 == 0 || decoded.key_set_id == 0 {
            return Err(Status::ConstraintError.into());
        }

        let mut endpoints: heapless::Vec<EndpointId, E> = heapless::Vec::new();
        for endpoint in decoded.endpoints.iter() {
            let endpoint = endpoint.map_err(|_| StatusIb::from(Status::InvalidCommand))?;
            // Step 3c: "If any endpoint is invalid or is the RootEndpoint (Endpoint 0), the
            // server SHALL stop command processing and SHALL return with status
            // UNSUPPORTED_ENDPOINT" — groupcast never reaches the root endpoint's clusters.
            if endpoint == 0 {
                return Err(Status::UnsupportedEndpoint.into());
            }
            if endpoints.contains(&endpoint) {
                // Step 6a/6b: "omitting duplicates".
                continue;
            }
            if endpoints.len() >= MAX_JOIN_ENDPOINTS {
                return Err(Status::ConstraintError.into());
            }
            endpoints
                .push(endpoint)
                .map_err(|_| StatusIb::from(Status::ResourceExhausted))?;
        }

        // Steps 2a and 3a: the feature map decides which shape of join is legal.
        if endpoints.is_empty() && !self.is_sender() {
            return Err(Status::ConstraintError.into());
        }
        if !endpoints.is_empty() && !self.is_listener() {
            return Err(Status::ConstraintError.into());
        }
        // Step 3d: "If the UseAuxiliaryACL field is provided and the command was invoked by a
        // client that does not have at least Administer privilege granted" — the command itself
        // is `M`, so this field is the one part of it an administrator alone may use.
        // `None` means the caller did not compute a privilege, and this is the cautious branch:
        // the field generates ACL entries, so "not known to be Administer" is refused.
        if decoded.use_auxiliary_acl.is_some()
            && !ctx
                .privilege
                .is_some_and(|granted| granted.grants(crate::dm::access::Privilege::Administer))
        {
            return Err(Status::UnsupportedAccess.into());
        }
        let policy = decoded
            .mcast_addr_policy
            .unwrap_or(MulticastAddrPolicyEnum::IanaAddr);
        if policy == MulticastAddrPolicyEnum::PerGroup
            && self.feature_map & FEATURE_PER_GROUP_ADDRESS == 0
        {
            return Err(Status::ConstraintError.into());
        }

        self.install_key(fabric, decoded.key_set_id, decoded.key)?;

        let existing = self.find(fabric, decoded.group_id);
        if existing.is_none() {
            // Step 1, and §11.27.6.1's per-fabric half.
            if self.count_groups(fabric) >= self.per_fabric_limit() {
                return Err(Status::ResourceExhausted.into());
            }
        }

        let mut memberships = self.memberships.borrow_mut();
        match memberships
            .iter_mut()
            .find(|m| m.fabric_index == fabric && m.group == decoded.group_id)
        {
            Some(entry) => {
                // Step 6a: `ReplaceEndpoints` true overwrites; otherwise the list is appended to,
                // "omitting duplicates".
                if decoded.replace_endpoints == Some(true) {
                    entry.endpoints.clear();
                }
                for endpoint in &endpoints {
                    if !entry.endpoints.contains(endpoint)
                        && entry.endpoints.push(*endpoint).is_err()
                    {
                        return Err(Status::ResourceExhausted.into());
                    }
                }
                entry.key_set = decoded.key_set_id;
                entry.policy = policy;
                if let Some(use_acl) = decoded.use_auxiliary_acl {
                    entry.has_auxiliary_acl = use_acl;
                }
            }
            None => {
                memberships
                    .push(Membership {
                        fabric_index: fabric,
                        group: decoded.group_id,
                        endpoints,
                        key_set: decoded.key_set_id,
                        has_auxiliary_acl: decoded.use_auxiliary_acl.unwrap_or(false),
                        policy,
                    })
                    .map_err(|_| StatusIb::from(Status::ResourceExhausted))?;
            }
        }
        drop(memberships);

        // §11.27.9: the group's key set and the §11.2 map move together, so a group joined here
        // is one [`group::wire`](crate::group::wire) can already send to and receive on.
        self.keys
            .borrow_mut()
            .map_group(fabric, decoded.group_id, decoded.key_set_id)?;
        Ok(None)
    }

    /// §11.27.7.2, whose response says which endpoints actually left.
    fn leave(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<Option<CommandId>, StatusIb> {
        let decoded: spec_gc::LeaveGroupFields<'_> = super::decode_fields(payload)?;
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));

        // Step 1: "If the GroupID is 0x00 … all groups on the node for this fabric are affected."
        if decoded.group_id.0 == 0 {
            if self.count_groups(fabric) == 0 {
                return Err(Status::NotFound.into());
            }
            let groups: heapless::Vec<GroupId, M> = self
                .memberships
                .borrow()
                .iter()
                .filter(|m| m.fabric_index == fabric)
                .map(|m| m.group)
                .collect();
            for group in groups {
                self.forget(fabric, group);
            }
            // §11.27.7.3: the response's Endpoints "SHALL be an empty list if … The GroupID
            // field is 0, indicating multiple groups were affected, resulting in ambiguous
            // Endpoints list content."
            full(w.start_structure(tag))?;
            full(w.unsigned(Tag::Context(0), 0))?;
            full(w.start_array(Tag::Context(1)))?;
            full(w.end_container())?;
            full(w.end_container())?;
            return Ok(Some(LEAVE_GROUP_RESPONSE));
        }

        // Steps 2 and 3.
        if self.find(fabric, decoded.group_id).is_none() {
            return Err(Status::NotFound.into());
        }

        let mut removed: heapless::Vec<EndpointId, E> = heapless::Vec::new();
        match decoded.endpoints {
            // Step 4: a partial withdrawal.
            Some(list) => {
                let mut memberships = self.memberships.borrow_mut();
                if let Some(entry) = memberships
                    .iter_mut()
                    .find(|m| m.fabric_index == fabric && m.group == decoded.group_id)
                {
                    for endpoint in list.iter() {
                        let Ok(endpoint) = endpoint else { continue };
                        // Step 4b: "If a listed endpoint is not a member of the group, the
                        // server SHALL ignore it … the ignored endpoints SHALL be excluded from
                        // the LeaveGroupResponse."
                        if entry.endpoints.contains(&endpoint) {
                            entry.endpoints.retain(|e| *e != endpoint);
                            let _ = removed.push(endpoint);
                        }
                    }
                }
                let emptied = memberships.iter().any(|m| {
                    m.fabric_index == fabric
                        && m.group == decoded.group_id
                        && m.endpoints.is_empty()
                });
                drop(memberships);
                // Step 4c: "If a Membership entry is left with no endpoints, and the device is a
                // Listener only" — a sender still belongs to the group with no endpoints at all,
                // which is exactly what §11.27.5.4 describes.
                if emptied && !self.is_sender() {
                    self.forget(fabric, decoded.group_id);
                }
            }
            // Step 5: the whole group.
            None => {
                if let Some(entry) = self.find(fabric, decoded.group_id) {
                    removed = entry.endpoints;
                }
                self.forget(fabric, decoded.group_id);
            }
        }

        full(w.start_structure(tag))?;
        full(w.unsigned(Tag::Context(0), u64::from(decoded.group_id.0)))?;
        full(w.start_array(Tag::Context(1)))?;
        for endpoint in &removed {
            full(w.unsigned(Tag::Anonymous, u64::from(*endpoint)))?;
        }
        full(w.end_container())?;
        full(w.end_container())?;
        Ok(Some(LEAVE_GROUP_RESPONSE))
    }

    /// §11.27.7.4.
    fn update_key(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
    ) -> core::result::Result<Option<CommandId>, StatusIb> {
        let decoded: spec_gc::UpdateGroupKeyFields<'_> = super::decode_fields(payload)?;
        if decoded.group_id.0 == 0 || decoded.key_set_id == 0 {
            return Err(Status::ConstraintError.into());
        }
        // Step 1: the group has to exist first. Updating the key of a group this node has not
        // joined would install a key nothing uses.
        if self.find(fabric, decoded.group_id).is_none() {
            return Err(Status::NotFound.into());
        }
        self.install_key(fabric, decoded.key_set_id, decoded.key)?;
        if let Some(entry) = self
            .memberships
            .borrow_mut()
            .iter_mut()
            .find(|m| m.fabric_index == fabric && m.group == decoded.group_id)
        {
            entry.key_set = decoded.key_set_id;
        }
        self.keys
            .borrow_mut()
            .map_group(fabric, decoded.group_id, decoded.key_set_id)?;
        Ok(None)
    }

    /// §11.27.7.5.
    fn configure_auxiliary_acl(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
    ) -> core::result::Result<Option<CommandId>, StatusIb> {
        let decoded: spec_gc::ConfigureAuxiliaryACLFields = super::decode_fields(payload)?;
        let mut memberships = self.memberships.borrow_mut();
        let Some(entry) = memberships
            .iter_mut()
            .find(|m| m.fabric_index == fabric && m.group == decoded.group_id)
        else {
            return Err(Status::NotFound.into());
        };
        entry.has_auxiliary_acl = decoded.use_auxiliary_acl;
        Ok(None)
    }

    /// §11.27.7.1 steps 4 and 5, and §11.27.7.4 steps 2 and 3 — the same rule twice.
    ///
    /// A `Key` creates the key set; no `Key` requires one to exist already. Either way the
    /// **input** key is not kept: §11.27.7.1, "the InputKey itself SHALL NOT be stored", so what
    /// goes into [`GroupKeys`] is the epoch key and what comes out is the operational one.
    fn install_key(
        &self,
        fabric: FabricIndex,
        key_set: KeySetId,
        key: Option<&[u8]>,
    ) -> core::result::Result<(), Status> {
        let mut keys = self.keys.borrow_mut();
        match key {
            Some(key) => {
                if key.len() != SYMMETRIC_KEY_LENGTH_BYTES {
                    return Err(Status::ConstraintError);
                }
                // "This key SHALL be new for the group, with a unique KeySetID that does not
                // exist on the node yet."
                if keys.key_set(fabric, key_set).is_some() {
                    return Err(Status::AlreadyExists);
                }
                let bytes = <[u8; SYMMETRIC_KEY_LENGTH_BYTES]>::try_from(key)
                    .map_err(|_| Status::ConstraintError)?;
                let mut epoch_keys = heapless::Vec::new();
                epoch_keys
                    .push(EpochKey {
                        key: SymmetricKey::new(bytes),
                        // §11.27.7.1 spells the synthesised key set out: TrustFirst,
                        // EpochStartTime0 = 1, and the other two slots null.
                        start_time_us: 1,
                    })
                    .map_err(|_| Status::ResourceExhausted)?;
                keys.write_key_set(GroupKeySet {
                    fabric_index: fabric,
                    id: key_set,
                    policy: GroupKeySecurityPolicy::TrustFirst,
                    epoch_keys,
                })
            }
            // "The server SHALL verify that the KeySetID field maps to an existing
            // OperationalGroupKey of the fabric. Otherwise … NOT_FOUND."
            None if keys.key_set(fabric, key_set).is_none() => Err(Status::NotFound),
            None => Ok(()),
        }
    }

    fn find(&self, fabric: FabricIndex, group: GroupId) -> Option<Membership<E>> {
        self.memberships
            .borrow()
            .iter()
            .find(|m| m.fabric_index == fabric && m.group == group)
            .cloned()
    }

    /// Removes a group and everything that hangs off it (§11.27.7.2 steps 4c and 5).
    fn forget(&self, fabric: FabricIndex, group: GroupId) {
        let key_set = self.find(fabric, group).map(|m| m.key_set);
        self.memberships
            .borrow_mut()
            .retain(|m| !(m.fabric_index == fabric && m.group == group));
        let mut keys = self.keys.borrow_mut();
        let remaining: heapless::Vec<_, 32> = keys
            .map()
            .iter()
            .filter(|(f, g, _)| *f == fabric && *g != group)
            .map(|(_, g, set)| (*g, *set))
            .collect();
        let _ = keys.replace_map(fabric, &remaining);
        // "The server SHALL also delete all operational group keys of the removed group" — but
        // only when nothing else is still using the key set, since §11.27.7.1 lets several
        // groups share one.
        if let Some(key_set) = key_set
            && !self
                .memberships
                .borrow()
                .iter()
                .any(|m| m.fabric_index == fabric && m.key_set == key_set)
        {
            let _ = keys.remove_key_set(fabric, key_set);
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<const M: usize, const E: usize, const K: usize, const G: usize> Cluster
    for Groupcast<'_, M, E, K, G>
{
    const ID: ClusterId = ID;
}
