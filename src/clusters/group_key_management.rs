//! Group Key Management, cluster `0x003F` (Core §11.2).
//!
//! Where an administrator installs the keys that make groupcast possible, and the map from a
//! Group ID to the key set that secures it. §4.17.4: "the key material of a Node is exposed via
//! Attributes with ACL entries that only allow access by the key distribution Administrator."
//!
//! # Keys go in and never come back out
//!
//! §11.2.7.2 is the rule that matters most here, and it is one line:
//!
//! > the contents of that Group Key Set SHALL be sent in a KeySetReadResponse command, but with
//! > the EpochKey0, EpochKey1 and EpochKey2 fields replaced by null.
//!
//! An administrator can write a key, learn *that* a key exists, and learn its policy and start
//! times. It cannot read the key back. A device that echoed the epoch keys would let anyone with
//! Administer privilege on any fabric — including one being removed — walk away with the key to
//! every group message on the node.
//!
//! # Key set 0 is not a key set
//!
//! §11.2.7.4: `KeySetRemove` of key set `0` is `INVALID_COMMAND`. Zero is the Identity
//! Protection Key's, synthesised by `AddNOC` (§11.18.6.8.1), and "the only method to remove the
//! IPK is usage of the RemoveFabric command". Removing it any other way would leave the fabric
//! with a CASE handshake it could no longer complete.
//!
//! # A write is a replacement, on purpose
//!
//! §4.17.3.2: "Any update of the key set, including a partial update, SHALL remove all previous
//! keys in the set, however many were defined." That is what makes `KeySetWrite` idempotent and
//! keeps "the Administrator … always the source of truth" — a merge would leave a node holding
//! a key the administrator believed it had withdrawn.

use core::cell::RefCell;

use crate::clusters::generated::group_key_management as spec_gkm;
use crate::config::Config;
use crate::crypto::{SYMMETRIC_KEY_LENGTH_BYTES, SymmetricKey};
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::group::keys::{EpochKey, GroupKeySecurityPolicy, GroupKeySet, GroupKeys, KeySetId};
use crate::im::{
    ClusterHandler, ClusterId, CommandId, EndpointId, InteractionContext, Status, StatusIb, WriteOp,
};
use crate::msg::{FabricIndex, GroupId};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, ToTlv, Value};

use super::Cluster;

pub use spec_gkm::attribute::{
    GROUP_KEY_MAP, GROUP_TABLE, MAX_GROUP_KEYS_PER_FABRIC, MAX_GROUPS_PER_FABRIC,
};
pub use spec_gkm::command::{
    KEY_SET_READ, KEY_SET_READ_ALL_INDICES, KEY_SET_READ_ALL_INDICES_RESPONSE,
    KEY_SET_READ_RESPONSE, KEY_SET_REMOVE, KEY_SET_WRITE,
};
pub use spec_gkm::{ID, PICS, REVISION};

/// What a device knows about which endpoints are in which group.
///
/// §11.2.6.2: `GroupTable` "reflects data managed via the Groups cluster", so this cluster does
/// not own it — it reads it. The one rule it must not break is stated there too: "The GroupTable
/// SHALL NOT contain any entry whose GroupInfoMapStruct has an empty Endpoints list."
pub trait GroupTable {
    /// Every `(fabric, group, endpoint)` membership the node holds, in any order.
    ///
    /// The cluster groups them by `(fabric, group)` itself, so an implementation can simply walk
    /// its Groups cluster instances.
    fn memberships(&self, each: &mut dyn FnMut(FabricIndex, GroupId, EndpointId));

    /// A group's name, if the Groups cluster kept one (§1.3.6.1's `GroupNames` feature).
    fn name(&self, fabric: FabricIndex, group: GroupId) -> Option<&str> {
        let _ = (fabric, group);
        None
    }
}

/// A node with no Groups cluster, whose `GroupTable` is therefore empty.
impl GroupTable for () {
    fn memberships(&self, _each: &mut dyn FnMut(FabricIndex, GroupId, EndpointId)) {}
}

/// The Group Key Management cluster (§11.2).
///
/// `K` and `M` size [`GroupKeys`]; `T` is whatever can answer "which endpoints are in this
/// group", which is the Groups cluster on a device that has one.
#[derive(Debug)]
pub struct GroupKeyManagement<
    'a,
    C: Config,
    T: GroupTable,
    const K: usize = 15,
    const M: usize = 20,
> {
    keys: &'a RefCell<GroupKeys<C, K, M>>,
    table: &'a T,
}

impl<'a, C: Config, T: GroupTable, const K: usize, const M: usize>
    GroupKeyManagement<'a, C, T, K, M>
{
    /// A cluster over the node's group keys and its group membership.
    #[must_use]
    pub const fn new(keys: &'a RefCell<GroupKeys<C, K, M>>, table: &'a T) -> Self {
        Self { keys, table }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<5, 4, 2, 0>> {
        Conforming::new(&spec_gkm::CLUSTER, feature_map, optional)
    }

    /// The key table this cluster manages, for the message layer to send and receive with.
    #[must_use]
    pub const fn keys(&self) -> &'a RefCell<GroupKeys<C, K, M>> {
        self.keys
    }
}

/// §11.2.7.1's validation of a `GroupKeySetStruct`, in the order the specification lists it.
///
/// The order is the answer: a null `EpochKey0` is `INVALID_COMMAND` and a sixteen-octet check
/// failure is `CONSTRAINT_ERROR`, so a client that sent neither can tell which it got wrong.
fn validate(set: &spec_gkm::GroupKeySetStruct<'_>) -> core::result::Result<(), Status> {
    let epochs = [
        (set.epoch_key0.0, set.epoch_start_time0.0),
        (set.epoch_key1.0, set.epoch_start_time1.0),
        (set.epoch_key2.0, set.epoch_start_time2.0),
    ];
    // "If the EpochKey0 field is null or its associated EpochStartTime0 field is null, then this
    // command SHALL fail with an INVALID_COMMAND status code."
    let (Some(key0), Some(start0)) = epochs[0] else {
        return Err(Status::InvalidCommand);
    };
    if key0.len() != SYMMETRIC_KEY_LENGTH_BYTES {
        return Err(Status::ConstraintError);
    }
    // "If the EpochStartTime0 is set to 0, then this command SHALL fail with an INVALID_COMMAND
    // status code." Zero is legal *internally* — `AddNOC` synthesises the IPK's set with it —
    // but never from a client.
    if start0 == 0 {
        return Err(Status::InvalidCommand);
    }

    let mut previous_start = start0;
    let mut previous_present = true;
    for (key, start) in epochs.into_iter().skip(1) {
        match (key, start) {
            (None, None) => {
                previous_present = false;
            }
            (Some(key), Some(start)) => {
                // "If the EpochKey2 field is not null, then the EpochKey1 and EpochKey0 fields
                // SHALL NOT be null" — a chain with a hole in it is not a rotation.
                if !previous_present {
                    return Err(Status::InvalidCommand);
                }
                if key.len() != SYMMETRIC_KEY_LENGTH_BYTES {
                    return Err(Status::ConstraintError);
                }
                // "SHALL contain a later epoch start time than the epoch start time found in
                // the EpochStartTime0 field" — the order is what "current" is read from.
                if start <= previous_start {
                    return Err(Status::InvalidCommand);
                }
                previous_start = start;
            }
            // "If exactly one of the EpochKey1 or EpochStartTime1 is null, rather than both
            // being null, or neither being null" — a key with no start time is unusable, and a
            // start time with no key names nothing.
            _ => return Err(Status::InvalidCommand),
        }
    }
    Ok(())
}

/// Turns a validated `GroupKeySetStruct` into the stored form.
fn to_key_set(
    set: &spec_gkm::GroupKeySetStruct<'_>,
    fabric: FabricIndex,
) -> core::result::Result<GroupKeySet, Status> {
    let mut epoch_keys = heapless::Vec::new();
    for (key, start) in [
        (set.epoch_key0.0, set.epoch_start_time0.0),
        (set.epoch_key1.0, set.epoch_start_time1.0),
        (set.epoch_key2.0, set.epoch_start_time2.0),
    ] {
        let (Some(key), Some(start_time_us)) = (key, start) else {
            continue;
        };
        let bytes = <[u8; SYMMETRIC_KEY_LENGTH_BYTES]>::try_from(key)
            .map_err(|_| Status::ConstraintError)?;
        epoch_keys
            .push(EpochKey {
                key: SymmetricKey::new(bytes),
                start_time_us,
            })
            .map_err(|_| Status::ResourceExhausted)?;
    }
    Ok(GroupKeySet {
        fabric_index: fabric,
        id: set.group_key_set_id,
        policy: GroupKeySecurityPolicy::from_value(set.group_key_security_policy.value())
            .map_err(|_| Status::ConstraintError)?,
        epoch_keys,
    })
}

impl<C: Config, T: GroupTable, const K: usize, const M: usize> ClusterHandler
    for GroupKeyManagement<'_, C, T, K, M>
{
    /// §11.2.7.4: a fabric's group keys go with the fabric. Leaving them behind leaves key
    /// material for a fabric this node is no longer on — the IPK included.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        if let crate::im::Lifecycle::FabricRemoved(fabric) = event {
            self.keys.borrow_mut().remove_fabric(fabric);
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
        let keys = self.keys.borrow();
        match resolved.attribute {
            MAX_GROUPS_PER_FABRIC => full(w.unsigned(tag, keys.max_groups_per_fabric() as u64)),
            MAX_GROUP_KEYS_PER_FABRIC => {
                full(w.unsigned(tag, keys.max_key_sets_per_fabric() as u64))
            }
            GROUP_KEY_MAP => {
                full(w.start_array(tag))?;
                for (fabric, group, key_set) in keys.map() {
                    if !visible(ctx, *fabric) {
                        continue;
                    }
                    full(
                        spec_gkm::GroupKeyMapStruct {
                            group_id: *group,
                            group_key_set_id: *key_set,
                            fabric_index: *fabric,
                        }
                        .to_tlv(w, Tag::Anonymous),
                    )?;
                }
                full(w.end_container())
            }
            GROUP_TABLE => self.read_group_table(ctx, w, tag),
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        op: WriteOp,
        ctx: &InteractionContext<'_>,
    ) -> core::result::Result<(), Status> {
        if resolved.attribute != GROUP_KEY_MAP {
            // `GroupTable` is `R F`: it is the Groups cluster's data, and writing it here would
            // let an administrator claim a membership no endpoint has.
            return Err(Status::UnsupportedWrite);
        }
        let Some(fabric) = ctx.fabric_index.filter(|f| f.0 != 0) else {
            return Err(Status::UnsupportedAccess);
        };

        let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;
        let mut keys = self.keys.borrow_mut();
        match op {
            WriteOp::Replace => {
                if element.value.container() != Some(ContainerKind::Array) {
                    return Err(Status::InvalidAction);
                }
                let mut entries: heapless::Vec<(GroupId, KeySetId), M> = heapless::Vec::new();
                loop {
                    let Some(item) = reader.next_element().map_err(|_| Status::InvalidAction)?
                    else {
                        return Err(Status::InvalidAction);
                    };
                    if item.value == Value::EndOfContainer {
                        break;
                    }
                    let entry = decode_map_entry(&mut reader, &item)?;
                    entries.push(entry).map_err(|_| Status::ResourceExhausted)?;
                }
                keys.replace_map(fabric, &entries)
            }
            WriteOp::Append => {
                let (group, key_set) = decode_map_entry(&mut reader, &element)?;
                keys.map_group(fabric, group, key_set)
            }
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
        // §11.2.7: "All commands in this cluster SHALL be scoped to the accessing fabric."
        let fabric = ctx
            .fabric_index
            .filter(|f| f.0 != 0)
            .ok_or(StatusIb::from(Status::UnsupportedAccess))?;
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        match resolved.command.id {
            KEY_SET_WRITE => {
                let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
                let decoded: spec_gkm::KeySetWriteFields<'_> = super::decode_fields(payload)?;
                validate(&decoded.group_key_set)?;
                let set = to_key_set(&decoded.group_key_set, fabric)?;
                self.keys.borrow_mut().write_key_set(set)?;
                Ok(None)
            }
            KEY_SET_READ => {
                let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
                let decoded: spec_gkm::KeySetReadFields = super::decode_fields(payload)?;
                let keys = self.keys.borrow();
                let set = keys
                    .key_set(fabric, decoded.group_key_set_id)
                    .ok_or(StatusIb::from(Status::NotFound))?;
                full(Self::read_response(set).to_tlv(w, tag))?;
                Ok(Some(KEY_SET_READ_RESPONSE))
            }
            KEY_SET_REMOVE => {
                let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
                let decoded: spec_gkm::KeySetRemoveFields = super::decode_fields(payload)?;
                self.keys
                    .borrow_mut()
                    .remove_key_set(fabric, decoded.group_key_set_id)?;
                Ok(None)
            }
            KEY_SET_READ_ALL_INDICES => {
                let keys = self.keys.borrow();
                full(w.start_structure(tag))?;
                full(w.start_array(Tag::Context(0)))?;
                for set in keys.key_sets().iter().filter(|s| s.fabric_index == fabric) {
                    full(w.unsigned(Tag::Anonymous, u64::from(set.id)))?;
                }
                full(w.end_container())?;
                full(w.end_container())?;
                Ok(Some(KEY_SET_READ_ALL_INDICES_RESPONSE))
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<C: Config, T: GroupTable, const K: usize, const M: usize> GroupKeyManagement<'_, C, T, K, M> {
    /// §11.2.7.3's response: everything about the key set except the keys.
    fn read_response(set: &GroupKeySet) -> spec_gkm::KeySetReadResponseFields<'static> {
        let start = |index: usize| {
            set.epoch_keys
                .get(index)
                .map(|k| k.start_time_us)
                .map_or(crate::tlv::Nullable::null(), crate::tlv::Nullable::some)
        };
        spec_gkm::KeySetReadResponseFields {
            group_key_set: spec_gkm::GroupKeySetStruct {
                group_key_set_id: set.id,
                group_key_security_policy: spec_gkm::GroupKeySecurityPolicyEnum::from_value(
                    set.policy.value(),
                )
                .unwrap_or(spec_gkm::GroupKeySecurityPolicyEnum::TrustFirst),
                // §11.2.7.2: "with the EpochKey0, EpochKey1 and EpochKey2 fields replaced by
                // null". The start times are not secret and are what an administrator needs in
                // order to schedule the next rotation; the keys never leave the node.
                epoch_key0: crate::tlv::Nullable::null(),
                epoch_start_time0: start(0),
                epoch_key1: crate::tlv::Nullable::null(),
                epoch_start_time1: start(1),
                epoch_key2: crate::tlv::Nullable::null(),
                epoch_start_time2: start(2),
                group_key_multicast_policy: None,
                fabric_index: set.fabric_index,
            },
        }
    }

    /// §11.2.6.2's `GroupTable`, grouped by `(fabric, group)`.
    fn read_group_table(
        &self,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        // Collect the distinct (fabric, group) pairs first: the trait yields memberships in any
        // order, and one group's endpoints have to be written as one list.
        let mut groups: heapless::Vec<(FabricIndex, GroupId), M> = heapless::Vec::new();
        self.table.memberships(&mut |fabric, group, _| {
            if visible(ctx, fabric) && !groups.contains(&(fabric, group)) {
                let _ = groups.push((fabric, group));
            }
        });

        full(w.start_array(tag))?;
        for (fabric, group) in &groups {
            full(w.start_structure(Tag::Anonymous))?;
            full(w.unsigned(Tag::Context(1), u64::from(group.0)))?;
            full(w.start_array(Tag::Context(2)))?;
            let mut result = Ok(());
            self.table.memberships(&mut |f, g, endpoint| {
                if f == *fabric && g == *group && result.is_ok() {
                    result = w.unsigned(Tag::Anonymous, u64::from(endpoint));
                }
            });
            full(result)?;
            full(w.end_container())?;
            if let Some(name) = self.table.name(*fabric, *group) {
                full(w.utf8(Tag::Context(3), name))?;
            }
            full(w.unsigned(Tag::Context(254), u64::from(fabric.0)))?;
            full(w.end_container())?;
        }
        full(w.end_container())
    }
}

/// Reads one `GroupKeyMapStruct`. §7.19.1.8.1: the client's `FabricIndex` is ignored.
fn decode_map_entry<'a>(
    reader: &mut TlvReader<'a>,
    element: &crate::tlv::Element<'a>,
) -> core::result::Result<(GroupId, KeySetId), Status> {
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }
    let entry = <spec_gkm::GroupKeyMapStruct as crate::tlv::FromTlv<'a>>::from_tlv(reader, element)
        .map_err(|_| Status::InvalidAction)?;
    Ok((entry.group_id, entry.group_key_set_id))
}

/// Whether a fabric's entries belong in this read (§7.19.1.8.2).
fn visible(ctx: &InteractionContext<'_>, index: FabricIndex) -> bool {
    !ctx.fabric_filtered || ctx.fabric_index == Some(index)
}

/// So a tuple of clusters can dispatch to it by id.
impl<C: Config, T: GroupTable, const K: usize, const M: usize> Cluster
    for GroupKeyManagement<'_, C, T, K, M>
{
    const ID: ClusterId = ID;
}
