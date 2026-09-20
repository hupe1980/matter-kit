//! Group key sets and the map from a group to one (Core §4.17, §11.2).
//!
//! The table an administrator writes through the Group Key Management cluster, and the lookup a
//! message goes through in both directions: a sender asks "which key encrypts for this group",
//! a receiver asks "which keys could have encrypted this".

use heapless::Vec;

use crate::config::Config;
use crate::crypto::SymmetricKey;
use crate::error::{Error, ErrorCode, Result};
use crate::fabric::{CompressedFabricId, operational_group_key};
use crate::im::Status;
use crate::msg::{FabricIndex, GroupId};
use crate::platform::Instant;

/// A Group Key Set ID (§11.2.5.4). `0` is the IPK's, which §11.2.7.1 forbids writing.
pub type KeySetId = u16;

/// §11.2.7.1: "if the GroupKeySetID is 0 … the server SHALL respond with INVALID_COMMAND" —
/// key set 0 is the Identity Protection Key's, installed by `AddNOC` and owned by the fabric.
pub const IPK_KEY_SET: KeySetId = 0;

/// §4.17.3.2: "there SHALL be at least 1 and at most 3 epoch keys in rotation".
pub const MAX_EPOCH_KEYS: usize = 3;

/// §11.2.5.4's `GroupKeySecurityPolicyEnum`, which chooses how a receiver decides a message is
/// fresh (§4.18.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GroupKeySecurityPolicy {
    /// §4.18.1.1: "The first authenticated message counter from an unsynchronized peer is
    /// trusted." Lower latency, and — the specification's own warning — "susceptible to
    /// accepting a replayed message after a Node has been rebooted".
    TrustFirst = 0,
    /// §4.18.1.2: hold the message, synchronise over [`mcsp`](super::mcsp), then process it.
    /// Replay protection across a reboot, at the cost of a round trip. Provisional: support is
    /// declared through the cluster's `CacheAndSync` feature.
    CacheAndSync = 1,
}

impl GroupKeySecurityPolicy {
    /// The wire value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Reads the wire value.
    pub const fn from_value(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::TrustFirst,
            1 => Self::CacheAndSync,
            // §7.19.2: a value this revision does not define is not one to guess at, and
            // guessing wrong here would pick the *weaker* replay policy.
            _ => return Err(Error::new(ErrorCode::TlvOutOfRange)),
        })
    }
}

/// One epoch key and the moment it becomes the one a sender uses (§4.17.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochKey {
    /// The key an administrator generated with `Crypto_DRBG`.
    pub key: SymmetricKey,
    /// "absolute UTC time in microseconds encoded using the epoch-us representation".
    ///
    /// §4.17.3.1: "An epoch key marked with the maximum start time SHALL be disabled" — which
    /// is [`DISABLED`](Self::DISABLED).
    pub start_time_us: u64,
}

impl EpochKey {
    /// §4.17.3.1's disabled marker: "An epoch key marked with the maximum start time SHALL be
    /// disabled and render the corresponding epoch key slot unused."
    pub const DISABLED: u64 = u64::MAX;

    /// Whether this slot is in use.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.start_time_us != Self::DISABLED
    }
}

/// A group key set: up to three epoch keys in rotation, and the policy that governs them
/// (§4.17.2.2, §11.2.5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKeySet {
    /// Which fabric it belongs to. Key material is per fabric: §4.17.2.1, "with the exception of
    /// the group security info, all input key material SHALL be maintained on a per-Fabric
    /// basis".
    pub fabric_index: FabricIndex,
    /// Its id, unique within the fabric.
    pub id: KeySetId,
    /// How a receiver decides a message under this key is fresh.
    pub policy: GroupKeySecurityPolicy,
    /// The epoch keys, oldest first — §4.17.3.2: "An epoch key update SHALL order the keys from
    /// oldest to newest."
    pub epoch_keys: Vec<EpochKey, MAX_EPOCH_KEYS>,
}

impl GroupKeySet {
    /// A key set holding one epoch key, which is what §11.27.7.1's `JoinGroup` and
    /// §11.18.6.8's `AddNOC` both synthesise.
    ///
    /// Rotation needs two or three; a group that has just been created has one, and building it
    /// is otherwise four lines of `heapless::Vec` at every call site.
    #[must_use]
    pub fn single(
        fabric_index: FabricIndex,
        id: KeySetId,
        policy: GroupKeySecurityPolicy,
        key: SymmetricKey,
        start_time_us: u64,
    ) -> Self {
        let mut epoch_keys = Vec::new();
        let _ = epoch_keys.push(EpochKey { key, start_time_us });
        Self {
            fabric_index,
            id,
            policy,
            epoch_keys,
        }
    }

    /// The epoch key a *sender* uses: §4.17.3.1's "the epoch key with the latest start time that
    /// is not in the future".
    ///
    /// `now` is UTC microseconds, or [`None`] on a node without a synchronised clock — which
    /// §4.17.3.4 provides for: "such a Node can note which of the keys is the current epoch key
    /// by comparing their relative start times and using the current epoch key which has the
    /// second newest time." With fewer than two enabled keys that degrades to the newest, which
    /// is the only one it could mean.
    #[must_use]
    pub fn current(&self, now: Option<u64>) -> Option<&EpochKey> {
        let mut enabled: Vec<&EpochKey, MAX_EPOCH_KEYS> =
            self.epoch_keys.iter().filter(|k| k.is_enabled()).collect();
        // Oldest first is how they arrive, but an administrator is not the only source of this
        // table — a persisted set read back is not ordered by anything.
        enabled.sort_unstable_by_key(|k| k.start_time_us);
        match now {
            Some(now) => enabled
                .iter()
                .rev()
                .find(|k| k.start_time_us <= now)
                .copied()
                // Every start time is in the future: the node's clock is behind the
                // administrator's, and the oldest key is the closest thing to current.
                .or_else(|| enabled.first().copied()),
            None => {
                let len = enabled.len();
                enabled
                    .get(len.saturating_sub(2))
                    .or_else(|| enabled.first())
                    .copied()
            }
        }
    }
}

/// The per-fabric group state of §11.2: the key sets, and which key set each group uses.
///
/// `K` bounds the key sets across every fabric and `M` the group-to-key-set map. The per-fabric
/// quotas §11.2.6.3's `MaxGroupKeysPerFabric` and §11.2.6.2's `MaxGroupsPerFabric` report come
/// from [`Config`], and [`GroupKeys::CHECK`] refuses at compile time a `K` or `M` too small to
/// give every fabric its share — which is the only way those two attributes can be the promise
/// the specification says they are rather than a pair of numbers typed beside the table.
#[derive(Debug)]
pub struct GroupKeys<C: Config, const K: usize = 15, const M: usize = 20> {
    sets: Vec<GroupKeySet, K>,
    map: Vec<(FabricIndex, GroupId, KeySetId), M>,
    _config: core::marker::PhantomData<C>,
}

/// An operational key a message can be sent or received under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalKey {
    /// The key itself, derived from an epoch key and the fabric's compressed identifier.
    pub key: SymmetricKey,
    /// Which key set it came from, so the policy that governs it can be found again.
    pub key_set: KeySetId,
    /// The fabric it belongs to.
    pub fabric_index: FabricIndex,
    /// The policy of the key set (§4.18.1).
    pub policy: GroupKeySecurityPolicy,
    /// §4.17.3.6's Group Session ID, which goes in the message header.
    pub session_id: u16,
}

impl<C: Config, const K: usize, const M: usize> crate::config::Capacity for GroupKeys<C, K, M> {
    const TOTAL: usize = K;
    /// §11.2.6.3's `MaxGroupKeysPerFabric`.
    const PER_FABRIC: usize = C::GROUP_KEYS_PER_FABRIC;
}

impl<C: Config, const K: usize, const M: usize> Default for GroupKeys<C, K, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Config, const K: usize, const M: usize> GroupKeys<C, K, M> {
    /// Compile-time proof that both tables can keep §2.11.1.2's promises.
    ///
    /// > at least four groups per fabric … at least three group keys per fabric
    ///
    /// The quotas are what stop the first fabric to provision from filling the table; this is
    /// what stops the quotas from promising room that is not there.
    pub const CHECK: () = {
        let () = crate::config::AssertValid::<C>::CHECK;
        assert!(
            K >= C::GROUP_KEYS_PER_FABRIC * C::FABRICS,
            "GroupKeys: Core §2.11.1.2 promises GROUP_KEYS_PER_FABRIC to every fabric, so K \
             must be FABRICS × that many"
        );
        assert!(
            M >= C::GROUPS_PER_FABRIC * C::FABRICS,
            "GroupKeys: Core §2.11.1.2 promises GROUPS_PER_FABRIC to every fabric, so M must \
             be FABRICS × that many"
        );
    };

    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        let () = Self::CHECK;
        Self {
            sets: Vec::new(),
            map: Vec::new(),
            _config: core::marker::PhantomData,
        }
    }

    /// `MaxGroupsPerFabric` (§11.2.6.2).
    #[must_use]
    pub const fn max_groups_per_fabric(&self) -> usize {
        C::GROUPS_PER_FABRIC
    }

    /// `MaxGroupKeysPerFabric` (§11.2.6.3).
    #[must_use]
    pub const fn max_key_sets_per_fabric(&self) -> usize {
        C::GROUP_KEYS_PER_FABRIC
    }

    /// Every key set, for a device about to persist them.
    #[must_use]
    pub fn key_sets(&self) -> &[GroupKeySet] {
        &self.sets
    }

    /// The `GroupKeyMap` entries (§11.2.6.1).
    #[must_use]
    pub fn map(&self) -> &[(FabricIndex, GroupId, KeySetId)] {
        &self.map
    }

    /// Installs or replaces a key set — §11.2.7.1's `KeySetWrite`.
    ///
    /// > Any update of the key set, including a partial update, SHALL remove all previous keys
    /// > in the set, however many were defined.
    ///
    /// So this replaces rather than merges, which is what makes the command idempotent and the
    /// administrator "always the source of truth".
    pub fn write_key_set(&mut self, set: GroupKeySet) -> core::result::Result<(), Status> {
        if set.epoch_keys.is_empty() {
            // §11.2.7.1: EpochKey0 is mandatory, so a set with nothing in it is not one.
            return Err(Status::InvalidCommand);
        }
        if let Some(existing) = self
            .sets
            .iter_mut()
            .find(|s| s.id == set.id && s.fabric_index == set.fabric_index)
        {
            *existing = set;
            return Ok(());
        }
        if self.count_sets(set.fabric_index) >= C::GROUP_KEYS_PER_FABRIC {
            return Err(Status::ResourceExhausted);
        }
        self.sets.push(set).map_err(|_| Status::ResourceExhausted)
    }

    /// One key set, if this fabric has it.
    #[must_use]
    pub fn key_set(&self, fabric: FabricIndex, id: KeySetId) -> Option<&GroupKeySet> {
        self.sets
            .iter()
            .find(|s| s.id == id && s.fabric_index == fabric)
    }

    /// Removes a key set — §11.2.7.4's `KeySetRemove`.
    ///
    /// > This command SHALL fail with an INVALID_COMMAND status code back to the initiator if
    /// > the GroupKeySetID being removed is 0, which is the key set associated with the Identity
    /// > Protection Key (IPK).
    pub fn remove_key_set(
        &mut self,
        fabric: FabricIndex,
        id: KeySetId,
    ) -> core::result::Result<(), Status> {
        if id == IPK_KEY_SET {
            return Err(Status::InvalidCommand);
        }
        if self.key_set(fabric, id).is_none() {
            return Err(Status::NotFound);
        }
        self.sets
            .retain(|s| !(s.id == id && s.fabric_index == fabric));
        // §11.2.7.4: "This command SHALL also remove all entries in the GroupKeyMap whose
        // GroupKeySetID matches" — a group mapped to a key set that no longer exists could
        // neither send nor receive, and would keep its multicast subscription alive for nothing.
        self.map.retain(|(f, _, set)| !(*set == id && *f == fabric));
        Ok(())
    }

    /// Maps a group to a key set — one entry of §11.2.6.1's `GroupKeyMap`.
    pub fn map_group(
        &mut self,
        fabric: FabricIndex,
        group: GroupId,
        key_set: KeySetId,
    ) -> core::result::Result<(), Status> {
        // §11.2.6.1: "an entry in this list SHALL only be added if the GroupKeySetID exists",
        // and a map to nothing is a group that can neither send nor receive.
        if self.key_set(fabric, key_set).is_none() {
            return Err(Status::NotFound);
        }
        if let Some(entry) = self
            .map
            .iter_mut()
            .find(|(f, g, _)| *f == fabric && *g == group)
        {
            entry.2 = key_set;
            return Ok(());
        }
        if self.count_groups(fabric) >= C::GROUPS_PER_FABRIC {
            return Err(Status::ResourceExhausted);
        }
        self.map
            .push((fabric, group, key_set))
            .map_err(|_| Status::ResourceExhausted)
    }

    /// Replaces one fabric's whole `GroupKeyMap`, which is what a list write does.
    pub fn replace_map(
        &mut self,
        fabric: FabricIndex,
        entries: &[(GroupId, KeySetId)],
    ) -> core::result::Result<(), Status> {
        if entries.len() > C::GROUPS_PER_FABRIC {
            return Err(Status::ResourceExhausted);
        }
        for (_, key_set) in entries {
            if self.key_set(fabric, *key_set).is_none() {
                return Err(Status::NotFound);
            }
        }
        self.map.retain(|(f, _, _)| *f != fabric);
        for (group, key_set) in entries {
            self.map
                .push((fabric, *group, *key_set))
                .map_err(|_| Status::ResourceExhausted)?;
        }
        Ok(())
    }

    /// Forgets everything one fabric installed — what `RemoveFabric` must do.
    pub fn remove_fabric(&mut self, fabric: FabricIndex) {
        self.sets.retain(|s| s.fabric_index != fabric);
        self.map.retain(|(f, _, _)| *f != fabric);
    }

    /// The key a *sender* encrypts a message to `group` with (§4.16.2 step 1).
    ///
    /// > Obtain, for the given GroupKeySetID, the current Operational Group Key as the
    /// > Encryption Key, and the associated Group Session ID. If no key is found for the given
    /// > GroupKeySetID, security processing SHALL fail and no further security processing SHALL
    /// > be done on this message.
    pub fn sending_key(
        &self,
        fabric: FabricIndex,
        compressed: CompressedFabricId,
        group: GroupId,
        now: Option<Instant>,
    ) -> Result<OperationalKey> {
        let key_set = self
            .map
            .iter()
            .find(|(f, g, _)| *f == fabric && *g == group)
            .map(|(_, _, set)| *set)
            .ok_or(Error::new(ErrorCode::NoSession))?;
        let set = self
            .key_set(fabric, key_set)
            .ok_or(Error::new(ErrorCode::NoSession))?;
        let epoch = set
            .current(now.map(Instant::as_micros))
            .ok_or(Error::new(ErrorCode::NoSession))?;
        Self::operational(set, epoch, compressed)
    }

    /// Every key a *receiver* should try for a message that named `session_id` (§4.17.3.6).
    ///
    /// > On receipt of a message of Group Session Type, all valid, installed, operational group
    /// > key candidates referenced by the given Group Session ID SHALL be attempted until
    /// > authentication is passed or there are no more operational group keys to try.
    ///
    /// Every *installed* epoch key, not just the current one: §4.17.3.1 has a receiver "accept
    /// the use of any key derived from one of the currently installed epoch keys … regardless of
    /// whether the start time for the key is in the future or the past", because the sender's
    /// clock is not this node's.
    pub fn receiving_keys<const N: usize>(
        &self,
        compressed: impl Fn(FabricIndex) -> Option<CompressedFabricId>,
        session_id: u16,
    ) -> Vec<OperationalKey, N> {
        let mut out = Vec::new();
        for set in &self.sets {
            let Some(compressed) = compressed(set.fabric_index) else {
                continue;
            };
            for epoch in set.epoch_keys.iter().filter(|k| k.is_enabled()) {
                let Ok(candidate) = Self::operational(set, epoch, compressed) else {
                    continue;
                };
                if candidate.session_id == session_id && out.push(candidate).is_err() {
                    return out;
                }
            }
        }
        out
    }

    /// §4.17.2's derivation, plus §4.17.3.6's session id, which always travel together.
    fn operational(
        set: &GroupKeySet,
        epoch: &EpochKey,
        compressed: CompressedFabricId,
    ) -> Result<OperationalKey> {
        let key = operational_group_key(&epoch.key, compressed)?;
        let session_id = super::session_id(&key)?;
        Ok(OperationalKey {
            key,
            key_set: set.id,
            fabric_index: set.fabric_index,
            policy: set.policy,
            session_id,
        })
    }

    fn count_sets(&self, fabric: FabricIndex) -> usize {
        self.sets
            .iter()
            .filter(|s| s.fabric_index == fabric)
            .count()
    }

    fn count_groups(&self, fabric: FabricIndex) -> usize {
        self.map.iter().filter(|(f, _, _)| *f == fabric).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const F1: FabricIndex = FabricIndex(1);

    fn key(byte: u8) -> SymmetricKey {
        SymmetricKey::new([byte; 16])
    }

    fn set_with(times: &[u64]) -> GroupKeySet {
        let mut epoch_keys = Vec::new();
        for (i, start) in times.iter().enumerate() {
            let _ = epoch_keys.push(EpochKey {
                key: key(i as u8),
                start_time_us: *start,
            });
        }
        GroupKeySet {
            fabric_index: F1,
            id: 1,
            policy: GroupKeySecurityPolicy::TrustFirst,
            epoch_keys,
        }
    }

    #[test]
    fn the_current_key_is_the_newest_that_has_started() {
        // §4.17.3.1: "the epoch key with the latest start time that is not in the future".
        let set = set_with(&[100, 200, 300]);
        assert_eq!(set.current(Some(250)).unwrap().start_time_us, 200);
        assert_eq!(set.current(Some(300)).unwrap().start_time_us, 300);
        assert_eq!(set.current(Some(99)).unwrap().start_time_us, 100);
    }

    #[test]
    fn a_node_without_a_clock_uses_the_second_newest() {
        // §4.17.3.4: "such a Node can note which of the keys is the current epoch key by
        // comparing their relative start times and using the current epoch key which has the
        // second newest time."
        let set = set_with(&[100, 200, 300]);
        assert_eq!(set.current(None).unwrap().start_time_us, 200);
        // With two keys the second newest is the older of them; with one there is no choice.
        assert_eq!(
            set_with(&[100, 200]).current(None).unwrap().start_time_us,
            100
        );
        assert_eq!(set_with(&[100]).current(None).unwrap().start_time_us, 100);
    }

    #[test]
    fn a_disabled_slot_is_not_a_key() {
        // §4.17.3.1: "An epoch key marked with the maximum start time SHALL be disabled and
        // render the corresponding epoch key slot unused."
        let set = set_with(&[100, EpochKey::DISABLED]);
        assert_eq!(set.current(Some(u64::MAX)).unwrap().start_time_us, 100);
        assert_eq!(set.current(None).unwrap().start_time_us, 100);
    }

    #[test]
    fn keys_out_of_order_still_resolve() {
        // §4.17.3.2 asks an administrator to order them oldest to newest, but a set read back
        // from persistence is ordered by nothing at all.
        let set = set_with(&[300, 100, 200]);
        assert_eq!(set.current(Some(250)).unwrap().start_time_us, 200);
        assert_eq!(set.current(None).unwrap().start_time_us, 200);
    }
}
