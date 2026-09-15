//! Cluster data versions (Core §7.10.3).
//!
//! > A cluster data version SHALL increment or be set (wrap) to zero if incrementing would
//! > exceed its maximum value. **A cluster data version SHALL be maintained for each cluster
//! > instance.** A cluster data version SHALL be initialized randomly when it is first
//! > published. A cluster data version SHALL be incremented if any attribute data changes.
//!
//! It is a cache tag. A client that has read a cluster keeps the version it came with and sends
//! it back in a `DataVersionFilter`; the server then omits everything that has not changed
//! (§8.4.3.2), which is the difference between a subscription costing one datagram and costing
//! twenty.
//!
//! # Why it is not optional in practice
//!
//! §10.6.4.1 permits an `AttributeDataIB` to omit its `DataVersion` — "it SHALL be interpreted
//! as though a data version was not specified" — so a report without one is a legal report. The
//! CHIP SDK does not keep such an attribute: its cluster-state cache is keyed by version, and an
//! attribute that arrives without one is parsed, logged, and dropped. The visible symptom is a
//! commissioner that reads `BasicCommissioningInfo`, `VendorID` and every other attribute it
//! needs, receives all of them, and then fails with *Key not found* on each.
//!
//! So a device that omits the version is spec-legal and uncommissionable, which is the worst of
//! both. This table exists so that the correct thing happens without a cluster having to
//! implement anything: [`ClusterHandler::data_version`](crate::im::ClusterHandler::data_version)
//! stays the authority for a cluster that tracks its own, and a [`Server`](crate::im::Server)
//! given one of these falls back to it for every cluster that does not.
//!
//! ```
//! use matter_kit::dm::{DataVersionSource, DataVersions};
//!
//! // Sized by the integrator: one entry per cluster instance the node serves.
//! let versions = DataVersions::<16>::new(0x1234_5678);
//! let first = versions.version(0, 0x0006);
//! assert_eq!(versions.version(0, 0x0006), first, "stable until something changes");
//!
//! versions.touch(0, 0x0006);
//! assert_ne!(versions.version(0, 0x0006), first, "and moves when it does");
//! ```

use core::cell::RefCell;

use crate::im::{ClusterId, EndpointId};

/// Where a [`Server`](crate::im::Server) gets a cluster's data version.
///
/// A trait rather than a concrete table so that `Server` does not take the table's capacity as a
/// generic parameter — the capacity is the integrator's business and nothing in the server's
/// signature should depend on it.
pub trait DataVersionSource: core::fmt::Debug {
    /// The current version of one cluster instance, allocating one if it has never been read.
    fn version(&self, endpoint: EndpointId, cluster: ClusterId) -> u32;

    /// Records that an attribute of this cluster instance changed.
    ///
    /// "A cluster data version SHALL be incremented if any attribute data changes" — *any*, so
    /// a cluster that changes on its own (a sensor reading, a switch someone pressed) has to
    /// call this too. Only writes that arrive through the interaction model are automatic.
    fn touch(&self, endpoint: EndpointId, cluster: ClusterId);
}

/// One cluster instance's version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    endpoint: EndpointId,
    cluster: ClusterId,
    version: u32,
}

/// A fixed-capacity table of §7.10.3's cluster data versions.
///
/// `N` is how many cluster instances the node has — endpoints times the clusters on each, which
/// is `const` data, so the number is known when the node is designed. A table that fills stops
/// tracking new instances rather than evicting a live one: an evicted version would be handed
/// out again later and tell a client its cache is current when it is not, which is worse than
/// having no version at all.
#[derive(Debug)]
pub struct DataVersions<const N: usize> {
    entries: RefCell<heapless::Vec<Entry, N>>,
    /// The generator for a version's initial value.
    seed: RefCell<u32>,
    /// Cluster instances touched since [`DataVersions::drain_changes`] last ran.
    ///
    /// §7.10.3 already makes the data version the record of "an attribute of this cluster
    /// changed" — "A cluster data version SHALL be incremented if any attribute data changes".
    /// This makes that record *observable*, which is what a subscription needs: §8.5.3 dirties
    /// a subscription on a change to a path it covers, and without somewhere to read changes
    /// from, a node has to be told about each one by hand and will forget.
    ///
    /// Kept separately from `entries` rather than as a flag on one, because a change to an
    /// instance nobody has read yet still has to be reported: `touch` deliberately does not
    /// allocate a version for such an instance, and losing the change with it would make the
    /// signal depend on whether anyone happened to have read the cluster first.
    changed: RefCell<heapless::Vec<(EndpointId, ClusterId), N>>,
}

impl<const N: usize> DataVersions<N> {
    /// An empty table whose first version is derived from `seed`.
    ///
    /// §7.10.3: "A cluster data version SHALL be initialized randomly when it is first
    /// published." `seed` should come from [`Rng`](crate::platform::Rng). Starting every cluster
    /// at zero on every boot is what lets a client keep a cache across a device's restart and be
    /// wrong about it: the versions match, the data does not.
    #[must_use]
    pub fn new(seed: u32) -> Self {
        Self {
            entries: RefCell::new(heapless::Vec::new()),
            seed: RefCell::new(seed),
            changed: RefCell::new(heapless::Vec::new()),
        }
    }

    /// The cluster instances whose data changed since this was last called, and clears them.
    ///
    /// Drained rather than read, because the caller is expected to hand each one to
    /// [`SubscriptionTable::note_cluster_change`](crate::im::SubscriptionTable::note_cluster_change)
    /// and a change reported twice is a report sent twice.
    ///
    /// This is the seam between "a cluster changed" and "a subscriber is owed a report". Writes
    /// that arrive through the interaction model land here on their own; a cluster that changes
    /// on its own — a sensor reading, a switch somebody pressed — is the one that has to call
    /// [`DataVersionSource::touch`], which §7.10.3 requires of it regardless.
    #[must_use]
    pub fn drain_changes(&self) -> heapless::Vec<(EndpointId, ClusterId), N> {
        core::mem::take(&mut self.changed.borrow_mut())
    }

    /// How many cluster instances are being tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Whether nothing has been published yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.borrow().is_empty()
    }

    /// The next initial version, advanced so that two instances do not start together.
    fn next_seed(&self) -> u32 {
        let mut seed = self.seed.borrow_mut();
        // A Weyl sequence: every value distinct over the whole period, and no state but the
        // counter. The values only have to differ and be unpredictable to a client that has not
        // read them, which this achieves without a generator the node has to carry.
        *seed = seed.wrapping_add(0x9E37_79B9);
        *seed
    }
}

impl<const N: usize> DataVersionSource for DataVersions<N> {
    fn version(&self, endpoint: EndpointId, cluster: ClusterId) -> u32 {
        if let Some(entry) = self
            .entries
            .borrow()
            .iter()
            .find(|e| e.endpoint == endpoint && e.cluster == cluster)
        {
            return entry.version;
        }
        let version = self.next_seed();
        // A full table still answers — with a version that does not persist, which a client
        // reads as "changed every time". Losing the cache is a cost; handing out a stale-looking
        // match is a correctness bug.
        let _ = self.entries.borrow_mut().push(Entry {
            endpoint,
            cluster,
            version,
        });
        version
    }

    fn touch(&self, endpoint: EndpointId, cluster: ClusterId) {
        {
            // Recorded before the version moves, and deduplicated: a burst of writes to one
            // cluster between two drains is one thing for a subscriber to hear about. A full
            // list is not an error either — it means more changed than the node can name, and
            // the drain reports what it has; nothing is lost that a re-prime would not cover.
            let mut changed = self.changed.borrow_mut();
            if !changed.contains(&(endpoint, cluster)) {
                let _ = changed.push((endpoint, cluster));
            }
        }
        let mut entries = self.entries.borrow_mut();
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.endpoint == endpoint && e.cluster == cluster)
        {
            // "SHALL increment or be set (wrap) to zero if incrementing would exceed its
            // maximum value" — which is what wrapping addition is.
            entry.version = entry.version.wrapping_add(1);
        }
        // An instance nobody has read has no version to move; the one it gets when it is first
        // published will be new to every client by construction.
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_version_is_stable_until_something_changes() {
        let versions = DataVersions::<8>::new(1);
        let first = versions.version(0, 0x0006);
        assert_eq!(versions.version(0, 0x0006), first);
        versions.touch(0, 0x0006);
        assert_eq!(versions.version(0, 0x0006), first.wrapping_add(1));
    }

    /// §7.10.3 keys the version by *instance*, so the same cluster on two endpoints is two
    /// versions. Sharing one would make a client re-read an endpoint that had not changed.
    #[test]
    fn each_cluster_instance_has_its_own() {
        let versions = DataVersions::<8>::new(1);
        let a = versions.version(0, 0x0006);
        let b = versions.version(1, 0x0006);
        let c = versions.version(0, 0x0008);
        assert_ne!(a, b);
        assert_ne!(a, c);

        versions.touch(0, 0x0006);
        assert_eq!(versions.version(1, 0x0006), b, "the neighbour did not move");
        assert_eq!(versions.version(0, 0x0008), c);
    }

    /// "A cluster data version SHALL be initialized randomly when it is first published." Two
    /// nodes that started every cluster at zero would let a client keep a cache across a reboot
    /// and be wrong about it.
    #[test]
    fn versions_do_not_start_at_zero_or_together() {
        let versions = DataVersions::<8>::new(0xDEAD_BEEF);
        let a = versions.version(0, 0x0006);
        let b = versions.version(0, 0x0008);
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
    }

    /// "SHALL increment or be set (wrap) to zero if incrementing would exceed its maximum."
    #[test]
    fn the_version_wraps_rather_than_overflowing() {
        let versions = DataVersions::<8>::new(0);
        // Drive one entry to the maximum and past it.
        let _ = versions.version(0, 0x0006);
        {
            let mut entries = versions.entries.borrow_mut();
            entries[0].version = u32::MAX;
        }
        versions.touch(0, 0x0006);
        assert_eq!(versions.version(0, 0x0006), 0);
    }

    /// A full table answers rather than refusing: a read that returned no version is a read the
    /// CHIP SDK discards entirely.
    #[test]
    fn a_full_table_still_answers() {
        let versions = DataVersions::<2>::new(7);
        let _ = versions.version(0, 1);
        let _ = versions.version(0, 2);
        assert_eq!(versions.len(), 2);
        let overflow = versions.version(0, 3);
        assert_ne!(overflow, 0);
        assert_eq!(versions.len(), 2, "and does not evict a tracked instance");
    }
}
