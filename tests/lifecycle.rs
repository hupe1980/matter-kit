//! What a node owes its clusters when the node's own state changes (`im::Lifecycle`).
//!
//! §11.18.6.12 is one sentence — `RemoveFabric` "SHALL remove all associated data" — and it
//! reaches further than any other sentence in the specification: scenes, groups, bindings,
//! ICD registrations, OTA providers, TLS endpoints, group keys and access-control entries are
//! each fabric-scoped, each owned by a different cluster, and none of them visible from the
//! cluster that ran the command.
//!
//! The failure that prevents is not a leak of disused rows. Fabric indices are **reused**: an
//! entry that survives its fabric is inherited by whoever is assigned that index next, and an
//! access-control entry inherited that way is an administrator nobody granted.
//!
//! So the fan-out is a property of the handler tuple — the one place in a device that already
//! names every cluster it has — rather than a checklist in the application. These tests drive
//! it through `ClusterHandler`, exactly as a device does.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::{Cell, RefCell};

use matter_kit::acl::{Acl, Entry};
use matter_kit::clusters::access_control::AccessControl;
use matter_kit::clusters::binding::{Binding, Target};
use matter_kit::clusters::group_key_management::GroupKeyManagement;
use matter_kit::clusters::{At, Endpoints};
use matter_kit::crypto::SymmetricKey;
use matter_kit::dm::Privilege;
use matter_kit::group::{GroupKeySecurityPolicy, GroupKeySet, GroupKeys, IPK_KEY_SET};
use matter_kit::im::{ClusterHandler, InteractionContext, Lifecycle, Status};
use matter_kit::msg::{FabricIndex, NodeId};
use matter_kit::tlv::{Tag, TlvWriter};
use matter_kit::{Config, DefaultConfig};

const A: FabricIndex = FabricIndex(1);
const B: FabricIndex = FabricIndex(2);

type Entries = Acl<DefaultConfig, { DefaultConfig::ACL_ENTRIES }, 4, 3>;

/// A cluster that records what it was told, standing in for the ones whose fabric-scoped
/// state is only reachable through their own commands.
#[derive(Debug, Default)]
struct Witness {
    removed: Cell<Option<FabricIndex>>,
    expired: Cell<bool>,
    committed: Cell<bool>,
}

impl ClusterHandler for Witness {
    fn read(
        &self,
        _resolved: &matter_kit::dm::Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<(), Status> {
        Ok(())
    }

    fn on_lifecycle(&self, event: Lifecycle) {
        match event {
            Lifecycle::FabricRemoved(fabric) => self.removed.set(Some(fabric)),
            Lifecycle::FailSafeExpired { .. } => self.expired.set(true),
            Lifecycle::CommissioningComplete(_) => self.committed.set(true),
            _ => {}
        }
    }
}

impl matter_kit::clusters::Cluster for Witness {
    const ID: matter_kit::im::ClusterId = 0xFFF1_0001;
}

fn populate(
    acl: &RefCell<Entries>,
    keys: &RefCell<GroupKeys<8, 8>>,
    binding: &Binding<DefaultConfig, 8>,
) {
    for fabric in [A, B] {
        acl.borrow_mut()
            .add(
                Entry::case(fabric, Privilege::Administer)
                    .with_subject(NodeId(0x0000_0000_0001_0000 | u64::from(fabric.0)))
                    .expect("one subject"),
            )
            .expect("room for an entry");
        keys.borrow_mut()
            .write_key_set(GroupKeySet::single(
                fabric,
                IPK_KEY_SET,
                GroupKeySecurityPolicy::TrustFirst,
                SymmetricKey::new([fabric.0; 16]),
                0,
            ))
            .expect("room for a key set");
        binding
            .add(Target::unicast(fabric, NodeId(0x1234), 1))
            .expect("room for a binding");
    }
}

/// The whole point: one call, from wherever `RemoveFabric` was answered, and every cluster
/// that holds something scoped to that fabric has forgotten it.
#[test]
fn removing_a_fabric_reaches_every_cluster_in_the_handler() {
    let acl = RefCell::new(Entries::new());
    let keys = RefCell::new(GroupKeys::<8, 8>::new(4, 3));
    let binding: Binding<DefaultConfig, 8> = Binding::new(4);
    let witness = Witness::default();
    populate(&acl, &keys, &binding);

    let handler = (
        AccessControl::new(&acl),
        GroupKeyManagement::new(&keys, &()),
        &binding,
        &witness,
    );
    handler.on_lifecycle(Lifecycle::FabricRemoved(A));

    assert!(
        acl.borrow().entries().all(|e| e.fabric_index != A),
        "§9.10.5.3: an access-control entry that outlives its fabric is inherited by the \
         next holder of that index"
    );
    assert!(
        keys.borrow().key_set(A, IPK_KEY_SET).is_none(),
        "§11.2.7.4: a fabric's group keys go with the fabric — the IPK included"
    );
    assert_eq!(
        binding.len_of_fabric(A),
        0,
        "§9.6: the Binding table is fabric-scoped"
    );
    assert_eq!(
        witness.removed.get(),
        Some(A),
        "every member of the tuple is told, not just the ones the path would have routed to"
    );

    // And the fabric that is still there kept everything.
    assert!(acl.borrow().entries().any(|e| e.fabric_index == B));
    assert!(keys.borrow().key_set(B, IPK_KEY_SET).is_some());
    assert_eq!(binding.len_of_fabric(B), 1);
}

/// A node with more than one endpoint routes reads and writes by endpoint. It does not route
/// this: the fabric went away for the whole node.
#[test]
fn every_endpoint_is_told_not_just_the_one_a_path_would_name() {
    let root = Witness::default();
    let light = Witness::default();
    let handler = Endpoints((At::new(0, &root), At::new(1, &light)));

    handler.on_lifecycle(Lifecycle::FabricRemoved(A));

    assert_eq!(root.removed.get(), Some(A));
    assert_eq!(light.removed.get(), Some(A));
}

/// The other two events reach the same way, and each reaches every cluster.
#[test]
fn the_fail_safe_and_commissioning_complete_reach_every_cluster() {
    let one = Witness::default();
    let two = Witness::default();
    let handler = (&one, &two);

    handler.on_lifecycle(Lifecycle::FailSafeExpired { fabric: Some(A) });
    assert!(one.expired.get() && two.expired.get());

    handler.on_lifecycle(Lifecycle::CommissioningComplete(A));
    assert!(one.committed.get() && two.committed.get());
}

/// Most clusters have nothing scoped to a fabric and stage nothing under the fail-safe. The
/// default does nothing, so only the clusters that do carry any code at all.
#[test]
fn a_cluster_without_fabric_scoped_state_needs_no_implementation() {
    struct Stateless;
    impl ClusterHandler for Stateless {
        fn read(
            &self,
            _resolved: &matter_kit::dm::Resolved<'_>,
            _ctx: &InteractionContext<'_>,
            _w: &mut TlvWriter<'_>,
            _tag: Tag,
        ) -> Result<(), Status> {
            Ok(())
        }
    }
    Stateless.on_lifecycle(Lifecycle::FabricRemoved(A));
    Stateless.on_lifecycle(Lifecycle::FailSafeExpired { fabric: None });
    Stateless.on_lifecycle(Lifecycle::CommissioningComplete(A));
}
