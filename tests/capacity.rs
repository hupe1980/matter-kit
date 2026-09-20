//! A capacity is declared once, on the table, and every number derived from it comes from there.
//!
//! Stable Rust cannot write `Vec<T, { C::SESSIONS }>`, so a table's capacity is its own const
//! parameter and `Config` carries only the per-fabric shares a capacity cannot tell you. Three
//! things follow, and this file checks the two that reach the wire:
//!
//! * a per-fabric quota is enforced against the table that has to honour it;
//! * §11.1.4.4's `CapabilityMinima`, §9.10.6.7 and §11.2.6.x report "the **actual**" figure,
//!   which only the table knows.
//!
//! The third — that a table too small for the node's promises does not compile — cannot be
//! tested from here, because a test that fails to build is not a test. It is a `compile_fail`
//! doctest in `src/lib.rs`.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use matter_kit::acl::Acl;
use matter_kit::clusters::basic_information::CapabilityMinima;
use matter_kit::config::{Capacity, Config, SubscriptionCapacity};
use matter_kit::group::GroupKeys;
use matter_kit::im::SubscriptionTable;
use matter_kit::session::SessionTable;
use matter_kit::{DefaultConfig, fabric::FabricTable};

/// A node that promises more per fabric than the specification's floor, to prove the checks
/// follow the policy rather than a constant.
struct Generous;
impl Config for Generous {
    const FABRICS: usize = 6;
    const SUBSCRIPTIONS_PER_FABRIC: usize = 5;
    const ACL_ENTRIES_PER_FABRIC: usize = 6;
    const GROUPS_PER_FABRIC: usize = 5;
    const GROUP_KEYS_PER_FABRIC: usize = 4;
}

#[test]
fn every_table_publishes_the_capacity_it_actually_has() {
    assert_eq!(<SessionTable<DefaultConfig, 16> as Capacity>::TOTAL, 16);
    assert_eq!(<Acl<DefaultConfig> as Capacity>::TOTAL, 20);
    assert_eq!(<SubscriptionTable<DefaultConfig> as Capacity>::TOTAL, 15);
    assert_eq!(<FabricTable<DefaultConfig> as Capacity>::TOTAL, 5);
    assert_eq!(<GroupKeys<DefaultConfig> as Capacity>::TOTAL, 15);
}

#[test]
fn a_per_fabric_share_is_the_policy_the_node_advertises() {
    // The share is `Config`'s, because no table length can tell you how it is meant to be
    // divided — that is the one thing `Config` is for.
    assert_eq!(
        <Acl<DefaultConfig> as Capacity>::PER_FABRIC,
        DefaultConfig::ACL_ENTRIES_PER_FABRIC
    );
    assert_eq!(
        <SubscriptionTable<DefaultConfig> as Capacity>::PER_FABRIC,
        DefaultConfig::SUBSCRIPTIONS_PER_FABRIC
    );
    // A session table has no quota, so its share is the honest division.
    assert_eq!(<SessionTable<DefaultConfig, 16> as Capacity>::PER_FABRIC, 3);
    assert_eq!(
        <SessionTable<DefaultConfig, 50> as Capacity>::PER_FABRIC,
        10
    );
}

#[test]
fn capability_minima_is_the_actual_number_and_never_a_floor() {
    type Sessions = SessionTable<DefaultConfig, 16>;
    type Subs = SubscriptionTable<DefaultConfig>;
    let minima = CapabilityMinima::from_tables::<DefaultConfig, Sessions, Subs>();

    // 16 sessions over 5 fabrics is 3 each, with one spare that is nobody's guarantee.
    assert_eq!(minima.case_sessions_per_fabric, 3);
    assert_eq!(minima.subscriptions_per_fabric, 3);
    assert_eq!(minima.subscribe_paths, Some(3));
    assert_eq!(minima.read_paths, Some(DefaultConfig::READ_PATHS as u16));

    // A bigger table moves the attribute, which is the property that was missing: the number
    // followed `Config` before, and `Config` cannot size a table.
    type Big = SessionTable<DefaultConfig, 40>;
    let bigger = CapabilityMinima::from_tables::<DefaultConfig, Big, Subs>();
    assert_eq!(bigger.case_sessions_per_fabric, 8);
}

#[test]
fn a_generous_policy_is_carried_all_the_way_to_the_advertised_numbers() {
    type Sessions = SessionTable<Generous, 24>; // 6 fabrics × 4
    type Subs = SubscriptionTable<Generous, 30, 4>; // 6 × 5, four paths each
    let minima = CapabilityMinima::from_tables::<Generous, Sessions, Subs>();
    assert_eq!(minima.case_sessions_per_fabric, 4);
    assert_eq!(minima.subscriptions_per_fabric, 5);
    assert_eq!(minima.subscribe_paths, Some(4));

    assert_eq!(<Acl<Generous, 36, 4, 3> as Capacity>::PER_FABRIC, 6);
    assert_eq!(<GroupKeys<Generous, 24, 30> as Capacity>::PER_FABRIC, 4);
    assert_eq!(<Subs as SubscriptionCapacity>::PATHS, 4);
}

#[test]
fn the_acl_quota_is_the_one_the_cluster_advertises() {
    // §9.10.6.7 is answered from `Acl`'s `PER_FABRIC`, and `Acl::insert` enforces the same
    // number. Before, the attribute read a `Config` constant and the list held `N`, so the two
    // agreed only by coincidence.
    let acl: Acl<DefaultConfig> = Acl::new();
    let advertised = <Acl<DefaultConfig> as Capacity>::PER_FABRIC;
    assert_eq!(advertised, 4);
    // The list can hold every fabric's share at once, which is what `Acl::CHECK` proves.
    const {
        assert!(
            <Acl<DefaultConfig> as Capacity>::TOTAL
                >= <Acl<DefaultConfig> as Capacity>::PER_FABRIC * DefaultConfig::FABRICS
        );
    }
    assert!(acl.is_empty());
}

/// §9.16.6.6's `ClientsSupportedPerFabric` is "the maximum number of entries that the server is
/// able to store **for each fabric**", so the table needs room for all of them.
#[test]
fn the_icd_registration_table_holds_every_fabrics_share() {
    use matter_kit::clusters::icd_management::IcdManagement;
    let _: IcdManagement<'_, DefaultConfig, 5> =
        IcdManagement::new(Default::default(), Default::default());
    const {
        assert!(5 >= DefaultConfig::ICD_CLIENTS_PER_FABRIC * DefaultConfig::FABRICS);
    }
}

#[test]
fn a_group_key_table_holds_every_fabrics_share() {
    let keys: GroupKeys<DefaultConfig> = GroupKeys::new();
    assert_eq!(
        keys.max_key_sets_per_fabric(),
        DefaultConfig::GROUP_KEYS_PER_FABRIC
    );
    assert_eq!(
        keys.max_groups_per_fabric(),
        DefaultConfig::GROUPS_PER_FABRIC
    );
    const {
        assert!(
            <GroupKeys<DefaultConfig> as Capacity>::TOTAL
                >= DefaultConfig::GROUP_KEYS_PER_FABRIC * DefaultConfig::FABRICS
        );
    }
}
