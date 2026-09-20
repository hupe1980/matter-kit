//! "Provisional means off" — the ninth rule, checked rather than asserted.
//!
//! A provisional mechanism is one the Alliance has said may change before it is certifiable, so
//! a node that serves one by accident has a defect it discovers at a test laboratory. A
//! certifiable build is therefore the *default* build, and serving a provisional element is a
//! deliberate act spelled `--features provisional`.
//!
//! Two mechanisms, because one is not enough. `Cluster::validate` reports a `P` element that a
//! build without the feature furnishes — most provisional elements sit inside a cluster that is
//! otherwise certifiable, so the Cargo feature has nothing to gate. And **Core §2.13 is not the
//! only list**: the Application Cluster and Device Library specifications keep their own, in
//! prose, and the data model does not always mark what a paragraph names.

#![cfg(feature = "std")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use matter_kit::dm::spec::{Defect, PROVISIONAL_CLUSTERS};

/// Every cluster the Application Cluster specification's own list names is in the table, with
/// the id the generated library gives it.
#[test]
fn the_prose_list_is_carried_by_cluster_id() {
    let ids: Vec<_> = PROVISIONAL_CLUSTERS.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&0x050F), "Content Control");
    assert!(ids.contains(&0x0064), "Temperature Alarm");
    assert!(ids.contains(&0x0431), "Ambient Context Sensing");
    assert_eq!(
        ids.len(),
        3,
        "a list that grows in the specification and not here is the defect this exists to stop"
    );
    for (id, citation) in PROVISIONAL_CLUSTERS {
        assert!(
            citation.contains('§'),
            "cluster {id:#06x} is on the list with no sentence behind it"
        );
    }
}

/// The generated ids and the table agree, so an uplift that renumbers a cluster is a failing
/// test rather than a silently empty check.
#[test]
fn the_table_names_clusters_the_library_actually_has() {
    use matter_kit::clusters::generated;
    assert_eq!(generated::content_control::ID, 0x050F);
    assert_eq!(generated::temperature_alarm::ID, 0x0064);
    assert_eq!(generated::ambient_context_sensing::ID, 0x0431);
}

/// A device that furnishes a provisional cluster is refused on a build that did not ask for one,
/// and accepted on a build that did.
#[test]
fn a_provisional_cluster_is_a_defect_unless_the_build_asked_for_it() {
    use matter_kit::clusters::generated::temperature_alarm;
    use matter_kit::dm::ClusterDescriptor;

    // A device that serves the cluster's mandatory attribute and nothing else.
    let attributes = &[matter_kit::dm::AttributeDescriptor::read_only(0x0000)];
    let descriptor = ClusterDescriptor {
        id: temperature_alarm::ID,
        revision: temperature_alarm::REVISION,
        feature_map: 0,
        attributes,
        accepted_commands: &[],
        generated_commands: &[],
        events: &[],
    };

    let mut defects = Vec::new();
    temperature_alarm::CLUSTER.validate(&descriptor, |d| defects.push(d));

    let provisional = defects
        .iter()
        .filter(|d| matches!(d, Defect::Provisional(_)))
        .count();

    if cfg!(feature = "provisional") {
        assert_eq!(
            provisional, 0,
            "the build asked for provisional mechanisms, so serving one is a choice"
        );
    } else {
        assert!(
            provisional > 0,
            "App §1.1 calls Temperature Alarm provisional, and the data model does not mark it — \
             so nothing but the prose list can catch this"
        );
    }
}

/// And a cluster nobody calls provisional is still clean, so the check has not been bought by
/// refusing everything.
#[test]
fn an_ordinary_cluster_reports_no_provisional_defect() {
    use matter_kit::clusters::generated::on_off;
    use matter_kit::dm::ClusterDescriptor;

    // The base cluster with no features: `OnOff` alone, and its three commands.
    let attributes = &[matter_kit::dm::AttributeDescriptor::read_only(0x0000)];
    let descriptor = ClusterDescriptor {
        id: on_off::ID,
        revision: on_off::REVISION,
        feature_map: 0,
        attributes,
        accepted_commands: &[
            matter_kit::dm::CommandDescriptor::new(0x00),
            matter_kit::dm::CommandDescriptor::new(0x01),
            matter_kit::dm::CommandDescriptor::new(0x02),
        ],
        generated_commands: &[],
        events: &[],
    };

    let mut defects = Vec::new();
    on_off::CLUSTER.validate(&descriptor, |d| defects.push(d));
    assert!(
        !defects.iter().any(|d| matches!(d, Defect::Provisional(_))),
        "On/Off is on no provisional list: {defects:?}"
    );
}
