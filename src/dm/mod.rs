//! The data model: what a node *has* (Core ch. 7).
//!
//! A node is a tree — endpoints, each holding cluster instances, each holding attributes,
//! commands and events. This module is that tree's shape and the rules for addressing it;
//! [`im`](crate::im) is how the shape is talked about on the wire.
//!
//! | | |
//! |---|---|
//! | [`access`] | §7.6's privileges and access qualities |
//! | [`meta`] | §7.10–7.12's descriptors: what a cluster is |
//! | [`global`] | §7.13's five self-description attributes, synthesised |
//! | [`node`] | the tree, and §8.2.1.6's wildcard expansion |
//!
//! # The shape lives in flash
//!
//! Every descriptor here is `Copy` and borrows `&'static` slices. A device's whole data
//! model is `const` data the application points at; nothing is allocated, and adding an
//! endpoint costs a slice entry rather than a heap node. That also means the lookups
//! binary-search, which is why [`Node::validate`] exists: an unsorted `const` slice does not
//! fail loudly, it silently fails to find things.
//!
//! [`events`] is the exception to "metadata only": §7.14's event store holds *records*, since
//! an event has no attribute to live in and exists only as something that happened.
//!
//! # What is not here yet
//!
//! Cluster *state* and the handlers that serve it — reading an attribute's value, running a
//! command — along with conformance validation (§7.3) and atomic writes (§7.15). This module
//! says what exists; making it answer is the next layer.

pub mod access;
pub mod conformance;
pub mod device;
pub mod events;
pub mod global;
pub mod mei;
pub mod meta;
pub mod node;
pub mod spec;
pub mod version;

pub use access::{Access, AccessQualities, Privilege};
pub use conformance::{Clause, Condition, Conform, Conformance, Supports};
pub use meta::{
    AttributeDescriptor, AttributeQualities, ClusterDescriptor, CommandDescriptor, DeviceType,
    EventDescriptor, EventPriority, Reporting,
};
pub use node::{
    Endpoint, Expand, ExpandCommands, ExpandCursor, Malformed, Missing, MissingCommand, Node,
    Resolved, ResolvedCommand, ResolvedEvent,
};
pub use version::{DataVersionSource, DataVersions};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::im::{AttributePath, Status};

    // A node shaped like a two-endpoint light: a root node endpoint with one utility
    // cluster, and an application endpoint with two.
    const ON_OFF_ATTRS: &[AttributeDescriptor] = &[
        AttributeDescriptor::read_only(0x0000),
        AttributeDescriptor::read_write(0x4000),
    ];
    const LEVEL_ATTRS: &[AttributeDescriptor] = &[AttributeDescriptor::read_only(0x0000)];
    const BASIC_ATTRS: &[AttributeDescriptor] = &[
        AttributeDescriptor::read_only(0x0001),
        AttributeDescriptor::read_only(0x0002),
    ];
    const CMDS: &[CommandDescriptor] =
        &[CommandDescriptor::new(0x00), CommandDescriptor::new(0x01)];

    const fn cluster(
        id: crate::im::ClusterId,
        attributes: &'static [AttributeDescriptor],
    ) -> ClusterDescriptor<'static> {
        ClusterDescriptor {
            id,
            revision: 1,
            feature_map: 0,
            attributes,
            accepted_commands: CMDS,
            generated_commands: &[],
            events: &[],
        }
    }

    const EP0: &[ClusterDescriptor<'static>] = &[cluster(0x0028, BASIC_ATTRS)];
    const EP1: &[ClusterDescriptor<'static>] =
        &[cluster(0x0006, ON_OFF_ATTRS), cluster(0x0008, LEVEL_ATTRS)];
    const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, EP0), Endpoint::new(1, EP1)];

    fn node() -> Node<'static> {
        Node::new(ENDPOINTS)
    }

    /// How many attributes a cluster has once §7.13's globals are counted.
    const GLOBALS: usize = 5;

    #[test]
    fn a_well_formed_node_validates() {
        node().validate().expect("well formed");
    }

    #[test]
    fn unsorted_slices_are_caught_rather_than_silently_missing() {
        // Every lookup binary-searches, so an unsorted slice does not fail loudly — a
        // cluster simply appears not to exist. That is the failure this check exists for.
        const OUT_OF_ORDER: &[Endpoint<'static>] = &[Endpoint::new(1, EP1), Endpoint::new(0, EP0)];
        assert_eq!(
            Node::new(OUT_OF_ORDER).validate(),
            Err(Malformed::Endpoints)
        );

        const BAD_CLUSTERS: &[ClusterDescriptor<'static>] =
            &[cluster(0x0008, LEVEL_ATTRS), cluster(0x0006, ON_OFF_ATTRS)];
        const BAD_EP: &[Endpoint<'static>] = &[Endpoint::new(0, BAD_CLUSTERS)];
        assert_eq!(
            Node::new(BAD_EP).validate(),
            Err(Malformed::Clusters { endpoint: 0 })
        );
    }

    #[test]
    fn a_whole_node_wildcard_expands_to_everything() {
        // §10.6.2.5's `Path = [[ ]]`: "all attributes in all clusters on the node".
        let expanded: heapless::Vec<_, 64> = node().expand(&AttributePath::wildcard()).collect();
        // Basic(2) + OnOff(2) + Level(1) own attributes, each cluster plus its five globals.
        let expected = (2 + GLOBALS) + (2 + GLOBALS) + (1 + GLOBALS);
        assert_eq!(expanded.len(), expected);
        // Every result is a concrete path.
        assert!(expanded.iter().all(|r| !r.path().has_wildcard()));
    }

    #[test]
    fn an_endpoint_wildcard_stays_on_that_endpoint() {
        let path = AttributePath {
            endpoint: Some(1),
            ..AttributePath::wildcard()
        };
        let expanded: heapless::Vec<_, 64> = node().expand(&path).collect();
        assert_eq!(expanded.len(), (2 + GLOBALS) + (1 + GLOBALS));
        assert!(expanded.iter().all(|r| r.endpoint == 1));
    }

    #[test]
    fn a_cluster_wildcard_crosses_endpoints() {
        // §8.9.2.6's "Wildcard endpoint, Specific cluster": every instance of one cluster,
        // wherever it is. A client reading Descriptor across a bridge does exactly this.
        let path = AttributePath {
            cluster: Some(0x0006),
            ..AttributePath::wildcard()
        };
        let expanded: heapless::Vec<_, 64> = node().expand(&path).collect();
        assert_eq!(expanded.len(), 2 + GLOBALS);
        assert!(expanded.iter().all(|r| r.cluster.id == 0x0006));
    }

    #[test]
    fn a_global_attribute_across_a_wildcard_cluster_hits_every_cluster() {
        // §8.9.2.6's "Wildcard cluster, Specific attribute … (e.g. ClusterRevision)" — the
        // shape a commissioner uses to enumerate a node in one round trip.
        let path = AttributePath {
            attribute: Some(global::CLUSTER_REVISION),
            ..AttributePath::wildcard()
        };
        let expanded: heapless::Vec<_, 64> = node().expand(&path).collect();
        assert_eq!(expanded.len(), 3, "one per cluster instance");
        assert!(
            expanded
                .iter()
                .all(|r| r.attribute == global::CLUSTER_REVISION)
        );
    }

    #[test]
    fn expansion_yields_the_globals_as_well_as_the_clusters_own() {
        let path = AttributePath::cluster(1, 0x0008);
        let ids: heapless::Vec<_, 16> = node().expand(&path).map(|r| r.attribute).collect();
        assert_eq!(
            ids.as_slice(),
            &[
                0x0000,
                global::GENERATED_COMMAND_LIST,
                global::ACCEPTED_COMMAND_LIST,
                global::ATTRIBUTE_LIST,
                global::FEATURE_MAP,
                global::CLUSTER_REVISION,
            ]
        );
    }

    #[test]
    fn a_wildcard_naming_nothing_expands_to_nothing() {
        // Not an error: §8.4.3.2 step 2 says "If no error-free existent paths remain, then
        // AttributeRequests are considered empty", so an empty expansion is a valid outcome.
        let path = AttributePath {
            endpoint: Some(9),
            ..AttributePath::wildcard()
        };
        assert_eq!(node().expand(&path).count(), 0);

        let path = AttributePath::cluster(1, 0xDEAD);
        assert_eq!(node().expand(&path).count(), 0);
    }

    #[test]
    fn a_concrete_path_says_which_level_is_missing() {
        // §8.4.3.2 needs three distinct statuses, so "not found" is not a good enough answer:
        // a client tells a missing endpoint from a missing feature on one that is there.
        let node = node();
        assert_eq!(node.resolve(9, 0x0006, 0).unwrap_err(), Missing::Endpoint);
        assert_eq!(node.resolve(1, 0xDEAD, 0).unwrap_err(), Missing::Cluster);
        assert_eq!(
            node.resolve(1, 0x0006, 0xDEAD).unwrap_err(),
            Missing::Attribute
        );

        assert_eq!(Missing::Endpoint.status(), Status::UnsupportedEndpoint);
        assert_eq!(Missing::Cluster.status(), Status::UnsupportedCluster);
        assert_eq!(Missing::Attribute.status(), Status::UnsupportedAttribute);
    }

    #[test]
    fn a_concrete_path_to_a_global_resolves() {
        // The globals are not in the descriptor's slice, so a lookup that only searched it
        // would report UNSUPPORTED_ATTRIBUTE for an attribute every cluster must serve.
        let resolved = node()
            .resolve(1, 0x0006, global::CLUSTER_REVISION)
            .expect("globals resolve");
        assert_eq!(resolved.attribute, global::CLUSTER_REVISION);
        assert_eq!(resolved.cluster.id, 0x0006);
    }

    #[test]
    fn the_deprecated_event_list_does_not_resolve() {
        // It is reserved but not served, so a client asking for it gets
        // UNSUPPORTED_ATTRIBUTE rather than an empty list.
        assert_eq!(
            node().resolve(1, 0x0006, global::EVENT_LIST).unwrap_err(),
            Missing::Attribute
        );
    }

    #[test]
    fn expansion_does_not_check_access() {
        // §8.2.1.6: "This process does not check access qualities, such as read or write
        // access, privileges, or fabric qualities." A write-only attribute still expands;
        // it is the caller that discards it.
        const WRITE_ONLY: &[AttributeDescriptor] = &[AttributeDescriptor::read_only(0x0000)
            .with_access(Access::write_only(Privilege::Manage))];
        const CL: &[ClusterDescriptor<'static>] = &[cluster(0x0006, WRITE_ONLY)];
        const EPS: &[Endpoint<'static>] = &[Endpoint::new(0, CL)];
        let node = Node::new(EPS);
        let expanded: heapless::Vec<_, 64> = node.expand(&AttributePath::wildcard()).collect();
        assert_eq!(expanded.len(), 1 + GLOBALS);
        assert!(
            expanded.iter().any(|r| r.attribute == 0x0000),
            "the unreadable attribute is still expanded"
        );
    }
}
