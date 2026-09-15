//! A node's tree of endpoints and clusters, and what a wildcard path expands to
//! (Core §7.2, §8.2.1.6).
//!
//! A node is a fixed set of endpoints; each endpoint is a fixed set of cluster instances.
//! "Fixed" is the point: [`Node`] borrows slices of `const` descriptors rather than owning
//! anything, so the whole shape of a device lives in flash and costs no RAM.
//!
//! # Expansion is the whole of §8.2.1.6
//!
//! > Each path in the list that is a Wildcard Path SHALL be expanded into a complete list of
//! > existent paths. This is done by generating all permutations where the wildcarded
//! > elements are replaced with existent elements.
//!
//! and, in the same section, the sentence that decides the shape of this module:
//!
//! > This process does not check access qualities, such as read or write access, privileges,
//! > or fabric qualities.
//!
//! So [`Node::expand`] yields every path that *exists*, and says nothing about whether the
//! caller may have it. Access is applied afterwards, and §8.4.3.2 is precise about why the
//! order matters: a **concrete** path that fails a check produces an `AttributeStatusIB`
//! naming the failure, while an **expanded** path that fails one is "discarded" silently. A
//! client that asked for a specific attribute learns it may not have it; a client that asked
//! for everything simply does not see it. Merging the two would leak the shape of a node to
//! a subject with no privilege over it.

use crate::dm::meta::ClusterDescriptor;
use crate::im::{AttributeId, AttributePath, ClusterId, EndpointId};

/// One endpoint: a set of cluster instances (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint<'a> {
    /// The endpoint id. Endpoint 0 is the root node (§9.2).
    pub id: EndpointId,
    /// The clusters on it, **sorted by cluster id**.
    pub clusters: &'a [ClusterDescriptor<'a>],
    /// The device types it conforms to (§9.5.6.1).
    ///
    /// §9.5 requires "at least one device type entry", and two layers read it: the Descriptor
    /// cluster publishes it as `DeviceTypeList`, and §6.6.6.2's access control matches an ACL
    /// target's `DeviceType` against it. Keeping it here is what stops those two from
    /// describing different devices.
    pub device_types: &'a [crate::dm::meta::DeviceType],
    /// `ClientList` (§9.5.6.3) — the clusters this endpoint speaks *as a client*.
    ///
    /// Not derivable from `clusters`: a [`ClusterDescriptor`] describes a *server* instance,
    /// and a client binding has no descriptor to be found in — a switch that controls a light
    /// is a client of On/Off and a server of nothing much.
    ///
    /// It lives here rather than on the Descriptor cluster for the same reason
    /// `device_types` does: two layers read it, the Descriptor cluster publishing
    /// `ClientList` and §9.2's device-type check demanding it, and a device type may require a
    /// cluster on the client side — §6.1's On/Off Light Switch requires On/Off as a client and
    /// as nothing else, which is the only thing that tells it apart from a light.
    pub clients: &'a [ClusterId],
}

impl<'a> Endpoint<'a> {
    /// An endpoint with clusters and no device types yet.
    #[must_use]
    pub const fn new(id: EndpointId, clusters: &'a [ClusterDescriptor<'a>]) -> Self {
        Self {
            id,
            clusters,
            device_types: &[],
            clients: &[],
        }
    }

    /// The same endpoint, declaring the clusters it speaks as a client (§9.5.6.3).
    #[must_use]
    pub const fn with_clients(mut self, clients: &'a [ClusterId]) -> Self {
        self.clients = clients;
        self
    }

    /// The same endpoint, declaring the device types of §9.5.6.1.
    #[must_use]
    pub const fn with_device_types(
        mut self,
        device_types: &'a [crate::dm::meta::DeviceType],
    ) -> Self {
        self.device_types = device_types;
        self
    }

    /// Whether this endpoint conforms to `device_type`.
    ///
    /// §6.6.6.2's `endpoint_contains_device_type`, which decides whether an ACL target that
    /// names a device type rather than an endpoint applies here.
    #[must_use]
    pub fn has_device_type(&self, device_type: u32) -> bool {
        self.device_types
            .iter()
            .any(|d| d.device_type == device_type)
    }
}

impl<'a> Endpoint<'a> {
    /// The descriptor for a cluster id on this endpoint.
    #[must_use]
    pub fn cluster(&self, id: ClusterId) -> Option<&'a ClusterDescriptor<'a>> {
        self.clusters
            .binary_search_by_key(&id, |c| c.id)
            .ok()
            .and_then(|index| self.clusters.get(index))
    }
}

/// A node's data model: its endpoints and everything on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node<'a> {
    /// The endpoints, **sorted by id**.
    pub endpoints: &'a [Endpoint<'a>],
}

/// Why a node's descriptors are not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    /// The endpoints are not sorted by id, or two share one.
    Endpoints,
    /// An endpoint's clusters are not sorted by id, or two share one.
    Clusters {
        /// Which endpoint.
        endpoint: EndpointId,
    },
    /// A cluster's attributes, commands or events are unsorted, or it declares one of
    /// §7.13's global attribute ids as its own.
    Cluster {
        /// Which endpoint.
        endpoint: EndpointId,
        /// Which cluster.
        cluster: ClusterId,
    },
}

/// One path that exists on a node, with the descriptors it resolves to.
#[derive(Debug, Clone, Copy)]
pub struct Resolved<'a> {
    /// The endpoint.
    pub endpoint: EndpointId,
    /// The cluster's descriptor.
    pub cluster: &'a ClusterDescriptor<'a>,
    /// The attribute id.
    pub attribute: AttributeId,
}

impl Resolved<'_> {
    /// The concrete path this resolves to, for putting in a report.
    #[must_use]
    pub const fn path(&self) -> AttributePath {
        AttributePath::attribute(self.endpoint, self.cluster.id, self.attribute)
    }
}

/// One command that exists on a node, with the descriptors it resolves to.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedCommand<'a> {
    /// The endpoint.
    pub endpoint: EndpointId,
    /// The cluster's descriptor.
    pub cluster: &'a ClusterDescriptor<'a>,
    /// The command's descriptor.
    pub command: crate::dm::meta::CommandDescriptor,
}

impl ResolvedCommand<'_> {
    /// The concrete path this resolves to.
    #[must_use]
    pub const fn path(&self) -> crate::im::CommandPath {
        crate::im::CommandPath::command(self.endpoint, self.cluster.id, self.command.id)
    }
}

impl<'a> Node<'a> {
    /// A node over a slice of endpoints.
    #[must_use]
    pub const fn new(endpoints: &'a [Endpoint<'a>]) -> Self {
        Self { endpoints }
    }

    /// The endpoint with this id.
    #[must_use]
    pub fn endpoint(&self, id: EndpointId) -> Option<&'a Endpoint<'a>> {
        self.endpoints
            .binary_search_by_key(&id, |e| e.id)
            .ok()
            .and_then(|index| self.endpoints.get(index))
    }

    /// The cluster at an endpoint.
    #[must_use]
    pub fn cluster(
        &self,
        endpoint: EndpointId,
        cluster: ClusterId,
    ) -> Option<&'a ClusterDescriptor<'a>> {
        self.endpoint(endpoint)?.cluster(cluster)
    }

    /// Checks every ordering invariant the lookups depend on.
    ///
    /// Everything here binary-searches, so an unsorted slice does not fail loudly — it
    /// silently fails to find things, which on a device looks like a cluster that is simply
    /// not there. `const` slices cannot be checked by the compiler today, so this is called
    /// once at start-up instead.
    pub fn validate(&self) -> Result<(), Malformed> {
        if !self
            .endpoints
            .windows(2)
            .all(|w| matches!(w, [a, b] if a.id < b.id))
        {
            return Err(Malformed::Endpoints);
        }
        for endpoint in self.endpoints {
            if !endpoint
                .clusters
                .windows(2)
                .all(|w| matches!(w, [a, b] if a.id < b.id))
            {
                return Err(Malformed::Clusters {
                    endpoint: endpoint.id,
                });
            }
            for cluster in endpoint.clusters {
                if !cluster.is_well_formed() {
                    return Err(Malformed::Cluster {
                        endpoint: endpoint.id,
                        cluster: cluster.id,
                    });
                }
            }
        }
        Ok(())
    }

    /// Expands a request path into every existent path it names (§8.2.1.6).
    ///
    /// **No access check happens here.** §8.2.1.6: "This process does not check access
    /// qualities, such as read or write access, privileges, or fabric qualities." The caller
    /// applies those, and §8.4.3.2 decides what to do when one fails — which differs between
    /// a concrete path and an expanded one.
    ///
    /// A concrete path that does not exist yields nothing; the caller must notice that and
    /// produce the right status, which is why [`Node::resolve`] exists beside this.
    #[must_use]
    pub fn expand(&self, path: &AttributePath) -> Expand<'a> {
        self.expand_from(path, ExpandCursor::START)
    }

    /// The same expansion, resumed at `cursor`.
    ///
    /// Core §10.2.3 splits a report "into multiple messages at logical boundaries due to the
    /// size limitations imposed by IPv6 for UDP packets", and each message after the first
    /// has to start where the last one stopped. A cursor from [`Expand::cursor`] is that
    /// place.
    #[must_use]
    pub fn expand_from(&self, path: &AttributePath, cursor: ExpandCursor) -> Expand<'a> {
        Expand {
            endpoints: self.endpoints,
            endpoint_filter: path.endpoint,
            cluster_filter: path.cluster,
            attribute_filter: path.attribute,
            endpoint_index: cursor.endpoint,
            cluster_index: cursor.cluster,
            attribute_index: cursor.attribute,
        }
    }

    /// Resolves a concrete path, saying precisely which part of it does not exist.
    ///
    /// §8.4.3.2 requires a distinct status for each level — `UNSUPPORTED_ENDPOINT`,
    /// `UNSUPPORTED_CLUSTER`, `UNSUPPORTED_ATTRIBUTE` — so "not found" is not a good enough
    /// answer: a client uses the difference to tell a missing endpoint from a missing
    /// feature on one that is there.
    pub fn resolve(
        &self,
        endpoint: EndpointId,
        cluster: ClusterId,
        attribute: AttributeId,
    ) -> Result<Resolved<'a>, Missing> {
        let Some(endpoint_ref) = self.endpoint(endpoint) else {
            return Err(Missing::Endpoint);
        };
        let Some(cluster_ref) = endpoint_ref.cluster(cluster) else {
            return Err(Missing::Cluster);
        };
        if cluster_ref.attribute(attribute).is_none() {
            return Err(Missing::Attribute);
        }
        Ok(Resolved {
            endpoint,
            cluster: cluster_ref,
            attribute,
        })
    }
}

/// One event that exists on a node, with the descriptors it resolves to.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedEvent<'a> {
    /// The endpoint.
    pub endpoint: EndpointId,
    /// The cluster's descriptor.
    pub cluster: &'a ClusterDescriptor<'a>,
    /// The event's descriptor — its access and its priority.
    pub event: crate::dm::EventDescriptor,
}

impl ResolvedEvent<'_> {
    /// The concrete path this resolves to, for putting in a report.
    #[must_use]
    pub const fn path(&self) -> crate::im::EventPath {
        crate::im::EventPath {
            node: None,
            endpoint: Some(self.endpoint),
            cluster: Some(self.cluster.id),
            event: Some(self.event.id),
            is_urgent: None,
        }
    }
}

/// Which level of a concrete command path was not found (§8.8.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MissingCommand {
    /// "the path indicates an endpoint that is unsupported".
    Endpoint,
    /// "the path indicates a cluster that is unsupported".
    Cluster,
    /// "the path indicates a command that is unsupported".
    Command,
}

impl MissingCommand {
    /// The status §8.8.2.3 step b.ii pairs with this level.
    #[must_use]
    pub const fn status(self) -> crate::im::Status {
        match self {
            Self::Endpoint => crate::im::Status::UnsupportedEndpoint,
            Self::Cluster => crate::im::Status::UnsupportedCluster,
            Self::Command => crate::im::Status::UnsupportedCommand,
        }
    }
}

/// Which level of a concrete path was not found (§8.4.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Missing {
    /// "the path indicates an endpoint that is unsupported".
    Endpoint,
    /// "the path indicates a cluster that is unsupported".
    Cluster,
    /// "the path indicates an attribute … that is unsupported".
    Attribute,
}

impl Missing {
    /// The status §8.4.3.2 pairs with this level.
    #[must_use]
    pub const fn status(self) -> crate::im::Status {
        match self {
            Self::Endpoint => crate::im::Status::UnsupportedEndpoint,
            Self::Cluster => crate::im::Status::UnsupportedCluster,
            Self::Attribute => crate::im::Status::UnsupportedAttribute,
        }
    }
}

impl<'a> Node<'a> {
    /// Resolves a concrete event path, the way [`Node::resolve`] does an attribute.
    ///
    /// §8.4.3.3's event paths are validated exactly like attribute paths: the endpoint, then
    /// the cluster, then the event — each level a different answer, because a client that asked
    /// for an endpoint this node does not have has made a different mistake from one that asked
    /// for an event the cluster does not define.
    pub fn resolve_event(
        &self,
        endpoint: EndpointId,
        cluster: ClusterId,
        event: crate::im::EventId,
    ) -> Result<ResolvedEvent<'a>, Missing> {
        let Some(endpoint_ref) = self.endpoint(endpoint) else {
            return Err(Missing::Endpoint);
        };
        let Some(cluster_ref) = endpoint_ref.cluster(cluster) else {
            return Err(Missing::Cluster);
        };
        let Some(descriptor) = cluster_ref.events.iter().find(|e| e.id == event) else {
            // `Missing::Attribute` is the leaf level, whatever the leaf is called.
            return Err(Missing::Attribute);
        };
        Ok(ResolvedEvent {
            endpoint,
            cluster: cluster_ref,
            event: *descriptor,
        })
    }

    /// Resolves a concrete command path, saying which level is missing (§8.8.2.3 step b.ii).
    pub fn resolve_command(
        &self,
        endpoint: EndpointId,
        cluster: crate::im::ClusterId,
        command: crate::im::CommandId,
    ) -> Result<ResolvedCommand<'a>, MissingCommand> {
        let Some(endpoint_ref) = self.endpoint(endpoint) else {
            return Err(MissingCommand::Endpoint);
        };
        let Some(cluster_ref) = endpoint_ref.cluster(cluster) else {
            return Err(MissingCommand::Cluster);
        };
        let Some(descriptor) = cluster_ref.accepted_command(command) else {
            return Err(MissingCommand::Command);
        };
        Ok(ResolvedCommand {
            endpoint,
            cluster: cluster_ref,
            command: descriptor,
        })
    }

    /// Expands a command path into every existent command it names (§8.2.1.6).
    ///
    /// §8.8 permits a wildcard here — "Invoke Request action SHALL support group paths and
    /// SHOULD support wildcard paths" — but only when the request carries exactly one
    /// command; §8.8.2.2 step 5a requires every path to be concrete once there are several.
    #[must_use]
    pub fn expand_commands(&self, path: &crate::im::CommandPath) -> ExpandCommands<'a> {
        ExpandCommands {
            endpoints: self.endpoints,
            endpoint_filter: path.endpoint,
            cluster_filter: path.cluster,
            command_filter: path.command,
            endpoint_index: 0,
            cluster_index: 0,
            command_index: 0,
        }
    }
}

/// The commands a wildcard path names, produced one at a time.
#[derive(Debug, Clone)]
pub struct ExpandCommands<'a> {
    endpoints: &'a [Endpoint<'a>],
    endpoint_filter: Option<EndpointId>,
    cluster_filter: Option<crate::im::ClusterId>,
    command_filter: Option<crate::im::CommandId>,
    endpoint_index: usize,
    cluster_index: usize,
    command_index: usize,
}

impl<'a> Iterator for ExpandCommands<'a> {
    type Item = ResolvedCommand<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let endpoint = self.endpoints.get(self.endpoint_index)?;
            if self
                .endpoint_filter
                .is_some_and(|wanted| wanted != endpoint.id)
            {
                self.endpoint_index = self.endpoint_index.saturating_add(1);
                self.cluster_index = 0;
                self.command_index = 0;
                continue;
            }

            let Some(cluster) = endpoint.clusters.get(self.cluster_index) else {
                self.endpoint_index = self.endpoint_index.saturating_add(1);
                self.cluster_index = 0;
                self.command_index = 0;
                continue;
            };
            if self
                .cluster_filter
                .is_some_and(|wanted| wanted != cluster.id)
            {
                self.cluster_index = self.cluster_index.saturating_add(1);
                self.command_index = 0;
                continue;
            }

            let Some(command) = cluster.accepted_commands.get(self.command_index) else {
                self.cluster_index = self.cluster_index.saturating_add(1);
                self.command_index = 0;
                continue;
            };
            self.command_index = self.command_index.saturating_add(1);

            if self
                .command_filter
                .is_some_and(|wanted| wanted != command.id)
            {
                continue;
            }

            return Some(ResolvedCommand {
                endpoint: endpoint.id,
                cluster,
                command: *command,
            });
        }
    }
}

/// How far a wildcard expansion got, so the next message can carry on from there.
///
/// A whole-node wildcard expands to more than one message holds, and Core §10.2.3 answers
/// that by chunking rather than truncating. Chunking needs somewhere to resume, and this is
/// it: three indices into the endpoint, cluster and attribute slices, which is enough to
/// name a position without borrowing the node or remembering the paths already sent.
///
/// [`ExpandCursor::START`] is the beginning. A cursor is only meaningful against the node
/// and path that produced it — the indices are positional, so feeding one to a different
/// node resumes at a position that means something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExpandCursor {
    endpoint: usize,
    cluster: usize,
    attribute: usize,
}

impl ExpandCursor {
    /// The start of an expansion.
    pub const START: Self = Self {
        endpoint: 0,
        cluster: 0,
        attribute: 0,
    };

    /// Whether this is the start, i.e. nothing has been served for this path yet.
    #[must_use]
    pub const fn is_start(&self) -> bool {
        self.endpoint == 0 && self.cluster == 0 && self.attribute == 0
    }
}

/// The paths a wildcard names, produced one at a time.
///
/// Lazy for the same reason the interaction model's arrays are: a whole-node wildcard
/// on a bridge expands to thousands of paths, and a server must be able to fill one message
/// and stop rather than materialise the list first.
///
/// [`Expand::cursor`] and [`Node::expand_from`] make that stop *resumable*, which is what
/// §10.2.3's chunking needs.
#[derive(Debug, Clone)]
pub struct Expand<'a> {
    endpoints: &'a [Endpoint<'a>],
    endpoint_filter: Option<EndpointId>,
    cluster_filter: Option<ClusterId>,
    attribute_filter: Option<AttributeId>,
    endpoint_index: usize,
    cluster_index: usize,
    attribute_index: usize,
}

impl Expand<'_> {
    /// Where this expansion has got to.
    ///
    /// Taken *after* a [`Resolved`] has been dealt with, the cursor names the next path; so
    /// a chunk that could not fit its last path re-takes the cursor from before that path
    /// and resumes there.
    #[must_use]
    pub const fn cursor(&self) -> ExpandCursor {
        ExpandCursor {
            endpoint: self.endpoint_index,
            cluster: self.cluster_index,
            attribute: self.attribute_index,
        }
    }
}

impl<'a> Iterator for Expand<'a> {
    type Item = Resolved<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let endpoint = self.endpoints.get(self.endpoint_index)?;
            if self
                .endpoint_filter
                .is_some_and(|wanted| wanted != endpoint.id)
            {
                self.endpoint_index = self.endpoint_index.saturating_add(1);
                self.cluster_index = 0;
                self.attribute_index = 0;
                continue;
            }

            let Some(cluster) = endpoint.clusters.get(self.cluster_index) else {
                self.endpoint_index = self.endpoint_index.saturating_add(1);
                self.cluster_index = 0;
                self.attribute_index = 0;
                continue;
            };
            if self
                .cluster_filter
                .is_some_and(|wanted| wanted != cluster.id)
            {
                self.cluster_index = self.cluster_index.saturating_add(1);
                self.attribute_index = 0;
                continue;
            }

            // A cluster's attributes are its own followed by §7.13's globals, so the index
            // walks past the end of the descriptor's slice into that fixed tail.
            let own = cluster.attributes.len();
            let attribute = match self.attribute_index.checked_sub(own) {
                Some(global) => crate::dm::global::ATTRIBUTE_IDS.get(global).copied(),
                None => cluster.attributes.get(self.attribute_index).map(|a| a.id),
            };
            let Some(attribute) = attribute else {
                self.cluster_index = self.cluster_index.saturating_add(1);
                self.attribute_index = 0;
                continue;
            };
            self.attribute_index = self.attribute_index.saturating_add(1);

            if self
                .attribute_filter
                .is_some_and(|wanted| wanted != attribute)
            {
                continue;
            }

            return Some(Resolved {
                endpoint: endpoint.id,
                cluster,
                attribute,
            });
        }
    }
}
