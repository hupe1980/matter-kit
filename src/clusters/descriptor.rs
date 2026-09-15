//! Descriptor cluster `0x001D` (Core §9.5) — what an endpoint *is*.
//!
//! > This cluster describes an endpoint instance on the node, independently from other
//! > endpoints, but also allows composition of endpoints to conform to complex device type
//! > patterns.
//!
//! Every endpoint has one, and a commissioner reads it first: `DeviceTypeList` says what the
//! endpoint claims to be, `ServerList` and `ClientList` say what it speaks, `PartsList` says
//! what it is composed of.
//!
//! # Three of its five attributes are derived, not stored
//!
//! `ServerList` is "each cluster ID for the server clusters present on the endpoint
//! instance" — which the node's own [`Endpoint`] already says. So this
//! cluster reads it out of the data model rather than holding a second copy, for exactly the
//! reason §7.13's globals are synthesised: a hand-maintained list is a list that drifts, and
//! a `ServerList` that disagrees with what the endpoint serves fails certification in a way
//! that is tedious to find.
//!
//! `PartsList` is the exception that must be given: §9.2.3's endpoint composition is a
//! *tree*, and a flat set of endpoints does not say which contains which. So the
//! [`Descriptor`] is constructed per endpoint with its parts.
//!
//! # Revision 3
//!
//! | Revision | Change |
//! |---|---|
//! | 1 | Initial revision |
//! | 2 | Semantic tag list; `TagList` feature |
//! | 3 | Add `EndpointUniqueID` attribute |

use crate::dm::meta::{AttributeDescriptor, AttributeQualities, ClusterDescriptor};
use crate::dm::{Endpoint, Node, Resolved};
use crate::im::{AttributeId, ClusterHandler, ClusterId, EndpointId, InteractionContext, Status};
use crate::tlv::{Tag, TlvWriter};

use super::Cluster;

/// `0x001D` (§9.5.3).
pub const ID: ClusterId = 0x001D;

/// The highest revision in §9.5.1's table.
pub const REVISION: u16 = 3;

/// `DeviceTypeList` (§9.5.6.1) — `list[DeviceTypeStruct]`, min 1, `F`, `RV`, mandatory.
pub const DEVICE_TYPE_LIST: AttributeId = 0x0000;
/// `ServerList` (§9.5.6.2) — `list[cluster-id]`, `F`, `RV`, mandatory.
pub const SERVER_LIST: AttributeId = 0x0001;
/// `ClientList` (§9.5.6.3) — `list[cluster-id]`, `F`, `RV`, mandatory.
pub const CLIENT_LIST: AttributeId = 0x0002;
/// `PartsList` (§9.5.6.4) — `list[endpoint-no]`, `RV`, mandatory. Not `F`: a bridge's parts
/// change as devices appear.
pub const PARTS_LIST: AttributeId = 0x0003;
/// `TagList` (§9.5.6.5) — `list[SemanticTagStruct]`, 1 to 6, `F`, `RV`, `TAGLIST`.
pub const TAG_LIST: AttributeId = 0x0004;
/// `EndpointUniqueID` (§9.5.6.6) — `string`, max 32, `F`, `RV`, optional.
pub const ENDPOINT_UNIQUE_ID: AttributeId = 0x0005;

/// `TAGLIST` (§9.5.4, bit 0) — "The TagList attribute is present".
pub const FEATURE_TAG_LIST: u32 = 1 << 0;

pub use crate::dm::DeviceType;

/// A `SemanticTagStruct` (System Model §9.8.1), as carried by `TagList`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticTag<'a> {
    /// `MfgCode [0]` — the vendor that defined the namespace, or `None` for a standard one.
    /// Nullable: "If the MfgCode field is not null, the namespace… SHALL be scoped to the
    /// manufacturer."
    pub mfg_code: Option<crate::msg::VendorId>,
    /// `NamespaceID [1]` — which namespace the tag is drawn from.
    pub namespace_id: u8,
    /// `Tag [2]` — the tag within that namespace.
    pub tag: u8,
    /// `Label [3]` — an optional human-readable label, max 64, nullable.
    pub label: Option<&'a str>,
}

/// The attribute descriptors §9.5.6 defines, without `TagList` or `EndpointUniqueID`.
///
/// All four are `RV` at View — §7.6's default — and all but `PartsList` are `F`.
const BASE_ATTRIBUTES: [AttributeDescriptor; 4] = [
    AttributeDescriptor::read_only(DEVICE_TYPE_LIST).with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(SERVER_LIST).with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(CLIENT_LIST).with_qualities(AttributeQualities::FIXED),
    AttributeDescriptor::read_only(PARTS_LIST),
];

/// … and with `TagList`, for an endpoint that declares the `TAGLIST` feature.
const TAGGED_ATTRIBUTES: [AttributeDescriptor; 5] = [
    BASE_ATTRIBUTES[0],
    BASE_ATTRIBUTES[1],
    BASE_ATTRIBUTES[2],
    BASE_ATTRIBUTES[3],
    AttributeDescriptor::read_only(TAG_LIST).with_qualities(AttributeQualities::FIXED),
];

/// … and with `EndpointUniqueID` but no `TagList`.
const IDENTIFIED_ATTRIBUTES: [AttributeDescriptor; 5] = [
    BASE_ATTRIBUTES[0],
    BASE_ATTRIBUTES[1],
    BASE_ATTRIBUTES[2],
    BASE_ATTRIBUTES[3],
    AttributeDescriptor::read_only(ENDPOINT_UNIQUE_ID).with_qualities(AttributeQualities::FIXED),
];

/// … and with both.
const FULL_ATTRIBUTES: [AttributeDescriptor; 6] = [
    TAGGED_ATTRIBUTES[0],
    TAGGED_ATTRIBUTES[1],
    TAGGED_ATTRIBUTES[2],
    TAGGED_ATTRIBUTES[3],
    TAGGED_ATTRIBUTES[4],
    AttributeDescriptor::read_only(ENDPOINT_UNIQUE_ID).with_qualities(AttributeQualities::FIXED),
];

/// The descriptor for an endpoint with neither optional attribute.
#[must_use]
pub const fn cluster() -> ClusterDescriptor<'static> {
    descriptor_with(&BASE_ATTRIBUTES, 0)
}

/// The descriptor for an endpoint that serves `TagList`, declaring `TAGLIST`.
#[must_use]
pub const fn cluster_with_tags() -> ClusterDescriptor<'static> {
    descriptor_with(&TAGGED_ATTRIBUTES, FEATURE_TAG_LIST)
}

/// The descriptor for an endpoint that serves `EndpointUniqueID` but not `TagList`.
#[must_use]
pub const fn cluster_with_unique_id() -> ClusterDescriptor<'static> {
    descriptor_with(&IDENTIFIED_ATTRIBUTES, 0)
}

/// The descriptor for an endpoint that serves both optional attributes.
#[must_use]
pub const fn cluster_full() -> ClusterDescriptor<'static> {
    descriptor_with(&FULL_ATTRIBUTES, FEATURE_TAG_LIST)
}

const fn descriptor_with(
    attributes: &'static [AttributeDescriptor],
    feature_map: u32,
) -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map,
        attributes,
        accepted_commands: &[],
        generated_commands: &[],
        events: &[],
    }
}

/// The Descriptor cluster on one endpoint.
///
/// Borrows the [`Node`] rather than copying anything out of it: `ServerList` and `ClientList`
/// are views of the endpoint's own cluster set, and the whole point is that they cannot
/// disagree with it.
///
/// One instance per endpoint, because §9.5 is scoped to an endpoint — [`Descriptor::endpoint`]
/// is the endpoint it answers for, and a read of any other endpoint's Descriptor is a
/// different instance.
#[derive(Debug, Clone, Copy)]
pub struct Descriptor<'a> {
    /// The node this endpoint belongs to — the source of `ServerList`.
    pub node: Node<'a>,
    /// The endpoint this instance is on.
    pub endpoint: EndpointId,
    /// `PartsList` (§9.5.6.4) — the endpoints this one is composed of.
    pub parts: &'a [EndpointId],
    /// `TagList` (§9.5.6.5), when the instance declares `TAGLIST`.
    pub tags: &'a [SemanticTag<'a>],
    /// `EndpointUniqueID` (§9.5.6.6), when the instance serves it.
    pub unique_id: Option<&'a str>,
}

impl<'a> Descriptor<'a> {
    /// A Descriptor for an endpoint, with nothing composed under it.
    ///
    /// `DeviceTypeList` is not a parameter: §9.5.6.1's list is the endpoint's own, and it is
    /// read from the node. Passing it separately would let a Descriptor publish device types
    /// that the endpoint it names does not have — and §6.6.6.2's access control matches ACL
    /// targets against the endpoint's, so the two disagreeing is a privilege decision made on
    /// one list and reported from another.
    #[must_use]
    pub const fn new(node: Node<'a>, endpoint: EndpointId) -> Self {
        Self {
            node,
            endpoint,
            parts: &[],
            tags: &[],
            unique_id: None,
        }
    }

    /// The device types of the endpoint this instance answers for (§9.5.6.1).
    #[must_use]
    pub fn device_types(&self) -> &'a [DeviceType] {
        match self.node.endpoint(self.endpoint) {
            Some(endpoint) => endpoint.device_types,
            None => &[],
        }
    }

    /// The clusters the endpoint speaks as a client (§9.5.6.3).
    ///
    /// Read from the node for the same reason `DeviceTypeList` is: a Descriptor that carried
    /// its own copy could publish a `ClientList` the endpoint it names does not have, and
    /// §9.2's device-type check reads the endpoint's.
    #[must_use]
    pub fn clients(&self) -> &'a [ClusterId] {
        match self.node.endpoint(self.endpoint) {
            Some(endpoint) => endpoint.clients,
            None => &[],
        }
    }

    /// The same instance with a `PartsList`.
    #[must_use]
    pub const fn with_parts(mut self, parts: &'a [EndpointId]) -> Self {
        self.parts = parts;
        self
    }

    /// The same instance with a `TagList` — requires the `TAGLIST` feature.
    #[must_use]
    pub const fn with_tags(mut self, tags: &'a [SemanticTag<'a>]) -> Self {
        self.tags = tags;
        self
    }

    /// The same instance with an `EndpointUniqueID`.
    #[must_use]
    pub const fn with_unique_id(mut self, unique_id: &'a str) -> Self {
        self.unique_id = Some(unique_id);
        self
    }

    /// The cluster descriptor matching what this instance serves.
    ///
    /// `TagList` and `EndpointUniqueID` are in the list exactly when this instance has them,
    /// because §7.13.3's `AttributeList` is what a commissioner builds its model from — an
    /// entry for an attribute that answers `UNSUPPORTED_ATTRIBUTE` is a certification
    /// failure, and so is a served attribute missing from the list.
    #[must_use]
    pub fn descriptor(&self) -> ClusterDescriptor<'static> {
        match (!self.tags.is_empty(), self.unique_id.is_some()) {
            (false, false) => cluster(),
            (true, false) => cluster_with_tags(),
            (false, true) => cluster_with_unique_id(),
            (true, true) => cluster_full(),
        }
    }

    fn this_endpoint(&self) -> Option<&'a Endpoint<'a>> {
        self.node.endpoint(self.endpoint)
    }
}

impl ClusterHandler for Descriptor<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<(), Status> {
        // A Descriptor instance answers for one endpoint. Reading it through a path on a
        // different endpoint would silently report the wrong endpoint's cluster list, which
        // is worse than refusing: a commissioner would build its model from it.
        if resolved.endpoint != self.endpoint {
            return Err(Status::UnsupportedEndpoint);
        }
        match resolved.attribute {
            DEVICE_TYPE_LIST => {
                w.start_array(tag).map_err(|_| Status::ResourceExhausted)?;
                for device_type in self.device_types() {
                    w.start_structure(Tag::Anonymous)
                        .map_err(|_| Status::ResourceExhausted)?;
                    w.unsigned(Tag::Context(0), u64::from(device_type.device_type))
                        .map_err(|_| Status::ResourceExhausted)?;
                    w.unsigned(Tag::Context(1), u64::from(device_type.revision))
                        .map_err(|_| Status::ResourceExhausted)?;
                    w.end_container().map_err(|_| Status::ResourceExhausted)?;
                }
                w.end_container().map_err(|_| Status::ResourceExhausted)?;
                Ok(())
            }
            SERVER_LIST => {
                // Derived, never stored: the endpoint's own cluster set is the answer.
                let endpoint = self.this_endpoint().ok_or(Status::UnsupportedEndpoint)?;
                write_cluster_ids(w, tag, endpoint.clusters.iter().map(|c| c.id))
            }
            CLIENT_LIST => write_cluster_ids(w, tag, self.clients().iter().copied()),
            PARTS_LIST => {
                w.start_array(tag).map_err(|_| Status::ResourceExhausted)?;
                for part in self.parts {
                    w.unsigned(Tag::Anonymous, u64::from(*part))
                        .map_err(|_| Status::ResourceExhausted)?;
                }
                w.end_container().map_err(|_| Status::ResourceExhausted)?;
                Ok(())
            }
            TAG_LIST => {
                w.start_array(tag).map_err(|_| Status::ResourceExhausted)?;
                for semantic in self.tags {
                    w.start_structure(Tag::Anonymous)
                        .map_err(|_| Status::ResourceExhausted)?;
                    match semantic.mfg_code {
                        Some(vendor) => w.unsigned(Tag::Context(0), u64::from(vendor.0)),
                        None => w.null(Tag::Context(0)),
                    }
                    .map_err(|_| Status::ResourceExhausted)?;
                    w.unsigned(Tag::Context(1), u64::from(semantic.namespace_id))
                        .map_err(|_| Status::ResourceExhausted)?;
                    w.unsigned(Tag::Context(2), u64::from(semantic.tag))
                        .map_err(|_| Status::ResourceExhausted)?;
                    if let Some(label) = semantic.label {
                        w.utf8(Tag::Context(3), label)
                            .map_err(|_| Status::ResourceExhausted)?;
                    }
                    w.end_container().map_err(|_| Status::ResourceExhausted)?;
                }
                w.end_container().map_err(|_| Status::ResourceExhausted)?;
                Ok(())
            }
            ENDPOINT_UNIQUE_ID => {
                let unique_id = self.unique_id.ok_or(Status::UnsupportedAttribute)?;
                w.utf8(tag, unique_id)
                    .map_err(|_| Status::ResourceExhausted)
            }
            _ => Err(Status::UnsupportedAttribute),
        }
    }
}

fn write_cluster_ids(
    w: &mut TlvWriter<'_>,
    tag: Tag,
    ids: impl Iterator<Item = ClusterId>,
) -> core::result::Result<(), Status> {
    w.start_array(tag).map_err(|_| Status::ResourceExhausted)?;
    for id in ids {
        w.unsigned(Tag::Anonymous, u64::from(id))
            .map_err(|_| Status::ResourceExhausted)?;
    }
    w.end_container().map_err(|_| Status::ResourceExhausted)
}

impl Cluster for Descriptor<'_> {
    const ID: ClusterId = ID;
}
