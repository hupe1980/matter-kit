//! The paths that address things in the data model (Core §10.6.2, §10.6.7, §10.6.8,
//! §10.6.11).
//!
//! A path names an attribute, event or command somewhere in a node's tree of endpoints and
//! clusters. Three of the four are **wildcardable**: omitting a field means "all of them",
//! which is how a client reads a whole endpoint in one action instead of enumerating it.
//!
//! # Why these are lists and not structures
//!
//! Every other information block is a TLV structure. The paths are `List`s, and the reason
//! shows up in §10.6.2: `ListIndex` may repeat conceptually, and more importantly a list
//! permits the tag-compression scheme where fields are *omitted* and inherited from an
//! earlier path in the same action. A structure's "unique tags, all present that the schema
//! requires" reading does not fit that.
//!
//! # Wildcards are absence, not a value
//!
//! There is no "wildcard" marker. §10.6.2.1: "omission of any of the tags in question (with
//! the exception of Node) indicates wildcard semantics". So every wildcardable field here is
//! an `Option`, and `None` means *all*, not *unknown* — which is why
//! [`AttributePath::concrete`] exists to say whether a path names exactly one thing.
//!
//! # Tag compression is provisional and not implemented
//!
//! §10.6.2.1 defines an `EnableTagCompression` flag whose omitted fields inherit from "the
//! last AttributePathIB that had EnableTagCompression not present or set to false … seen in
//! a message that is part of the same interaction model Action". The specification marks it
//! provisional. It is decoded and preserved — a path that sets it round-trips — but this
//! crate does not *resolve* it, and [`AttributePath::enable_tag_compression`] being true is
//! something a caller must refuse rather than misread, because the alternative is silently
//! treating an inherited field as a wildcard.

use crate::error::{Error, ErrorCode, Result, bail};
use crate::msg::NodeId;
use crate::tlv::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value, set_once};

/// An endpoint identifier (§7.5).
pub type EndpointId = u16;
/// A cluster identifier (§7.5).
pub type ClusterId = u32;
/// An attribute identifier (§7.5).
pub type AttributeId = u32;
/// An event identifier (§7.5).
pub type EventId = u32;
/// A command identifier (§7.5).
pub type CommandId = u32;

/// `ListIndex` when the path means "append to this list" (§10.6.4.3.1).
///
/// "Path SHALL refer to a list with ListIndex containing a value of null and Data containing
/// the new value of the list item that will be added to the list."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListIndex {
    /// A specific item in a top-level list.
    At(u16),
    /// Null — a list append.
    Append,
}

/// `AttributePathIB` (§10.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttributePath {
    /// `EnableTagCompression [0]` — provisional, decoded but not resolved.
    pub enable_tag_compression: bool,
    /// `Node [1]` — "MAY be omitted if the target node of the path matches the NodeID of
    /// the server involved in the interaction", so `None` means *this* node and never
    /// "every node".
    pub node: Option<NodeId>,
    /// `Endpoint [2]`; `None` is a wildcard.
    pub endpoint: Option<EndpointId>,
    /// `Cluster [3]`; `None` is a wildcard.
    pub cluster: Option<ClusterId>,
    /// `Attribute [4]`; `None` is a wildcard.
    pub attribute: Option<AttributeId>,
    /// `ListIndex [5]` — only meaningful when `attribute` is present.
    pub list_index: Option<ListIndex>,
    /// `WildcardPathFlags [6]` (§10.6.2.6), which narrows what a wildcard expands to.
    pub wildcard_path_flags: Option<WildcardPathFlags>,
    /// `WildcardFilterConfigurationVersion [7]`, added in interaction model revision 13.
    pub wildcard_filter_configuration_version: Option<u32>,
}

bitflags::bitflags! {
    /// `WildcardPathFlags` — which kinds of attribute a wildcard expansion skips
    /// (§10.6.2.6).
    ///
    /// A client that only wants a device's own state can ask a wildcard not to expand into
    /// the global attributes every cluster carries, which is most of what a naive wildcard
    /// read returns.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct WildcardPathFlags: u32 {
        /// Bit 0 — "Skip the Root Node endpoint (endpoint 0) during wildcard expansion."
        const SKIP_ROOT_NODE = 0x0000_0001;
        /// Bit 1 — "Skip several large global attributes": §8.2.1.6 names exactly three,
        /// `GeneratedCommandList`, `AcceptedCommandList` and `AttributeList`.
        const SKIP_GLOBAL_ATTRIBUTES = 0x0000_0002;
        /// Bit 2 — "Skip the AttributeList global attribute" (`0xFFFB`) alone.
        const SKIP_ATTRIBUTE_LIST = 0x0000_0004;
        /// Bit 4 — "Skip the AcceptedCommandList and GeneratedCommandList global attributes."
        ///
        /// **Bit 4, not bit 3.** §2.13.2's table reserves bit 3 as `DoNotUse`, and reading the
        /// list of names without the bit numbers beside them puts this and every flag after it
        /// one place too low — which is what this crate did, silently, for as long as nothing
        /// honoured them.
        const SKIP_COMMAND_LISTS = 0x0000_0010;
        /// Bit 5 — "Skip any manufacturer-specific clusters or attributes."
        const SKIP_CUSTOM_ELEMENTS = 0x0000_0020;
        /// Bit 6 — "Skip any Fixed (F) quality attributes."
        const SKIP_FIXED_ATTRIBUTES = 0x0000_0040;
        /// Bit 7 — "Skip any Changes Omitted (C) quality attributes."
        const SKIP_CHANGES_OMITTED = 0x0000_0080;
        /// Bit 8 — "Skip all clusters with the Diagnostics (K) quality."
        ///
        /// Decoded and round-tripped, and **not** applied during expansion: `ClusterDescriptor`
        /// carries no Diagnostics quality to test, and inventing one from the cluster id would
        /// be a guess about which clusters the specification means. A flag this node cannot
        /// honour is one it does not act on; see [`AttributePath::unsupported_flags`].
        const SKIP_DIAGNOSTICS_CLUSTERS = 0x0000_0100;
    }
}

impl AttributePath {
    /// Whether §8.9.2.6's table admits this path in a Read or Subscribe.
    ///
    /// The table lists every legal wildcard combination, and one plausible-looking shape is
    /// missing from it: a **wildcard cluster with a concrete attribute** is allowed only when
    /// that attribute is a *global* one. The row reads "a specific **global** attribute data or
    /// field for all clusters", and there is no row for a specific non-global attribute across
    /// unspecified clusters.
    ///
    /// The reason is that attribute ids are only unique *within* a cluster. `0x0000` is
    /// `OnOff` on one cluster and `CurrentLevel`-adjacent on another; asking for "attribute
    /// 0x0000 on every cluster" asks for a set of unrelated values that happen to share a
    /// number. Global attributes are the exception because their ids mean the same thing
    /// everywhere, which is what makes them global.
    ///
    /// §8.4.3.2 step 1 makes a path the table does not admit a malformed *action*, so the whole
    /// request is answered `INVALID_ACTION` rather than the path being given a status.
    #[must_use]
    pub const fn is_valid_for_read(&self) -> bool {
        match (self.cluster, self.attribute) {
            (None, Some(attribute)) => crate::dm::global::is_global(attribute),
            _ => true,
        }
    }

    /// A path naming exactly one attribute.
    #[must_use]
    pub const fn attribute(
        endpoint: EndpointId,
        cluster: ClusterId,
        attribute: AttributeId,
    ) -> Self {
        Self {
            enable_tag_compression: false,
            node: None,
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attribute: Some(attribute),
            list_index: None,
            wildcard_path_flags: None,
            wildcard_filter_configuration_version: None,
        }
    }

    /// A path naming every attribute of one cluster on one endpoint.
    #[must_use]
    pub const fn cluster(endpoint: EndpointId, cluster: ClusterId) -> Self {
        Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            ..Self::wildcard()
        }
    }

    /// The path that names everything on the node — §10.6.2.5's `Path = [[ ]]`.
    #[must_use]
    pub const fn wildcard() -> Self {
        Self {
            enable_tag_compression: false,
            node: None,
            endpoint: None,
            cluster: None,
            attribute: None,
            list_index: None,
            wildcard_path_flags: None,
            wildcard_filter_configuration_version: None,
        }
    }

    /// The endpoint, cluster and attribute, if the path names exactly one of each.
    ///
    /// `None` when any of the three is wildcarded — which a server must expand rather than
    /// reject, so this is a question and not a validation.
    #[must_use]
    pub const fn concrete(&self) -> Option<(EndpointId, ClusterId, AttributeId)> {
        match (self.endpoint, self.cluster, self.attribute) {
            (Some(e), Some(c), Some(a)) => Some((e, c, a)),
            _ => None,
        }
    }

    /// Whether any field is wildcarded.
    #[must_use]
    pub const fn has_wildcard(&self) -> bool {
        self.concrete().is_none()
    }

    /// Writes the path as a `List` under `tag`.
    ///
    /// §10.6.1: "all context tags SHALL be emitted in the order as defined in the
    /// appropriate specification. This is done to reduce receiver side complexity in having
    /// to deal with arbitrary order tags." So the order here is the schema's, not a choice.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_list(tag)?;
        if self.enable_tag_compression {
            w.bool(Tag::Context(0), true)?;
        }
        if let Some(node) = self.node {
            w.unsigned(Tag::Context(1), node.0)?;
        }
        if let Some(endpoint) = self.endpoint {
            w.unsigned(Tag::Context(2), u64::from(endpoint))?;
        }
        if let Some(cluster) = self.cluster {
            w.unsigned(Tag::Context(3), u64::from(cluster))?;
        }
        if let Some(attribute) = self.attribute {
            w.unsigned(Tag::Context(4), u64::from(attribute))?;
        }
        match self.list_index {
            Some(ListIndex::At(index)) => w.unsigned(Tag::Context(5), u64::from(index))?,
            Some(ListIndex::Append) => w.null(Tag::Context(5))?,
            None => {}
        }
        if let Some(flags) = self.wildcard_path_flags {
            w.unsigned(Tag::Context(6), u64::from(flags.bits()))?;
        }
        if let Some(version) = self.wildcard_filter_configuration_version {
            w.unsigned(Tag::Context(7), u64::from(version))?;
        }
        w.end_container()
    }

    /// Reads a path whose opening `List` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut out = Self::default();
        let mut enable_tag_compression = None;
        let mut node = None;
        let mut endpoint = None;
        let mut cluster = None;
        let mut attribute = None;
        let mut list_index = None;
        let mut flags = None;
        let mut version = None;

        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut enable_tag_compression, element.bool()?)?,
                Some(1) => set_once(&mut node, NodeId(element.unsigned()?))?,
                Some(2) => set_once(&mut endpoint, narrow(element.unsigned()?)?)?,
                Some(3) => set_once(&mut cluster, narrow32(element.unsigned()?)?)?,
                Some(4) => set_once(&mut attribute, narrow32(element.unsigned()?)?)?,
                Some(5) => {
                    // Nullable: null means append (§10.6.4.3.1), and "ListIndex is
                    // currently only allowed to be omitted or null. Any other value SHALL
                    // be interpreted as an error" — but that restriction belongs to the
                    // *write* path, and a read may legitimately index one, so the value is
                    // carried and the caller decides.
                    let value = match element.value {
                        Value::Null => ListIndex::Append,
                        Value::Unsigned(_) => ListIndex::At(narrow(element.unsigned()?)?),
                        _ => bail!(TlvWrongType),
                    };
                    set_once(&mut list_index, value)?;
                }
                Some(6) => {
                    let raw = narrow32(element.unsigned()?)?;
                    // An unknown flag is kept rather than refused: §10.2.2 makes unknown
                    // *tags* ignorable, and a flag this revision has not heard of should
                    // round-trip through a proxy rather than be dropped.
                    set_once(&mut flags, WildcardPathFlags::from_bits_retain(raw))?;
                }
                Some(7) => set_once(&mut version, narrow32(element.unsigned()?)?)?,
                // §10.2.2: "any context-specific tag not listed in a given schema SHALL be
                // reserved for future use and SHALL be silently ignored".
                _ => reader.skip_value(&element)?,
            }
        }

        out.enable_tag_compression = enable_tag_compression.unwrap_or(false);
        out.node = node;
        out.endpoint = endpoint;
        out.cluster = cluster;
        out.attribute = attribute;
        out.list_index = list_index;
        out.wildcard_path_flags = flags;
        out.wildcard_filter_configuration_version = version;
        Ok(out)
    }

    /// Reads a path from an element that should open a `List`.
    pub fn from_element(reader: &mut TlvReader<'_>, element: &Element<'_>) -> Result<Self> {
        if element.value.container() != Some(ContainerKind::List) {
            bail!(TlvWrongType)
        }
        Self::decode(reader)
    }
}

/// `ClusterPathIB` (§10.6.7) — a path with no attribute, used by data-version filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClusterPath {
    /// `Node [0]`.
    pub node: Option<NodeId>,
    /// `Endpoint [1]`.
    pub endpoint: Option<EndpointId>,
    /// `Cluster [2]`.
    pub cluster: Option<ClusterId>,
}

impl ClusterPath {
    /// A path naming one cluster on one endpoint.
    #[must_use]
    pub const fn new(endpoint: EndpointId, cluster: ClusterId) -> Self {
        Self {
            node: None,
            endpoint: Some(endpoint),
            cluster: Some(cluster),
        }
    }

    /// Writes the path as a `List` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_list(tag)?;
        if let Some(node) = self.node {
            w.unsigned(Tag::Context(0), node.0)?;
        }
        if let Some(endpoint) = self.endpoint {
            w.unsigned(Tag::Context(1), u64::from(endpoint))?;
        }
        if let Some(cluster) = self.cluster {
            w.unsigned(Tag::Context(2), u64::from(cluster))?;
        }
        w.end_container()
    }

    /// Reads a path whose opening `List` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut node = None;
        let mut endpoint = None;
        let mut cluster = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut node, NodeId(element.unsigned()?))?,
                Some(1) => set_once(&mut endpoint, narrow(element.unsigned()?)?)?,
                Some(2) => set_once(&mut cluster, narrow32(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            node,
            endpoint,
            cluster,
        })
    }
}

/// `EventPathIB` (§10.6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventPath {
    /// `Node [0]`.
    pub node: Option<NodeId>,
    /// `Endpoint [1]`; `None` is a wildcard.
    pub endpoint: Option<EndpointId>,
    /// `Cluster [2]`; `None` is a wildcard.
    pub cluster: Option<ClusterId>,
    /// `Event [3]`; `None` is a wildcard.
    pub event: Option<EventId>,
    /// `IsUrgent [4]` — a subscription asks for this event to be reported without waiting
    /// for the next interval.
    pub is_urgent: Option<bool>,
}

impl EventPath {
    /// A path naming one event.
    #[must_use]
    pub const fn event(endpoint: EndpointId, cluster: ClusterId, event: EventId) -> Self {
        Self {
            node: None,
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            event: Some(event),
            is_urgent: None,
        }
    }

    /// Writes the path as a `List` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_list(tag)?;
        if let Some(node) = self.node {
            w.unsigned(Tag::Context(0), node.0)?;
        }
        if let Some(endpoint) = self.endpoint {
            w.unsigned(Tag::Context(1), u64::from(endpoint))?;
        }
        if let Some(cluster) = self.cluster {
            w.unsigned(Tag::Context(2), u64::from(cluster))?;
        }
        if let Some(event) = self.event {
            w.unsigned(Tag::Context(3), u64::from(event))?;
        }
        if let Some(urgent) = self.is_urgent {
            w.bool(Tag::Context(4), urgent)?;
        }
        w.end_container()
    }

    /// Reads a path whose opening `List` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut node = None;
        let mut endpoint = None;
        let mut cluster = None;
        let mut event = None;
        let mut is_urgent = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut node, NodeId(element.unsigned()?))?,
                Some(1) => set_once(&mut endpoint, narrow(element.unsigned()?)?)?,
                Some(2) => set_once(&mut cluster, narrow32(element.unsigned()?)?)?,
                Some(3) => set_once(&mut event, narrow32(element.unsigned()?)?)?,
                Some(4) => set_once(&mut is_urgent, element.bool()?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            node,
            endpoint,
            cluster,
            event,
            is_urgent,
        })
    }
}

/// `CommandPathIB` (§10.6.11).
///
/// Unlike the other three this has no `Node` field and no wildcards in practice: §8.9 makes
/// a command invocation address one endpoint — a wildcard invoke is permitted only in the
/// group case, where the endpoint comes from the group binding rather than the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommandPath {
    /// `Endpoint [0]`; omitted for a group invoke.
    pub endpoint: Option<EndpointId>,
    /// `Cluster [1]`.
    pub cluster: Option<ClusterId>,
    /// `Command [2]`.
    pub command: Option<CommandId>,
}

impl CommandPath {
    /// A path naming one command.
    #[must_use]
    pub const fn command(endpoint: EndpointId, cluster: ClusterId, command: CommandId) -> Self {
        Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            command: Some(command),
        }
    }

    /// The endpoint, cluster and command, if the path names all three.
    #[must_use]
    pub const fn concrete(&self) -> Option<(EndpointId, ClusterId, CommandId)> {
        match (self.endpoint, self.cluster, self.command) {
            (Some(e), Some(c), Some(cmd)) => Some((e, c, cmd)),
            _ => None,
        }
    }

    /// Writes the path as a `List` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_list(tag)?;
        if let Some(endpoint) = self.endpoint {
            w.unsigned(Tag::Context(0), u64::from(endpoint))?;
        }
        if let Some(cluster) = self.cluster {
            w.unsigned(Tag::Context(1), u64::from(cluster))?;
        }
        if let Some(command) = self.command {
            w.unsigned(Tag::Context(2), u64::from(command))?;
        }
        w.end_container()
    }

    /// Reads a path whose opening `List` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut endpoint = None;
        let mut cluster = None;
        let mut command = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut endpoint, narrow(element.unsigned()?)?)?,
                Some(1) => set_once(&mut cluster, narrow32(element.unsigned()?)?)?,
                Some(2) => set_once(&mut command, narrow32(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            endpoint,
            cluster,
            command,
        })
    }
}

fn narrow(value: u64) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

fn narrow32(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}
