//! What a cluster *is*: the descriptors a node is built from (Core §7.10–7.13).
//!
//! These are static data, meant to be `const` and to live in flash. A cluster's shape does
//! not change at runtime — its *values* do — so nothing here is owned or mutable, and an
//! endpoint is a slice of descriptors the application points at rather than a structure it
//! builds.
//!
//! # The global attributes are not in the list
//!
//! §7.13 gives every cluster instance five attributes it must support:
//! `ClusterRevision`, `FeatureMap`, `AttributeList`, `AcceptedCommandList` and
//! `GeneratedCommandList`. They are **synthesised** from the descriptor rather than written
//! into it — [`global`](crate::dm::global) — because three of the five are lists *of* the
//! descriptor's contents, and a hand-maintained copy is a copy that drifts.
//!
//! That is not a stylistic preference. `AttributeList` is read by every commissioner during
//! discovery, and a cluster whose declared list disagrees with what it actually serves fails
//! certification in a way that is tedious to find.

use crate::dm::access::Access;
use crate::im::{AttributeId, ClusterId, CommandId, EventId};

/// How often an attribute's value may be reported (§7.7.8, §7.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Reporting {
    /// Reported on every change — the ordinary case.
    #[default]
    OnChange,
    /// `Q` — Quieter Reporting: "Changes to the value under conditions other than those
    /// specified in the attribute description SHOULD NOT be reported." The conditions are
    /// prose per attribute, so the policy lives with the cluster, not here.
    Quieter,
    /// `C` — changes are omitted entirely; a client must poll.
    ChangesOmitted,
}

bitflags::bitflags! {
    /// The qualities §7.12 gives an attribute, beyond its access.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct AttributeQualities: u8 {
        /// `X` — nullable: the attribute may hold TLV null.
        const NULLABLE = 1 << 0;
        /// `N` — non-volatile: the value survives a reboot (§7.12.1).
        const NON_VOLATILE = 1 << 1;
        /// `F` — fixed: the value never changes after the node is built, so it need not be
        /// watched for reporting.
        const FIXED = 1 << 2;
        /// `P` — the attribute supports atomic writes (§7.15).
        const ATOMIC = 1 << 3;
        /// `L` — large message: the value requires TCP (§7.7.5).
        const LARGE = 1 << 4;
        /// `S` — the attribute takes part in scenes: Scenes Management captures and recalls
        /// it (§1.4.5's extension field sets). A cluster that forgets which of its attributes
        /// are `S` produces scenes that restore some of a light's state and not the rest.
        const SCENE = 1 << 5;
    }
}

/// One attribute of a cluster (§7.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeDescriptor {
    /// The attribute id.
    pub id: AttributeId,
    /// Its access qualities.
    pub access: Access,
    /// Its reporting policy.
    pub reporting: Reporting,
    /// Its other qualities.
    pub qualities: AttributeQualities,
}

impl AttributeDescriptor {
    /// A readable attribute at View privilege — §7.6's default.
    #[must_use]
    pub const fn read_only(id: AttributeId) -> Self {
        Self {
            id,
            access: Access::read_only(crate::dm::access::Privilege::View),
            reporting: Reporting::OnChange,
            qualities: AttributeQualities::empty(),
        }
    }

    /// A readable and writable attribute — `RW VO`.
    #[must_use]
    pub const fn read_write(id: AttributeId) -> Self {
        Self {
            id,
            access: Access::read_write(),
            reporting: Reporting::OnChange,
            qualities: AttributeQualities::empty(),
        }
    }

    /// The same attribute with a different access.
    #[must_use]
    pub const fn with_access(mut self, access: Access) -> Self {
        self.access = access;
        self
    }

    /// The same attribute with extra qualities.
    #[must_use]
    pub const fn with_qualities(mut self, qualities: AttributeQualities) -> Self {
        self.qualities = qualities;
        self
    }

    /// The same attribute with a reporting policy.
    #[must_use]
    pub const fn with_reporting(mut self, reporting: Reporting) -> Self {
        self.reporting = reporting;
        self
    }
}

/// One command of a cluster (§7.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandDescriptor {
    /// The command id.
    pub id: CommandId,
    /// Its access — which for a command means its invoke privilege.
    pub access: Access,
    /// The id of the command this one is answered with, if it has a response.
    ///
    /// §7.13.4: "For each client request command in this list that mandates a response from
    /// the server, the response command SHALL be indicated in the GeneratedCommandList" — so
    /// this is what lets that list be synthesised rather than written twice.
    pub response: Option<CommandId>,
}

impl CommandDescriptor {
    /// A request command invocable at Operate — §7.6's default for a request command.
    #[must_use]
    pub const fn new(id: CommandId) -> Self {
        Self {
            id,
            access: Access::invoke(crate::dm::access::Privilege::Operate),
            response: None,
        }
    }

    /// The same command, answered by `response`.
    #[must_use]
    pub const fn with_response(mut self, response: CommandId) -> Self {
        self.response = Some(response);
        self
    }

    /// The same command with a different access.
    #[must_use]
    pub const fn with_access(mut self, access: Access) -> Self {
        self.access = access;
        self
    }
}

/// An event's priority (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum EventPriority {
    /// Lowest: development and diagnostics.
    Debug,
    /// The ordinary case.
    #[default]
    Info,
    /// Highest: an event whose loss matters.
    Critical,
}

/// One event of a cluster (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDescriptor {
    /// The event id.
    pub id: EventId,
    /// Its access — read only, at some privilege.
    pub access: Access,
    /// Its priority.
    pub priority: EventPriority,
}

impl EventDescriptor {
    /// An event readable at View — §7.6's default.
    #[must_use]
    pub const fn new(id: EventId) -> Self {
        Self {
            id,
            access: Access::read_only(crate::dm::access::Privilege::View),
            priority: EventPriority::Info,
        }
    }

    /// The same event at a different priority.
    #[must_use]
    pub const fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }
}

/// What a cluster instance looks like (§7.10).
///
/// Static: this is the cluster's *shape*, which does not change at runtime. The attribute,
/// command and event slices are expected to be `const` arrays in flash, and to be **sorted
/// by id** — [`ClusterDescriptor::attribute`] and its siblings binary-search them, and
/// §7.13's synthesised lists are emitted in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterDescriptor<'a> {
    /// The cluster id.
    pub id: ClusterId,
    /// `ClusterRevision` (§7.13.1) — "the (highest) revision number of the cluster
    /// specification that has been implemented", and never zero for a cluster defined after
    /// the attribute existed.
    pub revision: u16,
    /// `FeatureMap` (§7.13.2). Zero "for a cluster whose definition does not define a
    /// FeatureMap".
    pub feature_map: u32,
    /// The attributes this instance serves, **excluding** the global ones of §7.13, sorted
    /// by id.
    pub attributes: &'a [AttributeDescriptor],
    /// The client-to-server commands it accepts, sorted by id.
    pub accepted_commands: &'a [CommandDescriptor],
    /// The server-to-client commands it generates that are *not* responses to an accepted
    /// command — most clusters have none, because responses are derived from
    /// [`CommandDescriptor::response`].
    pub generated_commands: &'a [CommandId],
    /// The events it may emit, sorted by id.
    pub events: &'a [EventDescriptor],
}

impl<'a> ClusterDescriptor<'a> {
    /// The descriptor for an attribute id, including the global ones of §7.13.
    #[must_use]
    pub fn attribute(&self, id: AttributeId) -> Option<AttributeDescriptor> {
        if let Some(global) = crate::dm::global::descriptor(id) {
            return Some(global);
        }
        self.attributes
            .binary_search_by_key(&id, |a| a.id)
            .ok()
            .and_then(|index| self.attributes.get(index).copied())
    }

    /// The descriptor for an accepted command id.
    #[must_use]
    pub fn accepted_command(&self, id: CommandId) -> Option<CommandDescriptor> {
        self.accepted_commands
            .binary_search_by_key(&id, |c| c.id)
            .ok()
            .and_then(|index| self.accepted_commands.get(index).copied())
    }

    /// The descriptor for an event id.
    #[must_use]
    pub fn event(&self, id: EventId) -> Option<EventDescriptor> {
        self.events
            .binary_search_by_key(&id, |e| e.id)
            .ok()
            .and_then(|index| self.events.get(index).copied())
    }

    /// Every attribute id this instance serves, in ascending order: the cluster's own,
    /// then §7.13's globals.
    ///
    /// This is `AttributeList`'s content. The globals sort last because their ids are
    /// `0xFFF8`–`0xFFFD`, above any cluster-specific id.
    pub fn attribute_ids(&self) -> impl Iterator<Item = AttributeId> + 'a {
        let own = self.attributes.iter().map(|a| a.id);
        own.chain(crate::dm::global::ATTRIBUTE_IDS.iter().copied())
    }

    /// Every command id the server may generate: each accepted command's response, plus any
    /// declared outright.
    ///
    /// §7.13.5: "For each command in this list that is a response to a client request
    /// command, the request command SHALL be indicated in the AcceptedCommandList" — which
    /// is exactly the relation this derives from, so the two lists cannot disagree.
    pub fn generated_command_ids(&self) -> impl Iterator<Item = CommandId> + 'a {
        let responses = self.accepted_commands.iter().filter_map(|c| c.response);
        responses.chain(self.generated_commands.iter().copied())
    }

    /// Whether the descriptor is well formed: every slice sorted and free of duplicates, and
    /// no attribute claiming an id §7.13 reserves for a global.
    ///
    /// A `const` node cannot be validated at compile time today, so this is what
    /// [`Node::validate`](crate::dm::Node::validate) calls — once, at start-up, rather than
    /// per request. An unsorted slice would make the binary searches silently miss.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        fn ascending<T: Copy, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
            items.windows(2).all(|w| match w {
                [a, b] => key(a) < key(b),
                _ => true,
            })
        }
        ascending(self.attributes, |a| a.id)
            && ascending(self.accepted_commands, |c| c.id)
            && ascending(self.events, |e| e.id)
            && !self
                .attributes
                .iter()
                .any(|a| crate::dm::global::is_global(a.id))
    }
}

/// A device type an endpoint conforms to (§9.5.5.1).
///
/// Part of the node's *shape*, not of any one cluster: §9.5 requires every endpoint to
/// declare at least one, the Descriptor cluster merely publishes it, and §6.6.6.2's access
/// control matches ACL targets against it. Holding it on the endpoint is what keeps those
/// three readings of the same fact from disagreeing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceType {
    /// `DeviceType [0]` — a `devtype-id`, the identifier from the Device Library.
    pub device_type: u32,
    /// `Revision [1]` — "the implemented revision of the device type definition", min 1.
    pub revision: u16,
}

impl DeviceType {
    /// A device type at a revision.
    #[must_use]
    pub const fn new(device_type: u32, revision: u16) -> Self {
        Self {
            device_type,
            revision,
        }
    }
}
