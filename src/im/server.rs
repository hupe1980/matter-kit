//! Serving a Read: from a request path to a report (Core §8.4.3.2).
//!
//! §8.4.3.2 spells out the processing in fifteen numbered steps, and the shape that falls
//! out of them is not obvious until you notice one thing: **a concrete path and an expanded
//! path are handled differently on failure.**
//!
//! > b. Else if the path is a concrete path … an AttributeStatusIB SHALL be generated with
//! >    the UNSUPPORTED_ENDPOINT Status Code.
//! >
//! > c. Else perform Request Path Expansion and process each expanded existent path as
//! >    follows: … the path SHALL be discarded.
//!
//! A client that asked for one specific attribute is *told* why it cannot have it. A client
//! that asked for everything simply does not see it. That asymmetry is the privacy property
//! of a wildcard read: merging the two would let a subject with no privilege over a cluster
//! learn that the cluster exists by counting statuses.
//!
//! # The two access checks
//!
//! A concrete path is checked **twice**, and the first one is not redundant. §8.4.3.2 step
//! b.i checks "assuming the required_privilege for the element is View, to determine whether
//! the subject would have had at least some access", *before* looking at whether the element
//! exists; step b.iii then checks the attribute's actual privilege. The order is what stops
//! the existence checks in between from leaking: a subject with no access at all learns
//! `UNSUPPORTED_ACCESS` rather than `UNSUPPORTED_CLUSTER`, and so cannot map a node it has
//! no rights over.
//!
//! # Chunking
//!
//! A whole-node wildcard does not fit in one message, and §4.4.4 caps a UDP message at the
//! 1280-octet IPv6 minimum MTU. §10.2.3 answers that by *chunking* — "maximally packing these
//! information blocks (IBs) into a series of 'data' messages" — so filling one message and
//! stopping is not an option a conforming server has: `MoreChunkedMessages` is a promise that
//! another message follows, and a client that is told it waits.
//!
//! So the boundary is found by *size*, by writing a block and rolling it back when it does not
//! fit ([`TlvWriter::checkpoint`](crate::tlv::TlvWriter::checkpoint)), and a [`ReadCursor`]
//! records where to resume. [`Server::serve_chunk`] is the loop; [`Server::serve`] is the
//! one-message convenience for reads known to be small.
//!
//! Progress is guaranteed even when a single value is larger than an entire message: a list is
//! split per §10.6.4.3.1, and a value that cannot be split is refused with
//! `RESOURCE_EXHAUSTED` for its own path rather than stalling the read.
//!
//! # What this does not do
//!
//! Events and `DataVersionFilter`s. Access control is a trait the caller supplies, because the
//! Access Control cluster (§9.10) does not exist yet — and making it a parameter means the
//! ordering above is testable without it.

use crate::dm::{AttributeQualities, Node, Privilege};
use crate::error::{ErrorCode, Result, bail};
use crate::im::ib::{
    AttributeData, AttributeReport, AttributeStatus, CommandData, CommandStatus, InvokeResponse,
    StatusIb,
};
use crate::im::path::AttributePath;
use crate::im::status::Status;
use crate::tlv::{ContainerKind, Tag, TlvWriter};

/// Who is asking, and what they may have.
///
/// A trait rather than a concrete type because the answer comes from the Access Control
/// cluster (§9.10), which does not exist yet — and because making it a parameter is what
/// lets §8.4.3.2's check *ordering* be tested without one.
pub trait AccessControl {
    /// Whether the subject holds `required` over this path.
    ///
    /// §6.6.1's subsumption is the implementor's to apply: a subject granted Administer
    /// holds every lower privilege, which [`Privilege::grants`] expresses.
    fn allows(&self, path: &AttributePath, required: Privilege) -> Outcome;
}

/// What an access check decided (§8.4.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The subject may proceed.
    Granted,
    /// "If the outcome is AccessDenied, an AttributeStatusIB SHALL be generated with the
    /// UNSUPPORTED_ACCESS Status Code."
    Denied,
    /// "Else if the outcome is AccessRestricted, an AttributeStatusIB SHALL be generated
    /// with the ACCESS_RESTRICTED Status Code" — an Access Restriction List (§6.6.3).
    Restricted,
}

impl Outcome {
    /// The status §8.4.3.2 pairs with a refusal, or `None` when it granted.
    #[must_use]
    pub const fn status(self) -> Option<Status> {
        match self {
            Self::Granted => None,
            Self::Denied => Some(Status::UnsupportedAccess),
            Self::Restricted => Some(Status::AccessRestricted),
        }
    }
}

/// An access control that grants everything, for a node with no Access Control cluster yet.
///
/// **Not a default.** A commissioned node must consult §9.10, and this is here so that the
/// path-processing rules can be exercised on their own — and so that the PASE session's
/// implicit administrator privilege during commissioning (§6.6.2.4) has something to be.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

/// What a write does to the attribute it names (§10.6.4.3.1's Change enumeration).
///
/// The distinction exists because a list may be larger than one message, so §10.6.4.3.1 lets
/// a client send it as a series of blocks: one that replaces the list, then one per item. The
/// two are told apart *only* by whether the path carries `ListIndex`, which is why this has
/// to reach the cluster — the data alone cannot say which was meant.
///
/// For an attribute that is not a list there is only [`WriteOp::Replace`], and it means what
/// a write has always meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WriteOp {
    /// `ListIndex` omitted — §10.6.4.3.1's REPLACE.
    ///
    /// "Path SHALL refer to a list with ListIndex omitted and Data SHALL contain new values
    /// that will replace the existing contents of the list." An empty array therefore clears
    /// the list, which is how the item-by-item encoding starts.
    #[default]
    Replace,
    /// `ListIndex` present and null — §10.6.4.3.1's ADD.
    ///
    /// "Path SHALL refer to a list with ListIndex containing a value of null and Data
    /// containing the new value of the list item that will be added to the list." The item is
    /// appended; §8.7.3.3 requires the blocks be "processed in the order conveyed", so the
    /// list ends up in the order the client sent.
    Append,
}

impl WriteOp {
    /// The operation a path names, or `None` when its `ListIndex` is one the spec forbids.
    ///
    /// §10.6.4.3.1: "ListIndex is currently only allowed to be omitted or null. Any other
    /// value SHALL be interpreted as an error." Writing *at* an index is not a thing a client
    /// may ask for, and silently treating it as a replace would let one item's write wipe the
    /// list.
    const fn of(path: &AttributePath) -> Option<Self> {
        match path.list_index {
            None => Some(Self::Replace),
            Some(crate::im::ListIndex::Append) => Some(Self::Append),
            Some(crate::im::ListIndex::At(_)) => None,
        }
    }
}

/// What a device's clusters actually do.
///
/// One trait rather than three, because a device has one cluster implementation table and
/// not three. Write and invoke have defaults that refuse, so a read-only node implements one
/// method — and a cluster that forgets to implement `write` refuses writes rather than
/// silently accepting them.
///
/// Every method returns a [`Status`] rather than an error, because §8.4.3.2, §8.7.3.2 and
/// §8.8.2.3 all require one path's failure to be reported *for that path* without failing
/// the action. An error type would force the whole request to fail.
pub trait ClusterHandler {
    /// Writes the value of `resolved`'s attribute under `tag`.
    ///
    /// The global attributes of §7.13 never reach here: they are synthesised from the
    /// descriptor ([`dm::global`](crate::dm::global)), so a cluster does not implement its
    /// own `ClusterRevision`.
    fn read(
        &self,
        resolved: &crate::dm::Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<(), Status>;

    /// The cluster instance's data version (§7.10.3), if it tracks one.
    ///
    /// `None` omits the field, which a report may do; a client then cannot use a
    /// `DataVersionFilter` against that cluster, which costs bandwidth rather than
    /// correctness. It also means §8.7.3.2 step b.vi's `DATA_VERSION_MISMATCH` check cannot
    /// fire, so a write is never rejected for staleness.
    fn data_version(&self, _resolved: &crate::dm::Resolved<'_>) -> Option<u32> {
        None
    }

    /// Writes `data` — the encoded TLV element, tag included — into the attribute.
    ///
    /// `op` says *how*, and a cluster holding a list must honour it. §10.6.4.3.1 gives a
    /// client two ways to write a list, and they are told apart only by whether the path
    /// carries `ListIndex`: without it the data replaces the whole list, with it (null) the
    /// data is one more item to add. A cluster that ignores `op` and replaces on every block
    /// keeps only the last item of a list written item by item — which is how an access
    /// control list arrives, so the failure is a device that silently drops every ACL entry
    /// but one.
    ///
    /// §8.7.3.3: a value outside the cluster's constraints is `CONSTRAINT_ERROR`; a value
    /// that is well-typed but wrong for the device's current state is
    /// [`Status::DynamicConstraintError`]. A list that cannot take another item is
    /// [`Status::ResourceExhausted`].
    fn write(
        &self,
        _resolved: &crate::dm::Resolved<'_>,
        _data: &[u8],
        _op: WriteOp,
        _ctx: &InteractionContext<'_>,
    ) -> core::result::Result<(), Status> {
        Err(Status::UnsupportedWrite)
    }

    /// Runs a command.
    ///
    /// `fields` is the encoded `CommandFields` element, or `None` for a command that takes
    /// none. The three outcomes are exactly §8.8.2.3's "Invoke Execution":
    ///
    /// * `Ok(None)` — the command succeeded and the cluster defines no response command, so
    ///   a `CommandStatusIB` with `SUCCESS` is generated.
    /// * `Ok(Some(id))` — the cluster defines a response command; its fields have been
    ///   written under `tag` and `id` is its command id.
    /// * `Err(status)` — a `CommandStatusIB` with that status.
    ///
    /// The error is a [`StatusIb`], not a bare [`Status`], because §10.6.17 lets a cluster
    /// define its own codes alongside `FAILURE` — and some commands have no other way to
    /// report why they refused. §11.19's `OpenCommissioningWindow` is the example: `Busy`,
    /// `PAKEParameterError` and `WindowNotOpen` are cluster-specific codes, and it has no
    /// response command to put them in. [`From<Status>`](StatusIb) makes the common case a
    /// `?` away.
    fn invoke(
        &self,
        _resolved: &crate::dm::ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> core::result::Result<Option<crate::im::CommandId>, StatusIb> {
        Err(Status::UnsupportedCommand.into())
    }
}

/// A shared reference to a handler is a handler.
///
/// Which is what lets a device assemble its cluster table out of borrowed clusters — the
/// clusters themselves own references to the fabric table, the key store and the fail-safe,
/// so they are rarely cheap to move and there is no reason to.
impl<T: ClusterHandler + ?Sized> ClusterHandler for &T {
    fn read(
        &self,
        resolved: &crate::dm::Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<(), Status> {
        (**self).read(resolved, ctx, w, tag)
    }

    fn data_version(&self, resolved: &crate::dm::Resolved<'_>) -> Option<u32> {
        (**self).data_version(resolved)
    }

    fn write(
        &self,
        resolved: &crate::dm::Resolved<'_>,
        data: &[u8],
        op: WriteOp,
        ctx: &InteractionContext<'_>,
    ) -> core::result::Result<(), Status> {
        (**self).write(resolved, data, op, ctx)
    }

    fn invoke(
        &self,
        resolved: &crate::dm::ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<Option<crate::im::CommandId>, StatusIb> {
        (**self).invoke(resolved, fields, ctx, w, tag)
    }
}

/// What a handler needs to know about the interaction it is running inside.
///
/// Everything here is a fact about the *session and action*, not about the node: a cluster
/// cannot read any of it for itself, and several of §11.18's commands are wrong without it.
#[derive(Debug, Clone, Copy)]
pub struct InteractionContext<'a> {
    /// Whether this action is part of a Timed transaction (§8.7.4).
    ///
    /// The server has already refused anything that *requires* one and did not get it, so a
    /// handler needs this only if it wants to impose its own rule.
    pub timed: bool,
    /// The fabric this interaction is scoped to, if any.
    ///
    /// `None` on a PASE session during commissioning, which is why §8.8.2.3 step b.v makes a
    /// fabric-scoped command `UNSUPPORTED_ACCESS` when there is no accessing fabric.
    pub fabric_index: Option<crate::msg::FabricIndex>,
    /// Whether the transport can carry Large Messages (§7.7.5) — that is, whether it is TCP.
    pub large_messages: bool,
    /// Whether the request asked for fabric filtering (§7.19.1.8.2).
    ///
    /// A fabric-scoped list read with filtering on reports only the accessing fabric's
    /// entries; with it off, the full list, each entry carrying its `FabricIndex` global
    /// field. `ReadRequest` and `SubscribeRequest` both carry the flag, and a cluster that
    /// ignored it would either leak every administrator's entries to one of them or hide from
    /// a verifier the entries §6.4.10 requires it to read.
    ///
    /// Defaults to `false` — the unfiltered, full-list reading, which is what
    /// `AttributePathIB`'s own default means.
    pub fabric_filtered: bool,
    /// Monotonic time, as of the moment the action started.
    ///
    /// Handed to the handler rather than read by it, because a cluster is not the thing that
    /// owns a clock — and because a single action must see a single instant: §11.10.7.2's
    /// fail-safe decides whether it is armed, re-arms it, and records progress, all of which
    /// must agree about *when*.
    ///
    /// Defaults to [`Instant::ZERO`](crate::platform::Instant::ZERO), which is correct for a
    /// node whose clusters have no deadlines — nothing consults it.
    pub now: crate::platform::Instant,
    /// Whether §6.4.10's Vendor ID Verification has been run against this peer.
    ///
    /// Only §11.25.6.1 consults it, and the default of `false` is the cautious one: a node that
    /// assumed verification had happened would cross-sign an intermediate CA for an ecosystem
    /// whose vendor nobody had checked.
    pub vendor_id_verified: bool,
    /// Which secure session this action arrived on.
    ///
    /// §11.18.6.7 scopes the CSR state to a session — "If no context or memory exists of a
    /// prior CSRRequest command having been invoked **in the same secure session** as that
    /// which is receiving this AddNOC or UpdateNOC invocation, then the Node SHALL … respond
    /// with a StatusCode of MissingCsr". Without this, one administrator's `CSRRequest` could
    /// be consumed by another's `AddNOC`.
    pub session: Option<crate::msg::SessionId>,
    /// The atomic write this action is part of, if any (§7.15.3).
    ///
    /// An attribute with the Atomic quality is writable *only* inside a claim covering it —
    /// §7.15.3: "If a server receives a Write Request for an attribute that is not associated
    /// with an Atomic Write State that is also associated with the client making the request,
    /// the server SHALL return the error code INVALID_IN_STATE." Derived by the caller from
    /// [`AtomicWrites::find`](crate::im::AtomicWrites::find), the same way `timed` is derived
    /// from the window table, and asserted here.
    pub atomic: Option<crate::im::atomic::ClaimRef<'a>>,
    /// The peer's operational Node ID, when the session authenticated one (§6.6.6.3).
    ///
    /// `None` on a PASE session, which has no node id — only a passcode. §6.6.6.1.3's
    /// Incoming Subject Descriptor is "deterministic based on both incoming message fields and
    /// session metadata fields", and this is the session's half: it is what CASE *proved*,
    /// never what a message claimed, which is the difference between an access decision and a
    /// suggestion from the sender.
    pub peer_node_id: Option<crate::msg::NodeId>,
    /// The session's `AttestationChallenge` — the third key it derived (§4.14.2.6.2).
    ///
    /// §11.18.4.7, §11.18.4.9 and §11.18.6.16 all sign over it, and it "SHALL NOT be included
    /// in any of the payloads conveyed": a signature made over it proves the signer is on
    /// *this* session, which is precisely what stops a recorded attestation being replayed.
    ///
    /// Borrowed rather than copied, because it is key material with a
    /// [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop) owner and there is no reason for a second
    /// copy to exist.
    pub attestation_challenge: Option<&'a crate::crypto::SymmetricKey>,
    /// The strongest privilege the ISD holds over this path (§6.6.6.2), when the caller
    /// computed one.
    ///
    /// The access check that admitted an action only proves the subject cleared the *required*
    /// bar. A few clusters need to know how far above it the subject actually is, because the
    /// specification gives administrators and managers different rules for the same command:
    /// §9.16.7.1's `RegisterClient` demands a verification key from a manager and ignores one
    /// from an administrator, so a server that could not tell them apart would either lock
    /// administrators out or let a manager overwrite any registration it liked.
    ///
    /// Derived by the caller from the same access decision that admitted the action — with
    /// [`Granted::highest`](crate::acl::Granted::highest) where the ACL engine is in use —
    /// the way `timed` and `atomic` are derived. `None` means the caller did not compute one,
    /// and a cluster that needs it must then take the cautious branch.
    pub privilege: Option<Privilege>,
    /// The group this action was addressed to, when it arrived as a groupcast (§4.15.3).
    ///
    /// `None` is a unicast. Several clusters branch on this rather than on anything in the
    /// payload: §1.3.7.1.2 says the Groups cluster "SHALL NOT generate an AddGroupResponse
    /// command" for a groupcast, and the reason is arithmetic — one multicast reaching twenty
    /// lights would otherwise draw twenty unicast responses at once, on a network chosen for
    /// low power rather than burst capacity.
    ///
    /// §8.8.2.2 also forbids a groupcast Invoke from carrying a concrete endpoint or expecting
    /// any response at all, so a cluster that answered anyway would be answering a request the
    /// client is not listening for.
    pub group: Option<crate::msg::GroupId>,
    /// §8.4.3.3 step 6.a.i's `EventFilters`, still encoded, as the request carried them.
    ///
    /// A client that already holds events up to some number sends this so the node does not
    /// resend them — the event log's equivalent of `DataVersionFilters`, and the only way a
    /// client resuming after a gap avoids re-reading the whole ring.
    pub event_filters: Option<&'a [u8]>,
    /// §8.4.3.2 step 3.a's `DataVersionFilters`, still encoded, as the request carried them.
    ///
    /// Kept as TLV rather than a decoded list because this type is `Copy` and the crate does
    /// not allocate: the filters are walked once per reported attribute, which is cheap for the
    /// handful a client sends and costs nothing when there are none.
    ///
    /// A client sends these to say "do not send me a cluster I already have", which is the
    /// only mechanism in the interaction model that makes a wildcard read cheap on a device
    /// that mostly has not changed. A server that decodes them and ignores them is correct
    /// about every value it sends and wrong about the bandwidth, on exactly the reads that
    /// matter most.
    pub data_version_filters: Option<&'a [u8]>,
}

impl Default for InteractionContext<'_> {
    /// The same as [`InteractionContext::new`], so the two cannot drift apart.
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> InteractionContext<'a> {
    /// The context of an action on an unauthenticated, untimed session.
    ///
    /// A starting point for the `with_*` builders. This is `const`, and the builders are too,
    /// because a device's fixed set of contexts is `const` data — and a `const` struct literal
    /// has to name every field, so every field added here would otherwise be a breaking change
    /// for anyone who wrote one.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            timed: false,
            fabric_index: None,
            large_messages: false,
            fabric_filtered: false,
            now: crate::platform::Instant::ZERO,
            session: None,
            atomic: None,
            peer_node_id: None,
            attestation_challenge: None,
            privilege: None,
            group: None,
            vendor_id_verified: false,
            data_version_filters: None,
            event_filters: None,
        }
    }

    /// Carries §8.4.3.3 step 6.a.i's `EventFilters`, as the request encoded them.
    #[must_use]
    pub const fn with_event_filters(mut self, filters: &'a [u8]) -> Self {
        self.event_filters = Some(filters);
        self
    }

    /// Carries §8.4.3.2 step 3.a's `DataVersionFilters`, as the request encoded them.
    #[must_use]
    pub const fn with_data_version_filters(mut self, filters: &'a [u8]) -> Self {
        self.data_version_filters = Some(filters);
        self
    }

    /// Marks the action as a groupcast addressed to `group` (§4.15.3).
    #[must_use]
    pub const fn with_group(mut self, group: crate::msg::GroupId) -> Self {
        self.group = Some(group);
        self
    }

    /// Records the strongest privilege the ISD holds over this path.
    #[must_use]
    pub const fn with_privilege(mut self, privilege: Privilege) -> Self {
        self.privilege = Some(privilege);
        self
    }

    /// Records that §6.4.10's Fabric Table Vendor ID Verification Procedure was run against
    /// the peer that sent this action.
    ///
    /// §11.25.6.1 is the one place that asks: `ICACCSRRequest` refuses with `JfVidNotVerified`
    /// until the peer has proved which vendor owns the fabric it is administering from. The
    /// procedure itself is a challenge and a signature over an exchange this layer does not
    /// see, so the answer comes in with the action rather than being derived here.
    #[must_use]
    pub const fn with_vendor_id_verified(mut self) -> Self {
        self.vendor_id_verified = true;
        self
    }

    /// Marks the action as part of a Timed transaction (§8.7.4).
    #[must_use]
    pub const fn timed(mut self) -> Self {
        self.timed = true;
        self
    }

    /// Sets the accessing fabric.
    #[must_use]
    pub const fn with_fabric(mut self, fabric_index: crate::msg::FabricIndex) -> Self {
        self.fabric_index = Some(fabric_index);
        self
    }

    /// Marks the transport as able to carry Large Messages (§7.7.5) — that is, TCP.
    #[must_use]
    pub const fn with_large_messages(mut self) -> Self {
        self.large_messages = true;
        self
    }

    /// Asks for §7.19.1.8.2's fabric filtering on a fabric-scoped list read.
    #[must_use]
    pub const fn fabric_filtered(mut self) -> Self {
        self.fabric_filtered = true;
        self
    }

    /// Sets the instant the action started.
    #[must_use]
    pub const fn at(mut self, now: crate::platform::Instant) -> Self {
        self.now = now;
        self
    }

    /// Sets the secure session this action arrived on.
    #[must_use]
    pub const fn on_session(mut self, session: crate::msg::SessionId) -> Self {
        self.session = Some(session);
        self
    }

    /// Marks this action as writing under an open atomic claim (§7.15.3).
    #[must_use]
    pub const fn under_claim(mut self, claim: crate::im::atomic::ClaimRef<'a>) -> Self {
        self.atomic = Some(claim);
        self
    }

    /// Sets the peer's operational Node ID, as CASE proved it (§6.6.6.3).
    #[must_use]
    pub const fn from_peer(mut self, peer_node_id: crate::msg::NodeId) -> Self {
        self.peer_node_id = Some(peer_node_id);
        self
    }

    /// Attaches the session's `AttestationChallenge` (§4.14.2.6.2).
    #[must_use]
    pub const fn with_attestation_challenge(
        mut self,
        challenge: &'a crate::crypto::SymmetricKey,
    ) -> Self {
        self.attestation_challenge = Some(challenge);
        self
    }
}

/// How far a read got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOutcome {
    /// How many reports were written.
    pub reports: usize,
    /// Whether the message filled before every path was served.
    ///
    /// When this is set the message carries `MoreChunkedMessages` (§10.2.3), which promises
    /// the client a continuation — so a caller that sets it must send one.
    /// [`Server::serve_chunk`] produces it; [`ReadCursor`] is where it resumes.
    pub truncated: bool,
    /// One past the highest event number this message carried, or `0` if it carried none.
    ///
    /// §8.5.3.4's bookmark: the next report over the same subscription starts here, so an event
    /// is delivered once. [`Server::report_chunk`] records it on the subscription itself, so
    /// [`Subscription::reported`](crate::im::subscription::Subscription::reported) does not ask
    /// a caller for a number only the server has.
    pub events_through: u64,
}

/// Where a chunked read stopped, and where its next message resumes.
///
/// Core §10.2.3 splits a report "into multiple messages at logical boundaries due to the
/// size limitations imposed by IPv6 for UDP packets", and §4.4.4 fixes that size at the
/// 1280-octet IPv6 minimum MTU. A whole-node wildcard does not fit in one message and is not
/// supposed to: it is chunked, "maximally packing" information blocks into each message,
/// with `MoreChunkedMessages` set on every message but the last.
///
/// A cursor is three positions: which request path is being served, how far into that path's
/// wildcard expansion, and — when one list attribute is itself too big for a message — how
/// many of its items have gone out. It is `Copy` and holds no borrows, so a device can park
/// one between messages while it waits for the `StatusResponse` that §10.2.3 requires
/// before the next chunk.
///
/// ```no_run
/// # use matter_kit::im::{ReadCursor, Server, AttributePath, InteractionContext};
/// # fn go<A: matter_kit::im::AccessControl, H: matter_kit::im::ClusterHandler>(
/// #     server: Server<'_, A, H>, paths: &[AttributePath],
/// #     scratch: &mut [u8], buf: &mut [u8]) -> Result<(), matter_kit::Error> {
/// let mut cursor = ReadCursor::START;
/// while !cursor.is_done() {
///     let (bytes, outcome) = server.serve_chunk(
///         paths.iter().copied().map(Ok), &InteractionContext::default(),
///         None, &mut cursor, scratch, buf)?;
///     send(bytes);
///     // §10.2.3: "each data message requires a response before the next data message
///     // can be sent" — await the StatusResponse here.
///     let _ = outcome;
/// }
/// # Ok(()) }
/// # fn send(_: &[u8]) {}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCursor {
    /// Which of the request's paths is being served.
    path: usize,
    /// How far into that path's wildcard expansion.
    expansion: crate::dm::ExpandCursor,
    /// How many items of an oversized list have been sent, once one is being split.
    list: Option<u32>,
    /// Which of the request's *event* paths is being served, and the lowest event number not
    /// yet reported from it.
    ///
    /// Separate from `path` because §10.7.3's `ReportData` carries two arrays and a series may
    /// end part-way through either. The number rather than an index because that is what
    /// resuming an event log means: records are identified by §7.14.1.1's monotonic number, and
    /// a record added between two chunks must not shift the position of the ones after it.
    event_path: usize,
    event_from: u64,
    /// Whether every path has been served.
    done: bool,
}

impl ReadCursor {
    /// Starts the event half of a report at `number` (§8.5.3.4's bookmark).
    pub const fn set_event_from(&mut self, number: u64) {
        self.event_from = number;
    }

    /// The lowest event number this cursor has **not** reported.
    ///
    /// For a device driving [`Server::serve_chunk_with_events`] itself. A subscription's
    /// bookmark is kept by the subscription — [`Server::report_chunk`] records it and
    /// [`Subscription::reported`](crate::im::Subscription::reported) applies it — so that it
    /// moves with what actually went out and no caller has to carry the number between the two.
    #[must_use]
    pub const fn event_from(&self) -> u64 {
        self.event_from
    }

    /// The start of a read: nothing served yet.
    pub const START: Self = Self {
        path: 0,
        expansion: crate::dm::ExpandCursor::START,
        list: None,
        event_path: 0,
        event_from: 0,
        done: false,
    };

    /// Whether the read is complete, so no further chunk is owed.
    ///
    /// This is the loop condition: a cursor becomes done on the message that does *not*
    /// carry `MoreChunkedMessages`.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }
}

impl Default for ReadCursor {
    fn default() -> Self {
        Self::START
    }
}

/// The members of an encoded list value, each yielded as its own raw TLV element.
///
/// Used to split a list too large for one message (§10.6.4.3.1). The items are yielded as
/// slices of the value already encoded in scratch, so splitting a list costs no second copy
/// of it — [`TlvWriter::raw_element_retagged`] does the re-tagging as it writes.
struct ListItems<'a> {
    reader: crate::tlv::TlvReader<'a>,
    done: bool,
}

impl<'a> ListItems<'a> {
    /// Reads `encoded` — one `Data [2]` element — as a list, or `None` if it is not one.
    fn new(encoded: &'a [u8]) -> Option<Self> {
        let mut reader = crate::tlv::TlvReader::new_in(encoded, ContainerKind::Structure);
        let first = reader.next_element().ok()??;
        if first.value.container() != Some(ContainerKind::Array) {
            return None;
        }
        Some(Self {
            reader,
            done: false,
        })
    }
}

impl<'a> Iterator for ListItems<'a> {
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let start = self.reader.position();
        let element = match self.reader.next_element() {
            Ok(Some(element)) => element,
            Ok(None) => {
                self.done = true;
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };
        if element.value == crate::tlv::Value::EndOfContainer {
            self.done = true;
            return None;
        }
        if let Err(e) = self.reader.skip_value(&element) {
            self.done = true;
            return Some(Err(e));
        }
        match self.reader.slice_from(start) {
            Ok(bytes) => Some(Ok(bytes)),
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// One message being packed, and the two limits that end it.
///
/// §10.2.3's boundary is a size — "maximally packing these information blocks (IBs) into a
/// series of 'data' messages" — so the real test of whether one more block fits is to write
/// it and see. [`TlvWriter::checkpoint`] makes that non-destructive: a block that does not
/// fit is rolled back, leaving the message that was already packed intact.
struct Chunk<'w, 'b> {
    w: &'w mut TlvWriter<'b>,
    reports: usize,
    limit: usize,
    /// Set when a block did not fit, which ends this message and saves a cursor.
    full: bool,
}

/// Writes one information block, undoing it if it does not fit.
///
/// A block that overruns the message must leave no trace: the writer documents that a failed
/// write leaves "the buffer's contents unspecified", so without the rollback the blocks
/// already packed would be corrupted and the whole action would have to fail. With it, a full
/// buffer is an ordinary boundary — the caller reports `truncated` and the message it has is
/// still valid.
///
/// `Ok(false)` means the message is full. Errors other than running out of room are real
/// failures and propagate.
fn put_block(
    w: &mut TlvWriter<'_>,
    responses: &mut usize,
    limit: usize,
    f: impl FnOnce(&mut TlvWriter<'_>) -> Result<()>,
) -> Result<bool> {
    if *responses >= limit {
        return Ok(false);
    }
    let checkpoint = w.checkpoint();
    match f(w) {
        Ok(()) => {
            *responses = responses.saturating_add(1);
            Ok(true)
        }
        Err(e) if e.code() == ErrorCode::BufferTooSmall => {
            w.rollback(&checkpoint);
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

impl Chunk<'_, '_> {
    /// Writes one information block, undoing it if it does not fit.
    ///
    /// `Ok(false)` means the message is full — the caller stops and records where.
    fn put(&mut self, f: impl FnOnce(&mut TlvWriter<'_>) -> Result<()>) -> Result<bool> {
        let mut reports = self.reports;
        let fitted = put_block(self.w, &mut reports, self.limit, f)?;
        self.reports = reports;
        if !fitted {
            self.full = true;
        }
        Ok(fitted)
    }

    /// Whether anything has been packed into this message yet.
    ///
    /// A message that fills before its *first* block would make no progress, and the read
    /// would never terminate. That is the case §10.6.4.3.1's list encoding exists for, and
    /// failing that the one `RESOURCE_EXHAUSTED` answers.
    const fn is_empty(&self) -> bool {
        self.reports == 0
    }
}

/// A server that answers interactions against one node.
///
/// The node, the access control and the cluster handler are all long-lived — a device has
/// one of each for its whole life — so they are held here rather than threaded through every
/// call. What varies per interaction is the paths and the buffers.
#[derive(Debug, Clone, Copy)]
pub struct Server<'a, A, H> {
    /// The data model being served.
    pub node: Node<'a>,
    /// Who is asking, and what they may have.
    pub access: &'a A,
    /// The device's clusters.
    pub handler: &'a H,
    /// The most reports one message may carry, on top of what fits in its buffer.
    ///
    /// A second, coarser bound than the buffer: both end a chunk, whichever comes first, and
    /// neither loses anything, because [`Server::serve_chunk`] resumes from a
    /// [`ReadCursor`]. Bounding a message by *bytes* is what §10.2.3 actually asks for, so
    /// `usize::MAX` here is a reasonable choice — the buffer decides. A smaller value is for
    /// bounding the work a single response costs the peer that must parse it.
    pub limit: usize,
    /// §7.10.3's cluster data versions, for every cluster that does not track its own.
    ///
    /// `None` means a report carries a `DataVersion` only where a cluster supplied one. That is
    /// legal — §10.6.4.1 makes the field omissible — and it is also how a node ends up
    /// uncommissionable: the CHIP SDK's cluster-state cache is keyed by version and silently
    /// drops an attribute that arrives without one, so a commissioner receives every attribute
    /// it asked for and then reports each as missing. Give the server a table.
    pub versions: Option<&'a dyn crate::dm::DataVersionSource>,
    /// §7.14's event log, for the `EventRequests` half of a read or subscription.
    ///
    /// `None` is a node that reports no events, which is legal — §8.4.3.3 step 5 makes an
    /// empty `EventRequests` an empty answer — and is the wrong answer for any node whose
    /// clusters define events, because the client is told the log is empty rather than that
    /// nobody is serving it.
    pub events: Option<&'a dyn crate::dm::events::EventSource>,
}

impl<'a, A: AccessControl, H: ClusterHandler> Server<'a, A, H> {
    /// A server over a node.
    #[must_use]
    pub const fn new(node: Node<'a>, access: &'a A, handler: &'a H, limit: usize) -> Self {
        Self {
            node,
            access,
            handler,
            limit,
            versions: None,
            events: None,
        }
    }

    /// Supplies §7.10.3's data versions for clusters that do not track their own.
    ///
    /// A cluster's own [`ClusterHandler::data_version`] still wins where it returns `Some`: a
    /// cluster that knows when its data changed knows better than a table that is only told
    /// about writes arriving over the wire.
    #[must_use]
    pub const fn with_data_versions(
        mut self,
        versions: &'a dyn crate::dm::DataVersionSource,
    ) -> Self {
        self.versions = Some(versions);
        self
    }

    /// Supplies §7.14's event log, so a read or subscription can answer `EventRequests`.
    ///
    /// Without it every event path is answered as though the node had recorded nothing, which
    /// a client cannot tell from a node that genuinely has.
    #[must_use]
    pub const fn with_events(mut self, events: &'a dyn crate::dm::events::EventSource) -> Self {
        self.events = Some(events);
        self
    }

    /// Serves one request path into an open `AttributeReports` array, resuming at `cursor`.
    ///
    /// Follows §8.4.3.2 step 1 exactly: a concrete path gets a status on failure, an expanded
    /// one is discarded.
    ///
    /// Returns `true` when the path was served to the end, `false` when the message filled
    /// first — in which case `cursor` names where to carry on.
    fn serve_path_chunked(
        &self,
        path: &AttributePath,
        ctx: &InteractionContext<'_>,
        chunk: &mut Chunk<'_, '_>,
        cursor: &mut ReadCursor,
        scratch: &mut [u8],
    ) -> Result<bool> {
        // §10.6.2.1's tag compression is provisional and not resolved here. A path that sets
        // it has fields whose meaning depends on an earlier path in the same action, and
        // treating an inherited field as a wildcard would read the path as far broader than
        // it says.
        //
        // How it is refused depends on whether it *can* be named. §8.2.1 requires that "each
        // path indicated by the Report Data action SHALL be a Concrete Path", so a status
        // may only carry a path that is one:
        //
        // * All of endpoint, cluster and attribute present — nothing is omitted, so nothing
        //   would be inherited and the flag is inert. The path can be named, so it is,
        //   with `INVALID_ACTION`.
        // * Anything missing — its value "SHALL be set to the value for that tag in the last
        //   AttributePathIB that had EnableTagCompression not present or set to false", which
        //   this crate does not track, and which §10.6.2.1 says "MAY still be missing. In
        //   that case … they indicate wildcard semantics". So it cannot be named concretely,
        //   and echoing it would put a wildcard in a report. It is discarded instead —
        //   §8.4.3.2 step 1c's treatment of any expanded path that cannot be served.
        if path.enable_tag_compression {
            return if path.concrete().is_some() {
                self.write_status(chunk, path, Status::InvalidAction)
            } else {
                Ok(true)
            };
        }

        match path.concrete() {
            Some(concrete) => {
                // A concrete path is one attribute, but that attribute may still be a list
                // too large for a message, so it carries the list cursor too.
                self.serve_concrete(path, concrete, ctx, chunk, cursor, scratch)
            }
            None => {
                let mut expand = self.node.expand_from(path, cursor.expansion);
                loop {
                    // Taken *before* the step, so a path that does not fit is resumed rather
                    // than skipped.
                    let resume = expand.cursor();
                    let Some(resolved) = expand.next() else {
                        cursor.expansion = crate::dm::ExpandCursor::START;
                        return Ok(true);
                    };
                    let concrete = resolved.path();
                    let Some(descriptor) = resolved.cluster.attribute(resolved.attribute) else {
                        continue;
                    };
                    // §8.4.3.2 step c.i: "If the path indicates attribute data that is not
                    // readable, then the path SHALL be discarded."
                    let Some(required) = descriptor.access.read else {
                        continue;
                    };
                    // step c.ii: "If the outcome is either AccessDenied or AccessRestricted,
                    // then the path SHALL be discarded." No status — silence is the point.
                    if self.access.allows(&concrete, required) != Outcome::Granted {
                        continue;
                    }
                    if !self.write_data(&resolved, ctx, chunk, cursor, scratch)? {
                        cursor.expansion = resume;
                        return Ok(false);
                    }
                }
            }
        }
    }

    fn serve_concrete(
        &self,
        path: &AttributePath,
        concrete: (
            crate::im::EndpointId,
            crate::im::ClusterId,
            crate::im::AttributeId,
        ),
        ctx: &InteractionContext<'_>,
        chunk: &mut Chunk<'_, '_>,
        cursor: &mut ReadCursor,
        scratch: &mut [u8],
    ) -> Result<bool> {
        let (endpoint, cluster, attribute) = concrete;
        // §8.4.3.2 step b.i — the *first* check, at View, before existence is examined. This
        // is what stops the existence checks below from telling a subject with no access at
        // all which clusters a node has.
        if let Some(status) = self.access.allows(path, Privilege::View).status() {
            return self.write_status(chunk, path, status);
        }

        // step b.ii — existence, level by level, each with its own status.
        let resolved = match self.node.resolve(endpoint, cluster, attribute) {
            Ok(resolved) => resolved,
            Err(missing) => return self.write_status(chunk, path, missing.status()),
        };
        let Some(descriptor) = resolved.cluster.attribute(attribute) else {
            return self.write_status(chunk, path, Status::UnsupportedAttribute);
        };
        // step b.ii.E — "an attribute that is not readable" is UNSUPPORTED_READ, which is a
        // different answer from "does not exist".
        let Some(required) = descriptor.access.read else {
            return self.write_status(chunk, path, Status::UnsupportedRead);
        };

        // step b.iii — the second check, at the attribute's actual privilege.
        if let Some(status) = self.access.allows(path, required).status() {
            return self.write_status(chunk, path, status);
        }

        self.write_data(&resolved, ctx, chunk, cursor, scratch)
    }

    /// §8.4.3.2 step 3.a: whether the requester already holds this cluster's data.
    ///
    /// > "If the DataVersionFilters field indicates DataVersionFilterIB entries with a Path
    /// > field that matches the path, where **all** matching entries have a DataVersion field
    /// > that matches the data version of the cluster instance in the path, then the path
    /// > SHALL be ignored"
    ///
    /// The quantifier is the whole rule, and `any` is the natural way to get it wrong. A client
    /// that sends two filters for one cluster with different versions has contradicted itself,
    /// and only one of those versions can be the one it holds — so it is told nothing and sent
    /// the data. `all` over an empty set is vacuously true, which would ignore *every* path, so
    /// a match must also exist: `matched` is what separates "no filter mentions this cluster"
    /// from "every filter that does, agrees".
    ///
    /// A path is *ignored*, not refused: no `AttributeDataIB` and no status. The requester
    /// already has the value and asked not to be told again.
    fn already_held(
        &self,
        resolved: &crate::dm::Resolved<'_>,
        ctx: &InteractionContext<'_>,
        data_version: Option<u32>,
    ) -> bool {
        let (Some(filters), Some(version)) = (ctx.data_version_filters, data_version) else {
            return false;
        };
        let Ok(entries) = crate::im::ArrayIter::new(
            filters,
            ContainerKind::Structure,
            crate::im::DataVersionFilter::decode,
        ) else {
            // Filters this node cannot read are filters it cannot honour. Sending the data is
            // the safe direction: the requester gets something it may already have, rather than
            // silently not getting something it does not.
            return false;
        };
        let mut matched = false;
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            // §10.6.2's `ClusterPathIB`. An absent field matches anything, which is what makes
            // "every cluster on endpoint 0" expressible. `node` is not checked: a message that
            // reached this node is for this node.
            let path = &entry.path;
            if path.endpoint.is_some_and(|e| e != resolved.endpoint)
                || path.cluster.is_some_and(|c| c != resolved.cluster.id)
            {
                continue;
            }
            matched = true;
            if entry.data_version != version {
                return false;
            }
        }
        matched
    }

    /// Writes one `AttributeDataIB`, or the status the cluster answered with.
    fn write_data(
        &self,
        resolved: &crate::dm::Resolved<'_>,
        ctx: &InteractionContext<'_>,
        chunk: &mut Chunk<'_, '_>,
        cursor: &mut ReadCursor,
        scratch: &mut [u8],
    ) -> Result<bool> {
        let path = resolved.path();
        // The cluster's own answer first; the node's table where it has none. §7.10.3 requires
        // a version per cluster instance, and a report without one is one the CHIP SDK discards.
        let data_version = self.handler.data_version(resolved).or_else(|| {
            self.versions
                .map(|v| v.version(resolved.endpoint, resolved.cluster.id))
        });

        // §8.4.3.2 step 3.a, applied after the existence and access checks of step 2 — the
        // filter decides what to *send*, never what exists or who may see it.
        if self.already_held(resolved, ctx, data_version) {
            return Ok(true);
        }

        // The value is built beside the message so that a cluster which runs out of room, or
        // refuses, leaves no half-written element in the report.
        let mut value = TlvWriter::new_in(scratch, ContainerKind::Structure);
        let global_written = crate::dm::global::encode(
            resolved.cluster,
            resolved.attribute,
            &mut value,
            Tag::Context(2),
        )?;
        if !global_written
            && let Err(status) = self
                .handler
                .read(resolved, ctx, &mut value, Tag::Context(2))
        {
            return self.write_status(chunk, &path, status);
        }
        let Ok(encoded) = value.finish() else {
            // A cluster that wrote nothing, or something unfinished, is a bug in the cluster
            // — but it must not corrupt the report, so it becomes a status like any other
            // refusal.
            return self.write_status(chunk, &path, Status::Failure);
        };

        // The ordinary case: the whole value fits in one block, which §10.6.4.3.1 says
        // SHOULD be preferred "when it is possible to encode the entirety of the list in a
        // single AttributeDataIB that fits in a single message".
        if cursor.list.is_none() {
            let fitted = chunk.put(|w| {
                AttributeReport::Data(AttributeData {
                    data_version,
                    path,
                    data: encoded,
                })
                .encode(w)
            })?;
            if fitted {
                return Ok(true);
            }
            // It did not fit. If this message already carries something, the next one gets
            // a clean try at the whole value; only a value too big for an *empty* message
            // has to be split.
            if !chunk.is_empty() {
                return Ok(false);
            }
        }

        self.write_list_in_chunks(&path, data_version, encoded, chunk, cursor)
    }

    /// Splits one oversized list attribute across messages (§10.6.4.3.1).
    ///
    /// The spec's second encoding: "a series of AttributeDataIBs, with the first containing a
    /// path to the list itself and Data that is an empty array, which signals clearing the
    /// list, and subsequent AttributeDataIBs each containing a path to each list item with
    /// ListIndex being null, in order, and Data that contains the value of the list item."
    /// It is what §10.6.4.3.1 says SHOULD be used "when it is NOT possible to encode the
    /// entirety of the list in a single AttributeDataIB that fits in a single message".
    ///
    /// A value that is not a list cannot be split at all, and a single item that will not fit
    /// an empty message cannot either. Both would leave the read unable to make progress, so
    /// both answer `RESOURCE_EXHAUSTED` (§8.10.1) for that path and move on.
    fn write_list_in_chunks(
        &self,
        path: &AttributePath,
        data_version: Option<u32>,
        encoded: &[u8],
        chunk: &mut Chunk<'_, '_>,
        cursor: &mut ReadCursor,
    ) -> Result<bool> {
        let Some(items) = ListItems::new(encoded) else {
            // Not a list: nothing to split along. Telling the client the value exists but
            // cannot be sent is the honest answer, and it keeps the read moving.
            cursor.list = None;
            return self.write_status(chunk, path, Status::ResourceExhausted);
        };

        // Step one, once per list: the empty array that clears it.
        if cursor.list.is_none() {
            let fitted = chunk.put(|w| {
                let mut empty = [0u8; 4];
                let mut v = TlvWriter::new_in(&mut empty, ContainerKind::Structure);
                v.start_array(Tag::Context(2))?;
                v.end_container()?;
                let empty = v.finish()?;
                AttributeReport::Data(AttributeData {
                    data_version,
                    path: *path,
                    data: empty,
                })
                .encode(w)
            })?;
            if !fitted {
                return Ok(false);
            }
            cursor.list = Some(0);
        }

        // Step two: one block per item, with `ListIndex` null — §10.6.4.3.1's ADD.
        let sent = cursor.list.unwrap_or(0);
        for (index, item) in items.enumerate().skip(sent as usize) {
            let item = item?;
            let mut append = *path;
            append.list_index = Some(crate::im::ListIndex::Append);
            // Written out by hand rather than through `AttributeData`, because the item is
            // an anonymous member of the array it came from and has to be re-tagged into the
            // `Data [2]` slot on the way out.
            let fitted = chunk.put(|w| {
                w.start_structure(Tag::Anonymous)?;
                w.start_structure(Tag::Context(1))?;
                if let Some(version) = data_version {
                    w.unsigned(Tag::Context(0), u64::from(version))?;
                }
                append.encode(w, Tag::Context(1))?;
                w.raw_element_retagged(item, Tag::Context(2))?;
                w.end_container()?;
                w.end_container()
            })?;
            if !fitted {
                if chunk.is_empty() {
                    // One item alone will not fit an empty message. Nothing can send it, so
                    // say so rather than loop forever.
                    cursor.list = None;
                    return self.write_status(chunk, path, Status::ResourceExhausted);
                }
                cursor.list = Some(u32::try_from(index).unwrap_or(u32::MAX));
                return Ok(false);
            }
        }
        cursor.list = None;
        Ok(true)
    }

    fn write_status(
        &self,
        chunk: &mut Chunk<'_, '_>,
        path: &AttributePath,
        status: Status,
    ) -> Result<bool> {
        chunk.put(|w| {
            AttributeReport::Status(AttributeStatus {
                path: *path,
                status: StatusIb::new(status),
            })
            .encode(w)
        })
    }

    /// Whether any path in `paths` survives §8.4.3.2's steps 1 and 2 — exists, and the subject
    /// may read it.
    ///
    /// §8.4.3 step 2: "If no error-free existent paths remain, then AttributeRequests are
    /// considered empty", and step 7.a makes an empty Subscribe `INVALID_ACTION`. So a
    /// subscription to a cluster the subscriber cannot read is not an empty subscription that
    /// reports nothing — it is a malformed action, and answering it with a `SubscribeResponse`
    /// tells the subscriber it will hear about something it will never hear about.
    pub fn any_readable(
        &self,
        paths: impl IntoIterator<Item = Result<AttributePath>>,
    ) -> Result<bool> {
        for path in paths {
            let path = path?;
            for resolved in self.node.expand(&path) {
                let Some(descriptor) = resolved.cluster.attribute(resolved.attribute) else {
                    continue;
                };
                let Some(required) = descriptor.access.read else {
                    continue;
                };
                if self
                    .access
                    .allows(&resolved.path(), required)
                    .status()
                    .is_none()
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Serves one event request path into an open `EventReports` array (§8.4.3.3).
    ///
    /// Mirrors [`Server::serve_path_chunked`] and its asymmetry: a *concrete* path that names
    /// something this node does not have gets an `EventStatusIB`, an *expanded* one is
    /// discarded. A client that asked for a specific event deserves to know it does not exist;
    /// one that asked for "every event on the node" does not want a status for every cluster
    /// that has none.
    ///
    /// Returns `false` when the message filled, leaving `from` at the first record not yet
    /// reported.
    fn serve_event_path(
        &self,
        path: &crate::im::EventPath,
        ctx: &InteractionContext<'_>,
        chunk: &mut Chunk<'_, '_>,
        from: &mut u64,
    ) -> Result<bool> {
        let concrete = path.endpoint.zip(path.cluster).zip(path.event);
        if let Some(((endpoint, cluster), event)) = concrete {
            match self.node.resolve_event(endpoint, cluster, event) {
                Err(missing) => {
                    let status = match missing {
                        crate::dm::Missing::Endpoint => Status::UnsupportedEndpoint,
                        crate::dm::Missing::Cluster => Status::UnsupportedCluster,
                        crate::dm::Missing::Attribute => Status::UnsupportedEvent,
                    };
                    return self.write_event_status(chunk, path, status);
                }
                Ok(resolved) => {
                    // §8.4.3.3 step 4: the access check is the event's own, and a path the
                    // subject may not read is refused rather than silently empty.
                    if let Some(required) = resolved.event.access.read {
                        let attribute_path = AttributePath::attribute(endpoint, cluster, 0);
                        if let Some(status) = self.access.allows(&attribute_path, required).status()
                        {
                            return self.write_event_status(chunk, path, status);
                        }
                    }
                }
            }
        }

        let Some(source) = self.events else {
            // No log to read. An expanded path says nothing; a concrete one has already been
            // resolved above, so the honest answer is that there are no records.
            return Ok(true);
        };

        // §8.4.3.3 step 6.a: every queued record, lowest number first, minus the three
        // exceptions — the event filter (6.a.i), the path (6.a.ii) and fabric sensitivity
        // (6.a.iii). The store applies the last two; `min_number` is the first.
        // §8.4.3.3 step 6.a.i: "If the node indicated matches the Node information field of an
        // EventFilterIB from EventFilters, and the event number is less than the EventMin
        // field in the EventFilterIB" — the record is not reported.
        //
        // Several filters raise the floor together: the highest `EventMin` that applies wins,
        // because a record below *any* of them is excluded by that one.
        let floor = (*from).max(self.event_floor(ctx));
        let mut fitted = true;
        let mut next = floor;
        // §10.6.9.1 and §10.6.9.2's delta forms, against "the previous record" — which here
        // means the `EventDataIB` immediately before this one in the array. Records inside one
        // path's run are written consecutively, so the previous one is exactly that; the first
        // record of each run has nothing before it and takes the absolute form.
        //
        // The saving is real on the networks this crate targets: a system timestamp is
        // milliseconds since boot and grows without bound, while the gap between two records in
        // one report is usually small enough to encode in one or two octets.
        let mut previous: Option<crate::dm::events::Timestamp> = None;
        source.each_matching(path, ctx.fabric_index, floor, &mut |record| {
            let data = crate::im::EventData {
                path: crate::im::EventPath {
                    node: None,
                    endpoint: Some(record.endpoint),
                    cluster: Some(record.cluster),
                    event: Some(record.event),
                    is_urgent: None,
                },
                number: record.number,
                priority: record.priority as u8,
                timestamp: previous
                    .and_then(|before| record.timestamp.delta_from(before))
                    .unwrap_or_else(|| record.timestamp.absolute()),
                data: &record.data,
            };
            match chunk.put(|w| crate::im::EventReport::Data(data).encode(w)) {
                Ok(true) => {
                    next = record.number.saturating_add(1);
                    previous = Some(record.timestamp);
                    true
                }
                Ok(false) | Err(_) => {
                    fitted = false;
                    false
                }
            }
        });
        *from = next;
        Ok(fitted)
    }

    /// The lowest event number §8.4.3.3 step 6.a.i lets this request see.
    ///
    /// Only entries that omit `Node` are applied. §10.6.6 says the tag "MAY be omitted if the
    /// target node of the path matches the NodeID of the server involved in the interaction",
    /// so an absent `Node` means *this* node and is the ordinary encoding. An entry naming a
    /// node cannot be checked here — the server does not know which of its fabrics' node ids
    /// the client meant — and the safe direction is to ignore it: an event sent twice is
    /// recoverable, one silently withheld is not.
    fn event_floor(&self, ctx: &InteractionContext<'_>) -> u64 {
        let Some(filters) = ctx.event_filters else {
            return 0;
        };
        let Ok(entries) = crate::im::ArrayIter::new(
            filters,
            ContainerKind::Structure,
            crate::im::EventFilter::decode,
        ) else {
            return 0;
        };
        let mut floor = 0;
        for entry in entries {
            let Ok(entry) = entry else {
                return 0;
            };
            if entry.node.is_none() {
                floor = floor.max(entry.event_min);
            }
        }
        floor
    }

    /// Writes one `EventStatusIB`.
    fn write_event_status(
        &self,
        chunk: &mut Chunk<'_, '_>,
        path: &crate::im::EventPath,
        status: Status,
    ) -> Result<bool> {
        chunk.put(|w| {
            crate::im::EventReport::Status(crate::im::EventStatus {
                path: *path,
                status: StatusIb::new(status),
            })
            .encode(w)
        })
    }

    /// Serves a whole `ReadRequest` into a **single** `ReportData` message.
    ///
    /// For reads known to be small. A read that does not fit is
    /// [`ErrorCode::ReportWouldChunk`] rather than a truncated message: a single message
    /// cannot honour `MoreChunkedMessages`, and emitting one anyway would promise the client
    /// a continuation that never arrives. Serve such a read with [`Server::serve_chunk`],
    /// which is the same processing across as many messages as it takes.
    ///
    /// A whole-node wildcard on any real device does not fit, so a server answering arbitrary
    /// client reads wants `serve_chunk` and not this.
    pub fn serve<'b>(
        &self,
        paths: impl IntoIterator<Item = Result<AttributePath>>,
        ctx: &InteractionContext<'_>,
        subscription_id: Option<u32>,
        scratch: &mut [u8],
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        let mut cursor = ReadCursor::START;
        let (bytes, outcome) =
            self.serve_chunk(paths, ctx, subscription_id, &mut cursor, scratch, buf)?;
        if outcome.truncated {
            bail!(ReportWouldChunk)
        }
        Ok((bytes, outcome))
    }

    /// Serves one message of a `ReadRequest`, resuming at `cursor` (§10.2.3).
    ///
    /// Packs as many information blocks into `buf` as fit, then stops on a block boundary
    /// and records where in `cursor`. When more remains the message carries
    /// `MoreChunkedMessages` and `ReadOutcome::truncated` is set; call again with the same
    /// `cursor` for the next message. The read is over when
    /// [`ReadCursor::is_done`] is true, which happens on the message that does *not* set the
    /// flag.
    ///
    /// §10.2.3 requires the client's `StatusResponse` between messages — "each data message
    /// requires a response before the next data message can be sent" — so the loop is driven
    /// by the exchange, not by this call.
    ///
    /// Forward progress is guaranteed: a value too large for an empty message is either split
    /// per §10.6.4.3.1 when it is a list, or answered `RESOURCE_EXHAUSTED` when it cannot be
    /// split. So the loop always terminates, whatever a cluster returns.
    pub fn serve_chunk<'b>(
        &self,
        paths: impl IntoIterator<Item = Result<AttributePath>>,
        ctx: &InteractionContext<'_>,
        subscription_id: Option<u32>,
        cursor: &mut ReadCursor,
        scratch: &mut [u8],
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        self.serve_chunk_with_events(
            paths,
            core::iter::empty::<Result<crate::im::EventPath>>(),
            ctx,
            subscription_id,
            cursor,
            scratch,
            buf,
        )
    }

    /// One message of a read that asks for **both** attributes and events (§10.7.3).
    ///
    /// A `ReportData` carries two arrays, and §8.4.3 processes `AttributeRequests` and
    /// `EventRequests` as two halves of one action. They chunk together: attributes first,
    /// then events, with the cursor remembering which half a series stopped in. A node that
    /// served only the first half would answer every `EventRequests` as though its log were
    /// empty — which a client cannot tell from a node that has genuinely recorded nothing.
    ///
    /// [`Server::serve_chunk`] is this with no event paths.
    #[allow(clippy::too_many_arguments)]
    pub fn serve_chunk_with_events<'b>(
        &self,
        paths: impl IntoIterator<Item = Result<AttributePath>>,
        events: impl IntoIterator<Item = Result<crate::im::EventPath>>,
        ctx: &InteractionContext<'_>,
        subscription_id: Option<u32>,
        cursor: &mut ReadCursor,
        scratch: &mut [u8],
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        if let Some(id) = subscription_id {
            w.unsigned(Tag::Context(0), u64::from(id))?;
        }
        w.start_array(Tag::Context(1))?;

        let start = cursor.path;
        let mut truncated = false;
        let mut events_closed = false;
        let mut events_through = 0u64;
        // Scoped so the writer is free again for the `EventReports` array below: a `Chunk`
        // borrows it for as long as it lives.
        let mut reports;
        {
            let mut chunk = Chunk {
                w: &mut w,
                reports: 0,
                limit: self.limit,
                full: false,
            };
            for (index, path) in paths.into_iter().enumerate() {
                let path = path?;
                // Paths served by an earlier message of this same action.
                if index < start {
                    continue;
                }
                cursor.path = index;
                if !self.serve_path_chunked(&path, ctx, &mut chunk, cursor, scratch)? {
                    truncated = true;
                    break;
                }
                // Finished: the next message starts at the next path, not inside this one.
                cursor.path = index.saturating_add(1);
                cursor.expansion = crate::dm::ExpandCursor::START;
                cursor.list = None;
            }
            reports = chunk.reports;
        }
        // §10.7.3: `AttributeReports` closes before `EventReports` opens — two arrays, in tag
        // order. Events are served only once the attribute half has finished, because a series
        // that stopped mid-attribute must resume there, and a `ReportData` whose second array
        // ran ahead of its first would deliver events for a state the client has not been sent.
        if !truncated {
            w.end_container()?;
            let mut opened = false;
            let mut event_chunk = Chunk {
                w: &mut w,
                reports,
                limit: self.limit,
                full: false,
            };
            for (index, path) in events.into_iter().enumerate() {
                let path = path?;
                if index < cursor.event_path {
                    continue;
                }
                if !opened {
                    event_chunk.w.start_array(Tag::Context(2))?;
                    opened = true;
                }
                cursor.event_path = index;
                let mut from = cursor.event_from;
                let fitted = self.serve_event_path(&path, ctx, &mut event_chunk, &mut from)?;
                cursor.event_from = from;
                // The bookmark is the highest position reached across every path in the
                // message, not the last path's: `cursor.event_from` is reset per path below,
                // so reading it at the end would give whatever the final path happened to
                // leave — usually zero.
                events_through = events_through.max(from);
                if !fitted {
                    truncated = true;
                    break;
                }
                cursor.event_path = index.saturating_add(1);
                cursor.event_from = 0;
            }
            reports = event_chunk.reports;
            if opened {
                w.end_container()?;
            }
            events_closed = true;
        }

        if truncated && reports == 0 {
            // Chunking makes progress by putting at least one block in every message. A
            // message that ends empty and still has more to say has made none, so the cursor
            // has not moved and a caller looping until `is_done` would loop forever. The
            // buffer is simply too small to hold any block this read produces, and no series
            // of messages fixes that — every other reason a block does not fit is handled
            // before here, by splitting the value or refusing its path.
            bail!(BufferTooSmall)
        }

        if !events_closed {
            w.end_container()?;
        }
        if truncated {
            // §10.2.3: "A MoreChunkedMessages flag SHALL be set on every data message except
            // the last." §10.7.3.2 adds that SuppressResponse must then be false, which it is
            // — it is not written at all, and its default is false.
            w.bool(Tag::Context(3), true)?;
        } else {
            cursor.done = true;
        }
        w.unsigned(
            Tag::Context(crate::im::REVISION_TAG),
            u64::from(crate::im::INTERACTION_MODEL_REVISION),
        )?;
        w.end_container()?;
        let bytes = w.finish()?;
        Ok((
            bytes,
            ReadOutcome {
                reports,
                truncated,
                events_through,
            },
        ))
    }
}

/// The access decision a Write Request action has already taken, and for which path.
///
/// §10.6.4.3.1's way of writing a whole list is "a series of AttributeDataIBs, with the first
/// containing a path to the list itself and Data that is empty array, which signals clearing
/// the list, and subsequent AttributeDataIBs containing updates" — every one of them naming the
/// same attribute. On one attribute that idiom revokes the writer's own access half-way through:
/// clearing the `ACL` list removes the administrator entry the writer is administering *with*,
/// so §8.7.3.2 step b.iii fails on the second AttributeDataIB and the node is left with an
/// empty list and no administrator at all.
///
/// So the decision is taken once per concrete path per action, on the first AttributeDataIB that
/// names it, and reused by the rest. This cannot widen anybody's access: the grant it reuses was
/// checked against the ACL as it stood when the action began, which is the state the client's
/// request was composed against.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteAction {
    granted: Option<(
        crate::im::EndpointId,
        crate::im::ClusterId,
        crate::im::AttributeId,
    )>,
}

impl WriteAction {
    /// Nothing written yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { granted: None }
    }

    const fn already_granted(
        &self,
        endpoint: crate::im::EndpointId,
        cluster: crate::im::ClusterId,
        attribute: crate::im::AttributeId,
    ) -> bool {
        match self.granted {
            Some((e, c, a)) => e == endpoint && c == cluster && a == attribute,
            None => false,
        }
    }

    const fn grant(
        &mut self,
        endpoint: crate::im::EndpointId,
        cluster: crate::im::ClusterId,
        attribute: crate::im::AttributeId,
    ) {
        self.granted = Some((endpoint, cluster, attribute));
    }
}

// --- Write (§8.7.3.2) ---------------------------------------------------------------------------

impl<A: AccessControl, H: ClusterHandler> Server<'_, A, H> {
    /// Serves one write path into an already-open `WriteResponses` array.
    ///
    /// §8.7.3.2 mirrors §8.4.3.2 step for step — the same concrete/expanded asymmetry, the
    /// same two-stage access check — with three checks a read does not have:
    ///
    /// * step b.iv: an attribute with the `T` quality needs a Timed transaction
    ///   (`NEEDS_TIMED_INTERACTION`);
    /// * step b.v: a fabric-scoped attribute needs an accessing fabric
    ///   (`UNSUPPORTED_ACCESS`);
    /// * step b.vi: a `DataVersion` that disagrees with the cluster's
    ///   (`DATA_VERSION_MISMATCH`).
    ///
    /// And one difference in what is reported: §8.7.3.3 step 2.b.ii generates a
    /// `SUCCESS` status for every path that was written, where a read reports success by
    /// returning data. So a write response is never empty unless everything was discarded.
    pub fn serve_write_path(
        &self,
        data: &AttributeData<'_>,
        ctx: &InteractionContext<'_>,
        action: &mut WriteAction,
        w: &mut TlvWriter<'_>,
        responses: &mut usize,
    ) -> Result<bool> {
        let path = data.path;
        // The same rule as a read's, and for the same reason: §8.7.3.3's responses name
        // concrete paths, so a tag-compressed path is refused by name only when it already
        // is one, and otherwise discarded rather than echoed with its wildcards.
        if path.enable_tag_compression {
            return if path.concrete().is_some() {
                self.write_response_status(w, &path, Status::InvalidAction, responses)
            } else {
                Ok(true)
            };
        }

        // §10.6.4.3.1: "ListIndex is currently only allowed to be omitted or null. Any other
        // value SHALL be interpreted as an error." Checked once, here, so neither branch
        // below can act on a path whose meaning the specification does not define.
        let Some(op) = WriteOp::of(&path) else {
            return if path.concrete().is_some() {
                self.write_response_status(w, &path, Status::InvalidAction, responses)
            } else {
                // The same concrete-path rule as above: a status may only name a path that
                // is concrete, so a wildcard carrying a bad ListIndex is discarded.
                Ok(true)
            };
        };

        match path.concrete() {
            Some((endpoint, cluster, attribute)) => self.write_concrete(
                data, endpoint, cluster, attribute, op, ctx, action, w, responses,
            ),
            None => {
                for resolved in self.node.expand(&path) {
                    let concrete = resolved.path();
                    let Some(descriptor) = resolved.cluster.attribute(resolved.attribute) else {
                        continue;
                    };
                    // step c.i: "If the path indicates attribute data that is not writable,
                    // then the path SHALL be discarded."
                    let Some(required) = descriptor.access.write else {
                        continue;
                    };
                    // step c.ii: denied or restricted — discarded, with no status.
                    if self.access.allows(&concrete, required) != Outcome::Granted {
                        continue;
                    }
                    // step c.iii: a Timed-only attribute outside a Timed transaction.
                    if descriptor.access.needs_timed() && !ctx.timed {
                        continue;
                    }
                    // §7.15.3: an atomic attribute is writable only inside a claim. An
                    // expanded path is discarded rather than answered, per step 1c.
                    if descriptor.qualities.contains(AttributeQualities::ATOMIC)
                        && !ctx.atomic.is_some_and(|claim| {
                            claim.covers(resolved.endpoint, resolved.cluster.id, resolved.attribute)
                        })
                    {
                        continue;
                    }
                    let status = match self.handler.write(&resolved, data.data, op, ctx) {
                        Ok(()) => Status::Success,
                        Err(status) => status,
                    };
                    if !self.write_response_status(w, &concrete, status, responses)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the endpoint, cluster and attribute are the path's own parts, already \
                  destructured by the caller"
    )]
    fn write_concrete(
        &self,
        data: &AttributeData<'_>,
        endpoint: crate::im::EndpointId,
        cluster: crate::im::ClusterId,
        attribute: crate::im::AttributeId,
        op: WriteOp,
        ctx: &InteractionContext<'_>,
        action: &mut WriteAction,
        w: &mut TlvWriter<'_>,
        responses: &mut usize,
    ) -> Result<bool> {
        let path = data.path;
        // A later AttributeDataIB of a list write this action has already been granted. See
        // [`WriteAction`]: the `ACL` attribute is the one where re-checking is wrong, because
        // clearing the list is what removes the writer's own grant.
        let carried = action.already_granted(endpoint, cluster, attribute);
        // step b.i — the View check, before existence.
        if !carried && let Some(status) = self.access.allows(&path, Privilege::View).status() {
            return self.write_response_status(w, &path, status, responses);
        }

        // step b.ii — existence, level by level.
        let resolved = match self.node.resolve(endpoint, cluster, attribute) {
            Ok(resolved) => resolved,
            Err(missing) => {
                return self.write_response_status(w, &path, missing.status(), responses);
            }
        };
        let Some(descriptor) = resolved.cluster.attribute(attribute) else {
            return self.write_response_status(w, &path, Status::UnsupportedAttribute, responses);
        };
        // step b.ii.E — "an attribute that is not writable" is UNSUPPORTED_WRITE. The
        // globals of §7.13 land here: Table 95 gives all five `RV`, so a client writing one
        // is told it is read-only rather than that it does not exist.
        let Some(required) = descriptor.access.write else {
            return self.write_response_status(w, &path, Status::UnsupportedWrite, responses);
        };

        // step b.iii — the second check, at the attribute's actual write privilege.
        if !carried {
            if let Some(status) = self.access.allows(&path, required).status() {
                return self.write_response_status(w, &path, status, responses);
            }
            action.grant(endpoint, cluster, attribute);
        }

        // §7.15.3: "If a server receives a Write Request for an attribute that is not
        // associated with an Atomic Write State that is also associated with the client making
        // the request, the server SHALL return the error code INVALID_IN_STATE." Before the
        // Timed check, because an atomic attribute written outside a claim is wrong whatever
        // else is true of the request.
        if descriptor.qualities.contains(AttributeQualities::ATOMIC)
            && !ctx
                .atomic
                .is_some_and(|claim| claim.covers(endpoint, cluster, attribute))
        {
            return self.write_response_status(w, &path, Status::InvalidInState, responses);
        }

        // step b.iv — a Timed-only attribute outside a Timed transaction.
        if descriptor.access.needs_timed() && !ctx.timed {
            return self.write_response_status(w, &path, Status::NeedsTimedInteraction, responses);
        }

        // step b.v — "Else if the attribute in the path indicates a fabric-scoped list and
        // there is no accessing fabric". A PASE session during commissioning has none.
        if descriptor.access.is_fabric_scoped() && ctx.fabric_index.is_none() {
            return self.write_response_status(w, &path, Status::UnsupportedAccess, responses);
        }

        // step b.vi — the client's cached version is stale, so its write was computed
        // against data that has since changed.
        if let (Some(expected), Some(actual)) =
            (data.data_version, self.handler.data_version(&resolved))
            && expected != actual
        {
            return self.write_response_status(w, &path, Status::DataVersionMismatch, responses);
        }

        // §8.7.3.3 — the write itself, and a SUCCESS status for it. `op` carries whether the
        // client meant to replace the attribute or to append one item to a list; §10.6.4.3.1
        // encodes that in the path, not in the data, so only this layer can tell the cluster.
        let status = match self.handler.write(&resolved, data.data, op, ctx) {
            Ok(()) => {
                // "A cluster data version SHALL be incremented if any attribute data changes."
                // This is the half the server can see; a cluster that changes on its own calls
                // `DataVersionSource::touch` itself.
                if let Some(versions) = self.versions {
                    versions.touch(resolved.endpoint, resolved.cluster.id);
                }
                Status::Success
            }
            Err(status) => status,
        };
        self.write_response_status(w, &path, status, responses)
    }

    /// Serves a whole `WriteRequest` into a `WriteResponse` message.
    pub fn serve_write<'b>(
        &self,
        writes: impl IntoIterator<Item = Result<AttributeData<'b>>>,
        ctx: &InteractionContext<'_>,
        more_chunked: bool,
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        // §10.7.6.2: "A Write Request action that is part of a Timed Write Interaction SHALL
        // NOT be chunked." The two mechanisms contradict each other — §8.7.4's window is
        // consumed by the first request on it, so every later chunk of the same action would
        // arrive to find no window and be refused as a client bug. Refusing the action up
        // front says what is actually wrong.
        if more_chunked && ctx.timed {
            bail!(InvalidAction)
        }
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.start_array(Tag::Context(0))?;

        let mut responses = 0usize;
        let mut truncated = false;
        let mut action = WriteAction::new();
        for data in writes {
            let data = data?;
            if !self.serve_write_path(&data, ctx, &mut action, &mut w, &mut responses)? {
                truncated = true;
                break;
            }
        }

        w.end_container()?;
        w.unsigned(
            Tag::Context(crate::im::REVISION_TAG),
            u64::from(crate::im::INTERACTION_MODEL_REVISION),
        )?;
        w.end_container()?;
        let bytes = w.finish()?;
        Ok((
            bytes,
            ReadOutcome {
                reports: responses,
                truncated,
                events_through: 0,
            },
        ))
    }
}

// --- Invoke (§8.8.2.3) -------------------------------------------------------------------------

impl<A: AccessControl, H: ClusterHandler> Server<'_, A, H> {
    /// Serves one command into an already-open `InvokeResponses` array.
    ///
    /// §8.8.2.3 again mirrors the read, with one difference that matters: the *first* access
    /// check is at **Operate**, not View. §8.8.2.3 step b.i: "assuming the required_privilege
    /// for the element is Operate". That is because there is no such thing as a read-only
    /// command — View is enough to look at a node, and never enough to make it do something.
    pub fn serve_invoke_command(
        &self,
        command: &CommandData<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        responses: &mut usize,
        scratch: &mut [u8],
    ) -> Result<bool> {
        let path = command.path;
        match path.concrete() {
            Some((endpoint, cluster, id)) => {
                self.invoke_concrete(command, endpoint, cluster, id, ctx, w, responses, scratch)
            }
            None => {
                for resolved in self.node.expand_commands(&path) {
                    let concrete = resolved.path();
                    let Some(required) = resolved.command.access.invoke else {
                        continue;
                    };
                    let attribute_path = command_as_attribute_path(&concrete);
                    // step c.i: denied or restricted — discarded, with no status.
                    if self.access.allows(&attribute_path, required) != Outcome::Granted {
                        continue;
                    }
                    // step c.ii: a Large Message command on a transport that cannot carry
                    // one (§7.7.5).
                    if resolved.command.access.needs_large_messages() && !ctx.large_messages {
                        continue;
                    }
                    // step c.iii: fabric-scoped with no accessing fabric.
                    if resolved.command.access.is_fabric_scoped() && ctx.fabric_index.is_none() {
                        continue;
                    }
                    // step c.iv: Timed-only outside a Timed transaction.
                    if resolved.command.access.needs_timed() && !ctx.timed {
                        continue;
                    }
                    if !self.run_command(&resolved, command, ctx, w, responses, scratch)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the endpoint, cluster and command are the path's own parts, already \
                  destructured by the caller"
    )]
    fn invoke_concrete(
        &self,
        command: &CommandData<'_>,
        endpoint: crate::im::EndpointId,
        cluster: crate::im::ClusterId,
        id: crate::im::CommandId,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        responses: &mut usize,
        scratch: &mut [u8],
    ) -> Result<bool> {
        let path = command.path;
        let attribute_path = command_as_attribute_path(&path);

        // step b.i — "assuming the required_privilege for the element is Operate". Not View:
        // looking at a node and making it do something are different things.
        if let Some(status) = self
            .access
            .allows(&attribute_path, Privilege::Operate)
            .status()
        {
            return self.command_status(w, &path, status, command.command_ref, responses);
        }

        // step b.ii — existence, level by level.
        let resolved = match self.node.resolve_command(endpoint, cluster, id) {
            Ok(resolved) => resolved,
            Err(missing) => {
                return self.command_status(
                    w,
                    &path,
                    missing.status(),
                    command.command_ref,
                    responses,
                );
            }
        };
        let Some(required) = resolved.command.access.invoke else {
            return self.command_status(
                w,
                &path,
                Status::UnsupportedCommand,
                command.command_ref,
                responses,
            );
        };

        // step b.iii — the second check, at the command's actual privilege.
        if let Some(status) = self.access.allows(&attribute_path, required).status() {
            return self.command_status(w, &path, status, command.command_ref, responses);
        }

        // step b.iv — "If the command in the path has the Large Message Quality and was
        // received on a transport that is not capable of transporting Large Messages". A
        // privilege cannot substitute for a transport, so this is checked after the access
        // checks and independently of them.
        if resolved.command.access.needs_large_messages() && !ctx.large_messages {
            return self.command_status(
                w,
                &path,
                Status::InvalidTransportType,
                command.command_ref,
                responses,
            );
        }

        // step b.v — fabric-scoped with no accessing fabric.
        if resolved.command.access.is_fabric_scoped() && ctx.fabric_index.is_none() {
            return self.command_status(
                w,
                &path,
                Status::UnsupportedAccess,
                command.command_ref,
                responses,
            );
        }

        // step b.vi — a command that requires a Timed Invoke and did not get one.
        if resolved.command.access.needs_timed() && !ctx.timed {
            return self.command_status(
                w,
                &path,
                Status::NeedsTimedInteraction,
                command.command_ref,
                responses,
            );
        }

        self.run_command(&resolved, command, ctx, w, responses, scratch)
    }

    /// Runs one command and writes whatever §8.8.2.3's "Invoke Execution" says it produced.
    fn run_command(
        &self,
        resolved: &crate::dm::ResolvedCommand<'_>,
        command: &CommandData<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        responses: &mut usize,
        scratch: &mut [u8],
    ) -> Result<bool> {
        if *responses >= self.limit {
            return Ok(false);
        }
        let path = resolved.path();

        // The response fields are built beside the message so that a command which refuses,
        // or runs out of room, leaves nothing half-written in the response. Note this runs
        // the command *before* knowing whether its response fits: §8.8.2.3 has no way to
        // undo an invocation, so a response that will not fit is reported as a status rather
        // than retried on the next message.
        let mut fields = TlvWriter::new_in(scratch, ContainerKind::Structure);
        let outcome =
            self.handler
                .invoke(resolved, command.fields, ctx, &mut fields, Tag::Context(1));

        // §7.10.3: "A cluster data version SHALL be incremented if any attribute data changes"
        // — *any*, and a command is one of the ways they change. `ArmFailSafe` sets
        // `Breadcrumb`, `AddNOC` fills the fabric table, `MoveToLevel` moves `CurrentLevel`.
        // The write path has always done this; the invoke path did not, so an attribute changed
        // by a command left its version where it was and every client caching by
        // `DataVersionFilters` was told its copy was current when it was not — and never found
        // out otherwise.
        //
        // The server cannot see *which* attribute moved, so it bumps the cluster whenever a
        // command succeeds. Deliberately conservative: §7.10.3 sets a floor, and a version that
        // moves when nothing changed costs a client one re-read, while a version that fails to
        // move when something did is a wrong answer the client cannot detect. The alternative —
        // each cluster announcing its own changes — is the one every cluster forgets, and this
        // document has three decisions about exactly that failure (D77, D78, D79). A cluster
        // that changes an attribute with no command behind it, a sensor reading or a switch
        // somebody pressed, still calls [`DataVersionSource::touch`] itself; there is nothing
        // here for the server to hook.
        if outcome.is_ok()
            && let Some(versions) = self.versions
        {
            versions.touch(resolved.endpoint, resolved.cluster.id);
        }

        match outcome {
            // "If the cluster specification defines a following command in response to the
            // command, a CommandDataIB SHALL be generated for the following command."
            Ok(Some(response_id)) => {
                let Ok(encoded) = fields.finish() else {
                    return self.command_status(
                        w,
                        &path,
                        Status::Failure,
                        command.command_ref,
                        responses,
                    );
                };
                let response = CommandData {
                    // "ClusterPath field … that is a duplicate of the command path processed,
                    // up to the cluster ID; Command field … that is the command ID of the
                    // following command."
                    path: crate::im::CommandPath::command(
                        resolved.endpoint,
                        resolved.cluster.id,
                        response_id,
                    ),
                    fields: Some(encoded),
                    command_ref: command.command_ref,
                };
                if put_block(w, responses, self.limit, |w| {
                    InvokeResponse::Command(response).encode(w)
                })? {
                    return Ok(true);
                }
                // The command has already run and cannot be run again, so its response
                // cannot simply wait for the next message. Saying the response would not fit
                // is the only honest answer left: the client learns the command executed and
                // that its result is unavailable, rather than never hearing about it.
                self.command_status(
                    w,
                    &path,
                    Status::ResourceExhausted,
                    command.command_ref,
                    responses,
                )
            }
            // "Else if the cluster specification defines a success or error status as a
            // response … a CommandStatusIB SHALL be generated."
            Ok(None) => {
                self.command_status(w, &path, Status::Success, command.command_ref, responses)
            }
            Err(status) => self.command_status(w, &path, status, command.command_ref, responses),
        }
    }

    /// Writes a bare `AttributeStatusIB` — what a `WriteResponse`'s array holds.
    ///
    /// Not the same as [`Server::write_status`], which emits an `AttributeReportIB`
    /// *wrapping* one: §10.7.3's `AttributeReports` is an array of `AttributeReportIB`, and
    /// §10.7.7's `WriteResponses` is an array of `AttributeStatusIB` directly. Reusing the
    /// read's helper here produces a response a client cannot decode.
    fn write_response_status(
        &self,
        w: &mut TlvWriter<'_>,
        path: &AttributePath,
        status: Status,
        responses: &mut usize,
    ) -> Result<bool> {
        put_block(w, responses, self.limit, |w| {
            AttributeStatus {
                path: *path,
                status: StatusIb::new(status),
            }
            .encode(w, Tag::Anonymous)
        })
    }

    fn command_status(
        &self,
        w: &mut TlvWriter<'_>,
        path: &crate::im::CommandPath,
        status: impl Into<StatusIb>,
        command_ref: Option<u16>,
        responses: &mut usize,
    ) -> Result<bool> {
        let status = status.into();
        put_block(w, responses, self.limit, |w| {
            InvokeResponse::Status(CommandStatus {
                // §8.8.2.3 step b: "its CommandPath field SHALL be a duplicate of the concrete
                // path processed, including the command ID of the original concrete path."
                path: *path,
                status,
                command_ref,
            })
            .encode(w)
        })
    }

    /// Serves a whole `InvokeRequest` into an `InvokeResponse` message.
    ///
    /// `commands` is the request's `InvokeRequests` array. §8.8.2.2 step 5 forbids a wildcard
    /// once there is more than one command, and the caller is expected to have refused such a
    /// request with `INVALID_ACTION` before reaching here — this serves what it is given.
    pub fn serve_invoke<'b>(
        &self,
        commands: impl IntoIterator<Item = Result<CommandData<'b>>>,
        ctx: &InteractionContext<'_>,
        suppress_response: bool,
        scratch: &mut [u8],
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        // §8.8.3.1: "as Matter does not support responses to InvokeResponse actions, this
        // field has no effect" — but it is mandatory, so it is echoed.
        w.bool(Tag::Context(0), suppress_response)?;
        w.start_array(Tag::Context(1))?;

        let mut responses = 0usize;
        let mut truncated = false;
        for command in commands {
            let command = command?;
            if !self.serve_invoke_command(&command, ctx, &mut w, &mut responses, scratch)? {
                truncated = true;
                break;
            }
        }

        w.end_container()?;
        if truncated {
            w.bool(Tag::Context(2), true)?;
        }
        w.unsigned(
            Tag::Context(crate::im::REVISION_TAG),
            u64::from(crate::im::INTERACTION_MODEL_REVISION),
        )?;
        w.end_container()?;
        let bytes = w.finish()?;
        Ok((
            bytes,
            ReadOutcome {
                reports: responses,
                truncated,
                events_through: 0,
            },
        ))
    }
}

/// Borrows a command path as an attribute path, for the access check.
///
/// [`AccessControl`] is expressed over attribute paths because §6.6's access-control entries
/// are: a `TargetStruct` names an endpoint, a cluster and optionally a device type, never a
/// command. So a command's access is decided by its endpoint and cluster, and this makes that
/// explicit rather than leaving two near-identical traits.
fn command_as_attribute_path(path: &crate::im::CommandPath) -> AttributePath {
    AttributePath {
        endpoint: path.endpoint,
        cluster: path.cluster,
        ..AttributePath::wildcard()
    }
}

// --- Subscribe (§8.5) -----------------------------------------------------------------------

impl<A: AccessControl, H: ClusterHandler> Server<'_, A, H> {
    /// Serves the priming report of a subscription — §8.5.1's second action.
    ///
    /// A Subscribe transaction is four actions: the request, a `ReportData` that primes the
    /// subscriber, a `StatusResponse` acknowledging it, and only then the `SubscribeResponse`
    /// that activates the subscription. This is the second, and it is an ordinary read — the
    /// specification routes both through the same processing, "as defined in Incoming Read
    /// Request and Subscribe Request Action Processing".
    ///
    /// The difference is the `SubscriptionId`, which §8.5.3.2 requires to be "the same as the
    /// one used in Report Data generated to prime this subscription". So the id is allocated
    /// *before* the priming report and confirmed afterwards, not the other way round.
    pub fn prime<'b>(
        &self,
        subscription_id: u32,
        paths: impl IntoIterator<Item = Result<AttributePath>>,
        ctx: &InteractionContext<'_>,
        scratch: &mut [u8],
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        self.serve(paths, ctx, Some(subscription_id), scratch, buf)
    }

    /// The priming report, chunked (§10.2.3).
    ///
    /// A priming report is a whole read of everything the subscription covers, so it
    /// overflows one message for exactly the reasons an ordinary wildcard read does — and a
    /// subscription that cannot be primed cannot be established at all. Drive it the way
    /// [`Server::serve_chunk`] is driven, until the cursor is done.
    pub fn prime_chunk<'b>(
        &self,
        subscription_id: u32,
        paths: impl IntoIterator<Item = Result<AttributePath>>,
        ctx: &InteractionContext<'_>,
        cursor: &mut ReadCursor,
        scratch: &mut [u8],
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        self.serve_chunk(paths, ctx, Some(subscription_id), cursor, scratch, buf)
    }

    /// Serves a subscription's periodic report (§8.6).
    ///
    /// `reason` decides the shape. A [`ReportReason::Data`](crate::im::subscription::ReportReason::Data) report carries what changed and
    /// asks for a `StatusResponse`; a [`ReportReason::KeepAlive`](crate::im::subscription::ReportReason::KeepAlive) one is §8.6.2's "Report
    /// Transaction Empty" — "report with no data or events with SuppressResponse set to TRUE",
    /// because its only job is to prove the publisher is still there and there is nothing for
    /// a subscriber to acknowledge.
    ///
    /// A subscription whose dirty set overflowed reports everything it covers: §8.5's own
    /// recovery, "Including all subscription data to re-prime the subscription".
    ///
    /// One message only, and [`ErrorCode::ReportWouldChunk`] when that is not enough — the
    /// re-primed case above makes that likely, so a publisher serving wildcard subscriptions
    /// wants [`Server::report_chunk`].
    pub fn report<'b, const P: usize>(
        &self,
        subscription: &mut crate::im::subscription::Subscription<P>,
        reason: crate::im::subscription::ReportReason,
        ctx: &InteractionContext<'_>,
        scratch: &mut [u8],
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        let (bytes, outcome) = self.report_chunk(subscription, reason, ctx, scratch, buf)?;
        if outcome.truncated {
            // Same rule as [`Server::serve`]: one message cannot honour the flag it would
            // have to set, so this refuses rather than promising a continuation. The series
            // it started is abandoned with it, or the next call here would resume a report
            // this one told the caller it never sent.
            subscription.cursor = ReadCursor::START;
            bail!(ReportWouldChunk)
        }
        Ok((bytes, outcome))
    }

    /// One message of a subscription's report, resuming at `cursor` (§10.2.3).
    ///
    /// A report over a wildcard subscription, and any re-primed one, is as large as the read
    /// that primed it, so it chunks the same way. [`Server::report`] is this for reports
    /// expected to fit.
    ///
    /// The subscription carries its own cursor, so a series resumes and a finished one starts
    /// over without the caller tracking either: call this until
    /// [`ReadOutcome::truncated`] is false, answering each `StatusResponse` with the next
    /// chunk (§10.2.3). Two subscriptions reporting at once therefore cannot resume into each
    /// other's report, which is the failure a single shared cursor produces and nothing on the
    /// wire reveals.
    pub fn report_chunk<'b, const P: usize>(
        &self,
        subscription: &mut crate::im::subscription::Subscription<P>,
        reason: crate::im::subscription::ReportReason,
        ctx: &InteractionContext<'_>,
        scratch: &mut [u8],
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        use crate::im::subscription::ReportReason;

        let id = subscription.id;
        match reason {
            ReportReason::KeepAlive => {
                subscription.cursor.done = true;
                self.empty_report(id, buf)
            }
            ReportReason::Data => {
                let (paths, events, from, cursor) = subscription.report_source();
                // A cursor that finished its last series starts the next one, which is why no
                // caller resets it: the two states a caller could confuse — "resume" and
                // "begin" — are the same call.
                if cursor.is_done() {
                    *cursor = ReadCursor::START;
                }
                // §8.5.3.4's bookmark: a *new* series starts at the first event the subscriber
                // has not been sent; a resumed one keeps the position it stopped at. "New" is a
                // cursor still at the start — which covers both a series that finished above
                // and one that `Subscription::reported` reset after the last report went out.
                // `is_done()` alone covers only the first, and the second is the common case.
                if *cursor == ReadCursor::START {
                    cursor.set_event_from(from);
                }
                let served = self.serve_chunk_with_events(
                    paths.iter().copied().map(Ok),
                    events.iter().copied().map(Ok),
                    ctx,
                    Some(id),
                    cursor,
                    scratch,
                    buf,
                );
                // Where this message left the bookmark, recorded on the subscription rather
                // than returned to the device: §8.5.3.4 resumes the next report after the last
                // event delivered, and that is a fact the server has and the device would have
                // to reconstruct. Both devices in this repository reconstructed it as `0`.
                //
                // Accumulated across the chunks of one series — `note_reported_through` keeps
                // the maximum — because each chunk carries part of it.
                if let Ok((_, outcome)) = &served {
                    subscription.note_reported_through(outcome.events_through);
                }
                served
            }
        }
    }

    /// §8.6.2's Report Transaction Empty: a `ReportData` with no reports and
    /// `SuppressResponse` set.
    fn empty_report<'b>(
        &self,
        subscription_id: u32,
        buf: &'b mut [u8],
    ) -> Result<(&'b [u8], ReadOutcome)> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(subscription_id))?;
        // No `AttributeReports`, no `EventReports`: an empty report is empty.
        // §8.6.2: "SuppressResponse set to TRUE" — there is nothing to acknowledge, and asking
        // would double the traffic a keep-alive exists to minimise.
        w.bool(Tag::Context(4), true)?;
        w.unsigned(
            Tag::Context(crate::im::REVISION_TAG),
            u64::from(crate::im::INTERACTION_MODEL_REVISION),
        )?;
        w.end_container()?;
        let bytes = w.finish()?;
        Ok((
            bytes,
            ReadOutcome {
                reports: 0,
                truncated: false,
                events_through: 0,
            },
        ))
    }
}
