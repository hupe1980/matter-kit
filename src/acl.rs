//! Who may do what to which element: the Access Control List (Core §6.6).
//!
//! Every interaction a commissioned node serves is checked here first. §6.6.6 gives the
//! decision as a "Conceptual Access Control Privilege Granting algorithm" and is unusually
//! strict about it — "Implementations of this algorithm SHALL have an identical outcome to
//! the output of this conceptual algorithm" — so [`Acl::granted`] follows its pseudocode
//! clause by clause rather than paraphrasing it.
//!
//! # What an entry is
//!
//! An [`Entry`] grants one [`Privilege`] to a set of *subjects*, over a set of *targets*,
//! for one authentication mode, on one fabric. Every one of those is a filter, and an empty
//! subject or target list is a **wildcard** rather than an empty set — the single most
//! dangerous place to get a sign backwards, because reading it as "matches nothing" turns
//! the broadest possible grant into a no-op and reading it the other way is worse.
//!
//! # Why there is no entry for the commissioner
//!
//! A factory-fresh node has an empty ACL, and a commissioner arriving over PASE has no entry
//! to match. §6.6.6.2 resolves that in the algorithm rather than in the table:
//!
//! > PASE commissioning channel implicitly grants administer privilege to commissioner
//!
//! so the grant exists only while the PASE session does, and cannot be written, read back,
//! or left behind. §6.6.2.1 is explicit that the table must not be able to express it:
//! "ACL entries with a PASE authentication mode SHALL NOT be explicitly added to the Access
//! Control List", which [`Acl::add`] enforces.
//!
//! # Fabric isolation
//!
//! An entry belongs to a fabric and is invisible to every other one. That is what stops a
//! second administrator on the same node from granting itself access to the first's
//! endpoints, and it is why [`Acl::granted`] rejects a fabric mismatch before it looks at
//! anything else.

use core::marker::PhantomData;

use heapless::Vec;

use crate::config::{AssertValid, Config};
use crate::dm::{Node, Privilege};
use crate::error::{Error, ErrorCode, Result, bail};
use crate::im::{ClusterId, EndpointId};
use crate::msg::{CaseAuthenticatedTag, FabricIndex, NodeId};

/// How the subject of an action authenticated itself (§9.10.5.4).
///
/// An entry matches only an action authenticated the same way. The modes are not
/// interchangeable and one never subsumes another: a group key proves possession of a shared
/// secret, a CASE session proves a certificate chain back to the fabric root, and confusing
/// the two would let a group message act with a node's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMode {
    /// `1` — a passcode-authenticated session, during commissioning only.
    Pase = 1,
    /// `2` — a CASE session, authenticated by an operational certificate.
    Case = 2,
    /// `3` — a group message, authenticated by an operational group key.
    Group = 3,
}

impl AuthMode {
    /// Reads the enum value off the wire.
    #[must_use]
    pub const fn from_value(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Pase),
            2 => Some(Self::Case),
            3 => Some(Self::Group),
            _ => None,
        }
    }
}

/// What an entry applies to (§9.10.5.6's `AccessControlTargetStruct`).
///
/// Every field is nullable and a null one is a wildcard. §6.6.6.2 states two preconditions
/// the algorithm relies on, both checked by [`Target::is_valid`]: a target may not be empty,
/// and it may not name both an endpoint and a device type — they are two ways of saying
/// *where*, and an entry that used both would be asking a question with no defined answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Target {
    /// `Cluster [0]` — which cluster, or every cluster.
    pub cluster: Option<ClusterId>,
    /// `Endpoint [1]` — which endpoint, or every endpoint.
    pub endpoint: Option<EndpointId>,
    /// `DeviceType [2]` — every endpoint conforming to this device type (§9.5.6.1).
    pub device_type: Option<u32>,
}

impl Target {
    /// A target naming one cluster, anywhere on the node.
    #[must_use]
    pub const fn cluster(cluster: ClusterId) -> Self {
        Self {
            cluster: Some(cluster),
            endpoint: None,
            device_type: None,
        }
    }

    /// A target naming one endpoint, every cluster on it.
    #[must_use]
    pub const fn endpoint(endpoint: EndpointId) -> Self {
        Self {
            cluster: None,
            endpoint: Some(endpoint),
            device_type: None,
        }
    }

    /// A target naming every endpoint that conforms to a device type.
    #[must_use]
    pub const fn device_type(device_type: u32) -> Self {
        Self {
            cluster: None,
            endpoint: None,
            device_type: Some(device_type),
        }
    }

    /// The same target, narrowed to one cluster.
    #[must_use]
    pub const fn and_cluster(mut self, cluster: ClusterId) -> Self {
        self.cluster = Some(cluster);
        self
    }

    /// §6.6.6.2's two preconditions on a target.
    ///
    /// "Precondition: target cannot be empty" and "Precondition: target cannot specify both
    /// endpoint and device type". The algorithm asserts these rather than handling them, so
    /// they are refused at the door instead.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        let named = self.cluster.is_some() || self.endpoint.is_some() || self.device_type.is_some();
        let both_places = self.endpoint.is_some() && self.device_type.is_some();
        if !named || both_places {
            return false;
        }
        // Each field that *is* present has to name something that could exist. §7.21.2's MEI
        // tables bound a cluster id and a device type id, and §7.19.2.27 bounds an endpoint
        // number: "Endpoint numbers SHALL NOT be 0xFFFF". An out-of-range identifier here is
        // not a target the node happens not to have — it is a target no node could have, which
        // is §8.10.1's `CONSTRAINT_ERROR` and not `UNSUPPORTED_CLUSTER`.
        //
        // Unchecked, `0xFFFF_FFFF` is stored, read back and matched against nothing forever:
        // an administrator's mistake that takes effect as an entry which grants access to no
        // cluster on no endpoint, and says so nowhere.
        if let Some(cluster) = self.cluster
            && !crate::dm::mei::cluster_is_valid(cluster)
        {
            return false;
        }
        if let Some(device_type) = self.device_type
            && !crate::dm::mei::device_type_is_valid(device_type)
        {
            return false;
        }
        if let Some(endpoint) = self.endpoint
            && endpoint == 0xFFFF
        {
            return false;
        }
        true
    }

    /// Whether this target covers an element on `endpoint` in `cluster`.
    fn matches(&self, node: &Node<'_>, endpoint: EndpointId, cluster: ClusterId) -> bool {
        if self.cluster.is_some_and(|wanted| wanted != cluster) {
            return false;
        }
        if self.endpoint.is_some_and(|wanted| wanted != endpoint) {
            return false;
        }
        if let Some(wanted) = self.device_type {
            // "Endpoint may be specified indirectly via device type" — so this asks the node
            // what the endpoint *is*, which is why device types live on the endpoint rather
            // than only on its Descriptor cluster.
            let Some(endpoint) = node.endpoint(endpoint) else {
                return false;
            };
            if !endpoint.has_device_type(wanted) {
                return false;
            }
        }
        true
    }
}

/// One access control entry (§9.10.5.7's `AccessControlEntryStruct`).
///
/// `S` and `T` bound the subject and target lists; they come from
/// [`Config::ACL_SUBJECTS`] and [`Config::ACL_TARGETS`], which §9.10.6 requires to be at
/// least 4 and 3 respectively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<const S: usize, const T: usize> {
    /// The fabric this entry belongs to, and the only one that can see it.
    pub fabric_index: FabricIndex,
    /// `Privilege [1]` — what this entry grants.
    pub privilege: Privilege,
    /// `AuthMode [2]` — the authentication mode it applies to.
    pub auth_mode: AuthMode,
    /// `Subjects [3]` — who. **Empty is a wildcard**, not an empty set.
    pub subjects: Vec<NodeId, S>,
    /// `Targets [4]` — what. **Empty is a wildcard**, not an empty set.
    pub targets: Vec<Target, T>,
}

impl<const S: usize, const T: usize> Entry<S, T> {
    /// An entry granting `privilege` to CASE subjects on `fabric`, wildcard in both lists.
    #[must_use]
    pub fn case(fabric_index: FabricIndex, privilege: Privilege) -> Self {
        Self {
            fabric_index,
            privilege,
            auth_mode: AuthMode::Case,
            subjects: Vec::new(),
            targets: Vec::new(),
        }
    }

    /// Adds a subject, which narrows the entry from its wildcard.
    ///
    /// A CAT is carried as its §6.6.2.1.2 node-id sub-encoding; [`CaseAuthenticatedTag`]
    /// produces it.
    pub fn with_subject(mut self, subject: NodeId) -> Result<Self> {
        self.subjects
            .push(subject)
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        Ok(self)
    }

    /// Adds a target, which narrows the entry from its wildcard.
    pub fn with_target(mut self, target: Target) -> Result<Self> {
        if !target.is_valid() {
            bail!(InvalidArgument)
        }
        self.targets
            .push(target)
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        Ok(self)
    }

    /// Whether this entry is one §6.6 permits to exist.
    fn is_well_formed(&self) -> bool {
        // §6.6.2.1: "ACL entries with a PASE authentication mode SHALL NOT be explicitly
        // added to the Access Control List" — the commissioner's grant is implicit and
        // temporary, and an explicit one would outlive the session that justified it.
        if matches!(self.auth_mode, AuthMode::Pase) {
            return false;
        }
        // §6.6.2.11: "it SHALL NOT be valid to have an Administer privilege set on an Access
        // Control Entry, unless AuthMode is 'CASE'." Stated as the specification states it —
        // a positive requirement on CASE rather than a prohibition on Group — because that is
        // the rule that survives if the set of authentication modes ever grows. A group key is
        // a shared secret with "no source Node authentication and reduced attribution
        // ability", so administering with one would make every holder an administrator and
        // leave no record of which one acted.
        if matches!(self.privilege, Privilege::Administer)
            && !matches!(self.auth_mode, AuthMode::Case)
        {
            return false;
        }
        // §6.6.6.2: "only CASE and Group auth can have empty subjects".
        if self.subjects.is_empty() && !matches!(self.auth_mode, AuthMode::Case | AuthMode::Group) {
            return false;
        }
        // A fabric index of 0 names no fabric; §6.6.6.2 skips such entries outright, so one
        // could never grant anything.
        if self.fabric_index.0 == 0 {
            return false;
        }
        // §9.10.5.7's Subject Semantics table gives each authentication mode its own shape for
        // a Subject ID, and a value outside it is not a subject that can ever match. Left
        // unchecked, an entry naming `0` — the Unspecified Node ID, "a reserved value that
        // never appears in messages or protocol usage" (§2.5.5.6) — is stored, read back, and
        // grants nothing to anybody, which is indistinguishable from an administrator's
        // typo taking effect.
        if !self.subjects.iter().all(|s| self.subject_is_valid(*s)) {
            return false;
        }
        self.targets.iter().all(Target::is_valid)
    }

    /// Whether `subject` is a Subject ID this entry's authentication mode can carry
    /// (§9.10.5.7).
    fn subject_is_valid(&self, subject: NodeId) -> bool {
        match self.auth_mode {
            // "CASE — 64-bits → Node ID or CASE Authenticated Tag". A CAT's version is part of
            // the check: §6.6.2.1.2 says "A version number of 0 is invalid and SHALL NOT be
            // used", so `0xFFFF_FFFD_xxxx_0000` is in the range and is still not a CAT.
            AuthMode::Case => match subject.kind() {
                crate::msg::NodeIdKind::Operational => true,
                crate::msg::NodeIdKind::CaseAuthenticatedTag => {
                    CaseAuthenticatedTag::from_node_id(subject).is_some_and(|cat| cat.is_valid())
                }
                _ => false,
            },
            // "Group — Lower 16-bits → Group ID, Upper 48-bits → all bits clear." Group 0 is
            // excluded because §11.2.4 reserves it: "The Group ID 0 is reserved for the
            // All-Nodes group", which no access control entry names.
            AuthMode::Group => subject.0 != 0 && subject.0 <= u64::from(u16::MAX),
            // Unreachable: a PASE entry is refused above, before this is asked.
            AuthMode::Pase => false,
        }
    }
}

/// The set of privileges an action was granted (§6.6.6.2).
///
/// A set rather than a single highest privilege, because §9.10.5.2's `ProxyView` is *not*
/// part of the subsumption chain: `add_granted_privilege` expands Operate, Manage and
/// Administer downward to View, but nothing grants `ProxyView` except `ProxyView` itself.
/// Collapsing the set to its maximum would quietly hand every `View` holder a privilege the
/// specification never gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Granted(u8);

impl Granted {
    /// Nothing granted.
    pub const NONE: Self = Self(0);

    const fn bit(privilege: Privilege) -> u8 {
        1u8 << (privilege as u8)
    }

    /// §6.6.6.2's `add_granted_privilege`, including everything the privilege subsumes.
    fn add(&mut self, privilege: Privilege) {
        self.0 |= Self::bit(privilege);
        match privilege {
            Privilege::Operate => self.0 |= Self::bit(Privilege::View),
            Privilege::Manage => {
                self.0 |= Self::bit(Privilege::Operate) | Self::bit(Privilege::View);
            }
            Privilege::Administer => {
                self.0 |= Self::bit(Privilege::Manage)
                    | Self::bit(Privilege::Operate)
                    | Self::bit(Privilege::View);
            }
            Privilege::ProxyView | Privilege::View => {}
        }
    }

    /// Whether the set contains `privilege`.
    #[must_use]
    pub const fn has(self, privilege: Privilege) -> bool {
        self.0 & Self::bit(privilege) != 0
    }

    /// Whether nothing at all was granted.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The strongest privilege in the set, in §6.6.1's order.
    ///
    /// A set is what §6.6.6.2 actually produces, and it is the honest shape — ProxyView sits
    /// outside the chain, so "the maximum" is not always a single answer. This reduces it to
    /// one for the callers that need a single value to hand a cluster, and ProxyView is not
    /// among the answers: it grants nothing the other four do and is never what a cluster
    /// means by "the privilege this subject holds".
    #[must_use]
    pub const fn highest(self) -> Option<Privilege> {
        if self.has(Privilege::Administer) {
            Some(Privilege::Administer)
        } else if self.has(Privilege::Manage) {
            Some(Privilege::Manage)
        } else if self.has(Privilege::Operate) {
            Some(Privilege::Operate)
        } else if self.has(Privilege::View) {
            Some(Privilege::View)
        } else {
            None
        }
    }
}

/// What an incoming message authenticated as — §6.6.6.1.3's Incoming Subject Descriptor.
///
/// Derived once per message from the session it arrived on (§6.6.6.3), never from the
/// message's own claims: a source node id in a header is whatever the sender wrote, while the
/// id in a session context is what CASE proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDescriptor {
    /// Whether commissioning is under way on this session.
    ///
    /// The one thing that turns a PASE session into an administrator, and only for as long as
    /// it is true.
    pub is_commissioning: bool,
    /// How the action authenticated, or `None` for §6.6.6.3's `AuthModeEnum::None`.
    ///
    /// `None` is the "do nothing on error" outcome: a message whose session could not be
    /// identified gets a descriptor that matches no entry, so it is granted nothing rather
    /// than being treated as some default. Modelling it as `Option` rather than as a fourth
    /// [`AuthMode`] keeps it out of [`Entry`] entirely — an entry that authenticated nobody
    /// is not a thing the table can hold.
    pub auth_mode: Option<AuthMode>,
    /// The subjects it presents: a CASE node's operational id plus any CATs its certificate
    /// carried, a group id for a group message, or the passcode id for PASE.
    ///
    /// Four, because §6.5.6 allows a NOC to carry at most three CATs alongside its node id.
    pub subjects: Vec<NodeId, 4>,
    /// Which fabric, or 0 for a PASE session that has none yet.
    pub fabric_index: FabricIndex,
}

/// "`DEFAULT_COMMISSIONING_PASSCODE = 0`" (§6.6.6.3).
///
/// The subject a PASE session presents. §6.6.2.1: "any Passcode ID other than 0 … is reserved
/// for future use".
pub const DEFAULT_COMMISSIONING_PASSCODE: u64 = 0;

impl SubjectDescriptor {
    /// §6.6.6.3's starting value: authenticated as nobody, granted nothing.
    ///
    /// The result for a message whose session cannot be identified — "Do nothing on error,
    /// ISD remains unchanged".
    #[must_use]
    pub fn unauthenticated() -> Self {
        Self {
            is_commissioning: false,
            auth_mode: None,
            subjects: Vec::new(),
            fabric_index: FabricIndex(0),
        }
    }

    /// The descriptor for a PASE session (§6.6.6.3).
    ///
    /// `IsCommissioning` is true for *any* PASE session: the specification sets it in the PASE
    /// branch unconditionally, because a passcode-authenticated session exists only to
    /// commission. The fabric "may be zero" — it is, until `AddNOC`.
    #[must_use]
    pub fn pase(fabric_index: FabricIndex) -> Self {
        let mut subjects = Vec::new();
        let _ = subjects.push(NodeId(DEFAULT_COMMISSIONING_PASSCODE));
        Self {
            is_commissioning: true,
            auth_mode: Some(AuthMode::Pase),
            subjects,
            fabric_index,
        }
    }

    /// The descriptor for a commissioner on the PASE channel before it has a fabric.
    #[must_use]
    pub fn commissioning() -> Self {
        Self::pase(FabricIndex(0))
    }

    /// The descriptor for a CASE session with a node id and no CATs.
    #[must_use]
    pub fn case(fabric_index: FabricIndex, node_id: NodeId) -> Self {
        let mut subjects = Vec::new();
        let _ = subjects.push(node_id);
        Self {
            is_commissioning: false,
            auth_mode: Some(AuthMode::Case),
            subjects,
            fabric_index,
        }
    }

    /// The descriptor for a group message (§6.6.6.3).
    ///
    /// The caller must already have checked that the group and key are mapped — the spec sets
    /// the auth mode only "if group_key_management_cluster.group_key_map_has_mapping(group_id,
    /// group_key_id)", and a message that failed that check is
    /// [`SubjectDescriptor::unauthenticated`].
    #[must_use]
    pub fn group(fabric_index: FabricIndex, group_id: crate::msg::GroupId) -> Self {
        let mut subjects = Vec::new();
        let _ = subjects.push(NodeId(u64::from(group_id.0)));
        Self {
            is_commissioning: false,
            auth_mode: Some(AuthMode::Group),
            subjects,
            fabric_index,
        }
    }

    /// Adds a CAT the peer's operational certificate carried (§6.6.2.1.2).
    pub fn with_cat(mut self, cat: CaseAuthenticatedTag) -> Result<Self> {
        self.subjects
            .push(cat.to_node_id())
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        Ok(self)
    }

    /// §6.6.6.3's derivation, for a unicast session.
    ///
    /// > Each incoming message has a unique `<AuthMode, SubjectDescriptor>` applicable to it,
    /// > whose derivation is deterministic based on both incoming message fields and session
    /// > metadata fields.
    ///
    /// Session metadata, never the message's own claims — a source node id in a header is
    /// whatever the sender wrote, while the id in a session context is what CASE proved. That
    /// is the whole reason this takes a [`SecureSession`](crate::session::SecureSession)
    /// rather than a header.
    ///
    /// `pending_fabric` is the fabric index `AddNOC` has created but the fail-safe has not yet
    /// committed, if any: §6.6.6.3 marks a CASE session on it as commissioning, which is how a
    /// commissioner that has switched from PASE to CASE mid-flow keeps its standing.
    ///
    /// Group messages do not arrive on a unicast session and are built with
    /// [`SubjectDescriptor::group`] instead, after the Group Key Management check the
    /// specification requires.
    #[cfg(feature = "rustcrypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
    #[must_use]
    pub fn from_session(
        session: &crate::session::SecureSession,
        pending_fabric: Option<FabricIndex>,
    ) -> Self {
        match session.kind {
            crate::session::SessionKind::Pase => Self::pase(session.fabric_index),
            crate::session::SessionKind::Case => {
                // "assert(isd.FabricIndex != 0) # cannot be zero" — a CASE session without a
                // fabric is not a thing that can exist, and treating one as fabric 0 would
                // silently match no entry rather than saying so.
                if session.fabric_index.0 == 0 {
                    return Self::unauthenticated();
                }
                let mut descriptor = Self::case(session.fabric_index, session.peer_node_id);
                descriptor.is_commissioning =
                    pending_fabric.is_some_and(|pending| pending == session.fabric_index);
                for cat in &session.peer_cats {
                    // The list is sized for a node id plus §6.5.6's three CATs, so this
                    // cannot overflow for a well-formed certificate.
                    let _ = descriptor.subjects.push(cat.to_node_id());
                }
                descriptor
            }
        }
    }
}

/// §6.6.6.2's `subject_matches`.
///
/// "Subjects must match exactly, or both are CAT with matching CAT ID and acceptable CAT
/// version." The version comparison is the interesting half and its direction is the whole
/// point: the *entry* names the minimum version and the *subject* must be at least that, so
/// an administrator revokes a tag by issuing a higher version and rewriting the entry. Read
/// backwards, a revoked node keeps its access forever.
fn subject_matches(acl_subject: NodeId, isd_subject: NodeId) -> bool {
    if acl_subject == isd_subject {
        return true;
    }
    match (
        CaseAuthenticatedTag::from_node_id(acl_subject),
        CaseAuthenticatedTag::from_node_id(isd_subject),
    ) {
        (Some(acl), Some(isd)) => {
            acl.identifier() == isd.identifier() && isd.version() >= acl.version()
        }
        _ => false,
    }
}

/// A node's Access Control List, and the decision it exists to make (§6.6).
///
/// `N` is [`Config::ACL_ENTRIES`], `S` is [`Config::ACL_SUBJECTS`] and `T` is
/// [`Config::ACL_TARGETS`].
#[derive(Debug)]
pub struct Acl<C: Config, const N: usize, const S: usize, const T: usize> {
    entries: Vec<Entry<S, T>, N>,
    _config: PhantomData<C>,
}

impl<C: Config, const N: usize, const S: usize, const T: usize> Default for Acl<C, N, S, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Config, const N: usize, const S: usize, const T: usize> Acl<C, N, S, T> {
    /// An empty list — what a factory-fresh node has (§9.10.6.1).
    #[must_use]
    pub fn new() -> Self {
        let () = AssertValid::<C>::CHECK;
        Self {
            entries: Vec::new(),
            _config: PhantomData,
        }
    }

    /// How many entries the list holds, across every fabric.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry<S, T>> {
        self.entries.iter()
    }

    /// The entries belonging to one fabric — what a read of the `ACL` attribute reports.
    ///
    /// §9.10.6's `ACL` attribute is `F`, fabric-scoped, so a client sees its own fabric's
    /// entries and no others.
    pub fn of_fabric(&self, fabric: FabricIndex) -> impl Iterator<Item = &Entry<S, T>> {
        self.entries
            .iter()
            .filter(move |entry| entry.fabric_index == fabric)
    }

    /// How many entries one fabric has, against [`Config::ACL_ENTRIES_PER_FABRIC`].
    #[must_use]
    pub fn len_of_fabric(&self, fabric: FabricIndex) -> usize {
        self.of_fabric(fabric).count()
    }

    /// Adds an entry.
    ///
    /// Refuses one §6.6 does not permit to exist — a PASE entry, a Group entry at Administer,
    /// an entry on no fabric, or a malformed target — with [`ErrorCode::InvalidArgument`],
    /// and a fabric already at its quota with [`ErrorCode::NoSpace`].
    pub fn add(&mut self, entry: Entry<S, T>) -> Result<()> {
        if !entry.is_well_formed() {
            bail!(InvalidArgument)
        }
        if self.len_of_fabric(entry.fabric_index) >= C::ACL_ENTRIES_PER_FABRIC {
            bail!(NoSpace)
        }
        self.entries
            .push(entry)
            .map_err(|_| Error::new(ErrorCode::NoSpace))
    }

    /// Adds §11.18.6.8 step 7's administrator entry for a fabric just joined.
    ///
    /// `AddNOC` carries a `CaseAdminSubject`, and the specification fixes exactly what the
    /// resulting entry must be:
    ///
    /// ```text
    /// { FabricIndex: <new>, Privilege: Administer, AuthMode: CASE,
    ///   Subjects: [CaseAdminSubject], Targets: [] }   // entire node
    /// ```
    ///
    /// It exists as a named constructor because the consequence of getting it wrong is not a
    /// visible failure. §11.18.6.8: "Unless such an Access Control Entry is added atomically
    /// as described here, there would be no way for the caller on its given Fabric to
    /// eventually add another Access Control Entry for CASE authentication mode" — the fabric
    /// is joined, the node advertises itself, and the moment the PASE session closes nobody
    /// can administer it again.
    ///
    /// `subject` must be an operational node id or a CAT; anything else is
    /// [`ErrorCode::InvalidArgument`], which is the condition §11.18.6.8 answers with
    /// `InvalidAdminSubject`.
    pub fn add_admin_for_fabric(&mut self, fabric: FabricIndex, subject: NodeId) -> Result<()> {
        // "not being in either the Operational or CASE Authenticated Tag range".
        if !matches!(
            subject.kind(),
            crate::msg::NodeIdKind::Operational | crate::msg::NodeIdKind::CaseAuthenticatedTag
        ) {
            bail!(InvalidArgument)
        }
        let entry = Entry::<S, T>::case(fabric, Privilege::Administer).with_subject(subject)?;
        self.add(entry)
    }

    /// Removes every entry of one fabric — §6.6.4's side-effect of `RemoveFabric`.
    ///
    /// A fabric's entries must not outlive it. Left behind, they would be matched by the next
    /// fabric to be issued the same index, handing a new administrator the privileges of a
    /// removed one.
    pub fn remove_fabric(&mut self, fabric: FabricIndex) {
        self.entries.retain(|entry| entry.fabric_index != fabric);
    }

    /// Replaces one fabric's entries, which is how §10.6.4.3.1's list write lands.
    ///
    /// A write of the whole `ACL` attribute replaces only the accessing fabric's entries;
    /// every other fabric's are untouched, because they were never visible to the writer.
    pub fn replace_fabric(
        &mut self,
        fabric: FabricIndex,
        entries: impl IntoIterator<Item = Entry<S, T>>,
    ) -> Result<()> {
        self.entries.retain(|entry| entry.fabric_index != fabric);
        for entry in entries {
            self.add(entry)?;
        }
        Ok(())
    }

    /// §6.6.6.2's `get_granted_privileges`: every privilege this action holds here.
    ///
    /// Follows the pseudocode clause by clause. The order of the checks is not cosmetic — a
    /// fabric mismatch is rejected before an auth mode, and both before any subject is
    /// compared — because each one is what makes the next one's comparison meaningful.
    #[must_use]
    pub fn granted(
        &self,
        node: &Node<'_>,
        subject: &SubjectDescriptor,
        endpoint: EndpointId,
        cluster: ClusterId,
    ) -> Granted {
        let mut granted = Granted::NONE;

        // "PASE commissioning channel implicitly grants administer privilege to commissioner".
        // It is deliberately not an entry: it exists only while this session does.
        if subject.auth_mode == Some(AuthMode::Pase) && subject.is_commissioning {
            granted.add(Privilege::Administer);
        }

        for entry in &self.entries {
            // "End checking if highest privilege is granted".
            if granted.has(Privilege::Administer) {
                break;
            }
            // "FabricIndex must match, there are no valid entries with FabricIndex == 0".
            if entry.fabric_index.0 == 0 || entry.fabric_index != subject.fabric_index {
                continue;
            }
            if Some(entry.auth_mode) != subject.auth_mode {
                continue;
            }

            // "Subject must match, or be wildcard" — and empty *is* the wildcard.
            if !entry.subjects.is_empty() {
                let matched = entry.subjects.iter().any(|acl_subject| {
                    subject
                        .subjects
                        .iter()
                        .any(|isd| subject_matches(*acl_subject, *isd))
                });
                if !matched {
                    continue;
                }
            }

            // "Target must match, or be wildcard".
            if entry.targets.is_empty() {
                // The Auxiliary feature's carve-out: a group may not reach endpoint 0, whose
                // clusters administer the node itself.
                if matches!(entry.auth_mode, AuthMode::Group) && C::ACL_AUXILIARY && endpoint == 0 {
                    continue;
                }
            } else {
                let matched = entry
                    .targets
                    .iter()
                    .any(|target| target.matches(node, endpoint, cluster));
                if !matched {
                    continue;
                }
            }

            // §6.6.6.2's remaining clause is `extensions_are_valid`, which validates the
            // `Extension` attribute against the entry. That attribute belongs to the `EXTS`
            // feature and is not served here, so there are no extensions to invalidate an
            // entry and the clause is vacuously true — not skipped.
            granted.add(entry.privilege);
        }

        // "Should never grant Administer privilege to a Group." An entry that could do so is
        // refused by `add`, so this can only fire on a list built some other way — and it
        // fires by withholding the privilege rather than by trusting the earlier check.
        if subject.auth_mode == Some(AuthMode::Group) && granted.has(Privilege::Administer) {
            return Granted::NONE;
        }

        granted
    }

    /// Whether an action holding `required` may proceed.
    ///
    /// The shape [`AccessControl`](crate::im::AccessControl) wants. `Restricted` is never
    /// returned: §6.6.2.8's Access Restriction List belongs to the ManagedDevice feature,
    /// which this build does not implement, and inventing a restriction would deny access the
    /// specification grants.
    #[must_use]
    pub fn allows(
        &self,
        node: &Node<'_>,
        subject: &SubjectDescriptor,
        endpoint: EndpointId,
        cluster: ClusterId,
        required: Privilege,
    ) -> crate::im::Outcome {
        if self.granted(node, subject, endpoint, cluster).has(required) {
            crate::im::Outcome::Granted
        } else {
            crate::im::Outcome::Denied
        }
    }
}

/// An [`Acl`] as the [`AccessControl`](crate::im::AccessControl) one interaction sees.
///
/// The trait asks "may this action have `required` on this path?" and takes no subject,
/// because the subject is not a property of the path — it is a property of the *session the
/// action arrived on*. So the subject is bound here, once, when the interaction is set up,
/// and the trait's question becomes answerable:
///
/// ```no_run
/// # use core::cell::RefCell;
/// # use matter_kit::acl::{Acl, AclAccess, SubjectDescriptor};
/// # use matter_kit::config::DefaultConfig;
/// # use matter_kit::dm::Node;
/// # use matter_kit::msg::{FabricIndex, NodeId};
/// # fn go(node: Node<'_>, acl: &RefCell<Acl<DefaultConfig, 20, 4, 3>>) {
/// // Derived from the session (§6.6.6.3), never from anything the message claimed.
/// let subject = SubjectDescriptor::case(FabricIndex(1), NodeId(0x1234));
/// let access = AclAccess::new(acl, node, &subject);
/// // `access` is now what `Server::new` takes.
/// # let _ = access;
/// # }
/// ```
///
/// A path that is not concrete is denied. Every call the server makes passes a concrete one —
/// a wildcard is expanded before it is checked — so this is unreachable in practice, and it
/// fails closed rather than guessing which endpoint a caller meant.
#[derive(Debug)]
pub struct AclAccess<'a, C: Config, const N: usize, const S: usize, const T: usize> {
    acl: &'a core::cell::RefCell<Acl<C, N, S, T>>,
    node: Node<'a>,
    subject: &'a SubjectDescriptor,
}

impl<'a, C: Config, const N: usize, const S: usize, const T: usize> AclAccess<'a, C, N, S, T> {
    /// Binds a list, a node and the subject of one interaction.
    #[must_use]
    pub const fn new(
        acl: &'a core::cell::RefCell<Acl<C, N, S, T>>,
        node: Node<'a>,
        subject: &'a SubjectDescriptor,
    ) -> Self {
        Self { acl, node, subject }
    }
}

impl<C: Config, const N: usize, const S: usize, const T: usize> crate::im::AccessControl
    for AclAccess<'_, C, N, S, T>
{
    fn allows(&self, path: &crate::im::AttributePath, required: Privilege) -> crate::im::Outcome {
        let (Some(endpoint), Some(cluster)) = (path.endpoint, path.cluster) else {
            return crate::im::Outcome::Denied;
        };
        self.acl
            .borrow()
            .allows(&self.node, self.subject, endpoint, cluster, required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultConfig;
    use crate::dm::{
        AttributeDescriptor, ClusterDescriptor, CommandDescriptor, DeviceType, Endpoint,
    };

    type TestAcl = Acl<
        DefaultConfig,
        { DefaultConfig::ACL_ENTRIES },
        { DefaultConfig::ACL_SUBJECTS },
        { DefaultConfig::ACL_TARGETS },
    >;
    type TestEntry = Entry<{ DefaultConfig::ACL_SUBJECTS }, { DefaultConfig::ACL_TARGETS }>;

    const ATTRS: &[AttributeDescriptor] = &[AttributeDescriptor::read_only(0)];
    const NO_CMDS: &[CommandDescriptor] = &[];

    const fn cluster(id: ClusterId) -> ClusterDescriptor<'static> {
        ClusterDescriptor {
            id,
            revision: 1,
            feature_map: 0,
            attributes: ATTRS,
            accepted_commands: NO_CMDS,
            generated_commands: &[],
            events: &[],
        }
    }

    const ON_OFF: ClusterId = 0x0006;
    const LEVEL: ClusterId = 0x0008;
    const ROOT: &[ClusterDescriptor<'static>] = &[cluster(0x001D)];
    const APP: &[ClusterDescriptor<'static>] = &[cluster(ON_OFF), cluster(LEVEL)];
    /// `0x0100` is the Device Library's On/Off Light.
    const LIGHT: &[DeviceType] = &[DeviceType::new(0x0100, 1)];
    const ENDPOINTS: &[Endpoint<'static>] = &[
        Endpoint::new(0, ROOT),
        Endpoint::new(1, APP).with_device_types(LIGHT),
    ];

    fn node() -> Node<'static> {
        Node::new(ENDPOINTS)
    }

    const F1: FabricIndex = FabricIndex(1);
    const F2: FabricIndex = FabricIndex(2);
    const ALICE: NodeId = NodeId(0x0000_0000_0000_1111);
    const BOB: NodeId = NodeId(0x0000_0000_0000_2222);

    #[test]
    fn an_empty_list_grants_nothing() {
        let acl = TestAcl::new();
        let subject = SubjectDescriptor::case(F1, ALICE);
        assert!(acl.granted(&node(), &subject, 1, ON_OFF).is_empty());
    }

    #[test]
    fn a_pase_commissioner_is_an_administrator_without_an_entry() {
        // §6.6.6.2's first clause, and §9.10.6.1's reason the ACL can start empty at all.
        let acl = TestAcl::new();
        let granted = acl.granted(&node(), &SubjectDescriptor::commissioning(), 0, 0x001D);
        assert!(granted.has(Privilege::Administer));
        assert!(granted.has(Privilege::View), "and everything it subsumes");
    }

    #[test]
    fn a_pase_session_that_is_not_commissioning_grants_nothing() {
        let acl = TestAcl::new();
        let mut subject = SubjectDescriptor::commissioning();
        subject.is_commissioning = false;
        assert!(acl.granted(&node(), &subject, 0, 0x001D).is_empty());
    }

    #[test]
    fn an_empty_subject_list_is_a_wildcard_not_an_empty_set() {
        // The sign that must not be backwards: empty means "anyone on this fabric".
        let mut acl = TestAcl::new();
        acl.add(TestEntry::case(F1, Privilege::Operate))
            .expect("add");
        let granted = acl.granted(&node(), &SubjectDescriptor::case(F1, ALICE), 1, ON_OFF);
        assert!(granted.has(Privilege::Operate));
        assert!(granted.has(Privilege::View), "Operate subsumes View");
        assert!(!granted.has(Privilege::Manage));
    }

    #[test]
    fn a_named_subject_excludes_every_other() {
        let mut acl = TestAcl::new();
        acl.add(
            TestEntry::case(F1, Privilege::Manage)
                .with_subject(ALICE)
                .expect("subject"),
        )
        .expect("add");
        assert!(
            acl.granted(&node(), &SubjectDescriptor::case(F1, ALICE), 1, ON_OFF)
                .has(Privilege::Manage)
        );
        assert!(
            acl.granted(&node(), &SubjectDescriptor::case(F1, BOB), 1, ON_OFF)
                .is_empty()
        );
    }

    #[test]
    fn another_fabrics_entry_is_invisible() {
        // The isolation that stops a second administrator inheriting the first's node.
        let mut acl = TestAcl::new();
        acl.add(TestEntry::case(F2, Privilege::Administer))
            .expect("add");
        assert!(
            acl.granted(&node(), &SubjectDescriptor::case(F1, ALICE), 1, ON_OFF)
                .is_empty()
        );
        assert!(
            acl.granted(&node(), &SubjectDescriptor::case(F2, ALICE), 1, ON_OFF)
                .has(Privilege::Administer)
        );
    }

    #[test]
    fn an_auth_mode_never_subsumes_another() {
        let mut acl = TestAcl::new();
        acl.add(TestEntry::case(F1, Privilege::Operate))
            .expect("add");
        let mut group = SubjectDescriptor::case(F1, ALICE);
        group.auth_mode = Some(AuthMode::Group);
        assert!(acl.granted(&node(), &group, 1, ON_OFF).is_empty());
    }

    #[test]
    fn a_target_narrows_to_one_cluster() {
        let mut acl = TestAcl::new();
        acl.add(
            TestEntry::case(F1, Privilege::Operate)
                .with_target(Target::cluster(ON_OFF))
                .expect("target"),
        )
        .expect("add");
        let subject = SubjectDescriptor::case(F1, ALICE);
        assert!(
            acl.granted(&node(), &subject, 1, ON_OFF)
                .has(Privilege::Operate)
        );
        assert!(acl.granted(&node(), &subject, 1, LEVEL).is_empty());
    }

    #[test]
    fn a_target_may_name_an_endpoint_by_its_device_type() {
        // "Endpoint may be specified indirectly via device type" — which only works because
        // the endpoint itself carries its device types.
        let mut acl = TestAcl::new();
        acl.add(
            TestEntry::case(F1, Privilege::Operate)
                .with_target(Target::device_type(0x0100))
                .expect("target"),
        )
        .expect("add");
        let subject = SubjectDescriptor::case(F1, ALICE);
        assert!(
            acl.granted(&node(), &subject, 1, ON_OFF)
                .has(Privilege::Operate),
            "endpoint 1 is an On/Off Light"
        );
        assert!(
            acl.granted(&node(), &subject, 0, 0x001D).is_empty(),
            "endpoint 0 is not"
        );
    }

    #[test]
    fn a_cat_matches_at_or_above_the_entrys_version() {
        // The direction that decides whether revocation works at all.
        let tag = CaseAuthenticatedTag::new(0xABCD, 3);
        let mut acl = TestAcl::new();
        acl.add(
            TestEntry::case(F1, Privilege::Manage)
                .with_subject(tag.to_node_id())
                .expect("subject"),
        )
        .expect("add");

        for (version, expected) in [(2u16, false), (3, true), (4, true)] {
            let subject = SubjectDescriptor::case(F1, ALICE)
                .with_cat(CaseAuthenticatedTag::new(0xABCD, version))
                .expect("cat");
            assert_eq!(
                acl.granted(&node(), &subject, 1, ON_OFF)
                    .has(Privilege::Manage),
                expected,
                "version {version} against an entry naming 3"
            );
        }
    }

    #[test]
    fn a_cat_with_another_identifier_never_matches() {
        let mut acl = TestAcl::new();
        acl.add(
            TestEntry::case(F1, Privilege::Manage)
                .with_subject(CaseAuthenticatedTag::new(0xABCD, 1).to_node_id())
                .expect("subject"),
        )
        .expect("add");
        let subject = SubjectDescriptor::case(F1, ALICE)
            .with_cat(CaseAuthenticatedTag::new(0x1234, 9))
            .expect("cat");
        assert!(acl.granted(&node(), &subject, 1, ON_OFF).is_empty());
    }

    #[test]
    fn a_pase_entry_cannot_be_written() {
        // §6.6.2.1: the commissioner's grant is implicit, and an explicit one would outlive
        // the session that justified it.
        let mut acl = TestAcl::new();
        let mut entry = TestEntry::case(F1, Privilege::Administer);
        entry.auth_mode = AuthMode::Pase;
        assert_eq!(
            acl.add(entry).map_err(|e| e.code()),
            Err(ErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn a_group_entry_may_not_administer() {
        // §9.10.5.7: a group key has no per-node attribution, so administering with one
        // would make every holder an administrator and leave no record of which acted.
        let mut acl = TestAcl::new();
        let mut entry = TestEntry::case(F1, Privilege::Administer);
        entry.auth_mode = AuthMode::Group;
        assert_eq!(
            acl.add(entry).map_err(|e| e.code()),
            Err(ErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn a_target_naming_both_an_endpoint_and_a_device_type_is_refused() {
        let target = Target {
            cluster: None,
            endpoint: Some(1),
            device_type: Some(0x0100),
        };
        assert!(!target.is_valid());
        assert!(
            TestEntry::case(F1, Privilege::View)
                .with_target(target)
                .is_err()
        );
    }

    #[test]
    fn an_empty_target_is_refused() {
        assert!(!Target::default().is_valid());
    }

    #[test]
    fn proxy_view_is_not_subsumed_by_anything() {
        // §9.10.5.2's subsumption chain runs View ← Operate ← Manage ← Administer. ProxyView
        // is outside it, so an Administer grant does not carry it.
        let mut acl = TestAcl::new();
        acl.add(TestEntry::case(F1, Privilege::Administer))
            .expect("add");
        let granted = acl.granted(&node(), &SubjectDescriptor::case(F1, ALICE), 1, ON_OFF);
        assert!(granted.has(Privilege::Administer));
        assert!(granted.has(Privilege::View));
        assert!(
            !granted.has(Privilege::ProxyView),
            "ProxyView is not in the chain"
        );
    }

    #[test]
    fn removing_a_fabric_takes_its_entries() {
        let mut acl = TestAcl::new();
        acl.add(TestEntry::case(F1, Privilege::Operate))
            .expect("add");
        acl.add(TestEntry::case(F2, Privilege::Operate))
            .expect("add");
        acl.remove_fabric(F1);
        assert_eq!(acl.len(), 1);
        assert!(
            acl.granted(&node(), &SubjectDescriptor::case(F1, ALICE), 1, ON_OFF)
                .is_empty()
        );
        assert!(
            acl.granted(&node(), &SubjectDescriptor::case(F2, ALICE), 1, ON_OFF)
                .has(Privilege::Operate)
        );
    }

    #[test]
    fn the_add_noc_administrator_entry_has_the_shape_11_18_6_8_fixes() {
        // The entry that keeps a freshly commissioned node administrable. Its shape is
        // specified exactly, and every field of it matters.
        let mut acl = TestAcl::new();
        acl.add_admin_for_fabric(F1, ALICE).expect("bootstrap");

        let entry = acl.of_fabric(F1).next().expect("one entry");
        assert_eq!(entry.privilege, Privilege::Administer);
        assert_eq!(entry.auth_mode, AuthMode::Case);
        assert_eq!(entry.subjects.as_slice(), &[ALICE]);
        assert!(
            entry.targets.is_empty(),
            "Targets: [] means the entire node"
        );

        // ...and it does what it is for: that subject can now administer over CASE.
        let subject = SubjectDescriptor::case(F1, ALICE);
        assert!(
            acl.granted(&node(), &subject, 0, 0x001D)
                .has(Privilege::Administer)
        );
    }

    #[test]
    fn a_target_naming_an_identifier_that_cannot_exist_is_refused() {
        // §7.21.2's MEI tables and §7.19.2.27's "Endpoint numbers SHALL NOT be 0xFFFF". A
        // target whose cluster, endpoint or device type is outside its range names nothing any
        // node could ever have, so it is a constraint error rather than an absent cluster.
        for bad in [
            // Prefix 0xFFFF is Invalid in Table 103's own words.
            Target {
                cluster: Some(0xFFFF_FFFF),
                ..Target::default()
            },
            // The gap between a standard cluster and a manufacturer-specific one.
            Target {
                cluster: Some(0x0000_8000),
                ..Target::default()
            },
            Target {
                device_type: Some(0xFFFF_FFFF),
                ..Target::default()
            },
            // Past Table 102's 0xBFFF for a device type.
            Target {
                device_type: Some(0x0000_C000),
                ..Target::default()
            },
            Target {
                endpoint: Some(0xFFFF),
                ..Target::default()
            },
        ] {
            assert!(!bad.is_valid(), "{bad:?} was accepted");
            // And `with_target` refuses it, so it cannot reach an entry in the first place.
            let entry = TestEntry::case(F1, Privilege::Operate)
                .with_target(bad)
                .map_err(|e| e.code());
            assert_eq!(entry.err(), Some(ErrorCode::InvalidArgument));
        }

        // And the shapes that are legal stay legal.
        for good in [
            Target {
                cluster: Some(0x0000_0006),
                ..Target::default()
            },
            Target {
                cluster: Some(0xFFF1_FC00),
                ..Target::default()
            },
            Target {
                endpoint: Some(1),
                ..Target::default()
            },
            Target {
                device_type: Some(0x0000_0100),
                ..Target::default()
            },
        ] {
            assert!(good.is_valid(), "{good:?} was refused");
        }
    }

    #[test]
    fn a_subject_outside_its_auth_modes_shape_is_refused() {
        // §9.10.5.7's Subject Semantics table. Every one of these is a 64-bit integer the
        // decoder is happy with and the access-control algorithm can never match, so an entry
        // holding one is an administrator's mistake that takes effect as silence.
        for bad in [
            // §2.5.5.6's Unspecified Node ID: "a reserved value that never appears in messages
            // or protocol usage".
            NodeId(0),
            // The top of the group range, which is not a CASE subject at all.
            NodeId(0xFFFF_FFFF_FFFF_FFFF),
            // A group node id, likewise.
            NodeId(0xFFFF_FFFF_FFFF_0000),
            // In the CAT range, and not a CAT: §6.6.2.1.2 says "A version number of 0 is
            // invalid and SHALL NOT be used", and this one's version is 0.
            NodeId(0xFFFF_FFFD_0000_0000),
            NodeId(0xFFFF_FFFD_ABCD_0000),
            // The PAKE key identifier and temporary-local ranges are not subjects either.
            NodeId(0xFFFF_FFFB_0000_0001),
            NodeId(0xFFFF_FFFE_0000_0001),
        ] {
            let mut acl = TestAcl::new();
            let entry = TestEntry::case(F1, Privilege::Operate)
                .with_subject(bad)
                .expect("the list has room");
            assert_eq!(
                acl.add(entry).map_err(|e| e.code()),
                Err(ErrorCode::InvalidArgument),
                "{bad:?} was accepted as a CASE subject"
            );
        }

        // And the two shapes that are legal stay legal.
        for good in [ALICE, CaseAuthenticatedTag::new(0xABCD, 2).to_node_id()] {
            let mut acl = TestAcl::new();
            let entry = TestEntry::case(F1, Privilege::Operate)
                .with_subject(good)
                .expect("the list has room");
            acl.add(entry).expect("a legal CASE subject");
        }
    }

    #[test]
    fn a_group_subject_is_a_group_id_and_nothing_else() {
        // "Group — Lower 16-bits → Group ID, Upper 48-bits → all bits clear", and §11.2.4
        // reserves group 0 for the All-Nodes group.
        let mut acl = TestAcl::new();
        let mut entry = TestEntry::case(F1, Privilege::Operate);
        entry.auth_mode = AuthMode::Group;
        // `ALICE` is deliberately not in this list: it is `0x1111`, which fits in sixteen bits
        // and *is* a well-formed group subject. A node id is only out of shape here when it
        // sets one of the upper forty-eight.
        for bad in [NodeId(0), NodeId(0x0001_0000), NodeId(0x1234_5678)] {
            let candidate = entry.clone().with_subject(bad).expect("the list has room");
            assert_eq!(
                acl.add(candidate).map_err(|e| e.code()),
                Err(ErrorCode::InvalidArgument),
                "{bad:?} was accepted as a Group subject"
            );
        }
        let good = entry.with_subject(NodeId(0x1234)).expect("room");
        acl.add(good).expect("a group id is a group subject");
    }

    #[test]
    fn a_case_admin_subject_outside_the_two_legal_ranges_is_refused() {
        // §11.18.6.8: "not being in either the Operational or CASE Authenticated Tag range"
        // is `InvalidAdminSubject`. A group id or zero names something that can never
        // authenticate over CASE, so an entry for it would be permanently dead — and the
        // node permanently unadministrable.
        let mut acl = TestAcl::new();
        for bad in [NodeId(0), NodeId(0xFFFF_FFFF_FFFF_0001)] {
            assert_eq!(
                acl.add_admin_for_fabric(F1, bad).map_err(|e| e.code()),
                Err(ErrorCode::InvalidArgument),
                "{bad:?}"
            );
        }
        // A CAT is legal, and is how §6.6.3's fleet administrators are granted.
        acl.add_admin_for_fabric(F1, CaseAuthenticatedTag::new(0xFFF1, 1).to_node_id())
            .expect("a CAT is a valid admin subject");
    }

    #[test]
    fn administer_requires_case_whichever_way_it_is_asked_for() {
        // §6.6.2.11: "it SHALL NOT be valid to have an Administer privilege set on an Access
        // Control Entry, unless AuthMode is 'CASE'."
        let mut acl = TestAcl::new();
        for mode in [AuthMode::Group, AuthMode::Pase] {
            let mut entry = TestEntry::case(F1, Privilege::Administer);
            entry.auth_mode = mode;
            assert_eq!(
                acl.add(entry).map_err(|e| e.code()),
                Err(ErrorCode::InvalidArgument),
                "{mode:?} at Administer"
            );
        }
        // Every lower privilege is fine on a Group entry.
        for privilege in [Privilege::View, Privilege::Operate, Privilege::Manage] {
            let mut entry = TestEntry::case(F1, privilege);
            entry.auth_mode = AuthMode::Group;
            acl.add(entry)
                .expect("a group entry below Administer is legal");
        }
    }

    #[test]
    fn a_fabrics_quota_is_its_own() {
        let mut acl = TestAcl::new();
        for _ in 0..DefaultConfig::ACL_ENTRIES_PER_FABRIC {
            acl.add(TestEntry::case(F1, Privilege::View)).expect("fits");
        }
        assert_eq!(
            acl.add(TestEntry::case(F1, Privilege::View))
                .map_err(|e| e.code()),
            Err(ErrorCode::NoSpace)
        );
        acl.add(TestEntry::case(F2, Privilege::View))
            .expect("another fabric has its own quota");
    }

    // --- §6.6.6.3, deriving the subject from the session ------------------------------------

    #[cfg(feature = "rustcrypto")]
    fn session(kind: crate::session::SessionKind) -> crate::session::SecureSession {
        use crate::msg::SessionId;
        use crate::platform::Instant;
        use crate::session::{EstablishedKeys, Role, SecureSession};
        SecureSession::new(
            SessionId(1),
            SessionId(2),
            kind,
            Role::Responder,
            EstablishedKeys::derive(b"shared secret", &[]).expect("derive"),
            1,
            Instant::ZERO,
        )
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn a_pase_session_derives_the_commissioning_subject() {
        // §6.6.6.3's PASE branch sets IsCommissioning unconditionally and presents the
        // passcode id as the subject.
        let s = session(crate::session::SessionKind::Pase);
        let isd = SubjectDescriptor::from_session(&s, None);
        assert_eq!(isd.auth_mode, Some(AuthMode::Pase));
        assert!(isd.is_commissioning);
        assert_eq!(
            isd.subjects.as_slice(),
            &[NodeId(DEFAULT_COMMISSIONING_PASSCODE)]
        );
        assert_eq!(isd.fabric_index, FabricIndex(0), "PASE has no fabric yet");
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn a_case_session_presents_its_node_id_and_every_cat() {
        let mut s = session(crate::session::SessionKind::Case);
        s.fabric_index = F1;
        s.peer_node_id = ALICE;
        let tags = [
            CaseAuthenticatedTag::new(0xAAAA, 1),
            CaseAuthenticatedTag::new(0xBBBB, 2),
            CaseAuthenticatedTag::new(0xCCCC, 3),
        ];
        for tag in tags {
            s.peer_cats.push(tag).expect("three fit");
        }

        let isd = SubjectDescriptor::from_session(&s, None);
        assert_eq!(isd.auth_mode, Some(AuthMode::Case));
        assert!(!isd.is_commissioning);
        assert_eq!(isd.fabric_index, F1);
        assert_eq!(
            isd.subjects.len(),
            4,
            "the node id plus §6.5.6's three CATs"
        );
        assert_eq!(isd.subjects[0], ALICE);
        for (index, tag) in tags.iter().enumerate() {
            assert_eq!(isd.subjects[index + 1], tag.to_node_id());
        }
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn a_case_session_on_the_pending_fabric_is_still_commissioning() {
        // §6.6.6.3: "isd.IsCommissioning = get_fabric_index(session_id) ==
        // get_pending_fabric_index()". A commissioner that has switched from PASE to CASE
        // before the fail-safe commits keeps its standing.
        let mut s = session(crate::session::SessionKind::Case);
        s.fabric_index = F1;
        s.peer_node_id = ALICE;

        assert!(SubjectDescriptor::from_session(&s, Some(F1)).is_commissioning);
        assert!(!SubjectDescriptor::from_session(&s, Some(F2)).is_commissioning);
        assert!(!SubjectDescriptor::from_session(&s, None).is_commissioning);
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn a_case_session_without_a_fabric_authenticates_nobody() {
        // "assert(isd.FabricIndex != 0) # cannot be zero". Rather than carry on with a fabric
        // that names nothing, the derivation returns the "no auth" descriptor — which grants
        // nothing, where fabric 0 would merely have failed to match and looked the same.
        let s = session(crate::session::SessionKind::Case);
        assert_eq!(s.fabric_index.0, 0);
        let isd = SubjectDescriptor::from_session(&s, None);
        assert_eq!(isd.auth_mode, None);
        assert!(isd.subjects.is_empty());
    }

    #[test]
    fn an_unauthenticated_subject_matches_no_entry_at_all() {
        // §6.6.6.3's error path: "Do nothing on error, ISD remains unchanged." A wildcard
        // entry grants everyone on its fabric — and still not this.
        let mut acl = TestAcl::new();
        acl.add(TestEntry::case(F1, Privilege::Administer))
            .expect("add");
        let mut isd = SubjectDescriptor::unauthenticated();
        isd.fabric_index = F1;
        assert!(acl.granted(&node(), &isd, 1, ON_OFF).is_empty());
    }

    #[test]
    fn a_group_subject_presents_its_group_id() {
        let isd = SubjectDescriptor::group(F1, crate::msg::GroupId(7));
        assert_eq!(isd.auth_mode, Some(AuthMode::Group));
        assert_eq!(isd.subjects.as_slice(), &[NodeId(7)]);
        assert!(!isd.is_commissioning);
    }

    #[test]
    fn a_read_of_the_attribute_sees_only_its_own_fabric() {
        let mut acl = TestAcl::new();
        acl.add(TestEntry::case(F1, Privilege::Operate))
            .expect("add");
        acl.add(TestEntry::case(F2, Privilege::Manage))
            .expect("add");
        assert_eq!(acl.len_of_fabric(F1), 1);
        assert!(
            acl.of_fabric(F1)
                .all(|entry| entry.privilege == Privilege::Operate)
        );
    }
}
