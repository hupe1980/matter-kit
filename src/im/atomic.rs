//! Atomic writes: several attributes changed together, or not at all (Core §7.15).
//!
//! > Atomic writes allow a client to make multiple writes to certain sets of attributes
//! > atomically, such that changes are either applied entirely or none at all.
//!
//! The case it exists for is a set of attributes whose *combination* has to be valid — a
//! thermostat's heating and cooling setpoints, where each is legal alone and the pair can be
//! contradictory. Writing them one at a time means passing through a state the device must
//! either reject or briefly obey, and neither is acceptable.
//!
//! §7.15.1's flow is three stages: `AtomicRequest(BeginWrite)` claims a set of attributes,
//! ordinary Write Requests then *pend* rather than apply, and `AtomicRequest(CommitWrite)`
//! applies them together — or `RollbackWrite` throws them away.
//!
//! # What this module is
//!
//! The **state**, which is the part with the security-relevant rules. §7.15.3 defines an
//! Atomic Write State as five things — an endpoint, a cluster, an Atomic Writer ID, the
//! accessing fabric, and a set of attribute ids — and this is the table of them, with the
//! timeout that §7.15.6.4 requires a claim to expire under.
//!
//! Holding the *pending values* is the cluster's, deliberately. A pending value has the
//! cluster's own type, and a table here would have to hold it as bytes and hand the cluster
//! back something it must re-parse — for no gain, since the cluster is the only thing that
//! can evaluate §7.15.3's "integrity checks … in the context of the pending values".
//!
//! # The writer is the session's, never the message's
//!
//! §7.15.2: "If the session context for the transaction is a Secure Session Context, the
//! Atomic Writer ID SHALL be the Peer Node ID stored in the context." A claim identified by
//! something the message carried could be taken over by anyone who could guess it — so
//! [`Writer::from_context`] reads the session and nothing else, and a group message, which
//! has no peer node id, can never hold a claim at all.

use core::marker::PhantomData;

use heapless::Vec;

use crate::config::{AssertValid, Config};
use crate::im::{AttributeId, ClusterId, EndpointId, InteractionContext, Status};
use crate::msg::{FabricIndex, NodeId, NodeIdKind};
use crate::platform::{Duration, Instant};

/// §7.15.4's `AtomicRequestTypeEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestType {
    /// `0` — claim a set of attributes and start pending writes to them.
    BeginWrite = 0,
    /// `1` — apply every pending write, or none.
    CommitWrite = 1,
    /// `2` — "Rollback an atomic write, discarding any pending changes".
    RollbackWrite = 2,
}

impl RequestType {
    /// Reads the enum value off the wire.
    #[must_use]
    pub const fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::BeginWrite),
            1 => Some(Self::CommitWrite),
            2 => Some(Self::RollbackWrite),
            _ => None,
        }
    }
}

/// Who holds a claim — §7.15.2's Atomic Writer ID, together with its fabric.
///
/// §7.15.3 keys a state on both: the same node id on two fabrics is two different clients,
/// and letting one inherit the other's claim would let a second administrator commit writes
/// the first had staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Writer {
    /// The peer's operational Node ID, from the session.
    pub node: NodeId,
    /// The accessing fabric.
    pub fabric: FabricIndex,
}

impl Writer {
    /// The writer an interaction identifies, or `None` when it cannot hold a claim.
    ///
    /// §7.15.6.4: "If an AtomicRequest command is received without an accessing fabric, the
    /// server SHALL return a status code of INVALID_COMMAND", and likewise for a writer id
    /// that is "either unavailable or not a valid Operational Node ID". Both are `None` here.
    ///
    /// A PASE session has no operational node id, and a group message has no peer at all, so
    /// neither can begin an atomic write — which is right: an atomic write is a claim held
    /// across several messages, and a claim needs somebody to be held *by*.
    #[must_use]
    pub fn from_context(ctx: &InteractionContext<'_>) -> Option<Self> {
        let node = ctx.peer_node_id?;
        if !matches!(node.kind(), NodeIdKind::Operational) {
            return None;
        }
        let fabric = ctx.fabric_index?;
        if fabric.0 == 0 {
            return None;
        }
        Some(Self { node, fabric })
    }
}

/// One Atomic Write State (§7.15.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim<const A: usize> {
    /// Which endpoint.
    pub endpoint: EndpointId,
    /// Which cluster instance on it.
    pub cluster: ClusterId,
    /// Who holds it.
    pub writer: Writer,
    /// The attributes it covers.
    pub attributes: Vec<AttributeId, A>,
    /// When it lapses if no `CommitWrite` arrives (§7.15.6.4 BeginWrite step 3(e)(iii)).
    pub deadline: Instant,
}

impl<const A: usize> Claim<A> {
    /// A borrowed, non-generic view of this claim.
    ///
    /// What [`InteractionContext`] carries: the server needs only "which attributes, on which
    /// cluster instance", and threading `A` through every layer that touches a write would
    /// spread one table's sizing across the whole interaction model.
    #[must_use]
    pub fn as_ref(&self) -> ClaimRef<'_> {
        ClaimRef {
            endpoint: self.endpoint,
            cluster: self.cluster,
            attributes: &self.attributes,
        }
    }
}

/// The claim an action is writing under (§7.15.3), as the server sees it.
///
/// Derived by the caller from [`AtomicWrites::find`] and asserted by the server — the same
/// shape as [`InteractionContext::timed`], and for the same reason: the table that knows the
/// answer is the device's, and the interaction model's job is to *apply* it rather than to own
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimRef<'a> {
    /// The endpoint the claim is on.
    pub endpoint: EndpointId,
    /// The cluster instance it covers.
    pub cluster: ClusterId,
    /// The attributes it covers.
    pub attributes: &'a [AttributeId],
}

impl ClaimRef<'_> {
    /// Whether this claim covers one attribute of one cluster instance.
    #[must_use]
    pub fn covers(&self, endpoint: EndpointId, cluster: ClusterId, attribute: AttributeId) -> bool {
        self.endpoint == endpoint && self.cluster == cluster && self.attributes.contains(&attribute)
    }
}

/// The claims a node is holding (§7.15.3).
///
/// `N` is how many may be open at once and `A` how many attributes one may cover.
#[derive(Debug)]
pub struct AtomicWrites<C: Config, const N: usize, const A: usize> {
    claims: Vec<Claim<A>, N>,
    _config: PhantomData<C>,
}

impl<C: Config, const N: usize, const A: usize> Default for AtomicWrites<C, N, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Config, const N: usize, const A: usize> AtomicWrites<C, N, A> {
    /// A node holding no claims.
    #[must_use]
    pub fn new() -> Self {
        let () = AssertValid::<C>::CHECK;
        Self {
            claims: Vec::new(),
            _config: PhantomData,
        }
    }

    /// How many claims are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Every open claim.
    pub fn iter(&self) -> impl Iterator<Item = &Claim<A>> {
        self.claims.iter()
    }

    /// §7.15.6.4's `BeginWrite`.
    ///
    /// The per-attribute statuses §7.15.6.4 BeginWrite step 3(a) asks for are the *cluster's*
    /// to produce — only it knows whether an attribute supports atomic writes or whether it
    /// has room to pend a value. What this decides is the two rules that are about the table:
    ///
    /// * a client already holding a claim on the same cluster and endpoint is
    ///   [`Status::InvalidInState`] (§7.15.6.4 BeginWrite step 1);
    /// * an attribute another client is already using is [`Status::Busy`]
    ///   (§7.15.6.4 BeginWrite step 3(a)(iii)).
    ///
    /// `attributes` must be non-empty and free of duplicates — §7.15.6.4's rules 1 and 2, both
    /// [`Status::InvalidCommand`].
    pub fn begin(
        &mut self,
        endpoint: EndpointId,
        cluster: ClusterId,
        writer: Writer,
        attributes: &[AttributeId],
        timeout: Duration,
        now: Instant,
    ) -> Result<(), Status> {
        // Rule 1: "If the AttributeRequests field is empty, the server SHALL return an error
        // code of INVALID_COMMAND."
        if attributes.is_empty() {
            return Err(Status::InvalidCommand);
        }
        // Rule 2: duplicates. A set that named an attribute twice would be committed twice,
        // and the second write would see the first's pending value as if it were current.
        for (index, id) in attributes.iter().enumerate() {
            if attributes
                .get(index.saturating_add(1)..)
                .is_some_and(|rest| rest.contains(id))
            {
                return Err(Status::InvalidCommand);
            }
        }

        // §7.15.6.4 BeginWrite step 1: one claim per client per cluster instance.
        if self.find(endpoint, cluster, writer).is_some() {
            return Err(Status::InvalidInState);
        }
        // §7.15.6.4 BeginWrite step 3(a)(iii): "If the specified attribute is currently being
        // used by a different atomic write, the status SHALL be BUSY."
        for id in attributes {
            if self.holder(endpoint, cluster, *id).is_some() {
                return Err(Status::Busy);
            }
        }

        let mut held = Vec::new();
        for id in attributes {
            held.push(*id).map_err(|_| Status::ResourceExhausted)?;
        }
        self.claims
            .push(Claim {
                endpoint,
                cluster,
                writer,
                attributes: held,
                deadline: now.saturating_add(timeout),
            })
            .map_err(|_| Status::ResourceExhausted)
    }

    /// §7.15.6's `CommitWrite` and `RollbackWrite`: releases the claim.
    ///
    /// Both end the claim; what differs is whether the cluster applies its pending values,
    /// which it does on the strength of the [`RequestType`] it was given. Returns
    /// [`Status::InvalidInState`] when the client holds no matching claim — §7.15.6's rule 1
    /// for `CommitWrite`, which requires the attribute set to match too, "irrespective of
    /// order".
    pub fn finish(
        &mut self,
        endpoint: EndpointId,
        cluster: ClusterId,
        writer: Writer,
        attributes: &[AttributeId],
    ) -> Result<(), Status> {
        let Some(index) = self
            .claims
            .iter()
            .position(|c| c.endpoint == endpoint && c.cluster == cluster && c.writer == writer)
        else {
            return Err(Status::InvalidInState);
        };
        let matches = self
            .claims
            .get(index)
            .is_some_and(|claim| same_set(&claim.attributes, attributes));
        if !matches {
            return Err(Status::InvalidInState);
        }
        self.claims.swap_remove(index);
        Ok(())
    }

    /// The claim a client holds on a cluster instance, if any.
    #[must_use]
    pub fn find(
        &self,
        endpoint: EndpointId,
        cluster: ClusterId,
        writer: Writer,
    ) -> Option<&Claim<A>> {
        self.claims
            .iter()
            .find(|c| c.endpoint == endpoint && c.cluster == cluster && c.writer == writer)
    }

    /// Who holds a claim covering one attribute, if anybody.
    #[must_use]
    pub fn holder(
        &self,
        endpoint: EndpointId,
        cluster: ClusterId,
        attribute: AttributeId,
    ) -> Option<Writer> {
        self.claims
            .iter()
            .find(|c| {
                c.endpoint == endpoint && c.cluster == cluster && c.attributes.contains(&attribute)
            })
            .map(|c| c.writer)
    }

    /// Whether a write to an attribute with the Atomic quality may proceed (§7.15.3).
    ///
    /// > If a server receives a Write Request for an attribute that is not associated with an
    /// > Atomic Write State that is also associated with the client making the request, the
    /// > server SHALL return the error code INVALID_IN_STATE.
    ///
    /// Both halves matter, and they are different failures. A write with **no** claim is a
    /// client that skipped `BeginWrite`; a write against **somebody else's** claim is a client
    /// trying to change values another client has staged and is about to commit.
    pub fn check_write(
        &self,
        endpoint: EndpointId,
        cluster: ClusterId,
        writer: Option<Writer>,
        attribute: AttributeId,
    ) -> Result<(), Status> {
        let Some(writer) = writer else {
            return Err(Status::InvalidInState);
        };
        match self.find(endpoint, cluster, writer) {
            Some(claim) if claim.attributes.contains(&attribute) => Ok(()),
            _ => Err(Status::InvalidInState),
        }
    }

    /// Drops every claim whose timeout has passed, returning how many — §7.15.6.4 BeginWrite
    /// step 3(e)(iii).
    ///
    /// > If the server does not receive a matching AtomicRequest with a RequestType of
    /// > CommitWrite from the associated client before the timeout … the server SHALL roll
    /// > back any pending writes and discard the atomic write.
    ///
    /// Without this a client that crashed mid-write would hold its attributes against every
    /// other client until the device was restarted.
    pub fn reap(&mut self, now: Instant) -> usize {
        let before = self.claims.len();
        self.claims.retain(|claim| claim.deadline > now);
        before.saturating_sub(self.claims.len())
    }

    /// Drops every claim a fabric holds — what `RemoveFabric` must do.
    pub fn remove_fabric(&mut self, fabric: FabricIndex) -> usize {
        let before = self.claims.len();
        self.claims.retain(|claim| claim.writer.fabric != fabric);
        before.saturating_sub(self.claims.len())
    }

    /// When [`AtomicWrites::reap`] next has something to do.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.claims.iter().map(|c| c.deadline).min()
    }
}

/// Whether two attribute sets are equal "irrespective of order" (§7.15.6's Commit rule 1).
fn same_set(held: &[AttributeId], asked: &[AttributeId]) -> bool {
    held.len() == asked.len() && held.iter().all(|id| asked.contains(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultConfig;

    type Table = AtomicWrites<DefaultConfig, 4, 4>;

    const EP: EndpointId = 1;
    const THERMOSTAT: ClusterId = 0x0201;
    const HEAT: AttributeId = 0x0012;
    const COOL: AttributeId = 0x0011;

    fn alice() -> Writer {
        Writer {
            node: NodeId(0x0000_0000_0000_1111),
            fabric: FabricIndex(1),
        }
    }

    fn bob() -> Writer {
        Writer {
            node: NodeId(0x0000_0000_0000_2222),
            fabric: FabricIndex(1),
        }
    }

    fn at(ms: u64) -> Instant {
        Instant::from_micros(ms.saturating_mul(1000))
    }

    fn timeout() -> Duration {
        Duration::from_millis(1_000)
    }

    #[test]
    fn a_claim_covers_its_attributes_and_only_its_own_client() {
        let mut table = Table::new();
        table
            .begin(EP, THERMOSTAT, alice(), &[HEAT, COOL], timeout(), at(0))
            .expect("begin");

        assert!(
            table
                .check_write(EP, THERMOSTAT, Some(alice()), HEAT)
                .is_ok()
        );
        // Somebody else's claim is not a licence to write into it.
        assert_eq!(
            table.check_write(EP, THERMOSTAT, Some(bob()), HEAT),
            Err(Status::InvalidInState)
        );
        // Nor is an attribute the claim does not cover.
        assert_eq!(
            table.check_write(EP, THERMOSTAT, Some(alice()), 0x0099),
            Err(Status::InvalidInState)
        );
    }

    #[test]
    fn writing_an_atomic_attribute_with_no_claim_is_invalid_in_state() {
        // §7.15.3: an attribute with the Atomic quality is writable only inside a claim, so a
        // client that skipped BeginWrite is told so rather than having its write applied.
        let table = Table::new();
        assert_eq!(
            table.check_write(EP, THERMOSTAT, Some(alice()), HEAT),
            Err(Status::InvalidInState)
        );
        // And a session with no writer at all — a PASE or group one — never has a claim.
        assert_eq!(
            table.check_write(EP, THERMOSTAT, None, HEAT),
            Err(Status::InvalidInState)
        );
    }

    #[test]
    fn a_second_claim_on_the_same_cluster_by_the_same_client_is_refused() {
        // §7.15.6.4 BeginWrite step 1: one claim per client per cluster instance.
        let mut table = Table::new();
        table
            .begin(EP, THERMOSTAT, alice(), &[HEAT], timeout(), at(0))
            .expect("begin");
        assert_eq!(
            table.begin(EP, THERMOSTAT, alice(), &[COOL], timeout(), at(0)),
            Err(Status::InvalidInState)
        );
    }

    #[test]
    fn an_attribute_another_client_has_claimed_is_busy() {
        // §7.15.6.4 BeginWrite step 3(a)(iii). `BUSY` rather than a flat refusal because the
        // client "could attempt to write to it again after a pause" — try later, not never.
        let mut table = Table::new();
        table
            .begin(EP, THERMOSTAT, alice(), &[HEAT], timeout(), at(0))
            .expect("begin");
        assert_eq!(
            table.begin(EP, THERMOSTAT, bob(), &[HEAT], timeout(), at(0)),
            Err(Status::Busy)
        );
        // A disjoint set is fine: two clients may stage different attributes at once.
        table
            .begin(EP, THERMOSTAT, bob(), &[COOL], timeout(), at(0))
            .expect("a different attribute is free");
    }

    #[test]
    fn an_empty_or_duplicated_attribute_set_is_invalid() {
        // §7.15.6.4 rules 1 and 2. A duplicate would be committed twice, with the second
        // write seeing the first's pending value as if it were the current one.
        let mut table = Table::new();
        assert_eq!(
            table.begin(EP, THERMOSTAT, alice(), &[], timeout(), at(0)),
            Err(Status::InvalidCommand)
        );
        assert_eq!(
            table.begin(EP, THERMOSTAT, alice(), &[HEAT, HEAT], timeout(), at(0)),
            Err(Status::InvalidCommand)
        );
    }

    #[test]
    fn committing_requires_the_same_set_in_any_order() {
        // §7.15.6's Commit rule 1: the set must match "irrespective of order" — order is not
        // meaningful, but a *different* set means the client and server disagree about what
        // is being committed, and applying either reading would be a guess.
        let mut table = Table::new();
        table
            .begin(EP, THERMOSTAT, alice(), &[HEAT, COOL], timeout(), at(0))
            .expect("begin");

        assert_eq!(
            table.finish(EP, THERMOSTAT, alice(), &[HEAT]),
            Err(Status::InvalidInState),
            "a subset is not the set"
        );
        assert_eq!(
            table.finish(EP, THERMOSTAT, bob(), &[COOL, HEAT]),
            Err(Status::InvalidInState),
            "and not another client's"
        );
        table
            .finish(EP, THERMOSTAT, alice(), &[COOL, HEAT])
            .expect("the same set, reordered");
        assert!(table.is_empty(), "the claim is released either way");
    }

    #[test]
    fn a_claim_that_is_never_committed_lapses() {
        // §7.15.6.4 BeginWrite step 3(e)(iii). Without it a client that crashed mid-write would
        // hold its attributes against everyone else until the device restarted.
        let mut table = Table::new();
        table
            .begin(EP, THERMOSTAT, alice(), &[HEAT], timeout(), at(0))
            .expect("begin");
        assert_eq!(table.next_deadline(), Some(at(1_000)));

        assert_eq!(table.reap(at(999)), 0, "not yet");
        assert_eq!(table.reap(at(1_001)), 1, "lapsed");
        assert!(table.is_empty());

        // ...and the attribute is free for somebody else.
        table
            .begin(EP, THERMOSTAT, bob(), &[HEAT], timeout(), at(1_001))
            .expect("no longer held");
    }

    #[test]
    fn only_an_operational_node_on_a_fabric_can_hold_a_claim() {
        // §7.15.2: the writer is the session's Peer Node ID, and "an Atomic Writer ID that is
        // not a valid Operational Node ID SHALL be invalid". A PASE session has no
        // operational identity, so it can stage nothing.
        let mut ctx = InteractionContext::new();
        assert_eq!(Writer::from_context(&ctx), None, "no peer at all");

        ctx.peer_node_id = Some(NodeId(0x0000_0000_0000_1111));
        assert_eq!(Writer::from_context(&ctx), None, "no accessing fabric");

        ctx.fabric_index = Some(FabricIndex(1));
        assert_eq!(
            Writer::from_context(&ctx),
            Some(alice()),
            "a CASE session on a fabric"
        );

        // A group node id is not operational, so it can never be a writer.
        ctx.peer_node_id = Some(NodeId(0xFFFF_FFFF_FFFF_0001));
        assert_eq!(Writer::from_context(&ctx), None);
    }

    #[test]
    fn removing_a_fabric_releases_its_claims() {
        let mut table = Table::new();
        table
            .begin(EP, THERMOSTAT, alice(), &[HEAT], timeout(), at(0))
            .expect("begin");
        let other_fabric = Writer {
            node: NodeId(0x0000_0000_0000_3333),
            fabric: FabricIndex(2),
        };
        table
            .begin(EP, THERMOSTAT, other_fabric, &[COOL], timeout(), at(0))
            .expect("begin");

        assert_eq!(table.remove_fabric(FabricIndex(1)), 1);
        assert_eq!(table.len(), 1);
        assert!(table.find(EP, THERMOSTAT, other_fabric).is_some());
    }

    #[test]
    fn the_same_node_id_on_two_fabrics_is_two_clients() {
        // §7.15.3 keys a state on the fabric as well as the writer. Letting one inherit the
        // other's claim would let a second administrator commit writes the first had staged.
        let mut table = Table::new();
        let on_one = alice();
        let on_two = Writer {
            node: on_one.node,
            fabric: FabricIndex(2),
        };
        table
            .begin(EP, THERMOSTAT, on_one, &[HEAT], timeout(), at(0))
            .expect("begin");
        assert_eq!(
            table.check_write(EP, THERMOSTAT, Some(on_two), HEAT),
            Err(Status::InvalidInState)
        );
    }
}
