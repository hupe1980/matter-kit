//! What a command leaves for the node: §11.10.7.2.2's rollback, §11.10.7.6's commit,
//! §11.18.6.8's and §11.18.6.12's fabric changes, and §9.10.9.1's audit events.
//!
//! Each of these touches state no cluster owns — the session table, the subscriptions, the group
//! key store, the channel — so the clusters *report* it and the node *applies* it. Skipping any
//! one leaves a disarmed fail-safe's fabric behind, a joined fabric no administrator can reach, a
//! `KeySetRead(0)` that answers `NotFound`, or subscriptions that outlive their fabric.

use heapless::Vec;

use super::{AccessList, ChangeLog, Device, EventLog, GroupKeyStore, Notice, Runtime};
use crate::clusters::access_control;
use crate::clusters::general_commissioning::Aftermath;
use crate::clusters::operational_credentials::FabricChange;
use crate::commissioning::failsafe::Cleanup;
use crate::config::Config;
use crate::crypto::KeyStore;
use crate::dm::EventPriority;
use crate::dm::events::{NewEvent, Timestamp};
use crate::im::{ClusterHandler, InteractionContext, Lifecycle};
use crate::msg::{FabricIndex, NodeId, SessionId};
use crate::platform::{Instant, Rng};
use crate::session::SessionKind;

/// What waits until the reply has been queued.
///
/// §11.18.6.12 has the node "send the NOCResponse" and *then* terminate the removed fabric's
/// sessions, and an administrator removing its own fabric is the ordinary case — closing first
/// strands the reply on an exchange that no longer exists, which the controller sees as a timeout
/// on a command the node has carried out. `ArmFailSafe(0)` and `CommissioningComplete` arrive on
/// the very sessions their cleanup closes, for the same reason.
#[derive(Debug, Default)]
pub(super) struct Deferred {
    close_fabrics: Vec<FabricIndex, 2>,
    close_pase: bool,
}

impl<
    C: Config,
    const S: usize,
    const X: usize,
    const I: usize,
    const R: usize,
    const Q: usize,
    const B: usize,
> Runtime<C, S, X, I, R, Q, B>
{
    /// Applies what the last interaction left behind, in the order §11.10.7.2.2 needs: the
    /// aftermath first (a rollback removes a fabric, which is itself a change), then the fabric
    /// change, then the access-control events both of those produce.
    pub(super) fn follow_up<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        session: SessionId,
        now: Instant,
    ) -> Deferred
    where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let mut deferred = Deferred::default();
        let ctx = self.admin_context(session, now);
        match device.commissioning.take_aftermath() {
            Some(Aftermath::Rollback(cleanup)) => {
                self.rollback(device, cleanup, &ctx, &mut deferred);
            }
            Some(Aftermath::Commissioned) => {
                // §11.10.7.6 is CASE-only and fabric-matched, so the session it arrived on names
                // the fabric being committed. What the fail-safe protected is now permanent:
                // every cluster drops the snapshot it would otherwise revert to at the *next*
                // expiry, however many commissionings later that is.
                let committed = self
                    .stack
                    .sessions()
                    .find(session)
                    .map(|s| s.fabric_index)
                    .filter(|i| i.0 != 0);
                device.credentials.commit_update();
                if let Some(fabric) = committed {
                    device
                        .handler
                        .on_lifecycle(Lifecycle::CommissioningComplete(fabric));
                    self.notify(Notice::Commissioned(fabric));
                }
                // Steps 3 and 4: "Revoke the temporary administrative privileges granted to any
                // open PASE session" and clear its Secure Session Context.
                deferred.close_pase = true;
            }
            None => {}
        }
        self.fabric_change(device, session, &ctx, &mut deferred);
        self.audit(device, now);
        deferred
    }

    /// The context a follow-up acts in: the session's peer, so §9.10.9.1's change records name
    /// the administrator (CASE) or the passcode (PASE) that caused them.
    fn admin_context(&self, session: SessionId, now: Instant) -> InteractionContext<'static> {
        let mut ctx = InteractionContext::new().at(now).on_session(session);
        if let Some(s) = self.stack.sessions().find(session) {
            if s.fabric_index.0 != 0 {
                ctx = ctx.with_fabric(s.fabric_index);
            }
            if s.peer_node_id.kind() == crate::msg::NodeIdKind::Operational {
                ctx = ctx.from_peer(s.peer_node_id);
            }
        }
        ctx
    }

    /// §11.10.7.2.2's cleanup steps, in order.
    fn rollback<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        cleanup: Cleanup,
        ctx: &InteractionContext<'_>,
        deferred: &mut Deferred,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        // Steps 2 and 3: every PASE session, after the reply.
        deferred.close_pase |= cleanup.close_pase_sessions;
        // Step 4: the fabric's CASE sessions, after the reply.
        if let Some(fabric) = cleanup.close_case_sessions_for {
            push_unique(&mut deferred.close_fabrics, fabric);
        }
        // Step 6: an `UpdateNOC` goes back to the identity it replaced.
        if let Some(fabric) = cleanup.revert_noc_for {
            device.credentials.revert_update(fabric);
        }
        // Step 5 and everything like it: each cluster reverts what it staged — one broadcast
        // rather than a list the application keeps in step with its cluster set.
        device.handler.on_lifecycle(Lifecycle::FailSafeExpired {
            fabric: cleanup
                .remove_fabric
                .or(cleanup.revert_noc_for)
                .or(cleanup.close_case_sessions_for),
        });
        // Step 7: the fabric `AddNOC` added, "as though by RemoveFabric" — which is exactly the
        // call, so its key is destroyed and the `FabricChange` it reports strips the rest.
        if let Some(fabric) = cleanup.remove_fabric {
            let _ = device.credentials.remove_fabric(fabric, ctx);
        }
        // Steps 8 and 9.
        if cleanup.discard_operational_key || cleanup.prune_trusted_roots {
            device.credentials.discard_pending();
        }
        self.notify(Notice::RolledBack);
    }

    /// §11.18.6.8 and §11.18.6.12's work for the node.
    fn fabric_change<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        session: SessionId,
        ctx: &InteractionContext<'_>,
        deferred: &mut Deferred,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let Some(change) = device.credentials.take_change() else {
            return;
        };
        match change {
            FabricChange::Added {
                index,
                case_admin_subject,
                bind_pase_session,
            } => {
                // Step 7. Without it "there would be no way for the caller on its given Fabric to
                // eventually add another Access Control Entry for CASE authentication mode" — the
                // fabric is joined and every operational interaction is `UNSUPPORTED_ACCESS`.
                // Through the cluster, not the list, so it is recorded as a change (§9.10.9.1).
                let _ = device
                    .access_control
                    .grant_admin(index, NodeId(case_admin_subject), ctx);
                // Step 10a: "augment the currently executing PASE session with the FabricIndex
                // generated above, such that subsequent interactions have the proper accessing
                // fabric".
                if bind_pase_session
                    && let Some(s) = self.stack.sessions_mut().find_mut(session)
                    && s.kind == SessionKind::Pase
                {
                    s.fabric_index = index;
                }
                // "having provided it is equivalent to a KeySetWrite of group key set 0" — so
                // the node performs that write; without it `KeySetRead(0)` answers `NotFound` on
                // a node just commissioned with an IPK it accepted.
                let ipk = device
                    .credentials
                    .fabrics
                    .borrow()
                    .find(index)
                    .map(|f| f.ipk.clone());
                if let Some(ipk) = ipk {
                    let _ = device.group_keys.install_ipk(index, ipk);
                }
                self.notify(Notice::FabricAdded(index));
            }
            FabricChange::Updated { index } => self.notify(Notice::FabricUpdated(index)),
            FabricChange::Removed { index, .. } => {
                // §11.18.6.12: "SHALL remove all associated data". The clusters hear it through
                // the handler; what is the node's own — subscriptions, the window this fabric
                // opened — goes here. Fabric indices are reused, so anything that outlives its
                // fabric is inherited by the next holder of the index.
                device.handler.on_lifecycle(Lifecycle::FabricRemoved(index));
                self.im.subscriptions.remove_for_fabric(index);
                device
                    .commissioning
                    .window
                    .borrow_mut()
                    .forget_fabric(index);
                push_unique(&mut deferred.close_fabrics, index);
                self.notify(Notice::FabricRemoved(index));
            }
        }
    }

    /// §9.10.9.1: "the cluster SHALL generate an AccessControlEntryChanged event" for every add,
    /// change or removal. The cluster records what happened; turning it into an *event* is the
    /// node's, because the event store is the node's. And recording is half of reporting: an
    /// urgent event subscriber learns of it only when the subscription table is told.
    pub(super) fn audit<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        now: Instant,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let mut lost: Vec<Option<crate::dm::events::RecordError>, 4> = Vec::new();
        let mut recorded = false;
        device.access_control.drain_changes(&mut |fabric, encoded| {
            let Ok(data) = encoded else {
                let _ = lost.push(None);
                return;
            };
            let event = NewEvent {
                endpoint: 0,
                cluster: access_control::ID,
                event: access_control::ACCESS_CONTROL_ENTRY_CHANGED,
                priority: EventPriority::Info,
                timestamp: Timestamp::System(now.as_millis()),
                // §7.14.4: the event belongs to the fabric whose list changed, so one
                // administrator cannot read another's audit trail.
                fabric_index: Some(fabric),
                data,
            };
            match device.events.record(&event) {
                Ok(_) => recorded = true,
                Err(e) => {
                    let _ = lost.push(Some(e));
                }
            }
        });
        if recorded {
            self.im.subscriptions.note_event(
                0,
                access_control::ID,
                access_control::ACCESS_CONTROL_ENTRY_CHANGED,
            );
        }
        for e in lost {
            self.notify(Notice::EventLost(e));
        }
    }

    /// Runs what waited for the reply.
    pub(super) fn apply(&mut self, deferred: Deferred) {
        for fabric in deferred.close_fabrics {
            // Through the stack, so the exchanges go too: §4.13.3.1 removes "all state associated
            // with the session".
            let sessions: Vec<SessionId, S> = self
                .stack
                .sessions()
                .iter()
                .filter(|s| s.fabric_index == fabric)
                .map(|s| s.local_session_id)
                .collect();
            for session in sessions {
                self.close_session(session);
            }
            self.im.subscriptions.remove_for_fabric(fabric);
        }
        if deferred.close_pase {
            let sessions: Vec<SessionId, S> = self
                .stack
                .sessions()
                .iter()
                .filter(|s| s.kind == SessionKind::Pase)
                .map(|s| s.local_session_id)
                .collect();
            for session in sessions {
                self.close_session(session);
            }
        }
    }

    /// §11.10.7.2.2's "Behavior on expiry of Fail-Safe timer": when the deadline passes with no
    /// command arriving, "the fail-safe cleanup steps SHALL be executed". A commissioner that
    /// disconnects after `AddNOC` otherwise leaves its fabric installed until some later command
    /// happens to notice the lapse.
    pub(super) fn expire_fail_safe<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        now: Instant,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let lapsed = device.commissioning.fail_safe.borrow_mut().expire(now);
        let Some(cleanup) = lapsed else {
            return;
        };
        let mut deferred = Deferred::default();
        let ctx = InteractionContext::new().at(now);
        self.rollback(device, cleanup, &ctx, &mut deferred);
        self.fabric_change(device, SessionId(0), &ctx, &mut deferred);
        self.audit(device, now);
        // No reply is waiting, so nothing is stranded by closing now.
        self.apply(deferred);
    }
}

fn push_unique<const N: usize>(list: &mut Vec<FabricIndex, N>, fabric: FabricIndex) {
    if !list.contains(&fabric) {
        let _ = list.push(fabric);
    }
}
