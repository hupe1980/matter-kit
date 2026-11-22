//! The interaction-model path: one message in, at most one reply out (§8, §10.2.3).

use heapless::Vec;

use super::interactions::PendingSubscribe;
use super::{
    AccessList, ChangeLog, Device, EventLog, GroupKeyStore, Notice, REPORT_LIMIT, Runtime,
    SUBSCRIPTION_PATHS,
};
use crate::acl::SubjectDescriptor;
use crate::config::{Config, MAX_UDP_PAYLOAD};
use crate::crypto::{KeyStore, SymmetricKey};
use crate::error::{Error, ErrorCode, Result};
use crate::exchange::ExchangeKey;
use crate::im::{
    AttributePath, ClusterHandler, EventPath, InteractionContext, NewSubscription, ReadCursor,
    ReportReason, Request, Served, Server, Status, StatusResponse, SubscribeResponse,
    SubscriptionPolicy, opcode,
};
use crate::msg::{FabricIndex, NodeIdKind, ProtocolId};
use crate::platform::{Duration, Instant, PeerAddr, Rng};

/// How long a subscription whose report could not be built waits before the next attempt.
const REPORT_RETRY: Duration = Duration::from_secs(1);

/// Who is asking, read from the session an interaction arrived on (§6.6.6.3).
struct Asker {
    subject: SubjectDescriptor,
    fabric: Option<FabricIndex>,
    peer: Option<crate::msg::NodeId>,
    /// §6.2.3's attestation challenge, "derived during session establishment of the current
    /// secure session" — the session's own, never whichever handshake ran last. Taking it from
    /// the PASE channel leaves a CASE session with none, so a `CSRRequest` over CASE — the
    /// UpdateNOC rotation — is refused outright.
    challenge: Option<SymmetricKey>,
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
    /// §6.6.6.3 derives the subject from **session metadata**, never from the message: "the id in
    /// a message header is whatever the sender wrote, while the id in a session context is what
    /// CASE proved". Over PASE that is the commissioner; over CASE the peer CASE authenticated,
    /// with its fabric and CATs. A CASE session on the fabric `AddNOC` created and the fail-safe
    /// has not committed still counts as commissioning, which is how a commissioner that moved
    /// from PASE to CASE mid-flow keeps its standing.
    fn asker<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        exchange: ExchangeKey,
        now: Instant,
    ) -> Asker
    where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let Some(session) = self.stack.sessions().find(exchange.session) else {
            return Asker {
                subject: SubjectDescriptor::unauthenticated(),
                fabric: None,
                peer: None,
                challenge: None,
            };
        };
        let pending = device
            .commissioning
            .fail_safe
            .borrow()
            .armed(now)
            .and_then(|a| a.fabric_index);
        Asker {
            subject: SubjectDescriptor::from_session(session, pending),
            fabric: Some(session.fabric_index).filter(|i| i.0 != 0),
            peer: Some(session.peer_node_id),
            challenge: Some(session.keys.attestation_challenge.clone()),
        }
    }

    /// Serves one interaction-model message on a session, driving §10.2.3's series and §8.5.2's
    /// subscribe flow. `Ok(None)` means send nothing — a suppressed write, or a `StatusResponse`
    /// acknowledging the last chunk of a finished series.
    pub(super) fn interaction<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        exchange: ExchangeKey,
        op: u8,
        body: &[u8],
        now: Instant,
    ) -> Result<Option<(u8, usize)>>
    where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let asker = self.asker(device, exchange, now);
        // Every field here is load-bearing:
        //
        // - the **session**: §11.18.6.7 scopes CSR state to the session that requested it — "If
        //   no context or memory exists of a prior CSRRequest command having been invoked in the
        //   same secure session" — so without it one administrator's `AddNOC` consumes another's
        //   `CSRRequest`;
        // - the **accessing fabric**: §8.8.2.3 step b.v makes every fabric-scoped command
        //   `UNSUPPORTED_ACCESS` without one, so a node that never sets it commissions and then
        //   refuses `CommissioningComplete`;
        // - the **peer node id**: §9.10.9.1's "Exactly one of AdminNodeID and AdminPasscodeID
        //   SHALL be set, depending on whether the change occurred via a CASE or PASE session";
        // - the **attestation challenge**: what `AttestationRequest` signs over (§6.2.3).
        let mut ctx = InteractionContext::new()
            .at(now)
            .on_session(exchange.session);
        if let Some(fabric) = asker.fabric {
            ctx = ctx.with_fabric(fabric);
        }
        if let Some(challenge) = &asker.challenge {
            ctx = ctx.with_attestation_challenge(challenge);
        }
        if let Some(peer) = asker.peer.filter(|id| id.kind() == NodeIdKind::Operational) {
            ctx = ctx.from_peer(peer);
        }

        let access = device.access_control.access(device.node, &asker.subject);
        let server = Server::new(device.node, &access, device.handler, REPORT_LIMIT)
            .with_data_versions(device.versions)
            .with_events(device.events.source());

        let interaction = self
            .im
            .interactions
            .get(exchange, now)
            .ok_or(Error::new(ErrorCode::NoSpace))?;

        // A `StatusResponse` is one of three things, and this exchange's state says which: the
        // client asking for the next chunk of a read (§10.2.3), acknowledging a priming report
        // (§8.5.2), or closing a series. A non-success status ends the series either way.
        if op == opcode::STATUS_RESPONSE {
            let succeeded = StatusResponse::decode(body).is_ok_and(|r| r.status == Status::Success);
            if !succeeded {
                interaction.pending_read.clear();
                interaction.pending_subscribe = None;
                return Ok(None);
            }
            if let Some(pending) = interaction.pending_subscribe.take() {
                return self.priming_acknowledged(&server, &ctx, exchange, pending, now);
            }
            if interaction.pending_read.is_empty() {
                return Ok(None);
            }
        }

        // The continuation is served from the request this node already has. Copied out, because
        // the series state is updated below with the outcome.
        let continuation: Vec<u8, MAX_UDP_PAYLOAD> = interaction.pending_read.clone();
        let (op, body) = if op == opcode::STATUS_RESPONSE {
            (opcode::READ_REQUEST, &continuation[..])
        } else {
            // A *new* read starts a new series, whatever was pending on this exchange.
            if op == opcode::READ_REQUEST {
                interaction.read_cursor = ReadCursor::START;
                interaction.pending_read.clear();
            }
            (op, body)
        };
        let request = Request {
            opcode: op,
            payload: body,
            session: Some(exchange.session),
            exchange: exchange.id,
            groupcast: false,
        };
        let served = self.im.dispatcher.dispatch(
            &server,
            request,
            &ctx,
            &mut interaction.read_cursor,
            &mut self.buf.scratch,
            &mut self.buf.payload,
        )?;
        match served {
            Served::Reply {
                opcode: reply,
                len,
                more_chunks,
            } => {
                if op == opcode::READ_REQUEST {
                    interaction.pending_read.clear();
                    // Keep the request: the client's acknowledgement is the cue for the rest. One
                    // too large to keep ends the series rather than continuing from a truncated
                    // copy — which would serve paths the client never asked for.
                    if more_chunks && interaction.pending_read.extend_from_slice(body).is_err() {
                        interaction.pending_read.clear();
                        let len = StatusResponse::new(Status::ResourceExhausted)
                            .encode(&mut self.buf.payload)?
                            .len();
                        return Ok(Some((opcode::STATUS_RESPONSE, len)));
                    }
                }
                Ok(Some((reply, len)))
            }
            Served::Silent | Served::Unhandled { .. } => Ok(None),
            Served::Subscribe(subscribe) => {
                // §8.5.2's flow is four messages, not two: SubscribeRequest, a priming
                // ReportData, the subscriber's StatusResponse, and only then the
                // SubscribeResponse naming the id and the interval granted.
                let mut paths: Vec<AttributePath, SUBSCRIPTION_PATHS> = Vec::new();
                if let Some(iter) = subscribe.attribute_paths()? {
                    for path in iter {
                        if paths.push(path?).is_err() {
                            return status(Status::ResourceExhausted, &mut self.buf.payload);
                        }
                    }
                }
                let mut event_paths: Vec<EventPath, SUBSCRIPTION_PATHS> = Vec::new();
                if let Some(iter) = subscribe.event_paths()? {
                    for path in iter {
                        if event_paths.push(path?).is_err() {
                            return status(Status::ResourceExhausted, &mut self.buf.payload);
                        }
                    }
                }
                let max_interval_s = SubscriptionPolicy::default().max_interval(
                    subscribe.min_interval_floor_s,
                    subscribe.max_interval_ceiling_s,
                );
                let new = NewSubscription {
                    session: Some(exchange.session),
                    fabric_index: asker.fabric,
                    peer_node_id: asker.peer,
                    fabric_filtered: subscribe.fabric_filtered,
                    keep_subscriptions: subscribe.keep_subscriptions,
                    min_interval_s: subscribe.min_interval_floor_s,
                    max_interval_s,
                    paths: &paths,
                    event_paths: &event_paths,
                    min_event_number: 0,
                };
                let id = match self.im.subscriptions.subscribe(&new, now) {
                    Ok(id) => id,
                    Err(e) => return status(e.status(), &mut self.buf.payload),
                };
                let Some(subscription) = self.im.subscriptions.find_mut(id) else {
                    return Ok(None);
                };
                // §8.5.3.4: the priming report carries "all the attribute and event data that the
                // subscription requested", not a delta — so the subscription starts re-primed.
                subscription.reprime();
                // §8.5.2: "The EventFilters and DataVersionFilters fields in the Subscribe Request
                // are one time parameters for the priming of the subscription." One time — so they
                // go into this report's context and are *not* stored on the subscription.
                let mut priming = ctx;
                if let Some(filters) = subscribe.data_version_filters_raw() {
                    priming = priming.with_data_version_filters(filters);
                }
                if let Some(filters) = subscribe.event_filters_raw() {
                    priming = priming.with_event_filters(filters);
                }
                let (bytes, outcome) = server.report_chunk(
                    subscription,
                    ReportReason::Data,
                    &priming,
                    &mut self.buf.scratch,
                    &mut self.buf.payload,
                )?;
                let len = bytes.len();
                if let Some(interaction) = self.im.interactions.get(exchange, now) {
                    interaction.pending_subscribe = Some(PendingSubscribe {
                        id,
                        max_interval_s,
                        more_chunks: outcome.truncated,
                    });
                }
                self.notify(Notice::Subscribed { id, max_interval_s });
                Ok(Some((opcode::REPORT_DATA, len)))
            }
        }
    }

    /// The subscriber acknowledged a priming chunk: send the next, or the grant.
    fn priming_acknowledged<A: crate::im::AccessControl, H: ClusterHandler>(
        &mut self,
        server: &Server<'_, A, H>,
        ctx: &InteractionContext<'_>,
        exchange: ExchangeKey,
        pending: PendingSubscribe,
        now: Instant,
    ) -> Result<Option<(u8, usize)>> {
        let Some(subscription) = self.im.subscriptions.find_mut(pending.id) else {
            return Ok(None);
        };
        if pending.more_chunks {
            let (bytes, outcome) = server.report_chunk(
                subscription,
                ReportReason::Data,
                ctx,
                &mut self.buf.scratch,
                &mut self.buf.payload,
            )?;
            let len = bytes.len();
            if let Some(interaction) = self.im.interactions.get(exchange, now) {
                interaction.pending_subscribe = Some(PendingSubscribe {
                    more_chunks: outcome.truncated,
                    ..pending
                });
            }
            return Ok(Some((opcode::REPORT_DATA, len)));
        }
        // Reported as of now: the next report is measured from the grant.
        subscription.reported(now);
        let len = SubscribeResponse::new(pending.id, pending.max_interval_s)
            .encode(&mut self.buf.payload)?
            .len();
        self.notify(Notice::Granted { id: pending.id });
        Ok(Some((opcode::SUBSCRIBE_RESPONSE, len)))
    }

    /// §4.16.3: a group datagram belongs to no session, so `Messaging` hands it back rather than
    /// routing it; the key is found by trying every installed one whose Group Session ID matches.
    /// §8.7.2.3 and §1.3.7.1.2: a groupcast is acted on and never answered — one multicast to
    /// twenty lights that each replied would put twenty responses on the link at once.
    pub(super) fn groupcast<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        datagram: &mut [u8],
        from: PeerAddr,
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
        let fabrics = device.credentials.fabrics;
        let compressed = |index: FabricIndex| fabrics.borrow().find(index).map(|f| f.compressed);
        let opened = device.group_keys.open(
            datagram,
            from,
            &mut self.group_peers,
            &compressed,
            &mut self.buf.evict,
        );
        let message = match opened {
            Ok(crate::group::wire::Received::Message(message)) => message,
            Ok(_) => return,
            Err(e) => {
                self.notify(Notice::Dropped(e));
                return;
            }
        };
        if message.protocol.protocol != ProtocolId::INTERACTION_MODEL {
            return;
        }
        let group = message.context.group;
        let subject = SubjectDescriptor::group(message.context.fabric_index, group);
        let access = device.access_control.access(device.node, &subject);
        let server = Server::new(device.node, &access, device.handler, REPORT_LIMIT)
            .with_data_versions(device.versions)
            .with_events(device.events.source());
        let ctx = InteractionContext::new()
            .at(now)
            .with_fabric(message.context.fabric_index)
            .with_group(group);
        let request = Request {
            opcode: message.protocol.opcode,
            payload: message.payload,
            session: None,
            exchange: message.protocol.exchange_id,
            groupcast: true,
        };
        let mut cursor = ReadCursor::START;
        let served = self.im.dispatcher.dispatch(
            &server,
            request,
            &ctx,
            &mut cursor,
            &mut self.buf.scratch,
            &mut self.buf.payload,
        );
        match served {
            Ok(_) => self.notify(Notice::Groupcast(group)),
            Err(e) => self.notify(Notice::Refused(e)),
        }
        let deferred = self.follow_up(device, crate::msg::SessionId(0), now);
        self.apply(deferred);
    }

    /// §8.5.3: every subscription that is due and free to report, reports.
    ///
    /// A subscription reports when something it covers changed and `MinInterval` has passed, or
    /// when `MaxInterval` is about to — the keep-alive that stops a quiet node being declared
    /// dead. It does not report while its own priming report is still going out: §8.5.2 makes it
    /// active only once the `SubscribeResponse` has been sent, and a report before that clears
    /// the re-prime flag mid-series, so the subscriber is left holding whatever the first chunk
    /// happened to contain. And it does not report while its last report is unacknowledged:
    /// MRP owns delivery, and a second exchange per tick is how a node fills its exchange table.
    pub(super) fn reports<K, G, H, Ac, Gk, Ev, V, const F: usize>(
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
        self.im.backoff.retain(|(_, retry)| *retry > now);
        let due: Vec<(u32, ReportReason), 15> = self
            .im
            .subscriptions
            .due(now)
            .filter(|(s, _)| {
                !self.im.interactions.priming(s.id)
                    && !self.im.reporting.iter().any(|(id, _)| *id == s.id)
                    && !self.im.backoff.iter().any(|(id, _)| *id == s.id)
            })
            .map(|(s, reason)| (s.id, reason))
            .collect();
        for (id, reason) in due {
            if self.im.reporting.is_full() {
                break;
            }
            if let Err(error) = self.report(device, id, reason, now) {
                let _ = self.im.backoff.push((id, now.saturating_add(REPORT_RETRY)));
                self.notify(Notice::ReportFailed { id, error });
            }
        }
    }

    fn report<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        id: u32,
        reason: ReportReason,
        now: Instant,
    ) -> Result<()>
    where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let Some(subscription) = self.im.subscriptions.find_mut(id) else {
            return Ok(());
        };
        let session = subscription
            .session
            .ok_or(Error::new(ErrorCode::NoSession))?;
        // §6.6.6.3 again: a report is served to the *subscriber*, so it is filtered by the
        // subscriber's standing, which the subscription recorded when CASE proved it.
        let subject = match (subscription.fabric_index, subscription.peer_node_id) {
            (Some(fabric), Some(node)) if node.kind() == NodeIdKind::Operational => {
                SubjectDescriptor::case(fabric, node)
            }
            _ => match self.stack.sessions().find(session) {
                Some(s) => SubjectDescriptor::from_session(s, None),
                None => SubjectDescriptor::unauthenticated(),
            },
        };
        let access = device.access_control.access(device.node, &subject);
        let server = Server::new(device.node, &access, device.handler, REPORT_LIMIT)
            .with_data_versions(device.versions)
            .with_events(device.events.source());
        let mut ctx = InteractionContext::new().at(now).on_session(session);
        if let Some(fabric) = subscription.fabric_index {
            ctx = ctx.with_fabric(fabric);
        }
        let len = server
            .report_chunk(
                subscription,
                reason,
                &ctx,
                &mut self.buf.scratch,
                &mut self.buf.payload,
            )?
            .0
            .len();
        let exchange = self
            .stack
            .open(session, ProtocolId::INTERACTION_MODEL, now)?;
        let randomness = device.credentials.rng.borrow().next_u32().unwrap_or(0);
        let before = self.outbox.len();
        if let Err(e) = self.frame(exchange, opcode::REPORT_DATA, len, randomness, now) {
            // Nothing went out, so nothing is owed on this exchange — and the subscription is
            // *not* marked reported, or the change that prompted this would be forgotten.
            self.stack.close(exchange);
            return Err(e);
        }
        if self.outbox.len() == before {
            self.stack.close(exchange);
            self.resend.forget(exchange);
            return Err(Error::new(ErrorCode::NoSpace));
        }
        let _ = self.im.reporting.push((id, exchange));
        if let Some(subscription) = self.im.subscriptions.find_mut(id) {
            // Reported as far as this node is concerned: MRP owns delivery from here.
            subscription.reported(now);
        }
        Ok(())
    }
}

/// A `StatusResponse` as the whole reply.
fn status(status: Status, buf: &mut [u8]) -> Result<Option<(u8, usize)>> {
    let len = StatusResponse::new(status).encode(buf)?.len();
    Ok(Some((opcode::STATUS_RESPONSE, len)))
}
