//! Subscriptions and the reporting engine (Core §8.5, §8.6).
//!
//! > This allows the subscriber to maintain a coherent snapshot, or twin, of the subscription
//! > data as it currently exists on the publisher.
//!
//! A subscription is a standing read: the subscriber names some paths once, and the publisher
//! reports every change to them for the life of the subscription. It is how a light tells a
//! controller it was switched on at the wall — and it is the only interaction where the
//! *publisher* decides when to speak.
//!
//! # Two intervals, doing opposite jobs
//!
//! `MinInterval` is a **floor on frequency**: "Each Report transaction SHALL NOT be initiated
//! by the publisher until the minimum interval has expired since the last Report transaction."
//! It is what stops a flapping sensor from flooding a network.
//!
//! `MaxInterval` is a **ceiling on silence**: "To keep the subscription alive, a Report
//! transaction is sent from the publisher every maximum interval, or possibly more
//! frequently." A report that carries nothing is still a report — it is how the subscriber
//! knows the publisher is alive, and "If the subscriber does not receive a Report transaction
//! within the maximum interval from the last Report Data, the subscriber SHALL terminate the
//! Subscribe interaction."
//!
//! So between `last + min` and `last + max` the publisher reports *if it has something*, and
//! at `last + max` it reports regardless.
//!
//! # The negotiation is stranger than it looks
//!
//! §8.5.3.2: `MinIntervalFloor ≤ MaxInterval ≤ MAX(SUBSCRIPTION_MAX_INTERVAL_PUBLISHER_LIMIT,
//! MaxIntervalCeiling)`.
//!
//! That is **`MAX`**, not `MIN`. The upper bound is the *larger* of the publisher's own limit
//! and what the subscriber asked for — so a publisher may legally stay silent for longer than
//! the subscriber's ceiling, up to an hour. That is deliberate: §2.11.2.2 sets the limit to
//! "the Idle Mode Duration or 60 minutes, whichever is greater" for an intermittently
//! connected device, and a battery-powered sensor that woke every thirty seconds because a
//! controller asked would not last. Reading it as `MIN` would make an ICD unimplementable.
//!
//! # What a report contains
//!
//! Every change since the last report — "with the exception of attribute data with the Changes
//! Omitted (C) quality", which a client must poll for. Tracking those would report values the
//! specification asks a publisher *not* to report.
//!
//! When there is more to say than fits in a [`DirtySet`], the subscription re-primes: it
//! reports everything it covers. §8.5 permits exactly that — "Including all subscription data
//! to re-prime the subscription" — so overflowing is degradation, not failure.

use heapless::Vec;

use crate::config::{AssertValid, Config};
use crate::error::{Error, ErrorCode};
use crate::im::path::{AttributePath, EventPath};
use crate::im::{ClusterId, EndpointId};
use crate::msg::{FabricIndex, NodeId, SessionId};
use crate::platform::{Duration, Instant};

/// `SUBSCRIPTION_MAX_INTERVAL_PUBLISHER_LIMIT` (§2.11.2.2) — 60 minutes, in seconds.
///
/// "If the publisher is an ICD, this SHALL be set to the Idle Mode Duration or 60 minutes,
/// whichever is greater. Otherwise, this SHALL be set to 60 minutes." A device with a longer
/// idle duration raises it through [`SubscriptionPolicy::max_interval_limit_s`].
pub const MAX_INTERVAL_PUBLISHER_LIMIT_S: u16 = 3600;

/// How a publisher answers a subscriber's requested bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionPolicy {
    /// `SUBSCRIPTION_MAX_INTERVAL_PUBLISHER_LIMIT` for this node.
    ///
    /// An ICD raises it to its Idle Mode Duration; §2.11.2.2 says "whichever is greater", so
    /// it is never below [`MAX_INTERVAL_PUBLISHER_LIMIT_S`].
    pub max_interval_limit_s: u16,
    /// The interval this publisher would *prefer*, before the subscriber's bounds are applied.
    ///
    /// `None` means "honour the subscriber's ceiling", which is the polite default and what a
    /// mains-powered device should do. A battery-powered one names a longer value here, and
    /// §8.5.3.2's `MAX(limit, ceiling)` upper bound is what makes that legal.
    pub preferred_max_interval_s: Option<u16>,
}

impl Default for SubscriptionPolicy {
    fn default() -> Self {
        Self {
            max_interval_limit_s: MAX_INTERVAL_PUBLISHER_LIMIT_S,
            preferred_max_interval_s: None,
        }
    }
}

impl SubscriptionPolicy {
    /// The `MaxInterval` to put in the `SubscribeResponse` (§8.5.3.2).
    ///
    /// > This SHALL respect the following constraint: MinIntervalFloor ≤ MaxInterval ≤
    /// > MAX(SUBSCRIPTION_MAX_INTERVAL_PUBLISHER_LIMIT, MaxIntervalCeiling)
    ///
    /// The floor wins over the ceiling when a subscriber asks for a ceiling below its own
    /// floor — which is a contradictory request, and the constraint resolves it in exactly one
    /// direction.
    #[must_use]
    pub fn max_interval(&self, floor_s: u16, ceiling_s: u16) -> u16 {
        let upper = self.max_interval_limit_s.max(ceiling_s);
        let wanted = self.preferred_max_interval_s.unwrap_or(ceiling_s);
        wanted.clamp(floor_s.min(upper), upper)
    }
}

/// One attribute path that has changed since the last report.
///
/// A fixed-capacity set, because a subscription's report must be bounded and a device cannot
/// allocate. When it fills, the subscription stops tracking individual paths and re-primes on
/// the next report — §8.5's own recovery: "Including all subscription data to re-prime the
/// subscription".
#[derive(Debug, Clone)]
pub struct DirtySet<const N: usize> {
    paths: Vec<AttributePath, N>,
    /// Whether so much changed that the next report has to carry everything.
    overflowed: bool,
}

impl<const N: usize> Default for DirtySet<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DirtySet<N> {
    /// An empty set — nothing has changed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            paths: Vec::new(),
            overflowed: false,
        }
    }

    /// Records a change to a concrete path.
    ///
    /// Duplicates are dropped: a value that changed twice between reports is reported once,
    /// with its latest value — §8.5 asks for "the attribute data that has changed", not a
    /// history of it.
    pub fn insert(&mut self, path: AttributePath) {
        if self.overflowed || self.paths.contains(&path) {
            return;
        }
        if self.paths.push(path).is_err() {
            // More changed than can be listed. Reporting everything is correct and merely
            // wasteful; reporting a truncated list would leave the subscriber's twin
            // permanently wrong about whatever fell off the end.
            self.overflowed = true;
            self.paths.clear();
        }
    }

    /// The changed paths, or empty when the set has overflowed.
    #[must_use]
    pub fn paths(&self) -> &[AttributePath] {
        &self.paths
    }

    /// Whether anything has changed.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.overflowed || !self.paths.is_empty()
    }

    /// Whether the next report must carry the whole subscription.
    #[must_use]
    pub const fn must_reprime(&self) -> bool {
        self.overflowed
    }

    /// Forgets everything — what a completed report does.
    pub fn clear(&mut self) {
        self.paths.clear();
        self.overflowed = false;
    }

    /// Marks the subscription for a full re-prime.
    ///
    /// §8.5: "If the publisher does not receive a Status Response action in response to a
    /// Report Data action … the publisher MAY terminate the Subscribe interaction or SHALL
    /// re-synchronize the subscription in the next Report Data transaction by … Including all
    /// subscription data to re-prime the subscription."
    pub fn reprime(&mut self) {
        self.paths.clear();
        self.overflowed = true;
    }
}

/// How many paths one subscription tracks as dirty before it re-primes.
///
/// Small on purpose: a device with a hundred subscribed attributes that all change at once is
/// better served by one full report than by a hundred entries, and the fixed cost per
/// subscription is what makes a table of them affordable.
pub const DIRTY_PATHS: usize = 8;

/// One active subscription (§8.5).
#[derive(Debug, Clone)]
pub struct Subscription<const P: usize> {
    /// `SubscriptionId` — "generated by the publisher", unique among its subscriptions.
    pub id: u32,
    /// The session it was created on.
    ///
    /// §8.5.2.3: "If KeepSubscriptions is FALSE, all existing or pending subscriptions on the
    /// publisher **for this subscriber** SHALL be terminated" — so a subscription has to
    /// remember whose it is.
    pub session: Option<SessionId>,
    /// The accessing fabric, if the session has one. §2.11.2.2 permits a subscription with
    /// none: "A server MAY permit Subscribe Interactions even when there is no accessing
    /// fabric, subject to available resources (e.g over PASE)."
    pub fabric_index: Option<FabricIndex>,
    /// Whose subscription it is, as CASE proved it.
    ///
    /// A `SessionId` names a session, and a session does not survive a reboot; this names the
    /// *node*, and does. It is what [`persist`](crate::im::persist) rebinds a restored
    /// subscription by, and `None` on a PASE session, which has no operational identity.
    pub peer_node_id: Option<NodeId>,
    /// `FabricFiltered`, which "SHALL remain in effect for all data reported during the
    /// interaction" — a one-time parameter that outlives the request carrying it.
    pub fabric_filtered: bool,
    /// The negotiated minimum interval, in seconds — the subscriber's requested floor.
    ///
    /// §8.5.3.2: the subscription becomes active "with a min interval equal to the requested
    /// MinIntervalFloor", so the publisher does not choose this one.
    pub min_interval_s: u16,
    /// The negotiated maximum interval, in seconds — what went in the `SubscribeResponse`.
    pub max_interval_s: u16,
    /// The subscribed attribute paths, as requested. Wildcards are kept as wildcards and
    /// expanded at report time, so a path that starts matching a newly-added endpoint is
    /// reported without the subscription being rebuilt.
    pub paths: Vec<AttributePath, P>,
    /// When the last report went out.
    pub last_report: Instant,
    /// The subscribed event paths, as requested.
    ///
    /// Separate from the attribute paths because they behave differently: an attribute change
    /// dirties a set that a report drains, while an event is *queued* and delivered in order.
    pub event_paths: Vec<EventPath, P>,
    /// What has changed since.
    pub dirty: DirtySet<DIRTY_PATHS>,
    /// The event number the next report starts from.
    ///
    /// §8.5.3.4: "Subsequent ReportData actions, as part of the subscription, SHALL include
    /// the latest EventNo associated with each node generating new events." This is the
    /// bookmark that makes that possible — and the reason `EventFilters` is "a one time
    /// parameter for the priming of the subscription": after the priming report the
    /// subscription tracks its own position.
    pub next_event_number: u64,
    /// Whether an event matching an urgent path has been queued since the last report.
    ///
    /// §8.5: "When the IsUrgent flag is TRUE for a subscription's event path in the
    /// EventPathIB, the queueing of such an event SHALL trigger a Report transaction for the
    /// subscription, subject to all Report transaction rules." Without the flag, "event
    /// queueing does not automatically trigger a Report transaction" — the events wait for the
    /// next report, whenever it happens.
    urgent: bool,
    /// One past the highest event number the report currently being built carries, from the
    /// server rather than from the device. See [`Subscription::reported`].
    reported_through: u64,
    /// How far through its current report this subscription has got.
    ///
    /// Per subscription, and deliberately not the integrator's to hold: a report over a
    /// wildcard subscription chunks (§10.2.3), a chunked series spans several messages, and
    /// two subscribers report concurrently. One cursor shared between them resumes each
    /// subscriber's report where the *other* one left off, which fails silently — every
    /// message is well-formed, it just describes the wrong twin.
    pub(crate) cursor: crate::im::server::ReadCursor,
}

/// Why a report is due now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportReason {
    /// Something changed and the minimum interval has passed.
    ///
    /// "Something" is an attribute change, a queued urgent event, or a re-prime — all three
    /// produce a report that carries data and expects a `StatusResponse`.
    Data,
    /// Nothing changed, but the maximum interval has — "to keep the subscription alive".
    ///
    /// §8.6.2's Report Transaction Empty: "report with no data or events with
    /// SuppressResponse set to TRUE". An empty report needs no acknowledgement, because
    /// its only job is to prove the publisher is still there.
    KeepAlive,
}

impl<const P: usize> Subscription<P> {
    /// Marks every path dirty, so the next report is a full one (§8.5.3.4).
    ///
    /// What a re-prime says is not "these things changed" but "I no longer know what you
    /// have" — after a dirty-set overflow, or after a reboot, the subscriber's twin is
    /// unknown rather than stale in some identified way.
    pub fn reprime(&mut self) {
        self.dirty.reprime();
        // Re-priming swaps the dirty set for the full path list. A cursor part-way through
        // the old list indexes the new one meaninglessly, so the series restarts — the
        // subscriber may see a path twice, which is recoverable, rather than miss one, which
        // is not.
        self.cursor = crate::im::server::ReadCursor::START;
    }

    /// The paths this subscription's next report draws from, and where it is up to.
    ///
    /// One call, because the two are a matched pair: the cursor indexes *this* list, and
    /// handing them out separately is what lets them drift apart.
    pub(crate) fn report_source(
        &mut self,
    ) -> (
        &[AttributePath],
        &[EventPath],
        u64,
        &mut crate::im::server::ReadCursor,
    ) {
        let Self {
            paths,
            dirty,
            cursor,
            event_paths,
            next_event_number,
            ..
        } = self;
        // §8.5.3.4: a re-primed subscription reports everything it subscribed to; otherwise
        // it reports only what changed.
        let source = if dirty.must_reprime() {
            paths.as_slice()
        } else {
            dirty.paths()
        };
        (source, event_paths.as_slice(), *next_event_number, cursor)
    }

    /// The earliest a report may go out — `last_report + min_interval`.
    #[must_use]
    pub fn earliest_report(&self) -> Instant {
        self.last_report
            .saturating_add(Duration::from_secs(u64::from(self.min_interval_s)))
    }

    /// The latest a report may go out — `last_report + max_interval`.
    #[must_use]
    pub fn latest_report(&self) -> Instant {
        self.last_report
            .saturating_add(Duration::from_secs(u64::from(self.max_interval_s)))
    }

    /// Whether anything is waiting to be reported.
    ///
    /// An attribute change, or an event queued against a path the subscriber marked urgent.
    /// A non-urgent event is *not* pending: §8.5 says its queueing "does not automatically
    /// trigger a Report transaction", and it rides out with the next one.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.dirty.is_dirty() || self.urgent
    }

    /// Whether a report is due now, and why.
    ///
    /// The two rules, in the order they bind: nothing before the minimum interval, and
    /// something by the maximum. In between, a report goes out exactly when there is
    /// something to say — "Attribute changes SHALL be delivered as soon as possible, taking
    /// into account the minimum interval".
    #[must_use]
    pub fn due(&self, now: Instant) -> Option<ReportReason> {
        if now >= self.latest_report() {
            // The keep-alive deadline binds even when nothing changed — and when something
            // did, this is still a data report.
            return Some(if self.has_pending() {
                ReportReason::Data
            } else {
                ReportReason::KeepAlive
            });
        }
        if self.has_pending() && now >= self.earliest_report() {
            return Some(ReportReason::Data);
        }
        None
    }

    /// When this subscription next needs attention.
    ///
    /// A device sleeps until the earliest deadline across its subscriptions; an
    /// intermittently connected one uses it to decide whether it can stay idle. Dirty data
    /// pulls the deadline in to the minimum interval, clean data leaves it at the maximum.
    #[must_use]
    pub fn next_deadline(&self) -> Instant {
        if self.has_pending() {
            self.earliest_report().min(self.latest_report())
        } else {
            self.latest_report()
        }
    }

    /// Records that a report went out, resetting both timers and everything pending.
    ///
    /// The event bookmark comes from the report the server built, not from the caller.
    /// [`Server::report_chunk`](crate::im::Server::report_chunk) leaves
    /// [`ReadOutcome::events_through`](crate::im::server::ReadOutcome::events_through) here as
    /// it writes, so §8.5.3.4's "the next report resumes after the last event delivered" is a
    /// fact the server already has rather than a number the device is asked to reconstruct.
    ///
    /// Not a parameter, because it is not a number a caller can compute: a report is built path
    /// by path and the cursor's position is reset between them, so the answer every caller
    /// reaches for is `0` — and a bookmark stuck at zero re-sends the subscriber's whole event
    /// history on every report, for the life of the subscription.
    pub fn reported(&mut self, now: Instant) {
        self.last_report = now;
        self.dirty.clear();
        // The next report is a new series over a different path list, so it starts at the
        // beginning rather than wherever this one ended.
        self.cursor = crate::im::server::ReadCursor::START;
        self.urgent = false;
        self.next_event_number = self.next_event_number.max(self.reported_through);
        // Consumed: the next series accumulates its own, and a report that carries no events
        // must not re-apply the last one's.
        self.reported_through = 0;
    }

    /// Where the report the server has just built left the event bookmark.
    ///
    /// Set by [`Server::report_chunk`](crate::im::Server::report_chunk) and consumed by
    /// [`reported`](Self::reported), which is only called once the report has actually gone
    /// out: a report that was built and never sent must not advance the bookmark past events
    /// the subscriber never saw.
    pub(crate) fn note_reported_through(&mut self, through: u64) {
        self.reported_through = self.reported_through.max(through);
    }

    /// Whether this subscription asked for `path`, and whether it asked urgently.
    ///
    /// Returns `None` when no subscribed path covers the event. §10.6.8's `IsUrgent` is a
    /// property of the *path*, not of the event, so the same event may be urgent to one
    /// subscriber and not to another.
    #[must_use]
    pub fn event_urgency(&self, endpoint: u16, cluster: u32, event: u32) -> Option<bool> {
        let mut urgent = None;
        for path in &self.event_paths {
            let covers = path.endpoint.is_none_or(|wanted| wanted == endpoint)
                && path.cluster.is_none_or(|wanted| wanted == cluster)
                && path.event.is_none_or(|wanted| wanted == event);
            if covers {
                // Several paths may cover one event; urgency is the union, because a
                // subscriber that asked urgently anywhere asked urgently.
                urgent = Some(urgent.unwrap_or(false) || path.is_urgent.unwrap_or(false));
            }
        }
        urgent
    }

    /// Records that an event was queued, if this subscription wants it.
    ///
    /// Returns whether the event triggers a report — which is only when the subscriber marked
    /// the path urgent. §8.5: "When the IsUrgent flag is FALSE or absent … event queueing does
    /// not automatically trigger a Report transaction."
    pub fn note_event(&mut self, endpoint: u16, cluster: u32, event: u32) -> bool {
        match self.event_urgency(endpoint, cluster, event) {
            Some(true) => {
                self.urgent = true;
                true
            }
            _ => false,
        }
    }

    /// Whether this subscription covers `path` — the test a change has to pass before it
    /// dirties anything.
    ///
    /// A subscribed path may be a wildcard, so this is containment rather than equality: a
    /// subscription to "every attribute of cluster 6 on every endpoint" is dirtied by a
    /// change to endpoint 1's `OnOff`.
    #[must_use]
    pub fn covers(&self, path: &AttributePath) -> bool {
        self.paths.iter().any(|subscribed| covers(subscribed, path))
    }

    /// Records a change, if this subscription covers it.
    ///
    /// Returns whether it did, so a caller can tell whether a report is now pending.
    pub fn note_change(&mut self, path: &AttributePath) -> bool {
        if !self.covers(path) {
            return false;
        }
        self.dirty.insert(*path);
        true
    }
}

/// Whether `subscribed` — possibly a wildcard — names `concrete`.
///
/// §10.6.2.1: "omission of any of the tags in question … indicates wildcard semantics", so an
/// absent field matches anything. `Node` is the exception and is not compared: a path with a
/// node id names *this* node, which is the only node a subscription can be about.
fn covers(subscribed: &AttributePath, concrete: &AttributePath) -> bool {
    let matches = |wanted: Option<u32>, have: Option<u32>| match wanted {
        None => true,
        Some(wanted) => have == Some(wanted),
    };
    matches(
        subscribed.endpoint.map(u32::from),
        concrete.endpoint.map(u32::from),
    ) && matches(subscribed.cluster, concrete.cluster)
        && matches(subscribed.attribute, concrete.attribute)
}

/// Whether a subscribed path and a whole cluster instance overlap, and what of the
/// subscription falls inside it.
///
/// This is *not* [`covers`], and the difference is the whole point. `covers` asks whether a
/// subscribed wildcard names one concrete attribute; this asks whether a subscription and a
/// changed cluster have anything in common. A subscription on
/// `(endpoint 0, cluster 0x0030, attribute 0x0000)` overlaps a change to all of
/// `(0, 0x0030)` — `covers` would say no, because an absent attribute on the *changed* side is
/// not a wildcard, it is "no attribute named".
///
/// What comes back is the intersection, which is what belongs in the dirty set: the changed
/// cluster with the subscription's own attribute, or the whole cluster when the subscription
/// asked for all of it.
fn intersect_cluster(
    subscribed: &AttributePath,
    endpoint: EndpointId,
    cluster: ClusterId,
) -> Option<AttributePath> {
    if subscribed.endpoint.is_some_and(|wanted| wanted != endpoint) {
        return None;
    }
    if subscribed.cluster.is_some_and(|wanted| wanted != cluster) {
        return None;
    }
    Some(AttributePath {
        endpoint: Some(endpoint),
        cluster: Some(cluster),
        attribute: subscribed.attribute,
        ..*subscribed
    })
}

/// The publisher's set of active subscriptions.
///
/// Fixed capacity from `N`, which [`SubscriptionTable::CHECK`] holds to
/// §2.11.2.2's "at least three Subscribe Interactions" per fabric.
#[derive(Debug)]
pub struct SubscriptionTable<C: Config, const N: usize = 15, const P: usize = 3> {
    subscriptions: Vec<Subscription<P>, N>,
    /// The last id handed out. Ids are monotonic for the same reason fabric indices are: a
    /// subscriber caches one, and reusing it points a stale reference at somebody else's
    /// subscription.
    last_id: u32,
    _config: core::marker::PhantomData<C>,
}

impl<C: Config, const N: usize, const P: usize> crate::config::Capacity
    for SubscriptionTable<C, N, P>
{
    const TOTAL: usize = N;
    /// §11.1.4.4's `SubscriptionsPerFabric`: the fixed share each fabric is promised.
    ///
    /// The policy figure rather than `N / FABRICS`, because the share is what
    /// `SubscriptionTable::admit` enforces — and [`SubscriptionTable::CHECK`] is what makes
    /// the two agree.
    const PER_FABRIC: usize = C::SUBSCRIPTIONS_PER_FABRIC;
}

impl<C: Config, const N: usize, const P: usize> crate::config::SubscriptionCapacity
    for SubscriptionTable<C, N, P>
{
    const PATHS: usize = P;
}

impl<C: Config, const N: usize, const P: usize> SubscriptionTable<C, N, P> {
    /// Compile-time proof that this table can keep §2.11.2.2's promise.
    ///
    /// > A publisher SHALL ensure that every fabric the node is commissioned into can support
    /// > at least three Subscribe Interactions to the publisher.
    ///
    /// A promise of `SUBSCRIPTIONS_PER_FABRIC` to each of `FABRICS` fabrics needs room for
    /// their product. Without this the node advertises a guarantee it cannot keep, and the
    /// fabric that finds out is the last one commissioned.
    pub const CHECK: () = {
        let () = Self::CHECK;
        assert!(
            N >= C::SUBSCRIPTIONS_PER_FABRIC * C::FABRICS,
            "SubscriptionTable: Core §2.11.2.2 promises SUBSCRIPTIONS_PER_FABRIC to every \
             fabric, so the table must hold FABRICS × that many"
        );
        assert!(
            P >= 3,
            "SubscriptionTable: Core §2.11.2.2 requires at least 3 paths per subscription"
        );
    };
}

impl<C: Config, const N: usize, const P: usize> Default for SubscriptionTable<C, N, P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a `SubscribeRequest` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeError {
    /// §8.5.2.2: "At least one attribute or event SHALL be indicated in the action."
    NoPaths,
    /// More paths than the table's `P` admits — §11.1.4.4's `SubscribePathsSupported`.
    TooManyPaths,
    /// More subscriptions than the table's `N` admits. §8.10's `RESOURCE_EXHAUSTED`.
    Full,
    /// This fabric already holds [`Config::SUBSCRIPTIONS_PER_FABRIC`] subscriptions.
    ///
    /// Distinct from [`SubscribeError::Full`] because the table may have plenty of room: the
    /// slots left are promised to *other* fabrics, and handing them out would break §2.11.2.2's
    /// guarantee that "every fabric the node is commissioned into can support at least three
    /// Subscribe Interactions". Both answer `RESOURCE_EXHAUSTED` on the wire — there is no
    /// status for "not yours" — but an integrator reading a log needs to tell them apart.
    FabricQuota,
}

impl SubscribeError {
    /// The status a `StatusResponse` carries for this refusal.
    #[must_use]
    pub const fn status(self) -> crate::im::Status {
        match self {
            // §8.10.1: "INVALID_ACTION — the request is malformed, has missing fields, or
            // fields with invalid values." A subscription to nothing is all three.
            Self::NoPaths => crate::im::Status::InvalidAction,
            // §8.10.1's `PATHS_EXHAUSTED`: "The request is not possible due to the number of
            // paths requested."
            Self::TooManyPaths => crate::im::Status::PathsExhausted,
            Self::Full | Self::FabricQuota => crate::im::Status::ResourceExhausted,
        }
    }
}

impl<C: Config, const N: usize, const P: usize> SubscriptionTable<C, N, P> {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        let () = AssertValid::<C>::CHECK;
        Self {
            subscriptions: Vec::new(),
            last_id: 0,
            _config: core::marker::PhantomData,
        }
    }

    /// How many subscriptions are active.
    #[must_use]
    pub fn len(&self) -> usize {
        self.subscriptions.len()
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
    }

    /// How many this node can serve.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The subscriptions, in creation order.
    pub fn iter(&self) -> impl Iterator<Item = &Subscription<P>> {
        self.subscriptions.iter()
    }

    /// The subscription with this id.
    #[must_use]
    pub fn find(&self, id: u32) -> Option<&Subscription<P>> {
        self.subscriptions.iter().find(|s| s.id == id)
    }

    /// The subscription with this id, mutably.
    pub fn find_mut(&mut self, id: u32) -> Option<&mut Subscription<P>> {
        self.subscriptions.iter_mut().find(|s| s.id == id)
    }

    /// Ends a subscription.
    ///
    /// §8.5: "When a Subscribe interaction is terminated on the publisher or subscriber, the
    /// subscription, identified by a SubscriptionId, SHALL also be terminated."
    pub fn remove(&mut self, id: u32) -> bool {
        match self.subscriptions.iter().position(|s| s.id == id) {
            Some(index) => {
                self.subscriptions.remove(index);
                true
            }
            None => false,
        }
    }

    /// Ends every subscription belonging to one session — §8.5.2.3's `KeepSubscriptions`.
    ///
    /// > If KeepSubscriptions is FALSE, all existing or pending subscriptions on the publisher
    /// > for this subscriber SHALL be terminated.
    ///
    /// Returns how many went. A subscriber that re-subscribes without the flag is saying "I
    /// have restarted, forget what you knew about me" — and a publisher that kept the old
    /// subscriptions would report to a twin that no longer exists until the maximum interval
    /// ran out on each.
    pub fn remove_for_session(&mut self, session: Option<SessionId>) -> usize {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|s| s.session != session);
        before.saturating_sub(self.subscriptions.len())
    }

    /// Ends every subscription scoped to a fabric — what `RemoveFabric` cascades into.
    pub fn remove_for_fabric(&mut self, fabric: FabricIndex) -> usize {
        let before = self.subscriptions.len();
        self.subscriptions
            .retain(|s| s.fabric_index != Some(fabric));
        before.saturating_sub(self.subscriptions.len())
    }

    /// Records a queued event against every subscription that wants it.
    ///
    /// Returns how many were made *pending* — that is, how many had marked the path urgent.
    /// A subscription that wants the event but did not ask urgently still receives it, on
    /// whatever report happens next; §8.5 is explicit that non-urgent queueing "does not
    /// automatically trigger a Report transaction".
    pub fn note_event(&mut self, endpoint: u16, cluster: u32, event: u32) -> usize {
        let mut urgent = 0usize;
        for subscription in &mut self.subscriptions {
            if subscription.note_event(endpoint, cluster, event) {
                urgent = urgent.saturating_add(1);
            }
        }
        urgent
    }

    /// Records a change against every subscription that covers it.
    ///
    /// This is the whole of the reporting engine's input: a cluster whose value changed calls
    /// it once, and each subscription decides for itself whether it cares and when it will
    /// say so.
    ///
    /// **Not** for an attribute with the `C` quality. §8.5: a report carries every change
    /// "with the exception of attribute data with the Changes Omitted (C) quality" — a client
    /// polls for those, and reporting one would be reporting what the specification asked a
    /// publisher not to.
    pub fn note_change(&mut self, path: &AttributePath) -> usize {
        let mut dirtied = 0usize;
        for subscription in &mut self.subscriptions {
            if subscription.note_change(path) {
                dirtied = dirtied.saturating_add(1);
            }
        }
        dirtied
    }

    /// Marks every subscription for a full re-prime — what a lost acknowledgement calls for.
    pub fn reprime_all(&mut self) {
        for subscription in &mut self.subscriptions {
            subscription.dirty.reprime();
        }
    }

    /// The earliest moment any subscription needs attention, if there are any.
    ///
    /// A device sleeps until this. An intermittently connected one uses it to decide whether
    /// it can stay idle, which is why §2.11.2.2 lets it choose a long maximum interval.
    ///
    /// Unbound subscriptions are skipped for the same reason [`SubscriptionTable::due`] skips
    /// them: waking for one would be waking to do nothing.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.subscriptions
            .iter()
            .filter(|s| s.session.is_some())
            .map(Subscription::next_deadline)
            .min()
    }

    /// The subscriptions with a report due at `now`, and why.
    ///
    /// A subscription with no session is skipped however overdue it is, because there is
    /// nowhere to send the report — that is the state a subscription restored from storage
    /// begins in ([`persist`](crate::im::persist)), waiting for its subscriber to come back
    /// on a new CASE session. Handing it to a caller that could only discard it would make
    /// every poll return work that cannot be done.
    pub fn due(&self, now: Instant) -> impl Iterator<Item = (&Subscription<P>, ReportReason)> {
        self.subscriptions
            .iter()
            .filter(|s| s.session.is_some())
            .filter_map(move |s| s.due(now).map(|reason| (s, reason)))
    }

    /// Creates a subscription, allocating an id.
    ///
    /// `keep_subscriptions` is the request's flag: when false, every existing subscription
    /// for this session goes first (§8.5.2.3). That happens *before* the capacity check, so a
    /// subscriber re-subscribing at the table's limit succeeds rather than being refused with
    /// its own stale subscriptions in the way.
    pub fn subscribe(
        &mut self,
        request: &NewSubscription<'_>,
        now: Instant,
    ) -> core::result::Result<u32, SubscribeError> {
        if !request.keep_subscriptions {
            self.remove_for_session(request.session);
        }
        // §8.5.2.2: "At least one attribute or event SHALL be indicated in the action." An
        // event-only subscription is perfectly ordinary — a door lock reporting `LockOperation`
        // subscribes to no attribute at all.
        if request.paths.is_empty() && request.event_paths.is_empty() {
            return Err(SubscribeError::NoPaths);
        }
        if request.paths.len() > P || request.event_paths.len() > P {
            return Err(SubscribeError::TooManyPaths);
        }
        if self.subscriptions.len() >= N {
            return Err(SubscribeError::Full);
        }
        self.admit(request.fabric_index)?;

        let mut paths = Vec::new();
        for path in request.paths {
            paths
                .push(*path)
                .map_err(|_| SubscribeError::TooManyPaths)?;
        }
        let mut event_paths = Vec::new();
        for path in request.event_paths {
            event_paths
                .push(*path)
                .map_err(|_| SubscribeError::TooManyPaths)?;
        }
        let id = self.allocate_id();
        let subscription = Subscription {
            id,
            session: request.session,
            fabric_index: request.fabric_index,
            peer_node_id: request.peer_node_id,
            fabric_filtered: request.fabric_filtered,
            min_interval_s: request.min_interval_s,
            max_interval_s: request.max_interval_s,
            paths,
            event_paths,
            // §8.5.3.4: "Upon subscription activation, the minimum and maximum interval
            // parameters SHALL take effect" — and the priming report is the first report, so
            // both timers start from it.
            last_report: now,
            dirty: DirtySet::new(),
            // `EventFilters` is "a one time parameter for the priming of the subscription",
            // so the subscriber's minimum event number starts the bookmark and the
            // subscription keeps its own position from then on.
            next_event_number: request.min_event_number,
            urgent: false,
            reported_through: 0,
            cursor: crate::im::server::ReadCursor::START,
        };
        self.subscriptions
            .push(subscription)
            .map_err(|_| SubscribeError::Full)?;
        Ok(id)
    }

    /// Records that an attribute of one cluster instance changed, dirtying every subscription
    /// that overlaps it. Returns how many.
    ///
    /// This is the cluster-grained counterpart to [`SubscriptionTable::note_change`], and it is
    /// what [`DataVersions::drain_changes`](crate::dm::DataVersions::drain_changes) feeds. The
    /// grain is the cluster because that is the grain §7.10.3 records changes at: "A cluster
    /// data version SHALL be incremented if any attribute data changes" says *which cluster*,
    /// never which attribute.
    ///
    /// Reporting a whole cluster when one attribute of it moved is more than the minimum and
    /// never less, which is the safe direction: §8.5 already allows a report to carry more than
    /// changed — a re-prime carries everything — and a subscriber that is told too much is
    /// correct where one that is told too little is not.
    pub fn note_cluster_change(&mut self, endpoint: EndpointId, cluster: ClusterId) -> usize {
        let mut dirtied: usize = 0;
        for subscription in &mut self.subscriptions {
            let mut hit = false;
            // Collected first: `paths` is borrowed while it is walked, and the dirty set it
            // feeds lives on the same subscription.
            let mut overlaps: Vec<AttributePath, P> = Vec::new();
            for subscribed in &subscription.paths {
                if let Some(path) = intersect_cluster(subscribed, endpoint, cluster) {
                    let _ = overlaps.push(path);
                }
            }
            for path in overlaps {
                subscription.dirty.insert(path);
                hit = true;
            }
            if hit {
                dirtied = dirtied.saturating_add(1);
            }
        }
        dirtied
    }

    /// Ensures the next allocated id is above `id`, which restoring a persisted subscription
    /// needs (§8.5.3.1's ids must stay unique across a reboot).
    pub(crate) fn reserve_id(&mut self, id: u32) {
        if id > self.last_id {
            self.last_id = id;
        }
    }

    /// Every subscription, mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Subscription<P>> {
        self.subscriptions.iter_mut()
    }

    /// Adds a subscription restored from storage, keeping its id.
    ///
    /// Separate from [`SubscriptionTable::subscribe`] because none of that method's work
    /// applies: there is no request to validate, no id to allocate, and — crucially — no
    /// `KeepSubscriptions` rule to apply, since a restored subscription must not terminate
    /// another restored one belonging to the same subscriber. They were all agreed before the
    /// reboot and all of them are still owed.
    pub(crate) fn insert_restored(
        &mut self,
        durable: crate::im::persist::Durable<P>,
        now: Instant,
    ) -> core::result::Result<(), Error> {
        if self.find(durable.id).is_some() {
            return Err(Error::new(ErrorCode::AlreadyExists));
        }
        let mut subscription = Subscription {
            id: durable.id,
            // Deliberately not restored: a session id from before the reboot names whatever
            // session holds that number now, which is at best nobody and at worst somebody
            // else. `persist::rebind` supplies the real one.
            session: None,
            fabric_index: Some(durable.fabric_index),
            peer_node_id: Some(durable.peer_node_id),
            fabric_filtered: durable.fabric_filtered,
            min_interval_s: durable.min_interval_s,
            max_interval_s: durable.max_interval_s,
            paths: durable.paths,
            event_paths: durable.event_paths,
            // The clock restarted at zero; treating a stored instant as elapsed time would
            // either fire a report immediately or suppress one for as long as the device was
            // off.
            last_report: now,
            dirty: DirtySet::new(),
            next_event_number: durable.next_event_number,
            urgent: false,
            reported_through: 0,
            cursor: crate::im::server::ReadCursor::START,
        };
        // The device has no record of what changed while it was off, so nothing about the
        // subscriber's twin can be trusted — it is unknown rather than stale in some
        // identified way. §8.5.3.4's priming report is the only honest answer.
        subscription.reprime();
        self.subscriptions
            .push(subscription)
            .map_err(|_| Error::new(ErrorCode::NoSpace))
    }

    /// How many subscriptions one fabric holds. `None` counts the fabric-less ones.
    #[must_use]
    pub fn len_of_fabric(&self, fabric: Option<FabricIndex>) -> usize {
        self.subscriptions
            .iter()
            .filter(|s| s.fabric_index == fabric)
            .count()
    }

    /// §2.11.2.2's per-fabric guarantee, applied to one arriving request.
    ///
    /// A fabric-scoped subscription gets a fixed share. A fabric-*less* one — §2.11.2.2 permits
    /// them "subject to available resources (e.g over PASE)" — gets only what is not promised
    /// to a fabric, because a `MAY` must never consume a `SHALL`. On a node sized to the
    /// minimum there is nothing left over and PASE subscriptions are refused, which is what
    /// "subject to available resources" means when there are none.
    fn admit(&self, fabric: Option<FabricIndex>) -> core::result::Result<(), SubscribeError> {
        let share = <Self as crate::config::Capacity>::PER_FABRIC;
        if fabric.is_some() {
            return if self.len_of_fabric(fabric) >= share {
                Err(SubscribeError::FabricQuota)
            } else {
                Ok(())
            };
        }
        // `Self::CHECK` has already refused, at compile time, a table too small to owe every
        // fabric its share — so this subtraction cannot be hiding a promise the node has
        // already broken.
        let promised = C::FABRICS.saturating_mul(share);
        let claimed = self
            .subscriptions
            .iter()
            .filter(|s| s.fabric_index.is_some())
            .count();
        let still_owed = promised.saturating_sub(claimed);
        let free = N.saturating_sub(self.subscriptions.len());
        if free > still_owed {
            Ok(())
        } else {
            Err(SubscribeError::Full)
        }
    }

    /// Allocates the next unused id, never zero.
    ///
    /// Monotonic and wrapping, like a fabric index and for the same reason: a subscriber
    /// caches its id, and handing a freed one straight back out would point a stale
    /// `SubscriptionId` at somebody else's subscription. Zero is skipped so that it can mean
    /// "no subscription" in a caller's own bookkeeping.
    fn allocate_id(&mut self) -> u32 {
        for _ in 0..=u32::from(u16::MAX) {
            self.last_id = self.last_id.wrapping_add(1);
            if self.last_id != 0 && self.find(self.last_id).is_none() {
                return self.last_id;
            }
        }
        // Unreachable while `N` is far below the id space; returning a duplicate would be
        // worse than returning one that is merely unlikely to collide.
        self.last_id
    }
}

/// What a `SubscribeRequest` asks for, after its paths have been validated.
#[derive(Debug, Clone, Copy)]
pub struct NewSubscription<'a> {
    /// The session the request arrived on.
    pub session: Option<SessionId>,
    /// The accessing fabric, if any.
    pub fabric_index: Option<FabricIndex>,
    /// The subscriber's operational Node ID, from the session (§6.6.6.3). `None` over PASE.
    pub peer_node_id: Option<NodeId>,
    /// `FabricFiltered`.
    pub fabric_filtered: bool,
    /// `KeepSubscriptions`.
    pub keep_subscriptions: bool,
    /// The negotiated minimum interval — the request's `MinIntervalFloor`.
    pub min_interval_s: u16,
    /// The negotiated maximum interval, from [`SubscriptionPolicy::max_interval`].
    pub max_interval_s: u16,
    /// The attribute paths, as requested.
    pub paths: &'a [AttributePath],
    /// The event paths, as requested.
    pub event_paths: &'a [EventPath],
    /// The lowest event number to report, from the request's `EventFilters`.
    ///
    /// §8.5.3.4: "The EventFilters and DataVersionFilters fields in the Subscribe Request are
    /// one time parameters for the priming of the subscription" — so this seeds the bookmark
    /// and is never consulted again.
    pub min_event_number: u64,
}

/// Builds the `Err` for a refusal, so a caller can answer a `StatusResponse`.
impl From<SubscribeError> for Error {
    fn from(error: SubscribeError) -> Self {
        match error {
            SubscribeError::NoPaths => Self::new(ErrorCode::InvalidArgument),
            SubscribeError::TooManyPaths | SubscribeError::Full | SubscribeError::FabricQuota => {
                Self::new(ErrorCode::NoSpace)
            }
        }
    }
}
