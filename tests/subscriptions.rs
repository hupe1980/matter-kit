//! Subscriptions and the reporting engine against Core §8.5 and §8.6.
//!
//! §8.5 is prose about *timing*, which nothing can be compared against — so the rules here are
//! driven against a virtual clock and the interesting ones are tested by breaking them. Three
//! are worth naming up front, because each reads like a detail and is not:
//!
//! 1. **`MinInterval` is a floor on frequency, `MaxInterval` a ceiling on silence.** They pull
//!    in opposite directions, and a report is due at the later of "something changed and the
//!    minimum has passed" and "the maximum has passed regardless".
//! 2. **§8.5.3.2's upper bound is `MAX`, not `MIN`.** A publisher may legally stay silent
//!    longer than the subscriber's ceiling, up to an hour — which is what makes a
//!    battery-powered device implementable at all.
//! 3. **`KeepSubscriptions = false` terminates the subscriber's *existing* subscriptions.**
//!    A publisher that kept them would report to a twin that no longer exists.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use matter_kit::im::AttributePath;
use matter_kit::im::subscription::{
    DIRTY_PATHS, DirtySet, MAX_INTERVAL_PUBLISHER_LIMIT_S, NewSubscription, ReportReason,
    SubscribeError, SubscriptionPolicy, SubscriptionTable,
};
use matter_kit::msg::{FabricIndex, SessionId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::{Config, DefaultConfig};

// The specification's own minimum for five fabrics: three subscriptions each and three paths
// apiece. `SubscriptionTable::CHECK` is what refuses less.
type Table = SubscriptionTable<DefaultConfig>;

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

fn path(endpoint: u16, cluster: u32, attribute: u32) -> AttributePath {
    AttributePath::attribute(endpoint, cluster, attribute)
}

fn request<'a>(paths: &'a [AttributePath], min: u16, max: u16) -> NewSubscription<'a> {
    NewSubscription {
        session: Some(SessionId(1)),
        fabric_index: Some(FabricIndex(1)),
        peer_node_id: None,
        fabric_filtered: true,
        keep_subscriptions: true,
        min_interval_s: min,
        max_interval_s: max,
        paths,
        event_paths: &[],
        min_event_number: 0,
    }
}

// --- The negotiation ---------------------------------------------------------------------------

#[test]
fn the_max_interval_bound_is_max_not_min() {
    // §8.5.3.2: "MinIntervalFloor ≤ MaxInterval ≤ MAX(SUBSCRIPTION_MAX_INTERVAL_PUBLISHER_LIMIT,
    // MaxIntervalCeiling)".
    //
    // The upper bound is the *larger* of the publisher's own limit and what the subscriber
    // asked for. §2.11.2.2 sets that limit to "the Idle Mode Duration or 60 minutes, whichever
    // is greater" for an intermittently connected device — so a battery-powered sensor may
    // legally stay silent for an hour even though a controller asked for thirty seconds.
    // Reading the bound as `MIN` would make an ICD unimplementable.
    assert_eq!(MAX_INTERVAL_PUBLISHER_LIMIT_S, 3600);

    // A mains-powered publisher honours the ceiling, which is always within the bound.
    let polite = SubscriptionPolicy::default();
    assert_eq!(polite.max_interval(0, 30), 30);
    assert_eq!(
        polite.max_interval(0, 7200),
        7200,
        "above the hour, but asked for"
    );

    // A sleepy one names its own preference, and the `MAX` is what lets it exceed the ceiling.
    let sleepy = SubscriptionPolicy {
        max_interval_limit_s: 3600,
        preferred_max_interval_s: Some(1800),
    };
    assert_eq!(sleepy.max_interval(0, 30), 1800);
    // …but never past the bound.
    let greedy = SubscriptionPolicy {
        max_interval_limit_s: 3600,
        preferred_max_interval_s: Some(u16::MAX),
    };
    assert_eq!(
        greedy.max_interval(0, 30),
        3600,
        "capped at MAX(limit, ceiling)"
    );
    assert_eq!(
        greedy.max_interval(0, 7200),
        7200,
        "and the ceiling raises the cap when it is the larger"
    );
}

#[test]
fn a_ceiling_below_the_floor_is_resolved_in_favour_of_the_floor() {
    // A contradictory request: "report at most every 60 seconds" and "never stay silent longer
    // than 30". §8.5.3.2's constraint has only one solution — `MinIntervalFloor ≤ MaxInterval`
    // binds, and the ceiling does not.
    let policy = SubscriptionPolicy::default();
    assert_eq!(policy.max_interval(60, 30), 60);
    assert!(
        policy.max_interval(60, 30) >= 60,
        "the floor is a hard bound"
    );
}

// --- The timing --------------------------------------------------------------------------------

#[test]
fn nothing_is_reported_before_the_minimum_interval() {
    // §8.5: "Each Report transaction SHALL NOT be initiated by the publisher until the minimum
    // interval has expired since the last Report transaction." This is what stops a flapping
    // sensor from flooding a network.
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let id = table
        .subscribe(&request(&paths, 10, 60), at(0))
        .expect("subscribe");

    table.note_change(&paths[0]);
    let subscription = table.find(id).expect("subscription");
    assert!(subscription.dirty.is_dirty());

    for second in 0..10 {
        assert_eq!(
            subscription.due(at(second)),
            None,
            "a report at t={second}s, before the 10s minimum"
        );
    }
    assert_eq!(subscription.due(at(10)), Some(ReportReason::Data));
}

#[test]
fn a_keep_alive_goes_out_at_the_maximum_interval_with_nothing_to_say() {
    // §8.5: "To keep the subscription alive, a Report transaction is sent from the publisher
    // every maximum interval." And §8.6.2's Report Transaction Empty is what it looks like:
    // "report with no data or events with SuppressResponse set to TRUE". The subscriber needs
    // it — "If the subscriber does not receive a Report transaction within the maximum
    // interval from the last Report Data, the subscriber SHALL terminate the Subscribe
    // interaction."
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let id = table
        .subscribe(&request(&paths, 10, 60), at(0))
        .expect("subscribe");

    let subscription = table.find(id).expect("subscription");
    assert_eq!(
        subscription.due(at(59)),
        None,
        "nothing changed, nothing due"
    );
    assert_eq!(subscription.due(at(60)), Some(ReportReason::KeepAlive));

    // …and once it goes out, both timers restart.
    table.find_mut(id).expect("subscription").reported(at(60));
    let subscription = table.find(id).expect("subscription");
    assert_eq!(subscription.due(at(119)), None);
    assert_eq!(subscription.due(at(120)), Some(ReportReason::KeepAlive));
}

#[test]
fn a_change_at_the_deadline_is_a_data_report_not_a_keep_alive() {
    // The two rules can both bind at once. What goes out then is a *data* report: it carries
    // the change and also resets the keep-alive, so sending an empty one would lose the
    // change for another whole interval.
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let id = table
        .subscribe(&request(&paths, 10, 60), at(0))
        .expect("subscribe");
    table.note_change(&paths[0]);
    assert_eq!(
        table.find(id).expect("subscription").due(at(60)),
        Some(ReportReason::Data)
    );
}

#[test]
fn the_next_deadline_is_what_a_sleepy_device_sleeps_until() {
    // An intermittently connected device asks the table when it may next go idle. Clean data
    // means the keep-alive deadline; dirty data pulls it in to the minimum interval — which
    // is why §8.5's note asks a subscriber to use `MinIntervalFloor = 0` against an ICD.
    let mut table = Table::new();
    assert_eq!(table.next_deadline(), None, "nothing to wait for");

    let paths = [path(1, 0x0006, 0x0000)];
    let id = table
        .subscribe(&request(&paths, 10, 60), at(0))
        .expect("subscribe");
    assert_eq!(table.next_deadline(), Some(at(60)));

    table.note_change(&paths[0]);
    assert_eq!(table.next_deadline(), Some(at(10)));

    // A second subscription with a shorter maximum pulls the whole node's deadline in.
    let other = [path(2, 0x0008, 0x0000)];
    table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(2)),
                min_interval_s: 0,
                max_interval_s: 5,
                ..request(&other, 0, 5)
            },
            at(0),
        )
        .expect("subscribe");
    assert_eq!(table.next_deadline(), Some(at(5)));
    let _ = id;
}

// --- What is dirty -----------------------------------------------------------------------------

#[test]
fn a_wildcard_subscription_is_dirtied_by_a_concrete_change() {
    // §10.6.2.1: "omission of any of the tags in question … indicates wildcard semantics", so
    // a subscription to "every attribute of cluster 6" must notice endpoint 1's OnOff. A
    // publisher that compared paths for equality would report nothing at all to the most
    // common kind of subscription there is.
    let mut table = Table::new();
    let wildcard = [AttributePath {
        cluster: Some(0x0006),
        ..AttributePath::default()
    }];
    let id = table
        .subscribe(&request(&wildcard, 0, 60), at(0))
        .expect("subscribe");

    assert_eq!(table.note_change(&path(1, 0x0006, 0x0000)), 1);
    assert_eq!(table.note_change(&path(7, 0x0006, 0x4003)), 1);
    // A different cluster is not covered.
    assert_eq!(table.note_change(&path(1, 0x0008, 0x0000)), 0);

    let subscription = table.find(id).expect("subscription");
    assert_eq!(subscription.dirty.paths().len(), 2);
    assert!(!subscription.dirty.must_reprime());
}

#[test]
fn the_same_change_twice_is_reported_once() {
    // §8.5 asks for "the attribute data that has changed", not a history of it. A value that
    // flapped twice between reports is one entry with its latest value.
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let id = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    for _ in 0..100 {
        table.note_change(&paths[0]);
    }
    assert_eq!(table.find(id).expect("subscription").dirty.paths().len(), 1);
}

#[test]
fn overflowing_the_dirty_set_re_primes_rather_than_truncating() {
    // A fixed-capacity set has to do something when it fills. Truncating would leave the
    // subscriber's twin permanently wrong about whatever fell off the end — so instead the
    // subscription reports everything it covers, which is §8.5's own recovery: "Including all
    // subscription data to re-prime the subscription."
    let mut set = DirtySet::<4>::new();
    for attribute in 0..4u32 {
        set.insert(path(1, 0x0006, attribute));
    }
    assert_eq!(set.paths().len(), 4);
    assert!(!set.must_reprime());

    set.insert(path(1, 0x0006, 4));
    assert!(set.must_reprime(), "one too many re-primes");
    assert!(set.is_dirty());
    assert!(
        set.paths().is_empty(),
        "and the partial list is discarded rather than sent"
    );

    // A report clears both.
    set.clear();
    assert!(!set.is_dirty());
    assert!(!set.must_reprime());

    // The real capacity is a compile-time constant worth pinning.
    assert_eq!(DIRTY_PATHS, 8);
}

#[test]
fn a_lost_acknowledgement_re_primes_the_subscription() {
    // §8.5: "If the publisher does not receive a Status Response action in response to a
    // Report Data action … the publisher MAY terminate the Subscribe interaction or SHALL
    // re-synchronize the subscription in the next Report Data transaction by … Including all
    // subscription data to re-prime the subscription."
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let id = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    assert!(!table.find(id).expect("subscription").dirty.is_dirty());

    table.reprime_all();
    let subscription = table.find(id).expect("subscription");
    assert!(subscription.dirty.must_reprime());
    assert_eq!(subscription.due(at(0)), Some(ReportReason::Data));
}

// --- The table ---------------------------------------------------------------------------------

#[test]
fn keep_subscriptions_false_terminates_the_subscribers_own_subscriptions() {
    // §8.5.2.3: "If KeepSubscriptions is FALSE, all existing or pending subscriptions on the
    // publisher for this subscriber SHALL be terminated." A subscriber re-subscribing without
    // the flag is saying "I have restarted, forget what you knew about me" — and a publisher
    // that kept the old ones would report to a twin that no longer exists until the maximum
    // interval ran out on each.
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let first = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    let second = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    assert_eq!(table.len(), 2);

    // A third subscriber on a different session is untouched.
    let other_session = NewSubscription {
        session: Some(SessionId(9)),
        ..request(&paths, 0, 60)
    };
    let elsewhere = table.subscribe(&other_session, at(0)).expect("subscribe");

    let fresh = NewSubscription {
        keep_subscriptions: false,
        ..request(&paths, 0, 60)
    };
    let third = table.subscribe(&fresh, at(0)).expect("subscribe");

    assert!(table.find(first).is_none());
    assert!(table.find(second).is_none());
    assert!(table.find(third).is_some());
    assert!(
        table.find(elsewhere).is_some(),
        "another subscriber's subscription is not this one's to end"
    );
    assert_eq!(table.len(), 2);
}

#[test]
fn a_full_table_refuses_but_re_subscribing_still_works() {
    // The order matters: §8.5.2.3's termination happens *before* the capacity check, so a
    // subscriber re-subscribing at the limit succeeds rather than being refused with its own
    // stale subscriptions standing in the way.
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    // Spread across fabrics, because §2.11.2.2 caps what any one of them may hold: filling the
    // table from a single fabric is the thing the per-fabric quota exists to prevent.
    for index in 0..<Table as matter_kit::Capacity>::TOTAL {
        let fabric = u8::try_from(index / <Table as matter_kit::Capacity>::PER_FABRIC)
            .expect("fits")
            .saturating_add(1);
        let session = NewSubscription {
            session: Some(SessionId(u16::try_from(index).expect("fits"))),
            fabric_index: Some(FabricIndex(fabric)),
            ..request(&paths, 0, 60)
        };
        table.subscribe(&session, at(0)).expect("subscribe");
    }
    assert_eq!(table.len(), table.capacity());

    // A new subscriber is refused.
    let newcomer = NewSubscription {
        session: Some(SessionId(0xFFFF)),
        ..request(&paths, 0, 60)
    };
    assert_eq!(table.subscribe(&newcomer, at(0)), Err(SubscribeError::Full));
    assert_eq!(
        SubscribeError::Full.status(),
        matter_kit::im::Status::ResourceExhausted
    );

    // An existing one re-subscribing without KeepSubscriptions succeeds.
    let again = NewSubscription {
        session: Some(SessionId(0)),
        fabric_index: Some(FabricIndex(1)),
        keep_subscriptions: false,
        ..request(&paths, 0, 60)
    };
    assert!(table.subscribe(&again, at(0)).is_ok());
    assert_eq!(table.len(), table.capacity());
}

/// §2.11.2.2: "A publisher SHALL ensure that every fabric the node is commissioned into can
/// support at least three Subscribe Interactions to the publisher."
///
/// A table with only a global limit cannot make that promise. The first administrator to ask
/// fills it, and every fabric commissioned afterwards is told the node is out of resources —
/// by a node that, from its own point of view, is working perfectly. That is a multi-admin
/// isolation failure of the same kind the ACL's per-fabric quota exists to prevent.
#[test]
fn a_fabrics_quota_is_its_own() {
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];

    for n in 0..<Table as matter_kit::Capacity>::PER_FABRIC {
        let request = NewSubscription {
            session: Some(SessionId(u16::try_from(n).expect("fits"))),
            fabric_index: Some(FabricIndex(1)),
            ..request(&paths, 0, 60)
        };
        table.subscribe(&request, at(0)).expect("within its quota");
    }

    // One more from the same fabric is refused, even though the table is mostly empty.
    let greedy = NewSubscription {
        session: Some(SessionId(50)),
        fabric_index: Some(FabricIndex(1)),
        ..request(&paths, 0, 60)
    };
    assert_eq!(
        table.subscribe(&greedy, at(0)),
        Err(SubscribeError::FabricQuota)
    );
    assert!(
        table.len() < table.capacity(),
        "and the refusal is not because the node is out of room"
    );

    // A second fabric gets its own three, which is the guarantee.
    for n in 0..<Table as matter_kit::Capacity>::PER_FABRIC {
        let other = NewSubscription {
            session: Some(SessionId(
                u16::try_from(n).expect("fits").saturating_add(100),
            )),
            fabric_index: Some(FabricIndex(2)),
            ..request(&paths, 0, 60)
        };
        other_fabric_gets_its_share(&mut table, &other);
    }
    assert_eq!(table.len_of_fabric(Some(FabricIndex(1))), 3);
    assert_eq!(table.len_of_fabric(Some(FabricIndex(2))), 3);
}

fn other_fabric_gets_its_share(table: &mut Table, request: &NewSubscription<'_>) {
    table
        .subscribe(request, at(0))
        .expect("another fabric has its own quota");
}

/// §2.11.2.2 permits a subscription with no accessing fabric "subject to available resources
/// (e.g over PASE)" — a `MAY`. It must never consume what a `SHALL` promised a fabric, so on a
/// node sized to the minimum there is nothing spare and it is refused.
#[test]
fn a_fabricless_subscription_never_eats_a_fabrics_guarantee() {
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let pase = NewSubscription {
        session: Some(SessionId(9)),
        fabric_index: None,
        peer_node_id: None,
        ..request(&paths, 0, 60)
    };
    // DefaultConfig is sized exactly to FABRICS * SUBSCRIPTIONS_PER_FABRIC, so every slot is
    // promised and there is no slack.
    assert_eq!(
        <Table as matter_kit::Capacity>::TOTAL,
        DefaultConfig::FABRICS * <Table as matter_kit::Capacity>::PER_FABRIC
    );
    assert_eq!(table.subscribe(&pase, at(0)), Err(SubscribeError::Full));
    assert_eq!(table.len(), 0, "and nothing was stored");
}

#[test]
fn a_subscription_with_no_paths_is_refused() {
    // §8.5.2.2: "At least one attribute or event SHALL be indicated in the action."
    let mut table = Table::new();
    assert_eq!(
        table.subscribe(&request(&[], 0, 60), at(0)),
        Err(SubscribeError::NoPaths)
    );
    assert_eq!(
        SubscribeError::NoPaths.status(),
        matter_kit::im::Status::InvalidAction
    );
    assert!(table.is_empty());
}

#[test]
fn more_paths_than_the_node_supports_is_paths_exhausted() {
    // §8.10.1's `PATHS_EXHAUSTED`: "The request is not possible due to the number of paths
    // requested." §2.11.2.2 puts the floor at three per subscription, which `Config::SUB_PATHS`
    // asserts at compile time.
    let mut table = Table::new();
    let too_many: Vec<AttributePath> = (0..=<Table as matter_kit::SubscriptionCapacity>::PATHS
        as u32)
        .map(|attribute| path(1, 0x0006, attribute))
        .collect();
    assert_eq!(
        table.subscribe(&request(&too_many, 0, 60), at(0)),
        Err(SubscribeError::TooManyPaths)
    );
    assert_eq!(
        SubscribeError::TooManyPaths.status(),
        matter_kit::im::Status::PathsExhausted
    );

    // Exactly the limit fits.
    let exactly: Vec<AttributePath> = (0..<Table as matter_kit::SubscriptionCapacity>::PATHS
        as u32)
        .map(|attribute| path(1, 0x0006, attribute))
        .collect();
    assert!(table.subscribe(&request(&exactly, 0, 60), at(0)).is_ok());
}

#[test]
fn subscription_ids_are_never_zero_and_never_reused_immediately() {
    // A subscriber caches its `SubscriptionId`. Handing a freed one straight back out would
    // point a stale reference at somebody else's subscription — the same reason §11.18.6.8
    // allocates fabric indices monotonically.
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let first = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    assert_ne!(first, 0, "zero is reserved for 'no subscription'");

    let second = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    assert_ne!(first, second);

    table.remove(first);
    let third = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    assert_ne!(third, first, "a freed id is not handed straight back");
    assert_ne!(third, second);
}

#[test]
fn removing_a_fabric_takes_its_subscriptions_with_it() {
    // §11.18.6.12: `RemoveFabric` deletes "all associated Fabric-Scoped data … Any Matter
    // related data including logs, secure sessions, exchanges and interaction model constructs
    // SHALL also be removed." A subscription is one of those constructs, and one that survived
    // would keep reporting to an administrator that has been removed.
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let mine = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    let theirs = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(2)),
                fabric_index: Some(FabricIndex(2)),
                peer_node_id: None,
                ..request(&paths, 0, 60)
            },
            at(0),
        )
        .expect("subscribe");

    assert_eq!(table.remove_for_fabric(FabricIndex(1)), 1);
    assert!(table.find(mine).is_none());
    assert!(table.find(theirs).is_some());
}

#[test]
fn fabric_filtering_outlives_the_request_that_set_it() {
    // §8.5.3.4: "The FabricFiltered parameter from the Subscribe Request SHALL remain in
    // effect for all data reported during the interaction." It is a one-time field on the
    // request and a permanent property of the subscription — which is why it is stored rather
    // than read from each report's context.
    let mut table = Table::new();
    let paths = [path(1, 0x0006, 0x0000)];
    let filtered = table
        .subscribe(&request(&paths, 0, 60), at(0))
        .expect("subscribe");
    let unfiltered = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(2)),
                fabric_filtered: false,
                ..request(&paths, 0, 60)
            },
            at(0),
        )
        .expect("subscribe");

    assert!(table.find(filtered).expect("subscription").fabric_filtered);
    assert!(
        !table
            .find(unfiltered)
            .expect("subscription")
            .fabric_filtered
    );
}

#[test]
fn the_due_iterator_reports_every_subscription_that_needs_one() {
    let mut table = Table::new();
    let a = [path(1, 0x0006, 0x0000)];
    let b = [path(2, 0x0008, 0x0000)];
    let quick = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(1)),
                ..request(&a, 0, 10)
            },
            at(0),
        )
        .expect("subscribe");
    let slow = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(2)),
                ..request(&b, 0, 100)
            },
            at(0),
        )
        .expect("subscribe");

    assert_eq!(table.due(at(5)).count(), 0);
    let due: Vec<_> = table
        .due(at(10))
        .map(|(s, reason)| (s.id, reason))
        .collect();
    assert_eq!(due, vec![(quick, ReportReason::KeepAlive)]);

    table.note_change(&b[0]);
    let due: Vec<_> = table
        .due(at(10))
        .map(|(s, reason)| (s.id, reason))
        .collect();
    assert_eq!(
        due,
        vec![(quick, ReportReason::KeepAlive), (slow, ReportReason::Data)]
    );
}

// --- The reports on the wire ---------------------------------------------------------------------

mod wire {
    use super::*;
    use matter_kit::dm::{
        Access, AttributeDescriptor, ClusterDescriptor, CommandDescriptor, Endpoint, Node,
        Privilege, Reporting, Resolved,
    };
    use matter_kit::im::{
        AccessControl, AttributeReport, ClusterHandler, InteractionContext, Outcome, ReportData,
        Server, Status,
    };
    use matter_kit::tlv::{Tag, TlvReader, TlvWriter};

    const ON_OFF: u32 = 0x0006;
    const ATTRS: &[AttributeDescriptor] = &[
        AttributeDescriptor::read_only(0x0000),
        AttributeDescriptor::read_only(0x0001),
        // `C` — Changes Omitted. §8.5: a report carries every change "with the exception of
        // attribute data with the Changes Omitted (C) quality".
        AttributeDescriptor::read_only(0x0002).with_reporting(Reporting::ChangesOmitted),
    ];
    const NO_CMDS: &[CommandDescriptor] = &[];
    const CLUSTERS: &[ClusterDescriptor<'static>] = &[ClusterDescriptor {
        id: ON_OFF,
        revision: 6,
        feature_map: 0,
        attributes: ATTRS,
        accepted_commands: NO_CMDS,
        generated_commands: &[],
        events: &[],
    }];
    const ENDPOINTS: &[Endpoint<'static>] =
        &[Endpoint::new(1, CLUSTERS), Endpoint::new(2, CLUSTERS)];

    struct Fake;

    impl ClusterHandler for Fake {
        fn read(
            &self,
            resolved: &Resolved<'_>,
            _ctx: &InteractionContext<'_>,
            w: &mut TlvWriter<'_>,
            tag: Tag,
        ) -> Result<(), Status> {
            w.unsigned(tag, u64::from(resolved.attribute))
                .map_err(|_| Status::Failure)
        }

        fn data_version(&self, _resolved: &Resolved<'_>) -> Option<u32> {
            Some(3)
        }
    }

    struct AllowAll;

    impl AccessControl for AllowAll {
        fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
            Outcome::Granted
        }
    }

    /// The `SubscriptionId [0]` of a `ReportData`, and its `SuppressResponse [4]`.
    fn header(bytes: &[u8]) -> (Option<u32>, bool) {
        let report = ReportData::decode(bytes).expect("decode");
        (report.subscription_id, report.suppress_response)
    }

    fn paths_of(bytes: &[u8]) -> Vec<AttributePath> {
        let report = ReportData::decode(bytes).expect("decode");
        let Some(iter) = report.attribute_reports().expect("reports") else {
            return Vec::new();
        };
        iter.map(|item| match item.expect("decode each") {
            AttributeReport::Data(d) => d.path,
            AttributeReport::Status(s) => s.path,
        })
        .collect()
    }

    #[test]
    fn a_priming_report_carries_the_subscription_id() {
        // §8.5.3.2: "The SubscriptionId value SHALL be the same as the one used in Report Data
        // generated to prime this subscription." So the id is allocated *before* the priming
        // report — a publisher that allocated it with the `SubscribeResponse` would have
        // nothing to put in the report that came first.
        let mut table = Table::new();
        let paths = [AttributePath {
            cluster: Some(ON_OFF),
            ..AttributePath::default()
        }];
        let id = table
            .subscribe(&request(&paths, 0, 60), at(0))
            .expect("subscribe");

        let access = AllowAll;
        let server = Server::new(Node::new(ENDPOINTS), &access, &Fake, 24);
        let ctx = InteractionContext::default();
        let mut scratch = [0u8; 512];
        let mut buf = [0u8; 2048];
        let (bytes, outcome) = server
            .prime(
                id,
                paths.iter().copied().map(Ok),
                &ctx,
                &mut scratch,
                &mut buf,
            )
            .expect("prime");

        assert_eq!(header(bytes).0, Some(id));
        // Two endpoints × three attributes, plus §7.13's five synthesised globals each.
        assert!(outcome.reports >= 6, "{} reports", outcome.reports);
        let reported = paths_of(bytes);
        assert!(
            reported.iter().all(|p| p.concrete().is_some()),
            "§8.4.3.2: every reported path is concrete"
        );
    }

    #[test]
    fn a_keep_alive_report_is_empty_and_suppresses_its_response() {
        // §8.6.2's Report Transaction Empty: "report with no data or events with
        // SuppressResponse set to TRUE". Asking for an acknowledgement would double the
        // traffic that a keep-alive exists to minimise — and there is nothing to acknowledge.
        let mut table = Table::new();
        let paths = [AttributePath {
            cluster: Some(ON_OFF),
            ..AttributePath::default()
        }];
        let id = table
            .subscribe(&request(&paths, 0, 60), at(0))
            .expect("subscribe");
        let subscription = table.find_mut(id).expect("subscription");
        assert_eq!(subscription.due(at(60)), Some(ReportReason::KeepAlive));

        let access = AllowAll;
        let server = Server::new(Node::new(ENDPOINTS), &access, &Fake, 24);
        let ctx = InteractionContext::default();
        let mut scratch = [0u8; 512];
        let mut buf = [0u8; 2048];
        let (bytes, outcome) = server
            .report(
                subscription,
                ReportReason::KeepAlive,
                &ctx,
                &mut scratch,
                &mut buf,
            )
            .expect("report");

        assert_eq!(outcome.reports, 0);
        assert_eq!(header(bytes), (Some(id), true));
        assert!(paths_of(bytes).is_empty());
    }

    #[test]
    fn a_data_report_carries_only_what_changed() {
        // §8.5: "Each Report transaction in a subscription SHALL report the path for each
        // delta change in the subscription data … since the last Report transaction." Sending
        // everything would work and would defeat the point of a subscription.
        let mut table = Table::new();
        let paths = [AttributePath {
            cluster: Some(ON_OFF),
            ..AttributePath::default()
        }];
        let id = table
            .subscribe(&request(&paths, 0, 60), at(0))
            .expect("subscribe");
        table.note_change(&path(2, ON_OFF, 0x0001));

        let subscription = table.find_mut(id).expect("subscription");
        assert_eq!(subscription.due(at(0)), Some(ReportReason::Data));

        let access = AllowAll;
        let server = Server::new(Node::new(ENDPOINTS), &access, &Fake, 24);
        let ctx = InteractionContext::default();
        let mut scratch = [0u8; 512];
        let mut buf = [0u8; 2048];
        let (bytes, _) = server
            .report(
                subscription,
                ReportReason::Data,
                &ctx,
                &mut scratch,
                &mut buf,
            )
            .expect("report");

        assert_eq!(
            header(bytes),
            (Some(id), false),
            "a data report is acknowledged"
        );
        assert_eq!(paths_of(bytes), vec![path(2, ON_OFF, 0x0001)]);
    }

    #[test]
    fn a_re_primed_report_carries_the_whole_subscription_again() {
        // §8.5's recovery: "Including all subscription data to re-prime the subscription."
        let mut table = Table::new();
        let paths = [AttributePath {
            cluster: Some(ON_OFF),
            ..AttributePath::default()
        }];
        let id = table
            .subscribe(&request(&paths, 0, 60), at(0))
            .expect("subscribe");
        table.reprime_all();

        let access = AllowAll;
        let server = Server::new(Node::new(ENDPOINTS), &access, &Fake, 24);
        let ctx = InteractionContext::default();
        let mut scratch = [0u8; 512];
        let mut buf = [0u8; 2048];
        let subscription = table.find_mut(id).expect("subscription");
        let (bytes, outcome) = server
            .report(
                subscription,
                ReportReason::Data,
                &ctx,
                &mut scratch,
                &mut buf,
            )
            .expect("report");
        assert!(outcome.reports >= 6, "the whole subscription, not a delta");
        assert_eq!(header(bytes).0, Some(id));
    }

    #[test]
    fn a_changes_omitted_attribute_is_the_callers_to_leave_alone() {
        // §8.5: a report carries every change "with the exception of attribute data with the
        // Changes Omitted (C) quality". The table cannot enforce that on its own — it does not
        // know an attribute's qualities — so the rule belongs where the change is noticed, and
        // the descriptor is what says so.
        let cluster = CLUSTERS[0];
        let quiet = cluster.attribute(0x0002).expect("attribute");
        assert_eq!(quiet.reporting, Reporting::ChangesOmitted);
        let noisy = cluster.attribute(0x0000).expect("attribute");
        assert_eq!(noisy.reporting, Reporting::OnChange);

        // A device that checks it reports nothing for the quiet one.
        let mut table = Table::new();
        let paths = [AttributePath {
            cluster: Some(ON_OFF),
            ..AttributePath::default()
        }];
        let id = table
            .subscribe(&request(&paths, 0, 60), at(0))
            .expect("subscribe");
        for attribute in [0x0000u32, 0x0001, 0x0002] {
            let changed = path(1, ON_OFF, attribute);
            let descriptor = cluster.attribute(attribute).expect("attribute");
            if descriptor.reporting != Reporting::ChangesOmitted {
                table.note_change(&changed);
            }
        }
        let subscription = table.find(id).expect("subscription");
        assert_eq!(
            subscription.dirty.paths(),
            &[path(1, ON_OFF, 0x0000), path(1, ON_OFF, 0x0001)]
        );
        let _ = Access::read_only(Privilege::View);
        let _ = TlvReader::new(&[]);
    }

    /// A report built from a cluster-grained dirty entry must carry the cluster's attributes with
    /// their *current* values, under the subscription id the subscriber is holding.
    ///
    /// This is the question the container could not answer cheaply. `chip-tool` receives the
    /// reports and accepts them — it answers each with a `StatusResponse` — and its cache still does
    /// not have the value, so what is in doubt is the content, not the delivery. A report attributed
    /// to the wrong subscription id would look exactly the same from outside.
    #[test]
    fn a_cluster_grained_dirty_entry_reports_the_clusters_attributes() {
        let mut table = Table::new();
        let paths = [AttributePath::default()];
        let id = table
            .subscribe(&request(&paths, 0, 60), at(0))
            .expect("subscribe");
        table.find_mut(id).expect("present").reported(at(0));

        // Exactly what `DataVersions::drain_changes` feeds in: a whole cluster instance.
        assert_eq!(table.note_cluster_change(1, ON_OFF), 1);

        let subscription = table.find_mut(id).expect("present");
        let access = AllowAll;
        let server = Server::new(Node::new(ENDPOINTS), &access, &Fake, 24);
        let ctx = InteractionContext::default();
        let mut scratch = [0u8; 512];
        let mut buf = [0u8; 2048];
        let (bytes, outcome) = server
            .report(
                subscription,
                ReportReason::Data,
                &ctx,
                &mut scratch,
                &mut buf,
            )
            .expect("report");

        // It carries the subscription's own id — a report the subscriber cannot attribute is a
        // report it accepts and discards.
        assert_eq!(
            header(bytes).0,
            Some(id),
            "reported under the wrong subscription id"
        );
        // And it carries attributes, each at a concrete path.
        assert!(outcome.reports > 0, "the report is empty");
        let reported = paths_of(bytes);
        assert!(
            reported.iter().all(|p| p.concrete().is_some()),
            "§8.4.3.2: every reported path is concrete"
        );
        assert!(
            reported
                .iter()
                .all(|p| p.cluster == Some(ON_OFF) && p.endpoint == Some(1)),
            "only the cluster that changed: {reported:?}"
        );
    }

    /// Two subscribers reporting at the same time each get their *own* report, whole.
    ///
    /// This is the defect the CHIP certification harness found and nothing in this suite could:
    /// `report_chunk` used to take the cursor from the caller, so a node serving two controllers
    /// naturally kept one — it works perfectly until the second subscriber arrives. Then the
    /// second subscription's priming report resumes at wherever the first one's chunked series
    /// had got to, and the first one's next chunk resumes into the second's.
    ///
    /// Nothing looks wrong from outside. Every message is well-formed, carries the correct
    /// subscription id, and is acknowledged; the subscriber caches what it is told and reads back
    /// a value that was never sent. `TC_CGEN_2_1` saw it as "read returned 1, subscription cache
    /// has 0" three seconds later, with no error at either end.
    ///
    /// The cursor now lives on the subscription, so there is no cursor for a caller to share.
    #[test]
    fn two_subscriptions_reporting_at_once_do_not_resume_into_each_other() {
        let mut table = Table::new();
        let whole_node = [AttributePath::default()];
        let first = table
            .subscribe(&request(&whole_node, 0, 60), at(0))
            .expect("first");
        let second = table
            .subscribe(&request(&whole_node, 0, 60), at(0))
            .expect("second");

        let access = AllowAll;
        let server = Server::new(Node::new(ENDPOINTS), &access, &Fake, 24);
        let ctx = InteractionContext::default();
        let mut scratch = [0u8; 512];
        // Small enough that a whole-node report has to chunk, which is the only way the two
        // series can overlap at all.
        let mut buf = [0u8; 256];

        // Both re-prime: §8.5.3.4's priming report is everything the subscription asked for.
        table.find_mut(first).expect("first").reprime();
        table.find_mut(second).expect("second").reprime();

        // Interleave them the way two controllers do: a chunk to one, a chunk to the other,
        // until both series finish. Each subscriber collects what it was actually sent.
        let mut collected: [Vec<AttributePath>; 2] = [Vec::new(), Vec::new()];
        let mut running = [true, true];
        let mut messages = 0;
        while running.iter().any(|r| *r) {
            for (slot, id) in [first, second].into_iter().enumerate() {
                if !running[slot] {
                    continue;
                }
                let subscription = table.find_mut(id).expect("present");
                let (bytes, outcome) = server
                    .report_chunk(
                        subscription,
                        ReportReason::Data,
                        &ctx,
                        &mut scratch,
                        &mut buf,
                    )
                    .expect("chunk");
                assert_eq!(
                    header(bytes).0,
                    Some(id),
                    "chunk attributed to the wrong subscription"
                );
                collected[slot].extend(paths_of(bytes));
                running[slot] = outcome.truncated;
                messages += 1;
                assert!(messages < 500, "the series never finished");
            }
        }

        // The point: interleaving changed nothing. Each subscriber got the whole node.
        assert!(!collected[0].is_empty(), "the first subscriber got nothing");
        assert_eq!(
            collected[0], collected[1],
            "the two subscribers were sent different data for the same whole-node subscription"
        );

        // And what each got is what one alone would have got.
        let mut alone = Table::new();
        let solo = alone
            .subscribe(&request(&whole_node, 0, 60), at(0))
            .expect("solo");
        alone.find_mut(solo).expect("solo").reprime();
        let mut expected: Vec<AttributePath> = Vec::new();
        for message in 0.. {
            assert!(message < 500, "the series never finished");
            let subscription = alone.find_mut(solo).expect("solo");
            let (bytes, outcome) = server
                .report_chunk(
                    subscription,
                    ReportReason::Data,
                    &ctx,
                    &mut scratch,
                    &mut buf,
                )
                .expect("chunk");
            expected.extend(paths_of(bytes));
            if !outcome.truncated {
                break;
            }
        }
        assert_eq!(
            collected[0], expected,
            "sharing the wire with another subscriber changed what a subscription reported"
        );
    }

    /// A finished series starts the next report over, so no caller has to reset anything.
    ///
    /// The mirror of the bug above, and the one that made the shared cursor look survivable: a
    /// cursor left `done` by the last chunk of a series produces an *empty* next report. It is
    /// well-formed, correctly attributed, accepted — and `reported()` then clears the change that
    /// prompted it, so the subscriber holds a stale value for ever with no error at either end.
    #[test]
    fn a_report_after_a_finished_series_is_not_empty() {
        let mut table = Table::new();
        let whole_node = [AttributePath::default()];
        let id = table
            .subscribe(&request(&whole_node, 0, 60), at(0))
            .expect("subscribe");

        let access = AllowAll;
        let server = Server::new(Node::new(ENDPOINTS), &access, &Fake, 24);
        let ctx = InteractionContext::default();
        let mut scratch = [0u8; 512];
        let mut buf = [0u8; 256];

        // Run a full priming series to completion, leaving the cursor wherever it ends up.
        table.find_mut(id).expect("present").reprime();
        for message in 0.. {
            assert!(message < 500, "the priming series never finished");
            let subscription = table.find_mut(id).expect("present");
            let (_, outcome) = server
                .report_chunk(
                    subscription,
                    ReportReason::Data,
                    &ctx,
                    &mut scratch,
                    &mut buf,
                )
                .expect("chunk");
            if !outcome.truncated {
                break;
            }
        }
        table.find_mut(id).expect("present").reported(at(1));

        // Now one attribute changes. The report that follows must carry it.
        assert_eq!(table.note_cluster_change(1, ON_OFF), 1);
        let subscription = table.find_mut(id).expect("present");
        let (bytes, outcome) = server
            .report_chunk(
                subscription,
                ReportReason::Data,
                &ctx,
                &mut scratch,
                &mut buf,
            )
            .expect("report");
        assert!(
            outcome.reports > 0,
            "the first report after a finished series carried nothing"
        );
        assert_eq!(header(bytes).0, Some(id));
    }
}

// --- Events in a subscription -------------------------------------------------------------------

use matter_kit::im::EventPath;

fn with_events(events: &[EventPath], min: u16, max: u16) -> NewSubscription<'_> {
    NewSubscription {
        session: Some(SessionId(1)),
        fabric_index: Some(FabricIndex(1)),
        peer_node_id: None,
        fabric_filtered: true,
        keep_subscriptions: true,
        min_interval_s: min,
        max_interval_s: max,
        paths: &[],
        event_paths: events,
        min_event_number: 0,
    }
}

#[test]
fn an_event_only_subscription_is_perfectly_ordinary() {
    // §8.5.2.2: "At least one attribute **or event** SHALL be indicated in the action." A door
    // lock reporting `LockOperation` subscribes to no attribute at all, and a publisher that
    // required one would refuse the most security-relevant subscription there is.
    let mut table = Table::new();
    let events = [EventPath::event(1, 0x0101, 0x0002)];
    let id = table
        .subscribe(&with_events(&events, 0, 60), at(0))
        .expect("subscribe");
    assert!(table.find(id).expect("subscription").paths.is_empty());
    assert_eq!(table.find(id).expect("subscription").event_paths.len(), 1);

    // But neither kind of path at all is still `NoPaths`.
    assert_eq!(
        table.subscribe(&with_events(&[], 0, 60), at(0)),
        Err(SubscribeError::NoPaths)
    );
}

#[test]
fn a_non_urgent_event_waits_for_the_next_report() {
    // §8.5: "When the IsUrgent flag is FALSE or absent for a subscription's event path in the
    // EventPathIB, event queueing does not automatically trigger a Report transaction."
    //
    // The events still go out — on whatever report happens next, at the latest the keep-alive
    // — but they do not *cause* one. A publisher that reported every event immediately would
    // wake a battery-powered subscriber for a debug log entry.
    let mut table = Table::new();
    let events = [EventPath::event(1, 0x0101, 0x0002)];
    let id = table
        .subscribe(&with_events(&events, 0, 60), at(0))
        .expect("subscribe");

    assert_eq!(table.note_event(1, 0x0101, 0x0002), 0, "nothing urgent");
    let subscription = table.find(id).expect("subscription");
    assert!(!subscription.has_pending());
    assert_eq!(subscription.due(at(1)), None);
    assert_eq!(subscription.due(at(60)), Some(ReportReason::KeepAlive));
}

#[test]
fn an_urgent_event_triggers_a_report() {
    // §8.5: "When the IsUrgent flag is TRUE for a subscription's event path in the
    // EventPathIB, the queueing of such an event SHALL trigger a Report transaction for the
    // subscription, subject to all Report transaction rules."
    //
    // "Subject to all Report transaction rules" is the qualifier that matters: urgency does
    // not override the minimum interval.
    let mut table = Table::new();
    let events = [EventPath {
        endpoint: Some(1),
        cluster: Some(0x0101),
        event: Some(0x0002),
        is_urgent: Some(true),
        node: None,
    }];
    let id = table
        .subscribe(&with_events(&events, 10, 600), at(0))
        .expect("subscribe");

    assert_eq!(table.note_event(1, 0x0101, 0x0002), 1);
    let subscription = table.find(id).expect("subscription");
    assert!(subscription.has_pending());
    assert_eq!(
        subscription.due(at(9)),
        None,
        "urgency is still subject to the minimum interval"
    );
    assert_eq!(subscription.due(at(10)), Some(ReportReason::Data));
    assert_eq!(subscription.next_deadline(), at(10));
}

#[test]
fn urgency_is_a_property_of_the_path_not_of_the_event() {
    // §10.6.8 puts `IsUrgent` in the `EventPathIB`, which is part of the *request*. The same
    // event is therefore urgent to one subscriber and not to another — a publisher that
    // recorded urgency on the event would wake every subscriber whenever any of them cared.
    let mut table = Table::new();
    let urgent = [EventPath {
        endpoint: Some(1),
        cluster: Some(0x0101),
        event: Some(0x0002),
        is_urgent: Some(true),
        node: None,
    }];
    let patient = [EventPath::event(1, 0x0101, 0x0002)];

    let eager = table
        .subscribe(&with_events(&urgent, 0, 600), at(0))
        .expect("subscribe");
    let relaxed = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(2)),
                ..with_events(&patient, 0, 600)
            },
            at(0),
        )
        .expect("subscribe");

    assert_eq!(table.note_event(1, 0x0101, 0x0002), 1, "one of the two");
    assert!(table.find(eager).expect("subscription").has_pending());
    assert!(!table.find(relaxed).expect("subscription").has_pending());
}

#[test]
fn a_wildcard_event_path_covers_and_a_mismatched_one_does_not() {
    let mut table = Table::new();
    let any_on_cluster = [EventPath {
        cluster: Some(0x0101),
        is_urgent: Some(true),
        ..EventPath::default()
    }];
    let id = table
        .subscribe(&with_events(&any_on_cluster, 0, 600), at(0))
        .expect("subscribe");

    assert_eq!(
        table
            .find(id)
            .expect("subscription")
            .event_urgency(7, 0x0101, 0x0009),
        Some(true),
        "any endpoint, any event on the cluster"
    );
    assert_eq!(
        table
            .find(id)
            .expect("subscription")
            .event_urgency(1, 0x0006, 0x0000),
        None,
        "a different cluster is not covered at all"
    );
}

#[test]
fn the_event_bookmark_starts_at_the_filter_and_advances_with_reports() {
    // §8.5.3.4: "The EventFilters and DataVersionFilters fields in the Subscribe Request are
    // one time parameters for the priming of the subscription", and "Subsequent ReportData
    // actions … SHALL include the latest EventNo". So the filter seeds a bookmark that the
    // subscription then keeps for itself.
    let mut table = Table::new();
    let events = [EventPath {
        cluster: Some(0x0101),
        is_urgent: Some(true),
        ..EventPath::default()
    }];
    let id = table
        .subscribe(&with_events(&events, 0, 60), at(0))
        .expect("subscribe");
    assert_eq!(table.find(id).expect("subscription").next_event_number, 0);

    let id = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(2)),
                ..with_events(&events, 0, 60)
            },
            at(0),
        )
        .expect("subscribe");
    table.find_mut(id).expect("subscription").next_event_number = 0;

    table.note_event(1, 0x0101, 0x0002);
    assert!(table.find(id).expect("subscription").has_pending());

    // A report clears the urgency. Where it leaves the bookmark is the *server's* to say —
    // `Server::report_chunk` records what the message actually carried — so that half is tested
    // against a real report in `tests/im_events_read.rs`, where the two reports and what each
    // one delivered are visible.
    table.find_mut(id).expect("subscription").reported(at(1));
    let subscription = table.find(id).expect("subscription");
    assert!(!subscription.has_pending());
    assert_eq!(
        subscription.next_event_number, 0,
        "a report that carried no events leaves the bookmark alone"
    );
}

#[test]
fn a_subscription_primed_from_a_filter_starts_there() {
    let mut table = Table::new();
    let events = [EventPath::event(1, 0x0101, 0x0002)];
    let id = table
        .subscribe(&with_events(&events, 0, 60), at(0))
        .expect("subscribe");
    assert_eq!(table.find(id).expect("subscription").next_event_number, 0);

    let id = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(2)),
                ..with_events(&events, 0, 60)
            },
            at(0),
        )
        .expect("subscribe");
    let _ = id;

    // An `EventFilter` of 500 means "I already have everything below 500".
    let id = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(3)),
                ..with_events(&events, 0, 60)
            },
            at(0),
        )
        .expect("subscribe");
    table.find_mut(id).expect("subscription").next_event_number = 500;
    assert_eq!(table.find(id).expect("subscription").next_event_number, 500);
}

// --- Persistence across a reboot (§8.5) ---------------------------------------------------

/// A subscription from a real CASE subscriber, so it has an identity a reboot can find again.
fn case_request<'a>(
    paths: &'a [AttributePath],
    session: u16,
    fabric: u8,
    peer: u64,
) -> NewSubscription<'a> {
    NewSubscription {
        session: Some(SessionId(session)),
        fabric_index: Some(FabricIndex(fabric)),
        peer_node_id: Some(matter_kit::msg::NodeId(peer)),
        fabric_filtered: true,
        keep_subscriptions: true,
        min_interval_s: 2,
        max_interval_s: 60,
        paths,
        event_paths: &[],
        min_event_number: 41,
    }
}

/// Saves a table and restores it into a fresh one, as a reboot would.
fn reboot(table: &Table, now: Instant) -> (Table, usize, usize) {
    use matter_kit::im::persist;
    use matter_kit::tlv::{Tag, TlvWriter};

    let mut buf = [0u8; 4096];
    let mut w = TlvWriter::new(&mut buf);
    let saved = persist::save(table, &mut w, Tag::Anonymous).expect("save");
    let bytes = w.finish().expect("finish").to_vec();

    let mut fresh = Table::new();
    let restored = persist::restore(&mut fresh, &bytes, now).expect("restore");
    (fresh, saved, restored)
}

#[test]
fn a_restored_subscription_keeps_its_identity_and_forgets_its_session() {
    let paths = [path(1, 0x0006, 0x0000), path(1, 0x0008, 0x0000)];
    let mut table = Table::new();
    let id = table
        .subscribe(&case_request(&paths, 7, 1, 0xAABB), at(0))
        .expect("subscribe");

    let (restored, saved, count) = reboot(&table, at(0));
    assert_eq!((saved, count), (1, 1));

    let subscription = restored.find(id).expect("the same id survived");
    assert_eq!(subscription.fabric_index, Some(FabricIndex(1)));
    assert_eq!(
        subscription.peer_node_id,
        Some(matter_kit::msg::NodeId(0xAABB))
    );
    assert_eq!(subscription.min_interval_s, 2);
    assert_eq!(subscription.max_interval_s, 60);
    assert!(subscription.fabric_filtered);
    assert_eq!(subscription.paths.as_slice(), &paths);
    assert_eq!(
        subscription.next_event_number, 41,
        "§7.14.1.1's event numbers are themselves durable, so the bookmark is meaningful"
    );

    // The session is not restored. A session id from before the reboot names whatever session
    // holds that number now — at best nobody, at worst somebody else's.
    assert_eq!(subscription.session, None);
}

#[test]
fn a_restored_subscription_re_primes_rather_than_reporting_deltas() {
    // While the device was off, anything could have changed and it has no record of what. The
    // subscriber's twin is not stale in some identified way, it is unknown — so §8.5.3.4's
    // priming report is the only honest answer. A restored subscription that reported deltas
    // would leave the client permanently wrong about every attribute that changed during the
    // outage, with nothing left to correct it.
    let paths = [path(1, 0x0006, 0x0000)];
    let mut table = Table::new();
    table
        .subscribe(&case_request(&paths, 7, 1, 0xAABB), at(0))
        .expect("subscribe");
    // Clean at the moment of the save: nothing is known to have changed.
    for subscription in table.iter() {
        assert!(!subscription.dirty.is_dirty());
    }

    let (restored, _, _) = reboot(&table, at(0));
    let subscription = restored.iter().next().expect("one subscription");
    assert!(
        subscription.dirty.is_dirty(),
        "a restored subscription owes a full report"
    );
    assert!(subscription.has_pending());
}

#[test]
fn a_restored_subscription_reports_nothing_until_its_subscriber_returns() {
    use matter_kit::im::persist;

    let paths = [path(1, 0x0006, 0x0000)];
    let mut table = Table::new();
    table
        .subscribe(&case_request(&paths, 7, 1, 0xAABB), at(0))
        .expect("subscribe");
    let (mut restored, _, _) = reboot(&table, at(0));

    // It is dirty and past its minimum interval, and still nothing is due: there is nowhere to
    // send it. A device polling `due` would otherwise be handed the same unreportable
    // subscription on every poll for the rest of its life — and an intermittently connected
    // one would wake for it.
    assert!(restored.iter().next().expect("one").has_pending());
    assert_eq!(restored.due(at(100)).count(), 0);
    assert_eq!(restored.next_deadline(), None);

    // The subscriber comes back on a *new* CASE session. Matching is on fabric and Node ID,
    // which is what CASE proved; the old session id proved nothing and is gone.
    let bound = persist::rebind(
        &mut restored,
        FabricIndex(1),
        matter_kit::msg::NodeId(0xAABB),
        SessionId(99),
        at(100),
    );
    assert_eq!(bound, 1);
    let subscription = restored.iter().next().expect("one");
    assert_eq!(subscription.session, Some(SessionId(99)));

    // And the intervals restart from the moment it became live — §8.5.3.4's minimum interval
    // is a promise about pacing, and a subscription that sat dormant for an hour must not fire
    // the instant it is bound.
    assert!(restored.due(at(100)).next().is_none());
    assert!(restored.due(at(102)).next().is_some());
}

#[test]
fn rebinding_matches_the_subscriber_not_the_session_number() {
    use matter_kit::im::persist;

    let paths = [path(1, 0x0006, 0x0000)];
    let mut table = Table::new();
    table
        .subscribe(&case_request(&paths, 7, 1, 0xAABB), at(0))
        .expect("mine");
    table
        .subscribe(&case_request(&paths, 8, 1, 0xCCDD), at(0))
        .expect("another node on the same fabric");
    table
        .subscribe(&case_request(&paths, 9, 2, 0xAABB), at(0))
        .expect("the same node on another fabric");

    let (mut restored, saved, count) = reboot(&table, at(0));
    assert_eq!((saved, count), (3, 3));

    // Only the one whose *fabric and node* both match is bound. The other two are somebody
    // else's, and a device that bound them would report one subscriber's data to another.
    let bound = persist::rebind(
        &mut restored,
        FabricIndex(1),
        matter_kit::msg::NodeId(0xAABB),
        SessionId(99),
        at(10),
    );
    assert_eq!(bound, 1);
    assert_eq!(restored.iter().filter(|s| s.session.is_some()).count(), 1);
    let bound = restored
        .iter()
        .find(|s| s.session == Some(SessionId(99)))
        .expect("one was bound");
    assert_eq!(bound.fabric_index, Some(FabricIndex(1)));
    assert_eq!(bound.peer_node_id, Some(matter_kit::msg::NodeId(0xAABB)));
}

#[test]
fn a_subscription_with_no_operational_identity_is_not_persisted() {
    // §2.11.2.2 permits a subscription over PASE — "A server MAY permit Subscribe Interactions
    // even when there is no accessing fabric" — but there is nothing on the far side of a
    // reboot for it to belong to. The PASE session is gone, the commissioner has moved on to
    // CASE, and a restored one could never be rebound: it would hold one of a device's few
    // subscription slots for the rest of its life.
    let paths = [path(1, 0x0006, 0x0000)];
    let mut table = Table::new();
    table
        .subscribe(&request(&paths, 2, 60), at(0))
        .expect("PASE");
    table
        .subscribe(&case_request(&paths, 8, 1, 0xCCDD), at(0))
        .expect("CASE");
    assert_eq!(table.len(), 2);

    let (restored, saved, count) = reboot(&table, at(0));
    assert_eq!((saved, count), (1, 1), "only the CASE one is durable");
    assert_eq!(
        restored.iter().next().expect("one").peer_node_id,
        Some(matter_kit::msg::NodeId(0xCCDD))
    );
}

#[test]
fn a_restored_id_is_never_handed_out_again() {
    // §8.5.3.1's ids must stay unique across a reboot too. A subscriber caches its
    // `SubscriptionId`, and reusing one points that cached value at somebody else's
    // subscription — so the next `Subscribe` after a restore must not collide with what came
    // back.
    let paths = [path(1, 0x0006, 0x0000)];
    let mut table = Table::new();
    let mut ids = Vec::new();
    // Two fabrics: §2.11.2.2 allows any one of them three, and this needs four.
    for n in 0..4u64 {
        let fabric = if n < 2 { 1 } else { 2 };
        ids.push(
            table
                .subscribe(&case_request(&paths, 7, fabric, 0xA000 + n), at(0))
                .expect("subscribe"),
        );
    }

    let (mut restored, _, count) = reboot(&table, at(0));
    assert_eq!(count, 4);

    // One of the restored subscriptions ends before anything new is created — its subscriber
    // dropped off, or the fabric it belonged to went away. Its id is now free, and its
    // subscriber's cached `SubscriptionId` does not know that. A merely collision-free
    // allocator hands the number straight back out and points that stale value at somebody
    // else's subscription; the allocator is monotonic precisely so it cannot, and a restore
    // has to carry the high-water mark across for that to keep working.
    let ended = ids[1];
    assert!(restored.remove(ended));
    let next = restored
        .subscribe(&case_request(&paths, 7, 1, 0xB000), at(0))
        .expect("a new subscription after the reboot");
    assert_ne!(next, ended, "a freed id was handed straight back out");
    assert!(
        !ids.contains(&next),
        "{next} collides with a restored id from {ids:?}"
    );
}

#[test]
fn a_damaged_store_fails_the_whole_restore() {
    use matter_kit::im::persist;

    // Persisted state that does not decode means the store is damaged, and a device that
    // quietly kept the half it could read would have subscriptions the client believes in and
    // the device has forgotten — the exact failure persistence exists to prevent, arrived at
    // more slowly and with no way to tell it happened.
    let mut fresh = Table::new();
    for damaged in [
        &[][..],
        &[0x15, 0x18][..],             // a structure where an array belongs
        &[0x16][..],                   // an array that never ends
        &[0x16, 0x15, 0x18, 0x18][..], // a record with no id and no paths
    ] {
        assert!(
            persist::restore(&mut fresh, damaged, at(0)).is_err(),
            "{damaged:02X?} should not restore"
        );
    }
    assert!(fresh.is_empty());
}

/// §7.10.3 records a change at the grain of a *cluster* — "A cluster data version SHALL be
/// incremented if any attribute data changes" names the cluster and never the attribute — so
/// that is the grain a node can report changes at without every cluster being rewritten to
/// announce each field it touches.
///
/// The matching rule is therefore intersection, not coverage, and the difference is the whole
/// reason this exists. A subscription that names one concrete attribute overlaps a change to
/// the cluster containing it; `covers` would say no, because an absent attribute on the
/// *changed* side means "no attribute named" rather than "any".
#[test]
fn a_cluster_change_dirties_every_subscription_that_overlaps_it() {
    const GENERAL_COMMISSIONING: u32 = 0x0030;
    const BREADCRUMB: u32 = 0x0000;

    let mut table = Table::new();

    // One subscriber wants the whole node; one wants exactly Breadcrumb; one wants a different
    // cluster entirely.
    let wildcard = table
        .subscribe(&request(&[AttributePath::default()], 0, 60), at(0))
        .expect("wildcard");
    let concrete = table
        .subscribe(
            &request(
                &[AttributePath {
                    endpoint: Some(0),
                    cluster: Some(GENERAL_COMMISSIONING),
                    attribute: Some(BREADCRUMB),
                    ..AttributePath::default()
                }],
                0,
                60,
            ),
            at(0),
        )
        .expect("concrete");
    let elsewhere = table
        .subscribe(
            &request(
                &[AttributePath {
                    cluster: Some(0x0006),
                    ..AttributePath::default()
                }],
                0,
                60,
            ),
            at(0),
        )
        .expect("elsewhere");

    // Everything starts clean, so what follows is the change and nothing else.
    for id in [wildcard, concrete, elsewhere] {
        table.find_mut(id).expect("present").reported(at(0));
    }

    assert_eq!(table.note_cluster_change(0, GENERAL_COMMISSIONING), 2);
    assert!(table.find(wildcard).expect("present").has_pending());
    assert!(
        table.find(concrete).expect("present").has_pending(),
        "a subscription naming one attribute of the changed cluster is owed a report"
    );
    assert!(
        !table.find(elsewhere).expect("present").has_pending(),
        "a subscription on another cluster is not"
    );

    // The dirty entry is the intersection: the changed cluster, narrowed to what each
    // subscription actually asked for.
    let narrowed = table.find(concrete).expect("present").dirty.paths();
    assert_eq!(narrowed.len(), 1);
    assert_eq!(narrowed[0].cluster, Some(GENERAL_COMMISSIONING));
    assert_eq!(narrowed[0].attribute, Some(BREADCRUMB));
}
