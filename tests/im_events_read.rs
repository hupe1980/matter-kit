//! Reading **events** over the interaction model — §8.4.3.3's other half.
//!
//! Every piece of this existed and none of it was joined: `dm::events` held the records,
//! `im::ib` encoded `EventDataIB` and `EventStatusIB`, `EventPath` and `EventFilter` decoded,
//! and `im::server` had no reference to an event path anywhere. A node could record events
//! perfectly and never deliver one, and `SPEC_COVERAGE.md` called §8.4 Read ✅.
//!
//! So these tests ask the only question that catches that: does a record a cluster wrote come
//! back out of a `ReportData`?

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use matter_kit::dm::events::{EventNumbers, EventStore, NewEvent, Timestamp};
use matter_kit::dm::{
    AttributeDescriptor, ClusterDescriptor, Endpoint, EventDescriptor, EventPriority, Node,
    Resolved,
};
use matter_kit::im::{
    AccessControl, ClusterHandler, EventPath, EventReport, InteractionContext, ReportData, Server,
    Status,
};
use matter_kit::msg::FabricIndex;
use matter_kit::tlv::{Tag, TlvWriter};

const ON_OFF: u32 = 0x0006;
const STARTED: u32 = 0x0000;
/// `Administer` to read, so the access check has something to refuse.
const SECRET: u32 = 0x0001;

const ATTRS: &[AttributeDescriptor] = &[AttributeDescriptor::read_only(0x0000)];
const EVENTS: &[EventDescriptor] = &[
    EventDescriptor::new(STARTED),
    EventDescriptor {
        id: SECRET,
        access: matter_kit::dm::Access::read_only(matter_kit::dm::access::Privilege::Administer),
        priority: EventPriority::Critical,
    },
];

const EP1: &[ClusterDescriptor<'static>] = &[ClusterDescriptor {
    id: ON_OFF,
    revision: 6,
    feature_map: 0,
    attributes: ATTRS,
    accepted_commands: &[],
    generated_commands: &[],
    events: EVENTS,
}];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(1, EP1)];

fn node() -> Node<'static> {
    Node::new(ENDPOINTS)
}

/// §10.6.9.3's encoding for an event with no payload: an empty structure under context tag 7.
const EMPTY_DATA: &[u8] = &[0x35, 0x07, 0x18];

#[derive(Debug)]
struct Fake;
impl ClusterHandler for Fake {
    fn read(
        &self,
        _r: &Resolved<'_>,
        _c: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.unsigned(tag, 1).map_err(|_| Status::Failure)
    }
}

struct Holds(matter_kit::dm::access::Privilege);
impl AccessControl for Holds {
    fn allows(
        &self,
        _path: &matter_kit::im::AttributePath,
        required: matter_kit::dm::access::Privilege,
    ) -> matter_kit::im::Outcome {
        if self.0.grants(required) {
            matter_kit::im::Outcome::Granted
        } else {
            matter_kit::im::Outcome::Denied
        }
    }
}

type Store = EventStore<4, 4, 4>;

fn store_at(records: &[(u32, EventPriority, Option<FabricIndex>, u64)]) -> Store {
    let mut numbers = EventNumbers::restore(0);
    let owed = numbers.reservation().expect("a fresh counter owes one");
    numbers.reserved(owed);
    let mut store = EventStore::new(numbers);
    for (event, priority, fabric, millis) in records {
        store
            .record(&NewEvent {
                endpoint: 1,
                cluster: ON_OFF,
                event: *event,
                priority: *priority,
                timestamp: Timestamp::System(*millis),
                fabric_index: *fabric,
                data: EMPTY_DATA,
            })
            .expect("record");
    }
    store
}

fn store_with(records: &[(u32, EventPriority, Option<FabricIndex>)]) -> Store {
    let mut numbers = EventNumbers::restore(0);
    let owed = numbers.reservation().expect("a fresh counter owes one");
    numbers.reserved(owed);
    let mut store = EventStore::new(numbers);
    for (event, priority, fabric) in records {
        store
            .record(&NewEvent {
                endpoint: 1,
                cluster: ON_OFF,
                event: *event,
                priority: *priority,
                timestamp: Timestamp::System(1_000),
                fabric_index: *fabric,
                data: EMPTY_DATA,
            })
            .expect("record");
    }
    store
}

/// Reads `paths` as events and returns what came back, in order.
fn read_events(
    store: &Store,
    paths: &[EventPath],
    access: &Holds,
    ctx: &InteractionContext<'_>,
) -> Vec<(EventPath, Option<Status>, Option<u64>)> {
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let server = Server::new(node(), access, &Fake, 64).with_events(store);
    let mut cursor = matter_kit::im::ReadCursor::START;
    let (bytes, _) = server
        .serve_chunk_with_events(
            core::iter::empty(),
            paths.iter().copied().map(Ok),
            ctx,
            None,
            &mut cursor,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let report = ReportData::decode(bytes).expect("decode");
    let Some(iter) = report.event_reports().expect("reports") else {
        return Vec::new();
    };
    iter.map(|item| match item.expect("decode each") {
        EventReport::Data(data) => (data.path, None, Some(data.number)),
        EventReport::Status(s) => (s.path, Some(s.status.status), None),
    })
    .collect()
}

fn wildcard() -> EventPath {
    EventPath {
        node: None,
        endpoint: None,
        cluster: None,
        event: None,
        is_urgent: None,
    }
}

#[test]
fn a_recorded_event_comes_back_out_of_a_report() {
    // The question nothing asked: a node recorded an event — does a read deliver it? Before
    // `Server::with_events` the answer was no, for every node and every event, and the only
    // symptom was a client that saw an empty log.
    let store = store_with(&[(STARTED, EventPriority::Info, None)]);
    let got = read_events(
        &store,
        &[wildcard()],
        &Holds(matter_kit::dm::access::Privilege::View),
        &InteractionContext::default(),
    );
    assert_eq!(got.len(), 1, "the recorded event was not reported: {got:?}");
    assert_eq!(got[0].1, None, "expected data, got a status");
    assert_eq!(got[0].0.event, Some(STARTED));
}

#[test]
fn events_are_reported_in_event_number_order() {
    // §8.5: "Each Report containing events SHALL deliver queued events without reordering the
    // queue." Critical is recorded second here, and a store that walked its priority buffers in
    // turn would put it first — handing the client a log that contradicts itself.
    let store = store_with(&[
        (STARTED, EventPriority::Info, None),
        (STARTED, EventPriority::Critical, None),
        (STARTED, EventPriority::Debug, None),
    ]);
    let got = read_events(
        &store,
        &[wildcard()],
        &Holds(matter_kit::dm::access::Privilege::View),
        &InteractionContext::default(),
    );
    let numbers: Vec<u64> = got.iter().filter_map(|g| g.2).collect();
    let mut sorted = numbers.clone();
    sorted.sort_unstable();
    assert_eq!(numbers, sorted, "events arrived out of order: {numbers:?}");
    assert_eq!(numbers.len(), 3);
}

#[test]
fn a_concrete_path_for_an_event_that_does_not_exist_is_a_status() {
    // §8.4.3.3 mirrors §8.4.3.2's asymmetry: a concrete path gets an answer, a wildcard is
    // discarded. A client that named one event deserves to be told it is not there.
    let store = store_with(&[]);
    let got = read_events(
        &store,
        &[EventPath {
            node: None,
            endpoint: Some(1),
            cluster: Some(ON_OFF),
            event: Some(0x00FF),
            is_urgent: None,
        }],
        &Holds(matter_kit::dm::access::Privilege::View),
        &InteractionContext::default(),
    );
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, Some(Status::UnsupportedEvent));
}

#[test]
fn an_event_above_the_subjects_privilege_is_refused_not_hidden() {
    // §8.4.3.3 step 4: the check is the *event's* own access. A node that skipped it would
    // hand a `View` subject a Critical event the specification restricts to administrators.
    let store = store_with(&[(SECRET, EventPriority::Critical, None)]);
    let got = read_events(
        &store,
        &[EventPath {
            node: None,
            endpoint: Some(1),
            cluster: Some(ON_OFF),
            event: Some(SECRET),
            is_urgent: None,
        }],
        &Holds(matter_kit::dm::access::Privilege::View),
        &InteractionContext::default(),
    );
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].1,
        Some(Status::UnsupportedAccess),
        "a restricted event was served to a View subject"
    );
}

#[test]
fn a_fabric_sensitive_event_is_invisible_to_another_fabric() {
    // §7.14.4: "A read interaction SHALL NOT report fabric-sensitive event records that are
    // associated with a fabric different than the accessing fabric."
    let store = store_with(&[(STARTED, EventPriority::Info, Some(FabricIndex(2)))]);
    let ctx = InteractionContext::default().with_fabric(FabricIndex(1));
    let got = read_events(
        &store,
        &[wildcard()],
        &Holds(matter_kit::dm::access::Privilege::View),
        &ctx,
    );
    assert!(
        got.is_empty(),
        "another fabric's event was reported: {got:?}"
    );

    // …and visible to its own.
    let ctx = InteractionContext::default().with_fabric(FabricIndex(2));
    let mine = read_events(
        &store,
        &[wildcard()],
        &Holds(matter_kit::dm::access::Privilege::View),
        &ctx,
    );
    assert_eq!(mine.len(), 1, "a fabric could not see its own event");
}

#[test]
fn a_node_with_no_event_source_reports_nothing_rather_than_failing() {
    // `with_events` is optional, and a node that does not serve events must still answer a read
    // that asks for them — §8.4.3.3 step 5 makes an empty `EventRequests` an empty answer.
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = Holds(matter_kit::dm::access::Privilege::View);
    let server = Server::new(node(), &access, &Fake, 64);
    let mut cursor = matter_kit::im::ReadCursor::START;
    let (bytes, _) = server
        .serve_chunk_with_events(
            core::iter::empty(),
            [wildcard()].iter().copied().map(Ok),
            &InteractionContext::default(),
            None,
            &mut cursor,
            &mut scratch,
            &mut buf,
        )
        .expect("a node without an event log still answers");
    ReportData::decode(bytes).expect("a well-formed report");
}

#[test]
fn an_event_filter_suppresses_everything_below_its_minimum() {
    // §8.4.3.3 step 6.a.i: a record whose number is *less than* `EventMin` is not reported.
    // This is how a client that already holds the first half of the log asks for the rest,
    // and without it every reconnection re-reads the whole ring.
    use matter_kit::im::EventFilter;

    let store = store_with(&[
        (STARTED, EventPriority::Info, None),
        (STARTED, EventPriority::Info, None),
        (STARTED, EventPriority::Info, None),
    ]);
    let all = read_events(
        &store,
        &[wildcard()],
        &Holds(matter_kit::dm::access::Privilege::View),
        &InteractionContext::default(),
    );
    assert_eq!(all.len(), 3);
    let second = all[1].2.expect("a number");

    // Encode `EventFilters` the way a `ReadRequest` carries them.
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, matter_kit::tlv::ContainerKind::Structure);
    w.start_array(Tag::Context(2)).expect("array");
    EventFilter {
        node: None,
        event_min: second,
    }
    .encode(&mut w)
    .expect("entry");
    w.end_container().expect("end");
    let encoded = w.finish().expect("finish").to_vec();

    let filtered = read_events(
        &store,
        &[wildcard()],
        &Holds(matter_kit::dm::access::Privilege::View),
        &InteractionContext::default().with_event_filters(&encoded),
    );
    assert_eq!(
        filtered.len(),
        2,
        "the filter did not exclude records below its minimum: {filtered:?}"
    );
    assert!(
        filtered.iter().all(|f| f.2.is_some_and(|n| n >= second)),
        "a record below EventMin was reported"
    );
}

#[test]
fn the_second_event_in_a_report_carries_a_delta_timestamp() {
    // §10.6.9.1: `DeltaSystemTimestamp` is "the time delta from the previous EventDataIB". The
    // absolute form is always legal, so this is an optimisation — but it is the one the
    // specification provides for a reason: a system timestamp is milliseconds since boot and
    // grows without bound, while the gap between two records in one report is usually one or
    // two octets.
    //
    // `Timestamp::delta_from` existed, was tested, and had **no callers** — the encoder always
    // wrote the absolute form while `DATA_MODEL.md` said it chose deltas.
    let store = store_at(&[
        (STARTED, EventPriority::Info, None, 1_000),
        (STARTED, EventPriority::Info, None, 1_250),
    ]);
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = Holds(matter_kit::dm::access::Privilege::View);
    let server = Server::new(node(), &access, &Fake, 64).with_events(&store);
    let mut cursor = matter_kit::im::ReadCursor::START;
    let (bytes, _) = server
        .serve_chunk_with_events(
            core::iter::empty(),
            [wildcard()].iter().copied().map(Ok),
            &InteractionContext::default(),
            None,
            &mut cursor,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let report = ReportData::decode(bytes).expect("decode");
    let stamps: Vec<matter_kit::im::EventTimestamp> = report
        .event_reports()
        .expect("reports")
        .expect("present")
        .map(|item| match item.expect("decode each") {
            EventReport::Data(d) => d.timestamp,
            EventReport::Status(_) => panic!("expected data"),
        })
        .collect();
    assert_eq!(stamps.len(), 2);
    assert_eq!(
        stamps[0],
        matter_kit::im::EventTimestamp::System(1_000),
        "the first record has nothing to be a delta from"
    );
    assert_eq!(
        stamps[1],
        matter_kit::im::EventTimestamp::DeltaSystem(250),
        "the second record did not use the delta form"
    );
}

/// A subscription's event bookmark moves, so an event is delivered once.
///
/// §8.5.3.4: the next report resumes after the last event delivered. The bookmark used to be a
/// number the *device* passed to `Subscription::reported`, and both devices in this repository
/// passed `0` — so it never moved, and every report re-sent the subscriber's whole event
/// history from the beginning. A subscriber waiting for a change it had just made was handed
/// the first event of the node's life instead: a correct report of the wrong thing, with
/// nothing anywhere recording an error.
///
/// So this drives two real reports over one subscription and asks what the second one carries.
#[test]
fn a_second_report_does_not_resend_the_first_reports_events() {
    use matter_kit::im::subscription::{NewSubscription, ReportReason, SubscriptionTable};
    use matter_kit::platform::Instant;

    let mut store = store_with(&[(STARTED, EventPriority::Info, None)]);
    use matter_kit::{Config, DefaultConfig};
    type Table = SubscriptionTable<
        DefaultConfig,
        { DefaultConfig::SUBSCRIPTIONS },
        { DefaultConfig::SUB_PATHS },
    >;
    let mut table = Table::new();
    let events = [wildcard()];
    let id = table
        .subscribe(
            &NewSubscription {
                session: Some(matter_kit::msg::SessionId(1)),
                fabric_index: Some(FabricIndex(1)),
                peer_node_id: None,
                fabric_filtered: false,
                keep_subscriptions: true,
                min_interval_s: 0,
                max_interval_s: 60,
                paths: &[],
                event_paths: &events,
                min_event_number: 0,
            },
            Instant::from_micros(0),
        )
        .expect("subscribe");

    let access = Holds(matter_kit::dm::access::Privilege::View);
    let ctx = InteractionContext::default();
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];

    let mut report = |table: &mut Table, store: &Store, at: u64| -> Vec<u64> {
        let server = Server::new(node(), &access, &Fake, 64).with_events(store);
        let subscription = table.find_mut(id).expect("subscription");
        let (bytes, outcome) = server
            .report_chunk(
                subscription,
                ReportReason::Data,
                &ctx,
                &mut scratch,
                &mut buf,
            )
            .expect("report");
        assert!(!outcome.truncated, "the fixture fits in one message");
        let decoded = ReportData::decode(bytes).expect("decode");
        let numbers = match decoded.event_reports().expect("reports") {
            Some(iter) => iter
                .map(|item| match item.expect("decode each") {
                    EventReport::Data(data) => data.number,
                    EventReport::Status(_) => panic!("expected data"),
                })
                .collect(),
            None => Vec::new(),
        };
        table
            .find_mut(id)
            .expect("subscription")
            .reported(Instant::from_micros(at));
        numbers
    };

    // The priming report carries what is there.
    let first = report(&mut table, &store, 1);
    assert_eq!(first, vec![0], "the priming report carries the one record");

    // One more event, and only that one comes back.
    store
        .record(&NewEvent {
            endpoint: 1,
            cluster: ON_OFF,
            event: STARTED,
            priority: EventPriority::Info,
            timestamp: Timestamp::System(2_000),
            fabric_index: None,
            data: EMPTY_DATA,
        })
        .expect("record");
    table.note_event(1, ON_OFF, STARTED);
    let second = report(&mut table, &store, 2);
    assert_eq!(
        second,
        vec![1],
        "the second report re-sent the first report's events"
    );

    // And a third with nothing new carries nothing at all.
    let third = report(&mut table, &store, 3);
    assert!(third.is_empty(), "a quiet report still carried events");
}
