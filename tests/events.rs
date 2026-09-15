//! The event store and event reporting, against Core §7.14 and §10.6.9.
//!
//! Events are the part of the data model that carries a *guarantee*: §7.14 opens by saying
//! attributes provide "no guarantees that every attribute change will be conveyed to
//! observers", while events "permit capturing every single edge … This is critical for safety
//! and security applications that rely upon such guarantees for correct behavior."
//!
//! Three rules make that guarantee hold, and each has a cheaper implementation that silently
//! does not:
//!
//! 1. **The event number is monotonic across restarts** (§7.14.1.1) — a client uses it to tell
//!    "nothing happened" from "I missed something".
//! 2. **Priority decides what survives** (§7.14.2) — a flood of `Debug` records must not push
//!    out a `Critical` one, which a single shared ring always lets it do.
//! 3. **A fabric-sensitive event is visible only to its fabric, and an unassociated one to
//!    everyone** (§7.14.4) — two rules in opposite directions.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use matter_kit::dm::EventPriority;
use matter_kit::dm::events::{
    EVENT_DATA_MAX, EventNumbers, EventStore, NUMBER_RESERVATION, NewEvent, RecordError, Timestamp,
};
use matter_kit::im::{EventPath, EventTimestamp};
use matter_kit::msg::FabricIndex;

/// A store with room for two of each priority, so the overwrite rule is reachable.
type Store = EventStore<2, 2, 2>;

fn numbers() -> EventNumbers {
    let mut numbers = EventNumbers::restore(0);
    let owed = numbers.reservation().expect("a fresh counter owes one");
    numbers.reserved(owed);
    numbers
}

fn store() -> Store {
    EventStore::new(numbers())
}

/// An empty TLV structure under context tag 7 — §10.6.9.3's encoding for an event with no
/// payload.
const EMPTY_DATA: &[u8] = &[0x35, 0x07, 0x18];

fn event(cluster: u32, id: u32, priority: EventPriority) -> NewEvent<'static> {
    NewEvent {
        endpoint: 1,
        cluster,
        event: id,
        priority,
        timestamp: Timestamp::System(1000),
        fabric_index: None,
        data: EMPTY_DATA,
    }
}

// --- The number --------------------------------------------------------------------------------

#[test]
fn event_numbers_are_reserved_before_they_are_handed_out() {
    // §7.14.1.1's own strategy, step by step: "Read the counter value at start-up. Before
    // processing any message, write counter + N to storage … Process messages normally until
    // the counter has a value one less than the counter in storage."
    assert_eq!(NUMBER_RESERVATION, 1000);

    let mut numbers = EventNumbers::restore(0);
    assert_eq!(
        numbers.next(),
        None,
        "a number cannot be handed out before it is reserved"
    );
    assert_eq!(numbers.reservation(), Some(1000));

    numbers.reserved(1000);
    for expected in 0..1000u64 {
        assert_eq!(numbers.next(), Some(expected));
    }
    assert_eq!(numbers.next(), None, "the reservation is spent");
    assert_eq!(numbers.reservation(), Some(2000));
}

#[test]
fn a_restart_may_skip_forward_but_never_back() {
    // "When a node restarts, the event number MAY increase by a larger step than 1" — the
    // price of not writing to flash on every event. What must never happen is the counter
    // going *backwards*: a record with a reused number tells a client that nothing happened
    // when something did.
    let mut before = EventNumbers::restore(0);
    before.reserved(1000);
    for _ in 0..5 {
        before.next().expect("number");
    }
    assert_eq!(before.peek(), 5);

    // The device crashes. On reboot it resumes from the last *persisted* value, which is the
    // reservation — not the five it actually used.
    let mut after = EventNumbers::restore(1000);
    after.reserved(2000);
    let next = after.next().expect("number");
    assert_eq!(next, 1000);
    assert!(next > 5, "forward, by a larger step than 1");
}

#[test]
fn recording_refuses_rather_than_reusing_a_number() {
    // The store cannot invent a number it has not reserved. Refusing is the only safe answer:
    // an event assigned an unreserved number survives a crash as a duplicate.
    let mut store = EventStore::<2, 2, 2>::new(EventNumbers::restore(0));
    let outcome = store.record(&event(0x0028, 0x00, EventPriority::Critical));
    assert_eq!(outcome, Err(RecordError::NeedsReservation(1000)));
    assert!(store.is_empty());

    store.reserved(1000);
    assert_eq!(
        store.record(&event(0x0028, 0x00, EventPriority::Critical)),
        Ok(0)
    );
}

#[test]
fn a_payload_longer_than_the_buffer_is_refused_whole() {
    let mut store = store();
    let long = vec![0u8; EVENT_DATA_MAX + 1];
    let outcome = store.record(&NewEvent {
        data: &long,
        ..event(0x0028, 0x00, EventPriority::Info)
    });
    assert_eq!(outcome, Err(RecordError::DataTooLong));
    assert!(store.is_empty(), "and nothing half-stored");
}

// --- The buffering -----------------------------------------------------------------------------

#[test]
fn a_flood_of_debug_records_cannot_push_out_a_critical_one() {
    // §7.14.2: "Event records SHALL be buffered on the Node, with priority given to events of
    // a higher priority level over a lower priority level."
    //
    // That is a *guarantee*, and a single shared ring cannot make it: a device logging at
    // Debug would eventually lose the Critical record that a safety application depends on.
    // Separate rings per priority is what makes it structural.
    let mut store = store();
    store
        .record(&event(0x0028, 0x00, EventPriority::Critical))
        .expect("critical");

    for _ in 0..100 {
        store
            .record(&event(0x0028, 0x02, EventPriority::Debug))
            .expect("debug");
    }

    let path = EventPath::default();
    let numbers: Vec<u64> = store.matching(&path, None, 0).map(|r| r.number).collect();
    assert!(
        numbers.contains(&0),
        "the Critical record survived a hundred Debug ones"
    );
    // And the Debug ring kept only its two newest.
    let debug = store.buffer(EventPriority::Debug);
    assert_eq!(debug.records().len(), 2);
    // A hundred pushed, two kept: the first two fill the ring and the other ninety-eight
    // each displace one.
    assert_eq!(debug.dropped(), 98);
}

#[test]
fn a_full_buffer_drops_the_oldest_rather_than_refusing_the_newest() {
    // §7.14.2: "Within a priority level, newer event records SHALL overwrite older event
    // records." Refusing the new one would lose the most recent edge — which is the one a
    // client most needs.
    let mut store = store();
    for _ in 0..3 {
        store
            .record(&event(0x0028, 0x01, EventPriority::Info))
            .expect("info");
    }
    let buffer = store.buffer(EventPriority::Info);
    assert_eq!(buffer.records().len(), 2);
    assert_eq!(
        buffer
            .records()
            .iter()
            .map(|r| r.number)
            .collect::<Vec<_>>(),
        vec![1, 2],
        "the oldest went, the newest stayed"
    );
    assert_eq!(buffer.dropped(), 1);
}

#[test]
fn records_come_back_in_event_number_order_across_priorities() {
    // §8.5: "Each Report containing events SHALL deliver queued events without reordering the
    // queue." Across priorities that means by number, because the number is the order things
    // actually happened in — reporting every Critical record before every Info one would hand
    // a client a log that contradicts itself.
    let mut store = store();
    store
        .record(&event(0x0028, 0x01, EventPriority::Info))
        .expect("info");
    store
        .record(&event(0x0028, 0x00, EventPriority::Critical))
        .expect("critical");
    store
        .record(&event(0x0028, 0x02, EventPriority::Debug))
        .expect("debug");

    let path = EventPath::default();
    let numbers: Vec<u64> = store.matching(&path, None, 0).map(|r| r.number).collect();
    assert_eq!(numbers, vec![0, 1, 2]);
}

#[test]
fn a_wildcard_path_matches_and_a_specific_one_filters() {
    // §10.6.8: in a request, "Omission of the Endpoint, Cluster and Event tags" is a wildcard.
    let mut store = store();
    store
        .record(&event(0x0028, 0x00, EventPriority::Critical))
        .expect("record");
    store
        .record(&event(0x0006, 0x00, EventPriority::Critical))
        .expect("record");

    let all = EventPath::default();
    assert_eq!(store.matching(&all, None, 0).count(), 2);

    let basic = EventPath {
        cluster: Some(0x0028),
        ..EventPath::default()
    };
    assert_eq!(store.matching(&basic, None, 0).count(), 1);

    let specific = EventPath::event(1, 0x0028, 0x00);
    assert_eq!(store.matching(&specific, None, 0).count(), 1);
    let elsewhere = EventPath::event(9, 0x0028, 0x00);
    assert_eq!(store.matching(&elsewhere, None, 0).count(), 0);

    // §7.14.3: "Interactions that report event records MAY be filtered by event ID and/or
    // event number."
    assert_eq!(store.matching(&all, None, 1).count(), 1);
    assert_eq!(store.matching(&all, None, 2).count(), 0);
}

// --- Fabric sensitivity -------------------------------------------------------------------------

#[test]
fn an_unassociated_event_is_visible_to_everyone_and_a_sensitive_one_is_not() {
    // §7.14.4's two sentences pull in opposite directions:
    //
    //   "A read interaction SHALL NOT filter event records, based on fabric, for event records
    //    that are not associated with a fabric."
    //   "A read interaction SHALL NOT report fabric-sensitive event records that are associated
    //    with a fabric different than the accessing fabric."
    //
    // Treating the first like the second would hide a node's `StartUp` from every client.
    let mut store = store();
    store
        .record(&event(0x0028, 0x00, EventPriority::Critical))
        .expect("unassociated");
    store
        .record(&NewEvent {
            fabric_index: Some(FabricIndex(1)),
            ..event(0x0028, 0x02, EventPriority::Info)
        })
        .expect("fabric 1");

    let all = EventPath::default();
    // A client on fabric 1 sees both.
    assert_eq!(store.matching(&all, Some(FabricIndex(1)), 0).count(), 2);
    // A client on fabric 2 sees only the unassociated one.
    let visible: Vec<u64> = store
        .matching(&all, Some(FabricIndex(2)), 0)
        .map(|r| r.number)
        .collect();
    assert_eq!(visible, vec![0]);
    // …and so does a session with no fabric at all.
    let visible: Vec<u64> = store.matching(&all, None, 0).map(|r| r.number).collect();
    assert_eq!(visible, vec![0]);
}

// --- The timestamp ------------------------------------------------------------------------------

#[test]
fn the_timestamp_choice_is_one_of_four_and_a_delta_needs_a_comparable_base() {
    // §10.6.9 wraps tags 3 to 6 in a `one-of`, and both delta forms say "When this tag is
    // present, all other timestamp tags SHALL be omitted."
    assert_eq!(EventTimestamp::Epoch(5).tag(), 3);
    assert_eq!(EventTimestamp::System(5).tag(), 4);
    assert_eq!(EventTimestamp::DeltaEpoch(5).tag(), 5);
    assert_eq!(EventTimestamp::DeltaSystem(5).tag(), 6);
    assert!(!EventTimestamp::Epoch(5).is_delta());
    assert!(EventTimestamp::DeltaSystem(5).is_delta());

    // A delta is only meaningful against the same kind of clock, moving forward.
    let now = Timestamp::System(5000);
    let before = Timestamp::System(4990);
    assert_eq!(
        now.delta_from(before),
        Some(EventTimestamp::DeltaSystem(10))
    );
    // Across kinds there is no delta: encoding one would produce a number with no meaning.
    assert_eq!(now.delta_from(Timestamp::Epoch(4990)), None);
    // And a timestamp that went backwards has no delta either.
    assert_eq!(now.delta_from(Timestamp::System(5001)), None);

    assert_eq!(Timestamp::Epoch(7).absolute(), EventTimestamp::Epoch(7));
    assert_eq!(Timestamp::System(7).millis(), 7);
}

// --- The wire ----------------------------------------------------------------------------------

mod wire {
    use super::*;
    use matter_kit::im::{EventData, EventReport, EventStatus, Status, StatusIb};
    use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

    fn round_trip(data: &EventData<'_>) -> Vec<u8> {
        let mut buf = [0u8; 512];
        let mut w = TlvWriter::new(&mut buf);
        data.encode(&mut w, Tag::Anonymous).expect("encode");
        w.finish().expect("finish").to_vec()
    }

    #[test]
    fn an_event_data_block_round_trips() {
        // §10.6.9's own example: `Path = [[ Endpoint = 10, Cluster = Disco Ball, EventID =
        // Started ]], EventNumber = 1001, Priority = INFO, EpochTimestamp = 102340234293,
        // Data = { }`.
        let data = EventData {
            path: EventPath::event(10, 0x0006, 0x0000),
            number: 1001,
            priority: 1,
            timestamp: EventTimestamp::Epoch(102_340_234_293),
            data: EMPTY_DATA,
        };
        let bytes = round_trip(&data);

        let mut reader = TlvReader::new(&bytes);
        reader.next_element().expect("read").expect("struct");
        let decoded = EventData::decode(&mut reader).expect("decode");
        assert_eq!(decoded.path, data.path);
        assert_eq!(decoded.number, 1001);
        assert_eq!(decoded.priority, 1);
        assert_eq!(decoded.timestamp, EventTimestamp::Epoch(102_340_234_293));
        // §10.6.9.3: an event with no payload is "encoded as a struct with no member
        // elements", not an absent field.
        assert_eq!(decoded.data, EMPTY_DATA);
    }

    #[test]
    fn every_timestamp_form_round_trips_and_only_one_may_be_present() {
        for timestamp in [
            EventTimestamp::Epoch(1),
            EventTimestamp::System(2),
            EventTimestamp::DeltaEpoch(3),
            EventTimestamp::DeltaSystem(4),
        ] {
            let data = EventData {
                path: EventPath::event(1, 0x0028, 0x00),
                number: 7,
                priority: 2,
                timestamp,
                data: EMPTY_DATA,
            };
            let bytes = round_trip(&data);
            let mut reader = TlvReader::new(&bytes);
            reader.next_element().expect("read").expect("struct");
            assert_eq!(
                EventData::decode(&mut reader).expect("decode").timestamp,
                timestamp
            );
        }

        // Two timestamp tags in one block is a violation of the `one-of`, and it decodes as a
        // duplicate rather than as "the last one wins" — the same §A.5.1 rule every other
        // decoder here follows.
        let mut buf = [0u8; 256];
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).expect("open");
        EventPath::event(1, 0x0028, 0x00)
            .encode(&mut w, Tag::Context(0))
            .expect("path");
        w.unsigned(Tag::Context(1), 7).expect("number");
        w.unsigned(Tag::Context(2), 2).expect("priority");
        w.unsigned(Tag::Context(3), 100).expect("epoch");
        w.unsigned(Tag::Context(4), 200).expect("system");
        w.raw_element(EMPTY_DATA).expect("data");
        w.end_container().expect("close");
        let bytes = w.finish().expect("finish").to_vec();

        let mut reader = TlvReader::new(&bytes);
        reader.next_element().expect("read").expect("struct");
        assert!(
            EventData::decode(&mut reader).is_err(),
            "two timestamp tags must not decode"
        );
    }

    #[test]
    fn an_event_report_is_a_choice_of_data_or_status() {
        // §10.6.10, the same shape as `AttributeReportIB`: one or the other, never both.
        let data = EventData {
            path: EventPath::event(1, 0x0028, 0x00),
            number: 1,
            priority: 3,
            timestamp: EventTimestamp::System(50),
            data: EMPTY_DATA,
        };
        let mut buf = [0u8; 512];
        let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Array);
        EventReport::Data(data).encode(&mut w).expect("encode");
        let bytes = w.finish().expect("finish").to_vec();

        let mut reader = TlvReader::new_in(&bytes, ContainerKind::Array);
        reader.next_element().expect("read").expect("struct");
        match EventReport::decode(&mut reader).expect("decode") {
            EventReport::Data(decoded) => assert_eq!(decoded.number, 1),
            EventReport::Status(_) => panic!("expected data"),
        }

        let status = EventReport::Status(EventStatus {
            path: EventPath::event(1, 0x0028, 0x00),
            status: StatusIb::new(Status::UnsupportedEvent),
        });
        let mut buf = [0u8; 512];
        let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Array);
        status.encode(&mut w).expect("encode");
        let bytes = w.finish().expect("finish").to_vec();
        let mut reader = TlvReader::new_in(&bytes, ContainerKind::Array);
        reader.next_element().expect("read").expect("struct");
        match EventReport::decode(&mut reader).expect("decode") {
            EventReport::Status(decoded) => {
                assert_eq!(decoded.status.status, Status::UnsupportedEvent);
            }
            EventReport::Data(_) => panic!("expected a status"),
        }
    }
}
