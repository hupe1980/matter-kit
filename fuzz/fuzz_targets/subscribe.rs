//! Subscriptions against arbitrary `SubscribeRequest` bytes and arbitrary change sequences.
//!
//! A subscription is the one interaction where the *publisher* decides when to speak, and it
//! holds state for the life of the subscription — so the failure modes are different from
//! every other fuzz target here. They are timing and accounting, not parsing.
//!
//! Five properties:
//!
//! 1. **Nothing panics**, on any request and any sequence of changes.
//! 2. **§8.5.3.2's constraint holds**: `MinIntervalFloor ≤ MaxInterval ≤ MAX(limit, ceiling)`,
//!    for every pair of bounds a subscriber can ask for — including the contradictory ones.
//! 3. **No report before the minimum interval.** The rule that stops a flapping sensor
//!    flooding a network, and the one an arithmetic slip silently removes.
//! 4. **A report by the maximum interval, always.** A subscriber terminates the subscription
//!    if one does not arrive, so a missed deadline is a dropped subscription.
//! 5. **The table never exceeds its capacity, and an id is never zero.**

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::im::subscription::{
    NewSubscription, ReportReason, SubscribeError, SubscriptionPolicy, SubscriptionTable,
};
use matter_kit::im::{AttributePath, SubscribeRequest};
use matter_kit::msg::{FabricIndex, SessionId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::{Config, DefaultConfig};

type Table =
    SubscriptionTable<DefaultConfig, { DefaultConfig::SUBSCRIPTIONS }, { DefaultConfig::SUB_PATHS }>;

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

fuzz_target!(|data: &[u8]| {
    let policy = SubscriptionPolicy {
        max_interval_limit_s: 3600,
        preferred_max_interval_s: None,
    };

    // Property 2, swept over every pair the two leading octets can name — scaled so the
    // interesting boundaries (a ceiling below the floor, a ceiling above the hour) are all
    // reachable from two bytes.
    let floor = u16::from(data.first().copied().unwrap_or(0)).saturating_mul(37);
    let ceiling = u16::from(data.get(1).copied().unwrap_or(0)).saturating_mul(41);
    let negotiated = policy.max_interval(floor, ceiling);
    let upper = policy.max_interval_limit_s.max(ceiling);
    assert!(
        negotiated <= upper,
        "MaxInterval {negotiated} above MAX(limit, ceiling) {upper}"
    );
    assert!(
        negotiated >= floor.min(upper),
        "MaxInterval {negotiated} below MinIntervalFloor {floor}"
    );

    // A real `SubscribeRequest` off the wire, when the input happens to be one.
    let mut table = Table::new();
    if let Ok(request) = SubscribeRequest::decode(data) {
        let mut paths = Vec::<AttributePath>::new();
        if let Ok(Some(iter)) = request.attribute_paths() {
            for path in iter {
                let Ok(path) = path else { break };
                if paths.len() >= DefaultConfig::SUB_PATHS {
                    break;
                }
                paths.push(path);
            }
        }
        let max_interval =
            policy.max_interval(request.min_interval_floor_s, request.max_interval_ceiling_s);
        let outcome = table.subscribe(
            &NewSubscription {
                session: Some(SessionId(1)),
                fabric_index: Some(FabricIndex(1)),
                fabric_filtered: request.fabric_filtered,
                keep_subscriptions: request.keep_subscriptions,
                min_interval_s: request.min_interval_floor_s,
                max_interval_s: max_interval,
                paths: &paths,
                event_paths: &[],
                min_event_number: 0,
                // §8.5.1's persisted subscription is keyed on the peer, not the session: a
                // session dies at every reboot and the subscription outlives it.
                peer_node_id: Some(matter_kit::msg::NodeId(0x0000_0000_0000_0001)),
            },
            at(0),
        );
        match outcome {
            Ok(id) => assert_ne!(id, 0, "zero is reserved"),
            Err(SubscribeError::NoPaths | SubscribeError::TooManyPaths | SubscribeError::Full) => {}
        }
    }

    // A sequence of subscriptions and changes driven by the remaining bytes.
    for (index, chunk) in data.chunks(4).enumerate().take(64) {
        let session = SessionId(u16::from(chunk.first().copied().unwrap_or(0)));
        let endpoint = u16::from(chunk.get(1).copied().unwrap_or(0));
        let cluster = u32::from(chunk.get(2).copied().unwrap_or(0));
        let attribute = u32::from(chunk.get(3).copied().unwrap_or(0));
        let path = AttributePath::attribute(endpoint, cluster, attribute);

        if index % 3 == 0 {
            let paths = [path];
            let _ = table.subscribe(
                &NewSubscription {
                    session: Some(session),
                    fabric_index: Some(FabricIndex(1)),
                    fabric_filtered: false,
                    keep_subscriptions: index % 6 != 0,
                    min_interval_s: floor,
                    max_interval_s: policy.max_interval(floor, ceiling),
                    paths: &paths,
                    event_paths: &[],
                    min_event_number: 0,
                    peer_node_id: Some(matter_kit::msg::NodeId(0x0000_0000_0000_0001)),
                },
                at(0),
            );
        } else {
            table.note_change(&path);
        }

        // Property 5.
        assert!(table.len() <= table.capacity());
        for subscription in table.iter() {
            assert_ne!(subscription.id, 0);
        }
    }

    // Properties 3 and 4, over the whole table at a sweep of instants.
    for second in [0u64, 1, 5, 59, 60, 3599, 3600, 3601, 100_000] {
        let now = at(second);
        for subscription in table.iter() {
            match subscription.due(now) {
                Some(ReportReason::Data) => {
                    assert!(
                        now >= subscription.earliest_report()
                            || now >= subscription.latest_report(),
                        "a data report before the minimum interval"
                    );
                }
                Some(ReportReason::KeepAlive) => {
                    assert!(
                        now >= subscription.latest_report(),
                        "a keep-alive before the maximum interval"
                    );
                }
                None => {
                    assert!(
                        now < subscription.latest_report(),
                        "no report due past the maximum interval"
                    );
                }
            }
            // The deadline a sleepy device sleeps until is never past the keep-alive.
            assert!(subscription.next_deadline() <= subscription.latest_report());
        }
    }
});
