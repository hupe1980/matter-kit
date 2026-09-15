//! Restoring subscriptions from arbitrary stored bytes (Core §8.5).
//!
//! This parser reads a device's own storage rather than the network, which sounds safer than
//! it is: on most of the hardware this crate targets the key-value store is an external flash
//! part on a bus anyone with the case open can reach, and a device that reboots into a
//! panicking restore never comes back at all.
//!
//! Three properties:
//!
//! 1. **Nothing panics**, whatever the stored bytes are, and no partial restore survives a
//!    failure — a damaged store leaves the table empty rather than half-populated.
//! 2. **Restoring is a fixed point.** Whatever restores can be saved and restored again to the
//!    same thing, which is what makes the format safe to write back after an edit.
//! 3. **A restored subscription is inert and owes a full report.** It has no session, so
//!    nothing is due; and it is re-primed, because the device has no record of what changed
//!    while it was off.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::Config;
use matter_kit::config::DefaultConfig;
use matter_kit::im::persist;
use matter_kit::im::subscription::SubscriptionTable;
use matter_kit::platform::Instant;
use matter_kit::tlv::{Tag, TlvWriter};

type Table = SubscriptionTable<
    DefaultConfig,
    { DefaultConfig::SUBSCRIPTIONS },
    { DefaultConfig::SUB_PATHS },
>;

fuzz_target!(|data: &[u8]| {
    let now = Instant::from_micros(1_000_000);
    let mut table = Table::new();

    // Property 1.
    let Ok(restored) = persist::restore(&mut table, data, now) else {
        assert!(
            table.is_empty(),
            "a failed restore left subscriptions behind"
        );
        return;
    };
    assert_eq!(restored, table.len());

    // Property 3.
    assert!(
        table.due(now).next().is_none(),
        "a restored subscription has no session and cannot be reported on"
    );
    assert_eq!(table.next_deadline(), None);
    for subscription in table.iter() {
        assert!(subscription.session.is_none());
        assert!(
            subscription.fabric_index.is_some(),
            "a persisted record has a fabric"
        );
        assert!(subscription.peer_node_id.is_some(), "…and a subscriber");
        assert!(
            !subscription.paths.is_empty() || !subscription.event_paths.is_empty(),
            "§8.5.2.2: at least one path"
        );
        assert!(
            subscription.dirty.is_dirty(),
            "a restored subscription owes a full priming report"
        );
    }

    // Property 2.
    let mut buf = [0u8; 8192];
    let mut w = TlvWriter::new(&mut buf);
    let Ok(saved) = persist::save(&table, &mut w, Tag::Anonymous) else {
        return;
    };
    assert_eq!(saved, table.len());
    let Ok(bytes) = w.finish() else { return };

    let mut again = Table::new();
    let count = persist::restore(&mut again, bytes, now).expect("our own output must restore");
    assert_eq!(count, restored);
    for (first, second) in table.iter().zip(again.iter()) {
        assert_eq!(first.id, second.id);
        assert_eq!(first.fabric_index, second.fabric_index);
        assert_eq!(first.peer_node_id, second.peer_node_id);
        assert_eq!(first.fabric_filtered, second.fabric_filtered);
        assert_eq!(first.min_interval_s, second.min_interval_s);
        assert_eq!(first.max_interval_s, second.max_interval_s);
        assert_eq!(first.next_event_number, second.next_event_number);
        assert_eq!(first.paths, second.paths);
        assert_eq!(first.event_paths, second.event_paths);
    }
});
