//! Thermostat suggestions (Application Cluster §4.3.7, §4.3.8, §4.3.12) — new in 1.6.
//!
//! A suggestion is advice, not a command, and the whole of §4.3 is careful about the
//! difference: the thermostat has a schedule, an occupancy sensor and possibly a hold, and it is
//! allowed to decline. What it is *not* allowed to do is decline silently — §4.3.11.56's
//! `NotFollowingReason` is what stops an energy manager and a thermostat fighting invisibly.
//!
//! The rules worth pinning are the ones that make a suggestion bounded in time, because a
//! suggestion that outlived its window would be a thermostat obeying an instruction nobody
//! remembers giving.

#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::clusters::thermostat_suggestions::{
    EXPIRATION_MINUTES_MAX, EXPIRATION_MINUTES_MIN, PRESET_HANDLE_MAX, Suggestions,
    ThermostatSuggestionNotFollowingReasonBitmap,
};
use matter_kit::im::Status;

const HOME: &[u8] = b"home";
const AWAY: &[u8] = b"away";
const SLEEP: &[u8] = b"sleep";

/// The `Presets` attribute this thermostat actually has.
fn known(handle: &[u8]) -> bool {
    matches!(handle, b"home" | b"away" | b"sleep")
}

// --- §4.3.12.4: adding one -----------------------------------------------------------------

#[test]
fn every_check_has_its_own_status_and_they_run_in_order() {
    let mut table = Suggestions::<2>::new();

    // Step 1: "If the server does not have its time synchronized, the server SHALL return
    // INVALID_IN_STATE." Checked before anything else, because every other field is a UTC
    // timestamp and without a clock none of them means anything.
    assert_eq!(
        table.add(b"nonesuch", None, 30, None, known),
        Err(Status::InvalidInState),
        "the clock is checked before the preset"
    );

    // Step 2: a handle the Presets attribute does not have.
    assert_eq!(
        table.add(b"nonesuch", None, 30, Some(1_000), known),
        Err(Status::NotFound)
    );

    // Step 4: more than 24 hours out.
    assert_eq!(
        table.add(HOME, Some(1_000 + 86_401), 30, Some(1_000), known),
        Err(Status::InvalidCommand)
    );
    // Exactly 24 hours is still allowed — the bound is "greater than".
    assert!(
        table
            .add(HOME, Some(1_000 + 86_400), 30, Some(1_000), known)
            .is_ok()
    );

    // Step 3: the table is full.
    assert!(table.add(AWAY, None, 30, Some(1_000), known).is_ok());
    assert_eq!(
        table.add(SLEEP, None, 30, Some(1_000), known),
        Err(Status::ResourceExhausted)
    );
}

#[test]
fn the_duration_is_bounded_at_both_ends() {
    // §4.3.12.4's constraint on `ExpirationInMinutes` is "30 to 1440": at least half an hour, at
    // most a day. A suggestion shorter than the first is noise; one longer than the second is a
    // schedule, and §4.3 has one of those already.
    let mut table = Suggestions::<4>::new();
    assert_eq!(
        table.add(HOME, None, EXPIRATION_MINUTES_MIN - 1, Some(0), known),
        Err(Status::ConstraintError)
    );
    assert_eq!(
        table.add(HOME, None, EXPIRATION_MINUTES_MAX + 1, Some(0), known),
        Err(Status::ConstraintError)
    );
    assert!(
        table
            .add(HOME, None, EXPIRATION_MINUTES_MIN, Some(0), known)
            .is_ok()
    );
    assert!(
        table
            .add(HOME, None, EXPIRATION_MINUTES_MAX, Some(0), known)
            .is_ok()
    );
}

#[test]
fn an_over_long_preset_handle_is_refused() {
    // §4.3.10.29's constraint is "max 16".
    let mut table = Suggestions::<4>::new();
    let long = vec![b'x'; PRESET_HANDLE_MAX + 1];
    assert_eq!(
        table.add(&long, None, 30, Some(0), |_| true),
        Err(Status::ConstraintError)
    );
}

// --- §4.3.12.6: removing one ----------------------------------------------------------------

#[test]
fn removing_names_an_entry_or_says_not_found() {
    let mut table = Suggestions::<4>::new();
    let id = table.add(HOME, None, 30, Some(0), known).unwrap();
    assert!(table.remove(id).is_ok());
    assert_eq!(table.remove(id), Err(Status::NotFound));
    assert!(table.entries().is_empty());
}

// --- §4.3.7: re-evaluation --------------------------------------------------------------------

#[test]
fn a_clock_that_stops_takes_the_current_suggestion_with_it() {
    // §4.3.7 step 1: "If the server does not have its time synchronized, it SHALL set the
    // CurrentThermostatSuggestion attribute to null." Not "keep the last one" — a thermostat
    // that held a suggestion through a clock outage would be following a window it could no
    // longer tell it had left.
    let mut table = Suggestions::<4>::new();
    let id = table.add(HOME, Some(0), 60, Some(0), known).unwrap();
    assert_eq!(table.evaluate(Some(10)).current, Some(id));
    assert_eq!(table.evaluate(None).current, None);
    // And the entry is still there: losing the clock does not lose the suggestion, only the
    // ability to act on it.
    assert_eq!(table.entries().len(), 1);
    assert_eq!(table.evaluate(Some(20)).current, Some(id));
}

#[test]
fn a_suggestion_that_has_not_started_is_not_current() {
    // §4.3.7 step 2c: only entries "with a value in the EffectiveTime field that is less than or
    // equal to the current timestamp". §4.3.11.54 keeps future entries deliberately — they are
    // what a pre-cool decision is made from — but they are not *current*.
    let mut table = Suggestions::<4>::new();
    let id = table.add(HOME, Some(1_000), 60, Some(0), known).unwrap();
    let evaluation = table.evaluate(Some(500));
    assert_eq!(evaluation.current, None);
    assert_eq!(
        evaluation.wake_at,
        Some(1_000),
        "and a timer for when it starts"
    );
    assert_eq!(table.entries().len(), 1, "the entry survives");
    assert_eq!(table.evaluate(Some(1_000)).current, Some(id));
}

#[test]
fn an_expired_suggestion_is_removed_rather_than_ignored() {
    // §4.3.7 step 2b removes it. Leaving it would grow the table until
    // `MaxThermostatSuggestions` was reached by entries that could never apply again.
    let mut table = Suggestions::<4>::new();
    table.add(HOME, Some(0), 30, Some(0), known).unwrap();
    table.add(AWAY, Some(0), 60, Some(0), known).unwrap();
    table.evaluate(Some(1_800));
    assert_eq!(table.entries().len(), 1, "the 30-minute one is gone");
    assert_eq!(table.entries()[0].preset_handle.as_slice(), AWAY);
}

#[test]
fn the_timer_is_the_earliest_boundary_still_ahead() {
    // §4.3.7 step 2e. A thermostat that woke later would keep following a suggestion past its
    // expiry; one that woke earlier would just wake for nothing.
    let mut table = Suggestions::<8>::new();
    table.add(HOME, Some(0), 30, Some(0), known).unwrap(); // 0 .. 1800
    table.add(AWAY, Some(3_600), 30, Some(0), known).unwrap(); // 3600 .. 5400
    assert_eq!(table.evaluate(Some(0)).wake_at, Some(1_800));
    assert_eq!(table.evaluate(Some(1_800)).wake_at, Some(3_600));
    assert_eq!(table.evaluate(Some(3_600)).wake_at, Some(5_400));
    assert_eq!(
        table.evaluate(Some(5_400)).wake_at,
        None,
        "nothing left to wake for"
    );
    assert!(table.entries().is_empty());
}

// --- §4.3.8: choosing between them --------------------------------------------------------

#[test]
fn the_most_suggested_preset_wins_and_then_the_newest() {
    // §4.3.8 step 1: "the server SHOULD choose the entry with the most recent EffectiveTime from
    // the entries with the highest count of the same PresetHandle." Three clients asking for
    // `away` outvote one asking for `home`.
    let mut table = Suggestions::<8>::new();
    table.add(HOME, Some(0), 60, Some(0), known).unwrap();
    table.add(AWAY, Some(0), 60, Some(0), known).unwrap();
    table.add(AWAY, Some(10), 60, Some(0), known).unwrap();
    let newest_away = table.add(AWAY, Some(20), 60, Some(0), known).unwrap();

    let evaluation = table.evaluate(Some(30));
    assert_eq!(evaluation.current, Some(newest_away));
    assert!(
        evaluation.not_following.is_empty(),
        "a decision was reached, so nothing is not-followed"
    );
    assert_eq!(
        table
            .get(evaluation.current.unwrap())
            .unwrap()
            .preset_handle
            .as_slice(),
        AWAY
    );
}

#[test]
fn a_single_suggestion_is_followed() {
    let mut table = Suggestions::<4>::new();
    let id = table.add(SLEEP, None, 30, Some(100), known).unwrap();
    let evaluation = table.evaluate(Some(100));
    assert_eq!(evaluation.current, Some(id));
    assert!(evaluation.not_following.is_empty());
}

#[test]
fn nothing_effective_means_no_reason_either() {
    // §4.3.11.56: the reason says why a suggestion is not being followed. With no suggestion in
    // its window there is nothing to follow, so setting a bit would be reporting a conflict that
    // does not exist.
    let mut table = Suggestions::<4>::new();
    let evaluation = table.evaluate(Some(0));
    assert_eq!(evaluation.current, None);
    assert_eq!(
        evaluation.not_following,
        ThermostatSuggestionNotFollowingReasonBitmap::empty()
    );
}

#[test]
fn the_conflict_bit_exists_for_the_case_the_table_cannot_resolve() {
    // §4.3.8 step 7: when nothing lets the server choose, "the thermostat SHALL NOT follow any
    // of the suggestions, set the CurrentThermostatSuggestion attribute to null and set the
    // ThermostatSuggestionNotFollowingReason attribute to ConflictingSuggestions."
    //
    // This table always reaches a decision — §4.3.8's steps 1 and 4 are total, because the
    // identifier breaks the last tie — so the bit is here for a Thermostat that applies step 5's
    // "additional decision making policies" and comes up empty.
    assert_eq!(
        ThermostatSuggestionNotFollowingReasonBitmap::CONFLICTING_SUGGESTIONS.bits(),
        1 << 7
    );
    let mut table = Suggestions::<4>::new();
    table.add(HOME, Some(0), 60, Some(0), known).unwrap();
    table.add(AWAY, Some(0), 60, Some(0), known).unwrap();
    // Two equally-weighted suggestions: the identifier decides, and a decision is a decision.
    let evaluation = table.evaluate(Some(10));
    assert!(evaluation.current.is_some());
    assert!(evaluation.not_following.is_empty());
}

#[test]
fn the_choice_does_not_depend_on_insertion_order() {
    // §4.3.11.54 calls it "an unordered set", so two thermostats given the same suggestions in
    // different orders must reach the same answer — otherwise a controller reconciling two
    // devices sees them disagree for no reason it can see.
    let by_handle = |table: &mut Suggestions<8>, now: u32| {
        let id = table.evaluate(Some(now)).current.expect("a choice");
        table.get(id).unwrap().preset_handle.clone()
    };

    let mut forwards = Suggestions::<8>::new();
    forwards.add(HOME, Some(0), 60, Some(0), known).unwrap();
    forwards.add(AWAY, Some(10), 60, Some(0), known).unwrap();
    forwards.add(AWAY, Some(20), 60, Some(0), known).unwrap();

    let mut backwards = Suggestions::<8>::new();
    backwards.add(AWAY, Some(20), 60, Some(0), known).unwrap();
    backwards.add(AWAY, Some(10), 60, Some(0), known).unwrap();
    backwards.add(HOME, Some(0), 60, Some(0), known).unwrap();

    assert_eq!(by_handle(&mut forwards, 30), by_handle(&mut backwards, 30));
}

#[test]
fn a_future_suggestion_keeps_its_whole_window() {
    // §4.3.12.4 step 5a iii measures the duration from the *effective* time. A pre-cool
    // suggestion for an hour's time that expired on schedule from *now* would be over before it
    // began.
    let mut table = Suggestions::<4>::new();
    let id = table.add(HOME, Some(3_600), 30, Some(0), known).unwrap();
    let entry = table.get(id).unwrap();
    assert_eq!(entry.effective_time, 3_600);
    assert_eq!(entry.expiration_time, 3_600 + 1_800);
    assert_eq!(table.evaluate(Some(3_600)).current, Some(id));
    assert_eq!(table.evaluate(Some(5_399)).current, Some(id));
    assert_eq!(
        table.evaluate(Some(5_400)).current,
        None,
        "and then it is over"
    );
}
