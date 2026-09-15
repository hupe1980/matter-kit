//! Thermostat suggestions: §4.3.7's `TSUG` feature of the Thermostat cluster (App §4.3).
//!
//! New in 1.6, and the shape of a negotiation rather than a command. An energy manager, a
//! tariff, a home-automation app — any of them may *suggest* a preset, with a window in which
//! the suggestion applies. The thermostat decides whether to follow it, and says why not when it
//! does not.
//!
//! > The Thermostat MAY use this information to ensure user comfort while also prioritizing
//! > other factors (e.g. energy savings, cost, and so on).
//!
//! That "MAY" is the whole design. A `Move to 19°C` command would be an instruction; a
//! suggestion is advice a device with its own schedule, occupancy sensor and hold state is
//! allowed to decline — and §4.3.11.56's
//! [`NotFollowingReason`](ThermostatSuggestionNotFollowingReasonBitmap) is how it declines
//! legibly, which is what stops the app and the thermostat fighting silently.
//!
//! # Why this is a component and not a cluster
//!
//! §4.3's Thermostat is one of the largest clusters in the library, and the suggestion table is
//! an independent piece of it: four attributes, two commands, and a re-evaluation rule that
//! touches nothing else. So it is written the way [`mode`](super::mode) is — the *shape*, for a
//! Thermostat implementation to hold — rather than a cluster handler that would have to be the
//! whole of §4.3 to be useful.
//!
//! # Time is a precondition, not a detail
//!
//! §4.3.4.3: "If this feature is supported, the thermostat SHALL support a mechanism to do time
//! synchronization." Every field here is an `epoch-s`, and §4.3.7 step 1 is unambiguous about
//! what happens without one:
//!
//! > If the server does not have its time synchronized, it SHALL set the
//! > CurrentThermostatSuggestion attribute to null.
//!
//! Not "keep the last one" — null. A thermostat that held a suggestion through a clock outage
//! would be following a window it could no longer tell it had left.

use heapless::Vec;

use crate::im::Status;

pub use crate::clusters::generated::thermostat::ThermostatSuggestionNotFollowingReasonBitmap;

/// §4.3.10.29's constraint on `PresetHandle`: "max 16".
pub const PRESET_HANDLE_MAX: usize = 16;

/// §4.3.12.4's constraint on `ExpirationInMinutes`: "30 to 1440".
pub const EXPIRATION_MINUTES_MIN: u16 = 30;
/// The other end of it — twenty-four hours.
pub const EXPIRATION_MINUTES_MAX: u16 = 1440;

/// §4.3.12.4 step 4: "If the value of the EffectiveTime field is greater than the current time
/// in UTC plus 24 hours, the server SHALL return a status code of INVALID_COMMAND."
pub const EFFECTIVE_TIME_HORIZON_S: u32 = 24 * 60 * 60;

/// One entry of the `ThermostatSuggestions` attribute (§4.3.10.29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// "a generated identifier that identifies a distinct entry".
    pub unique_id: u8,
    /// The `PresetHandle` of the `PresetStruct` this suggests.
    pub preset_handle: Vec<u8, PRESET_HANDLE_MAX>,
    /// "the UTC timestamp at which the suggestion SHALL take effect".
    pub effective_time: u32,
    /// "the UTC timestamp at which the suggestion SHALL expire".
    pub expiration_time: u32,
}

impl Suggestion {
    /// Whether the suggestion is in its window at `now`.
    #[must_use]
    pub const fn is_effective(&self, now: u32) -> bool {
        self.effective_time <= now && now < self.expiration_time
    }
}

/// What a re-evaluation concluded (§4.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    /// The `UniqueID` of the chosen entry, or `None` for §4.3.11.55's null.
    pub current: Option<u8>,
    /// §4.3.7 step 2e: "the earliest of the set of times that are greater than the current
    /// timestamp in UTC and are present in either the EffectiveTime or the ExpirationTime
    /// fields".
    ///
    /// `None` when nothing is scheduled to change — which happens only when the table is empty,
    /// since every live entry has an expiry ahead of it.
    pub wake_at: Option<u32>,
    /// §4.3.11.56's reason, when the server could not choose. `ConflictingSuggestions` is the
    /// only bit this table sets; the rest are the thermostat's own state.
    pub not_following: ThermostatSuggestionNotFollowingReasonBitmap,
}

/// The `ThermostatSuggestions` attribute and §4.3.7's re-evaluation (App §4.3).
///
/// `N` is §4.3.11.53's `MaxThermostatSuggestions`.
#[derive(Debug)]
pub struct Suggestions<const N: usize> {
    entries: Vec<Suggestion, N>,
    /// The next identifier to try. §4.3.12.4 step 5a iv asks only for "a generated identifier
    /// that is distinct from all other entries", so this counts and skips what is taken.
    next_id: u8,
}

impl<const N: usize> Default for Suggestions<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Suggestions<N> {
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 0,
        }
    }

    /// §4.3.11.53's `MaxThermostatSuggestions`.
    #[must_use]
    pub const fn max(&self) -> usize {
        N
    }

    /// The `ThermostatSuggestions` attribute (§4.3.11.54), "an unordered set".
    #[must_use]
    pub fn entries(&self) -> &[Suggestion] {
        &self.entries
    }

    /// One entry by its identifier.
    #[must_use]
    pub fn get(&self, unique_id: u8) -> Option<&Suggestion> {
        self.entries.iter().find(|e| e.unique_id == unique_id)
    }

    /// §4.3.12.4's `AddThermostatSuggestion`, in the order the specification lists its checks.
    ///
    /// `now` is the UTC timestamp, or [`None`] when the clock is not synchronised — step 1's
    /// `INVALID_IN_STATE`. `preset_exists` answers step 2 against the `Presets` attribute, which
    /// belongs to the Thermostat rather than to this table.
    ///
    /// Returns the `UniqueID` for §4.3.12.5's response.
    pub fn add(
        &mut self,
        preset_handle: &[u8],
        effective_time: Option<u32>,
        expiration_in_minutes: u16,
        now: Option<u32>,
        preset_exists: impl Fn(&[u8]) -> bool,
    ) -> Result<u8, Status> {
        // Step 1. Every field is a UTC timestamp, so without a clock there is no window to
        // record and no way to tell when it ends.
        let Some(now) = now else {
            return Err(Status::InvalidInState);
        };
        if preset_handle.len() > PRESET_HANDLE_MAX
            || !(EXPIRATION_MINUTES_MIN..=EXPIRATION_MINUTES_MAX).contains(&expiration_in_minutes)
        {
            return Err(Status::ConstraintError);
        }
        // Step 2: "the Presets attribute does not contain a PresetStruct whose PresetHandle
        // field matches" — a suggestion naming nothing is one the thermostat could never act on.
        if !preset_exists(preset_handle) {
            return Err(Status::NotFound);
        }
        // Step 3.
        if self.entries.len() >= N {
            return Err(Status::ResourceExhausted);
        }
        // Step 5a ii: "If the EffectiveTime field of this command is null, the EffectiveTime
        // field SHALL be set to a timestamp in UTC representing now."
        let effective_time = effective_time.unwrap_or(now);
        // Step 4: a window more than a day out is refused. §4.3.11.54 allows future entries for
        // "pre-cool or pre-heat decisions", but a suggestion for next week is a schedule, and
        // this table is not one.
        if effective_time > now.saturating_add(EFFECTIVE_TIME_HORIZON_S) {
            return Err(Status::InvalidCommand);
        }

        let unique_id = self.allocate().ok_or(Status::ResourceExhausted)?;
        let mut handle = Vec::new();
        handle
            .extend_from_slice(preset_handle)
            .map_err(|_| Status::ConstraintError)?;
        self.entries
            .push(Suggestion {
                unique_id,
                preset_handle: handle,
                effective_time,
                // Step 5a iii: "the value in the EffectiveTime field of the struct, plus the
                // value in the ExpirationInMinutes field of this command, with the latter
                // converted to seconds" — from the *effective* time, not from now, so a future
                // suggestion still gets its full window.
                expiration_time: effective_time
                    .saturating_add(u32::from(expiration_in_minutes).saturating_mul(60)),
            })
            .map_err(|_| Status::ResourceExhausted)?;
        Ok(unique_id)
    }

    /// §4.3.12.6's `RemoveThermostatSuggestion`.
    pub fn remove(&mut self, unique_id: u8) -> Result<(), Status> {
        let before = self.entries.len();
        self.entries.retain(|e| e.unique_id != unique_id);
        if self.entries.len() == before {
            // "Otherwise, the server SHALL return a status code of NOT_FOUND."
            return Err(Status::NotFound);
        }
        Ok(())
    }

    /// §4.3.7's re-evaluation, which is also what §4.3.12.4 and §4.3.12.6 trigger.
    ///
    /// Expired entries are dropped here — step 2b — so this mutates, and a caller that only
    /// wanted to look would be asking the wrong question: §4.3.7 makes the removal part of the
    /// evaluation rather than a separate tidy-up.
    pub fn evaluate(&mut self, now: Option<u32>) -> Evaluation {
        // Step 1.
        let Some(now) = now else {
            return Evaluation {
                current: None,
                wake_at: None,
                not_following: ThermostatSuggestionNotFollowingReasonBitmap::empty(),
            };
        };
        // Step 2b: "remove any entries … whose ExpirationTime is less than or equal to the
        // current timestamp in UTC".
        self.entries.retain(|e| e.expiration_time > now);

        // Step 2e: the next moment anything changes, computed over what is left.
        let wake_at = self
            .entries
            .iter()
            .flat_map(|e| [e.effective_time, e.expiration_time])
            .filter(|at| *at > now)
            .min();

        // Step 2c: nothing in its window means no current suggestion.
        let current = self.choose(now);
        let not_following = if current.is_none() && self.entries.iter().any(|e| e.is_effective(now))
        {
            // §4.3.8 step 7: "if the above steps … does not result in the server being able to
            // determine which entry to follow, the thermostat SHALL NOT follow any of the
            // suggestions, set the CurrentThermostatSuggestion attribute to null and set the
            // ThermostatSuggestionNotFollowingReason attribute to ConflictingSuggestions."
            ThermostatSuggestionNotFollowingReasonBitmap::CONFLICTING_SUGGESTIONS
        } else {
            ThermostatSuggestionNotFollowingReasonBitmap::empty()
        };
        Evaluation {
            current,
            wake_at,
            not_following,
        }
    }

    /// §4.3.8's guidelines, as far as they can be followed without the thermostat's own state.
    ///
    /// > If the list of entries … has multiple suggestions with the same PresetHandle, the
    /// > server SHOULD calculate the number of entries with the same PresetHandle. The server
    /// > SHOULD choose the entry with the most recent EffectiveTime from the entries with the
    /// > highest count of the same PresetHandle.
    ///
    /// Then step 4's tie-break: "The server MAY also decide to choose an entry with the most
    /// recent EffectiveTime." Steps 2 and 3 need the `Presets` attribute's `PresetScenario`,
    /// which this table does not hold — a Thermostat that wants them overrides the choice, which
    /// is what step 5's "additional decision making policies" is for.
    fn choose(&self, now: u32) -> Option<u8> {
        let mut best: Option<(usize, u32, u8)> = None;
        for entry in self.entries.iter().filter(|e| e.is_effective(now)) {
            let count = self
                .entries
                .iter()
                .filter(|other| {
                    other.is_effective(now) && other.preset_handle == entry.preset_handle
                })
                .count();
            let candidate = (count, entry.effective_time, entry.unique_id);
            // Most votes first, then the most recent effective time. The identifier breaks the
            // remaining tie so that the answer does not depend on the order of a list §4.3.11.54
            // calls "an unordered set".
            if best.is_none_or(|current| candidate > current) {
                best = Some(candidate);
            }
        }
        best.map(|(_, _, unique_id)| unique_id)
    }

    /// §4.3.12.4 step 5a iv: "a generated identifier that is distinct from all other entries".
    fn allocate(&mut self) -> Option<u8> {
        for _ in 0..=usize::from(u8::MAX) {
            let candidate = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if !self.entries.iter().any(|e| e.unique_id == candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &[u8] = b"home";
    const AWAY: &[u8] = b"away";

    fn any(_: &[u8]) -> bool {
        true
    }

    #[test]
    fn a_suggestion_runs_from_its_effective_time_for_its_duration() {
        // §4.3.12.4 step 5a iii: the expiry is the *effective* time plus the duration, so a
        // suggestion for later still gets its full window rather than a truncated one.
        let mut table = Suggestions::<4>::new();
        let id = table
            .add(HOME, Some(2_000), 60, Some(1_000), any)
            .expect("added");
        let entry = table.get(id).expect("stored");
        assert_eq!(entry.effective_time, 2_000);
        assert_eq!(entry.expiration_time, 2_000 + 3_600);
    }

    #[test]
    fn a_null_effective_time_means_now() {
        // §4.3.12.4 step 5a ii A.
        let mut table = Suggestions::<4>::new();
        let id = table.add(HOME, None, 30, Some(500), any).expect("added");
        assert_eq!(table.get(id).expect("stored").effective_time, 500);
    }

    #[test]
    fn identifiers_are_distinct_and_reused_only_when_free() {
        let mut table = Suggestions::<4>::new();
        let first = table.add(HOME, None, 30, Some(0), any).unwrap();
        let second = table.add(AWAY, None, 30, Some(0), any).unwrap();
        assert_ne!(first, second);
        table.remove(first).expect("removed");
        // The counter has moved on, so the next identifier is a new one rather than the freed
        // one — which matters because a controller may still hold the old value.
        let third = table.add(HOME, None, 30, Some(0), any).unwrap();
        assert_ne!(third, second);
    }

    #[test]
    fn expired_entries_are_dropped_by_the_evaluation() {
        // §4.3.7 step 2b, and it is the evaluation that does it — not a separate tidy-up.
        let mut table = Suggestions::<4>::new();
        table.add(HOME, Some(0), 30, Some(0), any).unwrap();
        assert_eq!(table.entries().len(), 1);
        let evaluation = table.evaluate(Some(1_800));
        assert!(table.entries().is_empty(), "the window closed at 1800");
        assert_eq!(evaluation.current, None);
    }

    #[test]
    fn the_timer_is_the_next_boundary_of_any_entry() {
        // §4.3.7 step 2e: "the earliest of the set of times that are greater than the current
        // timestamp … present in either the EffectiveTime or the ExpirationTime fields".
        let mut table = Suggestions::<4>::new();
        table.add(HOME, Some(0), 30, Some(0), any).unwrap(); // expires at 1800
        table.add(AWAY, Some(600), 60, Some(0), any).unwrap(); // effective at 600
        let evaluation = table.evaluate(Some(0));
        assert_eq!(evaluation.wake_at, Some(600), "the nearer of the two");
        let evaluation = table.evaluate(Some(700));
        assert_eq!(evaluation.wake_at, Some(1_800));
    }

    #[test]
    fn the_most_suggested_preset_wins() {
        // §4.3.8 step 1: "choose the entry with the most recent EffectiveTime from the entries
        // with the highest count of the same PresetHandle."
        let mut table = Suggestions::<8>::new();
        table.add(AWAY, Some(0), 60, Some(0), any).unwrap();
        table.add(HOME, Some(10), 60, Some(0), any).unwrap();
        let newest_home = table.add(HOME, Some(20), 60, Some(0), any).unwrap();
        let evaluation = table.evaluate(Some(30));
        assert_eq!(
            evaluation.current,
            Some(newest_home),
            "two votes for home beat one for away, and the newer of the two wins"
        );
        assert!(evaluation.not_following.is_empty());
    }
}
