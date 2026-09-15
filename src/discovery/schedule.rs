//! *When* to send — RFC 6762's probing, announcing, conflict resolution and rate limits.
//!
//! [`responder`](super::responder) decides what a message says; this decides when one may be
//! sent. Core §4.3 delegates the rules: the instance name "SHALL be unique within the
//! namespace of the local network", and "name conflict detection is described in Section 9
//! ('Conflict Resolution') of the Multicast DNS specification".
//!
//! Sans-I/O, in the same shape as [`Mrp`](crate::exchange::Mrp): the caller polls with the
//! current [`Instant`] and a value from its [`Rng`](crate::platform::Rng), gets an [`Action`]
//! or nothing, and asks [`Schedule::wake_at`] when to come back. A 750 ms claim window is then
//! testable in microseconds.
//!
//! ```
//! use matter_kit::discovery::schedule::{Action, Schedule};
//! use matter_kit::platform::{Duration, Instant};
//!
//! let mut schedule = Schedule::new();
//! let mut now = Instant::ZERO;
//! schedule.start(now, 0);
//!
//! // Three probes, 250 ms apart (§8.1) — nothing may be advertised until they pass.
//! for _ in 0..3 {
//!     now = schedule.wake_at().unwrap();
//!     assert_eq!(schedule.poll(now), Some(Action::Probe));
//!     assert!(!schedule.may_respond());
//! }
//!
//! // 250 ms after the third probe with no conflicting answer, the name is ours.
//! now = schedule.wake_at().unwrap();
//! assert_eq!(schedule.poll(now), Some(Action::Announce));
//! assert!(schedule.may_respond());
//! # Ok::<(), matter_kit::Error>(())
//! ```

use crate::platform::{Duration, Instant};

/// RFC 6762 §8.1: the random delay before the first probe, "uniformly distributed in the
/// range 0-250 ms".
///
/// It exists for the case where "several devices are powered on simultaneously" — without it
/// every device on a freshly powered hub probes in the same millisecond and they all conflict
/// with each other.
pub const PROBE_JITTER: Duration = Duration::from_millis(250);

/// RFC 6762 §8.1: "250 ms after the first query, the host should send a second; then, 250 ms
/// after that, a third."
pub const PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// RFC 6762 §8.1: "If, by 250 ms after the third probe, no conflicting Multicast DNS
/// responses have been received, the host may move to the next step, announcing."
pub const PROBES: u8 = 3;

/// RFC 6762 §8.2: a host that loses a simultaneous-probe tiebreak "defers to the winning host
/// by waiting one second, and then begins probing for this record again".
pub const TIEBREAK_DEFER: Duration = Duration::from_secs(1);

/// RFC 6762 §8.1: "If fifteen conflicts occur within any ten-second period, then the host MUST
/// wait at least five seconds before each successive additional probe attempt."
pub const CONFLICT_BURST: u8 = 15;

/// The window the fifteen conflicts of [`CONFLICT_BURST`] are counted over.
pub const CONFLICT_WINDOW: Duration = Duration::from_secs(10);

/// How long a throttled responder waits before each further probe attempt (§8.1).
pub const CONFLICT_BACKOFF: Duration = Duration::from_secs(5);

/// RFC 6762 §8.3: "The Multicast DNS responder MUST send at least two unsolicited responses,
/// one second apart."
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(1);

/// The minimum number of announcements §8.3 requires.
pub const ANNOUNCEMENTS_MIN: u8 = 2;

/// RFC 6762 §8.3: "a responder MAY send up to eight unsolicited responses, provided that the
/// interval between unsolicited responses increases by at least a factor of two with every
/// response sent."
pub const ANNOUNCEMENTS_MAX: u8 = 8;

/// RFC 6762 §6: "a Multicast DNS responder MUST NOT … multicast a record on a given interface
/// until at least one second has elapsed since the last time that record was multicast on that
/// particular interface."
pub const MULTICAST_INTERVAL: Duration = Duration::from_secs(1);

/// The one exception to [`MULTICAST_INTERVAL`], for defending a name against a probe (§6).
///
/// "In this special case only, when responding via multicast to a probe, a Multicast DNS
/// responder is only required to delay its transmission as necessary to ensure an interval of
/// at least 250 ms since the last time the record was multicast on that interface." A probing
/// host has 750 ms in total to hear a defence, so a full second of silence would hand it the
/// name.
pub const DEFEND_INTERVAL: Duration = Duration::from_millis(250);

/// RFC 6762 §6: the lower bound of the delay before answering a query that others may also
/// answer.
///
/// "The reason for requiring that the delay be at least 20 ms is to accommodate the situation
/// where two or more query packets are sent back-to-back" — the responder can then aggregate
/// its answers into one message.
pub const SHARED_DELAY_MIN: Duration = Duration::from_millis(20);

/// RFC 6762 §6: the upper bound of that delay.
pub const SHARED_DELAY_MAX: Duration = Duration::from_millis(120);

/// RFC 6762 §6: the lower bound of the delay when the query has the TC bit set, "to allow
/// enough time for all the Known-Answer packets to arrive".
pub const KNOWN_ANSWER_DELAY_MIN: Duration = Duration::from_millis(400);

/// RFC 6762 §6: the upper bound of that delay.
pub const KNOWN_ANSWER_DELAY_MAX: Duration = Duration::from_millis(500);

/// What the caller should send, now.
///
/// Every variant is a multicast to [`MDNS_IPV6_GROUP`](super::MDNS_IPV6_GROUP) except
/// [`Action::Rename`], which is not a packet at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Multicast a probe query (§8.1).
    ///
    /// One question per name being claimed, qtype `ANY`, with the unicast-response bit set —
    /// "the probes SHOULD be sent as 'QU' questions … to allow a defending host to respond
    /// immediately via unicast". The proposed records go in the **Authority** section, which
    /// is what makes [`tiebreak`] possible for anyone else probing at the same moment.
    Probe,
    /// Multicast an unsolicited response carrying every record (§8.3).
    ///
    /// Unique records — SRV, TXT, AAAA — carry the cache-flush bit; the shared PTRs do not.
    Announce,
    /// Multicast every record with a TTL of zero (§10.1), then stop advertising.
    Goodbye,
    /// Probing lost: another responder owns the name.
    ///
    /// §9's recommended course is to "programmatically change the resource record name in an
    /// attempt to find a new name that is unique" — for a Matter commissionable node that is
    /// §4.3.1's own rule, "a new pseudo-randomly selected 64-bit temporary unique identifier
    /// SHALL be generated". Nothing may be advertised under the old name; call
    /// [`Schedule::renamed`] once a new one is chosen.
    Rename,
}

/// The phase a schedule is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    /// Not advertising, nothing due.
    Idle,
    /// §8.1's probes are in progress. The name is not yet ours and queries go unanswered.
    Probing,
    /// §8.3's announcements are in progress. The name is ours.
    Announcing,
    /// Probed and announced; answering queries.
    Established,
    /// A conflict was lost. The caller owes a new name before anything else can happen.
    Renaming,
    /// A goodbye is due, after which the schedule returns to [`Phase::Idle`].
    Leaving,
}

/// The startup, conflict and rate-limit schedule of one advertised name.
///
/// One per *name*, not per node: a node advertising a commissionable service and an
/// operational service claims two independent names and can be probing for one while the other
/// is established.
#[derive(Debug, Clone)]
pub struct Schedule {
    phase: Phase,
    /// When the next action in the current phase is due.
    due: Instant,
    /// How many probes or announcements have gone out in this phase.
    sent: u8,
    /// How many announcements this schedule sends, in `ANNOUNCEMENTS_MIN..=ANNOUNCEMENTS_MAX`.
    announcements: u8,
    /// §8.1's fifteen-in-ten-seconds counter, and when its window opened.
    conflicts: u8,
    window: Instant,
    throttled: bool,
}

impl Default for Schedule {
    fn default() -> Self {
        Self::new()
    }
}

impl Schedule {
    /// An idle schedule, advertising nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            due: Instant::ZERO,
            sent: 0,
            announcements: ANNOUNCEMENTS_MIN,
            conflicts: 0,
            window: Instant::ZERO,
            throttled: false,
        }
    }

    /// Sends `n` announcements rather than §8.3's minimum of two, clamped to `2..=8`.
    ///
    /// More announcements is more robustness against a lost packet and more traffic; §8.3
    /// permits up to eight and requires the interval to double each time, which this does.
    #[must_use]
    pub const fn with_announcements(mut self, n: u8) -> Self {
        self.announcements = if n < ANNOUNCEMENTS_MIN {
            ANNOUNCEMENTS_MIN
        } else if n > ANNOUNCEMENTS_MAX {
            ANNOUNCEMENTS_MAX
        } else {
            n
        };
        self
    }

    /// The phase the schedule is in.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether the responder may answer queries for this name.
    ///
    /// False until the first announcement: RFC 6762 §6 lets a responder answer only with
    /// records "for which that responder is explicitly authoritative", and a name being probed
    /// for is not yet owned. Answering during probing is how two devices both conclude they
    /// won.
    #[must_use]
    pub const fn may_respond(&self) -> bool {
        matches!(self.phase, Phase::Announcing | Phase::Established)
    }

    /// Begins the startup sequence of §8 — probe, then announce.
    ///
    /// §8: a responder does this "whenever \[it\] starts up, wakes up from sleep, receives an
    /// indication of a network interface 'Link Change' event, or has any other reason to
    /// believe that its network connectivity may have changed in some relevant way". It is
    /// also what §4.3.1 requires when a node enters commissioning mode under a new instance
    /// name.
    ///
    /// `randomness` supplies §8.1's 0–250 ms delay; any value will do, its low bits are used.
    pub fn start(&mut self, now: Instant, randomness: u32) {
        self.phase = Phase::Probing;
        self.sent = 0;
        self.due = now.saturating_add(self.first_probe_delay(randomness));
    }

    /// Re-announces after the record data changed, without re-probing (§8.4).
    ///
    /// "At any time, if the rdata of any of a host's Multicast DNS records changes, the host
    /// MUST repeat the Announcing step … The host does not need to repeat the Probing step
    /// because it has already established unique ownership of that name." A Matter node does
    /// this every time a TXT key moves — `CM` when a commissioning window opens, `SII`/`SAI`
    /// when the node changes ICD mode.
    ///
    /// Ignored while probing or renaming, where the name is not owned and an announcement
    /// would be a claim the node has no right to make.
    pub fn updated(&mut self, now: Instant) {
        if matches!(self.phase, Phase::Announcing | Phase::Established) {
            self.phase = Phase::Announcing;
            self.sent = 0;
            self.due = now;
        }
    }

    /// A conflicting response arrived (§9).
    ///
    /// A conflict is "a record with the same name, rrtype and rrclass, but inconsistent
    /// rdata", seen in **any** section of any response. The two cases are different rules:
    ///
    /// * **Probing** — §8.1: "the probing host MUST defer to the existing host, and SHOULD
    ///   choose new names". The next [`Schedule::poll`] yields [`Action::Rename`].
    /// * **Announced or established** — §9: "reset its conflicted unique record to probing
    ///   state, and go through the startup steps". It does *not* rename yet; only a probe that
    ///   draws a conflicting answer loses the name.
    ///
    /// Collapsing them either way is wrong: rename-always gives up names the node would have
    /// won, re-probe-always makes two probing devices loop forever.
    pub fn on_conflict(&mut self, now: Instant, randomness: u32) {
        self.note_conflict(now);
        match self.phase {
            Phase::Probing => {
                self.phase = Phase::Renaming;
                self.due = now;
                self.sent = 0;
            }
            Phase::Announcing | Phase::Established => self.start(now, randomness),
            Phase::Idle | Phase::Renaming | Phase::Leaving => {}
        }
    }

    /// A simultaneous probe was lost on the tiebreak of §8.2.
    ///
    /// Not a conflict: the other host has not claimed the name yet, it merely proposed
    /// lexicographically later data. "\[The host\] defers to the winning host by waiting one
    /// second, and then begins probing for this record again" — and the second exists to
    /// outlive a stale probe packet echoed back by a switch, which is why the name is *not*
    /// abandoned here.
    pub fn on_tiebreak_loss(&mut self, now: Instant) {
        if matches!(self.phase, Phase::Probing) {
            self.sent = 0;
            self.due = now.saturating_add(TIEBREAK_DEFER);
        }
    }

    /// A new name was chosen after [`Action::Rename`]; probing restarts.
    ///
    /// §9 step 3 asks that the chosen name be recorded in persistent storage "so that the
    /// device will use the same name the next time it is power-cycled". A Matter commissionable
    /// node is the exception and must *not*: §4.3.1 requires a new random instance name on
    /// every boot, precisely so that it cannot be tracked.
    pub fn renamed(&mut self, now: Instant, randomness: u32) {
        if matches!(self.phase, Phase::Renaming) {
            self.start(now, randomness);
        }
    }

    /// Stops advertising, sending §10.1's goodbye first.
    ///
    /// The goodbye is "the same resource record name, rrtype, rrclass, and rdata, but an RR
    /// TTL of zero", which deletes the entry from every cache on the link rather than leaving
    /// it to expire — a device that reboots into a new instance name would otherwise be two
    /// devices as far as every commissioner is concerned, for the record's full TTL.
    ///
    /// Only a name that was actually announced says goodbye; there is nothing in anyone's
    /// cache for a name that never got past probing.
    pub fn stop(&mut self, now: Instant) {
        if self.may_respond() {
            self.phase = Phase::Leaving;
            self.due = now;
            self.sent = 0;
        } else {
            self.phase = Phase::Idle;
        }
    }

    /// When the next action becomes due, or `None` if nothing is scheduled.
    #[must_use]
    pub const fn wake_at(&self) -> Option<Instant> {
        match self.phase {
            Phase::Idle | Phase::Established => None,
            _ => Some(self.due),
        }
    }

    /// The action due at `now`, advancing the schedule, or `None` if nothing is due yet.
    ///
    /// Yields at most one action per call. A caller that cannot send — the interface is down,
    /// the buffer is busy — simply does not call again until it can, and the schedule stays
    /// where it is; nothing here assumes the send happened.
    ///
    /// [`Action::Rename`] is the exception: it repeats on every poll until
    /// [`Schedule::renamed`], because the schedule cannot make progress without a new name and
    /// a caller that dropped the first one would otherwise have a node that is silently
    /// invisible with nothing to explain why.
    pub fn poll(&mut self, now: Instant) -> Option<Action> {
        if self.wake_at().is_none_or(|due| now < due) {
            return None;
        }
        match self.phase {
            // §8.1's window closes 250 ms *after* the third probe, not at it: until then a
            // conflicting answer still costs the name, so the phase stays `Probing` and
            // `may_respond` stays false through the whole window.
            Phase::Probing if self.sent >= PROBES => {
                self.phase = Phase::Announcing;
                self.sent = 0;
                Some(self.announce(now))
            }
            Phase::Probing => Some(self.probe(now)),
            Phase::Announcing => Some(self.announce(now)),
            Phase::Renaming => Some(Action::Rename),
            Phase::Leaving => {
                self.phase = Phase::Idle;
                Some(Action::Goodbye)
            }
            // `wake_at` returned `None` for these, so the guard above already returned.
            Phase::Idle | Phase::Established => None,
        }
    }

    fn probe(&mut self, now: Instant) -> Action {
        self.sent = self.sent.saturating_add(1);
        // §8.1's success condition is silence for a further 250 ms *after* the third probe,
        // not the third probe itself — so the same interval schedules both the next probe and
        // the check that ends the sequence.
        self.due = now.saturating_add(PROBE_INTERVAL);
        Action::Probe
    }

    fn announce(&mut self, now: Instant) -> Action {
        // §8.3: "at least two unsolicited responses, one second apart", and if there are more,
        // "the interval … increases by at least a factor of two with every response sent".
        let mut interval = ANNOUNCE_INTERVAL;
        for _ in 0..self.sent {
            interval = interval.saturating_add(interval);
        }
        self.sent = self.sent.saturating_add(1);
        if self.sent >= self.announcements {
            self.phase = Phase::Established;
        } else {
            self.due = now.saturating_add(interval);
        }
        Action::Announce
    }

    /// §8.1's first-probe delay, plus §8.1's five-second throttle if conflicts are flooding.
    fn first_probe_delay(&self, randomness: u32) -> Duration {
        let jitter = Duration::from_micros(
            u64::from(randomness)
                .checked_rem(PROBE_JITTER.as_micros())
                .unwrap_or(0),
        );
        if self.throttled {
            CONFLICT_BACKOFF.saturating_add(jitter)
        } else {
            jitter
        }
    }

    /// Counts a conflict into §8.1's rolling ten-second window.
    fn note_conflict(&mut self, now: Instant) {
        if self.conflicts == 0 || now.saturating_duration_since(self.window) >= CONFLICT_WINDOW {
            self.window = now;
            self.conflicts = 1;
            self.throttled = false;
        } else {
            self.conflicts = self.conflicts.saturating_add(1);
        }
        if self.conflicts >= CONFLICT_BURST {
            self.throttled = true;
        }
    }

    /// Whether §8.1's fifteen-conflicts-in-ten-seconds throttle is in force.
    ///
    /// "This is to help ensure that, in the event of software bugs or other unanticipated
    /// problems, errant hosts do not flood the network with a continuous stream of multicast
    /// traffic." Exposed because a device that reaches this state has something wrong with it
    /// and should say so in a log.
    #[must_use]
    pub const fn is_throttled(&self) -> bool {
        self.throttled
    }
}

/// What kind of query is being answered, which decides the delay before answering (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Answering {
    /// A probe query from another host, asking for a name this responder owns.
    ///
    /// §6: "answering such probe queries to defend a unique record is a high priority and
    /// needs to be done without delay". The prober has 750 ms in total.
    Probe,
    /// A query every one of whose answers is a record this responder has verified unique.
    ///
    /// §6: it "SHOULD NOT impose any random delay before responding" — there is no one else to
    /// collide with.
    Unique,
    /// A query whose answer is a shared record, such as a service PTR.
    ///
    /// §6: "each responder SHOULD delay its response by a random amount of time selected with
    /// uniform random distribution in the range 20-120 ms". This is the common case for a
    /// `_matterc._udp` browse, which every commissionable node on the link answers.
    Shared,
    /// A query with the TC bit set, so Known-Answer packets are still coming (§7.2).
    ///
    /// §6: delay 400–500 ms "to allow enough time for all the Known-Answer packets to arrive".
    KnownAnswerSuppression,
}

/// How long to wait before answering, per RFC 6762 §6.
///
/// `randomness` is any value; its low bits pick the point in the range.
#[must_use]
pub fn response_delay(answering: Answering, randomness: u32) -> Duration {
    let pick = |low: Duration, high: Duration| -> Duration {
        let span = high.as_micros().saturating_sub(low.as_micros());
        let draw = u64::from(randomness).checked_rem(span).unwrap_or(0);
        low.saturating_add(Duration::from_micros(draw))
    };
    match answering {
        Answering::Probe | Answering::Unique => Duration::ZERO,
        Answering::Shared => pick(SHARED_DELAY_MIN, SHARED_DELAY_MAX),
        Answering::KnownAnswerSuppression => pick(KNOWN_ANSWER_DELAY_MIN, KNOWN_ANSWER_DELAY_MAX),
    }
}

/// RFC 6762 §6's per-record multicast rate limit.
///
/// "A Multicast DNS responder MUST NOT (except in the one special case of answering probe
/// queries) multicast a record on a given interface until at least one second has elapsed
/// since the last time that record was multicast on that particular interface."
///
/// The limit is *per record*; this tracks it per **record set**, one slot per advertisement,
/// which is coarser and therefore always at least as conservative: it can delay a record that
/// was individually due, never send one that was not. A per-record table would need a key per
/// name and type — around eighty entries for the eight advertisements a Matter node may carry
/// — to buy back at most a few hundred milliseconds on a link this crate is trying to keep
/// quiet anyway (§4.3: "excessive use of multicast would be detrimental").
#[derive(Debug, Clone)]
pub struct MulticastLimiter<const N: usize> {
    /// When each slot was last multicast, and whether it ever was.
    last: [(Instant, bool); N],
}

impl<const N: usize> Default for MulticastLimiter<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> MulticastLimiter<N> {
    /// A limiter that has sent nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: [(Instant::ZERO, false); N],
        }
    }

    /// The earliest instant at which slot `index` may be multicast again.
    ///
    /// `defending` selects §6's probe exception — 250 ms instead of a second. An unknown index
    /// may be sent immediately; a limiter cannot rate-limit what it is not tracking, and
    /// pretending otherwise would silently drop answers.
    #[must_use]
    pub fn earliest(&self, index: usize, defending: bool) -> Instant {
        match self.last.get(index) {
            Some(&(_, false)) | None => Instant::ZERO,
            Some(&(at, true)) => at.saturating_add(if defending {
                DEFEND_INTERVAL
            } else {
                MULTICAST_INTERVAL
            }),
        }
    }

    /// Whether slot `index` may be multicast at `now`.
    #[must_use]
    pub fn may_send(&self, index: usize, now: Instant, defending: bool) -> bool {
        now >= self.earliest(index, defending)
    }

    /// Records that slot `index` was multicast at `now`.
    pub fn sent(&mut self, index: usize, now: Instant) {
        if let Some(slot) = self.last.get_mut(index) {
            *slot = (now, true);
        }
    }
}

/// The outcome of RFC 6762 §8.2's simultaneous-probe tiebreak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tiebreak {
    /// Our proposed data is lexicographically later: "it simply ignores the other host's
    /// probe".
    Won,
    /// The other host's data is lexicographically later. Defer for one second, then probe
    /// again — [`Schedule::on_tiebreak_loss`].
    Lost,
    /// The two record sets are identical.
    ///
    /// §8.2.1: "this indicates that two devices are advertising identical sets of records, as
    /// is sometimes done for fault tolerance, and there is, in fact, no conflict."
    Identical,
}

/// One record, reduced to what §8.2 compares: class, type, and uncompressed RDATA.
///
/// "The determination of 'lexicographically later' is performed by first comparing the record
/// class (excluding the cache-flush bit …), then the record type, then raw comparison of the
/// binary content of the rdata without regard for meaning or structure."
///
/// The RDATA must be *uncompressed* — "the details of how a particular name is compressed is
/// an artifact of how and where the record is written into the DNS message; it is not an
/// intrinsic property of the resource record itself" — so a caller building one from a
/// received message uses the decompressed name, not the bytes off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tiebreaker<'a> {
    /// The record class with the cache-flush bit masked off — `CLASS_IN` for everything Matter
    /// publishes.
    pub class: u16,
    /// The record type's wire value.
    pub kind: u16,
    /// The uncompressed RDATA.
    pub rdata: &'a [u8],
}

impl Tiebreaker<'_> {
    /// §8.2's ordering: class, then type, then RDATA bytes as **unsigned** values.
    ///
    /// "Note that it is vital that the bytes are interpreted as UNSIGNED values in the range
    /// 0-255, or the wrong outcome may result" — the RFC's own example is
    /// `169.254.99.200` against `169.254.200.50`, where reading 200 as `-56` picks the wrong
    /// winner. Rust's `u8` makes that the default rather than a hazard, and the test keeps it
    /// that way.
    ///
    /// "or one of the resource records runs out of rdata (in which case, the resource record
    /// which still has remaining data first is deemed lexicographically later)" — which is
    /// exactly a byte-slice comparison, since a prefix sorts before what extends it.
    #[must_use]
    pub fn cmp_lexicographic(&self, other: &Self) -> core::cmp::Ordering {
        self.class
            .cmp(&other.class)
            .then(self.kind.cmp(&other.kind))
            .then_with(|| self.rdata.cmp(other.rdata))
    }
}

/// RFC 6762 §8.2.1's tiebreak over two *sorted* sets of records.
///
/// Both sides must already be "sorted into order … using the same lexicographical order",
/// then they are "compared pairwise … until a difference is found". Sorting is the caller's
/// because this crate does not allocate: a caller with a fixed array sorts it in place.
///
/// "If either list of records runs out of records before any difference is found, then the
/// list with records remaining is deemed to have won the tiebreak."
#[must_use]
pub fn tiebreak<'a, 'b>(
    ours: impl IntoIterator<Item = Tiebreaker<'a>>,
    theirs: impl IntoIterator<Item = Tiebreaker<'b>>,
) -> Tiebreak {
    let mut ours = ours.into_iter();
    let mut theirs = theirs.into_iter();
    loop {
        return match (ours.next(), theirs.next()) {
            (None, None) => Tiebreak::Identical,
            (Some(_), None) => Tiebreak::Won,
            (None, Some(_)) => Tiebreak::Lost,
            (Some(mine), Some(yours)) => match mine.cmp_lexicographic(&yours) {
                core::cmp::Ordering::Equal => continue,
                core::cmp::Ordering::Greater => Tiebreak::Won,
                core::cmp::Ordering::Less => Tiebreak::Lost,
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Seen<T> = heapless::Vec<T, 32>;

    /// Runs the schedule forward, always at the instant the next action is due.
    fn drive(schedule: &mut Schedule, steps: usize) -> (Instant, Seen<Action>) {
        let mut now = Instant::ZERO;
        let mut seen = Seen::new();
        for _ in 0..steps {
            let Some(due) = schedule.wake_at() else { break };
            now = due;
            if let Some(action) = schedule.poll(now) {
                seen.push(action).expect("fewer than 32 actions");
            }
        }
        (now, seen)
    }

    #[test]
    fn startup_probes_three_times_then_announces_twice() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let (_, actions) = drive(&mut schedule, 8);
        assert_eq!(
            actions.as_slice(),
            &[
                Action::Probe,
                Action::Probe,
                Action::Probe,
                Action::Announce,
                Action::Announce
            ]
        );
        assert_eq!(schedule.phase(), Phase::Established);
    }

    #[test]
    fn the_probes_are_250ms_apart_and_the_name_is_claimed_750ms_in() {
        let mut schedule = Schedule::new();
        // randomness 0 means no jitter, so the arithmetic is exact.
        schedule.start(Instant::ZERO, 0);
        let mut at = [Instant::ZERO; 4];
        for slot in &mut at {
            let due = schedule.wake_at().expect("scheduled");
            *slot = due;
            let _ = schedule.poll(due);
        }
        assert_eq!(at[0], Instant::ZERO);
        assert_eq!(at[1], Instant::ZERO.saturating_add(PROBE_INTERVAL));
        assert_eq!(
            at[2],
            Instant::ZERO.saturating_add(Duration::from_millis(500))
        );
        // §8.1: the name is not claimed at the third probe but 250 ms after it.
        assert_eq!(
            at[3],
            Instant::ZERO.saturating_add(Duration::from_millis(750))
        );
    }

    #[test]
    fn the_first_probe_is_jittered_within_250ms() {
        for randomness in [0u32, 1, 999, 249_999, 250_000, u32::MAX] {
            let mut schedule = Schedule::new();
            schedule.start(Instant::ZERO, randomness);
            let due = schedule.wake_at().expect("scheduled");
            assert!(due.saturating_duration_since(Instant::ZERO) < PROBE_JITTER);
        }
    }

    #[test]
    fn nothing_is_answered_until_the_first_announcement() {
        let mut schedule = Schedule::new();
        assert!(!schedule.may_respond());
        schedule.start(Instant::ZERO, 0);
        for _ in 0..PROBES {
            let due = schedule.wake_at().expect("scheduled");
            assert_eq!(schedule.poll(due), Some(Action::Probe));
            assert!(!schedule.may_respond(), "a probed name is not yet owned");
        }
        let due = schedule.wake_at().expect("scheduled");
        assert_eq!(schedule.poll(due), Some(Action::Announce));
        assert!(schedule.may_respond());
    }

    #[test]
    fn announcement_intervals_double() {
        let mut schedule = Schedule::new().with_announcements(4);
        schedule.start(Instant::ZERO, 0);
        let mut announced = Seen::<Instant>::new();
        for _ in 0..16 {
            let Some(due) = schedule.wake_at() else { break };
            if schedule.poll(due) == Some(Action::Announce) {
                let _ = announced.push(due);
            }
        }
        assert_eq!(announced.len(), 4);
        let gap = |a: usize, b: usize| announced[b].saturating_duration_since(announced[a]);
        assert_eq!(gap(0, 1), Duration::from_secs(1));
        assert_eq!(gap(1, 2), Duration::from_secs(2));
        assert_eq!(gap(2, 3), Duration::from_secs(4));
    }

    #[test]
    fn announcement_count_is_clamped_to_the_rfcs_range() {
        assert_eq!(Schedule::new().with_announcements(0).announcements, 2);
        assert_eq!(Schedule::new().with_announcements(1).announcements, 2);
        assert_eq!(Schedule::new().with_announcements(200).announcements, 8);
    }

    #[test]
    fn a_conflict_while_probing_renames() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let due = schedule.wake_at().expect("scheduled");
        assert_eq!(schedule.poll(due), Some(Action::Probe));
        schedule.on_conflict(due, 0);
        assert_eq!(schedule.phase(), Phase::Renaming);
        assert_eq!(schedule.poll(due), Some(Action::Rename));
        // Nothing happens until a new name is chosen.
        assert_eq!(schedule.poll(due), Some(Action::Rename));
        schedule.renamed(due, 0);
        assert_eq!(schedule.phase(), Phase::Probing);
    }

    #[test]
    fn a_conflict_once_established_reprobes_rather_than_renaming() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let (now, _) = drive(&mut schedule, 8);
        assert_eq!(schedule.phase(), Phase::Established);
        schedule.on_conflict(now, 0);
        // §9 sends it back to probing; the name is only lost if that probe draws an answer.
        assert_eq!(schedule.phase(), Phase::Probing);
        assert!(!schedule.may_respond());
    }

    #[test]
    fn a_tiebreak_loss_defers_a_second_and_reprobes_without_renaming() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let due = schedule.wake_at().expect("scheduled");
        let _ = schedule.poll(due);
        schedule.on_tiebreak_loss(due);
        assert_eq!(schedule.phase(), Phase::Probing);
        assert_eq!(
            schedule.wake_at().expect("scheduled"),
            due.saturating_add(TIEBREAK_DEFER)
        );
        // And the probe sequence starts over rather than continuing from where it was.
        let (_, actions) = drive(&mut schedule, 8);
        assert_eq!(
            actions.iter().filter(|a| **a == Action::Probe).count(),
            usize::from(PROBES)
        );
    }

    #[test]
    fn fifteen_conflicts_in_ten_seconds_throttles_the_next_probe() {
        let mut schedule = Schedule::new();
        let mut now = Instant::ZERO;
        schedule.start(now, 0);
        for _ in 0..CONFLICT_BURST {
            now = now.saturating_add(Duration::from_millis(100));
            schedule.on_conflict(now, 0);
            if schedule.phase() == Phase::Renaming {
                let _ = schedule.poll(now);
                schedule.renamed(now, 0);
            }
        }
        assert!(schedule.is_throttled());
        let due = schedule.wake_at().expect("scheduled");
        assert!(due.saturating_duration_since(now) >= CONFLICT_BACKOFF);
    }

    #[test]
    fn conflicts_spread_past_the_window_do_not_throttle() {
        let mut schedule = Schedule::new();
        let mut now = Instant::ZERO;
        schedule.start(now, 0);
        for _ in 0..40 {
            now = now.saturating_add(CONFLICT_WINDOW);
            schedule.on_conflict(now, 0);
            if schedule.phase() == Phase::Renaming {
                let _ = schedule.poll(now);
                schedule.renamed(now, 0);
            }
            assert!(!schedule.is_throttled());
        }
    }

    #[test]
    fn an_update_reannounces_without_reprobing() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let (now, _) = drive(&mut schedule, 8);
        schedule.updated(now);
        let (_, actions) = drive(&mut schedule, 8);
        assert_eq!(actions.as_slice(), &[Action::Announce, Action::Announce]);
    }

    #[test]
    fn an_update_while_probing_is_ignored() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let due = schedule.wake_at().expect("scheduled");
        let _ = schedule.poll(due);
        schedule.updated(due);
        assert_eq!(schedule.phase(), Phase::Probing);
    }

    #[test]
    fn stopping_an_established_name_says_goodbye_once() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let (now, _) = drive(&mut schedule, 8);
        schedule.stop(now);
        assert_eq!(schedule.poll(now), Some(Action::Goodbye));
        assert_eq!(schedule.phase(), Phase::Idle);
        assert_eq!(schedule.wake_at(), None);
        assert_eq!(schedule.poll(now), None);
    }

    #[test]
    fn stopping_a_name_that_was_never_announced_says_nothing() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let due = schedule.wake_at().expect("scheduled");
        let _ = schedule.poll(due);
        schedule.stop(due);
        assert_eq!(schedule.phase(), Phase::Idle);
        assert_eq!(schedule.poll(due), None);
    }

    #[test]
    fn an_established_schedule_has_no_wakeup() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 0);
        let (now, _) = drive(&mut schedule, 8);
        assert_eq!(schedule.wake_at(), None, "§8.3: no periodic announcements");
        assert_eq!(
            schedule.poll(now.saturating_add(Duration::from_secs(3600))),
            None
        );
    }

    #[test]
    fn polling_early_yields_nothing_and_does_not_advance() {
        let mut schedule = Schedule::new();
        schedule.start(Instant::ZERO, 12_345);
        let due = schedule.wake_at().expect("scheduled");
        assert_eq!(schedule.poll(Instant::ZERO), None);
        assert_eq!(schedule.wake_at(), Some(due));
    }

    #[test]
    fn response_delays_match_the_rfcs_ranges() {
        // The bounds are written out rather than taken from the constants: a test that
        // compares a constant against itself passes however wrong the constant is.
        let ms = Duration::from_millis;
        for randomness in [0u32, 7, 5_000, 99_999, u32::MAX] {
            assert_eq!(response_delay(Answering::Probe, randomness), Duration::ZERO);
            assert_eq!(
                response_delay(Answering::Unique, randomness),
                Duration::ZERO
            );
            // §6: "uniform random distribution in the range 20-120 ms".
            let shared = response_delay(Answering::Shared, randomness);
            assert!(shared >= ms(20) && shared < ms(120), "{shared:?}");
            // §6: "in the range 400-500 ms".
            let known = response_delay(Answering::KnownAnswerSuppression, randomness);
            assert!(known >= ms(400) && known < ms(500), "{known:?}");
        }
        // And the range is actually used: two different draws give two different delays.
        assert_ne!(
            response_delay(Answering::Shared, 0),
            response_delay(Answering::Shared, 50_000)
        );
    }

    #[test]
    fn the_rfcs_own_numbers_are_the_constants() {
        // Every timing in this module is a number RFC 6762 states outright. Spelling them out
        // once means a typo in a constant fails here rather than on a link somewhere.
        assert_eq!(PROBE_JITTER, Duration::from_millis(250));
        assert_eq!(PROBE_INTERVAL, Duration::from_millis(250));
        assert_eq!(PROBES, 3);
        assert_eq!(TIEBREAK_DEFER, Duration::from_secs(1));
        assert_eq!(CONFLICT_BURST, 15);
        assert_eq!(CONFLICT_WINDOW, Duration::from_secs(10));
        assert_eq!(CONFLICT_BACKOFF, Duration::from_secs(5));
        assert_eq!(ANNOUNCE_INTERVAL, Duration::from_secs(1));
        assert_eq!(ANNOUNCEMENTS_MIN, 2);
        assert_eq!(ANNOUNCEMENTS_MAX, 8);
        assert_eq!(MULTICAST_INTERVAL, Duration::from_secs(1));
        assert_eq!(DEFEND_INTERVAL, Duration::from_millis(250));
        assert_eq!(SHARED_DELAY_MIN, Duration::from_millis(20));
        assert_eq!(SHARED_DELAY_MAX, Duration::from_millis(120));
        assert_eq!(KNOWN_ANSWER_DELAY_MIN, Duration::from_millis(400));
        assert_eq!(KNOWN_ANSWER_DELAY_MAX, Duration::from_millis(500));
    }

    #[test]
    fn a_record_may_not_be_multicast_twice_within_a_second() {
        let mut limiter = MulticastLimiter::<4>::new();
        let now = Instant::ZERO.saturating_add(Duration::from_secs(10));
        assert!(limiter.may_send(0, now, false), "nothing sent yet");
        limiter.sent(0, now);
        assert!(!limiter.may_send(0, now.saturating_add(Duration::from_millis(999)), false));
        assert!(limiter.may_send(0, now.saturating_add(MULTICAST_INTERVAL), false));
        // A different slot is unaffected.
        assert!(limiter.may_send(1, now, false));
    }

    #[test]
    fn defending_a_name_only_waits_250ms() {
        let mut limiter = MulticastLimiter::<2>::new();
        let now = Instant::ZERO.saturating_add(Duration::from_secs(10));
        limiter.sent(0, now);
        let at = now.saturating_add(DEFEND_INTERVAL);
        assert!(limiter.may_send(0, at, true), "§6's probe exception");
        assert!(!limiter.may_send(0, at, false));
    }

    #[test]
    fn an_untracked_slot_is_never_rate_limited() {
        let mut limiter = MulticastLimiter::<1>::new();
        limiter.sent(9, Instant::ZERO.saturating_add(Duration::from_secs(10)));
        assert!(limiter.may_send(9, Instant::ZERO, false));
    }

    /// RFC 6762 §8.2's own worked example.
    #[test]
    fn rfc_8_2_address_example() {
        // MyPrinter.local. A 169.254.99.200 versus 169.254.200.50.
        let lower = Tiebreaker {
            class: 1,
            kind: 1,
            rdata: &[169, 254, 99, 200],
        };
        let higher = Tiebreaker {
            class: 1,
            kind: 1,
            rdata: &[169, 254, 200, 50],
        };
        // "the third byte, with value 200, is greater than its counterpart with value 99, so
        // it is deemed the winner" — and reading 200 as a signed -56 would invert this.
        assert_eq!(tiebreak([higher], [lower]), Tiebreak::Won);
        assert_eq!(tiebreak([lower], [higher]), Tiebreak::Lost);
    }

    #[test]
    fn class_beats_type_beats_rdata() {
        let big_class = Tiebreaker {
            class: 2,
            kind: 1,
            rdata: &[0],
        };
        let big_type = Tiebreaker {
            class: 1,
            kind: 255,
            rdata: &[0],
        };
        let big_rdata = Tiebreaker {
            class: 1,
            kind: 1,
            rdata: &[255],
        };
        assert_eq!(tiebreak([big_class], [big_type]), Tiebreak::Won);
        assert_eq!(tiebreak([big_type], [big_rdata]), Tiebreak::Won);
    }

    #[test]
    fn a_prefix_loses_to_what_extends_it() {
        // "one of the resource records runs out of rdata … the resource record which still
        // has remaining data first is deemed lexicographically later".
        let short = Tiebreaker {
            class: 1,
            kind: 16,
            rdata: &[1, 2],
        };
        let long = Tiebreaker {
            class: 1,
            kind: 16,
            rdata: &[1, 2, 0],
        };
        assert_eq!(tiebreak([long], [short]), Tiebreak::Won);
    }

    #[test]
    fn a_longer_set_wins_and_identical_sets_do_not_conflict() {
        let a = Tiebreaker {
            class: 1,
            kind: 16,
            rdata: &[1],
        };
        let b = Tiebreaker {
            class: 1,
            kind: 33,
            rdata: &[2],
        };
        assert_eq!(tiebreak([a, b], [a]), Tiebreak::Won);
        assert_eq!(tiebreak([a], [a, b]), Tiebreak::Lost);
        assert_eq!(tiebreak([a, b], [a, b]), Tiebreak::Identical);
        assert_eq!(
            tiebreak(core::iter::empty(), core::iter::empty()),
            Tiebreak::Identical
        );
    }
}
