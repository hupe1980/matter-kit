//! The Message Reliability Protocol (Core §4.12).
//!
//! UDP loses messages. MRP is how Matter gets them there anyway: a sender sets the **R**
//! flag, keeps the message, and retransmits on a backoff curve until the receiver
//! acknowledges it or [`MRP_MAX_TRANSMISSIONS`] attempts have gone by. The receiver
//! acknowledges either by piggybacking on a message it was going to send anyway, or —
//! after [`MRP_STANDALONE_ACK_TIMEOUT`] of having nothing to say — with a standalone
//! acknowledgement.
//!
//! # Sans-I/O
//!
//! Nothing here touches a socket or reads a clock. Time arrives as a parameter:
//!
//! ```text
//! on_send(counter, now)         // a reliable message went out
//! on_ack(counter)               // the peer acknowledged one
//! poll_deadline()               // when to come back
//! on_timeout(now)               // the deadline passed: retransmit, or give up
//! ```
//!
//! Which is what makes the whole five-transmission ladder — four seconds of wall-clock
//! waiting — a unit test that runs in microseconds, and the same test every time.
//!
//! # The backoff curve
//!
//! §4.12.2.1 states it as
//!
//! ```text
//! mrpBackoffTime = i * MRP_BACKOFF_BASE^max(0, n - MRP_BACKOFF_THRESHOLD)
//!                    * (1.0 + random(0,1) * MRP_BACKOFF_JITTER)
//! ```
//!
//! where `n` is "the number of send attempts before the current one" and `i` is the peer's
//! retry interval, scaled by [`MRP_BACKOFF_MARGIN`]. The threshold gives it two phases:
//! flat at first — "to improve initial latency when congestion is not the cause of packet
//! drops" — and exponential after, "to provide convergence when the network is congested".
//!
//! It is computed here in integer arithmetic, because a microcontroller has no FPU and a
//! retransmission timer does not need one. [`Duration::mul_ratio`] is the whole trick.

use crate::error::{Error, ErrorCode, Result};
use crate::platform::Duration;
use crate::platform::Instant;

/// "The maximum number of transmission attempts for a given reliable message" (Table 22).
pub const MRP_MAX_TRANSMISSIONS: u32 = 5;

/// "The base number for the exponential backoff equation": 1.6, as 16/10.
pub const MRP_BACKOFF_BASE: (u64, u64) = (16, 10);

/// "The scaler for random jitter in the backoff equation": 0.25, as 1/4.
pub const MRP_BACKOFF_JITTER: (u64, u64) = (1, 4);

/// "The scaler margin increase to backoff over the peer idle interval": 1.1, as 11/10.
pub const MRP_BACKOFF_MARGIN: (u64, u64) = (11, 10);

/// "The number of retransmissions before transitioning from linear to exponential
/// backoff".
pub const MRP_BACKOFF_THRESHOLD: u32 = 1;

/// "Amount of time to wait for an opportunity to piggyback an acknowledgement on an
/// outbound message before falling back to sending a standalone acknowledgement."
pub const MRP_STANDALONE_ACK_TIMEOUT: Duration = Duration::from_millis(200);

/// "Minimum amount of time between sender retries when the destination node is Idle"
/// (Table 22).
pub const SESSION_IDLE_INTERVAL: Duration = Duration::from_millis(500);

/// "Minimum amount of time between sender retries when the destination node is Active".
pub const SESSION_ACTIVE_INTERVAL: Duration = Duration::from_millis(300);

/// "Minimum amount of time the node SHOULD stay active after network activity".
pub const SESSION_ACTIVE_THRESHOLD: Duration = Duration::from_millis(4000);

/// The peer's retry parameters, learned from discovery or session establishment
/// (§4.12.3).
///
/// "MRP control parameters … are computed outside of the Exchange communication itself;
/// instead, they are valid for the duration of a secure session." A peer advertises them
/// in its `SII`, `SAI` and `SAT` TXT keys, or sends them in Sigma1/Sigma2 or the PBKDF
/// parameter exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrpParams {
    /// `SESSION_IDLE_INTERVAL` — how often to retry a peer that is idle.
    pub idle_interval: Duration,
    /// `SESSION_ACTIVE_INTERVAL` — how often to retry a peer that is active.
    pub active_interval: Duration,
    /// `SESSION_ACTIVE_THRESHOLD` — how long a peer stays active after it last spoke.
    pub active_threshold: Duration,
}

impl Default for MrpParams {
    fn default() -> Self {
        Self {
            idle_interval: SESSION_IDLE_INTERVAL,
            active_interval: SESSION_ACTIVE_INTERVAL,
            active_threshold: SESSION_ACTIVE_THRESHOLD,
        }
    }
}

impl MrpParams {
    /// Clamps values that arrived from a peer to what the specification allows.
    ///
    /// "The SII value SHALL NOT exceed 3600000 (1 hour in milliseconds)", likewise `SAI`;
    /// `SAT` "SHALL NOT exceed 65535". A peer that sends more is not trusted to set this
    /// node's timers to an hour and a half — these are numbers a stranger on the network
    /// controls, and they decide how long this node waits.
    #[must_use]
    pub fn clamped(self) -> Self {
        const MAX_INTERVAL: Duration = Duration::from_millis(3_600_000);
        const MAX_THRESHOLD: Duration = Duration::from_millis(65_535);
        Self {
            idle_interval: min(self.idle_interval, MAX_INTERVAL),
            active_interval: min(self.active_interval, MAX_INTERVAL),
            active_threshold: min(self.active_threshold, MAX_THRESHOLD),
        }
    }

    /// The base retry interval `i` for a peer in the given state, including the
    /// [`MRP_BACKOFF_MARGIN`] of §4.12.2.1.
    ///
    /// "The backoff base interval SHALL be set to a value at least 10% greater than the
    /// idle interval of the destination."
    #[must_use]
    pub fn base_interval(&self, peer_active: bool) -> Duration {
        let i = if peer_active {
            self.active_interval
        } else {
            self.idle_interval
        };
        i.mul_ratio(MRP_BACKOFF_MARGIN.0, MRP_BACKOFF_MARGIN.1)
    }
}

const fn min(a: Duration, b: Duration) -> Duration {
    if a.as_micros() <= b.as_micros() { a } else { b }
}

/// The retransmission timeout for the `n`-th attempt, without jitter (§4.12.2.1).
///
/// `n` is "the number of send attempts before the current one for this message (0 if this
/// is the initial transmission)".
#[must_use]
pub fn backoff(base_interval: Duration, n: u32) -> Duration {
    let exponent = n.saturating_sub(MRP_BACKOFF_THRESHOLD);
    let mut d = base_interval;
    for _ in 0..exponent {
        d = d.mul_ratio(MRP_BACKOFF_BASE.0, MRP_BACKOFF_BASE.1);
    }
    d
}

/// Applies the jitter term `(1.0 + random(0,1) * MRP_BACKOFF_JITTER)`.
///
/// `randomness` is any value; its low bits are used as the `random(0,1)` draw, so a
/// caller passes whatever its [`Rng`](crate::platform::Rng) produced without scaling it.
/// Jitter only ever *adds*: the specification's term is `1.0 + …`, so the un-jittered
/// backoff is the floor, not the average.
#[must_use]
pub fn with_jitter(backoff: Duration, randomness: u32) -> Duration {
    // A draw in 0..RESOLUTION stands for random(0,1).
    const RESOLUTION: u64 = 1 << 16;
    let draw = u64::from(randomness) % RESOLUTION;
    let denominator = RESOLUTION.saturating_mul(MRP_BACKOFF_JITTER.1);
    let extra = backoff.mul_ratio(draw.saturating_mul(MRP_BACKOFF_JITTER.0), denominator);
    backoff.saturating_add(extra)
}

/// What the sender should do when a retransmission timer fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OnTimeout {
    /// Send the message again; this is attempt number `attempt` (zero-based).
    Retransmit {
        /// The message counter to resend — "logical retransmission is of a given message
        /// as identified by its message counter" (§4.4.1.4), so the counter does not
        /// change.
        counter: u32,
        /// Which attempt this is, counting the original as 0.
        attempt: u32,
    },
    /// Send the standalone acknowledgement that has been waiting for a piggyback ride.
    SendStandaloneAck {
        /// The counter to acknowledge.
        counter: u32,
    },
    /// [`MRP_MAX_TRANSMISSIONS`] attempts have gone by unacknowledged. §4.12.2.1: the
    /// sender gives up and, in the specification's words, notifies the application.
    GiveUp {
        /// The counter that was never acknowledged.
        counter: u32,
    },
    /// The deadline that fired was not one this state machine set.
    Nothing,
}

/// One exchange's reliability state.
///
/// §4.12.3: "MRP SHALL support one pending acknowledgement and one pending retransmission
/// per Exchange" — so this holds exactly one of each, and the types say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mrp {
    params: MrpParams,
    /// The message awaiting acknowledgement, if any.
    pending_tx: Option<PendingTx>,
    /// The counter awaiting acknowledgement to the peer, if any.
    pending_ack: Option<PendingAck>,
    /// When the peer was last heard from, for the `PeerActiveMode` rule of §4.12.5.
    last_heard: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingTx {
    counter: u32,
    /// How many times it has been sent; 1 after the original transmission.
    sent: u32,
    /// When the current retransmission timer expires.
    deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingAck {
    counter: u32,
    /// When to give up on piggybacking and send a standalone acknowledgement.
    deadline: Instant,
}

impl Mrp {
    /// A fresh exchange with the given peer parameters.
    #[must_use]
    pub fn new(params: MrpParams) -> Self {
        Self {
            params: params.clamped(),
            pending_tx: None,
            pending_ack: None,
            last_heard: None,
        }
    }

    /// The peer's parameters, as clamped.
    #[must_use]
    pub const fn params(&self) -> MrpParams {
        self.params
    }

    /// Whether a message is awaiting acknowledgement.
    #[must_use]
    pub const fn is_awaiting_ack(&self) -> bool {
        self.pending_tx.is_some()
    }

    /// The counter awaiting acknowledgement from the peer, if any.
    #[must_use]
    pub const fn awaiting(&self) -> Option<u32> {
        match self.pending_tx {
            Some(tx) => Some(tx.counter),
            None => None,
        }
    }

    /// Whether the peer counts as active right now (§4.12.5).
    ///
    /// `PeerActiveMode = (now() - ActiveTimestamp) < SESSION_ACTIVE_THRESHOLD`.
    #[must_use]
    pub fn peer_active(&self, now: Instant) -> bool {
        match self.last_heard {
            Some(t) => now.saturating_duration_since(t) < self.params.active_threshold,
            None => false,
        }
    }

    /// Records that something arrived from the peer, which makes it active.
    pub fn note_peer_activity(&mut self, now: Instant) {
        self.last_heard = Some(now);
    }

    /// Records a reliable message that has just been sent.
    ///
    /// `randomness` seeds the jitter. Returns [`ErrorCode::Busy`] if a message is already
    /// awaiting acknowledgement: §4.12.3 allows exactly one per exchange, and quietly
    /// dropping the first would lose it.
    pub fn on_send(&mut self, counter: u32, now: Instant, randomness: u32) -> Result<()> {
        if self.pending_tx.is_some() {
            return Err(Error::new(ErrorCode::Busy));
        }
        // §4.12.2.1: "For the first message of a new exchange, the base interval, i, SHALL
        // be set according to the idle state of the peer … For all subsequent messages of
        // the exchange, the base interval … according to the active state."
        let base = self.params.base_interval(self.peer_active(now));
        let deadline = now.saturating_add(with_jitter(backoff(base, 0), randomness));
        self.pending_tx = Some(PendingTx {
            counter,
            sent: 1,
            deadline,
        });
        Ok(())
    }

    /// The counter that should be piggybacked on the next outbound message, if any.
    ///
    /// Taking it clears the pending acknowledgement: §4.12.2.2's "piggybacking outstanding
    /// acknowledgments on messages that it needs to send back".
    pub fn take_piggyback(&mut self) -> Option<u32> {
        self.pending_ack.take().map(|a| a.counter)
    }

    /// Records an arriving reliable message that must be acknowledged.
    ///
    /// `duplicate` says whether the message layer judged it a replay. §4.12.2.2: "The
    /// receiver SHALL send an acknowledgment message to the sender for each instance of
    /// an authenticated, reliable message, **including duplicates**" — so a duplicate
    /// still schedules an acknowledgement; it is only the *payload* that is dropped.
    pub fn on_reliable_received(&mut self, counter: u32, now: Instant, _duplicate: bool) {
        self.note_peer_activity(now);
        self.pending_ack = Some(PendingAck {
            counter,
            deadline: now.saturating_add(MRP_STANDALONE_ACK_TIMEOUT),
        });
    }

    /// Records an acknowledgement from the peer.
    ///
    /// Returns `true` if it acknowledged the message that was pending. An acknowledgement
    /// for anything else is ignored, not an error: a delayed duplicate acknowledgement for
    /// an earlier message is a normal thing to receive.
    pub fn on_ack(&mut self, counter: u32, now: Instant) -> bool {
        self.note_peer_activity(now);
        match self.pending_tx {
            Some(tx) if tx.counter == counter => {
                self.pending_tx = None;
                true
            }
            _ => false,
        }
    }

    /// The next instant at which [`Mrp::on_timeout`] has something to do.
    #[must_use]
    pub fn poll_deadline(&self) -> Option<Instant> {
        match (self.pending_tx, self.pending_ack) {
            (Some(tx), Some(ack)) => Some(min_instant(tx.deadline, ack.deadline)),
            (Some(tx), None) => Some(tx.deadline),
            (None, Some(ack)) => Some(ack.deadline),
            (None, None) => None,
        }
    }

    /// Handles a deadline that has passed.
    ///
    /// Call it whenever [`Mrp::poll_deadline`] has come and gone; call it again until it
    /// returns [`OnTimeout::Nothing`], since a retransmission and a standalone
    /// acknowledgement can both be due at once.
    pub fn on_timeout(&mut self, now: Instant, randomness: u32) -> OnTimeout {
        // The standalone acknowledgement first: it is cheap, and the peer is waiting on it
        // before it will send anything this node could have piggybacked on.
        if let Some(ack) = self.pending_ack
            && ack.deadline.is_elapsed_at(now)
        {
            self.pending_ack = None;
            return OnTimeout::SendStandaloneAck {
                counter: ack.counter,
            };
        }

        if let Some(tx) = self.pending_tx
            && tx.deadline.is_elapsed_at(now)
        {
            if tx.sent >= MRP_MAX_TRANSMISSIONS {
                self.pending_tx = None;
                return OnTimeout::GiveUp {
                    counter: tx.counter,
                };
            }
            // `sent` is how many have gone out, which is exactly the `n` of §4.12.2.1 for
            // the attempt about to be made.
            let base = self.params.base_interval(self.peer_active(now));
            let wait = with_jitter(backoff(base, tx.sent), randomness);
            let attempt = tx.sent;
            self.pending_tx = Some(PendingTx {
                counter: tx.counter,
                sent: tx.sent.saturating_add(1),
                deadline: now.saturating_add(wait),
            });
            return OnTimeout::Retransmit {
                counter: tx.counter,
                attempt,
            };
        }

        OnTimeout::Nothing
    }

    /// Abandons everything pending — what closing an exchange does.
    pub fn close(&mut self) {
        self.pending_tx = None;
        self.pending_ack = None;
    }
}

const fn min_instant(a: Instant, b: Instant) -> Instant {
    if a.as_micros() <= b.as_micros() { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The base interval Core Table 21 is computed with: the *active* interval of 300 ms
    /// scaled by the 1.1 margin.
    fn table_21_base() -> Duration {
        MrpParams::default().base_interval(true)
    }

    #[test]
    fn the_margin_is_applied_to_the_peer_interval() {
        let p = MrpParams::default();
        assert_eq!(p.base_interval(true).as_millis(), 330, "1.1 * 300");
        assert_eq!(p.base_interval(false).as_millis(), 550, "1.1 * 500");
    }

    /// Milliseconds, rounded to nearest — which is how Core Table 21 is printed.
    ///
    /// The arithmetic here is exact microseconds: the fourth transmission is 844 800 µs,
    /// and the table shows it as 845. Truncating instead of rounding makes that look like
    /// an off-by-one in the backoff curve, when it is only how the table was typeset.
    fn round_ms(d: Duration) -> u64 {
        d.as_micros().saturating_add(500).wrapping_div(1_000)
    }

    #[test]
    fn the_backoff_curve_matches_core_table_21() {
        // "Min Jitter": 330, 330, 528, 845, 1352 for transmissions 0..4.
        let base = table_21_base();
        let expected = [330u64, 330, 528, 845, 1352];
        for (n, want) in expected.iter().enumerate() {
            let got = backoff(base, n as u32);
            assert_eq!(round_ms(got), *want, "transmission #{n}");
        }
        // And the exact values, so a change to the arithmetic is visible rather than
        // hidden inside a rounding tolerance.
        assert_eq!(backoff(base, 0).as_micros(), 330_000);
        assert_eq!(backoff(base, 2).as_micros(), 528_000);
        assert_eq!(backoff(base, 3).as_micros(), 844_800);
        assert_eq!(backoff(base, 4).as_micros(), 1_351_680);
    }

    #[test]
    fn maximum_jitter_matches_core_table_21() {
        // "Max Jitter": 413, 413, 660, 1056, 1690 — the min row times 1.25.
        let base = table_21_base();
        let expected = [413u64, 413, 660, 1056, 1690];
        for (n, want) in expected.iter().enumerate() {
            // The largest draw the resolution allows.
            let got = round_ms(with_jitter(backoff(base, n as u32), u32::MAX));
            // Within a millisecond of the table: the draw is `< 1`, never `== 1`.
            assert!(
                got.abs_diff(*want) <= 1,
                "transmission #{n}: got {got}, table says {want}"
            );
        }
    }

    #[test]
    fn jitter_only_ever_adds() {
        // The specification's term is `(1.0 + random * 0.25)`, so the plain backoff is a
        // floor. A jitter that could subtract would retry sooner than the peer allows.
        let base = table_21_base();
        for n in 0..MRP_MAX_TRANSMISSIONS {
            let plain = backoff(base, n);
            for r in [0u32, 1, 1000, u32::MAX / 2, u32::MAX] {
                let jittered = with_jitter(plain, r);
                assert!(jittered >= plain, "n={n} r={r}");
                assert!(
                    jittered <= plain.saturating_add(plain.mul_ratio(1, 4)),
                    "n={n} r={r}: more than 25% added"
                );
            }
        }
    }

    #[test]
    fn a_zero_draw_is_the_unjittered_backoff() {
        let base = table_21_base();
        assert_eq!(with_jitter(backoff(base, 0), 0), backoff(base, 0));
    }

    #[test]
    fn an_acknowledgement_stops_the_timer() {
        let mut mrp = Mrp::new(MrpParams::default());
        let t0 = Instant::ZERO;
        mrp.on_send(7, t0, 0).expect("first send");
        assert!(mrp.is_awaiting_ack());
        assert_eq!(mrp.awaiting(), Some(7));
        assert!(mrp.poll_deadline().is_some());

        assert!(mrp.on_ack(7, t0), "the pending message is acknowledged");
        assert!(!mrp.is_awaiting_ack());
        assert_eq!(mrp.poll_deadline(), None);
    }

    #[test]
    fn an_acknowledgement_for_something_else_is_ignored() {
        let mut mrp = Mrp::new(MrpParams::default());
        mrp.on_send(7, Instant::ZERO, 0).expect("send");
        assert!(!mrp.on_ack(6, Instant::ZERO), "not the pending counter");
        assert!(mrp.is_awaiting_ack(), "still waiting");
    }

    #[test]
    fn one_pending_retransmission_per_exchange() {
        // §4.12.3.
        let mut mrp = Mrp::new(MrpParams::default());
        mrp.on_send(1, Instant::ZERO, 0).expect("first");
        assert_eq!(
            mrp.on_send(2, Instant::ZERO, 0).unwrap_err().code(),
            ErrorCode::Busy
        );
    }

    #[test]
    fn the_ladder_is_five_transmissions_then_give_up() {
        let mut mrp = Mrp::new(MrpParams::default());
        let mut now = Instant::ZERO;
        mrp.on_send(42, now, 0).expect("send");

        let mut attempts = heapless::Vec::<u32, 8>::new();
        while let Some(deadline) = mrp.poll_deadline() {
            now = deadline;
            match mrp.on_timeout(now, 0) {
                OnTimeout::Retransmit { counter, attempt } => {
                    assert_eq!(counter, 42, "the counter never changes");
                    let _ = attempts.push(attempt);
                }
                OnTimeout::GiveUp { counter } => {
                    assert_eq!(counter, 42);
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        // The original plus four retransmissions is MRP_MAX_TRANSMISSIONS attempts.
        assert_eq!(&attempts[..], &[1, 2, 3, 4]);
        assert!(!mrp.is_awaiting_ack(), "giving up clears the state");
    }

    #[test]
    fn the_cumulative_time_matches_core_table_21() {
        // "Min Total": 330, 660, 1188, 2033, 3385.
        let mut mrp = Mrp::new(MrpParams::default());
        // Make the peer active, which is what Table 21 is computed for.
        mrp.note_peer_activity(Instant::ZERO);
        let mut now = Instant::ZERO;
        mrp.on_send(1, now, 0).expect("send");

        // Table 21's "Min Total" row is the running sum of its own *rounded* "Min
        // Jitter" row, so it accumulates a little rounding: 330 + 330 + 528 + 845 + 1352.
        // The sum of the exact values is 3 384 480 µs, which the table prints as 3385.
        let expected = [330u64, 660, 1188, 2033, 3385];
        let mut totals = heapless::Vec::<u64, 8>::new();
        let mut rounded_sum = 0u64;
        let mut previous = Instant::ZERO;
        while let Some(deadline) = mrp.poll_deadline() {
            now = deadline;
            rounded_sum =
                rounded_sum.saturating_add(round_ms(now.saturating_duration_since(previous)));
            previous = now;
            let _ = totals.push(rounded_sum);
            if matches!(mrp.on_timeout(now, 0), OnTimeout::GiveUp { .. }) {
                break;
            }
        }
        assert_eq!(
            &totals[..],
            &expected[..],
            "cumulative retransmission times"
        );
        assert_eq!(
            now.saturating_duration_since(Instant::ZERO).as_micros(),
            3_384_480,
            "the exact total, before the table's per-step rounding"
        );
    }

    #[test]
    fn a_reliable_message_schedules_a_standalone_acknowledgement() {
        let mut mrp = Mrp::new(MrpParams::default());
        let t0 = Instant::ZERO;
        mrp.on_reliable_received(9, t0, false);

        let deadline = mrp.poll_deadline().expect("an ack deadline");
        assert_eq!(
            deadline.saturating_duration_since(t0),
            MRP_STANDALONE_ACK_TIMEOUT
        );
        assert_eq!(
            mrp.on_timeout(deadline, 0),
            OnTimeout::SendStandaloneAck { counter: 9 }
        );
        assert_eq!(mrp.poll_deadline(), None, "and then nothing is pending");
    }

    #[test]
    fn a_piggyback_cancels_the_standalone_acknowledgement() {
        let mut mrp = Mrp::new(MrpParams::default());
        mrp.on_reliable_received(9, Instant::ZERO, false);
        assert_eq!(mrp.take_piggyback(), Some(9));
        assert_eq!(mrp.poll_deadline(), None, "nothing left to send alone");
        assert_eq!(mrp.take_piggyback(), None, "and only once");
    }

    #[test]
    fn a_duplicate_is_still_acknowledged() {
        // §4.12.2.2: "for each instance of an authenticated, reliable message, including
        // duplicates". Not acknowledging one makes the peer retransmit until it gives up.
        let mut mrp = Mrp::new(MrpParams::default());
        mrp.on_reliable_received(9, Instant::ZERO, true);
        assert_eq!(mrp.take_piggyback(), Some(9));
    }

    #[test]
    fn an_idle_peer_gets_the_idle_interval() {
        let mut mrp = Mrp::new(MrpParams::default());
        let t0 = Instant::ZERO;
        mrp.on_send(1, t0, 0).expect("send");
        let deadline = mrp.poll_deadline().expect("a deadline");
        assert_eq!(
            deadline.saturating_duration_since(t0).as_millis(),
            550,
            "a peer never heard from is idle: 1.1 * 500"
        );
    }

    #[test]
    fn an_active_peer_gets_the_active_interval() {
        let mut mrp = Mrp::new(MrpParams::default());
        let t0 = Instant::ZERO;
        mrp.note_peer_activity(t0);
        mrp.on_send(1, t0, 0).expect("send");
        let deadline = mrp.poll_deadline().expect("a deadline");
        assert_eq!(deadline.saturating_duration_since(t0).as_millis(), 330);
    }

    #[test]
    fn a_peer_goes_idle_after_the_active_threshold() {
        let mut mrp = Mrp::new(MrpParams::default());
        mrp.note_peer_activity(Instant::ZERO);
        assert!(mrp.peer_active(Instant::from_micros(0)));
        let just_inside = Instant::ZERO
            .saturating_add(SESSION_ACTIVE_THRESHOLD)
            .saturating_sub(Duration::from_micros(1));
        assert!(mrp.peer_active(just_inside));
        let at_threshold = Instant::ZERO.saturating_add(SESSION_ACTIVE_THRESHOLD);
        assert!(!mrp.peer_active(at_threshold), "the comparison is strict");
    }

    #[test]
    fn peer_parameters_from_the_network_are_clamped() {
        // These are numbers a stranger sets, and they decide how long this node waits.
        let hostile = MrpParams {
            idle_interval: Duration::from_secs(86_400),
            active_interval: Duration::from_secs(86_400),
            active_threshold: Duration::from_secs(86_400),
        };
        let safe = hostile.clamped();
        assert_eq!(safe.idle_interval.as_millis(), 3_600_000);
        assert_eq!(safe.active_interval.as_millis(), 3_600_000);
        assert_eq!(safe.active_threshold.as_millis(), 65_535);
        // And a node built with them uses the clamped values.
        assert_eq!(Mrp::new(hostile).params(), safe);
    }

    #[test]
    fn both_a_retransmission_and_an_acknowledgement_can_be_due() {
        let mut mrp = Mrp::new(MrpParams::default());
        let t0 = Instant::ZERO;
        mrp.on_send(1, t0, 0).expect("send");
        mrp.on_reliable_received(2, t0, false);

        // The acknowledgement is due first (200 ms against 550 ms).
        let first = mrp.poll_deadline().expect("a deadline");
        assert_eq!(
            first.saturating_duration_since(t0),
            MRP_STANDALONE_ACK_TIMEOUT
        );
        assert!(matches!(
            mrp.on_timeout(first, 0),
            OnTimeout::SendStandaloneAck { counter: 2 }
        ));
        // The retransmission is still scheduled.
        assert!(mrp.poll_deadline().is_some());
        assert!(mrp.is_awaiting_ack());
    }

    #[test]
    fn an_early_timeout_does_nothing() {
        let mut mrp = Mrp::new(MrpParams::default());
        mrp.on_send(1, Instant::ZERO, 0).expect("send");
        assert_eq!(
            mrp.on_timeout(Instant::from_micros(1), 0),
            OnTimeout::Nothing
        );
        assert!(mrp.is_awaiting_ack(), "and changes nothing");
    }

    #[test]
    fn closing_abandons_everything() {
        let mut mrp = Mrp::new(MrpParams::default());
        mrp.on_send(1, Instant::ZERO, 0).expect("send");
        mrp.on_reliable_received(2, Instant::ZERO, false);
        mrp.close();
        assert_eq!(mrp.poll_deadline(), None);
        assert!(!mrp.is_awaiting_ack());
    }
}
