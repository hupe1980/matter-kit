//! Message counters and duplicate detection (Core §4.6).
//!
//! Every message carries a 32-bit counter that does two jobs: it is part of the
//! encryption nonce, and it is how a receiver notices it has seen this message before.
//! The second job is the one with teeth — "a malicious third party attempted to replay an
//! old message to gain some advantage" — and it is done with a *lossy* history: the
//! largest counter seen, plus a 32-bit bitmap of which of the 32 counters immediately
//! before it have arrived (§4.6.5.1).
//!
//! That compression is what makes the state affordable: 8 octets per peer instead of a set
//! of every counter ever seen. The cost is that a message more than
//! [`MSG_COUNTER_WINDOW_SIZE`] behind the maximum is treated as a duplicate even if it is
//! genuinely new, which is exactly the trade the specification makes.
//!
//! # Two rules, because there are two counter spaces
//!
//! A secure unicast session's counter never rolls over: the session is rekeyed long before
//! 2³² messages. So "new" simply means "greater than the maximum" (§4.6.5.2.1).
//!
//! A group counter is global and free-running, and does roll over. So "new" means "within
//! the next 2³¹ counters, modulo 2³²" — the counter space is cut in half, ahead and
//! behind (§4.6.5.2.2).
//!
//! Getting these two the wrong way round is a security bug in one direction (a replay
//! accepted) and an interoperability bug in the other (a live peer locked out), which is
//! why they are separate variants rather than a flag.

use crate::error::{Error, ErrorCode, Result};

/// "Maximum number of previously processed messages" a receiver remembers per peer
/// (Core Table 20).
pub const MSG_COUNTER_WINDOW_SIZE: u32 = 32;

/// Which duplicate-detection rule applies to a counter space (§4.6.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CounterKind {
    /// A secure unicast session, whose counter does not roll over (§4.6.5.2.1).
    ///
    /// "any arriving message with a counter in the range `[(max_message_counter + 1) to
    /// (2³² - 1)]` SHALL be considered new".
    SecureUnicast,
    /// A group session, or an unencrypted peer — a free-running counter that rolls over
    /// (§4.6.5.2.2).
    ///
    /// "any arriving message with a counter in the range `[(max_message_counter + 1) to
    /// (max_message_counter + 2³¹ - 1)]` (modulo 2³²) SHALL be considered new".
    Rollover,
}

/// What a receiver should do with an arriving counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Not seen before: process it, and the window has been updated to record it.
    New,
    /// Seen before, or too far behind to tell.
    ///
    /// §4.12.2.2 is emphatic about what happens next for a *reliable* message: "The
    /// receiver SHALL send an acknowledgment message to the sender for each instance of
    /// an authenticated, reliable message, including duplicates. The reliability layer
    /// SHALL only propagate the first instance of a message to the next higher layer."
    /// So a duplicate is acknowledged and then dropped — never silently ignored, or the
    /// sender retransmits until it gives up.
    Duplicate,
}

/// The message reception state for one peer or session (§4.6.5.1).
///
/// Eight octets: the largest counter seen, and a bitmap of the 32 before it. Bit 0 stands
/// for `max - 1`, bit 1 for `max - 2`, and so on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterWindow {
    kind: CounterKind,
    max: u32,
    bitmap: u32,
    /// Whether anything has been received yet. A fresh window must accept whatever
    /// counter arrives first, since the peer chose its starting value at random
    /// (§4.6.1.1) and there is nothing to compare against.
    primed: bool,
}

impl CounterWindow {
    /// An empty window that will accept the first counter it sees.
    #[must_use]
    pub const fn new(kind: CounterKind) -> Self {
        Self {
            kind,
            max: 0,
            bitmap: 0,
            primed: false,
        }
    }

    /// A window that has already seen `max` and nothing before it.
    ///
    /// This is how a session resumed from storage starts: the counter it left off at is
    /// known, the 32 before it are not, so they are treated as already seen — which is
    /// the safe direction.
    #[must_use]
    pub const fn primed_at(kind: CounterKind, max: u32) -> Self {
        Self {
            kind,
            max,
            bitmap: u32::MAX,
            primed: true,
        }
    }

    /// The largest counter accepted so far.
    #[must_use]
    pub const fn max(&self) -> u32 {
        self.max
    }

    /// Which rule this window applies.
    #[must_use]
    pub const fn kind(&self) -> CounterKind {
        self.kind
    }

    /// Judges `counter`, and records it when it is new.
    pub fn accept(&mut self, counter: u32) -> Verdict {
        if !self.primed {
            self.primed = true;
            self.max = counter;
            self.bitmap = 0;
            return Verdict::New;
        }

        if counter == self.max {
            // "A message counter equal to max_message_counter SHALL be considered
            // duplicate."
            return Verdict::Duplicate;
        }

        let ahead = match self.kind {
            // No rollover: strictly greater is ahead, full stop.
            CounterKind::SecureUnicast => counter > self.max,
            // Rollover: ahead means within the next 2³¹ - 1, modulo 2³².
            CounterKind::Rollover => {
                let delta = counter.wrapping_sub(self.max);
                delta != 0 && delta < 0x8000_0000
            }
        };

        if ahead {
            let shift = counter.wrapping_sub(self.max);
            // Shift the history along by however far the maximum moved, then record that
            // the old maximum was itself received.
            self.bitmap = if shift >= MSG_COUNTER_WINDOW_SIZE {
                // Everything the bitmap held is now outside the window.
                if shift == MSG_COUNTER_WINDOW_SIZE {
                    // The old maximum lands exactly on the last bit.
                    1u32.checked_shl(MSG_COUNTER_WINDOW_SIZE.saturating_sub(1))
                        .unwrap_or(0)
                } else {
                    0
                }
            } else {
                // `shift` is in 1..32 here, so both shifts are in range.
                let moved = self.bitmap.checked_shl(shift).unwrap_or(0);
                let old_max_bit = 1u32.checked_shl(shift.saturating_sub(1)).unwrap_or(0);
                moved | old_max_bit
            };
            self.max = counter;
            return Verdict::New;
        }

        // Behind the maximum. Inside the bitmap it is a duplicate if the bit is set and
        // new otherwise; outside it, "All other message counters SHALL be considered
        // duplicate."
        let behind = self.max.wrapping_sub(counter);
        if behind == 0 || behind > MSG_COUNTER_WINDOW_SIZE {
            return Verdict::Duplicate;
        }
        let Some(bit) = 1u32.checked_shl(behind.saturating_sub(1)) else {
            return Verdict::Duplicate;
        };
        if self.bitmap & bit != 0 {
            Verdict::Duplicate
        } else {
            self.bitmap |= bit;
            Verdict::New
        }
    }

    /// Whether `counter` would be accepted, without recording it.
    #[must_use]
    pub fn would_accept(&self, counter: u32) -> Verdict {
        let mut probe = *self;
        probe.accept(counter)
    }
}

/// A sender's own counter for one key (§4.6.1).
///
/// "The message counter is generated based on the Session Type and increases
/// monotonically for each unique message generated." A retransmission reuses its
/// counter — "logical retransmission is of a given message as identified by its message
/// counter" (§4.4.1.4) — so the counter is taken once, when the message is first built,
/// and not again.
///
/// §4.6.1.1's `Crypto_DRBG(len = 28) + 1`, applied to a full-width random word.
///
/// "All message counters SHALL be initialized with a random value using the
/// `Crypto_DRBG(len = 28) + 1` primitive" — *all*, which is four counters in this crate with
/// four different lifetimes: a secure session's (§4.6.2, randomised at establishment), the
/// global unencrypted one (§4.6.1.2, randomised at startup), the two global group ones
/// (§4.6.1.3) and the Check-In counter (§4.6.3), both randomised at factory reset and persisted
/// after that. They share one rule, so they share one implementation: a counter that starts
/// anywhere in `u32` is a rule broken four times over, or not at all.
///
/// The result is in `1..=2^28`. §4.6.1.1 gives the reason for the ceiling in its own words —
/// the range is narrow "in order to maximize initial entropy while still reserving the vast
/// majority of the range to actual counter values (roughly 2³² - 2²⁸)".
///
/// ```
/// use matter_kit::msg::initial_counter;
///
/// assert_eq!(initial_counter(0), 1);
/// assert_eq!(initial_counter(u32::MAX), 1 << 28);
/// assert!((1..=(1 << 28)).contains(&initial_counter(0xDEAD_BEEF)));
/// ```
#[must_use]
pub const fn initial_counter(randomness: u32) -> u32 {
    // `& 0x0FFF_FFFF` is `Crypto_DRBG(len = 28)`: twenty-eight bits. `+ 1` moves it off zero,
    // which §4.6.1.1 excludes, and makes 2²⁸ itself reachable.
    (randomness & 0x0FFF_FFFF).saturating_add(1)
}

/// The initial value is random (§4.6.1.1), which is why [`MessageCounter::new`] takes one
/// rather than starting at zero: a counter that always starts at 1 leaks how many times a
/// device has rebooted, and makes nonce reuse across a factory reset far too easy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageCounter {
    next: u32,
    /// Set once [`u32::MAX`] has been handed out. Without it the increment fails on the
    /// call that should return the last legal counter, throwing one away.
    exhausted: bool,
}

impl MessageCounter {
    /// §4.6.1.1's initialisation, from `randomness` — which should come from
    /// [`crate::platform::Rng`].
    ///
    /// "All message counters SHALL be initialized with a random value using the
    /// `Crypto_DRBG(len = 28) + 1` primitive", so the starting value is in `1..=2^28` and not
    /// anywhere in `u32`. The specification gives the reason in the next sentence: the range is
    /// deliberately narrow "in order to maximize initial entropy while still reserving the vast
    /// majority of the range to actual counter values (roughly 2³² - 2²⁸)".
    ///
    /// That reservation is load-bearing rather than decorative. [`take`](Self::take) refuses on
    /// exhaustion instead of rolling over — §4.6.2 has a secure session "discarded and
    /// re-established before any Secure Session Message Counter overflow or repetition occurs"
    /// — so the initial value is also the size of the session's supply. Seeded from the full
    /// `u32` a session begins on average half-way through its own lifetime, and one in four
    /// thousand begins with under a million counters left: it stops working early, and nothing
    /// anywhere says why.
    ///
    /// The narrowing lives here rather than at each caller for the same reason the peer and the
    /// report cursor do (D82, D83). [`at`](Self::at) is for an exact value — a persisted
    /// counter, or the end of the range in a test.
    #[must_use]
    pub const fn new(randomness: u32) -> Self {
        Self::at(initial_counter(randomness))
    }

    /// A counter at exactly `value`, bypassing §4.6.1.1.
    ///
    /// For restoring a counter that was persisted — a group sender's counters outlive a reboot
    /// — and for tests that need to stand at a particular point in the range. A counter for a
    /// *new* session comes from [`new`](Self::new).
    #[must_use]
    pub const fn at(value: u32) -> Self {
        Self {
            next: value,
            exhausted: false,
        }
    }

    /// The value the next message will carry.
    #[must_use]
    pub const fn peek(&self) -> u32 {
        self.next
    }

    /// Takes the next counter.
    ///
    /// Returns [`ErrorCode::InvalidState`] on exhaustion rather than rolling over: for a
    /// secure unicast session, reusing a counter means reusing a nonce, which is a
    /// catastrophic failure of the encryption rather than a wrap to handle. A session that
    /// reaches 2³² messages must be re-established, and the caller is told so.
    pub fn take(&mut self) -> Result<u32> {
        if self.exhausted {
            return Err(Error::new(ErrorCode::InvalidState));
        }
        let value = self.next;
        match self.next.checked_add(1) {
            Some(n) => self.next = n,
            // `value` is still legal and is returned; it is the *next* call that fails.
            None => self.exhausted = true,
        }
        Ok(value)
    }

    /// Takes the next counter, rolling over at 2³².
    ///
    /// For the group counter space, which §4.6.5.2.2 defines as "a free running message
    /// counter that monotonically increases, but rolls over to zero when it exceeds the
    /// maximum value of the counter".
    pub fn take_with_rollover(&mut self) -> u32 {
        let value = self.next;
        self.next = self.next.wrapping_add(1);
        self.exhausted = false;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_counter_is_always_accepted() {
        // A peer picks its initial counter at random (§4.6.1.1), so there is nothing to
        // compare the first one against.
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        assert_eq!(w.accept(0x8000_0000), Verdict::New);
        assert_eq!(w.max(), 0x8000_0000);
    }

    #[test]
    fn a_repeat_of_the_maximum_is_a_duplicate() {
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        assert_eq!(w.accept(100), Verdict::New);
        assert_eq!(w.accept(100), Verdict::Duplicate);
    }

    #[test]
    fn in_order_delivery_is_all_new() {
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        for c in 1..1000 {
            assert_eq!(w.accept(c), Verdict::New, "counter {c}");
        }
        assert_eq!(w.max(), 999);
    }

    #[test]
    fn out_of_order_inside_the_window_is_accepted_once() {
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        assert_eq!(w.accept(100), Verdict::New);
        assert_eq!(w.accept(105), Verdict::New);
        // The four that were skipped are still new the first time they arrive.
        for c in [101, 102, 103, 104] {
            assert_eq!(w.accept(c), Verdict::New, "counter {c}");
            assert_eq!(w.accept(c), Verdict::Duplicate, "counter {c} again");
        }
        assert_eq!(w.max(), 105, "a late arrival does not move the maximum");
    }

    #[test]
    fn beyond_the_window_is_a_duplicate_even_if_it_is_new() {
        // The documented cost of the lossy history (§4.6.5.1).
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        assert_eq!(w.accept(1000), Verdict::New);
        // One past the far edge of the window: genuinely new, reported as a duplicate.
        assert_eq!(
            w.accept(1000 - MSG_COUNTER_WINDOW_SIZE - 1),
            Verdict::Duplicate
        );
        assert_eq!(w.accept(1), Verdict::Duplicate);
    }

    #[test]
    fn the_window_edge_is_where_the_spec_puts_it() {
        // §4.6.5.1: the window is "between [(max - MSG_COUNTER_WINDOW_SIZE) to
        // (max - 1)]", and bit i stands for `max - 1 - i`. So `max - 32` is the *last*
        // bit, inside the window, and `max - 33` is the first one outside it.
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        assert_eq!(w.accept(1000), Verdict::New);
        assert_eq!(
            w.accept(1000 - 32),
            Verdict::New,
            "32 behind is the last bit"
        );
        assert_eq!(w.accept(1000 - 32), Verdict::Duplicate, "and now it is set");
        assert_eq!(w.accept(1000 - 33), Verdict::Duplicate, "33 behind is out");
        assert_eq!(
            w.accept(1000 - 1),
            Verdict::New,
            "1 behind is the first bit"
        );
    }

    #[test]
    fn a_big_jump_forward_clears_the_history() {
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        assert_eq!(w.accept(100), Verdict::New);
        assert_eq!(w.accept(99), Verdict::New);
        assert_eq!(w.accept(10_000), Verdict::New);
        // 99 is now far behind, so it reads as a duplicate — which it is.
        assert_eq!(w.accept(99), Verdict::Duplicate);
    }

    #[test]
    fn a_secure_unicast_counter_does_not_roll_over() {
        // §4.6.5.2.1: new is "[(max + 1) to (2³² - 1)]" — nothing wraps.
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        assert_eq!(w.accept(u32::MAX - 1), Verdict::New);
        assert_eq!(w.accept(u32::MAX), Verdict::New);
        assert_eq!(w.accept(0), Verdict::Duplicate, "0 is behind, not ahead");
        assert_eq!(w.accept(5), Verdict::Duplicate);
    }

    #[test]
    fn a_group_counter_does_roll_over() {
        // §4.6.5.2.2: new is "[(max + 1) to (max + 2³¹ - 1)] (modulo 2³²)".
        let mut w = CounterWindow::new(CounterKind::Rollover);
        assert_eq!(w.accept(u32::MAX), Verdict::New);
        assert_eq!(w.accept(0), Verdict::New, "0 is one past u32::MAX");
        assert_eq!(w.accept(1), Verdict::New);
        assert_eq!(w.accept(u32::MAX), Verdict::Duplicate, "and back is behind");
    }

    #[test]
    fn the_group_space_is_cut_in_half() {
        let mut w = CounterWindow::new(CounterKind::Rollover);
        assert_eq!(w.accept(1000), Verdict::New);
        // Just under half the space ahead is new.
        assert_eq!(w.accept(1000u32.wrapping_add(0x7FFF_FFFF)), Verdict::New);
        let mut w = CounterWindow::new(CounterKind::Rollover);
        assert_eq!(w.accept(1000), Verdict::New);
        // Exactly half is behind, not ahead.
        assert_eq!(
            w.accept(1000u32.wrapping_add(0x8000_0000)),
            Verdict::Duplicate
        );
    }

    #[test]
    fn a_window_restored_from_storage_rejects_everything_behind_it() {
        let mut w = CounterWindow::primed_at(CounterKind::SecureUnicast, 5000);
        for c in [4999, 4990, 4969, 1] {
            assert_eq!(w.accept(c), Verdict::Duplicate, "counter {c}");
        }
        assert_eq!(w.accept(5001), Verdict::New);
    }

    #[test]
    fn would_accept_does_not_record() {
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        assert_eq!(w.accept(100), Verdict::New);
        assert_eq!(w.would_accept(101), Verdict::New);
        assert_eq!(w.would_accept(101), Verdict::New, "still new");
        assert_eq!(w.accept(101), Verdict::New);
        assert_eq!(w.would_accept(101), Verdict::Duplicate, "now it is not");
    }

    #[test]
    fn a_replay_of_an_entire_window_is_caught() {
        let mut w = CounterWindow::new(CounterKind::SecureUnicast);
        for c in 1..=64u32 {
            assert_eq!(w.accept(c), Verdict::New);
        }
        // An attacker replays the lot.
        for c in 1..=64u32 {
            assert_eq!(w.accept(c), Verdict::Duplicate, "replayed counter {c}");
        }
    }

    #[test]
    fn the_sender_counter_refuses_to_reuse_a_nonce() {
        let mut c = MessageCounter::at(u32::MAX - 1);
        assert_eq!(c.take().expect("one left"), u32::MAX - 1);
        assert_eq!(
            c.take().expect("the last counter is usable"),
            u32::MAX,
            "giving up at u32::MAX - 1 throws away a legal counter"
        );
        assert_eq!(
            c.take().unwrap_err().code(),
            ErrorCode::InvalidState,
            "a unicast counter must not wrap: that reuses a nonce"
        );
    }

    #[test]
    fn the_group_sender_counter_does_roll_over() {
        let mut c = MessageCounter::at(u32::MAX);
        assert_eq!(c.take_with_rollover(), u32::MAX);
        assert_eq!(c.take_with_rollover(), 0);
        assert_eq!(c.peek(), 1);
    }

    /// §4.6.1.1: "All message counters SHALL be initialized with a random value using the
    /// `Crypto_DRBG(len = 28) + 1` primitive."
    ///
    /// A production counter is seeded from `Rng::next_u32`, so the whole `u32` is what it can
    /// be handed; the sweep is over the boundaries of the mask plus every top-byte pattern,
    /// which is where a wrong mask or a missing `+ 1` shows.
    #[test]
    fn an_initial_counter_is_inside_the_twenty_eight_bit_range() {
        const CEILING: u32 = 1 << 28;
        let mut seen_top = false;
        for high in 0..=u8::MAX {
            for low in [0x00u32, 0x01, 0x7F, 0x80, 0xFE, 0xFF] {
                let randomness = (u32::from(high) << 24) | (low << 16) | (low << 8) | low;
                let start = MessageCounter::new(randomness).peek();
                assert!(
                    (1..=CEILING).contains(&start),
                    "{randomness:#010x} started at {start:#010x}"
                );
                seen_top |= start == CEILING;
            }
        }
        // `+ 1` makes 2²⁸ itself reachable; a mask alone would stop one short.
        assert!(seen_top, "the top of the range is never reached");
        // And zero is not in it, which is the whole point of the `+ 1`.
        assert_eq!(MessageCounter::new(0).peek(), 1);
        assert_eq!(MessageCounter::new(u32::MAX).peek(), CEILING);
    }

    /// The counter a session is given has to leave it room to run.
    ///
    /// `take` refuses on exhaustion rather than rolling over (§4.6.2), so the initial value
    /// is also the size of the session's supply. Seeding from the full `u32` left one session
    /// in four thousand with under a million counters, which is a session that stops working
    /// early and says nothing about why.
    #[test]
    fn an_initial_counter_leaves_the_session_its_supply() {
        const RESERVED: u32 = u32::MAX - (1 << 28);
        for randomness in [0, 1, u32::MAX, u32::MAX - 1, 0xFFFF_0000, 0x8000_0000] {
            let remaining = u32::MAX - MessageCounter::new(randomness).peek();
            assert!(
                remaining >= RESERVED,
                "{randomness:#010x} left only {remaining} counters"
            );
        }
    }

    /// `at` is the escape hatch, and it really does bypass the narrowing — otherwise the tests
    /// that stand at the end of the range would be standing somewhere else.
    #[test]
    fn at_takes_the_value_it_is_given() {
        assert_eq!(MessageCounter::at(u32::MAX).peek(), u32::MAX);
        assert_eq!(MessageCounter::at(0).peek(), 0);
    }
}
