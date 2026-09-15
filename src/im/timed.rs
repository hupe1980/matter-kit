//! The Timed transaction window — Core §8.7.4, §8.7.3.2, §8.8.2.3.
//!
//! A Timed transaction puts a deadline on its second phase:
//!
//! ```text
//! Timed Request (Timeout = 1000 ms)  ──▶
//!                                    ◀──  Status Response (SUCCESS)   ← the clock starts here
//! Write Request / Invoke Request     ──▶   … within 1000 ms, or TIMEOUT
//! ```
//!
//! Elements with the `T` quality require one — `Door Lock`'s unlock,
//! `OpenCommissioningWindow`, Access Control entries — so that a captured message stops being
//! useful shortly after it is captured.
//!
//! [`ClusterHandler`](super::server::ClusterHandler) already refuses an element that requires
//! a Timed transaction when
//! [`InteractionContext::timed`](super::server::InteractionContext::timed) is false.
//! [`TimedWindows`] is what *decides* that flag, applying §8.7.3.2's and §8.8.2.3's rules —
//! the same on both the Write and Invoke sides:
//!
//! | Window | `TimedRequest` flag | Outcome |
//! |---|---|---|
//! | open, not expired | true | proceed, timed |
//! | open, **expired** | either | `TIMEOUT` |
//! | open, not expired | false | `TIMED_REQUEST_MISMATCH` |
//! | none | true | `TIMED_REQUEST_MISMATCH` |
//! | none | false | proceed, untimed |
//!
//! The two failures stay distinct: `TIMEOUT` means retry with a longer timeout,
//! `TIMED_REQUEST_MISMATCH` means the client is wrong. Both were `UNSUPPORTED_ACCESS` before
//! Matter 1.4.

use crate::msg::{ExchangeId, SessionId};
use crate::platform::{Duration, Instant};

use super::status::Status;

/// One open Timed transaction window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    /// The session the Timed Request arrived on.
    session: Option<SessionId>,
    /// The exchange — §8.7.3.2's "matching the same TransactionID".
    exchange: ExchangeId,
    /// When the window closes.
    deadline: Instant,
}

/// The open Timed transaction windows of a node.
///
/// `N` is how many may be open at once. One per concurrent administrator is generous: a Timed
/// transaction's whole life is one round trip plus a timeout the *client* chose, and a client
/// with two open at once on the same session is already misbehaving.
#[derive(Debug, Clone)]
pub struct TimedWindows<const N: usize> {
    windows: [Option<Window>; N],
}

impl<const N: usize> Default for TimedWindows<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TimedWindows<N> {
    /// A table with nothing open.
    #[must_use]
    pub const fn new() -> Self {
        Self { windows: [None; N] }
    }

    /// Opens a window, as §8.7.4.3 requires after answering a Timed Request.
    ///
    /// `sent_at` is when the `SUCCESS` status response went out, **not** when the Timed Request
    /// arrived: §8.7.4, "the Timeout interval SHALL start when the Status Response action
    /// acknowledging the Timed Request action with a success code is sent".
    ///
    /// A second Timed Request on the same exchange replaces the first: one transaction, one
    /// deadline.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::NoSpace`](crate::ErrorCode::NoSpace) when every slot holds a live window —
    /// §8.7.3.2's `BUSY` case, so a caller answers [`Status::Busy`] rather than pretending the
    /// window opened.
    pub fn open(
        &mut self,
        session: Option<SessionId>,
        exchange: ExchangeId,
        timeout_ms: u16,
        sent_at: Instant,
    ) -> crate::Result<()> {
        let window = Window {
            session,
            exchange,
            deadline: sent_at.saturating_add(Duration::from_millis(u64::from(timeout_ms))),
        };
        if let Some(slot) = self.slot_for(session, exchange) {
            *slot = Some(window);
            return Ok(());
        }
        if let Some(slot) = self.windows.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(window);
            return Ok(());
        }
        // Every slot is taken. An expired window is a window whose client is not coming back,
        // so it is the one to give up — at the cost that its owner now gets
        // TIMED_REQUEST_MISMATCH instead of TIMEOUT if it turns up after all. Both are
        // refusals, and holding the slot would refuse a client that is on time.
        let oldest_expired = self
            .windows
            .iter_mut()
            .filter(|slot| slot.is_some_and(|w| w.deadline <= sent_at))
            .min_by_key(|slot| slot.map(|w| w.deadline));
        if let Some(slot) = oldest_expired {
            *slot = Some(window);
            return Ok(());
        }
        Err(crate::Error::new(crate::ErrorCode::NoSpace))
    }

    /// Applies §8.7.3.2 and §8.8.2.3's timed rules to an arriving Write or Invoke Request.
    ///
    /// `timed_request` is the request's own `TimedRequest` flag. Returns what
    /// [`InteractionContext::timed`](super::server::InteractionContext::timed) must be set to,
    /// or the status the interaction terminates with.
    ///
    /// The window is **consumed** either way — every outcome here terminates the transaction,
    /// and a window that survived would let one Timed Request pay for a second request later.
    ///
    /// # Errors
    ///
    /// [`Status::Timeout`] when the window expired, [`Status::TimedRequestMismatch`] when the
    /// flag and the window disagree.
    pub fn check(
        &mut self,
        session: Option<SessionId>,
        exchange: ExchangeId,
        timed_request: bool,
        now: Instant,
    ) -> core::result::Result<bool, Status> {
        let Some(slot) = self.slot_for(session, exchange) else {
            // §8.8.2.3 rule 3: "If this action is marked with TimedRequest as TRUE, but this
            // action is not part of a Timed Invoke transaction … TIMED_REQUEST_MISMATCH".
            return if timed_request {
                Err(Status::TimedRequestMismatch)
            } else {
                Ok(false)
            };
        };
        let expired = slot.is_some_and(|window| now > window.deadline);
        *slot = None;
        if expired {
            // §8.8.2.3 rule 1 is checked before rule 2: an expired window is TIMEOUT whatever
            // the flag says. A client that is both late and wrong is told it was late, which is
            // the fault it can do something about.
            return Err(Status::Timeout);
        }
        if !timed_request {
            // §8.8.2.3 rule 2.
            return Err(Status::TimedRequestMismatch);
        }
        Ok(true)
    }

    /// Closes the window on an exchange without applying any rule.
    ///
    /// For the case where the exchange itself ends — the session closed, the client vanished —
    /// rather than a request arriving on it.
    pub fn close(&mut self, session: Option<SessionId>, exchange: ExchangeId) {
        if let Some(slot) = self.slot_for(session, exchange) {
            *slot = None;
        }
    }

    /// Drops every window of a session, for when the session closes.
    pub fn close_session(&mut self, session: Option<SessionId>) {
        for slot in &mut self.windows {
            if slot.is_some_and(|window| window.session == session) {
                *slot = None;
            }
        }
    }

    /// Drops every window whose deadline has passed, returning how many went.
    ///
    /// Optional: [`TimedWindows::open`] already reclaims expired slots when it needs one. A
    /// window dropped here can no longer produce [`Status::Timeout`], only
    /// [`Status::TimedRequestMismatch`], since the evidence that there was a window is gone.
    pub fn reap(&mut self, now: Instant) -> usize {
        let mut reaped = 0usize;
        for slot in &mut self.windows {
            if slot.is_some_and(|window| now > window.deadline) {
                *slot = None;
                reaped = reaped.saturating_add(1);
            }
        }
        reaped
    }

    /// How many windows are held, expired or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.windows.iter().filter(|slot| slot.is_some()).count()
    }

    /// Whether no window is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The earliest deadline, for a caller that wants to schedule a reap.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.windows
            .iter()
            .filter_map(|slot| slot.map(|window| window.deadline))
            .min()
    }

    fn slot_for(
        &mut self,
        session: Option<SessionId>,
        exchange: ExchangeId,
    ) -> Option<&mut Option<Window>> {
        self.windows.iter_mut().find(|slot| {
            slot.is_some_and(|window| window.session == session && window.exchange == exchange)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: Option<SessionId> = Some(SessionId(7));
    const EXCHANGE: ExchangeId = ExchangeId(42);

    fn at(ms: u64) -> Instant {
        Instant::ZERO.saturating_add(Duration::from_millis(ms))
    }

    #[test]
    fn an_untimed_request_with_no_window_proceeds() {
        let mut windows = TimedWindows::<2>::new();
        assert_eq!(windows.check(SESSION, EXCHANGE, false, at(0)), Ok(false));
    }

    #[test]
    fn a_timed_request_inside_the_window_proceeds() {
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 1000, at(0)).expect("open");
        assert_eq!(windows.check(SESSION, EXCHANGE, true, at(999)), Ok(true));
    }

    #[test]
    fn the_deadline_is_inclusive_of_its_last_instant() {
        // §8.7.4: "within Timeout milliseconds of sending the Status Response". A request that
        // arrives exactly on the boundary is within it.
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 100, at(0)).expect("open");
        assert_eq!(windows.check(SESSION, EXCHANGE, true, at(100)), Ok(true));

        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 100, at(0)).expect("open");
        assert_eq!(
            windows.check(SESSION, EXCHANGE, true, at(101)),
            Err(Status::Timeout)
        );
    }

    #[test]
    fn the_clock_starts_when_the_status_response_is_sent() {
        // §8.7.4: "The Timeout interval SHALL start when the Status Response action
        // acknowledging the Timed Request action with a success code is sent." A server that
        // started it on *receipt* would charge the client for its own processing.
        let mut windows = TimedWindows::<2>::new();
        // The request arrived at 0; the status response went out at 50.
        windows.open(SESSION, EXCHANGE, 100, at(50)).expect("open");
        assert_eq!(windows.check(SESSION, EXCHANGE, true, at(150)), Ok(true));
    }

    #[test]
    fn an_expired_window_is_timeout_not_mismatch() {
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 10, at(0)).expect("open");
        assert_eq!(
            windows.check(SESSION, EXCHANGE, true, at(11)),
            Err(Status::Timeout)
        );
    }

    #[test]
    fn expiry_is_checked_before_the_flag() {
        // §8.8.2.3 lists them in that order. A client that is both late and has its flag clear
        // is told it was late — the fault it can act on.
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 10, at(0)).expect("open");
        assert_eq!(
            windows.check(SESSION, EXCHANGE, false, at(11)),
            Err(Status::Timeout)
        );
    }

    #[test]
    fn a_timed_window_with_an_untimed_request_is_a_mismatch() {
        // §8.8.2.3 rule 2.
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 1000, at(0)).expect("open");
        assert_eq!(
            windows.check(SESSION, EXCHANGE, false, at(1)),
            Err(Status::TimedRequestMismatch)
        );
    }

    #[test]
    fn an_untimed_window_with_a_timed_request_is_a_mismatch() {
        // §8.8.2.3 rule 3. This is the one a replay would hit: a captured Invoke Request with
        // `TimedRequest` set, sent again later with no Timed Request in front of it.
        let mut windows = TimedWindows::<2>::new();
        assert_eq!(
            windows.check(SESSION, EXCHANGE, true, at(0)),
            Err(Status::TimedRequestMismatch)
        );
    }

    #[test]
    fn a_window_is_consumed_by_the_request_it_admits() {
        // Every outcome terminates the transaction, so a second request must not find the
        // window still open — that would let one Timed Request pay for two writes.
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 1000, at(0)).expect("open");
        assert_eq!(windows.check(SESSION, EXCHANGE, true, at(1)), Ok(true));
        assert_eq!(
            windows.check(SESSION, EXCHANGE, true, at(2)),
            Err(Status::TimedRequestMismatch)
        );
        assert!(windows.is_empty());
    }

    #[test]
    fn a_window_is_consumed_even_by_a_request_it_refuses() {
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 1000, at(0)).expect("open");
        assert_eq!(
            windows.check(SESSION, EXCHANGE, false, at(1)),
            Err(Status::TimedRequestMismatch)
        );
        assert!(windows.is_empty());
    }

    #[test]
    fn windows_are_scoped_to_their_exchange_and_session() {
        // §8.7.3.2: "matching the same TransactionID". Another exchange's window must not
        // admit this one's request, or one Timed Request would cover a whole session.
        let mut windows = TimedWindows::<4>::new();
        windows.open(SESSION, EXCHANGE, 1000, at(0)).expect("open");
        assert_eq!(
            windows.check(SESSION, ExchangeId(43), true, at(1)),
            Err(Status::TimedRequestMismatch)
        );
        assert_eq!(
            windows.check(Some(SessionId(8)), EXCHANGE, true, at(1)),
            Err(Status::TimedRequestMismatch)
        );
        // And the original is untouched.
        assert_eq!(windows.check(SESSION, EXCHANGE, true, at(1)), Ok(true));
    }

    #[test]
    fn a_second_timed_request_on_one_exchange_replaces_the_first() {
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 10, at(0)).expect("open");
        windows.open(SESSION, EXCHANGE, 1000, at(0)).expect("open");
        assert_eq!(windows.len(), 1, "one transaction, one deadline");
        assert_eq!(windows.check(SESSION, EXCHANGE, true, at(500)), Ok(true));
    }

    #[test]
    fn a_full_table_of_live_windows_refuses() {
        let mut windows = TimedWindows::<2>::new();
        windows
            .open(SESSION, ExchangeId(1), 1000, at(0))
            .expect("open");
        windows
            .open(SESSION, ExchangeId(2), 1000, at(0))
            .expect("open");
        assert!(
            windows.open(SESSION, ExchangeId(3), 1000, at(0)).is_err(),
            "§8.7.3.2's BUSY case"
        );
        // Both live windows survive the refusal.
        assert_eq!(windows.check(SESSION, ExchangeId(1), true, at(1)), Ok(true));
    }

    #[test]
    fn a_full_table_gives_up_its_oldest_expired_window_first() {
        let mut windows = TimedWindows::<2>::new();
        windows
            .open(SESSION, ExchangeId(1), 10, at(0))
            .expect("open");
        windows
            .open(SESSION, ExchangeId(2), 20, at(0))
            .expect("open");
        windows
            .open(SESSION, ExchangeId(3), 1000, at(100))
            .expect("open");
        // Exchange 1 expired first, so it is the one that went.
        assert_eq!(
            windows.check(SESSION, ExchangeId(1), true, at(101)),
            Err(Status::TimedRequestMismatch)
        );
        assert_eq!(
            windows.check(SESSION, ExchangeId(2), true, at(101)),
            Err(Status::Timeout),
            "the later-expiring window is still there to report TIMEOUT"
        );
    }

    #[test]
    fn closing_a_session_drops_its_windows_and_leaves_others() {
        let mut windows = TimedWindows::<4>::new();
        windows
            .open(SESSION, ExchangeId(1), 1000, at(0))
            .expect("open");
        windows
            .open(Some(SessionId(8)), ExchangeId(1), 1000, at(0))
            .expect("open");
        windows.close_session(SESSION);
        assert_eq!(windows.len(), 1);
        assert_eq!(
            windows.check(Some(SessionId(8)), ExchangeId(1), true, at(1)),
            Ok(true)
        );
    }

    #[test]
    fn reaping_trades_timeout_for_mismatch() {
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 10, at(0)).expect("open");
        assert_eq!(windows.reap(at(11)), 1);
        // The evidence that there was ever a window is gone, so the late client is told its
        // flag was wrong rather than that it was slow. Both refuse; only one is informative.
        assert_eq!(
            windows.check(SESSION, EXCHANGE, true, at(12)),
            Err(Status::TimedRequestMismatch)
        );
    }

    #[test]
    fn reaping_leaves_live_windows_alone() {
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 1000, at(0)).expect("open");
        assert_eq!(windows.reap(at(11)), 0);
        assert_eq!(windows.check(SESSION, EXCHANGE, true, at(12)), Ok(true));
    }

    #[test]
    fn the_next_deadline_is_the_earliest() {
        let mut windows = TimedWindows::<4>::new();
        assert_eq!(windows.next_deadline(), None);
        windows
            .open(SESSION, ExchangeId(1), 500, at(0))
            .expect("open");
        windows
            .open(SESSION, ExchangeId(2), 100, at(0))
            .expect("open");
        assert_eq!(windows.next_deadline(), Some(at(100)));
    }

    #[test]
    fn a_zero_timeout_expires_immediately_but_still_reports_timeout() {
        // A client may legally ask for zero. It gets one instant, and after that TIMEOUT —
        // not a mismatch, because the window really did exist.
        let mut windows = TimedWindows::<2>::new();
        windows.open(SESSION, EXCHANGE, 0, at(0)).expect("open");
        assert_eq!(
            windows.check(SESSION, EXCHANGE, true, at(1)),
            Err(Status::Timeout)
        );
    }
}
