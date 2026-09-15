//! Which `PBKDFParamRequest` a commissionee may answer (Core §5.5).
//!
//! [`sc::PaseResponder`](crate::sc::PaseResponder) runs *one* PASE handshake. Nothing in it
//! decides whether that handshake should have been started, and §5.5 has three rules that say
//! it should not — each one a countermeasure against an online attack on a six-digit passcode:
//!
//! 1. **One at a time.** "When a Commissioner is either in the process of establishing a PASE
//!    session with the Commissionee or has successfully established a session, the Commissionee
//!    SHALL NOT accept any more requests for new PASE sessions until one of the following
//!    events occurs: session establishment fails, the successfully established PASE session is
//!    terminated on the commissioning channel, the PASE session is established through NFC
//!    Transport Layer (NTL) and Commissionee receives a valid SELECT command."
//! 2. **Sixty seconds.** "In order to avoid locking out the Commissionee from accepting new
//!    PASE session requests indefinitely, a Commissionee SHALL expect a PASE session to be
//!    established within 60 seconds of receiving the initial request … If the PASE session is
//!    not established within the expected time window the Commissionee SHALL terminate the
//!    current session establishment using the INVALID_PARAMETER status code."
//! 3. **Twenty attempts.** "In both concurrent connection commissioning flow and non-concurrent
//!    connection commissioning flow, the Commissionee SHALL exit Commissioning Mode after 20
//!    failed attempts."
//!
//! And one more, which is the same question asked of a node that is already on a fabric: "Once
//! a Commissionee has been successfully commissioned by a Commissioner into its fabric, the
//! commissioned Node SHALL NOT accept any more PASE requests until any one of the following
//! conditions is met: Device is factory-reset. Device enters commissioning mode."
//!
//! # Why these are here rather than left to the application
//!
//! Rule 1 is the one with teeth, and it is not obvious. Without it an attacker does not need
//! to guess the passcode at all: it waits for the owner to start commissioning, sends its own
//! `PBKDFParamRequest` mid-handshake, and the device — having replaced the in-flight responder
//! with a fresh one — finishes the handshake with the attacker instead. That is a takeover of
//! an *uncommissioned* device with no physical access, which is exactly the threat §5.5's
//! physical-interaction requirement exists to prevent.
//!
//! Rules 2 and 3 are what keep a 10⁸-passcode space out of reach: without a retry limit, and
//! without a bound on how long one attempt may occupy the channel, an attacker can try passcodes
//! continuously. All three are cheap to implement, easy to leave out, and invisible when absent —
//! a device missing them commissions perfectly.
//!
//! # Shape
//!
//! Sans-I/O and clock-free, like everything else here: time arrives as a parameter, so the
//! sixty-second rule is a test that runs in microseconds rather than a minute
//! ([`platform::sim`](crate::platform::sim)). It owns no cryptography and no session — it
//! answers one question, and the caller does the work.
//!
//! ```
//! use matter_kit::commissioning::{Admit, PaseAdmission};
//! use matter_kit::platform::Instant;
//!
//! let mut gate = PaseAdmission::new();
//! let t0 = Instant::ZERO;
//!
//! // A factory-new device answers the first request.
//! assert_eq!(gate.admit(true, t0), Admit::Admitted);
//! // …and refuses the second while the first is still in flight (§5.5 rule 1).
//! assert_eq!(gate.admit(true, t0), Admit::Busy);
//! ```

use crate::platform::{Duration, Instant};

/// How long a commissionee waits for `Pake3` before giving up (§5.5).
///
/// "a Commissionee SHALL expect a PASE session to be established within 60 seconds of
/// receiving the initial request. This means the Commissionee SHALL expect to receive the
/// PAKE3 message within 60 seconds after sending a PBKDFParamResponse."
pub const PASE_ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(60);

/// How many failed attempts end commissioning mode (§5.5; `CM100` for threats `T101`, `T112`).
///
/// "the Commissionee SHALL exit Commissioning Mode after 20 failed attempts."
pub const MAX_FAILED_ATTEMPTS: u8 = 20;

/// What a commissionee should do with an arriving `PBKDFParamRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Admit {
    /// Answer it: build a [`PaseResponder`](crate::sc::PaseResponder) and reply with
    /// `PBKDFParamResponse`.
    ///
    /// The sixty-second clock is now running; the caller must report the outcome with
    /// [`PaseAdmission::established`] or [`PaseAdmission::failed`], or let
    /// [`PaseAdmission::poll`] time it out.
    Admitted,
    /// Refuse: another PASE session is being established, or one is established and has not
    /// been closed (§5.5 rule 1).
    ///
    /// The refusal is a `StatusReport` carrying
    /// [`SecureChannelCode::Busy`](crate::sc::SecureChannelCode::Busy) — "Indication that the
    /// sender cannot currently fulfill the request".
    Busy,
    /// Refuse: the node is not in commissioning mode.
    ///
    /// Either it is commissioned and no window is open — "the commissioned Node SHALL NOT
    /// accept any more PASE requests until … Device is factory-reset \[or\] Device enters
    /// commissioning mode" — or the window it had has expired.
    NotCommissionable,
    /// Refuse: [`MAX_FAILED_ATTEMPTS`] have failed and the node has left commissioning mode.
    ///
    /// Distinct from [`Admit::NotCommissionable`] because the cause is different and an
    /// integrator debugging a device that has stopped pairing needs to be told which it is.
    AttemptsExhausted,
}

impl Admit {
    /// Whether the request may be answered.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }
}

/// What one failed attempt did to the node's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Failure {
    /// How many attempts have failed since the last reset.
    pub attempts: u8,
    /// Whether that was the last one §5.5 allows.
    ///
    /// When true the node "SHALL exit Commissioning Mode": the caller closes the commissioning
    /// window and stops advertising. [`PaseAdmission::reset`] is what lets it back in, and the
    /// only things that legitimately call it are a new `OpenCommissioningWindow` and a factory
    /// reset.
    pub exit_commissioning_mode: bool,
}

/// The commissioning channel's state: which of §5.5's three rules currently applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    /// Nothing in flight; a request may be admitted.
    Idle,
    /// A `PBKDFParamResponse` has gone out and `Pake3` has not arrived.
    Establishing {
        /// When rule 2's sixty seconds are up.
        deadline: Instant,
    },
    /// PASE succeeded and the session has not been closed.
    Established,
}

/// §5.5's gate on new PASE session requests.
///
/// One per node — the rules are about the *commissioning channel*, of which there is one,
/// not about a session or an exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaseAdmission {
    channel: Channel,
    failures: u8,
}

impl Default for PaseAdmission {
    fn default() -> Self {
        Self::new()
    }
}

impl PaseAdmission {
    /// A node that has admitted nothing yet — what a device boots with.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            channel: Channel::Idle,
            failures: 0,
        }
    }

    /// Judges an arriving `PBKDFParamRequest`, and starts the clock when it admits one.
    ///
    /// `commissionable` is whether the node is in commissioning mode at all: a window is open
    /// ([`CommissioningWindow::status`](super::CommissioningWindow::status)) or the node is
    /// factory-new and has no fabrics. It is the caller's to compute because only the caller
    /// holds the fabric table, and getting it from here would mean this module knowing about
    /// fabrics to answer a question about handshakes.
    pub fn admit(&mut self, commissionable: bool, now: Instant) -> Admit {
        // Rule 2 first: an establishment whose sixty seconds have already run out is not
        // in flight any more, and must not make the node look busy to the next commissioner.
        // Checking it here as well as in `poll` is what makes the gate correct for a caller
        // that never polls — the rule is about admitting requests, not about having a timer.
        self.expire(now);

        if self.failures >= MAX_FAILED_ATTEMPTS {
            return Admit::AttemptsExhausted;
        }
        if !commissionable {
            return Admit::NotCommissionable;
        }
        match self.channel {
            Channel::Establishing { .. } | Channel::Established => Admit::Busy,
            Channel::Idle => {
                self.channel = Channel::Establishing {
                    deadline: now.saturating_add(PASE_ESTABLISHMENT_TIMEOUT),
                };
                Admit::Admitted
            }
        }
    }

    /// Records that PASE completed: `Pake3` verified and the session installed.
    ///
    /// The channel stays closed to new requests — rule 1 holds "or has successfully
    /// established a session" — until [`PaseAdmission::closed`].
    ///
    /// The failure count is cleared. A commissioner that got the passcode right is evidence
    /// the attempts before it were somebody fumbling a QR code rather than an attack, and a
    /// device that had to be factory-reset to be re-paired after nineteen mistyped codes
    /// would be a worse device.
    pub const fn established(&mut self) {
        self.channel = Channel::Established;
        self.failures = 0;
    }

    /// Records that establishment failed — a bad `Pake3`, a malformed message, or the
    /// commissioner giving up.
    ///
    /// Frees the channel for the next commissioner, and counts against [`MAX_FAILED_ATTEMPTS`].
    pub const fn failed(&mut self) -> Failure {
        self.channel = Channel::Idle;
        self.failures = self.failures.saturating_add(1);
        Failure {
            attempts: self.failures,
            exit_commissioning_mode: self.failures >= MAX_FAILED_ATTEMPTS,
        }
    }

    /// Records that an established PASE session has been terminated on the commissioning
    /// channel — a `CloseSession` status report either way, or NTL's `SELECT` command.
    ///
    /// This is rule 1's release. It is deliberately *not* the same call as
    /// [`PaseAdmission::failed`]: closing a session that worked is not a failed attempt, and
    /// counting it as one would mean twenty successful commissionings bricked the device.
    pub const fn closed(&mut self) {
        self.channel = Channel::Idle;
    }

    /// Clears the failure count and the channel.
    ///
    /// The two things §5.5 says re-admit a node that has left commissioning mode: "Device is
    /// factory-reset" and "Device enters commissioning mode" — so the callers are a factory
    /// reset and an accepted `OpenCommissioningWindow` / `OpenBasicCommissioningWindow`.
    pub const fn reset(&mut self) {
        self.channel = Channel::Idle;
        self.failures = 0;
    }

    /// Applies rule 2's deadline, returning the failure it recorded when one expired.
    ///
    /// `Some` means the in-flight establishment has just been abandoned and the caller owes
    /// the commissioner a `StatusReport` carrying
    /// [`SecureChannelCode::InvalidParameter`](crate::sc::SecureChannelCode::InvalidParameter)
    /// — "SHALL terminate the current session establishment using the INVALID_PARAMETER status
    /// code" — and must drop the [`PaseResponder`](crate::sc::PaseResponder) it was driving.
    pub const fn poll(&mut self, now: Instant) -> Option<Failure> {
        if self.expire(now) {
            Some(Failure {
                attempts: self.failures,
                exit_commissioning_mode: self.failures >= MAX_FAILED_ATTEMPTS,
            })
        } else {
            None
        }
    }

    /// Moves an expired establishment to `Idle`, counting it as a failure. Returns whether
    /// it did.
    const fn expire(&mut self, now: Instant) -> bool {
        if let Channel::Establishing { deadline } = self.channel
            && now.as_micros() > deadline.as_micros()
        {
            self.channel = Channel::Idle;
            self.failures = self.failures.saturating_add(1);
            return true;
        }
        false
    }

    /// When [`PaseAdmission::poll`] next has something to do, for the event loop's timer.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        match self.channel {
            Channel::Establishing { deadline } => Some(deadline),
            Channel::Idle | Channel::Established => None,
        }
    }

    /// How many attempts have failed since the last [`PaseAdmission::reset`].
    #[must_use]
    pub const fn failures(&self) -> u8 {
        self.failures
    }

    /// Whether the node has left commissioning mode under rule 3.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.failures >= MAX_FAILED_ATTEMPTS
    }

    /// Whether a PASE session is established and not yet closed.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.channel, Channel::Established)
    }

    /// Whether a handshake is in flight.
    #[must_use]
    pub const fn is_establishing(&self) -> bool {
        matches!(self.channel, Channel::Establishing { .. })
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn at(secs: u64) -> Instant {
        Instant::ZERO.saturating_add(Duration::from_secs(secs))
    }

    #[test]
    fn a_factory_new_node_admits_the_first_request() {
        let mut gate = PaseAdmission::new();
        assert_eq!(gate.admit(true, at(0)), Admit::Admitted);
        assert!(gate.is_establishing());
    }

    /// §5.5 rule 1, and the reason the module exists: the second commissioner is refused
    /// rather than allowed to replace the first.
    #[test]
    fn a_second_request_while_establishing_is_refused() {
        let mut gate = PaseAdmission::new();
        assert_eq!(gate.admit(true, at(0)), Admit::Admitted);
        assert_eq!(gate.admit(true, at(1)), Admit::Busy);
        assert_eq!(gate.admit(true, at(59)), Admit::Busy);
    }

    #[test]
    fn a_request_while_a_session_is_established_is_refused() {
        let mut gate = PaseAdmission::new();
        assert!(gate.admit(true, at(0)).is_admitted());
        gate.established();
        assert_eq!(gate.admit(true, at(1)), Admit::Busy);
        // …until the commissioning channel closes it.
        gate.closed();
        assert_eq!(gate.admit(true, at(2)), Admit::Admitted);
    }

    #[test]
    fn a_failed_establishment_frees_the_channel() {
        let mut gate = PaseAdmission::new();
        assert!(gate.admit(true, at(0)).is_admitted());
        let failure = gate.failed();
        assert_eq!(failure.attempts, 1);
        assert!(!failure.exit_commissioning_mode);
        assert_eq!(gate.admit(true, at(1)), Admit::Admitted);
    }

    /// §5.5 rule 2. The whole point of driving time as a parameter: sixty seconds is one line.
    #[test]
    fn an_establishment_expires_after_sixty_seconds() {
        let mut gate = PaseAdmission::new();
        assert!(gate.admit(true, at(0)).is_admitted());
        assert_eq!(
            gate.poll(at(60)),
            None,
            "exactly on the deadline is not late"
        );
        let Some(failure) = gate.poll(at(61)) else {
            panic!("the deadline passed")
        };
        assert_eq!(failure.attempts, 1);
        assert!(!gate.is_establishing());
        assert_eq!(gate.admit(true, at(62)), Admit::Admitted);
    }

    /// The rule must hold for a caller that never polls, or a node without a timer would stay
    /// busy forever after one abandoned handshake — which is the lock-out §5.5 names.
    #[test]
    fn an_expired_establishment_does_not_block_the_next_request() {
        let mut gate = PaseAdmission::new();
        assert!(gate.admit(true, at(0)).is_admitted());
        assert_eq!(gate.admit(true, at(61)), Admit::Admitted);
        assert_eq!(gate.failures(), 1, "the abandoned attempt still counted");
    }

    /// §5.5 rule 3 / CM100.
    #[test]
    fn twenty_failures_end_commissioning_mode() {
        let mut gate = PaseAdmission::new();
        for n in 1..MAX_FAILED_ATTEMPTS {
            assert!(gate.admit(true, at(0)).is_admitted(), "attempt {n}");
            let failure = gate.failed();
            assert!(!failure.exit_commissioning_mode, "attempt {n}");
        }
        assert!(gate.admit(true, at(0)).is_admitted());
        let last = gate.failed();
        assert_eq!(last.attempts, MAX_FAILED_ATTEMPTS);
        assert!(last.exit_commissioning_mode);
        assert!(gate.is_exhausted());
        assert_eq!(gate.admit(true, at(0)), Admit::AttemptsExhausted);
    }

    #[test]
    fn a_new_window_readmits_an_exhausted_node() {
        let mut gate = PaseAdmission::new();
        for _ in 0..MAX_FAILED_ATTEMPTS {
            let _ = gate.admit(true, at(0));
            let _ = gate.failed();
        }
        assert_eq!(gate.admit(true, at(0)), Admit::AttemptsExhausted);
        gate.reset();
        assert_eq!(gate.admit(true, at(0)), Admit::Admitted);
    }

    /// A successful commissioning is evidence the failures before it were fumbles.
    #[test]
    fn success_clears_the_failure_count() {
        let mut gate = PaseAdmission::new();
        for _ in 0..5 {
            let _ = gate.admit(true, at(0));
            let _ = gate.failed();
        }
        assert_eq!(gate.failures(), 5);
        assert!(gate.admit(true, at(0)).is_admitted());
        gate.established();
        assert_eq!(gate.failures(), 0);
    }

    /// Closing a session that worked is not a failed attempt.
    #[test]
    fn closing_an_established_session_is_not_a_failure() {
        let mut gate = PaseAdmission::new();
        assert!(gate.admit(true, at(0)).is_admitted());
        gate.established();
        gate.closed();
        assert_eq!(gate.failures(), 0);
    }

    /// "the commissioned Node SHALL NOT accept any more PASE requests until … Device enters
    /// commissioning mode."
    #[test]
    fn a_commissioned_node_with_no_window_is_not_commissionable() {
        let mut gate = PaseAdmission::new();
        assert_eq!(gate.admit(false, at(0)), Admit::NotCommissionable);
        assert!(!gate.is_establishing(), "a refusal starts no clock");
    }

    /// Rule 3 outranks rule 1: a node out of attempts says so rather than saying "busy",
    /// which would read as "try again in a moment".
    #[test]
    fn exhaustion_is_reported_before_commissionability() {
        let mut gate = PaseAdmission::new();
        for _ in 0..MAX_FAILED_ATTEMPTS {
            let _ = gate.admit(true, at(0));
            let _ = gate.failed();
        }
        assert_eq!(gate.admit(false, at(0)), Admit::AttemptsExhausted);
    }

    #[test]
    fn the_deadline_is_only_live_while_establishing() {
        let mut gate = PaseAdmission::new();
        assert_eq!(gate.deadline(), None);
        assert!(gate.admit(true, at(0)).is_admitted());
        assert_eq!(gate.deadline(), Some(at(60)));
        gate.established();
        assert_eq!(
            gate.deadline(),
            None,
            "an established session has no deadline"
        );
    }
}
