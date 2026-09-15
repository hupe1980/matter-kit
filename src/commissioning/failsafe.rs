//! The fail-safe: what makes commissioning recoverable (Core §11.10.7.2).
//!
//! Commissioning writes a lot of state into a device — a trusted root, an operational
//! certificate, a fabric entry, a network configuration — and any of it can fail halfway. A
//! device that kept the half of it that landed would be neither commissioned nor factory
//! fresh, which is the one state nobody can recover from without a reset button.
//!
//! So every commissioning write happens inside a **fail-safe context**: a transaction with a
//! timer. If the commissioner finishes, `CommissioningComplete` disarms it and the state
//! stands. If anything goes wrong — a crash, a lost network, a commissioner that walks away
//! — the timer expires and §11.10.7.2.2's eleven cleanup steps put the device back.
//!
//! # Two timers, and why the second one cannot be extended
//!
//! `ArmFailSafe` may be called again to extend the deadline, which a commissioner doing slow
//! work needs. That alone would let a commissioner hold a device hostage forever, so
//! §11.10.7.2 adds a second timer:
//!
//! > On creation of the Fail Safe Context a second timer SHALL be created to expire at
//! > MaxCumulativeFailsafeSeconds … it SHALL NOT be extended or modified on subsequent
//! > invocations of ArmFailSafe associated with this Fail Safe Context.
//!
//! The first timer bounds one step; the second bounds the whole attempt. [`FailSafe::arm`]
//! enforces both.
//!
//! # A restart is an expiry
//!
//! > If the receiver restarts unexpectedly (e.g., power interruption, software crash, or
//! > other reset) the receiver SHALL behave as if the fail-safe timer expired and perform the
//! > sequence of clean-up steps listed below.
//!
//! Which is why nothing a fail-safe protects may be committed to persistent storage before
//! `CommissioningComplete`: a device that persisted a fabric and then lost power would come
//! back holding a fabric no commissioner knows about. [`FailSafe`] is deliberately not
//! persistable for that reason.

use crate::error::{Result, bail};
use crate::msg::FabricIndex;
use crate::platform::{Duration, Instant};

/// `CommissioningErrorEnum` (§11.10.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum CommissioningError {
    /// `0` — no error.
    Ok = 0,
    /// `1` — "Attempting to set regulatory configuration to a region or indoor/outdoor mode
    /// for which the server does not have proper configuration."
    ValueOutsideRange = 1,
    /// `2` — "Executed CommissioningComplete outside CASE session."
    InvalidAuthentication = 2,
    /// `3` — "Executed CommissioningComplete when there was no active Fail-Safe context."
    NoFailSafe = 3,
    /// `4` — "Attempting to arm fail-safe or execute CommissioningComplete from a fabric
    /// different than the one associated with the current fail-safe context."
    BusyWithOtherAdmin = 4,
    /// `5` — a required Terms and Conditions feature was not accepted.
    RequiredTcNotAccepted = 5,
    /// `6` — no or insufficient Terms and Conditions acknowledgements.
    TcAcknowledgementsNotReceived = 6,
    /// `7` — the acknowledged Terms and Conditions version is below the minimum.
    TcMinVersionNotMet = 7,
}

impl CommissioningError {
    /// The value the enum encodes as.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Whether this is [`CommissioningError::Ok`].
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// "a conservative initial duration (in seconds) to set in the FailSafe for the commissioning
/// flow to complete successfully" — §11.10.7.2's `ExpiryLengthSeconds` fallback.
pub const DEFAULT_EXPIRY_SECONDS: u16 = 900;

/// §11.10.5.4: "it is RECOMMENDED that the value of this field be aligned with the initial
/// Announcement Duration and default to 900 seconds."
pub const DEFAULT_MAX_CUMULATIVE_SECONDS: u16 = 900;

/// `BasicCommissioningInfo` (§11.10.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicCommissioningInfo {
    /// `FailSafeExpiryLengthSeconds [0]`.
    pub expiry_length_seconds: u16,
    /// `MaxCumulativeFailsafeSeconds [1]`, which "SHALL be greater than or equal to the
    /// FailSafeExpiryLengthSeconds".
    pub max_cumulative_seconds: u16,
}

impl Default for BasicCommissioningInfo {
    fn default() -> Self {
        Self {
            expiry_length_seconds: DEFAULT_EXPIRY_SECONDS,
            max_cumulative_seconds: DEFAULT_MAX_CUMULATIVE_SECONDS,
        }
    }
}

impl BasicCommissioningInfo {
    /// Checks §11.10.5.4's ordering constraint.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.max_cumulative_seconds >= self.expiry_length_seconds
    }
}

/// What has happened inside the current fail-safe period, and therefore what must be undone.
///
/// §11.10.7.2's "Fail Safe Context" lists exactly this state. Each flag decides one of
/// §11.10.7.2.2's cleanup steps: without them, expiry could not tell a device that merely
/// armed a fail-safe from one that joined a fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// "Whether an AddNOC command … has taken place" — step 7 removes the fabric it added.
    pub added_noc: bool,
    /// Whether `UpdateNOC` has — step 6 reverts that fabric's credentials.
    pub updated_noc: bool,
    /// Whether `CSRRequest` has — step 8 discards the operational key it generated, but only
    /// if no NOC command used it.
    pub csr_requested: bool,
    /// Whether `AddTrustedRootCertificate` has — step 9 removes roots no fabric references.
    pub added_trusted_root: bool,
    /// Whether the Network Commissioning `Networks` attribute was touched — step 5 restores
    /// it.
    pub changed_networks: bool,
}

impl Progress {
    /// Whether the operational key from a `CSRRequest` is now orphaned.
    ///
    /// §11.10.7.2.2 step 8: "If the CSRRequest command had been successfully invoked, but no
    /// AddNOC or UpdateNOC command had been successfully invoked, then the new operational
    /// key pair … SHALL be removed as it is no longer needed."
    #[must_use]
    pub const fn orphaned_operational_key(&self) -> bool {
        self.csr_requested && !self.added_noc && !self.updated_noc
    }
}

/// The armed fail-safe context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Armed {
    /// When the current `ExpiryLengthSeconds` runs out.
    pub expires_at: Instant,
    /// When the cumulative timer runs out. Never extended.
    pub cumulative_expires_at: Instant,
    /// The fabric the context is scoped to.
    ///
    /// "starting at the accessing fabric index for the ArmFailSafe command, and updated with
    /// the Fabric Index associated with an AddNOC or an UpdateNOC command being invoked
    /// successfully". `None` on a PASE session, which has no accessing fabric.
    pub fabric_index: Option<FabricIndex>,
    /// What has happened so far.
    pub progress: Progress,
}

/// The fail-safe state machine (§11.10.7.2).
///
/// Holds no timer of its own: every method takes the current [`Instant`], so the same code
/// runs against `platform::sim`'s virtual clock in a test and a real one on a device — which
/// is how the expiry paths get tested at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailSafe {
    info: BasicCommissioningInfo,
    armed: Option<Armed>,
    /// §11.10.6.1's `Breadcrumb`. Reset to zero on expiry (step 10), on
    /// `CommissioningComplete` (step 5), and "on start/restart of the server".
    breadcrumb: u64,
}

/// What a caller must do after the fail-safe expired (§11.10.7.2.2).
///
/// The cleanup steps touch the fabric table, the session table, the key store and the network
/// configuration — none of which this module owns. So expiry *reports* what must be undone
/// and the caller does it, which is also what keeps the eleven steps auditable against the
/// specification rather than buried in a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cleanup {
    /// Step 2 and 3: terminate any open PASE session and revoke its administrative privilege.
    pub close_pase_sessions: bool,
    /// Step 4: terminate CASE sessions for this fabric, if a NOC command recorded one.
    pub close_case_sessions_for: Option<FabricIndex>,
    /// Step 5: restore the `Networks` attribute.
    pub restore_networks: bool,
    /// Step 6: revert this fabric's operational key, NOC and ICAC.
    pub revert_noc_for: Option<FabricIndex>,
    /// Step 7: remove the fabric `AddNOC` added, as though by `RemoveFabric`.
    pub remove_fabric: Option<FabricIndex>,
    /// Step 8: discard the operational key a `CSRRequest` generated and nothing used.
    pub discard_operational_key: bool,
    /// Step 9: remove trusted roots no fabric references.
    pub prune_trusted_roots: bool,
}

impl FailSafe {
    /// A disarmed fail-safe.
    #[must_use]
    pub const fn new(info: BasicCommissioningInfo) -> Self {
        Self {
            info,
            armed: None,
            breadcrumb: 0,
        }
    }

    /// The `BasicCommissioningInfo` attribute.
    #[must_use]
    pub const fn info(&self) -> BasicCommissioningInfo {
        self.info
    }

    /// The `Breadcrumb` attribute (§11.10.6.1).
    #[must_use]
    pub const fn breadcrumb(&self) -> u64 {
        self.breadcrumb
    }

    /// Writes the `Breadcrumb`. Its content "is unspecified and its value is not otherwise
    /// used by the functioning of any cluster".
    pub const fn set_breadcrumb(&mut self, value: u64) {
        self.breadcrumb = value;
    }

    /// Whether a context is currently armed, as of `now`.
    ///
    /// Expiry is *lazy*: nothing here runs on a timer, so a caller that never asks never
    /// learns. A device drives this from its own timer and from
    /// [`FailSafe::next_deadline`].
    #[must_use]
    pub fn is_armed(&self, now: Instant) -> bool {
        self.armed
            .is_some_and(|armed| !Self::has_expired(&armed, now))
    }

    /// The armed context, if one is live as of `now`.
    #[must_use]
    pub fn armed(&self, now: Instant) -> Option<Armed> {
        self.armed.filter(|armed| !Self::has_expired(armed, now))
    }

    /// When the next expiry is due, whichever timer is sooner.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.armed.map(|armed| {
            if armed.cumulative_expires_at < armed.expires_at {
                armed.cumulative_expires_at
            } else {
                armed.expires_at
            }
        })
    }

    fn has_expired(armed: &Armed, now: Instant) -> bool {
        now >= armed.expires_at || now >= armed.cumulative_expires_at
    }

    /// `ArmFailSafe` (§11.10.7.2).
    ///
    /// `accessing_fabric` is the fabric of the session the command arrived on — `None` for a
    /// PASE session, which is the ordinary case during initial commissioning.
    /// `window_open_over_case` is the one condition that is not about the timer:
    ///
    /// > If the fail-safe timer is not currently armed, the commissioning window is open, and
    /// > the command was received over a CASE session … respond with … BusyWithOtherAdmin.
    /// > This is done to allow commissioners, which use PASE connections, the opportunity to
    /// > use the failsafe during the relatively short commissioning window.
    ///
    /// That is not a conflict between two administrators — it is a *priority* rule, holding
    /// the fail-safe for the commissioner that is mid-flow over PASE.
    pub fn arm(
        &mut self,
        expiry_length_seconds: u16,
        breadcrumb: u64,
        accessing_fabric: Option<FabricIndex>,
        now: Instant,
        window_open_over_case: bool,
    ) -> ArmResult {
        // A context that lapsed while nobody was looking is still owed its cleanup. A device
        // drives that from its own timer ([`FailSafe::next_deadline`]), but a device without
        // one would otherwise discard the lapsed context here — keeping the half-added fabric
        // that step 7 exists to remove.
        let lapsed = self.expire(now);

        let live = self.armed(now);

        let outcome = if live.is_none() && window_open_over_case {
            ArmOutcome::Refused(CommissioningError::BusyWithOtherAdmin)
        } else {
            match (expiry_length_seconds, live) {
                // "If ExpiryLengthSeconds is 0 and the fail-safe timer was already armed and
                // the accessing fabric matches … the fail-safe timer SHALL be immediately
                // expired (see further below for side-effects of expiration)."
                (0, Some(armed)) if armed.fabric_index == accessing_fabric => {
                    let cleanup = self.expire_now(armed);
                    return ArmResult {
                        outcome: ArmOutcome::Disarmed,
                        // Only one context can be live, so `lapsed` is necessarily `None`
                        // here; `or` keeps that an invariant rather than an assumption.
                        cleanup: lapsed.or(Some(cleanup)),
                    };
                }
                // "If ExpiryLengthSeconds is 0 and the fail-safe timer was not armed, then
                // this command invocation SHALL lead to a success response with no
                // side-effects against the fail-safe context." The Breadcrumb is not part of
                // that context — "The value of the Breadcrumb field SHALL be written to the
                // Breadcrumb on successful execution of the command" applies to every
                // success — so it lands.
                (0, None) => {
                    self.breadcrumb = breadcrumb;
                    ArmOutcome::NoChange
                }
                // A zero expiry from a different fabric is the conflict case: otherwise any
                // administrator could cancel a commissioner mid-flow and trigger its
                // rollback.
                (0, Some(_)) => ArmOutcome::Refused(CommissioningError::BusyWithOtherAdmin),
                // "If ExpiryLengthSeconds is non-zero and the fail-safe timer was not
                // currently armed, then the fail-safe timer SHALL be armed for that
                // duration."
                (seconds, None) => {
                    let cumulative = now.saturating_add(Duration::from_secs(u64::from(
                        self.info.max_cumulative_seconds,
                    )));
                    self.armed = Some(Armed {
                        expires_at: Self::deadline(now, seconds, cumulative),
                        cumulative_expires_at: cumulative,
                        fabric_index: accessing_fabric,
                        progress: Progress::default(),
                    });
                    self.breadcrumb = breadcrumb;
                    ArmOutcome::Armed
                }
                // "…and the accessing Fabric matches the fail-safe context's associated
                // Fabric, then the fail-safe timer SHALL be re-armed to expire in
                // ExpiryLengthSeconds."
                (seconds, Some(armed)) if armed.fabric_index == accessing_fabric => {
                    // The cumulative timer is *not* touched: that is what stops an
                    // administrator extending a hold on the device indefinitely.
                    self.armed = Some(Armed {
                        expires_at: Self::deadline(now, seconds, armed.cumulative_expires_at),
                        ..armed
                    });
                    self.breadcrumb = breadcrumb;
                    ArmOutcome::Armed
                }
                // "Otherwise … BusyWithOtherAdmin, indicating a likely conflict between
                // commissioners."
                (_, Some(_)) => ArmOutcome::Refused(CommissioningError::BusyWithOtherAdmin),
            }
        };

        ArmResult {
            outcome,
            cleanup: lapsed,
        }
    }

    /// The expiry instant, clamped so it can never outlast the cumulative timer.
    fn deadline(now: Instant, seconds: u16, cumulative: Instant) -> Instant {
        let requested = now.saturating_add(Duration::from_secs(u64::from(seconds)));
        if requested > cumulative {
            cumulative
        } else {
            requested
        }
    }

    /// Records that something happened inside the fail-safe period.
    ///
    /// Returns [`ErrorCode::InvalidState`](crate::error::ErrorCode::InvalidState) when nothing is armed, which is what makes
    /// §11.18's `FAILSAFE_REQUIRED` reachable: a command that mutates commissioning state
    /// outside a fail-safe has nothing to be rolled back by.
    pub fn record(&mut self, now: Instant, f: impl FnOnce(&mut Progress)) -> Result<()> {
        let Some(armed) = self.armed.as_mut().filter(|a| !Self::has_expired(a, now)) else {
            bail!(InvalidState)
        };
        f(&mut armed.progress);
        Ok(())
    }

    /// Moves the context to the fabric an `AddNOC` or `UpdateNOC` just created or changed.
    ///
    /// §11.10.7.2: the context's fabric index is "updated with the Fabric Index associated
    /// with an AddNOC or an UpdateNOC command being invoked successfully". That is what lets
    /// `CommissioningComplete` arrive over CASE on the *new* fabric and still match.
    pub fn adopt_fabric(&mut self, fabric: FabricIndex, now: Instant) -> Result<()> {
        let Some(armed) = self.armed.as_mut().filter(|a| !Self::has_expired(a, now)) else {
            bail!(InvalidState)
        };
        armed.fabric_index = Some(fabric);
        Ok(())
    }

    /// `CommissioningComplete` (§11.10.7.6).
    ///
    /// `over_case` and `accessing_fabric` describe the session it arrived on. The three
    /// refusals are exactly the ones §11.10.7.6 names, and the order matters: a command with
    /// no fail-safe at all is `NoFailSafe` whether or not it came over CASE.
    pub fn complete(
        &mut self,
        over_case: bool,
        accessing_fabric: Option<FabricIndex>,
        now: Instant,
    ) -> CompleteResult {
        // As in [`FailSafe::arm`]: a context that lapsed unobserved is still owed its
        // cleanup, and this is the last moment to notice before answering `NoFailSafe`.
        let lapsed = self.expire(now);

        let Some(armed) = self.armed(now) else {
            // "An ErrorCode of NoFailSafe SHALL be responded to the invoker if the
            // CommissioningComplete command was received when no Fail-Safe context exists."
            return CompleteResult {
                error: CommissioningError::NoFailSafe,
                cleanup: lapsed,
            };
        };
        if !over_case {
            // "this command is only permitted over CASE … An ErrorCode of
            // InvalidAuthentication SHALL be responded" otherwise.
            return CompleteResult {
                error: CommissioningError::InvalidAuthentication,
                cleanup: lapsed,
            };
        }
        if accessing_fabric.is_none() || accessing_fabric != armed.fabric_index {
            // "or if the accessing fabric is not the one associated with the ongoing
            // Fail-Safe context." After AddNOC that is the *new* fabric, which
            // `adopt_fabric` recorded.
            return CompleteResult {
                error: CommissioningError::InvalidAuthentication,
                cleanup: lapsed,
            };
        }

        // Steps 1 and 5. Steps 2, 3 and 4 touch the commissioning window and the session
        // table, which this does not own — [`Completion`](crate::clusters::
        // general_commissioning::Completion) reports them.
        self.armed = None;
        self.breadcrumb = 0;
        CompleteResult {
            error: CommissioningError::Ok,
            cleanup: lapsed,
        }
    }

    /// Expires the context and reports §11.10.7.2.2's cleanup steps.
    ///
    /// Call this when [`FailSafe::next_deadline`] passes, and on start-up: "If the receiver
    /// restarts unexpectedly … the receiver SHALL behave as if the fail-safe timer expired."
    ///
    /// Returns `None` if nothing was armed.
    pub fn expire(&mut self, now: Instant) -> Option<Cleanup> {
        let armed = self.armed?;
        if !Self::has_expired(&armed, now) {
            return None;
        }
        Some(self.expire_now(armed))
    }

    /// Expires `armed`, whatever the time — what `ArmFailSafe(0)` does.
    fn expire_now(&mut self, armed: Armed) -> Cleanup {
        self.armed = None;
        // Step 10: "Reset the Breadcrumb attribute to zero."
        self.breadcrumb = 0;
        let progress = armed.progress;
        Cleanup {
            // Steps 2 and 3: terminate any open PASE session and revoke the temporary
            // administrative privileges it was granted. Unconditional — §11.10.7.2.2 does not
            // make them depend on what happened during the period.
            close_pase_sessions: true,
            // Step 4: only if a NOC command recorded a fabric.
            close_case_sessions_for: (progress.added_noc || progress.updated_noc)
                .then_some(armed.fabric_index)
                .flatten(),
            // Step 5.
            restore_networks: progress.changed_networks,
            // Step 6.
            revert_noc_for: progress.updated_noc.then_some(armed.fabric_index).flatten(),
            // Step 7.
            remove_fabric: progress.added_noc.then_some(armed.fabric_index).flatten(),
            // Step 8.
            discard_operational_key: progress.orphaned_operational_key(),
            // Step 9.
            prune_trusted_roots: progress.added_trusted_root,
        }
    }
}

/// What `ArmFailSafe` did (§11.10.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmOutcome {
    /// The timer was armed or re-armed; answer `OK`.
    Armed,
    /// `ExpiryLengthSeconds` was zero and nothing was armed: a success with no side-effect
    /// on the fail-safe context. Answer `OK`.
    NoChange,
    /// `ExpiryLengthSeconds` was zero and a matching context was armed, so it expired
    /// immediately. [`ArmResult::cleanup`] carries the steps that still apply.
    Disarmed,
    /// The command was refused; answer with this error and change nothing.
    Refused(CommissioningError),
}

/// What `ArmFailSafe` produced.
///
/// `cleanup` is separate from `outcome` because the two answer different questions: the
/// outcome decides the `ErrorCode` in the response, and the cleanup is work the device owes
/// whether the command succeeded or not — a context that lapsed while nobody was watching is
/// reaped here, and dropping it on the floor would leave behind exactly the half-commissioned
/// state §11.10.7.2.2 exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmResult {
    /// What the command did; [`ArmOutcome::error_code`] turns it into a response.
    pub outcome: ArmOutcome,
    /// §11.10.7.2.2's cleanup steps, if any context ended.
    pub cleanup: Option<Cleanup>,
}

/// What `CommissioningComplete` produced (§11.10.7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteResult {
    /// The `ErrorCode` for the response.
    pub error: CommissioningError,
    /// §11.10.7.2.2's cleanup steps, owed to a context that had already lapsed. A *successful*
    /// completion produces none: it is not a rollback.
    pub cleanup: Option<Cleanup>,
}

impl ArmOutcome {
    /// The `ErrorCode` to put in an `ArmFailSafeResponse`.
    #[must_use]
    pub const fn error_code(&self) -> CommissioningError {
        match self {
            Self::Armed | Self::NoChange | Self::Disarmed => CommissioningError::Ok,
            Self::Refused(error) => *error,
        }
    }
}
