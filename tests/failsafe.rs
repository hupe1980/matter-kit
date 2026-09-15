//! The fail-safe state machine against Core §11.10.7.2 and §11.10.7.2.2.
//!
//! Every assertion here is a sentence of the specification, quoted in the test name or the
//! comment above it. The expiry paths are driven by moving a virtual clock rather than by
//! waiting, which is the whole reason [`Instant`] is a parameter and not something the state
//! machine reads.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use matter_kit::commissioning::failsafe::{
    ArmOutcome, BasicCommissioningInfo, Cleanup, CommissioningError, DEFAULT_EXPIRY_SECONDS,
    DEFAULT_MAX_CUMULATIVE_SECONDS, FailSafe, Progress,
};
use matter_kit::msg::FabricIndex;
use matter_kit::platform::{Duration, Instant};

const COMMISSIONER: Option<FabricIndex> = None; // A PASE session has no accessing fabric.
const FABRIC_1: Option<FabricIndex> = Some(FabricIndex(1));
const FABRIC_2: Option<FabricIndex> = Some(FabricIndex(2));

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

fn fresh() -> FailSafe {
    FailSafe::new(BasicCommissioningInfo::default())
}

#[test]
fn enum_values_match_section_11_10_5_1() {
    // §11.10.5.1's table, as literals.
    assert_eq!(CommissioningError::Ok.value(), 0);
    assert_eq!(CommissioningError::ValueOutsideRange.value(), 1);
    assert_eq!(CommissioningError::InvalidAuthentication.value(), 2);
    assert_eq!(CommissioningError::NoFailSafe.value(), 3);
    assert_eq!(CommissioningError::BusyWithOtherAdmin.value(), 4);
    assert_eq!(CommissioningError::RequiredTcNotAccepted.value(), 5);
    assert_eq!(CommissioningError::TcAcknowledgementsNotReceived.value(), 6);
    assert_eq!(CommissioningError::TcMinVersionNotMet.value(), 7);
}

#[test]
fn defaults_match_section_11_10_5_4() {
    // "it is RECOMMENDED that the value of this field be aligned with the initial
    // Announcement Duration and default to 900 seconds."
    assert_eq!(DEFAULT_EXPIRY_SECONDS, 900);
    assert_eq!(DEFAULT_MAX_CUMULATIVE_SECONDS, 900);
    // "The value of this field SHALL be greater than or equal to the
    // FailSafeExpiryLengthSeconds."
    assert!(BasicCommissioningInfo::default().is_valid());
    assert!(
        !BasicCommissioningInfo {
            expiry_length_seconds: 600,
            max_cumulative_seconds: 300,
        }
        .is_valid()
    );
}

#[test]
fn arming_a_disarmed_context_succeeds_and_writes_the_breadcrumb() {
    let mut fs = fresh();
    assert!(!fs.is_armed(at(0)));
    // "If ExpiryLengthSeconds is non-zero and the fail-safe timer was not currently armed,
    // then the fail-safe timer SHALL be armed for that duration."
    assert_eq!(
        fs.arm(60, 0x1234, COMMISSIONER, at(0), false).outcome,
        ArmOutcome::Armed
    );
    assert!(fs.is_armed(at(59)));
    // "The value of the Breadcrumb field SHALL be written to the Breadcrumb on successful
    // execution of the command."
    assert_eq!(fs.breadcrumb(), 0x1234);
    assert_eq!(fs.next_deadline(), Some(at(60)));
}

#[test]
fn the_timer_expires_at_its_deadline() {
    let mut fs = fresh();
    fs.arm(60, 1, COMMISSIONER, at(0), false);
    assert!(fs.is_armed(at(59)));
    assert!(!fs.is_armed(at(60)));
    let cleanup = fs.expire(at(60)).expect("expired");
    // Steps 2 and 3 are unconditional.
    assert!(cleanup.close_pase_sessions);
    // Step 10: "Reset the Breadcrumb attribute to zero."
    assert_eq!(fs.breadcrumb(), 0);
    // A second expiry has nothing to do.
    assert_eq!(fs.expire(at(120)), None);
}

#[test]
fn re_arming_extends_the_first_timer_but_never_the_cumulative_one() {
    // §11.10.7.2: the CFSC timer "SHALL NOT be extended or modified on subsequent
    // invocations of ArmFailSafe associated with this Fail Safe Context."
    let mut fs = FailSafe::new(BasicCommissioningInfo {
        expiry_length_seconds: 60,
        max_cumulative_seconds: 100,
    });
    fs.arm(60, 1, COMMISSIONER, at(0), false);
    assert_eq!(fs.armed(at(0)).unwrap().cumulative_expires_at, at(100));

    // Re-arm at t=50 for another 60 seconds. The first timer moves to t=110 — but the
    // cumulative one still ends the context at t=100.
    assert_eq!(
        fs.arm(60, 2, COMMISSIONER, at(50), false).outcome,
        ArmOutcome::Armed
    );
    assert_eq!(fs.armed(at(50)).unwrap().cumulative_expires_at, at(100));
    assert!(fs.is_armed(at(99)));
    assert!(!fs.is_armed(at(100)));
    assert!(fs.expire(at(100)).is_some());
}

#[test]
fn re_arming_past_the_cumulative_limit_rolls_the_device_back_first() {
    // The CFSC timer does not stop an administrator arming *again* — §11.10.7.2 is explicit
    // that ending a context "SHALL also delete the CFSC timer", so the next ArmFailSafe
    // opens a fresh one. What it guarantees is that no single context outlives the limit, and
    // therefore that everything done inside one is rolled back before the next begins.
    //
    // That is the property worth testing, and it is the one a lazily-expiring implementation
    // silently breaks: without reaping the lapsed context here, the re-arm would quietly
    // adopt the device's half-commissioned state and the AddNOC would never be undone.
    let mut fs = FailSafe::new(BasicCommissioningInfo {
        expiry_length_seconds: 10,
        max_cumulative_seconds: 100,
    });
    fs.arm(10, 1, COMMISSIONER, at(0), false);
    fs.record(at(1), |p| p.added_noc = true).unwrap();
    fs.adopt_fabric(FabricIndex(4), at(1)).unwrap();

    // The commissioner keeps the fail-safe alive from the fabric it just joined, which is
    // what §11.10.7.2's "updated with the Fabric Index associated with an AddNOC" makes
    // possible — and what an administrator holding the device hostage would do.
    let mut rolled_back: Option<Cleanup> = None;
    for second in 1..=200 {
        let result = fs.arm(10, 1, Some(FabricIndex(4)), at(second), false);
        if let Some(cleanup) = result.cleanup {
            assert!(
                second >= 100,
                "the context was reaped at t={second}s, before its 100s limit"
            );
            rolled_back = Some(cleanup);
            break;
        }
    }

    let cleanup = rolled_back.expect("the context never lapsed despite the cumulative limit");
    // Step 7: the fabric the AddNOC created is removed, not inherited by the new context.
    assert_eq!(cleanup.remove_fabric, Some(FabricIndex(4)));
    // And the context the same command opened in place of it starts clean — the new
    // administrator inherits nothing.
    assert!(!fs.armed(at(100)).unwrap().progress.added_noc);
}

#[test]
fn one_context_never_outlives_the_cumulative_limit() {
    // The narrower statement, without any re-arming to muddy it.
    let mut fs = FailSafe::new(BasicCommissioningInfo {
        expiry_length_seconds: 10,
        max_cumulative_seconds: 100,
    });
    fs.arm(10, 0, COMMISSIONER, at(0), false);
    let opened = fs.armed(at(0)).unwrap().cumulative_expires_at;
    for second in 1..100 {
        fs.arm(10, 0, COMMISSIONER, at(second), false);
        assert_eq!(
            fs.armed(at(second)).unwrap().cumulative_expires_at,
            opened,
            "the CFSC timer moved at t={second}s"
        );
    }
    assert!(!fs.is_armed(at(100)));
}

#[test]
fn a_zero_expiry_from_the_same_fabric_disarms_immediately() {
    // "If ExpiryLengthSeconds is 0 and the fail-safe timer was already armed and the
    // accessing fabric matches … the fail-safe timer SHALL be immediately expired."
    let mut fs = fresh();
    fs.arm(600, 7, FABRIC_1, at(0), false);
    let result = fs.arm(0, 9, FABRIC_1, at(1), false);
    assert_eq!(result.outcome, ArmOutcome::Disarmed);
    let cleanup = result.cleanup.expect("a disarm owes its cleanup steps");
    assert!(!fs.is_armed(at(1)));
    assert!(cleanup.close_pase_sessions);
    // The disarm runs the cleanup, and step 10 resets the breadcrumb — so the command's own
    // Breadcrumb field does not survive it.
    assert_eq!(fs.breadcrumb(), 0);
}

#[test]
fn a_zero_expiry_with_nothing_armed_is_a_success_with_no_side_effects() {
    // "If ExpiryLengthSeconds is 0 and the fail-safe timer was not armed, then this command
    // invocation SHALL lead to a success response with no side-effects against the fail-safe
    // context."
    let mut fs = fresh();
    assert_eq!(
        fs.arm(0, 0x42, COMMISSIONER, at(0), false).outcome,
        ArmOutcome::NoChange
    );
    assert!(!fs.is_armed(at(0)));
    // The Breadcrumb is not part of the fail-safe context, and every successful ArmFailSafe
    // writes it.
    assert_eq!(fs.breadcrumb(), 0x42);
}

#[test]
fn a_second_administrator_is_refused_with_busy_with_other_admin() {
    // "Otherwise … BusyWithOtherAdmin, indicating a likely conflict between commissioners."
    let mut fs = fresh();
    fs.arm(600, 1, FABRIC_1, at(0), false);
    assert_eq!(
        fs.arm(600, 2, FABRIC_2, at(1), false).outcome,
        ArmOutcome::Refused(CommissioningError::BusyWithOtherAdmin)
    );
    // And the refusal changed nothing: fabric 1 still owns the context and its breadcrumb.
    assert_eq!(fs.armed(at(1)).unwrap().fabric_index, FABRIC_1);
    assert_eq!(fs.breadcrumb(), 1);
}

#[test]
fn another_admin_cannot_disarm_a_context_it_does_not_own() {
    // The zero-expiry disarm is fabric-scoped too — otherwise any administrator could cancel
    // a commissioner mid-flow and trigger its rollback.
    let mut fs = fresh();
    fs.arm(600, 1, FABRIC_1, at(0), false);
    assert_eq!(
        fs.arm(0, 0, FABRIC_2, at(1), false).outcome,
        ArmOutcome::Refused(CommissioningError::BusyWithOtherAdmin)
    );
    assert!(fs.is_armed(at(1)));
}

#[test]
fn an_open_commissioning_window_gives_pase_priority_over_case() {
    // "If the fail-safe timer is not currently armed, the commissioning window is open, and
    // the command was received over a CASE session … BusyWithOtherAdmin. This is done to
    // allow commissioners, which use PASE connections, the opportunity to use the failsafe."
    let mut fs = fresh();
    assert_eq!(
        fs.arm(600, 1, FABRIC_1, at(0), true).outcome,
        ArmOutcome::Refused(CommissioningError::BusyWithOtherAdmin)
    );
    // The same command over PASE is allowed.
    assert_eq!(
        fs.arm(600, 1, COMMISSIONER, at(0), false).outcome,
        ArmOutcome::Armed
    );
}

#[test]
fn the_window_rule_only_applies_while_nothing_is_armed() {
    // "If the fail-safe timer is **not currently armed**…" — an administrator that already
    // owns the context may re-arm it even with the window open, or a slow commissioning flow
    // would deadlock itself.
    let mut fs = fresh();
    fs.arm(600, 1, FABRIC_1, at(0), false);
    assert_eq!(
        fs.arm(600, 2, FABRIC_1, at(1), true).outcome,
        ArmOutcome::Armed
    );
}

#[test]
fn commissioning_complete_needs_a_fail_safe_a_case_session_and_the_right_fabric() {
    // §11.10.7.6's three refusals.
    let mut fs = fresh();

    // "An ErrorCode of NoFailSafe SHALL be responded to the invoker if the
    // CommissioningComplete command was received when no Fail-Safe context exists."
    assert_eq!(
        fs.complete(true, FABRIC_1, at(0)).error,
        CommissioningError::NoFailSafe
    );

    fs.arm(600, 1, FABRIC_1, at(0), false);

    // "this command is only permitted over CASE".
    assert_eq!(
        fs.complete(false, FABRIC_1, at(1)).error,
        CommissioningError::InvalidAuthentication
    );
    // "or if the accessing fabric is not the one associated with the ongoing Fail-Safe
    // context."
    assert_eq!(
        fs.complete(true, FABRIC_2, at(1)).error,
        CommissioningError::InvalidAuthentication
    );
    // None of the refusals disarmed anything.
    assert!(fs.is_armed(at(1)));

    assert_eq!(
        fs.complete(true, FABRIC_1, at(1)).error,
        CommissioningError::Ok
    );
    // Step 1: disarmed. Step 5: "The Breadcrumb attribute SHALL be reset to zero."
    assert!(!fs.is_armed(at(1)));
    assert_eq!(fs.breadcrumb(), 0);
}

#[test]
fn add_noc_moves_the_context_to_the_new_fabric() {
    // §11.10.7.2: the context's fabric index is "updated with the Fabric Index associated
    // with an AddNOC or an UpdateNOC command being invoked successfully". §11.10.7.6:
    // "After an AddNOC command has been successfully invoked, the CommissioningComplete
    // command must originate from the Fabric which was joined through the execution of that
    // command."
    let mut fs = fresh();
    // Commissioning starts over PASE, so the context has no fabric at all.
    fs.arm(600, 1, COMMISSIONER, at(0), false);
    assert_eq!(fs.armed(at(0)).unwrap().fabric_index, None);

    fs.record(at(1), |p| p.added_noc = true).unwrap();
    fs.adopt_fabric(FabricIndex(3), at(1)).unwrap();

    // Now CommissioningComplete over CASE on the new fabric is accepted…
    assert_eq!(
        fs.complete(true, Some(FabricIndex(3)), at(2)).error,
        CommissioningError::Ok
    );
}

#[test]
fn commissioning_complete_from_the_wrong_new_fabric_is_refused() {
    let mut fs = fresh();
    fs.arm(600, 1, COMMISSIONER, at(0), false);
    fs.record(at(1), |p| p.added_noc = true).unwrap();
    fs.adopt_fabric(FabricIndex(3), at(1)).unwrap();
    // …and from any other fabric it is not. Without this check, any node already on the
    // device could complete a commissioning it did not perform, keeping the half-added
    // fabric alive.
    assert_eq!(
        fs.complete(true, Some(FabricIndex(4)), at(2)).error,
        CommissioningError::InvalidAuthentication
    );
}

#[test]
fn expiry_after_add_noc_removes_the_fabric_and_closes_its_sessions() {
    // §11.10.7.2.2 steps 4 and 7.
    let mut fs = fresh();
    fs.arm(60, 1, COMMISSIONER, at(0), false);
    fs.record(at(1), |p| {
        p.added_noc = true;
        p.added_trusted_root = true;
        p.changed_networks = true;
    })
    .unwrap();
    fs.adopt_fabric(FabricIndex(5), at(1)).unwrap();

    let cleanup = fs.expire(at(60)).expect("expired");
    assert!(cleanup.close_pase_sessions); // steps 2, 3
    assert_eq!(cleanup.close_case_sessions_for, Some(FabricIndex(5))); // step 4
    assert!(cleanup.restore_networks); // step 5
    assert_eq!(cleanup.revert_noc_for, None); // step 6 — no UpdateNOC
    assert_eq!(cleanup.remove_fabric, Some(FabricIndex(5))); // step 7
    assert!(!cleanup.discard_operational_key); // step 8 — the key was used
    assert!(cleanup.prune_trusted_roots); // step 9
}

#[test]
fn expiry_after_update_noc_reverts_rather_than_removes() {
    // Step 6 reverts the fabric's credentials; step 7 must *not* fire, or an UpdateNOC that
    // timed out would delete a fabric the device was already a member of.
    let mut fs = fresh();
    fs.arm(60, 1, FABRIC_1, at(0), false);
    fs.record(at(1), |p| p.updated_noc = true).unwrap();

    let cleanup = fs.expire(at(60)).expect("expired");
    assert_eq!(cleanup.revert_noc_for, FABRIC_1);
    assert_eq!(cleanup.remove_fabric, None);
    assert_eq!(cleanup.close_case_sessions_for, FABRIC_1);
}

#[test]
fn a_csr_with_no_noc_leaves_an_orphaned_key_to_discard() {
    // Step 8: "If the CSRRequest command had been successfully invoked, but no AddNOC or
    // UpdateNOC command had been successfully invoked, then the new operational key pair …
    // SHALL be removed as it is no longer needed."
    assert!(
        Progress {
            csr_requested: true,
            ..Progress::default()
        }
        .orphaned_operational_key()
    );
    // …and once a NOC command used it, it is not orphaned.
    assert!(
        !Progress {
            csr_requested: true,
            added_noc: true,
            ..Progress::default()
        }
        .orphaned_operational_key()
    );
    assert!(
        !Progress {
            csr_requested: true,
            updated_noc: true,
            ..Progress::default()
        }
        .orphaned_operational_key()
    );
}

#[test]
fn nothing_can_be_recorded_outside_an_armed_period() {
    // §8.10.1's FAILSAFE_REQUIRED exists because a command that mutates commissioning state
    // with no fail-safe has nothing to roll it back.
    let mut fs = fresh();
    assert!(fs.record(at(0), |p| p.added_noc = true).is_err());
    assert!(fs.adopt_fabric(FabricIndex(1), at(0)).is_err());

    fs.arm(60, 0, COMMISSIONER, at(0), false);
    assert!(fs.record(at(1), |p| p.added_noc = true).is_ok());
    // …and an expired one is no better than an absent one, even before anyone calls expire().
    assert!(fs.record(at(61), |p| p.updated_noc = true).is_err());
}

#[test]
fn a_restart_is_an_expiry() {
    // "If the receiver restarts unexpectedly (e.g., power interruption, software crash, or
    // other reset) the receiver SHALL behave as if the fail-safe timer expired and perform
    // the sequence of clean-up steps listed below."
    //
    // A device models a restart by moving its clock past the deadline, which every restart
    // does: Instant is monotonic from boot, so a fail-safe armed before one is already past
    // its deadline afterwards. What this asserts is the part that must not be lost — the
    // cleanup is computed from recorded progress, so the progress has to have been kept.
    let mut fs = fresh();
    fs.arm(60, 1, COMMISSIONER, at(0), false);
    fs.record(at(1), |p| p.added_noc = true).unwrap();
    fs.adopt_fabric(FabricIndex(2), at(1)).unwrap();

    let cleanup = fs.expire(Instant::MAX).expect("a restart expires it");
    assert_eq!(cleanup.remove_fabric, Some(FabricIndex(2)));
}

#[test]
fn next_deadline_is_whichever_timer_is_sooner() {
    let mut fs = FailSafe::new(BasicCommissioningInfo {
        expiry_length_seconds: 900,
        max_cumulative_seconds: 900,
    });
    fs.arm(60, 0, COMMISSIONER, at(0), false);
    assert_eq!(fs.next_deadline(), Some(at(60)));
    // Asking for longer than the cumulative limit gets the cumulative limit.
    fs.arm(5_000, 0, COMMISSIONER, at(0), false);
    assert_eq!(fs.next_deadline(), Some(at(900)));
}
