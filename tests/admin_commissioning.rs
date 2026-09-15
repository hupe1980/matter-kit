//! The Administrator Commissioning cluster against Core §11.19.
//!
//! Two things make this cluster worth its own test file. It is the only one in the crate that
//! returns **cluster-specific status codes** — §11.19.6's `Busy`, `PAKEParameterError` and
//! `WindowNotOpen`, which travel in a `StatusIB`'s `ClusterStatus` field because none of the
//! three commands has a response command. And it owns the commissioning *window*, which
//! §11.10.7.2 and §11.10.7.6 also read and write, so the state has to be genuinely shared
//! rather than copied.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use core::cell::RefCell;

use matter_kit::clusters::administrator_commissioning::{
    self as admin, AdminStatus, AdministratorCommissioning, OpenWindowRequest,
};
use matter_kit::clusters::general_commissioning::{self, GeneralCommissioning, RegulatoryLocation};
use matter_kit::clusters::{Cluster, basic_information::Location};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::{CommissioningWindow, WindowStatus};
use matter_kit::crypto::Spake2pVerifierData;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::im::{
    AccessControl, AttributePath, ClusterHandler, CommandData, CommandPath, InteractionContext,
    InvokeResponse, InvokeResponseMessage, Outcome, Server, Status, StatusIb,
};
use matter_kit::msg::{FabricIndex, VendorId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

// --- The tables ------------------------------------------------------------------------------

#[test]
fn ids_and_revision_match_section_11_19() {
    assert_eq!(admin::ID, 0x003C);
    assert_eq!(admin::REVISION, 1);
    assert_eq!(admin::FEATURE_BASIC, 1 << 0);

    assert_eq!(admin::WINDOW_STATUS, 0x0000);
    assert_eq!(admin::ADMIN_FABRIC_INDEX, 0x0001);
    assert_eq!(admin::ADMIN_VENDOR_ID, 0x0002);

    assert_eq!(admin::OPEN_COMMISSIONING_WINDOW, 0x00);
    assert_eq!(admin::OPEN_BASIC_COMMISSIONING_WINDOW, 0x01);
    assert_eq!(admin::REVOKE_COMMISSIONING, 0x02);

    // §11.19.5.1.
    assert_eq!(WindowStatus::NotOpen.value(), 0);
    assert_eq!(WindowStatus::EnhancedOpen.value(), 1);
    assert_eq!(WindowStatus::BasicOpen.value(), 2);

    // §11.19.6.1. Note the gap: there is no 0x00 or 0x01, because these are *cluster* status
    // codes and the values are chosen not to collide with the ones a reader might confuse
    // them with.
    assert_eq!(AdminStatus::Busy.value(), 0x02);
    assert_eq!(AdminStatus::PakeParameterError.value(), 0x03);
    assert_eq!(AdminStatus::WindowNotOpen.value(), 0x04);

    // §11.19.8.1's `PAKEPasscodeVerifier` is `w0 || L`: 32 + 65.
    assert_eq!(matter_kit::commissioning::window::PAKE_VERIFIER_LEN, 97);
    // §5.4.2.3.1's two bounds.
    assert_eq!(admin::COMMISSIONING_TIMEOUT_MIN_SECONDS, 180);
    assert_eq!(admin::COMMISSIONING_TIMEOUT_MAX_SECONDS, 900);
}

#[test]
fn every_command_is_administer_and_timed() {
    // §11.19.8's access column is `AT`. The `T` is what stops a recorded invocation being
    // replayed later — and opening a commissioning window is precisely the command where a
    // replay would matter, because it would put a device back into commissioning mode at a
    // moment of the attacker's choosing.
    for cluster in [admin::cluster(), admin::cluster_with_basic()] {
        assert!(cluster.is_well_formed());
        for command in cluster.accepted_commands {
            assert_eq!(command.access.invoke, Some(Privilege::Administer));
            assert!(
                command.access.needs_timed(),
                "command {:#04x} must be Timed",
                command.id
            );
            // "Response: Y" — none of the three has a response command.
            assert_eq!(command.response, None);
        }
    }

    // Without `BC`, the Basic command is absent entirely.
    assert_eq!(admin::cluster().feature_map, 0);
    assert!(
        admin::cluster()
            .accepted_command(admin::OPEN_BASIC_COMMISSIONING_WINDOW)
            .is_none()
    );
    assert_eq!(
        admin::cluster_with_basic().feature_map,
        admin::FEATURE_BASIC
    );
    assert!(
        admin::cluster_with_basic()
            .accepted_command(admin::OPEN_BASIC_COMMISSIONING_WINDOW)
            .is_some()
    );

    // The two nullable attributes are marked so.
    use matter_kit::dm::AttributeQualities;
    for id in [admin::ADMIN_FABRIC_INDEX, admin::ADMIN_VENDOR_ID] {
        let attribute = admin::cluster().attribute(id).expect("attribute");
        assert!(attribute.qualities.contains(AttributeQualities::NULLABLE));
    }
}

// --- Fixtures --------------------------------------------------------------------------------

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

fn verifier_bytes() -> [u8; 97] {
    Spake2pVerifierData::from_passcode(20_202_021, &[0x42; 16], 1000)
        .expect("verifier")
        .to_bytes()
}

fn request(verifier: &[u8]) -> OpenWindowRequest<'_> {
    OpenWindowRequest {
        timeout_seconds: 300,
        verifier,
        discriminator: 840,
        iterations: 1000,
        salt: &[0x42; 16],
    }
}

fn ctx(now: Instant) -> InteractionContext<'static> {
    InteractionContext {
        now,
        ..InteractionContext::default()
    }
}

fn on_fabric(fabric: u8, now: Instant) -> InteractionContext<'static> {
    InteractionContext {
        fabric_index: Some(FabricIndex(fabric)),
        now,
        // Every command here is Timed, so a context that reaches the cluster has one open.
        timed: true,
        ..InteractionContext::default()
    }
}

// --- The window ------------------------------------------------------------------------------

#[test]
fn opening_a_window_records_the_administrator_that_opened_it() {
    // §11.19.7.2 and §11.19.7.3: both attributes describe "the Administrator that opened the
    // window", and the vendor id is read "at the time of window opening".
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |fabric: FabricIndex| (fabric == FabricIndex(1)).then_some(VendorId(0xFFF1));
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);

    let bytes = verifier_bytes();
    cluster
        .open_commissioning_window(&request(&bytes), &on_fabric(1, at(0)))
        .expect("open");

    let borrowed = window.borrow();
    let open = borrowed.open(at(0)).expect("open");
    assert_eq!(open.status, WindowStatus::EnhancedOpen);
    assert_eq!(open.admin_fabric, Some(FabricIndex(1)));
    assert_eq!(open.admin_vendor, Some(VendorId(0xFFF1)));
    assert_eq!(open.discriminator, 840);
    assert!(open.ephemeral.is_some(), "an ECM window carries a verifier");
    assert_eq!(borrowed.status(at(0)), WindowStatus::EnhancedOpen);
    // 300 seconds from now.
    assert_eq!(borrowed.deadline(), Some(at(300)));
}

#[test]
fn a_window_reverts_to_not_open_when_it_expires() {
    // §11.19.7.1: "This attribute SHALL revert to WindowNotOpen upon expiry of a commissioning
    // window." And with it goes the ephemeral verifier: §11.19.8.1 says it "SHALL be deleted
    // by the Node at … expiration of the OpenCommissioningWindow command".
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);

    let bytes = verifier_bytes();
    cluster
        .open_commissioning_window(&request(&bytes), &on_fabric(1, at(0)))
        .expect("open");

    assert_eq!(window.borrow().status(at(299)), WindowStatus::EnhancedOpen);
    assert_eq!(window.borrow().status(at(300)), WindowStatus::NotOpen);
    assert!(window.borrow().ephemeral(at(300)).is_none());
    assert!(window.borrow().ephemeral(at(0)).is_some());
}

#[test]
fn only_one_window_can_be_open_at_a_time() {
    // §11.19.8: "Only one commissioning window can be active at a time. If a Node receives
    // another open commissioning command when an Open Commissioning Window is already active,
    // it SHALL return a failure response."
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor).with_basic();

    let bytes = verifier_bytes();
    cluster
        .open_commissioning_window(&request(&bytes), &on_fabric(1, at(0)))
        .expect("open");
    assert_eq!(
        cluster.open_commissioning_window(&request(&bytes), &on_fabric(2, at(1))),
        Err(AdminStatus::Busy.as_status())
    );
    // The Basic command hits the same rule.
    assert_eq!(
        cluster.open_basic_commissioning_window(300, 840, &on_fabric(2, at(1))),
        Err(AdminStatus::Busy.as_status())
    );
    // And the first window is untouched.
    assert_eq!(
        window
            .borrow()
            .open(at(1))
            .expect("still open")
            .admin_fabric,
        Some(FabricIndex(1))
    );
}

#[test]
fn an_armed_fail_safe_makes_the_command_busy() {
    // §11.19.8.1: "If the fail-safe timer is currently armed, this command SHALL fail with a
    // cluster specific status code of Busy, since it is likely that concurrent commissioning
    // operations from multiple separate Commissioners are about to take place."
    let window = RefCell::new(CommissioningWindow::new());
    let mut armed = FailSafe::new(BasicCommissioningInfo::default());
    armed.arm(600, 0, Some(FabricIndex(1)), at(0), false);
    let fail_safe = RefCell::new(armed);
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);

    let bytes = verifier_bytes();
    assert_eq!(
        cluster.open_commissioning_window(&request(&bytes), &on_fabric(1, at(1))),
        Err(AdminStatus::Busy.as_status())
    );
    assert!(window.borrow().open(at(1)).is_none());

    // Once the fail-safe lapses, the window opens.
    assert!(
        cluster
            .open_commissioning_window(&request(&bytes), &on_fabric(1, at(1000)))
            .is_ok()
    );
}

#[test]
fn a_malformed_pake_verifier_is_a_cluster_specific_error() {
    // §11.19.8.1: "If any format or validity errors related to the PAKEPasscodeVerifier,
    // Iterations or Salt arguments arise, this command SHALL fail with a cluster specific
    // status code of PAKEParameterError."
    //
    // Checking `L` is a point on the curve is the part that matters: a verifier that merely
    // looked the right length would fail much later, inside PASE, as an inexplicable
    // handshake failure that no commissioner could diagnose.
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);

    // 97 octets that are not a valid `(w0, L)`.
    let garbage = [0x01u8; 97];
    assert_eq!(
        cluster.open_commissioning_window(&request(&garbage), &on_fabric(1, at(0))),
        Err(AdminStatus::PakeParameterError.as_status())
    );

    // §3.9's bounds on the PBKDF parameters, which §11.19.8.1's table repeats.
    let bytes = verifier_bytes();
    for (iterations, salt_len) in [(999u32, 16usize), (100_001, 16), (1000, 15), (1000, 33)] {
        let salt = vec![0x42u8; salt_len];
        let request = OpenWindowRequest {
            timeout_seconds: 300,
            verifier: &bytes,
            discriminator: 840,
            iterations,
            salt: &salt,
        };
        assert_eq!(
            cluster.open_commissioning_window(&request, &on_fabric(1, at(0))),
            Err(AdminStatus::PakeParameterError.as_status()),
            "iterations {iterations}, salt {salt_len}"
        );
    }
    assert!(window.borrow().open(at(0)).is_none());
}

#[test]
fn the_timeout_is_bounded_at_both_ends() {
    // §5.4.2.3.1: a device "SHALL NOT announce with a rapid interval for a duration longer
    // than 15 minutes" and "SHALL NOT announce for a duration of less than 3 minutes". Out of
    // range is "any other parameter error", which §11.19.8.1 makes COMMAND_INVALID rather than
    // a cluster-specific code — a distinction a caller has to see to handle correctly.
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);
    let bytes = verifier_bytes();

    for timeout in [0u16, 1, 179, 901, u16::MAX] {
        let request = OpenWindowRequest {
            timeout_seconds: timeout,
            ..request(&bytes)
        };
        assert_eq!(
            cluster.open_commissioning_window(&request, &on_fabric(1, at(0))),
            Err(StatusIb::new(Status::InvalidCommand)),
            "timeout {timeout}"
        );
    }
    for timeout in [180u16, 300, 900] {
        let request = OpenWindowRequest {
            timeout_seconds: timeout,
            ..request(&bytes)
        };
        assert!(
            cluster
                .open_commissioning_window(&request, &on_fabric(1, at(0)))
                .is_ok(),
            "timeout {timeout}"
        );
        window.borrow_mut().close();
    }

    // §11.19.8.1's discriminator is `0 to 4095`.
    let request = OpenWindowRequest {
        discriminator: 4096,
        ..request(&bytes)
    };
    assert_eq!(
        cluster.open_commissioning_window(&request, &on_fabric(1, at(0))),
        Err(StatusIb::new(Status::ConstraintError))
    );
}

#[test]
fn revoking_is_idempotent_and_acts_even_when_no_window_is_open() {
    // §11.19.8.3 step 1 runs "regardless of current commissioning window state", and only
    // step 2 answers `WindowNotOpen`. A device that returned early on the error would leave a
    // PASE session alive after a revoke — which is the one thing the command exists to
    // prevent.
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);

    let (revoked, status) = cluster.revoke_commissioning(&ctx(at(0)));
    assert_eq!(status, Err(AdminStatus::WindowNotOpen.as_status()));
    assert!(
        revoked.close_pase_sessions,
        "step 1.b runs regardless of window state"
    );
    assert!(!revoked.stop_advertising, "there was nothing to withdraw");

    // With a window open, the same command succeeds and also withdraws the advertisement.
    let bytes = verifier_bytes();
    cluster
        .open_commissioning_window(&request(&bytes), &on_fabric(1, at(0)))
        .expect("open");
    let (revoked, status) = cluster.revoke_commissioning(&ctx(at(1)));
    assert_eq!(status, Ok(()));
    assert!(revoked.close_pase_sessions);
    assert!(revoked.stop_advertising);
    assert_eq!(window.borrow().status(at(1)), WindowStatus::NotOpen);
    assert!(
        window.borrow().ephemeral(at(1)).is_none(),
        "step 1.a deletes the temporary verifier"
    );
}

#[test]
fn revoking_expires_a_fail_safe_a_pase_session_was_holding() {
    // §11.19.8.3 step 1.c: "immediately expire any fail-safe held by an open PASE session and
    // perform the cleanup steps outlined in §11.10.7.2.2". A fail-safe with no accessing
    // fabric is one a PASE session armed — §11.10.7.2 starts the context "at the accessing
    // fabric index", which a PASE session does not have.
    let window = RefCell::new(CommissioningWindow::new());
    let mut armed = FailSafe::new(BasicCommissioningInfo::default());
    armed.arm(600, 0, None, at(0), false);
    armed
        .record(at(0), |p| p.added_trusted_root = true)
        .expect("record");
    let fail_safe = RefCell::new(armed);
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);

    let (revoked, _) = cluster.revoke_commissioning(&ctx(at(1)));
    let cleanup = revoked
        .fail_safe_cleanup
        .expect("a PASE-held fail-safe must be expired");
    assert!(
        cleanup.prune_trusted_roots,
        "and its cleanup steps reported"
    );
    assert!(!fail_safe.borrow().is_armed(at(1)));

    // A fail-safe held by a *CASE* administrator is not touched: it is not "held by an open
    // PASE session", and expiring it would let any administrator cancel another's
    // commissioning by revoking a window.
    let mut armed = FailSafe::new(BasicCommissioningInfo::default());
    armed.arm(600, 0, Some(FabricIndex(2)), at(0), false);
    let fail_safe = RefCell::new(armed);
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);
    let (revoked, _) = cluster.revoke_commissioning(&ctx(at(1)));
    assert_eq!(revoked.fail_safe_cleanup, None);
    assert!(fail_safe.borrow().is_armed(at(1)));
}

#[test]
fn removing_the_admins_fabric_nulls_the_index_but_not_the_vendor() {
    // §11.19.7.2: "If, during an open commissioning window, the fabric for the Administrator
    // that opened the window is removed, then this attribute SHALL be set to null."
    // §11.19.7.3, of the *vendor*: "this attribute SHALL NOT be updated." The asymmetry is
    // deliberate — a user looking at the device still learns who opened the window.
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| Some(VendorId(0xFFF1));
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);
    let bytes = verifier_bytes();
    cluster
        .open_commissioning_window(&request(&bytes), &on_fabric(3, at(0)))
        .expect("open");

    window.borrow_mut().forget_fabric(FabricIndex(9));
    assert_eq!(
        window.borrow().open(at(0)).expect("open").admin_fabric,
        Some(FabricIndex(3)),
        "another fabric's removal changes nothing"
    );

    window.borrow_mut().forget_fabric(FabricIndex(3));
    let borrowed = window.borrow();
    let open = borrowed.open(at(0)).expect("still open");
    assert_eq!(open.admin_fabric, None);
    assert_eq!(open.admin_vendor, Some(VendorId(0xFFF1)));
    assert_eq!(open.status, WindowStatus::EnhancedOpen, "and still open");
}

#[test]
fn the_basic_command_is_refused_without_the_feature() {
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);
    assert_eq!(
        cluster.open_basic_commissioning_window(300, 840, &on_fabric(1, at(0))),
        Err(StatusIb::new(Status::UnsupportedCommand))
    );

    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor).with_basic();
    assert!(
        cluster
            .open_basic_commissioning_window(300, 840, &on_fabric(1, at(0)))
            .is_ok()
    );
    let borrowed = window.borrow();
    let open = borrowed.open(at(0)).expect("open");
    assert_eq!(open.status, WindowStatus::BasicOpen);
    assert!(
        open.ephemeral.is_none(),
        "a Basic window runs against the device's own factory verifier"
    );
}

#[test]
fn a_verifier_that_is_only_the_right_length_is_not_a_verifier() {
    // §11.19.8.1 accepts a PAKE verifier *from an administrator over the wire*, so it is
    // peer-supplied cryptographic material and gets the same treatment every other piece of
    // it does. `L` must be on the curve — otherwise an invalid-curve attack, and a verifier
    // that would make every session key a constant — and `w0` must be a canonical scalar.
    //
    // A length-only check would accept all of these and fail much later, inside PASE, as a
    // handshake that simply does not complete.
    let good = verifier_bytes();
    assert!(Spake2pVerifierData::from_bytes(&good).is_ok());

    // `L` that is not an uncompressed SEC 1 point at all.
    let mut bad = good;
    bad[32] = 0x02;
    assert!(Spake2pVerifierData::from_bytes(&bad).is_err(), "not 0x04");

    // `L` that claims to be uncompressed but is not on the curve.
    let mut bad = good;
    bad[96] ^= 0x01;
    assert!(
        Spake2pVerifierData::from_bytes(&bad).is_err(),
        "off the curve"
    );

    // `w0` at or above the group order: n for P-256 is
    // FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551.
    let mut bad = good;
    bad[..32].copy_from_slice(&[0xFFu8; 32]);
    assert!(
        Spake2pVerifierData::from_bytes(&bad).is_err(),
        "a non-canonical w0 is a verifier nobody computed"
    );

    // And the wrong length, which is the only case the first version caught.
    assert!(Spake2pVerifierData::from_bytes(&good[..96]).is_err());
    assert!(Spake2pVerifierData::from_bytes(&[]).is_err());
}

// --- Through the interaction model ---------------------------------------------------------------

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

// Sorted by cluster id — 0x0030 before 0x003C — because `Endpoint::cluster` binary-searches
// and `Node::validate` is what catches getting it wrong.
const CLUSTERS: &[ClusterDescriptor<'static>] = &[
    general_commissioning::cluster(),
    admin::cluster_with_basic(),
];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, CLUSTERS)];

fn fields(build: impl FnOnce(&mut TlvWriter<'_>)) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).expect("open");
    build(&mut w);
    w.end_container().expect("close");
    w.finish().expect("finish").to_vec()
}

/// Invokes a command and returns the `StatusIB` it produced, or the response command id.
fn invoke<H: ClusterHandler>(
    handler: &H,
    cluster: u32,
    command: u32,
    payload: &[u8],
    ctx: &InteractionContext<'_>,
) -> Result<u32, StatusIb> {
    let data = CommandData {
        fields: Some(payload),
        ..CommandData::new(CommandPath::command(0, cluster, command))
    };
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(Node::new(ENDPOINTS), &access, handler, 8);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    match response
        .responses()
        .expect("responses")
        .next()
        .expect("one")
        .expect("decode")
    {
        InvokeResponse::Command(c) => Ok(c.path.command.expect("id")),
        InvokeResponse::Status(s) if s.status.status == Status::Success => Ok(0),
        InvokeResponse::Status(s) => Err(s.status),
    }
}

fn open_window_fields(timeout: u16, verifier: &[u8], discriminator: u16) -> Vec<u8> {
    fields(|w| {
        w.unsigned(Tag::Context(0), u64::from(timeout)).expect("0");
        w.octets(Tag::Context(1), verifier).expect("1");
        w.unsigned(Tag::Context(2), u64::from(discriminator))
            .expect("2");
        w.unsigned(Tag::Context(3), 1000).expect("3");
        w.octets(Tag::Context(4), &[0x42; 16]).expect("4");
    })
}

#[test]
fn a_cluster_specific_status_code_reaches_the_wire() {
    // §11.19.6's codes travel in a `StatusIB`'s `ClusterStatus` field beside `FAILURE`
    // (§10.6.17), because none of these commands has a response command to put them in. A
    // handler that could only return an interaction-model status would have to answer plain
    // `FAILURE` — and a commissioner could not tell "busy" from "your verifier is malformed".
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| Some(VendorId(0xFFF1));
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor).with_basic();
    let bytes = verifier_bytes();

    // Success is a plain SUCCESS status: "Response: Y".
    assert_eq!(
        invoke(
            &cluster,
            admin::ID,
            admin::OPEN_COMMISSIONING_WINDOW,
            &open_window_fields(300, &bytes, 840),
            &on_fabric(1, at(0))
        ),
        Ok(0)
    );

    // A second open is Busy — `FAILURE` with `ClusterStatus = 2`.
    assert_eq!(
        invoke(
            &cluster,
            admin::ID,
            admin::OPEN_COMMISSIONING_WINDOW,
            &open_window_fields(300, &bytes, 840),
            &on_fabric(2, at(1))
        ),
        Err(StatusIb {
            status: Status::Failure,
            cluster_status: Some(AdminStatus::Busy.value()),
        })
    );

    // Revoke, then revoke again: the second is WindowNotOpen.
    let empty = fields(|_| {});
    assert_eq!(
        invoke(
            &cluster,
            admin::ID,
            admin::REVOKE_COMMISSIONING,
            &empty,
            &on_fabric(1, at(2))
        ),
        Ok(0)
    );
    assert_eq!(
        invoke(
            &cluster,
            admin::ID,
            admin::REVOKE_COMMISSIONING,
            &empty,
            &on_fabric(1, at(3))
        ),
        Err(StatusIb {
            status: Status::Failure,
            cluster_status: Some(AdminStatus::WindowNotOpen.value()),
        })
    );

    // A malformed verifier is PAKEParameterError, distinguishable from both.
    assert_eq!(
        invoke(
            &cluster,
            admin::ID,
            admin::OPEN_COMMISSIONING_WINDOW,
            &open_window_fields(300, &[0x01; 97], 840),
            &on_fabric(1, at(4))
        ),
        Err(StatusIb {
            status: Status::Failure,
            cluster_status: Some(AdminStatus::PakeParameterError.value()),
        })
    );
}

#[test]
fn an_untimed_invocation_is_refused_before_the_cluster_sees_it() {
    // §11.19.8's `AT`, enforced by §8.8.2.3 step b.vi. A replayed
    // `OpenCommissioningWindow` would put a device back into commissioning mode at a moment
    // of the attacker's choosing, which is what §8.7.4's Timed transaction exists to stop.
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);
    let bytes = verifier_bytes();

    let untimed = InteractionContext {
        fabric_index: Some(FabricIndex(1)),
        now: at(0),
        ..InteractionContext::default()
    };
    assert_eq!(
        invoke(
            &cluster,
            admin::ID,
            admin::OPEN_COMMISSIONING_WINDOW,
            &open_window_fields(300, &bytes, 840),
            &untimed
        ),
        Err(StatusIb::new(Status::NeedsTimedInteraction))
    );
    assert!(
        window.borrow().open(at(0)).is_none(),
        "and nothing reached the cluster"
    );
}

#[test]
fn the_window_is_the_same_window_general_commissioning_sees() {
    // The dangling wire this cluster exists to connect. §11.10.7.2 refuses an `ArmFailSafe`
    // that arrives over CASE against a disarmed fail-safe *while the window is open*, "to
    // allow commissioners, which use PASE connections, the opportunity to use the failsafe".
    // Two clusters keeping their own flag would be two answers to "is a window open", and
    // this priority rule is exactly where they would disagree.
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let location = Location::region_agnostic();
    let admin_cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);
    let gc = GeneralCommissioning::new(
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );

    assert!(!gc.is_window_open(at(0)));
    let arm = fields(|w| {
        w.unsigned(Tag::Context(0), 600).expect("expiry");
        w.unsigned(Tag::Context(1), 1).expect("breadcrumb");
    });
    // Over CASE with no window open: allowed.
    let handler = (&admin_cluster, &gc);
    assert_eq!(
        invoke(
            &handler,
            general_commissioning::ID,
            general_commissioning::ARM_FAIL_SAFE,
            &arm,
            &on_fabric(1, at(0))
        ),
        Ok(general_commissioning::ARM_FAIL_SAFE_RESPONSE)
    );

    // Disarm, open a window, and try again: now the CASE administrator is held off.
    let disarm = fields(|w| {
        w.unsigned(Tag::Context(0), 0).expect("expiry");
        w.unsigned(Tag::Context(1), 0).expect("breadcrumb");
    });
    invoke(
        &handler,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &disarm,
        &on_fabric(1, at(1)),
    )
    .expect("disarm");
    let _ = gc.take_aftermath();

    let bytes = verifier_bytes();
    invoke(
        &handler,
        admin::ID,
        admin::OPEN_COMMISSIONING_WINDOW,
        &open_window_fields(300, &bytes, 840),
        &on_fabric(1, at(2)),
    )
    .expect("open");
    assert!(gc.is_window_open(at(2)), "the same window");

    // §11.10.7.2's priority rule now applies, and the response carries
    // `BusyWithOtherAdmin` (4) rather than an interaction-model failure.
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let data = CommandData {
        fields: Some(&arm),
        ..CommandData::new(CommandPath::command(
            0,
            general_commissioning::ID,
            general_commissioning::ARM_FAIL_SAFE,
        ))
    };
    let server = Server::new(Node::new(ENDPOINTS), &access, &handler, 8);
    let (response, _) = server
        .serve_invoke(
            [Ok(data)],
            &on_fabric(1, at(3)),
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let decoded = InvokeResponseMessage::decode(response).expect("decode");
    let InvokeResponse::Command(c) = decoded
        .responses()
        .expect("responses")
        .next()
        .expect("one")
        .expect("decode")
    else {
        panic!("expected an ArmFailSafeResponse");
    };
    let mut reader = TlvReader::new_in(c.fields.expect("fields"), ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    let error = reader.next_element().expect("read").expect("error");
    assert_eq!(
        error.unsigned().expect("uint"),
        4,
        "BusyWithOtherAdmin: the window holds the fail-safe for a PASE commissioner"
    );
}

#[test]
fn commissioning_complete_closes_the_window() {
    // §11.10.7.6 step 2: "The commissioning window at the Server SHALL be closed." Which also
    // destroys the ephemeral verifier — §11.19.8.1: "It SHALL be deleted by the Node at the
    // end of commissioning."
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| None;
    let location = Location::region_agnostic();
    let admin_cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);
    let gc = GeneralCommissioning::new(
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );

    let bytes = verifier_bytes();
    admin_cluster
        .open_commissioning_window(&request(&bytes), &on_fabric(1, at(0)))
        .expect("open");
    assert!(window.borrow().ephemeral(at(0)).is_some());

    // A commissioner arms the fail-safe over PASE and completes on the fabric it joined.
    fail_safe.borrow_mut().arm(600, 0, None, at(1), false);
    fail_safe
        .borrow_mut()
        .adopt_fabric(FabricIndex(2), at(1))
        .expect("adopt");
    let completion = gc.commissioning_complete(true, Some(FabricIndex(2)), at(2));
    assert!(completion.error.is_ok());
    assert!(completion.close_pase_sessions);

    assert_eq!(window.borrow().status(at(2)), WindowStatus::NotOpen);
    assert!(
        window.borrow().ephemeral(at(2)).is_none(),
        "the ephemeral verifier must not outlive the commissioning it was for"
    );
}

#[test]
fn the_attributes_report_the_window_through_a_read() {
    let window = RefCell::new(CommissioningWindow::new());
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let vendor = |_: FabricIndex| Some(VendorId(0x1234));
    let cluster = AdministratorCommissioning::new(&window, &fail_safe, &vendor);
    let node = Node::new(ENDPOINTS);

    let read = |attribute: u32, now: Instant| -> Vec<u8> {
        let resolved = node.resolve(0, admin::ID, attribute).expect("path");
        let mut buf = [0u8; 128];
        let mut w = TlvWriter::new(&mut buf);
        cluster
            .read(&resolved, &ctx(now), &mut w, Tag::Anonymous)
            .expect("read");
        w.finish().expect("finish").to_vec()
    };
    let value = |bytes: &[u8]| -> Option<u64> {
        let mut reader = TlvReader::new(bytes);
        let element = reader.next_element().expect("read").expect("value");
        if element.value.is_null() {
            None
        } else {
            Some(element.unsigned().expect("uint"))
        }
    };

    // Closed: status 0, and both other attributes null.
    assert_eq!(value(&read(admin::WINDOW_STATUS, at(0))), Some(0));
    assert_eq!(value(&read(admin::ADMIN_FABRIC_INDEX, at(0))), None);
    assert_eq!(value(&read(admin::ADMIN_VENDOR_ID, at(0))), None);

    let bytes = verifier_bytes();
    cluster
        .open_commissioning_window(&request(&bytes), &on_fabric(7, at(0)))
        .expect("open");
    assert_eq!(value(&read(admin::WINDOW_STATUS, at(0))), Some(1));
    assert_eq!(value(&read(admin::ADMIN_FABRIC_INDEX, at(0))), Some(7));
    assert_eq!(value(&read(admin::ADMIN_VENDOR_ID, at(0))), Some(0x1234));

    // …and once it expires, all three revert without anything being called.
    assert_eq!(value(&read(admin::WINDOW_STATUS, at(300))), Some(0));
    assert_eq!(value(&read(admin::ADMIN_FABRIC_INDEX, at(300))), None);
    assert_eq!(value(&read(admin::ADMIN_VENDOR_ID, at(300))), None);
}

#[test]
fn the_cluster_trait_id_matches_the_module_constant() {
    assert_eq!(<AdministratorCommissioning<'_> as Cluster>::ID, admin::ID);
}
