//! Network Recovery (Core §5.9), the way back for a node whose network moved.
//!
//! A device whose Wi-Fi password changed underneath it is not broken and not commissionable: it
//! still holds its fabric, its NOC and its access control list. §5.9 is how it gets a new
//! network without being factory reset — advertise, let an administrator open a **CASE** session
//! over the recovery channel, and take new credentials through it.
//!
//! Three rules carry the flow, and each is a rule against being helpful:
//!
//! * Wait 120 seconds first. A device that advertised on the first failed association would be
//!   broadcasting through every brief outage its access point has.
//! * Arm a fail-safe the moment the session opens, against an administrator that connects and
//!   then wanders off mid-flow.
//! * Refuse `CommissioningComplete` unless it arrives over the *operational* network — the one
//!   thing the whole flow exists to restore.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::clusters::basic_information::Location;
use matter_kit::clusters::general_commissioning::{
    self as gc, GeneralCommissioning, NetworkRecoveryReason, RECOVERY_FAIL_SAFE_SECONDS,
    RECOVERY_HOLD_OFF, Recovery, RegulatoryLocation,
};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{ClusterHandler, InteractionContext, Status};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{Tag, TlvReader, TlvWriter, Value};
use matter_kit::transport::ble::Advertisement;

const RECOVERY_ID: u64 = 0x0123_4567_89AB_CDEF;

fn at(secs: u64) -> Instant {
    Instant::from_micros(secs * 1_000_000)
}

// --- §5.9.3 step 3: wait before you shout ---------------------------------------------------

#[test]
fn a_node_waits_two_minutes_before_it_announces() {
    // §5.9.3 step 3: "the Recovery Node SHALL continue to attempt to connect to the operational
    // network for a duration of at least 120 seconds using its existing credentials."
    let recovery = Recovery::new(RECOVERY_ID);
    recovery.network_lost(at(0), NetworkRecoveryReason::Visibility);

    assert!(!recovery.may_announce(at(0)));
    assert!(!recovery.may_announce(at(119)));
    assert!(!recovery.begin_announcing(at(119)));
    assert!(!recovery.is_announcing());

    assert!(recovery.may_announce(at(120)));
    assert!(recovery.begin_announcing(at(120)));
    assert!(recovery.is_announcing());
    assert_eq!(RECOVERY_HOLD_OFF, Duration::from_secs(120));
}

#[test]
fn the_clock_starts_at_the_first_failure_not_the_latest() {
    // A device retries continuously while it is disconnected. If each retry restarted the
    // hold-off, the 120 seconds would never elapse and the node would never announce.
    let recovery = Recovery::new(RECOVERY_ID);
    recovery.network_lost(at(0), NetworkRecoveryReason::Auth);
    for retry in 1..120 {
        recovery.network_lost(at(retry), NetworkRecoveryReason::Auth);
    }
    assert!(recovery.may_announce(at(120)));
    assert_eq!(
        recovery.reason(),
        Some(NetworkRecoveryReason::Auth),
        "and the first reason is the one reported"
    );
}

#[test]
fn a_network_that_comes_back_ends_the_flow() {
    let recovery = Recovery::new(RECOVERY_ID);
    recovery.network_lost(at(0), NetworkRecoveryReason::Visibility);
    recovery.begin_announcing(at(200));
    assert!(recovery.is_announcing());

    recovery.network_restored();
    assert!(!recovery.is_announcing());
    // §11.10.6.12: "This attribute SHALL be null when the Node is not undergoing a Network
    // Recovery flow" — the reason is state, not a diagnostic that lingers.
    assert_eq!(recovery.reason(), None);
    assert!(!recovery.may_announce(at(1000)), "the clock is reset too");
}

// --- §5.9.3 step 16: finish where it matters -------------------------------------------------

#[test]
fn commissioning_complete_is_refused_over_the_recovery_channel() {
    // §5.9.3 step 16: "The Recovery Node SHALL reject the CommissioningComplete that is not
    // received over the operational network." Completing over BLE would declare the flow a
    // success at the exact moment nothing had been shown to work — and the administrator would
    // walk away from a device still unable to reach anything.
    let recovery = Recovery::new(RECOVERY_ID);
    recovery.network_lost(at(0), NetworkRecoveryReason::Auth);
    recovery.begin_announcing(at(200));

    assert!(!recovery.may_complete(false), "over the recovery channel");
    assert!(recovery.may_complete(true), "over the operational network");
}

#[test]
fn an_ordinary_commissioning_completes_over_whatever_channel_it_ran_on() {
    // The rule is §5.9's, not §5.5's: a device that is not in recovery completes over the
    // channel it commissioned on, which for a non-concurrent flow is the commissioning channel.
    let recovery = Recovery::new(RECOVERY_ID);
    assert!(recovery.may_complete(false));
    recovery.network_lost(at(0), NetworkRecoveryReason::Auth);
    assert!(
        recovery.may_complete(false),
        "losing the network is not yet the recovery flow; announcing is"
    );
}

// --- §11.10.6.11, §11.10.6.12: the two attributes --------------------------------------------

struct Fixture {
    node: Node<'static>,
    location: Location,
    fail_safe: RefCell<FailSafe>,
    window: RefCell<CommissioningWindow>,
    recovery: Recovery,
}

fn fixture(with_recovery: bool) -> Fixture {
    let descriptor = if with_recovery {
        gc::cluster_with_recovery()
    } else {
        gc::cluster()
    };
    let clusters: &'static [ClusterDescriptor<'static>] = Box::leak(Box::new([descriptor]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(0, clusters)]));
    Fixture {
        node: Node::new(endpoints),
        location: Location::default(),
        fail_safe: RefCell::new(FailSafe::new(BasicCommissioningInfo::default())),
        window: RefCell::new(CommissioningWindow::new()),
        recovery: Recovery::new(RECOVERY_ID),
    }
}

impl Fixture {
    fn cluster(&self, with_recovery: bool) -> GeneralCommissioning<'_> {
        let cluster = GeneralCommissioning::new(
            &self.location,
            RegulatoryLocation::IndoorOutdoor,
            &self.fail_safe,
            &self.window,
        );
        if with_recovery {
            cluster.with_recovery(&self.recovery)
        } else {
            cluster
        }
    }

    fn read(&self, with_recovery: bool, attribute: u32) -> Result<Value<'static>, Status> {
        let cluster = self.cluster(with_recovery);
        let resolved = self
            .node
            .resolve(0, gc::ID, attribute)
            .expect("the path exists");
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        cluster.read(
            &resolved,
            &InteractionContext::default(),
            &mut w,
            Tag::Anonymous,
        )?;
        let bytes = w.finish().expect("finish").to_vec();
        let mut reader = TlvReader::new(&bytes);
        Ok(match reader.next_element().unwrap().unwrap().value {
            Value::Unsigned(v) => Value::Unsigned(v),
            Value::Null => Value::Null,
            other => panic!("unexpected {other:?}"),
        })
    }
}

#[test]
fn the_recovery_identifier_is_readable_and_fixed() {
    // §11.10.6.11: "a random 64-bit value, that value SHALL be reset on factory reset and SHALL
    // remain unchanged until a next factory reset."
    let fixture = fixture(true);
    assert_eq!(
        fixture.read(true, gc::RECOVERY_IDENTIFIER).unwrap(),
        Value::Unsigned(RECOVERY_ID)
    );
    // Reading it twice gives the same value, because it is not derived from anything that moves.
    assert_eq!(
        fixture.read(true, gc::RECOVERY_IDENTIFIER).unwrap(),
        Value::Unsigned(RECOVERY_ID)
    );
}

#[test]
fn the_recovery_reason_is_null_outside_the_flow() {
    let fixture = fixture(true);
    assert_eq!(
        fixture.read(true, gc::NETWORK_RECOVERY_REASON).unwrap(),
        Value::Null
    );
    fixture
        .recovery
        .network_lost(at(0), NetworkRecoveryReason::Auth);
    assert_eq!(
        fixture.read(true, gc::NETWORK_RECOVERY_REASON).unwrap(),
        Value::Unsigned(u64::from(NetworkRecoveryReason::Auth.value()))
    );
    fixture.recovery.network_restored();
    assert_eq!(
        fixture.read(true, gc::NETWORK_RECOVERY_REASON).unwrap(),
        Value::Null
    );
}

#[test]
fn a_node_without_the_feature_has_neither_attribute() {
    // §11.10.6's conformance gates both on `NR`, and the refusal comes from the data model
    // rather than the handler: the path does not resolve at all, which is what a client reading
    // `AttributeList` is told as well. A node that answered anyway would be advertising a
    // feature it does not implement.
    let fixture = fixture(false);
    for attribute in [gc::RECOVERY_IDENTIFIER, gc::NETWORK_RECOVERY_REASON] {
        assert!(
            fixture.node.resolve(0, gc::ID, attribute).is_err(),
            "attribute {attribute:#06x} must not resolve without the NR feature"
        );
    }
}

#[test]
fn a_descriptor_that_claims_the_feature_without_the_state_refuses_rather_than_invents() {
    // The other half of the same rule, and the one a device gets wrong: it sets the feature bit
    // in its descriptor and forgets to hand the cluster a `Recovery`. Answering with a zero
    // identifier would have every such device advertise the same one.
    let fixture = fixture(true);
    assert_eq!(
        fixture.read(false, gc::RECOVERY_IDENTIFIER),
        Err(Status::UnsupportedAttribute)
    );
    assert_eq!(
        fixture.read(false, gc::NETWORK_RECOVERY_REASON),
        Err(Status::UnsupportedAttribute)
    );
}

#[test]
fn the_feature_bit_and_the_attributes_move_together() {
    // §7.3's conformance is the whole point of the two descriptors: a device that set the
    // feature bit without serving the attributes, or served them without the bit, would be
    // caught here rather than by the Test Harness.
    let plain = gc::cluster();
    assert_eq!(plain.feature_map, 0);
    assert!(
        !plain
            .attributes
            .iter()
            .any(|a| a.id == gc::RECOVERY_IDENTIFIER)
    );

    let recovering = gc::cluster_with_recovery();
    assert_eq!(recovering.feature_map, gc::FEATURE_NETWORK_RECOVERY);
    assert!(
        recovering
            .attributes
            .iter()
            .any(|a| a.id == gc::RECOVERY_IDENTIFIER)
    );
    assert!(
        recovering
            .attributes
            .iter()
            .any(|a| a.id == gc::NETWORK_RECOVERY_REASON)
    );
    // And the base attributes are still all there.
    assert!(recovering.attributes.len() > plain.attributes.len());
    for attribute in plain.attributes {
        assert!(recovering.attributes.iter().any(|a| a.id == attribute.id));
    }
}

// --- §5.4.2.5: what goes on the air -----------------------------------------------------------

#[test]
fn the_identifier_the_cluster_reports_is_the_one_advertised() {
    // §5.9.1: "The advertisement for Network Recovery SHALL contain the value of the
    // RecoveryIdentifier attribute." The two are the same number, and the reason the attribute
    // is `RA` is that the advertisement is not: anyone in radio range hears it, so it must not
    // be the Node ID.
    let fixture = fixture(true);
    let advertised = Advertisement::NetworkRecovery {
        recovery_id: fixture.recovery.identifier(),
        additional_data: false,
    };
    let mut buf = [0u8; 32];
    let n = advertised.encode(&mut buf).expect("encode");
    let read = Advertisement::decode(&buf[..n]).expect("decode");
    let Advertisement::NetworkRecovery { recovery_id, .. } = read else {
        panic!("expected a recovery advertisement");
    };
    assert_eq!(recovery_id, RECOVERY_ID);
    assert_eq!(
        fixture.read(true, gc::RECOVERY_IDENTIFIER).unwrap(),
        Value::Unsigned(recovery_id)
    );
}

#[test]
fn the_autonomous_fail_safe_is_sixty_seconds() {
    // §5.9.3 step 10: "the Recovery Node SHALL autonomously arm the fail-safe timer for a
    // timeout of 60 seconds. This is to guard against the Administrator not proceeding with the
    // rest of the flow in a timely fashion."
    assert_eq!(RECOVERY_FAIL_SAFE_SECONDS, 60);
}
