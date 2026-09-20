//! Intermittently Connected Devices: the Check-In Protocol and its cluster, driven end to end.
//!
//! `icd::checkin`'s unit tests already pin the cryptography against Appendix F.4's six
//! vectors. What is tested here is the half those vectors cannot reach: registering a client
//! through the interaction model, the verification key that stops one manager evicting
//! another's registration, and then the device actually checking in to the client it
//! registered — with the client's replay window and the server's counter meeting for the
//! first time.
//!
//! That last part is the only place the two halves are one feature. A cluster that handed out
//! the wrong `ICDCounter` in its response, or a device that sent a counter it had already
//! spent, would pass every test on either side alone and fail here.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use matter_kit::clusters::icd_management::{
    self, ClientType, Feature, IcdManagement, OperatingMode, Registration, Timings,
    UserActiveModeTrigger,
};
use matter_kit::crypto::SymmetricKey;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::icd::checkin::{self, KEY_REFRESH_OFFSET};
use matter_kit::im::{
    AllowAll, CommandData, CommandPath, InteractionContext, InvokeResponse, InvokeResponseMessage,
    Server, Status,
};
use matter_kit::msg::{FabricIndex, NodeId};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};

/// A node that promises each fabric two Check-In registrations rather than §9.16.6.6's floor of
/// one, so that these tests reach the per-fabric quota rather than the table's end. The quota is
/// `Config`'s, and `IcdManagement::CHECK` refuses a table too small to keep it.
struct TwoClients;
impl matter_kit::Config for TwoClients {
    const ICD_CLIENTS_PER_FABRIC: usize = 2;
}

// Five fabrics × two registrations each: `IcdManagement::CHECK` refuses less.
type Icd<'a> = IcdManagement<'a, TwoClients, 10>;

const FABRIC: FabricIndex = FabricIndex(1);
const OTHER_FABRIC: FabricIndex = FabricIndex(2);
const HUB: NodeId = NodeId(0x1111_2222_3333_AAAA);
const PHONE: NodeId = NodeId(0x4444_5555_6666_BBBB);

const EVERYTHING: Feature = Feature::from_bits_truncate(
    Feature::CHECK_IN_PROTOCOL_SUPPORT.bits()
        | Feature::USER_ACTIVE_MODE_TRIGGER.bits()
        | Feature::LONG_IDLE_TIME_SUPPORT.bits(),
);

fn key(byte: u8) -> SymmetricKey {
    SymmetricKey::new([byte; 16])
}

fn timings() -> Timings {
    Timings {
        idle_mode_duration: 600,
        active_mode_duration: 1_000,
        active_mode_threshold: 500,
        maximum_check_in_backoff: 3_600,
    }
}

/// The cluster under test, and the node that serves it.
struct Device<'a> {
    node: Node<'a>,
    icd: Icd<'a>,
}

/// A node with just this cluster on endpoint 0.
///
/// The descriptor is **derived** from the specification's tables rather than written out, so
/// it moves with the feature map — which is what stops a device advertising `OperatingMode`
/// without claiming `LITS`. That storage has to outlive the node that borrows it; in a test,
/// leaking it is the honest way to say "for the rest of the process".
fn device<'a>() -> Device<'a> {
    let conforming = Box::leak(Box::new(
        icd_management::conforming(EVERYTHING, &matter_kit::dm::spec::Optional::NONE)
            .expect("the const parameters are large enough"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(0, clusters)]));
    Device {
        node: Node::new(endpoints),
        icd: Icd::new(EVERYTHING, timings()),
    }
}

fn context(fabric: FabricIndex, privilege: Privilege) -> InteractionContext<'static> {
    InteractionContext::new()
        .with_fabric(fabric)
        .with_privilege(privilege)
}

/// `RegisterClient`'s fields (§9.16.7.1), authored as the `CommandDataIB`'s context-1 member.
fn register_fields(
    check_in: NodeId,
    subject: u64,
    key: &SymmetricKey,
    verification: Option<&SymmetricKey>,
    client_type: ClientType,
) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), check_in.0).unwrap();
    w.unsigned(Tag::Context(1), subject).unwrap();
    w.octets(Tag::Context(2), key.as_bytes()).unwrap();
    if let Some(verification) = verification {
        w.octets(Tag::Context(3), verification.as_bytes()).unwrap();
    }
    w.unsigned(Tag::Context(4), client_type as u64).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// `UnregisterClient`'s fields (§9.16.7.3).
fn unregister_fields(check_in: NodeId, verification: Option<&SymmetricKey>) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), check_in.0).unwrap();
    if let Some(verification) = verification {
        w.octets(Tag::Context(1), verification.as_bytes()).unwrap();
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// One field's u64 value, or a status.
enum Outcome {
    Response(u64),
    Success,
    Status(Status),
}

fn invoke(device: &Device<'_>, command: u32, fields: &[u8], ctx: &InteractionContext) -> Outcome {
    let data = CommandData {
        fields: Some(fields),
        ..CommandData::new(CommandPath::command(0, icd_management::ID, command))
    };
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.icd, 8);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    match responses.next().expect("one response").expect("decode") {
        InvokeResponse::Command(c) => {
            let fields = c.fields.expect("response fields");
            let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
            reader.next_element().unwrap().unwrap();
            let first = reader.next_element().unwrap().unwrap();
            assert_eq!(first.tag, Tag::Context(0));
            Outcome::Response(first.unsigned().expect("a u32 field"))
        }
        InvokeResponse::Status(s) => {
            if s.status.status == Status::Success {
                Outcome::Success
            } else {
                Outcome::Status(s.status.status)
            }
        }
    }
}

// --- The tables --------------------------------------------------------------------------

#[test]
fn the_ids_and_revision_match_the_specification() {
    // §9.16.3, §9.16.1, §9.16.6 and §9.16.7, transcribed.
    assert_eq!(icd_management::ID, 0x0046);
    assert_eq!(icd_management::REVISION, 3);
    assert_eq!(icd_management::IDLE_MODE_DURATION, 0x0000);
    assert_eq!(icd_management::ACTIVE_MODE_DURATION, 0x0001);
    assert_eq!(icd_management::ACTIVE_MODE_THRESHOLD, 0x0002);
    assert_eq!(icd_management::REGISTERED_CLIENTS, 0x0003);
    assert_eq!(icd_management::ICD_COUNTER, 0x0004);
    assert_eq!(icd_management::CLIENTS_SUPPORTED_PER_FABRIC, 0x0005);
    assert_eq!(icd_management::USER_ACTIVE_MODE_TRIGGER_HINT, 0x0006);
    assert_eq!(icd_management::USER_ACTIVE_MODE_TRIGGER_INSTRUCTION, 0x0007);
    assert_eq!(icd_management::OPERATING_MODE, 0x0008);
    assert_eq!(icd_management::MAXIMUM_CHECK_IN_BACKOFF, 0x0009);

    assert_eq!(icd_management::REGISTER_CLIENT, 0x00);
    assert_eq!(icd_management::REGISTER_CLIENT_RESPONSE, 0x01);
    assert_eq!(icd_management::UNREGISTER_CLIENT, 0x02);
    assert_eq!(icd_management::STAY_ACTIVE_REQUEST, 0x03);
    assert_eq!(icd_management::STAY_ACTIVE_RESPONSE, 0x04);

    // §9.16.4's feature bits.
    assert_eq!(Feature::CHECK_IN_PROTOCOL_SUPPORT.bits(), 1 << 0);
    assert_eq!(Feature::USER_ACTIVE_MODE_TRIGGER.bits(), 1 << 1);
    assert_eq!(Feature::LONG_IDLE_TIME_SUPPORT.bits(), 1 << 2);
    assert_eq!(Feature::DYNAMIC_SIT_LIT_SUPPORT.bits(), 1 << 3);

    // §9.16.5's enums.
    assert_eq!(ClientType::Permanent as u8, 0);
    assert_eq!(ClientType::Ephemeral as u8, 1);
    assert_eq!(OperatingMode::Sit as u8, 0);
    assert_eq!(OperatingMode::Lit as u8, 1);
}

#[test]
fn the_trigger_bitmap_matches_the_user_active_mode_trigger_table() {
    // §9.16.5.1's seventeen bits, in order.
    assert_eq!(UserActiveModeTrigger::POWER_CYCLE.bits(), 1 << 0);
    assert_eq!(UserActiveModeTrigger::SETTINGS_MENU.bits(), 1 << 1);
    assert_eq!(UserActiveModeTrigger::CUSTOM_INSTRUCTION.bits(), 1 << 2);
    assert_eq!(UserActiveModeTrigger::DEVICE_MANUAL.bits(), 1 << 3);
    assert_eq!(UserActiveModeTrigger::ACTUATE_SENSOR.bits(), 1 << 4);
    assert_eq!(UserActiveModeTrigger::APP_DEFINED_BUTTON.bits(), 1 << 16);

    // §9.16.6.7's exception, which is the part a reading of the dependency column alone gets
    // wrong: bits 7, 9 and 14 depend on the instruction but do not require it, because all it
    // adds is the colour of a light.
    for exempt in [
        UserActiveModeTrigger::ACTUATE_SENSOR_LIGHTS_BLINK,
        UserActiveModeTrigger::RESET_BUTTON_LIGHTS_BLINK,
        UserActiveModeTrigger::SETUP_BUTTON_LIGHTS_BLINK,
    ] {
        assert!(!exempt.needs_instruction(), "{exempt:?}");
    }
    for required in [
        UserActiveModeTrigger::CUSTOM_INSTRUCTION,
        UserActiveModeTrigger::RESET_BUTTON_SECONDS,
        UserActiveModeTrigger::SETUP_BUTTON_TIMES,
    ] {
        assert!(required.needs_instruction(), "{required:?}");
    }

    // And a device declaring one of those without an instruction is refused at build time,
    // because a client will display "press the button for N seconds" with no N.
    let icd = Icd::new(EVERYTHING, timings());
    assert!(
        icd.with_trigger(UserActiveModeTrigger::RESET_BUTTON_SECONDS, "")
            .is_err()
    );
    let icd = Icd::new(EVERYTHING, timings());
    icd.with_trigger(UserActiveModeTrigger::RESET_BUTTON, "")
        .expect("a trigger that needs no instruction");
}

#[test]
fn the_idle_and_active_durations_are_compared_in_the_same_unit() {
    // §9.16.6.1: "The IdleModeDuration SHALL NOT be smaller than the ActiveModeDuration" —
    // and the first is seconds while the second is milliseconds. A device advertising one
    // second idle and five seconds active is describing something impossible, and comparing
    // the two numbers directly (1 < 5000) happens to reject it for the wrong reason while
    // accepting 600 seconds idle against 900000 ms active, which is also impossible.
    assert!(timings().is_valid());
    assert!(
        Timings {
            idle_mode_duration: 1,
            active_mode_duration: 1_000,
            active_mode_threshold: 300,
            maximum_check_in_backoff: 1,
        }
        .is_valid(),
        "one second idle and 1000 ms active are the same duration"
    );
    assert!(
        !Timings {
            idle_mode_duration: 1,
            active_mode_duration: 1_001,
            active_mode_threshold: 300,
            maximum_check_in_backoff: 1,
        }
        .is_valid(),
        "one millisecond more is not"
    );

    // §9.16.6's bounds: 1 to 64800 seconds, and MaximumCheckInBackoff no lower than the idle
    // duration.
    assert!(
        !Timings {
            idle_mode_duration: 0,
            ..timings()
        }
        .is_valid()
    );
    assert!(
        !Timings {
            idle_mode_duration: 64_801,
            ..timings()
        }
        .is_valid()
    );
    assert!(
        !Timings {
            maximum_check_in_backoff: 599,
            ..timings()
        }
        .is_valid()
    );
}

// --- Registration ------------------------------------------------------------------------

#[test]
fn a_client_registers_and_is_told_the_counter_its_window_starts_from() {
    let device = device();
    device.icd.restore_counter(42);

    let fields = register_fields(HUB, HUB.0, &key(0xA1), None, ClientType::Permanent);
    let Outcome::Response(counter) = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &fields,
        &context(FABRIC, Privilege::Administer),
    ) else {
        panic!("RegisterClient answers with RegisterClientResponse")
    };

    // §9.16.7.2: "The ICDCounter field SHALL be set to the ICDCounter attribute of the
    // server." The client stores it as §4.22.1.2's starting value, so a server that returned
    // a counter it had already sent a check-in with would have that check-in rejected as a
    // replay the moment it arrived.
    assert_eq!(counter, 42);
    assert_eq!(device.icd.clients().len(), 1);
    assert_eq!(device.icd.clients()[0].check_in_node_id, HUB);
    assert_eq!(device.icd.clients()[0].fabric_index, FABRIC);
}

#[test]
fn a_manager_must_prove_it_knows_the_key_it_is_replacing() {
    // §9.16.7.1 steps 2–3. Without this, any node with Manage on the cluster could point
    // another client's check-ins at itself — and the dispossessed client would simply never
    // hear from the device again, with nothing anywhere reporting an error.
    let device = device();
    let original = key(0xA1);
    let usurper = key(0xB2);

    invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(HUB, HUB.0, &original, None, ClientType::Permanent),
        &context(FABRIC, Privilege::Administer),
    );

    // A manager with no verification key: step 3a, FAILURE.
    let outcome = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(HUB, PHONE.0, &usurper, None, ClientType::Ephemeral),
        &context(FABRIC, Privilege::Manage),
    );
    assert!(matches!(outcome, Outcome::Status(Status::Failure)));

    // A manager with the wrong one: step 3b, FAILURE.
    let outcome = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(
            HUB,
            PHONE.0,
            &usurper,
            Some(&key(0xCC)),
            ClientType::Ephemeral,
        ),
        &context(FABRIC, Privilege::Manage),
    );
    assert!(matches!(outcome, Outcome::Status(Status::Failure)));
    assert_eq!(
        device.icd.clients()[0].monitored_subject,
        HUB.0,
        "and nothing was modified"
    );

    // A manager with the right one: step 3c, and the entry is updated.
    let outcome = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(
            HUB,
            PHONE.0,
            &usurper,
            Some(&original),
            ClientType::Ephemeral,
        ),
        &context(FABRIC, Privilege::Manage),
    );
    assert!(matches!(outcome, Outcome::Response(_)));
    assert_eq!(device.icd.clients()[0].monitored_subject, PHONE.0);
    assert_eq!(device.icd.clients()[0].client_type, ClientType::Ephemeral);
}

#[test]
fn an_administrator_needs_no_verification_key_and_one_it_sends_is_ignored() {
    // §9.16.7.1: "The verification key SHOULD NOT be provided by clients with administrator
    // permissions … SHALL be ignored by the server if it is provided by a client with
    // administrator permissions." A server that checked it anyway would lock out the
    // administrator that set the entry up, which is the one client guaranteed not to have a
    // copy of another client's key.
    let device = device();
    invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(HUB, HUB.0, &key(0xA1), None, ClientType::Permanent),
        &context(FABRIC, Privilege::Administer),
    );

    let outcome = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(
            HUB,
            PHONE.0,
            &key(0xB2),
            Some(&key(0xEE)),
            ClientType::Permanent,
        ),
        &context(FABRIC, Privilege::Administer),
    );
    assert!(
        matches!(outcome, Outcome::Response(_)),
        "a wrong key is ignored"
    );
    assert_eq!(device.icd.clients()[0].monitored_subject, PHONE.0);
}

#[test]
fn the_per_fabric_quota_stops_one_fabric_filling_the_table() {
    // §9.16.6.4: "The maximum number of entries that can be in the list SHALL be
    // ClientsSupportedPerFabric for **each fabric**." A single global limit would let the
    // first administrator to register leave every later fabric unable to.
    let device = device();
    let admin = context(FABRIC, Privilege::Administer);
    for id in 1..=2u64 {
        let outcome = invoke(
            &device,
            icd_management::REGISTER_CLIENT,
            &register_fields(NodeId(id), id, &key(id as u8), None, ClientType::Permanent),
            &admin,
        );
        assert!(matches!(outcome, Outcome::Response(_)), "entry {id}");
    }
    let outcome = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(NodeId(3), 3, &key(3), None, ClientType::Permanent),
        &admin,
    );
    assert!(matches!(
        outcome,
        Outcome::Status(Status::ResourceExhausted)
    ));

    // A second fabric still has its own two.
    let outcome = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(NodeId(3), 3, &key(3), None, ClientType::Permanent),
        &context(OTHER_FABRIC, Privilege::Administer),
    );
    assert!(matches!(outcome, Outcome::Response(_)));
    assert_eq!(device.icd.len_of_fabric(FABRIC), 2);
    assert_eq!(device.icd.len_of_fabric(OTHER_FABRIC), 1);
}

#[test]
fn unregistering_is_scoped_to_the_fabric_and_needs_the_same_proof() {
    let device = device();
    let secret = key(0xA1);
    invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(HUB, HUB.0, &secret, None, ClientType::Permanent),
        &context(FABRIC, Privilege::Administer),
    );

    // Another fabric cannot see it, so it is NOT_FOUND rather than a refusal — §9.16.7.3's
    // steps 1a and 2a give the same answer, and giving them different ones would tell an
    // unprivileged caller which node ids are registered on a fabric it cannot read.
    let outcome = invoke(
        &device,
        icd_management::UNREGISTER_CLIENT,
        &unregister_fields(HUB, None),
        &context(OTHER_FABRIC, Privilege::Administer),
    );
    assert!(matches!(outcome, Outcome::Status(Status::NotFound)));

    // A manager without the key: step 4a.
    let outcome = invoke(
        &device,
        icd_management::UNREGISTER_CLIENT,
        &unregister_fields(HUB, None),
        &context(FABRIC, Privilege::Manage),
    );
    assert!(matches!(outcome, Outcome::Status(Status::Failure)));
    assert_eq!(device.icd.clients().len(), 1);

    // With it: step 4c, and the entry goes.
    let outcome = invoke(
        &device,
        icd_management::UNREGISTER_CLIENT,
        &unregister_fields(HUB, Some(&secret)),
        &context(FABRIC, Privilege::Manage),
    );
    assert!(matches!(outcome, Outcome::Success));
    assert!(device.icd.clients().is_empty());
}

#[test]
fn removing_a_fabric_removes_its_registrations() {
    // §11.18.6.12's `RemoveFabric` must leave nothing of the fabric behind, and a registration
    // holds a key that can still decrypt this device's check-ins.
    let device = device();
    for (fabric, id) in [(FABRIC, 1u64), (OTHER_FABRIC, 2)] {
        invoke(
            &device,
            icd_management::REGISTER_CLIENT,
            &register_fields(NodeId(id), id, &key(id as u8), None, ClientType::Permanent),
            &context(fabric, Privilege::Administer),
        );
    }
    device.icd.remove_fabric(FABRIC);
    assert_eq!(device.icd.len_of_fabric(FABRIC), 0);
    assert_eq!(device.icd.len_of_fabric(OTHER_FABRIC), 1);
}

// --- The monitored subject ------------------------------------------------------------------

#[test]
fn a_cat_subject_matches_a_subscriber_at_that_version_or_higher() {
    // §9.16.5.3's own example: "if the MonitoredSubject has the value 0xFFFF_FFFD_AA12_0002,
    // and one of the subscribers … bears the CASE Authenticated TAG value 0xAA12 and the
    // version 0x0002 **or higher** within its NOC, then the entry matches."
    //
    // Comparing CATs for equality makes every client look absent the moment its tag version is
    // bumped, and the device starts sending check-ins to a client sitting there subscribed.
    let entry = Registration::new(
        HUB,
        0xFFFF_FFFD_AA12_0002,
        ClientType::Permanent,
        FABRIC,
        key(0xA1),
    );
    assert!(entry.matches_subscriber(PHONE, &[0xAA12_0002]));
    assert!(
        entry.matches_subscriber(PHONE, &[0xAA12_0009]),
        "a higher version"
    );
    assert!(
        !entry.matches_subscriber(PHONE, &[0xAA12_0001]),
        "a lower one"
    );
    assert!(
        !entry.matches_subscriber(PHONE, &[0xBB34_0002]),
        "another tag"
    );
    assert!(!entry.matches_subscriber(PHONE, &[]));

    // §9.16.5.3's first example: a plain Node ID subject is an equality test.
    let entry = Registration::new(HUB, HUB.0, ClientType::Permanent, FABRIC, key(0xA1));
    assert!(entry.matches_subscriber(HUB, &[]));
    assert!(!entry.matches_subscriber(PHONE, &[]));
    assert!(
        !entry.matches_subscriber(PHONE, &[0xAA12_0002]),
        "a CAT does not satisfy a node-id subject"
    );
}

// --- Where the two halves meet ---------------------------------------------------------------

#[test]
fn a_device_checks_in_to_the_client_that_registered_and_the_counter_lines_up() {
    // The only test where the cluster and the protocol are one feature. A cluster returning
    // the wrong `ICDCounter`, or a device sending a counter it had already spent, passes every
    // test on its own side and fails here.
    let device = device();
    device.icd.restore_counter(1_000);

    let token = key(0xA1);
    let Outcome::Response(start) = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(HUB, HUB.0, &token, None, ClientType::Permanent),
        &context(FABRIC, Privilege::Administer),
    ) else {
        panic!("registered")
    };
    assert_eq!(start, 1_000);

    // The client keeps what the response told it (§4.22.1.2).
    let mut client = checkin::Registration::new(token, u32::try_from(start).unwrap());

    // The device wakes and checks in, three times, with two of them lost on the air. The
    // first counter is 1001, not 1000: the value reported at registration is the client's
    // *starting* value, and a check-in bearing it has an offset of zero — a replay.
    let mut out = [0u8; 64];
    for expected in [1_001u32, 1_002, 1_003] {
        let counter = device.icd.next_check_in_counter();
        assert_eq!(counter, expected);
        let n = checkin::encrypt(device.icd.clients()[0].key(), counter, b"", &mut out)
            .expect("encrypt");
        if expected == 1_003 {
            // Only the last one arrives — a sleeping device's check-ins are lost routinely,
            // and the window has to tolerate the gap rather than demand every counter.
            let mut buf = out;
            let message = client.accept(&mut buf[..n]).expect("valid");
            assert_eq!(message.counter, 1_003);
            assert_eq!(client.offset(), 3);
        }
    }

    // A replay of the one that did arrive is refused.
    let n = checkin::encrypt(device.icd.clients()[0].key(), 1_003, b"", &mut out).expect("encrypt");
    let mut buf = out;
    assert!(client.accept(&mut buf[..n]).is_err());
    assert!(!client.needs_key_refresh());
}

#[test]
fn re_registering_gives_the_client_a_fresh_key_and_a_fresh_window() {
    // §4.22.3.4: a key is good for one pass through the counter space, and the client is the
    // one that has to notice. Re-registering is the whole remedy, and it must reset both the
    // key and the window — keeping either would carry the exhaustion across.
    let device = device();
    device.icd.restore_counter(0);
    let first = key(0xA1);
    invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(HUB, HUB.0, &first, None, ClientType::Permanent),
        &context(FABRIC, Privilege::Administer),
    );
    let mut client = checkin::Registration::new(first.clone(), 0);

    // The counter reaches half the space.
    let mut out = [0u8; 64];
    let n = checkin::encrypt(&first, KEY_REFRESH_OFFSET, b"", &mut out).expect("encrypt");
    let mut buf = out;
    client.accept(&mut buf[..n]).expect("still valid");
    assert!(client.needs_key_refresh());

    // The client re-registers with a new token, and the device answers with its counter.
    let second = key(0xB2);
    device.icd.restore_counter(77);
    let Outcome::Response(start) = invoke(
        &device,
        icd_management::REGISTER_CLIENT,
        &register_fields(HUB, HUB.0, &second, Some(&first), ClientType::Permanent),
        &context(FABRIC, Privilege::Manage),
    ) else {
        panic!("re-registered")
    };
    client.refresh(second.clone(), u32::try_from(start).unwrap());
    assert!(!client.needs_key_refresh());

    // And the device's next check-in, under the new key, is accepted.
    let counter = device.icd.next_check_in_counter();
    let n =
        checkin::encrypt(device.icd.clients()[0].key(), counter, b"", &mut out).expect("encrypt");
    let mut buf = out;
    assert_eq!(client.accept(&mut buf[..n]).expect("valid").counter, 78);

    // The old key no longer opens anything the device sends.
    let counter = device.icd.next_check_in_counter();
    let n =
        checkin::encrypt(device.icd.clients()[0].key(), counter, b"", &mut out).expect("encrypt");
    let mut buf = out;
    assert!(checkin::decrypt(&first, &mut buf[..n]).is_err());
}

#[test]
fn a_device_without_long_idle_time_support_will_not_pretend_to_have_it() {
    // §9.16.4.3: LITS "is supported if and only if the device is a Long Idle Time ICD". A SIT
    // device that let itself be switched to LIT would be telling clients to expect a polling
    // interval its radio never uses, and they would stop expecting it to answer.
    let sit_only = Icd::new(Feature::CHECK_IN_PROTOCOL_SUPPORT, timings());
    assert_eq!(sit_only.operating_mode(), OperatingMode::Sit);
    assert_eq!(
        sit_only.set_operating_mode(OperatingMode::Lit),
        Err(Status::UnsupportedAttribute)
    );

    // §9.16.4.4: without DSLS, a device may not switch while a client is registered — the
    // registered client was promised the mode it saw.
    let lit = Icd::new(EVERYTHING, timings());
    lit.set_operating_mode(OperatingMode::Lit)
        .expect("no clients yet");
    lit.set_operating_mode(OperatingMode::Sit)
        .expect("back again");
}

#[test]
fn the_counter_is_never_handed_out_twice() {
    // Reusing a Check-In Counter reuses the nonce it derives (§4.22.3.4), which costs the
    // confidentiality of both messages that share it. So reading and advancing are one
    // operation rather than two a caller could get out of order.
    let icd = Icd::new(EVERYTHING, timings());
    icd.restore_counter(u32::MAX - 1);
    assert_eq!(icd.next_check_in_counter(), u32::MAX);
    assert_eq!(
        icd.next_check_in_counter(),
        0,
        "§4.22.3.3's arithmetic is mod 2³²"
    );
    assert_eq!(icd.counter(), 0);
    assert_eq!(icd.next_check_in_counter(), 1);
}

#[test]
fn a_factory_reset_randomizes_the_counter_into_the_specified_range() {
    // §4.6.3: "The device SHALL randomize the initial value of the counter on factory reset per
    // Section 4.6.1.1" — which is `Crypto_DRBG(len = 28) + 1`, so `1..=2^28` and never zero.
    //
    // The cluster's constructor is a `const fn` with no randomness to draw on, so it starts at
    // zero and the device calls this once. Starting from zero on *every* boot is what §4.6.3
    // forbids: a client validates a check-in as `stored offset < received − start`, so a
    // counter that rewinds past a registered client's starting value makes every later check-in
    // look like a replay, and the client stops waking for a device that is calling it.
    const CEILING: u32 = 1 << 28;
    let icd = Icd::new(EVERYTHING, timings());
    assert_eq!(
        icd.counter(),
        0,
        "a factory-fresh cluster has no counter yet"
    );

    for randomness in [0u32, 1, 0x0FFF_FFFF, 0x1000_0000, 0xDEAD_BEEF, u32::MAX] {
        icd.randomize_counter(randomness);
        let start = icd.counter();
        assert!(
            (1..=CEILING).contains(&start),
            "{randomness:#010x} started at {start:#010x}"
        );
    }

    // And it is the same narrowing the message counters use, not a second one that drifted.
    icd.randomize_counter(0xDEAD_BEEF);
    assert_eq!(icd.counter(), matter_kit::msg::initial_counter(0xDEAD_BEEF));
}
