//! The diagnostics clusters against their specification tables (Core §11.12, §11.13).
//!
//! Chapters 11.12 and 11.13 publish tables, not vectors, so every id, revision, enum value and
//! feature bit here is a literal transcribed from one. The behaviours that are worth more than
//! transcription are the three where getting it wrong is invisible:
//!
//! * `TestEventTrigger`'s `EnableKey`, which is the only thing between a shipped product and a
//!   set of undocumented behaviours defined by certification test literature.
//! * The difference between an attribute that is absent and one that reads zero — "no heap"
//!   and "no heap free" are the same number and opposite facts.
//! * `ResetWatermarks`, which resets a high watermark to *current usage*, not to zero.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::Cell;

use matter_kit::clusters::general_diagnostics::{
    self, BootReason, DeviceLoad, Diagnostics, GeneralDiagnostics, HardwareFault, InterfaceType,
    NetworkFault, NetworkInterface, RadioFault, Unknown,
};
use matter_kit::clusters::software_diagnostics::{
    self, NoMetrics, SoftwareDiagnostics, SoftwareMetrics, ThreadMetrics,
};
use matter_kit::crypto::SymmetricKey;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, ClusterHandler, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Server, Status,
};
use matter_kit::platform::Instant;
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

const ENABLE_KEY: [u8; 16] = [0x11; 16];

/// A device that answers everything §11.12 allows it to.
struct Talkative {
    key: SymmetricKey,
    triggered: Cell<Option<u64>>,
}

impl Talkative {
    fn new() -> Self {
        Self {
            key: SymmetricKey::new(ENABLE_KEY),
            triggered: Cell::new(None),
        }
    }
}

impl Diagnostics for Talkative {
    fn network_interfaces(&self, emit: &mut dyn FnMut(&NetworkInterface<'_>)) {
        emit(&NetworkInterface {
            name: "wlan0",
            is_operational: true,
            off_premise_ipv4: Some(true),
            // "The value SHALL be null if the Node does not use such services or does not know
            // whether it can reach them" — a distinct answer from `false`.
            off_premise_ipv6: None,
            hardware_address: &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            ipv4_addresses: &[[192, 168, 1, 20]],
            ipv6_addresses: &[[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]],
            interface_type: InterfaceType::WiFi,
        });
    }

    fn reboot_count(&self) -> u16 {
        7
    }

    fn up_time(&self) -> u64 {
        86_400
    }

    fn total_operational_hours(&self) -> Option<u32> {
        Some(1_234)
    }

    fn boot_reason(&self) -> BootReason {
        BootReason::SoftwareUpdateCompleted
    }

    fn active_hardware_faults(&self, emit: &mut dyn FnMut(HardwareFault)) {
        emit(HardwareFault::Sensor);
        emit(HardwareFault::TamperDetected);
    }

    fn active_radio_faults(&self, emit: &mut dyn FnMut(RadioFault)) {
        emit(RadioFault::WiFiFault);
    }

    fn active_network_faults(&self, emit: &mut dyn FnMut(NetworkFault)) {
        emit(NetworkFault::NetworkJammed);
    }

    fn device_load(&self, ctx: &InteractionContext<'_>) -> Option<DeviceLoad> {
        Some(DeviceLoad {
            current_subscriptions: 3,
            // "If no accessing fabric is available, this field SHALL be set to zero."
            current_subscriptions_for_fabric: if ctx.fabric_index.is_some() { 2 } else { 0 },
            total_subscriptions_established: 9,
            total_im_messages_sent: 100,
            total_im_messages_received: 101,
        })
    }

    fn enable_key(&self) -> Option<&SymmetricKey> {
        Some(&self.key)
    }

    fn test_event_trigger(&self, trigger: u64) -> bool {
        if trigger == 0xFFFF_FFFF_0000_0001 {
            self.triggered.set(Some(trigger));
            return true;
        }
        false
    }

    fn posix_time_ms(&self) -> Option<u64> {
        Some(1_700_000_000_000)
    }
}

/// A runtime with a heap to talk about.
#[derive(Debug)]
struct Heap {
    used: Cell<u64>,
    watermark: Cell<u64>,
    stack_minimum: Cell<u32>,
}

impl SoftwareMetrics for Heap {
    fn thread_metrics(&self, emit: &mut dyn FnMut(&ThreadMetrics<'_>)) {
        emit(&ThreadMetrics {
            id: 1,
            name: "main",
            stack_free_current: Some(2_048),
            stack_free_minimum: Some(self.stack_minimum.get()),
            stack_size: Some(8_192),
        });
    }

    fn current_heap_free(&self) -> Option<u64> {
        Some(16_384 - self.used.get())
    }

    fn current_heap_used(&self) -> Option<u64> {
        Some(self.used.get())
    }

    fn current_heap_high_watermark(&self) -> Option<u64> {
        Some(self.watermark.get())
    }

    fn reset_watermarks(&self) {
        // §11.13.7.1: to *current usage*, not to zero.
        self.watermark.set(self.used.get());
        self.stack_minimum.set(2_048);
    }
}

/// The two nodes under test, furnished from the specification's own tables.
///
/// Both descriptors are **derived** rather than written out: the element set follows the
/// feature map, so `PayloadTestRequest` appears only with `DMTEST` and
/// `CurrentHeapHighWatermark` only with `WTRMRK`. The storage has to outlive the node that
/// borrows it; in a test, leaking it says "for the rest of the process" without pretending
/// otherwise.
fn general_endpoints() -> &'static [Endpoint<'static>] {
    static ONCE: std::sync::OnceLock<&'static [Endpoint<'static>]> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let conforming = Box::leak(Box::new(
            general_diagnostics::conforming(
                general_diagnostics::FEATURE_DATA_MODEL_TEST,
                &general_diagnostics::ALL_OPTIONAL,
            )
            .expect("sized"),
        ));
        let clusters: &'static [ClusterDescriptor<'static>] =
            Box::leak(Box::new([conforming.descriptor()]));
        Box::leak(Box::new([Endpoint::new(0, clusters)]))
    })
}

fn software_endpoints() -> &'static [Endpoint<'static>] {
    static ONCE: std::sync::OnceLock<&'static [Endpoint<'static>]> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let conforming = Box::leak(Box::new(
            software_diagnostics::conforming(
                software_diagnostics::FEATURE_WATERMARKS,
                &software_diagnostics::ALL_OPTIONAL,
            )
            .expect("sized"),
        ));
        let clusters: &'static [ClusterDescriptor<'static>] =
            Box::leak(Box::new([conforming.descriptor()]));
        Box::leak(Box::new([Endpoint::new(0, clusters)]))
    })
}

/// Reads one attribute straight through the handler, returning its encoded value as a
/// top-level TLV element.
fn read<H: ClusterHandler>(
    handler: &H,
    node: Node<'_>,
    cluster: u32,
    attribute: u32,
    ctx: &InteractionContext,
) -> Result<Vec<u8>, Status> {
    let resolved = node
        .resolve(0, cluster, attribute)
        .expect("the path exists");
    let mut buf = [0u8; 4096];
    let mut w = TlvWriter::new(&mut buf);
    handler.read(&resolved, ctx, &mut w, Tag::Anonymous)?;
    Ok(w.finish().expect("finish").to_vec())
}

/// The one value of an attribute read that carries a single unsigned element.
fn attribute_u64(bytes: &[u8]) -> u64 {
    TlvReader::new(bytes)
        .next_element()
        .unwrap()
        .unwrap()
        .unsigned()
        .expect("an unsigned attribute")
}

enum Outcome {
    Fields(Vec<u8>),
    Success,
    Status(Status),
}

fn invoke<H: ClusterHandler>(
    handler: &H,
    node: Node<'_>,
    cluster: u32,
    command: u32,
    fields: &[u8],
    ctx: &InteractionContext,
) -> Outcome {
    let data = CommandData {
        fields: Some(fields),
        ..CommandData::new(CommandPath::command(0, cluster, command))
    };
    let mut scratch = [0u8; 4096];
    let mut buf = [0u8; 8192];
    let access = AllowAll;
    let server = Server::new(node, &access, handler, 8);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    match responses.next().expect("one response").expect("decode") {
        InvokeResponse::Command(c) => Outcome::Fields(c.fields.expect("fields").to_vec()),
        InvokeResponse::Status(s) => {
            if s.status.status == Status::Success {
                Outcome::Success
            } else {
                Outcome::Status(s.status.status)
            }
        }
    }
}

fn trigger_fields(key: &[u8], trigger: u64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.octets(Tag::Context(0), key).unwrap();
    w.unsigned(Tag::Context(1), trigger).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn payload_test_fields(key: &[u8], value: u8, count: u16) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.octets(Tag::Context(0), key).unwrap();
    w.unsigned(Tag::Context(1), u64::from(value)).unwrap();
    w.unsigned(Tag::Context(2), u64::from(count)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// The one unsigned value of a single-field response.
fn one_unsigned(fields: &[u8]) -> u64 {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    reader.next_element().unwrap().unwrap();
    let first = reader.next_element().unwrap().unwrap();
    first.unsigned().expect("an unsigned field")
}

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_general_diagnostics_tables_match_the_specification() {
    // §11.12.3, §11.12.1, §11.12.4, §11.12.6, §11.12.7 and §11.12.8, transcribed.
    assert_eq!(general_diagnostics::ID, 0x0033);
    assert_eq!(general_diagnostics::REVISION, 3);
    assert_eq!(general_diagnostics::FEATURE_DATA_MODEL_TEST, 1 << 0);

    assert_eq!(general_diagnostics::NETWORK_INTERFACES, 0x0000);
    assert_eq!(general_diagnostics::REBOOT_COUNT, 0x0001);
    assert_eq!(general_diagnostics::UP_TIME, 0x0002);
    assert_eq!(general_diagnostics::TOTAL_OPERATIONAL_HOURS, 0x0003);
    assert_eq!(general_diagnostics::BOOT_REASON, 0x0004);
    assert_eq!(general_diagnostics::ACTIVE_HARDWARE_FAULTS, 0x0005);
    assert_eq!(general_diagnostics::ACTIVE_RADIO_FAULTS, 0x0006);
    assert_eq!(general_diagnostics::ACTIVE_NETWORK_FAULTS, 0x0007);
    assert_eq!(general_diagnostics::TEST_EVENT_TRIGGERS_ENABLED, 0x0008);
    // 0x0009 is reserved: "Attribute 0x0009 SHALL NOT be used in any implementation of
    // previous, current or future version of this specification."
    assert_eq!(general_diagnostics::DEVICE_LOAD_STATUS, 0x000A);

    assert_eq!(general_diagnostics::TEST_EVENT_TRIGGER, 0x00);
    assert_eq!(general_diagnostics::TIME_SNAPSHOT, 0x01);
    assert_eq!(general_diagnostics::TIME_SNAPSHOT_RESPONSE, 0x02);
    assert_eq!(general_diagnostics::PAYLOAD_TEST_REQUEST, 0x03);
    assert_eq!(general_diagnostics::PAYLOAD_TEST_RESPONSE, 0x04);

    assert_eq!(general_diagnostics::HARDWARE_FAULT_CHANGE, 0x00);
    assert_eq!(general_diagnostics::RADIO_FAULT_CHANGE, 0x01);
    assert_eq!(general_diagnostics::NETWORK_FAULT_CHANGE, 0x02);
    assert_eq!(general_diagnostics::BOOT_REASON_EVENT, 0x03);

    // §11.12.5's five enums, at their table values.
    assert_eq!(HardwareFault::Unspecified as u8, 0);
    assert_eq!(HardwareFault::TamperDetected as u8, 10);
    assert_eq!(RadioFault::Unspecified as u8, 0);
    assert_eq!(RadioFault::CellularFault as u8, 2);
    assert_eq!(RadioFault::EthernetFault as u8, 6);
    assert_eq!(NetworkFault::ConnectionFailed as u8, 3);
    assert_eq!(InterfaceType::Thread as u8, 4);
    assert_eq!(BootReason::Unspecified as u8, 0);
    assert_eq!(BootReason::SoftwareReset as u8, 6);
}

#[test]
fn the_software_diagnostics_tables_match_the_specification() {
    // §11.13.3, §11.13.1, §11.13.4, §11.13.6, §11.13.7, §11.13.8.
    assert_eq!(software_diagnostics::ID, 0x0034);
    assert_eq!(software_diagnostics::REVISION, 1);
    assert_eq!(software_diagnostics::FEATURE_WATERMARKS, 1 << 0);
    assert_eq!(software_diagnostics::THREAD_METRICS, 0x0000);
    assert_eq!(software_diagnostics::CURRENT_HEAP_FREE, 0x0001);
    assert_eq!(software_diagnostics::CURRENT_HEAP_USED, 0x0002);
    assert_eq!(software_diagnostics::CURRENT_HEAP_HIGH_WATERMARK, 0x0003);
    assert_eq!(software_diagnostics::RESET_WATERMARKS, 0x00);
    assert_eq!(software_diagnostics::SOFTWARE_FAULT, 0x00);
}

// --- General Diagnostics ------------------------------------------------------------------

#[test]
fn every_attribute_reads_back_what_the_device_reported() {
    let device = Talkative::new();
    let cluster = GeneralDiagnostics::new(&device, general_diagnostics::FEATURE_DATA_MODEL_TEST);
    let node = Node::new(general_endpoints());
    let ctx = InteractionContext::new().with_fabric(matter_kit::msg::FabricIndex(1));

    let value = |attribute| {
        attribute_u64(
            &read(&cluster, node, general_diagnostics::ID, attribute, &ctx).expect("read"),
        )
    };
    assert_eq!(value(general_diagnostics::REBOOT_COUNT), 7);
    assert_eq!(value(general_diagnostics::UP_TIME), 86_400);
    assert_eq!(value(general_diagnostics::TOTAL_OPERATIONAL_HOURS), 1_234);
    assert_eq!(
        value(general_diagnostics::BOOT_REASON),
        BootReason::SoftwareUpdateCompleted as u64
    );

    // The three fault lists, each an array of enum values.
    let faults = |attribute| -> Vec<u64> {
        let bytes = read(&cluster, node, general_diagnostics::ID, attribute, &ctx).expect("read");
        let mut reader = TlvReader::new(&bytes);
        reader.next_element().unwrap().unwrap();
        let mut out = Vec::new();
        while let Some(item) = reader.next_element().unwrap() {
            if item.value == Value::EndOfContainer {
                break;
            }
            out.push(item.unsigned().expect("an enum value"));
        }
        out
    };
    assert_eq!(
        faults(general_diagnostics::ACTIVE_HARDWARE_FAULTS),
        vec![
            HardwareFault::Sensor as u64,
            HardwareFault::TamperDetected as u64
        ]
    );
    assert_eq!(
        faults(general_diagnostics::ACTIVE_RADIO_FAULTS),
        vec![RadioFault::WiFiFault as u64]
    );
    assert_eq!(
        faults(general_diagnostics::ACTIVE_NETWORK_FAULTS),
        vec![NetworkFault::NetworkJammed as u64]
    );
}

#[test]
fn an_unknown_off_premise_reachability_is_null_and_not_false() {
    // §11.12.5.6: "The value SHALL be null if the Node does not use such services or does not
    // know whether it can reach them." `false` says the node tried and failed, which sends a
    // support engineer looking for a network problem that does not exist.
    let device = Talkative::new();
    let cluster = GeneralDiagnostics::new(&device, 0);
    let node = Node::new(general_endpoints());
    let ctx = InteractionContext::new();
    let bytes = read(
        &cluster,
        node,
        general_diagnostics::ID,
        general_diagnostics::NETWORK_INTERFACES,
        &ctx,
    )
    .expect("read");

    let mut reader = TlvReader::new(&bytes);
    reader.next_element().unwrap().unwrap(); // the array
    reader.next_element().unwrap().unwrap(); // the struct
    let mut seen = Vec::new();
    while let Some(field) = reader.next_element().unwrap() {
        if field.value == Value::EndOfContainer {
            break;
        }
        seen.push((field.tag.context(), field.value.is_null()));
        if field.value.container().is_some() {
            // Skip the two address arrays wholesale.
            let mut depth = 1;
            while depth > 0 {
                let inner = reader.next_element().unwrap().unwrap();
                if inner.value == Value::EndOfContainer {
                    depth -= 1;
                } else if inner.value.container().is_some() {
                    depth += 1;
                }
            }
        }
    }
    let is_null = |tag| seen.iter().find(|(t, _)| *t == Some(tag)).unwrap().1;
    assert!(!is_null(2), "OffPremiseServicesReachableIPv4 was answered");
    assert!(
        is_null(3),
        "OffPremiseServicesReachableIPv6 is null, not false"
    );
}

#[test]
fn device_load_reports_zero_for_the_fabric_when_there_is_no_accessing_fabric() {
    // §11.12.5.7: "If no accessing fabric is available, this field SHALL be set to zero." The
    // other fields are node-wide and stay as they are.
    let device = Talkative::new();
    let cluster = GeneralDiagnostics::new(&device, 0);
    let node = Node::new(general_endpoints());

    let for_fabric = |ctx: &InteractionContext| {
        let bytes = read(
            &cluster,
            node,
            general_diagnostics::ID,
            general_diagnostics::DEVICE_LOAD_STATUS,
            ctx,
        )
        .expect("read");
        let mut reader = TlvReader::new(&bytes);
        reader.next_element().unwrap().unwrap(); // the struct
        reader.next_element().unwrap().unwrap(); // CurrentSubscriptions
        reader
            .next_element()
            .unwrap()
            .unwrap()
            .unsigned()
            .expect("CurrentSubscriptionsForFabric")
    };
    assert_eq!(
        for_fabric(&InteractionContext::new().with_fabric(matter_kit::msg::FabricIndex(1))),
        2
    );
    assert_eq!(for_fabric(&InteractionContext::new()), 0);
}

#[test]
fn a_device_with_no_enable_key_answers_nothing_and_cannot_be_talked_into_one() {
    // §11.12.7.1: "Devices not targeted towards going to a certification test event SHALL NOT
    // have a non-zero EnableKey value configured, so that only devices in test environments
    // are responsive to this command." A shipped product that answered these would carry a set
    // of behaviours the specification deliberately does not document.
    let shipped = Unknown;
    let cluster = GeneralDiagnostics::new(&shipped, general_diagnostics::FEATURE_DATA_MODEL_TEST);
    let node = Node::new(general_endpoints());
    let ctx = InteractionContext::new();
    assert!(!cluster.triggers_enabled());

    for key in [&ENABLE_KEY, &[0u8; 16]] {
        let outcome = invoke(
            &cluster,
            node,
            general_diagnostics::ID,
            general_diagnostics::TEST_EVENT_TRIGGER,
            &trigger_fields(key, 1),
            &ctx,
        );
        assert!(matches!(outcome, Outcome::Status(Status::ConstraintError)));
    }

    // And it cannot be switched into test mode either, because there would be nothing for a
    // caller's key to match.
    assert_eq!(
        cluster.set_triggers_enabled(true),
        Err(Status::ConstraintError)
    );
}

#[test]
fn the_enable_key_must_match_and_all_zeroes_never_does() {
    let device = Talkative::new();
    let cluster = GeneralDiagnostics::new(&device, general_diagnostics::FEATURE_DATA_MODEL_TEST);
    let node = Node::new(general_endpoints());
    let ctx = InteractionContext::new();
    assert!(
        cluster.triggers_enabled(),
        "a provisioned key means test mode"
    );

    let attempt = |key: &[u8], trigger: u64| {
        invoke(
            &cluster,
            node,
            general_diagnostics::ID,
            general_diagnostics::TEST_EVENT_TRIGGER,
            &trigger_fields(key, trigger),
            &ctx,
        )
    };

    // "this command SHALL respond with a response status of CONSTRAINT_ERROR if the EnableKey
    // field does not match the a-priori value configured on the device."
    assert!(matches!(
        attempt(&[0x22; 16], 0xFFFF_FFFF_0000_0001),
        Outcome::Status(Status::ConstraintError)
    ));
    // "The value of all zeroes is reserved to indicate that no EnableKey is set. Therefore, if
    // the EnableKey field is received with all zeroes, this command SHALL FAIL."
    assert!(matches!(
        attempt(&[0u8; 16], 0xFFFF_FFFF_0000_0001),
        Outcome::Status(Status::ConstraintError)
    ));
    // The field is constrained to exactly 16 octets.
    assert!(matches!(
        attempt(&[0x11; 8], 0xFFFF_FFFF_0000_0001),
        Outcome::Status(Status::ConstraintError)
    ));
    assert_eq!(device.triggered.get(), None, "nothing ran");

    // The right key and a supported trigger.
    assert!(matches!(
        attempt(&ENABLE_KEY, 0xFFFF_FFFF_0000_0001),
        Outcome::Success
    ));
    assert_eq!(device.triggered.get(), Some(0xFFFF_FFFF_0000_0001));

    // "If the value of EventTrigger received is not supported by the receiving Node, this
    // command SHALL fail with a status code of INVALID_COMMAND" — a different answer from a
    // wrong key, deliberately: a test operator needs to tell "wrong device" from "wrong test".
    assert!(matches!(
        attempt(&ENABLE_KEY, 0xDEAD),
        Outcome::Status(Status::InvalidCommand)
    ));
}

/// A device whose configured key is all zeros — §11.12.7.1 says that *is* "no key set".
struct Misconfigured(SymmetricKey);

impl Diagnostics for Misconfigured {
    fn enable_key(&self) -> Option<&SymmetricKey> {
        Some(&self.0)
    }

    fn test_event_trigger(&self, _trigger: u64) -> bool {
        true
    }
}

#[test]
fn an_all_zero_enable_key_is_no_key_even_when_it_matches() {
    // The rule that only bites on a device somebody misconfigured, which is the only kind that
    // needs it. "The value of all zeroes is reserved to indicate that no EnableKey is set."
    // A server that merely compared the offered key against the configured one would let such
    // a device be unlocked by sixteen zero bytes — a key an attacker guesses on the first try,
    // and the likeliest value for a field nobody remembered to provision.
    let device = Misconfigured(SymmetricKey::new([0u8; 16]));
    let cluster = GeneralDiagnostics::new(&device, general_diagnostics::FEATURE_DATA_MODEL_TEST);
    let node = Node::new(general_endpoints());
    let ctx = InteractionContext::new();

    let outcome = invoke(
        &cluster,
        node,
        general_diagnostics::ID,
        general_diagnostics::TEST_EVENT_TRIGGER,
        &trigger_fields(&[0u8; 16], 1),
        &ctx,
    );
    assert!(
        matches!(outcome, Outcome::Status(Status::ConstraintError)),
        "all zeroes must be refused even against an all-zero configured key"
    );

    // And `PayloadTestRequest` shares the check, so it is refused the same way.
    let outcome = invoke(
        &cluster,
        node,
        general_diagnostics::ID,
        general_diagnostics::PAYLOAD_TEST_REQUEST,
        &payload_test_fields(&[0u8; 16], 0x55, 4),
        &ctx,
    );
    assert!(matches!(outcome, Outcome::Status(Status::ConstraintError)));
}

#[test]
fn payload_test_returns_exactly_what_it_was_asked_for() {
    // §11.12.7.4's own two examples, byte for byte.
    let device = Talkative::new();
    let cluster = GeneralDiagnostics::new(&device, general_diagnostics::FEATURE_DATA_MODEL_TEST);
    let node = Node::new(general_endpoints());
    let ctx = InteractionContext::new();

    let payload = |value: u8, count: u16| -> Vec<u8> {
        let Outcome::Fields(fields) = invoke(
            &cluster,
            node,
            general_diagnostics::ID,
            general_diagnostics::PAYLOAD_TEST_REQUEST,
            &payload_test_fields(&ENABLE_KEY, value, count),
            &ctx,
        ) else {
            panic!("PayloadTestRequest answers with PayloadTestResponse")
        };
        let mut reader = TlvReader::new_in(&fields, ContainerKind::Structure);
        reader.next_element().unwrap().unwrap();
        reader
            .next_element()
            .unwrap()
            .unwrap()
            .octets()
            .expect("the Payload field")
            .to_vec()
    };

    // "If Value is 0x55 and the Count is zero, then the PayloadTestResponse would have the
    // Payload field set to an empty octet string."
    assert!(payload(0x55, 0).is_empty());
    // "If Value is 0xA5 and the Count is 10 … A5A5A5A5A5A5A5A5A5A5".
    assert_eq!(payload(0xA5, 10), vec![0xA5u8; 10]);

    // The command is gated on the same key, and on the DMTEST feature.
    let outcome = invoke(
        &cluster,
        node,
        general_diagnostics::ID,
        general_diagnostics::PAYLOAD_TEST_REQUEST,
        &payload_test_fields(&[0x22; 16], 0x55, 4),
        &ctx,
    );
    assert!(matches!(outcome, Outcome::Status(Status::ConstraintError)));

    // "max 2048" on Count.
    let outcome = invoke(
        &cluster,
        node,
        general_diagnostics::ID,
        general_diagnostics::PAYLOAD_TEST_REQUEST,
        &payload_test_fields(&ENABLE_KEY, 0x55, 2_049),
        &ctx,
    );
    assert!(matches!(outcome, Outcome::Status(Status::ConstraintError)));
}

#[test]
fn time_snapshot_reports_the_action_s_own_instant() {
    // §11.12.7.3: "all fields SHALL be gathered as close together in time as possible, so that
    // the time jitter between the values is minimized" — the whole point of the command is to
    // let a client align its clock with the one that stamps this node's events, so a second
    // clock read here would be the jitter it is meant to avoid.
    let device = Talkative::new();
    let cluster = GeneralDiagnostics::new(&device, 0);
    let node = Node::new(general_endpoints());
    let ctx = InteractionContext::new().at(Instant::from_micros(12_345_678));

    let mut buf = [0u8; 16];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.end_container().unwrap();
    let empty = w.finish().unwrap().to_vec();

    let Outcome::Fields(fields) = invoke(
        &cluster,
        node,
        general_diagnostics::ID,
        general_diagnostics::TIME_SNAPSHOT,
        &empty,
        &ctx,
    ) else {
        panic!("TimeSnapshot answers with TimeSnapshotResponse")
    };
    assert_eq!(one_unsigned(&fields), 12_345, "systime-ms, truncated");

    // A node without Time Synchronization writes null rather than guessing.
    let silent = Unknown;
    let quiet = GeneralDiagnostics::new(&silent, 0);
    let Outcome::Fields(fields) = invoke(
        &quiet,
        node,
        general_diagnostics::ID,
        general_diagnostics::TIME_SNAPSHOT,
        &empty,
        &ctx,
    ) else {
        panic!("a response")
    };
    let mut reader = TlvReader::new_in(&fields, ContainerKind::Structure);
    reader.next_element().unwrap().unwrap();
    reader.next_element().unwrap().unwrap(); // SystemTimeMs
    let posix = reader.next_element().unwrap().unwrap();
    assert_eq!(posix.tag, Tag::Context(1));
    assert!(posix.value.is_null(), "PosixTimeMs is null, not zero");
}

// --- Software Diagnostics ---------------------------------------------------------------------

#[test]
fn a_node_with_no_heap_reports_no_heap_rather_than_zero() {
    // "0 bytes free" and "there is no heap" are the same number and opposite facts. The first
    // reads as a device about to fall over.
    let metrics = NoMetrics;
    let cluster = SoftwareDiagnostics::new(&metrics, 0);
    let node = Node::new(software_endpoints());
    let ctx = InteractionContext::new();
    for attribute in [
        software_diagnostics::CURRENT_HEAP_FREE,
        software_diagnostics::CURRENT_HEAP_USED,
        software_diagnostics::CURRENT_HEAP_HIGH_WATERMARK,
    ] {
        assert_eq!(
            read(&cluster, node, software_diagnostics::ID, attribute, &ctx),
            Err(Status::UnsupportedAttribute)
        );
    }
    // The thread list is still a list — an empty one, which is a fact rather than an absence.
    read(
        &cluster,
        node,
        software_diagnostics::ID,
        software_diagnostics::THREAD_METRICS,
        &ctx,
    )
    .expect("an empty list");
}

#[test]
fn the_watermark_attribute_and_command_follow_the_feature_bit() {
    // §11.13.6 and §11.13.7 both mark these `WTRMRK` rather than `O`: the feature bit is the
    // promise they exist, so serving them without declaring it contradicts the `FeatureMap` a
    // client read first.
    let heap = Heap {
        used: Cell::new(4_096),
        watermark: Cell::new(12_000),
        stack_minimum: Cell::new(64),
    };
    let node = Node::new(software_endpoints());
    let ctx = InteractionContext::new();

    let without = SoftwareDiagnostics::new(&heap, 0);
    assert_eq!(
        read(
            &without,
            node,
            software_diagnostics::ID,
            software_diagnostics::CURRENT_HEAP_HIGH_WATERMARK,
            &ctx
        ),
        Err(Status::UnsupportedAttribute)
    );
    let outcome = invoke(
        &without,
        node,
        software_diagnostics::ID,
        software_diagnostics::RESET_WATERMARKS,
        &[],
        &ctx,
    );
    assert!(matches!(
        outcome,
        Outcome::Status(Status::UnsupportedCommand)
    ));
    assert_eq!(heap.watermark.get(), 12_000, "and nothing was reset");
}

#[test]
fn resetting_a_watermark_sets_it_to_current_usage_not_to_zero() {
    // §11.13.7.1: "the server SHALL set the value of the CurrentHeapHighWatermark attribute to
    // the value of the CurrentHeapUsed attribute", and each thread's StackFreeMinimum to its
    // StackFreeCurrent. A watermark reset to zero claims the node once used no memory at all,
    // and then does not rise again until usage passes the real peak — so the one number that
    // said how close the device came is quietly replaced by one that says nothing.
    let heap = Heap {
        used: Cell::new(4_096),
        watermark: Cell::new(12_000),
        stack_minimum: Cell::new(64),
    };
    let cluster = SoftwareDiagnostics::new(&heap, software_diagnostics::FEATURE_WATERMARKS);
    let node = Node::new(software_endpoints());
    let ctx = InteractionContext::new();

    let watermark = || {
        attribute_u64(
            &read(
                &cluster,
                node,
                software_diagnostics::ID,
                software_diagnostics::CURRENT_HEAP_HIGH_WATERMARK,
                &ctx,
            )
            .expect("read"),
        )
    };
    assert_eq!(watermark(), 12_000);

    let outcome = invoke(
        &cluster,
        node,
        software_diagnostics::ID,
        software_diagnostics::RESET_WATERMARKS,
        &[],
        &ctx,
    );
    assert!(matches!(outcome, Outcome::Success));
    assert_eq!(watermark(), 4_096, "current usage, not zero");
    assert_eq!(heap.stack_minimum.get(), 2_048, "and the stack likewise");
}
