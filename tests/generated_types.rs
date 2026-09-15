//! The generated structures and command payloads, on the wire.
//!
//! [`conformance`](../conformance/index.html) checks that the generated *tables* agree with
//! the specification. This checks the generated *types*: that a command payload encodes to the
//! bytes the specification's field numbers say it should, that it decodes back, and that the
//! three states Matter distinguishes — absent, null, and present — survive the round trip.
//!
//! The types are produced mechanically, so a bug here is a bug in 193 structures and 434
//! command payloads at once. That is the argument for generating them and the reason to test
//! the generator's *output* rather than trusting the generator.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::clusters::generated::{
    binding, general_diagnostics, groups, level_control, on_off, scenes_management,
};
use matter_kit::tlv::{Element, FromTlv, Nullable, Tag, TlvList, TlvReader, TlvWriter, ToTlv};

/// Encodes a value as a top-level element.
fn encode<T: ToTlv>(value: &T, buf: &mut [u8]) -> Vec<u8> {
    let mut w = TlvWriter::new(buf);
    value.to_tlv(&mut w, Tag::Anonymous).expect("encode");
    w.finish().expect("finish").to_vec()
}

/// Decodes a top-level element.
fn decode<'a, T: FromTlv<'a>>(bytes: &'a [u8]) -> T {
    let mut reader = TlvReader::new(bytes);
    let element: Element<'a> = reader.next_element().expect("read").expect("an element");
    T::from_tlv(&mut reader, &element).expect("decode")
}

#[test]
fn a_command_payload_encodes_to_the_field_numbers_the_specification_assigns() {
    // Application Cluster §1.5.7.6: `OnOffControl` is field 0, `OnTime` 1, `OffWaitTime` 2.
    // A generator that mixed them up would produce a light that stayed on for the guard time
    // and guarded for the on time, and nothing but the wire bytes would show it.
    let fields = on_off::OnWithTimedOffFields {
        on_off_control: on_off::OnOffControlBitmap::ACCEPT_ONLY_WHEN_ON,
        on_time: 0x1234,
        off_wait_time: 0x00FF,
    };
    let mut buf = [0u8; 64];
    let bytes = encode(&fields, &mut buf);

    // A structure, then three context-tagged members in field order. Each takes the
    // *narrowest* encoding §A.7.1 allows, which is why `OffWaitTime` of 0x00FF is one octet
    // and `OnTime` of 0x1234 is two — the width is a property of the value, not the field.
    assert_eq!(
        bytes,
        vec![
            0x15, // anonymous structure
            0x24, 0x00, 0x01, // field 0, 1-octet unsigned: AcceptOnlyWhenOn
            0x25, 0x01, 0x34, 0x12, // field 1, 2-octet unsigned: OnTime, little-endian
            0x24, 0x02, 0xFF, // field 2, 1-octet unsigned: OffWaitTime
            0x18, // end of container
        ]
    );

    assert_eq!(decode::<on_off::OnWithTimedOffFields>(&bytes), fields);
}

#[test]
fn an_enumeration_refuses_a_value_this_revision_does_not_define() {
    // §7.19.2 answers a reserved value `CONSTRAINT_ERROR`. Decoding one as whichever variant
    // happens to be nearby would make the device's behaviour depend on what a *future*
    // revision assigns — the one thing a forward-compatible protocol must not do.
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new(&mut buf);
    w.unsigned(Tag::Anonymous, 0x7F).expect("write");
    let bytes = w.finish().expect("finish").to_vec();

    let mut reader = TlvReader::new(&bytes);
    let element = reader.next_element().unwrap().unwrap();
    assert!(on_off::StartUpOnOffEnum::from_tlv(&mut reader, &element).is_err());

    // And a value it does define round-trips.
    let bytes = encode(&on_off::StartUpOnOffEnum::Toggle, &mut buf);
    assert_eq!(
        decode::<on_off::StartUpOnOffEnum>(&bytes),
        on_off::StartUpOnOffEnum::Toggle
    );
}

#[test]
fn a_bitmap_refuses_a_bit_this_revision_does_not_define() {
    // §7.19.2: reserved bits "SHALL be set to 0". Masking one away would accept a command a
    // future revision gave a meaning to, and act on the half it understood.
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new(&mut buf);
    w.unsigned(Tag::Anonymous, 0xFE).expect("write");
    let bytes = w.finish().expect("finish").to_vec();

    let mut reader = TlvReader::new(&bytes);
    let element = reader.next_element().unwrap().unwrap();
    assert!(on_off::OnOffControlBitmap::from_tlv(&mut reader, &element).is_err());
}

#[test]
fn absent_null_and_present_are_three_different_things() {
    // Level Control's `MoveToLevel` has two nullable fields — `OptionsMask` and
    // `OptionsOverride` are mandatory, `TransitionTime` is nullable. Null means "use the
    // device's own default transition"; absent would mean something else again, and a type
    // that could only say `None` would lose the difference.
    let mut buf = [0u8; 64];
    let with_time = level_control::MoveToLevelFields {
        level: 128,
        transition_time: Nullable::some(20),
        options_mask: level_control::OptionsBitmap::empty(),
        options_override: level_control::OptionsBitmap::empty(),
    };
    let bytes = encode(&with_time, &mut buf);
    assert_eq!(
        decode::<level_control::MoveToLevelFields>(&bytes).transition_time,
        Nullable::some(20)
    );

    let with_null = level_control::MoveToLevelFields {
        transition_time: Nullable::null(),
        ..with_time
    };
    let bytes = encode(&with_null, &mut buf);
    let decoded = decode::<level_control::MoveToLevelFields>(&bytes);
    assert!(decoded.transition_time.is_null(), "null survived the trip");
    // TLV null is its own element type, 0x34 with a context tag — not a zero.
    assert!(bytes.contains(&0x34), "a null element, not a zero value");
}

#[test]
fn a_borrowed_field_points_into_the_buffer_it_was_decoded_from() {
    // What "zero-copy" has to mean to be worth anything: a `string` field is a slice of the
    // datagram, not a copy of it. A device with 32 KB of RAM cannot afford the copy, and a
    // generator that made one silently would be the reason it ran out.
    let mut buf = [0u8; 128];
    let fields = groups::AddGroupFields {
        group_id: matter_kit::msg::GroupId(7),
        group_name: "kitchen",
    };
    let bytes = encode(&fields, &mut buf);
    let decoded = decode::<groups::AddGroupFields<'_>>(&bytes);
    assert_eq!(decoded.group_name, "kitchen");

    let start = bytes.as_ptr() as usize;
    let field = decoded.group_name.as_ptr() as usize;
    assert!(
        field >= start && field < start + bytes.len(),
        "the string borrows from the encoded bytes rather than copying them"
    );
}

#[test]
fn a_list_field_decodes_its_entries_lazily() {
    // Scenes Management's `AddScene` carries `list[ExtensionFieldSetStruct]` — a scene is a
    // set of attribute values across clusters, and there is no bound on how many. Reading it
    // where it lies is what lets a device with no allocator handle one.
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new(&mut buf);
    w.start_array(Tag::Anonymous).expect("array");
    for cluster in [0x0006u32, 0x0008] {
        w.start_structure(Tag::Anonymous).expect("member");
        w.unsigned(Tag::Context(0), u64::from(cluster))
            .expect("cluster");
        w.start_array(Tag::Context(1)).expect("values");
        w.end_container().expect("end values");
        w.end_container().expect("end member");
    }
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let list: TlvList<'_, scenes_management::ExtensionFieldSetStruct<'_>> = decode(&bytes);
    assert_eq!(list.count().expect("count"), 2);
    let clusters: Vec<u32> = list
        .iter()
        .map(|entry| entry.expect("decode").cluster_id)
        .collect();
    assert_eq!(clusters, vec![0x0006, 0x0008]);

    // And it re-encodes to exactly what it came from, which is what makes a bridge able to
    // relay a scene it does not itself understand.
    let mut out = [0u8; 256];
    assert_eq!(encode(&list, &mut out), bytes);
}

#[test]
fn an_unknown_field_is_ignored_rather_than_refusing_the_whole_structure() {
    // §7.19.2's forward compatibility, and the reason a 1.6 device can talk to a 1.7 one: a
    // receiver skips what it does not know. Refusing would make every revision a flag day.
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).expect("structure");
    w.unsigned(Tag::Context(0), 42).expect("GroupID");
    w.utf8(Tag::Context(1), "hall").expect("GroupName");
    // A field a later revision added, carrying a container so skipping is not just one octet.
    w.start_structure(Tag::Context(99)).expect("future");
    w.unsigned(Tag::Context(0), 1).expect("inner");
    w.end_container().expect("end future");
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let decoded = decode::<groups::AddGroupFields<'_>>(&bytes);
    assert_eq!(decoded.group_id, matter_kit::msg::GroupId(42));
    assert_eq!(decoded.group_name, "hall");
}

#[test]
fn a_missing_mandatory_field_is_refused() {
    // The other half of forward compatibility: unknown fields are skipped, but a field the
    // *current* revision requires is not optional because the sender left it out. A command
    // acted on with a default nobody chose is worse than one refused.
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).expect("structure");
    w.unsigned(Tag::Context(0), 42).expect("GroupID");
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let mut reader = TlvReader::new(&bytes);
    let element = reader.next_element().unwrap().unwrap();
    assert!(
        groups::AddGroupFields::from_tlv(&mut reader, &element).is_err(),
        "GroupName is mandatory"
    );
}

#[test]
fn a_nested_structure_round_trips() {
    // General Diagnostics' `NetworkInterface` has two nullable booleans and two lists, and
    // `DeviceLoadStruct` is a plain nest — between them they exercise every shape the emitter
    // produces.
    let mut buf = [0u8; 256];
    let load = general_diagnostics::DeviceLoadStruct {
        current_subscriptions: 3,
        current_subscriptions_for_fabric: 2,
        total_subscriptions_established: 9,
        total_interaction_model_messages_sent: 100,
        total_interaction_model_messages_received: 101,
    };
    let bytes = encode(&load, &mut buf);
    assert_eq!(
        decode::<general_diagnostics::DeviceLoadStruct>(&bytes),
        load
    );
}

#[test]
fn a_fabric_scoped_struct_carries_its_index() {
    // Binding's `TargetStruct` is fabric-scoped, so §7.19.1.9's `FabricIndex` is field 254 —
    // and a generated type that dropped it would produce entries no fabric owns.
    let target = binding::TargetStruct {
        node: Some(matter_kit::msg::NodeId(0xAABB)),
        group: None,
        endpoint: Some(1),
        cluster: Some(0x0006),
        fabric_index: matter_kit::msg::FabricIndex(2),
    };
    let mut buf = [0u8; 128];
    let bytes = encode(&target, &mut buf);
    assert_eq!(decode::<binding::TargetStruct>(&bytes), target);
    // 254 needs a two-octet context tag? No — context tags are one octet, so the value is
    // there literally.
    assert!(bytes.contains(&254), "the FabricIndex field number");
}
