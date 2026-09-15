//! DNS-SD against Core §4.3's own worked examples.
//!
//! §4.3.1.14 prints the exact Multicast DNS records a commissionable node publishes, for two
//! different device configurations, down to the TXT strings and the subtype names. §4.3.2.1
//! prints an operational instance name. Those are the vectors here — everything asserted is a
//! line from the specification, not a second copy of this crate's opinion.
//!
//! The DNS wire format gets the other kind of test: encode, decode, and assert the round trip,
//! plus the hostile cases a compression pointer makes possible.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use matter_kit::discovery::dns::{
    CACHE_FLUSH, CLASS_IN, DnsWriter, FLAGS_QUERY, FLAGS_RESPONSE, HEADER_LEN, Name, Questions,
    RDATA_MAX, ReadData, Record, RecordData, RecordType, ResourceRecords, Section,
    UNICAST_RESPONSE,
};
use matter_kit::discovery::responder::{Advertisement, Responder};
use matter_kit::discovery::schedule::{Action, Schedule, Tiebreak, Tiebreaker, tiebreak};
use matter_kit::discovery::txt::{
    CommissionableTxt, CommissioningMode, JointFabric, MrpAdvertisement, OperationalTxt,
    TransportModes, TxtReader, TxtWriter, parse_decimal,
};
use matter_kit::discovery::{
    self, COMMISSIONABLE_SERVICE, COMMISSIONING_MODE_SUBTYPE, LOCAL_DOMAIN, MDNS_PORT,
    OPERATIONAL_SERVICE,
};
use matter_kit::msg::VendorId;
use matter_kit::platform::Instant;

// --- The naming conventions ---------------------------------------------------------------------

#[test]
fn the_service_types_match_section_4_3() {
    assert_eq!(COMMISSIONABLE_SERVICE, ["_matterc", "_udp"]);
    // "_matter._tcp. Note that the string _tcp is boilerplate text inherited from the original
    // DNS SRV specification … and doesn't necessarily mean that the advertised
    // application-layer protocol runs only over TCP."
    assert_eq!(OPERATIONAL_SERVICE, ["_matter", "_tcp"]);
    assert_eq!(discovery::COMMISSIONER_SERVICE, ["_matterd", "_udp"]);
    assert_eq!(LOCAL_DOMAIN, "local");
    assert_eq!(MDNS_PORT, 5353);
    assert_eq!(
        discovery::MDNS_IPV6_GROUP,
        [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB]
    );
    // RFC 6762 §10's two TTLs.
    assert_eq!(discovery::HOST_RECORD_TTL, 120);
    assert_eq!(discovery::OTHER_RECORD_TTL, 4500);
}

#[test]
fn the_commissionable_instance_name_is_sixteen_uppercase_hex_digits() {
    // §4.3.1: "a fixed-length sixteen-character hexadecimal string, encoded as ASCII (UTF-8)
    // text using capital letters, e.g., DD200C20D25AE5F7."
    let name = discovery::commissionable_instance_name(0xDD20_0C20_D25A_E5F7);
    assert_eq!(name.as_str(), "DD200C20D25AE5F7");
    assert_eq!(name.len(), 16);
    // Leading zeroes are *not* omitted here — it is a fixed-length field, unlike every
    // subtype, which is where the two conventions are easy to confuse.
    assert_eq!(
        discovery::commissionable_instance_name(1).as_str(),
        "0000000000000001"
    );
}

#[test]
fn the_host_name_is_the_link_layer_address_in_hex() {
    // §4.3.1.1's own example: "a 48-bit device MAC address … e.g., B75AFB458ECD.<domain>".
    let host = discovery::host_name(&[0xB7, 0x5A, 0xFB, 0x45, 0x8E, 0xCD]).expect("48-bit");
    assert_eq!(host.as_str(), "B75AFB458ECD");
    // A 64-bit MAC Extended Address, for Thread.
    let host = discovery::host_name(&[1, 2, 3, 4, 5, 6, 7, 8]).expect("64-bit");
    assert_eq!(host.as_str(), "0102030405060708");
    // Nothing else has a defined form: "If future link layers are supported by Matter that do
    // not use 48-bit MAC addresses or 64-bit MAC Extended Address identifiers, then a similar
    // rule will be defined for those technologies."
    assert!(discovery::host_name(&[1, 2, 3, 4]).is_err());
    assert!(discovery::host_name(&[]).is_err());
}

#[test]
fn the_subtypes_match_section_4_3_1_3s_examples() {
    // "_L840" and "_S3" for discriminator 840, from §4.3.1.14's first example.
    assert_eq!(discovery::long_discriminator_subtype(840).as_str(), "_L840");
    assert_eq!(discovery::short_discriminator_subtype(840).as_str(), "_S3");
    // "_V123" for Vendor ID 123, "_T81" for device type 81 — both from the second example.
    assert_eq!(discovery::vendor_subtype(VendorId(123)).as_str(), "_V123");
    assert_eq!(discovery::device_type_subtype(81).as_str(), "_T81");
    assert_eq!(COMMISSIONING_MODE_SUBTYPE, "_CM");

    // Every one is "a variable-length decimal number in ASCII text, omitting any leading
    // zeroes" — so zero is the single digit `0`, not the empty string.
    assert_eq!(discovery::long_discriminator_subtype(0).as_str(), "_L0");
    assert_eq!(discovery::short_discriminator_subtype(0).as_str(), "_S0");
    // The discriminator is twelve bits: anything above is masked, not rejected, because a
    // caller cannot express a thirteen-bit one.
    assert_eq!(
        discovery::long_discriminator_subtype(0xF000 | 840).as_str(),
        "_L840"
    );
    // The short discriminator is "the upper 4 bits": 0xFFF >> 8 is 15.
    assert_eq!(
        discovery::short_discriminator_subtype(0x0FFF).as_str(),
        "_S15"
    );
}

// --- The TXT records --------------------------------------------------------------------------

/// Decodes a TXT record into its `KEY=VALUE` strings, for comparison with the specification's
/// printed listings.
fn txt_strings(bytes: &[u8]) -> Vec<String> {
    TxtReader::new(bytes)
        .map(|(key, value)| {
            let mut out = String::from_utf8(key.to_vec()).expect("ascii key");
            if !value.is_empty() {
                out.push('=');
                out.push_str(core::str::from_utf8(value).expect("utf-8 value"));
            }
            out
        })
        .collect()
}

#[test]
fn the_first_worked_examples_txt_record_is_d_840_cm_2() {
    // §4.3.1.14: `DD200C20D25AE5F7._matterc._udp.local. TXT "D=840" "CM=2"`.
    let txt = CommissionableTxt {
        discriminator: 840,
        commissioning_mode: CommissioningMode::Enhanced,
        ..CommissionableTxt::default()
    }
    .encode()
    .expect("encode");
    assert_eq!(txt_strings(txt.finish()), vec!["D=840", "CM=2"]);
}

#[test]
fn the_second_worked_examples_txt_record_matches_line_for_line() {
    // §4.3.1.14: `TXT "D=840" "VP=123+456" "CM=1" "DT=81" "DN=Kitchen Plug" "PH=256" "PI=5"`.
    //
    // The printed listing says CM=1 while the command above it says CM=2 and the prose says
    // "Commissioning Mode is 2" — an inconsistency in the specification's own example. The
    // prose and the command agree with each other, so they are what this follows; the value
    // is the parameter here either way.
    let txt = CommissionableTxt {
        discriminator: 840,
        vendor_id: Some(VendorId(123)),
        product_id: Some(456),
        commissioning_mode: CommissioningMode::Enhanced,
        device_type: Some(81),
        device_name: Some("Kitchen Plug"),
        pairing_hint: Some(256),
        pairing_instruction: Some("5"),
        ..CommissionableTxt::default()
    }
    .encode()
    .expect("encode");
    assert_eq!(
        txt_strings(txt.finish()),
        vec![
            "D=840",
            "VP=123+456",
            "CM=2",
            "DT=81",
            "DN=Kitchen Plug",
            "PH=256",
            "PI=5",
        ]
    );
}

#[test]
fn a_vendor_id_without_a_product_id_has_no_plus() {
    // §4.3.1.6: "If the VP key is present without a Product ID, the value SHALL contain only
    // the Vendor ID alone, with no '+' character."
    let txt = CommissionableTxt {
        discriminator: 1,
        vendor_id: Some(VendorId(123)),
        ..CommissionableTxt::default()
    }
    .encode()
    .expect("encode");
    assert_eq!(txt_strings(txt.finish()), vec!["D=1", "VP=123", "CM=0"]);

    // "If the VP key is present, the value SHALL contain at least the Vendor ID" — so a
    // Product ID with no Vendor ID has no encoding at all, and is a caller error rather than
    // something to silently drop.
    assert!(
        CommissionableTxt {
            discriminator: 1,
            product_id: Some(456),
            ..CommissionableTxt::default()
        }
        .encode()
        .is_err()
    );
}

#[test]
fn the_commissioning_mode_values_match_section_4_3_1_7() {
    assert_eq!(CommissioningMode::None.value(), 0);
    assert_eq!(CommissioningMode::Basic.value(), 1);
    assert_eq!(CommissioningMode::Enhanced.value(), 2);
    assert_eq!(CommissioningMode::JointFabric.value(), 3);
    // "The absence of key CM SHALL imply a value of 0 (CM=0)."
    assert_eq!(CommissioningMode::default(), CommissioningMode::None);
    assert_eq!(CommissioningMode::from_value(7), CommissioningMode::None);

    // §4.3.1.3: the `_CM` subtype is published for 1, 2 and 3, and never for 0.
    assert!(!CommissioningMode::None.publishes_subtype());
    for mode in [
        CommissioningMode::Basic,
        CommissioningMode::Enhanced,
        CommissioningMode::JointFabric,
    ] {
        assert!(mode.publishes_subtype(), "{mode:?}");
    }
}

#[test]
fn the_rotating_device_identifier_is_uppercase_hex() {
    // §4.3.1.10: "the concatenation of each octet's value as a 2-digit uppercase hexadecimal
    // number", and "SHALL NOT be longer than 100 characters, which implies a Rotating Device
    // Identifier of at most 50 octets".
    let txt = CommissionableTxt {
        discriminator: 1,
        rotating_id: Some(&[0x0A, 0xFF, 0x00]),
        ..CommissionableTxt::default()
    }
    .encode()
    .expect("encode");
    assert_eq!(txt_strings(txt.finish()), vec!["D=1", "CM=0", "RI=0AFF00"]);

    assert!(
        CommissionableTxt {
            discriminator: 1,
            rotating_id: Some(&[0u8; 50]),
            ..CommissionableTxt::default()
        }
        .encode()
        .is_ok()
    );
    assert!(
        CommissionableTxt {
            discriminator: 1,
            rotating_id: Some(&[0u8; 51]),
            ..CommissionableTxt::default()
        }
        .encode()
        .is_err()
    );
}

#[test]
fn the_common_mrp_keys_carry_their_caps() {
    // §4.3.4: SII and SAI "SHALL NOT exceed 3600000 (1 hour in milliseconds)"; SAT "SHALL NOT
    // exceed 65535", which the `u16` itself enforces.
    let txt = OperationalTxt {
        mrp: MrpAdvertisement {
            idle_interval_ms: Some(5300),
            active_interval_ms: Some(1250),
            active_threshold_ms: Some(1250),
        },
        ..OperationalTxt::default()
    }
    .encode()
    .expect("encode");
    // §4.3.4's own examples: "SII=5300", "SAI=1250", "SAT=1250".
    assert_eq!(
        txt_strings(txt.finish()),
        vec!["SII=5300", "SAI=1250", "SAT=1250"]
    );

    assert!(
        OperationalTxt {
            mrp: MrpAdvertisement {
                idle_interval_ms: Some(3_600_001),
                ..MrpAdvertisement::default()
            },
            ..OperationalTxt::default()
        }
        .encode()
        .is_err()
    );
}

#[test]
fn an_operational_node_with_nothing_to_say_still_emits_a_legal_txt() {
    // §4.3.2.6: "The TXT record MAY be omitted if no keys are defined." But a DNS TXT record
    // with zero-length RDATA is not legal — RFC 6763 §6.1 requires "a single zero-length
    // string" — so what goes on the wire is one empty string, not nothing.
    let txt = OperationalTxt::default().encode().expect("encode");
    assert!(txt.is_empty());
    assert_eq!(txt.finish(), &[0u8]);
    assert_eq!(txt_strings(txt.finish()), Vec::<String>::new());
}

#[test]
fn the_transport_and_icd_keys_are_operational_only() {
    // §4.3.4's Table 7: bit 0 "is deprecated and SHALL be set to 0 by the advertising node".
    // There is no flag for it, so it cannot be set by accident.
    assert_eq!(TransportModes::TCP_CLIENT.bits(), 1 << 1);
    assert_eq!(TransportModes::TCP_SERVER.bits(), 1 << 2);
    let txt = OperationalTxt {
        transports: TransportModes::TCP_CLIENT | TransportModes::TCP_SERVER,
        long_idle_time_icd: Some(true),
        ..OperationalTxt::default()
    }
    .encode()
    .expect("encode");
    // "a Node advertising with key T=6 represents both a TCP client and a TCP server".
    assert_eq!(txt_strings(txt.finish()), vec!["T=6", "ICD=1"]);

    // `None` is not `Some(false)`: "The key SHALL NOT be provided by a Node that does not
    // support the ICD Long Idle Time operating mode."
    let txt = OperationalTxt {
        long_idle_time_icd: Some(false),
        ..OperationalTxt::default()
    }
    .encode()
    .expect("encode");
    assert_eq!(txt_strings(txt.finish()), vec!["ICD=0"]);
}

#[test]
fn the_joint_fabric_key_refuses_the_combination_note_1_forbids() {
    // §4.3.1.13 Note 1: "bit 0 (Available) SHALL be unset for any of bits 1, 2 or 3 to be set."
    assert!(JointFabric::AVAILABLE.is_valid());
    assert!((JointFabric::ADMINISTRATOR | JointFabric::ANCHOR).is_valid());
    assert!(!(JointFabric::AVAILABLE | JointFabric::ADMINISTRATOR).is_valid());
    assert!(
        CommissionableTxt {
            discriminator: 1,
            joint_fabric: Some(JointFabric::AVAILABLE | JointFabric::DATASTORE),
            ..CommissionableTxt::default()
        }
        .encode()
        .is_err()
    );
}

#[test]
fn a_malformed_decimal_value_is_silently_ignored_not_partially_parsed() {
    // §4.3.1.5: "Any key D with a value mismatching the aforementioned format SHALL be
    // silently ignored." `840x` is not 840 — a partial parse would accept a discriminator a
    // conforming publisher never sent.
    assert_eq!(parse_decimal(b"840"), Some(840));
    assert_eq!(parse_decimal(b"0"), Some(0));
    assert_eq!(parse_decimal(b"840x"), None);
    assert_eq!(parse_decimal(b""), None);
    assert_eq!(parse_decimal(b"-1"), None);
    assert_eq!(parse_decimal(b" 840"), None);
    // Ten digits is u32's width; eleven cannot be one.
    assert_eq!(parse_decimal(b"4294967295"), Some(u32::MAX));
    assert_eq!(parse_decimal(b"4294967296"), None);
    assert_eq!(parse_decimal(b"99999999999"), None);
}

#[test]
fn an_unrecognised_key_survives_a_round_trip() {
    // "Commissioners SHALL silently ignore TXT record keys that they do not recognize. This is
    // to facilitate future evolution of this specification" — so a reader hands back
    // everything and refuses nothing.
    let mut w = TxtWriter::new();
    w.push("D", "840").expect("push");
    w.push("ZZ", "from the future").expect("push");
    w.push("FLAG", "").expect("push");
    let reader = TxtReader::new(w.finish());
    assert_eq!(reader.get("D"), Some(&b"840"[..]));
    assert_eq!(reader.get("ZZ"), Some(&b"from the future"[..]));
    assert_eq!(reader.decimal("D"), Some(840));
    assert_eq!(reader.decimal("ZZ"), None);
    // DNS keys are case-insensitive in practice, and a querier may normalise them.
    assert_eq!(reader.get("d"), Some(&b"840"[..]));
}

// --- The DNS wire format ------------------------------------------------------------------------

#[test]
fn a_name_round_trips_through_the_wire_format() {
    let mut buf = [0u8; 256];
    let labels = ["DD200C20D25AE5F7", "_matterc", "_udp", "local"];
    let mut w = DnsWriter::new(&mut buf).expect("writer");
    w.question(&labels, RecordType::Ptr, false)
        .expect("question");
    let bytes = w.finish(0x1234, FLAGS_QUERY).expect("finish").to_vec();

    let questions = Questions::decode(&bytes).expect("decode");
    assert_eq!(questions.id(), 0x1234);
    assert!(!questions.is_response());
    let question = questions.into_iter().next().expect("one").expect("decode");
    assert!(question.matches_labels(&labels));
    assert_eq!(question.kind, RecordType::Ptr);
    assert!(!question.unicast);
}

/// `Question` has no helper for this; the test wants one.
trait MatchesLabels {
    fn matches_labels(&self, labels: &[&str]) -> bool;
}

impl MatchesLabels for matter_kit::discovery::dns::Question {
    fn matches_labels(&self, labels: &[&str]) -> bool {
        let owned: Vec<&[u8]> = labels.iter().map(|l| l.as_bytes()).collect();
        self.name.matches(&owned)
    }
}

#[test]
fn names_compare_case_insensitively() {
    // RFC 1035 §2.3.3 and RFC 6762 §16. A responder that compared bytes would miss a query for
    // `_MATTERC._UDP.local.`, which a conforming querier is entitled to send.
    let lower = Name::from_strs(&["_matterc", "_udp", "local"]).expect("name");
    let upper = Name::from_strs(&["_MATTERC", "_UDP", "LOCAL"]).expect("name");
    assert!(lower.eq_ignore_case(&upper));
    assert!(lower.matches(&[b"_MATTERC", b"_UDP", b"local"]));
    assert!(!lower.matches(&[b"_matterc", b"_udp"]));
}

#[test]
fn the_unicast_response_bit_is_read_off_the_question_class() {
    // RFC 6762 §5.4's bit, the top one of the question's class.
    let mut buf = [0u8; 256];
    let labels = ["_matterc", "_udp", "local"];
    let mut w = DnsWriter::new(&mut buf).expect("writer");
    w.question(&labels, RecordType::Ptr, true)
        .expect("question");
    let bytes = w.finish(0, FLAGS_QUERY).expect("finish").to_vec();
    let question = Questions::decode(&bytes)
        .expect("decode")
        .next()
        .expect("one")
        .expect("decode");
    assert!(question.unicast);
    assert_eq!(
        question.kind,
        RecordType::Ptr,
        "the bit is not part of the class"
    );
    assert_eq!(UNICAST_RESPONSE, 0x8000);
    assert_eq!(CACHE_FLUSH, 0x8000);
    assert_eq!(CLASS_IN, 1);
}

#[test]
fn compression_shortens_a_response_and_it_still_decodes() {
    // RFC 1035 §4.1.4. Two records ending in `_matterc._udp.local.` — the difference between
    // fitting one datagram and not. What matters more than the saving is that the *decoded*
    // names are unchanged, which is the property a broken compressor quietly loses: the first
    // version of this writer re-emitted the labels it had already written, producing a name
    // with every label doubled that still parsed as a name.
    let service = ["_matterc", "_udp", "local"];
    let instance = ["DD200C20D25AE5F7", "_matterc", "_udp", "local"];
    let host = ["B75AFB458ECD", "local"];

    let mut buf = [0u8; 512];
    let mut w = DnsWriter::new(&mut buf).expect("writer");
    w.answer(&Record {
        name: &service,
        kind: RecordType::Ptr,
        ttl: 4500,
        cache_flush: false,
        data: RecordData::Ptr(&instance),
    })
    .expect("ptr");
    w.answer(&Record {
        name: &instance,
        kind: RecordType::Srv,
        ttl: 120,
        cache_flush: true,
        data: RecordData::Srv {
            port: 11111,
            target: &host,
        },
    })
    .expect("srv");
    let bytes = w.finish(0, FLAGS_RESPONSE).expect("finish").to_vec();

    // Uncompressed, these two records need 155 octets: 12 header, 69 for the PTR and 74 for
    // the SRV. Compression turns three repeated suffixes into three two-octet pointers.
    assert_eq!(bytes.len(), 95, "the exact compressed layout");

    let records: Vec<_> = ResourceRecords::decode(&bytes)
        .expect("decode")
        .map(|r| r.expect("each record"))
        .collect();
    assert_eq!(records.len(), 2);

    assert!(records[0].name.matches(&[b"_matterc", b"_udp", b"local"]));
    assert_eq!(records[0].ttl, 4500);
    assert!(
        !records[0].cache_flush,
        "a shared PTR must not flush caches"
    );
    let ReadData::Ptr(target) = records[0].data.as_ref().expect("ptr data") else {
        panic!("expected a PTR");
    };
    assert!(target.matches(&[b"DD200C20D25AE5F7", b"_matterc", b"_udp", b"local"]));

    assert!(
        records[1]
            .name
            .matches(&[b"DD200C20D25AE5F7", b"_matterc", b"_udp", b"local"])
    );
    assert!(records[1].cache_flush, "an SRV is uniquely owned");
    let ReadData::Srv { port, target } = records[1].data.as_ref().expect("srv data") else {
        panic!("expected an SRV");
    };
    assert_eq!(*port, 11111);
    assert!(target.matches(&[b"B75AFB458ECD", b"local"]));
}

#[test]
fn a_compression_pointer_must_go_strictly_backwards() {
    // The classic decompression loop. A pointer that points at itself, or forwards, is what
    // makes one possible — so a name that contains either is refused rather than merely
    // bounded.
    //
    // A hand-built message: header, then a name at offset 12 that points at offset 12.
    let mut message = vec![0u8; HEADER_LEN];
    message[4] = 0; // QDCOUNT high
    message[5] = 1; // QDCOUNT low
    message.extend_from_slice(&[0xC0, 12]); // pointer to itself
    message.extend_from_slice(&[0, 12, 0, 1]); // type PTR, class IN
    let result = Questions::decode(&message)
        .expect("header")
        .next()
        .expect("one");
    assert!(result.is_err(), "a self-pointer must not decode");

    // Forwards is equally refused — and this case is the one that shows why the rule is
    // about *direction* rather than about looping. The pointer here targets a perfectly good
    // name later in the message, so a decoder that only bounded its work would accept it and
    // hand back `test.` RFC 1035 §4.1.4 admits a pointer only to "a prior occurrence".
    let mut message = vec![0u8; HEADER_LEN];
    message[5] = 1;
    message.extend_from_slice(&[0xC0, 20]); // offsets 12..14: forward pointer to 20
    message.extend_from_slice(&[0, 12, 0, 1]); // 14..18: type PTR, class IN
    message.extend_from_slice(&[0, 0]); // 18..20: padding
    message.extend_from_slice(&[4, b't', b'e', b's', b't', 0]); // 20..: a real name
    let result = Questions::decode(&message)
        .expect("header")
        .next()
        .expect("one");
    assert!(
        result.is_err(),
        "a forward pointer must not decode, even to a name that is really there"
    );
}

#[test]
fn a_reserved_label_type_and_a_truncated_name_are_both_refused() {
    // RFC 1035 §4.1.4 defines two of the four two-bit label types; the other two are reserved.
    let mut message = vec![0u8; HEADER_LEN];
    message[5] = 1;
    message.extend_from_slice(&[0x80, 0x00]); // reserved type 0b10
    assert!(
        Questions::decode(&message)
            .expect("header")
            .next()
            .expect("one")
            .is_err()
    );

    // A label that claims more octets than the message holds.
    let mut message = vec![0u8; HEADER_LEN];
    message[5] = 1;
    message.extend_from_slice(&[40, b'a', b'b']);
    assert!(
        Questions::decode(&message)
            .expect("header")
            .next()
            .expect("one")
            .is_err()
    );

    // A header that is not even a header.
    assert!(Questions::decode(&[0u8; 4]).is_err());
}

#[test]
fn arbitrary_bytes_never_panic_and_never_loop() {
    // The two failure modes a compression pointer makes possible, swept exhaustively over the
    // shapes that produce them.
    for a in 0u8..=255 {
        for b in [0u8, 1, 11, 12, 13, 0xC0, 0xFF] {
            let mut message = vec![0u8; HEADER_LEN];
            message[5] = 1;
            message.extend_from_slice(&[a, b, a, b, 0, 12, 0, 1]);
            if let Ok(questions) = Questions::decode(&message) {
                for question in questions {
                    let _ = question;
                }
            }
        }
    }
}

// --- The responder ------------------------------------------------------------------------------

/// §4.3.1.14's first example, as an advertisement.
///
/// ```text
/// dns-sd -R DD200C20D25AE5F7 _matterc._udp,_S3,_L840,_CM . 11111 D=840 CM=2
/// ```
fn worked_example_txt() -> TxtWriter {
    CommissionableTxt {
        discriminator: 840,
        commissioning_mode: CommissioningMode::Enhanced,
        ..CommissionableTxt::default()
    }
    .encode()
    .expect("encode")
}

const LINK_LOCAL: [u8; 16] = [
    0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0xF5, 0x15, 0x57, 0x6F, 0x97, 0x83, 0x3F, 0x30,
];

fn worked_example<'a>(txt: &'a [u8]) -> Advertisement<'a> {
    Advertisement::new(
        "DD200C20D25AE5F7",
        COMMISSIONABLE_SERVICE,
        "B75AFB458ECD",
        11111,
        txt,
    )
    .with_subtype("_S3")
    .expect("subtype")
    .with_subtype("_L840")
    .expect("subtype")
    .with_subtype(COMMISSIONING_MODE_SUBTYPE)
    .expect("subtype")
    .with_address(LINK_LOCAL)
    .expect("address")
}

/// A record as `(owner labels, type, ttl)` plus a rendering of its data, for comparison with
/// the specification's printed listing.
fn describe(record: &matter_kit::discovery::ReadRecord<'_>) -> (String, String) {
    let owner = record
        .name
        .labels()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect::<Vec<_>>()
        .join(".");
    let data = match record.data.as_ref() {
        Some(ReadData::Ptr(target)) => format!(
            "PTR {}",
            target
                .labels()
                .map(|l| String::from_utf8_lossy(l).into_owned())
                .collect::<Vec<_>>()
                .join(".")
        ),
        Some(ReadData::Srv { port, target }) => format!(
            "SRV 0 0 {port} {}",
            target
                .labels()
                .map(|l| String::from_utf8_lossy(l).into_owned())
                .collect::<Vec<_>>()
                .join(".")
        ),
        Some(ReadData::Txt(bytes)) => format!("TXT {}", txt_strings(bytes).join(" ")),
        Some(ReadData::Aaaa(address)) => {
            let groups: Vec<String> = address
                .chunks(2)
                .map(|pair| format!("{:04x}", u16::from_be_bytes([pair[0], pair[1]])))
                .collect();
            format!("AAAA {}", groups.join(":"))
        }
        Some(ReadData::A(_)) | None => "?".to_owned(),
    };
    (owner, data)
}

#[test]
fn an_announcement_is_exactly_section_4_3_1_14s_record_listing() {
    // The specification prints these seven records, in this order:
    //
    //   _matterc._udp.local.                   PTR   DD200C20D25AE5F7._matterc._udp.local.
    //   _S3._sub._matterc._udp.local.          PTR   DD200C20D25AE5F7._matterc._udp.local.
    //   _L840._sub._matterc._udp.local.        PTR   DD200C20D25AE5F7._matterc._udp.local.
    //   _CM._sub._matterc._udp.local.          PTR   DD200C20D25AE5F7._matterc._udp.local.
    //   DD200C20D25AE5F7._matterc._udp.local.  SRV   0 0 11111 B75AFB458ECD.local.
    //   DD200C20D25AE5F7._matterc._udp.local.  TXT   "D=840" "CM=2"
    //   B75AFB458ECD.local.                    AAAA  fe80::f515:576f:9783:3f30
    let txt = worked_example_txt();
    let advertisement = worked_example(txt.finish());
    let advertisements = [advertisement];
    let responder = Responder::new(&advertisements);

    let mut buf = [0u8; 1024];
    let bytes = responder.announce(&mut buf).expect("announce").to_vec();

    let described: Vec<(String, String)> = ResourceRecords::decode(&bytes)
        .expect("decode")
        .map(|r| describe(&r.expect("record")))
        .collect();

    assert_eq!(
        described,
        vec![
            (
                "_matterc._udp.local".to_owned(),
                "PTR DD200C20D25AE5F7._matterc._udp.local".to_owned()
            ),
            (
                "_S3._sub._matterc._udp.local".to_owned(),
                "PTR DD200C20D25AE5F7._matterc._udp.local".to_owned()
            ),
            (
                "_L840._sub._matterc._udp.local".to_owned(),
                "PTR DD200C20D25AE5F7._matterc._udp.local".to_owned()
            ),
            (
                "_CM._sub._matterc._udp.local".to_owned(),
                "PTR DD200C20D25AE5F7._matterc._udp.local".to_owned()
            ),
            (
                "DD200C20D25AE5F7._matterc._udp.local".to_owned(),
                "SRV 0 0 11111 B75AFB458ECD.local".to_owned()
            ),
            (
                "DD200C20D25AE5F7._matterc._udp.local".to_owned(),
                "TXT D=840 CM=2".to_owned()
            ),
            (
                "B75AFB458ECD.local".to_owned(),
                "AAAA fe80:0000:0000:0000:f515:576f:9783:3f30".to_owned()
            ),
        ]
    );
}

/// Builds a query for one name and type.
fn query(labels: &[&str], kind: RecordType, buf: &mut [u8]) -> Vec<u8> {
    let mut w = DnsWriter::new(buf).expect("writer");
    w.question(labels, kind, false).expect("question");
    w.finish(0x00AB, FLAGS_QUERY).expect("finish").to_vec()
}

#[test]
fn a_browse_for_the_service_is_answered_with_the_ptr_and_everything_after_it() {
    // RFC 6762 §6.2: a responder "SHOULD include in the Additional Section" what the querier
    // will ask for next. Answering a PTR with only the PTR turns one discovery into three
    // round trips — which on a Thread mesh, where "excessive use of multicast would be
    // detrimental", is the difference that matters.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);

    let mut qbuf = [0u8; 256];
    let q = query(&["_matterc", "_udp", "local"], RecordType::Ptr, &mut qbuf);

    let mut buf = [0u8; 1024];
    let (bytes, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert_eq!(answered.answers, 1, "one PTR");
    assert_eq!(answered.additional, 3, "the SRV, the TXT and the address");
    assert!(!answered.is_empty());
    assert!(!answered.unicast);

    let kinds: Vec<_> = ResourceRecords::decode(bytes)
        .expect("decode")
        .map(|r| r.expect("record").kind.expect("known type"))
        .collect();
    assert_eq!(
        kinds,
        vec![
            RecordType::Ptr,
            RecordType::Srv,
            RecordType::Txt,
            RecordType::Aaaa
        ]
    );
}

#[test]
fn a_browse_for_a_subtype_finds_only_that_subtype() {
    // §4.3.1.3: "The long discriminator subtype (e.g., _L840) enables filtering of results to
    // find only Commissionees that match the full discriminator code."
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let mut qbuf = [0u8; 256];

    for (labels, expected) in [
        (["_L840", "_sub", "_matterc", "_udp", "local"], 1),
        (["_S3", "_sub", "_matterc", "_udp", "local"], 1),
        (["_CM", "_sub", "_matterc", "_udp", "local"], 1),
        // A discriminator this device does not have.
        (["_L841", "_sub", "_matterc", "_udp", "local"], 0),
        // The operational service, which this advertisement is not.
        (["_I0000", "_sub", "_matter", "_tcp", "local"], 0),
    ] {
        let q = query(&labels, RecordType::Ptr, &mut qbuf);
        let (_, answered) = responder.respond(&q, &mut buf).expect("respond");
        assert_eq!(answered.answers, expected, "{labels:?}");
    }
}

#[test]
fn a_responder_matches_a_query_whose_labels_are_uppercase() {
    // RFC 1035 §2.3.3 and RFC 6762 §16: DNS is case-insensitive, and a conforming querier may
    // send `_MATTERC._UDP.local.` A responder that compared bytes would simply never be found
    // by one that does.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let mut qbuf = [0u8; 256];

    let q = query(&["_MATTERC", "_UDP", "LOCAL"], RecordType::Ptr, &mut qbuf);
    let (_, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert_eq!(answered.answers, 1, "an uppercase browse must still match");

    // The instance name too, which is hexadecimal and therefore has a natural lowercase form.
    let q = query(
        &["dd200c20d25ae5f7", "_matterc", "_udp", "local"],
        RecordType::Any,
        &mut qbuf,
    );
    let (_, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert_eq!(answered.answers, 2);
}

#[test]
fn a_query_that_matches_nothing_produces_a_response_that_must_not_be_sent() {
    // RFC 6762 §6: "if the responder has no records that answer the question, it MUST NOT send
    // any response." A caller that ignored `is_empty` would put a header on the link for
    // nothing, once per query, from every device that heard it.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let mut qbuf = [0u8; 256];

    let q = query(&["_printer", "_tcp", "local"], RecordType::Ptr, &mut qbuf);
    let (_, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert!(answered.is_empty());
    assert_eq!(answered.additional, 0);
}

#[test]
fn a_responder_never_answers_a_response() {
    // Two responders that answered each other's responses would keep a link busy forever.
    // The case that matters is a message with the QR bit set that *also* carries a question —
    // an announcement has no questions, so ignoring it proves nothing.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let mut qbuf = [0u8; 256];

    let q = query(&["_matterc", "_udp", "local"], RecordType::Ptr, &mut qbuf);
    // The same message, with QR flipped on: byte 2, bit 7.
    let mut as_response = q.clone();
    as_response[2] |= 0x80;

    let (_, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert_eq!(answered.answers, 1, "the query is answered");

    let (_, answered) = responder.respond(&as_response, &mut buf).expect("respond");
    assert!(
        answered.is_empty(),
        "the same message with QR set must be ignored"
    );

    // An announcement — QR set, no questions — is equally ignored.
    let announcement = {
        let mut abuf = [0u8; 1024];
        responder.announce(&mut abuf).expect("announce").to_vec()
    };
    let (_, answered) = responder.respond(&announcement, &mut buf).expect("respond");
    assert!(answered.is_empty());
}

#[test]
fn an_any_query_on_the_instance_returns_the_srv_and_the_txt() {
    // RFC 6762 §6 makes `ANY` the ordinary way to ask for everything about a name.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let mut qbuf = [0u8; 256];

    let q = query(
        &["DD200C20D25AE5F7", "_matterc", "_udp", "local"],
        RecordType::Any,
        &mut qbuf,
    );
    let (bytes, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert_eq!(answered.answers, 2, "the SRV and the TXT");
    assert_eq!(answered.additional, 1, "and the address");
    let kinds: Vec<_> = ResourceRecords::decode(bytes)
        .expect("decode")
        .map(|r| r.expect("record").kind.expect("known"))
        .collect();
    assert_eq!(
        kinds,
        vec![RecordType::Srv, RecordType::Txt, RecordType::Aaaa]
    );
}

#[test]
fn the_unicast_bit_is_reported_back_to_the_caller() {
    // RFC 6762 §5.4. A responder that honours it sends one datagram to the asker rather than
    // to the whole link — which is the whole point of the bit.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let mut qbuf = [0u8; 256];

    let mut w = DnsWriter::new(&mut qbuf).expect("writer");
    w.question(&["_matterc", "_udp", "local"], RecordType::Ptr, true)
        .expect("question");
    let q = w.finish(0, FLAGS_QUERY).expect("finish").to_vec();

    let (_, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert!(answered.unicast);
    assert_eq!(answered.answers, 1);
}

#[test]
fn a_goodbye_sets_every_ttl_to_zero() {
    // RFC 6762 §10.1, and §4.3.2.5's "SHALL withdraw it (using SRP update or DNS-SD with
    // TTL=0)". A device that simply stopped answering would stay in every cache on the link
    // for seventy-five minutes.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let bytes = responder.goodbye(&mut buf).expect("goodbye").to_vec();

    let ttls: Vec<u32> = ResourceRecords::decode(&bytes)
        .expect("decode")
        .map(|r| r.expect("record").ttl)
        .collect();
    assert_eq!(ttls.len(), 7);
    assert!(ttls.iter().all(|ttl| *ttl == 0));
}

#[test]
fn the_cache_flush_bit_is_set_on_owned_records_and_clear_on_shared_ones() {
    // RFC 6762 §10.2. Setting it on a shared PTR would tell every receiver to forget every
    // other Matter device on the link — a way to make a home's worth of commissionable nodes
    // disappear by advertising on it.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let bytes = responder.announce(&mut buf).expect("announce").to_vec();

    for record in ResourceRecords::decode(&bytes).expect("decode") {
        let record = record.expect("record");
        let expected = !matches!(record.kind, Some(RecordType::Ptr));
        assert_eq!(
            record.cache_flush,
            expected,
            "{:?} {:?}",
            record.kind,
            describe(&record).0
        );
    }
}

#[test]
fn an_operational_advertisement_carries_its_compressed_fabric_subtype() {
    // §4.3.2.1's own example: compressed fabric 2906C908D115D362, node 8FC7772401CD0696, so
    // the instance name is `2906C908D115D362-8FC7772401CD0696` and the subtype is
    // `_I2906C908D115D362` — "exactly 16 uppercase hexadecimal characters", not decimal.
    let txt = OperationalTxt::default().encode().expect("encode");
    let advertisements = [Advertisement::new(
        "2906C908D115D362-8FC7772401CD0696",
        OPERATIONAL_SERVICE,
        "B75AFB458ECD",
        5540,
        txt.finish(),
    )
    .with_subtype("_I2906C908D115D362")
    .expect("subtype")
    .with_address(LINK_LOCAL)
    .expect("address")];
    let responder = Responder::new(&advertisements);

    let mut buf = [0u8; 1024];
    let bytes = responder.announce(&mut buf).expect("announce").to_vec();
    let described: Vec<(String, String)> = ResourceRecords::decode(&bytes)
        .expect("decode")
        .map(|r| describe(&r.expect("record")))
        .collect();
    assert_eq!(described[0].0, "_matter._tcp.local");
    assert_eq!(
        described[0].1,
        "PTR 2906C908D115D362-8FC7772401CD0696._matter._tcp.local"
    );
    assert_eq!(described[1].0, "_I2906C908D115D362._sub._matter._tcp.local");
    assert!(described[3].1.starts_with("TXT"), "{:?}", described[3]);
}

#[test]
fn one_responder_serves_several_advertisements() {
    // A device is commissionable *and* operational on several fabrics at once, and every
    // instance shares the host name and the addresses — which is exactly the case compression
    // pays for.
    let commissionable_txt = worked_example_txt();
    let operational_txt = OperationalTxt::default().encode().expect("encode");
    let advertisements = [
        worked_example(commissionable_txt.finish()),
        Advertisement::new(
            "2906C908D115D362-8FC7772401CD0696",
            OPERATIONAL_SERVICE,
            "B75AFB458ECD",
            5540,
            operational_txt.finish(),
        )
        .with_address(LINK_LOCAL)
        .expect("address"),
    ];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 2048];
    let mut qbuf = [0u8; 256];

    // A browse for the operational service finds only the operational instance.
    let q = query(&["_matter", "_tcp", "local"], RecordType::Ptr, &mut qbuf);
    let (bytes, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert_eq!(answered.answers, 1);
    let first = ResourceRecords::decode(bytes)
        .expect("decode")
        .next()
        .expect("one")
        .expect("record");
    let ReadData::Ptr(target) = first.data.as_ref().expect("ptr") else {
        panic!("expected a PTR");
    };
    assert!(target.matches(&[
        b"2906C908D115D362-8FC7772401CD0696",
        b"_matter",
        b"_tcp",
        b"local"
    ]));

    // A query for the shared host name is answered once per advertisement that owns it — the
    // address is the same, so a querier sees it twice rather than not at all.
    let q = query(&["B75AFB458ECD", "local"], RecordType::Aaaa, &mut qbuf);
    let (_, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert_eq!(answered.answers, 2);
}

#[test]
fn a_response_that_does_not_fit_is_an_error_not_a_truncation() {
    // Half a record is worse than none: a querier that decoded it would cache a name with no
    // data behind it. So a writer that runs out refuses, and the caller decides what to drop.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut tiny = [0u8; 40];
    assert!(responder.announce(&mut tiny).is_err());
    // …and a buffer too small even for a header.
    let mut nothing = [0u8; 4];
    assert!(responder.announce(&mut nothing).is_err());
}

#[test]
fn the_subtype_set_follows_section_4_3_1_3s_rules() {
    use matter_kit::discovery::CommissionableSubtypes;

    // §4.3.1.14's second example publishes _S3, _L840, _V123, _CM and _T81.
    let subtypes = CommissionableSubtypes::new(840, CommissioningMode::Enhanced)
        .with_vendor(VendorId(123))
        .with_device_type(81);
    assert_eq!(
        subtypes.labels().collect::<Vec<_>>(),
        vec!["_S3", "_L840", "_V123", "_CM", "_T81"]
    );

    // §4.3.1.3: "A Commissionee that is not in commissioning mode (CM=0) SHALL NOT publish
    // this subtype." Nothing else in the stack couples the subtype to the TXT key, so a
    // device assembling them separately could advertise `_CM` beside `CM=0` — which is
    // exactly the state a commissioner filters on `_CM` to avoid.
    let quiet = CommissionableSubtypes::new(840, CommissioningMode::None);
    assert_eq!(quiet.labels().collect::<Vec<_>>(), vec!["_S3", "_L840"]);

    // …and it is published for all three commissioning modes, not only for 2.
    for mode in [
        CommissioningMode::Basic,
        CommissioningMode::Enhanced,
        CommissioningMode::JointFabric,
    ] {
        let subtypes = CommissionableSubtypes::new(840, mode);
        assert!(
            subtypes.labels().any(|label| label == "_CM"),
            "{mode:?} must publish _CM"
        );
    }

    // The two optional ones are absent unless asked for: "A vendor MAY choose not to include
    // it at all, for privacy reasons."
    let minimal = CommissionableSubtypes::new(840, CommissioningMode::Basic);
    assert_eq!(
        minimal.labels().collect::<Vec<_>>(),
        vec!["_S3", "_L840", "_CM"]
    );
}

#[test]
fn the_operational_subtype_is_fixed_width_hexadecimal() {
    // §4.3.2.3: "_I<hhhh>, where <hhhh> is the Compressed Fabric Identifier encoded as exactly
    // 16 uppercase hexadecimal characters, for example _I87E1B004E235A130". Not decimal, and
    // not variable-width — which is the opposite of every commissionable subtype, and the
    // mistake that makes a node unfindable on its own fabric.
    use matter_kit::fabric::CompressedFabricId;

    let subtype =
        matter_kit::discovery::compressed_fabric_subtype(CompressedFabricId(0x87E1_B004_E235_A130));
    assert_eq!(subtype.as_str(), "_I87E1B004E235A130");
    assert_eq!(subtype.len(), 18);

    // Leading zeroes are kept, unlike `_L0` or `_V0`.
    let subtype =
        matter_kit::discovery::compressed_fabric_subtype(CompressedFabricId(0x0000_0000_0000_0001));
    assert_eq!(subtype.as_str(), "_I0000000000000001");
}

// --- RFC 6762 §8: probing, announcing, conflict resolution ---------------------------------------

#[test]
fn a_probe_query_asks_only_for_the_names_it_wants_to_own() {
    // RFC 6762 §8.1: a responder probes "for all those resource records that [it] desires to
    // be unique on the local link". The service PTR is *not* one of them — every
    // commissionable node on the link owns `_matterc._udp.local.`, so probing for it would
    // find a conflict the moment there are two Matter devices in the house.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let bytes = responder.probe(&mut buf).expect("probe").to_vec();

    let questions = Questions::decode(&bytes).expect("decode");
    assert!(!questions.is_response(), "a probe is a query");
    let names: Vec<Vec<String>> = questions
        .clone()
        .map(|q| {
            let q = q.expect("question");
            // §8.1: "query type 'ANY' (255) … to elicit answers for all types of records with
            // that name", and "the probes SHOULD be sent as 'QU' questions".
            assert_eq!(q.kind, RecordType::Any);
            assert!(q.unicast, "§8.1: probes are QU questions");
            q.name
                .labels()
                .map(|l| String::from_utf8(l.to_vec()).unwrap())
                .collect()
        })
        .collect();

    assert_eq!(
        names,
        vec![
            vec!["DD200C20D25AE5F7", "_matterc", "_udp", "local"],
            vec!["B75AFB458ECD", "local"],
        ]
    );
}

#[test]
fn a_probe_carries_every_proposed_record_in_the_authority_section() {
    // RFC 6762 §8.2: "for tiebreaking to work correctly in all cases, the Authority Section
    // must contain *all* the records and proposed rdata being probed for uniqueness." A probe
    // with an empty Authority section still claims the name, but two devices probing at the
    // same instant would both conclude they won.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let bytes = responder.probe(&mut buf).expect("probe").to_vec();

    let authority: Vec<RecordType> = ResourceRecords::decode(&bytes)
        .expect("decode")
        .section(Section::Authority)
        .map(|r| r.expect("record").kind.expect("known type"))
        .collect();
    assert_eq!(
        authority,
        vec![RecordType::Srv, RecordType::Txt, RecordType::Aaaa]
    );

    // And nothing is in the Answer section: a probe asserts nothing yet.
    let answers = ResourceRecords::decode(&bytes)
        .expect("decode")
        .section(Section::Answer)
        .count();
    assert_eq!(answers, 0);
}

#[test]
fn several_advertisements_probe_one_host_name_once() {
    // A node advertising a commissionable service and an operational one shares one host name.
    // Asking for it twice wastes room in a message that has 750 ms to reach every device on
    // the link.
    let txt = worked_example_txt();
    let operational = OperationalTxt::default().encode().expect("txt");
    let advertisements = [
        worked_example(txt.finish()),
        Advertisement::new(
            "1234567890ABCDEF-8FC7772401CD0696",
            OPERATIONAL_SERVICE,
            "B75AFB458ECD",
            MDNS_PORT,
            operational.finish(),
        ),
    ];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let bytes = responder.probe(&mut buf).expect("probe").to_vec();

    let hosts = Questions::decode(&bytes)
        .expect("decode")
        .filter(|q| q.as_ref().map(|q| q.name.len()).unwrap_or(0) == 2)
        .count();
    assert_eq!(hosts, 1, "one host name, asked for once");
    assert_eq!(Questions::decode(&bytes).expect("decode").count(), 3);
}

#[test]
fn a_probe_is_recognised_as_one_and_an_ordinary_query_is_not() {
    // RFC 6762 §6: "a probe query can be distinguished from a normal query by the fact that a
    // probe query contains a proposed record in the Authority Section that answers the
    // question in the Question Section." That distinction buys an exemption from §6's
    // one-second multicast rate limit, so reading it loosely would let any sender opt out of
    // the limit by attaching an unrelated Authority record.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut probe_buf = [0u8; 1024];
    let probe = responder.probe(&mut probe_buf).expect("probe").to_vec();

    let mut buf = [0u8; 1024];
    let (_, answered) = responder.respond(&probe, &mut buf).expect("respond");
    assert!(answered.probe, "our own probe is a probe");
    // And the responder defends: the names in the probe are the ones it owns.
    assert!(answered.answers > 0);

    let mut qbuf = [0u8; 256];
    let q = query(&["_matterc", "_udp", "local"], RecordType::Ptr, &mut qbuf);
    let (_, answered) = responder.respond(&q, &mut buf).expect("respond");
    assert!(!answered.probe, "a plain browse is not a probe");
}

#[test]
fn an_authority_record_for_a_different_name_is_not_a_probe() {
    // The other half of §6's test: an Authority record that does *not* answer the question in
    // the Question Section. A DNS Update carries exactly that shape.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);

    let mut buf = [0u8; 512];
    let mut writer = DnsWriter::new(&mut buf).expect("writer");
    let asked: [&str; 4] = ["DD200C20D25AE5F7", "_matterc", "_udp", "local"];
    let other: [&str; 2] = ["SOMEONEELSE", "local"];
    writer
        .question(&asked, RecordType::Any, true)
        .expect("question");
    writer
        .authority(&Record {
            name: &other,
            kind: RecordType::Aaaa,
            ttl: 120,
            cache_flush: true,
            data: RecordData::Aaaa([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        })
        .expect("authority");
    let bytes = writer.finish(0, FLAGS_QUERY).expect("finish").to_vec();

    let mut out = [0u8; 1024];
    let (_, answered) = responder.respond(&bytes, &mut out).expect("respond");
    assert!(!answered.probe);
    assert!(answered.answers > 0, "it is still a query, and it matches");
}

#[test]
fn rdata_is_compared_uncompressed() {
    // RFC 6762 §8.2: "the names MUST be uncompressed before comparison. (The details of how a
    // particular name is compressed is an artifact of how and where the record is written into
    // the DNS message; it is not an intrinsic property of the resource record itself.)"
    //
    // The proof: take the SRV out of a real probe, where its target *was* compressed against
    // an earlier name, and check it compares equal to the same record written on its own.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let bytes = responder.probe(&mut buf).expect("probe").to_vec();

    let srv = ResourceRecords::decode(&bytes)
        .expect("decode")
        .section(Section::Authority)
        .map(|r| r.expect("record"))
        .find(|r| r.kind == Some(RecordType::Srv))
        .expect("an srv");

    let mut theirs = [0u8; RDATA_MAX];
    let theirs = srv
        .data
        .as_ref()
        .expect("srv data")
        .write_rdata(&mut theirs)
        .expect("rdata");

    let host: [&str; 2] = ["B75AFB458ECD", "local"];
    let mut ours = [0u8; RDATA_MAX];
    let ours = RecordData::Srv {
        port: 11111,
        target: &host,
    }
    .write_rdata(&mut ours)
    .expect("rdata");

    assert_eq!(ours, theirs);
    // Written out in full rather than compared only against each other: both sides come from
    // the same encoder, so "they match" would still hold if the encoder dropped the root
    // octet or the SRV's priority and weight.
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0, 0]); // priority 0
    expected.extend_from_slice(&[0, 0]); // weight 0
    expected.extend_from_slice(&11111u16.to_be_bytes());
    expected.push(12);
    expected.extend_from_slice(b"B75AFB458ECD");
    expected.push(5);
    expected.extend_from_slice(b"local");
    expected.push(0); // the root label terminates an uncompressed name
    assert_eq!(ours, expected.as_slice());
    assert!(!ours.contains(&0xC0), "no compression pointer survived");
}

#[test]
fn reading_one_section_of_a_malformed_message_still_reports_the_error() {
    // A caller tiebreaking against an arriving probe has to tell "no tiebreaker record" from
    // "this message is malformed". Filtering the error away collapses the two, and the one it
    // collapses to is the one where a name gets claimed that should not have been.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let probe = responder.probe(&mut buf).expect("probe").to_vec();

    for cut in (HEADER_LEN + 1)..probe.len() {
        let Ok(records) = ResourceRecords::decode(&probe[..cut]) else {
            continue;
        };
        // Every truncation either decodes cleanly or yields exactly one error and stops: the
        // cursor is no longer at a record boundary, so anything after it would be invention.
        let outcomes: Vec<bool> = records
            .section(Section::Authority)
            .map(|r| r.is_ok())
            .collect();
        assert!(outcomes.iter().filter(|ok| !**ok).count() <= 1);
    }

    // And explicitly: a header claiming an authority record that is not there yields an error.
    let mut lying = probe.clone();
    lying.truncate(probe.len() - 1);
    let errors = ResourceRecords::decode(&lying)
        .expect("header decodes")
        .section(Section::Authority)
        .filter(|r| r.is_err())
        .count();
    assert_eq!(errors, 1);
}

#[test]
fn a_simultaneous_probe_is_decided_by_the_authority_records() {
    // The whole §8.2 path end to end: a probe arrives for the name we are probing for, we
    // build tiebreakers from its Authority section and from our own proposed records, and the
    // lexicographically later data wins.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut buf = [0u8; 1024];
    let theirs = responder.probe(&mut buf).expect("probe").to_vec();

    // Their SRV, ours identical but for one octet of the port.
    let their_srv = ResourceRecords::decode(&theirs)
        .expect("decode")
        .section(Section::Authority)
        .map(|r| r.expect("record"))
        .find(|r| r.kind == Some(RecordType::Srv))
        .expect("an srv");
    let mut their_bytes = [0u8; RDATA_MAX];
    let their_bytes = their_srv
        .data
        .as_ref()
        .expect("data")
        .write_rdata(&mut their_bytes)
        .expect("rdata");
    let them = Tiebreaker {
        class: their_srv.class,
        kind: RecordType::Srv.value(),
        rdata: their_bytes,
    };

    let host: [&str; 2] = ["B75AFB458ECD", "local"];
    let mut our_bytes = [0u8; RDATA_MAX];
    let our_bytes = RecordData::Srv {
        port: 11112,
        target: &host,
    }
    .write_rdata(&mut our_bytes)
    .expect("rdata");
    let us = Tiebreaker {
        class: CLASS_IN,
        kind: RecordType::Srv.value(),
        rdata: our_bytes,
    };

    assert_eq!(tiebreak([us], [them]), Tiebreak::Won);
    assert_eq!(tiebreak([them], [us]), Tiebreak::Lost);
    assert_eq!(tiebreak([them], [them]), Tiebreak::Identical);
}

#[test]
fn the_cache_flush_bit_is_excluded_from_the_tiebreak() {
    // RFC 6762 §8.2 compares "the record class (excluding the cache-flush bit described in
    // Section 10.2)". An announcement sets that bit and a probe's Authority records do not, so
    // comparing the raw class would make every announcement beat every probe regardless of
    // rdata — and the winner would depend on which message the record arrived in.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);

    let mut buf = [0u8; 1024];
    let announcement = responder.announce(&mut buf).expect("announce").to_vec();
    let announced = ResourceRecords::decode(&announcement)
        .expect("decode")
        .map(|r| r.expect("record"))
        .find(|r| r.kind == Some(RecordType::Srv))
        .expect("an srv");
    assert!(announced.cache_flush, "an announced SRV sets it");
    assert_eq!(announced.class, CLASS_IN, "and `class` has it masked off");

    let mut probe_buf = [0u8; 1024];
    let probe = responder.probe(&mut probe_buf).expect("probe").to_vec();
    let probed = ResourceRecords::decode(&probe)
        .expect("decode")
        .section(Section::Authority)
        .map(|r| r.expect("record"))
        .find(|r| r.kind == Some(RecordType::Srv))
        .expect("an srv");
    assert_eq!(probed.class, announced.class);
}

#[test]
fn the_startup_sequence_is_three_probes_then_two_announcements() {
    // RFC 6762 §8, driven the way an integrator would: poll the schedule, send whatever it
    // asks for, and go back to sleep until `wake_at`.
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut schedule = Schedule::new();
    let mut now = Instant::ZERO;
    schedule.start(now, 0x5EED);

    let mut sent: Vec<(Action, usize)> = Vec::new();
    let mut buf = [0u8; 1024];
    while let Some(due) = schedule.wake_at() {
        now = due;
        let Some(action) = schedule.poll(now) else {
            break;
        };
        let bytes = match action {
            Action::Probe => responder.probe(&mut buf).expect("probe"),
            Action::Announce => responder.announce(&mut buf).expect("announce"),
            Action::Goodbye => responder.goodbye(&mut buf).expect("goodbye"),
            Action::Rename => panic!("nothing conflicted"),
            other => panic!("unexpected {other:?}"),
        };
        sent.push((action, bytes.len()));
    }

    let kinds: Vec<Action> = sent.iter().map(|(a, _)| *a).collect();
    assert_eq!(
        kinds,
        vec![
            Action::Probe,
            Action::Probe,
            Action::Probe,
            Action::Announce,
            Action::Announce
        ]
    );
    // §8.3 forbids periodic announcements: once established there is nothing more to send.
    assert_eq!(schedule.wake_at(), None);
    assert!(schedule.may_respond());
}

#[test]
fn losing_a_probe_means_a_new_instance_name_and_nothing_advertised_meanwhile() {
    // §8.1 plus §4.3.1: "In the rare event of a collision in the selection of the 64-bit
    // temporary unique identifier, the existing DNS-SD name conflict detection mechanism will
    // detect this collision, and a new pseudo-randomly selected 64-bit temporary unique
    // identifier SHALL be generated."
    let txt = worked_example_txt();
    let advertisements = [worked_example(txt.finish())];
    let responder = Responder::new(&advertisements);
    let mut schedule = Schedule::new();
    let mut now = Instant::ZERO;
    schedule.start(now, 0);

    now = schedule.wake_at().expect("scheduled");
    assert_eq!(schedule.poll(now), Some(Action::Probe));

    // Someone answers, defending the name.
    let mut buf = [0u8; 1024];
    let defence = responder.announce(&mut buf).expect("announce").to_vec();
    assert!(!defence.is_empty());
    schedule.on_conflict(now, 0);

    assert_eq!(schedule.poll(now), Some(Action::Rename));
    assert!(
        !schedule.may_respond(),
        "nothing may be advertised under a name that was lost"
    );

    // A new instance name, and the whole sequence runs again.
    schedule.renamed(now, 0);
    let mut probes = 0;
    while let Some(due) = schedule.wake_at() {
        now = due;
        match schedule.poll(now) {
            Some(Action::Probe) => probes += 1,
            Some(Action::Announce) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(probes, 3);
    assert!(schedule.may_respond());
}
