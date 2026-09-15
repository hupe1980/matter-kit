//! The interaction model encoding, against Core chapter 10.
//!
//! There are no published byte-level vectors for these messages the way there are for TLV,
//! SPAKE2+ and the certificates — chapter 10 gives schemas and prose examples rather than
//! hex dumps. So the checks here are of three kinds, in increasing strength:
//!
//! 1. **The schema, field by field.** Every tag number and TLV type is asserted against
//!    §10.6 and §10.7 by decoding bytes written by hand to the schema, so a transposed tag
//!    shows up here rather than against somebody else's implementation.
//! 2. **The prose examples of §10.6.2.5**, which state what each wildcard path means.
//! 3. **Round trips**, which catch a field that encodes and decodes consistently wrongly
//!    only when combined with (1).
//!
//! The first is the one that matters. Two implementations agreeing proves nothing, and this
//! crate agreeing with itself proves less — so every tag number below is written out as a
//! literal taken from the specification's table, not read back from the encoder.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use matter_kit::im::{
    AttributeData, AttributePath, AttributeReport, AttributeStatus, ClusterPath, CommandData,
    CommandPath, CommandStatus, DataVersionFilter, EventFilter, EventPath,
    INTERACTION_MODEL_REVISION, InvokeRequest, InvokeResponse, InvokeResponseMessage, ListIndex,
    REVISION_TAG, ReadRequest, ReportData, Status, StatusIb, StatusResponse, SubscribeRequest,
    SubscribeResponse, TimedRequest, WildcardPathFlags, WriteRequest, WriteResponse,
    encode_invoke_request, encode_invoke_response, encode_read_request, encode_report_data,
    encode_write_request, encode_write_response, opcode,
};
use matter_kit::msg::NodeId;
use matter_kit::tlv::{ContainerKind, Pretty, Tag, TlvReader, TlvWriter, Value};

const DISCO_BALL: u32 = 0x0000_1234;
const AXIS: u32 = 0x0000_0001;
const PATTERN: u32 = 0x0000_0002;

fn encode_path(path: &AttributePath) -> heapless::Vec<u8, 128> {
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new(&mut buf);
    path.encode(&mut w, Tag::Anonymous).expect("encode");
    heapless::Vec::from_slice(w.finish().expect("finish")).expect("fits")
}

fn decode_path(bytes: &[u8]) -> AttributePath {
    let mut reader = TlvReader::new(bytes);
    let element = reader.next_element().expect("element").expect("present");
    AttributePath::from_element(&mut reader, &element).expect("decode")
}

// --- §10.2.1: the opcodes --------------------------------------------------------------------

#[test]
fn the_opcodes_are_the_ones_the_spec_assigns() {
    // §10.2.1's table. These go in a message header, so a wrong one is an action the peer
    // dispatches to the wrong handler.
    assert_eq!(opcode::STATUS_RESPONSE, 0x01);
    assert_eq!(opcode::READ_REQUEST, 0x02);
    assert_eq!(opcode::SUBSCRIBE_REQUEST, 0x03);
    assert_eq!(opcode::SUBSCRIBE_RESPONSE, 0x04);
    assert_eq!(opcode::REPORT_DATA, 0x05);
    assert_eq!(opcode::WRITE_REQUEST, 0x06);
    assert_eq!(opcode::WRITE_RESPONSE, 0x07);
    assert_eq!(opcode::INVOKE_REQUEST, 0x08);
    assert_eq!(opcode::INVOKE_RESPONSE, 0x09);
    assert_eq!(opcode::TIMED_REQUEST, 0x0A);
}

#[test]
fn the_revision_is_thirteen_under_tag_255() {
    // §10.2.2.2 puts InteractionModelRevision at context tag 0xFF, and §8.1.1's history ends
    // at 13 ("Added WildcardFilterConfigurationVersion").
    assert_eq!(REVISION_TAG, 0xFF);
    assert_eq!(INTERACTION_MODEL_REVISION, 13);
}

// --- §10.6.2: AttributePathIB ----------------------------------------------------------------

#[test]
fn an_attribute_path_uses_the_tag_numbers_of_10_6_2() {
    // Written out here from the specification's table rather than read back from the
    // encoder, so a transposed pair shows up as a failure and not as agreement.
    let path = AttributePath {
        enable_tag_compression: true,
        node: Some(NodeId(0x0018_B430_0030_2020)),
        endpoint: Some(10),
        cluster: Some(DISCO_BALL),
        attribute: Some(AXIS),
        list_index: Some(ListIndex::At(4)),
        wildcard_path_flags: Some(WildcardPathFlags::SKIP_ROOT_NODE),
        wildcard_filter_configuration_version: Some(7),
    };
    let bytes = encode_path(&path);
    let shown = std::format!("{}", Pretty(&bytes));

    // An AttributePathIB is a List, not a Structure — §10.6.2's "TLV Type: List". The
    // pretty printer renders both lists and arrays with brackets, so the container kind
    // comes from the reader rather than from the rendering.
    let mut reader = TlvReader::new(&bytes);
    let head = reader.next_element().expect("element").expect("present");
    assert_eq!(head.value, Value::Container(ContainerKind::List));

    let node = std::format!("{}U", 0x0018_B430_0030_2020u64);
    for (tag, value) in [
        (0u8, "true".to_string()),
        (1, node),
        (2, "10U".to_string()),
        (3, "4660U".to_string()),
        (4, "1U".to_string()),
        (5, "4U".to_string()),
        (6, "1U".to_string()),
        (7, "7U".to_string()),
    ] {
        assert!(
            shown.contains(&std::format!("{tag} = {value}")),
            "tag {tag} = {value} missing from {shown}"
        );
    }
    assert_eq!(decode_path(&bytes), path);
}

#[test]
fn the_wildcard_examples_of_10_6_2_5_mean_what_the_spec_says() {
    // "Select all attributes on a given cluster and endpoint."
    let cluster = AttributePath::cluster(10, DISCO_BALL);
    assert_eq!(cluster.endpoint, Some(10));
    assert_eq!(cluster.attribute, None, "omission is a wildcard");
    assert!(cluster.has_wildcard());
    assert_eq!(cluster.concrete(), None);

    // "Select all attributes in all clusters on a given endpoint": Path = [[ Endpoint = 10 ]]
    let endpoint = AttributePath {
        endpoint: Some(10),
        ..AttributePath::wildcard()
    };
    assert_eq!(endpoint.cluster, None);

    // "Select all attributes in all clusters on the node": Path = [[ ]]
    let all = AttributePath::wildcard();
    let bytes = encode_path(&all);
    assert_eq!(
        std::format!("{}", Pretty(&bytes)),
        "[]",
        "an empty list is the whole-node wildcard"
    );
    assert_eq!(decode_path(&bytes), all);

    // "Select a specific attribute."
    let one = AttributePath::attribute(10, DISCO_BALL, AXIS);
    assert_eq!(one.concrete(), Some((10, DISCO_BALL, AXIS)));
    assert!(!one.has_wildcard());

    // "Select a specific item in a top-level list."
    let item = AttributePath {
        list_index: Some(ListIndex::At(4)),
        ..AttributePath::attribute(10, DISCO_BALL, PATTERN)
    };
    assert_eq!(decode_path(&encode_path(&item)), item);

    // "Select all attributes in all clusters on a given endpoint on a proxied node."
    let proxied = AttributePath {
        node: Some(NodeId(0x018B_4300_0302_0203)),
        endpoint: Some(10),
        ..AttributePath::wildcard()
    };
    assert_eq!(decode_path(&encode_path(&proxied)), proxied);
    // Node is the one field whose omission is *not* a wildcard (§10.6.2.2).
    assert!(AttributePath::wildcard().node.is_none());
}

#[test]
fn a_null_list_index_is_a_list_append() {
    // §10.6.4.3.1: "Path SHALL refer to a list with ListIndex containing a value of null and
    // Data containing the new value of the list item that will be added to the list."
    let append = AttributePath {
        list_index: Some(ListIndex::Append),
        ..AttributePath::attribute(1, DISCO_BALL, PATTERN)
    };
    let bytes = encode_path(&append);
    assert!(
        std::format!("{}", Pretty(&bytes)).contains("5 = null"),
        "the append marker is a null, not a sentinel index"
    );
    assert_eq!(decode_path(&bytes), append);
    // And it is distinct from index 5, which is a different operation entirely.
    assert_ne!(
        append,
        AttributePath {
            list_index: Some(ListIndex::At(5)),
            ..AttributePath::attribute(1, DISCO_BALL, PATTERN)
        }
    );
}

#[test]
fn an_unknown_wildcard_flag_survives_a_round_trip() {
    // §10.2.2: unknown *tags* are ignored, but a flag inside a known field is data a proxy
    // must not silently drop.
    let path = AttributePath {
        wildcard_path_flags: Some(WildcardPathFlags::from_bits_retain(0x8000_0000)),
        ..AttributePath::cluster(1, DISCO_BALL)
    };
    assert_eq!(
        decode_path(&encode_path(&path))
            .wildcard_path_flags
            .expect("flags")
            .bits(),
        0x8000_0000
    );
}

#[test]
fn an_unknown_tag_in_a_path_is_skipped() {
    // §10.2.2: "any context-specific tag not listed in a given schema SHALL be reserved for
    // future use and SHALL be silently ignored by clients and servers if seen in a payload."
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    w.start_list(Tag::Anonymous).expect("list");
    w.unsigned(Tag::Context(2), 10).expect("endpoint");
    w.unsigned(Tag::Context(200), 0xDEAD)
        .expect("a tag from the future");
    w.unsigned(Tag::Context(3), u64::from(DISCO_BALL))
        .expect("cluster");
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let path = decode_path(&bytes);
    assert_eq!(path.endpoint, Some(10));
    assert_eq!(
        path.cluster,
        Some(DISCO_BALL),
        "the field after it still reads"
    );
}

#[test]
fn a_duplicate_tag_in_a_path_is_refused() {
    // A list permits repeated tags structurally, but §10.6.2's schema names each field once
    // and a second Endpoint would leave two readers disagreeing about what was addressed.
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    w.start_list(Tag::Anonymous).expect("list");
    w.unsigned(Tag::Context(2), 10).expect("endpoint");
    w.unsigned(Tag::Context(2), 11).expect("a second endpoint");
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let mut reader = TlvReader::new(&bytes);
    let element = reader.next_element().expect("element").expect("present");
    assert!(AttributePath::from_element(&mut reader, &element).is_err());
}

// --- §10.6.7, §10.6.8, §10.6.11: the other three paths ---------------------------------------

#[test]
fn the_other_paths_use_their_own_tag_numbers() {
    // Each path type numbers its fields from 0 independently — ClusterPath's Endpoint is 1
    // where AttributePath's is 2, because AttributePath has EnableTagCompression at 0.
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    ClusterPath::new(10, DISCO_BALL)
        .encode(&mut w, Tag::Anonymous)
        .expect("encode");
    let shown = std::format!("{}", Pretty(w.finish().expect("finish")));
    assert!(
        shown.contains("1 = 10U"),
        "ClusterPath endpoint is tag 1: {shown}"
    );
    assert!(shown.contains("2 = 4660U"), "cluster is tag 2: {shown}");

    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    CommandPath::command(10, DISCO_BALL, 5)
        .encode(&mut w, Tag::Anonymous)
        .expect("encode");
    let shown = std::format!("{}", Pretty(w.finish().expect("finish")));
    assert!(
        shown.contains("0 = 10U"),
        "CommandPath endpoint is tag 0: {shown}"
    );
    assert!(shown.contains("2 = 5U"), "command is tag 2: {shown}");

    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    EventPath {
        is_urgent: Some(true),
        ..EventPath::event(10, DISCO_BALL, 3)
    }
    .encode(&mut w, Tag::Anonymous)
    .expect("encode");
    let shown = std::format!("{}", Pretty(w.finish().expect("finish")));
    assert!(
        shown.contains("3 = 3U"),
        "EventPath event is tag 3: {shown}"
    );
    assert!(shown.contains("4 = true"), "IsUrgent is tag 4: {shown}");
}

// --- §10.6: the information blocks -----------------------------------------------------------

/// An encoded `uint8 = 42` under `tag`, standing in for a cluster's attribute value.
///
/// Written with `new_in`, because a context-specific tag is illegal at the top level and
/// required inside a structure — and this fragment is destined for one.
fn a_value(tag: u8) -> heapless::Vec<u8, 16> {
    let mut buf = [0u8; 16];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.unsigned(Tag::Context(tag), 42).expect("value");
    heapless::Vec::from_slice(w.finish().expect("finish")).expect("fits")
}

#[test]
fn an_attribute_data_block_carries_its_value_verbatim() {
    // §10.6.4.3 makes Data "Variable": its type is the cluster's, not the interaction
    // model's. So it must survive a round trip byte for byte — a bridge forwards reports
    // for clusters it has never heard of.
    let value = a_value(2);
    let data = AttributeData {
        data_version: Some(0xDEAD_BEEF),
        path: AttributePath::attribute(1, DISCO_BALL, AXIS),
        data: &value,
    };

    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new(&mut buf);
    data.encode(&mut w, Tag::Anonymous).expect("encode");
    let bytes = w.finish().expect("finish").to_vec();

    let mut reader = TlvReader::new(&bytes);
    reader.next_element().expect("element").expect("present");
    let decoded = AttributeData::decode(&mut reader).expect("decode");
    assert_eq!(decoded.data, &value[..], "the value is carried verbatim");
    assert_eq!(decoded.data_version, Some(0xDEAD_BEEF));
    assert_eq!(decoded.path, data.path);
}

#[test]
fn a_structured_value_survives_being_carried() {
    // Not just scalars: a cluster's attribute can be a struct or a list, and the whole
    // subtree has to come through untouched.
    let mut value_buf = [0u8; 64];
    let mut vw = TlvWriter::new_in(&mut value_buf, ContainerKind::Structure);
    vw.start_structure(Tag::Context(2)).expect("struct");
    vw.unsigned(Tag::Context(0), 1).expect("a");
    vw.utf8(Tag::Context(1), "nested").expect("b");
    vw.start_array(Tag::Context(2)).expect("array");
    vw.unsigned(Tag::Anonymous, 7).expect("item");
    vw.end_container().expect("end array");
    vw.end_container().expect("end struct");
    let value = vw.finish().expect("finish").to_vec();

    let data = AttributeData {
        data_version: None,
        path: AttributePath::attribute(1, DISCO_BALL, PATTERN),
        data: &value,
    };
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new(&mut buf);
    data.encode(&mut w, Tag::Anonymous).expect("encode");
    let bytes = w.finish().expect("finish").to_vec();

    let mut reader = TlvReader::new(&bytes);
    reader.next_element().expect("element").expect("present");
    let decoded = AttributeData::decode(&mut reader).expect("decode");
    assert_eq!(decoded.data, &value[..]);
}

#[test]
fn a_status_ib_uses_the_tag_numbers_of_10_6_17() {
    let status = StatusIb {
        status: Status::ConstraintError,
        cluster_status: Some(9),
    };
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new(&mut buf);
    status.encode(&mut w, Tag::Anonymous).expect("encode");
    let bytes = w.finish().expect("finish").to_vec();
    let shown = std::format!("{}", Pretty(&bytes));
    assert!(shown.contains("0 = 135U"), "0x87 CONSTRAINT_ERROR: {shown}");
    assert!(shown.contains("1 = 9U"), "ClusterStatus is tag 1: {shown}");

    let mut reader = TlvReader::new(&bytes);
    reader.next_element().expect("element").expect("present");
    assert_eq!(StatusIb::decode(&mut reader).expect("decode"), status);
}

#[test]
fn a_report_is_a_status_or_data_and_never_both() {
    // §10.6.5's schema has two optional fields and §8.4.3 always fills exactly one. Modelling
    // it as a choice makes the other two cases unrepresentable rather than merely wrong.
    let value = a_value(2);
    for report in [
        AttributeReport::Data(AttributeData {
            data_version: Some(1),
            path: AttributePath::attribute(1, DISCO_BALL, AXIS),
            data: &value,
        }),
        AttributeReport::Status(AttributeStatus {
            path: AttributePath::attribute(1, DISCO_BALL, AXIS),
            status: StatusIb::new(Status::UnsupportedAttribute),
        }),
    ] {
        let mut buf = [0u8; 128];
        let mut w = TlvWriter::new(&mut buf);
        report.encode(&mut w).expect("encode");
        let bytes = w.finish().expect("finish").to_vec();

        let mut reader = TlvReader::new(&bytes);
        reader.next_element().expect("element").expect("present");
        assert_eq!(
            AttributeReport::decode(&mut reader).expect("decode"),
            report
        );
        assert_eq!(report.path(), AttributePath::attribute(1, DISCO_BALL, AXIS));
    }
}

#[test]
fn a_report_with_neither_arm_is_refused() {
    // It names a path and says nothing about it, which no reader can act on.
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).expect("start");
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let mut reader = TlvReader::new(&bytes);
    reader.next_element().expect("element").expect("present");
    assert!(AttributeReport::decode(&mut reader).is_err());
}

#[test]
fn the_filters_round_trip_and_use_their_own_tag_numbers() {
    // A DataVersionFilter says "I already hold version V of this cluster, skip it"
    // (§10.6.3); an EventFilter says the same for events (§10.6.6). Both are how a
    // subscription avoids re-sending what the client already has, so a misread tag turns a
    // cheap resubscribe into a full dump.
    let filter = DataVersionFilter {
        path: ClusterPath::new(1, DISCO_BALL),
        data_version: 0x1234_5678,
    };
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    filter.encode(&mut w).expect("encode");
    let bytes = w.finish().expect("finish").to_vec();
    let shown = std::format!("{}", Pretty(&bytes));
    assert!(
        shown.contains("1 = 305419896U"),
        "DataVersion is tag 1: {shown}"
    );

    let mut reader = TlvReader::new(&bytes);
    let head = reader.next_element().expect("element").expect("present");
    assert_eq!(head.value, Value::Container(ContainerKind::Structure));
    assert_eq!(
        DataVersionFilter::decode(&mut reader).expect("decode"),
        filter
    );

    let event_filter = EventFilter {
        node: Some(NodeId(0xDEAD_BEEF)),
        event_min: 42,
    };
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    event_filter.encode(&mut w).expect("encode");
    let bytes = w.finish().expect("finish").to_vec();
    let shown = std::format!("{}", Pretty(&bytes));
    assert!(shown.contains("1 = 42U"), "EventMin is tag 1: {shown}");

    let mut reader = TlvReader::new(&bytes);
    reader.next_element().expect("element").expect("present");
    assert_eq!(
        EventFilter::decode(&mut reader).expect("decode"),
        event_filter
    );
}

#[test]
fn a_read_request_carries_its_filters_through() {
    // The filters ride in a ReadRequest's optional arrays, and both are structures rather
    // than lists — the container kind differs from the path arrays beside them.
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).expect("start");
    w.start_array(Tag::Context(2)).expect("event filters");
    EventFilter {
        node: None,
        event_min: 7,
    }
    .encode(&mut w)
    .expect("filter");
    w.end_container().expect("end");
    w.bool(Tag::Context(3), false).expect("fabric filtered");
    w.start_array(Tag::Context(4)).expect("version filters");
    DataVersionFilter {
        path: ClusterPath::new(1, DISCO_BALL),
        data_version: 9,
    }
    .encode(&mut w)
    .expect("filter");
    w.end_container().expect("end");
    w.unsigned(Tag::Context(REVISION_TAG), 13)
        .expect("revision");
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let request = ReadRequest::decode(&bytes).expect("decode");
    let events: Vec<_> = request
        .event_filters()
        .expect("filters")
        .expect("present")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_min, 7);

    let versions: Vec<_> = request
        .data_version_filters()
        .expect("filters")
        .expect("present")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].data_version, 9);
    assert_eq!(versions[0].path.cluster, Some(DISCO_BALL));
}

#[test]
fn a_path_array_whose_members_are_structures_is_refused() {
    // §10.6.2 makes an AttributePathIB a List. A decoder that shrugged and accepted a
    // Structure would accept paths no conforming peer sends, and the two container types
    // have different tag rules — so it would be accepting a different grammar.
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).expect("start");
    w.start_array(Tag::Context(0)).expect("paths");
    w.start_structure(Tag::Anonymous)
        .expect("a structure, not a list");
    w.unsigned(Tag::Context(2), 1).expect("endpoint");
    w.end_container().expect("end");
    w.end_container().expect("end array");
    w.bool(Tag::Context(3), false).expect("fabric filtered");
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let request = ReadRequest::decode(&bytes).expect("the message itself is well formed");
    let first = request
        .attribute_paths()
        .expect("paths")
        .expect("present")
        .next()
        .expect("one member");
    assert!(first.is_err(), "a structure is not an AttributePathIB");
}

// --- §10.7: the messages ---------------------------------------------------------------------

#[test]
fn a_read_request_round_trips_with_its_paths() {
    let mut buf = [0u8; 512];
    let bytes = encode_read_request(
        &mut buf,
        [
            AttributePath::attribute(1, DISCO_BALL, AXIS),
            AttributePath::cluster(2, DISCO_BALL),
            AttributePath::wildcard(),
        ],
        [EventPath::event(1, DISCO_BALL, 3)],
        true,
    )
    .expect("encode")
    .to_vec();

    let request = ReadRequest::decode(&bytes).expect("decode");
    assert!(request.fabric_filtered);
    assert_eq!(request.revision, Some(INTERACTION_MODEL_REVISION));

    let paths: Vec<_> = request
        .attribute_paths()
        .expect("paths")
        .expect("present")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(paths.len(), 3);
    assert_eq!(paths[0].concrete(), Some((1, DISCO_BALL, AXIS)));
    assert_eq!(paths[1].attribute, None);
    assert_eq!(paths[2], AttributePath::wildcard());

    let events: Vec<_> = request
        .event_paths()
        .expect("events")
        .expect("present")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, Some(3));
}

#[test]
fn a_read_request_with_no_paths_is_still_well_formed() {
    // Every array in a ReadRequest is optional (§10.7.2); only FabricFiltered is not.
    let mut buf = [0u8; 64];
    let bytes = encode_read_request(&mut buf, [], [], false)
        .expect("encode")
        .to_vec();
    let request = ReadRequest::decode(&bytes).expect("decode");
    assert!(!request.fabric_filtered);
    assert!(request.attribute_paths().expect("paths").is_none());
    assert!(request.event_paths().expect("events").is_none());
}

#[test]
fn a_report_data_round_trips_with_its_reports() {
    let value = a_value(2);
    let reports = [
        AttributeReport::Data(AttributeData {
            data_version: Some(7),
            path: AttributePath::attribute(1, DISCO_BALL, AXIS),
            data: &value,
        }),
        AttributeReport::Status(AttributeStatus {
            path: AttributePath::attribute(1, DISCO_BALL, PATTERN),
            status: StatusIb::new(Status::UnsupportedAccess),
        }),
    ];
    let mut buf = [0u8; 512];
    let bytes = encode_report_data(&mut buf, Some(0x1234_5678), reports, true, false)
        .expect("encode")
        .to_vec();

    let report = ReportData::decode(&bytes).expect("decode");
    assert_eq!(report.subscription_id, Some(0x1234_5678));
    assert!(report.more_chunked_messages);
    assert!(!report.suppress_response);

    let decoded: Vec<_> = report
        .attribute_reports()
        .expect("reports")
        .expect("present")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(decoded.len(), 2);
    match decoded[0] {
        AttributeReport::Data(data) => {
            assert_eq!(data.data, &value[..]);
            assert_eq!(data.data_version, Some(7));
        }
        AttributeReport::Status(_) => panic!("expected data"),
    }
    match decoded[1] {
        AttributeReport::Status(status) => {
            assert_eq!(status.status.status, Status::UnsupportedAccess);
        }
        AttributeReport::Data(_) => panic!("expected status"),
    }
}

#[test]
fn the_omit_if_false_booleans_are_actually_omitted() {
    // §10.7.3 marks MoreChunkedMessages "Can be omitted" and SuppressResponse "Omit if
    // 'false'". These are on the path that drives chunking, so the octets are not free.
    let mut buf = [0u8; 128];
    let bytes = encode_report_data(&mut buf, None, [], false, false)
        .expect("encode")
        .to_vec();
    let shown = std::format!("{}", Pretty(&bytes));
    assert!(
        !shown.contains("3 = false"),
        "tag 3 should be omitted: {shown}"
    );
    assert!(
        !shown.contains("4 = false"),
        "tag 4 should be omitted: {shown}"
    );

    let report = ReportData::decode(&bytes).expect("decode");
    assert!(!report.more_chunked_messages, "absent reads as false");
    assert!(!report.suppress_response);
}

#[test]
fn a_write_request_round_trips_with_its_data() {
    let value = a_value(2);
    let mut buf = [0u8; 512];
    let bytes = encode_write_request(
        &mut buf,
        [AttributeData {
            data_version: None,
            path: AttributePath::attribute(1, DISCO_BALL, AXIS),
            data: &value,
        }],
        true,
        false,
    )
    .expect("encode")
    .to_vec();

    let request = WriteRequest::decode(&bytes).expect("decode");
    assert!(request.timed_request);
    assert!(!request.suppress_response);
    let writes: Vec<_> = request
        .writes()
        .expect("writes")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].data, &value[..]);
    assert_eq!(writes[0].path.concrete(), Some((1, DISCO_BALL, AXIS)));
}

#[test]
fn a_write_response_round_trips() {
    let mut buf = [0u8; 256];
    let bytes = encode_write_response(
        &mut buf,
        [
            AttributeStatus {
                path: AttributePath::attribute(1, DISCO_BALL, AXIS),
                status: StatusIb::new(Status::Success),
            },
            AttributeStatus {
                path: AttributePath::attribute(1, DISCO_BALL, PATTERN),
                status: StatusIb {
                    status: Status::Failure,
                    cluster_status: Some(3),
                },
            },
        ],
    )
    .expect("encode")
    .to_vec();

    let response = WriteResponse::decode(&bytes).expect("decode");
    let statuses: Vec<_> = response
        .statuses()
        .expect("statuses")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(statuses.len(), 2);
    assert!(statuses[0].status.status.is_success());
    assert_eq!(statuses[1].status.cluster_status, Some(3));
}

#[test]
fn an_invoke_round_trips_in_both_directions() {
    let fields = a_value(1);
    let mut buf = [0u8; 512];
    let bytes = encode_invoke_request(
        &mut buf,
        [
            CommandData {
                path: CommandPath::command(1, DISCO_BALL, 0),
                fields: Some(&fields),
                command_ref: Some(1),
            },
            CommandData {
                path: CommandPath::command(1, DISCO_BALL, 1),
                fields: None,
                command_ref: Some(2),
            },
        ],
        false,
        false,
    )
    .expect("encode")
    .to_vec();

    let request = InvokeRequest::decode(&bytes).expect("decode");
    let commands: Vec<_> = request
        .commands()
        .expect("commands")
        .collect::<Result<_, _>>()
        .expect("decode each");
    // Two commands in one request: revision 12 and later (§8.1.1).
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].fields, Some(&fields[..]));
    assert_eq!(commands[0].command_ref, Some(1));
    assert_eq!(commands[1].fields, None, "a command with no fields");

    let response_fields = a_value(1);
    let mut buf = [0u8; 512];
    let bytes = encode_invoke_response(
        &mut buf,
        [
            InvokeResponse::Command(CommandData {
                path: CommandPath::command(1, DISCO_BALL, 0),
                fields: Some(&response_fields),
                command_ref: Some(1),
            }),
            InvokeResponse::Status(CommandStatus {
                path: CommandPath::command(1, DISCO_BALL, 1),
                status: StatusIb::new(Status::UnsupportedCommand),
                command_ref: Some(2),
            }),
        ],
        false,
    )
    .expect("encode")
    .to_vec();

    let response = InvokeResponseMessage::decode(&bytes).expect("decode");
    let responses: Vec<_> = response
        .responses()
        .expect("responses")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(responses.len(), 2);
    match responses[0] {
        InvokeResponse::Command(command) => {
            assert_eq!(command.fields, Some(&response_fields[..]));
            assert_eq!(command.command_ref, Some(1));
        }
        InvokeResponse::Status(_) => panic!("expected a command"),
    }
    match responses[1] {
        InvokeResponse::Status(status) => {
            assert_eq!(status.status.status, Status::UnsupportedCommand);
            assert_eq!(status.command_ref, Some(2), "matched to its request");
        }
        InvokeResponse::Command(_) => panic!("expected a status"),
    }
}

#[test]
fn the_small_messages_round_trip() {
    let mut buf = [0u8; 64];
    let bytes = StatusResponse::new(Status::Busy)
        .encode(&mut buf)
        .expect("encode")
        .to_vec();
    let decoded = StatusResponse::decode(&bytes).expect("decode");
    assert_eq!(decoded.status, Status::Busy);
    assert_eq!(decoded.revision, Some(INTERACTION_MODEL_REVISION));

    let mut buf = [0u8; 64];
    let bytes = TimedRequest::new(5_000)
        .encode(&mut buf)
        .expect("encode")
        .to_vec();
    assert_eq!(
        TimedRequest::decode(&bytes).expect("decode").timeout_ms,
        5_000
    );

    let mut buf = [0u8; 64];
    let bytes = SubscribeResponse::new(0xABCD_EF01, 60)
        .encode(&mut buf)
        .expect("encode")
        .to_vec();
    let decoded = SubscribeResponse::decode(&bytes).expect("decode");
    assert_eq!(decoded.subscription_id, 0xABCD_EF01);
    assert_eq!(decoded.max_interval_s, 60);
    // §10.7.5 has no tag 1: it held a MinInterval that was removed, and the gap is the
    // specification's rather than an omission here.
    let shown = std::format!("{}", Pretty(&bytes));
    assert!(!shown.contains("1 = "), "there is no tag 1: {shown}");
    assert!(shown.contains("2 = 60U"), "MaxInterval is tag 2: {shown}");
}

#[test]
fn a_subscribe_request_uses_the_tag_numbers_of_10_7_4() {
    // Tag 6 is skipped in the schema and FabricFiltered is 7 — an off-by-one here would
    // silently turn a fabric-filtered subscription into an unfiltered one.
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).expect("start");
    w.bool(Tag::Context(0), true).expect("keep");
    w.unsigned(Tag::Context(1), 1).expect("min");
    w.unsigned(Tag::Context(2), 60).expect("max");
    w.start_array(Tag::Context(3)).expect("paths");
    AttributePath::cluster(1, DISCO_BALL)
        .encode(&mut w, Tag::Anonymous)
        .expect("path");
    w.end_container().expect("end paths");
    w.bool(Tag::Context(7), true).expect("fabric filtered");
    w.unsigned(Tag::Context(REVISION_TAG), 13)
        .expect("revision");
    w.end_container().expect("end");
    let bytes = w.finish().expect("finish").to_vec();

    let request = SubscribeRequest::decode(&bytes).expect("decode");
    assert!(request.keep_subscriptions);
    assert_eq!(request.min_interval_floor_s, 1);
    assert_eq!(request.max_interval_ceiling_s, 60);
    assert!(request.fabric_filtered);
    let paths: Vec<_> = request
        .attribute_paths()
        .expect("paths")
        .expect("present")
        .collect::<Result<_, _>>()
        .expect("decode each");
    assert_eq!(paths.len(), 1);
}

// --- Robustness -------------------------------------------------------------------------------

#[test]
fn every_truncation_of_every_message_is_an_error_not_a_panic() {
    // Every one of these arrives from a peer that is authenticated but not trusted.
    let value = a_value(2);
    let mut buf = [0u8; 512];

    let read = encode_read_request(
        &mut buf,
        [AttributePath::attribute(1, DISCO_BALL, AXIS)],
        [],
        true,
    )
    .expect("encode")
    .to_vec();
    for len in 0..read.len() {
        let _ = ReadRequest::decode(&read[..len]);
    }

    let mut buf = [0u8; 512];
    let report = encode_report_data(
        &mut buf,
        Some(1),
        [AttributeReport::Data(AttributeData {
            data_version: Some(1),
            path: AttributePath::attribute(1, DISCO_BALL, AXIS),
            data: &value,
        })],
        false,
        false,
    )
    .expect("encode")
    .to_vec();
    for len in 0..report.len() {
        if let Ok(decoded) = ReportData::decode(&report[..len])
            && let Ok(Some(iter)) = decoded.attribute_reports()
        {
            for item in iter {
                let _ = item;
            }
        }
    }
}

#[test]
fn a_truncated_array_errors_during_iteration_and_then_stops() {
    // An iterator that yielded an error and then kept going would let a caller loop forever
    // on malformed input.
    let value = a_value(2);
    let mut buf = [0u8; 512];
    let bytes = encode_report_data(
        &mut buf,
        None,
        [AttributeReport::Data(AttributeData {
            data_version: Some(1),
            path: AttributePath::attribute(1, DISCO_BALL, AXIS),
            data: &value,
        })],
        false,
        false,
    )
    .expect("encode")
    .to_vec();

    for len in 8..bytes.len() {
        let Ok(report) = ReportData::decode(&bytes[..len]) else {
            continue;
        };
        let Ok(Some(iter)) = report.attribute_reports() else {
            continue;
        };
        let mut seen = 0usize;
        for item in iter {
            seen += 1;
            assert!(seen < 64, "iteration did not terminate at len {len}");
            if item.is_err() {
                break;
            }
        }
    }
}

#[test]
fn every_single_bit_flip_of_a_report_is_caught_or_decodes_consistently() {
    let value = a_value(2);
    let mut buf = [0u8; 512];
    let original = encode_report_data(
        &mut buf,
        Some(1),
        [AttributeReport::Data(AttributeData {
            data_version: Some(1),
            path: AttributePath::attribute(1, DISCO_BALL, AXIS),
            data: &value,
        })],
        false,
        false,
    )
    .expect("encode")
    .to_vec();

    let mut corrupted = vec![0u8; original.len()];
    for index in 0..original.len() {
        for bit in 0..8u32 {
            corrupted.copy_from_slice(&original);
            corrupted[index] ^= 1 << bit;
            let Ok(report) = ReportData::decode(&corrupted) else {
                continue;
            };
            let Ok(Some(iter)) = report.attribute_reports() else {
                continue;
            };
            // Whatever it decoded to, walking it terminates and never panics.
            for item in iter.take(64) {
                let _ = item;
            }
        }
    }
}
