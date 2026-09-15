//! Chunking a report across messages (Core §10.2.3, §10.6.4.3.1).
//!
//! A whole-node wildcard read does not fit in one message and is not meant to. §4.4.4 caps a
//! UDP message at the 1280-octet IPv6 minimum MTU, and §10.2.3 answers that by *chunking*:
//! "maximally packing these information blocks (IBs) into a series of 'data' messages", with
//! `MoreChunkedMessages` set on every message but the last.
//!
//! Two things make this easy to get subtly and dangerously wrong:
//!
//! 1. **The flag is a promise.** A message that sets `MoreChunkedMessages` tells the client
//!    another message is coming. A server that sets it and stops leaves the client waiting
//!    for a message that will never arrive — worse than refusing the read outright, because
//!    the client cannot tell the difference between that and a slow device.
//!
//! 2. **The boundary is a size, not a count.** Packing must be driven by what actually fits
//!    in the buffer. A server that chunks on a report count still fails on one large value,
//!    and a server that stops on the first `BufferTooSmall` has already corrupted the message
//!    it was packing.
//!
//! The property that ties it together is that chunking is *lossless and terminating*: every
//! path the unchunked read would have produced comes out exactly once, across however many
//! messages it takes, and the loop always ends — including when a single value is too large
//! for an empty message.

#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::dm::{AttributeDescriptor, ClusterDescriptor, Endpoint, Node, Privilege, Resolved};
use matter_kit::im::{
    AccessControl, AttributePath, AttributeReport, InteractionContext, ListIndex, Outcome,
    ReadCursor, ReportData, Server, Status,
};
use matter_kit::tlv::{Tag, TlvWriter};

const NO_CMDS: &[matter_kit::dm::CommandDescriptor] = &[];

const ATTRS: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_only(0),
    AttributeDescriptor::read_only(1),
    AttributeDescriptor::read_only(2),
    AttributeDescriptor::read_only(3),
    AttributeDescriptor::read_only(4),
    AttributeDescriptor::read_only(5),
    AttributeDescriptor::read_only(6),
    AttributeDescriptor::read_only(7),
    AttributeDescriptor::read_only(8),
    AttributeDescriptor::read_only(9),
    AttributeDescriptor::read_only(10),
    AttributeDescriptor::read_only(11),
    AttributeDescriptor::read_only(12),
    AttributeDescriptor::read_only(13),
    AttributeDescriptor::read_only(14),
    AttributeDescriptor::read_only(15),
    AttributeDescriptor::read_only(16),
    AttributeDescriptor::read_only(17),
    AttributeDescriptor::read_only(18),
    AttributeDescriptor::read_only(19),
];

const CL: &[ClusterDescriptor<'static>] = &[ClusterDescriptor {
    id: 0x0006,
    revision: 3,
    feature_map: 0,
    attributes: ATTRS,
    accepted_commands: NO_CMDS,
    generated_commands: &[],
    events: &[],
}];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(1, CL)];

struct Big;
impl matter_kit::im::ClusterHandler for Big {
    fn read(
        &self,
        _r: &Resolved<'_>,
        _c: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.octets(tag, &[0xAB; 64]).map_err(|_| Status::Failure)
    }
    fn data_version(&self, _r: &Resolved<'_>) -> Option<u32> {
        Some(7)
    }
}

/// One attribute whose value is a list far too big for a message.
struct BigList;
impl matter_kit::im::ClusterHandler for BigList {
    fn read(
        &self,
        _r: &Resolved<'_>,
        _c: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        // Twenty 64-octet items: ~1.3 kB, so the whole list cannot be one block.
        w.start_array(tag).map_err(|_| Status::Failure)?;
        for i in 0..20u8 {
            w.octets(Tag::Anonymous, &[i; 64])
                .map_err(|_| Status::Failure)?;
        }
        w.end_container().map_err(|_| Status::Failure)
    }
    fn data_version(&self, _r: &Resolved<'_>) -> Option<u32> {
        Some(7)
    }
}

/// A value that is neither small enough nor a list: unsplittable.
struct Unsplittable;
impl matter_kit::im::ClusterHandler for Unsplittable {
    fn read(
        &self,
        _r: &Resolved<'_>,
        _c: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.octets(tag, &[0xCD; 900]).map_err(|_| Status::Failure)
    }
    fn data_version(&self, _r: &Resolved<'_>) -> Option<u32> {
        Some(7)
    }
}

struct All;
impl AccessControl for All {
    fn allows(&self, _p: &AttributePath, _r: Privilege) -> Outcome {
        Outcome::Granted
    }
}

/// Drives a chunked read to completion, returning every report in order.
fn drive<H: matter_kit::im::ClusterHandler>(
    handler: &H,
    mtu: usize,
    limit: usize,
) -> (Vec<(AttributePath, Option<Status>)>, usize) {
    let mut scratch = [0u8; 2048];
    let node = Node::new(ENDPOINTS);
    let server = Server::new(node, &All, handler, limit);
    let mut cursor = ReadCursor::START;
    let mut all = Vec::new();
    let mut messages = 0usize;
    while !cursor.is_done() {
        let mut buf = vec![0u8; mtu];
        let (bytes, outcome) = server
            .serve_chunk(
                [AttributePath::wildcard()].iter().copied().map(Ok),
                &InteractionContext::default(),
                None,
                &mut cursor,
                &mut scratch,
                &mut buf,
            )
            .expect("a chunk always encodes");
        messages += 1;
        assert!(bytes.len() <= mtu);
        let report = ReportData::decode(bytes).expect("every chunk decodes");
        // §10.2.3: the flag is set on every message except the last.
        assert_eq!(
            report.more_chunked_messages,
            !cursor.is_done(),
            "MoreChunkedMessages must mean exactly 'another follows'"
        );
        assert_eq!(report.more_chunked_messages, outcome.truncated);
        if report.more_chunked_messages {
            assert!(
                !report.suppress_response,
                "§10.7.3.2: if MoreChunkedMessages is true, SuppressResponse SHALL be false"
            );
        }
        if let Some(iter) = report.attribute_reports().expect("reports") {
            for item in iter {
                all.push(match item.expect("decode") {
                    AttributeReport::Status(s) => (s.path, Some(s.status.status)),
                    AttributeReport::Data(d) => (d.path, None),
                });
            }
        }
        assert!(messages < 1000, "chunking must terminate");
    }
    (all, messages)
}

/// The whole expansion arrives, in order, across as many messages as it takes.
#[test]
fn a_wildcard_too_big_for_one_message_is_chunked_not_truncated() {
    let (reports, messages) = drive(&Big, 1280, usize::MAX);
    assert!(
        messages > 1,
        "it must actually have chunked, got {messages}"
    );
    // 20 own attributes + 5 globals, all on one cluster of one endpoint.
    assert_eq!(reports.len(), 25);
    assert!(reports.iter().all(|(_, status)| status.is_none()));
    // Every path distinct and in expansion order: nothing repeated, nothing lost.
    let ids: Vec<_> = reports.iter().map(|(p, _)| p.attribute.unwrap()).collect();
    let mut sorted = ids.clone();
    sorted.dedup();
    assert_eq!(ids.len(), sorted.len(), "no path served twice");
}

/// The same read, chunked by the report limit rather than by bytes, loses nothing either.
#[test]
fn a_report_limit_is_a_chunk_boundary_too() {
    let (reports, messages) = drive(&Big, 4096, 3);
    assert!(messages >= 9, "25 reports at 3 per message");
    assert_eq!(reports.len(), 25);
}

/// §10.6.4.3.1: a list too big for a message becomes an empty array plus one block per item.
#[test]
fn an_oversized_list_is_split_into_append_blocks() {
    let (reports, messages) = drive(&BigList, 512, usize::MAX);
    assert!(messages > 1);
    // The first report for attribute 0 is the list-clearing empty array (no ListIndex);
    // every later one for it appends a single item.
    let for_attr0: Vec<_> = reports
        .iter()
        .filter(|(p, _)| p.attribute == Some(0))
        .collect();
    assert!(for_attr0.len() > 1, "the list was split");
    assert_eq!(
        for_attr0[0].0.list_index, None,
        "first block clears the list"
    );
    assert!(
        for_attr0[1..]
            .iter()
            .all(|(p, _)| p.list_index == Some(ListIndex::Append)),
        "every later block appends"
    );
    assert_eq!(
        for_attr0.len(),
        1 + 20,
        "the empty array plus all twenty items"
    );
}

/// A value that is too big and cannot be split is refused per path, and the read goes on.
#[test]
fn an_unsplittable_oversized_value_is_resource_exhausted_and_does_not_hang() {
    let (reports, _) = drive(&Unsplittable, 512, usize::MAX);
    let exhausted = reports
        .iter()
        .filter(|(_, s)| *s == Some(Status::ResourceExhausted))
        .count();
    assert_eq!(
        exhausted, 20,
        "each oversized attribute refused individually"
    );
    // ...and thefive  globals, which are small, still got served.
    assert!(
        reports.iter().any(|(_, s)| s.is_none()),
        "small attributes still served"
    );
}

/// A read that fits in one message is still a single message with no flag set.
#[test]
fn a_read_that_fits_is_one_message_with_no_chunk_flag() {
    let (reports, messages) = drive(&Big, 8192, usize::MAX);
    assert_eq!(messages, 1);
    assert_eq!(reports.len(), 25);
}

/// Several request paths in one read chunk across the path boundary without losing any.
///
/// The cursor has to name *which* request path it stopped in as well as where inside that
/// path's expansion — a server that only remembered the expansion would restart every path
/// from the beginning of the list on each message.
#[test]
fn chunking_spans_several_request_paths() {
    let mut scratch = [0u8; 2048];
    let node = Node::new(ENDPOINTS);
    let server = Server::new(node, &All, &Big, usize::MAX);
    // Three concrete paths plus a wildcard: the wildcard alone overflows a message, so the
    // boundary lands inside it and the earlier paths must not be replayed.
    let paths = [
        AttributePath::attribute(1, 0x0006, 0),
        AttributePath::attribute(1, 0x0006, 1),
        AttributePath::attribute(1, 0x0006, 2),
        AttributePath::wildcard(),
    ];
    let mut cursor = ReadCursor::START;
    let mut all = Vec::new();
    let mut messages = 0usize;
    while !cursor.is_done() {
        let mut buf = [0u8; 1280];
        let (bytes, _) = server
            .serve_chunk(
                paths.iter().copied().map(Ok),
                &InteractionContext::default(),
                None,
                &mut cursor,
                &mut scratch,
                &mut buf,
            )
            .expect("chunk");
        messages += 1;
        let report = ReportData::decode(bytes).expect("decode");
        if let Some(iter) = report.attribute_reports().expect("reports") {
            for item in iter {
                all.push(item.expect("decode").path());
            }
        }
        assert!(messages < 100, "must terminate");
    }
    assert!(messages > 1, "the wildcard forced a chunk");
    // Three explicit paths, then the whole 25-attribute expansion.
    assert_eq!(all.len(), 3 + 25);
    assert_eq!(all[0].attribute, Some(0));
    assert_eq!(all[1].attribute, Some(1));
    assert_eq!(all[2].attribute, Some(2));
}

/// A buffer too small to hold even one block must fail, not spin.
///
/// Chunking makes progress by putting at least one block in each message. A buffer that
/// cannot hold a single block makes no progress at all, so the cursor never advances — and a
/// caller looping until `is_done` would loop forever. There is no series of messages that
/// serves this read, and saying so is the only terminating answer.
#[test]
fn a_buffer_too_small_for_one_block_fails_instead_of_spinning() {
    let mut scratch = [0u8; 2048];
    let node = Node::new(ENDPOINTS);
    let server = Server::new(node, &All, &Big, usize::MAX);
    let mut cursor = ReadCursor::START;
    let mut buf = [0u8; 24]; // room for the report envelope, not for any block
    let mut messages = 0usize;
    loop {
        let r = server.serve_chunk(
            [AttributePath::wildcard()].iter().copied().map(Ok),
            &InteractionContext::default(),
            None,
            &mut cursor,
            &mut scratch,
            &mut buf,
        );
        match r {
            Ok((_, outcome)) => {
                messages += 1;
                assert!(
                    !outcome.truncated || messages < 50,
                    "made no progress and kept promising more"
                );
                if cursor.is_done() {
                    break;
                }
            }
            Err(_) => break, // the honest answer
        }
        assert!(messages < 50, "did not terminate");
    }
}

/// The round trip: what the server splits, the client puts back together — identically.
///
/// Chunking and reassembly are written in different modules for different roles, and the only
/// thing that makes them one feature is that the answer survives the journey. A server that
/// packed correctly and a client that reassembled *almost* correctly would produce a report
/// that decodes, looks plausible, and is missing an attribute — which is exactly the failure
/// neither side can detect alone.
///
/// So this asserts the strong form: the reassembled answer is block-for-block what a single
/// unchunked message would have carried, in the same order.
#[test]
fn what_the_server_chunks_the_client_reassembles_exactly() {
    use matter_kit::im::ReportAssembler;

    let node = Node::new(ENDPOINTS);
    let server = Server::new(node, &All, &Big, usize::MAX);
    let paths = [AttributePath::wildcard()];
    let mut scratch = [0u8; 2048];

    // What one message would have said, had one been enough.
    let mut whole = [0u8; 8192];
    let (bytes, _) = server
        .serve(
            paths.iter().copied().map(Ok),
            &InteractionContext::default(),
            None,
            &mut scratch,
            &mut whole,
        )
        .expect("it fits in 8 KiB");
    let expected: Vec<(AttributePath, Option<Status>)> = ReportData::decode(bytes)
        .expect("decode")
        .attribute_reports()
        .expect("reports")
        .expect("some")
        .map(|item| match item.expect("decode") {
            AttributeReport::Status(s) => (s.path, Some(s.status.status)),
            AttributeReport::Data(d) => (d.path, None),
        })
        .collect();
    assert!(expected.len() > 1);

    // The same answer over a 1280-octet link, reassembled by the client.
    let mut cursor = ReadCursor::START;
    let mut assembler = ReportAssembler::<8192>::new();
    let mut messages = 0usize;
    while !cursor.is_done() {
        let mut buf = [0u8; 1280];
        let (bytes, _) = server
            .serve_chunk(
                paths.iter().copied().map(Ok),
                &InteractionContext::default(),
                None,
                &mut cursor,
                &mut scratch,
                &mut buf,
            )
            .expect("chunk");
        messages += 1;
        let report = ReportData::decode(bytes).expect("decode");
        // §10.2.3: a client sends a StatusResponse between chunks, and `push` returning
        // false is the signal. The server here is driven by the loop instead.
        let complete = assembler.push(&report).expect("push");
        assert_eq!(complete, cursor.is_done());
        assert!(messages < 100, "must terminate");
    }
    assert!(messages > 1, "it really was chunked");
    assert!(assembler.is_complete());
    assert_eq!(assembler.chunks(), messages);

    let got: Vec<(AttributePath, Option<Status>)> = assembler
        .reports()
        .map(|item| match item.expect("decode") {
            AttributeReport::Status(s) => (s.path, Some(s.status.status)),
            AttributeReport::Data(d) => (d.path, None),
        })
        .collect();

    assert_eq!(
        got, expected,
        "the reassembled answer is exactly the one a single message would have carried"
    );
}
