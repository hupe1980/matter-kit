//! Chunking a report across messages, against attacker-chosen values and message sizes.
//!
//! §10.2.3 splits a report "into multiple messages at logical boundaries due to the size
//! limitations imposed by IPv6 for UDP packets". Getting that wrong is not a parsing bug — it
//! is a liveness bug, and the two ways to fail are both invisible to a unit test that happens
//! to pick convenient sizes:
//!
//! * A message that sets `MoreChunkedMessages` and is never followed leaves the client waiting
//!   forever. The flag is a promise.
//! * A boundary that makes no progress — a value that never fits, retried each message —
//!   loops until the device is reset.
//!
//! Both are decided by the size of the values a *cluster* produces and the buffer a caller
//! supplies, which is exactly what a fuzzer can choose better than an author can.
//!
//! Five properties:
//!
//! 1. **Nothing panics**, whatever the value sizes and whatever the message budget.
//! 2. **It terminates.** The loop ends in a bounded number of messages, for every input.
//! 3. **Every message decodes** as a `ReportData` and fits the budget it was given.
//! 4. **The flag means what it says**: `MoreChunkedMessages` is set on exactly the messages
//!    that are not the last, and §10.7.3.2's "if MoreChunkedMessages is true, SuppressResponse
//!    SHALL be false" holds.
//! 5. **Chunking is lossless and duplicate-free.** The concatenation of every chunk carries
//!    each expanded path exactly once — except a split list, which is one clearing block
//!    followed by its items.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::dm::{
    AttributeDescriptor, ClusterDescriptor, CommandDescriptor, Endpoint, Node, Privilege, Resolved,
};
use matter_kit::im::{
    AccessControl, AttributePath, AttributeReport, InteractionContext, ListIndex, Outcome,
    ReadCursor, ReportData, Server, Status,
};
use matter_kit::tlv::{Tag, TlvWriter};

const ATTRS: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_only(0x0000),
    AttributeDescriptor::read_only(0x0001),
    AttributeDescriptor::read_only(0x0002),
    AttributeDescriptor::read_only(0x0003),
];
const NO_CMDS: &[CommandDescriptor] = &[];

const fn cluster(id: u32) -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id,
        revision: 3,
        feature_map: 0,
        attributes: ATTRS,
        accepted_commands: NO_CMDS,
        generated_commands: &[],
        events: &[],
    }
}

const EP0: &[ClusterDescriptor<'static>] = &[cluster(0x0006), cluster(0x0008)];
const EP1: &[ClusterDescriptor<'static>] = &[cluster(0x0028)];
const ENDPOINTS: &[Endpoint<'static>] = &[
    Endpoint::new(0, EP0),
    Endpoint::new(1, EP1),
];

struct All;
impl AccessControl for All {
    fn allows(&self, _p: &AttributePath, _r: Privilege) -> Outcome {
        Outcome::Granted
    }
}

/// A cluster whose value shape and size the fuzzer chooses, per attribute.
struct Fuzzed<'a> {
    shape: &'a [u8],
}

impl Fuzzed<'_> {
    /// The value for one attribute: a scalar, an octet string, or a list, of a chosen size.
    fn plan(&self, resolved: &Resolved<'_>) -> (u8, usize) {
        let key = (resolved.endpoint as usize)
            .wrapping_mul(31)
            .wrapping_add(resolved.cluster.id as usize)
            .wrapping_mul(31)
            .wrapping_add(resolved.attribute as usize);
        let a = self.shape.get(key % self.shape.len().max(1)).copied().unwrap_or(0);
        let b = self
            .shape
            .get((key.wrapping_add(1)) % self.shape.len().max(1))
            .copied()
            .unwrap_or(0);
        // Sizes up to ~1 kB, which straddles a 1280-octet message in both directions.
        (a % 3, (b as usize) * 4)
    }
}

impl matter_kit::im::ClusterHandler for Fuzzed<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _c: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let (shape, size) = self.plan(resolved);
        match shape {
            0 => w.unsigned(tag, size as u64).map_err(|_| Status::Failure),
            1 => {
                let buf = [0xABu8; 1024];
                let n = size.min(buf.len());
                w.octets(tag, &buf[..n]).map_err(|_| Status::Failure)
            }
            _ => {
                // A list of `size / 32` items, each 32 octets: the case §10.6.4.3.1 splits.
                w.start_array(tag).map_err(|_| Status::Failure)?;
                for i in 0..(size / 32).min(40) {
                    w.octets(Tag::Anonymous, &[i as u8; 32])
                        .map_err(|_| Status::Failure)?;
                }
                w.end_container().map_err(|_| Status::Failure)
            }
        }
    }

    fn data_version(&self, _r: &Resolved<'_>) -> Option<u32> {
        Some(7)
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&budget, shape)) = data.split_first() else {
        return;
    };
    if shape.is_empty() {
        return;
    }
    // A message budget from 64 octets up to well past the 1280-octet IPv6 minimum.
    let mtu = 64 + (budget as usize) * 8;
    let mut buf = [0u8; 2112];
    let Some(buf) = buf.get_mut(..mtu.min(2112)) else {
        return;
    };
    let budget = buf.len();
    let mut scratch = [0u8; 4096];

    let handler = Fuzzed { shape };
    let server = Server::new(Node::new(ENDPOINTS), &All, &handler, usize::MAX);
    let paths = [AttributePath::wildcard()];

    let mut cursor = ReadCursor::START;
    let mut seen: Vec<(AttributePath, bool)> = Vec::new();
    let mut messages = 0usize;

    while !cursor.is_done() {
        let Ok((bytes, outcome)) = server.serve_chunk(
            paths.iter().copied().map(Ok),
            &InteractionContext::default(),
            None,
            &mut cursor,
            &mut scratch,
            buf,
        ) else {
            // A buffer too small to hold even an empty report is a legitimate refusal.
            return;
        };
        messages += 1;
        // Property 2: the loop is bounded. The node has 3 cluster instances of 9 attributes
        // each; even split item-by-item that cannot need thousands of messages.
        assert!(messages < 2000, "chunking did not terminate");

        // Property 3.
        assert!(bytes.len() <= budget);
        let report = ReportData::decode(bytes).expect("every chunk must decode");

        // Property 4.
        assert_eq!(
            report.more_chunked_messages,
            !cursor.is_done(),
            "MoreChunkedMessages must mean exactly 'another message follows'"
        );
        assert_eq!(report.more_chunked_messages, outcome.truncated);
        if report.more_chunked_messages {
            assert!(
                !report.suppress_response,
                "§10.7.3.2: MoreChunkedMessages true requires SuppressResponse false"
            );
        }

        if let Some(iter) = report.attribute_reports().expect("reports") {
            for item in iter {
                let item = item.expect("every block in a chunk we wrote must decode");
                let path = item.path();
                assert!(
                    !path.has_wildcard(),
                    "§8.4.3.2: every reported path is concrete"
                );
                let appended = path.list_index == Some(ListIndex::Append);
                if let AttributeReport::Status(s) = item {
                    // The only status this node can produce is the refusal of a value too
                    // large to split at all.
                    assert_eq!(s.status.status, Status::ResourceExhausted);
                }
                seen.push((path, appended));
            }
        }
    }

    // Property 5: no path reported twice, except the append blocks of a split list, which
    // legitimately repeat their path.
    let mut heads: Vec<AttributePath> = seen
        .iter()
        .filter(|(_, appended)| !appended)
        .map(|(p, _)| *p)
        .collect();
    let before = heads.len();
    heads.sort_by_key(|p| (p.endpoint, p.cluster, p.attribute));
    heads.dedup_by_key(|p| (p.endpoint, p.cluster, p.attribute));
    assert_eq!(before, heads.len(), "a path was reported twice");

    // Every expanded path the node holds was reported exactly once.
    let expected = Node::new(ENDPOINTS)
        .expand(&AttributePath::wildcard())
        .count();
    assert_eq!(before, expected, "chunking lost or invented a path");
});
