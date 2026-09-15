//! The Access Control cluster against arbitrary writes, and the list against arbitrary reads.
//!
//! This is the cluster that decides what every other cluster will allow, so its failure mode
//! is not a crash — it is a *quiet* grant. The interesting properties are all of the form
//! "no sequence of bytes produces a list that grants more than it should", and none of them
//! are visible in a test that writes well-formed entries.
//!
//! Seven properties:
//!
//! 1. **Nothing panics**, whatever an administrator writes into the `ACL` attribute.
//! 2. **No arbitrary input ever reaches another fabric.** Everything is written as fabric 1;
//!    a subject on fabric 2 must be granted nothing, ever. This is the isolation that stops a
//!    second administrator taking the node from the first.
//! 3. **A PASE entry never enters the list.** §6.6.2.1 forbids one, because the commissioner's
//!    grant is implicit and must not outlive the session that justified it.
//! 4. **A Group entry never holds Administer.** §9.10.5.7: a shared key has no per-node
//!    attribution, so administering with one leaves no record of who acted.
//! 5. **No entry is ever stored on fabric 0**, which §6.6.6.2 treats as naming no fabric.
//! 6. **The per-fabric quota holds**, so one administrator cannot exhaust the table and lock
//!    every other one out (§9.10.6.3, §2.11.1.1).
//! 7. **What the list holds reads back as decodable TLV** — a report a client cannot parse
//!    would be worse than a refusal.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::acl::{Acl, AuthMode, SubjectDescriptor};
use matter_kit::clusters::access_control::{self, AccessControl};
use matter_kit::config::{Config, DefaultConfig};
use matter_kit::dm::{
    AttributeDescriptor, ClusterDescriptor, CommandDescriptor, DeviceType, Endpoint, Node,
    Privilege, Resolved,
};
use matter_kit::im::{ClusterHandler, InteractionContext, WriteOp};
use matter_kit::msg::{FabricIndex, NodeId};
use matter_kit::tlv::{Tag, TlvReader, TlvWriter};

const ENTRIES: usize = DefaultConfig::ACL_ENTRIES;
const SUBJECTS: usize = DefaultConfig::ACL_SUBJECTS;
const TARGETS: usize = DefaultConfig::ACL_TARGETS;

type FuzzAcl = Acl<DefaultConfig, ENTRIES, SUBJECTS, TARGETS>;

const ON_OFF: u32 = 0x0006;
const ON_OFF_ATTRS: &[AttributeDescriptor] = &[AttributeDescriptor::read_write(0x0000)];
const NO_CMDS: &[CommandDescriptor] = &[];

const fn plain(id: u32, attributes: &'static [AttributeDescriptor]) -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id,
        revision: 1,
        feature_map: 0,
        attributes,
        accepted_commands: NO_CMDS,
        generated_commands: &[],
        events: &[],
    }
}

const EP0: &[ClusterDescriptor<'static>] = &[access_control::cluster()];
const EP1: &[ClusterDescriptor<'static>] = &[plain(ON_OFF, ON_OFF_ATTRS)];
const LIGHT: &[DeviceType] = &[DeviceType::new(0x0100, 1)];
const ENDPOINTS: &[Endpoint<'static>] = &[
    Endpoint::new(0, EP0),
    Endpoint::new(1, EP1).with_device_types(LIGHT),
];

/// The cluster descriptor the writes are resolved against.
const AC_CLUSTER: ClusterDescriptor<'static> = access_control::cluster();

/// The fabric everything is written as. Nothing may ever reach any other.
const WRITER: FabricIndex = FabricIndex(1);
/// A fabric that writes nothing and must therefore be granted nothing.
const OTHER: FabricIndex = FabricIndex(2);

fuzz_target!(|data: &[u8]| {
    let node = Node::new(ENDPOINTS);
    let acl = core::cell::RefCell::new(FuzzAcl::new());
    let cluster = AccessControl::<DefaultConfig, ENTRIES, SUBJECTS, TARGETS>::new(&acl);

    let ctx = InteractionContext::new().with_fabric(WRITER);
    let resolved = Resolved {
        endpoint: 0,
        cluster: &AC_CLUSTER,
        attribute: access_control::ACL,
    };

    // The fuzzer's bytes are offered both as a whole-list replace and as an append, because
    // the two take different paths through the decoder and only one of them is bounded by the
    // quota. Every chunk of the input is offered in turn, so one input drives many writes.
    for chunk in data.chunks(64) {
        for op in [WriteOp::Replace, WriteOp::Append] {
            let _ = cluster.write(&resolved, chunk, op, &ctx);

            let list = acl.borrow();
            for entry in list.entries() {
                // Property 3 and 4.
                assert_ne!(
                    entry.auth_mode,
                    AuthMode::Pase,
                    "§6.6.2.1: a PASE entry must never enter the list"
                );
                assert!(
                    !(entry.auth_mode == AuthMode::Group
                        && entry.privilege == Privilege::Administer),
                    "§9.10.5.7: a Group entry must never hold Administer"
                );
                // Property 5.
                assert_ne!(entry.fabric_index.0, 0, "no entry names fabric 0");
                // Property 2, at the table: nothing lands on another fabric.
                assert_eq!(
                    entry.fabric_index, WRITER,
                    "a write as one fabric must not create an entry on another"
                );
            }
            // Property 6.
            assert!(
                list.len_of_fabric(WRITER) <= DefaultConfig::ACL_ENTRIES_PER_FABRIC,
                "the per-fabric quota must hold"
            );
            drop(list);

            // Property 2, at the decision: a subject on another fabric is granted nothing, on
            // any endpoint or cluster this node has.
            let stranger = SubjectDescriptor::case(OTHER, NodeId(0xDEAD_BEEF));
            for (endpoint, cluster_id) in [(0u16, access_control::ID), (1, ON_OFF)] {
                assert!(
                    acl.borrow()
                        .granted(&node, &stranger, endpoint, cluster_id)
                        .is_empty(),
                    "another fabric's subject must never be granted anything"
                );
            }

            // A PASE session that is not commissioning has no standing either, whatever the
            // list says — the implicit grant of §6.6.6.2 is conditional on both.
            let mut idle_pase = SubjectDescriptor::commissioning();
            idle_pase.is_commissioning = false;
            assert!(
                acl.borrow()
                    .granted(&node, &idle_pase, 1, ON_OFF)
                    .is_empty(),
                "a PASE session that is not commissioning grants nothing"
            );

            // Property 7: whatever the list now holds, a read of it is TLV a client can parse.
            let mut buf = [0u8; 4096];
            let mut w = TlvWriter::new(&mut buf);
            if cluster
                .read(&resolved, &ctx, &mut w, Tag::Anonymous)
                .is_ok()
            {
                let bytes = w.finish().expect("a completed read is a complete encoding");
                TlvReader::validate(bytes).expect("a served ACL must decode");
            }
        }
    }

    // Whatever happened above, a fabric with no entries of its own still grants nothing.
    let empty_fabric = SubjectDescriptor::case(FabricIndex(7), NodeId(1));
    assert!(
        acl.borrow()
            .granted(&node, &empty_fabric, 1, ON_OFF)
            .is_empty()
    );
});
