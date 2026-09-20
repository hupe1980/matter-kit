//! One multicast datagram, and a light that turns on (Core §4.16 into §8.8).
//!
//! `tests/groupcast.rs` proves a group datagram can be authenticated; `tests/groupcast_cluster.rs`
//! proves the Groupcast cluster keeps its membership tables. Between them sat the thing a device
//! actually does with a group message, and nothing exercised it — so the crate could authenticate
//! a datagram nobody routed, and every test passed while "turn off all the lights" did nothing.
//!
//! Three rules meet here and each is easy to get right alone and wrong together:
//!
//! * the key is found by **trying** every candidate whose Group Session ID matches (§4.17.3.6),
//!   because a group message names no session;
//! * the subject is the **group**, not a node — §6.6.6.3's Group auth mode, which is why an ACL
//!   entry for a group may never carry Administer;
//! * and the reply is **silence** (§8.7.2.3, §1.3.7.1.2). One multicast to twenty lights that
//!   each answered would put twenty unicast responses on the link at the same instant.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::Cell;

use matter_kit::DefaultConfig;
use matter_kit::acl::{Acl, AclAccess, AuthMode, Entry, SubjectDescriptor};
use matter_kit::clusters::on_off::{self, OnOff, OnOffHooks};
use matter_kit::crypto::SymmetricKey;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::fabric::CompressedFabricId;
use matter_kit::group::keys::{EpochKey, GroupKeySecurityPolicy, GroupKeySet, GroupKeys};
use matter_kit::group::peers::PeerTable;
use matter_kit::group::wire::{self, Received, Sender};
use matter_kit::im::{Dispatcher, InteractionContext, ReadCursor, Request, Served};
use matter_kit::im::{Server, opcode};
use matter_kit::msg::{ExchangeId, FabricIndex, GroupId, NodeId, ProtocolHeader, ProtocolId};
use matter_kit::platform::PeerAddr;
use matter_kit::tlv::{Tag, TlvWriter};

const F1: FabricIndex = FabricIndex(1);
const COMPRESSED: CompressedFabricId = CompressedFabricId(0x87E1_B004_E235_A130);
const LIGHTS: GroupId = GroupId(0x0001);
const SWITCH: NodeId = NodeId(0x0000_0000_0000_AAAA);
const FROM: PeerAddr = PeerAddr::new([0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xAA]);
const EPOCH: [u8; 16] = [
    0x23, 0x5b, 0xf7, 0xe6, 0x28, 0x23, 0xd3, 0x58, 0xdc, 0xa4, 0xba, 0x50, 0xb1, 0x53, 0x5f, 0x4b,
];

#[derive(Debug, Default)]
struct Lamp {
    on: Cell<bool>,
}

impl OnOffHooks for Lamp {
    fn set(&self, on: bool) {
        self.on.set(on);
    }
}

/// The key table a commissioner would have written with `KeySetWrite` and `GroupKeyMapWrite`.
fn keys() -> GroupKeys<DefaultConfig> {
    let mut keys = GroupKeys::new();
    let mut epoch_keys = heapless::Vec::new();
    epoch_keys
        .push(EpochKey {
            key: SymmetricKey::new(EPOCH),
            start_time_us: 1,
        })
        .unwrap();
    keys.write_key_set(GroupKeySet {
        fabric_index: F1,
        id: 7,
        policy: GroupKeySecurityPolicy::TrustFirst,
        epoch_keys,
    })
    .unwrap();
    keys.map_group(F1, LIGHTS, 7).unwrap();
    keys
}

/// An `InvokeRequest` carrying one command and nothing else.
fn invoke(command: u32) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap();
    w.bool(Tag::Context(0), false).unwrap(); // SuppressResponse
    w.bool(Tag::Context(1), false).unwrap(); // TimedRequest
    w.start_array(Tag::Context(2)).unwrap(); // InvokeRequests
    w.start_structure(Tag::Anonymous).unwrap();
    w.start_list(Tag::Context(0)).unwrap(); // CommandPathIB
    w.unsigned(Tag::Context(0), 1).unwrap(); // Endpoint
    w.unsigned(Tag::Context(1), u64::from(on_off::ID)).unwrap();
    w.unsigned(Tag::Context(2), u64::from(command)).unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    // §10.7.1's InteractionModelRevision, which every action message carries.
    w.unsigned(
        Tag::Context(0xFF),
        u64::from(matter_kit::im::INTERACTION_MODEL_REVISION),
    )
    .unwrap();
    w.end_container().unwrap();
    let n = w.finish().unwrap().len();
    buf[..n].to_vec()
}

/// The whole path: a switch multicasts `On`, and the light is on and has said nothing.
#[test]
fn a_multicast_invoke_reaches_the_cluster_and_is_answered_with_silence() {
    let keys = keys();
    let mut peers: PeerTable<4, 2> = PeerTable::new();

    // The switch sends one datagram to the group.
    let mut sender = Sender::new(SWITCH, 1, 1);
    let key = keys
        .sending_key(F1, COMPRESSED, LIGHTS, None)
        .expect("a key for the group");
    let header = ProtocolHeader {
        initiator: true,
        acknowledged_counter: None,
        // §4.16: never reliable. Twenty lights acknowledging one multicast is the failure.
        reliability: false,
        exchange_id: ExchangeId(0x1234),
        protocol: ProtocolId::INTERACTION_MODEL,
        opcode: opcode::INVOKE_REQUEST,
    };
    let body = invoke(on_off::ON);
    let (mut scratch, mut datagram) = ([0u8; 1280], [0u8; 1280]);
    let n = sender
        .send(
            &key,
            LIGHTS,
            &header,
            &body,
            false,
            &mut scratch,
            &mut datagram,
        )
        .expect("send");

    // The light: §4.17.3.6's candidate scan, with no session anywhere in it.
    let mut original = [0u8; 1280];
    let received = wire::receive(
        &mut datagram[..n],
        FROM,
        &keys,
        &mut peers,
        |_| Some(COMPRESSED),
        &mut original,
    )
    .expect("the light holds the key");
    let Received::Message(message) = received else {
        panic!("expected a message, got {received:?}");
    };
    assert_eq!(message.context.group, LIGHTS);
    assert_eq!(message.context.source, SWITCH);

    // What a device does next: dispatch it as a groupcast, with the group as the subject.
    let lamp = Lamp::default();
    let cluster = OnOff::new(&lamp, on_off::feature::LIGHTING, None);
    let conforming =
        OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE).expect("descriptor");
    let clusters: [ClusterDescriptor<'_>; 1] = [conforming.descriptor()];
    let endpoints = [Endpoint::new(1, &clusters)];
    let node = Node::new(&endpoints);

    let acl_cell: core::cell::RefCell<Acl<DefaultConfig, 20, 4, 3>> =
        core::cell::RefCell::new(Acl::new());
    // §9.10.5.7: a Group entry may never carry Administer — a shared key administering a node
    // would be an administrator with no attribution.
    let mut subjects = heapless::Vec::new();
    subjects.push(NodeId(u64::from(LIGHTS.0))).unwrap();
    acl_cell
        .borrow_mut()
        .add(Entry {
            fabric_index: F1,
            privilege: Privilege::Operate,
            auth_mode: AuthMode::Group,
            subjects,
            targets: heapless::Vec::new(),
        })
        .expect("room for an entry");

    // §6.6.6.3: the subject is the *group*, not a node — the message proves possession of a
    // shared key and nothing about who sent it.
    let subject = SubjectDescriptor::group(message.context.fabric_index, message.context.group);
    let access = AclAccess::new(&acl_cell, node, &subject);
    let server = Server::new(node, &access, &cluster, 8);
    let ctx = InteractionContext::new()
        .with_fabric(message.context.fabric_index)
        .with_group(message.context.group);
    let mut dispatcher: Dispatcher<4> = Dispatcher::new(1);
    let mut cursor = ReadCursor::START;
    let (mut scratch, mut payload) = ([0u8; 1024], [0u8; 1024]);

    let served = dispatcher
        .dispatch(
            &server,
            Request {
                opcode: message.protocol.opcode,
                payload: message.payload,
                session: None,
                exchange: message.protocol.exchange_id,
                groupcast: true,
            },
            &ctx,
            &mut cursor,
            &mut scratch,
            &mut payload,
        )
        .expect("dispatch");

    assert!(
        matches!(served, Served::Silent),
        "§1.3.7.1.2: a groupcast is acted on and never answered — got {served:?}"
    );
    assert!(lamp.on.get(), "the light is on");
}

/// The same datagram, from a fabric whose ACL grants the group nothing.
#[test]
fn a_group_with_no_grant_changes_nothing_and_still_says_nothing() {
    let keys = keys();
    let mut peers: PeerTable<4, 2> = PeerTable::new();
    let mut sender = Sender::new(SWITCH, 1, 1);
    let key = keys.sending_key(F1, COMPRESSED, LIGHTS, None).unwrap();
    let header = ProtocolHeader {
        initiator: true,
        acknowledged_counter: None,
        reliability: false,
        exchange_id: ExchangeId(0x1234),
        protocol: ProtocolId::INTERACTION_MODEL,
        opcode: opcode::INVOKE_REQUEST,
    };
    let body = invoke(on_off::ON);
    let (mut scratch, mut datagram) = ([0u8; 1280], [0u8; 1280]);
    let n = sender
        .send(
            &key,
            LIGHTS,
            &header,
            &body,
            false,
            &mut scratch,
            &mut datagram,
        )
        .unwrap();
    let mut original = [0u8; 1280];
    let Received::Message(message) = wire::receive(
        &mut datagram[..n],
        FROM,
        &keys,
        &mut peers,
        |_| Some(COMPRESSED),
        &mut original,
    )
    .unwrap() else {
        panic!("expected a message");
    };

    let lamp = Lamp::default();
    let cluster = OnOff::new(&lamp, on_off::feature::LIGHTING, None);
    let conforming =
        OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE).expect("descriptor");
    let clusters: [ClusterDescriptor<'_>; 1] = [conforming.descriptor()];
    let endpoints = [Endpoint::new(1, &clusters)];
    let node = Node::new(&endpoints);

    // An empty list: the group is a member of nothing it may operate.
    let acl_cell: core::cell::RefCell<Acl<DefaultConfig, 20, 4, 3>> =
        core::cell::RefCell::new(Acl::new());
    let subject = SubjectDescriptor::group(message.context.fabric_index, message.context.group);
    let access = AclAccess::new(&acl_cell, node, &subject);
    let server = Server::new(node, &access, &cluster, 8);
    let ctx = InteractionContext::new()
        .with_fabric(message.context.fabric_index)
        .with_group(message.context.group);
    let mut dispatcher: Dispatcher<4> = Dispatcher::new(1);
    let mut cursor = ReadCursor::START;
    let (mut scratch, mut payload) = ([0u8; 1024], [0u8; 1024]);

    let served = dispatcher
        .dispatch(
            &server,
            Request {
                opcode: message.protocol.opcode,
                payload: message.payload,
                session: None,
                exchange: message.protocol.exchange_id,
                groupcast: true,
            },
            &ctx,
            &mut cursor,
            &mut scratch,
            &mut payload,
        )
        .expect("dispatch");

    assert!(
        matches!(served, Served::Silent),
        "a refused groupcast is refused silently: a status back to the sender would tell an \
         eavesdropper which nodes hold which grants"
    );
    assert!(!lamp.on.get(), "and nothing happened");
}
