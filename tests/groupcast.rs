//! Group communication end to end (Core §4.16, §4.17, §4.18).
//!
//! One switch, two lights, one multicast datagram. Everything a unicast session gives for free
//! has to be rebuilt here, and each of the three rebuilt pieces has a way of going wrong that
//! nothing else would catch:
//!
//! * **The key is found by trying, not by looking up.** §4.17.3.6's Group Session ID narrows the
//!   candidates and no more: "It SHALL NOT be used as the sole means to locate the associated
//!   Operational Group Key, since it MAY collide within the fabric." So this file *constructs* a
//!   collision and checks the right key still wins.
//! * **Freshness has no handshake.** §4.18's peer table is the only replay protection a group
//!   message has, and §4.16.1 forbids recycling it.
//! * **Keys go in and do not come back.** §11.2.7.2 replaces the epoch keys with null in every
//!   read, and a device that echoed them would hand the group away to any administrator.

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

use matter_kit::DefaultConfig;
use matter_kit::crypto::SymmetricKey;
use matter_kit::fabric::{CompressedFabricId, operational_group_key};
use matter_kit::group::keys::{EpochKey, GroupKeySecurityPolicy, GroupKeySet, GroupKeys};
use matter_kit::group::peers::{Admitted, PeerTable};
use matter_kit::group::wire::{self, Received, Sender};
use matter_kit::group::{self, mcsp};
use matter_kit::msg::{FabricIndex, GroupId, NodeId, ProtocolHeader, ProtocolId};
use matter_kit::platform::PeerAddr;

const F1: FabricIndex = FabricIndex(1);
const F2: FabricIndex = FabricIndex(2);
const COMPRESSED: CompressedFabricId = CompressedFabricId(0x87E1_B004_E235_A130);
const LIGHTS: GroupId = GroupId(0x0001);
const SWITCH: NodeId = NodeId(0x0000_0000_0000_AAAA);
const FROM: PeerAddr = PeerAddr::new([0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xAA]);

type Keys = GroupKeys<DefaultConfig>;
type Peers = PeerTable<4, 2>;

fn compressed(_: FabricIndex) -> Option<CompressedFabricId> {
    Some(COMPRESSED)
}

/// A key table with one key set holding one epoch key, mapped to the lights group.
fn table(key: [u8; 16], policy: GroupKeySecurityPolicy) -> Keys {
    let mut keys = Keys::new();
    let mut epoch_keys = heapless::Vec::new();
    epoch_keys
        .push(EpochKey {
            key: SymmetricKey::new(key),
            start_time_us: 1,
        })
        .unwrap();
    keys.write_key_set(GroupKeySet {
        fabric_index: F1,
        id: 7,
        policy,
        epoch_keys,
    })
    .unwrap();
    keys.map_group(F1, LIGHTS, 7).unwrap();
    keys
}

const EPOCH: [u8; 16] = [
    0x23, 0x5b, 0xf7, 0xe6, 0x28, 0x23, 0xd3, 0x58, 0xdc, 0xa4, 0xba, 0x50, 0xb1, 0x53, 0x5f, 0x4b,
];

fn on_command() -> ProtocolHeader {
    ProtocolHeader {
        initiator: true,
        acknowledged_counter: None,
        // §4.16: a group message is never reliable — there is nobody in particular to
        // acknowledge it, and twenty lights acknowledging one multicast is the failure mode.
        reliability: false,
        exchange_id: matter_kit::msg::ExchangeId(0x1234),
        protocol: ProtocolId::INTERACTION_MODEL,
        opcode: 0x08, // InvokeRequest
    }
}

/// Sends one group message and returns the datagram.
fn send(sender: &mut Sender, keys: &Keys, payload: &[u8], control: bool) -> Vec<u8> {
    let key = keys
        .sending_key(F1, COMPRESSED, LIGHTS, None)
        .expect("a key for the group");
    let mut scratch = [0u8; 1280];
    let mut out = [0u8; 1280];
    let n = sender
        .send(
            &key,
            LIGHTS,
            &on_command(),
            payload,
            control,
            &mut scratch,
            &mut out,
        )
        .expect("send");
    out[..n].to_vec()
}

// --- §4.16: one message, many nodes ------------------------------------------------------

#[test]
fn one_datagram_reaches_every_member_of_the_group() {
    let keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let mut sender = Sender::restore(SWITCH, 1000, 5000);
    let datagram = send(&mut sender, &keys, b"turn on", false);

    // Two lights, each with its own peer table, both holding the same epoch key.
    for _ in 0..2 {
        let light_keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
        let mut peers = Peers::new();
        let mut buf = datagram.clone();
        let mut scratch = [0u8; 1280];
        let received = wire::receive(
            &mut buf,
            FROM,
            &light_keys,
            &mut peers,
            compressed,
            &mut scratch,
        )
        .expect("receive");
        let Received::Message(inbound) = received else {
            panic!("expected a message");
        };
        assert_eq!(inbound.payload, b"turn on");
        // §4.16.1's Groupcast Session Context: fabric, group and source together.
        assert_eq!(inbound.context.fabric_index, F1);
        assert_eq!(inbound.context.group, LIGHTS);
        assert_eq!(inbound.context.source, SWITCH);
        assert_eq!(inbound.context.from, FROM);
        assert_eq!(inbound.context.key_set, 7);
        assert_eq!(inbound.protocol.opcode, 0x08);
        assert!(!inbound.protocol.reliability, "no MRP on a multicast");
    }
}

#[test]
fn a_node_without_the_epoch_key_learns_nothing() {
    // Group membership *is* possession of the epoch key (§4.17.1). A node on the same fabric,
    // listening to the same multicast address, with a different key set gets nothing.
    let keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let mut sender = Sender::restore(SWITCH, 1000, 5000);
    let mut datagram = send(&mut sender, &keys, b"turn on", false);

    let outsider = table([0xAA; 16], GroupKeySecurityPolicy::TrustFirst);
    let mut peers = Peers::new();
    let mut scratch = [0u8; 1280];
    assert!(
        wire::receive(
            &mut datagram,
            FROM,
            &outsider,
            &mut peers,
            compressed,
            &mut scratch
        )
        .is_err()
    );
}

#[test]
fn a_replayed_datagram_is_refused() {
    // §4.18 is the only replay protection a group message has: there is no session, so there is
    // no session counter.
    let keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let mut sender = Sender::restore(SWITCH, 1000, 5000);
    let datagram = send(&mut sender, &keys, b"unlock", false);

    let mut peers = Peers::new();
    let mut scratch = [0u8; 1280];
    let mut first = datagram.clone();
    assert!(matches!(
        wire::receive(
            &mut first,
            FROM,
            &keys,
            &mut peers,
            compressed,
            &mut scratch
        )
        .unwrap(),
        Received::Message(_)
    ));
    let mut again = datagram;
    assert!(matches!(
        wire::receive(
            &mut again,
            FROM,
            &keys,
            &mut peers,
            compressed,
            &mut scratch
        )
        .unwrap(),
        Received::Duplicate(_)
    ));
}

#[test]
fn a_unicast_message_is_not_taken_by_the_group_path() {
    // The group path skips the session lookup that binds a unicast message to a peer, so a
    // message that is not of Group Session Type has to be refused rather than processed.
    let keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let mut peers = Peers::new();
    let mut scratch = [0u8; 1280];
    // An unsecured unicast header: flags 0, session id 0, security flags 0.
    let mut unicast = [0u8; 32];
    unicast[0] = 0x00;
    assert!(
        wire::receive(
            &mut unicast,
            FROM,
            &keys,
            &mut peers,
            compressed,
            &mut scratch
        )
        .is_err()
    );
}

// --- §4.17.3.6: the session id narrows, it does not decide --------------------------------

/// Finds an epoch key whose operational key has the same Group Session ID as `target`.
///
/// Sixteen bits, so a search over a counter finds one in about 65 536 tries — which is the
/// point: a collision is not exotic, it is expected roughly once per 65 536 keys in a fabric.
fn colliding_epoch_key(target: u16) -> Option<[u8; 16]> {
    for i in 0u32..200_000 {
        let mut candidate = [0u8; 16];
        candidate[..4].copy_from_slice(&i.to_le_bytes());
        candidate[4] = 0xC0;
        let operational =
            operational_group_key(&SymmetricKey::new(candidate), COMPRESSED).expect("kdf");
        if group::session_id(&operational).expect("kdf") == target {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn a_colliding_session_id_does_not_decide_the_key() {
    // §4.17.3.6: "On receipt of a message of Group Session Type, all valid, installed,
    // operational group key candidates referenced by the given Group Session ID SHALL be
    // attempted until authentication is passed or there are no more operational group keys to
    // try. This is done because the same Group Session ID might arise from different keys."
    //
    // A receiver that stopped at the first candidate would drop one group's traffic entirely
    // whenever two of its keys happened to collide — and which group would depend on the order
    // the administrator installed them in.
    let real = operational_group_key(&SymmetricKey::new(EPOCH), COMPRESSED).unwrap();
    let target = group::session_id(&real).unwrap();
    let decoy = colliding_epoch_key(target).expect("a 16-bit space has collisions");
    assert_ne!(decoy, EPOCH);

    // The sender uses the real key; the receiver holds the decoy *first*, so the first candidate
    // it tries is the wrong one.
    let sender_keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let mut sender = Sender::restore(SWITCH, 1000, 5000);
    let mut datagram = send(&mut sender, &sender_keys, b"turn on", false);

    let mut receiver_keys = Keys::new();
    for (id, key) in [(3u16, decoy), (7, EPOCH)] {
        let mut epoch_keys = heapless::Vec::new();
        epoch_keys
            .push(EpochKey {
                key: SymmetricKey::new(key),
                start_time_us: 1,
            })
            .unwrap();
        receiver_keys
            .write_key_set(GroupKeySet {
                fabric_index: F1,
                id,
                policy: GroupKeySecurityPolicy::TrustFirst,
                epoch_keys,
            })
            .unwrap();
    }
    receiver_keys.map_group(F1, LIGHTS, 7).unwrap();

    // Both are candidates for the same session id.
    assert_eq!(
        receiver_keys.receiving_keys::<8>(compressed, target).len(),
        2
    );

    let mut peers = Peers::new();
    let mut scratch = [0u8; 1280];
    let received = wire::receive(
        &mut datagram,
        FROM,
        &receiver_keys,
        &mut peers,
        compressed,
        &mut scratch,
    )
    .expect("the second candidate authenticates");
    let Received::Message(inbound) = received else {
        panic!("expected a message");
    };
    assert_eq!(inbound.payload, b"turn on");
    assert_eq!(
        inbound.context.key_set, 7,
        "the key that actually decrypted"
    );
}

// --- §4.18: synchronising a counter -------------------------------------------------------

#[test]
fn cache_and_sync_holds_the_message_until_mcsp_completes() {
    // §4.18.1.2: "The message that triggers message counter synchronization is stored, a message
    // counter synchronization exchange is initiated, and only when the synchronization is
    // completed is the original message processed."
    let keys = table(EPOCH, GroupKeySecurityPolicy::CacheAndSync);
    let mut sender = Sender::restore(SWITCH, 1000, 5000);
    let datagram = send(&mut sender, &keys, b"unlock", false);

    let mut peers = Peers::new();
    let mut scratch = [0u8; 1280];
    let mut held = datagram.clone();
    let Received::NeedsSync(context) =
        wire::receive(&mut held, FROM, &keys, &mut peers, compressed, &mut scratch).unwrap()
    else {
        panic!("cache-and-sync holds the first message");
    };
    assert_eq!(context.source, SWITCH);

    // The sync exchange: a challenge out, the sender's current counter back.
    let request = mcsp::SyncRequest {
        challenge: [0x11; 8],
    };
    let response = mcsp::SyncResponse {
        counter: 1000,
        response: request.challenge,
    };
    assert!(response.answers(&request));
    assert!(peers.synchronize(context.fabric_index, context.source, response.counter));

    // The held message was counter 1000, which is now a duplicate of what was synchronised —
    // exactly right: the receiver knows it has seen everything up to and including it.
    let mut replay = datagram;
    assert!(matches!(
        wire::receive(
            &mut replay,
            FROM,
            &keys,
            &mut peers,
            compressed,
            &mut scratch
        )
        .unwrap(),
        Received::Duplicate(_)
    ));

    // And the next message is processed without another round trip.
    let next = send(&mut sender, &keys, b"lock", false);
    let mut next = next;
    assert!(matches!(
        wire::receive(&mut next, FROM, &keys, &mut peers, compressed, &mut scratch).unwrap(),
        Received::Message(_)
    ));
}

#[test]
fn a_control_message_never_waits_for_mcsp() {
    // §4.18.1.1: "All control messages (any message with C Flag set) use the control message
    // counter and SHALL use Trust-first for synchronization." MCSP's own two messages are
    // control messages, so a control message that waited for MCSP would wait for itself.
    let keys = table(EPOCH, GroupKeySecurityPolicy::CacheAndSync);
    let mut sender = Sender::restore(SWITCH, 1000, 5000);
    let mut datagram = send(&mut sender, &keys, b"sync", true);

    let mut peers = Peers::new();
    let mut scratch = [0u8; 1280];
    let received = wire::receive(
        &mut datagram,
        FROM,
        &keys,
        &mut peers,
        compressed,
        &mut scratch,
    )
    .unwrap();
    assert!(matches!(received, Received::Message(_)));
    let Received::Message(inbound) = received else {
        unreachable!()
    };
    assert!(inbound.control);
}

#[test]
fn a_full_peer_table_drops_rather_than_recycles() {
    // §4.16.1: "Any message from a source that cannot be tracked SHALL be dropped." Evicting an
    // entry would let an attacker exhaust the table and then replay the evicted peer's traffic.
    let keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let mut peers = PeerTable::<1, 1>::new();
    let mut scratch = [0u8; 1280];

    let mut first = Sender::restore(NodeId(1), 10, 10);
    let mut datagram = send(&mut first, &keys, b"a", false);
    assert!(matches!(
        wire::receive(
            &mut datagram,
            FROM,
            &keys,
            &mut peers,
            compressed,
            &mut scratch
        )
        .unwrap(),
        Received::Message(_)
    ));

    let mut second = Sender::restore(NodeId(2), 10, 10);
    let mut datagram = send(&mut second, &keys, b"b", false);
    assert!(matches!(
        wire::receive(
            &mut datagram,
            FROM,
            &keys,
            &mut peers,
            compressed,
            &mut scratch
        )
        .unwrap(),
        Received::Untracked(_)
    ));
}

// --- §4.16.2: the message on the wire -----------------------------------------------------

#[test]
fn a_group_message_is_always_private_and_names_its_sender() {
    // §4.16.2 step 2c: "The Security Flags SHALL have only the P Flag set." And §4.4.1.5: the
    // Source Node ID is never elided on a group message — §4.8.1.1 builds the nonce from it, so
    // a receiver that did not have it could not decrypt at all.
    let keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let mut sender = Sender::restore(SWITCH, 1000, 5000);
    let datagram = send(&mut sender, &keys, b"turn on", false);

    // Message Flags is the first octet: version 0, S flag (bit 2) set, DSIZ 2 for a Group ID.
    assert_eq!(
        datagram[0] & 0x04,
        0x04,
        "the S flag: a source node id is present"
    );
    assert_eq!(datagram[0] & 0x03, 0x02, "DSIZ 2: a 16-bit Group ID");

    // Security Flags is octet 3: P (0x80) set, C (0x40) clear for a data message, session type 1.
    assert_eq!(datagram[3] & 0x80, 0x80, "the P flag");
    assert_eq!(datagram[3] & 0x40, 0x00, "not a control message");
    assert_eq!(datagram[3] & 0x03, 0x01, "session type 1: group");

    let control = send(&mut sender, &keys, b"sync", true);
    assert_eq!(control[3] & 0x40, 0x40, "the C flag on a control message");
}

#[test]
fn the_session_id_in_the_header_is_the_group_session_id() {
    let keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let key = keys.sending_key(F1, COMPRESSED, LIGHTS, None).unwrap();
    // §4.17.3.6's worked example continues §4.17.2's: this epoch key gives 0xB9F7.
    assert_eq!(key.session_id, 0xB9F7);

    let mut sender = Sender::restore(SWITCH, 1000, 5000);
    let datagram = send(&mut sender, &keys, b"turn on", false);
    // Session ID is octets 1..3, little-endian in the header even though the value itself was
    // read big-endian out of the KDF.
    assert_eq!(u16::from_le_bytes([datagram[1], datagram[2]]), 0xB9F7);
}

#[test]
fn the_sender_counter_rolls_over() {
    // §4.6.5.2.2: the group counter space is free-running. A sender that refused to wrap would
    // stop being able to send after 2³² messages, which a hub reaches.
    let keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    // `restore`, not `new`: a counter at the top of its range is one this node reached, and
    // §4.6.1.1's initialisation deliberately cannot produce it.
    let mut sender = Sender::restore(SWITCH, u32::MAX, 0);
    let mut peers = Peers::new();
    let mut scratch = [0u8; 1280];
    for expected in [u32::MAX, 0, 1] {
        let mut datagram = send(&mut sender, &keys, b"tick", false);
        let Received::Message(inbound) = wire::receive(
            &mut datagram,
            FROM,
            &keys,
            &mut peers,
            compressed,
            &mut scratch,
        )
        .unwrap() else {
            panic!("each of these is new");
        };
        assert_eq!(inbound.counter, expected);
    }
}

// --- §4.17: the key table ------------------------------------------------------------------

#[test]
fn removing_a_key_set_removes_the_groups_mapped_to_it() {
    // §11.2.7.4: "If there exist any entries for the accessing fabric within the GroupKeyMap
    // attribute that refer to the GroupKeySetID just removed, then these entries SHALL be
    // removed from that list." A group mapped to nothing could neither send nor receive, and
    // would keep its multicast subscription alive for no reason.
    let mut keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    assert!(keys.sending_key(F1, COMPRESSED, LIGHTS, None).is_ok());
    keys.remove_key_set(F1, 7).unwrap();
    assert!(keys.map().is_empty());
    assert!(keys.sending_key(F1, COMPRESSED, LIGHTS, None).is_err());
}

#[test]
fn the_ipk_key_set_cannot_be_removed_this_way() {
    // §11.2.7.4: key set 0 is the Identity Protection Key's, and "the only method to remove the
    // IPK is usage of the RemoveFabric command". Removing it here would leave the fabric unable
    // to complete a CASE handshake.
    let mut keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    assert_eq!(
        keys.remove_key_set(F1, 0),
        Err(matter_kit::im::Status::InvalidCommand)
    );
}

#[test]
fn a_group_cannot_map_to_a_key_set_that_does_not_exist() {
    // §11.2.6.1: the map is what turns a Group ID into a key, so an entry pointing at nothing is
    // a group that silently cannot communicate.
    let mut keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    assert_eq!(
        keys.map_group(F1, GroupId(9), 99),
        Err(matter_kit::im::Status::NotFound)
    );
}

/// §11.2.6.3's `MaxGroupKeysPerFabric` is a quota, and it is the quota the cluster *advertises*.
///
/// The fixture is the node's real one. The quota is `Config`'s and the table is asserted at
/// compile time to have room for it — §2.11.1.2's minimum is three per fabric — so the only way
/// to reach the edge is to walk to it.
#[test]
fn the_per_fabric_quota_is_enforced() {
    use matter_kit::Config;

    let quota = DefaultConfig::GROUP_KEYS_PER_FABRIC;
    let mut keys = Keys::new();
    let mut epoch_keys = heapless::Vec::new();
    epoch_keys
        .push(EpochKey {
            key: SymmetricKey::new(EPOCH),
            start_time_us: 1,
        })
        .unwrap();

    for id in 0..quota {
        keys.write_key_set(GroupKeySet {
            fabric_index: F1,
            id: id as u16 + 1,
            policy: GroupKeySecurityPolicy::TrustFirst,
            epoch_keys: epoch_keys.clone(),
        })
        .unwrap_or_else(|e| panic!("set {id} is inside the fabric's quota of {quota}: {e:?}"));
    }

    // Writing an id the fabric already holds is a replacement, not a new set, so it stays inside
    // the quota however often it is repeated (§11.2.7.1).
    keys.write_key_set(GroupKeySet {
        fabric_index: F1,
        id: 1,
        policy: GroupKeySecurityPolicy::TrustFirst,
        epoch_keys: epoch_keys.clone(),
    })
    .expect("replacing an existing set does not spend quota");

    // One past it is refused, and the status is the one §8.10 gives for a resource limit.
    assert_eq!(
        keys.write_key_set(GroupKeySet {
            fabric_index: F1,
            id: quota as u16 + 1,
            policy: GroupKeySecurityPolicy::TrustFirst,
            epoch_keys: epoch_keys.clone(),
        }),
        Err(matter_kit::im::Status::ResourceExhausted)
    );

    // And the quota is *per fabric*: a second fabric still gets its own full share, which is the
    // whole reason the limit is not simply the table's length.
    keys.write_key_set(GroupKeySet {
        fabric_index: F2,
        id: 1,
        policy: GroupKeySecurityPolicy::TrustFirst,
        epoch_keys,
    })
    .expect("another fabric's quota is its own");
}

#[test]
fn removing_a_fabric_takes_its_keys_and_its_peers() {
    let mut keys = table(EPOCH, GroupKeySecurityPolicy::TrustFirst);
    let mut peers = Peers::new();
    assert_eq!(
        peers.admit(F1, SWITCH, false, 1, GroupKeySecurityPolicy::TrustFirst),
        Admitted::Process
    );
    keys.remove_fabric(F1);
    peers.remove_fabric(F1);
    assert!(keys.key_sets().is_empty());
    assert!(keys.map().is_empty());
    assert!(peers.is_empty());
}
