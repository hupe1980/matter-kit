//! §4.13.2.1's Unsecured Session Context, from both ends.
//!
//! PASE and CASE both run on the unsecured session before there is a key, and §4.13.2.1 gives
//! that session one piece of state: an Ephemeral Initiator Node ID, "enclosed by initiator as
//! Source Node ID and responder as Destination Node ID".
//!
//! Both halves are checked here because each hides the other. An initiator that never
//! establishes a context sends a message with neither field, which rule 1(c) tells a responder
//! to discard — and a responder that does not implement 1(c) accepts it. Two ends of one crate
//! then agree with each other and disagree with the specification, which is the one failure a
//! suite with matter-kit on both ends cannot see.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use matter_kit::DefaultConfig;
use matter_kit::error::ErrorCode;
use matter_kit::messaging::{Messaging, Received};
use matter_kit::msg::{MessageHeader, NodeId, ProtocolId, SessionId};
use matter_kit::platform::{Duration, Instant, Peer, PeerAddr};

type Stack = Messaging<DefaultConfig>;

const PEER: Peer = Peer::Udp(PeerAddr::new([
    0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]));

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

#[test]
fn an_unsecured_initiator_encloses_an_ephemeral_node_id() {
    let mut node = Stack::new(0x1000, 0x100, 7);
    let exchange = node
        .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0x0102_0304_0506_0708)
        .expect("an unsecured exchange opens its own context");
    let mut frame = [0u8; 512];
    let mut out = [0u8; 512];
    let (len, _) = node
        .send(
            exchange,
            0x20,
            true,
            b"pbkdfparamrequest",
            at(0),
            0,
            &mut frame,
            &mut out,
        )
        .expect("send");

    let (header, _) = MessageHeader::decode(&out[..len]).expect("decode");
    let source = header
        .source
        .expect("§4.13.2.1: the initiator encloses its Ephemeral Initiator Node ID as Source");
    assert!(
        source.is_operational(),
        "§4.13.2.1: selected from the Operational Node ID range, and this one is {source:?}"
    );
    assert_eq!(node.unsecured_ephemeral_id(), Some(source));
}

#[test]
fn opening_an_unsecured_exchange_without_a_context_is_refused() {
    // The door that was open. `open` on the unsecured session used to produce an exchange whose
    // every message was unroutable, and said nothing about it.
    let mut node = Stack::new(0x1000, 0x100, 7);
    let err = node
        .open(SessionId::UNSECURED, ProtocolId::SECURE_CHANNEL, at(0))
        .expect_err("no Unsecured Session Context has been established");
    assert_eq!(err.code(), ErrorCode::InvalidState);

    let err = node
        .open_to(
            SessionId::UNSECURED,
            ProtocolId::SECURE_CHANNEL,
            PEER,
            at(0),
        )
        .expect_err("the same rule holds for an exchange to a known peer");
    assert_eq!(err.code(), ErrorCode::InvalidState);
}

#[test]
fn a_new_unsecured_session_gets_a_new_ephemeral_id() {
    // "Initiators SHALL select a new random ephemeral node ID for each unsecured session."
    // A commissioner runs PASE and then CASE, and those are two unsecured sessions.
    let mut node = Stack::new(0x1000, 0x100, 7);
    node.open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0x1111_2222_3333_4444)
        .expect("pase");
    let first = node.unsecured_ephemeral_id().expect("a context");
    node.close_unsecured();
    node.open_unsecured(ProtocolId::SECURE_CHANNEL, at(1), 0x5555_6666_7777_8888)
        .expect("case");
    let second = node.unsecured_ephemeral_id().expect("a context");
    assert_ne!(first, second, "each unsecured session gets its own id");
    assert!(first.is_operational() && second.is_operational());
}

#[test]
fn a_message_with_no_source_and_no_matching_context_is_discarded() {
    // §4.13.2.1 rule 1(c). Accepting these is what let the initiator above get away with
    // sending one: the two ends agreed, and the specification did not.
    let mut initiator = Stack::new(0x1000, 0x100, 7);
    let mut responder = Stack::new(0x2000, 0x200, 9);

    // Build a legitimate message, then strip the Source Node ID the way a careless sender would
    // have left it out: clear the S flag and remove the eight octets it introduced.
    let exchange = initiator
        .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0x0102_0304_0506_0708)
        .expect("open");
    let mut frame = [0u8; 512];
    let mut out = [0u8; 512];
    let (len, _) = initiator
        .send(exchange, 0x20, true, b"x", at(0), 0, &mut frame, &mut out)
        .expect("send");

    let mut stripped = Vec::with_capacity(len);
    stripped.extend_from_slice(&out[..8]);
    stripped.extend_from_slice(&out[16..len]);
    stripped[0] &= !0x04; // the S flag

    let err = responder
        .receive(&mut stripped, PEER, at(1))
        .expect_err("§4.13.2.1 rule 1c: else discard the message");
    assert_eq!(err.code(), ErrorCode::NoSession);
}

#[test]
fn a_responder_still_answers_a_well_formed_handshake() {
    // The discard rule must not have been bought by refusing the messages it exists to admit.
    let mut initiator = Stack::new(0x1000, 0x100, 7);
    let mut responder = Stack::new(0x2000, 0x200, 9);
    let exchange = initiator
        .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0x0102_0304_0506_0708)
        .expect("open");
    let mut frame = [0u8; 512];
    let mut out = [0u8; 512];
    let (len, _) = initiator
        .send(
            exchange,
            0x20,
            true,
            b"hello",
            at(0),
            0,
            &mut frame,
            &mut out,
        )
        .expect("send");

    let received = responder
        .receive(&mut out[..len], PEER, at(1))
        .expect("a well-formed unsecured message");
    assert!(matches!(received, Received::Message { .. }));
    assert_eq!(
        responder.unsecured_ephemeral_id(),
        initiator.unsecured_ephemeral_id(),
        "the responder records the initiator's id as its own context"
    );
}

#[test]
fn an_ephemeral_id_is_always_in_the_operational_range() {
    // Folded rather than rejected, so a caller never has to decide what to do about randomness
    // that fell outside the range. Every value has to land inside it, including the corners.
    for randomness in [
        0,
        u64::MAX,
        0xFFFF_FFFF_FFFF_0000,
        0xFFFF_FFEF_FFFF_FFFF,
        0x8000_0000_0000_0000,
    ] {
        let id = NodeId::ephemeral(randomness);
        assert!(
            id.is_operational(),
            "{randomness:#018x} produced {id:?}, which is not an Operational Node ID"
        );
    }
}
