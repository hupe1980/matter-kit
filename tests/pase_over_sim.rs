//! A commissioner and a device establish a session from a printed passcode, over the
//! simulated network, and then talk encrypted.
//!
//! This is the whole M1 stack working at once: TLV encodes the PASE messages, the message
//! layer frames them on the *unsecured* session, MRP would carry them reliably, SPAKE2+
//! turns the passcode into `Ke`, the session module derives `I2RKey`/`R2IKey`, and the
//! security layer then encrypts real traffic with them. Every one of those has unit tests;
//! none of those tests would catch the two halves disagreeing about, say, which direction
//! a key belongs to.
//!
//! The interesting assertions are the negative ones. A wrong passcode must fail at the
//! confirmation step, not later and not never; a tampered message must fail the tag; and
//! the keys must be *directional*, so a node that used the wrong one would be caught here
//! rather than in the field.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::crypto::Spake2pVerifierData;
use matter_kit::error::ErrorCode;
use matter_kit::msg::{
    Destination, MessageHeader, NodeId, NonceSource, ProtocolHeader, ProtocolId, SessionId,
    protect, unprotect,
};
use matter_kit::platform::sim::{SimNet, block_on};
use matter_kit::platform::{PeerAddr, Timer, Udp};
use matter_kit::sc::{
    PaseInitiator, PaseResponder, PbkdfParameters, ResponderConfig, SessionParams, opcode,
};
use matter_kit::session::{EstablishedKeys, Role, SecureSession, SessionKind};

/// The passcode CHIP's test devices print, and the salt they use.
const TEST_PASSCODE: u32 = 20_202_021;
const TEST_SALT: &[u8] = b"SPAKE2P Key Salt";
const TEST_ITERATIONS: u32 = 1_000;

/// Everything a PASE exchange needs that is not a message.
struct Setup {
    device: PaseResponder,
    commissioner: PaseInitiator,
}

fn setup(device_passcode: u32, commissioner_passcode: u32, share_parameters: bool) -> Setup {
    let parameters = PbkdfParameters::new(TEST_ITERATIONS, TEST_SALT).expect("parameters");
    // What a factory computes once and burns in.
    let verifier = Spake2pVerifierData::from_passcode(device_passcode, TEST_SALT, TEST_ITERATIONS)
        .expect("verifier");

    let device = PaseResponder::new(
        ResponderConfig {
            verifier,
            parameters: parameters.clone(),
            session_params: Some(SessionParams {
                idle_interval_ms: 500,
                active_interval_ms: 300,
                active_threshold_ms: 4_000,
                ..SessionParams::legacy_peer()
            }),
        },
        SessionId(0x1001),
    );
    let commissioner = PaseInitiator::new(
        commissioner_passcode,
        SessionId(0x2002),
        // A commissioner that scanned the QR code already knows the parameters; one that
        // typed the manual pairing code does not and must be told.
        share_parameters.then_some(parameters),
        None,
    );
    Setup {
        device,
        commissioner,
    }
}

/// Runs the five-message exchange, returning both ends' keys.
///
/// Every message goes over the simulated network as a real Matter message on the unsecured
/// session, which is what §4.14.1.2 requires: "All PASE messages are sent using an
/// Unsecured Session: The Session ID field SHALL be set to 0."
fn run_exchange(
    net: &SimNet,
    setup: &mut Setup,
) -> Result<(EstablishedKeys, EstablishedKeys), (ErrorCode, &'static str)> {
    let commissioner_node = net.node(1);
    let device_node = net.node(2);
    let device_addr = device_node.addr();
    let commissioner_addr = commissioner_node.addr();

    let mut wire = [0u8; 512];
    let mut payload = [0u8; 512];

    block_on(net, async {
        // 1. PBKDFParamRequest.
        let n = setup
            .commissioner
            .start(&[0x11; 32], &mut payload)
            .map_err(|e| (e.code(), "start"))?;
        send(
            &commissioner_node,
            device_addr,
            opcode::PBKDF_PARAM_REQUEST,
            true,
            &payload[..n],
            &mut wire,
        )
        .await;

        // 2. PBKDFParamResponse.
        let got = recv(&device_node, &mut wire).await;
        let n = setup
            .device
            .on_pbkdf_param_request(&got, &[0x22; 32], &mut payload)
            .map_err(|e| (e.code(), "on_pbkdf_param_request"))?;
        send(
            &device_node,
            commissioner_addr,
            opcode::PBKDF_PARAM_RESPONSE,
            false,
            &payload[..n],
            &mut wire,
        )
        .await;

        // 3. Pake1 — the expensive step: PBKDF2 on the commissioner.
        let got = recv(&commissioner_node, &mut wire).await;
        let n = setup
            .commissioner
            .on_pbkdf_param_response(&got, &[0x33; 32], &mut payload)
            .map_err(|e| (e.code(), "on_pbkdf_param_response"))?;
        send(
            &commissioner_node,
            device_addr,
            opcode::PAKE1,
            true,
            &payload[..n],
            &mut wire,
        )
        .await;

        // 4. Pake2.
        let got = recv(&device_node, &mut wire).await;
        let n = setup
            .device
            .on_pake1(&got, &[0x44; 32], &mut payload)
            .map_err(|e| (e.code(), "on_pake1"))?;
        send(
            &device_node,
            commissioner_addr,
            opcode::PAKE2,
            false,
            &payload[..n],
            &mut wire,
        )
        .await;

        // 5. Pake3 — where a wrong passcode is caught, by the commissioner.
        let got = recv(&commissioner_node, &mut wire).await;
        let n = setup
            .commissioner
            .on_pake2(&got, &mut payload)
            .map_err(|e| (e.code(), "on_pake2"))?;
        send(
            &commissioner_node,
            device_addr,
            opcode::PAKE3,
            true,
            &payload[..n],
            &mut wire,
        )
        .await;

        // 6. PakeFinished — where a wrong passcode is caught by the device.
        let got = recv(&device_node, &mut wire).await;
        let (n, device_keys) = setup
            .device
            .on_pake3(&got, &mut payload)
            .map_err(|e| (e.code(), "on_pake3"))?;
        send(
            &device_node,
            commissioner_addr,
            opcode::STATUS_REPORT,
            false,
            &payload[..n],
            &mut wire,
        )
        .await;

        let got = recv(&commissioner_node, &mut wire).await;
        let commissioner_keys = setup
            .commissioner
            .on_pake_finished(&got)
            .map_err(|e| (e.code(), "on_pake_finished"))?;

        Ok((commissioner_keys, device_keys))
    })
}

/// Frames a PASE payload as a Matter message on the unsecured session and sends it.
async fn send(
    from: &matter_kit::platform::sim::SimNode<'_>,
    to: PeerAddr,
    opcode: u8,
    initiator: bool,
    payload: &[u8],
    wire: &mut [u8],
) {
    // §4.14.1.2: session id 0, session type 0 — there is no key yet.
    let header = MessageHeader {
        session_id: SessionId(0),
        message_counter: 1,
        // "In the PASE messages from the initiator, S Flag SHALL be set to 1 and DSIZ
        // SHALL be set to 0. In the PASE messages from the responder, S Flag SHALL be set
        // to 0 and DSIZ SHALL be set to 1."
        source: initiator.then_some(NodeId(1)),
        destination: if initiator {
            Destination::None
        } else {
            Destination::Node(NodeId(1))
        },
        ..MessageHeader::default()
    };
    let protocol = ProtocolHeader {
        initiator,
        // "All PASE messages SHALL be sent reliably."
        reliability: true,
        exchange_id: matter_kit::msg::ExchangeId(1),
        protocol: ProtocolId::SECURE_CHANNEL,
        opcode,
        ..ProtocolHeader::default()
    };

    let mut at = header.encode(wire).expect("header");
    at += protocol.encode(&mut wire[at..]).expect("protocol");
    wire[at..at + payload.len()].copy_from_slice(payload);
    at += payload.len();
    from.send_to(&wire[..at], to).await.expect("send");
}

/// Receives one message and returns its application payload.
async fn recv(
    node: &matter_kit::platform::sim::SimNode<'_>,
    wire: &mut [u8],
) -> heapless::Vec<u8, 512> {
    let (n, _) = node.recv_from(wire).await.expect("recv");
    let (_, rest) = MessageHeader::decode(&wire[..n]).expect("header");
    let (_, payload) = ProtocolHeader::decode(rest).expect("protocol");
    heapless::Vec::from_slice(payload).expect("fits")
}

#[test]
fn the_right_passcode_establishes_a_session() {
    let net = SimNet::new(1);
    let mut s = setup(TEST_PASSCODE, TEST_PASSCODE, true);
    let (commissioner, device) = run_exchange(&net, &mut s).expect("the exchange should complete");

    // Both ends derived the same three keys.
    assert_eq!(commissioner.i2r, device.i2r);
    assert_eq!(commissioner.r2i, device.r2i);
    assert_eq!(
        commissioner.attestation_challenge,
        device.attestation_challenge
    );
    // And the three are distinct from each other.
    assert_ne!(commissioner.i2r.encryption, commissioner.r2i.encryption);

    assert!(s.device.is_established());
    assert!(s.commissioner.is_established());
    // Each end knows where to send: its own id to listen on, the peer's to address.
    assert_eq!(s.commissioner.peer_session_id(), SessionId(0x1001));
    assert_eq!(s.device.peer_session_id(), SessionId(0x2002));
}

#[test]
fn the_session_it_produces_actually_carries_traffic() {
    // Deriving matching keys is not the same as being able to use them: the direction has
    // to be right too, and that is what this checks.
    let net = SimNet::new(2);
    let mut s = setup(TEST_PASSCODE, TEST_PASSCODE, true);
    let (commissioner_keys, device_keys) = run_exchange(&net, &mut s).expect("exchange");

    let commissioner = SecureSession::new(
        SessionId(0x2002),
        SessionId(0x1001),
        SessionKind::Pase,
        Role::Initiator,
        commissioner_keys,
        1,
        Timer::now(&net),
    );
    let device = SecureSession::new(
        SessionId(0x1001),
        SessionId(0x2002),
        SessionKind::Pase,
        Role::Responder,
        device_keys,
        1,
        Timer::now(&net),
    );

    // Commissioner → device.
    let header = MessageHeader {
        session_id: device.local_session_id,
        message_counter: 7,
        ..MessageHeader::default()
    };
    let mut buf = [0u8; 256];
    let n = protect(
        &header,
        commissioner.send_nonce_source(),
        b"an encrypted command",
        commissioner.encrypt_keys(),
        &mut buf,
    )
    .expect("protect");
    let (_, range) = unprotect(
        &mut buf[..n],
        device.decrypt_keys(),
        device.recv_nonce_source(),
    )
    .expect("the device must be able to read it");
    assert_eq!(&buf[range], b"an encrypted command");

    // Device → commissioner, which uses the *other* key.
    let header = MessageHeader {
        session_id: commissioner.local_session_id,
        message_counter: 7,
        ..MessageHeader::default()
    };
    let mut buf = [0u8; 256];
    let n = protect(
        &header,
        device.send_nonce_source(),
        b"an encrypted response",
        device.encrypt_keys(),
        &mut buf,
    )
    .expect("protect");
    let (_, range) = unprotect(
        &mut buf[..n],
        commissioner.decrypt_keys(),
        commissioner.recv_nonce_source(),
    )
    .expect("the commissioner must be able to read it");
    assert_eq!(&buf[range], b"an encrypted response");
}

#[test]
fn the_keys_are_directional() {
    // If a node used its *sending* key to decrypt, it would still talk to itself
    // perfectly. This is the test that catches that.
    let net = SimNet::new(3);
    let mut s = setup(TEST_PASSCODE, TEST_PASSCODE, true);
    let (commissioner_keys, _) = run_exchange(&net, &mut s).expect("exchange");

    let commissioner = SecureSession::new(
        SessionId(1),
        SessionId(2),
        SessionKind::Pase,
        Role::Initiator,
        commissioner_keys,
        1,
        Timer::now(&net),
    );
    assert_ne!(commissioner.encrypt_keys(), commissioner.decrypt_keys());

    let header = MessageHeader {
        session_id: SessionId(2),
        message_counter: 1,
        ..MessageHeader::default()
    };
    let mut buf = [0u8; 128];
    let n = protect(
        &header,
        NonceSource::Pase,
        b"x",
        commissioner.encrypt_keys(),
        &mut buf,
    )
    .expect("protect");
    assert_eq!(
        unprotect(
            &mut buf[..n],
            commissioner.decrypt_keys(),
            NonceSource::Pase
        )
        .unwrap_err()
        .code(),
        ErrorCode::IntegrityCheckFailed,
        "a node must not be able to decrypt what it encrypted"
    );
}

#[test]
fn the_wrong_passcode_fails_at_the_confirmation() {
    // The commissioner finds out first, at Pake2: cB will not match. That is the *one*
    // guess SPAKE2+ allows, and it costs a full exchange.
    let net = SimNet::new(4);
    let mut s = setup(TEST_PASSCODE, 12_345_678, true);
    let (code, step) = run_exchange(&net, &mut s).expect_err("a wrong passcode must fail");
    assert_eq!(code, ErrorCode::IntegrityCheckFailed);
    assert_eq!(step, "on_pake2", "it must fail at cB, not earlier or later");
    assert!(s.commissioner.is_failed());
}

#[test]
fn a_device_that_lies_about_its_confirmation_is_caught() {
    // A man in the middle who forwards pB but forges cB.
    let net = SimNet::new(5);
    let mut s = setup(TEST_PASSCODE, TEST_PASSCODE, true);
    let commissioner_node = net.node(1);
    let device_node = net.node(2);
    let mut wire = [0u8; 512];
    let mut payload = [0u8; 512];

    block_on(&net, async {
        let n = s
            .commissioner
            .start(&[0x11; 32], &mut payload)
            .expect("start");
        send(
            &commissioner_node,
            device_node.addr(),
            opcode::PBKDF_PARAM_REQUEST,
            true,
            &payload[..n],
            &mut wire,
        )
        .await;
        let got = recv(&device_node, &mut wire).await;
        let n = s
            .device
            .on_pbkdf_param_request(&got, &[0x22; 32], &mut payload)
            .expect("response");
        send(
            &device_node,
            commissioner_node.addr(),
            opcode::PBKDF_PARAM_RESPONSE,
            false,
            &payload[..n],
            &mut wire,
        )
        .await;
        let got = recv(&commissioner_node, &mut wire).await;
        let n = s
            .commissioner
            .on_pbkdf_param_response(&got, &[0x33; 32], &mut payload)
            .expect("pake1");
        send(
            &commissioner_node,
            device_node.addr(),
            opcode::PAKE1,
            true,
            &payload[..n],
            &mut wire,
        )
        .await;
        let got = recv(&device_node, &mut wire).await;
        let n = s
            .device
            .on_pake1(&got, &[0x44; 32], &mut payload)
            .expect("pake2");

        // Forge cB itself. Flipping the *last* octet of the encoding would hit the TLV
        // end-of-container marker and test the parser instead of the protocol.
        let mut pake2 = matter_kit::sc::Pake2::decode(&payload[..n]).expect("decode");
        pake2.cb[0] ^= 0xFF;
        let mut forged = [0u8; 512];
        let n = pake2.encode(&mut forged).expect("re-encode");

        assert_eq!(
            s.commissioner
                .on_pake2(&forged[..n], &mut payload)
                .unwrap_err()
                .code(),
            ErrorCode::IntegrityCheckFailed
        );
        assert!(s.commissioner.is_failed());
    });
}

#[test]
fn a_commissioner_that_lies_about_its_confirmation_is_caught() {
    // The mirror image: the device checks cA at Pake3.
    let mut s = setup(TEST_PASSCODE, TEST_PASSCODE, true);
    let mut payload = [0u8; 512];
    let mut scratch = [0u8; 512];

    let n = s
        .commissioner
        .start(&[0x11; 32], &mut payload)
        .expect("start");
    let request = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let n = s
        .device
        .on_pbkdf_param_request(&request, &[0x22; 32], &mut payload)
        .expect("response");
    let response = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let n = s
        .commissioner
        .on_pbkdf_param_response(&response, &[0x33; 32], &mut payload)
        .expect("pake1");
    let pake1 = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let n = s
        .device
        .on_pake1(&pake1, &[0x44; 32], &mut payload)
        .expect("pake2");
    let pake2 = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let n = s
        .commissioner
        .on_pake2(&pake2, &mut payload)
        .expect("pake3");

    let mut pake3 = matter_kit::sc::Pake3::decode(&payload[..n]).expect("decode");
    pake3.ca[0] ^= 0xFF;
    let mut forged = [0u8; 512];
    let n = pake3.encode(&mut forged).expect("re-encode");
    assert_eq!(
        s.device
            .on_pake3(&forged[..n], &mut scratch)
            .unwrap_err()
            .code(),
        ErrorCode::IntegrityCheckFailed
    );
    assert!(s.device.is_failed());
}

#[test]
fn a_commissioner_without_the_parameters_is_told_them() {
    // The manual-pairing-code path: hasPBKDFParameters is false, so the device must send
    // the salt and iteration count, and the exchange must still work.
    let net = SimNet::new(7);
    let mut s = setup(TEST_PASSCODE, TEST_PASSCODE, false);
    let (commissioner, device) = run_exchange(&net, &mut s).expect("exchange");
    assert_eq!(commissioner.i2r, device.i2r);
}

#[test]
fn a_failed_exchange_cannot_be_retried_on_the_same_state_machine() {
    // §4.14.1.2 says to "perform no further processing" after a confirmation failure.
    // Letting the peer try again on the same exchange would turn SPAKE2+'s one guess into
    // as many as it likes.
    let net = SimNet::new(8);
    let mut s = setup(TEST_PASSCODE, 12_345_678, true);
    let _ = run_exchange(&net, &mut s).expect_err("wrong passcode");
    assert!(s.commissioner.is_failed());

    let mut out = [0u8; 256];
    assert_eq!(
        s.commissioner
            .start(&[0x11; 32], &mut out)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidState
    );
}

#[test]
fn two_runs_with_the_same_passcode_produce_different_keys() {
    // Different ephemerals each time, so a recorded session cannot be replayed into a new
    // one. The exchange is deterministic given its randomness, which is what lets the test
    // vary only that.
    let net = SimNet::new(9);
    let mut first = setup(TEST_PASSCODE, TEST_PASSCODE, true);
    let (a, _) = run_exchange(&net, &mut first).expect("first");

    let mut second = setup(TEST_PASSCODE, TEST_PASSCODE, true);
    // `run_exchange` uses fixed ephemerals, so vary them through a second exchange that
    // drives the state machines directly.
    let mut payload = [0u8; 512];
    let n = second
        .commissioner
        .start(&[0xAA; 32], &mut payload)
        .expect("start");
    let request = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let n = second
        .device
        .on_pbkdf_param_request(&request, &[0xBB; 32], &mut payload)
        .expect("response");
    let response = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let n = second
        .commissioner
        .on_pbkdf_param_response(&response, &[0xCC; 32], &mut payload)
        .expect("pake1");
    let pake1 = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let n = second
        .device
        .on_pake1(&pake1, &[0xDD; 32], &mut payload)
        .expect("pake2");
    let pake2 = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let n = second
        .commissioner
        .on_pake2(&pake2, &mut payload)
        .expect("pake3");
    let pake3 = heapless::Vec::<u8, 512>::from_slice(&payload[..n]).expect("fits");
    let (n, _) = second
        .device
        .on_pake3(&pake3, &mut payload)
        .expect("finished");
    let b = second
        .commissioner
        .on_pake_finished(&payload[..n])
        .expect("keys");

    assert_ne!(a.i2r, b.i2r, "a new exchange must produce new keys");
    assert_ne!(a.attestation_challenge, b.attestation_challenge);
}
