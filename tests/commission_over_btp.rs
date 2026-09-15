//! Commissioning a device over BLE, from the advertisement to the shared session key.
//!
//! [`commission_over_messaging`](../commission_over_messaging/index.html) proves the stack
//! composes over UDP, where a Matter message *is* a datagram. BLE is the case where it is not:
//! a GATT PDU carries at most 244 octets and a PASE message is several times that, so every
//! message here is cut into segments, acknowledged, and put back together by
//! [`transport::btp`](matter_kit::transport::btp) before the message layer ever sees it.
//!
//! The whole path runs: the device's advertisement, a commissioner matching the discriminator
//! it read off the QR code, the BTP handshake, then PASE — five real Matter messages, each one
//! segmented across the GATT connection. What is missing is only the radio.
//!
//! It also pins the rule that is easiest to get wrong once two reliability mechanisms are in
//! play. Core §4.12.4: "Reliable messages sent over TCP, PAFTP, or BTP SHALL utilize the
//! underlying reliability mechanisms of those transports and SHOULD NOT set the R Flag."
//! Running MRP on top of BTP would retransmit messages BTP has already delivered.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::commissioning::{CustomFlow, DiscoveryCapabilities, OnboardingPayload, Passcode};
use matter_kit::config::DefaultConfig;
use matter_kit::crypto::Spake2pVerifierData;
use matter_kit::exchange::ExchangeKey;
use matter_kit::messaging::{Messaging, Received as Delivered};
use matter_kit::msg::{ProtocolId, SessionId, VendorId};
use matter_kit::platform::{Instant, Peer};
use matter_kit::sc::{
    PaseInitiator, PaseResponder, PbkdfParameters, ResponderConfig, SessionParams, opcode,
};
use matter_kit::transport::ble::Advertisement;
use matter_kit::transport::btp::{
    HandshakeRequest, HandshakeResponse, MAX_SEGMENT, MIN_ATT_MTU, Received, Role, Session,
    negotiate,
};

type Stack = Messaging<DefaultConfig, 4, 8>;
/// A BTP SDU is a whole Matter message, so the reassembly buffer is §4.4.4's 1280 octets.
type Btp = Session<1280>;

const PASSCODE: u32 = 20_202_021;
const SALT: &[u8] = b"SPAKE2P Key Salt";
const ITERATIONS: u32 = 1_000;
const DISCRIMINATOR: u16 = 0xF00;

const DEVICE_SESSION: SessionId = SessionId(0x1001);
const COMMISSIONER_SESSION: SessionId = SessionId(0x2002);

/// The BLE connection handle the platform would hand back. Its value means nothing to Matter;
/// what matters is that it is a [`Peer::Ble`] and not an address.
const HANDLE: Peer = Peer::Ble(0x0042);

fn at(secs: u64) -> Instant {
    Instant::from_micros(secs * 1_000_000)
}

/// How many GATT PDUs crossed the link, and the largest of them.
#[derive(Debug, Default)]
struct Traffic {
    packets: usize,
    largest: usize,
}

/// Carries one Matter message from `tx` to `rx` as a BTP SDU, letting either end acknowledge
/// as the receive window demands, and returns what came out the far side.
///
/// The `else` branch is the interesting one: when the window closes, the *receiver* is the
/// only peer that can make progress, and it does so by sending the stand-alone acknowledgement
/// §4.19.4.8 requires once its own window is down to two free slots. Without that rule this
/// loop would deadlock, which is precisely why the rule exists.
fn carry(tx: &mut Btp, rx: &mut Btp, sdu: &[u8], now: Instant, traffic: &mut Traffic) -> Vec<u8> {
    tx.send(sdu).expect("no other SDU is in flight");
    let mut gatt = [0u8; 256];
    for _ in 0..4096 {
        if let Some(n) = tx.poll_send(now, &mut gatt).expect("segment") {
            traffic.packets += 1;
            traffic.largest = traffic.largest.max(n);
            assert!(
                n <= usize::from(MAX_SEGMENT),
                "§4.19.4.2 caps C1 and C2 at 244 octets"
            );
            if rx.receive(&gatt[..n], now).expect("reassemble") == Received::Message {
                let message = rx.message().to_vec();
                rx.take_message();
                return message;
            }
        } else if let Some(n) = rx.poll_send(now, &mut gatt).expect("acknowledgement") {
            traffic.packets += 1;
            tx.receive(&gatt[..n], now).expect("acknowledgement");
        } else {
            panic!("neither peer can make progress: the session has deadlocked");
        }
    }
    panic!("the transfer did not terminate");
}

/// Opens the BTP session the two ends agree on, by the handshake of §4.19.3.
fn handshake(device_att_mtu: u16) -> (Btp, Btp, HandshakeResponse) {
    // The commissioner offers its own limits over C1.
    let mut gatt = [0u8; 64];
    let n = HandshakeRequest::new(247, 6)
        .encode(&mut gatt)
        .expect("encode");

    // The device answers over C2 with the lower of each — never the client's word for it.
    let offered = HandshakeRequest::decode(&gatt[..n]).expect("the device reads the request");
    let agreed = negotiate(&offered, device_att_mtu, 4).expect("a version and a window both use");
    let n = agreed.encode(&mut gatt).expect("encode");
    let confirmed =
        HandshakeResponse::decode(&gatt[..n]).expect("the commissioner reads the response");
    assert_eq!(confirmed, agreed);
    assert_eq!(confirmed.window, 4, "the device's window is the smaller");
    assert_eq!(confirmed.att_mtu, device_att_mtu);

    (
        Session::new(Role::Client, &confirmed.params(), at(0)),
        Session::new(Role::Server, &confirmed.params(), at(0)),
        confirmed,
    )
}

/// The whole flow: an advertisement, a handshake, and PASE over the GATT connection.
///
/// It runs at both ends of the MTU range, because they are different protocols in practice.
/// At 247 a PASE message is one GATT PDU and BTP is barely more than a wrapper; at the BLE
/// 4.0 minimum of 23 — what a peripheral has before any MTU exchange — the same message is
/// cut into twenty-octet pieces, the receive window closes part way through every one of
/// them, and the transfer only continues because §4.19.4.8 makes the receiver speak up.
#[test]
fn a_commissioner_finds_a_device_over_ble_and_completes_pase_through_btp() {
    // Six Matter messages, six GATT PDUs: the largest PASE message is 124 octets and BTP is
    // barely more than a wrapper here.
    let wide = commission(247);
    assert_eq!(wide.packets, 6);
    assert!((100..=usize::from(MAX_SEGMENT)).contains(&wide.largest));

    // The same six messages over the BLE 4.0 minimum: twenty octets a packet, and the extra
    // packets are the segments plus the stand-alone acknowledgements that reopen the window.
    let narrow = commission(MIN_ATT_MTU);
    assert!(narrow.largest <= 20, "ATT_MTU 23 leaves ATT_MTU - 3 octets");
    assert!(
        narrow.packets > wide.packets * 4,
        "{} packets against {}",
        narrow.packets,
        wide.packets
    );
}

/// Runs the flow once over a connection with the given ATT_MTU, returning what crossed it.
fn commission(device_att_mtu: u16) -> Traffic {
    // --- Discovery (§5.4.2.5) ------------------------------------------------------------
    //
    // The device advertises what its own label says, so the discriminator a user scanned off
    // the QR code is the one on the air.
    let label = OnboardingPayload::new(
        VendorId(0xFFF1),
        0x8000,
        DISCRIMINATOR,
        Passcode::new(PASSCODE).expect("passcode"),
        DiscoveryCapabilities::BLE,
        CustomFlow::Standard,
    )
    .expect("onboarding payload");

    let mut air = [0u8; Advertisement::MAX];
    let n = Advertisement::for_onboarding(&label)
        .encode(&mut air)
        .expect("advertise");

    // A passive scan is enough: §5.4.2.5.6 puts everything needed in the advertising data.
    let seen = Advertisement::decode(&air[..n]).expect("the commissioner scans");
    let Advertisement::Commissionable { discriminator, .. } = seen else {
        panic!("a commissionable device")
    };
    assert_eq!(
        discriminator, label.discriminator,
        "the commissioner matches what it read off the QR code"
    );

    // --- The BTP session (§4.19.3) -------------------------------------------------------
    let (mut ble_client, mut ble_server, agreed) = handshake(device_att_mtu);
    assert!(
        agreed.segment_size() <= usize::from(MAX_SEGMENT),
        "§4.19.4.2 caps C1 and C2 at 244 octets however large the MTU grows"
    );

    // --- PASE, every message segmented across the GATT connection -------------------------
    let parameters = PbkdfParameters::new(ITERATIONS, SALT).expect("parameters");
    let verifier =
        Spake2pVerifierData::from_passcode(PASSCODE, SALT, ITERATIONS).expect("verifier");
    let mut device_pase = PaseResponder::new(
        ResponderConfig {
            verifier,
            parameters: parameters.clone(),
            session_params: Some(SessionParams::default()),
        },
        DEVICE_SESSION,
    );
    let mut commissioner_pase =
        PaseInitiator::new(PASSCODE, COMMISSIONER_SESSION, Some(parameters), None);

    let mut commissioner = Stack::new(0x2000, 0x100, 0xABCD_0000);
    let mut device = Stack::new(0x1000, 0x200, 0x1234_0000);
    let mut traffic = Traffic::default();
    let mut payload = [0u8; 1024];
    let mut datagram = [0u8; 1280];
    let mut scratch = [0u8; 1280];

    // The commissioner knows where the device is: at the far end of a BLE connection.
    let out = commissioner
        .open_to(
            SessionId::UNSECURED,
            ProtocolId::SECURE_CHANNEL,
            HANDLE,
            at(0),
        )
        .expect("open");

    // 1. PBKDFParamRequest.
    let n = commissioner_pase
        .start(&[0x11; 32], &mut payload)
        .expect("start");
    let (len, _) = commissioner
        .send(
            out,
            opcode::PBKDF_PARAM_REQUEST,
            true,
            &payload[..n],
            at(0),
            0,
            &mut scratch,
            &mut datagram,
        )
        .expect("send");
    let sdu = carry(
        &mut ble_client,
        &mut ble_server,
        &datagram[..len],
        at(0),
        &mut traffic,
    );

    // 2. PBKDFParamResponse.
    let (device_exchange, code, got) = deliver(&mut device, sdu, at(1));
    assert_eq!(code, opcode::PBKDF_PARAM_REQUEST);
    let n = device_pase
        .on_pbkdf_param_request(&got, &[0x22; 32], &mut payload)
        .expect("on_pbkdf_param_request");
    let (len, _) = device
        .send(
            device_exchange,
            opcode::PBKDF_PARAM_RESPONSE,
            true,
            &payload[..n],
            at(1),
            0,
            &mut scratch,
            &mut datagram,
        )
        .expect("send");
    let sdu = carry(
        &mut ble_server,
        &mut ble_client,
        &datagram[..len],
        at(1),
        &mut traffic,
    );

    // 3. Pake1 — the largest message of the exchange, and the one that proves segmentation.
    let (_, code, got) = deliver(&mut commissioner, sdu, at(2));
    assert_eq!(code, opcode::PBKDF_PARAM_RESPONSE);
    let n = commissioner_pase
        .on_pbkdf_param_response(&got, &[0x33; 32], &mut payload)
        .expect("on_pbkdf_param_response");
    let (len, _) = commissioner
        .send(
            out,
            opcode::PAKE1,
            true,
            &payload[..n],
            at(2),
            0,
            &mut scratch,
            &mut datagram,
        )
        .expect("send");
    let sdu = carry(
        &mut ble_client,
        &mut ble_server,
        &datagram[..len],
        at(2),
        &mut traffic,
    );

    // 4. Pake2.
    let (_, code, got) = deliver(&mut device, sdu, at(3));
    assert_eq!(code, opcode::PAKE1);
    let n = device_pase
        .on_pake1(&got, &[0x44; 32], &mut payload)
        .expect("on_pake1");
    let (len, _) = device
        .send(
            device_exchange,
            opcode::PAKE2,
            true,
            &payload[..n],
            at(3),
            0,
            &mut scratch,
            &mut datagram,
        )
        .expect("send");
    let sdu = carry(
        &mut ble_server,
        &mut ble_client,
        &datagram[..len],
        at(3),
        &mut traffic,
    );

    // 5. Pake3.
    let (_, code, got) = deliver(&mut commissioner, sdu, at(4));
    assert_eq!(code, opcode::PAKE2);
    let n = commissioner_pase
        .on_pake2(&got, &mut payload)
        .expect("on_pake2");
    let (len, _) = commissioner
        .send(
            out,
            opcode::PAKE3,
            true,
            &payload[..n],
            at(4),
            0,
            &mut scratch,
            &mut datagram,
        )
        .expect("send");
    let sdu = carry(
        &mut ble_client,
        &mut ble_server,
        &datagram[..len],
        at(4),
        &mut traffic,
    );

    // 6. StatusReport(PakeFinished).
    let (_, code, got) = deliver(&mut device, sdu, at(5));
    assert_eq!(code, opcode::PAKE3);
    let (n, device_keys) = device_pase.on_pake3(&got, &mut payload).expect("on_pake3");
    let (len, _) = device
        .send(
            device_exchange,
            opcode::STATUS_REPORT,
            true,
            &payload[..n],
            at(5),
            0,
            &mut scratch,
            &mut datagram,
        )
        .expect("send");
    let sdu = carry(
        &mut ble_server,
        &mut ble_client,
        &datagram[..len],
        at(5),
        &mut traffic,
    );

    let (_, code, got) = deliver(&mut commissioner, sdu, at(6));
    assert_eq!(code, opcode::STATUS_REPORT);
    let commissioner_keys = commissioner_pase
        .on_pake_finished(&got)
        .expect("the device proved it knows the passcode");

    assert_eq!(
        device_keys.attestation_challenge, commissioner_keys.attestation_challenge,
        "both ends derived the same secrets, over BLE"
    );
    traffic
}

/// §4.12.4: MRP does not run on top of a transport that is already reliable.
#[test]
fn a_ble_exchange_never_sets_the_reliability_flag() {
    // Two mechanisms guaranteeing the same delivery is not twice as safe: MRP would retransmit
    // a message BTP has already delivered, and BTP would faithfully carry the duplicate.
    let mut node = Stack::new(0x2000, 0x100, 7);
    let ble = node
        .open_to(
            SessionId::UNSECURED,
            ProtocolId::SECURE_CHANNEL,
            HANDLE,
            at(0),
        )
        .expect("open");
    let mut datagram = [0u8; 256];
    let mut scratch = [0u8; 256];
    node.send(
        ble,
        opcode::PBKDF_PARAM_REQUEST,
        true,
        b"request",
        at(0),
        0,
        &mut scratch,
        &mut datagram,
    )
    .expect("send");

    // The R flag is bit 2 of the Exchange Flags, the first octet of the protocol header. On an
    // unsecured session the payload starts at octet 8: flags, session id, security flags,
    // counter.
    assert_eq!(datagram[8] & 0x04, 0, "no R flag over BLE");
    // Asserted on MRP itself rather than on `wake_at`, which also reports when an abandoned
    // exchange could next be reclaimed (§4.10.5.3) and so is `Some` for any open exchange.
    assert!(
        !node
            .exchanges()
            .find(ble)
            .expect("open")
            .mrp
            .is_awaiting_ack(),
        "and no retransmission timer was armed for it"
    );

    // The same message over UDP does set it, and does arm one.
    let udp = node
        .open_to(
            SessionId::UNSECURED,
            ProtocolId::SECURE_CHANNEL,
            Peer::Udp(matter_kit::platform::PeerAddr::new([
                0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            at(0),
        )
        .expect("open");
    node.send(
        udp,
        opcode::PBKDF_PARAM_REQUEST,
        true,
        b"request",
        at(0),
        0,
        &mut scratch,
        &mut datagram,
    )
    .expect("send");
    assert_eq!(datagram[8] & 0x04, 0x04, "the R flag is set over UDP");
    assert!(
        node.exchanges()
            .find(udp)
            .expect("open")
            .mrp
            .is_awaiting_ack(),
        "and MRP is watching for the ack"
    );
}

/// Takes a reassembled SDU into the message layer, exactly as a UDP datagram would be.
fn deliver(to: &mut Stack, mut sdu: Vec<u8>, now: Instant) -> (ExchangeKey, u8, Vec<u8>) {
    match to
        .receive(&mut sdu, HANDLE, now)
        .expect("a well-formed Matter message")
    {
        Delivered::Message {
            exchange,
            header,
            payload,
            needs_ack,
        } => {
            assert!(
                !needs_ack,
                "§4.12.4: a message over BTP carries no R flag, so none is owed"
            );
            (exchange, header.opcode, payload.to_vec())
        }
        other => panic!("expected a protocol message, got {other:?}"),
    }
}
