//! Matter over Wi-Fi Public Action Frames (Core §4.20), end to end.
//!
//! §4.20.2: "The PAFTP frame format is identical to BTP frame format", and everything after the
//! handshake — segmentation, sequence numbers, receive windows, acknowledgements — is BTP's
//! rules with the word BTP replaced. So the thing worth testing is that the *shared* session
//! really does carry PAFTP traffic, and that the one place the two differ does differ.
//!
//! That one place is the frame size. A BTP segment is `ATT_MTU - 3`, capped at 244; a PAFTP
//! segment is a Service Specific Info length — 350 by default — less the PAFTP header. A module
//! that reused BTP's arithmetic would understate every segment, and nothing but a test that
//! counts octets would notice.

#![cfg(all(feature = "std", feature = "paf"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::platform::Instant;
use matter_kit::transport::paftp::{
    self, HandshakeRequest, HandshakeResponse, Received, Role, Session,
};

type Paftp = Session<2048>;

fn at(secs: u64) -> Instant {
    Instant::from_micros(secs * 1_000_000)
}

/// §4.20.3.3's handshake, with the two ends offering different limits.
fn handshake(device_ssi: u16, device_window: u8) -> (Paftp, Paftp, HandshakeResponse) {
    let mut frame = [0u8; 64];
    let n = HandshakeRequest::new(paftp::DEFAULT_SSI_LENGTH, 6)
        .encode(&mut frame)
        .expect("encode");

    let offered = HandshakeRequest::decode(&frame[..n]).expect("the device reads the request");
    let agreed = paftp::negotiate(&offered, device_ssi, device_window).expect("a shared version");
    let n = agreed.encode(&mut frame).expect("encode");
    let confirmed =
        HandshakeResponse::decode(&frame[..n]).expect("the commissioner reads the response");
    assert_eq!(confirmed, agreed);

    (
        Session::new(Role::Client, &confirmed.params(), at(0)),
        Session::new(Role::Server, &confirmed.params(), at(0)),
        confirmed,
    )
}

/// Carries one message from `tx` to `rx`, letting either end acknowledge as the window demands.
fn carry(tx: &mut Paftp, rx: &mut Paftp, sdu: &[u8]) -> (Vec<u8>, usize, usize) {
    tx.send(sdu).expect("no other SDU is in flight");
    let mut frame = [0u8; 512];
    let (mut packets, mut largest) = (0usize, 0usize);
    for _ in 0..4096 {
        if let Some(n) = tx.poll_send(at(1), &mut frame).expect("segment") {
            packets += 1;
            largest = largest.max(n);
            if rx.receive(&frame[..n], at(1)).expect("reassemble") == Received::Message {
                let message = rx.message().to_vec();
                rx.take_message();
                return (message, packets, largest);
            }
        } else if let Some(n) = rx.poll_send(at(1), &mut frame).expect("acknowledgement") {
            packets += 1;
            tx.receive(&frame[..n], at(1)).expect("acknowledgement");
        } else {
            panic!("neither peer can make progress: the session has deadlocked");
        }
    }
    panic!("the transfer did not terminate");
}

#[test]
fn a_matter_message_crosses_a_paftp_session_in_both_directions() {
    let (mut commissioner, mut device, agreed) = handshake(paftp::DEFAULT_SSI_LENGTH, 4);
    assert_eq!(agreed.window, 4, "the device's window is the smaller");
    assert_eq!(agreed.ssi_length, paftp::DEFAULT_SSI_LENGTH);

    // A PASE-sized message: one frame each way, because 345 octets is most of a Matter message.
    let request: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
    let (got, packets, largest) = carry(&mut commissioner, &mut device, &request);
    assert_eq!(got, request);
    assert_eq!(packets, 1, "200 octets fits one Public Action Frame");
    assert!(largest <= usize::from(paftp::DEFAULT_SSI_LENGTH));

    let response: Vec<u8> = (0..64u8).collect();
    let (got, _, _) = carry(&mut device, &mut commissioner, &response);
    assert_eq!(got, response);
}

#[test]
fn a_message_larger_than_one_frame_is_segmented_and_reassembled() {
    // §4.20.3.5's segmentation, which is BTP's — the point of the test is that the *shared*
    // session does it with PAFTP's frame size rather than BTP's.
    let (mut commissioner, mut device, agreed) = handshake(paftp::DEFAULT_SSI_LENGTH, 4);
    let segment = agreed.segment_size();
    assert_eq!(
        segment, 345,
        "350 less the PAFTP header, not BTP's ATT_MTU - 3"
    );

    let big: Vec<u8> = (0..1500u16).map(|i| (i % 251) as u8).collect();
    let (got, packets, _) = carry(&mut commissioner, &mut device, &big);
    assert_eq!(got, big);
    // Five segments of at most 345 octets, plus whatever acknowledgements the window forced.
    assert!(
        packets >= 5,
        "1500 octets needs at least five frames, got {packets}"
    );
}

#[test]
fn a_narrow_frame_still_completes() {
    // A chipset that can only manage a small Service Specific Info turns the same message into
    // many more frames, and the receive window closes part way through every one of them. The
    // transfer continues only because §4.20.3.8's stand-alone acknowledgement exists.
    let (mut commissioner, mut device, agreed) = handshake(64, 2);
    assert_eq!(agreed.segment_size(), 59);

    let message: Vec<u8> = (0..600u16).map(|i| (i % 251) as u8).collect();
    let (got, packets, largest) = carry(&mut commissioner, &mut device, &message);
    assert_eq!(got, message);
    assert!(largest <= 64, "no frame exceeds the negotiated length");
    assert!(packets > 10, "a narrow frame means many of them");
}

#[test]
fn the_two_handshakes_are_not_interchangeable() {
    // Byte for byte the same shape, and a different meaning in the middle: BTP's 16-bit field
    // is a GATT MTU that three octets come off, PAFTP's is a frame length that five do. Reading
    // one as the other would negotiate a 350-octet segment over a 23-octet BLE connection.
    let paf = HandshakeResponse {
        version: paftp::VERSION,
        ssi_length: 350,
        window: 4,
    };
    let mut buf = [0u8; 16];
    let n = paf.encode(&mut buf).unwrap();

    let as_btp = matter_kit::transport::btp::HandshakeResponse::decode(&buf[..n]).unwrap();
    assert_eq!(as_btp.att_mtu, 350, "the octets are the same");
    assert_eq!(
        as_btp.segment_size(),
        244,
        "but BTP caps at MAX_SEGMENT and subtracts a GATT header"
    );
    assert_eq!(paf.segment_size(), 345, "PAFTP does neither");
}

#[test]
fn a_window_of_zero_is_refused() {
    // §4.20.3.7's window is what admits a packet at all, so a session that negotiated zero
    // could never send one — and would look like a hang rather than a failure.
    let request = HandshakeRequest::new(350, 0);
    assert!(paftp::negotiate(&request, 350, 4).is_err());
}
