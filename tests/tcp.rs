//! Matter over TCP: §4.5's stream framing, and the two rules a stream brings with it.
//!
//! A datagram transport hands the message layer a message. A stream hands it bytes, and the
//! only thing that says where one message ends is the length prefix §4.5 puts in front of it.
//! That makes two failures possible that UDP does not have — a message split across reads, and
//! a message too large to hold — and this file pins both.
//!
//! The prefix is checked against a hand-written expectation rather than against the crate's own
//! reader, because a framer written with the same mistake as the writer reads it back happily.
//! §4.5.1 is four octets, little-endian, *not* counting themselves.

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

use matter_kit::ErrorCode;
use matter_kit::platform::{Peer, PeerAddr};
use matter_kit::transport::tcp::{self, DATAGRAM_MAX, Framed, Framer, LENGTH_PREFIX};

/// Frames a message into a fresh `Vec`, the way a socket writer would.
fn wire(message: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; message.len() + LENGTH_PREFIX];
    tcp::frame(message, &mut buf).unwrap().to_vec()
}

/// Pushes every byte of `bytes` in chunks of `chunk`, collecting the messages that fall out.
fn feed<const N: usize>(framer: &mut Framer<N>, bytes: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let offered = &rest[..chunk.min(rest.len())];
        let taken = framer.push(offered).unwrap();
        rest = &rest[taken..];
        while let Framed::Message(message) = framer.poll().unwrap() {
            out.push(message.to_vec());
        }
        // Nothing was taken and nothing came out: the loop would spin.
        assert!(taken > 0 || rest.is_empty(), "push made no progress");
    }
    out
}

// --- §4.5.1: the prefix ---------------------------------------------------------------

#[test]
fn prefix_is_four_little_endian_octets() {
    // 0x0102 = 258 octets, so the low byte comes first and the high byte second.
    let message = vec![0xAAu8; 258];
    let framed = wire(&message);
    assert_eq!(&framed[..LENGTH_PREFIX], &[0x02, 0x01, 0x00, 0x00]);
    assert_eq!(&framed[LENGTH_PREFIX..], &message[..]);
}

#[test]
fn prefix_does_not_count_itself() {
    let framed = wire(b"12345");
    assert_eq!(u32::from_le_bytes(framed[..4].try_into().unwrap()), 5);
    assert_eq!(framed.len(), 5 + LENGTH_PREFIX);
}

#[test]
fn frame_refuses_a_buffer_that_cannot_hold_the_prefix_too() {
    let message = [0u8; 8];
    // Room for the message but not the four octets in front of it.
    let mut exact = [0u8; 8];
    assert_eq!(
        tcp::frame(&message, &mut exact).unwrap_err().code(),
        ErrorCode::BufferTooSmall
    );
    let mut room = [0u8; 8 + LENGTH_PREFIX];
    assert!(tcp::frame(&message, &mut room).is_ok());
}

// --- Reassembly -----------------------------------------------------------------------

#[test]
fn a_whole_message_arrives_whole() {
    let mut framer = Framer::<DATAGRAM_MAX>::new();
    assert_eq!(
        feed(&mut framer, &wire(b"hello"), usize::MAX),
        vec![b"hello".to_vec()]
    );
}

#[test]
fn a_message_split_one_octet_at_a_time_is_put_back_together() {
    let message: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
    let mut framer = Framer::<DATAGRAM_MAX>::new();
    assert_eq!(feed(&mut framer, &wire(&message), 1), vec![message]);
}

#[test]
fn a_prefix_split_across_reads_is_still_read() {
    let mut framer = Framer::<DATAGRAM_MAX>::new();
    let framed = wire(b"split");
    // Three octets of the prefix: not enough to know anything.
    assert_eq!(framer.push(&framed[..3]).unwrap(), 3);
    assert_eq!(framer.poll().unwrap(), Framed::Incomplete { needed: 1 });
    assert_eq!(framer.push(&framed[3..]).unwrap(), framed.len() - 3);
    assert_eq!(framer.poll().unwrap(), Framed::Message(b"split"));
}

#[test]
fn two_messages_in_one_read_come_out_in_order() {
    let mut framer = Framer::<DATAGRAM_MAX>::new();
    let mut stream = wire(b"first");
    stream.extend_from_slice(&wire(b"second"));
    stream.extend_from_slice(&wire(b"third"));
    assert_eq!(
        feed(&mut framer, &stream, usize::MAX),
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
}

#[test]
fn a_read_ending_mid_message_leaves_the_tail_for_the_next_one() {
    let mut framer = Framer::<DATAGRAM_MAX>::new();
    let mut stream = wire(b"aaaa");
    stream.extend_from_slice(&wire(b"bbbb"));
    // Cut three octets into the second message's body.
    let cut = stream.len() - 1;
    assert_eq!(feed(&mut framer, &stream[..cut], 7), vec![b"aaaa".to_vec()]);
    assert_eq!(feed(&mut framer, &stream[cut..], 7), vec![b"bbbb".to_vec()]);
}

#[test]
fn push_stops_at_a_message_boundary_rather_than_dropping_the_rest() {
    let mut framer = Framer::<DATAGRAM_MAX>::new();
    let mut stream = wire(b"one");
    stream.extend_from_slice(&wire(b"two"));
    // One framer holds one message: the first push takes exactly the first message.
    let taken = framer.push(&stream).unwrap();
    assert_eq!(taken, LENGTH_PREFIX + 3);
    assert_eq!(framer.poll().unwrap(), Framed::Message(b"one"));
    // And pushing again before polling takes nothing rather than losing bytes.
    assert_eq!(framer.push(&stream[taken..]).unwrap(), LENGTH_PREFIX + 3);
    assert_eq!(framer.poll().unwrap(), Framed::Message(b"two"));
}

#[test]
fn incomplete_says_how_many_more_octets_it_wants() {
    let mut framer = Framer::<DATAGRAM_MAX>::new();
    assert_eq!(
        framer.poll().unwrap(),
        Framed::Incomplete {
            needed: LENGTH_PREFIX
        }
    );
    let framed = wire(&[0u8; 100]);
    framer.push(&framed[..LENGTH_PREFIX + 40]).unwrap();
    assert_eq!(framer.poll().unwrap(), Framed::Incomplete { needed: 60 });
    assert_eq!(framer.buffered(), 40);
}

#[test]
fn a_message_of_exactly_the_maximum_size_is_accepted() {
    const MAX: usize = 512;
    let message = vec![0x5Au8; MAX];
    let mut framer = Framer::<MAX>::new();
    assert_eq!(framer.max_message(), MAX);
    assert_eq!(feed(&mut framer, &wire(&message), 64), vec![message]);
}

// --- §4.15.2.3: a message too large is fatal ------------------------------------------

#[test]
fn one_octet_past_the_maximum_is_refused() {
    const MAX: usize = 512;
    let mut framer = Framer::<MAX>::new();
    let framed = wire(&vec![0u8; MAX + 1]);
    assert_eq!(
        framer.push(&framed).unwrap_err().code(),
        ErrorCode::MessageTooLarge
    );
}

#[test]
fn a_too_large_message_latches_the_failure() {
    const MAX: usize = 64;
    let mut framer = Framer::<MAX>::new();
    assert!(!framer.is_failed());
    let mut stream = wire(&[0u8; MAX + 1]);
    // Whatever follows is perfectly good framing; it must not be read anyway, because the
    // framer has lost its place in the stream.
    stream.extend_from_slice(&wire(b"well-formed"));
    assert!(framer.push(&stream).is_err());
    assert!(framer.is_failed());
    assert_eq!(
        framer.push(&wire(b"well-formed")).unwrap_err().code(),
        ErrorCode::MessageTooLarge
    );
    assert_eq!(
        framer.poll().unwrap_err().code(),
        ErrorCode::MessageTooLarge
    );
}

#[test]
fn the_length_is_checked_before_the_body_is_buffered() {
    // 4 GiB announced, nothing sent: a framer that waited for the bytes before judging the
    // length would sit there forever, and one that trusted it would try to allocate it.
    let mut framer = Framer::<1024>::new();
    let err = framer.push(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::MessageTooLarge);
    assert!(framer.is_failed());
}

#[test]
fn a_zero_length_prefix_is_a_lost_stream() {
    // §4.4's header alone is eight octets, so a prefix of zero cannot be a message. Accepting
    // it would hand the message layer an empty slice on every poll, forever.
    let mut framer = Framer::<1024>::new();
    assert_eq!(
        framer.push(&[0, 0, 0, 0]).unwrap_err().code(),
        ErrorCode::MessageTooLarge
    );
    assert!(framer.is_failed());
}

#[test]
fn too_large_encodes_a_status_report_with_general_code_17() {
    let mut buf = [0u8; 32];
    let report = tcp::too_large(&mut buf).unwrap();
    // §4.10.1.1: a u16 GeneralCode, a u32 ProtocolId, a u16 ProtocolCode, all little-endian.
    // MESSAGE_TOO_LARGE is 17 and the protocol is SECURE_CHANNEL (vendor 0x0000, id 0x0000).
    assert_eq!(report, &[17, 0, 0, 0, 0, 0, 0, 0]);
}

// --- §4.15: MRP does not run on a stream ----------------------------------------------

const ADDR: PeerAddr = PeerAddr::new([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

#[test]
fn a_tcp_peer_is_reliable_without_mrp() {
    // §4.15: "a node that is using TCP as the underlying transport protocol SHALL NOT use MRP
    // reliability semantics on its message exchanges."
    assert!(Peer::Tcp(ADDR, 7).is_reliable());
    assert!(Peer::Ble(7).is_reliable());
    assert!(!Peer::Udp(ADDR).is_reliable());
}

#[test]
fn a_tcp_peer_still_has_an_address() {
    // Unlike BLE: a reply goes back to an IPv6 address, down a particular connection.
    assert_eq!(Peer::Tcp(ADDR, 7).addr(), Some(ADDR));
    assert_eq!(Peer::Ble(7).addr(), None);
}

#[test]
fn the_connection_handle_distinguishes_two_streams_to_one_address() {
    // §4.15.2 allows more than one connection between the same pair of nodes, and a reply has
    // to go back down the one the request came up.
    assert_ne!(Peer::Tcp(ADDR, 1), Peer::Tcp(ADDR, 2));
    assert_ne!(Peer::Tcp(ADDR, 1), Peer::Udp(ADDR));
}

#[test]
fn only_tcp_carries_a_large_message() {
    // §4.4.4 caps a datagram at 1280 octets; the `L` quality in the data model is what says a
    // command needs more, and this is what an application checks it against.
    assert!(Peer::Tcp(ADDR, 1).supports_large_payloads());
    assert!(!Peer::Udp(ADDR).supports_large_payloads());
    assert!(!Peer::Ble(1).supports_large_payloads());
}

// --- §4.4.4, §4.15.1: a message that would not fit in a datagram --------------------------

/// A stream is not only a different way of carrying a datagram — it raises the ceiling.
///
/// §4.4.4 caps a UDP message at 1280 octets, and §4.15.1 is why TCP exists: "The maximum size
/// of the payload for messages sent over a TCP connection is 1,048,576 octets". A node that
/// framed every message through a 1280-octet buffer could never send one, whatever the
/// transport underneath — so the buffer the message layer joins the header and payload in is
/// the caller's, sized from the transport it is actually on.
#[cfg(feature = "rustcrypto")]
mod over_a_stream {
    use matter_kit::config::DefaultConfig;
    use matter_kit::messaging::Messaging;
    use matter_kit::msg::ProtocolId;
    use matter_kit::platform::{Instant, Peer};
    use matter_kit::transport::tcp::{self, Framed, Framer};

    use super::{ADDR, LENGTH_PREFIX};

    type Stack = Messaging<DefaultConfig>;

    const CONNECTION: Peer = Peer::Tcp(ADDR, 0x0042);
    /// Larger than §4.4.4's datagram limit, and larger than the old fixed framing buffer.
    const PAYLOAD: usize = 4000;

    fn at(ms: u64) -> Instant {
        Instant::from_micros(ms * 1000)
    }

    #[test]
    fn a_four_kilobyte_message_frames_and_reassembles() {
        let mut node = Stack::new(0x3000, 0x200, 7);
        let exchange = node
            .open_unsecured_to(
                ProtocolId::SECURE_CHANNEL,
                CONNECTION,
                at(0),
                0xC0DE_0011_2233_4455,
            )
            .expect("open");

        let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
        let mut scratch = [0u8; 8192];
        let mut datagram = [0u8; 8192];
        let (len, _) = node
            .send(
                exchange,
                0x20,
                true,
                &payload,
                at(0),
                0,
                &mut scratch,
                &mut datagram,
            )
            .expect("a message larger than a datagram still frames");
        assert!(len > 1280, "the whole payload is in the message");

        // §4.12.4: no MRP on a stream, even though `reliable` was asked for. The R flag is bit
        // 2 of the Exchange Flags, the first octet of the protocol header — which begins where
        // the message header ends, and that is not a constant: an unsecured initiator encloses
        // §4.13.2.1's Ephemeral Initiator Node ID as a Source Node ID, so the header is eight
        // octets longer than a bare one.
        let (sent_header, _) =
            matter_kit::msg::MessageHeader::decode(&datagram[..len]).expect("decode");
        assert_eq!(
            datagram[sent_header.encoded_len()] & 0x04,
            0,
            "no R flag over TCP"
        );
        // On MRP itself, not on `wake_at`: that also reports when an abandoned exchange could
        // next be reclaimed (§4.10.5.3), so it is `Some` for any open exchange.
        assert!(
            !node
                .exchanges()
                .find(exchange)
                .expect("open")
                .mrp
                .is_awaiting_ack(),
            "and no retransmission timer"
        );

        // Onto the stream, and back off it.
        let mut wire = vec![0u8; len + LENGTH_PREFIX];
        let framed = tcp::frame(&datagram[..len], &mut wire)
            .expect("framed")
            .to_vec();

        let mut framer = Framer::<8192>::new();
        let mut rest = &framed[..];
        let mut message = Vec::new();
        while !rest.is_empty() {
            let taken = framer.push(rest).expect("push");
            rest = &rest[taken..];
            while let Framed::Message(whole) = framer.poll().expect("poll") {
                message = whole.to_vec();
            }
        }
        assert_eq!(message, &datagram[..len], "the message survives the stream");
        assert_eq!(&message[message.len() - PAYLOAD..], &payload[..]);
    }

    #[test]
    fn a_scratch_too_small_for_the_message_is_refused_rather_than_truncating() {
        // The buffer is the caller's, so getting it wrong has to be an error and not a short
        // message: a truncated payload would be encrypted and sent, and the peer would fail
        // the integrity check with nothing to say why.
        let mut node = Stack::new(0x3000, 0x200, 7);
        let exchange = node
            .open_unsecured_to(
                ProtocolId::SECURE_CHANNEL,
                CONNECTION,
                at(0),
                0xC0DE_0011_2233_4455,
            )
            .expect("open");
        let payload = [0u8; PAYLOAD];
        let mut small = [0u8; 256];
        let mut datagram = [0u8; 8192];
        assert!(
            node.send(
                exchange,
                0x20,
                true,
                &payload,
                at(0),
                0,
                &mut small,
                &mut datagram,
            )
            .is_err()
        );
    }
}
