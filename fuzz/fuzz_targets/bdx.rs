//! BDX message parsing and transfer state against arbitrary bytes (Core §11.22).
//!
//! BDX runs inside a PASE or CASE session (§11.22.4), so the peer is authenticated — but it is
//! also the protocol that moves firmware images, and the one place in the stack where a
//! length, an offset and a block counter arrive together and are used to index a buffer. That
//! is the shape of a parser worth fuzzing.
//!
//! Four properties:
//!
//! 1. **Nothing panics**, whatever the payload is — including the four-and-eight-octet range
//!    fields, whose width comes from a bit in the message itself.
//! 2. **A decoded message re-encodes to the same bytes**, once the two spellings of an
//!    indefinite length (§11.22.5.1.5) are collapsed. A decoder that read a field from the
//!    wrong offset would not survive being written back.
//! 3. **A Receiver never accepts more than the negotiated length**, and never accepts a block
//!    larger than the negotiated Max Block Size. This is the one that guards the caller's
//!    buffer: the application writes `len` octets at `received()`.
//! 4. **A finished transfer stays finished.** §11.22.2.8 ends the session at BlockAckEOF, and
//!    nothing after it may be taken.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::bdx::{
    Block, BlockQueryWithSkip, Counter, Direction, Init, Limits, Parameters, ReceiveAccept,
    Receiver, SendAccept, Sender, negotiate,
};

/// Checks that a decoded message survives a round trip, and that encoding is canonical.
///
/// Byte-for-byte equality with the *input* is the wrong property: several fields have more
/// than one legal spelling — §11.22.5.1.5's zero-or-absent length, the RFU bits of a Range
/// Control octet — and a decoder is right to accept all of them. What must hold is that
/// re-encoding lands on one spelling and stays there, and that nothing is lost on the way.
macro_rules! round_trip {
    ($ty:ty, $message:expr) => {{
        let mut first = [0u8; 2048];
        if let Ok(n) = $message.encode(&mut first) {
            let canonical = first.get(..n).expect("encode reported what it wrote");
            let again = <$ty>::decode(canonical).expect("our own encoding decodes");
            assert_eq!(again, $message, "a round trip changed the message");
            let mut second = [0u8; 2048];
            let m = again
                .encode(&mut second)
                .expect("the same message encodes again");
            assert_eq!(
                second.get(..m),
                Some(canonical),
                "encoding is not canonical"
            );
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    // Every message format, against the same bytes: a payload that is a valid Init is very
    // unlikely to be a valid BlockQueryWithSkip, and both paths want exercising.
    let _ = Counter::decode(data);
    let _ = BlockQueryWithSkip::decode(data);

    if let Ok(block) = Block::decode(data) {
        round_trip!(Block, block);
    }
    if let Ok(accept) = SendAccept::decode(data) {
        round_trip!(SendAccept, accept);
    }
    if let Ok(accept) = ReceiveAccept::decode(data) {
        round_trip!(ReceiveAccept, accept);
    }

    let Ok(init) = Init::decode(data) else {
        return;
    };
    round_trip!(Init, init);

    // A real negotiation from whatever the fuzzer proposed, then a transfer driven by the
    // remaining bytes.
    let limits = Limits {
        max_block_size: 64,
        available: init.definite_length,
        ..Limits::default()
    };
    let Ok(agreed) = negotiate(Direction::Download, &init, &limits) else {
        return;
    };
    let accept = agreed.receive_accept(&[]);
    let Ok(mirrored) = Parameters::from_receive_accept(&init, &accept) else {
        return;
    };
    assert_eq!(agreed, mirrored, "both ends read one accept differently");

    let block_size = usize::from(agreed.max_block_size);
    let length = agreed.length;
    let mut sender = Sender::new(agreed);
    let mut receiver = Receiver::new(mirrored);

    // Each remaining octet is one step: its low bits are a block length, its top bit says EOF.
    for step in init.file_designator.iter().chain(init.metadata.iter()) {
        if receiver.is_complete() {
            break;
        }
        let len = usize::from(step & 0x3F);
        let eof = step & 0x80 != 0;
        if !agreed.control.sender_drive {
            let Ok(asked) = receiver.query() else { break };
            if sender.on_query(asked).is_err() {
                break;
            }
        }
        let Ok(counter) = sender.block(len, eof) else {
            continue;
        };
        assert!(len <= block_size, "a block past the negotiated size");
        receiver
            .on_block(counter, len, eof)
            .expect("a block the sender produced is one the receiver takes");
        assert!(len <= block_size);
        if let Some(length) = length {
            assert!(receiver.received() <= length, "past the negotiated length");
        }
        let Ok((_, acked)) = receiver.ack() else {
            break;
        };
        if sender.on_ack(acked, eof).is_err() {
            break;
        }
    }

    if receiver.is_complete() {
        // §11.22.2.8: the session ends at BlockAckEOF and nothing follows it.
        assert!(receiver.on_block(0, 1, false).is_err());
        assert!(receiver.ack().is_err());
        assert!(sender.is_complete());
        assert!(!sender.may_send());
        if let Some(length) = length {
            assert_eq!(receiver.received(), length, "a short transfer completed");
        }
    }
});
