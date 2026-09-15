//! BTP reception against arbitrary GATT writes (Core §4.19).
//!
//! This is the first code a commissionee runs on anything a BLE peer writes to C1, and the
//! peer has proved nothing at all yet: BTP sits *below* PASE, so every octet here arrives
//! from a stranger within radio range. It also has state a stranger would like to move — a
//! reassembly buffer, a sequence number, two timers and a window.
//!
//! Four properties:
//!
//! 1. **Nothing panics**, whatever the bytes are, and no buffer is overrun.
//! 2. **A reassembled message never exceeds what its Beginning segment declared.** This is
//!    the one that matters most: the reassembly buffer is a fixed array, and a length that
//!    could be exceeded is the classic way a BLE stack is taken over.
//! 3. **A failure is final.** §4.19.4.5 and §4.19.4.6 close the session on a bad sequence
//!    number or a bad reassembly, and BTP has no way to resynchronise — so after an error the
//!    session must stay refused rather than quietly resume mid-message.
//! 4. **The window arithmetic stays within its bound.** `remote_window` and `own_window_free`
//!    are both derived from wrapping sequence numbers, which is exactly where an off-by-one
//!    turns into a peer that may send forever.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::platform::Instant;
use matter_kit::transport::btp::{
    Frame, HandshakeRequest, HandshakeResponse, MAX_SEGMENT, Received, Role, Session, negotiate,
};

/// Small enough that the fuzzer can actually fill it, large enough to segment.
const SDU: usize = 512;
const WINDOW: u8 = 4;

fn at(ms: u64) -> Instant {
    Instant::from_micros(ms.saturating_mul(1000))
}

fuzz_target!(|data: &[u8]| {
    // The first octets choose the negotiated parameters, so the fuzzer explores the whole MTU
    // range rather than one configuration — the twenty-octet case has a different header
    // budget from the 244-octet one.
    let (mtu, rest) = match data.split_first() {
        Some((&first, rest)) => (23u16.saturating_add(u16::from(first)), rest),
        None => return,
    };

    // A handshake request is also just bytes from a stranger.
    let _ = HandshakeRequest::decode(rest);
    let _ = HandshakeResponse::decode(rest);

    let request = HandshakeRequest::new(mtu, WINDOW);
    let Ok(agreed) = negotiate(&request, mtu, WINDOW) else {
        return;
    };
    // Whatever is negotiated, a segment never exceeds the characteristic's limit.
    assert!(agreed.segment_size() <= usize::from(MAX_SEGMENT));

    let mut session = Session::<SDU>::new(Role::Server, &agreed.params(), at(0));
    let mut clock = 0u64;
    let mut closed = false;

    // Each chunk is one GATT write. Several in a row, because the interesting failures are
    // cumulative: a reassembly that spans packets, a window that drifts.
    for chunk in rest.chunks(64) {
        if chunk.is_empty() {
            continue;
        }
        clock = clock.saturating_add(1);
        let now = at(clock);

        // Property 1: this must not panic for any input.
        let outcome = session.receive(chunk, now);

        // Property 4: both counters stay inside the negotiated window.
        assert!(session.remote_window() <= WINDOW);
        assert!(session.own_window_free() <= WINDOW);

        match outcome {
            Ok(Received::Message) => {
                assert!(!closed, "a closed session must not deliver a message");
                // Property 2: the reassembled SDU fits the buffer and matches what the
                // Beginning segment promised — `receive` checks the latter, and a message
                // longer than `SDU` could only mean the bound was not enforced.
                assert!(session.message().len() <= SDU);
                session.take_message();
            }
            Ok(Received::Partial | Received::Ack) => {
                assert!(!closed, "a closed session must not accept more segments");
            }
            Err(_) => closed = true,
        }

        // Polling is safe at any point, and never produces an over-long packet.
        let mut out = [0u8; 256];
        if let Ok(Some(n)) = session.poll_send(now, &mut out) {
            assert!(n <= agreed.segment_size(), "a packet never exceeds the MTU");
            // Anything this session emits is a frame it could itself decode.
            let frame = Frame::decode(&out[..n]).expect("own output must be well-formed");
            assert!(frame.payload.len() <= agreed.segment_size());
        }
        // And the timers never resolve to something a scheduler would spin on.
        let _ = session.wake_at();
        let _ = session.poll_timeout(now);
    }
});
