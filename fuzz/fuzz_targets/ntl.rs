//! NFC Transport Layer APDUs against arbitrary bytes (Core §4.21).
//!
//! An NFC reader is whatever is held against the device, and the APDU layer is the first code
//! that looks at what it sent. There is no session, no key, and no prior handshake beyond a
//! `SELECT` — so every field here, including the length that drives reassembly, is chosen by
//! whoever is holding the phone.
//!
//! Three properties:
//!
//! 1. **Nothing panics**, whatever the APDU is — in particular the `Lc` field, which says how
//!    many octets of the command are payload.
//! 2. **Reassembly never exceeds what was announced**, and never exceeds the buffer. §4.21.4.2's
//!    `P1`/`P2` is a length an attacker picks; the answer to one too large is `6A 84`, not a
//!    partial write.
//! 3. **A chain either completes exactly or produces nothing.** A message shorter or longer than
//!    its announced length would be handed to the message layer as a truncated Matter message,
//!    which fails its integrity check with nothing to say why.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::transport::ntl::{self, Reassembled, Reassembler, Selected, Status, Transport};

/// Small enough that the fuzzer reaches the "not enough memory" path.
const LIMIT: usize = 512;

fuzz_target!(|data: &[u8]| {
    // Every reader of the three, against the same bytes.
    let _ = ntl::is_select(data);
    let _ = Selected::decode(data);

    let mut device = Reassembler::<LIMIT>::new();
    let mut buffered = 0usize;

    // Each APDU in the stream, one after another: the fuzzer's bytes are a series of commands.
    let mut rest = data;
    while !rest.is_empty() {
        let Ok(command) = Transport::decode(rest) else {
            break;
        };
        // `Lc` and the fixed header say how long this command was.
        let consumed = 6usize.saturating_add(command.fragment.len());
        rest = rest.get(consumed..).unwrap_or(&[]);

        match device.push(&command) {
            Ok(Reassembled::More) => {
                buffered = buffered.saturating_add(command.fragment.len());
                assert!(
                    buffered <= usize::from(command.message_length),
                    "buffered more than the message announced"
                );
                assert!(device.message().len() <= LIMIT);
            }
            Ok(Reassembled::Message) => {
                let length = usize::from(command.message_length);
                // Property 3: exactly what was promised, or nothing.
                assert_eq!(device.message().len(), length);
                assert!(length <= LIMIT);
                device.take_message();
                buffered = 0;
            }
            Err(status) => {
                // Property 2: the two refusals are the only ones, and both reset the buffer.
                assert!(
                    status == Status::NOT_ENOUGH_MEMORY || status == Status::CONDITIONS_NOT_SATISFIED
                );
                assert!(device.message().is_empty(), "a refusal leaves nothing behind");
                buffered = 0;
            }
        }
    }
});
