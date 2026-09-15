//! The Check-In Protocol against arbitrary messages (Core §4.22).
//!
//! A Check-In message is **sessionless** — that is its whole purpose, since it exists to
//! recover a session that was lost — so this parser runs on bytes from anyone within reach of
//! the network, with no session, no exchange and no prior authentication in front of it. The
//! only thing standing between it and the client's state is a 128-bit key.
//!
//! Four properties:
//!
//! 1. **Nothing panics**, whatever the bytes are.
//! 2. **Nothing opens without the key.** No sequence of bytes ever decrypts under a key it was
//!    not encrypted with — which is also how a client *identifies* the sender (§4.22.4.2 step
//!    2), so a false positive is not a decode error, it is the wrong device.
//! 3. **The counter and the nonce always agree.** §4.22.4.2 step 4 re-derives the nonce from
//!    the decrypted counter, and a message that opens must satisfy it. The specification
//!    publishes a vector (Test 6) that decrypts cleanly and fails this, so it is not implied
//!    by the AEAD.
//! 4. **The replay window only moves forward.** A registration's offset never decreases,
//!    whatever arrives, and a rejected message never moves it at all — otherwise one replayed
//!    message could jump the window past check-ins that have not been sent yet.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::crypto::SymmetricKey;
use matter_kit::icd::checkin::{self, Registration};

fuzz_target!(|data: &[u8]| {
    let Some((&seed, rest)) = data.split_first() else {
        return;
    };
    // Two keys: one the messages below may have been built with, one that must never open
    // anything.
    let key = SymmetricKey::new([seed; 16]);
    let stranger = SymmetricKey::new([seed ^ 0xFF; 16]);

    let mut registration = Registration::new(key.clone(), u32::from(seed));
    let mut last_offset = registration.offset();

    for chunk in rest.chunks(64) {
        if chunk.is_empty() {
            continue;
        }
        // Each step decrypts in place, so each gets its own copy of the same bytes.
        let mut scratch = [0u8; 64];
        let take = |into: &mut [u8; 64]| -> bool {
            let Some(slot) = into.get_mut(..chunk.len()) else {
                return false;
            };
            slot.copy_from_slice(chunk);
            true
        };

        // Property 2: a key this was not built with never opens it. A false positive here is
        // a client attributing a check-in to the wrong device.
        if !take(&mut scratch) {
            continue;
        }
        assert!(
            checkin::decrypt(&stranger, &mut scratch[..chunk.len()]).is_err(),
            "a stranger's key opened a message"
        );

        // Properties 1 and 3.
        take(&mut scratch);
        if let Ok(message) = checkin::decrypt(&key, &mut scratch[..chunk.len()]) {
            let counter = message.counter;
            let derived = checkin::nonce(&key, counter).expect("nonce");
            let Some(received) = chunk.get(..derived.len()) else {
                continue;
            };
            assert_eq!(
                received,
                derived.as_slice(),
                "§4.22.4.2 step 4: the plaintext counter must be the one the nonce came from"
            );
        }

        // Property 4.
        take(&mut scratch);
        let accepted = registration.accept(&mut scratch[..chunk.len()]).is_ok();
        let offset = registration.offset();
        if accepted {
            assert!(offset > last_offset, "an accepted message moves the window on");
        } else {
            assert_eq!(offset, last_offset, "a rejected message moves nothing");
        }
        last_offset = offset;
    }

    // A registration this far along has to be replaced before its nonces repeat.
    if registration.offset() >= (1 << 31) {
        assert!(registration.needs_key_refresh());
    }
});
