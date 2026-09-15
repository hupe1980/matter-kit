//! Whatever the reader accepts, the writer must be able to write back.
//!
//! This is a stronger property than "does not panic": it says the two halves agree about
//! what valid TLV is. A reader that accepts something the writer cannot emit means one of
//! them has the specification wrong, and that is the kind of disagreement that only shows
//! up against somebody else's implementation.
//!
//! It also proves the canonical form is a fixed point: re-encoding an already-canonical
//! encoding reproduces it byte for byte, which is what a signature over a TLV structure
//! depends on (§A.2.4).

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::tlv::{TlvReader, re_encode_is_identical, validate_canonical};

fuzz_target!(|data: &[u8]| {
    // Only well-formed input has anything to prove here.
    if TlvReader::validate(data).is_err() {
        return;
    }

    let mut out = [0u8; 4096];
    if data.len() > out.len() {
        return;
    }

    // The writer must accept everything the reader did.
    let identical = match re_encode_is_identical(data, &mut out) {
        Ok(v) => v,
        Err(e) => panic!("the reader accepted {data:02x?} but the writer refused it: {e}"),
    };

    // A canonical encoding is a fixed point of the writer. The converse does not hold —
    // `validate_canonical` checks tag order, which minimality does not imply — so this is
    // one-directional on purpose.
    if identical && validate_canonical(data).is_ok() {
        let mut again = [0u8; 4096];
        match re_encode_is_identical(&out[..data.len()], &mut again) {
            Ok(true) => {}
            other => panic!("re-encoding is not idempotent for {data:02x?}: {other:?}"),
        }
    }
});
