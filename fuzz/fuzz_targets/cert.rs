//! Matter certificates arrive from the network during commissioning and CASE, before
//! anything has been authenticated. The decoder is therefore one of the few parsers in this
//! crate whose bytes a completely untrusted peer chooses.
//!
//! Two properties, of increasing strength:
//!
//! 1. Decoding never panics, however malformed the input, and anything that decodes can be
//!    encoded back — a decoder that accepts what the encoder cannot emit means the two
//!    halves disagree about what a certificate is.
//! 2. Encoding is a **fixed point**: decoding and re-encoding the output reproduces it
//!    exactly. §6.5.2 makes the Matter TLV a re-spelling of an X.509 certificate whose
//!    signature is over regenerated DER, so a decoder that silently reordered a DN, moved an
//!    extension or dropped the `PrintableString` marker would produce a certificate that
//!    will not verify — and that failure would surface far from here, as an unexplained CASE
//!    rejection.
//!
//! The first pass is deliberately not required to be byte-identical to the input. Matter TLV
//! admits several widths for the same integer and this crate writes the narrowest, so a
//! certificate encoded with a wider one re-encodes shorter. That normalisation is
//! value-preserving and invisible to the DER; anything that is *not* value-preserving shows
//! up as a difference on the second pass, which is what this asserts.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::cert::{CERT_TLV_MAX, MatterCertificate};

fuzz_target!(|data: &[u8]| {
    let Ok(first) = MatterCertificate::decode(data) else {
        return;
    };

    let mut buf = [0u8; CERT_TLV_MAX];
    let once = first
        .encode(&mut buf)
        .expect("a decoded certificate re-encodes");

    let mut again = [0u8; CERT_TLV_MAX];
    let len = once.len();
    again[..len].copy_from_slice(once);
    let second = MatterCertificate::decode(&again[..len]).expect("its own output decodes");
    assert_eq!(second, first, "a round trip changed the certificate");

    let mut twice = [0u8; CERT_TLV_MAX];
    let twice = second.encode(&mut twice).expect("re-encodes");
    assert_eq!(twice, &again[..len], "encoding is not a fixed point");

    // Whatever `validate` decides, it decides without panicking — and a certificate it
    // accepts must have a type, since that is what it dispatches on.
    if first.validate().is_ok() {
        assert!(first.cert_type().is_some());
    }
});
