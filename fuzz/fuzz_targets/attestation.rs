//! The attestation payloads a commissioner reads out of a device's responses.
//!
//! These are Matter TLV rather than DER, and each is inside a signature: the attestation
//! elements and the NOCSR elements are both signed with the device attestation key, and the
//! certification elements are signed by the CSA. So the property worth asserting is that a
//! decode followed by an encode reproduces the input exactly — a decoder that dropped a
//! field, widened an integer or reordered anything would produce a payload whose signature
//! no longer covers what it appears to say.
//!
//! Byte-identity with *arbitrary* input is not that property, for two reasons that are worth
//! separating:
//!
//! * Matter TLV admits several widths for one integer and this crate writes the narrowest, so
//!   a payload encoded with a wider one re-encodes shorter. That never affects a signature,
//!   because nothing verifies a re-encoding: `SignedData::content` is a borrow of the bytes
//!   that arrived, and `verify` covers those.
//! * `attestation-elements` and `nocsr-elements` permit vendor-specific fields this crate does
//!   not model and deliberately skips.
//!
//! So what is asserted is that encoding is a **fixed point** — decode, encode, decode again,
//! and nothing has changed. A field that was silently dropped, reordered or altered shows up
//! there; a width that was narrowed does not. Byte-exactness against the *specification's*
//! payloads, which are minimally encoded, is asserted in `tests/attestation_vectors.rs`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::attestation::cd::CertificationElements;
use matter_kit::attestation::nocsr::{MAX_NOCSR_ELEMENTS, NocsrElements};
use matter_kit::attestation::{AttestationElements, MAX_ATTESTATION_ELEMENTS};

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; MAX_ATTESTATION_ELEMENTS];

    if let Ok(cd) = CertificationElements::decode(data) {
        let encoded = cd
            .encode(&mut buf)
            .expect("a decoded declaration re-encodes");
        let len = encoded.len();
        let mut again = [0u8; MAX_ATTESTATION_ELEMENTS];
        again[..len].copy_from_slice(encoded);
        let round = CertificationElements::decode(&again[..len]).expect("its own output decodes");
        assert_eq!(round, cd, "a round trip changed the declaration");

        let mut twice = [0u8; MAX_ATTESTATION_ELEMENTS];
        let twice = round.encode(&mut twice).expect("re-encodes");
        assert_eq!(twice, &again[..len], "encoding is not a fixed point");
    }

    // attestation-elements: vendor fields are skipped, so compare the modelled fields after
    // a second decode rather than the bytes.
    if let Ok(elements) = AttestationElements::decode(data) {
        let encoded = elements.encode(&mut buf).expect("re-encodes");
        let len = encoded.len();
        let mut again = [0u8; MAX_ATTESTATION_ELEMENTS];
        again[..len].copy_from_slice(encoded);
        let round = AttestationElements::decode(&again[..len]).expect("its own output decodes");
        assert_eq!(round, elements, "a round trip changed the elements");
    }

    if let Ok(elements) = NocsrElements::decode(data) {
        let mut out = [0u8; MAX_NOCSR_ELEMENTS];
        let encoded = elements.encode(&mut out).expect("re-encodes");
        let len = encoded.len();
        let mut again = [0u8; MAX_NOCSR_ELEMENTS];
        again[..len].copy_from_slice(encoded);
        let round = NocsrElements::decode(&again[..len]).expect("its own output decodes");
        assert_eq!(round, elements, "a round trip changed the elements");
        // The CSR inside is DER, and parsing it must not panic whatever it holds.
        let _ = elements.parse_csr();
    }
});
