//! The CASE message parsers face the network before anything is authenticated.
//!
//! A Sigma1 in particular is the very first thing a commissioned device parses from a
//! stranger: it arrives on an unsecured session, from anyone who can reach the port, and the
//! device must decide from it alone whether to spend an ECDH and a signature answering. So
//! the parser has to be total, and it has to preserve enough to answer correctly.
//!
//! Round-tripping is the property worth asserting. Every CASE key is salted with the hash of
//! the messages exchanged, so a decoder that dropped or altered a field would produce a
//! session where the two peers hold different keys — a failure that surfaces as an
//! unexplained decryption error one message later, on the other node.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::sc::{Sigma1, Sigma2, Sigma2Resume, Sigma3};

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 2048];

    if let Ok(sigma1) = Sigma1::decode(data) {
        let encoded = sigma1
            .encode(&mut buf)
            .expect("a decoded Sigma1 re-encodes");
        let len = encoded.len();
        let mut again = [0u8; 2048];
        again[..len].copy_from_slice(encoded);
        let round = Sigma1::decode(&again[..len]).expect("its own output decodes");
        // `encoded` differs between the two — one borrows the input, one the copy — so the
        // fields are compared rather than the structs.
        assert_eq!(round.initiator_random, sigma1.initiator_random);
        assert_eq!(round.initiator_session_id, sigma1.initiator_session_id);
        assert_eq!(round.destination_id, sigma1.destination_id);
        assert_eq!(round.initiator_eph_pub_key, sigma1.initiator_eph_pub_key);
        assert_eq!(round.resumption_id, sigma1.resumption_id);
        assert_eq!(round.initiator_resume_mic, sigma1.initiator_resume_mic);
        assert_eq!(round.is_resumption(), sigma1.is_resumption());
    }

    if let Ok(sigma2) = Sigma2::decode(data) {
        let encoded = sigma2
            .encode(&mut buf)
            .expect("a decoded Sigma2 re-encodes");
        let len = encoded.len();
        let mut again = [0u8; 2048];
        again[..len].copy_from_slice(encoded);
        let round = Sigma2::decode(&again[..len]).expect("its own output decodes");
        assert_eq!(round.responder_random, sigma2.responder_random);
        assert_eq!(round.responder_session_id, sigma2.responder_session_id);
        assert_eq!(round.responder_eph_pub_key, sigma2.responder_eph_pub_key);
        assert_eq!(round.encrypted2, sigma2.encrypted2);
    }

    if let Ok(sigma3) = Sigma3::decode(data) {
        let encoded = Sigma3::encode(sigma3.encrypted3, &mut buf).expect("re-encodes");
        let len = encoded.len();
        let mut again = [0u8; 2048];
        again[..len].copy_from_slice(encoded);
        let round = Sigma3::decode(&again[..len]).expect("its own output decodes");
        assert_eq!(round.encrypted3, sigma3.encrypted3);
    }

    if let Ok(resume) = Sigma2Resume::decode(data) {
        let encoded = resume.encode(&mut buf).expect("re-encodes");
        let len = encoded.len();
        let mut again = [0u8; 2048];
        again[..len].copy_from_slice(encoded);
        assert_eq!(
            Sigma2Resume::decode(&again[..len]).expect("decodes"),
            resume
        );
    }
});
