//! Appendix F's attestation test vectors, run against this implementation.
//!
//! The specification publishes three complete worked examples, and between them they cover
//! every byte a commissioner has to get right during device attestation:
//!
//! * **F.1** — two Certification Declarations, each as both the TLV of its contents and the
//!   CMS `SignedData` that wraps and signs it. The second exercises every optional field:
//!   two product ids, `dac_origin_*`, and an `authorized_paa_list`.
//! * **F.2** — a Device Attestation Response: the `attestation_elements_message`, the
//!   `attestation_tbs` it is concatenated into, the SHA-256 of that, and the signature.
//! * **F.3** — a Node Operational CSR Response, with the PKCS#10 `CertificationRequest` and
//!   the `nocsr_elements_message` around it.
//!
//! Two of the signatures in these vectors were produced with a *fixed* `k` that the
//! specification states, while this crate signs deterministically per RFC 6979. So the
//! signature bytes cannot be reproduced — but they can be **verified**, which is the
//! direction a commissioner actually needs and the stronger check of the two: it fails if
//! any byte of the message this crate builds differs from the message the CSA signed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use hex_literal::hex;
use matter_kit::attestation::cd::CertificationElements;
use matter_kit::attestation::nocsr::{MAX_CSR_LEN, MAX_NOCSR_ELEMENTS};
use matter_kit::attestation::{
    AttestationElements, CertificationType, SignedData, attestation_tbs_hash, verify_attestation,
};
use matter_kit::attestation::{Csr, NocsrElements, build_csr, sign_nocsr, verify_nocsr};
use matter_kit::crypto::{KeyPurpose, KeyStore, SoftKeyStore};
use matter_kit::crypto::{PublicKey, SymmetricKey};
use matter_kit::msg::VendorId;

/// F.1, first example — the certification elements TLV (54 bytes).
const CD1_TLV: &[u8] = &hex!(
    "152400012501f1ff360205008018250334122c04135a494732303134315a42333330"
    "3030312d32342405002406002507942624080018"
);

/// F.1, first example — the CMS `SignedData` around it (235 bytes).
const CD1_CMS: &[u8] = &hex!(
    "3081e806092a864886f70d010702a081da3081d7020103310d300b06096086480165"
    "03040201304506092a864886f70d010701a0380436152400012501f1ff3602050080"
    "18250334122c04135a494732303134315a423333303030312d323424050024060025"
    "07942624080018317c307a020103801462fa823359acfaa9963e1cfa140addf504f3"
    "7160300b0609608648016503040201300a06082a8648ce3d04030204463044022043"
    "a63f2b943df33c38b3e02fcaa75fe3532aebbf5e63f5bbdbc0b1f01d3c4f6002204c"
    "1abf5f1807b81894b1576c47e4724e4d966c612ed3fa25c118c3f2b3f90369"
);

/// F.1, second example — every optional field present (90 bytes).
const CD2_TLV: &[u8] = &hex!(
    "152400012501f2ff360205018005028018250334122c04135a494732303134325a42"
    "3333303030322d3234240500240600250794262408002509f1ff250a0080360b1014"
    "785ce705b86b8f4e6fc793aa60cb43ea696882d51818"
);

/// F.1, second example — its CMS `SignedData` (273 bytes).
const CD2_CMS: &[u8] = &hex!(
    "3082010d06092a864886f70d010702a081ff3081fc020103310d300b060960864801"
    "6503040201306906092a864886f70d010701a05c045a152400012501f2ff36020501"
    "8005028018250334122c04135a494732303134325a423333303030322d3234240500"
    "240600250794262408002509f1ff250a0080360b1014785ce705b86b8f4e6fc793aa"
    "60cb43ea696882d51818317d307b020103801462fa823359acfaa9963e1cfa140add"
    "f504f37160300b0609608648016503040201300a06082a8648ce3d04030204473045"
    "02204ae9c9b7f8aa68610add84e41291fc8f4dc533fca29dc1fff2253c09cd32f775"
    "0221009c0a5fdef9e008d1cc8bb7c3959cdb65c46125cb7295081e47b5c131e4d1f4"
    "8c"
);

/// F.2 — `attestation_elements_message` (383 bytes).
const ATTESTATION_ELEMENTS: &[u8] = &hex!(
    "15310111013082010d06092a864886f70d010702a081ff3081fc020103310d300b06"
    "09608648016503040201306906092a864886f70d010701a05c045a152400012501f2"
    "ff360205018005028018250334122c04135a494732303134325a423333303030322d"
    "3234240500240600250794262408002509f1ff250a0080360b1014785ce705b86b8f"
    "4e6fc793aa60cb43ea696882d51818317d307b020103801462fa823359acfaa9963e"
    "1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d0403"
    "020447304502204ae9c9b7f8aa68610add84e41291fc8f4dc533fca29dc1fff2253c"
    "09cd32f7750221009c0a5fdef9e008d1cc8bb7c3959cdb65c46125cb7295081e47b5"
    "c131e4d1f48c300220e0421b91c6fdcdb40e2a4d2cf31db2b4e18b411b1d3ad4d12a"
    "9d90aa8e52fae22603fdc65b28d0f1ff3e0001001773616d706c655f76656e646f72"
    "5f726573657276656431d0f1ff3e0003001876656e646f725f726573657276656433"
    "5f6578616d706c6518"
);

/// F.2 — `attestation_tbs`, which is never sent (399 bytes).
const ATTESTATION_TBS: &[u8] = &hex!(
    "15310111013082010d06092a864886f70d010702a081ff3081fc020103310d300b06"
    "09608648016503040201306906092a864886f70d010701a05c045a152400012501f2"
    "ff360205018005028018250334122c04135a494732303134325a423333303030322d"
    "3234240500240600250794262408002509f1ff250a0080360b1014785ce705b86b8f"
    "4e6fc793aa60cb43ea696882d51818317d307b020103801462fa823359acfaa9963e"
    "1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d0403"
    "020447304502204ae9c9b7f8aa68610add84e41291fc8f4dc533fca29dc1fff2253c"
    "09cd32f7750221009c0a5fdef9e008d1cc8bb7c3959cdb65c46125cb7295081e47b5"
    "c131e4d1f48c300220e0421b91c6fdcdb40e2a4d2cf31db2b4e18b411b1d3ad4d12a"
    "9d90aa8e52fae22603fdc65b28d0f1ff3e0001001773616d706c655f76656e646f72"
    "5f726573657276656431d0f1ff3e0003001876656e646f725f726573657276656433"
    "5f6578616d706c65187a495305d07779a494dd39a0851b660d"
);

/// The public key of F.1's sample CSA CD signing certificate.
const CD_SIGNER_PUBLIC_KEY: [u8; 65] = hex!(
    "043c398922452b55caf389c25bd1bca4656952ccb90e8869249ad8474653014cbf"
    "95d687965e036b521c51037e6b8cedefca1eb44046694fa08882eed6519decba"
);

/// Its Subject Key Identifier, which is what the CMS names the signer by.
const CD_SIGNER_KEY_ID: [u8; 20] = hex!("62fa823359acfaa9963e1cfa140addf504f37160");

/// F.2's example Device Attestation public key.
const DAC_PUBLIC_KEY: [u8; 65] = hex!(
    "04ce5cf8efb05d4eee790d0a71d5c011bb747240dba21458845d33e34b0af66516"
    "33063a804b2ff85dcab2019a0ab6f5595775fe8d85fbd7a07c8e837da4d5a8b9"
);

/// F.2's example Device Attestation private key.
const DAC_PRIVATE_KEY: [u8; 32] =
    hex!("38f3e0a1f145ba1bf3e44b552def65273d1d8e276aa314ac742eb128933ba64b");

/// F.2's example attestation challenge — the third key a session derives.
const ATTESTATION_CHALLENGE: [u8; 16] = hex!("7a495305d07779a494dd39a0851b660d");

/// F.2's attestation nonce.
const ATTESTATION_NONCE: [u8; 32] =
    hex!("e0421b91c6fdcdb40e2a4d2cf31db2b4e18b411b1d3ad4d12a9d90aa8e52fae2");

/// The SHA-256 of `attestation_tbs` that F.2 states separately.
const ATTESTATION_TBS_HASH: [u8; 32] =
    hex!("1df105b13084c3cc13199edf07b8769ebe2e260d848f27a6cab66dd9a58ceab1");

/// F.2's attestation signature.
const ATTESTATION_SIGNATURE: [u8; 64] = hex!(
    "7982535d24cfe14a71ab0424cf0bacf1e345487ed50f1ac0bc259eccfb39081e"
    "d7a752188d9f76f9063703eb240f9cd14b0a43e741fe60ef2a81635aea5b484d"
);

// --- F.1: the Certification Declaration ------------------------------------------------------

#[test]
fn the_first_declaration_decodes_as_the_spec_states_its_inputs() {
    let cd = CertificationElements::decode(CD1_TLV).expect("decode");
    assert_eq!(cd.format_version, 1);
    assert_eq!(cd.vendor_id, VendorId(0xFFF1));
    assert_eq!(cd.product_ids.as_slice(), &[0x8000]);
    assert_eq!(cd.device_type_id, 0x1234);
    assert_eq!(cd.certificate_id, "ZIG20141ZB330001-24");
    assert_eq!(cd.security_level, 0);
    assert_eq!(cd.security_information, 0);
    assert_eq!(cd.version_number, 0x2694);
    assert_eq!(cd.certification_type, CertificationType::DevelopmentAndTest);
    assert_eq!(cd.dac_origin_vendor_id, None);
    assert_eq!(cd.dac_origin_product_id, None);
    assert_eq!(cd.authorized_paas, None);

    // An absent authorized_paa_list authorises whatever the commissioner already trusts.
    assert!(cd.authorizes_paa(&[0xAB; 20]));
    assert!(cd.covers_product(0x8000));
    assert!(!cd.covers_product(0x8001));
}

#[test]
fn the_second_declaration_exercises_every_optional_field() {
    let cd = CertificationElements::decode(CD2_TLV).expect("decode");
    assert_eq!(cd.vendor_id, VendorId(0xFFF2));
    assert_eq!(cd.product_ids.as_slice(), &[0x8001, 0x8002]);
    assert_eq!(cd.certificate_id, "ZIG20142ZB330002-24");
    assert_eq!(cd.dac_origin_vendor_id, Some(VendorId(0xFFF1)));
    assert_eq!(cd.dac_origin_product_id, Some(0x8000));

    let paas = cd.authorized_paas.as_ref().expect("authorized_paa_list");
    assert_eq!(paas.len(), 1);
    assert_eq!(paas[0], hex!("785ce705b86b8f4e6fc793aa60cb43ea696882d5"));
    // With a list present, only its members are authorised.
    assert!(cd.authorizes_paa(&hex!("785ce705b86b8f4e6fc793aa60cb43ea696882d5")));
    assert!(!cd.authorizes_paa(&CD_SIGNER_KEY_ID));
}

#[test]
fn both_declarations_re_encode_byte_for_byte() {
    // The TLV is what the CMS signature covers, so a decoder that lost or reordered a field
    // would produce a declaration that no longer verifies.
    let mut buf = [0u8; 256];
    for (name, tlv) in [("first", CD1_TLV), ("second", CD2_TLV)] {
        let cd = CertificationElements::decode(tlv).expect("decode");
        assert_eq!(cd.encode(&mut buf).expect("encode"), tlv, "{name}");
    }
}

#[test]
fn the_cms_wrapper_parses_and_its_signature_verifies() {
    // This is the check that matters: the signature is over the eContent octets directly,
    // because the SignerInfo carries no signedAttrs (RFC 5652 §5.4). A parser that assumed
    // signed attributes would hash the wrong thing and fail in a way that looks like a bad
    // key rather than a bad parse.
    let signer = PublicKey::from_bytes(CD_SIGNER_PUBLIC_KEY);
    for (name, cms, tlv) in [("first", CD1_CMS, CD1_TLV), ("second", CD2_CMS, CD2_TLV)] {
        let signed = SignedData::parse(cms).expect("parse");
        assert_eq!(signed.content, tlv, "{name}: eContent");
        assert_eq!(signed.signer_key_id, CD_SIGNER_KEY_ID, "{name}: signer");
        assert!(signed.verify(&signer).expect("verify"), "{name}: signature");
        // And the content parses as the elements it should.
        assert_eq!(
            signed.elements().expect("elements"),
            CertificationElements::decode(tlv).expect("decode"),
            "{name}"
        );
    }
}

#[test]
fn a_declaration_does_not_verify_under_the_wrong_key() {
    // Otherwise the test above would pass for a `verify` that always says yes.
    let signed = SignedData::parse(CD1_CMS).expect("parse");
    assert!(
        !signed
            .verify(&PublicKey::from_bytes(DAC_PUBLIC_KEY))
            .expect("verify")
    );
}

#[test]
fn a_tampered_declaration_does_not_verify() {
    // The eContent is inside the CMS, so changing *it* changes what the signature covers.
    // Which byte matters: a flip in the SignerInfo's key identifier, say, leaves the signed
    // content untouched and the signature still verifies — correctly. So the target is
    // located rather than guessed at.
    let content_at = CD1_CMS
        .windows(CD1_TLV.len())
        .position(|w| w == CD1_TLV)
        .expect("the eContent is in the CMS");

    let signer = PublicKey::from_bytes(CD_SIGNER_PUBLIC_KEY);
    let mut cms = [0u8; 512];
    // Every octet of the declaration's contents, one at a time.
    for offset in 0..CD1_TLV.len() {
        cms[..CD1_CMS.len()].copy_from_slice(CD1_CMS);
        cms[content_at + offset] ^= 0x01;
        let Ok(signed) = SignedData::parse(&cms[..CD1_CMS.len()]) else {
            // A flip that breaks the TLV's own framing is caught earlier, which is fine.
            continue;
        };
        assert_ne!(signed.content, CD1_TLV, "offset {offset}");
        assert!(
            !signed.verify(&signer).expect("verify"),
            "offset {offset} changed the declaration and it still verified"
        );
    }
}

#[test]
fn every_truncation_of_a_declaration_is_an_error_not_a_panic() {
    // A CD arrives from an unauthenticated device during commissioning.
    for len in 0..CD1_CMS.len() {
        let _ = SignedData::parse(&CD1_CMS[..len]);
    }
    for len in 0..CD1_TLV.len() {
        let _ = CertificationElements::decode(&CD1_TLV[..len]);
    }
}

#[test]
fn every_single_bit_flip_of_a_declaration_is_caught_or_survives() {
    // Either the parse fails, or it succeeds and the signature no longer verifies. What must
    // not happen is a declaration that parses to different contents and still verifies.
    let signer = PublicKey::from_bytes(CD_SIGNER_PUBLIC_KEY);
    let mut buf = [0u8; 512];
    for index in 0..CD1_CMS.len() {
        for bit in 0..8u32 {
            buf[..CD1_CMS.len()].copy_from_slice(CD1_CMS);
            buf[index] ^= 1 << bit;
            let Ok(signed) = SignedData::parse(&buf[..CD1_CMS.len()]) else {
                continue;
            };
            if signed.content == CD1_TLV
                && signed.signature.as_bytes()
                    == SignedData::parse(CD1_CMS)
                        .expect("orig")
                        .signature
                        .as_bytes()
            {
                // The flip landed somewhere the parse ignores; nothing to assert.
                continue;
            }
            assert!(
                !signed.verify(&signer).expect("verify"),
                "bit {bit} of byte {index} changed the declaration and it still verified"
            );
        }
    }
}

// --- F.2: the Device Attestation Response ----------------------------------------------------

#[test]
fn the_attestation_elements_decode_as_the_spec_states_its_inputs() {
    let elements = AttestationElements::decode(ATTESTATION_ELEMENTS).expect("decode");
    assert_eq!(elements.attestation_nonce, ATTESTATION_NONCE);
    // "-> Desired timestamp in epoch-s: 677103357".
    assert_eq!(elements.timestamp, 677_103_357);
    assert_eq!(elements.firmware_information, None, "F.2 omits it");
    // The embedded declaration is F.1's second example, verbatim.
    assert_eq!(elements.certification_declaration, CD2_CMS);
}

#[test]
fn the_vendor_specific_fields_are_skipped_not_stumbled_over() {
    // F.2 carries two fully-qualified vendor tags, which §11.18.4.7 permits and which a
    // commissioner "MAY ignore". Ignoring them must not desynchronise the parse — the
    // timestamp that follows them is the proof it did not.
    let elements = AttestationElements::decode(ATTESTATION_ELEMENTS).expect("decode");
    assert_eq!(elements.timestamp, 677_103_357);
    // And the TLV is well-formed all the way to the end.
    matter_kit::tlv::TlvReader::validate(ATTESTATION_ELEMENTS).expect("valid TLV");
}

#[test]
fn the_attestation_tbs_is_the_elements_followed_by_the_challenge() {
    // §11.18.4.7 step 3. The vector states the concatenation explicitly, which is worth
    // pinning because the challenge never appears on the wire and a wrong one produces a
    // signature failure with nothing to inspect.
    assert_eq!(
        &ATTESTATION_TBS[..ATTESTATION_ELEMENTS.len()],
        ATTESTATION_ELEMENTS
    );
    assert_eq!(
        &ATTESTATION_TBS[ATTESTATION_ELEMENTS.len()..],
        ATTESTATION_CHALLENGE
    );
}

#[test]
fn the_attestation_tbs_hash_matches_the_spec() {
    // The one intermediate value checkable without a private key, so a disagreement here
    // localises to the concatenation rather than to the signature.
    let hash = attestation_tbs_hash(
        ATTESTATION_ELEMENTS,
        &SymmetricKey::new(ATTESTATION_CHALLENGE),
    )
    .expect("hash");
    assert_eq!(hash, ATTESTATION_TBS_HASH);
}

#[test]
fn the_attestation_signature_verifies() {
    // The end of the exercise, and the check a commissioner actually performs.
    assert!(
        verify_attestation(
            &PublicKey::from_bytes(DAC_PUBLIC_KEY),
            ATTESTATION_ELEMENTS,
            &SymmetricKey::new(ATTESTATION_CHALLENGE),
            &matter_kit::crypto::Signature::from_bytes(ATTESTATION_SIGNATURE),
        )
        .expect("verify")
    );
}

#[test]
fn the_attestation_signature_is_bound_to_its_session() {
    // The whole point of the challenge: a recorded response cannot be replayed into a
    // different session, because a different session has a different challenge.
    let mut other = ATTESTATION_CHALLENGE;
    other[0] ^= 0x01;
    assert!(
        !verify_attestation(
            &PublicKey::from_bytes(DAC_PUBLIC_KEY),
            ATTESTATION_ELEMENTS,
            &SymmetricKey::new(other),
            &matter_kit::crypto::Signature::from_bytes(ATTESTATION_SIGNATURE),
        )
        .expect("verify")
    );
}

#[test]
fn a_changed_nonce_breaks_the_attestation() {
    // And the nonce is inside the signed elements, so a commissioner's freshness check and
    // the signature agree rather than being two independent hopes.
    let mut elements = [0u8; 512];
    elements[..ATTESTATION_ELEMENTS.len()].copy_from_slice(ATTESTATION_ELEMENTS);
    // The nonce is the 32 octets following its context-2 octet-string header.
    let at = ATTESTATION_ELEMENTS
        .windows(32)
        .position(|w| w == ATTESTATION_NONCE)
        .expect("nonce is in the message");
    elements[at] ^= 0x01;
    assert!(
        !verify_attestation(
            &PublicKey::from_bytes(DAC_PUBLIC_KEY),
            &elements[..ATTESTATION_ELEMENTS.len()],
            &SymmetricKey::new(ATTESTATION_CHALLENGE),
            &matter_kit::crypto::Signature::from_bytes(ATTESTATION_SIGNATURE),
        )
        .expect("verify")
    );
}

#[test]
fn the_embedded_declaration_verifies_from_inside_the_attestation() {
    // The two proofs chain: the attestation signature says "this device holds the DAC key",
    // and the declaration inside it says "the CSA certified this device type".
    let elements = AttestationElements::decode(ATTESTATION_ELEMENTS).expect("decode");
    let signed = SignedData::parse(elements.certification_declaration).expect("parse");
    assert!(
        signed
            .verify(&PublicKey::from_bytes(CD_SIGNER_PUBLIC_KEY))
            .expect("verify")
    );
    let cd = signed.elements().expect("elements");
    assert_eq!(cd.vendor_id, VendorId(0xFFF2));
    assert_eq!(cd.dac_origin_vendor_id, Some(VendorId(0xFFF1)));
}

// --- F.3: the Node Operational CSR Response --------------------------------------------------

/// F.3 — the PKCS#10 `CertificationRequest` (221 bytes).
const CSR_DER: &[u8] = &hex!(
    "3081da308181020100300e310c300a060355040a0c034353413059301306072a8648"
    "ce3d020106082a8648ce3d030107034200045ca279e36682c2d46ce7d4cf89678467"
    "08b5b9f85b9cdafd8ca8852612cb0f0c7a71314ec8dc9c9634ddeefee9f63f0e8bd7"
    "dacfc3b6a4532aadd89a9651cd6ea011300f06092a864886f70d01090e3102300030"
    "0a06082a8648ce3d040302034800304502200e675ee1b3bbfe152a174af535e22d55"
    "ce10c150cac01b3118de05e8fd9f1048022100d88c57cc6e74f0e5488a26167a07fd"
    "6dbef1aaad721c580b6eae21be5e6d0c72"
);

/// F.3 — `nocsr_elements_message` (314 bytes).
const NOCSR_ELEMENTS: &[u8] = &hex!(
    "153001dd3081da308181020100300e310c300a060355040a0c034353413059301306"
    "072a8648ce3d020106082a8648ce3d030107034200045ca279e36682c2d46ce7d4cf"
    "8967846708b5b9f85b9cdafd8ca8852612cb0f0c7a71314ec8dc9c9634ddeefee9f6"
    "3f0e8bd7dacfc3b6a4532aadd89a9651cd6ea011300f06092a864886f70d01090e31"
    "023000300a06082a8648ce3d040302034800304502200e675ee1b3bbfe152a174af5"
    "35e22d55ce10c150cac01b3118de05e8fd9f1048022100d88c57cc6e74f0e5488a26"
    "167a07fd6dbef1aaad721c580b6eae21be5e6d0c72300220814a4d4c1c4a8ebbeadb"
    "0ae282f991eb13ac5f9fce94309319aa94096c8cd4b830031773616d706c655f7665"
    "6e646f725f72657365727665643130051876656e646f725f7265736572766564335f"
    "6578616d706c6518"
);

/// F.3's candidate operational private key, which the CSR is signed with.
const OPERATIONAL_PRIVATE_KEY: [u8; 32] =
    hex!("1c1882e87f80d81a259a62b6ea02db0817e210684684 2beb3aabc25386a91e89");

/// Its public half, which the CSR carries.
const OPERATIONAL_PUBLIC_KEY: [u8; 65] = hex!(
    "045ca279e36682c2d46ce7d4cf8967846708b5b9f85b9cdafd8ca8852612cb0f0c"
    "7a71314ec8dc9c9634ddeefee9f63f0e8bd7dacfc3b6a4532aadd89a9651cd6e"
);

/// F.3's CSR nonce.
const CSR_NONCE: [u8; 32] =
    hex!("814a4d4c1c4a8ebbeadb0ae282f991eb13ac5f9fce94309319aa94096c8cd4b8");

#[test]
fn the_published_csr_parses_and_its_inner_signature_verifies() {
    // PKCS#10's proof of possession: whoever asked for this certificate holds the private
    // half of the key in it. §6.4.6.1 validation step 2 requires a commissioner to check it,
    // and without it a commissioner could be induced to certify somebody else's key.
    let csr = Csr::parse(CSR_DER).expect("parse");
    assert_eq!(csr.public_key.as_bytes(), &OPERATIONAL_PUBLIC_KEY);
    assert!(csr.verify().expect("verify"), "the inner signature");

    // The signed part is the first element inside the outer SEQUENCE, and `tbs` is a borrow
    // of exactly those bytes rather than a copy — which is what lets the signature be
    // checked over what arrived rather than over a re-encoding of it.
    let at = CSR_DER
        .windows(csr.tbs.len())
        .position(|w| w == csr.tbs)
        .expect("the tbs is a contiguous slice of the request");
    assert_eq!(&CSR_DER[at..at + csr.tbs.len()], csr.tbs);
    assert!(
        at > 0 && at < 8,
        "it follows only the outer header, at {at}"
    );
}

#[test]
fn a_csr_this_crate_builds_matches_the_published_one_where_it_can() {
    // The signature cannot match: F.3's was made with a stated fixed `k`, and this crate
    // signs deterministically per RFC 6979. Everything the signature covers can and must —
    // so the `certificationRequestInfo` is compared byte for byte, and the signature is
    // checked by verifying it rather than by comparing it.
    let mut keys = SoftKeyStore::<2>::new();
    let handle = keys
        .import(KeyPurpose::Operational, &OPERATIONAL_PRIVATE_KEY)
        .expect("import");

    let mut buf = [0u8; MAX_CSR_LEN];
    let built = build_csr(&keys, handle, &mut buf).expect("build");

    let ours = Csr::parse(built).expect("parse ours");
    let theirs = Csr::parse(CSR_DER).expect("parse theirs");
    assert_eq!(ours.tbs, theirs.tbs, "certificationRequestInfo");
    assert_eq!(ours.public_key.as_bytes(), theirs.public_key.as_bytes());
    assert!(ours.verify().expect("verify"), "our own signature");
}

#[test]
fn the_nocsr_elements_decode_as_the_spec_states_its_inputs() {
    let elements = NocsrElements::decode(NOCSR_ELEMENTS).expect("decode");
    assert_eq!(elements.csr, CSR_DER);
    assert_eq!(elements.csr_nonce, CSR_NONCE);
    // F.3 carries vendor_reserved1 and vendor_reserved3, and no vendor_reserved2.
    assert_eq!(elements.vendor_reserved.len(), 2);
    assert_eq!(elements.vendor_reserved[0].0, 3);
    assert_eq!(elements.vendor_reserved[0].1, b"sample_vendor_reserved1");
    assert_eq!(elements.vendor_reserved[1].0, 5);
    assert_eq!(elements.vendor_reserved[1].1, b"vendor_reserved3_example");
}

#[test]
fn the_nocsr_elements_re_encode_byte_for_byte() {
    // They are inside the outer signature, so a lost or reordered field would break it.
    let elements = NocsrElements::decode(NOCSR_ELEMENTS).expect("decode");
    let mut buf = [0u8; MAX_NOCSR_ELEMENTS];
    assert_eq!(elements.encode(&mut buf).expect("encode"), NOCSR_ELEMENTS);
}

#[test]
fn the_csr_inside_the_elements_verifies() {
    // The two layers agree: the TLV carries the DER, and the DER's own signature is sound.
    let elements = NocsrElements::decode(NOCSR_ELEMENTS).expect("decode");
    let csr = elements.parse_csr().expect("parse");
    assert!(csr.verify().expect("verify"));
    assert_eq!(csr.public_key.as_bytes(), &OPERATIONAL_PUBLIC_KEY);
}

#[test]
fn the_outer_nocsr_signature_binds_the_request_to_the_session() {
    // The second of the two signatures: made with the *attestation* key, over
    // `nocsr_elements_message || attestation_challenge`. It says the attested device is the
    // one asking, in this session — which is what stops a recorded CSRResponse being
    // replayed into another one.
    let mut keys = SoftKeyStore::<2>::new();
    let dac = keys
        .import(KeyPurpose::DeviceAttestation, &DAC_PRIVATE_KEY)
        .expect("import");
    let challenge = SymmetricKey::new(ATTESTATION_CHALLENGE);

    let signature = sign_nocsr(&keys, dac, NOCSR_ELEMENTS, &challenge).expect("sign");
    assert!(
        verify_nocsr(
            &PublicKey::from_bytes(DAC_PUBLIC_KEY),
            NOCSR_ELEMENTS,
            &challenge,
            &signature
        )
        .expect("verify")
    );

    // A different session cannot use it.
    let mut other = ATTESTATION_CHALLENGE;
    other[15] ^= 0x01;
    assert!(
        !verify_nocsr(
            &PublicKey::from_bytes(DAC_PUBLIC_KEY),
            NOCSR_ELEMENTS,
            &challenge_of(other),
            &signature
        )
        .expect("verify")
    );
}

fn challenge_of(bytes: [u8; 16]) -> SymmetricKey {
    SymmetricKey::new(bytes)
}

#[test]
fn a_csr_whose_signature_is_for_another_key_is_refused() {
    // Proof of possession, demonstrated: swapping the public key for one whose private half
    // the requester does not hold must break the inner signature.
    let mut der = [0u8; MAX_CSR_LEN];
    der[..CSR_DER.len()].copy_from_slice(CSR_DER);
    let at = CSR_DER
        .windows(65)
        .position(|w| w == OPERATIONAL_PUBLIC_KEY)
        .expect("the key is in the request");
    // Flip a bit of the y coordinate, which keeps the point encoding well-formed enough to
    // parse while making it a different key.
    der[at + 40] ^= 0x01;
    let csr = Csr::parse(&der[..CSR_DER.len()]).expect("still parses");
    assert_ne!(csr.public_key.as_bytes(), &OPERATIONAL_PUBLIC_KEY);
    assert!(!csr.verify().unwrap_or(false));
}

#[test]
fn every_truncation_of_a_csr_is_an_error_not_a_panic() {
    for len in 0..CSR_DER.len() {
        let _ = Csr::parse(&CSR_DER[..len]);
    }
    for len in 0..NOCSR_ELEMENTS.len() {
        let _ = NocsrElements::decode(&NOCSR_ELEMENTS[..len]);
    }
}
