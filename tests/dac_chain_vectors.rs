//! The Device Attestation certificate chain the specification publishes (Core §6.2.2).
//!
//! §6.2.2.3 through §6.2.2.5 print a complete, valid chain — a DAC, the PAI that issued it
//! and the self-signed PAA above that — plus a **second DAC** that carries the same identity
//! through the "fallback method" of §6.2.2.2, with `Mvid:` and `Mpid:` substrings inside its
//! `commonName` instead of Matter-specific RDN attributes.
//!
//! Having both is what makes this worth testing rather than eyeballing. The two encodings are
//! mutually exclusive *per field*, and the rule is not "try one then the other": the presence
//! of either Matter OID anywhere in a field "SHALL cause the 'fallback method' to be skipped
//! altogether for that field". The fallback DAC exercises exactly that split — its issuer
//! uses the Matter OIDs and its subject uses the substrings — so a parser that got the rule
//! backwards would read one field of it wrongly and nothing else.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use hex_literal::hex;
use matter_kit::attestation::cd::CertificationElements;
use matter_kit::attestation::x509::{FALLBACK_PID_PREFIX, FALLBACK_VID_PREFIX, KeyUsage, VidPid};
use matter_kit::attestation::{X509Certificate, check_declaration_against_chain, verify_dac_chain};
use matter_kit::msg::VendorId;

/// §6.2.2.3's example DAC, using the preferred method (Matter RDN attributes).
const DAC_PREFERRED: &[u8] = &hex!(
    "308201e93082018fa00302010202080e063b742bcfbe5d300a06082a8648ce3d0403"
    "0230463118301606035504030c0f4d61747465722054657374205041493114301206"
    "0a2b0601040182a27c02010c044646463131143012060a2b0601040182a27c02020c"
    "04383030303020170d3231303632383134323334335a180f39393939313233313233"
    "353935395a304b311d301b06035504030c144d617474657220546573742044414320"
    "3030303131143012060a2b0601040182a27c02010c044646463131143012060a2b06"
    "01040182a27c02020c04383030303059301306072a8648ce3d020106082a8648ce3d"
    "03010703420004c2258322c7dc72737c33beed707337aa2485bc46793e4d5ac9a75a"
    "d7435266c90a028eecaf2650fe7009effcaecbead1f2c3d12435dec2ead3d99295bf"
    "ced6c3a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403"
    "020780301d0603551d0e0416041496c2d92494ea9785c0d16708e388f1c091ea0fd5"
    "301f0603551d23041830168014af42b7094debd515ec6ecf33b81115225f32528830"
    "0a06082a8648ce3d040302034800304502205fcb29a40d3c35a6e8ce6065c6d09da6"
    "173dc5b245ec320491e3d34932b73e17022100b456990f520510045a388f754e7715"
    "40a04497923196455e440d6825d9610364"
);

/// §6.2.2.3's example DAC, using the fallback method in its subject's `commonName`.
const DAC_FALLBACK: &[u8] = &hex!(
    "308201d030820177a00302010202086de73d970df06690300a06082a8648ce3d0403"
    "0230463118301606035504030c0f4d61747465722054657374205041493114301206"
    "0a2b0601040182a27c02010c044646463131143012060a2b0601040182a27c02020c"
    "04383030303020170d3231303632383134323334335a180f39393939313233313233"
    "353935395a30333131302f06035504030c284d617474657220546573742044414320"
    "30303031204d7669643a46464631204d7069643a383030303059301306072a8648ce"
    "3d020106082a8648ce3d03010703420004c2258322c7dc72737c33beed707337aa24"
    "85bc46793e4d5ac9a75ad7435266c90a028eecaf2650fe7009effcaecbead1f2c3d1"
    "2435dec2ead3d99295bfced6c3a360305e300c0603551d130101ff04023000300e06"
    "03551d0f0101ff040403020780301d0603551d0e0416041496c2d92494ea9785c0d1"
    "6708e388f1c091ea0fd5301f0603551d23041830168014af42b7094debd515ec6ecf"
    "33b81115225f325288300a06082a8648ce3d040302034700304402206ef62c1da191"
    "4e0d49ccf4c1e93a9f5453c0045f0b0989043f502f57b021c8be0220008a5b703a62"
    "2c6ab6a29f930bafc3cd66315ca6a9a7d4f24c79935734cea6de"
);

/// §6.2.2.4's example PAI.
const PAI: &[u8] = &hex!(
    "308201d43082017aa00302010202083e6ce6509ad840cd300a06082a8648ce3d0403"
    "0230303118301606035504030c0f4d61747465722054657374205041413114301206"
    "0a2b0601040182a27c02010c04464646313020170d3231303632383134323334335a"
    "180f39393939313233313233353935395a30463118301606035504030c0f4d617474"
    "657220546573742050414931143012060a2b0601040182a27c02010c044646463131"
    "143012060a2b0601040182a27c02020c04383030303059301306072a8648ce3d0201"
    "06082a8648ce3d0301070342000480ddf11b228f3e31f63bcf5798da14623aebbde8"
    "2ef378eeadbfb18fe1abce31d08ed4b20604b6ccc6d9b5fab64e7de10cb74be017c9"
    "ec1516056d70f2cd0b22a366306430120603551d130101ff040830060101ff020100"
    "300e0603551d0f0101ff040403020106301d0603551d0e04160414af42b7094debd5"
    "15ec6ecf33b81115225f325288301f0603551d230418301680146afd22771f511fec"
    "bf1641976710dcdc31a1717e300a06082a8648ce3d040302034800304502210096c9"
    "c8cf2e01886005d8f5bc72c07b75fd9a57695ac4911131138bea033ce50302202554"
    "943be57d53d6c475f7d23ebfcfc2036cd29ba6393ec7efad8714ab718219"
);

/// §6.2.2.5's example PAA, self-signed.
const PAA: &[u8] = &hex!(
    "308201bd30820164a00302010202084ea8e83182d41c1c300a06082a8648ce3d0403"
    "0230303118301606035504030c0f4d61747465722054657374205041413114301206"
    "0a2b0601040182a27c02010c04464646313020170d3231303632383134323334335a"
    "180f39393939313233313233353935395a30303118301606035504030c0f4d617474"
    "657220546573742050414131143012060a2b0601040182a27c02010c044646463130"
    "59301306072a8648ce3d020106082a8648ce3d03010703420004b6cb6372887f2928"
    "f5bac81aa9d93ae2431cada9d79e242f65177ef9ced932a28ecd03baaf6a8fca184a"
    "1a503542960d453f303f1f19421d751e8f8f1a9a9b75a366306430120603551d1301"
    "01ff040830060101ff020101300e0603551d0f0101ff040403020106301d0603551d"
    "0e041604146afd22771f511fecbf1641976710dcdc31a1717e301f0603551d230418"
    "301680146afd22771f511fecbf1641976710dcdc31a1717e300a06082a8648ce3d04"
    "03020347003044022050aa8002f4d932a9a00538f65368ad0fffc8efbbc9beb7da56"
    "9835cf9aa7510e022023bac8fe0f23e75445b65339081a47994929c72aaf0a1548d4"
    "0d034d514b25de"
);

const TEST_VENDOR: VendorId = VendorId(0xFFF1);
const TEST_PRODUCT: u16 = 0x8000;

#[test]
fn the_published_chain_validates() {
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");

    let chain = verify_dac_chain(&dac, &pai, &paa).expect("chain");
    assert_eq!(chain.vendor_id, TEST_VENDOR);
    assert_eq!(chain.product_id, TEST_PRODUCT);
    assert_eq!(chain.paa_key_id, paa.subject_key_id);
    assert_eq!(chain.validated_at, dac.not_before);
}

#[test]
fn the_fallback_dac_reaches_the_same_identity() {
    // Same vendor, same product, a different encoding of both. If the two disagreed, a
    // device would be attested as a different product depending on its CA's tooling.
    let dac = X509Certificate::parse(DAC_FALLBACK).expect("dac");
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");

    let chain = verify_dac_chain(&dac, &pai, &paa).expect("chain");
    assert_eq!(chain.vendor_id, TEST_VENDOR);
    assert_eq!(chain.product_id, TEST_PRODUCT);
}

#[test]
fn the_two_encodings_are_read_per_field_not_per_certificate() {
    // The fallback DAC's *issuer* uses the Matter OIDs and its *subject* uses the substrings
    // — §6.2.2.2 says the choice "applies field by field independently". A parser that
    // decided once per certificate would read one of these two fields wrongly.
    let dac = X509Certificate::parse(DAC_FALLBACK).expect("dac");
    assert_eq!(dac.issuer_vid_pid.vendor_id, Some(TEST_VENDOR));
    assert_eq!(dac.issuer_vid_pid.product_id, Some(TEST_PRODUCT));
    assert_eq!(dac.subject_vid_pid.vendor_id, Some(TEST_VENDOR));
    assert_eq!(dac.subject_vid_pid.product_id, Some(TEST_PRODUCT));

    // And the preferred DAC uses the OIDs in both.
    let preferred = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    assert_eq!(preferred.subject_vid_pid.vendor_id, Some(TEST_VENDOR));
    assert_eq!(preferred.subject_vid_pid.product_id, Some(TEST_PRODUCT));
}

#[test]
fn the_certificates_carry_the_extensions_their_roles_require() {
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");

    // §6.2.2.3: a DAC is not a CA and signs only.
    assert!(!dac.is_ca());
    assert_eq!(dac.key_usage, Some(KeyUsage::DIGITAL_SIGNATURE));
    assert!(dac.subject_key_id.is_some() && dac.authority_key_id.is_some());

    // §6.2.2.4: a PAI is a CA whose pathLen is 0, which is what forecloses a second
    // intermediate beneath it.
    assert!(pai.is_ca());
    assert_eq!(pai.basic_constraints.expect("basic").path_len, Some(0));
    assert_eq!(
        pai.key_usage,
        Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
    );

    // §6.2.2.5: a PAA is a self-signed CA.
    assert!(paa.is_ca());
    assert_eq!(paa.issuer, paa.subject);
    assert_eq!(paa.subject_vid_pid.product_id, None, "rule 8 forbids one");
}

#[test]
fn each_link_names_the_one_above_it() {
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");

    // §6.2.2.3 rule 6 requires a byte-for-byte match, not an equivalent name.
    assert_eq!(dac.issuer, pai.subject);
    assert_eq!(pai.issuer, paa.subject);
    assert_eq!(dac.authority_key_id, pai.subject_key_id);
    assert_eq!(pai.authority_key_id, paa.subject_key_id);
}

#[test]
fn each_signature_verifies_and_only_against_the_right_key() {
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");

    assert!(pai.verify_signature_of(&dac).expect("dac"));
    assert!(paa.verify_signature_of(&pai).expect("pai"));
    assert!(paa.verify_signature_of(&paa).expect("paa is self-signed"));

    // And not against the wrong one — otherwise the checks above prove nothing.
    assert!(!paa.verify_signature_of(&dac).expect("verify"));
    assert!(!pai.verify_signature_of(&pai).expect("verify"));
}

#[test]
fn a_chain_with_the_pai_missing_is_refused() {
    // "It is especially important to ensure the entire chain has a length of exactly 3
    // elements … to avoid unauthorized path chaining." Presenting the PAA where the PAI
    // belongs is the shortest way to test that the shape is enforced rather than searched.
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let paa = X509Certificate::parse(PAA).expect("paa");
    assert!(verify_dac_chain(&dac, &paa, &paa).is_err());
}

#[test]
fn a_dac_presented_as_its_own_issuer_is_refused() {
    // A DAC is not a CA, so it can never occupy the PAI slot — which is what stops a
    // compromised device from minting certificates for others.
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let paa = X509Certificate::parse(PAA).expect("paa");
    assert!(verify_dac_chain(&dac, &dac, &paa).is_err());
}

#[test]
fn a_tampered_certificate_fails_its_signature() {
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");

    let mut der = [0u8; 600];
    der[..DAC_PREFERRED.len()].copy_from_slice(DAC_PREFERRED);
    // The serial number is inside the tbsCertificate, so changing it breaks the signature.
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let at = DAC_PREFERRED
        .windows(dac.serial_number.len())
        .position(|w| w == dac.serial_number)
        .expect("serial is in the certificate");
    der[at] ^= 0x01;

    let tampered = X509Certificate::parse(&der[..DAC_PREFERRED.len()]).expect("still parses");
    assert!(!pai.verify_signature_of(&tampered).expect("verify"));
    assert!(verify_dac_chain(&tampered, &pai, &paa).is_err());
}

#[test]
fn every_truncation_of_every_certificate_is_an_error_not_a_panic() {
    // A DAC chain arrives from an unauthenticated device during commissioning.
    for der in [DAC_PREFERRED, DAC_FALLBACK, PAI, PAA] {
        for len in 0..der.len() {
            let _ = X509Certificate::parse(&der[..len]);
        }
    }
}

#[test]
fn every_single_bit_flip_is_caught_or_fails_its_signature() {
    // Either the parse fails, or the certificate no longer verifies, or the flip landed in a
    // field the parser ignores and everything still holds. What must not happen is a
    // certificate that parses to a *different identity* and still validates.
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");
    let original = X509Certificate::parse(DAC_PREFERRED).expect("dac");

    let mut der = [0u8; 600];
    for index in 0..DAC_PREFERRED.len() {
        for bit in 0..8u32 {
            der[..DAC_PREFERRED.len()].copy_from_slice(DAC_PREFERRED);
            der[index] ^= 1 << bit;
            let Ok(candidate) = X509Certificate::parse(&der[..DAC_PREFERRED.len()]) else {
                continue;
            };
            if candidate == original {
                continue;
            }
            assert!(
                verify_dac_chain(&candidate, &pai, &paa).is_err(),
                "bit {bit} of byte {index} changed the certificate and it still validated"
            );
        }
    }
}

// --- §6.2.2.2's own worked examples of the fallback method -----------------------------------

/// Builds a minimal `Name` DER holding one `commonName`, to exercise [`VidPid::from_name`]
/// against the examples §6.2.2.2 prints in prose.
fn name_with_common_name(cn: &str) -> heapless::Vec<u8, 256> {
    // Name ::= SEQUENCE OF RDN; RDN ::= SET OF AttributeTypeAndValue.
    let mut atv = heapless::Vec::<u8, 256>::new();
    // OID 2.5.4.3 (commonName).
    atv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03])
        .unwrap();
    atv.push(0x0C).unwrap(); // UTF8String
    atv.push(u8::try_from(cn.len()).unwrap()).unwrap();
    atv.extend_from_slice(cn.as_bytes()).unwrap();

    let mut seq = heapless::Vec::<u8, 256>::new();
    seq.push(0x30).unwrap();
    seq.push(u8::try_from(atv.len()).unwrap()).unwrap();
    seq.extend_from_slice(&atv).unwrap();

    let mut set = heapless::Vec::<u8, 256>::new();
    set.push(0x31).unwrap();
    set.push(u8::try_from(seq.len()).unwrap()).unwrap();
    set.extend_from_slice(&seq).unwrap();
    set
}

#[test]
fn the_fallback_examples_parse_exactly_as_the_spec_says_they_should() {
    // Every valid and invalid example §6.2.2.2 prints, verbatim.
    let valid: &[(&str, u16, u16)] = &[
        (
            "ACME Matter Devel DAC 5CDA9899 Mvid:FFF1 Mpid:00B1",
            0xFFF1,
            0x00B1,
        ),
        (
            "ACME Matter Devel DAC 5CDA9899 Mpid:00B1 Mvid:FFF1",
            0xFFF1,
            0x00B1,
        ),
        (
            "Mpid:00B1,ACME Matter Devel DAC 5CDA9899,Mvid:FFF1",
            0xFFF1,
            0x00B1,
        ),
        (
            "ACME Matter Devel DAC 5CDA9899 Mvid:FFF1Mpid:00B1",
            0xFFF1,
            0x00B1,
        ),
        (
            "Mvid:FFF1ACME Matter Devel DAC 5CDAMpid:00B19899",
            0xFFF1,
            0x00B1,
        ),
        // "highly discouraged, though technically valid": the leftmost *correct* match wins,
        // so `Mpid:Mvid:` and `Mpid:12cd` are both passed over for `Mpid:FE67`.
        (
            "Mpid:Mvid:FFF1 Mpid:12cd Matter Test Mpid:FE67",
            0xFFF1,
            0xFE67,
        ),
    ];
    for (cn, vid, pid) in valid {
        let name = name_with_common_name(cn);
        let parsed = VidPid::from_name(&name).unwrap_or_else(|e| panic!("{cn:?}: {e}"));
        assert_eq!(parsed.vendor_id, Some(VendorId(*vid)), "{cn:?}");
        assert_eq!(parsed.product_id, Some(*pid), "{cn:?}");
    }

    let invalid: &[&str] = &[
        // "not exactly 4 uppercase hexadecimal digits"
        "ACME Matter Devel DAC 5CDA9899 Mvid:FF1 Mpid:00B1",
        "ACME Matter Devel DAC 5CDA9899 Mvid:fff1 Mpid:00B1",
        "ACME Matter Devel DAC 5CDA9899 Mvid:FFF1 Mpid:B1",
        // "the prefix Mpid: was found but there is no occurrence of Mpid: followed by
        // exactly 4 uppercase hexadecimal digits"
        "ACME Matter Devel DAC 5CDA9899 Mpid: Mvid:FFF1",
    ];
    for cn in invalid {
        let name = name_with_common_name(cn);
        assert!(
            VidPid::from_name(&name).is_err(),
            "{cn:?} should be refused"
        );
    }
}

#[test]
fn a_common_name_without_either_prefix_has_no_vid_or_pid() {
    // Absence is not an error — a PAA's commonName routinely carries neither.
    let name = name_with_common_name("Matter Test PAA");
    let parsed = VidPid::from_name(&name).expect("parse");
    assert_eq!(parsed, VidPid::default());
    // And the prefixes are exactly what the specification names them.
    assert_eq!(FALLBACK_VID_PREFIX, b"Mvid:");
    assert_eq!(FALLBACK_PID_PREFIX, b"Mpid:");
}

// --- The two halves of attestation, checked against each other -------------------------------

/// F.1's first Certification Declaration: vendor `0xFFF1`, product `0x8000`, no
/// `dac_origin_*` and no `authorized_paa_list`.
const CD1_TLV: &[u8] = &hex!(
    "152400012501f1ff360205008018250334122c04135a494732303134315a42333330"
    "3030312d32342405002406002507942624080018"
);

/// F.1's second: vendor `0xFFF2`, with `dac_origin_*` pointing at `0xFFF1`/`0x8000` and an
/// `authorized_paa_list` naming a PAA that is *not* the one §6.2.2.5 publishes.
const CD2_TLV: &[u8] = &hex!(
    "152400012501f2ff360205018005028018250334122c04135a494732303134325a42"
    "3333303030322d3234240500240600250794262408002509f1ff250a0080360b1014"
    "785ce705b86b8f4e6fc793aa60cb43ea696882d51818"
);

/// Reads the PAI's vendor and product, which the declaration checks are made against.
fn pai_identity() -> (VendorId, Option<u16>) {
    let pai = X509Certificate::parse(PAI).expect("pai");
    (
        pai.subject_vid_pid.vendor_id.expect("pai vendor"),
        pai.subject_vid_pid.product_id,
    )
}

#[test]
fn the_published_declaration_matches_the_published_chain() {
    // These come from different chapters and were never written to be used together, which
    // is what makes the agreement meaningful: §6.2.3.1's rules relate a CD's vendor and
    // product fields to a DAC chain's, and F.1's first declaration and §6.2.2's chain happen
    // to describe the same device — vendor 0xFFF1, product 0x8000.
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");
    let chain = verify_dac_chain(&dac, &pai, &paa).expect("chain");

    let cd = CertificationElements::decode(CD1_TLV).expect("cd");
    let (pai_vid, pai_pid) = pai_identity();
    check_declaration_against_chain(&cd, &chain, pai_vid, pai_pid, None)
        .expect("the declaration covers this device");

    // And with the Basic Information the device would report.
    check_declaration_against_chain(
        &cd,
        &chain,
        pai_vid,
        pai_pid,
        Some((TEST_VENDOR, TEST_PRODUCT)),
    )
    .expect("and the reported identity agrees");
}

#[test]
fn a_declaration_for_another_product_is_refused() {
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");
    let chain = verify_dac_chain(&dac, &pai, &paa).expect("chain");
    let cd = CertificationElements::decode(CD1_TLV).expect("cd");
    let (pai_vid, pai_pid) = pai_identity();

    // The device claims a product the declaration does not cover.
    assert!(
        check_declaration_against_chain(&cd, &chain, pai_vid, pai_pid, Some((TEST_VENDOR, 0x8001)))
            .is_err()
    );
    // Or a vendor it does not cover.
    assert!(
        check_declaration_against_chain(
            &cd,
            &chain,
            pai_vid,
            pai_pid,
            Some((VendorId(0xFFF2), TEST_PRODUCT))
        )
        .is_err()
    );
}

#[test]
fn an_unauthorized_paa_is_refused() {
    // F.1's second declaration carries an `authorized_paa_list` naming a PAA whose Subject
    // Key Identifier is not the published PAA's. §6.2.3.1: the SKI of the PAA "SHALL be
    // present as one of the values in the authorized_paa_list field" — so this chain, valid
    // in every other respect, is not one this declaration vouches for.
    let dac = X509Certificate::parse(DAC_PREFERRED).expect("dac");
    let pai = X509Certificate::parse(PAI).expect("pai");
    let paa = X509Certificate::parse(PAA).expect("paa");
    let chain = verify_dac_chain(&dac, &pai, &paa).expect("chain");
    let cd = CertificationElements::decode(CD2_TLV).expect("cd");
    let (pai_vid, pai_pid) = pai_identity();

    // Its vendor and product checks would pass: dac_origin_* name 0xFFF1/0x8000, which is
    // exactly this chain's identity. Only the PAA authorisation fails.
    assert_eq!(cd.dac_origin_vendor_id, Some(TEST_VENDOR));
    assert_eq!(cd.dac_origin_product_id, Some(TEST_PRODUCT));
    assert!(!cd.authorizes_paa(&paa.subject_key_id.expect("paa ski")));

    assert!(check_declaration_against_chain(&cd, &chain, pai_vid, pai_pid, None).is_err());
}

#[test]
fn the_dac_origin_path_is_taken_when_the_fields_are_present() {
    // F.1's second declaration is the ODM case: certified under vendor 0xFFF2, but
    // manufactured under 0xFFF1's attestation PKI. §6.2.3.1 says the DAC is then compared
    // against `dac_origin_*` and *not* against `vendor_id` — so a checker that used
    // `vendor_id` here would reject a perfectly legitimate device.
    let cd = CertificationElements::decode(CD2_TLV).expect("cd");
    assert_eq!(
        cd.vendor_id,
        VendorId(0xFFF2),
        "certified under this vendor"
    );
    assert_eq!(
        cd.dac_origin_vendor_id,
        Some(TEST_VENDOR),
        "but attested under this one"
    );
    assert_ne!(cd.vendor_id, cd.dac_origin_vendor_id.expect("origin"));
}
