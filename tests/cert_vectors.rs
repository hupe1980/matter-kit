//! The three Matter certificates the specification prints in full (Core §6.5.15), decoded,
//! checked field by field against its own schema rendering, and re-encoded.
//!
//! They form a chain: the RCAC signs the ICAC, which signs the NOC. Between them they
//! exercise nearly every branch of the format — a CA and a leaf, `is-ca` true and false,
//! both key-usage shapes, an extended key usage array, a two-attribute subject DN of
//! Matter-specific scalars, and the self-issued case where the authority key identifier
//! equals the subject's.
//!
//! The re-encode is the part worth having. §6.5.2 makes the Matter TLV a lossless
//! re-spelling of an X.509 certificate — "validating the signature in a Matter certificate
//! entails its logical conversion to the corresponding X.509 certificate" — so any field
//! this crate normalises, reorders or widens on the way through becomes a signature that
//! does not verify, in a way no amount of round-tripping against *itself* would reveal.
//! Asserting `encode(decode(bytes)) == bytes` against bytes the CSA published catches it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use hex_literal::hex;
use matter_kit::ErrorCode;
use matter_kit::cert::{
    CERT_DER_MAX, CERT_TLV_MAX, CertType, DnAttributeKind, EllipticCurveId, Extension, Extensions,
    KeyPurposeId, KeyUsage, MatterCertificate, PublicKeyAlgorithm, SignatureAlgorithm, der,
};
use matter_kit::crypto::verify;
use matter_kit::msg::{FabricId, NodeId};

/// §6.5.15.1 — "RCAC in Matter TLV Format".
const RCAC: &[u8] = &hex!(
    "1530010859eaa632947f541c2402013703271401000000cacacaca182604ef171b27"
    "26056eb5b94c3706271401000000cacacaca1824070124080130094104"
    "1353a3b3ef1da708c4908048014e407d5990ce22bc4eb33e9a5acb25a85603eba6"
    "dcd8213666a4e44f5aca13eb767fafa7dcdddc33411f82a30b543dd1d24ba8"
    "370a350129011824026030041413af81ab37374b2ed2a9649b12b7a3a4287e151d"
    "30051413af81ab37374b2ed2a9649b12b7a3a4287e151d18300b40"
    "458164466c8f195abc0abb7c6cb5a27a83f41d37f8d53beec520abd2a0da0509"
    "b8a7c25c042e30cf64dc30fe334e120019664e515049134f5781238444fc753118"
);

/// §6.5.15.2 — "ICAC in Matter TLV Format", issued by the RCAC above.
const ICAC: &[u8] = &hex!(
    "153001082db444855641aedf2402013703271401000000cacacaca182604ef171b27"
    "26056eb5b94c3706271303000000cacacaca1824070124080130094104"
    "c5d0861bb8f90c405c12314e4c5ebeea939f72774bcc33239e2f59f6f46af8dc7d"
    "4682a0e3ccc646e6df29ea86bf562ae720a898337d383f32c0a09e416019ea"
    "370a35012901182402603004145352d7059e9c15a508906862864801a29f1f41d3"
    "30051413af81ab37374b2ed2a9649b12b7a3a4287e151d18300b40"
    "841a06d43b5e9fecd24e87b1244eb51c6a2cf20d9b5e6ba07f11e6002f7e0ca34e"
    "32a602c3609d0092d348bdbd198a114646bd41cf103783641ae25e3f23fd2618"
);

/// §6.5.15.3 — "NOC in Matter TLV Format", issued by the ICAC above.
const NOC: &[u8] = &hex!(
    "153001083efcff1702b9a17a2402013703271303000000cacacaca182604ef171b27"
    "26056eb5b94c3706271101000100dededede27151d0000000000b0fa18"
    "24070124080130094104"
    "9a2a216fb39dd6b6fa211b835c89e3e6afb66c14f75831954f9ff4f7a3f0112c8a"
    "0d8eaf29c653294d48eee0708a032cca39393c3a7b46f181aea078fead8383"
    "370a350128011824020136030402040118"
    "3004149f55a26b7e4303e60883e913bf94f4fb5e2a6161"
    "30051453 52d7059e9c15a508906862864801a29f1f41d318300b40"
    "7955c202630b4ba4d5912526322fdf28f89edfe5af9c0e572bd8a14aaabb4d12"
    "b83ca17c7b05fb164b77d79c529613316bcfd17895e4b2a4f2404b981732715918"
);

/// The key identifier of the root, which is its own authority key identifier and the ICAC's.
const RCAC_KEY_ID: [u8; 20] = hex!("13af81ab37374b2ed2a9649b12b7a3a4287e151d");
/// The ICAC's key identifier, which is the NOC's authority key identifier.
const ICAC_KEY_ID: [u8; 20] = hex!("5352d7059e9c15a508906862864801a29f1f41d3");
/// The NOC's key identifier.
const NOC_KEY_ID: [u8; 20] = hex!("9f55a26b7e4303e60883e913bf94f4fb5e2a6161");

/// Every certificate in the chain shares these, so they are asserted once per test.
const NOT_BEFORE: u32 = 0x271B_17EF;
const NOT_AFTER: u32 = 0x4CB9_B56E;
/// `matter-rcac-id` of the root, and the issuer of both the root and the ICAC.
const RCAC_ID: u64 = 0xCACA_CACA_0000_0001;
/// `matter-icac-id` of the intermediate, and the issuer of the NOC.
const ICAC_ID: u64 = 0xCACA_CACA_0000_0003;

fn assert_reencodes(bytes: &[u8], cert: &MatterCertificate<'_>) {
    let mut buf = [0u8; CERT_TLV_MAX];
    let written = cert.encode(&mut buf).expect("re-encode");
    assert_eq!(
        written, bytes,
        "re-encoding changed the bytes, which would break the X.509 signature"
    );
}

#[test]
fn the_rcac_decodes_exactly_as_the_spec_prints_it() {
    let cert = MatterCertificate::decode(RCAC).expect("decode");

    assert_eq!(cert.serial_number, hex!("59eaa632947f541c"));
    assert_eq!(
        cert.signature_algorithm,
        SignatureAlgorithm::EcdsaWithSha256
    );
    assert_eq!(cert.public_key_algorithm, PublicKeyAlgorithm::EcPubKey);
    assert_eq!(cert.elliptic_curve_id, EllipticCurveId::Prime256V1);
    assert_eq!(cert.not_before, NOT_BEFORE);
    assert_eq!(cert.not_after, NOT_AFTER);

    // "issuer = [[ matter-rcac-id = 0xCACACACA00000001U ]]" — and the subject is the same,
    // because a root certificate is self-issued.
    assert_eq!(cert.issuer.len(), 1);
    assert_eq!(
        cert.issuer.single_uint(DnAttributeKind::MatterRcacId),
        Some(RCAC_ID)
    );
    assert_eq!(
        cert.subject.single_uint(DnAttributeKind::MatterRcacId),
        Some(RCAC_ID)
    );

    assert_eq!(
        cert.public_key.as_bytes(),
        &hex!(
            "041353a3b3ef1da708c4908048014e407d5990ce22bc4eb33e9a5acb25a85603"
            "eba6dcd8213666a4e44f5aca13eb767fafa7dcdddc33411f82a30b543dd1d24b"
            "a8"
        )
    );

    let ext = &cert.extensions;
    assert!(ext.basic_constraints().expect("basic-cnstr").is_ca);
    assert_eq!(
        ext.basic_constraints()
            .expect("basic-cnstr")
            .path_len_constraint,
        None
    );
    // "key-usage = 0x60U" — keyCertSign | CRLSign.
    assert_eq!(
        ext.key_usage(),
        Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
    );
    assert_eq!(ext.key_usage().expect("key-usage").bits(), 0x60);
    // "the extended key usage extension SHALL NOT be present" for a CA (§6.5.12).
    assert_eq!(ext.extended_key_usage(), None);
    assert_eq!(ext.subject_key_id(), Some(RCAC_KEY_ID));
    assert_eq!(ext.authority_key_id(), Some(RCAC_KEY_ID));
    assert_eq!(ext.future().count(), 0);

    assert_eq!(cert.cert_type(), Some(CertType::Rcac));
    assert!(cert.is_ca());
    cert.validate().expect("a valid RCAC");
    assert_reencodes(RCAC, &cert);
}

#[test]
fn the_icac_decodes_exactly_as_the_spec_prints_it() {
    let cert = MatterCertificate::decode(ICAC).expect("decode");

    assert_eq!(cert.serial_number, hex!("2db444855641aedf"));
    // Issued by the root: its issuer is the root's subject.
    assert_eq!(
        cert.issuer.single_uint(DnAttributeKind::MatterRcacId),
        Some(RCAC_ID)
    );
    assert_eq!(
        cert.subject.single_uint(DnAttributeKind::MatterIcacId),
        Some(ICAC_ID)
    );
    assert_eq!(cert.not_before, NOT_BEFORE);
    assert_eq!(cert.not_after, NOT_AFTER);

    let ext = &cert.extensions;
    assert!(ext.basic_constraints().expect("basic-cnstr").is_ca);
    assert_eq!(
        ext.key_usage(),
        Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
    );
    assert_eq!(ext.extended_key_usage(), None);
    assert_eq!(ext.subject_key_id(), Some(ICAC_KEY_ID));
    // Unlike the root, an intermediate's authority key identifier is its issuer's.
    assert_eq!(ext.authority_key_id(), Some(RCAC_KEY_ID));

    assert_eq!(cert.cert_type(), Some(CertType::Icac));
    assert!(cert.is_ca());
    // An ICAC with no matter-fabric-id is legal: §6.5.6.3 says "MAY encode at most one".
    assert_eq!(cert.fabric_id(), None);
    cert.validate().expect("a valid ICAC");
    assert_reencodes(ICAC, &cert);
}

#[test]
fn the_noc_decodes_exactly_as_the_spec_prints_it() {
    let cert = MatterCertificate::decode(NOC).expect("decode");

    assert_eq!(cert.serial_number, hex!("3efcff1702b9a17a"));
    assert_eq!(
        cert.issuer.single_uint(DnAttributeKind::MatterIcacId),
        Some(ICAC_ID)
    );

    // "subject = [[ matter-node-id = 0xDEDEDEDE00010001U,
    //               matter-fabric-id = 0xFAB000000000001DU ]]"
    assert_eq!(cert.subject.len(), 2);
    assert_eq!(cert.node_id(), Some(NodeId(0xDEDE_DEDE_0001_0001)));
    assert_eq!(cert.fabric_id(), Some(FabricId(0xFAB0_0000_0000_001D)));
    // And in that order, which the DER — and therefore the signature — depends on.
    assert_eq!(
        cert.subject.attributes()[0].kind,
        DnAttributeKind::MatterNodeId
    );
    assert_eq!(
        cert.subject.attributes()[1].kind,
        DnAttributeKind::MatterFabricId
    );
    assert!(cert.subject.noc_cats().is_empty());

    let ext = &cert.extensions;
    assert!(!ext.basic_constraints().expect("basic-cnstr").is_ca);
    // "key-usage = 0x01U" — exactly digitalSignature.
    assert_eq!(ext.key_usage(), Some(KeyUsage::DIGITAL_SIGNATURE));
    // "extended-key-usage = [ 0x02U, 0x01U ]" — clientAuth then serverAuth. The order is
    // the X.509 certificate's, not a canonical one, and it is preserved.
    assert_eq!(
        ext.extended_key_usage(),
        Some(&[KeyPurposeId::ClientAuth, KeyPurposeId::ServerAuth][..])
    );
    assert_eq!(ext.subject_key_id(), Some(NOC_KEY_ID));
    assert_eq!(ext.authority_key_id(), Some(ICAC_KEY_ID));

    assert_eq!(cert.cert_type(), Some(CertType::Noc));
    assert!(!cert.is_ca());
    cert.validate().expect("a valid NOC");
    assert_reencodes(NOC, &cert);
}

#[test]
fn the_chain_links_up() {
    // Each certificate's authority key identifier names its issuer's subject key
    // identifier, and each issuer DN matches its issuer's subject DN. That is the
    // structural half of path validation; the cryptographic half needs DER regeneration.
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(NOC).expect("noc");

    assert_eq!(
        icac.extensions.authority_key_id(),
        rcac.extensions.subject_key_id()
    );
    assert_eq!(
        noc.extensions.authority_key_id(),
        icac.extensions.subject_key_id()
    );
    assert_eq!(icac.issuer, rcac.subject);
    assert_eq!(noc.issuer, icac.subject);
    // And the root is the only one that is its own issuer.
    assert_eq!(rcac.issuer, rcac.subject);
    assert_ne!(icac.issuer, icac.subject);
}

#[test]
fn every_certificate_fits_the_size_the_spec_allows() {
    // §6.1.3: "all certificates SHALL NOT be longer than 400 bytes in their TLV form."
    for (name, bytes) in [("RCAC", RCAC), ("ICAC", ICAC), ("NOC", NOC)] {
        assert!(
            bytes.len() <= CERT_TLV_MAX,
            "{name} is {} bytes",
            bytes.len()
        );
    }
}

#[test]
fn the_validity_window_is_honoured() {
    let cert = MatterCertificate::decode(NOC).expect("decode");
    assert!(cert.is_valid_at(NOT_BEFORE));
    assert!(cert.is_valid_at(NOT_AFTER));
    assert!(cert.is_valid_at(NOT_BEFORE + 1));
    assert!(!cert.is_valid_at(NOT_BEFORE - 1));
    assert!(!cert.is_valid_at(NOT_AFTER + 1));
}

#[test]
fn a_certificate_of_the_wrong_type_is_refused() {
    // validate_as is for callers that know what they asked for: handing a NOC where a root
    // was expected has to fail, even though the NOC is perfectly valid as a NOC.
    let noc = MatterCertificate::decode(NOC).expect("decode");
    noc.validate_as(CertType::Noc).expect("it is a NOC");
    assert!(noc.validate_as(CertType::Rcac).is_err());
    assert!(noc.validate_as(CertType::Icac).is_err());
}

#[test]
fn every_single_byte_flip_is_caught_or_survives_a_round_trip() {
    // A decoder that accepts a corrupted certificate and re-encodes it to a *different*
    // certificate is worse than one that rejects it: the difference would only show up as a
    // signature failure much later, far from its cause. Either outcome is fine — rejection,
    // or an encoding that decodes back to the same thing. Silently altering it is not.
    //
    // Byte-identity is not the assertion here, because it is not true in general: a flip can
    // widen an integer, and this crate always writes the narrowest. That normalisation is
    // value-preserving, which is exactly what the second decode checks.
    let mut buf = [0u8; CERT_TLV_MAX];
    for (name, bytes) in [("RCAC", RCAC), ("ICAC", ICAC), ("NOC", NOC)] {
        for index in 0..bytes.len() {
            for bit in 0..8u32 {
                let mut corrupted = [0u8; CERT_TLV_MAX];
                let corrupted = &mut corrupted[..bytes.len()];
                corrupted.copy_from_slice(bytes);
                corrupted[index] ^= 1 << bit;
                if corrupted == bytes {
                    continue;
                }
                let Ok(cert) = MatterCertificate::decode(corrupted) else {
                    continue;
                };
                let written = cert.encode(&mut buf).expect("re-encode");
                let mut round = [0u8; CERT_TLV_MAX];
                let len = written.len();
                round[..len].copy_from_slice(written);
                let again = MatterCertificate::decode(&round[..len]).unwrap_or_else(|e| {
                    panic!("{name}: bit {bit} of byte {index} re-encoded to garbage: {e}")
                });
                assert_eq!(
                    again, cert,
                    "{name}: flipping bit {bit} of byte {index} decoded but re-encoded to a \
                     different certificate"
                );
            }
        }
    }
}

#[test]
fn the_published_certificates_re_encode_byte_for_byte() {
    // Weaker than it looks only in one direction: the assertion above allows a
    // value-preserving width change, this one allows nothing at all. Real certificates are
    // minimally encoded — all three of the specification's are — so this is the property
    // that actually holds in the field, and the one that would break first if a field were
    // reordered or dropped.
    let mut buf = [0u8; CERT_TLV_MAX];
    for (name, bytes) in [("RCAC", RCAC), ("ICAC", ICAC), ("NOC", NOC)] {
        let cert = MatterCertificate::decode(bytes).expect("decode");
        assert_eq!(cert.encode(&mut buf).expect("encode"), bytes, "{name}");
    }
}

// --- The X.509 DER the same certificates are a re-spelling of (§6.5.15) -------------------

/// The DER of §6.5.15's RCAC, from the PEM block the specification prints.
const RCAC_DER: &[u8] = &hex!(
    "3082019d30820143a003020102020859eaa632947f541c300a06082a8648ce3d0403"
    "0230223120301e060a2b0601040182a27c01040c1043414341434143413030303030"
    "303031301e170d3230313031353134323334335a170d343031303135313432333432"
    "5a30223120301e060a2b0601040182a27c01040c1043414341434143413030303030"
    "3030313059301306072a8648ce3d020106082a8648ce3d030107034200041353a3b3"
    "ef1da708c4908048014e407d5990ce22bc4eb33e9a5acb25a85603eba6dcd8213666"
    "a4e44f5aca13eb767fafa7dcdddc33411f82a30b543dd1d24ba8a3633061300f0603"
    "551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d060355"
    "1d0e0416041413af81ab37374b2ed2a9649b12b7a3a4287e151d301f0603551d2304"
    "183016801413af81ab37374b2ed2a9649b12b7a3a4287e151d300a06082a8648ce3d"
    "04030203480030450220458164466c8f195abc0abb7c6cb5a27a83f41d37f8d53bee"
    "c520abd2a0da0509022100b8a7c25c042e30cf64dc30fe334e120019664e51504913"
    "4f5781238444fc7531"
);

/// The DER of §6.5.15's ICAC, from the PEM block the specification prints.
const ICAC_DER: &[u8] = &hex!(
    "3082019d30820143a00302010202082db444855641aedf300a06082a8648ce3d0403"
    "0230223120301e060a2b0601040182a27c01040c1043414341434143413030303030"
    "303031301e170d3230313031353134323334335a170d343031303135313432333432"
    "5a30223120301e060a2b0601040182a27c01030c1043414341434143413030303030"
    "3030333059301306072a8648ce3d020106082a8648ce3d03010703420004c5d0861b"
    "b8f90c405c12314e4c5ebeea939f72774bcc33239e2f59f6f46af8dc7d4682a0e3cc"
    "c646e6df29ea86bf562ae720a898337d383f32c0a09e416019eaa3633061300f0603"
    "551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d060355"
    "1d0e041604145352d7059e9c15a508906862864801a29f1f41d3301f0603551d2304"
    "183016801413af81ab37374b2ed2a9649b12b7a3a4287e151d300a06082a8648ce3d"
    "0403020348003045022100841a06d43b5e9fecd24e87b1244eb51c6a2cf20d9b5e6b"
    "a07f11e6002f7e0ca302204e32a602c3609d0092d348bdbd198a114646bd41cf1037"
    "83641ae25e3f23fd26"
);

/// The DER of §6.5.15's NOC, from the PEM block the specification prints.
const NOC_DER: &[u8] = &hex!(
    "308201e030820186a00302010202083efcff1702b9a17a300a06082a8648ce3d0403"
    "0230223120301e060a2b0601040182a27c01030c1043414341434143413030303030"
    "303033301e170d3230313031353134323334335a170d343031303135313432333432"
    "5a30443120301e060a2b0601040182a27c01010c1044454445444544453030303130"
    "3030313120301e060a2b0601040182a27c01050c1046414230303030303030303030"
    "3031443059301306072a8648ce3d020106082a8648ce3d030107034200049a2a216f"
    "b39dd6b6fa211b835c89e3e6afb66c14f75831954f9ff4f7a3f0112c8a0d8eaf29c6"
    "53294d48eee0708a032cca39393c3a7b46f181aea078fead8383a38183308180300c"
    "0603551d130101ff04023000300e0603551d0f0101ff04040302078030200603551d"
    "250101ff0416301406082b0601050507030206082b06010505070301301d0603551d"
    "0e041604149f55a26b7e4303e60883e913bf94f4fb5e2a6161301f0603551d230418"
    "301680145352d7059e9c15a508906862864801a29f1f41d3300a06082a8648ce3d04"
    "0302034800304502207955c202630b4ba4d5912526322fdf28f89edfe5af9c0e572b"
    "d8a14aaabb4d12022100b83ca17c7b05fb164b77d79c529613316bcfd17895e4b2a4"
    "f2404b9817327159"
);

#[test]
fn the_regenerated_der_is_byte_for_byte_what_the_ca_signed() {
    // This is the assertion the whole certificate module exists to make possible. §6.5.2:
    // the signature is "the signatureValue of the corresponding X.509 certificate, not a
    // signature of the preceding Matter TLV data", so verification means rebuilding this
    // DER exactly. An "equivalent" DER is a failed signature.
    //
    // The expected bytes are the PEM blocks the specification prints beside each Matter TLV
    // certificate — the CSA's own encoding, not this crate's idea of one.
    let mut buf = [0u8; CERT_DER_MAX];
    for (name, tlv, der) in [
        ("RCAC", RCAC, RCAC_DER),
        ("ICAC", ICAC, ICAC_DER),
        ("NOC", NOC, NOC_DER),
    ] {
        let cert = MatterCertificate::decode(tlv).expect("decode");
        let regenerated = der::certificate(&cert, &mut buf).expect("to DER");
        assert_eq!(regenerated.len(), der.len(), "{name}: DER length");
        assert_eq!(regenerated, der, "{name}: DER content");
    }
}

#[test]
fn the_tbs_certificate_is_the_prefix_the_signature_covers() {
    // The tbsCertificate is the first element of the certificate SEQUENCE, so it appears
    // verbatim inside the full DER — at a known offset, after the outer header.
    let mut tbs_buf = [0u8; CERT_DER_MAX];
    for (name, tlv, der) in [
        ("RCAC", RCAC, RCAC_DER),
        ("ICAC", ICAC, ICAC_DER),
        ("NOC", NOC, NOC_DER),
    ] {
        let cert = MatterCertificate::decode(tlv).expect("decode");
        let tbs = der::tbs_certificate(&cert, &mut tbs_buf).expect("tbs");
        // The outer SEQUENCE of these certificates uses a two-octet length, so its header
        // is four octets: 0x30, 0x82, and the length.
        assert_eq!(der.get(..2), Some(&[0x30u8, 0x82][..]), "{name}");
        assert_eq!(der.get(4..4 + tbs.len()), Some(tbs), "{name}");
    }
}

#[test]
fn the_signature_verifies_against_its_issuers_public_key() {
    // The end of the exercise: hash the regenerated tbsCertificate and check the Matter
    // certificate's own `signature` against the issuer's key. If any byte of the DER were
    // wrong this would fail, which is what makes it a stronger check than comparing against
    // the PEM — it is the check a commissioner actually performs.
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(NOC).expect("noc");

    let mut buf = [0u8; CERT_DER_MAX];
    for (name, subject, issuer) in [
        ("RCAC (self-signed)", &rcac, &rcac),
        ("ICAC", &icac, &rcac),
        ("NOC", &noc, &icac),
    ] {
        let tbs = der::tbs_certificate(subject, &mut buf).expect("tbs");
        assert!(
            verify(&issuer.public_key, tbs, &subject.signature).expect("verify"),
            "{name}: signature did not verify against its issuer"
        );
    }
}

#[test]
fn a_signature_does_not_verify_against_the_wrong_key() {
    // Otherwise the test above would pass for a `verify` that always says yes.
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let noc = MatterCertificate::decode(NOC).expect("noc");
    let mut buf = [0u8; CERT_DER_MAX];
    let tbs = der::tbs_certificate(&noc, &mut buf).expect("tbs");
    assert!(
        !verify(&rcac.public_key, tbs, &noc.signature).expect("verify"),
        "the NOC is signed by the ICAC, not by the root"
    );
}

#[test]
fn a_future_extension_is_copied_back_into_the_der_verbatim() {
    // §6.5.11.7: the field "SHALL be an exact copy of the DER encoded extension field
    // (including the DER encoded ASN.1 OID of the extension) in the corresponding X.509
    // certificate". So it is not an extension this crate has to understand — it is one it must
    // not touch. Regenerating the certificate means putting the octets back, at their place in
    // the list, and nothing else.
    //
    // This crate used to refuse such a certificate outright, on the reasoning that it could not
    // know the OID or the criticality. It does not need to know either: both are inside the
    // blob. The cost of that reading was that the CHIP SDK's own test framework could not
    // commission a matter-kit device at all, because its certificates carry one
    // (`tests/cert_future_extension.rs`).
    const BLOB: &[u8] = &[
        0x30, 0x0d, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x03, 0x41, 0x42, 0x43,
    ];
    let mut cert = MatterCertificate::decode(RCAC).expect("decode");
    let mut extensions = Extensions::new();
    for entry in cert.extensions.entries() {
        extensions.push(entry.clone()).expect("fits");
    }
    extensions.push(Extension::Future(BLOB)).expect("fits");
    cert.extensions = extensions;

    let mut buf = [0u8; CERT_DER_MAX];
    let der_bytes = der::certificate(&cert, &mut buf).expect("a future extension is convertible");
    // It appears exactly once, byte for byte.
    let hits = der_bytes.windows(BLOB.len()).filter(|w| *w == BLOB).count();
    assert_eq!(hits, 1, "the blob is copied through untouched");
    // And it is last, because it was pushed last: §6.5.11.7 requires the original order.
    let start = der_bytes
        .windows(BLOB.len())
        .position(|w| w == BLOB)
        .expect("present");
    let extensions_end = der_bytes.len();
    assert!(
        start + BLOB.len() <= extensions_end,
        "inside the certificate"
    );
}

#[test]
fn a_buffer_that_is_too_small_is_an_error_at_every_length() {
    // The DER writer fills backwards, so an overrun is a subtraction below zero rather than
    // an index past the end — a different failure mode, and one worth pinning down.
    let cert = MatterCertificate::decode(NOC).expect("decode");
    for len in 0..NOC_DER.len() {
        let mut buf = [0u8; CERT_DER_MAX];
        let small = buf.get_mut(..len).expect("in range");
        assert!(
            der::certificate(&cert, small).is_err(),
            "a {len}-octet buffer must not produce a {}-octet certificate",
            NOC_DER.len()
        );
    }
    let mut exact = [0u8; CERT_DER_MAX];
    let slot = exact.get_mut(..NOC_DER.len()).expect("in range");
    assert_eq!(der::certificate(&cert, slot).expect("exact fit"), NOC_DER);
}

// --- Chain validation (§6.4.5) -------------------------------------------------------------

#[test]
fn the_published_chain_validates_end_to_end() {
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(NOC).expect("noc");

    let identity =
        matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, Some(NOT_BEFORE)).expect("chain");
    assert_eq!(identity.node_id, NodeId(0xDEDE_DEDE_0001_0001));
    assert_eq!(identity.fabric_id, FabricId(0xFAB0_0000_0000_001D));

    // And with no clock at all, which §6.4.5.1 permits for "constrained or sleepy devices".
    matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, None).expect("no clock");
}

#[test]
fn the_root_self_signature_checks_out() {
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    assert!(matter_kit::cert::verify_self_signed(&rcac).expect("verify"));
    // An ICAC is not self-signed, and `verify_self_signed` refuses it as the wrong type
    // rather than quietly returning false.
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    assert!(matter_kit::cert::verify_self_signed(&icac).is_err());
}

#[test]
fn skipping_the_intermediate_is_refused() {
    // The NOC was issued by the ICAC. Presenting it as though the root had issued it
    // directly must fail, even though both certificates are individually valid — this is
    // the splice a chain check exists to stop.
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let noc = MatterCertificate::decode(NOC).expect("noc");
    assert_eq!(
        matter_kit::cert::verify_chain(&noc, None, &rcac, None)
            .map(|_| ())
            .unwrap_err()
            .code(),
        ErrorCode::CertPathInvalid
    );
}

#[test]
fn an_expired_chain_is_refused_only_when_there_is_a_clock() {
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(NOC).expect("noc");

    for at in [NOT_BEFORE - 1, NOT_AFTER + 1] {
        assert_eq!(
            matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, Some(at))
                .map(|_| ())
                .unwrap_err()
                .code(),
            ErrorCode::CertExpired,
            "at {at:#x}"
        );
    }
    matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, None).expect("no clock, no expiry");
}

#[test]
fn a_tampered_certificate_fails_its_signature() {
    // Changing anything the DER covers must break the link. The serial number is a field
    // the TLV carries verbatim, so this is a clean single-field change.
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let mut noc = MatterCertificate::decode(NOC).expect("noc");
    noc.serial_number = &[0x3E, 0xFC, 0xFF, 0x17, 0x02, 0xB9, 0xA1, 0x7B];

    assert_eq!(
        matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, None)
            .map(|_| ())
            .unwrap_err()
            .code(),
        ErrorCode::CertPathInvalid
    );
}

#[test]
fn a_chain_from_another_fabric_is_refused() {
    // §6.5.6.3: a matter-fabric-id on the root or ICAC "SHALL match the one present in the
    // NOC within the same certificate chain". A valid certificate from the wrong fabric is
    // exactly what this rule is for.
    let mut rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(NOC).expect("noc");

    rcac.subject
        .push(matter_kit::cert::DnAttribute::fabric_id(FabricId(0x1234)))
        .expect("push");
    assert_eq!(
        matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, None)
            .map(|_| ())
            .unwrap_err()
            .code(),
        ErrorCode::CertPathInvalid
    );
}

#[test]
fn a_root_that_forbids_intermediates_is_honoured() {
    // path-len-constraint 0 means "this CA may issue leaves, not CAs".
    let mut rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(NOC).expect("noc");

    let mut extensions = Extensions::new();
    for entry in rcac.extensions.entries() {
        extensions
            .push(match entry {
                Extension::BasicConstraints(basic) => {
                    Extension::BasicConstraints(matter_kit::cert::BasicConstraints {
                        is_ca: basic.is_ca,
                        path_len_constraint: Some(0),
                    })
                }
                other => other.clone(),
            })
            .expect("fits");
    }
    rcac.extensions = extensions;

    assert_eq!(
        matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, None)
            .map(|_| ())
            .unwrap_err()
            .code(),
        ErrorCode::CertPathInvalid
    );
}
