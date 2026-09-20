//! A certificate chain issued by somebody else's CA, carrying a `future-extension`.
//!
//! These three certificates were issued by the **CHIP SDK's own test framework** during a run
//! of `interop/chip/python.sh`, and captured off the wire. They are what the Test Harness calls
//! *maximized* certificates: deliberately grown to the limits §6.1.3 sets — 400 octets of TLV
//! for the RCAC and ICAC, against 600 of DER — by padding them with a §6.5.11.6
//! `future-extension` holding a `subjectAltName` full of `A`s.
//!
//! That padding is the point. R12 is the risk that this crate cannot regenerate somebody
//! else's DER byte for byte, and §6.5.2 makes that regeneration the *only* way to verify a
//! Matter certificate's signature — "validating the signature in a Matter certificate entails
//! its logical conversion to the corresponding X.509 certificate". Every fixture the crate had
//! before this one came out of the specification itself, and the specification does not print a
//! certificate with a future extension in it. This crate refused these outright, which meant it
//! could not be commissioned by the reference implementation's test framework at all.
//!
//! §6.5.11.6 is what makes the fix a re-emission rather than a reconstruction: the field "SHALL
//! be an exact copy of the DER encoded extension field (including the DER encoded ASN.1 OID of
//! the extension)", and the extensions "SHALL be encoded in the same order as they appeared in
//! the original X.509 certificate". So the octets already are the extension, and putting them
//! back where they were is the whole job.

// The certificate and secure-channel types this file exercises live behind `rustcrypto`, so
// without the gate `cargo test --no-default-features` fails to *compile* — which is a broken
// gate rather than a failing test, and reports nothing about the code under it.
#![cfg(feature = "rustcrypto")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use hex_literal::hex;
use matter_kit::cert::{CERT_DER_MAX, CERT_TLV_MAX, CertType, Extension, MatterCertificate, der};
use matter_kit::crypto::verify;

/// The framework's root, 400 octets — exactly §6.1.3's cap.
const RCAC: &[u8] = &hex!(
    "1530010101240201370324140118260480228127260580254d3a3706241401182407"
    "0124080130094104f8e85558c95de48c71ec5e43da8f006909e36988672479aef284"
    "0736c6ffd6c09b0da40719895c4b5e37e1497742b0da755ac8d396d8db41784d70a7"
    "f29d9a34370a350129011824026030041401d3665fd7c044911998035c051be1e941"
    "59130c30051401d3665fd7c044911998035c051be1e94159130c3006a63081a30603"
    "551d1104819b04819841414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141"
    "4141414141414141414141414141414141414141414141414118300b40e89f6bfcc9"
    "5315fbe495527e37f93e289b151ea4b25b6a2b5ffb8a92638ae6ea25d922bb5a580a"
    "2b16b1af92e1f0699ea6f2ce917778824b4528f444770f53eb18"
);

/// The framework's intermediate, also at the cap.
const ICAC: &[u8] = &hex!(
    "1530010101240201370324140118260480228127260580254d3a3706241302182407"
    "01240801300941040220ea2373c83cfff6abb74d87a8badf4c5e3aae8c97222e2dbc"
    "44c24209300cac94de993fd002fafb7f3d11d82720a1de94dd052344f109603faa8b"
    "ed098971370a3501290118240260300414187258b838a0bc016d049c4021a8d7240a"
    "7b8b1330051401d3665fd7c044911998035c051be1e94159130c3006a63081a30603"
    "551d1104819b04819841414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141"
    "4141414141414141414141414141414141414141414141414118300b40e4b07d525a"
    "73e40b943fdf84d696513b141c8c372cb0307f4c29840c9afd360662abc1604c4027"
    "4ee50bdb84717f526a835fa2ab05812e3ad15e3b51c03b80b718"
);

/// The NOC it issued for the device.
const NOC: &[u8] = &hex!(
    "1530010101240201370324130218260480228127260580254d3a3706241501261121"
    "433412182407012408013009410418dc5b7dc92c3bc39fb0144e0f4a57123c89e502"
    "441ccedbbacacecbff63b2717ad1c90c652b2d60125501271a6be2b3abcd6a0748e7"
    "73acdb0390806afc0f93370a350128011824020136030402040118300414389717be"
    "96c07759395d4356ed01d859a002d712300514187258b838a0bc016d049c4021a8d7"
    "240a7b8b1330067930770603551d110470046e414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414118300b40dc6371"
    "bbf924d0db16f7c4f5a0685902b8445e4dec9fa168de4c76d1d76d00222221e278d9"
    "28c21294e63a995b443b2c5468395cc2b973059f9196cfca0865a718"
);

#[test]
fn the_chain_is_at_the_size_limits_of_6_1_3() {
    assert_eq!(RCAC.len(), CERT_TLV_MAX);
    assert_eq!(ICAC.len(), CERT_TLV_MAX);
    assert!(NOC.len() <= CERT_TLV_MAX);
}

/// All three decoded before the fix too — refusing them happened later, on the way back to
/// DER. Asserting it here is what localises a future regression.
#[test]
fn every_certificate_decodes() {
    MatterCertificate::decode(RCAC).expect("rcac");
    MatterCertificate::decode(ICAC).expect("icac");
    MatterCertificate::decode(NOC).expect("noc");
}

/// The padding really is a future extension, and it really is a complete DER `Extension`.
#[test]
fn the_padding_is_a_future_extension_holding_a_der_extension() {
    let noc = MatterCertificate::decode(NOC).expect("noc");
    let future: Vec<&[u8]> = noc
        .extensions
        .entries()
        .iter()
        .filter_map(|e| match e {
            Extension::Future(bytes) => Some(*bytes),
            _ => None,
        })
        .collect();
    assert_eq!(future.len(), 1, "one future extension");
    let blob = future[0];
    // `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, ... }` — so a SEQUENCE tag, then a
    // length, then an OID tag. The OID here is 2.5.29.17, subjectAltName: `06 03 55 1d 11`.
    assert_eq!(blob[0], 0x30, "a DER SEQUENCE");
    assert!(
        blob.windows(5).any(|w| w == [0x06, 0x03, 0x55, 0x1d, 0x11]),
        "carries its own OID, which is what makes re-emission possible"
    );
}

/// The regression test proper: regenerate each certificate's TBS and check the CA's signature
/// over it. This is what returned `Unsupported` before, and it is the only check that proves
/// the future extension was put back at the right offset — a byte out of place anywhere in the
/// TBS and the signature simply does not verify.
#[test]
fn the_chain_verifies_after_regenerating_the_der() {
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(NOC).expect("noc");

    for (subject, issuer, what) in [(&icac, &rcac, "icac<-rcac"), (&noc, &icac, "noc<-icac")] {
        let mut buf = [0u8; CERT_DER_MAX];
        let tbs = der::tbs_certificate(subject, &mut buf)
            .unwrap_or_else(|e| panic!("{what}: regenerating the TBS failed: {e:?}"));
        assert!(
            verify(&issuer.public_key, tbs, &subject.signature).expect("verify"),
            "{what}: the regenerated DER does not match what the CA signed"
        );
    }

    // And the root over itself.
    let mut buf = [0u8; CERT_DER_MAX];
    let tbs = der::tbs_certificate(&rcac, &mut buf).expect("rcac tbs");
    assert!(
        verify(&rcac.public_key, tbs, &rcac.signature).expect("verify"),
        "self-signed root"
    );
}

/// The whole chain, through the same entry point `AddNOC` uses.
#[test]
fn the_chain_validates_end_to_end() {
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(NOC).expect("noc");
    rcac.validate_as(CertType::Rcac).expect("rcac shape");
    icac.validate_as(CertType::Icac).expect("icac shape");
    noc.validate_as(CertType::Noc).expect("noc shape");

    let identity = matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, None)
        .expect("the reference implementation's own chain must verify");
    assert!(identity.node_id.is_operational());
}
