//! The development attestation chain (Core §6.2.2), verified by §6.2.3's own procedure.
//!
//! The same argument as `tests/ca.rs`: this file builds certificates and `attestation::chain`
//! validates them, and the two were written from §6.2.2 independently. A factory whose output
//! passes the verifier that rejects everything else is evidence; one that agreed only with
//! itself would be a closed loop.
//!
//! A chain from here is a *development* chain — the PAA is one this code made up, and no
//! commissioner should trust it. §6.2.2.1 makes the trust decision the commissioner's, and
//! `0xFFF1`–`0xFFF4` are the vendor ids the CSA reserves so that a development device is
//! visibly a development device.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::attestation::factory::{DevelopmentChain, TEST_VENDOR_ID};
use matter_kit::attestation::x509::KeyUsage;
use matter_kit::attestation::{X509Certificate, verify_dac_chain};
use matter_kit::crypto::{KeyHandle, KeyPurpose, KeyStore, PublicKey, SoftKeyStore};
use matter_kit::msg::VendorId;

const NOW: u32 = 757_382_400;
const PRODUCT_ID: u16 = 0x8000;
const DER_MAX: usize = 600;

type Keys = SoftKeyStore<8>;

fn key(keys: &mut Keys, seed: u8) -> (KeyHandle, PublicKey) {
    let mut secret = [1u8; 32];
    secret[31] = seed;
    let handle = keys
        .import(KeyPurpose::DeviceAttestation, &secret)
        .expect("a valid key");
    let public = keys.public_key(handle).expect("a public key");
    (handle, public)
}

struct Chain {
    paa: Vec<u8>,
    pai: Vec<u8>,
    dac: Vec<u8>,
}

fn chain(chain: &DevelopmentChain, keys: &mut Keys) -> Chain {
    let (paa_key, _) = key(keys, 1);
    let (pai_key, pai_public) = key(keys, 2);
    let (_, dac_public) = key(keys, 3);

    let mut buf = [0u8; DER_MAX];
    let paa = chain.paa(keys, &mut buf, paa_key).expect("a PAA").to_vec();
    let mut buf = [0u8; DER_MAX];
    let pai = chain
        .pai(keys, &mut buf, paa_key, &pai_public)
        .expect("a PAI")
        .to_vec();
    let mut buf = [0u8; DER_MAX];
    let dac = chain
        .dac(keys, &mut buf, pai_key, &dac_public, PRODUCT_ID)
        .expect("a DAC")
        .to_vec();
    Chain { paa, pai, dac }
}

#[test]
fn a_development_chain_passes_the_device_attestation_procedure() {
    // §6.2.3's chain validation, in full: three certificates, two signatures, the issuer and
    // subject key identifiers lining up, and the vendor id matching across the PAI/DAC link.
    let development = DevelopmentChain::new(NOW, 10);
    let mut keys = Keys::new();
    let built = chain(&development, &mut keys);

    let paa = X509Certificate::parse(&built.paa).expect("a parseable PAA");
    let pai = X509Certificate::parse(&built.pai).expect("a parseable PAI");
    let dac = X509Certificate::parse(&built.dac).expect("a parseable DAC");
    let verified = verify_dac_chain(&dac, &pai, &paa).expect("a valid chain");
    assert_eq!(verified.vendor_id, TEST_VENDOR_ID);
    assert_eq!(verified.product_id, PRODUCT_ID);
}

#[test]
fn each_certificate_carries_what_its_role_requires() {
    // §6.2.2.4's rules, which `verify_dac_chain` enforces one at a time — worth asserting
    // directly so a failure says *which* rule rather than "invalid".
    let development = DevelopmentChain::new(NOW, 10);
    let mut keys = Keys::new();
    let built = chain(&development, &mut keys);
    let paa = X509Certificate::parse(&built.paa).expect("parses");
    let pai = X509Certificate::parse(&built.pai).expect("parses");
    let dac = X509Certificate::parse(&built.dac).expect("parses");

    // Rule 2 and 3: the PAA is a CA one level above the DAC, the PAI exactly zero.
    assert!(paa.basic_constraints.expect("basic").is_ca);
    assert_eq!(paa.basic_constraints.expect("basic").path_len, Some(1));
    assert!(pai.basic_constraints.expect("basic").is_ca);
    assert_eq!(pai.basic_constraints.expect("basic").path_len, Some(0));

    // Rule 12: a DAC signs attestations and is not a CA.
    assert!(!dac.basic_constraints.expect("basic").is_ca);
    assert_eq!(dac.key_usage, Some(KeyUsage::DIGITAL_SIGNATURE));

    // Rules 8, 9 and 8a: the DAC's subject carries both ids, and its vendor id matches the
    // issuer's — the PAI that signed it.
    assert_eq!(dac.subject_vid_pid.vendor_id, Some(TEST_VENDOR_ID));
    assert_eq!(dac.subject_vid_pid.product_id, Some(PRODUCT_ID));
    assert_eq!(dac.issuer_vid_pid.vendor_id, Some(TEST_VENDOR_ID));

    // Rules 11c and 11d: the identifiers chain.
    assert_eq!(dac.authority_key_id, pai.subject_key_id);
    assert_eq!(pai.authority_key_id, paa.subject_key_id);
    assert_eq!(paa.authority_key_id, paa.subject_key_id, "self-signed");
    assert!(paa.issuer == paa.subject);
}

#[test]
fn a_dac_from_a_different_paa_does_not_verify() {
    // The signature is the proof. Two chains built the same way from different keys must not
    // be interchangeable, or the chain check is decoration.
    let development = DevelopmentChain::new(NOW, 10);
    let mut keys = Keys::new();
    let built = chain(&development, &mut keys);

    let mut other_keys = Keys::new();
    let (other_paa_key, _) = key(&mut other_keys, 9);
    let mut buf = [0u8; DER_MAX];
    let other_paa = development
        .paa(&other_keys, &mut buf, other_paa_key)
        .expect("a PAA")
        .to_vec();

    let pai = X509Certificate::parse(&built.pai).expect("parses");
    let dac = X509Certificate::parse(&built.dac).expect("parses");
    let other_paa = X509Certificate::parse(&other_paa).expect("parses");
    assert!(
        verify_dac_chain(&dac, &pai, &other_paa).is_err(),
        "a DAC verified against a PAA that did not sign its PAI"
    );
}

#[test]
fn a_chain_claiming_a_real_vendor_id_is_refused() {
    // A development chain claiming a real vendor's id is a forgery, however well-intentioned,
    // and §6.2.2 gives a commissioner no way to tell the two apart except the id. `0xFFF1`
    // through `0xFFF4` are the ones reserved for this.
    let development = DevelopmentChain::new(NOW, 10);
    for vendor in [0x0000u16, 0x1234, 0xFFF0, 0xFFF5] {
        assert!(
            development.for_vendor(VendorId(vendor)).is_err(),
            "{vendor:#06x} was accepted as a development vendor id"
        );
    }
    for vendor in [0xFFF1u16, 0xFFF2, 0xFFF3, 0xFFF4] {
        assert!(development.for_vendor(VendorId(vendor)).is_ok());
    }
}

#[test]
fn the_vendor_and_product_ids_are_uppercase_hex() {
    // §6.2.2.2's fallback form is "uppercase hexadecimal, exactly 4 characters", and this
    // crate's own parser calls `Mvid:fff1` invalid — so a factory that wrote lowercase would
    // produce certificates its own verifier rejects.
    let development = DevelopmentChain::new(NOW, 10)
        .for_vendor(VendorId(0xFFF2))
        .unwrap();
    let mut keys = Keys::new();
    let (paa_key, _) = key(&mut keys, 1);
    let (pai_key, pai_public) = key(&mut keys, 2);
    let (_, dac_public) = key(&mut keys, 3);
    let mut buf = [0u8; DER_MAX];
    let _ = development.paa(&keys, &mut buf, paa_key).expect("a PAA");
    let mut buf = [0u8; DER_MAX];
    let pai = development
        .pai(&keys, &mut buf, paa_key, &pai_public)
        .expect("a PAI")
        .to_vec();
    let mut buf = [0u8; DER_MAX];
    let dac = development
        .dac(&keys, &mut buf, pai_key, &dac_public, 0x00AB)
        .expect("a DAC")
        .to_vec();

    // The text is in the DER, uppercase.
    assert!(
        dac.windows(9).any(|w| w == b"Mvid:FFF2"),
        "the vendor id was not written as uppercase hex"
    );
    assert!(
        dac.windows(9).any(|w| w == b"Mpid:00AB"),
        "the product id was not padded"
    );
    assert!(pai.windows(9).any(|w| w == b"Mvid:FFF2"));

    // ...and the parser reads it back.
    let dac = X509Certificate::parse(&dac).expect("parses");
    assert_eq!(dac.subject_vid_pid.vendor_id, Some(VendorId(0xFFF2)));
    assert_eq!(dac.subject_vid_pid.product_id, Some(0x00AB));
}

#[test]
fn a_certificate_fits_the_six_hundred_octet_limit() {
    // §6.1.3: "All certificates SHALL NOT be longer than 600 bytes in their uncompressed DER
    // format", and §11.18.6.3's `CertificateChainResponse` is sized for exactly that. A factory
    // that emitted more would produce a device that cannot answer a commissioner.
    let development = DevelopmentChain::new(NOW, 10);
    let mut keys = Keys::new();
    let built = chain(&development, &mut keys);
    for (name, der) in [
        ("PAA", &built.paa),
        ("PAI", &built.pai),
        ("DAC", &built.dac),
    ] {
        assert!(der.len() <= DER_MAX, "{name} is {} octets", der.len());
    }
}

/// A factory key is random, so the serial derived from its digest is random too — and a serial
/// number is a DER INTEGER, where the top octet's high bit is the *sign* and one digest in 256
/// is not valid content at all (a redundant sign octet, which DER's shortest-form rule
/// forbids).
///
/// The fixtures above use three fixed seeds. That is why the chain built correctly in every
/// test in this file and a device generating one from a real key produced a negative serial
/// half the time, and refused to build a chain at all roughly one boot in eighty-five.
#[test]
fn every_key_yields_a_positive_serial_number() {
    let development = DevelopmentChain::new(NOW, 10);
    for seed in 0..=u8::MAX {
        let mut keys = Keys::new();
        let (paa_key, _) = key(&mut keys, seed);
        let mut buf = [0u8; DER_MAX];
        let paa = development
            .paa(&keys, &mut buf, paa_key)
            .unwrap_or_else(|e| panic!("seed {seed}: the PAA did not build: {e:?}"));
        let parsed = X509Certificate::parse(paa).expect("a parseable PAA");
        let first = parsed.serial_number[0];
        assert!(
            (0x01..0x80).contains(&first),
            "seed {seed}: the serial starts {first:#04x}, which is negative or a redundant zero"
        );
    }
}
