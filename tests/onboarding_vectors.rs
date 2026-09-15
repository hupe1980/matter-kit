//! Onboarding payloads from outside this crate, decoded and re-encoded.
//!
//! The QR and manual-code encodings are bit-packing and a radix conversion — the kind of
//! code that round-trips against itself perfectly while being wrong. These vectors come
//! from somewhere else:
//!
//! * `MT:-24J0AFN00KA0648G00` and `34970112332` are the payload and manual code every
//!   CHIP test device carries, quoted throughout the SDK's documentation and used by
//!   `chip-tool pairing code`. If this crate produces those strings from the same inputs,
//!   its bit layout, base-38 conversion and Verhoeff digit all agree with the reference
//!   implementation.
//! * `MT:-MOA57ZU02IT2L2BJ00` appears in Core §5.7.3.1 as a worked example embedded in a
//!   commissioning fallback URL. It is a different device entirely — different product,
//!   discriminator, passcode and discovery method — so it exercises field positions the
//!   test-device payload leaves at convenient values.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use matter_kit::commissioning::{CustomFlow, DiscoveryCapabilities, OnboardingPayload, Passcode};
use matter_kit::msg::VendorId;

/// What the CHIP test devices — and therefore every `chip-tool` example — carry.
const TEST_DEVICE_QR: &str = "MT:-24J0AFN00KA0648G00";
const TEST_DEVICE_MANUAL: &str = "34970112332";

fn test_device() -> OnboardingPayload {
    OnboardingPayload::new(
        VendorId(0xFFF1),
        0x8001,
        3840,
        Passcode::new(20_202_021).unwrap(),
        DiscoveryCapabilities::ON_IP_NETWORK,
        CustomFlow::Standard,
    )
    .unwrap()
}

#[test]
fn the_test_device_payload_encodes_to_the_published_string() {
    // The single most-quoted onboarding payload in the whole ecosystem. Producing it
    // exactly means the bit layout of Core Table 59 and the base-38 method of §5.1.3.1.5
    // both agree with the reference implementation.
    assert_eq!(test_device().to_qr().unwrap().as_str(), TEST_DEVICE_QR);
}

#[test]
fn the_test_device_manual_code_matches_the_published_digits() {
    // Including the Verhoeff check digit, which is the last one.
    assert_eq!(
        test_device().to_manual_code(false).unwrap().as_str(),
        TEST_DEVICE_MANUAL
    );
}

#[test]
fn the_published_strings_parse_back_to_the_same_device() {
    let from_qr = OnboardingPayload::from_qr(TEST_DEVICE_QR).unwrap();
    assert_eq!(from_qr, test_device());

    let from_manual = OnboardingPayload::from_manual_code(TEST_DEVICE_MANUAL).unwrap();
    assert_eq!(from_manual.passcode, test_device().passcode);
    // A manual code carries only the top four bits of the discriminator, so the two forms
    // agree on those and only those.
    assert_eq!(
        from_manual.discriminator >> 8,
        test_device().discriminator >> 8
    );
}

#[test]
fn the_specifications_own_worked_example_decodes_coherently() {
    // Core §5.7.3.1: "Onboarding payload QR content MT:-MOA57ZU02IT2L2BJ00 was embedded
    // within MTop key". The specification does not print the fields, so what this checks
    // is that they are *coherent* — every one in range, and the whole thing re-encoding to
    // the same string. A bit-packing error would show up as an out-of-range field or a
    // different string.
    let payload = OnboardingPayload::from_qr("MT:-MOA57ZU02IT2L2BJ00").unwrap();

    assert!(payload.discriminator <= 0x0FFF, "12-bit discriminator");
    assert!(
        (Passcode::MIN..=Passcode::MAX).contains(&payload.passcode.value()),
        "passcode in range"
    );
    assert!(
        !Passcode::INVALID.contains(&payload.passcode.value()),
        "not one of the twelve forbidden values"
    );
    assert_eq!(
        payload.to_qr().unwrap().as_str(),
        "MT:-MOA57ZU02IT2L2BJ00",
        "re-encoding must reproduce the specification's own string"
    );
}

#[test]
fn a_ble_test_payload_decodes_too() {
    // The same test device advertising over BLE rather than IP, which moves the discovery
    // bitmask and therefore every bit after it.
    let payload = OnboardingPayload::from_qr("MT:Y.K9042C00KA0648G00").unwrap();
    assert_eq!(payload.vendor_id, VendorId(0xFFF1));
    assert_eq!(payload.passcode.value(), 20_202_021);
    assert_eq!(payload.discriminator, 3840);
    assert_eq!(payload.discovery, DiscoveryCapabilities::BLE);
    assert_eq!(
        payload.to_qr().unwrap().as_str(),
        "MT:Y.K9042C00KA0648G00",
        "and re-encodes"
    );
}

#[test]
fn every_published_string_survives_every_single_character_change() {
    // Not a specification requirement — a crate one. A QR scanner misreads characters, and
    // a misread payload must be an error rather than a panic or a plausible-looking
    // different device.
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";
    for original in [TEST_DEVICE_QR, "MT:-MOA57ZU02IT2L2BJ00"] {
        let body = original.strip_prefix("MT:").unwrap();
        for position in 0..body.len() {
            for replacement in ALPHABET {
                let mut mutated = heapless::String::<32>::new();
                for (i, c) in body.bytes().enumerate() {
                    let c = if i == position { *replacement } else { c };
                    mutated.push(char::from(c)).unwrap();
                }
                // Whatever it decodes to, it must not panic and must not be the original.
                if let Ok(decoded) = OnboardingPayload::from_qr(&mutated)
                    && mutated.as_str() != body
                {
                    assert_ne!(
                        decoded,
                        OnboardingPayload::from_qr(original).unwrap(),
                        "a changed character produced the same device: {mutated}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_manual_code_with_any_single_digit_wrong_is_rejected() {
    // The published code, with each digit replaced by each other digit: 11 × 9 = 99
    // mistypings, every one of which Verhoeff must catch.
    let bytes = TEST_DEVICE_MANUAL.as_bytes();
    let mut caught = 0u32;
    for position in 0..bytes.len() {
        for replacement in b'0'..=b'9' {
            if bytes[position] == replacement {
                continue;
            }
            let mut mutated = heapless::String::<32>::new();
            for (i, b) in bytes.iter().enumerate() {
                let c = if i == position { replacement } else { *b };
                mutated.push(char::from(c)).unwrap();
            }
            assert!(
                OnboardingPayload::from_manual_code(&mutated).is_err(),
                "{mutated} was accepted"
            );
            caught += 1;
        }
    }
    assert_eq!(caught, 99, "every single-digit mistyping was tested");
}

#[test]
fn the_qr_and_manual_forms_agree_about_the_passcode() {
    // The two encodings share nothing but the values they carry, so agreeing on the
    // passcode across a range of them is real evidence both are right.
    for passcode in [1u32, 7, 1_000, 20_202_021, 67_108_863, 99_999_998] {
        let payload = OnboardingPayload::new(
            VendorId(0x1234),
            0x5678,
            0x0ABC,
            Passcode::new(passcode).unwrap(),
            DiscoveryCapabilities::BLE,
            CustomFlow::Standard,
        )
        .unwrap();

        let from_qr = OnboardingPayload::from_qr(&payload.to_qr().unwrap()).unwrap();
        let from_manual =
            OnboardingPayload::from_manual_code(&payload.to_manual_code(false).unwrap()).unwrap();

        assert_eq!(from_qr.passcode.value(), passcode);
        assert_eq!(from_manual.passcode.value(), passcode);
        assert_eq!(from_qr.discriminator, 0x0ABC);
        assert_eq!(from_manual.discriminator >> 8, 0x0ABC >> 8);
    }
}
