//! The onboarding payload (Core §5.1), read by two implementations.
//!
//! This is the best first differential target in the specification: §5.1 is small, entirely
//! self-contained, has no cryptography, no I/O and no state, and *both* crates implement it from
//! the same prose. It is also the one a user meets first — a QR code on a box and eleven digits
//! on a label — so a disagreement here is a device that will not pair.
//!
//! Three properties, in increasing strength:
//!
//! 1. **Both agree with the specification.** §5.1.3 and §5.1.4 publish one worked example each,
//!    and each crate reproduces them. This is the weakest of the three, because a shared
//!    misreading of anything the example does not exercise survives it.
//! 2. **What one writes, the other reads.** `matter-kit` encodes, `rs-matter` decodes, and every
//!    field comes back. This is where a disagreement about bit order or field width shows up.
//! 3. **What one reads, the other reads identically — over arbitrary inputs.** The property
//!    test drives every field across its whole range. Neither crate's own test suite can find a
//!    disagreement here, because each is checking its own reading of the same sentences.
//!
//! Where the two differ, one of them is wrong and neither can say which; the point of writing it
//! down is that the disagreement becomes visible at all.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use matter_kit::commissioning::{
    CustomFlow, DiscoveryCapabilities, OnboardingPayload, Passcode, QR_PREFIX,
};
use matter_kit::msg::VendorId;

use rs_matter::pairing::qr::QrPayload;

// `rs_matter::BasicCommData` would let this compare the two *encoders* directly, but it cannot
// be constructed downstream: its `password` field is public while the type it holds,
// `Spake2pVerifierPassword`, lives in a `pub(crate)` module and is re-exported nowhere. So the
// manual-code comparison runs in the one direction the public API allows — matter-kit encodes,
// rs-matter parses — which still catches any disagreement about the digit layout.

/// §5.1.3.1's worked example, which both crates must reproduce.
const SPEC_QR: &str = "MT:-24J0AFN00KA0648G00";
/// §5.1.4.1's worked example.
const SPEC_MANUAL: &str = "34970112332";
const SPEC_PASSCODE: u32 = 20_202_021;
const SPEC_DISCRIMINATOR: u16 = 3840;

// --- 1. Both agree with the specification -------------------------------------------------------

#[test]
fn both_crates_reproduce_the_specifications_qr_example() {
    let ours = OnboardingPayload::from_qr(SPEC_QR).expect("matter-kit parses §5.1.3.1's example");

    let mut buf = [0u8; 128];
    let theirs = QrPayload::parse(SPEC_QR, &mut buf).expect("rs-matter parses it too");

    assert_eq!(ours.passcode.value(), SPEC_PASSCODE);
    assert_eq!(theirs.passcode(), SPEC_PASSCODE);
    assert_eq!(ours.discriminator, SPEC_DISCRIMINATOR);
}

#[test]
fn both_crates_reproduce_the_specifications_manual_code_example() {
    let ours = OnboardingPayload::from_manual_code(SPEC_MANUAL)
        .expect("matter-kit parses §5.1.4.1's example");
    let theirs = QrPayload::parse_pairing_code(SPEC_MANUAL).expect("rs-matter parses it too");

    assert_eq!(ours.passcode.value(), SPEC_PASSCODE);
    assert_eq!(theirs.passcode(), SPEC_PASSCODE);
    // A manual code carries only the *short* discriminator — the upper four bits — which is
    // why rs-matter deliberately exposes no `discriminator()` on this payload type.
    assert_eq!(ours.short_discriminator(), (SPEC_DISCRIMINATOR >> 8) as u8);
}

// --- 2. What one writes, the other reads --------------------------------------------------------

fn ours(vendor: u16, product: u16, discriminator: u16, passcode: u32) -> OnboardingPayload {
    OnboardingPayload::new(
        VendorId(vendor),
        product,
        discriminator,
        Passcode::new(passcode).expect("a valid passcode"),
        DiscoveryCapabilities::ON_IP_NETWORK,
        CustomFlow::Standard,
    )
    .expect("a valid payload")
}

#[test]
fn rs_matter_reads_every_field_matter_kit_writes() {
    let payload = ours(0xFFF1, 0x8001, 0x0F00, 20_202_021);
    let qr = payload.to_qr().expect("encode");

    let mut buf = [0u8; 128];
    let theirs = QrPayload::parse(&qr, &mut buf).expect("rs-matter reads what we wrote");

    assert_eq!(theirs.passcode(), payload.passcode.value());
    assert_eq!(theirs.vid(), payload.vendor_id.0);
    assert_eq!(theirs.pid(), payload.product_id);
    assert_eq!(theirs.discriminator(), payload.discriminator);
}

#[test]
fn rs_matter_reads_every_manual_code_matter_kit_writes() {
    // The eleven digits are three packed groups plus a Verhoeff check digit, and every one of
    // the boundaries below is a place the packing could be off by a bit without either crate
    // noticing on its own.
    for (discriminator, passcode) in [
        (SPEC_DISCRIMINATOR, SPEC_PASSCODE),
        (0x0FFF, 1),
        (0x0000, 99_999_998),
        (0x0ABC, 12_345_679),
        (0x0800, 54_321_098),
    ] {
        let code = ours(0xFFF1, 0x8001, discriminator, passcode)
            .to_manual_code(false)
            .expect("matter-kit encodes");
        let theirs = QrPayload::parse_pairing_code(&code)
            .unwrap_or_else(|e| panic!("rs-matter rejected our manual code {code}: {e:?}"));

        assert_eq!(
            theirs.passcode(),
            passcode,
            "passcode through {code} (discriminator {discriminator:#06x})"
        );
        assert_eq!(
            theirs.short_discriminator(),
            (discriminator >> 8) as u8,
            "short discriminator through {code}"
        );
    }
}

// --- 3. Arbitrary inputs ------------------------------------------------------------------------

mod property {
    use super::{OnboardingPayload, QR_PREFIX, QrPayload, ours};
    use proptest::prelude::*;

    proptest! {
        /// Every field across its whole range, through the QR form.
        ///
        /// A disagreement about a field's width or bit offset shows up here and nowhere in
        /// either crate's own suite, because each one packs and unpacks with the same
        /// constant it would have to get wrong twice to notice.
        #[test]
        fn a_qr_matter_kit_writes_is_read_identically_by_rs_matter(
            vendor in any::<u16>(),
            product in any::<u16>(),
            discriminator in 0u16..=0x0FFF,
            passcode in 1u32..=99_999_998,
        ) {
            // §5.1.1.6 forbids a handful of trivial passcodes; skip what our own constructor
            // refuses rather than asserting on values the specification excludes.
            let Ok(payload) = std::panic::catch_unwind(|| {
                ours(vendor, product, discriminator, passcode)
            }) else {
                return Ok(());
            };

            let qr = payload.to_qr().expect("encode");
            let mut buf = [0u8; 256];
            let theirs = QrPayload::parse(&qr, &mut buf).expect("rs-matter reads it");

            prop_assert_eq!(theirs.passcode(), payload.passcode.value());
            prop_assert_eq!(theirs.vid(), vendor);
            prop_assert_eq!(theirs.pid(), product);
            prop_assert_eq!(theirs.discriminator(), discriminator);

            // ...and our own reader agrees with our own writer, which is what makes the
            // comparison above meaningful rather than a test of the encoder alone.
            let round = OnboardingPayload::from_qr(&qr).expect("decode");
            prop_assert_eq!(round.discriminator, discriminator);
            prop_assert_eq!(round.passcode.value(), passcode);
        }

        /// Arbitrary text, to both parsers. Neither may panic, and — the part worth asserting —
        /// a string one of them *accepts* must not be rejected by the other: a commissioner
        /// that reads a QR its peer considers malformed is a device that cannot be paired.
        #[test]
        fn the_two_parsers_accept_the_same_strings(s in "\\PC{0,40}") {
            let text = format!("{QR_PREFIX}{s}");
            let mut buf = [0u8; 256];

            let ours_ok = OnboardingPayload::from_qr(&text).is_ok();
            let theirs_ok = QrPayload::parse(&text, &mut buf).is_ok();

            // rs-matter keeps trailing optional TLV that matter-kit's no-TLV form refuses, so
            // "they agree" is asserted in the direction that matters: whatever *we* accept,
            // the other implementation must also accept, or a device we commissioned from a
            // printed code is one a second ecosystem cannot.
            if ours_ok {
                prop_assert!(
                    theirs_ok,
                    "matter-kit accepted a QR rs-matter rejects: {text}"
                );
            }
        }
    }
}
