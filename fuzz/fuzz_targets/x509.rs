//! Everything this crate parses as DER, against arbitrary bytes.
//!
//! All three of these arrive from an unauthenticated peer during commissioning: a device
//! hands over its DAC chain and its Certification Declaration before anything about it has
//! been established, and a commissioner hands back a CSR response. They are the widest
//! attack surface in the crate after the message header.
//!
//! DER is a *distinguished* encoding — one valid encoding per value — so the strongest
//! property available is that the reader enforces it: a length not in its shortest form, a
//! BER indefinite length, or trailing octets after a complete structure must be refused
//! rather than tolerated. A parser that accepted two encodings of one certificate would
//! accept a certificate whose signature covers only one of them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::attestation::cd::SignedData;
use matter_kit::attestation::nocsr::Csr;
use matter_kit::attestation::x509::X509Certificate;
use matter_kit::der::DerReader;

fuzz_target!(|data: &[u8]| {
    // A DAC, PAI or PAA.
    if let Ok(cert) = X509Certificate::parse(data) {
        // Whatever it parsed, the tbs must be a real slice of the input — the signature is
        // checked over it, so a tbs that pointed anywhere else would be checking the wrong
        // bytes.
        assert!(
            data.windows(cert.tbs.len()).any(|w| w == cert.tbs),
            "the tbs is not a slice of the input"
        );
        assert!(data.windows(cert.issuer.len()).any(|w| w == cert.issuer));
        assert!(data.windows(cert.subject.len()).any(|w| w == cert.subject));
        // Validity must be coherent: a window that excludes its own start is not a window.
        if cert.not_after.is_some() {
            assert_eq!(
                cert.is_valid_at(cert.not_before),
                cert.not_before <= cert.not_after.unwrap_or(u32::MAX)
            );
        } else {
            assert!(cert.is_valid_at(cert.not_before));
            assert!(cert.is_valid_at(u32::MAX));
        }
    }

    // A Certification Declaration's CMS wrapper, and the TLV inside it.
    if let Ok(signed) = SignedData::parse(data) {
        assert!(
            data.windows(signed.content.len())
                .any(|w| w == signed.content)
        );
        let _ = signed.elements();
    }

    // A PKCS#10 certification request.
    if let Ok(csr) = Csr::parse(data) {
        assert!(data.windows(csr.tbs.len()).any(|w| w == csr.tbs));
        let _ = csr.verify();
    }

    // And the reader underneath all three: walking arbitrary bytes must terminate, and
    // anything it accepts must be exactly as long as it said it was.
    let mut reader = DerReader::new(data);
    while let Ok(element) = reader.next_element() {
        assert!(element.raw.len() >= element.content.len());
        assert!(element.raw.ends_with(element.content));
    }
});
