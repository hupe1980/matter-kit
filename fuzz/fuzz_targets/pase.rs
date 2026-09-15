//! Does any byte string make a PASE message decoder panic — or a state machine misbehave?
//!
//! These five message types are parsed on the **unsecured** session: there is no key yet,
//! so there is no authentication, so *anything* that reaches the socket during a
//! commissioning window reaches this code. It is the second-highest-value target in the
//! crate after the message header, and unlike the header it runs a state machine with
//! cryptography behind it.
//!
//! The target also drives a responder through a whole exchange with fuzzer-chosen bytes at
//! each step, which is what finds an ordering the state machine did not expect.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::crypto::Spake2pVerifierData;
use matter_kit::msg::SessionId;
use matter_kit::sc::{
    Pake1, Pake2, Pake3, PaseResponder, PbkdfParamRequest, PbkdfParamResponse, PbkdfParameters,
    ResponderConfig, StatusReport,
};

fuzz_target!(|data: &[u8]| {
    // Every decoder, on the raw input.
    if let Ok(request) = PbkdfParamRequest::decode(data) {
        // Whatever decoded must re-encode without panicking, and into a buffer this size.
        let mut out = [0u8; 512];
        let _ = request.encode(&mut out);
    }
    if let Ok(response) = PbkdfParamResponse::decode(data) {
        let mut out = [0u8; 512];
        let _ = response.encode(&mut out);
    }
    if let Ok(pake) = Pake1::decode(data) {
        let mut out = [0u8; 256];
        let _ = pake.encode(&mut out);
    }
    if let Ok(pake) = Pake2::decode(data) {
        let mut out = [0u8; 256];
        let _ = pake.encode(&mut out);
    }
    if let Ok(pake) = Pake3::decode(data) {
        let mut out = [0u8; 256];
        let _ = pake.encode(&mut out);
    }
    let _ = StatusReport::decode(data);

    // And the responder state machine, fed the same bytes at each step. A commissioning
    // window is open to anything on the network, so this is the real threat model.
    let Ok(parameters) = PbkdfParameters::new(1_000, b"SPAKE2P Key Salt") else {
        return;
    };
    let Ok(verifier) = Spake2pVerifierData::from_passcode(20_202_021, b"SPAKE2P Key Salt", 1_000)
    else {
        return;
    };
    let mut device = PaseResponder::new(
        ResponderConfig {
            verifier,
            parameters,
            session_params: None,
        },
        SessionId(1),
    );

    let mut out = [0u8; 512];
    let _ = device.on_pbkdf_param_request(data, &[0x42; 32], &mut out);
    let _ = device.on_pake1(data, &[0x43; 32], &mut out);
    let _ = device.on_pake3(data, &mut out);

    // A responder must never claim to be established without having checked a confirmation
    // value. The fuzzer has no way to produce a valid one, so this must always hold.
    assert!(
        !device.is_established(),
        "a PASE responder accepted an unauthenticated exchange"
    );
});
