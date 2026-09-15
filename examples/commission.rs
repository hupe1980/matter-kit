//! A commissioner turns a printed passcode into an encrypted session with a device.
//!
//! Run it with `cargo run --example commission --features std`.
//!
//! This is PASE — Core §4.14.1 — end to end: five messages over the simulated network, a
//! SPAKE2+ exchange in the middle, and real encrypted traffic at the end. It also shows
//! what happens when the passcode is wrong, which is the case the whole protocol exists
//! for: the attacker gets exactly one guess per exchange and learns nothing from it.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use matter_kit::crypto::Spake2pVerifierData;
use matter_kit::msg::{MessageHeader, SessionId, protect, unprotect};
use matter_kit::platform::Timer;
use matter_kit::platform::sim::{SimNet, block_on};
use matter_kit::sc::{PaseInitiator, PaseResponder, PbkdfParameters, ResponderConfig};
use matter_kit::session::{Role, SecureSession, SessionKind};

/// The passcode on the device's label, and the PBKDF parameters its factory used.
const PASSCODE: u32 = 20_202_021;
const SALT: &[u8] = b"SPAKE2P Key Salt";
const ITERATIONS: u32 = 1_000;

fn main() {
    println!("Matter PASE — commissioning from a printed passcode\n");

    // What the factory burns in: the SPAKE2+ verifier, from which the passcode cannot be
    // recovered. The device never stores the passcode itself.
    let parameters = PbkdfParameters::new(ITERATIONS, SALT).expect("parameters");
    let verifier =
        Spake2pVerifierData::from_passcode(PASSCODE, SALT, ITERATIONS).expect("verifier");
    println!(
        "  device factory data: {} octets of verifier (w0 ‖ L), no passcode\n",
        Spake2pVerifierData::LEN
    );

    for (label, attempt) in [
        ("the passcode on the label", PASSCODE),
        ("a guess", 12_345_678),
    ] {
        let net = SimNet::new(0xBEEF);
        let mut device = PaseResponder::new(
            ResponderConfig {
                verifier,
                parameters: parameters.clone(),
                session_params: None,
            },
            SessionId(0x1001),
        );
        let mut commissioner =
            PaseInitiator::new(attempt, SessionId(0x2002), Some(parameters.clone()), None);

        println!("  commissioner tries {label} ({attempt}):");

        let mut buf = [0u8; 512];
        let mut scratch = [0u8; 512];

        // 1. PBKDFParamRequest → PBKDFParamResponse.
        let n = commissioner.start(&[0x11; 32], &mut buf).expect("start");
        println!("    → PBKDFParamRequest   {n:3} octets");
        let n = device
            .on_pbkdf_param_request(&buf[..n], &[0x22; 32], &mut scratch)
            .expect("response");
        println!("    ← PBKDFParamResponse  {n:3} octets");

        // 2. Pake1 — the commissioner runs PBKDF2 here.
        let n = commissioner
            .on_pbkdf_param_response(&scratch[..n], &[0x33; 32], &mut buf)
            .expect("pake1");
        println!("    → Pake1 (pA)          {n:3} octets");

        // 3. Pake2 — the device answers with its share and a confirmation.
        let n = device
            .on_pake1(&buf[..n], &[0x44; 32], &mut scratch)
            .expect("pake2");
        println!("    ← Pake2 (pB, cB)      {n:3} octets");

        // 4. The commissioner checks cB. A wrong passcode dies here, and this is the only
        //    information a guess ever yields: that it was wrong.
        let n = match commissioner.on_pake2(&scratch[..n], &mut buf) {
            Ok(n) => n,
            Err(e) => {
                println!("    ✗ cB did not match: {e}");
                println!("      one guess spent, nothing learned\n");
                continue;
            }
        };
        println!("    → Pake3 (cA)          {n:3} octets");

        // 5. The device checks cA and says so.
        let (n, device_keys) = device.on_pake3(&buf[..n], &mut scratch).expect("finished");
        println!("    ← PakeFinished        {n:3} octets");
        let commissioner_keys = commissioner.on_pake_finished(&scratch[..n]).expect("keys");

        println!("    ✓ session established");

        // The two ends now hold the same three keys, and can talk.
        let commissioner_session = SecureSession::new(
            SessionId(0x2002),
            SessionId(0x1001),
            SessionKind::Pase,
            Role::Initiator,
            commissioner_keys,
            1,
            Timer::now(&net),
        );
        let device_session = SecureSession::new(
            SessionId(0x1001),
            SessionId(0x2002),
            SessionKind::Pase,
            Role::Responder,
            device_keys,
            1,
            Timer::now(&net),
        );

        let header = MessageHeader {
            session_id: device_session.local_session_id,
            message_counter: 1,
            ..MessageHeader::default()
        };
        let plaintext = b"ArmFailSafe";
        let n = protect(
            &header,
            commissioner_session.send_nonce_source(),
            plaintext,
            commissioner_session.encrypt_keys(),
            &mut buf,
        )
        .expect("protect");
        println!(
            "    → {n} octets on the wire, of which the payload is unreadable: {:02x?}…",
            &buf[header.encoded_len()..header.encoded_len() + 6]
        );

        let (_, range) = unprotect(
            &mut buf[..n],
            device_session.decrypt_keys(),
            device_session.recv_nonce_source(),
        )
        .expect("the device can read it");
        println!(
            "    ✓ device decrypts: {:?}\n",
            core::str::from_utf8(&buf[range]).unwrap_or("<binary>")
        );

        // A real node would now put both sessions in its session table and start
        // commissioning proper. `net` is unused beyond the clock in this example.
        let _ = block_on(&net, async { net.node(1).addr() });
    }

    println!("  the device's flash holds no passcode, so reading it does not let anyone");
    println!("  impersonate the commissioner to another device.");
}
