//! `session-parameter-struct` — Core §4.13.1, Table 23.
//!
//! The tag numbers here are literals transcribed from §4.13.1's schema, never read back from
//! this crate's own encoder: a round-trip test over a wrong tag number passes, and that is
//! precisely the failure this file exists to prevent. §4.13.1 publishes a schema rather than
//! a hex dump, so there is no CSA-published vector to compare against — the schema is the
//! vector.

// The certificate and secure-channel types this file exercises live behind `rustcrypto`, so
// without the gate `cargo test --no-default-features` fails to *compile* — which is a broken
// gate rather than a failing test, and reports nothing about the code under it.
#![cfg(feature = "rustcrypto")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use matter_kit::exchange::MrpParams;
use matter_kit::msg::SessionId;
use matter_kit::sc::{PASSCODE_ID_COMMISSIONING, PbkdfParamRequest, RANDOM_LEN, SessionParams};
use matter_kit::transport::TransportModes;

/// Wraps `params` in the smallest message that carries one and returns the encoded bytes.
///
/// `SessionParams::encode` is crate-private, so every test here goes through a real message,
/// which is the path that actually reaches a peer.
fn encode_with(params: Option<SessionParams>) -> Vec<u8> {
    let req = PbkdfParamRequest {
        initiator_random: [0x11; RANDOM_LEN],
        initiator_session_id: SessionId(0x1234),
        passcode_id: PASSCODE_ID_COMMISSIONING,
        has_pbkdf_parameters: false,
        session_params: params,
    };
    let mut buf = [0u8; 256];
    let n = req.encode(&mut buf).expect("encode");
    buf[..n].to_vec()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The regression test for the defect that blocked commissioning.
///
/// A `session-parameter-struct` whose every field was optional could encode to `35 05 18` —
/// structure, context tag 5, end-of-container, with nothing between them. Appendix A permits
/// it and this crate's own decoder accepts it, but every released CHIP SDK refuses it:
/// `PairingSession::DecodeSessionParametersIfPresent` calls `Next()` once without guarding it
/// against `CHIP_END_OF_TLV`, where every later call in that function is guarded. The symptom
/// was a Sigma2 rejected with `End of TLV` while every test in this repository passed.
#[test]
fn the_struct_is_never_encoded_empty() {
    let bytes = encode_with(Some(SessionParams::announce(&MrpParams::default())));
    // 0x35 = structure, context tag; 0x05 = tag 5; 0x18 = end of container.
    assert!(
        !contains(&bytes, &[0x35, 0x05, 0x18]),
        "an empty session-parameter-struct reached the wire: {bytes:02x?}"
    );
    // And the opening of the container is followed by an element, not by its own end.
    let open = bytes
        .windows(2)
        .position(|w| w == [0x35, 0x05])
        .expect("tag 5 structure present");
    assert_ne!(bytes[open + 2], 0x18, "tag 5 structure is empty");
}

/// Tags 4-8 have been mandatory since Matter 1.3. Their absence is what makes a peer conclude
/// it is talking to a 1.0-era node: §4.13.1 says "if the DATA_MODEL_REVISION field is missing,
/// it implies a DataModelRevision value of either 16 or 17".
#[test]
fn every_mandatory_field_is_present_with_its_specification_value() {
    let bytes = encode_with(Some(SessionParams::announce(&MrpParams::default())));

    // Control octet 0x24 = unsigned integer, 1-octet value, context tag.
    // Control octet 0x26 = unsigned integer, 4-octet value, context tag.
    // DATA_MODEL_REVISION [4] = 21 (§7.1.1's newest revision).
    assert!(
        contains(&bytes, &[0x24, 0x04, 21]),
        "tag 4 missing or wrong"
    );
    // INTERACTION_MODEL_REVISION [5] = 13 (§8.1.1's newest revision).
    assert!(
        contains(&bytes, &[0x24, 0x05, 13]),
        "tag 5 missing or wrong"
    );
    // SPECIFICATION_VERSION [6] = 0x01_06_00_00, little-endian on the wire.
    assert!(
        contains(&bytes, &[0x26, 0x06, 0x00, 0x00, 0x06, 0x01]),
        "tag 6 missing or wrong"
    );
    // MAX_PATHS_PER_INVOKE [7] = 1, §11.1.5.23's floor.
    assert!(contains(&bytes, &[0x24, 0x07, 1]), "tag 7 missing or wrong");
    // SUPPORTED_TRANSPORTS [8] = 0, Table 7's empty bitmap: MRP only.
    assert!(contains(&bytes, &[0x24, 0x08, 0]), "tag 8 missing or wrong");
}

/// §4.13.1: "if any tag after tag 2 (SESSION_ACTIVE_INTERVAL) is present, then the
/// SESSION_ACTIVE_INTERVAL SHALL also be present." Tags 4-8 are always present, so tag 2
/// always is too — which is why it is not an `Option` in the struct.
#[test]
fn session_active_interval_accompanies_the_later_tags() {
    let bytes = encode_with(Some(SessionParams::announce(&MrpParams::default())));
    // 300 ms is Table 23's default and needs two octets: 0x25 = unsigned, 2-octet, context.
    assert!(
        contains(&bytes, &[0x25, 0x02, 0x2c, 0x01]),
        "tag 2 absent while later tags are present: {bytes:02x?}"
    );
}

#[test]
fn every_field_survives_a_round_trip() {
    let sent = SessionParams::announce(&MrpParams::default())
        .with_max_paths_per_invoke(7)
        .with_transports(
            TransportModes::TCP_CLIENT | TransportModes::TCP_SERVER,
            128_000,
        );
    let bytes = encode_with(Some(sent));
    let back = PbkdfParamRequest::decode(&bytes).expect("decode");
    assert_eq!(back.session_params, Some(sent));
    assert!(sent.accepts_tcp());
    assert_eq!(sent.max_tcp_message_size_or_default(), 128_000);
}

/// A peer older than Matter 1.3 sends tags 1-3 and nothing else. Table 23 requires the
/// recipient to fill the rest from the defaults, and the defaults for the revisions are the
/// 1.0-era floors — not this node's own values, which would be assuming the peer understands
/// everything this node does.
#[test]
fn a_pre_1_3_peer_decodes_to_the_specification_defaults() {
    // Hand-built PBKDFParamRequest carrying only tags 1-3 inside its tag-5 structure.
    let mut msg = vec![0x15]; // anonymous structure
    msg.extend_from_slice(&[0x30, 0x01, 32]); // initiatorRandom [1], 32 octets
    msg.extend_from_slice(&[0x22; 32]);
    msg.extend_from_slice(&[0x25, 0x02, 0x34, 0x12]); // initiatorSessionId [2] = 0x1234
    msg.extend_from_slice(&[0x24, 0x03, 0x00]); // passcodeId [3] = 0
    msg.extend_from_slice(&[0x28, 0x04]); // hasPBKDFParameters [4] = false
    msg.extend_from_slice(&[0x35, 0x05]); // initiatorSessionParams [5] = structure
    msg.extend_from_slice(&[0x26, 0x01, 0xf4, 0x01, 0x00, 0x00]); // idle = 500
    msg.extend_from_slice(&[0x26, 0x02, 0x2c, 0x01, 0x00, 0x00]); // active = 300
    msg.extend_from_slice(&[0x25, 0x03, 0xa0, 0x0f]); // threshold = 4000
    msg.push(0x18); // end of session params
    msg.push(0x18); // end of message

    let req = PbkdfParamRequest::decode(&msg).expect("decode");
    let p = req.session_params.expect("params present");
    assert_eq!(p.idle_interval_ms, 500);
    assert_eq!(p.active_interval_ms, 300);
    assert_eq!(p.active_threshold_ms, 4000);
    // §4.13.1: an absent DATA_MODEL_REVISION "implies a value of either 16 or 17".
    assert_eq!(p.data_model_revision, 16);
    // §8.1.1: "Matter revision 1.0 SHALL be considered equivalent to revision 10".
    assert_eq!(p.interaction_model_revision, 10);
    assert_eq!(p.specification_version, 0x0100_0000);
    // §11.1.5.23: "absent or zero … clients SHALL assume a value of 1".
    assert_eq!(p.max_paths_per_invoke, 1);
    assert!(p.supported_transports.is_empty());
    assert!(!p.accepts_tcp());
    // Table 23's default for a field the peer never sent.
    assert_eq!(p.max_tcp_message_size_or_default(), 64_000);
}

/// §11.1.5.23: "If the MaxPathsPerInvoke attribute is absent or zero … clients SHALL assume a
/// value of 1." A zero on the wire is therefore indistinguishable from absent, so this node
/// never writes one and never keeps one.
#[test]
fn max_paths_per_invoke_is_never_zero() {
    let sent = SessionParams::announce(&MrpParams::default()).with_max_paths_per_invoke(0);
    assert_eq!(sent.max_paths_per_invoke, 1);
    assert!(contains(&encode_with(Some(sent)), &[0x24, 0x07, 1]));
}

/// Table 7 bit 0: "This bit index is deprecated and SHALL be set to 0. Clients SHALL silently
/// ignore this bit." So must every bit a later revision adds — refusing the session over an
/// unknown transport bit would make the next specification drop a breaking change.
#[test]
fn reserved_and_unknown_transport_bits_are_ignored() {
    let mut msg = vec![0x15];
    msg.extend_from_slice(&[0x30, 0x01, 32]);
    msg.extend_from_slice(&[0x22; 32]);
    msg.extend_from_slice(&[0x25, 0x02, 0x34, 0x12]);
    msg.extend_from_slice(&[0x24, 0x03, 0x00]);
    msg.extend_from_slice(&[0x28, 0x04]);
    msg.extend_from_slice(&[0x35, 0x05]);
    msg.extend_from_slice(&[0x26, 0x02, 0x2c, 0x01, 0x00, 0x00]);
    // bit 0 (reserved) + bit 2 (TCP server) + bit 9 (does not exist yet) = 0x0205
    msg.extend_from_slice(&[0x25, 0x08, 0x05, 0x02]);
    msg.push(0x18);
    msg.push(0x18);

    let p = PbkdfParamRequest::decode(&msg)
        .expect("decode")
        .session_params
        .expect("params");
    assert_eq!(p.supported_transports, TransportModes::TCP_SERVER);
    assert!(p.accepts_tcp());
}

/// The values decide how long this node waits before retransmitting, and they came from a
/// stranger.
#[test]
fn hostile_timings_are_clamped() {
    let hostile = SessionParams {
        idle_interval_ms: u32::MAX,
        active_interval_ms: u32::MAX,
        active_threshold_ms: u16::MAX,
        ..SessionParams::legacy_peer()
    };
    let mrp = hostile.to_mrp();
    assert_eq!(mrp.idle_interval.as_millis(), 3_600_000);
    assert_eq!(mrp.active_interval.as_millis(), 3_600_000);
}

/// `Default` was the shape of the original defect: three `Option`s and a derived `Default`
/// meant "no fields at all". It is restored here because the type can no longer express that
/// — but the assertion is what keeps it true if somebody adds an `Option` back.
#[test]
fn the_default_announcement_is_conformant_and_not_empty() {
    assert_eq!(
        SessionParams::default(),
        SessionParams::announce(&MrpParams::default())
    );
    let bytes = encode_with(Some(SessionParams::default()));
    assert!(!contains(&bytes, &[0x35, 0x05, 0x18]));
    assert!(contains(&bytes, &[0x24, 0x04, 21]));
}
