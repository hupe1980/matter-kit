//! What you write, somebody stricter will read.
//!
//! The specification says what is legal; a peer's parser says what is *accepted*. An optional
//! structure encoded with nothing in it is legal Appendix A, accepted by this crate's decoder,
//! and refused by every released CHIP SDK — so the rule kept here is stricter than the
//! specification's: **an optional structure that would be empty is not written at all.**
//!
//! It cannot live in `TlvWriter`, because §4.14.1.2 gives empty a meaning:
//! `PBKDFParamResponse.pbkdf_parameters [4]` empty is the encoding of "the initiator already has
//! them", which is a claim rather than an absence. So the rule is checked *over* the writer by
//! [`TlvReader::first_empty_optional`], and that one exception is asserted to still be one.
//!
//! `tests/session_params.rs` pins the instance; this pins the rule, and the `dispatch` fuzz
//! target pins the server's response path, where the messages a test cannot call directly are
//! built.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use matter_kit::msg::SessionId;
use matter_kit::sc::{
    PASSCODE_ID_COMMISSIONING, PbkdfParamRequest, PbkdfParamResponse, RANDOM_LEN, SessionParams,
};
use matter_kit::tlv::{Tag, TlvReader};

/// Fails with the tag of the first empty optional container, naming the message.
fn refuse_empty_optionals(what: &str, encoded: &[u8]) {
    match TlvReader::first_empty_optional(encoded).expect("the encoder produced well-formed TLV") {
        None => {}
        Some(Tag::Context(n)) => panic!(
            "{what} wrote an empty optional structure under context tag {n}. Appendix A permits \
             it, this crate's decoder accepts it, and every released CHIP SDK refuses it — so \
             the field is omitted instead, or the exception is documented where §4.14.1.2's is."
        ),
        Some(other) => panic!("{what} wrote an empty container under {other:?}"),
    }
}

/// This node's own announcement — Table 22's MRP timings and Table 23's revisions.
fn params() -> SessionParams {
    SessionParams::default()
}

#[test]
fn a_pbkdf_param_request_never_carries_an_empty_optional() {
    let mut buf = [0u8; 512];

    // With session parameters and without. The second is the shape that matters: a node with
    // nothing to say omits the field rather than writing an empty structure.
    for (what, session_params) in [
        ("PBKDFParamRequest with session parameters", Some(params())),
        ("PBKDFParamRequest with none", None),
    ] {
        let req = PbkdfParamRequest {
            initiator_random: [0x11; RANDOM_LEN],
            initiator_session_id: SessionId(0x1234),
            passcode_id: PASSCODE_ID_COMMISSIONING,
            has_pbkdf_parameters: false,
            session_params,
        };
        let len = req.encode(&mut buf).expect("encode");
        refuse_empty_optionals(what, &buf[..len]);
    }
}

/// §4.14.1.2's exception, asserted to still be one.
///
/// > The PBKDFParameters field SHALL be present if and only if the `hasPBKDFParameters` field
/// > of the PBKDFParamRequest was set to FALSE.
///
/// An *empty* parameter set is the encoding of "the initiator already has them", which is a
/// claim rather than an absence — so this is the one place the rule above does not apply, and a
/// test that quietly generalised the rule would delete a protocol behaviour.
#[test]
fn the_pbkdf_parameters_exception_is_still_an_exception() {
    let mut buf = [0u8; 512];
    let response = PbkdfParamResponse {
        initiator_random: [0x11; RANDOM_LEN],
        responder_random: [0x22; RANDOM_LEN],
        responder_session_id: SessionId(0x5678),
        pbkdf_parameters: None,
        session_params: Some(params()),
    };
    let len = response.encode(&mut buf).expect("encode");

    // Present *and empty*, which is the point. §4.14.1.2 makes the empty parameter set the
    // encoding of "the initiator already has them" — a claim, not an absence — so this is the
    // one message in the crate that the rule above must not be applied to, and a sweep that
    // quietly generalised the rule would delete a protocol behaviour rather than fix a bug.
    assert_eq!(
        TlvReader::first_empty_optional(&buf[..len]).expect("well-formed"),
        Some(Tag::Context(4)),
        "§4.14.1.2's empty parameter set is the exception, and it has to still be there"
    );
}

/// Every interaction-model message this crate can build, over inputs that are empty in every
/// way the encoders allow.
///
/// The empty cases are the point. A message with data in it cannot produce an empty optional
/// structure; a message with *nothing* in it is where an encoder reaches for one.
#[test]
fn no_interaction_model_message_carries_an_empty_optional() {
    use matter_kit::im::{
        AttributePath, AttributeStatus, CommandData, encode_invoke_request, encode_read_request,
        encode_subscribe_request, encode_write_response,
    };

    let mut buf = [0u8; 1024];

    let encoded = encode_read_request(&mut buf, [AttributePath::wildcard()], [], false)
        .expect("read request");
    refuse_empty_optionals("ReadRequest over a wildcard", encoded);

    let encoded = encode_subscribe_request(
        &mut buf,
        [AttributePath::wildcard()],
        [],
        0,
        60,
        false,
        false,
    )
    .expect("subscribe request");
    refuse_empty_optionals("SubscribeRequest", encoded);

    let encoded = encode_write_response(&mut buf, core::iter::empty::<AttributeStatus>())
        .expect("empty write response");
    refuse_empty_optionals("WriteResponse with no statuses", encoded);

    let encoded = encode_invoke_request(
        &mut buf,
        core::iter::empty::<CommandData<'_>>(),
        false,
        false,
    )
    .expect("invoke with no commands");
    refuse_empty_optionals("InvokeRequest with no commands", encoded);
}

/// The check itself has to be able to fail, or it is a test that always passes.
#[test]
fn the_check_finds_a_deliberate_offender() {
    use matter_kit::tlv::{ContainerKind, TlvWriter};

    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    w.start(Tag::Anonymous, ContainerKind::Structure).unwrap();
    w.unsigned(Tag::Context(0), 1).unwrap();
    w.start(Tag::Context(5), ContainerKind::Structure).unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    let encoded = w.finish().unwrap();

    assert_eq!(
        TlvReader::first_empty_optional(encoded).unwrap(),
        Some(Tag::Context(5))
    );

    // And an *anonymous* empty container is not an offence: an empty list is how a
    // factory-fresh node answers "what are your fabrics".
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    w.start(Tag::Anonymous, ContainerKind::Array).unwrap();
    w.end_container().unwrap();
    let encoded = w.finish().unwrap();
    assert_eq!(TlvReader::first_empty_optional(encoded).unwrap(), None);

    // Neither is a non-empty structure under a context tag.
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    w.start(Tag::Anonymous, ContainerKind::Structure).unwrap();
    w.start(Tag::Context(3), ContainerKind::Structure).unwrap();
    w.unsigned(Tag::Context(0), 7).unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    let encoded = w.finish().unwrap();
    assert_eq!(TlvReader::first_empty_optional(encoded).unwrap(), None);

    // And an empty *array* under a context tag is a value rather than an absence: an empty
    // `WriteResponses [0]` is a node that wrote nothing, which it has to be able to say.
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    w.start(Tag::Anonymous, ContainerKind::Structure).unwrap();
    w.start(Tag::Context(0), ContainerKind::Array).unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    let encoded = w.finish().unwrap();
    assert_eq!(TlvReader::first_empty_optional(encoded).unwrap(), None);
}
