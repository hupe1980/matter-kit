//! Does any byte string make the message frame decoder panic?
//!
//! Core §4.4's header is the very first thing a Matter node parses — before any key is
//! found, before anything is decrypted, and therefore *before the sender is authenticated*.
//! Anything that reaches a socket reaches this code, so it is the highest-value target in
//! the crate.
//!
//! The protocol header is decoded from whatever the message header left behind, which is
//! how a real receive path chains them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::msg::{MessageHeader, ProtocolHeader};

fuzz_target!(|data: &[u8]| {
    let Ok((header, payload)) = MessageHeader::decode(data) else {
        return;
    };

    // Whatever decoded must re-encode, and into no more room than it claimed.
    let mut buf = [0u8; 64];
    if let Ok(n) = header.encode(&mut buf) {
        assert_eq!(n, header.encoded_len(), "encoded_len lied about {header:?}");
        // And that re-encoding must decode to the same thing. Message extensions are the
        // one exception: they are skipped on the way in and not preserved, by design
        // ("Version 1.0 Nodes SHALL ignore the contents of the Message Extensions
        // payload, by skipping it").
        if let Ok((again, _)) = MessageHeader::decode(&buf[..n]) {
            assert_eq!(again, header, "a header did not survive a round trip");
        }
    }

    let Ok((protocol, _app)) = ProtocolHeader::decode(payload) else {
        return;
    };
    let mut buf = [0u8; 32];
    if let Ok(n) = protocol.encode(&mut buf) {
        assert_eq!(
            n,
            protocol.encoded_len(),
            "encoded_len lied about {protocol:?}"
        );
        if let Ok((again, _)) = ProtocolHeader::decode(&buf[..n]) {
            assert_eq!(again, protocol, "a protocol header did not survive a round trip");
        }
    }
});
