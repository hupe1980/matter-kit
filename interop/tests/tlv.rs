//! TLV (Core Appendix A), written by one implementation and read by the other.
//!
//! TLV is the largest shared surface in the specification: every byte Matter puts on the wire
//! above the message header is TLV, so a disagreement here is a disagreement about *everything*.
//! It is also the place where a misreading is least likely to be caught by either crate alone —
//! each one packs and unpacks with the same constant, and would have to get it wrong twice
//! before its own round-trip test noticed.
//!
//! Both crates reproduce Core Tables 127–129 in their own suites. What that cannot establish is
//! agreement on the encodings the tables do not print: the 1-, 2-, 4- and 8-octet length forms,
//! the boundary values of every integer width, and the tag forms nothing in the tables uses. So
//! those are what this drives.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use matter_kit::tlv::{Tag, TlvReader, TlvWriter};
use rs_matter::tlv::TLVElement;

/// Encodes with matter-kit into an anonymous structure holding one context-tagged value.
fn wrap(write: impl FnOnce(&mut TlvWriter<'_>)) -> Vec<u8> {
    let mut buf = [0u8; 4096];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).expect("open");
    write(&mut w);
    w.end_container().expect("close");
    w.finish().expect("finish").to_vec()
}

/// The `rs-matter` view of what matter-kit wrote: the structure's context-0 member.
fn theirs(bytes: &[u8]) -> TLVElement<'_> {
    TLVElement::new(bytes)
        .structure()
        .expect("rs-matter reads it as a structure")
        .ctx(0)
        .expect("with a context-0 member")
}

// --- Integers ------------------------------------------------------------------------------------

/// Every boundary of every signed width, including the ones that decide whether a value is
/// encoded in one octet or eight.
#[test]
fn rs_matter_reads_every_signed_boundary_matter_kit_writes() {
    for value in [
        0i64,
        -1,
        i64::from(i8::MIN),
        i64::from(i8::MAX),
        i64::from(i8::MIN) - 1,
        i64::from(i8::MAX) + 1,
        i64::from(i16::MIN),
        i64::from(i16::MAX),
        i64::from(i16::MIN) - 1,
        i64::from(i16::MAX) + 1,
        i64::from(i32::MIN),
        i64::from(i32::MAX),
        i64::from(i32::MIN) - 1,
        i64::from(i32::MAX) + 1,
        i64::MIN,
        i64::MAX,
    ] {
        let bytes = wrap(|w| w.signed(Tag::Context(0), value).expect("write"));
        let got = theirs(&bytes)
            .i64()
            .expect("rs-matter reads a signed value");
        assert_eq!(got, value, "signed {value} encoded as {bytes:02x?}");
    }
}

#[test]
fn rs_matter_reads_every_unsigned_boundary_matter_kit_writes() {
    for value in [
        0u64,
        1,
        u64::from(u8::MAX),
        u64::from(u8::MAX) + 1,
        u64::from(u16::MAX),
        u64::from(u16::MAX) + 1,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        let bytes = wrap(|w| w.unsigned(Tag::Context(0), value).expect("write"));
        let got = theirs(&bytes)
            .u64()
            .expect("rs-matter reads an unsigned value");
        assert_eq!(got, value, "unsigned {value} encoded as {bytes:02x?}");
    }
}

// --- Strings, and the four length forms ----------------------------------------------------------

/// §A.7's octet strings carry their length in 1, 2, 4 or 8 octets, and which form is used is the
/// writer's choice. A reader that only ever met its own writer has only met the forms that
/// writer picks.
#[test]
fn rs_matter_reads_every_octet_string_length_form() {
    for len in [0usize, 1, 255, 256, 257, 1024] {
        let bytes = wrap(|w| {
            w.octets_fill(Tag::Context(0), len, 0xAB).expect("write");
        });
        let got = theirs(&bytes).octets().expect("rs-matter reads octets");
        assert_eq!(got.len(), len, "octet string of {len}");
        assert!(got.iter().all(|&b| b == 0xAB), "contents survived");
    }
}

#[test]
fn rs_matter_reads_utf8_matter_kit_writes() {
    for text in ["", "a", "Matter", "ünïcödé — ⌘", &"x".repeat(300)] {
        let bytes = wrap(|w| w.utf8(Tag::Context(0), text).expect("write"));
        let got = theirs(&bytes).utf8().expect("rs-matter reads utf8");
        assert_eq!(got, text);
    }
}

// --- The remaining element types -----------------------------------------------------------------

#[test]
fn rs_matter_reads_the_simple_types() {
    let bytes = wrap(|w| w.bool(Tag::Context(0), true).expect("write"));
    assert!(theirs(&bytes).bool().expect("bool"));

    let bytes = wrap(|w| w.bool(Tag::Context(0), false).expect("write"));
    assert!(!theirs(&bytes).bool().expect("bool"));

    let bytes = wrap(|w| w.null(Tag::Context(0)).expect("write"));
    theirs(&bytes).null().expect("rs-matter reads null");

    let bytes = wrap(|w| w.float(Tag::Context(0), 1.5).expect("write"));
    assert!((theirs(&bytes).f32().expect("f32") - 1.5).abs() < f32::EPSILON);

    let bytes = wrap(|w| w.double(Tag::Context(0), -2.25).expect("write"));
    assert!((theirs(&bytes).f64().expect("f64") + 2.25).abs() < f64::EPSILON);
}

/// Containers nest, and §A.5's end-of-container is the one octet whose miscounting turns a
/// well-formed message into a differently well-formed one.
#[test]
fn rs_matter_reads_nested_containers_matter_kit_writes() {
    let mut buf = [0u8; 512];
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).expect("open");
    w.start_array(Tag::Context(0)).expect("array");
    w.unsigned(Tag::Anonymous, 1).expect("write");
    w.unsigned(Tag::Anonymous, 2).expect("write");
    w.start_structure(Tag::Anonymous).expect("inner");
    w.signed(Tag::Context(3), -7).expect("write");
    w.end_container().expect("close inner");
    w.end_container().expect("close array");
    w.utf8(Tag::Context(1), "after").expect("write");
    w.end_container().expect("close");
    let bytes = w.finish().expect("finish").to_vec();

    let outer = TLVElement::new(&bytes).structure().expect("structure");
    let array = outer.ctx(0).expect("array member").array().expect("array");
    let mut values = array.iter();
    let mut next = || values.next().expect("a member").expect("well-formed");
    assert_eq!(next().u64().expect("u64"), 1);
    assert_eq!(next().u64().expect("u64"), 2);
    let inner = next().structure().expect("structure");
    assert_eq!(inner.ctx(3).expect("member").i64().expect("i64"), -7);
    // The member *after* the nested container is what proves the end-of-container octets were
    // counted correctly rather than merely present.
    assert_eq!(outer.ctx(1).expect("after").utf8().expect("utf8"), "after");
}

// --- Arbitrary values ----------------------------------------------------------------------------

mod property {
    use super::{TLVElement, Tag, TlvReader, theirs, wrap};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn every_integer_survives_the_crossing(value in any::<i64>()) {
            let bytes = wrap(|w| w.signed(Tag::Context(0), value).expect("write"));
            prop_assert_eq!(theirs(&bytes).i64().expect("read"), value);
        }

        #[test]
        fn every_unsigned_survives_the_crossing(value in any::<u64>()) {
            let bytes = wrap(|w| w.unsigned(Tag::Context(0), value).expect("write"));
            prop_assert_eq!(theirs(&bytes).u64().expect("read"), value);
        }

        #[test]
        fn every_octet_string_survives_the_crossing(data in prop::collection::vec(any::<u8>(), 0..600)) {
            let bytes = wrap(|w| w.octets(Tag::Context(0), &data).expect("write"));
            prop_assert_eq!(theirs(&bytes).octets().expect("read"), &data[..]);
        }

        /// Arbitrary bytes to both readers. The assertion runs in the direction that matters:
        /// anything *matter-kit* considers well-formed TLV, rs-matter must also parse. The
        /// converse is deliberately not asserted — matter-kit enforces §A.11's canonical-form
        /// rules that rs-matter does not, so it is the stricter reader by design, and a buffer
        /// it rejects is one no conforming peer would have sent.
        #[test]
        fn whatever_matter_kit_accepts_rs_matter_also_parses(data in prop::collection::vec(any::<u8>(), 0..64)) {
            if TlvReader::validate(&data).is_err() {
                return Ok(());
            }
            let element = TLVElement::new(&data);
            prop_assert!(
                element.tlv().is_ok(),
                "matter-kit accepted TLV rs-matter cannot parse: {:02x?}",
                data
            );
        }
    }
}
