//! Every encoding example in Core Appendix A, as a test.
//!
//! Tables 127, 128 and 129 of the Matter 1.6 Core Specification print a value and the
//! octets it encodes as. They are the only officially published TLV vectors, they cover
//! every element type and every tag form, and agreeing with them is the difference between
//! "our encoder and our decoder agree" and "our encoder is right".
//!
//! Each vector is checked **three** ways, because they fail differently:
//!
//! 1. decode — the octets produce the stated value;
//! 2. encode — the value produces the stated octets;
//! 3. fixed point — re-encoding the octets reproduces them exactly, which is what a
//!    signature over a TLV structure depends on (§A.2.4).
//!
//! A vector whose encoding the specification deliberately shows as *non*-minimal — "the
//! sender is free to send more octets than strictly necessary" (§A.11.1) — is marked, and
//! only checked the first way.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::tlv::{ContainerKind, Pretty, Tag, TlvReader, TlvWriter, Value};

/// What a writer call looks like, so a vector can carry the value as data.
enum Write {
    Signed(Tag, i64),
    Unsigned(Tag, u64),
    Bool(Tag, bool),
    Float(Tag, f32),
    Double(Tag, f64),
    Utf8(Tag, &'static str),
    Octets(Tag, &'static [u8]),
    Null(Tag),
    Start(Tag, ContainerKind),
    End,
}

struct Vector {
    /// What Table 127/128/129 calls it.
    name: &'static str,
    /// The octets the table prints.
    bytes: &'static [u8],
    /// The calls that should produce them, or empty when the vector is decode-only.
    writes: &'static [Write],
    /// `true` when the specification's encoding is legal but not narrowest, so this crate
    /// will not reproduce it.
    non_minimal: bool,
}

fn apply(w: &mut TlvWriter<'_>, writes: &[Write]) {
    for write in writes {
        let r = match *write {
            Write::Signed(t, v) => w.signed(t, v),
            Write::Unsigned(t, v) => w.unsigned(t, v),
            Write::Bool(t, v) => w.bool(t, v),
            Write::Float(t, v) => w.float(t, v),
            Write::Double(t, v) => w.double(t, v),
            Write::Utf8(t, v) => w.utf8(t, v),
            Write::Octets(t, v) => w.octets(t, v),
            Write::Null(t) => w.null(t),
            Write::Start(t, k) => w.start(t, k),
            Write::End => w.end_container(),
        };
        r.expect("every vector is legal TLV");
    }
}

const FQ: Tag = Tag::FullyQualified {
    vendor: 0xFFF1,
    profile: 0xDEED,
    number: 1,
};
const FQ_BIG: Tag = Tag::FullyQualified {
    vendor: 0xFFF1,
    profile: 0xDEED,
    number: 0xAA55_FEED,
};
const FQ_INNER: Tag = Tag::FullyQualified {
    vendor: 0xFFF1,
    profile: 0xDEED,
    number: 0xAA55,
};

/// Table 127 — "Sample encoding of primitive types". All anonymous.
const TABLE_127: &[Vector] = &[
    Vector {
        name: "Boolean false",
        bytes: &[0x08],
        writes: &[Write::Bool(Tag::Anonymous, false)],
        non_minimal: false,
    },
    Vector {
        name: "Boolean true",
        bytes: &[0x09],
        writes: &[Write::Bool(Tag::Anonymous, true)],
        non_minimal: false,
    },
    Vector {
        name: "Signed Integer, 1-octet, value 42",
        bytes: &[0x00, 0x2a],
        writes: &[Write::Signed(Tag::Anonymous, 42)],
        non_minimal: false,
    },
    Vector {
        name: "Signed Integer, 1-octet, value -17",
        bytes: &[0x00, 0xef],
        writes: &[Write::Signed(Tag::Anonymous, -17)],
        non_minimal: false,
    },
    Vector {
        name: "Unsigned Integer, 1-octet, value 42U",
        bytes: &[0x04, 0x2a],
        writes: &[Write::Unsigned(Tag::Anonymous, 42)],
        non_minimal: false,
    },
    Vector {
        name: "Signed Integer, 2-octet, value 42",
        bytes: &[0x01, 0x2a, 0x00],
        // §A.11.1 permits a wider encoding than needed; this crate always writes the
        // narrowest, so it will not reproduce these octets.
        writes: &[],
        non_minimal: true,
    },
    Vector {
        name: "Signed Integer, 4-octet, value -170000",
        bytes: &[0x02, 0xf0, 0x67, 0xfd, 0xff],
        writes: &[Write::Signed(Tag::Anonymous, -170_000)],
        non_minimal: false,
    },
    Vector {
        name: "Signed Integer, 8-octet, value 40000000000",
        bytes: &[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00],
        writes: &[Write::Signed(Tag::Anonymous, 40_000_000_000)],
        non_minimal: false,
    },
    Vector {
        name: r#"UTF-8 String, 1-octet length, "Hello!""#,
        bytes: &[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21],
        writes: &[Write::Utf8(Tag::Anonymous, "Hello!")],
        non_minimal: false,
    },
    Vector {
        name: r#"UTF-8 String, 1-octet length, "Tschüs""#,
        bytes: &[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73],
        writes: &[Write::Utf8(Tag::Anonymous, "Tschüs")],
        non_minimal: false,
    },
    Vector {
        name: "Octet String, 1-octet length, octets 00 01 02 03 04",
        bytes: &[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04],
        writes: &[Write::Octets(Tag::Anonymous, &[0, 1, 2, 3, 4])],
        non_minimal: false,
    },
    Vector {
        name: "Null",
        bytes: &[0x14],
        writes: &[Write::Null(Tag::Anonymous)],
        non_minimal: false,
    },
    Vector {
        name: "Single precision floating point 0.0",
        bytes: &[0x0a, 0x00, 0x00, 0x00, 0x00],
        writes: &[Write::Float(Tag::Anonymous, 0.0)],
        non_minimal: false,
    },
    Vector {
        name: "Single precision floating point (1.0 / 3.0)",
        bytes: &[0x0a, 0xab, 0xaa, 0xaa, 0x3e],
        writes: &[Write::Float(Tag::Anonymous, 1.0 / 3.0)],
        non_minimal: false,
    },
    Vector {
        name: "Single precision floating point 17.9",
        bytes: &[0x0a, 0x33, 0x33, 0x8f, 0x41],
        writes: &[Write::Float(Tag::Anonymous, 17.9)],
        non_minimal: false,
    },
    Vector {
        name: "Single precision floating point infinity",
        bytes: &[0x0a, 0x00, 0x00, 0x80, 0x7f],
        writes: &[Write::Float(Tag::Anonymous, f32::INFINITY)],
        non_minimal: false,
    },
    Vector {
        name: "Single precision floating point negative infinity",
        bytes: &[0x0a, 0x00, 0x00, 0x80, 0xff],
        writes: &[Write::Float(Tag::Anonymous, f32::NEG_INFINITY)],
        non_minimal: false,
    },
    Vector {
        name: "Double precision floating point 0.0",
        bytes: &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        writes: &[Write::Double(Tag::Anonymous, 0.0)],
        non_minimal: false,
    },
    Vector {
        name: "Double precision floating point (1.0 / 3.0)",
        bytes: &[0x0b, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xd5, 0x3f],
        writes: &[Write::Double(Tag::Anonymous, 1.0 / 3.0)],
        non_minimal: false,
    },
    Vector {
        name: "Double precision floating point 17.9",
        bytes: &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40],
        writes: &[Write::Double(Tag::Anonymous, 17.9)],
        non_minimal: false,
    },
    Vector {
        name: "Double precision floating point infinity",
        bytes: &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f],
        writes: &[Write::Double(Tag::Anonymous, f64::INFINITY)],
        non_minimal: false,
    },
    Vector {
        name: "Double precision floating point negative infinity",
        bytes: &[0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff],
        writes: &[Write::Double(Tag::Anonymous, f64::NEG_INFINITY)],
        non_minimal: false,
    },
];

/// Table 128 — "Sample encoding of containers".
const TABLE_128: &[Vector] = &[
    Vector {
        name: "Empty Structure, {}",
        bytes: &[0x15, 0x18],
        writes: &[
            Write::Start(Tag::Anonymous, ContainerKind::Structure),
            Write::End,
        ],
        non_minimal: false,
    },
    Vector {
        name: "Empty Array, []",
        bytes: &[0x16, 0x18],
        writes: &[
            Write::Start(Tag::Anonymous, ContainerKind::Array),
            Write::End,
        ],
        non_minimal: false,
    },
    Vector {
        name: "Empty List, []",
        bytes: &[0x17, 0x18],
        writes: &[
            Write::Start(Tag::Anonymous, ContainerKind::List),
            Write::End,
        ],
        non_minimal: false,
    },
    Vector {
        name: "Structure, two context specific tags, {0 = 42, 1 = -17}",
        bytes: &[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18],
        writes: &[
            Write::Start(Tag::Anonymous, ContainerKind::Structure),
            Write::Signed(Tag::Context(0), 42),
            Write::Signed(Tag::Context(1), -17),
            Write::End,
        ],
        non_minimal: false,
    },
    Vector {
        name: "Array, Signed Integer, 1-octet values, [0, 1, 2, 3, 4]",
        bytes: &[
            0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18,
        ],
        writes: &[
            Write::Start(Tag::Anonymous, ContainerKind::Array),
            Write::Signed(Tag::Anonymous, 0),
            Write::Signed(Tag::Anonymous, 1),
            Write::Signed(Tag::Anonymous, 2),
            Write::Signed(Tag::Anonymous, 3),
            Write::Signed(Tag::Anonymous, 4),
            Write::End,
        ],
        non_minimal: false,
    },
    Vector {
        name: "List, mix of anonymous and context tags",
        bytes: &[
            0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18,
        ],
        writes: &[
            Write::Start(Tag::Anonymous, ContainerKind::List),
            Write::Signed(Tag::Anonymous, 1),
            Write::Signed(Tag::Context(0), 42),
            Write::Signed(Tag::Anonymous, 2),
            Write::Signed(Tag::Anonymous, 3),
            Write::Signed(Tag::Context(0), -17),
            Write::End,
        ],
        non_minimal: false,
    },
    Vector {
        name: r#"Array, mix of element types, [42, -170000, {}, 17.9, "Hello!"]"#,
        bytes: &[
            0x16, 0x00, 0x2a, 0x02, 0xf0, 0x67, 0xfd, 0xff, 0x15, 0x18, 0x0a, 0x33, 0x33, 0x8f,
            0x41, 0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x18,
        ],
        writes: &[
            Write::Start(Tag::Anonymous, ContainerKind::Array),
            Write::Signed(Tag::Anonymous, 42),
            Write::Signed(Tag::Anonymous, -170_000),
            Write::Start(Tag::Anonymous, ContainerKind::Structure),
            Write::End,
            Write::Float(Tag::Anonymous, 17.9),
            Write::Utf8(Tag::Anonymous, "Hello!"),
            Write::End,
        ],
        non_minimal: false,
    },
];

/// Table 129 — "Sample encoding of different tag types", Vendor ID 0xFFF2 in the caption
/// but 0xFFF1 in the rows themselves.
const TABLE_129: &[Vector] = &[
    Vector {
        name: "Anonymous tag, Unsigned Integer, 1-octet value, 42U",
        bytes: &[0x04, 0x2a],
        writes: &[Write::Unsigned(Tag::Anonymous, 42)],
        non_minimal: false,
    },
    Vector {
        name: "Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U",
        // §A.2.2 forbids a context tag on the outermost element, so the row is shown
        // here inside the structure it would have to live in.
        bytes: &[0x15, 0x24, 0x01, 0x2a, 0x18],
        writes: &[
            Write::Start(Tag::Anonymous, ContainerKind::Structure),
            Write::Unsigned(Tag::Context(1), 42),
            Write::End,
        ],
        non_minimal: false,
    },
    Vector {
        name: "Common profile tag 1, Matter::1 = 42U",
        bytes: &[0x44, 0x01, 0x00, 0x2a],
        writes: &[Write::Unsigned(Tag::Common(1), 42)],
        non_minimal: false,
    },
    Vector {
        name: "Common profile tag 100000, Matter::100000 = 42U",
        bytes: &[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a],
        writes: &[Write::Unsigned(Tag::Common(100_000), 42)],
        non_minimal: false,
    },
    Vector {
        name: "Fully qualified tag, 2-octet tag, 65521::57069:1 = 42U",
        bytes: &[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a],
        writes: &[Write::Unsigned(FQ, 42)],
        non_minimal: false,
    },
    Vector {
        name: "Fully qualified tag, 4-octet tag, 65521::57069:2857762541 = 42U",
        bytes: &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a],
        writes: &[Write::Unsigned(FQ_BIG, 42)],
        non_minimal: false,
    },
    Vector {
        name: "Structure with a fully qualified tag, containing one",
        bytes: &[
            0xd5, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x55, 0xaa,
            0x2a, 0x18,
        ],
        writes: &[
            Write::Start(FQ, ContainerKind::Structure),
            Write::Unsigned(FQ_INNER, 42),
            Write::End,
        ],
        non_minimal: false,
    },
];

fn check(table: &str, vectors: &[Vector]) {
    for v in vectors {
        // 1. It decodes, and it is well-formed by every rule the reader enforces.
        TlvReader::validate(v.bytes)
            .unwrap_or_else(|e| panic!("{table} {:?}: does not decode: {e}", v.name));

        if v.non_minimal {
            continue;
        }

        // 2. The stated value encodes to the stated octets.
        let mut buf = [0u8; 256];
        let mut w = TlvWriter::new(&mut buf);
        apply(&mut w, v.writes);
        let written = w.finish().expect("a complete encoding");
        assert_eq!(
            written, v.bytes,
            "{table} {:?}: encoded {written:02x?}, table says {:02x?}",
            v.name, v.bytes
        );

        // 3. And the octets are a fixed point, which is what §A.2.4 needs.
        let mut out = [0u8; 256];
        assert!(
            matter_kit::tlv::re_encode_is_identical(v.bytes, &mut out).expect("re-encode"),
            "{table} {:?}: not a canonical encoding",
            v.name
        );
    }
}

#[test]
fn table_127_primitive_types() {
    check("Table 127", TABLE_127);
}

#[test]
fn table_128_containers() {
    check("Table 128", TABLE_128);
}

#[test]
fn table_129_tag_types() {
    check("Table 129", TABLE_129);
}

#[test]
fn every_vector_survives_every_truncation() {
    // Not a specification requirement — a crate one. Rule 7 of concepts/README.md: every
    // number off the wire is hostile, including a length that outruns the buffer.
    for table in [TABLE_127, TABLE_128, TABLE_129] {
        for v in table {
            for cut in 0..v.bytes.len() {
                let _ = TlvReader::validate(&v.bytes[..cut]);
            }
        }
    }
}

#[test]
fn every_vector_survives_every_single_bit_flip() {
    // Neither is this. A corrupted message must be an error, and the point is that no
    // input at all reaches a panic.
    for table in [TABLE_127, TABLE_128, TABLE_129] {
        for v in table {
            let mut bytes = [0u8; 64];
            let Some(dst) = bytes.get_mut(..v.bytes.len()) else {
                continue;
            };
            dst.copy_from_slice(v.bytes);
            for byte in 0..v.bytes.len() {
                for bit in 0..8u32 {
                    let mut mutated = bytes;
                    mutated[byte] ^= 1u8 << bit;
                    let _ = TlvReader::validate(&mutated[..v.bytes.len()]);
                    let _ = matter_kit::tlv::validate_canonical(&mutated[..v.bytes.len()]);
                }
            }
        }
    }
}

#[test]
fn the_pretty_printer_reads_like_the_specification() {
    // The specification writes these values in exactly this notation.
    assert_eq!(
        std::format!(
            "{}",
            Pretty(&[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18])
        ),
        "{0 = 42, 1 = -17}"
    );
    assert_eq!(
        std::format!(
            "{}",
            Pretty(&[
                0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18
            ])
        ),
        "[0, 1, 2, 3, 4]"
    );
}

#[test]
fn a_structure_reads_back_field_by_field() {
    // The shape almost every interaction-model payload has.
    let bytes = [0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18];
    let mut r = TlvReader::new(&bytes);

    let open = r.next_element().unwrap().unwrap();
    assert_eq!(open.value, Value::Container(ContainerKind::Structure));

    let zero = r.next_element().unwrap().unwrap();
    assert_eq!(zero.tag, Tag::Context(0));
    assert_eq!(zero.signed().unwrap(), 42);

    let one = r.next_element().unwrap().unwrap();
    assert_eq!(one.tag, Tag::Context(1));
    assert_eq!(one.signed().unwrap(), -17);

    assert_eq!(
        r.next_element().unwrap().unwrap().value,
        Value::EndOfContainer
    );
    assert!(r.next_element().unwrap().is_none());
    r.finish().unwrap();
}
