//! Matter TLV — the tag-length-value encoding of Core Appendix A.
//!
//! Every byte Matter puts on the wire above the message header is TLV: interaction-model
//! payloads, operational certificates, the onboarding payload's contents, attestation
//! structures. It is a small format — a control octet, an optional tag, an optional
//! length, a value — and this module is the whole of it, with nothing above it and no
//! allocation underneath.
//!
//! # Reading
//!
//! [`TlvReader`] is a cursor. It yields [`Element`]s; containers appear as an opening
//! element, then their members, then [`Value::EndOfContainer`]. Reading is therefore a
//! loop, never a recursion, so a pathological encoding costs a bounded depth counter
//! rather than the call stack.
//!
//! ```
//! use matter_kit::tlv::{TlvReader, Tag, Value};
//!
//! // { 0 = 42, 1 = -17 } — Core Table 128.
//! let bytes = [0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18];
//! let mut r = TlvReader::new(&bytes);
//!
//! assert!(matches!(r.next_element()?.unwrap().value, Value::Container(_)));
//! let first = r.next_element()?.unwrap();
//! assert_eq!(first.tag, Tag::Context(0));
//! assert_eq!(first.signed()?, 42);
//! # Ok::<(), matter_kit::Error>(())
//! ```
//!
//! # Writing
//!
//! [`TlvWriter`] fills a buffer you own and **refuses to produce invalid TLV**: an
//! anonymous member of a structure, a tagged member of an array, an unbalanced container
//! or a second top-level element are errors at the call that would create them.
//!
//! ```
//! use matter_kit::tlv::{Tag, TlvWriter};
//!
//! let mut buf = [0u8; 32];
//! let mut w = TlvWriter::new(&mut buf);
//! w.start_structure(Tag::Anonymous)?;
//! w.signed(Tag::Context(0), 42)?;
//! w.signed(Tag::Context(1), -17)?;
//! w.end_container()?;
//! assert_eq!(w.finish()?, &[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18]);
//! # Ok::<(), matter_kit::Error>(())
//! ```
//!
//! # What is checked, and where
//!
//! The specification's structural rules are enforced on **both** sides, because a rule
//! checked only on the way out is a rule a peer can break for you:
//!
//! | Rule | Section |
//! |---|---|
//! | Reserved element types `0x19`–`0x1F` are refused | §A.7.1 |
//! | End-of-container is `0x18` exactly — tag control bits zero | §A.10 |
//! | Structure members are never anonymous | §A.5.1 |
//! | Array members are always anonymous | §A.5.2 |
//! | List members may carry any tag form | §A.5.3 |
//! | A context-specific tag is never the outermost element | §A.2.2 |
//! | Exactly one top-level element, with nothing after it | §A.1 |
//! | UTF-8 string values are valid UTF-8 | §A.11.2 |
//! | Nesting is bounded by [`MAX_DEPTH`] | this crate |
//!
//! One rule is deliberately *not* enforced while reading: §A.5.1's "all member elements
//! within a structure SHALL have a unique tag". Checking it costs memory proportional to
//! the widest structure, which a no-alloc reader does not have; [`validate_canonical`]
//! does check it, for callers that have a buffer to spare and a reason to care.
//!
//! # Canonical form
//!
//! §A.9 and §A.11.1 let a sender pick any sufficient width for a length or an integer, so
//! the same value has many legal encodings. [`TlvWriter`] always picks the narrowest,
//! which makes its output deterministic — necessary whenever an encoding is hashed or
//! signed. §A.2.4's canonical tag order is available as [`Tag::canonical_cmp`].

mod reader;
mod types;
mod writer;

mod canonical;
mod pretty;

pub use canonical::{re_encode_is_identical, validate_canonical};
pub use pretty::Pretty;
pub use reader::{Element, MAX_DEPTH, TlvReader, Value};
pub use types::{COMMON_PROFILE, ContainerKind, ElementType, Tag, Width};
pub use writer::TlvWriter;
