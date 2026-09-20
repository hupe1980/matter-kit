//! A zero-copy, non-recursive, allocation-free TLV reader.
//!
//! The reader is a cursor over a byte slice that yields one [`Element`] at a time.
//! Containers are reported as their opening element followed by their members and an
//! [`Value::EndOfContainer`], so reading is a loop rather than a recursion — a hostile
//! encoding cannot grow the stack, only exhaust a fixed depth budget.
//!
//! Everything borrowed from the input is borrowed, not copied: a `&str` or `&[u8]` value
//! points into the original buffer.

use super::types::{ContainerKind, ElementType, Tag, Width, read_le_i64, read_le_u64};
use crate::error::{Error, ErrorCode, Result, bail};

/// How deeply containers may nest before the reader refuses to go further.
///
/// The specification sets no limit ("Container types can be nested to any depth"), but a
/// reader must, or a 1 KB message of nothing but `15` octets costs a kilobyte of reader
/// state. Matter's own encodings are shallow — the deepest interaction-model payload nests
/// about eight levels — so 16 is roomy without being exploitable.
pub const MAX_DEPTH: usize = 16;

/// A decoded element value (Core §A.11).
///
/// Container variants carry no members: they mark the *start* of a container, whose
/// members follow as further elements until [`Value::EndOfContainer`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Value<'a> {
    /// A signed integer, sign-extended from its encoded width.
    Signed(i64),
    /// An unsigned integer, zero-extended from its encoded width.
    Unsigned(u64),
    /// A boolean, whose value lives in the control octet.
    Bool(bool),
    /// A single-precision float.
    Float(f32),
    /// A double-precision float.
    Double(f64),
    /// A UTF-8 string, validated on read (§A.11.2).
    Utf8(&'a str),
    /// An octet string.
    Octets(&'a [u8]),
    /// The null value.
    Null,
    /// The start of a container.
    Container(ContainerKind),
    /// The end of the innermost open container.
    EndOfContainer,
}

impl Value<'_> {
    /// Whether this is TLV null.
    ///
    /// Matter's `X` quality makes null a *value*, distinct from an absent field: §11.9.6.6's
    /// `LastNetworkingStatus` is null when nothing has been attempted and `0` when the last
    /// attempt succeeded, which are different claims. A decoder that treated the two alike
    /// would report success for a device that has never tried.
    #[must_use]
    pub const fn is_null(self) -> bool {
        matches!(self, Self::Null)
    }

    /// The container this value opens, if it opens one.
    #[must_use]
    pub const fn container(self) -> Option<ContainerKind> {
        match self {
            Self::Container(k) => Some(k),
            _ => None,
        }
    }
}

/// A tag and the value it labels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Element<'a> {
    /// The element's tag; [`Tag::Anonymous`] when it has none.
    pub tag: Tag,
    /// The element's value.
    pub value: Value<'a>,
}

impl<'a> Element<'a> {
    /// The value as an unsigned integer, or [`ErrorCode::TlvWrongType`].
    pub fn unsigned(&self) -> Result<u64> {
        match self.value {
            Value::Unsigned(v) => Ok(v),
            _ => Err(Error::new(ErrorCode::TlvWrongType)),
        }
    }

    /// The value as a signed integer, or [`ErrorCode::TlvWrongType`].
    pub fn signed(&self) -> Result<i64> {
        match self.value {
            Value::Signed(v) => Ok(v),
            _ => Err(Error::new(ErrorCode::TlvWrongType)),
        }
    }

    /// The value as a boolean, or [`ErrorCode::TlvWrongType`].
    pub fn bool(&self) -> Result<bool> {
        match self.value {
            Value::Bool(v) => Ok(v),
            _ => Err(Error::new(ErrorCode::TlvWrongType)),
        }
    }

    /// The value as a string, or [`ErrorCode::TlvWrongType`].
    pub fn utf8(&self) -> Result<&'a str> {
        match self.value {
            Value::Utf8(v) => Ok(v),
            _ => Err(Error::new(ErrorCode::TlvWrongType)),
        }
    }

    /// The value as an octet string, or [`ErrorCode::TlvWrongType`].
    pub fn octets(&self) -> Result<&'a [u8]> {
        match self.value {
            Value::Octets(v) => Ok(v),
            _ => Err(Error::new(ErrorCode::TlvWrongType)),
        }
    }
}

/// A cursor over a TLV encoding.
#[derive(Debug, Clone)]
pub struct TlvReader<'a> {
    buf: &'a [u8],
    pos: usize,
    stack: [ContainerKind; MAX_DEPTH],
    depth: usize,
    /// Set once the single top-level element of §A.1 has been fully read, so that a
    /// second one is reported rather than silently accepted.
    top_level_done: bool,
    /// Whether this cursor reads a container's *members* rather than one element.
    ///
    /// §A.1's "single top-level element" is a rule about an encoding, and a members fragment
    /// is not one — it is the inside of a container whose punctuation is somewhere else. A
    /// reader that applied the rule anyway would accept the first member and refuse the
    /// second, which is a spectacularly confusing way to fail.
    many: bool,
    /// Whether [`TlvReader::new_in`] made this cursor start inside a container.
    started_inside: bool,
}

impl<'a> TlvReader<'a> {
    /// Starts reading at the beginning of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            stack: [ContainerKind::Structure; MAX_DEPTH],
            depth: 0,
            top_level_done: false,
            many: false,
            started_inside: false,
        }
    }

    /// Starts reading as though the cursor were already inside `container`.
    ///
    /// Which tag forms are legal depends on where an element sits (§A.2.2, §A.5.1,
    /// §A.5.2), so a fragment that will be spliced into a structure has to be checked
    /// against a structure's rules, not against the top level's. A context-specific tag
    /// is invalid at the top level and required inside a structure — validating such a
    /// fragment with [`TlvReader::new`] would reject exactly the bytes that are correct.
    ///
    /// This is what [`TlvWriter::raw_element`](super::TlvWriter::raw_element) uses.
    #[must_use]
    pub const fn new_in(buf: &'a [u8], container: ContainerKind) -> Self {
        Self {
            buf,
            pos: 0,
            stack: [container; MAX_DEPTH],
            depth: 1,
            top_level_done: false,
            many: false,
            started_inside: true,
        }
    }

    /// A cursor over the *members* of a container — many elements, not one.
    ///
    /// [`TlvReader::new_in`] reads a fragment that will be spliced in as a single element, and
    /// holds it to §A.1's "single top-level element". This reads the inside of a container
    /// whose opening and closing octets live somewhere else, so the rule does not apply:
    /// [`TlvList`](super::TlvList) keeps a list's members that way, and a reader that refused
    /// the second one would be applying a rule about encodings to something that is not one.
    ///
    /// The members must **not** include the end-of-container: that octet closes a container
    /// this cursor was never told it is inside, and meeting it is
    /// [`ErrorCode::TlvContainerMismatch`].
    #[must_use]
    pub const fn new_members(buf: &'a [u8], container: ContainerKind) -> Self {
        Self {
            buf,
            pos: 0,
            stack: [container; MAX_DEPTH],
            depth: 1,
            top_level_done: false,
            many: true,
            started_inside: true,
        }
    }

    /// How many octets have been consumed.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// How many containers are currently open.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// The octets not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// Whether the cursor is at the end of the buffer.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::new(ErrorCode::TlvTruncated))?;
        let Some(slice) = self.buf.get(self.pos..end) else {
            bail!(TlvTruncated)
        };
        self.pos = end;
        Ok(slice)
    }

    /// The depth the cursor started at: 0 normally, 1 for [`TlvReader::new_in`].
    const fn base_depth(&self) -> usize {
        // `new_in` is the only way to start inside a container, and it starts at 1.
        if self.started_inside { 1 } else { 0 }
    }

    /// The container the cursor is directly inside, or `None` at the top level.
    fn current_container(&self) -> Option<ContainerKind> {
        self.depth
            .checked_sub(1)
            .and_then(|i| self.stack.get(i))
            .copied()
    }

    /// Enforces §A.2.2, §A.5.1 and §A.5.2: which tag forms a container admits.
    fn check_tag(&self, tag: Tag) -> Result<()> {
        match self.current_container() {
            // "All valid TLV encodings consist of a single top-level element", and a
            // context-specific tag "cannot appear as the outermost element of a TLV
            // encoding" (§A.2.2). Profile-specific tags are fine at the top level —
            // Table 129's last row is exactly that.
            None => {
                if tag.context().is_some() {
                    bail!(TlvInvalidTag)
                }
            }
            // "Member elements without tags (anonymous elements) are not allowed in
            // structures" (§A.5.1).
            Some(ContainerKind::Structure) => {
                if tag.is_anonymous() {
                    bail!(TlvInvalidTag)
                }
            }
            // "All member elements of an array SHALL be anonymous elements" (§A.5.2).
            Some(ContainerKind::Array) => {
                if !tag.is_anonymous() {
                    bail!(TlvInvalidTag)
                }
            }
            // "The members of a list may be encoded with any form of tag" (§A.5.3).
            Some(ContainerKind::List) => {}
        }
        Ok(())
    }

    /// Reads the next element.
    ///
    /// Returns `Ok(None)` at the end of the buffer. An unterminated container is *not* an
    /// error here — it is one in [`TlvReader::finish`], which is what a caller that has
    /// read a whole encoding should call.
    pub fn next_element(&mut self) -> Result<Option<Element<'a>>> {
        if self.is_empty() {
            return Ok(None);
        }
        if self.top_level_done && !self.many && self.depth == self.base_depth() {
            // §A.1: "All valid TLV encodings consist of a single top-level element."
            bail!(TlvContainerMismatch)
        }

        let control = {
            let b = self.take(1)?;
            let Some(&c) = b.first() else {
                bail!(TlvTruncated)
            };
            c
        };
        let element_type = ElementType::from_bits(control)?;

        // §A.10: end-of-container is control octet 0x18 exactly — "The tag control bits
        // within the control octet SHALL be set to zero".
        if matches!(element_type, ElementType::EndOfContainer) {
            if control != 0x18 {
                bail!(TlvInvalidControl)
            }
            let Some(new_depth) = self.depth.checked_sub(1) else {
                bail!(TlvContainerMismatch)
            };
            if new_depth < self.base_depth() {
                // Closing the container this cursor was told it is inside would leave the
                // fragment, which is not something a fragment may do.
                bail!(TlvContainerMismatch)
            }
            self.depth = new_depth;
            if self.depth == self.base_depth() {
                self.top_level_done = true;
            }
            return Ok(Some(Element {
                tag: Tag::Anonymous,
                value: Value::EndOfContainer,
            }));
        }

        let (tag, tag_len) = Tag::decode(control, self.remaining())?;
        self.pos = self
            .pos
            .checked_add(tag_len)
            .ok_or(Error::new(ErrorCode::TlvTruncated))?;
        self.check_tag(tag)?;

        let value = match element_type {
            ElementType::SignedInt(w) => Value::Signed(read_le_i64(self.take(w.octets())?)?),
            ElementType::UnsignedInt(w) => Value::Unsigned(read_le_u64(self.take(w.octets())?)?),
            ElementType::Bool(v) => Value::Bool(v),
            ElementType::Float => {
                let raw = read_le_u64(self.take(4)?)?;
                let Ok(bits) = u32::try_from(raw) else {
                    bail!(TlvOutOfRange)
                };
                Value::Float(f32::from_bits(bits))
            }
            ElementType::Double => Value::Double(f64::from_bits(read_le_u64(self.take(8)?)?)),
            ElementType::Utf8(w) => {
                let bytes = self.take_string(w)?;
                match core::str::from_utf8(bytes) {
                    Ok(s) => Value::Utf8(s),
                    Err(_) => bail!(TlvInvalidUtf8),
                }
            }
            ElementType::Octets(w) => Value::Octets(self.take_string(w)?),
            ElementType::Null => Value::Null,
            ElementType::Structure | ElementType::Array | ElementType::List => {
                let kind = match element_type {
                    ElementType::Structure => ContainerKind::Structure,
                    ElementType::Array => ContainerKind::Array,
                    _ => ContainerKind::List,
                };
                let Some(slot) = self.stack.get_mut(self.depth) else {
                    bail!(TlvDepthExceeded)
                };
                *slot = kind;
                self.depth = self
                    .depth
                    .checked_add(1)
                    .ok_or(Error::new(ErrorCode::TlvDepthExceeded))?;
                Value::Container(kind)
            }
            // Handled above.
            ElementType::EndOfContainer => bail!(TlvInvalidControl),
        };

        if self.depth == self.base_depth() {
            self.top_level_done = true;
        }
        Ok(Some(Element { tag, value }))
    }

    /// Reads a string's length field and then its value octets.
    fn take_string(&mut self, w: Width) -> Result<&'a [u8]> {
        let len = read_le_u64(self.take(w.octets())?)?;
        let Ok(len) = usize::try_from(len) else {
            // A length that does not fit a `usize` cannot be satisfied by a buffer that
            // does, so this is truncation rather than an out-of-range value.
            bail!(TlvTruncated)
        };
        self.take(len)
    }

    /// Skips the container the cursor has just entered, leaving it positioned after that
    /// container's end-of-container element.
    ///
    /// Call this immediately after a [`Value::Container`] element. It is iterative, so
    /// nesting costs no stack.
    pub fn skip_container(&mut self) -> Result<()> {
        let Some(target) = self.depth.checked_sub(1) else {
            bail!(TlvContainerMismatch)
        };
        while self.depth > target {
            if self.next_element()?.is_none() {
                bail!(TlvContainerMismatch)
            }
        }
        Ok(())
    }

    /// The octets between `start` and the cursor — one element with its tag, when `start`
    /// was taken immediately before reading it.
    ///
    /// This is how a payload whose schema belongs to somebody else is carried: an attribute's
    /// value has a cluster's type, not the interaction model's, so the interaction model keeps
    /// the encoded element and hands it on with
    /// [`TlvWriter::raw_element`](super::TlvWriter::raw_element) rather than interpreting it.
    ///
    /// Returns [`ErrorCode::TlvTruncated`] if `start` is past the cursor, which can only
    /// happen if a caller passed a position from a different reader.
    pub fn slice_from(&self, start: usize) -> Result<&'a [u8]> {
        self.buf
            .get(start..self.pos)
            .ok_or(Error::new(ErrorCode::TlvTruncated))
    }

    /// Skips whatever the given element is: a no-op for a primitive, a whole subtree for
    /// a container.
    pub fn skip_value(&mut self, element: &Element<'a>) -> Result<()> {
        if element.value.container().is_some() {
            self.skip_container()?;
        }
        Ok(())
    }

    /// Checks that the encoding is complete and well-formed: every container closed, and
    /// exactly one top-level element present.
    pub fn finish(&self) -> Result<()> {
        if self.depth != self.base_depth() {
            bail!(TlvContainerMismatch)
        }
        if !self.top_level_done {
            bail!(TlvTruncated)
        }
        if !self.is_empty() {
            // Trailing octets after the single top-level element.
            bail!(TlvContainerMismatch)
        }
        Ok(())
    }

    /// Reads the whole encoding, checking it is well-formed, and returns how many
    /// elements it contained.
    ///
    /// This is what a fuzz target and a "is this valid TLV?" caller want.
    pub fn validate(buf: &'a [u8]) -> Result<usize> {
        let mut r = Self::new(buf);
        let mut count = 0usize;
        while r.next_element()?.is_some() {
            count = count.saturating_add(1);
        }
        r.finish()?;
        Ok(count)
    }

    /// The first container with no members under a context-specific tag, if there is one.
    ///
    /// **What you write, somebody stricter will read.** An optional structure encoded with
    /// nothing in it is legal Appendix A, accepted by this crate's decoder, and refused by every
    /// released CHIP SDK — so the rule kept here is stricter than the specification's: an
    /// optional structure that would be empty is not written at all.
    ///
    /// It cannot live in [`TlvWriter`](crate::tlv::TlvWriter), because §4.14.1.2 gives empty a
    /// meaning: an empty `PBKDFParamResponse.pbkdf_parameters [4]` encodes "the initiator
    /// already has them", which is a claim rather than an absence. So the rule is checked *over*
    /// the writer, on encoded output, and the caller knows its own exceptions.
    ///
    /// Two narrowings, and both matter. **Only structures** — an empty array or list is a value,
    /// and a node that wrote nothing has to be able to say so. **Only context-specific tags** —
    /// an anonymous empty structure is an element of the list containing it, not an absent field.
    ///
    /// ```
    /// use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut w = TlvWriter::new(&mut buf);
    /// w.start(Tag::Anonymous, ContainerKind::Structure).unwrap();
    /// w.start(Tag::Context(4), ContainerKind::Structure).unwrap();   // optional, and empty
    /// w.end_container().unwrap();
    /// w.end_container().unwrap();
    /// let encoded = w.finish().unwrap();
    ///
    /// assert_eq!(TlvReader::first_empty_optional(encoded).unwrap(), Some(Tag::Context(4)));
    /// ```
    ///
    /// Errors only when `buf` is not well-formed TLV; [`TlvReader::validate`] is the check that
    /// makes that complaint.
    pub fn first_empty_optional(buf: &'a [u8]) -> Result<Option<Tag>> {
        let mut r = Self::new(buf);
        // The tag of each container currently open, innermost last, and whether anything has
        // been written inside it yet.
        let mut open: heapless::Vec<(Tag, bool, crate::tlv::ContainerKind), 16> =
            heapless::Vec::new();
        while let Some(element) = r.next_element()? {
            match element.value {
                Value::Container(kind) => {
                    if let Some((_, seen, _)) = open.last_mut() {
                        *seen = true;
                    }
                    if open.push((element.tag, false, kind)).is_err() {
                        // Deeper than Appendix A's own nesting limit, which `next_element` has
                        // already refused — so this is unreachable, and saying so is cheaper
                        // than a second error code nobody can produce.
                        bail!(TlvContainerMismatch)
                    }
                }
                Value::EndOfContainer => {
                    let Some((tag, seen, kind)) = open.pop() else {
                        bail!(TlvContainerMismatch)
                    };
                    let empty_structure =
                        !seen && matches!(kind, crate::tlv::ContainerKind::Structure);
                    if empty_structure && matches!(tag, Tag::Context(_)) {
                        return Ok(Some(tag));
                    }
                }
                _ => {
                    if let Some((_, seen, _)) = open.last_mut() {
                        *seen = true;
                    }
                }
            }
        }
        r.finish()?;
        Ok(None)
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn one(buf: &[u8]) -> Element<'_> {
        let mut r = TlvReader::new(buf);
        r.next_element().expect("read").expect("an element")
    }

    #[test]
    fn primitives_from_table_127() {
        assert_eq!(one(&[0x08]).value, Value::Bool(false));
        assert_eq!(one(&[0x09]).value, Value::Bool(true));
        assert_eq!(one(&[0x00, 0x2a]).value, Value::Signed(42));
        assert_eq!(one(&[0x00, 0xef]).value, Value::Signed(-17));
        assert_eq!(one(&[0x04, 0x2a]).value, Value::Unsigned(42));
        assert_eq!(one(&[0x01, 0x2a, 0x00]).value, Value::Signed(42));
        assert_eq!(
            one(&[0x02, 0xf0, 0x67, 0xfd, 0xff]).value,
            Value::Signed(-170_000)
        );
        assert_eq!(
            one(&[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00]).value,
            Value::Signed(40_000_000_000)
        );
        assert_eq!(
            one(&[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21]).value,
            Value::Utf8("Hello!")
        );
        assert_eq!(
            one(&[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73]).value,
            Value::Utf8("Tschüs")
        );
        assert_eq!(
            one(&[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04]).value,
            Value::Octets(&[0, 1, 2, 3, 4])
        );
        assert_eq!(one(&[0x14]).value, Value::Null);
        assert_eq!(
            one(&[0x0a, 0x00, 0x00, 0x00, 0x00]).value,
            Value::Float(0.0)
        );
        assert_eq!(
            one(&[0x0a, 0x33, 0x33, 0x8f, 0x41]).value,
            Value::Float(17.9)
        );
        assert_eq!(
            one(&[0x0a, 0x00, 0x00, 0x80, 0x7f]).value,
            Value::Float(f32::INFINITY)
        );
        assert_eq!(
            one(&[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40]).value,
            Value::Double(17.9)
        );
    }

    #[test]
    fn tags_from_table_129() {
        assert_eq!(one(&[0x04, 0x2a]).tag, Tag::Anonymous);
        // A context tag cannot be outermost (§A.2.2), so Table 129's second row is read
        // where such a tag is legal: inside a structure.
        {
            let buf = [0x15, 0x24, 0x01, 0x2a, 0x18];
            let mut r = TlvReader::new(&buf);
            let _open = r.next_element().expect("read").expect("an element");
            let member = r.next_element().expect("read").expect("an element");
            assert_eq!(member.tag, Tag::Context(1));
            assert_eq!(member.unsigned().expect("unsigned"), 42);
        }
        assert_eq!(one(&[0x44, 0x01, 0x00, 0x2a]).tag, Tag::Common(1));
        assert_eq!(
            one(&[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a]).tag,
            Tag::Common(100_000)
        );
        assert_eq!(
            one(&[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a]).tag,
            Tag::FullyQualified {
                vendor: 0xFFF1,
                profile: 0xDEED,
                number: 1
            }
        );
        assert_eq!(
            one(&[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a]).tag,
            Tag::FullyQualified {
                vendor: 0xFFF1,
                profile: 0xDEED,
                number: 0xAA55_FEED
            }
        );
    }

    #[test]
    fn containers_from_table_128() {
        assert_eq!(TlvReader::validate(&[0x15, 0x18]).unwrap(), 2);
        assert_eq!(TlvReader::validate(&[0x16, 0x18]).unwrap(), 2);
        assert_eq!(TlvReader::validate(&[0x17, 0x18]).unwrap(), 2);
        // {0 = 42, 1 = -17}
        assert_eq!(
            TlvReader::validate(&[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18]).unwrap(),
            4
        );
        // [0, 1, 2, 3, 4]
        assert_eq!(
            TlvReader::validate(&[
                0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18
            ])
            .unwrap(),
            7
        );
        // List with a mix of anonymous and context tags.
        assert_eq!(
            TlvReader::validate(&[
                0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18
            ])
            .unwrap(),
            7
        );
        // Array with a mix of element types, including an empty structure.
        assert_eq!(
            TlvReader::validate(&[
                0x16, 0x00, 0x2a, 0x02, 0xf0, 0x67, 0xfd, 0xff, 0x15, 0x18, 0x0a, 0x33, 0x33, 0x8f,
                0x41, 0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x18
            ])
            .unwrap(),
            // array, 42, -170000, {, }, 17.9, "Hello!", ] — eight elements.
            8
        );
        // Structure with fully-qualified tags, inside and out.
        assert_eq!(
            TlvReader::validate(&[
                0xd5, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x55, 0xaa,
                0x2a, 0x18
            ])
            .unwrap(),
            3
        );
    }

    #[test]
    fn structure_members_may_not_be_anonymous() {
        // §A.5.1.
        assert_eq!(
            TlvReader::validate(&[0x15, 0x04, 0x2a, 0x18])
                .unwrap_err()
                .code(),
            ErrorCode::TlvInvalidTag
        );
    }

    #[test]
    fn array_members_must_be_anonymous() {
        // §A.5.2.
        assert_eq!(
            TlvReader::validate(&[0x16, 0x24, 0x01, 0x2a, 0x18])
                .unwrap_err()
                .code(),
            ErrorCode::TlvInvalidTag
        );
    }

    #[test]
    fn context_tag_may_not_be_outermost() {
        // §A.2.2.
        assert_eq!(
            TlvReader::validate(&[0x24, 0x01, 0x2a]).unwrap_err().code(),
            ErrorCode::TlvInvalidTag
        );
    }

    #[test]
    fn end_of_container_must_have_zero_tag_control() {
        // §A.10: 0x18 exactly. 0x38 is end-of-container with a context tag control.
        assert_eq!(
            TlvReader::validate(&[0x15, 0x38, 0x01]).unwrap_err().code(),
            ErrorCode::TlvInvalidControl
        );
    }

    #[test]
    fn unbalanced_containers_are_refused() {
        assert_eq!(
            TlvReader::validate(&[0x15]).unwrap_err().code(),
            ErrorCode::TlvContainerMismatch
        );
        assert_eq!(
            TlvReader::validate(&[0x18]).unwrap_err().code(),
            ErrorCode::TlvContainerMismatch
        );
    }

    #[test]
    fn only_one_top_level_element() {
        // §A.1.
        assert_eq!(
            TlvReader::validate(&[0x04, 0x2a, 0x04, 0x2b])
                .unwrap_err()
                .code(),
            ErrorCode::TlvContainerMismatch
        );
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        for cut in 1..8 {
            let full = [0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21];
            let _ = TlvReader::validate(&full[..cut]);
        }
        assert_eq!(
            TlvReader::validate(&[0x0c, 0x06, 0x48]).unwrap_err().code(),
            ErrorCode::TlvTruncated
        );
    }

    #[test]
    fn invalid_utf8_is_refused() {
        assert_eq!(
            TlvReader::validate(&[0x0c, 0x02, 0xff, 0xfe])
                .unwrap_err()
                .code(),
            ErrorCode::TlvInvalidUtf8
        );
    }

    #[test]
    fn depth_is_bounded() {
        // Arrays, because an array's members are anonymous (§A.5.2) and a structure's
        // may not be (§A.5.1) — nesting bare structures is invalid for a different
        // reason and would not test the depth budget.
        fn nested(levels: usize) -> heapless::Vec<u8, 128> {
            let mut v = heapless::Vec::new();
            for _ in 0..levels {
                let _ = v.push(0x16);
            }
            for _ in 0..levels {
                let _ = v.push(0x18);
            }
            v
        }
        assert!(
            TlvReader::validate(&nested(MAX_DEPTH)).is_ok(),
            "MAX_DEPTH levels must be readable"
        );
        assert_eq!(
            TlvReader::validate(&nested(MAX_DEPTH + 1))
                .unwrap_err()
                .code(),
            ErrorCode::TlvDepthExceeded
        );
    }

    #[test]
    fn skip_container_lands_after_the_end() {
        let buf = [0x15, 0x24, 0x00, 0x2a, 0x24, 0x01, 0xef, 0x18];
        let mut r = TlvReader::new(&buf);
        let e = r.next_element().unwrap().unwrap();
        assert_eq!(e.value, Value::Container(ContainerKind::Structure));
        r.skip_container().unwrap();
        assert!(r.is_empty());
        r.finish().unwrap();
    }

    #[test]
    fn a_huge_declared_length_is_truncation() {
        // An 8-octet length of u64::MAX with nothing behind it.
        let buf = [0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            TlvReader::validate(&buf).unwrap_err().code(),
            ErrorCode::TlvTruncated
        );
    }
}
