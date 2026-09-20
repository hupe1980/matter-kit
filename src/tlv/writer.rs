//! A TLV writer over a caller-supplied buffer.
//!
//! The writer never allocates: it fills a `&mut [u8]` and tells you how much it used.
//! Running out of room is [`ErrorCode::BufferTooSmall`], never a panic and never a
//! truncated encoding — a failed write leaves the buffer's contents unspecified but the
//! error is returned before anything claims to be complete.
//!
//! It also *refuses to produce invalid TLV*: an anonymous member of a structure, a tagged
//! member of an array, an unbalanced container or a second top-level element are errors
//! at the call that would create them, not surprises at the far end. Values are encoded
//! at their narrowest legal width, which §A.9 and §A.11.1 leave to the sender's
//! discretion, so the output is deterministic and therefore safe to hash.

use super::reader::MAX_DEPTH;
use super::types::{ContainerKind, ElementType, Tag, Width, write_le};
use crate::error::{Error, ErrorCode, Result, bail};

/// A position in a [`TlvWriter`], taken by [`TlvWriter::checkpoint`].
///
/// Opaque and `Copy`: it is the writer's whole state minus the buffer, which is sixteen
/// container kinds and three scalars, so keeping one per chunk boundary costs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pos: usize,
    stack: [ContainerKind; MAX_DEPTH],
    depth: usize,
    top_level_done: bool,
}

/// Builds a TLV encoding in a borrowed buffer.
#[derive(Debug)]
pub struct TlvWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    stack: [ContainerKind; MAX_DEPTH],
    depth: usize,
    top_level_done: bool,
    /// Whether [`TlvWriter::new_in`] made this cursor start inside a container, so that
    /// `finish` knows which depth means "done".
    started_inside: bool,
}

impl<'a> TlvWriter<'a> {
    /// Starts writing at the beginning of `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            stack: [ContainerKind::Structure; MAX_DEPTH],
            depth: 0,
            top_level_done: false,
            started_inside: false,
        }
    }

    /// Starts writing as though the cursor were already inside `container`.
    ///
    /// Which tag forms are legal depends on where an element sits (§A.5.1, §A.5.2), so a
    /// fragment that will be spliced into a structure has to be *written* against a
    /// structure's rules as well as read against them: a context-specific tag is illegal at
    /// the top level and required inside a structure, so building such a fragment with
    /// [`TlvWriter::new`] refuses exactly the bytes that are correct.
    ///
    /// This is the counterpart of [`TlvReader::new_in`](super::TlvReader::new_in), and what
    /// produces the payloads [`TlvWriter::raw_element`] consumes — an attribute's value, a
    /// command's fields: anything whose schema belongs to a cluster rather than to the layer
    /// carrying it.
    ///
    /// ```
    /// use matter_kit::tlv::{ContainerKind, Tag, TlvWriter};
    ///
    /// // An attribute value destined for an AttributeDataIB's context-2 slot.
    /// let mut buf = [0u8; 16];
    /// let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    /// w.unsigned(Tag::Context(2), 42)?;
    /// assert_eq!(w.finish()?, &[0x24, 0x02, 0x2A]);
    /// # Ok::<(), matter_kit::Error>(())
    /// ```
    #[must_use]
    pub fn new_in(buf: &'a mut [u8], container: ContainerKind) -> Self {
        Self {
            buf,
            pos: 0,
            stack: [container; MAX_DEPTH],
            depth: 1,
            top_level_done: false,
            started_inside: true,
        }
    }

    /// How many octets have been written.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pos
    }

    /// Whether nothing has been written yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// How many containers are currently open.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// The encoding written so far.
    ///
    /// Prefer [`TlvWriter::finish`], which also checks that the encoding is complete.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        self.buf.get(..self.pos).unwrap_or(&[])
    }

    /// Records the writer's position so a failed write can be undone.
    ///
    /// This is what makes size-driven chunking possible (Core §10.2.3). "Chunking entails
    /// maximally packing these information blocks into a series of 'data' messages", and
    /// the only way to know whether one more block fits is to try: a writer that runs out
    /// of room leaves "the buffer's contents unspecified", which would corrupt the message
    /// already packed into it. Taking a checkpoint before a block and rolling back when it
    /// does not fit turns that into a clean boundary.
    ///
    /// ```
    /// use matter_kit::tlv::{Tag, TlvWriter};
    ///
    /// let mut buf = [0u8; 8];
    /// let mut w = TlvWriter::new(&mut buf);
    /// w.start_array(Tag::Anonymous)?;
    /// let cp = w.checkpoint();
    /// // Far too big for what is left; the buffer is now unspecified past `cp`.
    /// assert!(w.octets(Tag::Anonymous, &[0; 32]).is_err());
    /// w.rollback(&cp);
    /// // ...and the array is intact, so it can still be closed and sent.
    /// w.end_container()?;
    /// assert_eq!(w.finish()?, &[0x16, 0x18]);
    /// # Ok::<(), matter_kit::Error>(())
    /// ```
    #[must_use]
    pub const fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            pos: self.pos,
            stack: self.stack,
            depth: self.depth,
            top_level_done: self.top_level_done,
        }
    }

    /// Restores a position taken by [`TlvWriter::checkpoint`], discarding everything
    /// written since.
    ///
    /// The octets past the restored position keep whatever a failed write left in them;
    /// they are simply no longer part of the encoding, because [`TlvWriter::written`] and
    /// [`TlvWriter::finish`] both stop at `pos`.
    pub const fn rollback(&mut self, checkpoint: &Checkpoint) {
        self.pos = checkpoint.pos;
        self.stack = checkpoint.stack;
        self.depth = checkpoint.depth;
        self.top_level_done = checkpoint.top_level_done;
    }

    /// How many octets are still free.
    ///
    /// A lower bound on what will fit: every element also costs a control octet and a tag,
    /// so this answers "is it even worth trying?" rather than "will this value fit?".
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Checks the encoding is complete — one top-level element, every container closed —
    /// and returns it.
    pub fn finish(self) -> Result<&'a [u8]> {
        let base = usize::from(self.started_inside);
        if self.depth != base {
            bail!(TlvContainerMismatch)
        }
        // A top-level encoding is one element (§A.1); a fragment written with
        // [`TlvWriter::new_in`] is one member of a container, so "done" means something was
        // written rather than that the single top-level element completed.
        if self.started_inside {
            if self.pos == 0 {
                bail!(InvalidState)
            }
        } else if !self.top_level_done {
            bail!(InvalidState)
        }
        self.buf
            .get(..self.pos)
            .ok_or(Error::new(ErrorCode::BufferTooSmall))
    }

    fn room(&mut self, n: usize) -> Result<&mut [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let Some(slice) = self.buf.get_mut(self.pos..end) else {
            bail!(BufferTooSmall)
        };
        Ok(slice)
    }

    fn advance(&mut self, n: usize) -> Result<()> {
        self.pos = self
            .pos
            .checked_add(n)
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        Ok(())
    }

    fn current_container(&self) -> Option<ContainerKind> {
        self.depth
            .checked_sub(1)
            .and_then(|i| self.stack.get(i))
            .copied()
    }

    /// The mirror of the reader's check: which tag forms this position admits.
    fn check_tag(&self, tag: Tag) -> Result<()> {
        if self.depth == 0 && self.top_level_done {
            // §A.1: one top-level element.
            bail!(InvalidState)
        }
        match self.current_container() {
            None => {
                if tag.context().is_some() {
                    bail!(TlvInvalidTag)
                }
            }
            Some(ContainerKind::Structure) => {
                if tag.is_anonymous() {
                    bail!(TlvInvalidTag)
                }
            }
            Some(ContainerKind::Array) => {
                if !tag.is_anonymous() {
                    bail!(TlvInvalidTag)
                }
            }
            Some(ContainerKind::List) => {}
        }
        Ok(())
    }

    /// Writes a control octet and its tag.
    fn head(&mut self, tag: Tag, ty: ElementType) -> Result<()> {
        self.check_tag(tag)?;
        let tag_len = tag.encoded_len();
        let total = tag_len
            .checked_add(1)
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let slot = self.room(total)?;
        let Some(control) = slot.first_mut() else {
            bail!(BufferTooSmall)
        };
        *control = tag.control_bits() | ty.bits();
        let Some(rest) = slot.get_mut(1..) else {
            bail!(BufferTooSmall)
        };
        tag.encode(rest)?;
        self.advance(total)?;
        if self.depth == 0 {
            self.top_level_done = true;
        }
        Ok(())
    }

    /// Writes a signed integer at its narrowest legal width.
    #[expect(
        clippy::cast_sign_loss,
        reason = "a two's-complement reinterpretation before a little-endian write of exactly `n` octets"
    )]
    pub fn signed(&mut self, tag: Tag, value: i64) -> Result<()> {
        let w = Width::for_signed(value);
        self.head(tag, ElementType::SignedInt(w))?;
        let n = w.octets();
        let slot = self.room(n)?;
        write_le(slot, value as u64, n)?;
        self.advance(n)
    }

    /// Writes an unsigned integer at its narrowest legal width.
    pub fn unsigned(&mut self, tag: Tag, value: u64) -> Result<()> {
        let w = Width::for_unsigned(value);
        self.head(tag, ElementType::UnsignedInt(w))?;
        let n = w.octets();
        let slot = self.room(n)?;
        write_le(slot, value, n)?;
        self.advance(n)
    }

    /// Writes a boolean, whose value lives in the control octet.
    pub fn bool(&mut self, tag: Tag, value: bool) -> Result<()> {
        self.head(tag, ElementType::Bool(value))
    }

    /// Writes the null value.
    pub fn null(&mut self, tag: Tag) -> Result<()> {
        self.head(tag, ElementType::Null)
    }

    /// Writes a single-precision float.
    pub fn float(&mut self, tag: Tag, value: f32) -> Result<()> {
        self.head(tag, ElementType::Float)?;
        let slot = self.room(4)?;
        write_le(slot, u64::from(value.to_bits()), 4)?;
        self.advance(4)
    }

    /// Writes a double-precision float.
    pub fn double(&mut self, tag: Tag, value: f64) -> Result<()> {
        self.head(tag, ElementType::Double)?;
        let slot = self.room(8)?;
        write_le(slot, value.to_bits(), 8)?;
        self.advance(8)
    }

    /// Writes a UTF-8 string. The length field takes its narrowest legal width.
    pub fn utf8(&mut self, tag: Tag, value: &str) -> Result<()> {
        self.string(tag, value.as_bytes(), true)
    }

    /// Writes an octet string. The length field takes its narrowest legal width.
    pub fn octets(&mut self, tag: Tag, value: &[u8]) -> Result<()> {
        self.string(tag, value, false)
    }

    /// Writes an octet string of `len` copies of one byte, without a source buffer.
    ///
    /// A TLV octet string states its length before its content, so a caller that wants a
    /// large uniform value would otherwise need a buffer of that size to copy *from* — which
    /// on a device means a second copy of something already in the output buffer. §11.12.7.4's
    /// `PayloadTestRequest` asks for up to 2048 such octets, and it exists precisely to find
    /// the size at which a device runs out of room, so materialising them twice would move
    /// the answer.
    pub fn octets_fill(&mut self, tag: Tag, len: usize, byte: u8) -> Result<()> {
        let length = len as u64;
        let w = Width::for_unsigned(length);
        self.head(tag, ElementType::Octets(w))?;
        let n = w.octets();
        let slot = self.room(n)?;
        write_le(slot, length, n)?;
        self.advance(n)?;
        let dst = self.room(len)?;
        let Some(dst) = dst.get_mut(..len) else {
            bail!(BufferTooSmall)
        };
        dst.fill(byte);
        self.advance(len)
    }

    fn string(&mut self, tag: Tag, value: &[u8], utf8: bool) -> Result<()> {
        let len = value.len() as u64;
        let w = Width::for_unsigned(len);
        let ty = if utf8 {
            ElementType::Utf8(w)
        } else {
            ElementType::Octets(w)
        };
        self.head(tag, ty)?;
        let n = w.octets();
        let slot = self.room(n)?;
        write_le(slot, len, n)?;
        self.advance(n)?;
        let dst = self.room(value.len())?;
        let Some(dst) = dst.get_mut(..value.len()) else {
            bail!(BufferTooSmall)
        };
        dst.copy_from_slice(value);
        self.advance(value.len())
    }

    /// Opens a container. Every one must be closed with [`TlvWriter::end_container`].
    pub fn start(&mut self, tag: Tag, kind: ContainerKind) -> Result<()> {
        if self.depth >= MAX_DEPTH {
            bail!(TlvDepthExceeded)
        }
        self.head(tag, kind.element_type())?;
        let Some(slot) = self.stack.get_mut(self.depth) else {
            bail!(TlvDepthExceeded)
        };
        *slot = kind;
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or(Error::new(ErrorCode::TlvDepthExceeded))?;
        // A container's *opening* element is the top-level element; it is not complete
        // until its end-of-container, so undo what `head` concluded.
        self.top_level_done = false;
        Ok(())
    }

    /// Opens a structure.
    pub fn start_structure(&mut self, tag: Tag) -> Result<()> {
        self.start(tag, ContainerKind::Structure)
    }

    /// Opens an array.
    pub fn start_array(&mut self, tag: Tag) -> Result<()> {
        self.start(tag, ContainerKind::Array)
    }

    /// Opens a list.
    pub fn start_list(&mut self, tag: Tag) -> Result<()> {
        self.start(tag, ContainerKind::List)
    }

    /// Closes the innermost open container (§A.10: control octet `0x18`, never tagged).
    pub fn end_container(&mut self) -> Result<()> {
        let Some(new_depth) = self.depth.checked_sub(1) else {
            bail!(TlvContainerMismatch)
        };
        let slot = self.room(1)?;
        let Some(b) = slot.first_mut() else {
            bail!(BufferTooSmall)
        };
        *b = 0x18;
        self.advance(1)?;
        self.depth = new_depth;
        if self.depth == 0 {
            self.top_level_done = true;
        }
        Ok(())
    }

    /// Copies an already-encoded element in, replacing its tag.
    ///
    /// An element's tag is the only part of it that depends on where it sits, so moving one
    /// between containers means re-tagging it: a member of an array is anonymous, and the
    /// same value as a member of a structure needs a context tag. Core §10.6.4.3.1's list
    /// chunking does exactly this — each item of a list is lifted out of the array and sent
    /// as its own `Data` field — and doing it by re-encoding would mean a second buffer as
    /// large as the value.
    ///
    /// Only the control octet and tag are rewritten; the value is copied verbatim, so this
    /// costs nothing beyond the copy `raw_element` already does.
    pub fn raw_element_retagged(&mut self, bytes: &[u8], tag: Tag) -> Result<()> {
        use super::reader::TlvReader;
        // Validated against the container it *came* from — an anonymous member of an array
        // is well-formed there and would be rejected against a structure's rules.
        let mut r = TlvReader::new_in(bytes, ContainerKind::List);
        let Some(first) = r.next_element()? else {
            bail!(InvalidArgument)
        };
        if first.value.container().is_some() {
            r.skip_container()?;
        }
        r.finish()?;

        let Some(&control) = bytes.first() else {
            bail!(InvalidArgument)
        };
        // The element type is the low five bits; the old tag's width is fixed by the top
        // three, so the value starts at a known offset.
        let old_tag_len = first.tag.encoded_len();
        let value_start = old_tag_len
            .checked_add(1)
            .ok_or(Error::new(ErrorCode::InvalidArgument))?;
        let Some(value) = bytes.get(value_start..) else {
            bail!(InvalidArgument)
        };

        self.check_tag(tag)?;
        let new_tag_len = tag.encoded_len();
        let head = new_tag_len
            .checked_add(1)
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let total = head
            .checked_add(value.len())
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let slot = self.room(total)?;
        let Some(first_byte) = slot.first_mut() else {
            bail!(BufferTooSmall)
        };
        *first_byte = tag.control_bits() | (control & 0x1F);
        let Some(rest) = slot.get_mut(1..) else {
            bail!(BufferTooSmall)
        };
        tag.encode(rest)?;
        let Some(dst) = slot.get_mut(head..total) else {
            bail!(BufferTooSmall)
        };
        dst.copy_from_slice(value);
        self.advance(total)?;
        if self.depth == 0 {
            self.top_level_done = true;
        }
        Ok(())
    }

    /// Copies an already-encoded element in verbatim.
    ///
    /// The bytes are checked to be one well-formed TLV element and to carry a tag this
    /// position admits, so a forwarding path (a proxy, a bridge) cannot launder invalid
    /// TLV through this writer.
    ///
    /// The check is made *in this position*: a fragment destined for a structure is
    /// validated against a structure's rules, so a context-specific tag — illegal at the
    /// top level, required inside a structure — is judged the way it will actually be
    /// read.
    pub fn raw_element(&mut self, bytes: &[u8]) -> Result<()> {
        use super::reader::TlvReader;
        let mut r = match self.current_container() {
            Some(kind) => TlvReader::new_in(bytes, kind),
            None => TlvReader::new(bytes),
        };
        let Some(first) = r.next_element()? else {
            bail!(InvalidArgument)
        };
        if first.value.container().is_some() {
            r.skip_container()?;
        }
        r.finish()?;
        self.check_tag(first.tag)?;
        let dst = self.room(bytes.len())?;
        let Some(dst) = dst.get_mut(..bytes.len()) else {
            bail!(BufferTooSmall)
        };
        dst.copy_from_slice(bytes);
        self.advance(bytes.len())?;
        if self.depth == 0 {
            self.top_level_done = true;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::tlv::TlvReader;

    fn write_with(f: impl FnOnce(&mut TlvWriter<'_>) -> Result<()>) -> heapless::Vec<u8, 256> {
        let mut buf = [0u8; 256];
        let mut w = TlvWriter::new(&mut buf);
        f(&mut w).expect("write");
        let out = w.finish().expect("finish");
        heapless::Vec::from_slice(out).expect("fits")
    }

    #[test]
    fn primitives_match_table_127() {
        assert_eq!(&write_with(|w| w.bool(Tag::Anonymous, false))[..], &[0x08]);
        assert_eq!(&write_with(|w| w.bool(Tag::Anonymous, true))[..], &[0x09]);
        assert_eq!(
            &write_with(|w| w.signed(Tag::Anonymous, 42))[..],
            &[0x00, 0x2a]
        );
        assert_eq!(
            &write_with(|w| w.signed(Tag::Anonymous, -17))[..],
            &[0x00, 0xef]
        );
        assert_eq!(
            &write_with(|w| w.unsigned(Tag::Anonymous, 42))[..],
            &[0x04, 0x2a]
        );
        assert_eq!(
            &write_with(|w| w.signed(Tag::Anonymous, -170_000))[..],
            &[0x02, 0xf0, 0x67, 0xfd, 0xff]
        );
        assert_eq!(
            &write_with(|w| w.signed(Tag::Anonymous, 40_000_000_000))[..],
            &[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            &write_with(|w| w.utf8(Tag::Anonymous, "Hello!"))[..],
            &[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21]
        );
        assert_eq!(
            &write_with(|w| w.utf8(Tag::Anonymous, "Tschüs"))[..],
            &[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73]
        );
        assert_eq!(
            &write_with(|w| w.octets(Tag::Anonymous, &[0, 1, 2, 3, 4]))[..],
            &[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(&write_with(|w| w.null(Tag::Anonymous))[..], &[0x14]);
        assert_eq!(
            &write_with(|w| w.float(Tag::Anonymous, 17.9))[..],
            &[0x0a, 0x33, 0x33, 0x8f, 0x41]
        );
        assert_eq!(
            &write_with(|w| w.double(Tag::Anonymous, 17.9))[..],
            &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40]
        );
        assert_eq!(
            &write_with(|w| w.float(Tag::Anonymous, f32::NEG_INFINITY))[..],
            &[0x0a, 0x00, 0x00, 0x80, 0xff]
        );
    }

    #[test]
    fn profile_tags_match_table_129() {
        assert_eq!(
            &write_with(|w| w.unsigned(Tag::Common(1), 42))[..],
            &[0x44, 0x01, 0x00, 0x2a]
        );
        assert_eq!(
            &write_with(|w| w.unsigned(Tag::Common(100_000), 42))[..],
            &[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a]
        );
        assert_eq!(
            &write_with(|w| w.unsigned(
                Tag::FullyQualified {
                    vendor: 0xFFF1,
                    profile: 0xDEED,
                    number: 1
                },
                42
            ))[..],
            &[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a]
        );
        assert_eq!(
            &write_with(|w| w.unsigned(
                Tag::FullyQualified {
                    vendor: 0xFFF1,
                    profile: 0xDEED,
                    number: 0xAA55_FEED
                },
                42
            ))[..],
            &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a]
        );
    }

    #[test]
    fn containers_match_table_128() {
        assert_eq!(
            &write_with(|w| {
                w.start_structure(Tag::Anonymous)?;
                w.end_container()
            })[..],
            &[0x15, 0x18]
        );
        assert_eq!(
            &write_with(|w| {
                w.start_structure(Tag::Anonymous)?;
                w.signed(Tag::Context(0), 42)?;
                w.signed(Tag::Context(1), -17)?;
                w.end_container()
            })[..],
            &[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18]
        );
        assert_eq!(
            &write_with(|w| {
                w.start_array(Tag::Anonymous)?;
                for v in 0..5 {
                    w.signed(Tag::Anonymous, v)?;
                }
                w.end_container()
            })[..],
            &[
                0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18
            ]
        );
        assert_eq!(
            &write_with(|w| {
                w.start_list(Tag::Anonymous)?;
                w.signed(Tag::Anonymous, 1)?;
                w.signed(Tag::Context(0), 42)?;
                w.signed(Tag::Anonymous, 2)?;
                w.signed(Tag::Anonymous, 3)?;
                w.signed(Tag::Context(0), -17)?;
                w.end_container()
            })[..],
            &[
                0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18
            ]
        );
        // The nested fully-qualified structure of Table 129's last row.
        assert_eq!(
            &write_with(|w| {
                w.start_structure(Tag::FullyQualified {
                    vendor: 0xFFF1,
                    profile: 0xDEED,
                    number: 1,
                })?;
                w.unsigned(
                    Tag::FullyQualified {
                        vendor: 0xFFF1,
                        profile: 0xDEED,
                        number: 0xAA55,
                    },
                    42,
                )?;
                w.end_container()
            })[..],
            &[
                0xd5, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x55, 0xaa,
                0x2a, 0x18
            ]
        );
    }

    #[test]
    fn the_writer_refuses_to_emit_invalid_tlv() {
        let mut buf = [0u8; 64];

        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        assert_eq!(
            w.unsigned(Tag::Anonymous, 1).unwrap_err().code(),
            ErrorCode::TlvInvalidTag,
            "anonymous member of a structure"
        );

        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).unwrap();
        assert_eq!(
            w.unsigned(Tag::Context(1), 1).unwrap_err().code(),
            ErrorCode::TlvInvalidTag,
            "tagged member of an array"
        );

        let mut w = TlvWriter::new(&mut buf);
        assert_eq!(
            w.unsigned(Tag::Context(1), 1).unwrap_err().code(),
            ErrorCode::TlvInvalidTag,
            "context tag at the top level"
        );

        let mut w = TlvWriter::new(&mut buf);
        w.unsigned(Tag::Anonymous, 1).unwrap();
        assert_eq!(
            w.unsigned(Tag::Anonymous, 2).unwrap_err().code(),
            ErrorCode::InvalidState,
            "second top-level element"
        );

        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        assert_eq!(
            w.finish().unwrap_err().code(),
            ErrorCode::TlvContainerMismatch,
            "unclosed container"
        );
    }

    #[test]
    fn a_full_buffer_is_an_error_not_a_panic() {
        let mut buf = [0u8; 3];
        let mut w = TlvWriter::new(&mut buf);
        assert_eq!(
            w.utf8(Tag::Anonymous, "Hello!").unwrap_err().code(),
            ErrorCode::BufferTooSmall
        );
    }

    #[test]
    fn everything_written_reads_back() {
        let out = write_with(|w| {
            w.start_structure(Tag::Anonymous)?;
            w.unsigned(Tag::Context(0), 1)?;
            w.utf8(Tag::Context(1), "matter")?;
            w.start_array(Tag::Context(2))?;
            w.unsigned(Tag::Anonymous, 7)?;
            w.end_container()?;
            w.end_container()
        });
        assert!(TlvReader::validate(&out).is_ok());
    }

    #[test]
    fn raw_element_checks_what_it_copies() {
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        // A well-formed, correctly-tagged element goes in.
        w.raw_element(&[0x24, 0x01, 0x2a]).unwrap();
        // A malformed one does not.
        assert!(w.raw_element(&[0x15]).is_err());
        // Nor does one whose tag this container forbids.
        assert_eq!(
            w.raw_element(&[0x04, 0x2a]).unwrap_err().code(),
            ErrorCode::TlvInvalidTag
        );
        w.end_container().unwrap();
        let out = w.finish().unwrap();
        assert_eq!(out, &[0x15, 0x24, 0x01, 0x2a, 0x18]);
    }
}
