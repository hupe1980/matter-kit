//! The canonical-form check of §A.2.4 and §A.5.1.
//!
//! Two of the specification's rules are about a *whole container* rather than a single
//! element, so [`TlvReader`] — which sees one element at a time and keeps no history —
//! cannot enforce them:
//!
//! * §A.5.1: "All member elements within a structure SHALL have a unique tag."
//! * §A.2.4: where a distinguished ordering is required — "for the purposes of generating
//!   a hash or cryptographic signature" — members are ordered by the canonical tag rules.
//!
//! Checking uniqueness in general needs memory proportional to the widest structure.
//! Checking *strict* canonical ordering does not: the previous tag at each level is
//! enough, which is `MAX_DEPTH` tags of stack — and strict ordering implies uniqueness,
//! so this one pass answers both questions.
//!
//! This is what to run over an encoding that is about to be signed, or that arrived
//! claiming to be signed.

use super::reader::{MAX_DEPTH, TlvReader, Value};
use super::types::{ContainerKind, Tag};
use crate::error::{Result, bail};

/// Checks that `buf` is well-formed TLV *and* in canonical form.
///
/// Canonical form here means all of:
///
/// * every rule [`TlvReader`] already enforces;
/// * structure members appear in strictly increasing [`Tag::canonical_cmp`] order, which
///   also proves their tags are unique (§A.5.1, §A.2.4);
///
/// It does **not** check that widths are narrowest — §A.9 and §A.11.1 leave the width to
/// the sender, and a decoded [`Value`] no longer remembers the one it arrived in. That
/// question is [`re_encode_is_identical`], which answers it for the whole encoding at
/// once and more strictly.
///
/// Lists are ordered collections whose "meanings … are denoted by their position"
/// (§A.5.3), so their member order is data and is not checked. Arrays are likewise
/// ordered, and their members are anonymous.
///
/// Returns the number of elements, like [`TlvReader::validate`].
pub fn validate_canonical(buf: &[u8]) -> Result<usize> {
    let mut r = TlvReader::new(buf);
    // The last tag seen at each depth, and whether that level is a structure.
    let mut last: [Option<Tag>; MAX_DEPTH] = [None; MAX_DEPTH];
    let mut is_struct = [false; MAX_DEPTH];
    let mut count = 0usize;

    while let Some(element) = r.next_element()? {
        count = count.saturating_add(1);

        // `depth()` after reading is the depth *inside* a container it just opened, so
        // the level this element belongs to is one less for a container start.
        let level = match element.value {
            Value::Container(_) => r.depth().saturating_sub(1),
            Value::EndOfContainer => {
                // Leaving a level: forget its history so a sibling container starts fresh.
                if let Some(slot) = last.get_mut(r.depth()) {
                    *slot = None;
                }
                continue;
            }
            _ => r.depth(),
        };

        if let Some(&parent_is_struct) = level.checked_sub(1).and_then(|i| is_struct.get(i))
            && parent_is_struct
            && let Some(previous) = level
                .checked_sub(1)
                .and_then(|i| last.get(i))
                .copied()
                .flatten()
            && element.tag.canonical_cmp(previous) != core::cmp::Ordering::Greater
        {
            // Equal means a duplicate tag (§A.5.1); less means out of order (§A.2.4).
            bail!(TlvInvalidTag)
        }
        if let Some(slot) = level.checked_sub(1).and_then(|i| last.get_mut(i)) {
            *slot = Some(element.tag);
        }

        if let Value::Container(kind) = element.value
            && let Some(slot) = is_struct.get_mut(level)
        {
            *slot = matches!(kind, ContainerKind::Structure);
            if let Some(slot) = last.get_mut(level) {
                *slot = None;
            }
        }
    }
    r.finish()?;
    Ok(count)
}

/// Whether `buf` re-encodes to itself — the strongest statement of minimality.
///
/// A canonical encoding is a fixed point of [`TlvWriter`](super::TlvWriter): decode it and
/// write it back, and if every width was already narrowest and every tag already in order,
/// the bytes are identical. `out` must be at least `buf.len()` long.
///
/// This is the check to run before treating a received encoding as canonical.
pub fn re_encode_is_identical(buf: &[u8], out: &mut [u8]) -> Result<bool> {
    use super::writer::TlvWriter;

    let mut r = TlvReader::new(buf);
    let mut w = TlvWriter::new(out);
    while let Some(element) = r.next_element()? {
        match element.value {
            Value::Signed(v) => w.signed(element.tag, v)?,
            Value::Unsigned(v) => w.unsigned(element.tag, v)?,
            Value::Bool(v) => w.bool(element.tag, v)?,
            Value::Float(v) => w.float(element.tag, v)?,
            Value::Double(v) => w.double(element.tag, v)?,
            Value::Utf8(v) => w.utf8(element.tag, v)?,
            Value::Octets(v) => w.octets(element.tag, v)?,
            Value::Null => w.null(element.tag)?,
            Value::Container(kind) => w.start(element.tag, kind)?,
            Value::EndOfContainer => w.end_container()?,
        }
    }
    r.finish()?;
    let written = w.finish()?;
    Ok(written == buf)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn canonical_structure_passes() {
        // { 0 = 42, 1 = -17 } — tags in strictly increasing order.
        assert!(validate_canonical(&[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18]).is_ok());
    }

    #[test]
    fn duplicate_structure_tags_are_refused() {
        // §A.5.1: { 0 = 42, 0 = -17 }.
        assert!(validate_canonical(&[0x15, 0x20, 0x00, 0x2a, 0x20, 0x00, 0xef, 0x18]).is_err());
    }

    #[test]
    fn out_of_order_structure_tags_are_refused() {
        // §A.2.4: { 1 = -17, 0 = 42 } — well-formed, but not canonical.
        let buf = [0x15, 0x20, 0x01, 0xef, 0x20, 0x00, 0x2a, 0x18];
        assert!(TlvReader::validate(&buf).is_ok(), "still valid TLV");
        assert!(validate_canonical(&buf).is_err(), "but not canonical");
    }

    #[test]
    fn list_order_is_data_not_a_rule() {
        // A list may repeat tags and need not be ordered (§A.5.3).
        let buf = [
            0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18,
        ];
        assert!(validate_canonical(&buf).is_ok());
    }

    #[test]
    fn sibling_containers_do_not_share_history() {
        // [{0=1},{0=1}] — each structure starts its own tag sequence.
        let buf = [
            0x16, 0x15, 0x24, 0x00, 0x01, 0x18, 0x15, 0x24, 0x00, 0x01, 0x18, 0x18,
        ];
        assert!(validate_canonical(&buf).is_ok());
    }

    #[test]
    fn non_minimal_widths_are_not_fixed_points() {
        let mut out = [0u8; 64];
        // 2-octet 42, which §A.11.1 permits but is not narrowest.
        assert!(!re_encode_is_identical(&[0x01, 0x2a, 0x00], &mut out).unwrap());
        // 1-octet 42 is.
        assert!(re_encode_is_identical(&[0x00, 0x2a], &mut out).unwrap());
    }

    #[test]
    fn round_trip_of_every_spec_vector_is_a_fixed_point() {
        let mut out = [0u8; 128];
        for v in [
            &[0x08][..],
            &[0x09][..],
            &[0x00, 0x2a][..],
            &[0x00, 0xef][..],
            &[0x04, 0x2a][..],
            &[0x02, 0xf0, 0x67, 0xfd, 0xff][..],
            &[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00][..],
            &[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21][..],
            &[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04][..],
            &[0x14][..],
            &[0x0a, 0x33, 0x33, 0x8f, 0x41][..],
            &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40][..],
            &[0x15, 0x18][..],
            &[0x16, 0x18][..],
            &[0x17, 0x18][..],
            &[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18][..],
        ] {
            assert!(
                re_encode_is_identical(v, &mut out).unwrap(),
                "spec vector {v:02x?} is not a fixed point"
            );
        }
    }
}
