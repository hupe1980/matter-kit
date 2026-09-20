//! Element types, tag forms and tags — the vocabulary of Core Appendix A.

use crate::error::{Error, ErrorCode, Result, bail};

/// The element type field: the low 5 bits of a control octet (Core §A.7.1).
///
/// The variants carry the width the specification packs into the bottom two bits, because
/// a reader needs it and a writer chooses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElementType {
    /// Signed integer; the value field is 1, 2, 4 or 8 octets.
    SignedInt(Width),
    /// Unsigned integer; the value field is 1, 2, 4 or 8 octets.
    UnsignedInt(Width),
    /// Boolean; the value is in the control octet itself.
    Bool(bool),
    /// Single-precision float, 4-octet value.
    Float,
    /// Double-precision float, 8-octet value.
    Double,
    /// UTF-8 string; the length field is 1, 2, 4 or 8 octets.
    Utf8(Width),
    /// Octet string; the length field is 1, 2, 4 or 8 octets.
    Octets(Width),
    /// The null value.
    Null,
    /// Structure: members are uniquely tagged and never anonymous (§A.5.1).
    Structure,
    /// Array: members are always anonymous (§A.5.2).
    Array,
    /// List: members may carry any tag form, including none (§A.5.3).
    List,
    /// End-of-container, control octet `0x18` exactly (§A.10).
    EndOfContainer,
}

/// How many octets a length or integer value field occupies.
///
/// The specification encodes this as the bottom two bits of the element type for both
/// integers ("00 — 1 octet … 11 — 8 octets") and strings, so one type serves both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Width {
    /// 1 octet.
    One = 0,
    /// 2 octets.
    Two = 1,
    /// 4 octets.
    Four = 2,
    /// 8 octets.
    Eight = 3,
}

impl Width {
    /// The number of octets this width stands for.
    #[must_use]
    pub const fn octets(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::One,
            1 => Self::Two,
            2 => Self::Four,
            _ => Self::Eight,
        }
    }

    /// The narrowest width that can hold `value` as an unsigned integer.
    #[must_use]
    pub const fn for_unsigned(value: u64) -> Self {
        if value <= u8::MAX as u64 {
            Self::One
        } else if value <= u16::MAX as u64 {
            Self::Two
        } else if value <= u32::MAX as u64 {
            Self::Four
        } else {
            Self::Eight
        }
    }

    /// The narrowest width that can hold `value` as a two's-complement signed integer.
    #[must_use]
    pub const fn for_signed(value: i64) -> Self {
        if value >= i8::MIN as i64 && value <= i8::MAX as i64 {
            Self::One
        } else if value >= i16::MIN as i64 && value <= i16::MAX as i64 {
            Self::Two
        } else if value >= i32::MIN as i64 && value <= i32::MAX as i64 {
            Self::Four
        } else {
            Self::Eight
        }
    }
}

impl ElementType {
    /// Decodes the low 5 bits of a control octet.
    ///
    /// Returns [`ErrorCode::TlvInvalidControl`] for the reserved types `0x19`–`0x1F` and
    /// for `0x18` — end-of-container — which is handled by the caller because §A.10 makes
    /// its tag control bits significant.
    pub(crate) const fn from_bits(bits: u8) -> Result<Self> {
        let t = bits & 0x1F;
        Ok(match t {
            0x00..=0x03 => Self::SignedInt(Width::from_bits(t)),
            0x04..=0x07 => Self::UnsignedInt(Width::from_bits(t)),
            0x08 => Self::Bool(false),
            0x09 => Self::Bool(true),
            0x0A => Self::Float,
            0x0B => Self::Double,
            0x0C..=0x0F => Self::Utf8(Width::from_bits(t)),
            0x10..=0x13 => Self::Octets(Width::from_bits(t)),
            0x14 => Self::Null,
            0x15 => Self::Structure,
            0x16 => Self::Array,
            0x17 => Self::List,
            0x18 => Self::EndOfContainer,
            // 0x19..=0x1F: "Reserved".
            _ => return Err(Error::new(ErrorCode::TlvInvalidControl)),
        })
    }

    /// The low 5 bits this type encodes as.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            // Signed integers are element types 0x00..=0x03: the width *is* the value.
            Self::SignedInt(w) => w as u8,
            Self::UnsignedInt(w) => 0x04 | w as u8,
            Self::Bool(false) => 0x08,
            Self::Bool(true) => 0x09,
            Self::Float => 0x0A,
            Self::Double => 0x0B,
            Self::Utf8(w) => 0x0C | w as u8,
            Self::Octets(w) => 0x10 | w as u8,
            Self::Null => 0x14,
            Self::Structure => 0x15,
            Self::Array => 0x16,
            Self::List => 0x17,
            Self::EndOfContainer => 0x18,
        }
    }
}

/// Which of the three container types an element opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerKind {
    /// A structure (§A.5.1).
    Structure,
    /// An array (§A.5.2).
    Array,
    /// A list (§A.5.3).
    List,
}

impl ContainerKind {
    /// The element type that opens this container.
    #[must_use]
    pub const fn element_type(self) -> ElementType {
        match self {
            Self::Structure => ElementType::Structure,
            Self::Array => ElementType::Array,
            Self::List => ElementType::List,
        }
    }
}

/// The tag control field: the top 3 bits of a control octet (Core §A.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
enum TagControl {
    Anonymous = 0b000,
    ContextSpecific = 0b001,
    CommonProfile2 = 0b010,
    CommonProfile4 = 0b011,
    ImplicitProfile2 = 0b100,
    ImplicitProfile4 = 0b101,
    FullyQualified6 = 0b110,
    FullyQualified8 = 0b111,
}

impl TagControl {
    const fn from_bits(bits: u8) -> Self {
        match bits >> 5 {
            0b000 => Self::Anonymous,
            0b001 => Self::ContextSpecific,
            0b010 => Self::CommonProfile2,
            0b011 => Self::CommonProfile4,
            0b100 => Self::ImplicitProfile2,
            0b101 => Self::ImplicitProfile4,
            0b110 => Self::FullyQualified6,
            // The field is three bits; there is no eighth case.
            _ => Self::FullyQualified8,
        }
    }

    /// How many tag octets follow the control octet.
    const fn octets(self) -> usize {
        match self {
            Self::Anonymous => 0,
            Self::ContextSpecific => 1,
            Self::CommonProfile2 | Self::ImplicitProfile2 => 2,
            Self::CommonProfile4 | Self::ImplicitProfile4 => 4,
            Self::FullyQualified6 => 6,
            Self::FullyQualified8 => 8,
        }
    }
}

/// The Matter Common Profile, under which the predefined cross-organisation tags of
/// §A.2.1 are defined.
pub const COMMON_PROFILE: u16 = 0x0000;

/// An element's tag (Core §A.2).
///
/// A tag is *optional*: an element without one is anonymous. The rest identify the element
/// either within its containing structure (context-specific) or globally
/// (profile-specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tag {
    /// No tag — §A.2.3. The only form allowed for array members and for the outermost
    /// element of an encoding.
    Anonymous,
    /// A context-specific tag: one octet, meaningful only inside its containing structure
    /// or list (§A.2.2).
    Context(u8),
    /// A tag in the Matter Common Profile (§A.8.3).
    Common(u32),
    /// A profile-specific tag whose vendor and profile come from the protocol context the
    /// encoding travels in (§A.8.2).
    Implicit(u32),
    /// A fully-qualified profile-specific tag (§A.8.1).
    FullyQualified {
        /// The 16-bit Vendor ID.
        vendor: u16,
        /// The 16-bit profile number.
        profile: u16,
        /// The tag number: 16-bit on the wire when below 65536, else 32-bit.
        number: u32,
    },
}

impl Tag {
    /// Whether this is [`Tag::Anonymous`].
    #[must_use]
    pub const fn is_anonymous(self) -> bool {
        matches!(self, Self::Anonymous)
    }

    /// The context-specific tag number, if this is one.
    #[must_use]
    pub const fn context(self) -> Option<u8> {
        match self {
            Self::Context(n) => Some(n),
            _ => None,
        }
    }

    /// The tag control bits this tag encodes as, given the width its number needs.
    const fn control(self) -> TagControl {
        match self {
            Self::Anonymous => TagControl::Anonymous,
            Self::Context(_) => TagControl::ContextSpecific,
            Self::Common(n) => {
                if n < 0x1_0000 {
                    TagControl::CommonProfile2
                } else {
                    TagControl::CommonProfile4
                }
            }
            Self::Implicit(n) => {
                if n < 0x1_0000 {
                    TagControl::ImplicitProfile2
                } else {
                    TagControl::ImplicitProfile4
                }
            }
            Self::FullyQualified { number, .. } => {
                if number < 0x1_0000 {
                    TagControl::FullyQualified6
                } else {
                    TagControl::FullyQualified8
                }
            }
        }
    }

    /// How many octets this tag occupies on the wire.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        self.control().octets()
    }

    /// The top 3 bits of the control octet for this tag.
    pub(crate) const fn control_bits(self) -> u8 {
        (self.control() as u8) << 5
    }

    /// Writes the tag octets into `out`, little-endian, returning how many were written.
    ///
    /// `out` must be at least [`Tag::encoded_len`] long.
    pub(crate) fn encode(self, out: &mut [u8]) -> Result<usize> {
        let n = self.encoded_len();
        let Some(dst) = out.get_mut(..n) else {
            bail!(BufferTooSmall)
        };
        match self {
            Self::Anonymous => {}
            Self::Context(t) => {
                let Some(b) = dst.first_mut() else {
                    bail!(BufferTooSmall)
                };
                *b = t;
            }
            Self::Common(number) | Self::Implicit(number) => {
                write_le(dst, u64::from(number), n)?;
            }
            Self::FullyQualified {
                vendor,
                profile,
                number,
            } => {
                let Some(head) = dst.get_mut(..4) else {
                    bail!(BufferTooSmall)
                };
                write_le(head, u64::from(vendor), 2)?;
                let Some(prof) = head.get_mut(2..4) else {
                    bail!(BufferTooSmall)
                };
                write_le(prof, u64::from(profile), 2)?;
                let Some(num) = dst.get_mut(4..) else {
                    bail!(BufferTooSmall)
                };
                // 6-octet form carries 2 tag octets, 8-octet form carries 4.
                write_le(num, u64::from(number), n.saturating_sub(4))?;
            }
        }
        Ok(n)
    }

    /// Reads a tag of the form named by `control_bits` from the front of `buf`.
    ///
    /// Returns the tag and how many octets it consumed.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Appendix A's fully-qualified tag takes vendor and profile from two-octet fields"
    )]
    pub(crate) fn decode(control_bits: u8, buf: &[u8]) -> Result<(Self, usize)> {
        let control = TagControl::from_bits(control_bits);
        let n = control.octets();
        let Some(src) = buf.get(..n) else {
            bail!(TlvTruncated)
        };
        let tag = match control {
            TagControl::Anonymous => Self::Anonymous,
            TagControl::ContextSpecific => {
                let Some(&b) = src.first() else {
                    bail!(TlvTruncated)
                };
                Self::Context(b)
            }
            TagControl::CommonProfile2 | TagControl::CommonProfile4 => {
                Self::Common(read_le_u32(src)?)
            }
            TagControl::ImplicitProfile2 | TagControl::ImplicitProfile4 => {
                Self::Implicit(read_le_u32(src)?)
            }
            TagControl::FullyQualified6 | TagControl::FullyQualified8 => {
                let Some(vendor) = src.get(..2) else {
                    bail!(TlvTruncated)
                };
                let Some(profile) = src.get(2..4) else {
                    bail!(TlvTruncated)
                };
                let Some(number) = src.get(4..) else {
                    bail!(TlvTruncated)
                };
                Self::FullyQualified {
                    vendor: read_le_u32(vendor)? as u16,
                    profile: read_le_u32(profile)? as u16,
                    number: read_le_u32(number)?,
                }
            }
        };
        Ok((tag, n))
    }

    /// Orders two tags by the canonical rules of §A.2.4, which a signature over a
    /// structure depends on.
    ///
    /// The rules are stated in terms of Vendor ID and profile number, so
    /// [`Tag::Implicit`] — whose vendor and profile come from the protocol context — has
    /// no defined place among fully-qualified tags. It is ordered after
    /// [`Tag::Common`] and before [`Tag::FullyQualified`] here; a caller that mixes
    /// implicit tags with fully-qualified ones in one container and then signs it must
    /// resolve the implicit ones to their profile first.
    #[must_use]
    pub fn canonical_cmp(self, other: Self) -> core::cmp::Ordering {
        fn key(t: Tag) -> (u8, u16, u16, u32) {
            match t {
                // "Anonymous tags SHALL be ordered before all other tags."
                Tag::Anonymous => (0, 0, 0, 0),
                // "Context-specific tags SHALL be ordered before profile-specific tags."
                Tag::Context(n) => (1, 0, 0, u32::from(n)),
                Tag::Common(n) => (2, COMMON_PROFILE, 0, n),
                Tag::Implicit(n) => (3, 0, 0, n),
                Tag::FullyQualified {
                    vendor,
                    profile,
                    number,
                } => (4, vendor, profile, number),
            }
        }
        key(self).cmp(&key(other))
    }
}

/// Writes the low `n` octets of `value`, little-endian.
pub(crate) fn write_le(out: &mut [u8], value: u64, n: usize) -> Result<()> {
    let Some(dst) = out.get_mut(..n) else {
        bail!(BufferTooSmall)
    };
    let bytes = value.to_le_bytes();
    for (i, slot) in dst.iter_mut().enumerate() {
        // `i < n <= 8` and `bytes` is 8 long, so this index is in range.
        let Some(&b) = bytes.get(i) else {
            bail!(BufferTooSmall)
        };
        *slot = b;
    }
    Ok(())
}

/// Reads up to 8 little-endian octets as a `u64`.
pub(crate) fn read_le_u64(src: &[u8]) -> Result<u64> {
    if src.len() > 8 {
        bail!(TlvOutOfRange)
    }
    let mut out = 0u64;
    for (i, &b) in src.iter().enumerate() {
        // `i < 8`, so the shift is in range.
        let shift = u32::try_from(i)
            .ok()
            .and_then(|i| i.checked_mul(8))
            .ok_or(Error::new(ErrorCode::TlvOutOfRange))?;
        out |= u64::from(b) << shift;
    }
    Ok(out)
}

fn read_le_u32(src: &[u8]) -> Result<u32> {
    u32::try_from(read_le_u64(src)?).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

/// Sign-extends the `n`-octet little-endian two's-complement integer in `src`.
#[expect(
    clippy::cast_possible_wrap,
    reason = "a two's-complement reinterpretation, which is what Appendix A's signed integers are"
)]
pub(crate) fn read_le_i64(src: &[u8]) -> Result<i64> {
    let raw = read_le_u64(src)?;
    let bits = u32::try_from(src.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(Error::new(ErrorCode::TlvOutOfRange))?;
    if bits == 0 || bits >= 64 {
        // A zero-width integer does not exist in TLV, and a full-width one needs no
        // extension.
        return Ok(raw as i64);
    }
    let shift = 64u32.saturating_sub(bits);
    // Shift left then arithmetic-shift right to replicate the sign bit.
    Ok(((raw << shift) as i64) >> shift)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn element_type_round_trips_through_bits() {
        for raw in 0u8..=0x18 {
            let Ok(t) = ElementType::from_bits(raw) else {
                continue;
            };
            assert_eq!(t.bits(), raw, "type {t:?} from 0x{raw:02x}");
        }
    }

    #[test]
    fn reserved_element_types_are_refused() {
        for raw in 0x19u8..=0x1F {
            assert_eq!(
                ElementType::from_bits(raw).unwrap_err().code(),
                ErrorCode::TlvInvalidControl
            );
        }
    }

    #[test]
    fn tag_widths_follow_a8() {
        assert_eq!(Tag::Anonymous.encoded_len(), 0);
        assert_eq!(Tag::Context(1).encoded_len(), 1);
        assert_eq!(Tag::Common(1).encoded_len(), 2);
        assert_eq!(Tag::Common(100_000).encoded_len(), 4);
        assert_eq!(Tag::Implicit(1).encoded_len(), 2);
        assert_eq!(Tag::Implicit(0x1_0000).encoded_len(), 4);
        assert_eq!(
            Tag::FullyQualified {
                vendor: 0xFFF1,
                profile: 0xDEED,
                number: 1
            }
            .encoded_len(),
            6
        );
        assert_eq!(
            Tag::FullyQualified {
                vendor: 0xFFF1,
                profile: 0xDEED,
                number: 0xAA55_FEED
            }
            .encoded_len(),
            8
        );
    }

    #[test]
    fn sign_extension() {
        assert_eq!(read_le_i64(&[0xEF]).unwrap(), -17);
        assert_eq!(read_le_i64(&[0x2A]).unwrap(), 42);
        assert_eq!(read_le_i64(&[0xF0, 0x67, 0xFD, 0xFF]).unwrap(), -170_000);
        assert_eq!(
            read_le_i64(&[0x00, 0x90, 0x2F, 0x50, 0x09, 0x00, 0x00, 0x00]).unwrap(),
            40_000_000_000
        );
    }

    #[test]
    fn minimal_widths() {
        assert_eq!(Width::for_unsigned(42), Width::One);
        assert_eq!(Width::for_unsigned(256), Width::Two);
        assert_eq!(Width::for_signed(-17), Width::One);
        assert_eq!(Width::for_signed(-170_000), Width::Four);
        assert_eq!(Width::for_signed(128), Width::Two, "128 needs a sign bit");
        assert_eq!(Width::for_signed(-128), Width::One);
    }

    #[test]
    fn canonical_order_is_a24() {
        let mut tags = [
            Tag::FullyQualified {
                vendor: 1,
                profile: 1,
                number: 1,
            },
            Tag::Context(5),
            Tag::Anonymous,
            Tag::Context(1),
            Tag::FullyQualified {
                vendor: 1,
                profile: 0,
                number: 9,
            },
        ];
        tags.sort_by(|a, b| a.canonical_cmp(*b));
        assert_eq!(tags[0], Tag::Anonymous);
        assert_eq!(tags[1], Tag::Context(1));
        assert_eq!(tags[2], Tag::Context(5));
        // Lower profile number sorts first within the same vendor.
        assert_eq!(
            tags[3],
            Tag::FullyQualified {
                vendor: 1,
                profile: 0,
                number: 9
            }
        );
    }
}
