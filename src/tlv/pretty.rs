//! Printing TLV the way the specification writes it.
//!
//! A hex dump of a failing payload is a puzzle; `{0 = 42, 1 = -17}` is a sentence. This is
//! the difference between reading a capture and decoding one by hand, and it costs no
//! allocation — [`Pretty`] is a `Display` wrapper over the bytes.

use core::fmt::{self, Display, Write as _};

use super::reader::{MAX_DEPTH, TlvReader, Value};
use super::types::{ContainerKind, Tag};

/// Formats a TLV encoding in the notation of Core Appendix A.
///
/// ```
/// use matter_kit::tlv::Pretty;
///
/// let bytes = [0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18];
/// # #[cfg(feature = "std")]
/// assert_eq!(std::format!("{}", Pretty(&bytes)), "{0 = 42, 1 = -17}");
/// ```
///
/// Malformed input does not fail the format call — it prints what it understood and then
/// `<!error>`, because a formatter that refuses to print a broken message is useless
/// exactly when a broken message is what you have.
#[derive(Debug, Clone, Copy)]
pub struct Pretty<'a>(pub &'a [u8]);

/// Formats a TLV **fragment** — one or more members of a container, rather than a complete
/// top-level encoding.
///
/// Which tag forms are legal depends on where an element sits, so a fragment carrying a
/// context-specific tag is valid inside a structure and invalid on its own.
/// [`Pretty`] reads at the top level and would print `<!error>` for exactly the bytes that
/// are correct; this reads them the way they will be read.
///
/// The counterpart of [`TlvReader::new_in`] and
/// [`TlvWriter::new_in`](super::TlvWriter::new_in).
///
/// ```
/// use matter_kit::tlv::{ContainerKind, PrettyIn};
///
/// // An attribute value destined for an AttributeDataIB's context-2 slot.
/// let bytes = [0x24, 0x02, 0x2A];
/// # #[cfg(feature = "std")]
/// assert_eq!(
///     std::format!("{}", PrettyIn(&bytes, ContainerKind::Structure)),
///     "2 = 42U"
/// );
/// ```
#[derive(Debug, Clone, Copy)]
pub struct PrettyIn<'a>(pub &'a [u8], pub ContainerKind);

impl Display for Pretty<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_tlv(f, TlvReader::new(self.0))
    }
}

impl Display for PrettyIn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_tlv(f, TlvReader::new_in(self.0, self.1))
    }
}

/// The shared body of both formatters.
fn write_tlv(f: &mut fmt::Formatter<'_>, reader: TlvReader<'_>) -> fmt::Result {
    {
        let mut r = reader;
        // Per level: which container is open there, and whether it has printed a member.
        let mut open = [ContainerKind::Structure; MAX_DEPTH];
        let mut empty = [true; MAX_DEPTH];

        loop {
            // The level this element belongs to, read before the cursor moves.
            let level = r.depth();

            let element = match r.next_element() {
                Ok(None) => return Ok(()),
                Ok(Some(e)) => e,
                Err(_) => return f.write_str("<!error>"),
            };

            if matches!(element.value, Value::EndOfContainer) {
                // `depth()` has already been popped, so it now names the closing level.
                let closing = r.depth();
                let kind = open
                    .get(closing)
                    .copied()
                    .unwrap_or(ContainerKind::Structure);
                return_brace(f, kind)?;
                continue;
            }

            let level = level.min(MAX_DEPTH.saturating_sub(1));
            if let Some(slot) = empty.get_mut(level) {
                if !*slot {
                    f.write_str(", ")?;
                }
                *slot = false;
            }

            write_tag(f, element.tag)?;
            write_value(f, &element.value)?;

            if let Value::Container(kind) = element.value {
                // The cursor is now inside it; record what to close and reset its state.
                let inner = r.depth().saturating_sub(1).min(MAX_DEPTH.saturating_sub(1));
                if let Some(slot) = open.get_mut(inner) {
                    *slot = kind;
                }
                if let Some(slot) = empty.get_mut(r.depth().min(MAX_DEPTH.saturating_sub(1))) {
                    *slot = true;
                }
            }
        }
    }
}

fn return_brace(f: &mut fmt::Formatter<'_>, kind: ContainerKind) -> fmt::Result {
    f.write_char(match kind {
        ContainerKind::Structure => '}',
        ContainerKind::Array | ContainerKind::List => ']',
    })
}

fn write_tag(f: &mut fmt::Formatter<'_>, tag: Tag) -> fmt::Result {
    match tag {
        Tag::Anonymous => Ok(()),
        Tag::Context(n) => write!(f, "{n} = "),
        Tag::Common(n) => write!(f, "Matter::{n} = "),
        Tag::Implicit(n) => write!(f, "implicit:{n} = "),
        Tag::FullyQualified {
            vendor,
            profile,
            number,
        } => write!(f, "{vendor}::{profile}:{number} = "),
    }
}

fn write_value(f: &mut fmt::Formatter<'_>, value: &Value<'_>) -> fmt::Result {
    match value {
        Value::Signed(v) => write!(f, "{v}"),
        Value::Unsigned(v) => write!(f, "{v}U"),
        Value::Bool(v) => write!(f, "{v}"),
        Value::Float(v) => write!(f, "{v}"),
        Value::Double(v) => write!(f, "{v}"),
        Value::Utf8(v) => write!(f, "{v:?}"),
        Value::Octets(v) => {
            f.write_str("0x")?;
            for b in *v {
                write!(f, "{b:02x}")?;
            }
            Ok(())
        }
        Value::Null => f.write_str("null"),
        Value::Container(ContainerKind::Structure) => f.write_char('{'),
        Value::Container(ContainerKind::Array | ContainerKind::List) => f.write_char('['),
        Value::EndOfContainer => Ok(()),
    }
}

#[cfg(all(test, feature = "std"))]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn prints_the_spec_examples() {
        assert_eq!(
            std::format!(
                "{}",
                Pretty(&[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18])
            ),
            "{0 = 42, 1 = -17}"
        );
        assert_eq!(std::format!("{}", Pretty(&[0x04, 0x2a])), "42U");
        assert_eq!(std::format!("{}", Pretty(&[0x14])), "null");
        assert_eq!(
            std::format!(
                "{}",
                Pretty(&[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21])
            ),
            "\"Hello!\""
        );
    }

    #[test]
    fn containers_close_with_the_brace_they_opened() {
        assert_eq!(std::format!("{}", Pretty(&[0x15, 0x18])), "{}");
        assert_eq!(std::format!("{}", Pretty(&[0x16, 0x18])), "[]");
        assert_eq!(std::format!("{}", Pretty(&[0x17, 0x18])), "[]");
        // [0, 1, 2, 3, 4]
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
    fn nesting_closes_in_the_right_order() {
        // { 0 = [ {} ] }
        let buf = [0x15, 0x36, 0x00, 0x15, 0x18, 0x18, 0x18];
        assert_eq!(std::format!("{}", Pretty(&buf)), "{0 = [{}]}");
    }

    #[test]
    fn a_broken_encoding_prints_what_it_understood() {
        let s = std::format!("{}", Pretty(&[0x15, 0x24, 0x00, 0x2a, 0x0c, 0x06, 0x48]));
        assert!(s.contains("<!error>"), "{s}");
        assert!(s.starts_with('{'), "{s}");
    }
}
