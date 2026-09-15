//! Turning Rust values into TLV elements, and back (Core Appendix A).
//!
//! [`TlvWriter`] and [`TlvReader`] are the wire format. This is the layer above: two traits
//! that say how one *type* is written and read, so a structure's fields compose rather than
//! each being spelled out at every call site.
//!
//! It exists because the cluster library is generated. A hand-written cluster can afford to
//! write its own encode and decode — `binding::Target` does — but 193 structures and 434
//! command payloads cannot each be bespoke, and a nested structure or a `list[T]` field has to
//! reach the same code the top level does.
//!
//! # Three things Matter distinguishes that Rust would not
//!
//! * **absent** — the field is not in the structure at all. `Option<T>` on the Rust side, and
//!   decided by the *container*, which is why there is no blanket `FromTlv for Option<T>`:
//!   absence is not something an element can be.
//! * **null** — the field is present and its value is TLV null (§7.12's `X` quality).
//!   [`Nullable<T>`], so `Option<Nullable<T>>` says "may be missing, and may be null" without
//!   the two collapsing into one `None` that means neither.
//! * **empty** — a list that is present with no members, which is different again from absent.
//!
//! # Lists stay on the wire
//!
//! [`TlvList`] holds the encoded members and decodes them one at a time. A device cannot
//! allocate, and a fixed-capacity array sized for the largest list any cluster might carry
//! would cost more than the whole rest of the structure — so a list is read where it lies, and
//! a caller that needs one element does not pay for the other two hundred.

use core::marker::PhantomData;

use super::reader::{Element, TlvReader, Value};
use super::types::{ContainerKind, Tag};
use super::writer::TlvWriter;
use crate::error::{Error, ErrorCode, Result, bail};

/// A value that can be written as one TLV element.
pub trait ToTlv {
    /// Writes it under `tag`.
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()>;
}

/// A value that can be read from one TLV element.
///
/// `element` is what [`TlvReader::next_element`] just produced — its control octet and tag are
/// already consumed, so an implementation reads the *value*, and for a container reads its
/// members and the end-of-container that closes it.
pub trait FromTlv<'a>: Sized {
    /// Reads it.
    fn from_tlv(reader: &mut TlvReader<'a>, element: &Element<'a>) -> Result<Self>;
}

// --- Primitives ---------------------------------------------------------------------------

impl ToTlv for bool {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.bool(tag, *self)
    }
}

impl FromTlv<'_> for bool {
    fn from_tlv(_reader: &mut TlvReader<'_>, element: &Element<'_>) -> Result<Self> {
        element.bool()
    }
}

/// The unsigned types, which all narrow from TLV's `u64`.
///
/// A value too wide for the field is [`ErrorCode::TlvOutOfRange`] rather than a truncation:
/// §7.19.2 answers an out-of-range value `CONSTRAINT_ERROR`, and silently keeping the low
/// octets would turn a rejected command into an accepted one with different arguments.
macro_rules! unsigned {
    ($($ty:ty),+) => {$(
        impl ToTlv for $ty {
            fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
                w.unsigned(tag, u64::from(*self))
            }
        }

        impl FromTlv<'_> for $ty {
            fn from_tlv(_reader: &mut TlvReader<'_>, element: &Element<'_>) -> Result<Self> {
                Self::try_from(element.unsigned()?)
                    .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
            }
        }
    )+};
}
unsigned!(u8, u16, u32);

impl ToTlv for u64 {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.unsigned(tag, *self)
    }
}

impl FromTlv<'_> for u64 {
    fn from_tlv(_reader: &mut TlvReader<'_>, element: &Element<'_>) -> Result<Self> {
        element.unsigned()
    }
}

macro_rules! signed {
    ($($ty:ty),+) => {$(
        impl ToTlv for $ty {
            fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
                w.signed(tag, i64::from(*self))
            }
        }

        impl FromTlv<'_> for $ty {
            fn from_tlv(_reader: &mut TlvReader<'_>, element: &Element<'_>) -> Result<Self> {
                Self::try_from(element.signed()?)
                    .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
            }
        }
    )+};
}
signed!(i8, i16, i32);

impl ToTlv for i64 {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.signed(tag, *self)
    }
}

impl FromTlv<'_> for i64 {
    fn from_tlv(_reader: &mut TlvReader<'_>, element: &Element<'_>) -> Result<Self> {
        element.signed()
    }
}

impl ToTlv for f32 {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.float(tag, *self)
    }
}

impl FromTlv<'_> for f32 {
    fn from_tlv(_reader: &mut TlvReader<'_>, element: &Element<'_>) -> Result<Self> {
        match element.value {
            Value::Float(v) => Ok(v),
            // A `single` field carrying a double is not a rounding decision this layer may
            // make: §A.7.2 lets an encoder choose the narrower form, never the wider.
            _ => Err(Error::new(ErrorCode::TlvWrongType)),
        }
    }
}

impl ToTlv for f64 {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.double(tag, *self)
    }
}

impl FromTlv<'_> for f64 {
    fn from_tlv(_reader: &mut TlvReader<'_>, element: &Element<'_>) -> Result<Self> {
        match element.value {
            Value::Double(v) => Ok(v),
            // Widening is lossless and §A.7.2 permits the narrower encoding, so a `double`
            // field carrying a `single` is a conforming encoder being economical.
            Value::Float(v) => Ok(f64::from(v)),
            _ => Err(Error::new(ErrorCode::TlvWrongType)),
        }
    }
}

impl ToTlv for &str {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.utf8(tag, self)
    }
}

impl<'a> FromTlv<'a> for &'a str {
    fn from_tlv(_reader: &mut TlvReader<'a>, element: &Element<'a>) -> Result<Self> {
        element.utf8()
    }
}

impl ToTlv for &[u8] {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.octets(tag, self)
    }
}

impl<'a> FromTlv<'a> for &'a [u8] {
    fn from_tlv(_reader: &mut TlvReader<'a>, element: &Element<'a>) -> Result<Self> {
        element.octets()
    }
}

// --- The identifier newtypes ----------------------------------------------------------------

/// The crate's identifier types, so a field typed `node-id` cannot be handed a `group-id`.
///
/// The specification distinguishes them and so does this: they are all integers on the wire,
/// and the compiler is the only thing that will notice two of them swapped.
macro_rules! newtype {
    ($($ty:path => $inner:ty),+ $(,)?) => {$(
        impl ToTlv for $ty {
            fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
                self.0.to_tlv(w, tag)
            }
        }

        impl<'a> FromTlv<'a> for $ty {
            fn from_tlv(reader: &mut TlvReader<'a>, element: &Element<'a>) -> Result<Self> {
                <$inner as FromTlv<'a>>::from_tlv(reader, element).map(Self)
            }
        }
    )+};
}
newtype!(
    crate::msg::NodeId => u64,
    crate::msg::GroupId => u16,
    crate::msg::VendorId => u16,
    crate::msg::FabricIndex => u8,
);

// --- Null ------------------------------------------------------------------------------------

/// A field that may be TLV null — §7.12's `X` quality.
///
/// Distinct from `Option<T>` on purpose. `Option<T>` is a field that may be *absent*, and a
/// field can be both: `Option<Nullable<T>>` says "may be missing, and if present may be null",
/// which is three states the specification really does distinguish. Collapsing them loses the
/// difference between "the device does not implement this" and "the device implements it and
/// has no value" — which is exactly the difference between §11.12.5.6's null
/// `OffPremiseServicesReachableIPv4` and its absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Nullable<T>(pub Option<T>);

impl<T> Nullable<T> {
    /// A value.
    pub const fn some(value: T) -> Self {
        Self(Some(value))
    }

    /// TLV null.
    pub const fn null() -> Self {
        Self(None)
    }

    /// Whether it is null.
    pub const fn is_null(&self) -> bool {
        self.0.is_none()
    }
}

impl<T: ToTlv> ToTlv for Nullable<T> {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        match &self.0 {
            Some(value) => value.to_tlv(w, tag),
            None => w.null(tag),
        }
    }
}

impl<'a, T: FromTlv<'a>> FromTlv<'a> for Nullable<T> {
    fn from_tlv(reader: &mut TlvReader<'a>, element: &Element<'a>) -> Result<Self> {
        if element.value.is_null() {
            return Ok(Self(None));
        }
        T::from_tlv(reader, element).map(Self::some)
    }
}

// --- Lists -----------------------------------------------------------------------------------

/// A `list[T]` field, read where it lies.
///
/// Holds the encoded *members* — everything between the array's opening element and its
/// end-of-container — and decodes them on demand. A device cannot allocate, and a
/// fixed-capacity array sized for the largest list any cluster might carry would cost more
/// than the whole rest of the structure; a caller that wants one entry should not pay for the
/// other two hundred.
///
/// The trade is that a member's own errors surface during iteration rather than at decode, so
/// [`TlvList::iter`] yields `Result`. That is honest: nothing has looked at member 47 yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvList<'a, T> {
    members: &'a [u8],
    _entry: PhantomData<fn() -> T>,
}

impl<T> Default for TlvList<'_, T> {
    /// An empty list, which is a different thing from an absent one.
    fn default() -> Self {
        Self {
            members: &[],
            _entry: PhantomData,
        }
    }
}

impl<'a, T> TlvList<'a, T> {
    /// A list over already-encoded members.
    #[must_use]
    pub const fn from_members(members: &'a [u8]) -> Self {
        Self {
            members,
            _entry: PhantomData,
        }
    }

    /// The encoded members, for a caller forwarding the list without reading it.
    #[must_use]
    pub const fn members(&self) -> &'a [u8] {
        self.members
    }

    /// Whether the list has no members.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

impl<'a, T: FromTlv<'a>> TlvList<'a, T> {
    /// The entries, decoded one at a time.
    pub fn iter(&self) -> impl Iterator<Item = Result<T>> + 'a {
        let mut reader = TlvReader::new_members(self.members, ContainerKind::Array);
        core::iter::from_fn(move || match reader.next_element() {
            Ok(None) => None,
            Ok(Some(element)) if element.value == Value::EndOfContainer => None,
            Ok(Some(element)) => Some(T::from_tlv(&mut reader, &element)),
            Err(error) => Some(Err(error)),
        })
    }

    /// How many entries it has, by walking it.
    ///
    /// Not `len`, because it is not free: the members are on the wire and counting them means
    /// decoding their headers. A caller in a loop should iterate rather than ask twice.
    pub fn count(&self) -> Result<usize> {
        let mut n = 0usize;
        for entry in self.iter() {
            entry?;
            n = n.saturating_add(1);
        }
        Ok(n)
    }
}

impl<T> ToTlv for TlvList<'_, T> {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_array(tag)?;
        // Member by member through `raw_element`, which re-validates each against the array
        // it is going into. Copying the span wholesale would be faster and would also let a
        // list decoded in one context be spliced into another where its tags are illegal.
        let mut reader = TlvReader::new_members(self.members, ContainerKind::Array);
        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                break;
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            reader.skip_value(&element)?;
            w.raw_element(reader.slice_from(start)?)?;
        }
        w.end_container()
    }
}

impl<'a, T> FromTlv<'a> for TlvList<'a, T> {
    fn from_tlv(reader: &mut TlvReader<'a>, element: &Element<'a>) -> Result<Self> {
        if element.value.container() != Some(ContainerKind::Array) {
            bail!(TlvWrongType)
        }
        // The opening element is already consumed, so the members start here. Walking to the
        // end-of-container rather than skipping to it is what makes the span exact: the
        // terminator must be *outside* it, or a reader over the members would meet an
        // end-of-container for a container it was never told it is inside.
        let start = reader.position();
        let end = loop {
            let before = reader.position();
            let Some(member) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if member.value == Value::EndOfContainer {
                break before;
            }
            reader.skip_value(&member)?;
        };
        let members = reader
            .slice_from(start)?
            .get(..end.saturating_sub(start))
            .ok_or(Error::new(ErrorCode::TlvTruncated))?;
        Ok(Self::from_members(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<'a, T>(value: &T, buf: &'a mut [u8]) -> &'a [u8]
    where
        T: ToTlv,
    {
        let mut w = TlvWriter::new(buf);
        value.to_tlv(&mut w, Tag::Anonymous).expect("encode");
        w.finish().expect("finish")
    }

    fn decode<'a, T: FromTlv<'a>>(bytes: &'a [u8]) -> Result<T> {
        let mut reader = TlvReader::new(bytes);
        let element = reader.next_element()?.expect("an element");
        T::from_tlv(&mut reader, &element)
    }

    #[test]
    fn the_primitives_round_trip() {
        let mut buf = [0u8; 64];
        assert!(decode::<bool>(round_trip(&true, &mut buf)).expect("bool"));
        assert_eq!(
            decode::<u16>(round_trip(&1234u16, &mut buf)).expect("u16"),
            1234
        );
        assert_eq!(
            decode::<i32>(round_trip(&-7i32, &mut buf)).expect("i32"),
            -7
        );
        assert_eq!(
            decode::<u64>(round_trip(&u64::MAX, &mut buf)).expect("u64"),
            u64::MAX
        );
        let bytes = round_trip(&"hello", &mut buf);
        assert_eq!(decode::<&str>(bytes).expect("str"), "hello");
        let mut buf2 = [0u8; 64];
        let bytes = round_trip(&&[1u8, 2, 3][..], &mut buf2);
        assert_eq!(decode::<&[u8]>(bytes).expect("octets"), &[1, 2, 3]);
    }

    #[test]
    fn a_value_too_wide_for_its_field_is_refused_rather_than_truncated() {
        // §7.19.2 answers an out-of-range value `CONSTRAINT_ERROR`. Keeping the low octets
        // would turn a rejected command into an accepted one with different arguments — a
        // `MoveToLevel(300)` becoming `MoveToLevel(44)`.
        let mut buf = [0u8; 32];
        let wide = round_trip(&300u32, &mut buf);
        assert_eq!(
            decode::<u8>(wide).map_err(|e| e.code()),
            Err(ErrorCode::TlvOutOfRange)
        );
        assert_eq!(decode::<u16>(wide).expect("fits"), 300);
    }

    #[test]
    fn null_and_absent_are_different_things() {
        // Three states, and a type that can only say two of them loses the one that matters:
        // "the device implements this and has no value" versus "the device does not implement
        // it" (§11.12.5.6's `OffPremiseServicesReachableIPv4` is exactly this).
        let mut buf = [0u8; 32];
        let bytes = round_trip(&Nullable::<u8>::null(), &mut buf);
        let decoded: Nullable<u8> = decode(bytes).expect("null");
        assert!(decoded.is_null());

        let bytes = round_trip(&Nullable::some(9u8), &mut buf);
        assert_eq!(
            decode::<Nullable<u8>>(bytes).expect("value"),
            Nullable::some(9)
        );

        // `Option<Nullable<T>>` is the full three-way answer; absence is the container's to
        // report, which is why there is no `FromTlv for Option<T>`.
        let present_and_null: Option<Nullable<u8>> = Some(Nullable::null());
        assert!(present_and_null.is_some_and(|n| n.is_null()));
    }

    #[test]
    fn a_list_is_read_where_it_lies() {
        let mut buf = [0u8; 128];
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).expect("array");
        for value in 1..=5u16 {
            w.unsigned(Tag::Anonymous, u64::from(value))
                .expect("member");
        }
        w.end_container().expect("end");
        let bytes = w.finish().expect("finish");

        let list: TlvList<'_, u16> = decode(bytes).expect("list");
        assert_eq!(list.count().expect("count"), 5);
        let values: Result<heapless::Vec<u16, 8>> = list.iter().collect();
        assert_eq!(values.expect("members").as_slice(), &[1, 2, 3, 4, 5]);

        // An empty list is a list, and not the same as an absent one.
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).expect("array");
        w.end_container().expect("end");
        let bytes = w.finish().expect("finish");
        let empty: TlvList<'_, u16> = decode(bytes).expect("list");
        assert!(empty.is_empty());
        assert_eq!(empty.count().expect("count"), 0);
    }

    #[test]
    fn a_decoded_list_re_encodes_to_the_same_bytes() {
        // What makes a list forwardable: a cluster that reads one and writes it back must
        // produce what it was given, or a bridge changes the data it relays.
        let mut buf = [0u8; 128];
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).expect("array");
        for value in [7u32, 70, 700, 7000] {
            w.unsigned(Tag::Anonymous, u64::from(value))
                .expect("member");
        }
        w.end_container().expect("end");
        let original = w.finish().expect("finish").to_vec();

        let list: TlvList<'_, u32> = decode(&original).expect("list");
        let mut out = [0u8; 128];
        let again = round_trip(&list, &mut out);
        assert_eq!(again, original.as_slice());
    }

    #[test]
    fn a_list_of_the_wrong_container_kind_is_refused() {
        // A structure where an array belongs is not a list with different punctuation: its
        // members carry tags, and reading them as anonymous entries would silently succeed
        // for the first one and then drift.
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).expect("structure");
        w.unsigned(Tag::Context(0), 1).expect("member");
        w.end_container().expect("end");
        let bytes = w.finish().expect("finish");
        assert_eq!(
            decode::<TlvList<'_, u16>>(bytes).map_err(|e| e.code()),
            Err(ErrorCode::TlvWrongType)
        );
    }

    #[test]
    fn a_member_that_does_not_decode_surfaces_at_that_member() {
        // The trade a lazy list makes, stated: nothing has looked at member three yet, so its
        // error arrives when something does rather than at decode time.
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).expect("array");
        w.unsigned(Tag::Anonymous, 1).expect("member");
        w.utf8(Tag::Anonymous, "not a number").expect("member");
        w.end_container().expect("end");
        let bytes = w.finish().expect("finish");

        let list: TlvList<'_, u16> = decode(bytes).expect("the list itself is well formed");
        let mut entries = list.iter();
        assert_eq!(entries.next().expect("first").expect("a number"), 1);
        assert!(entries.next().expect("second").is_err());
    }
}
