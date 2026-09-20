//! Distinguished names in a Matter certificate (Core §6.1.1, §6.5.6).
//!
//! An X.509 DN is a sequence of Relative Distinguished Names, each of which may in
//! principle hold a *set* of attributes. Matter narrows that: "The RDN in a Matter
//! certificate SHALL be always a single DN attribute." So a DN here is a list of
//! attributes, in order, and two DNs match when they have the same attributes in the same
//! order.
//!
//! # The `+0x80` marker
//!
//! A Matter certificate has to reproduce the DER of the X.509 certificate it stands for,
//! byte for byte, or the signature will not verify — §6.5.2: "validating the signature in a
//! Matter certificate entails its logical conversion to the corresponding X.509
//! certificate". DER distinguishes `UTF8String` from `PrintableString`, so the TLV has to
//! carry that distinction too. It does it by logically OR-ing the tag with `0x80`: tag 1 is
//! `common-name` as a `UTF8String`, tag 129 is the same attribute as a `PrintableString`.
//!
//! [`DnAttribute`] keeps that as a separate [`DnAttribute::printable_string`] flag rather
//! than as thirty separate variants, so the round-trip is exact without the enum doubling.

use heapless::Vec;

use crate::error::{Error, ErrorCode, Result};
use crate::msg::{CaseAuthenticatedTag, FabricId, NodeId};
use crate::tlv::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

/// "All implementations SHALL accept, parse, and handle Matter certificates with up to 5
/// RDNs in a single DN" — and "SHALL reject" more (§6.5.6.3).
pub const MAX_RDNS: usize = 5;

/// "The subject DN MAY encode at most three matter-noc-cat attributes" (§6.5.6.3).
pub const MAX_NOC_CATS: usize = 3;

/// The tag added to a standard attribute whose X.509 form is a `PrintableString`.
const PRINTABLE_STRING_OFFSET: u8 = 0x80;

/// Which attribute type a [`DnAttribute`] carries (§6.5.6.1, Tables 85, 87 and 88).
///
/// The discriminants are the TLV context tags, so the encoding is the value itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum DnAttributeKind {
    /// `common-name` — X.520 `commonName`.
    CommonName = 1,
    /// `surname`.
    Surname = 2,
    /// `serial-num` — the DN attribute, not the certificate's serial number.
    SerialNum = 3,
    /// `country-name`.
    CountryName = 4,
    /// `locality-name`.
    LocalityName = 5,
    /// `state-or-province-name`.
    StateOrProvinceName = 6,
    /// `org-name`.
    OrgName = 7,
    /// `org-unit-name`.
    OrgUnitName = 8,
    /// `title`.
    Title = 9,
    /// `name`.
    Name = 10,
    /// `given-name`.
    GivenName = 11,
    /// `initials`.
    Initials = 12,
    /// `gen-qualifier`.
    GenQualifier = 13,
    /// `dn-qualifier`.
    DnQualifier = 14,
    /// `pseudonym`.
    Pseudonym = 15,
    /// `domain-component` — an `IA5String` in X.509, so it has no `-ps` form.
    DomainComponent = 16,
    /// `matter-node-id` — "Certifies the identity of a Matter Node Operational Certificate".
    MatterNodeId = 17,
    /// `matter-firmware-signing-id`.
    MatterFirmwareSigningId = 18,
    /// `matter-icac-id`.
    MatterIcacId = 19,
    /// `matter-rcac-id`.
    MatterRcacId = 20,
    /// `matter-fabric-id`.
    MatterFabricId = 21,
    /// `matter-noc-cat` — a [`CaseAuthenticatedTag`], 32 bits rather than 64.
    MatterNocCat = 22,
    /// `matter-vvs-id` — "Certifies the identity of a Vendor Verification Signer".
    MatterVvsId = 23,
}

impl DnAttributeKind {
    /// The kind a base tag names, or `None` if the tag is not one of Tables 85, 87 or 88.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::CommonName,
            2 => Self::Surname,
            3 => Self::SerialNum,
            4 => Self::CountryName,
            5 => Self::LocalityName,
            6 => Self::StateOrProvinceName,
            7 => Self::OrgName,
            8 => Self::OrgUnitName,
            9 => Self::Title,
            10 => Self::Name,
            11 => Self::GivenName,
            12 => Self::Initials,
            13 => Self::GenQualifier,
            14 => Self::DnQualifier,
            15 => Self::Pseudonym,
            16 => Self::DomainComponent,
            17 => Self::MatterNodeId,
            18 => Self::MatterFirmwareSigningId,
            19 => Self::MatterIcacId,
            20 => Self::MatterRcacId,
            21 => Self::MatterFabricId,
            22 => Self::MatterNocCat,
            23 => Self::MatterVvsId,
            _ => return None,
        })
    }

    /// The base TLV context tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Whether the value is a string. The Matter-specific types, tags 17 through 23, are
    /// "normatively defined as scalars" and encode as unsigned integers.
    #[must_use]
    pub const fn is_string(self) -> bool {
        (self as u8) <= 16
    }

    /// Whether this is one of the `1.3.6.1.4.1.37244` private-arc types.
    #[must_use]
    pub const fn is_matter_specific(self) -> bool {
        !self.is_string()
    }

    /// Whether a `PrintableString` form — the `+0x80` tag — exists for this type.
    ///
    /// Tables 87 covers tags 1 through 15. `domain-component` is an `IA5String` and the
    /// Matter-specific types are integers, so neither has one.
    #[must_use]
    pub const fn has_printable_string_form(self) -> bool {
        matches!(self as u8, 1..=15)
    }

    /// How many octets the scalar occupies in its X.509 hexadecimal form's *value*
    /// (Table 85's "Length (octets)"), or `None` for a string type.
    ///
    /// Only `matter-noc-cat` is four; the rest are eight. This is what decides whether the
    /// X.509 string is 8 or 16 characters.
    #[must_use]
    pub const fn scalar_octets(self) -> Option<usize> {
        match self {
            Self::MatterNocCat => Some(4),
            _ if self.is_matter_specific() => Some(8),
            _ => None,
        }
    }
}

/// One attribute of a distinguished name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnAttribute<'a> {
    /// Which attribute type this is.
    pub kind: DnAttributeKind,
    /// Whether the X.509 form encodes the value as a `PrintableString` rather than a
    /// `UTF8String`. Only meaningful when
    /// [`DnAttributeKind::has_printable_string_form`]; always `false` otherwise.
    pub printable_string: bool,
    /// The value.
    pub value: DnValue<'a>,
}

/// The value of a DN attribute: a string, or a Matter-specific scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnValue<'a> {
    /// A string attribute's text, borrowed from the certificate.
    Str(&'a str),
    /// A Matter-specific attribute's scalar.
    Uint(u64),
}

impl<'a> DnAttribute<'a> {
    /// A string attribute in its `UTF8String` form.
    #[must_use]
    pub const fn string(kind: DnAttributeKind, value: &'a str) -> Self {
        Self {
            kind,
            printable_string: false,
            value: DnValue::Str(value),
        }
    }

    /// A string attribute in its `PrintableString` form — the `+0x80` tag.
    #[must_use]
    pub const fn printable(kind: DnAttributeKind, value: &'a str) -> Self {
        Self {
            kind,
            printable_string: true,
            value: DnValue::Str(value),
        }
    }

    /// A Matter-specific scalar attribute.
    #[must_use]
    pub const fn uint(kind: DnAttributeKind, value: u64) -> Self {
        Self {
            kind,
            printable_string: false,
            value: DnValue::Uint(value),
        }
    }

    /// `matter-node-id`.
    #[must_use]
    pub const fn node_id(id: NodeId) -> Self {
        Self::uint(DnAttributeKind::MatterNodeId, id.0)
    }

    /// `matter-fabric-id`.
    #[must_use]
    pub const fn fabric_id(id: FabricId) -> Self {
        Self::uint(DnAttributeKind::MatterFabricId, id.0)
    }

    /// `matter-noc-cat`.
    #[must_use]
    pub const fn noc_cat(cat: CaseAuthenticatedTag) -> Self {
        Self::uint(DnAttributeKind::MatterNocCat, cat.0 as u64)
    }

    /// The TLV context tag this attribute encodes under, `+0x80` included.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        if self.printable_string {
            self.kind.tag().wrapping_add(PRINTABLE_STRING_OFFSET)
        } else {
            self.kind.tag()
        }
    }

    /// The scalar, if this is a Matter-specific attribute.
    #[must_use]
    pub const fn as_uint(&self) -> Option<u64> {
        match self.value {
            DnValue::Uint(v) => Some(v),
            DnValue::Str(_) => None,
        }
    }

    /// The text, if this is a string attribute.
    #[must_use]
    pub const fn as_str(&self) -> Option<&'a str> {
        match self.value {
            DnValue::Str(s) => Some(s),
            DnValue::Uint(_) => None,
        }
    }

    /// Checks the attribute against the rules of §6.1.1 and §6.5.6.1.
    ///
    /// A scalar whose type says four octets must fit in 32 bits, a string type must carry
    /// a string, and the `+0x80` form must only be used where Table 87 defines one.
    pub fn validate(&self) -> Result<()> {
        match (self.kind.is_string(), self.value) {
            (true, DnValue::Str(_)) => {}
            (false, DnValue::Uint(v)) => {
                if self.kind.scalar_octets() == Some(4) && v > u64::from(u32::MAX) {
                    return Err(Error::new(ErrorCode::CertInvalid));
                }
            }
            _ => return Err(Error::new(ErrorCode::CertInvalid)),
        }
        if self.printable_string && !self.kind.has_printable_string_form() {
            return Err(Error::new(ErrorCode::CertInvalid));
        }
        Ok(())
    }

    /// Writes the attribute into an open `issuer` or `subject` list.
    pub fn encode(&self, writer: &mut TlvWriter<'_>) -> Result<()> {
        self.validate()?;
        let tag = Tag::Context(self.tag());
        match self.value {
            DnValue::Str(s) => writer.utf8(tag, s),
            DnValue::Uint(v) => writer.unsigned(tag, v),
        }
    }

    /// Reads one attribute from an element inside a DN list.
    pub fn decode(element: &Element<'a>) -> Result<Self> {
        let Some(raw_tag) = element.tag.context() else {
            return Err(Error::new(ErrorCode::CertInvalid));
        };
        let printable_string = raw_tag >= PRINTABLE_STRING_OFFSET;
        let base = raw_tag.wrapping_sub(if printable_string {
            PRINTABLE_STRING_OFFSET
        } else {
            0
        });
        let Some(kind) = DnAttributeKind::from_tag(base) else {
            return Err(Error::new(ErrorCode::CertInvalid));
        };
        let value = match element.value {
            Value::Utf8(s) => DnValue::Str(s),
            Value::Unsigned(v) => DnValue::Uint(v),
            _ => return Err(Error::new(ErrorCode::CertInvalid)),
        };
        let attribute = Self {
            kind,
            printable_string,
            value,
        };
        attribute.validate()?;
        Ok(attribute)
    }
}

/// A distinguished name: up to [`MAX_RDNS`] attributes, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DistinguishedName<'a> {
    attributes: Vec<DnAttribute<'a>, MAX_RDNS>,
}

impl<'a> DistinguishedName<'a> {
    /// An empty name. A certificate with one is invalid — the schema says `length 1..` —
    /// but building one up starts here.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attributes: Vec::new(),
        }
    }

    /// Appends an attribute.
    ///
    /// Returns [`ErrorCode::CertInvalid`] past [`MAX_RDNS`], because §6.5.6.3 makes that a
    /// rejection rather than a truncation.
    pub fn push(&mut self, attribute: DnAttribute<'a>) -> Result<()> {
        attribute.validate()?;
        self.attributes
            .push(attribute)
            .map_err(|_| Error::new(ErrorCode::CertInvalid))
    }

    /// The attributes, in encoding order.
    #[must_use]
    pub fn attributes(&self) -> &[DnAttribute<'a>] {
        &self.attributes
    }

    /// How many attributes there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// How many attributes of a kind there are.
    #[must_use]
    pub fn count(&self, kind: DnAttributeKind) -> usize {
        self.attributes.iter().filter(|a| a.kind == kind).count()
    }

    /// The scalar of the single attribute of this kind, or `None` if there is not exactly
    /// one.
    ///
    /// "Not exactly one" rather than "the first": a subject with two `matter-fabric-id`
    /// attributes is invalid, and answering with either one would hide that.
    #[must_use]
    pub fn single_uint(&self, kind: DnAttributeKind) -> Option<u64> {
        let mut found = None;
        for attribute in &self.attributes {
            if attribute.kind == kind {
                if found.is_some() {
                    return None;
                }
                found = attribute.as_uint();
            }
        }
        found
    }

    /// The `matter-node-id`, if the DN carries exactly one.
    #[must_use]
    pub fn node_id(&self) -> Option<NodeId> {
        self.single_uint(DnAttributeKind::MatterNodeId).map(NodeId)
    }

    /// The `matter-fabric-id`, if the DN carries exactly one.
    #[must_use]
    pub fn fabric_id(&self) -> Option<FabricId> {
        self.single_uint(DnAttributeKind::MatterFabricId)
            .map(FabricId)
    }

    /// Every `matter-noc-cat` in the DN, in order.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a NOC CAT is the low 32 bits of a matter-noc-cat DN value (§6.5.6.3)"
    )]
    pub fn noc_cats(&self) -> Vec<CaseAuthenticatedTag, MAX_NOC_CATS> {
        let mut out = Vec::new();
        for attribute in &self.attributes {
            if attribute.kind == DnAttributeKind::MatterNocCat
                && let Some(value) = attribute.as_uint()
            {
                // The cast is lossless: `validate` has already refused a noc-cat above
                // 32 bits.
                let _ = out.push(CaseAuthenticatedTag(value as u32));
            }
        }
        out
    }

    /// Writes the DN as a `LIST` under `tag`.
    pub fn encode(&self, writer: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        if self.attributes.is_empty() {
            return Err(Error::new(ErrorCode::CertInvalid));
        }
        writer.start_list(tag)?;
        for attribute in &self.attributes {
            attribute.encode(writer)?;
        }
        writer.end_container()
    }

    /// Reads a DN from a reader positioned just after the opening of its list.
    pub fn decode(reader: &mut TlvReader<'a>) -> Result<Self> {
        let mut dn = Self::new();
        loop {
            let Some(element) = reader.next_element()? else {
                return Err(Error::new(ErrorCode::CertInvalid));
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            dn.push(DnAttribute::decode(&element)?)?;
        }
        if dn.attributes.is_empty() {
            return Err(Error::new(ErrorCode::CertInvalid));
        }
        Ok(dn)
    }
}

/// The kind of container a DN is: `LIST`, per §6.5.2's `LIST [ length 1.. ] OF dn-attribute`.
pub const DN_CONTAINER: ContainerKind = ContainerKind::List;
