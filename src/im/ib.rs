//! Information blocks — the pieces every interaction model action is built from
//! (Core §10.6).
//!
//! §10.6: "These are elements that may apply to multiple message types, and are defined in
//! a common way to permit re-use as a definition."
//!
//! # Data is carried, not interpreted
//!
//! An attribute's value has a *cluster's* type, not the interaction model's. §10.6.4.3 makes
//! the `Data` field "Variable", and what it holds is whatever the cluster's schema says. So
//! every IB here keeps that field as the **encoded TLV element**, borrowed from the buffer
//! it arrived in, and hands it on with
//! [`TlvWriter::raw_element`](crate::tlv::TlvWriter::raw_element).
//!
//! That is not laziness, it is the only correct shape at this layer: a proxy forwarding a
//! report must not need to know the cluster to forward it, and a server reading a value must
//! hand the cluster exactly the octets the client sent rather than a re-encoding of them.
//! The writer still validates that the bytes are one well-formed element carrying a tag this
//! position admits, so a forwarding path cannot launder invalid TLV.
//!
//! # Status or data, never both
//!
//! [`AttributeReport`] and [`InvokeResponse`] are the two places the specification models a
//! choice as a structure with two optional fields. A report carries an `AttributeStatusIB`
//! *or* an `AttributeDataIB`; §8.4.3 is clear that one of them is always present. They are
//! modelled as enums here, so "neither" and "both" are unrepresentable rather than merely
//! discouraged.

use crate::error::{Error, ErrorCode, Result, bail};
use crate::im::path::{AttributePath, ClusterPath, CommandPath, EventPath};
use crate::im::status::Status;
use crate::tlv::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value, set_once};

/// A cluster's data version (§7.10.3), which a client caches and filters on.
pub type DataVersion = u32;

/// `StatusIB` (§10.6.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusIb {
    /// `Status [0]` — an interaction model status (§8.10).
    pub status: Status,
    /// `ClusterStatus [1]` — a cluster-defined code, meaningful only when `status` is
    /// `FAILURE` and the cluster defines one.
    pub cluster_status: Option<u8>,
}

impl From<Status> for StatusIb {
    fn from(status: Status) -> Self {
        Self::new(status)
    }
}

impl StatusIb {
    /// A cluster-defined failure — §8.10's `FAILURE` with a `ClusterStatus` beside it.
    ///
    /// §8.10.1: `FAILURE` is "the sender has failed to execute the request for an unspecified
    /// reason", and the cluster-specific code is what specifies it. §11.19.6's `Busy`,
    /// `PAKEParameterError` and `WindowNotOpen` are the ones this crate uses.
    ///
    /// The status must be `FAILURE` for the code to mean anything: §10.6.17 makes
    /// `ClusterStatus` "meaningful only when the Status is FAILURE".
    #[must_use]
    pub const fn cluster_failure(cluster_status: u8) -> Self {
        Self {
            status: Status::Failure,
            cluster_status: Some(cluster_status),
        }
    }

    /// A plain status with no cluster-specific code.
    #[must_use]
    pub const fn new(status: Status) -> Self {
        Self {
            status,
            cluster_status: None,
        }
    }

    /// Writes the block as a `Structure` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        w.unsigned(Tag::Context(0), u64::from(self.status.value()))?;
        if let Some(cluster_status) = self.cluster_status {
            w.unsigned(Tag::Context(1), u64::from(cluster_status))?;
        }
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut status = None;
        let mut cluster_status = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(
                    &mut status,
                    Status::from_value(narrow8(element.unsigned()?)?),
                )?,
                Some(1) => set_once(&mut cluster_status, narrow8(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            status: status.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            cluster_status,
        })
    }
}

/// `AttributeDataIB` (§10.6.4) — a path and the value at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeData<'a> {
    /// `DataVersion [0]` — "the data version of the cluster instance", present in a report
    /// and absent in a write.
    pub data_version: Option<DataVersion>,
    /// `Path [1]`.
    pub path: AttributePath,
    /// `Data [2]` — the encoded TLV element, tag included, exactly as it arrived.
    pub data: &'a [u8],
}

impl<'a> AttributeData<'a> {
    /// Writes the block as a `Structure` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        if let Some(version) = self.data_version {
            w.unsigned(Tag::Context(0), u64::from(version))?;
        }
        self.path.encode(w, Tag::Context(1))?;
        // The data already carries its context-2 tag; `raw_element` checks that it is one
        // well-formed element and that the tag is legal here before copying it.
        w.raw_element(self.data)?;
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'a>) -> Result<Self> {
        let mut data_version = None;
        let mut path = None;
        let mut data = None;
        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut data_version, narrow32(element.unsigned()?)?)?,
                Some(1) => {
                    if element.value.container() != Some(ContainerKind::List) {
                        bail!(TlvWrongType)
                    }
                    set_once(&mut path, AttributePath::decode(reader)?)?;
                }
                Some(2) => {
                    reader.skip_value(&element)?;
                    set_once(&mut data, reader.slice_from(start)?)?;
                }
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            data_version,
            path: path.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            data: data.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

/// `AttributeStatusIB` (§10.6.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeStatus {
    /// `Path [0]`.
    pub path: AttributePath,
    /// `Status [1]`.
    pub status: StatusIb,
}

impl AttributeStatus {
    /// Writes the block as a `Structure` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        self.path.encode(w, Tag::Context(0))?;
        self.status.encode(w, Tag::Context(1))?;
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut path = None;
        let mut status = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => {
                    if element.value.container() != Some(ContainerKind::List) {
                        bail!(TlvWrongType)
                    }
                    set_once(&mut path, AttributePath::decode(reader)?)?;
                }
                Some(1) => {
                    if element.value.container() != Some(ContainerKind::Structure) {
                        bail!(TlvWrongType)
                    }
                    set_once(&mut status, StatusIb::decode(reader)?)?;
                }
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            status: status.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

/// `AttributeReportIB` (§10.6.5) — one attribute's outcome in a report.
///
/// The schema is a structure with two optional fields; §8.4.3 gives exactly one of them.
/// Modelling it as a choice makes "neither" and "both" unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeReport<'a> {
    /// `AttributeStatus [0]` — the path could not be served.
    Status(AttributeStatus),
    /// `AttributeData [1]` — the value.
    Data(AttributeData<'a>),
}

impl<'a> AttributeReport<'a> {
    /// The path this report is about, whichever arm it is.
    #[must_use]
    pub const fn path(&self) -> AttributePath {
        match self {
            Self::Status(s) => s.path,
            Self::Data(d) => d.path,
        }
    }

    /// Writes the block as an anonymous `Structure`, which is what an array member is.
    pub fn encode(&self, w: &mut TlvWriter<'_>) -> Result<()> {
        w.start_structure(Tag::Anonymous)?;
        match self {
            Self::Status(status) => status.encode(w, Tag::Context(0))?,
            Self::Data(data) => data.encode(w, Tag::Context(1))?,
        }
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'a>) -> Result<Self> {
        let mut out = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => {
                    expect_structure(&element)?;
                    set_once(&mut out, Self::Status(AttributeStatus::decode(reader)?))?;
                }
                Some(1) => {
                    expect_structure(&element)?;
                    set_once(&mut out, Self::Data(AttributeData::decode(reader)?))?;
                }
                _ => reader.skip_value(&element)?,
            }
        }
        // A report with neither arm says nothing about the path it names, which no reader
        // could act on.
        out.ok_or(Error::new(ErrorCode::TlvNotFound))
    }
}

/// `DataVersionFilterIB` (§10.6.3) — "I already have version V of this cluster; skip it."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataVersionFilter {
    /// `Path [0]`.
    pub path: ClusterPath,
    /// `DataVersion [1]`.
    pub data_version: DataVersion,
}

impl DataVersionFilter {
    /// Writes the block as an anonymous `Structure`.
    pub fn encode(&self, w: &mut TlvWriter<'_>) -> Result<()> {
        w.start_structure(Tag::Anonymous)?;
        self.path.encode(w, Tag::Context(0))?;
        w.unsigned(Tag::Context(1), u64::from(self.data_version))?;
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut path = None;
        let mut data_version = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => {
                    if element.value.container() != Some(ContainerKind::List) {
                        bail!(TlvWrongType)
                    }
                    set_once(&mut path, ClusterPath::decode(reader)?)?;
                }
                Some(1) => set_once(&mut data_version, narrow32(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            data_version: data_version.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

/// `EventFilterIB` (§10.6.6) — "I already have events up to number N."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventFilter {
    /// `Node [0]`.
    pub node: Option<crate::msg::NodeId>,
    /// `EventMin [1]` — the lowest event number the client still wants.
    pub event_min: u64,
}

impl EventFilter {
    /// Writes the block as an anonymous `Structure`.
    pub fn encode(&self, w: &mut TlvWriter<'_>) -> Result<()> {
        w.start_structure(Tag::Anonymous)?;
        if let Some(node) = self.node {
            w.unsigned(Tag::Context(0), node.0)?;
        }
        w.unsigned(Tag::Context(1), self.event_min)?;
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut node = None;
        let mut event_min = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut node, crate::msg::NodeId(element.unsigned()?))?,
                Some(1) => set_once(&mut event_min, element.unsigned()?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            node,
            event_min: event_min.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

/// `CommandDataIB` (§10.6.12) — a command invocation, or a command response's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandData<'a> {
    /// `CommandPath [0]`.
    pub path: CommandPath,
    /// `CommandFields [1]` — the encoded TLV element, or `None` for a command with no
    /// fields.
    pub fields: Option<&'a [u8]>,
    /// `CommandRef [2]` — which request this response answers, when an `InvokeRequest`
    /// carried more than one command (interaction model revision 12 and later).
    pub command_ref: Option<u16>,
}

impl<'a> CommandData<'a> {
    /// An invocation of a command that takes no fields.
    #[must_use]
    pub const fn new(path: CommandPath) -> Self {
        Self {
            path,
            fields: None,
            command_ref: None,
        }
    }

    /// Writes the block as an anonymous `Structure`.
    pub fn encode(&self, w: &mut TlvWriter<'_>) -> Result<()> {
        w.start_structure(Tag::Anonymous)?;
        self.path.encode(w, Tag::Context(0))?;
        if let Some(fields) = self.fields {
            w.raw_element(fields)?;
        }
        if let Some(command_ref) = self.command_ref {
            w.unsigned(Tag::Context(2), u64::from(command_ref))?;
        }
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'a>) -> Result<Self> {
        let mut path = None;
        let mut fields = None;
        let mut command_ref = None;
        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => {
                    if element.value.container() != Some(ContainerKind::List) {
                        bail!(TlvWrongType)
                    }
                    set_once(&mut path, CommandPath::decode(reader)?)?;
                }
                Some(1) => {
                    reader.skip_value(&element)?;
                    set_once(&mut fields, reader.slice_from(start)?)?;
                }
                Some(2) => set_once(&mut command_ref, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            fields,
            command_ref,
        })
    }
}

/// `CommandStatusIB` (§10.6.14) — a command that produced a status rather than a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandStatus {
    /// `CommandPath [0]`.
    pub path: CommandPath,
    /// `Status [1]`.
    pub status: StatusIb,
    /// `CommandRef [2]`.
    pub command_ref: Option<u16>,
}

impl CommandStatus {
    /// Writes the block as a `Structure` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        self.path.encode(w, Tag::Context(0))?;
        self.status.encode(w, Tag::Context(1))?;
        if let Some(command_ref) = self.command_ref {
            w.unsigned(Tag::Context(2), u64::from(command_ref))?;
        }
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut path = None;
        let mut status = None;
        let mut command_ref = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => {
                    if element.value.container() != Some(ContainerKind::List) {
                        bail!(TlvWrongType)
                    }
                    set_once(&mut path, CommandPath::decode(reader)?)?;
                }
                Some(1) => {
                    expect_structure(&element)?;
                    set_once(&mut status, StatusIb::decode(reader)?)?;
                }
                Some(2) => set_once(&mut command_ref, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            status: status.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            command_ref,
        })
    }
}

/// `InvokeResponseIB` (§10.6.13) — one command's outcome.
///
/// As with [`AttributeReport`], the schema's two optional fields are a choice: a command
/// either produced a response payload or a status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeResponse<'a> {
    /// `Command [0]` — a response command with its fields.
    Command(CommandData<'a>),
    /// `Status [1]`.
    Status(CommandStatus),
}

impl<'a> InvokeResponse<'a> {
    /// Writes the block as an anonymous `Structure`.
    pub fn encode(&self, w: &mut TlvWriter<'_>) -> Result<()> {
        w.start_structure(Tag::Anonymous)?;
        match self {
            Self::Command(command) => {
                // A CommandDataIB is itself an anonymous structure in an array, but here it
                // sits under context tag 0, so it is written out field by field rather than
                // through `CommandData::encode`.
                w.start_structure(Tag::Context(0))?;
                command.path.encode(w, Tag::Context(0))?;
                if let Some(fields) = command.fields {
                    w.raw_element(fields)?;
                }
                if let Some(command_ref) = command.command_ref {
                    w.unsigned(Tag::Context(2), u64::from(command_ref))?;
                }
                w.end_container()?;
            }
            Self::Status(status) => status.encode(w, Tag::Context(1))?,
        }
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'a>) -> Result<Self> {
        let mut out = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => {
                    expect_structure(&element)?;
                    set_once(&mut out, Self::Command(CommandData::decode(reader)?))?;
                }
                Some(1) => {
                    expect_structure(&element)?;
                    set_once(&mut out, Self::Status(CommandStatus::decode(reader)?))?;
                }
                _ => reader.skip_value(&element)?,
            }
        }
        out.ok_or(Error::new(ErrorCode::TlvNotFound))
    }
}

/// `EventStatusIB` (§10.6.15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventStatus {
    /// `Path [0]`.
    pub path: EventPath,
    /// `Status [1]`.
    pub status: StatusIb,
}

impl EventStatus {
    /// Writes the block as a `Structure` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        self.path.encode(w, Tag::Context(0))?;
        self.status.encode(w, Tag::Context(1))?;
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'_>) -> Result<Self> {
        let mut path = None;
        let mut status = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => {
                    if element.value.container() != Some(ContainerKind::List) {
                        bail!(TlvWrongType)
                    }
                    set_once(&mut path, EventPath::decode(reader)?)?;
                }
                Some(1) => {
                    expect_structure(&element)?;
                    set_once(&mut status, StatusIb::decode(reader)?)?;
                }
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            status: status.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

fn expect_structure(element: &Element<'_>) -> Result<()> {
    if element.value.container() == Some(ContainerKind::Structure) {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::TlvWrongType))
    }
}

fn narrow8(value: u64) -> Result<u8> {
    u8::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

fn narrow16(value: u64) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

fn narrow32(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

/// `EventDataIB` (§10.6.9).
///
/// # The timestamp is a *choice* of four, and exactly one is present
///
/// §10.6.9's schema wraps tags 3 to 6 in a `one-of`, and the two delta forms say so twice
/// over: "When this tag is present, all other timestamp tags SHALL be omitted." A record
/// therefore carries an absolute epoch time, an absolute system time, or a delta against the
/// previous record in the same report — never two of them, and never none.
///
/// The delta forms exist because a burst of events reported together differ by milliseconds:
/// §7.14.1.2 requires a timestamp on every record "at the time it was created (and not when
/// it is reported to a client)", and encoding forty of them as full 64-bit values is forty
/// times eight octets where a delta is usually one or two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventData<'a> {
    /// `Path [0]`.
    pub path: EventPath,
    /// `EventNumber [1]` — §7.14.1.1's node-scoped number, "monotonically increasing for the
    /// life of the node", preserved across restarts.
    pub number: u64,
    /// `Priority [2]`.
    pub priority: u8,
    /// The timestamp, in one of §10.6.9's four forms.
    pub timestamp: EventTimestamp,
    /// `Data [7]` — the encoded TLV element, tag included, exactly as the cluster wrote it.
    ///
    /// §10.6.9.3: "If the cluster does not define any payload for the given event instance,
    /// this Data field SHALL be encoded as a struct with no member elements" — an *empty
    /// structure*, not an absent field.
    pub data: &'a [u8],
}

/// §10.6.9's timestamp choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTimestamp {
    /// `EpochTimestamp [3]` — POSIX milliseconds. A node that knows the wall-clock time.
    Epoch(u64),
    /// `SystemTimestamp [4]` — milliseconds since boot. A node that does not.
    System(u64),
    /// `DeltaEpochTimestamp [5]` — milliseconds since the previous record's epoch time.
    DeltaEpoch(u64),
    /// `DeltaSystemTimestamp [6]` — milliseconds since the previous record's system time.
    DeltaSystem(u64),
}

impl EventTimestamp {
    /// The context tag this form occupies.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Epoch(_) => 3,
            Self::System(_) => 4,
            Self::DeltaEpoch(_) => 5,
            Self::DeltaSystem(_) => 6,
        }
    }

    /// The value, whichever form it is.
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Epoch(value)
            | Self::System(value)
            | Self::DeltaEpoch(value)
            | Self::DeltaSystem(value) => value,
        }
    }

    /// Whether this is one of the two delta forms.
    #[must_use]
    pub const fn is_delta(self) -> bool {
        matches!(self, Self::DeltaEpoch(_) | Self::DeltaSystem(_))
    }
}

impl<'a> EventData<'a> {
    /// Writes the block as a `Structure` under `tag`.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        self.path.encode(w, Tag::Context(0))?;
        w.unsigned(Tag::Context(1), self.number)?;
        w.unsigned(Tag::Context(2), u64::from(self.priority))?;
        // Exactly one timestamp tag: the `one-of` is a choice, not a set.
        w.unsigned(Tag::Context(self.timestamp.tag()), self.timestamp.value())?;
        // The data already carries its context-7 tag; `raw_element` checks that it is one
        // well-formed element and that the tag is legal here before copying it.
        w.raw_element(self.data)?;
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'a>) -> Result<Self> {
        let mut path = None;
        let mut number = None;
        let mut priority = None;
        let mut timestamp: Option<EventTimestamp> = None;
        let mut data = None;
        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => {
                    let decoded = EventPath::decode(reader)?;
                    set_once(&mut path, decoded)?;
                }
                Some(1) => set_once(&mut number, element.unsigned()?)?,
                Some(2) => set_once(&mut priority, narrow8(element.unsigned()?)?)?,
                // All four timestamp tags land in one slot, so a second one — of any form —
                // is a duplicate. That is what makes "all other timestamp tags SHALL be
                // omitted" enforceable rather than merely stated.
                Some(3) => set_once(&mut timestamp, EventTimestamp::Epoch(element.unsigned()?))?,
                Some(4) => set_once(&mut timestamp, EventTimestamp::System(element.unsigned()?))?,
                Some(5) => {
                    set_once(
                        &mut timestamp,
                        EventTimestamp::DeltaEpoch(element.unsigned()?),
                    )?;
                }
                Some(6) => {
                    set_once(
                        &mut timestamp,
                        EventTimestamp::DeltaSystem(element.unsigned()?),
                    )?;
                }
                Some(7) => {
                    reader.skip_value(&element)?;
                    set_once(&mut data, reader.slice_from(start)?)?;
                }
                _ => reader.skip_value(&element)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            number: number.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            priority: priority.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            timestamp: timestamp.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            data: data.ok_or(Error::new(ErrorCode::TlvNotFound))?,
        })
    }
}

/// `EventReportIB` (§10.6.10).
///
/// As with [`AttributeReport`], the schema's two fields are a *choice*: a report carries the
/// event, or a status saying why it could not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventReport<'a> {
    /// `EventStatus [0]`.
    Status(EventStatus),
    /// `EventData [1]`.
    Data(EventData<'a>),
}

impl<'a> EventReport<'a> {
    /// Writes the block as an anonymous `Structure`, for an array member.
    pub fn encode(&self, w: &mut TlvWriter<'_>) -> Result<()> {
        w.start_structure(Tag::Anonymous)?;
        match self {
            Self::Status(status) => status.encode(w, Tag::Context(0))?,
            Self::Data(data) => data.encode(w, Tag::Context(1))?,
        }
        w.end_container()
    }

    /// Reads a block whose opening `Structure` element the caller has just taken.
    pub fn decode(reader: &mut TlvReader<'a>) -> Result<Self> {
        let mut report = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut report, Self::Status(EventStatus::decode(reader)?))?,
                Some(1) => set_once(&mut report, Self::Data(EventData::decode(reader)?))?,
                _ => reader.skip_value(&element)?,
            }
        }
        report.ok_or(Error::new(ErrorCode::TlvNotFound))
    }
}
