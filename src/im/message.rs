//! The ten interaction model messages (Core §10.7).
//!
//! # Arrays are iterated, not collected
//!
//! Every one of these messages carries at least one array whose length the *peer* chooses: a
//! `ReadRequest` can name any number of paths, a `ReportData` can carry any number of
//! attributes. Decoding those into a fixed-capacity array would mean picking a number, and
//! any number picked is either too small for a legitimate client or too large for the
//! smallest node this crate targets.
//!
//! So a decoded message holds the array's **encoded bytes** and hands out an iterator. The
//! cost of parsing is paid per element, by the caller, as it walks — which is also what lets
//! a server stop early when it runs out of room and answer `PATHS_EXHAUSTED` (§8.10.1)
//! rather than having already allocated for paths it cannot serve.
//!
//! # `InteractionModelRevision` is not optional
//!
//! §10.2.2.2: "All action messages defined in Section 10.7 SHALL include these tagged
//! fields", and the field is context tag `0xFF`. It is written on every message here. On the
//! way in it is accepted as absent, because §8.1.1 has revisions going back to 10 and a peer
//! that omits it is old rather than malformed.

use crate::error::{Error, ErrorCode, Result, bail};
use crate::im::ib::{
    AttributeData, AttributeReport, CommandData, DataVersionFilter, EventFilter, InvokeResponse,
};
use crate::im::path::{AttributePath, EventPath};
use crate::im::status::Status;
use crate::tlv::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value, set_once};

/// `InteractionModelRevision`, context tag `0xFF` on every action (§10.2.2.2).
pub const REVISION_TAG: u8 = 0xFF;

/// The revision this crate implements — 13, "Added WildcardFilterConfigurationVersion"
/// (§8.1.1).
pub const INTERACTION_MODEL_REVISION: u16 = 13;

/// The protocol opcodes of §10.2.1, under `PROTOCOL_ID_INTERACTION_MODEL`.
pub mod opcode {
    /// `StatusResponseMessage`.
    pub const STATUS_RESPONSE: u8 = 0x01;
    /// `ReadRequestMessage`.
    pub const READ_REQUEST: u8 = 0x02;
    /// `SubscribeRequestMessage`.
    pub const SUBSCRIBE_REQUEST: u8 = 0x03;
    /// `SubscribeResponseMessage`.
    pub const SUBSCRIBE_RESPONSE: u8 = 0x04;
    /// `ReportDataMessage`.
    pub const REPORT_DATA: u8 = 0x05;
    /// `WriteRequestMessage`.
    pub const WRITE_REQUEST: u8 = 0x06;
    /// `WriteResponseMessage`.
    pub const WRITE_RESPONSE: u8 = 0x07;
    /// `InvokeRequestMessage`.
    pub const INVOKE_REQUEST: u8 = 0x08;
    /// `InvokeResponseMessage`.
    pub const INVOKE_RESPONSE: u8 = 0x09;
    /// `TimedRequestMessage`.
    pub const TIMED_REQUEST: u8 = 0x0A;
}

/// Opens the anonymous outer structure every action message is.
fn open(buf: &[u8]) -> Result<TlvReader<'_>> {
    let mut reader = TlvReader::new(buf);
    let Some(head) = reader.next_element()? else {
        bail!(TlvTruncated)
    };
    if head.value.container() != Some(ContainerKind::Structure) || !head.tag.is_anonymous() {
        bail!(TlvWrongType)
    }
    Ok(reader)
}

/// Captures an array's encoded bytes, for later iteration.
fn take_array<'a>(
    reader: &mut TlvReader<'a>,
    element: &Element<'a>,
    start: usize,
) -> Result<&'a [u8]> {
    if element.value.container() != Some(ContainerKind::Array) {
        bail!(TlvWrongType)
    }
    reader.skip_value(element)?;
    reader.slice_from(start)
}

/// Walks the members of a captured array, decoding one at a time.
///
/// Each member is an anonymous container, and **which** container depends on the block: the
/// path blocks of §10.6.2, §10.6.8 and §10.6.11 are `List`s, and everything else is a
/// `Structure`. That is not a detail to paper over by accepting either — a list and a
/// structure have different tag rules, and a decoder that accepted a structure where the
/// schema says list would accept paths no conforming peer sends and reject none.
#[derive(Debug, Clone)]
pub struct ArrayIter<'a, T> {
    reader: TlvReader<'a>,
    done: bool,
    member: ContainerKind,
    decode: fn(&mut TlvReader<'a>) -> Result<T>,
}

impl<'a, T> ArrayIter<'a, T> {
    /// Starts an iterator over an array's encoded bytes, whose members are `member`.
    pub(crate) fn new(
        bytes: &'a [u8],
        member: ContainerKind,
        decode: fn(&mut TlvReader<'a>) -> Result<T>,
    ) -> Result<Self> {
        // The captured slice is the array element itself, tag included. Which tag is legal
        // depends on where it sat, and it sat inside a structure.
        let mut reader = TlvReader::new_in(bytes, ContainerKind::Structure);
        let Some(head) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if head.value.container() != Some(ContainerKind::Array) {
            bail!(TlvWrongType)
        }
        Ok(Self {
            reader,
            done: false,
            member,
            decode,
        })
    }
}

impl<'a, T> Iterator for ArrayIter<'a, T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let element = match self.reader.next_element() {
            Ok(Some(element)) => element,
            Ok(None) => {
                self.done = true;
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };
        if element.value == Value::EndOfContainer {
            self.done = true;
            return None;
        }
        // An information block in an array is anonymous, and is the container its own
        // schema names (§10.6).
        if element.value.container() != Some(self.member) || !element.tag.is_anonymous() {
            self.done = true;
            return Some(Err(Error::new(ErrorCode::TlvWrongType)));
        }
        let out = (self.decode)(&mut self.reader);
        if out.is_err() {
            self.done = true;
        }
        Some(out)
    }
}

/// Writes the `InteractionModelRevision` every action carries.
fn write_revision(w: &mut TlvWriter<'_>) -> Result<()> {
    w.unsigned(
        Tag::Context(REVISION_TAG),
        u64::from(INTERACTION_MODEL_REVISION),
    )
}

// --- StatusResponse (§10.7.1) ----------------------------------------------------------------

/// `StatusResponseMessage` — the one-field message that answers an action outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusResponse {
    /// `Status [0]`.
    pub status: Status,
    /// `InteractionModelRevision [0xFF]`, absent from a peer older than revision 10.
    pub revision: Option<u16>,
}

impl StatusResponse {
    /// A response carrying `status`.
    #[must_use]
    pub const fn new(status: Status) -> Self {
        Self {
            status,
            revision: Some(INTERACTION_MODEL_REVISION),
        }
    }

    /// Encodes the message.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(self.status.value()))?;
        write_revision(&mut w)?;
        w.end_container()?;
        w.finish()
    }

    /// Decodes the message.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut status = None;
        let mut revision = None;
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
                    Status::from_value(
                        u8::try_from(element.unsigned()?)
                            .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))?,
                    ),
                )?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;
        Ok(Self {
            status: status.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            revision,
        })
    }
}

// --- ReadRequest (§10.7.2) -------------------------------------------------------------------

/// `ReadRequestMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRequest<'a> {
    attribute_requests: Option<&'a [u8]>,
    event_requests: Option<&'a [u8]>,
    event_filters: Option<&'a [u8]>,
    data_version_filters: Option<&'a [u8]>,
    /// `FabricFiltered [3]` — whether fabric-scoped data is limited to the accessing
    /// fabric (§8.4.2).
    pub fabric_filtered: bool,
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl<'a> ReadRequest<'a> {
    /// The attribute paths, decoded one at a time.
    pub fn attribute_paths(&self) -> Result<Option<ArrayIter<'a, AttributePath>>> {
        self.attribute_requests
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::List, path_from_list))
            .transpose()
    }

    /// The event paths.
    pub fn event_paths(&self) -> Result<Option<ArrayIter<'a, EventPath>>> {
        self.event_requests
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::List, event_path_from_list))
            .transpose()
    }

    /// The event filters, still encoded — what
    /// [`InteractionContext::event_filters`](crate::im::InteractionContext) carries.
    #[must_use]
    pub const fn event_filters_raw(&self) -> Option<&'a [u8]> {
        self.event_filters
    }

    /// The event filters.
    pub fn event_filters(&self) -> Result<Option<ArrayIter<'a, EventFilter>>> {
        self.event_filters
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::Structure, EventFilter::decode))
            .transpose()
    }

    /// The data version filters, still encoded — what
    /// [`InteractionContext::data_version_filters`](crate::im::InteractionContext) carries.
    #[must_use]
    pub const fn data_version_filters_raw(&self) -> Option<&'a [u8]> {
        self.data_version_filters
    }

    /// The data version filters.
    pub fn data_version_filters(&self) -> Result<Option<ArrayIter<'a, DataVersionFilter>>> {
        self.data_version_filters
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::Structure, DataVersionFilter::decode))
            .transpose()
    }

    /// Decodes the message.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut attribute_requests = None;
        let mut event_requests = None;
        let mut event_filters = None;
        let mut data_version_filters = None;
        let mut fabric_filtered = None;
        let mut revision = None;

        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(
                    &mut attribute_requests,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(1) => set_once(
                    &mut event_requests,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(2) => {
                    set_once(
                        &mut event_filters,
                        take_array(&mut reader, &element, start)?,
                    )?;
                }
                Some(3) => set_once(&mut fabric_filtered, element.bool()?)?,
                Some(4) => set_once(
                    &mut data_version_filters,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        Ok(Self {
            attribute_requests,
            event_requests,
            event_filters,
            data_version_filters,
            // `FabricFiltered` is not optional in the schema; §8.4.2 makes `true` the safe
            // reading, since it narrows what is returned rather than widening it.
            fabric_filtered: fabric_filtered.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            revision,
        })
    }
}

/// Writes a `ReadRequestMessage` from paths a caller supplies.
///
/// Taking iterators rather than slices keeps the builder usable from a generator: a
/// controller reading every endpoint does not have to materialise the path list first.
pub fn encode_read_request<A, E>(
    buf: &mut [u8],
    attribute_paths: A,
    event_paths: E,
    fabric_filtered: bool,
) -> Result<&[u8]>
where
    A: IntoIterator<Item = AttributePath>,
    E: IntoIterator<Item = EventPath>,
{
    let mut w = TlvWriter::new(buf);
    w.start_structure(Tag::Anonymous)?;

    let mut attributes = attribute_paths.into_iter().peekable();
    if attributes.peek().is_some() {
        w.start_array(Tag::Context(0))?;
        for path in attributes {
            path.encode(&mut w, Tag::Anonymous)?;
        }
        w.end_container()?;
    }

    let mut events = event_paths.into_iter().peekable();
    if events.peek().is_some() {
        w.start_array(Tag::Context(1))?;
        for path in events {
            path.encode(&mut w, Tag::Anonymous)?;
        }
        w.end_container()?;
    }

    w.bool(Tag::Context(3), fabric_filtered)?;
    write_revision(&mut w)?;
    w.end_container()?;
    w.finish()
}

/// Writes a `SubscribeRequestMessage` (§10.7.5).
///
/// The client's half of §8.5. The two intervals are a *request*: §8.5.3.2 lets the server
/// answer with a `MaxInterval` of its own inside the `SubscribeResponse`, and a client that
/// assumed its ceiling had been honoured would call a live subscription dead.
///
/// `keep_subscriptions` is the one field with teeth. §8.5.2.3: false "SHALL be treated as a
/// request to terminate all existing subscriptions" from this subscriber — which is what a
/// controller wants after a restart, and exactly what it does not want when adding a second
/// subscription to a node it is already watching.
pub fn encode_subscribe_request<A, E>(
    buf: &mut [u8],
    attribute_paths: A,
    event_paths: E,
    min_interval_floor_s: u16,
    max_interval_ceiling_s: u16,
    keep_subscriptions: bool,
    fabric_filtered: bool,
) -> Result<&[u8]>
where
    A: IntoIterator<Item = AttributePath>,
    E: IntoIterator<Item = EventPath>,
{
    let mut w = TlvWriter::new(buf);
    w.start_structure(Tag::Anonymous)?;
    w.bool(Tag::Context(0), keep_subscriptions)?;
    w.unsigned(Tag::Context(1), u64::from(min_interval_floor_s))?;
    w.unsigned(Tag::Context(2), u64::from(max_interval_ceiling_s))?;

    let mut attributes = attribute_paths.into_iter().peekable();
    if attributes.peek().is_some() {
        w.start_array(Tag::Context(3))?;
        for path in attributes {
            path.encode(&mut w, Tag::Anonymous)?;
        }
        w.end_container()?;
    }

    let mut events = event_paths.into_iter().peekable();
    if events.peek().is_some() {
        w.start_array(Tag::Context(4))?;
        for path in events {
            path.encode(&mut w, Tag::Anonymous)?;
        }
        w.end_container()?;
    }

    w.bool(Tag::Context(7), fabric_filtered)?;
    write_revision(&mut w)?;
    w.end_container()?;
    w.finish()
}

// --- ReportData (§10.7.3) --------------------------------------------------------------------

/// `ReportDataMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportData<'a> {
    /// `SubscriptionID [0]`, present when this report belongs to a subscription.
    pub subscription_id: Option<u32>,
    attribute_reports: Option<&'a [u8]>,
    event_reports: Option<&'a [u8]>,
    /// `MoreChunkedMessages [3]` — another message of this same action follows (§10.2.3).
    pub more_chunked_messages: bool,
    /// `SuppressResponse [4]` — the receiver need not send a `StatusResponse`.
    pub suppress_response: bool,
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl<'a> ReportData<'a> {
    /// The attribute reports, decoded one at a time.
    pub fn attribute_reports(&self) -> Result<Option<ArrayIter<'a, AttributeReport<'a>>>> {
        self.attribute_reports
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::Structure, AttributeReport::decode))
            .transpose()
    }

    /// The event reports, decoded one at a time.
    pub fn event_reports(&self) -> Result<Option<ArrayIter<'a, crate::im::EventReport<'a>>>> {
        self.event_reports
            .map(|bytes| {
                ArrayIter::new(
                    bytes,
                    ContainerKind::Structure,
                    crate::im::EventReport::decode,
                )
            })
            .transpose()
    }

    /// The raw bytes of the attribute reports array, for a caller that forwards or
    /// accumulates them without looking — a bridge relaying a report, or
    /// [`ReportAssembler`](crate::im::ReportAssembler) putting a chunked one back together.
    ///
    /// The slice is the whole array *element*, tag and end-of-container included, which is
    /// why two chunks cannot simply be concatenated: that would make two arrays, not one.
    #[must_use]
    pub const fn attribute_reports_bytes(&self) -> Option<&'a [u8]> {
        self.attribute_reports
    }

    /// The raw bytes of the event reports array, for a caller that forwards them without
    /// looking — a bridge relaying a report for a cluster it has never heard of.
    #[must_use]
    pub const fn event_reports_bytes(&self) -> Option<&'a [u8]> {
        self.event_reports
    }

    /// Decodes the message.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut subscription_id = None;
        let mut attribute_reports = None;
        let mut event_reports = None;
        let mut more_chunked_messages = None;
        let mut suppress_response = None;
        let mut revision = None;

        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut subscription_id, narrow32(element.unsigned()?)?)?,
                Some(1) => set_once(
                    &mut attribute_reports,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(2) => {
                    set_once(
                        &mut event_reports,
                        take_array(&mut reader, &element, start)?,
                    )?;
                }
                Some(3) => set_once(&mut more_chunked_messages, element.bool()?)?,
                Some(4) => set_once(&mut suppress_response, element.bool()?)?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        Ok(Self {
            subscription_id,
            attribute_reports,
            event_reports,
            // Both booleans are "can be omitted" / "omit if false" in §10.7.3.
            more_chunked_messages: more_chunked_messages.unwrap_or(false),
            suppress_response: suppress_response.unwrap_or(false),
            revision,
        })
    }
}

/// Writes a `ReportDataMessage`.
pub fn encode_report_data<'b, R>(
    buf: &'b mut [u8],
    subscription_id: Option<u32>,
    reports: R,
    more_chunked_messages: bool,
    suppress_response: bool,
) -> Result<&'b [u8]>
where
    R: IntoIterator<Item = AttributeReport<'b>>,
{
    let mut w = TlvWriter::new(buf);
    w.start_structure(Tag::Anonymous)?;
    if let Some(id) = subscription_id {
        w.unsigned(Tag::Context(0), u64::from(id))?;
    }
    let mut reports = reports.into_iter().peekable();
    if reports.peek().is_some() {
        w.start_array(Tag::Context(1))?;
        for report in reports {
            report.encode(&mut w)?;
        }
        w.end_container()?;
    }
    // "Can be omitted" / "Omit if 'false'" — writing the default would be legal but is
    // wasted octets in a message whose size drives chunking.
    if more_chunked_messages {
        w.bool(Tag::Context(3), true)?;
    }
    if suppress_response {
        w.bool(Tag::Context(4), true)?;
    }
    write_revision(&mut w)?;
    w.end_container()?;
    w.finish()
}

// --- WriteRequest (§10.7.6) and WriteResponse (§10.7.7) --------------------------------------

/// `WriteRequestMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteRequest<'a> {
    /// `SuppressResponse [0]`.
    pub suppress_response: bool,
    /// `TimedRequest [1]` — this write is inside a Timed interaction (§8.7).
    pub timed_request: bool,
    write_requests: &'a [u8],
    /// `MoreChunkedMessages [3]`.
    pub more_chunked_messages: bool,
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl<'a> WriteRequest<'a> {
    /// The attribute data to write, decoded one at a time.
    pub fn writes(&self) -> Result<ArrayIter<'a, AttributeData<'a>>> {
        ArrayIter::new(
            self.write_requests,
            ContainerKind::Structure,
            AttributeData::decode,
        )
    }

    /// Decodes the message.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut suppress_response = None;
        let mut timed_request = None;
        let mut write_requests = None;
        let mut more_chunked_messages = None;
        let mut revision = None;

        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut suppress_response, element.bool()?)?,
                Some(1) => set_once(&mut timed_request, element.bool()?)?,
                Some(2) => set_once(
                    &mut write_requests,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(3) => set_once(&mut more_chunked_messages, element.bool()?)?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        Ok(Self {
            suppress_response: suppress_response.unwrap_or(false),
            timed_request: timed_request.unwrap_or(false),
            // `WriteRequests` is the only mandatory field: a write with nothing to write is
            // not a write.
            write_requests: write_requests.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            more_chunked_messages: more_chunked_messages.unwrap_or(false),
            revision,
        })
    }
}

/// Writes a `WriteRequestMessage`.
pub fn encode_write_request<'b, W>(
    buf: &'b mut [u8],
    writes: W,
    timed_request: bool,
    suppress_response: bool,
) -> Result<&'b [u8]>
where
    W: IntoIterator<Item = AttributeData<'b>>,
{
    let mut w = TlvWriter::new(buf);
    w.start_structure(Tag::Anonymous)?;
    if suppress_response {
        w.bool(Tag::Context(0), true)?;
    }
    w.bool(Tag::Context(1), timed_request)?;
    w.start_array(Tag::Context(2))?;
    for data in writes {
        // An AttributeDataIB inside an array is an anonymous structure.
        data.encode(&mut w, Tag::Anonymous)?;
    }
    w.end_container()?;
    write_revision(&mut w)?;
    w.end_container()?;
    w.finish()
}

/// `WriteResponseMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteResponse<'a> {
    write_responses: &'a [u8],
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl<'a> WriteResponse<'a> {
    /// The per-path outcomes, decoded one at a time.
    pub fn statuses(&self) -> Result<ArrayIter<'a, crate::im::ib::AttributeStatus>> {
        ArrayIter::new(
            self.write_responses,
            ContainerKind::Structure,
            crate::im::ib::AttributeStatus::decode,
        )
    }

    /// Decodes the message.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut write_responses = None;
        let mut revision = None;
        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(
                    &mut write_responses,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;
        Ok(Self {
            write_responses: write_responses.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            revision,
        })
    }
}

/// Writes a `WriteResponseMessage`.
pub fn encode_write_response<S>(buf: &mut [u8], statuses: S) -> Result<&[u8]>
where
    S: IntoIterator<Item = crate::im::ib::AttributeStatus>,
{
    let mut w = TlvWriter::new(buf);
    w.start_structure(Tag::Anonymous)?;
    w.start_array(Tag::Context(0))?;
    for status in statuses {
        status.encode(&mut w, Tag::Anonymous)?;
    }
    w.end_container()?;
    write_revision(&mut w)?;
    w.end_container()?;
    w.finish()
}

// --- InvokeRequest (§10.7.9) and InvokeResponse (§10.7.10) -----------------------------------

/// `InvokeRequestMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvokeRequest<'a> {
    /// `SuppressResponse [0]`.
    pub suppress_response: bool,
    /// `TimedRequest [1]`.
    pub timed_request: bool,
    invoke_requests: &'a [u8],
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl<'a> InvokeRequest<'a> {
    /// The commands to invoke, decoded one at a time.
    ///
    /// More than one is permitted from interaction model revision 12 (§8.1.1: "added support
    /// for multiple CommandDataIB in one Invoke Request"), and each then carries a
    /// `CommandRef` so the responses can be matched up.
    pub fn commands(&self) -> Result<ArrayIter<'a, CommandData<'a>>> {
        ArrayIter::new(
            self.invoke_requests,
            ContainerKind::Structure,
            CommandData::decode,
        )
    }

    /// Decodes the message.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut suppress_response = None;
        let mut timed_request = None;
        let mut invoke_requests = None;
        let mut revision = None;

        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut suppress_response, element.bool()?)?,
                Some(1) => set_once(&mut timed_request, element.bool()?)?,
                Some(2) => set_once(
                    &mut invoke_requests,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        Ok(Self {
            suppress_response: suppress_response.unwrap_or(false),
            timed_request: timed_request.unwrap_or(false),
            invoke_requests: invoke_requests.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            revision,
        })
    }
}

/// Writes an `InvokeRequestMessage`.
pub fn encode_invoke_request<'b, C>(
    buf: &'b mut [u8],
    commands: C,
    timed_request: bool,
    suppress_response: bool,
) -> Result<&'b [u8]>
where
    C: IntoIterator<Item = CommandData<'b>>,
{
    let mut w = TlvWriter::new(buf);
    w.start_structure(Tag::Anonymous)?;
    w.bool(Tag::Context(0), suppress_response)?;
    w.bool(Tag::Context(1), timed_request)?;
    w.start_array(Tag::Context(2))?;
    for command in commands {
        command.encode(&mut w)?;
    }
    w.end_container()?;
    write_revision(&mut w)?;
    w.end_container()?;
    w.finish()
}

/// `InvokeResponseMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvokeResponseMessage<'a> {
    /// `SuppressResponse [0]`.
    pub suppress_response: bool,
    invoke_responses: &'a [u8],
    /// `MoreChunkedMessages [2]`.
    pub more_chunked_messages: bool,
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl<'a> InvokeResponseMessage<'a> {
    /// The per-command outcomes, decoded one at a time.
    pub fn responses(&self) -> Result<ArrayIter<'a, InvokeResponse<'a>>> {
        ArrayIter::new(
            self.invoke_responses,
            ContainerKind::Structure,
            InvokeResponse::decode,
        )
    }

    /// Decodes the message.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut suppress_response = None;
        let mut invoke_responses = None;
        let mut more_chunked_messages = None;
        let mut revision = None;

        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut suppress_response, element.bool()?)?,
                Some(1) => set_once(
                    &mut invoke_responses,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(2) => set_once(&mut more_chunked_messages, element.bool()?)?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        Ok(Self {
            suppress_response: suppress_response.unwrap_or(false),
            invoke_responses: invoke_responses.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            more_chunked_messages: more_chunked_messages.unwrap_or(false),
            revision,
        })
    }
}

/// Writes an `InvokeResponseMessage`.
pub fn encode_invoke_response<'b, R>(
    buf: &'b mut [u8],
    responses: R,
    suppress_response: bool,
) -> Result<&'b [u8]>
where
    R: IntoIterator<Item = InvokeResponse<'b>>,
{
    let mut w = TlvWriter::new(buf);
    w.start_structure(Tag::Anonymous)?;
    w.bool(Tag::Context(0), suppress_response)?;
    w.start_array(Tag::Context(1))?;
    for response in responses {
        response.encode(&mut w)?;
    }
    w.end_container()?;
    write_revision(&mut w)?;
    w.end_container()?;
    w.finish()
}

// --- TimedRequest (§10.7.8) ------------------------------------------------------------------

/// `TimedRequestMessage` — opens a Timed interaction (§8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedRequest {
    /// `Timeout [0]`, in milliseconds.
    pub timeout_ms: u16,
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl TimedRequest {
    /// A request with this timeout.
    #[must_use]
    pub const fn new(timeout_ms: u16) -> Self {
        Self {
            timeout_ms,
            revision: Some(INTERACTION_MODEL_REVISION),
        }
    }

    /// Encodes the message.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(self.timeout_ms))?;
        write_revision(&mut w)?;
        w.end_container()?;
        w.finish()
    }

    /// Decodes the message.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut timeout_ms = None;
        let mut revision = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut timeout_ms, narrow16(element.unsigned()?)?)?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;
        Ok(Self {
            timeout_ms: timeout_ms.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            revision,
        })
    }
}

// --- SubscribeRequest (§10.7.4) and SubscribeResponse (§10.7.5) ------------------------------

/// `SubscribeRequestMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscribeRequest<'a> {
    /// `KeepSubscriptions [0]` — leave the client's existing subscriptions in place.
    pub keep_subscriptions: bool,
    /// `MinIntervalFloor [1]`, in seconds — the shortest gap between reports.
    pub min_interval_floor_s: u16,
    /// `MaxIntervalCeiling [2]`, in seconds — the longest the server may stay silent.
    pub max_interval_ceiling_s: u16,
    attribute_requests: Option<&'a [u8]>,
    event_requests: Option<&'a [u8]>,
    event_filters: Option<&'a [u8]>,
    data_version_filters: Option<&'a [u8]>,
    /// `FabricFiltered [7]`.
    pub fabric_filtered: bool,
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl<'a> SubscribeRequest<'a> {
    /// The attribute paths, decoded one at a time.
    pub fn attribute_paths(&self) -> Result<Option<ArrayIter<'a, AttributePath>>> {
        self.attribute_requests
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::List, path_from_list))
            .transpose()
    }

    /// The event paths.
    pub fn event_paths(&self) -> Result<Option<ArrayIter<'a, EventPath>>> {
        self.event_requests
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::List, event_path_from_list))
            .transpose()
    }

    /// The data version filters, still encoded — what
    /// [`InteractionContext::data_version_filters`](crate::im::InteractionContext) carries.
    #[must_use]
    pub const fn data_version_filters_raw(&self) -> Option<&'a [u8]> {
        self.data_version_filters
    }

    /// The data version filters.
    pub fn data_version_filters(&self) -> Result<Option<ArrayIter<'a, DataVersionFilter>>> {
        self.data_version_filters
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::Structure, DataVersionFilter::decode))
            .transpose()
    }

    /// The event filters, still encoded — what
    /// [`InteractionContext::event_filters`](crate::im::InteractionContext) carries.
    #[must_use]
    pub const fn event_filters_raw(&self) -> Option<&'a [u8]> {
        self.event_filters
    }

    /// The event filters.
    pub fn event_filters(&self) -> Result<Option<ArrayIter<'a, EventFilter>>> {
        self.event_filters
            .map(|bytes| ArrayIter::new(bytes, ContainerKind::Structure, EventFilter::decode))
            .transpose()
    }

    /// Decodes the message.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut keep_subscriptions = None;
        let mut min_interval_floor_s = None;
        let mut max_interval_ceiling_s = None;
        let mut attribute_requests = None;
        let mut event_requests = None;
        let mut event_filters = None;
        let mut data_version_filters = None;
        let mut fabric_filtered = None;
        let mut revision = None;

        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut keep_subscriptions, element.bool()?)?,
                Some(1) => set_once(&mut min_interval_floor_s, narrow16(element.unsigned()?)?)?,
                Some(2) => set_once(&mut max_interval_ceiling_s, narrow16(element.unsigned()?)?)?,
                Some(3) => set_once(
                    &mut attribute_requests,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(4) => set_once(
                    &mut event_requests,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(5) => {
                    set_once(
                        &mut event_filters,
                        take_array(&mut reader, &element, start)?,
                    )?;
                }
                Some(7) => set_once(&mut fabric_filtered, element.bool()?)?,
                Some(8) => set_once(
                    &mut data_version_filters,
                    take_array(&mut reader, &element, start)?,
                )?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        Ok(Self {
            keep_subscriptions: keep_subscriptions.unwrap_or(false),
            min_interval_floor_s: min_interval_floor_s.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            max_interval_ceiling_s: max_interval_ceiling_s
                .ok_or(Error::new(ErrorCode::TlvNotFound))?,
            attribute_requests,
            event_requests,
            event_filters,
            data_version_filters,
            fabric_filtered: fabric_filtered.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            revision,
        })
    }
}

/// `SubscribeResponseMessage`.
///
/// Note the gap: the schema has `SubscriptionID [0]` and `MaxInterval [2]`, with no tag 1.
/// That is the specification's, not a transcription slip — tag 1 held a `MinInterval` that
/// was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscribeResponse {
    /// `SubscriptionID [0]`.
    pub subscription_id: u32,
    /// `MaxInterval [2]`, in seconds — what the server actually settled on.
    pub max_interval_s: u16,
    /// `InteractionModelRevision [0xFF]`.
    pub revision: Option<u16>,
}

impl SubscribeResponse {
    /// A response granting a subscription.
    #[must_use]
    pub const fn new(subscription_id: u32, max_interval_s: u16) -> Self {
        Self {
            subscription_id,
            max_interval_s,
            revision: Some(INTERACTION_MODEL_REVISION),
        }
    }

    /// Encodes the message.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(self.subscription_id))?;
        w.unsigned(Tag::Context(2), u64::from(self.max_interval_s))?;
        write_revision(&mut w)?;
        w.end_container()?;
        w.finish()
    }

    /// Decodes the message.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut reader = open(buf)?;
        let mut subscription_id = None;
        let mut max_interval_s = None;
        let mut revision = None;
        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            match element.tag.context() {
                Some(0) => set_once(&mut subscription_id, narrow32(element.unsigned()?)?)?,
                Some(2) => set_once(&mut max_interval_s, narrow16(element.unsigned()?)?)?,
                Some(REVISION_TAG) => set_once(&mut revision, narrow16(element.unsigned()?)?)?,
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;
        Ok(Self {
            subscription_id: subscription_id.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            max_interval_s: max_interval_s.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            revision,
        })
    }
}

fn path_from_list(reader: &mut TlvReader<'_>) -> Result<AttributePath> {
    AttributePath::decode(reader)
}

fn event_path_from_list(reader: &mut TlvReader<'_>) -> Result<EventPath> {
    EventPath::decode(reader)
}

fn narrow16(value: u64) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

fn narrow32(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}
