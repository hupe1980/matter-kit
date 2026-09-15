//! DNS messages, as much of them as Matter's DNS-SD needs (RFC 1035, RFC 6762).
//!
//! Matter "requires no modifications to IETF Standard DNS-SD" (§4.3), so this is ordinary
//! DNS on the wire: a header, questions, and resource records, with names as sequences of
//! length-prefixed labels.
//!
//! # Names are slices of labels, not strings
//!
//! `DD200C20D25AE5F7._matterc._udp.local.` is four labels, and nothing here ever joins them
//! into a string. That is not only to avoid allocating: the wire format is label-by-label,
//! compression points *at* a label boundary, and a dotted string would have to be split again
//! at every one of those points — reintroducing the question of what a dot inside a label
//! means. A DNS-SD instance name may legitimately contain dots.
//!
//! # Compression is what makes a response fit
//!
//! A Matter commissionable advertisement is four PTR records, an SRV, a TXT and an AAAA, all
//! naming `…_matterc._udp.local.` I RFC 1035 §4.1.4's pointers turn every repeat of that
//! suffix into two octets. [`DnsWriter`] remembers the names it has written and emits the
//! longest suffix match it can, which is the difference between a response that fits one
//! datagram and one that does not.
//!
//! # Reading is hostile-input territory
//!
//! A compression pointer can point anywhere, including backwards into itself — the classic
//! decompression loop. [`Name`] follows pointers with a hard bound and refuses any pointer
//! that does not point strictly backwards, which makes a cycle impossible rather than merely
//! bounded.

use heapless::Vec;

use crate::error::{Error, ErrorCode, Result, bail};

/// The IANA record types Matter's DNS-SD uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum RecordType {
    /// `A` — an IPv4 address. Matter does not use IPv4, but a query may still ask.
    A = 1,
    /// `PTR` — a service instance, or a subtype's member.
    Ptr = 12,
    /// `TXT` — the key/value pairs of §4.3.4.
    Txt = 16,
    /// `AAAA` — an IPv6 address. "Matter software discovering other Matter instances SHALL
    /// process DNS AAAA (IPv6 address) records" (§4.3).
    Aaaa = 28,
    /// `SRV` — priority, weight, port and target host.
    Srv = 33,
    /// `NSEC` — "this name has these types and no others", RFC 6762 §6.1's way of saying
    /// "there is no AAAA here" without silence.
    Nsec = 47,
    /// `ANY` — only ever a *question* type. RFC 6762 §6 makes it the ordinary way to ask for
    /// everything a responder knows about one name.
    Any = 255,
}

impl RecordType {
    /// The wire value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self as u16
    }

    /// Decodes a wire value, or `None` for a type this crate does not model.
    ///
    /// An unknown type is not an error: a responder simply has no records of it, and RFC 6762
    /// §6 says "if the responder has no records that answer the question, it MUST NOT send
    /// any response".
    #[must_use]
    pub const fn from_value(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::A),
            12 => Some(Self::Ptr),
            16 => Some(Self::Txt),
            28 => Some(Self::Aaaa),
            33 => Some(Self::Srv),
            47 => Some(Self::Nsec),
            255 => Some(Self::Any),
            _ => None,
        }
    }

    /// Whether a record of this type answers a question of `asked`.
    ///
    /// `ANY` matches everything; otherwise the types must be equal.
    #[must_use]
    pub const fn answers(self, asked: Self) -> bool {
        matches!(asked, Self::Any) || (self as u16) == (asked as u16)
    }
}

/// `IN` — the Internet class, the only one Matter uses.
pub const CLASS_IN: u16 = 1;

/// RFC 6762 §10.2's cache-flush bit, the top bit of a resource record's class.
///
/// "the most significant bit of the rrclass for a record in a Multicast DNS response message
/// is the cache-flush bit" — it tells a receiver to discard everything it already had for
/// this name and type. A responder sets it on records it is authoritative for, which for a
/// Matter node is all of them except the shared PTRs.
pub const CACHE_FLUSH: u16 = 0x8000;

/// RFC 6762 §5.4's unicast-response bit, the top bit of a question's class.
///
/// "a special bit in the rrclass field of the question … indicating that the querier is
/// willing to accept unicast replies". A responder that honours it sends one datagram back to
/// the asker rather than to the whole link.
pub const UNICAST_RESPONSE: u16 = 0x8000;

/// The longest label RFC 1035 §2.3.4 admits.
pub const LABEL_MAX: usize = 63;

/// How many labels a name may have here.
///
/// `<instance>._matterc._udp.local.` is four. Eight leaves room for a subtype's extra
/// `_S3._sub`, and refuses anything a Matter responder would never emit.
pub const LABELS_MAX: usize = 8;

/// How many compression pointers may be followed before the message is declared malformed.
///
/// Each pointer must go strictly backwards, so a cycle is already impossible; this bounds the
/// *work* a hostile message can cause.
const POINTER_LIMIT: usize = 16;

/// A domain name, as the sequence of labels it is on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    labels: Vec<Vec<u8, LABEL_MAX>, LABELS_MAX>,
}

impl Name {
    /// An empty name — the root.
    #[must_use]
    pub const fn root() -> Self {
        Self { labels: Vec::new() }
    }

    /// A name from its labels.
    pub fn from_labels(labels: &[&[u8]]) -> Result<Self> {
        let mut name = Self::root();
        for label in labels {
            name.push(label)?;
        }
        Ok(name)
    }

    /// A name from its labels, given as strings.
    pub fn from_strs(labels: &[&str]) -> Result<Self> {
        let mut name = Self::root();
        for label in labels {
            name.push(label.as_bytes())?;
        }
        Ok(name)
    }

    /// Appends a label.
    pub fn push(&mut self, label: &[u8]) -> Result<()> {
        if label.is_empty() || label.len() > LABEL_MAX {
            bail!(InvalidArgument)
        }
        let stored = Vec::from_slice(label).map_err(|_| Error::new(ErrorCode::NoSpace))?;
        self.labels
            .push(stored)
            .map_err(|_| Error::new(ErrorCode::NoSpace))
    }

    /// The labels, outermost first.
    pub fn labels(&self) -> impl Iterator<Item = &[u8]> {
        self.labels.iter().map(|label| label.as_slice())
    }

    /// How many labels the name has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Whether this is the root name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Whether two names are the same.
    ///
    /// **Case-insensitively**, because DNS is: RFC 1035 §2.3.3, and RFC 6762 §16 repeats it
    /// for Multicast DNS. A responder that compared bytes would miss a query for
    /// `_MATTERC._UDP.local.` — which a conforming querier is entitled to send, and which some
    /// stacks do send.
    #[must_use]
    pub fn eq_ignore_case(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .labels()
                .zip(other.labels())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Whether this name matches `labels`, case-insensitively.
    #[must_use]
    pub fn matches(&self, labels: &[&[u8]]) -> bool {
        self.len() == labels.len()
            && self
                .labels()
                .zip(labels.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Reads a name from `buf` starting at `at`, following compression pointers.
    ///
    /// Returns the name and the offset just past it *in the original stream* — which is not
    /// where the name ended if a pointer was followed, so the two are tracked separately.
    pub fn decode(buf: &[u8], at: usize) -> Result<(Self, usize)> {
        let mut name = Self::root();
        let mut cursor = at;
        let mut end: Option<usize> = None;
        let mut jumps = 0usize;

        loop {
            let length = *buf.get(cursor).ok_or_else(truncated)?;
            match length & 0xC0 {
                0x00 => {
                    let next = cursor.checked_add(1).ok_or_else(malformed)?;
                    if length == 0 {
                        // The root label ends the name.
                        return Ok((name, end.unwrap_or(next)));
                    }
                    let stop = next
                        .checked_add(usize::from(length))
                        .ok_or_else(malformed)?;
                    let label = buf.get(next..stop).ok_or_else(truncated)?;
                    name.push(label)?;
                    cursor = stop;
                }
                0xC0 => {
                    // RFC 1035 §4.1.4: a two-octet pointer, fourteen bits of offset.
                    let low = *buf
                        .get(cursor.checked_add(1).ok_or_else(malformed)?)
                        .ok_or_else(truncated)?;
                    let target = (usize::from(length & 0x3F) << 8) | usize::from(low);
                    // A pointer must go strictly backwards. That is not merely conventional —
                    // it is what makes a decompression loop impossible rather than merely
                    // bounded, because each jump reaches a strictly smaller offset.
                    if target >= cursor {
                        bail!(DnsMalformed)
                    }
                    jumps = jumps.saturating_add(1);
                    if jumps > POINTER_LIMIT {
                        bail!(DnsMalformed)
                    }
                    if end.is_none() {
                        end = Some(cursor.checked_add(2).ok_or_else(malformed)?);
                    }
                    cursor = target;
                }
                // 0x40 and 0x80 are reserved (RFC 6891 retired the one that used 0x40).
                _ => bail!(DnsMalformed),
            }
        }
    }
}

fn truncated() -> Error {
    Error::new(ErrorCode::DnsTruncated)
}

fn malformed() -> Error {
    Error::new(ErrorCode::DnsMalformed)
}

/// One resource record, as a responder holds it before encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// The owner name, as labels.
    pub name: &'a [&'a str],
    /// The record type.
    pub kind: RecordType,
    /// Seconds. RFC 6762 §10: 120 for host records, 4500 for the rest.
    pub ttl: u32,
    /// RFC 6762 §10.2's cache-flush bit.
    ///
    /// Set for records a responder is uniquely authoritative for — its SRV, TXT and AAAA —
    /// and **clear** for the shared PTRs, where several devices legitimately own the same
    /// name. Setting it on a PTR would tell every receiver to forget the other devices on the
    /// link.
    pub cache_flush: bool,
    /// The record's data.
    pub data: RecordData<'a>,
}

/// The RDATA of the record types Matter's DNS-SD uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordData<'a> {
    /// `PTR` — a target name.
    Ptr(&'a [&'a str]),
    /// `SRV` — priority, weight, port, target. Matter always uses priority 0 and weight 0.
    Srv {
        /// The port the service listens on. §4.3.1.14: "services are not constrained to use a
        /// single predetermined well-known port."
        port: u16,
        /// The target host name.
        target: &'a [&'a str],
    },
    /// `TXT` — the encoded key/value strings.
    Txt(&'a [u8]),
    /// `AAAA` — a 128-bit address.
    Aaaa([u8; 16]),
    /// `A` — a 32-bit address. Matter never publishes one; it is here so a reader can skip it.
    A([u8; 4]),
}

impl RecordData<'_> {
    /// Writes the RDATA **uncompressed**, as RFC 6762 §8.2's tiebreak compares it.
    ///
    /// "In the case of resource records containing rdata that is subject to name compression,
    /// the names MUST be uncompressed before comparison. (The details of how a particular name
    /// is compressed is an artifact of how and where the record is written into the DNS
    /// message; it is not an intrinsic property of the resource record itself.)" Comparing the
    /// bytes as they appear in a message would make the winner depend on which record happened
    /// to be written first.
    ///
    /// [`RDATA_MAX`] is always enough.
    pub fn write_rdata<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut cursor = Cursor::new(buf);
        match self {
            Self::Ptr(target) => cursor.put_labels(target.iter().map(|l| l.as_bytes()))?,
            Self::Srv { port, target } => {
                // Matter always uses priority 0 and weight 0 (§4.3.1.14).
                cursor.put_u16(0)?;
                cursor.put_u16(0)?;
                cursor.put_u16(*port)?;
                cursor.put_labels(target.iter().map(|l| l.as_bytes()))?;
            }
            Self::Txt(bytes) => cursor.put(bytes)?,
            Self::Aaaa(address) => cursor.put(address)?,
            Self::A(address) => cursor.put(address)?,
        }
        cursor.finish()
    }

    /// The record type this data belongs to.
    #[must_use]
    pub const fn kind(&self) -> RecordType {
        match self {
            Self::Ptr(_) => RecordType::Ptr,
            Self::Srv { .. } => RecordType::Srv,
            Self::Txt(_) => RecordType::Txt,
            Self::Aaaa(_) => RecordType::Aaaa,
            Self::A(_) => RecordType::A,
        }
    }
}

/// The longest RDATA this crate writes uncompressed: an SRV's six fixed octets plus a name.
///
/// A name is at most [`LABELS_MAX`] labels of [`LABEL_MAX`] octets, each with a length octet,
/// plus the root.
pub const RDATA_MAX: usize = 6 + LABELS_MAX * (LABEL_MAX + 1) + 1;

/// Writes bytes into a fixed buffer, refusing rather than truncating.
struct Cursor<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.at.checked_add(bytes.len()).ok_or_else(no_space)?;
        let slot = self.buf.get_mut(self.at..end).ok_or_else(no_space)?;
        slot.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    fn put_u16(&mut self, value: u16) -> Result<()> {
        self.put(&value.to_be_bytes())
    }

    /// An uncompressed name: each label length-prefixed, terminated by the root's zero octet.
    fn put_labels<'l>(&mut self, labels: impl Iterator<Item = &'l [u8]>) -> Result<()> {
        for label in labels {
            let length = u8::try_from(label.len()).map_err(|_| Error::new(ErrorCode::NoSpace))?;
            if usize::from(length) > LABEL_MAX {
                bail!(NoSpace)
            }
            self.put(&[length])?;
            self.put(label)?;
        }
        self.put(&[0])
    }

    fn finish(self) -> Result<&'a [u8]> {
        self.buf.get(..self.at).ok_or_else(no_space)
    }
}

/// How many distinct names a writer remembers for compression.
///
/// A Matter response has an instance name, a service name, a domain, a host name and up to
/// five subtype names — and compression only pays for a name that repeats, which in practice
/// is the last three. Sixteen is comfortably more than enough and costs a few hundred bytes of
/// stack.
const COMPRESSION_SLOTS: usize = 16;

/// Writes a DNS message, compressing names as it goes.
///
/// The compression is RFC 1035 §4.1.4's: a name whose *suffix* has already been written is
/// emitted as its own leading labels followed by a two-octet pointer to that suffix. For a
/// Matter commissionable response — four PTRs, an SRV, a TXT and an AAAA, all ending in
/// `_matterc._udp.local.` — that is the difference between fitting one datagram and not.
pub struct DnsWriter<'a, 'n> {
    buf: &'a mut [u8],
    at: usize,
    /// `(offset, labels)` for every name suffix written so far.
    seen: Vec<(u16, &'n [&'n str]), COMPRESSION_SLOTS>,
    counts: [u16; 4],
}

impl<'a, 'n> DnsWriter<'a, 'n> {
    /// Starts a message with a twelve-octet header, to be filled in by [`DnsWriter::finish`].
    pub fn new(buf: &'a mut [u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            bail!(NoSpace)
        }
        let mut writer = Self {
            buf,
            at: 0,
            seen: Vec::new(),
            counts: [0; 4],
        };
        // The header is written last, once the counts are known — but the space has to be
        // reserved first, because every compression offset is relative to the message start.
        writer.at = HEADER_LEN;
        Ok(writer)
    }

    /// Writes a question.
    ///
    /// Questions come before answers; a writer that has already written an answer refuses,
    /// because the header's counts would no longer describe the message.
    pub fn question(&mut self, name: &'n [&'n str], kind: RecordType, unicast: bool) -> Result<()> {
        if self.counts.get(1).copied().unwrap_or(0) != 0 {
            bail!(InvalidState)
        }
        self.name(name)?;
        self.u16(kind.value())?;
        self.u16(if unicast {
            CLASS_IN | UNICAST_RESPONSE
        } else {
            CLASS_IN
        })?;
        self.bump(0)
    }

    /// Writes a record into the Answer section.
    pub fn answer(&mut self, record: &Record<'n>) -> Result<()> {
        self.record(record)?;
        self.bump(1)
    }

    /// Writes a record into the Authority section.
    ///
    /// RFC 6762 §8.2: a probe query "populates the query message's Authority Section with the
    /// record or records with the rdata that it would be proposing to use, should its probing
    /// be successful … for tiebreaking to work correctly in all cases, the Authority Section
    /// must contain *all* the records and proposed rdata being probed for uniqueness". It is
    /// also what lets a receiver tell a probe from an ordinary query (§6).
    pub fn authority(&mut self, record: &Record<'n>) -> Result<()> {
        self.record(record)?;
        self.bump(2)
    }

    /// Writes a record into the Additional section.
    ///
    /// RFC 6762 §6.2: a responder "SHOULD include in the Additional Section" the records a
    /// querier will need next — the SRV and TXT for a PTR it answered, the AAAA for an SRV.
    /// Doing so is what turns a three-round-trip discovery into one.
    pub fn additional(&mut self, record: &Record<'n>) -> Result<()> {
        self.record(record)?;
        self.bump(3)
    }

    /// How many records are in each section: questions, answers, authority, additional.
    #[must_use]
    pub const fn counts(&self) -> [u16; 4] {
        self.counts
    }

    /// Fills in the header and returns the message.
    ///
    /// `id` is the transaction id, which RFC 6762 §18.1 makes zero for an unsolicited
    /// announcement and the query's id for a response to one.
    pub fn finish(self, id: u16, flags: u16) -> Result<&'a [u8]> {
        let header = [
            id.to_be_bytes(),
            flags.to_be_bytes(),
            self.counts.first().copied().unwrap_or(0).to_be_bytes(),
            self.counts.get(1).copied().unwrap_or(0).to_be_bytes(),
            self.counts.get(2).copied().unwrap_or(0).to_be_bytes(),
            self.counts.get(3).copied().unwrap_or(0).to_be_bytes(),
        ];
        let slot = self.buf.get_mut(..HEADER_LEN).ok_or_else(no_space)?;
        for (index, pair) in header.iter().enumerate() {
            let start = index.saturating_mul(2);
            let end = start.saturating_add(2);
            if let Some(target) = slot.get_mut(start..end) {
                target.copy_from_slice(pair);
            }
        }
        self.buf.get(..self.at).ok_or_else(no_space)
    }

    fn bump(&mut self, section: usize) -> Result<()> {
        let slot = self.counts.get_mut(section).ok_or_else(malformed)?;
        *slot = slot.checked_add(1).ok_or_else(no_space)?;
        Ok(())
    }

    fn record(&mut self, record: &Record<'n>) -> Result<()> {
        self.name(record.name)?;
        self.u16(record.data.kind().value())?;
        self.u16(if record.cache_flush {
            CLASS_IN | CACHE_FLUSH
        } else {
            CLASS_IN
        })?;
        self.u32(record.ttl)?;
        // RDLENGTH is not known until the RDATA is written, and the RDATA may itself contain a
        // compressed name — so the length is written as a placeholder and patched.
        let length_at = self.at;
        self.u16(0)?;
        let start = self.at;
        match record.data {
            RecordData::Ptr(target) => self.name(target)?,
            RecordData::Srv { port, target } => {
                // Priority and weight are both zero: Matter advertises one instance per
                // service, so there is nothing to prioritise between.
                self.u16(0)?;
                self.u16(0)?;
                self.u16(port)?;
                // RFC 2782 says an SRV target must not be compressed; RFC 6762 §18.14 says
                // Multicast DNS responders MAY compress it, and every deployed one does.
                self.name(target)?;
            }
            RecordData::Txt(bytes) => self.bytes(bytes)?,
            RecordData::Aaaa(address) => self.bytes(&address)?,
            RecordData::A(address) => self.bytes(&address)?,
        }
        let length = self.at.checked_sub(start).ok_or_else(malformed)?;
        let length = u16::try_from(length).map_err(|_| no_space())?;
        if let Some(slot) = self.buf.get_mut(length_at..length_at.saturating_add(2)) {
            slot.copy_from_slice(&length.to_be_bytes());
        }
        Ok(())
    }

    /// Writes a name, compressing against the longest suffix already written.
    ///
    /// Label by label: at each position, ask whether the *remaining* suffix has been written
    /// before. If it has, emit a pointer to it and stop — the labels before it are already on
    /// the wire, because this loop put them there. Writing them again is the mistake that
    /// makes a message decode to a name with every label doubled.
    fn name(&mut self, labels: &'n [&'n str]) -> Result<()> {
        for skip in 0..labels.len() {
            let tail = labels.get(skip..).unwrap_or(&[]);
            if let Some(offset) = self.find(tail) {
                return self.u16(0xC000 | offset);
            }
            // Not found: remember where this suffix will start, then write its first label.
            let offset = u16::try_from(self.at).ok();
            // RFC 1035's pointer is fourteen bits, so a name past 0x3FFF cannot be pointed at.
            // Recording it anyway would emit a pointer with the top bits truncated.
            if let Some(offset) = offset.filter(|value| *value < 0x4000) {
                let _ = self.seen.push((offset, tail));
            }
            let label = labels.get(skip).ok_or_else(malformed)?;
            self.label(label)?;
        }
        self.byte(0)
    }

    fn find(&self, tail: &[&str]) -> Option<u16> {
        self.seen
            .iter()
            .find(|(_, seen)| {
                seen.len() == tail.len()
                    && seen
                        .iter()
                        .zip(tail.iter())
                        .all(|(a, b)| a.as_bytes().eq_ignore_ascii_case(b.as_bytes()))
            })
            .map(|(offset, _)| *offset)
    }

    fn label(&mut self, label: &str) -> Result<()> {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > LABEL_MAX {
            bail!(InvalidArgument)
        }
        self.byte(u8::try_from(bytes.len()).map_err(|_| no_space())?)?;
        self.bytes(bytes)
    }

    fn byte(&mut self, value: u8) -> Result<()> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<()> {
        self.bytes(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<()> {
        self.bytes(&value.to_be_bytes())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<()> {
        let end = self.at.checked_add(value.len()).ok_or_else(no_space)?;
        let slot = self.buf.get_mut(self.at..end).ok_or_else(no_space)?;
        slot.copy_from_slice(value);
        self.at = end;
        Ok(())
    }
}

/// The twelve-octet DNS header (RFC 1035 §4.1.1).
pub const HEADER_LEN: usize = 12;

/// `QR | AA` — the flags on a Multicast DNS response (RFC 6762 §18.2, §18.4).
///
/// "In response messages the Authoritative Answer bit MUST be set to one", and multicast DNS
/// has no notion of a non-authoritative answer.
pub const FLAGS_RESPONSE: u16 = 0x8400;

/// The flags on a Multicast DNS query: all zero (RFC 6762 §18.1–18.11).
pub const FLAGS_QUERY: u16 = 0x0000;

fn no_space() -> Error {
    Error::new(ErrorCode::NoSpace)
}

/// One question read from a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The name asked about.
    pub name: Name,
    /// The type asked for. `ANY` is ordinary in Multicast DNS.
    pub kind: RecordType,
    /// RFC 6762 §5.4's unicast-response bit.
    pub unicast: bool,
}

/// Reads the questions from a DNS message.
///
/// Only the questions: a responder has no use for another responder's answers beyond RFC
/// 6762 §7.1's known-answer suppression, which needs a cache this module does not have.
#[derive(Debug, Clone)]
pub struct Questions<'a> {
    buf: &'a [u8],
    at: usize,
    left: u16,
}

impl<'a> Questions<'a> {
    /// Reads a message's header and positions at its first question.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let header = buf.get(..HEADER_LEN).ok_or_else(truncated)?;
        let count = u16::from_be_bytes([
            header.get(4).copied().ok_or_else(truncated)?,
            header.get(5).copied().ok_or_else(truncated)?,
        ]);
        Ok(Self {
            buf,
            at: HEADER_LEN,
            left: count,
        })
    }

    /// The message's transaction id.
    #[must_use]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([
            self.buf.first().copied().unwrap_or(0),
            self.buf.get(1).copied().unwrap_or(0),
        ])
    }

    /// Whether this message is a response — RFC 1035's `QR` bit.
    ///
    /// A responder ignores responses: RFC 6762 §6 has it answer queries only, and answering a
    /// response would be an easy way to make two devices talk to each other forever.
    #[must_use]
    pub fn is_response(&self) -> bool {
        self.buf.get(2).copied().unwrap_or(0) & 0x80 != 0
    }
}

impl Iterator for Questions<'_> {
    type Item = Result<Question>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left = self.left.saturating_sub(1);
        Some(self.read())
    }
}

impl Questions<'_> {
    fn read(&mut self) -> Result<Question> {
        let (name, after) = Name::decode(self.buf, self.at)?;
        let kind_at = after;
        let class_at = kind_at.checked_add(2).ok_or_else(malformed)?;
        let end = class_at.checked_add(2).ok_or_else(malformed)?;
        let kind = u16::from_be_bytes([
            self.buf.get(kind_at).copied().ok_or_else(truncated)?,
            self.buf
                .get(kind_at.saturating_add(1))
                .copied()
                .ok_or_else(truncated)?,
        ]);
        let class = u16::from_be_bytes([
            self.buf.get(class_at).copied().ok_or_else(truncated)?,
            self.buf
                .get(class_at.saturating_add(1))
                .copied()
                .ok_or_else(truncated)?,
        ]);
        self.at = end;
        // A question for a class other than IN is not for us. It is not an error either —
        // "if the responder has no records that answer the question, it MUST NOT send any
        // response" — so it decodes as a type nothing matches.
        let kind = if class & !UNICAST_RESPONSE == CLASS_IN {
            RecordType::from_value(kind)
        } else {
            None
        };
        Ok(Question {
            name,
            kind: kind.unwrap_or(RecordType::Nsec),
            unicast: class & UNICAST_RESPONSE != 0,
        })
    }
}

/// Which section of a message a record was read from.
///
/// It matters: RFC 6762 §8.2's tiebreaker records live in the **Authority** section and are a
/// *proposal*, while a conflicting record in any other section is a *claim* — §9's conflict
/// resolution and §8.2's tiebreak are different rules with different outcomes, and telling
/// them apart starts here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Section {
    /// Answer — what the message asserts.
    Answer,
    /// Authority — for a probe query, the rdata the prober proposes to use (§8.2).
    Authority,
    /// Additional — what the sender thinks the receiver will want next (§6.2).
    Additional,
}

/// One resource record read from a message.
///
/// The RDATA is borrowed from the message, and a name inside it — a PTR's target, an SRV's
/// host — has already been decompressed into a [`Name`], because a pointer is meaningless
/// once separated from the message it points into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRecord<'a> {
    /// Which section the record came from.
    pub section: Section,
    /// The record class, with RFC 6762 §10.2's cache-flush bit masked off.
    ///
    /// §8.2 compares "the record class (excluding the cache-flush bit …)" first, so the bit has
    /// to be gone before a comparison rather than after it.
    pub class: u16,
    /// The owner name.
    pub name: Name,
    /// The record type, or `None` for one this crate does not model.
    ///
    /// Not an error: "Nodes SHALL silently ignore TXT record keys that they do not recognize"
    /// is the same spirit as ignoring a record type, and a responder on the link may publish
    /// anything.
    pub kind: Option<RecordType>,
    /// Seconds. Zero is RFC 6762 §10.1's goodbye — "this record is going away".
    pub ttl: u32,
    /// RFC 6762 §10.2's cache-flush bit.
    pub cache_flush: bool,
    /// The decoded data, for the types this crate models.
    pub data: Option<ReadData<'a>>,
}

/// The decoded RDATA of a read record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadData<'a> {
    /// `PTR` — the target name, decompressed.
    Ptr(Name),
    /// `SRV` — the port and the target host, decompressed.
    Srv {
        /// The advertised port.
        port: u16,
        /// The target host name.
        target: Name,
    },
    /// `TXT` — the raw key/value strings, to be read with
    /// [`TxtReader`](crate::discovery::txt::TxtReader).
    Txt(&'a [u8]),
    /// `AAAA` — an IPv6 address.
    Aaaa([u8; 16]),
    /// `A` — an IPv4 address. Matter "does not use IPv4"; a reader still has to step over one.
    A([u8; 4]),
}

impl ReadData<'_> {
    /// Writes the RDATA **uncompressed**, the form RFC 6762 §8.2's tiebreak compares.
    ///
    /// The mirror of [`RecordData::write_rdata`], for a record that arrived on the wire: the
    /// names here were decompressed on decode, so this re-serialises them in the canonical
    /// form both sides of a tiebreak must be in.
    ///
    /// [`RDATA_MAX`] is always enough.
    pub fn write_rdata<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut cursor = Cursor::new(buf);
        match self {
            Self::Ptr(target) => cursor.put_labels(target.labels())?,
            Self::Srv { port, target } => {
                cursor.put_u16(0)?;
                cursor.put_u16(0)?;
                cursor.put_u16(*port)?;
                cursor.put_labels(target.labels())?;
            }
            Self::Txt(bytes) => cursor.put(bytes)?,
            Self::Aaaa(address) => cursor.put(address)?,
            Self::A(address) => cursor.put(address)?,
        }
        cursor.finish()
    }
}

/// Reads the resource records of a message, in wire order across all three sections.
///
/// A Matter commissioner needs this: a `_matterc._udp` browse answers with a PTR, and the
/// Additional section carries the SRV, TXT and AAAA that turn it into an address and a port.
#[derive(Debug, Clone)]
pub struct ResourceRecords<'a> {
    buf: &'a [u8],
    at: usize,
    /// How many records remain in each of Answer, Authority and Additional, in wire order.
    left: [u32; 3],
    /// Set once a record failed to decode: the cursor is no longer at a record boundary, so
    /// everything after it is noise.
    stopped: bool,
}

impl<'a> ResourceRecords<'a> {
    /// Positions at the first record, skipping the questions.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let header = buf.get(..HEADER_LEN).ok_or_else(truncated)?;
        let count_at = |index: usize| -> Result<u16> {
            let start = index.saturating_mul(2);
            Ok(u16::from_be_bytes([
                header.get(start).copied().ok_or_else(truncated)?,
                header
                    .get(start.saturating_add(1))
                    .copied()
                    .ok_or_else(truncated)?,
            ]))
        };
        let questions = count_at(2)?;
        let left = [
            u32::from(count_at(3)?),
            u32::from(count_at(4)?),
            u32::from(count_at(5)?),
        ];

        // Step over the questions: each is a name plus four octets.
        let mut at = HEADER_LEN;
        for _ in 0..questions {
            let (_, after) = Name::decode(buf, at)?;
            at = after.checked_add(4).ok_or_else(malformed)?;
        }
        Ok(Self {
            buf,
            at,
            left,
            stopped: false,
        })
    }

    /// Only the records of one section.
    ///
    /// Errors are **kept**, not filtered out. A caller reading the Authority section of a
    /// hostile message to tiebreak against it must be able to tell "there was no tiebreaker"
    /// from "the message was malformed"; silently dropping the error turns the second into the
    /// first, and the second is the one where a name gets claimed that should not have been.
    /// The underlying iteration stops at its first error, so at most one arrives.
    pub fn section(self, section: Section) -> impl Iterator<Item = Result<ReadRecord<'a>>> {
        self.filter(move |record| !matches!(record, Ok(record) if record.section != section))
    }
}

impl<'a> Iterator for ResourceRecords<'a> {
    type Item = Result<ReadRecord<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped {
            return None;
        }
        let index = self.left.iter().position(|left| *left != 0)?;
        if let Some(left) = self.left.get_mut(index) {
            *left = left.saturating_sub(1);
        }
        let section = match index {
            0 => Section::Answer,
            1 => Section::Authority,
            _ => Section::Additional,
        };
        // One error ends the iteration. After a record that did not decode, `at` is no longer
        // at a record boundary, so every further "record" is an arbitrary reading of whatever
        // follows — and a header claiming 65535 records would otherwise buy 65535 of them.
        let record = self.read(section);
        self.stopped = record.is_err();
        Some(record)
    }
}

impl<'a> ResourceRecords<'a> {
    fn read(&mut self, section: Section) -> Result<ReadRecord<'a>> {
        let (name, after) = Name::decode(self.buf, self.at)?;
        let be16 = |at: usize| -> Result<u16> {
            Ok(u16::from_be_bytes([
                self.buf.get(at).copied().ok_or_else(truncated)?,
                self.buf
                    .get(at.saturating_add(1))
                    .copied()
                    .ok_or_else(truncated)?,
            ]))
        };
        let kind_value = be16(after)?;
        let class = be16(after.checked_add(2).ok_or_else(malformed)?)?;
        let ttl_at = after.checked_add(4).ok_or_else(malformed)?;
        let ttl = u32::from_be_bytes([
            self.buf.get(ttl_at).copied().ok_or_else(truncated)?,
            self.buf
                .get(ttl_at.saturating_add(1))
                .copied()
                .ok_or_else(truncated)?,
            self.buf
                .get(ttl_at.saturating_add(2))
                .copied()
                .ok_or_else(truncated)?,
            self.buf
                .get(ttl_at.saturating_add(3))
                .copied()
                .ok_or_else(truncated)?,
        ]);
        let length_at = ttl_at.checked_add(4).ok_or_else(malformed)?;
        let length = usize::from(be16(length_at)?);
        let start = length_at.checked_add(2).ok_or_else(malformed)?;
        let end = start.checked_add(length).ok_or_else(malformed)?;
        let rdata = self.buf.get(start..end).ok_or_else(truncated)?;
        self.at = end;

        let kind = RecordType::from_value(kind_value);
        let data = match kind {
            // A name inside RDATA may point anywhere in the message, so it is decoded against
            // the whole buffer rather than against the RDATA slice.
            Some(RecordType::Ptr) => Some(ReadData::Ptr(Name::decode(self.buf, start)?.0)),
            Some(RecordType::Srv) => {
                let port = be16(start.checked_add(4).ok_or_else(malformed)?)?;
                let target = Name::decode(self.buf, start.checked_add(6).ok_or_else(malformed)?)?.0;
                Some(ReadData::Srv { port, target })
            }
            Some(RecordType::Txt) => Some(ReadData::Txt(rdata)),
            Some(RecordType::Aaaa) => {
                let address: [u8; 16] = rdata.try_into().map_err(|_| malformed())?;
                Some(ReadData::Aaaa(address))
            }
            Some(RecordType::A) => {
                let address: [u8; 4] = rdata.try_into().map_err(|_| malformed())?;
                Some(ReadData::A(address))
            }
            _ => None,
        };

        Ok(ReadRecord {
            section,
            class: class & !CACHE_FLUSH,
            name,
            kind,
            ttl,
            cache_flush: class & CACHE_FLUSH != 0,
            data,
        })
    }
}
