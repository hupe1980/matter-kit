//! Turning a Matter advertisement into DNS records, and a query into a response
//! (Core §4.3, RFC 6762, RFC 6763).
//!
//! An [`Advertisement`] is the specification's record listing, as data:
//!
//! ```text
//! _matterc._udp.local.                    PTR   DD200C20D25AE5F7._matterc._udp.local.
//! _S3._sub._matterc._udp.local.           PTR   DD200C20D25AE5F7._matterc._udp.local.
//! _L840._sub._matterc._udp.local.         PTR   DD200C20D25AE5F7._matterc._udp.local.
//! _CM._sub._matterc._udp.local.           PTR   DD200C20D25AE5F7._matterc._udp.local.
//! DD200C20D25AE5F7._matterc._udp.local.   SRV   0 0 11111 B75AFB458ECD.local.
//! DD200C20D25AE5F7._matterc._udp.local.   TXT   "D=840" "CM=2"
//! B75AFB458ECD.local.                     AAAA  fe80::f515:576f:9783:3f30
//! ```
//!
//! — §4.3.1.14's own first example, which is also a test.
//!
//! # What a responder does, and what it does not
//!
//! [`Responder::respond`] answers a query: it walks the questions, finds the records that
//! match, and writes a response with the additional records RFC 6762 §6.2 asks for. That is
//! the part that is exact, testable, and the same on every platform.
//!
//! What it does not do is decide *when* to send. RFC 6762's probing (§8.1), its announcement
//! sequence (§8.3), its conflict resolution (§9) and its rate limits (§6) all need a timer and
//! a socket. Those belong to the integrator, and a responder that owned them could not be
//! tested without one.
//!
//! # The cache-flush bit is not set on everything
//!
//! RFC 6762 §10.2's bit tells a receiver to discard everything it had for a name and type. A
//! responder sets it on records it is uniquely authoritative for — its own SRV, TXT and AAAA —
//! and **clears it on the shared PTRs**, where every Matter device on the link legitimately
//! owns `_matterc._udp.local.` Setting it there would tell every receiver to forget the other
//! devices, which is a way to make a link's worth of commissionable nodes disappear by
//! advertising on it.

use heapless::Vec;

use super::dns::{
    DnsWriter, FLAGS_QUERY, FLAGS_RESPONSE, Name, Questions, Record, RecordData, RecordType,
    ResourceRecords, Section,
};
use super::{HOST_RECORD_TTL, LOCAL_DOMAIN, OTHER_RECORD_TTL, SUBTYPE_LABEL};
use crate::error::{Error, ErrorCode, Result};

/// How many subtypes one advertisement may carry.
///
/// §4.3.1.3 defines five for commissionable discovery — `_L`, `_S`, `_V`, `_T`, `_CM` — and
/// §4.3.2 two for operational. Six covers either with room to spare.
pub const SUBTYPES_MAX: usize = 6;

/// How many IPv6 addresses one advertisement may carry.
///
/// "Nodes SHALL publish AAAA records for all available IPv6 addresses upon which they are
/// willing to accept Matter commissioning messages" (§4.3.1.4) — a link-local, a global, and a
/// unique-local is the usual set.
pub const ADDRESSES_MAX: usize = 4;

/// How many services one responder may advertise at once.
///
/// A commissionable instance plus one operational instance per fabric — and `Config::FABRICS`
/// is at least five (§11.18.5.3) — so eight is the smallest number that covers a
/// minimum-conformance node with room for the commissionable advertisement beside it.
pub const ADVERTISEMENTS_MAX: usize = 8;

/// One Matter service instance, as the records that describe it.
///
/// The label slices are borrowed, not owned: the instance name, the service type, the host
/// name and every subtype outlive the responder, and a record set that copied them would be a
/// second place for them to be wrong.
#[derive(Debug, Clone)]
pub struct Advertisement<'a> {
    /// The instance label — sixteen hex digits for commissionable discovery,
    /// `<compressed>-<node>` for operational.
    pub instance: &'a str,
    /// The service type, as its two labels: `["_matterc", "_udp"]` or `["_matter", "_tcp"]`.
    pub service: [&'a str; 2],
    /// The host name label, without the domain — §4.3.1.1's twelve or sixteen hex digits.
    pub host: &'a str,
    /// The port the service listens on.
    pub port: u16,
    /// The encoded TXT record.
    pub txt: &'a [u8],
    /// Subtype labels, each including its leading underscore: `_S3`, `_L840`, `_CM`, `_I…`.
    pub subtypes: Vec<&'a str, SUBTYPES_MAX>,
    /// Every IPv6 address the node accepts Matter messages on.
    pub addresses: Vec<[u8; 16], ADDRESSES_MAX>,
}

impl<'a> Advertisement<'a> {
    /// An advertisement with no subtypes and no addresses yet.
    #[must_use]
    pub fn new(
        instance: &'a str,
        service: [&'a str; 2],
        host: &'a str,
        port: u16,
        txt: &'a [u8],
    ) -> Self {
        Self {
            instance,
            service,
            host,
            port,
            txt,
            subtypes: Vec::new(),
            addresses: Vec::new(),
        }
    }

    /// Adds a subtype label.
    pub fn with_subtype(mut self, subtype: &'a str) -> Result<Self> {
        self.subtypes
            .push(subtype)
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        Ok(self)
    }

    /// Adds an IPv6 address.
    pub fn with_address(mut self, address: [u8; 16]) -> Result<Self> {
        self.addresses
            .push(address)
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        Ok(self)
    }

    /// `<service>.<proto>.local.` — the name a browse asks for.
    #[must_use]
    pub fn service_name(&self) -> [&'a str; 3] {
        [self.service[0], self.service[1], LOCAL_DOMAIN]
    }

    /// `<instance>.<service>.<proto>.local.` — the name an SRV and TXT hang off.
    #[must_use]
    pub fn instance_name(&self) -> [&'a str; 4] {
        [
            self.instance,
            self.service[0],
            self.service[1],
            LOCAL_DOMAIN,
        ]
    }

    /// `<host>.local.` — the name an AAAA hangs off.
    #[must_use]
    pub fn host_name(&self) -> [&'a str; 2] {
        [self.host, LOCAL_DOMAIN]
    }

    /// `<subtype>._sub.<service>.<proto>.local.` — RFC 6763 §7.1's subtype name.
    #[must_use]
    pub fn subtype_name(&self, subtype: &'a str) -> [&'a str; 5] {
        [
            subtype,
            SUBTYPE_LABEL,
            self.service[0],
            self.service[1],
            LOCAL_DOMAIN,
        ]
    }
}

/// A record of the advertisement, with the names it needs kept alive alongside it.
///
/// The label arrays have to live somewhere while a record borrows them, and a record set is
/// built and consumed within one call — so they live here, and [`Records`] is what a caller
/// iterates.
#[derive(Debug)]
pub struct Records<'a> {
    service: [&'a str; 3],
    instance: [&'a str; 4],
    host: [&'a str; 2],
    subtypes: Vec<[&'a str; 5], SUBTYPES_MAX>,
    advertisement: &'a Advertisement<'a>,
}

impl<'a> Records<'a> {
    /// Builds the name arrays for an advertisement.
    #[must_use]
    pub fn new(advertisement: &'a Advertisement<'a>) -> Self {
        let mut subtypes = Vec::new();
        for subtype in &advertisement.subtypes {
            let _ = subtypes.push(advertisement.subtype_name(subtype));
        }
        Self {
            service: advertisement.service_name(),
            instance: advertisement.instance_name(),
            host: advertisement.host_name(),
            subtypes,
            advertisement,
        }
    }

    /// The service PTR — what a browse for `_matterc._udp.local.` is answered with.
    ///
    /// Shared, so the cache-flush bit is clear: every Matter device on the link owns this name.
    #[must_use]
    pub fn service_ptr(&self) -> Record<'_> {
        Record {
            name: &self.service,
            kind: RecordType::Ptr,
            ttl: OTHER_RECORD_TTL,
            cache_flush: false,
            data: RecordData::Ptr(&self.instance),
        }
    }

    /// One PTR per subtype, each equally shared.
    pub fn subtype_ptrs(&self) -> impl Iterator<Item = Record<'_>> {
        self.subtypes.iter().map(|name| Record {
            name,
            kind: RecordType::Ptr,
            ttl: OTHER_RECORD_TTL,
            cache_flush: false,
            data: RecordData::Ptr(&self.instance),
        })
    }

    /// The SRV: priority 0, weight 0, the port, and the host.
    #[must_use]
    pub fn srv(&self) -> Record<'_> {
        Record {
            name: &self.instance,
            kind: RecordType::Srv,
            ttl: HOST_RECORD_TTL,
            cache_flush: true,
            data: RecordData::Srv {
                port: self.advertisement.port,
                target: &self.host,
            },
        }
    }

    /// The TXT record.
    #[must_use]
    pub fn txt(&self) -> Record<'_> {
        Record {
            name: &self.instance,
            kind: RecordType::Txt,
            // RFC 6762 §10 puts TXT with the long-lived records: it does not go stale when an
            // address changes, and a Matter TXT changes only when the node's state does.
            ttl: OTHER_RECORD_TTL,
            cache_flush: true,
            data: RecordData::Txt(self.advertisement.txt),
        }
    }

    /// One AAAA per address.
    pub fn addresses(&self) -> impl Iterator<Item = Record<'_>> {
        self.advertisement.addresses.iter().map(|address| Record {
            name: &self.host,
            kind: RecordType::Aaaa,
            ttl: HOST_RECORD_TTL,
            cache_flush: true,
            data: RecordData::Aaaa(*address),
        })
    }

    /// Every record, in the order §4.3.1.14 lists them: the service PTR, the subtype PTRs,
    /// the SRV, the TXT, then the addresses.
    pub fn all(&self) -> impl Iterator<Item = Record<'_>> {
        core::iter::once(self.service_ptr())
            .chain(self.subtype_ptrs())
            .chain(core::iter::once(self.srv()))
            .chain(core::iter::once(self.txt()))
            .chain(self.addresses())
    }
}

/// Answers Multicast DNS queries for one or more advertisements.
///
/// Holds no state and no socket: [`Responder::respond`] is a pure function of the query and
/// the advertisements, which is what makes every rule below testable without a network.
#[derive(Debug, Clone, Copy)]
pub struct Responder<'a> {
    /// The services this node advertises — a commissionable one, an operational one per
    /// fabric, or both.
    pub advertisements: &'a [Advertisement<'a>],
}

/// What answering a query produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answered {
    /// How many records went into the Answer section.
    pub answers: usize,
    /// How many went into Additional.
    pub additional: usize,
    /// Whether the querier asked for a unicast reply (RFC 6762 §5.4).
    ///
    /// "a special bit in the rrclass field of the question … indicating that the querier is
    /// willing to accept unicast replies". Set if *any* question asked for one, which is the
    /// conservative reading: a unicast reply reaches the asker either way.
    pub unicast: bool,
    /// Whether the query was a probe — RFC 6762 §8.1, someone else claiming a name.
    ///
    /// §6: "a probe query can be distinguished from a normal query by the fact that a probe
    /// query contains a proposed record in the Authority Section that answers the question in
    /// the Question Section". If this is set and anything matched, the responder is *defending*
    /// a name it owns: answer immediately with no random delay
    /// ([`Answering::Probe`](crate::discovery::schedule::Answering::Probe)) and against the
    /// shorter rate limit of
    /// [`DEFEND_INTERVAL`](crate::discovery::schedule::DEFEND_INTERVAL). The prober has 750 ms
    /// in total, so an answer that waits its usual turn arrives after the name is gone.
    pub probe: bool,
}

impl Answered {
    /// Whether anything at all matched.
    ///
    /// RFC 6762 §6: "if the responder has no records that answer the question, it MUST NOT
    /// send any response". A caller that sent an empty response would be adding noise to the
    /// link for nothing — and on a Thread mesh, "excessive use of multicast would be
    /// detrimental" (§4.3).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.answers == 0
    }
}

impl<'a> Responder<'a> {
    /// A responder over a set of advertisements.
    #[must_use]
    pub const fn new(advertisements: &'a [Advertisement<'a>]) -> Self {
        Self { advertisements }
    }

    /// Answers `query`, writing a response into `buf`.
    ///
    /// Returns the response and what went into it. A caller that gets
    /// [`Answered::is_empty`] must **not** send: RFC 6762 §6 forbids it.
    pub fn respond<'b>(&self, query: &[u8], buf: &'b mut [u8]) -> Result<(&'b [u8], Answered)> {
        let questions = Questions::decode(query)?;
        // A response is not a query. Answering one is how two responders start talking to
        // each other and do not stop.
        if questions.is_response() {
            return Self::empty(buf, questions.id());
        }

        let mut unicast = false;
        let probe = Self::is_probe(query, &questions);
        // The record sets are built *before* the writer, because the writer's compression
        // table borrows the label arrays they own: a name recorded at one offset has to still
        // be there when a later record compresses against it.
        let sets = Self::record_sets(self.advertisements)?;

        let mut writer = DnsWriter::new(buf)?;
        let mut answers = 0usize;
        let mut additional = 0usize;

        for records in &sets {
            let mut matched_ptr = false;
            let mut matched_instance = false;

            for question in questions.clone() {
                let question = question?;
                unicast |= question.unicast;

                // A PTR question names a service or a subtype.
                if question.kind.answers(RecordType::Ptr) || question.kind == RecordType::Any {
                    if name_is(&question.name, &records.service) {
                        writer.answer(&records.service_ptr())?;
                        answers = answers.saturating_add(1);
                        matched_ptr = true;
                    }
                    for (index, subtype) in records.subtypes.iter().enumerate() {
                        if name_is(&question.name, subtype)
                            && let Some(record) = records.subtype_ptrs().nth(index)
                        {
                            writer.answer(&record)?;
                            answers = answers.saturating_add(1);
                            matched_ptr = true;
                        }
                    }
                }

                if name_is(&question.name, &records.instance) {
                    if RecordType::Srv.answers(question.kind) {
                        writer.answer(&records.srv())?;
                        answers = answers.saturating_add(1);
                        matched_instance = true;
                    }
                    if RecordType::Txt.answers(question.kind) {
                        writer.answer(&records.txt())?;
                        answers = answers.saturating_add(1);
                        matched_instance = true;
                    }
                }

                if name_is(&question.name, &records.host) && RecordType::Aaaa.answers(question.kind)
                {
                    for record in records.addresses() {
                        writer.answer(&record)?;
                        answers = answers.saturating_add(1);
                    }
                }
            }

            // RFC 6762 §6.2: "a Multicast DNS responder SHOULD include in the Additional
            // Section" what the querier will ask for next. A PTR answer implies the SRV and
            // TXT; either of those implies the addresses. Doing it here turns a three-round-
            // trip discovery into one, which on a Thread mesh is the difference that matters.
            if matched_ptr {
                writer.additional(&records.srv())?;
                writer.additional(&records.txt())?;
                additional = additional.saturating_add(2);
            }
            if matched_ptr || matched_instance {
                for record in records.addresses() {
                    writer.additional(&record)?;
                    additional = additional.saturating_add(1);
                }
            }
        }

        let id = questions.id();
        let bytes = writer.finish(id, FLAGS_RESPONSE)?;
        Ok((
            bytes,
            Answered {
                answers,
                additional,
                unicast,
                probe,
            },
        ))
    }

    /// Whether `query` is a probe (§8.1), per §6's test.
    ///
    /// "A probe query can be distinguished from a normal query by the fact that a probe query
    /// contains a proposed record in the Authority Section that answers the question in the
    /// Question Section." Both halves matter: an Authority record alone is not enough — a DNS
    /// Update carries one too — and neither is a question alone.
    ///
    /// A malformed message is not a probe. Getting this wrong in the lenient direction would
    /// let any sender opt out of §6's one-second multicast rate limit by claiming to probe.
    fn is_probe(query: &[u8], questions: &Questions<'_>) -> bool {
        let Ok(records) = ResourceRecords::decode(query) else {
            return false;
        };
        for record in records.section(Section::Authority) {
            let Ok(record) = record else { return false };
            for question in questions.clone() {
                let Ok(question) = question else { return false };
                if record.name == question.name
                    && record.kind.is_some_and(|kind| kind.answers(question.kind))
                {
                    return true;
                }
            }
        }
        false
    }

    /// Writes RFC 6762 §8.1's probe query for every name this responder wants to own.
    ///
    /// One question per unique name — the service instance and the host — with query type
    /// `ANY`, "to elicit answers for all types of records with that name … \[and\] verify
    /// exclusive ownership of a name for all rrtypes". The unicast-response bit is set: "the
    /// probes SHOULD be sent as 'QU' questions with the unicast-response bit set, to allow a
    /// defending host to respond immediately via unicast, instead of potentially having to
    /// wait before replying via multicast".
    ///
    /// The **shared** PTRs are deliberately absent. §8.1 probes "those resource records that a
    /// Multicast DNS responder desires to be unique on the local link", and a service PTR is
    /// the opposite: every commissionable node on the link owns `_matterc._udp.local.` at
    /// once, so probing for it would find a conflict every time there is a second Matter
    /// device present.
    ///
    /// The Authority section carries the SRV, TXT and AAAA being claimed — §8.2 requires
    /// "*all* the records and proposed rdata being probed for uniqueness" there, or a
    /// simultaneous prober cannot tiebreak against them.
    pub fn probe<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let sets = Self::record_sets(self.advertisements)?;
        let mut writer = DnsWriter::new(buf)?;
        // Several advertisements share one host name; asking for it twice would be wasted
        // space in a message that has 750 ms to reach everyone.
        let mut asked: Vec<&[&str], { ADVERTISEMENTS_MAX * 2 }> = Vec::new();
        for records in &sets {
            for name in [records.instance.as_slice(), records.host.as_slice()] {
                if asked.contains(&name) {
                    continue;
                }
                asked
                    .push(name)
                    .map_err(|_| Error::new(ErrorCode::NoSpace))?;
                writer.question(name, RecordType::Any, true)?;
            }
        }
        for records in &sets {
            writer.authority(&records.srv())?;
            writer.authority(&records.txt())?;
            for record in records.addresses() {
                writer.authority(&record)?;
            }
        }
        writer.finish(0, FLAGS_QUERY)
    }

    /// Writes every record of every advertisement — RFC 6762 §8.3's announcement.
    ///
    /// > The Multicast DNS responder MUST send at least two unsolicited responses, one second
    /// > apart. To provide increased robustness against packet loss, a responder MAY send up
    /// > to eight unsolicited responses.
    ///
    /// The *timing* is the caller's; this is what goes in each of them. An announcement has no
    /// questions and a transaction id of zero (§18.1: "In multicast query messages, the Query
    /// Identifier SHOULD be set to zero").
    pub fn announce<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let sets = Self::record_sets(self.advertisements)?;
        let mut writer = DnsWriter::new(buf)?;
        for records in &sets {
            for record in records.all() {
                writer.answer(&record)?;
            }
        }
        writer.finish(0, FLAGS_RESPONSE)
    }

    /// Writes every record with a TTL of zero — RFC 6762 §10.1's goodbye.
    ///
    /// > In the case where a host knows that certain resource record data is about to become
    /// > invalid … the host SHOULD send an unsolicited Multicast DNS response … with an RR TTL
    /// > of zero.
    ///
    /// §4.3.2.5 asks for exactly this when a node withdraws its `_IC` subtype: "SHALL withdraw
    /// it (using SRP update or DNS-SD with TTL=0)". A device that simply stopped answering
    /// would stay in every cache on the link for seventy-five minutes.
    pub fn goodbye<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let sets = Self::record_sets(self.advertisements)?;
        let mut writer = DnsWriter::new(buf)?;
        for records in &sets {
            for mut record in records.all() {
                record.ttl = 0;
                writer.answer(&record)?;
            }
        }
        writer.finish(0, FLAGS_RESPONSE)
    }

    fn record_sets(
        advertisements: &'a [Advertisement<'a>],
    ) -> Result<Vec<Records<'a>, ADVERTISEMENTS_MAX>> {
        let mut sets = Vec::new();
        for advertisement in advertisements {
            sets.push(Records::new(advertisement))
                .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        }
        Ok(sets)
    }

    fn empty(buf: &mut [u8], id: u16) -> Result<(&[u8], Answered)> {
        let writer = DnsWriter::new(buf)?;
        let bytes = writer.finish(id, FLAGS_RESPONSE)?;
        Ok((
            bytes,
            Answered {
                answers: 0,
                additional: 0,
                unicast: false,
                probe: false,
            },
        ))
    }
}

/// Whether a decoded name equals a label array, case-insensitively.
fn name_is(name: &Name, labels: &[&str]) -> bool {
    name.len() == labels.len()
        && name
            .labels()
            .zip(labels.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b.as_bytes()))
}
