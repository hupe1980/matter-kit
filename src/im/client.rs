//! The client half of the interaction model: putting a chunked answer back together.
//!
//! A client's encoding is already done — [`encode_read_request`](crate::im::encode_read_request)
//! and its siblings build every request of chapter 10. What a client additionally needs, and
//! what a server does not, is the *inverse of chunking*.
//!
//! §10.2.3 splits a report "into multiple messages at logical boundaries due to the size
//! limitations imposed by IPv6 for UDP packets". A whole-node wildcard read therefore arrives
//! as a series of `ReportData` messages, each carrying part of the answer and all but the last
//! setting `MoreChunkedMessages`. A client that looked at only the first would silently see a
//! fraction of the node — and would have no way to know it, because the fraction it sees is
//! perfectly well-formed.
//!
//! [`ReportAssembler`] is the other side of [`Server::serve_chunk`](crate::im::Server::serve_chunk):
//! feed it every chunk, and it tells you when the answer is whole.
//!
//! # Between chunks, the client must speak
//!
//! §10.2.3: "each data message requires a response before the next data message can be sent".
//! The server will not send chunk *n+1* until the client's `StatusResponse` to chunk *n*
//! arrives, so a client that assembles without acknowledging waits forever on a server that is
//! waiting for it. [`ReportAssembler::push`] returning `false` is the signal to send one.
//!
//! # Lists arrive in pieces too
//!
//! A list too large for one message is sent as §10.6.4.3.1's series: one block clearing the
//! list, then one block per item with `ListIndex` null. The assembler keeps those blocks as
//! they came, in order, because reassembling them means knowing the attribute's *type* — which
//! is the application's knowledge, not the interaction model's.
//! [`AttributePath::list_index`](crate::im::AttributePath::list_index)
//! is how each block says which it is.

use crate::error::{Error, ErrorCode, Result, bail};
use crate::im::ib::AttributeReport;
use crate::im::message::ReportData;
use crate::tlv::{ContainerKind, TlvReader, Value};

/// An `Array` with an anonymous tag — Core Table 128's control octet.
const ANONYMOUS_ARRAY: u8 = 0x16;
/// End-of-container — §A.10: "control octet 0x18 exactly".
const END_OF_CONTAINER: u8 = 0x18;

/// Reassembles a report that arrived as a series of chunks (§10.2.3).
///
/// `N` is the byte budget for the assembled answer. A whole-node wildcard read of a real
/// device is several kilobytes, so this is the one place in the crate where a caller has to
/// size a buffer against *what it asked for* rather than against a message: the answer is by
/// definition larger than any single message, or it would not have been chunked.
#[derive(Debug)]
pub struct ReportAssembler<const N: usize> {
    /// A real `Array` element: the header, then every member seen so far, then — once the
    /// last chunk has arrived — its end-of-container.
    ///
    /// Storing the members bare would be smaller and wrong: §A.1 says "all valid TLV
    /// encodings consist of a single top-level element", so a bare run of members is not TLV
    /// anything can read, and [`ReportAssembler::assembled`] promises bytes that can be
    /// forwarded without looking.
    buf: [u8; N],
    len: usize,
    subscription_id: Option<u32>,
    chunks: usize,
    complete: bool,
}

impl<const N: usize> Default for ReportAssembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ReportAssembler<N> {
    /// An empty assembler.
    #[must_use]
    pub const fn new() -> Self {
        let mut buf = [0u8; N];
        buf[0] = ANONYMOUS_ARRAY;
        Self {
            buf,
            len: 1,
            subscription_id: None,
            chunks: 0,
            complete: false,
        }
    }

    /// Forgets everything, for the next read on the same buffer.
    pub const fn reset(&mut self) {
        self.buf[0] = ANONYMOUS_ARRAY;
        self.len = 1;
        self.subscription_id = None;
        self.chunks = 0;
        self.complete = false;
    }

    /// Whether the last chunk has arrived.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// How many messages the answer took.
    #[must_use]
    pub const fn chunks(&self) -> usize {
        self.chunks
    }

    /// The subscription this report belongs to, if any (§8.5.3.2).
    #[must_use]
    pub const fn subscription_id(&self) -> Option<u32> {
        self.subscription_id
    }

    /// Adds one chunk, returning whether the report is now complete.
    ///
    /// `false` means another `ReportData` is coming — and that the server is waiting for a
    /// `StatusResponse` before it sends one (§10.2.3).
    ///
    /// [`ErrorCode::NoSpace`] means the answer is larger than `N`. Nothing partial is kept:
    /// half a report is not a smaller report, it is a wrong one.
    pub fn push(&mut self, report: &ReportData<'_>) -> Result<bool> {
        if self.complete {
            // A chunk after the last one is not part of this answer. Accepting it would
            // silently splice two reports together.
            bail!(InvalidState)
        }
        // §8.5.3.2 requires every report of one subscription to carry the same id; a change
        // mid-answer means these are not chunks of the same thing.
        match (self.subscription_id, report.subscription_id) {
            (None, id) if self.chunks == 0 => self.subscription_id = id,
            (held, id) if held == id => {}
            _ => bail!(InvalidState),
        }

        if let Some(bytes) = report.attribute_reports_bytes() {
            self.append_members(bytes)?;
        }

        self.chunks = self.chunks.saturating_add(1);
        if !report.more_chunked_messages {
            self.push_byte(END_OF_CONTAINER)?;
            self.complete = true;
        }
        Ok(self.complete)
    }

    /// Copies each member of a captured `AttributeReports` array into the accumulator.
    ///
    /// Member by member rather than wholesale, because each chunk carries a *complete* array
    /// element — header and end-of-container included — and concatenating two of those would
    /// produce two arrays rather than one.
    fn append_members(&mut self, array: &[u8]) -> Result<()> {
        let mut reader = TlvReader::new_in(array, ContainerKind::Structure);
        let Some(head) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if head.value.container() != Some(ContainerKind::Array) {
            bail!(TlvWrongType)
        }
        loop {
            let start = reader.position();
            let Some(element) = reader.next_element()? else {
                return Ok(());
            };
            if element.value == Value::EndOfContainer {
                return Ok(());
            }
            reader.skip_value(&element)?;
            let member = reader.slice_from(start)?;
            let end = self
                .len
                .checked_add(member.len())
                // One byte is always reserved for the end-of-container, so a report that
                // exactly fills the buffer still closes.
                .and_then(|end| (end < N).then_some(end))
                .ok_or(Error::new(ErrorCode::NoSpace))?;
            let Some(slot) = self.buf.get_mut(self.len..end) else {
                bail!(NoSpace)
            };
            slot.copy_from_slice(member);
            self.len = end;
        }
    }

    fn push_byte(&mut self, byte: u8) -> Result<()> {
        let Some(slot) = self.buf.get_mut(self.len) else {
            bail!(NoSpace)
        };
        *slot = byte;
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// Every attribute report the answer carried, in the order it arrived.
    ///
    /// Order is part of the answer: §10.6.4.3.1's list encoding is a clearing block followed
    /// by its items, and reordering them would change what the list means.
    pub fn reports(&self) -> Reports<'_> {
        let mut reader = TlvReader::new(self.assembled());
        // Step over the array header. An incomplete answer has no end-of-container yet, so
        // this is also where an iteration before the last chunk stops being meaningful.
        let opened = matches!(
            reader.next_element(),
            Ok(Some(element)) if element.value.container() == Some(ContainerKind::Array)
        );
        Reports {
            reader,
            done: !opened,
        }
    }

    /// The assembled answer as one `Array` element.
    ///
    /// Valid TLV once [`ReportAssembler::is_complete`], and forwardable verbatim — a bridge
    /// relaying a report it does not understand needs exactly this.
    #[must_use]
    pub fn assembled(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

/// The attribute reports of an assembled answer, decoded one at a time.
#[derive(Debug)]
pub struct Reports<'a> {
    reader: TlvReader<'a>,
    done: bool,
}

impl<'a> Iterator for Reports<'a> {
    type Item = Result<AttributeReport<'a>>;

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
        if element.value.container() != Some(ContainerKind::Structure) {
            self.done = true;
            return Some(Err(Error::new(ErrorCode::TlvWrongType)));
        }
        match AttributeReport::decode(&mut self.reader) {
            Ok(report) => Some(Ok(report)),
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::im::ib::AttributeData;
    use crate::im::{AttributePath, encode_report_data};
    use crate::tlv::{Tag, TlvWriter};

    /// Builds a `ReportData` carrying `values` for attributes `first..`.
    fn chunk(buf: &mut [u8], first: u32, values: &[u64], more: bool) -> usize {
        let mut value_bufs: heapless::Vec<heapless::Vec<u8, 16>, 8> = heapless::Vec::new();
        for value in values {
            let mut scratch = [0u8; 16];
            let mut w = TlvWriter::new_in(&mut scratch, ContainerKind::Structure);
            w.unsigned(Tag::Context(2), *value).expect("value");
            let encoded = w.finish().expect("finish");
            value_bufs
                .push(heapless::Vec::from_slice(encoded).expect("fits"))
                .expect("fits");
        }
        let reports: heapless::Vec<AttributeReport<'_>, 8> = values
            .iter()
            .enumerate()
            .map(|(index, _)| {
                AttributeReport::Data(AttributeData {
                    data_version: Some(1),
                    path: AttributePath::attribute(1, 0x0006, first + index as u32),
                    data: &value_bufs[index],
                })
            })
            .collect();
        let bytes = encode_report_data(buf, None, reports, more, false).expect("encode");
        bytes.len()
    }

    #[test]
    fn a_report_split_across_messages_comes_back_whole_and_in_order() {
        let mut assembler = ReportAssembler::<512>::new();

        let mut first = [0u8; 256];
        let n = chunk(&mut first, 0, &[10, 11], true);
        let report = ReportData::decode(&first[..n]).expect("decode");
        assert!(
            !assembler.push(&report).expect("push"),
            "more is coming, and the server is waiting for a StatusResponse"
        );

        let mut second = [0u8; 256];
        let n = chunk(&mut second, 2, &[12], false);
        let report = ReportData::decode(&second[..n]).expect("decode");
        assert!(assembler.push(&report).expect("push"), "the last chunk");

        assert!(assembler.is_complete());
        assert_eq!(assembler.chunks(), 2);

        let paths: heapless::Vec<u32, 8> = assembler
            .reports()
            .map(|r| r.expect("decode").path().attribute.expect("concrete"))
            .collect();
        assert_eq!(
            paths.as_slice(),
            &[0, 1, 2],
            "every block, in the order it arrived — order is part of the answer"
        );
    }

    #[test]
    fn a_single_message_answer_is_complete_at_once() {
        let mut assembler = ReportAssembler::<256>::new();
        let mut buf = [0u8; 256];
        let n = chunk(&mut buf, 0, &[42], false);
        let report = ReportData::decode(&buf[..n]).expect("decode");
        assert!(assembler.push(&report).expect("push"));
        assert_eq!(assembler.chunks(), 1);
        assert_eq!(assembler.reports().count(), 1);
    }

    #[test]
    fn an_answer_larger_than_the_buffer_is_refused_rather_than_truncated() {
        // Half a report is not a smaller report, it is a wrong one — and a client that kept
        // the fraction would have no way to tell.
        let mut assembler = ReportAssembler::<24>::new();
        let mut buf = [0u8; 256];
        let n = chunk(&mut buf, 0, &[1, 2, 3, 4], false);
        let report = ReportData::decode(&buf[..n]).expect("decode");
        assert_eq!(
            assembler.push(&report).map_err(|e| e.code()),
            Err(ErrorCode::NoSpace)
        );
    }

    #[test]
    fn a_chunk_after_the_last_one_is_refused() {
        // Accepting it would splice two separate answers into one.
        let mut assembler = ReportAssembler::<256>::new();
        let mut buf = [0u8; 256];
        let n = chunk(&mut buf, 0, &[1], false);
        let report = ReportData::decode(&buf[..n]).expect("decode");
        assert!(assembler.push(&report).expect("push"));
        assert_eq!(
            assembler.push(&report).map_err(|e| e.code()),
            Err(ErrorCode::InvalidState)
        );
    }

    #[test]
    fn chunks_of_two_different_subscriptions_are_not_spliced_together() {
        // §8.5.3.2 requires every report of one subscription to carry the same id, so a
        // change mid-answer means these are not chunks of the same thing.
        let mut assembler = ReportAssembler::<512>::new();
        let mut first = [0u8; 256];
        let mut scratch = [0u8; 16];
        let mut w = TlvWriter::new_in(&mut scratch, ContainerKind::Structure);
        w.unsigned(Tag::Context(2), 1).expect("value");
        let value = w.finish().expect("finish").to_vec();
        let report = AttributeReport::Data(AttributeData {
            data_version: Some(1),
            path: AttributePath::attribute(1, 0x0006, 0),
            data: &value,
        });
        let bytes = encode_report_data(&mut first, Some(7), [report], true, false).expect("encode");
        let len = bytes.len();
        let decoded = ReportData::decode(&first[..len]).expect("decode");
        assert!(!assembler.push(&decoded).expect("push"));
        assert_eq!(assembler.subscription_id(), Some(7));

        let mut second = [0u8; 256];
        let report = AttributeReport::Data(AttributeData {
            data_version: Some(1),
            path: AttributePath::attribute(1, 0x0006, 1),
            data: &value,
        });
        let bytes =
            encode_report_data(&mut second, Some(9), [report], false, false).expect("encode");
        let len = bytes.len();
        let decoded = ReportData::decode(&second[..len]).expect("decode");
        assert_eq!(
            assembler.push(&decoded).map_err(|e| e.code()),
            Err(ErrorCode::InvalidState),
            "a different subscription id is a different answer"
        );
    }

    #[test]
    fn reset_makes_it_usable_for_the_next_read() {
        let mut assembler = ReportAssembler::<256>::new();
        let mut buf = [0u8; 256];
        let n = chunk(&mut buf, 0, &[1], false);
        let report = ReportData::decode(&buf[..n]).expect("decode");
        assembler.push(&report).expect("push");
        assembler.reset();
        assert!(!assembler.is_complete());
        assert_eq!(assembler.chunks(), 0);
        assert_eq!(assembler.reports().count(), 0);
        assembler.push(&report).expect("usable again");
        assert!(assembler.is_complete());
    }
}

// --- Subscriptions, from the client's side ---------------------------------------------------

/// What a client knows about a subscription it holds (§8.5).
///
/// The server's half lives in [`subscription`](crate::im::subscription); this is the twin a
/// controller keeps. It exists for one reason: §8.5.3.2 lets the server answer with intervals
/// that are *not* the ones requested —
///
/// > the publisher SHALL compute the MaxInterval ... and SHALL report it in the
/// > SubscribeResponse
///
/// — so a client that assumed its own ceiling had been honoured would declare a perfectly live
/// subscription dead, tear it down and build another, for ever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscription {
    /// `SubscriptionID`, which every subsequent report carries.
    id: u32,
    /// The `MaxInterval` the *publisher* chose, in seconds.
    max_interval_s: u16,
    /// When the last report or keep-alive arrived.
    last_heard: crate::platform::Instant,
}

impl Subscription {
    /// Records a subscription the publisher has just confirmed.
    #[must_use]
    pub const fn new(
        response: &crate::im::message::SubscribeResponse,
        now: crate::platform::Instant,
    ) -> Self {
        Self {
            id: response.subscription_id,
            max_interval_s: response.max_interval_s,
            last_heard: now,
        }
    }

    /// The id every report of this subscription carries.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// The `MaxInterval` the publisher chose — not the ceiling that was asked for.
    #[must_use]
    pub const fn max_interval_s(&self) -> u16 {
        self.max_interval_s
    }

    /// Records that something arrived on this subscription.
    ///
    /// Any report counts, including §8.5.3's empty keep-alive: "the publisher SHALL send an
    /// empty ReportData message" when nothing has changed by the maximum interval, and its
    /// whole purpose is to be this proof of life.
    ///
    /// Returns `false` — and records nothing — for a report belonging to a *different*
    /// subscription. §8.5.3.2 makes the id part of every report precisely so a subscriber
    /// holding several can tell them apart; crediting one subscription's liveness to another
    /// would keep a dead one alive indefinitely.
    pub fn heard(&mut self, report: &ReportData<'_>, now: crate::platform::Instant) -> bool {
        if report.subscription_id != Some(self.id) {
            return false;
        }
        self.last_heard = now;
        true
    }

    /// When this subscription should be considered lost (§8.5.4).
    ///
    /// > If the subscriber does not receive a report within the maximum interval ... the
    /// > subscriber SHALL consider the subscription to have expired.
    ///
    /// The window is deliberately generous: `MaxInterval` plus the time a report needs to
    /// traverse a lossy network and be retried by MRP. A subscriber that timed out at exactly
    /// `MaxInterval` would tear down a working subscription on the first retransmission — and
    /// a Thread network's first retransmission is not unusual.
    #[must_use]
    pub fn expires_at(&self) -> crate::platform::Instant {
        self.last_heard.saturating_add(
            crate::platform::Duration::from_secs(u64::from(self.max_interval_s))
                .saturating_add(LIVENESS_MARGIN),
        )
    }

    /// Whether the subscription has gone quiet for longer than §8.5.4 permits.
    #[must_use]
    pub fn is_expired(&self, now: crate::platform::Instant) -> bool {
        now >= self.expires_at()
    }
}

/// How long past `MaxInterval` a subscriber waits before giving up (§8.5.4).
///
/// §8.5.4 does not fix a number — it says a subscriber "SHALL consider the subscription to have
/// expired" without saying when to start counting past the interval. This is the allowance for
/// one MRP retransmission cycle over a sleepy network, which is the case that makes an exact
/// deadline wrong.
pub const LIVENESS_MARGIN: crate::platform::Duration = crate::platform::Duration::from_secs(10);
