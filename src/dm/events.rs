//! The event store (Core §7.14) — the node's log of things that happened.
//!
//! > Unlike attributes, which do not provide any edge-preserving capabilities (i.e. no
//! > guarantees that every attribute change will be conveyed to observers), events permit
//! > capturing every single edge or change and conveying it reliably to an observer. **This
//! > is critical for safety and security applications that rely upon such guarantees for
//! > correct behavior.**
//!
//! That is the whole difference. A subscriber that misses an attribute report learns the new
//! value on the next one; a subscriber that misses a `Leave` event never learns the node left.
//! So events are buffered, numbered, and delivered in order.
//!
//! # The number is the guarantee
//!
//! §7.14.1.1: "This number SHALL be monotonically increasing for the life of the node. **This
//! monotonicity guarantee SHALL be preserved across restarts.**" A client uses it to tell
//! "nothing happened" from "I missed something", and an `EventFilter` uses it to resume.
//!
//! Preserving it across a restart without writing to flash on every event is §7.14.1.1's own
//! recipe: reserve a block of numbers at start-up, hand them out from RAM, and reserve the
//! next block just before running out. [`EventNumbers`] is that, and the cost is stated
//! plainly — "When a node restarts, the event number MAY increase by a larger step than 1."
//!
//! # Priority decides what survives
//!
//! §7.14.2: "Event records SHALL be buffered on the Node, with priority given to events of a
//! higher priority level over a lower priority level. Within a priority level, newer event
//! records SHALL overwrite older event records."
//!
//! So the buffers are per priority and each is a ring: a flood of `Debug` records can never
//! push out a `Critical` one, which is what makes the safety guarantee hold under load. The
//! second sentence is the one that decides the data structure — **newer overwrites older**, so
//! a full buffer drops its oldest record rather than refusing the new one.

use heapless::Vec;

use crate::dm::meta::EventPriority;
use crate::im::{ClusterId, EndpointId, EventId, EventPath};
use crate::msg::FabricIndex;

/// How far ahead of the last durable value an event number is reserved.
///
/// §7.14.1.1's worked strategy: "write counter + N to storage, where N is a carefully chosen
/// number (e.g. 1000). This number N should be chosen carefully in order not to exhaust the
/// lifetime 64-bit counter space." A thousand is the specification's own example, and at one
/// flash write per thousand events a device generating one event a second writes once every
/// seventeen minutes.
pub const NUMBER_RESERVATION: u64 = 1000;

/// The node's event-number counter (§7.14.1.1).
///
/// Hands out numbers from RAM and tells the caller when to persist the next reservation, so
/// that monotonicity survives a restart without a flash write per event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventNumbers {
    next: u64,
    reserved_through: u64,
}

impl Default for EventNumbers {
    fn default() -> Self {
        Self::restore(0)
    }
}

impl EventNumbers {
    /// Resumes from the value that was last persisted.
    ///
    /// §7.14.1.1's step 1 and 2: "Read the counter value at start-up. Before processing any
    /// message, write counter + N to storage." So a fresh boot starts at the persisted value
    /// and immediately owes a write of `persisted + N` — which [`EventNumbers::reservation`]
    /// reports.
    #[must_use]
    pub const fn restore(persisted: u64) -> Self {
        Self {
            next: persisted,
            reserved_through: persisted,
        }
    }

    /// The value the node must persist before handing out any more numbers.
    ///
    /// `None` when the current reservation still has room. A caller that ignores this breaks
    /// the monotonicity guarantee *only across a restart* — which is exactly the kind of bug
    /// that never shows up in testing.
    #[must_use]
    pub const fn reservation(&self) -> Option<u64> {
        if self.next >= self.reserved_through {
            Some(self.next.saturating_add(NUMBER_RESERVATION))
        } else {
            None
        }
    }

    /// Records that `value` has been durably stored.
    pub const fn reserved(&mut self, value: u64) {
        if value > self.reserved_through {
            self.reserved_through = value;
        }
    }

    /// Takes the next event number.
    ///
    /// Returns `None` while a reservation is owed: handing out a number the node has not
    /// reserved is precisely how a restart rewinds the counter, and a record with a reused
    /// number tells a client that nothing happened when something did.
    pub const fn next(&mut self) -> Option<u64> {
        if self.next >= self.reserved_through {
            return None;
        }
        let number = self.next;
        self.next = self.next.saturating_add(1);
        Some(number)
    }

    /// The number the next event will take.
    #[must_use]
    pub const fn peek(&self) -> u64 {
        self.next
    }
}

/// The timestamp an event record carries (§7.14.1.2).
///
/// > This timestamp SHALL either be System Time in milliseconds or POSIX Time in
/// > milliseconds.
///
/// Which one a node uses depends on whether it knows the wall-clock time —
/// [`Clock::utc`](crate::platform::Clock::utc) returning `None` is exactly the case for
/// `System`. A node must not invent an epoch time it does not have: a client comparing
/// timestamps across nodes would be comparing an uptime with a date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timestamp {
    /// POSIX milliseconds.
    Epoch(u64),
    /// Milliseconds since boot.
    System(u64),
}

impl Timestamp {
    /// The value, whichever kind it is.
    #[must_use]
    pub const fn millis(self) -> u64 {
        match self {
            Self::Epoch(value) | Self::System(value) => value,
        }
    }

    /// The absolute `EventDataIB` form (§10.6.9).
    #[must_use]
    pub const fn absolute(self) -> crate::im::EventTimestamp {
        match self {
            Self::Epoch(value) => crate::im::EventTimestamp::Epoch(value),
            Self::System(value) => crate::im::EventTimestamp::System(value),
        }
    }

    /// The delta form against `previous`, when both are the same kind and `previous` is no
    /// later (§10.6.9.1, §10.6.9.2).
    ///
    /// `None` when they cannot be compared — different kinds, or a timestamp that went
    /// backwards — in which case the absolute form is the only correct encoding. Encoding a
    /// delta across a kind change would produce a number with no meaning at all.
    #[must_use]
    pub fn delta_from(self, previous: Self) -> Option<crate::im::EventTimestamp> {
        match (self, previous) {
            (Self::Epoch(now), Self::Epoch(before)) => Some(crate::im::EventTimestamp::DeltaEpoch(
                now.checked_sub(before)?,
            )),
            (Self::System(now), Self::System(before)) => Some(
                crate::im::EventTimestamp::DeltaSystem(now.checked_sub(before)?),
            ),
            _ => None,
        }
    }
}

/// The longest event payload one record holds.
///
/// An event's `Data` is "the cluster-specific payload of the Event" encoded as a TLV
/// structure. Matter's own events are small — §11.1.6's `StartUp` is one `uint32` — and a
/// device that needs more is describing something an event is the wrong shape for.
pub const EVENT_DATA_MAX: usize = 128;

/// One buffered event record (§7.14.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    /// `Number` — §7.14.1.1's node-scoped monotonic value.
    pub number: u64,
    /// Which endpoint, cluster and event this is.
    pub endpoint: EndpointId,
    /// The cluster.
    pub cluster: ClusterId,
    /// The event.
    pub event: EventId,
    /// `Priority` — "Each generated event record SHALL have an event priority that MAY
    /// override the defined priority for that event", so it is stored per record rather than
    /// looked up from the descriptor.
    pub priority: EventPriority,
    /// When it happened — "at the time it was created (and not when it is reported to a
    /// client)".
    pub timestamp: Timestamp,
    /// The fabric a fabric-sensitive event belongs to (§7.14.4).
    ///
    /// `None` for an event that "SHALL NOT be associated with a fabric", which is most of
    /// them. The distinction decides who may read the record, so it is part of it.
    pub fabric_index: Option<FabricIndex>,
    /// `Data` — the encoded TLV structure, tag included.
    ///
    /// §10.6.9.3: an event with no payload is "encoded as a struct with no member elements",
    /// not an absent field — so this is never empty.
    pub data: Vec<u8, EVENT_DATA_MAX>,
}

impl EventRecord {
    /// The `EventPathIB` this record reports under.
    #[must_use]
    pub const fn path(&self) -> EventPath {
        EventPath::event(self.endpoint, self.cluster, self.event)
    }

    /// Whether `path` — possibly a wildcard — names this record.
    ///
    /// §10.6.8: "Omission of the Endpoint, Cluster and Event tags SHALL have different
    /// interpretations depending on where the EventPathIB is used"; in a request they are
    /// wildcards. `IsUrgent` is not part of the match: it says how to *deliver*, not what.
    #[must_use]
    pub fn matches(&self, path: &EventPath) -> bool {
        path.endpoint.is_none_or(|wanted| wanted == self.endpoint)
            && path.cluster.is_none_or(|wanted| wanted == self.cluster)
            && path.event.is_none_or(|wanted| wanted == self.event)
    }

    /// Whether a subject on `accessing` may read this record (§7.14.4).
    ///
    /// > A read interaction SHALL NOT filter event records, based on fabric, for event records
    /// > that are not associated with a fabric.
    /// >
    /// > A read interaction SHALL NOT report fabric-sensitive event records that are
    /// > associated with a fabric different than the accessing fabric.
    ///
    /// Two sentences that pull in opposite directions, and both matter: an unassociated record
    /// is visible to everyone, and an associated one only to its own fabric. Treating the
    /// first like the second would hide a node's `StartUp` from every client.
    #[must_use]
    pub fn visible_to(&self, accessing: Option<FabricIndex>) -> bool {
        match self.fabric_index {
            None => true,
            Some(fabric) => accessing == Some(fabric),
        }
    }
}

/// A ring of records at one priority level.
///
/// §7.14.2: "Within a priority level, newer event records SHALL overwrite older event
/// records." So when it is full the *oldest* goes — a full buffer never refuses a new record,
/// because refusing would lose the edge that events exist to preserve.
#[derive(Debug)]
pub struct PriorityBuffer<const N: usize> {
    records: Vec<EventRecord, N>,
    /// How many records have been dropped to make room, so a caller can tell a client that
    /// its view has a hole in it.
    dropped: u64,
}

impl<const N: usize> Default for PriorityBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PriorityBuffer<N> {
    /// An empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            dropped: 0,
        }
    }

    /// Appends a record, dropping the oldest if there is no room.
    pub fn push(&mut self, record: EventRecord) {
        if self.records.len() >= N {
            if self.records.is_empty() {
                // `N == 0`: the buffer cannot hold anything, and the record is dropped whole
                // rather than half-stored.
                self.dropped = self.dropped.saturating_add(1);
                return;
            }
            self.records.remove(0);
            self.dropped = self.dropped.saturating_add(1);
        }
        // Cannot fail: room was just made.
        let _ = self.records.push(record);
    }

    /// The records, oldest first — which is the order §8.5 requires them reported in:
    /// "Each Report containing events SHALL deliver queued events without reordering the
    /// queue."
    #[must_use]
    pub fn records(&self) -> &[EventRecord] {
        &self.records
    }

    /// How many records have been lost to make room.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// How many are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Forgets every record with a number below `number` — what a client's acknowledged
    /// progress allows.
    pub fn prune_below(&mut self, number: u64) {
        self.records.retain(|record| record.number >= number);
    }
}

/// The node's event store: one ring per priority (§7.14.2).
///
/// > Event records SHALL be buffered on the Node, with priority given to events of a higher
/// > priority level over a lower priority level.
///
/// Separate buffers rather than one shared ring with a priority field, because that sentence
/// is a *guarantee*: a flood of `Debug` records must not be able to push out a `Critical` one,
/// and in a shared ring it always can. The sizes are the caller's, so a device that logs
/// heavily at `Debug` pays for it only there.
#[derive(Debug)]
pub struct EventStore<const C: usize, const I: usize, const D: usize> {
    critical: PriorityBuffer<C>,
    info: PriorityBuffer<I>,
    debug: PriorityBuffer<D>,
    numbers: EventNumbers,
}

impl<const C: usize, const I: usize, const D: usize> Default for EventStore<C, I, D> {
    fn default() -> Self {
        Self::new(EventNumbers::default())
    }
}

/// Why an event could not be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// The event-number counter needs a durable reservation first (§7.14.1.1).
    ///
    /// The caller must persist [`EventNumbers::reservation`] and call
    /// [`EventStore::reserved`], then try again. Handing out an unreserved number would let a
    /// restart rewind the counter — and a record with a reused number tells a client that
    /// nothing happened when something did.
    NeedsReservation(u64),
    /// The payload is longer than [`EVENT_DATA_MAX`].
    DataTooLong,
}

impl<const C: usize, const I: usize, const D: usize> EventStore<C, I, D> {
    /// An empty store resuming from a counter.
    #[must_use]
    pub const fn new(numbers: EventNumbers) -> Self {
        Self {
            critical: PriorityBuffer::new(),
            info: PriorityBuffer::new(),
            debug: PriorityBuffer::new(),
            numbers,
        }
    }

    /// The event-number counter.
    #[must_use]
    pub const fn numbers(&self) -> EventNumbers {
        self.numbers
    }

    /// Records that a reservation has been durably stored (§7.14.1.1 step 2).
    pub const fn reserved(&mut self, value: u64) {
        self.numbers.reserved(value);
    }

    /// Records an event, assigning it the next number.
    pub fn record(&mut self, event: &NewEvent<'_>) -> Result<u64, RecordError> {
        let NewEvent {
            endpoint,
            cluster,
            event: event_id,
            priority,
            timestamp,
            fabric_index,
            data,
        } = *event;
        let stored = Vec::from_slice(data).map_err(|_| RecordError::DataTooLong)?;
        let Some(number) = self.numbers.next() else {
            let owed = self
                .numbers
                .reservation()
                .unwrap_or(self.numbers.peek().saturating_add(NUMBER_RESERVATION));
            return Err(RecordError::NeedsReservation(owed));
        };
        let record = EventRecord {
            number,
            endpoint,
            cluster,
            event: event_id,
            priority,
            timestamp,
            fabric_index,
            data: stored,
        };
        match priority {
            EventPriority::Critical => self.critical.push(record),
            EventPriority::Info => self.info.push(record),
            EventPriority::Debug => self.debug.push(record),
        }
        Ok(number)
    }

    /// The buffer for one priority.
    #[must_use]
    pub const fn buffer(&self, priority: EventPriority) -> &dyn BufferView {
        match priority {
            EventPriority::Critical => &self.critical,
            EventPriority::Info => &self.info,
            EventPriority::Debug => &self.debug,
        }
    }

    /// Every buffered record matching `path`, visible to `accessing`, with a number at or
    /// above `min_number`, **in event-number order**.
    ///
    /// §8.5: "Each Report containing events SHALL deliver queued events without reordering the
    /// queue." Across priorities that means by number, because the number is the order things
    /// happened in — reporting all the `Critical` records before all the `Info` ones would
    /// hand a client a log that contradicts itself.
    pub fn matching<'a>(
        &'a self,
        path: &'a EventPath,
        accessing: Option<FabricIndex>,
        min_number: u64,
    ) -> impl Iterator<Item = &'a EventRecord> {
        let mut all: Vec<&'a EventRecord, 64> = Vec::new();
        for record in self
            .critical
            .records()
            .iter()
            .chain(self.info.records())
            .chain(self.debug.records())
        {
            if record.number >= min_number
                && record.matches(path)
                && record.visible_to(accessing)
                && all.push(record).is_err()
            {
                break;
            }
        }
        all.sort_unstable_by_key(|record| record.number);
        all.into_iter()
    }

    /// How many records are held, across every priority.
    #[must_use]
    pub fn len(&self) -> usize {
        self.critical
            .len()
            .saturating_add(self.info.len())
            .saturating_add(self.debug.len())
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets every record below `number`, across every priority.
    pub fn prune_below(&mut self, number: u64) {
        self.critical.prune_below(number);
        self.info.prune_below(number);
        self.debug.prune_below(number);
    }
}

/// An event about to be recorded.
///
/// A struct rather than seven parameters because the seven travel together — they come from
/// one thing happening — and because the three identifiers are all integers, which at a call
/// site is how an endpoint ends up where a cluster belongs.
#[derive(Debug, Clone, Copy)]
pub struct NewEvent<'a> {
    /// Which endpoint it happened on.
    pub endpoint: EndpointId,
    /// Which cluster.
    pub cluster: ClusterId,
    /// Which event.
    pub event: EventId,
    /// Its priority. "Each generated event record SHALL have an event priority that MAY
    /// override the defined priority for that event" — so it is given here, not looked up.
    pub priority: EventPriority,
    /// When it happened — "at the time it was created (and not when it is reported to a
    /// client)".
    pub timestamp: Timestamp,
    /// The fabric, for a fabric-sensitive event (§7.14.4); `None` otherwise.
    pub fabric_index: Option<FabricIndex>,
    /// The encoded TLV structure under context tag 7 — §10.6.9.3's "struct with no member
    /// elements" for an event that carries no payload.
    pub data: &'a [u8],
}

/// What a caller may ask of a priority buffer without knowing its size.
pub trait BufferView {
    /// The records, oldest first.
    fn records(&self) -> &[EventRecord];
    /// How many have been dropped to make room.
    fn dropped(&self) -> u64;
}

impl<const N: usize> BufferView for PriorityBuffer<N> {
    fn records(&self) -> &[EventRecord] {
        self.records()
    }

    fn dropped(&self) -> u64 {
        self.dropped()
    }
}

/// The node's event log, as §8.4.3.3's report writer needs to see it.
///
/// A trait rather than a concrete store for the same reason
/// [`AccessControl`](crate::im::AccessControl) and [`ClusterHandler`](crate::im::ClusterHandler)
/// are: [`EventStore`] is generic over three buffer sizes, and threading those through
/// [`Server`](crate::im::Server) would put a device's capacity choices into the type of every
/// read. The server needs one question answered — "which records match this path, for this
/// subject, from this number on" — and that is the whole trait.
///
/// The callback returns whether to continue, because a report stops when the message is full
/// and resumes in the next one: §10.2.3's chunking applies to events exactly as it does to
/// attributes.
pub trait EventSource: core::fmt::Debug {
    /// Every queued record matching `path`, visible to `accessing`, whose number is at least
    /// `min_number` — **in event-number order**, which §8.5 requires: "Each Report containing
    /// events SHALL deliver queued events without reordering the queue."
    ///
    /// Stops early when `each` returns `false`.
    fn each_matching(
        &self,
        path: &EventPath,
        accessing: Option<FabricIndex>,
        min_number: u64,
        each: &mut dyn FnMut(&EventRecord) -> bool,
    );

    /// The highest event number the node has assigned, or `None` when it has recorded nothing.
    ///
    /// §8.5.3.4: "Subsequent ReportData actions … SHALL include the latest EventNo associated
    /// with each node generating new events" — a subscription's bookmark moves to this even
    /// when nothing it asked for happened, so that a later report does not re-walk the whole
    /// log to discover that again.
    fn highest_number(&self) -> Option<u64>;
}

impl<const C: usize, const I: usize, const D: usize> EventSource for EventStore<C, I, D> {
    fn each_matching(
        &self,
        path: &EventPath,
        accessing: Option<FabricIndex>,
        min_number: u64,
        each: &mut dyn FnMut(&EventRecord) -> bool,
    ) {
        for record in self.matching(path, accessing, min_number) {
            if !each(record) {
                return;
            }
        }
    }

    fn highest_number(&self) -> Option<u64> {
        self.critical
            .records()
            .iter()
            .chain(self.info.records())
            .chain(self.debug.records())
            .map(|record| record.number)
            .max()
    }
}

/// A store a device keeps behind a [`RefCell`](core::cell::RefCell) is still an event source.
///
/// Recording needs `&mut`, reporting needs `&`, and both happen on one device between two
/// messages — so the store lives in a `RefCell` exactly as `DataVersions` does. Without this
/// impl a device would have to choose between recording events and serving them.
///
/// The borrow is taken for the duration of one walk. That is safe because the callback belongs
/// to the report writer, which does not record: a cluster that tried to log an event *while*
/// the log was being read would be re-entering its own store, and the panic that produces is a
/// better answer than the half-written report.
impl<T: EventSource> EventSource for core::cell::RefCell<T> {
    fn each_matching(
        &self,
        path: &EventPath,
        accessing: Option<FabricIndex>,
        min_number: u64,
        each: &mut dyn FnMut(&EventRecord) -> bool,
    ) {
        self.borrow()
            .each_matching(path, accessing, min_number, each);
    }

    fn highest_number(&self) -> Option<u64> {
        self.borrow().highest_number()
    }
}
