//! An in-process network with a virtual clock.
//!
//! This is a supported platform, not a test fixture. It
//! implements the same traits a real machine does, so the stack above it cannot tell the
//! difference — and it gives three things a real machine cannot:
//!
//! **Time costs nothing.** [`SimNet`] is itself the [`Timer`], and advances to the next
//! scheduled deadline instead of waiting for it, so an hour of an intermittently-connected
//! device's idle period, or the whole of MRP's five-transmission backoff ladder, runs in
//! microseconds.
//!
//! **The network misbehaves on demand.** [`SimNet`] drops, duplicates, delays and reorders
//! datagrams to a schedule you set, so "what happens when the third retransmission is the
//! one that gets through" is a test rather than a hope.
//!
//! **Everything is deterministic.** Same inputs, same interleaving, same result, every
//! time — including the pseudo-random choices, which come from a seeded generator you can
//! write down in the test.
//!
//! ```
//! use matter_kit::platform::sim::{SimNet, block_on};
//! use matter_kit::platform::{Timer, Udp, Duration};
//!
//! let net = SimNet::new(42);
//! let a = net.node(1);
//! let b = net.node(2);
//!
//! block_on(&net, async {
//!     a.send_to(b"hello", b.addr()).await.unwrap();
//!     let mut buf = [0u8; 32];
//!     let (n, from) = b.recv_from(&mut buf).await.unwrap();
//!     assert_eq!(&buf[..n], b"hello");
//!     assert_eq!(from, a.addr());
//! });
//! ```

use core::cell::{Cell, RefCell};
use core::future::{Future, poll_fn};
use core::task::Poll;

use heapless::Deque;

use super::{Clock, Duration, Granularity, Instant, KvStore, PeerAddr, Rng, Timer, Udp};
use crate::error::{Error, ErrorCode, Result};

/// How many datagrams one simulated node may have queued before sends start failing.
const QUEUE: usize = 32;
/// The largest simulated datagram.
const MTU: usize = crate::config::MAX_UDP_MESSAGE;
/// How many nodes one [`SimNet`] can hold.
const NODES: usize = 8;
/// How many key-value entries a [`SimKv`] holds.
const KV_ENTRIES: usize = 32;
/// The largest value a [`SimKv`] entry holds.
const KV_VALUE: usize = 1024;

/// A deterministic pseudo-random generator.
///
/// This is `xorshift64*`: three shifts and a multiply, no state beyond a `u64`, and a
/// period long enough for any test. It is **not** cryptographically secure and must never
/// be used for anything but simulation — which is why it lives here and not in a module a
/// real node would reach for.
#[derive(Debug)]
pub struct SimRng {
    state: Cell<u64>,
}

impl SimRng {
    /// Seeds the generator. A zero seed is replaced, since xorshift cannot leave zero.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: Cell::new(if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            }),
        }
    }

    /// The next value in the sequence.
    pub fn next(&self) -> u64 {
        let mut x = self.state.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state.set(x);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `0..bound`, or 0 when `bound` is 0.
    pub fn below(&self, bound: u32) -> u32 {
        // Modulo bias is irrelevant for a simulation, but dividing by zero is not: the
        // `checked_rem` is what makes `bound == 0` a value rather than a trap.
        self.next()
            .checked_rem(u64::from(bound))
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0)
    }

    /// True with probability `percent`/100.
    pub fn chance(&self, percent: u8) -> bool {
        self.below(100) < u32::from(percent)
    }
}

impl Rng for SimRng {
    fn fill(&self, out: &mut [u8]) -> Result<()> {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(bytes.iter()) {
                *dst = *src;
            }
        }
        Ok(())
    }
}

/// What the simulated network should do to the datagrams crossing it.
///
/// The defaults are a perfect network. Set a field and it stops being one, the same way
/// every time for a given [`SimNet`] seed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Impairment {
    /// Percentage of datagrams dropped outright.
    pub loss_percent: u8,
    /// Percentage of datagrams delivered twice.
    pub duplicate_percent: u8,
    /// Latency added to every datagram.
    pub latency: Duration,
    /// Extra latency added to a random fraction of datagrams, which is what reorders them.
    pub jitter: Duration,
}

impl Impairment {
    /// A network that loses the given percentage of datagrams and nothing else.
    #[must_use]
    pub const fn lossy(loss_percent: u8) -> Self {
        Self {
            loss_percent,
            duplicate_percent: 0,
            latency: Duration::ZERO,
            jitter: Duration::ZERO,
        }
    }

    /// A network with latency and jitter, which delivers out of order.
    #[must_use]
    pub const fn jittery(latency: Duration, jitter: Duration) -> Self {
        Self {
            loss_percent: 0,
            duplicate_percent: 0,
            latency,
            jitter,
        }
    }
}

/// One datagram in flight.
#[derive(Debug)]
struct InFlight {
    from: PeerAddr,
    to_node: u8,
    at: Instant,
    len: usize,
    data: [u8; MTU],
}

/// A simulated network: a virtual clock, a set of nodes, and the datagrams between them.
#[derive(Debug)]
pub struct SimNet {
    now: Cell<Instant>,
    rng: SimRng,
    impairment: Cell<Impairment>,
    /// Datagrams that have been sent but not yet delivered, ordered by nothing — the
    /// receiver picks the earliest that is due, which is what models reordering.
    flight: RefCell<Deque<InFlight, QUEUE>>,
    /// Deadlines that sleeping tasks are waiting for.
    deadlines: RefCell<Deque<Instant, QUEUE>>,
    /// Counters, for tests that assert on what the network did.
    sent: Cell<u32>,
    delivered: Cell<u32>,
    dropped: Cell<u32>,
    duplicated: Cell<u32>,
}

impl SimNet {
    /// A new network with a perfect link and a seeded generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            now: Cell::new(Instant::ZERO),
            rng: SimRng::new(seed),
            impairment: Cell::new(Impairment::default()),
            flight: RefCell::new(Deque::new()),
            deadlines: RefCell::new(Deque::new()),
            sent: Cell::new(0),
            delivered: Cell::new(0),
            dropped: Cell::new(0),
            duplicated: Cell::new(0),
        }
    }

    /// Sets what the link does to datagrams from now on.
    pub fn impair(&self, impairment: Impairment) {
        self.impairment.set(impairment);
    }

    /// A handle for the node with the given index, whose address is `fd00::<index>`.
    #[must_use]
    pub fn node(&self, index: u8) -> SimNode<'_> {
        SimNode { net: self, index }
    }

    /// The generator the network's own choices come from, also usable as an [`Rng`].
    #[must_use]
    pub const fn rng(&self) -> &SimRng {
        &self.rng
    }

    /// How many datagrams have been handed to [`Udp::send_to`].
    #[must_use]
    pub fn sent(&self) -> u32 {
        self.sent.get()
    }

    /// How many datagrams have been returned from [`Udp::recv_from`].
    #[must_use]
    pub fn delivered(&self) -> u32 {
        self.delivered.get()
    }

    /// How many datagrams the impairment dropped.
    #[must_use]
    pub fn dropped(&self) -> u32 {
        self.dropped.get()
    }

    /// How many datagrams the impairment duplicated.
    #[must_use]
    pub fn duplicated(&self) -> u32 {
        self.duplicated.get()
    }

    /// The current virtual time.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.now.get()
    }

    /// Moves virtual time to the earliest thing that is waiting — a sleeping task or a
    /// datagram in flight — and returns whether there was anything to move to.
    ///
    /// `false` means nothing can make progress: every task is blocked on something that
    /// will never happen. That is a deadlock, and in a simulation it is a bug in the code
    /// under test rather than a reason to wait longer.
    pub fn advance_to_next_event(&self) -> bool {
        let mut next = Instant::MAX;
        for d in self.deadlines.borrow().iter() {
            if *d < next {
                next = *d;
            }
        }
        for f in self.flight.borrow().iter() {
            if f.at < next {
                next = f.at;
            }
        }
        if next == Instant::MAX {
            return false;
        }
        if next > self.now.get() {
            self.now.set(next);
        }
        // Deadlines that have now passed are no longer pending.
        let mut kept: Deque<Instant, QUEUE> = Deque::new();
        let now = self.now.get();
        for d in self.deadlines.borrow().iter() {
            if *d > now {
                let _ = kept.push_back(*d);
            }
        }
        *self.deadlines.borrow_mut() = kept;
        true
    }

    /// Moves virtual time forward by `d`, delivering anything that becomes due.
    pub fn advance(&self, d: Duration) {
        let target = self.now.get().saturating_add(d);
        while self.now.get() < target {
            let before = self.now.get();
            if !self.advance_to_next_event() || self.now.get() > target {
                self.now.set(target);
                return;
            }
            if self.now.get() == before {
                // Something was already due; nothing to wait for.
                self.now.set(target);
                return;
            }
        }
    }

    fn register_deadline(&self, at: Instant) {
        let mut d = self.deadlines.borrow_mut();
        if d.iter().any(|x| *x == at) {
            return;
        }
        let _ = d.push_back(at);
    }

    /// Queues one datagram, applying the current impairment.
    fn enqueue(&self, from: PeerAddr, to_node: u8, data: &[u8]) -> Result<()> {
        self.sent.set(self.sent.get().saturating_add(1));
        let imp = self.impairment.get();

        if imp.loss_percent > 0 && self.rng.chance(imp.loss_percent) {
            self.dropped.set(self.dropped.get().saturating_add(1));
            return Ok(());
        }

        let copies = if imp.duplicate_percent > 0 && self.rng.chance(imp.duplicate_percent) {
            self.duplicated.set(self.duplicated.get().saturating_add(1));
            2
        } else {
            1
        };

        for _ in 0..copies {
            let jitter = if imp.jitter == Duration::ZERO {
                Duration::ZERO
            } else {
                let max = u32::try_from(imp.jitter.as_micros()).unwrap_or(u32::MAX);
                Duration::from_micros(u64::from(self.rng.below(max)))
            };
            let at = self
                .now
                .get()
                .saturating_add(imp.latency)
                .saturating_add(jitter);

            let Some(src) = data.get(..data.len().min(MTU)) else {
                return Err(Error::new(ErrorCode::BufferTooSmall));
            };
            let mut buf = [0u8; MTU];
            let Some(dst) = buf.get_mut(..src.len()) else {
                return Err(Error::new(ErrorCode::BufferTooSmall));
            };
            dst.copy_from_slice(src);

            let entry = InFlight {
                from,
                to_node,
                at,
                len: src.len(),
                data: buf,
            };
            if self.flight.borrow_mut().push_back(entry).is_err() {
                // A full queue is a congested network, which drops.
                self.dropped.set(self.dropped.get().saturating_add(1));
                return Ok(());
            }
            self.register_deadline(at);
        }
        Ok(())
    }

    /// Takes the earliest datagram due for `node`, if any is due now.
    fn dequeue(&self, node: u8, out: &mut [u8]) -> Option<(usize, PeerAddr)> {
        let now = self.now.get();
        let mut flight = self.flight.borrow_mut();

        // Find the earliest due entry for this node. Scanning is fine: the queue is small
        // by construction, and a real network has no order either.
        let mut best: Option<(usize, Instant)> = None;
        for (i, f) in flight.iter().enumerate() {
            if f.to_node == node && f.at <= now && best.is_none_or(|(_, at)| f.at < at) {
                best = Some((i, f.at));
            }
        }
        let (index, _) = best?;

        // `Deque` has no remove-at, so rotate the chosen entry to the front.
        let mut taken = None;
        let len = flight.len();
        for i in 0..len {
            let Some(entry) = flight.pop_front() else {
                break;
            };
            if i == index {
                taken = Some(entry);
            } else {
                let _ = flight.push_back(entry);
            }
        }
        let entry = taken?;

        let n = entry.len.min(out.len());
        let (Some(dst), Some(src)) = (out.get_mut(..n), entry.data.get(..n)) else {
            return None;
        };
        dst.copy_from_slice(src);
        self.delivered.set(self.delivered.get().saturating_add(1));
        Some((n, entry.from))
    }
}

impl Timer for SimNet {
    fn now(&self) -> Instant {
        self.now.get()
    }

    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        self.register_deadline(deadline);
        poll_fn(move |_| {
            if deadline.is_elapsed_at(self.now.get()) {
                Poll::Ready(())
            } else {
                self.register_deadline(deadline);
                Poll::Pending
            }
        })
    }
}

impl Clock for SimNet {
    fn utc(&self) -> Option<u64> {
        // The simulated wall clock is the virtual monotonic clock offset to 2024-01-01,
        // which is far enough into the Matter epoch for certificate validity to work.
        const Y2024: u64 = 757_382_400_000_000;
        Some(Y2024.saturating_add(self.now.get().as_micros()))
    }

    fn granularity(&self) -> Granularity {
        Granularity::MicrosecondsGranularity
    }
}

impl Rng for SimNet {
    fn fill(&self, out: &mut [u8]) -> Result<()> {
        self.rng.fill(out)
    }
}

/// One node's view of a [`SimNet`]: a [`Udp`] socket with an address.
#[derive(Debug, Clone, Copy)]
pub struct SimNode<'a> {
    net: &'a SimNet,
    index: u8,
}

impl SimNode<'_> {
    /// This node's address, `fd00::<index>` on the Matter port.
    #[must_use]
    pub fn addr(&self) -> PeerAddr {
        let mut a = [0u8; 16];
        a[0] = 0xfd;
        a[15] = self.index;
        PeerAddr::new(a)
    }

    /// The network this node is on.
    #[must_use]
    pub const fn net(&self) -> &SimNet {
        self.net
    }

    fn node_of(addr: PeerAddr) -> Option<u8> {
        if addr.addr[0] != 0xfd {
            return None;
        }
        addr.addr.last().copied()
    }
}

impl Udp for SimNode<'_> {
    fn recv_from(&self, buf: &mut [u8]) -> impl Future<Output = Result<(usize, PeerAddr)>> {
        poll_fn(move |_| match self.net.dequeue(self.index, buf) {
            Some(v) => Poll::Ready(Ok(v)),
            None => Poll::Pending,
        })
    }

    fn send_to(&self, buf: &[u8], addr: PeerAddr) -> impl Future<Output = Result<()>> {
        let result = match Self::node_of(addr) {
            Some(to) if usize::from(to) < NODES => self.net.enqueue(self.addr(), to, buf),
            // A datagram to an address no node holds is delivered nowhere, which is what
            // a real network does with it too.
            _ => Ok(()),
        };
        core::future::ready(result)
    }
}

/// An in-memory key-value store.
#[derive(Debug, Default)]
pub struct SimKv {
    entries:
        RefCell<heapless::Vec<(heapless::String<64>, heapless::Vec<u8, KV_VALUE>), KV_ENTRIES>>,
}

impl SimKv {
    /// An empty store — what a factory-fresh node has.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many keys are stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.borrow().is_empty()
    }
}

impl KvStore for SimKv {
    fn get(&self, key: &str, out: &mut [u8]) -> impl Future<Output = Result<Option<usize>>> {
        let result = (|| {
            let entries = self.entries.borrow();
            let Some((_, value)) = entries.iter().find(|(k, _)| k.as_str() == key) else {
                return Ok(None);
            };
            let Some(dst) = out.get_mut(..value.len()) else {
                return Err(Error::new(ErrorCode::BufferTooSmall));
            };
            dst.copy_from_slice(value);
            Ok(Some(value.len()))
        })();
        core::future::ready(result)
    }

    fn set(&self, key: &str, value: &[u8]) -> impl Future<Output = Result<()>> {
        let result = (|| {
            let mut entries = self.entries.borrow_mut();
            let stored =
                heapless::Vec::from_slice(value).map_err(|_| Error::new(ErrorCode::NoSpace))?;
            if let Some((_, slot)) = entries.iter_mut().find(|(k, _)| k.as_str() == key) {
                *slot = stored;
                return Ok(());
            }
            let name =
                heapless::String::try_from(key).map_err(|_| Error::new(ErrorCode::NoSpace))?;
            entries
                .push((name, stored))
                .map_err(|_| Error::new(ErrorCode::NoSpace))
        })();
        core::future::ready(result)
    }

    fn remove(&self, key: &str) -> impl Future<Output = Result<()>> {
        let mut entries = self.entries.borrow_mut();
        if let Some(i) = entries.iter().position(|(k, _)| k.as_str() == key) {
            entries.swap_remove(i);
        }
        core::future::ready(Ok(()))
    }

    fn remove_prefix(&self, prefix: &str) -> impl Future<Output = Result<()>> {
        let mut entries = self.entries.borrow_mut();
        entries.retain(|(k, _)| !k.as_str().starts_with(prefix));
        core::future::ready(Ok(()))
    }
}

/// Runs a future to completion on virtual time.
///
/// Polls the future; when it cannot make progress, advances the clock to the next
/// scheduled event and polls again. There is no thread, no executor and no waiting: a
/// scenario that would take an hour of wall-clock time finishes as fast as the code in it
/// can run.
///
/// # Panics
///
/// If the future is pending and nothing is scheduled — every task blocked on something
/// that will never arrive. In a simulation that is a deadlock in the code under test, and
/// reporting it immediately is far more useful than a test that hangs.
#[allow(clippy::panic)]
pub fn block_on<F: Future>(net: &SimNet, fut: F) -> F::Output {
    let waker = core::task::Waker::noop();
    let mut cx = core::task::Context::from_waker(waker);
    let mut fut = core::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => {
                assert!(
                    net.advance_to_next_event(),
                    "simulated deadlock: the future is pending and nothing is scheduled"
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_datagram_arrives() {
        let net = SimNet::new(1);
        let a = net.node(1);
        let b = net.node(2);
        block_on(&net, async {
            a.send_to(b"hello", b.addr()).await.unwrap();
            let mut buf = [0u8; 32];
            let (n, from) = b.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello");
            assert_eq!(from, a.addr());
        });
        assert_eq!(net.delivered(), 1);
    }

    #[test]
    fn virtual_time_costs_nothing() {
        let net = SimNet::new(1);
        let start = Timer::now(&net);
        block_on(&net, async {
            net.sleep(Duration::from_secs(3600)).await;
        });
        assert_eq!(
            Timer::now(&net).saturating_duration_since(start),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn loss_is_deterministic_for_a_seed() {
        fn run(seed: u64) -> u32 {
            let net = SimNet::new(seed);
            net.impair(Impairment::lossy(50));
            let a = net.node(1);
            let b = net.node(2);
            for _ in 0..100 {
                let _ = block_on(&net, a.send_to(b"x", b.addr()));
            }
            net.dropped()
        }
        let first = run(7);
        assert_eq!(first, run(7), "same seed, same drops");
        assert!(first > 20 && first < 80, "about half of 100, got {first}");
    }

    #[test]
    fn jitter_reorders() {
        let net = SimNet::new(3);
        net.impair(Impairment::jittery(
            Duration::from_millis(10),
            Duration::from_millis(50),
        ));
        let a = net.node(1);
        let b = net.node(2);
        block_on(&net, async {
            for i in 0u8..8 {
                a.send_to(&[i], b.addr()).await.unwrap();
            }
        });
        let mut order = heapless::Vec::<u8, 8>::new();
        block_on(&net, async {
            for _ in 0..8 {
                let mut buf = [0u8; 4];
                let (n, _) = b.recv_from(&mut buf).await.unwrap();
                assert_eq!(n, 1);
                let _ = order.push(buf[0]);
            }
        });
        assert_eq!(order.len(), 8, "everything arrives");
        assert_ne!(&order[..], &[0, 1, 2, 3, 4, 5, 6, 7], "but not in order");
    }

    #[test]
    fn duplicates_are_delivered_twice() {
        let net = SimNet::new(5);
        net.impair(Impairment {
            duplicate_percent: 100,
            ..Impairment::default()
        });
        let a = net.node(1);
        let b = net.node(2);
        block_on(&net, async {
            a.send_to(b"x", b.addr()).await.unwrap();
            let mut buf = [0u8; 4];
            b.recv_from(&mut buf).await.unwrap();
            b.recv_from(&mut buf).await.unwrap();
        });
        assert_eq!(net.delivered(), 2);
    }

    #[test]
    fn the_key_value_store_round_trips() {
        let net = SimNet::new(1);
        let kv = SimKv::new();
        block_on(&net, async {
            let mut buf = [0u8; 32];
            assert_eq!(kv.get("fabrics", &mut buf).await.unwrap(), None);
            kv.set("fabrics", b"abc").await.unwrap();
            assert_eq!(kv.get("fabrics", &mut buf).await.unwrap(), Some(3));
            assert_eq!(&buf[..3], b"abc");
            kv.set("fabrics", b"de").await.unwrap();
            assert_eq!(kv.get("fabrics", &mut buf).await.unwrap(), Some(2));
            kv.set("app/x", b"1").await.unwrap();
            kv.remove_prefix("app/").await.unwrap();
            assert_eq!(kv.get("app/x", &mut buf).await.unwrap(), None);
            assert_eq!(kv.len(), 1);
            kv.remove("fabrics").await.unwrap();
            assert!(kv.is_empty());
        });
    }

    #[test]
    fn a_too_small_buffer_is_an_error() {
        let net = SimNet::new(1);
        let kv = SimKv::new();
        block_on(&net, async {
            kv.set("k", b"0123456789").await.unwrap();
            let mut small = [0u8; 4];
            assert_eq!(
                kv.get("k", &mut small).await.unwrap_err().code(),
                ErrorCode::BufferTooSmall
            );
        });
    }
}
