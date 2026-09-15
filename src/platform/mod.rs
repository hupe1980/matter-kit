//! The seams between this crate and the machine it runs on.
//!
//! Matter needs sockets, a clock, randomness, storage and cryptography. None of those is
//! the protocol, and every one of them differs between a Linux bridge, an ESP32 and a
//! simulator. So they are traits, and the crate names no implementation of them: there is
//! no `tokio` and no `embassy-time` in its dependency tree, and a consumer who has already
//! chosen an executor keeps it.
//!
//! The traits are deliberately small. A platform is a handful of `async fn`s, not a
//! framework.
//!
//! # What is here
//!
//! | Trait | For |
//! |---|---|
//! | [`Timer`] | monotonic time and sleeping — every deadline in the specification |
//! | [`Clock`] | wall-clock UTC, which only the Time Synchronization cluster needs |
//! | [`Rng`] | cryptographically secure random bytes |
//! | [`Udp`] | IPv6 datagrams, the transport every Matter node must have |
//! | [`KvStore`] | opaque, versioned blobs that survive a reboot |
//!
//! Each has an implementation in [`sim`] — an in-process network with a virtual clock —
//! and, with the `std` feature, in [`crate::platform::os`].
//!
//! # Why the clock is a trait, and not `Instant::now()`
//!
//! Because half of Matter is timers. MRP retransmits on a backoff curve; a fail-safe
//! expires; an intermittently-connected device sleeps for an hour and wakes to check in; a
//! subscription dies if no report arrives inside its interval. Testing any of that against
//! a real clock means *waiting*, which means those paths get tested rarely, shallowly, and
//! flakily.
//!
//! With time as a parameter, [`sim::SimNet`] advances to the next scheduled deadline
//! instantly, so an hour-long intermittently-connected scenario is a unit test that
//! finishes in microseconds and fails the same way every time.

use core::future::Future;

pub mod sim;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod os;

mod time;

pub use time::{Duration, Instant};

use crate::error::Result;

/// Monotonic time, and the ability to wait for it.
///
/// "Monotonic" is the whole requirement: it must never go backwards, and it must not jump
/// when somebody sets the wall clock. Matter's deadlines are all durations from now.
pub trait Timer {
    /// How long since some fixed point this timer never changes.
    fn now(&self) -> Instant;

    /// Completes at `deadline`, or immediately if it has passed.
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()>;

    /// Completes after `duration`.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
        self.sleep_until(self.now().saturating_add(duration))
    }
}

/// Wall-clock time in UTC.
///
/// Separate from [`Timer`] because most nodes do not have one: a light with no real-time
/// clock and no Time Synchronization cluster implements [`NoClock`] and is none the worse.
/// Matter never uses wall-clock time for protocol deadlines, only for the Time
/// Synchronization cluster and for certificate validity.
pub trait Clock {
    /// Microseconds since the Matter epoch — 2000-01-01 00:00:00 UTC — or `None` when the
    /// node does not know the time.
    fn utc(&self) -> Option<u64>;

    /// Sets the current time, if the platform can. A node that cannot returns
    /// `Err(ErrorCode::Platform)`; the Time Synchronization cluster reports that honestly
    /// rather than pretending the write worked.
    fn set_utc(&self, _micros: u64) -> Result<()> {
        Err(crate::error::Error::new(crate::error::ErrorCode::Platform))
    }

    /// How precise [`Clock::utc`] is, as the Time Synchronization cluster's
    /// `Granularity` enumeration.
    fn granularity(&self) -> Granularity {
        Granularity::NoTimeGranularity
    }
}

/// How precisely a node knows the time (Core §11.17, `GranularityEnum`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Granularity {
    /// The node does not know the time at all.
    NoTimeGranularity = 0,
    /// Accurate to within a minute.
    MinutesGranularity = 1,
    /// Accurate to within a second.
    SecondsGranularity = 2,
    /// Accurate to within a millisecond.
    MillisecondsGranularity = 3,
    /// Accurate to within a microsecond.
    MicrosecondsGranularity = 4,
}

/// A node with no real-time clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoClock;

impl Clock for NoClock {
    fn utc(&self) -> Option<u64> {
        None
    }
}

/// A cryptographically secure random number generator.
///
/// Matter needs random bytes for nonces, ephemeral keys, exchange ids and the initial
/// message counter. A predictable one breaks the security of every session, so this is not
/// somewhere to save a few bytes of code: it must be a CSPRNG seeded from real entropy.
pub trait Rng {
    /// Fills `out` with random bytes.
    ///
    /// Returns `Err` only when the platform's entropy source has failed — which a node
    /// must treat as fatal rather than continue with predictable values.
    fn fill(&self, out: &mut [u8]) -> Result<()>;

    /// A random `u32`.
    fn next_u32(&self) -> Result<u32> {
        let mut b = [0u8; 4];
        self.fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// A random `u64`.
    fn next_u64(&self) -> Result<u64> {
        let mut b = [0u8; 8];
        self.fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// A random `u16`.
    fn next_u16(&self) -> Result<u16> {
        let mut b = [0u8; 2];
        self.fill(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }
}

/// An IPv6 address and port — where a Matter message came from, or goes to.
///
/// Matter is IPv6-only for operational communication (Core §2.5.6): "This protocol uses
/// IPv6 addressing for its operational communication." An IPv4 address cannot be a peer,
/// which is why this type has no variant for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerAddr {
    /// The 128-bit address, in network byte order.
    pub addr: [u8; 16],
    /// The UDP port; [`crate::PORT`] unless the peer announced another.
    pub port: u16,
    /// The scope zone for a link-local address, which is meaningless for other scopes.
    ///
    /// A link-local address (`fe80::/10`) is ambiguous without the interface it was seen
    /// on, and Matter uses link-local addresses routinely — a Thread node may have no
    /// other kind.
    pub scope_id: u32,
}

impl PeerAddr {
    /// Builds an address with the standard Matter port and no scope.
    #[must_use]
    pub const fn new(addr: [u8; 16]) -> Self {
        Self {
            addr,
            port: crate::PORT,
            scope_id: 0,
        }
    }

    /// Builds an address with an explicit port.
    #[must_use]
    pub const fn with_port(addr: [u8; 16], port: u16) -> Self {
        Self {
            addr,
            port,
            scope_id: 0,
        }
    }

    /// Whether this is a link-local address (`fe80::/10`), for which [`Self::scope_id`]
    /// is significant.
    #[must_use]
    pub const fn is_link_local(&self) -> bool {
        self.addr[0] == 0xfe && (self.addr[1] & 0xc0) == 0x80
    }

    /// Whether this is a multicast address (`ff00::/8`).
    #[must_use]
    pub const fn is_multicast(&self) -> bool {
        self.addr[0] == 0xff
    }
}

/// Where a Matter message came from, or goes to, whichever transport carried it.
///
/// A Matter node speaks more than one at once: during commissioning a device may be answering
/// BLE on one side and advertising over IPv6 on the other, and the reply to a message has to
/// go back the way it came.
///
/// The distinction is not only routing. Core §4.12.4:
///
/// > Reliable messages sent over TCP, PAFTP, or BTP SHALL utilize the underlying reliability
/// > mechanisms of those transports and SHOULD NOT set the R Flag.
///
/// So which transport a peer is on decides whether MRP runs at all, and
/// [`Messaging`](crate::messaging::Messaging) reads it from here rather than trusting each
/// caller to remember.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Peer {
    /// A UDP peer, addressed by IPv6. MRP supplies the reliability.
    Udp(PeerAddr),
    /// A BLE peer, named by whatever handle the platform's stack uses for the connection.
    /// [`btp`](crate::transport::btp) supplies the reliability.
    Ble(u16),
    /// A TCP peer: an address, plus the connection the stream arrived on.
    ///
    /// The address alone does not identify it. Core §4.15.2 lets two nodes hold more than one
    /// connection at a time, and a reply has to go back down the one the request came up, so
    /// the platform's own handle for the socket travels with the address.
    /// [`tcp`](crate::transport::tcp) supplies the reliability.
    Tcp(PeerAddr, u16),
}

impl Peer {
    /// Whether the transport is reliable on its own, so §4.12.4 says not to set the R flag.
    #[must_use]
    pub const fn is_reliable(&self) -> bool {
        match self {
            Self::Udp(_) => false,
            Self::Ble(_) | Self::Tcp(..) => true,
        }
    }

    /// Whether the transport can carry a message larger than the 1280-octet IPv6 minimum
    /// MTU, so a Large Message command (§4.4.4) may be sent over it.
    ///
    /// Only TCP can. §4.4.4: "The maximum size of the payload for messages sent over a TCP
    /// connection is 1,048,576 octets", against 1280 for everything datagram-shaped. This is
    /// what an application passes to
    /// [`InteractionContext::with_large_messages`](crate::im::server::InteractionContext::with_large_messages),
    /// so the data model's `L` quality is enforced against the transport that is actually
    /// underneath rather than against a build-time guess.
    #[must_use]
    pub const fn supports_large_payloads(&self) -> bool {
        matches!(self, Self::Tcp(..))
    }

    /// The IPv6 address, when there is one.
    #[must_use]
    pub const fn addr(&self) -> Option<PeerAddr> {
        match self {
            Self::Udp(addr) | Self::Tcp(addr, _) => Some(*addr),
            Self::Ble(_) => None,
        }
    }
}

impl From<PeerAddr> for Peer {
    fn from(addr: PeerAddr) -> Self {
        Self::Udp(addr)
    }
}

/// Sending and receiving IPv6 datagrams.
///
/// This is the one transport every Matter node must have: Core §2.3 puts Matter on "any
/// IPv6-bearing network", and UDP on port 5540 is where operational traffic lives.
pub trait Udp {
    /// Receives one datagram into `buf`, returning how many octets arrived and from where.
    ///
    /// A datagram larger than `buf` is truncated or dropped at the platform's discretion;
    /// `buf` is always at least [`crate::config::MAX_UDP_MESSAGE`] when this crate calls
    /// it, which Core §4.4.4 makes sufficient.
    fn recv_from(&self, buf: &mut [u8]) -> impl Future<Output = Result<(usize, PeerAddr)>>;

    /// Sends one datagram.
    fn send_to(&self, buf: &[u8], addr: PeerAddr) -> impl Future<Output = Result<()>>;

    /// Joins an IPv6 multicast group, so that group messages addressed to it arrive.
    ///
    /// Matter needs one membership per operational group (Core §2.11.1.2).
    fn join_multicast(&self, _group: [u8; 16], _scope_id: u32) -> Result<()> {
        Err(crate::error::Error::new(crate::error::ErrorCode::Platform))
    }

    /// Leaves a multicast group.
    fn leave_multicast(&self, _group: [u8; 16], _scope_id: u32) -> Result<()> {
        Err(crate::error::Error::new(crate::error::ErrorCode::Platform))
    }
}

/// Non-volatile storage, as opaque blobs under string keys.
///
/// The store never sees a Matter type: this crate serialises everything itself, prefixes
/// each blob with a schema version, and treats an unknown newer version as a failure
/// rather than a value to guess at. That keeps the platform's job to five methods and
/// keeps migrations in one place.
pub trait KvStore {
    /// Reads the value of `key` into `out`, returning how many octets it holds.
    ///
    /// Returns `Ok(None)` when the key is absent — which is not an error, it is how a
    /// factory-fresh node reads every key.
    fn get(&self, key: &str, out: &mut [u8]) -> impl Future<Output = Result<Option<usize>>>;

    /// Writes `value` to `key`, replacing what was there.
    fn set(&self, key: &str, value: &[u8]) -> impl Future<Output = Result<()>>;

    /// Removes `key`. Removing an absent key succeeds.
    fn remove(&self, key: &str) -> impl Future<Output = Result<()>>;

    /// Removes every key with the given prefix.
    ///
    /// This is what `RemoveFabric` and a factory reset are built from.
    fn remove_prefix(&self, prefix: &str) -> impl Future<Output = Result<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_detection() {
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        assert!(PeerAddr::new(a).is_link_local());
        a[1] = 0xc0;
        assert!(!PeerAddr::new(a).is_link_local());
        assert!(PeerAddr::new([0xff; 16]).is_multicast());
    }

    #[test]
    fn default_port_is_5540() {
        assert_eq!(PeerAddr::new([0; 16]).port, crate::PORT);
    }

    #[test]
    fn a_node_without_a_clock_says_so() {
        assert_eq!(NoClock.utc(), None);
        assert_eq!(NoClock.granularity(), Granularity::NoTimeGranularity);
        assert!(NoClock.set_utc(0).is_err());
    }
}
