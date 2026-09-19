//! How big everything is.
//!
//! A Matter node is a set of tables: fabrics it belongs to, sessions it holds, exchanges
//! in flight, subscriptions it serves, access-control entries it enforces. On a
//! microcontroller every one of those is a fixed-capacity array, and its length has to be
//! known at compile time.
//!
//! The obvious way to express that is Cargo features — `fabrics-5`, `fabrics-32`,
//! `sessions-16` — which is what the other Rust implementation does, with seventy-odd of
//! them. It has two problems. Cargo features are *additive and global*: two crates in one
//! binary that want different sizes silently get the union, and there is no way to say so.
//! And nothing checks the result against the specification, so a build that cannot pass
//! certification compiles happily.
//!
//! So sizing is a **trait**. A consumer writes one type, the numbers travel with it
//! through every generic in the crate, and the specification's minima are `const`
//! assertions that fail the build rather than the certification laboratory.
//!
//! **Every constant here is read by the crate.** A sizing knob nothing reads is worse than
//! no knob at all: it reads as a promise, it can carry an assertion that looks like
//! enforcement, and the table it claims to size is whatever length somebody else picked. So
//! `Config` carries what the protocol core allocates — fabrics, sessions, exchanges,
//! subscriptions, access control — and no more. Capacities that belong to one instance of one
//! table are const parameters on that table (`GroupKeys<K, M>`, `SceneTable<N, EFS, F>`,
//! `Binding<C, N>`), chosen where it is constructed, because that is where the device knows
//! how many it wants. `GROUPS` and `GROUP_KEYS` stay because §2.11.1.2's per-fabric minima
//! are checked against them and a device passes them straight to those tables.
//!
//! ```
//! use matter_kit::Config;
//!
//! /// A Thread light: one ecosystem plus room for a second, and not much else.
//! struct Light;
//! impl Config for Light {
//!     const FABRICS: usize = 5;
//!     const SESSIONS: usize = 16;
//!     const SUBSCRIPTIONS: usize = 15;
//! }
//! ```
//!
//! Everything not named takes the value in [`DefaultConfig`], which is a device-sized
//! profile that satisfies every minimum.
//!
//! # What is checked
//!
//! | Constant | Rule | Section |
//! |---|---|---|
//! | `FABRICS` | 5 ..= 254 — the `SupportedFabrics` constraint | §11.18.5.3 |
//! | `ACL_ENTRIES` | at least 4 per fabric | §2.11.1.1 |
//! | `GROUP_KEYS` | at least 3 per fabric | §2.11.1.2 |
//! | `SESSIONS` | at least 3 CASE sessions per fabric | §4.14.2.8 |
//! | `SUBSCRIPTIONS` | at least 3 per fabric | §2.11.2.2 |
//! | `SUB_PATHS` | at least 3 per subscription | §2.11.2.2 |
//! | `READ_PATHS` | at least 9 | §2.11.2.1 |
//! | `EXCHANGES_PER_SESSION` | at least 1 | — |
//!
//! The assertions are in [`assert_valid`], which every generic entry point in the crate
//! instantiates. A `Config` that breaks a rule therefore fails to compile at the first
//! place it is used, with the failing rule named in the panic message.

/// The sizes a Matter node is built to.
///
/// Implement this on a zero-sized type and pass it as the `C` parameter. Every constant
/// has a default from [`DefaultConfig`], so a minimal implementation is `impl Config for
/// MyNode {}`.
pub trait Config {
    /// How many fabrics — commissioned ecosystems — the node can belong to.
    ///
    /// Reported as `SupportedFabrics` (Core §11.18.5.3), whose constraint is `5 to 254`:
    /// a node that supports fewer than five cannot be commissioned into the number of
    /// ecosystems the specification requires.
    const FABRICS: usize = 5;

    /// How many secure sessions can exist at once, across all fabrics.
    ///
    /// Core §4.14.2.8: "A node SHALL support at least 3 CASE session contexts per fabric."
    const SESSIONS: usize = 16;

    /// How many exchanges can be open on one session at once.
    const EXCHANGES_PER_SESSION: usize = 4;

    /// How many subscriptions the node can serve, across all fabrics.
    ///
    /// Core §2.11.2.2: at least three per fabric.
    const SUBSCRIPTIONS: usize = 15;

    /// How many subscriptions any one fabric may hold.
    ///
    /// §2.11.2.2 states the rule as a *guarantee*, not a cap: "A publisher SHALL ensure that
    /// every fabric the node is commissioned into can support at least three Subscribe
    /// Interactions to the publisher." A table with only a global limit cannot make that
    /// promise — the first administrator to ask fills it, and every fabric commissioned
    /// afterwards is told the node is out of resources by a node that is, from its own point
    /// of view, working perfectly.
    ///
    /// So the guarantee is kept the way [`Config::ACL_ENTRIES_PER_FABRIC`] keeps §6.6's: a
    /// fixed share each, refusing a fabric that is at its quota even when the table has room.
    /// That is the strict reading, it is always conformant, and it cannot surprise an
    /// administrator by granting a subscription one day and refusing it the next when what
    /// changed was somebody else's fabric.
    const SUBSCRIPTIONS_PER_FABRIC: usize = 3;

    /// How many attribute or event paths one subscription can carry.
    ///
    /// Core §2.11.2.2: at least three.
    const SUB_PATHS: usize = 3;

    /// How many paths one read interaction can carry.
    ///
    /// Core §2.11.2.1: "a single Read Interaction from a client on that fabric containing
    /// up to 9 paths".
    const READ_PATHS: usize = 9;

    /// How many access-control entries the node stores, across all fabrics.
    ///
    /// Core §2.11.1.1: "at least four Access Control Entries available for every fabric".
    const ACL_ENTRIES: usize = 4 * Self::FABRICS;

    /// How many access-control entries **one fabric** may hold — §9.10.6.7's
    /// `AccessControlEntriesPerFabric`, constrained to `4 to 65534`.
    ///
    /// A per-fabric quota, not just a total: §2.11.1.1 requires "at least four Access Control
    /// Entries available for every fabric supported by the node", and without a quota the
    /// first fabric to fill the table would lock every later administrator out of granting
    /// itself anything.
    ///
    /// §2.11.1.1 permits over-subscription — "if it supports N entries must enforce that any K
    /// fabrics together do not use more than N - 4*(5-K) entries" — which would let one fabric
    /// borrow the unused quota of another. This is the strict reading instead: a fixed share
    /// each. It is always conformant and it cannot surprise an administrator by granting a
    /// quota one day and refusing it the next, when what changed was another fabric.
    const ACL_ENTRIES_PER_FABRIC: usize = 4;

    /// How many subjects one access-control entry can name.
    ///
    /// §9.10.6.5's `SubjectsPerAccessControlEntry`, constrained to `4 to 65534`.
    const ACL_SUBJECTS: usize = 4;

    /// How many targets one access-control entry can name.
    ///
    /// §9.10.6.6's `TargetsPerAccessControlEntry`, constrained to `3 to 65534`.
    const ACL_TARGETS: usize = 3;

    /// Whether §9.10.4.3's Auxiliary feature is implemented.
    ///
    /// It changes an access decision: with it, §6.6.6.2 stops a wildcard Group entry from
    /// reaching endpoint 0, whose clusters administer the node itself.
    const ACL_AUXILIARY: bool = false;

    /// How many group memberships the node keeps, across all fabrics.
    const GROUPS: usize = 4 * Self::FABRICS;

    /// How many group key sets the node keeps, across all fabrics.
    ///
    /// Core §2.11.1.2: "at least three group keys per fabric".
    const GROUP_KEYS: usize = 3 * Self::FABRICS;

    /// The largest message the node will accept over a stream transport.
    ///
    /// Core §4.15.2.3 calls this the "Maximum Message Size", and a peer that announces a
    /// larger one gets `MESSAGE_TOO_LARGE` and a closed connection. It is the `N` of
    /// [`tcp::Framer`](crate::transport::tcp::Framer), and the specification sets no figure:
    /// "The system platform MAY configure a Maximum Message Size for the payload that it is
    /// capable of receiving", so a device that cannot spare 64 KiB says so here.
    const MAX_TCP_MSG: usize = 64 * 1024;
}

/// A device-sized profile that satisfies every minimum: five fabrics, sixteen sessions,
/// fifteen subscriptions.
///
/// This is the configuration the crate's own tests and examples use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultConfig;

impl Config for DefaultConfig {}

/// The largest message that fits the IPv6 minimum MTU (Core §4.4.4).
///
/// "Support for IPv6 fragmentation is not mandatory in Matter, and the expected supported
/// MTU is 1280 bytes … all messages, including transport headers, SHALL fit within that
/// minimal IPv6 MTU. This message size limit SHALL apply to the UDP transport."
pub const MAX_UDP_MESSAGE: usize = 1280;

/// The largest framing a secured unicast message can carry, in octets.
///
/// Message header: flags, session id, security flags and counter (8), a source node id (8) and
/// a destination node id (8) — [`MessageHeader::encoded_len`](crate::msg::MessageHeader::encoded_len)'s
/// worst case. Protocol header: flags, opcode, exchange id and protocol id (6), a vendor id (2)
/// and an acknowledged counter (4) — [`ProtocolHeader::encoded_len`](crate::msg::ProtocolHeader::encoded_len)'s.
/// Then §4.8's AEAD tag (16).
pub const MAX_MESSAGE_FRAMING: usize = (8 + 8 + 8) + (6 + 2 + 4) + 16;

/// The largest protocol payload that is **certain** to fit a UDP datagram once framed.
///
/// A node builds its reply in a payload buffer and hands it to the messaging layer, which adds
/// the headers and the AEAD tag. So the payload bound is the datagram bound *minus the framing*,
/// and sizing that buffer by anything else is guesswork that fails as `buffer too small` — from
/// this node, about its own reply, with nothing on the wire to explain it.
///
/// It is a floor rather than an exact figure: a message with no source node id, or on a common
/// protocol, or with nothing to acknowledge, has room to spare. Sizing to the worst case is what
/// makes "it fits" independent of which of those happens to be true.
pub const MAX_UDP_PAYLOAD: usize = MAX_UDP_MESSAGE.saturating_sub(MAX_MESSAGE_FRAMING);

/// Compile-time proof that a [`Config`] satisfies the specification's minima.
///
/// Instantiating this type evaluates its assertions; every generic entry point in the
/// crate does so, which is what makes a bad `Config` a build failure at its first use.
pub struct AssertValid<C: Config>(core::marker::PhantomData<C>);

impl<C: Config> AssertValid<C> {
    /// The assertions themselves. Referencing this constant is what runs them.
    pub const CHECK: () = {
        assert!(
            C::FABRICS >= 5,
            "Config::FABRICS: Core §11.18.5.3 constrains SupportedFabrics to 5..=254"
        );
        assert!(
            C::FABRICS <= 254,
            "Config::FABRICS: Core §11.18.5.3 constrains SupportedFabrics to 5..=254"
        );
        assert!(
            C::ACL_ENTRIES >= 4 * C::FABRICS,
            "Config::ACL_ENTRIES: Core §2.11.1.1 requires at least 4 entries per fabric"
        );
        assert!(
            C::GROUP_KEYS >= 3 * C::FABRICS,
            "Config::GROUP_KEYS: Core §2.11.1.2 requires at least 3 group keys per fabric"
        );
        assert!(
            C::SESSIONS >= 3 * C::FABRICS,
            "Config::SESSIONS: Core §4.14.2.8 requires at least 3 CASE sessions per fabric"
        );
        assert!(
            C::SUBSCRIPTIONS_PER_FABRIC >= 3,
            "Config::SUBSCRIPTIONS_PER_FABRIC: Core §2.11.2.2 requires at least 3 per fabric"
        );
        assert!(
            C::SUBSCRIPTIONS >= C::SUBSCRIPTIONS_PER_FABRIC * C::FABRICS,
            "Config::SUBSCRIPTIONS: every fabric must be able to reach SUBSCRIPTIONS_PER_FABRIC"
        );
        assert!(
            C::SUBSCRIPTIONS >= 3 * C::FABRICS,
            "Config::SUBSCRIPTIONS: Core §2.11.2.2 requires at least 3 subscriptions per fabric"
        );
        assert!(
            C::SUB_PATHS >= 3,
            "Config::SUB_PATHS: Core §2.11.2.2 requires at least 3 paths per subscription"
        );
        assert!(
            C::READ_PATHS >= 9,
            "Config::READ_PATHS: Core §2.11.2.1 requires a read of up to 9 paths"
        );
        assert!(
            C::EXCHANGES_PER_SESSION >= 1,
            "Config::EXCHANGES_PER_SESSION: a session with no exchange can do nothing"
        );
    };
}

/// Runs [`AssertValid::CHECK`] for `C`.
///
/// Call it from any `const` context — or just let the crate's generic types do it.
pub const fn assert_valid<C: Config>() {
    #[allow(clippy::let_unit_value)]
    let () = AssertValid::<C>::CHECK;
}

#[cfg(test)]
mod tests {
    use super::*;

    // The real check is a `const` one: `assert_valid` evaluates `AssertValid::CHECK`,
    // which fails the *build* rather than a test run. Naming it in a `const` context is
    // what proves that, so these are `const` blocks and not runtime assertions.
    const _: () = assert_valid::<DefaultConfig>();

    #[test]
    fn the_default_config_satisfies_every_minimum() {
        // Reaching this line at all means the `const` above compiled.
        assert_valid::<DefaultConfig>();
    }

    #[test]
    fn derived_defaults_follow_the_fabric_count() {
        #[derive(Debug)]
        struct Big;
        impl Config for Big {
            const FABRICS: usize = 16;
            const SESSIONS: usize = 64;
            const SUBSCRIPTIONS: usize = 48;
        }
        const _: () = assert_valid::<Big>();
        // ACL_ENTRIES and GROUP_KEYS default off FABRICS, so they scale with it.
        assert_eq!(Big::ACL_ENTRIES, 64);
        assert_eq!(Big::GROUP_KEYS, 48);
    }

    #[test]
    fn max_udp_message_is_the_ipv6_minimum_mtu() {
        assert_eq!(MAX_UDP_MESSAGE, 1280);
    }
}

#[cfg(test)]
mod payload_bound {
    use super::{MAX_MESSAGE_FRAMING, MAX_UDP_MESSAGE, MAX_UDP_PAYLOAD};
    use crate::msg::{
        Destination, MessageHeader, NodeId, ProtocolHeader, ProtocolId, SessionId, SessionType,
    };

    /// `MAX_MESSAGE_FRAMING` is the worst case the encoders can actually produce.
    ///
    /// Derived by hand from two `encoded_len` implementations, which is exactly the kind of
    /// arithmetic that is right when written and wrong after the next field is added. So it is
    /// checked against the encoders rather than against itself.
    #[test]
    fn the_framing_bound_is_what_the_headers_encode() {
        // Every optional field present: a source node id, a destination node id, a vendor
        // protocol and an acknowledgement.
        let message = MessageHeader {
            session_id: SessionId(0x1234),
            session_type: SessionType::Unicast,
            privacy: false,
            control: false,
            message_counter: 0xDEAD_BEEF,
            source: Some(NodeId(0x0102_0304_0506_0708)),
            destination: Destination::Node(NodeId(0x1112_1314_1516_1718)),
        };
        let protocol = ProtocolHeader {
            acknowledged_counter: Some(0x0BAD_F00D),
            protocol: ProtocolId {
                vendor: crate::msg::VendorId(0xFFF1),
                id: 0x0001,
            },
            ..ProtocolHeader::default()
        };
        let encoded = message.encoded_len() + protocol.encoded_len();
        let mic = crate::crypto::AEAD_MIC_LENGTH_BYTES;
        assert_eq!(
            encoded + mic,
            MAX_MESSAGE_FRAMING,
            "the framing bound no longer matches what the headers encode"
        );
        assert_eq!(MAX_UDP_PAYLOAD + MAX_MESSAGE_FRAMING, MAX_UDP_MESSAGE);
    }
}
