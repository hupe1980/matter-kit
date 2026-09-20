//! What the node promises, and how its promises are checked.
//!
//! A Matter node is a set of tables: fabrics it belongs to, sessions it holds, exchanges in
//! flight, subscriptions it serves, access-control entries it enforces. On a microcontroller
//! every one of those is a fixed-capacity array whose length has to be known at compile time.
//!
//! The obvious way to express that is Cargo features — `fabrics-5`, `sessions-16` — which is
//! what the other Rust implementation does, with seventy-odd of them. Cargo features are
//! *additive and global*: two crates in one binary that want different sizes silently get the
//! union, and nothing checks the result against the specification.
//!
//! # Capacity is declared once, on the table
//!
//! Stable Rust cannot write `Vec<T, { C::SESSIONS }>`: an associated const may not appear in
//! const-generic position. So a table's capacity **is** its own const parameter —
//! `SessionTable<C, N>`, `Acl<C, N, S, T>` — and there is no second place that also claims to
//! be it. A trait constant that names a capacity it cannot size is worse than no constant at
//! all: it reads as a promise, it can carry an assertion that looks like enforcement, and the
//! table it claims to size is whatever length somebody else picked.
//!
//! What a table's capacity cannot tell you is what share of it each *fabric* is owed. That is a
//! policy, it is what the node advertises on the wire, and it is what this trait carries:
//!
//! | Constant | What it is | Section |
//! |---|---|---|
//! | [`FABRICS`](Config::FABRICS) | how many ecosystems the node can join — `SupportedFabrics` | §11.18.5.3 |
//! | [`SUBSCRIPTIONS_PER_FABRIC`](Config::SUBSCRIPTIONS_PER_FABRIC) | `SubscriptionsPerFabric` | §2.11.2.2 |
//! | [`ACL_ENTRIES_PER_FABRIC`](Config::ACL_ENTRIES_PER_FABRIC) | `AccessControlEntriesPerFabric` | §2.11.1.1, §9.10.6.7 |
//! | [`GROUPS_PER_FABRIC`](Config::GROUPS_PER_FABRIC) | `MaxGroupsPerFabric` | §2.11.1.2, §11.2.6.2 |
//! | [`GROUP_KEYS_PER_FABRIC`](Config::GROUP_KEYS_PER_FABRIC) | `MaxGroupKeysPerFabric` | §2.11.1.2, §11.2.6.3 |
//! | [`READ_PATHS`](Config::READ_PATHS) | `ReadPathsSupported` | §2.11.2.1, §11.1.4.4 |
//! | [`ICD_CLIENTS_PER_FABRIC`](Config::ICD_CLIENTS_PER_FABRIC) | `ClientsSupportedPerFabric` | §9.16.6.6 |
//! | [`ACL_AUXILIARY`](Config::ACL_AUXILIARY) | whether §9.10.4.3's Auxiliary feature is served | §6.6.6.2 |
//!
//! Every one of those is read by the crate through `C::`, and every assertion in
//! [`AssertValid`] constrains a number something reads.
//!
//! # Who checks that a table can keep the promise
//!
//! The table does, at compile time, against the `Config` it is parameterised by. A
//! `SubscriptionTable<C, N, P>` will not compile unless `N` can hold
//! `FABRICS × SUBSCRIPTIONS_PER_FABRIC`; an `Acl<C, N, S, T>` will not compile unless `N` can
//! hold `FABRICS × ACL_ENTRIES_PER_FABRIC`, `S` is at least §9.10.6.5's four and `T` at least
//! §9.10.6.6's three. The failing rule is named in the build error.
//!
//! That is the whole mechanism, and it is why §11.1.4.4's `CapabilityMinima` is built from the
//! tables rather than from this trait: the specification says each field "SHALL indicate the
//! **actual**" number, and only the table knows it.
//!
//! ```
//! use matter_kit::Config;
//!
//! /// A Thread light: room for five ecosystems, and the specification's minimum of everything.
//! struct Light;
//! impl Config for Light {}
//! ```
//!
//! Everything not named takes the value in [`DefaultConfig`].

/// What a Matter node promises each fabric, and which optional behaviours it serves.
///
/// Implement this on a zero-sized type and pass it as the `C` parameter. Every constant has a
/// default that is the specification's own minimum, so `impl Config for MyNode {}` is a
/// complete and conformant implementation.
///
/// It does **not** size anything: see the module documentation.
pub trait Config {
    /// How many fabrics — commissioned ecosystems — the node can belong to.
    ///
    /// Reported as `SupportedFabrics` (Core §11.18.5.3), whose constraint is `5 to 254`: a node
    /// that supports fewer than five cannot be commissioned into the number of ecosystems the
    /// specification requires. The fabric table is asserted at compile time to hold this many.
    const FABRICS: usize = 5;

    /// How many subscriptions any one fabric may hold.
    ///
    /// §2.11.2.2 states the rule as a *guarantee*, not a cap: "A publisher SHALL ensure that
    /// every fabric the node is commissioned into can support at least three Subscribe
    /// Interactions to the publisher." A table with only a global limit cannot make that
    /// promise — the first administrator to ask fills it, and every fabric commissioned
    /// afterwards is told the node is out of resources by a node that is, from its own point
    /// of view, working perfectly.
    ///
    /// So the guarantee is a fixed share each, refusing a fabric that is at its quota even when
    /// the table has room. That is the strict reading, it is always conformant, and it cannot
    /// surprise an administrator by granting a subscription one day and refusing it the next
    /// when what changed was somebody else's fabric.
    const SUBSCRIPTIONS_PER_FABRIC: usize = 3;

    /// How many access-control entries **one fabric** may hold — §9.10.6.7's
    /// `AccessControlEntriesPerFabric`, constrained to `4 to 65534`.
    ///
    /// §2.11.1.1 requires "at least four Access Control Entries available for every fabric
    /// supported by the node", and without a quota the first fabric to fill the table would
    /// lock every later administrator out of granting itself anything.
    ///
    /// §2.11.1.1 permits over-subscription — "if it supports N entries must enforce that any K
    /// fabrics together do not use more than N - 4*(5-K) entries" — which would let one fabric
    /// borrow the unused quota of another. This is the strict reading instead: a fixed share
    /// each, for the same reason as [`SUBSCRIPTIONS_PER_FABRIC`](Config::SUBSCRIPTIONS_PER_FABRIC).
    const ACL_ENTRIES_PER_FABRIC: usize = 4;

    /// How many group memberships one fabric may hold — §11.2.6.2's `MaxGroupsPerFabric`.
    ///
    /// Core §2.11.1.2: "at least four groups per fabric".
    const GROUPS_PER_FABRIC: usize = 4;

    /// How many group key sets one fabric may hold — §11.2.6.3's `MaxGroupKeysPerFabric`.
    ///
    /// Core §2.11.1.2: "at least three group keys per fabric".
    const GROUP_KEYS_PER_FABRIC: usize = 3;

    /// How many paths one Read Request is guaranteed to be answered with.
    ///
    /// §11.1.4.4's `ReadPathsSupported`, constrained to `9 to 10000`: "the actual maximum
    /// number of read paths … which a node guarantees being able to process in any Read Request
    /// Action". Core §2.11.2.1 sets the floor: "a single Read Interaction from a client on that
    /// fabric containing up to 9 paths".
    ///
    /// Unlike every other constant here this one is a promise about *work* rather than about
    /// storage, so no table can check it. `tests/im_read_server.rs` does, by reading that many
    /// paths in one action and requiring an answer.
    const READ_PATHS: usize = 9;

    /// How many Check-In registrations one fabric may hold — §9.16.6.6's
    /// `ClientsSupportedPerFabric`, constrained to `min 1`.
    ///
    /// §9.16.6.5: "The maximum number of entries that can be in the list SHALL be
    /// ClientsSupportedPerFabric for each fabric", so this is a per-fabric guarantee like the
    /// others and the registration table is checked against it at compile time.
    const ICD_CLIENTS_PER_FABRIC: usize = 1;

    /// Whether §9.10.4.3's Auxiliary feature is implemented.
    ///
    /// It changes an access decision: with it, §6.6.6.2 stops a wildcard Group entry from
    /// reaching endpoint 0, whose clusters administer the node itself.
    const ACL_AUXILIARY: bool = false;
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

/// Compile-time proof that a [`Config`] is internally conformant.
///
/// Instantiating this type evaluates its assertions; every generic entry point in the crate
/// does so, which is what makes a bad `Config` a build failure at its first use.
///
/// It checks the *policy* only. Whether a table is big enough to keep that policy is checked by
/// the table — see [`Capacity`].
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
            C::SUBSCRIPTIONS_PER_FABRIC >= 3,
            "Config::SUBSCRIPTIONS_PER_FABRIC: Core §2.11.2.2 requires at least 3 per fabric"
        );
        assert!(
            C::ACL_ENTRIES_PER_FABRIC >= 4,
            "Config::ACL_ENTRIES_PER_FABRIC: Core §2.11.1.1 requires at least 4 per fabric"
        );
        assert!(
            C::GROUPS_PER_FABRIC >= 4,
            "Config::GROUPS_PER_FABRIC: Core §2.11.1.2 requires at least 4 groups per fabric"
        );
        assert!(
            C::GROUP_KEYS_PER_FABRIC >= 3,
            "Config::GROUP_KEYS_PER_FABRIC: Core §2.11.1.2 requires at least 3 group keys per fabric"
        );
        assert!(
            C::READ_PATHS >= 9,
            "Config::READ_PATHS: Core §2.11.2.1 requires a read of up to 9 paths"
        );
        assert!(
            C::ICD_CLIENTS_PER_FABRIC >= 1,
            "Config::ICD_CLIENTS_PER_FABRIC: §9.16.6.6 constrains ClientsSupportedPerFabric to min 1"
        );
    };
}

/// A table whose capacity the node states on the wire.
///
/// §11.1.4.4 requires `CapabilityMinima` to report "the **actual**" number a node supports, and
/// §11.18.5.3, §9.10.6.7, §11.2.6.2 and §11.2.6.3 do the same for their clusters. Only the table
/// knows that number, so the table is what publishes it — never [`Config`], which cannot size
/// anything, and never a value the integrator types beside it.
///
/// Implemented by [`FabricTable`](crate::fabric::FabricTable),
/// [`SessionTable`](crate::session::SessionTable),
/// [`SubscriptionTable`](crate::im::SubscriptionTable), [`Acl`](crate::acl::Acl) and
/// [`GroupKeys`](crate::group::GroupKeys).
pub trait Capacity {
    /// Total slots, across every fabric.
    const TOTAL: usize;

    /// What one fabric is guaranteed — the number the specification calls "actual".
    ///
    /// A table with no per-fabric quota reports its total.
    const PER_FABRIC: usize;
}

/// A subscription table, which has one more number the node states: how many paths one
/// subscription may carry.
///
/// §11.1.4.4's `SubscribePathsSupported`, constrained to `3 to 10000`. It is separate from
/// [`Capacity`] because it is the only table with an inner capacity the specification asks
/// about, and a constant on `Capacity` that every other table answered zero to would be a
/// number that means nothing four times over.
pub trait SubscriptionCapacity: Capacity {
    /// How many attribute or event paths one subscription can carry.
    const PATHS: usize;
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
    fn a_bigger_fabric_count_is_still_a_valid_policy() {
        #[derive(Debug)]
        struct Big;
        impl Config for Big {
            const FABRICS: usize = 16;
        }
        const _: () = assert_valid::<Big>();
        // Nothing here scales with `FABRICS`, because nothing here is a capacity. What scales
        // is the *requirement* each table is checked against: a `SessionTable<Big, 16>` now
        // fails to build, because §4.14.2.8 wants 48 sessions for sixteen fabrics.
        assert_eq!(Big::SUBSCRIPTIONS_PER_FABRIC, 3);
        assert_eq!(Big::ACL_ENTRIES_PER_FABRIC, 4);
    }

    #[test]
    fn the_defaults_are_the_specifications_own_minima() {
        // A `Config` that names nothing is a conformant node and nothing more: every extra is a
        // deliberate act, and `AssertValid` refuses anything below.
        assert_eq!(DefaultConfig::FABRICS, 5);
        assert_eq!(DefaultConfig::SUBSCRIPTIONS_PER_FABRIC, 3);
        assert_eq!(DefaultConfig::ACL_ENTRIES_PER_FABRIC, 4);
        assert_eq!(DefaultConfig::GROUPS_PER_FABRIC, 4);
        assert_eq!(DefaultConfig::GROUP_KEYS_PER_FABRIC, 3);
        assert_eq!(DefaultConfig::READ_PATHS, 9);
        const { assert!(!<DefaultConfig as Config>::ACL_AUXILIARY) };
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
