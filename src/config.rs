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
//! | `PACKET_BUFS` | at least 2 — one to receive into, one to retransmit from | — |
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

    /// How many endpoints the node can present, including endpoint 0.
    ///
    /// A bridge grows this: each bridged device is at least one endpoint.
    const ENDPOINTS: usize = 8;

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

    /// How many subjects one access-control entry can name.
    const ACL_SUBJECTS: usize = 4;

    /// How many targets one access-control entry can name.
    const ACL_TARGETS: usize = 3;

    /// How many group memberships the node keeps, across all fabrics.
    const GROUPS: usize = 4 * Self::FABRICS;

    /// How many group key sets the node keeps, across all fabrics.
    ///
    /// Core §2.11.1.2: "at least three group keys per fabric".
    const GROUP_KEYS: usize = 3 * Self::FABRICS;

    /// How many octets of event ring buffer to keep, per priority.
    const EVENT_BUF_BYTES: usize = 1024;

    /// How many packet buffers the node owns.
    ///
    /// Each is [`MAX_UDP_MESSAGE`] octets — the IPv6 minimum MTU of Core §4.4.4 — so this
    /// is the single largest term in the node's memory budget.
    const PACKET_BUFS: usize = 4;

    /// The largest message the node will accept over a stream transport.
    ///
    /// Core §4.15.2.3 calls this the "Maximum Message Size", and a peer that announces a
    /// larger one gets `MESSAGE_TOO_LARGE` and a closed connection. Only meaningful with
    /// the `alloc` feature, which is what unlocks TCP.
    const MAX_TCP_MSG: usize = 64 * 1024;

    /// How many BTP (Bluetooth transport) sessions can be open at once.
    const BTP_SESSIONS: usize = 1;

    /// The largest blob the key-value store must be able to hold.
    const KV_BLOB_MAX: usize = 4096;

    /// How many resolved addresses to remember per peer when dialling.
    const RESOLVE_CANDIDATES: usize = 4;

    /// How many messages to remember per session for duplicate detection.
    ///
    /// Core §4.6.6's message reception state; the window has to be at least wide enough
    /// to absorb the reordering a network produces.
    const REPLAY_WINDOW: usize = 32;
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
            C::ENDPOINTS >= 1,
            "Config::ENDPOINTS: endpoint 0 is the root node (Core §2.10)"
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
        assert!(
            C::PACKET_BUFS >= 2,
            "Config::PACKET_BUFS: one buffer to receive into and one to retransmit from"
        );
        assert!(
            C::REPLAY_WINDOW >= 1,
            "Config::REPLAY_WINDOW: Core §4.6.6 requires message reception state"
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
