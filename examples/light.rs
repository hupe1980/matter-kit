//! A commissionable Matter device on real sockets.
//!
//! ```text
//! cargo run --example light --features std
//! ```
//!
//! This is the whole stack on an operating system: a UDP socket on port 5540 for Matter, an
//! mDNS socket on 5353 so a commissioner can find the node, PASE from a printed passcode, and
//! the commissioning clusters reachable over the session it produces.
//!
//! Point a commissioner at it:
//!
//! ```text
//! chip-tool pairing onnetwork 1 20202021
//! ```
//!
//! # What this example is
//!
//! It is the assembly, written out. `matter-kit` is sans-I/O by design — every protocol layer
//! takes bytes and a clock and returns bytes — so *something* has to own the sockets and the
//! event loop, and until that something exists in one place it is hard to see how the pieces
//! fit. This is that place, and it is deliberately one file with no framework.
//!
//! The loop is three things:
//!
//! 1. wait for a Matter datagram, an mDNS datagram, or the next timer deadline;
//! 2. route it — [`Messaging`] answers "which session, which exchange, which protocol";
//! 3. drive the timers that nobody else will.
//!
//! # What it is not
//!
//! A finished product. It commissions and it answers the commissioning clusters; it does not
//! persist anything across a restart, does not implement an application cluster, and its
//! access control grants everything, which is correct only while a PASE commissioning channel
//! is the only way in.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::too_many_lines
)]

use core::cell::RefCell;
use core::future::poll_fn;
use core::pin::pin;
use core::task::Poll;

use matter_kit::acl::{Acl, AclAccess, SubjectDescriptor};
use matter_kit::attestation::factory::DevelopmentChain;
use matter_kit::cert::MatterCertificate;
use matter_kit::clusters::access_control::{self, AccessControl};
use matter_kit::clusters::administrator_commissioning::{self, AdministratorCommissioning};
use matter_kit::clusters::basic_information::{
    Attributes, BasicInformation, CapabilityMinima, Location, Product,
};
use matter_kit::clusters::binding::{self, Binding};
use matter_kit::clusters::descriptor::{self, Descriptor};
use matter_kit::clusters::general_commissioning::{self, GeneralCommissioning, RegulatoryLocation};
use matter_kit::clusters::general_diagnostics::{
    self, BootReason, Diagnostics, GeneralDiagnostics,
};
use matter_kit::clusters::generated::device_types::ON_OFF_LIGHT;
use matter_kit::clusters::group_key_management::{self, GroupKeyManagement};
use matter_kit::clusters::groups::{self, Groups};
use matter_kit::clusters::identify::{
    EffectIdentifierEnum, EffectVariantEnum, Identify, IdentifyHooks, IdentifyTypeEnum,
};
use matter_kit::clusters::label::{self, FixedLabel, Label, UserLabel};
use matter_kit::clusters::on_off::{self, OnOff, OnOffHooks};
use matter_kit::clusters::operational_credentials::{
    self as opcreds, DeviceAttestation, OperationalCredentials,
};
use matter_kit::clusters::scenes::{self, ExtensionFieldSetStruct, SceneHooks, SceneTable, Scenes};
use matter_kit::clusters::{At, Endpoints};
use matter_kit::commissioning::admission::{Admit, PaseAdmission};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::{CommissioningWindow, WindowStatus};
use matter_kit::config::{Config, DefaultConfig};
use matter_kit::crypto::{KeyPurpose, KeyStore, SoftKeyStore, Spake2pVerifierData};
use matter_kit::discovery::responder::{Advertisement, Responder};
use matter_kit::discovery::txt::{CommissionableTxt, CommissioningMode, OperationalTxt};
use matter_kit::discovery::{COMMISSIONABLE_SERVICE, MDNS_PORT, OPERATIONAL_SERVICE};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{DataVersions, DeviceType, Endpoint, Node};
use matter_kit::fabric::FabricTable;
use matter_kit::im::{
    Dispatcher, InteractionContext, NewSubscription, ReadCursor, ReportReason, Request, Served,
    Server, SubscribeResponse, SubscriptionPolicy, SubscriptionTable,
};
use matter_kit::messaging::{Due, Messaging, Received};
use matter_kit::msg::{FabricIndex, NodeId, ProtocolId, SessionId, VendorId};
use matter_kit::platform::os::{StdRng, StdTimer, StdUdp, block_on};
use matter_kit::platform::{Instant, Peer, PeerAddr, Rng, Timer, Udp};
use matter_kit::sc::{
    CaseResponder, PaseResponder, PbkdfParameters, ResponderConfig, SecureChannelCode,
    SessionParams, Sigma1, Sigma3, StatusReport, opcode,
};
use matter_kit::session::{Role, SecureSession, SessionKind};

/// The passcode that would be printed on the device's label, and its factory PBKDF salt.
const PASSCODE: u32 = 20_202_021;
const SALT: &[u8] = b"SPAKE2P Key Salt";
const ITERATIONS: u32 = 1_000;
/// §5.1.1.3's 12-bit discriminator, which a commissioner filters on.
const DISCRIMINATOR: u16 = 3840;

const VENDOR: VendorId = VendorId(0xFFF1);
const PRODUCT_ID: u16 = 0x8000;

const PRODUCT: Product<'static> = Product::new(
    "Example Vendor",
    VENDOR,
    "matter-kit light",
    PRODUCT_ID,
    "matter-kit-light-0001",
)
// §11.1.4.4's `CapabilityMinimaStruct` is what this node *guarantees*, and those numbers are
// `Config`'s — not a product's to invent. `from_config` reads them, so they cannot drift away
// from the tables they describe the first time a size changes.
.with_capability_minima(CapabilityMinima::from_config::<DefaultConfig>());

const ACL_ENTRIES: usize = DefaultConfig::ACL_ENTRIES;
const ACL_SUBJECTS: usize = DefaultConfig::ACL_SUBJECTS;
const ACL_TARGETS: usize = DefaultConfig::ACL_TARGETS;

/// What the factory burned in (§9.8): read-only, and not a commissioner's to change.
const FIXED_LABELS: &[Label<'static>] = &[match Label::new("model", "matter-kit") {
    Some(l) => l,
    None => panic!("within §9.7.4.1's 16 characters"),
}];

/// The interface to advertise on, when `MATTER_IFINDEX` does not say.
///
/// `1` is the loopback on most systems, which is enough to see the node with a local
/// commissioner and not enough to be found from another machine. `ip link` or `ifconfig`
/// gives the real one.
const DEFAULT_IFINDEX: u32 = 1;

/// Appendix F.1's first Certification Declaration, CMS `SignedData` and all.
///
/// A real CD is signed by the CSA, and this crate has no way to *produce* one — `attestation::cd`
/// parses and verifies, which is what a device and a commissioner need. So a development device
/// carries the specification's own published example: it is a genuine CMS structure a
/// commissioner can parse, and it attests to nothing, which is the honest answer for a device
/// that has never been certified.
const CERTIFICATION_DECLARATION: &[u8] = &[
    0x30, 0x81, 0xe8, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x81,
    0xda, 0x30, 0x81, 0xd7, 0x02, 0x01, 0x03, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x45, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x07, 0x01, 0xa0, 0x38, 0x04, 0x36, 0x15, 0x24, 0x00, 0x01, 0x25, 0x01, 0xf1, 0xff, 0x36,
    0x02, 0x05, 0x00, 0x80, 0x18, 0x25, 0x03, 0x34, 0x12, 0x2c, 0x04, 0x13, 0x5a, 0x49, 0x47, 0x32,
    0x30, 0x31, 0x34, 0x31, 0x5a, 0x42, 0x33, 0x33, 0x30, 0x30, 0x30, 0x31, 0x2d, 0x32, 0x34, 0x24,
    0x05, 0x00, 0x24, 0x06, 0x00, 0x25, 0x07, 0x94, 0x26, 0x24, 0x08, 0x00, 0x18, 0x31, 0x7c, 0x30,
    0x7a, 0x02, 0x01, 0x03, 0x80, 0x14, 0x62, 0xfa, 0x82, 0x33, 0x59, 0xac, 0xfa, 0xa9, 0x96, 0x3e,
    0x1c, 0xfa, 0x14, 0x0a, 0xdd, 0xf5, 0x04, 0xf3, 0x71, 0x60, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x04, 0x46, 0x30, 0x44, 0x02, 0x20, 0x43, 0xa6, 0x3f, 0x2b, 0x94, 0x3d, 0xf3,
    0x3c, 0x38, 0xb3, 0xe0, 0x2f, 0xca, 0xa7, 0x5f, 0xe3, 0x53, 0x2a, 0xeb, 0xbf, 0x5e, 0x63, 0xf5,
    0xbb, 0xdb, 0xc0, 0xb1, 0xf0, 0x1d, 0x3c, 0x4f, 0x60, 0x02, 0x20, 0x4c, 0x1a, 0xbf, 0x5f, 0x18,
    0x07, 0xb8, 0x18, 0x94, 0xb1, 0x57, 0x6c, 0x47, 0xe4, 0x72, 0x4e, 0x4d, 0x96, 0x6c, 0x61, 0x2e,
    0xd3, 0xfa, 0x25, 0xc1, 0x18, 0xc3, 0xf2, 0xb3, 0xf9, 0x03, 0x69,
];

/// `0x0016` is the Device Library's Root Node; every node has one on endpoint 0.
const ROOT_NODE: &[DeviceType] = &[DeviceType::new(0x0016, 3)];

/// Endpoint 1 is an `On/Off Light` (Device Library §4.1) — `0x0100`, revision 3.
///
/// The claim is what makes a node show up in an app as a light rather than as a thing that
/// answers, and it is a *promise*: a commissioner reads `DeviceTypeList` and expects Identify
/// with `TriggerEffect`, Groups, On/Off with its Lighting feature, and Scenes Management with
/// `CopyScene` to all be there. `clusters::validate_endpoint` checks that promise against the
/// generated device-type library, and `tests/device_types.rs` runs it over this very cluster
/// list — in a test rather than at start-up, because an endpoint's furnishing is `const` and
/// the check costs the whole 131 KB cluster library to perform.
const ON_OFF_LIGHT_TYPE: &[DeviceType] = &[DeviceType::new(ON_OFF_LIGHT.id, ON_OFF_LIGHT.revision)];

/// How many groups one fabric may make on the light (§1.3), and how many scenes the endpoint
/// stores across all fabrics (§1.4.8.1 sets the minimum at 16).
const GROUPS_PER_FABRIC: usize = 4;
/// The whole group table, across every fabric.
const GROUP_SLOTS: usize = 16;
/// §1.4.8.1: "The minimum size of this table ... SHALL be 16"; §1.4.6 then gives each fabric
/// half of it.
const SCENE_SLOTS: usize = 16;
/// What one scene's extension field sets may occupy. This endpoint stores a single boolean,
/// so the room is for the clusters a later revision of this example might add.
const SCENE_BYTES: usize = 128;
/// How many fabrics' `SceneInfoStruct` the endpoint tracks (§1.4.8.2).
const FABRICS: usize = 5;

/// The Groups cluster as this example instantiates it — spelled out because the Scenes
/// cluster is generic over whatever answers §1.4.9's "is the endpoint in this group?".
type GroupTable<'a> =
    Groups<'a, GROUP_SLOTS, Identify<'a, Lamp>, SceneTable<SCENE_SLOTS, SCENE_BYTES, FABRICS>>;

/// The exchange table is `SESSIONS * EXCHANGES_PER_SESSION`, which is what
/// [`matter_kit::exchange::ExchangeTable`] documents its capacity as.
///
/// It was `16` — a round number, next to sixteen sessions, so a node with more than one
/// controller had fewer than one exchange each. The same mistake as D80, D89 and D91: a bound
/// chosen because it looked big enough rather than derived from what it bounds.
type Stack = Messaging<
    DefaultConfig,
    { DefaultConfig::SESSIONS },
    { DefaultConfig::SESSIONS * DefaultConfig::EXCHANGES_PER_SESSION },
>;

/// How many paths one subscription may name. §8.5's wildcard case needs few: a whole-node
/// subscription is one path with every field absent.
const SUB_PATHS: usize = DefaultConfig::SUB_PATHS;
type Subscriptions = SubscriptionTable<DefaultConfig, { DefaultConfig::SUBSCRIPTIONS }, SUB_PATHS>;

/// What the node owes a subscriber between its priming report and its `SubscribeResponse`.
///
/// §8.5.2 makes the grant the *fourth* message of the exchange, not the first: the report goes
/// out, the subscriber acknowledges it, and only then is the id it will see confirmed. So the
/// id has to survive between two dispatches.
#[derive(Debug, Clone, Copy)]
struct PendingSubscribe {
    id: u32,
    max_interval_s: u16,
    /// Whether the priming report chunked, in which case the acknowledgement asks for the rest
    /// (§10.2.3) and the response is still owed.
    more_chunks: bool,
}

/// The Groups cluster, seen as the membership table Group Key Management reads (§11.2.7.4).
///
/// Two clusters, one fact: §1.3 owns "which endpoints are in this group" and §11.2 reports it as
/// `GroupTable`. The library keeps them apart — a cluster does not reach into another cluster —
/// and asks the device to join them, which is this.
struct Memberships<'a>(&'a GroupTable<'a>);

impl group_key_management::GroupTable for Memberships<'_> {
    fn memberships(
        &self,
        each: &mut dyn FnMut(
            matter_kit::msg::FabricIndex,
            matter_kit::msg::GroupId,
            matter_kit::im::EndpointId,
        ),
    ) {
        // Endpoint 1 is the lamp, and the only endpoint this node puts in groups.
        for membership in self.0.memberships().iter() {
            each(membership.fabric, membership.group, 1);
        }
    }

    fn name(
        &self,
        fabric: matter_kit::msg::FabricIndex,
        group: matter_kit::msg::GroupId,
    ) -> Option<&str> {
        let _ = (fabric, group);
        // The names live behind a `Ref`, which cannot outlive this call. A device that stores
        // them outside the cluster would return them here.
        None
    }
}

/// What one interaction remembers between its own messages.
///
/// Per exchange, and that is the whole point. §10.2.3 makes a reply too large for one datagram
/// a *series*: "each data message requires a response before the next data message can be
/// sent", so the request outlives the message that carried it and the cursor remembers the
/// position in it. A node talks to more than one controller at a time — a certification run
/// always does, and a commissioned home does for as long as it has two hubs — and one copy of
/// this state shared between them resumes each controller's series wherever the *other* one
/// left off.
///
/// Nothing on the wire says so. Every message is well-formed, carries the right ids, and is
/// acknowledged; the data inside is simply someone else's. That is why this is a struct with a
/// key rather than three variables next to each other in `main`, which is what it was.
#[derive(Debug)]
struct Interaction {
    /// §10.2.3's position in the series.
    read_cursor: ReadCursor,
    /// The read request being served, kept because the continuation is served from the same
    /// bytes. A commissioner's first read is a wildcard over several clusters and never fits
    /// in one datagram, so this is the ordinary path and not an edge case.
    pending_read: heapless::Vec<u8, 1024>,
    /// A subscription whose priming report is still going out.
    pending_subscribe: Option<PendingSubscribe>,
}

impl Default for Interaction {
    fn default() -> Self {
        Self {
            read_cursor: ReadCursor::START,
            pending_read: heapless::Vec::new(),
            pending_subscribe: None,
        }
    }
}

impl Interaction {
    /// Whether nothing is part-way through, so the exchange may be closed.
    fn idle(&self) -> bool {
        self.pending_read.is_empty() && self.pending_subscribe.is_none()
    }
}

/// [`Interaction`] per open exchange.
///
/// Sized above `EXCHANGES_PER_SESSION` so an entry is never evicted while its exchange is
/// alive; [`Interactions::forget`] on close is what actually keeps it small.
#[derive(Debug, Default)]
struct Interactions {
    entries: heapless::Vec<(matter_kit::exchange::ExchangeKey, Instant, Interaction), 8>,
}

impl Interactions {
    fn new() -> Self {
        Self::default()
    }

    /// This exchange's state, created empty on first use.
    fn get(&mut self, key: matter_kit::exchange::ExchangeKey, now: Instant) -> &mut Interaction {
        // An exchange the stack reclaimed (`EXCHANGE_IDLE_TIMEOUT`) leaves its entry behind,
        // and exchange ids are the peer's to choose and to reuse. A stale `pending_read` under
        // a reused id makes a *new* read look like a continuation of a dead one — the same
        // cross-talk this type exists to prevent, arriving through the other door. So the
        // entries expire on the stack's own schedule.
        let expiry = now.saturating_sub(matter_kit::exchange::EXCHANGE_IDLE_TIMEOUT);
        self.entries
            .retain(|(k, seen, _)| *k == key || *seen > expiry);
        if let Some(index) = self.entries.iter().position(|(k, _, _)| *k == key) {
            self.entries[index].1 = now;
            return &mut self.entries[index].2;
        }
        if self.entries.is_full() {
            // Only reachable if every entry is live and `forget` was missed on a close.
            // Dropping the oldest keeps the node answering; that interaction restarts rather
            // than resuming, which is the safe direction.
            self.entries.remove(0);
        }
        let _ = self.entries.push((key, now, Interaction::default()));
        &mut self
            .entries
            .last_mut()
            .expect("just pushed, and the table was made room for")
            .2
    }

    /// Whether this exchange has nothing part-way through. True for one never seen.
    fn idle(&self, key: matter_kit::exchange::ExchangeKey) -> bool {
        self.entries
            .iter()
            .find(|(k, _, _)| *k == key)
            .is_none_or(|(_, _, state)| state.idle())
    }

    /// Whether this subscription's priming report is still going out, on any exchange.
    ///
    /// Asked per subscription rather than "is anything priming", which stops the whole node
    /// reporting whenever one controller subscribes.
    fn priming(&self, subscription: u32) -> bool {
        self.entries.iter().any(|(_, _, state)| {
            state
                .pending_subscribe
                .is_some_and(|p| p.id == subscription)
        })
    }

    /// How many exchanges this table is holding state for.
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Drops an exchange's state, which closing it makes unreachable.
    fn forget(&mut self, key: matter_kit::exchange::ExchangeKey) {
        self.entries.retain(|(k, _, _)| *k != key);
    }
}

/// The subject a subscription is created for, read from the session it arrived on (§6.6.6.3).
#[derive(Debug, Clone, Copy, Default)]
struct SubscriptionContext {
    session: Option<SessionId>,
    fabric_index: Option<FabricIndex>,
    peer_node_id: Option<NodeId>,
}

/// What the loop woke up for.
enum Event {
    Matter(usize, PeerAddr),
    Mdns(usize),
    Deadline,
}

fn main() {
    let timer = StdTimer::new();
    let rng = StdRng;

    // --- Sockets ---------------------------------------------------------------------------
    let matter_socket = match StdUdp::bind(matter_kit::PORT) {
        Ok(socket) => socket,
        Err(e) => {
            println!("could not bind UDP {} ({e:?})", matter_kit::PORT);
            println!("another Matter node is probably already running.");
            return;
        }
    };
    // Port 5353 is almost always already held by the system responder, which is why this
    // binds with SO_REUSEADDR rather than expecting the port to be free.
    //
    // The interface index matters twice: it is the link the group is joined on, and it is the
    // zone every answer is sent with. `ff02::fb` is link-local, so a send with no interface is
    // ambiguous and the operating system refuses it — a responder that got this wrong would
    // compute correct answers and transmit none of them. Override with `MATTER_IFINDEX`.
    // The address this node puts in its AAAA records. A device reads it from the interface it
    // advertises on; a process on a laptop has no portable way to ask, so it is told.
    let advertise_addr: Option<[u8; 16]> = std::env::var("MATTER_ADVERTISE_ADDR")
        .ok()
        .and_then(|v| v.parse::<std::net::Ipv6Addr>().ok())
        .map(|a| a.octets());
    let scope_id: u32 = std::env::var("MATTER_IFINDEX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_IFINDEX);
    let mdns_socket = match StdUdp::bind_mdns(scope_id) {
        Ok(socket) => socket,
        Err(e) => {
            println!("could not bind mDNS ({e:?}); the node will not be discoverable.");
            return;
        }
    };
    let Some(mdns_group) = mdns_socket.mdns_group() else {
        println!("the mDNS socket has no group to answer on");
        return;
    };

    // --- What the node is ------------------------------------------------------------------
    let location = Location::region_agnostic();
    let attributes = Attributes::new(&PRODUCT, false, false);
    // Sorted by cluster id — 0x001D, 0x001E, 0x001F, 0x0028, 0x0030, 0x0040, 0x0041 — because
    // every lookup binary-searches and `Node::validate` is what catches getting it wrong.
    // General Diagnostics' descriptor is *derived* from the specification's own tables rather
    // than written out: the element set follows the feature map, so this node — which claims
    // no features and reports nothing optional — advertises exactly the mandatory set and
    // nothing more. `AttributeList` and what the handler answers cannot drift apart.
    let diagnostics_descriptor = general_diagnostics::conforming(0, &Optional::NONE)
        .expect("the const parameters hold the mandatory set");
    // On/Off with Lighting: `StartUpOnOff`, `OnTime`, `OffWaitTime` and the timed-off state
    // machine, all of which appear because the feature is claimed rather than because anybody
    // listed them.
    let lamp_descriptor = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE)
        .expect("the const parameters hold the Lighting set");
    // The other three clusters an On/Off Light owes a commissioner. Each descriptor is derived
    // from the specification's own tables, and each carries the one optional element the
    // device type makes mandatory — `TriggerEffect` and `CopyScene`.
    let identify_descriptor = Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT)
        .expect("the const parameters hold the Identify set");
    let groups_descriptor =
        Groups::<GROUP_SLOTS>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE)
            .expect("the const parameters hold the Groups set");
    // §11.2 puts Group Key Management on the root endpoint, and it is mandatory for any node
    // that serves Groups at all — which this one does, on endpoint 1. Without it a commissioner
    // cannot write or read the group key set it needs to address the node by group, and
    // `KeySetRead` comes back `UnsupportedCluster`.
    let group_key_descriptor = GroupKeyManagement::<
        Memberships<'_>,
        { DefaultConfig::GROUP_KEYS },
        { DefaultConfig::GROUPS },
    >::conforming(0, &Optional::NONE)
    .expect("the const parameters hold the Group Key Management set");
    let scenes_descriptor =
        Scenes::<Lamp, GroupTable, SCENE_SLOTS, SCENE_BYTES, FABRICS>::conforming(
            scenes::feature::SCENE_NAMES,
            &Scenes::<Lamp, GroupTable, SCENE_SLOTS, SCENE_BYTES, FABRICS>::WITH_COPY_SCENE,
        )
        .expect("the const parameters hold the Scenes set");
    let clusters = [
        descriptor::cluster(),                  // 0x001D
        binding::cluster(),                     // 0x001E
        access_control::cluster(),              // 0x001F
        attributes.cluster(),                   // 0x0028
        general_commissioning::cluster(),       // 0x0030
        diagnostics_descriptor.descriptor(),    // 0x0033
        administrator_commissioning::cluster(), // 0x003C — ECM only, no `BC` feature
        opcreds::cluster(),                     // 0x003E
        group_key_descriptor.descriptor(),      // 0x003F
        label::fixed_cluster(),                 // 0x0040
        label::user_cluster(),                  // 0x0041
    ];
    // Endpoint 1: the light itself. Sorted by cluster id, like endpoint 0's — Identify,
    // Groups, On/Off, Descriptor, Scenes Management.
    let lamp_clusters = [
        identify_descriptor.descriptor(), // 0x0003
        groups_descriptor.descriptor(),   // 0x0004
        lamp_descriptor.descriptor(),     // 0x0006
        descriptor::cluster(),            // 0x001D
        scenes_descriptor.descriptor(),   // 0x0062
    ];
    let endpoints = [
        Endpoint::new(0, &clusters).with_device_types(ROOT_NODE),
        Endpoint::new(1, &lamp_clusters).with_device_types(ON_OFF_LIGHT_TYPE),
    ];
    let node = Node::new(&endpoints);
    node.validate().expect("the clusters are sorted by id");

    // --- Attestation ------------------------------------------------------------------------
    // §6.2.2's chain, generated at start-up rather than burned in at manufacture. A real product
    // has its DAC written by a factory tool and its private key in a secure element; this is a
    // development device, and generating the chain is what makes the example self-contained —
    // nothing to vendor, nothing to keep in step with a certificate somebody else issued.
    let keys = RefCell::new(SoftKeyStore::<8>::new());
    // `DerWriter` fills its buffer **from the end backwards**, so that a length is always known
    // by the time its header is written — which means a certificate is the *tail* of the buffer
    // and never a prefix of it. Copying the returned slice out is what keeps that detail from
    // leaking downstream; taking `&buf[..len]` instead yields a block of zeros that every
    // parser rejects, and the failure surfaces a long way away, as a commissioner refusing the
    // attestation it was sent.
    let mut scratch_cert = [0u8; 1024];
    let mut paa_der: heapless::Vec<u8, 1024> = heapless::Vec::new();
    let mut pai_der: heapless::Vec<u8, 1024> = heapless::Vec::new();
    let mut dac_der: heapless::Vec<u8, 1024> = heapless::Vec::new();
    let dac_key = {
        let mut store = keys.borrow_mut();
        let mut seed = [0u8; 32];
        let mut fresh = |store: &mut SoftKeyStore<8>| {
            rng.fill(&mut seed).expect("rng");
            store
                .generate(KeyPurpose::DeviceAttestation, &seed)
                .expect("generate an attestation key")
        };
        let (paa_key, _) = fresh(&mut store);
        let (pai_key, pai_public) = fresh(&mut store);
        let (dac_key, dac_public) = fresh(&mut store);
        // §6.2.2.4's validity, in *Matter* epoch seconds — 2000-01-01, not 1970. Anchoring it
        // at zero makes a chain that expired in 2010, which a commissioner reports as
        // `DAC is expired` long after the certificate itself parsed perfectly.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u64, |d| d.as_secs());
        let not_before = u32::try_from(
            now_unix.saturating_sub(u64::try_from(matter_kit::der::MATTER_EPOCH_UNIX).unwrap_or(0)),
        )
        .unwrap_or(0);
        let chain = DevelopmentChain::new(not_before, 10);
        paa_der
            .extend_from_slice(chain.paa(&*store, &mut scratch_cert, paa_key).expect("PAA"))
            .expect("the PAA fits");
        pai_der
            .extend_from_slice(
                chain
                    .pai(&*store, &mut scratch_cert, paa_key, &pai_public)
                    .expect("PAI"),
            )
            .expect("the PAI fits");
        dac_der
            .extend_from_slice(
                chain
                    .dac(&*store, &mut scratch_cert, pai_key, &dac_public, PRODUCT_ID)
                    .expect("DAC"),
            )
            .expect("the DAC fits");
        dac_key
    };
    let paa_der = &paa_der[..];
    let pai_der = &pai_der[..];
    let dac_der = &dac_der[..];

    // A commissioner verifies the DAC chain against a *PAA it already trusts* (§6.2.2.3), and a
    // chain generated at start-up is in nobody's trust store. Writing the root out is what lets
    // one be pointed at it — `chip-tool --paa-trust-store-path` takes a directory of DER — so
    // attestation can be verified for real rather than bypassed.
    if let Ok(dir) = std::env::var("MATTER_PAA_OUT") {
        let path = std::path::Path::new(&dir).join("matter-kit-dev-paa.der");
        match std::fs::write(&path, paa_der) {
            Ok(()) => println!("  PAA written to {}", path.display()),
            Err(e) => println!("  could not write the PAA to {} ({e})", path.display()),
        }
    }

    let fabrics = RefCell::new(FabricTable::<DefaultConfig, { DefaultConfig::FABRICS }>::new());
    let rng_cell = RefCell::new(StdRng);
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let window = RefCell::new(CommissioningWindow::new());
    // §11.19. The window is shared with General Commissioning, which closes it when
    // `CommissioningComplete` succeeds; this is what *opens* it again, and without it a node
    // can never join a second fabric — the only way in is the commissioning window, and the
    // only way to open one after the first commissioner has gone is this command.
    let vendor_of_fabric = |index: matter_kit::msg::FabricIndex| {
        fabrics.borrow().find(index).map(|f| f.admin_vendor_id)
    };
    let general_commissioning = GeneralCommissioning::new(
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );
    let admin_commissioning =
        AdministratorCommissioning::new(&window, &fail_safe, &vendor_of_fabric);
    let acl = RefCell::new(Acl::<DefaultConfig, ACL_ENTRIES, ACL_SUBJECTS, ACL_TARGETS>::new());
    // Named so its §9.10.9.1 change records can be drained into the event store after every
    // interaction. The cluster edits the list; turning the edits into *events* is the device's
    // job, because the event store is the device's (D31).
    let access_control_cluster = AccessControl::new(&acl);
    let bindings = Binding::<DefaultConfig, 8>::new(4);
    let user_labels = UserLabel::<4>::new();
    let diagnostics = Uptime::new(&timer);
    let lamp = Lamp::default();
    // `StartUpOnOff` is null — "the OnOff attribute is set to its previous value" — and this
    // process persists nothing, so the previous value is off.
    let lamp_cluster = OnOff::new(&lamp, on_off::feature::LIGHTING, None);
    lamp_cluster.start(false);
    // The Scene Table is a value of its own because two clusters hold it: §1.3.7.4 makes
    // `RemoveGroup` remove that group's scenes, which is a rule about the Scene Table written
    // in the Groups chapter. Building it first is what lets both borrow it without a cycle.
    let scene_table = SceneTable::<SCENE_SLOTS, SCENE_BYTES, FABRICS>::new(true);
    let identify_cluster = Identify::new(&lamp, IdentifyTypeEnum::LightOutput);
    let groups_cluster: GroupTable<'_> =
        Groups::with(GROUPS_PER_FABRIC, true, &identify_cluster, &scene_table);
    let scenes_cluster = Scenes::new(&scene_table, &groups_cluster, &lamp, true);
    let memberships = Memberships(&groups_cluster);
    let group_keys = RefCell::new(matter_kit::group::GroupKeys::<
        { DefaultConfig::GROUP_KEYS },
        { DefaultConfig::GROUPS },
    >::new(GROUPS_PER_FABRIC, 3));
    let group_keys_cluster = GroupKeyManagement::new(&group_keys, &memberships);
    // Named rather than built inline, because §11.18.6.8's `AddNOC` does not finish inside
    // the cluster: it *reports* what the node must do next through `take_change`, and step 7
    // of that list is an access-control entry only the node can add (D31). A node that never
    // reads the report joins the fabric, advertises itself, and refuses every CASE
    // interaction that follows with `UNSUPPORTED_ACCESS` — "there would be no way for the
    // caller on its given Fabric to eventually add another Access Control Entry".
    let opcreds = OperationalCredentials::new(
        &fabrics,
        &keys,
        &rng_cell,
        &fail_safe,
        DeviceAttestation {
            dac: dac_der,
            pai: pai_der,
            certification_declaration: CERTIFICATION_DECLARATION,
            dac_key,
            firmware_information: None,
        },
    );

    // Two endpoints, so the handler routes on the endpoint before the cluster id: both
    // endpoints serve Descriptor (§9.5), and the id alone no longer picks an instance.
    let handler = Endpoints((
        At::new(
            0,
            (
                Descriptor::new(node, 0).with_parts(&[1]),
                &bindings,
                &access_control_cluster,
                BasicInformation::new(&PRODUCT, &location),
                &general_commissioning,
                GeneralDiagnostics::new(&diagnostics, 0),
                &admin_commissioning,
                &opcreds,
                &group_keys_cluster,
                FixedLabel::new(FIXED_LABELS),
                &user_labels,
            ),
        ),
        At::new(
            1,
            (
                Descriptor::new(node, 1),
                &identify_cluster,
                &groups_cluster,
                &lamp_cluster,
                &scenes_cluster,
            ),
        ),
    ));

    // §7.10.3's data versions. Every cluster instance needs one, and a report without one is
    // an attribute the CHIP SDK's cache discards — so a device that omits them is legal and
    // uncommissionable at the same time.
    let versions = DataVersions::<16>::new(rng.next_u32().expect("rng"));
    // §7.14's event log. Four of each priority is small on purpose: the ring drops its oldest
    // rather than refusing, so the size is a bandwidth choice, not a correctness one.
    //
    // A node whose clusters define events and which serves none reports an empty log, and a
    // client cannot tell that from a node that has genuinely recorded nothing — which is why
    // §9.10's `AccessControlEntryChanged` is wired below rather than left as an exercise.
    let events = RefCell::new(matter_kit::dm::events::EventStore::<4, 4, 4>::new({
        // §7.14.1.1's numbers are "monotonically increasing for the life of the node" and
        // survive a reboot, so they are handed out in *reserved blocks*: the node persists the
        // high-water mark before using any number below it, and a store that has not been told
        // the reservation landed refuses to record. A device restores the mark from storage and
        // writes the next one back; this one has no storage, so it acknowledges its own.
        //
        // Skipping this is silent in the worst way — every `record` returns
        // `NeedsReservation` and the node simply has no events, which is what it looks like
        // when nothing has happened.
        let mut numbers = matter_kit::dm::events::EventNumbers::restore(0);
        if let Some(owed) = numbers.reservation() {
            numbers.reserved(owed);
        }
        numbers
    }));

    // --- What it advertises ------------------------------------------------------------------
    let txt = CommissionableTxt {
        discriminator: DISCRIMINATOR,
        vendor_id: Some(VENDOR),
        product_id: Some(PRODUCT_ID),
        commissioning_mode: CommissioningMode::Basic,
        ..CommissionableTxt::default()
    }
    .encode()
    .expect("the advertisement fits");
    let txt = txt.finish();

    let long_subtype = format!("_L{DISCRIMINATOR}");
    let short_subtype = format!("_S{}", DISCRIMINATOR >> 8);
    let advertisement = Advertisement::new(
        "0011223344556677",
        COMMISSIONABLE_SERVICE,
        "0011223344556677",
        matter_kit::PORT,
        txt,
    )
    .with_subtype(&long_subtype)
    .expect("subtype")
    .with_subtype(&short_subtype)
    .expect("subtype")
    .with_subtype("_CM")
    .expect("subtype");
    let commissionable = match advertise_addr {
        Some(address) => advertisement.with_address(address).expect("address"),
        None => advertisement,
    };

    // --- Session establishment ----------------------------------------------------------------
    let parameters = PbkdfParameters::new(ITERATIONS, SALT).expect("parameters");
    let verifier =
        Spake2pVerifierData::from_passcode(PASSCODE, SALT, ITERATIONS).expect("verifier");

    let mut stack = Stack::new(
        rng.next_u32().expect("rng") as u16 | 1,
        rng.next_u32().expect("rng") as u16,
        rng.next_u32().expect("rng"),
    );
    // §8.7.4's window table and §10.2.3's read cursor, both of which belong to the node rather
    // than to one message. `MaxPathsPerInvoke` is what Basic Information advertises.
    let mut dispatcher: Dispatcher<4> = Dispatcher::new(PRODUCT.max_paths_per_invoke);
    // §10.2.3's series state, one entry per exchange. See [`Interaction`].
    let mut interactions = Interactions::new();
    // §8.5's subscriptions. The table outlives every exchange that touches it: a subscription
    // is created by one, reported on by many, and removed when its session goes away.
    let mut subscriptions = Subscriptions::new();
    // One outstanding report per subscription, and no more. A report goes out on an exchange of
    // the node's own making, and MRP owns it until the subscriber acknowledges it or it is
    // abandoned. Opening a second one while the first is still in flight is how a node with
    // `EXCHANGES_PER_SESSION` of four fills its table in four ticks and then drops every
    // datagram with `no space` — including the acknowledgements that would have freed it.
    let mut reporting: heapless::Vec<(u32, matter_kit::exchange::ExchangeKey), 8> =
        heapless::Vec::new();
    // §6.2.3's attestation challenge, which PASE produces alongside the session keys and which
    // `AttestationRequest` signs over. It belongs to the *session*, so a device with more than
    // one would keep it there; this example holds the one it has.
    let mut attestation_challenge: Option<matter_kit::crypto::SymmetricKey> = None;
    let mut case: Option<CaseResponder> = None;
    let mut case_local = SessionId(0);
    // The fabric Sigma1 resolved from the destination identifier. Sigma3 validates the peer's
    // certificate chain against *this* fabric's root.
    let mut case_fabric = matter_kit::msg::FabricIndex(0);
    let mut pase: Option<PaseResponder> = None;
    let mut pase_local = SessionId(0);
    // §5.5's gate: one handshake at a time, sixty seconds to finish it, twenty failures and
    // the node leaves commissioning mode. Without it the second `PBKDFParamRequest` to arrive
    // would replace the first — which is a session takeover, not a race.
    let mut admission = PaseAdmission::new();
    // Whether a commissioning window was open last time round the loop, so that its *opening*
    // can be acted on. See the note at the top of the loop body.
    let mut window_was_open = false;

    println!("matter-kit light");
    println!("  UDP        :{}", matter_kit::PORT);
    println!("  mDNS       :{MDNS_PORT} (ff02::fb, interface {scope_id})");
    println!("  passcode    {PASSCODE}");
    println!("  discriminator {DISCRIMINATOR}");
    println!("\n  chip-tool pairing onnetwork 1 {PASSCODE}\n");

    block_on(async {
        let mut matter_buf = [0u8; 1280];
        let mut mdns_buf = [0u8; 1280];
        let mut out = [0u8; 1280];
        // Sigma2 is the largest single payload this node ever encodes: two certificates at
        // §6.1.3's 400-octet cap, encrypted, plus the handshake's own fields. That is 1081
        // octets, and this buffer used to be a round 1024 — which worked against every
        // certificate in this repository and failed against a CA that issues certificates at
        // the size the specification permits, as `sigma1 refused: buffer too small`. Sizing it
        // from the library's own bound is the fix; the round number was the bug.
        // The interaction model's reply, before the messaging layer frames it. `MAX_SIGMA2` was
        // the wrong bound again and for the third time in this file: a *secure channel* figure
        // used because it was the largest constant in scope. A whole-node wildcard read chunks
        // to fill a datagram, and a chunk that cannot be built is `refused: buffer too small` —
        // from this node, about its own reply, with nothing on the wire to explain it.
        //
        // `MAX_UDP_PAYLOAD` is the datagram bound minus the worst-case framing, which is the
        // number this buffer actually wants. Sigma2 is smaller than it, so this covers both.
        let mut payload = [0u8; matter_kit::config::MAX_UDP_PAYLOAD];
        // The scratch a read builds **one whole attribute value** in, before the server decides
        // whether it fits the message or has to be split across several (§10.6.4.3.1). It is
        // therefore sized by the largest *value* this node can produce, not by the largest
        // message it can send — and those are different numbers, because a value too big for a
        // message is exactly the case list chunking exists for.
        //
        // `MAX_SIGMA2` was the wrong bound and the same mistake as D80 in the other direction:
        // a buffer sized by whatever constant happened to be biggest. A non-fabric-filtered read
        // of `NOCs` carries every fabric's NOC and ICAC — §6.1.3 caps each at 400 octets — so
        // five fabrics is over four kilobytes, and the cluster ran out of room writing it and
        // answered `ResourceExhausted` before the server ever got the chance to chunk it.
        // `max_nocs_len` is the library's own bound for it, so nobody has to do that sum.
        let mut scratch = [0u8; opcreds::max_nocs_len(DefaultConfig::FABRICS)];
        // Where §4.8's AEAD is handed the protocol header and the payload joined together.
        // A datagram node needs exactly Core §4.4.4's 1280 octets and no more.
        let mut frame_buf = [0u8; 1280];

        loop {
            let now = timer.now();
            // §8.5.3: a change to a path a subscription covers is what makes a report due, and
            // §7.10.3 already records every such change — "A cluster data version SHALL be
            // incremented if any attribute data changes". So the version table is where changes
            // are read from, rather than every cluster being taught to announce each field it
            // touches.
            //
            // Drained here, at the top of the loop, rather than beside the code that answered
            // the request — because that path has four `continue`s in it. A suppressed write, a
            // groupcast, a `StatusResponse`, a message for a protocol this node does not serve:
            // each one leaves early, and each one would have skipped the drain and lost the
            // change with it. `drain_changes` is destructive, so a change skipped is a change
            // nobody is left to hear about.
            // §5.5's "Device enters commissioning mode" is one of the two things that
            // re-admit a node — and a node commissioned once is *not* admitting anybody.
            // `PaseAdmission` holds the channel `Established` from the moment PASE succeeded
            // until it is told otherwise, which is the rule that stops a second commissioner
            // hijacking the first one's handshake; it also means that without this, a node can
            // never be commissioned twice. `OpenCommissioningWindow` succeeds, the node
            // advertises, the new administrator finds it — and every `PBKDFParamRequest` comes
            // back `Busy`, which looks like a device that is ignoring its own open window.
            //
            // Watched here rather than signalled from the cluster, because the cluster is
            // reached through the `ClusterHandler` and has no business knowing about the
            // node's secure channel. The window opening is the observable fact.
            let window_open = window.borrow().open(now).is_some();
            if window_open && !window_was_open {
                admission.reset();
                println!("  commissioning window open — the channel admits PASE again");
            }
            window_was_open = window_open;
            // §5.5 rule 1 holds the commissioning channel closed while a PASE session is
            // established on it, which is what stops a second commissioner stepping into the
            // first one's handshake. It is released by a `CloseSession`, and a commissioner is
            // under no obligation to send one: the CHIP controller calls `StopPairing`, evicts
            // its own session, says nothing to the node, and opens a fresh PASE five seconds
            // later. The node answers `Busy` for ever.
            //
            // An open commissioning window with a *disarmed* fail-safe is the honest reading of
            // "no commissioning is in progress": the previous one either committed or rolled
            // back, so there is no handshake left to hijack and the window is an explicit
            // invitation to start another. Without a window this does not fire, so a
            // commissioned node with nothing open still refuses PASE — which is the point of
            // the rule.
            if window_open && admission.is_established() && fail_safe.borrow().armed(now).is_none()
            {
                admission.closed();
                println!("  commissioning finished and the window is open — PASE admitted again");
            }

            for (endpoint, cluster) in versions.drain_changes() {
                let dirtied = subscriptions.note_cluster_change(endpoint, cluster);
                println!(
                    "  change: endpoint {endpoint} cluster {cluster:#06x} -> {dirtied} subscription(s)"
                );
            }
            // Everything time-driven, on every iteration and not in an arm of the select.
            //
            // These used to live under `Event::Deadline`, which meant they ran only when the
            // timer won a race against two sockets — and a select that returns the first ready
            // source always starves something. Done here, they are driven by the loop itself:
            // whichever event woke it, MRP's retransmissions and §8.5.3's reports are both
            // considered before anything else happens, and neither traffic nor an overdue
            // deadline can crowd the other out.
            // §8.5.3: a subscription reports when something it covers has changed and
            // `MinInterval` has passed, or when `MaxInterval` is about to, whichever
            // comes first. The second is the keep-alive, and it is what stops a quiet
            // node from being declared dead.
            //
            // A subscription does not report while *its own* priming report is still
            // going out. §8.5.2 makes the subscription active only once the
            // `SubscribeResponse` has been sent, and a report before that does more than
            // jump the gun: it calls
            // `reported()`, which clears the re-prime flag *mid-series*, so the next
            // chunk of the priming report finds an empty dirty set and carries nothing.
            // The subscriber then holds whatever the first chunk happened to contain
            // and believes it has the whole node. With a `MinIntervalFloor` of zero —
            // which is what the CHIP test framework asks for — that race is not a race
            // at all, it is the ordinary case.
            let due_now: heapless::Vec<(u32, ReportReason), { DefaultConfig::SUBSCRIPTIONS }> =
                subscriptions
                    .due(now)
                    .filter(|(s, _)| !interactions.priming(s.id))
                    .map(|(s, reason)| (s.id, reason))
                    .collect();
            for (id, reason) in due_now {
                if reporting.iter().any(|(pending, _)| *pending == id) {
                    continue;
                }
                // The in-flight table is what bounds exchange creation, and a `push` that
                // silently fails removes that bound: the guard above never sees the entry, so
                // the subscription opens a *fresh* exchange every time round the loop and the
                // node fills its exchange table in a handful of iterations. After that it drops
                // every datagram with `no space` — including the acknowledgements that would
                // have freed it, so nothing recovers until MRP has given up on all of them,
                // tens of seconds later.
                //
                // Only reachable once reports actually went out (D83): while every report was
                // being built and dropped, no exchange was ever held open by one.
                //
                // `break` rather than `continue`, because no other subscription can be sent
                // this round either.
                if reporting.is_full() {
                    println!("  reports already in flight; subscription {id} waits");
                    break;
                }
                let Some(session) = subscriptions.find(id).and_then(|s| s.session) else {
                    println!("  subscription {id} is due but has no session to report on");
                    continue;
                };
                let Some(subscription) = subscriptions.find(id) else {
                    continue;
                };
                // §6.6.6.3 again: the report is served to the *subscriber*, so it is
                // filtered by the subscriber's standing, not by the node's. A
                // subscription remembers the fabric and node CASE proved for exactly
                // this, because the session it was created on may be long gone.
                let subject = match (subscription.fabric_index, subscription.peer_node_id) {
                    (Some(fabric), Some(node_id)) => SubjectDescriptor::case(fabric, node_id),
                    _ => SubjectDescriptor::unauthenticated(),
                };
                let access = AclAccess::new(&acl, node, &subject);
                let server = Server::new(node, &access, &handler, 24)
                    .with_data_versions(&versions)
                    .with_events(&events);
                let mut ctx = InteractionContext::new().at(now);
                if let Some(fabric) = subscription.fabric_index {
                    ctx = ctx.with_fabric(fabric);
                }
                let Some(subscription) = subscriptions.find_mut(id) else {
                    continue;
                };
                let report =
                    server.report_chunk(subscription, reason, &ctx, &mut scratch, &mut payload);
                let Ok((bytes, _)) = report else {
                    println!("  could not build a report for subscription {id}");
                    continue;
                };
                let len = bytes.len();
                let Ok(exchange) = stack.open(session, ProtocolId::INTERACTION_MODEL, now) else {
                    println!("  no exchange for subscription {id}");
                    continue;
                };
                let randomness = rng.next_u32().expect("rng");
                // Every way this can fail is reported. A report that is built, encrypted,
                // counted and then silently dropped is indistinguishable from one that was
                // never due: the subscriber simply never hears again, holds whatever the
                // priming report gave it, and there is no error at either end to find. That
                // is exactly how this went unnoticed through a dozen container runs.
                let framed = match stack.send(
                    exchange,
                    matter_kit::im::opcode::REPORT_DATA,
                    true,
                    &payload[..len],
                    now,
                    randomness,
                    &mut frame_buf,
                    &mut out,
                ) {
                    Ok((sent, _)) => Some(sent),
                    Err(e) => {
                        println!("  subscription {id}: report could not be framed: {e}");
                        None
                    }
                };
                let addr = match stack.peer(exchange) {
                    Some(Peer::Udp(addr)) => Some(addr),
                    other => {
                        println!("  subscription {id}: nowhere to send the report: {other:?}");
                        None
                    }
                };
                let mut delivered = false;
                if let (Some(sent), Some(addr)) = (framed, addr) {
                    match matter_socket.send_to(&out[..sent], addr).await {
                        Ok(_) => {
                            let _ = reporting.push((id, exchange));
                            delivered = true;
                        }
                        Err(e) => println!("  subscription {id}: report not sent: {e}"),
                    }
                }
                if !delivered {
                    // Nothing went out, so nothing is owed on this exchange — and the
                    // subscription is *not* marked reported, or the change that prompted
                    // this would be forgotten by a report the subscriber never received.
                    stack.close(exchange);
                    continue;
                }
                if let Some(subscription) = subscriptions.find_mut(id) {
                    // Reported as far as this node is concerned: MRP owns delivery from
                    // here, and re-reporting because an acknowledgement has not arrived
                    // yet would send the same data twice.
                    subscription.reported(now);
                }
            }

            while let Some(due) = stack.poll(now, rng.next_u32().expect("rng")) {
                match due {
                    // §4.12.5.2.2: the acknowledgement waited for a message to ride
                    // on and none came, so it goes on its own — and it has to actually
                    // go. `acknowledge` only *writes* it; the exchange knows the peer
                    // it is owed to, which is the whole reason `Messaging::peer`
                    // exists. Building the datagram and dropping it leaves the sender
                    // retransmitting until it gives up, which is a timeout at the far
                    // end and silence at this one.
                    Due::Acknowledge { exchange } => {
                        if let Ok(len) = stack.acknowledge(exchange, now, &mut out)
                            && len > 0
                            && let Some(Peer::Udp(addr)) = stack.peer(exchange)
                        {
                            match matter_socket.send_to(&out[..len], addr).await {
                                Ok(()) => println!("  standalone ack"),
                                Err(e) => println!("  standalone ack failed: {e}"),
                            }
                        }
                        // §4.10.5.3's other door, and the one that wedges a busy node.
                        // A standalone acknowledgement goes out when this node received
                        // something it is not replying to — a `StatusResponse` closing a
                        // report or a read series, a suppressed write, an opcode it does not
                        // serve. No `Received::Acknowledged` is ever coming for it, because
                        // nobody acknowledges an acknowledgement, so the arm that closes
                        // exchanges never sees this one and it sits for D75's sixty seconds.
                        // A certification case produces hundreds of them in far less than
                        // that: measured, the table went from full — every datagram dropped
                        // with `no space`, including the acknowledgements that would have
                        // freed it — to consistently empty.
                        //
                        // Restricted to exchanges **this node did not open**. Its own are the
                        // report exchanges, and those are already accounted for by
                        // `reporting`, `Received::Acknowledged` and `Due::Abandoned`; closing
                        // one here would drop the acknowledgement it is waiting for.
                        if matches!(exchange.role, matter_kit::exchange::Role::Responder)
                            && interactions.idle(exchange)
                        {
                            interactions.forget(exchange);
                            stack.close(exchange);
                        }
                    }
                    // A real device keeps the bytes it sent so it can resend them;
                    // this one has nothing in flight worth the buffer.
                    Due::Retransmit { .. } => {}
                    Due::Abandoned { exchange } => {
                        // MRP has given up; the exchange is closed and its report will
                        // never be acknowledged, so free the slot or this subscription
                        // never reports again.
                        reporting.retain(|(_, sent_on)| *sent_on != exchange);
                        interactions.forget(exchange);
                        println!("  gave up on exchange {:?}", exchange.id);
                    }
                }
            }
            // §5.5's sixty seconds is a deadline like any other, so it goes in the same
            // place MRP's does — a timer the loop already waits on rather than a special case.
            let deadline = [
                stack.wake_at(),
                admission.deadline(),
                // §8.5.3's MaxInterval is a promise: a subscriber that hears nothing for longer
                // than the interval it was granted considers the subscription dead. So the
                // report deadline is a deadline like any other, and the loop waits on it.
                subscriptions.next_deadline(),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or_else(|| now.saturating_add(matter_kit::platform::Duration::from_secs(1)));

            // Wait for whichever comes first. Written out rather than with a `select`
            // combinator because the crate deliberately has no executor of its own: this is
            // the whole of what one would have provided.
            let event = {
                let mut matter = pin!(matter_socket.recv_from(&mut matter_buf));
                let mut mdns = pin!(mdns_socket.recv_from(&mut mdns_buf));
                let mut sleep = pin!(timer.sleep_until(deadline));
                poll_fn(|cx| {
                    // A select that returns the *first* ready source starves whichever it polls
                    // last, and both orderings were tried. Sockets first starves the timer on a
                    // network with steady mDNS traffic — the deadline passes and passes and the
                    // arm that would notice is never chosen. Timer first starves the sockets the
                    // moment any deadline is overdue, because an overdue timer is ready forever.
                    //
                    // So the ordering is not where time-driven work belongs. Everything the
                    // deadline used to carry — §8.5.3's reports, MRP's retransmissions — is done
                    // at the top of the loop now, on every iteration, whichever event woke it.
                    // What is left here is only *waiting*, and waiting may prefer the sockets.
                    if let Poll::Ready(Ok((n, from))) = matter.as_mut().poll(cx) {
                        return Poll::Ready(Event::Matter(n, from));
                    }
                    if let Poll::Ready(Ok((n, from))) = mdns.as_mut().poll(cx) {
                        let _ = from;
                        return Poll::Ready(Event::Mdns(n));
                    }
                    if sleep.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Event::Deadline);
                    }
                    Poll::Pending
                })
                .await
            };
            let now = timer.now();

            match event {
                // --- A Matter message ---------------------------------------------------
                Event::Matter(n, from) => {
                    let received = match stack.receive(&mut matter_buf[..n], Peer::Udp(from), now) {
                        Ok(received) => received,
                        Err(e) => {
                            println!("  dropped a datagram: {e}");
                            let mut census: std::collections::BTreeMap<String, usize> =
                                std::collections::BTreeMap::new();
                            for open in stack.exchanges().iter() {
                                *census
                                    .entry(format!("{:?}/{:?}", open.protocol, open.key.role))
                                    .or_default() += 1;
                            }
                            println!(
                                "  EXCHANGES {} open: {census:?} | interactions {}",
                                stack.exchanges().len(),
                                interactions.len()
                            );
                            continue;
                        }
                    };
                    let (exchange, header, body) = match received {
                        Received::Message {
                            exchange,
                            header,
                            payload,
                            ..
                        } => (exchange, header, payload.to_vec()),
                        // §4.12.2.2: acknowledged, not acted on.
                        Received::Duplicate { exchange, .. } => {
                            let len = stack.acknowledge(exchange, now, &mut out).unwrap_or(0);
                            if len > 0 {
                                let _ = matter_socket.send_to(&out[..len], from).await;
                            }
                            continue;
                        }
                        // §4.10.5.3 leaves reclaiming a finished exchange to "the
                        // application layer", and a fixed-capacity table makes that not
                        // optional: once the peer has acknowledged the response, a
                        // request/response exchange is over. An example that never says so
                        // fills `EXCHANGES_PER_SESSION` and then drops every datagram with
                        // `no space` — which looks like the peer going quiet, and is this node
                        // refusing to listen. D75's sixty-second reclamation is the backstop
                        // for exchanges nobody finished, not a substitute for finishing them.
                        //
                        // A chunked read is the exception: the client acknowledges each chunk
                        // and then asks for the next on the *same* exchange (§10.2.3), so the
                        // exchange is finished only when the series is.
                        Received::Acknowledged { exchange } => {
                            // Two series keep an exchange alive past the acknowledgement of a
                            // single message, and both of them are §10.2.3's chunking: a read
                            // whose continuation is held in `pending_read`, and a subscription
                            // whose priming report is still going out. In each the subscriber
                            // acknowledges a chunk and then asks for the next *on the same
                            // exchange*, so closing here would strand the series — the next
                            // request arrives on an exchange that no longer exists, and the
                            // subscriber is left holding whichever chunks it happened to get.
                            // A report this node sent has been acknowledged: the slot is free
                            // for the next one.
                            reporting.retain(|(_, sent_on)| *sent_on != exchange);
                            // Asked of *this* exchange. A global check keeps every exchange
                            // open for as long as any one of them has a series running, which
                            // is D75's reclamation bug wearing a different hat: the table
                            // fills, and the node then drops the datagrams that would have
                            // freed it.
                            if interactions.idle(exchange) {
                                interactions.forget(exchange);
                                stack.close(exchange);
                            }
                            continue;
                        }
                    };

                    let reply = if header.protocol == ProtocolId::SECURE_CHANNEL {
                        match header.opcode {
                            // §5.5: one handshake at a time, sixty seconds to finish it,
                            // twenty failures and the node leaves commissioning mode. Answering
                            // every request unconditionally — which is the obvious thing to
                            // write — lets a second commissioner replace an in-flight one and
                            // finish the handshake in its place.
                            opcode::PBKDF_PARAM_REQUEST => match admission.admit(true, now) {
                                Admit::Admitted => {
                                    // §11.19.8.1: an Enhanced window runs PASE against the
                                    // verifier the *administrator* supplied, with that
                                    // command's salt and iteration count — not the factory
                                    // passcode. A node that answers with its own verifier
                                    // while an ECM window is open is a node whose printed
                                    // passcode still works after an administrator deliberately
                                    // replaced it, which is the guarantee ECM exists to give.
                                    // A Basic window carries no verifier and falls back to the
                                    // factory one, which is what makes it Basic.
                                    let ecm = window.borrow().ephemeral(now).and_then(|e| {
                                        let v =
                                            Spake2pVerifierData::from_bytes(&e.verifier).ok()?;
                                        let p = PbkdfParameters::new(e.iterations, &e.salt).ok()?;
                                        Some((v, p))
                                    });
                                    let (verifier, parameters) = match ecm {
                                        Some((v, p)) => (v, p),
                                        None => (verifier, parameters.clone()),
                                    };
                                    let mut responder = PaseResponder::new(
                                        ResponderConfig {
                                            verifier,
                                            parameters,
                                            session_params: Some(SessionParams::default()),
                                        },
                                        // A session id this node is not already using.
                                        SessionId(rng.next_u32().expect("rng") as u16 | 1),
                                    );
                                    let mut random = [0u8; 32];
                                    rng.fill(&mut random).expect("rng");
                                    match responder.on_pbkdf_param_request(
                                        &body,
                                        &random,
                                        &mut payload,
                                    ) {
                                        Ok(n) => {
                                            pase_local = responder.local_session_id();
                                            pase = Some(responder);
                                            Ok((opcode::PBKDF_PARAM_RESPONSE, n))
                                        }
                                        // A request this node could not parse is a failed
                                        // attempt like any other: it frees the channel, and it
                                        // counts towards the twenty.
                                        Err(e) => {
                                            report_failure(&mut admission, &mut pase, &window);
                                            Err(e)
                                        }
                                    }
                                }
                                // §4.11.1.3's codes: BUSY says "not now", which is true while
                                // another commissioner holds the channel; the rest are refusals
                                // that will not change until the device is put back into
                                // commissioning mode.
                                refusal => {
                                    println!("  refused a PASE request: {refusal:?}");
                                    let code = if matches!(refusal, Admit::Busy) {
                                        SecureChannelCode::Busy
                                    } else {
                                        SecureChannelCode::InvalidParameter
                                    };
                                    StatusReport::secure_channel(code)
                                        .encode(&mut payload)
                                        .map(|n| (opcode::STATUS_REPORT, n))
                                }
                            },
                            opcode::PAKE1 => {
                                let mut random = [0u8; 32];
                                rng.fill(&mut random).expect("rng");
                                match pase.as_mut() {
                                    Some(p) => {
                                        let r = p
                                            .on_pake1(&body, &random, &mut payload)
                                            .map(|n| (opcode::PAKE2, n));
                                        if r.is_err() {
                                            report_failure(&mut admission, &mut pase, &window);
                                        }
                                        r
                                    }
                                    None => continue,
                                }
                            }
                            opcode::PAKE3 => match pase.as_mut() {
                                Some(p) => match p.on_pake3(&body, &mut payload) {
                                    Ok((n, keys)) => {
                                        let keys_challenge = keys.attestation_challenge.clone();
                                        // The commissioner's session id came from
                                        // PBKDFParamRequest; PASE remembered it.
                                        let peer = p.peer_session_id();
                                        let session = SecureSession::new(
                                            pase_local,
                                            peer,
                                            SessionKind::Pase,
                                            Role::Responder,
                                            keys,
                                            rng.next_u32().expect("rng"),
                                            now,
                                        );
                                        attestation_challenge = Some(keys_challenge);
                                        if stack.sessions_mut().insert(session).is_err() {
                                            println!("  no room for another session");
                                            report_failure(&mut admission, &mut pase, &window);
                                        } else {
                                            println!("  PASE complete — session {pase_local:?}");
                                            // §5.5 rule 1 holds "or has successfully
                                            // established a session": the channel stays shut
                                            // until this session is closed.
                                            admission.established();
                                        }
                                        Ok((opcode::STATUS_REPORT, n))
                                    }
                                    Err(e) => {
                                        report_failure(&mut admission, &mut pase, &window);
                                        Err(e)
                                    }
                                },
                                None => continue,
                            },
                            // §4.14.2.3's Sigma1: find the fabric whose destination identifier
                            // the initiator computed, and answer with Sigma2. The scan is over
                            // the fabrics `AddNOC` created, so a device answers CASE only for
                            // an administrator it was actually commissioned by.
                            opcode::SIGMA1 => {
                                let mut random = [0u8; 32];
                                let mut ephemeral = [0u8; 32];
                                let mut resumption = [0u8; 16];
                                rng.fill(&mut random).expect("rng");
                                rng.fill(&mut ephemeral).expect("rng");
                                rng.fill(&mut resumption).expect("rng");
                                match serve_sigma1(
                                    &fabrics,
                                    &keys,
                                    &body,
                                    &random,
                                    &ephemeral,
                                    &resumption,
                                    SessionId(rng.next_u32().expect("rng") as u16 | 1),
                                    &mut payload,
                                ) {
                                    Ok((responder, local, fabric, n)) => {
                                        case_local = local;
                                        case_fabric = fabric;
                                        case = Some(responder);
                                        Ok((opcode::SIGMA2, n))
                                    }
                                    Err(e) => {
                                        println!("  sigma1 refused: {e}");
                                        case = None;
                                        StatusReport::secure_channel(
                                            SecureChannelCode::NoSharedTrustRoots,
                                        )
                                        .encode(&mut payload)
                                        .map(|n| (opcode::STATUS_REPORT, n))
                                    }
                                }
                            }
                            opcode::SIGMA3 => match case.as_mut() {
                                Some(responder) => {
                                    match serve_sigma3(
                                        responder,
                                        &fabrics,
                                        case_fabric,
                                        &body,
                                        &mut payload,
                                    ) {
                                        Ok((outcome, n)) => {
                                            // Every identity the session needs comes from the
                                            // outcome and the fabric, so it is built from both
                                            // rather than field by field. `local_node_id` is
                                            // the one that cannot be left out: §4.9.2's nonce
                                            // carries the sender's operational node id, which
                                            // is never in the header, so a session without it
                                            // encrypts everything unreadably and the peer
                                            // discards it without telling anyone.
                                            let Some(fabric) = fabrics
                                                .borrow()
                                                .iter()
                                                .find(|f| f.fabric_id == outcome.peer.fabric_id)
                                                .cloned()
                                            else {
                                                println!("  no fabric for the CASE peer");
                                                case = None;
                                                continue;
                                            };
                                            let session = outcome.into_session(
                                                case_local,
                                                &fabric,
                                                rng.next_u32().expect("rng"),
                                                now,
                                            );
                                            if stack.sessions_mut().insert(session).is_err() {
                                                println!("  no room for a CASE session");
                                            } else {
                                                println!(
                                                    "  CASE complete — session {case_local:?} \
                                                     for node {:?}",
                                                    outcome.peer.node_id
                                                );
                                            }
                                            case = None;
                                            Ok((opcode::STATUS_REPORT, n))
                                        }
                                        Err(e) => {
                                            println!("  sigma3 refused: {e}");
                                            case = None;
                                            Err(e)
                                        }
                                    }
                                }
                                None => continue,
                            },
                            other => {
                                println!("  unhandled secure channel opcode {other:#04x}");
                                continue;
                            }
                        }
                    } else if header.protocol == ProtocolId::INTERACTION_MODEL {
                        // A `StatusResponse` on a read that is not finished is the client
                        // asking for the next chunk (§10.2.3), and the next chunk is served
                        // from the request this node already has.
                        // Copied rather than borrowed: the same buffer is handed on mutably
                        // below, so that it can be cleared when the series ends. An example
                        // pays a kilobyte memcpy for the simpler lifetime; a device would keep
                        // the request in the exchange it belongs to.
                        let continuation = interactions.get(exchange, now).pending_read.clone();
                        let (opcode, body) = if header.opcode
                            == matter_kit::im::opcode::STATUS_RESPONSE
                            && !continuation.is_empty()
                        {
                            (matter_kit::im::opcode::READ_REQUEST, &continuation[..])
                        } else {
                            (header.opcode, &body[..])
                        };
                        let request = Request {
                            opcode,
                            payload: body,
                            session: Some(exchange.session),
                            exchange: exchange.id,
                            groupcast: false,
                        };
                        // §6.6.6.3 derives the subject from **session metadata**, never from
                        // the message: "the id in a message header is whatever the sender
                        // wrote, while the id in a session context is what CASE proved". So it
                        // is built per request from the session the request arrived on, and a
                        // node that fixes one subject at start-up is a node that answers every
                        // caller as whoever it first imagined. Over PASE that is the
                        // commissioner; over CASE it is the peer CASE authenticated, with its
                        // fabric and its CATs.
                        let accessing_fabric = stack
                            .sessions()
                            .find(exchange.session)
                            .map(|s| s.fabric_index)
                            .filter(|i| i.0 != 0);
                        let subject = match stack.sessions().find(exchange.session) {
                            Some(session) => SubjectDescriptor::from_session(
                                session,
                                // §6.6.6.3: a CASE session on the fabric `AddNOC` created
                                // but the fail-safe has not committed still counts as
                                // commissioning, which is how a commissioner that switched
                                // from PASE to CASE mid-flow keeps its standing.
                                fail_safe.borrow().armed(now).and_then(|a| a.fabric_index),
                            ),
                            None => SubjectDescriptor::unauthenticated(),
                        };
                        let access = AclAccess::new(&acl, node, &subject);
                        let server = Server::new(node, &access, &handler, 24)
                            .with_data_versions(&versions)
                            .with_events(&events);
                        let subscription_ctx = SubscriptionContext {
                            session: Some(exchange.session),
                            fabric_index: accessing_fabric,
                            peer_node_id: stack
                                .sessions()
                                .find(exchange.session)
                                .map(|s| s.peer_node_id),
                        };
                        match dispatch_one(
                            &mut dispatcher,
                            &server,
                            request,
                            now,
                            accessing_fabric,
                            attestation_challenge.as_ref(),
                            interactions.get(exchange, now),
                            &mut subscriptions,
                            &subscription_ctx,
                            &mut scratch,
                            &mut payload,
                        ) {
                            Ok(Some(reply)) => Ok(reply),
                            Ok(None) => {
                                // Nothing is owed on this exchange and nothing is part-way
                                // through it, so §4.10.5.3's "the application layer" has just
                                // decided the exchange is over — close it.
                                //
                                // The close cannot wait for `Received::Acknowledged`, which is
                                // what this used to rely on: that arrives only for a *bare*
                                // acknowledgement, and a peer is free to piggyback its
                                // acknowledgement on the next message instead. The CHIP SDK
                                // does exactly that — §10.7.3.2's `StatusResponse` to a
                                // `ReportData` carries the ack — so a read leaves an exchange
                                // open that nothing ever closes, and a node answering reads
                                // back to back fills its table in as many reads as it has
                                // slots. Measured: sixteen open, every one Interaction Model
                                // and Responder, then `no space` on the next datagram.
                                if interactions.idle(exchange) {
                                    interactions.forget(exchange);
                                    stack.close(exchange);
                                }
                                continue;
                            }
                            Err(e) => Err(e),
                        }
                    } else {
                        continue;
                    };

                    // Deferred to after the reply; see step 4 below.
                    let mut close_sessions_for: Option<matter_kit::msg::FabricIndex> = None;
                    // §11.10.7.2.2's eleven steps. The cluster computes them and hands them
                    // over — they reach the fabric table, the session table and the key store,
                    // none of which belong to a cluster (D31) — and the device applies them.
                    // Forgetting to, which is what this example did, means a disarmed fail-safe
                    // **leaves its fabric behind**: `ArmFailSafe(0)` answers SUCCESS, the
                    // commissioning it was protecting is supposedly undone, and the node keeps
                    // the fabric, its root and its administrator for ever.
                    //
                    // Applied before `take_change`, because removing the fabric produces a
                    // `FabricChange::Removed` that the block below still has to act on.
                    if let Some(aftermath) = general_commissioning.take_aftermath() {
                        match aftermath {
                            matter_kit::clusters::general_commissioning::Aftermath::Rollback(
                                cleanup,
                            ) => {
                                println!("  fail-safe rolled back: {cleanup:?}");
                                // Step 4: sessions for the fabric being reverted, but **after
                                // the reply goes out**. `ArmFailSafe(0)` is itself a command
                                // arriving on one of those sessions, and closing it first
                                // strands its own response — the commissioner then waits for an
                                // answer to a command the node has already carried out.
                                close_sessions_for = cleanup.close_case_sessions_for;
                                // Step 7: the fabric `AddNOC` added, as though by `RemoveFabric`
                                // — which is exactly the call, so the key is destroyed and the
                                // `FabricChange` below strips the access-control entries.
                                if let Some(index) = cleanup.remove_fabric {
                                    let ctx = InteractionContext::new().at(now);
                                    let _ = opcreds.remove_fabric(index, &ctx);
                                }
                                // Steps 8 and 9: the operational key a `CSRRequest` generated
                                // and nothing used, and trusted roots no fabric references.
                                if cleanup.discard_operational_key || cleanup.prune_trusted_roots {
                                    opcreds.discard_pending();
                                }
                            }
                            matter_kit::clusters::general_commissioning::Aftermath::Commissioned => {
                                println!("  commissioning complete");
                            }
                        }
                    }
                    if let Some(change) = opcreds.take_change() {
                        match change {
                            opcreds::FabricChange::Added {
                                index,
                                case_admin_subject,
                                bind_pase_session,
                            } => {
                                // Step 7. Without it, "there would be no way for the caller on
                                // its given Fabric to eventually add another Access Control
                                // Entry for CASE authentication mode" — the fabric is joined,
                                // the node advertises itself, and every operational
                                // interaction is answered `UNSUPPORTED_ACCESS`.
                                //
                                // Through the *cluster*, not straight into the list: §9.10.9.1
                                // wants an `AccessControlEntryChanged` for every change, and
                                // this is the entry every other one is granted by. The fabric
                                // is passed explicitly because step 10a binds it to the session
                                // only below this.
                                let admin_ctx = InteractionContext::new().at(now);
                                if let Err(e) = access_control_cluster.add_admin_for_fabric(
                                    index,
                                    NodeId(case_admin_subject),
                                    &admin_ctx,
                                ) {
                                    println!("  could not grant the administrator: {e}");
                                }
                                // Step 10a: "augment the currently executing PASE session with
                                // the FabricIndex generated above, such that subsequent
                                // interactions have the proper accessing fabric".
                                if bind_pase_session
                                    && let Some(session) =
                                        stack.sessions_mut().find_mut(exchange.session)
                                {
                                    session.fabric_index = index;
                                }
                                // §11.18.6.8: "This is needed to bootstrap a necessary
                                // configuration value for subsequent CASE to succeed", and
                                // "having provided it is equivalent to a KeySetWrite of group
                                // key set 0". *Equivalent to* — so the node must actually
                                // perform that write; `AddNOC` stores the IPK on the fabric and
                                // the group key store is the device's, not the cluster's (D31).
                                //
                                // Without it `KeySetRead(0)` answers `NotFound` on a node that
                                // has just been commissioned with an IPK it accepted.
                                if let Some(ipk) =
                                    fabrics.borrow().find(index).map(|f| f.ipk.clone())
                                {
                                    let set = matter_kit::group::GroupKeySet::single(
                                        index,
                                        matter_kit::group::IPK_KEY_SET,
                                        matter_kit::group::GroupKeySecurityPolicy::TrustFirst,
                                        ipk,
                                        0,
                                    );
                                    if let Err(e) = group_keys.borrow_mut().write_key_set(set) {
                                        println!("  could not install the IPK key set: {e:?}");
                                    }
                                }
                                println!("  fabric {index:?} joined — administrator granted");
                            }
                            opcreds::FabricChange::Updated { index } => {
                                println!("  fabric {index:?} rotated its identity");
                            }
                            opcreds::FabricChange::Removed { index, .. } => {
                                acl.borrow_mut().remove_fabric(index);
                                // §11.2.7.4: a fabric's group keys go with the fabric. Leaving
                                // them behind leaves key material for a fabric this node is no
                                // longer on.
                                group_keys.borrow_mut().remove_fabric(index);
                                println!("  fabric {index:?} removed");
                            }
                        }
                    }

                    // §9.10.9.1: "the cluster SHALL generate an AccessControlEntryChanged
                    // event" for every add, change or removal. The cluster records what
                    // happened and the device turns it into an event, because the event store
                    // belongs to the device (D31) — so a node that never drains this keeps no
                    // audit trail at all.
                    //
                    // After the fail-safe aftermath and the fabric change, before the reply
                    // goes out: both of those are themselves changes to the list — §11.18.6.8
                    // step 7 adds the administrator entry, a rollback strips a fabric's.
                    for change in access_control_cluster.take_changes() {
                        let mut payload = [0u8; 64];
                        let mut w = matter_kit::tlv::TlvWriter::new_in(
                            &mut payload,
                            matter_kit::tlv::ContainerKind::Structure,
                        );
                        if change
                            .encode(&mut w, matter_kit::tlv::Tag::Context(7))
                            .is_err()
                        {
                            println!("  could not encode an ACL change event");
                            continue;
                        }
                        let Ok(encoded) = w.finish() else {
                            continue;
                        };
                        let recorded =
                            events
                                .borrow_mut()
                                .record(&matter_kit::dm::events::NewEvent {
                                    endpoint: 0,
                                    cluster: access_control::ID,
                                    event: access_control::ACCESS_CONTROL_ENTRY_CHANGED,
                                    priority: matter_kit::dm::EventPriority::Info,
                                    timestamp: matter_kit::dm::events::Timestamp::System(
                                        now.as_millis(),
                                    ),
                                    // §7.14.4: the event belongs to the fabric whose list changed, so
                                    // one administrator cannot read another's audit trail.
                                    fabric_index: Some(change.fabric_index),
                                    data: encoded,
                                });
                        if let Err(e) = recorded {
                            println!("  could not record an ACL change event: {e:?}");
                            continue;
                        }
                        // Recording an event is half of reporting one: §8.5.3 has a path the
                        // subscriber marked *urgent* reported "as soon as possible" rather than
                        // at the next interval, and the subscription table cannot know an event
                        // happened unless the device says so. Without this every `ReadEvent`
                        // answers correctly and an urgent subscriber waits out its maximum
                        // interval, which looks exactly like nothing having happened.
                        subscriptions.note_event(
                            0,
                            access_control::ID,
                            access_control::ACCESS_CONTROL_ENTRY_CHANGED,
                        );
                    }

                    match reply {
                        Ok((opcode, len)) => {
                            let randomness = rng.next_u32().expect("rng");
                            match stack.send(
                                exchange,
                                opcode,
                                true,
                                &payload[..len],
                                now,
                                randomness,
                                &mut frame_buf,
                                &mut out,
                            ) {
                                Ok((sent, _)) => {
                                    let _ = matter_socket.send_to(&out[..sent], from).await;
                                }
                                Err(e) => println!("  could not send: {e}"),
                            }
                        }
                        Err(e) => println!("  refused: {e}"),
                    }
                    // Now the answer has gone, §11.10.7.2.2 step 4 may take the sessions with
                    // it. "Terminate any CASE session associated with the Fabric whose
                    // configuration is being reverted."
                    if let Some(index) = close_sessions_for {
                        let closed = stack.sessions_mut().remove_fabric(index);
                        subscriptions.remove_for_fabric(index);
                        println!("  rollback closed {closed} session(s) for {index:?}");
                    }
                }

                // --- An mDNS query ----------------------------------------------------------
                Event::Mdns(n) => {
                    // §4.3.1 versus §4.3.2: a node advertises `_matterc._udp` while it is
                    // commissionable and `_matter._tcp` once it is on a fabric, under an
                    // instance name derived from the compressed fabric id and its operational
                    // node id. A commissioner that has just sent `AddNOC` looks for the second
                    // one — so a device that keeps advertising the first is commissioned and
                    // then never found again.
                    //
                    // Rebuilt per query because the name does not exist until `AddNOC` created
                    // the fabric. A device would rebuild it once, when the fabric table changes.
                    // **Every** fabric, not the first. §4.3.2 gives each fabric its own
                    // `_matter._tcp` instance, named from that fabric's compressed id and the
                    // node id it issued — so a node on three fabrics publishes three records.
                    // Advertising only `iter().next()` leaves every fabric after the first
                    // unresolvable: `AddNOC` succeeds, the administrator gets its NOCResponse,
                    // and then operational discovery finds nothing and the commissioning times
                    // out with no error the node could report.
                    let operational: heapless::Vec<_, { DefaultConfig::FABRICS }> = fabrics
                        .borrow()
                        .iter()
                        .map(|f| (f.instance_name(), f.compressed.subtype()))
                        .collect();
                    let operational_txt = OperationalTxt::default()
                        .encode()
                        .expect("the advertisement fits");
                    let operational_txt = operational_txt.finish();
                    // Declared before the vector that borrows them, so they outlive it.
                    let (long, short, window_txt);
                    let mut advertisements: heapless::Vec<
                        Advertisement<'_>,
                        { DefaultConfig::FABRICS + 1 },
                    > = heapless::Vec::new();
                    for (instance, subtype) in &operational {
                        let mut a = Advertisement::new(
                            instance,
                            OPERATIONAL_SERVICE,
                            "0011223344556677",
                            matter_kit::PORT,
                            operational_txt,
                        )
                        .with_subtype(subtype)
                        .expect("subtype");
                        // §4.3.1.3's AAAA. An SRV names a host; without an address record for
                        // that host a resolver has a port and nowhere to send it, and the
                        // commissioner reports the device as simply not found.
                        if let Some(address) = advertise_addr {
                            a = a.with_address(address).expect("address");
                        }
                        let _ = advertisements.push(a);
                    }
                    if operational.is_empty() {
                        let _ = advertisements.push(commissionable.clone());
                    }
                    // §11.19.7: a *commissioned* node with an open window advertises **both**.
                    // The operational record is what its existing fabric resolves it by and
                    // must not disappear; the commissionable one is the only way a second
                    // administrator can find it at all. Replacing one with the other — which is
                    // what a single-advertisement node does — either hides the node from the
                    // fabric it is already on, or makes joining a second one impossible.
                    //
                    // Its discriminator is the window's, not the factory one (§11.19.8.1: "used
                    // by the Node as the long discriminator for DNS-SD advertisement"), and the
                    // subtypes are derived from it, so the whole record is rebuilt here rather
                    // than reusing `commissionable`.
                    let open = window.borrow().open(now).map(|w| {
                        (
                            w.discriminator,
                            match w.status {
                                WindowStatus::EnhancedOpen => CommissioningMode::Enhanced,
                                _ => CommissioningMode::Basic,
                            },
                        )
                    });
                    let reopened = open.filter(|_| !operational.is_empty());
                    if let Some((discriminator, mode)) = reopened {
                        let encoded = CommissionableTxt {
                            discriminator,
                            vendor_id: Some(VENDOR),
                            product_id: Some(PRODUCT_ID),
                            commissioning_mode: mode,
                            ..CommissionableTxt::default()
                        }
                        .encode()
                        .expect("the advertisement fits");
                        window_txt = encoded;
                        long = format!("_L{discriminator}");
                        short = format!("_S{}", discriminator >> 8);
                        let mut a = Advertisement::new(
                            "0011223344556677",
                            COMMISSIONABLE_SERVICE,
                            "0011223344556677",
                            matter_kit::PORT,
                            window_txt.finish(),
                        )
                        .with_subtype(&long)
                        .expect("subtype")
                        .with_subtype(&short)
                        .expect("subtype")
                        .with_subtype("_CM")
                        .expect("subtype");
                        if let Some(address) = advertise_addr {
                            a = a.with_address(address).expect("address");
                        }
                        let _ = advertisements.push(a);
                    }
                    let responder = Responder::new(&advertisements);
                    // Most traffic on 5353 is other people's; `respond` answers only what is
                    // actually asked of this node, and never answers a response (RFC 6762 §6).
                    match responder.respond(&mdns_buf[..n], &mut out) {
                        Ok((bytes, answered)) if !answered.is_empty() => {
                            let len = bytes.len();
                            match mdns_socket.send_to(bytes, mdns_group).await {
                                Ok(()) => println!("  discovered — answered {len} octets"),
                                Err(e) => println!("  mDNS send failed: {e}"),
                            }
                        }
                        Ok(_) | Err(_) => {}
                    }
                }

                // --- Timers -------------------------------------------------------------------
                Event::Deadline => {
                    // "If the PASE session is not established within the expected time window
                    // the Commissionee SHALL terminate the current session establishment using
                    // the INVALID_PARAMETER status code."
                    if let Some(failure) = admission.poll(now) {
                        println!("  PASE timed out after 60 s ({} failed)", failure.attempts);
                        pase = None;
                        if failure.exit_commissioning_mode {
                            println!("  20 failed attempts — leaving commissioning mode");
                            window.borrow_mut().close();
                        }
                    }
                }
            }
        }
    });
}

/// Records a failed PASE attempt, and leaves commissioning mode on the twentieth.
///
/// §5.5: "the Commissionee SHALL exit Commissioning Mode after 20 failed attempts." The
/// responder is dropped either way — a half-finished handshake is not one a later message may
/// resume, and keeping it would hold the channel against the next commissioner.
fn report_failure(
    admission: &mut PaseAdmission,
    pase: &mut Option<PaseResponder>,
    window: &RefCell<CommissioningWindow>,
) {
    *pase = None;
    let failure = admission.failed();
    println!("  PASE attempt {} failed", failure.attempts);
    if failure.exit_commissioning_mode {
        println!("  20 failed attempts — leaving commissioning mode");
        window.borrow_mut().close();
    }
}

/// Serves one interaction model message, returning the opcode and length of the answer.
/// Answers a Sigma1 with a Sigma2 (§4.14.2.3).
///
/// The fabric is found by *destination identifier*: §4.14.2.4.1 makes it an HMAC an initiator can
/// only compute if it already holds the fabric's IPK and one of this node's identities, which is
/// what lets a device decide whether to spend an ECDH and a signature on a stranger. The scan is
/// constant-time in `FabricTable`, so a near miss and a wild miss cost the same.
#[allow(clippy::too_many_arguments)]
fn serve_sigma1(
    fabrics: &RefCell<FabricTable<DefaultConfig, { DefaultConfig::FABRICS }>>,
    keys: &RefCell<SoftKeyStore<8>>,
    body: &[u8],
    responder_random: &[u8; 32],
    ephemeral_random: &[u8; 32],
    resumption_random: &[u8; 16],
    local: SessionId,
    out: &mut [u8],
) -> matter_kit::Result<(
    CaseResponder,
    SessionId,
    matter_kit::msg::FabricIndex,
    usize,
)> {
    let sigma1 = Sigma1::decode(body)?;
    let table = fabrics.borrow();
    let fabric = table
        .find_by_destination_identifier(&sigma1.initiator_random, &sigma1.destination_id)?
        .ok_or_else(|| matter_kit::Error::new(matter_kit::ErrorCode::NoSession))?;
    // The NOC and ICAC this node presents are the ones `AddNOC` stored for that fabric.
    let noc = fabric.credentials.noc.clone();
    let icac = fabric.credentials.icac.clone();
    let fabric = fabric.clone();
    drop(table);

    let mut responder = CaseResponder::new(local, Some(SessionParams::default()));
    let n = responder.handle_sigma1(
        &sigma1,
        &fabric,
        &noc,
        icac.as_deref(),
        &mut *keys.borrow_mut(),
        ephemeral_random,
        responder_random,
        resumption_random,
        out,
    )?;
    Ok((responder, local, fabric.index, n))
}

/// Accepts a Sigma3 and writes the `SigmaFinished` status report (§4.14.2.3).
fn serve_sigma3(
    responder: &mut CaseResponder,
    fabrics: &RefCell<FabricTable<DefaultConfig, { DefaultConfig::FABRICS }>>,
    fabric: matter_kit::msg::FabricIndex,
    body: &[u8],
    out: &mut [u8],
) -> matter_kit::Result<(matter_kit::sc::CaseOutcome, usize)> {
    let sigma3 = Sigma3::decode(body)?;
    // The initiator's NOC is checked against *this fabric's* trusted root, which is the whole
    // point of §4.14.2.3's Validate Sigma3: a chain that verifies against some other root is a
    // chain from some other fabric's administrator.
    //
    // `fabric` is the one Sigma1 resolved from the destination identifier, not whichever the
    // table happens to list first. Taking the first works perfectly on a node with one fabric
    // and refuses *every* peer on the second — `cert: chain does not validate`, which reads
    // like a bad certificate and is a chain checked against a stranger's root.
    let table = fabrics.borrow();
    let rcac = table
        .find(fabric)
        .map(|f| f.credentials.rcac.clone())
        .ok_or_else(|| matter_kit::Error::new(matter_kit::ErrorCode::NoSession))?;
    drop(table);
    let root = MatterCertificate::decode(&rcac)?;
    let outcome = responder.handle_sigma3(&sigma3, &root, None)?;
    let n = responder.finished(out)?;
    Ok((outcome, n))
}

/// Serves one interaction-model message, driving §10.2.3's chunk series.
///
/// [`Dispatcher`] owns the rules of §8.7.2.3 and §8.8.2.3 — the Timed window, the
/// `MaxPathsPerInvoke` bound — and chooses the response opcode. What it cannot own is the
/// *series*: a report too large for one datagram is several messages, each waiting for the
/// client's `StatusResponse` before the next goes out, and the request has to survive between
/// them. `pending_read` is that memory, and `cursor` is the position in it.
///
/// `None` means send nothing, which is a real outcome rather than an error: a suppressed write,
/// a groupcast, or a `StatusResponse` acknowledging the last chunk of a finished read.
#[allow(clippy::too_many_arguments)]
fn dispatch_one<A: matter_kit::im::AccessControl, H: matter_kit::im::ClusterHandler>(
    dispatcher: &mut Dispatcher<4>,
    server: &Server<'_, A, H>,
    request: Request<'_>,
    now: Instant,
    fabric_index: Option<matter_kit::msg::FabricIndex>,
    challenge: Option<&matter_kit::crypto::SymmetricKey>,
    interaction: &mut Interaction,
    subscriptions: &mut Subscriptions,
    subscription_ctx: &SubscriptionContext,
    scratch: &mut [u8],
    out: &mut [u8],
) -> matter_kit::Result<Option<(u8, usize)>> {
    let mut ctx = InteractionContext::new().at(now);
    // The accessing fabric, from the session rather than from the message. Leaving it `None`
    // is not a neutral default: §8.8.2.3 step b.v makes every fabric-scoped command
    // `UNSUPPORTED_ACCESS` when there is no accessing fabric, so a node that never sets it
    // commissions cleanly and then refuses `CommissioningComplete` — and every other
    // fabric-scoped command after it — with no indication of why.
    if let Some(index) = fabric_index {
        ctx = ctx.with_fabric(index);
    }
    if let Some(challenge) = challenge {
        ctx = ctx.with_attestation_challenge(challenge);
    }
    // Who is asking, from the *session* — §6.6.6.3 derives an administrator's identity there
    // and never from anything the message claimed. A PASE session has no operational node id,
    // and `SecureSession` carries `NodeId::UNSPECIFIED` for it, so only a real one is set.
    //
    // §9.10.9.1 needs it: "Exactly one of AdminNodeID and AdminPasscodeID SHALL be set,
    // depending on whether the change occurred via a CASE or PASE session". Left unset, every
    // access-control change names a passcode and the audit trail names nobody — and
    // §11.30.7.1's `RequestCommissioningApproval` refuses outright.
    if let Some(peer) = subscription_ctx
        .peer_node_id
        .filter(|id| id.kind() == matter_kit::msg::NodeIdKind::Operational)
    {
        ctx = ctx.from_peer(peer);
    }
    let is_read = request.opcode == matter_kit::im::opcode::READ_REQUEST;
    // A *new* read starts a new series; a continuation keeps the cursor where it was.
    if is_read && interaction.pending_read.is_empty() {
        interaction.read_cursor = ReadCursor::START;
    }
    let payload = request.payload;

    match dispatcher.dispatch(
        server,
        request,
        &ctx,
        &mut interaction.read_cursor,
        scratch,
        out,
    )? {
        Served::Reply {
            opcode,
            len,
            more_chunks,
        } => {
            if is_read {
                if more_chunks {
                    // Keep the request: the client's acknowledgement is the cue for the rest.
                    interaction.pending_read.clear();
                    if interaction.pending_read.extend_from_slice(payload).is_err() {
                        println!("  a read too large to continue was truncated");
                        interaction.pending_read.clear();
                    }
                } else {
                    interaction.pending_read.clear();
                }
            }
            Ok(Some((opcode, len)))
        }
        Served::Silent => Ok(None),
        Served::Subscribe(request) => {
            // §8.5.2's flow is four messages, not two: SubscribeRequest, a priming ReportData,
            // the subscriber's StatusResponse, and only then the SubscribeResponse that names
            // the id and the interval actually granted. This returns the *priming report*, and
            // `interaction.pending_subscribe` remembers what to answer the StatusResponse with.
            //
            // A wildcard subscription is the normal case — every certification test in the CHIP
            // SDK's Python suite starts one over the whole node — and it is as large as the
            // read that primes it, so it chunks exactly like one (§10.2.3).
            let mut paths: heapless::Vec<matter_kit::im::AttributePath, SUB_PATHS> =
                heapless::Vec::new();
            if let Some(iter) = request.attribute_paths()? {
                for path in iter {
                    let _ = paths.push(path?);
                }
            }
            let mut event_paths: heapless::Vec<matter_kit::im::EventPath, SUB_PATHS> =
                heapless::Vec::new();
            if let Some(iter) = request.event_paths()? {
                for path in iter {
                    let _ = event_paths.push(path?);
                }
            }

            let policy = SubscriptionPolicy::default();
            let new = NewSubscription {
                session: subscription_ctx.session,
                fabric_index: subscription_ctx.fabric_index,
                peer_node_id: subscription_ctx.peer_node_id,
                fabric_filtered: request.fabric_filtered,
                keep_subscriptions: request.keep_subscriptions,
                min_interval_s: request.min_interval_floor_s,
                max_interval_s: policy
                    .max_interval(request.min_interval_floor_s, request.max_interval_ceiling_s),
                paths: &paths,
                event_paths: &event_paths,
                min_event_number: 0,
            };
            let id = match subscriptions.subscribe(&new, now) {
                Ok(id) => id,
                Err(e) => {
                    println!("  subscription refused: {e:?}");
                    return Err(matter_kit::Error::from(e));
                }
            };
            // §8.5.3.4: the priming report carries "all the attribute and event data that
            // the subscription requested", not a delta — there is nothing yet to be a delta
            // from. A newly created subscription's dirty set is empty, and an empty dirty set
            // reports *nothing*, so the subscriber would cache nothing and every later read
            // against its cache would come back absent. Re-priming is what says "you do not
            // know what I have", which is exactly true of a subscriber that has just arrived.
            let Some(subscription) = subscriptions.find_mut(id) else {
                return Ok(None);
            };
            subscription.reprime();
            // §8.5.2: "The EventFilters and DataVersionFilters fields in the Subscribe Request
            // are one time parameters for the priming of the subscription." One time — so they
            // go into the context this report is built with and are *not* stored on the
            // subscription. A later report that still honoured them would suppress exactly the
            // change it exists to announce.
            let priming = match request.data_version_filters_raw() {
                Some(filters) => ctx.with_data_version_filters(filters),
                None => ctx,
            };
            let (bytes, outcome) =
                server.report_chunk(subscription, ReportReason::Data, &priming, scratch, out)?;
            let len = bytes.len();
            let granted = new.max_interval_s;
            interaction.pending_subscribe = Some(PendingSubscribe {
                id,
                max_interval_s: granted,
                more_chunks: outcome.truncated,
            });
            println!(
                "  subscription {id}: {} path(s), priming report {} attributes in {len} octets{}, \
                 max interval {granted}s",
                paths.len(),
                outcome.reports,
                if outcome.truncated { ", chunked" } else { "" }
            );
            Ok(Some((matter_kit::im::opcode::REPORT_DATA, len)))
        }
        Served::Unhandled { opcode } => {
            // A `StatusResponse` means one of three things, and the state decides which.
            if opcode == matter_kit::im::opcode::STATUS_RESPONSE {
                if let Some(pending) = interaction.pending_subscribe.take() {
                    // §8.5.2: the subscriber has acknowledged the priming report. If the report
                    // chunked, the acknowledgement asks for the next chunk and the response is
                    // still owed; otherwise this is where the subscription becomes real and the
                    // id and interval are finally named.
                    if pending.more_chunks {
                        let Some(subscription) = subscriptions.find_mut(pending.id) else {
                            return Ok(None);
                        };
                        let (bytes, outcome) = server.report_chunk(
                            subscription,
                            ReportReason::Data,
                            &ctx,
                            scratch,
                            out,
                        )?;
                        let len = bytes.len();
                        println!(
                            "  subscription {} chunk: {} attributes in {len} octets{}",
                            pending.id,
                            outcome.reports,
                            if outcome.truncated {
                                ", more"
                            } else {
                                ", last"
                            }
                        );
                        interaction.pending_subscribe = Some(PendingSubscribe {
                            more_chunks: outcome.truncated,
                            ..pending
                        });
                        return Ok(Some((matter_kit::im::opcode::REPORT_DATA, len)));
                    }
                    if let Some(subscription) = subscriptions.find_mut(pending.id) {
                        subscription.reported(now);
                    }
                    let len = SubscribeResponse::new(pending.id, pending.max_interval_s)
                        .encode(out)?
                        .len();
                    println!("  subscription {} granted", pending.id);
                    return Ok(Some((matter_kit::im::opcode::SUBSCRIBE_RESPONSE, len)));
                }
                // Otherwise it acknowledges a read chunk or a report, and nothing is owed.
                return Ok(None);
            }
            println!("  unhandled interaction model opcode {opcode:#04x}");
            Ok(None)
        }
    }
}

/// The General Diagnostics a host process can honestly answer (§11.12).
///
/// Almost nothing, which is the point of the trait's defaults. A process on a laptop has no
/// reboot count, no boot reason it can distinguish from any other, and no hardware faults to
/// report — and saying so is a conformant cluster, where inventing values would not be.
///
/// `UpTime` it *can* answer, because §11.12.6.3 asks for time "since the Node's last reboot"
/// measured on "the same System Time source as those used to fulfill any usage of the
/// systime-us and systime-ms data types" — which is the same `Timer` everything else here
/// reads, so the number agrees with the timestamps on this node's events.
struct Uptime<'a> {
    timer: &'a StdTimer,
    started: Instant,
}

impl<'a> Uptime<'a> {
    fn new(timer: &'a StdTimer) -> Self {
        let started = timer.now();
        Self { timer, started }
    }
}

impl Diagnostics for Uptime<'_> {
    fn up_time(&self) -> u64 {
        self.timer
            .now()
            .saturating_duration_since(self.started)
            .as_secs()
    }

    fn boot_reason(&self) -> BootReason {
        // §11.12.5.5's `Unspecified`: "The Node is unable to identify the Power-On reason as
        // one of the other provided enumeration values." A process that was started by a shell
        // genuinely cannot.
        BootReason::Unspecified
    }

    // No `enable_key`, so `TestEventTrigger` answers `CONSTRAINT_ERROR` and this binary cannot
    // be made to do anything the specification does not define (§11.12.7.1).
}

/// The light this binary controls, which is a line on standard output.
///
/// A real product drives a pin here, or a PWM channel, or a DALI bus. What matters is that it
/// is *all* it does: §1.5.7's state machine — the timed-off guard, the global scene, the
/// startup behaviour — belongs to the cluster, and a device that reimplemented any of it would
/// be reimplementing the part certification tests.
#[derive(Debug, Default)]
struct Lamp {
    on: RefCell<bool>,
}

impl OnOffHooks for Lamp {
    fn set(&self, on: bool) {
        *self.on.borrow_mut() = on;
        println!("  light: {}", if on { "on" } else { "off" });
    }
}

impl IdentifyHooks for Lamp {
    fn identifying(&self, on: bool) {
        // §1.2.5.1 recommends "flashing a light with a period of 0.5 seconds"; a terminal
        // gets one line, because the point is that the *transition* is what the hook reports.
        println!("  identify: {}", if on { "started" } else { "stopped" });
    }

    fn trigger_effect(&self, effect: EffectIdentifierEnum, variant: EffectVariantEnum) {
        println!("  effect: {effect:?} / {variant:?}");
    }
}

impl SceneHooks for Lamp {
    fn capture(&self, w: &mut matter_kit::tlv::TlvWriter<'_>) -> matter_kit::error::Result<()> {
        // One extension field set: On/Off's `OnOff`, the only attribute on this endpoint with
        // §7.13's Scenes quality. §1.4.7.3.2: "Data types bool, map8, and uint8 SHALL map to
        // ValueUnsigned8."
        w.start_structure(matter_kit::tlv::Tag::Anonymous)?;
        w.unsigned(matter_kit::tlv::Tag::Context(0), u64::from(on_off::ID))?;
        w.start_array(matter_kit::tlv::Tag::Context(1))?;
        w.start_structure(matter_kit::tlv::Tag::Anonymous)?;
        w.unsigned(matter_kit::tlv::Tag::Context(0), u64::from(on_off::ON_OFF))?;
        w.unsigned(
            matter_kit::tlv::Tag::Context(1),
            u64::from(*self.on.borrow()),
        )?;
        w.end_container()?;
        w.end_container()?;
        w.end_container()
    }

    fn apply<'a>(
        &self,
        sets: matter_kit::tlv::TlvList<'a, ExtensionFieldSetStruct<'a>>,
        transition: u32,
    ) {
        for set in sets.iter() {
            let Ok(set) = set else { continue };
            if set.cluster_id != on_off::ID {
                continue;
            }
            for pair in set.attribute_value_list.iter() {
                // §1.4.9.12.4: "If an extension field set would cause an unknown or missing
                // attribute to be set for any reason, that attribute SHALL be skipped."
                let Ok(pair) = pair else { continue };
                if pair.attribute_id == on_off::ON_OFF {
                    println!("  scene: over {transition} ms");
                    self.set(pair.value_unsigned8.unwrap_or(0) != 0);
                }
            }
        }
    }
}
