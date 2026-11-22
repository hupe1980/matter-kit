//! A commissionable Matter light on real sockets.
//!
//! ```text
//! cargo run --example light --features std
//! chip-tool pairing onnetwork 1 20202021
//! ```
//!
//! Everything here is the *application's*: the product's identity, its attestation material,
//! its clusters and what the lamp does. The sequence every Matter device must keep — sessions,
//! chunked reads, subscriptions and reports, retransmission, the commissioning follow-ups —
//! belongs to [`node::Runtime`], and [`Runtime::run`](node::Runtime::run) is the whole loop.
//!
//! What it is not: a product. It persists nothing across a restart, and its attestation chain is
//! generated at start-up, so a commissioner must be pointed at the root it writes out
//! (`MATTER_PAA_OUT`) or told to skip attestation.
//!
//! `MATTER_IFINDEX` picks the interface to advertise on (default 1, the loopback on most
//! systems); `MATTER_ADVERTISE_ADDR` is the IPv6 address to put in AAAA records.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

use core::cell::RefCell;

use matter_kit::acl::Acl;
use matter_kit::attestation::factory::DevelopmentChain;
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
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::config::{Config, DefaultConfig};
use matter_kit::crypto::{KeyPurpose, KeyStore, SoftKeyStore, Spake2pVerifierData};
use matter_kit::discovery::advertiser::{Advertiser, Identity};
use matter_kit::dm::events::{EventNumbers, EventStore};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{DataVersions, DeviceType, Endpoint, Node};
use matter_kit::fabric::FabricTable;
use matter_kit::msg::{FabricIndex, GroupId, VendorId};
use matter_kit::node::{self, Device, Mdns, Runtime};
use matter_kit::platform::os::{StdRng, StdTimer, StdUdp, block_on};
use matter_kit::platform::{Instant, Rng, Timer};
use matter_kit::sc::PbkdfParameters;

/// The passcode on the device's label.
const PASSCODE: u32 = 20_202_021;
/// §3.9 allows 1 000 to 100 000 PBKDF iterations. The floor is what an offline attack on leaked
/// verifier material is priced at, and the passcode holds about 27 bits; ten times the floor
/// costs a commissioner one derivation per pairing.
const ITERATIONS: u32 = 10_000;
/// §5.1.1.3's 12-bit discriminator.
const DISCRIMINATOR: u16 = 3840;
const VENDOR: VendorId = VendorId(0xFFF1);
const PRODUCT_ID: u16 = 0x8000;

/// The session table the runtime keeps by default, named so `CapabilityMinima` is derived from
/// the tables that have to honour it rather than typed beside them.
type Sessions = matter_kit::session::SessionTable<DefaultConfig, 16>;

const PRODUCT: Product<'static> = Product::new(
    "Example Vendor",
    VENDOR,
    "matter-kit light",
    PRODUCT_ID,
    "matter-kit-light-0001",
)
.with_capability_minima(CapabilityMinima::from_tables::<
    DefaultConfig,
    Sessions,
    node::Subscriptions<DefaultConfig>,
>());

/// What the factory burned in (§9.8).
const FIXED_LABELS: &[Label<'static>] = &[match Label::new("model", "matter-kit") {
    Some(l) => l,
    None => panic!("within §9.7.4.1's 16 characters"),
}];

/// Appendix F.1's first Certification Declaration. A real CD is signed by the CSA; a development
/// device carries the specification's own example, which parses and attests to nothing.
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

/// Endpoint 0 is the Root Node; endpoint 1 an On/Off Light (Device Library §4.1), a promise
/// `tests/device_types.rs` checks this cluster list against.
const ROOT_NODE: &[DeviceType] = &[DeviceType::new(0x0016, 3)];
const ON_OFF_LIGHT_TYPE: &[DeviceType] = &[DeviceType::new(ON_OFF_LIGHT.id, ON_OFF_LIGHT.revision)];

const GROUPS_PER_FABRIC: usize = 4;
const GROUP_SLOTS: usize = 16;
/// §1.4.8.1: "The minimum size of this table ... SHALL be 16".
const SCENE_SLOTS: usize = 16;
const SCENE_BYTES: usize = 128;
const FABRICS: usize = DefaultConfig::FABRICS;

type GroupTable<'a> =
    Groups<'a, GROUP_SLOTS, Identify<'a, Lamp>, SceneTable<SCENE_SLOTS, SCENE_BYTES, FABRICS>>;

fn main() {
    let timer = StdTimer::new();
    let rng = StdRng;

    let Ok(matter_socket) = StdUdp::bind(matter_kit::PORT) else {
        println!(
            "could not bind UDP {}; is another Matter node running?",
            matter_kit::PORT
        );
        return;
    };
    let interface: u32 = env("MATTER_IFINDEX").unwrap_or(1);
    let Ok(mdns_socket) = StdUdp::bind_mdns(interface) else {
        println!("could not bind mDNS on interface {interface}");
        return;
    };
    let Some(mdns_group) = mdns_socket.mdns_group() else {
        println!("the mDNS socket has no group to answer on");
        return;
    };

    // --- What the node is --------------------------------------------------------------------
    // Descriptors are derived from the specification's own tables: the element set follows the
    // features claimed, so `AttributeList` and what the cluster answers cannot drift apart.
    let location = Location::region_agnostic();
    let attributes = Attributes::new(&PRODUCT, false, false);
    let diagnostics_descriptor =
        general_diagnostics::conforming(0, &Optional::NONE).expect("mandatory set");
    let lamp_descriptor = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE)
        .expect("Lighting set");
    let identify_descriptor =
        Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT).expect("Identify set");
    let groups_descriptor =
        Groups::<GROUP_SLOTS>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE)
            .expect("Groups set");
    let group_key_descriptor =
        GroupKeyManagement::<DefaultConfig, Memberships<'_>>::conforming(0, &Optional::NONE)
            .expect("Group Key Management set");
    let scenes_descriptor =
        Scenes::<Lamp, GroupTable, SCENE_SLOTS, SCENE_BYTES, FABRICS>::conforming(
            scenes::feature::SCENE_NAMES,
            &Scenes::<Lamp, GroupTable, SCENE_SLOTS, SCENE_BYTES, FABRICS>::WITH_COPY_SCENE,
        )
        .expect("Scenes set");
    // Sorted by cluster id: every lookup binary-searches, and `Node::validate` says so.
    let root_clusters = [
        descriptor::cluster(),
        binding::cluster(),
        access_control::cluster(),
        attributes.cluster(),
        general_commissioning::cluster(),
        diagnostics_descriptor.descriptor(),
        administrator_commissioning::cluster(),
        opcreds::cluster(),
        group_key_descriptor.descriptor(),
        label::fixed_cluster(),
        label::user_cluster(),
    ];
    let lamp_clusters = [
        identify_descriptor.descriptor(),
        groups_descriptor.descriptor(),
        lamp_descriptor.descriptor(),
        descriptor::cluster(),
        scenes_descriptor.descriptor(),
    ];
    let endpoints = [
        Endpoint::new(0, &root_clusters).with_device_types(ROOT_NODE),
        Endpoint::new(1, &lamp_clusters).with_device_types(ON_OFF_LIGHT_TYPE),
    ];
    let node = Node::new(&endpoints);
    node.validate().expect("the clusters are sorted by id");

    // --- Attestation (§6.2.2) ----------------------------------------------------------------
    // Generated at start-up so the example needs nothing vendored. A product's DAC is written
    // at manufacture and its key lives in a secure element.
    let keys = RefCell::new(SoftKeyStore::<8>::new());
    let chain = attestation_chain(&keys, &rng);

    // --- The node's tables and system clusters -------------------------------------------------
    let fabrics = RefCell::new(FabricTable::<DefaultConfig, FABRICS>::new());
    let rng_cell = RefCell::new(StdRng);
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let window = RefCell::new(CommissioningWindow::new());
    let vendor_of_fabric =
        |index: FabricIndex| fabrics.borrow().find(index).map(|f| f.admin_vendor_id);
    let general_commissioning = GeneralCommissioning::new(
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );
    let admin_commissioning =
        AdministratorCommissioning::new(&window, &fail_safe, &vendor_of_fabric);
    let acl = RefCell::new(Acl::<DefaultConfig, 20, 4, 3>::new());
    let access_control_cluster = AccessControl::new(&acl);
    let bindings = Binding::<DefaultConfig, 8>::new(4);
    let user_labels = UserLabel::<4>::new();
    let diagnostics = Uptime::new(&timer);
    let credentials = OperationalCredentials::new(
        &fabrics,
        &keys,
        &rng_cell,
        &fail_safe,
        DeviceAttestation {
            dac: &chain.dac,
            pai: &chain.pai,
            certification_declaration: CERTIFICATION_DECLARATION,
            dac_key: chain.dac_key,
            firmware_information: None,
        },
    );

    // --- The light ------------------------------------------------------------------------------
    let lamp = Lamp::default();
    // `StartUpOnOff` is null — "the previous value" — and this process persists nothing.
    let lamp_cluster = OnOff::new(&lamp, on_off::feature::LIGHTING, None);
    lamp_cluster.start(false);
    // One Scene Table, two clusters: §1.3.7.4 has `RemoveGroup` remove that group's scenes.
    let scene_table = SceneTable::<SCENE_SLOTS, SCENE_BYTES, FABRICS>::new(true);
    let identify_cluster = Identify::new(&lamp, IdentifyTypeEnum::LightOutput);
    let groups_cluster: GroupTable<'_> =
        Groups::with(GROUPS_PER_FABRIC, true, &identify_cluster, &scene_table);
    let scenes_cluster = Scenes::new(&scene_table, &groups_cluster, &lamp, true);
    let memberships = Memberships(&groups_cluster);
    let group_keys = RefCell::new(matter_kit::group::GroupKeys::<DefaultConfig>::new());
    let group_keys_cluster = GroupKeyManagement::new(&group_keys, &memberships);

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
                &credentials,
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

    // §7.10.3's data versions and §7.14's event log. Event numbers survive a reboot by reserved
    // blocks; a device restores the mark from storage, this one acknowledges its own.
    let versions = DataVersions::<16>::new(rng.next_u32().expect("rng"));
    let events = RefCell::new(EventStore::<4, 4, 4>::new({
        let mut numbers = EventNumbers::restore(0);
        if let Some(owed) = numbers.reservation() {
            numbers.reserved(owed);
        }
        numbers
    }));

    // --- PASE ----------------------------------------------------------------------------------
    // A per-device salt, drawn once at manufacture beside the verifier; the passcode itself is
    // not stored. This example knows its passcode, so it does at boot what a factory does once.
    let mut salt = [0u8; matter_kit::crypto::PBKDF_SALT_MIN_BYTES];
    rng.fill(&mut salt).expect("rng");
    let parameters = PbkdfParameters::new(ITERATIONS, &salt).expect("parameters");
    let verifier =
        Spake2pVerifierData::from_passcode(PASSCODE, &salt, ITERATIONS).expect("verifier");

    let device = Device {
        node,
        handler: &handler,
        credentials: &credentials,
        commissioning: &general_commissioning,
        access_control: &access_control_cluster,
        group_keys: &group_keys,
        events: &events,
        versions: &versions,
        verifier: &verifier,
        parameters: &parameters,
        memberships: Some(&memberships),
    };
    let mut runtime = Box::new(
        Runtime::<DefaultConfig>::new(&rng)
            .expect("rng")
            .with_max_paths_per_invoke(PRODUCT.max_paths_per_invoke),
    );
    let identity = Identity {
        discriminator: DISCRIMINATOR,
        vendor_id: VENDOR,
        product_id: PRODUCT_ID,
        port: matter_kit::PORT,
    };
    let mut advertiser = Advertiser::<FABRICS, { FABRICS + 1 }>::new(identity, &rng).expect("rng");
    if let Some(address) = env::<std::net::Ipv6Addr>("MATTER_ADVERTISE_ADDR") {
        advertiser = advertiser.with_address(address.octets());
    }

    println!(
        "matter-kit light — UDP {}, mDNS on interface {interface}",
        matter_kit::PORT
    );
    println!("  chip-tool pairing onnetwork 1 {PASSCODE}");

    block_on(runtime.run(
        &device,
        &matter_socket,
        Mdns {
            socket: &mdns_socket,
            group: mdns_group,
            interface,
        },
        &mut advertiser,
        &timer,
        |notice| println!("  {notice:?}"),
    ));
}

fn env<T: core::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// The attestation chain a development device makes for itself.
struct Chain {
    pai: Vec<u8>,
    dac: Vec<u8>,
    dac_key: matter_kit::crypto::KeyHandle,
}

fn attestation_chain(keys: &RefCell<SoftKeyStore<8>>, rng: &impl Rng) -> Chain {
    let mut store = keys.borrow_mut();
    let fresh = |store: &mut SoftKeyStore<8>| {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed).expect("rng");
        store
            .generate(KeyPurpose::DeviceAttestation, &seed)
            .expect("generate an attestation key")
    };
    let (paa_key, _) = fresh(&mut store);
    let (pai_key, pai_public) = fresh(&mut store);
    let (dac_key, dac_public) = fresh(&mut store);
    // §6.2.2.4's validity is in *Matter* epoch seconds (2000-01-01); anchoring at zero makes a
    // chain that expired in 2010.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let not_before = u32::try_from(
        now_unix.saturating_sub(u64::try_from(matter_kit::der::MATTER_EPOCH_UNIX).unwrap_or(0)),
    )
    .unwrap_or(0);
    let chain = DevelopmentChain::new(not_before, 10);
    // `DerWriter` fills from the end, so each certificate is the returned slice, never a prefix.
    let mut scratch = [0u8; 1024];
    let paa = chain
        .paa(&*store, &mut scratch, paa_key)
        .expect("PAA")
        .to_vec();
    let pai = chain
        .pai(&*store, &mut scratch, paa_key, &pai_public)
        .expect("PAI")
        .to_vec();
    let dac = chain
        .dac(&*store, &mut scratch, pai_key, &dac_public, PRODUCT_ID)
        .expect("DAC")
        .to_vec();
    // A commissioner verifies against a PAA it already trusts (§6.2.2.3); writing the root out
    // lets one be pointed at it — `chip-tool --paa-trust-store-path` takes a directory of DER.
    if let Ok(dir) = std::env::var("MATTER_PAA_OUT") {
        let path = std::path::Path::new(&dir).join("matter-kit-dev-paa.der");
        match std::fs::write(&path, &paa) {
            Ok(()) => println!("  PAA written to {}", path.display()),
            Err(e) => println!("  could not write the PAA to {} ({e})", path.display()),
        }
    }
    Chain { pai, dac, dac_key }
}

/// The Groups cluster as the membership table Group Key Management reports (§11.2.7.4): two
/// clusters, one fact, joined by the device because a cluster does not reach into another.
struct Memberships<'a>(&'a GroupTable<'a>);

impl group_key_management::GroupTable for Memberships<'_> {
    fn memberships(&self, each: &mut dyn FnMut(FabricIndex, GroupId, matter_kit::im::EndpointId)) {
        // Endpoint 1 is the only one this node puts in groups.
        for membership in self.0.memberships().iter() {
            each(membership.fabric, membership.group, 1);
        }
    }

    fn name(&self, _fabric: FabricIndex, _group: GroupId) -> Option<&str> {
        None
    }
}

/// General Diagnostics a host process can honestly answer (§11.12): `UpTime`, from the same
/// clock as every timestamp on this node, and nothing it would have to invent.
struct Uptime<'a> {
    timer: &'a StdTimer,
    started: Instant,
}

impl<'a> Uptime<'a> {
    fn new(timer: &'a StdTimer) -> Self {
        Self {
            timer,
            started: timer.now(),
        }
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
        // A process started by a shell cannot tell one power-on reason from another.
        BootReason::Unspecified
    }
}

/// The lamp: a line on standard output. §1.5.7's state machine belongs to the cluster; this is
/// only what a pin, a PWM channel or a DALI bus would be.
#[derive(Debug, Default)]
struct Lamp {
    on: core::cell::Cell<bool>,
}

impl OnOffHooks for Lamp {
    fn set(&self, on: bool) {
        self.on.set(on);
        println!("  light: {}", if on { "on" } else { "off" });
    }
}

impl IdentifyHooks for Lamp {
    fn identifying(&self, on: bool) {
        println!("  identify: {}", if on { "started" } else { "stopped" });
    }

    fn trigger_effect(&self, effect: EffectIdentifierEnum, variant: EffectVariantEnum) {
        println!("  effect: {effect:?} / {variant:?}");
    }
}

impl SceneHooks for Lamp {
    fn capture(&self, w: &mut matter_kit::tlv::TlvWriter<'_>) -> matter_kit::error::Result<()> {
        // On/Off's `OnOff`, the only attribute here with §7.13's Scenes quality, as
        // §1.4.7.3.2's ValueUnsigned8.
        use matter_kit::tlv::Tag;
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(on_off::ID))?;
        w.start_array(Tag::Context(1))?;
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(on_off::ON_OFF))?;
        w.unsigned(Tag::Context(1), u64::from(self.on.get()))?;
        w.end_container()?;
        w.end_container()?;
        w.end_container()
    }

    fn apply<'a>(
        &self,
        sets: matter_kit::tlv::TlvList<'a, ExtensionFieldSetStruct<'a>>,
        transition: u32,
    ) {
        // §1.4.9.12.4: an unknown or missing attribute "SHALL be skipped".
        for set in sets.iter().flatten() {
            if set.cluster_id != on_off::ID {
                continue;
            }
            for pair in set.attribute_value_list.iter().flatten() {
                if pair.attribute_id == on_off::ON_OFF {
                    println!("  scene: over {transition} ms");
                    self.set(pair.value_unsigned8.unwrap_or(0) != 0);
                }
            }
        }
    }
}
