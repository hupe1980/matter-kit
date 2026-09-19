//! What the stack costs on a part, measured by linking it.
//!
//! The README says this crate scales down to a 256 KB-RAM, 1 MB-flash microcontroller. That
//! claim was made for a long time on the strength of `cargo build --target
//! thumbv7em-none-eabihf` succeeding, which proves the crate *compiles* for the part and says
//! nothing about whether it fits on one. Compiling is not fitting.
//!
//! So this is a firmware image: `cortex-m-rt`'s entry point, a linker script with an
//! nRF52840's memory, and a light assembled out of the crate the way a product would assemble
//! it — endpoint 0's commissioning clusters, endpoint 1's On/Off and Identify, the message
//! layer, both session establishments, the interaction model, subscriptions and the mDNS
//! responder. `footprint/run.sh` links it and reads the sections out with `llvm-size`.
//!
//! # What the numbers do and do not include
//!
//! They are **the stack and nothing else**: no radio. A shipping Thread light also carries
//! OpenThread and a BLE host, and those are the larger half of the flash on any Matter device.
//! rs-matter publishes ~600–650 KB of flash and ~60 KB of `.bss` on this part *with Thread and
//! BLE*, so the two numbers are not comparable as they stand and this file says so rather than
//! quietly inviting the comparison.
//!
//! `.bss` here is what the node's tables cost at the `Config` below — every one of them is a
//! fixed-capacity array, so the figure moves with `FABRICS`, `SESSIONS` and the rest, and is a
//! property of the configuration rather than of the crate. The tables are in `static`s, which
//! is both what firmware does and the only way a linker can report them: this crate holds no
//! global state of its own, so a node whose tables live on the stack has a `.bss` of zero and
//! a RAM cost nobody has measured.
//!
//! # Why it calls things
//!
//! A linker drops what nothing reaches. Everything below is therefore *driven* — a datagram is
//! received, a handshake is started, an interaction is dispatched, a report is built — with
//! `black_box` around the inputs and the results so that nothing can be folded away. The image
//! does not do anything useful; it contains the same code a device that did would contain.

#![no_std]
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use core::cell::RefCell;
use core::hint::black_box;

use cortex_m_rt::entry;
use matter_kit::Config;
use matter_kit::acl::Acl;
use matter_kit::clusters::access_control::AccessControl;
use matter_kit::clusters::basic_information::{Attributes, CapabilityMinima, Product};
use matter_kit::clusters::descriptor::Descriptor;
use matter_kit::clusters::general_commissioning::{GeneralCommissioning, RegulatoryLocation};
use matter_kit::clusters::group_key_management::GroupKeyManagement;
use matter_kit::clusters::groups::Groups;
use matter_kit::clusters::identify::{Identify, IdentifyHooks};
use matter_kit::clusters::on_off::{OnOff, OnOffHooks};
use matter_kit::clusters::operational_credentials::{DeviceAttestation, OperationalCredentials};
use matter_kit::clusters::scenes::{SceneTable, Scenes};
use matter_kit::clusters::{At, Endpoints, access_control, descriptor, general_commissioning};
use matter_kit::clusters::{basic_information, identify, on_off, operational_credentials};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, DataVersions, Endpoint, Node};
use matter_kit::im::{
    Dispatcher, InteractionContext, ReadCursor, Request, Server, SubscriptionTable,
};
use matter_kit::messaging::Messaging;
use matter_kit::msg::{SessionId, VendorId};
use matter_kit::platform::{Instant, Peer, PeerAddr};
use matter_kit::sc::{PaseResponder, PbkdfParameters, ResponderConfig};
use static_cell::StaticCell;

/// The four buffers a node needs at once: what arrived, what is being built, the scratch one
/// attribute value is written in, and the datagram going out.
struct Buffers {
    datagram: [u8; 1280],
    scratch: [u8; 1024],
    payload: [u8; 1024],
    out: [u8; 1280],
}

/// A light's sizes: two ecosystems' worth of fabrics and what §2.11 demands of each.
struct Light;

impl Config for Light {
    const FABRICS: usize = 5;
    const SESSIONS: usize = 16;
    const SUBSCRIPTIONS: usize = 15;
}

const PRODUCT: Product<'static> = Product::new(
    "Example Vendor",
    VendorId(0xFFF1),
    "matter-kit light",
    0x8000,
    "matter-kit-light-0001",
)
.with_capability_minima(CapabilityMinima::from_config::<Light>());

/// Randomness is injected everywhere in this crate, and on a part it comes from the radio's
/// entropy source. A counter is the wrong answer for a product and the right one here: what is
/// being measured is the code the stack links, not the quality of a number it is handed.
struct Counter(core::cell::Cell<u32>);

impl matter_kit::platform::Rng for Counter {
    fn fill(&self, out: &mut [u8]) -> matter_kit::Result<()> {
        let mut state = self.0.get();
        for byte in out.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        self.0.set(state);
        Ok(())
    }
}

/// A lamp with nowhere to put the light, which is what a footprint image is.
struct Lamp;

impl OnOffHooks for Lamp {
    fn set(&self, on: bool) {
        black_box(on);
    }
}

impl matter_kit::clusters::scenes::SceneHooks for Lamp {
    fn capture(&self, w: &mut matter_kit::tlv::TlvWriter<'_>) -> matter_kit::Result<()> {
        // One extension field set: On/Off's `OnOff`, the only attribute on this endpoint with
        // §7.13's Scenes quality.
        w.start_structure(matter_kit::tlv::Tag::Anonymous)?;
        w.unsigned(matter_kit::tlv::Tag::Context(0), u64::from(on_off::ID))?;
        w.start_array(matter_kit::tlv::Tag::Context(1))?;
        w.start_structure(matter_kit::tlv::Tag::Anonymous)?;
        w.unsigned(matter_kit::tlv::Tag::Context(0), u64::from(on_off::ON_OFF))?;
        w.unsigned(matter_kit::tlv::Tag::Context(1), 0)?;
        w.end_container()?;
        w.end_container()?;
        w.end_container()
    }

    fn apply<'a>(
        &self,
        sets: matter_kit::tlv::TlvList<
            'a,
            matter_kit::clusters::scenes::ExtensionFieldSetStruct<'a>,
        >,
        transition: u32,
    ) {
        black_box((sets.iter().count(), transition));
    }
}

impl IdentifyHooks for Lamp {
    fn identifying(&self, on: bool) {
        black_box(on);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // The crate forbids panicking on network input, and this image has no way to report one.
    loop {
        core::hint::spin_loop();
    }
}

#[entry]
fn main() -> ! {
    let now = Instant::ZERO;
    let peer = Peer::Udp(PeerAddr::new([
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]));

    // --- The data model -------------------------------------------------------------------
    let attributes = Attributes::new(&PRODUCT, false, false);
    let lamp_descriptor = OnOff::<Lamp>::conforming(on_off::feature::LIGHTING, &Optional::NONE)
        .expect("the Lighting set");
    let identify_descriptor =
        Identify::<Lamp>::conforming(&Identify::<Lamp>::WITH_TRIGGER_EFFECT).expect("Identify");

    let root_clusters = [
        descriptor::cluster(),
        access_control::cluster(),
        attributes.cluster(),
        general_commissioning::cluster(),
        operational_credentials::cluster(),
    ];
    let groups_descriptor = Groups::<8>::conforming(
        matter_kit::clusters::groups::feature::GROUP_NAMES,
        &Optional::NONE,
    )
    .expect("the Groups set");
    let lamp_clusters: [ClusterDescriptor<'_>; 4] = [
        identify_descriptor.descriptor(),
        groups_descriptor.descriptor(),
        lamp_descriptor.descriptor(),
        descriptor::cluster(),
    ];
    let endpoints = [
        Endpoint::new(0, &root_clusters),
        Endpoint::new(1, &lamp_clusters),
    ];
    let node = Node::new(&endpoints);

    // --- The clusters behind it -----------------------------------------------------------
    //
    // Endpoint 0 is what makes the light commissionable at all, and it is where the flash goes:
    // Operational Credentials drags in Matter TLV certificates, X.509 regeneration, the DAC
    // chain and the fail-safe behind it.
    let lamp = Lamp;
    let location = Default::default();
    let on_off_server = OnOff::new(&lamp, on_off::feature::LIGHTING, None);
    let identify_server = Identify::new(&lamp, identify::IdentifyTypeEnum::LightOutput);
    // DL §4.1 makes Groups and Scenes Management mandatory on an On/Off Light, and §1.3.7.4
    // makes the Scene Table shared between them — so it is a value both borrow.
    static SCENE_TABLE: StaticCell<SceneTable<8, 32, { Light::FABRICS }>> = StaticCell::new();
    static GROUP_KEYS: StaticCell<
        RefCell<matter_kit::group::GroupKeys<{ Light::GROUP_KEYS }, { Light::GROUPS }>>,
    > = StaticCell::new();
    let scene_table = SCENE_TABLE.init(SceneTable::new(true));
    let groups_server = Groups::<8, _, _>::with(4, true, &identify_server, scene_table);
    let scenes_server = Scenes::new(scene_table, &groups_server, &lamp, true);
    let group_keys = GROUP_KEYS.init(RefCell::new(matter_kit::group::GroupKeys::new(4, 3)));
    let group_key_server = GroupKeyManagement::new(group_keys, &());
    // --- The node's tables, where firmware keeps them ---------------------------------------
    //
    // Every one is a fixed-capacity array sized from `Light`, and together they are what the
    // stack costs in RAM. The buffers below them are the other half: a datagram, the payload a
    // reply is built in, and the scratch one attribute value is written to.
    static STACK: StaticCell<Messaging<Light, { Light::SESSIONS }, 24>> = StaticCell::new();
    static SUBSCRIPTIONS: StaticCell<
        SubscriptionTable<Light, { Light::SUBSCRIPTIONS }, { Light::SUB_PATHS }>,
    > = StaticCell::new();
    static BUFFERS: StaticCell<Buffers> = StaticCell::new();

    let stack = STACK.init(Messaging::new(1, 100, 7));
    let subscriptions = SUBSCRIPTIONS.init(SubscriptionTable::new());
    // The Access Control cluster is a *view* onto the node's list, so the list is the node's
    // and the cluster borrows it. `RefCell` rather than the table directly, for the same
    // reason a device does it: the cluster edits it while the server reads it.
    static ACL_CELL: StaticCell<
        RefCell<
            Acl<Light, { Light::ACL_ENTRIES }, { Light::ACL_SUBJECTS }, { Light::ACL_TARGETS }>,
        >,
    > = StaticCell::new();
    let acl_cell = ACL_CELL.init(RefCell::new(Acl::new()));
    let access_control = AccessControl::new(acl_cell);
    let buffers = BUFFERS.init(Buffers {
        datagram: [0; 1280],
        scratch: [0; 1024],
        payload: [0; 1024],
        out: [0; 1280],
    });
    // What `AddNOC` and `ArmFailSafe` need behind them.
    static FAIL_SAFE: StaticCell<RefCell<FailSafe>> = StaticCell::new();
    static WINDOW: StaticCell<RefCell<CommissioningWindow>> = StaticCell::new();
    static FABRIC_CELL: StaticCell<
        RefCell<matter_kit::fabric::FabricTable<Light, { Light::FABRICS }>>,
    > = StaticCell::new();
    static KEY_CELL: StaticCell<RefCell<matter_kit::crypto::SoftKeyStore<8>>> = StaticCell::new();
    static RNG_CELL: StaticCell<RefCell<Counter>> = StaticCell::new();

    let fail_safe = FAIL_SAFE.init(RefCell::new(FailSafe::new(
        BasicCommissioningInfo::default(),
    )));
    let window = WINDOW.init(RefCell::new(CommissioningWindow::new()));
    let fabric_cell = FABRIC_CELL.init(RefCell::new(matter_kit::fabric::FabricTable::new()));
    let key_cell = KEY_CELL.init(RefCell::new(matter_kit::crypto::SoftKeyStore::new()));
    let rng_cell = RNG_CELL.init(RefCell::new(Counter(core::cell::Cell::new(1))));

    let general_commissioning = GeneralCommissioning::new(
        &location,
        RegulatoryLocation::IndoorOutdoor,
        fail_safe,
        window,
    );
    let opcreds = OperationalCredentials::new(
        fabric_cell,
        key_cell,
        rng_cell,
        fail_safe,
        DeviceAttestation {
            dac: &[],
            pai: &[],
            certification_declaration: &[],
            dac_key: matter_kit::crypto::KeyHandle(0),
            firmware_information: None,
        },
    );

    // Endpoint 0 is where the flash goes: Operational Credentials drags in Matter TLV
    // certificates, X.509 regeneration, the DAC chain and the fail-safe behind them.
    let handler = Endpoints((
        At::new(
            0,
            (
                Descriptor::new(node, 0).with_parts(&[1]),
                &access_control,
                basic_information::BasicInformation::new(&PRODUCT, &location),
                &general_commissioning,
                &opcreds,
                &group_key_server,
            ),
        ),
        At::new(
            1,
            (
                Descriptor::new(node, 1),
                &identify_server,
                &groups_server,
                &on_off_server,
                &scenes_server,
            ),
        ),
    ));

    let versions = DataVersions::<8>::new(1);
    let mut dispatcher: Dispatcher<4> = Dispatcher::new(1);
    let mut cursor = ReadCursor::START;

    let Buffers {
        datagram,
        scratch,
        payload,
        out,
    } = buffers;

    // §4.7.2: a datagram finds its session, its exchange and its protocol.
    let received = stack.receive(black_box(datagram), peer, now);
    black_box(&received);
    drop(received);

    // §4.14.1: PASE, which is how the light is commissioned.
    let parameters = PbkdfParameters::new(10_000, black_box(&[0x5Au8; 16])).expect("parameters");
    let verifier = matter_kit::crypto::Spake2pVerifierData::from_passcode(
        black_box(20_202_021),
        &parameters.salt,
        parameters.iterations,
    )
    .expect("verifier");
    let mut pase = PaseResponder::new(
        ResponderConfig {
            verifier,
            parameters,
            session_params: None,
        },
        SessionId(1),
    );
    black_box(pase.on_pbkdf_param_request(
        black_box(&datagram[..8]),
        black_box(&[0x11; 32]),
        &mut *out,
    ))
    .ok();

    // §4.14.2: CASE, which is every session after that, with the fabric table behind it.
    if let Ok(sigma1) = matter_kit::sc::Sigma1::decode(black_box(&datagram[..16])) {
        black_box(matter_kit::sc::case::accept_sigma1(
            &sigma1,
            &fabric_cell.borrow(),
            &mut *key_cell.borrow_mut(),
            SessionId(2),
            None,
            &matter_kit::sc::case::Sigma2Randomness {
                ephemeral: &[0x22; 32],
                responder: &[0x33; 32],
                resumption: &[0x44; 16],
            },
            &mut out[..],
        ))
        .ok();
    }

    // §8.4, §8.7, §8.8: the interaction model, through the one entry point that applies
    // §8.7.2.3's and §8.8.2.3's rules first.
    let access = matter_kit::im::AllowAll;
    let server = Server::new(node, &access, &handler, 8).with_data_versions(&versions);
    let request = Request {
        opcode: matter_kit::im::opcode::READ_REQUEST,
        payload: black_box(&datagram[..4]),
        session: Some(SessionId(1)),
        exchange: matter_kit::msg::ExchangeId(1),
        groupcast: false,
    };
    let ctx = InteractionContext::new().at(now);
    black_box(dispatcher.dispatch(
        &server,
        request,
        &ctx,
        &mut cursor,
        &mut scratch[..],
        &mut payload[..],
    ))
    .ok();

    // §8.5: subscriptions, and the reporting engine that decides when one is due and builds
    // what it owes — which is where a subscribed light spends its time.
    black_box(subscriptions.due(now).count());
    if let Some(subscription) = subscriptions.iter_mut().next() {
        black_box(server.report_chunk(
            subscription,
            matter_kit::im::ReportReason::Data,
            &ctx,
            &mut scratch[..],
            &mut payload[..],
        ))
        .ok();
    }
    black_box(acl_cell.borrow().entries().count());
    black_box(&access_control);
    black_box(stack.poll(now, 0));
    black_box(stack.wake_at());

    // §4.3: the mDNS responder, which is how a commissioner finds the light at all.
    let txt = matter_kit::discovery::txt::TxtWriter::new();
    let advertisement = matter_kit::discovery::responder::Advertisement::new(
        "0011223344556677",
        matter_kit::discovery::COMMISSIONABLE_SERVICE,
        "0011223344556677",
        matter_kit::PORT,
        txt.finish(),
    );
    let advertisements = [advertisement];
    let responder = matter_kit::discovery::responder::Responder {
        advertisements: &advertisements,
    };
    black_box(responder.respond(black_box(&datagram[..12]), &mut out[..])).ok();

    loop {
        core::hint::spin_loop();
    }
}
