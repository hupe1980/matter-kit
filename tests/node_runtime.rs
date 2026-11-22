//! The node runtime against controllers built from this crate's own client half.
//!
//! Each test drives `node::Runtime` the way a device's loop does — datagrams in, `poll` on time,
//! datagrams out — and checks a rule the runtime owns that a hand-written loop used to keep (or
//! forget). Most were found as defects in `examples/light`; several are written so that they fail
//! on a node that keeps the rule the way that example did.
//!
//! The controllers are `Messaging` stacks with a session installed directly at both ends with
//! known keys, so a test is about the interaction rather than about PASE or CASE — except where
//! the handshake itself is the point. Both ends being this crate is the limitation every
//! in-process test here shares: a reading both ends get wrong the same way passes. That is what
//! `interop/` is for.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use core::cell::RefCell;

use hex_literal::hex;
use matter_kit::acl::Acl;
use matter_kit::cert::{
    BasicConstraints, CERT_DER_MAX, CERT_TLV_MAX, DistinguishedName, DnAttribute, EllipticCurveId,
    Extension, Extensions, KeyPurposeId, KeyUsage, MatterCertificate, PublicKeyAlgorithm,
    SignatureAlgorithm, der,
};
use matter_kit::clusters::access_control::{self, AccessControl};
use matter_kit::clusters::basic_information::{Attributes, BasicInformation, Location, Product};
use matter_kit::clusters::descriptor::{self, Descriptor};
use matter_kit::clusters::general_commissioning::{self, GeneralCommissioning, RegulatoryLocation};
use matter_kit::clusters::group_key_management::{self, GroupKeyManagement};
use matter_kit::clusters::on_off::{self, OnOff, OnOffHooks};
use matter_kit::clusters::operational_credentials::{
    self as opcreds, DeviceAttestation, NocStatus, OperationalCredentials,
};
use matter_kit::clusters::{At, Endpoints};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::crypto::{
    GROUP_SIZE_BYTES, KeyPurpose, KeyStore, PublicKey, SoftKeyStore, Spake2pVerifierData,
    SymmetricKey,
};
use matter_kit::dm::events::{EventNumbers, EventStore};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{DataVersions, DeviceType, Endpoint, EventPriority, Node, Privilege};
use matter_kit::exchange::{ExchangeKey, Role};
use matter_kit::fabric::{Credentials, Fabric, FabricIdentity, FabricTable};
use matter_kit::group::GroupKeys;
use matter_kit::im::{
    self, AttributePath, ClusterHandler, CommandData, CommandPath, InvokeResponse,
    InvokeResponseMessage, ReportData, Status, StatusResponse, SubscribeResponse, opcode,
};
use matter_kit::messaging::{Messaging, Received};
use matter_kit::msg::{
    FabricId, FabricIndex, NodeId, ProtocolId, SessionId, SessionKeys, VendorId,
};
use matter_kit::node::{AccessList, ChangeLog, Device, EventLog, GroupKeyStore, Notice, Runtime};
use matter_kit::platform::sim::SimRng;
use matter_kit::platform::{Duration, Instant, Peer, PeerAddr, Rng};
use matter_kit::sc::PbkdfParameters;
use matter_kit::session::{self, EstablishedKeys, SecureSession, SessionKind};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};
use matter_kit::{Config, DefaultConfig};

type Rt = Runtime<DefaultConfig>;
type Store = SoftKeyStore<8>;
type Fabrics = FabricTable<DefaultConfig, { DefaultConfig::FABRICS }>;

const PRODUCT: Product<'static> = Product::new(
    "Test Vendor",
    VendorId(0xFFF1),
    "node runtime",
    0x8000,
    "node-runtime-0001",
);
const ROOT: &[DeviceType] = &[DeviceType::new(0x0016, 3)];
const LIGHT: &[DeviceType] = &[DeviceType::new(0x0100, 3)];
const SALT: &[u8] = b"SPAKE2P Key Salt";

fn at(ms: u64) -> Instant {
    Instant::from_micros(ms * 1000)
}

// --- The device --------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Lamp {
    on: core::cell::Cell<bool>,
}

impl OnOffHooks for Lamp {
    fn set(&self, on: bool) {
        self.on.set(on);
    }
}

/// A node with no Groups cluster.
struct NoGroups;

impl group_key_management::GroupTable for NoGroups {
    fn memberships(&self, _each: &mut dyn FnMut(FabricIndex, matter_kit::msg::GroupId, u16)) {}
    fn name(&self, _fabric: FabricIndex, _group: matter_kit::msg::GroupId) -> Option<&str> {
        None
    }
}

const DAC_PRIVATE_KEY: [u8; GROUP_SIZE_BYTES] =
    hex!("a565b3fa28a8ed6a74fb6f0ff8a4d340d9e1ae98f21dfa1f0a59a4ea021a1627");
const DAC_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
const PAI_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x02];
const CD: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x03];

/// Builds a device and a runtime in the caller's scope: `fixture!(device, rt, parts)`.
///
/// A macro because a `Device` borrows two dozen locals, which no function can return.
macro_rules! fixture {
    ($device:ident, $rt:ident, $parts:ident) => {
        let location = Location::region_agnostic();
        let attributes = Attributes::new(&PRODUCT, false, false);
        let gkm = GroupKeyManagement::<DefaultConfig, NoGroups>::conforming(0, &Optional::NONE)
            .expect("gkm");
        let lamp_descriptor = OnOff::<Lamp>::conforming(0, &Optional::NONE).expect("on/off");
        let root_clusters = [
            descriptor::cluster(),
            access_control::cluster(),
            attributes.cluster(),
            general_commissioning::cluster(),
            opcreds::cluster(),
            gkm.descriptor(),
        ];
        let lamp_clusters = [lamp_descriptor.descriptor(), descriptor::cluster()];
        let endpoints = [
            Endpoint::new(0, &root_clusters).with_device_types(ROOT),
            Endpoint::new(1, &lamp_clusters).with_device_types(LIGHT),
        ];
        let node = Node::new(&endpoints);
        node.validate().expect("valid node");

        let mut store = Store::new();
        let dac_key = store
            .import(KeyPurpose::DeviceAttestation, &DAC_PRIVATE_KEY)
            .expect("dac");
        let keys = RefCell::new(store);
        let fabrics = RefCell::new(Fabrics::new());
        let rng = RefCell::new(SimRng::new(7));
        let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
        let window = RefCell::new(CommissioningWindow::new());
        let general_commissioning = GeneralCommissioning::new(
            &location,
            RegulatoryLocation::IndoorOutdoor,
            &fail_safe,
            &window,
        );
        let acl = RefCell::new(Acl::<DefaultConfig, 20, 4, 3>::new());
        let access_control_cluster = AccessControl::new(&acl);
        let group_keys = RefCell::new(GroupKeys::<DefaultConfig>::new());
        let no_groups = NoGroups;
        let group_keys_cluster = GroupKeyManagement::new(&group_keys, &no_groups);
        let lamp = Lamp::default();
        let lamp_cluster = OnOff::new(&lamp, 0, None);
        lamp_cluster.start(false);
        let credentials = OperationalCredentials::new(
            &fabrics,
            &keys,
            &rng,
            &fail_safe,
            DeviceAttestation {
                dac: DAC_DER,
                pai: PAI_DER,
                certification_declaration: CD,
                dac_key,
                firmware_information: None,
            },
        );
        let handler = Endpoints((
            At::new(
                0,
                (
                    Descriptor::new(node, 0).with_parts(&[1]),
                    &access_control_cluster,
                    BasicInformation::new(&PRODUCT, &location),
                    &general_commissioning,
                    &credentials,
                    &group_keys_cluster,
                ),
            ),
            At::new(1, (&lamp_cluster, Descriptor::new(node, 1))),
        ));
        let versions = DataVersions::<16>::new(1);
        let events = RefCell::new(EventStore::<4, 4, 4>::new({
            let mut numbers = EventNumbers::restore(0);
            if let Some(owed) = numbers.reservation() {
                numbers.reserved(owed);
            }
            numbers
        }));
        let parameters = PbkdfParameters::new(1_000, SALT).expect("parameters");
        let verifier =
            Spake2pVerifierData::from_passcode(20_202_021, SALT, 1_000).expect("verifier");
        let $device = Device {
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
            memberships: None,
        };
        let mut $rt = Box::new(Rt::new(&SimRng::new(11)).expect("runtime"));
        #[allow(unused_variables)]
        let $parts = Parts {
            acl: &acl,
            fabrics: &fabrics,
            keys: &keys,
            fail_safe: &fail_safe,
            window: &window,
            group_keys: &group_keys,
            events: &events,
        };
    };
}

/// The tables a test inspects behind the runtime's back.
struct Parts<'a> {
    acl: &'a RefCell<Acl<DefaultConfig, 20, 4, 3>>,
    fabrics: &'a RefCell<Fabrics>,
    keys: &'a RefCell<Store>,
    fail_safe: &'a RefCell<FailSafe>,
    window: &'a RefCell<CommissioningWindow>,
    group_keys: &'a RefCell<GroupKeys<DefaultConfig>>,
    events: &'a RefCell<EventStore<4, 4, 4>>,
}

/// The runtime bound to its device, as a test drives it.
trait Drive {
    fn rx(&mut self, bytes: &mut [u8], from: PeerAddr, now: Instant);
    fn tick(&mut self, now: Instant);
    fn tx(&mut self) -> Option<(Peer, Vec<u8>)>;
    fn rt(&mut self) -> &mut Rt;
    fn notices(&mut self) -> Vec<Notice> {
        let mut out = Vec::new();
        while let Some(n) = self.rt().notice() {
            out.push(n);
        }
        out
    }
}

struct Dut<'r, 'd, D> {
    rt: &'r mut Rt,
    device: &'d D,
}

impl<K, G, H, Ac, Gk, Ev, V, const F: usize> Drive
    for Dut<'_, '_, Device<'_, DefaultConfig, K, G, H, Ac, Gk, Ev, V, F>>
where
    K: KeyStore,
    G: Rng,
    H: ClusterHandler,
    Ac: AccessList,
    Gk: GroupKeyStore,
    Ev: EventLog,
    V: ChangeLog,
{
    fn rx(&mut self, bytes: &mut [u8], from: PeerAddr, now: Instant) {
        self.rt.receive(self.device, bytes, Peer::Udp(from), now);
        self.rt.poll(self.device, now);
    }
    fn tick(&mut self, now: Instant) {
        self.rt.poll(self.device, now);
    }
    fn tx(&mut self) -> Option<(Peer, Vec<u8>)> {
        self.rt.transmit().map(|(p, b)| (p, b.to_vec()))
    }
    fn rt(&mut self) -> &mut Rt {
        self.rt
    }
}

fn bind<'r, 'd, D>(rt: &'r mut Rt, device: &'d D) -> Dut<'r, 'd, D> {
    Dut { rt, device }
}

// --- The controllers ---------------------------------------------------------------------------

/// One message a controller received.
#[derive(Debug, Clone)]
struct Msg {
    exchange: ExchangeKey,
    opcode: u8,
    payload: Vec<u8>,
}

/// A controller: a messaging stack with one session to the device.
struct Controller {
    stack: Messaging<DefaultConfig>,
    addr: PeerAddr,
    session: SessionId,
    inbox: Vec<Msg>,
    outbox: Vec<Vec<u8>>,
    /// Drop everything that arrives — a subscriber that has gone quiet.
    deaf: bool,
}

fn keys(seed: u8) -> EstablishedKeys {
    EstablishedKeys {
        i2r: SessionKeys::from_encryption_key(SymmetricKey::new([seed; 16])).expect("i2r"),
        r2i: SessionKeys::from_encryption_key(SymmetricKey::new([seed ^ 0xFF; 16])).expect("r2i"),
        attestation_challenge: SymmetricKey::new([seed ^ 0x5A; 16]),
    }
}

impl Controller {
    /// A controller on `fabric` as operational node `node`, or over PASE if `fabric` is `None`.
    fn new(index: u8, rt: &mut Rt, fabric: Option<FabricIndex>, node: NodeId) -> Self {
        let addr = PeerAddr::new([0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, index]);
        let device_session = SessionId(0x1000 + u16::from(index));
        let controller_session = SessionId(0x2000 + u16::from(index));
        let kind = if fabric.is_some() {
            SessionKind::Case
        } else {
            SessionKind::Pase
        };
        let device_node = NodeId(0x0000_0000_00DE_0001);
        let mut ours = SecureSession::new(
            controller_session,
            device_session,
            kind,
            session::Role::Initiator,
            keys(index),
            1,
            at(0),
        );
        let mut theirs = SecureSession::new(
            device_session,
            controller_session,
            kind,
            session::Role::Responder,
            keys(index),
            1,
            at(0),
        );
        if let Some(fabric) = fabric {
            ours.local_node_id = node;
            ours.peer_node_id = device_node;
            ours.fabric_index = fabric;
            theirs.local_node_id = device_node;
            theirs.peer_node_id = node;
            theirs.fabric_index = fabric;
        }
        theirs.peer = Some(Peer::Udp(addr));
        rt.messaging_mut()
            .sessions_mut()
            .insert(theirs)
            .expect("room on the device");
        let mut stack = Messaging::new(
            0x3000 + u16::from(index) * 16,
            0x400,
            0x0100_0000 * u32::from(index),
        );
        stack.sessions_mut().insert(ours).expect("room");
        Self {
            stack,
            addr,
            session: controller_session,
            inbox: Vec::new(),
            outbox: Vec::new(),
            deaf: false,
        }
    }

    fn open(&mut self, now: Instant) -> ExchangeKey {
        self.stack
            .open(self.session, ProtocolId::INTERACTION_MODEL, now)
            .expect("open")
    }

    fn send(&mut self, exchange: ExchangeKey, opcode: u8, payload: &[u8], now: Instant) {
        let mut scratch = [0u8; 1280];
        let mut out = [0u8; 1280];
        let (n, _) = self
            .stack
            .send(
                exchange,
                opcode,
                true,
                payload,
                now,
                0,
                &mut scratch,
                &mut out,
            )
            .expect("send");
        self.outbox.push(out[..n].to_vec());
    }

    fn ack(&mut self, exchange: ExchangeKey, now: Instant) {
        let mut out = [0u8; 1280];
        let n = self
            .stack
            .acknowledge(exchange, now, &mut out)
            .expect("ack");
        if n > 0 {
            self.outbox.push(out[..n].to_vec());
        }
    }

    fn deliver(&mut self, bytes: &[u8], now: Instant) {
        if self.deaf {
            return;
        }
        let mut buf = bytes.to_vec();
        let device = Peer::Udp(PeerAddr::new([
            0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        match self.stack.receive(&mut buf, device, now) {
            Ok(Received::Message {
                exchange,
                header,
                payload,
                ..
            }) => self.inbox.push(Msg {
                exchange,
                opcode: header.opcode,
                payload: payload.to_vec(),
            }),
            Ok(Received::Duplicate { exchange, .. }) => self.ack(exchange, now),
            Ok(_) | Err(_) => {}
        }
    }

    /// The next message, which must be there.
    fn take(&mut self) -> Msg {
        assert!(!self.inbox.is_empty(), "expected a message");
        self.inbox.remove(0)
    }

    /// Sends a request on a fresh exchange.
    fn request(&mut self, op: u8, payload: &[u8], now: Instant) -> ExchangeKey {
        let exchange = self.open(now);
        self.send(exchange, op, payload, now);
        exchange
    }

    /// `StatusResponse(SUCCESS)` on `exchange`: next chunk, or acknowledge a report.
    fn ok(&mut self, exchange: ExchangeKey, now: Instant) {
        let mut buf = [0u8; 16];
        let bytes = StatusResponse::new(Status::Success)
            .encode(&mut buf)
            .expect("encode");
        self.send(exchange, opcode::STATUS_RESPONSE, bytes, now);
    }
}

/// Moves datagrams until neither side has anything left to send.
fn pump(dut: &mut impl Drive, controllers: &mut [&mut Controller], now: Instant) {
    for _ in 0..10_000 {
        let mut moved = false;
        while let Some((peer, bytes)) = dut.tx() {
            moved = true;
            if let Peer::Udp(addr) = peer {
                for c in controllers.iter_mut() {
                    if c.addr == addr {
                        c.deliver(&bytes, now);
                    }
                }
            }
        }
        for c in controllers.iter_mut() {
            let pending: Vec<Vec<u8>> = std::mem::take(&mut c.outbox);
            for mut datagram in pending {
                moved = true;
                dut.rx(&mut datagram, c.addr, now);
            }
        }
        if !moved {
            return;
        }
    }
    panic!("the exchange never settled");
}

// --- Messages ----------------------------------------------------------------------------------

fn read(paths: &[AttributePath], fabric_filtered: bool) -> Vec<u8> {
    let mut buf = [0u8; 512];
    im::encode_read_request(&mut buf, paths.iter().copied(), [], fabric_filtered)
        .expect("read")
        .to_vec()
}

fn subscribe(paths: &[AttributePath], min: u16, max: u16) -> Vec<u8> {
    let mut buf = [0u8; 512];
    im::encode_subscribe_request(&mut buf, paths.iter().copied(), [], min, max, true, false)
        .expect("subscribe")
        .to_vec()
}

fn invoke(endpoint: u16, cluster: u32, command: u32, fields: Option<&[u8]>) -> Vec<u8> {
    let mut buf = [0u8; 2048];
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(endpoint, cluster, command))
    };
    im::encode_invoke_request(&mut buf, [data], false, false)
        .expect("invoke")
        .to_vec()
}

/// The response command's fields, or the status.
fn invoke_response(payload: &[u8]) -> Result<Vec<u8>, Status> {
    let response = InvokeResponseMessage::decode(payload).expect("decode");
    match response
        .responses()
        .expect("responses")
        .next()
        .expect("one")
        .expect("decode")
    {
        InvokeResponse::Command(c) => Ok(c.fields.unwrap_or(&[]).to_vec()),
        InvokeResponse::Status(s) => Err(s.status.status),
    }
}

/// The paths in a report, and whether more chunks follow.
fn report(payload: &[u8]) -> (Vec<AttributePath>, bool, Option<u32>) {
    let report = ReportData::decode(payload).expect("report");
    let paths = report
        .attribute_reports()
        .expect("reports")
        .map(|it| it.map(|r| r.expect("report").path()).collect())
        .unwrap_or_default();
    (paths, report.more_chunked_messages, report.subscription_id)
}

/// Reads to completion on one exchange, acknowledging chunks; returns every path reported.
fn read_all(
    dut: &mut impl Drive,
    c: &mut Controller,
    request: &[u8],
    now: Instant,
) -> Vec<AttributePath> {
    let exchange = c.request(opcode::READ_REQUEST, request, now);
    let mut all = Vec::new();
    loop {
        pump(dut, &mut [c], now);
        let msg = c.take();
        assert_eq!(msg.exchange, exchange);
        assert_eq!(msg.opcode, opcode::REPORT_DATA);
        let (paths, more, _) = report(&msg.payload);
        all.extend(paths);
        if !more {
            c.ack(exchange, now);
            pump(dut, &mut [c], now);
            c.stack.close(exchange);
            return all;
        }
        c.ok(exchange, now);
    }
}

/// Subscribes and runs the flow to the grant; returns the subscription id and the priming paths.
fn subscribe_all(
    dut: &mut impl Drive,
    c: &mut Controller,
    request: &[u8],
    now: Instant,
) -> (u32, Vec<AttributePath>) {
    let exchange = c.request(opcode::SUBSCRIBE_REQUEST, request, now);
    let mut primed = Vec::new();
    loop {
        pump(dut, &mut [c], now);
        let msg = c.take();
        assert_eq!(msg.exchange, exchange);
        if msg.opcode == opcode::SUBSCRIBE_RESPONSE {
            let granted = SubscribeResponse::decode(&msg.payload).expect("response");
            c.ack(exchange, now);
            pump(dut, &mut [c], now);
            c.stack.close(exchange);
            return (granted.subscription_id, primed);
        }
        assert_eq!(msg.opcode, opcode::REPORT_DATA);
        let (paths, _, _) = report(&msg.payload);
        primed.extend(paths);
        c.ok(exchange, now);
    }
}

/// Toggles the lamp over `c`'s session, delivering whatever else the device sends to `others`.
fn toggle_seen(
    dut: &mut impl Drive,
    c: &mut Controller,
    others: &mut [&mut Controller],
    now: Instant,
) {
    let exchange = c.request(
        opcode::INVOKE_REQUEST,
        &invoke(1, on_off::ID, on_off::TOGGLE, None),
        now,
    );
    let mut all: Vec<&mut Controller> = vec![&mut *c];
    all.extend(others.iter_mut().map(|o| &mut **o));
    pump(dut, &mut all, now);
    let i = c
        .inbox
        .iter()
        .position(|m| m.exchange == exchange)
        .expect("a response");
    let msg = c.inbox.remove(i);
    assert_eq!(invoke_response(&msg.payload), Err(Status::Success));
    c.ack(exchange, now);
    pump(dut, &mut [c], now);
    c.stack.close(exchange);
}

/// Toggles the lamp over `c`'s session.
fn toggle(dut: &mut impl Drive, c: &mut Controller, now: Instant) {
    let exchange = c.request(
        opcode::INVOKE_REQUEST,
        &invoke(1, on_off::ID, on_off::TOGGLE, None),
        now,
    );
    pump(dut, &mut [c], now);
    let msg = c.take();
    assert_eq!(msg.exchange, exchange);
    assert_eq!(invoke_response(&msg.payload), Err(Status::Success));
    c.ack(exchange, now);
    pump(dut, &mut [c], now);
    c.stack.close(exchange);
}

/// A fabric in the table, without a commissioning flow — its certificates are placeholders,
/// which is enough for everything here except CASE.
fn synthetic_fabric(parts: &Parts<'_>, index: u8) -> FabricIndex {
    let mut seed = [0u8; 32];
    SimRng::new(u64::from(index)).fill(&mut seed).unwrap();
    let (key, public) = parts
        .keys
        .borrow_mut()
        .generate(KeyPurpose::Operational, &seed)
        .expect("key");
    let fabric = Fabric::new(
        FabricIndex(index),
        FabricIdentity {
            fabric_id: FabricId(0xFAB0_0000_0000_0000 | u64::from(index)),
            node_id: NodeId(0x0000_0000_00DE_0001),
            root_public_key: public,
            admin_vendor_id: VendorId(0xFFF1),
        },
        &SymmetricKey::new([index; 16]),
        key,
        Credentials::new(&[1], &[2]).expect("credentials"),
    )
    .expect("fabric");
    parts.fabrics.borrow_mut().insert(fabric).expect("room")
}

fn admin(parts: &Parts<'_>, fabric: FabricIndex, node: NodeId) {
    parts
        .acl
        .borrow_mut()
        .add_admin_for_fabric(fabric, node)
        .expect("admin");
}

const NODE_A: NodeId = NodeId(0x0000_0000_0000_00A1);
const NODE_B: NodeId = NodeId(0x0000_0000_0000_00B2);

// --- US1: the interaction model ----------------------------------------------------------------

/// §10.2.3, per exchange: a wildcard read chunks, and two controllers reading at once each get
/// exactly their own series. With one cursor shared between them — what a node that keeps
/// "the read in progress" in one variable has — the second controller's continuation resumes
/// wherever the first left off.
#[test]
fn two_controllers_reading_chunked_never_see_each_others_chunks() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    let f2 = synthetic_fabric(&parts, 2);
    admin(&parts, f1, NODE_A);
    admin(&parts, f2, NODE_B);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut b = Controller::new(3, &mut rt, Some(f2), NODE_B);
    let mut dut = bind(&mut rt, &device);
    let wildcard = read(&[AttributePath::wildcard()], false);

    // What one controller sees alone.
    let alone = read_all(&mut dut, &mut a, &wildcard, at(10));
    assert!(
        alone.len() > 24,
        "a wildcard read chunks: {} paths",
        alone.len()
    );

    // Both at once, interleaving every acknowledgement.
    let ea = a.request(opcode::READ_REQUEST, &wildcard, at(20));
    let eb = b.request(opcode::READ_REQUEST, &wildcard, at(20));
    let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
    let (mut done_a, mut done_b) = (false, false);
    while !(done_a && done_b) {
        pump(&mut dut, &mut [&mut a, &mut b], at(20));
        for (c, e, got, done) in [
            (&mut a, ea, &mut got_a, &mut done_a),
            (&mut b, eb, &mut got_b, &mut done_b),
        ] {
            if *done {
                continue;
            }
            let msg = c.take();
            assert_eq!(msg.exchange, e);
            let (paths, more, _) = report(&msg.payload);
            got.extend(paths);
            if more {
                c.ok(e, at(20));
            } else {
                c.ack(e, at(20));
                *done = true;
            }
        }
    }
    pump(&mut dut, &mut [&mut a, &mut b], at(20));
    assert_eq!(got_a, alone, "controller A got exactly its own series");
    assert_eq!(
        got_b.len(),
        alone.len(),
        "controller B got a whole series of its own"
    );
    assert_eq!(dut.rt().messaging().exchanges().len(), 0);
}

/// §4.10.5.3: the exchange is the application layer's to close, and a fixed-capacity table makes
/// that not optional. A hundred reads, each acknowledged the way a client may choose to, leave
/// nothing behind.
#[test]
fn a_hundred_reads_leave_the_exchange_table_empty() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut dut = bind(&mut rt, &device);
    let one = read(
        &[AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)],
        false,
    );
    for i in 0..100 {
        let paths = read_all(&mut dut, &mut a, &one, at(10 + i));
        assert_eq!(paths.len(), 1);
    }
    assert_eq!(dut.rt().messaging().exchanges().len(), 0);
}

/// §8.5.2: four messages, and the subscription is active only after the fourth. A report that
/// went out before the `SubscribeResponse` would clear the re-prime flag mid-series.
#[test]
fn a_subscription_is_granted_after_its_priming_report_and_no_report_precedes_it() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut b = Controller::new(3, &mut rt, Some(f1), NODE_B);
    admin(&parts, f1, NODE_B);
    let mut dut = bind(&mut rt, &device);

    let exchange = a.request(
        opcode::SUBSCRIBE_REQUEST,
        &subscribe(&[AttributePath::wildcard()], 0, 60),
        at(10),
    );
    pump(&mut dut, &mut [&mut a], at(10));
    let first = a.take();
    assert_eq!(first.opcode, opcode::REPORT_DATA);
    let (_, more, id) = report(&first.payload);
    assert!(more, "the priming report of a wildcard subscription chunks");
    // A change while the priming report is going out, and time for MinInterval (0) to pass.
    toggle(&mut dut, &mut b, at(11));
    dut.tick(at(5_000));
    pump(&mut dut, &mut [&mut a], at(5_000));
    assert!(
        a.inbox.iter().all(|m| m.exchange == exchange),
        "no report on another exchange before the grant"
    );
    // Drive the priming to its end.
    a.ok(exchange, at(5_000));
    loop {
        pump(&mut dut, &mut [&mut a], at(5_000));
        let msg = a.take();
        if msg.opcode == opcode::SUBSCRIBE_RESPONSE {
            assert_eq!(
                SubscribeResponse::decode(&msg.payload)
                    .unwrap()
                    .subscription_id,
                id.unwrap()
            );
            break;
        }
        a.ok(exchange, at(5_000));
    }
    assert!(dut.notices().contains(&Notice::Granted { id: id.unwrap() }));
}

/// §8.5.3 and MRP: one report in flight per subscription. A subscriber that stops acknowledging
/// must not make the node open an exchange per tick until its table is full.
#[test]
fn a_silent_subscriber_holds_one_report_exchange_at_most() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    admin(&parts, f1, NODE_B);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut b = Controller::new(3, &mut rt, Some(f1), NODE_B);
    let mut dut = bind(&mut rt, &device);
    let path = [AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)];
    subscribe_all(&mut dut, &mut a, &subscribe(&path, 0, 60), at(10));
    a.deaf = true;
    for i in 0..20u64 {
        toggle(&mut dut, &mut b, at(100 + i * 100));
        dut.tick(at(150 + i * 100));
        pump(&mut dut, &mut [&mut a, &mut b], at(150 + i * 100));
        let own = dut
            .rt()
            .messaging()
            .exchanges()
            .iter()
            .filter(|e| e.key.role == Role::Initiator)
            .count();
        assert!(own <= 1, "{own} report exchanges open for one subscriber");
    }
}

/// §11.18.6.7 scopes CSR state to "the same secure session". A node that does not tell the
/// cluster which session an interaction arrived on lets one commissioner's `AddNOC` consume the
/// key another one's `CSRRequest` generated.
#[test]
fn a_csr_from_one_session_cannot_be_consumed_from_another() {
    fixture!(device, rt, parts);
    let mut a = Controller::new(2, &mut rt, None, NodeId(0));
    let mut b = Controller::new(3, &mut rt, None, NodeId(0));
    let mut dut = bind(&mut rt, &device);
    let now = at(10);

    let e = a.request(
        opcode::INVOKE_REQUEST,
        &invoke(
            0,
            general_commissioning::ID,
            general_commissioning::ARM_FAIL_SAFE,
            Some(&arm_fail_safe(120)),
        ),
        now,
    );
    pump(&mut dut, &mut [&mut a], now);
    assert!(invoke_response(&a.take().payload).is_ok());
    a.ack(e, now);
    let public = csr(&mut dut, &mut a, now);
    add_root(&mut dut, &mut b, now);
    let mut noc = [0u8; CERT_TLV_MAX];
    let n = issue_noc(DEVICE_NODE_ID, public, &mut noc);
    let status = add_noc(&mut dut, &mut b, &noc[..n], now);
    assert_eq!(
        status,
        NocStatus::MissingCsr.value(),
        "B may not use the key A asked for"
    );
}

/// §4.12.2.1: "Logical retransmission is of a given message as identified by its message
/// counter" — the same bytes again. A node that keeps nothing it sent cannot retransmit at all,
/// and one lost datagram fails the interaction.
#[test]
fn a_lost_reply_is_resent_byte_for_byte() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut dut = bind(&mut rt, &device);
    let one = read(
        &[AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)],
        false,
    );
    let mut request = {
        let e = a.open(at(10));
        a.send(e, opcode::READ_REQUEST, &one, at(10));
        a.outbox.pop().unwrap()
    };
    dut.rx(&mut request, a.addr, at(10));
    let (_, original) = dut.tx().expect("a reply");
    // Lost. MRP's first retransmission is due within a few seconds.
    let mut resent = None;
    for ms in (100..10_000).step_by(100) {
        dut.tick(at(10 + ms));
        if let Some((_, bytes)) = dut.tx() {
            resent = Some(bytes);
            break;
        }
    }
    assert_eq!(resent.expect("a retransmission"), original);
}

/// A report that cannot be handed out does not count as reported: the subscription stays due and
/// the failure is a notice, not silence.
#[test]
fn a_report_that_cannot_be_framed_stays_due() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    admin(&parts, f1, NODE_B);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut b = Controller::new(3, &mut rt, Some(f1), NODE_B);
    let a_session = SessionId(0x1002);
    let mut dut = bind(&mut rt, &device);
    let path = [AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)];
    let (id, _) = subscribe_all(&mut dut, &mut a, &subscribe(&path, 0, 60), at(10));
    // The node forgets where A is: the report has nowhere to go.
    let peer = dut
        .rt()
        .messaging_mut()
        .sessions_mut()
        .find_mut(a_session)
        .unwrap()
        .peer
        .take();
    toggle(&mut dut, &mut b, at(100));
    dut.tick(at(200));
    let failed = dut
        .notices()
        .into_iter()
        .any(|n| matches!(n, Notice::ReportFailed { id: failed, .. } if failed == id));
    assert!(failed, "the failure is reported");
    assert!(
        dut.rt().subscriptions().find(id).unwrap().has_pending(),
        "and still due"
    );
    // Once it can go, it goes.
    dut.rt()
        .messaging_mut()
        .sessions_mut()
        .find_mut(a_session)
        .unwrap()
        .peer = peer;
    dut.tick(at(1_500));
    pump(&mut dut, &mut [&mut a], at(1_500));
    let msg = a.take();
    assert_eq!(report(&msg.payload).2, Some(id));
}

// --- US2: cascades ------------------------------------------------------------------------------

/// §11.18.6.12: removing a fabric removes *its* subscriptions — and only after the
/// `NOCResponse` has gone, since the command usually arrives on one of that fabric's sessions.
/// The subscription table is not a cluster, so a lifecycle broadcast to the clusters never
/// reached it; a node built any other way than the example kept the removed fabric's
/// subscriptions, to be inherited by the next fabric to take the index.
#[test]
fn removing_a_fabric_keeps_only_the_other_fabrics_subscriptions() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    let f2 = synthetic_fabric(&parts, 2);
    admin(&parts, f1, NODE_A);
    admin(&parts, f2, NODE_B);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut b = Controller::new(3, &mut rt, Some(f2), NODE_B);
    let mut dut = bind(&mut rt, &device);
    let path = [AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)];
    let (_, _) = subscribe_all(&mut dut, &mut a, &subscribe(&path, 0, 60), at(10));
    let (kept, _) = subscribe_all(&mut dut, &mut b, &subscribe(&path, 0, 60), at(20));
    assert_eq!(dut.rt().subscriptions().len(), 2, "both fabrics subscribed");

    let remove = fields(|w| w.unsigned(Tag::Context(0), u64::from(f1.0)).unwrap());
    let exchange = a.request(
        opcode::INVOKE_REQUEST,
        &invoke(0, opcreds::ID, opcreds::REMOVE_FABRIC, Some(&remove)),
        at(30),
    );
    pump(&mut dut, &mut [&mut a, &mut b], at(30));
    let reply = a.take();
    assert_eq!(
        reply.exchange, exchange,
        "the NOCResponse reached the remover"
    );
    assert_eq!(
        noc_status(&invoke_response(&reply.payload).unwrap()),
        NocStatus::Ok.value()
    );

    let ids: Vec<u32> = dut.rt().subscriptions().iter().map(|s| s.id).collect();
    assert_eq!(ids, vec![kept], "only fabric 2's subscription survives");
    assert!(
        dut.rt()
            .messaging()
            .sessions()
            .find(SessionId(0x1002))
            .is_none(),
        "the removed fabric's session is closed"
    );
    // And fabric 2 still hears about changes.
    b.inbox.clear();
    toggle_seen(&mut dut, &mut b, &mut [], at(40));
    dut.tick(at(100));
    pump(&mut dut, &mut [&mut b], at(100));
    assert!(
        b.inbox
            .iter()
            .any(|m| m.opcode == opcode::REPORT_DATA && report(&m.payload).2 == Some(kept)),
        "fabric 2 still hears about changes"
    );
}

/// §8.5: a subscription reports on a session. A session its peer closed takes the subscription.
#[test]
fn a_closed_session_takes_its_subscriptions() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut dut = bind(&mut rt, &device);
    let path = [AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)];
    subscribe_all(&mut dut, &mut a, &subscribe(&path, 0, 60), at(10));
    assert_eq!(dut.rt().subscriptions().len(), 1);

    // §4.11.1.4: CloseSession is a Secure Channel StatusReport.
    let report = matter_kit::sc::status::StatusReport {
        general: matter_kit::sc::status::GeneralCode::Success,
        protocol: ProtocolId::SECURE_CHANNEL,
        protocol_code: matter_kit::sc::status::SecureChannelCode::CloseSession as u16,
        data: &[],
    };
    let mut body = [0u8; 16];
    let n = report.encode(&mut body).unwrap();
    let exchange = a
        .stack
        .open(a.session, ProtocolId::SECURE_CHANNEL, at(20))
        .unwrap();
    a.send(
        exchange,
        matter_kit::sc::opcode::STATUS_REPORT,
        &body[..n],
        at(20),
    );
    pump(&mut dut, &mut [&mut a], at(20));
    assert_eq!(dut.rt().subscriptions().len(), 0);
    assert!(dut.notices().iter().any(|n| matches!(
        n,
        Notice::SessionClosed {
            subscriptions: 1,
            ..
        }
    )));
}

// --- US3: commissioning finishes itself ---------------------------------------------------------

/// §11.18.6.8's three follow-ups, and §9.10.9.1's event for the first of them: the CASE
/// administrator is granted on the new fabric (and nowhere else), the PASE session is bound to
/// it, the IPK is key set 0, and the grant is in the audit trail.
#[test]
fn add_noc_grants_exactly_the_case_admin_subject_and_records_it() {
    fixture!(device, rt, parts);
    let mut c = Controller::new(2, &mut rt, None, NodeId(0));
    let mut dut = bind(&mut rt, &device);
    let index = commission(&mut dut, &mut c, at(10));

    let acl = parts.acl.borrow();
    let entries: Vec<_> = acl.entries().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].fabric_index, index);
    assert_eq!(entries[0].privilege, Privilege::Administer);
    assert_eq!(
        entries[0].subjects.as_slice(),
        &[NodeId(CASE_ADMIN_SUBJECT)]
    );
    drop(acl);
    assert_eq!(
        dut.rt()
            .messaging()
            .sessions()
            .find(SessionId(0x1002))
            .unwrap()
            .fabric_index,
        index,
        "the PASE session is bound to the new fabric (step 10a)"
    );
    assert!(
        parts
            .group_keys
            .borrow()
            .key_set(index, matter_kit::group::IPK_KEY_SET)
            .is_some(),
        "the IPK is installed as group key set 0"
    );
    let events = parts.events.borrow();
    let recorded = events.buffer(EventPriority::Info).records();
    assert!(
        recorded.iter().any(|r| r.cluster == access_control::ID
            && r.event == access_control::ACCESS_CONTROL_ENTRY_CHANGED
            && r.fabric_index == Some(index)),
        "an AccessControlEntryChanged for the grant"
    );
}

/// §11.10.7.6 steps 3 and 4: on `CommissioningComplete`, PASE's temporary administrative
/// privilege is revoked and its session cleared — after the response, which arrives over CASE.
#[test]
fn commissioning_complete_closes_the_pase_session_after_replying() {
    fixture!(device, rt, parts);
    let mut pase = Controller::new(2, &mut rt, None, NodeId(0));
    let mut dut = bind(&mut rt, &device);
    let index = commission(&mut dut, &mut pase, at(10));
    let mut case = Controller::new(3, dut.rt(), Some(index), NodeId(CASE_ADMIN_SUBJECT));

    let exchange = case.request(
        opcode::INVOKE_REQUEST,
        &invoke(
            0,
            general_commissioning::ID,
            general_commissioning::COMMISSIONING_COMPLETE,
            Some(&fields(|_| {})),
        ),
        at(20),
    );
    pump(&mut dut, &mut [&mut pase, &mut case], at(20));
    let reply = case.take();
    assert_eq!(reply.exchange, exchange, "the response went out");
    assert!(invoke_response(&reply.payload).is_ok());
    let sessions = dut.rt().messaging().sessions();
    assert!(sessions.find(SessionId(0x1002)).is_none(), "PASE is gone");
    assert!(sessions.find(SessionId(0x1003)).is_some(), "CASE remains");
    assert!(dut.notices().contains(&Notice::Commissioned(index)));
}

/// §11.10.7.2.2's "Behavior on expiry of Fail-Safe timer": a commissioner that goes away after
/// `AddNOC` leaves nothing behind, without any further command arriving.
#[test]
fn a_lapsed_fail_safe_removes_the_added_fabric_without_another_command() {
    fixture!(device, rt, parts);
    let mut c = Controller::new(2, &mut rt, None, NodeId(0));
    let mut dut = bind(&mut rt, &device);
    let index = commission(&mut dut, &mut c, at(10));
    assert!(parts.fabrics.borrow().find(index).is_some());

    // ArmFailSafe(120) at 10 ms; nothing more arrives.
    dut.tick(at(121_000));
    assert!(
        parts.fabrics.borrow().find(index).is_none(),
        "the fabric AddNOC added is gone"
    );
    assert!(
        parts.acl.borrow().entries().next().is_none(),
        "with its administrator"
    );
    assert!(
        dut.rt()
            .messaging()
            .sessions()
            .find(SessionId(0x1002))
            .is_none(),
        "and the PASE session (steps 2 and 3)"
    );
    let notices = dut.notices();
    assert!(notices.contains(&Notice::RolledBack));
    assert!(notices.contains(&Notice::FabricRemoved(index)));
}

/// §5.5: a window opening re-admits PASE, which is how a commissioned node joins a second fabric.
#[test]
fn opening_a_window_admits_pase_again() {
    fixture!(device, rt, parts);
    let mut dut = bind(&mut rt, &device);
    parts
        .window
        .borrow_mut()
        .install(matter_kit::commissioning::window::OpenWindow {
            status: matter_kit::commissioning::window::WindowStatus::BasicOpen,
            expires_at: at(180_000),
            admin_fabric: None,
            admin_vendor: None,
            discriminator: 3840,
            ephemeral: None,
        });
    dut.tick(at(10));
    assert!(dut.notices().contains(&Notice::WindowOpened));
    let _ = parts.fail_safe;
}

// --- The commissioning flow ---------------------------------------------------------------------

const RCAC: &[u8] = &hex!(
    "1530010859eaa632947f541c2402013703271401000000cacacaca182604ef171b27"
    "26056eb5b94c3706271401000000cacacaca1824070124080130094104"
    "1353a3b3ef1da708c4908048014e407d5990ce22bc4eb33e9a5acb25a85603eba6"
    "dcd8213666a4e44f5aca13eb767fafa7dcdddc33411f82a30b543dd1d24ba8"
    "370a350129011824026030041413af81ab37374b2ed2a9649b12b7a3a4287e151d"
    "30051413af81ab37374b2ed2a9649b12b7a3a4287e151d18300b40"
    "458164466c8f195abc0abb7c6cb5a27a83f41d37f8d53beec520abd2a0da0509"
    "b8a7c25c042e30cf64dc30fe334e120019664e515049134f5781238444fc753118"
);
const ICAC: &[u8] = &hex!(
    "153001082db444855641aedf2402013703271401000000cacacaca182604ef171b27"
    "26056eb5b94c3706271303000000cacacaca1824070124080130094104"
    "c5d0861bb8f90c405c12314e4c5ebeea939f72774bcc33239e2f59f6f46af8dc7d"
    "4682a0e3ccc646e6df29ea86bf562ae720a898337d383f32c0a09e416019ea"
    "370a35012901182402603004145352d7059e9c15a508906862864801a29f1f41d3"
    "30051413af81ab37374b2ed2a9649b12b7a3a4287e151d18300b40"
    "841a06d43b5e9fecd24e87b1244eb51c6a2cf20d9b5e6ba07f11e6002f7e0ca34e"
    "32a602c3609d0092d348bdbd198a114646bd41cf103783641ae25e3f23fd2618"
);
const ICAC_PRIVATE_KEY: [u8; GROUP_SIZE_BYTES] =
    hex!("11843bdcf0ad206db10251a54dac581d75f992fcb522752a216cd79c717546a9");
const FABRIC_ID: FabricId = FabricId(0xFAB0_0000_0000_001D);
const DEVICE_NODE_ID: NodeId = NodeId(0xDEDE_DEDE_0001_0001);
const CASE_ADMIN_SUBJECT: u64 = 0xDEDE_DEDE_0001_00AA;
const IPK_EPOCH: [u8; 16] = hex!("4a71cdd7b2a3ca9024f96f3c96a19dee");

fn issue_noc(node_id: NodeId, public_key: PublicKey, out: &mut [u8]) -> usize {
    let mut ca = Store::new();
    let ca_handle = ca
        .import(KeyPurpose::Operational, &ICAC_PRIVATE_KEY)
        .unwrap();
    let icac = MatterCertificate::decode(ICAC).unwrap();
    let mut subject = DistinguishedName::new();
    subject.push(DnAttribute::node_id(node_id)).unwrap();
    subject.push(DnAttribute::fabric_id(FABRIC_ID)).unwrap();
    let digest = matter_kit::crypto::hash(public_key.as_bytes());
    let mut skid = [0u8; 20];
    skid.copy_from_slice(&digest[..20]);
    let mut extensions = Extensions::new();
    extensions
        .push(Extension::BasicConstraints(BasicConstraints {
            is_ca: false,
            path_len_constraint: None,
        }))
        .unwrap();
    extensions
        .push(Extension::KeyUsage(KeyUsage::DIGITAL_SIGNATURE))
        .unwrap();
    let mut purposes = heapless::Vec::<KeyPurposeId, 6>::new();
    purposes.push(KeyPurposeId::ServerAuth).unwrap();
    purposes.push(KeyPurposeId::ClientAuth).unwrap();
    extensions
        .push(Extension::ExtendedKeyUsage(purposes))
        .unwrap();
    extensions.push(Extension::SubjectKeyId(skid)).unwrap();
    extensions
        .push(Extension::AuthorityKeyId(
            icac.extensions.subject_key_id().unwrap(),
        ))
        .unwrap();
    let mut cert = MatterCertificate {
        serial_number: &[0x01, 0x02, 0x03, 0x04],
        signature_algorithm: SignatureAlgorithm::EcdsaWithSha256,
        issuer: icac.subject.clone(),
        not_before: icac.not_before,
        not_after: icac.not_after,
        subject,
        public_key_algorithm: PublicKeyAlgorithm::EcPubKey,
        elliptic_curve_id: EllipticCurveId::Prime256V1,
        public_key,
        extensions,
        signature: matter_kit::crypto::Signature::from_bytes([0; 64]),
    };
    let mut der_buf = [0u8; CERT_DER_MAX];
    let tbs = der::tbs_certificate(&cert, &mut der_buf).unwrap();
    cert.signature = ca.sign(ca_handle, tbs).unwrap();
    cert.encode(out).unwrap().len()
}

fn fields(build: impl FnOnce(&mut TlvWriter<'_>)) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    build(&mut w);
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn arm_fail_safe(seconds: u16) -> Vec<u8> {
    fields(|w| {
        w.unsigned(Tag::Context(0), u64::from(seconds)).unwrap();
        w.unsigned(Tag::Context(1), 1).unwrap();
    })
}

/// The octet string under `tag` in a response's fields.
fn octets(bytes: &[u8], tag: u8) -> Vec<u8> {
    let mut reader = TlvReader::new_in(bytes, ContainerKind::Structure);
    reader.next_element().unwrap().unwrap();
    let depth = reader.depth();
    while let Some(element) = reader.next_element().unwrap() {
        if reader.depth() < depth {
            break;
        }
        if element.tag == Tag::Context(tag) {
            return element.octets().unwrap().to_vec();
        }
        reader.skip_value(&element).unwrap();
    }
    panic!("no field {tag}");
}

fn noc_status(fields: &[u8]) -> u8 {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    reader.next_element().unwrap().unwrap();
    let status = reader.next_element().unwrap().unwrap();
    status.unsigned().unwrap() as u8
}

/// Invokes on endpoint 0 and returns the response.
fn call(
    dut: &mut impl Drive,
    c: &mut Controller,
    cluster: u32,
    command: u32,
    f: &[u8],
    now: Instant,
) -> Result<Vec<u8>, Status> {
    let e = c.request(
        opcode::INVOKE_REQUEST,
        &invoke(0, cluster, command, Some(f)),
        now,
    );
    pump(dut, &mut [c], now);
    let msg = c.take();
    assert_eq!(msg.exchange, e);
    c.ack(e, now);
    pump(dut, &mut [c], now);
    c.stack.close(e);
    invoke_response(&msg.payload)
}

fn csr(dut: &mut impl Drive, c: &mut Controller, now: Instant) -> PublicKey {
    let response = call(
        dut,
        c,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &fields(|w| w.octets(Tag::Context(0), &[0x11; 32]).unwrap()),
        now,
    )
    .expect("csr");
    let elements = octets(&response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(&elements).unwrap();
    nocsr.parse_csr().unwrap().public_key
}

fn add_root(dut: &mut impl Drive, c: &mut Controller, now: Instant) {
    let outcome = call(
        dut,
        c,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &fields(|w| w.octets(Tag::Context(0), RCAC).unwrap()),
        now,
    );
    assert_eq!(outcome, Err(Status::Success));
}

fn add_noc(dut: &mut impl Drive, c: &mut Controller, noc: &[u8], now: Instant) -> u8 {
    let f = fields(|w| {
        w.octets(Tag::Context(0), noc).unwrap();
        w.octets(Tag::Context(1), ICAC).unwrap();
        w.octets(Tag::Context(2), &IPK_EPOCH).unwrap();
        w.unsigned(Tag::Context(3), CASE_ADMIN_SUBJECT).unwrap();
        w.unsigned(Tag::Context(4), 0xFFF1).unwrap();
    });
    noc_status(&call(dut, c, opcreds::ID, opcreds::ADD_NOC, &f, now).expect("add noc"))
}

/// ArmFailSafe(120), CSRRequest, AddTrustedRootCertificate, AddNOC — over `c`'s PASE session.
fn commission(dut: &mut impl Drive, c: &mut Controller, now: Instant) -> FabricIndex {
    assert!(
        call(
            dut,
            c,
            general_commissioning::ID,
            general_commissioning::ARM_FAIL_SAFE,
            &arm_fail_safe(120),
            now
        )
        .is_ok()
    );
    let public = csr(dut, c, now);
    add_root(dut, c, now);
    let mut noc = [0u8; CERT_TLV_MAX];
    let n = issue_noc(DEVICE_NODE_ID, public, &mut noc);
    assert_eq!(add_noc(dut, c, &noc[..n], now), NocStatus::Ok.value());
    let added = dut.notices().into_iter().find_map(|n| match n {
        Notice::FabricAdded(index) => Some(index),
        _ => None,
    });
    added.expect("a FabricAdded notice")
}

// --- Over the simulated network, through the driver --------------------------------------------

use core::future::{Future, poll_fn};
use core::pin::pin;
use core::task::Poll;
use matter_kit::discovery::advertiser::{Advertiser, Identity};
use matter_kit::messaging::Due;
use matter_kit::node::Mdns;
use matter_kit::platform::sim::{Impairment, SimNet, SimNode, block_on};
use matter_kit::platform::{Timer, Udp};

/// Runs `background` (which never finishes) until `test` does.
async fn race<B: Future, T: Future>(background: B, test: T) -> T::Output {
    let mut background = pin!(background);
    let mut test = pin!(test);
    poll_fn(|cx| {
        if let Poll::Ready(v) = test.as_mut().poll(cx) {
            return Poll::Ready(v);
        }
        let _ = background.as_mut().poll(cx);
        Poll::Pending
    })
    .await
}

/// A controller on the simulated network that does its own MRP: it keeps what it sent and
/// resends it when its stack says so, and acknowledges what it receives.
struct SimController<'n> {
    c: Controller,
    socket: SimNode<'n>,
    device: PeerAddr,
    sent: Vec<(ExchangeKey, Vec<u8>)>,
}

impl<'n> SimController<'n> {
    async fn flush(&mut self) {
        for datagram in self.c.outbox.drain(..) {
            let _ = self.socket.send_to(&datagram, self.device).await;
        }
    }

    fn send(&mut self, exchange: ExchangeKey, op: u8, payload: &[u8], now: Instant) {
        self.c.send(exchange, op, payload, now);
        let last = self.c.outbox.last().unwrap().clone();
        self.sent.retain(|(e, _)| *e != exchange);
        self.sent.push((exchange, last));
    }

    /// The next message on `exchange`, driving MRP until it arrives.
    async fn next(&mut self, net: &SimNet, exchange: ExchangeKey) -> Msg {
        let mut buf = [0u8; 1280];
        for spin in 0.. {
            assert!(
                spin < 100_000,
                "controller spun: now {:?} wake {:?}",
                net.now(),
                self.c.stack.wake_at()
            );
            self.flush().await;
            if let Some(i) = self.c.inbox.iter().position(|m| m.exchange == exchange) {
                return self.c.inbox.remove(i);
            }
            let wake = self
                .c
                .stack
                .wake_at()
                .unwrap_or_else(|| net.now().saturating_add(Duration::from_millis(200)));
            let got = {
                let mut recv = pin!(self.socket.recv_from(&mut buf));
                let mut sleep = pin!(net.sleep_until(wake));
                poll_fn(|cx| {
                    if let Poll::Ready(Ok((n, _))) = recv.as_mut().poll(cx) {
                        return Poll::Ready(Some(n));
                    }
                    if sleep.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(None);
                    }
                    Poll::Pending
                })
                .await
            };
            let now = net.now();
            if let Some(n) = got {
                self.c.deliver(&buf[..n], now);
            }
            while let Some(due) = self.c.stack.poll(now, 0) {
                match due {
                    Due::Retransmit { exchange, .. } => {
                        if let Some((_, bytes)) = self.sent.iter().find(|(e, _)| *e == exchange) {
                            self.c.outbox.push(bytes.clone());
                        }
                    }
                    Due::Acknowledge { exchange } => self.c.ack(exchange, now),
                    Due::Abandoned { .. } => panic!("the controller gave up on the device"),
                }
            }
        }
        unreachable!()
    }

    /// A whole read, acknowledging every chunk.
    async fn read(&mut self, net: &SimNet, request: &[u8]) -> Vec<AttributePath> {
        let now = net.now();
        let exchange = self.c.open(now);
        self.send(exchange, opcode::READ_REQUEST, request, now);
        let mut all = Vec::new();
        loop {
            let msg = self.next(net, exchange).await;
            let (paths, more, _) = report(&msg.payload);
            all.extend(paths);
            let now = net.now();
            if !more {
                self.c.ack(exchange, now);
                self.flush().await;
                self.sent.retain(|(e, _)| *e != exchange);
                return all;
            }
            let mut buf = [0u8; 16];
            let ok = StatusResponse::new(Status::Success)
                .encode(&mut buf)
                .unwrap()
                .to_vec();
            self.send(exchange, opcode::STATUS_RESPONSE, &ok, now);
        }
    }
}

/// SC-004: two controllers reading the whole node at once over a link that loses and duplicates
/// datagrams, fifty seeds. Every series must arrive whole and be the reader's own: the device's
/// retransmissions are the runtime's (§4.12.2.1), and chunks must never cross between exchanges.
#[test]
fn fifty_seeded_runs_with_loss_and_duplication_keep_every_series_whole_and_separate() {
    for seed in 0..50u64 {
        fixture!(device, rt, parts);
        let f1 = synthetic_fabric(&parts, 1);
        let f2 = synthetic_fabric(&parts, 2);
        admin(&parts, f1, NODE_A);
        admin(&parts, f2, NODE_B);
        let net = SimNet::new(seed);
        let matter = net.node(1);
        let mdns = net.node(9);
        let mut a = SimController {
            c: Controller::new(2, &mut rt, Some(f1), NODE_A),
            socket: net.node(2),
            device: matter.addr(),
            sent: Vec::new(),
        };
        let mut b = SimController {
            c: Controller::new(3, &mut rt, Some(f2), NODE_B),
            socket: net.node(3),
            device: matter.addr(),
            sent: Vec::new(),
        };
        let mut advertiser = Advertiser::<5, 6>::new(IDENTITY, &net).unwrap();
        let wildcard = read(&[AttributePath::wildcard()], false);

        // The baseline, on a perfect link.
        let (alone, (got_a, got_b)) = block_on(&net, async {
            let device_loop = rt.run(
                &device,
                &matter,
                Mdns {
                    socket: &mdns,
                    group: mdns.addr(),
                    interface: 0,
                },
                &mut advertiser,
                &net,
                |_| {},
            );
            race(device_loop, async {
                let alone = a.read(&net, &wildcard).await;
                net.impair(Impairment {
                    loss_percent: 10,
                    duplicate_percent: 10,
                    ..Impairment::default()
                });
                let both = join(a.read(&net, &wildcard), b.read(&net, &wildcard)).await;
                (alone, both)
            })
            .await
        });
        assert!(alone.len() > 24, "seed {seed}: the read chunks");
        assert_eq!(got_a, alone, "seed {seed}: A's series is whole and its own");
        assert_eq!(got_b.len(), alone.len(), "seed {seed}: B's series is whole");
    }
}

/// Both futures to completion.
async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let mut a = pin!(a);
    let mut b = pin!(b);
    let (mut ra, mut rb) = (None, None);
    poll_fn(|cx| {
        if ra.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            ra = Some(v);
        }
        if rb.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            rb = Some(v);
        }
        if ra.is_some() && rb.is_some() {
            Poll::Ready((ra.take().unwrap(), rb.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

const IDENTITY: Identity = Identity {
    discriminator: 3840,
    vendor_id: VendorId(0xFFF1),
    product_id: 0x8000,
    port: 5540,
};

/// The driver does its time-driven work on every iteration, whichever source woke it: a socket
/// that is never quiet must not starve a subscription's keep-alive.
#[test]
fn a_busy_socket_does_not_starve_reports() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    let net = SimNet::new(1);
    let matter = net.node(1);
    let mdns = net.node(9);
    let flooder = net.node(8);
    let mut a = SimController {
        c: Controller::new(2, &mut rt, Some(f1), NODE_A),
        socket: net.node(2),
        device: matter.addr(),
        sent: Vec::new(),
    };
    let mut advertiser = Advertiser::<5, 6>::new(IDENTITY, &net).unwrap();
    let path = [AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)];
    let reports = block_on(&net, async {
        let device_loop = rt.run(
            &device,
            &matter,
            Mdns {
                socket: &mdns,
                group: mdns.addr(),
                interface: 0,
            },
            &mut advertiser,
            &net,
            |_| {},
        );
        // Garbage at the mDNS socket every millisecond, for ever.
        let flood = async {
            loop {
                let _ = flooder.send_to(&[0xFF; 12], mdns.addr()).await;
                net.sleep(Duration::from_millis(1)).await;
            }
        };
        let background = join(device_loop, flood);
        race(background, async {
            let now = net.now();
            let exchange = a.c.open(now);
            a.send(
                exchange,
                opcode::SUBSCRIBE_REQUEST,
                &subscribe(&path, 0, 2),
                now,
            );
            let mut reports = 0;
            let start = net.now();
            while net.now().saturating_duration_since(start) < Duration::from_secs(10) {
                let msg = a.next(&net, exchange).await;
                if msg.opcode == opcode::SUBSCRIBE_RESPONSE {
                    a.c.ack(exchange, net.now());
                    break;
                }
                let mut buf = [0u8; 16];
                let ok = StatusResponse::new(Status::Success)
                    .encode(&mut buf)
                    .unwrap()
                    .to_vec();
                a.send(exchange, opcode::STATUS_RESPONSE, &ok, net.now());
            }
            // Keep-alives arrive on exchanges the device opens.
            let deadline = net.now().saturating_add(Duration::from_secs(10));
            while net.now() < deadline {
                let mut buf = [0u8; 1280];
                let n = {
                    let mut recv = pin!(a.socket.recv_from(&mut buf));
                    let mut sleep = pin!(net.sleep_until(deadline));
                    poll_fn(|cx| {
                        if let Poll::Ready(Ok((n, _))) = recv.as_mut().poll(cx) {
                            return Poll::Ready(Some(n));
                        }
                        if sleep.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(None);
                        }
                        Poll::Pending
                    })
                    .await
                };
                let Some(n) = n else { break };
                a.c.deliver(&buf[..n], net.now());
                while let Some(msg) = a.c.inbox.pop() {
                    if msg.opcode == opcode::REPORT_DATA {
                        reports += 1;
                        let ok = {
                            let mut buf = [0u8; 16];
                            StatusResponse::new(Status::Success)
                                .encode(&mut buf)
                                .unwrap()
                                .to_vec()
                        };
                        a.send(msg.exchange, opcode::STATUS_RESPONSE, &ok, net.now());
                    }
                }
                a.flush().await;
            }
            reports
        })
        .await
    });
    // MaxInterval 2 s over 10 s: four keep-alives at least, however busy the other socket is.
    assert!(reports >= 4, "{reports} reports in ten seconds");
}

/// A deadline in the past is one a loop wakes for again and again at the same instant; in
/// virtual time that is a hang, on a real clock a busy loop.
#[test]
fn an_idle_device_has_no_deadline_in_the_past() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut dut = bind(&mut rt, &device);
    let wildcard = read(&[AttributePath::wildcard()], false);
    read_all(&mut dut, &mut a, &wildcard, at(10));
    for t in [10, 20, 1_000, 70_000] {
        dut.tick(at(t));
        let d = rt_deadline(&mut dut, &device);
        assert!(d.is_none_or(|d| d > at(t)), "deadline {d:?} at {t} ms");
    }
}

fn rt_deadline<K, G, H, Ac, Gk, Ev, V, const F: usize>(
    dut: &mut Dut<'_, '_, Device<'_, DefaultConfig, K, G, H, Ac, Gk, Ev, V, F>>,
    device: &Device<'_, DefaultConfig, K, G, H, Ac, Gk, Ev, V, F>,
) -> Option<Instant>
where
    K: KeyStore,
    G: Rng,
    H: ClusterHandler,
    Ac: AccessList,
    Gk: GroupKeyStore,
    Ev: EventLog,
    V: ChangeLog,
{
    dut.rt.next_deadline(device)
}

/// §8.7.2.3 and §1.3.7.1.2: a groupcast is acted on and never answered — one multicast to twenty
/// lights that each replied would put twenty responses on the link at once.
#[test]
fn a_groupcast_is_acted_on_and_never_answered() {
    use matter_kit::acl::{AuthMode, Entry};
    use matter_kit::group::keys::{EpochKey, GroupKeySecurityPolicy, GroupKeySet};
    use matter_kit::group::wire::Sender;
    use matter_kit::msg::{ExchangeId, GroupId, ProtocolHeader};

    const LIGHTS: GroupId = GroupId(0x0001);
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    let compressed = parts.fabrics.borrow().find(f1).unwrap().compressed;
    let mut epoch_keys = heapless::Vec::new();
    epoch_keys
        .push(EpochKey {
            key: SymmetricKey::new([0x23; 16]),
            start_time_us: 1,
        })
        .unwrap();
    {
        let mut keys = parts.group_keys.borrow_mut();
        keys.write_key_set(GroupKeySet {
            fabric_index: f1,
            id: 7,
            policy: GroupKeySecurityPolicy::TrustFirst,
            epoch_keys,
        })
        .unwrap();
        keys.map_group(f1, LIGHTS, 7).unwrap();
    }
    let mut subjects = heapless::Vec::new();
    subjects.push(NodeId(u64::from(LIGHTS.0))).unwrap();
    parts
        .acl
        .borrow_mut()
        .add(Entry {
            fabric_index: f1,
            privilege: Privilege::Operate,
            auth_mode: AuthMode::Group,
            subjects,
            targets: heapless::Vec::new(),
        })
        .unwrap();

    let key = parts
        .group_keys
        .borrow()
        .sending_key(f1, compressed, LIGHTS, None)
        .expect("a key for the group");
    let header = ProtocolHeader {
        initiator: true,
        acknowledged_counter: None,
        reliability: false,
        exchange_id: ExchangeId(0x1234),
        protocol: ProtocolId::INTERACTION_MODEL,
        opcode: opcode::INVOKE_REQUEST,
    };
    let body = invoke(1, on_off::ID, on_off::TOGGLE, None);
    let (mut scratch, mut datagram) = ([0u8; 1280], [0u8; 1280]);
    let n = Sender::new(NodeId(0xAAAA), 1, 1)
        .send(
            &key,
            LIGHTS,
            &header,
            &body,
            false,
            &mut scratch,
            &mut datagram,
        )
        .expect("send");

    let mut dut = bind(&mut rt, &device);
    let from = PeerAddr::new([0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xAA]);
    dut.rx(&mut datagram[..n], from, at(10));
    assert!(
        dut.notices().contains(&Notice::Groupcast(LIGHTS)),
        "acted on"
    );
    assert!(dut.tx().is_none(), "and answered with silence");
}

/// The runtime's RAM, with the defaults. Almost all of it is datagram buffers — the interaction
/// table's retained requests, the outbox, the retransmission store and four work buffers — and
/// `I`, `R` and `Q` are what a small device lowers. The bound is the figure the documentation
/// states; this fails when the type grows past it.
#[test]
fn the_runtime_fits_its_documented_size() {
    let size = core::mem::size_of::<Rt>();
    eprintln!("Runtime<DefaultConfig> = {size} bytes");
    assert!(size <= 64 * 1024, "{size} bytes");
}

// --- Real PASE through the runtime ---------------------------------------------------------------

impl Controller {
    /// A controller with no session at all, for a real handshake.
    fn bare(index: u8) -> Self {
        Self {
            stack: Messaging::new(
                0x3000 + u16::from(index) * 16,
                0x400,
                0x0100_0000 * u32::from(index),
            ),
            addr: PeerAddr::new([0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, index]),
            session: SessionId(0x2000 + u16::from(index)),
            inbox: Vec::new(),
            outbox: Vec::new(),
            deaf: false,
        }
    }
}

/// Runs PASE from `c` against the runtime. `Ok` once the device has said `PakeFinished`; `Err`
/// with the device's answer if it refused the first message.
fn pase(
    dut: &mut impl Drive,
    c: &mut Controller,
    others: &mut [&mut Controller],
    now: Instant,
) -> Result<(), Msg> {
    use matter_kit::sc::{PaseInitiator, opcode as sc};
    let mut initiator = PaseInitiator::new(20_202_021, c.session, None, None);
    let mut payload = [0u8; 1024];
    let exchange = c
        .stack
        .open_unsecured(
            ProtocolId::SECURE_CHANNEL,
            now,
            0xE0E0_1234_5678_9A00 | u64::from(c.addr.addr[15]),
        )
        .unwrap();
    let n = initiator.start(&[0x11; 32], &mut payload).unwrap();
    c.send(exchange, sc::PBKDF_PARAM_REQUEST, &payload[..n], now);
    {
        let mut all: Vec<&mut Controller> = vec![&mut *c];
        all.extend(others.iter_mut().map(|o| &mut **o));
        pump(dut, &mut all, now);
    }
    let reply = c.take();
    if reply.opcode != sc::PBKDF_PARAM_RESPONSE {
        return Err(reply);
    }
    let n = initiator
        .on_pbkdf_param_response(&reply.payload, &[0x33; 32], &mut payload)
        .unwrap();
    c.send(exchange, sc::PAKE1, &payload[..n], now);
    {
        let mut all: Vec<&mut Controller> = vec![&mut *c];
        all.extend(others.iter_mut().map(|o| &mut **o));
        pump(dut, &mut all, now);
    }
    let pake2 = c.take();
    assert_eq!(pake2.opcode, sc::PAKE2);
    let n = initiator.on_pake2(&pake2.payload, &mut payload).unwrap();
    c.send(exchange, sc::PAKE3, &payload[..n], now);
    {
        let mut all: Vec<&mut Controller> = vec![&mut *c];
        all.extend(others.iter_mut().map(|o| &mut **o));
        pump(dut, &mut all, now);
    }
    let finished = c.take();
    assert_eq!(finished.opcode, sc::STATUS_REPORT);
    initiator
        .on_pake_finished(&finished.payload)
        .expect("the passcode matched");
    c.ack(exchange, now);
    {
        let mut all: Vec<&mut Controller> = vec![&mut *c];
        all.extend(others.iter_mut().map(|o| &mut **o));
        pump(dut, &mut all, now);
    }
    c.stack.close(exchange);
    c.stack.close_unsecured();
    Ok(())
}

/// §4.11.1.1: a full session table evicts the least recently used session to make room, the
/// evicted peer is owed a `CloseSession`, and everything above the messaging layer that was keyed
/// on that session goes with it.
#[test]
fn an_evicted_session_takes_its_subscriptions_and_its_peer_is_told() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    // Fill the rest of the sixteen-session table with sessions used more recently than A's.
    for i in 0..15u16 {
        let mut s = SecureSession::new(
            SessionId(0x4000 + i),
            SessionId(0x5000 + i),
            SessionKind::Case,
            session::Role::Responder,
            keys(0x60),
            1,
            at(50),
        );
        s.fabric_index = f1;
        rt.messaging_mut().sessions_mut().insert(s).unwrap();
    }
    let mut commissioner = Controller::bare(4);
    let mut dut = bind(&mut rt, &device);
    let path = [AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)];
    subscribe_all(&mut dut, &mut a, &subscribe(&path, 0, 60), at(10));
    // A's session is now the least recently used; a new PASE session evicts it.
    pase(&mut dut, &mut commissioner, &mut [&mut a], at(100)).expect("PASE");
    assert_eq!(
        dut.rt().subscriptions().len(),
        0,
        "A's subscription went with its session"
    );
    assert!(
        dut.rt()
            .messaging()
            .sessions()
            .find(SessionId(0x1002))
            .is_none()
    );
    assert!(
        a.stack.sessions().find(a.session).is_none(),
        "A was sent its CloseSession, and closed its end"
    );
    assert!(
        dut.notices()
            .iter()
            .any(|n| matches!(n, Notice::Evicted { .. }))
    );
}

/// §5.5 rule 1 and §11.10.7.2.2: while a commissioning is in progress a second commissioner is
/// `Busy`, even with a window open; once the fail-safe is disarmed the rollback closes the PASE
/// session and the channel admits the next one.
#[test]
fn an_armed_fail_safe_keeps_pase_closed_to_a_second_commissioner() {
    fixture!(device, rt, parts);
    let mut first = Controller::bare(2);
    let mut second = Controller::bare(3);
    let mut third = Controller::bare(5);
    let mut dut = bind(&mut rt, &device);
    pase(&mut dut, &mut first, &mut [], at(10)).expect("the first commissioner is admitted");
    // Its session, as the device installed it, for the commissioning commands.
    let device_session = dut
        .rt()
        .messaging()
        .sessions()
        .iter()
        .find(|s| s.kind == SessionKind::Pase)
        .map(|s| (s.local_session_id, s.peer_session_id))
        .unwrap();
    let _ = device_session;
    let _ = parts
        .fail_safe
        .borrow_mut()
        .arm(120, 0, None, at(20), false);
    parts
        .window
        .borrow_mut()
        .install(matter_kit::commissioning::window::OpenWindow {
            status: matter_kit::commissioning::window::WindowStatus::BasicOpen,
            expires_at: at(180_000),
            admin_fabric: None,
            admin_vendor: None,
            discriminator: 3840,
            ephemeral: None,
        });
    dut.tick(at(30));
    let busy = pase(&mut dut, &mut second, &mut [], at(40)).expect_err("Busy while commissioning");
    assert_eq!(busy.opcode, matter_kit::sc::opcode::STATUS_REPORT);
    assert!(!dut.notices().contains(&Notice::ChannelReleased));
    // The commissioning ends: the fail-safe expires and its rollback closes the PASE session.
    dut.tick(at(121_000));
    assert!(dut.notices().contains(&Notice::RolledBack));
    pase(&mut dut, &mut third, &mut [], at(122_000))
        .expect("admitted once the first commissioning ended");
}

/// §11.10.7.2.2 through `ArmFailSafe(0)`: the reply goes out on the very session the cleanup
/// closes, and then the added fabric and the PASE session are gone.
#[test]
fn disarming_the_fail_safe_after_add_noc_rolls_back_after_replying() {
    fixture!(device, rt, parts);
    let mut c = Controller::new(2, &mut rt, None, NodeId(0));
    let mut dut = bind(&mut rt, &device);
    let index = commission(&mut dut, &mut c, at(10));
    let e = c.request(
        opcode::INVOKE_REQUEST,
        &invoke(
            0,
            general_commissioning::ID,
            general_commissioning::ARM_FAIL_SAFE,
            Some(&arm_fail_safe(0)),
        ),
        at(20),
    );
    pump(&mut dut, &mut [&mut c], at(20));
    let reply = c.take();
    assert_eq!(reply.exchange, e, "ArmFailSafe(0) was answered");
    assert!(invoke_response(&reply.payload).is_ok());
    assert!(parts.fabrics.borrow().find(index).is_none());
    assert!(
        dut.rt()
            .messaging()
            .sessions()
            .find(SessionId(0x1002))
            .is_none()
    );
}

/// §6.6.6.3: a subject is what the session proved. A subscriber whose fabric grants View on
/// endpoint 1 only gets endpoint 1, in the priming report and in every report after it, however
/// much another fabric's administrator may see.
#[test]
fn a_report_is_filtered_as_the_subscriber_that_created_it() {
    use matter_kit::acl::{AuthMode, Entry, Target};
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    let f2 = synthetic_fabric(&parts, 2);
    admin(&parts, f1, NODE_A);
    let mut subjects = heapless::Vec::new();
    subjects.push(NODE_B).unwrap();
    let mut targets = heapless::Vec::new();
    targets
        .push(Target {
            endpoint: Some(1),
            ..Target::default()
        })
        .unwrap();
    parts
        .acl
        .borrow_mut()
        .add(Entry {
            fabric_index: f2,
            privilege: Privilege::View,
            auth_mode: AuthMode::Case,
            subjects,
            targets,
        })
        .unwrap();
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut b = Controller::new(3, &mut rt, Some(f2), NODE_B);
    let mut dut = bind(&mut rt, &device);
    // B, reading a concrete endpoint-0 attribute, is refused.
    let refused = read_all(
        &mut dut,
        &mut b,
        &read(
            &[AttributePath::attribute(
                0,
                access_control::ID,
                access_control::ACL,
            )],
            false,
        ),
        at(10),
    );
    assert_eq!(refused.len(), 1, "one status for the concrete path");
    let (id, primed) = subscribe_all(
        &mut dut,
        &mut b,
        &subscribe(&[AttributePath::wildcard()], 0, 60),
        at(20),
    );
    assert!(!primed.is_empty());
    assert!(
        primed.iter().all(|p| p.endpoint == Some(1)),
        "only endpoint 1 is primed"
    );
    toggle_seen(&mut dut, &mut a, &mut [&mut b], at(30));
    dut.tick(at(100));
    pump(&mut dut, &mut [&mut b], at(100));
    let reports: Vec<_> = b
        .inbox
        .iter()
        .filter(|m| m.opcode == opcode::REPORT_DATA && report(&m.payload).2 == Some(id))
        .collect();
    assert!(!reports.is_empty(), "B hears about the change");
    for r in reports {
        assert!(report(&r.payload).0.iter().all(|p| p.endpoint == Some(1)));
    }
}

/// §9.10.9.1: recording the event is half of it; a subscriber to `AccessControlEntryChanged`
/// must hear about the change, at its minimum interval rather than its maximum.
#[test]
fn an_event_subscriber_hears_about_an_acl_change() {
    fixture!(device, rt, parts);
    let f1 = synthetic_fabric(&parts, 1);
    admin(&parts, f1, NODE_A);
    let mut a = Controller::new(2, &mut rt, Some(f1), NODE_A);
    let mut dut = bind(&mut rt, &device);
    // §8.5.3: an urgent event is reported "as soon as possible"; a non-urgent one rides the next
    // report.
    let event = matter_kit::im::EventPath {
        is_urgent: Some(true),
        ..matter_kit::im::EventPath::event(
            0,
            access_control::ID,
            access_control::ACCESS_CONTROL_ENTRY_CHANGED,
        )
    };
    let mut buf = [0u8; 512];
    let request = im::encode_subscribe_request(&mut buf, [], [event], 0, 60, true, false)
        .unwrap()
        .to_vec();
    let (id, _) = subscribe_all(&mut dut, &mut a, &request, at(10));

    // Append a View entry for B.
    let mut value = [0u8; 256];
    let mut w = TlvWriter::new_in(&mut value, ContainerKind::Structure);
    w.start_structure(Tag::Context(2)).unwrap();
    w.unsigned(Tag::Context(1), 1).unwrap(); // View
    w.unsigned(Tag::Context(2), 2).unwrap(); // CASE
    w.start_array(Tag::Context(3)).unwrap();
    w.unsigned(Tag::Anonymous, NODE_B.0).unwrap();
    w.end_container().unwrap();
    w.null(Tag::Context(4)).unwrap();
    w.end_container().unwrap();
    let value = w.finish().unwrap().to_vec();
    let path = AttributePath {
        list_index: Some(matter_kit::im::ListIndex::Append),
        ..AttributePath::attribute(0, access_control::ID, access_control::ACL)
    };
    let mut wbuf = [0u8; 512];
    let write = im::encode_write_request(
        &mut wbuf,
        [matter_kit::im::AttributeData {
            data_version: None,
            path,
            data: &value,
        }],
        false,
        false,
    )
    .unwrap()
    .to_vec();
    let e = a.request(opcode::WRITE_REQUEST, &write, at(20));
    pump(&mut dut, &mut [&mut a], at(20));
    assert!(
        a.inbox
            .iter()
            .any(|m| m.exchange == e && m.opcode == opcode::WRITE_RESPONSE)
    );
    dut.tick(at(30));
    pump(&mut dut, &mut [&mut a], at(30));
    let heard = a.inbox.iter().any(|m| {
        m.opcode == opcode::REPORT_DATA
            && ReportData::decode(&m.payload).is_ok_and(|r| {
                r.subscription_id == Some(id)
                    && r.event_reports()
                        .unwrap()
                        .is_some_and(|mut e| e.next().is_some())
            })
    });
    assert!(heard, "the event subscriber hears the change at once");
}

/// The fail-safe's own timer, with a subscription on the fabric it rolls back.
#[test]
fn a_lapsed_fail_safe_takes_the_added_fabrics_subscriptions() {
    fixture!(device, rt, parts);
    let mut c = Controller::new(2, &mut rt, None, NodeId(0));
    let mut dut = bind(&mut rt, &device);
    commission(&mut dut, &mut c, at(10));
    let path = [AttributePath::attribute(1, on_off::ID, on_off::ON_OFF)];
    subscribe_all(&mut dut, &mut c, &subscribe(&path, 0, 60), at(20));
    assert_eq!(dut.rt().subscriptions().len(), 1);
    dut.tick(at(121_000));
    assert_eq!(dut.rt().subscriptions().len(), 0);
}
