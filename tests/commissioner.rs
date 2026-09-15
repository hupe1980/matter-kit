//! A commissioner and a commissionee, end to end (Core §5.5).
//!
//! Both halves of commissioning are in this crate, and they were written from §5.5 and §11.18
//! separately — `commissioning::commissioner` drives, `clusters::operational_credentials` and
//! `clusters::general_commissioning` answer. This file runs one against the other, which is the
//! only way to find the places where the two readings of the same specification disagree.
//!
//! Everything is real: the attestation chain is built by `attestation::factory` and verified by
//! `attestation::chain`, the operational certificates are issued by `ca` and verified by
//! `cert::chain`, and every signature is made and checked by the same `KeyStore` a device would
//! use. The only thing stubbed is the network, and `tests/commission_over_messaging.rs` covers
//! that.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::attestation::factory::DevelopmentChain;
use matter_kit::ca::{CertAuthority, Identity, Validity};
use matter_kit::clusters::basic_information::Location;
use matter_kit::clusters::general_commissioning::{self, GeneralCommissioning, RegulatoryLocation};
use matter_kit::clusters::operational_credentials::{
    self as opcreds, DeviceAttestation, OperationalCredentials,
};
use matter_kit::commissioning::commissioner::{Attestation, Commissioner, Plan, Stage, Step};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::crypto::{KeyHandle, KeyPurpose, KeyStore, SoftKeyStore, SymmetricKey};
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::fabric::FabricTable;
use matter_kit::im::{
    AccessControl, AttributePath, CommandData, CommandPath, InteractionContext, InvokeResponse,
    InvokeResponseMessage, Outcome, Server, Status,
};
use matter_kit::msg::{FabricId, FabricIndex, NodeId, SessionId, VendorId};
use matter_kit::platform::sim::SimRng;
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvWriter};
use matter_kit::{Config, DefaultConfig};

const NOW: u32 = 757_382_400;
const PRODUCT_ID: u16 = 0x8000;
const FABRIC_ID: FabricId = FabricId(0xFAB0_0000_0000_001D);
const DEVICE_NODE_ID: NodeId = NodeId(0xDEDE_DEDE_0001_0001);
const CASE_ADMIN_SUBJECT: u64 = 0xDEDE_DEDE_0001_00AA;
const DER_MAX: usize = 600;

type Store = SoftKeyStore<8>;
type Fabrics = FabricTable<DefaultConfig, { DefaultConfig::FABRICS }>;

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

fn import(keys: &mut Store, purpose: KeyPurpose, seed: u8) -> KeyHandle {
    let mut secret = [1u8; 32];
    secret[31] = seed;
    keys.import(purpose, &secret).expect("a valid key")
}

// --- The commissionee ---------------------------------------------------------------------------

const CLUSTERS: &[ClusterDescriptor<'static>] =
    &[general_commissioning::cluster(), opcreds::cluster()];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, CLUSTERS)];

/// Everything a commissionee owns, including a real attestation chain.
struct Commissionee {
    fabrics: RefCell<Fabrics>,
    keys: RefCell<Store>,
    rng: RefCell<SimRng>,
    fail_safe: RefCell<FailSafe>,
    window: RefCell<CommissioningWindow>,
    location: Location,
    dac_key: KeyHandle,
    dac: Vec<u8>,
    pai: Vec<u8>,
    paa: Vec<u8>,
}

fn commissionee() -> Commissionee {
    let mut keys = Store::new();
    // The device's own attestation identity, and the factory that issued it. In a real product
    // the PAA key never leaves the CSA and the DAC is burned in at manufacture; here all three
    // are built so the whole of §6.2.3 can actually run.
    let paa_key = import(&mut keys, KeyPurpose::DeviceAttestation, 1);
    let pai_key = import(&mut keys, KeyPurpose::DeviceAttestation, 2);
    let dac_key = import(&mut keys, KeyPurpose::DeviceAttestation, 3);
    let pai_public = keys.public_key(pai_key).expect("a public key");
    let dac_public = keys.public_key(dac_key).expect("a public key");

    let chain = DevelopmentChain::new(NOW, 10);
    let mut buf = [0u8; DER_MAX];
    let paa = chain.paa(&keys, &mut buf, paa_key).expect("a PAA").to_vec();
    let mut buf = [0u8; DER_MAX];
    let pai = chain
        .pai(&keys, &mut buf, paa_key, &pai_public)
        .expect("a PAI")
        .to_vec();
    let mut buf = [0u8; DER_MAX];
    let dac = chain
        .dac(&keys, &mut buf, pai_key, &dac_public, PRODUCT_ID)
        .expect("a DAC")
        .to_vec();

    Commissionee {
        fabrics: RefCell::new(Fabrics::new()),
        keys: RefCell::new(keys),
        rng: RefCell::new(SimRng::new(0x5EED_0000_1234_5678)),
        fail_safe: RefCell::new(FailSafe::new(BasicCommissioningInfo::default())),
        window: RefCell::new(CommissioningWindow::new()),
        location: Location::region_agnostic(),
        dac_key,
        dac,
        pai,
        paa,
    }
}

/// The two clusters the commissioning flow talks to.
struct Device<'a> {
    node: Node<'static>,
    gc: GeneralCommissioning<'a>,
    opcreds: OperationalCredentials<'a, DefaultConfig, Store, SimRng, { DefaultConfig::FABRICS }>,
}

/// Stand-in for the Certification Declaration, whose contents `tests/attestation_vectors.rs`
/// checks against Appendix F. What matters here is that it round-trips inside the signed
/// attestation elements.
const CD: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x03];

fn device(owned: &Commissionee) -> Device<'_> {
    Device {
        node: Node::new(ENDPOINTS),
        gc: GeneralCommissioning::new(
            &owned.location,
            RegulatoryLocation::IndoorOutdoor,
            &owned.fail_safe,
            &owned.window,
        ),
        opcreds: OperationalCredentials::new(
            &owned.fabrics,
            &owned.keys,
            &owned.rng,
            &owned.fail_safe,
            DeviceAttestation {
                dac: &owned.dac,
                pai: &owned.pai,
                certification_declaration: CD,
                dac_key: owned.dac_key,
                firmware_information: None,
            },
        ),
    }
}

/// Invokes one command on endpoint 0 over the given session.
fn invoke<'b>(
    device: &Device<'_>,
    cluster: u32,
    command: u32,
    fields: &'b [u8],
    ctx: &InteractionContext<'_>,
    buf: &'b mut [u8],
) -> Result<Option<&'b [u8]>, Status> {
    let data = CommandData {
        fields: Some(fields),
        ..CommandData::new(CommandPath::command(0, cluster, command))
    };
    let mut scratch = [0u8; 2048];
    let access = AllowAll;
    let handler = (&device.gc, &device.opcreds);
    let server = Server::new(device.node, &access, &handler, 8);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], ctx, false, &mut scratch, buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    match response
        .responses()
        .expect("responses")
        .next()
        .expect("one response")
        .expect("decode")
    {
        InvokeResponse::Command(c) => Ok(Some(c.fields.unwrap_or(&[]))),
        // §11.18.6.13's `AddTrustedRootCertificate` has no response command: a bare `SUCCESS`
        // is the answer, and anything else is a real failure.
        InvokeResponse::Status(s) if s.status.status == Status::Success => Ok(None),
        InvokeResponse::Status(s) => Err(s.status.status),
    }
}

/// A PASE session — no accessing fabric, which is what makes it the commissioning channel.
fn over_pase(challenge: &SymmetricKey, now: Instant) -> InteractionContext<'_> {
    InteractionContext {
        session: Some(SessionId(1)),
        attestation_challenge: Some(challenge),
        now,
        ..InteractionContext::default()
    }
}

/// The operational session the credentials just installed make possible.
fn over_case(
    fabric: FabricIndex,
    challenge: &SymmetricKey,
    now: Instant,
) -> InteractionContext<'_> {
    InteractionContext {
        fabric_index: Some(fabric),
        session: Some(SessionId(2)),
        attestation_challenge: Some(challenge),
        peer_node_id: Some(NodeId(CASE_ADMIN_SUBJECT)),
        now,
        ..InteractionContext::default()
    }
}

/// The commissioner's side: a key store holding the fabric root, and the CA over it.
struct Administrator {
    keys: Store,
    ca: CertAuthority,
}

fn administrator() -> Administrator {
    let mut keys = Store::new();
    let root_key = import(&mut keys, KeyPurpose::Operational, 42);
    Administrator {
        keys,
        ca: CertAuthority::new(root_key, 0xCAFE).for_fabric(FABRIC_ID),
    }
}

fn base_plan() -> Plan {
    Plan::new(
        Identity::new(FABRIC_ID, DEVICE_NODE_ID),
        CASE_ADMIN_SUBJECT,
        VendorId(0xFFF1),
        Validity::years(NOW, 1),
    )
}

/// A distinguishable challenge, standing in for what PASE derived.
fn new_challenge() -> SymmetricKey {
    SymmetricKey::from_slice(&[0x5Au8; 16]).expect("16 octets")
}

/// Runs the whole PASE-phase sequence, driving the commissioner against the device.
///
/// Returns the stage it stopped at, so a test can assert it reached the operational handover
/// rather than merely not failing.
fn run_pase_phase(
    commissioner: &mut Commissioner,
    admin: &Administrator,
    device: &Device<'_>,
    challenge: &SymmetricKey,
) -> Stage {
    let ctx = over_pase(challenge, at(0));
    for _ in 0..16 {
        // §5.5 step 13's two credential commands need the CA, so they have their own entry
        // points — everything else is `step`.
        let step = match commissioner.stage() {
            Stage::AddTrustedRoot => commissioner.add_root(&admin.ca, &admin.keys),
            Stage::AddNoc => commissioner.add_noc(&admin.ca, &admin.keys, None),
            _ => commissioner.step(),
        }
        .expect("a step");
        let (cluster, command, fields) = match step {
            Step::Invoke {
                cluster,
                command,
                fields,
                ..
            } => (cluster, command, fields.to_vec()),
            _ => return commissioner.stage(),
        };
        let mut buf = [0u8; 4096];
        let response = invoke(device, cluster, command, &fields, &ctx, &mut buf)
            .expect("the device answered")
            .map(<[u8]>::to_vec);
        commissioner
            .on_response(response.as_deref())
            .expect("the commissioner accepted the response");

        // §6.2.3's chain check needs a PAA from the commissioner's own trust store, so it
        // happens here rather than inside the flow.
        if commissioner.stage() == Stage::RequestCsr && commissioner.attestation().is_some() {
            // Left to the caller deliberately; see the attestation tests below.
        }
    }
    panic!("the flow did not terminate");
}

/// Finishes a commissioning: the operational handover and `CommissioningComplete` over CASE.
///
/// §11.10.7.6 makes that command CASE-only, which is what proves the credentials just installed
/// actually work — and it is what commits the fabric, so a caller that stops before it leaves
/// the device with a fabric the next `ArmFailSafe` will revert.
fn complete(
    commissioner: &mut Commissioner,
    device: &Device<'_>,
    challenge: &SymmetricKey,
    index: FabricIndex,
    now: Instant,
) {
    commissioner.on_operational().expect("handover");
    let ctx = over_case(index, challenge, now);
    let Step::Invoke {
        cluster,
        command,
        fields,
        ..
    } = commissioner.step().expect("a step")
    else {
        panic!("expected an invoke");
    };
    let fields = fields.to_vec();
    let mut buf = [0u8; 2048];
    let response = invoke(device, cluster, command, &fields, &ctx, &mut buf)
        .expect("the device answered")
        .map(<[u8]>::to_vec);
    commissioner
        .on_response(response.as_deref())
        .expect("accepted");
    assert_eq!(commissioner.stage(), Stage::Done);
}

// --- The whole flow -------------------------------------------------------------------------

#[test]
fn a_commissioner_walks_a_device_through_the_whole_flow() {
    let owned = commissionee();
    let device = device(&owned);
    let admin = administrator();
    let challenge = new_challenge();
    let mut commissioner = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);

    assert_eq!(commissioner.stage(), Stage::ArmFailSafe);
    let stage = run_pase_phase(&mut commissioner, &admin, &device, &challenge);
    assert_eq!(
        stage,
        Stage::Operational,
        "the PASE phase did not reach the operational handover"
    );

    // §5.5 step 10's decision is the caller's, and it needs a PAA the *commissioner* trusts.
    let outcome = commissioner
        .verify_attestation_against(&owned.paa)
        .expect("the check ran");
    assert_eq!(
        outcome,
        Attestation::Trusted,
        "the device's own chain did not verify"
    );

    // The device is on the fabric: one entry, with the identity the commissioner chose.
    let fabrics = owned.fabrics.borrow();
    assert_eq!(fabrics.len(), 1);
    let entry = fabrics.iter().next().expect("a fabric");
    assert_eq!(entry.node_id, DEVICE_NODE_ID);
    assert_eq!(entry.fabric_id, FABRIC_ID);
    let index = entry.index;
    drop(fabrics);

    // §5.5's setup phase: the caller configures the network, finds the node and opens CASE.
    assert!(
        commissioner.pause(),
        "the flow did not pause for the caller"
    );
    commissioner.on_operational().expect("handover");
    assert_eq!(commissioner.stage(), Stage::CommissioningComplete);

    // §11.10.7.6 makes `CommissioningComplete` CASE-only, which is what proves the credentials
    // just installed actually work before the fail-safe is allowed to lapse.
    let ctx = over_case(index, &challenge, at(1));
    let Step::Invoke {
        cluster,
        command,
        fields,
        ..
    } = commissioner.step().expect("a step")
    else {
        panic!("expected an invoke");
    };
    let fields = fields.to_vec();
    let mut buf = [0u8; 2048];
    let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
        .expect("the device answered")
        .map(<[u8]>::to_vec);
    commissioner
        .on_response(response.as_deref())
        .expect("accepted");
    assert_eq!(commissioner.stage(), Stage::Done);
    assert!(matches!(commissioner.step().expect("done"), Step::Done));

    // The fail-safe is disarmed and the fabric is committed.
    assert!(!owned.fail_safe.borrow().is_armed(at(1)));
    assert_eq!(owned.fabrics.borrow().len(), 1);
}

#[test]
fn the_order_is_the_flows_and_a_caller_cannot_skip_a_step() {
    // §5.5's order is not a convenience. The fail-safe is armed first because everything after
    // it is undone if the commissioner walks away; attestation comes before the CSR because the
    // CSR is signed by the same DAC key the attestation proved possession of; the root goes in
    // before the NOC because the device cannot check a chain whose anchor it lacks.
    let owned = commissionee();
    let device = device(&owned);
    let admin = administrator();
    let challenge = new_challenge();
    let mut commissioner = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);

    // The credential commands are not available before their turn.
    assert!(commissioner.add_root(&admin.ca, &admin.keys).is_err());
    assert!(commissioner.add_noc(&admin.ca, &admin.keys, None).is_err());
    assert!(commissioner.on_operational().is_err());

    let expected = [
        Stage::ArmFailSafe,
        Stage::RequestDac,
        Stage::RequestPai,
        Stage::RequestAttestation,
        Stage::RequestCsr,
        Stage::AddTrustedRoot,
        Stage::AddNoc,
        Stage::Operational,
    ];
    let ctx = over_pase(&challenge, at(0));
    let mut seen = Vec::new();
    loop {
        seen.push(commissioner.stage());
        if commissioner.stage() == Stage::Operational {
            break;
        }
        let step = match commissioner.stage() {
            Stage::AddTrustedRoot => commissioner.add_root(&admin.ca, &admin.keys),
            Stage::AddNoc => commissioner.add_noc(&admin.ca, &admin.keys, None),
            _ => commissioner.step(),
        }
        .expect("a step");
        let Step::Invoke {
            cluster,
            command,
            fields,
            ..
        } = step
        else {
            break;
        };
        let fields = fields.to_vec();
        let mut buf = [0u8; 4096];
        let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
            .expect("answered")
            .map(<[u8]>::to_vec);
        commissioner
            .on_response(response.as_deref())
            .expect("accepted");
    }
    assert_eq!(seen, expected);
}

// --- Attestation ------------------------------------------------------------------------------

#[test]
fn a_nonce_the_device_does_not_echo_back_fails_attestation() {
    // §11.18.6.1: "the Commissioner SHALL verify that the AttestationNonce ... matches the one
    // it sent". Without it, a recorded attestation from any prior session would pass — which is
    // the whole reason the nonce exists.
    //
    // Driven by *rewriting* the commissioner's expectation rather than the device's answer,
    // because the device is the honest one here and the mismatch is what matters.
    let owned = commissionee();
    let device = device(&owned);
    let challenge = new_challenge();
    let mut commissioner = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);

    // Walk to the attestation step.
    let ctx = over_pase(&challenge, at(0));
    while commissioner.stage() != Stage::RequestAttestation {
        let Step::Invoke {
            cluster,
            command,
            fields,
            ..
        } = commissioner.step().expect("a step")
        else {
            panic!("expected an invoke");
        };
        let fields = fields.to_vec();
        let mut buf = [0u8; 4096];
        let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
            .expect("answered")
            .map(<[u8]>::to_vec);
        commissioner
            .on_response(response.as_deref())
            .expect("accepted");
    }

    // A second commissioner with a *different* nonce, fed the first one's response.
    let mut impostor = Commissioner::new(base_plan(), new_challenge(), [0xFF; 32], [0xB2; 32]);
    let Step::Invoke {
        cluster,
        command,
        fields,
        ..
    } = commissioner.step().expect("a step")
    else {
        panic!("expected an invoke");
    };
    let fields = fields.to_vec();
    let mut buf = [0u8; 4096];
    let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
        .expect("answered")
        .expect("a response command")
        .to_vec();

    // Walk the impostor to the same stage without letting it send its own nonce.
    while impostor.stage() != Stage::RequestAttestation {
        let Step::Invoke {
            cluster,
            command,
            fields,
            ..
        } = impostor.step().expect("a step")
        else {
            panic!("expected an invoke");
        };
        let fields = fields.to_vec();
        let mut buf = [0u8; 4096];
        let reply = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
            .expect("answered")
            .map(<[u8]>::to_vec);
        impostor.on_response(reply.as_deref()).expect("accepted");
    }
    impostor.on_response(Some(&response)).expect("recorded");
    assert!(
        matches!(impostor.attestation(), Some(Attestation::Failed(_))),
        "a replayed attestation was accepted: {:?}",
        impostor.attestation()
    );

    // The honest one passes.
    commissioner.on_response(Some(&response)).expect("accepted");
    assert_eq!(commissioner.attestation(), Some(Attestation::Trusted));
}

#[test]
fn a_chain_that_does_not_reach_the_commissioners_paa_is_reported() {
    // §6.2.3's chain check needs a root the *commissioner* trusts; a device supplying its own
    // would be attesting to itself. §5.5 step 10 makes the outcome a report rather than a
    // verdict — a development device with an uncertified PAA is a case the specification
    // explicitly wants commissionable, with a warning.
    let owned = commissionee();
    let device = device(&owned);
    let admin = administrator();
    let challenge = new_challenge();
    let mut commissioner = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);
    run_pase_phase(&mut commissioner, &admin, &device, &challenge);

    // Somebody else's PAA.
    let mut other_keys = Store::new();
    let other_paa_key = import(&mut other_keys, KeyPurpose::DeviceAttestation, 77);
    let mut buf = [0u8; DER_MAX];
    let other_paa = DevelopmentChain::new(NOW, 10)
        .paa(&other_keys, &mut buf, other_paa_key)
        .expect("a PAA")
        .to_vec();

    let outcome = commissioner
        .verify_attestation_against(&other_paa)
        .expect("the check ran");
    assert!(
        matches!(outcome, Attestation::Failed(_)),
        "a chain verified against a PAA that signed nothing in it"
    );

    // ...and the commissioning itself had already completed its PASE phase, which is the point:
    // the policy decision is the caller's and it comes after the facts are in.
    assert_eq!(commissioner.stage(), Stage::Operational);
}

// --- The CSR ------------------------------------------------------------------------------------

#[test]
fn the_noc_is_issued_for_the_key_the_device_generated() {
    // §11.18.6.5: "The CSRRequest command will cause the generation of a new operational key
    // pair at the Commissionee." The commissioner never sees the private half, and the NOC it
    // issues is for the public half the CSR carried — which is what makes the certificate
    // useless to anybody else.
    let owned = commissionee();
    let device = device(&owned);
    let admin = administrator();
    let challenge = new_challenge();
    let mut commissioner = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);
    run_pase_phase(&mut commissioner, &admin, &device, &challenge);

    let operational = commissioner
        .operational_key()
        .expect("the CSR carried a public key");

    // The device's fabric entry holds the matching private key, and its public half is the one
    // the commissioner certified.
    let fabrics = owned.fabrics.borrow();
    let entry = fabrics.iter().next().expect("a fabric");
    let device_public = owned
        .keys
        .borrow()
        .public_key(entry.operational_key)
        .expect("the operational key");
    assert_eq!(
        device_public, operational,
        "the NOC was issued for a key the device does not hold"
    );
}

#[test]
fn a_second_administrator_joins_the_same_device_to_its_own_fabric() {
    // §5.5's multi-admin case, and §11.18's reason for existing: a device belongs to as many
    // fabrics as have commissioned it, and each gets *a new* operational key pair (§11.18.6.5).
    // Two fabrics sharing one key would let either read the other's CASE traffic, which the
    // fabric isolation of §6.4.5 rests on not being true.
    let owned = commissionee();
    let device = device(&owned);
    let admin = administrator();
    let challenge = new_challenge();

    let mut first = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);
    run_pase_phase(&mut first, &admin, &device, &challenge);
    let first_key = first.operational_key().expect("a key");
    let first_index = owned
        .fabrics
        .borrow()
        .iter()
        .next()
        .expect("a fabric")
        .index;
    // The first commissioning has to *finish* before a second can start: §11.10.7.2 makes a
    // new `ArmFailSafe` revert whatever the previous one left pending, so two concurrent
    // commissionings are not a thing the fail-safe permits.
    complete(&mut first, &device, &challenge, first_index, at(1));

    // A second administrator, a second fabric, the same device.
    let mut second_keys = Store::new();
    let second_root = import(&mut second_keys, KeyPurpose::Operational, 43);
    let second_admin = Administrator {
        keys: second_keys,
        ca: CertAuthority::new(second_root, 0xBEEF).for_fabric(FabricId(0xFAB0_0000_0000_002D)),
    };
    let second_plan = Plan::new(
        Identity::new(
            FabricId(0xFAB0_0000_0000_002D),
            NodeId(0xDEDE_DEDE_0002_0001),
        ),
        CASE_ADMIN_SUBJECT,
        VendorId(0xFFF1),
        Validity::years(NOW, 1),
    );
    let mut second = Commissioner::new(second_plan, new_challenge(), [0xC3; 32], [0xD4; 32]);
    run_pase_phase(&mut second, &second_admin, &device, &challenge);
    let second_key = second.operational_key().expect("a key");
    let second_index = owned
        .fabrics
        .borrow()
        .iter()
        .find(|fabric| fabric.index != first_index)
        .expect("a second fabric")
        .index;
    complete(&mut second, &device, &challenge, second_index, at(2));

    assert_ne!(
        first_key, second_key,
        "two fabrics were given the same operational key"
    );
    let fabrics = owned.fabrics.borrow();
    assert_eq!(fabrics.len(), 2, "the device is on two fabrics");
    // ...and each names the node the *administrator that commissioned it* chose. §6.4.5's
    // isolation starts here: neither fabric's node id is visible to the other.
    let ids: Vec<NodeId> = fabrics.iter().map(|fabric| fabric.node_id).collect();
    assert!(ids.contains(&DEVICE_NODE_ID));
    assert!(ids.contains(&NodeId(0xDEDE_DEDE_0002_0001)));
    let roots: Vec<_> = fabrics
        .iter()
        .map(|fabric| fabric.root_public_key)
        .collect();
    assert_ne!(roots[0], roots[1], "both fabrics trust the same root");
}

// --- The plan ------------------------------------------------------------------------------------

#[test]
fn a_device_that_needs_regulatory_config_is_sent_it() {
    // §5.5 step 8: "If the Commissionee has at least one instance of the Network Commissioning
    // cluster on any endpoint with either the WI ... or TH ... feature flags set". A wired
    // device has none, and sending it anyway wastes a round trip on a device with no radio — so
    // it is in the plan rather than always.
    let owned = commissionee();
    let device = device(&owned);
    let challenge = new_challenge();
    let configured = base_plan().with_regulatory_config(
        matter_kit::clusters::generated::general_commissioning::RegulatoryLocationTypeEnum::Indoor,
    );
    let mut commissioner = Commissioner::new(configured, new_challenge(), [0xA1; 32], [0xB2; 32]);

    let ctx = over_pase(&challenge, at(0));
    let Step::Invoke { .. } = commissioner.step().expect("a step") else {
        panic!("expected an invoke");
    };
    // ArmFailSafe first, always.
    assert_eq!(commissioner.stage(), Stage::ArmFailSafe);
    let Step::Invoke {
        cluster,
        command,
        fields,
        ..
    } = commissioner.step().expect("a step")
    else {
        panic!("expected an invoke");
    };
    let fields = fields.to_vec();
    let mut buf = [0u8; 4096];
    let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
        .expect("answered")
        .map(<[u8]>::to_vec);
    commissioner
        .on_response(response.as_deref())
        .expect("accepted");
    assert_eq!(
        commissioner.stage(),
        Stage::SetRegulatoryConfig,
        "a device that needs regulatory config did not get it"
    );

    // ...and without it, the flow goes straight to attestation.
    let mut plain = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);
    let Step::Invoke {
        cluster,
        command,
        fields,
        ..
    } = plain.step().expect("a step")
    else {
        panic!("expected an invoke");
    };
    let fields = fields.to_vec();
    let mut buf = [0u8; 4096];
    let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
        .expect("answered")
        .map(<[u8]>::to_vec);
    plain.on_response(response.as_deref()).expect("accepted");
    assert_eq!(plain.stage(), Stage::RequestDac);
}

#[test]
fn the_fail_safe_is_armed_to_the_plans_duration() {
    // §5.5 step 7: the commissioner re-arms "to the desired commissioning timeout within 60
    // seconds of the completion of PASE session establishment". The device armed 60 seconds for
    // itself at step 6; this is the commissioner replacing it with something long enough to
    // finish in.
    let owned = commissionee();
    let device = device(&owned);
    let challenge = new_challenge();
    let mut commissioner = Commissioner::new(
        base_plan().with_fail_safe(120),
        new_challenge(),
        [0xA1; 32],
        [0xB2; 32],
    );
    let ctx = over_pase(&challenge, at(0));
    let Step::Invoke {
        cluster,
        command,
        fields,
        ..
    } = commissioner.step().expect("a step")
    else {
        panic!("expected an invoke");
    };
    let fields = fields.to_vec();
    let mut buf = [0u8; 4096];
    invoke(&device, cluster, command, &fields, &ctx, &mut buf).expect("answered");

    assert!(owned.fail_safe.borrow().is_armed(at(119)));
    assert!(!owned.fail_safe.borrow().is_armed(at(121)));
}

#[test]
fn a_csr_nonce_the_device_does_not_echo_back_is_refused() {
    // §11.18.6.6: "the Commissioner SHALL verify that the CSRNonce ... matches". The same replay
    // argument as the attestation nonce, and it matters more here: a replayed `CSRResponse`
    // would put a *previous* device's public key into this device's certificate, and the
    // certificate would then be useless to the device that holds it.
    let owned = commissionee();
    let device = device(&owned);
    let admin = administrator();
    let challenge = new_challenge();
    let mut honest = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);
    // A second commissioner asking for a different CSR nonce.
    let mut impostor = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xFF; 32]);
    let ctx = over_pase(&challenge, at(0));

    // Walk both to the CSR step.
    for commissioner in [&mut honest, &mut impostor] {
        while commissioner.stage() != Stage::RequestCsr {
            let step = match commissioner.stage() {
                Stage::AddTrustedRoot => commissioner.add_root(&admin.ca, &admin.keys),
                Stage::AddNoc => commissioner.add_noc(&admin.ca, &admin.keys, None),
                _ => commissioner.step(),
            }
            .expect("a step");
            let Step::Invoke {
                cluster,
                command,
                fields,
                ..
            } = step
            else {
                panic!("expected an invoke");
            };
            let fields = fields.to_vec();
            let mut buf = [0u8; 4096];
            let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
                .expect("answered")
                .map(<[u8]>::to_vec);
            commissioner
                .on_response(response.as_deref())
                .expect("accepted");
        }
    }

    // The honest commissioner's `CSRRequest`, and the device's answer to it.
    let Step::Invoke {
        cluster,
        command,
        fields,
        ..
    } = honest.step().expect("a step")
    else {
        panic!("expected an invoke");
    };
    let fields = fields.to_vec();
    let mut buf = [0u8; 4096];
    let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
        .expect("answered")
        .expect("a response command")
        .to_vec();

    // The impostor asked for a different nonce, so this response is not its answer.
    assert!(
        impostor.on_response(Some(&response)).is_err(),
        "a CSR answering somebody else's nonce was accepted"
    );
    assert!(impostor.operational_key().is_none());

    // ...and the honest one takes it.
    honest.on_response(Some(&response)).expect("accepted");
    assert!(honest.operational_key().is_some());
}

#[test]
fn a_csr_whose_inner_signature_is_wrong_is_refused() {
    // §11.18.6.6 has two signatures, and both matter. The *outer* one is the DAC's over the
    // whole `NOCSRElements`, which ties the new operational key to the attestation already
    // performed. The *inner* one is PKCS#10's proof of possession: the CSR is self-signed by
    // the operational key.
    //
    // Without the inner check a device could hand over somebody else's public key, correctly
    // signed by its own DAC — and the commissioner would issue a certificate for a key the
    // device does not hold, which nothing would ever be able to use.
    let owned = commissionee();
    let device = device(&owned);
    let admin = administrator();
    let challenge = new_challenge();
    let mut commissioner = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);
    let ctx = over_pase(&challenge, at(0));
    while commissioner.stage() != Stage::RequestCsr {
        let step = match commissioner.stage() {
            Stage::AddTrustedRoot => commissioner.add_root(&admin.ca, &admin.keys),
            Stage::AddNoc => commissioner.add_noc(&admin.ca, &admin.keys, None),
            _ => commissioner.step(),
        }
        .expect("a step");
        let Step::Invoke {
            cluster,
            command,
            fields,
            ..
        } = step
        else {
            panic!("expected an invoke");
        };
        let fields = fields.to_vec();
        let mut buf = [0u8; 4096];
        let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
            .expect("answered")
            .map(<[u8]>::to_vec);
        commissioner
            .on_response(response.as_deref())
            .expect("accepted");
    }

    // Build a `CSRResponse` whose outer DAC signature is perfectly good and whose inner CSR
    // self-signature is not — which is exactly what a device handing over a stolen key would
    // produce.
    let mut keys = owned.keys.borrow_mut();
    let operational = import(&mut keys, KeyPurpose::Operational, 55);
    let mut csr_buf = [0u8; 512];
    let csr = matter_kit::attestation::nocsr::build_csr(&*keys, operational, &mut csr_buf)
        .expect("a CSR")
        .to_vec();
    drop(keys);
    let mut forged = csr.clone();
    // Flip a bit in the trailing signature — PKCS#10 puts it last.
    let last = forged.len() - 1;
    forged[last] ^= 0x01;

    let elements = matter_kit::attestation::NocsrElements {
        csr: &forged,
        csr_nonce: [0xB2; 32],
        vendor_reserved: Default::default(),
    };
    let mut elements_buf = [0u8; 1024];
    let encoded = elements
        .encode(&mut elements_buf)
        .expect("encodes")
        .to_vec();
    let signature = matter_kit::attestation::nocsr::sign_nocsr(
        &*owned.keys.borrow(),
        owned.dac_key,
        &encoded,
        &challenge,
    )
    .expect("signs");

    let mut buf = [0u8; 2048];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.octets(Tag::Context(0), &encoded).unwrap();
    w.octets(Tag::Context(1), signature.as_bytes()).unwrap();
    w.end_container().unwrap();
    let response = w.finish().unwrap().to_vec();

    assert!(
        commissioner.on_response(Some(&response)).is_err(),
        "a CSR that does not prove possession of its own key was accepted"
    );
    assert!(commissioner.operational_key().is_none());
}

#[test]
fn a_good_chain_does_not_rescue_a_signature_that_did_not_verify() {
    // §6.2.3 is a *procedure*, not a menu: the attestation signature and the certificate chain
    // are two separate checks and passing one does not excuse failing the other. A device whose
    // chain is impeccable and whose signature is a replay has not proved it holds the DAC key,
    // which is the only thing the chain is evidence *about*.
    let owned = commissionee();
    let device = device(&owned);
    let admin = administrator();
    let challenge = new_challenge();
    let mut honest = Commissioner::new(base_plan(), new_challenge(), [0xA1; 32], [0xB2; 32]);
    let mut impostor = Commissioner::new(base_plan(), new_challenge(), [0xFF; 32], [0xB2; 32]);
    let ctx = over_pase(&challenge, at(0));

    for commissioner in [&mut honest, &mut impostor] {
        while commissioner.stage() != Stage::RequestAttestation {
            let Step::Invoke {
                cluster,
                command,
                fields,
                ..
            } = commissioner.step().expect("a step")
            else {
                panic!("expected an invoke");
            };
            let fields = fields.to_vec();
            let mut buf = [0u8; 4096];
            let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
                .expect("answered")
                .map(<[u8]>::to_vec);
            commissioner
                .on_response(response.as_deref())
                .expect("accepted");
        }
    }

    let Step::Invoke {
        cluster,
        command,
        fields,
        ..
    } = honest.step().expect("a step")
    else {
        panic!("expected an invoke");
    };
    let fields = fields.to_vec();
    let mut buf = [0u8; 4096];
    let response = invoke(&device, cluster, command, &fields, &ctx, &mut buf)
        .expect("answered")
        .expect("a response command")
        .to_vec();
    impostor.on_response(Some(&response)).expect("recorded");
    assert!(matches!(
        impostor.attestation(),
        Some(Attestation::Failed(_))
    ));

    // The chain is the device's own and verifies perfectly — and the outcome stays Failed.
    let outcome = impostor
        .verify_attestation_against(&owned.paa)
        .expect("the check ran");
    assert!(
        matches!(outcome, Attestation::Failed(_)),
        "a good chain rescued a signature that did not verify"
    );
    let _ = admin;
}
