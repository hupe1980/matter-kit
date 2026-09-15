//! Commissioning a device into a fabric, command by command, through the interaction model.
//!
//! This is §5.5's operational-credentials phase run for real: `ArmFailSafe`,
//! `AttestationRequest`, `CertificateChainRequest`, `CSRRequest`,
//! `AddTrustedRootCertificate`, `AddNOC`, `CommissioningComplete`. Nothing is stubbed — the
//! device generates its own operational key, the test's certificate authority mints a NOC
//! over the public key that came back in the CSR, and the resulting fabric entry is the one
//! CASE would use.
//!
//! What that proves which unit tests could not:
//!
//! * the NOC's public key really is the one the device generated — §11.18.6.7 step 2, and the
//!   check that stops an administrator installing a certificate over a key pair it made
//!   itself and then impersonating the node;
//! * the fail-safe's `Progress` is what the credential commands read and record, so the
//!   ordering rules of §11.18.6.5, §11.18.6.8 and §11.18.6.13 are enforced against one
//!   shared context rather than a cluster's private copy;
//! * the `Fabrics` and `NOCs` attributes report what was actually installed, in the encoding
//!   a commissioner decodes.
//!
//! The certificates are §6.5.15's published RCAC and ICAC; the NOC is minted here under the
//! ICAC's published private key.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use core::cell::RefCell;

use hex_literal::hex;
use matter_kit::cert::{
    BasicConstraints, CERT_DER_MAX, CERT_TLV_MAX, DistinguishedName, DnAttribute, EllipticCurveId,
    Extension, Extensions, KeyPurposeId, KeyUsage, MatterCertificate, PublicKeyAlgorithm,
    SignatureAlgorithm, der,
};
use matter_kit::clusters::general_commissioning::{self, GeneralCommissioning, RegulatoryLocation};
use matter_kit::clusters::operational_credentials::{
    self as opcreds, DeviceAttestation, FabricChange, NocStatus, OperationalCredentials,
};
use matter_kit::clusters::{Cluster, basic_information::Location};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::crypto::{
    GROUP_SIZE_BYTES, KeyPurpose, KeyStore, PublicKey, SoftKeyStore, SymmetricKey,
};
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::fabric::FabricTable;
use matter_kit::im::{
    AccessControl, AttributePath, ClusterHandler, CommandData, CommandPath, InteractionContext,
    InvokeResponse, InvokeResponseMessage, Outcome, Server, Status,
};
use matter_kit::msg::{FabricId, FabricIndex, NodeId, SessionId, VendorId};
use matter_kit::platform::sim::SimRng;
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter};
use matter_kit::{Config, DefaultConfig};

// --- The specification's certificates ----------------------------------------------------------

/// §6.5.15.1's RCAC, the fabric's trust anchor.
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

/// §6.5.15.2's ICAC, which issues the NOC below.
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
/// The administrator that will hold Administer over the new fabric (§11.18.6.8 step 7).
const CASE_ADMIN_SUBJECT: u64 = 0xDEDE_DEDE_0001_00AA;
const IPK_EPOCH: [u8; 16] = hex!("4a71cdd7b2a3ca9024f96f3c96a19dee");

/// Stand-ins for the device's attestation material. Their *contents* are not under test here
/// — `tests/attestation_vectors.rs` checks those against Appendix F — but their round trip
/// through `CertificateChainRequest` is.
const DAC_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
const PAI_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x02];
const CD: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x03];

type Store = SoftKeyStore<8>;
type Fabrics = FabricTable<DefaultConfig, { DefaultConfig::FABRICS }>;

/// Issues a NOC for `node_id` over `public_key`, signed by §6.5.15.2's ICAC.
///
/// This is what a commissioner's certificate authority does after reading a `CSRResponse`.
fn issue_noc(node_id: NodeId, public_key: PublicKey, out: &mut [u8]) -> usize {
    let mut ca = Store::new();
    let ca_handle = ca
        .import(KeyPurpose::Operational, &ICAC_PRIVATE_KEY)
        .expect("import the ICAC key");
    let icac = MatterCertificate::decode(ICAC).expect("icac");

    let mut subject = DistinguishedName::new();
    subject
        .push(DnAttribute::node_id(node_id))
        .expect("node id");
    subject
        .push(DnAttribute::fabric_id(FABRIC_ID))
        .expect("fabric id");

    // A truncated SHA-256 stands in for §6.5.11.4's SHA-1 key identifier: SHA-1 is not in
    // Matter's cryptosuite, and a key identifier only has to be a stable per-key label.
    let digest = matter_kit::crypto::hash(public_key.as_bytes());
    let mut subject_key_id = [0u8; 20];
    subject_key_id.copy_from_slice(&digest[..20]);

    let mut extensions = Extensions::new();
    extensions
        .push(Extension::BasicConstraints(BasicConstraints {
            is_ca: false,
            path_len_constraint: None,
        }))
        .expect("basic constraints");
    extensions
        .push(Extension::KeyUsage(KeyUsage::DIGITAL_SIGNATURE))
        .expect("key usage");
    let mut purposes = heapless::Vec::<KeyPurposeId, 6>::new();
    purposes.push(KeyPurposeId::ServerAuth).expect("fits");
    purposes.push(KeyPurposeId::ClientAuth).expect("fits");
    extensions
        .push(Extension::ExtendedKeyUsage(purposes))
        .expect("eku");
    extensions
        .push(Extension::SubjectKeyId(subject_key_id))
        .expect("skid");
    extensions
        .push(Extension::AuthorityKeyId(
            icac.extensions.subject_key_id().expect("icac skid"),
        ))
        .expect("akid");

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
    let tbs = der::tbs_certificate(&cert, &mut der_buf).expect("tbs");
    cert.signature = ca.sign(ca_handle, tbs).expect("sign");
    cert.encode(out).expect("encode").len()
}

// --- The device --------------------------------------------------------------------------------

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

const CLUSTERS: &[ClusterDescriptor<'static>] =
    &[general_commissioning::cluster(), opcreds::cluster()];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, CLUSTERS)];

/// A commissionee: a fabric table, a key store, a fail-safe and the two clusters that use
/// them.
struct Device<'a> {
    node: Node<'static>,
    fabrics: &'a RefCell<Fabrics>,
    keys: &'a RefCell<Store>,
    fail_safe: &'a RefCell<FailSafe>,
    gc: GeneralCommissioning<'a>,
    opcreds: OperationalCredentials<'a, DefaultConfig, Store, SimRng, { DefaultConfig::FABRICS }>,
}

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

/// A PASE session, which is what initial commissioning runs over: no accessing fabric.
fn over_pase(challenge: &SymmetricKey, now: Instant) -> InteractionContext<'_> {
    InteractionContext {
        session: Some(SessionId(1)),
        attestation_challenge: Some(challenge),
        now,
        ..InteractionContext::default()
    }
}

fn over_case(fabric: u8, challenge: &SymmetricKey, now: Instant) -> InteractionContext<'_> {
    InteractionContext {
        fabric_index: Some(FabricIndex(fabric)),
        session: Some(SessionId(2)),
        attestation_challenge: Some(challenge),
        now,
        ..InteractionContext::default()
    }
}

/// Invokes one command on endpoint 0 and returns the response command's fields, or the status.
fn invoke<'b>(
    device: &Device<'_>,
    cluster: u32,
    command: u32,
    fields: &'b [u8],
    ctx: &InteractionContext<'_>,
    buf: &'b mut [u8],
) -> Result<(u32, &'b [u8]), Status> {
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
        InvokeResponse::Command(c) => Ok((
            c.path.command.expect("a response command id"),
            c.fields.unwrap_or(&[]),
        )),
        InvokeResponse::Status(s) => Err(s.status.status),
    }
}

// --- Field builders ----------------------------------------------------------------------------

/// Authors a `CommandFields` fragment: the context-1 member of a `CommandDataIB` (§10.6.11).
fn fields(build: impl FnOnce(&mut TlvWriter<'_>)) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).expect("open");
    build(&mut w);
    w.end_container().expect("close");
    w.finish().expect("finish").to_vec()
}

fn arm_fail_safe_fields(seconds: u16, breadcrumb: u64) -> Vec<u8> {
    fields(|w| {
        w.unsigned(Tag::Context(0), u64::from(seconds)).expect("0");
        w.unsigned(Tag::Context(1), breadcrumb).expect("1");
    })
}

fn octets_field(tag: u8, value: &[u8]) -> Vec<u8> {
    fields(|w| {
        w.octets(Tag::Context(tag), value).expect("octets");
    })
}

fn unsigned_field(tag: u8, value: u64) -> Vec<u8> {
    fields(|w| {
        w.unsigned(Tag::Context(tag), value).expect("unsigned");
    })
}

fn add_noc_fields(noc: &[u8], icac: Option<&[u8]>, subject: u64, vendor: u16) -> Vec<u8> {
    fields(|w| {
        w.octets(Tag::Context(0), noc).expect("noc");
        if let Some(icac) = icac {
            w.octets(Tag::Context(1), icac).expect("icac");
        }
        w.octets(Tag::Context(2), &IPK_EPOCH).expect("ipk");
        w.unsigned(Tag::Context(3), subject).expect("subject");
        w.unsigned(Tag::Context(4), u64::from(vendor))
            .expect("vendor");
    })
}

/// The `StatusCode [0]` of a `NOCResponse`, and its `FabricIndex [1]` if present.
fn noc_response(bytes: &[u8]) -> (u8, Option<u8>) {
    let mut reader = TlvReader::new_in(bytes, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    let status = reader.next_element().expect("read").expect("status");
    assert_eq!(status.tag, Tag::Context(0));
    let code = u8::try_from(status.unsigned().expect("uint")).expect("fits");
    let next = reader.next_element().expect("read").expect("next");
    let index = match next.tag {
        Tag::Context(1) => Some(u8::try_from(next.unsigned().expect("uint")).expect("fits")),
        _ => None,
    };
    (code, index)
}

/// The octet string under a context tag in a response structure.
fn response_octets(bytes: &[u8], tag: u8) -> &[u8] {
    let mut reader = TlvReader::new_in(bytes, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    let depth = reader.depth();
    while let Some(element) = reader.next_element().expect("read") {
        if reader.depth() < depth {
            break;
        }
        if element.tag == Tag::Context(tag) {
            return element.octets().expect("octets");
        }
        reader.skip_value(&element).expect("skip");
    }
    panic!("no field {tag}");
}

// --- The flow ----------------------------------------------------------------------------------

/// Everything a commissionee owns, kept alive for the duration of a test.
struct Owned {
    fabrics: RefCell<Fabrics>,
    keys: RefCell<Store>,
    rng: RefCell<SimRng>,
    fail_safe: RefCell<FailSafe>,
    window: RefCell<CommissioningWindow>,
    location: Location,
    dac_key: matter_kit::crypto::KeyHandle,
}

/// A stand-in Device Attestation private key. The DAC's *contents* are not under test here,
/// but the signature over `nocsr_tbs` is made with a real key by a real store.
const DAC_PRIVATE_KEY: [u8; GROUP_SIZE_BYTES] =
    hex!("a565b3fa28a8ed6a74fb6f0ff8a4d340d9e1ae98f21dfa1f0a59a4ea021a1627");

fn owned() -> Owned {
    let mut keys = Store::new();
    let dac_key = keys
        .import(KeyPurpose::DeviceAttestation, &DAC_PRIVATE_KEY)
        .expect("import the DAC key");
    Owned {
        fabrics: RefCell::new(Fabrics::new()),
        keys: RefCell::new(keys),
        rng: RefCell::new(SimRng::new(0x5EED_0000_1234_5678)),
        fail_safe: RefCell::new(FailSafe::new(BasicCommissioningInfo::default())),
        window: RefCell::new(CommissioningWindow::new()),
        location: Location::region_agnostic(),
        dac_key,
    }
}

fn device(owned: &Owned) -> Device<'_> {
    Device {
        node: Node::new(ENDPOINTS),
        fabrics: &owned.fabrics,
        keys: &owned.keys,
        fail_safe: &owned.fail_safe,
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
                dac: DAC_DER,
                pai: PAI_DER,
                certification_declaration: CD,
                dac_key: owned.dac_key,
                firmware_information: None,
            },
        ),
    }
}

/// Runs the whole credentials phase and returns the fabric index that was created.
fn commission(device: &Device<'_>, challenge: &SymmetricKey) -> FabricIndex {
    let ctx = over_pase(challenge, at(0));
    let mut buf = [0u8; 4096];

    // 1. ArmFailSafe — everything below is inside it.
    let armed = arm_fail_safe_fields(120, 1);
    let (id, _) = invoke(
        device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &armed,
        &ctx,
        &mut buf,
    )
    .expect("arm");
    assert_eq!(id, general_commissioning::ARM_FAIL_SAFE_RESPONSE);

    // 2. CSRRequest — the device makes a key it has never had before.
    let csr_nonce = [0x11u8; 32];
    let csr_fields = octets_field(0, &csr_nonce);
    let mut csr_buf = [0u8; 4096];
    let (id, response) = invoke(
        device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr_fields,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    assert_eq!(id, opcreds::CSR_RESPONSE);
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    assert_eq!(
        nocsr.csr_nonce, csr_nonce,
        "the nonce is echoed, not invented"
    );
    let csr = nocsr.parse_csr().expect("parse the CSR");
    assert!(csr.verify().expect("verify"), "the CSR is self-signed");
    let device_public = csr.public_key;

    // 3. The commissioner's CA mints a NOC over the key the device just generated.
    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(DEVICE_NODE_ID, device_public, &mut noc);
    let noc = &noc[..noc_len];

    // 4. AddTrustedRootCertificate, then AddNOC.
    let root_fields = octets_field(0, RCAC);
    let mut root_buf = [0u8; 2048];
    let outcome = invoke(
        device,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &root_fields,
        &ctx,
        &mut root_buf,
    );
    // No response command: §11.18.6's table gives `Y`, so success is a SUCCESS status.
    assert_eq!(outcome.unwrap_err(), Status::Success);

    let add = add_noc_fields(noc, Some(ICAC), CASE_ADMIN_SUBJECT, 0xFFF1);
    let mut add_buf = [0u8; 2048];
    let (id, response) = invoke(
        device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &add,
        &ctx,
        &mut add_buf,
    )
    .expect("add noc");
    assert_eq!(id, opcreds::NOC_RESPONSE);
    let (code, index) = noc_response(response);
    assert_eq!(code, NocStatus::Ok.value(), "AddNOC failed with {code}");
    FabricIndex(index.expect("a fabric index on success"))
}

/// `CommissioningComplete` over CASE on `index`, which disarms the fail-safe.
fn complete(device: &Device<'_>, index: FabricIndex, challenge: &SymmetricKey, now: Instant) {
    let ctx = over_case(index.0, challenge, now);
    let mut buf = [0u8; 2048];
    let empty = fields(|_| {});
    let (id, response) = invoke(
        device,
        general_commissioning::ID,
        general_commissioning::COMMISSIONING_COMPLETE,
        &empty,
        &ctx,
        &mut buf,
    )
    .expect("complete");
    assert_eq!(id, general_commissioning::COMMISSIONING_COMPLETE_RESPONSE);
    let mut reader = TlvReader::new_in(response, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    let error = reader.next_element().expect("read").expect("error");
    assert_eq!(error.unsigned().expect("uint"), 0, "CommissioningComplete");
}

#[test]
fn a_device_joins_a_fabric_and_completes_commissioning() {
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);

    let index = commission(&device, &challenge);
    assert_eq!(index, FabricIndex(1));

    // §11.18.6.8 step 7 and step 10a are the device's, and the cluster says so.
    assert_eq!(
        device.opcreds.take_change(),
        Some(FabricChange::Added {
            index,
            case_admin_subject: CASE_ADMIN_SUBJECT,
            bind_pase_session: true,
        })
    );

    // The fabric is real: derived values and all.
    let fabrics = device.fabrics.borrow();
    let fabric = fabrics.find(index).expect("the fabric exists");
    assert_eq!(fabric.fabric_id, FABRIC_ID);
    assert_eq!(fabric.node_id, DEVICE_NODE_ID);
    assert_eq!(fabric.admin_vendor_id, VendorId(0xFFF1));
    assert!(fabric.credentials.icac.is_some());
    drop(fabrics);

    // Step 9: the fail-safe adopted the new fabric, so CommissioningComplete over CASE on it
    // is accepted — which it would not be if the context still pointed at "no fabric".
    complete(&device, index, &challenge, at(1));
    assert!(!device.fail_safe.borrow().is_armed(at(1)));
}

// --- The refusals ------------------------------------------------------------------------------

#[test]
fn every_credential_command_needs_an_armed_fail_safe() {
    // §11.18.6.5, §11.18.6.8, §11.18.6.9 and §11.18.6.13 each say so in the same words: "If
    // this command is received without an armed fail-safe context … then this command SHALL
    // fail with a FAILSAFE_REQUIRED status code."
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 2048];

    for (command, payload) in [
        (opcreds::CSR_REQUEST, octets_field(0, &[0x11; 32])),
        (opcreds::ADD_TRUSTED_ROOT_CERTIFICATE, octets_field(0, RCAC)),
        (
            opcreds::ADD_NOC,
            add_noc_fields(RCAC, None, CASE_ADMIN_SUBJECT, 0xFFF1),
        ),
    ] {
        assert_eq!(
            invoke(&device, opcreds::ID, command, &payload, &ctx, &mut buf).unwrap_err(),
            Status::FailsafeRequired,
            "command {command:#04x}"
        );
    }
}

#[test]
fn add_noc_without_a_csr_is_missing_csr() {
    // §11.18.6.7: "If no context or memory exists of a prior CSRRequest command having been
    // invoked in the same secure session … MissingCsr."
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    let armed = arm_fail_safe_fields(120, 1);
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &armed,
        &ctx,
        &mut buf,
    )
    .expect("arm");

    let add = add_noc_fields(RCAC, None, CASE_ADMIN_SUBJECT, 0xFFF1);
    let mut add_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &add,
        &ctx,
        &mut add_buf,
    )
    .expect("noc response");
    assert_eq!(noc_response(response).0, NocStatus::MissingCsr.value());
}

#[test]
fn a_csr_from_another_session_cannot_be_used() {
    // §11.18.6.7 scopes the CSR record to "the same secure session". Without that, one
    // administrator's CSRRequest could be consumed by another administrator's AddNOC — and
    // the second would end up holding a certificate over a key the first is watching.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    let armed = arm_fail_safe_fields(120, 1);
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &armed,
        &ctx,
        &mut buf,
    )
    .expect("arm");

    let csr_fields = octets_field(0, &[0x11; 32]);
    let mut csr_buf = [0u8; 4096];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr_fields,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    let public = nocsr.parse_csr().expect("csr").public_key;
    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(DEVICE_NODE_ID, public, &mut noc);

    // A different session on the same fail-safe.
    let other = InteractionContext {
        session: Some(SessionId(9)),
        ..ctx
    };
    invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &octets_field(0, RCAC),
        &other,
        &mut buf,
    )
    .unwrap_err();

    let add = add_noc_fields(&noc[..noc_len], Some(ICAC), CASE_ADMIN_SUBJECT, 0xFFF1);
    let mut add_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &add,
        &other,
        &mut add_buf,
    )
    .expect("noc response");
    assert_eq!(noc_response(response).0, NocStatus::MissingCsr.value());
    assert!(device.fabrics.borrow().is_empty());
}

#[test]
fn add_noc_requires_a_root_installed_in_the_same_fail_safe_period() {
    // §11.18.6.8: "AddNOC always requires that the client provides the root of trust
    // certificate within the same Fail-Safe context as the rest of the new fabric's
    // operational credentials, **even if some other fabric already uses the exact same root
    // of trust certificate**." Reusing an installed root would let an administrator graft a
    // fabric onto a root it never presented.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(120, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");

    let csr_fields = octets_field(0, &[0x11; 32]);
    let mut csr_buf = [0u8; 4096];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr_fields,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    let public = nocsr.parse_csr().expect("csr").public_key;
    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(DEVICE_NODE_ID, public, &mut noc);

    // No AddTrustedRootCertificate.
    let add = add_noc_fields(&noc[..noc_len], Some(ICAC), CASE_ADMIN_SUBJECT, 0xFFF1);
    let mut add_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &add,
        &ctx,
        &mut add_buf,
    )
    .expect("noc response");
    assert_eq!(noc_response(response).0, NocStatus::InvalidNoc.value());
    assert!(device.fabrics.borrow().is_empty());
}

#[test]
fn a_noc_over_a_key_the_device_did_not_generate_is_refused() {
    // §11.18.6.7 step 2: "The public key of the NOC SHALL match the last generated
    // operational public key on this session … If this check fails, the error status SHALL be
    // InvalidPublicKey."
    //
    // This is the step that ties the certificate to a key the *device* made. Without it an
    // administrator could install a NOC over a key pair it generated itself and then
    // impersonate the node to everyone else on the fabric.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(120, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");
    let mut csr_buf = [0u8; 4096];
    invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &octets_field(0, &[0x11; 32]),
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &octets_field(0, RCAC),
        &ctx,
        &mut buf,
    )
    .unwrap_err();

    // A NOC over a key the commissioner made, not the device.
    let mut attacker = Store::new();
    let (_, attacker_public) = attacker
        .generate(KeyPurpose::Operational, &[0x7Cu8; GROUP_SIZE_BYTES])
        .expect("generate");
    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(DEVICE_NODE_ID, attacker_public, &mut noc);

    let add = add_noc_fields(&noc[..noc_len], Some(ICAC), CASE_ADMIN_SUBJECT, 0xFFF1);
    let mut add_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &add,
        &ctx,
        &mut add_buf,
    )
    .expect("noc response");
    assert_eq!(
        noc_response(response).0,
        NocStatus::InvalidPublicKey.value()
    );
    assert!(device.fabrics.borrow().is_empty());
}

#[test]
fn a_failed_add_noc_leaves_the_csr_usable() {
    // §11.18.6.7: "the device … SHALL leave all non-volatile state of the device untouched,
    // as if the AddNOC command had never been received. **The information about the last CSR
    // state associated with this session SHALL also be untouched** in this case, so that a
    // valid AddNOC command MAY still be issued later that would match that CSR state."
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(120, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");
    let csr_fields = octets_field(0, &[0x11; 32]);
    let mut csr_buf = [0u8; 4096];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr_fields,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    let public = nocsr.parse_csr().expect("csr").public_key;
    invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &octets_field(0, RCAC),
        &ctx,
        &mut buf,
    )
    .unwrap_err();

    // A first AddNOC with a subject that is not a valid CASE subject.
    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(DEVICE_NODE_ID, public, &mut noc);
    let noc = &noc[..noc_len];
    let bad = add_noc_fields(noc, Some(ICAC), 0xFFFF_FFFF_FFFF_0001, 0xFFF1);
    let mut bad_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &bad,
        &ctx,
        &mut bad_buf,
    )
    .expect("noc response");
    assert_eq!(
        noc_response(response).0,
        NocStatus::InvalidAdminSubject.value(),
        "a group node id is not a CASE subject"
    );

    // …and the same CSR still works on a second try.
    let good = add_noc_fields(noc, Some(ICAC), CASE_ADMIN_SUBJECT, 0xFFF1);
    let mut good_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &good,
        &ctx,
        &mut good_buf,
    )
    .expect("noc response");
    assert_eq!(noc_response(response).0, NocStatus::Ok.value());
}

#[test]
fn a_second_add_noc_in_one_fail_safe_period_is_a_constraint_error() {
    // §11.18.6.8: "If a prior UpdateNOC or AddNOC command was successfully executed within
    // the fail-safe timer period, then this command SHALL fail with a CONSTRAINT_ERROR."
    // A *status*, not a NOCResponse: the command never runs.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    commission(&device, &challenge);

    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 2048];
    let add = add_noc_fields(RCAC, None, CASE_ADMIN_SUBJECT, 0xFFF1);
    assert_eq!(
        invoke(&device, opcreds::ID, opcreds::ADD_NOC, &add, &ctx, &mut buf).unwrap_err(),
        Status::ConstraintError
    );
    // And a CSRRequest after a NOC command is refused the same way (§11.18.6.5).
    let csr = octets_field(0, &[0x22; 32]);
    assert_eq!(
        invoke(
            &device,
            opcreds::ID,
            opcreds::CSR_REQUEST,
            &csr,
            &ctx,
            &mut buf
        )
        .unwrap_err(),
        Status::ConstraintError
    );
    // …as is a second root (§11.18.6.13).
    let root = octets_field(0, RCAC);
    assert_eq!(
        invoke(
            &device,
            opcreds::ID,
            opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
            &root,
            &ctx,
            &mut buf
        )
        .unwrap_err(),
        Status::ConstraintError
    );
}

#[test]
fn a_csr_for_update_cannot_be_used_by_add_noc() {
    // §11.18.6.8: "If the prior CSRRequest state that preceded AddNOC had the IsForUpdateNOC
    // field indicated as true, then this command SHALL fail with a CONSTRAINT_ERROR." The two
    // commands have different preconditions and different effects; a key tagged for one must
    // not silently serve the other.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    // IsForUpdateNOC over PASE is INVALID_COMMAND outright (§11.18.6.5), so this runs on a
    // session that has a fabric — which means commissioning first.
    let index = commission(&device, &challenge);
    let _ = device.opcreds.take_change();
    complete(&device, index, &challenge, at(1));

    // A second fail-safe period, over CASE on the fabric just joined.
    let ctx = over_case(index.0, &challenge, at(10));
    let mut buf = [0u8; 4096];
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(120, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");

    let csr = fields(|w| {
        w.octets(Tag::Context(0), &[0x33; 32]).expect("nonce");
        w.bool(Tag::Context(1), true).expect("for update");
    });
    let mut csr_buf = [0u8; 4096];
    invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr for update");

    let add = add_noc_fields(RCAC, None, CASE_ADMIN_SUBJECT, 0xFFF1);
    assert_eq!(
        invoke(&device, opcreds::ID, opcreds::ADD_NOC, &add, &ctx, &mut buf).unwrap_err(),
        Status::ConstraintError
    );
}

#[test]
fn is_for_update_noc_over_pase_is_invalid() {
    // §11.18.6.5: "If the IsForUpdateNOC field is present and set to true, but the command was
    // received over a PASE session, the command SHALL fail with an INVALID_COMMAND status
    // code, as it would never be possible to use a resulting subsequent certificate … with
    // the UpdateNOC command, which is forbidden over PASE sessions."
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(120, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");

    let csr = fields(|w| {
        w.octets(Tag::Context(0), &[0x33; 32]).expect("nonce");
        w.bool(Tag::Context(1), true).expect("for update");
    });
    assert_eq!(
        invoke(
            &device,
            opcreds::ID,
            opcreds::CSR_REQUEST,
            &csr,
            &ctx,
            &mut buf
        )
        .unwrap_err(),
        Status::InvalidCommand
    );
}

#[test]
fn an_expired_fail_safe_discards_the_operational_key_it_generated() {
    // §11.10.7.2.2 step 8, seen from the cluster: a `CSRRequest` whose fail-safe lapsed must
    // not leave a usable key behind for the *next* commissioner's `AddNOC`.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(60, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");
    let csr_fields = octets_field(0, &[0x11; 32]);
    let mut csr_buf = [0u8; 4096];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr_fields,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    let stale_public = nocsr.parse_csr().expect("csr").public_key;
    let mut stale_noc = [0u8; CERT_TLV_MAX];
    let stale_len = issue_noc(DEVICE_NODE_ID, stale_public, &mut stale_noc);

    // Time passes; a new commissioner arms a fresh fail-safe.
    let later = over_pase(&challenge, at(100));
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(60, 2),
        &later,
        &mut buf,
    )
    .expect("re-arm");
    invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &octets_field(0, RCAC),
        &later,
        &mut buf,
    )
    .unwrap_err();

    // The NOC minted over the stale key is not accepted: the key is gone.
    let add = add_noc_fields(
        &stale_noc[..stale_len],
        Some(ICAC),
        CASE_ADMIN_SUBJECT,
        0xFFF1,
    );
    let mut add_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &add,
        &later,
        &mut add_buf,
    )
    .expect("noc response");
    assert_eq!(noc_response(response).0, NocStatus::MissingCsr.value());
    assert!(device.fabrics.borrow().is_empty());
}

#[test]
fn certificate_chain_request_returns_the_der_it_was_given() {
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 2048];

    for (kind, expected) in [(1u64, DAC_DER), (2, PAI_DER)] {
        let request = unsigned_field(0, kind);
        let (id, response) = invoke(
            &device,
            opcreds::ID,
            opcreds::CERTIFICATE_CHAIN_REQUEST,
            &request,
            &ctx,
            &mut buf,
        )
        .expect("chain");
        assert_eq!(id, opcreds::CERTIFICATE_CHAIN_RESPONSE);
        assert_eq!(response_octets(response, 0), expected);
    }

    // §11.18.6.3: "If the CertificateType is not a valid value per CertificateChainTypeEnum
    // then the command SHALL fail with a Status Code of INVALID_COMMAND." Zero is not a
    // value — the enumeration starts at one.
    for bad in [0u64, 3, 255] {
        let request = unsigned_field(0, bad);
        assert_eq!(
            invoke(
                &device,
                opcreds::ID,
                opcreds::CERTIFICATE_CHAIN_REQUEST,
                &request,
                &ctx,
                &mut buf
            )
            .unwrap_err(),
            Status::InvalidCommand,
            "CertificateType {bad}"
        );
    }
}

#[test]
fn attestation_response_is_verifiable_and_bound_to_the_session() {
    // §11.18.4.7: the signature is over `attestation_elements_message ||
    // attestation_challenge`, and the challenge "SHALL NOT be included in any of the payloads
    // conveyed". So a response recorded on one session does not verify against another —
    // which is the whole point, and what stops a replayed attestation.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 2048];

    let nonce = [0x5Au8; 32];
    let request = octets_field(0, &nonce);
    let (id, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ATTESTATION_REQUEST,
        &request,
        &ctx,
        &mut buf,
    )
    .expect("attestation");
    assert_eq!(id, opcreds::ATTESTATION_RESPONSE);

    let elements = response_octets(response, 0);
    let signature_bytes = response_octets(response, 1);
    let decoded = matter_kit::attestation::AttestationElements::decode(elements).expect("decode");
    assert_eq!(decoded.attestation_nonce, nonce, "the nonce is echoed");
    assert_eq!(decoded.certification_declaration, CD);

    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_bytes);
    let signature = matter_kit::crypto::Signature::from_bytes(signature);
    let public = owned
        .keys
        .borrow()
        .public_key(owned.dac_key)
        .expect("dac public key");
    assert!(
        matter_kit::attestation::verify_attestation(&public, elements, &challenge, &signature)
            .expect("verify"),
        "the DAC's own signature must verify"
    );
    // …and not under a different session's challenge.
    let other = SymmetricKey::new([0x43; 16]);
    assert!(
        !matter_kit::attestation::verify_attestation(&public, elements, &other, &signature)
            .expect("verify"),
        "a recorded attestation must not verify on another session"
    );
}

#[test]
fn the_attributes_report_what_was_installed() {
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);

    let ctx = over_case(index.0, &challenge, at(1));
    let read = |attribute: u32, ctx: &InteractionContext<'_>| -> Vec<u8> {
        let resolved = device
            .node
            .resolve(0, opcreds::ID, attribute)
            .expect("the path exists");
        let mut buf = [0u8; 2048];
        let mut w = TlvWriter::new(&mut buf);
        device
            .opcreds
            .read(&resolved, ctx, &mut w, Tag::Anonymous)
            .expect("read");
        w.finish().expect("finish").to_vec()
    };

    // CommissionedFabrics and SupportedFabrics.
    let commissioned = read(opcreds::COMMISSIONED_FABRICS, &ctx);
    let mut reader = TlvReader::new(&commissioned);
    assert_eq!(
        reader
            .next_element()
            .expect("read")
            .expect("value")
            .unsigned()
            .expect("uint"),
        1
    );
    let supported = read(opcreds::SUPPORTED_FABRICS, &ctx);
    let mut reader = TlvReader::new(&supported);
    assert_eq!(
        reader
            .next_element()
            .expect("read")
            .expect("value")
            .unsigned()
            .expect("uint"),
        DefaultConfig::FABRICS as u64
    );

    // CurrentFabricIndex is the *accessing* fabric, so a PASE session reads 0 — §11.18.5.6's
    // fallback, and the value that means "no fabric".
    let pase = over_pase(&challenge, at(1));
    let current = read(opcreds::CURRENT_FABRIC_INDEX, &pase);
    let mut reader = TlvReader::new(&current);
    assert_eq!(
        reader
            .next_element()
            .expect("read")
            .expect("value")
            .unsigned()
            .expect("uint"),
        0
    );

    // The Fabrics entry carries the global FabricIndex field at tag 254 (§7.19.1.9), which is
    // *not* in §11.18.4.5's table and must be emitted anyway.
    let fabrics = read(opcreds::FABRICS, &ctx);
    let mut reader = TlvReader::new(&fabrics);
    reader.next_element().expect("read").expect("array");
    reader.next_element().expect("read").expect("struct");
    let mut saw_fabric_index = false;
    let mut saw_node_id = false;
    let depth = reader.depth();
    while let Some(element) = reader.next_element().expect("read") {
        if reader.depth() < depth {
            break;
        }
        match element.tag {
            Tag::Context(3) => assert_eq!(element.unsigned().expect("uint"), FABRIC_ID.0),
            Tag::Context(4) => {
                assert_eq!(element.unsigned().expect("uint"), DEVICE_NODE_ID.0);
                saw_node_id = true;
            }
            Tag::Context(opcreds::FABRIC_INDEX_FIELD) => {
                assert_eq!(element.unsigned().expect("uint"), u64::from(index.0));
                saw_fabric_index = true;
            }
            _ => reader.skip_value(&element).expect("skip"),
        }
    }
    assert!(saw_node_id && saw_fabric_index);
}

#[test]
fn fabric_filtering_decides_which_entries_a_read_sees() {
    // §7.19.1.8.2: "For a read interaction on a list, with fabric-filtering disabled, the list
    // SHALL be reported as a full list with all entries." With it enabled, only the accessing
    // fabric's. §6.4.10 depends on the unfiltered form — its first three steps read NOCs,
    // Fabrics and TrustedRootCertificates "using a non-fabric-filtered read".
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);

    let count = |ctx: &InteractionContext<'_>| -> usize {
        let resolved = device
            .node
            .resolve(0, opcreds::ID, opcreds::FABRICS)
            .expect("path");
        let mut buf = [0u8; 2048];
        let mut w = TlvWriter::new(&mut buf);
        device
            .opcreds
            .read(&resolved, ctx, &mut w, Tag::Anonymous)
            .expect("read");
        let bytes = w.finish().expect("finish").to_vec();
        let mut reader = TlvReader::new(&bytes);
        reader.next_element().expect("read").expect("array");
        let depth = reader.depth();
        let mut entries = 0usize;
        while let Some(element) = reader.next_element().expect("read") {
            if reader.depth() < depth {
                break;
            }
            entries += 1;
            reader.skip_value(&element).expect("skip");
        }
        entries
    };

    // Unfiltered from anywhere: the whole list.
    assert_eq!(count(&over_pase(&challenge, at(1))), 1);
    // Filtered on the fabric itself: its own entry.
    let mine = InteractionContext {
        fabric_filtered: true,
        ..over_case(index.0, &challenge, at(1))
    };
    assert_eq!(count(&mine), 1);
    // Filtered on a fabric that is not this one: nothing.
    let theirs = InteractionContext {
        fabric_filtered: true,
        ..over_case(index.0.wrapping_add(1), &challenge, at(1))
    };
    assert_eq!(count(&theirs), 0);
    // Filtered on a session with no fabric at all: also nothing, which is right — there is no
    // fabric whose entries it is asking for.
    let nobody = InteractionContext {
        fabric_filtered: true,
        ..over_pase(&challenge, at(1))
    };
    assert_eq!(count(&nobody), 0);
}

#[test]
fn remove_fabric_destroys_the_operational_key() {
    // §11.18.6.12: removal deletes "all associated Fabric-Scoped data, including … operational
    // certificates". The key has to actually be destroyed, not merely forgotten: a key that
    // survived removal could still be used to impersonate the node on a fabric it has left.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);
    let _ = device.opcreds.take_change();

    let handle = device
        .fabrics
        .borrow()
        .find(index)
        .expect("fabric")
        .operational_key;
    assert!(device.keys.borrow().public_key(handle).is_ok());

    let ctx = over_case(index.0, &challenge, at(1));
    let mut buf = [0u8; 2048];
    let request = unsigned_field(0, u64::from(index.0));
    let (id, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::REMOVE_FABRIC,
        &request,
        &ctx,
        &mut buf,
    )
    .expect("remove");
    assert_eq!(id, opcreds::NOC_RESPONSE);
    assert_eq!(
        noc_response(response),
        (NocStatus::Ok.value(), Some(index.0))
    );

    assert!(device.fabrics.borrow().is_empty());
    assert!(
        device.keys.borrow().public_key(handle).is_err(),
        "the operational key must be destroyed, not merely dropped from the table"
    );
    assert_eq!(
        device.opcreds.take_change(),
        Some(FabricChange::Removed {
            index,
            was_last: true,
            was_accessing: true,
        })
    );

    // An index that names nothing is InvalidFabricIndex, with no change.
    let request = unsigned_field(0, 7);
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::REMOVE_FABRIC,
        &request,
        &ctx,
        &mut buf,
    )
    .expect("remove");
    assert_eq!(
        noc_response(response).0,
        NocStatus::InvalidFabricIndex.value()
    );
}

#[test]
fn the_cluster_id_and_revision_match_section_11_18() {
    assert_eq!(opcreds::ID, 0x003E);
    assert_eq!(opcreds::REVISION, 2);
    assert_eq!(opcreds::RESP_MAX, 900);
    assert_eq!(
        <OperationalCredentials<'_, DefaultConfig, Store, SimRng, 5> as Cluster>::ID,
        opcreds::ID
    );
    assert!(opcreds::cluster().is_well_formed());
}

#[test]
fn update_noc_rotates_the_identity_and_destroys_the_old_key() {
    // §11.18.6.9: "The Operational Certificate under the accessing fabric index in the NOCs
    // list SHALL be updated … such that the Node's Operational Identifier within the Fabric
    // immediately changes", and step 1.c: "All internal data reflecting the prior operational
    // identifier of the Node within the Fabric SHALL be revoked and removed." The old key is
    // the first of those, and the one whose survival would silently keep the old identity
    // usable.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);
    let _ = device.opcreds.take_change();
    complete(&device, index, &challenge, at(1));

    let old_key = device
        .fabrics
        .borrow()
        .find(index)
        .expect("fabric")
        .operational_key;

    let ctx = over_case(index.0, &challenge, at(10));
    let mut buf = [0u8; 4096];
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(120, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");

    let csr = fields(|w| {
        w.octets(Tag::Context(0), &[0x77; 32]).expect("nonce");
        w.bool(Tag::Context(1), true).expect("for update");
    });
    let mut csr_buf = [0u8; 4096];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    let public = nocsr.parse_csr().expect("csr").public_key;

    // A new node id on the *same* fabric — which is what a key rotation looks like.
    const ROTATED: NodeId = NodeId(0xDEDE_DEDE_0001_0055);
    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(ROTATED, public, &mut noc);
    let update = fields(|w| {
        w.octets(Tag::Context(0), &noc[..noc_len]).expect("noc");
        w.octets(Tag::Context(1), ICAC).expect("icac");
    });
    let mut update_buf = [0u8; 2048];
    let (id, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::UPDATE_NOC,
        &update,
        &ctx,
        &mut update_buf,
    )
    .expect("update");
    assert_eq!(id, opcreds::NOC_RESPONSE);
    assert_eq!(
        noc_response(response),
        (NocStatus::Ok.value(), Some(index.0))
    );

    let fabrics = device.fabrics.borrow();
    let fabric = fabrics.find(index).expect("still there");
    assert_eq!(fabric.node_id, ROTATED);
    assert_ne!(fabric.operational_key, old_key);
    drop(fabrics);
    assert!(
        device.keys.borrow().public_key(old_key).is_err(),
        "the previous operational key must be destroyed"
    );
    assert_eq!(
        device.opcreds.take_change(),
        Some(FabricChange::Updated { index })
    );
}

#[test]
fn update_noc_refuses_a_certificate_for_another_fabric() {
    // §11.18.6.9: "The NOC provided in the NOCValue does not refer in its subject to the
    // FabricID associated with the accessing fabric" is InvalidNOC. Without the check, an
    // administrator could move a node onto a different fabric under the guise of a rotation
    // while keeping the entry — and every ACL entry scoped to the old fabric with it.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);
    let _ = device.opcreds.take_change();
    complete(&device, index, &challenge, at(1));

    // Move the fabric's recorded FabricID out from under the update, which is the same thing
    // as presenting a NOC for a different fabric.
    device
        .fabrics
        .borrow_mut()
        .find_mut(index)
        .expect("fabric")
        .fabric_id = FabricId(0xFAB0_0000_0000_00FF);

    let ctx = over_case(index.0, &challenge, at(10));
    let mut buf = [0u8; 4096];
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(120, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");
    let csr = fields(|w| {
        w.octets(Tag::Context(0), &[0x77; 32]).expect("nonce");
        w.bool(Tag::Context(1), true).expect("for update");
    });
    let mut csr_buf = [0u8; 4096];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    let public = nocsr.parse_csr().expect("csr").public_key;
    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(DEVICE_NODE_ID, public, &mut noc);
    let update = fields(|w| {
        w.octets(Tag::Context(0), &noc[..noc_len]).expect("noc");
        w.octets(Tag::Context(1), ICAC).expect("icac");
    });
    let mut update_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::UPDATE_NOC,
        &update,
        &ctx,
        &mut update_buf,
    )
    .expect("update");
    assert_eq!(noc_response(response).0, NocStatus::InvalidNoc.value());
}

#[test]
fn update_fabric_label_refuses_a_label_another_fabric_holds() {
    // §11.18.6.11: "If the Label field is identical to a Label already in use by a Fabric
    // within the Fabrics list **that is not the accessing fabric** … LabelConflict." Labels
    // are how a user tells administrators apart, so two fabrics sharing one is a phishing
    // surface, not a cosmetic problem.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);
    let _ = device.opcreds.take_change();

    let ctx = over_case(index.0, &challenge, at(1));
    let mut buf = [0u8; 2048];
    let label = fields(|w| {
        w.utf8(Tag::Context(0), "Living room").expect("label");
    });
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::UPDATE_FABRIC_LABEL,
        &label,
        &ctx,
        &mut buf,
    )
    .expect("label");
    assert_eq!(
        noc_response(response),
        (NocStatus::Ok.value(), Some(index.0))
    );
    assert_eq!(
        device.fabrics.borrow().find(index).expect("fabric").label,
        "Living room"
    );

    // Re-setting the *same* label on the *same* fabric is fine: the conflict rule names
    // fabrics that are "not the accessing fabric".
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::UPDATE_FABRIC_LABEL,
        &label,
        &ctx,
        &mut buf,
    )
    .expect("label");
    assert_eq!(noc_response(response).0, NocStatus::Ok.value());

    // A second fabric may not take it.
    let second = FabricIndex(index.0.wrapping_add(1));
    {
        let mut table = device.fabrics.borrow_mut();
        let mut clone = table.find(index).expect("fabric").clone();
        clone.index = second;
        clone.node_id = NodeId(0xDEDE_DEDE_0001_0099);
        clone.label.clear();
        table.insert(clone).expect("second fabric");
    }
    let other = over_case(second.0, &challenge, at(2));
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::UPDATE_FABRIC_LABEL,
        &label,
        &other,
        &mut buf,
    )
    .expect("label");
    assert_eq!(noc_response(response).0, NocStatus::LabelConflict.value());
}

#[test]
fn sign_vid_verification_binds_the_fabric_to_the_session() {
    // §6.4.10 / §11.18.6.16. The server signs
    // `fabric_binding_version || client_challenge || attestation_challenge || fabric_index ||
    // vendor_fabric_binding_message || <vid_verification_statement>` with the *operational*
    // key — a statement about the fabric, not about the hardware. The attestation challenge
    // is what makes it unreplayable.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);
    let _ = device.opcreds.take_change();

    let ctx = over_case(index.0, &challenge, at(1));
    let mut buf = [0u8; 2048];
    let client_challenge = [0x9Au8; 32];
    let request = fields(|w| {
        w.unsigned(Tag::Context(0), u64::from(index.0))
            .expect("index");
        w.octets(Tag::Context(1), &client_challenge)
            .expect("challenge");
    });
    let (id, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::SIGN_VID_VERIFICATION_REQUEST,
        &request,
        &ctx,
        &mut buf,
    )
    .expect("sign");
    assert_eq!(id, opcreds::SIGN_VID_VERIFICATION_RESPONSE);

    let mut reader = TlvReader::new_in(response, ContainerKind::Structure);
    reader.next_element().expect("read").expect("struct");
    let echoed = reader.next_element().expect("read").expect("index");
    assert_eq!(echoed.unsigned().expect("uint"), u64::from(index.0));
    let version = reader.next_element().expect("read").expect("version");
    assert_eq!(
        version.unsigned().expect("uint"),
        u64::from(matter_kit::fabric::FABRIC_BINDING_VERSION),
        "0x01 for version 1.0 of the Matter Cryptographic Primitives"
    );
    let signature_bytes = response_octets(response, 2);

    // Rebuild the message the way a verifier would (§6.4.10.1 steps 8 to 10) and check it.
    let fabrics = device.fabrics.borrow();
    let fabric = fabrics.find(index).expect("fabric");
    let mut tbs_buf = [0u8; matter_kit::fabric::VENDOR_ID_VERIFICATION_TBS_MAX];
    let tbs = matter_kit::fabric::vendor_id_verification_tbs(
        &mut tbs_buf,
        (&client_challenge, &challenge),
        index,
        &matter_kit::fabric::VendorIdBinding {
            root_public_key: &fabric.root_public_key,
            fabric_id: fabric.fabric_id,
            vendor_id: fabric.admin_vendor_id,
            statement: None,
        },
    );
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_bytes);
    let signature = matter_kit::crypto::Signature::from_bytes(signature);
    let public = device
        .keys
        .borrow()
        .public_key(fabric.operational_key)
        .expect("operational public key");
    assert!(
        matter_kit::crypto::verify(&public, tbs, &signature).expect("verify"),
        "the response must verify under the fabric's own operational key"
    );

    // …and not under a different client challenge, which is what replaying one would be.
    let mut other_buf = [0u8; matter_kit::fabric::VENDOR_ID_VERIFICATION_TBS_MAX];
    let other = matter_kit::fabric::vendor_id_verification_tbs(
        &mut other_buf,
        (&[0x00u8; 32], &challenge),
        index,
        &matter_kit::fabric::VendorIdBinding {
            root_public_key: &fabric.root_public_key,
            fabric_id: fabric.fabric_id,
            vendor_id: fabric.admin_vendor_id,
            statement: None,
        },
    );
    assert!(!matter_kit::crypto::verify(&public, other, &signature).expect("verify"));
}

#[test]
fn set_vid_verification_statement_enforces_its_lengths() {
    // §11.18.6.14: "If the length of the field's value is neither exactly 0 nor exactly 85,
    // then the command SHALL fail with a status code of CONSTRAINT_ERROR", and a zero-length
    // value erases rather than stores.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);
    let _ = device.opcreds.take_change();

    let ctx = over_case(index.0, &challenge, at(1));
    let mut buf = [0u8; 2048];

    let statement = [0x21u8; matter_kit::fabric::VID_VERIFICATION_STATEMENT_LEN];
    let set = octets_field(1, &statement);
    invoke(
        &device,
        opcreds::ID,
        opcreds::SET_VID_VERIFICATION_STATEMENT,
        &set,
        &ctx,
        &mut buf,
    )
    .unwrap_err(); // no response command: SUCCESS is a status
    assert_eq!(
        device
            .fabrics
            .borrow()
            .find(index)
            .expect("fabric")
            .vid_verification_statement,
        Some(statement)
    );

    for bad in [1usize, 84, 86] {
        let wrong = vec![0u8; bad];
        let set = octets_field(1, &wrong);
        assert_eq!(
            invoke(
                &device,
                opcreds::ID,
                opcreds::SET_VID_VERIFICATION_STATEMENT,
                &set,
                &ctx,
                &mut buf
            )
            .unwrap_err(),
            Status::ConstraintError,
            "a {bad}-octet statement"
        );
    }
    // Still the good one: a refused command changes nothing.
    assert_eq!(
        device
            .fabrics
            .borrow()
            .find(index)
            .expect("fabric")
            .vid_verification_statement,
        Some(statement)
    );

    // Zero erases.
    let erase = octets_field(1, &[]);
    invoke(
        &device,
        opcreds::ID,
        opcreds::SET_VID_VERIFICATION_STATEMENT,
        &erase,
        &ctx,
        &mut buf,
    )
    .unwrap_err();
    assert!(
        device
            .fabrics
            .borrow()
            .find(index)
            .expect("fabric")
            .vid_verification_statement
            .is_none()
    );

    // A VVSC alongside an ICAC is INVALID_COMMAND (§11.18.4.4's mutual exclusion): the fabric
    // commissioned above has an ICAC.
    let vvsc = octets_field(2, RCAC);
    assert_eq!(
        invoke(
            &device,
            opcreds::ID,
            opcreds::SET_VID_VERIFICATION_STATEMENT,
            &vvsc,
            &ctx,
            &mut buf
        )
        .unwrap_err(),
        Status::InvalidCommand
    );
}

#[test]
fn a_root_from_a_lapsed_fail_safe_does_not_carry_over() {
    // §11.18.6.13: "the only method of removing a trusted root is by removing the Fabric that
    // uses it". So a root installed under a fail-safe that then expired must never have been
    // installed at all — otherwise a commissioner that walked away would leave behind a root
    // the *next* one could build a fabric on without ever presenting it.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(60, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");
    invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &octets_field(0, RCAC),
        &ctx,
        &mut buf,
    )
    .unwrap_err();

    // The fail-safe lapses; a second commissioner arrives and does everything *except*
    // install a root.
    let later = over_pase(&challenge, at(100));
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(60, 2),
        &later,
        &mut buf,
    )
    .expect("re-arm");
    let csr_fields = octets_field(0, &[0x44; 32]);
    let mut csr_buf = [0u8; 4096];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr_fields,
        &later,
        &mut csr_buf,
    )
    .expect("csr");
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    let public = nocsr.parse_csr().expect("csr").public_key;
    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(DEVICE_NODE_ID, public, &mut noc);

    let add = add_noc_fields(&noc[..noc_len], Some(ICAC), CASE_ADMIN_SUBJECT, 0xFFF1);
    let mut add_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &add,
        &later,
        &mut add_buf,
    )
    .expect("noc response");
    assert_eq!(noc_response(response).0, NocStatus::InvalidNoc.value());
    assert!(device.fabrics.borrow().is_empty());
}

#[test]
fn a_second_fabric_on_the_same_root_and_fabric_id_is_a_conflict() {
    // §11.18.6.8: "If the NOC provided in the NOCValue encodes an Operational Identifier for a
    // <Root Public Key, FabricID> pair already present on the device … FabricConflict",
    // whose summary is explicit about why: "Trying to AddNOC instead of UpdateNOC against an
    // existing Fabric." Two entries a peer cannot tell apart is the outcome to avoid.
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);
    let _ = device.opcreds.take_change();
    complete(&device, index, &challenge, at(1));

    // A second commissioner, a second fail-safe, the same root and fabric.
    let ctx = over_pase(&challenge, at(10));
    let mut buf = [0u8; 4096];
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(120, 1),
        &ctx,
        &mut buf,
    )
    .expect("arm");
    let csr_fields = octets_field(0, &[0x66; 32]);
    let mut csr_buf = [0u8; 4096];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::CSR_REQUEST,
        &csr_fields,
        &ctx,
        &mut csr_buf,
    )
    .expect("csr");
    let elements = response_octets(response, 0);
    let nocsr = matter_kit::attestation::nocsr::NocsrElements::decode(elements).expect("nocsr");
    let public = nocsr.parse_csr().expect("csr").public_key;
    invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &octets_field(0, RCAC),
        &ctx,
        &mut buf,
    )
    .unwrap_err();

    let mut noc = [0u8; CERT_TLV_MAX];
    let noc_len = issue_noc(NodeId(0xDEDE_DEDE_0001_00BB), public, &mut noc);
    let add = add_noc_fields(&noc[..noc_len], Some(ICAC), CASE_ADMIN_SUBJECT, 0xFFF1);
    let mut add_buf = [0u8; 2048];
    let (_, response) = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_NOC,
        &add,
        &ctx,
        &mut add_buf,
    )
    .expect("noc response");
    assert_eq!(noc_response(response).0, NocStatus::FabricConflict.value());
    assert_eq!(device.fabrics.borrow().len(), 1);
}

#[test]
fn the_attribute_qualities_match_section_11_18_5() {
    use matter_kit::dm::{AttributeQualities, Reporting};

    let cluster = opcreds::cluster();
    // `NOCs` is `CN`: changes omitted *and* non-volatile.
    let nocs = cluster.attribute(opcreds::NOCS).expect("NOCs");
    assert_eq!(nocs.reporting, Reporting::ChangesOmitted);
    assert!(nocs.qualities.contains(AttributeQualities::NON_VOLATILE));
    // `RAF`: Administer to read, and fabric-scoped.
    assert_eq!(nocs.access.read, Some(Privilege::Administer));
    assert!(nocs.access.is_fabric_scoped());

    // `Fabrics` is `RVF` — View, not Administer. A fabric's existence and label are public to
    // anyone with View; its certificates are not.
    let fabrics = cluster.attribute(opcreds::FABRICS).expect("Fabrics");
    assert_eq!(fabrics.access.read, Some(Privilege::View));
    assert!(fabrics.access.is_fabric_scoped());

    // `TrustedRootCertificates` is `CN` too, and *not* fabric-scoped: §6.4.10 reads it whole.
    let roots = cluster
        .attribute(opcreds::TRUSTED_ROOT_CERTIFICATES)
        .expect("roots");
    assert_eq!(roots.reporting, Reporting::ChangesOmitted);
    assert!(!roots.access.is_fabric_scoped());

    // `SupportedFabrics` is `F`.
    let supported = cluster
        .attribute(opcreds::SUPPORTED_FABRICS)
        .expect("supported");
    assert!(supported.qualities.contains(AttributeQualities::FIXED));

    // §11.18.6: AddNOC and RemoveFabric are `A`, not `AF` — the first runs over PASE before
    // any fabric exists, the second may target a fabric other than the caller's.
    for id in [opcreds::ADD_NOC, opcreds::REMOVE_FABRIC] {
        let command = cluster.accepted_command(id).expect("command");
        assert_eq!(command.access.invoke, Some(Privilege::Administer));
        assert!(
            !command.access.is_fabric_scoped(),
            "{id:#04x} must not be AF"
        );
    }
    // …and UpdateNOC, UpdateFabricLabel and SetVIDVerificationStatement are `AF`.
    for id in [
        opcreds::UPDATE_NOC,
        opcreds::UPDATE_FABRIC_LABEL,
        opcreds::SET_VID_VERIFICATION_STATEMENT,
    ] {
        let command = cluster.accepted_command(id).expect("command");
        assert!(command.access.is_fabric_scoped(), "{id:#04x} must be AF");
    }
    // AddTrustedRootCertificate and SetVIDVerificationStatement have no response command.
    for id in [
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        opcreds::SET_VID_VERIFICATION_STATEMENT,
    ] {
        assert_eq!(
            cluster.accepted_command(id).expect("command").response,
            None
        );
    }
}

#[test]
fn the_noc_status_values_match_section_11_18_4_3() {
    // The table, as literals — including the gap: 7 and 8 are not assigned, and inventing
    // them would put a status on the wire that no client can name.
    assert_eq!(NocStatus::Ok.value(), 0);
    assert_eq!(NocStatus::InvalidPublicKey.value(), 1);
    assert_eq!(NocStatus::InvalidNodeOpId.value(), 2);
    assert_eq!(NocStatus::InvalidNoc.value(), 3);
    assert_eq!(NocStatus::MissingCsr.value(), 4);
    assert_eq!(NocStatus::TableFull.value(), 5);
    assert_eq!(NocStatus::InvalidAdminSubject.value(), 6);
    assert_eq!(NocStatus::FabricConflict.value(), 9);
    assert_eq!(NocStatus::LabelConflict.value(), 10);
    assert_eq!(NocStatus::InvalidFabricIndex.value(), 11);

    // §11.18.4.2's CertificateChainTypeEnum starts at 1.
    assert_eq!(opcreds::CertificateChainType::from_value(0), None);
    assert_eq!(
        opcreds::CertificateChainType::from_value(1),
        Some(opcreds::CertificateChainType::Dac)
    );
    assert_eq!(
        opcreds::CertificateChainType::from_value(2),
        Some(opcreds::CertificateChainType::Pai)
    );
    assert_eq!(opcreds::CertificateChainType::from_value(3), None);
}

/// The step that keeps a freshly commissioned node administrable (§11.18.6.8 step 7).
///
/// `AddNOC` reports a `CaseAdminSubject`, and the device must turn it into an Access Control
/// entry. This test is the whole point of that step: before it, the commissioner's only
/// standing is §6.6.6.2's implicit PASE grant, which evaporates with the session. After it,
/// the administrator named in the command can administer over CASE.
///
/// Skipping it is the failure with no symptom — the fabric is joined, the node advertises
/// itself, `CommissioningComplete` succeeds, and the device is then permanently beyond
/// anyone's reach.
#[test]
fn the_case_admin_subject_becomes_the_entry_that_keeps_the_node_administrable() {
    use matter_kit::acl::{Acl, SubjectDescriptor};
    use matter_kit::config::DefaultConfig;
    use matter_kit::dm::Privilege;
    use matter_kit::msg::NodeId;

    type TestAcl = Acl<
        DefaultConfig,
        { DefaultConfig::ACL_ENTRIES },
        { DefaultConfig::ACL_SUBJECTS },
        { DefaultConfig::ACL_TARGETS },
    >;

    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);

    let Some(FabricChange::Added {
        case_admin_subject, ..
    }) = device.opcreds.take_change()
    else {
        panic!("AddNOC reports the subject the device must grant");
    };

    // A node fresh out of commissioning has an empty list, so the administrator has nothing.
    let mut acl = TestAcl::new();
    let admin = SubjectDescriptor::case(index, NodeId(case_admin_subject));
    let node = matter_kit::dm::Node::new(&[]);
    assert!(
        acl.granted(&node, &admin, 0, 0x001F).is_empty(),
        "before step 7 there is no standing at all"
    );

    // Step 7.
    acl.add_admin_for_fabric(index, NodeId(case_admin_subject))
        .expect("the reported subject is a valid one");

    assert!(
        acl.granted(&node, &admin, 0, 0x001F)
            .has(Privilege::Administer),
        "and after it, the named administrator can administer over CASE"
    );
    // Scoped to the fabric it joined, and to no other.
    let elsewhere = SubjectDescriptor::case(FabricIndex(2), NodeId(case_admin_subject));
    assert!(acl.granted(&node, &elsewhere, 0, 0x001F).is_empty());
}

#[test]
fn a_trusted_root_with_a_broken_signature_is_refused() {
    // §11.18.6.13: a certificate that "fails any validity checks" is `INVALID_COMMAND`, and the
    // signature is a validity check. This is the *only* moment it can be one: §6.4.5.3 trusts a
    // root by provenance, so nothing downstream ever verifies it — `verify_chain` checks the
    // NOC and the ICAC against this root's public key and takes the root itself as given.
    //
    // So a root accepted here with a corrupt signature is accepted for the life of the fabric,
    // and every certificate issued under it verifies perfectly. The CHIP certification suite
    // asks this directly, and reported the crate's answer as "Unexpected success adding trusted
    // root cert with malformed signature".
    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    let armed = arm_fail_safe_fields(120, 1);
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &armed,
        &ctx,
        &mut buf,
    )
    .expect("arm");

    // The signature is the last element of the Matter certificate TLV (tag 11), so flipping a
    // bit in the final octets leaves a structurally perfect certificate whose signature is
    // wrong — which is exactly the case that used to pass.
    let mut broken = RCAC.to_vec();
    let last = broken.len() - 2;
    broken[last] ^= 0x01;
    assert_ne!(
        broken.as_slice(),
        RCAC,
        "the corruption must change something"
    );

    let fields = octets_field(0, &broken);
    let mut root_buf = [0u8; 2048];
    assert_eq!(
        invoke(
            &device,
            opcreds::ID,
            opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
            &fields,
            &ctx,
            &mut root_buf,
        )
        .unwrap_err(),
        Status::InvalidCommand,
        "a root whose self-signature does not verify was installed"
    );

    // And the untouched one still works, so the check rejects the forgery rather than the form.
    let fields = octets_field(0, RCAC);
    let mut ok_buf = [0u8; 2048];
    assert_eq!(
        invoke(
            &device,
            opcreds::ID,
            opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
            &fields,
            &ctx,
            &mut ok_buf,
        )
        .unwrap_err(),
        Status::Success,
        "a valid root must still install"
    );
}

#[test]
fn a_trusted_root_appears_in_the_attribute_before_add_noc_commits_it() {
    // §11.18.6.13: "This command SHALL add a Trusted Root CA Certificate … **to the
    // TrustedRootCertificates Attribute list**". Present tense, and the list is the attribute
    // — so the root is there the moment the command succeeds, not when `AddNOC` commits it to
    // a fabric.
    //
    // That is the order an administrator works in: add the root, read the attribute back to
    // confirm the node took it, then send `AddNOC`. A node that lists only committed roots
    // answers that read with the root missing, having just answered SUCCESS to the command that
    // added it — which `TC_OPCREDS_3_1` reports as "1 != 2 Unexpected number of entries in the
    // TrustedRootCertificates table".
    use matter_kit::im::ClusterHandler;

    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let ctx = over_pase(&challenge, at(0));
    let mut buf = [0u8; 4096];

    let armed = arm_fail_safe_fields(120, 1);
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &armed,
        &ctx,
        &mut buf,
    )
    .expect("arm");

    let read_roots = |device: &Device<'_>| -> Vec<Vec<u8>> {
        let mut out = [0u8; 4096];
        let mut w = TlvWriter::new(&mut out);
        let descriptor = opcreds::cluster();
        let resolved = matter_kit::dm::Resolved {
            endpoint: 0,
            cluster: &descriptor,
            attribute: opcreds::TRUSTED_ROOT_CERTIFICATES,
        };
        device
            .opcreds
            .read(&resolved, &ctx, &mut w, Tag::Anonymous)
            .expect("read TrustedRootCertificates");
        let bytes = w.finish().expect("finish");
        let mut reader = TlvReader::new(bytes);
        let mut roots = Vec::new();
        // The array's own control octet, then its members until the end-of-container.
        let _array = reader.next_element().expect("array").expect("present");
        while let Some(element) = reader.next_element().expect("element") {
            let Ok(octets) = element.octets() else {
                break; // the end-of-container that closes the array
            };
            roots.push(octets.to_vec());
        }
        roots
    };

    assert!(
        read_roots(&device).is_empty(),
        "a factory-new node has no roots"
    );

    let fields = octets_field(0, RCAC);
    let mut root_buf = [0u8; 2048];
    assert_eq!(
        invoke(
            &device,
            opcreds::ID,
            opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
            &fields,
            &ctx,
            &mut root_buf,
        )
        .unwrap_err(),
        Status::Success,
    );

    // The command said SUCCESS, so the attribute has to say so too — before any `AddNOC`.
    let roots = read_roots(&device);
    assert_eq!(roots.len(), 1, "the root the node just accepted is missing");
    assert_eq!(roots[0], RCAC, "and it is the root that was added");

    // …and it is gone the moment the fail-safe that added it ends. §11.10.7.2.2 step 9 removes
    // trusted roots no fabric references, and `ArmFailSafe(0)` is an expiry like any other.
    // `reap` does the actual removal on the next *invoke*, so a read arriving before that must
    // not report a root the node has already promised to have dropped — which is exactly what
    // `TC_OPCREDS_3_1` reads immediately after disarming.
    let disarm = arm_fail_safe_fields(0, 0);
    let mut disarm_buf = [0u8; 2048];
    let _ = invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &disarm,
        &ctx,
        &mut disarm_buf,
    );
    assert!(
        read_roots(&device).is_empty(),
        "a root whose fail-safe rolled back is still in the attribute"
    );
}

#[test]
fn a_rolled_back_root_is_gone_even_after_the_next_fail_safe_is_armed() {
    // The in-process reproduction of what `TC_OPCREDS_3_1` step 34 checks, and the reason to
    // write it rather than run the container again: the same question, in milliseconds.
    //
    // A node is commissioned, so one root is committed. A second fail-safe adds another root
    // and then disarms without committing it — §11.10.7.2.2 step 9 removes trusted roots no
    // fabric references. Hiding the root while the fail-safe is disarmed is not enough: the
    // next `ArmFailSafe` would bring it back, because `reap` only runs on an *invoke* against
    // this cluster and `ArmFailSafe` belongs to General Commissioning. It has to be *gone*.
    use matter_kit::im::ClusterHandler;

    let owned = owned();
    let device = device(&owned);
    let challenge = SymmetricKey::new([0x42; 16]);
    let index = commission(&device, &challenge);
    assert_eq!(index, FabricIndex(1));

    // §11.18.6.8 step 10 binds the accessing session to the fabric `AddNOC` just created, so
    // every command after it arrives with that accessing fabric. Without modelling that, the
    // fail-safe belongs to fabric 1 and this context to nobody, and §11.10.7.2 correctly
    // refuses to let a stranger disarm somebody else's commissioning.
    let ctx = over_case(index.0, &challenge, at(0));
    let read_roots = |device: &Device<'_>, ctx: &InteractionContext<'_>| -> usize {
        let mut out = [0u8; 4096];
        let mut w = TlvWriter::new(&mut out);
        let descriptor = opcreds::cluster();
        let resolved = matter_kit::dm::Resolved {
            endpoint: 0,
            cluster: &descriptor,
            attribute: opcreds::TRUSTED_ROOT_CERTIFICATES,
        };
        device
            .opcreds
            .read(&resolved, ctx, &mut w, Tag::Anonymous)
            .expect("read");
        let bytes = w.finish().expect("finish");
        let mut reader = TlvReader::new(bytes);
        let _array = reader.next_element().expect("array").expect("present");
        let mut n = 0;
        while let Some(element) = reader.next_element().expect("element") {
            if element.octets().is_err() {
                break;
            }
            n += 1;
        }
        n
    };

    assert_eq!(
        read_roots(&device, &ctx),
        1,
        "the commissioned fabric's root"
    );

    // End the commissioning fail-safe. Without this the next `ArmFailSafe` re-arms the *same*
    // context, whose progress already records an `AddNOC`, and §11.18.6.13 then refuses the
    // root with `CONSTRAINT_ERROR` — correctly. `CommissioningComplete` is the real way, and it
    // cannot run over PASE (§11.10.7.6), so this disarms instead.
    let mut done = [0u8; 4096];
    let _ = invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &arm_fail_safe_fields(0, 0),
        &ctx,
        &mut done,
    );

    // A second fail-safe adds a root and abandons it.
    let mut buf = [0u8; 4096];
    let armed = arm_fail_safe_fields(120, 1);
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &armed,
        &ctx,
        &mut buf,
    )
    .expect("arm again");
    let fields = octets_field(0, RCAC);
    let mut root_buf = [0u8; 2048];
    let _ = invoke(
        &device,
        opcreds::ID,
        opcreds::ADD_TRUSTED_ROOT_CERTIFICATE,
        &fields,
        &ctx,
        &mut root_buf,
    );
    assert_eq!(read_roots(&device, &ctx), 2, "committed plus pending");

    // `ArmFailSafe(0)` — §11.10.7.2.2's rollback.
    let disarm = arm_fail_safe_fields(0, 0);
    let mut disarm_buf = [0u8; 2048];
    let _ = invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &disarm,
        &ctx,
        &mut disarm_buf,
    );
    assert_eq!(
        read_roots(&device, &ctx),
        1,
        "the abandoned root is still listed after rollback"
    );

    // And arming again must not resurrect it. This is the step the container run failed on.
    let armed = arm_fail_safe_fields(120, 1);
    let mut again = [0u8; 4096];
    invoke(
        &device,
        general_commissioning::ID,
        general_commissioning::ARM_FAIL_SAFE,
        &armed,
        &ctx,
        &mut again,
    )
    .expect("arm a third time");
    assert_eq!(
        read_roots(&device, &ctx),
        1,
        "a rolled-back root came back when the next fail-safe was armed"
    );
}
