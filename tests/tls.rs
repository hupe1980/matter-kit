//! TLS Certificate Management and TLS Client Management (Core ch. 14).
//!
//! Chapter 14 writes every command as an ordered list of checks, each with its own status code,
//! and the order is load-bearing: `ProvisionRootCertificate` refuses a duplicate certificate
//! *before* it looks at whether the table is full, so a fabric that is out of room and sends a
//! certificate it already has is told `ALREADY_EXISTS`, not `RESOURCE_EXHAUSTED`. This file
//! walks each list.
//!
//! Two things beyond that:
//!
//! * **Every fabric-scoped miss is `NOT_FOUND`.** Not `UNSUPPORTED_ACCESS` — answering "exists,
//!   but not yours" would tell one administrator how many certificates another had provisioned.
//! * **The two clusters interlock.** A root certificate an endpoint still names cannot be
//!   removed (§14.4.6.7), and an endpoint naming a certificate that does not exist cannot be
//!   provisioned (§14.5.7.1). Each check reads the other cluster's table.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::clusters::tls::certificate_management::{self as cert, CertificateManagement};
use matter_kit::clusters::tls::client_management::{
    self as client, ClientManagement, StatusCodeEnum,
};
use matter_kit::clusters::tls::{Slot, TlsCertificateHooks, TlsTables, fingerprint};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{ClusterHandler, InteractionContext, Status, StatusIb};
use matter_kit::msg::FabricIndex;
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

const F1: FabricIndex = FabricIndex(1);
const F2: FabricIndex = FabricIndex(2);

/// A certificate store in a `Vec`, plus knobs for the two cryptographic judgements.
#[derive(Debug, Default)]
struct Store {
    slots: RefCell<Vec<(Slot, Vec<u8>)>>,
    keys: RefCell<Vec<u16>>,
    /// A certificate starting with these bytes is refused as invalid.
    reject_keys: RefCell<bool>,
}

impl Store {
    fn get(&self, slot: Slot) -> Option<Vec<u8>> {
        self.slots
            .borrow()
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, der)| der.clone())
    }
}

impl TlsCertificateHooks for Store {
    fn is_valid_certificate(&self, der: &[u8]) -> bool {
        // Chapter 14 is Web PKI, not Matter's own profile, so "valid" is the product's. Here it
        // is a marker, so a test can produce an invalid certificate on demand.
        !der.starts_with(b"BAD")
    }

    fn save(&self, slot: Slot, der: &[u8]) -> Result<(), Status> {
        let mut slots = self.slots.borrow_mut();
        slots.retain(|(s, _)| *s != slot);
        slots.push((slot, der.to_vec()));
        Ok(())
    }

    fn write_certificate(&self, slot: Slot, w: &mut TlvWriter<'_>, tag: Tag) -> Result<(), Status> {
        let der = self.get(slot).ok_or(Status::Failure)?;
        w.octets(tag, &der).map_err(|_| Status::ResourceExhausted)
    }

    fn clear(&self, slot: Slot) {
        self.slots.borrow_mut().retain(|(s, _)| *s != slot);
    }

    fn generate_key(&self, ccdid: u16) -> Result<(), Status> {
        if *self.reject_keys.borrow() {
            // §14.4.6.8's key-collision path.
            return Err(Status::DynamicConstraintError);
        }
        self.keys.borrow_mut().push(ccdid);
        Ok(())
    }

    fn write_csr(
        &self,
        ccdid: u16,
        nonce: &[u8],
        w: &mut TlvWriter<'_>,
        csr_tag: Tag,
        signature_tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: matter_kit::Result<()>| r.map_err(|_| Status::Failure);
        full(w.octets(csr_tag, &[b'C', b'S', b'R', ccdid as u8]))?;
        full(w.octets(signature_tag, nonce))
    }

    fn key_matches(&self, ccdid: u16, certificate: &[u8]) -> bool {
        // A certificate whose last octet names the CCDID it was issued for.
        certificate.last() == Some(&(ccdid as u8))
    }

    fn remove_key(&self, ccdid: u16) {
        self.keys.borrow_mut().retain(|k| *k != ccdid);
    }
}

type Tables = TlsTables<8, 8, 8>;
type Certificates<'a> = CertificateManagement<'a, Store, 8, 8, 8>;
type Endpoints<'a> = ClientManagement<'a, 8, 8, 8>;

/// A node holding both clusters on the root endpoint, as §14.5 requires.
fn node() -> Node<'static> {
    let certificates = Box::leak(Box::new(
        Certificates::conforming(0, &Optional::NONE).expect("sized"),
    ));
    let endpoints = Box::leak(Box::new(
        Endpoints::conforming(0, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] = Box::leak(Box::new([
        certificates.descriptor(),
        endpoints.descriptor(),
    ]));
    let endpoint_list: &'static [Endpoint<'static>] =
        Box::leak(Box::new([Endpoint::new(0, clusters)]));
    Node::new(endpoint_list)
}

/// A context on `fabric`, with the Large Message transport the `L` commands need.
fn on(fabric: FabricIndex) -> InteractionContext<'static> {
    InteractionContext::default()
        .with_fabric(fabric)
        .with_large_messages()
}

/// What an invoke returned: the response fields, decoded into a flat list of `(tag, value)`.
type Fields = Vec<(u8, Decoded)>;

#[derive(Debug, Clone, PartialEq)]
enum Decoded {
    Unsigned(u64),
    Octets(Vec<u8>),
    Null,
    /// A list of structures, each flattened the same way.
    List(Vec<Fields>),
    /// A nested structure.
    Struct(Fields),
}

fn invoke<H: ClusterHandler>(
    node: &Node<'_>,
    handler: &H,
    cluster: u32,
    command: u32,
    fields: &[u8],
    ctx: &InteractionContext<'_>,
) -> Result<Fields, StatusIb> {
    let resolved = node
        .resolve_command(0, cluster, command)
        .expect("the command exists");
    let mut buf = [0u8; 4096];
    let mut w = TlvWriter::new(&mut buf);
    // A command with no response command writes nothing, and an empty writer has no top-level
    // element to finish.
    if handler
        .invoke(&resolved, Some(fields), ctx, &mut w, Tag::Anonymous)?
        .is_none()
    {
        return Ok(Vec::new());
    }
    let bytes = w.finish().expect("finish").to_vec();
    Ok(decode_structure(&mut TlvReader::new(&bytes)))
}

fn read<H: ClusterHandler>(
    node: &Node<'_>,
    handler: &H,
    cluster: u32,
    attribute: u32,
    ctx: &InteractionContext<'_>,
) -> Result<Vec<u8>, Status> {
    let resolved = node
        .resolve(0, cluster, attribute)
        .expect("the path exists");
    let mut buf = [0u8; 4096];
    let mut w = TlvWriter::new(&mut buf);
    handler.read(&resolved, ctx, &mut w, Tag::Anonymous)?;
    Ok(w.finish().expect("finish").to_vec())
}

/// Reads a structure whose opening element is the reader's next.
fn decode_structure(reader: &mut TlvReader<'_>) -> Fields {
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Structure));
    decode_members(reader)
}

fn decode_members(reader: &mut TlvReader<'_>) -> Fields {
    let mut out = Vec::new();
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        let tag = field.tag.context().unwrap_or(255);
        let value = match &field.value {
            Value::Unsigned(v) => Decoded::Unsigned(*v),
            Value::Octets(v) => Decoded::Octets(v.to_vec()),
            Value::Null => Decoded::Null,
            _ if field.value.container() == Some(ContainerKind::Array) => {
                let mut items = Vec::new();
                loop {
                    let item = reader.next_element().unwrap().unwrap();
                    if item.value == Value::EndOfContainer {
                        break;
                    }
                    match &item.value {
                        Value::Octets(v) => items.push(vec![(255, Decoded::Octets(v.to_vec()))]),
                        _ => items.push(decode_members(reader)),
                    }
                }
                Decoded::List(items)
            }
            _ if field.value.container() == Some(ContainerKind::Structure) => {
                Decoded::Struct(decode_members(reader))
            }
            other => panic!("unexpected value {other:?}"),
        };
        out.push((tag, value));
    }
    out
}

/// Builds a command payload from `(tag, value)` pairs.
enum Arg<'a> {
    U(u64),
    O(&'a [u8]),
    Null,
    Octets(&'a [&'a [u8]]),
}

fn payload(args: &[(u8, Arg<'_>)]) -> Vec<u8> {
    let mut buf = [0u8; 4096];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    for (tag, arg) in args {
        match arg {
            Arg::U(v) => w.unsigned(Tag::Context(*tag), *v).unwrap(),
            Arg::O(v) => w.octets(Tag::Context(*tag), v).unwrap(),
            Arg::Null => w.null(Tag::Context(*tag)).unwrap(),
            Arg::Octets(list) => {
                w.start_array(Tag::Context(*tag)).unwrap();
                for item in *list {
                    w.octets(Tag::Anonymous, item).unwrap();
                }
                w.end_container().unwrap();
            }
        }
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// A `ProvisionRootCertificate` payload.
fn provision_root(certificate: &[u8], caid: Option<u16>) -> Vec<u8> {
    payload(&[
        (0, Arg::O(certificate)),
        (1, caid.map_or(Arg::Null, |caid| Arg::U(u64::from(caid)))),
    ])
}

fn status_of<T>(result: Result<T, StatusIb>) -> Status {
    result.err().expect("a failure").status
}

fn cluster_status_of<T>(result: Result<T, StatusIb>) -> Option<u8> {
    result.err().expect("a failure").cluster_status
}

/// The three pieces a test needs, with the clock already set.
struct Fixture {
    node: Node<'static>,
    tables: &'static Tables,
    store: &'static Store,
}

fn fixture() -> Fixture {
    let tables: &'static Tables = Box::leak(Box::new(Tables::with_quotas(2, 2, 2)));
    tables.set_time_known(true);
    Fixture {
        node: node(),
        tables,
        store: Box::leak(Box::new(Store::default())),
    }
}

impl Fixture {
    fn certificates(&self) -> Certificates<'_> {
        CertificateManagement::new(self.tables, self.store)
    }

    fn endpoints(&self) -> Endpoints<'_> {
        ClientManagement::new(self.tables)
    }

    fn cert_invoke(
        &self,
        command: u32,
        fields: &[u8],
        ctx: &InteractionContext<'_>,
    ) -> Result<Fields, StatusIb> {
        invoke(
            &self.node,
            &self.certificates(),
            cert::ID,
            command,
            fields,
            ctx,
        )
    }

    fn endpoint_invoke(
        &self,
        command: u32,
        fields: &[u8],
        ctx: &InteractionContext<'_>,
    ) -> Result<Fields, StatusIb> {
        invoke(
            &self.node,
            &self.endpoints(),
            client::ID,
            command,
            fields,
            ctx,
        )
    }

    /// Provisions a root certificate and returns its CAID.
    fn add_root(&self, certificate: &[u8], fabric: FabricIndex) -> u16 {
        let response = self
            .cert_invoke(
                cert::PROVISION_ROOT_CERTIFICATE,
                &provision_root(certificate, None),
                &on(fabric),
            )
            .expect("provisioned");
        match response.as_slice() {
            [(0, Decoded::Unsigned(caid))] => *caid as u16,
            other => panic!("unexpected response {other:?}"),
        }
    }

    /// Runs the CSR half of §14.3.1.2 and returns the CCDID.
    fn add_client(&self, fabric: FabricIndex) -> u16 {
        let response = self
            .cert_invoke(
                cert::CLIENT_CSR,
                &payload(&[(0, Arg::O(&[0u8; 32])), (1, Arg::Null)]),
                &on(fabric),
            )
            .expect("csr");
        match response.first() {
            Some((0, Decoded::Unsigned(ccdid))) => *ccdid as u16,
            other => panic!("unexpected response {other:?}"),
        }
    }
}

// --- §14.4.6.1: ProvisionRootCertificate ------------------------------------------------

#[test]
fn a_root_certificate_needs_a_clock_first() {
    // §14.3.1: "standard Web PKI and TLS policy performs time and date validation of all X.509
    // certificates in the chain", so a node with no time cannot judge an expiry — and the check
    // comes before every other, including the one that would reject an invalid certificate.
    let fixture = fixture();
    fixture.tables.set_time_known(false);
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::PROVISION_ROOT_CERTIFICATE,
            &provision_root(b"BAD", None),
            &on(F1),
        )),
        Status::InvalidInState
    );
    assert!(fixture.tables.roots().is_empty());
}

#[test]
fn an_invalid_certificate_is_a_dynamic_constraint_error() {
    let fixture = fixture();
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::PROVISION_ROOT_CERTIFICATE,
            &provision_root(b"BAD-cert", None),
            &on(F1),
        )),
        Status::DynamicConstraintError
    );
}

#[test]
fn ids_are_handed_out_from_zero() {
    let fixture = fixture();
    assert_eq!(fixture.add_root(b"root-a", F1), 0);
    assert_eq!(fixture.add_root(b"root-b", F1), 1);
    // And the certificate itself reached the store.
    assert_eq!(
        fixture.store.get(Slot::Root {
            fabric_index: F1,
            caid: 0
        }),
        Some(b"root-a".to_vec())
    );
}

#[test]
fn the_same_certificate_twice_on_one_fabric_already_exists() {
    // §14.4.6.1: "If any existing entry for Certificate is found … which has both a matching
    // Fingerprint and an associated fabric which matches the accessing fabric: Fail the command
    // with the status code ALREADY_EXISTS."
    let fixture = fixture();
    fixture.add_root(b"root-a", F1);
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::PROVISION_ROOT_CERTIFICATE,
            &provision_root(b"root-a", None),
            &on(F1),
        )),
        Status::AlreadyExists
    );
    // Another fabric may hold the same CA: the check is scoped to the accessing fabric.
    assert_eq!(fixture.add_root(b"root-a", F2), 1);
}

#[test]
fn a_full_fabric_is_resource_exhausted() {
    // The quota here is two per fabric, and it is per fabric: the second fabric is unaffected.
    let fixture = fixture();
    fixture.add_root(b"root-a", F1);
    fixture.add_root(b"root-b", F1);
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::PROVISION_ROOT_CERTIFICATE,
            &provision_root(b"root-c", None),
            &on(F1),
        )),
        Status::ResourceExhausted
    );
    assert_eq!(fixture.add_root(b"root-c", F2), 2);
}

#[test]
fn rotating_an_unknown_or_foreign_caid_is_not_found() {
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::PROVISION_ROOT_CERTIFICATE,
            &provision_root(b"root-b", Some(99)),
            &on(F1),
        )),
        Status::NotFound
    );
    // The entry exists, but it is another fabric's — and the answer is the same, so that one
    // administrator cannot probe another's table.
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::PROVISION_ROOT_CERTIFICATE,
            &provision_root(b"root-b", Some(caid)),
            &on(F2),
        )),
        Status::NotFound
    );
}

#[test]
fn rotating_replaces_the_certificate_and_keeps_the_id() {
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    let response = fixture
        .cert_invoke(
            cert::PROVISION_ROOT_CERTIFICATE,
            &provision_root(b"root-a-v2", Some(caid)),
            &on(F1),
        )
        .expect("rotated");
    assert_eq!(response, vec![(0, Decoded::Unsigned(u64::from(caid)))]);
    assert_eq!(
        fixture.store.get(Slot::Root {
            fabric_index: F1,
            caid
        }),
        Some(b"root-a-v2".to_vec())
    );
    // And the fingerprint index moved with it, or `LookupRootCertificate` would find the old.
    assert_eq!(
        fixture.tables.roots()[0].fingerprint,
        fingerprint(b"root-a-v2")
    );
}

// --- §14.4.6.3, §14.4.6.5: finding one ---------------------------------------------------

#[test]
fn finding_in_an_empty_table_is_not_found() {
    let fixture = fixture();
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::FIND_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::Null)]),
            &on(F1),
        )),
        Status::NotFound
    );
}

#[test]
fn a_null_caid_finds_this_fabrics_certificates_and_no_others() {
    let fixture = fixture();
    fixture.add_root(b"root-a", F1);
    fixture.add_root(b"root-b", F2);
    let response = fixture
        .cert_invoke(
            cert::FIND_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::Null)]),
            &on(F1),
        )
        .expect("found");
    let [(0, Decoded::List(entries))] = response.as_slice() else {
        panic!("expected a list, got {response:?}");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0][0], (0, Decoded::Unsigned(0)));
    // The command carries the `L` quality, so the certificate is always included.
    assert_eq!(entries[0][1], (1, Decoded::Octets(b"root-a".to_vec())));
    assert_eq!(entries[0][2], (254, Decoded::Unsigned(1)));
}

#[test]
fn a_fabric_with_no_certificates_of_its_own_is_not_found() {
    // "If the resulting list has no entries: Fail the command with the status code NOT_FOUND."
    let fixture = fixture();
    fixture.add_root(b"root-a", F1);
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::FIND_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::Null)]),
            &on(F2),
        )),
        Status::NotFound
    );
}

#[test]
fn a_fingerprint_lookup_returns_the_caid() {
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    let response = fixture
        .cert_invoke(
            cert::LOOKUP_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::O(&fingerprint(b"root-a")))]),
            &on(F1),
        )
        .expect("looked up");
    assert_eq!(response, vec![(0, Decoded::Unsigned(u64::from(caid)))]);

    // An unknown fingerprint, and a known one on another fabric, are both NOT_FOUND.
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::LOOKUP_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::O(&fingerprint(b"nothing")))]),
            &on(F1),
        )),
        Status::NotFound
    );
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::LOOKUP_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::O(&fingerprint(b"root-a")))]),
            &on(F2),
        )),
        Status::NotFound
    );
}

// --- §14.4.5.2: the Large Message rule ---------------------------------------------------

#[test]
fn a_read_over_a_small_transport_leaves_the_certificate_out() {
    // §14.4.5.2: "When this attribute is read over a non Large Message capable transport, the
    // Certificate field SHALL NOT be included." A 3000-octet certificate does not fit in
    // §4.4.4's 1280-octet datagram, and the ids are still useful without it.
    let fixture = fixture();
    fixture.add_root(b"root-a", F1);
    let certificates = fixture.certificates();

    let small = read(
        &fixture.node,
        &certificates,
        cert::ID,
        cert::PROVISIONED_ROOT_CERTIFICATES,
        &InteractionContext::default().with_fabric(F1),
    )
    .unwrap();
    let entries = decode_array(&small);
    assert_eq!(
        entries[0],
        vec![(0, Decoded::Unsigned(0)), (254, Decoded::Unsigned(1))],
        "no Certificate field over a datagram transport"
    );

    let large = read(
        &fixture.node,
        &certificates,
        cert::ID,
        cert::PROVISIONED_ROOT_CERTIFICATES,
        &on(F1),
    )
    .unwrap();
    let entries = decode_array(&large);
    assert_eq!(entries[0][1], (1, Decoded::Octets(b"root-a".to_vec())));
}

fn decode_array(bytes: &[u8]) -> Vec<Fields> {
    let mut reader = TlvReader::new(bytes);
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Array));
    let mut out = Vec::new();
    loop {
        let item = reader.next_element().unwrap().unwrap();
        if item.value == Value::EndOfContainer {
            break;
        }
        out.push(decode_members(&mut reader));
    }
    out
}

// --- §14.4.6.8, §14.4.6.10: the client certificate procedure ------------------------------

#[test]
fn a_csr_allocates_an_id_and_leaves_the_certificate_null() {
    // §14.4.4.4: "A NULL value indicates that the TLS Client Certificate Signing Request (CSR)
    // Procedure has not yet completed."
    let fixture = fixture();
    let ccdid = fixture.add_client(F1);
    assert_eq!(ccdid, 0);
    assert_eq!(fixture.tables.clients()[0].fingerprint, None);
    assert_eq!(*fixture.store.keys.borrow(), vec![0]);

    let certificates = fixture.certificates();
    let bytes = read(
        &fixture.node,
        &certificates,
        cert::ID,
        cert::PROVISIONED_CLIENT_CERTIFICATES,
        &on(F1),
    )
    .unwrap();
    let entries = decode_array(&bytes);
    assert_eq!(entries[0][1], (1, Decoded::Null));
}

#[test]
fn a_csr_signs_the_nonce_it_was_given() {
    // §14.3.1.2 step 4: "The client SHALL verify NonceSignature field on the ClientCSRResponse
    // is valid against the nonce value it provided" — which is the freshness proof, so the
    // nonce has to reach the signer unaltered.
    let fixture = fixture();
    let nonce: Vec<u8> = (0..32u8).collect();
    let response = fixture
        .cert_invoke(
            cert::CLIENT_CSR,
            &payload(&[(0, Arg::O(&nonce)), (1, Arg::Null)]),
            &on(F1),
        )
        .expect("csr");
    assert_eq!(response[0], (0, Decoded::Unsigned(0)));
    assert_eq!(response[1], (1, Decoded::Octets(b"CSR\0".to_vec())));
    assert_eq!(response[2], (2, Decoded::Octets(nonce)));
}

#[test]
fn a_nonce_that_is_not_thirty_two_octets_is_refused() {
    // §14.4.6.8's constraint is an exact 32, "generated using Crypto_DRBG()". A short nonce is
    // a weak freshness proof, which is the one thing the nonce is for.
    let fixture = fixture();
    for length in [0usize, 16, 31, 33] {
        assert_eq!(
            status_of(fixture.cert_invoke(
                cert::CLIENT_CSR,
                &payload(&[(0, Arg::O(&vec![0u8; length])), (1, Arg::Null)]),
                &on(F1),
            )),
            Status::ConstraintError,
            "nonce of {length} octets"
        );
    }
}

#[test]
fn a_key_collision_provisions_nothing() {
    // §14.4.6.8: "Discard the new key pair. Fail the command with the status code
    // DYNAMIC_CONSTRAINT_ERROR" — and nothing is recorded, so the id is still free.
    let fixture = fixture();
    *fixture.store.reject_keys.borrow_mut() = true;
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::CLIENT_CSR,
            &payload(&[(0, Arg::O(&[0u8; 32])), (1, Arg::Null)]),
            &on(F1),
        )),
        Status::DynamicConstraintError
    );
    assert!(fixture.tables.clients().is_empty());
}

#[test]
fn a_certificate_for_another_key_is_refused() {
    // §14.4.6.10: "If the public key of the passed in ClientCertificate does not correspond to
    // the private key of the matching entry" — a certificate this node could never use in a
    // handshake, and would discover at connection time.
    let fixture = fixture();
    let ccdid = fixture.add_client(F1);
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::PROVISION_CLIENT_CERTIFICATE,
            &payload(&[
                (0, Arg::U(u64::from(ccdid))),
                (1, Arg::O(b"cert-for-someone-else\x09")),
                (2, Arg::Octets(&[])),
            ]),
            &on(F1),
        )),
        Status::DynamicConstraintError
    );
    assert_eq!(fixture.tables.clients()[0].fingerprint, None);
}

#[test]
fn provisioning_a_client_certificate_stores_the_chain() {
    let fixture = fixture();
    let ccdid = fixture.add_client(F1);
    fixture
        .cert_invoke(
            cert::PROVISION_CLIENT_CERTIFICATE,
            &payload(&[
                (0, Arg::U(u64::from(ccdid))),
                (1, Arg::O(b"client\x00")),
                (2, Arg::Octets(&[b"ica-1", b"ica-2"])),
            ]),
            &on(F1),
        )
        .expect("provisioned");
    assert_eq!(fixture.tables.clients()[0].intermediates, 2);
    assert_eq!(
        fixture.store.get(Slot::Intermediate {
            fabric_index: F1,
            ccdid,
            index: 1
        }),
        Some(b"ica-2".to_vec())
    );

    // §14.4.6.11 then returns the whole chain.
    let response = fixture
        .cert_invoke(
            cert::FIND_CLIENT_CERTIFICATE,
            &payload(&[(0, Arg::Null)]),
            &on(F1),
        )
        .expect("found");
    let [(0, Decoded::List(entries))] = response.as_slice() else {
        panic!("expected a list, got {response:?}");
    };
    assert_eq!(entries[0][1], (1, Decoded::Octets(b"client\x00".to_vec())));
    assert_eq!(
        entries[0][2],
        (
            2,
            Decoded::List(vec![
                vec![(255, Decoded::Octets(b"ica-1".to_vec()))],
                vec![(255, Decoded::Octets(b"ica-2".to_vec()))],
            ])
        )
    );
}

#[test]
fn rotating_a_client_certificate_drops_the_old_chain() {
    // A chain that shrinks would otherwise leave its tail in the store, and the old
    // intermediate would be read back as part of the new chain.
    let fixture = fixture();
    let ccdid = fixture.add_client(F1);
    let provision = |certificate: &[u8], chain: &[&[u8]]| {
        payload(&[
            (0, Arg::U(u64::from(ccdid))),
            (1, Arg::O(certificate)),
            (2, Arg::Octets(chain)),
        ])
    };
    fixture
        .cert_invoke(
            cert::PROVISION_CLIENT_CERTIFICATE,
            &provision(b"client\x00", &[b"ica-1", b"ica-2", b"ica-3"]),
            &on(F1),
        )
        .expect("provisioned");
    fixture
        .cert_invoke(
            cert::PROVISION_CLIENT_CERTIFICATE,
            &provision(b"client-v2\x00", &[b"ica-9"]),
            &on(F1),
        )
        .expect("rotated");

    assert_eq!(fixture.tables.clients()[0].intermediates, 1);
    assert_eq!(
        fixture.store.get(Slot::Intermediate {
            fabric_index: F1,
            ccdid,
            index: 1
        }),
        None,
        "the old chain's tail must be gone"
    );
}

#[test]
fn an_over_long_chain_is_refused_before_anything_is_stored() {
    // §14.4.6.10's constraint on `IntermediateCertificates` is "0 to 10".
    let fixture = fixture();
    let ccdid = fixture.add_client(F1);
    let chain: Vec<&[u8]> = vec![b"ica"; 11];
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::PROVISION_CLIENT_CERTIFICATE,
            &payload(&[
                (0, Arg::U(u64::from(ccdid))),
                (1, Arg::O(b"client\x00")),
                (2, Arg::Octets(&chain)),
            ]),
            &on(F1),
        )),
        Status::ConstraintError
    );
    assert_eq!(fixture.tables.clients()[0].fingerprint, None);
    assert_eq!(
        fixture.store.get(Slot::Client {
            fabric_index: F1,
            ccdid
        }),
        None,
        "a chain refused halfway would be one this node presents"
    );
}

// --- The two interlocks -------------------------------------------------------------------

#[test]
fn a_root_certificate_an_endpoint_names_cannot_be_removed() {
    // §14.4.6.7: "If the passed in CAID equals the CAID of any entry in the ProvisionedEndpoints
    // list in the TLS Client Management Cluster: Fail the command with the status code
    // INVALID_IN_STATE." Otherwise the endpoint points at a CA that no longer resolves, and
    // finds out at connection time.
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &payload(&[
                (0, Arg::O(b"example.test")),
                (1, Arg::U(443)),
                (2, Arg::U(u64::from(caid))),
                (3, Arg::Null),
                (4, Arg::Null),
            ]),
            &on(F1),
        )
        .expect("provisioned");

    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::REMOVE_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::U(u64::from(caid)))]),
            &on(F1),
        )),
        Status::InvalidInState
    );

    // Remove the endpoint and the certificate goes.
    fixture
        .endpoint_invoke(
            client::REMOVE_ENDPOINT,
            &payload(&[(0, Arg::U(0))]),
            &on(F1),
        )
        .expect("removed");
    fixture
        .cert_invoke(
            cert::REMOVE_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::U(u64::from(caid)))]),
            &on(F1),
        )
        .expect("removed");
    assert!(fixture.tables.roots().is_empty());
    assert_eq!(
        fixture.store.get(Slot::Root {
            fabric_index: F1,
            caid
        }),
        None
    );
}

#[test]
fn a_client_certificate_an_endpoint_names_cannot_be_removed() {
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    let ccdid = fixture.add_client(F1);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &payload(&[
                (0, Arg::O(b"example.test")),
                (1, Arg::U(443)),
                (2, Arg::U(u64::from(caid))),
                (3, Arg::U(u64::from(ccdid))),
                (4, Arg::Null),
            ]),
            &on(F1),
        )
        .expect("provisioned");
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::REMOVE_CLIENT_CERTIFICATE,
            &payload(&[(0, Arg::U(u64::from(ccdid)))]),
            &on(F1),
        )),
        Status::InvalidInState
    );
}

#[test]
fn removing_a_client_certificate_removes_its_key() {
    // §14.4.6.15: "Remove the TLS Key Pair belonging to the passed in CCDID." A key left behind
    // is a key that can still sign.
    let fixture = fixture();
    let ccdid = fixture.add_client(F1);
    fixture
        .cert_invoke(
            cert::REMOVE_CLIENT_CERTIFICATE,
            &payload(&[(0, Arg::U(u64::from(ccdid)))]),
            &on(F1),
        )
        .expect("removed");
    assert!(fixture.tables.clients().is_empty());
    assert!(fixture.store.keys.borrow().is_empty());
}

// --- §14.5.7: TLS Client Management ------------------------------------------------------

/// A `ProvisionEndpoint` payload.
fn provision_endpoint(
    hostname: &[u8],
    port: u16,
    caid: u16,
    ccdid: Option<u16>,
    endpoint_id: Option<u16>,
) -> Vec<u8> {
    payload(&[
        (0, Arg::O(hostname)),
        (1, Arg::U(u64::from(port))),
        (2, Arg::U(u64::from(caid))),
        (3, ccdid.map_or(Arg::Null, |v| Arg::U(u64::from(v)))),
        (4, endpoint_id.map_or(Arg::Null, |v| Arg::U(u64::from(v)))),
    ])
}

#[test]
fn an_endpoint_needs_a_clock_first() {
    // §14.5.7.1's first check, and the only one that uses the cluster-specific InvalidTime.
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    fixture.tables.set_time_known(false);
    let result = fixture.endpoint_invoke(
        client::PROVISION_ENDPOINT,
        &provision_endpoint(b"example.test", 443, caid, None, None),
        &on(F1),
    );
    assert_eq!(status_of(result), Status::Failure);
    let result = fixture.endpoint_invoke(
        client::PROVISION_ENDPOINT,
        &provision_endpoint(b"example.test", 443, caid, None, None),
        &on(F1),
    );
    assert_eq!(
        cluster_status_of(result),
        Some(StatusCodeEnum::InvalidTime.value())
    );
}

#[test]
fn an_endpoint_naming_a_certificate_that_does_not_exist_is_refused() {
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);

    // No such CAID.
    assert_eq!(
        cluster_status_of(fixture.endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, 99, None, None),
            &on(F1),
        )),
        Some(StatusCodeEnum::RootCertificateNotFound.value())
    );
    // The CAID exists, but on another fabric.
    assert_eq!(
        cluster_status_of(fixture.endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, None, None),
            &on(F2),
        )),
        Some(StatusCodeEnum::RootCertificateNotFound.value())
    );
    // No such CCDID.
    assert_eq!(
        cluster_status_of(fixture.endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, Some(7), None),
            &on(F1),
        )),
        Some(StatusCodeEnum::ClientCertificateNotFound.value())
    );
}

#[test]
fn one_host_and_port_per_fabric() {
    // §14.5.7.1: "If there is an existing entry for the Hostname / Port combination in the
    // ProvisionedEndpoints list, where the associated fabric equals the accessing fabric: Fail
    // the command with the cluster-specific status code of EndpointAlreadyInstalled."
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, None, None),
            &on(F1),
        )
        .expect("provisioned");
    assert_eq!(
        cluster_status_of(fixture.endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, None, None),
            &on(F1),
        )),
        Some(StatusCodeEnum::EndpointAlreadyInstalled.value())
    );
    // A different port is a different endpoint.
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 8443, caid, None, None),
            &on(F1),
        )
        .expect("provisioned");
}

#[test]
fn an_update_does_not_collide_with_itself() {
    // §14.5.7.1's update path says "If *another* entry exists for the passed in Hostname / Port
    // combination" — rewriting an endpoint's port while leaving its host alone must work.
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, None, None),
            &on(F1),
        )
        .expect("provisioned");
    let response = fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, None, Some(0)),
            &on(F1),
        )
        .expect("updated in place");
    assert_eq!(response, vec![(0, Decoded::Unsigned(0))]);
    assert_eq!(fixture.tables.endpoints().len(), 1);
}

#[test]
fn a_hostname_and_port_are_checked_against_their_constraints() {
    // §14.5.4.2: a hostname of "4 to 253", a port of "1 to 65535". Port 0 is not a port.
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    for (hostname, port) in [
        (&b"abc"[..], 443u16),
        (&[b'a'; 254][..], 443),
        (&b"example.test"[..], 0),
    ] {
        assert_eq!(
            status_of(fixture.endpoint_invoke(
                client::PROVISION_ENDPOINT,
                &provision_endpoint(hostname, port, caid, None, None),
                &on(F1),
            )),
            Status::ConstraintError
        );
    }
}

#[test]
fn an_endpoint_in_use_cannot_be_removed() {
    // §14.5.7.5: "If the ReferenceCount of that matching entry is greater than 0: Fail the
    // command with the status code INVALID_IN_STATE."
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, None, None),
            &on(F1),
        )
        .expect("provisioned");
    fixture.tables.set_reference_count(0, 1);
    assert_eq!(
        status_of(fixture.endpoint_invoke(
            client::REMOVE_ENDPOINT,
            &payload(&[(0, Arg::U(0))]),
            &on(F1),
        )),
        Status::InvalidInState
    );
    fixture.tables.set_reference_count(0, 0);
    fixture
        .endpoint_invoke(
            client::REMOVE_ENDPOINT,
            &payload(&[(0, Arg::U(0))]),
            &on(F1),
        )
        .expect("removed");
}

#[test]
fn finding_an_endpoint_returns_every_field() {
    // §14.5.7.4 returns one `TLSEndpointStruct`, not a list — and §14.5.4.2's six fields plus
    // the fabric index are all of it.
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    let ccdid = fixture.add_client(F1);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 8443, caid, Some(ccdid), None),
            &on(F1),
        )
        .expect("provisioned");
    let response = fixture
        .endpoint_invoke(client::FIND_ENDPOINT, &payload(&[(0, Arg::U(0))]), &on(F1))
        .expect("found");
    let [(0, Decoded::Struct(endpoint))] = response.as_slice() else {
        panic!("expected one TLSEndpointStruct, got {response:?}");
    };
    assert_eq!(
        endpoint.as_slice(),
        &[
            (0, Decoded::Unsigned(0)),                      // EndpointID
            (1, Decoded::Octets(b"example.test".to_vec())), // Hostname
            (2, Decoded::Unsigned(8443)),                   // Port
            (3, Decoded::Unsigned(u64::from(caid))),        // CAID
            (4, Decoded::Unsigned(u64::from(ccdid))),       // CCDID
            (5, Decoded::Unsigned(0)),                      // ReferenceCount
            (254, Decoded::Unsigned(1)),                    // FabricIndex
        ]
    );
}

#[test]
fn an_endpoint_with_no_client_certificate_says_null() {
    // §14.5.4.2: "A NULL value means no client certificate is used with this endpoint."
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, None, None),
            &on(F1),
        )
        .expect("provisioned");
    let response = fixture
        .endpoint_invoke(client::FIND_ENDPOINT, &payload(&[(0, Arg::U(0))]), &on(F1))
        .expect("found");
    let [(0, Decoded::Struct(endpoint))] = response.as_slice() else {
        panic!("expected one TLSEndpointStruct, got {response:?}");
    };
    assert_eq!(endpoint[4], (4, Decoded::Null));
}

#[test]
fn an_endpoint_of_another_fabric_is_not_found() {
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, None, None),
            &on(F1),
        )
        .expect("provisioned");
    for command in [client::FIND_ENDPOINT, client::REMOVE_ENDPOINT] {
        assert_eq!(
            status_of(fixture.endpoint_invoke(command, &payload(&[(0, Arg::U(0))]), &on(F2))),
            Status::NotFound
        );
    }
}

#[test]
fn removing_a_fabric_forgets_everything_it_provisioned() {
    let fixture = fixture();
    let caid = fixture.add_root(b"root-a", F1);
    let ccdid = fixture.add_client(F1);
    fixture.add_root(b"root-b", F2);
    fixture
        .endpoint_invoke(
            client::PROVISION_ENDPOINT,
            &provision_endpoint(b"example.test", 443, caid, Some(ccdid), None),
            &on(F1),
        )
        .expect("provisioned");

    fixture.tables.remove_fabric(F1, fixture.store);
    assert!(fixture.tables.endpoints().is_empty());
    assert_eq!(fixture.tables.roots().len(), 1, "F2 keeps its own");
    assert!(fixture.tables.clients().is_empty());
    assert!(fixture.store.keys.borrow().is_empty());
    assert_eq!(
        fixture.store.get(Slot::Root {
            fabric_index: F1,
            caid
        }),
        None
    );
}

#[test]
fn a_command_with_no_accessing_fabric_is_refused() {
    // Every command in §14.4.6 and §14.5.7 is `F`, and a PASE session has no fabric to scope to.
    let fixture = fixture();
    let bare = InteractionContext::default().with_large_messages();
    assert_eq!(
        status_of(fixture.cert_invoke(
            cert::FIND_ROOT_CERTIFICATE,
            &payload(&[(0, Arg::Null)]),
            &bare,
        )),
        Status::UnsupportedAccess
    );
    assert_eq!(
        status_of(fixture.endpoint_invoke(
            client::FIND_ENDPOINT,
            &payload(&[(0, Arg::U(0))]),
            &bare
        )),
        Status::UnsupportedAccess
    );
}

// --- §7.12.5, §8.8.2.3 step b.iv: the Large Message quality ------------------------------

/// §14.4 and §14.5 both say it outright: "Commands in this cluster uniformly use the Large
/// Message qualifier, even when the command doesn't require it, to reduce the testing matrix."
///
/// That qualifier is not decoration. A 3000-octet certificate does not fit in §4.4.4's
/// 1280-octet datagram, so the interaction model refuses the command on a transport that could
/// not carry one — §8.8.2.3 step b.iv — and the answer is `INVALID_TRANSPORT_TYPE`, which tells
/// the client to come back over TCP rather than to give up.
#[test]
fn a_tls_command_over_a_datagram_transport_is_refused_by_the_interaction_model() {
    use matter_kit::im::{
        AllowAll, CommandData, CommandPath, InvokeResponse, InvokeResponseMessage, Server,
    };

    let fixture = fixture();
    let certificates = fixture.certificates();
    let access = AllowAll;
    let server = Server::new(fixture.node, &access, &certificates, 8);

    let invoke_over = |large: bool| {
        let fields = provision_root(b"root-a", None);
        let data = CommandData {
            fields: Some(&fields),
            ..CommandData::new(CommandPath::command(
                0,
                cert::ID,
                cert::PROVISION_ROOT_CERTIFICATE,
            ))
        };
        let mut ctx = InteractionContext::default().with_fabric(F1);
        if large {
            ctx = ctx.with_large_messages();
        }
        let mut scratch = [0u8; 4096];
        let mut buf = [0u8; 4096];
        let (bytes, _) = server
            .serve_invoke([Ok(data)], &ctx, false, &mut scratch, &mut buf)
            .expect("serve");
        let message = InvokeResponseMessage::decode(bytes).expect("decode");
        match message
            .responses()
            .expect("responses")
            .next()
            .expect("one response")
            .expect("decode")
        {
            InvokeResponse::Command(_) => Status::Success,
            InvokeResponse::Status(s) => s.status.status,
        }
    };

    assert_eq!(invoke_over(false), Status::InvalidTransportType);
    assert_eq!(invoke_over(true), Status::Success);
}

/// §14.4.4.4 words the omission more narrowly than §14.4.4.3 does, and the difference is the
/// point: the field is left out when it "is non-NULL" — or, for the chain, "is non-empty".
///
/// So a client certificate that the CSR procedure has not finished reads back as NULL even over
/// a datagram transport, and an empty chain reads back as an empty list. Both cost two octets,
/// and they carry the one thing a client on UDP could not otherwise learn: which entries are
/// still waiting for their certificate.
#[test]
fn a_null_client_certificate_survives_a_small_transport() {
    let fixture = fixture();
    let ccdid = fixture.add_client(F1);
    let certificates = fixture.certificates();
    let small = InteractionContext::default().with_fabric(F1);

    let bytes = read(
        &fixture.node,
        &certificates,
        cert::ID,
        cert::PROVISIONED_CLIENT_CERTIFICATES,
        &small,
    )
    .unwrap();
    assert_eq!(
        decode_array(&bytes)[0],
        vec![
            (0, Decoded::Unsigned(u64::from(ccdid))),
            (1, Decoded::Null),
            (2, Decoded::List(vec![])),
            (254, Decoded::Unsigned(1)),
        ]
    );

    // Once provisioned, the same read leaves the certificate and the chain out.
    fixture
        .cert_invoke(
            cert::PROVISION_CLIENT_CERTIFICATE,
            &payload(&[
                (0, Arg::U(u64::from(ccdid))),
                (1, Arg::O(b"client\x00")),
                (2, Arg::Octets(&[b"ica-1"])),
            ]),
            &on(F1),
        )
        .expect("provisioned");
    let bytes = read(
        &fixture.node,
        &certificates,
        cert::ID,
        cert::PROVISIONED_CLIENT_CERTIFICATES,
        &small,
    )
    .unwrap();
    assert_eq!(
        decode_array(&bytes)[0],
        vec![
            (0, Decoded::Unsigned(u64::from(ccdid))),
            (254, Decoded::Unsigned(1)),
        ],
        "a non-NULL certificate and a non-empty chain are both omitted"
    );

    // And over a Large Message transport, all of it.
    let bytes = read(
        &fixture.node,
        &certificates,
        cert::ID,
        cert::PROVISIONED_CLIENT_CERTIFICATES,
        &on(F1),
    )
    .unwrap();
    assert_eq!(
        decode_array(&bytes)[0],
        vec![
            (0, Decoded::Unsigned(u64::from(ccdid))),
            (1, Decoded::Octets(b"client\x00".to_vec())),
            (
                2,
                Decoded::List(vec![vec![(255, Decoded::Octets(b"ica-1".to_vec()))]])
            ),
            (254, Decoded::Unsigned(1)),
        ]
    );
}

#[test]
fn an_empty_chain_survives_a_small_transport_too() {
    // A provisioned certificate with no intermediates: the certificate goes, the empty list
    // stays, because "an empty value means that no intermediate certificates are needed".
    let fixture = fixture();
    let ccdid = fixture.add_client(F1);
    fixture
        .cert_invoke(
            cert::PROVISION_CLIENT_CERTIFICATE,
            &payload(&[
                (0, Arg::U(u64::from(ccdid))),
                (1, Arg::O(b"client\x00")),
                (2, Arg::Octets(&[])),
            ]),
            &on(F1),
        )
        .expect("provisioned");
    let certificates = fixture.certificates();
    let bytes = read(
        &fixture.node,
        &certificates,
        cert::ID,
        cert::PROVISIONED_CLIENT_CERTIFICATES,
        &InteractionContext::default().with_fabric(F1),
    )
    .unwrap();
    assert_eq!(
        decode_array(&bytes)[0],
        vec![
            (0, Decoded::Unsigned(u64::from(ccdid))),
            (2, Decoded::List(vec![])),
            (254, Decoded::Unsigned(1)),
        ]
    );
}
