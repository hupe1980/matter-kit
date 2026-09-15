//! The fabric's certificate authority (Core §6.5) — and the chains it produces, verified by the
//! *other* half of the crate.
//!
//! This is the cheapest useful test available here: `ca` builds certificates and `cert::chain`
//! validates them, and the two were written from §6.5 independently. A CA that agreed with its
//! own validator and nothing else would be a closed loop; one whose output passes the validator
//! that rejects everything else is evidence.
//!
//! Every chain below is also checked against the rules §6.5 spends most of its length on: the
//! subject is the *authority's* to choose, an ICAC may not mint further CAs, a root pinned to
//! one fabric may not sign for another, and a key identifier is a hint rather than a proof.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::ca::{CertAuthority, Identity, MAX_CATS, Validity};
use matter_kit::cert::{
    CERT_TLV_MAX, CertType, MatterCertificate, verify_chain, verify_self_signed,
};
use matter_kit::crypto::{KeyPurpose, KeyStore, PublicKey, SoftKeyStore};
use matter_kit::msg::{CaseAuthenticatedTag, FabricId, NodeId};

/// The Matter epoch second this suite calls "now" — 2024-01-01.
const NOW: u32 = 757_382_400;

type Keys = SoftKeyStore<8>;

/// A deterministic key, so a failure is reproducible.
fn key(keys: &mut Keys, seed: u8) -> (matter_kit::crypto::KeyHandle, PublicKey) {
    let mut secret = [1u8; 32];
    secret[31] = seed;
    let handle = keys
        .import(KeyPurpose::Operational, &secret)
        .expect("a valid key");
    let public = keys.public_key(handle).expect("a public key");
    (handle, public)
}

struct Fabric {
    keys: Keys,
    ca: CertAuthority,
    root: Vec<u8>,
}

fn new_fabric_with(seed: u8, fabric_id: Option<FabricId>) -> Fabric {
    let mut keys = Keys::new();
    let (root_key, _) = key(&mut keys, seed);
    let mut ca = CertAuthority::new(root_key, u64::from(seed) << 8 | 0xCA);
    if let Some(fabric_id) = fabric_id {
        ca = ca.for_fabric(fabric_id);
    }
    let mut buf = [0u8; CERT_TLV_MAX];
    let root = ca
        .self_signed_root(&keys, &mut buf, Validity::years(NOW, 10))
        .expect("a root")
        .to_vec();
    Fabric { keys, ca, root }
}

fn new_fabric(fabric_id: Option<FabricId>) -> Fabric {
    new_fabric_with(1, fabric_id)
}

// --- The root ----------------------------------------------------------------------------------

#[test]
fn a_root_is_self_signed_and_is_a_ca() {
    // §6.5.6.2's RCAC. §6.4.5.3 says trust in it "is established by provenance, not by the
    // self-signature" — but a self-signature that does not check means a corrupted or
    // mis-transcribed root, which is worth catching at `AddTrustedRootCertificate`.
    let fabric = new_fabric(None);
    let root = MatterCertificate::decode(&fabric.root).expect("decodes");
    root.validate_as(CertType::Rcac).expect("a valid RCAC");
    assert!(root.is_ca());
    assert_eq!(root.issuer, root.subject, "a root issues itself");
    assert!(verify_self_signed(&root).expect("checks"));

    // §6.5.11.2: an RCAC signs certificates and revocation lists, and nothing else. A root that
    // could also sign arbitrary messages would be usable for more than it is trusted for.
    let usage = root.extensions.key_usage().expect("key usage");
    assert!(usage.contains(matter_kit::cert::KeyUsage::KEY_CERT_SIGN));
    assert!(!usage.contains(matter_kit::cert::KeyUsage::DIGITAL_SIGNATURE));
}

#[test]
fn a_root_with_the_wrong_key_does_not_verify() {
    // The self-signature is the only thing that ties the certificate to the key inside it. A
    // validator that merely looked at the shape would accept a root somebody rewrote.
    let mut keys = Keys::new();
    let (a, _) = key(&mut keys, 1);
    let (b, other_public) = key(&mut keys, 2);
    let ca = CertAuthority::new(a, 0xCAFE);
    let mut buf = [0u8; CERT_TLV_MAX];
    let root = ca
        .self_signed_root(&keys, &mut buf, Validity::years(NOW, 10))
        .expect("a root")
        .to_vec();
    let _ = b;

    let mut decoded = MatterCertificate::decode(&root).expect("decodes");
    decoded.public_key = other_public;
    assert!(
        !verify_self_signed(&decoded).unwrap_or(false),
        "a root whose key was swapped still verified"
    );
}

// --- NOCs --------------------------------------------------------------------------------------

#[test]
fn a_noc_under_its_root_verifies_and_names_the_node() {
    let mut fabric = new_fabric(None);
    let (_, node_key) = key(&mut fabric.keys, 7);
    let identity = Identity::new(
        FabricId(0x1122_3344_5566_7788),
        NodeId(0x0000_0000_DEAD_BEEF),
    );
    let mut buf = [0u8; CERT_TLV_MAX];
    let noc = fabric
        .ca
        .issue_noc(
            &fabric.keys,
            &mut buf,
            &identity,
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("a NOC")
        .to_vec();

    let root = MatterCertificate::decode(&fabric.root).expect("decodes");
    let noc = MatterCertificate::decode(&noc).expect("decodes");
    let verified = verify_chain(&noc, None, &root, Some(NOW)).expect("a valid chain");
    assert_eq!(verified.node_id, identity.node_id);
    assert_eq!(verified.fabric_id, identity.fabric_id);
    assert!(verified.cats.is_empty());

    // §6.5.11.2 and §6.5.11.3: a NOC signs, and is not a CA.
    assert!(!noc.is_ca());
    assert!(
        noc.extensions
            .key_usage()
            .expect("key usage")
            .contains(matter_kit::cert::KeyUsage::DIGITAL_SIGNATURE)
    );
}

#[test]
fn the_subject_is_the_authoritys_to_choose_not_the_devices() {
    // §11.18 gives the device's half of commissioning: it generates a key and signs a CSR. The
    // CSR carries a public key and nothing else the CA is obliged to believe — the commissioner
    // decides the node id, the fabric id and the CATs.
    //
    // A CA that echoed a subject the device proposed would let a device name itself, and a
    // device that could name itself could name itself as somebody else.
    let mut fabric = new_fabric(None);
    let (_, node_key) = key(&mut fabric.keys, 7);
    let mut buf = [0u8; CERT_TLV_MAX];
    let first = fabric
        .ca
        .issue_noc(
            &fabric.keys,
            &mut buf,
            &Identity::new(FabricId(1), NodeId(10)),
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("a NOC")
        .to_vec();
    let mut buf = [0u8; CERT_TLV_MAX];
    let second = fabric
        .ca
        .issue_noc(
            &fabric.keys,
            &mut buf,
            // The same key, a different identity — which is exactly what a second fabric
            // commissioning the same device produces.
            &Identity::new(FabricId(2), NodeId(20)),
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("a NOC")
        .to_vec();

    let first = MatterCertificate::decode(&first).expect("decodes");
    let second = MatterCertificate::decode(&second).expect("decodes");
    assert_eq!(first.node_id(), Some(NodeId(10)));
    assert_eq!(second.node_id(), Some(NodeId(20)));
    assert_eq!(first.public_key, second.public_key, "the same device key");
}

#[test]
fn a_group_or_unspecified_node_id_is_refused() {
    // §2.5.5: an operational node id is neither zero nor a group id. A NOC naming one would be
    // an identity nothing could ever authenticate as — and §6.5.6.1 makes exactly one
    // `matter-node-id` mandatory, so there is no "leave it out" option.
    let mut fabric = new_fabric(None);
    let (_, node_key) = key(&mut fabric.keys, 7);
    for node in [
        NodeId::UNSPECIFIED,
        NodeId::from_group(matter_kit::msg::GroupId(4)),
    ] {
        let mut buf = [0u8; CERT_TLV_MAX];
        assert!(
            fabric
                .ca
                .issue_noc(
                    &fabric.keys,
                    &mut buf,
                    &Identity::new(FabricId(1), node),
                    &node_key,
                    Validity::years(NOW, 1)
                )
                .is_err(),
            "{node:?} was accepted as an operational identity"
        );
    }
}

#[test]
fn cats_reach_the_subject_and_come_back_out_of_the_chain() {
    // §6.6.2.1.2's CASE Authenticated Tags are how an ACL grants a *class* of administrator
    // rather than a list of node ids. They live in the NOC's subject, so they are the CA's to
    // grant — a device cannot award itself a tag.
    let mut fabric = new_fabric(None);
    let (_, node_key) = key(&mut fabric.keys, 7);
    let identity = Identity::new(FabricId(1), NodeId(10))
        .with_cats(&[
            CaseAuthenticatedTag(0x0001_0001),
            CaseAuthenticatedTag(0x0002_0003),
        ])
        .expect("two distinct tags");
    let mut buf = [0u8; CERT_TLV_MAX];
    let noc = fabric
        .ca
        .issue_noc(
            &fabric.keys,
            &mut buf,
            &identity,
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("a NOC")
        .to_vec();

    let root = MatterCertificate::decode(&fabric.root).expect("decodes");
    let noc = MatterCertificate::decode(&noc).expect("decodes");
    let verified = verify_chain(&noc, None, &root, Some(NOW)).expect("a valid chain");
    assert_eq!(verified.cats.len(), 2);
    assert!(verified.cats.contains(&CaseAuthenticatedTag(0x0001_0001)));
}

#[test]
fn two_cats_with_the_same_identifier_are_refused() {
    // §6.6.2.1.2 makes the low sixteen bits a *version*. Two tags sharing an identifier are two
    // versions of one group, and §6.6.2.1.2's matching rule is "an equal or higher version" —
    // so an ACL demanding version 3 would be silently satisfied by the version-1 tag sitting
    // beside it in the same certificate.
    let identity = Identity::new(FabricId(1), NodeId(10));
    assert!(
        identity
            .with_cats(&[
                CaseAuthenticatedTag(0x0001_0001),
                CaseAuthenticatedTag(0x0001_0003)
            ])
            .is_err()
    );
    assert!(
        Identity::new(FabricId(1), NodeId(10))
            .with_cats(&[
                CaseAuthenticatedTag(0x0001_0001),
                CaseAuthenticatedTag(0x0002_0001),
                CaseAuthenticatedTag(0x0003_0001),
                CaseAuthenticatedTag(0x0004_0001),
            ])
            .is_err(),
        "more than {MAX_CATS} tags was accepted"
    );
}

// --- Intermediate CAs ----------------------------------------------------------------------

#[test]
fn a_noc_under_an_icac_verifies_through_both_links() {
    // §6.4.5.1 permits either shape: a NOC "issued by either a Root CA trusted within the
    // Fabric or by an Intermediate Certificate Authority whose ICA certificate is directly
    // issued by such a Root CA".
    let mut fabric = new_fabric(None);
    let (icac_key, icac_public) = key(&mut fabric.keys, 3);
    let mut buf = [0u8; CERT_TLV_MAX];
    let icac = fabric
        .ca
        .issue_icac(
            &fabric.keys,
            &mut buf,
            0xBEEF,
            &icac_public,
            Validity::years(NOW, 5),
        )
        .expect("an ICAC")
        .to_vec();

    let intermediate = CertAuthority::intermediate(icac_key, 0xBEEF);
    let (_, node_key) = key(&mut fabric.keys, 7);
    let mut buf = [0u8; CERT_TLV_MAX];
    // The ICAC signs the NOC, so the NOC's issuer must be the *ICAC's* subject. A CA built for
    // an intermediate writes its own `matter-icac-id`... which is a different attribute from
    // `matter-rcac-id`, so this is the case the crate has to get right or nothing chains.
    let noc = intermediate
        .issue_noc(
            &fabric.keys,
            &mut buf,
            &Identity::new(FabricId(1), NodeId(10)),
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("a NOC")
        .to_vec();

    let root = MatterCertificate::decode(&fabric.root).expect("decodes");
    let icac = MatterCertificate::decode(&icac).expect("decodes");
    let noc = MatterCertificate::decode(&noc).expect("decodes");
    icac.validate_as(CertType::Icac).expect("a valid ICAC");

    // §6.4.5.1's "directly issued" — one level, no more.
    assert_eq!(
        icac.extensions
            .basic_constraints()
            .and_then(|b| b.path_len_constraint),
        Some(0),
        "an ICAC that could mint further CAs"
    );

    let verified = verify_chain(&noc, Some(&icac), &root, Some(NOW)).expect("a valid chain");
    assert_eq!(verified.node_id, NodeId(10));

    // ...and the same NOC does not verify straight against the root, because the root did not
    // sign it. A chain that skipped the intermediate would accept any ICAC's NOCs as the
    // root's own.
    assert!(verify_chain(&noc, None, &root, Some(NOW)).is_err());
}

// --- Fabric pinning ----------------------------------------------------------------------------

#[test]
fn a_root_pinned_to_one_fabric_will_not_sign_for_another() {
    // §6.5.6.3: "When any matter-fabric-id attributes are present in either the Matter Root CA
    // Certificate or the Matter ICA Certificate, the value SHALL match the one present in the
    // NOC within the same certificate chain."
    //
    // Caught here rather than at `verify_chain` so the CA never emits a certificate that cannot
    // be used — the alternative is the device discovering it at `AddNOC`, three round trips
    // into commissioning.
    let mut fabric = new_fabric(Some(FabricId(0xAAAA)));
    let (_, node_key) = key(&mut fabric.keys, 7);
    let mut buf = [0u8; CERT_TLV_MAX];
    assert!(
        fabric
            .ca
            .issue_noc(
                &fabric.keys,
                &mut buf,
                &Identity::new(FabricId(0xBBBB), NodeId(10)),
                &node_key,
                Validity::years(NOW, 1)
            )
            .is_err()
    );

    let mut buf = [0u8; CERT_TLV_MAX];
    let noc = fabric
        .ca
        .issue_noc(
            &fabric.keys,
            &mut buf,
            &Identity::new(FabricId(0xAAAA), NodeId(10)),
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("the pinned fabric")
        .to_vec();
    let root = MatterCertificate::decode(&fabric.root).expect("decodes");
    let noc = MatterCertificate::decode(&noc).expect("decodes");
    verify_chain(&noc, None, &root, Some(NOW)).expect("a valid chain");
}

// --- Validity ------------------------------------------------------------------------------------

#[test]
fn a_certificate_outside_its_window_is_refused() {
    // §6.5.5's `not-before`/`not-after`. A commissioner with a wrong clock is a real failure
    // mode — it is why §11.18.6.8 lets a device be given a root before it has any time source.
    let mut fabric = new_fabric(None);
    let (_, node_key) = key(&mut fabric.keys, 7);
    let mut buf = [0u8; CERT_TLV_MAX];
    let noc = fabric
        .ca
        .issue_noc(
            &fabric.keys,
            &mut buf,
            &Identity::new(FabricId(1), NodeId(10)),
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("a NOC")
        .to_vec();
    let root = MatterCertificate::decode(&fabric.root).expect("decodes");
    let noc = MatterCertificate::decode(&noc).expect("decodes");

    verify_chain(&noc, None, &root, Some(NOW + 86_400)).expect("a day in");
    assert!(
        verify_chain(&noc, None, &root, Some(NOW - 1)).is_err(),
        "before not-before"
    );
    assert!(
        verify_chain(&noc, None, &root, Some(NOW + 40_000_000)).is_err(),
        "after not-after"
    );
    // With no time at all the window is not checked — §6.4.5.4.1 lets a node with no trusted
    // time source proceed, because refusing would make a device that has never synchronised
    // uncommissionable.
    verify_chain(&noc, None, &root, None).expect("no clock, no window check");
}

#[test]
fn ten_years_is_ten_years() {
    // 365.25 days a year, so a decade does not land a fortnight early — a certificate that
    // expires before a deployment expects it to is a fleet that stops talking on a Tuesday.
    let window = Validity::years(NOW, 10);
    let days = (window.not_after - window.not_before) / 86_400;
    assert_eq!(days, 3_652);

    // §6.5.5's open-ended form is available but never the default.
    assert_eq!(Validity::forever(NOW).not_after, 0);
}

// --- The whole identity, end to end ---------------------------------------------------------

#[test]
fn a_key_identifier_is_a_hint_and_the_signature_is_the_proof() {
    // §6.5.11.5's authority key identifier "names" the issuer, and `verify_chain` uses it as a
    // cheap pre-filter. It is not evidence: this crate does not implement SHA-1 and derives the
    // identifier from SHA-256 instead, which §6.5.11.4 permits ("other methods of generating
    // unique key identifiers are also acceptable"). If the identifier were load-bearing, that
    // substitution would be a security change rather than an implementation choice.
    let mut fabric = new_fabric(None);
    let (_, node_key) = key(&mut fabric.keys, 7);
    let mut buf = [0u8; CERT_TLV_MAX];
    let noc = fabric
        .ca
        .issue_noc(
            &fabric.keys,
            &mut buf,
            &Identity::new(FabricId(1), NodeId(10)),
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("a NOC")
        .to_vec();
    let root = MatterCertificate::decode(&fabric.root).expect("decodes");
    let noc = MatterCertificate::decode(&noc).expect("decodes");

    // The identifiers line up, which is what lets a chain be *built*...
    assert_eq!(
        noc.extensions.authority_key_id(),
        root.extensions.subject_key_id()
    );
    assert_eq!(noc.extensions.subject_key_id().map(|id| id.len()), Some(20));

    // ...and a NOC from a different root does not verify even though it is well formed.
    // A *different* root key, which is the whole point of the assertion below.
    let mut other = new_fabric_with(2, None);
    let (_, other_node) = key(&mut other.keys, 9);
    let mut buf = [0u8; CERT_TLV_MAX];
    let foreign = other
        .ca
        .issue_noc(
            &other.keys,
            &mut buf,
            &Identity::new(FabricId(1), NodeId(10)),
            &other_node,
            Validity::years(NOW, 1),
        )
        .expect("a NOC")
        .to_vec();
    let foreign = MatterCertificate::decode(&foreign).expect("decodes");
    assert!(verify_chain(&foreign, None, &root, Some(NOW)).is_err());
}

#[test]
fn an_intermediate_may_issue_nocs_and_nothing_else() {
    // §6.4.5.1 permits exactly one level: "an Intermediate Certificate Authority whose ICA
    // certificate is directly issued by such a Root CA". An intermediate that could mint
    // further intermediates would make the chain's depth unbounded — and the path-length
    // constraint of 0 that `issue_icac` writes says it must not, so the CA has to agree with
    // its own output.
    let mut fabric = new_fabric(None);
    let (icac_key, icac_public) = key(&mut fabric.keys, 3);
    let mut buf = [0u8; CERT_TLV_MAX];
    fabric
        .ca
        .issue_icac(
            &fabric.keys,
            &mut buf,
            0xBEEF,
            &icac_public,
            Validity::years(NOW, 5),
        )
        .expect("a root may issue an ICAC");

    let intermediate = CertAuthority::intermediate(icac_key, 0xBEEF);
    let (_, other_public) = key(&mut fabric.keys, 4);
    let mut buf = [0u8; CERT_TLV_MAX];
    assert!(
        intermediate
            .issue_icac(
                &fabric.keys,
                &mut buf,
                0xF00D,
                &other_public,
                Validity::years(NOW, 5)
            )
            .is_err(),
        "an intermediate minted a second intermediate"
    );

    // Nor can it declare itself a root.
    let mut buf = [0u8; CERT_TLV_MAX];
    assert!(
        intermediate
            .self_signed_root(&fabric.keys, &mut buf, Validity::years(NOW, 10))
            .is_err()
    );

    // What it *can* do is the thing it exists for.
    let (_, node_key) = key(&mut fabric.keys, 7);
    let mut buf = [0u8; CERT_TLV_MAX];
    intermediate
        .issue_noc(
            &fabric.keys,
            &mut buf,
            &Identity::new(FabricId(1), NodeId(10)),
            &node_key,
            Validity::years(NOW, 1),
        )
        .expect("an intermediate issues NOCs");
}

#[test]
fn every_key_yields_a_positive_serial_number() {
    // §6.5.4: a Matter certificate "follows the same limitation on admissible serial numbers as
    // in [RFC 5280]", and RFC 5280 §4.1.2.2 is where that limitation reads "The serial number
    // MUST be a positive integer". §6.5.4's `serial-num` **is** the DER INTEGER's content —
    // carried through unchanged, sign octet and all. The serial here is derived from the subject
    // key's digest, which is uniformly random, so two things follow that a fixed-seed fixture
    // never shows:
    //
    //   - the high bit of the first octet is the sign, so half of all keys would produce a
    //     *negative* serial, which RFC 5280 forbids in as many words;
    //   - one digest in 256 begins with a redundant sign octet, which DER's shortest-form rule
    //     makes invalid content, so the certificate does not encode at all.
    //
    // Both are one call to `positive_serial`, and both are invisible to a test that uses three
    // fixed seeds. This sweeps the whole octet.
    for seed in 0..=u8::MAX {
        let fabric = new_fabric_with(seed, None);
        let root = MatterCertificate::decode(&fabric.root)
            .unwrap_or_else(|e| panic!("seed {seed}: the root did not decode: {e:?}"));
        let first = root.serial_number[0];
        assert!(
            (0x01..0x80).contains(&first),
            "seed {seed}: the serial starts {first:#04x}, which is negative or a redundant zero"
        );
    }
}
