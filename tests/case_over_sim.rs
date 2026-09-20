//! A full CASE exchange between two nodes, driven with the specification's own operational
//! certificates and private keys.
//!
//! The certificates are §6.5.15's published RCAC/ICAC/NOC and the EC private keys printed
//! beside them, so the responder's identity is one the CSA issued, not one this crate
//! invented. The initiator's NOC is **minted here**, signed by the specification's ICAC
//! private key — which means the test also exercises the issuance path a commissioner uses,
//! and proves that a certificate this crate builds is one this crate (and, since the DER is
//! byte-exact against the published examples, anyone else) will accept.
//!
//! What the exchange proves that a unit test could not:
//!
//! * the two ends agree on all three session keys, having exchanged only public values;
//! * each end authenticated the other's certificate chain up to the same trusted root;
//! * the transcript binding works — a tampered Sigma1 changes S2K and the Sigma2 no longer
//!   decrypts;
//! * resumption reaches the same peer identity at a fraction of the work, and falls back to
//!   the full protocol when the responder has forgotten the session.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use hex_literal::hex;
use matter_kit::cert::{
    BasicConstraints, CERT_DER_MAX, CERT_TLV_MAX, DistinguishedName, DnAttribute, EllipticCurveId,
    Extension, Extensions, KeyPurposeId, KeyUsage, MatterCertificate, PublicKeyAlgorithm,
    SignatureAlgorithm, der,
};
use matter_kit::crypto::{GROUP_SIZE_BYTES, KeyPurpose, KeyStore, SoftKeyStore, SymmetricKey};
use matter_kit::fabric::{Credentials, Fabric, FabricIdentity};
use matter_kit::msg::{FabricIndex, NodeId, NonceSource, SessionId, VendorId};
use matter_kit::platform::Rng;
use matter_kit::platform::sim::SimRng;
use matter_kit::sc::{
    CaseInitiator, CaseOutcome, CaseResponder, Sigma1, Sigma2, Sigma2Resume, Sigma3,
};

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

/// §6.5.15.2's ICAC, which issued both NOCs used here.
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

/// §6.5.15.3's NOC — node `0xDEDEDEDE00010001` on fabric `0xFAB000000000001D`.
const NOC: &[u8] = &hex!(
    "153001083efcff1702b9a17a2402013703271303000000cacacaca182604ef171b27"
    "26056eb5b94c3706271101000100dededede27151d0000000000b0fa18"
    "24070124080130094104"
    "9a2a216fb39dd6b6fa211b835c89e3e6afb66c14f75831954f9ff4f7a3f0112c8a"
    "0d8eaf29c653294d48eee0708a032cca39393c3a7b46f181aea078fead8383"
    "370a350128011824020136030402040118"
    "3004149f55a26b7e4303e60883e913bf94f4fb5e2a6161"
    "300514535 2d7059e9c15a508906862864801a29f1f41d318300b40"
    "7955c202630b4ba4d5912526322fdf28f89edfe5af9c0e572bd8a14aaabb4d12"
    "b83ca17c7b05fb164b77d79c529613316bcfd17895e4b2a4f2404b981732715918"
);

/// The private key of §6.5.15.3's NOC, from the PEM block beside it.
const NOC_PRIVATE_KEY: [u8; GROUP_SIZE_BYTES] =
    hex!("a565b3fa28a8ed6a74fb6f0ff8a4d340d9e1ae98f21dfa1f0a59a4ea021a1627");
/// The private key of §6.5.15.2's ICAC, used here to issue the commissioner's NOC.
const ICAC_PRIVATE_KEY: [u8; GROUP_SIZE_BYTES] =
    hex!("11843bdcf0ad206db10251a54dac581d75f992fcb522752a216cd79c717546a9");

/// The fabric both nodes are on, from the NOC's `matter-fabric-id`.
const FABRIC_ID: matter_kit::msg::FabricId = matter_kit::msg::FabricId(0xFAB0_0000_0000_001D);
/// The IPK epoch key of §4.14.2.4.1's worked example.
const IPK_EPOCH: [u8; 16] = hex!("4a71cdd7b2a3ca9024f96f3c96a19dee");
/// A time inside every certificate's validity window.
const NOW: u32 = 0x271B_17F0;

const DEVICE_NODE_ID: NodeId = NodeId(0xDEDE_DEDE_0001_0001);
const COMMISSIONER_NODE_ID: NodeId = NodeId(0xDEDE_DEDE_0001_0002);

type Store = SoftKeyStore<8>;

/// Issues a NOC for `node_id` under §6.5.15.2's ICAC, signing it with the ICAC's key.
///
/// This is what a commissioner's CA does, and doing it here rather than pasting a second
/// canned certificate means the test proves the issuance path works — the DER this crate
/// regenerates is the DER the signature is computed over, and the result validates under
/// the same rules as the CSA's own certificate.
fn issue_noc(node_id: NodeId, public_key: matter_kit::crypto::PublicKey, out: &mut [u8]) -> usize {
    issue_noc_with_cats(node_id, public_key, &[], out)
}

/// The same, with §6.6.2.1.2's CASE Authenticated Tags in the subject DN.
fn issue_noc_with_cats(
    node_id: NodeId,
    public_key: matter_kit::crypto::PublicKey,
    cats: &[matter_kit::msg::CaseAuthenticatedTag],
    out: &mut [u8],
) -> usize {
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
    for cat in cats {
        subject.push(DnAttribute::noc_cat(*cat)).expect("noc cat");
    }

    // §6.5.11.4: the subject key identifier is "the 160-bit SHA-1 hash of the certificate's
    // subject public key value". This crate has no SHA-1 — it is not in the Matter
    // cryptosuite, and adding one for a key identifier would be a poor trade. A key
    // identifier only has to be a stable, unique-per-key label for path building, and the
    // signature is what actually authenticates, so a truncated SHA-256 serves here. A real
    // CA must use SHA-1 to interoperate with X.509 tooling.
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
        // Filled in below, once there is a tbsCertificate to sign.
        signature: matter_kit::crypto::Signature::from_bytes([0; 64]),
    };

    let mut der_buf = [0u8; CERT_DER_MAX];
    let tbs = der::tbs_certificate(&cert, &mut der_buf).expect("tbs");
    cert.signature = ca.sign(ca_handle, tbs).expect("sign");

    let encoded = cert.encode(out).expect("encode").len();
    // It must validate under the same rules the specification's own certificates do.
    let round = MatterCertificate::decode(&out[..encoded]).expect("decode what we just wrote");
    round.validate().expect("a valid NOC");
    encoded
}

/// The two nodes, each with its fabric entry, key store and certificate chain.
struct Peers {
    device: Fabric,
    device_keys: Store,
    commissioner: Fabric,
    commissioner_keys: Store,
    commissioner_noc: [u8; CERT_TLV_MAX],
    commissioner_noc_len: usize,
}

fn peers() -> Peers {
    let root = MatterCertificate::decode(RCAC).expect("rcac");

    let mut device_keys = Store::new();
    let device_handle = device_keys
        .import(KeyPurpose::Operational, &NOC_PRIVATE_KEY)
        .expect("import");
    let device = Fabric::new(
        FabricIndex(1),
        FabricIdentity {
            fabric_id: FABRIC_ID,
            node_id: DEVICE_NODE_ID,
            root_public_key: root.public_key,
            admin_vendor_id: VendorId(0xFFF1),
        },
        &SymmetricKey::new(IPK_EPOCH),
        device_handle,
        Credentials::new(NOC, RCAC)
            .expect("fits")
            .with_icac(ICAC)
            .expect("fits"),
    )
    .expect("device fabric");

    let mut commissioner_keys = Store::new();
    let rng = SimRng::new(0xC0FF_EE00_1234_5678);
    let mut random = [0u8; GROUP_SIZE_BYTES];
    rng.fill(&mut random).expect("rng");
    let (commissioner_handle, commissioner_public) = commissioner_keys
        .generate(KeyPurpose::Operational, &random)
        .expect("generate");

    let mut commissioner_noc = [0u8; CERT_TLV_MAX];
    let commissioner_noc_len = issue_noc(
        COMMISSIONER_NODE_ID,
        commissioner_public,
        &mut commissioner_noc,
    );

    let commissioner = Fabric::new(
        FabricIndex(1),
        FabricIdentity {
            fabric_id: FABRIC_ID,
            node_id: COMMISSIONER_NODE_ID,
            root_public_key: root.public_key,
            admin_vendor_id: VendorId(0xFFF1),
        },
        &SymmetricKey::new(IPK_EPOCH),
        commissioner_handle,
        Credentials::new(
            commissioner_noc
                .get(..commissioner_noc_len)
                .expect("in range"),
            RCAC,
        )
        .expect("fits")
        .with_icac(ICAC)
        .expect("fits"),
    )
    .expect("commissioner fabric");

    Peers {
        device,
        device_keys,
        commissioner,
        commissioner_keys,
        commissioner_noc,
        commissioner_noc_len,
    }
}

/// 32 octets of deterministic "randomness", so a failure is reproducible.
fn randomness(rng: &SimRng) -> [u8; 32] {
    let mut out = [0u8; 32];
    rng.fill(&mut out).expect("rng");
    out
}

/// Runs the full three-message exchange, returning both ends' outcomes.
fn run_case(peers: &mut Peers, seed: u64) -> (CaseOutcome, CaseOutcome) {
    let rng = SimRng::new(seed);
    let root = MatterCertificate::decode(RCAC).expect("rcac");
    let commissioner_noc = &peers.commissioner_noc[..peers.commissioner_noc_len];

    let mut initiator = CaseInitiator::new(SessionId(0x1111), None);
    let mut responder = CaseResponder::new(SessionId(0x2222), None);

    // Sigma1.
    let mut msg1 = [0u8; 512];
    let len1 = initiator
        .start(
            &peers.commissioner,
            DEVICE_NODE_ID,
            &mut peers.commissioner_keys,
            &randomness(&rng),
            &randomness(&rng),
            &mut msg1,
        )
        .expect("sigma1");
    let sigma1 = Sigma1::decode(&msg1[..len1]).expect("decode sigma1");
    assert!(!sigma1.is_resumption());

    // Sigma2.
    let mut msg2 = [0u8; 1024];
    let mut resumption_random = [0u8; 16];
    rng.fill(&mut resumption_random).expect("rng");
    let len2 = responder
        .handle_sigma1(
            &sigma1,
            &peers.device,
            NOC,
            Some(ICAC),
            &mut peers.device_keys,
            &randomness(&rng),
            &randomness(&rng),
            &resumption_random,
            &mut msg2,
        )
        .expect("sigma2");
    let sigma2 = Sigma2::decode(&msg2[..len2]).expect("decode sigma2");

    // Sigma3.
    let mut msg3 = [0u8; 1024];
    let (len3, initiator_outcome) = initiator
        .handle_sigma2(
            &sigma2,
            &peers.commissioner,
            &root,
            commissioner_noc,
            Some(ICAC),
            &mut peers.commissioner_keys,
            Some(NOW),
            &mut msg3,
        )
        .expect("sigma3");
    let sigma3 = Sigma3::decode(&msg3[..len3]).expect("decode sigma3");

    let responder_outcome = responder
        .handle_sigma3(&sigma3, &root, Some(NOW))
        .expect("accept sigma3");

    // SigmaFinished.
    let mut finished = [0u8; 32];
    let len = responder.finished(&mut finished).expect("finished");
    initiator
        .accept_finished(&finished[..len])
        .expect("accept finished");

    (initiator_outcome, responder_outcome)
}

#[test]
fn a_full_exchange_agrees_on_keys_and_identities() {
    let mut peers = peers();
    let (initiator, responder) = run_case(&mut peers, 0x1234_5678_9ABC_DEF0);

    // The whole point: two nodes that exchanged only public values hold the same keys.
    assert_eq!(initiator.keys, responder.keys, "session keys must agree");

    // And each authenticated the other, not itself.
    assert_eq!(initiator.peer.node_id, DEVICE_NODE_ID);
    assert_eq!(responder.peer.node_id, COMMISSIONER_NODE_ID);
    assert_eq!(initiator.peer.fabric_id, FABRIC_ID);
    assert_eq!(responder.peer.fabric_id, FABRIC_ID);

    // Each learned the session id the other will listen on.
    assert_eq!(initiator.peer_session_id, SessionId(0x2222));
    assert_eq!(responder.peer_session_id, SessionId(0x1111));

    // Both remember the same secret and resumption id, which is what makes resumption work.
    assert_eq!(
        initiator.resumption.resumption_id,
        responder.resumption.resumption_id
    );
}

#[test]
fn the_attestation_challenge_is_not_an_encryption_key() {
    // §4.14.2.6.6: "The AttestationChallenge SHALL only be used as a challenge during
    // device attestation." It must be a third, distinct value — a derivation that produced
    // a repeat of one of the session keys would be a real flaw.
    let mut peers = peers();
    let (initiator, _) = run_case(&mut peers, 0x0BAD_F00D_0BAD_F00D);
    let challenge = initiator.keys.attestation_challenge.as_bytes();
    assert_ne!(challenge, initiator.keys.i2r.encryption.as_bytes());
    assert_ne!(challenge, initiator.keys.r2i.encryption.as_bytes());
    assert_ne!(
        initiator.keys.i2r.encryption.as_bytes(),
        initiator.keys.r2i.encryption.as_bytes(),
        "the two directions must not share a key"
    );
}

#[test]
fn two_exchanges_produce_different_keys() {
    // Otherwise the ephemerals are not doing their job, and a recorded session could be
    // replayed into a later one.
    let mut first_peers = peers();
    let (first, _) = run_case(&mut first_peers, 1);
    let mut second_peers = peers();
    let (second, _) = run_case(&mut second_peers, 2);
    assert_ne!(first.keys, second.keys);
    assert_ne!(
        first.resumption.resumption_id,
        second.resumption.resumption_id
    );
}

#[test]
fn a_sigma1_for_another_node_is_refused() {
    // The destination identifier names the node the initiator means. A responder that
    // answered one addressed to somebody else would let an attacker enumerate a fabric.
    let mut peers = peers();
    let rng = SimRng::new(7);
    let mut initiator = CaseInitiator::new(SessionId(1), None);
    let mut responder = CaseResponder::new(SessionId(2), None);

    let mut msg1 = [0u8; 512];
    let len1 = initiator
        .start(
            &peers.commissioner,
            NodeId(0xDEDE_DEDE_0001_00FF), // not this device
            &mut peers.commissioner_keys,
            &randomness(&rng),
            &randomness(&rng),
            &mut msg1,
        )
        .expect("sigma1");
    let sigma1 = Sigma1::decode(&msg1[..len1]).expect("decode");

    let mut msg2 = [0u8; 1024];
    assert!(
        responder
            .handle_sigma1(
                &sigma1,
                &peers.device,
                NOC,
                Some(ICAC),
                &mut peers.device_keys,
                &randomness(&rng),
                &randomness(&rng),
                &[0u8; 16],
                &mut msg2,
            )
            .is_err()
    );
    assert!(responder.is_failed());
}

#[test]
fn a_tampered_sigma1_breaks_the_sigma2_the_initiator_expects() {
    // The transcript binding, demonstrated: S2K is salted with Hash(Msg1), so a Sigma1 the
    // initiator did not send produces a Sigma2 the initiator cannot decrypt. There is no
    // separate transcript MAC — the key is the MAC.
    let mut peers = peers();
    let rng = SimRng::new(11);
    let root = MatterCertificate::decode(RCAC).expect("rcac");
    let commissioner_noc = peers.commissioner_noc[..peers.commissioner_noc_len].to_vec();

    let mut initiator = CaseInitiator::new(SessionId(1), None);
    let mut responder = CaseResponder::new(SessionId(2), None);

    let mut msg1 = [0u8; 512];
    let len1 = initiator
        .start(
            &peers.commissioner,
            DEVICE_NODE_ID,
            &mut peers.commissioner_keys,
            &randomness(&rng),
            &randomness(&rng),
            &mut msg1,
        )
        .expect("sigma1");

    // A man in the middle re-encodes Sigma1 with different session parameters: every field
    // the responder validates is untouched, and the message is still perfectly well formed.
    let mut tampered = Sigma1::decode(&msg1[..len1]).expect("decode");
    tampered.session_params = Some(matter_kit::sc::SessionParams {
        idle_interval_ms: 1234,
        ..matter_kit::sc::SessionParams::legacy_peer()
    });
    let mut msg1b = [0u8; 512];
    let len1b = tampered.encode(&mut msg1b).expect("re-encode").len();
    let sigma1b = Sigma1::decode(&msg1b[..len1b]).expect("decode");

    let mut msg2 = [0u8; 1024];
    let mut resumption_random = [0u8; 16];
    rng.fill(&mut resumption_random).expect("rng");
    let len2 = responder
        .handle_sigma1(
            &sigma1b,
            &peers.device,
            NOC,
            Some(ICAC),
            &mut peers.device_keys,
            &randomness(&rng),
            &randomness(&rng),
            &resumption_random,
            &mut msg2,
        )
        .expect("the responder is happy: the message is valid");
    let sigma2 = Sigma2::decode(&msg2[..len2]).expect("decode");

    // The initiator is not, because its transcript holds the message it actually sent.
    let mut msg3 = [0u8; 1024];
    assert!(
        initiator
            .handle_sigma2(
                &sigma2,
                &peers.commissioner,
                &root,
                &commissioner_noc,
                Some(ICAC),
                &mut peers.commissioner_keys,
                Some(NOW),
                &mut msg3,
            )
            .is_err(),
        "a modified Sigma1 must make Sigma2 undecryptable"
    );
    assert!(initiator.is_failed());
}

#[test]
fn an_expired_chain_is_refused_at_sigma2() {
    let mut peers = peers();
    let rng = SimRng::new(13);
    let root = MatterCertificate::decode(RCAC).expect("rcac");
    let commissioner_noc = peers.commissioner_noc[..peers.commissioner_noc_len].to_vec();

    let mut initiator = CaseInitiator::new(SessionId(1), None);
    let mut responder = CaseResponder::new(SessionId(2), None);

    let mut msg1 = [0u8; 512];
    let len1 = initiator
        .start(
            &peers.commissioner,
            DEVICE_NODE_ID,
            &mut peers.commissioner_keys,
            &randomness(&rng),
            &randomness(&rng),
            &mut msg1,
        )
        .expect("sigma1");
    let sigma1 = Sigma1::decode(&msg1[..len1]).expect("decode");

    let mut msg2 = [0u8; 1024];
    let len2 = responder
        .handle_sigma1(
            &sigma1,
            &peers.device,
            NOC,
            Some(ICAC),
            &mut peers.device_keys,
            &randomness(&rng),
            &randomness(&rng),
            &[3u8; 16],
            &mut msg2,
        )
        .expect("sigma2");
    let sigma2 = Sigma2::decode(&msg2[..len2]).expect("decode");

    let mut msg3 = [0u8; 1024];
    assert_eq!(
        initiator
            .handle_sigma2(
                &sigma2,
                &peers.commissioner,
                &root,
                &commissioner_noc,
                Some(ICAC),
                &mut peers.commissioner_keys,
                Some(0x4CB9_B56F), // one second after not-after
                &mut msg3,
            )
            .map(|_| ())
            .unwrap_err()
            .code(),
        matter_kit::ErrorCode::CertExpired
    );
}

#[test]
fn a_resumption_reaches_the_same_peer_with_no_signatures() {
    let mut peers = peers();
    let (initiator_first, responder_first) = run_case(&mut peers, 0xAAAA_BBBB_CCCC_DDDD);

    let rng = SimRng::new(0xFACE_0FF1_CE00_0001);
    let mut initiator = CaseInitiator::new(SessionId(0x3333), None);
    let mut responder = CaseResponder::new(SessionId(0x4444), None);

    let mut msg1 = [0u8; 512];
    let len1 = initiator
        .start_resumption(
            &peers.commissioner,
            DEVICE_NODE_ID,
            &initiator_first.resumption,
            &mut peers.commissioner_keys,
            &randomness(&rng),
            &randomness(&rng),
            &mut msg1,
        )
        .expect("sigma1 with resumption");
    let sigma1 = Sigma1::decode(&msg1[..len1]).expect("decode");
    assert!(sigma1.is_resumption(), "both fields must be present");

    let mut msg2 = [0u8; 256];
    let mut new_id = [0u8; 16];
    rng.fill(&mut new_id).expect("rng");
    let (len2, responder_outcome) = responder
        .handle_sigma1_resumption(&sigma1, &responder_first.resumption, &new_id, &mut msg2)
        .expect("resume");
    let resume = Sigma2Resume::decode(&msg2[..len2]).expect("decode");

    let initiator_outcome = initiator
        .accept_resume(
            &resume,
            &initiator_first.resumption,
            &mut peers.commissioner_keys,
        )
        .expect("accept resume");

    assert_eq!(initiator_outcome.keys, responder_outcome.keys);
    // A resumption is far cheaper than a full exchange, and it must still land on the same
    // identities — that is the property that makes it safe to skip the signatures.
    assert_eq!(initiator_outcome.peer, initiator_first.peer);
    assert_eq!(responder_outcome.peer, responder_first.peer);
    // And the keys are new, not the old session's.
    assert_ne!(initiator_outcome.keys, initiator_first.keys);
    // The resumption id rolls forward, so the next resumption chains off this one.
    assert_eq!(initiator_outcome.resumption.resumption_id, new_id);
    assert_eq!(responder_outcome.resumption.resumption_id, new_id);
}

#[test]
fn a_resumption_with_the_wrong_secret_is_refused_and_the_responder_can_retry() {
    // §4.14.2.2: a responder that cannot resume "SHALL process the message as a Sigma1
    // without any resumption fields", so a failed resumption must leave it usable.
    let mut peers = peers();
    let (initiator_first, responder_first) = run_case(&mut peers, 0x5555_6666_7777_8888);

    let rng = SimRng::new(0xFEED_FACE_0000_0002);
    let mut initiator = CaseInitiator::new(SessionId(5), None);
    let mut responder = CaseResponder::new(SessionId(6), None);

    let mut msg1 = [0u8; 512];
    let len1 = initiator
        .start_resumption(
            &peers.commissioner,
            DEVICE_NODE_ID,
            &initiator_first.resumption,
            &mut peers.commissioner_keys,
            &randomness(&rng),
            &randomness(&rng),
            &mut msg1,
        )
        .expect("sigma1 with resumption");
    let sigma1 = Sigma1::decode(&msg1[..len1]).expect("decode");

    // The responder remembers the right id but the wrong secret — a device that was
    // factory reset and re-commissioned, say.
    let mut wrong = responder_first.resumption.clone();
    wrong.shared_secret = matter_kit::crypto::Secret::new([0x11; 32]);

    let mut msg2 = [0u8; 256];
    assert!(
        responder
            .handle_sigma1_resumption(&sigma1, &wrong, &[9u8; 16], &mut msg2)
            .is_err()
    );
    assert!(!responder.is_failed(), "it must still be usable");

    // And the full path completes from the very same Sigma1.
    let mut msg2b = [0u8; 1024];
    let len2 = responder
        .handle_sigma1(
            &sigma1,
            &peers.device,
            NOC,
            Some(ICAC),
            &mut peers.device_keys,
            &randomness(&rng),
            &randomness(&rng),
            &[4u8; 16],
            &mut msg2b,
        )
        .expect("falls back to a full Sigma2");
    assert!(Sigma2::decode(&msg2b[..len2]).is_ok());
}

#[test]
fn a_minted_noc_is_accepted_by_the_same_rules_as_the_published_one() {
    // The commissioner's certificate is built by this crate and signed with the
    // specification's ICAC key. If the DER regeneration were wrong in any way, this chain
    // would not verify — which is the same check a real device performs at Sigma3.
    let peers = peers();
    let root = MatterCertificate::decode(RCAC).expect("rcac");
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let noc = MatterCertificate::decode(&peers.commissioner_noc[..peers.commissioner_noc_len])
        .expect("minted noc");

    let identity =
        matter_kit::cert::verify_chain(&noc, Some(&icac), &root, Some(NOW)).expect("chain");
    assert_eq!(identity.node_id, COMMISSIONER_NODE_ID);
    assert_eq!(identity.fabric_id, FABRIC_ID);
}

#[test]
fn the_initiator_refuses_a_responder_that_is_not_the_node_it_addressed() {
    // §4.14.2.3, *Validate Sigma2* step 5a: "The Fabric ID and Node ID SHALL match the
    // intended identity of the receiver Node, as included in the computation of the
    // Destination Identifier when generating Sigma1."
    //
    // Without this check, any node holding a valid NOC on the same fabric could answer in
    // place of the one that was addressed, and the initiator would end up with a perfectly
    // sound session to the wrong device. The exchange below is legitimate in every other
    // respect: the responder's chain verifies, its signature verifies, and it holds the
    // fabric's IPK. Only its node id is wrong.
    let mut peers = peers();
    let rng = SimRng::new(0x5A5A_5A5A_5A5A_5A5A);
    let root = MatterCertificate::decode(RCAC).expect("rcac");
    let commissioner_noc = peers.commissioner_noc[..peers.commissioner_noc_len].to_vec();

    // A second device on the same fabric, with its own NOC issued by the same ICAC.
    let impostor_node = NodeId(0xDEDE_DEDE_0001_0009);
    let mut impostor_keys = Store::new();
    let mut key_random = [0u8; GROUP_SIZE_BYTES];
    rng.fill(&mut key_random).expect("rng");
    let (impostor_handle, impostor_public) = impostor_keys
        .generate(KeyPurpose::Operational, &key_random)
        .expect("generate");
    let mut impostor_noc = [0u8; CERT_TLV_MAX];
    let impostor_noc_len = issue_noc(impostor_node, impostor_public, &mut impostor_noc);
    let _ = impostor_handle;

    // The impostor's credentials are impeccable: its chain verifies to the same trusted root
    // on the same fabric. If this failed, the test below would pass for the wrong reason.
    {
        let icac = MatterCertificate::decode(ICAC).expect("icac");
        let noc = MatterCertificate::decode(&impostor_noc[..impostor_noc_len]).expect("noc");
        let identity =
            matter_kit::cert::verify_chain(&noc, Some(&icac), &root, Some(NOW)).expect("chain");
        assert_eq!(identity.fabric_id, FABRIC_ID);
        assert_eq!(identity.node_id, impostor_node);
    }

    let mut initiator = CaseInitiator::new(SessionId(1), None);
    let mut responder = CaseResponder::new(SessionId(2), None);

    // The initiator addresses the *device*.
    let mut msg1 = [0u8; 512];
    let len1 = initiator
        .start(
            &peers.commissioner,
            DEVICE_NODE_ID,
            &mut peers.commissioner_keys,
            &randomness(&rng),
            &randomness(&rng),
            &mut msg1,
        )
        .expect("sigma1");
    let sigma1 = Sigma1::decode(&msg1[..len1]).expect("decode");

    // The impostor answers. It has to be handed the device's fabric entry to match the
    // destination identifier at all — which is the first line of defence — so the test
    // reaches past that to the check being exercised, and replies with its own NOC.
    let mut msg2 = [0u8; 1024];
    let len2 = responder
        .handle_sigma1(
            &sigma1,
            &peers.device,
            &impostor_noc[..impostor_noc_len],
            Some(ICAC),
            &mut impostor_keys,
            &randomness(&rng),
            &randomness(&rng),
            &[8u8; 16],
            &mut msg2,
        )
        .expect("a well-formed Sigma2");
    let sigma2 = Sigma2::decode(&msg2[..len2]).expect("decode");

    let mut msg3 = [0u8; 1024];
    assert_eq!(
        initiator
            .handle_sigma2(
                &sigma2,
                &peers.commissioner,
                &root,
                &commissioner_noc,
                Some(ICAC),
                &mut peers.commissioner_keys,
                Some(NOW),
                &mut msg3,
            )
            .map(|_| ())
            .unwrap_err()
            .code(),
        matter_kit::ErrorCode::CertPathInvalid,
        "a NOC for the wrong node must be refused"
    );
    assert!(initiator.is_failed());
}

#[test]
fn a_failed_exchange_does_not_strand_ephemeral_keys() {
    // A key store has a fixed number of slots. If a failed CASE left its ephemeral behind, a
    // peer that fails repeatedly — or an attacker sending malformed Sigma2s — would exhaust
    // the store and stop the node establishing any session at all.
    let mut peers = peers();
    let rng = SimRng::new(0x7777_8888_9999_AAAA);
    let root = MatterCertificate::decode(RCAC).expect("rcac");
    let commissioner_noc = peers.commissioner_noc[..peers.commissioner_noc_len].to_vec();

    // One operational key is in the store to begin with.
    let before = peers.commissioner_keys.len();

    // More failures than the store has slots.
    for round in 0..12u64 {
        let mut initiator = CaseInitiator::new(SessionId(1), None);
        let mut responder = CaseResponder::new(SessionId(2), None);

        let mut msg1 = [0u8; 512];
        let len1 = initiator
            .start(
                &peers.commissioner,
                DEVICE_NODE_ID,
                &mut peers.commissioner_keys,
                &randomness(&rng),
                &randomness(&rng),
                &mut msg1,
            )
            .expect("sigma1");
        let sigma1 = Sigma1::decode(&msg1[..len1]).expect("decode");

        let mut msg2 = [0u8; 1024];
        let len2 = responder
            .handle_sigma1(
                &sigma1,
                &peers.device,
                NOC,
                Some(ICAC),
                &mut peers.device_keys,
                &randomness(&rng),
                &randomness(&rng),
                &[round as u8; 16],
                &mut msg2,
            )
            .expect("sigma2");

        // Corrupt the ciphertext so the initiator's decryption fails.
        let mut sigma2 = Sigma2::decode(&msg2[..len2]).expect("decode");
        let mut encrypted = sigma2.encrypted2.to_vec();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        sigma2.encrypted2 = &encrypted;
        let mut msg2b = [0u8; 1024];
        let len2b = sigma2.encode(&mut msg2b).expect("re-encode").len();
        let sigma2 = Sigma2::decode(&msg2b[..len2b]).expect("decode");

        let mut msg3 = [0u8; 1024];
        assert!(
            initiator
                .handle_sigma2(
                    &sigma2,
                    &peers.commissioner,
                    &root,
                    &commissioner_noc,
                    Some(ICAC),
                    &mut peers.commissioner_keys,
                    Some(NOW),
                    &mut msg3,
                )
                .is_err(),
            "round {round}"
        );
        assert_eq!(
            peers.commissioner_keys.len(),
            before,
            "round {round}: the ephemeral outlived the exchange"
        );
        // And the responder's store, whose ephemeral is destroyed the moment ECDH is done.
        assert_eq!(peers.device_keys.len(), 1, "round {round}");
    }

    // The store is still usable, which is the property that matters.
    let mut initiator = CaseInitiator::new(SessionId(1), None);
    let mut msg1 = [0u8; 512];
    initiator
        .start(
            &peers.commissioner,
            DEVICE_NODE_ID,
            &mut peers.commissioner_keys,
            &randomness(&rng),
            &randomness(&rng),
            &mut msg1,
        )
        .expect("a thirteenth exchange still starts");
}

/// A NOC's CASE Authenticated Tags survive verification and reach the access-control subject.
///
/// §6.6.6.3 builds the subject from a CASE session's node id **and** its CATs, and the CATs
/// exist only in the certificate that CASE verified. A chain check that returned the node id
/// and discarded the tags would leave every CAT-based access control entry unable to match
/// anything — silently, and in the direction that denies rather than grants, so the symptom is
/// a fleet of nodes that were granted access and do not have it.
#[test]
fn a_nocs_case_authenticated_tags_reach_the_access_control_subject() {
    use matter_kit::acl::SubjectDescriptor;
    use matter_kit::msg::{CaseAuthenticatedTag, FabricIndex, SessionId};
    use matter_kit::session::{EstablishedKeys, Role, SecureSession, SessionKind};

    let tags = [
        CaseAuthenticatedTag::new(0xABCD, 3),
        CaseAuthenticatedTag::new(0x1234, 1),
    ];

    let mut store = Store::new();
    let key_random = [0x42u8; GROUP_SIZE_BYTES];
    let (handle, public) = store
        .generate(KeyPurpose::Operational, &key_random)
        .expect("generate");
    let _ = handle;

    let node_id = NodeId(0x0000_0000_0000_ABCD);
    let mut noc = [0u8; 512];
    let len = issue_noc_with_cats(node_id, public, &tags, &mut noc);
    let noc = MatterCertificate::decode(&noc[..len]).expect("decode the minted NOC");

    // The tags are in the DN the CA wrote.
    assert_eq!(noc.subject.noc_cats().as_slice(), &tags);

    // ...and they survive chain verification, which is the step that could drop them.
    let icac = MatterCertificate::decode(ICAC).expect("icac");
    let rcac = MatterCertificate::decode(RCAC).expect("rcac");
    let identity = matter_kit::cert::verify_chain(&noc, Some(&icac), &rcac, None)
        .expect("the minted NOC verifies");
    assert_eq!(identity.node_id, node_id);
    assert_eq!(identity.cats.as_slice(), &tags);

    // ...and reach the subject §6.6.6.2 matches entries against.
    let mut session = SecureSession::new(
        SessionId(1),
        SessionId(2),
        SessionKind::Case,
        Role::Responder,
        EstablishedKeys::derive(b"secret", &[]).expect("derive"),
        1,
        matter_kit::platform::Instant::ZERO,
    );
    session.fabric_index = FabricIndex(1);
    session.peer_node_id = identity.node_id;
    for cat in &identity.cats {
        session.peer_cats.push(*cat).expect("two fit");
    }

    let isd = SubjectDescriptor::from_session(&session, None);
    assert_eq!(isd.subjects.len(), 1 + tags.len());
    assert_eq!(isd.subjects[0], node_id);
    for (index, tag) in tags.iter().enumerate() {
        assert_eq!(isd.subjects[index + 1], tag.to_node_id());
    }
}

/// §4.9.2's nonce is "the Security Flags, the Message Counter, and the Source Node ID of that
/// message", and on a CASE session the Source Node ID is the sender's *operational* node id —
/// which never travels in the header, because both ends are meant to know it from the session.
///
/// A session whose `local_node_id` is left at [`NodeId::UNSPECIFIED`] therefore encrypts every
/// message with a nonce its peer cannot reconstruct, and the peer discards them as
/// unauthenticated. Nothing fails locally, so what it looks like is a peer that has gone quiet.
///
/// The assertion that matters is the last one: two sessions both left unspecified *agree with
/// each other*, so a test that only round-trips between two of this crate's own sessions passes
/// while every real peer refuses the traffic. That is exactly how this reached the wire.
#[test]
fn a_case_session_encrypts_under_its_operational_node_id() {
    let mut peers = peers();
    let (initiator_outcome, responder_outcome) = run_case(&mut peers, 0x5EED);

    let now = matter_kit::platform::Instant::from_micros(0);
    let device = responder_outcome.into_session(SessionId(0x2222), &peers.device, 1, now);
    let commissioner =
        initiator_outcome.into_initiator_session(SessionId(0x1111), &peers.commissioner, 1, now);

    // Each side signs with its own identity...
    assert_eq!(
        device.send_nonce_source(),
        NonceSource::Case(peers.device.node_id)
    );
    assert_eq!(
        commissioner.send_nonce_source(),
        NonceSource::Case(peers.commissioner.node_id)
    );
    // ...and expects the other's.
    assert_eq!(
        device.recv_nonce_source(),
        NonceSource::Case(peers.commissioner.node_id)
    );
    assert_eq!(
        commissioner.recv_nonce_source(),
        NonceSource::Case(peers.device.node_id)
    );

    // Neither is the default, and the two differ. Both halves are load-bearing: a pair left
    // at `UNSPECIFIED` satisfies "they match" and fails against everything else on the wire.
    assert_ne!(
        device.send_nonce_source(),
        NonceSource::Case(NodeId::UNSPECIFIED)
    );
    assert_ne!(
        commissioner.send_nonce_source(),
        NonceSource::Case(NodeId::UNSPECIFIED)
    );
    assert_ne!(device.send_nonce_source(), commissioner.send_nonce_source());

    // The fabric and the peer identity come across too, because access control reads them
    // from session metadata rather than from the message (§6.6.6.3).
    assert_eq!(device.fabric_index, peers.device.index);
    assert_eq!(device.peer_node_id, peers.commissioner.node_id);
}
