//! The three fabric-identifier derivations, against the specification's worked examples.
//!
//! Core §4.3.2.2, §4.17.2 and §4.14.2.4.1 each print a complete example with its expected
//! output. They are worth pinning at the public boundary as well as inside the module,
//! because all three are load-bearing in ways that fail silently:
//!
//! * a wrong **compressed fabric identifier** produces a node that advertises itself under
//!   a name no controller is looking for — it simply never appears;
//! * a wrong **operational group key** produces group messages nobody can decrypt;
//! * a wrong **destination identifier** produces a CASE that always answers
//!   `NO_SHARED_TRUST_ROOTS`, on both sides, for every peer.
//!
//! None of those looks like a cryptographic error from the outside. They look like a device
//! that does not work.
//!
//! The three also disagree about endianness and about the public key's `04` prefix, in ways
//! that are easy to get backwards and impossible to notice without exactly these vectors —
//! which is the reason they are here rather than trusted to review.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use hex_literal::hex;
use matter_kit::crypto::{PublicKey, SymmetricKey};
use matter_kit::fabric::{
    CompressedFabricId, compressed_fabric_id, destination_identifier, operational_group_key,
};
use matter_kit::msg::{FabricId, NodeId};

/// The root public key of §4.3.2.2's and §4.14.2.4.1's examples, in "raw uncompressed point
/// form" — with the `04` marker that §4.3.2.2 then strips and §4.14.2.4.1 keeps.
const ROOT_PUBLIC_KEY: [u8; 65] = hex!(
    "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641c"
    "b8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfac"
    "fa"
);

/// "a TargetOperationalFabricID value of 0x2906_C908_D115_D362".
const FABRIC: FabricId = FabricId(0x2906_C908_D115_D362);

fn root_key() -> PublicKey {
    PublicKey::from_bytes(ROOT_PUBLIC_KEY)
}

#[test]
fn section_4_3_2_2_compressed_fabric_identifier() {
    // "…then the CompressedFabricIdentifier to use in advertising would be
    // 87E1B004E235A130 (octet string 87:e1:b0:04:e2:35:a1:30)."
    let compressed = compressed_fabric_id(&root_key(), FABRIC).expect("derive");
    assert_eq!(compressed, CompressedFabricId(0x87E1_B004_E235_A130));
    assert_eq!(compressed.to_bytes(), hex!("87e1b004e235a130"));
    // §4.3.2.1 renders it as sixteen uppercase hex characters, and §4.3.2.3 as a subtype.
    assert_eq!(compressed.to_hex().as_str(), "87E1B004E235A130");
    assert_eq!(compressed.subtype().as_str(), "_I87E1B004E235A130");
}

#[test]
fn section_4_17_2_operational_group_key() {
    // "An Epoch Key value of: 23:5b:f7:e6:… A CompressedFabricIdentifier value of:
    // 87:e1:b0:04:e2:35:a1:30 … the resulting operational group key would be:
    // a6:f5:30:6b:af:6d:05:0a:f2:3b:a4:bd:6b:9d:d9:60."
    let epoch = SymmetricKey::new(hex!("235bf7e62823d358dca4ba50b1535f4b"));
    let key =
        operational_group_key(&epoch, CompressedFabricId(0x87E1_B004_E235_A130)).expect("derive");
    assert_eq!(key.as_bytes(), &hex!("a6f5306baf6d050af23ba4bd6b9dd960"));
}

#[test]
fn section_4_14_2_4_1_identity_protection_key() {
    // "The derived Operational Group Key to be used for computation of a destination
    // identifier … would be: IPK := 9b:c6:1c:d9:…" — the same derivation as above, applied
    // to the IPK epoch key, which is what makes the IPK "the operational group key under
    // GroupKeySetID of 0".
    let epoch = SymmetricKey::new(hex!("4a71cdd7b2a3ca9024f96f3c96a19dee"));
    let compressed = compressed_fabric_id(&root_key(), FABRIC).expect("derive");
    let ipk = operational_group_key(&epoch, compressed).expect("derive");
    assert_eq!(ipk.as_bytes(), &hex!("9bc61cd9c62a2df6d64dfcaa9dc472d4"));
}

#[test]
fn section_4_14_2_4_1_destination_identifier() {
    // The whole chain, ending in the value the specification prints under
    // "DestinationIdentifier octets".
    let epoch = SymmetricKey::new(hex!("4a71cdd7b2a3ca9024f96f3c96a19dee"));
    let compressed = compressed_fabric_id(&root_key(), FABRIC).expect("derive");
    let ipk = operational_group_key(&epoch, compressed).expect("derive");

    let initiator_random = hex!("7e171231568dfa17206b3accf8faec2f4d21b580113196f47c7c4deb810a73dc");
    let id = destination_identifier(
        &ipk,
        &initiator_random,
        &root_key(),
        FABRIC,
        NodeId(0xCD55_44AA_7B13_EF14),
    )
    .expect("derive");

    assert_eq!(
        id,
        hex!("dc35dd5fc9134cc5544538c9c3fc4297c1ec3370c839136a80e10796451d4c53")
    );
}

#[test]
fn the_two_endiannesses_are_not_interchangeable() {
    // Both derivations take the same Fabric ID, one big-endian and one little-endian. If
    // this crate ever used one convention for both, a byte-reversed Fabric ID would give
    // the same answer — so asserting it does not is what pins the distinction.
    let reversed = FabricId(FABRIC.0.swap_bytes());
    assert_ne!(
        compressed_fabric_id(&root_key(), FABRIC).expect("a"),
        compressed_fabric_id(&root_key(), reversed).expect("b")
    );

    let ipk = SymmetricKey::new(hex!("9bc61cd9c62a2df6d64dfcaa9dc472d4"));
    let random = [0x42u8; 32];
    let node = NodeId(0xCD55_44AA_7B13_EF14);
    assert_ne!(
        destination_identifier(&ipk, &random, &root_key(), FABRIC, node).expect("a"),
        destination_identifier(&ipk, &random, &root_key(), reversed, node).expect("b")
    );
}

#[test]
fn the_compressed_id_ignores_the_public_keys_format_marker_and_the_destination_id_does_not() {
    // §4.3.2.2 derives from the key "without any format marker prefix byte"; §4.14.2.4.1
    // includes the point "as an uncompressed elliptic curve point as defined in section
    // 2.3.3 of SEC 1", marker and all. Changing only that byte must therefore leave one
    // derivation alone and change the other.
    let mut altered = ROOT_PUBLIC_KEY;
    altered[0] = 0x05; // not a legal marker, but this is a test of what is hashed
    let altered = PublicKey::from_bytes(altered);

    assert_eq!(
        compressed_fabric_id(&root_key(), FABRIC).expect("a"),
        compressed_fabric_id(&altered, FABRIC).expect("b"),
        "the compressed id must not depend on the marker"
    );

    let ipk = SymmetricKey::new(hex!("9bc61cd9c62a2df6d64dfcaa9dc472d4"));
    let random = [0x42u8; 32];
    let node = NodeId(0xCD55_44AA_7B13_EF14);
    assert_ne!(
        destination_identifier(&ipk, &random, &root_key(), FABRIC, node).expect("a"),
        destination_identifier(&ipk, &random, &altered, FABRIC, node).expect("b"),
        "the destination id must depend on it"
    );
}
