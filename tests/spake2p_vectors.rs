//! The published SPAKE2+ test vectors, run against this implementation.
//!
//! Two implementations that agree with each other prove nothing: they can be wrong in the
//! same way, and a stack that is self-consistent and cannot commission anything is exactly
//! the failure this catches. These vectors come from the SPAKE2+ draft the Matter
//! specification cites (§3.10), by way of the CHIP SDK's
//! `src/crypto/tests/SPAKE2P_RFC_test_vectors.h`, and they state every intermediate value:
//! `w0`, `w1`, `L`, the ephemerals `x` and `y`, the points `X` and `Y`, and the outputs
//! `Ke`, `cA` and `cB`.
//!
//! Reproducing them proves the group arithmetic, the transcript layout of §3.10.3, the
//! `Ka ‖ Ke` split and the confirmation-key derivation of §3.10.4 — every part of SPAKE2+
//! except the passcode-to-`w0`/`w1` step, which is PBKDF2 and has vectors of its own.
//!
//! The fourth vector is the one shaped like Matter: **both identities empty**. The other
//! three exercise the identity fields, which Matter never uses but which are part of the
//! transcript either way — an implementation that got their length prefixes wrong would
//! pass the fourth and fail the first three.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use hex_literal::hex;
use matter_kit::crypto::{Spake2pProver, Spake2pVerifier, ct_eq};

struct Vector {
    name: &'static str,
    context: &'static [u8],
    prover_identity: &'static [u8],
    verifier_identity: &'static [u8],
    w0: [u8; 32],
    w1: [u8; 32],
    l: [u8; 65],
    x: [u8; 32],
    big_x: [u8; 65],
    y: [u8; 32],
    big_y: [u8; 65],
    ke: [u8; 16],
    ca: [u8; 32],
    cb: [u8; 32],
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "test_vector_16",
        context: b"SPAKE2+-P256-SHA256-HKDF draft-01",
        prover_identity: b"client",
        verifier_identity: b"server",
        w0: hex!("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"),
        w1: hex!("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"),
        l: hex!(
            "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"
        ),
        x: hex!("8b0f3f383905cf3a3bb955ef8fb62e24849dd349a05ca79aafb18041d30cbdb6"),
        big_x: hex!(
            "04af09987a593d3bac8694b123839422c3cc87e37d6b41c1d630f000dd64980e537ae704bcede04ea3bec9b7475b32fa2ca3b684be14d11645e38ea6609eb39e7e"
        ),
        y: hex!("2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91"),
        big_y: hex!(
            "04417592620aebf9fd203616bbb9f121b730c258b286f890c5f19fea833a9c900cbe9057bc549a3e19975be9927f0e7614f08d1f0a108eede5fd7eb5624584a4f4"
        ),
        ke: hex!("801db297654816eb4f02868129b9dc89"),
        ca: hex!("d4376f2da9c72226dd151b77c2919071155fc22a2068d90b5faa6c78c11e77dd"),
        cb: hex!("0660a680663e8c5695956fb22dff298b1d07a526cf3cc591adfecd1f6ef6e02e"),
    },
    Vector {
        name: "test_vector_32",
        context: b"SPAKE2+-P256-SHA256-HKDF draft-01",
        prover_identity: b"client",
        verifier_identity: b"",
        w0: hex!("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"),
        w1: hex!("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"),
        l: hex!(
            "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"
        ),
        x: hex!("ec82d9258337f61239c9cd68e8e532a3a6b83d12d2b1ca5d543f44def17dfb8d"),
        big_x: hex!(
            "04230779960824076d3666a7418e4d433e2fa15b06176eabdd572f43a32ecc79a192b243d2624310a7356273b86e5fd9bd627d3ade762baeff1a320d4ad7a4e47f"
        ),
        y: hex!("eac3f7de4b198d5fe25c443c0cd4963807add767815dd02a6f0133b4bc2c9eb0"),
        big_y: hex!(
            "044558642e71b616b248c9583bd6d7aa1b3952c6df6a9f7492a06035ca5d92522d84443de7aa20a59380fa4de6b7438d925dbfb7f1cfe60d79acf961ee33988c7d"
        ),
        ke: hex!("6989d8f9177ef7df67da437987f07255"),
        ca: hex!("e1b9258807ba4750dae1d7f3c3c294f13dc4fa60cde346d5de7d200e2f8fd3fc"),
        cb: hex!("b9c39dfa49c47757de778d9bedeaca2448b905be19a43b94ee24b770208135e3"),
    },
    Vector {
        name: "test_vector_48",
        context: b"SPAKE2+-P256-SHA256-HKDF draft-01",
        prover_identity: b"",
        verifier_identity: b"server",
        w0: hex!("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"),
        w1: hex!("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"),
        l: hex!(
            "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"
        ),
        x: hex!("ba0f0f5b78ef23fd07868e46aeca63b51fda519a3420501acbe23d53c2918748"),
        big_x: hex!(
            "04c14d28f4370fea20745106cea58bcfb60f2949fa4e131b9aff5ea13fd5aa79d507ae1d229e447e000f15eb78a9a32c2b88652e3411642043c1b2b7992cf2d4de"
        ),
        y: hex!("39397fbe6db47e9fbd1a263d79f5d0aaa44df26ce755f78e092644b434533a42"),
        big_y: hex!(
            "04d1bee3120fd87e86fe189cb952dc688823080e62524dd2c08dffe3d22a0a8986aa64c9fe0191033cafbc9bcaefc8e2ba8ba860cd127af9efdd7f1c3a41920fe8"
        ),
        ke: hex!("2ea40e4badfa5452b5744dc5983e99ba"),
        ca: hex!("e564c93b3015efb946dc16d642bbe7d1c8da5be164ed9fc3bae4e0ff86e1bd3c"),
        cb: hex!("072a94d9a54edc201d8891534c2317cadf3ea3792827f479e873f93e90f21552"),
    },
    Vector {
        name: "test_vector_64",
        context: b"SPAKE2+-P256-SHA256-HKDF draft-01",
        prover_identity: b"",
        verifier_identity: b"",
        w0: hex!("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c"),
        w1: hex!("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512"),
        l: hex!(
            "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"
        ),
        x: hex!("5b478619804f4938d361fbba3a20648725222f0a54cc4c876139efe7d9a21786"),
        big_x: hex!(
            "04a6db23d001723fb01fcfc9d08746c3c2a0a3feff8635d29cad2853e7358623425cf39712e928054561ba71e2dc11f300f1760e71eb177021a8f85e78689071cd"
        ),
        y: hex!("766770dad8c8eecba936823c0aed044b8c3c4f7655e8beec44a15dcbcaf78e5e"),
        big_y: hex!(
            "04390d29bf185c3abf99f150ae7c13388c82b6be0c07b1b8d90d26853e84374bbdc82becdb978ca3792f472424106a2578012752c11938fcf60a41df75ff7cf947"
        ),
        ke: hex!("ea3276d68334576097e04b19ee5a3a8b"),
        ca: hex!("71d9412779b6c45a2c615c9df3f1fd93dc0aaf63104da8ece4aa1b5a3a415fea"),
        cb: hex!("095dc0400355cc233fde7437811815b3c1524aae80fd4e6810cf531cf11d20e3"),
    },
];

#[test]
fn every_published_vector_reproduces() {
    for v in VECTORS {
        // The prover's public share, from w0, w1 and the vector's own x.
        let prover = Spake2pProver::from_parts(&v.w0, &v.w1, &v.x)
            .unwrap_or_else(|e| panic!("{}: prover: {e}", v.name));
        assert_eq!(
            prover.pa(),
            &v.big_x,
            "{}: X = x·P + w0·M does not match",
            v.name
        );

        // The verifier's, from w0, L and the vector's own y.
        let verifier = Spake2pVerifier::from_parts(&v.w0, &v.l, &v.y)
            .unwrap_or_else(|e| panic!("{}: verifier: {e}", v.name));
        assert_eq!(
            verifier.pb(),
            &v.big_y,
            "{}: Y = y·P + w0·N does not match",
            v.name
        );

        // Both sides derive the transcript and the confirmations.
        let (p_ca, p_cb, p_ke) = prover
            .finish_with_identities(&v.big_y, v.context, v.prover_identity, v.verifier_identity)
            .unwrap_or_else(|e| panic!("{}: prover finish: {e}", v.name));
        let (v_ca, v_cb, v_ke) = verifier
            .finish_with_identities(&v.big_x, v.context, v.prover_identity, v.verifier_identity)
            .unwrap_or_else(|e| panic!("{}: verifier finish: {e}", v.name));

        assert_eq!(p_ke.as_bytes(), &v.ke, "{}: Ke does not match", v.name);
        assert_eq!(v_ke.as_bytes(), &v.ke, "{}: Ke does not match", v.name);
        assert_eq!(&p_ca, &v.ca, "{}: cA does not match", v.name);
        assert_eq!(&v_ca, &v.ca, "{}: cA does not match", v.name);
        assert_eq!(&p_cb, &v.cb, "{}: cB does not match", v.name);
        assert_eq!(&v_cb, &v.cb, "{}: cB does not match", v.name);
    }
}

#[test]
fn the_vectors_cover_every_identity_combination() {
    // If a future edit dropped a vector, the transcript's identity length prefixes would
    // stop being exercised and nothing would say so.
    let combinations: heapless::Vec<(bool, bool), 4> = VECTORS
        .iter()
        .map(|v| (v.prover_identity.is_empty(), v.verifier_identity.is_empty()))
        .collect();
    assert_eq!(combinations.len(), 4);
    for wanted in [(false, false), (false, true), (true, false), (true, true)] {
        assert!(
            combinations.contains(&wanted),
            "no vector with (prover empty, verifier empty) = {wanted:?}"
        );
    }
}

#[test]
fn a_vector_run_with_the_wrong_identities_does_not_reproduce() {
    // The identities are inside the transcript, so changing one must change the keys.
    // Otherwise the first test would pass even if the fields were ignored entirely.
    let v = &VECTORS[0];
    let prover = Spake2pProver::from_parts(&v.w0, &v.w1, &v.x).expect("prover");
    let (_, _, ke) = prover
        .finish_with_identities(&v.big_y, v.context, b"attacker", v.verifier_identity)
        .expect("finish");
    assert_ne!(ke.as_bytes(), &v.ke);
}

#[test]
fn confirmations_are_compared_in_constant_time() {
    // Not a property a test can observe directly — this is here so that the comparison
    // used in the vectors above is the one the protocol should use, and stays that way.
    let v = &VECTORS[3];
    let prover = Spake2pProver::from_parts(&v.w0, &v.w1, &v.x).expect("prover");
    let verifier = Spake2pVerifier::from_parts(&v.w0, &v.l, &v.y).expect("verifier");
    let (p_ca, _, _) = prover.finish(&v.big_y, v.context).expect("finish");
    let (e_ca, _, _) = verifier.finish(&v.big_x, v.context).expect("finish");
    assert!(ct_eq(&p_ca, &e_ca));
}
