//! SPAKE2+, the password-authenticated key exchange PASE is built on (Core §3.10).
//!
//! A commissioner knows an eight-digit passcode printed on the device. SPAKE2+ turns that
//! into a strong shared key without ever putting the passcode on the wire, and without
//! letting an eavesdropper — or a man in the middle — learn anything they could test
//! offline. An attacker gets **one guess per exchange**, which is what makes a
//! twenty-seven-bit secret usable at all.
//!
//! The asymmetry matters and Matter fixes which side is which: "The SPAKE2+ verifier is
//! the Commissionee/Responder and the SPAKE2+ prover is the Commissioner/Initiator."
//! The device stores `(w0, L)` — from which the passcode cannot be recovered cheaply — and
//! never stores `w1`. So reading a device's flash does not give you the passcode, and
//! therefore does not let you impersonate the *commissioner* to another device.
//!
//! ```text
//! prover (commissioner)                      verifier (commissionee)
//!   w0, w1 = PBKDF(passcode, salt, iters)      w0, L = w1·P        (stored, no w1)
//!   x ← random                                 y ← random
//!   pA = x·P + w0·M            ── pA ──▶
//!                              ◀── pB ──       pB = y·P + w0·N
//!   Z = x·(pB − w0·N)                          Z = y·(pA − w0·M)
//!   V = w1·(pB − w0·N)                         V = y·L
//!                    both derive Ka‖Ke = Hash(TT)
//!   cA = HMAC(KcA, pB)         ── cA ──▶       (checked)
//!                              ◀── cB ──       cB = HMAC(KcB, pA)
//! ```
//!
//! # A place where the specification and the SDK disagree
//!
//! §3.10 writes the confirmation-key derivation as `KDF(nil, Ka, "ConfirmationKeys")` and
//! separately defines `KDF(info, key, salt)`. Read positionally, that makes
//! `"ConfirmationKeys"` the **salt**. The SPAKE2+ draft the section cites defines its KDF
//! as `KDF(salt, ikm, info)`, which makes it the **info** — and that is what the CHIP SDK
//! computes, so it is what every deployed device computes.
//!
//! This crate follows the SDK: `HKDF(ikm = Ka, salt = [], info = "ConfirmationKeys")`.
//! Following the other reading would produce a stack that is self-consistent and cannot
//! commission anything.

// Group arithmetic is *modular and total*: `Scalar` addition and multiplication are taken
// modulo the group order, and point addition is closed over the curve. There is no
// overflow for `arithmetic_side_effects` to warn about, and the types have no `checked_*`
// variants to rewrite into — a scalar has no "too large" value. The denial stays in force
// for every module that does arithmetic on values off the wire.
#![allow(clippy::arithmetic_side_effects)]

use elliptic_curve::ops::Reduce;
use elliptic_curve::sec1::ToSec1Point as _;
use p256::{ProjectivePoint, Scalar, U256};

use super::rustcrypto::{hmac, kdf};
use super::{
    GROUP_SIZE_BYTES, HASH_LEN_BYTES, PUBLIC_KEY_SIZE_BYTES, SYMMETRIC_KEY_LENGTH_BYTES, Secret,
    W_SIZE_BYTES,
};
use crate::error::{Error, ErrorCode, Result};

/// `M`, in compressed SEC 1 form — "taken from the draft version 2 of the SPAKE2+
/// specification" (§3.10).
const M_COMPRESSED: [u8; 33] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];

/// `N`, in compressed SEC 1 form (§3.10).
const N_COMPRESSED: [u8; 33] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];

/// "CHIP PAKE V1 Commissioning" — §3.10.3.
///
/// "The usage of CHIP here is intentional and due to implementation in the SDK before the
/// name change, should not be renamed to Matter."
const CONTEXT_PREFIX: &[u8; 26] = b"CHIP PAKE V1 Commissioning";

/// The `info` of the confirmation-key derivation. See the module note on why this is the
/// info and not the salt.
const CONFIRMATION_KEYS_INFO: &[u8] = b"ConfirmationKeys";

/// `Ke`, the shared secret SPAKE2+ produces — `CRYPTO_HASH_LEN_BYTES / 2` octets (§3.10.4).
pub type SharedSecret = Secret<{ HASH_LEN_BYTES / 2 }>;

/// A confirmation value, `cA` or `cB` (§3.10.4).
pub type Confirmation = [u8; HASH_LEN_BYTES];

/// What a commissionee stores instead of the passcode: `(w0, L)` (§3.10).
///
/// "When the computation of `Crypto_PAKEValues_Responder` is done, fields `w0` and `L`
/// SHALL be stored in the Responder and `w1` SHALL NOT be stored in the Responder."
///
/// This is what goes into a device's factory data. It is 87 octets and it is *not* secret
/// in the way a private key is — but it is not public either: anyone holding it can
/// impersonate the device to a commissioner, so it is protected like a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spake2pVerifierData {
    /// `w0` — a scalar, big-endian.
    pub w0: [u8; GROUP_SIZE_BYTES],
    /// `L = w1 · P` — an uncompressed point.
    pub l: [u8; PUBLIC_KEY_SIZE_BYTES],
}

impl Spake2pVerifierData {
    /// The size of the serialised form: `w0 || L`.
    pub const LEN: usize = GROUP_SIZE_BYTES + PUBLIC_KEY_SIZE_BYTES;

    /// Computes `(w0, L)` from a passcode, as a factory-provisioning step would.
    ///
    /// `passcode` is the §5.1.1.6 passcode; the PBKDF input is its **little-endian**
    /// 4-octet encoding — "passcode 18924017 would be encoded as the octet string
    /// f1:c1:20:01".
    pub fn from_passcode(passcode: u32, salt: &[u8], iterations: u32) -> Result<Self> {
        let (w0, w1) = w0_w1(passcode, salt, iterations)?;
        // L = w1 · P.
        let l_point = ProjectivePoint::GENERATOR * w1;
        Ok(Self {
            w0: w0.to_bytes().into(),
            l: encode_point(&l_point)?,
        })
    }

    /// Serialises as `w0 || L`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        // Both slices are of known length and `out` is exactly their sum.
        if let Some(slot) = out.get_mut(..GROUP_SIZE_BYTES) {
            slot.copy_from_slice(&self.w0);
        }
        if let Some(slot) = out.get_mut(GROUP_SIZE_BYTES..) {
            slot.copy_from_slice(&self.l);
        }
        out
    }

    /// Reads `w0 || L`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (Some(w0), Some(l)) = (
            bytes.get(..GROUP_SIZE_BYTES),
            bytes.get(GROUP_SIZE_BYTES..Self::LEN),
        ) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        let mut out = Self {
            w0: [0; GROUP_SIZE_BYTES],
            l: [0; PUBLIC_KEY_SIZE_BYTES],
        };
        out.w0.copy_from_slice(w0);
        out.l.copy_from_slice(l);
        Ok(out)
    }
}

/// `Crypto_PAKEValues_Initiator` — derives `(w0, w1)` from a passcode (§3.10).
fn w0_w1(passcode: u32, salt: &[u8], iterations: u32) -> Result<(Scalar, Scalar)> {
    let mut ws = [0u8; 2 * W_SIZE_BYTES];
    // "passcode … serialized as little-endian over 4 octets".
    super::rustcrypto::pbkdf(&passcode.to_le_bytes(), salt, iterations, &mut ws)?;

    let (Some(w0s), Some(w1s)) = (ws.get(..W_SIZE_BYTES), ws.get(W_SIZE_BYTES..)) else {
        return Err(Error::new(ErrorCode::Platform));
    };
    let result = (reduce_wide(w0s)?, reduce_wide(w1s)?);

    // The PBKDF output is passcode-equivalent material; it does not outlive this call.
    use zeroize::Zeroize as _;
    ws.zeroize();
    Ok(result)
}

/// Reduces a big-endian integer wider than a scalar, modulo the group order.
///
/// `w0s` and `w1s` are `CRYPTO_GROUP_SIZE_BYTES + 8` octets and the specification says
/// `w0 = w0s mod p`. Horner's method over the octets does it in constant time with only
/// scalar arithmetic — no wide-integer type, no branch on the value, and obviously correct
/// at the cost of forty multiplications that happen once per commissioning.
fn reduce_wide(bytes: &[u8]) -> Result<Scalar> {
    let radix = Scalar::from(256u64);
    let mut acc = Scalar::ZERO;
    for byte in bytes {
        acc = acc * radix + Scalar::from(u64::from(*byte));
    }
    Ok(acc)
    // `Scalar: From<u64>` reduces nothing — every `u64` is already a valid scalar — and
    // the multiply-add is modular, so the whole loop is a reduction by construction.
}

fn m_point() -> Result<ProjectivePoint> {
    decode_point(&M_COMPRESSED)
}

fn n_point() -> Result<ProjectivePoint> {
    decode_point(&N_COMPRESSED)
}

/// Decodes a SEC 1 point, compressed or uncompressed.
///
/// `p256::PublicKey::from_sec1_bytes` is the right tool and not merely a convenient one:
/// it rejects a point that is not on the curve *and* rejects the identity. The first check
/// is what stops an invalid-curve attack — a peer offering an "x" that lies on a different,
/// weaker curve and hoping the scalar multiplication proceeds anyway — and skipping it
/// would leak the scalar it is multiplied by.
fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    let Ok(key) = p256::PublicKey::from_sec1_bytes(bytes) else {
        return Err(Error::new(ErrorCode::InvalidArgument));
    };
    Ok(key.to_projective())
}

/// Encodes a point as an uncompressed SEC 1 octet string.
///
/// Fails for the identity, which has no uncompressed encoding. No point this crate
/// computes should be the identity, and one that is would otherwise become a one-octet
/// "encoding" that silently shortens a transcript.
fn encode_point(point: &ProjectivePoint) -> Result<[u8; PUBLIC_KEY_SIZE_BYTES]> {
    let Ok(key) = p256::PublicKey::from_affine(point.to_affine()) else {
        return Err(Error::new(ErrorCode::InvalidArgument));
    };
    let encoded = key.to_sec1_point(false);
    let Ok(arr) = <[u8; PUBLIC_KEY_SIZE_BYTES]>::try_from(encoded.as_bytes()) else {
        return Err(Error::new(ErrorCode::Platform));
    };
    Ok(arr)
}

/// Appends `lengthInBytes(x) || x` to the transcript, with the length as an 8-octet
/// little-endian integer — "the SPAKE2+ specification indicates that we must include these
/// length fields" (§3.10.3).
fn tt_append(hasher: &mut super::rustcrypto::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

/// The shared half of both roles: build TT, hash it, split out the keys and confirmations.
#[allow(clippy::too_many_arguments)]
fn finish(
    context: &[u8],
    prover_identity: &[u8],
    verifier_identity: &[u8],
    pa: &[u8; PUBLIC_KEY_SIZE_BYTES],
    pb: &[u8; PUBLIC_KEY_SIZE_BYTES],
    z: &ProjectivePoint,
    v: &ProjectivePoint,
    w0: &Scalar,
) -> Result<Outcome> {
    let mut tt = super::rustcrypto::Hasher::new();
    tt_append(&mut tt, context);
    // SPAKE2+ puts both identities here. Matter uses neither — "the two
    // 0x0000000000000000 null-lengths indicate that no identities are present" — and an
    // absent identity is still a length field, which is why they cannot simply be
    // omitted.
    tt_append(&mut tt, prover_identity);
    tt_append(&mut tt, verifier_identity);
    tt_append(&mut tt, &encode_point(&m_point()?)?);
    tt_append(&mut tt, &encode_point(&n_point()?)?);
    tt_append(&mut tt, pa);
    tt_append(&mut tt, pb);
    tt_append(&mut tt, &encode_point(z)?);
    tt_append(&mut tt, &encode_point(v)?);
    let w0_bytes: [u8; GROUP_SIZE_BYTES] = w0.to_bytes().into();
    tt_append(&mut tt, &w0_bytes);

    let digest = tt.finish();
    let (Some(ka), Some(ke)) = (
        digest.get(..SYMMETRIC_KEY_LENGTH_BYTES),
        digest.get(SYMMETRIC_KEY_LENGTH_BYTES..),
    ) else {
        return Err(Error::new(ErrorCode::Platform));
    };

    // KcA || KcB = HKDF(ikm = Ka, salt = [], info = "ConfirmationKeys").
    let mut kc = [0u8; 2 * SYMMETRIC_KEY_LENGTH_BYTES];
    kdf(ka, &[], CONFIRMATION_KEYS_INFO, &mut kc)?;
    let (Some(kca), Some(kcb)) = (
        kc.get(..SYMMETRIC_KEY_LENGTH_BYTES),
        kc.get(SYMMETRIC_KEY_LENGTH_BYTES..),
    ) else {
        return Err(Error::new(ErrorCode::Platform));
    };

    // "cA := CRYPTO_HMAC(KcA, pB) and cB := CRYPTO_HMAC(KcB, pA)".
    let ca = hmac(kca, pb)?;
    let cb = hmac(kcb, pa)?;

    let mut shared = SharedSecret::zeroed();
    shared.as_mut().copy_from_slice(ke);

    use zeroize::Zeroize as _;
    kc.zeroize();

    Ok(Outcome { ca, cb, shared })
}

/// What both roles end up with.
struct Outcome {
    ca: Confirmation,
    cb: Confirmation,
    shared: SharedSecret,
}

/// Computes the `Context` of §3.10.3.
///
/// "in case PBKDFParamRequest and PBKDFParamResponse messages are not exchanged, they
/// SHALL be replaced by empty strings" — which is what passing empty slices does.
#[must_use]
pub fn context(pbkdf_param_request: &[u8], pbkdf_param_response: &[u8]) -> [u8; HASH_LEN_BYTES] {
    let mut h = super::rustcrypto::Hasher::new();
    h.update(CONTEXT_PREFIX);
    h.update(pbkdf_param_request);
    h.update(pbkdf_param_response);
    h.finish()
}

/// The prover: a commissioner that knows the passcode (§3.10).
pub struct Spake2pProver {
    w0: Scalar,
    w1: Scalar,
    x: Scalar,
    pa: [u8; PUBLIC_KEY_SIZE_BYTES],
}

impl core::fmt::Debug for Spake2pProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Spake2pProver(<redacted>)")
    }
}

impl Spake2pProver {
    /// Starts an exchange from a passcode and the PBKDF parameters the device announced.
    ///
    /// `random` must be 32 octets of cryptographically secure randomness — the ephemeral
    /// scalar `x`. A predictable `x` hands the session key to anyone watching.
    pub fn new(
        passcode: u32,
        salt: &[u8],
        iterations: u32,
        random: &[u8; GROUP_SIZE_BYTES],
    ) -> Result<Self> {
        let (w0, w1) = w0_w1(passcode, salt, iterations)?;
        let x = scalar_from_random(random)?;
        // pA = x·P + w0·M
        let pa_point = ProjectivePoint::GENERATOR * x + m_point()? * w0;
        Ok(Self {
            w0,
            w1,
            x,
            pa: encode_point(&pa_point)?,
        })
    }

    /// Starts an exchange from `w0` and `w1` directly.
    ///
    /// [`Spake2pProver::new`] derives those from a passcode, which is what a commissioner
    /// reading a QR code does. This takes them ready-made — for a commissioner whose
    /// PBKDF ran somewhere else, and for checking this implementation against the
    /// published SPAKE2+ test vectors, which state `w0` and `w1` rather than a passcode.
    pub fn from_parts(
        w0: &[u8; GROUP_SIZE_BYTES],
        w1: &[u8; GROUP_SIZE_BYTES],
        x: &[u8; GROUP_SIZE_BYTES],
    ) -> Result<Self> {
        let w0 = scalar_from_bytes(w0)?;
        let w1 = scalar_from_bytes(w1)?;
        let x = scalar_from_random(x)?;
        let pa_point = ProjectivePoint::GENERATOR * x + m_point()? * w0;
        Ok(Self {
            w0,
            w1,
            x,
            pa: encode_point(&pa_point)?,
        })
    }

    /// `pA`, to send to the commissionee.
    #[must_use]
    pub const fn pa(&self) -> &[u8; PUBLIC_KEY_SIZE_BYTES] {
        &self.pa
    }

    /// Given the commissionee's `pB`, derives the keys and the confirmations.
    ///
    /// Returns `(cA to send, cB to expect, Ke)`. The caller must compare the peer's `cB`
    /// against the returned one with [`ct_eq`](super::ct_eq), and abandon the session if
    /// it differs: that comparison is the only thing standing between a correct passcode
    /// and a wrong one.
    pub fn finish(
        &self,
        pb: &[u8; PUBLIC_KEY_SIZE_BYTES],
        context: &[u8],
    ) -> Result<(Confirmation, Confirmation, SharedSecret)> {
        self.finish_with_identities(pb, context, &[], &[])
    }

    /// [`Spake2pProver::finish`] with explicit SPAKE2+ identities.
    ///
    /// Matter uses neither identity, so [`Spake2pProver::finish`] is what a Matter
    /// commissioner calls. This exists because SPAKE2+ itself has them, and because the
    /// specification's own published test vectors exercise all four combinations — being
    /// able to run those is the difference between "our two halves agree" and "our
    /// arithmetic is right".
    pub fn finish_with_identities(
        &self,
        pb: &[u8; PUBLIC_KEY_SIZE_BYTES],
        context: &[u8],
        prover_identity: &[u8],
        verifier_identity: &[u8],
    ) -> Result<(Confirmation, Confirmation, SharedSecret)> {
        // `decode_point` has already rejected an off-curve point and the identity.
        let pb_point = decode_point(pb)?;
        // Y − w0·N
        let y_minus = pb_point - n_point()? * self.w0;
        let z = y_minus * self.x;
        let v = y_minus * self.w1;
        let out = finish(
            context,
            prover_identity,
            verifier_identity,
            &self.pa,
            pb,
            &z,
            &v,
            &self.w0,
        )?;
        Ok((out.ca, out.cb, out.shared))
    }
}

/// The verifier: a commissionee that stores `(w0, L)` and never saw `w1` (§3.10).
pub struct Spake2pVerifier {
    w0: Scalar,
    l: ProjectivePoint,
    y: Scalar,
    pb: [u8; PUBLIC_KEY_SIZE_BYTES],
}

impl core::fmt::Debug for Spake2pVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Spake2pVerifier(<redacted>)")
    }
}

impl Spake2pVerifier {
    /// Starts an exchange from stored verifier data.
    ///
    /// `random` must be 32 octets of cryptographically secure randomness — the ephemeral
    /// scalar `y`.
    pub fn new(data: &Spake2pVerifierData, random: &[u8; GROUP_SIZE_BYTES]) -> Result<Self> {
        let w0 = scalar_from_bytes(&data.w0)?;
        let l = decode_point(&data.l)?;
        let y = scalar_from_random(random)?;
        // pB = y·P + w0·N
        let pb_point = ProjectivePoint::GENERATOR * y + n_point()? * w0;
        Ok(Self {
            w0,
            l,
            y,
            pb: encode_point(&pb_point)?,
        })
    }

    /// Starts an exchange from `w0` and `L` directly, with an explicit `y`.
    ///
    /// The counterpart of [`Spake2pProver::from_parts`], and what the published test
    /// vectors need.
    pub fn from_parts(
        w0: &[u8; GROUP_SIZE_BYTES],
        l: &[u8; PUBLIC_KEY_SIZE_BYTES],
        y: &[u8; GROUP_SIZE_BYTES],
    ) -> Result<Self> {
        Self::new(&Spake2pVerifierData { w0: *w0, l: *l }, y)
    }

    /// `pB`, to send to the commissioner.
    #[must_use]
    pub const fn pb(&self) -> &[u8; PUBLIC_KEY_SIZE_BYTES] {
        &self.pb
    }

    /// Given the commissioner's `pA`, derives the keys and the confirmations.
    ///
    /// Returns `(cA to expect, cB to send, Ke)`.
    pub fn finish(
        &self,
        pa: &[u8; PUBLIC_KEY_SIZE_BYTES],
        context: &[u8],
    ) -> Result<(Confirmation, Confirmation, SharedSecret)> {
        self.finish_with_identities(pa, context, &[], &[])
    }

    /// [`Spake2pVerifier::finish`] with explicit SPAKE2+ identities. See
    /// [`Spake2pProver::finish_with_identities`].
    pub fn finish_with_identities(
        &self,
        pa: &[u8; PUBLIC_KEY_SIZE_BYTES],
        context: &[u8],
        prover_identity: &[u8],
        verifier_identity: &[u8],
    ) -> Result<(Confirmation, Confirmation, SharedSecret)> {
        let pa_point = decode_point(pa)?;
        // Z = y·(X − w0·M), V = y·L
        let z = (pa_point - m_point()? * self.w0) * self.y;
        let v = self.l * self.y;
        let out = finish(
            context,
            prover_identity,
            verifier_identity,
            pa,
            &self.pb,
            &z,
            &v,
            &self.w0,
        )?;
        Ok((out.ca, out.cb, out.shared))
    }
}

/// Turns 32 random octets into a scalar, refusing zero.
///
/// A zero ephemeral scalar makes `pA = w0·M`, from which an attacker who guesses `w0`
/// learns everything. The probability of drawing zero from a good generator is negligible;
/// the probability of a *broken* generator producing it is not.
fn scalar_from_random(random: &[u8; GROUP_SIZE_BYTES]) -> Result<Scalar> {
    let s = <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(random));
    if s == Scalar::ZERO {
        return Err(Error::new(ErrorCode::InvalidArgument));
    }
    Ok(s)
}

fn scalar_from_bytes(bytes: &[u8; GROUP_SIZE_BYTES]) -> Result<Scalar> {
    Ok(<Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(
        bytes,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ct_eq;

    const SALT: &[u8] = b"SPAKE2P Key Salt";
    const ITERATIONS: u32 = 1_000;

    fn run(passcode_prover: u32, passcode_verifier: u32) -> Result<(bool, bool)> {
        let data = Spake2pVerifierData::from_passcode(passcode_verifier, SALT, ITERATIONS)?;
        let prover = Spake2pProver::new(passcode_prover, SALT, ITERATIONS, &[7u8; 32])?;
        let verifier = Spake2pVerifier::new(&data, &[9u8; 32])?;

        let ctx = context(b"request", b"response");
        let (p_ca, p_cb, p_ke) = prover.finish(verifier.pb(), &ctx)?;
        let (v_ca, v_cb, v_ke) = verifier.finish(prover.pa(), &ctx)?;

        // The verifier checks the prover's cA; the prover checks the verifier's cB.
        let confirmed = ct_eq(&p_ca, &v_ca) && ct_eq(&p_cb, &v_cb);
        Ok((confirmed, p_ke == v_ke))
    }

    #[test]
    fn the_right_passcode_agrees_on_a_key() {
        let (confirmed, same_key) = run(20_202_021, 20_202_021).expect("exchange");
        assert!(confirmed, "confirmations must match");
        assert!(same_key, "and both sides derive the same Ke");
    }

    #[test]
    fn the_wrong_passcode_agrees_on_nothing() {
        // The whole point: one guess per exchange, and a wrong guess tells you only that
        // it was wrong.
        let (confirmed, same_key) = run(20_202_021, 12_345_678).expect("exchange");
        assert!(!confirmed, "confirmations must not match");
        assert!(!same_key, "and the keys must differ");
    }

    #[test]
    fn the_context_binds_the_exchange() {
        // Two runs that differ only in the PBKDFParamRequest must not produce the same
        // key — that binding is what stops a transcript being replayed into another
        // exchange.
        let data = Spake2pVerifierData::from_passcode(20_202_021, SALT, ITERATIONS).expect("data");
        let prover = Spake2pProver::new(20_202_021, SALT, ITERATIONS, &[7u8; 32]).expect("prover");
        let verifier = Spake2pVerifier::new(&data, &[9u8; 32]).expect("verifier");

        let (_, _, a) = prover
            .finish(verifier.pb(), &context(b"request-1", b"response"))
            .expect("finish");
        let (_, _, b) = prover
            .finish(verifier.pb(), &context(b"request-2", b"response"))
            .expect("finish");
        assert_ne!(a, b);
    }

    #[test]
    fn different_ephemerals_give_different_keys() {
        let data = Spake2pVerifierData::from_passcode(20_202_021, SALT, ITERATIONS).expect("data");
        let ctx = context(b"", b"");

        let mut keys = heapless::Vec::<SharedSecret, 4>::new();
        for seed in [1u8, 2, 3] {
            let prover =
                Spake2pProver::new(20_202_021, SALT, ITERATIONS, &[seed; 32]).expect("prover");
            let verifier =
                Spake2pVerifier::new(&data, &[seed.wrapping_add(50); 32]).expect("verifier");
            let (_, _, ke) = verifier.finish(prover.pa(), &ctx).expect("finish");
            let _ = keys.push(ke);
        }
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
    }

    #[test]
    fn the_verifier_never_holds_w1() {
        // The structural reason reading a device's flash does not yield the passcode:
        // what is stored is w0 and L = w1·P, and recovering w1 from L is a discrete log.
        let data = Spake2pVerifierData::from_passcode(20_202_021, SALT, ITERATIONS).expect("data");
        assert_eq!(data.to_bytes().len(), Spake2pVerifierData::LEN);
        assert_eq!(data.l[0], 0x04, "L is an uncompressed point");

        let round = Spake2pVerifierData::from_bytes(&data.to_bytes()).expect("round trip");
        assert_eq!(round, data);
    }

    #[test]
    fn verifier_data_is_deterministic_for_a_passcode() {
        // A factory can compute it once and burn it in; a device can recompute it from the
        // passcode. Both must agree.
        let a = Spake2pVerifierData::from_passcode(20_202_021, SALT, ITERATIONS).expect("a");
        let b = Spake2pVerifierData::from_passcode(20_202_021, SALT, ITERATIONS).expect("b");
        assert_eq!(a, b);
        let c = Spake2pVerifierData::from_passcode(20_202_022, SALT, ITERATIONS).expect("c");
        assert_ne!(a, c);
    }

    #[test]
    fn the_salt_and_iterations_change_the_verifier() {
        let a = Spake2pVerifierData::from_passcode(20_202_021, SALT, 1_000).expect("a");
        let b = Spake2pVerifierData::from_passcode(20_202_021, SALT, 2_000).expect("b");
        let c =
            Spake2pVerifierData::from_passcode(20_202_021, b"another key salt", 1_000).expect("c");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn a_point_that_is_not_on_the_curve_is_refused() {
        // An invalid-curve attack starts here: a peer sends a "point" whose x is on a
        // different, weaker curve, and hopes the scalar multiplication proceeds anyway.
        let data = Spake2pVerifierData::from_passcode(20_202_021, SALT, ITERATIONS).expect("data");
        let verifier = Spake2pVerifier::new(&data, &[9u8; 32]).expect("verifier");
        let mut bad = *verifier.pb();
        bad[40] ^= 0xFF;
        assert!(verifier.finish(&bad, &context(b"", b"")).is_err());
    }

    #[test]
    fn a_zero_ephemeral_is_refused() {
        let data = Spake2pVerifierData::from_passcode(20_202_021, SALT, ITERATIONS).expect("data");
        assert!(
            Spake2pVerifier::new(&data, &[0u8; 32]).is_err(),
            "y = 0 makes pB = w0·N and leaks the exchange"
        );
        assert!(Spake2pProver::new(20_202_021, SALT, ITERATIONS, &[0u8; 32]).is_err());
    }

    #[test]
    fn the_passcode_is_encoded_little_endian() {
        // §3.10: "passcode 18924017 would be encoded as the octet string f1:c1:20:01".
        assert_eq!(18_924_017u32.to_le_bytes(), [0xf1, 0xc1, 0x20, 0x01]);
        assert_eq!(5u32.to_le_bytes(), [0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn m_and_n_are_on_the_curve() {
        // If either constant were mistyped the exchange would simply never agree, with no
        // other symptom, so check them directly.
        assert!(m_point().is_ok());
        assert!(n_point().is_ok());
        assert_ne!(
            encode_point(&m_point().expect("m")).expect("enc"),
            encode_point(&n_point().expect("n")).expect("enc")
        );
    }

    #[test]
    fn wide_reduction_is_horners_method() {
        // Small values reduce to themselves.
        assert_eq!(reduce_wide(&[0, 0, 1]).expect("r"), Scalar::from(1u64));
        assert_eq!(reduce_wide(&[1, 0]).expect("r"), Scalar::from(256u64));
        assert_eq!(reduce_wide(&[]).expect("r"), Scalar::ZERO);
    }
}
