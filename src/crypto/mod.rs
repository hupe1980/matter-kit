//! The cryptosuite (Core ch. 3), and where a node's private keys live.
//!
//! Matter has exactly one cryptosuite. The specification is explicit: "There is no
//! cryptosuite negotiation in this protocol: one version of the Message Format has one
//! cryptosuite as defined in this chapter." SHA-256, HMAC-SHA256, HKDF, PBKDF2,
//! AES-128-CCM with a 16-octet tag, AES-128-CTR, NIST P-256, SPAKE2+. Nothing here is a
//! choice a node makes.
//!
//! # Why these are functions and not a trait
//!
//! The obvious shape is `Platform::Crypto`, an associated type threaded through every
//! generic in the stack. It is the wrong shape, and this crate's own design notes had it
//! wrong before the code existed.
//!
//! What varies is not the *algorithms* — the specification fixes those — but the
//! *implementation*: software here, an AES peripheral there, a vendor library somewhere
//! else. That is a property of the **build**, not of the node, and a build-time choice is
//! what a Cargo feature is for. Making it a type parameter would put `C: Crypto` in the
//! signature of everything from the session table to the interaction model, to express a
//! choice nobody makes twice in one binary.
//!
//! So: the cryptosuite is [`mod@crate::crypto`], selected by feature. What *does* vary per
//! node is **where the private keys live**, and that is [`KeyStore`] — a trait, because a
//! node with a secure element and a node without one are genuinely different nodes.
//!
//! # Keys that stop existing
//!
//! [`SymmetricKey`] and [`Secret`] zeroise themselves when dropped, and compare in
//! constant time. A `[u8; 16]` does neither: it leaves copies in freed memory and its
//! `==` returns early on the first differing byte, which over enough tries tells an
//! attacker the key one byte at a time.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, ErrorCode, Result};

#[cfg(feature = "rustcrypto")]
mod rustcrypto;

#[cfg(feature = "rustcrypto")]
pub use rustcrypto::*;

#[cfg(feature = "rustcrypto")]
mod spake2p;

#[cfg(feature = "rustcrypto")]
pub use spake2p::{
    Confirmation, SharedSecret, Spake2pProver, Spake2pVerifier, Spake2pVerifierData, context,
};

/// The `Info` string of the Privacy Key derivation (Core §4.9.1).
pub const PRIVACY_KEY_INFO: &[u8] = b"PrivacyKey";

// --- Constants, exactly as Core ch. 3 names them --------------------------------------

/// `CRYPTO_HASH_LEN_BYTES` — SHA-256 produces 32 octets (§3.3).
pub const HASH_LEN_BYTES: usize = 32;

/// `CRYPTO_GROUP_SIZE_BYTES` — the P-256 scalar size (§3.5.1).
pub const GROUP_SIZE_BYTES: usize = 32;

/// `CRYPTO_PUBLIC_KEY_SIZE_BYTES` — `(2 * 32) + 1`, an uncompressed SEC 1 point (§3.5.1).
pub const PUBLIC_KEY_SIZE_BYTES: usize = (2 * GROUP_SIZE_BYTES) + 1;

/// `CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES` — AES-128 (§3.6).
pub const SYMMETRIC_KEY_LENGTH_BYTES: usize = 16;

/// `CRYPTO_AEAD_MIC_LENGTH_BYTES` — a full-length CCM tag (§3.6).
pub const AEAD_MIC_LENGTH_BYTES: usize = 16;

/// `CRYPTO_AEAD_NONCE_LENGTH_BYTES` (§3.6).
pub const AEAD_NONCE_LENGTH_BYTES: usize = 13;

/// `CRYPTO_PRIVACY_NONCE_LENGTH_BYTES` (§3.7).
pub const PRIVACY_NONCE_LENGTH_BYTES: usize = 13;

/// The signature size: `r` and `s`, each a group element (§3.5.3).
pub const SIGNATURE_LEN_BYTES: usize = 2 * GROUP_SIZE_BYTES;

/// `CRYPTO_W_SIZE_BYTES` — the PBKDF2 output half-width for SPAKE2+ (§3.10).
pub const W_SIZE_BYTES: usize = GROUP_SIZE_BYTES + 8;

/// `CRYPTO_PBKDF_ITERATIONS_MIN` (§3.9).
pub const PBKDF_ITERATIONS_MIN: u32 = 1_000;

/// `CRYPTO_PBKDF_ITERATIONS_MAX` (§3.9).
pub const PBKDF_ITERATIONS_MAX: u32 = 100_000;

/// The shortest PBKDF2 salt the specification allows (§3.9).
pub const PBKDF_SALT_MIN_BYTES: usize = 16;

/// The longest PBKDF2 salt the specification allows (§3.9).
pub const PBKDF_SALT_MAX_BYTES: usize = 32;

// --- Key material ---------------------------------------------------------------------

/// A 128-bit symmetric key.
///
/// Zeroised on drop, and compared in constant time. There is no `Debug` that prints it and
/// no `Deref` to the bytes: getting at the material is [`SymmetricKey::as_bytes`], which is
/// easy to grep for in a review.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; SYMMETRIC_KEY_LENGTH_BYTES]);

impl SymmetricKey {
    /// Wraps raw key material.
    #[must_use]
    pub const fn new(bytes: [u8; SYMMETRIC_KEY_LENGTH_BYTES]) -> Self {
        Self(bytes)
    }

    /// Takes the first [`SYMMETRIC_KEY_LENGTH_BYTES`] of `bytes`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let Some(head) = bytes.get(..SYMMETRIC_KEY_LENGTH_BYTES) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        let mut out = [0u8; SYMMETRIC_KEY_LENGTH_BYTES];
        out.copy_from_slice(head);
        Ok(Self(out))
    }

    /// The raw material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SYMMETRIC_KEY_LENGTH_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A key that prints itself is a key in a log file.
        f.write_str("SymmetricKey(<redacted>)")
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SymmetricKey {}

/// A secret of arbitrary length that zeroises on drop — a shared secret, a transcript
/// hash, an intermediate KDF output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Wraps raw material.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// An all-zero secret, to be filled in.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self([0u8; N])
    }

    /// The raw material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// The raw material, mutably — for a primitive that writes into it.
    pub const fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl<const N: usize> Eq for Secret<N> {}

/// A P-256 public key, as an uncompressed SEC 1 point (§3.5.1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE_BYTES]);

impl PublicKey {
    /// Wraps an uncompressed point. The bytes are *not* checked to be on the curve here;
    /// the primitive that uses them does that, and says so when they are not.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Reads an uncompressed point from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let Ok(arr) = <[u8; PUBLIC_KEY_SIZE_BYTES]>::try_from(bytes) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        Ok(Self(arr))
    }

    /// The uncompressed SEC 1 encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public keys are public; printing the first few octets is enough to tell two
        // apart in a log without filling it.
        let head = self.0.get(..4).unwrap_or(&[]);
        write!(f, "PublicKey({head:02x?}…)")
    }
}

/// An ECDSA signature: `r || s`, each a group element (§3.5.3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN_BYTES]);

impl Signature {
    /// Wraps `r || s`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Reads `r || s` from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let Ok(arr) = <[u8; SIGNATURE_LEN_BYTES]>::try_from(bytes) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        Ok(Self(arr))
    }

    /// The `r || s` encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN_BYTES] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(..)")
    }
}

// --- Where private keys live ------------------------------------------------------------

/// A handle to a private key that this crate never sees the bytes of.
///
/// Opaque and `Copy`: an index, a slot number, whatever the store uses. The point is that
/// nothing above [`KeyStore`] can do anything with it except pass it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub u32);

/// What a private key is for, so a store can apply different policy to each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyPurpose {
    /// The Device Attestation Certificate's key. Written at manufacture, never replaced,
    /// and the one most worth putting in hardware: it is what proves the device is genuine.
    DeviceAttestation,
    /// A Node Operational Certificate's key, one per fabric. Created during commissioning,
    /// destroyed when the fabric is removed.
    Operational,
    /// An ephemeral key for one session establishment, discarded when it completes.
    Ephemeral,
}

/// Custody of private keys.
///
/// Every operation that needs a private key goes through here, and none of them returns
/// one. A node whose keys are in an ATECC608, an nRF KMU, an ESP32 HMAC peripheral or a
/// TPM implements this over that; a node without one gets
/// [`SoftKeyStore`], which keeps them in zeroising memory.
///
/// This is a trait — unlike the cryptosuite — because *where the keys live* really does
/// differ between two nodes running the same binary.
pub trait KeyStore {
    /// Generates a key pair from 32 octets of randomness, returning its handle and
    /// public key.
    ///
    /// The randomness is a parameter rather than something this crate fetches, for the
    /// same reason every other source of entropy is: it comes from the one
    /// [`Rng`](crate::platform::Rng) the integrator installed, so a platform with a
    /// hardware generator uses it everywhere and a test can be deterministic.
    ///
    /// Returns [`ErrorCode::InvalidArgument`] if the value is not a valid private key —
    /// zero, or at or above the group order. A caller should draw again.
    fn generate(
        &mut self,
        purpose: KeyPurpose,
        random: &[u8; GROUP_SIZE_BYTES],
    ) -> Result<(KeyHandle, PublicKey)>;

    /// Imports an existing private key. A store backed by hardware may refuse.
    fn import(&mut self, purpose: KeyPurpose, secret: &[u8; GROUP_SIZE_BYTES])
    -> Result<KeyHandle>;

    /// The public key for a handle.
    fn public_key(&self, handle: KeyHandle) -> Result<PublicKey>;

    /// Signs `message` — ECDSA over SHA-256 (§3.5.3.1).
    fn sign(&self, handle: KeyHandle, message: &[u8]) -> Result<Signature>;

    /// Computes the ECDH shared secret with `peer` (§3.5.4).
    ///
    /// "The output of ECDH() SHALL be the serialization of the x-coordinate of the
    /// resultant point."
    fn ecdh(&self, handle: KeyHandle, peer: &PublicKey) -> Result<Secret<GROUP_SIZE_BYTES>>;

    /// Destroys a key. Removing a fabric destroys its operational key, and that has to
    /// actually happen rather than merely be forgotten about.
    fn remove(&mut self, handle: KeyHandle) -> Result<()>;
}

/// Verifies an ECDSA signature (§3.5.3.2).
///
/// Free rather than a [`KeyStore`] method: verification needs only a public key, so there
/// is nothing for a key store to have custody of.
pub fn verify(public: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
    #[cfg(feature = "rustcrypto")]
    {
        rustcrypto::verify_impl(public, message, signature)
    }
    #[cfg(not(feature = "rustcrypto"))]
    {
        let _ = (public, message, signature);
        Err(Error::new(ErrorCode::Platform))
    }
}

/// Constant-time equality for anything secret.
///
/// A `==` on two byte slices returns as soon as it finds a difference, so how long it took
/// says how many leading octets matched. Over enough attempts that recovers a MIC or a
/// confirmation value one octet at a time.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // The lengths are public — they are on the wire in the clear — so branching on
        // them leaks nothing.
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_chapter_3() {
        assert_eq!(HASH_LEN_BYTES, 32);
        assert_eq!(GROUP_SIZE_BYTES, 32);
        assert_eq!(PUBLIC_KEY_SIZE_BYTES, 65);
        assert_eq!(SYMMETRIC_KEY_LENGTH_BYTES, 16);
        assert_eq!(AEAD_MIC_LENGTH_BYTES, 16);
        assert_eq!(AEAD_NONCE_LENGTH_BYTES, 13);
        assert_eq!(W_SIZE_BYTES, 40, "CRYPTO_GROUP_SIZE_BYTES + 8");
    }

    #[cfg(feature = "std")]
    #[test]
    fn a_key_does_not_print_itself() {
        // A key that prints itself is a key in a log file. Needs `std` only because
        // formatting to a `String` does.
        let k = SymmetricKey::new([0xAB; 16]);
        let shown = std::format!("{k:?}");
        assert!(shown.contains("redacted"), "{shown}");
        assert!(!shown.contains("ab"), "{shown}");
    }

    #[test]
    fn keys_compare_by_value() {
        assert_eq!(SymmetricKey::new([1; 16]), SymmetricKey::new([1; 16]));
        assert_ne!(SymmetricKey::new([1; 16]), SymmetricKey::new([2; 16]));
    }

    #[test]
    fn ct_eq_agrees_with_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"), "different lengths are not equal");
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn a_symmetric_key_from_a_short_slice_is_refused() {
        assert!(SymmetricKey::from_slice(&[0u8; 15]).is_err());
        assert!(SymmetricKey::from_slice(&[0u8; 16]).is_ok());
        // A longer slice takes the first 16, which is what a KDF output is.
        assert!(SymmetricKey::from_slice(&[0u8; 32]).is_ok());
    }
}
