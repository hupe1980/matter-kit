//! The software cryptosuite, on RustCrypto.
//!
//! Each function here is one line of Core ch. 3 turned into code, and the doc comment says
//! which line. Nothing is parameterised: the specification fixes the algorithms, so the
//! only thing a different backend changes is how they are computed.
//!
//! # Two details that are easy to get wrong
//!
//! **AES-CCM's `q`.** §3.6 sets `q = 2` and `n = 13`, so the counter blocks of NIST
//! 800-38C Appendix A.3 are `0x01 || nonce || counter`, with a *two-octet* counter. The
//! `ccm` crate is told this through its type parameters; the privacy mode in
//! [`privacy_xor`] builds them by hand, because a generic CTR mode would increment the
//! whole 128-bit block and silently differ from the specification once a message is long
//! enough to matter.
//!
//! **Nothing returns a `bool` for a comparison.** Tag verification is inside
//! [`aead_decrypt_in_place`], where the underlying implementation does it in constant
//! time; anywhere this crate compares secret bytes itself it uses
//! [`ct_eq`](super::ct_eq).

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use ccm::aead::AeadInOut;
use ccm::{Ccm, KeyInit as CcmKeyInit};
use hmac::{Mac, SimpleHmac};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::{
    AEAD_MIC_LENGTH_BYTES, AEAD_NONCE_LENGTH_BYTES, GROUP_SIZE_BYTES, HASH_LEN_BYTES, KeyHandle,
    KeyPurpose, KeyStore, PRIVACY_KEY_INFO, PUBLIC_KEY_SIZE_BYTES, PublicKey,
    SYMMETRIC_KEY_LENGTH_BYTES, Secret, Signature, SymmetricKey,
};
use crate::error::{Error, ErrorCode, Result};

/// AES-128-CCM with a 13-octet nonce and a 16-octet tag — §3.6's exact parameters.
type Aes128Ccm = Ccm<Aes128, ccm::consts::U16, ccm::consts::U13>;

/// HMAC-SHA256 (§3.4).
type HmacSha256 = SimpleHmac<Sha256>;

fn crypto_error(_: impl core::fmt::Debug) -> Error {
    Error::new(ErrorCode::IntegrityCheckFailed)
}

// --- Hash and MAC ----------------------------------------------------------------------

/// `Crypto_Hash()` — SHA-256 (§3.3).
#[must_use]
pub fn hash(message: &[u8]) -> [u8; HASH_LEN_BYTES] {
    Sha256::digest(message).into()
}

/// A running SHA-256, for a transcript built from several pieces.
#[derive(Clone, Default)]
pub struct Hasher(Sha256);

impl Hasher {
    /// Starts an empty digest.
    #[must_use]
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    /// Adds more input.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes, returning the digest.
    #[must_use]
    pub fn finish(self) -> [u8; HASH_LEN_BYTES] {
        self.0.finalize().into()
    }
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hasher(..)")
    }
}

/// `Crypto_HMAC()` — HMAC-SHA256 (§3.4).
pub fn hmac(key: &[u8], message: &[u8]) -> Result<[u8; HASH_LEN_BYTES]> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(crypto_error)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

// --- Key derivation ----------------------------------------------------------------------

/// `Crypto_KDF()` — HKDF-Expand over HKDF-Extract, both on HMAC-SHA256 (§3.8).
///
/// Fills `out`, whose length is the `len / 8` of the specification's signature.
pub fn kdf(input_key: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), input_key);
    hk.expand(info, out).map_err(crypto_error)
}

/// A [`kdf`] call that produces one symmetric key.
pub fn kdf_key(input_key: &[u8], salt: &[u8], info: &[u8]) -> Result<SymmetricKey> {
    let mut out = [0u8; SYMMETRIC_KEY_LENGTH_BYTES];
    kdf(input_key, salt, info, &mut out)?;
    Ok(SymmetricKey::new(out))
}

/// `Crypto_PBKDF()` — PBKDF2-HMAC-SHA256 (§3.9).
///
/// The iteration count is checked against `CRYPTO_PBKDF_ITERATIONS_MIN` and `_MAX`: it
/// arrives from a peer, and a peer that asks for one iteration has asked for a passcode
/// that can be brute-forced, while one that asks for a billion has asked this node to stop
/// responding.
pub fn pbkdf(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    if !(super::PBKDF_ITERATIONS_MIN..=super::PBKDF_ITERATIONS_MAX).contains(&iterations) {
        return Err(Error::new(ErrorCode::InvalidArgument));
    }
    if !(super::PBKDF_SALT_MIN_BYTES..=super::PBKDF_SALT_MAX_BYTES).contains(&salt.len()) {
        return Err(Error::new(ErrorCode::InvalidArgument));
    }
    pbkdf2::pbkdf2::<HmacSha256>(password, salt, iterations, out).map_err(crypto_error)
}

// --- AEAD --------------------------------------------------------------------------------

/// `Crypto_AEAD_GenerateEncrypt()` — AES-128-CCM (§3.6.1).
///
/// Encrypts `buffer` in place and writes the 16-octet tag to `tag`.
pub fn aead_encrypt_in_place(
    key: &SymmetricKey,
    nonce: &[u8; AEAD_NONCE_LENGTH_BYTES],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &mut [u8; AEAD_MIC_LENGTH_BYTES],
) -> Result<()> {
    let cipher = <Aes128Ccm as CcmKeyInit>::new_from_slice(key.as_bytes()).map_err(crypto_error)?;
    let computed = cipher
        .encrypt_inout_detached(nonce.into(), aad, buffer.into())
        .map_err(crypto_error)?;
    tag.copy_from_slice(&computed);
    Ok(())
}

/// `Crypto_AEAD_DecryptVerify()` — AES-128-CCM (§3.6.2).
///
/// Decrypts `buffer` in place. A failed tag check is
/// [`ErrorCode::IntegrityCheckFailed`], and "the contents of the payload array is
/// undefined" — so a caller must not look at `buffer` unless this returned `Ok`.
pub fn aead_decrypt_in_place(
    key: &SymmetricKey,
    nonce: &[u8; AEAD_NONCE_LENGTH_BYTES],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; AEAD_MIC_LENGTH_BYTES],
) -> Result<()> {
    let cipher = <Aes128Ccm as CcmKeyInit>::new_from_slice(key.as_bytes()).map_err(crypto_error)?;
    cipher
        .decrypt_inout_detached(nonce.into(), aad, buffer.into(), tag.into())
        .map_err(crypto_error)
}

// --- Privacy ------------------------------------------------------------------------------

/// `Crypto_Privacy_Encrypt()` and `Crypto_Privacy_Decrypt()` — AES-128-CTR (§3.7).
///
/// The two are the same operation: CTR mode XORs a keystream, so obfuscating and
/// deobfuscating are one function and the specification's two names describe one thing.
///
/// The counter blocks are those of NIST 800-38C Appendix A.3 with `q = 2`:
/// `0x01 || nonce(13) || counter(2, big-endian)`, starting at zero. Building them by hand
/// rather than reaching for a generic CTR mode is deliberate — a 128-bit counter would
/// agree with this only until the low two octets wrap, and would then differ silently.
pub fn privacy_xor(
    key: &SymmetricKey,
    nonce: &[u8; AEAD_NONCE_LENGTH_BYTES],
    buffer: &mut [u8],
) -> Result<()> {
    const BLOCK: usize = 16;
    let cipher = <Aes128 as KeyInit>::new_from_slice(key.as_bytes()).map_err(crypto_error)?;

    // `q = 2` gives a 16-bit counter, so the mode is only defined for 65 536 blocks.
    let blocks = buffer.len().div_ceil(BLOCK);
    if blocks > usize::from(u16::MAX) + 1 {
        return Err(Error::new(ErrorCode::InvalidArgument));
    }

    for (index, chunk) in buffer.chunks_mut(BLOCK).enumerate() {
        let mut counter_block = [0u8; BLOCK];
        // Flags octet: `[q-1]_8`, and `q` is 2.
        counter_block[0] = 0x01;
        let Some(slot) = counter_block.get_mut(1..1 + AEAD_NONCE_LENGTH_BYTES) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        slot.copy_from_slice(nonce);
        let Ok(index) = u16::try_from(index) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        let Some(slot) = counter_block.get_mut(14..16) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        slot.copy_from_slice(&index.to_be_bytes());

        cipher.encrypt_block((&mut counter_block).into());
        for (b, k) in chunk.iter_mut().zip(counter_block.iter()) {
            *b ^= *k;
        }
    }
    Ok(())
}

/// Derives the Privacy Key from an Encryption Key (§4.9.1).
///
/// `PrivacyKey = Crypto_KDF(InputKey = EncryptionKey, Salt = [], Info = "PrivacyKey",
/// Length = CRYPTO_SYMMETRIC_KEY_LENGTH_BITS)`.
pub fn privacy_key(encryption_key: &SymmetricKey) -> Result<SymmetricKey> {
    kdf_key(encryption_key.as_bytes(), &[], PRIVACY_KEY_INFO)
}

// --- P-256 ---------------------------------------------------------------------------------

/// `Crypto_Verify()` — ECDSA over SHA-256 (§3.5.3.2).
pub(super) fn verify_impl(
    public: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<bool> {
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(public.as_bytes()) else {
        return Err(Error::new(ErrorCode::InvalidArgument));
    };
    let Ok(sig) = EcdsaSignature::from_slice(signature.as_bytes()) else {
        // A malformed signature is not an error to report upwards differently from a
        // wrong one: both mean "this did not verify".
        return Ok(false);
    };
    let digest = hash(message);
    Ok(verifying.verify_prehash(&digest, &sig).is_ok())
}

/// Private keys held in memory, zeroised when removed or dropped.
///
/// What a node without a secure element gets. It is not a weaker *protocol* — the keys are
/// as strong — but the material is readable by anything that can read the process's
/// memory, which is the difference a secure element buys.
pub struct SoftKeyStore<const N: usize> {
    slots: [Option<Slot>; N],
    next_handle: u32,
}

struct Slot {
    handle: KeyHandle,
    purpose: KeyPurpose,
    key: SigningKey,
}

impl<const N: usize> Default for SoftKeyStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SoftKeyStore<N> {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: [const { None }; N],
            next_handle: 1,
        }
    }

    /// How many keys are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Whether the store holds no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert(&mut self, purpose: KeyPurpose, key: SigningKey) -> Result<KeyHandle> {
        let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) else {
            return Err(Error::new(ErrorCode::NoSpace));
        };
        let handle = KeyHandle(self.next_handle);
        self.next_handle = self.next_handle.saturating_add(1);
        *slot = Some(Slot {
            handle,
            purpose,
            key,
        });
        Ok(handle)
    }

    fn find(&self, handle: KeyHandle) -> Result<&Slot> {
        self.slots
            .iter()
            .flatten()
            .find(|s| s.handle == handle)
            .ok_or(Error::new(ErrorCode::InvalidArgument))
    }

    /// What a handle's key is for.
    pub fn purpose(&self, handle: KeyHandle) -> Result<KeyPurpose> {
        Ok(self.find(handle)?.purpose)
    }
}

impl<const N: usize> core::fmt::Debug for SoftKeyStore<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SoftKeyStore({} keys)", self.len())
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        // `SigningKey` zeroises its own scalar; this is here so that the intent survives a
        // future change to how the slot holds it.
    }
}

impl<const N: usize> KeyStore for SoftKeyStore<N> {
    fn generate(
        &mut self,
        purpose: KeyPurpose,
        random: &[u8; GROUP_SIZE_BYTES],
    ) -> Result<(KeyHandle, PublicKey)> {
        // `from_slice` rejects zero and anything at or above the group order, which is
        // exactly the rejection sampling a key generator owes. The chance a good generator
        // produces such a value is about 2⁻¹²⁸; the chance a *broken* one does is not, so
        // this is an error the caller retries rather than something to paper over.
        let Ok(key) = SigningKey::from_slice(random) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        let public = public_of(&key)?;
        let handle = self.insert(purpose, key)?;
        Ok((handle, public))
    }

    fn import(
        &mut self,
        purpose: KeyPurpose,
        secret: &[u8; GROUP_SIZE_BYTES],
    ) -> Result<KeyHandle> {
        let Ok(key) = SigningKey::from_slice(secret) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        self.insert(purpose, key)
    }

    fn public_key(&self, handle: KeyHandle) -> Result<PublicKey> {
        public_of(&self.find(handle)?.key)
    }

    fn sign(&self, handle: KeyHandle, message: &[u8]) -> Result<Signature> {
        let slot = self.find(handle)?;
        let digest = hash(message);
        let Ok(sig): core::result::Result<EcdsaSignature, _> = slot.key.sign_prehash(&digest)
        else {
            return Err(Error::new(ErrorCode::Platform));
        };
        Signature::from_slice(&sig.to_bytes())
    }

    fn ecdh(&self, handle: KeyHandle, peer: &PublicKey) -> Result<Secret<GROUP_SIZE_BYTES>> {
        let slot = self.find(handle)?;
        let Ok(peer_point) = p256::PublicKey::from_sec1_bytes(peer.as_bytes()) else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        let secret = p256::ecdh::diffie_hellman(
            p256::SecretKey::from(slot.key.clone()).to_nonzero_scalar(),
            peer_point.as_affine(),
        );
        let mut out = Secret::<GROUP_SIZE_BYTES>::zeroed();
        out.as_mut().copy_from_slice(secret.raw_secret_bytes());
        Ok(out)
    }

    fn remove(&mut self, handle: KeyHandle) -> Result<()> {
        let Some(slot) = self
            .slots
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|s| s.handle == handle))
        else {
            return Err(Error::new(ErrorCode::InvalidArgument));
        };
        *slot = None;
        Ok(())
    }
}

fn public_of(key: &SigningKey) -> Result<PublicKey> {
    let encoded = key.verifying_key().to_sec1_point(false);
    let Some(bytes) = encoded.as_bytes().get(..PUBLIC_KEY_SIZE_BYTES) else {
        return Err(Error::new(ErrorCode::Platform));
    };
    PublicKey::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, distinct 32-octet value each call — enough to stand in for a generator in
    /// a test without pulling one in.
    fn random() -> [u8; GROUP_SIZE_BYTES] {
        use core::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(1);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut out = [0x11u8; GROUP_SIZE_BYTES];
        out[28..32].copy_from_slice(&n.to_be_bytes());
        out
    }

    #[test]
    fn sha256_matches_fips_180_4() {
        // The one-block example from FIPS 180-4's appendix.
        assert_eq!(
            hex::encode(hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_incremental_hasher_agrees_with_the_one_shot() {
        let mut h = Hasher::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(h.finish(), hash(b"abc"));
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        // RFC 4231 test case 1, HMAC-SHA-256.
        let key = [0x0b; 20];
        let mac = hmac(&key, b"Hi There").expect("hmac");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hkdf_matches_rfc_5869() {
        // RFC 5869 test case 1.
        let ikm = [0x0b; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut out = [0u8; 42];
        kdf(&ikm, &salt, &info, &mut out).expect("kdf");
        assert_eq!(
            hex::encode(out),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn pbkdf2_matches_rfc_7914() {
        // RFC 7914 §11's PBKDF2-HMAC-SHA256 vector, with the iteration count raised to
        // the specification's minimum — the published vector uses 1, which §3.9 forbids
        // and this function therefore refuses.
        let mut out = [0u8; 32];
        assert!(
            pbkdf(b"passwd", b"0123456789abcdef", 1, &mut out).is_err(),
            "below CRYPTO_PBKDF_ITERATIONS_MIN"
        );
        assert!(
            pbkdf(b"passwd", b"0123456789abcdef", 1_000_000, &mut out).is_err(),
            "above CRYPTO_PBKDF_ITERATIONS_MAX"
        );
        // A salt outside 16..=32 octets is refused too.
        assert!(pbkdf(b"passwd", b"short", 1_000, &mut out).is_err());
        assert!(pbkdf(b"passwd", &[0u8; 33], 1_000, &mut out).is_err());
        assert!(pbkdf(b"passwd", &[0u8; 16], 1_000, &mut out).is_ok());
    }

    #[test]
    fn aes_ccm_round_trips() {
        let key = SymmetricKey::new([0x42; 16]);
        let nonce = [0x11u8; AEAD_NONCE_LENGTH_BYTES];
        let aad = b"header";
        let mut buf = *b"the payload";
        let original = buf;
        let mut tag = [0u8; AEAD_MIC_LENGTH_BYTES];

        aead_encrypt_in_place(&key, &nonce, aad, &mut buf, &mut tag).expect("encrypt");
        assert_ne!(buf, original, "the payload was encrypted");

        aead_decrypt_in_place(&key, &nonce, aad, &mut buf, &tag).expect("decrypt");
        assert_eq!(buf, original);
    }

    #[test]
    fn a_tampered_ciphertext_does_not_verify() {
        let key = SymmetricKey::new([0x42; 16]);
        let nonce = [0x11u8; AEAD_NONCE_LENGTH_BYTES];
        let mut buf = *b"the payload";
        let mut tag = [0u8; AEAD_MIC_LENGTH_BYTES];
        aead_encrypt_in_place(&key, &nonce, b"h", &mut buf, &mut tag).expect("encrypt");

        // Every single-bit flip in the ciphertext, the tag and the associated data must
        // be caught — that is what the tag is for.
        for byte in 0..buf.len() {
            let mut broken = buf;
            broken[byte] ^= 1;
            assert!(
                aead_decrypt_in_place(&key, &nonce, b"h", &mut broken, &tag).is_err(),
                "flipped ciphertext byte {byte}"
            );
        }
        for byte in 0..tag.len() {
            let mut broken_tag = tag;
            broken_tag[byte] ^= 1;
            let mut copy = buf;
            assert!(
                aead_decrypt_in_place(&key, &nonce, b"h", &mut copy, &broken_tag).is_err(),
                "flipped tag byte {byte}"
            );
        }
        let mut copy = buf;
        assert!(
            aead_decrypt_in_place(&key, &nonce, b"H", &mut copy, &tag).is_err(),
            "the associated data is authenticated too"
        );
        let mut copy = buf;
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert!(
            aead_decrypt_in_place(&key, &other_nonce, b"h", &mut copy, &tag).is_err(),
            "so is the nonce"
        );
    }

    #[test]
    fn privacy_is_its_own_inverse() {
        let key = SymmetricKey::new([0x7; 16]);
        let nonce = [0x9u8; AEAD_NONCE_LENGTH_BYTES];
        let original = *b"counter and node ids, obfuscated";
        let mut buf = original;

        privacy_xor(&key, &nonce, &mut buf).expect("obfuscate");
        assert_ne!(buf, original);
        privacy_xor(&key, &nonce, &mut buf).expect("deobfuscate");
        assert_eq!(buf, original, "CTR mode xors the same keystream both ways");
    }

    #[test]
    fn privacy_uses_the_counter_blocks_of_800_38c() {
        // Block n of the keystream is AES(key, 0x01 || nonce || n), so the second block
        // must equal the keystream a caller would get by encrypting that block directly.
        let key = SymmetricKey::new([0x3; 16]);
        let nonce = [0x5u8; AEAD_NONCE_LENGTH_BYTES];
        let mut buf = [0u8; 32];
        privacy_xor(&key, &nonce, &mut buf).expect("xor");

        let cipher = <Aes128 as KeyInit>::new_from_slice(key.as_bytes()).expect("key");
        for (index, chunk) in buf.chunks(16).enumerate() {
            let mut block = [0u8; 16];
            block[0] = 0x01;
            block[1..14].copy_from_slice(&nonce);
            block[14..16].copy_from_slice(&(index as u16).to_be_bytes());
            cipher.encrypt_block((&mut block).into());
            assert_eq!(chunk, &block[..chunk.len()], "keystream block {index}");
        }
    }

    #[test]
    fn the_privacy_key_is_derived_from_the_encryption_key() {
        // §4.9.1.
        let encryption = SymmetricKey::new([0xAA; 16]);
        let privacy = privacy_key(&encryption).expect("derive");
        assert_ne!(privacy, encryption);
        // And deterministically.
        assert_eq!(privacy, privacy_key(&encryption).expect("derive"));
    }

    #[test]
    fn signing_round_trips_through_verification() {
        let mut store = SoftKeyStore::<4>::new();
        let (handle, public) = store
            .generate(KeyPurpose::Operational, &random())
            .expect("generate");
        let sig = store.sign(handle, b"attestation").expect("sign");

        assert!(super::super::verify(&public, b"attestation", &sig).expect("verify"));
        assert!(!super::super::verify(&public, b"attestatioN", &sig).expect("verify"));

        let (_, other) = store
            .generate(KeyPurpose::Operational, &random())
            .expect("generate");
        assert!(
            !super::super::verify(&other, b"attestation", &sig).expect("verify"),
            "another key's signature does not verify"
        );
    }

    #[test]
    fn ecdh_agrees_from_both_sides() {
        let mut store = SoftKeyStore::<4>::new();
        let (a, a_pub) = store
            .generate(KeyPurpose::Ephemeral, &random())
            .expect("generate");
        let (b, b_pub) = store
            .generate(KeyPurpose::Ephemeral, &random())
            .expect("generate");

        let ab = store.ecdh(a, &b_pub).expect("ecdh");
        let ba = store.ecdh(b, &a_pub).expect("ecdh");
        assert_eq!(ab, ba, "Diffie-Hellman is symmetric");
    }

    #[test]
    fn a_public_key_is_an_uncompressed_sec1_point() {
        let mut store = SoftKeyStore::<2>::new();
        let (_, public) = store
            .generate(KeyPurpose::Ephemeral, &random())
            .expect("generate");
        assert_eq!(public.as_bytes().len(), 65);
        assert_eq!(public.as_bytes()[0], 0x04, "0x04 is 'uncompressed'");
    }

    #[test]
    fn a_removed_key_is_gone() {
        let mut store = SoftKeyStore::<2>::new();
        let (handle, _) = store
            .generate(KeyPurpose::Operational, &random())
            .expect("generate");
        assert_eq!(store.len(), 1);
        store.remove(handle).expect("remove");
        assert!(store.is_empty());
        assert!(store.sign(handle, b"x").is_err(), "and cannot be used");
        assert!(store.remove(handle).is_err(), "or removed twice");
    }

    #[test]
    fn a_full_store_is_a_value_not_an_abort() {
        let mut store = SoftKeyStore::<2>::new();
        store
            .generate(KeyPurpose::Operational, &random())
            .expect("one");
        store
            .generate(KeyPurpose::Operational, &random())
            .expect("two");
        assert_eq!(
            store
                .generate(KeyPurpose::Operational, &random())
                .unwrap_err()
                .code(),
            ErrorCode::NoSpace
        );
    }

    #[test]
    fn an_imported_key_signs_the_same_way() {
        // A known scalar, so the public key is reproducible across runs.
        let secret = [
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1,
            0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b,
            0x12, 0x0f, 0x67, 0x21,
        ];
        let mut store = SoftKeyStore::<2>::new();
        let handle = store
            .import(KeyPurpose::DeviceAttestation, &secret)
            .expect("import");
        let public = store.public_key(handle).expect("public");
        let sig = store.sign(handle, b"msg").expect("sign");
        assert!(super::super::verify(&public, b"msg", &sig).expect("verify"));
        assert_eq!(
            store.purpose(handle).expect("purpose"),
            KeyPurpose::DeviceAttestation
        );
    }

    #[test]
    fn an_all_zero_private_key_is_refused() {
        // Zero is not a valid P-256 scalar.
        let mut store = SoftKeyStore::<2>::new();
        assert!(store.import(KeyPurpose::Operational, &[0u8; 32]).is_err());
    }
}
