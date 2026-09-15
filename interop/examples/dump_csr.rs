//! Writes a freshly generated `CertificationRequest` to `/tmp/csr.der`, for `openssl` to judge.
//!
//! The vectors in `tests/attestation_vectors.rs` check a CSR built over the *specification's*
//! key. This builds one over a fresh key, which is what a device answers `CSRRequest` with, and
//! puts it somewhere a parser written by somebody else can read.
fn main() {
    use matter_kit::attestation::{build_csr, nocsr::MAX_CSR_LEN};
    use matter_kit::crypto::{KeyPurpose, KeyStore, SoftKeyStore};

    for n in 0..8u8 {
        let mut keys = SoftKeyStore::<2>::new();
        let seed = [n.wrapping_mul(37).wrapping_add(1); 32];
        let (handle, _) = keys
            .generate(KeyPurpose::Operational, &seed)
            .expect("generate");
        let mut buf = [0u8; MAX_CSR_LEN];
        let csr = build_csr(&keys, handle, &mut buf).expect("build");
        let path = format!("/tmp/csr{n}.der");
        std::fs::write(&path, csr).expect("write");
        println!("{path} {} bytes", csr.len());
    }
}
