//! A Matter implementation in Rust: one crate, `no_std`, no allocation, and no runtime of
//! its own.
//!
//! [Matter](https://csa-iot.org/all-solutions/matter/) is the CSA's smart-home standard —
//! the protocol behind Apple Home, Google Home, Alexa and SmartThings. This crate targets
//! **specification 1.6** (approved 2026-06-16) and is built to be *certifiable* rather
//! than merely interoperable: the same data model the certification Test Harness reads is
//! the data model this crate is generated from.
//!
//! # Status
//!
//! Under construction and pre-1.0. A commissioner and a device can now turn a printed
//! passcode into an encrypted session — the whole of PASE — but there is no data model and
//! no clusters yet, so there is nothing to *say* over that session.
//!
//! | Layer | Module | Specification | State |
//! |---|---|---|---|
//! | Wire format | [`tlv`] | Core Appendix A | ✅ |
//! | Message frame, counters, replay | [`msg`] | Core §4.4, §4.6 | ✅ |
//! | Message security and privacy | [`msg::protect`] | Core §4.8, §4.9 | ✅ |
//! | Exchanges, MRP | [`exchange`] | Core §4.10, §4.12 | ✅ |
//! | Cryptosuite, SPAKE2+, key custody | [`crypto`] | Core ch. 3 | ✅ |
//! | PASE, StatusReport | [`sc`] | Core §4.11, §4.14.1 | ✅ |
//! | Secure sessions | [`session`] | Core §4.13 | ✅ |
//! | Platform seams | [`platform`] | — | ✅ |
//! | Sizing | [`Config`] | Core §2.11 | ✅ |
//! | CASE | `sc::case` | Core §4.14.2 | 📐 |
//! | Commissioning, certificates, fabrics | `commissioning`, `cert`, `fabric` | Core ch. 5–6 | 📐 |
//! | Data and interaction models | `dm`, `im` | Core ch. 7–10 | 📐 |
//! | Clusters, device types | `clusters` | Application Cluster, Device Library | 📐 |
//!
//! # Three things that shape the whole crate
//!
//! **Sizing is a type, not a build flag.** Every table in the stack — fabrics, sessions,
//! exchanges, subscriptions, access-control entries — is a fixed-capacity array whose
//! length comes from an associated constant on [`Config`]. The specification's minima
//! (Core §2.11) are `const` assertions, so a configuration that could not pass
//! certification does not compile. Two libraries in one binary cannot fight over it the
//! way they fight over a Cargo feature.
//!
//! ```
//! use matter_kit::{Config, DefaultConfig};
//!
//! struct Small;
//! impl Config for Small {
//!     const FABRICS: usize = 5;          // Core §11.18.5.3 constrains this to 5..=254
//!     const SESSIONS: usize = 16;
//!     // …everything else defaults.
//! }
//! assert!(Small::ACL_ENTRIES >= 4 * Small::FABRICS); // Core §2.11.1.1
//! # let _ = DefaultConfig::FABRICS;
//! ```
//!
//! **No runtime is chosen for you.** The crate is `async` over [`core::future`] and talks
//! to the outside world through the traits in [`platform`]: sockets, timers, randomness,
//! storage, cryptography. Embassy and Tokio appear in `examples/`, never in the dependency
//! tree. One consequence worth having: every timeout in the specification — MRP backoff,
//! the fail-safe, an intermittently-connected device's idle period — is driven by a
//! [`platform::Timer`], so [`platform::sim`] runs an hour-long scenario in microseconds.
//!
//! **Nothing panics on network input.** `unwrap`, `expect`, `panic!` and slice indexing
//! are denied crate-wide; every parser returns [`Error`]. Resource exhaustion is a value
//! ([`ErrorCode::NoSpace`], [`ErrorCode::Busy`]), so a device that runs out of exchanges
//! answers rather than aborts.
//!
//! # Commissioning, in miniature
//!
//! ```
//! use matter_kit::crypto::Spake2pVerifierData;
//! use matter_kit::msg::SessionId;
//! use matter_kit::sc::{PaseInitiator, PaseResponder, PbkdfParameters, ResponderConfig};
//!
//! // What a factory burns into the device. The passcode itself is never stored.
//! let parameters = PbkdfParameters::new(1_000, b"SPAKE2P Key Salt")?;
//! let verifier =
//!     Spake2pVerifierData::from_passcode(20_202_021, &parameters.salt, parameters.iterations)?;
//!
//! let mut device = PaseResponder::new(
//!     ResponderConfig { verifier, parameters: parameters.clone(), session_params: None },
//!     SessionId(1),
//! );
//! let mut commissioner =
//!     PaseInitiator::new(20_202_021, SessionId(2), Some(parameters), None);
//!
//! let (mut a, mut b) = ([0u8; 512], [0u8; 512]);
//! let n = commissioner.start(&[0x11; 32], &mut a)?;
//! let n = device.on_pbkdf_param_request(&a[..n], &[0x22; 32], &mut b)?;
//! let n = commissioner.on_pbkdf_param_response(&b[..n], &[0x33; 32], &mut a)?;
//! let n = device.on_pake1(&a[..n], &[0x44; 32], &mut b)?;
//! let n = commissioner.on_pake2(&b[..n], &mut a)?;
//! let (n, device_keys) = device.on_pake3(&a[..n], &mut b)?;
//! let commissioner_keys = commissioner.on_pake_finished(&b[..n])?;
//!
//! // Both ends now hold the same three keys.
//! assert_eq!(commissioner_keys.i2r, device_keys.i2r);
//! # Ok::<(), matter_kit::Error>(())
//! ```
//!
//! # Reading a payload
//!
//! ```
//! use matter_kit::tlv::{Pretty, TlvReader};
//!
//! // { 0 = 42, 1 = -17 } — the example from Core Table 128.
//! let bytes = [0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18];
//! TlvReader::validate(&bytes)?;
//! # #[cfg(feature = "std")]
//! assert_eq!(std::format!("{}", Pretty(&bytes)), "{0 = 42, 1 = -17}");
//! # Ok::<(), matter_kit::Error>(())
//! ```
//!
//! # Matching on an event
//!
//! Enums this crate *reports* through are `#[non_exhaustive]`; enums the **specification**
//! closes are not. So a `match` on a protocol state is still checked for completeness —
//! which is where you want to be told about a new variant — and a `match` on a stream of
//! events does not break when a new one is worth reporting.
//!
//! ---
//!
//! Matter® is a registered trademark of the Connectivity Standards Alliance. This project
//! is not affiliated with or endorsed by the Alliance, and nothing here is a certified
//! implementation.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// The crate-wide `deny` list in `Cargo.toml` is aimed at code that faces the network.
// Test code faces a test: `unwrap` there is a legible assertion, and writing
// `let Some(x) = .. else { panic!() }` around every fixture buys nothing and hides the
// intent. The denials stay in force for everything that ships.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod config;
pub mod crypto;
pub mod error;
pub mod exchange;
pub mod msg;
pub mod platform;
#[cfg(feature = "rustcrypto")]
pub mod sc;
#[cfg(feature = "rustcrypto")]
pub mod session;
pub mod tlv;

pub use config::{Config, DefaultConfig};
pub use error::{Error, ErrorCode, Result};

/// The Matter specification version this crate implements, in the encoding of the Basic
/// Information cluster's `SpecificationVersion` attribute (Core §11.1.5.22).
///
/// The four component bytes are major, minor, patch and reserved: `0x01_06_00_00` is
/// 1.6.0. A larger value is newer.
pub const SPECIFICATION_VERSION: u32 = 0x0106_0000;

/// The IANA-assigned UDP port for Matter (Core §2.5.6.3).
pub const PORT: u16 = 5540;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specification_version_is_1_6_0() {
        assert_eq!(SPECIFICATION_VERSION.to_be_bytes(), [1, 6, 0, 0]);
    }
}
