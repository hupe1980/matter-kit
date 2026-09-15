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
//! Under construction and pre-1.0. A device can be commissioned into a fabric end to end,
//! answer Reads, Writes and Invokes against a `const` data model, hold subscriptions,
//! enforce §6.6's access control, and advertise itself over DNS-SD — with
//! [`messaging`] composing the layers, so a datagram finds its session, exchange and
//! protocol. What is missing is the application clusters. The
//! [README](https://github.com/hupe1980/matter-kit#status) carries the layer-by-layer table;
//! each module here states which sections it implements.
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
//! The whole of PASE: a printed passcode becomes three shared keys, without the passcode
//! ever crossing the wire. Needs the `rustcrypto` feature, which is on by default.
//!
//! ```
//! # #[cfg(feature = "rustcrypto")]
//! # fn demo() -> Result<(), matter_kit::Error> {
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
//! # Ok(())
//! # }
//! # fn main() {
//! #     #[cfg(feature = "rustcrypto")]
//! #     demo().expect("the exchange completes");
//! # }
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

mod bytes;

pub mod acl;
#[cfg(feature = "rustcrypto")]
pub mod attestation;
pub mod bdx;
/// The fabric's certificate authority needs [`cert`] and [`crypto`]'s signing.
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod ca;
#[cfg(feature = "rustcrypto")]
pub mod cert;
pub mod clusters;
pub mod commissioning;
pub mod config;
pub mod crypto;
#[cfg(feature = "rustcrypto")]
pub mod der;
pub mod discovery;
pub mod dm;
pub mod error;
pub mod exchange;
#[cfg(feature = "rustcrypto")]
pub mod fabric;
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod group;
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod icd;
pub mod im;
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod jf;
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod messaging;
pub mod msg;
pub mod platform;
pub mod sc;
#[cfg(feature = "rustcrypto")]
pub mod session;
pub mod sync;
pub mod tlv;
pub mod transport;

pub use config::{Config, DefaultConfig};
pub use error::{Error, ErrorCode, Result};

/// The Matter specification version this crate implements, in the encoding of the Basic
/// Information cluster's `SpecificationVersion` attribute (Core §11.1.5.22).
///
/// The four component bytes are major, minor, patch and reserved: `0x01_06_00_00` is
/// 1.6.0. A larger value is newer.
pub const SPECIFICATION_VERSION: u32 = 0x0106_0000;

/// The Data Model revision this crate implements — §7.1.1's revision 21, "Added Revision
/// conformance".
///
/// §11.1.5.1 requires a node to report "the revision number of the Data Model against which
/// the Node is certified", and "one of the valid values listed in Section 7.1.1". The table
/// grew by one between releases and the split is easy to miss: 1.5.1 ends at
/// `20 — Removed P quality and added Revision conformance`, and 1.6 divides that single row
/// into `20 — Removed P quality` and `21 — Added Revision conformance`. A 1.6 node reports
/// 21; carrying 20 forward advertises a 1.5.1 data model.
///
/// It lives here rather than in the Basic Information cluster because it is also
/// `DATA_MODEL_REVISION` in the `session-parameter-struct` of §4.13.1, which is exchanged
/// long before any cluster is readable. `clusters::basic_information` re-exports it.
pub const DATA_MODEL_REVISION: u16 = 21;

/// The IANA-assigned UDP port for Matter (Core §2.5.6.3).
pub const PORT: u16 = 5540;

/// The README's `rust` blocks, compiled as doctests.
///
/// Under `cfg(doctest)` only, so the README is not pulled into the crate's own
/// documentation — this exists so a landing-page example cannot quietly stop compiling.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specification_version_is_1_6_0() {
        assert_eq!(SPECIFICATION_VERSION.to_be_bytes(), [1, 6, 0, 0]);
    }

    /// The three revisions a peer reads out of `session-parameter-struct` (§4.13.1) move
    /// independently of each other and of the crate version, and each is a number taken from
    /// a table in a PDF. Asserting them here is what makes a spec uplift that forgets one
    /// fail loudly: 1.6 split §7.1.1's last row and `DATA_MODEL_REVISION` silently stayed at
    /// its 1.5.1 value until this test existed.
    #[test]
    fn the_revision_constants_are_the_1_6_values() {
        // Core §7.1.1, last row: "21 — Added Revision conformance".
        assert_eq!(DATA_MODEL_REVISION, 21);
        // Core §8.1.1, last row: "13 — Added WildcardFilterConfigurationVersion (Matter 1.3)".
        assert_eq!(crate::im::INTERACTION_MODEL_REVISION, 13);
        // Core §11.1.5.22, as four component bytes.
        assert_eq!(SPECIFICATION_VERSION, 0x0106_0000);
    }
}
