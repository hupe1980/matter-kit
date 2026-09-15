//! Commissioning: getting a device onto a fabric (Core ch. 5).
//!
//! The sequence of §2.8 is: discover the device, prove possession of its passcode with
//! PASE ([`crate::sc`]), check it is a genuine certified device, give it an operational
//! identity and a network, then talk to it over CASE. This module is the first and last
//! steps — everything that is *about* commissioning rather than about security.
//!
//! It holds four pieces: the **onboarding payload** — the QR code and manual pairing code
//! that carry a device's passcode from its label to a commissioner — the
//! [**fail-safe**](failsafe), the transaction that makes every commissioning write
//! recoverable; the [**commissioning window**](window), the node state three clusters share;
//! and [**PASE admission**](admission), §5.5's three rules on which `PBKDFParamRequest` a
//! commissionee may answer at all.
//!
//! ```
//! use matter_kit::commissioning::{
//!     CustomFlow, DiscoveryCapabilities, OnboardingPayload, Passcode,
//! };
//! use matter_kit::msg::VendorId;
//!
//! let payload = OnboardingPayload::new(
//!     VendorId(0xFFF1),
//!     0x8001,
//!     3840,
//!     Passcode::new(20_202_021)?,
//!     DiscoveryCapabilities::ON_IP_NETWORK,
//!     CustomFlow::Standard,
//! )?;
//!
//! let qr = payload.to_qr()?;              // MT:…
//! let manual = payload.to_manual_code(false)?;  // eleven digits
//! assert_eq!(OnboardingPayload::from_qr(&qr)?, payload);
//! assert_eq!(manual.len(), 11);
//! # Ok::<(), matter_kit::Error>(())
//! ```

pub mod admission;

/// The commissioner's side needs [`attestation`](crate::attestation) to check a device's DAC
/// and [`ca`](crate::ca) to issue it a NOC, both of which are cryptography.
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod commissioner;
pub mod failsafe;
mod payload;
pub mod window;

pub use admission::{
    Admit, Failure, MAX_FAILED_ATTEMPTS, PASE_ESTABLISHMENT_TIMEOUT, PaseAdmission,
};
pub use failsafe::{
    ArmOutcome, BasicCommissioningInfo, Cleanup, CommissioningError, FailSafe, Progress,
};
pub use payload::{
    CustomFlow, DiscoveryCapabilities, MANUAL_CODE_MAX_DIGITS, OnboardingPayload, PACKED_LEN,
    Passcode, QR_LEN_NO_TLV, QR_PREFIX,
};
pub use window::{CommissioningWindow, EphemeralVerifier, OpenWindow, WindowStatus};
