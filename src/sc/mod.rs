//! The Secure Channel protocol: session establishment and status (Core §4.11, §4.14).
//!
//! Everything that happens before a node can say anything useful. PASE turns a printed
//! passcode into the first session; CASE turns operational certificates into every session
//! after that; [`StatusReport`] is how both of them, and every other
//! protocol, report how it went.
//!
//! ```
//! use matter_kit::sc::{PaseInitiator, PaseResponder, ResponderConfig, PbkdfParameters};
//! use matter_kit::crypto::Spake2pVerifierData;
//! use matter_kit::msg::SessionId;
//!
//! // What a factory burns into the device: the verifier for its printed passcode.
//! let parameters = PbkdfParameters::new(1_000, b"SPAKE2P Key Salt")?;
//! let verifier =
//!     Spake2pVerifierData::from_passcode(20_202_021, &parameters.salt, parameters.iterations)?;
//!
//! let mut device = PaseResponder::new(
//!     ResponderConfig { verifier, parameters: parameters.clone(), session_params: None },
//!     SessionId(1),
//! );
//! let mut commissioner = PaseInitiator::new(20_202_021, SessionId(2), Some(parameters), None);
//! # Ok::<(), matter_kit::Error>(())
//! ```
//!
//! `tests/pase_over_sim.rs` runs the whole exchange over the simulated network.

mod pase;
pub mod status;

pub use pase::{
    PASSCODE_ID_COMMISSIONING, Pake1, Pake2, Pake3, PaseInitiator, PaseResponder,
    PbkdfParamRequest, PbkdfParamResponse, PbkdfParameters, RANDOM_LEN, ResponderConfig, opcode,
};
pub use status::{GeneralCode, SecureChannelCode, StatusReport};

use crate::error::Result;
use crate::exchange::MrpParams;
use crate::platform::Duration;
use crate::tlv::{Tag, TlvWriter};

/// `session-parameter-struct` — the MRP timings a peer announces during session
/// establishment (Core §4.12.3).
///
/// "the initiator of a secure session MAY provide these parameters in the initial CASE
/// Sigma1 or PASE PBKDFParamRequest messages, and the responder MAY provide its parameters
/// in the corresponding protocol messages". Every field is optional; an absent one means
/// "use the default".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionParams {
    /// `SESSION_IDLE_INTERVAL`, in milliseconds.
    pub idle_interval_ms: Option<u32>,
    /// `SESSION_ACTIVE_INTERVAL`, in milliseconds.
    pub active_interval_ms: Option<u32>,
    /// `SESSION_ACTIVE_THRESHOLD`, in milliseconds.
    pub active_threshold_ms: Option<u16>,
}

impl SessionParams {
    /// Builds the announcement for a node's own MRP parameters.
    #[must_use]
    pub fn from_mrp(params: &MrpParams) -> Self {
        Self {
            idle_interval_ms: u32::try_from(params.idle_interval.as_millis()).ok(),
            active_interval_ms: u32::try_from(params.active_interval.as_millis()).ok(),
            active_threshold_ms: u16::try_from(params.active_threshold.as_millis()).ok(),
        }
    }

    /// Turns an announcement into MRP parameters, filling absent fields from the defaults
    /// and clamping what the peer sent.
    ///
    /// The clamping is not optional politeness: these values decide how long this node
    /// waits before retransmitting, and they came from a stranger.
    #[must_use]
    pub fn to_mrp(self) -> MrpParams {
        let defaults = MrpParams::default();
        MrpParams {
            idle_interval: self.idle_interval_ms.map_or(defaults.idle_interval, |ms| {
                Duration::from_millis(u64::from(ms))
            }),
            active_interval: self
                .active_interval_ms
                .map_or(defaults.active_interval, |ms| {
                    Duration::from_millis(u64::from(ms))
                }),
            active_threshold: self
                .active_threshold_ms
                .map_or(defaults.active_threshold, |ms| {
                    Duration::from_millis(u64::from(ms))
                }),
        }
        .clamped()
    }

    pub(crate) fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        if let Some(v) = self.idle_interval_ms {
            w.unsigned(Tag::Context(1), u64::from(v))?;
        }
        if let Some(v) = self.active_interval_ms {
            w.unsigned(Tag::Context(2), u64::from(v))?;
        }
        if let Some(v) = self.active_threshold_ms {
            w.unsigned(Tag::Context(3), u64::from(v))?;
        }
        w.end_container()
    }

    pub(crate) fn decode(fields: &mut pase::Fields<'_>) -> Result<Self> {
        let mut out = Self::default();
        while let Some((tag, element)) = fields.next()? {
            match tag {
                1 => out.idle_interval_ms = u32::try_from(element.unsigned()?).ok(),
                2 => out.active_interval_ms = u32::try_from(element.unsigned()?).ok(),
                3 => out.active_threshold_ms = u16::try_from(element.unsigned()?).ok(),
                // 1.6 adds further fields here; an older node skips what it does not know.
                _ => fields.skip(&element)?,
            }
        }
        Ok(out)
    }
}
