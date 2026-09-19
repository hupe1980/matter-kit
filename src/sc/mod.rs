//! The Secure Channel protocol: session establishment and status (Core §4.11, §4.14).
//!
//! Everything that happens before a node can say anything useful. PASE turns a printed
//! passcode into the first session; CASE turns operational certificates into every session
//! after that; [`StatusReport`] is how both of them, and every other
//! protocol, report how it went.
//!
//! ```
//! # #[cfg(feature = "rustcrypto")]
//! # fn demo() -> Result<(), matter_kit::Error> {
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
//! # Ok(())
//! # }
//! ```
//!
//! `tests/pase_over_sim.rs` runs the whole exchange over the simulated network.

/// PASE and CASE are cryptography; [`status`] is not, and every protocol needs it — so a
/// node built without a [`crypto`](crate::crypto) backend still has
/// [`StatusReport`](status::StatusReport).
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod case;
/// The node's own secure channel: §5.5's admission rules, both handshakes, and the session
/// they produce. Needs the fabric table and the message layer, so it is gated like they are.
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod channel;
#[cfg(feature = "rustcrypto")]
mod pase;
pub mod status;

#[cfg(feature = "rustcrypto")]
pub use case::{
    CaseInitiator, CaseOutcome, CaseResponder, MAX_ENCRYPTED2, MAX_ENCRYPTED3, MAX_SESSION_PARAMS,
    MAX_SIGMA1, MAX_SIGMA2, MAX_SIGMA3, MAX_TBSDATA, ResumptionState, Sigma1, Sigma2, Sigma2Resume,
    Sigma3, TbeData, Transcript,
};
#[cfg(feature = "rustcrypto")]
pub use channel::{Channel, ChannelBuffers, ChannelContext, ChannelReply, Established};
#[cfg(feature = "rustcrypto")]
pub(crate) use pase::Fields;
#[cfg(feature = "rustcrypto")]
pub use pase::{
    PASSCODE_ID_COMMISSIONING, Pake1, Pake2, Pake3, PaseInitiator, PaseResponder,
    PbkdfParamRequest, PbkdfParamResponse, PbkdfParameters, RANDOM_LEN, ResponderConfig,
};
pub use status::{GeneralCode, SecureChannelCode, StatusReport};

#[cfg(feature = "rustcrypto")]
use crate::error::{Error, ErrorCode, Result};
use crate::exchange::MrpParams;
use crate::platform::Duration;
#[cfg(feature = "rustcrypto")]
use crate::tlv::{Tag, TlvWriter};
use crate::transport::TransportModes;

/// The Secure Channel protocol opcodes of Core Table 18.
///
/// Every message on [`ProtocolId::SECURE_CHANNEL`](crate::msg::ProtocolId::SECURE_CHANNEL)
/// carries one of these, and a receiver dispatches on it before it knows anything else about
/// the payload.
pub mod opcode {
    /// `0x00` — Message Counter Synchronization Request.
    pub const MSG_COUNTER_SYNC_REQ: u8 = 0x00;
    /// `0x01` — Message Counter Synchronization Response.
    pub const MSG_COUNTER_SYNC_RSP: u8 = 0x01;
    /// `0x10` — MRP Standalone Acknowledgement (§4.12.7.1).
    ///
    /// "This message is dedicated for the purpose of sending a stand-alone acknowledgement
    /// when there is no other data message available to piggyback an acknowledgement on top
    /// of." Its payload is empty and it is never itself reliable — acknowledging an
    /// acknowledgement would not terminate.
    pub const MRP_STANDALONE_ACK: u8 = 0x10;
    /// `0x20` — `PBKDFParamRequest`, the first message of PASE.
    pub const PBKDF_PARAM_REQUEST: u8 = 0x20;
    /// `0x21` — `PBKDFParamResponse`.
    pub const PBKDF_PARAM_RESPONSE: u8 = 0x21;
    /// `0x22` — PASE `Pake1`, "the first PAKE message of the PASE protocol".
    pub const PAKE1: u8 = 0x22;
    /// `0x23` — PASE `Pake2`.
    pub const PAKE2: u8 = 0x23;
    /// `0x24` — PASE `Pake3`.
    pub const PAKE3: u8 = 0x24;
    /// `0x30` — CASE `Sigma1`.
    pub const SIGMA1: u8 = 0x30;
    /// `0x31` — CASE `Sigma2`.
    pub const SIGMA2: u8 = 0x31;
    /// `0x32` — CASE `Sigma3`.
    pub const SIGMA3: u8 = 0x32;
    /// `0x33` — CASE `Sigma2_Resume`.
    pub const SIGMA2_RESUME: u8 = 0x33;
    /// `0x40` — `StatusReport` (Appendix D).
    pub const STATUS_REPORT: u8 = 0x40;
    /// `0x50` — the ICD Check-In message (§4.22).
    pub const ICD_CHECK_IN: u8 = 0x50;
}

/// `session-parameter-struct` — what each side announces about itself during session
/// establishment (Core §4.13.1, Table 23).
///
/// It rides in five messages: CASE `Sigma1`, `Sigma2` and `Sigma2_Resume`, and PASE
/// `PBKDFParamRequest` and `PBKDFParamResponse`. Nine fields, and the shape of the struct is
/// **not** the shape of the schema, deliberately:
///
/// | Tag | Field | §4.13.1 | Here |
/// |---|---|---|---|
/// | 1 | `SESSION_IDLE_INTERVAL` | optional | always sent |
/// | 2 | `SESSION_ACTIVE_INTERVAL` | optional | always sent — see below |
/// | 3 | `SESSION_ACTIVE_THRESHOLD` | optional | always sent |
/// | 4 | `DATA_MODEL_REVISION` | mandatory | [`Self::data_model_revision`] |
/// | 5 | `INTERACTION_MODEL_REVISION` | mandatory | [`Self::interaction_model_revision`] |
/// | 6 | `SPECIFICATION_VERSION` | mandatory | [`Self::specification_version`] |
/// | 7 | `MAX_PATHS_PER_INVOKE` | mandatory | [`Self::max_paths_per_invoke`] |
/// | 8 | `SUPPORTED_TRANSPORTS` | mandatory | [`Self::supported_transports`] |
/// | 9 | `MAX_TCP_MESSAGE_SIZE` | optional | [`Self::max_tcp_message_size`] |
///
/// **Why no field is an `Option` except the last.** Tags 4–8 have been mandatory since
/// Matter 1.3, so a struct that can omit them is a struct that can represent a message the
/// specification forbids. Tags 1–3 stay optional in the schema, but §4.13.1 adds "if any tag
/// after tag 2 (SESSION_ACTIVE_INTERVAL) is present, then the SESSION_ACTIVE_INTERVAL SHALL
/// also be present" — and tags 4–8 are always present — so tag 2 is mandatory in practice,
/// and sending 1 and 3 alongside it costs eight octets and removes two more `Option`s. What
/// is left optional is the one field that genuinely is: `MAX_TCP_MESSAGE_SIZE`, which is
/// meaningless on a node that does not speak TCP.
///
/// The consequence that matters is that **this struct cannot encode to an empty structure**.
/// The previous shape — three `Option`s and a derived `Default` — could, and did: every
/// released CHIP SDK refuses an empty `session-parameter-struct`, because
/// `PairingSession::DecodeSessionParametersIfPresent` calls `Next()` once without guarding
/// it against `CHIP_END_OF_TLV` where every later call in the same function is guarded. A
/// conformant struct is never empty, so conformance and interoperability close the same hole.
///
/// **Receiving is the asymmetric half.** A peer older than 1.3 sends only tags 1–3, so
/// `SessionParams::decode` — crate-private, because a peer's parameters reach this crate only
/// inside a message it parses — starts from [`SessionParams::legacy_peer`], Table 23's default
/// for every parameter, and overwrites what the peer actually sent. Table 23 requires
/// exactly that: "A Node SHALL use the provided default value for each parameter unless the
/// message recipient Node advertises an alternate value".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionParams {
    /// `SESSION_IDLE_INTERVAL [1]`, in milliseconds — "minimum amount of time between sender
    /// retries when the destination node is Idle". Table 23's default is 500 ms.
    pub idle_interval_ms: u32,
    /// `SESSION_ACTIVE_INTERVAL [2]`, in milliseconds — the same when the destination is
    /// Active. Table 23's default is 300 ms.
    pub active_interval_ms: u32,
    /// `SESSION_ACTIVE_THRESHOLD [3]`, in milliseconds — "minimum amount of time the node
    /// SHOULD stay active after network activity". Table 23's default is 4000 ms.
    pub active_threshold_ms: u16,
    /// `DATA_MODEL_REVISION [4]` — §7.1.1's revision. [`crate::DATA_MODEL_REVISION`] here.
    pub data_model_revision: u16,
    /// `INTERACTION_MODEL_REVISION [5]` — §8.1.1's revision.
    /// [`crate::im::INTERACTION_MODEL_REVISION`] here.
    pub interaction_model_revision: u16,
    /// `SPECIFICATION_VERSION [6]` — §11.1.5.22's four component bytes.
    /// [`crate::SPECIFICATION_VERSION`] here.
    pub specification_version: u32,
    /// `MAX_PATHS_PER_INVOKE [7]` — "the maximum number of elements in the InvokeRequests
    /// list that the Node is able to process". §11.1.5.23: "If the MaxPathsPerInvoke
    /// attribute is absent or zero … clients SHALL assume a value of 1", so 1 is the floor
    /// and never 0.
    pub max_paths_per_invoke: u16,
    /// `SUPPORTED_TRANSPORTS [8]` — Table 7's bitmap, "in addition to MRP". Empty means MRP
    /// only, which is every node that does not speak TCP.
    pub supported_transports: TransportModes,
    /// `MAX_TCP_MESSAGE_SIZE [9]`, in octets — "maximum size of the message carried over
    /// TCP, excluding the framing message length field, that the node is capable of
    /// receiving". `None` on a node with no TCP; Table 23's default is 64000.
    pub max_tcp_message_size: Option<u32>,
}

impl SessionParams {
    /// Table 23's default `MAX_TCP_MESSAGE_SIZE`.
    ///
    /// The three MRP timings have defaults too, and they are not repeated here: Table 22 and
    /// Table 23 are the same three numbers, and [`MrpParams::default`] already carries them.
    /// Two copies of a specification default are two things to forget at an uplift.
    pub const DEFAULT_MAX_TCP_MESSAGE_SIZE: u32 = 64_000;

    /// What a peer is assumed to be when it sends no `session-parameter-struct` at all, or
    /// one from before Matter 1.3 — every parameter at Table 23's default.
    ///
    /// The revisions are the **floors**, not this crate's values, and that is the whole
    /// point: §4.13.1 says "if the DATA_MODEL_REVISION field is missing, it implies a
    /// DataModelRevision value of either 16 or 17", so a peer that omitted it is a 1.0-era
    /// peer and must be treated as one. Assuming this node's own revisions for a silent peer
    /// would be assuming the peer understands everything this node does.
    #[must_use]
    pub fn legacy_peer() -> Self {
        // Table 22's MRP defaults and Table 23's session defaults are the same three numbers,
        // so they come from the one place that already holds them. The revisions are 1.0's:
        // §7.1.1's 16, §8.1.1's 10, and specification 1.0.0.0.
        Self::announce_with_revisions(&MrpParams::default(), 16, 10, 0x0100_0000)
    }

    /// The shared body of [`Self::announce`] and [`Self::legacy_peer`]: the same nine fields,
    /// differing only in whose revisions they carry.
    fn announce_with_revisions(
        mrp: &MrpParams,
        data_model_revision: u16,
        interaction_model_revision: u16,
        specification_version: u32,
    ) -> Self {
        Self {
            idle_interval_ms: clamp_ms_u32(mrp.idle_interval),
            active_interval_ms: clamp_ms_u32(mrp.active_interval),
            active_threshold_ms: clamp_ms_u16(mrp.active_threshold),
            data_model_revision,
            interaction_model_revision,
            specification_version,
            // §11.1.5.23: "absent or zero … clients SHALL assume a value of 1".
            max_paths_per_invoke: 1,
            // Table 7's bitmap is "in addition to MRP", so empty is MRP only.
            supported_transports: TransportModes::empty(),
            max_tcp_message_size: None,
        }
    }

    /// What this node announces: its own MRP timings, and this crate's revisions.
    ///
    /// `MAX_PATHS_PER_INVOKE` starts at 1 — §11.1.5.23's floor, and the value a node that
    /// has not thought about batched Invoke must report — and `SUPPORTED_TRANSPORTS` starts
    /// empty. Both are raised with the builders below, and both must match what the node
    /// actually does: a peer is entitled to send `MAX_PATHS_PER_INVOKE` commands in one
    /// Invoke and to open a TCP connection if this says it may.
    #[must_use]
    pub fn announce(mrp: &MrpParams) -> Self {
        Self::announce_with_revisions(
            mrp,
            crate::DATA_MODEL_REVISION,
            crate::im::INTERACTION_MODEL_REVISION,
            crate::SPECIFICATION_VERSION,
        )
    }

    /// Announces a `MAX_PATHS_PER_INVOKE` above the floor.
    ///
    /// Clamped to at least 1, because §11.1.5.23 makes zero mean one and a zero on the wire
    /// would be read as "absent" by a peer that follows it.
    #[must_use]
    pub const fn with_max_paths_per_invoke(mut self, max: u16) -> Self {
        self.max_paths_per_invoke = if max == 0 { 1 } else { max };
        self
    }

    /// Announces the transports this node supports in addition to MRP, and the largest TCP
    /// message it can receive.
    ///
    /// The two travel together because one without the other is a contradiction: a size for
    /// a transport that was not announced tells a peer nothing, and announcing
    /// [`TransportModes::TCP_SERVER`] without a size leaves the peer on Table 23's 64000.
    #[must_use]
    pub const fn with_transports(mut self, modes: TransportModes, max_tcp_message: u32) -> Self {
        self.supported_transports = modes;
        self.max_tcp_message_size = if modes.is_empty() {
            None
        } else {
            Some(max_tcp_message)
        };
        self
    }

    /// Turns an announcement into MRP parameters, clamping what the peer sent.
    ///
    /// The clamping is not optional politeness: these values decide how long this node
    /// waits before retransmitting, and they came from a stranger.
    #[must_use]
    pub fn to_mrp(self) -> MrpParams {
        MrpParams {
            idle_interval: Duration::from_millis(u64::from(self.idle_interval_ms)),
            active_interval: Duration::from_millis(u64::from(self.active_interval_ms)),
            active_threshold: Duration::from_millis(u64::from(self.active_threshold_ms)),
        }
        .clamped()
    }

    /// Whether the peer said it will accept a TCP connection (Table 7, bit 2).
    #[must_use]
    pub const fn accepts_tcp(&self) -> bool {
        self.supported_transports
            .contains(TransportModes::TCP_SERVER)
    }

    /// The largest TCP message the peer said it can receive, or Table 23's default.
    #[must_use]
    pub const fn max_tcp_message_size_or_default(&self) -> u32 {
        match self.max_tcp_message_size {
            Some(n) => n,
            None => Self::DEFAULT_MAX_TCP_MESSAGE_SIZE,
        }
    }

    #[cfg(feature = "rustcrypto")]
    pub(crate) fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        // Tags 1-3 are optional in the schema and unconditional here: §4.13.1 requires tag 2
        // whenever anything after it is present, and tags 4-8 always are.
        w.unsigned(Tag::Context(1), u64::from(self.idle_interval_ms))?;
        w.unsigned(Tag::Context(2), u64::from(self.active_interval_ms))?;
        w.unsigned(Tag::Context(3), u64::from(self.active_threshold_ms))?;
        w.unsigned(Tag::Context(4), u64::from(self.data_model_revision))?;
        w.unsigned(Tag::Context(5), u64::from(self.interaction_model_revision))?;
        w.unsigned(Tag::Context(6), u64::from(self.specification_version))?;
        w.unsigned(Tag::Context(7), u64::from(self.max_paths_per_invoke))?;
        w.unsigned(Tag::Context(8), u64::from(self.supported_transports.bits()))?;
        if let Some(size) = self.max_tcp_message_size {
            w.unsigned(Tag::Context(9), u64::from(size))?;
        }
        w.end_container()
    }

    /// Reads a `session-parameter-struct` whose opening element the caller has just taken.
    ///
    /// Absent fields keep [`SessionParams::legacy_peer`]'s value rather than becoming `None`,
    /// which is what Table 23 asks for: "A Node SHALL use the provided default value for each
    /// parameter unless the message recipient Node advertises an alternate value".
    ///
    /// This is a *nested* structure, so it reads through [`Fields::nested`]: without that the
    /// loop runs past its own end-of-container and swallows whatever follows it in the
    /// enclosing message. In a Sigma1 that is the resumption id and MIC, so an initiator that
    /// announced its MRP parameters would have its resumption request silently dropped and
    /// fall back to a full handshake — a failure with no error anywhere.
    #[cfg(feature = "rustcrypto")]
    pub(crate) fn decode(fields: &mut pase::Fields<'_>) -> Result<Self> {
        fields.nested(|fields| {
            let mut out = Self::legacy_peer();
            let mut seen = 0u32;
            while let Some((tag, element)) = fields.next()? {
                // Core §A.5.1: members of a structure have unique tags.
                if tag < 32 {
                    let bit = 1u32 << tag;
                    if seen & bit != 0 {
                        return Err(Error::new(ErrorCode::TlvDuplicateTag));
                    }
                    seen |= bit;
                }
                match tag {
                    1 => out.idle_interval_ms = saturating_u32(element.unsigned()?),
                    2 => out.active_interval_ms = saturating_u32(element.unsigned()?),
                    3 => out.active_threshold_ms = saturating_u16(element.unsigned()?),
                    4 => out.data_model_revision = saturating_u16(element.unsigned()?),
                    5 => out.interaction_model_revision = saturating_u16(element.unsigned()?),
                    6 => out.specification_version = saturating_u32(element.unsigned()?),
                    // §11.1.5.23: zero means one.
                    7 => out.max_paths_per_invoke = saturating_u16(element.unsigned()?).max(1),
                    // Bit 0 is reserved and "clients SHALL silently ignore this bit", which
                    // `from_bits_truncate` does along with every other unknown bit.
                    8 => {
                        out.supported_transports =
                            TransportModes::from_bits_truncate(saturating_u32(element.unsigned()?));
                    }
                    9 => out.max_tcp_message_size = Some(saturating_u32(element.unsigned()?)),
                    // A later revision adds fields here; an older node skips what it does not
                    // know rather than refusing the session.
                    _ => fields.skip(&element)?,
                }
            }
            Ok(out)
        })
    }
}

impl Default for SessionParams {
    /// This node's announcement with Table 22's MRP timings — the same thing
    /// [`SessionParams::announce`] builds from [`MrpParams::default`].
    ///
    /// A `Default` here was once the defect rather than the convenience: when every field was
    /// an `Option`, the derived `Default` was three `None`s and encoded to an empty structure
    /// that every released CHIP SDK refuses. It is safe now for a structural reason
    /// rather than a careful one — §4.13.1's tags 4-8 are mandatory, so they are plain fields,
    /// and there is no combination of this type that encodes to an empty container.
    fn default() -> Self {
        Self::announce(&MrpParams::default())
    }
}

/// An MRP interval in milliseconds, saturating.
///
/// `MrpParams` is already clamped to §4.13.1's ceilings by [`MrpParams::clamped`], so this
/// only has to be total, not lossy in practice.
fn clamp_ms_u32(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

fn clamp_ms_u16(d: Duration) -> u16 {
    u16::try_from(d.as_millis()).unwrap_or(u16::MAX)
}

/// Narrows a TLV unsigned to `u32`, saturating rather than failing.
///
/// Every one of these fields is schema-constrained to 16 or 32 bits, so a wider value is a
/// peer that is wrong. Refusing the session over it would be a denial of service with extra
/// steps; saturating keeps the clamp in [`SessionParams::to_mrp`] in charge of the only
/// values that can hurt this node.
#[cfg(feature = "rustcrypto")]
const fn saturating_u32(v: u64) -> u32 {
    if v > u32::MAX as u64 {
        u32::MAX
    } else {
        v as u32
    }
}

#[cfg(feature = "rustcrypto")]
const fn saturating_u16(v: u64) -> u16 {
    if v > u16::MAX as u64 {
        u16::MAX
    } else {
        v as u16
    }
}
