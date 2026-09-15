//! Bulk Data Exchange (Core §11.22): moving a file between two nodes.
//!
//! Matter's messages are small — §4.4.4 caps a datagram at 1280 octets — and a firmware image
//! is not. BDX is how anything larger moves: a negotiation, then a run of numbered blocks, then
//! an acknowledgement that ends the session. It is what an OTA image travels over, what
//! `RetrieveLogsRequest` (§11.12) hands a diagnostic log to, and the reason
//! [`ImageUri`](crate::clusters::ota_provider::ImageUri) spells `bdx://`.
//!
//! The protocol "has some semantic elements influenced by the Trivial File Transfer Protocol
//! (TFTP) RFC 1350", with one large difference: BDX does not retransmit. §11.22.4 requires a
//! reliable transport underneath — MRP, BTP or TCP — so `BlockAck` and `BlockQuery` are
//! *flow control*, not reliability. That is what lets a battery-powered node pace a download
//! it could not otherwise stay awake for.
//!
//! # Four roles, two of which are the same question
//!
//! §11.22.2 names the ends twice over. **Sender** and **Receiver** say which way the data
//! goes; **Initiator** and **Responder** say who spoke first. A download — an OTA Requestor
//! fetching an image — is an Initiator that is the Receiver, so it opens with `ReceiveInit`;
//! an upload opens with `SendInit`. Either way, exactly one end is the **Driver**: it paces
//! the transfer, and the other follows. [`Sender`] and [`Receiver`] are this module's two
//! halves, and [`Parameters::control`] is what says which of them drives.
//!
//! # Errors are status codes, because that is what goes on the wire
//!
//! Everything that inspects a peer's message returns [`Rejected`], whose error is the
//! [`StatusCode`] of §11.22.3.2 — `BAD_BLOCK_COUNTER` for a block out of order,
//! `LENGTH_MISMATCH` for a transfer that ended short. [`report`] turns one into the
//! `StatusReport` to send, and §11.22.3.2 is clear about what happens next: "the receiving peer
//! SHALL terminate its processing of the transfer and invalidate the exchange." Encoding, which
//! can only fail locally, keeps the crate's ordinary [`Error`].
//!
//! # A download, end to end
//!
//! ```
//! use matter_kit::bdx::{
//!     Direction, Init, Limits, MessageType, Parameters, Receiver, Sender, negotiate,
//! };
//!
//! // The Requestor proposes: whole file, 256-octet blocks, either drive mode.
//! let mut proposal = Init::new(b"firmware.ota", 256);
//! proposal.definite_length = Some(600);
//!
//! // The Provider answers with what it will actually do.
//! let limits = Limits { available: Some(600), ..Limits::default() };
//! let agreed = negotiate(Direction::Download, &proposal, &limits)?;
//! assert!(agreed.sender_drives());          // §11.22.5.4.1 prefers it
//!
//! let accept = agreed.receive_accept(&[]);
//! let mut provider = Sender::new(agreed);
//! let mut requestor = Receiver::new(Parameters::from_receive_accept(&proposal, &accept)?);
//!
//! // 600 octets in blocks of 256: 256, 256, then an 88-octet BlockEOF.
//! for (len, eof) in [(256, false), (256, false), (88, true)] {
//!     let counter = provider.block(len, eof)?;
//!     requestor.on_block(counter, len, eof)?;
//!     let (opcode, counter) = requestor.ack()?;
//!     provider.on_ack(counter, opcode == MessageType::BlockAckEof)?;
//! }
//! assert!(provider.is_complete() && requestor.is_complete());
//! assert_eq!(requestor.received(), 600);
//! # Ok::<(), matter_kit::bdx::StatusCode>(())
//! ```

pub mod message;
pub mod transfer;

pub use message::{
    Block, BlockQueryWithSkip, Counter, Init, MessageType, ReceiveAccept, SendAccept,
    TransferControl, VERSION,
};
pub use transfer::{
    DEFAULT_MAX_BLOCK_SIZE, Direction, Limits, Parameters, Receiver, Sender, negotiate,
};

use crate::error::{Error, ErrorCode, Result};
use crate::msg::ProtocolId;
use crate::sc::status::{GeneralCode, StatusReport};

/// The result of anything that judges a peer's message: the failure is the status code the
/// peer must be told.
///
/// Not [`crate::Result`], and deliberately: §11.22.3.2's codes are the entire content of a BDX
/// failure, and folding them into a general error would throw away the only thing the caller
/// needs in order to answer.
pub type Rejected<T> = core::result::Result<T, StatusCode>;

/// §11.22.3.2's status codes, as they appear in a `StatusReport`'s ProtocolCode field.
///
/// Exhaustive: the specification closes the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StatusCode {
    /// "Definite length too large to support. For example, trying to SendInit with too large
    /// of a file."
    LengthTooLarge = 0x0012,
    /// "Definite length proposed for transfer is too short for the context based on the
    /// responder's knowledge of expected size."
    LengthTooShort = 0x0013,
    /// "Pre-negotiated size of transfer was not fulfilled prior to BlockAckEOF."
    LengthMismatch = 0x0014,
    /// "Responder can only support proposed transfer if definite length is provided."
    LengthRequired = 0x0015,
    /// "Received a malformed protocol message."
    BadMessageContents = 0x0016,
    /// "Received block counter out of order from expectation."
    BadBlockCounter = 0x0017,
    /// "Received a well-formed message that was contextually inappropriate for the current
    /// state of the transfer."
    UnexpectedMessage = 0x0018,
    /// "Responder is too busy to proceed with a new transfer at this moment." An Initiator
    /// "SHOULD wait at least 60 seconds" before trying again.
    ResponderBusy = 0x0019,
    /// "Other error occurred, such as perhaps an input/output error occurring at one of the
    /// peers."
    TransferFailedUnknownError = 0x001F,
    /// "Received a message that mismatches the current transfer mode."
    TransferMethodNotSupported = 0x0050,
    /// "Attempted to request a file whose designator is unknown to the responder."
    FileDesignatorUnknown = 0x0051,
    /// "Proposed transfer with explicit start offset is not supported in current context."
    StartOffsetNotSupported = 0x0052,
    /// "Could not find a common supported version between initiator and responder."
    VersionNotSupported = 0x0053,
    /// "Other unexpected error."
    Unknown = 0x005F,
}

impl StatusCode {
    /// The wire value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self as u16
    }

    /// Reads a ProtocolCode from a `StatusReport` that named the BDX protocol.
    ///
    /// An unrecognised code becomes [`Unknown`](Self::Unknown) rather than an error: §11.22.3.2
    /// says "any other unexpected StatusReport" ends the transfer just the same, so the one
    /// thing a caller must not do is keep going because it could not read the reason.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0012 => Self::LengthTooLarge,
            0x0013 => Self::LengthTooShort,
            0x0014 => Self::LengthMismatch,
            0x0015 => Self::LengthRequired,
            0x0016 => Self::BadMessageContents,
            0x0017 => Self::BadBlockCounter,
            0x0018 => Self::UnexpectedMessage,
            0x0019 => Self::ResponderBusy,
            0x001F => Self::TransferFailedUnknownError,
            0x0050 => Self::TransferMethodNotSupported,
            0x0051 => Self::FileDesignatorUnknown,
            0x0052 => Self::StartOffsetNotSupported,
            0x0053 => Self::VersionNotSupported,
            _ => Self::Unknown,
        }
    }
}

impl From<StatusCode> for Error {
    /// For a caller that has to hand a BDX failure back through the crate's own error type —
    /// the transfer is over either way.
    fn from(_: StatusCode) -> Self {
        Self::new(ErrorCode::BdxAborted)
    }
}

/// Writes the `StatusReport` that ends a transfer (§11.22.3.2).
///
/// "StatusReport(GeneralCode: FAILURE, ProtocolId: {VendorID=0x0000, ProtocolId=BDX},
/// ProtocolCode: `<value>`)" — sent on the same exchange, which is then invalidated.
pub fn report(status: StatusCode, buf: &mut [u8]) -> Result<&[u8]> {
    let written = StatusReport {
        general: GeneralCode::Failure,
        protocol: ProtocolId::BDX,
        protocol_code: status.value(),
        data: &[],
    }
    .encode(buf)?;
    buf.get(..written)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))
}

/// Reads a `StatusReport` that arrived on a BDX exchange.
///
/// Returns the reason the transfer ended, or [`None`] if the report is not a BDX failure — a
/// `SUCCESS` report, or one belonging to another protocol, neither of which ends the transfer.
pub fn read_report(payload: &[u8]) -> Result<Option<StatusCode>> {
    let report = StatusReport::decode(payload)?;
    if report.general == GeneralCode::Success || report.protocol != ProtocolId::BDX {
        return Ok(None);
    }
    Ok(Some(StatusCode::from_u16(report.protocol_code)))
}
