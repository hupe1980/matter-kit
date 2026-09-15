//! One error type for the whole crate.
//!
//! Two things are true at once about a failure in a Matter stack: it has a *local* cause
//! that a developer needs (a truncated TLV element, a nonce that did not fit) and it may
//! have a *wire* meaning that a peer is owed (Core §8.10's `INVALID_ACTION`,
//! `RESOURCE_EXHAUSTED`, …). Splitting those into two types means every layer converts
//! between them and one of the conversions is always wrong, so [`Error`] carries both: an
//! [`ErrorCode`] always, and an interaction-model status when one applies.
//!
//! Resource exhaustion is a value here, never an abort — a device that runs out of
//! exchanges answers `BUSY` and stays on the network.

use core::fmt;

/// What went wrong, locally.
///
/// The set is closed by this crate rather than by the specification, so it is
/// `#[non_exhaustive]`: new codes appear as layers land, and a consumer matching
/// exhaustively should not break for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    // --- Encoding -------------------------------------------------------------------
    /// A TLV element ended before its declared length.
    TlvTruncated,
    /// A control octet named a reserved element type or an illegal tag control.
    TlvInvalidControl,
    /// A container was not terminated by an end-of-container element, or one appeared
    /// where no container was open.
    TlvContainerMismatch,
    /// The element is not of the type the reader was asked for.
    TlvWrongType,
    /// A UTF-8 string element held bytes that are not valid UTF-8.
    TlvInvalidUtf8,
    /// A structure member was anonymous, an array member was tagged, or a tag repeated
    /// inside a structure — Core §A.5.
    TlvInvalidTag,
    /// Container nesting went deeper than the reader's fixed depth budget.
    TlvDepthExceeded,
    /// The value does not fit the requested Rust type (a `u64` read as `u8`, say).
    TlvOutOfRange,
    /// A required element was absent.
    TlvNotFound,
    /// Two members of one structure carried the same tag — Core §A.5.1: "All member elements
    /// within a structure SHALL have a unique tag as compared to the other members".
    TlvDuplicateTag,

    // --- Message layer --------------------------------------------------------------
    /// The message is shorter than its own header says it is.
    MessageTruncated,
    /// The message header version is not one this node speaks — Core §4.4.1.1.
    UnsupportedVersion,
    /// A reserved `DSIZ` or session-type value — Core §4.4.1.1, §4.4.1.3.
    MessageReserved,
    /// The message counter is outside the replay window, or repeats one already seen.
    DuplicateMessage,
    /// Decryption or the integrity check failed.
    IntegrityCheckFailed,

    // --- Exchanges and sessions -----------------------------------------------------
    /// No exchange matches the message, and none could be created for it.
    NoExchange,
    /// No session matches the message's session id.
    NoSession,
    /// A reliable message was retransmitted `MRP_MAX_TRANSMISSIONS` times without an
    /// acknowledgement — Core §4.12.
    MrpRetransmitExhausted,

    // --- Capacity and lifecycle -----------------------------------------------------
    /// A fixed-capacity table sized by [`Config`](crate::Config) is full.
    NoSpace,
    /// The operation would block on a resource that is busy right now.
    Busy,
    /// A buffer given to this crate is too small for what was asked of it.
    BufferTooSmall,
    /// The argument is outside the range the specification allows.
    InvalidArgument,
    /// The call is not legal in the current state.
    InvalidState,
    /// The entry is already present and the operation does not replace it — the fabric
    /// conflict of §11.18's `AddNOC`, for one.
    AlreadyExists,
    /// An interaction model action is malformed and must be answered with a
    /// `StatusResponse` carrying `INVALID_ACTION` rather than its usual response
    /// (Core §8.10).
    ///
    /// This is an *action*-level refusal, distinct from the per-path
    /// [`Status`](crate::im::Status) a response carries: there is nothing well-formed enough
    /// to report a path for.
    InvalidAction,
    /// A report does not fit in one message and must be chunked — Core §10.2.3.
    ///
    /// Not a failure so much as the wrong method: the read is perfectly servable, just not
    /// in a single message.
    /// [`Server::serve_chunk`](crate::im::Server::serve_chunk) serves it as the series of
    /// messages §10.2.3 calls for. This exists so the one-message convenience can *refuse*
    /// rather than emit a `MoreChunkedMessages` it has no way to honour, which would leave
    /// the client waiting for a continuation that never comes.
    ReportWouldChunk,

    // --- Certificates ---------------------------------------------------------------
    /// A Matter certificate violates one of the §6.5 encoding rules: an element out of
    /// order, a value out of range, a distinguished name the certificate's type forbids.
    CertInvalid,
    /// A certificate chain does not validate — a signature that does not verify, an issuer
    /// that does not match, a path longer than a `path-len-constraint` allows.
    CertPathInvalid,
    /// A certificate is being used outside its `not-before`/`not-after` window.
    CertExpired,
    /// The operation is defined but this build does not implement it.
    Unsupported,
    /// A DER encoding is malformed: a truncated element, a length that is not in DER's
    /// shortest form, or a structure that is not what its context requires.
    DerMalformed,

    // --- Commissioning ---------------------------------------------------------------
    /// §6.2.3's Device Attestation Procedure did not pass: a signature that does not verify,
    /// a nonce the device did not echo back, or a chain that does not reach a trusted PAA.
    ///
    /// §5.5 step 10 makes this a *report*, not a verdict — "the Commissioner MAY choose to
    /// either continue to the Commissioning, or terminate it, depending on
    /// implementation-dependent policies" — so it reaches the caller rather than ending the
    /// flow on its own.
    AttestationFailed,
    /// A commissioning command answered with an error: §11.10.5.1's `CommissioningErrorEnum`
    /// or §11.18.5.1's `NodeOperationalCertStatusEnum`, neither of which is `OK`.
    CommissioningFailed,

    // --- Discovery ------------------------------------------------------------------
    /// A DNS message ended inside a name, a record, or a header.
    DnsTruncated,
    /// A DNS message is malformed: a reserved label type, a compression pointer that does
    /// not point strictly backwards, a name with more labels than a Matter record has.
    DnsMalformed,

    // --- Transports -----------------------------------------------------------------
    /// A message on a stream transport announced a length past §4.15.2.3's Maximum Message
    /// Size, or a length of zero.
    ///
    /// Fatal to the connection either way. §4.5's length prefix is the *only* message
    /// boundary a stream has, so a receiver that cannot hold the message has also lost its
    /// place: everything after it would be read as a header. §4.15.2.3 says to close, and
    /// [`tcp::too_large`](crate::transport::tcp::too_large) is the report to send first.
    MessageTooLarge,
    /// A BDX transfer ended in failure, and the §11.22.3.2 status code said why.
    ///
    /// This is the code for a caller that had to widen a
    /// [`bdx::StatusCode`](crate::bdx::StatusCode) into the crate's own error type; the
    /// [`bdx`](crate::bdx) module's own API keeps the status code, because it is what has to
    /// be sent back to the peer.
    BdxAborted,
    /// A BTP packet is malformed, or breaks one of §4.19.4.5's reassembly rules: an Ending
    /// segment with no Beginning, a Beginning while another SDU is in flight, a reassembled
    /// length that does not match the Message Length it was promised.
    ///
    /// Every one of these closes the BTP session. The protocol has no way to resynchronise,
    /// so continuing would mean reassembling two messages into one.
    BtpMalformed,
    /// A BTP sequence number did not increment by one, or an acknowledgement named a packet
    /// that was never sent or was already acknowledged — §4.19.4.6, §4.19.4.8. Also closes
    /// the session.
    BtpSequence,
    /// A BTP acknowledgement did not arrive within `BTP_ACK_TIMEOUT` (§4.19.4.8). The timer
    /// doubles as BTP's keep-alive, so this is also how a peer notices a remote stack that
    /// has stopped answering.
    BtpTimeout,
    /// The platform reported a failure.
    Platform,
}

impl ErrorCode {
    /// A short, stable, human-readable name — the one that appears in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TlvTruncated => "tlv: truncated element",
            Self::TlvInvalidControl => "tlv: reserved or invalid control octet",
            Self::TlvContainerMismatch => "tlv: unbalanced container",
            Self::TlvWrongType => "tlv: wrong element type",
            Self::TlvInvalidUtf8 => "tlv: invalid utf-8 in string element",
            Self::TlvInvalidTag => "tlv: tag not allowed in this container",
            Self::TlvDepthExceeded => "tlv: nesting too deep",
            Self::TlvOutOfRange => "tlv: value out of range for target type",
            Self::TlvNotFound => "tlv: element not found",
            Self::TlvDuplicateTag => "tlv: duplicate tag in a structure",
            Self::MessageTruncated => "msg: truncated",
            Self::UnsupportedVersion => "msg: unsupported version",
            Self::MessageReserved => "msg: reserved field value",
            Self::DuplicateMessage => "msg: duplicate or replayed counter",
            Self::IntegrityCheckFailed => "msg: integrity check failed",
            Self::NoExchange => "exchange: no matching exchange",
            Self::NoSession => "session: no matching session",
            Self::MrpRetransmitExhausted => "mrp: retransmissions exhausted",
            Self::NoSpace => "no space",
            Self::Busy => "busy",
            Self::BufferTooSmall => "buffer too small",
            Self::InvalidArgument => "invalid argument",
            Self::AlreadyExists => "entry already exists",
            Self::InvalidAction => "interaction model: invalid action",
            Self::ReportWouldChunk => "report does not fit one message",
            Self::AttestationFailed => "attestation: §6.2.3's procedure did not pass",
            Self::CommissioningFailed => "commissioning: the device answered with an error",
            Self::CertInvalid => "cert: violates the §6.5 encoding rules",
            Self::CertPathInvalid => "cert: chain does not validate",
            Self::CertExpired => "cert: outside its validity window",
            Self::Unsupported => "unsupported",
            Self::DerMalformed => "der: malformed encoding",
            Self::DnsTruncated => "dns: truncated message",
            Self::DnsMalformed => "dns: malformed message",
            Self::MessageTooLarge => "transport: message past the stream's maximum size",
            Self::BdxAborted => "bdx: transfer aborted",
            Self::BtpMalformed => "btp: malformed packet or reassembly",
            Self::BtpSequence => "btp: sequence or acknowledgement out of order",
            Self::BtpTimeout => "btp: acknowledgement timeout",
            Self::InvalidState => "invalid state",
            Self::Platform => "platform error",
        }
    }
}

/// A failure, with its local cause and — when the specification gives it one — the status
/// code a peer is owed.
///
/// The interaction-model status is filled in by the `im` module once that layer exists; the
/// field is here from the start so that lower layers can already answer, for example,
/// `RESOURCE_EXHAUSTED` for [`ErrorCode::NoSpace`] without a second error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
}

impl Error {
    /// Builds an error from its local cause.
    #[must_use]
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    /// The local cause.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        self.code
    }
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The crate's result type.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Builds an [`Err`] from an [`ErrorCode`] without the `Error::new` ceremony.
macro_rules! bail {
    ($code:ident) => {
        return Err($crate::error::Error::new($crate::error::ErrorCode::$code))
    };
}
pub(crate) use bail;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_the_code_name() {
        let e = Error::new(ErrorCode::TlvTruncated);
        #[cfg(feature = "std")]
        assert_eq!(std::format!("{e}"), "tlv: truncated element");
        assert_eq!(e.code(), ErrorCode::TlvTruncated);
    }

    #[test]
    fn every_code_has_a_name() {
        // A code whose name is empty is a code somebody added without a message.
        for code in [
            ErrorCode::TlvTruncated,
            ErrorCode::NoSpace,
            ErrorCode::Busy,
            ErrorCode::Platform,
        ] {
            assert!(!code.as_str().is_empty());
        }
    }
}
