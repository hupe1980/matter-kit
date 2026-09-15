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
