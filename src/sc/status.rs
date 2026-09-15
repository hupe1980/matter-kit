//! The StatusReport message (Core §4.11.1.2, Appendix D).
//!
//! One message format that every protocol uses to say how an operation went. It is *not*
//! TLV — it is eight fixed octets and an optional tail — which is why it can be parsed
//! before anything knows which protocol is speaking.
//!
//! ```text
//! ┌────────────────┬──────────────────────────┬────────────────┬──────────────┐
//! │ GeneralCode(2) │ ProtocolId(4)            │ ProtocolCode(2)│ ProtocolData │
//! └────────────────┴──────────────────────────┴────────────────┴──────────────┘
//! ```
//!
//! All three scalars are little-endian, and the `ProtocolId` is "a 32 bit value of Protocol
//! Vendor ID (upper 16 bits) and Protocol ID under that Protocol Vendor ID (lower 16
//! bits)".

use crate::error::{Error, ErrorCode, Result, bail};
use crate::msg::{ProtocolId, VendorId};

/// The uniform status codes of Appendix D.3.1.
///
/// Exhaustive on purpose: the **specification** closes this set, so a `match` on it should
/// be checked for completeness when a future revision adds one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum GeneralCode {
    /// Operation completed successfully.
    Success = 0,
    /// Generic failure; the protocol-specific code says more.
    Failure = 1,
    /// "Operation was rejected by the system because the system is in an invalid state."
    BadPrecondition = 2,
    /// A value was out of a required range.
    OutOfRange = 3,
    /// A request was unrecognized or malformed.
    BadRequest = 4,
    /// An unrecognized or unsupported request was received.
    Unsupported = 5,
    /// A request was not expected at this time.
    Unexpected = 6,
    /// Insufficient resources to process the given request.
    ResourceExhausted = 7,
    /// Device is busy and cannot handle this request at this time.
    Busy = 8,
    /// A timeout occurred.
    Timeout = 9,
    /// Context-specific signal to proceed.
    Continue = 10,
    /// Failure, may be due to a concurrency error.
    Aborted = 11,
    /// An invalid or unsupported argument was provided.
    InvalidArgument = 12,
    /// Some requested entity was not found.
    NotFound = 13,
    /// The sender attempted to create something that already exists.
    AlreadyExists = 14,
    /// The sender does not have sufficient permissions.
    PermissionDenied = 15,
    /// Unrecoverable data loss or corruption has occurred.
    DataLoss = 16,
    /// "Message size is larger than the recipient can handle" — what a node answers when a
    /// peer announces a message above its Maximum Message Size (§4.15.2.3).
    MessageTooLarge = 17,
}

impl GeneralCode {
    /// Decodes the wire value.
    pub const fn from_u16(value: u16) -> Result<Self> {
        Ok(match value {
            0 => Self::Success,
            1 => Self::Failure,
            2 => Self::BadPrecondition,
            3 => Self::OutOfRange,
            4 => Self::BadRequest,
            5 => Self::Unsupported,
            6 => Self::Unexpected,
            7 => Self::ResourceExhausted,
            8 => Self::Busy,
            9 => Self::Timeout,
            10 => Self::Continue,
            11 => Self::Aborted,
            12 => Self::InvalidArgument,
            13 => Self::NotFound,
            14 => Self::AlreadyExists,
            15 => Self::PermissionDenied,
            16 => Self::DataLoss,
            17 => Self::MessageTooLarge,
            _ => return Err(Error::new(ErrorCode::MessageReserved)),
        })
    }

    /// Whether this code reports success.
    ///
    /// `Continue` counts: Appendix D.3.2 groups it with `Success` as the two codes for
    /// which `ProtocolCode` 0 is a placeholder rather than a real code.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success | Self::Continue)
    }
}

/// The Secure Channel protocol-specific codes of Core Table 19.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SecureChannelCode {
    /// "Indication that the last session establishment message was successfully processed."
    SessionEstablishmentSuccess = 0x0000,
    /// Failure to find a common set of shared roots.
    NoSharedTrustRoots = 0x0001,
    /// "Generic failure during session establishment."
    InvalidParameter = 0x0002,
    /// "Indication that the sender will close the current session."
    CloseSession = 0x0003,
    /// "Indication that the sender cannot currently fulfill the request", carrying a
    /// minimum wait time in its protocol data (§4.11.1.5).
    Busy = 0x0004,
}

impl SecureChannelCode {
    /// The general code the specification pairs this one with (Table 19).
    ///
    /// Pairing them here rather than at each call site is what stops a `SUCCESS` status
    /// from carrying a failure code, which a peer would read as success.
    #[must_use]
    pub const fn general(self) -> GeneralCode {
        match self {
            Self::SessionEstablishmentSuccess | Self::CloseSession => GeneralCode::Success,
            Self::NoSharedTrustRoots | Self::InvalidParameter => GeneralCode::Failure,
            Self::Busy => GeneralCode::Busy,
        }
    }

    /// Whether the specification requires this status to be sent inside a secure session.
    #[must_use]
    pub const fn requires_encryption(self) -> bool {
        // Table 19's "Encrypted" column: only CloseSession is Y — the others are what a
        // node says *before* a session exists.
        matches!(self, Self::CloseSession)
    }
}

/// A StatusReport message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReport<'a> {
    /// The uniform code.
    pub general: GeneralCode,
    /// Which protocol's code space `protocol_code` is in.
    pub protocol: ProtocolId,
    /// The protocol-specific code.
    pub protocol_code: u16,
    /// "all data beyond the ProtocolCode field", whose meaning depends on the protocol.
    pub data: &'a [u8],
}

/// "ProtocolCode value 0xFFFF SHALL be reserved to indicate that no additional
/// protocol-specific status code is available."
pub const NO_PROTOCOL_CODE: u16 = 0xFFFF;

impl<'a> StatusReport<'a> {
    /// The fixed part: two, four and two octets.
    pub const HEADER_LEN: usize = 8;

    /// Builds a Secure Channel status report, taking the general code from Table 19.
    #[must_use]
    pub const fn secure_channel(code: SecureChannelCode) -> Self {
        Self {
            general: code.general(),
            protocol: ProtocolId::SECURE_CHANNEL,
            protocol_code: code as u16,
            data: &[],
        }
    }

    /// Whether this reports success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.general.is_success()
    }

    /// The Secure Channel code, when this is a Secure Channel report.
    #[must_use]
    pub fn secure_channel_code(&self) -> Option<SecureChannelCode> {
        if self.protocol != ProtocolId::SECURE_CHANNEL {
            return None;
        }
        Some(match self.protocol_code {
            0x0000 => SecureChannelCode::SessionEstablishmentSuccess,
            0x0001 => SecureChannelCode::NoSharedTrustRoots,
            0x0002 => SecureChannelCode::InvalidParameter,
            0x0003 => SecureChannelCode::CloseSession,
            0x0004 => SecureChannelCode::Busy,
            _ => return None,
        })
    }

    /// How many octets this encodes to.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        Self::HEADER_LEN.saturating_add(self.data.len())
    }

    /// Writes the message into `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let total = self.encoded_len();
        let Some(dst) = out.get_mut(..total) else {
            bail!(BufferTooSmall)
        };
        let Some(general) = dst.get_mut(..2) else {
            bail!(BufferTooSmall)
        };
        general.copy_from_slice(&(self.general as u16).to_le_bytes());

        // ProtocolId: vendor in the upper 16 bits, protocol in the lower.
        let qualified = (u32::from(self.protocol.vendor.0) << 16) | u32::from(self.protocol.id);
        let Some(slot) = dst.get_mut(2..6) else {
            bail!(BufferTooSmall)
        };
        slot.copy_from_slice(&qualified.to_le_bytes());

        let Some(slot) = dst.get_mut(6..8) else {
            bail!(BufferTooSmall)
        };
        slot.copy_from_slice(&self.protocol_code.to_le_bytes());

        let Some(slot) = dst.get_mut(8..) else {
            bail!(BufferTooSmall)
        };
        slot.copy_from_slice(self.data);
        Ok(total)
    }

    /// Reads a message from `buf`.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let (Some(general), Some(protocol), Some(code), Some(data)) =
            (buf.get(..2), buf.get(2..6), buf.get(6..8), buf.get(8..))
        else {
            bail!(MessageTruncated)
        };
        let (Ok(general), Ok(protocol), Ok(code)) = (
            <[u8; 2]>::try_from(general),
            <[u8; 4]>::try_from(protocol),
            <[u8; 2]>::try_from(code),
        ) else {
            bail!(MessageTruncated)
        };
        let qualified = u32::from_le_bytes(protocol);
        Ok(Self {
            general: GeneralCode::from_u16(u16::from_le_bytes(general))?,
            protocol: ProtocolId {
                vendor: VendorId((qualified >> 16) as u16),
                id: qualified as u16,
            },
            protocol_code: u16::from_le_bytes(code),
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_specs_worked_example_encodes_exactly() {
        // Appendix D.4: StatusReport(GeneralCode: FAILURE, ProtocolId: BDX, ProtocolCode:
        // START_OFFSET_NOT_SUPPORTED) "Encodes as: 01 00 02 00 00 00 52 00".
        let report = StatusReport {
            general: GeneralCode::Failure,
            protocol: ProtocolId::BDX,
            protocol_code: 0x0052,
            data: &[],
        };
        let mut buf = [0u8; 16];
        let n = report.encode(&mut buf).expect("encode");
        assert_eq!(&buf[..n], &[0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x52, 0x00]);
        assert_eq!(StatusReport::decode(&buf[..n]).expect("decode"), report);
    }

    #[test]
    fn a_vendor_protocol_id_keeps_its_vendor() {
        let report = StatusReport {
            general: GeneralCode::Failure,
            protocol: ProtocolId {
                vendor: VendorId(0xFFF1),
                id: 0x0042,
            },
            protocol_code: 7,
            data: &[],
        };
        let mut buf = [0u8; 16];
        let n = report.encode(&mut buf).expect("encode");
        // The 32-bit value is 0xFFF1_0042, little-endian.
        assert_eq!(&buf[2..6], &[0x42, 0x00, 0xF1, 0xFF]);
        assert_eq!(StatusReport::decode(&buf[..n]).expect("decode"), report);
    }

    #[test]
    fn pake_finished_is_a_success_report() {
        // §4.14.1's PakeFinished: SUCCESS / SECURE_CHANNEL / SESSION_ESTABLISHMENT_SUCCESS.
        let report = StatusReport::secure_channel(SecureChannelCode::SessionEstablishmentSuccess);
        assert_eq!(report.general, GeneralCode::Success);
        assert!(report.is_success());
        assert_eq!(
            report.secure_channel_code(),
            Some(SecureChannelCode::SessionEstablishmentSuccess)
        );

        let mut buf = [0u8; 16];
        let n = report.encode(&mut buf).expect("encode");
        assert_eq!(&buf[..n], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn each_secure_channel_code_carries_the_general_code_table_19_pairs_it_with() {
        // A SUCCESS status carrying a failure code would be read as success.
        assert_eq!(
            SecureChannelCode::SessionEstablishmentSuccess.general(),
            GeneralCode::Success
        );
        assert_eq!(
            SecureChannelCode::InvalidParameter.general(),
            GeneralCode::Failure
        );
        assert_eq!(
            SecureChannelCode::NoSharedTrustRoots.general(),
            GeneralCode::Failure
        );
        assert_eq!(
            SecureChannelCode::CloseSession.general(),
            GeneralCode::Success
        );
        assert_eq!(SecureChannelCode::Busy.general(), GeneralCode::Busy);
    }

    #[test]
    fn only_close_session_must_be_encrypted() {
        assert!(SecureChannelCode::CloseSession.requires_encryption());
        for code in [
            SecureChannelCode::SessionEstablishmentSuccess,
            SecureChannelCode::NoSharedTrustRoots,
            SecureChannelCode::InvalidParameter,
            SecureChannelCode::Busy,
        ] {
            assert!(
                !code.requires_encryption(),
                "{code:?} is sent before a session exists"
            );
        }
    }

    #[test]
    fn protocol_data_round_trips() {
        let report = StatusReport {
            general: GeneralCode::Busy,
            protocol: ProtocolId::SECURE_CHANNEL,
            protocol_code: SecureChannelCode::Busy as u16,
            // §4.11.1.5's minimum wait time.
            data: &[0xF4, 0x01],
        };
        let mut buf = [0u8; 16];
        let n = report.encode(&mut buf).expect("encode");
        assert_eq!(n, 10);
        let decoded = StatusReport::decode(&buf[..n]).expect("decode");
        assert_eq!(decoded.data, &[0xF4, 0x01]);
    }

    #[test]
    fn a_reserved_general_code_is_refused() {
        let buf = [0xFF, 0x00, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            StatusReport::decode(&buf).unwrap_err().code(),
            ErrorCode::MessageReserved
        );
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let buf = [0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x52, 0x00];
        for cut in 0..buf.len() {
            assert!(StatusReport::decode(&buf[..cut]).is_err(), "cut {cut}");
        }
        assert!(StatusReport::decode(&buf).is_ok());
    }

    #[test]
    fn a_too_small_buffer_is_an_error() {
        let report = StatusReport::secure_channel(SecureChannelCode::InvalidParameter);
        let mut buf = [0u8; 7];
        assert_eq!(
            report.encode(&mut buf).unwrap_err().code(),
            ErrorCode::BufferTooSmall
        );
    }

    #[test]
    fn general_codes_round_trip_through_their_numbers() {
        for (value, code) in [
            (0u16, GeneralCode::Success),
            (1, GeneralCode::Failure),
            (8, GeneralCode::Busy),
            (10, GeneralCode::Continue),
            (17, GeneralCode::MessageTooLarge),
        ] {
            assert_eq!(GeneralCode::from_u16(value).expect("known"), code);
            assert_eq!(code as u16, value);
        }
        assert!(GeneralCode::from_u16(18).is_err());
    }

    #[test]
    fn continue_counts_as_success() {
        assert!(GeneralCode::Continue.is_success());
        assert!(GeneralCode::Success.is_success());
        assert!(!GeneralCode::Failure.is_success());
        assert!(!GeneralCode::Busy.is_success());
    }
}
