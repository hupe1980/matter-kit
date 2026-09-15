//! Matter over Wi-Fi Public Action Frames: PAFTP (Core §4.20).
//!
//! > The Public Action Frame Transport Protocol (PAFTP) is akin to BTP. PAFTP is used when
//! > commissioning over Wi-Fi Public Action Frame while BTP is used when commissioning over
//! > Bluetooth.
//!
//! "Akin" understates it. §4.20.2: "The PAFTP frame format is identical to BTP frame format",
//! and §4.20.3.5 through §4.20.3.10 — segmentation, sequence numbers, receive windows,
//! acknowledgements, the idle timeout — are BTP's rules with the word BTP replaced. So this
//! module is a *handshake*, and everything after it is [`btp`](super::btp)'s
//! [`Session`], unchanged.
//!
//! # What actually differs
//!
//! One field, and what it means. BTP negotiates an **ATT_MTU** — a GATT PDU size, from which
//! three octets of GATT header are subtracted. PAFTP negotiates a **Supported Maximum Service
//! Specific Info Length**: the room inside a WFA-USD Service Discovery Frame Follow-up message,
//! with no header of its own to subtract. Its default is 350 rather than BLE's 23, which is why
//! a PAFTP segment is several times a BTP one.
//!
//! §4.20.4's three timeouts are BTP's three timeouts, to the second, so they are not restated
//! here — [`btp`](super::btp)'s are the same constants.
//!
//! # Why this is behind a feature
//!
//! Wi-Fi Aware USD is not something a device has by accident: it needs a chipset that can send
//! and receive Public Action Frames outside an association. `paf` gates the module rather than
//! the protocol, so a device that cannot do it does not carry the code.

use crate::bytes::Cursor;
use crate::error::{ErrorCode, Result, bail};

pub use super::btp::{
    ACK_TIMEOUT, CONN_IDLE_TIMEOUT, CONN_RSP_TIMEOUT, Frame, HANDSHAKE_FLAGS, MAX_WINDOW,
    OPCODE_HANDSHAKE, Received, Role, Session, SessionParams,
};

/// §4.20.3.1: "4 — PAFTP as defined by Matter v1.5".
pub const VERSION: u8 = 4;

/// §4.20.3.1's fallback: "If PAFTP is not aware of the Supported Maximum Service Specific Info
/// Length, the value SHALL be set to '350'."
pub const DEFAULT_SSI_LENGTH: u16 = 350;

/// The PAFTP header at its largest: flags, sequence, an ack number and a message length.
///
/// A segment is what is left of the Service Specific Info once this is taken out, which is the
/// one arithmetic PAFTP does that BTP does not do the same way — BTP subtracts a *GATT* header
/// that PAFTP has no equivalent of.
pub const HEADER_MAX: u16 = 5;

/// §4.20.3.1's PAFTP Handshake Request.
///
/// Byte for byte the shape of BTP's, and deliberately not a re-export of it: the 16-bit field
/// means something else, and a type that let the two be confused would let a caller negotiate a
/// 350-octet segment over a 23-octet BLE connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRequest {
    /// The versions offered, "listed once each, newest first, in descending order".
    pub versions: [u8; 8],
    /// "the maximum size of the service information that can be transmitted and received by the
    /// sender in Service Specific Info field".
    pub ssi_length: u16,
    /// "the maximum receive window size supported by the Commissioner".
    pub window: u8,
}

impl HandshakeRequest {
    /// How many octets it occupies: flags, opcode, four version octets, length, window.
    pub const LEN: usize = 9;

    /// A request offering only [`VERSION`].
    #[must_use]
    pub const fn new(ssi_length: u16, window: u8) -> Self {
        let mut versions = [0u8; 8];
        versions[0] = VERSION;
        Self {
            versions,
            ssi_length,
            window,
        }
    }

    /// Writes the request, returning how many octets it took.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Cursor::writer(out);
        w.u8(HANDSHAKE_FLAGS)?;
        w.u8(OPCODE_HANDSHAKE)?;
        // Eight version *nibbles* packed into four octets, low nibble first.
        for &[low, high] in self.versions.as_chunks::<2>().0 {
            w.u8((low & 0x0F) | ((high & 0x0F) << 4))?;
        }
        w.u16(self.ssi_length)?;
        w.u8(self.window)?;
        Ok(w.position())
    }

    /// Reads a request.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Cursor::reader(buf, ErrorCode::BtpMalformed);
        if r.read_u8()? != HANDSHAKE_FLAGS || r.read_u8()? != OPCODE_HANDSHAKE {
            bail!(BtpMalformed)
        }
        let mut versions = [0u8; 8];
        for [low, high] in versions.as_chunks_mut::<2>().0 {
            let octet = r.read_u8()?;
            *low = octet & 0x0F;
            *high = octet >> 4;
        }
        Ok(Self {
            versions,
            ssi_length: r.read_u16()?,
            window: r.read_u8()?,
        })
    }

    /// The newest offered version this crate also speaks, or `None` if there is none.
    #[must_use]
    pub fn best_version(&self) -> Option<u8> {
        self.versions
            .iter()
            .copied()
            .find(|&v| v != 0 && v <= VERSION)
    }
}

/// §4.20.3.2's PAFTP Handshake Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// "the PAFTP protocol version selected by the Commissionable Device".
    pub version: u8,
    /// The Selected Maximum Service Specific Info Length.
    pub ssi_length: u16,
    /// "the maximum receive window size supported by the Commissionable Device".
    pub window: u8,
}

impl HandshakeResponse {
    /// How many octets it occupies.
    pub const LEN: usize = 6;

    /// Writes the response, returning how many octets it took.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Cursor::writer(out);
        w.u8(HANDSHAKE_FLAGS)?;
        w.u8(OPCODE_HANDSHAKE)?;
        // "Final Protocol Version" in the low nibble; "Reserved … Must be set to '0'".
        w.u8(self.version & 0x0F)?;
        w.u16(self.ssi_length)?;
        w.u8(self.window)?;
        Ok(w.position())
    }

    /// Reads a response.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Cursor::reader(buf, ErrorCode::BtpMalformed);
        if r.read_u8()? != HANDSHAKE_FLAGS || r.read_u8()? != OPCODE_HANDSHAKE {
            bail!(BtpMalformed)
        }
        Ok(Self {
            version: r.read_u8()? & 0x0F,
            ssi_length: r.read_u16()?,
            window: r.read_u8()?,
        })
    }

    /// What a [`Session`] needs from this handshake.
    #[must_use]
    pub const fn params(&self) -> SessionParams {
        SessionParams {
            segment_size: self.segment_size(),
            window: self.window,
        }
    }

    /// The segment payload size: the Service Specific Info length less the PAFTP header.
    ///
    /// §4.20.3.1: the window is "specified in units of PAFTP packets where each packet length
    /// may be up to Supported Maximum Service Specific Info Length bytes minus PAFTP header".
    #[must_use]
    pub const fn segment_size(&self) -> usize {
        let length = if self.ssi_length == 0 {
            DEFAULT_SSI_LENGTH
        } else {
            self.ssi_length
        };
        length.saturating_sub(HEADER_MAX) as usize
    }
}

/// What a Commissionable Device answers a handshake request with (§4.20.3.3).
///
/// > The Commissionable Device SHALL select a window size equal to the minimum of its and the
/// > Commissioner's maximum window sizes. Likewise, the Commissionable Device SHALL select a
/// > maximum PAFTP Segment Size … by taking the minimum of Supported Maximum Service Specific
/// > Info Length received in PAFTP Handshake Request and locally Supported Maximum Service
/// > Specific Info Length.
///
/// Two minima, the same as BTP's, and for the same reason: echoing the commissioner's numbers
/// back unchecked would have a device promise a window and a frame size its own radio cannot
/// hold.
pub fn negotiate(
    request: &HandshakeRequest,
    own_ssi_length: u16,
    own_window: u8,
) -> Result<HandshakeResponse> {
    let Some(version) = request.best_version() else {
        // §4.20.3.3: "If the Commissionable Device determines that it and the Commissioner do
        // not share a supported PAFTP protocol version, the Commissionable Device SHALL close
        // its WFA-USD connection to the Commissioner."
        bail!(UnsupportedVersion)
    };
    let own = if own_ssi_length == 0 {
        DEFAULT_SSI_LENGTH
    } else {
        own_ssi_length
    };
    let requested = if request.ssi_length == 0 {
        own
    } else {
        request.ssi_length.min(own)
    };
    let window = request.window.min(own_window);
    if window == 0 {
        // A window of zero is a session that can never send: §4.20.3.7's window is what admits
        // a packet at all.
        bail!(InvalidArgument)
    }
    Ok(HandshakeResponse {
        version,
        ssi_length: requested.max(HEADER_MAX.saturating_add(1)),
        window,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_handshake_is_btps_shape_with_a_different_middle() {
        // §4.20.3.1's Table 40: flags 0x65, opcode 0x6C, four version octets, then the 16-bit
        // length and the window. Version nibbles are packed low-first, so offering only
        // version 4 puts 0x04 in the first version octet and nothing after it.
        let request = HandshakeRequest::new(DEFAULT_SSI_LENGTH, 4);
        let mut buf = [0u8; 16];
        let n = request.encode(&mut buf).expect("encode");
        assert_eq!(n, HandshakeRequest::LEN);
        assert_eq!(
            &buf[..n],
            &[0x65, 0x6C, 0x04, 0x00, 0x00, 0x00, 0x5E, 0x01, 0x04]
        );
        assert_eq!(
            HandshakeRequest::decode(&buf[..n]).expect("decode"),
            request
        );
    }

    #[test]
    fn a_response_round_trips() {
        let response = HandshakeResponse {
            version: VERSION,
            ssi_length: 350,
            window: 4,
        };
        let mut buf = [0u8; 16];
        let n = response.encode(&mut buf).expect("encode");
        assert_eq!(n, HandshakeResponse::LEN);
        assert_eq!(&buf[..n], &[0x65, 0x6C, 0x04, 0x5E, 0x01, 0x04]);
        assert_eq!(
            HandshakeResponse::decode(&buf[..n]).expect("decode"),
            response
        );
    }

    #[test]
    fn the_segment_is_the_frame_less_the_paftp_header() {
        // Not `- 3`: that is BTP's GATT header, which PAFTP has no equivalent of. A module that
        // reused BTP's arithmetic would understate every PAFTP segment by two octets and
        // overstate it by nothing — a silent loss of throughput nobody would trace here.
        let response = HandshakeResponse {
            version: VERSION,
            ssi_length: 350,
            window: 4,
        };
        assert_eq!(response.segment_size(), 345);
        assert_eq!(response.params().window, 4);

        // §4.20.3.1's fallback applies to a zero as well.
        let unknown = HandshakeResponse {
            ssi_length: 0,
            ..response
        };
        assert_eq!(unknown.segment_size(), 345);
    }

    #[test]
    fn negotiation_takes_both_minima() {
        let request = HandshakeRequest::new(350, 6);
        let response = negotiate(&request, 256, 4).expect("negotiate");
        assert_eq!(response.ssi_length, 256, "the smaller frame");
        assert_eq!(response.window, 4, "the smaller window");
        assert_eq!(response.version, VERSION);
    }

    #[test]
    fn a_version_nobody_shares_closes_the_connection() {
        let mut request = HandshakeRequest::new(350, 4);
        request.versions = [9, 8, 0, 0, 0, 0, 0, 0];
        assert!(negotiate(&request, 350, 4).is_err());
    }
}
