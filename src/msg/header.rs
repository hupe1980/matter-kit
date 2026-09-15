//! The Matter message frame (Core §4.4).
//!
//! Two headers, one inside the other. The **message header** is what the message layer
//! reads — session, counter, who it is from and to — and it is outside the encryption, so
//! a receiver can find the key before it can decrypt anything. The **protocol header** is
//! the first thing *inside* the encrypted payload: which exchange, which protocol, which
//! opcode, and what is being acknowledged.
//!
//! ```text
//! ┌── message header ─────────────────────────┐┌── payload (encrypted) ──┐┌ footer ┐
//! │ flags │ session │ sec │ counter │ src │ dst││ protocol header │ app   ││  MIC   │
//! └───────────────────────────────────────────┘└─────────────────────────┘└────────┘
//! ```
//!
//! "All multi-byte integer fields are transmitted in little-endian byte order unless
//! otherwise noted" (§4.4).

use bitflags::bitflags;

use super::ids::{ExchangeId, GroupId, NodeId, ProtocolId, SessionId, VendorId};
use crate::error::{Error, ErrorCode, Result, bail};

/// The Matter message format version this crate speaks (§4.4.1.1).
///
/// "0 — Matter Message Format version 1.0". Everything else is reserved, and a message
/// carrying one "SHALL be dropped without sending a message-layer acknowledgement".
pub const MESSAGE_FORMAT_VERSION: u8 = 0;

bitflags! {
    /// The Message Flags octet (§4.4.1.1).
    ///
    /// Bits 4–7 are the version, bit 2 the source-present flag, bits 0–1 the `DSIZ` field.
    /// Bit 3 is unused: "All unused bits … are reserved and SHALL be set to zero on
    /// transmission and SHALL be silently ignored on reception."
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MessageFlags: u8 {
        /// The Source Node ID field is present.
        const SOURCE_PRESENT = 0b0000_0100;
        /// `DSIZ` bit 0.
        const DSIZ_0 = 0b0000_0001;
        /// `DSIZ` bit 1.
        const DSIZ_1 = 0b0000_0010;
        /// The version field.
        const VERSION = 0b1111_0000;
    }
}

bitflags! {
    /// The Security Flags octet (§4.4.1.3).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SecurityFlags: u8 {
        /// Privacy: the message is encoded with the privacy enhancements of §4.9.3.
        const PRIVACY = 0b1000_0000;
        /// Control message: uses the control message counter for its nonce (§4.8.1.1).
        const CONTROL = 0b0100_0000;
        /// Message Extensions present. "Version 1.0 Nodes SHALL set this flag to zero."
        const MESSAGE_EXTENSIONS = 0b0010_0000;
        /// Session type bit 0.
        const SESSION_TYPE_0 = 0b0000_0001;
        /// Session type bit 1.
        const SESSION_TYPE_1 = 0b0000_0010;
    }
}

bitflags! {
    /// The Exchange Flags octet (§4.4.3.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ExchangeFlags: u8 {
        /// **I** — the message was sent by the initiator of the exchange.
        const INITIATOR = 0b0000_0001;
        /// **A** — the message acknowledges an earlier one; the Acknowledged Message
        /// Counter field is present.
        const ACKNOWLEDGEMENT = 0b0000_0010;
        /// **R** — the sender wants an acknowledgement (MRP, §4.12).
        const RELIABILITY = 0b0000_0100;
        /// **SX** — Secured Extensions present. "Version 1.0 Nodes SHALL set this flag to
        /// zero."
        const SECURED_EXTENSIONS = 0b0000_1000;
        /// **V** — the Protocol Vendor ID field is present.
        const VENDOR = 0b0001_0000;
    }
}

/// The kind of session a message belongs to (§4.4.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SessionType {
    /// A one-to-one session. With session id 0 this is the *unsecured* session, which
    /// "SHALL have no encryption, privacy, or message integrity checking".
    #[default]
    Unicast,
    /// A group session, addressed by Group ID.
    Group,
}

impl SessionType {
    const fn bits(self) -> u8 {
        match self {
            Self::Unicast => 0,
            Self::Group => 1,
        }
    }

    const fn from_bits(bits: u8) -> Result<Self> {
        match bits & 0b11 {
            0 => Ok(Self::Unicast),
            1 => Ok(Self::Group),
            // "Messages with Session Type set to reserved values are not valid and SHALL
            // be dropped without sending a message-layer acknowledgement."
            _ => Err(Error::new(ErrorCode::MessageReserved)),
        }
    }
}

/// The Destination Node ID field, whose size and meaning the `DSIZ` field sets
/// (§4.4.1.1, §4.4.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Destination {
    /// `DSIZ` 0 — the field is absent.
    #[default]
    None,
    /// `DSIZ` 1 — a 64-bit Node ID.
    Node(NodeId),
    /// `DSIZ` 2 — a 16-bit Group ID.
    Group(GroupId),
}

impl Destination {
    const fn dsiz(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Node(_) => 1,
            Self::Group(_) => 2,
        }
    }

    const fn encoded_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Node(_) => 8,
            Self::Group(_) => 2,
        }
    }
}

/// The unencrypted header every Matter message starts with (§4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    /// Which session — and so which key — this message belongs to.
    pub session_id: SessionId,
    /// Unicast or group.
    pub session_type: SessionType,
    /// Whether privacy processing (§4.9) was applied.
    pub privacy: bool,
    /// Whether this is a control message, which counts on its own counter (§4.8.1.1).
    pub control: bool,
    /// The sender's monotonically increasing counter for this key (§4.4.1.4).
    pub message_counter: u32,
    /// The sender, when it chose to say (§4.4.1.5).
    pub source: Option<NodeId>,
    /// The recipient (§4.4.1.6).
    pub destination: Destination,
}

impl Default for MessageHeader {
    fn default() -> Self {
        Self {
            session_id: SessionId::UNSECURED,
            session_type: SessionType::Unicast,
            privacy: false,
            control: false,
            message_counter: 0,
            source: None,
            destination: Destination::None,
        }
    }
}

impl MessageHeader {
    /// Whether this is the unsecured session: unicast, session id zero (§4.4.1.3).
    ///
    /// "The Unsecured Session SHALL have no encryption, privacy, or message integrity
    /// checking" — so a message on it carries no MIC.
    #[must_use]
    pub const fn is_unsecured(&self) -> bool {
        matches!(self.session_type, SessionType::Unicast) && self.session_id.0 == 0
    }

    /// How many octets this header occupies.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        // flags(1) + session(2) + security(1) + counter(4)
        const BASE: usize = 8;
        let src = if self.source.is_some() { 8 } else { 0 };
        BASE.saturating_add(src)
            .saturating_add(self.destination.encoded_len())
    }

    /// Writes the header into `out`, returning how many octets it used.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Cursor::new(out);

        let mut flags = MessageFlags::from_bits_retain(MESSAGE_FORMAT_VERSION << 4);
        if self.source.is_some() {
            flags |= MessageFlags::SOURCE_PRESENT;
        }
        flags = MessageFlags::from_bits_retain(flags.bits() | self.destination.dsiz());
        w.u8(flags.bits())?;
        w.u16(self.session_id.0)?;

        let mut security = SecurityFlags::from_bits_retain(self.session_type.bits());
        if self.privacy {
            security |= SecurityFlags::PRIVACY;
        }
        if self.control {
            security |= SecurityFlags::CONTROL;
        }
        w.u8(security.bits())?;
        w.u32(self.message_counter)?;

        if let Some(source) = self.source {
            w.u64(source.0)?;
        }
        match self.destination {
            Destination::None => {}
            Destination::Node(n) => w.u64(n.0)?,
            Destination::Group(g) => w.u16(g.0)?,
        }
        Ok(w.position())
    }

    /// Reads a header from the front of `buf`, returning it and the rest of the message.
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        let mut r = Cursor::new_read(buf);

        let flags = MessageFlags::from_bits_retain(r.read_u8()?);
        let version = (flags.bits() & MessageFlags::VERSION.bits()) >> 4;
        if version != MESSAGE_FORMAT_VERSION {
            // §4.4.1.1: "Messages with version field set to reserved values SHALL be
            // dropped without sending a message-layer acknowledgement."
            bail!(UnsupportedVersion)
        }

        let session_id = SessionId(r.read_u16()?);
        let security = SecurityFlags::from_bits_retain(r.read_u8()?);
        let session_type = SessionType::from_bits(security.bits())?;
        let message_counter = r.read_u32()?;

        let source = if flags.contains(MessageFlags::SOURCE_PRESENT) {
            Some(NodeId(r.read_u64()?))
        } else {
            None
        };

        let dsiz = flags.bits() & 0b11;
        let destination = match dsiz {
            0 => Destination::None,
            1 => Destination::Node(NodeId(r.read_u64()?)),
            2 => Destination::Group(GroupId(r.read_u16()?)),
            // §4.4.1.1: "Messages with DSIZ field set to reserved values SHALL be dropped".
            _ => bail!(MessageReserved),
        };

        // §4.4.1.7: the Message Extensions block is present only when MX is set, and
        // "Version 1.0 Nodes SHALL ignore the contents of the Message Extensions payload,
        // by skipping it, to access the Message Payload."
        if security.contains(SecurityFlags::MESSAGE_EXTENSIONS) {
            let len = usize::from(r.read_u16()?);
            r.skip(len)?;
        }

        let header = Self {
            session_id,
            session_type,
            privacy: security.contains(SecurityFlags::PRIVACY),
            control: security.contains(SecurityFlags::CONTROL),
            message_counter,
            source,
            destination,
        };
        Ok((header, r.rest()))
    }
}

/// The header at the start of a message's payload (§4.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolHeader {
    /// Whether this message came from the exchange's initiator.
    pub initiator: bool,
    /// The counter this message acknowledges, when it acknowledges one (§4.12.1).
    pub acknowledged_counter: Option<u32>,
    /// Whether the sender wants an acknowledgement — the MRP **R** flag.
    pub reliability: bool,
    /// Which conversation this message belongs to.
    pub exchange_id: ExchangeId,
    /// Which protocol, and whose.
    pub protocol: ProtocolId,
    /// What kind of message, within that protocol.
    pub opcode: u8,
}

impl Default for ProtocolHeader {
    fn default() -> Self {
        Self {
            initiator: false,
            acknowledged_counter: None,
            reliability: false,
            exchange_id: ExchangeId(0),
            protocol: ProtocolId::SECURE_CHANNEL,
            opcode: 0,
        }
    }
}

impl ProtocolHeader {
    /// How many octets this header occupies.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        // flags(1) + opcode(1) + exchange(2) + protocol(2)
        const BASE: usize = 6;
        let vendor = if self.protocol.is_common() { 0 } else { 2 };
        let ack = if self.acknowledged_counter.is_some() {
            4
        } else {
            0
        };
        BASE.saturating_add(vendor).saturating_add(ack)
    }

    /// Writes the header into `out`, returning how many octets it used.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Cursor::new(out);

        let mut flags = ExchangeFlags::empty();
        if self.initiator {
            flags |= ExchangeFlags::INITIATOR;
        }
        if self.acknowledged_counter.is_some() {
            flags |= ExchangeFlags::ACKNOWLEDGEMENT;
        }
        if self.reliability {
            flags |= ExchangeFlags::RELIABILITY;
        }
        if !self.protocol.is_common() {
            flags |= ExchangeFlags::VENDOR;
        }
        w.u8(flags.bits())?;
        w.u8(self.opcode)?;
        w.u16(self.exchange_id.0)?;
        if !self.protocol.is_common() {
            w.u16(self.protocol.vendor.0)?;
        }
        w.u16(self.protocol.id)?;
        if let Some(ack) = self.acknowledged_counter {
            w.u32(ack)?;
        }
        Ok(w.position())
    }

    /// Reads a header from the front of `buf`, returning it and the application payload.
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        let mut r = Cursor::new_read(buf);

        let flags = ExchangeFlags::from_bits_retain(r.read_u8()?);
        let opcode = r.read_u8()?;
        let exchange_id = ExchangeId(r.read_u16()?);
        let vendor = if flags.contains(ExchangeFlags::VENDOR) {
            VendorId(r.read_u16()?)
        } else {
            VendorId::COMMON
        };
        let protocol = ProtocolId {
            vendor,
            id: r.read_u16()?,
        };
        let acknowledged_counter = if flags.contains(ExchangeFlags::ACKNOWLEDGEMENT) {
            Some(r.read_u32()?)
        } else {
            None
        };

        // §4.4.3.7: Secured Extensions, present only when SX is set. Skipped like the
        // message extensions above.
        if flags.contains(ExchangeFlags::SECURED_EXTENSIONS) {
            let len = usize::from(r.read_u16()?);
            r.skip(len)?;
        }

        let header = Self {
            initiator: flags.contains(ExchangeFlags::INITIATOR),
            acknowledged_counter,
            reliability: flags.contains(ExchangeFlags::RELIABILITY),
            exchange_id,
            protocol,
            opcode,
        };
        Ok((header, r.rest()))
    }
}

/// A bounds-checked little-endian cursor.
///
/// Small enough to be obvious, which is the point: every read and write in a message
/// header goes through it, so "did that one forget to check the length?" has one answer.
struct Cursor<'a> {
    write: Option<&'a mut [u8]>,
    read: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self {
            write: Some(out),
            read: &[],
            pos: 0,
        }
    }

    fn new_read(buf: &'a [u8]) -> Self {
        Self {
            write: None,
            read: buf,
            pos: 0,
        }
    }

    const fn position(&self) -> usize {
        self.pos
    }

    fn rest(&self) -> &'a [u8] {
        self.read.get(self.pos..).unwrap_or(&[])
    }

    fn advance(&mut self, n: usize) -> Result<usize> {
        let start = self.pos;
        self.pos = self
            .pos
            .checked_add(n)
            .ok_or(Error::new(ErrorCode::MessageTruncated))?;
        Ok(start)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        let start = self.advance(n)?;
        if self.read.get(start..self.pos).is_none() {
            bail!(MessageTruncated)
        }
        Ok(())
    }

    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let start = self.advance(bytes.len())?;
        let Some(buf) = self.write.as_mut() else {
            bail!(InvalidState)
        };
        let Some(dst) = buf.get_mut(start..self.pos) else {
            bail!(BufferTooSmall)
        };
        dst.copy_from_slice(bytes);
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let start = self.advance(n)?;
        self.read
            .get(start..self.pos)
            .ok_or(Error::new(ErrorCode::MessageTruncated))
    }

    fn u8(&mut self, v: u8) -> Result<()> {
        self.put(&[v])
    }
    fn u16(&mut self, v: u16) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
    fn u32(&mut self, v: u32) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
}

/// The reading half. Separate names so a misuse is a compile error, not a silent zero.
impl Cursor<'_> {
    fn read_u8(&mut self) -> Result<u8> {
        let b = self.take(1)?;
        b.first()
            .copied()
            .ok_or(Error::new(ErrorCode::MessageTruncated))
    }
    fn read_u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        let arr: [u8; 2] = b
            .try_into()
            .map_err(|_| Error::new(ErrorCode::MessageTruncated))?;
        Ok(u16::from_le_bytes(arr))
    }
    fn read_u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        let arr: [u8; 4] = b
            .try_into()
            .map_err(|_| Error::new(ErrorCode::MessageTruncated))?;
        Ok(u32::from_le_bytes(arr))
    }
    fn read_u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let arr: [u8; 8] = b
            .try_into()
            .map_err(|_| Error::new(ErrorCode::MessageTruncated))?;
        Ok(u64::from_le_bytes(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(header: &MessageHeader) {
        let mut buf = [0u8; 64];
        let n = header.encode(&mut buf).expect("encode");
        assert_eq!(n, header.encoded_len(), "encoded_len disagrees with encode");
        let (decoded, rest) = MessageHeader::decode(&buf[..n]).expect("decode");
        assert_eq!(&decoded, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn message_header_round_trips() {
        round_trip(&MessageHeader::default());
        round_trip(&MessageHeader {
            session_id: SessionId(0x1234),
            session_type: SessionType::Unicast,
            message_counter: 0xDEAD_BEEF,
            source: Some(NodeId(0x0102_0304_0506_0708)),
            destination: Destination::Node(NodeId(1)),
            ..MessageHeader::default()
        });
        round_trip(&MessageHeader {
            session_id: SessionId(5),
            session_type: SessionType::Group,
            destination: Destination::Group(GroupId(0x4242)),
            control: true,
            privacy: true,
            ..MessageHeader::default()
        });
    }

    #[test]
    fn the_wire_layout_is_little_endian_and_in_order() {
        let header = MessageHeader {
            session_id: SessionId(0x1234),
            message_counter: 0x0A0B_0C0D,
            source: Some(NodeId(0x1122_3344_5566_7788)),
            destination: Destination::Group(GroupId(0xABCD)),
            ..MessageHeader::default()
        };
        let mut buf = [0u8; 64];
        let n = header.encode(&mut buf).expect("encode");
        assert_eq!(
            &buf[..n],
            &[
                // flags: version 0, S set (0x04), DSIZ 2 (group)
                0x06, //
                // session id, little-endian
                0x34, 0x12, //
                // security flags: unicast session type, nothing else
                0x00, //
                // message counter, little-endian
                0x0D, 0x0C, 0x0B, 0x0A, //
                // source node id, little-endian
                0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, //
                // destination group id, little-endian
                0xCD, 0xAB,
            ]
        );
    }

    #[test]
    fn a_reserved_version_is_dropped() {
        // §4.4.1.1.
        let buf = [0x10, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err().code(),
            ErrorCode::UnsupportedVersion
        );
    }

    #[test]
    fn a_reserved_dsiz_is_dropped() {
        // DSIZ 3 is "Reserved for future use".
        let buf = [0x03, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err().code(),
            ErrorCode::MessageReserved
        );
    }

    #[test]
    fn a_reserved_session_type_is_dropped() {
        // Session type 2 is "Reserved for future use".
        let buf = [0x00, 0, 0, 0x02, 0, 0, 0, 0];
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err().code(),
            ErrorCode::MessageReserved
        );
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let header = MessageHeader {
            source: Some(NodeId(7)),
            destination: Destination::Node(NodeId(8)),
            ..MessageHeader::default()
        };
        let mut buf = [0u8; 64];
        let n = header.encode(&mut buf).expect("encode");
        for cut in 0..n {
            assert!(
                MessageHeader::decode(&buf[..cut]).is_err(),
                "a {cut}-octet header should not decode"
            );
        }
    }

    #[test]
    fn a_too_small_buffer_is_an_error() {
        let header = MessageHeader {
            source: Some(NodeId(7)),
            ..MessageHeader::default()
        };
        let mut buf = [0u8; 4];
        assert!(header.encode(&mut buf).is_err());
    }

    #[test]
    fn message_extensions_are_skipped() {
        // §4.4.1.7: MX set, a 3-octet payload, then the real payload.
        let buf = [
            0x00, // flags
            0x00, 0x00, // session
            0x20, // security: MX
            0x00, 0x00, 0x00, 0x00, // counter
            0x03, 0x00, // extensions length
            0xAA, 0xBB, 0xCC, // extensions payload, ignored
            0x99, // the payload that follows
        ];
        let (header, rest) = MessageHeader::decode(&buf).expect("decode");
        assert_eq!(header.message_counter, 0);
        assert_eq!(rest, &[0x99]);
    }

    #[test]
    fn a_lying_extension_length_is_an_error() {
        let buf = [0x00, 0, 0, 0x20, 0, 0, 0, 0, 0xFF, 0xFF, 0xAA];
        assert_eq!(
            MessageHeader::decode(&buf).unwrap_err().code(),
            ErrorCode::MessageTruncated
        );
    }

    fn protocol_round_trip(header: &ProtocolHeader) {
        let mut buf = [0u8; 32];
        let n = header.encode(&mut buf).expect("encode");
        assert_eq!(n, header.encoded_len(), "encoded_len disagrees with encode");
        let (decoded, rest) = ProtocolHeader::decode(&buf[..n]).expect("decode");
        assert_eq!(&decoded, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn protocol_header_round_trips() {
        protocol_round_trip(&ProtocolHeader::default());
        protocol_round_trip(&ProtocolHeader {
            initiator: true,
            reliability: true,
            acknowledged_counter: Some(0x1234_5678),
            exchange_id: ExchangeId(0xBEEF),
            protocol: ProtocolId::INTERACTION_MODEL,
            opcode: 0x02,
        });
        protocol_round_trip(&ProtocolHeader {
            protocol: ProtocolId {
                vendor: VendorId::TEST_1,
                id: 0x0042,
            },
            ..ProtocolHeader::default()
        });
    }

    #[test]
    fn a_vendor_protocol_carries_its_vendor_id() {
        let common = ProtocolHeader::default();
        let vendor = ProtocolHeader {
            protocol: ProtocolId {
                vendor: VendorId::TEST_1,
                id: 1,
            },
            ..ProtocolHeader::default()
        };
        assert_eq!(
            vendor.encoded_len(),
            common.encoded_len() + 2,
            "the V flag adds exactly the Protocol Vendor ID field"
        );
    }

    #[test]
    fn payload_follows_the_protocol_header() {
        let header = ProtocolHeader {
            exchange_id: ExchangeId(1),
            protocol: ProtocolId::INTERACTION_MODEL,
            opcode: 5,
            ..ProtocolHeader::default()
        };
        let mut buf = [0u8; 32];
        let n = header.encode(&mut buf).expect("encode");
        buf[n] = 0xAB;
        let (decoded, payload) = ProtocolHeader::decode(&buf[..=n]).expect("decode");
        assert_eq!(decoded.opcode, 5);
        assert_eq!(payload, &[0xAB]);
    }

    #[test]
    fn protocol_truncation_is_an_error_not_a_panic() {
        let header = ProtocolHeader {
            acknowledged_counter: Some(1),
            protocol: ProtocolId {
                vendor: VendorId::TEST_1,
                id: 1,
            },
            ..ProtocolHeader::default()
        };
        let mut buf = [0u8; 32];
        let n = header.encode(&mut buf).expect("encode");
        for cut in 0..n {
            assert!(ProtocolHeader::decode(&buf[..cut]).is_err(), "cut {cut}");
        }
    }
}
