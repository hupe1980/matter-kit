//! The ten BDX messages of §11.22.5 and §11.22.6, on the wire.
//!
//! None of them is TLV. BDX is a byte protocol with a TLV *tail* — the optional metadata on
//! the four negotiation messages — so every field here is a fixed-width little-endian scalar
//! read straight out of the payload, and the message id lives in the exchange's protocol
//! header rather than in the payload at all.

use super::{Rejected, StatusCode};
use crate::error::{Error, ErrorCode, Result};

/// The protocol version this crate speaks (§11.22.5.1.1: "The first version, as of Matter
/// specification 1.0 is BDX Version 0").
pub const VERSION: u8 = 0;

/// §11.22.3.1's protocol opcodes, under [`ProtocolId::BDX`](crate::msg::ProtocolId::BDX).
///
/// Exhaustive on purpose: the specification closes this set, and the gaps in it (`0x03`,
/// `0x06`..=`0x0F`) are reserved, so an unknown opcode is a peer speaking something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// The Initiator wants to *send* — an upload (§11.22.5.1).
    SendInit = 0x01,
    /// The Responder accepts an upload (§11.22.5.2).
    SendAccept = 0x02,
    /// The Initiator wants to *receive* — a download (§11.22.5.1).
    ReceiveInit = 0x04,
    /// The Responder accepts a download (§11.22.5.3).
    ReceiveAccept = 0x05,
    /// A driving Receiver asks for the next block (§11.22.6.2).
    BlockQuery = 0x10,
    /// One block of data (§11.22.6.4).
    Block = 0x11,
    /// The last block, which may be empty (§11.22.6.5).
    BlockEof = 0x12,
    /// A Receiver acknowledges a block (§11.22.6.6).
    BlockAck = 0x13,
    /// A Receiver acknowledges the last block, ending the session (§11.22.6.7).
    BlockAckEof = 0x14,
    /// A driving Receiver seeks forward and asks for the next block (§11.22.6.3).
    BlockQueryWithSkip = 0x15,
}

impl MessageType {
    /// Reads an opcode from a protocol header.
    ///
    /// Rejects the reserved values rather than mapping them onto the nearest known one:
    /// §11.22.3.1 leaves `0x03` and `0x06`..=`0x0F` for future use, and guessing at one would
    /// put the transfer into a state neither end agreed to.
    pub const fn from_u8(value: u8) -> Rejected<Self> {
        Ok(match value {
            0x01 => Self::SendInit,
            0x02 => Self::SendAccept,
            0x04 => Self::ReceiveInit,
            0x05 => Self::ReceiveAccept,
            0x10 => Self::BlockQuery,
            0x11 => Self::Block,
            0x12 => Self::BlockEof,
            0x13 => Self::BlockAck,
            0x14 => Self::BlockAckEof,
            0x15 => Self::BlockQueryWithSkip,
            _ => return Err(StatusCode::UnexpectedMessage),
        })
    }

    /// The opcode as it appears in the protocol header.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}

/// The Transfer Control octet: a version and the transfer modes (§11.22.5.1.1, §11.22.5.4.1).
///
/// The same octet is `PTC` in an Init, where the bits are everything the Initiator *can* do,
/// and `TC` in an Accept, where exactly one drive bit is what the Responder *chose*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransferControl {
    /// `[VERSION]`, the low four bits.
    pub version: u8,
    /// `[SENDER_DRIVE]`: the Sender paces the transfer with Block messages.
    pub sender_drive: bool,
    /// `[RECEIVER_DRIVE]`: the Receiver paces it with BlockQuery messages.
    pub receiver_drive: bool,
    /// `[ASYNC]`: no driver, flow control left to the transport.
    ///
    /// Provisional in 1.6, and §11.22.5.4.1 is explicit that a Responder "SHALL not" choose it
    /// — so [`negotiate`](super::negotiate) never does.
    pub asynchronous: bool,
}

impl TransferControl {
    const VERSION_MASK: u8 = 0x0F;
    const SENDER_DRIVE: u8 = 1 << 4;
    const RECEIVER_DRIVE: u8 = 1 << 5;
    const ASYNC: u8 = 1 << 6;

    /// Proposes synchronous Sender drive and Receiver drive at [`VERSION`], which is what an
    /// initiator that can do either should offer (§11.22.5.1.1).
    #[must_use]
    pub const fn proposal() -> Self {
        Self {
            version: VERSION,
            sender_drive: true,
            receiver_drive: true,
            asynchronous: false,
        }
    }

    /// Reads the octet.
    ///
    /// Bit 7 is RFU and is ignored rather than refused: the version field is how BDX makes a
    /// breaking change, so a spare bit in a message a future version sends is not this
    /// version's business.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self {
            version: value & Self::VERSION_MASK,
            sender_drive: value & Self::SENDER_DRIVE != 0,
            receiver_drive: value & Self::RECEIVER_DRIVE != 0,
            asynchronous: value & Self::ASYNC != 0,
        }
    }

    /// Writes the octet.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        let mut out = self.version & Self::VERSION_MASK;
        if self.sender_drive {
            out |= Self::SENDER_DRIVE;
        }
        if self.receiver_drive {
            out |= Self::RECEIVER_DRIVE;
        }
        if self.asynchronous {
            out |= Self::ASYNC;
        }
        out
    }

    /// Whether exactly one drive mode is named, which is what an Accept must carry.
    ///
    /// §11.22.5.4.1: "exactly one mode SHALL be chosen for this transfer", and the two bits are
    /// mutually exclusive — "if this is set, TC\[RECEIVER_DRIVE\] SHALL be 0".
    #[must_use]
    pub const fn is_decided(self) -> bool {
        self.sender_drive ^ self.receiver_drive
    }
}

/// The Range Control octet: which of the optional offset and length fields are present, and
/// how wide they are (§11.22.5.1.2, §11.22.5.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct RangeControl {
    definite_length: bool,
    start_offset: bool,
    wide_range: bool,
}

impl RangeControl {
    const DEFLEN: u8 = 1 << 0;
    const STARTOFS: u8 = 1 << 1;
    const WIDERANGE: u8 = 1 << 4;

    const fn from_u8(value: u8) -> Self {
        Self {
            definite_length: value & Self::DEFLEN != 0,
            start_offset: value & Self::STARTOFS != 0,
            wide_range: value & Self::WIDERANGE != 0,
        }
    }

    const fn to_u8(self) -> u8 {
        let mut out = 0;
        if self.definite_length {
            out |= Self::DEFLEN;
        }
        if self.start_offset {
            out |= Self::STARTOFS;
        }
        if self.wide_range {
            out |= Self::WIDERANGE;
        }
        out
    }

    /// The width in octets of each present range field.
    const fn width(self) -> usize {
        if self.wide_range { 8 } else { 4 }
    }
}

/// Whether a value needs the 64-bit encoding.
///
/// `RC[WIDERANGE]` is one bit covering *both* range fields, so it is set when either of them
/// does not fit in 32 bits and cleared otherwise — the same "narrowest encoding that holds
/// the value" rule §A.7.1 states for TLV, applied to the only place BDX has a choice.
const fn needs_wide(value: u64) -> bool {
    value > u32::MAX as u64
}

/// A `SendInit` or `ReceiveInit` message (§11.22.5.1).
///
/// The two share a format exactly; which one it is decides who sends the data, and that is the
/// opcode, not a field. Everything here is a *proposal*: the Responder answers with the
/// parameters it will actually use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Init<'a> {
    /// Proposed Transfer Control: version and the modes the Initiator supports.
    pub control: TransferControl,
    /// Proposed Max Block Size, "exclusive of block header fields, such as a block counter".
    pub max_block_size: u16,
    /// Where in the file to start, when the Initiator asks for part of it.
    pub start_offset: Option<u64>,
    /// The size the Initiator commits to, or expects. `None` is §11.22.5.1.5's indefinite
    /// length, and so is a length of zero — the two are the same thing on the wire.
    pub definite_length: Option<u64>,
    /// The File Designator: whatever names the payload to the two ends.
    pub file_designator: &'a [u8],
    /// Optional application metadata, TLV, running to the end of the payload.
    pub metadata: &'a [u8],
}

impl<'a> Init<'a> {
    /// A proposal to transfer `file_designator` whole, in blocks of `max_block_size`.
    #[must_use]
    pub const fn new(file_designator: &'a [u8], max_block_size: u16) -> Self {
        Self {
            control: TransferControl::proposal(),
            max_block_size,
            start_offset: None,
            definite_length: None,
            file_designator,
            metadata: &[],
        }
    }

    /// The Range Control this message's optional fields imply.
    fn range(&self) -> RangeControl {
        let offset = self.start_offset.unwrap_or(0);
        let length = self.definite_length.unwrap_or(0);
        RangeControl {
            definite_length: self.definite_length.is_some_and(|len| len != 0),
            start_offset: self.start_offset.is_some(),
            wide_range: needs_wide(offset) || needs_wide(length),
        }
    }

    /// Writes the payload, and says how long it is.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let range = self.range();
        let mut w = Writer::new(buf);
        w.u8(self.control.to_u8())?;
        w.u8(range.to_u8())?;
        w.u16(self.max_block_size)?;
        if range.start_offset {
            w.uint(self.start_offset.unwrap_or(0), range.width())?;
        }
        if range.definite_length {
            w.uint(self.definite_length.unwrap_or(0), range.width())?;
        }
        let designator_len = u16::try_from(self.file_designator.len())
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        w.u16(designator_len)?;
        w.bytes(self.file_designator)?;
        w.bytes(self.metadata)?;
        Ok(w.written())
    }

    /// Reads the payload.
    pub fn decode(payload: &'a [u8]) -> Rejected<Self> {
        let mut r = Reader::new(payload);
        let control = TransferControl::from_u8(r.u8()?);
        let range = RangeControl::from_u8(r.u8()?);
        let max_block_size = r.u16()?;
        let start_offset = if range.start_offset {
            Some(r.uint(range.width())?)
        } else {
            None
        };
        let definite_length = if range.definite_length {
            // §11.22.5.1.5: "A length of 0 or a missing length field signifies an indefinite
            // length", so the two spellings collapse to one value here.
            Some(r.uint(range.width())?).filter(|len| *len != 0)
        } else {
            None
        };
        let designator_len = usize::from(r.u16()?);
        let file_designator = r.bytes(designator_len)?;
        Ok(Self {
            control,
            max_block_size,
            start_offset,
            definite_length,
            file_designator,
            metadata: r.rest(),
        })
    }
}

/// A `SendAccept` message (§11.22.5.2): the Responder will receive an upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendAccept<'a> {
    /// The one transfer mode and version chosen.
    pub control: TransferControl,
    /// The Max Block Size that will be used; §11.22.5.4.3 requires it be `<= PMBS`.
    pub max_block_size: u16,
    /// Optional application metadata, TLV.
    pub metadata: &'a [u8],
}

impl<'a> SendAccept<'a> {
    /// Writes the payload, and says how long it is.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(buf);
        w.u8(self.control.to_u8())?;
        w.u16(self.max_block_size)?;
        w.bytes(self.metadata)?;
        Ok(w.written())
    }

    /// Reads the payload.
    pub fn decode(payload: &'a [u8]) -> Rejected<Self> {
        let mut r = Reader::new(payload);
        let control = TransferControl::from_u8(r.u8()?);
        let max_block_size = r.u16()?;
        Ok(Self {
            control,
            max_block_size,
            metadata: r.rest(),
        })
    }
}

/// A `ReceiveAccept` message (§11.22.5.3): the Responder will send a download.
///
/// The extra field over [`SendAccept`] is the one that matters: the Responder is the Sender
/// here, so it is the end that knows how big the file actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveAccept<'a> {
    /// The one transfer mode and version chosen.
    pub control: TransferControl,
    /// The Max Block Size that will be used.
    pub max_block_size: u16,
    /// The length of the transfer, when the Sender knows it. `None` is indefinite.
    pub length: Option<u64>,
    /// Optional application metadata, TLV.
    pub metadata: &'a [u8],
}

impl<'a> ReceiveAccept<'a> {
    fn range(&self) -> RangeControl {
        let length = self.length.unwrap_or(0);
        RangeControl {
            definite_length: self.length.is_some_and(|len| len != 0),
            start_offset: false,
            wide_range: needs_wide(length),
        }
    }

    /// Writes the payload, and says how long it is.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let range = self.range();
        let mut w = Writer::new(buf);
        w.u8(self.control.to_u8())?;
        w.u8(range.to_u8())?;
        w.u16(self.max_block_size)?;
        if range.definite_length {
            w.uint(self.length.unwrap_or(0), range.width())?;
        }
        w.bytes(self.metadata)?;
        Ok(w.written())
    }

    /// Reads the payload.
    pub fn decode(payload: &'a [u8]) -> Rejected<Self> {
        let mut r = Reader::new(payload);
        let control = TransferControl::from_u8(r.u8()?);
        let range = RangeControl::from_u8(r.u8()?);
        let max_block_size = r.u16()?;
        let length = if range.definite_length {
            Some(r.uint(range.width())?).filter(|len| *len != 0)
        } else {
            None
        };
        Ok(Self {
            control,
            max_block_size,
            length,
            metadata: r.rest(),
        })
    }
}

/// A `Block` or `BlockEOF` message (§11.22.6.4, §11.22.6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block<'a> {
    /// The block counter, ascending and sequential from zero (§11.22.6.1).
    pub counter: u32,
    /// The data. "The data field's length is that of the remainder of the message payload
    /// after the Block Counter field, since Matter messages have definite length."
    pub data: &'a [u8],
}

impl<'a> Block<'a> {
    /// Writes the payload, and says how long it is.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(buf);
        w.u32(self.counter)?;
        w.bytes(self.data)?;
        Ok(w.written())
    }

    /// Reads the payload.
    pub fn decode(payload: &'a [u8]) -> Rejected<Self> {
        let mut r = Reader::new(payload);
        let counter = r.u32()?;
        Ok(Self {
            counter,
            data: r.rest(),
        })
    }
}

/// A bare block counter: `BlockQuery`, `BlockAck` and `BlockAckEOF` are all just this
/// (§11.22.6.2, §11.22.6.6, §11.22.6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter {
    /// The block being asked for, or acknowledged.
    pub counter: u32,
}

impl Counter {
    /// Writes the payload, and says how long it is.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(buf);
        w.u32(self.counter)?;
        Ok(w.written())
    }

    /// Reads the payload.
    ///
    /// Trailing octets are refused: unlike a Block, these messages have no variable field, so
    /// anything after the counter means the sender and this reader disagree about the format.
    pub fn decode(payload: &[u8]) -> Rejected<Self> {
        let mut r = Reader::new(payload);
        let counter = r.u32()?;
        r.end()?;
        Ok(Self { counter })
    }
}

/// A `BlockQueryWithSkip` message (§11.22.6.3): the next block, from `bytes_to_skip` further
/// on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockQueryWithSkip {
    /// The block counter, which advances by one exactly as a plain query's does.
    pub counter: u32,
    /// How far to move the Sender's cursor before reading the next block. Skipping past the
    /// end is not an error: the answer is an empty `BlockEOF`.
    pub bytes_to_skip: u64,
}

impl BlockQueryWithSkip {
    /// Writes the payload, and says how long it is.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(buf);
        w.u32(self.counter)?;
        w.uint(self.bytes_to_skip, 8)?;
        Ok(w.written())
    }

    /// Reads the payload.
    pub fn decode(payload: &[u8]) -> Rejected<Self> {
        let mut r = Reader::new(payload);
        let counter = r.u32()?;
        let bytes_to_skip = r.uint(8)?;
        r.end()?;
        Ok(Self {
            counter,
            bytes_to_skip,
        })
    }
}

// --- Little-endian scalars ------------------------------------------------------------

/// Reads fixed-width little-endian fields out of a payload.
///
/// Every shortfall is [`StatusCode::BadMessageContents`], which is what §11.22.3.2 says to
/// answer a malformed message with, so the caller never has to translate.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(payload: &'a [u8]) -> Self {
        Self { rest: payload }
    }

    fn bytes(&mut self, len: usize) -> Rejected<&'a [u8]> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(StatusCode::BadMessageContents)?;
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Rejected<u8> {
        let bytes = self.bytes(1)?;
        bytes.first().copied().ok_or(StatusCode::BadMessageContents)
    }

    fn u16(&mut self) -> Rejected<u16> {
        let bytes =
            <[u8; 2]>::try_from(self.bytes(2)?).map_err(|_| StatusCode::BadMessageContents)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Rejected<u32> {
        let bytes =
            <[u8; 4]>::try_from(self.bytes(4)?).map_err(|_| StatusCode::BadMessageContents)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// A 4- or 8-octet little-endian unsigned value, widened.
    fn uint(&mut self, width: usize) -> Rejected<u64> {
        let mut out = [0u8; 8];
        let bytes = self.bytes(width)?;
        let slot = out.get_mut(..width).ok_or(StatusCode::BadMessageContents)?;
        slot.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(out))
    }

    const fn rest(&self) -> &'a [u8] {
        self.rest
    }

    fn end(&self) -> Rejected<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(StatusCode::BadMessageContents)
        }
    }
}

/// Writes fixed-width little-endian fields into a payload buffer.
struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, at: 0 }
    }

    const fn written(&self) -> usize {
        self.at
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .at
            .checked_add(bytes.len())
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let slot = self
            .buf
            .get_mut(self.at..end)
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        slot.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<()> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<()> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<()> {
        self.bytes(&value.to_le_bytes())
    }

    fn uint(&mut self, value: u64, width: usize) -> Result<()> {
        let bytes = value.to_le_bytes();
        let slot = bytes
            .get(..width)
            .ok_or(Error::new(ErrorCode::InvalidArgument))?;
        self.bytes(slot)
    }
}
