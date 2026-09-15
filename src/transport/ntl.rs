//! Matter over NFC: the NFC Transport Layer (Core §4.21).
//!
//! Tap a phone against a device and commission it. §4.21 is how the Matter messages get across
//! the few centimetres: wrapped in ISO/IEC 7816-4 APDUs, the same envelopes a smart card
//! speaks, carried by ISO-DEP over NFC-A.
//!
//! # Asymmetric on purpose
//!
//! > NTL provides a reliable, datagram-oriented, transport interface with asymmetric roles: one
//! > end always transmits first, and the other end always responds. When NTL is used for Matter
//! > commissioning, the Commissioner always transmits first and the Commissionee responds.
//!
//! There is no BTP-style window here and no acknowledgement timer, because there is no
//! concurrency to manage: a command APDU goes out, a response APDU comes back, and nothing
//! happens in between. What replaces the window is *chaining* — the only mechanism NTL has for
//! a message larger than one frame, in each direction and spelled differently:
//!
//! * Commissioner to commissionee: the **CLA** octet says `0x90` on every fragment but the
//!   last, which says `0x80` (§4.21.4.2).
//! * Commissionee to commissioner: the response's **SW1** says `0x61` with SW2 counting what is
//!   left, and the commissioner fetches it with `GET RESPONSE` (§4.21.4.3).
//!
//! # Short fields, always
//!
//! §4.21.4: "Some smartphone NFC Reader/Writer implementations are limited to a maximum
//! 256-byte APDU payload … both the NFC Reader/Writer and NFC listener SHALL always use short
//! field coding (aka short length field) of APDUs." So `Lc` and `Le` are one octet each, a
//! fragment is at most 255 octets, and a response at most 256 — which is why a PASE message
//! takes several of them.
//!
//! # This module is the APDU layer and nothing below it
//!
//! §4.21.3: "The full ISO-DEP protocol SHALL be implemented in compliance with NFC Forum
//! Digital Specification" — by the platform's NFC stack, which is where the radio is. What is
//! here is the layer above: building the three commands, reading the responses, and reassembling
//! a Matter message out of the fragments.

use crate::bytes::Cursor;
use crate::error::{ErrorCode, Result, bail};

/// §4.21.4.1's Application Identifier: `A0 00 00 09 09 8A 77 E4 01`.
///
/// Nine octets that mean "Matter commissioning" to a card-emulating device, and the first thing
/// a commissioner sends.
pub const AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x09, 0x09, 0x8A, 0x77, 0xE4, 0x01];

/// §4.21.4.1: "The version SHALL be 0x01. Other values SHALL be reserved for future use."
pub const VERSION: u8 = 0x01;

/// `INS` of the interindustry SELECT command (§4.21.4.1).
pub const INS_SELECT: u8 = 0xA4;

/// `INS` of the proprietary TRANSPORT command (§4.21.4.2).
pub const INS_TRANSPORT: u8 = 0x20;

/// `INS` of the interindustry GET RESPONSE command (§4.21.4.3).
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// `CLA` of a TRANSPORT command that carries the last (or only) fragment.
pub const CLA_TRANSPORT_LAST: u8 = 0x80;

/// `CLA` of a TRANSPORT command with more fragments behind it.
pub const CLA_TRANSPORT_CHAINED: u8 = 0x90;

/// The largest `Lc`, and so the largest fragment, under short field coding.
pub const MAX_FRAGMENT: usize = 255;

/// §4.21.4.2: "P1 and P2 SHALL encode the number of octets of the full message", so a message
/// is at most what two octets can say.
pub const MAX_MESSAGE: usize = 0xFFFF;

/// A response status word (`SW1 SW2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Status {
    /// `SW1`.
    pub sw1: u8,
    /// `SW2`.
    pub sw2: u8,
}

impl Status {
    /// `90 00` — complete and successful (§4.21.4.2, Table 48).
    pub const OK: Self = Self {
        sw1: 0x90,
        sw2: 0x00,
    };
    /// `69 85` — "conditions of use are not satisfied": the device is not in commissioning
    /// mode, or a `GET RESPONSE` arrived with nothing outstanding (Tables 46 and 54).
    pub const CONDITIONS_NOT_SATISFIED: Self = Self {
        sw1: 0x69,
        sw2: 0x85,
    };
    /// `6A 84` — "Not enough memory space": the chained message is larger than this device can
    /// hold (Table 50).
    pub const NOT_ENOUGH_MEMORY: Self = Self {
        sw1: 0x6A,
        sw2: 0x84,
    };
    /// `61 XX` — successful, with `XX` more octets to fetch (Tables 49 and 53).
    #[must_use]
    pub const fn more(remaining: u8) -> Self {
        Self {
            sw1: 0x61,
            sw2: remaining,
        }
    }

    /// Whether this is a `61 XX`, and how much is left.
    #[must_use]
    pub const fn remaining(&self) -> Option<u8> {
        if self.sw1 == 0x61 {
            Some(self.sw2)
        } else {
            None
        }
    }

    /// Whether the command succeeded, complete or not.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self.sw1, 0x90 | 0x61)
    }
}

/// What a commissionee answers a `SELECT` with (§4.21.4.1, Table 45).
///
/// The same Discovery Information §5.4.2.4 puts in a BLE advertisement, which is what lets a
/// commissioner match the tap against the onboarding payload it scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selected<'a> {
    /// The NTL protocol version the commissionee speaks.
    pub version: u8,
    /// §5.4.2.4's 12-bit discriminator.
    pub discriminator: u16,
    /// The Vendor ID, or `0` when the device chooses not to say (§4.21.4.1).
    pub vendor_id: u16,
    /// The Product ID, or `0`. "A device SHALL NOT set the Vendor ID to 0 when providing a
    /// non-zero Product ID."
    pub product_id: u16,
    /// "Extended Data MAY be omitted."
    pub extended: &'a [u8],
}

impl<'a> Selected<'a> {
    /// The fixed part: version, a reserved octet, four bits of format and twelve of
    /// discriminator, then the two identifiers.
    pub const LEN: usize = 7;

    /// Writes the response data, status word excluded.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Cursor::writer(out);
        w.u8(self.version)?;
        // "The next 8 bits, cleared, are undefined (reserved)." And the next four, also
        // cleared, "encode the format of the following fields" — format 0 is this one.
        w.u8(0)?;
        w.u8(u8::try_from(self.discriminator >> 8).unwrap_or(0) & 0x0F)?;
        w.u8(u8::try_from(self.discriminator & 0xFF).unwrap_or(0))?;
        // §5.4.2.4's identifiers are big-endian here, unlike the little-endian scalars of the
        // message header — this is a smart-card envelope, not a Matter one.
        w.u8(u8::try_from(self.vendor_id >> 8).unwrap_or(0))?;
        w.u8(u8::try_from(self.vendor_id & 0xFF).unwrap_or(0))?;
        w.u8(u8::try_from(self.product_id >> 8).unwrap_or(0))?;
        w.u8(u8::try_from(self.product_id & 0xFF).unwrap_or(0))?;
        w.put(self.extended)?;
        Ok(w.position())
    }

    /// Reads the response data.
    pub fn decode(data: &'a [u8]) -> Result<Self> {
        let mut r = Cursor::reader(data, ErrorCode::MessageTruncated);
        let version = r.read_u8()?;
        let _reserved = r.read_u8()?;
        let high = r.read_u8()?;
        let low = r.read_u8()?;
        // The high nibble of `high` is the format field, which this revision defines as 0.
        if high >> 4 != 0 {
            bail!(UnsupportedVersion)
        }
        let discriminator = (u16::from(high & 0x0F) << 8) | u16::from(low);
        let vendor_hi = r.read_u8()?;
        let vendor_lo = r.read_u8()?;
        let product_hi = r.read_u8()?;
        let product_lo = r.read_u8()?;
        let vendor_id = (u16::from(vendor_hi) << 8) | u16::from(vendor_lo);
        let product_id = (u16::from(product_hi) << 8) | u16::from(product_lo);
        // §4.21.4.1: "A device SHALL NOT set the Vendor ID to 0 when providing a non-zero
        // Product ID." A commissioner that accepted it would match the tap against a product
        // whose vendor it could not name.
        if vendor_id == 0 && product_id != 0 {
            bail!(MessageReserved)
        }
        Ok(Self {
            version,
            discriminator,
            vendor_id,
            product_id,
            extended: r.rest(),
        })
    }
}

/// Writes §4.21.4.1's `SELECT` command: `00 A4 04 0C 09 <AID> 00`.
pub fn select(out: &mut [u8]) -> Result<usize> {
    let mut w = Cursor::writer(out);
    w.u8(0x00)?;
    w.u8(INS_SELECT)?;
    w.u8(0x04)?;
    w.u8(0x0C)?;
    w.u8(u8::try_from(AID.len()).unwrap_or(0))?;
    for byte in AID {
        w.u8(byte)?;
    }
    // "Le" of 0, which under short field coding means 256.
    w.u8(0x00)?;
    Ok(w.position())
}

/// Whether a command APDU is the `SELECT` of §4.21.4.1, addressed to Matter's AID.
#[must_use]
pub fn is_select(apdu: &[u8]) -> bool {
    let Some(&[cla, ins, p1, p2, lc]) = apdu.get(..5).and_then(|h| <&[u8; 5]>::try_from(h).ok())
    else {
        return false;
    };
    cla == 0x00
        && ins == INS_SELECT
        && p1 == 0x04
        && p2 == 0x0C
        && usize::from(lc) == AID.len()
        && apdu.get(5..5usize.saturating_add(AID.len())) == Some(&AID[..])
}

/// Writes §4.21.4.3's `GET RESPONSE`: `00 C0 00 00 <Le>`.
///
/// `le` is "the maximum length in octets that the reader/writer can receive", and 0 means 256.
pub fn get_response(le: u8, out: &mut [u8]) -> Result<usize> {
    let mut w = Cursor::writer(out);
    w.u8(0x00)?;
    w.u8(INS_GET_RESPONSE)?;
    w.u8(0x00)?;
    w.u8(0x00)?;
    w.u8(le)?;
    Ok(w.position())
}

/// One `TRANSPORT` command APDU (§4.21.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transport<'a> {
    /// Whether more fragments follow — the difference between `CLA` `0x90` and `0x80`.
    pub chained: bool,
    /// "the number of octets of the full message to transmit … The same value SHALL be used in
    /// all chained commands."
    pub message_length: u16,
    /// This fragment, at most [`MAX_FRAGMENT`] octets.
    pub fragment: &'a [u8],
    /// `Le`: what the commissioner can receive back. 0 means 256.
    pub le: u8,
}

impl<'a> Transport<'a> {
    /// Writes the command APDU.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if self.fragment.len() > MAX_FRAGMENT {
            // §4.21.4: short field coding, so `Lc` is one octet and this cannot be said.
            bail!(BufferTooSmall)
        }
        if usize::from(self.message_length) < self.fragment.len() {
            // A fragment longer than the message it is part of is a contradiction the receiver
            // would resolve by overrunning its reassembly buffer.
            bail!(InvalidArgument)
        }
        let mut w = Cursor::writer(out);
        w.u8(if self.chained {
            CLA_TRANSPORT_CHAINED
        } else {
            CLA_TRANSPORT_LAST
        })?;
        w.u8(INS_TRANSPORT)?;
        // "encoded as a 2-bytes integer with P1 being the most significant byte".
        w.u8(u8::try_from(self.message_length >> 8).unwrap_or(0))?;
        w.u8(u8::try_from(self.message_length & 0xFF).unwrap_or(0))?;
        w.u8(u8::try_from(self.fragment.len()).unwrap_or(0))?;
        w.put(self.fragment)?;
        w.u8(self.le)?;
        Ok(w.position())
    }

    /// Reads a command APDU.
    pub fn decode(apdu: &'a [u8]) -> Result<Self> {
        let mut r = Cursor::reader(apdu, ErrorCode::MessageTruncated);
        let cla = r.read_u8()?;
        let chained = match cla {
            CLA_TRANSPORT_LAST => false,
            CLA_TRANSPORT_CHAINED => true,
            _ => bail!(MessageReserved),
        };
        if r.read_u8()? != INS_TRANSPORT {
            bail!(MessageReserved)
        }
        let p1 = r.read_u8()?;
        let p2 = r.read_u8()?;
        let lc = usize::from(r.read_u8()?);
        let fragment = r.take(lc)?;
        // `Le` is the last octet; a command without one is not this command.
        let le = r.read_u8()?;
        Ok(Self {
            chained,
            message_length: (u16::from(p1) << 8) | u16::from(p2),
            fragment,
            le,
        })
    }
}

/// Reassembles a message from `TRANSPORT` fragments (§4.21.4.2).
///
/// `N` is the largest Matter message this node will accept over NFC. §4.21.4 is explicit that
/// the protocol could carry 65 535 octets and that "the maximum size of Matter Message than can
/// be actually transferred is limited by memory constraints of the implementation".
#[derive(Debug)]
pub struct Reassembler<const N: usize> {
    buf: heapless::Vec<u8, N>,
    expecting: Option<u16>,
}

/// What a fragment produced.
#[derive(Debug, PartialEq, Eq)]
pub enum Reassembled {
    /// More fragments are expected.
    More,
    /// The message is complete and may be read with [`Reassembler::message`].
    Message,
}

impl<const N: usize> Default for Reassembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Reassembler<N> {
    /// An empty reassembler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: heapless::Vec::new(),
            expecting: None,
        }
    }

    /// Takes one `TRANSPORT` fragment.
    ///
    /// Answers [`Status::NOT_ENOUGH_MEMORY`] — §4.21.4.2's `6A 84` — for a message this node
    /// cannot hold, which is checked against the *announced* length before a single octet is
    /// buffered rather than discovered part way through.
    pub fn push(&mut self, command: &Transport<'_>) -> core::result::Result<Reassembled, Status> {
        let length = command.message_length;
        if usize::from(length) > N {
            self.reset();
            return Err(Status::NOT_ENOUGH_MEMORY);
        }
        match self.expecting {
            // "The same value SHALL be used in all chained commands": a fragment that disagrees
            // belongs to a different message, and joining them would produce neither.
            Some(expected) if expected != length => {
                self.reset();
                return Err(Status::CONDITIONS_NOT_SATISFIED);
            }
            _ => self.expecting = Some(length),
        }
        // A chain may not deliver more than it announced. The final fragment's total is checked
        // below, but waiting for it is too late: every octet until then is buffered on the
        // strength of a length the sender chose, and a chain that kept overrunning would fill
        // the reassembly buffer before anything noticed.
        let total = self.buf.len().saturating_add(command.fragment.len());
        if total > usize::from(length) {
            self.reset();
            return Err(Status::CONDITIONS_NOT_SATISFIED);
        }
        if self.buf.extend_from_slice(command.fragment).is_err() {
            self.reset();
            return Err(Status::NOT_ENOUGH_MEMORY);
        }
        if command.chained {
            return Ok(Reassembled::More);
        }
        // The last fragment: what arrived has to be exactly what was promised.
        if self.buf.len() != usize::from(length) {
            self.reset();
            return Err(Status::CONDITIONS_NOT_SATISFIED);
        }
        Ok(Reassembled::Message)
    }

    /// The reassembled message.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.buf
    }

    /// Drops the reassembled message, ready for the next.
    pub fn take_message(&mut self) {
        self.reset();
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.expecting = None;
    }
}

/// Splits a message into `TRANSPORT` response fragments (§4.21.4.2, §4.21.4.3).
///
/// The commissionee's half of chaining: each fragment goes out with `61 XX` until the last,
/// which goes out with `90 00`. `XX` is "the number of bytes of message to be sent in the next
/// GET RESPONSE R-APDU", capped at 255 because it is one octet.
#[derive(Debug)]
pub struct Responder<'a> {
    message: &'a [u8],
    sent: usize,
}

impl<'a> Responder<'a> {
    /// A responder with `message` to deliver.
    #[must_use]
    pub const fn new(message: &'a [u8]) -> Self {
        Self { message, sent: 0 }
    }

    /// Whether anything is still outstanding, which is what makes a `GET RESPONSE` legal.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.sent >= self.message.len()
    }

    /// The next fragment and the status word that goes with it.
    ///
    /// `le` is the `Le` the commissioner asked for; 0 means 256, per short field coding.
    pub fn next(&mut self, le: u8) -> (&'a [u8], Status) {
        let room = if le == 0 { 256 } else { usize::from(le) };
        let remaining = self.message.len().saturating_sub(self.sent);
        let take = room.min(remaining);
        let fragment = self
            .message
            .get(self.sent..self.sent.saturating_add(take))
            .unwrap_or(&[]);
        self.sent = self.sent.saturating_add(take);
        let left = self.message.len().saturating_sub(self.sent);
        let status = if left == 0 {
            Status::OK
        } else {
            // One octet, so a long tail is reported as 255 — "at least this much", which is all
            // §4.21.4.2 can say and all the commissioner needs in order to ask again.
            Status::more(u8::try_from(left).unwrap_or(0xFF))
        };
        (fragment, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_select_command_is_table_44() {
        // §4.21.4.1: `00 A4 04 0C 09 A0:00:00:09:09:8A:77:E4:01 00`.
        let mut buf = [0u8; 32];
        let n = select(&mut buf).expect("encode");
        assert_eq!(
            &buf[..n],
            &[
                0x00, 0xA4, 0x04, 0x0C, 0x09, 0xA0, 0x00, 0x00, 0x09, 0x09, 0x8A, 0x77, 0xE4, 0x01,
                0x00
            ]
        );
        assert!(is_select(&buf[..n]));
        // Another application's AID is not Matter's.
        let mut other = buf;
        other[5] = 0xA1;
        assert!(!is_select(&other[..n]));
    }

    #[test]
    fn the_select_response_carries_discovery_information() {
        let selected = Selected {
            version: VERSION,
            discriminator: 0xF00,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            extended: &[],
        };
        let mut buf = [0u8; 32];
        let n = selected.encode(&mut buf).expect("encode");
        assert_eq!(n, Selected::LEN + 1);
        assert_eq!(&buf[..n], &[0x01, 0x00, 0x0F, 0x00, 0xFF, 0xF1, 0x80, 0x00]);
        assert_eq!(Selected::decode(&buf[..n]).expect("decode"), selected);
    }

    #[test]
    fn a_product_id_without_a_vendor_id_is_refused() {
        // §4.21.4.1: "A device SHALL NOT set the Vendor ID to 0 when providing a non-zero
        // Product ID." A commissioner that took it would name a product with no vendor.
        let data = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00];
        assert!(Selected::decode(&data).is_err());
        // Both zero is the documented way to say nothing.
        let quiet = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(Selected::decode(&quiet).expect("decode").vendor_id, 0);
    }

    #[test]
    fn a_transport_command_round_trips() {
        let command = Transport {
            chained: true,
            message_length: 0x0140,
            fragment: &[1, 2, 3],
            le: 0x00,
        };
        let mut buf = [0u8; 32];
        let n = command.encode(&mut buf).expect("encode");
        // CLA 0x90 (chained), INS 0x20, P1/P2 = 0x0140, Lc = 3, data, Le.
        assert_eq!(&buf[..n], &[0x90, 0x20, 0x01, 0x40, 0x03, 1, 2, 3, 0x00]);
        assert_eq!(Transport::decode(&buf[..n]).expect("decode"), command);

        // The last fragment says so in the CLA, and nowhere else.
        let last = Transport {
            chained: false,
            ..command
        };
        let n = last.encode(&mut buf).expect("encode");
        assert_eq!(buf[0], CLA_TRANSPORT_LAST);
        assert_eq!(Transport::decode(&buf[..n]).expect("decode"), last);
    }

    #[test]
    fn a_status_word_says_what_is_left() {
        assert!(Status::OK.is_ok());
        assert_eq!(Status::OK.remaining(), None);
        assert!(Status::more(42).is_ok());
        assert_eq!(Status::more(42).remaining(), Some(42));
        assert!(!Status::CONDITIONS_NOT_SATISFIED.is_ok());
        assert!(!Status::NOT_ENOUGH_MEMORY.is_ok());
    }
}
