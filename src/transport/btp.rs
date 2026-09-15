//! The Bluetooth Transport Protocol (Core §4.19).
//!
//! BLE gives Matter a pipe that is too small and has no flow control: a GATT PDU carries
//! `ATT_MTU - 3` octets, which on the minimum MTU is **20**, while a Matter message may be
//! 1280. BTP is what sits in between — it segments a message across GATT writes, reassembles
//! it, and supplies the one thing BLE does not.
//!
//! # The receive window is not an optimisation
//!
//! §4.19.4.7 explains why it exists, and the reason is physical rather than aesthetic:
//!
//! > In the case of some dual-chip architectures, writes and indications are received and
//! > confirmed by the BLE chip with no input from the host processor. When the BLE chip sends
//! > the result of a received GATT PDU to the host processor, that payload and the
//! > corresponding BTP packet will be permanently lost if the host does not have enough space
//! > to receive it.
//!
//! So the window is how a peer says "I can hold this many more before something is dropped on
//! the floor", and exceeding it loses data with no error raised anywhere. Three rules keep it
//! from deadlocking, and each is easy to leave out:
//!
//! * A peer must not send when the remote window has **one** slot left and it owes no
//!   acknowledgement — otherwise both windows fill and neither side can send the
//!   acknowledgement that would reopen them.
//! * A server starts its counter for the client's window at `max - 1`, because its handshake
//!   response already occupies a slot. A client starts the server's at `max`.
//! * A peer whose *own* window is down to two free slots sends its pending acknowledgement
//!   immediately, rather than waiting for the timer.
//!
//! # What this module is
//!
//! The protocol, sans-I/O: frames, the handshake, segmentation and reassembly, sequence
//! numbers, the window, and the two timers. GATT itself — the service, the characteristics,
//! the subscription — is in [`super::ble`] as constants and payload formats, because the
//! stack that drives it is where every BLE platform differs.
//!
//! ```
//! use matter_kit::transport::btp::{HandshakeRequest, Received, Role, Session, negotiate};
//! use matter_kit::platform::Instant;
//!
//! let now = Instant::from_micros(0);
//! // The commissioner offers, the device answers with the lower of each value.
//! let request = HandshakeRequest::new(247, 6);
//! let agreed = negotiate(&request, 247, 4)?;
//!
//! let mut client = Session::<1280>::new(Role::Client, &agreed.params(), now);
//! let mut server = Session::<1280>::new(Role::Server, &agreed.params(), now);
//!
//! client.send(b"a Matter message")?;
//! let mut wire = [0u8; 256];
//! while let Some(n) = client.poll_send(now, &mut wire)? {
//!     if server.receive(&wire[..n], now)? == Received::Message {
//!         assert_eq!(server.message(), b"a Matter message");
//!     }
//! }
//! # Ok::<(), matter_kit::Error>(())
//! ```

use crate::bytes::Cursor;
use crate::error::{Error, ErrorCode, Result, bail};
use crate::platform::{Duration, Instant};

/// `0x6C` — the only Management Opcode BTP defines (Core Table 30).
pub const OPCODE_HANDSHAKE: u8 = 0x6C;

/// The BTP version this crate speaks — "4 — BTP as defined by Matter v1.0" (§4.19.3.1).
pub const VERSION: u8 = 4;

/// The smallest `ATT_MTU` GATT allows, and what §4.19.3.1 says to offer when the negotiated
/// value is not yet known.
pub const MIN_ATT_MTU: u16 = 23;

/// Every GATT PDU costs a 3-octet header, so a BTP segment is `ATT_MTU - 3` (§4.19.3.1).
pub const GATT_HEADER: u16 = 3;

/// The largest segment a BTP session may use.
///
/// §4.19.4.2 caps C1 and C2 at 244 octets "to align with maximum PDU size when LE Data Packet
/// Length Extensions (DPLE) is enabled on Bluetooth 4.2 hardware" — so a larger negotiated
/// ATT_MTU buys nothing, and a peer that sent 500-octet segments would overrun hardware that
/// followed the specification.
pub const MAX_SEGMENT: u16 = 244;

/// "The maximum amount of time after sending a BTP Session Handshake request to wait for a
/// BTP Session Handshake response" (Table 35).
pub const CONN_RSP_TIMEOUT: Duration = Duration::from_secs(5);

/// "The maximum amount of time after sending a BTP packet before a peer must receive an
/// acknowledgement for it" (Table 35) — and, because an idle session still exchanges
/// acknowledgements, BTP's keep-alive.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(15);

/// "The maximum amount of time no unique data has been sent over a BTP session before the
/// Central Device must close the BTP session" (Table 35).
pub const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The send-acknowledgement timer: "any value less than one-half the acknowledgement timeout
/// interval" (§4.19.4.8).
///
/// A third rather than a half. The rule exists so that "on a healthy BLE connection, a peer
/// will always receive acknowledgements for sent packets before its acknowledgement-received
/// timer expires"; choosing exactly one half would make that a race with the radio rather
/// than a guarantee.
pub const SEND_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest window size any peer may support — "to prevent sequence number wrap-around"
/// (§4.19.4.7).
pub const MAX_WINDOW: u8 = 255;

bitflags::bitflags! {
    /// §4.19.2.1's control flags.
    ///
    /// The bit order is worth reading off the specification's own diagram rather than
    /// inferring from the order of the prose: it is `- H M - A E C B`, so `B` is bit 0 and
    /// `H` is bit 6.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Flags: u8 {
        /// `B` — the first segment of an SDU. Implies a Message Length field.
        const BEGINNING = 1 << 0;
        /// `C` — "set to '0' on the first segment … and '1' for all remaining segments",
        /// the last one included.
        const CONTINUING = 1 << 1;
        /// `E` — the last segment. A whole SDU in one packet sets `B` and `E` together.
        const ENDING = 1 << 2;
        /// `A` — an Ack Number field is present.
        const ACK = 1 << 3;
        /// `M` — a Management Opcode field is present.
        const MANAGEMENT = 1 << 5;
        /// `H` — a handshake packet, which has an entirely different layout.
        const HANDSHAKE = 1 << 6;
    }
}

/// `0x65` — the control flags every handshake packet carries (§4.19.3.1): `H | M | E | B`.
pub const HANDSHAKE_FLAGS: u8 = 0x65;

/// Which end of the BLE connection a peer is.
///
/// Not cosmetic. §4.19.4.6 and §4.19.4.7 give the two ends *different* starting values,
/// because the server's handshake response already occupies a slot in the client's window,
/// and a peer that starts on the wrong one desynchronises on its very first packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The Central: the commissioner, the GATT client, the end that writes to C1 and sends
    /// the handshake request.
    Client,
    /// The Peripheral: the commissionee, the GATT server, the end that indicates on C2.
    Server,
}

/// §4.19.3.1's BTP Handshake Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRequest {
    /// The versions offered, "listed once each, newest first, in descending order". Trailing
    /// zeroes are unused slots.
    pub versions: [u8; 8],
    /// "the size of the GATT PDU (ATT_MTU) that can be received by the sender minus the size
    /// of the GATT header", or 0 for no preference.
    pub att_mtu: u16,
    /// "the maximum receive window size supported by the client".
    pub window: u8,
}

impl HandshakeRequest {
    /// How many octets it occupies: flags, opcode, four version octets, MTU, window.
    pub const LEN: usize = 9;

    /// A request offering only [`VERSION`].
    #[must_use]
    pub const fn new(att_mtu: u16, window: u8) -> Self {
        let mut versions = [0u8; 8];
        versions[0] = VERSION;
        Self {
            versions,
            att_mtu,
            window,
        }
    }

    /// Writes the request, returning how many octets it took.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Cursor::writer(out);
        w.u8(HANDSHAKE_FLAGS)?;
        w.u8(OPCODE_HANDSHAKE)?;
        // Eight version *nibbles* packed into four octets, low nibble first — `Ver[0]`, the
        // newest version, is the low nibble of the first.
        for &[low, high] in self.versions.as_chunks::<2>().0 {
            w.u8((low & 0x0F) | ((high & 0x0F) << 4))?;
        }
        w.u16(self.att_mtu)?;
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
            att_mtu: r.read_u16()?,
            window: r.read_u8()?,
        })
    }

    /// The newest offered version this crate also speaks, or `None` if there is none.
    #[must_use]
    pub fn best_version(&self) -> Option<u8> {
        // "Supported versions are listed once each, newest first"; 0 marks an unused slot.
        self.versions
            .iter()
            .copied()
            .find(|&v| v != 0 && v <= VERSION)
    }
}

/// §4.19.3.2's BTP Handshake Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// "the BTP protocol version selected by the server".
    pub version: u8,
    /// "the maximum ATT_MTU for the connection selected by the server".
    pub att_mtu: u16,
    /// "the maximum receive window size supported by the server".
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
        // "Final Protocol Version" in the low nibble; "Reserved … SHALL be set to 0".
        w.u8(self.version & 0x0F)?;
        w.u16(self.att_mtu)?;
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
            att_mtu: r.read_u16()?,
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

    /// The segment payload size this session allows: `ATT_MTU - 3`, capped at
    /// [`MAX_SEGMENT`].
    #[must_use]
    pub const fn segment_size(&self) -> usize {
        let mtu = if self.att_mtu < MIN_ATT_MTU {
            MIN_ATT_MTU
        } else {
            self.att_mtu
        };
        let usable = mtu.saturating_sub(GATT_HEADER);
        (if usable > MAX_SEGMENT {
            MAX_SEGMENT
        } else {
            usable
        }) as usize
    }
}

/// What a [`Session`] needs from a completed handshake.
///
/// The session core is shared with `transport::paftp` (feature `paf`, so not always present —
/// which is why this is not an intra-doc link), whose handshake negotiates the same
/// two numbers under different names — a Service Specific Info length rather than an ATT_MTU —
/// over a radio with a different header. Everything after the handshake is identical, and this
/// is the seam that says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionParams {
    /// The largest segment payload, header excluded.
    pub segment_size: usize,
    /// The receive window, in packets.
    pub window: u8,
}

/// What a server answers a handshake request with (§4.19.3.2).
///
/// The negotiation is a pair of minima: the MTU both ends can carry and the window both can
/// hold. Echoing the client's values back unchecked would let a peer talk a device into
/// segments its own BLE chip cannot receive — which, per §4.19.4.7, are lost silently.
pub fn negotiate(
    request: &HandshakeRequest,
    own_att_mtu: u16,
    own_window: u8,
) -> Result<HandshakeResponse> {
    let Some(version) = request.best_version() else {
        bail!(UnsupportedVersion)
    };
    // "If the client has no preference, the value may be set to 0."
    let requested = if request.att_mtu == 0 {
        own_att_mtu
    } else {
        request.att_mtu.min(own_att_mtu)
    };
    let window = request.window.min(own_window);
    if window == 0 {
        // A zero window is a session that could never send a single packet.
        bail!(BtpMalformed)
    }
    Ok(HandshakeResponse {
        version,
        att_mtu: requested.max(MIN_ATT_MTU),
        window,
    })
}

/// One decoded data frame (§4.19.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Its control flags.
    pub flags: Flags,
    /// The sequence number it acknowledges, when `A` is set.
    pub ack: Option<u8>,
    /// Its own sequence number — "All BTP packets SHALL be sent with sequence numbers".
    pub sequence: u8,
    /// The whole SDU's length, present only on a Beginning segment.
    pub message_length: Option<u16>,
    /// The segment itself, empty on a stand-alone acknowledgement.
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Reads a data frame.
    ///
    /// A handshake packet is [`ErrorCode::BtpMalformed`] here rather than a `Frame`: its
    /// layout is different, and decoding one as data would read its version nibbles as a
    /// sequence number and its MTU as a payload.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut r = Cursor::reader(buf, ErrorCode::BtpMalformed);
        // Bits 4 and 7 are reserved. A sender SHALL clear them; a receiver that refused them
        // would break on a future revision that assigns one, so they are ignored.
        let flags = Flags::from_bits_truncate(r.read_u8()?);
        if flags.intersects(Flags::HANDSHAKE | Flags::MANAGEMENT) {
            // The handshake is the only Management Opcode BTP defines, and it is not a data
            // frame — so anything with `M` or `H` set is a packet nothing here can act on.
            bail!(BtpMalformed)
        }
        let ack = if flags.contains(Flags::ACK) {
            Some(r.read_u8()?)
        } else {
            None
        };
        let sequence = r.read_u8()?;
        let message_length = if flags.contains(Flags::BEGINNING) {
            Some(r.read_u16()?)
        } else {
            None
        };
        Ok(Self {
            flags,
            ack,
            sequence,
            message_length,
            payload: r.rest(),
        })
    }

    /// How many octets a header with these fields occupies.
    #[must_use]
    pub const fn header_len(ack: bool, beginning: bool) -> usize {
        // Control flags and sequence number always; an Ack Number and a Message Length only
        // when their flags say so.
        2usize
            .saturating_add(ack as usize)
            .saturating_add(if beginning { 2 } else { 0 })
    }
}

/// What arriving bytes turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// A complete SDU is ready; read it with [`Session::message`] and release the buffer with
    /// [`Session::take_message`].
    Message,
    /// A segment was taken and more of the SDU is still to come.
    Partial,
    /// A stand-alone acknowledgement, carrying no segment.
    Ack,
}

/// One BTP session (§4.19.4), sans-I/O.
///
/// `SDU` bounds the reassembled message. §4.4.4 sets the floor at 1280 octets for a node that
/// also speaks UDP; a BLE-only node may choose less, and pays for it in what it can be sent.
///
/// Every error this returns is fatal to the session: §4.19.4.5 and §4.19.4.6 close the BTP
/// session on a sequence number out of order, an invalid acknowledgement, or a reassembly
/// that does not match its declared length. BTP has no way to resynchronise, so continuing
/// would mean splicing two messages into one.
#[derive(Debug)]
pub struct Session<const SDU: usize> {
    role: Role,
    segment_size: usize,
    max_window: u8,

    /// The next sequence number this peer will send.
    tx_sequence: u8,
    /// The highest sequence number of *ours* the remote has acknowledged. Initialised to 255
    /// for both roles: the client's first packet is 0 and the server's handshake response was
    /// an implied 0, so in both cases "one before the first outstanding packet" is 255.
    tx_acked: u8,
    /// The last sequence number received, and the last one acknowledged back. §4.19.4.7 sizes
    /// this peer's own window from exactly that difference.
    rx_sequence: u8,
    rx_acked: u8,
    /// The acknowledgement owed to the remote, if any.
    pending_ack: Option<u8>,
    /// §4.19.4.8's send-acknowledgement timer.
    send_ack_at: Option<Instant>,
    /// §4.19.4.8's acknowledgement-received timer. `None` means nothing is outstanding.
    ack_deadline: Option<Instant>,
    /// When an SDU segment last crossed the session in either direction — §4.19.4.9's
    /// "unique data", as distinct from the acknowledgements that keep flowing regardless.
    last_data: Instant,
    /// Why the session closed, once it has. Latched, because §4.19.4.5 and §4.19.4.6 leave
    /// no way back: a peer whose sequence numbers desynchronised cannot resynchronise them,
    /// so a session that kept going would splice two messages into one.
    closed: Option<ErrorCode>,

    /// Reassembly.
    rx: [u8; SDU],
    rx_len: usize,
    rx_expected: Option<u16>,

    /// The SDU being sent, and how much of it has gone.
    tx: [u8; SDU],
    tx_len: usize,
    tx_sent: usize,
    tx_active: bool,
}

impl<const SDU: usize> Session<SDU> {
    /// A session over a completed handshake.
    ///
    /// The two roles start from different values, and the asymmetry is the handshake response:
    /// it "bears an implied sequence number of zero because it occupies a slot in the client's
    /// receive window". So a server's first *data* packet is sequence 1 and it starts the
    /// client's window at one below the maximum, while a client's is 0 with the full window —
    /// and a client begins already owing an acknowledgement for that implied zero.
    #[must_use]
    pub fn new(role: Role, params: &SessionParams, now: Instant) -> Self {
        let (tx_sequence, rx_sequence, pending_ack, send_ack_at, ack_deadline) = match role {
            // The client has "received" the response, whose implied sequence is 0, and owes
            // an acknowledgement for it. It has nothing outstanding of its own.
            Role::Client => (
                0,
                0,
                Some(0),
                Some(now.saturating_add(SEND_ACK_TIMEOUT)),
                None,
            ),
            // "a server SHALL start its acknowledgement-received timer when it sends a
            // handshake response". `rx_sequence` of 255 makes the client's first packet,
            // sequence 0, the correct successor.
            Role::Server => (1, 255, None, None, Some(now.saturating_add(ACK_TIMEOUT))),
        };
        Self {
            role,
            segment_size: params.segment_size,
            max_window: params.window,
            tx_sequence,
            tx_acked: 255,
            rx_sequence,
            rx_acked: 255,
            pending_ack,
            send_ack_at,
            ack_deadline,
            last_data: now,
            closed: None,
            rx: [0u8; SDU],
            rx_len: 0,
            rx_expected: None,
            tx: [0u8; SDU],
            tx_len: 0,
            tx_sent: 0,
            tx_active: false,
        }
    }

    /// Which end this is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Whether the session has closed.
    ///
    /// A closed session is finished: the caller's job is to tear down the BLE connection
    /// (§4.19.4.10) and report the error upwards, not to keep polling. Every method below
    /// refuses from here on, with the code that closed it.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Why the session closed, if it has.
    #[must_use]
    pub const fn close_reason(&self) -> Option<ErrorCode> {
        self.closed
    }

    /// Refuses anything on a session that has already closed.
    fn guard(&self) -> Result<()> {
        match self.closed {
            Some(code) => Err(Error::new(code)),
            None => Ok(()),
        }
    }

    /// Latches a fatal failure, so a caller that misses the first error cannot go on to
    /// reassemble a message out of the fragments either side of it.
    fn fail<T>(&mut self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            self.closed = Some(error.code());
        }
        result
    }

    /// The largest segment payload this session uses.
    #[must_use]
    pub const fn segment_size(&self) -> usize {
        self.segment_size
    }

    /// How many packets this peer has sent that the remote has not acknowledged.
    #[must_use]
    pub const fn in_flight(&self) -> u8 {
        self.tx_sequence.wrapping_sub(self.tx_acked).wrapping_sub(1)
    }

    /// How many more packets the remote peer can hold — §4.19.4.7's counter, derived rather
    /// than stored so it cannot drift from the sequence numbers it is defined by.
    #[must_use]
    pub const fn remote_window(&self) -> u8 {
        self.max_window.saturating_sub(self.in_flight())
    }

    /// How many slots are free in this peer's *own* receive window: "the sequence number
    /// difference between the last packet they received and the last packet they
    /// acknowledged" (§4.19.4.7).
    #[must_use]
    pub const fn own_window_free(&self) -> u8 {
        self.max_window
            .saturating_sub(self.rx_sequence.wrapping_sub(self.rx_acked))
    }

    /// Whether an acknowledgement is owed to the remote.
    #[must_use]
    pub const fn owes_ack(&self) -> bool {
        self.pending_ack.is_some()
    }

    /// Whether an SDU is part-sent.
    #[must_use]
    pub const fn is_sending(&self) -> bool {
        self.tx_active
    }

    /// Queues an SDU for transmission.
    ///
    /// §4.19.4.5: "At any point in time, only one BTP SDU may be transmitted in each
    /// direction", so a second one while the first is still going out is
    /// [`ErrorCode::Busy`]. Queueing happens above this layer, where the caller knows how many
    /// messages it is willing to hold.
    pub fn send(&mut self, sdu: &[u8]) -> Result<()> {
        // Not `fail`: a full queue or an over-long message is the caller's mistake to fix,
        // not something the peer did to the session.
        self.guard()?;
        if self.tx_active {
            bail!(Busy)
        }
        if sdu.is_empty() {
            bail!(InvalidArgument)
        }
        let Some(slot) = self.tx.get_mut(..sdu.len()) else {
            bail!(BufferTooSmall)
        };
        slot.copy_from_slice(sdu);
        self.tx_len = sdu.len();
        self.tx_sent = 0;
        self.tx_active = true;
        Ok(())
    }

    /// Whether a packet may go out right now (§4.19.4.7).
    ///
    /// > A local peer SHALL also not send packets if the remote peer's receive window has one
    /// > slot open and the local peer does not have a pending packet acknowledgement.
    ///
    /// The deadlock this prevents is the whole reason for the rule: if both peers fill each
    /// other's windows, each waits for an acknowledgement the other can no longer send.
    /// Reserving the last slot for a packet that carries one keeps a way out.
    #[must_use]
    pub const fn can_send(&self) -> bool {
        match self.remote_window() {
            0 => false,
            1 => self.pending_ack.is_some(),
            _ => true,
        }
    }

    /// Writes the next packet, if there is one to write.
    ///
    /// Returns how many octets of `out` it fills, or `None` when there is nothing due or the
    /// window forbids sending. Call it again after every [`Session::receive`] and whenever
    /// [`Session::wake_at`] comes round.
    pub fn poll_send(&mut self, now: Instant, out: &mut [u8]) -> Result<Option<usize>> {
        self.guard()?;
        let result = self.poll_send_inner(now, out);
        self.fail(result)
    }

    fn poll_send_inner(&mut self, now: Instant, out: &mut [u8]) -> Result<Option<usize>> {
        if !self.can_send() {
            return Ok(None);
        }
        // "If a peer detects that its receive window has shrunk to two or fewer free slots, it
        // SHALL immediately send any pending acknowledgement as a stand-alone BTP packet. This
        // prevents the session from stalling in the interval between when a peer's receive
        // window becomes empty and when its send-acknowledgement timer would normally fire."
        let ack_due =
            self.own_window_free() <= 2 || self.send_ack_at.is_some_and(|deadline| now >= deadline);

        if !self.tx_active {
            if self.pending_ack.is_some() && ack_due {
                // A stand-alone acknowledgement "consumes a slot in a remote peer's window
                // just like any other packet", and must itself be acknowledged.
                return Ok(Some(self.write_header(now, false, false, 0, out)?));
            }
            return Ok(None);
        }

        let remaining = self.tx_len.saturating_sub(self.tx_sent);
        let beginning = self.tx_sent == 0;
        let room = self
            .segment_size
            .saturating_sub(Frame::header_len(self.pending_ack.is_some(), beginning));
        if room == 0 {
            // A negotiated ATT_MTU too small to carry a header plus one octet.
            bail!(BufferTooSmall)
        }
        let take = remaining.min(room);
        let ending = take == remaining;

        // The header goes down first so that its `&mut self` borrow is over before `self.tx`
        // is read; `out` is a separate borrow and does not conflict with either.
        let at = self.write_header(now, beginning, ending, take, out)?;
        let end = at.saturating_add(take);
        let sent_to = self.tx_sent.saturating_add(take);
        let (Some(slot), Some(segment)) =
            (out.get_mut(at..end), self.tx.get(self.tx_sent..sent_to))
        else {
            bail!(BufferTooSmall)
        };
        slot.copy_from_slice(segment);

        self.tx_sent = sent_to;
        self.last_data = now;
        if ending {
            self.tx_active = false;
            self.tx_len = 0;
            self.tx_sent = 0;
        }
        Ok(Some(end))
    }

    /// Writes one packet's header, taking a sequence number and any pending acknowledgement
    /// with it. Returns where the payload starts.
    fn write_header(
        &mut self,
        now: Instant,
        beginning: bool,
        ending: bool,
        payload_len: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        let mut flags = Flags::empty();
        if beginning {
            flags |= Flags::BEGINNING;
        } else if payload_len > 0 {
            // "Set to '0' on the first segment of a BTP SDU and set to '1' for all remaining
            // segments" — but a stand-alone acknowledgement is part of no SDU at all.
            flags |= Flags::CONTINUING;
        }
        if ending {
            flags |= Flags::ENDING;
        }
        let ack = self.pending_ack;
        if ack.is_some() {
            flags |= Flags::ACK;
        }

        let len = {
            let mut w = Cursor::writer(out);
            w.u8(flags.bits())?;
            if let Some(ack) = ack {
                w.u8(ack)?;
            }
            w.u8(self.tx_sequence)?;
            if beginning {
                // §4.19.4.5 caps an SDU at 64 KB, which is also all the field can say.
                let length = u16::try_from(self.tx_len)
                    .map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
                w.u16(length)?;
            }
            w.position()
        };
        debug_assert_eq!(len, Frame::header_len(ack.is_some(), beginning));

        // §4.19.4.6: sequence numbers "wrap to zero" past 255.
        self.tx_sequence = self.tx_sequence.wrapping_add(1);
        // "A peer SHALL stop its send-acknowledgement timer when any pending acknowledgement
        // is sent, either as a stand-alone BTP packet or piggybacked onto an outgoing buffer
        // segment."
        if let Some(ack) = ack {
            self.rx_acked = ack;
            self.pending_ack = None;
            self.send_ack_at = None;
        }
        // "When a peer sends any BTP packet, it SHALL start this timer if it is not already
        // running."
        if self.ack_deadline.is_none() {
            self.ack_deadline = Some(now.saturating_add(ACK_TIMEOUT));
        }
        Ok(len)
    }

    /// Takes one arriving packet (§4.19.4).
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<Received> {
        self.guard()?;
        let result = self.receive_inner(bytes, now);
        self.fail(result)
    }

    fn receive_inner(&mut self, bytes: &[u8], now: Instant) -> Result<Received> {
        let frame = Frame::decode(bytes)?;

        // §4.19.4.6: "Peers SHALL check to ensure that all received BTP packets properly
        // increment the sender's previous sequence number by 1."
        if frame.sequence != self.rx_sequence.wrapping_add(1) {
            bail!(BtpSequence)
        }
        self.rx_sequence = frame.sequence;
        if self.rx_sequence.wrapping_sub(self.rx_acked) > self.max_window {
            // The remote overran the window it agreed to. On real hardware the next packet
            // would be the one the BLE chip drops on the floor.
            bail!(BtpSequence)
        }
        // "When it receives any BTP packet, a peer SHALL record the packet's sequence number
        // as the corresponding BTP session's pending acknowledgement value and start the
        // send-acknowledgement timer if it is not already running."
        self.pending_ack = Some(frame.sequence);
        if self.send_ack_at.is_none() {
            self.send_ack_at = Some(now.saturating_add(SEND_ACK_TIMEOUT));
        }

        if let Some(acked) = frame.ack {
            // "Acknowledgement of a given packet implies acknowledgement of all packets
            // received on the same BTP session prior to the acknowledged packet", so one ack
            // can clear several slots at once.
            let outstanding = self.in_flight();
            let newly = acked.wrapping_sub(self.tx_acked);
            if newly == 0 || newly > outstanding {
                // "An acknowledgement is invalid if the acknowledged sequence number does not
                // correspond to an outstanding, unacknowledged BTP packet sequence number."
                bail!(BtpSequence)
            }
            self.tx_acked = acked;
            self.ack_deadline = if newly == outstanding {
                // "A peer SHALL stop its acknowledgement-received timer if it receives an
                // acknowledgement for its most recently sent unacknowledged packet."
                None
            } else {
                // "…SHALL restart … for any but its most recently sent unacknowledged packet."
                Some(now.saturating_add(ACK_TIMEOUT))
            };
        }

        if frame.payload.is_empty() && !frame.flags.contains(Flags::BEGINNING) {
            return Ok(Received::Ack);
        }
        self.last_data = now;

        if frame.flags.contains(Flags::BEGINNING) {
            if self.rx_expected.is_some() {
                // "a Beginning Segment when another BTP SDU's transmission is already in
                // progress" — §4.19.4.5 closes the session for it.
                bail!(BtpMalformed)
            }
            let Some(length) = frame.message_length else {
                bail!(BtpMalformed)
            };
            if usize::from(length) > SDU {
                bail!(BufferTooSmall)
            }
            self.rx_expected = Some(length);
            self.rx_len = 0;
        } else if self.rx_expected.is_none() {
            // "receiver receives an Ending Segment without the presence of a previous
            // Beginning Segment" — there is no Message Length to check the result against.
            bail!(BtpMalformed)
        }

        let end = self
            .rx_len
            .checked_add(frame.payload.len())
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let Some(slot) = self.rx.get_mut(self.rx_len..end) else {
            bail!(BufferTooSmall)
        };
        slot.copy_from_slice(frame.payload);
        self.rx_len = end;

        if !frame.flags.contains(Flags::ENDING) {
            return Ok(Received::Partial);
        }
        // "verify that the reassembled BTP SDU's total length matches that specified by the
        // Beginning Segment's Message Length value."
        let Some(expected) = self.rx_expected.take() else {
            bail!(BtpMalformed)
        };
        if usize::from(expected) != self.rx_len {
            bail!(BtpMalformed)
        }
        Ok(Received::Message)
    }

    /// The reassembled message, valid until [`Session::take_message`].
    #[must_use]
    pub fn message(&self) -> &[u8] {
        self.rx.get(..self.rx_len).unwrap_or(&[])
    }

    /// Releases the reassembly buffer for the next message.
    pub const fn take_message(&mut self) {
        self.rx_len = 0;
        self.rx_expected = None;
    }

    /// Fails once the acknowledgement-received timer has expired (§4.19.4.8).
    ///
    /// This is also BTP's keep-alive: because an idle session still exchanges
    /// acknowledgements every send-acknowledgement interval, a remote stack that has crashed
    /// stops answering and the session closes on its own.
    pub fn poll_timeout(&mut self, now: Instant) -> Result<()> {
        self.guard()?;
        if self.ack_deadline.is_some_and(|deadline| now >= deadline) {
            self.closed = Some(ErrorCode::BtpTimeout);
            bail!(BtpTimeout)
        }
        Ok(())
    }

    /// Whether no SDU data has crossed the session for [`CONN_IDLE_TIMEOUT`] (§4.19.4.9).
    ///
    /// Acting on it is the Central's job: "The maximum amount of time no unique data has been
    /// sent over a BTP session before the Central Device must close the BTP session".
    #[must_use]
    pub fn is_idle(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_data) >= CONN_IDLE_TIMEOUT
    }

    /// When this session next needs attention: the earlier of its two timers.
    #[must_use]
    pub fn wake_at(&self) -> Option<Instant> {
        match (self.send_ack_at, self.ack_deadline) {
            (Some(a), Some(b)) => Some(if a <= b { a } else { b }),
            (Some(a), None) => Some(a),
            (None, b) => b,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> Instant {
        Instant::from_micros(secs.saturating_mul(1_000_000))
    }

    fn agreed() -> HandshakeResponse {
        HandshakeResponse {
            version: VERSION,
            att_mtu: 247,
            window: 6,
        }
    }

    /// A client and server over the same negotiated parameters, both at `t = 0`.
    fn pair() -> (Session<1280>, Session<1280>) {
        (
            Session::new(Role::Client, &agreed().params(), at(0)),
            Session::new(Role::Server, &agreed().params(), at(0)),
        )
    }

    #[test]
    fn the_handshake_request_matches_table_31() {
        // The version *nibbles* are what a round-trip alone would never catch: two versions
        // share an octet, low nibble first.
        let mut request = HandshakeRequest::new(247, 6);
        request.versions[1] = 3;
        let mut buf = [0u8; 16];
        assert_eq!(request.encode(&mut buf).expect("encode"), 9);
        assert_eq!(buf[0], 0x65, "H | M | E | B");
        assert_eq!(buf[1], 0x6C, "the only Management Opcode BTP defines");
        assert_eq!(buf[2], 0x34, "Ver[0] = 4 low, Ver[1] = 3 high");
        assert_eq!(&buf[3..6], &[0, 0, 0], "unused version slots are zero");
        assert_eq!(&buf[6..8], &[247, 0], "ATT_MTU little-endian");
        assert_eq!(buf[8], 6);
        assert_eq!(HandshakeRequest::decode(&buf).expect("decode"), request);
    }

    #[test]
    fn the_handshake_response_matches_table_32() {
        let mut buf = [0u8; 16];
        assert_eq!(agreed().encode(&mut buf).expect("encode"), 6);
        assert_eq!(&buf[..3], &[0x65, 0x6C, 4], "version in the low nibble");
        assert_eq!(&buf[3..5], &[247, 0]);
        assert_eq!(buf[5], 6);
        assert_eq!(HandshakeResponse::decode(&buf).expect("decode"), agreed());
    }

    #[test]
    fn negotiation_takes_the_lower_of_each() {
        // Echoing the client's MTU back would let a peer talk a device into segments its own
        // BLE chip cannot receive — and §4.19.4.7 says those are lost with no error anywhere.
        let bigger = HandshakeRequest::new(512, 10);
        let result = negotiate(&bigger, 247, 6).expect("negotiate");
        assert_eq!(result.att_mtu, 247, "the server's is smaller");
        assert_eq!(result.window, 6);

        // "If the client has no preference, the value may be set to 0."
        let none = HandshakeRequest::new(0, 4);
        assert_eq!(negotiate(&none, 247, 6).expect("ok").att_mtu, 247);
        assert_eq!(negotiate(&none, 247, 6).expect("ok").window, 4);

        let mut future = HandshakeRequest::new(247, 4);
        future.versions[0] = 9;
        assert_eq!(
            negotiate(&future, 247, 6).map_err(|e| e.code()),
            Err(ErrorCode::UnsupportedVersion)
        );
    }

    #[test]
    fn the_segment_size_is_capped_at_the_characteristic_length() {
        // §4.19.4.2 limits C1 and C2 to 244 octets, so a larger ATT_MTU buys nothing and
        // sending more would overrun conformant hardware.
        assert_eq!(agreed().segment_size(), 244);
        let huge = HandshakeResponse {
            att_mtu: 517,
            ..agreed()
        };
        assert_eq!(huge.segment_size(), 244);
        let minimum = HandshakeResponse {
            att_mtu: MIN_ATT_MTU,
            ..agreed()
        };
        assert_eq!(minimum.segment_size(), 20, "the BLE 4.0 floor");
    }

    #[test]
    fn the_two_ends_start_differently_because_the_response_occupies_a_slot() {
        // §4.19.4.6 and §4.19.4.7. Starting the server where the client starts desynchronises
        // the session on its very first packet.
        let (client, server) = pair();
        assert_eq!(client.tx_sequence, 0);
        assert_eq!(server.tx_sequence, 1, "the response was an implied zero");
        assert_eq!(client.remote_window(), 6);
        assert_eq!(
            server.remote_window(),
            5,
            "the response already took a slot"
        );
        assert!(
            client.owes_ack(),
            "the client acknowledges the response's implied sequence zero"
        );
        assert_eq!(
            client.own_window_free(),
            5,
            "and that slot is its own, used"
        );
        assert_eq!(server.own_window_free(), 6);
    }

    #[test]
    fn a_message_larger_than_a_segment_is_split_and_put_back_together() {
        let (mut client, mut server) = pair();
        let sdu: heapless::Vec<u8, 600> = (0..600u16).map(|i| i as u8).collect();
        client.send(&sdu).expect("queue");

        let mut segments = 0;
        let mut wire = [0u8; 256];
        while let Some(n) = client.poll_send(at(0), &mut wire).expect("send") {
            segments += 1;
            assert!(segments < 100, "segmentation must terminate");
            if server.receive(&wire[..n], at(0)).expect("receive") == Received::Message {
                break;
            }
        }
        assert!(
            segments > 1,
            "600 octets does not fit one 244-octet segment"
        );
        assert_eq!(server.message(), sdu.as_slice());
    }

    #[test]
    fn a_full_message_exchange_runs_in_both_directions() {
        // The round trip is where the two ends' differing start values would show up as a
        // sequence error, and where the piggybacked acknowledgements have to line up.
        let (mut client, mut server) = pair();
        let request: heapless::Vec<u8, 700> = (0..700u16).map(|i| (i * 7) as u8).collect();
        let response: heapless::Vec<u8, 500> = (0..500u16).map(|i| (i * 3) as u8).collect();

        let mut wire = [0u8; 256];
        client.send(&request).expect("queue");
        while let Some(n) = client.poll_send(at(0), &mut wire).expect("send") {
            server.receive(&wire[..n], at(0)).expect("receive");
        }
        assert_eq!(server.message(), request.as_slice());
        server.take_message();

        server.send(&response).expect("queue");
        while let Some(n) = server.poll_send(at(1), &mut wire).expect("send") {
            client.receive(&wire[..n], at(1)).expect("receive");
        }
        assert_eq!(client.message(), response.as_slice());

        // Every packet the client sent is acknowledged, so its timer is stopped.
        assert_eq!(client.in_flight(), 0);
        client
            .poll_timeout(at(1000))
            .expect("no packet outstanding");
    }

    #[test]
    fn a_whole_sdu_that_fits_one_segment_sets_both_beginning_and_ending() {
        // §4.19.4.5: "A segment MAY have both the Beginning and Ending bits set indicating
        // that a full BTP SDU is included in the message."
        let (mut client, _) = pair();
        client.send(b"short").expect("queue");
        let mut wire = [0u8; 256];
        let n = client
            .poll_send(at(0), &mut wire)
            .expect("send")
            .expect("a packet");
        let frame = Frame::decode(&wire[..n]).expect("decode");
        assert!(frame.flags.contains(Flags::BEGINNING | Flags::ENDING));
        assert!(!frame.flags.contains(Flags::CONTINUING));
        assert_eq!(frame.message_length, Some(5));
        assert_eq!(frame.payload, b"short");
        assert!(!client.is_sending());
    }

    #[test]
    fn every_segment_after_the_first_carries_the_continuing_bit() {
        // §4.19.2.1: "Set to '0' on the first segment of a BTP SDU and set to '1' for all
        // remaining segments" — the *last* one included, which is the half that gets missed.
        let (mut client, _) = pair();
        let sdu: heapless::Vec<u8, 600> = (0..600u16).map(|i| i as u8).collect();
        client.send(&sdu).expect("queue");

        let mut wire = [0u8; 256];
        let mut first = true;
        let mut saw_ending = false;
        while let Some(n) = client.poll_send(at(0), &mut wire).expect("send") {
            let frame = Frame::decode(&wire[..n]).expect("decode");
            assert_eq!(frame.flags.contains(Flags::CONTINUING), !first);
            assert_eq!(frame.flags.contains(Flags::BEGINNING), first);
            saw_ending = frame.flags.contains(Flags::ENDING);
            first = false;
        }
        assert!(saw_ending, "the last segment ends the SDU");
    }

    #[test]
    fn a_sequence_number_out_of_order_closes_the_session() {
        // §4.19.4.6. BTP cannot resynchronise, so continuing would splice two messages.
        let (mut client, mut server) = pair();
        client.send(b"one").expect("queue");
        let mut wire = [0u8; 256];
        let n = client
            .poll_send(at(0), &mut wire)
            .expect("send")
            .expect("a packet");
        server.receive(&wire[..n], at(0)).expect("the first packet");

        let mut tampered = wire;
        let sequence_at = usize::from(Frame::decode(&wire[..n]).expect("decode").ack.is_some()) + 1;
        tampered[sequence_at] = 5;
        assert_eq!(
            server.receive(&tampered[..n], at(0)).map_err(|e| e.code()),
            Err(ErrorCode::BtpSequence)
        );
    }

    #[test]
    fn an_acknowledgement_for_a_packet_never_sent_closes_the_session() {
        // "An acknowledgement is invalid if the acknowledged sequence number does not
        // correspond to an outstanding, unacknowledged BTP packet sequence number."
        let (_, mut server) = pair();
        // The client's first packet, sequence 0, acknowledging sequence 9 — but the server
        // has only ever sent the handshake response, an implied 0.
        let frame = [
            (Flags::BEGINNING | Flags::ENDING | Flags::ACK).bits(),
            9,
            0,
            1,
            0,
            0xAA,
        ];
        assert_eq!(
            server.receive(&frame, at(0)).map_err(|e| e.code()),
            Err(ErrorCode::BtpSequence)
        );
    }

    #[test]
    fn one_acknowledgement_clears_every_slot_before_it() {
        // "By induction, acknowledgement of a given packet implies acknowledgement of all
        // packets received on the same BTP session prior to the acknowledged packet."
        let (mut client, _) = pair();
        let sdu: heapless::Vec<u8, 900> = (0..900u16).map(|i| i as u8).collect();
        client.send(&sdu).expect("queue");
        let mut wire = [0u8; 256];
        // Send every segment without letting the server answer.
        while client.poll_send(at(0), &mut wire).expect("send").is_some() {}
        assert!(client.in_flight() >= 3, "several segments are outstanding");
        assert!(client.remote_window() < 6);

        // One acknowledgement naming the last of them reopens all of their slots at once.
        let last = client.tx_sequence.wrapping_sub(1);
        let ack = [Flags::ACK.bits(), last, 1];
        client.receive(&ack, at(1)).expect("the acknowledgement");
        assert_eq!(client.in_flight(), 0);
        assert_eq!(client.remote_window(), 6, "the whole window is back");
        assert!(
            client.wake_at().is_some(),
            "the send-acknowledgement timer is now running for the ack packet itself"
        );
    }

    #[test]
    fn an_ending_segment_with_no_beginning_is_refused() {
        // §4.19.4.5 closes the session: with no Beginning there is no Message Length to check
        // the reassembly against.
        let (_, mut server) = pair();
        let frame = [Flags::ENDING.bits(), 0, 0xAA, 0xBB];
        assert_eq!(
            server.receive(&frame, at(0)).map_err(|e| e.code()),
            Err(ErrorCode::BtpMalformed)
        );
    }

    #[test]
    fn a_second_beginning_while_an_sdu_is_in_progress_is_refused() {
        // The other half of §4.19.4.5's list. Without the check the two messages reassemble
        // into one, and the message layer above sees a single corrupt frame.
        let (mut client, mut server) = pair();
        let sdu: heapless::Vec<u8, 600> = (0..600u16).map(|i| i as u8).collect();
        client.send(&sdu).expect("queue");
        let mut wire = [0u8; 256];
        let n = client
            .poll_send(at(0), &mut wire)
            .expect("send")
            .expect("a packet");
        assert_eq!(
            server.receive(&wire[..n], at(0)).expect("first"),
            Received::Partial
        );

        // A fresh Beginning at the next sequence number, mid-transfer.
        let frame = [
            (Flags::BEGINNING | Flags::ENDING).bits(),
            server.rx_sequence.wrapping_add(1),
            1,
            0,
            0xAA,
        ];
        assert_eq!(
            server.receive(&frame, at(0)).map_err(|e| e.code()),
            Err(ErrorCode::BtpMalformed)
        );
    }

    #[test]
    fn a_reassembly_that_does_not_match_its_declared_length_is_refused() {
        // "verify that the reassembled BTP SDU's total length matches that specified by the
        // Beginning Segment's Message Length value" — a mismatch means a segment was lost or
        // invented, and the message above it would be silently wrong.
        let (_, mut server) = pair();
        let frame = [
            (Flags::BEGINNING | Flags::ENDING).bits(),
            0,
            9,
            0,
            0xAA,
            0xBB,
        ];
        assert_eq!(
            server.receive(&frame, at(0)).map_err(|e| e.code()),
            Err(ErrorCode::BtpMalformed)
        );
    }

    #[test]
    fn a_message_larger_than_the_reassembly_buffer_is_refused_at_its_first_segment() {
        // Better to fail on the Beginning segment, which states the whole length, than to
        // discover it part way through and have taken the segments in between.
        let mut small = Session::<64>::new(Role::Server, &agreed().params(), at(0));
        let frame = [Flags::BEGINNING.bits(), 0, 0x00, 0x02, 0xAA];
        assert_eq!(
            small.receive(&frame, at(0)).map_err(|e| e.code()),
            Err(ErrorCode::BufferTooSmall)
        );
    }

    #[test]
    fn the_window_reserves_its_last_slot_for_a_packet_that_carries_an_ack() {
        // §4.19.4.7's deadlock rule. Without it both peers fill each other's windows and each
        // waits for an acknowledgement the other can no longer send.
        let (mut client, _) = pair();
        // Five packets outstanding against a window of six leaves one slot.
        client.tx_sequence = 5;
        client.tx_acked = 255;
        assert_eq!(client.remote_window(), 1);

        client.pending_ack = None;
        assert!(!client.can_send(), "one slot and nothing to acknowledge");
        client.pending_ack = Some(3);
        assert!(
            client.can_send(),
            "the last slot is for a packet that reopens the other side"
        );

        client.tx_sequence = 6;
        assert_eq!(client.remote_window(), 0);
        assert!(!client.can_send(), "a closed window sends nothing at all");
    }

    #[test]
    fn a_closed_window_stops_segmentation_and_resuming_it_restarts_it() {
        // "When a closed window reopens, a local peer SHALL immediately resume any pending
        // BTP packet transmission."
        let narrow = HandshakeResponse {
            window: 3,
            ..agreed()
        };
        let mut client = Session::<1280>::new(Role::Client, &narrow.params(), at(0));
        let sdu: heapless::Vec<u8, 1200> = (0..1200u16).map(|i| i as u8).collect();
        client.send(&sdu).expect("queue");

        let mut wire = [0u8; 256];
        let mut sent = 0;
        while client.poll_send(at(0), &mut wire).expect("send").is_some() {
            sent += 1;
        }
        // Two of the three slots, and then a halt: the third is the one §4.19.4.7 reserves
        // for a packet carrying an acknowledgement, and the client owes none.
        assert_eq!(sent, 2);
        assert_eq!(client.remote_window(), 1);
        assert!(!client.can_send());
        assert!(client.is_sending(), "the SDU is not finished");

        // The server acknowledges, and transmission picks up where it stopped.
        let ack = [Flags::ACK.bits(), client.tx_sequence.wrapping_sub(1), 1];
        client.receive(&ack, at(1)).expect("ack");
        assert!(client.poll_send(at(1), &mut wire).expect("send").is_some());
    }

    #[test]
    fn a_second_sdu_while_one_is_in_flight_is_refused() {
        // §4.19.4.5: "The transmission of BTP segments of any two BTP SDUs SHALL NOT overlap."
        let (mut client, _) = pair();
        let big: heapless::Vec<u8, 600> = (0..600u16).map(|i| i as u8).collect();
        client.send(&big).expect("queue");
        let mut wire = [0u8; 256];
        client.poll_send(at(0), &mut wire).expect("send");
        assert!(client.is_sending());
        assert_eq!(
            client.send(b"jump the queue").map_err(|e| e.code()),
            Err(ErrorCode::Busy)
        );
    }

    #[test]
    fn a_handshake_packet_is_not_decoded_as_data() {
        // Its layout is different; taking one for data would read its version nibbles as a
        // sequence number and its MTU as payload.
        let mut buf = [0u8; 16];
        HandshakeRequest::new(247, 6)
            .encode(&mut buf)
            .expect("encode");
        assert_eq!(
            Frame::decode(&buf).map_err(|e| e.code()),
            Err(ErrorCode::BtpMalformed)
        );
    }

    #[test]
    fn a_pending_acknowledgement_rides_on_the_next_segment() {
        // §4.19.4.8: "If the peer sends any packet before this timer expires, it SHALL
        // piggyback any pending acknowledgement on the transmitted packet." A stand-alone ack
        // costs a window slot, so riding along is not merely tidier.
        let (mut client, mut server) = pair();
        client.send(b"hello").expect("queue");
        let mut wire = [0u8; 256];
        let n = client
            .poll_send(at(0), &mut wire)
            .expect("send")
            .expect("a packet");
        server.receive(&wire[..n], at(0)).expect("receive");
        assert!(server.owes_ack());

        server.send(b"reply").expect("queue");
        let n = server
            .poll_send(at(0), &mut wire)
            .expect("send")
            .expect("a packet");
        let frame = Frame::decode(&wire[..n]).expect("decode");
        assert_eq!(frame.ack, Some(0), "the client's first packet");
        assert!(
            !server.owes_ack(),
            "and the send-acknowledgement timer stops"
        );
    }

    #[test]
    fn an_idle_peer_sends_its_acknowledgement_alone_once_the_timer_fires() {
        // The keep-alive: with nothing to say, the acknowledgement still has to go out, or the
        // remote's acknowledgement-received timer expires and closes a healthy session.
        let (mut client, mut server) = pair();
        client.send(b"hello").expect("queue");
        let mut wire = [0u8; 256];
        let n = client
            .poll_send(at(0), &mut wire)
            .expect("send")
            .expect("a packet");
        server.receive(&wire[..n], at(0)).expect("receive");

        assert!(
            server.poll_send(at(0), &mut wire).expect("send").is_none(),
            "nothing is due yet"
        );
        let due = server
            .wake_at()
            .expect("the send-acknowledgement timer runs");
        let n = server
            .poll_send(due, &mut wire)
            .expect("send")
            .expect("a stand-alone ack");
        let frame = Frame::decode(&wire[..n]).expect("decode");
        assert!(frame.payload.is_empty(), "no segment rides with it");
        assert_eq!(frame.ack, Some(0));
        assert!(
            frame
                .flags
                .intersection(Flags::BEGINNING | Flags::CONTINUING | Flags::ENDING)
                .is_empty(),
            "a stand-alone ack belongs to no SDU"
        );
        assert_eq!(
            client.receive(&wire[..n], due).expect("receive"),
            Received::Ack
        );
        assert!(
            client.owes_ack(),
            "stand-alone acks are themselves acknowledged"
        );
    }

    #[test]
    fn a_nearly_full_receive_window_forces_the_acknowledgement_out_early() {
        // §4.19.4.8: "If a peer detects that its receive window has shrunk to two or fewer
        // free slots, it SHALL immediately send any pending acknowledgement as a stand-alone
        // BTP packet. This prevents the session from stalling in the interval between when a
        // peer's receive window becomes empty and when its send-acknowledgement timer would
        // normally fire."
        let (mut client, mut server) = pair();
        let sdu: heapless::Vec<u8, 1000> = (0..1000u16).map(|i| i as u8).collect();
        client.send(&sdu).expect("queue");

        let mut wire = [0u8; 256];
        let mut forced = None;
        while let Some(n) = client.poll_send(at(0), &mut wire).expect("send") {
            server.receive(&wire[..n], at(0)).expect("receive");
            if server.own_window_free() <= 2 {
                // Well before the five-second timer.
                forced = server.poll_send(at(0), &mut wire).expect("send");
                break;
            }
        }
        let n = forced.expect("the ack went out early");
        assert!(
            Frame::decode(&wire[..n])
                .expect("decode")
                .payload
                .is_empty(),
            "stand-alone, because the server has nothing to say yet"
        );
    }

    #[test]
    fn an_unanswered_packet_eventually_closes_the_session() {
        // §4.19.4.8's acknowledgement-received timer, which doubles as the keep-alive: a
        // remote stack that crashes simply stops acknowledging.
        let (mut client, _) = pair();
        client.send(b"hello").expect("queue");
        let mut wire = [0u8; 256];
        client.poll_send(at(0), &mut wire).expect("send");

        client
            .poll_timeout(at(14))
            .expect("still within the timeout");
        assert_eq!(
            client.poll_timeout(at(15)).map_err(|e| e.code()),
            Err(ErrorCode::BtpTimeout)
        );
    }

    #[test]
    fn the_server_starts_its_timer_when_it_sends_the_handshake_response() {
        // "Because the server's handshake response bears an implicit BTP sequence number of
        // zero, a server SHALL start its acknowledgement-received timer when it sends a
        // handshake response." A server that waited for its first data packet would never
        // notice a client that connected and then vanished.
        let (_, mut server) = pair();
        server.poll_timeout(at(14)).expect("still running");
        assert_eq!(
            server.poll_timeout(at(15)).map_err(|e| e.code()),
            Err(ErrorCode::BtpTimeout)
        );
    }

    #[test]
    fn a_session_that_closes_stays_closed() {
        // §4.19 gives no way to resynchronise, so a caller that misses the first error must
        // not be able to go on reassembling a message out of the fragments either side of it.
        let (mut client, mut server) = pair();
        client.send(b"hello").expect("queue");
        let mut wire = [0u8; 256];
        let n = client
            .poll_send(at(0), &mut wire)
            .expect("send")
            .expect("a packet");
        server.receive(&wire[..n], at(0)).expect("the first packet");

        // A sequence number out of order closes it.
        let mut tampered = wire;
        let sequence_at = usize::from(Frame::decode(&wire[..n]).expect("decode").ack.is_some()) + 1;
        tampered[sequence_at] = 200;
        assert_eq!(
            server.receive(&tampered[..n], at(0)).map_err(|e| e.code()),
            Err(ErrorCode::BtpSequence)
        );
        assert!(server.is_closed());
        assert_eq!(server.close_reason(), Some(ErrorCode::BtpSequence));

        // And everything afterwards reports the same reason, including the well-formed
        // continuation the peer is still sending.
        for code in [
            server.receive(&wire[..n], at(1)).err().map(|e| e.code()),
            server.poll_send(at(1), &mut wire).err().map(|e| e.code()),
            server.send(b"reply").err().map(|e| e.code()),
            server.poll_timeout(at(1)).err().map(|e| e.code()),
        ] {
            assert_eq!(code, Some(ErrorCode::BtpSequence));
        }
    }

    #[test]
    fn an_acknowledgement_for_all_but_the_newest_packet_restarts_the_timer() {
        // "A peer SHALL restart its acknowledgement-received timer when a valid
        // acknowledgement is received for any but its most recently sent unacknowledged
        // packet." Stopping it there instead would leave the newest packet unguarded.
        let (mut client, _) = pair();
        let sdu: heapless::Vec<u8, 900> = (0..900u16).map(|i| i as u8).collect();
        client.send(&sdu).expect("queue");
        let mut wire = [0u8; 256];
        while client.poll_send(at(0), &mut wire).expect("send").is_some() {}
        let outstanding = client.in_flight();
        assert!(outstanding >= 3);

        // Acknowledge all but the last.
        let partial = client.tx_sequence.wrapping_sub(2);
        client
            .receive(&[Flags::ACK.bits(), partial, 1], at(3))
            .expect("ack");
        assert_eq!(client.in_flight(), 1);
        client
            .poll_timeout(at(17))
            .expect("the timer restarted at t = 3");
        assert_eq!(
            client.poll_timeout(at(18)).map_err(|e| e.code()),
            Err(ErrorCode::BtpTimeout)
        );
    }

    #[test]
    fn idleness_is_measured_in_data_not_acknowledgements() {
        // §4.19.4.9: the Central closes a session after CONN_IDLE_TIMEOUT of "no unique data",
        // and acknowledgements keep flowing the whole time — so counting them would keep a
        // dead session open forever.
        let (mut client, mut server) = pair();
        client.send(b"hello").expect("queue");
        let mut wire = [0u8; 256];
        let n = client
            .poll_send(at(0), &mut wire)
            .expect("send")
            .expect("a packet");
        server.receive(&wire[..n], at(0)).expect("receive");
        assert!(!client.is_idle(at(29)));

        // A stand-alone acknowledgement at t = 20 does not count as data.
        let n = server
            .poll_send(at(20), &mut wire)
            .expect("send")
            .expect("an ack");
        client.receive(&wire[..n], at(20)).expect("receive");
        assert!(
            client.is_idle(at(31)),
            "thirty seconds since the last segment"
        );
    }

    #[test]
    fn the_smallest_ble_mtu_still_carries_a_matter_message() {
        // ATT_MTU 23 leaves 20 octets a packet, of which the header takes up to five. This is
        // the configuration where an off-by-one in the header arithmetic turns into an
        // infinite loop rather than a wrong answer.
        let tiny = HandshakeResponse {
            att_mtu: MIN_ATT_MTU,
            ..agreed()
        };
        let mut client = Session::<1280>::new(Role::Client, &tiny.params(), at(0));
        let mut server = Session::<1280>::new(Role::Server, &tiny.params(), at(0));
        let sdu: heapless::Vec<u8, 1280> = (0..1280u16).map(|i| i as u8).collect();
        client.send(&sdu).expect("queue");

        let mut wire = [0u8; 32];
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(guard < 1000, "the transfer must terminate");
            if let Some(n) = client.poll_send(at(0), &mut wire).expect("send") {
                assert!(n <= 20, "a segment never exceeds ATT_MTU - 3");
                if server.receive(&wire[..n], at(0)).expect("receive") == Received::Message {
                    break;
                }
            } else {
                // The window closed; let the server acknowledge and carry on.
                let Some(n) = server.poll_send(at(0), &mut wire).expect("send") else {
                    panic!("neither peer can make progress")
                };
                client.receive(&wire[..n], at(0)).expect("ack");
            }
        }
        assert_eq!(server.message(), sdu.as_slice());
    }
}
