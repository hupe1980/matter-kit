//! Matter over TCP: stream framing (Core §4.5) and what a large message costs (§4.15).
//!
//! > Therefore, nodes that need to send large command messages must use an alternative transport
//! > protocol, such as TCP.
//!
//! UDP caps a Matter message at the IPv6 minimum MTU — 1280 octets, header included — because
//! §4.4.4 will not rely on fragmentation. That is enough for almost everything a device does and
//! not nearly enough for a firmware image, a certificate chain or a wildcard read of a large
//! node. TCP is the way out, and this is the small piece of protocol that makes a byte stream
//! carry discrete messages again.
//!
//! # A length prefix, and only on a stream
//!
//! §4.5: "each Matter Message SHALL be prepended with a Message Length field. This field SHALL
//! only be present when the message is being transmitted over a stream-oriented channel."
//! Four octets, little-endian, and *not* counting itself. Over UDP the datagram's own length
//! says it, so the field is absent — a framer that always prepended one would produce messages
//! no UDP peer could parse.
//!
//! # MRP does not run here
//!
//! §4.15: "Since TCP already provides message transmission reliability, a node that is using TCP
//! as the underlying transport protocol SHALL NOT use MRP reliability semantics on its message
//! exchanges." [`Peer::Tcp`](crate::platform::Peer::Tcp) is what tells
//! [`messaging`](crate::messaging) that, the same way [`Peer::Ble`](crate::platform::Peer::Ble)
//! does for BTP. Setting the **R** flag on a TCP message would ask for an acknowledgement the
//! peer is under no obligation to send, and the sender would retransmit into a stream that had
//! already delivered it.
//!
//! # A message too large is fatal to the connection
//!
//! §4.15.2.3: "If a node receives a message header that indicates that the message is larger
//! than the Maximum Message Size that it supports, then it SHALL close the connection, and
//! SHOULD send a Status Report error message with a status code set to MESSAGE_TOO_LARGE."
//!
//! Close, not skip. A stream has no message boundaries of its own — the length prefix *is* the
//! boundary — so a receiver that could not buffer the message has also lost its place in the
//! stream, and everything after it would be read as a header.

use crate::error::{Error, ErrorCode, Result};
use crate::msg::ProtocolId;
use crate::sc::status::{GeneralCode, StatusReport};

/// §4.5.1: "for TCP, it SHALL be set to 4 bytes to allow for large payloads".
pub const LENGTH_PREFIX: usize = 4;

/// The largest message §4.4.4 permits over a datagram transport, header included.
///
/// Not a TCP limit — it is the reason TCP exists in the specification at all — but a useful
/// figure to compare against: anything at or below it did not need this transport.
pub const DATAGRAM_MAX: usize = 1280;

/// [`DefaultConfig`](crate::DefaultConfig)'s §4.15.2.3 Maximum Message Size, for a node that
/// has not chosen its own.
///
/// The number lives on [`Config::MAX_TCP_MSG`](crate::Config::MAX_TCP_MSG), where a device
/// sizes it along with every other table; this is the same value under the name the framer's
/// `N` is usually written with.
pub const DEFAULT_MAX_MESSAGE: usize = <crate::DefaultConfig as crate::Config>::MAX_TCP_MSG;

/// What a framer produced from the bytes it has so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framed<'a> {
    /// A whole message, with the length prefix stripped.
    Message(&'a [u8]),
    /// Not enough bytes yet. `needed` is how many *more* the framer wants before it can say
    /// anything else — a hint for a reader sizing its next call, never a promise that the
    /// message ends there.
    Incomplete {
        /// Octets still wanted.
        needed: usize,
    },
}

/// Reassembles Matter messages from a byte stream (§4.5).
///
/// `N` is §4.15.2.3's Maximum Message Size: the largest message this node will accept, not
/// counting the prefix. A device chooses it from the memory it actually has, and the choice is
/// visible to peers — §4.15.2.3 expects the number to be a configuration, not a surprise. The
/// four prefix octets are staged separately, so `N` is exactly the buffer a message costs and
/// not four less than one.
///
/// A socket read is offered with [`push`](Self::push), which takes as much as it can hold and
/// says how much that was, and messages are drawn out with [`poll`](Self::poll) until it asks
/// for more bytes. Two messages in one read, or one message across five reads, are the same
/// loop:
///
/// ```
/// use matter_kit::transport::tcp::{self, Framed, Framer};
///
/// let mut framer = Framer::<1280>::new();
/// let mut out = [0u8; 64];
/// let wire = tcp::frame(b"first", &mut out)?.to_vec();
///
/// let mut rest = &wire[..];
/// while !rest.is_empty() {
///     let taken = framer.push(rest)?;
///     rest = &rest[taken..];
///     loop {
///         match framer.poll()? {
///             Framed::Message(message) => assert_eq!(message, b"first"),
///             Framed::Incomplete { .. } => break,
///         }
///     }
/// }
/// # Ok::<(), matter_kit::Error>(())
/// ```
#[derive(Debug)]
pub struct Framer<const N: usize> {
    /// The message being reassembled. Never holds the prefix, so its capacity is `N`.
    body: heapless::Vec<u8, N>,
    /// The length prefix as it arrives, which may be split across reads like anything else.
    prefix: heapless::Vec<u8, LENGTH_PREFIX>,
    /// The length the prefix announced, once a whole prefix has arrived.
    expecting: Option<usize>,
    /// Latched once §4.15.2.3's limit has been exceeded, or a prefix announced nothing.
    ///
    /// The same argument as [`btp`](crate::transport::btp)'s closure: a stream that has lost its
    /// framing cannot recover, so every later call says so rather than returning bytes that are
    /// not messages.
    failed: bool,
    /// Whether the complete message in `body` has already been handed to a caller.
    ///
    /// Dropping it is deferred rather than done on the spot because the message is returned as
    /// a slice *into* `body`: it cannot be cleared while the caller still holds it, and the
    /// borrow checker is what says so. The next call clears it, which is also the next moment
    /// the borrow can have ended.
    taken: bool,
}

impl<const N: usize> Default for Framer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Framer<N> {
    /// An empty framer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            body: heapless::Vec::new(),
            prefix: heapless::Vec::new(),
            expecting: None,
            failed: false,
            taken: false,
        }
    }

    /// §4.15.2.3's Maximum Message Size for this framer.
    #[must_use]
    pub const fn max_message(&self) -> usize {
        N
    }

    /// Whether the stream has been given up on.
    ///
    /// Once true the connection must be closed: §4.15.2.3 says so, and there is no other honest
    /// option — the length prefix is the only message boundary a stream has, so a framer that
    /// could not hold one message no longer knows where the next begins.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.failed
    }

    /// How many octets of a part-built message are held.
    #[must_use]
    pub fn buffered(&self) -> usize {
        if self.taken {
            return 0;
        }
        self.body.len().saturating_add(self.prefix.len())
    }

    /// Adds bytes read from the socket, and says how many it took.
    ///
    /// A framer holds one message at a time, so a read carrying more than that is taken in
    /// parts: the return is the prefix of `bytes` that was consumed, and the caller offers the
    /// rest after [`poll`](Self::poll) has drawn the finished message out. Zero means exactly
    /// that — poll first — and never that the bytes were dropped.
    ///
    /// Returns [`ErrorCode::MessageTooLarge`] when the announced length exceeds `N` or is zero,
    /// having latched the failure: the caller answers §4.15.2.3 by sending [`too_large`] and
    /// closing the connection.
    pub fn push(&mut self, bytes: &[u8]) -> Result<usize> {
        self.guard()?;
        self.drain();
        let mut consumed = 0usize;
        let mut rest = bytes;
        while !rest.is_empty() {
            let took = match self.expecting {
                None => self.take_prefix(rest)?,
                // A whole message already waiting takes nothing: the caller has to poll it out
                // before the buffer is free again.
                Some(length) => self.take_body(rest, length)?,
            };
            if took == 0 {
                break;
            }
            consumed = consumed.saturating_add(took);
            rest = rest.get(took..).unwrap_or(&[]);
        }
        Ok(consumed)
    }

    /// The next whole message, or how many more octets are wanted.
    ///
    /// The message borrows the framer's own buffer, so it stays valid exactly until the next
    /// call — which is also when it is dropped from the buffer. A caller that needs to keep one
    /// longer copies it, and a caller that does not pays nothing.
    pub fn poll(&mut self) -> Result<Framed<'_>> {
        self.guard()?;
        self.drain();
        let Some(length) = self.expecting else {
            return Ok(Framed::Incomplete {
                needed: LENGTH_PREFIX.saturating_sub(self.prefix.len()),
            });
        };
        if self.body.len() < length {
            return Ok(Framed::Incomplete {
                needed: length.saturating_sub(self.body.len()),
            });
        }
        self.taken = true;
        Ok(Framed::Message(&self.body))
    }

    /// Refuses to work a stream that has lost its framing.
    const fn guard(&self) -> Result<()> {
        if self.failed {
            return Err(Error::new(ErrorCode::MessageTooLarge));
        }
        Ok(())
    }

    /// Drops the message the previous call handed out.
    fn drain(&mut self) {
        if !self.taken {
            return;
        }
        self.taken = false;
        self.body.clear();
        self.expecting = None;
    }

    /// Feeds message octets, up to the length the prefix announced.
    fn take_body(&mut self, bytes: &[u8], length: usize) -> Result<usize> {
        let take = length.saturating_sub(self.body.len()).min(bytes.len());
        let Some(chunk) = bytes.get(..take) else {
            return Ok(0);
        };
        self.body
            .extend_from_slice(chunk)
            .map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
        Ok(take)
    }

    /// Feeds the length prefix, and reads it once all four octets have arrived (§4.5.1).
    fn take_prefix(&mut self, bytes: &[u8]) -> Result<usize> {
        let wanted = LENGTH_PREFIX.saturating_sub(self.prefix.len());
        let take = wanted.min(bytes.len());
        let Some(chunk) = bytes.get(..take) else {
            return Ok(0);
        };
        self.prefix
            .extend_from_slice(chunk)
            .map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
        if self.prefix.len() < LENGTH_PREFIX {
            return Ok(take);
        }
        let bytes = <[u8; LENGTH_PREFIX]>::try_from(self.prefix.as_slice())
            .map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
        self.prefix.clear();
        // §4.5.1: "an unsigned integer value, in little-endian byte order".
        let length = usize::try_from(u32::from_le_bytes(bytes))
            .map_err(|_| Error::new(ErrorCode::MessageTooLarge))?;
        // Zero is not a short message: §4.4's header is at least eight octets, so a prefix of
        // zero is a stream that has lost its framing, exactly like one that is too long.
        // §4.15.2.3: close the connection. Latching means a caller that ignores the error still
        // cannot be handed bytes that are not a message.
        if length == 0 || length > N {
            self.failed = true;
            return Err(Error::new(ErrorCode::MessageTooLarge));
        }
        self.expecting = Some(length);
        Ok(take)
    }
}

/// Writes `message` onto a stream with §4.5's length prefix.
///
/// The prefix does not count itself — §4.5.1: "the overall length of the message in bytes, not
/// including the size of this field itself" — which is the one thing easy to get wrong and
/// impossible to notice locally, because a framer written with the same mistake reads it back.
pub fn frame<'b>(message: &[u8], buf: &'b mut [u8]) -> Result<&'b [u8]> {
    let total = LENGTH_PREFIX
        .checked_add(message.len())
        .ok_or_else(|| Error::new(ErrorCode::MessageTooLarge))?;
    if total > buf.len() {
        return Err(Error::new(ErrorCode::BufferTooSmall));
    }
    let length =
        u32::try_from(message.len()).map_err(|_| Error::new(ErrorCode::MessageTooLarge))?;
    let (prefix, rest) = buf
        .split_at_mut_checked(LENGTH_PREFIX)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
    prefix.copy_from_slice(&length.to_le_bytes());
    let body = rest
        .get_mut(..message.len())
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
    body.copy_from_slice(message);
    buf.get(..total)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))
}

/// §4.15.2.3's `MESSAGE_TOO_LARGE` report, to send before closing the connection.
///
/// "SHOULD send a Status Report error message with a status code set to MESSAGE_TOO_LARGE back
/// to the sender, before closing the connection" — a courtesy that turns an unexplained
/// disconnect into something the peer can act on, by sending less.
pub fn too_large(buf: &mut [u8]) -> Result<&[u8]> {
    let written = StatusReport {
        general: GeneralCode::MessageTooLarge,
        protocol: ProtocolId::SECURE_CHANNEL,
        protocol_code: 0,
        data: &[],
    }
    .encode(buf)?;
    buf.get(..written)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))
}
