//! Negotiating a BDX session and keeping it honest (§11.22.5, §11.22.6.1).
//!
//! Nothing here encodes or decodes. [`message`](super::message) does that; this is the part
//! that says whether a message was *allowed* — the block counters are in order, the blocks are
//! within the negotiated size, the promised number of bytes actually arrived — and it says so
//! with the [`StatusCode`] the peer has to be told, because that is the whole content of a
//! BDX failure.

use super::message::{Init, MessageType, ReceiveAccept, SendAccept, TransferControl, VERSION};
use super::{Rejected, StatusCode};

/// Where §11.22.6.1's counters start.
///
/// §11.22.6.2 says the block counter "SHOULD start at 0 at the start of the transfer", and
/// §11.22.6.5 states it as fact for the trivial case: "In that trivial case, the Block Counter
/// would be 0 in the BlockEOF." Both halves here require it rather than adopting whatever the
/// first message carried — a Sender and a Receiver that each picked their own starting point
/// would disagree on every counter after it, and §11.22.6.1's only tool for noticing is the
/// comparison that would then always fail.
const FIRST_COUNTER: u32 = 0;

/// A block size that fits a Matter message over any transport.
///
/// 1024 octets leaves comfortable room under §4.4.4's 1280-octet datagram limit for the
/// message header, the block counter and the AEAD tag. A transfer over TCP can negotiate far
/// more; this is the figure that always works.
pub const DEFAULT_MAX_BLOCK_SIZE: u16 = 1024;

/// Which Init started the transfer, and so which end sends the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `SendInit`: the Initiator is the Sender (§11.22.2.3).
    Upload,
    /// `ReceiveInit`: the Initiator is the Receiver — an OTA image, a diagnostic log.
    Download,
}

impl Direction {
    /// The opcode that opens the transfer.
    #[must_use]
    pub const fn init(self) -> MessageType {
        match self {
            Self::Upload => MessageType::SendInit,
            Self::Download => MessageType::ReceiveInit,
        }
    }

    /// The opcode that accepts it.
    #[must_use]
    pub const fn accept(self) -> MessageType {
        match self {
            Self::Upload => MessageType::SendAccept,
            Self::Download => MessageType::ReceiveAccept,
        }
    }
}

/// What a Responder will agree to.
///
/// Every field is a reason §11.22.5.1 gives for rejecting an Init, turned into a number the
/// application sets once instead of a check it has to remember to write.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The largest block this node will handle. The negotiated size is the smaller of this and
    /// the Initiator's proposal.
    pub max_block_size: u16,
    /// The largest definite length to accept — `LENGTH_TOO_LARGE` past it.
    pub max_length: Option<u64>,
    /// The smallest definite length that makes sense here — `LENGTH_TOO_SHORT` under it.
    pub min_length: Option<u64>,
    /// Whether a transfer may proceed without a definite length — `LENGTH_REQUIRED` if not.
    pub require_definite_length: bool,
    /// Whether a non-zero start offset is supported — `START_OFFSET_NOT_SUPPORTED` if not.
    ///
    /// §11.22.5.1.3: "Receivers are not required to accept non-zero start offset transfers.
    /// Devices SHOULD make every attempt to support non-zero start offset."
    pub allow_start_offset: bool,
    /// How much data this node actually has past the start offset, for a
    /// [`Download`](Direction::Download).
    ///
    /// §11.22.5.4.4 is the reason this exists: the accepted length is the proposed one only
    /// when the file is that big, and "smaller than the proposed definite length, if the
    /// remaining data in the file beyond the Start Offset is smaller than the proposed length".
    pub available: Option<u64>,
    /// Whether to turn the transfer away with `RESPONDER_BUSY`. §11.22.5.1: an Initiator
    /// "SHOULD wait at least 60 seconds" before trying again.
    pub busy: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            max_length: None,
            min_length: None,
            require_definite_length: false,
            allow_start_offset: true,
            available: None,
            busy: false,
        }
    }
}

/// The parameters both ends settled on: what the Accept message says, in one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    /// The chosen version and the one chosen drive mode.
    pub control: TransferControl,
    /// The Max Block Size in force. A block may be shorter; none may be longer.
    pub max_block_size: u16,
    /// Where in the file the transfer starts.
    pub start_offset: u64,
    /// The number of octets that will be transferred, when it is known in advance. `None` is
    /// §11.22.5.1.5's indefinite length, and turns off the end-of-transfer length check.
    pub length: Option<u64>,
}

impl Parameters {
    /// Whether the Sender paces the transfer (`TC[SENDER_DRIVE]`).
    #[must_use]
    pub const fn sender_drives(&self) -> bool {
        self.control.sender_drive
    }

    /// Whether the Receiver paces it with BlockQuery messages (`TC[RECEIVER_DRIVE]`).
    #[must_use]
    pub const fn receiver_drives(&self) -> bool {
        self.control.receiver_drive
    }

    /// The `SendAccept` that carries these parameters (§11.22.5.2).
    #[must_use]
    pub const fn send_accept<'a>(&self, metadata: &'a [u8]) -> SendAccept<'a> {
        SendAccept {
            control: self.control,
            max_block_size: self.max_block_size,
            metadata,
        }
    }

    /// The `ReceiveAccept` that carries these parameters (§11.22.5.3).
    #[must_use]
    pub const fn receive_accept<'a>(&self, metadata: &'a [u8]) -> ReceiveAccept<'a> {
        ReceiveAccept {
            control: self.control,
            max_block_size: self.max_block_size,
            length: self.length,
            metadata,
        }
    }

    /// Checks a Responder's `SendAccept` against what was proposed, for an upload.
    ///
    /// §11.22.5.1: "The parameters in the SendAccept/ReceiveAccept message SHALL be used in the
    /// transfer. If those parameters are unacceptable to the Initiator, it SHALL abort the
    /// transfer with an appropriate error."
    pub fn from_send_accept(proposed: &Init<'_>, accept: &SendAccept<'_>) -> Rejected<Self> {
        let control = check_accepted(proposed.control, accept.control)?;
        Ok(Self {
            control,
            max_block_size: check_block_size(proposed.max_block_size, accept.max_block_size)?,
            start_offset: proposed.start_offset.unwrap_or(0),
            // A SendAccept has no length field: the Sender said how much it would send, and a
            // Responder that could not take that much had to reject the SendInit instead.
            length: proposed.definite_length,
        })
    }

    /// Checks a Responder's `ReceiveAccept` against what was proposed, for a download.
    pub fn from_receive_accept(proposed: &Init<'_>, accept: &ReceiveAccept<'_>) -> Rejected<Self> {
        let control = check_accepted(proposed.control, accept.control)?;
        if let (Some(asked), Some(offered)) = (proposed.definite_length, accept.length) {
            // §11.22.5.4.4: the accepted length is the proposed one, or smaller when the file
            // is. Larger is the Responder answering a question that was not asked.
            if offered > asked {
                return Err(StatusCode::LengthTooLarge);
            }
        }
        Ok(Self {
            control,
            max_block_size: check_block_size(proposed.max_block_size, accept.max_block_size)?,
            start_offset: proposed.start_offset.unwrap_or(0),
            length: accept.length,
        })
    }
}

/// The Responder's half of §11.22.5.1: accept an Init, or say why not.
///
/// The returned parameters go straight into [`Parameters::send_accept`] or
/// [`Parameters::receive_accept`] and into a [`Sender`] or [`Receiver`]; the error goes into a
/// [`StatusReport`](crate::sc::StatusReport) via [`report`](super::report).
pub fn negotiate(direction: Direction, init: &Init<'_>, limits: &Limits) -> Rejected<Parameters> {
    if limits.busy {
        return Err(StatusCode::ResponderBusy);
    }
    if init.max_block_size == 0 {
        return Err(StatusCode::BadMessageContents);
    }
    // §11.22.5.1.1: "At least one of the PTC[RECEIVER_DRIVE] or PTC[SENDER_DRIVE] field bits
    // SHALL be set in order for the Responder to set the final transfer control."
    if !init.control.sender_drive && !init.control.receiver_drive {
        return Err(StatusCode::TransferMethodNotSupported);
    }
    let start_offset = match init.start_offset {
        // §11.22.5.1.3 speaks of the *presence* of the field, not of a non-zero value.
        Some(_) if !limits.allow_start_offset => return Err(StatusCode::StartOffsetNotSupported),
        Some(offset) => offset,
        None => 0,
    };
    if let Some(length) = init.definite_length {
        if limits.max_length.is_some_and(|max| length > max) {
            return Err(StatusCode::LengthTooLarge);
        }
        if limits.min_length.is_some_and(|min| length < min) {
            return Err(StatusCode::LengthTooShort);
        }
    } else if limits.require_definite_length {
        return Err(StatusCode::LengthRequired);
    }
    let length = match direction {
        // The Initiator is the Sender and committed to a size; there is no field to answer it
        // with, so the only choices were to take it or to have rejected it above.
        Direction::Upload => init.definite_length,
        // §11.22.5.4.4: the Responder is the Sender and knows what the file actually holds.
        Direction::Download => match (init.definite_length, limits.available) {
            (Some(asked), Some(have)) => Some(asked.min(have)),
            (Some(asked), None) => Some(asked),
            (None, have) => have,
        },
    };
    Ok(Parameters {
        control: TransferControl {
            // §11.22.5.4.1: "the newest version that is supported by the Responder and is not
            // newer than the proposed version". This crate speaks only version 0, the one BDX
            // has had since Matter 1.0, and 0 is never newer than anything — so there is no
            // version a proposal could carry that VERSION_NOT_SUPPORTED would answer.
            version: VERSION,
            // "If the Initiator proposed both … the Responder SHALL default to
            // TC[SENDER_DRIVE]", which keeps the request/response shape.
            sender_drive: init.control.sender_drive,
            receiver_drive: init.control.receiver_drive && !init.control.sender_drive,
            // "Support for the asynchronous mode is provisional and SHALL not be chosen by the
            // Responder."
            asynchronous: false,
        },
        max_block_size: init.max_block_size.min(limits.max_block_size),
        start_offset,
        length,
    })
}

/// Checks the Transfer Control an Accept came back with (§11.22.5.4.1).
fn check_accepted(
    proposed: TransferControl,
    accepted: TransferControl,
) -> Rejected<TransferControl> {
    if accepted.version > proposed.version {
        return Err(StatusCode::VersionNotSupported);
    }
    // Provisional, and a Responder is told not to choose it — so a transfer that comes back
    // asynchronous is one this crate will not drive.
    if accepted.asynchronous || !accepted.is_decided() {
        return Err(StatusCode::TransferMethodNotSupported);
    }
    let offered = (accepted.sender_drive && proposed.sender_drive)
        || (accepted.receiver_drive && proposed.receiver_drive);
    if !offered {
        return Err(StatusCode::TransferMethodNotSupported);
    }
    Ok(accepted)
}

/// §11.22.5.4.3: the accepted Max Block Size "SHALL be less than or equal to the proposed max
/// block size".
fn check_block_size(proposed: u16, accepted: u16) -> Rejected<u16> {
    if accepted == 0 || accepted > proposed {
        return Err(StatusCode::BadMessageContents);
    }
    Ok(accepted)
}

/// The data-carrying half of a transfer: what a Sender may send next, and when.
///
/// Whether this node is the Initiator or the Responder does not change any rule here — only
/// [`Parameters::control`] does, by saying which end drives.
#[derive(Debug)]
pub struct Sender {
    params: Parameters,
    /// Where in the file the next block is read from. Moves with the data sent *and* with a
    /// `BlockQueryWithSkip`, which is the only reason it is not `start_offset + sent`.
    cursor: u64,
    sent: u64,
    /// The counter of the last block sent, once one has been.
    counter: Option<u32>,
    /// A `BlockQuery` is outstanding, so a driving Receiver is waiting for a block.
    queried: bool,
    /// The last block sent was a `BlockEOF`.
    finished: bool,
    /// A `BlockAckEOF` closed the session (§11.22.2.8).
    complete: bool,
}

impl Sender {
    /// A Sender that has agreed `params` and sent nothing.
    #[must_use]
    pub const fn new(params: Parameters) -> Self {
        Self {
            cursor: params.start_offset,
            params,
            sent: 0,
            counter: None,
            queried: false,
            finished: false,
            complete: false,
        }
    }

    /// The negotiated parameters.
    #[must_use]
    pub const fn parameters(&self) -> &Parameters {
        &self.params
    }

    /// The offset in the file the next block should be read from.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// How many octets have been put into blocks so far.
    #[must_use]
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    /// Whether the Receiver has acknowledged the `BlockEOF`, ending the session.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Whether a block may be sent right now.
    ///
    /// In Sender drive, always, until the end. In Receiver drive, only while a `BlockQuery` is
    /// outstanding — which is the whole point of the mode: a sleepy Receiver is not woken by
    /// blocks it did not ask for.
    #[must_use]
    pub const fn may_send(&self) -> bool {
        if self.finished || self.complete {
            return false;
        }
        self.params.control.sender_drive || self.queried
    }

    /// The largest block that may be sent next: the negotiated size, or what is left of a
    /// definite length if that is smaller.
    #[must_use]
    pub fn room(&self) -> usize {
        let block = usize::from(self.params.max_block_size);
        match self.params.length {
            Some(length) => usize::try_from(length.saturating_sub(self.sent))
                .unwrap_or(usize::MAX)
                .min(block),
            None => block,
        }
    }

    /// Takes a `BlockQuery` from a driving Receiver (§11.22.6.2).
    pub fn on_query(&mut self, counter: u32) -> Rejected<()> {
        self.on_query_with_skip(counter, 0).map(|_| ())
    }

    /// Takes a `BlockQueryWithSkip` (§11.22.6.3) and returns the cursor it moved to.
    ///
    /// Skipping past the end of the file is explicitly not an error: "there SHALL be no error
    /// indicated when receiving a request to skip past the end of the transferable data", and
    /// the answer is an empty `BlockEOF`.
    pub fn on_query_with_skip(&mut self, counter: u32, bytes_to_skip: u64) -> Rejected<u64> {
        if self.finished || self.complete {
            return Err(StatusCode::UnexpectedMessage);
        }
        // A query is what a *driving Receiver* sends. In Sender drive nobody may ask.
        if !self.params.control.receiver_drive {
            return Err(StatusCode::UnexpectedMessage);
        }
        if self.queried {
            return Err(StatusCode::UnexpectedMessage);
        }
        if counter != self.next_counter() {
            return Err(StatusCode::BadBlockCounter);
        }
        self.queried = true;
        self.cursor = self.cursor.saturating_add(bytes_to_skip);
        Ok(self.cursor)
    }

    /// Registers a block of `len` octets, and returns the Block Counter to put in it.
    ///
    /// `eof` chooses between a `Block` and a `BlockEOF`, and the difference is not only the
    /// opcode: §11.22.6.4 requires a `Block` to carry at least one octet, while §11.22.6.5
    /// allows an empty `BlockEOF` "to indicate an empty file".
    pub fn block(&mut self, len: usize, eof: bool) -> Rejected<u32> {
        if !self.may_send() {
            return Err(StatusCode::UnexpectedMessage);
        }
        if len > usize::from(self.params.max_block_size) || (len == 0 && !eof) {
            return Err(StatusCode::BadMessageContents);
        }
        let len64 = u64::try_from(len).unwrap_or(u64::MAX);
        let total = self
            .sent
            .checked_add(len64)
            .ok_or(StatusCode::LengthTooLarge)?;
        if let Some(length) = self.params.length {
            // The Sender committed to exactly this many octets: overrunning it, or stopping
            // early, is the discrepancy §11.22.6.5 has the Receiver fail the transfer over.
            if total > length || (eof && total != length) {
                return Err(StatusCode::LengthMismatch);
            }
        }
        let counter = self.next_counter();
        self.counter = Some(counter);
        self.sent = total;
        self.cursor = self.cursor.saturating_add(len64);
        self.queried = false;
        self.finished = eof;
        Ok(counter)
    }

    /// Takes a `BlockAck` or `BlockAckEOF` (§11.22.6.6, §11.22.6.7).
    pub fn on_ack(&mut self, counter: u32, eof: bool) -> Rejected<()> {
        let Some(last) = self.counter else {
            return Err(StatusCode::UnexpectedMessage);
        };
        if self.complete {
            return Err(StatusCode::UnexpectedMessage);
        }
        // §11.22.6.7: a BlockAckEOF answers a BlockEOF and nothing else, and a plain BlockAck
        // does not end a session.
        if eof != self.finished {
            return Err(StatusCode::UnexpectedMessage);
        }
        if counter != last {
            return Err(StatusCode::BadBlockCounter);
        }
        self.complete = eof;
        Ok(())
    }

    /// §11.22.6.1: ascending, sequential, "modulo 2^32 integer arithmetic".
    const fn next_counter(&self) -> u32 {
        match self.counter {
            Some(last) => last.wrapping_add(1),
            None => FIRST_COUNTER,
        }
    }
}

/// The receiving half: what a Receiver may accept next, and what it owes the Sender.
#[derive(Debug)]
pub struct Receiver {
    params: Parameters,
    received: u64,
    /// The counter of the last block taken, once one has been.
    counter: Option<u32>,
    /// The counter of the next query to send, in Receiver drive.
    query: u32,
    /// A block has arrived and has not been acknowledged.
    pending: bool,
    /// The last block taken was a `BlockEOF`.
    finished: bool,
    /// A `BlockAckEOF` has been sent, ending the session.
    complete: bool,
}

impl Receiver {
    /// A Receiver that has agreed `params` and taken nothing.
    #[must_use]
    pub const fn new(params: Parameters) -> Self {
        Self {
            params,
            received: 0,
            counter: None,
            query: FIRST_COUNTER,
            pending: false,
            finished: false,
            complete: false,
        }
    }

    /// The negotiated parameters.
    #[must_use]
    pub const fn parameters(&self) -> &Parameters {
        &self.params
    }

    /// How many octets have arrived.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// Whether the session has ended with a `BlockAckEOF` (§11.22.2.8).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// The Block Counter for the next `BlockQuery` or `BlockQueryWithSkip` (§11.22.6.2).
    ///
    /// A query "implies a BlockAck of the previous block if no BlockAck was explicitly sent",
    /// so asking for the next block also clears the outstanding acknowledgement.
    pub fn query(&mut self) -> Rejected<u32> {
        if !self.params.control.receiver_drive || self.finished || self.complete {
            return Err(StatusCode::UnexpectedMessage);
        }
        // One query at a time: the transfer "consists of a series of request/responses, each
        // one initiated by the Driver" (§11.22.2.6), and a second query before the first is
        // answered is two outstanding requests.
        if self.awaiting() {
            return Err(StatusCode::UnexpectedMessage);
        }
        self.pending = false;
        let counter = self.query;
        self.query = self.query.wrapping_add(1);
        Ok(counter)
    }

    /// Takes a `Block` or `BlockEOF` (§11.22.6.4, §11.22.6.5).
    ///
    /// `len` is the data length, which the caller has in hand either way; the data itself is
    /// the application's to store.
    pub fn on_block(&mut self, counter: u32, len: usize, eof: bool) -> Rejected<()> {
        if self.finished || self.complete {
            return Err(StatusCode::UnexpectedMessage);
        }
        // In Receiver drive a block answers a query; one that answers nothing is a Sender that
        // did not wait.
        if self.params.control.receiver_drive && !self.awaiting() {
            return Err(StatusCode::UnexpectedMessage);
        }
        if counter != self.next_counter() {
            return Err(StatusCode::BadBlockCounter);
        }
        if len > usize::from(self.params.max_block_size) || (len == 0 && !eof) {
            return Err(StatusCode::BadMessageContents);
        }
        let len64 = u64::try_from(len).unwrap_or(u64::MAX);
        let total = self
            .received
            .checked_add(len64)
            .ok_or(StatusCode::LengthTooLarge)?;
        if let Some(length) = self.params.length {
            // §11.22.6.5: "the recipient SHALL verify that the pre-negotiated file size was
            // transferred". Too much is as wrong as too little, and is caught a block earlier.
            if total > length || (eof && total != length) {
                return Err(StatusCode::LengthMismatch);
            }
        }
        self.received = total;
        self.counter = Some(counter);
        self.pending = true;
        self.finished = eof;
        Ok(())
    }

    /// Acknowledges the block just taken: the opcode to send and the counter to put in it.
    ///
    /// §11.22.6.6: the Block Counter "SHALL correspond to the Block Counter which was embedded
    /// in the Block being acknowledged", so it is never the caller's to choose.
    pub fn ack(&mut self) -> Rejected<(MessageType, u32)> {
        let (Some(counter), true) = (self.counter, self.pending) else {
            return Err(StatusCode::UnexpectedMessage);
        };
        self.pending = false;
        self.complete = self.finished;
        Ok((
            if self.finished {
                MessageType::BlockAckEof
            } else {
                MessageType::BlockAck
            },
            counter,
        ))
    }

    /// Whether a query has gone out that no block has answered.
    const fn awaiting(&self) -> bool {
        // `query` counts queries sent; `counter` the blocks taken. They are equal exactly when
        // every query has been answered.
        match self.counter {
            Some(last) => self.query != last.wrapping_add(1),
            None => self.query != FIRST_COUNTER,
        }
    }

    /// §11.22.6.1: ascending, sequential, modulo 2^32.
    const fn next_counter(&self) -> u32 {
        match self.counter {
            Some(last) => last.wrapping_add(1),
            None => FIRST_COUNTER,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agreed(sender_drive: bool) -> Parameters {
        Parameters {
            control: TransferControl {
                version: VERSION,
                sender_drive,
                receiver_drive: !sender_drive,
                asynchronous: false,
            },
            max_block_size: 16,
            start_offset: 0,
            length: None,
        }
    }

    /// §11.22.6.1: "if the last Block Counter was 0xFFFF_FFFF, the next expected Block Counter
    /// would be 0x0000_0000". Reaching that by counting would take four billion blocks, so the
    /// counter is set directly — this is the one rule an integration test cannot get at.
    #[test]
    fn block_counters_wrap_at_2_to_the_32() {
        let mut sender = Sender::new(agreed(true));
        sender.counter = Some(u32::MAX);
        assert_eq!(sender.block(4, false), Ok(0));

        let mut receiver = Receiver::new(agreed(true));
        receiver.counter = Some(u32::MAX);
        assert_eq!(receiver.on_block(0, 4, false), Ok(()));
        // And one that did not wrap is still out of order.
        let mut receiver = Receiver::new(agreed(true));
        receiver.counter = Some(u32::MAX);
        assert_eq!(
            receiver.on_block(1, 4, false),
            Err(StatusCode::BadBlockCounter)
        );
    }

    #[test]
    fn a_query_wraps_the_same_way() {
        let mut sender = Sender::new(agreed(false));
        sender.counter = Some(u32::MAX);
        assert_eq!(sender.on_query(0), Ok(()));
    }
}
