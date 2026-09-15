//! Sending and receiving a group message (Core §4.16.2, §4.16.3, §4.18.4).
//!
//! Not part of [`Messaging`](crate::messaging::Messaging), and deliberately: §4.16 has no
//! session, no exchange and no reply, so everything that layer does — routing to an exchange,
//! arming MRP, acknowledging — is either absent or wrong here. What is left is the message
//! layer's own work, done against a key found by trying candidates rather than by session id.

use crate::error::{Error, ErrorCode, Result, bail};
use crate::msg::{
    Destination, MessageCounter, MessageHeader, NonceSource, ProtocolHeader, SessionId,
    SessionKeys, SessionType, preview, protect, unprotect,
};
use crate::msg::{FabricIndex, GroupId, NodeId};
use crate::platform::PeerAddr;

use super::GroupContext;
use super::keys::{GroupKeys, OperationalKey};
use super::peers::{Admitted, PeerTable};

/// The sending half: the two group counter spaces this node owns (§4.6.1).
///
/// A group message's counter is free-running and rolls over (§4.6.5.2.2) — unlike a session's,
/// which must never repeat, because a group counter's nonce is diversified by the Source Node ID
/// as well.
#[derive(Debug)]
pub struct Sender {
    node: NodeId,
    data: MessageCounter,
    control: MessageCounter,
}

impl Sender {
    /// A sender for `node`, with its two counters started where the caller says.
    ///
    /// §4.6.1.1 has a node choose its initial counters at random on boot, so these come from
    /// [`Rng`](crate::platform::Rng) rather than from zero: starting at zero would make every
    /// message this node has ever sent replayable against a peer that had not heard from it
    /// since its last boot. Pass the random words as they come —
    /// [`MessageCounter::new`](crate::msg::MessageCounter::new) narrows each to the range
    /// §4.6.1.1 specifies.
    ///
    /// This is the **factory-reset** path. §4.6.1.3 randomises these two counters once, on a
    /// factory reset, and requires them to be persisted and never to roll back after that — so
    /// a node that has run before restores them with [`restore`](Self::restore) instead, and
    /// calling this on every boot would rewind them and reuse a nonce.
    #[must_use]
    pub const fn new(node: NodeId, data: u32, control: u32) -> Self {
        Self {
            node,
            data: MessageCounter::new(data),
            control: MessageCounter::new(control),
        }
    }

    /// A sender whose counters come from durable storage, at exactly the values given.
    ///
    /// §4.6.1.3: "Nodes are required to persist the Global Group Encrypted Message Counters in
    /// durable storage. In particular, Nodes are required to ensure that the value of the
    /// Global Group Encrypted Message Counters never rolls back". Unlike [`new`](Self::new)
    /// these values are taken as they are: they are not a random seed, they are where this node
    /// actually was, and narrowing them to §4.6.1.1's range would roll them back by up to 2³²
    /// and reuse every nonce since.
    ///
    /// Persist *ahead* of where the counter stands, as §4.6.3 describes for the Check-In
    /// counter: a node that stores every value writes flash on every message, and one that
    /// stores the value it is at loses the writes it had not flushed when it lost power.
    #[must_use]
    pub const fn restore(node: NodeId, data: u32, control: u32) -> Self {
        Self {
            node,
            data: MessageCounter::at(data),
            control: MessageCounter::at(control),
        }
    }

    /// The node these messages say they are from.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Builds one group message (§4.16.2).
    ///
    /// `scratch` joins the protocol header and the payload for the AEAD, as on a unicast
    /// session; `out` takes the finished message, which the caller sends to
    /// [`multicast_address`](super::multicast_address) on
    /// [`PORT`](crate::PORT).
    ///
    /// §4.16.2 step 2c: "The Security Flags SHALL have only the P Flag set" — a group message is
    /// always privacy-obfuscated, because the whole point of the address is that anyone on the
    /// link can see it.
    #[expect(
        clippy::too_many_arguments,
        reason = "every one is a distinct fact about the message, the way `Messaging::send`'s \
                  are; bundling them would move the same list one line up"
    )]
    pub fn send(
        &mut self,
        key: &OperationalKey,
        group: GroupId,
        protocol_header: &ProtocolHeader,
        payload: &[u8],
        control: bool,
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let counter = if control {
            self.control.take_with_rollover()
        } else {
            self.data.take_with_rollover()
        };
        let header = MessageHeader {
            session_id: SessionId(key.session_id),
            session_type: SessionType::Group,
            message_counter: counter,
            // §4.16.1: the Source Node ID is what identifies the sender to every receiver, and
            // §4.8.1.1 folds it into the nonce — so unlike a unicast session it is never elided.
            source: Some(self.node),
            destination: Destination::Group(group),
            privacy: true,
            control,
        };
        let body = join(protocol_header, payload, scratch)?;
        let keys = SessionKeys::from_encryption_key(key.key.clone())?;
        protect(&header, NonceSource::Group, body, &keys, out)
    }
}

/// A group message that authenticated and was fresh (§4.16.1, §4.18.4).
#[derive(Debug)]
pub struct Inbound<'a> {
    /// §4.16.1's Groupcast Session Context.
    pub context: GroupContext,
    /// The protocol header it carried.
    pub protocol: ProtocolHeader,
    /// The payload, decrypted in place.
    pub payload: &'a [u8],
    /// The message counter it carried, which an [`mcsp`](super::mcsp) exchange would be about.
    pub counter: u32,
    /// Whether the **C** flag was set, so this is a control message (§4.18.1.1).
    pub control: bool,
}

/// What [`receive`] concluded.
#[derive(Debug)]
pub enum Received<'a> {
    /// Authenticated, fresh, and for the layer above.
    Message(Inbound<'a>),
    /// Authenticated but a duplicate or too old (§4.6.5). Dropped — a group message is never
    /// reliable, so there is nothing to acknowledge.
    Duplicate(GroupContext),
    /// Authenticated, but the sender's counter is unknown under a cache-and-sync key.
    ///
    /// §4.18.4 step 3c: hold the message and run [`mcsp`](super::mcsp) first. The context says
    /// who to ask and under which key.
    NeedsSync(GroupContext),
    /// Authenticated, but §4.16.1's peer table is full and "any message from a source that
    /// cannot be tracked SHALL be dropped".
    Untracked(GroupContext),
}

/// Processes one datagram that arrived on a group multicast address (§4.16.3, §4.18.4).
///
/// `buf` is decrypted in place, so everything returned borrows it. `compressed` maps a fabric
/// index to its compressed identifier, which is the salt every operational group key is derived
/// with — the fabric table owns that, not this module.
///
/// Every candidate key for the message's Group Session ID is tried, because §4.17.3.6 says the
/// id "SHALL NOT be used as the sole means to locate the associated Operational Group Key, since
/// it MAY collide within the fabric". A failed candidate leaves `buf` unusable for the next one,
/// so each attempt works on a copy of the ciphertext in `scratch`.
pub fn receive<'b, const K: usize, const M: usize, const D: usize, const C: usize>(
    buf: &'b mut [u8],
    from: PeerAddr,
    keys: &GroupKeys<K, M>,
    peers: &mut PeerTable<D, C>,
    compressed: impl Fn(FabricIndex) -> Option<crate::fabric::CompressedFabricId>,
    scratch: &mut [u8],
) -> Result<Received<'b>> {
    let head = preview(buf)?;
    if !matches!(head.session_type, SessionType::Group) {
        // A unicast message belongs to `Messaging::receive`; taking it here would skip the
        // session lookup that is the only thing binding it to a peer.
        bail!(InvalidArgument)
    }
    let original = scratch
        .get_mut(..buf.len())
        .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
    original.copy_from_slice(buf);

    // §4.17.3.6: every installed key whose session id matches, in turn.
    let candidates = keys.receiving_keys::<8>(compressed, head.session_id.0);
    let mut authenticated = None;
    for candidate in &candidates {
        let Ok(session_keys) = SessionKeys::from_encryption_key(candidate.key.clone()) else {
            continue;
        };
        // A failed AEAD leaves the buffer undefined (§3.6.2), so each attempt starts from the
        // untouched ciphertext.
        buf.copy_from_slice(original);
        if let Ok((header, range)) = unprotect(buf, &session_keys, NonceSource::Group) {
            authenticated = Some((candidate, header, range));
            break;
        }
    }
    let Some((key, header, range)) = authenticated else {
        bail!(IntegrityCheckFailed)
    };

    // §4.4.1.5 and §4.8.1.1: a group message carries its Source Node ID, and the nonce is built
    // from it — `unprotect` would have failed without one, but naming the requirement here is
    // what stops a later change from quietly dropping it.
    let source = header
        .source
        .ok_or(Error::new(ErrorCode::MessageReserved))?;
    let Destination::Group(group) = header.destination else {
        // The Session Type said group; the DSIZ must agree, or the two halves of the header
        // describe different messages.
        bail!(MessageReserved)
    };
    let context = GroupContext {
        fabric_index: key.fabric_index,
        group,
        source,
        from,
        session_id: header.session_id.0,
        key_set: key.key_set,
    };

    // Authenticated. Only now may any counter move (§4.7.2).
    let admitted = peers.admit(
        key.fabric_index,
        source,
        header.control,
        header.message_counter,
        key.policy,
    );
    match admitted {
        Admitted::Duplicate => return Ok(Received::Duplicate(context)),
        Admitted::NeedsSync => return Ok(Received::NeedsSync(context)),
        Admitted::Untracked => return Ok(Received::Untracked(context)),
        Admitted::Process => {}
    }

    let Some(payload) = buf.get(range) else {
        bail!(MessageTruncated)
    };
    let (protocol, body) = ProtocolHeader::decode(payload)?;
    Ok(Received::Message(Inbound {
        context,
        protocol,
        payload: body,
        counter: header.message_counter,
        control: header.control,
    }))
}

/// Joins the protocol header and the payload for the AEAD, as a unicast session does.
fn join<'a>(
    protocol_header: &ProtocolHeader,
    payload: &[u8],
    scratch: &'a mut [u8],
) -> Result<&'a [u8]> {
    let header_len = protocol_header.encode(scratch)?;
    let end = header_len
        .checked_add(payload.len())
        .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
    let slot = scratch
        .get_mut(header_len..end)
        .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
    slot.copy_from_slice(payload);
    scratch
        .get(..end)
        .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))
}
