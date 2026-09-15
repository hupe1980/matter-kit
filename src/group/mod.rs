//! Group communication: one message, many nodes (Core §4.16, §4.17, §4.18).
//!
//! Needs the `rustcrypto` feature: every operational group key is derived with
//! [`crypto`](crate::crypto)'s KDF from [`fabric`](crate::fabric)'s compressed identifier.
//!
//! A wall switch that controls twenty lights cannot send twenty messages. §4.16 is the
//! alternative: one IPv6 multicast datagram addressed by a 16-bit **Group ID**, encrypted under
//! a symmetric key every member of the group holds.
//!
//! That one sentence is also the whole of the difficulty. A group message has no session, no
//! exchange, no acknowledgement and no reply — so everything a unicast session gives for free
//! has to be rebuilt:
//!
//! * **Which key?** §4.17.3.6's [`Group Session ID`](session_id) narrows the candidates, and
//!   narrowing is all it does: "It SHALL NOT be used as the sole means to locate the associated
//!   Operational Group Key, since it MAY collide within the fabric." Every candidate is tried
//!   until the MIC passes.
//! * **Is it fresh?** There is no handshake to agree a starting counter, so §4.18's
//!   [`PeerTable`] tracks one per sender, and the [`GroupKeySecurityPolicy`] on the key chooses
//!   between trusting the first counter seen and synchronising over [`mcsp`].
//! * **Who sent it?** §4.16.1's [`GroupContext`] — fabric, group, source node — is what the
//!   layer above is given in place of a session.
//!
//! # Keys are derived, not distributed
//!
//! §4.17.2: an **epoch key** is what an administrator installs, and the key a message is
//! actually encrypted under is
//! [`operational_group_key`](crate::fabric::operational_group_key) — the epoch key salted with
//! the fabric's compressed identifier. So the same epoch key gives different operational keys on
//! different fabrics, and a node that is removed from a group simply stops being sent new epoch
//! keys: §4.17.3, "denying access to updated versions of these keys serves as a means to eject
//! group members".
//!
//! A **key set** holds up to three epoch keys with start times, which is what makes rotation
//! possible without a flag day: a sender uses the newest key whose start time has passed, and a
//! receiver accepts "any key derived from one of the currently installed epoch keys", future
//! start times included.
//!
//! ```
//! use matter_kit::fabric::CompressedFabricId;
//! use matter_kit::group;
//!
//! // §4.17.2's worked example, and §4.17.3.6's, which continues it.
//! let epoch = [
//!     0x23, 0x5b, 0xf7, 0xe6, 0x28, 0x23, 0xd3, 0x58,
//!     0xdc, 0xa4, 0xba, 0x50, 0xb1, 0x53, 0x5f, 0x4b,
//! ];
//! let compressed = CompressedFabricId(0x87E1_B004_E235_A130);
//! let operational = matter_kit::fabric::operational_group_key(
//!     &matter_kit::crypto::SymmetricKey::new(epoch),
//!     compressed,
//! )?;
//! assert_eq!(operational.as_bytes()[..2], [0xa6, 0xf5]);
//! assert_eq!(group::session_id(&operational)?, 0xB9F7);
//! # Ok::<(), matter_kit::Error>(())
//! ```

pub mod keys;
pub mod mcsp;
pub mod peers;
pub mod wire;

pub use keys::{
    EpochKey, GroupKeySecurityPolicy, GroupKeySet, GroupKeys, IPK_KEY_SET, KeySetId,
    MAX_EPOCH_KEYS, OperationalKey,
};
pub use mcsp::{CHALLENGE_LEN, SyncRequest, SyncResponse};
pub use peers::{Admitted, PeerState, PeerTable};
pub use wire::{Inbound, Received, Sender};

use crate::crypto::{SymmetricKey, kdf};
use crate::error::Result;
use crate::msg::{FabricId, GroupId, NodeId};
use crate::platform::PeerAddr;

/// §4.17.3.6's `Info`: the ASCII of `"GroupKeyHash"`.
pub const GROUP_KEY_HASH_INFO: &[u8] = b"GroupKeyHash";

/// The IANA-assigned site-scoped multicast address for Matter, `FF05::FA` (§2.5.6.2).
///
/// Required of "any device supporting the Groupcast cluster, whether as a Listener or Sender",
/// and the one address that does not depend on the fabric.
pub const IANA_MULTICAST: PeerAddr =
    PeerAddr::new([0xFF, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFA]);

/// §4.17.3.6's Group Session ID: which operational keys *might* have encrypted a message.
///
/// > The Group Session ID MAY help receiving nodes efficiently locate the Operational Group Key
/// > used to encrypt an incoming groupcast message. It SHALL NOT be used as the sole means to
/// > locate the associated Operational Group Key, since it MAY collide within the fabric.
///
/// Sixteen bits derived from the key, read big-endian — "GroupSessionId is computed by
/// considering the GroupKeyHash as a Big-Endian value" — which is the opposite of every other
/// scalar in the message header and the one thing to get wrong here.
pub fn session_id(operational: &SymmetricKey) -> Result<u16> {
    let mut hash = [0u8; 2];
    kdf(operational.as_bytes(), &[], GROUP_KEY_HASH_INFO, &mut hash)?;
    Ok(u16::from_be_bytes(hash))
}

/// §2.5.6.2's per-group IPv6 multicast address, `FF35:0040:FD<Fabric ID>00:<Group ID>`.
///
/// A unicast-prefix-based multicast address (RFC 3306) with site-local scope, so that "a low
/// probability of a node receiving a multicast message it is not interested in" comes from the
/// address rather than from decrypting everything. A collision needs two identical 64-bit
/// fabric ids *and* two identical group ids, and even then the MIC disambiguates.
#[must_use]
pub fn multicast_address(fabric: FabricId, group: GroupId) -> PeerAddr {
    let fabric = fabric.0.to_be_bytes();
    let group = group.0.to_be_bytes();
    PeerAddr::new([
        // 0xFF3 | scop 5: site-local, which "spans all networks in the Fabric".
        0xFF, 0x35, // Reserved, then plen 0x40: a 64-bit network prefix.
        0x00, 0x40,
        // The prefix: 0xFD for a locally assigned ULA, then the upper 56 bits of the fabric id.
        0xFD, fabric[0], fabric[1], fabric[2], fabric[3], fabric[4], fabric[5], fabric[6],
        // The 32-bit group identifier: the low 8 bits of the fabric id, a zero, then the group.
        fabric[7], 0x00, group[0], group[1],
    ])
}

/// §4.16.1's Groupcast Session Context: what a group message carries in place of a session.
///
/// > Together, Fabric Index, Group ID and Source Node ID comprise a unique identifier that
/// > upper layers may use to understand the source and destination of groupcast messages.
///
/// Built fresh on every message — "on ingress of each groupcast message, the following ephemeral
/// context SHALL be constructed" — because a group session is not a thing that is established,
/// only a membership that happens to still hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupContext {
    /// "the local Fabric Index for the Fabric to which an incoming message's group is scoped".
    pub fabric_index: crate::msg::FabricIndex,
    /// "the Group ID to which a groupcast message was sent".
    pub group: GroupId,
    /// "The Source Node ID enclosed by the sender of a groupcast message."
    pub source: NodeId,
    /// The unicast address the datagram came from, which is where an [`mcsp`] request goes —
    /// "as are required for the Message Counter Synchronization Protocol".
    pub from: PeerAddr,
    /// §4.17.3.6's Group Session ID the message named.
    pub session_id: u16,
    /// Which key set the key that authenticated it belongs to.
    pub key_set: KeySetId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_group_session_id_is_read_big_endian() {
        // §4.17.3.6's worked example: an operational group key of a6:f5:…:60 gives a
        // GroupKeyHash of b9:f7 and a Group Session ID of 0xB9F7. Reading the two octets the
        // other way round would give 0xF7B9, which is what every other scalar in the message
        // header would have been.
        let operational = SymmetricKey::new([
            0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a, 0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d,
            0xd9, 0x60,
        ]);
        assert_eq!(session_id(&operational).expect("kdf"), 0xB9F7);
    }

    #[test]
    fn the_multicast_address_is_the_specs_worked_form() {
        // §2.5.6.2: `FF35:0040:FD<Fabric ID>00:<Group ID>`, with the fabric id big-endian and
        // split across the prefix and the group identifier, and the group id big-endian.
        let addr = multicast_address(FabricId(0x0102_0304_0506_0708), GroupId(0xABCD));
        assert_eq!(
            addr.addr,
            [
                0xFF, 0x35, 0x00, 0x40, 0xFD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00,
                0xAB, 0xCD,
            ]
        );
        assert!(addr.is_multicast());
    }

    #[test]
    fn the_iana_address_is_ff05_fa() {
        assert_eq!(IANA_MULTICAST.addr[0..2], [0xFF, 0x05]);
        assert_eq!(IANA_MULTICAST.addr[15], 0xFA);
        assert!(IANA_MULTICAST.is_multicast());
    }
}
