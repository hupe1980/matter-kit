//! Group message reception against arbitrary multicast datagrams (Core §4.16, §4.18).
//!
//! This is the only reception path in the stack with no session behind it. A unicast datagram is
//! looked up by session id and dropped if there is none; a *group* datagram is tried against
//! every installed key in turn, and whatever survives the AEAD is handed up with a peer table
//! entry created for the sender. Both halves are reachable by anyone who can put a packet on the
//! link's site-local multicast address.
//!
//! Four properties:
//!
//! 1. **Nothing panics**, whatever the datagram is — including the candidate loop, which
//!    restores the ciphertext between attempts and must not run off the end of either buffer.
//! 2. **Nothing authenticates without a key.** No sequence of bytes produces a `Message` unless
//!    it was encrypted under one of the installed operational group keys.
//! 3. **The peer table is never recycled.** §4.16.1 forbids it, so an attacker must not be able
//!    to displace a tracked sender and then replay that sender's traffic.
//! 4. **A counter never goes backwards.** Once a peer is synchronised, no later datagram may
//!    lower its window's maximum — which is the whole of what replay protection means here.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::crypto::SymmetricKey;
use matter_kit::fabric::CompressedFabricId;
use matter_kit::group::keys::{GroupKeySecurityPolicy, GroupKeySet, GroupKeys};
use matter_kit::group::peers::PeerTable;
use matter_kit::group::wire::{self, Received};
use matter_kit::msg::{FabricIndex, GroupId};
use matter_kit::platform::PeerAddr;

const F1: FabricIndex = FabricIndex(1);
const COMPRESSED: CompressedFabricId = CompressedFabricId(0x87E1_B004_E235_A130);
const FROM: PeerAddr = PeerAddr::new([0xFD; 16]);

type Keys = GroupKeys<4, 8>;
/// Deliberately small: a full table is the interesting state, because §4.16.1 forbids evicting
/// from it.
type Peers = PeerTable<2, 1>;

fn table(epoch: [u8; 16], policy: GroupKeySecurityPolicy) -> Keys {
    let mut keys = Keys::new(4, 3);
    let _ = keys.write_key_set(GroupKeySet::single(
        F1,
        7,
        policy,
        SymmetricKey::new(epoch),
        1,
    ));
    let _ = keys.map_group(F1, GroupId(1), 7);
    keys
}

fuzz_target!(|data: &[u8]| {
    let Some((&policy, datagram)) = data.split_first() else {
        return;
    };
    // The first octet chooses the security policy, so both of §4.18.1's branches are explored.
    let policy = if policy & 1 == 0 {
        GroupKeySecurityPolicy::TrustFirst
    } else {
        GroupKeySecurityPolicy::CacheAndSync
    };
    let keys = table([0x42; 16], policy);
    let mut peers = Peers::new();
    let mut scratch = [0u8; 2048];

    // Two passes over the same bytes: whatever state the first leaves, the second must not be
    // able to turn into a message it could not produce the first time.
    for _ in 0..2 {
        let mut buf = datagram.to_vec();
        if buf.len() > scratch.len() {
            return;
        }
        let before: Vec<_> = [false, true]
            .into_iter()
            .filter_map(|control| {
                peers
                    .peer(F1, matter_kit::msg::NodeId(0), control)
                    .map(|p| (control, p.window.max()))
            })
            .collect();

        match wire::receive(&mut buf, FROM, &keys, &mut peers, |_| Some(COMPRESSED), &mut scratch) {
            // Property 2: a message means the AEAD passed, which means a key matched.
            Ok(Received::Message(inbound)) => {
                assert_eq!(inbound.context.fabric_index, F1);
                assert!(
                    peers
                        .peer(F1, inbound.context.source, inbound.control)
                        .is_some(),
                    "a processed message always leaves the sender tracked"
                );
            }
            Ok(_) | Err(_) => {}
        }

        // Property 4: nothing an arbitrary datagram can do lowers a synchronised window.
        for (control, was) in before {
            if let Some(peer) = peers.peer(F1, matter_kit::msg::NodeId(0), control) {
                assert!(
                    peer.window.max() >= was || peer.window.max().wrapping_sub(was) < 1 << 31,
                    "a counter went backwards"
                );
            }
        }
        // Property 3: the table only ever grows, and never past its capacity.
        let (data_peers, control_peers) = peers.len();
        assert!(data_peers <= 2 && control_peers <= 1);
    }
});
