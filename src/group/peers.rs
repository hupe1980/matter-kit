//! The Group Peer State Table (Core §4.18.2) and §4.18.4's admission rules.
//!
//! A unicast session agrees a starting message counter in its handshake. A group message has no
//! handshake, so the first message from any sender arrives with a counter that means nothing
//! yet — and §4.18 is the whole of what a receiver does about that.
//!
//! # Two counter spaces per peer, not one
//!
//! §4.18.2 keeps a *data* counter and a *control* counter for every peer, because they are
//! independent counter spaces (§4.6.1): the **C** flag chooses which one a message belongs to.
//! Folding them together would let a control message advance the data window and silently
//! discard everything the sender had in flight.
//!
//! # The table cannot be recycled
//!
//! §4.16.1 is unusually specific about the lifetime:
//!
//! > Once a Groupcast Session Context with trust-first policy is created to track authenticated
//! > messages from a given Source Node ID, that record SHALL NOT be deleted or recycled until
//! > the node reboots. This is to prevent replay attacks that first exhaust the memory allocated
//! > to group session counter tracking and then inject older messages as valid … Any message
//! > from a source that cannot be tracked SHALL be dropped.
//!
//! So [`PeerTable`] never evicts. A full table refuses new senders, which is the *point*: an
//! attacker that could push a real peer out would then be able to replay that peer's traffic.

use heapless::Vec;

use crate::msg::{CounterKind, CounterWindow, FabricIndex, NodeId, Verdict};

use super::keys::GroupKeySecurityPolicy;

/// §4.18.2: "There SHALL be at least 10 entries per supported fabric for Peer Encrypted Group
/// data Message Status in the Group Peer State table."
pub const MIN_DATA_PEERS_PER_FABRIC: usize = 10;

/// §4.18.2: "There SHALL be at least 2 entries per supported fabric for Peer Encrypted Group
/// Control Message Status."
pub const MIN_CONTROL_PEERS_PER_FABRIC: usize = 2;

/// What §4.18.4 says to do with a group message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// Process it. The counter has been recorded.
    Process,
    /// A duplicate, or older than the window. §4.6.5 drops it — and unlike a unicast reliable
    /// message there is nothing to acknowledge, because a group message is never reliable.
    Duplicate,
    /// The peer's counter is unknown and the key's policy is cache-and-sync, so the message is
    /// held and [`mcsp`](super::mcsp) runs first (§4.18.4 step 3c).
    NeedsSync,
    /// §4.16.1: "Any message from a source that cannot be tracked SHALL be dropped." The table
    /// is full of peers that may not be recycled.
    Untracked,
}

/// One peer's state for one counter space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerState {
    /// Which fabric the group was scoped to.
    pub fabric_index: FabricIndex,
    /// The sender.
    pub node: NodeId,
    /// Whether this is the control counter space (the **C** flag) rather than the data one.
    pub control: bool,
    /// §4.18.2's "message reception state bitmap tracking the recent window of … counters".
    pub window: CounterWindow,
    /// §4.18.2's "flag to indicate whether this counter value is valid and synchronized".
    ///
    /// Under trust-first this is set by the first message; under cache-and-sync only by an
    /// [`mcsp`](super::mcsp) response.
    pub synchronized: bool,
}

/// The Group Peer State Table (§4.18.2).
///
/// `D` bounds the data entries and `C` the control entries, across every fabric. §4.18.2's
/// minima are per fabric, so a five-fabric node wants at least fifty and ten.
#[derive(Debug)]
pub struct PeerTable<const D: usize, const C: usize> {
    data: Vec<PeerState, D>,
    control: Vec<PeerState, C>,
}

impl<const D: usize, const C: usize> Default for PeerTable<D, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const D: usize, const C: usize> PeerTable<D, C> {
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
            control: Vec::new(),
        }
    }

    /// How many peers are tracked in each counter space.
    #[must_use]
    pub fn len(&self) -> (usize, usize) {
        (self.data.len(), self.control.len())
    }

    /// Whether nothing is tracked yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.control.is_empty()
    }

    /// One peer's state, if it is tracked.
    #[must_use]
    pub fn peer(&self, fabric: FabricIndex, node: NodeId, control: bool) -> Option<&PeerState> {
        self.space(control)
            .iter()
            .find(|p| p.fabric_index == fabric && p.node == node)
    }

    /// §4.18.4: judges an authenticated group message.
    ///
    /// The message has already passed its MIC — this is only about freshness. `control` is the
    /// **C** flag, which §4.18.1.1 makes decisive on its own: "All control messages (any message
    /// with C Flag set) use the control message counter and SHALL use Trust-first for
    /// synchronization. Note that MCSP is not used for Trust-first synchronization." So a
    /// cache-and-sync key does not make a control message wait — there would be nothing to wait
    /// for, since MCSP's own messages are control messages.
    pub fn admit(
        &mut self,
        fabric: FabricIndex,
        node: NodeId,
        control: bool,
        counter: u32,
        policy: GroupKeySecurityPolicy,
    ) -> Admitted {
        if let Some(peer) = self.find_mut(fabric, node, control) {
            if !peer.synchronized {
                // A tracked-but-unsynchronised peer exists only under cache-and-sync, where the
                // entry was made when synchronisation started.
                return Admitted::NeedsSync;
            }
            return match peer.window.accept(counter) {
                Verdict::New => Admitted::Process,
                Verdict::Duplicate => Admitted::Duplicate,
            };
        }

        // A peer that has never been heard from. §4.18.4's two branches.
        let trust_first = control || policy == GroupKeySecurityPolicy::TrustFirst;
        let state = PeerState {
            fabric_index: fabric,
            node,
            control,
            // §4.6.5.2.2: a group counter is free-running and rolls over, unlike a session's.
            window: CounterWindow::primed_at(CounterKind::Rollover, counter),
            synchronized: trust_first,
        };
        if self.push(state, control).is_err() {
            // §4.16.1: the table may not be recycled, so a full one refuses rather than evicting
            // a peer whose traffic could then be replayed.
            return Admitted::Untracked;
        }
        if trust_first {
            // §4.18.4 step 3b: "Set the peer's group key data message counter to Message Counter
            // of the message … Mark the peer's group key data message counter as synchronized."
            Admitted::Process
        } else {
            Admitted::NeedsSync
        }
    }

    /// Records the counter an [`mcsp`](super::mcsp) response carried (§4.18.5).
    ///
    /// The peer becomes synchronised, and the held message is judged against the counter the
    /// *sender* reported rather than the one that arrived.
    pub fn synchronize(&mut self, fabric: FabricIndex, node: NodeId, counter: u32) -> bool {
        let Some(peer) = self.find_mut(fabric, node, false) else {
            return false;
        };
        peer.window = CounterWindow::primed_at(CounterKind::Rollover, counter);
        peer.synchronized = true;
        true
    }

    /// Forgets everything about one fabric — what `RemoveFabric` must do.
    ///
    /// This is not the recycling §4.16.1 forbids: the fabric itself is gone, so there is no peer
    /// left whose messages could be replayed into it.
    pub fn remove_fabric(&mut self, fabric: FabricIndex) {
        self.data.retain(|p| p.fabric_index != fabric);
        self.control.retain(|p| p.fabric_index != fabric);
    }

    fn space(&self, control: bool) -> &[PeerState] {
        if control { &self.control } else { &self.data }
    }

    fn find_mut(
        &mut self,
        fabric: FabricIndex,
        node: NodeId,
        control: bool,
    ) -> Option<&mut PeerState> {
        let space: &mut [PeerState] = if control {
            &mut self.control
        } else {
            &mut self.data
        };
        space
            .iter_mut()
            .find(|p| p.fabric_index == fabric && p.node == node)
    }

    fn push(&mut self, state: PeerState, control: bool) -> core::result::Result<(), ()> {
        if control {
            self.control.push(state).map_err(|_| ())
        } else {
            self.data.push(state).map_err(|_| ())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const F1: FabricIndex = FabricIndex(1);
    const A: NodeId = NodeId(0x1111);
    const B: NodeId = NodeId(0x2222);

    type Table = PeerTable<2, 1>;

    #[test]
    fn trust_first_accepts_whatever_arrives_first() {
        // §4.18.1.1: "The first authenticated message counter from an unsynchronized peer is
        // trusted, and its message counter is used to configure message-counter-based replay
        // protection on future messages from that node."
        let mut table = Table::new();
        let policy = GroupKeySecurityPolicy::TrustFirst;
        assert_eq!(table.admit(F1, A, false, 5000, policy), Admitted::Process);
        assert_eq!(table.admit(F1, A, false, 5001, policy), Admitted::Process);
        assert_eq!(table.admit(F1, A, false, 5001, policy), Admitted::Duplicate);
        assert_eq!(table.admit(F1, A, false, 4000, policy), Admitted::Duplicate);
    }

    #[test]
    fn cache_and_sync_holds_the_first_message() {
        // §4.18.4 step 3c: "Store the message for later processing. Proceed to Message Counter
        // Synchronization Exchange."
        let mut table = Table::new();
        let policy = GroupKeySecurityPolicy::CacheAndSync;
        assert_eq!(table.admit(F1, A, false, 5000, policy), Admitted::NeedsSync);
        // And keeps holding until a response arrives, rather than trusting the retry.
        assert_eq!(table.admit(F1, A, false, 5001, policy), Admitted::NeedsSync);
        assert!(table.synchronize(F1, A, 5000));
        assert_eq!(table.admit(F1, A, false, 5001, policy), Admitted::Process);
        assert_eq!(table.admit(F1, A, false, 5000, policy), Admitted::Duplicate);
    }

    #[test]
    fn a_control_message_is_always_trust_first() {
        // §4.18.1.1: "All control messages (any message with C Flag set) use the control message
        // counter and SHALL use Trust-first for synchronization." MCSP's own messages are
        // control messages, so a control message that waited for MCSP would wait for itself.
        let mut table = Table::new();
        assert_eq!(
            table.admit(F1, A, true, 9, GroupKeySecurityPolicy::CacheAndSync),
            Admitted::Process
        );
    }

    #[test]
    fn the_two_counter_spaces_are_independent() {
        // §4.6.1: the C flag selects a different counter space, and a control message must not
        // advance the data window.
        let mut table = Table::new();
        let policy = GroupKeySecurityPolicy::TrustFirst;
        assert_eq!(table.admit(F1, A, false, 100, policy), Admitted::Process);
        assert_eq!(table.admit(F1, A, true, 100, policy), Admitted::Process);
        // The data window is still at 100, so 101 is new there too.
        assert_eq!(table.admit(F1, A, false, 101, policy), Admitted::Process);
        assert_eq!(table.peer(F1, A, true).unwrap().window.max(), 100);
    }

    #[test]
    fn a_full_table_refuses_rather_than_recycling() {
        // §4.16.1: "that record SHALL NOT be deleted or recycled until the node reboots … Any
        // message from a source that cannot be tracked SHALL be dropped." Evicting would let an
        // attacker push a real peer out and then replay its traffic.
        let mut table = PeerTable::<1, 1>::new();
        let policy = GroupKeySecurityPolicy::TrustFirst;
        assert_eq!(table.admit(F1, A, false, 1, policy), Admitted::Process);
        assert_eq!(table.admit(F1, B, false, 1, policy), Admitted::Untracked);
        // And the peer that was already there is untouched.
        assert_eq!(table.admit(F1, A, false, 2, policy), Admitted::Process);
    }

    #[test]
    fn a_group_counter_rolls_over() {
        // §4.6.5.2.2: a group counter is free-running, so a counter just past 0xFFFF_FFFF is
        // new rather than four billion messages in the past.
        let mut table = Table::new();
        let policy = GroupKeySecurityPolicy::TrustFirst;
        assert_eq!(
            table.admit(F1, A, false, u32::MAX, policy),
            Admitted::Process
        );
        assert_eq!(table.admit(F1, A, false, 0, policy), Admitted::Process);
        assert_eq!(table.admit(F1, A, false, 1, policy), Admitted::Process);
    }
}
