//! The node runtime: the sequence every Matter device keeps, owned by a type.
//!
//! The rest of this crate is parts — a messaging layer, a secure channel, an interaction-model
//! server, a subscription table, the commissioning clusters — and each part is correct on its own.
//! What a device also needs is the *order* in which they are driven, and that order is where
//! defects live: a report opened while the priming report is still going out, a chunked read
//! continued on another controller's exchange, a removed fabric whose subscriptions keep
//! reporting, a fail-safe whose deadline nobody acts on. [`Runtime`] owns that order.
//!
//! # Shape
//!
//! Sans-I/O, like everything below it. A datagram goes in through [`Runtime::receive`], time goes
//! in through [`Runtime::poll`], and whatever the node owes the network comes out of
//! [`Runtime::transmit`]. [`Runtime::next_deadline`] says when `poll` next has work, and
//! [`Runtime::notice`] reports what happened, as values rather than log lines. A device with
//! sockets and a timer runs [`Runtime::run`] and writes no loop of its own.
//!
//! ```text
//!   datagram ──► receive ─┐                   ┌─► transmit ──► socket
//!                         ├─► Runtime ────────┤
//!   timer ─────► poll ────┘                   └─► notice ────► log
//! ```
//!
//! # What it owns
//!
//! - **The messaging stack**, the §5.5 secure channel, the interaction-model dispatcher and the
//!   §8.5 subscription table.
//! - **Per-exchange series state** (§10.2.3): a chunked read continues only on the exchange that
//!   started it, and a reused exchange id starts afresh.
//! - **The subscribe flow** (§8.5.2): subscription, priming report (chunked if need be), and the
//!   `SubscribeResponse` only once the subscriber has acknowledged the last chunk.
//! - **Reports** (§8.5.3): due reports go out with at most one unacknowledged per subscription,
//!   filtered as the subscriber that created them.
//! - **Exchange closing** (§4.10.5.3): what "the application layer" decides is closed.
//! - **Retransmission** (§4.12.2.1): the same bytes again when MRP asks.
//! - **Cascades**: a closed or evicted session takes its subscriptions, reports and series; a
//!   removed fabric takes its subscriptions and window, and its sessions after the reply.
//! - **Commissioning follow-ups**: §11.18.6.8's administrator entry, PASE fabric binding and IPK
//!   key set; §11.10.7.2.2's rollback (also on the timer) and §11.10.7.6's commit, including
//!   closing PASE sessions; §9.10.9.1's `AccessControlEntryChanged` events.
//!
//! What it does not own is the device: which clusters it has, what their hooks do, and its
//! sockets. Those arrive as a [`Device`] — a bundle of references the application builds once.

mod followups;
mod interactions;
mod outbox;
mod serve;

mod driver;

pub use driver::Mdns;

use core::cell::RefCell;

use heapless::{Deque, Vec};

use crate::acl::{AclAccess, SubjectDescriptor};
use crate::clusters::access_control::AccessControl as AccessControlCluster;
use crate::clusters::general_commissioning::GeneralCommissioning;
use crate::clusters::group_key_management::GroupTable;
use crate::clusters::operational_credentials::{OperationalCredentials, max_nocs_len};
use crate::config::{Config, DefaultConfig, MAX_UDP_MESSAGE, MAX_UDP_PAYLOAD};
use crate::crypto::{KeyStore, Spake2pVerifierData, SymmetricKey};
use crate::dm::events::{EventSource, EventStore, NewEvent, RecordError};
use crate::dm::{DataVersionSource, DataVersions, Node};
use crate::error::{Error, Result};
use crate::exchange::{ExchangeKey, Role};
use crate::fabric::CompressedFabricId;
use crate::group::{GroupKeySet, GroupKeys, PeerTable};
use crate::im::{
    ClusterHandler, ClusterId, Dispatcher, EndpointId, InteractionContext, Status,
    SubscriptionTable,
};
use crate::messaging::{Due, Evicted, Messaging, Received};
use crate::msg::{FabricIndex, GroupId, NodeId, ProtocolId, SessionId};
use crate::platform::{Duration, Instant, Peer, PeerAddr, Rng};
use crate::sc::{Channel, ChannelBuffers, ChannelContext, PbkdfParameters};
use crate::session::SessionKind;

use interactions::Interactions;
use outbox::{Outbox, Resend};

/// The scratch a read builds one whole attribute value in, sized for [`DefaultConfig`].
///
/// A value, not a message: a non-fabric-filtered read of `NOCs` carries every fabric's NOC and
/// ICAC, and [`max_nocs_len`] is the library's own bound for it.
pub const SCRATCH: usize = max_nocs_len(DefaultConfig::FABRICS);

/// How many attributes one report message carries at most, before §10.2.3 chunking.
const REPORT_LIMIT: usize = 24;

/// How many subscriptions the runtime holds — §8.5's minimum for five fabrics, three each.
pub const SUBSCRIPTIONS: usize = 15;

/// How many paths one subscription holds — §8.5's minimum of three.
pub const SUBSCRIPTION_PATHS: usize = 3;

/// The subscription table the runtime keeps.
pub type Subscriptions<C> = SubscriptionTable<C, SUBSCRIPTIONS, SUBSCRIPTION_PATHS>;

/// How long an established PASE channel may sit unused, with the fail-safe never armed, before
/// an open window may release it.
///
/// §5.5 rule 1 holds the commissioning channel closed "until session establishment fails or the
/// successfully established PASE session is terminated", which is what stops a second
/// commissioner stepping into the first one's commissioning. A commissioner is under no
/// obligation to send `CloseSession`, though: one that gives up before arming the fail-safe
/// leaves a session the node will never hear from again, and without a way out the node answers
/// `Busy` for ever. A commissioning that *did* arm the fail-safe ends in a commit or a rollback,
/// both of which close the PASE session; this is only for the one that never started.
pub const PASE_ABANDON_GRACE: Duration = Duration::from_secs(30);

mod sealed {
    pub trait Sealed {}
}

/// The Access Control cluster, as the runtime reaches it.
///
/// Implemented for [`AccessControl`](crate::clusters::access_control::AccessControl) and
/// nothing else; it exists to keep the list's four const parameters out of [`Device`].
pub trait AccessList: sealed::Sealed {
    /// The access check for one subject.
    type Access<'b>: crate::im::AccessControl
    where
        Self: 'b;
    /// The list, bound to a node and the subject of one interaction.
    fn access<'b>(&'b self, node: Node<'b>, subject: &'b SubjectDescriptor) -> Self::Access<'b>;
    /// §11.18.6.8 step 7's administrator entry, recorded as a change like any other.
    fn grant_admin(
        &self,
        fabric: FabricIndex,
        subject: NodeId,
        ctx: &InteractionContext<'_>,
    ) -> Result<()>;
    /// Every change since the last call, each as an encoded `AccessControlEntryChanged` payload
    /// and the fabric it belongs to (§9.10.9.1).
    fn drain_changes(&self, each: &mut dyn FnMut(FabricIndex, Result<&[u8]>));
}

impl<C: Config, const N: usize, const S: usize, const T: usize> sealed::Sealed
    for AccessControlCluster<'_, C, N, S, T>
{
}

impl<C: Config, const N: usize, const S: usize, const T: usize> AccessList
    for AccessControlCluster<'_, C, N, S, T>
{
    type Access<'b>
        = AclAccess<'b, C, N, S, T>
    where
        Self: 'b;

    fn access<'b>(&'b self, node: Node<'b>, subject: &'b SubjectDescriptor) -> Self::Access<'b> {
        AclAccess::new(self.acl(), node, subject)
    }

    fn grant_admin(
        &self,
        fabric: FabricIndex,
        subject: NodeId,
        ctx: &InteractionContext<'_>,
    ) -> Result<()> {
        self.add_admin_for_fabric(fabric, subject, ctx)
    }

    fn drain_changes(&self, each: &mut dyn FnMut(FabricIndex, Result<&[u8]>)) {
        for change in self.take_changes() {
            let mut buf = [0u8; crate::dm::events::EVENT_DATA_MAX];
            let mut w =
                crate::tlv::TlvWriter::new_in(&mut buf, crate::tlv::ContainerKind::Structure);
            let encoded = change
                .encode(&mut w, crate::tlv::Tag::Context(7))
                .and_then(|()| w.finish());
            each(change.fabric_index, encoded);
        }
    }
}

/// The group key store, as the runtime reaches it: `RefCell<GroupKeys<…>>`.
pub trait GroupKeyStore: sealed::Sealed {
    /// §11.18.6.8: providing an IPK "is equivalent to a KeySetWrite of group key set 0".
    fn install_ipk(
        &self,
        fabric: FabricIndex,
        ipk: SymmetricKey,
    ) -> core::result::Result<(), Status>;
    /// §4.16.3's receive path: find the key, check the counter, decrypt.
    fn open<'b>(
        &self,
        buf: &'b mut [u8],
        from: PeerAddr,
        peers: &mut GroupPeers,
        compressed: &dyn Fn(FabricIndex) -> Option<CompressedFabricId>,
        scratch: &mut [u8],
    ) -> Result<crate::group::wire::Received<'b>>;
}

/// §4.16.1's group peer table as the runtime sizes it.
pub type GroupPeers = PeerTable<4, 2>;

impl<C: Config, const K: usize, const M: usize> sealed::Sealed for RefCell<GroupKeys<C, K, M>> {}

impl<C: Config, const K: usize, const M: usize> GroupKeyStore for RefCell<GroupKeys<C, K, M>> {
    fn install_ipk(
        &self,
        fabric: FabricIndex,
        ipk: SymmetricKey,
    ) -> core::result::Result<(), Status> {
        let set = GroupKeySet::single(
            fabric,
            crate::group::IPK_KEY_SET,
            crate::group::GroupKeySecurityPolicy::TrustFirst,
            ipk,
            0,
        );
        self.borrow_mut().write_key_set(set)
    }

    fn open<'b>(
        &self,
        buf: &'b mut [u8],
        from: PeerAddr,
        peers: &mut GroupPeers,
        compressed: &dyn Fn(FabricIndex) -> Option<CompressedFabricId>,
        scratch: &mut [u8],
    ) -> Result<crate::group::wire::Received<'b>> {
        crate::group::wire::receive(buf, from, &self.borrow(), peers, compressed, scratch)
    }
}

/// The event store, as the runtime reaches it: `RefCell<EventStore<…>>`.
pub trait EventLog: sealed::Sealed {
    /// Records one event (§7.14).
    fn record(&self, event: &NewEvent<'_>) -> core::result::Result<u64, RecordError>;
    /// The store as reads and reports see it.
    fn source(&self) -> &dyn EventSource;
}

impl<const A: usize, const B: usize, const D: usize> sealed::Sealed
    for RefCell<EventStore<A, B, D>>
{
}

impl<const A: usize, const B: usize, const D: usize> EventLog for RefCell<EventStore<A, B, D>> {
    fn record(&self, event: &NewEvent<'_>) -> core::result::Result<u64, RecordError> {
        self.borrow_mut().record(event)
    }

    fn source(&self) -> &dyn EventSource {
        self
    }
}

/// §7.10.3's data versions, as the runtime reaches them: [`DataVersions`].
pub trait ChangeLog: DataVersionSource + sealed::Sealed {
    /// Every cluster instance whose data changed since the last call.
    fn drain(&self, each: &mut dyn FnMut(EndpointId, ClusterId));
}

impl<const N: usize> sealed::Sealed for DataVersions<N> {}

impl<const N: usize> ChangeLog for DataVersions<N> {
    fn drain(&self, each: &mut dyn FnMut(EndpointId, ClusterId)) {
        for (endpoint, cluster) in self.drain_changes() {
            each(endpoint, cluster);
        }
    }
}

/// What the application hands the runtime: its node and the parts the specification makes the
/// node's to drive.
///
/// Built once with a struct literal; every type parameter is inferred, so an application never
/// spells one. The clusters named here must also be in `handler` — the runtime reaches them
/// directly only for the follow-ups a cluster cannot perform itself: a cluster reports, the
/// node acts.
pub struct Device<'a, C, K, G, H, Ac, Gk, Ev, V, const F: usize>
where
    C: Config,
    K: KeyStore,
    G: Rng,
    H: ClusterHandler,
    Ac: AccessList,
    Gk: GroupKeyStore,
    Ev: EventLog,
    V: ChangeLog,
{
    /// The node's endpoints and clusters.
    pub node: Node<'a>,
    /// Every cluster instance, routed by endpoint and cluster id.
    pub handler: &'a H,
    /// Operational Credentials — and through it the fabric table, the key store, the rng and
    /// the fail-safe.
    pub credentials: &'a OperationalCredentials<'a, C, K, G, F>,
    /// General Commissioning — and through it the fail-safe and the commissioning window.
    pub commissioning: &'a GeneralCommissioning<'a>,
    /// Access Control.
    pub access_control: &'a Ac,
    /// The group key store Group Key Management serves.
    pub group_keys: &'a Gk,
    /// The event log.
    pub events: &'a Ev,
    /// The data versions.
    pub versions: &'a V,
    /// The SPAKE2+ verifier the passcode was turned into at manufacture.
    pub verifier: &'a Spake2pVerifierData,
    /// The PBKDF parameters that go with it.
    pub parameters: &'a PbkdfParameters,
    /// Which groups the node's endpoints are in, so the driver can join their multicast
    /// addresses (§2.5.6.2). `None` for a node with no Groups cluster.
    pub memberships: Option<&'a dyn GroupTable>,
}

impl<C, K, G, H, Ac, Gk, Ev, V, const F: usize> core::fmt::Debug
    for Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>
where
    C: Config,
    K: KeyStore,
    G: Rng,
    H: ClusterHandler,
    Ac: AccessList,
    Gk: GroupKeyStore,
    Ev: EventLog,
    V: ChangeLog,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Device")
            .field("node", &self.node)
            .field("groups", &self.memberships.is_some())
            .finish_non_exhaustive()
    }
}

/// Something worth knowing that happened, in the order it happened.
///
/// Nothing here is an error the caller must handle — the runtime has already done what the
/// specification asks. Each is something an integrator wants to log, count or assert on; the
/// runtime keeps the last sixteen and drops the oldest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Notice {
    /// A datagram was dropped before it reached any protocol: unparseable, unauthenticated, a
    /// replay, or for a session this node does not have.
    Dropped(Error),
    /// A message was received and could not be answered.
    Refused(Error),
    /// PASE or CASE completed.
    Established {
        /// The new session.
        session: SessionId,
        /// PASE or CASE.
        kind: SessionKind,
        /// The fabric, for CASE; `FabricIndex(0)` for PASE.
        fabric: FabricIndex,
    },
    /// A session closed — by its peer, by eviction, or by a cascade — with this many
    /// subscriptions.
    SessionClosed {
        /// The session.
        session: SessionId,
        /// How many subscriptions went with it.
        subscriptions: usize,
    },
    /// A session was evicted to make room for a new one (§4.11.1.1).
    Evicted {
        /// The session.
        session: SessionId,
    },
    /// A subscription was created and its priming report is going out.
    Subscribed {
        /// Its id.
        id: u32,
        /// The maximum interval granted.
        max_interval_s: u16,
    },
    /// A subscription's `SubscribeResponse` went out: it is active.
    Granted {
        /// Its id.
        id: u32,
    },
    /// A due report could not be built, framed or queued; the subscription is still due.
    ReportFailed {
        /// The subscription.
        id: u32,
        /// Why.
        error: Error,
    },
    /// A fabric joined (`AddNOC`).
    FabricAdded(FabricIndex),
    /// A fabric's identity was replaced (`UpdateNOC`).
    FabricUpdated(FabricIndex),
    /// A fabric left (`RemoveFabric`, or a rollback of `AddNOC`).
    FabricRemoved(FabricIndex),
    /// The fail-safe was disarmed or expired and its cleanup ran (§11.10.7.2.2).
    RolledBack,
    /// `CommissioningComplete` succeeded on this fabric (§11.10.7.6).
    Commissioned(FabricIndex),
    /// A commissioning window opened, and the channel admits PASE again.
    WindowOpened,
    /// An established PASE channel was released to an open window.
    ChannelReleased,
    /// A groupcast was acted on (and, as §8.7.2.3 requires, not answered).
    Groupcast(GroupId),
    /// An access-control change could not be recorded as an event.
    EventLost(Option<RecordError>),
    /// The outbox was full and a datagram was dropped; MRP will retransmit a reliable one.
    OutboxFull,
    /// MRP gave up on an exchange.
    Abandoned(ExchangeKey),
}

/// The interaction-model state the runtime keeps across messages.
#[derive(Debug)]
struct Im<C: Config, const I: usize> {
    dispatcher: Dispatcher<4>,
    interactions: Interactions<I>,
    subscriptions: Subscriptions<C>,
    /// One outstanding report per subscription: the exchange it went out on.
    reporting: Vec<(u32, ExchangeKey), SUBSCRIPTIONS>,
    /// Subscriptions whose last report could not be built, and when to try again — so a report
    /// that cannot be built does not spin the loop.
    backoff: Vec<(u32, Instant), SUBSCRIPTIONS>,
}

/// The work space the runtime builds messages in.
#[derive(Debug)]
struct Buffers<const B: usize> {
    /// The protocol payload of a reply, before framing.
    payload: [u8; MAX_UDP_PAYLOAD],
    /// One attribute value, before the server decides where it fits.
    scratch: [u8; B],
    /// Where §4.8's AEAD joins the header and the payload.
    frame: [u8; MAX_UDP_MESSAGE],
    /// The framed datagram.
    wire: [u8; MAX_UDP_MESSAGE],
    /// §4.11.1.1's `CloseSession` to an evicted peer; also a group message's decryption space.
    evict: [u8; MAX_UDP_MESSAGE],
}

/// The PASE channel's commissioning progress, for §5.5's release rule.
#[derive(Debug, Clone, Copy, Default)]
struct PaseProgress {
    established_at: Option<Instant>,
    armed_seen: bool,
}

/// The node runtime.
///
/// `S` sessions and `X` exchanges size the messaging stack ([`Messaging`]'s own defaults); `I`
/// interactions in progress; `R` datagrams kept for retransmission; `Q` datagrams queued for
/// sending; `B` octets of attribute scratch ([`SCRATCH`]). The defaults fit [`DefaultConfig`]
/// and satisfy every specification minimum for five fabrics; a device with less RAM lowers
/// `I`, `R` and `Q` first.
///
/// About 60 KiB with the defaults, almost all of it datagram buffers and the subscription
/// table, so a device puts it in a `static` rather than on a task's stack.
#[derive(Debug)]
pub struct Runtime<
    C: Config,
    const S: usize = 16,
    const X: usize = 64,
    const I: usize = 8,
    const R: usize = 4,
    const Q: usize = 4,
    const B: usize = SCRATCH,
> {
    stack: Messaging<C, S, X>,
    channel: Channel,
    im: Im<C, I>,
    outbox: Outbox<Q>,
    resend: Resend<R>,
    group_peers: GroupPeers,
    notices: Deque<Notice, 16>,
    window_was_open: bool,
    pase: PaseProgress,
    buf: Buffers<B>,
}

impl<
    C: Config,
    const S: usize,
    const X: usize,
    const I: usize,
    const R: usize,
    const Q: usize,
    const B: usize,
> Runtime<C, S, X, I, R, Q, B>
{
    /// A runtime with no sessions, its ids and counters drawn from `rng`.
    ///
    /// # Errors
    ///
    /// The `rng` failed.
    pub fn new(rng: &impl Rng) -> Result<Self> {
        const {
            assert!(
                B >= max_nocs_len(C::FABRICS),
                "the scratch must hold a non-fabric-filtered NOCs read for every fabric"
            );
            assert!(Q > 1, "one input can owe a reply and an eviction report");
        }
        Ok(Self {
            // §4.13.2.4 wants an unpredictable non-zero session id.
            stack: Messaging::new(rng.next_u16()? | 1, rng.next_u16()?, rng.next_u32()?),
            channel: Channel::new(),
            im: Im {
                // Basic Information's own default; `with_max_paths_per_invoke` matches a product
                // that advertises more.
                dispatcher: Dispatcher::new(1),
                interactions: Interactions::new(),
                subscriptions: SubscriptionTable::new(),
                reporting: Vec::new(),
                backoff: Vec::new(),
            },
            outbox: Outbox::new(),
            resend: Resend::new(),
            group_peers: PeerTable::new(),
            notices: Deque::new(),
            window_was_open: false,
            pase: PaseProgress::default(),
            buf: Buffers {
                payload: [0; MAX_UDP_PAYLOAD],
                scratch: [0; B],
                frame: [0; MAX_UDP_MESSAGE],
                wire: [0; MAX_UDP_MESSAGE],
                evict: [0; MAX_UDP_MESSAGE],
            },
        })
    }

    /// Sets `MaxPathsPerInvoke` (§8.8.2.3) — what Basic Information advertises.
    #[must_use]
    pub fn with_max_paths_per_invoke(mut self, max: u16) -> Self {
        self.im.dispatcher = Dispatcher::new(max);
        self
    }

    /// The messaging stack.
    #[must_use]
    pub const fn messaging(&self) -> &Messaging<C, S, X> {
        &self.stack
    }

    /// The messaging stack, for installing a session directly or registering protocols.
    pub const fn messaging_mut(&mut self) -> &mut Messaging<C, S, X> {
        &mut self.stack
    }

    /// The subscriptions.
    #[must_use]
    pub const fn subscriptions(&self) -> &Subscriptions<C> {
        &self.im.subscriptions
    }

    /// The secure channel.
    #[must_use]
    pub const fn channel(&self) -> &Channel {
        &self.channel
    }

    /// The next datagram to send, and where. Valid until the next call.
    pub fn transmit(&mut self) -> Option<(Peer, &[u8])> {
        self.outbox.pop()
    }

    /// The oldest notice not yet taken.
    pub fn notice(&mut self) -> Option<Notice> {
        self.notices.pop_front()
    }

    fn notify(&mut self, notice: Notice) {
        #[cfg(feature = "log")]
        log::debug!("{notice:?}");
        #[cfg(all(feature = "defmt", not(feature = "log")))]
        defmt::debug!("{}", defmt::Debug2Format(&notice));
        if self.notices.is_full() {
            self.notices.pop_front();
        }
        let _ = self.notices.push_back(notice);
    }

    /// One datagram in.
    ///
    /// Whatever it owes — a reply, an acknowledgement, a `CloseSession` to an evicted peer — is
    /// queued for [`Self::transmit`]. `datagram` is decrypted in place.
    pub fn receive<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        datagram: &mut [u8],
        from: Peer,
        now: Instant,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        self.watch_window(device, now);
        let received = match self.stack.receive(datagram, from, now) {
            Ok(received) => received,
            Err(e) => {
                self.notify(Notice::Dropped(e));
                return;
            }
        };
        match received {
            Received::Group { .. } => {
                if let Peer::Udp(addr) = from {
                    self.groupcast(device, datagram, addr, now);
                }
            }
            // §4.12.2.2: acknowledged, not acted on.
            Received::Duplicate {
                exchange,
                needs_ack,
            } => {
                if needs_ack {
                    self.acknowledge(exchange, now);
                }
            }
            // §4.11.1.4: the peer closed the session and `Messaging` has closed this end. What
            // is left is everything above that layer which was keyed on it.
            Received::SessionClosed { session } => self.session_gone(session),
            Received::Acknowledged { exchange } => {
                // A report this node sent has been acknowledged: the slot is free for the next.
                // Unless the acknowledgement was for an older message — a duplicate's, arriving
                // late — in which case the exchange still owes delivery and stays as it is.
                if !self.stack.is_awaiting_ack(exchange) {
                    self.im.reporting.retain(|(_, on)| *on != exchange);
                }
                self.close_if_idle(exchange);
            }
            Received::Message {
                exchange,
                header,
                payload,
                ..
            } => self.message(
                device,
                exchange,
                header.protocol,
                header.opcode,
                payload,
                now,
            ),
        }
        self.drain_changes(device);
    }

    /// Everything time-driven.
    ///
    /// Call it whenever [`Self::next_deadline`] passes, and after every [`Self::receive`] — the
    /// driver does both on every iteration, whichever event woke it, because a loop that runs
    /// time-driven work only when the timer wins a race against the sockets starves one or the
    /// other.
    pub fn poll<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        now: Instant,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        self.watch_window(device, now);
        // "If the PASE session is not established within the expected time window the
        // Commissionee SHALL terminate the current session establishment".
        if self.channel.deadline().is_some_and(|d| d <= now) {
            self.channel.poll(now, device.commissioning.window);
        }
        self.expire_fail_safe(device, now);
        self.drain_changes(device);
        self.reports(device, now);
        loop {
            let randomness = random(device);
            let Some(due) = self.stack.poll(now, randomness) else {
                break;
            };
            match due {
                // §4.12.5.2.2: the acknowledgement waited for a message to ride on and none came,
                // so it goes on its own — and it has to actually go.
                Due::Acknowledge { exchange } => {
                    self.acknowledge(exchange, now);
                    // A standalone acknowledgement means nothing is coming back on this exchange
                    // — nobody acknowledges an acknowledgement — so a responder exchange with no
                    // series in progress is finished. Not this node's own report exchanges: those
                    // are waiting for the acknowledgement that `Received::Acknowledged` closes.
                    if matches!(exchange.role, Role::Responder) {
                        self.close_if_idle(exchange);
                    }
                }
                Due::Retransmit { exchange, counter } => {
                    if let Some((peer, bytes)) = self.resend.find(exchange, counter)
                        && !self.outbox.push(peer, bytes)
                    {
                        self.notify(Notice::OutboxFull);
                    }
                }
                Due::Abandoned { exchange } => {
                    // The exchange is closed and its report will never be acknowledged; free the
                    // slot or the subscription never reports again.
                    self.im.reporting.retain(|(_, on)| *on != exchange);
                    self.im.interactions.forget(exchange);
                    self.resend.forget(exchange);
                    self.notify(Notice::Abandoned(exchange));
                }
            }
        }
    }

    /// The earliest instant [`Self::poll`] has work, if any.
    #[must_use]
    pub fn next_deadline<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
    ) -> Option<Instant>
    where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        // A subscription that cannot report yet — its priming report is going out, or a report
        // is already in flight — is not a deadline: waking for it would spin the loop until the
        // acknowledgement arrives, which is itself an event.
        let reports = self
            .im
            .subscriptions
            .iter()
            .filter(|s| {
                !self.im.interactions.priming(s.id)
                    && !self.im.reporting.iter().any(|(id, _)| *id == s.id)
            })
            .map(|s| {
                let at = s.next_deadline();
                match self.im.backoff.iter().find(|(id, _)| *id == s.id) {
                    Some((_, retry)) => at.max(*retry),
                    None => at,
                }
            })
            .min();
        let pase_release = self
            .pase
            .established_at
            .filter(|_| !self.pase.armed_seen)
            .map(|at| at.saturating_add(PASE_ABANDON_GRACE));
        [
            self.stack.wake_at(),
            self.channel.deadline(),
            reports,
            device.commissioning.fail_safe.borrow().next_deadline(),
            device.commissioning.window.borrow().deadline(),
            pase_release,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    // --- Routing ---------------------------------------------------------------------------

    fn message<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        exchange: ExchangeKey,
        protocol: ProtocolId,
        opcode: u8,
        body: &[u8],
        now: Instant,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        if protocol == ProtocolId::SECURE_CHANNEL {
            self.secure_channel(device, exchange, opcode, body, now);
            return;
        }
        if protocol != ProtocolId::INTERACTION_MODEL {
            return;
        }
        // §10.7.3.2: a subscriber answers a report with a `StatusResponse`, and a peer may carry
        // the acknowledgement on it rather than send a bare one — the CHIP SDK does. Either way
        // the report has been delivered once the exchange is no longer awaiting it, and the
        // in-flight slot is free; otherwise the subscription never reports again.
        if !self.stack.is_awaiting_ack(exchange) {
            self.im.reporting.retain(|(_, on)| *on != exchange);
        }
        let reply = self.interaction(device, exchange, opcode, body, now);
        // §11.10.7.2.2, §11.18.6.8, §11.18.6.12: what the command left for the node, applied
        // before the reply so the reply reflects it — and the parts that would strand the
        // reply (closing the session it is about to go out on) deferred until after it.
        let deferred = self.follow_up(device, exchange.session, now);
        match reply {
            Ok(Some((opcode, len))) => self.send(device, exchange, opcode, len, now),
            // Nothing is owed and nothing is part-way through, so §4.10.5.3's "application
            // layer" has decided the exchange is over. The close cannot wait for a bare
            // acknowledgement: a peer may piggyback it on its next message instead, and the CHIP
            // SDK does — a read would leave an exchange open that nothing ever closes.
            Ok(None) => self.close_if_idle(exchange),
            Err(e) => {
                self.notify(Notice::Refused(e));
                self.im.interactions.forget(exchange);
                self.close_if_idle(exchange);
            }
        }
        self.apply(deferred);
    }

    fn secure_channel<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        exchange: ExchangeKey,
        opcode: u8,
        body: &[u8],
        now: Instant,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let answered = {
            let rng = device.credentials.rng.borrow();
            let ctx = ChannelContext {
                fabrics: device.credentials.fabrics,
                keys: device.credentials.keys,
                rng: &*rng,
                window: device.commissioning.window,
                verifier: device.verifier,
                parameters: device.parameters,
                now,
            };
            let mut buffers = ChannelBuffers {
                reply: &mut self.buf.payload,
                frame: &mut self.buf.frame,
                evict: &mut self.buf.evict,
            };
            self.channel
                .on_message(&mut self.stack, opcode, body, &ctx, &mut buffers)
        };
        let answered = match answered {
            Ok(answered) => answered,
            Err(e) => {
                self.notify(Notice::Refused(e));
                return;
            }
        };
        if let Some(established) = &answered.established {
            if established.kind == SessionKind::Pase {
                self.pase = PaseProgress {
                    established_at: Some(now),
                    armed_seen: false,
                };
            }
            self.notify(Notice::Established {
                session: established.session,
                kind: established.kind,
                fabric: established.fabric,
            });
        }
        // A message for a handshake that is not running gets no answer: saying nothing is the
        // answer, not an error.
        if let Some((opcode, len)) = answered.reply {
            self.send(device, exchange, opcode, len, now);
        }
        if let Some(evicted) = answered.evicted {
            self.evicted(evicted);
        }
    }

    // --- Sending ---------------------------------------------------------------------------

    /// Frames `payload[..len]` on `exchange`, queues it, and keeps it for retransmission.
    fn send<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        exchange: ExchangeKey,
        opcode: u8,
        len: usize,
        now: Instant,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        if let Err(e) = self.frame(exchange, opcode, len, random(device), now) {
            self.notify(Notice::Refused(e));
        }
    }

    fn frame(
        &mut self,
        exchange: ExchangeKey,
        opcode: u8,
        len: usize,
        randomness: u32,
        now: Instant,
    ) -> Result<()> {
        let payload = self
            .buf
            .payload
            .get(..len)
            .ok_or(Error::new(crate::ErrorCode::BufferTooSmall))?;
        let (n, counter) = self.stack.send(
            exchange,
            opcode,
            true,
            payload,
            now,
            randomness,
            &mut self.buf.frame,
            &mut self.buf.wire,
        )?;
        let peer = self
            .stack
            .peer(exchange)
            .ok_or(Error::new(crate::ErrorCode::NoSession))?;
        let bytes = self
            .buf
            .wire
            .get(..n)
            .ok_or(Error::new(crate::ErrorCode::BufferTooSmall))?;
        let queued = self.outbox.push(peer, bytes);
        self.resend.record(exchange, counter, peer, bytes);
        if !queued {
            self.notify(Notice::OutboxFull);
        }
        Ok(())
    }

    fn acknowledge(&mut self, exchange: ExchangeKey, now: Instant) {
        let Ok(len) = self.stack.acknowledge(exchange, now, &mut self.buf.wire) else {
            return;
        };
        if len == 0 {
            return;
        }
        let (Some(peer), Some(bytes)) = (self.stack.peer(exchange), self.buf.wire.get(..len))
        else {
            return;
        };
        if !self.outbox.push(peer, bytes) {
            self.notify(Notice::OutboxFull);
        }
    }

    // --- Exchange and session lifetime -------------------------------------------------------

    /// Closes `exchange` if nothing is part-way through on it.
    ///
    /// §4.10.5.3 leaves reclaiming a finished exchange to "the application layer", and a
    /// fixed-capacity table makes that not optional: a node that never says so fills its
    /// exchange table and then drops every datagram — including the acknowledgements that would
    /// have freed it. A chunked read and a priming report are the two series that keep an
    /// exchange alive past one message.
    fn close_if_idle(&mut self, exchange: ExchangeKey) {
        if !self.im.interactions.idle(exchange) {
            return;
        }
        if self.im.reporting.iter().any(|(_, on)| *on == exchange) {
            return;
        }
        // Our own last message is still in flight: closing would drop its retransmission. The
        // acknowledgement that frees it closes the exchange; abandonment and §4.10.5.3's idle
        // reclamation are the backstops.
        if self.stack.is_awaiting_ack(exchange) {
            return;
        }
        self.im.interactions.forget(exchange);
        self.resend.forget(exchange);
        self.stack.close(exchange);
    }

    /// Everything above the messaging layer that was keyed on a session that has gone.
    ///
    /// §8.5: a subscription reports *on a session*, and one whose session has gone has nowhere to
    /// report — it would hold its slot until its maximum interval ran out. §5.5: the channel is
    /// released by the PASE session on it going away.
    fn session_gone(&mut self, session: SessionId) {
        let dropped = self.im.subscriptions.remove_for_session(Some(session));
        self.im.reporting.retain(|(_, on)| on.session != session);
        self.im.interactions.forget_session(session);
        self.resend.forget_session(session);
        self.channel.closed(session);
        if !self.channel.is_established() {
            self.pase = PaseProgress::default();
        }
        self.notify(Notice::SessionClosed {
            session,
            subscriptions: dropped,
        });
    }

    /// Closes a session this node decided to close, and cascades.
    fn close_session(&mut self, session: SessionId) {
        if self.stack.close_session(session) {
            self.session_gone(session);
        }
    }

    /// §4.11.1.1 step 2a: the evicted peer is owed a `CloseSession`, whether or not this node had
    /// anything else to say — without it the peer finds out at its next message, as a timeout.
    fn evicted(&mut self, evicted: Evicted) {
        if let (Some(peer), Some(bytes)) = (evicted.peer, self.buf.evict.get(..evicted.len))
            && evicted.len > 0
            && !self.outbox.push(peer, bytes)
        {
            self.notify(Notice::OutboxFull);
        }
        self.notify(Notice::Evicted {
            session: evicted.session,
        });
        self.session_gone(evicted.session);
    }

    // --- §5.5's channel against the commissioning window ------------------------------------

    /// §5.5's two ways back into commissioning mode.
    ///
    /// A window *opening* re-admits PASE: without it a node commissioned once can never be
    /// commissioned again — `OpenCommissioningWindow` succeeds, the node advertises, and every
    /// `PBKDFParamRequest` comes back `Busy`. Not while an established PASE session holds the
    /// channel, though: that is a commissioning in progress.
    ///
    /// An established channel is *released* to an open window only when the commissioning it
    /// was for is over and nothing else is: no fail-safe armed, and either one was armed and has
    /// since resolved (a commit or rollback, which also closes the session), or none ever was and
    /// the session has sat for [`PASE_ABANDON_GRACE`]. Releasing on "window open and fail-safe
    /// disarmed" alone would release the channel the instant PASE completes, before its
    /// commissioner has sent `ArmFailSafe` — admitting a second commissioner into the first one's
    /// commissioning, which is the takeover §5.5 rule 1 exists to prevent.
    fn watch_window<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        now: Instant,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let open = device.commissioning.window.borrow().open(now).is_some();
        // Not while a PASE session holds the channel: reopening would reset §5.5 rule 1 under a
        // commissioning in progress and admit a second commissioner into it. A held channel is
        // released by the rule below instead, once that commissioning is over.
        if open && !self.window_was_open && !self.channel.is_established() {
            self.channel.reopen();
            self.pase = PaseProgress::default();
            self.notify(Notice::WindowOpened);
        }
        self.window_was_open = open;
        if !self.channel.is_established() {
            return;
        }
        let armed = device.commissioning.fail_safe.borrow().armed(now).is_some();
        if armed {
            self.pase.armed_seen = true;
            return;
        }
        let abandoned = self
            .pase
            .established_at
            .is_some_and(|at| now.saturating_duration_since(at) >= PASE_ABANDON_GRACE);
        if open && (self.pase.armed_seen || abandoned) {
            self.channel.release();
            self.pase = PaseProgress::default();
            self.notify(Notice::ChannelReleased);
        }
    }

    /// §8.5.3: a change to a path a subscription covers is what makes a report due, and §7.10.3
    /// already records every such change — so the version table is where changes are read from.
    fn drain_changes<K, G, H, Ac, Gk, Ev, V, const F: usize>(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
    ) where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
    {
        let subscriptions = &mut self.im.subscriptions;
        device.versions.drain(&mut |endpoint, cluster| {
            subscriptions.note_cluster_change(endpoint, cluster);
        });
    }
}

/// A fresh 32-bit draw for MRP's jitter; a failed rng costs jitter, never a message.
fn random<C, K, G, H, Ac, Gk, Ev, V, const F: usize>(
    device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
) -> u32
where
    C: Config,
    K: KeyStore,
    G: Rng,
    H: ClusterHandler,
    Ac: AccessList,
    Gk: GroupKeyStore,
    Ev: EventLog,
    V: ChangeLog,
{
    device.credentials.rng.borrow().next_u32().unwrap_or(0)
}
