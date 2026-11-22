//! The whole loop, over the platform traits: a device with sockets and a timer writes none.

use core::future::poll_fn;
use core::pin::pin;
use core::task::Poll;

use heapless::Vec;

use super::{AccessList, ChangeLog, Device, EventLog, GroupKeyStore, Notice, Runtime};
use crate::commissioning::window::WindowStatus;
use crate::config::{Config, MAX_UDP_MESSAGE};
use crate::crypto::KeyStore;
use crate::discovery::advertiser::{Advertiser, OpenWindow};
use crate::discovery::{CommissioningMode, Responder};
use crate::im::ClusterHandler;
use crate::platform::{Duration, Instant, Peer, PeerAddr, Rng, Timer, Udp};

/// The mDNS side of [`Runtime::run`]: the socket bound to 5353, the group answers go to, and
/// the interface both live on.
///
/// The interface index matters twice: it is the link the multicast group is joined on, and the
/// zone every answer is sent with. `ff02::fb` is link-local, so a send with no interface is
/// ambiguous and the operating system refuses it.
#[derive(Debug)]
pub struct Mdns<'a, M: Udp> {
    /// The mDNS socket.
    pub socket: &'a M,
    /// `ff02::fb` on the interface — [`StdUdp::mdns_group`](crate::platform::os::StdUdp) on std.
    pub group: PeerAddr,
    /// The interface index, also used to join groupcast addresses.
    pub interface: u32,
}

/// What woke the loop.
enum Event {
    Matter(usize, PeerAddr),
    Mdns(usize),
    Deadline,
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
    /// Runs the node: Matter datagrams, mDNS queries, timers, for ever.
    ///
    /// Every iteration does the time-driven work first ([`Runtime::poll`]) and only then waits,
    /// whichever source woke it. A select that returns the first ready source starves whichever
    /// it polls last, and both orderings fail: sockets first starves the timer on a link with
    /// steady mDNS traffic, timer first starves the sockets the moment any deadline is overdue.
    /// Waiting may prefer the sockets because nothing time-driven happens in it.
    ///
    /// `on_notice` hears every [`Notice`], in order.
    pub async fn run<
        K,
        G,
        H,
        Ac,
        Gk,
        Ev,
        V,
        U,
        M,
        T,
        const F: usize,
        const AF: usize,
        const A: usize,
    >(
        &mut self,
        device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
        matter: &U,
        mdns: Mdns<'_, M>,
        advertiser: &mut Advertiser<AF, A>,
        timer: &T,
        mut on_notice: impl FnMut(Notice),
    ) -> !
    where
        K: KeyStore,
        G: Rng,
        H: ClusterHandler,
        Ac: AccessList,
        Gk: GroupKeyStore,
        Ev: EventLog,
        V: ChangeLog,
        U: Udp,
        M: Udp,
        T: Timer,
    {
        let mut matter_buf = [0u8; MAX_UDP_MESSAGE];
        let mut mdns_buf = [0u8; MAX_UDP_MESSAGE];
        let mut answer = [0u8; MAX_UDP_MESSAGE];
        let mut joined: Vec<[u8; 16], 16> = Vec::new();
        loop {
            let now = timer.now();
            self.poll(device, now);
            self.flush(matter).await;
            while let Some(notice) = self.notice() {
                on_notice(notice);
            }
            refresh(device, advertiser, now);
            join_groups(device, matter, mdns.interface, &mut joined);

            let deadline = self
                .next_deadline(device)
                .unwrap_or_else(|| now.saturating_add(Duration::from_secs(1)));
            let event = {
                let mut from_matter = pin!(matter.recv_from(&mut matter_buf));
                let mut from_mdns = pin!(mdns.socket.recv_from(&mut mdns_buf));
                let mut sleep = pin!(timer.sleep_until(deadline));
                poll_fn(|cx| {
                    if let Poll::Ready(Ok((n, from))) = from_matter.as_mut().poll(cx) {
                        return Poll::Ready(Event::Matter(n, from));
                    }
                    if let Poll::Ready(Ok((n, _))) = from_mdns.as_mut().poll(cx) {
                        return Poll::Ready(Event::Mdns(n));
                    }
                    if sleep.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Event::Deadline);
                    }
                    Poll::Pending
                })
                .await
            };
            match event {
                Event::Matter(n, from) => {
                    if let Some(datagram) = matter_buf.get_mut(..n) {
                        self.receive(device, datagram, Peer::Udp(from), timer.now());
                    }
                    self.flush(matter).await;
                }
                Event::Mdns(n) => {
                    // Most traffic on 5353 is other people's; `respond` answers only what is
                    // asked of this node, and never answers a response (RFC 6762 §6).
                    let advertisements = advertiser.advertisements();
                    let responder = Responder::new(&advertisements);
                    if let Some(query) = mdns_buf.get(..n)
                        && let Ok((bytes, answered)) = responder.respond(query, &mut answer)
                        && !answered.is_empty()
                    {
                        let _ = mdns.socket.send_to(bytes, mdns.group).await;
                    }
                }
                Event::Deadline => {}
            }
        }
    }

    /// Sends everything queued.
    async fn flush<U: Udp>(&mut self, matter: &U) {
        while let Some((peer, bytes)) = self.transmit() {
            if let Peer::Udp(addr) = peer {
                // A failed send is a lost datagram; MRP retransmits a reliable one.
                let _ = matter.send_to(bytes, addr).await;
            }
        }
    }
}

/// Rebuilds the advertisement set from the fabric table and the window.
fn refresh<C, K, G, H, Ac, Gk, Ev, V, const F: usize, const AF: usize, const A: usize>(
    device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
    advertiser: &mut Advertiser<AF, A>,
    now: Instant,
) where
    C: Config,
    K: KeyStore,
    G: Rng,
    H: ClusterHandler,
    Ac: AccessList,
    Gk: GroupKeyStore,
    Ev: EventLog,
    V: ChangeLog,
{
    let window = device
        .commissioning
        .window
        .borrow()
        .open(now)
        .map(|w| OpenWindow {
            discriminator: w.discriminator,
            mode: match w.status {
                WindowStatus::EnhancedOpen => CommissioningMode::Enhanced,
                _ => CommissioningMode::Basic,
            },
        });
    let fabrics = device.credentials.fabrics.borrow();
    let operational = fabrics
        .iter()
        .map(|f| (f.instance_name(), f.compressed.subtype()));
    let _ = advertiser.refresh(operational, window);
}

/// §2.5.6.2: a group is reached at an address derived from the fabric id and the group id, and a
/// node that never joins it is a node no groupcast reaches. Idempotent per address.
fn join_groups<C, K, G, H, Ac, Gk, Ev, V, U, const F: usize>(
    device: &Device<'_, C, K, G, H, Ac, Gk, Ev, V, F>,
    matter: &U,
    interface: u32,
    joined: &mut Vec<[u8; 16], 16>,
) where
    C: Config,
    K: KeyStore,
    G: Rng,
    H: ClusterHandler,
    Ac: AccessList,
    Gk: GroupKeyStore,
    Ev: EventLog,
    V: ChangeLog,
    U: Udp,
{
    let Some(memberships) = device.memberships else {
        return;
    };
    let fabrics = device.credentials.fabrics.borrow();
    memberships.memberships(&mut |fabric, group, _endpoint| {
        let Some(fabric_id) = fabrics.find(fabric).map(|f| f.fabric_id) else {
            return;
        };
        let address = crate::group::multicast_address(fabric_id, group).addr;
        if !joined.contains(&address) && matter.join_multicast(address, interface).is_ok() {
            let _ = joined.push(address);
        }
    });
}
