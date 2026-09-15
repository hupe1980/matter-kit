//! MRP against a network that loses, duplicates and reorders — Core §4.12 end to end.
//!
//! This is the test the reliability layer exists for, and it is the reason
//! [`matter_kit::platform::sim`] is a supported platform rather than a mock. Two nodes
//! exchange reliable messages over a virtual link whose loss rate, duplication rate and
//! jitter the test sets; the virtual clock jumps to each deadline instead of waiting for
//! it, so a scenario spanning minutes of retransmission ladders runs in microseconds and
//! gives the same answer every run.
//!
//! What is under test here is the *composition*: the message header, the exchange table,
//! the duplicate-detection window and the MRP state machine, driven together by real
//! datagrams. Each of them has unit tests of its own; none of those would catch a
//! disagreement between them.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use matter_kit::exchange::{Mrp, MrpParams, OnTimeout};
use matter_kit::msg::{
    CounterKind, CounterWindow, Destination, MessageCounter, MessageHeader, NodeId, ProtocolHeader,
    ProtocolId, SessionId, Verdict,
};
use matter_kit::platform::sim::{Impairment, SimNet, SimNode, block_on};
use matter_kit::platform::{Duration, Instant, PeerAddr, Timer, Udp};

/// One end of a conversation: a counter to send with, a window to judge by, and the MRP
/// state for its single exchange.
struct Peer<'a> {
    node: SimNode<'a>,
    counter: MessageCounter,
    window: CounterWindow,
    mrp: Mrp,
    /// Payloads handed up to "the application" — never a duplicate.
    delivered: heapless::Vec<u8, 32>,
    /// How many datagrams this peer put on the wire, retransmissions included.
    transmissions: u32,
    /// The payload of the message awaiting acknowledgement. MRP retransmits *the same
    /// message* — "logical retransmission is of a given message as identified by its
    /// message counter" — so the payload has to be kept, not invented again.
    pending_payload: u8,
}

impl<'a> Peer<'a> {
    fn new(node: SimNode<'a>, first_counter: u32) -> Self {
        Self {
            node,
            counter: MessageCounter::new(first_counter),
            window: CounterWindow::new(CounterKind::SecureUnicast),
            mrp: Mrp::new(MrpParams::default()),
            delivered: heapless::Vec::new(),
            transmissions: 0,
            pending_payload: 0,
        }
    }

    fn addr(&self) -> PeerAddr {
        self.node.addr()
    }

    /// Builds a message and puts it on the wire.
    async fn transmit(
        &mut self,
        to: PeerAddr,
        counter: u32,
        payload: u8,
        reliable: bool,
        ack: Option<u32>,
    ) {
        let header = MessageHeader {
            session_id: SessionId(1),
            message_counter: counter,
            source: Some(NodeId(1)),
            destination: Destination::Node(NodeId(2)),
            ..MessageHeader::default()
        };
        let protocol = ProtocolHeader {
            initiator: true,
            reliability: reliable,
            acknowledged_counter: ack,
            protocol: ProtocolId::SECURE_CHANNEL,
            opcode: 1,
            ..ProtocolHeader::default()
        };

        let mut buf = [0u8; 128];
        let mut at = header.encode(&mut buf).unwrap();
        at += protocol.encode(&mut buf[at..]).unwrap();
        buf[at] = payload;
        at += 1;

        self.transmissions += 1;
        self.node.send_to(&buf[..at], to).await.unwrap();
    }

    /// Sends a new reliable message, taking a fresh counter.
    async fn send_reliable(&mut self, to: PeerAddr, payload: u8, now: Instant, r: u32) {
        let counter = self.counter.take().unwrap();
        self.mrp.on_send(counter, now, r).unwrap();
        self.pending_payload = payload;
        let ack = self.mrp.take_piggyback();
        self.transmit(to, counter, payload, true, ack).await;
    }

    /// Handles one arriving datagram.
    async fn receive(&mut self, buf: &[u8], from: PeerAddr, now: Instant) {
        let (header, rest) = MessageHeader::decode(buf).unwrap();
        let (protocol, payload) = ProtocolHeader::decode(rest).unwrap();

        // The message layer judges the counter before anything else looks at the message.
        let verdict = self.window.accept(header.message_counter);

        if let Some(ack) = protocol.acknowledged_counter {
            self.mrp.on_ack(ack, now);
        }
        if protocol.reliability {
            // §4.12.2.2: acknowledge every instance, "including duplicates".
            self.mrp.on_reliable_received(
                header.message_counter,
                now,
                verdict == Verdict::Duplicate,
            );
        }

        // "The reliability layer SHALL only propagate the first instance of a message to
        // the next higher layer."
        if verdict == Verdict::New && !payload.is_empty() {
            let _ = self.delivered.push(payload[0]);
        }

        // A standalone acknowledgement is due immediately here rather than after the
        // piggyback timeout, since this test has nothing else to send.
        if let Some(counter) = self.mrp.take_piggyback() {
            self.transmit(from, self.counter.peek(), 0, false, Some(counter))
                .await;
        }
    }
}

/// Runs both peers until `a` has no pending retransmission, or the budget runs out.
///
/// Returns whether the message was acknowledged rather than abandoned.
async fn run_until_settled(net: &SimNet, a: &mut Peer<'_>, b: &mut Peer<'_>) -> bool {
    let b_addr = b.addr();
    let a_addr = a.addr();

    for _ in 0..1000 {
        // Deliver everything that is due, to either peer.
        let mut moved = false;
        let mut buf = [0u8; 256];
        loop {
            let now = Timer::now(net);
            let mut progressed = false;
            if let Some((n, from)) = try_recv(&b.node, &mut buf) {
                b.receive(&buf[..n], from, now).await;
                progressed = true;
            }
            if let Some((n, from)) = try_recv(&a.node, &mut buf) {
                a.receive(&buf[..n], from, now).await;
                progressed = true;
            }
            if !progressed {
                break;
            }
            moved = true;
        }

        if !a.mrp.is_awaiting_ack() {
            return true;
        }

        // Nothing more is deliverable now; move time to the next scheduled event.
        let deadlines = [a.mrp.poll_deadline(), b.mrp.poll_deadline()];
        let next = deadlines.iter().flatten().min().copied();
        if let Some(next) = next
            && next > Timer::now(net)
        {
            net.advance(next.saturating_duration_since(Timer::now(net)));
        } else if !moved && !net.advance_to_next_event() {
            break;
        }

        let now = Timer::now(net);
        // Both peers get their timers serviced.
        loop {
            match a.mrp.on_timeout(now, 0) {
                OnTimeout::Retransmit { counter, .. } => {
                    let payload = a.pending_payload;
                    a.transmit(b_addr, counter, payload, true, None).await;
                }
                OnTimeout::SendStandaloneAck { counter } => {
                    a.transmit(b_addr, a.counter.peek(), 0, false, Some(counter))
                        .await;
                }
                OnTimeout::GiveUp { .. } => return false,
                _ => break,
            }
        }
        loop {
            match b.mrp.on_timeout(now, 0) {
                OnTimeout::SendStandaloneAck { counter } => {
                    b.transmit(a_addr, b.counter.peek(), 0, false, Some(counter))
                        .await;
                }
                OnTimeout::Retransmit { counter, .. } => {
                    let payload = b.pending_payload;
                    b.transmit(a_addr, counter, payload, true, None).await;
                }
                OnTimeout::GiveUp { .. } => return false,
                _ => break,
            }
        }
    }
    !a.mrp.is_awaiting_ack()
}

/// A non-blocking receive: the simulated socket is ready or it is not.
fn try_recv(node: &SimNode<'_>, buf: &mut [u8]) -> Option<(usize, PeerAddr)> {
    let waker = core::task::Waker::noop();
    let mut cx = core::task::Context::from_waker(waker);
    let fut = node.recv_from(buf);
    let mut fut = core::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(Ok(v)) => Some(v),
        _ => None,
    }
}

use core::future::Future as _;

#[test]
fn a_perfect_network_needs_one_transmission() {
    let net = SimNet::new(1);
    let mut a = Peer::new(net.node(1), 1000);
    let mut b = Peer::new(net.node(2), 2000);
    let b_addr = b.addr();

    block_on(&net, async {
        a.send_reliable(b_addr, 0x42, Timer::now(&net), 0).await;
        assert!(run_until_settled(&net, &mut a, &mut b).await);
    });

    assert_eq!(a.transmissions, 1, "no retransmission was needed");
    assert_eq!(&b.delivered[..], &[0x42]);
}

#[test]
fn a_lost_message_is_retransmitted_until_it_lands() {
    // Drop the first two datagrams outright, then let the link through.
    let net = SimNet::new(2);
    let mut a = Peer::new(net.node(1), 1000);
    let mut b = Peer::new(net.node(2), 2000);
    let b_addr = b.addr();

    net.impair(Impairment::lossy(100));
    block_on(&net, async {
        a.send_reliable(b_addr, 0x42, Timer::now(&net), 0).await;
        // The first transmission is dropped. Let one retransmission be dropped too.
        for _ in 0..2 {
            if let Some(d) = a.mrp.poll_deadline() {
                net.advance(d.saturating_duration_since(Timer::now(&net)));
                if let OnTimeout::Retransmit { counter, .. } = a.mrp.on_timeout(Timer::now(&net), 0)
                {
                    let payload = a.pending_payload;
                    a.transmit(b_addr, counter, payload, true, None).await;
                }
            }
        }
        assert_eq!(b.delivered.len(), 0, "nothing has arrived yet");

        // Now heal the network and let it settle.
        net.impair(Impairment::default());
        assert!(
            run_until_settled(&net, &mut a, &mut b).await,
            "it should get through once the link works"
        );
    });

    assert!(a.transmissions >= 3, "it took {} goes", a.transmissions);
    assert_eq!(&b.delivered[..], &[0x42], "and arrived exactly once");
}

#[test]
fn a_duplicated_message_is_acknowledged_but_delivered_once() {
    // §4.12.2.2 in one test: every instance is acknowledged, only the first is propagated.
    let net = SimNet::new(3);
    let mut a = Peer::new(net.node(1), 1000);
    let mut b = Peer::new(net.node(2), 2000);
    let b_addr = b.addr();

    net.impair(Impairment {
        duplicate_percent: 100,
        ..Impairment::default()
    });

    block_on(&net, async {
        a.send_reliable(b_addr, 0x42, Timer::now(&net), 0).await;
        assert!(run_until_settled(&net, &mut a, &mut b).await);
    });

    assert!(
        net.duplicated() >= 1,
        "the link duplicates everything, acknowledgements included"
    );
    assert_eq!(&b.delivered[..], &[0x42], "but the application saw it once");
}

#[test]
fn reordering_does_not_lose_a_message() {
    // Latency plus jitter means datagrams arrive in a different order than they were sent,
    // which is what the counter window's bitmap is for.
    let net = SimNet::new(4);
    let mut a = Peer::new(net.node(1), 1000);
    let mut b = Peer::new(net.node(2), 2000);
    let b_addr = b.addr();

    net.impair(Impairment::jittery(
        Duration::from_millis(5),
        Duration::from_millis(60),
    ));

    block_on(&net, async {
        // Eight unreliable messages, sent back to back so the jitter shuffles them.
        for i in 0..8u8 {
            let counter = a.counter.take().unwrap();
            a.transmit(b_addr, counter, i, false, None).await;
        }
        // Let every one of them land.
        for _ in 0..64 {
            let now = Timer::now(&net);
            let mut buf = [0u8; 256];
            if let Some((n, from)) = try_recv(&b.node, &mut buf) {
                b.receive(&buf[..n], from, now).await;
            } else if !net.advance_to_next_event() {
                break;
            }
        }
    });

    assert_eq!(b.delivered.len(), 8, "every message was delivered");
    let mut sorted = b.delivered.clone();
    sorted.sort_unstable();
    assert_eq!(&sorted[..], &[0, 1, 2, 3, 4, 5, 6, 7], "and none was lost");
    assert_ne!(
        &b.delivered[..],
        &[0, 1, 2, 3, 4, 5, 6, 7],
        "but they did not arrive in order"
    );
}

#[test]
fn a_replayed_message_is_never_delivered_twice() {
    // The security case rather than the network one: an attacker captures a datagram and
    // sends it again, long after the fact.
    let net = SimNet::new(5);
    let mut a = Peer::new(net.node(1), 1000);
    let mut b = Peer::new(net.node(2), 2000);
    let b_addr = b.addr();

    block_on(&net, async {
        a.send_reliable(b_addr, 0x42, Timer::now(&net), 0).await;
        assert!(run_until_settled(&net, &mut a, &mut b).await);
        assert_eq!(&b.delivered[..], &[0x42]);

        // The attacker replays the same counter.
        a.transmit(b_addr, 1000, 0x42, true, None).await;
        let mut buf = [0u8; 256];
        for _ in 0..8 {
            let now = Timer::now(&net);
            if let Some((n, from)) = try_recv(&b.node, &mut buf) {
                b.receive(&buf[..n], from, now).await;
            } else if !net.advance_to_next_event() {
                break;
            }
        }
    });

    assert_eq!(
        &b.delivered[..],
        &[0x42],
        "the replay was dropped by the counter window"
    );
}

#[test]
fn a_dead_peer_makes_the_sender_give_up_after_five_transmissions() {
    // §4.12.2.1: "The sender SHALL retry up to a configured maximum number of times
    // (MRP_MAX_TRANSMISSIONS - 1) before giving up and notifying the application."
    let net = SimNet::new(6);
    let mut a = Peer::new(net.node(1), 1000);
    let mut b = Peer::new(net.node(2), 2000);
    let b_addr = b.addr();

    net.impair(Impairment::lossy(100));

    block_on(&net, async {
        a.send_reliable(b_addr, 0x42, Timer::now(&net), 0).await;
        assert!(
            !run_until_settled(&net, &mut a, &mut b).await,
            "it must give up, not retry forever"
        );
    });

    assert_eq!(
        a.transmissions,
        matter_kit::exchange::MRP_MAX_TRANSMISSIONS,
        "one original plus four retransmissions"
    );
    assert!(b.delivered.is_empty());
    // A peer that never answers is never *active*, so §4.12.2.1 gives it the idle
    // interval of 500 ms rather than the 300 ms active one Core Table 21 is printed with:
    // 550 + 550 + 880 + 1408 + 2252.8 = 5640.8 ms. Table 21 scaled by 500/300.
    assert_eq!(
        Timer::now(&net).as_micros(),
        5_640_800,
        "the idle-peer ladder is Table 21 scaled by the idle interval"
    );
}

#[test]
fn a_flaky_link_still_delivers_everything_eventually() {
    // 30% loss, duplication and jitter at once, over many messages: the property is that
    // nothing is lost and nothing is delivered twice.
    for seed in 1..=5u64 {
        let net = SimNet::new(seed);
        let mut a = Peer::new(net.node(1), 1000);
        let mut b = Peer::new(net.node(2), 2000);
        let b_addr = b.addr();

        net.impair(Impairment {
            loss_percent: 30,
            duplicate_percent: 20,
            latency: Duration::from_millis(2),
            jitter: Duration::from_millis(20),
        });

        let mut sent = heapless::Vec::<u8, 8>::new();
        block_on(&net, async {
            for i in 0..5u8 {
                a.send_reliable(b_addr, i, Timer::now(&net), 0).await;
                let ok = run_until_settled(&net, &mut a, &mut b).await;
                if ok {
                    let _ = sent.push(i);
                }
                a.mrp.close();
            }
        });

        // MRP gives *at least once*, and the sender's knowledge is weaker than the
        // receiver's: a message can arrive and have its acknowledgement lost, in which
        // case the sender gives up on something the receiver already has. So the property
        // is containment, not equality.
        for acked in &sent {
            assert!(
                b.delivered.contains(acked),
                "seed {seed}: message {acked} was acknowledged but never delivered"
            );
        }
        // Nothing is delivered twice, however often the link duplicates or the sender
        // retransmits — that is what the counter window is for.
        for i in 0..b.delivered.len() {
            for j in (i + 1)..b.delivered.len() {
                assert_ne!(
                    b.delivered[i], b.delivered[j],
                    "seed {seed}: message {} reached the application twice",
                    b.delivered[i]
                );
            }
        }
        // And what did arrive arrived in the order it was sent.
        let mut ordered = b.delivered.clone();
        ordered.sort_unstable();
        assert_eq!(
            &ordered[..],
            &b.delivered[..],
            "seed {seed}: delivered out of order"
        );
    }
}
