//! Two nodes exchanging reliable messages over a network that loses a third of them.
//!
//! Run it with `cargo run --example reliable_exchange --features std`.
//!
//! Everything here is real: the message frame of Core §4.4, the duplicate-detection window
//! of §4.6.5, the retransmission ladder of §4.12.2.1. The only pretend part is the network,
//! and the point of the example is what that buys — the run finishes instantly, prints the
//! same thing every time, and the "seconds" in the output are seconds the protocol
//! believes in rather than seconds you waited.

// An example is a program, not a library: its inputs come from the lines above it rather
// than from the network, and `expect` on something this file just constructed is clearer
// than error plumbing that can never fire. The crate's own modules keep the denials.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use matter_kit::exchange::{Mrp, MrpParams, OnTimeout};
use matter_kit::msg::{
    CounterKind, CounterWindow, Destination, MessageCounter, MessageHeader, NodeId, ProtocolHeader,
    ProtocolId, SessionId, Verdict,
};
use matter_kit::platform::sim::{Impairment, SimNet, block_on};
use matter_kit::platform::{Duration, PeerAddr, Timer, Udp};

fn main() {
    let net = SimNet::new(0xC0FFEE);
    // A third of everything is dropped, and what survives arrives late and out of order.
    net.impair(Impairment {
        loss_percent: 33,
        duplicate_percent: 10,
        latency: Duration::from_millis(8),
        jitter: Duration::from_millis(40),
    });

    let light = net.node(1);
    let controller = net.node(2);

    let mut counter = MessageCounter::at(1000);
    let mut mrp = Mrp::new(MrpParams::default());
    let mut window = CounterWindow::new(CounterKind::SecureUnicast);
    let mut delivered = 0u32;

    println!("a 33% loss / 10% duplication / 40 ms jitter link, on virtual time\n");

    block_on(&net, async {
        for message in 1..=5u8 {
            let sent_at = Timer::now(&net);
            let msg_counter = counter.take().expect("counters left");
            mrp.on_send(msg_counter, sent_at, net.rng().next() as u32)
                .expect("nothing else is in flight");

            send(&light, controller.addr(), msg_counter, message, true, None).await;
            let mut transmissions = 1u32;

            // Drive the exchange until it is acknowledged or abandoned.
            let outcome = loop {
                // Anything waiting for the controller?
                let mut buf = [0u8; 256];
                if let Some((n, from)) = poll_recv(&controller, &mut buf) {
                    let (header, rest) = MessageHeader::decode(&buf[..n]).expect("a header");
                    let (protocol, payload) = ProtocolHeader::decode(rest).expect("a protocol");

                    let verdict = window.accept(header.message_counter);
                    if verdict == Verdict::New && !payload.is_empty() {
                        delivered += 1;
                    }
                    // §4.12.2.2: acknowledge every instance, duplicates included.
                    if protocol.reliability {
                        send(&controller, from, 0, 0, false, Some(header.message_counter)).await;
                    }
                    continue;
                }

                // Anything waiting for the light?
                if let Some((n, _)) = poll_recv(&light, &mut buf) {
                    let now = Timer::now(&net);
                    let (_, rest) = MessageHeader::decode(&buf[..n]).expect("a header");
                    let (protocol, _) = ProtocolHeader::decode(rest).expect("a protocol");
                    if let Some(ack) = protocol.acknowledged_counter
                        && mrp.on_ack(ack, now)
                    {
                        break Outcome::Acknowledged;
                    }
                    continue;
                }

                // Nothing is deliverable right now. Move time to whichever comes first:
                // the next datagram the link has queued, or the retransmission timer.
                // The simulator knows about the former; only MRP knows about the latter,
                // so advancing to *its* next event alone would stall here forever.
                let mrp_deadline = mrp.poll_deadline();
                let before = Timer::now(&net);
                if !net.advance_to_next_event() {
                    match mrp_deadline {
                        Some(d) if d > before => {
                            net.advance(d.saturating_duration_since(before));
                        }
                        _ => break Outcome::Stalled,
                    }
                } else if let Some(d) = mrp_deadline
                    && d < Timer::now(&net)
                {
                    // The link's next event is further out than the retransmission timer.
                    net.advance(d.saturating_duration_since(before));
                }
                let now = Timer::now(&net);
                match mrp.on_timeout(now, net.rng().next() as u32) {
                    OnTimeout::Retransmit { counter: c, .. } => {
                        transmissions += 1;
                        send(&light, controller.addr(), c, message, true, None).await;
                    }
                    OnTimeout::GiveUp { .. } => break Outcome::GaveUp,
                    _ => {}
                }
            };

            // An abandoned or stalled exchange still holds MRP state; closing it is what
            // frees the one pending retransmission §4.12.3 allows.
            mrp.close();

            let elapsed = Timer::now(&net).saturating_duration_since(sent_at);
            println!(
                "  message {message}: {outcome:?} after {transmissions} transmission(s), {} ms",
                elapsed.as_millis()
            );
        }
    });

    println!(
        "\n  {delivered} of 5 reached the application, never twice\n  \
         {} sent, {} dropped, {} duplicated by the link\n  \
         virtual time elapsed: {:.1} s (wall-clock: none)",
        net.sent(),
        net.dropped(),
        net.duplicated(),
        Timer::now(&net).as_micros() as f64 / 1_000_000.0,
    );
}

#[derive(Debug)]
enum Outcome {
    Acknowledged,
    GaveUp,
    Stalled,
}

async fn send(
    from: &matter_kit::platform::sim::SimNode<'_>,
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
    let mut at = header.encode(&mut buf).expect("room for the header");
    at += protocol
        .encode(&mut buf[at..])
        .expect("room for the protocol header");
    buf[at] = payload;
    at += 1;
    from.send_to(&buf[..at], to).await.expect("send");
}

/// A non-blocking receive: the simulated socket is ready, or it is not.
fn poll_recv(
    node: &matter_kit::platform::sim::SimNode<'_>,
    buf: &mut [u8],
) -> Option<(usize, PeerAddr)> {
    use core::future::Future as _;
    let waker = core::task::Waker::noop();
    let mut cx = core::task::Context::from_waker(waker);
    let mut fut = core::pin::pin!(node.recv_from(buf));
    match fut.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(Ok(v)) => Some(v),
        _ => None,
    }
}
