//! An mDNS answer actually leaves the machine (Core §4.3, RFC 6762).
//!
//! `ff02::fb` is a **link-local** multicast address, and a link-local destination with no
//! interface attached is ambiguous: the operating system refuses the send rather than
//! guessing which link was meant. That makes it a uniquely quiet failure — the responder
//! computes a perfectly correct answer, `send_to` returns an error far away from any
//! discovery code, and the node is simply never found.
//!
//! No sans-I/O test can reach this. It needs a real socket, a real group join, and a real
//! datagram.

#![cfg(feature = "std")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::future::poll_fn;
use core::pin::pin;
use core::task::Poll;

use matter_kit::platform::Udp;
use matter_kit::platform::os::{StdUdp, block_on};

/// Loopback, which every machine has and which needs no network to be up.
const LOOPBACK_IFINDEX: u32 = 1;

#[test]
fn an_answer_sent_to_the_group_reaches_a_joined_socket() {
    let listener = match StdUdp::bind_mdns(LOOPBACK_IFINDEX) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("skipping: the environment refused an mDNS socket ({e:?})");
            return;
        }
    };
    // The group address the socket itself hands back — zoned to the interface it joined.
    // Building it by hand from the constant is exactly the mistake this test exists for.
    let group = listener
        .mdns_group()
        .expect("a socket from bind_mdns knows its group");
    assert_eq!(
        group.scope_id, LOOPBACK_IFINDEX,
        "the answer carries the zone the join used"
    );

    let sender = StdUdp::bind(0).expect("an ephemeral port");
    if block_on(async { sender.send_to(b"\x00\x00probe", group).await }).is_err() {
        eprintln!("skipping: the environment refused a multicast send");
        return;
    }

    let mut buf = [0u8; 256];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let got = block_on(async {
        let mut rx = pin!(listener.recv_from(&mut buf));
        poll_fn(|cx| {
            if let Poll::Ready(r) = rx.as_mut().poll(cx) {
                return Poll::Ready(Some(r));
            }
            if std::time::Instant::now() > deadline {
                return Poll::Ready(None);
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    });

    match got {
        Some(Ok((n, _))) => assert!(n >= 7, "the datagram arrived whole"),
        Some(Err(e)) => panic!("receive failed: {e:?}"),
        None => panic!("a joined socket never received a datagram sent to its own group"),
    }
}
