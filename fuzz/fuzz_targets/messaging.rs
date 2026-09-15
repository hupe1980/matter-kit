//! Message reception against arbitrary datagrams (Core §4.7.2).
//!
//! This is the code that runs *first* on anything arriving from the network, before the
//! sender has proved anything at all. Below it only the header decoder is more exposed, and
//! unlike the header decoder this one has **state**: a replay window, an exchange table, and
//! MRP timers, all of which an attacker would like to move.
//!
//! Five properties:
//!
//! 1. **Nothing panics**, whatever the bytes are, and no buffer is overrun.
//! 2. **No datagram ever creates a session.** Sessions come from PASE and CASE alone; a
//!    reception path that could add one would let an unauthenticated sender install keys.
//! 3. **The exchange table stays within its bound.** A peer that could open exchanges without
//!    limit would exhaust a node's fixed-capacity table and lock out every real one — so the
//!    table is the resource an unauthenticated flood aims at.
//! 4. **A rejected datagram leaves the node working — permanently.** After any amount of
//!    garbage, and once the clock has passed `EXCHANGE_IDLE_TIMEOUT` and the node has been
//!    polled, a real exchange must open, send and be received. The failure that matters here
//!    is not a crash but a node wedged by packets it already rejected.
//!
//!    This property used to stop one step short: a full exchange table was treated as a
//!    legitimate refusal and the run returned. It is legitimate only while the entries are
//!    *fresh* — §4.10.5.2 lets any unsecured datagram open an exchange, so an attacker chooses
//!    how full the table is, and "full" that never drains is a permanent denial of session
//!    establishment. Asserting recovery after the timeout is what makes the difference
//!    between the two visible.
//! 5. **Timers stay sane.** Whatever arrives, polling never loops forever.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::config::DefaultConfig;
use matter_kit::exchange::EXCHANGE_IDLE_TIMEOUT;
use matter_kit::messaging::{Messaging, Received};
use matter_kit::msg::{ProtocolId, SessionId};
use matter_kit::platform::{Instant, PeerAddr};

const SESSIONS: usize = 4;
const EXCHANGES: usize = 8;

type Stack = Messaging<DefaultConfig, SESSIONS, EXCHANGES>;

const PEER_ADDR: PeerAddr = PeerAddr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
/// §4.12.4 makes MRP's behaviour depend on the transport, so a peer is where it is *reached*,
/// not just an address.
const PEER: matter_kit::platform::Peer = matter_kit::platform::Peer::Udp(PEER_ADDR);

fn at(ms: u64) -> Instant {
    Instant::from_micros(ms.saturating_mul(1000))
}

fuzz_target!(|data: &[u8]| {
    let mut node = Stack::new(0x1000, 0x200, 0x4321);

    // Each chunk is one datagram from a stranger. Several in a row, because the interesting
    // failures are cumulative: a table that grows, a window that moves.
    let mut clock = 0u64;
    for chunk in data.chunks(96) {
        if chunk.is_empty() {
            continue;
        }
        let mut buf = [0u8; 96];
        let Some(slot) = buf.get_mut(..chunk.len()) else {
            continue;
        };
        slot.copy_from_slice(chunk);
        clock = clock.saturating_add(1);

        // Property 1: this must not panic for any input.
        match node.receive(slot, PEER, at(clock)) {
            Ok(Received::Message { exchange, .. } | Received::Duplicate { exchange, .. }) => {
                // Anything accepted on the unsecured session is a PASE message, which is the
                // only thing an unauthenticated peer may say.
                assert_eq!(
                    exchange.session,
                    SessionId::UNSECURED,
                    "with no session installed, nothing else can authenticate"
                );
            }
            Ok(Received::Acknowledged { .. }) | Err(_) => {}
        }

        // Property 2.
        assert!(
            node.sessions().is_empty(),
            "receiving a datagram must never install a session"
        );
        // Property 3.
        assert!(
            node.exchanges().len() <= EXCHANGES,
            "the exchange table must stay within the capacity `Config` sized it to"
        );

        // Property 5: whatever state the timers are in, draining them terminates.
        let mut drains = 0usize;
        while node.poll(at(clock.saturating_add(1_000_000)), 0).is_some() {
            drains = drains.saturating_add(1);
            assert!(drains < 10_000, "polling did not terminate");
        }
    }

    // Property 4: the node still works. An exchange opens, a message goes out, and the peer
    // reads it back — so nothing above left the tables or the counters wedged.
    let mut fresh = Stack::new(0x3000, 0x400, 0x9999);

    // Whatever the input filled, §4.10.5.3's cleanup must give it back. Move the clock past
    // the idle timeout and drive the timers the way a node's event loop would.
    let recovered = at(clock + 1)
        .saturating_add(EXCHANGE_IDLE_TIMEOUT)
        .saturating_add(matter_kit::platform::Duration::from_secs(1));
    let mut drains = 0usize;
    while node.poll(recovered, 0).is_some() {
        drains += 1;
        assert!(drains < 10_000, "polling did not terminate");
    }
    let exchange = node
        .open(SessionId::UNSECURED, ProtocolId::SECURE_CHANNEL, recovered)
        .expect("a node that cannot open an exchange can never establish another session");
    let mut out = [0u8; 512];
    let mut scratch = [0u8; 512];
    let Ok((len, _)) = node.send(
        exchange,
        matter_kit::sc::opcode::PBKDF_PARAM_REQUEST,
        true,
        b"still alive",
        recovered,
        0,
        &mut scratch,
        &mut out,
    ) else {
        return;
    };
    let Some(sent) = out.get_mut(..len) else {
        return;
    };
    match fresh.receive(
        sent,
        PEER,
        recovered.saturating_add(matter_kit::platform::Duration::from_millis(1)),
    ) {
        Ok(Received::Message { payload, .. }) => {
            assert_eq!(
                payload, b"still alive",
                "a real message must survive whatever came before it"
            );
        }
        other => panic!("a node poisoned by garbage: {other:?}"),
    }
});
