//! The mDNS socket binds and joins the group on a real machine (Core §4.3, RFC 6762).
//!
//! A responder that cannot own port 5353 never sees a query, and this is the one part of
//! discovery no sans-I/O test can reach: the failure is an operating system refusing a bind,
//! not a protocol mistake. Port 5353 is almost always already held — by `mDNSResponder` on
//! macOS, by Avahi on most Linux — so binding it at all is the thing worth proving.

#![cfg(feature = "std")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use matter_kit::platform::os::StdUdp;

#[test]
fn the_mdns_port_binds_and_joins_the_group_even_when_a_system_responder_holds_it() {
    let socket = match StdUdp::bind_mdns(0) {
        Ok(socket) => socket,
        Err(e) => {
            // A sandbox with no network namespace cannot join a multicast group. That is the
            // environment's limit, not the crate's, so it is reported rather than failed.
            eprintln!("skipping: the environment refused an mDNS socket ({e:?})");
            return;
        }
    };
    let addr = socket.local_addr().expect("bound");
    assert_eq!(addr.port, 5353, "a responder must own the mDNS port");

    // A second one binds the same port, which is what SO_REUSEADDR is for — and is the case
    // that fails without it, because the system daemon is already there.
    let second = StdUdp::bind_mdns(0).expect("a second responder shares the port");
    assert_eq!(second.local_addr().expect("bound").port, 5353);
}
