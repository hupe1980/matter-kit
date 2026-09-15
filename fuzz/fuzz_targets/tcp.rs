//! Stream framing against an arbitrary byte stream (Core §4.5).
//!
//! The framer is the first code to touch a TCP connection, before the message layer and so
//! before any session: everything here arrives from whoever opened the socket. It also holds
//! the one piece of state a stream gives an attacker to move — a length the peer chose, used
//! to decide how many octets to buffer.
//!
//! Three properties:
//!
//! 1. **Nothing panics**, and the buffer is never overrun: `N` is §4.15.2.3's Maximum Message
//!    Size and no message may exceed it.
//! 2. **A message that comes out went in.** The framer is fed in fuzzer-chosen chunk sizes, so
//!    the same stream split differently must produce the same messages — a split prefix, a
//!    coalesced read and a message straddling three reads are all the same stream.
//! 3. **A failure is final.** §4.15.2.3 closes the connection, and a stream that has lost its
//!    framing cannot be resynchronised, so no message may appear after one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::transport::tcp::{Framed, Framer};

/// Small enough that the fuzzer reaches the "too large" path, large enough to frame something.
const MAX: usize = 256;

/// Feeds `stream` in chunks of `chunk`, collecting whatever messages fall out.
fn run(stream: &[u8], chunk: usize) -> (Vec<Vec<u8>>, bool) {
    let mut framer = Framer::<MAX>::new();
    let mut out = Vec::new();
    let mut rest = stream;
    while !rest.is_empty() {
        let offered = rest.get(..chunk.min(rest.len())).unwrap_or(rest);
        let Ok(taken) = framer.push(offered) else {
            return (out, true);
        };
        rest = rest.get(taken..).unwrap_or(&[]);
        loop {
            match framer.poll() {
                Ok(Framed::Message(message)) => {
                    assert!(message.len() <= MAX, "a message past the maximum size");
                    out.push(message.to_vec());
                }
                Ok(Framed::Incomplete { .. }) => break,
                Err(_) => return (out, true),
            }
        }
        if taken == 0 {
            // poll() drew nothing and push() took nothing: the loop would spin.
            break;
        }
    }
    (out, framer.is_failed())
}

fuzz_target!(|data: &[u8]| {
    let Some((&size, stream)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(size).max(1);

    let (whole, failed) = run(stream, stream.len().max(1));
    let (split, split_failed) = run(stream, chunk);

    // How the stream was cut up is not something the peer's framing depends on.
    assert_eq!(whole, split, "chunking changed the messages");
    assert_eq!(failed, split_failed, "chunking changed the outcome");

    // A framer that gave up stays given up: §4.15.2.3 closes the connection.
    if failed {
        let mut framer = Framer::<MAX>::new();
        let _ = framer.push(stream);
        while framer.poll().is_ok() {
            if matches!(framer.poll(), Ok(Framed::Incomplete { .. })) {
                break;
            }
        }
        if framer.is_failed() {
            assert!(framer.push(&[0, 0, 0, 0]).is_err());
            assert!(framer.poll().is_err());
        }
    }
});
