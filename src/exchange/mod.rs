//! Exchanges and the Message Reliability Protocol (Core §4.10, §4.12).
//!
//! An **exchange** is one conversation: a request and its response, a whole commissioning
//! flow, a subscription's lifetime. Every message names the exchange it belongs to, and
//! the pair (exchange id, who initiated it) identifies it within a session — the same
//! number can name two different exchanges if the two nodes each chose it, which is why
//! the initiator flag is part of the key rather than an aside.
//!
//! On top of that sits [`Mrp`], which makes a message reliable over a transport that is
//! not.
//!
//! # Sans-I/O
//!
//! Nothing in this module touches a socket or a clock. Time is a parameter, so the whole
//! four-second retransmission ladder of Core Table 21 is a test that runs in microseconds
//! and gives the same answer every time.
//!
//! ```
//! use matter_kit::exchange::{Mrp, MrpParams, OnTimeout};
//! use matter_kit::platform::Instant;
//!
//! let mut mrp = Mrp::new(MrpParams::default());
//! mrp.on_send(42, Instant::ZERO, 0)?;
//!
//! // Nothing came back, so the timer fires and the message goes again — with the same
//! // counter, because "logical retransmission is of a given message as identified by its
//! // message counter".
//! let deadline = mrp.poll_deadline().expect("a retransmission is scheduled");
//! assert!(matches!(
//!     mrp.on_timeout(deadline, 0),
//!     OnTimeout::Retransmit { counter: 42, .. }
//! ));
//! # Ok::<(), matter_kit::Error>(())
//! ```

mod mrp;
mod table;

pub use mrp::{
    MRP_BACKOFF_BASE, MRP_BACKOFF_JITTER, MRP_BACKOFF_MARGIN, MRP_BACKOFF_THRESHOLD,
    MRP_MAX_TRANSMISSIONS, MRP_STANDALONE_ACK_TIMEOUT, Mrp, MrpParams, OnTimeout,
    SESSION_ACTIVE_INTERVAL, SESSION_ACTIVE_THRESHOLD, SESSION_IDLE_INTERVAL, backoff, with_jitter,
};
pub use table::{EXCHANGE_IDLE_TIMEOUT, Exchange, ExchangeKey, ExchangeTable, Role};
