//! The Matter message frame: headers, identifiers, and the counters that keep a message
//! from being replayed.
//!
//! This is Core §4.4–4.9 — everything between "some bytes arrived on a socket" and "this
//! is a protocol message for exchange 7". What is here is the framing and the anti-replay
//! machinery; encryption arrives with the secure channel, and the layout below is already
//! shaped for it (the header is outside the ciphertext because a receiver must find the
//! key before it can decrypt).
//!
//! ```text
//! ┌── message header ─────────────────────────┐┌── payload (encrypted) ──┐┌ footer ┐
//! │ flags │ session │ sec │ counter │ src │ dst││ protocol header │ app   ││  MIC   │
//! └───────────────────────────────────────────┘└─────────────────────────┘└────────┘
//! ```
//!
//! ```
//! use matter_kit::msg::{Destination, MessageHeader, NodeId, SessionId};
//!
//! let header = MessageHeader {
//!     session_id: SessionId(0x1234),
//!     message_counter: 42,
//!     source: Some(NodeId(1)),
//!     destination: Destination::Node(NodeId(2)),
//!     ..MessageHeader::default()
//! };
//!
//! let mut buf = [0u8; 64];
//! let n = header.encode(&mut buf)?;
//! let (decoded, payload) = MessageHeader::decode(&buf[..n])?;
//! assert_eq!(decoded, header);
//! assert!(payload.is_empty());
//! # Ok::<(), matter_kit::Error>(())
//! ```

mod counter;
mod header;
mod ids;
#[cfg(feature = "rustcrypto")]
mod security;

pub use counter::{
    CounterKind, CounterWindow, MSG_COUNTER_WINDOW_SIZE, MessageCounter, Verdict, initial_counter,
};
pub use header::{
    Destination, ExchangeFlags, MESSAGE_FORMAT_VERSION, MessageFlags, MessageHeader,
    ProtocolHeader, SecurityFlags, SessionType,
};
pub use ids::{
    CaseAuthenticatedTag, ExchangeId, FabricId, FabricIndex, GroupId, NodeId, NodeIdKind,
    ProtocolId, SessionId, VendorId,
};
#[cfg(feature = "rustcrypto")]
pub use security::{NonceSource, Preview, SessionKeys, preview, protect, unprotect};
