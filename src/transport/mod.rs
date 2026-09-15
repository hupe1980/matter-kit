//! The transports underneath the message layer.
//!
//! Matter's message format (§4.4) is carried over three things: IPv6 UDP, TCP, and BLE. The
//! first two are datagram-shaped and need nothing between them and [`crate::messaging`] —
//! a UDP payload *is* a Matter message, and the platform's socket delivers it whole.
//!
//! BLE is not. A GATT PDU carries at most `ATT_MTU - 3` octets — twenty, on the minimum MTU —
//! and has no flow control at the transport layer. [`btp`] is the protocol that bridges the
//! gap, and [`ble`] is its surface against the radio: the GATT service it lives in and the
//! advertisement a commissioner scans for.
//!
//! Both are sans-I/O, like the rest of the crate: they take bytes and a clock reading and
//! hand back bytes and deadlines. What actually drives the radio belongs to the platform.

pub mod ble;
pub mod btp;
#[cfg(feature = "nfc")]
#[cfg_attr(docsrs, doc(cfg(feature = "nfc")))]
pub mod ntl;
#[cfg(feature = "paf")]
#[cfg_attr(docsrs, doc(cfg(feature = "paf")))]
pub mod paftp;
pub mod tcp;

bitflags::bitflags! {
    /// Table 7's "Supported Transport Mode Values" — which transports a node supports
    /// **in addition to MRP** (§4.3.4, §4.13.1).
    ///
    /// The same bitmap appears in two places, which is why it lives here rather than in
    /// either of them: as the `T` key of a DNS-SD operational record
    /// ([`crate::discovery::txt`]), and as `SUPPORTED_TRANSPORTS` in the
    /// `session-parameter-struct` both handshakes exchange ([`crate::sc::SessionParams`]).
    ///
    /// They are not equally trustworthy, and §4.3.4 says so outright: "Because the
    /// information carried in DNS-SD records with Matter is not trustworthy (since the source
    /// is not authenticated), the value of the T key SHOULD be regarded only as a hint. The
    /// only reliable way to determine which transports are supported by a Node is to connect
    /// to it using CASE over MRP and get the list of supported transports from the session
    /// parameters." So the advertisement opens a connection and the session parameters decide
    /// what may be sent over it.
    ///
    /// Bit 0 is reserved: "This bit index is deprecated and SHALL be set to 0. Clients SHALL
    /// silently ignore this bit" — which is why it is absent here rather than defined and
    /// unused, and why [`TransportModes::from_bits_truncate`] is the right constructor for a
    /// value off the wire.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct TransportModes: u32 {
        /// Bit 1 — "The advertising Node implements the TCP Client mode and MAY connect to a
        /// peer Node that is a TCP Server".
        const TCP_CLIENT = 1 << 1;
        /// Bit 2 — "The advertising Node implements the TCP Server mode and SHALL listen for
        /// incoming TCP connections".
        const TCP_SERVER = 1 << 2;
    }
}
