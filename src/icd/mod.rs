//! Intermittently Connected Devices (Core §4.22, §9.16–9.17).
//!
//! A door sensor on a coin cell cannot hold a radio open. It wakes, says what it has to say,
//! and sleeps again — and for most of its life it is unreachable, which is a problem for a
//! protocol built on sessions and subscriptions that assume a peer answers.
//!
//! Matter's answer has two halves, and both are here:
//!
//! * [`checkin`] is §4.22's **Check-In Protocol** — a sessionless, encrypted message a
//!   sleeping device sends to say it is awake, so a client that lost its session can rebuild
//!   one.
//! * The **ICD Management cluster** (§9.17) is how a client registers to receive those
//!   messages in the first place, and how it reads the device's idle and active timings.

pub mod checkin;
