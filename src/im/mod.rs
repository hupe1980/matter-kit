//! The interaction model: how anything actually says anything (Core ch. 8, ch. 10).
//!
//! Every exchange above a session goes through here. A client *reads* and *writes*
//! attributes, *invokes* commands, and *subscribes* to be told when things change; a server
//! answers. §8.1.2 is explicit that this layer is "agnostic to underlying layers (encoding,
//! message, network, transport, etc.)" — so this module is the encoding of chapter 10, and
//! the behaviour of chapter 8 sits on top of it.
//!
//! # What is here
//!
//! | | |
//! |---|---|
//! | [`status`] | §8.10's one-byte outcome codes |
//! | [`path`] | §10.6's four path blocks, and what a wildcard is |
//! | [`ib`] | the twelve information blocks that are not paths |
//! | [`message`] | §10.7's ten messages, and §10.2.1's opcodes |
//! | [`server`] | §8.4.3.2's read processing, over a [`dm::Node`](crate::dm::Node) |
//! | [`subscription`] | §8.5's subscriptions and §8.6's reporting engine |
//! | [`timed`] | §8.7.4's Timed transaction window |
//!
//! # Two shapes worth knowing before reading any of it
//!
//! **Cluster data is carried, never interpreted.** An attribute's value has a cluster's
//! type, not the interaction model's, so every payload field here is the encoded TLV element
//! borrowed from the buffer it arrived in. A bridge can forward a report without knowing the
//! cluster, and a server hands its cluster exactly the octets the client sent.
//!
//! **Arrays are iterated, not collected.** The peer chooses how many paths a request names.
//! Decoding into a fixed array would mean picking a number that is either too small for a
//! real client or too large for the smallest node this crate targets, so a decoded message
//! keeps the array's bytes and hands out an iterator. Memory is O(1) in what the peer sent,
//! which is also what lets a server stop and answer `PATHS_EXHAUSTED` rather than having
//! already committed to paths it cannot serve.
//!
//! # What is not here yet
//!
//! Chapter 8's behaviour is here as far as Read (§8.4.3.2), Write (§8.7.3.2), Invoke
//! (§8.8.2.3) and Subscribe (§8.5) with its reporting engine (§8.6) — including §8.2.1.6's
//! wildcard expansion, the access checks of §7.6 on every path, and §10.2.3's chunking of a
//! report that does not fit one message ([`server::ReadCursor`]).
//!
//! §10.6.4.3.1's list semantics run both ways: a report splits an oversized list, and a write
//! carries its [`WriteOp`] — replace or append — through to the cluster, which is the only
//! thing that distinguishes "here is the whole list" from "here is one more item".
//!
//! §10.2.3's chunking also runs both ways: [`server::Server::serve_chunk`] packs a report into
//! a series of messages, and [`client::ReportAssembler`] puts the series back together.
//!
//! §7.15's **atomic writes** are in [`atomic`]: the claim, its timeout, and the rule that an
//! attribute with the Atomic quality is writable only inside one. The pending *values* belong
//! to the cluster, which is the only thing that can check them against each other.
//!
//! What is not: the **Timed transaction window** itself, since
//! [`server::InteractionContext`] carries whether one is open but nothing here opens or times
//! one out; and **subscription persistence** across a reboot.

pub mod atomic;
pub mod client;
pub mod dispatch;
pub mod ib;
pub mod message;
pub mod path;
pub mod persist;
pub mod server;
pub mod status;
pub mod subscription;
pub mod timed;

pub use atomic::{AtomicWrites, Claim, RequestType, Writer};
pub use client::{ReportAssembler, Reports};
pub use dispatch::{Dispatcher, Request, Served};
pub use ib::{
    AttributeData, AttributeReport, AttributeStatus, CommandData, CommandStatus, DataVersion,
    DataVersionFilter, EventData, EventFilter, EventReport, EventStatus, EventTimestamp,
    InvokeResponse, StatusIb,
};
pub use message::{
    ArrayIter, INTERACTION_MODEL_REVISION, InvokeRequest, InvokeResponseMessage, REVISION_TAG,
    ReadRequest, ReportData, StatusResponse, SubscribeRequest, SubscribeResponse, TimedRequest,
    WriteRequest, WriteResponse, encode_invoke_request, encode_invoke_response,
    encode_read_request, encode_report_data, encode_subscribe_request, encode_write_request,
    encode_write_response, opcode,
};
pub use path::{
    AttributeId, AttributePath, ClusterId, ClusterPath, CommandId, CommandPath, EndpointId,
    EventId, EventPath, ListIndex, WildcardPathFlags,
};
pub use server::{
    AccessControl, AllowAll, ClusterHandler, InteractionContext, Lifecycle, Outcome, ReadCursor,
    ReadOutcome, Server, WriteAction, WriteOp,
};
pub use status::Status;
pub use subscription::{
    DirtySet, NewSubscription, ReportReason, SubscribeError, Subscription, SubscriptionPolicy,
    SubscriptionTable,
};
pub use timed::TimedWindows;
