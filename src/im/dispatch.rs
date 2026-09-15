//! One entry point for an arriving interaction-model message (Core §8.7, §8.8).
//!
//! [`Server`] exposes the *processing* of each action — [`Server::serve_chunk`],
//! [`Server::serve_write`], [`Server::serve_invoke`] — and deliberately takes already-decoded
//! paths, because that is what makes each of them testable against the specification's own
//! path tables. What it does not do is decide *which* of them an opcode means, and that
//! decision is not the triviality it looks like: between the opcode and the processing sit the
//! rules of §8.7.2.3 and §8.8.2.3, which a node must apply before it does any work and which
//! are invisible in the shape of the request.
//!
//! [`Dispatcher`] is that layer. It owns the one piece of state the rules need — §8.7.4's
//! [`TimedWindows`] — and turns "a message arrived on this exchange" into "send this opcode
//! back", or into [`Served::Subscribe`] for the one action whose state lives elsewhere.
//!
//! # What it refuses before the node does any work
//!
//! | Rule | Section | Answer |
//! |---|---|---|
//! | a Timed transaction whose window expired | §8.7.2.3, §8.8.2.3 rule 1 | `TIMEOUT` |
//! | a Timed transaction whose request says `TimedRequest = false` | §8.7.2.3, §8.8.2.3 rule 2 | `TIMED_REQUEST_MISMATCH` |
//! | `TimedRequest = true` with no window open | §8.7.2.3, §8.8.2.3 rule 3 | `TIMED_REQUEST_MISMATCH` |
//! | more commands than `MaxPathsPerInvoke` | §8.8.2.3 rule 4 | `INVALID_ACTION` |
//! | a `TimedRequest` with no room to record it | §8.7.3.2 | `BUSY` |
//!
//! The fourth is the one a hand-written dispatch reliably forgets. `MaxPathsPerInvoke` is a
//! Basic Information attribute (§11.1.5.23) whose default is 1, so a device that does not
//! enforce it advertises "one command per invoke" and then executes however many a client
//! sends — which is both a specification violation and the only bound the server has on the
//! work one message can ask of it.
//!
//! # Why a length rather than a slice
//!
//! Every other encoder here returns `&'b [u8]`. This one returns how many octets it wrote,
//! because [`Server::serve_write`] ties the lifetime of the decoded `AttributeData` to the
//! lifetime of the output buffer, and a dispatcher that returned a borrow of the buffer would
//! propagate that unification into its own signature and tie the *request* to it too. The
//! caller writes `&buf[..len]`, which is what it was going to do with the slice anyway.

use super::message::{
    InvokeRequest, ReadRequest, StatusResponse, SubscribeRequest, TimedRequest, WriteRequest,
    opcode,
};
use super::server::{AccessControl, ClusterHandler, InteractionContext, ReadCursor, Server};
use super::status::Status;
use super::timed::TimedWindows;
use crate::error::Result;
use crate::msg::{ExchangeId, SessionId};

/// One arriving interaction-model message, with the exchange facts §8.7.4 keys its window on.
///
/// Constructible as a literal: an unsecured session is `session: None`, which
/// [`Request::new`] cannot express.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The protocol opcode (§10.2.1).
    pub opcode: u8,
    /// The message body, everything after the protocol header.
    pub payload: &'a [u8],
    /// Which secure session it arrived on, `None` for an unsecured one.
    ///
    /// §8.7.4's window is keyed by session *and* exchange, so that one client's Timed Request
    /// cannot be spent by another's Write on a coincidentally equal exchange id.
    pub session: Option<SessionId>,
    /// The exchange it arrived on.
    pub exchange: ExchangeId,
    /// Whether it arrived as a groupcast.
    ///
    /// §8.7.2.3: "If this action was unicast and SuppressResponse is FALSE, a Write Response
    /// action SHALL be generated … otherwise no Write Response SHALL be sent." A groupcast
    /// write is answered by silence whatever the flag says.
    pub groupcast: bool,
}

impl<'a> Request<'a> {
    /// A unicast request on a secure session.
    #[must_use]
    pub const fn new(
        opcode: u8,
        payload: &'a [u8],
        session: SessionId,
        exchange: ExchangeId,
    ) -> Self {
        Self {
            opcode,
            payload,
            session: Some(session),
            exchange,
            groupcast: false,
        }
    }

    /// The same request, marked as having arrived on a group session.
    #[must_use]
    pub const fn groupcast(mut self) -> Self {
        self.groupcast = true;
        self
    }
}

/// What the caller should do with the result of a dispatch.
///
/// Deliberately **not** `#[non_exhaustive]`. Every variant demands a different action from the
/// caller, so a wildcard arm is a silent bug rather than forward compatibility: a node that
/// matched `_ => {}` would answer a new action with silence. Adding a variant here is a
/// breaking change, and should be.
#[derive(Debug)]
pub enum Served<'a> {
    /// Send `buf[..len]` back on the same exchange, with this opcode.
    Reply {
        /// The response opcode (§10.2.1).
        opcode: u8,
        /// How many octets of the output buffer the message occupies.
        len: usize,
        /// Whether the message set `MoreChunkedMessages` (§10.2.3).
        ///
        /// When set, the read is not finished: §10.2.3 requires the client's `StatusResponse`
        /// before the next message, so the caller sends this one, waits for it, and dispatches
        /// again with the same [`ReadCursor`].
        more_chunks: bool,
    },
    /// A `SubscribeRequest`, decoded and handed on.
    ///
    /// Subscriptions are the one action whose state is not the dispatcher's: it lives in
    /// [`SubscriptionTable`](super::subscription::SubscriptionTable), outlives the exchange,
    /// and is driven by a reporting engine rather than by a reply. So this is where the
    /// dispatcher stops.
    Subscribe(SubscribeRequest<'a>),
    /// Nothing to send: the action was suppressed or groupcast (§8.7.2.3).
    Silent,
    /// Not an action this layer serves — a response opcode, or one from a newer revision.
    ///
    /// The one that matters in practice is `StatusResponse`: §10.2.3 makes it the client's
    /// acknowledgement of a chunk, so a caller holding a [`ReadCursor`] that is not
    /// [`ReadCursor::is_done`] answers it by dispatching the *same* read again rather than by
    /// treating it as a new action.
    ///
    /// §8.2.5.1 makes an unexpected action `INVALID_ACTION`, but a *response* opcode on an
    /// exchange this node initiated is not unexpected at all, and the dispatcher cannot tell
    /// the two apart without knowing which role it holds. So it says what it saw and lets the
    /// caller, which does know, decide.
    Unhandled {
        /// The opcode that was not served.
        opcode: u8,
    },
}

/// The opcode-to-action layer of §8.7 and §8.8, and the state its rules need.
///
/// `W` is how many Timed transactions may be open at once — §8.7.4's windows, one per
/// (session, exchange).
#[derive(Debug)]
pub struct Dispatcher<const W: usize> {
    timed: TimedWindows<W>,
    max_paths_per_invoke: u16,
}

impl<const W: usize> Dispatcher<W> {
    /// A dispatcher that enforces `max_paths_per_invoke` on incoming invokes.
    ///
    /// The value must be the one the node's Basic Information cluster advertises
    /// (§11.1.5.23), or the node promises one thing and enforces another.
    ///
    /// Zero is raised to one. §11.1.5.23 constrains the attribute to `min 1`, so zero is not a
    /// value a node may advertise — but it is what an uninitialised field holds, and a
    /// dispatcher that took it at its word would answer every invoke `INVALID_ACTION` and look
    /// like a data-model fault rather than a typo.
    #[must_use]
    pub const fn new(max_paths_per_invoke: u16) -> Self {
        Self {
            timed: TimedWindows::new(),
            max_paths_per_invoke: if max_paths_per_invoke == 0 {
                1
            } else {
                max_paths_per_invoke
            },
        }
    }

    /// The Timed windows, for the reaping and session-teardown a node owes them.
    pub const fn timed(&mut self) -> &mut TimedWindows<W> {
        &mut self.timed
    }

    /// Serves one message, returning what to send back.
    ///
    /// `ctx` supplies the facts about the session that the action does not carry — the
    /// accessing fabric, the clock, whether the transport is large-message capable. Its
    /// [`timed`](InteractionContext::timed) field is **overwritten** from §8.7.4's window
    /// rather than read: whether an action is part of a Timed transaction is a property of the
    /// exchange's history, which only this layer knows, and a caller that set it by hand would
    /// be guessing.
    ///
    /// `cursor` carries a chunked read between messages and is [`ReadCursor::START`] for a new
    /// one. One cursor belongs to one exchange.
    ///
    /// # Errors
    ///
    /// A malformed message is an [`Error`](crate::Error) — the decoders' own verdict. §8.2.5.1
    /// makes that `INVALID_ACTION` on the wire, which the caller sends; the dispatcher does not
    /// invent a status for bytes it could not parse.
    pub fn dispatch<'a, A: AccessControl, H: ClusterHandler>(
        &mut self,
        server: &Server<'_, A, H>,
        request: Request<'a>,
        ctx: &InteractionContext<'_>,
        cursor: &mut ReadCursor,
        scratch: &mut [u8],
        buf: &mut [u8],
    ) -> Result<Served<'a>> {
        match request.opcode {
            opcode::READ_REQUEST => self.read(server, request, ctx, cursor, scratch, buf),
            opcode::WRITE_REQUEST => self.write(server, request, ctx, buf),
            opcode::INVOKE_REQUEST => self.invoke(server, request, ctx, scratch, buf),
            opcode::TIMED_REQUEST => self.timed_request(request, ctx, buf),
            opcode::SUBSCRIBE_REQUEST => {
                let subscribe = SubscribeRequest::decode(request.payload)?;
                // §8.9.2.6's table is "valid for AttributePathIB for a Read Request action **or
                // a Subscribe Request action**". Enforced here rather than left to the device:
                // a subscription that accepted a path a read refuses would answer the same
                // question by a different door, and forever rather than once.
                if let Some(paths) = subscribe.attribute_paths()? {
                    for path in paths {
                        if !path?.is_valid_for_read() {
                            return status_reply(Status::InvalidAction, buf);
                        }
                    }
                }
                // §8.4.3 step 7.b: "if either MinIntervalFloor or MaxIntervalCeiling is
                // missing, or MinIntervalFloor is greater than MaxIntervalCeiling" the action
                // is `INVALID_ACTION`. Clamping instead would grant an interval the subscriber
                // never asked for and cannot detect.
                if subscribe.min_interval_floor_s > subscribe.max_interval_ceiling_s {
                    return status_reply(Status::InvalidAction, buf);
                }
                // §8.4.3 step 7.a: "If both AttributeRequests and EventRequests are empty" the
                // action is `INVALID_ACTION` — and step 2 defines empty as "no error-free
                // existent paths remain", so a path the subscriber may not read counts as
                // absent, not as a subscription that reports nothing.
                //
                // The difference matters to the subscriber and only to the subscriber: a
                // `SubscribeResponse` is a promise to report, and a subscription over paths it
                // will never be allowed to see is a promise that cannot be kept and cannot be
                // distinguished from a quiet device.
                let has_events = subscribe
                    .event_paths()?
                    .is_some_and(|mut paths| paths.next().is_some());
                let has_attributes = match subscribe.attribute_paths()? {
                    Some(paths) => server.any_readable(paths)?,
                    None => false,
                };
                if !has_attributes && !has_events {
                    return status_reply(Status::InvalidAction, buf);
                }
                Ok(Served::Subscribe(subscribe))
            }
            other => Ok(Served::Unhandled { opcode: other }),
        }
    }

    /// §8.4's Read, chunked per §10.2.3.
    fn read<'a, A: AccessControl, H: ClusterHandler>(
        &mut self,
        server: &Server<'_, A, H>,
        request: Request<'a>,
        ctx: &InteractionContext<'_>,
        cursor: &mut ReadCursor,
        scratch: &mut [u8],
        buf: &mut [u8],
    ) -> Result<Served<'a>> {
        let read = ReadRequest::decode(request.payload)?;
        let mut ctx = *ctx;
        ctx.timed = false;
        ctx.fabric_filtered = read.fabric_filtered;
        // §8.4.3.2 step 3.a. §10.7.2.4 permits ignoring them when `AttributeRequests` is empty
        // — which is exactly when they cost nothing to carry, so they are simply passed on.
        ctx.data_version_filters = read.data_version_filters_raw();
        ctx.event_filters = read.event_filters_raw();
        // §8.9.2.6's table of valid wildcard combinations. Checked before anything is served,
        // because a path it does not admit makes the whole *action* malformed — not one path
        // in it — so the answer is a single `INVALID_ACTION`, not a report with a status in it.
        if let Some(paths) = read.attribute_paths()? {
            for path in paths {
                if !path?.is_valid_for_read() {
                    return status_reply(Status::InvalidAction, buf);
                }
            }
        }
        let paths = read.attribute_paths()?;
        // §8.4.3.3's other half. A read may ask for events, attributes or both, and a server
        // that answered only the attribute half would report an empty log rather than say it
        // is not serving one.
        let events = read.event_paths()?;
        let (bytes, outcome) = server.serve_chunk_with_events(
            paths.into_iter().flatten(),
            events.into_iter().flatten(),
            &ctx,
            None,
            cursor,
            scratch,
            buf,
        )?;
        Ok(Served::Reply {
            opcode: opcode::REPORT_DATA,
            len: bytes.len(),
            more_chunks: outcome.truncated,
        })
    }

    /// §8.7.2.3's Write, with its three Timed rules and its two silences.
    fn write<'a, A: AccessControl, H: ClusterHandler>(
        &mut self,
        server: &Server<'_, A, H>,
        request: Request<'a>,
        ctx: &InteractionContext<'_>,
        buf: &mut [u8],
    ) -> Result<Served<'a>> {
        let write = WriteRequest::decode(request.payload)?;
        let timed = match self.timed.check(
            request.session,
            request.exchange,
            write.timed_request,
            ctx.now,
        ) {
            Ok(timed) => timed,
            Err(status) => return status_reply(status, buf),
        };
        let mut ctx = *ctx;
        ctx.timed = timed;
        let writes = write.writes()?;
        let (bytes, _) = server.serve_write(writes, &ctx, write.more_chunked_messages, buf)?;
        let len = bytes.len();
        // "If this action was unicast and SuppressResponse is FALSE, a Write Response action
        // SHALL be generated … otherwise no Write Response SHALL be sent."
        if request.groupcast || write.suppress_response {
            return Ok(Served::Silent);
        }
        Ok(Served::Reply {
            opcode: opcode::WRITE_RESPONSE,
            len,
            more_chunks: false,
        })
    }

    /// §8.8.2.3's Invoke: rules 1–3 are the Timed window, rule 4 is `MaxPathsPerInvoke`.
    fn invoke<'a, A: AccessControl, H: ClusterHandler>(
        &mut self,
        server: &Server<'_, A, H>,
        request: Request<'a>,
        ctx: &InteractionContext<'_>,
        scratch: &mut [u8],
        buf: &mut [u8],
    ) -> Result<Served<'a>> {
        let invoke = InvokeRequest::decode(request.payload)?;
        let timed = match self.timed.check(
            request.session,
            request.exchange,
            invoke.timed_request,
            ctx.now,
        ) {
            Ok(timed) => timed,
            Err(status) => return status_reply(status, buf),
        };

        // Rule 4: "If this action contains more CommandDataIB elements in the InvokeRequests
        // list than are supported by the device … then a Status Response action with the
        // INVALID_ACTION Status Code SHALL be submitted to the message layer and this
        // interaction SHALL terminate."
        //
        // Counted before anything is executed, because the point is to execute none of them.
        // A malformed element inside the list is *not* judged here — that is rule 5's
        // per-path processing, which answers with a status for that path rather than
        // terminating the interaction — so the count stops at the first decode error and
        // lets `serve_invoke` report it.
        let mut commands = 0usize;
        for command in invoke.commands()? {
            if command.is_err() {
                break;
            }
            commands = commands.saturating_add(1);
            if commands > usize::from(self.max_paths_per_invoke) {
                return status_reply(Status::InvalidAction, buf);
            }
        }

        let mut ctx = *ctx;
        ctx.timed = timed;
        let (bytes, _) = server.serve_invoke(
            invoke.commands()?,
            &ctx,
            invoke.suppress_response,
            scratch,
            buf,
        )?;
        Ok(Served::Reply {
            opcode: opcode::INVOKE_RESPONSE,
            len: bytes.len(),
            more_chunks: false,
        })
    }

    /// §8.7.4.3: answer `SUCCESS`, then expect a Write or Invoke within `Timeout`.
    fn timed_request<'a>(
        &mut self,
        request: Request<'a>,
        ctx: &InteractionContext<'_>,
        buf: &mut [u8],
    ) -> Result<Served<'a>> {
        let timed = TimedRequest::decode(request.payload)?;
        // §8.7.4: "the Timeout interval SHALL start when the Status Response action
        // acknowledging the Timed Request action with a success code is sent". The dispatcher
        // does not send — it writes the bytes the caller sends — so the window opens from
        // `ctx.now`, which is the moment the action started and is earlier than the send by
        // however long it takes to hand a buffer to a socket. Earlier is the safe direction:
        // it can only shorten the client's window, never extend it past the timeout.
        if self
            .timed
            .open(request.session, request.exchange, timed.timeout_ms, ctx.now)
            .is_err()
        {
            // §8.7.3.2's exhaustion case: every slot holds a live window.
            return status_reply(Status::Busy, buf);
        }
        status_reply(Status::Success, buf)
    }
}

/// Encodes a `StatusResponse` carrying `status`.
fn status_reply<'a>(status: Status, buf: &mut [u8]) -> Result<Served<'a>> {
    let bytes = StatusResponse::new(status).encode(buf)?;
    Ok(Served::Reply {
        opcode: opcode::STATUS_RESPONSE,
        len: bytes.len(),
        more_chunks: false,
    })
}
