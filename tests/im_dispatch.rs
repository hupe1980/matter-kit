//! `im::Dispatcher` — the opcode-to-action layer of Core §8.7 and §8.8.
//!
//! The processing each action gets is tested in `im_read_server.rs` and `im_write_invoke.rs`.
//! What is tested here is everything that happens *before* it: the rules a node must apply
//! between reading an opcode and doing any work, and the choice of response opcode, which is
//! the part a hand-written `match` gets wrong silently — a `WriteResponse` labelled
//! `REPORT_DATA` decodes as nothing a client can use, and no test of the write itself notices.
//!
//! The rule that earns the module is §8.8.2.3's fourth: "If this action contains more
//! CommandDataIB elements in the InvokeRequests list than are supported by the device" — its
//! `MaxPathsPerInvoke` — "then a Status Response action with the INVALID_ACTION Status Code
//! SHALL be submitted to the message layer and this interaction SHALL terminate."
//! `MaxPathsPerInvoke`
//! defaults to 1, so a node that does not enforce it advertises one command per invoke and then
//! executes as many as it is sent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::dm::{
    AttributeDescriptor, ClusterDescriptor, CommandDescriptor, Endpoint, Node, Privilege, Resolved,
    ResolvedCommand,
};
use matter_kit::im::{
    AccessControl, AttributePath, CommandData, CommandPath, Dispatcher, InteractionContext,
    Outcome, ReadCursor, Request, Served, Server, Status, StatusResponse, TimedRequest,
    encode_invoke_request, encode_read_request, encode_write_request, opcode,
};
use matter_kit::msg::{ExchangeId, SessionId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvWriter};

const EP: u16 = 1;
const CL: u32 = 0x0006;
const ATTR: u32 = 0x0000;
const CMD: u32 = 0x00;

const ATTRS: &[AttributeDescriptor] = &[AttributeDescriptor::read_write(ATTR)];
const CMDS: &[CommandDescriptor] = &[CommandDescriptor::new(CMD)];

const CLUSTERS: &[ClusterDescriptor<'static>] = &[ClusterDescriptor {
    id: CL,
    revision: 4,
    feature_map: 0,
    attributes: ATTRS,
    accepted_commands: CMDS,
    generated_commands: &[],
    events: &[],
}];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(EP, CLUSTERS)];

fn node() -> Node<'static> {
    Node::new(ENDPOINTS)
}

/// Counts what it was asked to do, so a test can assert that nothing ran.
#[derive(Default)]
struct Handler {
    invokes: RefCell<usize>,
    writes: RefCell<usize>,
}

impl matter_kit::im::ClusterHandler for Handler {
    fn read(
        &self,
        _resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.unsigned(tag, 1).map_err(|_| Status::Failure)
    }

    fn write(
        &self,
        _resolved: &Resolved<'_>,
        _data: &[u8],
        _op: matter_kit::im::WriteOp,
        _ctx: &InteractionContext,
    ) -> Result<(), Status> {
        *self.writes.borrow_mut() += 1;
        Ok(())
    }

    fn invoke(
        &self,
        _resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<u32>, matter_kit::im::StatusIb> {
        *self.invokes.borrow_mut() += 1;
        Ok(None)
    }
}

struct Allows;

impl AccessControl for Allows {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

const SESSION: SessionId = SessionId(7);
const EXCHANGE: ExchangeId = ExchangeId(3);

fn ctx_at(now: Instant) -> InteractionContext<'static> {
    InteractionContext::new().at(now)
}

fn at(secs: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(secs))
}

/// An encoded `uint8` under context tag 2, as an `AttributeDataIB` carries its value.
fn value(v: u8) -> heapless::Vec<u8, 8> {
    let mut buf = [0u8; 8];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.unsigned(Tag::Context(2), u64::from(v)).expect("value");
    heapless::Vec::from_slice(w.finish().expect("finish")).expect("fits")
}

/// Runs one message through a dispatcher, returning what it decided.
struct Harness {
    handler: Handler,
}

impl Harness {
    fn new() -> Self {
        Self {
            handler: Handler::default(),
        }
    }

    fn dispatch<const W: usize>(
        &self,
        dispatcher: &mut Dispatcher<W>,
        request: Request<'_>,
        now: Instant,
        buf: &mut [u8],
    ) -> (Option<u8>, usize, bool) {
        let mut scratch = [0u8; 2048];
        let mut cursor = ReadCursor::START;
        let server = Server::new(node(), &Allows, &self.handler, 64);
        match dispatcher
            .dispatch(
                &server,
                request,
                &ctx_at(now),
                &mut cursor,
                &mut scratch,
                buf,
            )
            .expect("dispatch")
        {
            Served::Reply {
                opcode,
                len,
                more_chunks,
            } => (Some(opcode), len, more_chunks),
            Served::Silent => (None, 0, false),
            Served::Subscribe(_) => (Some(opcode::SUBSCRIBE_REQUEST), 0, false),
            Served::Unhandled { opcode } => (Some(opcode), 0, false),
        }
    }
}

fn status_of(buf: &[u8], len: usize) -> Status {
    StatusResponse::decode(&buf[..len])
        .expect("a StatusResponse")
        .status
}

// --- Response opcodes --------------------------------------------------------------------------

#[test]
fn a_read_is_answered_with_report_data() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 512];
    let bytes = encode_read_request(
        &mut req,
        [AttributePath::attribute(EP, CL, ATTR)],
        [],
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, len, more) = h.dispatch(
        &mut d,
        Request::new(opcode::READ_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::REPORT_DATA));
    assert!(len > 0);
    assert!(!more, "one attribute fits in one message");
}

#[test]
fn an_invoke_is_answered_with_invoke_response() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 512];
    let bytes = encode_invoke_request(
        &mut req,
        [CommandData {
            path: CommandPath::command(EP, CL, CMD),
            fields: None,
            command_ref: None,
        }],
        false,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::INVOKE_RESPONSE));
    assert!(len > 0);
    assert_eq!(*h.handler.invokes.borrow(), 1);
}

#[test]
fn a_write_is_answered_with_write_response() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let v = value(1);
    let mut req = [0u8; 512];
    let bytes = encode_write_request(
        &mut req,
        [matter_kit::im::AttributeData {
            data_version: None,
            path: AttributePath::attribute(EP, CL, ATTR),
            data: &v,
        }],
        false,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::WRITE_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::WRITE_RESPONSE));
    assert!(len > 0);
    assert_eq!(*h.handler.writes.borrow(), 1);
}

// --- §8.8.2.3 rule 4: MaxPathsPerInvoke ---------------------------------------------------------

/// "If this action contains more CommandDataIB elements in the InvokeRequests list than are
/// supported by the device … a Status Response action with the INVALID_ACTION Status Code
/// SHALL be submitted … and this interaction SHALL terminate."
#[test]
fn more_commands_than_max_paths_per_invoke_is_invalid_action() {
    let h = Harness::new();
    // What Basic Information's `MaxPathsPerInvoke` defaults to.
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 512];
    let bytes = encode_invoke_request(
        &mut req,
        [
            CommandData {
                path: CommandPath::command(EP, CL, CMD),
                fields: None,
                command_ref: None,
            },
            CommandData {
                path: CommandPath::command(EP, CL, CMD),
                fields: None,
                command_ref: None,
            },
        ],
        false,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::STATUS_RESPONSE));
    assert_eq!(status_of(&buf, len), Status::InvalidAction);
    // "SHALL terminate" — and terminating after running the first command would be the worst
    // of both: a client told the batch failed, and a device that already acted on half of it.
    assert_eq!(
        *h.handler.invokes.borrow(),
        0,
        "the batch was refused before anything ran"
    );
}

#[test]
fn a_device_that_advertises_more_paths_accepts_them() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(3);
    let mut req = [0u8; 512];
    let bytes = encode_invoke_request(
        &mut req,
        [
            CommandData {
                path: CommandPath::command(EP, CL, CMD),
                fields: None,
                command_ref: None,
            },
            CommandData {
                path: CommandPath::command(EP, CL, CMD),
                fields: None,
                command_ref: None,
            },
        ],
        false,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, _, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::INVOKE_RESPONSE));
    assert_eq!(*h.handler.invokes.borrow(), 2);
}

// --- §8.7.4 Timed transactions ------------------------------------------------------------------

fn timed_request_bytes(buf: &mut [u8], timeout_ms: u16) -> &[u8] {
    TimedRequest::new(timeout_ms).encode(buf).expect("encode")
}

/// §8.7.4.3: "Upon receipt of this action, this layer SHALL construct and send a Status
/// Response action with SUCCESS to the initiator."
#[test]
fn a_timed_request_is_answered_success_and_opens_a_window() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 64];
    let bytes = timed_request_bytes(&mut req, 1000);
    let mut buf = [0u8; 512];
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::TIMED_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::STATUS_RESPONSE));
    assert_eq!(status_of(&buf, len), Status::Success);

    // The invoke that follows it, within the window, is served.
    let mut req2 = [0u8; 512];
    let invoke = encode_invoke_request(
        &mut req2,
        [CommandData {
            path: CommandPath::command(EP, CL, CMD),
            fields: None,
            command_ref: None,
        }],
        true,
        false,
    )
    .expect("encode");
    let (op, _, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, invoke, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::INVOKE_RESPONSE));
    assert_eq!(*h.handler.invokes.borrow(), 1);
}

/// §8.8.2.3 rule 3: `TimedRequest = true` with no window open.
#[test]
fn a_timed_invoke_with_no_window_is_a_mismatch() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 512];
    let bytes = encode_invoke_request(
        &mut req,
        [CommandData {
            path: CommandPath::command(EP, CL, CMD),
            fields: None,
            command_ref: None,
        }],
        true,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::STATUS_RESPONSE));
    assert_eq!(status_of(&buf, len), Status::TimedRequestMismatch);
    assert_eq!(*h.handler.invokes.borrow(), 0);
}

/// §8.8.2.3 rule 2: a window is open but the action says `TimedRequest = false`.
#[test]
fn an_untimed_invoke_inside_a_window_is_a_mismatch() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 64];
    let bytes = timed_request_bytes(&mut req, 1000);
    let mut buf = [0u8; 2048];
    let _ = h.dispatch(
        &mut d,
        Request::new(opcode::TIMED_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );

    let mut req2 = [0u8; 512];
    let invoke = encode_invoke_request(
        &mut req2,
        [CommandData {
            path: CommandPath::command(EP, CL, CMD),
            fields: None,
            command_ref: None,
        }],
        false,
        false,
    )
    .expect("encode");
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, invoke, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::STATUS_RESPONSE));
    assert_eq!(status_of(&buf, len), Status::TimedRequestMismatch);
    assert_eq!(*h.handler.invokes.borrow(), 0);
}

/// §8.8.2.3 rule 1: the window expired. Checked before rule 2, so a client that is both late
/// and wrong is told it was late.
#[test]
fn an_expired_window_is_a_timeout() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 64];
    let bytes = timed_request_bytes(&mut req, 1000);
    let mut buf = [0u8; 2048];
    let _ = h.dispatch(
        &mut d,
        Request::new(opcode::TIMED_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );

    let mut req2 = [0u8; 512];
    let invoke = encode_invoke_request(
        &mut req2,
        [CommandData {
            path: CommandPath::command(EP, CL, CMD),
            fields: None,
            command_ref: None,
        }],
        true,
        false,
    )
    .expect("encode");
    // One second of timeout, and two seconds later.
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, invoke, SESSION, EXCHANGE),
        at(2),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::STATUS_RESPONSE));
    assert_eq!(status_of(&buf, len), Status::Timeout);
    assert_eq!(*h.handler.invokes.borrow(), 0);
}

/// §8.7.4: the window is consumed by the first request on it, so a second Invoke does not get
/// to spend the same Timed Request.
#[test]
fn a_window_pays_for_exactly_one_action() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 64];
    let bytes = timed_request_bytes(&mut req, 1000);
    let mut buf = [0u8; 2048];
    let _ = h.dispatch(
        &mut d,
        Request::new(opcode::TIMED_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );

    let mut req2 = [0u8; 512];
    let invoke = encode_invoke_request(
        &mut req2,
        [CommandData {
            path: CommandPath::command(EP, CL, CMD),
            fields: None,
            command_ref: None,
        }],
        true,
        false,
    )
    .expect("encode");
    let (first, _, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, invoke, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(first, Some(opcode::INVOKE_RESPONSE));

    let (second, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, invoke, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(second, Some(opcode::STATUS_RESPONSE));
    assert_eq!(status_of(&buf, len), Status::TimedRequestMismatch);
    assert_eq!(*h.handler.invokes.borrow(), 1);
}

/// §8.7.4's window is keyed by session *and* exchange: one client's Timed Request must not be
/// spendable by another client that happens to hold the same exchange id.
#[test]
fn a_window_does_not_cross_sessions() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 64];
    let bytes = timed_request_bytes(&mut req, 1000);
    let mut buf = [0u8; 2048];
    let _ = h.dispatch(
        &mut d,
        Request::new(opcode::TIMED_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );

    let mut req2 = [0u8; 512];
    let invoke = encode_invoke_request(
        &mut req2,
        [CommandData {
            path: CommandPath::command(EP, CL, CMD),
            fields: None,
            command_ref: None,
        }],
        true,
        false,
    )
    .expect("encode");
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::INVOKE_REQUEST, invoke, SessionId(99), EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::STATUS_RESPONSE));
    assert_eq!(status_of(&buf, len), Status::TimedRequestMismatch);
    assert_eq!(*h.handler.invokes.borrow(), 0);
}

// --- §8.7.2.3's two silences --------------------------------------------------------------------

/// "If this action was unicast and SuppressResponse is FALSE, a Write Response action SHALL be
/// generated … otherwise no Write Response SHALL be sent."
#[test]
fn a_suppressed_write_is_answered_with_silence() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let v = value(1);
    let mut req = [0u8; 512];
    let bytes = encode_write_request(
        &mut req,
        [matter_kit::im::AttributeData {
            data_version: None,
            path: AttributePath::attribute(EP, CL, ATTR),
            data: &v,
        }],
        false,
        true,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, _, _) = h.dispatch(
        &mut d,
        Request::new(opcode::WRITE_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, None, "no response");
    assert_eq!(
        *h.handler.writes.borrow(),
        1,
        "but the write still happened"
    );
}

#[test]
fn a_groupcast_write_is_answered_with_silence() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let v = value(1);
    let mut req = [0u8; 512];
    let bytes = encode_write_request(
        &mut req,
        [matter_kit::im::AttributeData {
            data_version: None,
            path: AttributePath::attribute(EP, CL, ATTR),
            data: &v,
        }],
        false,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, _, _) = h.dispatch(
        &mut d,
        Request::new(opcode::WRITE_REQUEST, bytes, SESSION, EXCHANGE).groupcast(),
        at(0),
        &mut buf,
    );
    assert_eq!(op, None, "a groupcast is never answered");
    assert_eq!(*h.handler.writes.borrow(), 1);
}

// --- Everything else ----------------------------------------------------------------------------

#[test]
fn a_subscribe_is_handed_back_decoded() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 512];
    let bytes = matter_kit::im::encode_subscribe_request(
        &mut req,
        [AttributePath::attribute(EP, CL, ATTR)],
        [],
        1,
        60,
        true,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, _, _) = h.dispatch(
        &mut d,
        Request::new(opcode::SUBSCRIBE_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::SUBSCRIBE_REQUEST), "handed to the caller");
}

/// A response opcode on an exchange this node initiated is not a client error, so the
/// dispatcher reports it rather than inventing `INVALID_ACTION` for it.
#[test]
fn an_unserved_opcode_is_reported_not_refused() {
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut buf = [0u8; 512];
    let (op, _, _) = h.dispatch(
        &mut d,
        Request::new(opcode::REPORT_DATA, &[], SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::REPORT_DATA));
}

// --- §8.4.3 step 7: what makes a Subscribe malformed -----------------------------------------

/// An access control that grants nothing, so every path fails step 2's access check.
struct Denies;

impl AccessControl for Denies {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Denied
    }
}

#[test]
fn a_subscribe_whose_paths_the_subject_cannot_read_is_invalid_action() {
    // §8.4.3 step 7.a: "If both AttributeRequests and EventRequests are empty" the action is
    // `INVALID_ACTION` — and step 2 defines empty as "no error-free existent paths remain", so
    // a path the subscriber may not read counts as *absent*, not as a subscription that reports
    // nothing.
    //
    // The difference is visible only to the subscriber, which is why it matters: a
    // `SubscribeResponse` is a promise to report, and a subscription over paths that will never
    // be readable is a promise that cannot be kept and looks exactly like a quiet device.
    // `TC_IDM_4_2` step 4 builds a controller without access and expects the refusal.
    let handler = Handler::default();
    let server = Server::new(node(), &Denies, &handler, 64);
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 512];
    let bytes = matter_kit::im::encode_subscribe_request(
        &mut req,
        [AttributePath::attribute(EP, CL, ATTR)],
        [],
        1,
        60,
        true,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let mut scratch = [0u8; 2048];
    let mut cursor = ReadCursor::START;
    match d
        .dispatch(
            &server,
            Request::new(opcode::SUBSCRIBE_REQUEST, bytes, SESSION, EXCHANGE),
            &ctx_at(at(0)),
            &mut cursor,
            &mut scratch,
            &mut buf,
        )
        .expect("dispatch")
    {
        Served::Reply {
            opcode: op, len, ..
        } => {
            assert_eq!(op, opcode::STATUS_RESPONSE);
            assert_eq!(
                status_of(&buf, len),
                Status::InvalidAction,
                "a subscription nobody may read was accepted"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_subscribe_with_a_floor_above_its_ceiling_is_invalid_action() {
    // §8.4.3 step 7.b. Clamping instead would grant an interval the subscriber never asked for
    // and has no way to detect.
    let h = Harness::new();
    let mut d: Dispatcher<4> = Dispatcher::new(1);
    let mut req = [0u8; 512];
    let bytes = matter_kit::im::encode_subscribe_request(
        &mut req,
        [AttributePath::attribute(EP, CL, ATTR)],
        [],
        120,
        60,
        true,
        false,
    )
    .expect("encode");
    let mut buf = [0u8; 2048];
    let (op, len, _) = h.dispatch(
        &mut d,
        Request::new(opcode::SUBSCRIBE_REQUEST, bytes, SESSION, EXCHANGE),
        at(0),
        &mut buf,
    );
    assert_eq!(op, Some(opcode::STATUS_RESPONSE));
    assert_eq!(status_of(&buf, len), Status::InvalidAction);
}
