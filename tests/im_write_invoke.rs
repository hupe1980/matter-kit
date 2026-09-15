//! Serving Writes and Invokes, against Core §8.7.3.2 and §8.8.2.3.
//!
//! Both mirror the Read processing step for step — the same concrete-versus-expanded
//! asymmetry, the same two-stage access check — with the additions each interaction needs.
//! What is tested here is those additions, and the three places the mirror is *not* exact:
//!
//! * **A write reports success explicitly.** §8.7.3.3 step 2.b.ii generates a `SUCCESS`
//!   status for every path written, where a read reports success by returning data. A write
//!   response is therefore never empty unless everything was discarded.
//! * **An invoke's first access check is at Operate, not View.** §8.8.2.3 step b.i says so
//!   outright, and the reason is that there is no such thing as a read-only command: View is
//!   enough to look at a node and never enough to make it do something.
//! * **A response command's path is rebuilt.** §8.8.2.3's Invoke Execution says the response
//!   keeps the request's endpoint and cluster and takes the *response* command's id — so a
//!   server that echoed the request path would send a response a client cannot match.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use core::cell::RefCell;

use matter_kit::dm::{
    Access, AccessQualities, AttributeDescriptor, ClusterDescriptor, CommandDescriptor,
    DataVersions, Endpoint, Node, Privilege, Resolved, ResolvedCommand, global,
};
use matter_kit::im::TimedWindows;
use matter_kit::im::{
    AccessControl, AttributeData, AttributePath, CommandData, CommandPath, InteractionContext,
    InvokeResponse, InvokeResponseMessage, Outcome, Server, Status, WriteResponse,
};
use matter_kit::msg::{ExchangeId, FabricIndex, SessionId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvWriter};

const CL: u32 = 0x0006;
const PLAIN: u32 = 0x0000;
const TIMED_ONLY: u32 = 0x0001;
const FABRIC_SCOPED: u32 = 0x0002;
const READ_ONLY: u32 = 0x0003;
const ADMIN_WRITE: u32 = 0x0004;

const CMD_PLAIN: u32 = 0x00;
const CMD_WITH_RESPONSE: u32 = 0x01;
const CMD_RESPONSE_ID: u32 = 0x41;
const CMD_TIMED: u32 = 0x02;
const CMD_FABRIC: u32 = 0x03;
const CMD_LARGE: u32 = 0x04;
const CMD_ADMIN: u32 = 0x05;

const ATTRS: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_write(PLAIN),
    AttributeDescriptor::read_write(TIMED_ONLY)
        .with_access(Access::read_write().with_qualities(AccessQualities::TIMED)),
    AttributeDescriptor::read_write(FABRIC_SCOPED)
        .with_access(Access::read_write().with_qualities(AccessQualities::FABRIC_SCOPED)),
    AttributeDescriptor::read_only(READ_ONLY),
    AttributeDescriptor::read_write(ADMIN_WRITE).with_access(Access::read_write_with(
        Privilege::View,
        Privilege::Administer,
    )),
];

const CMDS: &[CommandDescriptor] = &[
    CommandDescriptor::new(CMD_PLAIN),
    CommandDescriptor::new(CMD_WITH_RESPONSE).with_response(CMD_RESPONSE_ID),
    CommandDescriptor::new(CMD_TIMED)
        .with_access(Access::invoke(Privilege::Operate).with_qualities(AccessQualities::TIMED)),
    CommandDescriptor::new(CMD_FABRIC).with_access(
        Access::invoke(Privilege::Operate).with_qualities(AccessQualities::FABRIC_SCOPED),
    ),
    CommandDescriptor::new(CMD_LARGE)
        .with_access(Access::invoke(Privilege::Operate).with_qualities(AccessQualities::LARGE)),
    CommandDescriptor::new(CMD_ADMIN).with_access(Access::invoke(Privilege::Administer)),
];

const CLUSTERS: &[ClusterDescriptor<'static>] = &[ClusterDescriptor {
    id: CL,
    revision: 4,
    feature_map: 0,
    attributes: ATTRS,
    accepted_commands: CMDS,
    generated_commands: &[],
    events: &[],
}];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(1, CLUSTERS)];

fn node() -> Node<'static> {
    Node::new(ENDPOINTS)
}

/// Records what was written and what was invoked.
#[derive(Default)]
struct Handler {
    writes: RefCell<heapless::Vec<(u32, u8), 16>>,
    invokes: RefCell<heapless::Vec<u32, 16>>,
    /// The data version this handler reports; `None` disables the staleness check.
    version: Option<u32>,
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

    fn data_version(&self, _resolved: &Resolved<'_>) -> Option<u32> {
        self.version
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        _op: matter_kit::im::WriteOp,
        _ctx: &InteractionContext,
    ) -> Result<(), Status> {
        // The value arrives as the encoded element; the last octet of `24 02 NN` is it.
        let value = data.last().copied().unwrap_or(0);
        if value == 0xFF {
            return Err(Status::ConstraintError);
        }
        let _ = self.writes.borrow_mut().push((resolved.attribute, value));
        Ok(())
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<u32>, matter_kit::im::StatusIb> {
        let _ = self.invokes.borrow_mut().push(resolved.command.id);
        match resolved.command.response {
            Some(id) => {
                w.unsigned(tag, 99).map_err(|_| Status::Failure)?;
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }
}

struct Holds(Privilege);

impl AccessControl for Holds {
    fn allows(&self, _path: &AttributePath, required: Privilege) -> Outcome {
        if self.0.grants(required) {
            Outcome::Granted
        } else {
            Outcome::Denied
        }
    }
}

struct DeniesCluster(u32);

impl AccessControl for DeniesCluster {
    fn allows(&self, path: &AttributePath, _required: Privilege) -> Outcome {
        if path.cluster == Some(self.0) {
            Outcome::Denied
        } else {
            Outcome::Granted
        }
    }
}

/// An encoded `uint8` value under context tag 2, as an attribute write carries it.
fn value(v: u8) -> heapless::Vec<u8, 8> {
    let mut buf = [0u8; 8];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.unsigned(Tag::Context(2), u64::from(v)).expect("value");
    heapless::Vec::from_slice(w.finish().expect("finish")).expect("fits")
}

fn write<A: AccessControl>(
    writes: &[AttributeData<'_>],
    access: &A,
    handler: &Handler,
    ctx: &InteractionContext,
) -> Vec<(AttributePath, Status)> {
    let mut buf = [0u8; 2048];
    let server = Server::new(node(), access, handler, 64);
    let (bytes, _) = server
        .serve_write(writes.iter().copied().map(Ok), ctx, false, &mut buf)
        .expect("serve");
    let response = WriteResponse::decode(bytes).expect("decode");
    response
        .statuses()
        .expect("statuses")
        .map(|s| {
            let s = s.expect("decode each");
            (s.path, s.status.status)
        })
        .collect()
}

fn invoke<A: AccessControl>(
    commands: &[CommandData<'_>],
    access: &A,
    handler: &Handler,
    ctx: &InteractionContext,
) -> Vec<(CommandPath, Result<u32, Status>)> {
    let mut scratch = [0u8; 256];
    let mut buf = [0u8; 2048];
    let server = Server::new(node(), access, handler, 64);
    let (bytes, _) = server
        .serve_invoke(
            commands.iter().copied().map(Ok),
            ctx,
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    response
        .responses()
        .expect("responses")
        .map(|r| match r.expect("decode each") {
            InvokeResponse::Command(c) => (c.path, Ok(c.path.command.unwrap_or(0))),
            InvokeResponse::Status(s) => (s.path, Err(s.status.status)),
        })
        .collect()
}

fn untimed() -> InteractionContext<'static> {
    InteractionContext::default()
}

fn timed() -> InteractionContext<'static> {
    InteractionContext {
        timed: true,
        ..InteractionContext::default()
    }
}

fn on_fabric() -> InteractionContext<'static> {
    InteractionContext {
        fabric_index: Some(FabricIndex(1)),
        ..InteractionContext::default()
    }
}

// --- Write ---------------------------------------------------------------------------------

#[test]
fn a_write_reports_success_for_every_path_it_wrote() {
    // §8.7.3.3 step 2.b.ii, and the difference from a read: success is stated, not implied.
    let handler = Handler::default();
    let v = value(7);
    let path = AttributePath::attribute(1, CL, PLAIN);
    let statuses = write(
        &[AttributeData {
            data_version: None,
            path,
            data: &v,
        }],
        &Holds(Privilege::Administer),
        &handler,
        &untimed(),
    );
    assert_eq!(statuses, vec![(path, Status::Success)]);
    assert_eq!(handler.writes.borrow().as_slice(), &[(PLAIN, 7)]);
}

#[test]
fn a_read_only_attribute_is_unsupported_write_not_unsupported_attribute() {
    // §8.7.3.2 step b.ii.E. The attribute exists; it just cannot be written.
    let handler = Handler::default();
    let v = value(1);
    let path = AttributePath::attribute(1, CL, READ_ONLY);
    let statuses = write(
        &[AttributeData {
            data_version: None,
            path,
            data: &v,
        }],
        &Holds(Privilege::Administer),
        &handler,
        &untimed(),
    );
    assert_eq!(statuses, vec![(path, Status::UnsupportedWrite)]);
    assert!(handler.writes.borrow().is_empty(), "nothing was written");
}

#[test]
fn a_global_attribute_cannot_be_written() {
    // Table 95 gives all five `RV`. A client writing one is told it is read-only rather than
    // that it does not exist — and the server must not let it through to a handler.
    let handler = Handler::default();
    let v = value(1);
    let path = AttributePath::attribute(1, CL, global::CLUSTER_REVISION);
    let statuses = write(
        &[AttributeData {
            data_version: None,
            path,
            data: &v,
        }],
        &Holds(Privilege::Administer),
        &handler,
        &untimed(),
    );
    assert_eq!(statuses, vec![(path, Status::UnsupportedWrite)]);
    assert!(handler.writes.borrow().is_empty());
}

#[test]
fn a_timed_only_attribute_needs_a_timed_transaction() {
    // §8.7.3.2 step b.iv. The `T` quality exists so that a write with real-world consequence
    // cannot be replayed long after the client sent it.
    let handler = Handler::default();
    let v = value(1);
    let path = AttributePath::attribute(1, CL, TIMED_ONLY);
    let data = AttributeData {
        data_version: None,
        path,
        data: &v,
    };
    assert_eq!(
        write(&[data], &Holds(Privilege::Administer), &handler, &untimed()),
        vec![(path, Status::NeedsTimedInteraction)]
    );
    assert!(handler.writes.borrow().is_empty());

    assert_eq!(
        write(&[data], &Holds(Privilege::Administer), &handler, &timed()),
        vec![(path, Status::Success)]
    );
    assert_eq!(handler.writes.borrow().as_slice(), &[(TIMED_ONLY, 1)]);
}

#[test]
fn a_fabric_scoped_attribute_needs_an_accessing_fabric() {
    // §8.7.3.2 step b.v. A PASE session during commissioning has no accessing fabric, so a
    // fabric-scoped write over one has no fabric to attribute the data to.
    let handler = Handler::default();
    let v = value(1);
    let path = AttributePath::attribute(1, CL, FABRIC_SCOPED);
    let data = AttributeData {
        data_version: None,
        path,
        data: &v,
    };
    assert_eq!(
        write(&[data], &Holds(Privilege::Administer), &handler, &untimed()),
        vec![(path, Status::UnsupportedAccess)]
    );
    assert_eq!(
        write(
            &[data],
            &Holds(Privilege::Administer),
            &handler,
            &on_fabric()
        ),
        vec![(path, Status::Success)]
    );
}

#[test]
fn a_stale_data_version_is_refused() {
    // §8.7.3.2 step b.vi. The client computed its write against data that has since changed,
    // so applying it would silently clobber whatever changed it.
    let handler = Handler {
        version: Some(42),
        ..Handler::default()
    };
    let v = value(1);
    let path = AttributePath::attribute(1, CL, PLAIN);
    assert_eq!(
        write(
            &[AttributeData {
                data_version: Some(41),
                path,
                data: &v,
            }],
            &Holds(Privilege::Administer),
            &handler,
            &untimed()
        ),
        vec![(path, Status::DataVersionMismatch)]
    );
    assert!(handler.writes.borrow().is_empty());

    // The matching version goes through.
    assert_eq!(
        write(
            &[AttributeData {
                data_version: Some(42),
                path,
                data: &v,
            }],
            &Holds(Privilege::Administer),
            &handler,
            &untimed()
        ),
        vec![(path, Status::Success)]
    );
}

#[test]
fn a_write_privilege_is_checked_separately_from_the_read_one() {
    // `RW VA`: readable at View, writable only at Administer. A subject that can read it
    // must not therefore be able to write it.
    let handler = Handler::default();
    let v = value(1);
    let path = AttributePath::attribute(1, CL, ADMIN_WRITE);
    let data = AttributeData {
        data_version: None,
        path,
        data: &v,
    };
    assert_eq!(
        write(&[data], &Holds(Privilege::Operate), &handler, &untimed()),
        vec![(path, Status::UnsupportedAccess)]
    );
    assert_eq!(
        write(&[data], &Holds(Privilege::Administer), &handler, &untimed()),
        vec![(path, Status::Success)]
    );
}

#[test]
fn a_cluster_may_refuse_a_value() {
    // §8.7.3.3 step 2.a: a value outside the cluster's constraints is CONSTRAINT_ERROR, and
    // it fails that path without failing the action.
    let handler = Handler::default();
    let bad = value(0xFF);
    let good = value(1);
    let paths = [
        AttributePath::attribute(1, CL, PLAIN),
        AttributePath::attribute(1, CL, ADMIN_WRITE),
    ];
    let statuses = write(
        &[
            AttributeData {
                data_version: None,
                path: paths[0],
                data: &bad,
            },
            AttributeData {
                data_version: None,
                path: paths[1],
                data: &good,
            },
        ],
        &Holds(Privilege::Administer),
        &handler,
        &untimed(),
    );
    assert_eq!(
        statuses,
        vec![
            (paths[0], Status::ConstraintError),
            (paths[1], Status::Success)
        ],
        "one path's failure does not fail the action"
    );
}

#[test]
fn a_wildcard_write_discards_what_it_may_not_touch() {
    // §8.7.3.2 step c: the same silence as a read. A wildcard write from a subject with
    // partial rights writes what it can and says nothing about the rest.
    //
    // The discards step c lists are exactly three — not writable (c.i), access denied or
    // restricted (c.ii), and Timed-only outside a Timed transaction (c.iii). Notably it does
    // **not** include the fabric-scoped check that step b.v applies to a *concrete* path:
    // §8.7.3.3 step 1 instead says such a path "SHALL be processed as a fabric-filtered list
    // of fabric-scoped structs", so the handling moves into the write itself rather than
    // discarding the path. The asymmetry is the specification's, and implementing the
    // symmetric version would silently drop writes a conforming client expects to land.
    let handler = Handler::default();
    let v = value(3);
    let statuses = write(
        &[AttributeData {
            data_version: None,
            path: AttributePath::cluster(1, CL),
            data: &v,
        }],
        &Holds(Privilege::Operate),
        &handler,
        &untimed(),
    );
    // PLAIN and FABRIC_SCOPED are both writable at Operate and neither is Timed-only.
    // ADMIN_WRITE needs Administer, TIMED_ONLY needs a Timed transaction, READ_ONLY is not
    // writable, and the globals are read-only.
    assert_eq!(
        statuses,
        vec![
            (AttributePath::attribute(1, CL, PLAIN), Status::Success),
            (
                AttributePath::attribute(1, CL, FABRIC_SCOPED),
                Status::Success
            ),
        ]
    );
    assert_eq!(
        handler.writes.borrow().as_slice(),
        &[(PLAIN, 3), (FABRIC_SCOPED, 3)]
    );
}

#[test]
fn the_fabric_check_applies_to_a_concrete_write_and_not_to_an_expanded_one() {
    // Pinning the asymmetry above on its own, because it looks like an oversight and is not:
    // §8.7.3.2 step b.v discards a fabric-scoped *concrete* path with no accessing fabric,
    // and step c has no corresponding rule.
    let handler = Handler::default();
    let v = value(1);
    let concrete = AttributePath::attribute(1, CL, FABRIC_SCOPED);
    assert_eq!(
        write(
            &[AttributeData {
                data_version: None,
                path: concrete,
                data: &v
            }],
            &Holds(Privilege::Operate),
            &handler,
            &untimed()
        ),
        vec![(concrete, Status::UnsupportedAccess)],
        "concrete: step b.v refuses it"
    );

    let handler = Handler::default();
    let statuses = write(
        &[AttributeData {
            data_version: None,
            path: AttributePath::cluster(1, CL),
            data: &v,
        }],
        &Holds(Privilege::Operate),
        &handler,
        &untimed(),
    );
    assert!(
        statuses.iter().any(|(path, _)| path == &concrete),
        "expanded: step c has no fabric rule, so it is written"
    );
}

#[test]
fn a_denied_concrete_write_is_told_so_and_a_wildcard_is_not() {
    // The same asymmetry as a read, which is what stops a wildcard write from enumerating
    // what a subject may not touch.
    let handler = Handler::default();
    let v = value(1);
    let path = AttributePath::attribute(1, CL, PLAIN);
    assert_eq!(
        write(
            &[AttributeData {
                data_version: None,
                path,
                data: &v
            }],
            &DeniesCluster(CL),
            &handler,
            &untimed()
        ),
        vec![(path, Status::UnsupportedAccess)]
    );
    assert!(
        write(
            &[AttributeData {
                data_version: None,
                path: AttributePath::cluster(1, CL),
                data: &v
            }],
            &DeniesCluster(CL),
            &handler,
            &untimed()
        )
        .is_empty(),
        "a denied wildcard write produces nothing at all"
    );
}

// --- Invoke -------------------------------------------------------------------------------

#[test]
fn a_command_with_no_response_produces_a_success_status() {
    // §8.8.2.3's Invoke Execution step 1.c.
    let handler = Handler::default();
    let path = CommandPath::command(1, CL, CMD_PLAIN);
    let responses = invoke(
        &[CommandData::new(path)],
        &Holds(Privilege::Operate),
        &handler,
        &untimed(),
    );
    assert_eq!(responses, vec![(path, Err(Status::Success))]);
    assert_eq!(handler.invokes.borrow().as_slice(), &[CMD_PLAIN]);
}

#[test]
fn a_response_command_keeps_the_cluster_and_takes_the_response_id() {
    // §8.8.2.3 Invoke Execution step 1.b: the response's ClusterPath duplicates the request's
    // "up to the cluster ID", and its Command field is "the command ID of the following
    // command". Echoing the request's command id would send a response a client cannot match
    // to the command it defines.
    let handler = Handler::default();
    let responses = invoke(
        &[CommandData::new(CommandPath::command(
            1,
            CL,
            CMD_WITH_RESPONSE,
        ))],
        &Holds(Privilege::Operate),
        &handler,
        &untimed(),
    );
    assert_eq!(responses.len(), 1);
    let (path, outcome) = responses[0];
    assert_eq!(path.endpoint, Some(1));
    assert_eq!(path.cluster, Some(CL));
    assert_eq!(path.command, Some(CMD_RESPONSE_ID), "the response's id");
    assert_eq!(outcome, Ok(CMD_RESPONSE_ID));
}

#[test]
fn the_first_invoke_access_check_is_at_operate_not_view() {
    // §8.8.2.3 step b.i: "assuming the required_privilege for the element is Operate". A View
    // subject must not get past it — and, because the check precedes the existence checks, it
    // must not learn whether the command exists either.
    let handler = Handler::default();
    let missing = CommandPath::command(1, CL, 0xDEAD);
    let responses = invoke(
        &[CommandData::new(missing)],
        &Holds(Privilege::View),
        &handler,
        &untimed(),
    );
    assert_eq!(
        responses,
        vec![(missing, Err(Status::UnsupportedAccess))],
        "a View subject learns nothing about which commands exist"
    );
    assert!(handler.invokes.borrow().is_empty());
}

#[test]
fn each_missing_level_of_a_command_path_gets_its_own_status() {
    // §8.8.2.3 step b.ii.B through D.
    let handler = Handler::default();
    let cases = [
        (
            CommandPath::command(9, CL, CMD_PLAIN),
            Status::UnsupportedEndpoint,
        ),
        (
            CommandPath::command(1, 0xDEAD, CMD_PLAIN),
            Status::UnsupportedCluster,
        ),
        (
            CommandPath::command(1, CL, 0xDEAD),
            Status::UnsupportedCommand,
        ),
    ];
    for (path, expected) in cases {
        assert_eq!(
            invoke(
                &[CommandData::new(path)],
                &Holds(Privilege::Administer),
                &handler,
                &untimed()
            ),
            vec![(path, Err(expected))],
            "{path:?}"
        );
    }
}

#[test]
fn a_timed_only_command_needs_a_timed_invoke() {
    // §8.8.2.3 step b.vi.
    let handler = Handler::default();
    let path = CommandPath::command(1, CL, CMD_TIMED);
    assert_eq!(
        invoke(
            &[CommandData::new(path)],
            &Holds(Privilege::Administer),
            &handler,
            &untimed()
        ),
        vec![(path, Err(Status::NeedsTimedInteraction))]
    );
    assert!(handler.invokes.borrow().is_empty());
    assert_eq!(
        invoke(
            &[CommandData::new(path)],
            &Holds(Privilege::Administer),
            &handler,
            &timed()
        ),
        vec![(path, Err(Status::Success))]
    );
}

#[test]
fn a_fabric_scoped_command_needs_an_accessing_fabric() {
    // §8.8.2.3 step b.v.
    let handler = Handler::default();
    let path = CommandPath::command(1, CL, CMD_FABRIC);
    assert_eq!(
        invoke(
            &[CommandData::new(path)],
            &Holds(Privilege::Administer),
            &handler,
            &untimed()
        ),
        vec![(path, Err(Status::UnsupportedAccess))]
    );
    assert_eq!(
        invoke(
            &[CommandData::new(path)],
            &Holds(Privilege::Administer),
            &handler,
            &on_fabric()
        ),
        vec![(path, Err(Status::Success))]
    );
}

#[test]
fn a_large_message_command_needs_a_transport_that_can_carry_one() {
    // §8.8.2.3 step b.iv, and §7.7.5's "SHALL require TCP for communication". No privilege
    // substitutes for a transport, so even an administrator is refused over UDP.
    let handler = Handler::default();
    let path = CommandPath::command(1, CL, CMD_LARGE);
    assert_eq!(
        invoke(
            &[CommandData::new(path)],
            &Holds(Privilege::Administer),
            &handler,
            &untimed()
        ),
        vec![(path, Err(Status::InvalidTransportType))]
    );

    let over_tcp = InteractionContext {
        large_messages: true,
        ..InteractionContext::default()
    };
    assert_eq!(
        invoke(
            &[CommandData::new(path)],
            &Holds(Privilege::Administer),
            &handler,
            &over_tcp
        ),
        vec![(path, Err(Status::Success))]
    );
}

#[test]
fn several_commands_are_matched_up_by_command_ref() {
    // Revision 12 and later allow more than one command per request (§8.1.1), and each
    // carries a CommandRef so the responses can be matched even though §8.8.2.3 step 2.d
    // says they may come back in a different order.
    let handler = Handler::default();
    let commands = [
        CommandData {
            command_ref: Some(7),
            ..CommandData::new(CommandPath::command(1, CL, CMD_PLAIN))
        },
        CommandData {
            command_ref: Some(8),
            ..CommandData::new(CommandPath::command(1, CL, CMD_WITH_RESPONSE))
        },
    ];
    let mut scratch = [0u8; 256];
    let mut buf = [0u8; 2048];
    let server = Server::new(node(), &Holds(Privilege::Operate), &handler, 64);
    let (bytes, outcome) = server
        .serve_invoke(
            commands.iter().copied().map(Ok),
            &untimed(),
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    assert_eq!(outcome.reports, 2);

    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let refs: Vec<_> = response
        .responses()
        .expect("responses")
        .map(|r| match r.expect("decode each") {
            InvokeResponse::Command(c) => c.command_ref,
            InvokeResponse::Status(s) => s.command_ref,
        })
        .collect();
    assert_eq!(refs, vec![Some(7), Some(8)]);
}

#[test]
fn a_wildcard_invoke_runs_every_command_the_subject_may() {
    // §8.8: "Invoke Request action … SHOULD support wildcard paths." The discards are the
    // same silence as elsewhere: the Administer-only, Timed-only, fabric-scoped and
    // large-message commands are simply not run.
    let handler = Handler::default();
    let path = CommandPath {
        endpoint: Some(1),
        cluster: Some(CL),
        command: None,
    };
    let responses = invoke(
        &[CommandData::new(path)],
        &Holds(Privilege::Operate),
        &handler,
        &untimed(),
    );
    assert_eq!(
        handler.invokes.borrow().as_slice(),
        &[CMD_PLAIN, CMD_WITH_RESPONSE],
        "only the commands that pass every check are run"
    );
    assert_eq!(responses.len(), 2);
}

#[test]
fn a_denied_wildcard_invoke_runs_nothing_and_says_nothing() {
    let handler = Handler::default();
    let path = CommandPath {
        endpoint: Some(1),
        cluster: Some(CL),
        command: None,
    };
    assert!(
        invoke(
            &[CommandData::new(path)],
            &DeniesCluster(CL),
            &handler,
            &untimed()
        )
        .is_empty()
    );
    assert!(handler.invokes.borrow().is_empty());
}

#[test]
fn a_command_privilege_is_honoured() {
    let handler = Handler::default();
    let path = CommandPath::command(1, CL, CMD_ADMIN);
    assert_eq!(
        invoke(
            &[CommandData::new(path)],
            &Holds(Privilege::Manage),
            &handler,
            &untimed()
        ),
        vec![(path, Err(Status::UnsupportedAccess))]
    );
    assert_eq!(
        invoke(
            &[CommandData::new(path)],
            &Holds(Privilege::Administer),
            &handler,
            &untimed()
        ),
        vec![(path, Err(Status::Success))]
    );
}

#[test]
fn a_handler_that_does_not_implement_write_or_invoke_refuses_them() {
    // The trait's defaults. A cluster that forgets to implement `write` must refuse writes
    // rather than silently accept them.
    struct ReadOnly;
    impl matter_kit::im::ClusterHandler for ReadOnly {
        fn read(
            &self,
            _resolved: &Resolved<'_>,
            _ctx: &InteractionContext<'_>,
            w: &mut TlvWriter<'_>,
            tag: Tag,
        ) -> Result<(), Status> {
            w.unsigned(tag, 0).map_err(|_| Status::Failure)
        }
    }

    let v = value(1);
    let path = AttributePath::attribute(1, CL, PLAIN);
    let mut buf = [0u8; 1024];
    let server = Server::new(node(), &Holds(Privilege::Administer), &ReadOnly, 64);
    let (bytes, _) = server
        .serve_write(
            [Ok(AttributeData {
                data_version: None,
                path,
                data: &v,
            })],
            &untimed(),
            false,
            &mut buf,
        )
        .expect("serve");
    let statuses: Vec<_> = WriteResponse::decode(bytes)
        .expect("decode")
        .statuses()
        .expect("statuses")
        .map(|s| s.expect("decode each").status.status)
        .collect();
    assert_eq!(statuses, vec![Status::UnsupportedWrite]);

    let mut scratch = [0u8; 128];
    let mut buf = [0u8; 1024];
    let (bytes, _) = server
        .serve_invoke(
            [Ok(CommandData::new(CommandPath::command(1, CL, CMD_PLAIN)))],
            &untimed(),
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let statuses: Vec<_> = InvokeResponseMessage::decode(bytes)
        .expect("decode")
        .responses()
        .expect("responses")
        .map(|r| match r.expect("decode each") {
            InvokeResponse::Status(s) => s.status.status,
            InvokeResponse::Command(_) => panic!("expected a status"),
        })
        .collect();
    assert_eq!(statuses, vec![Status::UnsupportedCommand]);
}

// --- The Timed transaction window — §8.7.4, §8.7.3.2, §8.8.2.3 -----------------------------

/// Runs the whole transaction: a Timed Request opens the window, then a request arrives with
/// its own `TimedRequest` flag, and `TimedWindows` decides `ctx.timed` rather than the caller
/// asserting it.
fn timed_invoke(
    windows: &mut TimedWindows<2>,
    exchange: ExchangeId,
    timed_request: bool,
    now: Instant,
    handler: &Handler,
) -> Result<(), Status> {
    let timed = windows.check(Some(SessionId(1)), exchange, timed_request, now)?;
    let ctx = InteractionContext {
        timed,
        now,
        session: Some(SessionId(1)),
        ..InteractionContext::default()
    };
    let responses = invoke(
        &[CommandData::new(CommandPath::command(1, CL, CMD_TIMED))],
        &Holds(Privilege::Administer),
        handler,
        &ctx,
    );
    // `CMD_TIMED` has no response command, so success arrives as a `SUCCESS` status rather
    // than as a command (§8.8.2.3's Invoke Execution).
    match responses.first().expect("one response").1 {
        Ok(_) | Err(Status::Success) => Ok(()),
        Err(status) => Err(status),
    }
}

fn ms(n: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_millis(n))
}

#[test]
fn a_timed_invoke_runs_when_the_window_is_open_and_the_flag_is_set() {
    let handler = Handler::default();
    let mut windows = TimedWindows::<2>::new();
    // §8.7.4: the clock starts when the SUCCESS status response goes out.
    windows
        .open(Some(SessionId(1)), ExchangeId(1), 1000, ms(0))
        .expect("open");
    assert_eq!(
        timed_invoke(&mut windows, ExchangeId(1), true, ms(500), &handler),
        Ok(())
    );
    assert_eq!(handler.invokes.borrow().as_slice(), &[CMD_TIMED]);
}

#[test]
fn a_timed_command_without_any_window_never_reaches_the_handler() {
    // The whole point of the `T` quality. §8.8.2.3 rule 3 refuses the flagged request, and
    // without the flag the server's own check (`needs_timed`) refuses it — either way the
    // command does not run.
    let handler = Handler::default();
    let mut windows = TimedWindows::<2>::new();
    assert_eq!(
        timed_invoke(&mut windows, ExchangeId(1), true, ms(0), &handler),
        Err(Status::TimedRequestMismatch)
    );
    assert_eq!(
        timed_invoke(&mut windows, ExchangeId(1), false, ms(0), &handler),
        Err(Status::NeedsTimedInteraction)
    );
    assert!(handler.invokes.borrow().is_empty());
}

#[test]
fn a_late_timed_invoke_is_timeout_and_the_command_does_not_run() {
    // This is the replay the `T` quality exists to stop: the captured Invoke Request is still
    // perfectly valid, and it is refused because it is late.
    let handler = Handler::default();
    let mut windows = TimedWindows::<2>::new();
    windows
        .open(Some(SessionId(1)), ExchangeId(1), 100, ms(0))
        .expect("open");
    assert_eq!(
        timed_invoke(&mut windows, ExchangeId(1), true, ms(101), &handler),
        Err(Status::Timeout)
    );
    assert!(handler.invokes.borrow().is_empty());
}

#[test]
fn one_timed_request_admits_exactly_one_invoke() {
    // A window that survived its request would let one Timed Request pay for a second command
    // at a moment of the sender's choosing — which is the property being bought.
    let handler = Handler::default();
    let mut windows = TimedWindows::<2>::new();
    windows
        .open(Some(SessionId(1)), ExchangeId(1), 1000, ms(0))
        .expect("open");
    assert_eq!(
        timed_invoke(&mut windows, ExchangeId(1), true, ms(1), &handler),
        Ok(())
    );
    assert_eq!(
        timed_invoke(&mut windows, ExchangeId(1), true, ms(2), &handler),
        Err(Status::TimedRequestMismatch)
    );
    assert_eq!(handler.invokes.borrow().len(), 1);
}

#[test]
fn a_timed_write_reaches_a_timed_attribute_and_an_untimed_one_does_not() {
    // The Write half of the same rules: §8.7.3.2 for the transaction, and the per-attribute
    // `T` quality for the element.
    let handler = Handler::default();
    let mut windows = TimedWindows::<2>::new();
    let v = value(9);
    let path = AttributePath::attribute(1, CL, TIMED_ONLY);

    windows
        .open(Some(SessionId(1)), ExchangeId(2), 1000, ms(0))
        .expect("open");
    let timed = windows
        .check(Some(SessionId(1)), ExchangeId(2), true, ms(10))
        .expect("inside the window");
    let ctx = InteractionContext {
        timed,
        ..InteractionContext::default()
    };
    let statuses = write(
        &[AttributeData {
            data_version: None,
            path,
            data: &v,
        }],
        &Holds(Privilege::Administer),
        &handler,
        &ctx,
    );
    assert_eq!(statuses, vec![(path, Status::Success)]);
    assert_eq!(handler.writes.borrow().as_slice(), &[(TIMED_ONLY, 9)]);

    // The same write with no window at all: the flag is false, so the transaction is untimed,
    // and the attribute's `T` quality refuses it.
    let handler = Handler::default();
    let timed = windows
        .check(Some(SessionId(1)), ExchangeId(3), false, ms(10))
        .expect("untimed is allowed");
    assert!(!timed);
    let ctx = InteractionContext {
        timed,
        ..InteractionContext::default()
    };
    let statuses = write(
        &[AttributeData {
            data_version: None,
            path,
            data: &v,
        }],
        &Holds(Privilege::Administer),
        &handler,
        &ctx,
    );
    assert_eq!(statuses, vec![(path, Status::NeedsTimedInteraction)]);
    assert!(handler.writes.borrow().is_empty());
}

#[test]
fn a_windows_deadline_belongs_to_its_own_exchange() {
    // §8.7.3.2: "matching the same TransactionID". One Timed Request must not cover every
    // exchange on the session — that would make the window a property of the connection.
    let handler = Handler::default();
    let mut windows = TimedWindows::<2>::new();
    windows
        .open(Some(SessionId(1)), ExchangeId(1), 1000, ms(0))
        .expect("open");
    assert_eq!(
        timed_invoke(&mut windows, ExchangeId(9), true, ms(1), &handler),
        Err(Status::TimedRequestMismatch)
    );
    assert!(handler.invokes.borrow().is_empty());
}

#[test]
fn a_tag_compressed_wildcard_write_is_discarded_rather_than_echoed() {
    // §8.7.3.3's responses name concrete paths, and §10.6.2.1's tag compression is refused
    // here rather than resolved. The two together mean the refusal can only be *named* when
    // the path already is concrete: a tag-compressed path with fields missing would inherit
    // them from an earlier path, and §10.6.2.1 says those "MAY still be missing. In that case
    // … they indicate wildcard semantics". Echoing it back puts a wildcard in a write
    // response, which is a path no client can act on.
    let v = value(7);
    let path = AttributePath {
        enable_tag_compression: true,
        ..AttributePath::wildcard()
    };
    let data = AttributeData {
        data_version: None,
        path,
        data: &v,
    };
    let handler = Handler::default();
    let responses = write(
        &[data],
        &Holds(Privilege::Administer),
        &handler,
        &InteractionContext::default(),
    );
    for (reported, _) in &responses {
        assert!(
            !reported.has_wildcard(),
            "a write response path is always concrete, got {reported:?}"
        );
    }
    assert!(responses.is_empty(), "the path is discarded, not answered");
}

#[test]
fn a_timed_write_may_not_be_chunked() {
    // §10.7.6.2: "A Write Request action that is part of a Timed Write Interaction SHALL NOT
    // be chunked." The two mechanisms contradict each other. §8.7.4's window is consumed by
    // the first request that arrives on it, so a second chunk of the same action would find
    // no window and be told `TIMED_REQUEST_MISMATCH` — "your client has a bug" — when the
    // real problem is that the action should never have been split. Refusing the action says
    // so once, instead of misdiagnosing every chunk after the first.
    let v = value(1);
    let path = AttributePath::attribute(1, CL, PLAIN);
    let data = AttributeData {
        data_version: None,
        path,
        data: &v,
    };
    let handler = Handler::default();
    let mut buf = [0u8; 1024];
    let server = Server::new(node(), &Holds(Privilege::Administer), &handler, 64);

    let err = server
        .serve_write([Ok(data)], &timed(), true, &mut buf)
        .expect_err("a chunked timed write is refused");
    assert_eq!(err.code(), matter_kit::ErrorCode::InvalidAction);

    // The same write unchunked is fine, and an untimed chunked one is ordinary.
    assert!(
        server
            .serve_write([Ok(data)], &timed(), false, &mut buf)
            .is_ok()
    );
    assert!(
        server
            .serve_write([Ok(data)], &untimed(), true, &mut buf)
            .is_ok()
    );
}

/// §7.10.3: "A cluster data version SHALL be incremented if any attribute data changes" — and a
/// command is one of the ways they change. `ArmFailSafe` sets `Breadcrumb`, `AddNOC` fills the
/// fabric table, `MoveToLevel` moves `CurrentLevel`.
///
/// The write path always did this. The invoke path did not, which meant an attribute changed by
/// a command kept its old version and a client filtering reads with `DataVersionFilters` was
/// told its cache was current when it was not — and had no way to find out. It surfaced as a
/// subscription that primed correctly and then never reported again, but the same staleness
/// breaks an ordinary filtered read.
#[test]
fn a_successful_command_moves_the_clusters_data_version() {
    let versions = DataVersions::<8>::new(1);
    let handler = Handler::default();
    let access = Holds(Privilege::Administer);
    let ctx = InteractionContext::default();

    let before = read_version(&versions);

    let mut scratch = [0u8; 256];
    let mut buf = [0u8; 2048];
    let server = Server::new(node(), &access, &handler, 64).with_data_versions(&versions);
    let command = CommandData {
        path: CommandPath::command(1, CL, PLAIN),
        fields: None,
        command_ref: None,
    };
    let _ = server
        .serve_invoke(
            [command].iter().copied().map(Ok),
            &ctx,
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");

    assert_ne!(
        read_version(&versions),
        before,
        "a command that succeeded left the cluster's data version where it was"
    );
}

/// Reads the version through the trait, which is the only way in — the field is private so that
/// nothing can report a version it did not get from the table.
fn read_version(versions: &DataVersions<8>) -> u32 {
    use matter_kit::dm::DataVersionSource;
    versions.version(1, CL)
}

/// The whole change-notification chain, end to end and in microseconds.
///
/// This is the test that should have existed before any of it was chased through a container.
/// Every piece is sans-I/O: a command changes an attribute, §7.10.3's version records it,
/// `drain_changes` reports it, and `note_cluster_change` dirties the subscription that covers
/// it. Four links, each of which was fixed separately over several twenty-minute commissioning
/// runs, and all four fit in one test that runs faster than a container can start.
#[test]
fn a_command_that_changes_an_attribute_makes_a_subscription_due() {
    use matter_kit::im::{NewSubscription, SubscriptionTable};

    let versions = DataVersions::<8>::new(1);
    let handler = Handler::default();
    let access = Holds(Privilege::Administer);
    let ctx = InteractionContext::default();

    // A subscriber that wants the whole node, primed and quiet.
    let mut table: SubscriptionTable<matter_kit::DefaultConfig, 4, 4> = SubscriptionTable::new();
    let paths = [AttributePath::default()];
    let id = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(1)),
                fabric_index: Some(FabricIndex(1)),
                peer_node_id: None,
                fabric_filtered: false,
                keep_subscriptions: true,
                min_interval_s: 0,
                max_interval_s: 60,
                paths: &paths,
                event_paths: &[],
                min_event_number: 0,
            },
            Instant::from_micros(0),
        )
        .expect("subscribe");
    table
        .find_mut(id)
        .expect("present")
        .reported(Instant::from_micros(0));
    assert!(
        !table.find(id).expect("present").has_pending(),
        "nothing is owed before anything changes"
    );

    // Link 1: a command runs and succeeds.
    let mut scratch = [0u8; 256];
    let mut buf = [0u8; 2048];
    let server = Server::new(node(), &access, &handler, 64).with_data_versions(&versions);
    let command = CommandData {
        path: CommandPath::command(1, CL, PLAIN),
        fields: None,
        command_ref: None,
    };
    let _ = server
        .serve_invoke(
            [command].iter().copied().map(Ok),
            &ctx,
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");

    // Link 2: §7.10.3 recorded it, and the record is readable.
    let changes = versions.drain_changes();
    assert!(
        changes.contains(&(1, CL)),
        "a command that changed an attribute did not reach `drain_changes`: {changes:?}"
    );

    // Link 3: draining is destructive, so the same change is not reported twice.
    assert!(
        versions.drain_changes().is_empty(),
        "a change was reported twice"
    );

    // Link 4: the subscription covering it is now owed a report.
    for (endpoint, cluster) in changes {
        table.note_cluster_change(endpoint, cluster);
    }
    assert!(
        table.find(id).expect("present").has_pending(),
        "the subscription covering the changed cluster is owed a report"
    );
    assert!(
        table.due(Instant::from_micros(0)).next().is_some(),
        "and the report is due, because `MinIntervalFloor` was zero"
    );
}
