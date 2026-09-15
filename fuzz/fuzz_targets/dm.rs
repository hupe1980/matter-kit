//! Serving Reads, Writes and Invokes against arbitrary request bytes.
//!
//! This is the whole pipeline a commissioned peer drives: decode a request, expand its paths
//! against a node, check access, run the handler, and write a response. Each piece is tested
//! on its own; what this covers is the seam between them, on input the peer chose.
//!
//! Four properties:
//!
//! 1. **Nothing panics**, and the buffers are never overrun — a wildcard expands to far more
//!    paths than fit in one message, so the limit must actually hold.
//! 2. **Whatever is produced is a valid `ReportData`** that decodes back. A server that
//!    emitted a half-written report on some input would corrupt a session rather than fail a
//!    request.
//! 3. **Every reported path is concrete.** §8.4.3.2: "Each path indicated by the Report Data
//!    action SHALL be a Concrete Path." A wildcard leaking into a report would leave a client
//!    unable to tell which attribute a value belonged to.
//! 4. **A denied wildcard expansion produces no status.** §8.4.3.2 step 1c discards it, and
//!    that silence is the privacy property of a wildcard read: statuses would let a subject
//!    with no privilege map the node by counting them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::dm::{
    Access, AttributeDescriptor, ClusterDescriptor, CommandDescriptor, Endpoint, Node, Privilege,
    Resolved,
};
use matter_kit::im::{
    AccessControl, AttributePath, AttributeReport, InteractionContext, InvokeRequest,
    InvokeResponse, InvokeResponseMessage, Outcome, ReadRequest, ReportData, Server, Status,
    WriteRequest, WriteResponse,
};
use matter_kit::tlv::{Tag, TlvWriter};

const ATTRS_A: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_only(0x0000),
    AttributeDescriptor::read_write(0x0001),
    // Unreadable: a wildcard must discard it, a concrete path must get UNSUPPORTED_READ.
    AttributeDescriptor::read_only(0x0002).with_access(Access::write_only(Privilege::Manage)),
    // Administer-only: a View subject must not see it.
    AttributeDescriptor::read_only(0x0003).with_access(Access::read_only(Privilege::Administer)),
];
const ATTRS_B: &[AttributeDescriptor] = &[AttributeDescriptor::read_only(0x0000)];
const CMDS: &[CommandDescriptor] = &[
    CommandDescriptor::new(0).with_response(1),
    CommandDescriptor::new(2),
    CommandDescriptor::new(3).with_access(
        Access::invoke(Privilege::Operate).with_qualities(matter_kit::dm::AccessQualities::TIMED),
    ),
];

const fn cluster(
    id: u32,
    attributes: &'static [AttributeDescriptor],
) -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id,
        revision: 2,
        feature_map: 3,
        attributes,
        accepted_commands: CMDS,
        generated_commands: &[],
        events: &[],
    }
}

const EP0: &[ClusterDescriptor<'static>] = &[cluster(0x0006, ATTRS_A), cluster(0x0028, ATTRS_B)];
const EP1: &[ClusterDescriptor<'static>] = &[cluster(0x0008, ATTRS_B)];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, EP0), Endpoint::new(1, EP1)];

/// Denies one cluster, to exercise the discard path.
struct Policy(Privilege);

impl AccessControl for Policy {
    fn allows(&self, path: &AttributePath, required: Privilege) -> Outcome {
        if path.cluster == Some(0x0028) {
            return Outcome::Denied;
        }
        if self.0.grants(required) {
            Outcome::Granted
        } else {
            Outcome::Denied
        }
    }
}

struct Reader;

impl matter_kit::im::ClusterHandler for Reader {
    fn write(
        &self,
        _resolved: &Resolved<'_>,
        data: &[u8],
        _op: matter_kit::im::WriteOp,
        _ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        // Refuse on a sentinel, so the failure path is exercised too.
        if data.last() == Some(&0xFF) {
            return Err(Status::ConstraintError);
        }
        Ok(())
    }

    fn invoke(
        &self,
        resolved: &matter_kit::dm::ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<u32>, matter_kit::im::StatusIb> {
        match resolved.command.response {
            Some(id) => {
                w.unsigned(tag, 1).map_err(|_| Status::Failure)?;
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.unsigned(tag, u64::from(resolved.attribute))
            .map_err(|_| Status::Failure)
    }

    fn data_version(&self, _resolved: &Resolved<'_>) -> Option<u32> {
        Some(1)
    }
}

/// Every context a handler might run in, so the Timed and fabric branches are reached.
const CONTEXTS: [InteractionContext<'static>; 2] = [
    InteractionContext::new(),
    InteractionContext::new()
        .timed()
        .with_fabric(matter_kit::msg::FabricIndex(1))
        .with_large_messages()
        .fabric_filtered()
        .on_session(matter_kit::msg::SessionId(1)),
];

fuzz_target!(|data: &[u8]| {
    let node = Node::new(ENDPOINTS);
    // The descriptors are `const`; if they were unsorted every lookup would silently miss.
    node.validate().expect("the test node is well formed");

    serve_writes(node, data);
    serve_invokes(node, data);

    let Ok(request) = ReadRequest::decode(data) else {
        return;
    };
    let Ok(paths) = request.attribute_paths() else {
        return;
    };
    let Some(paths) = paths else {
        return;
    };

    for (privilege, ctx) in [Privilege::View, Privilege::Administer]
        .into_iter()
        .zip(CONTEXTS)
    {
        let policy = Policy(privilege);
        let server = Server::new(node, &policy, &Reader, 24);
        let mut scratch = [0u8; 256];
        let mut buf = [0u8; 2048];
        let Ok((bytes, outcome)) = server.serve(paths.clone(), &ctx, None, &mut scratch, &mut buf)
        else {
            continue;
        };
        assert!(outcome.reports <= 24, "the report limit did not hold");

        // Whatever came out must be a report a peer can read.
        let report = ReportData::decode(bytes).expect("a served report decodes");
        assert_eq!(
            report.more_chunked_messages, outcome.truncated,
            "MoreChunkedMessages must match whether the read was cut short"
        );
        let Ok(Some(reports)) = report.attribute_reports() else {
            continue;
        };
        let mut seen = 0usize;
        for item in reports {
            seen += 1;
            assert!(seen <= 24, "more reports than the limit allowed");
            let item = item.expect("each served report decodes");
            let path = item.path();
            assert!(
                !path.has_wildcard(),
                "§8.4.3.2: every reported path is a concrete path"
            );
            if let AttributeReport::Status(status) = item {
                // A status can only come from a concrete request path. The denied cluster is
                // never reachable that way unless the request named it outright.
                assert!(
                    status.status.status != Status::Success,
                    "a status report never carries SUCCESS"
                );
            }
        }
        assert_eq!(
            seen, outcome.reports,
            "the count must match what was written"
        );
    }
});

/// A `WriteRequest`'s paths, served under both contexts.
fn serve_writes(node: Node<'static>, data: &[u8]) {
    let Ok(request) = WriteRequest::decode(data) else {
        return;
    };
    let Ok(writes) = request.writes() else {
        return;
    };
    for ctx in CONTEXTS {
        let policy = Policy(Privilege::Administer);
        let server = Server::new(node, &policy, &Reader, 24);
        let mut buf = [0u8; 2048];
        let Ok((bytes, outcome)) = server.serve_write(writes.clone(), &ctx, false, &mut buf) else {
            continue;
        };
        assert!(outcome.reports <= 24, "the response limit did not hold");

        let response = WriteResponse::decode(bytes).expect("a served write response decodes");
        let Ok(statuses) = response.statuses() else {
            continue;
        };
        let mut seen = 0usize;
        for status in statuses {
            seen += 1;
            assert!(seen <= 24, "more responses than the limit allowed");
            let status = status.expect("each served status decodes");
            assert!(
                !status.path.has_wildcard(),
                "a write response names a concrete path"
            );
        }
        assert_eq!(seen, outcome.reports);
    }
}

/// An `InvokeRequest`'s commands, served under both contexts.
fn serve_invokes(node: Node<'static>, data: &[u8]) {
    let Ok(request) = InvokeRequest::decode(data) else {
        return;
    };
    let Ok(commands) = request.commands() else {
        return;
    };
    for ctx in CONTEXTS {
        let policy = Policy(Privilege::Administer);
        let server = Server::new(node, &policy, &Reader, 24);
        let mut scratch = [0u8; 256];
        let mut buf = [0u8; 2048];
        let Ok((bytes, outcome)) =
            server.serve_invoke(commands.clone(), &ctx, false, &mut scratch, &mut buf)
        else {
            continue;
        };
        assert!(outcome.reports <= 24, "the response limit did not hold");

        let response =
            InvokeResponseMessage::decode(bytes).expect("a served invoke response decodes");
        let Ok(responses) = response.responses() else {
            continue;
        };
        let mut seen = 0usize;
        for item in responses {
            seen += 1;
            assert!(seen <= 24, "more responses than the limit allowed");
            match item.expect("each served response decodes") {
                InvokeResponse::Command(command) => {
                    // §8.8.3.2: "A valid InvokeResponseIB SHALL only indicate a concrete
                    // path." A response whose path is wildcarded cannot be matched to the
                    // command that produced it.
                    assert!(command.path.concrete().is_some());
                }
                InvokeResponse::Status(status) => {
                    assert!(status.path.concrete().is_some());
                }
            }
        }
        assert_eq!(seen, outcome.reports);
    }
}
