//! The interaction-model dispatcher, against an arbitrary opcode and arbitrary bytes.
//!
//! `im::Dispatcher` is the first thing a commissioned node runs on an operational message: it
//! reads an opcode chosen by the peer, decodes the body as whatever that opcode claims, and
//! applies §8.7.2.3 and §8.8.2.3's rules before any cluster sees anything. Every one of those
//! inputs is a number a peer chose, and a peer on the fabric is authenticated, not trusted.
//!
//! The decoders themselves are fuzzed by `im`. What is fuzzed here is the layer above them —
//! routing, the Timed window and the `MaxPathsPerInvoke` count — and the two properties that
//! layer is responsible for:
//!
//! 1. **Nothing panics**, for any opcode and any body, against any window state. The command
//!    count walks a lazy array whose length the peer chose, and the window arithmetic is over
//!    a `u16` timeout and an `Instant` the caller supplies.
//! 2. **A `Reply` never claims more of the buffer than it wrote.** The dispatcher returns a
//!    length rather than a slice, so nothing but this check stands between a wrong length and
//!    a caller transmitting uninitialised buffer contents to the network.
//! 3. **§8.8.2.3 rule 4 terminates the interaction.** When the peer sends more
//!    `CommandDataIB` elements than the node advertises, *no* command reaches a cluster —
//!    "SHALL terminate", not "SHALL stop after the first few". The bound is over elements and
//!    not over invocations: §8.8.2.2 rule 4a lets a single element carry a wildcard that
//!    expands to many commands, which is why the count has to be taken from the request rather
//!    than from the handler.

#![no_main]

use core::cell::Cell;

use libfuzzer_sys::fuzz_target;
use matter_kit::dm::{
    AttributeDescriptor, ClusterDescriptor, CommandDescriptor, Endpoint, Node, Privilege, Resolved,
    ResolvedCommand,
};
use matter_kit::im::{
    AccessControl, AttributePath, Dispatcher, InteractionContext, InvokeRequest, Outcome,
    ReadCursor, Request, Served, Server, Status, StatusIb, opcode as im_opcode,
};
use matter_kit::msg::{ExchangeId, SessionId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{Tag, TlvWriter};

const ATTRS: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_write(0x0000),
    AttributeDescriptor::read_write(0x0001),
];
const CMDS: &[CommandDescriptor] = &[CommandDescriptor::new(0x00), CommandDescriptor::new(0x01)];

const fn cluster(id: u32) -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id,
        revision: 3,
        feature_map: 0,
        attributes: ATTRS,
        accepted_commands: CMDS,
        generated_commands: &[],
        events: &[],
    }
}

const EP0: &[ClusterDescriptor<'static>] = &[cluster(0x0006)];
const EP1: &[ClusterDescriptor<'static>] = &[cluster(0x0008)];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, EP0), Endpoint::new(1, EP1)];

struct All;
impl AccessControl for All {
    fn allows(&self, _p: &AttributePath, _r: Privilege) -> Outcome {
        Outcome::Granted
    }
}

/// Counts what actually reached a cluster, so the invoke bound can be asserted.
#[derive(Default)]
struct Counting {
    invokes: Cell<usize>,
}

impl matter_kit::im::ClusterHandler for Counting {
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
        Ok(())
    }

    fn invoke(
        &self,
        _resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<u32>, StatusIb> {
        self.invokes.set(self.invokes.get().saturating_add(1));
        Ok(None)
    }
}

fuzz_target!(|data: &[u8]| {
    // The first three octets steer the run; the rest is the message body.
    let Some((&opcode, rest)) = data.split_first() else {
        return;
    };
    let Some((&limit, rest)) = rest.split_first() else {
        return;
    };
    let Some((&clock, body)) = rest.split_first() else {
        return;
    };

    let max_paths = u16::from(limit % 4);
    let handler = Counting::default();
    let server = Server::new(Node::new(ENDPOINTS), &All, &handler, 64);
    let mut dispatcher: Dispatcher<2> = Dispatcher::new(max_paths);
    // `new` raises zero to one, so this is the bound that is actually in force.
    let enforced = usize::from(if max_paths == 0 { 1 } else { max_paths });

    let mut cursor = ReadCursor::START;
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 1024];

    // How many `CommandDataIB` elements the peer actually sent, counted the way rule 4 counts
    // them — stopping at the first that does not decode, since a malformed element is rule 5's
    // business and not rule 4's.
    let sent_commands = if opcode == im_opcode::INVOKE_REQUEST {
        InvokeRequest::decode(body).ok().and_then(|request| {
            request.commands().ok().map(|commands| {
                let mut n = 0usize;
                for command in commands {
                    if command.is_err() {
                        break;
                    }
                    n = n.saturating_add(1);
                }
                n
            })
        })
    } else {
        None
    };

    // Two dispatches of the same message: the second sees whatever window state the first
    // left, which is how a Timed Request followed by its action is reached, and how a window
    // is made to expire between them.
    for round in 0..2u8 {
        let now = Instant::ZERO.saturating_add(Duration::from_millis(
            u64::from(clock).saturating_mul(u64::from(round)),
        ));
        let request = Request {
            opcode,
            payload: body,
            session: Some(SessionId(1)),
            exchange: ExchangeId(1),
            groupcast: opcode % 7 == 0,
        };
        let ctx = InteractionContext::new().at(now);
        let before = handler.invokes.get();
        match dispatcher.dispatch(&server, request, &ctx, &mut cursor, &mut scratch, &mut buf) {
            Ok(Served::Reply { len, .. }) => {
                assert!(
                    len <= buf.len(),
                    "a reply claimed {len} octets of a {}-octet buffer",
                    buf.len()
                );
            }
            Ok(Served::Subscribe(_) | Served::Silent | Served::Unhandled { .. }) | Err(_) => {}
        }
        if let Some(sent) = sent_commands
            && sent > enforced
        {
            assert_eq!(
                handler.invokes.get(),
                before,
                "{sent} command blocks against a MaxPathsPerInvoke of {enforced} \
                 ran {} of them instead of terminating the interaction",
                handler.invokes.get().saturating_sub(before)
            );
        }
    }
});
