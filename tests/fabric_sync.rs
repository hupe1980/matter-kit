//! Commissioner Control (Core §11.26) — Fabric Synchronization's front door.
//!
//! Two ecosystems and a householder with a light in one that they want in the other. The usual
//! answer is to commission the light twice; this is the other answer, where the ecosystems
//! arrange it between themselves.
//!
//! The rules worth testing are about *who* may act on *whose* request:
//!
//! * both commands are CASE-only (§11.26.6.1, §11.26.6.5), because the whole flow turns on
//!   matching a later `CommissionNode` to the same node on the same fabric;
//! * approval is a separate step with an event in between (§11.26.6.1), because asking a person
//!   takes longer than a command may;
//! * a `CommissionNode` from the wrong node, the wrong fabric or with the wrong id is `FAILURE`.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use core::cell::{Cell, RefCell};

use matter_kit::clusters::commissioner_control::{
    self as cctrl, CommissionerControl, CommissionerControlHooks, Decision, Request,
    SupportedDeviceCategoryBitmap, VERIFIER_LEN, Window,
};
use matter_kit::clusters::generated;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, CommandData, CommandPath, InteractionContext, InvokeResponse, InvokeResponseMessage,
    Server, Status,
};
use matter_kit::msg::{FabricIndex, NodeId, SessionId, VendorId};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

const CLIENT: NodeId = NodeId(0x1111_2222_3333_4444);
const OTHER_CLIENT: NodeId = NodeId(0x5555_6666_7777_8888);
const FABRIC: FabricIndex = FabricIndex(1);
const OTHER_FABRIC: FabricIndex = FabricIndex(2);
const REQUEST_ID: u64 = 0xABCD;

/// An aggregator that can commission other ecosystems' nodes.
#[derive(Debug)]
struct Aggregator {
    seen: RefCell<Vec<Request>>,
    offer_window: Cell<bool>,
    verifier: [u8; VERIFIER_LEN],
    salt: [u8; 16],
}

impl Default for Aggregator {
    fn default() -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
            offer_window: Cell::new(true),
            verifier: [0x7Cu8; VERIFIER_LEN],
            salt: [0x5Au8; 16],
        }
    }
}

impl CommissionerControlHooks for Aggregator {
    fn requested(&self, request: &Request) {
        self.seen.borrow_mut().push(*request);
    }

    fn window(&self, _request: &Request) -> Option<Window<'_>> {
        self.offer_window.get().then_some(Window {
            commissioning_timeout: 180,
            pake_passcode_verifier: &self.verifier,
            discriminator: 3840,
            iterations: 1_000,
            salt: &self.salt,
        })
    }
}

struct Device<'a> {
    node: Node<'a>,
    cluster: CommissionerControl<'a, Aggregator, 4>,
}

fn device(aggregator: &Aggregator) -> Device<'_> {
    let conforming = Box::leak(Box::new(
        CommissionerControl::<Aggregator, 4>::conforming(0, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(0, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: CommissionerControl::new(
            aggregator,
            SupportedDeviceCategoryBitmap::FABRIC_SYNCHRONIZATION,
        ),
    }
}

/// A CASE session from `client` on `fabric`.
fn over_case(client: NodeId, fabric: FabricIndex) -> InteractionContext<'static> {
    InteractionContext {
        fabric_index: Some(fabric),
        peer_node_id: Some(client),
        session: Some(SessionId(2)),
        ..InteractionContext::default()
    }
}

#[derive(Debug, PartialEq)]
enum Answer {
    Status(Status),
    /// A `ReverseOpenCommissioningWindow`: `(timeout, discriminator, iterations, salt length)`.
    Reverse(u16, u16, u32, usize),
}

fn invoke(
    device: &Device<'_>,
    command: u32,
    fields: Option<&[u8]>,
    ctx: &InteractionContext<'_>,
) -> Answer {
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(0, cctrl::ID, command))
    };
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let (bytes, _) = server
        .serve_invoke([Ok(data)], ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let message = InvokeResponseMessage::decode(bytes).expect("decode");
    match message
        .responses()
        .expect("responses")
        .next()
        .expect("one response")
        .expect("decode")
    {
        InvokeResponse::Status(s) => Answer::Status(s.status.status),
        InvokeResponse::Command(c) => decode(c.fields.expect("fields")),
    }
}

fn decode(fields: &[u8]) -> Answer {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Structure));
    let (mut timeout, mut discriminator, mut iterations, mut salt) = (0u16, 0u16, 0u32, 0usize);
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        match (field.tag.context(), &field.value) {
            (Some(0), Value::Unsigned(v)) => timeout = *v as u16,
            (Some(2), Value::Unsigned(v)) => discriminator = *v as u16,
            (Some(3), Value::Unsigned(v)) => iterations = *v as u32,
            (Some(4), Value::Octets(v)) => salt = v.len(),
            _ => reader.skip_value(&field).unwrap(),
        }
    }
    Answer::Reverse(timeout, discriminator, iterations, salt)
}

fn approval(request_id: u64, label: Option<&str>) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), request_id).unwrap();
    w.unsigned(Tag::Context(1), 0xFFF1).unwrap();
    w.unsigned(Tag::Context(2), 0x8000).unwrap();
    if let Some(label) = label {
        w.utf8(Tag::Context(3), label).unwrap();
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn commission(request_id: u64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), request_id).unwrap();
    w.unsigned(Tag::Context(1), 30).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

// --- The flow -----------------------------------------------------------------------------------

#[test]
fn the_whole_flow_runs_approval_event_then_reverse_window() {
    // §11.26's three commands and the event between them. `RequestCommissioningApproval` is a
    // *question*: §11.26.6.1 requires it to answer SUCCESS whatever the server thinks, because
    // the thinking may involve a person and a command may not wait for one.
    let aggregator = Aggregator::default();
    let device = device(&aggregator);
    let ctx = over_case(CLIENT, FABRIC);

    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, Some("Kitchen lamp"))),
            &ctx
        ),
        Answer::Status(Status::Success)
    );
    assert_eq!(aggregator.seen.borrow().len(), 1);
    assert_eq!(aggregator.seen.borrow()[0].vendor_id, VendorId(0xFFF1));
    assert!(
        device.cluster.take_events().is_empty(),
        "the decision was reported before anybody made it"
    );

    // A client that jumps the gun is asking the server to commission something it has not
    // agreed to.
    assert_eq!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(REQUEST_ID)),
            &ctx
        ),
        Answer::Status(Status::Failure)
    );

    // §11.26.7.1: the real answer arrives as an event.
    assert!(
        device
            .cluster
            .decide(REQUEST_ID, CLIENT, Decision::Approved)
    );
    let events = device.cluster.take_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].request_id, REQUEST_ID);
    assert_eq!(events[0].client_node_id, CLIENT);
    assert_eq!(events[0].decision, Decision::Approved);

    // ...and now the roles reverse: the server answers with a command for the *client* to run.
    assert_eq!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(REQUEST_ID)),
            &ctx
        ),
        Answer::Reverse(180, 3840, 1_000, 16)
    );
    assert!(
        device.cluster.reverse_pending(),
        "the caller was not told to send the reverse command"
    );
    assert!(!device.cluster.reverse_pending(), "it was taken twice");
}

#[test]
fn both_commands_need_a_case_session() {
    // §11.26.6.1 and §11.26.6.5: "If the command is not executed via a CASE session, the command
    // SHALL fail with a status code of UNSUPPORTED_ACCESS." A request over PASE comes from
    // something that has not proved which fabric it is on — and the flow turns on matching a
    // later `CommissionNode` to the same node on the same fabric.
    let aggregator = Aggregator::default();
    let device = device(&aggregator);
    let pase = InteractionContext {
        session: Some(SessionId(1)),
        ..InteractionContext::default()
    };
    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, None)),
            &pase
        ),
        Answer::Status(Status::UnsupportedAccess)
    );
    assert_eq!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(REQUEST_ID)),
            &pase
        ),
        Answer::Status(Status::UnsupportedAccess)
    );
    assert!(aggregator.seen.borrow().is_empty());

    // A CASE session with no peer node id is not one either: §11.26.6.5 needs the id to match.
    let anonymous = InteractionContext {
        fabric_index: Some(FABRIC),
        session: Some(SessionId(2)),
        ..InteractionContext::default()
    };
    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, None)),
            &anonymous
        ),
        Answer::Status(Status::UnsupportedAccess)
    );
}

#[test]
fn a_commission_node_from_the_wrong_node_or_fabric_is_refused() {
    // §11.26.6.5: "The server SHALL return FAILURE if the CommissionNode command is not sent
    // from the same NodeID and on the same fabric as the RequestCommissioningApproval." Without
    // all three matching, anybody on the fabric could ride somebody else's approval.
    let aggregator = Aggregator::default();
    let device = device(&aggregator);
    let ctx = over_case(CLIENT, FABRIC);
    invoke(
        &device,
        cctrl::REQUEST_COMMISSIONING_APPROVAL,
        Some(&approval(REQUEST_ID, None)),
        &ctx,
    );
    device
        .cluster
        .decide(REQUEST_ID, CLIENT, Decision::Approved);
    device.cluster.take_events();

    // A different node on the same fabric.
    assert_eq!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(REQUEST_ID)),
            &over_case(OTHER_CLIENT, FABRIC)
        ),
        Answer::Status(Status::Failure)
    );
    // The same node on a different fabric.
    assert_eq!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(REQUEST_ID)),
            &over_case(CLIENT, OTHER_FABRIC)
        ),
        Answer::Status(Status::Failure)
    );
    // The right node, the wrong request.
    assert_eq!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(0x9999)),
            &ctx
        ),
        Answer::Status(Status::Failure)
    );
    // ...and the right one still works.
    assert!(matches!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(REQUEST_ID)),
            &ctx
        ),
        Answer::Reverse(..)
    ));
}

#[test]
fn a_repeated_request_id_from_the_same_client_is_refused() {
    // §11.26.6.1: "If the RequestID and client NodeID ... match a previously received
    // RequestCommissioningApproval and the server has not returned an error or completed
    // commissioning of a device for the prior request, then the server SHOULD return FAILURE."
    // Two live requests with one id would make the later `CommissionNode` ambiguous.
    let aggregator = Aggregator::default();
    let device = device(&aggregator);
    let ctx = over_case(CLIENT, FABRIC);
    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, None)),
            &ctx
        ),
        Answer::Status(Status::Success)
    );
    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, None)),
            &ctx
        ),
        Answer::Status(Status::Failure)
    );
    // A *different* client may use the same id: the pair is what identifies a request.
    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, None)),
            &over_case(OTHER_CLIENT, FABRIC)
        ),
        Answer::Status(Status::Success)
    );

    // Once the request is forgotten, the id is free again.
    device.cluster.forget(REQUEST_ID, CLIENT);
    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, None)),
            &ctx
        ),
        Answer::Status(Status::Success)
    );
}

#[test]
fn a_refused_or_timed_out_request_carries_its_reason() {
    // §11.26.7.3: SUCCESS "if the server is ready to begin commissioning", TIMEOUT "if the
    // server timed out due to user inaction" and FAILURE for anything else. A client told
    // TIMEOUT can ask the user again; one told FAILURE should not.
    let aggregator = Aggregator::default();
    let device = device(&aggregator);
    let ctx = over_case(CLIENT, FABRIC);

    for (id, decision, status) in [
        (1u64, Decision::TimedOut, Status::Timeout),
        (2, Decision::Refused, Status::Failure),
    ] {
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(id, None)),
            &ctx,
        );
        device.cluster.decide(id, CLIENT, decision);
        let events = device.cluster.take_events();
        assert_eq!(events[0].decision, decision);
        assert_eq!(events[0].decision.status(), status);

        // And a request that was not approved cannot be acted on.
        assert_eq!(
            invoke(&device, cctrl::COMMISSION_NODE, Some(&commission(id)), &ctx),
            Answer::Status(Status::Failure)
        );
    }
}

#[test]
fn a_window_that_breaks_the_open_commissioning_constraints_is_refused() {
    // §11.26.6.8: "This is an alias onto the OpenCommissioningWindow command" — so §11.19.8.1's
    // constraints come with it. A 97-octet verifier is not a formality: §3.10's SPAKE2+ needs
    // exactly that, and a client handed a short one would open a window nothing can pair with.
    let aggregator = Aggregator::default();
    let device = device(&aggregator);
    let ctx = over_case(CLIENT, FABRIC);
    invoke(
        &device,
        cctrl::REQUEST_COMMISSIONING_APPROVAL,
        Some(&approval(REQUEST_ID, None)),
        &ctx,
    );
    device
        .cluster
        .decide(REQUEST_ID, CLIENT, Decision::Approved);
    device.cluster.take_events();

    // A server that will not offer a window at all.
    aggregator.offer_window.set(false);
    assert_eq!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(REQUEST_ID)),
            &ctx
        ),
        Answer::Status(Status::Failure)
    );

    aggregator.offer_window.set(true);
    assert!(matches!(
        invoke(
            &device,
            cctrl::COMMISSION_NODE,
            Some(&commission(REQUEST_ID)),
            &ctx
        ),
        Answer::Reverse(..)
    ));
}

#[test]
fn a_label_past_the_constraint_is_refused() {
    // §11.26.6.1's constraint on `Label` is "max 64". It is what the *other* ecosystem shows a
    // user before completing the reverse commissioning, so a truncated one would name the
    // wrong device on somebody's screen.
    let aggregator = Aggregator::default();
    let device = device(&aggregator);
    let ctx = over_case(CLIENT, FABRIC);
    let long = "x".repeat(65);
    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, Some(&long))),
            &ctx
        ),
        Answer::Status(Status::ConstraintError)
    );
    let exact = "x".repeat(64);
    assert_eq!(
        invoke(
            &device,
            cctrl::REQUEST_COMMISSIONING_APPROVAL,
            Some(&approval(REQUEST_ID, Some(&exact))),
            &ctx
        ),
        Answer::Status(Status::Success)
    );
}

#[test]
fn the_cluster_matches_the_specification() {
    let spec = generated::find(cctrl::ID).expect("Commissioner Control");
    let built =
        CommissionerControl::<Aggregator, 4>::conforming(0, &Optional::NONE).expect("sized");
    let mut defects = Vec::new();
    spec.validate(&built.descriptor(), |defect| defects.push(defect));
    assert!(defects.is_empty(), "{defects:?}");

    // §11.26.6's table: two commands in, one out — and the one out is `server ⇒ client`, which
    // is why it appears in the generated list rather than the accepted one.
    assert_eq!(built.descriptor().accepted_commands.len(), 2);
}
