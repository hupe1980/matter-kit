//! Commissioning a device through the assembled stack, not through hand-wired pieces.
//!
//! Every layer below this has been tested on its own: [`sc::pase`] against the published
//! SPAKE2+ vectors, [`im::server`] against §8.8.2.3's numbered steps, [`msg`] against the
//! privacy worked example. What none of them tested is that the layers **compose** — that a
//! datagram arriving on a socket finds its session, its exchange and its protocol, and that
//! the answer goes back out the same way.
//!
//! That seam is [`messaging::Messaging`], and this is the test of it: a commissioner and a
//! device exchange real Matter datagrams, complete PASE, and then run an Interaction Model
//! Invoke **encrypted under the session PASE produced**. Nothing here builds a message header
//! by hand.
//!
//! It is the closest verifiable proxy for `chip-tool pairing onnetwork` that does not need a
//! socket: the same messages, in the same order, through the same code. What it does not
//! cover is the network itself — discovery, and the operating system's UDP stack.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::clusters::basic_information::Location;
use matter_kit::clusters::general_commissioning::{self, GeneralCommissioning, RegulatoryLocation};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::config::DefaultConfig;
use matter_kit::crypto::Spake2pVerifierData;
use matter_kit::crypto::SymmetricKey;
use matter_kit::dm::{
    AttributeDescriptor, ClusterDescriptor, CommandDescriptor, Endpoint, Node, Privilege,
};
use matter_kit::exchange::ExchangeKey;
use matter_kit::im::{
    AllowAll, AttributePath, CommandData, CommandPath, InteractionContext, InvokeRequest,
    InvokeResponse, InvokeResponseMessage, Server,
};
use matter_kit::messaging::{Due, Messaging, Received};
use matter_kit::msg::{NodeId, ProtocolId, SessionId, SessionKeys};
use matter_kit::platform::{Instant, Peer, PeerAddr};
use matter_kit::sc::{
    PaseInitiator, PaseResponder, PbkdfParameters, ResponderConfig, SessionParams, opcode,
};
use matter_kit::session::{EstablishedKeys, Role, SecureSession, SessionKind};
use matter_kit::tlv::{ContainerKind, Tag, TlvWriter};

type Stack = Messaging<DefaultConfig>;

const PASSCODE: u32 = 20_202_021;
const SALT: &[u8] = b"SPAKE2P Key Salt";
const ITERATIONS: u32 = 1_000;

const DEVICE_SESSION: SessionId = SessionId(0x1001);
const COMMISSIONER_SESSION: SessionId = SessionId(0x2002);

const ADDR: PeerAddr = PeerAddr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const PEER: Peer = Peer::Udp(ADDR);

fn at(ms: u64) -> Instant {
    Instant::from_micros(ms * 1000)
}

/// One datagram in flight.
struct Wire {
    bytes: [u8; 1280],
    len: usize,
}

impl Wire {
    const fn new() -> Self {
        Self {
            bytes: [0u8; 1280],
            len: 0,
        }
    }
}

/// Delivers a datagram and returns the opcode and payload it carried.
fn deliver(to: &mut Stack, wire: &mut Wire, now: Instant) -> (ExchangeKey, u8, Vec<u8>) {
    match to
        .receive(&mut wire.bytes[..wire.len], PEER, now)
        .expect("a well-formed datagram is received")
    {
        Received::Message {
            exchange,
            header,
            payload,
            ..
        } => (exchange, header.opcode, payload.to_vec()),
        other => panic!("expected a protocol message, got {other:?}"),
    }
}

/// Sends one protocol message, leaving it in `wire`.
fn send(
    from: &mut Stack,
    exchange: ExchangeKey,
    opcode: u8,
    payload: &[u8],
    now: Instant,
    wire: &mut Wire,
) {
    let mut scratch = [0u8; 1280];
    let (len, _) = from
        .send(
            exchange,
            opcode,
            true,
            payload,
            now,
            0,
            &mut scratch,
            &mut wire.bytes,
        )
        .expect("send");
    wire.len = len;
}

// --- The device's data model -------------------------------------------------------------------

const GC_ATTRS: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_write(general_commissioning::BREADCRUMB),
    AttributeDescriptor::read_only(general_commissioning::BASIC_COMMISSIONING_INFO),
    AttributeDescriptor::read_only(general_commissioning::REGULATORY_CONFIG),
    AttributeDescriptor::read_only(general_commissioning::LOCATION_CAPABILITY),
    AttributeDescriptor::read_only(general_commissioning::SUPPORTS_CONCURRENT_CONNECTION),
];

const GC_CMDS: &[CommandDescriptor] = &[
    CommandDescriptor::new(general_commissioning::ARM_FAIL_SAFE),
    CommandDescriptor::new(general_commissioning::SET_REGULATORY_CONFIG),
    CommandDescriptor::new(general_commissioning::COMMISSIONING_COMPLETE),
];

const GC: ClusterDescriptor<'static> = ClusterDescriptor {
    id: general_commissioning::ID,
    revision: 2,
    feature_map: 0,
    attributes: GC_ATTRS,
    accepted_commands: GC_CMDS,
    generated_commands: &[],
    events: &[],
};

const EP0: &[ClusterDescriptor<'static>] = &[GC];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, EP0)];

/// `ArmFailSafe` with a 60-second expiry and a breadcrumb, as §11.10.7.2 encodes it.
fn arm_fail_safe_fields(breadcrumb: u64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 60).unwrap();
    w.unsigned(Tag::Context(1), breadcrumb).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// The whole flow: five PASE messages, then an encrypted Invoke on the session they produced.
#[test]
fn a_commissioner_pairs_and_then_invokes_a_cluster_over_the_session_it_established() {
    let parameters = PbkdfParameters::new(ITERATIONS, SALT).expect("parameters");
    let verifier =
        Spake2pVerifierData::from_passcode(PASSCODE, SALT, ITERATIONS).expect("verifier");

    let mut device_pase = PaseResponder::new(
        ResponderConfig {
            verifier,
            parameters: parameters.clone(),
            session_params: Some(SessionParams::default()),
        },
        DEVICE_SESSION,
    );
    let mut commissioner_pase = PaseInitiator::new(
        PASSCODE,
        COMMISSIONER_SESSION,
        Some(parameters.clone()),
        None,
    );

    // Two nodes with nothing but their own randomness.
    let mut commissioner = Stack::new(0x2000, 0x100, 0xABCD_0000);
    let mut device = Stack::new(0x1000, 0x200, 0x1234_0000);

    let mut wire = Wire::new();
    let mut payload = [0u8; 1024];

    // --- PASE, on the unsecured session (§4.14.1.2) ---------------------------------------
    //
    // "All PASE messages are sent using an Unsecured Session: The Session ID field SHALL be
    // set to 0." The exchange is opened on session 0 and everything below flows through it.
    let out = commissioner
        .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0xE0E0_1234_5678_9ABC)
        .expect("open");

    // 1. PBKDFParamRequest.
    let n = commissioner_pase
        .start(&[0x11; 32], &mut payload)
        .expect("start");
    send(
        &mut commissioner,
        out,
        opcode::PBKDF_PARAM_REQUEST,
        &payload[..n],
        at(0),
        &mut wire,
    );

    // 2. PBKDFParamResponse.
    let (device_exchange, code, got) = deliver(&mut device, &mut wire, at(1));
    assert_eq!(code, opcode::PBKDF_PARAM_REQUEST);
    let n = device_pase
        .on_pbkdf_param_request(&got, &[0x22; 32], &mut payload)
        .expect("on_pbkdf_param_request");
    send(
        &mut device,
        device_exchange,
        opcode::PBKDF_PARAM_RESPONSE,
        &payload[..n],
        at(1),
        &mut wire,
    );

    // 3. Pake1.
    let (_, code, got) = deliver(&mut commissioner, &mut wire, at(2));
    assert_eq!(code, opcode::PBKDF_PARAM_RESPONSE);
    let n = commissioner_pase
        .on_pbkdf_param_response(&got, &[0x33; 32], &mut payload)
        .expect("on_pbkdf_param_response");
    send(
        &mut commissioner,
        out,
        opcode::PAKE1,
        &payload[..n],
        at(2),
        &mut wire,
    );

    // 4. Pake2.
    let (_, code, got) = deliver(&mut device, &mut wire, at(3));
    assert_eq!(code, opcode::PAKE1);
    let n = device_pase
        .on_pake1(&got, &[0x44; 32], &mut payload)
        .expect("on_pake1");
    send(
        &mut device,
        device_exchange,
        opcode::PAKE2,
        &payload[..n],
        at(3),
        &mut wire,
    );

    // 5. Pake3.
    let (_, code, got) = deliver(&mut commissioner, &mut wire, at(4));
    assert_eq!(code, opcode::PAKE2);
    let n = commissioner_pase
        .on_pake2(&got, &mut payload)
        .expect("on_pake2");
    send(
        &mut commissioner,
        out,
        opcode::PAKE3,
        &payload[..n],
        at(4),
        &mut wire,
    );

    // 6. StatusReport(PakeFinished), and the device has its keys.
    let (_, code, got) = deliver(&mut device, &mut wire, at(5));
    assert_eq!(code, opcode::PAKE3);
    let (n, device_keys) = device_pase.on_pake3(&got, &mut payload).expect("on_pake3");
    send(
        &mut device,
        device_exchange,
        opcode::STATUS_REPORT,
        &payload[..n],
        at(5),
        &mut wire,
    );

    let (_, code, got) = deliver(&mut commissioner, &mut wire, at(6));
    assert_eq!(code, opcode::STATUS_REPORT);
    let commissioner_keys = commissioner_pase
        .on_pake_finished(&got)
        .expect("the device proved it knows the passcode");

    assert_eq!(
        device_keys.attestation_challenge, commissioner_keys.attestation_challenge,
        "both ends derived the same secrets"
    );

    // --- Install the session both ends just agreed on ---------------------------------------
    install(
        &mut commissioner,
        COMMISSIONER_SESSION,
        DEVICE_SESSION,
        Role::Initiator,
        commissioner_keys,
        at(6),
    );
    install(
        &mut device,
        DEVICE_SESSION,
        COMMISSIONER_SESSION,
        Role::Responder,
        device_keys,
        at(6),
    );
    commissioner.close(out);
    device.close(device_exchange);

    // --- An Invoke, encrypted under it -------------------------------------------------------
    //
    // This is the step that proves the layers compose: nothing below re-frames anything, and
    // the datagram on the wire is now a real encrypted Matter message.
    let secure = commissioner
        .open(COMMISSIONER_SESSION, ProtocolId::INTERACTION_MODEL, at(7))
        .expect("open a secure exchange");

    let fields = arm_fail_safe_fields(0xDEAD_BEEF);
    let mut request = [0u8; 512];
    let request = matter_kit::im::encode_invoke_request(
        &mut request,
        [CommandData {
            path: CommandPath::command(
                0,
                general_commissioning::ID,
                general_commissioning::ARM_FAIL_SAFE,
            ),
            fields: Some(&fields),
            command_ref: None,
        }],
        false,
        false,
    )
    .expect("encode");
    send(
        &mut commissioner,
        secure,
        matter_kit::im::opcode::INVOKE_REQUEST,
        request,
        at(7),
        &mut wire,
    );

    // The datagram is genuinely encrypted: the plaintext command fields are not in it.
    assert!(
        !wire.bytes[..wire.len]
            .windows(4)
            .any(|w| w == 0xDEAD_BEEFu32.to_le_bytes()),
        "the breadcrumb must not be readable on the wire"
    );

    let (secure_exchange, code, got) = deliver(&mut device, &mut wire, at(8));
    assert_eq!(code, matter_kit::im::opcode::INVOKE_REQUEST);

    // The device serves it with its real commissioning clusters.
    let location = Location::region_agnostic();
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let window = RefCell::new(CommissioningWindow::new());
    let handler = GeneralCommissioning::new(
        &location,
        RegulatoryLocation::IndoorOutdoor,
        &fail_safe,
        &window,
    );
    let node = Node::new(ENDPOINTS);
    let access = AllowAll;
    let server = Server::new(node, &access, &handler, 24);

    let request = InvokeRequest::decode(&got).expect("the device decodes what arrived");
    let ctx = InteractionContext::new().at(at(8));
    let mut scratch = [0u8; 512];
    let mut response = [0u8; 1024];
    let (response, _) = server
        .serve_invoke(
            request.commands().expect("commands"),
            &ctx,
            false,
            &mut scratch,
            &mut response,
        )
        .expect("serve");

    send(
        &mut device,
        secure_exchange,
        matter_kit::im::opcode::INVOKE_RESPONSE,
        response,
        at(8),
        &mut wire,
    );

    // ...and the commissioner reads the answer back off the wire.
    let (_, code, got) = deliver(&mut commissioner, &mut wire, at(9));
    assert_eq!(code, matter_kit::im::opcode::INVOKE_RESPONSE);
    let decoded = InvokeResponseMessage::decode(&got).expect("decode");
    let mut responses = decoded.responses().expect("responses");
    let first = responses.next().expect("one response").expect("decode");
    match first {
        InvokeResponse::Command(command) => {
            assert_eq!(
                command.path.command,
                Some(general_commissioning::ARM_FAIL_SAFE_RESPONSE)
            );
        }
        InvokeResponse::Status(status) => {
            panic!("ArmFailSafe should answer with a response command, got {status:?}");
        }
    }

    // The fail-safe really is armed, on the device, from a command that crossed an encrypted
    // session established from a printed passcode.
    assert!(fail_safe.borrow().is_armed(at(8)));
    assert_eq!(fail_safe.borrow().breadcrumb(), 0xDEAD_BEEF);
    let _ = Privilege::Administer;
    let _ = AttributePath::wildcard();
}

fn install(
    stack: &mut Stack,
    local: SessionId,
    peer: SessionId,
    role: Role,
    keys: EstablishedKeys,
    now: Instant,
) {
    install_kind(stack, local, peer, role, keys, now, SessionKind::Pase);
}

fn install_kind(
    stack: &mut Stack,
    local: SessionId,
    peer: SessionId,
    role: Role,
    keys: EstablishedKeys,
    now: Instant,
    kind: SessionKind,
) {
    let mut session = SecureSession::new(local, peer, kind, role, keys, 1, now);
    // §4.9.2's nonce is built from the *sender's* operational node id, and on a CASE session
    // that id never travels in the header — both ends are meant to know it from the session.
    // Two sessions that both leave it at `UNSPECIFIED` therefore agree with each other and
    // with nothing else on the wire, so a test that omits it is a test that passes while the
    // node is unreachable. The ids are derived from the session ids so the two ends differ.
    if matches!(kind, SessionKind::Case) {
        session.local_node_id = NodeId(0x0000_0000_0001_0000 | u64::from(local.0));
        session.peer_node_id = NodeId(0x0000_0000_0001_0000 | u64::from(peer.0));
    }
    stack
        .sessions_mut()
        .insert(session)
        .expect("the table has room");
}

/// A lost message is retransmitted with the same counter, and the peer treats the second
/// copy as the duplicate it is (§4.12.2.1, §4.12.2.2).
#[test]
fn a_lost_pase_message_is_retransmitted_and_the_repeat_is_not_acted_on_twice() {
    let mut commissioner = Stack::new(0x2000, 0x100, 7);
    let mut device = Stack::new(0x1000, 0x200, 9);

    let out = commissioner
        .open_unsecured(ProtocolId::SECURE_CHANNEL, at(0), 0xE0E0_1234_5678_9ABC)
        .expect("open");
    let mut wire = Wire::new();
    send(
        &mut commissioner,
        out,
        opcode::PBKDF_PARAM_REQUEST,
        b"request",
        at(0),
        &mut wire,
    );
    let sent = Wire {
        bytes: wire.bytes,
        len: wire.len,
    };

    // It arrives, and the device acts on it.
    let (device_exchange, _, got) = deliver(&mut device, &mut wire, at(1));
    assert_eq!(got, b"request");

    // The acknowledgement is lost, so the commissioner's timer fires.
    let deadline = commissioner
        .wake_at()
        .expect("a reliable send arms a timer");
    match commissioner.poll(deadline, 0) {
        Some(Due::Retransmit { exchange, .. }) => assert_eq!(exchange, out),
        other => panic!("expected a retransmission, got {other:?}"),
    }

    // The retransmission is the same bytes. The device must acknowledge it and must not
    // hand it to the application again.
    let mut again = sent;
    match device
        .receive(&mut again.bytes[..again.len], PEER, at(2))
        .expect("receive")
    {
        Received::Duplicate {
            exchange,
            needs_ack,
        } => {
            assert_eq!(exchange, device_exchange);
            assert!(
                needs_ack,
                "§4.12.2.2: acknowledged even though it is a repeat"
            );
        }
        other => panic!("a repeat must not reach the application: {other:?}"),
    }
}

/// §4.9's privacy is a *sender's* choice on a unicast session, and a receiver honours the
/// flag either way.
///
/// The **P** flag is only required on group messages. On a secure unicast session it hides
/// the message counter from a passive observer — which is already authenticated, and readable
/// by anyone holding the key — so it is off by default rather than depending on every peer
/// having exercised its deobfuscation path. Reception is not a choice: the flag is in the
/// message.
#[test]
fn privacy_is_a_senders_choice_and_a_receiver_honours_the_flag_either_way() {
    for private in [false, true] {
        let mut a = Stack::new(0x2000, 0x100, 11);
        let mut b = Stack::new(0x1000, 0x200, 22);
        a.set_privacy(private);
        // The receiver's own setting is irrelevant: it always reads what arrived.
        b.set_privacy(!private);

        let keys = EstablishedKeys::derive(b"a shared secret", &[]).expect("derive");
        // A CASE session: §4.9 has nothing to hide on a PASE one, which carries no
        // operational identity to correlate.
        install_kind(
            &mut a,
            SessionId(0x11),
            SessionId(0x22),
            Role::Initiator,
            keys.clone(),
            at(0),
            SessionKind::Case,
        );
        install_kind(
            &mut b,
            SessionId(0x22),
            SessionId(0x11),
            Role::Responder,
            keys,
            at(0),
            SessionKind::Case,
        );

        let exchange = a
            .open(SessionId(0x11), ProtocolId::INTERACTION_MODEL, at(0))
            .expect("open");
        let mut wire = Wire::new();
        send(&mut a, exchange, 0x02, b"payload", at(0), &mut wire);

        // The flag on the wire says what the sender chose. Security flags are octet 3.
        let flagged = wire.bytes[3] & 0x80 != 0;
        assert_eq!(flagged, private, "the P flag reflects the sender's setting");

        let (_, opcode, payload) = deliver(&mut b, &mut wire, at(1));
        assert_eq!(opcode, 0x02);
        assert_eq!(
            payload, b"payload",
            "a private message decodes exactly like a plain one"
        );
    }
}

/// A node that opens an exchange of its own knows where to send it.
///
/// §8.5.3's subscription reports are the case that matters: the publisher, not the subscriber,
/// starts that exchange. `Stack::open` used to open it with no peer, and an exchange with no
/// peer has no address — so the report was built, encrypted, counted and then **dropped by the
/// application**, which had nowhere to send it. `Stack::send` succeeds; `Stack::peer` returns
/// `None`; a caller writing the natural `if let` swallows it.
///
/// Nothing reports an error. The subscriber holds whatever the priming report gave it and never
/// hears again, which `TC_CGEN_2_1` sees three seconds later as an attribute that was "never
/// reported via subscription" — with both ends healthy and no failed message to point at.
///
/// A session exists because a peer authenticated itself from somewhere, so the session
/// remembers where, and `open` uses it.
#[test]
fn an_exchange_this_node_opens_knows_where_its_peer_is() {
    let mut device = Stack::new(0x1000, 0x200, 0x1234_0000);
    let mut commissioner = Stack::new(0x2000, 0x100, 0xABCD_0000);
    let mut wire = Wire::new();

    // A session on both ends, sharing one set of keys with the roles the other way round.
    let keys = || EstablishedKeys {
        i2r: SessionKeys::from_encryption_key(SymmetricKey::new([0x41; 16])).expect("i2r"),
        r2i: SessionKeys::from_encryption_key(SymmetricKey::new([0x42; 16])).expect("r2i"),
        attestation_challenge: SymmetricKey::new([0x43; 16]),
    };
    install(
        &mut commissioner,
        COMMISSIONER_SESSION,
        DEVICE_SESSION,
        Role::Initiator,
        keys(),
        at(0),
    );
    install(
        &mut device,
        DEVICE_SESSION,
        COMMISSIONER_SESSION,
        Role::Responder,
        keys(),
        at(0),
    );
    let out = commissioner
        .open(COMMISSIONER_SESSION, ProtocolId::INTERACTION_MODEL, at(0))
        .expect("open");
    send(
        &mut commissioner,
        out,
        matter_kit::im::opcode::READ_REQUEST,
        b"hello",
        at(0),
        &mut wire,
    );
    let (inbound, _, _) = deliver(&mut device, &mut wire, at(1));

    // The exchange the *peer* opened learns the address from the datagram that opened it.
    assert_eq!(
        device.peer(inbound),
        Some(PEER),
        "an inbound exchange knows its peer"
    );

    // And so does one this node opens itself, which is the whole point.
    let outbound = device
        .open(DEVICE_SESSION, ProtocolId::INTERACTION_MODEL, at(2))
        .expect("open an exchange of this node's own");
    assert_eq!(
        device.peer(outbound),
        Some(PEER),
        "a node with a session has nowhere to send a report it started"
    );
}

/// §4.12.7.1: a standalone acknowledgement goes out under **Secure Channel**, whatever protocol
/// the exchange is running.
///
/// > The Protocol ID SHALL be set to PROTOCOL_ID_SECURE_CHANNEL.
///
/// Taking the exchange's protocol instead is the natural thing to write — the message *is* on
/// that exchange — and it produces a datagram that decodes as Interaction Model opcode `0x10`,
/// which the Interaction Model does not define. The CHIP SDK prints it as `IM:----` and answers
/// `Invalid message type`, ending the very interaction the acknowledgement was keeping alive.
///
/// Nothing in this repository could catch it: both ends would read the header the same way and
/// agree. `TC_IDM_2_2` found it.
#[test]
fn a_standalone_acknowledgement_is_a_secure_channel_message() {
    let mut device = Stack::new(0x1000, 0x200, 0x1234_0000);
    let mut commissioner = Stack::new(0x2000, 0x100, 0xABCD_0000);
    let mut wire = Wire::new();

    let keys = || EstablishedKeys {
        i2r: SessionKeys::from_encryption_key(SymmetricKey::new([0x51; 16])).expect("i2r"),
        r2i: SessionKeys::from_encryption_key(SymmetricKey::new([0x52; 16])).expect("r2i"),
        attestation_challenge: SymmetricKey::new([0x53; 16]),
    };
    install(
        &mut commissioner,
        COMMISSIONER_SESSION,
        DEVICE_SESSION,
        Role::Initiator,
        keys(),
        at(0),
    );
    install(
        &mut device,
        DEVICE_SESSION,
        COMMISSIONER_SESSION,
        Role::Responder,
        keys(),
        at(0),
    );

    // An Interaction Model exchange, so the wrong answer and the right one differ.
    let out = commissioner
        .open(COMMISSIONER_SESSION, ProtocolId::INTERACTION_MODEL, at(0))
        .expect("open");
    send(
        &mut commissioner,
        out,
        matter_kit::im::opcode::READ_REQUEST,
        b"hello",
        at(0),
        &mut wire,
    );
    let (inbound, _, _) = deliver(&mut device, &mut wire, at(1));

    let mut buf = [0u8; 256];
    let len = device
        .acknowledge(inbound, at(2), &mut buf)
        .expect("a standalone acknowledgement is owed");
    assert!(len > 0, "nothing was written");

    // Decode it the way a peer does, and look at the protocol the header names.
    let mut datagram = buf;
    match commissioner
        .receive(&mut datagram[..len], PEER, at(3))
        .expect("the peer accepts it")
    {
        Received::Acknowledged { .. } | Received::Duplicate { .. } => {}
        Received::Message { header, .. } => {
            assert_eq!(
                header.protocol,
                ProtocolId::SECURE_CHANNEL,
                "a standalone acknowledgement went out under the exchange's protocol"
            );
            assert_eq!(header.opcode, matter_kit::sc::opcode::MRP_STANDALONE_ACK);
        }
        other => panic!("unexpected {other:?}"),
    }
}
