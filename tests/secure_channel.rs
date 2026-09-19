//! The node's secure channel, driven the way a device drives it (`sc::Channel`).
//!
//! `tests/pase_over_sim.rs` and `tests/case_over_sim.rs` drive the two handshakes. This drives
//! the thing *around* them — the rules that belong to no handshake and were, until there was a
//! type for them, two hundred lines of `examples/light.rs`:
//!
//! * §5.5's first rule, which is the one with teeth: one handshake at a time. A node that
//!   answers every `PBKDFParamRequest` lets an attacker wait for the owner to start
//!   commissioning, interrupt, and finish the handshake in their place — a takeover of an
//!   uncommissioned device with no physical access, and a published analysis of Matter found it
//!   missing from a certified implementation.
//! * §5.5's failure count, which ends commissioning mode after twenty.
//! * §4.11.1.1's eviction, so the session a handshake produces always has somewhere to go.
//! * §6.2.3's attestation challenge, which PASE produces and `AttestationRequest` signs over.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::crypto::{SoftKeyStore, Spake2pVerifierData};
use matter_kit::fabric::FabricTable;
use matter_kit::messaging::Messaging;
use matter_kit::platform::Instant;
use matter_kit::platform::sim::SimNet;
use matter_kit::sc::{
    Channel, ChannelBuffers, ChannelContext, PaseInitiator, PbkdfParameters, opcode,
};
use matter_kit::session::SessionKind;
use matter_kit::{Config, DefaultConfig};

const PASSCODE: u32 = 20_202_021;
const SALT: &[u8] = b"a per-device salt";
const ITERATIONS: u32 = 1_000;

type Stack = Messaging<DefaultConfig, { DefaultConfig::SESSIONS }, 8>;

struct Node {
    channel: Channel,
    stack: Stack,
    fabrics: RefCell<FabricTable<DefaultConfig, { DefaultConfig::FABRICS }>>,
    keys: RefCell<SoftKeyStore<8>>,
    window: RefCell<CommissioningWindow>,
    verifier: Spake2pVerifierData,
    parameters: PbkdfParameters,
}

impl Node {
    fn new() -> Self {
        let parameters = PbkdfParameters::new(ITERATIONS, SALT).expect("parameters");
        Self {
            channel: Channel::new(),
            stack: Messaging::new(1, 100, 7),
            fabrics: RefCell::new(FabricTable::new()),
            keys: RefCell::new(SoftKeyStore::new()),
            window: RefCell::new(CommissioningWindow::new()),
            verifier: Spake2pVerifierData::from_passcode(PASSCODE, SALT, ITERATIONS)
                .expect("verifier"),
            parameters,
        }
    }
}

/// One commissioner's side of PASE, run against the channel until the session is installed.
fn commission(node: &mut Node, rng: &SimNet, now: Instant) -> matter_kit::Result<()> {
    let mut initiator = PaseInitiator::new(
        PASSCODE,
        matter_kit::msg::SessionId(0x4242),
        Some(node.parameters.clone()),
        None,
    );
    let (mut request, mut reply) = ([0u8; 1024], [0u8; 1024]);
    let (mut frame, mut evict) = ([0u8; 1024], [0u8; 1024]);

    let mut len = initiator.start(&[0x11; 32], &mut request)?;
    for opcode in [opcode::PBKDF_PARAM_REQUEST, opcode::PAKE1, opcode::PAKE3] {
        let ctx = ChannelContext {
            fabrics: &node.fabrics,
            keys: &node.keys,
            rng,
            window: &node.window,
            verifier: &node.verifier,
            parameters: &node.parameters,
            now,
        };
        let mut buffers = ChannelBuffers {
            reply: &mut reply,
            frame: &mut frame,
            evict: &mut evict,
        };
        let answered = node.channel.on_message(
            &mut node.stack,
            opcode,
            &request[..len],
            &ctx,
            &mut buffers,
        )?;
        let Some((_, answer_len)) = answered.reply else {
            panic!("the channel said nothing to {opcode:#04x}");
        };
        match opcode {
            opcode::PBKDF_PARAM_REQUEST => {
                len = initiator.on_pbkdf_param_response(
                    &reply[..answer_len],
                    &[0x33; 32],
                    &mut request,
                )?;
            }
            opcode::PAKE1 => {
                len = initiator.on_pake2(&reply[..answer_len], &mut request)?;
            }
            _ => {
                initiator.on_pake_finished(&reply[..answer_len])?;
                let established = answered.established.expect("PASE produced a session");
                assert_eq!(established.kind, SessionKind::Pase);
                assert!(
                    established.challenge.is_some(),
                    "§6.2.3: the attestation challenge comes out of PASE, and nothing else \
                     produces it"
                );
            }
        }
    }
    Ok(())
}

/// The whole of PASE through the channel, and the session installed at the end of it.
#[test]
fn a_handshake_run_through_the_channel_installs_a_session() {
    let net = SimNet::new(7);
    let mut node = Node::new();
    assert_eq!(node.stack.sessions().len(), 0);

    commission(&mut node, &net, Instant::ZERO).expect("commissioning");

    assert_eq!(node.stack.sessions().len(), 1, "the session was installed");
    assert!(
        node.channel.attestation_challenge().is_some(),
        "and the challenge is kept, because AttestationRequest signs over it"
    );
    assert!(node.channel.is_established());
}

/// §5.5 rule 1, which is the reason this type exists: while a PASE session is established on the
/// commissioning channel, a second `PBKDFParamRequest` is refused with `Busy`.
#[test]
fn a_second_commissioner_is_refused_while_the_first_holds_the_channel() {
    let net = SimNet::new(7);
    let mut node = Node::new();
    commission(&mut node, &net, Instant::ZERO).expect("commissioning");

    // A second commissioner arrives with a perfectly good request.
    let mut interloper = PaseInitiator::new(
        PASSCODE,
        matter_kit::msg::SessionId(0x9999),
        Some(node.parameters.clone()),
        None,
    );
    let (mut request, mut reply) = ([0u8; 1024], [0u8; 1024]);
    let (mut frame, mut evict) = ([0u8; 1024], [0u8; 1024]);
    let len = interloper.start(&[0x55; 32], &mut request).expect("start");

    let ctx = ChannelContext {
        fabrics: &node.fabrics,
        keys: &node.keys,
        rng: &net,
        window: &node.window,
        verifier: &node.verifier,
        parameters: &node.parameters,
        now: Instant::ZERO,
    };
    let mut buffers = ChannelBuffers {
        reply: &mut reply,
        frame: &mut frame,
        evict: &mut evict,
    };
    let answered = node
        .channel
        .on_message(
            &mut node.stack,
            opcode::PBKDF_PARAM_REQUEST,
            &request[..len],
            &ctx,
            &mut buffers,
        )
        .expect("the channel answers rather than failing");

    let (answer_opcode, answer_len) = answered.reply.expect("a refusal is still an answer");
    assert_eq!(answer_opcode, opcode::STATUS_REPORT);
    let report = matter_kit::sc::StatusReport::decode(&reply[..answer_len]).expect("decode");
    assert_eq!(
        report.protocol_code,
        matter_kit::sc::SecureChannelCode::Busy as u16,
        "§4.11.1.3: Busy says \"not now\", which is exactly true — and the alternative is a \
         second commissioner stepping into the first one's handshake"
    );
    assert!(answered.established.is_none());
    assert_eq!(
        node.stack.sessions().len(),
        1,
        "and nothing else was installed"
    );
}

/// §5.5's other half: the channel is released when the session on it closes, so a node can be
/// commissioned twice.
#[test]
fn closing_the_session_reopens_the_channel() {
    let net = SimNet::new(7);
    let mut node = Node::new();
    commission(&mut node, &net, Instant::ZERO).expect("first commissioning");
    assert!(node.channel.is_established());

    let session = node
        .stack
        .sessions()
        .iter()
        .next()
        .expect("the session")
        .local_session_id;
    node.stack.close_session(session);
    node.channel.closed(session);

    assert!(
        !node.channel.is_established(),
        "a node that never releases the channel can be commissioned exactly once"
    );
    commission(&mut node, &net, Instant::ZERO).expect("second commissioning");
    assert_eq!(node.stack.sessions().len(), 1);
}

/// A message for a handshake that is not running is dropped, not answered.
///
/// Answering would tell a stranger which handshake the node is in the middle of, and a node that
/// treated it as an error would have to decide what to do about an error nobody caused.
#[test]
fn a_message_for_a_handshake_that_is_not_running_is_met_with_silence() {
    let net = SimNet::new(7);
    let mut node = Node::new();
    let (mut reply, mut frame, mut evict) = ([0u8; 512], [0u8; 512], [0u8; 512]);
    let ctx = ChannelContext {
        fabrics: &node.fabrics,
        keys: &node.keys,
        rng: &net,
        window: &node.window,
        verifier: &node.verifier,
        parameters: &node.parameters,
        now: Instant::ZERO,
    };
    let mut buffers = ChannelBuffers {
        reply: &mut reply,
        frame: &mut frame,
        evict: &mut evict,
    };
    let answered = node
        .channel
        .on_message(
            &mut node.stack,
            opcode::PAKE3,
            &[0u8; 8],
            &ctx,
            &mut buffers,
        )
        .expect("silence is not an error");
    assert!(answered.reply.is_none());
    assert!(answered.established.is_none());

    // And an opcode the channel does not serve at all.
    let mut buffers = ChannelBuffers {
        reply: &mut reply,
        frame: &mut frame,
        evict: &mut evict,
    };
    let answered = node
        .channel
        .on_message(&mut node.stack, 0x7F, &[0u8; 8], &ctx, &mut buffers)
        .expect("silence");
    assert!(answered.reply.is_none());
}
