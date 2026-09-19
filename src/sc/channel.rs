//! The secure channel a node answers on: §5.5's rules, both handshakes, and the session they
//! produce.
//!
//! [`PaseResponder`] and [`CaseResponder`] are state machines over their own messages, and it is
//! right that they are: they take their inputs as parameters, so a test drives them with
//! fixtures and no node. What neither of them is, is *the node's secure channel* — and the
//! difference is a list of rules that belong to no handshake:
//!
//! * **§5.5's three admission rules.** One handshake at a time, sixty seconds to finish it,
//!   twenty failures and commissioning mode ends. None is a property of SPAKE2+; all three are
//!   properties of the channel it runs on, and a node that answers every `PBKDFParamRequest`
//!   unconditionally lets a second commissioner step into the first one's handshake and finish
//!   it in their place. A published analysis of Matter found exactly that missing from a
//!   *certified* implementation ([`commissioning::admission`](crate::commissioning::admission)).
//! * **§11.19.8.1's ephemeral verifier.** While an Enhanced Commissioning window is open, PASE
//!   runs against the verifier the administrator supplied — not the factory passcode. A node
//!   that answers with its own is a node whose printed passcode still works after an
//!   administrator deliberately replaced it.
//! * **§4.11.1.1's eviction.** The session a handshake produces has to go somewhere, and when
//!   there is no room the least recently used one is evicted and told so.
//! * **§6.2.3's attestation challenge.** PASE produces it beside the session keys, it never
//!   crosses the wire, and `AttestationRequest` signs over it. A node that forgets to keep it
//!   cannot answer the command that proves it is a genuine device.
//!
//! Every one of those was, until this module existed, the application's to remember — which in
//! this repository meant two hundred lines of `examples/light.rs`, where seven of the
//! interoperability defects found so far have lived.
//!
//! # What it does not own
//!
//! The socket, the clock and the buffers. [`Channel::on_message`] is sans-I/O like everything
//! else here: it is handed the opcode and the body, and it returns what to send. The caller
//! still decides when to read and when to write, and still owns the interaction model above it.

use core::cell::RefCell;

use crate::commissioning::admission::{Admit, PaseAdmission};
use crate::commissioning::window::CommissioningWindow;
use crate::config::Config;
use crate::crypto::{KeyStore, Spake2pVerifierData, SymmetricKey};
use crate::error::Result;
use crate::fabric::FabricTable;
use crate::messaging::{Evicted, Messaging};
use crate::msg::{FabricIndex, SessionId};
use crate::platform::{Instant, Rng};
use crate::sc::status::{SecureChannelCode, StatusReport};
use crate::sc::{
    CaseResponder, PaseResponder, PbkdfParameters, ResponderConfig, SessionParams, Sigma1, Sigma3,
    opcode,
};
use crate::session::{Role, SecureSession, SessionKind};

/// What the node brings to a handshake: its credentials, its randomness and its clock.
///
/// Borrowed rather than owned, and per call rather than per channel, because every one of these
/// belongs to the node and outlives any one handshake — and because a `Channel` that owned them
/// would need six type parameters to say so.
pub struct ChannelContext<'a, C: Config, const N: usize, K: KeyStore, R: Rng> {
    /// The fabrics `AddNOC` created, which is what CASE resolves a destination identifier
    /// against.
    pub fabrics: &'a RefCell<FabricTable<C, N>>,
    /// Where private keys live: the key store is the platform's, never this crate's.
    pub keys: &'a RefCell<K>,
    /// The only source of randomness the handshakes have.
    pub rng: &'a R,
    /// The commissioning window, which decides whether PASE runs against the factory verifier
    /// or an administrator's (§11.19.8.1), and which closes after twenty failures.
    pub window: &'a RefCell<CommissioningWindow>,
    /// The factory SPAKE2+ verifier, derived from the printed passcode at manufacture.
    pub verifier: &'a Spake2pVerifierData,
    /// The PBKDF parameters that verifier was derived with.
    pub parameters: &'a PbkdfParameters,
    /// Now. Nothing in this crate reads a clock for itself, so the caller says what time it is.
    pub now: Instant,
}

/// The three buffers a handshake needs, named rather than positional.
///
/// All three are `&mut [u8]`, so passing them in the wrong order type-checks — and the failure
/// would be a reply written into the buffer holding the eviction report, which is a message sent
/// to the wrong peer rather than a compile error. They are named for the same reason
/// [`Sigma2Randomness`](super::case::Sigma2Randomness) is.
pub struct ChannelBuffers<'a> {
    /// Where the answer to this message is written.
    pub reply: &'a mut [u8],
    /// Scratch for framing, when installing a session has to evict one.
    pub frame: &'a mut [u8],
    /// Where §4.11.1.1's `CloseSession` report to the evicted peer is left, ready to send.
    pub evict: &'a mut [u8],
}

/// A session this channel established, and everything the node needs to know about it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Established {
    /// The local session id it was installed under.
    pub session: SessionId,
    /// Which handshake produced it.
    pub kind: SessionKind,
    /// The fabric, for a CASE session; [`FabricIndex::NONE`] for PASE, which has none until
    /// §11.18.6.8 step 10a binds one.
    pub fabric: FabricIndex,
    /// §6.2.3's attestation challenge, for a PASE session.
    ///
    /// It never crosses the wire and `AttestationRequest` signs over it, so a node that drops it
    /// cannot answer the one command that proves it is a genuine device.
    pub challenge: Option<SymmetricKey>,
}

/// What [`Channel::on_message`] produced.
#[derive(Debug)]
#[non_exhaustive]
pub struct ChannelReply {
    /// The opcode to send back, and how much of the reply buffer it occupies.
    ///
    /// `None` means say nothing: a message for a handshake that is not running is dropped
    /// rather than answered, because answering it would tell a stranger what state the node is
    /// in.
    pub reply: Option<(u8, usize)>,
    /// The session this message completed, if it completed one.
    pub established: Option<Established>,
    /// A session evicted to make room for it (§4.11.1.1), whose peer is owed the report already
    /// framed in the eviction buffer.
    pub evicted: Option<Evicted>,
}

impl ChannelReply {
    const SILENT: Self = Self {
        reply: None,
        established: None,
        evicted: None,
    };

    const fn answer(opcode: u8, len: usize) -> Self {
        Self {
            reply: Some((opcode, len)),
            established: None,
            evicted: None,
        }
    }
}

/// The secure channel of one node: §5.5's admission rules, PASE, CASE, and session installation.
///
/// One at a time by construction — §5.5's first rule is that a node runs one handshake at a
/// time, so there is one slot for each kind and the type cannot represent two.
#[derive(Debug)]
pub struct Channel {
    admission: PaseAdmission,
    pase: Option<PaseResponder>,
    pase_local: SessionId,
    case: Option<CaseResponder>,
    case_local: SessionId,
    case_fabric: FabricIndex,
    challenge: Option<SymmetricKey>,
}

impl Default for Channel {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    /// A channel with nothing in flight.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            admission: PaseAdmission::new(),
            pase: None,
            pase_local: SessionId(0),
            case: None,
            case_local: SessionId(0),
            case_fabric: FabricIndex::NONE,
            challenge: None,
        }
    }

    /// §6.2.3's attestation challenge from the PASE session in progress or just established.
    #[must_use]
    pub fn attestation_challenge(&self) -> Option<&SymmetricKey> {
        self.challenge.as_ref()
    }

    /// Whether §5.5's channel is currently held by an established PASE session.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.admission.is_established()
    }

    /// Re-admits PASE, which is what *opening* a commissioning window means (§5.5).
    ///
    /// A node commissioned once is not admitting anybody: the channel stays shut from the moment
    /// PASE succeeded until something says otherwise. Without this a node can never be
    /// commissioned twice — `OpenCommissioningWindow` succeeds, the node advertises, and every
    /// `PBKDFParamRequest` comes back `Busy`.
    pub const fn reopen(&mut self) {
        self.admission.reset();
    }

    /// Releases the channel when the PASE session on it closes (§5.5).
    ///
    /// "until session establishment fails or the successfully established PASE session is
    /// terminated on the commissioning channel" — and a commissioner is under no obligation to
    /// say so politely, which is why [`Received::SessionClosed`](crate::messaging::Received)
    /// and a closed commissioning window both end up here.
    pub fn closed(&mut self, session: SessionId) {
        if session == self.pase_local {
            self.admission.closed();
            self.pase = None;
            self.challenge = None;
        }
    }

    /// Releases the channel without naming a session.
    ///
    /// §5.5 releases it when "the successfully established PASE session is terminated on the
    /// commissioning channel" — and a commissioner is under no obligation to terminate it
    /// politely. The CHIP controller calls `StopPairing`, evicts its own session, says nothing,
    /// and opens a fresh PASE five seconds later; a node holding the channel answers `Busy` for
    /// ever, which looks exactly like a device ignoring its own open commissioning window.
    ///
    /// So a device that can see commissioning has finished — an open window with a disarmed
    /// fail-safe is the honest reading — says so here. [`Channel::closed`] is the tidier path
    /// and applies when the session id is known.
    pub fn release(&mut self) {
        self.admission.closed();
        self.pase = None;
    }

    /// When §5.5's sixty seconds runs out on the handshake in flight, if one is.
    ///
    /// A deadline like any other, so it goes where the loop's other deadlines go rather than
    /// into a special case: `None` means nothing is waiting.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.admission.deadline()
    }

    /// Drives the deadlines §5.5 puts on a handshake in flight.
    ///
    /// Call it from the run loop. A handshake that was abandoned holds the channel until it is
    /// reaped, and one unanswered request would otherwise lock a device out of commissioning for
    /// good.
    pub fn poll(&mut self, now: Instant, window: &RefCell<CommissioningWindow>) {
        if let Some(failure) = self.admission.poll(now) {
            self.pase = None;
            if failure.exit_commissioning_mode {
                window.borrow_mut().close();
            }
        }
    }

    /// Answers one Secure Channel message (§4.11's opcodes).
    ///
    /// `reply` is where the answer is written. `frame` and `evict` are the two buffers
    /// [`Messaging::install_session`] needs when a session has to be evicted to make room —
    /// §4.11.1.1's report is framed under the evicted session's own keys, so it has to be built
    /// before that session goes away, and the caller sends it afterwards.
    ///
    /// An opcode this channel does not serve comes back with no reply at all, rather than an
    /// error: a message for a handshake that is not running tells a stranger nothing about the
    /// node, and a node that answered would say which handshake it is in the middle of.
    pub fn on_message<C, const S: usize, const X: usize, const N: usize, K, R>(
        &mut self,
        stack: &mut Messaging<C, S, X>,
        opcode: u8,
        body: &[u8],
        ctx: &ChannelContext<'_, C, N, K, R>,
        buffers: &mut ChannelBuffers<'_>,
    ) -> Result<ChannelReply>
    where
        C: Config,
        K: KeyStore,
        R: Rng,
    {
        match opcode {
            opcode::PBKDF_PARAM_REQUEST => self.pbkdf_param_request(body, ctx, buffers.reply),
            opcode::PAKE1 => self.pake1(body, ctx, buffers.reply),
            opcode::PAKE3 => self.pake3(stack, body, ctx, buffers),
            opcode::SIGMA1 => self.sigma1(body, ctx, buffers.reply),
            opcode::SIGMA3 => self.sigma3(stack, body, ctx, buffers),
            _ => Ok(ChannelReply::SILENT),
        }
    }

    /// §5.5's gate, then §4.14.1's first message.
    fn pbkdf_param_request<C, const N: usize, K, R>(
        &mut self,
        body: &[u8],
        ctx: &ChannelContext<'_, C, N, K, R>,
        reply: &mut [u8],
    ) -> Result<ChannelReply>
    where
        C: Config,
        K: KeyStore,
        R: Rng,
    {
        match self.admission.admit(true, ctx.now) {
            Admit::Admitted => {}
            refusal => {
                // §4.11.1.3's codes: `Busy` says "not now", which is true while another
                // commissioner holds the channel. The rest will not change until the device is
                // put back into commissioning mode.
                let code = if matches!(refusal, Admit::Busy) {
                    SecureChannelCode::Busy
                } else {
                    SecureChannelCode::InvalidParameter
                };
                let len = StatusReport::secure_channel(code).encode(reply)?;
                return Ok(ChannelReply::answer(opcode::STATUS_REPORT, len));
            }
        }

        // §11.19.8.1: an Enhanced window runs PASE against the verifier the *administrator*
        // supplied, with that command's salt and iteration count. A Basic window carries no
        // verifier and falls back to the factory one, which is what makes it Basic.
        let ephemeral = ctx.window.borrow().ephemeral(ctx.now).and_then(|e| {
            let verifier = Spake2pVerifierData::from_bytes(&e.verifier).ok()?;
            let parameters = PbkdfParameters::new(e.iterations, &e.salt).ok()?;
            Some((verifier, parameters))
        });
        let (verifier, parameters) = match ephemeral {
            Some(pair) => pair,
            None => (*ctx.verifier, ctx.parameters.clone()),
        };

        let mut responder = PaseResponder::new(
            ResponderConfig {
                verifier,
                parameters,
                session_params: Some(SessionParams::default()),
            },
            // A session id nothing else is using, with the low bit set so it is never zero —
            // §4.13.2.4 reserves that for the unsecured session.
            SessionId(ctx.rng.next_u32()? as u16 | 1),
        );
        let mut random = [0u8; 32];
        ctx.rng.fill(&mut random)?;
        match responder.on_pbkdf_param_request(body, &random, reply) {
            Ok(len) => {
                self.pase_local = responder.local_session_id();
                self.pase = Some(responder);
                Ok(ChannelReply::answer(opcode::PBKDF_PARAM_RESPONSE, len))
            }
            // A request this node could not parse is a failed attempt like any other: it frees
            // the channel, and it counts towards the twenty.
            Err(e) => {
                self.fail(ctx.window);
                Err(e)
            }
        }
    }

    fn pake1<C, const N: usize, K, R>(
        &mut self,
        body: &[u8],
        ctx: &ChannelContext<'_, C, N, K, R>,
        reply: &mut [u8],
    ) -> Result<ChannelReply>
    where
        C: Config,
        K: KeyStore,
        R: Rng,
    {
        let Some(pase) = self.pase.as_mut() else {
            return Ok(ChannelReply::SILENT);
        };
        let mut random = [0u8; 32];
        ctx.rng.fill(&mut random)?;
        match pase.on_pake1(body, &random, reply) {
            Ok(len) => Ok(ChannelReply::answer(opcode::PAKE2, len)),
            Err(e) => {
                self.fail(ctx.window);
                Err(e)
            }
        }
    }

    /// The last PASE message, and the session it produces.
    fn pake3<C, const S: usize, const X: usize, const N: usize, K, R>(
        &mut self,
        stack: &mut Messaging<C, S, X>,
        body: &[u8],
        ctx: &ChannelContext<'_, C, N, K, R>,
        buffers: &mut ChannelBuffers<'_>,
    ) -> Result<ChannelReply>
    where
        C: Config,
        K: KeyStore,
        R: Rng,
    {
        let Some(pase) = self.pase.as_mut() else {
            return Ok(ChannelReply::SILENT);
        };
        let (len, keys) = match pase.on_pake3(body, buffers.reply) {
            Ok(pair) => pair,
            Err(e) => {
                self.fail(ctx.window);
                return Err(e);
            }
        };
        let challenge = keys.attestation_challenge.clone();
        let session = SecureSession::new(
            self.pase_local,
            pase.peer_session_id(),
            SessionKind::Pase,
            Role::Responder,
            keys,
            ctx.rng.next_u32()?,
            ctx.now,
        );
        let evicted = match stack.install_session(
            session,
            ctx.now,
            ctx.rng.next_u32()?,
            buffers.frame,
            buffers.evict,
        ) {
            Ok(evicted) => evicted,
            Err(e) => {
                self.fail(ctx.window);
                return Err(e);
            }
        };
        self.challenge = Some(challenge.clone());
        // §5.5 rule 1 holds "or has successfully established a session": the channel stays shut
        // until that session is closed.
        self.admission.established();
        Ok(ChannelReply {
            reply: Some((opcode::STATUS_REPORT, len)),
            established: Some(Established {
                session: self.pase_local,
                kind: SessionKind::Pase,
                fabric: FabricIndex::NONE,
                challenge: Some(challenge),
            }),
            evicted,
        })
    }

    /// §4.14.2.3's Sigma1, answered against the fabric its destination identifier names.
    fn sigma1<C, const N: usize, K, R>(
        &mut self,
        body: &[u8],
        ctx: &ChannelContext<'_, C, N, K, R>,
        reply: &mut [u8],
    ) -> Result<ChannelReply>
    where
        C: Config,
        K: KeyStore,
        R: Rng,
    {
        let local = SessionId(ctx.rng.next_u32()? as u16 | 1);
        let mut responder_random = [0u8; 32];
        let mut ephemeral = [0u8; 32];
        let mut resumption = [0u8; 16];
        ctx.rng.fill(&mut responder_random)?;
        ctx.rng.fill(&mut ephemeral)?;
        ctx.rng.fill(&mut resumption)?;

        let accepted = Sigma1::decode(body).and_then(|sigma1| {
            super::case::accept_sigma1(
                &sigma1,
                &ctx.fabrics.borrow(),
                &mut *ctx.keys.borrow_mut(),
                local,
                Some(SessionParams::default()),
                &super::case::Sigma2Randomness {
                    ephemeral: &ephemeral,
                    responder: &responder_random,
                    resumption: &resumption,
                },
                reply,
            )
        });
        match accepted {
            Ok((responder, fabric, len)) => {
                self.case_local = local;
                self.case_fabric = fabric;
                self.case = Some(responder);
                Ok(ChannelReply::answer(opcode::SIGMA2, len))
            }
            // §4.11.1.3: no fabric matched, which is the ordinary answer to a Sigma1 meant for
            // another node on the link. The initiator is told so rather than left waiting.
            Err(_) => {
                self.case = None;
                let len = StatusReport::secure_channel(SecureChannelCode::NoSharedTrustRoots)
                    .encode(reply)?;
                Ok(ChannelReply::answer(opcode::STATUS_REPORT, len))
            }
        }
    }

    /// Sigma3, validated against the root of the fabric Sigma1 resolved.
    fn sigma3<C, const S: usize, const X: usize, const N: usize, K, R>(
        &mut self,
        stack: &mut Messaging<C, S, X>,
        body: &[u8],
        ctx: &ChannelContext<'_, C, N, K, R>,
        buffers: &mut ChannelBuffers<'_>,
    ) -> Result<ChannelReply>
    where
        C: Config,
        K: KeyStore,
        R: Rng,
    {
        let Some(responder) = self.case.as_mut() else {
            return Ok(ChannelReply::SILENT);
        };
        let accepted = Sigma3::decode(body).and_then(|sigma3| {
            responder.accept_sigma3(
                &sigma3,
                &ctx.fabrics.borrow(),
                self.case_fabric,
                None,
                buffers.reply,
            )
        });
        let (outcome, len) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                self.case = None;
                return Err(e);
            }
        };

        // Every identity the session needs comes from the outcome and the fabric, so it is built
        // from both rather than field by field. `local_node_id` is the one that cannot be
        // left out: §4.9.2's nonce carries the sender's operational node id, which is never in
        // the header, so a session without it encrypts everything unreadably.
        let fabric = ctx
            .fabrics
            .borrow()
            .iter()
            .find(|f| f.fabric_id == outcome.peer.fabric_id)
            .cloned();
        let Some(fabric) = fabric else {
            self.case = None;
            return Ok(ChannelReply::answer(opcode::STATUS_REPORT, len));
        };
        let index = fabric.index;
        let session = outcome.into_session(self.case_local, &fabric, ctx.rng.next_u32()?, ctx.now);
        let evicted = stack.install_session(
            session,
            ctx.now,
            ctx.rng.next_u32()?,
            buffers.frame,
            buffers.evict,
        )?;
        self.case = None;
        Ok(ChannelReply {
            reply: Some((opcode::STATUS_REPORT, len)),
            established: Some(Established {
                session: self.case_local,
                kind: SessionKind::Case,
                fabric: index,
                challenge: None,
            }),
            evicted,
        })
    }

    /// §5.5's failure path: the attempt frees the channel, counts towards the twenty, and closes
    /// the window when it reaches them.
    fn fail(&mut self, window: &RefCell<CommissioningWindow>) {
        self.pase = None;
        if self.admission.failed().exit_commissioning_mode {
            window.borrow_mut().close();
        }
    }
}
