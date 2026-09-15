//! Commissioner Control, cluster `0x0751` (Core §11.26) — Fabric Synchronization's front door.
//!
//! > The Commissioner Control Cluster supports the ability for clients to request the
//! > commissioning of themselves or other nodes onto a fabric which the cluster server can
//! > commission onto. An example use case is ecosystem to ecosystem Fabric Synchronization
//! > setup.
//!
//! Two ecosystems, and a householder who has a light in one and wants it in the other. The
//! usual answer is to commission the light twice, which means the light holds two fabrics and
//! the user does the work. Fabric Synchronization is the other answer: the ecosystems talk to
//! each other, and one asks the other to open a commissioning window on a node it already has.
//!
//! # Three commands and a deliberate pause between them
//!
//! §11.26.6 splits what could have been one command into two, and says why:
//!
//! > This is required to be a separate step in order to provide the server time for interacting
//! > with a user before informing the client that the CommissionNode operation may be
//! > successful.
//!
//! So `RequestCommissioningApproval` always answers `SUCCESS` — it is a *question*, not an
//! action — and the real answer arrives later as a `CommissioningRequestResult` event. Only
//! then does the client send `CommissionNode`, and the server answers by invoking
//! `ReverseOpenCommissioningWindow` back at it.
//!
//! The direction reversal is the point: the *server* of this cluster ends up as the
//! commissioner, and the client as the thing that opens a window. §11.26.6.8 is explicit that
//! the reverse command "is an alias onto the OpenCommissioningWindow command within the
//! Administrator Commissioning Cluster".
//!
//! # Both commands are CASE-only
//!
//! §11.26.6.1 and §11.26.6.5: "If the command is not executed via a CASE session, the command
//! SHALL fail with a status code of UNSUPPORTED_ACCESS." A request over PASE would come from
//! something that has not yet proved which fabric it is on — and the whole flow turns on the
//! server being able to match a later `CommissionNode` to the *same* node on the *same* fabric.

use core::cell::{Cell, RefCell};

use crate::clusters::generated::commissioner_control as spec_cctrl;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::msg::{FabricIndex, NodeId, VendorId};
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::Cluster;

pub use spec_cctrl::attribute::SUPPORTED_DEVICE_CATEGORIES;
pub use spec_cctrl::command::{
    COMMISSION_NODE, REQUEST_COMMISSIONING_APPROVAL, REVERSE_OPEN_COMMISSIONING_WINDOW,
};
pub use spec_cctrl::event::COMMISSIONING_REQUEST_RESULT;
pub use spec_cctrl::{ID, PICS, REVISION, SupportedDeviceCategoryBitmap};

/// §11.26.6.1's constraint on `Label`: "max 64".
pub const LABEL_MAX: usize = 64;

/// One outstanding approval request.
///
/// §11.26.6.5 makes the triple load-bearing: "The server SHALL return FAILURE if the
/// CommissionNode command is not sent from the same NodeID and on the same fabric as the
/// RequestCommissioningApproval or if the provided RequestID ... does not match."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// The client's own identifier for this request.
    pub request_id: u64,
    /// Which node asked.
    pub client_node_id: NodeId,
    /// On which fabric.
    pub fabric: FabricIndex,
    /// The vendor of the device the client wants commissioned — matched against the Basic
    /// Information of whatever turns up (§11.26.6.8).
    pub vendor_id: VendorId,
    /// Its product id.
    pub product_id: u16,
    /// Whether the server has decided yet.
    pub approved: Option<bool>,
}

/// What the server tells the client when its decision is ready (§11.26.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// "the server is ready to begin commissioning the requested device".
    Approved,
    /// "the server timed out due to user inaction".
    TimedOut,
    /// Anything else.
    Refused,
}

impl Decision {
    /// The `StatusCode` §11.26.7.3 puts in the event.
    #[must_use]
    pub const fn status(self) -> Status {
        match self {
            Self::Approved => Status::Success,
            Self::TimedOut => Status::Timeout,
            Self::Refused => Status::Failure,
        }
    }
}

/// An event this cluster produced, for the device to record in its own store (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommissioningRequestResult {
    /// Matches the `RequestID` the client sent.
    pub request_id: u64,
    /// The node that sent it.
    pub client_node_id: NodeId,
    /// What the server decided.
    pub decision: Decision,
}

/// What the window a `ReverseOpenCommissioningWindow` asks the client to open (§11.26.6.8).
///
/// Every field is `OpenCommissioningWindow`'s — §11.26.6.8 says so: "This is an alias onto the
/// OpenCommissioningWindow command within the Administrator Commissioning Cluster."
#[derive(Debug, Clone, Copy)]
pub struct Window<'a> {
    /// How long the window stays open, in seconds.
    pub commissioning_timeout: u16,
    /// §11.19.8.1's 97-octet PAKE verifier.
    pub pake_passcode_verifier: &'a [u8],
    /// The 12-bit discriminator (§5.1.1.3).
    pub discriminator: u16,
    /// PBKDF iterations, 1000 to 100000.
    pub iterations: u32,
    /// The salt, 16 to 32 octets.
    pub salt: &'a [u8],
}

/// §11.19.8.1's constraint on `PAKEPasscodeVerifier`: exactly 97 octets.
pub const VERIFIER_LEN: usize = 97;

/// What the product decides about a request.
pub trait CommissionerControlHooks {
    /// §11.26.6.1: a client would like a device commissioned.
    ///
    /// > The server MAY request approval from the user, but it is not required.
    ///
    /// Whatever this returns, the *command* answers `SUCCESS` — §11.26.6.1 requires it. The
    /// decision reaches the client as a `CommissioningRequestResult` event, which is exactly
    /// the separation the two-step flow exists for: asking a person takes longer than a
    /// command may.
    fn requested(&self, request: &Request);

    /// §11.26.6.5: the client is ready, so open a window on the node it named.
    ///
    /// The server is about to become the *commissioner*; this returns the window parameters it
    /// wants the client to open. `None` refuses.
    fn window(&self, request: &Request) -> Option<Window<'_>>;
}

/// Commissioner Control over a node that can commission others.
#[derive(Debug)]
pub struct CommissionerControl<'a, H: CommissionerControlHooks, const N: usize = 4> {
    hooks: &'a H,
    categories: SupportedDeviceCategoryBitmap,
    pending: RefCell<heapless::Vec<Request, N>>,
    events: RefCell<heapless::Vec<CommissioningRequestResult, N>>,
    /// The window the last `CommissionNode` produced, for the caller to send.
    reverse: Cell<bool>,
}

impl<'a, H: CommissionerControlHooks, const N: usize> CommissionerControl<'a, H, N> {
    /// A cluster over `hooks`, advertising `categories`.
    #[must_use]
    pub fn new(hooks: &'a H, categories: SupportedDeviceCategoryBitmap) -> Self {
        Self {
            hooks,
            categories,
            pending: RefCell::new(heapless::Vec::new()),
            events: RefCell::new(heapless::Vec::new()),
            reverse: Cell::new(false),
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<1, 2, 1, 1>> {
        Conforming::new(&spec_cctrl::CLUSTER, feature_map, optional)
    }

    /// `SupportedDeviceCategories` (§11.26.5.1).
    #[must_use]
    pub const fn categories(&self) -> SupportedDeviceCategoryBitmap {
        self.categories
    }

    /// The requests this server has not yet answered.
    #[must_use]
    pub fn pending(&self) -> core::cell::Ref<'_, heapless::Vec<Request, N>> {
        self.pending.borrow()
    }

    /// Records the server's decision about a request, producing §11.26.7.1's event.
    ///
    /// Separate from the command because the decision may take a person: §11.26.6.1 is explicit
    /// that the two-step flow exists "to provide the server time for interacting with a user".
    pub fn decide(&self, request_id: u64, client: NodeId, decision: Decision) -> bool {
        let mut pending = self.pending.borrow_mut();
        let Some(request) = pending
            .iter_mut()
            .find(|r| r.request_id == request_id && r.client_node_id == client)
        else {
            return false;
        };
        request.approved = Some(decision == Decision::Approved);
        drop(pending);
        let mut events = self.events.borrow_mut();
        if events.is_full() {
            events.remove(0);
        }
        let _ = events.push(CommissioningRequestResult {
            request_id,
            client_node_id: client,
            decision,
        });
        true
    }

    /// Takes the event records the cluster has produced.
    pub fn take_events(&self) -> heapless::Vec<CommissioningRequestResult, N> {
        core::mem::take(&mut self.events.borrow_mut())
    }

    /// Whether the last `CommissionNode` asked the caller to send a
    /// `ReverseOpenCommissioningWindow` back to the client.
    ///
    /// §11.26.6's command table marks that one `server ⇒ client`: it is not a *response*, it is
    /// a command the server invokes on the client over the same CASE session. So the interaction
    /// model's response machinery cannot carry it, and the caller sends it — which is also why
    /// it is the one command here this cluster does not answer with itself.
    #[must_use]
    pub fn reverse_pending(&self) -> bool {
        self.reverse.replace(false)
    }

    /// Forgets a request — after the reverse window has been sent, or the approval has lapsed.
    pub fn forget(&self, request_id: u64, client: NodeId) {
        self.pending
            .borrow_mut()
            .retain(|r| !(r.request_id == request_id && r.client_node_id == client));
    }
}

impl<H: CommissionerControlHooks, const N: usize> ClusterHandler for CommissionerControl<'_, H, N> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        if resolved.attribute != SUPPORTED_DEVICE_CATEGORIES {
            return Err(Status::UnsupportedAttribute);
        }
        w.unsigned(tag, u64::from(self.categories.bits()))
            .map_err(|_| Status::ResourceExhausted)
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let payload = || fields.ok_or(StatusIb::from(Status::InvalidCommand));
        // §11.26.6.1 and §11.26.6.5: "If the command is not executed via a CASE session, the
        // command SHALL fail with a status code of UNSUPPORTED_ACCESS." A request over PASE
        // comes from something that has not proved which fabric it is on, and the whole flow
        // turns on matching a later `CommissionNode` to the same node on the same fabric.
        let (Some(fabric), Some(client)) = (ctx.fabric_index, ctx.peer_node_id) else {
            return Err(Status::UnsupportedAccess.into());
        };
        match resolved.command.id {
            REQUEST_COMMISSIONING_APPROVAL => {
                let decoded: spec_cctrl::RequestCommissioningApprovalFields<'_> =
                    super::decode_fields(payload()?)?;
                if decoded.label.is_some_and(|label| label.len() > LABEL_MAX) {
                    return Err(Status::ConstraintError.into());
                }
                let mut pending = self.pending.borrow_mut();
                // §11.26.6.1: "If the RequestID and client NodeID ... match a previously
                // received RequestCommissioningApproval and the server has not returned an
                // error or completed commissioning ... then the server SHOULD return FAILURE."
                // Two live requests with one id would make the later `CommissionNode` ambiguous.
                if pending
                    .iter()
                    .any(|r| r.request_id == decoded.request_id && r.client_node_id == client)
                {
                    return Err(Status::Failure.into());
                }
                let request = Request {
                    request_id: decoded.request_id,
                    client_node_id: client,
                    fabric,
                    vendor_id: decoded.vendor_id,
                    product_id: decoded.product_id,
                    approved: None,
                };
                pending
                    .push(request)
                    .map_err(|_| StatusIb::from(Status::ResourceExhausted))?;
                drop(pending);
                self.hooks.requested(&request);
                // §11.26.6.1: "The server SHALL always return SUCCESS to a correctly formatted
                // RequestCommissioningApproval command, and then generate a
                // CommissioningRequestResult event ... once the result is ready." The command
                // is a question; the answer is an event.
                Ok(None)
            }
            COMMISSION_NODE => {
                let decoded: spec_cctrl::CommissionNodeFields = super::decode_fields(payload()?)?;
                let pending = self.pending.borrow();
                // §11.26.6.5's three-way match: same RequestID, same NodeID, same fabric.
                let Some(request) = pending.iter().copied().find(|r| {
                    r.request_id == decoded.request_id
                        && r.client_node_id == client
                        && r.fabric == fabric
                }) else {
                    return Err(Status::Failure.into());
                };
                drop(pending);
                // A request nobody has approved is not one to act on — §11.26.7.1's event is
                // what says it is ready, and a client that jumped the gun is asking the server
                // to commission something it has not agreed to.
                if request.approved != Some(true) {
                    return Err(Status::Failure.into());
                }
                let Some(window) = self.hooks.window(&request) else {
                    return Err(Status::Failure.into());
                };
                // §11.19.8.1's constraints, which §11.26.6.8 inherits wholesale.
                if window.pake_passcode_verifier.len() != VERIFIER_LEN
                    || window.discriminator > 0x0FFF
                    || !(1_000..=100_000).contains(&window.iterations)
                    || !(16..=32).contains(&window.salt.len())
                {
                    return Err(Status::Failure.into());
                }
                let _ = decoded.response_timeout_seconds;
                self.reverse.set(true);
                spec_cctrl::ReverseOpenCommissioningWindowFields {
                    commissioning_timeout: window.commissioning_timeout,
                    pake_passcode_verifier: window.pake_passcode_verifier,
                    discriminator: window.discriminator,
                    iterations: window.iterations,
                    salt: window.salt,
                }
                .to_tlv(w, tag)
                .map_err(|_| StatusIb::from(Status::Failure))?;
                Ok(Some(REVERSE_OPEN_COMMISSIONING_WINDOW))
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: CommissionerControlHooks, const N: usize> Cluster for CommissionerControl<'_, H, N> {
    const ID: ClusterId = ID;
}
