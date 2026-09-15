//! The commissioning window: node state three clusters share (Core §11.19.7).
//!
//! §11.19 opens and revokes it, §11.10.7.2 gives a PASE commissioner priority over a CASE
//! administrator *while it is open*, and §11.10.7.6 step 2 closes it on
//! `CommissioningComplete`. A flag per cluster would be three answers to "is a window open",
//! and the priority rule is exactly where they would disagree — so it lives here, beside the
//! fail-safe, and the clusters borrow it.
//!
//! # The PAKE material is bytes, not a verifier
//!
//! [`EphemeralVerifier`] holds the ninety-seven octets and the PBKDF parameters, not a
//! decoded [`Spake2pVerifierData`](crate::crypto::Spake2pVerifierData). That is not laziness:
//! it keeps this module free of cryptography, so a `no_std` build without the `rustcrypto`
//! feature still has a window. The *validation* §11.19.8.1 requires happens in the cluster,
//! which has the cryptography — and having happened, `Spake2pVerifierData::from_bytes` on
//! these octets cannot fail.

use heapless::Vec;

use crate::msg::{FabricIndex, VendorId};
use crate::platform::Instant;

/// `CommissioningWindowStatusEnum` (§11.19.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum WindowStatus {
    /// `0` — no commissioning window is open.
    ///
    /// §11.19.7.1's note is worth keeping in mind: "An initial commissioning window is not
    /// opened using either the OpenCommissioningWindow command or the
    /// OpenBasicCommissioningWindow command, and therefore this attribute SHALL be set to
    /// WindowNotOpen on initial commissioning." A factory-new device reads zero here while
    /// being perfectly commissionable.
    #[default]
    NotOpen = 0,
    /// `1` — an Enhanced Commissioning Method window is open.
    EnhancedOpen = 1,
    /// `2` — a Basic Commissioning Method window is open. Requires the `BC` feature.
    BasicOpen = 2,
}

impl WindowStatus {
    /// The value the attribute carries.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Whether a window is open at all.
    #[must_use]
    pub const fn is_open(self) -> bool {
        !matches!(self, Self::NotOpen)
    }
}

/// §11.19.8.1's `PAKEPasscodeVerifier` length — `w0 || L`, exactly 97 octets.
pub const PAKE_VERIFIER_LEN: usize = 97;

/// §3.9's longest PBKDF salt.
pub const SALT_MAX: usize = 32;

/// An open commissioning window (§11.19.7).
#[derive(Debug, Clone)]
pub struct OpenWindow {
    /// Which method opened it.
    pub status: WindowStatus,
    /// When it closes. §11.19.8.1.1: the timeout "applies only to cessation of any
    /// announcements and to accepting of new commissioning sessions; it does not apply to
    /// abortion of connections".
    pub expires_at: Instant,
    /// `AdminFabricIndex` — "the FabricIndex associated with the Fabric scoping of the
    /// Administrator that opened the window".
    ///
    /// "If, during an open commissioning window, the fabric for the Administrator that opened
    /// the window is removed, then this attribute SHALL be set to null" — which is why it is
    /// an `Option` even while the window is open.
    pub admin_fabric: Option<FabricIndex>,
    /// `AdminVendorId`. Unlike the fabric index, this one is *not* cleared when the fabric
    /// goes: "If the fabric for the Administrator that opened the window is removed from the
    /// node while the commissioning window is still open, this attribute SHALL NOT be
    /// updated." A user looking at the device still learns who opened it.
    pub admin_vendor: Option<VendorId>,
    /// `Discriminator` — "used by the Node as the long discriminator for DNS-SD
    /// advertisement … for discovery by the new Administrator".
    pub discriminator: u16,
    /// The ephemeral PAKE verifier and its PBKDF parameters, for an Enhanced window.
    ///
    /// `None` for a Basic window, which runs against the device's own factory verifier.
    pub ephemeral: Option<EphemeralVerifier>,
}

/// The PAKE material an `OpenCommissioningWindow` installed.
///
/// "It SHALL be deleted by the Node at the end of commissioning or expiration of the
/// OpenCommissioningWindow command" — which is what [`CommissioningWindow::close`] does, and
/// why this is owned by the window rather than handed to the device.
///
/// Zeroized on drop: `(w0, L)` is not a passcode, but it is what a PASE session is
/// authenticated by for as long as the window lasts, and leaving it in freed memory would
/// outlive the window it belongs to.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct EphemeralVerifier {
    /// `(w0 || L)`, from the command's `PAKEPasscodeVerifier` field — already validated by
    /// the cluster that accepted it.
    pub verifier: [u8; PAKE_VERIFIER_LEN],
    /// The PAKE iteration count to answer a `PBKDFParamRequest` with.
    #[zeroize(skip)]
    pub iterations: u32,
    /// The PAKE salt to answer a `PBKDFParamRequest` with.
    #[zeroize(skip)]
    pub salt: Vec<u8, SALT_MAX>,
}

/// The node's commissioning window.
#[derive(Debug, Default)]
pub struct CommissioningWindow {
    open: Option<OpenWindow>,
}

impl CommissioningWindow {
    /// Installs a window. The cluster that calls this has already checked §11.19's
    /// preconditions; this is the state change they guard.
    pub fn install(&mut self, window: OpenWindow) {
        self.open = Some(window);
    }

    /// A closed window — what a device boots with.
    #[must_use]
    pub const fn new() -> Self {
        Self { open: None }
    }

    /// The window, if one is open as of `now`.
    ///
    /// Expiry is lazy, as everywhere else in this crate: a caller that never asks never learns,
    /// and a device drives it from [`CommissioningWindow::deadline`].
    #[must_use]
    pub fn open(&self, now: Instant) -> Option<&OpenWindow> {
        self.open.as_ref().filter(|window| now < window.expires_at)
    }

    /// `WindowStatus` (§11.19.7.1).
    ///
    /// "This attribute SHALL revert to WindowNotOpen upon expiry of a commissioning window."
    #[must_use]
    pub fn status(&self, now: Instant) -> WindowStatus {
        self.open(now).map_or(WindowStatus::NotOpen, |w| w.status)
    }

    /// When the window closes, if one is open.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.open.as_ref().map(|window| window.expires_at)
    }

    /// Closes the window and destroys the ephemeral verifier with it.
    ///
    /// §11.19.8.1: the verifier "SHALL be deleted by the Node at the end of commissioning or
    /// expiration of the OpenCommissioningWindow command". Dropping [`EphemeralVerifier`] is
    /// what does it — it is `ZeroizeOnDrop`, so the material is wiped rather than merely
    /// forgotten.
    pub fn close(&mut self) {
        self.open = None;
    }

    /// Clears `AdminFabricIndex` when the administrator's fabric is removed (§11.19.7.2).
    ///
    /// The vendor id stays: §11.19.7.3 is explicit that it "SHALL NOT be updated".
    pub fn forget_fabric(&mut self, fabric: FabricIndex) {
        if let Some(window) = self.open.as_mut()
            && window.admin_fabric == Some(fabric)
        {
            window.admin_fabric = None;
        }
    }

    /// The PAKE material a PASE responder should use for this window.
    ///
    /// `None` means "use the device's own factory verifier" — a Basic window, or no window at
    /// all. A device must still check [`CommissioningWindow::status`] before accepting a PASE
    /// session; this only says *which* verifier applies.
    #[must_use]
    pub fn ephemeral(&self, now: Instant) -> Option<&EphemeralVerifier> {
        self.open(now)?.ephemeral.as_ref()
    }
}
