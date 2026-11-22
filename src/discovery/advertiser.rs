//! The DNS-SD records a node publishes, computed from its state (§4.3.1, §4.3.2, §11.19.7).
//!
//! Which records a node answers with is a function of three facts — whether it is on any
//! fabric, which fabrics, and whether a commissioning window is open — and each of the three
//! has been got wrong by assembling the set by hand:
//!
//! - **One operational record per fabric.** §4.3.2 names each instance from that fabric's
//!   compressed id and the node id it issued, so a node on three fabrics publishes three.
//!   Advertising only the first leaves every later fabric unable to resolve the node: `AddNOC`
//!   succeeds, and operational discovery then finds nothing.
//! - **Commissionable only when it should be.** A node with no fabric is commissionable; a
//!   commissioned one is not, unless a window is open — and then §11.19.7 has it advertise
//!   *both*, because the operational record is how its existing fabrics reach it and the
//!   commissionable one is the only way a new administrator can.
//! - **The window's discriminator, not the factory one.** §11.19.8.1: the `Discriminator` of
//!   `OpenCommissioningWindow` is "used by the Node as the long discriminator for DNS-SD
//!   advertisement", and the window's mode decides `CM`.
//!
//! [`Advertiser`] owns the strings an [`Advertisement`] borrows and rebuilds them on
//! [`Advertiser::refresh`], so a responder answers from a slice that is always the current
//! set — and so the set needs no allocation.
//!
//! The commissionable instance name is drawn from the node's [`Rng`] (§4.3.1.1: "a dynamic,
//! pseudo-randomly selected, 64-bit temporary unique identifier"), never a constant: two nodes
//! advertising one name on one link make one of them unreachable.

use heapless::{String, Vec};

use super::{
    COMMISSIONABLE_SERVICE, COMMISSIONING_MODE_SUBTYPE, CommissionableTxt, CommissioningMode,
    HOST_NAME_MAX, INSTANCE_NAME_LEN, INSTANCE_NAME_MAX, OPERATIONAL_SERVICE, OperationalTxt,
    SUBTYPE_MAX, TxtWriter, responder::Advertisement,
};
use crate::error::Result;
use crate::msg::VendorId;
use crate::platform::Rng;

/// What a node says about itself in every commissionable record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// §5.1.1.3's 12-bit discriminator printed on the label, used while no window overrides it.
    pub discriminator: u16,
    /// `VP`'s vendor id.
    pub vendor_id: VendorId,
    /// `VP`'s product id.
    pub product_id: u16,
    /// The UDP port Matter listens on — [`crate::PORT`] unless the platform says otherwise.
    pub port: u16,
}

/// Which window is open, as far as advertising cares: its discriminator and mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenWindow {
    /// The long discriminator to advertise.
    pub discriminator: u16,
    /// `Basic` or `Enhanced`.
    pub mode: CommissioningMode,
}

/// The commissionable record's own strings, rebuilt when the discriminator or mode changes.
#[derive(Debug)]
struct Commissionable {
    long: String<6>,
    short: String<4>,
    txt: TxtWriter,
}

/// The node's DNS-SD records, for `F` fabrics and up to `A` advertisements.
///
/// `A` must exceed `F` — every fabric's operational record plus one commissionable — which is
/// asserted when the advertiser is built. `Advertiser<5, 6>` fits [`DefaultConfig`].
///
/// [`DefaultConfig`]: crate::config::DefaultConfig
#[derive(Debug)]
pub struct Advertiser<const F: usize, const A: usize> {
    identity: Identity,
    host: String<HOST_NAME_MAX>,
    instance: String<INSTANCE_NAME_LEN>,
    address: Option<[u8; 16]>,
    operational: Vec<(String<INSTANCE_NAME_MAX>, String<SUBTYPE_MAX>), F>,
    operational_txt: TxtWriter,
    commissionable: Option<Commissionable>,
}

impl<const F: usize, const A: usize> Advertiser<F, A> {
    /// An advertiser with a fresh host name and commissionable instance name, both drawn from
    /// `rng`, advertising commissionable until [`Self::refresh`] says otherwise.
    ///
    /// # Errors
    ///
    /// The `rng` fails, or a TXT record does not fit — neither of which a well-formed
    /// [`Identity`] can cause.
    pub fn new(identity: Identity, rng: &impl Rng) -> Result<Self> {
        const {
            assert!(
                A > F,
                "one operational record per fabric and one commissionable"
            );
        }
        let mut advertiser = Self {
            identity,
            host: hex(rng.next_u64()?),
            instance: hex(rng.next_u64()?),
            address: None,
            operational: Vec::new(),
            operational_txt: OperationalTxt::default().encode()?,
            commissionable: None,
        };
        advertiser.refresh(core::iter::empty(), None)?;
        Ok(advertiser)
    }

    /// Puts an AAAA record for `address` in every advertisement (§4.3.1.3).
    ///
    /// A device reads its address from the interface it advertises on. Without one, a resolver
    /// gets an SRV naming a host it cannot reach, and the node looks absent.
    #[must_use]
    pub const fn with_address(mut self, address: [u8; 16]) -> Self {
        self.address = Some(address);
        self
    }

    /// Rebuilds the set from the node's current state.
    ///
    /// `operational` is each fabric's `(instance name, _I subtype)` — what
    /// [`Fabric::instance_name`] and [`CompressedFabricId::subtype`] return; `window` is the
    /// open commissioning window, if any. A node with no fabric is commissionable whether or
    /// not a window is open, with the factory discriminator unless a window says otherwise.
    ///
    /// Fabrics past `F` are not advertised; `F` is the fabric table's own capacity.
    ///
    /// # Errors
    ///
    /// A TXT record does not fit.
    ///
    /// [`Fabric::instance_name`]: crate::fabric::Fabric::instance_name
    /// [`CompressedFabricId::subtype`]: crate::fabric::CompressedFabricId::subtype
    pub fn refresh(
        &mut self,
        operational: impl IntoIterator<Item = (String<INSTANCE_NAME_MAX>, String<SUBTYPE_MAX>)>,
        window: Option<OpenWindow>,
    ) -> Result<()> {
        self.operational.clear();
        for entry in operational {
            if self.operational.push(entry).is_err() {
                break;
            }
        }
        let commissionable = match window {
            Some(window) => Some(window),
            None if self.operational.is_empty() => Some(OpenWindow {
                discriminator: self.identity.discriminator,
                mode: CommissioningMode::Basic,
            }),
            None => None,
        };
        self.commissionable = match commissionable {
            Some(window) => Some(self.commissionable_for(window)?),
            None => None,
        };
        Ok(())
    }

    fn commissionable_for(&self, window: OpenWindow) -> Result<Commissionable> {
        let txt = CommissionableTxt {
            discriminator: window.discriminator,
            vendor_id: Some(self.identity.vendor_id),
            product_id: Some(self.identity.product_id),
            commissioning_mode: window.mode,
            ..CommissionableTxt::default()
        }
        .encode()?;
        let mut long = String::new();
        let _ = core::fmt::Write::write_fmt(&mut long, format_args!("_L{}", window.discriminator));
        let mut short = String::new();
        let _ = core::fmt::Write::write_fmt(
            &mut short,
            format_args!("_S{}", window.discriminator >> 8),
        );
        Ok(Commissionable { long, short, txt })
    }

    /// The host name label, without the domain.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The commissionable instance name.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Whether the set currently includes a commissionable record.
    #[must_use]
    pub const fn is_commissionable(&self) -> bool {
        self.commissionable.is_some()
    }

    /// The records to answer from — operational first, then commissionable.
    #[must_use]
    pub fn advertisements(&self) -> Vec<Advertisement<'_>, A> {
        let mut out = Vec::new();
        for (instance, subtype) in &self.operational {
            let mut a = Advertisement::new(
                instance,
                OPERATIONAL_SERVICE,
                &self.host,
                self.identity.port,
                self.operational_txt.finish(),
            );
            // A fresh advertisement has room for every subtype and address this pushes.
            a.subtypes.push(subtype).ok();
            if let Some(address) = self.address {
                a.addresses.push(address).ok();
            }
            if out.push(a).is_err() {
                return out;
            }
        }
        if let Some(c) = &self.commissionable {
            let mut a = Advertisement::new(
                &self.instance,
                COMMISSIONABLE_SERVICE,
                &self.host,
                self.identity.port,
                c.txt.finish(),
            );
            a.subtypes.push(&c.long).ok();
            a.subtypes.push(&c.short).ok();
            a.subtypes.push(COMMISSIONING_MODE_SUBTYPE).ok();
            if let Some(address) = self.address {
                a.addresses.push(address).ok();
            }
            out.push(a).ok();
        }
        out
    }
}

/// Sixteen uppercase hex digits, as §4.3.1.1 spells an instance or host name.
fn hex(value: u64) -> String<16> {
    let mut out = String::new();
    let _ = core::fmt::Write::write_fmt(&mut out, format_args!("{value:016X}"));
    out
}
