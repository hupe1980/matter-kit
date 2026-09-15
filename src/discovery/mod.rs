//! Service advertising and discovery (Core §4.3) — how a Matter node is found.
//!
//! > Service Advertising and Discovery for Matter uses IETF Standard DNS-Based Service
//! > Discovery (DNS-SD) [RFC 6763]. **Matter requires no modifications to IETF Standard
//! > DNS-SD.**
//!
//! That sentence is the shape of this module: everything here is ordinary DNS-SD, and what
//! Matter adds is a naming convention and a set of TXT keys.
//!
//! | Context | Service type | Instance name |
//! |---|---|---|
//! | Commissionable Node (§4.3.1) | `_matterc._udp` | a random 64-bit value, 16 hex digits |
//! | Operational (§4.3.2) | `_matter._tcp` | `<compressed-fabric>-<node-id>` |
//! | Commissioner (§4.3.3) | `_matterd._udp` | vendor's choice |
//!
//! `_matter._tcp` is not a mistake: "the string `_tcp` is boilerplate text inherited from the
//! original DNS SRV specification … and doesn't necessarily mean that the advertised
//! application-layer protocol runs only over TCP" (§4.3.2.3). Matter's operational transport
//! is UDP with MRP.
//!
//! # Why the instance name is random, and why it changes
//!
//! §4.3.1: "the DNS-SD instance name SHALL be a dynamic, pseudo-randomly selected, 64-bit
//! temporary unique identifier … A new instance name SHALL be selected when the Node boots. A
//! new instance name SHALL be selected whenever the Node enters Commissioning mode."
//!
//! A stable name would be a tracking identifier — a device advertising the same sixteen hex
//! digits on every network it ever joins. The rule that it "SHALL NOT change while the Node is
//! in commissioning mode" is the other half: a commissioner that found the device must still
//! be able to reach it.
//!
//! # What is here and what is not
//!
//! The record model, the TXT keys, the DNS wire format, a responder that turns a query into a
//! response, and the *schedule* that says when anything may be sent at all — RFC 6762 §8's
//! probing and announcing, §9's conflict resolution and §6's rate limits, in [`schedule`].
//! [`responder`] decides what a message says; [`schedule`] decides when. Neither owns a socket
//! or a clock: the caller polls, sends, and sleeps until [`Schedule::wake_at`].
//!
//! What is not here: the `std` OS backends (Avahi, systemd-resolved, `dns-sd`) and the SRP
//! client Thread requires — platform code rather than protocol.
//!
//! ```
//! use matter_kit::discovery::{
//!     self, CommissionableSubtypes, COMMISSIONABLE_SERVICE,
//! };
//! use matter_kit::discovery::responder::{Advertisement, Responder};
//! use matter_kit::discovery::txt::{CommissionableTxt, CommissioningMode};
//! use matter_kit::msg::VendorId;
//!
//! // §4.3.1.14's own example: discriminator 840, in commissioning mode after an
//! // OpenCommissioningWindow.
//! let txt = CommissionableTxt {
//!     discriminator: 840,
//!     commissioning_mode: CommissioningMode::Enhanced,
//!     ..CommissionableTxt::default()
//! }
//! .encode()?;
//!
//! // The instance name is random and changes whenever the node enters commissioning mode;
//! // the host name comes from a link-layer address.
//! let instance = discovery::commissionable_instance_name(0xDD20_0C20_D25A_E5F7);
//! let host = discovery::host_name(&[0xB7, 0x5A, 0xFB, 0x45, 0x8E, 0xCD])?;
//! assert_eq!(instance.as_str(), "DD200C20D25AE5F7");
//!
//! // `_CM` is derived from the same commissioning mode the TXT key is, so the two cannot
//! // disagree — §4.3.1.3 forbids publishing it when `CM=0`.
//! let subtypes = CommissionableSubtypes::new(840, CommissioningMode::Enhanced);
//! let mut advertisement =
//!     Advertisement::new(&instance, COMMISSIONABLE_SERVICE, &host, 11111, txt.finish());
//! for subtype in subtypes.labels() {
//!     advertisement = advertisement.with_subtype(subtype)?;
//! }
//! advertisement = advertisement.with_address([
//!     0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0xF5, 0x15, 0x57, 0x6F, 0x97, 0x83, 0x3F, 0x30,
//! ])?;
//!
//! let advertisements = [advertisement];
//! let responder = Responder::new(&advertisements);
//! let mut buf = [0u8; 1024];
//! let announcement = responder.announce(&mut buf)?;
//! assert!(!announcement.is_empty());
//! # Ok::<(), matter_kit::Error>(())
//! ```

pub mod dns;
pub mod responder;
pub mod schedule;
pub mod txt;

pub use dns::{Name, ReadData, ReadRecord, RecordType, ResourceRecords};
pub use responder::{Advertisement, Responder};
pub use schedule::{Action, Phase, Schedule};
pub use txt::{CommissionableTxt, CommissioningMode, MrpAdvertisement, OperationalTxt, TxtWriter};

use heapless::String;

use crate::error::{Error, ErrorCode, Result};

/// `_matterc._udp` — Commissionable Node Discovery (§4.3.1).
pub const COMMISSIONABLE_SERVICE: [&str; 2] = ["_matterc", "_udp"];

/// `_matter._tcp` — Operational Discovery (§4.3.2.3).
pub const OPERATIONAL_SERVICE: [&str; 2] = ["_matter", "_tcp"];

/// `_matterd._udp` — Commissioner Discovery (§4.3.3).
pub const COMMISSIONER_SERVICE: [&str; 2] = ["_matterd", "_udp"];

/// `local` — "For link-local Multicast DNS the service domain SHALL be local" (§4.3.1).
pub const LOCAL_DOMAIN: &str = "local";

/// `_sub` — RFC 6763 §7.1's subtype label.
pub const SUBTYPE_LABEL: &str = "_sub";

/// The port Multicast DNS runs on (RFC 6762 §5).
pub const MDNS_PORT: u16 = 5353;

/// `ff02::fb` — RFC 6762's link-local IPv6 multicast group.
///
/// IPv6 only: §4.3 asks that "announcements and answers for this service need only be
/// performed over IPv6", and "A Matter device that only supports IPv6 gets these
/// optimizations automatically, simply by virtue of not supporting IPv4 at all."
pub const MDNS_IPV6_GROUP: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB];

/// RFC 6762 §10's TTL for records that contain a host name — A, AAAA, SRV.
///
/// Two minutes, "so that stale data is quickly purged" when a device moves or its address
/// changes.
pub const HOST_RECORD_TTL: u32 = 120;

/// RFC 6762 §10's TTL for everything else — PTR, TXT.
///
/// Seventy-five minutes. These records do not go stale when an address changes, and a longer
/// TTL is what keeps a quiet network quiet.
pub const OTHER_RECORD_TTL: u32 = 4500;

/// The length of the hexadecimal instance name §4.3.1 and §4.3.2.1 both use.
///
/// Sixteen characters for commissionable discovery's 64-bit random value; thirty-three for
/// operational discovery's `<16>-<16>`.
pub const INSTANCE_NAME_LEN: usize = 16;

/// The longest instance name: operational discovery's `<compressed>-<node>`.
pub const INSTANCE_NAME_MAX: usize = 33;

/// The longest host name: §4.3.1.1's sixteen-character form, for a 64-bit MAC Extended
/// Address.
pub const HOST_NAME_MAX: usize = 16;

/// A commissionable node's instance name — §4.3.1's "dynamic, pseudo-randomly selected,
/// 64-bit temporary unique identifier, expressed as a fixed-length sixteen-character
/// hexadecimal string, encoded as ASCII (UTF-8) text using **capital letters**".
///
/// The randomness is a parameter rather than something this crate draws, for the same reason
/// every other source of entropy is: it comes from the one [`Rng`](crate::platform::Rng) the
/// integrator installed.
#[must_use]
pub fn commissionable_instance_name(random: u64) -> String<INSTANCE_NAME_LEN> {
    let mut out = String::new();
    push_hex(&mut out, &random.to_be_bytes());
    out
}

/// A node's host name — §4.3.1.1's "fixed-length twelve-character (or sixteen-character)
/// hexadecimal string" built from a link-layer address.
///
/// > In the event that a device performs MAC address randomization for privacy, then the
/// > target host name SHALL use the privacy-preserving randomized version and the hostname
/// > SHALL be updated in the record every time the underlying link-layer address rotates.
///
/// Accepts a 6-octet MAC (Ethernet, Wi-Fi) or an 8-octet MAC Extended Address (Thread).
pub fn host_name(link_layer_address: &[u8]) -> Result<String<HOST_NAME_MAX>> {
    if !matches!(link_layer_address.len(), 6 | 8) {
        return Err(Error::new(ErrorCode::InvalidArgument));
    }
    let mut out = String::new();
    push_hex(&mut out, link_layer_address);
    Ok(out)
}

/// Appends octets as uppercase hexadecimal.
pub(crate) fn push_hex<const N: usize>(out: &mut String<N>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for byte in bytes {
        let hi = DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let lo = DIGITS
            .get(usize::from(byte & 0x0F))
            .copied()
            .unwrap_or(b'0');
        let _ = out.push(hi as char);
        let _ = out.push(lo as char);
    }
}

/// A DNS-SD subtype label, as §4.3.1.3 and §4.3.2.3 define them.
///
/// | Subtype | Meaning | Encoding |
/// |---|---|---|
/// | `_L<dddd>` | the full 12-bit discriminator | decimal, no leading zeroes |
/// | `_S<dd>` | its upper four bits | decimal, no leading zeroes |
/// | `_V<ddddd>` | the 16-bit Vendor ID | decimal, no leading zeroes |
/// | `_T<ddd>` | the primary device type | decimal, no leading zeroes |
/// | `_CM` | "currently in Commissioning Mode" | no value |
/// | `_I<hhhh>` | the Compressed Fabric Identifier | **exactly 16 uppercase hex** |
///
/// The two encodings are not interchangeable, and the difference is easy to miss: every
/// commissionable subtype is *decimal with leading zeroes omitted*, while the operational one
/// is *fixed-width hexadecimal*. A subtype in the wrong form is a name nobody browses for, and
/// the device is simply never found.
pub const SUBTYPE_MAX: usize = 18;

/// `_L<dddd>` — the long discriminator subtype (§4.3.1.3).
#[must_use]
pub fn long_discriminator_subtype(discriminator: u16) -> String<SUBTYPE_MAX> {
    decimal_subtype('L', u32::from(discriminator & 0x0FFF))
}

/// `_S<dd>` — the short discriminator subtype: "the upper 4 bits of the discriminator".
#[must_use]
pub fn short_discriminator_subtype(discriminator: u16) -> String<SUBTYPE_MAX> {
    decimal_subtype('S', u32::from((discriminator & 0x0FFF) >> 8))
}

/// `_V<ddddd>` — the Vendor ID subtype.
#[must_use]
pub fn vendor_subtype(vendor_id: crate::msg::VendorId) -> String<SUBTYPE_MAX> {
    decimal_subtype('V', u32::from(vendor_id.0))
}

/// `_T<ddd>` — the primary device type subtype.
#[must_use]
pub fn device_type_subtype(device_type: u32) -> String<SUBTYPE_MAX> {
    decimal_subtype('T', device_type)
}

/// `_CM` — "currently in Commissioning Mode".
///
/// §4.3.1.3: "the subtype is `_CM` regardless of whether the TXT record for commissioning mode
/// is set to 1 (CM=1), 2 (CM=2) or 3 (CM=3). A Commissionee that is not in commissioning mode
/// (CM=0) SHALL NOT publish this subtype."
pub const COMMISSIONING_MODE_SUBTYPE: &str = "_CM";

/// `_IC` — Incomplete Commissioning (§4.3.2.5), for NFC-based commissioning.
pub const INCOMPLETE_COMMISSIONING_SUBTYPE: &str = "_IC";

fn decimal_subtype(letter: char, value: u32) -> String<SUBTYPE_MAX> {
    let mut out = String::new();
    let _ = out.push('_');
    let _ = out.push(letter);
    push_decimal(&mut out, value);
    out
}

/// Appends a decimal number "omitting any leading zeroes" — which for zero means the single
/// digit `0`, not the empty string.
pub(crate) fn push_decimal<const N: usize>(out: &mut String<N>, value: u32) {
    if value == 0 {
        let _ = out.push('0');
        return;
    }
    let mut digits = [0u8; 10];
    let mut at = digits.len();
    let mut rest = value;
    while rest > 0 {
        at = at.saturating_sub(1);
        if let Some(slot) = digits.get_mut(at) {
            *slot = b'0'.saturating_add(u8::try_from(rest % 10).unwrap_or(0));
        }
        rest /= 10;
    }
    for digit in digits.get(at..).unwrap_or(&[]) {
        let _ = out.push(*digit as char);
    }
}

/// Builds a commissionable advertisement's subtypes from what §4.3.1.3 says to publish.
///
/// The five subtypes are not independent: `_CM` appears only in commissioning mode, `_V` and
/// `_T` only if the device chooses to publish them at all ("a vendor MAY choose not to include
/// it at all, for privacy reasons"), and the two discriminator subtypes always. Assembling
/// them in one place is what keeps a device from publishing `_CM` while advertising `CM=0`,
/// which §4.3.1.3 forbids and which nothing else would catch.
#[derive(Debug, Clone)]
pub struct CommissionableSubtypes {
    long: String<SUBTYPE_MAX>,
    short: String<SUBTYPE_MAX>,
    vendor: Option<String<SUBTYPE_MAX>>,
    device_type: Option<String<SUBTYPE_MAX>>,
    commissioning_mode: bool,
}

impl CommissionableSubtypes {
    /// The subtypes for a device with this discriminator and commissioning mode.
    #[must_use]
    pub fn new(discriminator: u16, mode: txt::CommissioningMode) -> Self {
        Self {
            long: long_discriminator_subtype(discriminator),
            short: short_discriminator_subtype(discriminator),
            vendor: None,
            device_type: None,
            commissioning_mode: mode.publishes_subtype(),
        }
    }

    /// Also publish `_V<vendor>`.
    #[must_use]
    pub fn with_vendor(mut self, vendor_id: crate::msg::VendorId) -> Self {
        self.vendor = Some(vendor_subtype(vendor_id));
        self
    }

    /// Also publish `_T<device-type>`.
    ///
    /// "In case the device combines multiple device types, the manufacturer SHOULD choose the
    /// device type identifier of the primary function of the device."
    #[must_use]
    pub fn with_device_type(mut self, device_type: u32) -> Self {
        self.device_type = Some(device_type_subtype(device_type));
        self
    }

    /// The subtype labels, in §4.3.1.14's order: `_S`, `_L`, `_V`, `_CM`, `_T`.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        core::iter::once(self.short.as_str())
            .chain(core::iter::once(self.long.as_str()))
            .chain(self.vendor.as_deref())
            .chain(
                self.commissioning_mode
                    .then_some(COMMISSIONING_MODE_SUBTYPE),
            )
            .chain(self.device_type.as_deref())
    }
}

/// The operational subtype for a fabric — `_I<hhhh>`, "exactly 16 uppercase hexadecimal
/// characters" (§4.3.2.3).
///
/// Not decimal, unlike every commissionable subtype, and not variable-width. A subtype in the
/// wrong form is a name nobody browses for, and the node is simply never found on its fabric.
///
/// [`CompressedFabricId::subtype`](crate::fabric::CompressedFabricId::subtype) is the same
/// value; this is here so the two naming conventions sit side by side, where the difference
/// between them is visible.
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
#[must_use]
pub fn compressed_fabric_subtype(
    compressed: crate::fabric::CompressedFabricId,
) -> String<SUBTYPE_MAX> {
    compressed.subtype()
}
