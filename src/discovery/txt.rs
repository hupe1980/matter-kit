//! The DNS-SD TXT key/value pairs Matter defines (Core §4.3.1.4–13, §4.3.4).
//!
//! A TXT record is a sequence of length-prefixed strings, each conventionally `KEY=VALUE`
//! (RFC 6763 §6). Matter's keys are all ASCII, and almost all of their values are "a
//! variable-length decimal number in ASCII text, omitting any leading zeroes" — a phrase the
//! specification repeats eleven times.
//!
//! # None of it is trustworthy
//!
//! §4.3.4 says so outright: "Because the information carried in DNS-SD records with Matter is
//! not trustworthy (since the source is not authenticated), the value of the T key SHOULD be
//! regarded only as a hint." That applies to every key here. A commissioner uses them to
//! *find* and *filter*; it learns nothing from them it may act on. The MRP timings are the
//! interesting case — they change how long a peer waits, and a lying advertisement can only
//! make a session slower, never insecure.
//!
//! # Two rules that are easy to miss
//!
//! "Commissioners SHALL silently ignore TXT record keys that they do not recognize. This is to
//! facilitate future evolution of this specification without breaking backwards compatibility"
//! — so [`TxtReader`] hands back every pair and refuses nothing.
//!
//! And `CM` has a *default*: "The absence of key CM SHALL imply a value of 0 (CM=0)." An absent
//! key is not an unknown state.

use heapless::String;

use crate::error::{Error, ErrorCode, Result};
use crate::msg::VendorId;

use super::push_decimal;

/// The longest TXT record this module builds.
///
/// RFC 6763 §6.1 asks that a TXT record fit comfortably in a single packet; §4.3.1's keys at
/// their maxima — a 32-byte `DN`, a 100-character `RI`, a 128-byte `PI` — come to rather more
/// than a commissionable advertisement ever carries in practice.
pub const TXT_MAX: usize = 512;

/// `CM` — the commissioning mode (§4.3.1.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum CommissioningMode {
    /// `0` — "the publisher is not currently in Commissioning Mode". The default, and what an
    /// absent `CM` key means.
    #[default]
    None = 0,
    /// `1` — in Commissioning Mode with the passcode "provided by the Commissionee (e.g.,
    /// embedded in Onboarding Material which is printed on device)": a factory-new device, or
    /// one that received `OpenBasicCommissioningWindow`.
    Basic = 1,
    /// `2` — in Commissioning Mode with "a dynamically generated Passcode … passed to the
    /// device using the OpenCommissioningWindow command".
    Enhanced = 2,
    /// `3` — in *Joint Fabric* Commissioning Mode, from `OpenJointCommissioningWindow`.
    ///
    /// A separate value from `2` so "a Commissioner can distinguish between a Commissionee
    /// that is in Joint Fabric Commissioning Mode and one that is in Commissioning Mode CM=2",
    /// which need different mutual-verification steps.
    JointFabric = 3,
}

impl CommissioningMode {
    /// The value the key carries.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Decodes a value, treating anything undefined as [`CommissioningMode::None`].
    #[must_use]
    pub const fn from_value(value: u8) -> Self {
        match value {
            1 => Self::Basic,
            2 => Self::Enhanced,
            3 => Self::JointFabric,
            _ => Self::None,
        }
    }

    /// Whether the `_CM` subtype should be published.
    ///
    /// §4.3.1.3: "A Commissionee that is not in commissioning mode (CM=0) SHALL NOT publish
    /// this subtype", and the subtype is `_CM` for all three of 1, 2 and 3.
    #[must_use]
    pub const fn publishes_subtype(self) -> bool {
        !matches!(self, Self::None)
    }
}

pub use crate::transport::TransportModes;

bitflags::bitflags! {
    /// `JF` — Table 6's "Joint Fabric Key Values" (§4.3.1.13).
    ///
    /// "bit 0 (Available) SHALL be unset for any of bits 1, 2 or 3 to be set", which
    /// [`JointFabric::is_valid`] checks.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct JointFabric: u32 {
        /// Bit 0 — "capable of acting as a Joint Fabric Administrator".
        const AVAILABLE = 1 << 0;
        /// Bit 1 — "acting as a Joint Fabric Administrator".
        const ADMINISTRATOR = 1 << 1;
        /// Bit 2 — "acting as a Joint Fabric Anchor Administrator".
        const ANCHOR = 1 << 2;
        /// Bit 3 — "acting as a Joint Fabric Datastore".
        const DATASTORE = 1 << 3;
    }
}

impl JointFabric {
    /// Whether Note 1's exclusion holds: `Available` and any of the other three are
    /// mutually exclusive.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        let acting = Self::ADMINISTRATOR.bits() | Self::ANCHOR.bits() | Self::DATASTORE.bits();
        !(self.contains(Self::AVAILABLE) && (self.bits() & acting) != 0)
    }
}

/// The MRP timings a node may publish (§4.3.4's `SII`, `SAI`, `SAT`).
///
/// Each "MAY optionally be provided by a Node to override the default setting. If the key is
/// not included or invalid, the Node querying the service record SHALL use the default MRP
/// parameter value." So `None` is not zero — it means "use the default", and publishing a
/// zero would say something quite different.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MrpAdvertisement {
    /// `SII` — `SESSION_IDLE_INTERVAL`, milliseconds, at most 3 600 000.
    pub idle_interval_ms: Option<u32>,
    /// `SAI` — `SESSION_ACTIVE_INTERVAL`, milliseconds, at most 3 600 000.
    pub active_interval_ms: Option<u32>,
    /// `SAT` — `SESSION_ACTIVE_THRESHOLD`, milliseconds, at most 65 535.
    pub active_threshold_ms: Option<u16>,
}

/// §4.3.4's cap on `SII` and `SAI`: "SHALL NOT exceed 3600000 (1 hour in milliseconds)".
pub const MRP_INTERVAL_MAX_MS: u32 = 3_600_000;

impl MrpAdvertisement {
    /// Whether both intervals are within §4.3.4's one-hour bound.
    ///
    /// `SAT`'s own bound — "SHALL NOT exceed 65535" — is the `u16` itself.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        let idle_ok = match self.idle_interval_ms {
            Some(value) => value <= MRP_INTERVAL_MAX_MS,
            None => true,
        };
        let active_ok = match self.active_interval_ms {
            Some(value) => value <= MRP_INTERVAL_MAX_MS,
            None => true,
        };
        idle_ok && active_ok
    }
}

/// Builds a TXT record: a sequence of length-prefixed `KEY=VALUE` strings (RFC 6763 §6.1).
#[derive(Debug, Default)]
pub struct TxtWriter {
    buf: heapless::Vec<u8, TXT_MAX>,
}

impl TxtWriter {
    /// An empty record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: heapless::Vec::new(),
        }
    }

    /// Appends `key=value`.
    ///
    /// RFC 6763 §6.1 caps one string at 255 octets, which is the length prefix's range.
    pub fn push(&mut self, key: &str, value: &str) -> Result<()> {
        let len = key
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(no_space)?;
        let len = u8::try_from(len).map_err(|_| no_space())?;
        self.buf.push(len).map_err(|_| no_space())?;
        self.buf
            .extend_from_slice(key.as_bytes())
            .map_err(|_| no_space())?;
        self.buf.push(b'=').map_err(|_| no_space())?;
        self.buf
            .extend_from_slice(value.as_bytes())
            .map_err(|_| no_space())
    }

    /// Appends `key=<decimal>`, "omitting any leading zeroes".
    pub fn push_decimal(&mut self, key: &str, value: u32) -> Result<()> {
        let mut text = String::<10>::new();
        push_decimal(&mut text, value);
        self.push(key, &text)
    }

    /// The encoded record.
    ///
    /// An *empty* TXT record is not the empty slice: RFC 6763 §6.1 requires at least one
    /// zero-length string, because a DNS TXT record with no data is not legal. Operational
    /// discovery hits this — §4.3.2.6 says "The TXT record MAY be omitted if no keys are
    /// defined", and a node with no MRP overrides has none.
    #[must_use]
    pub fn finish(&self) -> &[u8] {
        if self.buf.is_empty() {
            &[0u8]
        } else {
            &self.buf
        }
    }

    /// Whether no key has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

fn no_space() -> Error {
    Error::new(ErrorCode::NoSpace)
}

/// Reads a TXT record's key/value pairs.
///
/// Hands back every pair, including ones this crate does not define: "Commissioners SHALL
/// silently ignore TXT record keys that they do not recognize."
#[derive(Debug, Clone)]
pub struct TxtReader<'a> {
    rest: &'a [u8],
}

impl<'a> TxtReader<'a> {
    /// Reads `bytes` as a TXT record's RDATA.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The value of `key`, if present.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&'a [u8]> {
        self.clone()
            .find(|(k, _)| k.eq_ignore_ascii_case(key.as_bytes()))
            .map(|(_, value)| value)
    }

    /// The value of `key` read as a decimal number.
    #[must_use]
    pub fn decimal(&self, key: &str) -> Option<u32> {
        parse_decimal(self.get(key)?)
    }
}

impl<'a> Iterator for TxtReader<'a> {
    /// A `(key, value)` pair. A string with no `=` yields an empty value, which RFC 6763 §6.4
    /// defines as "attribute present, with no value".
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (&len, tail) = self.rest.split_first()?;
            let len = usize::from(len);
            let string = tail.get(..len)?;
            self.rest = tail.get(len..)?;
            if string.is_empty() {
                // RFC 6763 §6.1's lone empty string, which means "no attributes".
                continue;
            }
            let split = string.iter().position(|&b| b == b'=');
            return Some(match split {
                Some(at) => (
                    string.get(..at).unwrap_or(&[]),
                    string.get(at.saturating_add(1)..).unwrap_or(&[]),
                ),
                None => (string, &[]),
            });
        }
    }
}

/// Parses "a variable-length decimal number in ASCII text", refusing anything else.
///
/// §4.3.1.5 is explicit about what to do with a malformed one: "Any key D with a value
/// mismatching the aforementioned format SHALL be silently ignored." So this returns `None`
/// rather than a partial parse — `840x` is not 840.
#[must_use]
pub fn parse_decimal(value: &[u8]) -> Option<u32> {
    if value.is_empty() || value.len() > 10 {
        return None;
    }
    let mut out = 0u32;
    for byte in value {
        let digit = byte.checked_sub(b'0').filter(|d| *d <= 9)?;
        out = out.checked_mul(10)?.checked_add(u32::from(digit))?;
    }
    Some(out)
}

// --- The two advertisements ----------------------------------------------------------------------

/// The TXT record a Commissionable Node publishes (§4.3.1.4–13).
///
/// `D` is the only mandatory key. Every other one is optional, and several of them are
/// optional *for privacy*: §4.3.1.6 says a vendor "MAY choose not to include `VP` at all, for
/// privacy reasons", and §4.3.1.9 requires that a device publishing `DN` "SHALL provide a way
/// for the customer to disable its inclusion". Defaulting them to absent is therefore the
/// conservative reading as well as the simple one.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommissionableTxt<'a> {
    /// `D` — "the full 12-bit discriminator … SHALL be present".
    pub discriminator: u16,
    /// `VP` — the Vendor ID, and optionally the Product ID after a `+`.
    pub vendor_id: Option<VendorId>,
    /// The Product ID, which §4.3.1.6 only admits alongside a Vendor ID.
    pub product_id: Option<u16>,
    /// `CM` — the commissioning mode.
    pub commissioning_mode: CommissioningMode,
    /// `DT` — "the publisher's Primary Device Type".
    pub device_type: Option<u32>,
    /// `DN` — "a device advertisement name … maximum length of 32 bytes (matching the maximum
    /// length of the NodeLabel string in the Basic Information Cluster)".
    pub device_name: Option<&'a str>,
    /// `RI` — the Rotating Device Identifier, "at most 50 octets", published as uppercase hex.
    pub rotating_id: Option<&'a [u8]>,
    /// `PH` — the pairing hint: "a base-10 numeric value for a bitmap of methods supported by
    /// the Commissionee in its current state for putting it in Commissioning Mode".
    pub pairing_hint: Option<u32>,
    /// `PI` — the pairing instruction, "a valid UTF-8 string with a maximum length of 128
    /// bytes", whose meaning "is dependent upon the PH key value".
    pub pairing_instruction: Option<&'a str>,
    /// `JF` — Joint Fabric capabilities, "if and only if the Node is capable of being a Joint
    /// Fabric Administrator".
    pub joint_fabric: Option<JointFabric>,
    /// `SII`, `SAI`, `SAT` — the common MRP overrides of §4.3.4.
    pub mrp: MrpAdvertisement,
}

/// §4.3.1.10's cap: "The resulting ASCII string SHALL NOT be longer than 100 characters, which
/// implies a Rotating Device Identifier of at most 50 octets."
pub const ROTATING_ID_MAX_OCTETS: usize = 50;

/// §4.3.1.9's cap on `DN`, matching `NodeLabel`.
pub const DEVICE_NAME_MAX: usize = 32;

/// §4.3.1.12's cap on `PI`.
pub const PAIRING_INSTRUCTION_MAX: usize = 128;

impl CommissionableTxt<'_> {
    /// Encodes the record.
    ///
    /// The order is §4.3.1.14's: `D`, `VP`, `CM`, `DT`, `DN`, `RI`, `PH`, `PI`, then the common
    /// keys. TXT key order carries no meaning in DNS-SD, but matching the specification's own
    /// examples is what lets those examples be tests.
    pub fn encode(&self) -> Result<TxtWriter> {
        let mut w = TxtWriter::new();
        // "The discriminator value SHALL be encoded as a variable-length decimal number in
        // ASCII text, with up to four digits" — and it is the full 12 bits.
        w.push_decimal("D", u32::from(self.discriminator & 0x0FFF))?;

        if let Some(vendor) = self.vendor_id {
            let mut value = String::<16>::new();
            push_decimal(&mut value, u32::from(vendor.0));
            if let Some(product) = self.product_id {
                // "If the Product ID is present, it SHALL be separated from the Vendor ID
                // using a '+' character."
                let _ = value.push('+');
                push_decimal(&mut value, u32::from(product));
            }
            w.push("VP", &value)?;
        } else if self.product_id.is_some() {
            // "If the VP key is present, the value SHALL contain at least the Vendor ID."
            // A Product ID with no Vendor ID has no encoding, so it is a caller error rather
            // than something to silently drop.
            return Err(Error::new(ErrorCode::InvalidArgument));
        }

        w.push_decimal("CM", u32::from(self.commissioning_mode.value()))?;

        if let Some(device_type) = self.device_type {
            w.push_decimal("DT", device_type)?;
        }
        if let Some(name) = self.device_name {
            if name.len() > DEVICE_NAME_MAX {
                return Err(Error::new(ErrorCode::InvalidArgument));
            }
            w.push("DN", name)?;
        }
        if let Some(rotating) = self.rotating_id {
            if rotating.len() > ROTATING_ID_MAX_OCTETS {
                return Err(Error::new(ErrorCode::InvalidArgument));
            }
            // "the concatenation of each octet's value as a 2-digit uppercase hexadecimal
            // number".
            let mut value = String::<{ ROTATING_ID_MAX_OCTETS * 2 }>::new();
            super::push_hex(&mut value, rotating);
            w.push("RI", &value)?;
        }
        if let Some(hint) = self.pairing_hint {
            w.push_decimal("PH", hint)?;
        }
        if let Some(instruction) = self.pairing_instruction {
            if instruction.len() > PAIRING_INSTRUCTION_MAX {
                return Err(Error::new(ErrorCode::InvalidArgument));
            }
            w.push("PI", instruction)?;
        }
        if let Some(joint) = self.joint_fabric {
            if !joint.is_valid() {
                return Err(Error::new(ErrorCode::InvalidArgument));
            }
            w.push_decimal("JF", joint.bits())?;
        }
        push_mrp(&mut w, &self.mrp)?;
        Ok(w)
    }
}

/// The TXT record an operational node publishes (§4.3.2.6, §4.3.4).
///
/// Much smaller than the commissionable one: "The TXT record MAY be omitted if no keys are
/// defined", and a node with default MRP timings and no TCP has none.
#[derive(Debug, Clone, Copy, Default)]
pub struct OperationalTxt {
    /// `SII`, `SAI`, `SAT`.
    pub mrp: MrpAdvertisement,
    /// `T` — the transports beyond MRP over UDP. "This key SHALL only be used during
    /// operational discovery."
    pub transports: TransportModes,
    /// `ICD` — whether the node "is operating as a Long Idle Time ICD".
    ///
    /// "The key SHALL NOT be provided by a Node that does not support the ICD Long Idle Time
    /// operating mode", which is what `None` says — distinct from `Some(false)`, which says
    /// the node supports the mode and is not in it.
    pub long_idle_time_icd: Option<bool>,
    /// `IC` — Incomplete Commissioning (§4.3.2.7), for NFC-based commissioning.
    pub incomplete_commissioning: Option<bool>,
}

impl OperationalTxt {
    /// Encodes the record.
    pub fn encode(&self) -> Result<TxtWriter> {
        let mut w = TxtWriter::new();
        push_mrp(&mut w, &self.mrp)?;
        if !self.transports.is_empty() {
            // Bit 0 "is deprecated and SHALL be set to 0 by the advertising node", which
            // `TransportModes` has no flag for — so it cannot be set by accident.
            w.push_decimal("T", self.transports.bits())?;
        }
        if let Some(icd) = self.long_idle_time_icd {
            w.push_decimal("ICD", u32::from(icd))?;
        }
        if let Some(incomplete) = self.incomplete_commissioning {
            w.push_decimal("IC", u32::from(incomplete))?;
        }
        Ok(w)
    }
}

fn push_mrp(w: &mut TxtWriter, mrp: &MrpAdvertisement) -> Result<()> {
    if !mrp.is_valid() {
        return Err(Error::new(ErrorCode::InvalidArgument));
    }
    if let Some(idle) = mrp.idle_interval_ms {
        w.push_decimal("SII", idle)?;
    }
    if let Some(active) = mrp.active_interval_ms {
        w.push_decimal("SAI", active)?;
    }
    if let Some(threshold) = mrp.active_threshold_ms {
        w.push_decimal("SAT", u32::from(threshold))?;
    }
    Ok(())
}
