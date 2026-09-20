//! The onboarding payload — the QR code and the manual pairing code (Core §5.1).
//!
//! Everything PASE needs before it can start has to reach the commissioner somehow, and
//! this is how: a string printed on the device or its box. Two forms, from the same data.
//!
//! ```text
//! MT:-24J0AFN00KA0648G00        a QR code: 11 octets, base-38
//! 3497011266                5   a manual code: 11 digits, the last one a checksum
//! ```
//!
//! The QR form carries everything — vendor, product, how to discover the device, the
//! 12-bit discriminator, the 27-bit passcode, and optional TLV. The manual form carries
//! what a person can reasonably type: the passcode, the *top four bits* of the
//! discriminator, and optionally vendor and product. A commissioner given only a manual
//! code therefore has to search harder when it goes looking for the device.
//!
//! # The passcode is 27 bits and not all of them count
//!
//! "A Passcode SHALL be included as a 27-bit unsigned integer … SHALL be restricted to the
//! values 0x0000001 to 0x5F5E0FE" — 1 to 99 999 998 — and twelve further values are
//! forbidden outright for being guessable (§5.1.7.1). [`Passcode`] enforces both, because
//! a device shipped with `12345678` is a device anyone can commission.

use crate::error::{Error, ErrorCode, Result, bail};
use crate::msg::VendorId;

/// The base-38 alphabet of Core Table 61.
///
/// "a subset of the 45 available characters (A-Z0-9$%*+./ :-) in the QR code for
/// alphanumeric encoding … with characters `$`, `%`, `*`, `+`, `/`, space and `:`
/// removed" — so every character survives QR alphanumeric mode, which is what keeps the
/// code small.
const ALPHABET: &[u8; 38] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

/// The three-character prefix every Matter QR payload starts with (§5.1.3.1).
pub const QR_PREFIX: &str = "MT:";

/// The packed binary structure is 88 bits — 11 octets — before any TLV (§5.1.3.1.3).
pub const PACKED_LEN: usize = 11;

/// A base-38 QR payload for the packed structure alone, plus the prefix.
pub const QR_LEN_NO_TLV: usize = 3 + 19;

/// The longest manual pairing code: 21 digits, with vendor and product.
pub const MANUAL_CODE_MAX_DIGITS: usize = 21;

/// A validated setup passcode (§5.1.1.6, §5.1.7.1).
///
/// There is no way to build one that a device may not ship with, which is the point: the
/// check belongs at the type, not at each of the several places a passcode enters the
/// stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Passcode(u32);

impl Passcode {
    /// The smallest legal value.
    pub const MIN: u32 = 0x0000_0001;
    /// The largest legal value — 99 999 998.
    pub const MAX: u32 = 0x05F5_E0FE;

    /// "The following Passcodes SHALL NOT be used for the PASE protocol due to their
    /// trivial, insecure nature" (§5.1.7.1).
    pub const INVALID: [u32; 12] = [
        0, 11_111_111, 22_222_222, 33_333_333, 44_444_444, 55_555_555, 66_666_666, 77_777_777,
        88_888_888, 99_999_999, 12_345_678, 87_654_321,
    ];

    /// Checks a value against both rules.
    pub const fn new(value: u32) -> Result<Self> {
        if value < Self::MIN || value > Self::MAX {
            return Err(Error::new(ErrorCode::InvalidArgument));
        }
        // A `while let` over `split_first` keeps this both `const` and index-free.
        let mut rest: &[u32] = &Self::INVALID;
        while let [first, tail @ ..] = rest {
            if *first == value {
                return Err(Error::new(ErrorCode::InvalidArgument));
            }
            rest = tail;
        }
        Ok(Self(value))
    }

    /// The value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// The Device Commissioning Flow (§5.1.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum CustomFlow {
    /// "Standard commissioning flow: such a device, when uncommissioned, always enters
    /// commissioning mode upon power-up."
    #[default]
    Standard = 0,
    /// "User-intent commissioning flow: user action required to enter commissioning mode."
    UserIntent = 1,
    /// "Custom commissioning flow: interaction with a vendor-specified means is needed
    /// before commissioning."
    Custom = 2,
}

impl CustomFlow {
    const fn from_bits(bits: u8) -> Result<Self> {
        Ok(match bits {
            0 => Self::Standard,
            1 => Self::UserIntent,
            2 => Self::Custom,
            // "3: Reserved".
            _ => return Err(Error::new(ErrorCode::MessageReserved)),
        })
    }
}

bitflags::bitflags! {
    /// How a device can be discovered (Core Table 60).
    ///
    /// Every bit means "supports this **when not commissioned**": a device already on a
    /// fabric advertises none of them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct DiscoveryCapabilities: u8 {
        /// Bit 1 — "Device supports BLE for discovery when not commissioned."
        const BLE = 1 << 1;
        /// Bit 2 — "Device is already on the IP network."
        const ON_IP_NETWORK = 1 << 2;
        /// Bit 3 — Wi-Fi Public Action Frame.
        const WIFI_PAF = 1 << 3;
        /// Bit 4 — the NFC Transport Layer.
        const NFC = 1 << 4;
        /// Bit 5 — the Thread Commissioning Protocol. Provisional: "Until it becomes
        /// certifiable, Bit 5 should be treated as reserved."
        const THREAD_COMMISSIONING = 1 << 5;
    }
}

/// Everything printed on a device's label (§5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnboardingPayload {
    /// Who made it.
    pub vendor_id: VendorId,
    /// What it is.
    pub product_id: u16,
    /// Whether the user has to do something before commissioning can start.
    pub custom_flow: CustomFlow,
    /// How to find it.
    pub discovery: DiscoveryCapabilities,
    /// A 12-bit value the device also advertises, so a commissioner can tell two
    /// otherwise identical devices apart (§5.1.1.5).
    pub discriminator: u16,
    /// The shared secret PASE proves possession of.
    pub passcode: Passcode,
}

/// The 12-bit discriminator's mask.
const DISCRIMINATOR_MASK: u16 = 0x0FFF;

impl OnboardingPayload {
    /// Builds a payload, checking the discriminator fits 12 bits.
    pub fn new(
        vendor_id: VendorId,
        product_id: u16,
        discriminator: u16,
        passcode: Passcode,
        discovery: DiscoveryCapabilities,
        custom_flow: CustomFlow,
    ) -> Result<Self> {
        if discriminator > DISCRIMINATOR_MASK {
            bail!(InvalidArgument)
        }
        Ok(Self {
            vendor_id,
            product_id,
            custom_flow,
            discovery,
            discriminator,
            passcode,
        })
    }

    /// The top four bits of the discriminator — all a manual pairing code carries
    /// (§5.1.1.5).
    #[must_use]
    pub const fn short_discriminator(&self) -> u8 {
        (self.discriminator >> 8) as u8
    }

    /// Packs the structure of Core Table 59 into 11 octets.
    ///
    /// "The bits of each fixed-size value are placed in the packed binary data structure
    /// in order from least significant to most significant", and the whole is "padded with
    /// '0' bits at the end of the structure to the nearest byte boundary".
    pub fn pack(&self) -> [u8; PACKED_LEN] {
        let mut bits = BitWriter::new();
        // Version: "SHALL be 000".
        bits.push(0, 3);
        bits.push(u64::from(self.vendor_id.0), 16);
        bits.push(u64::from(self.product_id), 16);
        bits.push(self.custom_flow as u64, 2);
        bits.push(u64::from(self.discovery.bits()), 8);
        bits.push(u64::from(self.discriminator & DISCRIMINATOR_MASK), 12);
        bits.push(u64::from(self.passcode.value()), 27);
        // The four padding bits are already zero.
        bits.finish()
    }

    /// Reads the packed structure back.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "every `take` here is width-exact: §5.1.3.1.3's fields are 27, 16, 12, 8 and 2 bits"
    )]
    pub fn unpack(bytes: &[u8]) -> Result<Self> {
        let Some(packed) = bytes.get(..PACKED_LEN) else {
            bail!(MessageTruncated)
        };
        let mut bits = BitReader::new(packed);
        let version = bits.take(3)?;
        if version != 0 {
            // §5.1.1.1: the version "SHALL be 000"; anything else is a payload this
            // revision does not know how to read, and guessing would be worse than saying so.
            bail!(UnsupportedVersion)
        }
        let vendor_id = VendorId(bits.take(16)? as u16);
        let product_id = bits.take(16)? as u16;
        let custom_flow = CustomFlow::from_bits(bits.take(2)? as u8)?;
        let discovery = DiscoveryCapabilities::from_bits_retain(bits.take(8)? as u8);
        let discriminator = bits.take(12)? as u16;
        let passcode = Passcode::new(bits.take(27)? as u32)?;

        Ok(Self {
            vendor_id,
            product_id,
            custom_flow,
            discovery,
            discriminator,
            passcode,
        })
    }

    /// Renders the QR payload: `MT:` followed by the base-38 encoding.
    pub fn to_qr(&self) -> Result<heapless::String<QR_LEN_NO_TLV>> {
        let mut out = heapless::String::new();
        out.push_str(QR_PREFIX)
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        base38_encode(&self.pack(), &mut out)?;
        Ok(out)
    }

    /// Parses a QR payload.
    ///
    /// Accepts the string with or without its `MT:` prefix; a camera app that strips it is
    /// common enough that refusing would be unhelpful.
    pub fn from_qr(text: &str) -> Result<Self> {
        let body = text.strip_prefix(QR_PREFIX).unwrap_or(text);
        let mut packed = [0u8; PACKED_LEN];
        let n = base38_decode(body, &mut packed)?;
        if n < PACKED_LEN {
            bail!(MessageTruncated)
        }
        Self::unpack(&packed)
    }

    /// Renders the manual pairing code (§5.1.4).
    ///
    /// `include_vid_pid` produces the 21-digit form. §5.1.4.1.2 ties this to the
    /// commissioning flow: a standard-flow device uses the short form, and a user-intent
    /// or custom-flow device "SHALL" use the long one — so this refuses the combination
    /// the specification forbids rather than producing a code a commissioner will
    /// misread as standard flow.
    pub fn to_manual_code(
        &self,
        include_vid_pid: bool,
    ) -> Result<heapless::String<MANUAL_CODE_MAX_DIGITS>> {
        if !include_vid_pid && self.custom_flow != CustomFlow::Standard {
            bail!(InvalidArgument)
        }

        let passcode = self.passcode.value();
        let discriminator = u32::from(self.discriminator & DISCRIMINATOR_MASK);

        // DIGIT[1] := (VID_PID_PRESENT << 2) | (DISCRIMINATOR >> 10)
        let first = (u32::from(include_vid_pid) << 2) | (discriminator >> 10);
        // DIGIT[2..6] := ((DISCRIMINATOR & 0x300) << 6) | (PASSCODE & 0x3FFF)
        let group2 = ((discriminator & 0x300) << 6) | (passcode & 0x3FFF);
        // DIGIT[7..10] := (PASSCODE >> 14)
        let group3 = passcode >> 14;

        let mut out = heapless::String::<MANUAL_CODE_MAX_DIGITS>::new();
        push_digits(&mut out, first, 1)?;
        push_digits(&mut out, group2, 5)?;
        push_digits(&mut out, group3, 4)?;
        if include_vid_pid {
            push_digits(&mut out, u32::from(self.vendor_id.0), 5)?;
            push_digits(&mut out, u32::from(self.product_id), 5)?;
        }
        let check = verhoeff_check_digit(out.as_bytes())?;
        push_digits(&mut out, u32::from(check), 1)?;
        Ok(out)
    }

    /// Parses a manual pairing code.
    ///
    /// "The receiving application SHALL be robust against characters like dashes and
    /// spaces that may be included in the string" (§5.1.4.2), so those are stripped before
    /// anything else — a user who types `3497-011-2665` has typed a valid code.
    ///
    /// The discriminator that comes back has only its top four bits set; the rest are
    /// zero, because a manual code does not carry them.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "`bounded` holds each group to the width §5.1.4.1.4's tables give it, before any cast"
    )]
    pub fn from_manual_code(text: &str) -> Result<Self> {
        let mut digits = heapless::Vec::<u8, MANUAL_CODE_MAX_DIGITS>::new();
        for c in text.chars() {
            match c {
                '0'..='9' => digits
                    .push((c as u8).wrapping_sub(b'0'))
                    .map_err(|_| Error::new(ErrorCode::InvalidArgument))?,
                '-' | ' ' => {}
                _ => bail!(InvalidArgument),
            }
        }

        let expect_vid_pid = match digits.len() {
            11 => false,
            21 => true,
            _ => bail!(InvalidArgument),
        };
        if !verhoeff_is_valid(&digits) {
            // A single mistyped digit is caught here rather than by a failed PASE
            // exchange several seconds later.
            bail!(IntegrityCheckFailed)
        }

        let first = u32::from(digits.first().copied().unwrap_or(0));
        // §5.1.4.1.4: "First digit of '8' or '9' would be invalid for v1".
        if first > 7 {
            bail!(UnsupportedVersion)
        }
        let vid_pid_present = (first & 0b100) != 0;
        if vid_pid_present != expect_vid_pid {
            // The flag and the length must agree, or one of them is a lie.
            bail!(InvalidArgument)
        }

        // §5.1.4.1.4's Tables 63 and 64 state the range of every group, and a group outside it
        // is not a code this encoding produced. Reading one anyway is worse than refusing it:
        // the surplus bits fall off a mask or an `as`, so an invalid code decodes — silently —
        // to a *different* device's discriminator, passcode or vendor. `push_digits` has always
        // refused to write a value too wide for its group; this is the reading half of that.
        let group2 = bounded(digits_value(&digits, 1, 5)?, 0xFFFF)?;
        let group3 = bounded(digits_value(&digits, 6, 4)?, 0x1FFF)?;

        let discriminator = (((first & 0b011) << 10) | ((group2 & 0xC000) >> 6)) as u16;
        let passcode = Passcode::new((group2 & 0x3FFF) | (group3 << 14))?;

        let (vendor_id, product_id) = if vid_pid_present {
            (
                VendorId(bounded(digits_value(&digits, 10, 5)?, 0xFFFF)? as u16),
                bounded(digits_value(&digits, 15, 5)?, 0xFFFF)? as u16,
            )
        } else {
            (VendorId(0), 0)
        };

        Ok(Self {
            vendor_id,
            product_id,
            // §5.1.4.1.2: a short code means standard flow; a long one needs the
            // Distributed Compliance Ledger to say which of the other two it is, so the
            // most this parser can honestly report is "not standard".
            custom_flow: if vid_pid_present {
                CustomFlow::UserIntent
            } else {
                CustomFlow::Standard
            },
            discovery: DiscoveryCapabilities::empty(),
            discriminator,
            passcode,
        })
    }
}

fn push_digits<const N: usize>(
    out: &mut heapless::String<N>,
    value: u32,
    width: usize,
) -> Result<()> {
    let mut scratch = [0u8; 10];
    let mut v = value;
    for i in (0..width).rev() {
        let Some(slot) = scratch.get_mut(i) else {
            bail!(InvalidArgument)
        };
        *slot = b'0'.saturating_add((v % 10) as u8);
        v /= 10;
    }
    if v != 0 {
        // The value did not fit the width it was promised, which would silently shift
        // every later digit.
        bail!(InvalidArgument)
    }
    let Some(text) = scratch
        .get(..width)
        .and_then(|b| core::str::from_utf8(b).ok())
    else {
        bail!(InvalidArgument)
    };
    out.push_str(text)
        .map_err(|_| Error::new(ErrorCode::NoSpace))
}

/// A digit group's value, refused if it is wider than the field it encodes.
///
/// §5.1.4.1.4's tables give each group a range — 00000..=65535 for the two 16-bit groups,
/// 0000..=8191 for the 13-bit one — and a five-digit group can hold 99999. The difference is
/// exactly the space in which an invalid code would otherwise decode to a valid-looking one.
const fn bounded(value: u32, max: u32) -> Result<u32> {
    if value > max {
        return Err(Error::new(ErrorCode::InvalidArgument));
    }
    Ok(value)
}

fn digits_value(digits: &[u8], start: usize, width: usize) -> Result<u32> {
    let end = start
        .checked_add(width)
        .ok_or(Error::new(ErrorCode::InvalidArgument))?;
    let Some(slice) = digits.get(start..end) else {
        bail!(InvalidArgument)
    };
    let mut value = 0u32;
    for d in slice {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u32::from(*d)))
            .ok_or(Error::new(ErrorCode::InvalidArgument))?;
    }
    Ok(value)
}

// --- Base 38 (§5.1.3.1.5) ---------------------------------------------------------------

/// "every 3 bytes (24 bits) of binary source data are encoded to 5 characters", with two
/// bytes going to four characters and one byte to two.
fn base38_encode<const N: usize>(data: &[u8], out: &mut heapless::String<N>) -> Result<()> {
    for chunk in data.chunks(3) {
        let (value, width) = match chunk {
            // "UINT24 = (BYTE[N+2] << 16) | (BYTE[N+1] << 8) | (BYTE[N] << 0)" — the
            // chunk is little-endian.
            [a, b, c] => (
                u32::from(*a) | (u32::from(*b) << 8) | (u32::from(*c) << 16),
                5,
            ),
            [a, b] => (u32::from(*a) | (u32::from(*b) << 8), 4),
            [a] => (u32::from(*a), 2),
            _ => bail!(InvalidArgument),
        };
        let mut v = value;
        for _ in 0..width {
            let Some(&c) = ALPHABET.get((v % 38) as usize) else {
                bail!(InvalidArgument)
            };
            // "with the least-significant character appearing first (little-endian)".
            out.push(char::from(c))
                .map_err(|_| Error::new(ErrorCode::NoSpace))?;
            v /= 38;
        }
    }
    Ok(())
}

/// Decodes base-38 into `out`, returning how many octets it produced.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a base-38 group is checked against its own byte width before its octets are taken"
)]
fn base38_decode(text: &str, out: &mut [u8]) -> Result<usize> {
    let bytes = text.as_bytes();
    let mut written = 0usize;

    for chunk in bytes.chunks(5) {
        let width = match chunk.len() {
            5 => 3usize,
            4 => 2,
            2 => 1,
            // 1 or 3 characters cannot be a whole number of octets.
            _ => bail!(InvalidArgument),
        };
        let mut value = 0u32;
        // Least-significant character first, so fold from the end.
        for c in chunk.iter().rev() {
            let Some(digit) = ALPHABET.iter().position(|a| a == c) else {
                bail!(InvalidArgument)
            };
            value = value
                .checked_mul(38)
                .and_then(|v| v.checked_add(digit as u32))
                .ok_or(Error::new(ErrorCode::InvalidArgument))?;
        }
        // A 5-character group must fit 24 bits, a 4-character group 16, a 2-character
        // group 8 — a larger value means the encoding is not one this alphabet produced.
        let limit = 1u32
            .checked_shl((width as u32).saturating_mul(8))
            .unwrap_or(u32::MAX);
        if width < 4 && value >= limit {
            bail!(InvalidArgument)
        }
        for i in 0..width {
            let Some(slot) = out.get_mut(written) else {
                bail!(BufferTooSmall)
            };
            *slot = (value >> (i.saturating_mul(8))) as u8;
            written = written.saturating_add(1);
        }
    }
    Ok(written)
}

// --- Verhoeff (§5.1.4.1.5) ----------------------------------------------------------------

/// The dihedral group D₅ multiplication table.
const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/// The permutation table, applied by position.
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// The inverse table.
const VERHOEFF_INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/// The check digit for a string of ASCII digits.
///
/// Verhoeff catches every single-digit error and every adjacent transposition, which are
/// the two mistakes a person typing a number actually makes — a plain modulo-10 checksum
/// catches the first and misses the second.
fn verhoeff_check_digit(ascii_digits: &[u8]) -> Result<u8> {
    let mut c = 0u8;
    for (i, ascii) in ascii_digits.iter().rev().enumerate() {
        let digit = ascii.checked_sub(b'0').filter(|d| *d < 10);
        let Some(digit) = digit else {
            bail!(InvalidArgument)
        };
        // Generating the check digit permutes by `i + 1`, because the digit being
        // generated will occupy position 0 once it is appended.
        let Some(row) = VERHOEFF_P.get(i.saturating_add(1) % 8) else {
            bail!(InvalidArgument)
        };
        let Some(&permuted) = row.get(usize::from(digit)) else {
            bail!(InvalidArgument)
        };
        let Some(&next) = VERHOEFF_D
            .get(usize::from(c))
            .and_then(|r| r.get(usize::from(permuted)))
        else {
            bail!(InvalidArgument)
        };
        c = next;
    }
    VERHOEFF_INV
        .get(usize::from(c))
        .copied()
        .ok_or(Error::new(ErrorCode::InvalidArgument))
}

/// Whether a string of digits, check digit included, is self-consistent.
fn verhoeff_is_valid(digits: &[u8]) -> bool {
    let mut c = 0u8;
    for (i, digit) in digits.iter().rev().enumerate() {
        if *digit > 9 {
            return false;
        }
        let (Some(row), Some(table)) = (VERHOEFF_P.get(i % 8), VERHOEFF_D.get(usize::from(c)))
        else {
            return false;
        };
        let Some(&permuted) = row.get(usize::from(*digit)) else {
            return false;
        };
        let Some(&next) = table.get(usize::from(permuted)) else {
            return false;
        };
        c = next;
    }
    c == 0
}

// --- Bit packing ---------------------------------------------------------------------------

/// Writes fields least-significant-bit first, as Core Table 58 pictures.
struct BitWriter {
    bytes: [u8; PACKED_LEN],
    bit: usize,
}

impl BitWriter {
    const fn new() -> Self {
        Self {
            bytes: [0; PACKED_LEN],
            bit: 0,
        }
    }

    fn push(&mut self, value: u64, width: usize) {
        for i in 0..width {
            if (value >> i) & 1 == 1 {
                let index = self.bit.saturating_add(i);
                if let Some(slot) = self.bytes.get_mut(index / 8) {
                    *slot |= 1u8 << (index % 8);
                }
            }
        }
        self.bit = self.bit.saturating_add(width);
    }

    const fn finish(self) -> [u8; PACKED_LEN] {
        self.bytes
    }
}

/// Reads fields the same way.
struct BitReader<'a> {
    bytes: &'a [u8],
    bit: usize,
}

impl<'a> BitReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit: 0 }
    }

    fn take(&mut self, width: usize) -> Result<u64> {
        let mut value = 0u64;
        for i in 0..width {
            let index = self.bit.saturating_add(i);
            let Some(&byte) = self.bytes.get(index / 8) else {
                bail!(MessageTruncated)
            };
            if (byte >> (index % 8)) & 1 == 1 {
                value |= 1u64 << i;
            }
        }
        self.bit = self.bit.saturating_add(width);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The onboarding payload CHIP's test devices carry.
    fn test_payload() -> OnboardingPayload {
        OnboardingPayload::new(
            VendorId(0xFFF1),
            0x8001,
            3840,
            Passcode::new(20_202_021).expect("passcode"),
            DiscoveryCapabilities::ON_IP_NETWORK,
            CustomFlow::Standard,
        )
        .expect("payload")
    }

    #[test]
    fn the_passcode_rules_of_5_1_7_1_are_enforced() {
        assert!(Passcode::new(20_202_021).is_ok());
        assert!(Passcode::new(1).is_ok());
        assert!(Passcode::new(99_999_998).is_ok());
        // Out of range.
        assert!(Passcode::new(0).is_err());
        assert!(Passcode::new(99_999_999).is_err());
        assert!(Passcode::new(u32::MAX).is_err());
        // Every one of the twelve trivial values.
        for invalid in Passcode::INVALID {
            assert!(Passcode::new(invalid).is_err(), "{invalid} must be refused");
        }
    }

    #[test]
    fn the_packed_structure_is_88_bits() {
        // 3 + 16 + 16 + 2 + 8 + 12 + 27 = 84, padded to 88 = 11 octets.
        assert_eq!(test_payload().pack().len(), PACKED_LEN);
    }

    #[test]
    fn the_packed_structure_round_trips() {
        let payload = test_payload();
        assert_eq!(
            OnboardingPayload::unpack(&payload.pack()).expect("unpack"),
            payload
        );
    }

    #[test]
    fn version_zero_is_the_only_one_readable() {
        // §5.1.1.1: "SHALL be 000".
        let mut packed = test_payload().pack();
        packed[0] |= 0b001;
        assert_eq!(
            OnboardingPayload::unpack(&packed).unwrap_err().code(),
            ErrorCode::UnsupportedVersion
        );
    }

    #[test]
    fn the_qr_payload_round_trips() {
        let payload = test_payload();
        let qr = payload.to_qr().expect("qr");
        assert!(qr.starts_with("MT:"), "{qr}");
        // The packed structure alone is 11 octets: three 3-octet groups and one 2-octet
        // group, so 5 + 5 + 5 + 4 = 19 characters after the prefix.
        assert_eq!(qr.len(), 22, "{qr}");
        assert_eq!(OnboardingPayload::from_qr(&qr).expect("parse"), payload);
    }

    #[test]
    fn a_qr_payload_parses_with_or_without_its_prefix() {
        let qr = test_payload().to_qr().expect("qr");
        let bare = qr.strip_prefix("MT:").expect("prefix");
        assert_eq!(
            OnboardingPayload::from_qr(bare).expect("bare"),
            OnboardingPayload::from_qr(&qr).expect("prefixed")
        );
    }

    #[test]
    fn base38_uses_the_alphabet_of_table_61() {
        // Every character the encoder can produce must be in the QR alphanumeric set.
        const QR_ALPHANUMERIC: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        for c in ALPHABET {
            assert!(QR_ALPHANUMERIC.contains(c), "{}", char::from(*c));
        }
        assert_eq!(ALPHABET.len(), 38);
        // And the removed ones are genuinely absent.
        for removed in b"$%*+/ :" {
            assert!(!ALPHABET.contains(removed), "{}", char::from(*removed));
        }
    }

    #[test]
    fn base38_group_sizes_follow_the_specification() {
        // 3 octets → 5 characters, 2 → 4, 1 → 2.
        for (octets, chars) in [(3usize, 5usize), (2, 4), (1, 2), (6, 10), (11, 19)] {
            let mut out = heapless::String::<64>::new();
            base38_encode(&vec_of(octets), &mut out).expect("encode");
            assert_eq!(out.len(), chars, "{octets} octets");
        }
    }

    fn vec_of(n: usize) -> heapless::Vec<u8, 16> {
        let mut v = heapless::Vec::new();
        for i in 0..n {
            let _ = v.push(i as u8);
        }
        v
    }

    #[test]
    fn base38_round_trips_every_length() {
        for len in 1..=11usize {
            let data = vec_of(len);
            let mut text = heapless::String::<64>::new();
            base38_encode(&data, &mut text).expect("encode");
            let mut back = [0u8; 16];
            let n = base38_decode(&text, &mut back).expect("decode");
            assert_eq!(n, len);
            assert_eq!(&back[..n], &data[..], "length {len}");
        }
    }

    #[test]
    fn base38_refuses_characters_outside_the_alphabet() {
        let mut out = [0u8; 16];
        assert!(base38_decode("ABC$E", &mut out).is_err());
        assert!(base38_decode("abcde", &mut out).is_err(), "lower case");
        // A group of 1 or 3 characters is not a whole number of octets.
        assert!(base38_decode("A", &mut out).is_err());
        assert!(base38_decode("ABC", &mut out).is_err());
    }

    #[test]
    fn the_manual_code_round_trips() {
        let payload = test_payload();
        let code = payload.to_manual_code(false).expect("code");
        assert_eq!(code.len(), 11, "{code}");

        let parsed = OnboardingPayload::from_manual_code(&code).expect("parse");
        assert_eq!(parsed.passcode, payload.passcode);
        // A manual code carries only the top four bits of the discriminator.
        assert_eq!(
            parsed.discriminator >> 8,
            payload.discriminator >> 8,
            "{code}"
        );
        assert_eq!(parsed.discriminator & 0xFF, 0, "the rest are unknown");
    }

    #[test]
    fn the_long_manual_code_carries_vendor_and_product() {
        let mut payload = test_payload();
        payload.custom_flow = CustomFlow::UserIntent;
        let code = payload.to_manual_code(true).expect("code");
        assert_eq!(code.len(), 21, "{code}");

        let parsed = OnboardingPayload::from_manual_code(&code).expect("parse");
        assert_eq!(parsed.vendor_id, payload.vendor_id);
        assert_eq!(parsed.product_id, payload.product_id);
        assert_eq!(parsed.passcode, payload.passcode);
    }

    #[test]
    fn a_non_standard_flow_may_not_use_the_short_code() {
        // §5.1.4.1.2: a commissioner reading a short code "SHALL assume it is a 'standard
        // flow' device", so emitting one for a device that needs user action would make
        // commissioning fail in a way nobody can diagnose.
        let mut payload = test_payload();
        payload.custom_flow = CustomFlow::UserIntent;
        assert!(payload.to_manual_code(false).is_err());
        assert!(payload.to_manual_code(true).is_ok());
    }

    #[test]
    fn the_check_digit_catches_a_single_wrong_digit() {
        // This is what Verhoeff is for: a person typing eleven digits gets one wrong.
        let code = test_payload().to_manual_code(false).expect("code");
        let bytes = code.as_bytes();
        for position in 0..bytes.len() {
            for replacement in b'0'..=b'9' {
                if bytes[position] == replacement {
                    continue;
                }
                let mut broken = heapless::String::<32>::new();
                for (i, b) in bytes.iter().enumerate() {
                    let c = if i == position { replacement } else { *b };
                    let _ = broken.push(char::from(c));
                }
                assert!(
                    OnboardingPayload::from_manual_code(&broken).is_err(),
                    "a wrong digit at {position} was accepted: {broken}"
                );
            }
        }
    }

    #[test]
    fn the_check_digit_catches_a_transposition() {
        // The other mistake people make, and the one a modulo-10 checksum misses.
        let code = test_payload().to_manual_code(false).expect("code");
        let bytes = code.as_bytes();
        for i in 0..bytes.len().saturating_sub(1) {
            if bytes[i] == bytes[i + 1] {
                continue;
            }
            let mut swapped = heapless::String::<32>::new();
            for (j, b) in bytes.iter().enumerate() {
                let c = if j == i {
                    bytes[i + 1]
                } else if j == i + 1 {
                    bytes[i]
                } else {
                    *b
                };
                let _ = swapped.push(char::from(c));
            }
            assert!(
                OnboardingPayload::from_manual_code(&swapped).is_err(),
                "a transposition at {i} was accepted: {swapped}"
            );
        }
    }

    #[test]
    fn dashes_and_spaces_are_tolerated() {
        // §5.1.4.2: "a receiving application seeing the code '1234-567-8910' would need to
        // interpret it as '12345678910'".
        let code = test_payload().to_manual_code(false).expect("code");
        let mut spaced = heapless::String::<32>::new();
        for (i, c) in code.chars().enumerate() {
            if i == 4 || i == 7 {
                let _ = spaced.push('-');
            }
            let _ = spaced.push(c);
        }
        assert_eq!(
            OnboardingPayload::from_manual_code(&spaced).expect("spaced"),
            OnboardingPayload::from_manual_code(&code).expect("plain")
        );
    }

    #[test]
    fn a_manual_code_of_the_wrong_length_is_refused() {
        for text in [
            "",
            "1",
            "1234567890",
            "123456789012",
            "1".repeat(22).as_str(),
        ] {
            assert!(
                OnboardingPayload::from_manual_code(text).is_err(),
                "{text:?} has {} digits",
                text.len()
            );
        }
    }

    #[test]
    fn a_first_digit_of_eight_or_nine_is_a_future_version() {
        // §5.1.4.1.4: "First digit of '8' or '9' would be invalid for v1 and would
        // indicate new format".
        for first in ['8', '9'] {
            let mut code = heapless::String::<32>::new();
            let _ = code.push(first);
            for _ in 0..10 {
                let _ = code.push('0');
            }
            // Whatever the check digit says, the version is what is refused first — so
            // build one with a valid checksum.
            let digits: heapless::Vec<u8, 21> = code.bytes().take(10).map(|b| b - b'0').collect();
            let mut ascii = heapless::String::<32>::new();
            for d in &digits {
                let _ = ascii.push(char::from(b'0' + d));
            }
            let check = verhoeff_check_digit(ascii.as_bytes()).expect("check");
            let _ = ascii.push(char::from(b'0' + check));
            assert_eq!(
                OnboardingPayload::from_manual_code(&ascii)
                    .unwrap_err()
                    .code(),
                ErrorCode::UnsupportedVersion,
                "{ascii}"
            );
        }
    }

    #[test]
    fn the_discriminator_must_fit_twelve_bits() {
        assert!(
            OnboardingPayload::new(
                VendorId(1),
                1,
                0x1000,
                Passcode::new(1).expect("p"),
                DiscoveryCapabilities::empty(),
                CustomFlow::Standard,
            )
            .is_err()
        );
        assert!(
            OnboardingPayload::new(
                VendorId(1),
                1,
                0x0FFF,
                Passcode::new(1).expect("p"),
                DiscoveryCapabilities::empty(),
                CustomFlow::Standard,
            )
            .is_ok()
        );
    }

    #[test]
    fn a_reserved_custom_flow_is_refused() {
        // "3: Reserved". Custom Flow is two bits at offset 35 (3 + 16 + 16), so setting
        // both means bit 35 and bit 36 — byte 4, bits 3 and 4.
        assert_eq!(
            CustomFlow::from_bits(3).unwrap_err().code(),
            ErrorCode::MessageReserved
        );
        let mut packed = test_payload().pack();
        packed[4] |= 0b0001_1000;
        assert_eq!(
            OnboardingPayload::unpack(&packed).unwrap_err().code(),
            ErrorCode::MessageReserved,
            "a payload with the reserved flow must not decode"
        );
    }

    #[test]
    fn every_field_survives_the_round_trip_independently() {
        // A bit-packing bug usually shows as one field bleeding into the next, which a
        // single fixture would miss.
        for discriminator in [0u16, 1, 0x0FF, 0x800, 0x0FFF] {
            for passcode in [1u32, 20_202_021, 99_999_998] {
                for flow in [
                    CustomFlow::Standard,
                    CustomFlow::UserIntent,
                    CustomFlow::Custom,
                ] {
                    let payload = OnboardingPayload::new(
                        VendorId(0xFFF1),
                        0x8001,
                        discriminator,
                        Passcode::new(passcode).expect("passcode"),
                        DiscoveryCapabilities::BLE | DiscoveryCapabilities::ON_IP_NETWORK,
                        flow,
                    )
                    .expect("payload");
                    let qr = payload.to_qr().expect("qr");
                    assert_eq!(
                        OnboardingPayload::from_qr(&qr).expect("parse"),
                        payload,
                        "{discriminator:#x} {passcode} {flow:?}"
                    );
                }
            }
        }
    }
}
