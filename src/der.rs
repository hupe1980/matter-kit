//! A minimal DER reader and writer, for the ASN.1 that Matter cannot avoid.
//!
//! Matter is a TLV protocol and would rather not speak ASN.1 at all, but three things force
//! it to:
//!
//! * an operational certificate's signature is over the **X.509 DER** it stands for, not
//!   over its TLV ([`cert::der`](crate::cert::der), Core §6.5.2);
//! * a Certification Declaration is a **CMS `SignedData`** (§6.3.1);
//! * a Node Operational CSR is a **PKCS#10 `CertificationRequest`** (§6.4.7).
//!
//! So this module exists, and is deliberately the smallest thing that can do those three
//! jobs: definite lengths, the handful of universal tags Matter uses, and context tags by
//! number. There is no OID arc arithmetic, no `ANY`, no BER, no indefinite lengths.
//!
//! # Reading
//!
//! [`DerReader`] walks a sequence of elements in place. It never allocates and never copies:
//! every element's content is a borrow of the input, so a signature can be checked over
//! exactly the bytes that arrived.
//!
//! DER is a *distinguished* encoding — there is one valid encoding per value — and the
//! reader enforces the parts of that which matter for security: a length must be in its
//! shortest form, and a length that runs past the end of its parent is an error rather than
//! a truncation. A parser that accepted a non-minimal length would accept two encodings of
//! the same certificate, which is exactly what a signature is supposed to prevent.
//!
//! # Writing
//!
//! [`DerWriter`] fills its buffer **from the end backwards**, because DER puts each
//! element's length before its content and a forward writer would have to allocate or encode
//! twice. Content is written first; the header is prepended once the length is a known
//! difference of two positions. Every function that uses it therefore emits its fields in
//! reverse order, which is flagged at each call site.

use crate::error::{Error, ErrorCode, Result};

// --- Identifier octets ---------------------------------------------------------------------

/// `BOOLEAN`.
pub const TAG_BOOLEAN: u8 = 0x01;
/// `INTEGER`.
pub const TAG_INTEGER: u8 = 0x02;
/// `BIT STRING`.
pub const TAG_BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// `NULL`.
pub const TAG_NULL: u8 = 0x05;
/// `OBJECT IDENTIFIER`.
pub const TAG_OID: u8 = 0x06;
/// `UTF8String`.
pub const TAG_UTF8_STRING: u8 = 0x0C;
/// `PrintableString`.
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
/// `IA5String`.
pub const TAG_IA5_STRING: u8 = 0x16;
/// `UTCTime`.
pub const TAG_UTC_TIME: u8 = 0x17;
/// `GeneralizedTime`.
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
/// `SEQUENCE`, always constructed.
pub const TAG_SEQUENCE: u8 = 0x30;
/// `SET`, always constructed.
pub const TAG_SET: u8 = 0x31;

/// A context-specific tag, constructed — `[n] EXPLICIT`.
#[must_use]
pub const fn context_constructed(number: u8) -> u8 {
    0xA0 | (number & 0x1F)
}

/// A context-specific tag, primitive — `[n] IMPLICIT` over a primitive type.
#[must_use]
pub const fn context_primitive(number: u8) -> u8 {
    0x80 | (number & 0x1F)
}

// --- Object identifiers Matter uses, as DER content octets ---------------------------------

/// `ecdsa-with-SHA256` — 1.2.840.10045.4.3.2.
pub const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// `id-ecPublicKey` — 1.2.840.10045.2.1.
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `prime256v1` (secp256r1) — 1.2.840.10045.3.1.7.
pub const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `id-sha256` — 2.16.840.1.101.3.4.2.1.
pub const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `id-signedData` — 1.2.840.113549.1.7.2 (RFC 5652 §5.1).
pub const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// `id-data` (`pkcs7-data`) — 1.2.840.113549.1.7.1.
pub const OID_PKCS7_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
/// `extensionRequest` — 1.2.840.113549.1.9.14 (RFC 2985), the PKCS#10 attribute.
pub const OID_EXTENSION_REQUEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];
/// `organizationName` — 2.5.4.10.
pub const OID_ORGANIZATION_NAME: &[u8] = &[0x55, 0x04, 0x0A];
/// `commonName` — 2.5.4.3.
pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// The prefix of every extension OID: `2.5.29`.
pub const OID_CE_PREFIX: &[u8] = &[0x55, 0x1D];
/// The prefix of every `key-purpose-id`: `1.3.6.1.5.5.7.3`.
pub const OID_KP_PREFIX: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03];
/// Matter's private arc, `1.3.6.1.4.1.37244` (Core §6.1.1, Table 85).
///
/// Nothing is issued directly under it; the two sub-arcs below are what certificates use.
pub const OID_MATTER_PREFIX: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C];

/// `1.3.6.1.4.1.37244.1` — the operational distinguished-name attributes, whose final arc
/// is the attribute number: `.1` is `matter-node-id`, `.4` is `matter-rcac-id` (Table 85).
pub const OID_MATTER_DN_PREFIX: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01];

/// `1.3.6.1.4.1.37244.2` — the attestation distinguished-name attributes: `.1` is
/// `matter-oid-vid` and `.2` is `matter-oid-pid` (Table 85, Core §6.2.2.2).
pub const OID_MATTER_ATTESTATION_PREFIX: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02];
/// `domainComponent` — 0.9.2342.19200300.100.1.25.
pub const OID_DOMAIN_COMPONENT: &[u8] =
    &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19];

fn malformed() -> Error {
    Error::new(ErrorCode::DerMalformed)
}

// --- Reading ---------------------------------------------------------------------------------

/// One DER element: its identifier octet and the content it wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element<'a> {
    /// The identifier octet — a [`TAG_SEQUENCE`] or a [`context_constructed`], say.
    pub tag: u8,
    /// The content octets, borrowed from the input.
    pub content: &'a [u8],
    /// The whole element including its header, which is what a signature covers when the
    /// element is a `tbsCertificate` or a `certificationRequestInfo`.
    pub raw: &'a [u8],
}

impl<'a> Element<'a> {
    /// A reader over this element's content, for a constructed type.
    #[must_use]
    pub const fn content_reader(&self) -> DerReader<'a> {
        DerReader::new(self.content)
    }

    /// The content as a `BIT STRING`'s bits, refusing any that are not whole octets.
    ///
    /// A `BIT STRING`'s first content octet counts the unused bits in its last octet.
    /// Everything Matter puts in one — a public key, a signature — is whole octets, so a
    /// non-zero count is a malformed encoding rather than something to round.
    pub fn bit_string_octets(&self) -> Result<&'a [u8]> {
        if self.tag != TAG_BIT_STRING {
            return Err(malformed());
        }
        match self.content.split_first() {
            Some((0, rest)) => Ok(rest),
            _ => Err(malformed()),
        }
    }
}

/// A cursor over a sequence of DER elements.
#[derive(Debug, Clone)]
pub struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    /// Starts reading at the beginning of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Whether every element has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The octets not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// Returns the next element's identifier octet without consuming it.
    #[must_use]
    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Reads the next element, whatever it is.
    pub fn next_element(&mut self) -> Result<Element<'a>> {
        let start = self.pos;
        let tag = *self.buf.get(self.pos).ok_or_else(malformed)?;
        // A tag of 0x1F in the low five bits introduces a multi-octet tag number. Nothing
        // Matter uses needs one, and accepting them would mean accepting structures this
        // module cannot round-trip.
        if tag & 0x1F == 0x1F {
            return Err(Error::new(ErrorCode::Unsupported));
        }
        let mut at = self.pos.checked_add(1).ok_or_else(malformed)?;

        let first = *self.buf.get(at).ok_or_else(malformed)?;
        at = at.checked_add(1).ok_or_else(malformed)?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7F);
            // 0x80 is BER's indefinite length, which DER forbids; more than four octets is
            // a length no buffer this crate handles could hold.
            if count == 0 || count > 4 {
                return Err(malformed());
            }
            let end = at.checked_add(count).ok_or_else(malformed)?;
            let octets = self.buf.get(at..end).ok_or_else(malformed)?;
            // DER requires the shortest form: a length below 128 must use the single-octet
            // form, and a multi-octet length must not have a leading zero.
            if octets.first() == Some(&0) {
                return Err(malformed());
            }
            let mut value = 0usize;
            for byte in octets {
                value = value
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(usize::from(*byte)))
                    .ok_or_else(malformed)?;
            }
            if value < 0x80 {
                return Err(malformed());
            }
            at = end;
            value
        };

        let end = at.checked_add(len).ok_or_else(malformed)?;
        let content = self.buf.get(at..end).ok_or_else(malformed)?;
        let raw = self.buf.get(start..end).ok_or_else(malformed)?;
        self.pos = end;
        Ok(Element { tag, content, raw })
    }

    /// Reads the next element and requires it to have this identifier octet.
    pub fn expect(&mut self, tag: u8) -> Result<Element<'a>> {
        let element = self.next_element()?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(malformed())
        }
    }

    /// Reads a `SEQUENCE` and returns a reader over its members.
    pub fn expect_sequence(&mut self) -> Result<Self> {
        Ok(self.expect(TAG_SEQUENCE)?.content_reader())
    }

    /// Reads a `SET` and returns a reader over its members.
    pub fn expect_set(&mut self) -> Result<Self> {
        Ok(self.expect(TAG_SET)?.content_reader())
    }

    /// Reads an `OBJECT IDENTIFIER` and requires it to be `expected`.
    pub fn expect_oid(&mut self, expected: &[u8]) -> Result<()> {
        if self.expect(TAG_OID)?.content == expected {
            Ok(())
        } else {
            Err(malformed())
        }
    }

    /// Reads a non-negative `INTEGER` and returns its magnitude with the sign octet removed.
    ///
    /// DER's `INTEGER` is two's-complement and minimally encoded, which means a positive
    /// value whose top bit is set carries a leading `0x00` so that it does not read as
    /// negative. That octet is part of the encoding, not of the number, so a 256-bit scalar
    /// arrives as 33 octets about half the time.
    ///
    /// Both minimality rules are enforced: a leading `0x00` is legal only when the next
    /// octet has its top bit set, and a leading `0x80`-or-above is a negative number.
    pub fn expect_unsigned(&mut self) -> Result<&'a [u8]> {
        let content = self.expect(TAG_INTEGER)?.content;
        let (first, rest) = content.split_first().ok_or_else(malformed)?;
        if *first & 0x80 != 0 {
            // Negative. Nothing Matter encodes as an INTEGER is.
            return Err(malformed());
        }
        if *first == 0 && rest.first().is_some_and(|b| *b < 0x80) {
            // A leading zero that was not needed: not the distinguished encoding.
            return Err(malformed());
        }
        Ok(if *first == 0 { rest } else { content })
    }

    /// Reads a non-negative `INTEGER` that must fit in a `u64`.
    pub fn expect_uint(&mut self) -> Result<u64> {
        let magnitude = self.expect_unsigned()?;
        if magnitude.len() > 8 {
            return Err(malformed());
        }
        let mut value = 0u64;
        for byte in magnitude {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(*byte)))
                .ok_or_else(malformed)?;
        }
        Ok(value)
    }

    /// Reads the next element only if it has this identifier octet.
    ///
    /// This is how an `OPTIONAL` or a `DEFAULT` field is read: a look before the leap, since
    /// what follows an absent field is the *next* field and consuming it would desynchronise
    /// the parse.
    pub fn take_if(&mut self, tag: u8) -> Result<Option<Element<'a>>> {
        if self.peek_tag() == Some(tag) {
            Ok(Some(self.next_element()?))
        } else {
            Ok(None)
        }
    }

    /// Requires every element to have been consumed.
    ///
    /// Trailing octets after a complete structure are not a harmless suffix: in a signed
    /// document they are data the signature does not cover.
    pub fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(malformed())
        }
    }
}

// --- Writing ----------------------------------------------------------------------------------

/// A DER writer that fills its buffer from the end backwards, so that a length is always
/// known by the time its header is written.
#[derive(Debug)]
pub struct DerWriter<'a> {
    buf: &'a mut [u8],
    /// The index of the first byte written; everything from here to the end is output.
    pos: usize,
}

impl<'a> DerWriter<'a> {
    /// Starts writing at the end of `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        let pos = buf.len();
        Self { buf, pos }
    }

    /// How many octets have been written.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether nothing has been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Everything written, in the right order — the tail of the buffer.
    #[must_use]
    pub fn finish(self) -> &'a [u8] {
        let pos = self.pos;
        self.buf.get(pos..).unwrap_or(&[])
    }

    /// The current position, to be passed to [`DerWriter::header`] once an element's content
    /// has been written.
    #[must_use]
    pub const fn mark(&self) -> usize {
        self.pos
    }

    /// Prepends one octet.
    pub fn byte(&mut self, value: u8) -> Result<()> {
        let next = self
            .pos
            .checked_sub(1)
            .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
        let Some(slot) = self.buf.get_mut(next) else {
            return Err(Error::new(ErrorCode::BufferTooSmall));
        };
        *slot = value;
        self.pos = next;
        Ok(())
    }

    /// Prepends a slice.
    pub fn slice(&mut self, value: &[u8]) -> Result<()> {
        let next = self
            .pos
            .checked_sub(value.len())
            .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
        let Some(slot) = self.buf.get_mut(next..self.pos) else {
            return Err(Error::new(ErrorCode::BufferTooSmall));
        };
        slot.copy_from_slice(value);
        self.pos = next;
        Ok(())
    }

    /// Writes an identifier octet and the definite length of everything written since
    /// `mark`, in DER's minimal form.
    pub fn header(&mut self, tag: u8, mark: usize) -> Result<()> {
        let len = mark
            .checked_sub(self.pos)
            .ok_or_else(|| Error::new(ErrorCode::BufferTooSmall))?;
        // Lengths below 128 are a single octet; above, a count of length octets with the
        // high bit set, then the length big-endian with no leading zeros.
        if len < 0x80 {
            let short = u8::try_from(len).map_err(|_| malformed())?;
            self.byte(short)?;
        } else {
            let bytes = len.to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
            let significant = bytes.get(first..).unwrap_or(&[]);
            self.slice(significant)?;
            let count = u8::try_from(significant.len()).map_err(|_| malformed())?;
            self.byte(0x80 | count)?;
        }
        self.byte(tag)
    }

    /// Writes a complete primitive element.
    pub fn primitive(&mut self, tag: u8, content: &[u8]) -> Result<()> {
        let mark = self.mark();
        self.slice(content)?;
        self.header(tag, mark)
    }

    /// Writes an OID whose content is a prefix plus one final arc below 128.
    pub fn oid_with_arc(&mut self, prefix: &[u8], arc: u8) -> Result<()> {
        let mark = self.mark();
        self.byte(arc)?;
        self.slice(prefix)?;
        self.header(TAG_OID, mark)
    }

    /// Writes a `BIT STRING` whose content is whole octets — a public key or a signature.
    pub fn bit_string(&mut self, octets: &[u8]) -> Result<()> {
        let mark = self.mark();
        self.slice(octets)?;
        // The count of unused bits in the final octet; zero for whole octets.
        self.byte(0)?;
        self.header(TAG_BIT_STRING, mark)
    }

    /// Writes a fixed-width big-endian scalar as an `INTEGER`: leading zeros dropped, and
    /// one `0x00` put back if the top bit would otherwise make it negative.
    pub fn unsigned_integer(&mut self, scalar: &[u8]) -> Result<()> {
        let first = scalar
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(scalar.len().saturating_sub(1));
        let trimmed = scalar.get(first..).unwrap_or(&[0]);
        let mark = self.mark();
        self.slice(trimmed)?;
        if trimmed.first().is_some_and(|b| *b & 0x80 != 0) {
            self.byte(0)?;
        }
        self.header(TAG_INTEGER, mark)
    }

    /// Writes an `AlgorithmIdentifier` with no parameters — `SEQUENCE { OID }`.
    ///
    /// `ecdsa-with-SHA256` and `sha256` both take this form. An `AlgorithmIdentifier` with a
    /// spurious `NULL` here would hash differently and fail every signature.
    pub fn algorithm_identifier(&mut self, oid: &[u8]) -> Result<()> {
        let mark = self.mark();
        self.primitive(TAG_OID, oid)?;
        self.header(TAG_SEQUENCE, mark)
    }

    /// Writes a `SubjectPublicKeyInfo` for an uncompressed P-256 point.
    pub fn subject_public_key_info(&mut self, public_key: &[u8]) -> Result<()> {
        let mark = self.mark();
        self.bit_string(public_key)?;
        let algo = self.mark();
        self.primitive(TAG_OID, OID_PRIME256V1)?;
        self.primitive(TAG_OID, OID_EC_PUBLIC_KEY)?;
        self.header(TAG_SEQUENCE, algo)?;
        self.header(TAG_SEQUENCE, mark)
    }

    /// Writes an `ECDSA-Sig-Value` — `SEQUENCE { r INTEGER, s INTEGER }` — from the
    /// fixed-width `r || s` that Core §3.5.3 uses.
    pub fn ecdsa_sig_value(&mut self, raw: &[u8]) -> Result<()> {
        let half = raw.len().checked_div(2).ok_or_else(malformed)?;
        let (r, s) = raw.split_at(half);
        let mark = self.mark();
        self.unsigned_integer(s)?;
        self.unsigned_integer(r)?;
        self.header(TAG_SEQUENCE, mark)
    }
}

/// Reads an `ECDSA-Sig-Value` back into the fixed-width `r || s` of Core §3.5.3.
///
/// The DER form drops leading zeros and may add one, so neither integer is a fixed width;
/// this puts each back into its 32-octet slot right-aligned.
pub fn ecdsa_sig_value_to_raw(der: &[u8], out: &mut [u8; 64]) -> Result<()> {
    let mut reader = DerReader::new(der);
    let mut seq = reader.expect_sequence()?;
    reader.finish()?;
    for half in 0..2usize {
        let value = seq.expect_unsigned()?;
        if value.len() > 32 {
            return Err(malformed());
        }
        let start = half
            .checked_mul(32)
            .and_then(|s| s.checked_add(32))
            .and_then(|e| e.checked_sub(value.len()))
            .ok_or_else(malformed)?;
        let end = start.checked_add(value.len()).ok_or_else(malformed)?;
        out.get_mut(start..end)
            .ok_or_else(malformed)?
            .copy_from_slice(value);
    }
    seq.finish()?;
    Ok(())
}

// --- Time -------------------------------------------------------------------------------------

/// Seconds between the Unix epoch and the Matter epoch of 2000-01-01 00:00:00 UTC.
///
/// Matter times are `epoch-s` (Core §6.5.7), so a certificate's `not-before` of `0x271B17EF`
/// is 2020-10-15 14:23:43 UTC — as the corresponding X.509 certificate's `UTCTime` says.
pub const MATTER_EPOCH_UNIX: i64 = 946_684_800;

/// The year at which X.509 switches from `UTCTime` to `GeneralizedTime` (RFC 5280 §4.1.2.5).
pub const GENERALIZED_TIME_FROM: u32 = 2050;

/// A civil date and time, broken out of a Matter `epoch-s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    /// The full year, e.g. 2020.
    pub year: u32,
    /// 1 through 12.
    pub month: u32,
    /// 1 through 31.
    pub day: u32,
    /// 0 through 23.
    pub hour: u32,
    /// 0 through 59.
    pub minute: u32,
    /// 0 through 59; leap seconds are not represented.
    pub second: u32,
}

/// Converts a Matter `epoch-s` to a civil UTC date, by Howard Hinnant's `civil_from_days`.
///
/// The algorithm shifts the epoch to 0000-03-01 so that February's leap day lands at the
/// end of a "year", which makes the whole thing branch-free arithmetic rather than a table
/// of month lengths.
///
/// The plain arithmetic is deliberate and bounded. The input is a `u32`, so `unix` is at
/// most about 5.2e9 and `days` at most about 60 000; every intermediate below stays under
/// 2e8 in an `i64` whose range is 9.2e18. Rewriting the expressions with `checked_*` would
/// obscure an algorithm whose correctness rests on being read against its published form,
/// in exchange for branches that can never be taken.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "every intermediate is bounded by the u32 input; see above"
)]
pub fn civil_from_epoch_s(epoch_s: u32) -> Result<Civil> {
    let unix = i64::from(epoch_s)
        .checked_add(MATTER_EPOCH_UNIX)
        .ok_or_else(malformed)?;
    let days = unix.div_euclid(86_400);
    let secs_of_day = unix.rem_euclid(86_400);

    let z = days.checked_add(719_468).ok_or_else(malformed)?;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    Ok(Civil {
        year: u32::try_from(year).map_err(|_| malformed())?,
        month: u32::try_from(m).map_err(|_| malformed())?,
        day: u32::try_from(d).map_err(|_| malformed())?,
        hour: u32::try_from(secs_of_day / 3600).map_err(|_| malformed())?,
        minute: u32::try_from((secs_of_day / 60) % 60).map_err(|_| malformed())?,
        second: u32::try_from(secs_of_day % 60).map_err(|_| malformed())?,
    })
}

/// A `Time`: `UTCTime` before 2050, `GeneralizedTime` from 2050 on (RFC 5280 §4.1.2.5).
pub fn write_time(writer: &mut DerWriter<'_>, epoch_s: u32) -> Result<()> {
    let civil = civil_from_epoch_s(epoch_s)?;
    let mut out = [0u8; 15];
    if civil.year < GENERALIZED_TIME_FROM {
        // YYMMDDHHMMSSZ
        let digits = out.get_mut(..13).ok_or_else(malformed)?;
        write_two(digits, 0, civil.year % 100)?;
        write_two(digits, 2, civil.month)?;
        write_two(digits, 4, civil.day)?;
        write_two(digits, 6, civil.hour)?;
        write_two(digits, 8, civil.minute)?;
        write_two(digits, 10, civil.second)?;
        *digits.get_mut(12).ok_or_else(malformed)? = b'Z';
        writer.primitive(TAG_UTC_TIME, digits)
    } else {
        // YYYYMMDDHHMMSSZ
        write_two(&mut out, 0, civil.year / 100)?;
        write_two(&mut out, 2, civil.year % 100)?;
        write_two(&mut out, 4, civil.month)?;
        write_two(&mut out, 6, civil.day)?;
        write_two(&mut out, 8, civil.hour)?;
        write_two(&mut out, 10, civil.minute)?;
        write_two(&mut out, 12, civil.second)?;
        *out.get_mut(14).ok_or_else(malformed)? = b'Z';
        writer.primitive(TAG_GENERALIZED_TIME, &out)
    }
}

fn write_two(out: &mut [u8], at: usize, value: u32) -> Result<()> {
    if value > 99 {
        return Err(malformed());
    }
    let tens = u8::try_from(value / 10).map_err(|_| malformed())?;
    let ones = u8::try_from(value % 10).map_err(|_| malformed())?;
    *out.get_mut(at).ok_or_else(malformed)? = b'0'.wrapping_add(tens);
    *out.get_mut(at.checked_add(1).ok_or_else(malformed)?)
        .ok_or_else(malformed)? = b'0'.wrapping_add(ones);
    Ok(())
}

/// The Matter `epoch-s` of a civil UTC date, by Howard Hinnant's `days_from_civil`.
///
/// The inverse of [`civil_from_epoch_s`], and the direction an X.509 `UTCTime` has to go:
/// a DAC's `notBefore` is a printed date, and chain validation happens "with respect to the
/// notBefore timestamp of the DAC" (Core §6.2.3.1).
///
/// Returns `None` for a date before the Matter epoch of 2000-01-01 or beyond what a `u32`
/// of seconds can reach — which includes X.509's `99991231235959Z` "no expiry" value, so a
/// caller must handle that separately rather than treat it as an error.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "every intermediate is bounded by the validated field widths; see civil_from_epoch_s"
)]
#[must_use]
pub fn epoch_s_from_civil(civil: &Civil) -> Option<u32> {
    if civil.month < 1 || civil.month > 12 || civil.day < 1 || civil.day > 31 {
        return None;
    }
    if civil.hour > 23 || civil.minute > 59 || civil.second > 59 {
        return None;
    }
    let y = i64::from(civil.year) - i64::from(civil.month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(civil.month);
    let d = i64::from(civil.day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;

    let secs = days * 86_400
        + i64::from(civil.hour) * 3600
        + i64::from(civil.minute) * 60
        + i64::from(civil.second);
    u32::try_from(secs - MATTER_EPOCH_UNIX).ok()
}

/// The `GeneralizedTime` X.509 uses for "no well-defined expiration date" (RFC 5280
/// §4.1.2.5), which Matter's `not-after` represents as zero (Core §6.5.7).
pub const NO_EXPIRY: &[u8] = b"99991231235959Z";

/// Reads an X.509 `Time` — a `UTCTime` or a `GeneralizedTime` — as a Matter `epoch-s`.
///
/// Only the `Z` forms are accepted. RFC 5280 §4.1.2.5 requires them: "values MUST be
/// expressed in Greenwich Mean Time (Zulu)", and a local-time offset would make two
/// certificates with the same printed date compare differently.
///
/// Returns `Ok(None)` for the `99991231235959Z` that means no expiry, which is a value
/// rather than an error: a PAA carries it routinely.
pub fn read_time(element: &Element<'_>) -> Result<Option<u32>> {
    let (text, century_from_yy) = match element.tag {
        TAG_UTC_TIME => (element.content, true),
        TAG_GENERALIZED_TIME => (element.content, false),
        _ => return Err(malformed()),
    };
    if text == NO_EXPIRY {
        return Ok(None);
    }
    let expected = if century_from_yy { 13 } else { 15 };
    if text.len() != expected || text.last() != Some(&b'Z') {
        return Err(malformed());
    }

    let mut at = 0usize;
    let mut take = |digits: usize| -> Result<u32> {
        let end = at.checked_add(digits).ok_or_else(malformed)?;
        let slot = text.get(at..end).ok_or_else(malformed)?;
        at = end;
        let mut value = 0u32;
        for byte in slot {
            let digit = byte
                .checked_sub(b'0')
                .filter(|d| *d < 10)
                .ok_or_else(malformed)?;
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u32::from(digit)))
                .ok_or_else(malformed)?;
        }
        Ok(value)
    };

    let year = if century_from_yy {
        let yy = take(2)?;
        // RFC 5280 §4.1.2.5.1: "Where YY is greater than or equal to 50, the year SHALL be
        // interpreted as 19YY; and where YY is less than 50, as 20YY."
        if yy >= 50 {
            yy.saturating_add(1900)
        } else {
            yy.saturating_add(2000)
        }
    } else {
        take(4)?
    };
    let civil = Civil {
        year,
        month: take(2)?,
        day: take(2)?,
        hour: take(2)?,
        minute: take(2)?,
        second: take(2)?,
    };
    epoch_s_from_civil(&civil).map(Some).ok_or_else(malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_form_length_reads() {
        let mut reader = DerReader::new(&[0x02, 0x01, 0x2A]);
        let element = reader.next_element().expect("element");
        assert_eq!(element.tag, TAG_INTEGER);
        assert_eq!(element.content, &[0x2A]);
        assert_eq!(element.raw, &[0x02, 0x01, 0x2A]);
        reader.finish().expect("consumed");
    }

    #[test]
    fn a_long_form_length_reads() {
        let mut bytes = [0u8; 132];
        bytes[0] = TAG_OCTET_STRING;
        bytes[1] = 0x81;
        bytes[2] = 129;
        let mut reader = DerReader::new(&bytes);
        assert_eq!(reader.next_element().expect("element").content.len(), 129);
    }

    #[test]
    fn a_non_minimal_length_is_refused() {
        // DER has exactly one encoding per value. Accepting a second one would mean two
        // byte strings that are the same certificate — and a signature over only one.
        for bytes in [
            // 0x81 0x01: the long form for a length that fits the short form.
            &[0x04, 0x81, 0x01, 0xAA][..],
            // A leading zero in a multi-octet length.
            &[0x04, 0x82, 0x00, 0x01, 0xAA][..],
            // 0x80: BER's indefinite length, which DER forbids.
            &[0x30, 0x80, 0x00, 0x00][..],
        ] {
            assert!(
                DerReader::new(bytes).next_element().is_err(),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn a_length_past_the_end_is_an_error_not_a_truncation() {
        assert!(DerReader::new(&[0x04, 0x05, 0xAA]).next_element().is_err());
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let full = [0x30, 0x06, 0x02, 0x01, 0x2A, 0x04, 0x01, 0xFF];
        for len in 0..full.len() {
            let mut reader = DerReader::new(&full[..len]);
            // Either it errors, or it reads fewer complete elements — never panics.
            while let Ok(element) = reader.next_element() {
                let _ = element;
            }
        }
    }

    #[test]
    fn a_multi_octet_tag_is_refused_rather_than_misread() {
        // Nothing in Matter needs one, and silently skipping it would desynchronise a parse
        // that a signature is computed over.
        assert_eq!(
            DerReader::new(&[0x1F, 0x81, 0x00, 0x00])
                .next_element()
                .map(|_| ())
                .unwrap_err()
                .code(),
            ErrorCode::Unsupported
        );
    }

    #[test]
    fn integers_are_read_as_der_defines_them() {
        // Minimal, non-negative, and the sign octet stripped.
        let cases: &[(&[u8], Option<u64>)] = &[
            (&[0x02, 0x01, 0x00], Some(0)),
            (&[0x02, 0x01, 0x7F], Some(127)),
            (&[0x02, 0x02, 0x00, 0x80], Some(128)),
            (&[0x02, 0x02, 0x01, 0x00], Some(256)),
            // Negative.
            (&[0x02, 0x01, 0x80], None),
            // A redundant leading zero.
            (&[0x02, 0x02, 0x00, 0x01], None),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                DerReader::new(bytes).expect_uint().ok(),
                *expected,
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn a_bit_string_with_unused_bits_is_refused() {
        // Everything Matter puts in a BIT STRING is whole octets.
        let element = DerReader::new(&[0x03, 0x02, 0x00, 0xAB])
            .next_element()
            .expect("element");
        assert_eq!(element.bit_string_octets().expect("octets"), &[0xAB]);

        let element = DerReader::new(&[0x03, 0x02, 0x04, 0xB0])
            .next_element()
            .expect("element");
        assert!(element.bit_string_octets().is_err());
    }

    #[test]
    fn take_if_does_not_consume_the_wrong_element() {
        // An absent OPTIONAL field is followed by the next field, so a reader that consumed
        // before looking would lose it.
        let mut reader = DerReader::new(&[0x02, 0x01, 0x07, 0x04, 0x01, 0xFF]);
        assert!(reader.take_if(TAG_OCTET_STRING).expect("look").is_none());
        assert_eq!(reader.expect_uint().expect("int"), 7);
        assert_eq!(
            reader
                .take_if(TAG_OCTET_STRING)
                .expect("look")
                .expect("present")
                .content,
            &[0xFF]
        );
    }

    #[test]
    fn trailing_octets_are_refused() {
        // In a signed document, a trailing suffix is data the signature does not cover.
        let mut reader = DerReader::new(&[0x02, 0x01, 0x07, 0xFF]);
        reader.expect_uint().expect("int");
        assert!(reader.finish().is_err());
    }

    #[test]
    fn the_writer_and_the_reader_agree() {
        let mut buf = [0u8; 128];
        let mut w = DerWriter::new(&mut buf);
        let mark = w.mark();
        // Reverse order, as the writer requires.
        w.primitive(TAG_OCTET_STRING, &[0xDE, 0xAD])
            .expect("octets");
        w.primitive(TAG_INTEGER, &[0x2A]).expect("int");
        w.header(TAG_SEQUENCE, mark).expect("sequence");
        let bytes = w.finish();
        assert_eq!(
            bytes,
            &[0x30, 0x07, 0x02, 0x01, 0x2A, 0x04, 0x02, 0xDE, 0xAD]
        );

        let mut reader = DerReader::new(bytes);
        let mut seq = reader.expect_sequence().expect("sequence");
        assert_eq!(seq.expect_uint().expect("int"), 42);
        assert_eq!(
            seq.expect(TAG_OCTET_STRING).expect("octets").content,
            &[0xDE, 0xAD]
        );
        seq.finish().expect("consumed");
        reader.finish().expect("consumed");
    }

    #[test]
    fn a_signature_survives_the_round_trip_through_der() {
        // The fixed-width r || s of §3.5.3 and DER's minimal INTEGERs are different shapes,
        // and a value with a high top byte or leading zeros exercises both directions.
        let cases: [[u8; 64]; 4] = [
            [0x01; 64],
            [0xFF; 64],
            {
                let mut v = [0u8; 64];
                v[31] = 1;
                v[63] = 2;
                v
            },
            {
                let mut v = [0x7Fu8; 64];
                v[0] = 0x80;
                v[32] = 0x00;
                v
            },
        ];
        for raw in cases {
            let mut buf = [0u8; 128];
            let mut w = DerWriter::new(&mut buf);
            w.ecdsa_sig_value(&raw).expect("write");
            let der = w.finish();
            let mut back = [0u8; 64];
            ecdsa_sig_value_to_raw(der, &mut back).expect("read");
            assert_eq!(back, raw, "{raw:02x?}");
        }
    }

    #[test]
    fn the_two_time_directions_are_inverses() {
        // A date that survives epoch -> civil -> epoch is one where neither the leap-year
        // arithmetic nor the month table went wrong. Stepping by a prime number of seconds
        // lands on every weekday, month length and leap boundary over 60 years.
        let mut at = 0u32;
        while at < 1_900_000_000 {
            let civil = civil_from_epoch_s(at).expect("civil");
            assert_eq!(epoch_s_from_civil(&civil), Some(at), "{at}");
            at = at.saturating_add(1_000_003);
        }
    }

    #[test]
    fn leap_days_land_where_they_should() {
        // 2000 is a leap year (divisible by 400), 2100 would not be (divisible by 100 but
        // not 400) — the case a naive rule gets wrong, and the reason the algorithm shifts
        // its epoch to March.
        let cases = [
            (0u32, 2000, 1, 1),
            (59 * 86_400, 2000, 2, 29),
            (60 * 86_400, 2000, 3, 1),
            (365 * 86_400, 2000, 12, 31),
            (366 * 86_400, 2001, 1, 1),
        ];
        for (epoch, year, month, day) in cases {
            let civil = civil_from_epoch_s(epoch).expect("civil");
            assert_eq!(
                (civil.year, civil.month, civil.day),
                (year, month, day),
                "{epoch}"
            );
        }
    }

    #[test]
    fn an_x509_time_reads_as_the_spec_prints_it() {
        // The RCAC of Core §6.5.15.1 carries `170d 3230313031353134323334335a`, which
        // openssl prints as "Oct 15 14:23:43 2020 GMT" and whose Matter epoch-s the TLV
        // gives as 0x271B17EF.
        let element = DerReader::new(&[
            0x17, 0x0D, b'2', b'0', b'1', b'0', b'1', b'5', b'1', b'4', b'2', b'3', b'4', b'3',
            b'Z',
        ])
        .next_element()
        .expect("element");
        assert_eq!(read_time(&element).expect("time"), Some(0x271B_17EF));
    }

    #[test]
    fn a_two_digit_year_uses_rfc_5280s_pivot() {
        // "Where YY is greater than or equal to 50, the year SHALL be interpreted as 19YY;
        // and where YY is less than 50, as 20YY." A 19xx date is before the Matter epoch and
        // therefore has no epoch-s, which is an error rather than a wrap to a huge value.
        let mut bytes = [
            0x17, 0x0D, b'4', b'9', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0',
            b'Z',
        ];
        let element = DerReader::new(&bytes).next_element().expect("element");
        let civil =
            civil_from_epoch_s(read_time(&element).expect("time").expect("a time")).expect("civil");
        assert_eq!(civil.year, 2049);

        bytes[2] = b'5';
        bytes[3] = b'0';
        let element = DerReader::new(&bytes).next_element().expect("element");
        assert!(
            read_time(&element).is_err(),
            "1950 is before the Matter epoch"
        );
    }

    #[test]
    fn the_no_expiry_time_is_a_value_not_an_error() {
        // A PAA routinely carries 99991231235959Z, and treating it as a malformed date would
        // make every attestation chain fail at its root.
        let mut bytes = [0u8; 17];
        bytes[0] = TAG_GENERALIZED_TIME;
        bytes[1] = 15;
        bytes[2..17].copy_from_slice(NO_EXPIRY);
        let element = DerReader::new(&bytes).next_element().expect("element");
        assert_eq!(read_time(&element).expect("time"), None);
    }

    #[test]
    fn a_time_that_is_not_zulu_is_refused() {
        // RFC 5280 §4.1.2.5: "values MUST be expressed in Greenwich Mean Time (Zulu)". An
        // offset would make two certificates with the same printed date compare differently.
        let element = DerReader::new(&[
            0x17, 0x0D, b'2', b'0', b'1', b'0', b'1', b'5', b'1', b'4', b'2', b'3', b'4', b'3',
            b'+',
        ])
        .next_element()
        .expect("element");
        assert!(read_time(&element).is_err());
    }

    #[test]
    fn a_time_with_a_non_digit_is_refused() {
        let element = DerReader::new(&[
            0x17, 0x0D, b'2', b'0', b'1', b'0', b'1', b'5', b'1', b'4', b'2', b'3', b'4', b'x',
            b'Z',
        ])
        .next_element()
        .expect("element");
        assert!(read_time(&element).is_err());
    }

    #[test]
    fn a_buffer_that_is_too_small_is_an_error_at_every_length() {
        let mut full = [0u8; 32];
        let written = {
            let mut w = DerWriter::new(&mut full);
            w.primitive(TAG_OCTET_STRING, &[0xAA; 8]).expect("write");
            w.len()
        };
        for len in 0..written {
            let mut small = [0u8; 32];
            let slot = small.get_mut(..len).expect("in range");
            let mut w = DerWriter::new(slot);
            assert!(w.primitive(TAG_OCTET_STRING, &[0xAA; 8]).is_err(), "{len}");
        }
    }
}
