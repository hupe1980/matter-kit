//! Encrypting and decrypting a Matter message (Core §4.8, §4.9).
//!
//! Everything above the message header travels encrypted, and the header itself travels
//! *authenticated but in the clear* — a receiver has to read the Session ID before it can
//! find the key. That is why the header is the AEAD's associated data rather than part of
//! its payload: changing a single bit of it breaks the tag, but anyone can still read it.
//!
//! ```text
//!  ┌──────────── associated data (authenticated, clear) ────────────┐┌ encrypted ┐┌ tag ┐
//!  │ flags │ session │ sec │ counter │ [source] │ [dest] │ [ext]    ││  payload  ││ MIC │
//!  └───────┴─────────┴─────┴─────────┴──────────┴────────┴──────────┘└───────────┘└─────┘
//!           ╰──── never obfuscated ────╯╰─── obfuscated when P is set ───╯
//! ```
//!
//! # Privacy
//!
//! With the **P** flag set, the counter and node ids are additionally obfuscated with
//! AES-CTR under a key derived from the encryption key (§4.9). This does not add
//! confidentiality — they are already authenticated, and an attacker who has the key can
//! read them either way — it removes a *correlation handle*: without it, a passive observer
//! can follow one node across a network by its monotonically increasing counter.
//!
//! The first four octets are deliberately outside the obfuscation, because a receiver must
//! read the Session ID to know which key to try.
//!
//! # The nonce, and why it is an enum
//!
//! §4.8.1.1 gives three different answers for the nonce's Source Node ID depending on the
//! session: a CASE session uses the peer's operational id from the session context, a PASE
//! session uses the Unspecified Node ID, and a group message uses the id in the message.
//! Passing a bare `NodeId` would make all three look the same at the call site and let a
//! caller silently pick the wrong one — so [`NonceSource`] names them.

use super::header::{Destination, MessageHeader, SessionType};
use super::ids::NodeId;
use crate::crypto::{
    AEAD_MIC_LENGTH_BYTES, AEAD_NONCE_LENGTH_BYTES, SymmetricKey, aead_decrypt_in_place,
    aead_encrypt_in_place, privacy_key, privacy_xor,
};
use crate::error::{Error, ErrorCode, Result, bail};

/// The keys one session protects its messages with.
///
/// The privacy key is derived from the encryption key once, at session establishment,
/// rather than per message: it is a KDF call, and doing it on every send would be visible
/// on a microcontroller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// The AEAD key for this direction (§4.8).
    pub encryption: SymmetricKey,
    /// The AES-CTR key for header obfuscation (§4.9.1).
    pub privacy: SymmetricKey,
}

impl SessionKeys {
    /// Derives the privacy key from an encryption key (§4.9.1).
    pub fn from_encryption_key(encryption: SymmetricKey) -> Result<Self> {
        let privacy = privacy_key(&encryption)?;
        Ok(Self {
            encryption,
            privacy,
        })
    }
}

/// Where the Source Node ID in the AEAD nonce comes from (§4.8.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceSource {
    /// A PASE session: "the Nonce Source Node ID SHALL be Unspecified Node ID".
    ///
    /// Safe despite being a constant, and the specification says why: "Because PASE
    /// negotiates strong one-time keys per session and the I2RKey and R2IKey are distinct
    /// for each direction of communication, the use of the Unspecified Node ID as the
    /// Nonce Source Node ID remains semantically secure."
    Pase,
    /// A CASE session: "determined via the Secure Session Context associated with the
    /// Session Identifier" — the operational Node ID of whoever protected the message.
    Case(NodeId),
    /// A group message: the Source Node ID carried in the message itself.
    ///
    /// "The S Flag of the message SHALL be 1 … If the S Flag of the message is 0 the
    /// message SHALL be dropped."
    Group,
}

impl NonceSource {
    fn resolve(self, header: &MessageHeader) -> Result<NodeId> {
        match self {
            Self::Pase => Ok(NodeId::UNSPECIFIED),
            Self::Case(id) => Ok(id),
            Self::Group => header.source.ok_or(Error::new(ErrorCode::MessageReserved)),
        }
    }
}

/// Builds the AEAD nonce of Table 17: `Security Flags || Message Counter || Source Node ID`.
///
/// "The scalar fields in the nonce … SHALL be encoded in little-endian byte order … that
/// is, in the same byte ordering as the segment of the message from which its data
/// originates."
fn nonce(
    security_flags: u8,
    message_counter: u32,
    source: NodeId,
) -> [u8; AEAD_NONCE_LENGTH_BYTES] {
    let mut out = [0u8; AEAD_NONCE_LENGTH_BYTES];
    out[0] = security_flags;
    // Indices are constant and within a 13-octet array.
    if let Some(slot) = out.get_mut(1..5) {
        slot.copy_from_slice(&message_counter.to_le_bytes());
    }
    if let Some(slot) = out.get_mut(5..13) {
        slot.copy_from_slice(&source.0.to_le_bytes());
    }
    out
}

/// Builds the privacy nonce of §4.9.2: `Session ID (big-endian) || MIC[5..16]`.
fn privacy_nonce(
    session_id: u16,
    mic: &[u8; AEAD_MIC_LENGTH_BYTES],
) -> Result<[u8; AEAD_NONCE_LENGTH_BYTES]> {
    let mut out = [0u8; AEAD_NONCE_LENGTH_BYTES];
    // "the 16-bit Session ID (in big-endian format)" — the one place in the message layer
    // where a scalar is *not* little-endian.
    let Some(slot) = out.get_mut(..2) else {
        bail!(BufferTooSmall)
    };
    slot.copy_from_slice(&session_id.to_be_bytes());
    let (Some(dst), Some(src)) = (out.get_mut(2..13), mic.get(5..16)) else {
        bail!(BufferTooSmall)
    };
    dst.copy_from_slice(src);
    Ok(out)
}

/// How many header octets the privacy step obfuscates.
///
/// "M = Message Counter || [Source ID] || [Destination ID]" — the counter and the node ids,
/// and nothing before or after them. The four octets before (flags, session id, security
/// flags) stay readable because a receiver needs them to find the key; the message
/// extensions after are excluded by §4.4.1.7.
const PRIVACY_OFFSET: usize = 4;

fn privacy_len(header: &MessageHeader) -> usize {
    let counter = 4usize;
    let source = if header.source.is_some() { 8 } else { 0 };
    let destination = match header.destination {
        Destination::None => 0,
        Destination::Node(_) => 8,
        Destination::Group(_) => 2,
    };
    counter.saturating_add(source).saturating_add(destination)
}

/// Encrypts one message into `out`, returning how many octets it occupies.
///
/// `payload` is the protocol header and application payload — everything that travels
/// encrypted. The header's `privacy` flag decides whether §4.9's obfuscation is applied.
///
/// The result is `header || ciphertext || MIC`.
pub fn protect(
    header: &MessageHeader,
    nonce_source: NonceSource,
    payload: &[u8],
    keys: &SessionKeys,
    out: &mut [u8],
) -> Result<usize> {
    if header.is_unsecured() {
        // §4.4.2.1: "The Message Integrity Check field SHALL be present for all messages
        // except those of Unsecured Session Type." Protecting one would be a
        // contradiction, so it is refused rather than silently producing a message with a
        // tag nobody will check.
        bail!(InvalidState)
    }
    if matches!(header.session_type, SessionType::Group) && header.source.is_none() {
        // §4.8.1.1: a group message without a Source Node ID has no nonce.
        bail!(MessageReserved)
    }

    let header_len = header.encode(out)?;
    let source = nonce_source.resolve(header)?;
    let n = nonce(security_flags_of(header), header.message_counter, source);

    // The associated data is the header exactly as encoded — no re-serialisation, so the
    // bytes that are authenticated are provably the bytes that are sent.
    let Some(aad) = out.get(..header_len) else {
        bail!(BufferTooSmall)
    };
    let mut aad_copy = [0u8; MAX_HEADER];
    let Some(aad_slot) = aad_copy.get_mut(..header_len) else {
        bail!(BufferTooSmall)
    };
    aad_slot.copy_from_slice(aad);

    let cipher_end = header_len
        .checked_add(payload.len())
        .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
    let total = cipher_end
        .checked_add(AEAD_MIC_LENGTH_BYTES)
        .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
    let Some(body) = out.get_mut(header_len..cipher_end) else {
        bail!(BufferTooSmall)
    };
    body.copy_from_slice(payload);

    let mut tag = [0u8; AEAD_MIC_LENGTH_BYTES];
    aead_encrypt_in_place(&keys.encryption, &n, aad_slot, body, &mut tag)?;

    let Some(mic) = out.get_mut(cipher_end..total) else {
        bail!(BufferTooSmall)
    };
    mic.copy_from_slice(&tag);

    if header.privacy {
        // §4.9.3, and note the order: obfuscation happens *after* encryption, because its
        // nonce is built from the MIC that encryption produced.
        let nonce = privacy_nonce(header.session_id.0, &tag)?;
        let end = PRIVACY_OFFSET
            .checked_add(privacy_len(header))
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let Some(region) = out.get_mut(PRIVACY_OFFSET..end) else {
            bail!(BufferTooSmall)
        };
        privacy_xor(&keys.privacy, &nonce, region)?;
    }

    Ok(total)
}

/// The largest message header: flags, session, security, counter, source and destination.
const MAX_HEADER: usize = 1 + 2 + 1 + 4 + 8 + 8;

/// Reconstructs the Security Flags octet a header encodes to.
fn security_flags_of(header: &MessageHeader) -> u8 {
    let mut bits = match header.session_type {
        SessionType::Unicast => 0u8,
        SessionType::Group => 1,
    };
    if header.privacy {
        bits |= 0b1000_0000;
    }
    if header.control {
        bits |= 0b0100_0000;
    }
    bits
}

/// What a receiver can read before it has found a key.
///
/// The first four octets are never obfuscated and never encrypted, which is what makes a
/// session lookup possible at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preview {
    /// Which session's keys to try.
    pub session_id: super::ids::SessionId,
    /// Unicast or group — it decides which counter rule and which key set apply.
    pub session_type: SessionType,
    /// Whether the header is obfuscated.
    pub privacy: bool,
    /// Whether this is a control message, which counts on its own counter.
    pub control: bool,
}

/// Reads the four octets of a message that are always in the clear.
///
/// This is the first thing a receiver does: it cannot parse the rest of the header until
/// it has deobfuscated it, and it cannot deobfuscate it until it has found the session.
pub fn preview(buf: &[u8]) -> Result<Preview> {
    let (Some(&flags), Some(session), Some(&security)) = (buf.first(), buf.get(1..3), buf.get(3))
    else {
        bail!(MessageTruncated)
    };
    if (flags >> 4) != super::header::MESSAGE_FORMAT_VERSION {
        bail!(UnsupportedVersion)
    }
    let Ok(id) = <[u8; 2]>::try_from(session) else {
        bail!(MessageTruncated)
    };
    let session_type = match security & 0b11 {
        0 => SessionType::Unicast,
        1 => SessionType::Group,
        _ => bail!(MessageReserved),
    };
    Ok(Preview {
        session_id: super::ids::SessionId(u16::from_le_bytes(id)),
        session_type,
        privacy: security & 0b1000_0000 != 0,
        control: security & 0b0100_0000 != 0,
    })
}

/// Decrypts one message in place, returning its header and the range of `buf` holding the
/// plaintext payload.
///
/// On success `buf[range]` is the protocol header and application payload. On failure the
/// contents of `buf` are unspecified — §3.6.2 is explicit that a failed tag check leaves
/// the payload undefined — so a caller must not look at it.
pub fn unprotect(
    buf: &mut [u8],
    keys: &SessionKeys,
    nonce_source: NonceSource,
) -> Result<(MessageHeader, core::ops::Range<usize>)> {
    let head = preview(buf)?;

    if head.privacy {
        // Deobfuscate before parsing: the counter and node ids are unreadable until now,
        // and the header cannot be parsed without them.
        let total = buf.len();
        let mic_start = total
            .checked_sub(AEAD_MIC_LENGTH_BYTES)
            .ok_or(Error::new(ErrorCode::MessageTruncated))?;
        let Some(mic) = buf.get(mic_start..total) else {
            bail!(MessageTruncated)
        };
        let Ok(mic) = <[u8; AEAD_MIC_LENGTH_BYTES]>::try_from(mic) else {
            bail!(MessageTruncated)
        };
        let nonce = privacy_nonce(head.session_id.0, &mic)?;

        // The obfuscated region's length depends on the Message Flags, which are in the
        // clear — so it can be computed without decrypting anything.
        let Some(&flags) = buf.first() else {
            bail!(MessageTruncated)
        };
        let obfuscated = privacy_len_from_flags(flags)?;
        let end = PRIVACY_OFFSET
            .checked_add(obfuscated)
            .ok_or(Error::new(ErrorCode::MessageTruncated))?;
        let Some(region) = buf.get_mut(PRIVACY_OFFSET..end) else {
            bail!(MessageTruncated)
        };
        privacy_xor(&keys.privacy, &nonce, region)?;
    }

    let (header, rest) = MessageHeader::decode(buf)?;
    if header.is_unsecured() {
        // Nothing to unprotect; a caller that reached here has a session key for a session
        // that does not use one.
        bail!(InvalidState)
    }
    // §4.7.2's validity checks that depend on the session type.
    match header.session_type {
        SessionType::Unicast => {
            if matches!(header.destination, Destination::Group(_)) {
                // "If the message is of Secure Unicast Session Type: The DSIZ field SHALL
                // NOT indicate a Group ID is present."
                bail!(MessageReserved)
            }
        }
        SessionType::Group => {
            if matches!(header.destination, Destination::None) || header.source.is_none() {
                // "The DSIZ field SHALL NOT be 0. The S Flag field SHALL NOT be 0."
                bail!(MessageReserved)
            }
        }
    }

    let header_len = buf.len().saturating_sub(rest.len());
    let mut aad = [0u8; MAX_HEADER];
    let (Some(aad_slot), Some(header_bytes)) = (aad.get_mut(..header_len), buf.get(..header_len))
    else {
        bail!(MessageTruncated)
    };
    aad_slot.copy_from_slice(header_bytes);

    let total = buf.len();
    let mic_start = total
        .checked_sub(AEAD_MIC_LENGTH_BYTES)
        .ok_or(Error::new(ErrorCode::MessageTruncated))?;
    if mic_start < header_len {
        bail!(MessageTruncated)
    }
    let Some(mic) = buf.get(mic_start..total) else {
        bail!(MessageTruncated)
    };
    let Ok(tag) = <[u8; AEAD_MIC_LENGTH_BYTES]>::try_from(mic) else {
        bail!(MessageTruncated)
    };

    let source = nonce_source.resolve(&header)?;
    let n = nonce(security_flags_of(&header), header.message_counter, source);

    let Some(body) = buf.get_mut(header_len..mic_start) else {
        bail!(MessageTruncated)
    };
    aead_decrypt_in_place(&keys.encryption, &n, aad_slot, body, &tag)?;

    Ok((header, header_len..mic_start))
}

/// The obfuscated region's length, from the Message Flags octet alone.
fn privacy_len_from_flags(flags: u8) -> Result<usize> {
    let source = if flags & 0b0000_0100 != 0 { 8 } else { 0 };
    let destination = match flags & 0b11 {
        0 => 0usize,
        1 => 8,
        2 => 2,
        _ => bail!(MessageReserved),
    };
    Ok(4usize.saturating_add(source).saturating_add(destination))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{ExchangeId, GroupId, ProtocolHeader, ProtocolId, SessionId};

    fn keys() -> SessionKeys {
        SessionKeys::from_encryption_key(SymmetricKey::new([0x5A; 16])).expect("derive")
    }

    fn case_header() -> MessageHeader {
        MessageHeader {
            session_id: SessionId(0x1234),
            message_counter: 0x0102_0304,
            ..MessageHeader::default()
        }
    }

    #[test]
    fn the_nonce_is_table_17() {
        // Security Flags(1) || Message Counter(4, LE) || Source Node ID(8, LE).
        let n = nonce(0x80, 0x0A0B_0C0D, NodeId(0x1122_3344_5566_7788));
        assert_eq!(
            n,
            [
                0x80, // security flags
                0x0D, 0x0C, 0x0B, 0x0A, // counter, little-endian
                0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // source, little-endian
            ]
        );
    }

    #[test]
    fn the_privacy_nonce_matches_the_specs_worked_example() {
        // §4.9.2 prints this one in full: session 42, and a given MIC.
        let mic = [
            0xc5, 0xa0, 0x06, 0x3a, 0xd5, 0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c,
            0x16, 0x3b,
        ];
        let n = privacy_nonce(42, &mic).expect("nonce");
        assert_eq!(
            n,
            [
                0x00, 0x2a, // session id, big-endian
                0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16,
                0x3b, // MIC[5..16]
            ]
        );
    }

    #[test]
    fn a_case_message_round_trips() {
        let keys = keys();
        let header = case_header();
        let payload = b"protocol header and payload";

        let mut buf = [0u8; 256];
        let n = protect(
            &header,
            NonceSource::Case(NodeId(7)),
            payload,
            &keys,
            &mut buf,
        )
        .expect("protect");

        let (decoded, range) =
            unprotect(&mut buf[..n], &keys, NonceSource::Case(NodeId(7))).expect("unprotect");
        assert_eq!(decoded, header);
        assert_eq!(&buf[range], payload);
    }

    #[test]
    fn a_pase_message_round_trips() {
        let keys = keys();
        let header = case_header();
        let payload = b"pake1";
        let mut buf = [0u8; 128];
        let n = protect(&header, NonceSource::Pase, payload, &keys, &mut buf).expect("protect");
        let (_, range) = unprotect(&mut buf[..n], &keys, NonceSource::Pase).expect("unprotect");
        assert_eq!(&buf[range], payload);
    }

    #[test]
    fn the_wrong_nonce_source_does_not_decrypt() {
        // The whole reason `NonceSource` is an enum: picking the wrong one is a silent
        // interoperability failure, and this is what it looks like.
        let keys = keys();
        let header = case_header();
        let mut buf = [0u8; 128];
        let n =
            protect(&header, NonceSource::Case(NodeId(7)), b"x", &keys, &mut buf).expect("protect");
        assert_eq!(
            unprotect(&mut buf[..n], &keys, NonceSource::Pase)
                .unwrap_err()
                .code(),
            ErrorCode::IntegrityCheckFailed
        );
    }

    #[test]
    fn a_private_message_round_trips_and_hides_the_counter() {
        let keys = keys();
        let header = MessageHeader {
            privacy: true,
            source: Some(NodeId(0x1122_3344_5566_7788)),
            destination: Destination::Node(NodeId(9)),
            ..case_header()
        };
        let payload = b"obfuscated header, encrypted body";

        let mut buf = [0u8; 256];
        let n = protect(
            &header,
            NonceSource::Case(NodeId(0x1122_3344_5566_7788)),
            payload,
            &keys,
            &mut buf,
        )
        .expect("protect");

        // The counter is not readable on the wire…
        assert_ne!(
            &buf[4..8],
            &header.message_counter.to_le_bytes(),
            "the counter should be obfuscated"
        );
        // …but the first four octets are, because a receiver needs them.
        let head = preview(&buf[..n]).expect("preview");
        assert_eq!(head.session_id, header.session_id);
        assert!(head.privacy);

        let (decoded, range) = unprotect(
            &mut buf[..n],
            &keys,
            NonceSource::Case(NodeId(0x1122_3344_5566_7788)),
        )
        .expect("unprotect");
        assert_eq!(decoded, header);
        assert_eq!(&buf[range], payload);
    }

    #[test]
    fn a_group_message_round_trips() {
        let keys = keys();
        let header = MessageHeader {
            session_type: SessionType::Group,
            session_id: SessionId(5),
            source: Some(NodeId(42)),
            destination: Destination::Group(GroupId(7)),
            ..MessageHeader::default()
        };
        let mut buf = [0u8; 128];
        let n = protect(&header, NonceSource::Group, b"grouped", &keys, &mut buf).expect("protect");
        let (decoded, range) =
            unprotect(&mut buf[..n], &keys, NonceSource::Group).expect("unprotect");
        assert_eq!(decoded.source, Some(NodeId(42)));
        assert_eq!(&buf[range], b"grouped");
    }

    #[test]
    fn a_group_message_without_a_source_is_refused() {
        // §4.8.1.1: "If the S Flag of the message is 0 the message SHALL be dropped" —
        // there is no nonce without it.
        let keys = keys();
        let header = MessageHeader {
            session_type: SessionType::Group,
            session_id: SessionId(5),
            destination: Destination::Group(GroupId(7)),
            ..MessageHeader::default()
        };
        let mut buf = [0u8; 128];
        assert_eq!(
            protect(&header, NonceSource::Group, b"x", &keys, &mut buf)
                .unwrap_err()
                .code(),
            ErrorCode::MessageReserved
        );
    }

    #[test]
    fn an_unsecured_message_cannot_be_protected() {
        let keys = keys();
        let mut buf = [0u8; 64];
        assert_eq!(
            protect(
                &MessageHeader::default(),
                NonceSource::Pase,
                b"x",
                &keys,
                &mut buf
            )
            .unwrap_err()
            .code(),
            ErrorCode::InvalidState
        );
    }

    #[test]
    fn every_single_bit_flip_is_caught() {
        // The header is authenticated even though it is readable; the payload and MIC
        // obviously are. Nothing in the message may be changed without detection.
        let keys = keys();
        let header = case_header();
        let mut buf = [0u8; 128];
        let n = protect(
            &header,
            NonceSource::Case(NodeId(7)),
            b"payload",
            &keys,
            &mut buf,
        )
        .expect("protect");
        let original = buf;

        for byte in 0..n {
            for bit in 0..8u32 {
                let mut broken = original;
                broken[byte] ^= 1u8 << bit;
                let result = unprotect(&mut broken[..n], &keys, NonceSource::Case(NodeId(7)));
                assert!(
                    result.is_err(),
                    "flipping bit {bit} of octet {byte} went undetected"
                );
            }
        }
    }

    #[test]
    fn the_wrong_key_does_not_decrypt() {
        let keys = keys();
        let other = SessionKeys::from_encryption_key(SymmetricKey::new([0xA5; 16])).expect("k");
        let mut buf = [0u8; 128];
        let n = protect(&case_header(), NonceSource::Pase, b"x", &keys, &mut buf).expect("protect");
        assert!(unprotect(&mut buf[..n], &other, NonceSource::Pase).is_err());
    }

    #[test]
    fn a_group_id_on_a_unicast_session_is_refused() {
        // §4.7.2: "If the message is of Secure Unicast Session Type: The DSIZ field SHALL
        // NOT indicate a Group ID is present."
        let keys = keys();
        let header = MessageHeader {
            destination: Destination::Group(GroupId(1)),
            ..case_header()
        };
        let mut buf = [0u8; 128];
        let n =
            protect(&header, NonceSource::Case(NodeId(1)), b"x", &keys, &mut buf).expect("protect");
        assert_eq!(
            unprotect(&mut buf[..n], &keys, NonceSource::Case(NodeId(1)))
                .unwrap_err()
                .code(),
            ErrorCode::MessageReserved
        );
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let keys = keys();
        let mut buf = [0u8; 128];
        let n = protect(
            &case_header(),
            NonceSource::Pase,
            b"payload",
            &keys,
            &mut buf,
        )
        .expect("protect");
        for cut in 0..n {
            let mut copy = buf;
            let _ = unprotect(&mut copy[..cut], &keys, NonceSource::Pase);
        }
    }

    #[test]
    fn a_whole_message_round_trips_with_its_protocol_header() {
        // What a real send path does: encode the protocol header, protect the result.
        let keys = keys();
        let protocol = ProtocolHeader {
            initiator: true,
            reliability: true,
            exchange_id: ExchangeId(3),
            protocol: ProtocolId::SECURE_CHANNEL,
            opcode: 0x20,
            ..ProtocolHeader::default()
        };
        let mut inner = [0u8; 64];
        let inner_len = protocol.encode(&mut inner).expect("encode");

        let mut buf = [0u8; 256];
        let n = protect(
            &case_header(),
            NonceSource::Pase,
            &inner[..inner_len],
            &keys,
            &mut buf,
        )
        .expect("protect");

        let (_, range) = unprotect(&mut buf[..n], &keys, NonceSource::Pase).expect("unprotect");
        let (decoded, app) = ProtocolHeader::decode(&buf[range]).expect("decode");
        assert_eq!(decoded, protocol);
        assert!(app.is_empty());
    }

    #[test]
    fn the_preview_refuses_what_the_header_would() {
        assert_eq!(
            preview(&[]).unwrap_err().code(),
            ErrorCode::MessageTruncated
        );
        assert_eq!(
            preview(&[0x10, 0, 0, 0]).unwrap_err().code(),
            ErrorCode::UnsupportedVersion
        );
        assert_eq!(
            preview(&[0x00, 0, 0, 0x02]).unwrap_err().code(),
            ErrorCode::MessageReserved
        );
    }
}
