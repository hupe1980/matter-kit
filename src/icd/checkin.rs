//! The Check-In Protocol (Core §4.22).
//!
//! An Intermittently Connected Device sleeps. While it sleeps it has no session, no
//! subscription that can reach it, and — being asleep — no way to be told any of that. The
//! Check-In message is how it says "I am awake now" to a client that has been waiting.
//!
//! > The goal of the Check-In Protocol is to provide a way for a server to notify a client of
//! > an event or state outside of a secure session in a private and secure fashion.
//!
//! # Why it is encrypted the way it is
//!
//! The message is **sessionless**, "since one of the goals of the protocol is to provide a
//! means to recover a secure session that was lost". So there are no session keys, and the
//! only shared secret is the key the client handed over when it registered. That leaves one
//! problem — an AEAD needs a nonce, and there is nowhere to negotiate one — and §4.22.3.1
//! solves it by deriving the nonce from the key and a counter:
//!
//! ```text
//! nonce      = HMAC-SHA256(key, counter)[0..13]
//! ciphertext = AES-128-CCM(key, nonce, plaintext = counter ‖ application data)
//! payload    = nonce ‖ ciphertext ‖ MIC
//! ```
//!
//! The counter appears twice, and that is the point rather than redundancy. It is *outside*
//! the encryption only as the nonce it generated, and *inside* it as a value the MIC covers.
//! A client that decrypted successfully and then trusted the plaintext counter without
//! re-deriving the nonce from it would accept a message whose two copies disagree —
//! §4.22.4.2 step 4 is that check, and the specification's own Test 6 is a message that
//! decrypts cleanly and fails it.
//!
//! # Who counts
//!
//! The server counts up. The client does **not** store the server's counter — it stores the
//! value the counter had when it registered, plus the largest offset it has seen since
//! (§4.22.1.2). A counter at or below that offset has been used before, and the message is a
//! replay.
//!
//! That arithmetic is deliberately modular: "The subtraction SHALL be done as unsigned
//! integers mod 2³². This ensures that even if the subtraction rolls over, it will still
//! produce the correct offset." A client comparing counters directly instead is one that
//! stops accepting check-ins the first time the server's counter wraps.
//!
//! # Keys wear out
//!
//! A key is good for one pass through the counter space, because reusing a counter reuses a
//! nonce. §4.22.3.4 makes the client responsible for noticing: at an offset of 2³¹ — half way
//! — [`Registration::needs_key_refresh`] is true and the client must re-register with a new
//! key before the other half is spent.

use crate::crypto::{
    AEAD_MIC_LENGTH_BYTES, AEAD_NONCE_LENGTH_BYTES, SymmetricKey, aead_decrypt_in_place,
    aead_encrypt_in_place, ct_eq, hmac,
};
use crate::error::{Result, bail};

/// How many octets a Check-In message occupies beyond its application data: the plaintext
/// nonce, the encrypted counter, and the MIC.
pub const OVERHEAD: usize = AEAD_NONCE_LENGTH_BYTES + 4 + AEAD_MIC_LENGTH_BYTES;

/// The offset at which §4.22.3.4 requires a client to re-register with a fresh key.
///
/// Half the counter space. Not a limit that can be run to the end: the key must be replaced
/// while counter values remain, because the failure at the end is a *reused nonce*, which
/// costs the confidentiality of both messages that share it.
pub const KEY_REFRESH_OFFSET: u32 = 1 << 31;

/// Derives the nonce for one Check-In message (§4.22.3.1).
///
/// > nonce = Crypto_HMAC(key = key, message = counter)[0..(CRYPTO_AEAD_NONCE_LENGTH_BYTES-1)]
///
/// The counter is hashed in its wire form — 4 octets, little-endian — not as an integer, so
/// there is one answer rather than one per architecture.
pub fn nonce(key: &SymmetricKey, counter: u32) -> Result<[u8; AEAD_NONCE_LENGTH_BYTES]> {
    let digest = hmac(key.as_bytes(), &counter.to_le_bytes())?;
    let mut out = [0u8; AEAD_NONCE_LENGTH_BYTES];
    let Some(head) = digest.get(..AEAD_NONCE_LENGTH_BYTES) else {
        bail!(BufferTooSmall)
    };
    out.copy_from_slice(head);
    Ok(out)
}

/// Builds one Check-In message (§4.22.4.1).
///
/// Writes `nonce ‖ ciphertext ‖ MIC` into `out` and returns its length. `application_data` is
/// whatever the use case defines; the ICD use case sends none, and "if application data is not
/// used for a specific use-case, creation of a Check-In message SHALL use a zero-length byte
/// array".
///
/// The specification is emphatic about the failure path: "If the encryption procedure fails to
/// generate the Check-In message, the server SHALL NOT send the associated Check-In message."
/// An `Err` here is not a partial result to salvage — `out` holds nothing meaningful.
pub fn encrypt(
    key: &SymmetricKey,
    counter: u32,
    application_data: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let nonce = nonce(key, counter)?;
    let plaintext_len = application_data.len().saturating_add(4);
    let total = plaintext_len
        .saturating_add(AEAD_NONCE_LENGTH_BYTES)
        .saturating_add(AEAD_MIC_LENGTH_BYTES);
    if out.len() < total {
        bail!(BufferTooSmall)
    }

    // The nonce goes out in plaintext, ahead of everything it protects.
    let Some(head) = out.get_mut(..AEAD_NONCE_LENGTH_BYTES) else {
        bail!(BufferTooSmall)
    };
    head.copy_from_slice(&nonce);

    // "The plaintext SHALL be a concatenation of … the Check-In Counter value used in the
    // encryption process and the Application Data, if used by the use case."
    let body_end = AEAD_NONCE_LENGTH_BYTES.saturating_add(plaintext_len);
    let Some(body) = out.get_mut(AEAD_NONCE_LENGTH_BYTES..body_end) else {
        bail!(BufferTooSmall)
    };
    if body.len() < 4 {
        bail!(BufferTooSmall)
    }
    let (counter_slot, data_slot) = body.split_at_mut(4);
    counter_slot.copy_from_slice(&counter.to_le_bytes());
    data_slot.copy_from_slice(application_data);

    // "The additional data field SHALL NOT be used."
    let mut tag = [0u8; AEAD_MIC_LENGTH_BYTES];
    aead_encrypt_in_place(key, &nonce, &[], body, &mut tag)?;

    let Some(tail) = out.get_mut(body_end..total) else {
        bail!(BufferTooSmall)
    };
    tail.copy_from_slice(&tag);
    Ok(total)
}

/// What a successfully opened Check-In message carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckIn<'a> {
    /// The counter the server sent, already confirmed to match the nonce.
    pub counter: u32,
    /// The application data, empty for the ICD use case.
    pub application_data: &'a [u8],
}

/// Opens one Check-In message with a candidate key (§4.22.4.2, steps 1–4).
///
/// `buf` is decrypted in place, so the returned application data borrows it. This is the step
/// that also *identifies the sender*: "If the decryption succeeds, the device associated with
/// the key is identified as the server checking in", so a client holding several registrations
/// tries each key until one works. [`IntegrityCheckFailed`](crate::ErrorCode::IntegrityCheckFailed) means "not this key",
/// not "bad message" — keep going.
///
/// Replay is **not** checked here, because this function does not know which registration the
/// key came from. [`Registration::accept`] is that half.
pub fn decrypt<'a>(key: &SymmetricKey, buf: &'a mut [u8]) -> Result<CheckIn<'a>> {
    if buf.len() < OVERHEAD {
        bail!(BtpMalformed)
    }
    let (head, rest) = buf.split_at_mut(AEAD_NONCE_LENGTH_BYTES);
    let mut received_nonce = [0u8; AEAD_NONCE_LENGTH_BYTES];
    received_nonce.copy_from_slice(head);

    let body_len = rest.len().saturating_sub(AEAD_MIC_LENGTH_BYTES);
    let (body, tag_bytes) = rest.split_at_mut(body_len);
    let mut tag = [0u8; AEAD_MIC_LENGTH_BYTES];
    let Some(tag_slice) = tag_bytes.get(..AEAD_MIC_LENGTH_BYTES) else {
        bail!(BtpMalformed)
    };
    tag.copy_from_slice(tag_slice);

    aead_decrypt_in_place(key, &received_nonce, &[], body, &tag)?;

    let (Some(counter_bytes), Some(application_data)) = (body.get(..4), body.get(4..)) else {
        bail!(BtpMalformed)
    };
    let mut counter_le = [0u8; 4];
    counter_le.copy_from_slice(counter_bytes);
    let counter = u32::from_le_bytes(counter_le);

    // §4.22.4.2 step 4. The counter is both the nonce's input and part of the MIC'd plaintext,
    // and a message where the two disagree is one the sender did not construct: the tag proves
    // only that *this* nonce and *this* plaintext go together, not that the plaintext's own
    // counter is the one the nonce came from. The specification's Test 6 is exactly that
    // message, and it decrypts cleanly.
    let derived = nonce(key, counter)?;
    if !ct_eq(&derived, &received_nonce) {
        bail!(IntegrityCheckFailed)
    }

    Ok(CheckIn {
        counter,
        application_data,
    })
}

/// One server a client has registered with, and what it remembers about that server's counter
/// (§4.22.1.2).
///
/// Three values, and the reason there are three rather than one is that the client never
/// learns the server's counter: it learns where the counter *was* when it registered, and
/// tracks how far past that it has seen.
#[derive(Debug, Clone)]
pub struct Registration {
    key: SymmetricKey,
    /// "the starting value of Check-In Counter" — what the server reported at registration.
    start: u32,
    /// "the last known valid offset from the starting value of the Check-In Counter".
    offset: u32,
}

impl Registration {
    /// Records a registration.
    #[must_use]
    pub const fn new(key: SymmetricKey, start_counter: u32) -> Self {
        Self {
            key,
            start: start_counter,
            offset: 0,
        }
    }

    /// The key this registration decrypts with.
    #[must_use]
    pub const fn key(&self) -> &SymmetricKey {
        &self.key
    }

    /// The counter value the server reported when the client registered.
    #[must_use]
    pub const fn start_counter(&self) -> u32 {
        self.start
    }

    /// The largest offset past [`Registration::start_counter`] that has been accepted.
    #[must_use]
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    /// Whether a counter is one this registration has not already seen (§4.22.3.3).
    ///
    /// > Subtract the stored starting value of the counter from the value provided in the
    /// > Check-In message. The subtraction SHALL be done as unsigned integers mod 2³². This
    /// > ensures that even if the subtraction rolls over, it will still produce the correct
    /// > offset.
    ///
    /// Wrapping is the whole subtlety. A client that compared the two counters as ordinary
    /// integers would work for months and then, the first time the server's counter passed
    /// 2³²−1, reject every check-in from a perfectly healthy device — and the device would
    /// keep sending them.
    #[must_use]
    pub const fn is_fresh(&self, counter: u32) -> bool {
        self.offset < counter.wrapping_sub(self.start)
    }

    /// Whether §4.22.3.4 requires the client to re-register with a new key.
    ///
    /// "When a client receives a Check-In message with a Check-In Counter value indicating
    /// that 2³¹ counter values have been used, the client SHALL refresh its entry with a new
    /// key."
    #[must_use]
    pub const fn needs_key_refresh(&self) -> bool {
        self.offset >= KEY_REFRESH_OFFSET
    }

    /// Opens a Check-In message from this server and records its counter.
    ///
    /// The two halves are here rather than in [`decrypt`] because only a registration knows
    /// what has been seen before. A replayed message decrypts perfectly — the attacker is
    /// replaying a message the server really sent — so freshness is the only thing that
    /// separates it from the original.
    ///
    /// The offset moves **only on success**, which is what stops a replayed message from
    /// advancing the window past check-ins that have not arrived yet.
    pub fn accept<'a>(&mut self, buf: &'a mut [u8]) -> Result<CheckIn<'a>> {
        let message = decrypt(&self.key, buf)?;
        if !self.is_fresh(message.counter) {
            bail!(DuplicateMessage)
        }
        self.offset = message.counter.wrapping_sub(self.start);
        Ok(message)
    }

    /// Replaces the key and resets the window, as a re-registration does.
    pub fn refresh(&mut self, key: SymmetricKey, start_counter: u32) {
        self.key = key;
        self.start = start_counter;
        self.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses the specification's `aa:bb:cc` notation, so a vector can be pasted as printed.
    fn hex(text: &str) -> heapless::Vec<u8, 128> {
        text.split(':')
            .filter(|s| !s.is_empty())
            .map(|byte| u8::from_str_radix(byte.trim(), 16).expect("hex"))
            .collect()
    }

    fn key(text: &str) -> SymmetricKey {
        SymmetricKey::from_slice(&hex(text)).expect("16 octets")
    }

    /// Appendix F.4, Test 1: no application data.
    #[test]
    fn appendix_f4_test_1() {
        let k = key("d9:0e:13:18:0d:00:ba:ad:d2:0c:f5:ed:49:13:d3:ff");
        assert_eq!(
            nonce(&k, 0x0C).expect("nonce").as_slice(),
            hex("45:80:d2:c6:f1:31:0d:c4:eb:64:f1:f8:e8").as_slice()
        );

        let expected = hex(
            "45:80:d2:c6:f1:31:0d:c4:eb:64:f1:f8:e8:bd:c2:1f:b5:19:5d:74:7d:d2:87:9b:2b:0d:\
             43:ce:5b:1c:56:50:78",
        );
        let mut out = [0u8; 64];
        let n = encrypt(&k, 0x0C, b"", &mut out).expect("encrypt");
        assert_eq!(&out[..n], expected.as_slice());

        // The client registered when the counter was 0x0B, so 0x0C is one past it.
        let mut registration = Registration::new(k, 0x0B);
        let mut buf = expected.clone();
        let message = registration.accept(&mut buf).expect("valid");
        assert_eq!(message.counter, 0x0C);
        assert!(message.application_data.is_empty());
        assert_eq!(registration.offset(), 1);
    }

    /// Appendix F.4, Test 2: four octets of application data, and a gap in the counter.
    #[test]
    fn appendix_f4_test_2() {
        let k = key("18:fd:bc:ea:ef:01:95:5b:0e:c8:75:ed:a3:ae:6e:e8");
        assert_eq!(
            nonce(&k, 0x0F).expect("nonce").as_slice(),
            hex("9b:02:ed:21:ee:0c:7b:49:19:85:50:2e:37").as_slice()
        );

        let expected = hex(
            "9b:02:ed:21:ee:0c:7b:49:19:85:50:2e:37:2d:bd:7b:3f:8b:4f:8e:3c:5a:d9:94:19:38:\
             9f:41:a8:d6:09:93:8c:67:a8:6d:65",
        );
        let mut out = [0u8; 64];
        let n = encrypt(&k, 0x0F, b"This", &mut out).expect("encrypt");
        assert_eq!(&out[..n], expected.as_slice());

        // Counters 0x0C..0x0F were never seen; skipping them is normal, because a sleeping
        // device's check-ins are lost routinely.
        let mut registration = Registration::new(k, 0x0B);
        let mut buf = expected;
        let message = registration.accept(&mut buf).expect("valid");
        assert_eq!(message.counter, 0x0F);
        assert_eq!(message.application_data, b"This");
        assert_eq!(registration.offset(), 4);
    }

    /// Appendix F.4, Test 3: "Invalid Check-In message - Received counter has already been
    /// used." The counter equals the starting value, so its offset is zero and nothing about
    /// it is new.
    #[test]
    fn appendix_f4_test_3_a_counter_at_the_starting_value_is_a_replay() {
        let k = key("d9:0e:13:18:0d:00:ba:ad:d2:0c:f5:ed:49:13:d3:ff");
        let expected = hex(
            "aa:84:bc:60:88:6a:63:a8:47:5d:5d:be:b5:6d:63:5f:a9:52:85:ae:33:62:66:13:c7:63:\
             6c:e3:e3:b2:a8:b1:3a:8c:89:be:f7:68:91:e8:e2:96",
        );
        let mut out = [0u8; 64];
        let n = encrypt(&k, 0x0B, b"This is a", &mut out).expect("encrypt");
        assert_eq!(&out[..n], expected.as_slice());

        // It decrypts perfectly — that is the point. Only the window rejects it.
        let mut buf = expected.clone();
        let opened = decrypt(&k, &mut buf).expect("the cryptography is sound");
        assert_eq!(opened.counter, 0x0B);
        assert_eq!(opened.application_data, b"This is a");

        let mut registration = Registration::new(k, 0x0B);
        let mut buf = expected;
        assert_eq!(
            registration
                .accept(&mut buf)
                .map(|_| ())
                .map_err(|e| e.code()),
            Err(crate::ErrorCode::DuplicateMessage)
        );
        assert_eq!(
            registration.offset(),
            0,
            "a replay does not move the window"
        );
    }

    /// Appendix F.4, Test 4: the counter is *behind* what the client has already accepted.
    #[test]
    fn appendix_f4_test_4_a_counter_behind_the_window_is_a_replay() {
        let k = key("ca:67:d4:1f:f7:11:29:10:fd:d1:8a:1b:f9:9e:a9:74");
        let expected = hex(
            "7a:97:72:24:3c:97:c8:7d:5f:3a:31:c4:e6:db:bc:1a:a5:66:c4:43:c2:05:86:06:6b:42:\
             7b:fc:aa:ad:78:da:4a:10:5a:13:42:ad:bf:3f:47:98:cd:81:b9:ef:97:bb:b7",
        );
        let mut out = [0u8; 80];
        let n = encrypt(&k, 0x0B, b"This is a longer", &mut out).expect("encrypt");
        assert_eq!(&out[..n], expected.as_slice());

        // The vector prints "Client counter: 0f" for this test, and the number is the *last
        // accepted* counter rather than the registration start — §4.22.1.2 stores the start
        // and an offset, and here they are 0x0B and 4. Reading it as a start with a zero
        // offset gives the opposite answer, because 0x0B − 0x0F mod 2³² is 0xFFFF_FFFC and
        // that is "almost a whole cycle ahead" rather than "four behind".
        let mut registration = Registration::new(k.clone(), 0x0B);
        let mut ahead = [0u8; 80];
        let n = encrypt(&k, 0x0F, b"", &mut ahead).expect("encrypt");
        registration
            .accept(&mut ahead[..n])
            .expect("0x0F arrives first");
        assert_eq!(registration.offset(), 4);

        let mut buf = expected;
        assert_eq!(
            registration
                .accept(&mut buf)
                .map(|_| ())
                .map_err(|e| e.code()),
            Err(crate::ErrorCode::DuplicateMessage),
            "§4.22.3.3 rejects it because the window has already passed it"
        );
        assert_eq!(registration.offset(), 4, "and the window did not move");
    }

    #[test]
    fn a_counter_far_ahead_is_accepted_and_demands_a_new_key() {
        // The counterpart to Test 4, and the reason that test has to be read carefully. A
        // counter 0xFFFF_FFFC past the *start* is arithmetically fresh — §4.22.3.3's three
        // steps say so, and the CHIP reference implementation agrees — so it is accepted. What
        // makes it harmless is §4.22.3.4: an offset that large means more than 2³¹ counter
        // values have gone, and the key must be replaced before the nonces repeat.
        let k = key("d9:0e:13:18:0d:00:ba:ad:d2:0c:f5:ed:49:13:d3:ff");
        let mut registration = Registration::new(k.clone(), 0x0F);
        let mut out = [0u8; 64];
        let n = encrypt(&k, 0x0B, b"", &mut out).expect("encrypt");
        registration
            .accept(&mut out[..n])
            .expect("arithmetically fresh");
        assert_eq!(registration.offset(), 0xFFFF_FFFC);
        assert!(registration.needs_key_refresh());
    }

    /// Appendix F.4, Test 5: "Failed to decrypt Check-In message."
    #[test]
    fn appendix_f4_test_5_a_tampered_message_does_not_decrypt() {
        let k = key("ca:67:d4:1f:f7:11:29:10:fd:d1:8a:1b:f9:9e:a9:74");
        let mut buf = hex(
            "f9:34:67:6e:a6:e0:70:7b:7a:d7:81:4f:f8:2e:5b:18:d1:9a:23:b2:e4:fa:df:82:92:53:\
             51:7f:f3:c9:1d:8d:47:84:31:5a:1e:32:08:b8:ec:f6:11:8b:02:1a:5a:4c:d4:e9:d4:13:\
             8d:ff:29:71",
        );
        assert_eq!(
            decrypt(&k, &mut buf).map(|_| ()).map_err(|e| e.code()),
            Err(crate::ErrorCode::IntegrityCheckFailed)
        );
    }

    /// Appendix F.4, Test 6: "Invalid Check-In message - Nonce and received counter do not
    /// match."
    ///
    /// This is the vector that justifies §4.22.4.2's step 4 existing at all. The message
    /// decrypts cleanly and its MIC verifies — the tag proves this nonce and this plaintext go
    /// together, and they do. What it does not prove is that the plaintext's own counter is
    /// the one the nonce was derived from, and here it is not.
    #[test]
    fn appendix_f4_test_6_a_nonce_that_does_not_match_its_counter_is_refused() {
        let k = key("ca:67:d4:1f:f7:11:29:10:fd:d1:8a:1b:f9:9e:a9:74");
        let mut buf = hex(
            "06:34:67:6e:a6:e0:70:7b:7a:d7:81:4f:f8:29:5b:18:d1:9a:23:b2:e4:fa:df:82:92:53:\
             51:7f:f3:c9:1d:8d:47:84:2e:41:02:3c:03:ad:66:ac:4d:ca:72:47:e0:e4:c6:6b:d9:d3:\
             99:13:e2:3d:82:32:b9:61:fa:92:26",
        );
        assert_eq!(
            decrypt(&k, &mut buf).map(|_| ()).map_err(|e| e.code()),
            Err(crate::ErrorCode::IntegrityCheckFailed),
            "the AEAD succeeded; the nonce check is what refused it"
        );
    }

    #[test]
    fn the_window_survives_the_counter_wrapping() {
        // "The subtraction SHALL be done as unsigned integers mod 2³². This ensures that even
        // if the subtraction rolls over, it will still produce the correct offset." A client
        // comparing counters directly works for months and then rejects every check-in from a
        // healthy device the first time the server passes 2³² − 1.
        let k = key("d9:0e:13:18:0d:00:ba:ad:d2:0c:f5:ed:49:13:d3:ff");
        let start = u32::MAX.saturating_sub(2);
        let mut registration = Registration::new(k.clone(), start);

        let mut out = [0u8; 64];
        for counter in [u32::MAX - 1, u32::MAX, 0, 1, 2] {
            let n = encrypt(&k, counter, b"", &mut out).expect("encrypt");
            let mut buf = out;
            let message = registration
                .accept(&mut buf[..n])
                .expect("a wrapped counter is still moving forwards");
            assert_eq!(message.counter, counter);
        }
        assert_eq!(registration.offset(), 5);

        // And the one before the wrap is still a replay afterwards.
        let n = encrypt(&k, u32::MAX, b"", &mut out).expect("encrypt");
        let mut buf = out;
        assert_eq!(
            registration
                .accept(&mut buf[..n])
                .map(|_| ())
                .map_err(|e| e.code()),
            Err(crate::ErrorCode::DuplicateMessage)
        );
    }

    #[test]
    fn a_key_must_be_refreshed_at_half_the_counter_space() {
        // §4.22.3.4: the key has to go *before* the counters run out, because what waits at
        // the end is a reused nonce — and that costs the confidentiality of both messages that
        // share it, not merely the freshness of one.
        let k = key("d9:0e:13:18:0d:00:ba:ad:d2:0c:f5:ed:49:13:d3:ff");
        let mut registration = Registration::new(k.clone(), 0);
        assert!(!registration.needs_key_refresh());

        let mut out = [0u8; 64];
        let n = encrypt(&k, KEY_REFRESH_OFFSET, b"", &mut out).expect("encrypt");
        let mut buf = out;
        registration.accept(&mut buf[..n]).expect("still valid");
        assert!(
            registration.needs_key_refresh(),
            "2³¹ counter values have been used"
        );

        // Re-registering resets the window.
        let fresh = key("18:fd:bc:ea:ef:01:95:5b:0e:c8:75:ed:a3:ae:6e:e8");
        registration.refresh(fresh, 7);
        assert!(!registration.needs_key_refresh());
        assert_eq!(registration.offset(), 0);
        assert_eq!(registration.start_counter(), 7);
    }

    #[test]
    fn a_client_identifies_the_server_by_which_key_opens_the_message() {
        // §4.22.4.2 step 2: "When a client has multiple associated servers, the client iterates
        // through this process for the keys associated to each potential server until the keys
        // associated to all possible servers fail or a successful key is found." There is no
        // sender field in the message — the key that works *is* the identification.
        let a = key("d9:0e:13:18:0d:00:ba:ad:d2:0c:f5:ed:49:13:d3:ff");
        let b = key("18:fd:bc:ea:ef:01:95:5b:0e:c8:75:ed:a3:ae:6e:e8");
        let mut out = [0u8; 64];
        let n = encrypt(&b, 3, b"", &mut out).expect("encrypt");

        let mut buf = out;
        assert_eq!(
            decrypt(&a, &mut buf[..n]).map(|_| ()).map_err(|e| e.code()),
            Err(crate::ErrorCode::IntegrityCheckFailed),
            "the wrong key is a failure to try the next one with, not a bad message"
        );
        let mut buf = out;
        assert_eq!(decrypt(&b, &mut buf[..n]).expect("right key").counter, 3);
    }

    #[test]
    fn a_message_shorter_than_its_own_overhead_is_refused() {
        // It arrives from an unauthenticated sender on a sleeping device, so the length check
        // comes before anything else touches it.
        let k = key("d9:0e:13:18:0d:00:ba:ad:d2:0c:f5:ed:49:13:d3:ff");
        for len in 0..OVERHEAD {
            let mut buf = [0u8; OVERHEAD];
            assert!(decrypt(&k, &mut buf[..len]).is_err(), "length {len}");
        }
    }

    #[test]
    fn a_buffer_too_small_for_the_message_is_refused_rather_than_truncated() {
        let k = key("d9:0e:13:18:0d:00:ba:ad:d2:0c:f5:ed:49:13:d3:ff");
        let mut out = [0u8; OVERHEAD];
        encrypt(&k, 1, b"", &mut out).expect("exactly enough for no application data");
        assert_eq!(
            encrypt(&k, 1, b"x", &mut out).map_err(|e| e.code()),
            Err(crate::ErrorCode::BufferTooSmall)
        );
    }
}
