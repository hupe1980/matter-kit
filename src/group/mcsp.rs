//! The Message Counter Synchronization Protocol (Core §4.18.3).
//!
//! Two messages, of eight and twelve octets, and neither is TLV. They exist because a group
//! message has no handshake: a receiver that has never heard from a sender has no counter to
//! compare against, and §4.18 is how it gets one without simply trusting whatever arrives.
//!
//! Both ride on the Secure Channel protocol with the **C** flag set, "secured with the group key
//! for which counter synchronization is requested", and both go by *unicast* — the request to
//! the address the multicast came from, the response back.

use crate::error::{Error, ErrorCode, Result};

/// §4.18.3.1: the Challenge is "a 64-bit random number generated using the DRBG".
pub const CHALLENGE_LEN: usize = 8;

/// §4.18.5: "the Node SHALL first wait for a uniformly random amount of time between 0 and
/// MSG_COUNTER_SYNC_REQ_JITTER", so that a multicast heard by fifty nodes does not produce
/// fifty simultaneous unicast requests back at the sender.
pub const SYNC_REQ_JITTER_MS: u32 = 500;

/// §4.18.5: how long a synchronisation exchange may stay open. On expiry "any message waiting
/// on synchronization associated with the exchange SHALL be discarded".
pub const SYNC_TIMEOUT_MS: u32 = 2000;

/// `MsgCounterSyncReq` (§4.18.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRequest {
    /// The 64-bit random value that "uniquely identifies the synchronization request
    /// cryptographically", and which the response has to echo.
    pub challenge: [u8; CHALLENGE_LEN],
}

impl SyncRequest {
    /// Writes the payload.
    pub fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let slot = buf
            .get_mut(..CHALLENGE_LEN)
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        slot.copy_from_slice(&self.challenge);
        Ok(slot)
    }

    /// Reads the payload.
    ///
    /// Trailing octets are refused: the message is exactly eight, and anything more means the
    /// sender and this reader disagree about what they are speaking.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let challenge = <[u8; CHALLENGE_LEN]>::try_from(payload)
            .map_err(|_| Error::new(ErrorCode::MessageTruncated))?;
        Ok(Self { challenge })
    }
}

/// `MsgCounterSyncRsp` (§4.18.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncResponse {
    /// "The current data message counter for the node sending the MsgCounterSyncRsp message."
    pub counter: u32,
    /// "The Response SHALL be the same as the 64-bit value sent in the Challenge field of the
    /// corresponding MsgCounterSyncReq."
    pub response: [u8; CHALLENGE_LEN],
}

impl SyncResponse {
    /// The encoded length: a 32-bit counter and the echoed challenge.
    pub const LEN: usize = 4 + CHALLENGE_LEN;

    /// Writes the payload.
    pub fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let slot = buf
            .get_mut(..Self::LEN)
            .ok_or(Error::new(ErrorCode::BufferTooSmall))?;
        let (counter, response) = slot.split_at_mut(4);
        counter.copy_from_slice(&self.counter.to_le_bytes());
        response.copy_from_slice(&self.response);
        Ok(slot)
    }

    /// Reads the payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let bytes = <[u8; Self::LEN]>::try_from(payload)
            .map_err(|_| Error::new(ErrorCode::MessageTruncated))?;
        let (counter, response) = bytes.split_at(4);
        let counter =
            <[u8; 4]>::try_from(counter).map_err(|_| Error::new(ErrorCode::MessageTruncated))?;
        let response = <[u8; CHALLENGE_LEN]>::try_from(response)
            .map_err(|_| Error::new(ErrorCode::MessageTruncated))?;
        Ok(Self {
            counter: u32::from_le_bytes(counter),
            response,
        })
    }

    /// Whether this response answers `request` (§4.18.5).
    ///
    /// > The Response field corresponds to the Challenge field of the MsgCounterSyncReq message.
    ///
    /// Compared in constant time: the challenge is what stops an off-path attacker from
    /// answering a synchronisation request with a counter of its choosing, and a comparison that
    /// returned early would leak it one octet at a time.
    #[must_use]
    pub fn answers(&self, request: &SyncRequest) -> bool {
        crate::crypto::ct_eq(&self.response, &request.challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_eight_octets_of_challenge() {
        let request = SyncRequest {
            challenge: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut buf = [0u8; 16];
        assert_eq!(request.encode(&mut buf).unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            SyncRequest::decode(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
            request
        );
        // Table 26 gives the field one size, so neither short nor long is the message.
        assert!(SyncRequest::decode(&[1, 2, 3]).is_err());
        assert!(SyncRequest::decode(&[0u8; 9]).is_err());
    }

    #[test]
    fn a_response_is_a_counter_then_the_echoed_challenge() {
        let response = SyncResponse {
            counter: 0x0102_0304,
            response: [9, 8, 7, 6, 5, 4, 3, 2],
        };
        let mut buf = [0u8; 16];
        assert_eq!(
            response.encode(&mut buf).unwrap(),
            &[0x04, 0x03, 0x02, 0x01, 9, 8, 7, 6, 5, 4, 3, 2]
        );
        assert_eq!(
            SyncResponse::decode(&[0x04, 0x03, 0x02, 0x01, 9, 8, 7, 6, 5, 4, 3, 2]).unwrap(),
            response
        );
    }

    #[test]
    fn a_response_answers_only_its_own_challenge() {
        let request = SyncRequest {
            challenge: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let good = SyncResponse {
            counter: 7,
            response: request.challenge,
        };
        assert!(good.answers(&request));
        let mut wrong = good;
        wrong.response[7] ^= 1;
        assert!(!wrong.answers(&request));
    }
}
