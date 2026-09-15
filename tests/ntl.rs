//! Matter over NFC, end to end (Core §4.21).
//!
//! Tap, and a commissioning message crosses in pieces. §4.21's chaining is spelled differently
//! in each direction — the **CLA** octet going one way, the **SW1** status word coming back —
//! and both are exercised here against a message far larger than one APDU.
//!
//! The rule that makes NTL awkward is §4.21.4's: "both the NFC Reader/Writer and NFC listener
//! SHALL always use short field coding". One octet of length, so 255 octets a fragment, so a
//! PASE message is eight or nine taps' worth of APDU rather than one.

#![cfg(all(feature = "std", feature = "nfc"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::transport::ntl::{
    self, MAX_FRAGMENT, Reassembled, Reassembler, Responder, Selected, Status, Transport,
};

type Device = Reassembler<2048>;

/// The commissioner's half: splits `message` into `TRANSPORT` commands and hands each to the
/// device, returning how many APDUs it took.
fn send(device: &mut Device, message: &[u8], fragment_size: usize) -> (usize, Status) {
    let length = u16::try_from(message.len()).expect("under 64 KiB");
    let mut apdus = 0usize;
    let mut sent = 0usize;
    let mut status = Status::OK;
    while sent < message.len() {
        let take = fragment_size.min(message.len() - sent);
        let command = Transport {
            chained: sent + take < message.len(),
            message_length: length,
            fragment: &message[sent..sent + take],
            le: 0,
        };
        // Through the wire, not around it.
        let mut apdu = [0u8; 512];
        let n = command.encode(&mut apdu).expect("encode");
        let decoded = Transport::decode(&apdu[..n]).expect("decode");
        assert_eq!(decoded, command);

        apdus += 1;
        sent += take;
        match device.push(&decoded) {
            Ok(Reassembled::More) => status = Status::OK,
            Ok(Reassembled::Message) => status = Status::OK,
            Err(error) => return (apdus, error),
        }
    }
    (apdus, status)
}

#[test]
fn a_message_larger_than_one_apdu_is_chained_across() {
    // §4.21.4.2: "In case the size of the Matter message to transmit in the TRANSPORT command
    // APDU is bigger than the maximum size that can be transmitted by this APDU, the APDU
    // chaining procedure specified in ISO/IEC 7816-4 SHALL be used."
    let message: Vec<u8> = (0..1000u16).map(|i| (i % 251) as u8).collect();
    let mut device = Device::new();
    let (apdus, status) = send(&mut device, &message, MAX_FRAGMENT);
    assert_eq!(status, Status::OK);
    assert_eq!(apdus, 4, "1000 octets in fragments of 255");
    assert_eq!(device.message(), &message[..]);
}

#[test]
fn a_message_that_fits_takes_one_apdu_and_says_so_in_the_cla() {
    // §4.21.4.2: CLA 0x80 is the last (or only) fragment; 0x90 means more follow. A commissionee
    // that ignored the difference would wait forever for a continuation that never comes.
    let message = b"a short message";
    let mut device = Device::new();
    let (apdus, status) = send(&mut device, message, MAX_FRAGMENT);
    assert_eq!(apdus, 1);
    assert_eq!(status, Status::OK);
    assert_eq!(device.message(), message);

    let command = Transport {
        chained: false,
        message_length: message.len() as u16,
        fragment: message,
        le: 0,
    };
    let mut apdu = [0u8; 64];
    command.encode(&mut apdu).unwrap();
    assert_eq!(apdu[0], ntl::CLA_TRANSPORT_LAST);
}

#[test]
fn every_fragment_names_the_same_total_length() {
    // §4.21.4.2: "The same value SHALL be used in all chained commands." A fragment that names
    // a different total belongs to a different message, and joining them would produce neither.
    let mut device = Device::new();
    assert_eq!(
        device.push(&Transport {
            chained: true,
            message_length: 100,
            fragment: &[1, 2, 3],
            le: 0,
        }),
        Ok(Reassembled::More)
    );
    assert_eq!(
        device.push(&Transport {
            chained: false,
            message_length: 200,
            fragment: &[4, 5, 6],
            le: 0,
        }),
        Err(Status::CONDITIONS_NOT_SATISFIED)
    );
    assert!(
        device.message().is_empty(),
        "and the partial message is dropped"
    );
}

#[test]
fn a_short_last_fragment_is_refused() {
    // The announced length is a promise. A final fragment that leaves the message shorter than
    // promised would be handed up as a truncated Matter message, which fails its integrity
    // check with nothing to say why.
    let mut device = Device::new();
    assert_eq!(
        device.push(&Transport {
            chained: false,
            message_length: 100,
            fragment: &[1, 2, 3],
            le: 0,
        }),
        Err(Status::CONDITIONS_NOT_SATISFIED)
    );
}

#[test]
fn a_message_too_large_is_refused_before_a_single_octet_is_buffered() {
    // §4.21.4.2, Table 50: `6A 84`, "Not enough memory space". Checked against the *announced*
    // length, so a device says so on the first APDU rather than part way through.
    let mut small = Reassembler::<64>::new();
    assert_eq!(
        small.push(&Transport {
            chained: true,
            message_length: 1000,
            fragment: &[0u8; 10],
            le: 0,
        }),
        Err(Status::NOT_ENOUGH_MEMORY)
    );
    assert!(small.message().is_empty());
}

// --- §4.21.4.3: the response direction ------------------------------------------------------

#[test]
fn a_long_response_is_fetched_with_get_response() {
    // §4.21.4.2: a response that does not fit answers `61 XX`, "SW2 SHALL encode the number of
    // bytes of message to be sent in the next GET RESPONSE R-APDU", and §4.21.4.3 is how the
    // commissioner asks for it.
    let message: Vec<u8> = (0..600u16).map(|i| (i % 251) as u8).collect();
    let mut responder = Responder::new(&message);

    let mut got = Vec::new();
    let mut fetches = 0usize;
    loop {
        // `Le` of 0 means 256 under short field coding.
        let (fragment, status) = responder.next(0);
        got.extend_from_slice(fragment);
        if status == Status::OK {
            break;
        }
        assert_eq!(status.sw1, 0x61, "more to come");
        assert!(status.sw2 > 0);
        // The commissioner asks again.
        let mut apdu = [0u8; 8];
        let n = ntl::get_response(0, &mut apdu).expect("encode");
        assert_eq!(&apdu[..n], &[0x00, 0xC0, 0x00, 0x00, 0x00]);
        fetches += 1;
        assert!(fetches < 10, "the fetch loop does not terminate");
    }
    assert_eq!(got, message);
    assert!(responder.is_done());
    assert_eq!(fetches, 2, "600 octets in three reads of 256");
}

#[test]
fn a_small_reader_gets_smaller_fragments() {
    // `Le` is "the maximum length in octets that the reader/writer can receive", and a
    // commissionee that ignored it would overrun the reader's buffer.
    let message = [0xABu8; 100];
    let mut responder = Responder::new(&message);
    let (fragment, status) = responder.next(40);
    assert_eq!(fragment.len(), 40);
    assert_eq!(status, Status::more(60));
    let (fragment, status) = responder.next(40);
    assert_eq!(fragment.len(), 40);
    assert_eq!(status, Status::more(20));
    let (fragment, status) = responder.next(40);
    assert_eq!(fragment.len(), 20);
    assert_eq!(status, Status::OK);
    assert!(responder.is_done());
}

#[test]
fn a_tail_longer_than_one_octet_can_say_is_reported_as_255() {
    // SW2 is one octet. §4.21.4.2 has nothing to say about a longer tail, and 255 is "at least
    // this much" — which is all the commissioner needs in order to ask again.
    let message = [0u8; 1000];
    let mut responder = Responder::new(&message);
    let (_, status) = responder.next(10);
    assert_eq!(status, Status::more(0xFF));
}

// --- §4.21.4.1: the tap that starts it ------------------------------------------------------

#[test]
fn the_select_exchange_identifies_the_device() {
    let mut apdu = [0u8; 32];
    let n = ntl::select(&mut apdu).expect("encode");
    assert!(ntl::is_select(&apdu[..n]));

    // What a device in commissioning mode answers with (§4.21.4.1, Table 45).
    let answer = Selected {
        version: ntl::VERSION,
        discriminator: 3840,
        vendor_id: 0xFFF1,
        product_id: 0x8001,
        extended: &[],
    };
    let mut data = [0u8; 32];
    let n = answer.encode(&mut data).expect("encode");
    let read = Selected::decode(&data[..n]).expect("decode");
    assert_eq!(read.discriminator, 3840, "the 12 bits of §5.4.2.4");
    assert_eq!(read.vendor_id, 0xFFF1);
    assert_eq!(read.product_id, 0x8001);
    assert_eq!(read, answer);
}

#[test]
fn a_device_not_in_commissioning_mode_says_so() {
    // §4.21.4.1, Table 46: `69 85`, "conditions of use are not satisfied" — the one answer that
    // tells a commissioner to stop tapping and open the window first.
    assert_eq!(Status::CONDITIONS_NOT_SATISFIED.sw1, 0x69);
    assert_eq!(Status::CONDITIONS_NOT_SATISFIED.sw2, 0x85);
    assert!(!Status::CONDITIONS_NOT_SATISFIED.is_ok());
}

#[test]
fn extended_data_is_carried_through() {
    // "Extended Data MAY be omitted" — and when it is not, it is whatever the device appended.
    let answer = Selected {
        version: ntl::VERSION,
        discriminator: 1,
        vendor_id: 1,
        product_id: 1,
        extended: &[0xDE, 0xAD],
    };
    let mut data = [0u8; 32];
    let n = answer.encode(&mut data).expect("encode");
    assert_eq!(
        Selected::decode(&data[..n]).unwrap().extended,
        &[0xDE, 0xAD]
    );
}

#[test]
fn a_chain_may_not_deliver_more_than_it_announced() {
    // §4.21.4.2's `P1`/`P2` is "the number of octets of the full message to transmit", and it is
    // the sender's number. Checking only the *final* total would be too late: every fragment
    // until then is buffered on the strength of that promise, and a chain that kept overrunning
    // would fill the reassembly buffer before anything noticed.
    //
    // Found by `cargo fuzz run ntl`, from a two-octet message announced as zero.
    let mut device = Device::new();
    assert_eq!(
        device.push(&Transport {
            chained: true,
            message_length: 0,
            fragment: &[0x00],
            le: 0,
        }),
        Err(Status::CONDITIONS_NOT_SATISFIED)
    );
    assert!(device.message().is_empty());

    // And the same one fragment later, which is where a sender would try it.
    assert_eq!(
        device.push(&Transport {
            chained: true,
            message_length: 4,
            fragment: &[1, 2, 3],
            le: 0,
        }),
        Ok(Reassembled::More)
    );
    assert_eq!(
        device.push(&Transport {
            chained: true,
            message_length: 4,
            fragment: &[4, 5],
            le: 0,
        }),
        Err(Status::CONDITIONS_NOT_SATISFIED),
        "five octets for a four-octet message"
    );
    assert!(device.message().is_empty(), "and the chain is abandoned");
}
