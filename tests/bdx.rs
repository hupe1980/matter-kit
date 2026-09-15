//! Bulk Data Exchange (Core §11.22), read back from the specification's own tables.
//!
//! The wire formats here are written out by hand — `[0x30, 0x00, 0x00, 0x04, …]` — rather than
//! checked by round-tripping the crate's own writer through its own reader. A round-trip proves
//! two functions agree; it cannot tell that both of them put the file designator length in the
//! wrong place. Tables 112 to 124 are transcribed a second time, here, and the two
//! transcriptions have to match.
//!
//! The rest is §11.22.6.1's ordering rules and §11.22.5's negotiation, which is where a BDX
//! implementation actually goes wrong: a block counter that skips, a transfer that ends short
//! of a length it promised, a Responder that accepts a mode nobody offered.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::bdx::{
    Block, BlockQueryWithSkip, Counter, Direction, Init, Limits, MessageType, Parameters,
    ReceiveAccept, Receiver, SendAccept, Sender, StatusCode, TransferControl, VERSION, negotiate,
    read_report, report,
};

/// Encodes into a generous buffer and returns exactly what was written.
macro_rules! encoded {
    ($message:expr) => {{
        let mut buf = [0u8; 256];
        let n = $message.encode(&mut buf).unwrap();
        buf[..n].to_vec()
    }};
}

// --- §11.22.3.1: opcodes ---------------------------------------------------------------

#[test]
fn opcodes_are_table_110() {
    for (value, expected) in [
        (0x01, MessageType::SendInit),
        (0x02, MessageType::SendAccept),
        (0x04, MessageType::ReceiveInit),
        (0x05, MessageType::ReceiveAccept),
        (0x10, MessageType::BlockQuery),
        (0x11, MessageType::Block),
        (0x12, MessageType::BlockEof),
        (0x13, MessageType::BlockAck),
        (0x14, MessageType::BlockAckEof),
        (0x15, MessageType::BlockQueryWithSkip),
    ] {
        assert_eq!(MessageType::from_u8(value), Ok(expected));
        assert_eq!(expected.value(), value);
    }
}

#[test]
fn the_reserved_opcodes_are_refused() {
    // Table 110 leaves 0x03 and 0x06..=0x0F "Reserved for future use". Mapping one onto the
    // nearest known message would put the transfer into a state neither end agreed to.
    for value in [0x00, 0x03, 0x06, 0x0F, 0x16, 0xFF] {
        assert_eq!(
            MessageType::from_u8(value),
            Err(StatusCode::UnexpectedMessage),
            "opcode {value:#04x}"
        );
    }
}

// --- §11.22.5.1: Table 112, SendInit/ReceiveInit ----------------------------------------

#[test]
fn a_plain_init_is_seven_octets() {
    // PTC = version 0 with both drive bits: 0x10 | 0x20. RC = 0, nothing optional. PMBS =
    // 1024 little-endian. FDL = 1, FD = "f". No metadata.
    let init = Init::new(b"f", 1024);
    assert_eq!(encoded!(init), [0x30, 0x00, 0x00, 0x04, 0x01, 0x00, b'f']);
}

#[test]
fn range_control_says_which_optional_fields_are_there() {
    let mut init = Init::new(b"f", 1024);
    init.start_offset = Some(5);
    init.definite_length = Some(600);
    assert_eq!(
        encoded!(init),
        [
            0x30, // PTC
            0x03, // RC: DEFLEN | STARTOFS, WIDERANGE clear
            0x00, 0x04, // PMBS = 1024
            0x05, 0x00, 0x00, 0x00, // STARTOFS = 5, four octets
            0x58, 0x02, 0x00, 0x00, // LEN = 600, four octets
            0x01, 0x00, b'f', // FDL, FD
        ]
    );
}

#[test]
fn widerange_is_set_only_when_a_value_needs_it() {
    // §11.22.5.1.2 gives WIDERANGE one bit for both fields, so it is set when *either* needs
    // 64 bits — and, like §A.7.1's narrowest encoding, cleared whenever 32 will do.
    let mut init = Init::new(b"f", 64);
    init.definite_length = Some(u64::from(u32::MAX));
    assert_eq!(encoded!(init)[1], 0x01, "4 GiB - 1 still fits in 32 bits");

    init.definite_length = Some(u64::from(u32::MAX) + 1);
    let wide = encoded!(init);
    assert_eq!(wide[1], 0x11, "WIDERANGE | DEFLEN");
    assert_eq!(&wide[4..12], &[0, 0, 0, 0, 1, 0, 0, 0]);

    // One wide field widens the other: there is only the one bit.
    init.start_offset = Some(1);
    assert_eq!(encoded!(init)[1], 0x13);
    assert_eq!(&encoded!(init)[4..12], &[1, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn a_zero_length_is_an_indefinite_length() {
    // §11.22.5.1.5: "A length of 0 or a missing length field signifies an indefinite length."
    // Two spellings of one thing, so the encoder picks one and the decoder collapses both.
    let mut init = Init::new(b"f", 64);
    init.definite_length = Some(0);
    assert_eq!(
        encoded!(init)[1] & 0x01,
        0,
        "DEFLEN not set for a zero length"
    );
    assert_eq!(Init::decode(&encoded!(init)).unwrap().definite_length, None);

    // And a peer that does spell it out is understood.
    let spelled = [
        0x30, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, b'f',
    ];
    assert_eq!(Init::decode(&spelled).unwrap().definite_length, None);
}

#[test]
fn metadata_runs_to_the_end_of_the_payload() {
    // §11.22.5.1.7: "The TLV metadata consumes the rest of the payload … after all previous
    // fields." There is no length in front of it, so the file designator's length is the only
    // thing separating the two variable fields.
    let mut init = Init::new(b"designator", 64);
    init.metadata = &[0x15, 0x18]; // an empty TLV structure
    let bytes = encoded!(init);
    let back = Init::decode(&bytes).unwrap();
    assert_eq!(back.file_designator, b"designator");
    assert_eq!(back.metadata, &[0x15, 0x18]);
    assert_eq!(back, init);
}

#[test]
fn a_truncated_init_is_bad_message_contents() {
    let bytes = encoded!(Init::new(b"designator", 64));
    for cut in 0..bytes.len() {
        assert_eq!(
            Init::decode(&bytes[..cut]).map(|init| init.file_designator),
            Err(StatusCode::BadMessageContents),
            "truncated to {cut}"
        );
    }
    assert!(Init::decode(&bytes).is_ok());
}

// --- §11.22.5.4: Tables 115 and 116, the Accepts ----------------------------------------

#[test]
fn a_send_accept_has_no_range_control() {
    // Table 115: TC, MBS, MDATA — and no RC, because the Initiator is the Sender and already
    // said how much it would send.
    let accept = SendAccept {
        control: TransferControl {
            version: VERSION,
            sender_drive: true,
            receiver_drive: false,
            asynchronous: false,
        },
        max_block_size: 512,
        metadata: &[],
    };
    assert_eq!(encoded!(accept), [0x10, 0x00, 0x02]);
    assert_eq!(SendAccept::decode(&encoded!(accept)).unwrap(), accept);
}

#[test]
fn a_receive_accept_carries_the_length() {
    // Table 116: TC, RC, MBS, optional LEN, MDATA.
    let accept = ReceiveAccept {
        control: TransferControl {
            version: VERSION,
            sender_drive: true,
            receiver_drive: false,
            asynchronous: false,
        },
        max_block_size: 256,
        length: Some(600),
        metadata: &[],
    };
    assert_eq!(
        encoded!(accept),
        [0x10, 0x01, 0x00, 0x01, 0x58, 0x02, 0x00, 0x00]
    );
    assert_eq!(ReceiveAccept::decode(&encoded!(accept)).unwrap(), accept);
}

#[test]
fn transfer_control_bits_are_table_113() {
    for (octet, control) in [
        (0x00, TransferControl::default()),
        (
            0x10,
            TransferControl {
                version: 0,
                sender_drive: true,
                receiver_drive: false,
                asynchronous: false,
            },
        ),
        (
            0x20,
            TransferControl {
                version: 0,
                sender_drive: false,
                receiver_drive: true,
                asynchronous: false,
            },
        ),
        (
            0x40,
            TransferControl {
                version: 0,
                sender_drive: false,
                receiver_drive: false,
                asynchronous: true,
            },
        ),
        (
            0x0F,
            TransferControl {
                version: 15,
                sender_drive: false,
                receiver_drive: false,
                asynchronous: false,
            },
        ),
    ] {
        assert_eq!(TransferControl::from_u8(octet), control);
        assert_eq!(control.to_u8(), octet);
    }
    // Bit 7 is RFU: ignored on the way in, never set on the way out.
    assert_eq!(TransferControl::from_u8(0x90).to_u8(), 0x10);
}

// --- §11.22.6: the data messages --------------------------------------------------------

#[test]
fn a_block_is_a_counter_then_the_rest_of_the_payload() {
    let block = Block {
        counter: 0x0102_0304,
        data: b"abc",
    };
    assert_eq!(encoded!(block), [0x04, 0x03, 0x02, 0x01, b'a', b'b', b'c']);
    assert_eq!(Block::decode(&encoded!(block)).unwrap(), block);
    // An empty BlockEOF is the shortest legal block payload.
    assert_eq!(Block::decode(&[0, 0, 0, 0]).unwrap().data, b"");
}

#[test]
fn a_bare_counter_message_has_nothing_after_the_counter() {
    let counter = Counter { counter: 7 };
    assert_eq!(encoded!(counter), [7, 0, 0, 0]);
    assert_eq!(Counter::decode(&[7, 0, 0, 0]).unwrap(), counter);
    // Unlike a Block, there is no variable field to absorb a trailing octet, so one means the
    // two ends disagree about the format.
    assert_eq!(
        Counter::decode(&[7, 0, 0, 0, 0]),
        Err(StatusCode::BadMessageContents)
    );
    assert_eq!(
        Counter::decode(&[7, 0, 0]),
        Err(StatusCode::BadMessageContents)
    );
}

#[test]
fn block_query_with_skip_is_twelve_octets() {
    // Table 120: a 4-octet counter and an 8-octet BytesToSkip, both little-endian.
    let query = BlockQueryWithSkip {
        counter: 1,
        bytes_to_skip: 0x0102_0304_0506_0708,
    };
    assert_eq!(
        encoded!(query),
        [
            0x01, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        ]
    );
    assert_eq!(BlockQueryWithSkip::decode(&encoded!(query)).unwrap(), query);
}

// --- §11.22.5: negotiation --------------------------------------------------------------

fn download(init: &Init<'_>, limits: &Limits) -> Result<Parameters, StatusCode> {
    negotiate(Direction::Download, init, limits)
}

#[test]
fn a_responder_offered_both_modes_chooses_sender_drive() {
    // §11.22.5.4.1: "If the Initiator proposed both the PTC[RECEIVER_DRIVE] and
    // PTC[SENDER_DRIVE], the Responder SHALL select exactly one of those options. In that case,
    // to retain the request/response semantics, the Responder SHALL default to
    // TC[SENDER_DRIVE]."
    let agreed = download(&Init::new(b"f", 64), &Limits::default()).unwrap();
    assert!(agreed.sender_drives());
    assert!(!agreed.receiver_drives());
    assert!(agreed.control.is_decided());
}

#[test]
fn a_responder_offered_only_receiver_drive_uses_it() {
    let mut init = Init::new(b"f", 64);
    init.control.sender_drive = false;
    let agreed = download(&init, &Limits::default()).unwrap();
    assert!(agreed.receiver_drives());
    assert!(!agreed.sender_drives());
}

#[test]
fn a_proposal_with_no_drive_mode_is_rejected() {
    // §11.22.5.1.1: "If neither PTC[RECEIVER_DRIVE] or PTC[SENDER_DRIVE] is set, the transfer
    // SHALL be rejected by the Responder."
    let mut init = Init::new(b"f", 64);
    init.control.sender_drive = false;
    init.control.receiver_drive = false;
    assert_eq!(
        download(&init, &Limits::default()),
        Err(StatusCode::TransferMethodNotSupported)
    );
}

#[test]
fn asynchronous_mode_is_never_chosen() {
    // §11.22.5.4.1: "Support for the asynchronous mode is provisional and SHALL not be chosen
    // by the Responder." Offering it must not change what comes back.
    let mut init = Init::new(b"f", 64);
    init.control.asynchronous = true;
    let agreed = download(&init, &Limits::default()).unwrap();
    assert!(!agreed.control.asynchronous);
    assert!(agreed.sender_drives());
}

#[test]
fn the_block_size_is_the_smaller_of_the_two() {
    // §11.22.5.4.3: the accepted MBS "SHALL be less than or equal to the proposed max block
    // size" — and no larger than what this node can hold either.
    let limits = Limits {
        max_block_size: 256,
        ..Limits::default()
    };
    assert_eq!(
        download(&Init::new(b"f", 1024), &limits)
            .unwrap()
            .max_block_size,
        256
    );
    assert_eq!(
        download(&Init::new(b"f", 128), &limits)
            .unwrap()
            .max_block_size,
        128
    );
    assert_eq!(
        download(&Init::new(b"f", 0), &limits),
        Err(StatusCode::BadMessageContents)
    );
}

#[test]
fn a_download_is_clamped_to_what_the_responder_actually_has() {
    // §11.22.5.4.4: the accepted length is "smaller than the proposed definite length, if the
    // remaining data in the file beyond the Start Offset is smaller than the proposed length".
    let limits = Limits {
        available: Some(400),
        ..Limits::default()
    };
    let mut init = Init::new(b"f", 64);
    init.definite_length = Some(600);
    assert_eq!(download(&init, &limits).unwrap().length, Some(400));

    // And an indefinite proposal is answered with the size, "if known".
    init.definite_length = None;
    assert_eq!(download(&init, &limits).unwrap().length, Some(400));
    assert_eq!(download(&init, &Limits::default()).unwrap().length, None);
}

#[test]
fn an_upload_keeps_the_length_the_sender_committed_to() {
    // A SendAccept has no length field, so the Responder either takes the proposed length or
    // rejects the SendInit. `available` is the Responder's own file and means nothing here.
    let mut init = Init::new(b"f", 64);
    init.definite_length = Some(600);
    let limits = Limits {
        available: Some(400),
        ..Limits::default()
    };
    let agreed = negotiate(Direction::Upload, &init, &limits).unwrap();
    assert_eq!(agreed.length, Some(600));
}

#[test]
fn every_rejection_reason_has_its_own_status_code() {
    let mut init = Init::new(b"f", 64);
    init.definite_length = Some(600);

    assert_eq!(
        download(
            &init,
            &Limits {
                max_length: Some(599),
                ..Limits::default()
            }
        ),
        Err(StatusCode::LengthTooLarge)
    );
    assert_eq!(
        download(
            &init,
            &Limits {
                min_length: Some(601),
                ..Limits::default()
            }
        ),
        Err(StatusCode::LengthTooShort)
    );
    assert_eq!(
        download(
            &init,
            &Limits {
                busy: true,
                ..Limits::default()
            }
        ),
        Err(StatusCode::ResponderBusy)
    );

    let mut indefinite = Init::new(b"f", 64);
    assert_eq!(
        download(
            &indefinite,
            &Limits {
                require_definite_length: true,
                ..Limits::default()
            }
        ),
        Err(StatusCode::LengthRequired)
    );

    // §11.22.5.1.3 turns on the *presence* of the field, not on a non-zero value.
    indefinite.start_offset = Some(0);
    assert_eq!(
        download(
            &indefinite,
            &Limits {
                allow_start_offset: false,
                ..Limits::default()
            }
        ),
        Err(StatusCode::StartOffsetNotSupported)
    );
    assert!(download(&indefinite, &Limits::default()).is_ok());
}

// --- §11.22.5.1: the Initiator checks the Accept ----------------------------------------

#[test]
fn an_accept_that_changes_the_deal_is_refused() {
    let proposal = Init::new(b"f", 256);
    let good = SendAccept {
        control: TransferControl {
            version: VERSION,
            sender_drive: true,
            receiver_drive: false,
            asynchronous: false,
        },
        max_block_size: 256,
        metadata: &[],
    };
    assert!(Parameters::from_send_accept(&proposal, &good).is_ok());

    // A block size larger than proposed (§11.22.5.4.3), or none at all.
    let mut bigger = good;
    bigger.max_block_size = 257;
    assert_eq!(
        Parameters::from_send_accept(&proposal, &bigger),
        Err(StatusCode::BadMessageContents)
    );
    let mut zero = good;
    zero.max_block_size = 0;
    assert_eq!(
        Parameters::from_send_accept(&proposal, &zero),
        Err(StatusCode::BadMessageContents)
    );

    // Both drive bits, or neither: §11.22.5.4.1 wants exactly one.
    let mut both = good;
    both.control.receiver_drive = true;
    assert_eq!(
        Parameters::from_send_accept(&proposal, &both),
        Err(StatusCode::TransferMethodNotSupported)
    );
    let mut neither = good;
    neither.control.sender_drive = false;
    assert_eq!(
        Parameters::from_send_accept(&proposal, &neither),
        Err(StatusCode::TransferMethodNotSupported)
    );

    // Asynchronous mode is provisional, and a Responder is told not to choose it.
    let mut asynchronous = good;
    asynchronous.control.asynchronous = true;
    assert_eq!(
        Parameters::from_send_accept(&proposal, &asynchronous),
        Err(StatusCode::TransferMethodNotSupported)
    );

    // A version newer than the one proposed.
    let mut newer = good;
    newer.control.version = 1;
    assert_eq!(
        Parameters::from_send_accept(&proposal, &newer),
        Err(StatusCode::VersionNotSupported)
    );
}

#[test]
fn a_mode_that_was_not_offered_is_refused() {
    // "exactly one mode SHALL be chosen for this transfer, which SHALL be one of the original
    // proposed transfer methods sent by the Initiator."
    let mut proposal = Init::new(b"f", 256);
    proposal.control.receiver_drive = false; // sender drive only
    let accept = SendAccept {
        control: TransferControl {
            version: VERSION,
            sender_drive: false,
            receiver_drive: true,
            asynchronous: false,
        },
        max_block_size: 256,
        metadata: &[],
    };
    assert_eq!(
        Parameters::from_send_accept(&proposal, &accept),
        Err(StatusCode::TransferMethodNotSupported)
    );
}

#[test]
fn a_download_may_not_grow_past_what_was_asked_for() {
    let mut proposal = Init::new(b"f", 256);
    proposal.definite_length = Some(100);
    let accept = ReceiveAccept {
        control: TransferControl {
            version: VERSION,
            sender_drive: true,
            receiver_drive: false,
            asynchronous: false,
        },
        max_block_size: 256,
        length: Some(101),
        metadata: &[],
    };
    assert_eq!(
        Parameters::from_receive_accept(&proposal, &accept),
        Err(StatusCode::LengthTooLarge)
    );
    let smaller = ReceiveAccept {
        length: Some(60),
        ..accept
    };
    assert_eq!(
        Parameters::from_receive_accept(&proposal, &smaller)
            .unwrap()
            .length,
        Some(60)
    );
}

// --- §11.22.6.1: block ordering ---------------------------------------------------------

/// A pair of halves that have agreed the given mode, block size and length.
fn pair(sender_drive: bool, max_block_size: u16, length: Option<u64>) -> (Sender, Receiver) {
    let mut proposal = Init::new(b"f", max_block_size);
    proposal.definite_length = length;
    proposal.control.receiver_drive = !sender_drive;
    proposal.control.sender_drive = sender_drive;
    let limits = Limits {
        available: length,
        ..Limits::default()
    };
    let agreed = negotiate(Direction::Download, &proposal, &limits).unwrap();
    let accept = agreed.receive_accept(&[]);
    let mirrored = Parameters::from_receive_accept(&proposal, &accept).unwrap();
    assert_eq!(agreed, mirrored, "both ends read the accept the same way");
    (Sender::new(agreed), Receiver::new(mirrored))
}

#[test]
fn a_sender_driven_transfer_runs_block_ack_block_ack() {
    let (mut sender, mut receiver) = pair(true, 4, Some(10));
    for (len, eof) in [(4, false), (4, false), (2, true)] {
        let counter = sender.block(len, eof).unwrap();
        receiver.on_block(counter, len, eof).unwrap();
        let (opcode, acked) = receiver.ack().unwrap();
        assert_eq!(
            opcode,
            if eof {
                MessageType::BlockAckEof
            } else {
                MessageType::BlockAck
            }
        );
        sender.on_ack(acked, eof).unwrap();
    }
    assert!(sender.is_complete() && receiver.is_complete());
    assert_eq!(sender.sent(), 10);
    assert_eq!(receiver.received(), 10);
}

#[test]
fn a_receiver_driven_transfer_runs_query_block_query_block() {
    let (mut sender, mut receiver) = pair(false, 4, Some(6));
    for (len, eof) in [(4, false), (2, true)] {
        let asked = receiver.query().unwrap();
        sender.on_query(asked).unwrap();
        let counter = sender.block(len, eof).unwrap();
        receiver.on_block(counter, len, eof).unwrap();
        let (_, acked) = receiver.ack().unwrap();
        sender.on_ack(acked, eof).unwrap();
    }
    assert!(receiver.is_complete());
    assert_eq!(receiver.received(), 6);
}

#[test]
fn a_receiver_driven_sender_may_not_speak_first() {
    // The whole point of Receiver drive: a sleepy node is not woken by blocks it never asked
    // for.
    let (mut sender, _) = pair(false, 4, None);
    assert!(!sender.may_send());
    assert_eq!(sender.block(4, false), Err(StatusCode::UnexpectedMessage));
}

#[test]
fn a_sender_driven_receiver_may_not_query() {
    let (_, mut receiver) = pair(true, 4, None);
    assert_eq!(receiver.query(), Err(StatusCode::UnexpectedMessage));
}

#[test]
fn a_block_counter_that_skips_is_bad_block_counter() {
    // §11.22.6.1: "If the arriving Block Counter at the recipient is not exactly equal to
    // current expected Block Counter, the block counter SHALL be considered out-of-order."
    let (_, mut receiver) = pair(true, 4, None);
    assert_eq!(
        receiver.on_block(1, 4, false),
        Err(StatusCode::BadBlockCounter)
    );
    receiver.on_block(0, 4, false).unwrap();
    receiver.ack().unwrap();
    assert_eq!(
        receiver.on_block(2, 4, false),
        Err(StatusCode::BadBlockCounter)
    );
    assert_eq!(
        receiver.on_block(0, 4, false),
        Err(StatusCode::BadBlockCounter)
    );
    assert!(receiver.on_block(1, 4, false).is_ok());
}

#[test]
fn an_acknowledgement_names_the_block_it_acknowledges() {
    // §11.22.6.6: the counter "SHALL correspond to the Block Counter which was embedded in the
    // Block being acknowledged".
    let (mut sender, _) = pair(true, 4, None);
    let counter = sender.block(4, false).unwrap();
    assert_eq!(counter, 0);
    assert_eq!(sender.on_ack(1, false), Err(StatusCode::BadBlockCounter));
    assert!(sender.on_ack(0, false).is_ok());
}

#[test]
fn a_query_counter_that_skips_is_bad_block_counter() {
    // "Queries SHALL be made in ascending and sequential Block Counter order."
    let (mut sender, _) = pair(false, 4, None);
    assert_eq!(sender.on_query(1), Err(StatusCode::BadBlockCounter));
    sender.on_query(0).unwrap();
    sender.block(4, false).unwrap();
    sender.on_ack(0, false).unwrap();
    assert_eq!(sender.on_query(0), Err(StatusCode::BadBlockCounter));
    assert!(sender.on_query(1).is_ok());
}

#[test]
fn a_block_ack_eof_answers_a_block_eof_and_nothing_else() {
    let (mut sender, _) = pair(true, 4, None);
    sender.block(4, false).unwrap();
    // A BlockAckEOF for a plain Block would end a session that has not ended.
    assert_eq!(sender.on_ack(0, true), Err(StatusCode::UnexpectedMessage));
    sender.on_ack(0, false).unwrap();
    assert!(!sender.is_complete());

    sender.block(0, true).unwrap();
    assert_eq!(sender.on_ack(1, false), Err(StatusCode::UnexpectedMessage));
    sender.on_ack(1, true).unwrap();
    assert!(sender.is_complete());
}

// --- §11.22.6.4, §11.22.6.5: block sizes ------------------------------------------------

#[test]
fn a_block_may_not_exceed_the_negotiated_size() {
    let (mut sender, mut receiver) = pair(true, 4, None);
    assert_eq!(sender.block(5, false), Err(StatusCode::BadMessageContents));
    assert_eq!(
        receiver.on_block(0, 5, false),
        Err(StatusCode::BadMessageContents)
    );
    assert!(sender.block(4, false).is_ok());
}

#[test]
fn only_a_block_eof_may_be_empty() {
    // §11.22.6.4 gives Block the range "[0 < Length <= Max Block Size]"; §11.22.6.5 gives
    // BlockEOF "[0 <= Length <= Max Block Size] … a length of 0 is permissible to indicate an
    // empty file."
    let (mut sender, mut receiver) = pair(true, 4, None);
    assert_eq!(sender.block(0, false), Err(StatusCode::BadMessageContents));
    assert_eq!(
        receiver.on_block(0, 0, false),
        Err(StatusCode::BadMessageContents)
    );
    assert!(sender.block(0, true).is_ok());
}

#[test]
fn an_empty_file_is_one_block_eof_with_counter_zero() {
    // §11.22.6.5: "If the entire transfer fits within the negotiated block size, the BlockEOF
    // SHALL be the one and only message sent in the exchange … the Block Counter would be 0."
    let (mut sender, mut receiver) = pair(true, 16, Some(0));
    let counter = sender.block(0, true).unwrap();
    assert_eq!(counter, 0);
    receiver.on_block(counter, 0, true).unwrap();
    let (opcode, acked) = receiver.ack().unwrap();
    assert_eq!(opcode, MessageType::BlockAckEof);
    sender.on_ack(acked, true).unwrap();
    assert!(receiver.is_complete());
}

// --- §11.22.6.5: the promised length ----------------------------------------------------

#[test]
fn a_transfer_that_ends_short_is_a_length_mismatch() {
    // "the recipient SHALL verify that the pre-negotiated file size was transferred".
    let (mut sender, mut receiver) = pair(true, 4, Some(10));
    sender.block(4, false).unwrap();
    receiver.on_block(0, 4, false).unwrap();
    receiver.ack().unwrap();
    sender.on_ack(0, false).unwrap();
    assert_eq!(sender.block(2, true), Err(StatusCode::LengthMismatch));
    assert_eq!(
        receiver.on_block(1, 2, true),
        Err(StatusCode::LengthMismatch)
    );
}

#[test]
fn a_transfer_that_overruns_its_length_is_caught_a_block_early() {
    let (mut sender, mut receiver) = pair(true, 8, Some(10));
    sender.block(8, false).unwrap();
    receiver.on_block(0, 8, false).unwrap();
    receiver.ack().unwrap();
    sender.on_ack(0, false).unwrap();
    // Three octets left to give but only two owed: refused before the data moves, not after.
    assert_eq!(sender.block(3, false), Err(StatusCode::LengthMismatch));
    assert_eq!(
        receiver.on_block(1, 3, false),
        Err(StatusCode::LengthMismatch)
    );
    assert_eq!(sender.room(), 2);
    assert!(sender.block(2, true).is_ok());
}

#[test]
fn an_indefinite_transfer_ends_whenever_the_sender_says() {
    let (mut sender, mut receiver) = pair(true, 4, None);
    assert_eq!(sender.room(), 4);
    sender.block(4, false).unwrap();
    receiver.on_block(0, 4, false).unwrap();
    receiver.ack().unwrap();
    sender.on_ack(0, false).unwrap();
    assert!(sender.block(1, true).is_ok());
    assert!(receiver.on_block(1, 1, true).is_ok());
}

#[test]
fn nothing_follows_the_end_of_the_transfer() {
    let (mut sender, mut receiver) = pair(true, 4, None);
    sender.block(2, true).unwrap();
    receiver.on_block(0, 2, true).unwrap();
    receiver.ack().unwrap();
    sender.on_ack(0, true).unwrap();
    assert_eq!(sender.block(1, false), Err(StatusCode::UnexpectedMessage));
    assert_eq!(
        receiver.on_block(1, 1, false),
        Err(StatusCode::UnexpectedMessage)
    );
    assert_eq!(receiver.ack(), Err(StatusCode::UnexpectedMessage));
    assert_eq!(sender.on_ack(0, true), Err(StatusCode::UnexpectedMessage));
}

// --- §11.22.6.3: BlockQueryWithSkip -----------------------------------------------------

#[test]
fn a_skip_moves_the_senders_cursor() {
    let mut proposal = Init::new(b"f", 4);
    proposal.control.sender_drive = false;
    proposal.start_offset = Some(100);
    let agreed = negotiate(Direction::Download, &proposal, &Limits::default()).unwrap();
    let mut sender = Sender::new(agreed);
    assert_eq!(sender.cursor(), 100, "the transfer starts at STARTOFS");

    assert_eq!(sender.on_query_with_skip(0, 50).unwrap(), 150);
    sender.block(4, false).unwrap();
    assert_eq!(sender.cursor(), 154, "the data moves it too");
    sender.on_ack(0, false).unwrap();

    // "there SHALL be no error indicated when receiving a request to skip past the end of the
    // transferable data" — the Sender answers with an empty BlockEOF instead.
    assert_eq!(sender.on_query_with_skip(1, u64::MAX).unwrap(), u64::MAX);
    assert!(sender.block(0, true).is_ok());
}

#[test]
fn a_sender_driven_transfer_takes_no_queries() {
    let (mut sender, _) = pair(true, 4, None);
    assert_eq!(sender.on_query(0), Err(StatusCode::UnexpectedMessage));
    assert_eq!(
        sender.on_query_with_skip(0, 8),
        Err(StatusCode::UnexpectedMessage)
    );
}

#[test]
fn a_second_query_before_the_first_is_answered_is_refused() {
    let (mut sender, mut receiver) = pair(false, 4, None);
    receiver.query().unwrap();
    assert_eq!(receiver.query(), Err(StatusCode::UnexpectedMessage));
    sender.on_query(0).unwrap();
    assert_eq!(sender.on_query(1), Err(StatusCode::UnexpectedMessage));
}

// --- §11.22.3.2: status reports ---------------------------------------------------------

#[test]
fn status_codes_are_table_111() {
    for (value, status) in [
        (0x0012, StatusCode::LengthTooLarge),
        (0x0013, StatusCode::LengthTooShort),
        (0x0014, StatusCode::LengthMismatch),
        (0x0015, StatusCode::LengthRequired),
        (0x0016, StatusCode::BadMessageContents),
        (0x0017, StatusCode::BadBlockCounter),
        (0x0018, StatusCode::UnexpectedMessage),
        (0x0019, StatusCode::ResponderBusy),
        (0x001F, StatusCode::TransferFailedUnknownError),
        (0x0050, StatusCode::TransferMethodNotSupported),
        (0x0051, StatusCode::FileDesignatorUnknown),
        (0x0052, StatusCode::StartOffsetNotSupported),
        (0x0053, StatusCode::VersionNotSupported),
        (0x005F, StatusCode::Unknown),
    ] {
        assert_eq!(status.value(), value);
        assert_eq!(StatusCode::from_u16(value), status);
    }
    // Anything else still ends the transfer, so it reads as Unknown rather than failing to
    // read at all.
    assert_eq!(StatusCode::from_u16(0x0001), StatusCode::Unknown);
}

#[test]
fn a_report_names_the_bdx_protocol_and_a_failure() {
    // "StatusReport(GeneralCode: FAILURE, ProtocolId: {VendorID=0x0000, ProtocolId=BDX},
    // ProtocolCode: <value>)". GeneralCode FAILURE is 1; PROTOCOL_ID_BDX is 0x0002.
    let mut buf = [0u8; 16];
    let encoded = report(StatusCode::BadBlockCounter, &mut buf).unwrap();
    assert_eq!(encoded, &[1, 0, 0x02, 0x00, 0x00, 0x00, 0x17, 0x00]);
    assert_eq!(
        read_report(encoded).unwrap(),
        Some(StatusCode::BadBlockCounter)
    );
}

#[test]
fn a_success_report_does_not_end_a_transfer() {
    // Only a failure on the BDX protocol is a BDX abort; a SUCCESS report, or one belonging to
    // another protocol, is somebody else's message.
    let success = [0, 0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(read_report(&success).unwrap(), None);
    let other_protocol = [1, 0, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00];
    assert_eq!(read_report(&other_protocol).unwrap(), None);
}
