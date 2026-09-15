//! An OTA image moving from this crate's Provider to this crate's Requestor (Core §11.20, §11.22).
//!
//! `tests/ota_provider.rs` and `tests/ota_requestor.rs` each check one cluster against its own
//! section. This runs the whole update: a `QueryImage`, the `bdx:` URI it answers with, a BDX
//! transfer against that file designator, the nine states of §11.20.7.4.2 moving as it goes,
//! and `ApplyUpdateRequest` at the end.
//!
//! The value is that the two halves were written from different chapters. §11.20.6 defines what
//! a provider says; §11.20.7 defines what a requestor does with it; §11.22 defines how the bytes
//! move. Nothing here reaches across: the requestor learns the node and the file *only* from the
//! URI it parsed, and the provider learns what to send *only* from the file designator the
//! `ReceiveInit` carried. A disagreement between the three transcriptions shows up as a transfer
//! that does not complete.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use matter_kit::bdx::{
    self, Block, Counter, Direction, Init, Limits, MessageType, Parameters, Receiver, SendAccept,
    Sender, StatusCode,
};
use matter_kit::clusters::ota_provider::{Answer, ImageUri, OtaProviderHooks, Query};
use matter_kit::clusters::ota_requestor::{ChangeReasonEnum, Event, OtaRequestor, UpdateStateEnum};
use matter_kit::msg::NodeId;

const PROVIDER_NODE: NodeId = NodeId(0x0011_2233_4455_6677);
const NEW_VERSION: u32 = 2;
const BLOCK: u16 = 64;

/// A provider holding one image under one file designator.
#[derive(Debug)]
struct Depot {
    image: Vec<u8>,
    uri: String,
}

impl Depot {
    fn new(len: usize) -> Self {
        let image = (0..len).map(|i| (i % 251) as u8).collect();
        let mut buf = [0u8; 256];
        let uri = ImageUri {
            node_id: PROVIDER_NODE,
            file: "firmware-2.ota",
        }
        .write(&mut buf)
        .unwrap()
        .to_string();
        Self { image, uri }
    }
}

impl OtaProviderHooks for Depot {
    fn query(&self, query: &Query) -> Answer<'_> {
        if query.software_version >= NEW_VERSION {
            return Answer::NotAvailable;
        }
        Answer::Available {
            uri: &self.uri,
            software_version: NEW_VERSION,
            software_version_string: "2.0.0",
            update_token: b"token-01",
            user_consent_needed: false,
        }
    }
}

/// The BDX half of a download, driven by whichever end the negotiation chose.
///
/// Nothing here shares state between the two ends: every step goes through encoded messages,
/// exactly as it would over an exchange.
struct Transfer {
    sender: Sender,
    receiver: Receiver,
    image: Vec<u8>,
    received: Vec<u8>,
}

impl Transfer {
    /// The `ReceiveInit`/`ReceiveAccept` negotiation, through encoded messages.
    fn open(depot: &Depot, file: &str, block: u16) -> Result<Self, StatusCode> {
        let mut proposal = Init::new(file.as_bytes(), block);
        proposal.definite_length = Some(depot.image.len() as u64);

        // On the wire, and back.
        let mut buf = [0u8; 256];
        let n = proposal.encode(&mut buf).unwrap();
        let seen = Init::decode(&buf[..n])?;

        // The provider looks the file designator up the way it would any request: by name.
        let designator = core::str::from_utf8(seen.file_designator).map_err(|_| {
            // A designator that is not text is not one this provider issued.
            StatusCode::FileDesignatorUnknown
        })?;
        if designator != "firmware-2.ota" {
            return Err(StatusCode::FileDesignatorUnknown);
        }
        let agreed = bdx::negotiate(
            Direction::Download,
            &seen,
            &Limits {
                max_block_size: 128,
                available: Some(depot.image.len() as u64),
                ..Limits::default()
            },
        )?;

        let mut accept_buf = [0u8; 64];
        let n = agreed.receive_accept(&[]).encode(&mut accept_buf).unwrap();
        let accept = bdx::ReceiveAccept::decode(&accept_buf[..n])?;
        let mirrored = Parameters::from_receive_accept(&proposal, &accept)?;

        Ok(Self {
            sender: Sender::new(agreed),
            receiver: Receiver::new(mirrored),
            image: depot.image.clone(),
            received: Vec::new(),
        })
    }

    /// One request/response round, returning whether the transfer is over.
    fn step(&mut self) -> Result<bool, StatusCode> {
        let mut buf = [0u8; 256];

        // Receiver drive would send a BlockQuery here; Sender drive sends the block directly.
        if self.sender.parameters().receiver_drives() {
            let asked = self.receiver.query()?;
            let n = Counter { counter: asked }.encode(&mut buf).unwrap();
            let query = Counter::decode(&buf[..n])?;
            self.sender.on_query(query.counter)?;
        }

        let from = self.sender.cursor() as usize;
        let take = self
            .sender
            .room()
            .min(self.image.len().saturating_sub(from));
        let eof = from + take >= self.image.len();
        let counter = self.sender.block(take, eof)?;

        let n = Block {
            counter,
            data: &self.image[from..from + take],
        }
        .encode(&mut buf)
        .unwrap();
        let block = Block::decode(&buf[..n])?;
        self.receiver
            .on_block(block.counter, block.data.len(), eof)?;
        self.received.extend_from_slice(block.data);

        let (opcode, acked) = self.receiver.ack()?;
        let n = Counter { counter: acked }.encode(&mut buf).unwrap();
        let ack = Counter::decode(&buf[..n])?;
        self.sender
            .on_ack(ack.counter, opcode == MessageType::BlockAckEof)?;
        Ok(self.receiver.is_complete())
    }

    /// How far along, as §11.20.7.5's percentage.
    fn percent(&self) -> u8 {
        let total = self.image.len().max(1) as u64;
        ((self.received.len() as u64 * 100) / total) as u8
    }
}

type Requestor<'a> = OtaRequestor<'a, (), 4>;

#[test]
fn an_image_moves_from_the_provider_to_the_requestor() {
    // The cluster's own wire path is `tests/ota_provider.rs`; what is under test here is the
    // provider's *answer* and what the requestor does with it.
    let depot = Depot::new(1000);
    let requestor = Requestor::new(&());

    // 1. The requestor asks. §11.20.7.4.2's `Querying`.
    requestor.transition(UpdateStateEnum::Querying, ChangeReasonEnum::Success, None);
    let answer = depot.query(&Query {
        vendor_id: matter_kit::msg::VendorId(0xFFF1),
        product_id: 0x8000,
        software_version: 1,
        hardware_version: None,
        requestor_can_consent: false,
        supports_bdx: true,
        supports_https: false,
    });
    let Answer::Available {
        uri,
        software_version,
        ..
    } = answer
    else {
        panic!("an image is available");
    };
    assert_eq!(software_version, NEW_VERSION);

    // 2. The requestor learns where to fetch from *only* from the URI (§11.20.6.5).
    let image_uri = ImageUri::parse(uri).expect("a bdx: URI");
    assert_eq!(image_uri.node_id, PROVIDER_NODE);

    // 3. BDX. §11.20.7.4.2's `Downloading`, with the version it is downloading.
    requestor.transition(
        UpdateStateEnum::Downloading,
        ChangeReasonEnum::Success,
        Some(software_version),
    );
    let mut transfer = Transfer::open(&depot, image_uri.file, BLOCK).expect("negotiated");
    // §11.22.5.4.1 prefers Sender drive when both are offered.
    assert!(transfer.sender.parameters().sender_drives());
    assert_eq!(transfer.sender.parameters().max_block_size, BLOCK);

    while !transfer.step().expect("a clean transfer") {
        requestor.set_progress(Some(transfer.percent())).unwrap();
    }
    requestor.set_progress(Some(100)).unwrap();

    // 4. Every octet, in order.
    assert_eq!(transfer.received, depot.image);
    assert_eq!(transfer.receiver.received(), 1000);

    // 5. Apply, then the version is running. §11.20.7.7.2's `VersionApplied`.
    requestor.transition(
        UpdateStateEnum::Applying,
        ChangeReasonEnum::Success,
        Some(software_version),
    );
    assert_eq!(
        requestor.progress(),
        None,
        "a new state has no progress yet"
    );
    requestor.transition(UpdateStateEnum::Idle, ChangeReasonEnum::Success, None);
    requestor.version_applied(software_version, 0x8000);

    let events = requestor.take_events();
    let states: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::StateTransition {
                new_state,
                target_software_version,
                ..
            } => Some((*new_state, *target_software_version)),
            _ => None,
        })
        .collect();
    assert_eq!(
        states,
        vec![
            (UpdateStateEnum::Querying, None),
            (UpdateStateEnum::Downloading, Some(NEW_VERSION)),
            (UpdateStateEnum::Applying, Some(NEW_VERSION)),
            // §11.20.7.7.1: null outside the three states that have a target.
            (UpdateStateEnum::Idle, None),
        ]
    );
    assert_eq!(
        events.last(),
        Some(&Event::VersionApplied {
            software_version: NEW_VERSION,
            product_id: 0x8000,
        })
    );
}

#[test]
fn a_block_size_the_provider_cannot_meet_is_negotiated_down() {
    // §11.22.5.4.3: the accepted Max Block Size "SHALL be less than or equal to the proposed
    // max block size" — and no larger than what the sender can produce either.
    let depot = Depot::new(300);
    let transfer = Transfer::open(&depot, "firmware-2.ota", 1024).expect("negotiated");
    assert_eq!(transfer.sender.parameters().max_block_size, 128);
}

#[test]
fn an_image_shorter_than_one_block_is_a_single_block_eof() {
    // §11.22.6.5: "If the entire transfer fits within the negotiated block size, the BlockEOF
    // SHALL be the one and only message sent in the exchange."
    let depot = Depot::new(10);
    let mut transfer = Transfer::open(&depot, "firmware-2.ota", BLOCK).expect("negotiated");
    assert!(transfer.step().expect("one step"));
    assert_eq!(transfer.received, depot.image);
}

#[test]
fn an_unknown_file_designator_is_refused_before_any_data_moves() {
    // §11.22.5.1: "FILE_DESIGNATOR_UNKNOWN: The file designator field was present and contained
    // a file designator not found or supported by the responder."
    let depot = Depot::new(100);
    assert_eq!(
        Transfer::open(&depot, "firmware-3.ota", BLOCK).err(),
        Some(StatusCode::FileDesignatorUnknown)
    );
}

#[test]
fn a_failed_download_records_how_far_it_got() {
    // §11.20.7.7.3: `DownloadError` carries the bytes and "the nearest integer percent value",
    // which is what tells a fleet operator whether the image or the link is at fault.
    let depot = Depot::new(1000);
    let requestor = Requestor::new(&());
    requestor.transition(
        UpdateStateEnum::Downloading,
        ChangeReasonEnum::Success,
        Some(NEW_VERSION),
    );

    let mut transfer = Transfer::open(&depot, "firmware-2.ota", BLOCK).expect("negotiated");
    transfer.step().expect("one block");
    transfer.step().expect("another");

    // The link drops. Whatever the requestor holds is what it reports.
    requestor.download_error(
        NEW_VERSION,
        transfer.receiver.received(),
        Some(depot.image.len() as u64),
        Some(-110),
    );
    requestor.transition(UpdateStateEnum::Idle, ChangeReasonEnum::Failure, None);

    let events = requestor.take_events();
    assert_eq!(
        events.get(1),
        Some(&Event::DownloadError {
            software_version: NEW_VERSION,
            bytes_downloaded: 128,
            progress_percent: Some(13),
            platform_code: Some(-110),
        })
    );
}

#[test]
fn the_provider_declines_a_device_that_is_already_current() {
    let depot = Depot::new(100);
    let answer = depot.query(&Query {
        vendor_id: matter_kit::msg::VendorId(0xFFF1),
        product_id: 0x8000,
        software_version: NEW_VERSION,
        hardware_version: None,
        requestor_can_consent: false,
        supports_bdx: true,
        supports_https: false,
    });
    assert!(matches!(answer, Answer::NotAvailable));
}

#[test]
fn the_uri_the_provider_wrote_is_the_one_the_requestor_reads() {
    // §11.20.6.5 fixes the syntax so a requestor may parse by position: "exactly 16 characters
    // to encode the network byte order value of the NodeID", uppercase, leading zeros included.
    let depot = Depot::new(1);
    let uri = &depot.uri;
    assert_eq!(uri, "bdx://0011223344556677/firmware-2.ota");
    let parsed = ImageUri::parse(uri).unwrap();
    assert_eq!(parsed.node_id, PROVIDER_NODE);
    assert_eq!(parsed.file, "firmware-2.ota");
}

/// A `SendAccept` is not a `ReceiveAccept`, and a requestor that took one would read the block
/// size out of the wrong offset.
#[test]
fn a_download_is_not_accepted_by_an_upload_accept() {
    let proposal = Init::new(b"firmware-2.ota", BLOCK);
    let send_accept = SendAccept {
        control: proposal.control,
        max_block_size: BLOCK,
        metadata: &[],
    };
    // The two messages have different opcodes for exactly this reason (§11.22.3.1).
    assert_ne!(
        MessageType::SendAccept.value(),
        MessageType::ReceiveAccept.value()
    );
    // And a SendAccept's Transfer Control still has both drive bits, which no Accept may.
    assert_eq!(
        Parameters::from_send_accept(&proposal, &send_accept),
        Err(StatusCode::TransferMethodNotSupported)
    );
}
