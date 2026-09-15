//! The DNS-SD responder against arbitrary queries.
//!
//! A Multicast DNS responder parses packets from **anyone on the link**, before any Matter
//! security exists — earlier in a device's life than even the message header decoder, because
//! it runs before commissioning. And DNS name compression is the classic decompression-loop
//! surface: a pointer that points at itself, at a later name, or into the middle of a record.
//!
//! Six properties:
//!
//! 1. **Nothing panics** on any input, and no buffer is overrun.
//! 2. **Decoding terminates.** A name is followed through pointers that must each go strictly
//!    backwards, so a cycle is impossible rather than merely bounded — but a fuzzer is what
//!    says so about the code rather than about the argument.
//! 3. **Whatever is produced decodes.** A response a querier cannot parse would poison its
//!    cache, and half a record is worse than none.
//! 4. **A response is never produced for a response.** Two responders answering each other is
//!    a way to keep a link busy forever, and it needs only one malformed packet to start.
//! 5. **Probe detection is conservative.** RFC 6762 §6 exempts a probe from the one-second
//!    multicast rate limit, so "is this a probe?" is a question a hostile sender would like to
//!    answer for us. A claimed probe must really carry an Authority record that answers a
//!    question it really asks.
//! 6. **RDATA re-serialises.** §8.2's tiebreak compares uncompressed RDATA, so every record a
//!    hostile message carries gets written back out into a fixed buffer — a length the sender
//!    chose, into a buffer this crate sized.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::discovery::dns::{Questions, RDATA_MAX, RecordType, ResourceRecords, Section};
use matter_kit::discovery::responder::{Advertisement, Responder};
use matter_kit::discovery::txt::{CommissionableTxt, CommissioningMode, TxtReader};
use matter_kit::discovery::{COMMISSIONABLE_SERVICE, OPERATIONAL_SERVICE};
use matter_kit::msg::VendorId;

const LINK_LOCAL: [u8; 16] = [
    0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0xF5, 0x15, 0x57, 0x6F, 0x97, 0x83, 0x3F, 0x30,
];

fuzz_target!(|data: &[u8]| {
    // Reading questions and records must never panic or hang, whatever the bytes are.
    if let Ok(questions) = Questions::decode(data) {
        let _ = questions.id();
        let _ = questions.is_response();
        for question in questions {
            let _ = question;
        }
    }
    if let Ok(records) = ResourceRecords::decode(data) {
        for record in records {
            if let Ok(record) = record {
                // A TXT record's payload is attacker-chosen too.
                if let Some(matter_kit::discovery::ReadData::Txt(bytes)) = record.data {
                    for pair in TxtReader::new(bytes) {
                        let _ = pair;
                    }
                    let _ = TxtReader::new(bytes).decimal("D");
                }
                // Property 6: an arriving record is re-serialised uncompressed to be
                // tiebroken against. `RDATA_MAX` must be enough for anything that decoded.
                if let Some(rdata) = record.data.as_ref() {
                    let mut out = [0u8; RDATA_MAX];
                    rdata
                        .write_rdata(&mut out)
                        .expect("a record that decoded re-serialises");
                }
            }
        }
    }
    // Reading one section must terminate too, and must not lose the errors.
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        if let Ok(records) = ResourceRecords::decode(data) {
            let mut seen = 0usize;
            for record in records.section(section) {
                seen = seen.saturating_add(1);
                assert!(seen < 200_000, "iteration did not terminate");
                if let Ok(record) = record {
                    assert_eq!(record.section, section);
                }
            }
        }
    }

    let txt = CommissionableTxt {
        discriminator: 840,
        vendor_id: Some(VendorId(0xFFF1)),
        product_id: Some(0x8000),
        commissioning_mode: CommissioningMode::Enhanced,
        ..CommissionableTxt::default()
    }
    .encode()
    .expect("a fixed advertisement encodes");
    let operational_txt = matter_kit::discovery::txt::OperationalTxt::default()
        .encode()
        .expect("encodes");

    let commissionable = Advertisement::new(
        "DD200C20D25AE5F7",
        COMMISSIONABLE_SERVICE,
        "B75AFB458ECD",
        11111,
        txt.finish(),
    )
    .with_subtype("_S3")
    .expect("subtype")
    .with_subtype("_L840")
    .expect("subtype")
    .with_subtype("_CM")
    .expect("subtype")
    .with_address(LINK_LOCAL)
    .expect("address");
    let operational = Advertisement::new(
        "2906C908D115D362-8FC7772401CD0696",
        OPERATIONAL_SERVICE,
        "B75AFB458ECD",
        5540,
        operational_txt.finish(),
    )
    .with_subtype("_I2906C908D115D362")
    .expect("subtype")
    .with_address(LINK_LOCAL)
    .expect("address");

    let advertisements = [commissionable, operational];
    let responder = Responder::new(&advertisements);

    let mut buf = [0u8; 2048];
    let Ok((bytes, answered)) = responder.respond(data, &mut buf) else {
        // Running out of room is a legitimate refusal — half a record is worse than none.
        return;
    };

    // Property 3: whatever came out is a message a querier can read, all the way through.
    let records = ResourceRecords::decode(bytes).expect("a served response must decode");
    let mut seen = 0usize;
    for record in records {
        let record = record.expect("every record in a response we wrote must decode");
        assert!(record.kind.is_some(), "we only write types we model");
        seen = seen.saturating_add(1);
    }
    assert_eq!(
        seen,
        answered.answers.saturating_add(answered.additional),
        "the header's counts must describe the body"
    );

    // Property 4.
    let is_response = data.get(2).copied().unwrap_or(0) & 0x80 != 0;
    if is_response {
        assert!(
            answered.is_empty(),
            "a responder must not answer a response"
        );
    }

    // Property 5: a claimed probe really is one, by §6's test.
    if answered.probe {
        let questions = Questions::decode(data).expect("it parsed once already");
        let records = ResourceRecords::decode(data).expect("it parsed once already");
        let mut matched = false;
        for record in records.section(Section::Authority) {
            let Ok(record) = record else { break };
            for question in questions.clone() {
                let Ok(question) = question else { break };
                if record.name == question.name
                    && record.kind.is_some_and(|kind| kind.answers(question.kind))
                {
                    matched = true;
                }
            }
        }
        assert!(matched, "a probe must carry an answering authority record");
    }

    // The messages this responder *sends* must decode as well, and the probe is the one a
    // fuzzer never reaches through `respond`.
    let mut probe_buf = [0u8; 2048];
    if let Ok(probe) = responder.probe(&mut probe_buf) {
        let questions = Questions::decode(probe).expect("our own probe decodes");
        assert!(!questions.is_response(), "a probe is a query");
        for question in questions {
            assert_eq!(question.expect("decodes").kind, RecordType::Any);
        }
        for record in ResourceRecords::decode(probe).expect("decodes") {
            let record = record.expect("decodes");
            assert_eq!(record.section, Section::Authority);
        }
    }
});
