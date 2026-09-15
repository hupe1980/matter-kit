//! The OTA Software Update Provider (Core §11.20.6), driven through the interaction model.
//!
//! A provider hands out firmware, and the rules worth testing are the ones that keep a fleet
//! from all doing the same thing at the same moment:
//!
//! * **`DelayedActionTime` is the flow control.** §11.20.6.5 makes it mandatory for `Busy` and
//!   available everywhere else, and it is the only mechanism a provider has to stop a hundred
//!   devices downloading — or rebooting — together.
//! * **Consent may only be demanded of a requestor that can obtain it** (§11.20.3.4), or the
//!   update stalls for ever waiting for a confirmation nothing can give.
//! * **The `bdx:` URI is parsed by position** (§11.20.6.5), so a provider that drops a leading
//!   zero from the node id produces a URI the specification's own example calls invalid.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::{Cell, RefCell};

use matter_kit::clusters::generated;
use matter_kit::clusters::ota_provider::{
    self as ota, Answer, ApplyDecision, ApplyUpdateActionEnum, DownloadProtocolEnum, ImageUri,
    OtaProvider, OtaProviderHooks, Query, StatusEnum,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, CommandData, CommandPath, InteractionContext, InvokeResponse, InvokeResponseMessage,
    Server, Status,
};
use matter_kit::msg::{NodeId, VendorId};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

const PROVIDER_NODE: NodeId = NodeId(0x8899_AABB_CCDD_EEFF);
const TOKEN: &[u8] = b"01234567";

/// A provider holding one image, with knobs a test can turn.
#[derive(Debug)]
struct Depot {
    answer: RefCell<&'static str>,
    consent: Cell<bool>,
    busy_for: Cell<u32>,
    decision: Cell<ApplyDecision>,
    applied: RefCell<Vec<(Vec<u8>, u32)>>,
    queries: RefCell<Vec<Query>>,
}

impl Default for Depot {
    fn default() -> Self {
        Self {
            answer: RefCell::new("available"),
            consent: Cell::new(false),
            busy_for: Cell::new(600),
            decision: Cell::new(ApplyDecision::proceed()),
            applied: RefCell::new(Vec::new()),
            queries: RefCell::new(Vec::new()),
        }
    }
}

const URI: &str = "bdx://8899AABBCCDDEEFF/firmware-2.bin";

impl OtaProviderHooks for Depot {
    fn query(&self, query: &Query) -> Answer<'_> {
        self.queries.borrow_mut().push(*query);
        match *self.answer.borrow() {
            "busy" => Answer::Busy {
                delay_s: self.busy_for.get(),
            },
            "none" => Answer::NotAvailable,
            "protocol" => Answer::ProtocolNotSupported,
            _ => Answer::Available {
                uri: URI,
                software_version: 2,
                software_version_string: "2.0.0",
                update_token: TOKEN,
                user_consent_needed: self.consent.get(),
            },
        }
    }

    fn apply(&self, _update_token: &[u8], _new_version: u32) -> ApplyDecision {
        self.decision.get()
    }

    fn applied(&self, update_token: &[u8], software_version: u32) {
        self.applied
            .borrow_mut()
            .push((update_token.to_vec(), software_version));
    }
}

struct Device<'a> {
    node: Node<'a>,
    cluster: OtaProvider<'a, Depot>,
}

fn device(depot: &Depot) -> Device<'_> {
    let conforming = Box::leak(Box::new(
        OtaProvider::<Depot>::conforming(0, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(0, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: OtaProvider::new(depot),
    }
}

/// What a `QueryImageResponse` or `ApplyUpdateResponse` said.
#[derive(Debug, Default, PartialEq)]
struct Response {
    status: u8,
    delay: Option<u32>,
    uri: Option<String>,
    version: Option<u32>,
    version_string: Option<String>,
    token: Option<Vec<u8>>,
    consent: Option<bool>,
}

fn invoke(device: &Device<'_>, command: u32, fields: Option<&[u8]>) -> Result<Response, Status> {
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(0, ota::ID, command))
    };
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let (bytes, _) = server
        .serve_invoke(
            [Ok(data)],
            &InteractionContext::new(),
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let message = InvokeResponseMessage::decode(bytes).expect("decode");
    match message
        .responses()
        .expect("responses")
        .next()
        .expect("one response")
        .expect("decode")
    {
        InvokeResponse::Command(c) => Ok(decode(c.fields.expect("fields"))),
        InvokeResponse::Status(s) if s.status.status == Status::Success => Ok(Response::default()),
        InvokeResponse::Status(s) => Err(s.status.status),
    }
}

fn decode(fields: &[u8]) -> Response {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Structure));
    let mut out = Response::default();
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        match (field.tag.context(), &field.value) {
            (Some(0), Value::Unsigned(v)) => out.status = *v as u8,
            (Some(1), Value::Unsigned(v)) => out.delay = Some(*v as u32),
            (Some(2), Value::Utf8(v)) => out.uri = Some((*v).to_string()),
            (Some(3), Value::Unsigned(v)) => out.version = Some(*v as u32),
            (Some(4), Value::Utf8(v)) => out.version_string = Some((*v).to_string()),
            (Some(5), Value::Octets(v)) => out.token = Some(v.to_vec()),
            (Some(6), Value::Bool(v)) => out.consent = Some(*v),
            _ => reader.skip_value(&field).unwrap(),
        }
    }
    out
}

/// A `QueryImage` payload.
fn query(software_version: u32, can_consent: bool, protocols: &[DownloadProtocolEnum]) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 0xFFF1).unwrap();
    w.unsigned(Tag::Context(1), 0x8000).unwrap();
    w.unsigned(Tag::Context(2), u64::from(software_version))
        .unwrap();
    w.start_array(Tag::Context(3)).unwrap();
    for protocol in protocols {
        w.unsigned(Tag::Anonymous, u64::from(protocol.value()))
            .unwrap();
    }
    w.end_container().unwrap();
    w.bool(Tag::Context(6), can_consent).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn two_octets_and_version(tag_token: &[u8], version: u32) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.octets(Tag::Context(0), tag_token).unwrap();
    w.unsigned(Tag::Context(1), u64::from(version)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

const BDX: &[DownloadProtocolEnum] = &[DownloadProtocolEnum::BDXSynchronous];

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_cluster_matches_the_specification() {
    let spec = generated::find(ota::ID).expect("OTA Software Update Provider");
    let built = OtaProvider::<Depot>::conforming(0, &Optional::NONE).expect("sized");
    let mut defects = Vec::new();
    spec.validate(&built.descriptor(), |defect| defects.push(defect));
    assert!(defects.is_empty(), "{defects:?}");

    // §11.20.6 defines no attributes at all: a provider is all commands, because everything a
    // client could want is the answer to a query it has to make anyway.
    assert!(built.descriptor().attributes.is_empty());
    assert_eq!(built.descriptor().accepted_commands.len(), 3);
}

// --- QueryImage ---------------------------------------------------------------------------------

#[test]
fn an_available_image_comes_back_with_everything_the_requestor_needs() {
    // §11.20.6.5 makes `ImageURI`, `SoftwareVersion`, `SoftwareVersionString` and `UpdateToken`
    // all conformant on `Status == UpdateAvailable` — a requestor cannot start without any of
    // the four, so an "available" answer missing one is worse than "not available".
    let depot = Depot::default();
    let device = device(&depot);
    let response =
        invoke(&device, ota::QUERY_IMAGE, Some(&query(1, false, BDX))).expect("answered");
    assert_eq!(response.status, StatusEnum::UpdateAvailable.value());
    assert_eq!(response.uri.as_deref(), Some(URI));
    assert_eq!(response.version, Some(2));
    assert_eq!(response.version_string.as_deref(), Some("2.0.0"));
    assert_eq!(response.token.as_deref(), Some(TOKEN));

    // The provider saw what the requestor is running, which is what selection turns on.
    let queries = depot.queries.borrow();
    assert_eq!(queries[0].software_version, 1);
    assert_eq!(queries[0].vendor_id, VendorId(0xFFF1));
    assert!(queries[0].supports_bdx);
    assert!(!queries[0].supports_https);
}

#[test]
fn busy_always_carries_a_time_to_come_back() {
    // §11.20.6.5 makes `DelayedActionTime` mandatory for `Busy`, and it is the only mechanism a
    // provider has to stop a fleet of a hundred devices re-querying in a tight loop.
    let depot = Depot::default();
    let device = device(&depot);
    *depot.answer.borrow_mut() = "busy";
    depot.busy_for.set(900);
    let response =
        invoke(&device, ota::QUERY_IMAGE, Some(&query(1, false, BDX))).expect("answered");
    assert_eq!(response.status, StatusEnum::Busy.value());
    assert_eq!(response.delay, Some(900));
    assert_eq!(response.uri, None, "a busy answer offered an image");
}

#[test]
fn a_delay_longer_than_a_day_is_capped() {
    // §11.20.6.5: "If this field has a value higher than 86400 seconds (24 hours), then the OTA
    // Requestor MAY assume a value of 86400." Sending more is asking for a delay that will be
    // ignored — and a provider that thought it had deferred a device for a week would be
    // surprised.
    let depot = Depot::default();
    let device = device(&depot);
    *depot.answer.borrow_mut() = "busy";
    depot.busy_for.set(7 * 86_400);
    let response =
        invoke(&device, ota::QUERY_IMAGE, Some(&query(1, false, BDX))).expect("answered");
    assert_eq!(response.delay, Some(ota::MAX_USEFUL_DELAY_S));
}

#[test]
fn no_image_and_no_protocol_are_different_answers() {
    // §11.20.6.4: `NotAvailable` is "definitely no update currently available";
    // `DownloadProtocolNotSupported` means there *is* one and this requestor cannot fetch it.
    // A requestor told the first stops asking; told the second it might add a protocol.
    let depot = Depot::default();
    let device = device(&depot);
    *depot.answer.borrow_mut() = "none";
    let response =
        invoke(&device, ota::QUERY_IMAGE, Some(&query(1, false, BDX))).expect("answered");
    assert_eq!(response.status, StatusEnum::NotAvailable.value());

    *depot.answer.borrow_mut() = "protocol";
    let response =
        invoke(&device, ota::QUERY_IMAGE, Some(&query(1, false, BDX))).expect("answered");
    assert_eq!(
        response.status,
        StatusEnum::DownloadProtocolNotSupported.value()
    );
    assert_eq!(response.uri, None);
}

#[test]
fn consent_is_only_demanded_of_a_requestor_that_can_obtain_it() {
    // §11.20.3.4. A provider that demanded consent from a device with no way to ask a person
    // would stall the update for ever, waiting for a confirmation nothing can give — and the
    // device would keep re-querying and keep being told the same thing.
    let depot = Depot::default();
    let device = device(&depot);
    depot.consent.set(true);

    let response =
        invoke(&device, ota::QUERY_IMAGE, Some(&query(1, false, BDX))).expect("answered");
    assert_eq!(
        response.consent,
        Some(false),
        "consent was demanded of a requestor that cannot obtain it"
    );

    let response = invoke(&device, ota::QUERY_IMAGE, Some(&query(1, true, BDX))).expect("answered");
    assert_eq!(response.consent, Some(true));
}

#[test]
fn a_protocol_this_revision_does_not_define_is_ignored_rather_than_refused() {
    // §7.19.2's forward compatibility. A newer requestor may offer a protocol this provider has
    // never heard of; that is not an error in the *request*, and refusing would make every
    // future requestor un-updatable by every current provider.
    let depot = Depot::default();
    let device = device(&depot);
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 0xFFF1).unwrap();
    w.unsigned(Tag::Context(1), 0x8000).unwrap();
    w.unsigned(Tag::Context(2), 1).unwrap();
    w.start_array(Tag::Context(3)).unwrap();
    w.unsigned(Tag::Anonymous, 99).unwrap(); // not in DownloadProtocolEnum
    w.unsigned(
        Tag::Anonymous,
        u64::from(DownloadProtocolEnum::HTTPS.value()),
    )
    .unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    let fields = w.finish().unwrap().to_vec();

    let response = invoke(&device, ota::QUERY_IMAGE, Some(&fields)).expect("answered");
    assert_eq!(response.status, StatusEnum::UpdateAvailable.value());
    let queries = depot.queries.borrow();
    assert!(queries[0].supports_https);
    assert!(!queries[0].supports_bdx, "an unknown value became BDX");
}

// --- ApplyUpdateRequest ---------------------------------------------------------------------

#[test]
fn the_provider_decides_when_a_device_reboots() {
    // §11.20.6.5's `ApplyUpdateResponse`. This is what staggers a fleet: a hundred lights told
    // to reboot at once is a hundred lights dark at once, which is the failure a householder
    // notices and the manufacturer hears about.
    let depot = Depot::default();
    let device = device(&depot);

    depot.decision.set(ApplyDecision::proceed());
    let response = invoke(
        &device,
        ota::APPLY_UPDATE_REQUEST,
        Some(&two_octets_and_version(TOKEN, 2)),
    )
    .expect("answered");
    assert_eq!(response.status, ApplyUpdateActionEnum::Proceed.value());
    assert_eq!(response.delay, Some(0));

    depot.decision.set(ApplyDecision::wait(300));
    let response = invoke(
        &device,
        ota::APPLY_UPDATE_REQUEST,
        Some(&two_octets_and_version(TOKEN, 2)),
    )
    .expect("answered");
    assert_eq!(
        response.status,
        ApplyUpdateActionEnum::AwaitNextAction.value()
    );
    assert_eq!(response.delay, Some(300));

    // §11.20.6.5's day cap applies here too: "If this field has a value higher than 86400
    // seconds ... then the OTA Requestor MAY assume a value of 86400." A provider that thought
    // it had deferred a reboot for a week would find the device back in a day.
    depot.decision.set(ApplyDecision::wait(7 * 86_400));
    let response = invoke(
        &device,
        ota::APPLY_UPDATE_REQUEST,
        Some(&two_octets_and_version(TOKEN, 2)),
    )
    .expect("answered");
    assert_eq!(response.delay, Some(ota::MAX_USEFUL_DELAY_S));

    // §11.20.6.4's `Discontinue` — "a desire to rescind a previously provided Software Image".
    depot.decision.set(ApplyDecision::discontinue());
    let response = invoke(
        &device,
        ota::APPLY_UPDATE_REQUEST,
        Some(&two_octets_and_version(TOKEN, 2)),
    )
    .expect("answered");
    assert_eq!(response.status, ApplyUpdateActionEnum::Discontinue.value());
}

#[test]
fn a_token_outside_the_constraint_is_refused() {
    // §11.20.6.5's constraint on `UpdateToken` is "8 to 32". A token outside it is not one this
    // provider ever issued, so acting on it would be acting on somebody's guess.
    let depot = Depot::default();
    let device = device(&depot);
    for token in [&b"short"[..], &[0u8; 33][..]] {
        assert_eq!(
            invoke(
                &device,
                ota::APPLY_UPDATE_REQUEST,
                Some(&two_octets_and_version(token, 2))
            ),
            Err(Status::ConstraintError),
            "a {}-octet token was accepted",
            token.len()
        );
    }
    assert!(
        invoke(
            &device,
            ota::APPLY_UPDATE_REQUEST,
            Some(&two_octets_and_version(&[0u8; 32], 2))
        )
        .is_ok()
    );
}

#[test]
fn notify_update_applied_is_recorded_and_answers_a_bare_status() {
    // §11.20.6.5 gives it no response command: "An OTA Provider receiving an invocation of this
    // command MAY log it internally", and that is all. It is also optional for the requestor —
    // a device that updated and then fell off the network never sends it, so a provider that
    // waited for one would wait for ever.
    let depot = Depot::default();
    let device = device(&depot);
    let response = invoke(
        &device,
        ota::NOTIFY_UPDATE_APPLIED,
        Some(&two_octets_and_version(TOKEN, 2)),
    )
    .expect("answered");
    assert_eq!(
        response,
        Response::default(),
        "a bare status, not a command"
    );
    assert_eq!(*depot.applied.borrow(), vec![(TOKEN.to_vec(), 2)]);
}

// --- The bdx: URI -------------------------------------------------------------------------------

#[test]
fn a_bdx_uri_round_trips_through_the_specifications_own_examples() {
    // §11.20.6.5 lists these verbatim, valid and invalid, and explains why the syntax is so
    // tight: "the format constraints simplify the extraction of the necessary data", so a
    // requestor parses by position and a provider must give it exactly that shape.
    let parsed = ImageUri::parse("bdx://8899AABBCCDDEEFF/the_file_designator123").expect("valid");
    assert_eq!(parsed.node_id, NodeId(0x8899_AABB_CCDD_EEFF));
    assert_eq!(parsed.file, "the_file_designator123");

    // "Note that the %20 are retained and not converted to ASCII 0x20 (space). The file
    // designator is the path as received verbatim."
    let parsed =
        ImageUri::parse("bdx://0099AABBCCDDEE77/the%20file%20designator/some_more").expect("valid");
    assert_eq!(parsed.node_id, NodeId(0x0099_AABB_CCDD_EE77));
    assert_eq!(parsed.file, "the%20file%20designator/some_more");

    // "Invalid since it is not exactly 16 characters long, due to having omitted leading zeros."
    assert!(ImageUri::parse("bdx://99AABBCCDDEE77/the_file_designator123").is_err());
}

#[test]
fn a_uri_the_provider_writes_is_one_it_can_read() {
    let uri = ImageUri {
        node_id: PROVIDER_NODE,
        file: "firmware-2.bin",
    };
    let mut buf = [0u8; ota::URI_MAX];
    let text = uri.write(&mut buf).expect("writes");
    assert_eq!(text, URI);
    assert_eq!(ImageUri::parse(text).expect("parses"), uri);

    // A node id with leading zeros keeps all sixteen digits — §11.20.6.5's own invalid example
    // is one that dropped them.
    let uri = ImageUri {
        node_id: NodeId(0x0000_0000_0000_0001),
        file: "f",
    };
    let mut buf = [0u8; ota::URI_MAX];
    let text = uri.write(&mut buf).expect("writes");
    assert_eq!(text, "bdx://0000000000000001/f");
    assert_eq!(text.len(), ImageUri::MIN_LEN, "the shortest valid BDX URI");
}

#[test]
fn a_uri_with_a_query_or_a_fragment_is_refused() {
    // §11.20.6.5: "The URI SHALL NOT contain a query field" and "SHALL NOT contain a fragment
    // field". A requestor extracting the file designator as "everything after the first slash"
    // would otherwise ask a BDX server for a file whose name ends in `?v=2`.
    assert!(ImageUri::parse("bdx://8899AABBCCDDEEFF/firmware.bin?v=2").is_err());
    assert!(ImageUri::parse("bdx://8899AABBCCDDEEFF/firmware.bin#top").is_err());
    assert!(
        ImageUri::parse("bdx://8899AABBCCDDEEFF/").is_err(),
        "no file designator"
    );
    assert!(
        ImageUri::parse("http://8899AABBCCDDEEFF/f").is_err(),
        "not bdx"
    );
    // Lowercase, which §11.20.6.5 forbids: "uppercase hexadecimal format".
    assert!(ImageUri::parse("bdx://8899aabbccddeeff/f").is_err());
}

#[test]
fn a_uri_past_the_length_limit_is_refused_rather_than_truncated() {
    // §11.20.6.5's constraint on `ImageURI` is "max 256". A truncated URI is a different file,
    // or no file — and the requestor would have no way to tell.
    let file = "x".repeat(300);
    let uri = ImageUri {
        node_id: PROVIDER_NODE,
        file: &file,
    };
    let mut buf = [0u8; 512];
    assert!(uri.write(&mut buf).is_err());
}
