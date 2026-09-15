//! The commissioning clusters against arbitrary invoke and write payloads.
//!
//! `ArmFailSafe` and `SetRegulatoryConfig` are the two commands a device accepts **before it
//! has any idea who is talking to it** — they run over PASE, during commissioning, from
//! anyone holding the passcode. Their field decoders are therefore about as exposed as
//! anything in the stack, and they are hand-written rather than generated.
//!
//! Four properties:
//!
//! 1. **Nothing panics** on any payload, and no buffer is overrun.
//! 2. **The fail-safe's own invariants hold** whatever arrives: the cumulative deadline never
//!    moves once a context is open, and the context's deadline never outlives it. That is the
//!    property §11.10.7.2 adds the CFSC timer for, and a decoder that let a huge
//!    `ExpiryLengthSeconds` overflow into a wrapped `Instant` would break it silently.
//! 3. **`RegulatoryConfig` only ever holds a value §11.10.5.2 defines** — never a third-party
//!    byte that a radio stack would then be handed.
//! 4. **A response always decodes**, so a malformed request cannot corrupt the session by
//!    producing a half-written `InvokeResponseMessage`.
//! 5. **No fabric is ever joined by accident.** §11.18's `AddNOC` requires a fail-safe, a
//!    session-scoped CSR, a root installed in the same period and a NOC over the key the
//!    device generated — none of which arbitrary bytes can supply. A fabric table that grew
//!    means one of those checks can be bypassed.
//! 6. **The network list never exceeds `MaxNetworks` and never holds a malformed id.**
//!    §11.9.5.5 constrains a `NetworkID` to 1..=32 octets, and §11.9.7.5 caps the list — both
//!    on input a commissioner chose.

#![no_main]

use core::cell::RefCell;
use libfuzzer_sys::fuzz_target;
use matter_kit::clusters::administrator_commissioning::{
    self as admin, AdministratorCommissioning,
};
use matter_kit::clusters::basic_information::{BasicInformation, Location, Product};
use matter_kit::clusters::general_commissioning::{self, GeneralCommissioning, RegulatoryLocation};
use matter_kit::clusters::network_commissioning::{
    self as netcomm, Capabilities, EthernetDriver, NetworkCommissioning,
};
use matter_kit::clusters::operational_credentials::{
    self as opcreds, DeviceAttestation, OperationalCredentials,
};
use matter_kit::clusters::{Descriptor, basic_information, descriptor};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::crypto::{KeyPurpose, KeyStore, SoftKeyStore, SymmetricKey};
use matter_kit::dm::{Endpoint, Node, Privilege};
use matter_kit::fabric::FabricTable;
use matter_kit::im::{
    AccessControl, AttributePath, InvokeRequest, InvokeResponseMessage, Outcome, Server,
    WriteRequest, WriteResponse,
};
use matter_kit::msg::VendorId;
use matter_kit::platform::{Duration, Instant};
use matter_kit::{Config, DefaultConfig};

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

const PRODUCT: Product<'static> = Product::new(
    "Fuzz Vendor",
    VendorId(0xFFF1),
    "Fuzz Product",
    0x8000,
    "fuzz-unique-id",
);

/// §11.19.7.3's lookup, stubbed: no fabric, so the attribute stays null.
static NO_VENDOR: fn(matter_kit::msg::FabricIndex) -> Option<matter_kit::msg::VendorId> = |_| None;

fuzz_target!(|data: &[u8]| {
    // The first octet steers the harness; the rest is the request.
    let Some((&control, payload)) = data.split_first() else {
        return;
    };
    let capability = match control & 0b11 {
        0 => RegulatoryLocation::Indoor,
        1 => RegulatoryLocation::Outdoor,
        _ => RegulatoryLocation::IndoorOutdoor,
    };
    // Bounded so the clock arithmetic is exercised near both ends of the range.
    let now = if control & 0b100 == 0 {
        Instant::ZERO
    } else {
        Instant::MAX.saturating_sub(Duration::from_secs(1))
    };

    let attributes = basic_information::Attributes::new(&PRODUCT, true, true);
    let clusters = [
        descriptor::cluster(),
        attributes.cluster(),
        general_commissioning::cluster(),
        admin::cluster_with_basic(),
        opcreds::cluster(),
    ];
    // Network Commissioning goes on its own endpoint: §11.9's instances are per interface, and
    // a second instance of one cluster id cannot share an endpoint.
    let net_clusters = [netcomm::ethernet()];
    let endpoints = [
        Endpoint::new(0, &clusters).with_device_types(DEVICE_TYPES),
        Endpoint::new(1, &net_clusters),
    ];
    let node = Node::new(&endpoints);
    assert!(
        node.validate().is_ok(),
        "the fixture node must be well formed"
    );

    let location = Location::region_agnostic();
    let fail_safe = RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
    let window = RefCell::new(CommissioningWindow::new());
    let fabrics = RefCell::new(FabricTable::<DefaultConfig, { DefaultConfig::FABRICS }>::new());
    let mut store = SoftKeyStore::<8>::new();
    let dac_key = store
        .import(KeyPurpose::DeviceAttestation, &[7u8; 32])
        .expect("a valid private key");
    let keys = RefCell::new(store);
    let rng = RefCell::new(matter_kit::platform::sim::SimRng::new(
        0xF0FF_1234_5678_9ABC,
    ));
    let challenge = SymmetricKey::new([0x5A; 16]);

    let ethernet = EthernetDriver;
    let network = NetworkCommissioning::<_, 1>::new(&ethernet, &fail_safe, Capabilities::default());
    // §11.9.6.2's "exactly one NetworkInfoStruct instance", automatically populated.
    let _ = network.store_mut().seed(b"eth0", true);

    let handler = (
        Descriptor::new(node, 0),
        BasicInformation::new(&PRODUCT, &location),
        GeneralCommissioning::new(&location, capability, &fail_safe, &window),
        AdministratorCommissioning::new(&window, &fail_safe, &NO_VENDOR).with_basic(),
        OperationalCredentials::new(
            &fabrics,
            &keys,
            &rng,
            &fail_safe,
            DeviceAttestation {
                dac: b"\x30\x03\x02\x01\x01",
                pai: b"\x30\x03\x02\x01\x02",
                certification_declaration: b"\x30\x03\x02\x01\x03",
                dac_key,
                firmware_information: None,
            },
        ),
        network,
    );

    // Open a fail-safe first, so the interesting re-arm and completion paths are reachable
    // from a single input rather than only the first-arm one.
    if control & 0b1000 != 0 {
        handler.2.arm_fail_safe(60, 0, None, false, now);
    }
    let before = handler
        .2
        .fail_safe()
        .armed(now)
        .map(|a| a.cumulative_expires_at);

    let access = AllowAll;
    let server = Server::new(node, &access, &handler, 16);
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 4096];

    if control & 0b1_0000 == 0 {
        if let Ok(request) = InvokeRequest::decode(payload) {
            let ctx = request_context(&request, now, &challenge);
            if let Ok(commands) = request.commands() {
                if let Ok((bytes, _)) =
                    server.serve_invoke(commands, &ctx, false, &mut scratch, &mut buf)
                {
                    // Property 4.
                    let response = InvokeResponseMessage::decode(bytes)
                        .expect("a served invoke must produce a decodable response");
                    if let Ok(responses) = response.responses() {
                        for item in responses {
                            let _ = item.expect("each response must decode");
                        }
                    }
                }
            }
        }
    } else if let Ok(request) = WriteRequest::decode(payload) {
        let ctx = matter_kit::im::InteractionContext {
            now,
            fabric_index: Some(matter_kit::msg::FabricIndex(1)),
            attestation_challenge: Some(&challenge),
            ..matter_kit::im::InteractionContext::default()
        };
        if let Ok(writes) = request.writes() {
            if let Ok((bytes, _)) = server.serve_write(writes, &ctx, false, &mut buf) {
                let response = WriteResponse::decode(bytes)
                    .expect("a served write must produce a decodable response");
                if let Ok(statuses) = response.statuses() {
                    for item in statuses {
                        let _ = item.expect("each status must decode");
                    }
                }
            }
        }
    }

    // Property 2: the cumulative deadline of an open context never moves, and the context's
    // own deadline never outlives it.
    let fail_safe = handler.2.fail_safe();
    if let Some(armed) = fail_safe.armed(now) {
        assert!(
            armed.expires_at <= armed.cumulative_expires_at,
            "the fail-safe outlived its cumulative limit"
        );
        if let Some(before) = before {
            assert_eq!(
                armed.cumulative_expires_at, before,
                "the CFSC timer moved on a re-arm"
            );
        }
    }

    // Property 7: a commissioning window never opens outside §5.4.2.3.1's bounds, and its
    // discriminator is always twelve bits — both of which arbitrary bytes could otherwise set.
    if let Some(open) = window.borrow().open(now) {
        assert!(open.discriminator <= 0x0FFF, "a thirteen-bit discriminator");
        let seconds = open
            .expires_at
            .saturating_duration_since(now)
            .as_micros()
            .saturating_div(1_000_000);
        assert!(
            seconds <= u64::from(admin::COMMISSIONING_TIMEOUT_MAX_SECONDS),
            "a window longer than §5.4.2.3.1 admits"
        );
    }

    // Property 6: the network list stays within its bounds and holds only legal ids.
    {
        let store = handler.5.store();
        assert!(store.entries().len() <= store.capacity());
        for entry in store.entries() {
            assert!(
                !entry.id.is_empty() && entry.id.len() <= netcomm::NETWORK_ID_MAX,
                "a NetworkID outside §11.9.5.5's 1..=32"
            );
        }
    }

    // Property 5: no sequence of arbitrary invokes can add a fabric.
    assert!(
        fabrics.borrow().is_empty(),
        "a fabric was joined without a CSR, a root and a matching NOC"
    );

    // Property 3.
    assert!(matches!(
        handler.2.regulatory_config(),
        RegulatoryLocation::Indoor
            | RegulatoryLocation::Outdoor
            | RegulatoryLocation::IndoorOutdoor
    ));
});

const DEVICE_TYPES: &[matter_kit::clusters::descriptor::DeviceType] =
    &[matter_kit::clusters::descriptor::DeviceType::new(0x0016, 3)];

fn request_context<'a>(
    request: &InvokeRequest<'_>,
    now: Instant,
    challenge: &'a SymmetricKey,
) -> matter_kit::im::InteractionContext<'a> {
    let ctx = matter_kit::im::InteractionContext::new()
        // A fabric index makes the CASE-only paths of §11.10.7.6 reachable.
        .with_fabric(matter_kit::msg::FabricIndex(1))
        .at(now)
        .on_session(matter_kit::msg::SessionId(1))
        // Without it, §11.18's signing commands all refuse before decoding anything.
        .with_attestation_challenge(challenge);
    if request.timed_request {
        ctx.timed()
    } else {
        ctx
    }
}
