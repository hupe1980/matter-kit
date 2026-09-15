//! A controller watching an energy device (Core §8.5, §10.7.5).
//!
//! M5's exit criterion in executable form: a client subscribes to a Device Energy Management
//! device, receives reports as its state changes, and notices when it stops hearing from it.
//! Both halves are this crate's — `im::subscription` and `im::server` publish,
//! `im::client` subscribes — and they were written from §8.5 separately.
//!
//! The rule worth the most here is §8.5.3.2's: the *publisher* chooses the `MaxInterval`, and
//! the subscriber has to use the one it was told rather than the ceiling it asked for. A
//! subscriber that assumed otherwise would declare a live subscription dead, tear it down and
//! build another, for ever — on a battery device, until the battery ran out.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::Cell;

use matter_kit::clusters::device_energy_management::{
    self as dem, DemHooks, DeviceEnergyManagement, ESAStateEnum, ESATypeEnum, OptOutStateEnum,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::im::client::{LIVENESS_MARGIN, ReportAssembler, Subscription};
use matter_kit::im::ib::AttributeReport;
use matter_kit::im::message::SubscribeRequest;
use matter_kit::im::subscription::{NewSubscription, ReportReason, SubscriptionTable};
use matter_kit::im::{
    AccessControl, AttributePath, InteractionContext, Outcome, ReportData, Server,
    SubscribeResponse, encode_subscribe_request,
};
use matter_kit::msg::{FabricIndex, SessionId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::Value;
use matter_kit::{Config, DefaultConfig};

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

/// A battery inverter that an energy manager watches.
#[derive(Debug)]
struct Battery {
    state: Cell<ESAStateEnum>,
    opt_out: Cell<OptOutStateEnum>,
}

impl Default for Battery {
    fn default() -> Self {
        Self {
            state: Cell::new(ESAStateEnum::Online),
            opt_out: Cell::new(OptOutStateEnum::NoOptOut),
        }
    }
}

impl DemHooks for Battery {
    fn esa_type(&self) -> ESATypeEnum {
        ESATypeEnum::BatteryStorage
    }

    fn can_generate(&self) -> bool {
        true
    }

    fn base_state(&self) -> ESAStateEnum {
        self.state.get()
    }

    fn abs_min_power(&self) -> i64 {
        -5_000_000
    }

    fn abs_max_power(&self) -> i64 {
        5_000_000
    }

    fn opt_out_state(&self) -> OptOutStateEnum {
        self.opt_out.get()
    }
}

fn at(seconds: u64) -> Instant {
    Instant::ZERO.saturating_add(Duration::from_secs(seconds))
}

/// The subscription table a controller-facing device keeps.
type Table = SubscriptionTable<
    DefaultConfig,
    { DefaultConfig::SUBSCRIPTIONS },
    { DefaultConfig::SUB_PATHS },
>;

const FABRIC: FabricIndex = FabricIndex(1);

struct Device<'a> {
    node: Node<'a>,
    cluster: DeviceEnergyManagement<'a, Battery>,
}

fn device(battery: &Battery) -> Device<'_> {
    let conforming = Box::leak(Box::new(
        DeviceEnergyManagement::<Battery>::conforming(
            dem::feature::POWER_FORECAST_REPORTING,
            &Optional::NONE,
        )
        .expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: DeviceEnergyManagement::new(battery, dem::feature::POWER_FORECAST_REPORTING),
    }
}

fn ctx(now: Instant) -> InteractionContext<'static> {
    InteractionContext {
        fabric_index: Some(FABRIC),
        session: Some(SessionId(1)),
        now,
        ..InteractionContext::default()
    }
}

/// Publishes one report, as the device's loop would when a subscription comes due.
fn publish<'b>(
    device: &Device<'_>,
    subscriptions: &mut Table,
    id: u32,
    reason: ReportReason,
    now: Instant,
    buf: &'b mut [u8],
) -> &'b [u8] {
    let subscription = subscriptions.find_mut(id).expect("a subscription");
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let mut scratch = [0u8; 2048];
    let (bytes, _) = server
        .report(subscription, reason, &ctx(now), &mut scratch, buf)
        .expect("a report");
    bytes
}

// --- Subscribing -----------------------------------------------------------------------------

#[test]
fn a_controller_subscribes_to_an_energy_device_and_is_told_the_real_interval() {
    // §8.5.3.2: the publisher computes the `MaxInterval` and "SHALL report it in the
    // SubscribeResponse". A subscriber that used its own ceiling instead would time out early
    // on any publisher that chose a longer one — and §8.5.3.2 explicitly lets it.
    let battery = Battery::default();
    let device = device(&battery);

    // The controller's request, on the wire.
    let mut buf = [0u8; 512];
    let encoded = encode_subscribe_request(
        &mut buf,
        [
            AttributePath::attribute(1, dem::ID, dem::ESA_STATE),
            AttributePath::attribute(1, dem::ID, dem::OPT_OUT_STATE),
        ],
        [],
        5,
        60,
        true,
        true,
    )
    .expect("encodes")
    .to_vec();

    // The device decodes it and opens a subscription.
    let request = SubscribeRequest::decode(&encoded).expect("decodes");
    assert_eq!(request.min_interval_floor_s, 5);
    assert_eq!(request.max_interval_ceiling_s, 60);
    assert!(request.keep_subscriptions);
    assert!(request.fabric_filtered);
    let paths: Vec<AttributePath> = request
        .attribute_paths()
        .expect("paths")
        .expect("some")
        .map(|p| p.expect("decodes"))
        .collect();
    assert_eq!(paths.len(), 2);

    let mut subscriptions = Table::new();
    let id = subscriptions
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(1)),
                fabric_index: Some(FABRIC),
                peer_node_id: None,
                fabric_filtered: request.fabric_filtered,
                keep_subscriptions: request.keep_subscriptions,
                min_interval_s: request.min_interval_floor_s,
                max_interval_s: request.max_interval_ceiling_s,
                paths: &paths,
                event_paths: &[],
                min_event_number: 0,
            },
            at(0),
        )
        .expect("a subscription");

    let subscription = subscriptions.find(id).expect("it exists");
    let response = SubscribeResponse {
        subscription_id: id,
        max_interval_s: subscription.max_interval_s,
        revision: None,
    };

    // The controller records what it was *told*, not what it asked for.
    let mut held = Subscription::new(&response, at(0));
    assert_eq!(held.id(), id);
    assert_eq!(held.max_interval_s(), response.max_interval_s);

    // §8.5.1's second action: the *priming* report, which carries the whole of what was asked
    // for and goes out before the `SubscribeResponse` above. A subscriber whose first report
    // arrived only when something changed would not know the current state at all — and for an
    // attribute that rarely changes it might never find out.
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let mut scratch = [0u8; 2048];
    let mut buf = [0u8; 2048];
    let (bytes, _) = server
        .prime(
            id,
            paths.iter().copied().map(Ok),
            &ctx(at(0)),
            &mut scratch,
            &mut buf,
        )
        .expect("a priming report");
    let report = ReportData::decode(bytes).expect("decodes");
    assert_eq!(
        report.subscription_id,
        Some(id),
        "§8.5.3.2 requires the priming report to carry the subscription's own id"
    );
    assert!(held.heard(&report, at(0)), "the report was not ours");

    let mut assembler: ReportAssembler<2048> = ReportAssembler::new();
    assert!(assembler.push(&report).expect("push"), "one chunk is whole");
    let reports: Vec<_> = assembler.reports().map(|r| r.expect("decodes")).collect();
    assert_eq!(reports.len(), 2, "both attributes were reported");
}

#[test]
fn a_change_the_controller_asked_about_produces_a_report() {
    // The point of a subscription: the energy manager learns the battery went into a fault
    // without asking, which is what lets it stop planning around a machine that has stopped.
    let battery = Battery::default();
    let device = device(&battery);
    let paths = [AttributePath::attribute(1, dem::ID, dem::ESA_STATE)];
    let mut subscriptions = Table::new();
    let id = subscriptions
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(1)),
                fabric_index: Some(FABRIC),
                peer_node_id: None,
                fabric_filtered: true,
                keep_subscriptions: true,
                min_interval_s: 1,
                max_interval_s: 60,
                paths: &paths,
                event_paths: &[],
                min_event_number: 0,
            },
            at(0),
        )
        .expect("a subscription");

    // Nothing has changed, and the minimum interval has not elapsed.
    assert!(subscriptions.due(at(0)).next().is_none());

    battery.state.set(ESAStateEnum::Fault);
    assert_eq!(
        subscriptions.note_change(&AttributePath::attribute(1, dem::ID, dem::ESA_STATE)),
        1,
        "the change did not reach the subscription"
    );
    let (_, reason) = subscriptions.due(at(2)).next().expect("a report is due");
    assert_eq!(reason, ReportReason::Data);

    let mut buf = [0u8; 2048];
    let bytes = publish(&device, &mut subscriptions, id, reason, at(2), &mut buf);
    let report = ReportData::decode(bytes).expect("decodes");
    let mut assembler: ReportAssembler<2048> = ReportAssembler::new();
    assembler.push(&report).expect("push");

    let value = assembler
        .reports()
        .next()
        .expect("one report")
        .expect("decodes");
    let AttributeReport::Data(value) = value else {
        panic!("expected a value, not a status");
    };
    let mut reader =
        matter_kit::tlv::TlvReader::new_in(value.data, matter_kit::tlv::ContainerKind::Structure);
    let element = reader.next_element().unwrap().unwrap();
    assert_eq!(
        element.value,
        Value::Unsigned(u64::from(ESAStateEnum::Fault.value())),
        "the controller did not learn the new state"
    );
}

// --- Liveness ---------------------------------------------------------------------------------

#[test]
fn a_keep_alive_counts_as_proof_of_life() {
    // §8.5.3: when nothing has changed by the maximum interval "the publisher SHALL send an
    // empty ReportData message". Its whole purpose is to say the subscription is still there,
    // so a subscriber that only counted *data* reports would tear down every subscription to
    // a device that simply is not changing — which is most devices, most of the time.
    let battery = Battery::default();
    let device = device(&battery);
    let paths = [AttributePath::attribute(1, dem::ID, dem::ESA_STATE)];
    let mut subscriptions = Table::new();
    let id = subscriptions
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(1)),
                fabric_index: Some(FABRIC),
                peer_node_id: None,
                fabric_filtered: true,
                keep_subscriptions: true,
                min_interval_s: 1,
                max_interval_s: 30,
                paths: &paths,
                event_paths: &[],
                min_event_number: 0,
            },
            at(0),
        )
        .expect("a subscription");
    let subscription = subscriptions.find(id).expect("it exists");
    let mut held = Subscription::new(
        &SubscribeResponse {
            subscription_id: id,
            max_interval_s: subscription.max_interval_s,
            revision: None,
        },
        at(0),
    );

    // Nothing changed, so the report that goes out at the maximum interval is the empty one.
    let (_, reason) = subscriptions.due(at(30)).next().expect("due");
    assert_eq!(reason, ReportReason::KeepAlive);
    let mut buf = [0u8; 2048];
    let bytes = publish(&device, &mut subscriptions, id, reason, at(30), &mut buf);
    let report = ReportData::decode(bytes).expect("decodes");
    assert!(held.heard(&report, at(30)));

    // The subscriber's deadline moved with it.
    let margin = LIVENESS_MARGIN.as_secs();
    assert!(!held.is_expired(at(30 + 30 + margin - 1)));
    assert!(held.is_expired(at(30 + 30 + margin)));
}

#[test]
fn a_subscription_that_goes_quiet_expires_but_not_at_the_exact_interval() {
    // §8.5.4: "If the subscriber does not receive a report within the maximum interval ... the
    // subscriber SHALL consider the subscription to have expired." Timing out at *exactly*
    // MaxInterval would tear down a working subscription on the first MRP retransmission, and
    // over a sleepy Thread network the first retransmission is not unusual.
    let held = Subscription::new(
        &SubscribeResponse {
            subscription_id: 7,
            max_interval_s: 60,
            revision: None,
        },
        at(0),
    );
    let margin = LIVENESS_MARGIN.as_secs();
    assert!(!held.is_expired(at(60)), "expired at exactly MaxInterval");
    assert!(!held.is_expired(at(60 + margin - 1)));
    assert!(held.is_expired(at(60 + margin)));
    assert_eq!(held.expires_at(), at(60 + margin));
}

#[test]
fn one_subscriptions_reports_do_not_keep_another_alive() {
    // §8.5.3.2 puts the id in every report precisely so a subscriber holding several can tell
    // them apart. Crediting one subscription's liveness to another would keep a dead one alive
    // indefinitely — and a controller watching twenty devices holds twenty of these.
    let mut first = Subscription::new(
        &SubscribeResponse {
            subscription_id: 1,
            max_interval_s: 60,
            revision: None,
        },
        at(0),
    );
    // An empty keep-alive, as §8.5.3's would arrive — for subscription 2.
    let mut buf = [0u8; 64];
    let foreign = matter_kit::im::encode_report_data(
        &mut buf,
        Some(2),
        core::iter::empty::<matter_kit::im::ib::AttributeReport<'_>>(),
        false,
        true,
    )
    .expect("encodes")
    .to_vec();
    let foreign = ReportData::decode(&foreign).expect("decodes");
    assert!(
        !first.heard(&foreign, at(30)),
        "a foreign report was credited"
    );
    assert!(first.is_expired(at(60 + LIVENESS_MARGIN.as_secs())));

    let mut buf = [0u8; 64];
    let ours = matter_kit::im::encode_report_data(
        &mut buf,
        Some(1),
        core::iter::empty::<matter_kit::im::ib::AttributeReport<'_>>(),
        false,
        true,
    )
    .expect("encodes")
    .to_vec();
    let ours = ReportData::decode(&ours).expect("decodes");
    assert!(first.heard(&ours, at(30)));
    assert!(!first.is_expired(at(60 + LIVENESS_MARGIN.as_secs())));
}
