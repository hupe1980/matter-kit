//! Wi-Fi Network Diagnostics, cluster `0x0036` (Core §11.15).
//!
//! The counterpart to [`ethernet_network_diagnostics`](super::ethernet_network_diagnostics) for
//! a node reached over Wi-Fi, and the same shape: every number belongs to a radio this crate
//! does not own, so the cluster is a [`WiFiDriver`] the integrator implements.
//!
//! # What is different from Ethernet, and why it shows in the types
//!
//! §11.15.6 makes **every** attribute here nullable, and all but `CurrentMaxRate` mandatory or
//! conditional on a feature. So there is no "this device does not report `RSSI`" — a Wi-Fi
//! device reports it, and reports `null` while it is not associated. That is what
//! [`Option`] means on this trait: `None` is the specification's `null`, not a missing
//! implementation. Only `CurrentMaxRate` has all three answers, and only it takes a
//! [`Reading`].
//!
//! # Two features, and what claiming one promises
//!
//! §11.15.4 splits the counters: `PKTCNT` claims the four packet counts and `BeaconRxCount`,
//! `ERRCNT` claims `BeaconLostCount` and `OverrunCount`. Claiming a feature is a promise that
//! the driver can count the thing, which is why the defaults on [`WiFiDriver`] are the ones a
//! device that cannot measure should keep, and the feature map is what the integrator opts
//! into.
//!
//! `ResetCounts` is `ERRCNT` alone here — not `PKTCNT | ERRCNT` as it is on Ethernet. A device
//! that counts packets and no errors has no `ResetCounts`, which is a difference between two
//! adjacent clusters that reads like a mistake and is not one.
//!
//! ```
//! use matter_kit::clusters::wi_fi_network_diagnostics::{
//!     SecurityTypeEnum, WiFiDriver, WiFiNetworkDiagnostics, WiFiVersionEnum, feature,
//! };
//!
//! struct Radio;
//! impl WiFiDriver for Radio {
//!     fn bssid(&self) -> Option<[u8; 6]> { Some([0x02, 0x00, 0x5E, 0x10, 0x00, 0x01]) }
//!     fn security_type(&self) -> Option<SecurityTypeEnum> { Some(SecurityTypeEnum::WPA3) }
//!     fn wi_fi_version(&self) -> Option<WiFiVersionEnum> { Some(WiFiVersionEnum::N) }
//!     fn channel_number(&self) -> Option<u16> { Some(11) }
//!     fn rssi(&self) -> Option<i8> { Some(-58) }
//! }
//!
//! // No feature bits: this driver reports the association and counts nothing.
//! let cluster = WiFiNetworkDiagnostics::<_, 4>::new(&Radio, 0);
//! # let _ = (cluster, feature::PACKET_COUNTS);
//! ```

use core::cell::RefCell;

use crate::dm::spec::{Conforming, Optional};
use crate::dm::{EventPriority, Resolved, ResolvedCommand};
use crate::im::{
    ClusterHandler, ClusterId, CommandId, EventId, InteractionContext, Status, StatusIb,
};
use crate::tlv::{Tag, TlvWriter};

use super::{Cluster, Reading};
use crate::clusters::generated::wi_fi_network_diagnostics as spec_wifi;

pub use spec_wifi::{
    AssociationFailureCauseEnum, ConnectionStatusEnum, ID, PICS, REVISION, SecurityTypeEnum,
    WiFiVersionEnum, feature,
};

use spec_wifi::attribute::{
    BEACON_LOST_COUNT, BEACON_RX_COUNT, BSSID, CHANNEL_NUMBER, CURRENT_MAX_RATE, OVERRUN_COUNT,
    PACKET_MULTICAST_RX_COUNT, PACKET_MULTICAST_TX_COUNT, PACKET_UNICAST_RX_COUNT,
    PACKET_UNICAST_TX_COUNT, RSSI, SECURITY_TYPE, WI_FI_VERSION,
};
use spec_wifi::command::RESET_COUNTS;
pub use spec_wifi::event::{ASSOCIATION_FAILURE, CONNECTION_STATUS, DISCONNECTION};

/// What a device's Wi-Fi interface can report (§11.15.6).
///
/// Every method has a default, so an integrator implements only what the radio can measure.
/// The defaults are the conservative ones: `null` for the association, and `null` for the
/// counters §11.15.4 makes conditional on a feature — a driver that claims the feature is the
/// one that has to answer.
pub trait WiFiDriver {
    /// `BSSID` (§11.15.6.1) — the access point's MAC address, or `null` when not associated.
    fn bssid(&self) -> Option<[u8; 6]> {
        None
    }

    /// `SecurityType` (§11.15.6.2) — the security in use on the current association.
    fn security_type(&self) -> Option<SecurityTypeEnum> {
        None
    }

    /// `WiFiVersion` (§11.15.6.3) — the 802.11 generation the association is running at.
    fn wi_fi_version(&self) -> Option<WiFiVersionEnum> {
        None
    }

    /// `ChannelNumber` (§11.15.6.4) — the channel the association is on.
    fn channel_number(&self) -> Option<u16> {
        None
    }

    /// `RSSI` (§11.15.6.5), in dBm.
    ///
    /// Signed, and negative for every association a real radio will ever report. A driver that
    /// hands back an unsigned "signal strength" here is the unit mismatch this attribute
    /// invites.
    fn rssi(&self) -> Option<i8> {
        None
    }

    /// `BeaconLostCount` (§11.15.6.6). `ERRCNT`.
    fn beacon_lost_count(&self) -> Option<u32> {
        None
    }

    /// `BeaconRxCount` (§11.15.6.7). `PKTCNT`.
    fn beacon_rx_count(&self) -> Option<u32> {
        None
    }

    /// `PacketMulticastRxCount` (§11.15.6.8). `PKTCNT`.
    fn packet_multicast_rx_count(&self) -> Option<u32> {
        None
    }

    /// `PacketMulticastTxCount` (§11.15.6.9). `PKTCNT`.
    fn packet_multicast_tx_count(&self) -> Option<u32> {
        None
    }

    /// `PacketUnicastRxCount` (§11.15.6.10). `PKTCNT`.
    fn packet_unicast_rx_count(&self) -> Option<u32> {
        None
    }

    /// `PacketUnicastTxCount` (§11.15.6.11). `PKTCNT`.
    fn packet_unicast_tx_count(&self) -> Option<u32> {
        None
    }

    /// `CurrentMaxRate` (§11.15.6.12), in bits per second — the only optional attribute here,
    /// and so the only one a device may leave out of `AttributeList` altogether.
    fn current_max_rate(&self) -> Reading<u64> {
        Reading::Unsupported
    }

    /// `OverrunCount` (§11.15.6.13) — packets dropped for want of buffer memory. `ERRCNT`.
    fn overrun_count(&self) -> Option<u64> {
        None
    }

    /// `ResetCounts` (§11.15.7.1): zero every counter this cluster reports.
    ///
    /// The default does nothing, which is correct for a driver that reports no counters. One
    /// that does must implement this, or a client's reset silently fails.
    fn reset_counts(&self) {}
}

/// The driver for a device with no Wi-Fi metrics to report.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unknown;

impl WiFiDriver for Unknown {}

/// One of §11.15.8's events, as the radio noticed it.
///
/// The cluster collects these and the device drains them into its own event store, because
/// the store belongs to the node and not to any one cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// §11.15.8.1 `Disconnection`, carrying the 802.11 reason code the AP gave.
    Disconnection {
        /// `ReasonCode`, from IEEE 802.11-2020 table 9-49.
        reason_code: u16,
    },
    /// §11.15.8.2 `AssociationFailure`.
    AssociationFailure {
        /// `AssociationFailureCause`.
        cause: AssociationFailureCauseEnum,
        /// `Status`, the 802.11 status code.
        status: u16,
    },
    /// §11.15.8.3 `ConnectionStatus`, on every transition between connected and not.
    ConnectionStatus(ConnectionStatusEnum),
}

impl Event {
    /// The event id this record is reported under.
    #[must_use]
    pub const fn id(&self) -> EventId {
        match self {
            Self::Disconnection { .. } => DISCONNECTION,
            Self::AssociationFailure { .. } => ASSOCIATION_FAILURE,
            Self::ConnectionStatus(_) => CONNECTION_STATUS,
        }
    }

    /// Every event in §11.15.8 is `INFO` priority.
    #[must_use]
    pub const fn priority(&self) -> EventPriority {
        EventPriority::Info
    }

    /// Writes the event's fields as an `EventDataIB`'s `Data` (§10.6.13).
    ///
    /// # Errors
    ///
    /// Whatever the writer returns when the buffer is too small.
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: Tag) -> crate::error::Result<()> {
        w.start_structure(tag)?;
        match *self {
            Self::Disconnection { reason_code } => {
                w.unsigned(Tag::Context(0), u64::from(reason_code))?;
            }
            Self::AssociationFailure { cause, status } => {
                w.unsigned(Tag::Context(0), u64::from(cause.value()))?;
                w.unsigned(Tag::Context(1), u64::from(status))?;
            }
            Self::ConnectionStatus(status) => {
                w.unsigned(Tag::Context(0), u64::from(status.value()))?;
            }
        }
        w.end_container()
    }
}

/// Builds a descriptor for a feature map and the optional elements a product implements.
///
/// `CurrentMaxRate` is the only optional attribute; §11.15.8's three events are optional too,
/// and a device that never records one must not advertise it.
///
/// # Errors
///
/// [`ErrorCode::InvalidArgument`](crate::ErrorCode) for a feature this revision does not define.
pub fn conforming(
    features: u32,
    optional: &Optional<'_>,
) -> crate::error::Result<Conforming<18, 1, 0, 3>> {
    Conforming::new(&spec_wifi::CLUSTER, features, optional)
}

/// Everything §11.15 makes optional, for a device that reports all of it.
pub const ALL_OPTIONAL: Optional<'static> = Optional {
    attributes: &[CURRENT_MAX_RATE],
    commands: &[],
    events: &[DISCONNECTION, ASSOCIATION_FAILURE, CONNECTION_STATUS],
};

/// The Wi-Fi Network Diagnostics cluster (§11.15).
///
/// `E` is how many events the cluster holds before the oldest is dropped. A radio that
/// disconnects in a loop must not be able to grow this, and the device drains it every time
/// round its own loop.
#[derive(Debug)]
pub struct WiFiNetworkDiagnostics<'a, D: WiFiDriver, const E: usize = 4> {
    driver: &'a D,
    features: u32,
    events: RefCell<heapless::Vec<Event, E>>,
}

impl<'a, D: WiFiDriver, const E: usize> WiFiNetworkDiagnostics<'a, D, E> {
    /// A cluster over a device's own Wi-Fi driver.
    #[must_use]
    pub fn new(driver: &'a D, features: u32) -> Self {
        Self {
            driver,
            features,
            events: RefCell::new(heapless::Vec::new()),
        }
    }

    /// Records one of §11.15.8's events for the device to drain.
    ///
    /// Public because every one of them is the *radio's* to notice: this cluster is told that
    /// an association failed, it cannot find out.
    pub fn record(&self, event: Event) {
        let mut events = self.events.borrow_mut();
        if events.is_full() {
            events.remove(0);
        }
        let _ = events.push(event);
    }

    /// Takes the events recorded since the last call.
    #[must_use]
    pub fn take_events(&self) -> heapless::Vec<Event, E> {
        core::mem::take(&mut self.events.borrow_mut())
    }

    /// Whether `PKTCNT` is claimed.
    const fn counts_packets(&self) -> bool {
        self.features & feature::PACKET_COUNTS != 0
    }

    /// Whether `ERRCNT` is claimed.
    const fn counts_errors(&self) -> bool {
        self.features & feature::ERROR_COUNTS != 0
    }

    /// A counter §11.15.4 makes conditional on a feature.
    ///
    /// Two different refusals hide behind one `?`: an unclaimed feature means the attribute is
    /// not on this device at all, and `None` means the device has it and its value is `null`.
    /// Answering zero for the first would be the radio asserting a measurement it never made.
    fn counter(
        claimed: bool,
        value: Option<u64>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        if !claimed {
            return Err(Status::UnsupportedAttribute);
        }
        match value {
            Some(v) => w.unsigned(tag, v),
            None => w.null(tag),
        }
        .map_err(|_| Status::ResourceExhausted)
    }
}

/// Writes a mandatory nullable attribute: the value, or §11.15.6's `null`.
fn nullable<T>(
    value: Option<T>,
    w: &mut TlvWriter<'_>,
    tag: Tag,
    encode: impl FnOnce(&mut TlvWriter<'_>, Tag, T) -> crate::error::Result<()>,
) -> Result<(), Status> {
    match value {
        Some(v) => encode(w, tag, v),
        None => w.null(tag),
    }
    .map_err(|_| Status::ResourceExhausted)
}

impl<D: WiFiDriver, const E: usize> ClusterHandler for WiFiNetworkDiagnostics<'_, D, E> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let packets = self.counts_packets();
        let errors = self.counts_errors();
        match resolved.attribute {
            BSSID => nullable(self.driver.bssid(), w, tag, |w, tag, v| w.octets(tag, &v)),
            SECURITY_TYPE => nullable(self.driver.security_type(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v.value()))
            }),
            WI_FI_VERSION => nullable(self.driver.wi_fi_version(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v.value()))
            }),
            CHANNEL_NUMBER => nullable(self.driver.channel_number(), w, tag, |w, tag, v| {
                w.unsigned(tag, u64::from(v))
            }),
            RSSI => nullable(self.driver.rssi(), w, tag, |w, tag, v| {
                w.signed(tag, i64::from(v))
            }),
            BEACON_LOST_COUNT => Self::counter(
                errors,
                self.driver.beacon_lost_count().map(u64::from),
                w,
                tag,
            ),
            BEACON_RX_COUNT => Self::counter(
                packets,
                self.driver.beacon_rx_count().map(u64::from),
                w,
                tag,
            ),
            PACKET_MULTICAST_RX_COUNT => Self::counter(
                packets,
                self.driver.packet_multicast_rx_count().map(u64::from),
                w,
                tag,
            ),
            PACKET_MULTICAST_TX_COUNT => Self::counter(
                packets,
                self.driver.packet_multicast_tx_count().map(u64::from),
                w,
                tag,
            ),
            PACKET_UNICAST_RX_COUNT => Self::counter(
                packets,
                self.driver.packet_unicast_rx_count().map(u64::from),
                w,
                tag,
            ),
            PACKET_UNICAST_TX_COUNT => Self::counter(
                packets,
                self.driver.packet_unicast_tx_count().map(u64::from),
                w,
                tag,
            ),
            OVERRUN_COUNT => Self::counter(errors, self.driver.overrun_count(), w, tag),
            CURRENT_MAX_RATE => match self.driver.current_max_rate() {
                Reading::Value(rate) => {
                    w.unsigned(tag, rate).map_err(|_| Status::ResourceExhausted)
                }
                Reading::NotOperational => w.null(tag).map_err(|_| Status::ResourceExhausted),
                Reading::Unsupported => Err(Status::UnsupportedAttribute),
            },
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        match resolved.command.id {
            // §11.15.7's conformance is `ERRCNT` alone, which is narrower than the Ethernet
            // cluster's `PKTCNT | ERRCNT` — a device that only counts packets has no reset.
            RESET_COUNTS => {
                if !self.counts_errors() {
                    return Err(StatusIb::new(Status::UnsupportedCommand));
                }
                self.driver.reset_counts();
                Ok(None)
            }
            _ => Err(StatusIb::new(Status::UnsupportedCommand)),
        }
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<D: WiFiDriver, const E: usize> Cluster for WiFiNetworkDiagnostics<'_, D, E> {
    const ID: ClusterId = ID;
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::im::AttributeId;

    struct Radio;

    impl WiFiDriver for Radio {
        fn bssid(&self) -> Option<[u8; 6]> {
            Some([0x02, 0x00, 0x5E, 0x10, 0x00, 0x01])
        }
        fn security_type(&self) -> Option<SecurityTypeEnum> {
            Some(SecurityTypeEnum::WPA3)
        }
        fn wi_fi_version(&self) -> Option<WiFiVersionEnum> {
            Some(WiFiVersionEnum::Ax)
        }
        fn channel_number(&self) -> Option<u16> {
            Some(36)
        }
        fn rssi(&self) -> Option<i8> {
            Some(-58)
        }
        fn beacon_lost_count(&self) -> Option<u32> {
            Some(3)
        }
        fn beacon_rx_count(&self) -> Option<u32> {
            Some(900)
        }
        fn overrun_count(&self) -> Option<u64> {
            Some(7)
        }
        fn current_max_rate(&self) -> Reading<u64> {
            Reading::Value(144_400_000)
        }
    }

    /// A radio that is powered but not associated: every mandatory attribute is `null`.
    struct Detached;

    impl WiFiDriver for Detached {}

    fn read<D: WiFiDriver>(
        cluster: &WiFiNetworkDiagnostics<'_, D>,
        attribute: AttributeId,
    ) -> Result<heapless::Vec<u8, 64>, Status> {
        let descriptor = conforming(cluster.features, &ALL_OPTIONAL).expect("descriptor");
        let cl = descriptor.descriptor();
        let resolved = Resolved {
            endpoint: 0,
            cluster: &cl,
            attribute,
        };
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new_in(&mut buf, crate::tlv::ContainerKind::Structure);
        cluster.read(
            &resolved,
            &InteractionContext::new(),
            &mut w,
            Tag::Context(0),
        )?;
        Ok(heapless::Vec::from_slice(w.finish().expect("finish")).expect("fits"))
    }

    fn advertises(features: u32, attribute: AttributeId) -> bool {
        conforming(features, &ALL_OPTIONAL)
            .expect("descriptor")
            .descriptor()
            .attributes
            .iter()
            .any(|a| a.id == attribute)
    }

    /// §11.15.4's two features are independent, and each claims a different set of counters.
    #[test]
    fn an_unclaimed_counter_is_not_advertised_and_not_answered() {
        assert!(!advertises(0, BEACON_RX_COUNT));
        assert!(!advertises(0, BEACON_LOST_COUNT));
        assert!(advertises(feature::PACKET_COUNTS, BEACON_RX_COUNT));
        assert!(
            !advertises(feature::PACKET_COUNTS, BEACON_LOST_COUNT),
            "BeaconLostCount is ERRCNT's, not PKTCNT's — the two beacon counters are split \
             across the features"
        );
        assert!(advertises(feature::ERROR_COUNTS, OVERRUN_COUNT));
        assert!(!advertises(feature::ERROR_COUNTS, PACKET_UNICAST_TX_COUNT));

        let none = WiFiNetworkDiagnostics::<_, 4>::new(&Radio, 0);
        assert_eq!(
            read(&none, BEACON_RX_COUNT),
            Err(Status::UnsupportedAttribute)
        );
        assert_eq!(
            read(&none, OVERRUN_COUNT),
            Err(Status::UnsupportedAttribute)
        );
    }

    /// Every attribute in §11.15.6 is nullable, and an unassociated radio is what `null` is
    /// for. A device that answered `UNSUPPORTED_ATTRIBUTE` while its Wi-Fi was down would be
    /// changing its own `AttributeList` from one read to the next.
    #[test]
    fn an_unassociated_radio_answers_null_rather_than_refusing() {
        let detached = WiFiNetworkDiagnostics::<_, 4>::new(&Detached, feature::PACKET_COUNTS);
        // 0x34 is a context-tagged null.
        assert_eq!(read(&detached, BSSID).expect("bssid"), [0x34, 0x00]);
        assert_eq!(read(&detached, RSSI).expect("rssi"), [0x34, 0x00]);
        assert_eq!(
            read(&detached, SECURITY_TYPE).expect("security"),
            [0x34, 0x00]
        );
        assert_eq!(
            read(&detached, BEACON_RX_COUNT).expect("claimed, so present and null"),
            [0x34, 0x00]
        );
    }

    /// `CurrentMaxRate` is the one optional attribute, so it is the one with three answers.
    #[test]
    fn the_only_optional_attribute_is_the_only_one_that_can_be_unsupported() {
        assert!(
            advertises(0, CURRENT_MAX_RATE),
            "optional, so it is advertised only because ALL_OPTIONAL asks for it"
        );
        let reporting = WiFiNetworkDiagnostics::<_, 4>::new(&Radio, 0);
        assert_eq!(
            read(&reporting, CURRENT_MAX_RATE).expect("rate"),
            [0x26, 0x00, 0x80, 0x5E, 0x9B, 0x08]
        );

        let silent = WiFiNetworkDiagnostics::<_, 4>::new(&Detached, 0);
        assert_eq!(
            read(&silent, CURRENT_MAX_RATE),
            Err(Status::UnsupportedAttribute)
        );
    }

    #[test]
    fn values_round_trip_through_the_reader() {
        let radio = WiFiNetworkDiagnostics::<_, 4>::new(
            &Radio,
            feature::PACKET_COUNTS | feature::ERROR_COUNTS,
        );
        assert_eq!(
            read(&radio, BSSID).expect("bssid"),
            [0x30, 0x00, 0x06, 0x02, 0x00, 0x5E, 0x10, 0x00, 0x01]
        );
        // `SecurityTypeEnum::WPA3` is 5, `WiFiVersionEnum::Ax` is 5.
        assert_eq!(read(&radio, SECURITY_TYPE).expect("sec"), [0x24, 0x00, 5]);
        assert_eq!(read(&radio, WI_FI_VERSION).expect("ver"), [0x24, 0x00, 5]);
        assert_eq!(
            read(&radio, CHANNEL_NUMBER).expect("chan"),
            [0x24, 0x00, 36]
        );
        // -58 as a one-byte signed integer, which is the type `RSSI` actually has.
        assert_eq!(read(&radio, RSSI).expect("rssi"), [0x20, 0x00, 0xC6]);
        assert_eq!(
            read(&radio, BEACON_LOST_COUNT).expect("lost"),
            [0x24, 0x00, 3]
        );
        assert_eq!(
            read(&radio, OVERRUN_COUNT).expect("overrun"),
            [0x24, 0x00, 7]
        );
    }

    /// §11.15.7's `ResetCounts` is `ERRCNT` alone, which differs from §11.16.7's
    /// `PKTCNT | ERRCNT` — the kind of near-miss between two adjacent clusters that a shared
    /// helper would have flattened.
    #[test]
    fn reset_counts_belongs_to_the_error_counts_feature_alone() {
        assert!(
            conforming(feature::PACKET_COUNTS, &Optional::NONE)
                .expect("descriptor")
                .descriptor()
                .accepted_commands
                .is_empty(),
            "PKTCNT alone does not bring ResetCounts"
        );

        let descriptor = conforming(feature::ERROR_COUNTS, &Optional::NONE).expect("descriptor");
        let cl = descriptor.descriptor();
        let command = *cl
            .accepted_commands
            .iter()
            .find(|c| c.id == RESET_COUNTS)
            .expect("ERRCNT brings ResetCounts");
        let resolved = ResolvedCommand {
            endpoint: 0,
            cluster: &cl,
            command,
        };
        let mut buf = [0u8; 32];
        let mut w = TlvWriter::new(&mut buf);

        let packets = WiFiNetworkDiagnostics::<_, 4>::new(&Radio, feature::PACKET_COUNTS);
        assert_eq!(
            packets
                .invoke(
                    &resolved,
                    None,
                    &InteractionContext::new(),
                    &mut w,
                    Tag::Anonymous
                )
                .unwrap_err()
                .status,
            Status::UnsupportedCommand
        );

        let errors = WiFiNetworkDiagnostics::<_, 4>::new(&Radio, feature::ERROR_COUNTS);
        assert!(
            errors
                .invoke(
                    &resolved,
                    None,
                    &InteractionContext::new(),
                    &mut w,
                    Tag::Anonymous
                )
                .is_ok()
        );
    }

    /// The queue drops its oldest rather than refusing: a radio that disconnects in a loop
    /// must not be able to make the cluster fail, and the newest disconnection is the one a
    /// support engineer wants.
    #[test]
    fn the_event_queue_is_bounded_and_keeps_the_newest() {
        let radio = WiFiNetworkDiagnostics::<_, 2>::new(&Radio, 0);
        radio.record(Event::Disconnection { reason_code: 1 });
        radio.record(Event::Disconnection { reason_code: 2 });
        radio.record(Event::ConnectionStatus(ConnectionStatusEnum::Connected));
        let drained = radio.take_events();
        assert_eq!(
            drained.as_slice(),
            [
                Event::Disconnection { reason_code: 2 },
                Event::ConnectionStatus(ConnectionStatusEnum::Connected)
            ]
        );
        assert!(radio.take_events().is_empty(), "draining empties it");
    }

    #[test]
    fn an_event_encodes_its_fields_under_the_data_tag() {
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new_in(&mut buf, crate::tlv::ContainerKind::Structure);
        let event = Event::AssociationFailure {
            cause: AssociationFailureCauseEnum::AuthenticationFailed,
            status: 0x000F,
        };
        event.encode(&mut w, Tag::Context(7)).expect("encode");
        assert_eq!(event.id(), ASSOCIATION_FAILURE);
        assert_eq!(
            event.priority(),
            EventPriority::Info,
            "§11.15.8 gives all three events INFO priority, which is what decides which of the \
             event store's three rings the record lands in"
        );
        assert_eq!(
            w.finish().expect("finish"),
            // struct ctx-7 { ctx-0 = 2, ctx-1 = 15 }
            [0x35, 0x07, 0x24, 0x00, 0x02, 0x24, 0x01, 0x0F, 0x18]
        );
    }

    /// §11.15.4's features must not invent elements the revision does not define.
    #[test]
    fn an_undefined_feature_is_refused() {
        assert!(conforming(1 << 4, &Optional::NONE).is_err());
    }
}
