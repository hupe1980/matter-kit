//! Ethernet Network Diagnostics, cluster `0x0037` (Core §11.16).
//!
//! > The Ethernet Network Diagnostics Cluster attempts to centralize all metrics that are
//! > relevant to a potential Ethernet connection to a Node.
//!
//! Every number here belongs to a network interface this crate does not own, so the cluster is
//! a [`EthernetDriver`] the integrator implements — the same shape
//! [`general_diagnostics::Diagnostics`](super::general_diagnostics::Diagnostics) takes, and for
//! the same reason: a driver is the only thing that can count a collision.
//!
//! # Two features, and what they promise
//!
//! §11.16.4 splits the counters in two. `PKTCNT` claims `PacketRxCount` and `PacketTxCount`;
//! `ERRCNT` claims `TxErrCount`, `CollisionCount` and `OverrunCount`. Claiming a feature is a
//! promise that the driver can actually count the thing — a device that advertises `ERRCNT` and
//! reports zero collisions forever is worse than one that advertises neither, because the first
//! tells a support engineer the link is clean and the second tells them to look elsewhere. So
//! the defaults on [`EthernetDriver`] are the ones a device that cannot measure should keep, and
//! the feature map is what the integrator opts into.
//!
//! # `null` is a state, not a missing value
//!
//! `PHYRate`, `FullDuplex` and `CarrierDetect` are all `X`-quality: §11.16.6.1's "A value of null
//! SHALL indicate that the interface is not currently configured or operational". That is a
//! different fact from "this device does not report PHY rate", which is what omitting the
//! optional attribute means. `Option<Option<T>>` would say both, and say neither clearly, so the
//! trait returns [`Reading<T>`] instead and names the three answers.
//!
//! ```
//! use matter_kit::clusters::ethernet_network_diagnostics::{
//!     EthernetDriver, EthernetNetworkDiagnostics, PHYRateEnum, Reading, feature,
//! };
//!
//! struct Nic;
//! impl EthernetDriver for Nic {
//!     fn phy_rate(&self) -> Reading<PHYRateEnum> { Reading::Value(PHYRateEnum::Rate1G) }
//!     fn full_duplex(&self) -> Reading<bool> { Reading::Value(true) }
//!     fn packet_rx_count(&self) -> u64 { 1_234 }
//!     fn packet_tx_count(&self) -> u64 { 5_678 }
//! }
//!
//! // `PKTCNT` because this driver counts packets; no `ERRCNT`, because it does not count errors.
//! let cluster = EthernetNetworkDiagnostics::new(&Nic, feature::PACKET_COUNTS);
//! # let _ = cluster;
//! ```

use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::tlv::{Tag, TlvWriter};

use super::Cluster;
use crate::clusters::generated::ethernet_network_diagnostics as spec_eth;

pub use spec_eth::{ID, PHYRateEnum, PICS, REVISION, feature};

use spec_eth::attribute::{
    CARRIER_DETECT, COLLISION_COUNT, FULL_DUPLEX, OVERRUN_COUNT, PACKET_RX_COUNT, PACKET_TX_COUNT,
    PHY_RATE, TIME_SINCE_RESET, TX_ERR_COUNT,
};
use spec_eth::command::RESET_COUNTS;

/// What a driver can say about an attribute whose `null` means something (§11.16.6.1).
///
/// The three answers are genuinely different, and collapsing any two of them loses information a
/// support engineer needs:
///
/// * [`Reading::Value`] — measured, and this is it.
/// * [`Reading::NotOperational`] — measurable, but "the interface is not currently configured or
///   operational", which is what the specification's `null` means.
/// * [`Reading::Unsupported`] — this device does not report the attribute at all, so it must not
///   appear in `AttributeList` either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reading<T> {
    /// A measured value.
    Value(T),
    /// `null`: the interface is not configured or operational.
    NotOperational,
    /// The attribute is not implemented by this device.
    #[default]
    Unsupported,
}

impl<T> Reading<T> {
    /// Whether the device reports this attribute at all.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported)
    }
}

/// What a device's Ethernet interface can report (§11.16.6).
///
/// Every method has a default, so an integrator implements only what the hardware can measure.
/// The defaults are the conservative ones: an unsupported optional attribute, and a zero counter
/// for the features §11.16.4 makes the counters conditional on.
pub trait EthernetDriver {
    /// `PHYRate` (§11.16.6.1) — "the current nominal, usable speed at the top of the physical
    /// layer".
    fn phy_rate(&self) -> Reading<PHYRateEnum> {
        Reading::Unsupported
    }

    /// `FullDuplex` (§11.16.6.2) — "if the Node is currently utilizing the full-duplex
    /// operating mode".
    fn full_duplex(&self) -> Reading<bool> {
        Reading::Unsupported
    }

    /// `PacketRxCount` (§11.16.6.3). `PKTCNT`.
    ///
    /// "SHALL be reset to 0 upon a reboot of the Node" — so a driver that persisted it would be
    /// reporting something the attribute does not mean.
    fn packet_rx_count(&self) -> u64 {
        0
    }

    /// `PacketTxCount` (§11.16.6.4). `PKTCNT`.
    fn packet_tx_count(&self) -> u64 {
        0
    }

    /// `TxErrCount` (§11.16.6.5). `ERRCNT`.
    fn tx_err_count(&self) -> u64 {
        0
    }

    /// `CollisionCount` (§11.16.6.6). `ERRCNT`.
    fn collision_count(&self) -> u64 {
        0
    }

    /// `OverrunCount` (§11.16.6.7) — "packets dropped either at ingress or egress, due to lack
    /// of buffer memory". `ERRCNT`.
    fn overrun_count(&self) -> u64 {
        0
    }

    /// `CarrierDetect` (§11.16.6.8) — the carrier-detect control signal.
    fn carrier_detect(&self) -> Reading<bool> {
        Reading::Unsupported
    }

    /// `TimeSinceReset` (§11.16.6.9), **in minutes** since the interface last reset.
    ///
    /// Minutes, not the seconds every other duration in diagnostics uses, which is exactly the
    /// kind of unit mismatch that produces a plausible wrong number rather than an error.
    fn time_since_reset(&self) -> Option<u64> {
        None
    }

    /// `ResetCounts` (§11.16.7.1): zero `PacketRxCount`, `PacketTxCount`, `TxErrCount`,
    /// `CollisionCount` and `OverrunCount`.
    ///
    /// The default does nothing, which is correct for a driver that reports no counters. One
    /// that does report them must implement this, or a client's reset silently fails.
    fn reset_counts(&self) {}
}

/// The driver for a device with no Ethernet metrics to report.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unknown;

impl EthernetDriver for Unknown {}

/// Builds a descriptor for a feature map and the optional elements a product implements.
///
/// `Optional` names what §11.16.6 leaves to the product: `PHYRate`, `FullDuplex`,
/// `CarrierDetect` and `TimeSinceReset`. The counters are not optional — they are conditional on
/// `PKTCNT` and `ERRCNT`, and the conformance engine derives them from the feature map.
///
/// # Errors
///
/// [`ErrorCode::InvalidArgument`](crate::ErrorCode) for a feature this revision does not define.
pub fn conforming(
    features: u32,
    optional: &Optional<'_>,
) -> crate::error::Result<Conforming<14, 1, 0, 0>> {
    Conforming::new(&spec_eth::CLUSTER, features, optional)
}

/// Everything §11.16.6 makes optional, for a driver that reports all of it.
pub const ALL_OPTIONAL: Optional<'static> = Optional {
    attributes: &[PHY_RATE, FULL_DUPLEX, CARRIER_DETECT, TIME_SINCE_RESET],
    commands: &[],
    events: &[],
};

/// The Ethernet Network Diagnostics cluster (§11.16).
#[derive(Debug)]
pub struct EthernetNetworkDiagnostics<'a, D: EthernetDriver> {
    driver: &'a D,
    features: u32,
}

impl<'a, D: EthernetDriver> EthernetNetworkDiagnostics<'a, D> {
    /// A cluster over a device's own Ethernet driver.
    #[must_use]
    pub const fn new(driver: &'a D, features: u32) -> Self {
        Self { driver, features }
    }

    /// Whether `PKTCNT` is claimed.
    #[must_use]
    const fn counts_packets(&self) -> bool {
        self.features & feature::PACKET_COUNTS != 0
    }

    /// Whether `ERRCNT` is claimed.
    #[must_use]
    const fn counts_errors(&self) -> bool {
        self.features & feature::ERROR_COUNTS != 0
    }
}

/// Writes a `Reading`, mapping [`Reading::Unsupported`] to the status that says so.
fn reading<T>(
    value: Reading<T>,
    w: &mut TlvWriter<'_>,
    tag: Tag,
    encode: impl FnOnce(&mut TlvWriter<'_>, Tag, T) -> crate::error::Result<()>,
) -> Result<(), Status> {
    match value {
        Reading::Value(v) => encode(w, tag, v).map_err(|_| Status::ResourceExhausted),
        // §11.16.6.1: "A value of null SHALL indicate that the interface is not currently
        // configured or operational."
        Reading::NotOperational => w.null(tag).map_err(|_| Status::ResourceExhausted),
        Reading::Unsupported => Err(Status::UnsupportedAttribute),
    }
}

impl<D: EthernetDriver> ClusterHandler for EthernetNetworkDiagnostics<'_, D> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        // A counter whose feature is not claimed is not an attribute this cluster has. Answering
        // zero instead would be the device asserting a measurement it never made — a link that
        // has never dropped a packet, forever.
        let counter = |claimed: bool, value: u64| -> Result<u64, Status> {
            if claimed {
                Ok(value)
            } else {
                Err(Status::UnsupportedAttribute)
            }
        };
        match resolved.attribute {
            PHY_RATE => reading(self.driver.phy_rate(), w, tag, |w, tag, rate| {
                w.unsigned(tag, u64::from(rate.value()))
            }),
            FULL_DUPLEX => reading(self.driver.full_duplex(), w, tag, |w, tag, v| {
                w.bool(tag, v)
            }),
            CARRIER_DETECT => reading(self.driver.carrier_detect(), w, tag, |w, tag, v| {
                w.bool(tag, v)
            }),
            PACKET_RX_COUNT => full(w.unsigned(
                tag,
                counter(self.counts_packets(), self.driver.packet_rx_count())?,
            )),
            PACKET_TX_COUNT => full(w.unsigned(
                tag,
                counter(self.counts_packets(), self.driver.packet_tx_count())?,
            )),
            TX_ERR_COUNT => full(w.unsigned(
                tag,
                counter(self.counts_errors(), self.driver.tx_err_count())?,
            )),
            COLLISION_COUNT => full(w.unsigned(
                tag,
                counter(self.counts_errors(), self.driver.collision_count())?,
            )),
            OVERRUN_COUNT => full(w.unsigned(
                tag,
                counter(self.counts_errors(), self.driver.overrun_count())?,
            )),
            TIME_SINCE_RESET => match self.driver.time_since_reset() {
                Some(minutes) => full(w.unsigned(tag, minutes)),
                None => Err(Status::UnsupportedAttribute),
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
            RESET_COUNTS => {
                // §11.16.7's conformance is `PKTCNT | ERRCNT`: a device claiming neither has no
                // counters to reset and does not have the command.
                if !self.counts_packets() && !self.counts_errors() {
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
impl<D: EthernetDriver> Cluster for EthernetNetworkDiagnostics<'_, D> {
    const ID: ClusterId = ID;
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::im::AttributeId;

    struct Nic;

    impl EthernetDriver for Nic {
        fn phy_rate(&self) -> Reading<PHYRateEnum> {
            Reading::Value(PHYRateEnum::Rate1G)
        }
        fn full_duplex(&self) -> Reading<bool> {
            Reading::Value(true)
        }
        fn carrier_detect(&self) -> Reading<bool> {
            Reading::NotOperational
        }
        fn packet_rx_count(&self) -> u64 {
            11
        }
        fn packet_tx_count(&self) -> u64 {
            22
        }
        fn tx_err_count(&self) -> u64 {
            33
        }
        fn collision_count(&self) -> u64 {
            44
        }
        fn overrun_count(&self) -> u64 {
            55
        }
        fn time_since_reset(&self) -> Option<u64> {
            Some(7)
        }
    }

    fn read<D: EthernetDriver>(
        cluster: &EthernetNetworkDiagnostics<'_, D>,
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
        // `heapless`, not `alloc`: these tests run under `--no-default-features`
        // too, which is the build a device ships and the one with no allocator.
        Ok(heapless::Vec::from_slice(w.finish().expect("finish")).expect("fits"))
    }

    /// Whether an attribute is in the descriptor at all, which is what a client reads from
    /// `AttributeList` and what the server routes on.
    fn advertises(features: u32, attribute: AttributeId) -> bool {
        conforming(features, &ALL_OPTIONAL)
            .expect("descriptor")
            .descriptor()
            .attributes
            .iter()
            .any(|a| a.id == attribute)
    }

    /// §11.16.4 makes the counters conditional on `PKTCNT` and `ERRCNT`, and the two are
    /// independent. A device that claims neither does not *have* the counters — reporting zero
    /// would be it asserting a measurement it never made, which reads to a support engineer as
    /// a link that has never dropped a packet.
    #[test]
    fn an_unclaimed_counter_is_not_advertised_and_not_answered() {
        // The conformance engine keeps it out of the descriptor...
        assert!(!advertises(0, PACKET_RX_COUNT));
        assert!(!advertises(0, TX_ERR_COUNT));
        assert!(advertises(feature::PACKET_COUNTS, PACKET_RX_COUNT));
        assert!(
            !advertises(feature::PACKET_COUNTS, TX_ERR_COUNT),
            "PKTCNT does not imply ERRCNT"
        );
        assert!(advertises(feature::ERROR_COUNTS, COLLISION_COUNT));
        assert!(
            !advertises(feature::ERROR_COUNTS, PACKET_TX_COUNT),
            "and ERRCNT does not imply PKTCNT"
        );

        // ...and the handler refuses it even if something routed there anyway. The server never
        // will, having read the same descriptor — this is the second of the two answers, kept
        // because a cluster that returned 0 for an attribute it does not have would be wrong in
        // a way no descriptor check downstream could catch.
        let none = EthernetNetworkDiagnostics::new(&Nic, 0);
        assert_eq!(
            read(&none, PACKET_RX_COUNT),
            Err(Status::UnsupportedAttribute)
        );
        assert_eq!(read(&none, TX_ERR_COUNT), Err(Status::UnsupportedAttribute));

        let packets = EthernetNetworkDiagnostics::new(&Nic, feature::PACKET_COUNTS);
        assert!(read(&packets, PACKET_RX_COUNT).is_ok());
        assert_eq!(
            read(&packets, TX_ERR_COUNT),
            Err(Status::UnsupportedAttribute)
        );
    }

    /// §11.16.6.1's `null` is "not currently configured or operational", which is a different
    /// fact from the device not reporting the attribute.
    #[test]
    fn null_and_unsupported_are_different_answers() {
        let nic = EthernetNetworkDiagnostics::new(&Nic, 0);
        let carrier = read(&nic, CARRIER_DETECT).expect("carrier detect is reported");
        // 0x34 is a context-tagged null; the value being present at all is the point.
        assert_eq!(carrier, [0x34, 0x00], "null, not absent");

        let blank = EthernetNetworkDiagnostics::new(&Unknown, 0);
        assert_eq!(
            read(&blank, CARRIER_DETECT),
            Err(Status::UnsupportedAttribute),
            "a device that cannot measure it says so"
        );
    }

    #[test]
    fn values_round_trip_through_the_reader() {
        let nic =
            EthernetNetworkDiagnostics::new(&Nic, feature::PACKET_COUNTS | feature::ERROR_COUNTS);
        assert_eq!(read(&nic, PHY_RATE).expect("phy"), [0x24, 0x00, 0x02]);
        assert_eq!(read(&nic, FULL_DUPLEX).expect("duplex"), [0x29, 0x00]);
        assert_eq!(read(&nic, PACKET_RX_COUNT).expect("rx"), [0x24, 0x00, 11]);
        assert_eq!(
            read(&nic, OVERRUN_COUNT).expect("overrun"),
            [0x24, 0x00, 55]
        );
        assert_eq!(
            read(&nic, TIME_SINCE_RESET).expect("since"),
            [0x24, 0x00, 7]
        );
    }

    /// §11.16.7's conformance is `PKTCNT | ERRCNT`.
    #[test]
    fn reset_counts_needs_a_counter_to_reset() {
        let descriptor = conforming(feature::PACKET_COUNTS, &Optional::NONE).expect("descriptor");
        let cl = descriptor.descriptor();
        let command = *cl
            .accepted_commands
            .iter()
            .find(|c| c.id == RESET_COUNTS)
            .expect("ResetCounts is present when PKTCNT is claimed");
        let resolved = ResolvedCommand {
            endpoint: 0,
            cluster: &cl,
            command,
        };
        let mut buf = [0u8; 32];
        let mut w = TlvWriter::new(&mut buf);

        let none = EthernetNetworkDiagnostics::new(&Nic, 0);
        assert_eq!(
            none.invoke(
                &resolved,
                None,
                &InteractionContext::new(),
                &mut w,
                Tag::Anonymous
            )
            .unwrap_err()
            .status,
            Status::UnsupportedCommand,
            "a device with no counters has no ResetCounts"
        );

        let packets = EthernetNetworkDiagnostics::new(&Nic, feature::PACKET_COUNTS);
        assert!(
            packets
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

    /// §11.16.4's features must not invent elements the revision does not define.
    #[test]
    fn an_undefined_feature_is_refused() {
        assert!(conforming(1 << 5, &Optional::NONE).is_err());
    }
}
