//! Device types: what an endpoint must be furnished with (the Device Library).
//!
//! An endpoint advertises its device types in the Descriptor cluster's `DeviceTypeList`
//! (§9.5.5), and that list is a *claim*. A commissioner reading "On/Off Light" then expects
//! Identify, Groups, On/Off with its Lighting feature, and Scenes Management to be there — so
//! a device that advertises the type without furnishing it is one that appears in an app and
//! then does not work.
//!
//! These tables are generated from the same CSA XML the clusters are, and
//! [`DeviceType::validate`] is the check: given an endpoint's cluster list, what is missing
//! and what does not belong.

use crate::dm::conformance::{Conform, Conformance, Supports};
use crate::dm::node::Endpoint;
use crate::im::{AttributeId, ClusterId, CommandId, EventId};

/// A cluster a device type requires or allows on the endpoint.
#[derive(Debug, Clone, Copy)]
pub struct RequiredCluster {
    /// The cluster's id.
    pub id: ClusterId,
    /// The readable name — "On/Off".
    pub name: &'static str,
    /// Whether it is the server side. A *client* cluster is a binding target the endpoint
    /// talks to, not something it serves, so a validator must not demand it in the endpoint's
    /// own cluster list.
    pub server: bool,
    /// Whether the endpoint must have it.
    pub conform: Conform,
    /// Feature bits the device type demands beyond the cluster's own conformance, by the
    /// cluster's own short codes.
    ///
    /// This is the part a cluster list alone cannot express: On/Off Light does not merely
    /// require On/Off, it requires On/Off **with Lighting**, and a light that serves the
    /// cluster without the feature has no `StartUpOnOff` — so it comes back on at whatever
    /// state it was in, which is the behaviour the device type exists to rule out.
    pub features: &'static [(&'static str, Conform)],
    /// Attributes the device type demands beyond the cluster's own conformance, by name.
    pub attributes: &'static [(&'static str, Conform)],
    /// Commands it demands, by name.
    pub commands: &'static [(&'static str, Conform)],
    /// Events it demands, by name.
    pub events: &'static [(&'static str, Conform)],
}

/// One device type.
#[derive(Debug, Clone, Copy)]
pub struct DeviceType {
    /// The `DeviceTypeID` that appears in `DeviceTypeList`.
    pub id: u32,
    /// Its name — "On/Off Light".
    pub name: &'static str,
    /// The revision that goes alongside the id in `DeviceTypeList`.
    pub revision: u16,
    /// `simple`, `utility`, `node` or `dynamic utility`. A utility device type may share an
    /// endpoint with another; a *simple* one may not (§9.2), which is the rule a bridge gets
    /// wrong when it puts two lights on one endpoint.
    pub class: &'static str,
    /// `endpoint` or `node`.
    pub scope: &'static str,
    /// What the endpoint must and may serve.
    pub clusters: &'static [RequiredCluster],
}

/// What an endpoint's furnishing got wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    /// A cluster the device type requires and the endpoint does not serve.
    MissingCluster(ClusterId),
    /// A cluster the device type explicitly disallows.
    DisallowedCluster(ClusterId),
    /// A cluster is present but without a feature the device type demands of it.
    MissingFeature {
        /// Which cluster.
        cluster: ClusterId,
        /// The feature's short code, as the specification names it.
        code: &'static str,
    },
    /// A cluster the device type requires the endpoint to speak *as a client*, and the
    /// endpoint's `ClientList` does not name (§9.5.6.3).
    MissingClient(ClusterId),
    /// A cluster is present but without an element the device type demands of it.
    ///
    /// A device type may tighten its clusters' own conformance: §1.2.6 calls Identify's
    /// `TriggerEffect` optional, and §4.1's On/Off Light makes it mandatory. A check that
    /// only compared cluster ids would pass an endpoint whose app screen has a dead button.
    MissingElement {
        /// Which cluster.
        cluster: ClusterId,
        /// The element's name, as the specification writes it.
        name: &'static str,
    },
}

/// An endpoint, seen as a set of clusters, so device-type conformance can be evaluated.
struct Furnished<'a> {
    endpoint: &'a Endpoint<'a>,
}

impl Supports for Furnished<'_> {
    fn feature_map(&self) -> u32 {
        // A device type's conformance is about clusters, never about one cluster's features.
        0
    }

    fn has_attribute(&self, _id: AttributeId) -> bool {
        false
    }

    fn has_command(&self, _id: CommandId) -> bool {
        false
    }

    fn has_event(&self, _id: EventId) -> bool {
        false
    }

    fn has_cluster(&self, id: ClusterId) -> bool {
        self.endpoint
            .clusters
            .iter()
            .any(|cluster| cluster.id == id)
    }
}

impl DeviceType {
    /// Checks an endpoint against this device type, reporting each defect to `found`.
    ///
    /// Only **server** clusters are checked. A device type's client-side entries name what the
    /// endpoint may *bind to* — an On/Off Light's client Occupancy Sensing is a sensor
    /// somewhere else on the fabric — and demanding one in the endpoint's own list would
    /// reject every conformant light.
    ///
    /// Elements whose conformance is prose are skipped, for the same reason
    /// [`spec::Cluster::validate`](crate::dm::spec::Cluster::validate) skips them.
    pub fn validate(
        &self,
        endpoint: &Endpoint<'_>,
        spec_of: impl Fn(ClusterId) -> Option<&'static crate::dm::spec::Cluster>,
        mut found: impl FnMut(Defect),
    ) {
        let furnished = Furnished { endpoint };
        for required in self.clusters {
            let verdict = required.conform.verdict(&furnished);
            if !required.server {
                // §9.5.6.3's ClientList is the only evidence an endpoint *consumes* a
                // cluster — a client binding has no descriptor. §6.1's On/Off Light Switch
                // requires On/Off as a client and as nothing else, so skipping this would
                // make a light indistinguishable from the switch that controls it.
                if verdict == Conformance::Mandatory && !endpoint.clients.contains(&required.id) {
                    found(Defect::MissingClient(required.id));
                }
                continue;
            }
            let present = furnished.has_cluster(required.id);
            match verdict {
                Conformance::Mandatory if !present => {
                    found(Defect::MissingCluster(required.id));
                    continue;
                }
                Conformance::Disallowed if present => {
                    found(Defect::DisallowedCluster(required.id));
                    continue;
                }
                _ => {}
            }
            if !present {
                continue;
            }
            Self::check_features(endpoint, required, &spec_of, &mut found);
            Self::check_elements(endpoint, required, &spec_of, &mut found);
        }
    }

    /// The attributes, commands and events a device type demands of a cluster it requires.
    ///
    /// A device type names them by the specification's own names — "TriggerEffect",
    /// "CopyScene" — so resolving one to an id needs the cluster's table, which is what
    /// `spec_of` supplies. An element the caller's library does not define is skipped rather
    /// than guessed at, the same way an unknown cluster is.
    fn check_elements(
        endpoint: &Endpoint<'_>,
        required: &RequiredCluster,
        spec_of: &impl Fn(ClusterId) -> Option<&'static crate::dm::spec::Cluster>,
        found: &mut impl FnMut(Defect),
    ) {
        if required.attributes.is_empty()
            && required.commands.is_empty()
            && required.events.is_empty()
        {
            return;
        }
        let Some(served) = endpoint
            .clusters
            .iter()
            .find(|cluster| cluster.id == required.id)
        else {
            return;
        };
        let Some(defined) = spec_of(required.id) else {
            return;
        };
        let furnished = Furnished { endpoint };
        let mut demand = |name: &'static str, conform: &Conform, present: Option<bool>| {
            if conform.verdict(&furnished) != Conformance::Mandatory {
                return;
            }
            // `None` is an element the library does not define — nothing to check against.
            if present == Some(false) {
                found(Defect::MissingElement {
                    cluster: required.id,
                    name,
                });
            }
        };
        for (name, conform) in required.attributes {
            let present = defined
                .attributes
                .iter()
                .find(|a| a.name == *name)
                .map(|a| served.attribute(a.id).is_some());
            demand(name, conform, present);
        }
        for (name, conform) in required.commands {
            let present = defined.commands.iter().find(|c| c.name == *name).map(|c| {
                if c.to_server {
                    served.accepted_command(c.id).is_some()
                } else {
                    // A response command is generated, never accepted: §7.13.4's
                    // GeneratedCommandList is derived from the accepted commands' responses,
                    // plus whatever the instance generates unprompted.
                    served.generated_commands.contains(&c.id)
                        || served
                            .accepted_commands
                            .iter()
                            .any(|a| a.response == Some(c.id))
                }
            });
            demand(name, conform, present);
        }
        for (name, conform) in required.events {
            let present = defined
                .events
                .iter()
                .find(|e| e.name == *name)
                .map(|e| served.events.iter().any(|served| served.id == e.id));
            demand(name, conform, present);
        }
    }

    /// The features a device type demands of a cluster it requires.
    ///
    /// Resolving a short code to a bit needs the cluster's own feature table, and `spec_of`
    /// is how the caller supplies it —
    /// [`clusters::validate_endpoint`](crate::clusters::validate_endpoint) passes the
    /// generated library. A parameter rather than a reach into `clusters::generated` because
    /// the data model is the layer *below* the cluster library, and a cluster the caller does
    /// not know is skipped rather than guessed at: a manufacturer-specific cluster on an
    /// endpoint is perfectly legal and has no table anywhere.
    fn check_features(
        endpoint: &Endpoint<'_>,
        required: &RequiredCluster,
        spec_of: &impl Fn(ClusterId) -> Option<&'static crate::dm::spec::Cluster>,
        found: &mut impl FnMut(Defect),
    ) {
        if required.features.is_empty() {
            return;
        }
        let Some(served) = endpoint
            .clusters
            .iter()
            .find(|cluster| cluster.id == required.id)
        else {
            return;
        };
        let Some(defined) = spec_of(required.id) else {
            return;
        };
        for (code, conform) in required.features {
            if conform.verdict(&Furnished { endpoint }) != Conformance::Mandatory {
                continue;
            }
            let Some(feature) = defined.feature(code) else {
                continue;
            };
            if feature.bit < 32 && served.feature_map & (1u32 << feature.bit) == 0 {
                found(Defect::MissingFeature {
                    cluster: required.id,
                    code,
                });
            }
        }
    }

    /// Whether an endpoint is furnished for this device type.
    #[must_use]
    pub fn is_satisfied_by(
        &self,
        endpoint: &Endpoint<'_>,
        spec_of: impl Fn(ClusterId) -> Option<&'static crate::dm::spec::Cluster>,
    ) -> bool {
        let mut ok = true;
        self.validate(endpoint, spec_of, |_| ok = false);
        ok
    }
}
