//! The clusters every Matter node has (Core ch. 9 and ch. 11).
//!
//! A node is not just a data model — it has to *answer*. These are the utility clusters that
//! make a device commissionable and describable, implemented against the same
//! [cluster descriptor](crate::dm::ClusterDescriptor) and
//! [`ClusterHandler`] machinery an application cluster uses, so
//! there is one mechanism and not a privileged one for the built-ins.
//!
//! | Cluster | Id | Section | Revision | Feature |
//! |---|---|---|---|---|
//! | [`descriptor`] | `0x001D` | §9.5 | 3 | |
//! | [`basic_information`] | `0x0028` | §11.1 | 6 | |
//! | [`general_commissioning`] | `0x0030` | §11.10 | 2 | |
//! | [`network_commissioning`] | `0x0031` | §11.9 | 2 | |
//! | `administrator_commissioning` | `0x003C` | §11.19 | 1 | `rustcrypto` |
//! | `operational_credentials` | `0x003E` | §11.18 | 2 | `rustcrypto` |
//!
//! # Composition
//!
//! [`ClusterHandler`] is one trait for a whole device — a device
//! has one cluster implementation table and not one per cluster. So each cluster here
//! implements the narrower [`Cluster`] trait, which adds the one thing dispatch needs: the
//! cluster's id. A tuple of `Cluster`s is itself a `ClusterHandler`, dispatching on that id:
//!
//! ```
//! use matter_kit::clusters::basic_information::{Attributes, BasicInformation, Location, Product};
//! use matter_kit::clusters::descriptor::{self, DeviceType};
//! use matter_kit::clusters::general_commissioning::{self, GeneralCommissioning, RegulatoryLocation};
//! use matter_kit::clusters::network_commissioning::{
//!     self as netcomm, Capabilities, EthernetDriver, NetworkCommissioning,
//! };
//! use matter_kit::clusters::Descriptor;
//! use matter_kit::commissioning::window::CommissioningWindow;
//! use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
//! use matter_kit::dm::{Endpoint, Node};
//! use matter_kit::msg::VendorId;
//!
//! const PRODUCT: Product<'static> = Product::new(
//!     "Example Vendor", VendorId(0xFFF1), "Example Light", 0x8000, "unique-id",
//! );
//!
//! // The attribute list is derived from the product, not written twice.
//! let attributes = Attributes::new(&PRODUCT, false, false);
//! // Sorted by cluster id — 0x001D, 0x0028, 0x0030, 0x0031 — because the lookups binary-
//! // search and `Node::validate` is what catches getting it wrong.
//! let clusters = [
//!     descriptor::cluster(),            // 0x001D
//!     attributes.cluster(),             // 0x0028
//!     general_commissioning::cluster(), // 0x0030
//!     netcomm::ethernet(),              // 0x0031
//! ];
//! // §9.5 requires every endpoint to declare at least one device type. It lives on the
//! // endpoint rather than on the Descriptor cluster, because access control matches ACL
//! // targets against it too and the two must not be able to disagree.
//! const ROOT_NODE: &[DeviceType] = &[DeviceType::new(0x0016, 3)];
//! let endpoints = [Endpoint::new(0, &clusters).with_device_types(ROOT_NODE)];
//! let node = Node::new(&endpoints);
//! node.validate().expect("sorted, so the binary searches cannot silently miss");
//!
//! // One `Location` cell, shared: §11.10.7.4's SetRegulatoryConfig writes Basic
//! // Information's Location attribute.
//! let location = Location::region_agnostic();
//!
//! // The fail-safe is node state, not cluster state: §11.18's credential commands record
//! // against the same context General Commissioning arms.
//! let fail_safe = core::cell::RefCell::new(FailSafe::new(BasicCommissioningInfo::default()));
//! // And so is the commissioning window: §11.19 opens it, §11.10.7.2 gives a PASE
//! // commissioner priority while it is open, and §11.10.7.6 closes it.
//! let window = core::cell::RefCell::new(CommissioningWindow::new());
//!
//! // An Ethernet interface needs no driver and accepts no commands (§11.9.7's table is
//! // `WI | TH`); its one `Networks` entry is seeded by the server.
//! let ethernet = EthernetDriver;
//! let network = NetworkCommissioning::<_, 1>::new(&ethernet, &fail_safe, Capabilities::default());
//! network.store_mut().seed(b"eth0", true).expect("one entry fits");
//!
//! let handler = (
//!     Descriptor::new(node, 0),
//!     BasicInformation::new(&PRODUCT, &location),
//!     GeneralCommissioning::new(
//!         &location,
//!         RegulatoryLocation::IndoorOutdoor,
//!         &fail_safe,
//!         &window,
//!     ),
//!     network,
//! );
//! // `handler` is a `ClusterHandler`; hand it to `Server::new` with an access control.
//! # let _ = &handler;
//! ```
//!
//! The match is over `const` ids, so it compiles to a jump table and costs nothing at
//! runtime — the same dispatch a hand-written `match` would produce, without the chance of
//! forgetting an arm.
//!
//! # Why these three carry state and the descriptors do not
//!
//! A [cluster descriptor](crate::dm::ClusterDescriptor) is the cluster's *shape* and lives
//! in flash. What each type here adds is its *values* — a device's vendor name, its
//! breadcrumb, its fail-safe. [`ClusterHandler`] takes `&self`
//! because reads must be possible from a shared reference, so anything mutable is behind a
//! [`Cell`](core::cell::Cell): no allocation, no locking, and no `&mut` threaded through the
//! interaction model for the sake of two attributes.

pub mod access_control;
/// Administrator Commissioning needs [`crypto`](crate::crypto)'s SPAKE2+ verifier and
/// [`sc`](crate::sc)'s PBKDF parameters.
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod administrator_commissioning;
pub mod basic_information;
pub mod binding;
pub mod bridged_device_basic_information;
pub mod commissioner_control;
pub mod descriptor;
pub mod device_energy_management;
pub mod electrical_measurement;
pub mod energy_evse;
pub mod ethernet_network_diagnostics;
pub mod general_commissioning;
pub mod general_diagnostics;
pub mod generated;
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod group_key_management;
/// §11.27 is provisional (Core §2.13), and its key material is [`group`](crate::group)'s.
#[cfg(all(feature = "rustcrypto", feature = "provisional"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "rustcrypto", feature = "provisional"))))]
pub mod groupcast;
pub mod groups;
/// ICD Management needs [`icd`](crate::icd)'s Check-In Protocol, which is cryptography.
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod icd_management;
pub mod identify;
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod joint_fabric_administrator;
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod joint_fabric_datastore;
pub mod label;
pub mod level_control;
pub mod mode;
pub mod network_commissioning;
pub mod on_off;
/// Operational Credentials needs [`cert`](crate::cert), [`attestation`](crate::attestation)
/// and [`fabric`](crate::fabric), which are all cryptography.
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod operational_credentials;
pub mod ota_provider;
pub mod ota_requestor;
pub mod scenes;
pub mod software_diagnostics;
pub mod thermostat_suggestions;
#[cfg(feature = "rustcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustcrypto")))]
pub mod tls;
pub mod water_heater_management;

#[cfg(feature = "rustcrypto")]
pub use administrator_commissioning::AdministratorCommissioning;
pub use basic_information::BasicInformation;
pub use descriptor::Descriptor;
pub use general_commissioning::GeneralCommissioning;
pub use network_commissioning::NetworkCommissioning;
#[cfg(feature = "rustcrypto")]
pub use operational_credentials::OperationalCredentials;

use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb, WriteOp,
};
use crate::tlv::{ContainerKind, Element, FromTlv, Tag, TlvReader, TlvWriter};

/// Decodes a command's `CommandFields` — the `CommandDataIB`'s context-1 member (§10.6.11).
///
/// Shared by every cluster that takes a payload, so the failure modes cannot drift between
/// them: a malformed encoding is `INVALID_ACTION`, a well-formed one carrying a value the
/// field cannot hold is `CONSTRAINT_ERROR`, and a missing mandatory field is
/// `INVALID_COMMAND`. §8.8.2.3 makes that distinction the client's only clue about whether
/// retrying with different arguments is worth anything.
pub(crate) fn decode_fields<'a, T: FromTlv<'a>>(fields: &'a [u8]) -> Result<T, StatusIb> {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let element: Element<'a> = reader
        .next_element()
        .map_err(|_| StatusIb::from(Status::InvalidAction))?
        .ok_or(StatusIb::from(Status::InvalidAction))?;
    T::from_tlv(&mut reader, &element).map_err(|error| {
        StatusIb::from(match error.code() {
            crate::ErrorCode::TlvNotFound => Status::InvalidCommand,
            crate::ErrorCode::TlvOutOfRange | crate::ErrorCode::TlvWrongType => {
                Status::ConstraintError
            }
            _ => Status::InvalidAction,
        })
    })
}

/// One cluster implementation, tagged with the id it answers for.
///
/// The supertrait is what makes a `Cluster` usable on its own — a device with exactly one
/// cluster needs no dispatch — and the associated `ID` is what makes a tuple of them
/// dispatchable.
pub trait Cluster: ClusterHandler {
    /// The cluster id this implementation serves.
    const ID: ClusterId;
}

/// A shared reference to a cluster is a cluster, so a tuple of borrowed clusters dispatches
/// like a tuple of owned ones.
impl<T: Cluster + ?Sized> Cluster for &T {
    const ID: ClusterId = T::ID;
}

/// The status a dispatcher answers with for a cluster no member serves.
///
/// This should be unreachable in a well-formed device: the server resolves a path against
/// the [`Node`](crate::dm::Node) before calling the handler, so a cluster that is not in the
/// handler tuple is a cluster the node's descriptors claim and nothing implements. Answering
/// `UNSUPPORTED_CLUSTER` rather than panicking keeps that mistake a per-path failure instead
/// of taking the device down.
const UNMATCHED: Status = Status::UnsupportedCluster;

macro_rules! dispatch_tuple {
    ($($name:ident => $slot:ident),+ $(,)?) => {
        impl<$($name: Cluster),+> ClusterHandler for ($($name,)+) {
            fn read(
                &self,
                resolved: &Resolved<'_>,
                ctx: &InteractionContext<'_>,
                w: &mut TlvWriter<'_>,
                tag: Tag,
            ) -> core::result::Result<(), Status> {
                let ($($slot,)+) = self;
                match resolved.cluster.id {
                    $(id if id == $name::ID => $slot.read(resolved, ctx, w, tag),)+
                    _ => Err(UNMATCHED),
                }
            }

            fn data_version(&self, resolved: &Resolved<'_>) -> Option<u32> {
                let ($($slot,)+) = self;
                match resolved.cluster.id {
                    $(id if id == $name::ID => $slot.data_version(resolved),)+
                    _ => None,
                }
            }

            fn write(
                &self,
                resolved: &Resolved<'_>,
                data: &[u8],
                op: WriteOp,
                ctx: &InteractionContext<'_>,
            ) -> core::result::Result<(), Status> {
                let ($($slot,)+) = self;
                match resolved.cluster.id {
                    $(id if id == $name::ID => $slot.write(resolved, data, op, ctx),)+
                    _ => Err(UNMATCHED),
                }
            }

            fn invoke(
                &self,
                resolved: &ResolvedCommand<'_>,
                fields: Option<&[u8]>,
                ctx: &InteractionContext<'_>,
                w: &mut TlvWriter<'_>,
                tag: Tag,
            ) -> core::result::Result<Option<CommandId>, StatusIb> {
                let ($($slot,)+) = self;
                match resolved.cluster.id {
                    $(id if id == $name::ID => $slot.invoke(resolved, fields, ctx, w, tag),)+
                    _ => Err(UNMATCHED.into()),
                }
            }
        }
    };
}

dispatch_tuple!(A => a);
dispatch_tuple!(A => a, B => b);
dispatch_tuple!(A => a, B => b, C => c);
dispatch_tuple!(A => a, B => b, C => c, D => d);
dispatch_tuple!(A => a, B => b, C => c, D => d, E => e);
dispatch_tuple!(A => a, B => b, C => c, D => d, E => e, F => f);
dispatch_tuple!(A => a, B => b, C => c, D => d, E => e, F => f, G => g);
dispatch_tuple!(A => a, B => b, C => c, D => d, E => e, F => f, G => g, H => h);
dispatch_tuple!(A => a, B => b, C => c, D => d, E => e, F => f, G => g, H => h, I => i);
dispatch_tuple!(A => a, B => b, C => c, D => d, E => e, F => f, G => g, H => h, I => i, J => j);
dispatch_tuple!(A => a, B => b, C => c, D => d, E => e, F => f, G => g, H => h, I => i, J => j, K => k);
dispatch_tuple!(A => a, B => b, C => c, D => d, E => e, F => f, G => g, H => h, I => i, J => j, K => k, L => l);

/// One endpoint's clusters, for a node that has more than one.
///
/// A tuple of clusters dispatches by cluster id alone, which is all a single-endpoint device
/// needs. A node with two endpoints has the same cluster twice — every endpoint has its own
/// Descriptor (§9.5), and a two-gang switch has On/Off on both — so the id no longer picks an
/// instance. `At` supplies the missing half of the address, and [`Endpoints`] routes on it.
///
/// ```
/// # use matter_kit::clusters::{At, Endpoints, descriptor::Descriptor};
/// # use matter_kit::dm::{Endpoint, Node};
/// # let clusters = [matter_kit::clusters::descriptor::cluster()];
/// # let endpoints = [Endpoint::new(0, &clusters), Endpoint::new(1, &clusters)];
/// # let node = Node::new(&endpoints);
/// let handler = Endpoints((
///     At::new(0, Descriptor::new(node, 0)),
///     At::new(1, Descriptor::new(node, 1)),
/// ));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct At<H> {
    /// The endpoint this handler answers for.
    pub endpoint: crate::im::EndpointId,
    /// What serves it.
    pub handler: H,
}

impl<H> At<H> {
    /// Binds `handler` to `endpoint`.
    pub const fn new(endpoint: crate::im::EndpointId, handler: H) -> Self {
        Self { endpoint, handler }
    }
}

/// A node's endpoints, each an [`At`].
///
/// Routes on the endpoint first and the cluster id second, which is the order §8.9.2's
/// concrete path names them in. A path naming an endpoint no member holds is
/// `UNSUPPORTED_ENDPOINT` — the same answer the server would give for an endpoint the node
/// does not have, rather than another endpoint's data.
#[derive(Debug, Clone, Copy)]
pub struct Endpoints<T>(pub T);

/// The status for a path whose endpoint no member serves.
///
/// Unreachable in a well-formed device — the server resolves the path against the
/// [`Node`](crate::dm::Node) first — so this catches a node whose descriptors list an endpoint
/// nothing implements, and catches it per path rather than by taking the device down.
const NO_ENDPOINT: Status = Status::UnsupportedEndpoint;

macro_rules! endpoint_tuple {
    ($($name:ident => $slot:ident),+ $(,)?) => {
        impl<$($name: ClusterHandler),+> ClusterHandler for Endpoints<($(At<$name>,)+)> {
            fn read(
                &self,
                resolved: &Resolved<'_>,
                ctx: &InteractionContext<'_>,
                w: &mut TlvWriter<'_>,
                tag: Tag,
            ) -> core::result::Result<(), Status> {
                let Endpoints(($($slot,)+)) = self;
                $(if $slot.endpoint == resolved.endpoint {
                    return $slot.handler.read(resolved, ctx, w, tag);
                })+
                Err(NO_ENDPOINT)
            }

            fn data_version(&self, resolved: &Resolved<'_>) -> Option<u32> {
                let Endpoints(($($slot,)+)) = self;
                $(if $slot.endpoint == resolved.endpoint {
                    return $slot.handler.data_version(resolved);
                })+
                None
            }

            fn write(
                &self,
                resolved: &Resolved<'_>,
                data: &[u8],
                op: WriteOp,
                ctx: &InteractionContext<'_>,
            ) -> core::result::Result<(), Status> {
                let Endpoints(($($slot,)+)) = self;
                $(if $slot.endpoint == resolved.endpoint {
                    return $slot.handler.write(resolved, data, op, ctx);
                })+
                Err(NO_ENDPOINT)
            }

            fn invoke(
                &self,
                resolved: &ResolvedCommand<'_>,
                fields: Option<&[u8]>,
                ctx: &InteractionContext<'_>,
                w: &mut TlvWriter<'_>,
                tag: Tag,
            ) -> core::result::Result<Option<CommandId>, StatusIb> {
                let Endpoints(($($slot,)+)) = self;
                $(if $slot.endpoint == resolved.endpoint {
                    return $slot.handler.invoke(resolved, fields, ctx, w, tag);
                })+
                Err(NO_ENDPOINT.into())
            }
        }
    };
}

endpoint_tuple!(A => a);
endpoint_tuple!(A => a, B => b);
endpoint_tuple!(A => a, B => b, C => c);
endpoint_tuple!(A => a, B => b, C => c, D => d);
endpoint_tuple!(A => a, B => b, C => c, D => d, E => e);
endpoint_tuple!(A => a, B => b, C => c, D => d, E => e, F => f);
endpoint_tuple!(A => a, B => b, C => c, D => d, E => e, F => f, G => g);
endpoint_tuple!(A => a, B => b, C => c, D => d, E => e, F => f, G => g, H => h);

/// Checks an endpoint against a device type, using the generated cluster library to resolve
/// the feature codes a device type names (§9.2).
///
/// **For a device's tests, not its start-up path.** Resolving a feature code needs
/// [`generated::find`], which reaches the whole library — about 131 KB of read-only data that
/// a device linking three clusters would otherwise never pay for. The check itself is a
/// property of the *code*, not of the running device: an endpoint's furnishing is `const`, so
/// once a test has passed it, running the same check on the device proves nothing new.
///
/// `Descriptor`'s `DeviceTypeList` is a *claim*: a commissioner reading "On/Off Light" expects
/// Identify, Groups, On/Off with its Lighting feature and Scenes Management to be there. A
/// device that advertises the type without furnishing it appears in an app and then does not
/// work, which is a much worse failure than not appearing at all.
pub fn validate_endpoint(
    endpoint: &crate::dm::Endpoint<'_>,
    device_type: &crate::dm::device::DeviceType,
    found: impl FnMut(crate::dm::device::Defect),
) {
    device_type.validate(endpoint, generated::find, found);
}

/// Whether an endpoint is furnished for a device type it claims.
#[must_use]
pub fn endpoint_satisfies(
    endpoint: &crate::dm::Endpoint<'_>,
    device_type: &crate::dm::device::DeviceType,
) -> bool {
    device_type.is_satisfied_by(endpoint, generated::find)
}
