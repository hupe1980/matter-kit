//! TLS Client Management, cluster `0x0802` (Core §14.5).
//!
//! > This Cluster is used to provision TLS Endpoints with enough information to facilitate
//! > subsequent connection.
//!
//! A TLS endpoint is a hostname, a port, the root CA to authenticate the server with, and
//! optionally the client certificate to present. Nothing here opens a connection: §14.5 is
//! configuration, and the clusters that actually connect — Camera AV Stream Management, WebRTC
//! — name an endpoint id and let the platform's TLS stack do the rest.
//!
//! # Five cluster-specific status codes, because `FAILURE` would say nothing
//!
//! §14.5.5.1 defines its own codes, and they are the difference between an administrator who
//! can fix the problem and one who cannot: `RootCertificateNotFound` means provision the CA
//! first, `EndpointAlreadyInstalled` means this host and port are already configured,
//! `InvalidTime` means the clock has not been set yet. All five ride in a `StatusIb`'s
//! `ClusterStatus` beside §8.10's `FAILURE`, because none of these commands has a response to
//! put them in.
//!
//! # An endpoint in use cannot be removed
//!
//! §14.5.4.2's `ReferenceCount` is "the number of entities currently using this TLS Endpoint",
//! and §14.5.7.5 refuses to remove one that is non-zero. The count is the application's to keep
//! — "The node SHALL recompute this field to reflect the correct value at runtime" — through
//! [`TlsTables::set_reference_count`]; the refusal is this cluster's.

use crate::clusters::generated::tls_client_management as spec_tls;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::msg::FabricIndex;
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::{EndpointEntry, HOSTNAME_MAX, HOSTNAME_MIN, TlsEndpointId, TlsTables, visible};
use crate::clusters::Cluster;

pub use spec_tls::attribute::{MAX_PROVISIONED, PROVISIONED_ENDPOINTS};
pub use spec_tls::command::{
    FIND_ENDPOINT, FIND_ENDPOINT_RESPONSE, PROVISION_ENDPOINT, PROVISION_ENDPOINT_RESPONSE,
    REMOVE_ENDPOINT,
};
pub use spec_tls::{ID, PICS, REVISION, StatusCodeEnum};

/// The TLS Client Management cluster (§14.5).
///
/// It needs no hooks: an endpoint is four small fields, and the certificates it names belong to
/// [`certificate_management`](super::certificate_management).
#[derive(Debug)]
pub struct ClientManagement<'a, const R: usize, const C: usize, const E: usize> {
    tables: &'a TlsTables<R, C, E>,
}

impl<'a, const R: usize, const C: usize, const E: usize> ClientManagement<'a, R, C, E> {
    /// A cluster over shared tables.
    #[must_use]
    pub const fn new(tables: &'a TlsTables<R, C, E>) -> Self {
        Self { tables }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<2, 3, 2, 0>> {
        Conforming::new(&spec_tls::CLUSTER, feature_map, optional)
    }

    /// The tables this cluster shares with
    /// [`certificate_management`](super::certificate_management).
    #[must_use]
    pub const fn tables(&self) -> &'a TlsTables<R, C, E> {
        self.tables
    }
}

/// One of §14.5.5.1's cluster-specific codes, as a `FAILURE` with a `ClusterStatus`.
fn cluster_status(code: StatusCodeEnum) -> StatusIb {
    StatusIb::cluster_failure(code.value())
}

impl<const R: usize, const C: usize, const E: usize> ClusterHandler
    for ClientManagement<'_, R, C, E>
{
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            MAX_PROVISIONED => full(w.unsigned(tag, u64::from(self.tables.max_endpoints()))),
            PROVISIONED_ENDPOINTS => {
                let endpoints = self.tables.endpoints();
                full(w.start_array(tag))?;
                for endpoint in endpoints.iter().filter(|e| visible(ctx, e.fabric_index)) {
                    full(encode_endpoint(endpoint, w, Tag::Anonymous))?;
                }
                full(w.end_container())
            }
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        // Every command in §14.5.7 is `F`.
        let fabric = ctx
            .fabric_index
            .filter(|f| f.0 != 0)
            .ok_or(StatusIb::from(Status::UnsupportedAccess))?;
        let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
        match resolved.command.id {
            PROVISION_ENDPOINT => self.provision(fabric, payload, w, tag),
            FIND_ENDPOINT => self.find(fabric, payload, w, tag),
            REMOVE_ENDPOINT => self.remove(fabric, payload),
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<const R: usize, const C: usize, const E: usize> ClientManagement<'_, R, C, E> {
    /// §14.5.7.1, in the order the specification lists the checks.
    fn provision(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::ProvisionEndpointFields<'_> =
            crate::clusters::decode_fields(payload)?;
        // §14.5.4.2's constraints: a hostname of "4 to 253" and a port of "1 to 65535" — port 0
        // is not a port, and a node that stored one would try to connect to it.
        if !(HOSTNAME_MIN..=HOSTNAME_MAX).contains(&decoded.hostname.len()) || decoded.port == 0 {
            return Err(Status::ConstraintError.into());
        }
        // "If the UTCTime attribute of the Time Synchronization cluster is null: Fail the
        // command with the cluster-specific status code of InvalidTime."
        if !self.tables.time_known() {
            return Err(cluster_status(StatusCodeEnum::InvalidTime));
        }
        // The root certificate has to exist, on this fabric. Both failures are one code, the
        // same way §14.4.6 folds "not found" and "not yours" into `NOT_FOUND`.
        if !self
            .tables
            .roots()
            .iter()
            .any(|r| r.caid == decoded.caid && r.fabric_index == fabric)
        {
            return Err(cluster_status(StatusCodeEnum::RootCertificateNotFound));
        }
        let ccdid = decoded.ccdid.0;
        if let Some(ccdid) = ccdid
            && !self
                .tables
                .clients()
                .iter()
                .any(|c| c.ccdid == ccdid && c.fabric_index == fabric)
        {
            return Err(cluster_status(StatusCodeEnum::ClientCertificateNotFound));
        }

        let endpoint_id = match decoded.endpoint_id.0 {
            None => {
                if self.tables.count_endpoints(fabric) >= usize::from(self.tables.max_endpoints()) {
                    return Err(Status::ResourceExhausted.into());
                }
                if self.host_taken(fabric, decoded.hostname, decoded.port, None) {
                    return Err(cluster_status(StatusCodeEnum::EndpointAlreadyInstalled));
                }
                let taken = |candidate: TlsEndpointId| {
                    self.tables
                        .endpoints()
                        .iter()
                        .any(|e| e.endpoint_id == candidate)
                };
                let endpoint_id =
                    TlsTables::<R, C, E>::allocate(&self.tables.next_endpoint_id, taken)
                        .ok_or(StatusIb::from(Status::ResourceExhausted))?;
                let mut hostname = heapless::Vec::new();
                hostname
                    .extend_from_slice(decoded.hostname)
                    .map_err(|_| StatusIb::from(Status::ConstraintError))?;
                self.tables
                    .endpoints
                    .borrow_mut()
                    .push(EndpointEntry {
                        fabric_index: fabric,
                        endpoint_id,
                        hostname,
                        port: decoded.port,
                        caid: decoded.caid,
                        ccdid,
                        // "Set the ReferenceCount field to 0."
                        reference_count: 0,
                    })
                    .map_err(|_| StatusIb::from(Status::ResourceExhausted))?;
                endpoint_id
            }
            Some(endpoint_id) => {
                if !self
                    .tables
                    .endpoints()
                    .iter()
                    .any(|e| e.endpoint_id == endpoint_id && e.fabric_index == fabric)
                {
                    return Err(Status::NotFound.into());
                }
                // "If *another* entry exists for the passed in Hostname / Port combination" —
                // rewriting an endpoint to the host it already has is not a collision with
                // itself.
                if self.host_taken(fabric, decoded.hostname, decoded.port, Some(endpoint_id)) {
                    return Err(cluster_status(StatusCodeEnum::EndpointAlreadyInstalled));
                }
                let mut endpoints = self.tables.endpoints.borrow_mut();
                let Some(entry) = endpoints
                    .iter_mut()
                    .find(|e| e.endpoint_id == endpoint_id && e.fabric_index == fabric)
                else {
                    return Err(Status::NotFound.into());
                };
                entry.hostname.clear();
                entry
                    .hostname
                    .extend_from_slice(decoded.hostname)
                    .map_err(|_| StatusIb::from(Status::ConstraintError))?;
                entry.port = decoded.port;
                entry.caid = decoded.caid;
                entry.ccdid = ccdid;
                endpoint_id
            }
        };
        spec_tls::ProvisionEndpointResponseFields { endpoint_id }
            .to_tlv(w, tag)
            .map_err(|_| StatusIb::from(Status::Failure))?;
        Ok(Some(PROVISION_ENDPOINT_RESPONSE))
    }

    /// §14.5.7.3.
    fn find(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::FindEndpointFields = crate::clusters::decode_fields(payload)?;
        if self.tables.endpoints().is_empty() {
            return Err(Status::NotFound.into());
        }
        let endpoints = self.tables.endpoints();
        let entry = endpoints
            .iter()
            .find(|e| e.endpoint_id == decoded.endpoint_id && e.fabric_index == fabric)
            .ok_or(StatusIb::from(Status::NotFound))?;
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        full(w.start_structure(tag))?;
        full(encode_endpoint(entry, w, Tag::Context(0)))?;
        full(w.end_container())?;
        Ok(Some(FIND_ENDPOINT_RESPONSE))
    }

    /// §14.5.7.5.
    fn remove(&self, fabric: FabricIndex, payload: &[u8]) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::RemoveEndpointFields = crate::clusters::decode_fields(payload)?;
        if self.tables.endpoints().is_empty() {
            return Err(Status::NotFound.into());
        }
        let found = self
            .tables
            .endpoints()
            .iter()
            .find(|e| e.endpoint_id == decoded.endpoint_id && e.fabric_index == fabric)
            .map(|e| e.reference_count)
            .ok_or(StatusIb::from(Status::NotFound))?;
        // "If the ReferenceCount of that matching entry is greater than 0: Fail the command
        // with the status code INVALID_IN_STATE." Something is connected through it.
        if found > 0 {
            return Err(Status::InvalidInState.into());
        }
        self.tables
            .endpoints
            .borrow_mut()
            .retain(|e| !(e.endpoint_id == decoded.endpoint_id && e.fabric_index == fabric));
        Ok(None)
    }

    /// Whether this fabric already has an endpoint for `hostname` and `port`, ignoring `except`.
    fn host_taken(
        &self,
        fabric: FabricIndex,
        hostname: &[u8],
        port: u16,
        except: Option<TlsEndpointId>,
    ) -> bool {
        self.tables.endpoints().iter().any(|e| {
            e.fabric_index == fabric
                && e.port == port
                && e.hostname == hostname
                && except != Some(e.endpoint_id)
        })
    }
}

/// §14.5.4.2's `TLSEndpointStruct`.
fn encode_endpoint(
    entry: &EndpointEntry,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> crate::error::Result<()> {
    w.start_structure(tag)?;
    w.unsigned(Tag::Context(0), u64::from(entry.endpoint_id))?;
    w.octets(Tag::Context(1), &entry.hostname)?;
    w.unsigned(Tag::Context(2), u64::from(entry.port))?;
    w.unsigned(Tag::Context(3), u64::from(entry.caid))?;
    match entry.ccdid {
        // §14.5.4.2: "A NULL value means no client certificate is used with this endpoint."
        Some(ccdid) => w.unsigned(Tag::Context(4), u64::from(ccdid))?,
        None => w.null(Tag::Context(4))?,
    }
    w.unsigned(Tag::Context(5), u64::from(entry.reference_count))?;
    w.unsigned(Tag::Context(254), u64::from(entry.fabric_index.0))?;
    w.end_container()
}

/// So a tuple of clusters can dispatch to it by id.
impl<const R: usize, const C: usize, const E: usize> Cluster for ClientManagement<'_, R, C, E> {
    const ID: ClusterId = ID;
}
