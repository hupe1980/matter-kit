//! TLS Certificate Management, cluster `0x0801` (Core §14.4).
//!
//! > This cluster is used to manage TLS CA Root and Client Certificates on a Node, which are
//! > then used by other clusters to provision and manage their usage of TLS.
//!
//! Two halves that barely touch. **Root certificates** are trust: an administrator hands the
//! node a CA it should believe, and gets a `TLSCAID` back. **Client certificate details** are
//! identity: the node generates a key pair and a PKCS #10 request, the administrator has it
//! signed somewhere outside Matter, and hands the certificate back against the same `TLSCCDID`.
//!
//! # The status codes are the specification, and they are deliberate
//!
//! Every lookup in §14.4.6 fails with `NOT_FOUND` — not `UNSUPPORTED_ACCESS` — when the entry
//! belongs to another fabric. That is not sloppiness: answering "exists, but not yours" would
//! tell one administrator how many certificates another had provisioned, and the ids they were
//! given. A fabric sees its own entries and an empty table.
//!
//! # The two cross-cluster interlocks
//!
//! §14.4.6.7 and §14.4.6.15 both end with the same check: a certificate an endpoint still names
//! cannot be removed, `INVALID_IN_STATE`. Without it a node keeps an endpoint pointing at a
//! `TLSCAID` that no longer resolves, and finds out at connection time — which, for a camera
//! uploading to a server, is the worst moment to discover it cannot authenticate anything.
//! [`TlsTables`] is what lets this cluster see the other one's list.

use crate::clusters::generated::tls_certificate_management as spec_tls;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::msg::FabricIndex;
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::{
    CERTIFICATE_MAX, ClientEntry, FINGERPRINT_FIELD_MAX, INTERMEDIATES_MAX, NONCE_LEN, RootEntry,
    Slot, TlsCaid, TlsCcdid, TlsCertificateHooks, TlsTables, clear_client, fingerprint, visible,
};
use crate::clusters::Cluster;

pub use spec_tls::attribute::{
    MAX_CLIENT_CERTIFICATES, MAX_ROOT_CERTIFICATES, PROVISIONED_CLIENT_CERTIFICATES,
    PROVISIONED_ROOT_CERTIFICATES,
};
pub use spec_tls::command::{
    CLIENT_CSR, CLIENT_CSR_RESPONSE, FIND_CLIENT_CERTIFICATE, FIND_CLIENT_CERTIFICATE_RESPONSE,
    FIND_ROOT_CERTIFICATE, FIND_ROOT_CERTIFICATE_RESPONSE, LOOKUP_CLIENT_CERTIFICATE,
    LOOKUP_CLIENT_CERTIFICATE_RESPONSE, LOOKUP_ROOT_CERTIFICATE, LOOKUP_ROOT_CERTIFICATE_RESPONSE,
    PROVISION_CLIENT_CERTIFICATE, PROVISION_ROOT_CERTIFICATE, PROVISION_ROOT_CERTIFICATE_RESPONSE,
    REMOVE_CLIENT_CERTIFICATE, REMOVE_ROOT_CERTIFICATE,
};
pub use spec_tls::{ID, PICS, REVISION};

/// The TLS Certificate Management cluster (§14.4).
#[derive(Debug)]
pub struct CertificateManagement<
    'a,
    H: TlsCertificateHooks,
    const R: usize,
    const C: usize,
    const E: usize,
> {
    tables: &'a TlsTables<R, C, E>,
    hooks: &'a H,
}

impl<'a, H: TlsCertificateHooks, const R: usize, const C: usize, const E: usize>
    CertificateManagement<'a, H, R, C, E>
{
    /// A cluster over shared tables and a certificate store.
    #[must_use]
    pub const fn new(tables: &'a TlsTables<R, C, E>, hooks: &'a H) -> Self {
        Self { tables, hooks }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<4, 9, 6, 0>> {
        Conforming::new(&spec_tls::CLUSTER, feature_map, optional)
    }

    /// The tables this cluster shares with [`client_management`](super::client_management).
    #[must_use]
    pub const fn tables(&self) -> &'a TlsTables<R, C, E> {
        self.tables
    }
}

/// Where a fabric-scoped lookup landed.
///
/// The two failures are one status on purpose: §14.4.6 answers "no such id" and "not your id"
/// identically with `NOT_FOUND`, so that one fabric cannot probe another's.
fn find_root<const R: usize, const C: usize, const E: usize>(
    tables: &TlsTables<R, C, E>,
    fabric: FabricIndex,
    caid: TlsCaid,
) -> Result<RootEntry, Status> {
    tables
        .roots()
        .iter()
        .find(|r| r.caid == caid && r.fabric_index == fabric)
        .copied()
        .ok_or(Status::NotFound)
}

fn find_client<const R: usize, const C: usize, const E: usize>(
    tables: &TlsTables<R, C, E>,
    fabric: FabricIndex,
    ccdid: TlsCcdid,
) -> Result<ClientEntry, Status> {
    tables
        .clients()
        .iter()
        .find(|c| c.ccdid == ccdid && c.fabric_index == fabric)
        .copied()
        .ok_or(Status::NotFound)
}

impl<H: TlsCertificateHooks, const R: usize, const C: usize, const E: usize> ClusterHandler
    for CertificateManagement<'_, H, R, C, E>
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
            MAX_ROOT_CERTIFICATES => full(w.unsigned(tag, u64::from(self.tables.max_roots()))),
            MAX_CLIENT_CERTIFICATES => full(w.unsigned(tag, u64::from(self.tables.max_clients()))),
            PROVISIONED_ROOT_CERTIFICATES => {
                let roots = self.tables.roots();
                full(w.start_array(tag))?;
                for root in roots.iter().filter(|r| visible(ctx, r.fabric_index)) {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), u64::from(root.caid)))?;
                    // §14.4.5.2: "When this attribute is read over a non Large Message capable
                    // transport, the Certificate field SHALL NOT be included." Not a
                    // truncation — the attribute has a different shape on a transport that
                    // cannot carry 3000 octets, and `FindRootCertificate` is where the rest is.
                    if ctx.large_messages {
                        self.hooks.write_certificate(
                            Slot::Root {
                                fabric_index: root.fabric_index,
                                caid: root.caid,
                            },
                            w,
                            Tag::Context(1),
                        )?;
                    }
                    full(w.unsigned(Tag::Context(254), u64::from(root.fabric_index.0)))?;
                    full(w.end_container())?;
                }
                full(w.end_container())
            }
            PROVISIONED_CLIENT_CERTIFICATES => {
                let clients = self.tables.clients();
                full(w.start_array(tag))?;
                for client in clients.iter().filter(|c| visible(ctx, c.fabric_index)) {
                    full(w.start_structure(Tag::Anonymous))?;
                    full(w.unsigned(Tag::Context(0), u64::from(client.ccdid)))?;
                    self.write_client_certificate(client, ctx.large_messages, w)?;
                    full(w.unsigned(Tag::Context(254), u64::from(client.fabric_index.0)))?;
                    full(w.end_container())?;
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
        // Every command in §14.4.6 is `F`: fabric-scoped, and there is nothing to scope to
        // without an accessing fabric.
        let fabric = ctx
            .fabric_index
            .filter(|f| f.0 != 0)
            .ok_or(StatusIb::from(Status::UnsupportedAccess))?;
        let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
        match resolved.command.id {
            PROVISION_ROOT_CERTIFICATE => self.provision_root(fabric, payload, w, tag),
            FIND_ROOT_CERTIFICATE => self.find_roots(fabric, payload, w, tag),
            LOOKUP_ROOT_CERTIFICATE => self.lookup_root(fabric, payload, w, tag),
            REMOVE_ROOT_CERTIFICATE => self.remove_root(fabric, payload),
            CLIENT_CSR => self.client_csr(fabric, payload, w, tag),
            PROVISION_CLIENT_CERTIFICATE => self.provision_client(fabric, payload),
            FIND_CLIENT_CERTIFICATE => self.find_clients(fabric, payload, w, tag),
            LOOKUP_CLIENT_CERTIFICATE => self.lookup_client(fabric, payload, w, tag),
            REMOVE_CLIENT_CERTIFICATE => self.remove_client(fabric, payload),
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<H: TlsCertificateHooks, const R: usize, const C: usize, const E: usize>
    CertificateManagement<'_, H, R, C, E>
{
    /// §14.4.6.1, in the order the specification lists the checks.
    fn provision_root(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::ProvisionRootCertificateFields<'_> =
            crate::clusters::decode_fields(payload)?;
        if decoded.certificate.len() > CERTIFICATE_MAX {
            return Err(Status::ConstraintError.into());
        }
        // "If the UTCTime attribute of the Time Synchronization cluster is null: Fail the
        // command with the status code INVALID_IN_STATE."
        if !self.tables.time_known() {
            return Err(Status::InvalidInState.into());
        }
        if !self.hooks.is_valid_certificate(decoded.certificate) {
            return Err(Status::DynamicConstraintError.into());
        }
        let print = fingerprint(decoded.certificate);
        // The duplicate check comes before the CAID branch, so rotating an entry to a
        // certificate this fabric already holds is `ALREADY_EXISTS` too.
        if self
            .tables
            .roots()
            .iter()
            .any(|r| r.fabric_index == fabric && r.fingerprint == print)
        {
            return Err(Status::AlreadyExists.into());
        }

        let caid = match decoded.caid.0 {
            None => {
                if self.tables.count_roots(fabric) >= usize::from(self.tables.max_roots()) {
                    return Err(Status::ResourceExhausted.into());
                }
                let taken =
                    |candidate: TlsCaid| self.tables.roots().iter().any(|r| r.caid == candidate);
                let caid = TlsTables::<R, C, E>::allocate(&self.tables.next_caid, taken)
                    .ok_or(StatusIb::from(Status::ResourceExhausted))?;
                self.hooks.save(
                    Slot::Root {
                        fabric_index: fabric,
                        caid,
                    },
                    decoded.certificate,
                )?;
                self.tables
                    .roots
                    .borrow_mut()
                    .push(RootEntry {
                        fabric_index: fabric,
                        caid,
                        fingerprint: print,
                    })
                    .map_err(|_| StatusIb::from(Status::ResourceExhausted))?;
                caid
            }
            Some(caid) => {
                let existing = find_root(self.tables, fabric, caid)?;
                self.hooks.save(
                    Slot::Root {
                        fabric_index: fabric,
                        caid: existing.caid,
                    },
                    decoded.certificate,
                )?;
                if let Some(entry) = self
                    .tables
                    .roots
                    .borrow_mut()
                    .iter_mut()
                    .find(|r| r.caid == caid && r.fabric_index == fabric)
                {
                    entry.fingerprint = print;
                }
                caid
            }
        };
        spec_tls::ProvisionRootCertificateResponseFields { caid }
            .to_tlv(w, tag)
            .map_err(|_| StatusIb::from(Status::Failure))?;
        Ok(Some(PROVISION_ROOT_CERTIFICATE_RESPONSE))
    }

    /// §14.4.6.3. The certificate is always included: the command carries the `L` quality, so
    /// the interaction model has already refused it on a transport that could not hold one.
    fn find_roots(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::FindRootCertificateFields = crate::clusters::decode_fields(payload)?;
        if self.tables.roots().is_empty() {
            return Err(Status::NotFound.into());
        }
        let wanted = decoded.caid.0;
        let matches: heapless::Vec<RootEntry, R> = self
            .tables
            .roots()
            .iter()
            .filter(|r| r.fabric_index == fabric && wanted.is_none_or(|caid| r.caid == caid))
            .copied()
            .collect();
        // "If the resulting list has no entries: Fail the command with the status code
        // NOT_FOUND" — which is also the answer for a CAID that belongs to another fabric.
        if matches.is_empty() {
            return Err(Status::NotFound.into());
        }
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        full(w.start_structure(tag))?;
        full(w.start_array(Tag::Context(0)))?;
        for root in &matches {
            full(w.start_structure(Tag::Anonymous))?;
            full(w.unsigned(Tag::Context(0), u64::from(root.caid)))?;
            self.hooks.write_certificate(
                Slot::Root {
                    fabric_index: root.fabric_index,
                    caid: root.caid,
                },
                w,
                Tag::Context(1),
            )?;
            full(w.unsigned(Tag::Context(254), u64::from(root.fabric_index.0)))?;
            full(w.end_container())?;
        }
        full(w.end_container())?;
        full(w.end_container())?;
        Ok(Some(FIND_ROOT_CERTIFICATE_RESPONSE))
    }

    /// §14.4.6.5.
    fn lookup_root(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::LookupRootCertificateFields<'_> =
            crate::clusters::decode_fields(payload)?;
        if decoded.fingerprint.len() > FINGERPRINT_FIELD_MAX {
            return Err(Status::ConstraintError.into());
        }
        if self.tables.roots().is_empty() {
            return Err(Status::NotFound.into());
        }
        let caid = self
            .tables
            .roots()
            .iter()
            .find(|r| r.fabric_index == fabric && r.fingerprint.as_slice() == decoded.fingerprint)
            .map(|r| r.caid)
            .ok_or(StatusIb::from(Status::NotFound))?;
        spec_tls::LookupRootCertificateResponseFields { caid }
            .to_tlv(w, tag)
            .map_err(|_| StatusIb::from(Status::Failure))?;
        Ok(Some(LOOKUP_ROOT_CERTIFICATE_RESPONSE))
    }

    /// §14.4.6.7, whose last check is the interlock with the other cluster.
    fn remove_root(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::RemoveRootCertificateFields =
            crate::clusters::decode_fields(payload)?;
        if self.tables.roots().is_empty() {
            return Err(Status::NotFound.into());
        }
        let entry = find_root(self.tables, fabric, decoded.caid)?;
        // "If the passed in CAID equals the CAID of any entry in the ProvisionedEndpoints list
        // in the TLS Client Management Cluster: Fail the command with the status code
        // INVALID_IN_STATE."
        if self
            .tables
            .endpoints()
            .iter()
            .any(|e| e.caid == decoded.caid)
        {
            return Err(Status::InvalidInState.into());
        }
        self.hooks.clear(Slot::Root {
            fabric_index: entry.fabric_index,
            caid: entry.caid,
        });
        self.tables
            .roots
            .borrow_mut()
            .retain(|r| !(r.caid == entry.caid && r.fabric_index == fabric));
        Ok(None)
    }

    /// §14.4.6.8.
    fn client_csr(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::ClientCSRFields<'_> = crate::clusters::decode_fields(payload)?;
        // §14.4.6.8's constraint on `Nonce` is an exact 32, "generated using Crypto_DRBG()".
        if decoded.nonce.len() != NONCE_LEN {
            return Err(Status::ConstraintError.into());
        }
        let ccdid = match decoded.ccdid.0 {
            None => {
                if self.tables.count_clients(fabric) >= usize::from(self.tables.max_clients()) {
                    return Err(Status::ResourceExhausted.into());
                }
                let taken = |candidate: TlsCcdid| {
                    self.tables.clients().iter().any(|c| c.ccdid == candidate)
                };
                let ccdid = TlsTables::<R, C, E>::allocate(&self.tables.next_ccdid, taken)
                    .ok_or(StatusIb::from(Status::ResourceExhausted))?;
                // A key collision is `DYNAMIC_CONSTRAINT_ERROR` and the new key pair is
                // discarded, so nothing is recorded until this succeeds.
                self.hooks.generate_key(ccdid)?;
                self.tables
                    .clients
                    .borrow_mut()
                    .push(ClientEntry {
                        fabric_index: fabric,
                        ccdid,
                        // "Set the ClientCertificate and IntermediateCertificates fields to
                        // NULL" — the CSR procedure has not completed.
                        fingerprint: None,
                        intermediates: 0,
                    })
                    .map_err(|_| StatusIb::from(Status::ResourceExhausted))?;
                ccdid
            }
            Some(ccdid) => find_client(self.tables, fabric, ccdid)?.ccdid,
        };
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        full(w.start_structure(tag))?;
        full(w.unsigned(Tag::Context(0), u64::from(ccdid)))?;
        self.hooks
            .write_csr(ccdid, decoded.nonce, w, Tag::Context(1), Tag::Context(2))?;
        full(w.end_container())?;
        Ok(Some(CLIENT_CSR_RESPONSE))
    }

    /// §14.4.6.10, in the order the specification lists the checks.
    fn provision_client(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::ProvisionClientCertificateFields<'_> =
            crate::clusters::decode_fields(payload)?;
        if decoded.client_certificate.len() > CERTIFICATE_MAX {
            return Err(Status::ConstraintError.into());
        }
        if self.tables.clients().is_empty() {
            return Err(Status::NotFound.into());
        }
        let print = fingerprint(decoded.client_certificate);
        if self
            .tables
            .clients()
            .iter()
            .any(|c| c.fabric_index == fabric && c.fingerprint == Some(print))
        {
            return Err(Status::AlreadyExists.into());
        }
        let entry = find_client(self.tables, fabric, decoded.ccdid)?;
        if !self.hooks.is_valid_certificate(decoded.client_certificate) {
            return Err(Status::DynamicConstraintError.into());
        }
        // "If the public key of the passed in ClientCertificate does not correspond to the
        // private key of the matching entry" — a certificate issued for somebody else's key
        // would be presented in a handshake this node could never finish.
        if !self
            .hooks
            .key_matches(entry.ccdid, decoded.client_certificate)
        {
            return Err(Status::DynamicConstraintError.into());
        }

        // §14.4.6.10's constraint on `IntermediateCertificates` is "0 to 10 [max 3000]", and
        // every one of them has to be valid before any of them is stored: a chain half written
        // is one the node would present.
        let mut count = 0u8;
        for intermediate in decoded.intermediate_certificates.iter() {
            let der = intermediate.map_err(|_| StatusIb::from(Status::InvalidCommand))?;
            if der.len() > CERTIFICATE_MAX || usize::from(count) >= INTERMEDIATES_MAX {
                return Err(Status::ConstraintError.into());
            }
            if !self.hooks.is_valid_certificate(der) {
                return Err(Status::DynamicConstraintError.into());
            }
            count = count.saturating_add(1);
        }

        // The old chain may be longer than the new one, and its tail would otherwise be read
        // back as part of it.
        clear_client(self.hooks, fabric, entry.ccdid, entry.intermediates);
        self.hooks.save(
            Slot::Client {
                fabric_index: fabric,
                ccdid: entry.ccdid,
            },
            decoded.client_certificate,
        )?;
        let mut index = 0u8;
        for intermediate in decoded.intermediate_certificates.iter() {
            let der = intermediate.map_err(|_| StatusIb::from(Status::InvalidCommand))?;
            self.hooks.save(
                Slot::Intermediate {
                    fabric_index: fabric,
                    ccdid: entry.ccdid,
                    index,
                },
                der,
            )?;
            index = index.saturating_add(1);
        }
        if let Some(stored) = self
            .tables
            .clients
            .borrow_mut()
            .iter_mut()
            .find(|c| c.ccdid == entry.ccdid && c.fabric_index == fabric)
        {
            stored.fingerprint = Some(print);
            stored.intermediates = count;
        }
        Ok(None)
    }

    /// §14.4.6.11.
    fn find_clients(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::FindClientCertificateFields =
            crate::clusters::decode_fields(payload)?;
        if self.tables.clients().is_empty() {
            return Err(Status::NotFound.into());
        }
        let wanted = decoded.ccdid.0;
        let matches: heapless::Vec<ClientEntry, C> = self
            .tables
            .clients()
            .iter()
            .filter(|c| c.fabric_index == fabric && wanted.is_none_or(|ccdid| c.ccdid == ccdid))
            .copied()
            .collect();
        if matches.is_empty() {
            return Err(Status::NotFound.into());
        }
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        full(w.start_structure(tag))?;
        full(w.start_array(Tag::Context(0)))?;
        for client in &matches {
            full(w.start_structure(Tag::Anonymous))?;
            full(w.unsigned(Tag::Context(0), u64::from(client.ccdid)))?;
            // A command, so §14.4.6's `L` quality has already guaranteed the transport.
            self.write_client_certificate(client, true, w)?;
            full(w.unsigned(Tag::Context(254), u64::from(client.fabric_index.0)))?;
            full(w.end_container())?;
        }
        full(w.end_container())?;
        full(w.end_container())?;
        Ok(Some(FIND_CLIENT_CERTIFICATE_RESPONSE))
    }

    /// §14.4.6.13.
    fn lookup_client(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::LookupClientCertificateFields<'_> =
            crate::clusters::decode_fields(payload)?;
        if decoded.fingerprint.len() > FINGERPRINT_FIELD_MAX {
            return Err(Status::ConstraintError.into());
        }
        if self.tables.clients().is_empty() {
            return Err(Status::NotFound.into());
        }
        let ccdid = self
            .tables
            .clients()
            .iter()
            .find(|c| {
                c.fabric_index == fabric
                    && c.fingerprint
                        .is_some_and(|print| print.as_slice() == decoded.fingerprint)
            })
            .map(|c| c.ccdid)
            .ok_or(StatusIb::from(Status::NotFound))?;
        spec_tls::LookupClientCertificateResponseFields { ccdid }
            .to_tlv(w, tag)
            .map_err(|_| StatusIb::from(Status::Failure))?;
        Ok(Some(LOOKUP_CLIENT_CERTIFICATE_RESPONSE))
    }

    /// §14.4.6.15.
    fn remove_client(
        &self,
        fabric: FabricIndex,
        payload: &[u8],
    ) -> Result<Option<CommandId>, StatusIb> {
        let decoded: spec_tls::RemoveClientCertificateFields =
            crate::clusters::decode_fields(payload)?;
        if self.tables.clients().is_empty() {
            return Err(Status::NotFound.into());
        }
        let entry = find_client(self.tables, fabric, decoded.ccdid)?;
        if self
            .tables
            .endpoints()
            .iter()
            .any(|e| e.ccdid == Some(decoded.ccdid))
        {
            return Err(Status::InvalidInState.into());
        }
        clear_client(self.hooks, fabric, entry.ccdid, entry.intermediates);
        // "Remove the TLS Key Pair belonging to the passed in CCDID." A key left behind is a
        // key that can still sign.
        self.hooks.remove_key(entry.ccdid);
        self.tables
            .clients
            .borrow_mut()
            .retain(|c| !(c.ccdid == entry.ccdid && c.fabric_index == fabric));
        Ok(None)
    }

    /// Writes a client certificate's `ClientCertificate` and `IntermediateCertificates` fields.
    ///
    /// §14.4.4.4 draws a line the root certificate's rule does not. The omission on a small
    /// transport covers a field that "is non-NULL" — and, for the chain, one that "is
    /// non-empty":
    ///
    /// > When this field exists, is non-NULL, and is read over a non Large Message capable
    /// > transport, it SHALL NOT be included.
    ///
    /// So a **null** `ClientCertificate` and an **empty** chain are written whatever the
    /// transport. They cost two octets each, and they carry the one thing a client on a
    /// datagram transport could not otherwise learn: "A NULL value indicates that the TLS
    /// Client Certificate Signing Request (CSR) Procedure has not yet completed", which is a
    /// different thing from a field the transport could not carry.
    fn write_client_certificate(
        &self,
        client: &ClientEntry,
        large: bool,
        w: &mut TlvWriter<'_>,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match client.fingerprint {
            None => full(w.null(Tag::Context(1)))?,
            Some(_) if !large => {}
            Some(_) => self.hooks.write_certificate(
                Slot::Client {
                    fabric_index: client.fabric_index,
                    ccdid: client.ccdid,
                },
                w,
                Tag::Context(1),
            )?,
        }
        if !large && client.intermediates > 0 {
            return Ok(());
        }
        full(w.start_array(Tag::Context(2)))?;
        for index in 0..client.intermediates {
            self.hooks.write_certificate(
                Slot::Intermediate {
                    fabric_index: client.fabric_index,
                    ccdid: client.ccdid,
                    index,
                },
                w,
                Tag::Anonymous,
            )?;
        }
        full(w.end_container())
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: TlsCertificateHooks, const R: usize, const C: usize, const E: usize> Cluster
    for CertificateManagement<'_, H, R, C, E>
{
    const ID: ClusterId = ID;
}
