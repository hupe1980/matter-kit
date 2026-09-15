//! TLS on a Matter node (Core ch. 14): the certificates and the endpoints.
//!
//! Needs the `rustcrypto` feature: §14.2.2.1 identifies every certificate by its SHA-256
//! fingerprint, which is [`crypto`](crate::crypto).
//!
//! Some application clusters — Camera AV Stream Management, WebRTC — reach outside the fabric
//! over TLS. Chapter 14 is how the administrator provisions that: which root CAs the node
//! trusts, which client certificate it presents, and which host and port each of them is for.
//!
//! Two clusters share the job and this module's [`TlsTables`] is why they can:
//!
//! * [`certificate_management`] (`0x0801`) holds the trust material — root CAs and client
//!   certificate details, each with an id and a fingerprint.
//! * [`client_management`] (`0x0802`) holds the endpoints, each naming a host, a port, and the
//!   certificates from the other cluster to use with them.
//!
//! The two are not independent, and the rules that link them are the ones an implementation
//! gets wrong. §14.4.6.7 refuses to remove a root certificate an endpoint still names;
//! §14.5.7.1 refuses to provision an endpoint naming a certificate that does not exist. Each
//! check has to see both tables, so both clusters are views onto one.
//!
//! # Certificates do not live in RAM
//!
//! §14.4.4.3 caps a certificate at 3000 octets and §14.3.3.1 asks for five root certificates
//! *per fabric*, plus two client certificates and up to ten intermediates each. That is tens of
//! kilobytes, and no `no_std` node holds it in a `heapless::Vec`.
//!
//! So this module holds the *index* — ids, fingerprints, fabric associations, reference counts
//! — and the certificate bytes belong to the application through [`TlsCertificateHooks`], which
//! writes them straight into the response's TLV rather than through a buffer in between. The
//! index is where every rule lives; the bytes are just bytes.
//!
//! # Large Message, and why this is where TCP earns its place
//!
//! §14.4: "Commands in this cluster uniformly use the Large Message qualifier, even when the
//! command doesn't require it, to reduce the testing matrix." A 3000-octet certificate does not
//! fit in §4.4.4's 1280-octet datagram, so these commands need
//! [`Peer::Tcp`](crate::platform::Peer::Tcp) underneath — and the attributes say so themselves:
//!
//! > When this field exists and is read over a Large Message capable transport, it SHALL be
//! > included. When this field exists and is read over a non Large Message capable transport,
//! > it SHALL NOT be included.
//!
//! A read over UDP returns the ids without the certificates, which is not an error and not a
//! truncation — it is the attribute having a different shape on a transport that cannot carry
//! the whole of it.

use core::cell::{Cell, RefCell};

use crate::im::Status;
use crate::msg::FabricIndex;
use crate::tlv::{Tag, TlvWriter};

pub mod certificate_management;
pub mod client_management;

/// §14.4.4.1: a `TLSCAID` has "valid values from 0 to 65534".
pub type TlsCaid = u16;
/// §14.4.4.2: a `TLSCCDID`, over the same range.
pub type TlsCcdid = u16;
/// §14.5.4.1: a `TLSEndpointID`, over the same range.
pub type TlsEndpointId = u16;

/// The largest id any of chapter 14's three types may take. `0xFFFF` is not one of them: it is
/// the null value every one of these fields uses when it is nullable.
pub const ID_MAX: u16 = 65534;

/// §14.4.4.3's constraint on a certificate: "max 3000".
pub const CERTIFICATE_MAX: usize = 3000;

/// §14.2.2.1: a fingerprint is SHA-256 over the DER, so 32 octets.
pub const FINGERPRINT_LEN: usize = 32;

/// §14.4.6.5's constraint on a `Fingerprint` field: "max 64", which leaves room for a longer
/// hash than 1.6 defines.
pub const FINGERPRINT_FIELD_MAX: usize = 64;

/// §14.5.4.2's constraint on a `Hostname`: "4 to 253".
pub const HOSTNAME_MIN: usize = 4;
/// The other end of it — a DNS name's own limit.
pub const HOSTNAME_MAX: usize = 253;

/// §14.4.4.4's constraint on `IntermediateCertificates`: "max 10".
pub const INTERMEDIATES_MAX: usize = 10;

/// §14.4.6.8's constraint on `Nonce`: exactly 32 octets, "generated using Crypto_DRBG()".
pub const NONCE_LEN: usize = 32;

/// §14.3.3.1: "Nodes SHALL provide enough storage space for at least 5 Root certificates per
/// Fabric on a Node."
pub const MIN_ROOTS_PER_FABRIC: u8 = 5;

/// §14.3.3.1: "at least 2 Client Certificate Details per Fabric".
pub const MIN_CLIENTS_PER_FABRIC: u8 = 2;

/// The smallest `MaxProvisioned` §14.5.6 allows: its constraint is "5 to 254".
///
/// §14.3.3.2 asks only for "at least 2 TLS Endpoints per Fabric" and for "at least 2 concurrent
/// TLS client connections per Fabric"; the attribute's own constraint is the higher of the two,
/// and it is the one a client reads.
pub const MIN_ENDPOINTS_PER_FABRIC: u8 = 5;

/// §14.2.2.1's certificate fingerprint: "the SHA-256 hash algorithm … using the DER (binary)
/// encoding format of the certificate".
#[must_use]
pub fn fingerprint(der: &[u8]) -> [u8; FINGERPRINT_LEN] {
    crate::crypto::hash(der)
}

/// Which stored certificate a [`TlsCertificateHooks`] call is about.
///
/// Every slot is fabric-scoped: §14.4.4.3 and §14.4.4.4 are both "Access Modifier: Fabric
/// Scoped", and two fabrics may hold the same id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    /// A root CA certificate (`TLSRCAC`), by its `TLSCAID`.
    Root {
        /// The fabric that provisioned it.
        fabric_index: FabricIndex,
        /// Its Certificate Authority ID.
        caid: TlsCaid,
    },
    /// A client certificate, by its `TLSCCDID`.
    Client {
        /// The fabric that provisioned it.
        fabric_index: FabricIndex,
        /// Its Client Certificate Details ID.
        ccdid: TlsCcdid,
    },
    /// One intermediate certificate of a client certificate's chain, in chain order.
    Intermediate {
        /// The fabric that provisioned it.
        fabric_index: FabricIndex,
        /// The client certificate this chain belongs to.
        ccdid: TlsCcdid,
        /// Its position in the chain, `0..`[`INTERMEDIATES_MAX`].
        index: u8,
    },
}

/// Where the certificate bytes actually live, and who does the cryptography.
///
/// Every method that produces a certificate writes it into the outgoing TLV rather than
/// returning it: a node that keeps its certificates in flash streams them straight out, and one
/// that keeps them in RAM writes a slice. Neither needs a 3000-octet buffer in between, which
/// is the whole reason this is a trait.
pub trait TlsCertificateHooks {
    /// Whether `der` is a certificate this node will accept.
    ///
    /// §14.4.6.1: "If the passed in Certificate is an invalid TLS Certificate: Fail the command
    /// with the status code DYNAMIC_CONSTRAINT_ERROR". What "valid" means is the product's —
    /// chapter 14 is standard Web PKI, not [`cert`](crate::cert)'s Matter profile.
    fn is_valid_certificate(&self, der: &[u8]) -> bool;

    /// Stores a certificate, replacing whatever the slot held.
    ///
    /// [`Status::ResourceExhausted`] when there is no room for it — the index had room, the
    /// flash did not.
    fn save(&self, slot: Slot, der: &[u8]) -> core::result::Result<(), Status>;

    /// Writes a stored certificate into the response as an octet string under `tag`.
    ///
    /// A slot the index knows about but the store has lost is [`Status::Failure`]: the two
    /// have disagreed, and answering with a truncated chain would be worse.
    fn write_certificate(
        &self,
        slot: Slot,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<(), Status>;

    /// Forgets a stored certificate. Called for a slot that may never have held one.
    fn clear(&self, slot: Slot);

    /// §14.4.6.8: generates a key pair for a new `TLSCCDID`.
    ///
    /// > If a key collision is detected against any other TLS key pair or Operational
    /// > credential key pair: Discard the new key pair. Fail the command with the status code
    /// > DYNAMIC_CONSTRAINT_ERROR.
    fn generate_key(&self, ccdid: TlsCcdid) -> core::result::Result<(), Status>;

    /// §14.4.6.8: writes the `CSR` and `NonceSignature` fields of a `ClientCSRResponse`.
    ///
    /// Two tags rather than two buffers, for the same reason as
    /// [`write_certificate`](Self::write_certificate): a PKCS #10 request may be 3000 octets and
    /// there is nowhere to put it. `csr_tag` takes "a DER-encoded octet string of a PKCS #10
    /// format Certificate Signing Request"; `signature_tag` takes `Crypto_Sign(nonce)` under
    /// the same key, which is the freshness proof §14.3.1.2 has the client check against the
    /// CSR's own inner signature.
    fn write_csr(
        &self,
        ccdid: TlsCcdid,
        nonce: &[u8],
        w: &mut TlvWriter<'_>,
        csr_tag: Tag,
        signature_tag: Tag,
    ) -> core::result::Result<(), Status>;

    /// §14.4.6.10: "If the public key of the passed in ClientCertificate does not correspond to
    /// the private key of the matching entry" — a certificate for somebody else's key.
    fn key_matches(&self, ccdid: TlsCcdid, certificate: &[u8]) -> bool;

    /// §14.4.6.15: "Remove the TLS Key Pair belonging to the passed in CCDID."
    fn remove_key(&self, ccdid: TlsCcdid);
}

/// One provisioned root CA certificate, as the index knows it (§14.4.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootEntry {
    /// The fabric that provisioned it, and the only one that can see it.
    pub fabric_index: FabricIndex,
    /// Its `TLSCAID`.
    pub caid: TlsCaid,
    /// §14.2.2.1's SHA-256 over the DER, which is what `LookupRootCertificate` searches and
    /// what `ProvisionRootCertificate` refuses a duplicate of.
    pub fingerprint: [u8; FINGERPRINT_LEN],
}

/// One provisioned client certificate (§14.4.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientEntry {
    /// The fabric that provisioned it.
    pub fabric_index: FabricIndex,
    /// Its `TLSCCDID`.
    pub ccdid: TlsCcdid,
    /// The certificate's fingerprint, or `None` while there is no certificate.
    ///
    /// §14.4.4.4: "A NULL value indicates that the TLS Client Certificate Signing Request (CSR)
    /// Procedure has not yet completed" — a `ClientCSR` has allocated the id and the key pair,
    /// and `ProvisionClientCertificate` has not run yet.
    pub fingerprint: Option<[u8; FINGERPRINT_LEN]>,
    /// How many intermediates the chain holds, `0..=`[`INTERMEDIATES_MAX`].
    pub intermediates: u8,
}

/// One provisioned TLS endpoint (§14.5.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointEntry {
    /// The fabric that provisioned it.
    pub fabric_index: FabricIndex,
    /// Its `TLSEndpointID`.
    pub endpoint_id: TlsEndpointId,
    /// The TLS hostname, 4 to 253 octets.
    pub hostname: heapless::Vec<u8, HOSTNAME_MAX>,
    /// The TLS port, 1 to 65535.
    pub port: u16,
    /// The root CA to authenticate the server with.
    pub caid: TlsCaid,
    /// The client certificate to present, or `None` for "no client certificate is used with
    /// this endpoint".
    pub ccdid: Option<TlsCcdid>,
    /// §14.5.4.2: "a reference count of the number of entities currently using this TLS
    /// Endpoint", which blocks removal while it is non-zero.
    pub reference_count: u8,
}

/// The three tables chapter 14's two clusters share.
///
/// `R`, `C` and `E` are totals across every fabric; the `max_*` figures are the per-fabric
/// quotas the `Max…` attributes report, so that the first fabric to provision cannot leave a
/// later one unable to. §14.3.3's minima — five roots, two client certificates, two endpoints
/// per fabric — are what a certifiable node sizes these from.
#[derive(Debug)]
pub struct TlsTables<const R: usize, const C: usize, const E: usize> {
    roots: RefCell<heapless::Vec<RootEntry, R>>,
    clients: RefCell<heapless::Vec<ClientEntry, C>>,
    endpoints: RefCell<heapless::Vec<EndpointEntry, E>>,
    next_caid: Cell<u16>,
    next_ccdid: Cell<u16>,
    next_endpoint_id: Cell<u16>,
    max_roots: u8,
    max_clients: u8,
    max_endpoints: u8,
    time_known: Cell<bool>,
}

impl<const R: usize, const C: usize, const E: usize> TlsTables<R, C, E> {
    /// Empty tables with the per-fabric quotas §14.3.3 sets as minima.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_quotas(
            MIN_ROOTS_PER_FABRIC,
            MIN_CLIENTS_PER_FABRIC,
            MIN_ENDPOINTS_PER_FABRIC,
        )
    }

    /// Empty tables with explicit per-fabric quotas, which §14.3.3 lets a device type raise.
    #[must_use]
    pub const fn with_quotas(max_roots: u8, max_clients: u8, max_endpoints: u8) -> Self {
        Self {
            roots: RefCell::new(heapless::Vec::new()),
            clients: RefCell::new(heapless::Vec::new()),
            endpoints: RefCell::new(heapless::Vec::new()),
            next_caid: Cell::new(0),
            next_ccdid: Cell::new(0),
            next_endpoint_id: Cell::new(0),
            max_roots,
            max_clients,
            max_endpoints,
            time_known: Cell::new(false),
        }
    }

    /// `MaxRootCertificates` (§14.4.5.1).
    #[must_use]
    pub const fn max_roots(&self) -> u8 {
        self.max_roots
    }

    /// `MaxClientCertificates` (§14.4.5.3).
    #[must_use]
    pub const fn max_clients(&self) -> u8 {
        self.max_clients
    }

    /// `MaxProvisioned` (§14.5.6.1).
    #[must_use]
    pub const fn max_endpoints(&self) -> u8 {
        self.max_endpoints
    }

    /// Whether the Time Synchronization cluster has a `UTCTime`.
    ///
    /// §14.3.1: a node doing TLS "SHALL support the Time Synchronization cluster", because "Web
    /// PKI and TLS policy performs time and date validation of all X.509 certificates". Both
    /// `ProvisionRootCertificate` and `ProvisionEndpoint` refuse to run before it is set —
    /// provisioning a certificate whose expiry cannot be judged is how a node ends up trusting
    /// an expired CA for ever.
    pub fn set_time_known(&self, known: bool) {
        self.time_known.set(known);
    }

    /// Whether the clock is set.
    #[must_use]
    pub fn time_known(&self) -> bool {
        self.time_known.get()
    }

    /// Every provisioned root certificate, for a device about to persist them.
    #[must_use]
    pub fn roots(&self) -> core::cell::Ref<'_, heapless::Vec<RootEntry, R>> {
        self.roots.borrow()
    }

    /// Every provisioned client certificate.
    #[must_use]
    pub fn clients(&self) -> core::cell::Ref<'_, heapless::Vec<ClientEntry, C>> {
        self.clients.borrow()
    }

    /// Every provisioned endpoint.
    #[must_use]
    pub fn endpoints(&self) -> core::cell::Ref<'_, heapless::Vec<EndpointEntry, E>> {
        self.endpoints.borrow()
    }

    /// Sets an endpoint's `ReferenceCount` (§14.5.4.2).
    ///
    /// "The node SHALL recompute this field to reflect the correct value at runtime (e.g., when
    /// restored from a persisted value after a reboot)" — so it is the application's number,
    /// and the cluster's job is only to refuse to remove an endpoint that still has one.
    pub fn set_reference_count(&self, endpoint_id: TlsEndpointId, count: u8) {
        if let Some(entry) = self
            .endpoints
            .borrow_mut()
            .iter_mut()
            .find(|e| e.endpoint_id == endpoint_id)
        {
            entry.reference_count = count;
        }
    }

    /// Forgets everything one fabric provisioned — what `RemoveFabric` must do.
    ///
    /// The endpoints go first: every interlock in chapter 14 is "a certificate an endpoint
    /// still names", and removing the fabric removes both sides at once.
    pub fn remove_fabric(&self, fabric: FabricIndex, hooks: &impl TlsCertificateHooks) {
        self.endpoints
            .borrow_mut()
            .retain(|e| e.fabric_index != fabric);
        for root in self
            .roots
            .borrow()
            .iter()
            .filter(|r| r.fabric_index == fabric)
        {
            hooks.clear(Slot::Root {
                fabric_index: fabric,
                caid: root.caid,
            });
        }
        self.roots.borrow_mut().retain(|r| r.fabric_index != fabric);
        for client in self
            .clients
            .borrow()
            .iter()
            .filter(|c| c.fabric_index == fabric)
        {
            clear_client(hooks, fabric, client.ccdid, client.intermediates);
            hooks.remove_key(client.ccdid);
        }
        self.clients
            .borrow_mut()
            .retain(|c| c.fabric_index != fabric);
    }

    /// How many entries one fabric holds in each table.
    fn count_roots(&self, fabric: FabricIndex) -> usize {
        self.roots
            .borrow()
            .iter()
            .filter(|r| r.fabric_index == fabric)
            .count()
    }

    fn count_clients(&self, fabric: FabricIndex) -> usize {
        self.clients
            .borrow()
            .iter()
            .filter(|c| c.fabric_index == fabric)
            .count()
    }

    fn count_endpoints(&self, fabric: FabricIndex) -> usize {
        self.endpoints
            .borrow()
            .iter()
            .filter(|e| e.fabric_index == fabric)
            .count()
    }

    /// §14.4.4.1's id allocation: "start at 0 and monotonically increase by 1 with each new
    /// allocation … A value incremented past 65534 SHOULD wrap to 0. The Node SHALL verify that
    /// a new value does not match any other value for this type."
    ///
    /// The uniqueness check is across *every* fabric, not just the accessing one. Two fabrics
    /// sharing an id would still be told apart by the fabric association, but §14.4.4.1 says a
    /// new value must not match "any other value for this type", and an id that means two
    /// things is the sort of thing that survives until the day something indexes by it alone.
    fn allocate(next: &Cell<u16>, taken: impl Fn(u16) -> bool) -> Option<u16> {
        let start = next.get();
        let mut candidate = start;
        for _ in 0..=u32::from(ID_MAX) {
            if !taken(candidate) {
                next.set(if candidate >= ID_MAX {
                    0
                } else {
                    candidate.saturating_add(1)
                });
                return Some(candidate);
            }
            candidate = if candidate >= ID_MAX {
                0
            } else {
                candidate.saturating_add(1)
            };
        }
        None
    }
}

impl<const R: usize, const C: usize, const E: usize> Default for TlsTables<R, C, E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Clears a client certificate and every intermediate behind it.
fn clear_client(
    hooks: &impl TlsCertificateHooks,
    fabric_index: FabricIndex,
    ccdid: TlsCcdid,
    intermediates: u8,
) {
    hooks.clear(Slot::Client {
        fabric_index,
        ccdid,
    });
    for index in 0..intermediates {
        hooks.clear(Slot::Intermediate {
            fabric_index,
            ccdid,
            index,
        });
    }
}

/// Whether a fabric's entries belong in this read (§7.19.1.8.2).
fn visible(ctx: &crate::im::InteractionContext<'_>, index: FabricIndex) -> bool {
    !ctx.fabric_filtered || ctx.fabric_index == Some(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Tables = TlsTables<4, 4, 4>;

    /// §14.4.4.1: "This value SHOULD start at 0 and monotonically increase by 1 with each new
    /// allocation … A value incremented past 65534 SHOULD wrap to 0. The Node SHALL verify that
    /// a new value does not match any other value for this type."
    ///
    /// The wrap needs a counter at 65534 and an id already taken there — neither reachable by
    /// provisioning four certificates, which is what the integration tests can do.
    #[test]
    fn ids_start_at_zero_and_increase_by_one() {
        let tables = Tables::new();
        let none = |_: u16| false;
        assert_eq!(Tables::allocate(&tables.next_caid, none), Some(0));
        assert_eq!(Tables::allocate(&tables.next_caid, none), Some(1));
        assert_eq!(Tables::allocate(&tables.next_caid, none), Some(2));
    }

    #[test]
    fn an_id_past_65534_wraps_to_zero() {
        let tables = Tables::new();
        tables.next_caid.set(ID_MAX);
        let none = |_: u16| false;
        assert_eq!(Tables::allocate(&tables.next_caid, none), Some(ID_MAX));
        assert_eq!(
            Tables::allocate(&tables.next_caid, none),
            Some(0),
            "65535 is the null value, not an id"
        );
    }

    #[test]
    fn a_taken_id_is_skipped() {
        // "The Node SHALL verify that a new value does not match any other value for this type.
        // If such a match is found, the value SHALL be changed until a unique value is found."
        let tables = Tables::new();
        let taken = |id: u16| matches!(id, 0 | 1 | 3);
        assert_eq!(Tables::allocate(&tables.next_caid, taken), Some(2));
        assert_eq!(Tables::allocate(&tables.next_caid, taken), Some(4));
    }

    #[test]
    fn a_full_id_space_allocates_nothing() {
        // Rather than looping for ever, or handing out an id that is already in use.
        let tables = Tables::new();
        assert_eq!(Tables::allocate(&tables.next_caid, |_| true), None);
    }
}
