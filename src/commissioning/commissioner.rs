//! The commissioner's half of the commissioning flow (Core §5.5).
//!
//! §5.5 lists seventeen steps for the initial phase and four for the setup phase. Most are the
//! commissioner's, and they are all one shape: invoke a command over the PASE session, check the
//! response, invoke the next. This is that sequence, written as a state machine so the caller
//! keeps the sockets and the crypto and this keeps the *order* — which is the part that is easy
//! to get subtly wrong and hard to notice.
//!
//! # Why an order at all
//!
//! Every step depends on one before it, and several of the dependencies are security properties
//! rather than data flow:
//!
//! * The **fail-safe** is armed first (§5.5 step 7) because everything after it is undone if the
//!   commissioner walks away. A device that took a NOC with no fail-safe armed would keep a
//!   fabric nobody finished joining.
//! * **Attestation** comes before the CSR (§5.5 steps 10–11) because the CSR is signed by the
//!   *same* DAC key the attestation proved possession of. Asking for a CSR first would mean
//!   verifying a signature against a key nothing had vouched for.
//! * The **root** is installed before the NOC (§11.18.6.8), and in the same fail-safe period, or
//!   the device would be asked to trust a chain whose anchor it does not have.
//!
//! # What this does not do
//!
//! Own a socket, a clock or a key. [`Commissioner::step`](crate::commissioning::commissioner::Commissioner::step) hands back the command to send and
//! [`Commissioner::on_response`](crate::commissioning::commissioner::Commissioner::on_response) takes what came back; PASE and CASE are
//! [`PaseInitiator`](crate::sc::PaseInitiator) and [`CaseInitiator`](crate::sc::CaseInitiator),
//! and the exchange underneath is [`messaging`](crate::messaging)'s.
//!
//! It also does not configure the operational network (§5.5 steps 15–16). That is the one step
//! whose content is entirely device-specific — a Wi-Fi SSID, a Thread dataset — and a
//! commissioner that guessed would be guessing about somebody's house. [`Commissioner::pause`](crate::commissioning::commissioner::Commissioner::pause)
//! is where a caller does it, between the credentials and CASE.

use crate::attestation::chain::verify_dac_chain;
use crate::attestation::x509::X509Certificate;
use crate::attestation::{
    ATTESTATION_NONCE_LEN, AttestationElements, CSR_NONCE_LEN, Csr, NocsrElements,
    verify_attestation, verify_nocsr,
};
use crate::ca::{CertAuthority, Identity, Validity};
use crate::cert::CERT_TLV_MAX;
use crate::clusters::generated::{general_commissioning, operational_credentials};
use crate::crypto::{KeyStore, PublicKey, Signature, SymmetricKey};
use crate::error::{Error, ErrorCode, Result};
use crate::im::{ClusterId, CommandId, EndpointId};
use crate::msg::{NodeId, VendorId};
use crate::tlv::{ContainerKind, Tag, TlvWriter, ToTlv};

/// The `RootNode` endpoint every commissioning cluster lives on (§9.2).
pub const ROOT_ENDPOINT: EndpointId = 0;

/// §5.5 step 6: "the Commissionee SHALL autonomously arm the Fail-safe timer for a timeout of
/// 60 seconds", and step 7 gives the commissioner that long to re-arm it.
pub const AUTONOMOUS_FAIL_SAFE_SECONDS: u16 = 60;

/// The longest certificate a `CertificateChainResponse` may carry.
///
/// §11.18.6.3's constraint is "max 600" — a DER X.509 certificate, not the TLV form.
pub const DER_CERT_MAX: usize = 600;

/// How far commissioning has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stage {
    /// §5.5 step 7 — re-arm the fail-safe the device armed for itself.
    ArmFailSafe,
    /// §5.5 step 8 — regulatory information, for a device with a Wi-Fi or Thread radio.
    SetRegulatoryConfig,
    /// §5.5 step 10 — fetch the Device Attestation Certificate.
    RequestDac,
    /// ...and the Product Attestation Intermediate that issued it.
    RequestPai,
    /// Prove the device holds the DAC's private key.
    RequestAttestation,
    /// §5.5 step 11 — ask for an operational key and a CSR over it.
    RequestCsr,
    /// §5.5 step 13 — install the fabric's root.
    AddTrustedRoot,
    /// ...and the NOC under it.
    AddNoc,
    /// §5.5's setup phase steps 2–3 — the caller configures the network, discovers the node and
    /// opens a CASE session.
    Operational,
    /// §5.5 setup step 4 — the last command, and the only one that must be on CASE.
    CommissioningComplete,
    /// Nothing left.
    Done,
}

/// What the caller should do next.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Step<'a> {
    /// Invoke this command and feed the response back to
    /// [`Commissioner::on_response`].
    Invoke {
        /// The endpoint — always [`ROOT_ENDPOINT`] for the commissioning clusters.
        endpoint: EndpointId,
        /// The cluster.
        cluster: ClusterId,
        /// The command.
        command: CommandId,
        /// The encoded `CommandFields`, or empty for a command that takes none.
        fields: &'a [u8],
    },
    /// The PASE phase is finished. Configure the operational network if the device needs it,
    /// discover the node, and establish CASE — then call [`Commissioner::on_operational`].
    ///
    /// §5.5's setup phase exists as a separate phase precisely because the device may reboot
    /// onto a different network in between, and the commissioner has to find it again.
    Operational {
        /// The node id the NOC gave the device, which is what operational discovery advertises.
        node_id: NodeId,
    },
    /// Commissioning succeeded.
    Done,
}

/// What the commissioner decided about the device's attestation (§6.2.3).
///
/// §5.5 step 10 is explicit that failing it is *not* automatically fatal: "the Commissioner MAY
/// choose to either continue to the Commissioning, or terminate it, depending on
/// implementation-dependent policies", and SHOULD warn the user. So the outcome is reported and
/// the policy belongs to whoever is driving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attestation {
    /// The chain verified against a trusted PAA and the signatures held.
    Trusted,
    /// Something did not check out. `reason` is what.
    Failed(ErrorCode),
}

/// What a commissioner needs to know before it starts.
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    /// The identity the node will have.
    pub identity: Identity,
    /// §11.18.6.9's `CaseAdminSubject` — the subject that gets Administer over CASE.
    ///
    /// Usually the commissioner's own node id, and §11.18.6.9 requires it to be an operational
    /// node id or a CAT: "a CASE Authenticated Tag or an Operational Node ID". The single ACL
    /// entry `AddNOC` creates is the only way in until somebody writes more, so getting this
    /// wrong locks the fabric out of its own device.
    pub case_admin_subject: u64,
    /// §11.18.6.9's `AdminVendorId` — "a value for which the Vendor Schema in DCL contains the
    /// name and other information of the Commissioner's manufacturer" (§5.5 step 13).
    pub admin_vendor_id: VendorId,
    /// How long the fail-safe should run (§5.5 step 7).
    pub fail_safe_seconds: u16,
    /// The certificate validity to issue.
    pub validity: Validity,
    /// Whether the device needs §5.5 step 8's regulatory configuration.
    ///
    /// "If the Commissionee has at least one instance of the Network Commissioning cluster on
    /// any endpoint with either the WI ... or TH ... feature flags set" — a wired device does
    /// not, and sending it anyway wastes a round trip on a device that has none.
    pub needs_regulatory_config: bool,
    /// The regulatory location to set, when it is needed.
    pub regulatory_location: general_commissioning::RegulatoryLocationTypeEnum,
}

impl Plan {
    /// A plan for `identity`, administered over CASE by `case_admin_subject`.
    #[must_use]
    pub const fn new(
        identity: Identity,
        case_admin_subject: u64,
        admin_vendor_id: VendorId,
        validity: Validity,
    ) -> Self {
        Self {
            identity,
            case_admin_subject,
            admin_vendor_id,
            // §5.5 step 7 gives the commissioner 60 seconds to re-arm; the value it re-arms
            // *to* is its own choice, and 900 is what the CHIP SDK's controller uses — long
            // enough for a Thread join, short enough that an abandoned attempt clears within
            // a quarter of an hour.
            fail_safe_seconds: 900,
            validity,
            needs_regulatory_config: false,
            regulatory_location: general_commissioning::RegulatoryLocationTypeEnum::IndoorOutdoor,
        }
    }

    /// The same plan, sending §5.5 step 8's regulatory configuration.
    #[must_use]
    pub const fn with_regulatory_config(
        mut self,
        location: general_commissioning::RegulatoryLocationTypeEnum,
    ) -> Self {
        self.needs_regulatory_config = true;
        self.regulatory_location = location;
        self
    }

    /// The same plan with a different fail-safe duration.
    #[must_use]
    pub const fn with_fail_safe(mut self, seconds: u16) -> Self {
        self.fail_safe_seconds = seconds;
        self
    }
}

/// Drives §5.5's commissioning sequence.
///
/// Sans-I/O: [`Commissioner::step`] says what to send and [`Commissioner::on_response`] takes
/// what came back. The buffers are the commissioner's, so nothing here allocates.
#[derive(Debug)]
pub struct Commissioner {
    stage: Stage,
    plan: Plan,
    /// The PASE session's `AttestationChallenge` — §11.18.4.7 and §11.18.6.5 both sign over it,
    /// which is what binds an attestation to *this* session rather than a recording of another.
    challenge: SymmetricKey,
    attestation_nonce: [u8; ATTESTATION_NONCE_LEN],
    csr_nonce: [u8; CSR_NONCE_LEN],
    dac: heapless::Vec<u8, DER_CERT_MAX>,
    pai: heapless::Vec<u8, DER_CERT_MAX>,
    /// The operational public key the device generated for its CSR.
    operational_key: Option<PublicKey>,
    attestation: Option<Attestation>,
    /// Scratch for the command being sent.
    fields: heapless::Vec<u8, 1024>,
}

impl Commissioner {
    /// A commissioner about to run §5.5's initial phase over an established PASE session.
    ///
    /// `challenge` is that session's `AttestationChallenge` (§4.14.2.6.2) — the third key it
    /// derived. `attestation_nonce` and `csr_nonce` are 32 octets each from the caller's own
    /// [`Rng`](crate::platform::Rng): §11.18.6.1 and §11.18.6.5 make the device echo them back
    /// inside the signed structure, which is what stops a recorded response being replayed.
    #[must_use]
    pub fn new(
        plan: Plan,
        challenge: SymmetricKey,
        attestation_nonce: [u8; ATTESTATION_NONCE_LEN],
        csr_nonce: [u8; CSR_NONCE_LEN],
    ) -> Self {
        Self {
            stage: Stage::ArmFailSafe,
            plan,
            challenge,
            attestation_nonce,
            csr_nonce,
            dac: heapless::Vec::new(),
            pai: heapless::Vec::new(),
            operational_key: None,
            attestation: None,
            fields: heapless::Vec::new(),
        }
    }

    /// How far it has got.
    #[must_use]
    pub const fn stage(&self) -> Stage {
        self.stage
    }

    /// What the device's attestation turned out to be, once it has been checked.
    #[must_use]
    pub const fn attestation(&self) -> Option<Attestation> {
        self.attestation
    }

    /// The operational public key the device generated, once the CSR has arrived.
    #[must_use]
    pub const fn operational_key(&self) -> Option<PublicKey> {
        self.operational_key
    }

    /// The node this commissioner is creating.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.plan.identity.node_id
    }

    /// The next thing to do.
    ///
    /// Borrows `self` mutably because the encoded command lives in the commissioner's own
    /// buffer — a caller that wanted two outstanding at once would be running two
    /// commissionings, which §5.5's fail-safe does not permit anyway.
    pub fn step(&mut self) -> Result<Step<'_>> {
        use operational_credentials::command as opcreds;
        match self.stage {
            Stage::ArmFailSafe => {
                self.encode(&general_commissioning::ArmFailSafeFields {
                    expiry_length_seconds: self.plan.fail_safe_seconds,
                    // §11.10.7.2's breadcrumb is the commissioner's own progress marker; it
                    // starts at zero and the caller may read it back after a resumed attempt.
                    breadcrumb: 0,
                })?;
                Ok(self.invoke(
                    general_commissioning::ID,
                    general_commissioning::command::ARM_FAIL_SAFE,
                ))
            }
            Stage::SetRegulatoryConfig => {
                self.encode(&general_commissioning::SetRegulatoryConfigFields {
                    new_regulatory_config: self.plan.regulatory_location,
                    // §11.10.7.4's `CountryCode` is "the 2-character country code"; XX is
                    // ISO 3166-1's user-assigned "unknown", which is what a commissioner with
                    // no location knowledge should send rather than inventing a jurisdiction.
                    country_code: "XX",
                    breadcrumb: 0,
                })?;
                Ok(self.invoke(
                    general_commissioning::ID,
                    general_commissioning::command::SET_REGULATORY_CONFIG,
                ))
            }
            Stage::RequestDac => {
                self.encode(&operational_credentials::CertificateChainRequestFields {
                    certificate_type:
                        operational_credentials::CertificateChainTypeEnum::DACCertificate,
                })?;
                Ok(self.invoke(
                    operational_credentials::ID,
                    opcreds::CERTIFICATE_CHAIN_REQUEST,
                ))
            }
            Stage::RequestPai => {
                self.encode(&operational_credentials::CertificateChainRequestFields {
                    certificate_type:
                        operational_credentials::CertificateChainTypeEnum::PAICertificate,
                })?;
                Ok(self.invoke(
                    operational_credentials::ID,
                    opcreds::CERTIFICATE_CHAIN_REQUEST,
                ))
            }
            Stage::RequestAttestation => {
                let nonce = self.attestation_nonce;
                self.encode(&operational_credentials::AttestationRequestFields {
                    attestation_nonce: &nonce,
                })?;
                Ok(self.invoke(operational_credentials::ID, opcreds::ATTESTATION_REQUEST))
            }
            Stage::RequestCsr => {
                let nonce = self.csr_nonce;
                self.encode(&operational_credentials::CSRRequestFields {
                    csr_nonce: &nonce,
                    // §11.18.6.5: absent or false means a *new* fabric. `UpdateNOC`'s form is
                    // a different flow entirely.
                    is_for_update_noc: Some(false),
                })?;
                Ok(self.invoke(operational_credentials::ID, opcreds::CSR_REQUEST))
            }
            Stage::AddTrustedRoot | Stage::AddNoc => {
                // Both need the CA, which `step` has no access to. `add_root` and `add_noc`
                // take it; reaching here means the caller skipped them.
                Err(Error::new(ErrorCode::InvalidState))
            }
            Stage::Operational => Ok(Step::Operational {
                node_id: self.plan.identity.node_id,
            }),
            Stage::CommissioningComplete => {
                self.fields.clear();
                Ok(self.invoke(
                    general_commissioning::ID,
                    general_commissioning::command::COMMISSIONING_COMPLETE,
                ))
            }
            Stage::Done => Ok(Step::Done),
        }
    }

    /// §5.5 step 13's `AddTrustedRootCertificate`, with the fabric's own root.
    ///
    /// Separate from [`Commissioner::step`] because it needs the CA, and the CA holds a key
    /// handle into a store this type deliberately does not own.
    pub fn add_root<K: KeyStore>(&mut self, ca: &CertAuthority, keys: &K) -> Result<Step<'_>> {
        if self.stage != Stage::AddTrustedRoot {
            return Err(Error::new(ErrorCode::InvalidState));
        }
        let mut root = [0u8; CERT_TLV_MAX];
        let root = ca.self_signed_root(keys, &mut root, self.plan.validity)?;
        self.encode(&operational_credentials::AddTrustedRootCertificateFields {
            root_ca_certificate: root,
        })?;
        Ok(self.invoke(
            operational_credentials::ID,
            operational_credentials::command::ADD_TRUSTED_ROOT_CERTIFICATE,
        ))
    }

    /// §5.5 step 13's `AddNOC`, with a certificate issued for the key the device generated.
    ///
    /// `icac` is the intermediate to send alongside, when the deployment uses one; §6.4.5.1
    /// permits a NOC issued straight by the root.
    pub fn add_noc<K: KeyStore>(
        &mut self,
        ca: &CertAuthority,
        keys: &K,
        icac: Option<&[u8]>,
    ) -> Result<Step<'_>> {
        if self.stage != Stage::AddNoc {
            return Err(Error::new(ErrorCode::InvalidState));
        }
        let public_key = self
            .operational_key
            .ok_or_else(|| Error::new(ErrorCode::InvalidState))?;
        let mut noc = [0u8; CERT_TLV_MAX];
        let noc = ca.issue_noc(
            keys,
            &mut noc,
            &self.plan.identity,
            &public_key,
            self.plan.validity,
        )?;
        // §11.18.6.9's `IPKValue` is the fabric's Identity Protection Key — the epoch key that
        // makes operational discovery unlinkable and group messages authenticable. It is
        // derived from the CA's own signature over the fabric id, so every administrator on the
        // fabric computes the same one without ever sending it in the clear.
        let ipk = self.ipk(ca, keys)?;
        self.encode(&operational_credentials::AddNOCFields {
            noc_value: noc,
            icac_value: icac,
            ipk_value: &ipk,
            case_admin_subject: self.plan.case_admin_subject,
            admin_vendor_id: self.plan.admin_vendor_id,
        })?;
        Ok(self.invoke(
            operational_credentials::ID,
            operational_credentials::command::ADD_NOC,
        ))
    }

    /// The fabric's Identity Protection Key (§4.15.2, §11.18.6.9).
    ///
    /// Derived rather than random so that every administrator on the fabric arrives at the same
    /// value from the root key alone. A random IPK would have to be *transported* between
    /// administrators, and §4.15.2's whole point is that it is a shared secret nobody needs to
    /// send.
    fn ipk<K: KeyStore>(&self, ca: &CertAuthority, keys: &K) -> Result<[u8; 16]> {
        let mut material = [0u8; 8];
        material.copy_from_slice(&self.plan.identity.fabric_id.0.to_be_bytes());
        let signature = keys.sign(ca.key(), &material)?;
        let digest = crate::crypto::hash(signature.as_bytes());
        let mut ipk = [0u8; 16];
        let head = digest
            .get(..16)
            .ok_or_else(|| Error::new(ErrorCode::InvalidState))?;
        ipk.copy_from_slice(head);
        Ok(ipk)
    }

    /// Takes the response to the command [`Commissioner::step`] handed out.
    ///
    /// `fields` is the response command's `CommandFields`, or `None` for a command whose
    /// response is a bare status — which is `AddTrustedRootCertificate` and nothing else in
    /// this flow (§11.18.6.13 defines no response command for it).
    pub fn on_response(&mut self, fields: Option<&[u8]>) -> Result<()> {
        match self.stage {
            Stage::ArmFailSafe => {
                self.check_commissioning_error(fields)?;
                self.stage = if self.plan.needs_regulatory_config {
                    Stage::SetRegulatoryConfig
                } else {
                    Stage::RequestDac
                };
            }
            Stage::SetRegulatoryConfig => {
                self.check_commissioning_error(fields)?;
                self.stage = Stage::RequestDac;
            }
            Stage::RequestDac => {
                let certificate = Self::certificate(fields)?;
                self.dac = heapless::Vec::from_slice(certificate)
                    .map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
                self.stage = Stage::RequestPai;
            }
            Stage::RequestPai => {
                let certificate = Self::certificate(fields)?;
                self.pai = heapless::Vec::from_slice(certificate)
                    .map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
                self.stage = Stage::RequestAttestation;
            }
            Stage::RequestAttestation => {
                self.check_attestation(fields)?;
                self.stage = Stage::RequestCsr;
            }
            Stage::RequestCsr => {
                self.check_csr(fields)?;
                self.stage = Stage::AddTrustedRoot;
            }
            Stage::AddTrustedRoot => {
                // §11.18.6.13 defines no response command for `AddTrustedRootCertificate`: it
                // answers with a bare `SUCCESS`, and the caller reports that by passing `None`.
                // A commissioner that expected a `NOCResponse` here would fail on a conformant
                // device — which is exactly what the end-to-end test caught.
                if fields.is_some_and(|fields| !fields.is_empty()) {
                    return Err(Error::new(ErrorCode::InvalidState));
                }
                self.stage = Stage::AddNoc;
            }
            Stage::AddNoc => {
                Self::check_noc_status(fields)?;
                self.stage = Stage::Operational;
            }
            Stage::Operational => return Err(Error::new(ErrorCode::InvalidState)),
            Stage::CommissioningComplete => {
                self.check_commissioning_error(fields)?;
                self.stage = Stage::Done;
            }
            Stage::Done => return Err(Error::new(ErrorCode::InvalidState)),
        }
        Ok(())
    }

    /// The caller has configured the network, found the node and established CASE.
    ///
    /// §5.5's setup phase step 4: `CommissioningComplete` "SHALL be invoked over a CASE
    /// session", and §11.10.7.6 makes the device refuse it over PASE — which is what proves the
    /// credentials just installed actually work before the fail-safe is allowed to lapse.
    pub fn on_operational(&mut self) -> Result<()> {
        if self.stage != Stage::Operational {
            return Err(Error::new(ErrorCode::InvalidState));
        }
        self.stage = Stage::CommissioningComplete;
        Ok(())
    }

    /// Whether the caller may do its own work here — §5.5 steps 14–16.
    ///
    /// True at [`Stage::Operational`], which sits between the credentials being installed and
    /// CASE being established: the ACL, the Wi-Fi credentials and the Thread dataset all go in
    /// this window, and all of them are the caller's because none of them is derivable.
    #[must_use]
    pub const fn pause(&self) -> bool {
        matches!(self.stage, Stage::Operational)
    }

    /// Encodes a command's fields into the commissioner's buffer.
    fn encode<T: ToTlv>(&mut self, fields: &T) -> Result<()> {
        let mut buf = [0u8; 1024];
        let mut writer = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
        fields.to_tlv(&mut writer, Tag::Context(1))?;
        let encoded = writer.finish()?;
        self.fields = heapless::Vec::from_slice(encoded)
            .map_err(|_| Error::new(ErrorCode::BufferTooSmall))?;
        Ok(())
    }

    fn invoke(&self, cluster: ClusterId, command: CommandId) -> Step<'_> {
        Step::Invoke {
            endpoint: ROOT_ENDPOINT,
            cluster,
            command,
            fields: &self.fields,
        }
    }

    /// §11.10.7.3, §11.10.7.5 and §11.10.7.7 all answer with the same shape.
    fn check_commissioning_error(&self, fields: Option<&[u8]>) -> Result<()> {
        let decoded: general_commissioning::ArmFailSafeResponseFields<'_> =
            decode(fields.ok_or_else(|| Error::new(ErrorCode::InvalidState))?)?;
        if decoded.error_code != general_commissioning::CommissioningErrorEnum::OK {
            return Err(Error::new(ErrorCode::CommissioningFailed));
        }
        Ok(())
    }

    /// §11.18.6.10's `NOCResponse`.
    fn check_noc_status(fields: Option<&[u8]>) -> Result<()> {
        let decoded: operational_credentials::NOCResponseFields<'_> =
            decode(fields.ok_or_else(|| Error::new(ErrorCode::InvalidState))?)?;
        if decoded.status_code != operational_credentials::NodeOperationalCertStatusEnum::OK {
            return Err(Error::new(ErrorCode::CommissioningFailed));
        }
        Ok(())
    }

    fn certificate(fields: Option<&[u8]>) -> Result<&[u8]> {
        let decoded: operational_credentials::CertificateChainResponseFields<'_> =
            decode(fields.ok_or_else(|| Error::new(ErrorCode::InvalidState))?)?;
        Ok(decoded.certificate)
    }

    /// §6.2.3's Device Attestation Procedure, as far as a commissioner with no DCL can run it.
    ///
    /// The PAA is the one thing that cannot come from the device — §6.2.3 requires it from the
    /// commissioner's own trust store — so [`Commissioner::verify_attestation_against`] takes it
    /// and this records what happened. §5.5 step 10 makes the *decision* the caller's: a failure
    /// here is reported, not fatal, because a development device with an uncertified PAA is a
    /// case the specification explicitly wants to be commissionable with a warning.
    fn check_attestation(&mut self, fields: Option<&[u8]>) -> Result<()> {
        let decoded: operational_credentials::AttestationResponseFields<'_> =
            decode(fields.ok_or_else(|| Error::new(ErrorCode::InvalidState))?)?;
        let signature = Signature::from_slice(decoded.attestation_signature)?;
        let outcome = (|| -> Result<()> {
            let dac = X509Certificate::parse(&self.dac)?;
            // §11.18.6.2: the signature is over the elements *and* the session's challenge, so
            // a recording from another session does not verify here.
            if !verify_attestation(
                &dac.public_key,
                decoded.attestation_elements,
                &self.challenge,
                &signature,
            )? {
                return Err(Error::new(ErrorCode::AttestationFailed));
            }
            // §11.18.6.1: "the Commissioner SHALL verify that the AttestationNonce ... matches
            // the one it sent". Without this a device could replay any prior attestation.
            let elements = AttestationElements::decode(decoded.attestation_elements)?;
            if elements.attestation_nonce != self.attestation_nonce {
                return Err(Error::new(ErrorCode::AttestationFailed));
            }
            Ok(())
        })();
        self.attestation = Some(match outcome {
            Ok(()) => Attestation::Trusted,
            Err(error) => Attestation::Failed(error.code()),
        });
        Ok(())
    }

    /// Completes §6.2.3 with a PAA from the commissioner's trust store.
    ///
    /// Call this after [`Stage::RequestAttestation`] and before deciding whether to go on.
    /// §6.2.3's chain check needs a root the *commissioner* trusts, which is the whole point:
    /// a device that supplied its own would be attesting to itself.
    pub fn verify_attestation_against(&mut self, paa_der: &[u8]) -> Result<Attestation> {
        let outcome = (|| -> Result<()> {
            let dac = X509Certificate::parse(&self.dac)?;
            let pai = X509Certificate::parse(&self.pai)?;
            let paa = X509Certificate::parse(paa_der)?;
            verify_dac_chain(&dac, &pai, &paa)?;
            Ok(())
        })();
        let result = match (self.attestation, outcome) {
            // A chain that verifies does not rescue a signature that did not.
            (Some(Attestation::Failed(reason)), _) => Attestation::Failed(reason),
            (_, Err(error)) => Attestation::Failed(error.code()),
            (_, Ok(())) => Attestation::Trusted,
        };
        self.attestation = Some(result);
        Ok(result)
    }

    /// §11.18.6.6's `CSRResponse`.
    fn check_csr(&mut self, fields: Option<&[u8]>) -> Result<()> {
        let decoded: operational_credentials::CSRResponseFields<'_> =
            decode(fields.ok_or_else(|| Error::new(ErrorCode::InvalidState))?)?;
        let signature = Signature::from_slice(decoded.attestation_signature)?;
        let dac = X509Certificate::parse(&self.dac)?;
        // §11.18.6.6: the NOCSR is signed by the *DAC* key, not the new operational key — which
        // is what ties the freshly generated operational key to the device attestation already
        // performed. Verifying it against the operational key inside would be circular.
        if !verify_nocsr(
            &dac.public_key,
            decoded.nocsr_elements,
            &self.challenge,
            &signature,
        )? {
            return Err(Error::new(ErrorCode::AttestationFailed));
        }
        let elements = NocsrElements::decode(decoded.nocsr_elements)?;
        // §11.18.6.6: "the Commissioner SHALL verify that the CSRNonce ... matches". Same replay
        // argument as the attestation nonce, and it matters more here: a replayed CSR would put
        // a *previous* device's key into this device's certificate.
        if elements.csr_nonce != self.csr_nonce {
            return Err(Error::new(ErrorCode::AttestationFailed));
        }
        let csr = Csr::parse(elements.csr)?;
        // The CSR is self-signed by the operational key: PKCS#10's proof of possession, and
        // without it a device could hand over somebody else's public key.
        if !crate::crypto::verify(&csr.public_key, csr.tbs, &csr.signature)? {
            return Err(Error::new(ErrorCode::AttestationFailed));
        }
        self.operational_key = Some(csr.public_key);
        Ok(())
    }
}

/// Decodes a response command's `CommandFields`.
fn decode<'a, T: crate::tlv::FromTlv<'a>>(fields: &'a [u8]) -> Result<T> {
    let mut reader = crate::tlv::TlvReader::new_in(fields, ContainerKind::Structure);
    let element = reader
        .next_element()?
        .ok_or_else(|| Error::new(ErrorCode::TlvTruncated))?;
    T::from_tlv(&mut reader, &element)
}
