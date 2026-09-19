//! OTA Software Update Requestor, cluster `0x002A` (Core §11.20.7).
//!
//! The other half of [`ota_provider`](super::ota_provider): this is the cluster on the device
//! *being* updated. It holds where to ask ([`DEFAULT_OTA_PROVIDERS`]), says how far along an
//! update is ([`UPDATE_STATE`], [`UPDATE_STATE_PROGRESS`]), and reports what happened through
//! §11.20.7.7's three events.
//!
//! The download itself is [`bdx`](crate::bdx). A requestor asks a provider for an image, gets a
//! `bdx:` URI back ([`ImageUri`](super::ota_provider::ImageUri)), and opens a BDX transfer as
//! the Initiator and Receiver. What lives here is the *state* of that, because a controller
//! subscribing to `UpdateState` is how a user watches an update they cannot see.
//!
//! # One provider per fabric, and an announcement is not a provider
//!
//! §11.20.7.5: "There SHALL NOT be more than one entry per Fabric. On a list update that would
//! introduce more than one entry per fabric, the write SHALL fail with CONSTRAINT_ERROR status
//! code." Each fabric's administrator names its own provider, and the device asks each of them.
//!
//! The rule that is easy to get wrong is the one next to it:
//!
//! > Provider Locations obtained using the AnnounceOTAProvider command SHALL NOT overwrite
//! > values set in the DefaultOTAProviders attribute.
//!
//! An announcement is a hint to query *sooner*, from a provider that announced itself. It is
//! not a configuration change, and a device that let one rewrite the list would let any
//! administrator on the fabric redirect every later update — including after its own access was
//! removed. [`Announcement`] is handed to the application and the list is left alone.
//!
//! # The state machine is the product's, and the event is this cluster's
//!
//! §11.20.7.4.2's nine states are the shape of an OTA: `Idle`, `Querying`, `DelayedOnQuery`,
//! `Downloading`, `Applying`, and the rest. Which one the device is in is the application's to
//! say — [`OtaRequestor::transition`] is how it says so, and the `StateTransition` event, the
//! `TargetSoftwareVersion` rule and the progress reset all follow from it rather than having to
//! be remembered at nine call sites.

use core::cell::{Cell, RefCell};

use crate::clusters::generated::ota_software_update_requestor as spec_requestor;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::error::Result;
use crate::im::{
    ClusterHandler, ClusterId, CommandId, EndpointId, InteractionContext, Status, StatusIb, WriteOp,
};
use crate::msg::{FabricIndex, NodeId, VendorId};
use crate::tlv::{ContainerKind, FromTlv, Tag, TlvReader, TlvWriter, ToTlv, Value};

use super::Cluster;

pub use spec_requestor::attribute::{
    DEFAULT_OTA_PROVIDERS, UPDATE_POSSIBLE, UPDATE_STATE, UPDATE_STATE_PROGRESS,
};
pub use spec_requestor::command::ANNOUNCE_OTA_PROVIDER;
pub use spec_requestor::event::{DOWNLOAD_ERROR, STATE_TRANSITION, VERSION_APPLIED};
pub use spec_requestor::{
    AnnouncementReasonEnum, ChangeReasonEnum, ID, PICS, ProviderLocation, REVISION, UpdateStateEnum,
};

/// §11.20.7.6.1's constraint on `MetadataForNode`: "max 512".
pub const METADATA_MAX: usize = 512;

/// §11.20.7.5's constraint on `UpdateStateProgress`: "0 to 100".
pub const PROGRESS_MAX: u8 = 100;

/// How many events are held before the oldest is dropped.
pub const EVENT_QUEUE: usize = 8;

/// An `AnnounceOTAProvider` that arrived (§11.20.7.6.1).
///
/// Everything the command carried, including the metadata — which borrows the invoke's own
/// payload, and so is readable exactly while the application is being told about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announcement<'a> {
    /// The fabric the announcement came in on, which is the only one it applies to.
    pub fabric_index: FabricIndex,
    /// The node to query, "on the accessing fabric".
    pub provider_node_id: NodeId,
    /// "the endpoint number which has the OTA Provider device type and OTA Software Update
    /// Provider cluster server on the ProviderNodeID".
    pub endpoint: EndpointId,
    /// "the assigned Vendor ID of the Node invoking this command".
    pub vendor_id: VendorId,
    /// Why the provider is speaking up, and so how soon to act.
    pub reason: AnnouncementReasonEnum,
    /// "a manufacturer-specific payload, which the Node invoking this command wants to expose
    /// to the receiving Node".
    pub metadata: Option<&'a [u8]>,
}

impl Announcement<'_> {
    /// Where this announcement says to look, as a [`ProviderLocation`].
    ///
    /// Note what this is *not* for: §11.20.7.5 says an announcement "SHALL NOT overwrite values
    /// set in the DefaultOTAProviders attribute", so this is somewhere to query now, not
    /// somewhere to store.
    #[must_use]
    pub const fn location(&self) -> ProviderLocation {
        ProviderLocation {
            provider_node_id: self.provider_node_id,
            endpoint: self.endpoint,
            fabric_index: self.fabric_index,
        }
    }

    /// Whether §11.20.7.4.1 says to query now rather than at the next scheduled time.
    ///
    /// `UrgentUpdateAvailable` is "an important security update, or just after initial
    /// commissioning of a device"; the requestor "SHOULD query … after a random jitter delay
    /// between 1 and 600 seconds", which is the application's to schedule.
    #[must_use]
    pub const fn is_urgent(&self) -> bool {
        matches!(self.reason, AnnouncementReasonEnum::UrgentUpdateAvailable)
    }
}

/// What the product does with an announcement.
pub trait OtaRequestorHooks {
    /// An `AnnounceOTAProvider` arrived (§11.20.7.6.1).
    ///
    /// > The receiving Node MAY ignore the content of the announcement if it is unable or
    /// > unwilling to further query OTA Providers temporarily, or if its provider list is full.
    /// > If the announcement is ignored, the response SHOULD be SUCCESS.
    ///
    /// So this returns nothing: there is no way to refuse, only to do nothing.
    fn announced(&self, announcement: &Announcement<'_>) {
        let _ = announcement;
    }
}

/// A requestor that ignores announcements, which §11.20.7.6.1 explicitly permits.
impl OtaRequestorHooks for () {}

/// One of §11.20.7.7's three events, waiting to be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// `StateTransition` (§11.20.7.7.1), INFO — the `UpdateState` attribute changed.
    StateTransition {
        /// The state that preceded the transition, or `Unknown` if there was none.
        previous: UpdateStateEnum,
        /// The state now in effect.
        new_state: UpdateStateEnum,
        /// Why it changed.
        reason: ChangeReasonEnum,
        /// The version being worked on — non-null only while `Downloading`, `Applying` or
        /// `RollingBack`.
        target_software_version: Option<u32>,
    },
    /// `VersionApplied` (§11.20.7.7.2), CRITICAL — a new version is running.
    VersionApplied {
        /// "the same value as the one available in the SoftwareVersion attribute of the Basic
        /// Information Cluster for the newly executing version".
        software_version: u32,
        /// "the ProductID applying to the executing version".
        product_id: u16,
    },
    /// `DownloadError` (§11.20.7.7.3), INFO — a download failed.
    DownloadError {
        /// The version that was being downloaded.
        software_version: u32,
        /// How far the failed transfer got.
        bytes_downloaded: u64,
        /// "the nearest integer percent value" — null when the total length is unknown.
        progress_percent: Option<u8>,
        /// "some internal product-specific error code", or null.
        platform_code: Option<i64>,
    },
}

impl Event {
    /// The event id this record carries (§11.20.7.7).
    #[must_use]
    pub const fn id(&self) -> crate::im::EventId {
        match self {
            Self::StateTransition { .. } => STATE_TRANSITION,
            Self::VersionApplied { .. } => VERSION_APPLIED,
            Self::DownloadError { .. } => DOWNLOAD_ERROR,
        }
    }
}

impl ToTlv for Event {
    fn to_tlv(&self, w: &mut TlvWriter<'_>, tag: Tag) -> Result<()> {
        w.start_structure(tag)?;
        match *self {
            Self::StateTransition {
                previous,
                new_state,
                reason,
                target_software_version,
            } => {
                w.unsigned(Tag::Context(0), u64::from(previous.value()))?;
                w.unsigned(Tag::Context(1), u64::from(new_state.value()))?;
                w.unsigned(Tag::Context(2), u64::from(reason.value()))?;
                match target_software_version {
                    Some(version) => w.unsigned(Tag::Context(3), u64::from(version))?,
                    None => w.null(Tag::Context(3))?,
                }
            }
            Self::VersionApplied {
                software_version,
                product_id,
            } => {
                w.unsigned(Tag::Context(0), u64::from(software_version))?;
                w.unsigned(Tag::Context(1), u64::from(product_id))?;
            }
            Self::DownloadError {
                software_version,
                bytes_downloaded,
                progress_percent,
                platform_code,
            } => {
                w.unsigned(Tag::Context(0), u64::from(software_version))?;
                w.unsigned(Tag::Context(1), bytes_downloaded)?;
                match progress_percent {
                    Some(percent) => w.unsigned(Tag::Context(2), u64::from(percent))?,
                    None => w.null(Tag::Context(2))?,
                }
                match platform_code {
                    Some(code) => w.signed(Tag::Context(3), code)?,
                    None => w.null(Tag::Context(3))?,
                }
            }
        }
        w.end_container()
    }
}

/// The OTA Software Update Requestor cluster (§11.20.7).
///
/// `N` is how many provider locations the node can hold at once, which §11.20.7.5 makes one per
/// fabric — so a node that wants a provider for every fabric it supports sizes this at
/// [`Config::FABRICS`](crate::Config::FABRICS).
#[derive(Debug)]
pub struct OtaRequestor<'a, H: OtaRequestorHooks, const N: usize> {
    hooks: &'a H,
    providers: RefCell<heapless::Vec<ProviderLocation, N>>,
    possible: Cell<bool>,
    state: Cell<UpdateStateEnum>,
    progress: Cell<Option<u8>>,
    events: RefCell<heapless::Vec<Event, EVENT_QUEUE>>,
}

impl<'a, H: OtaRequestorHooks, const N: usize> OtaRequestor<'a, H, N> {
    /// A requestor with no providers configured, in §11.20.7.5's fallback state: an empty list
    /// and `UpdatePossible` true.
    ///
    /// The initial `UpdateState` is `Unknown`, which §11.20.7.4.2 defines as "the current state
    /// is not yet determined" — true of a device that has just booted and not yet decided
    /// whether it is idle or rolling back.
    #[must_use]
    pub const fn new(hooks: &'a H) -> Self {
        Self {
            hooks,
            providers: RefCell::new(heapless::Vec::new()),
            possible: Cell::new(true),
            state: Cell::new(UpdateStateEnum::Unknown),
            progress: Cell::new(None),
            events: RefCell::new(heapless::Vec::new()),
        }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    pub fn conforming(feature_map: u32, optional: &Optional<'_>) -> Result<Conforming<4, 1, 0, 3>> {
        Conforming::new(&spec_requestor::CLUSTER, feature_map, optional)
    }

    /// Every configured provider, for a device about to persist them (`N` is non-volatile).
    #[must_use]
    pub fn providers(&self) -> core::cell::Ref<'_, heapless::Vec<ProviderLocation, N>> {
        self.providers.borrow()
    }

    /// The provider configured for one fabric, if any.
    #[must_use]
    pub fn provider_for(&self, fabric: FabricIndex) -> Option<ProviderLocation> {
        self.providers
            .borrow()
            .iter()
            .find(|p| p.fabric_index == fabric)
            .copied()
    }

    /// Sets one fabric's provider, replacing whatever it had.
    ///
    /// §11.20.7.5 allows exactly one entry per fabric, so this replaces rather than appends —
    /// there is no list to append to.
    pub fn set_provider(&self, provider: ProviderLocation) -> core::result::Result<(), Status> {
        if provider.fabric_index.0 == 0 {
            return Err(Status::UnsupportedAccess);
        }
        let mut providers = self.providers.borrow_mut();
        if let Some(slot) = providers
            .iter_mut()
            .find(|p| p.fabric_index == provider.fabric_index)
        {
            *slot = provider;
            return Ok(());
        }
        providers
            .push(provider)
            .map_err(|_| Status::ResourceExhausted)
    }

    /// Forgets a fabric's provider — what `RemoveFabric` must do.
    pub fn remove_fabric(&self, fabric: FabricIndex) {
        self.providers
            .borrow_mut()
            .retain(|p| p.fabric_index != fabric);
    }

    /// `UpdatePossible` (§11.20.7.5).
    #[must_use]
    pub fn update_possible(&self) -> bool {
        self.possible.get()
    }

    /// Says whether the device could take an update right now.
    ///
    /// > This field is merely informational for diagnostics purposes and SHALL NOT affect the
    /// > responses provided by an OTA Provider to an OTA Requestor.
    ///
    /// So a device with a flat battery still asks, and still gets an answer; this is how a
    /// controller finds out why nothing happened.
    pub fn set_update_possible(&self, possible: bool) {
        self.possible.set(possible);
    }

    /// `UpdateState` (§11.20.7.5).
    #[must_use]
    pub fn state(&self) -> UpdateStateEnum {
        self.state.get()
    }

    /// `UpdateStateProgress` (§11.20.7.5), null when progress does not apply.
    #[must_use]
    pub fn progress(&self) -> Option<u8> {
        self.progress.get()
    }

    /// Moves to a new state, recording §11.20.7.7.1's `StateTransition` event.
    ///
    /// Three rules land here rather than at every call site:
    ///
    /// * The event is generated "when a change of the UpdateState attribute occurs" — so a
    ///   transition to the state already in effect records nothing.
    /// * `TargetSoftwareVersion` is set "whenever the NewState is Downloading, Applying or
    ///   RollingBack. Otherwise TargetSoftwareVersion SHALL be null" — a version passed for any
    ///   other state is dropped, not reported.
    /// * `UpdateStateProgress` "SHALL be null if a progress indication does not apply to the
    ///   current state", and after a transition nothing has been reported about the new one.
    pub fn transition(
        &self,
        new_state: UpdateStateEnum,
        reason: ChangeReasonEnum,
        target_software_version: Option<u32>,
    ) {
        let previous = self.state.get();
        if previous == new_state {
            return;
        }
        self.state.set(new_state);
        self.progress.set(None);
        self.push(Event::StateTransition {
            previous,
            new_state,
            reason,
            target_software_version: target_software_version
                .filter(|_| Self::has_target(new_state)),
        });
    }

    /// Reports progress within the current state (§11.20.7.5).
    ///
    /// "A value of 0 SHALL indicate that the beginning has occurred. A value of 100 SHALL
    /// indicate completion." Anything past 100 is outside the attribute's constraint, and
    /// [`Status::ConstraintError`] is what a write of it would earn.
    pub fn set_progress(&self, percent: Option<u8>) -> core::result::Result<(), Status> {
        if percent.is_some_and(|p| p > PROGRESS_MAX) {
            return Err(Status::ConstraintError);
        }
        self.progress.set(percent);
        Ok(())
    }

    /// Records §11.20.7.7.2's `VersionApplied`.
    ///
    /// > This event SHOULD be generated even if a software update was done using means outside
    /// > of this cluster.
    pub fn version_applied(&self, software_version: u32, product_id: u16) {
        self.push(Event::VersionApplied {
            software_version,
            product_id,
        });
    }

    /// Records §11.20.7.7.3's `DownloadError`, working out `ProgressPercent` from the transfer.
    ///
    /// `total` is the size of the transfer, when it was known — a BDX transfer with a definite
    /// length ([`Parameters::length`](crate::bdx::Parameters::length)) has one, and an
    /// indefinite one does not. "unless the total length of the transfer is unknown, in which
    /// case it SHALL be null."
    pub fn download_error(
        &self,
        software_version: u32,
        bytes_downloaded: u64,
        total: Option<u64>,
        platform_code: Option<i64>,
    ) {
        self.push(Event::DownloadError {
            software_version,
            bytes_downloaded,
            progress_percent: Self::percent(bytes_downloaded, total),
            platform_code,
        });
    }

    /// Takes the recorded events, for a device that turns them into §7.14 event records.
    pub fn take_events(&self) -> heapless::Vec<Event, EVENT_QUEUE> {
        core::mem::take(&mut self.events.borrow_mut())
    }

    /// "the nearest integer percent value reflecting how far within the transfer the failure
    /// occurred", or null when there is nothing to be a percentage of.
    fn percent(done: u64, total: Option<u64>) -> Option<u8> {
        let total = total.filter(|t| *t != 0)?;
        let scaled = done
            .checked_mul(200)?
            .checked_add(total)?
            .checked_div(total.checked_mul(2)?)?;
        u8::try_from(scaled.min(u64::from(PROGRESS_MAX))).ok()
    }

    /// §11.20.7.7.1: the three states a target version belongs to.
    const fn has_target(state: UpdateStateEnum) -> bool {
        matches!(
            state,
            UpdateStateEnum::Downloading | UpdateStateEnum::Applying | UpdateStateEnum::RollingBack
        )
    }

    fn push(&self, event: Event) {
        let mut events = self.events.borrow_mut();
        if events.is_full() {
            events.remove(0);
        }
        let _ = events.push(event);
    }

    /// Whether a fabric's entry belongs in this read (§7.19.1.8.2).
    fn visible(ctx: &InteractionContext<'_>, index: FabricIndex) -> bool {
        !ctx.fabric_filtered || ctx.fabric_index == Some(index)
    }
}

impl<H: OtaRequestorHooks, const N: usize> ClusterHandler for OtaRequestor<'_, H, N> {
    /// §11.20.7.5: `DefaultOTAProviders` is fabric-scoped, so a removed fabric's provider
    /// goes with it — otherwise this node would still ask it for firmware.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        if let crate::im::Lifecycle::FabricRemoved(fabric) = event {
            self.remove_fabric(fabric);
        }
    }
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> core::result::Result<(), Status> {
        let full = |r: Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            DEFAULT_OTA_PROVIDERS => {
                let providers = self.providers.borrow();
                full(w.start_array(tag))?;
                for provider in providers
                    .iter()
                    .filter(|p| Self::visible(ctx, p.fabric_index))
                {
                    full(provider.to_tlv(w, Tag::Anonymous))?;
                }
                full(w.end_container())
            }
            UPDATE_POSSIBLE => full(w.bool(tag, self.possible.get())),
            UPDATE_STATE => full(w.unsigned(tag, u64::from(self.state.get().value()))),
            UPDATE_STATE_PROGRESS => match self.progress.get() {
                Some(percent) => full(w.unsigned(tag, u64::from(percent))),
                None => full(w.null(tag)),
            },
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        op: WriteOp,
        ctx: &InteractionContext<'_>,
    ) -> core::result::Result<(), Status> {
        if resolved.attribute != DEFAULT_OTA_PROVIDERS {
            return Err(Status::UnsupportedWrite);
        }
        // §7.19.1.8.1: a fabric-scoped list needs an accessing fabric to scope the write to.
        let Some(fabric_index) = ctx.fabric_index else {
            return Err(Status::UnsupportedAccess);
        };

        let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;

        match op {
            WriteOp::Replace => {
                if element.value.container() != Some(ContainerKind::Array) {
                    return Err(Status::InvalidAction);
                }
                let mut replacement: Option<ProviderLocation> = None;
                loop {
                    let Some(item) = reader.next_element().map_err(|_| Status::InvalidAction)?
                    else {
                        return Err(Status::InvalidAction);
                    };
                    if item.value == Value::EndOfContainer {
                        break;
                    }
                    let provider = decode_provider(&mut reader, &item, fabric_index)?;
                    // §11.20.7.5: "On a list update that would introduce more than one entry
                    // per fabric, the write SHALL fail with CONSTRAINT_ERROR status code."
                    if replacement.replace(provider).is_some() {
                        return Err(Status::ConstraintError);
                    }
                }
                let mut providers = self.providers.borrow_mut();
                providers.retain(|p| p.fabric_index != fabric_index);
                if let Some(provider) = replacement {
                    providers
                        .push(provider)
                        .map_err(|_| Status::ResourceExhausted)?;
                }
                Ok(())
            }
            WriteOp::Append => {
                let provider = decode_provider(&mut reader, &element, fabric_index)?;
                // One entry per fabric, so appending to a fabric that already has one is the
                // same violation as sending two in a replace.
                if self.provider_for(fabric_index).is_some() {
                    return Err(Status::ConstraintError);
                }
                self.set_provider(provider)
            }
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> core::result::Result<Option<CommandId>, StatusIb> {
        if resolved.command.id != ANNOUNCE_OTA_PROVIDER {
            return Err(Status::UnsupportedCommand.into());
        }
        // §11.20.7.6.1: "If the accessing fabric index is 0, this command SHALL fail with an
        // UNSUPPORTED_ACCESS status code." A provider that is on no fabric is announcing
        // itself to a node that could never reach it.
        let Some(fabric_index) = ctx.fabric_index.filter(|f| f.0 != 0) else {
            return Err(Status::UnsupportedAccess.into());
        };
        let payload = fields.ok_or(StatusIb::from(Status::InvalidCommand))?;
        let decoded: spec_requestor::AnnounceOTAProviderFields<'_> = super::decode_fields(payload)?;
        if decoded
            .metadata_for_node
            .is_some_and(|m| m.len() > METADATA_MAX)
        {
            return Err(Status::ConstraintError.into());
        }
        self.hooks.announced(&Announcement {
            fabric_index,
            provider_node_id: decoded.provider_node_id,
            endpoint: decoded.endpoint,
            vendor_id: decoded.vendor_id,
            reason: decoded.announcement_reason,
            metadata: decoded.metadata_for_node,
        });
        // §11.20.7.5: an announcement "SHALL NOT overwrite values set in the
        // DefaultOTAProviders attribute" — so nothing here touches the list. §11.20.7.6.1:
        // "If the announcement is ignored, the response SHOULD be SUCCESS."
        Ok(None)
    }
}

/// Reads one `ProviderLocation`, stamped with the accessing fabric.
///
/// §7.19.1.8.1: "the FabricIndex field … SHALL be ignored" on a write, and the entry belongs to
/// whoever wrote it. A client that names another fabric's index is not permitted to place an
/// entry there.
fn decode_provider<'a>(
    reader: &mut TlvReader<'a>,
    element: &crate::tlv::Element<'a>,
    fabric_index: FabricIndex,
) -> core::result::Result<ProviderLocation, Status> {
    if element.value.container() != Some(ContainerKind::Structure) {
        return Err(Status::InvalidAction);
    }
    let mut provider =
        ProviderLocation::from_tlv(reader, element).map_err(|_| Status::InvalidAction)?;
    provider.fabric_index = fabric_index;
    Ok(provider)
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: OtaRequestorHooks, const N: usize> Cluster for OtaRequestor<'_, H, N> {
    const ID: ClusterId = ID;
}
