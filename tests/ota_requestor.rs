//! The OTA Software Update Requestor (Core §11.20.7), driven through the cluster interface.
//!
//! Three rules carry this cluster, and all three are the kind an implementation gets wrong
//! quietly:
//!
//! * **One provider per fabric** (§11.20.7.5), enforced with `CONSTRAINT_ERROR`. Each fabric's
//!   administrator names its own, and a device that let one fabric hold two would be asking
//!   twice and obeying whichever answered first.
//! * **An announcement is not a configuration.** "Provider Locations obtained using the
//!   AnnounceOTAProvider command SHALL NOT overwrite values set in the DefaultOTAProviders
//!   attribute." A device that let one rewrite the list would let any administrator on the
//!   fabric redirect every later update.
//! * **`TargetSoftwareVersion` is null except in three states** (§11.20.7.7.1), and
//!   `UpdateStateProgress` is null whenever progress does not apply. Both are `X` qualities,
//!   and a controller reads a stale number as a live one.

#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use core::cell::RefCell;

use matter_kit::clusters::ota_requestor::{
    self as ota, AnnouncementReasonEnum, ChangeReasonEnum, Event, OtaRequestor, OtaRequestorHooks,
    ProviderLocation, UpdateStateEnum,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{ClusterHandler, InteractionContext, Status, WriteOp};
use matter_kit::msg::{FabricIndex, NodeId};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

const F1: FabricIndex = FabricIndex(1);
const F2: FabricIndex = FabricIndex(2);
const PROVIDER: NodeId = NodeId(0x0011_2233_4455_6677);
const OTHER: NodeId = NodeId(0x8899_AABB_CCDD_EEFF);

/// One announcement as the application saw it.
type Seen = (FabricIndex, NodeId, u16, AnnouncementReasonEnum, Vec<u8>);

/// Records every announcement, so a test can see what the cluster passed on.
#[derive(Debug, Default)]
struct Log {
    seen: RefCell<Vec<Seen>>,
}

impl OtaRequestorHooks for Log {
    fn announced(&self, announcement: &ota::Announcement<'_>) {
        self.seen.borrow_mut().push((
            announcement.fabric_index,
            announcement.provider_node_id,
            announcement.endpoint,
            announcement.reason,
            announcement.metadata.unwrap_or(&[]).to_vec(),
        ));
    }
}

type Requestor<'a> = OtaRequestor<'a, Log, 4>;

/// A node holding just this cluster, so reads and writes can be resolved against it.
///
/// `AnnounceOTAProvider` is optional conformance (§11.20.7.6), so a device that accepts it has
/// to say so — which is also why a device that forgot would find the command unreachable.
fn node() -> Node<'static> {
    let optional = Optional {
        commands: &[ota::ANNOUNCE_OTA_PROVIDER],
        ..Optional::NONE
    };
    let conforming = Box::leak(Box::new(
        Requestor::conforming(0, &optional).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(0, clusters)]));
    Node::new(endpoints)
}

fn read(
    node: &Node<'_>,
    cluster: &Requestor<'_>,
    attribute: u32,
    ctx: &InteractionContext<'_>,
) -> Result<Vec<u8>, Status> {
    let resolved = node
        .resolve(0, ota::ID, attribute)
        .expect("the path exists");
    let mut buf = [0u8; 1024];
    let mut w = TlvWriter::new(&mut buf);
    cluster.read(&resolved, ctx, &mut w, Tag::Anonymous)?;
    Ok(w.finish().expect("finish").to_vec())
}

fn write(
    node: &Node<'_>,
    cluster: &Requestor<'_>,
    data: &[u8],
    op: WriteOp,
    ctx: &InteractionContext<'_>,
) -> Result<(), Status> {
    let resolved = node
        .resolve(0, ota::ID, ota::DEFAULT_OTA_PROVIDERS)
        .expect("the path exists");
    cluster.write(&resolved, data, op, ctx)
}

fn invoke(
    node: &Node<'_>,
    cluster: &Requestor<'_>,
    fields: Option<&[u8]>,
    ctx: &InteractionContext<'_>,
) -> Result<(), Status> {
    let resolved = node
        .resolve_command(0, ota::ID, ota::ANNOUNCE_OTA_PROVIDER)
        .expect("the command exists");
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new(&mut buf);
    cluster
        .invoke(&resolved, fields, ctx, &mut w, Tag::Anonymous)
        .map(|response| assert_eq!(response, None, "§11.20.7.6 gives it no response command"))
        .map_err(|status| status.status)
}

/// One `ProviderLocation`, written the way a client would — including the `FabricIndex` field
/// a client is allowed to send and the device is required to ignore (§7.19.1.8.1).
fn provider_struct(node_id: NodeId, endpoint: u16, claimed_fabric: u8) -> Vec<u8> {
    let mut buf = [0u8; 128];
    // The `Data` field of an `AttributeDataIB` is context tag 2, which is the element a
    // cluster's `write` is handed.
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(2)).unwrap();
    w.unsigned(Tag::Context(1), node_id.0).unwrap();
    w.unsigned(Tag::Context(2), u64::from(endpoint)).unwrap();
    w.unsigned(Tag::Context(254), u64::from(claimed_fabric))
        .unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// A list of providers, as a whole-attribute replace.
fn provider_list(entries: &[(NodeId, u16)]) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_array(Tag::Context(2)).unwrap();
    for (node_id, endpoint) in entries {
        w.start_structure(Tag::Anonymous).unwrap();
        w.unsigned(Tag::Context(1), node_id.0).unwrap();
        w.unsigned(Tag::Context(2), u64::from(*endpoint)).unwrap();
        w.unsigned(Tag::Context(254), 0).unwrap();
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// An `AnnounceOTAProvider` payload.
fn announcement(
    node_id: NodeId,
    endpoint: u16,
    reason: AnnouncementReasonEnum,
    metadata: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    // The `CommandFields` of an `InvokeRequest` are context tag 1.
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), node_id.0).unwrap();
    w.unsigned(Tag::Context(1), 0xFFF1).unwrap();
    w.unsigned(Tag::Context(2), u64::from(reason.value()))
        .unwrap();
    if let Some(metadata) = metadata {
        w.octets(Tag::Context(3), metadata).unwrap();
    }
    w.unsigned(Tag::Context(4), u64::from(endpoint)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// The `(ProviderNodeID, Endpoint, FabricIndex)` triples a read produced.
fn decode_providers(bytes: &[u8]) -> Vec<(u64, u16, u8)> {
    let mut reader = TlvReader::new(bytes);
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Array));
    let mut out = Vec::new();
    loop {
        let item = reader.next_element().unwrap().unwrap();
        if item.value == Value::EndOfContainer {
            break;
        }
        assert_eq!(item.value.container(), Some(ContainerKind::Structure));
        let (mut node_id, mut endpoint, mut fabric) = (0u64, 0u16, 0u8);
        loop {
            let field = reader.next_element().unwrap().unwrap();
            if field.value == Value::EndOfContainer {
                break;
            }
            match (field.tag.context(), &field.value) {
                (Some(1), Value::Unsigned(v)) => node_id = *v,
                (Some(2), Value::Unsigned(v)) => endpoint = *v as u16,
                (Some(254), Value::Unsigned(v)) => fabric = *v as u8,
                _ => reader.skip_value(&field).unwrap(),
            }
        }
        out.push((node_id, endpoint, fabric));
    }
    out
}

// --- §11.20.7.5: DefaultOTAProviders ----------------------------------------------------

#[test]
fn the_list_starts_empty() {
    // §11.20.7.5's fallback is `[]`, and `UpdatePossible` is True.
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let ctx = InteractionContext::default();
    assert_eq!(
        decode_providers(&read(&node, &cluster, ota::DEFAULT_OTA_PROVIDERS, &ctx).unwrap()),
        vec![]
    );
    assert!(cluster.update_possible());
    assert_eq!(cluster.state(), UpdateStateEnum::Unknown);
    assert_eq!(cluster.progress(), None);
}

#[test]
fn a_write_stamps_the_accessing_fabric_over_whatever_the_client_claimed() {
    // §7.19.1.8.1: the FabricIndex field of a written entry "SHALL be ignored". A client that
    // names another fabric is not permitted to place an entry there.
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let ctx = InteractionContext::default().with_fabric(F1);
    write(
        &node,
        &cluster,
        &provider_struct(PROVIDER, 3, 9),
        WriteOp::Append,
        &ctx,
    )
    .unwrap();
    assert_eq!(
        cluster.provider_for(F1),
        Some(ProviderLocation {
            provider_node_id: PROVIDER,
            endpoint: 3,
            fabric_index: F1,
        })
    );
    assert_eq!(cluster.provider_for(FabricIndex(9)), None);
}

#[test]
fn two_entries_for_one_fabric_are_a_constraint_error() {
    // §11.20.7.5: "There SHALL NOT be more than one entry per Fabric. On a list update that
    // would introduce more than one entry per fabric, the write SHALL fail with
    // CONSTRAINT_ERROR status code."
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let ctx = InteractionContext::default().with_fabric(F1);
    assert_eq!(
        write(
            &node,
            &cluster,
            &provider_list(&[(PROVIDER, 1), (OTHER, 2)]),
            WriteOp::Replace,
            &ctx,
        ),
        Err(Status::ConstraintError)
    );
    assert_eq!(cluster.provider_for(F1), None, "nothing was stored");

    // And the same violation spelled as two appends.
    write(
        &node,
        &cluster,
        &provider_struct(PROVIDER, 1, 0),
        WriteOp::Append,
        &ctx,
    )
    .unwrap();
    assert_eq!(
        write(
            &node,
            &cluster,
            &provider_struct(OTHER, 2, 0),
            WriteOp::Append,
            &ctx,
        ),
        Err(Status::ConstraintError)
    );
    assert_eq!(
        cluster.provider_for(F1).unwrap().provider_node_id,
        PROVIDER,
        "the first entry is not replaced by a refused second"
    );
}

#[test]
fn a_replace_touches_only_the_writing_fabrics_entry() {
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    cluster
        .set_provider(ProviderLocation {
            provider_node_id: OTHER,
            endpoint: 7,
            fabric_index: F2,
        })
        .unwrap();

    let ctx = InteractionContext::default().with_fabric(F1);
    write(
        &node,
        &cluster,
        &provider_list(&[(PROVIDER, 1)]),
        WriteOp::Replace,
        &ctx,
    )
    .unwrap();
    assert_eq!(cluster.provider_for(F1).unwrap().provider_node_id, PROVIDER);
    assert_eq!(cluster.provider_for(F2).unwrap().provider_node_id, OTHER);

    // An empty replace clears this fabric and leaves the other alone.
    write(&node, &cluster, &provider_list(&[]), WriteOp::Replace, &ctx).unwrap();
    assert_eq!(cluster.provider_for(F1), None);
    assert_eq!(cluster.provider_for(F2).unwrap().provider_node_id, OTHER);
}

#[test]
fn a_write_with_no_accessing_fabric_is_refused() {
    // §7.19.1.8.1: a fabric-scoped list needs a fabric to scope the write to. A PASE session
    // has none.
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    assert_eq!(
        write(
            &node,
            &cluster,
            &provider_struct(PROVIDER, 1, 1),
            WriteOp::Append,
            &InteractionContext::default(),
        ),
        Err(Status::UnsupportedAccess)
    );
}

#[test]
fn a_fabric_filtered_read_shows_one_fabric_its_own_entry() {
    // §7.19.1.8.2: a fabric-filtered read returns only the accessing fabric's entries.
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    for (fabric, provider) in [(F1, PROVIDER), (F2, OTHER)] {
        cluster
            .set_provider(ProviderLocation {
                provider_node_id: provider,
                endpoint: 1,
                fabric_index: fabric,
            })
            .unwrap();
    }

    let mut ctx = InteractionContext::default().with_fabric(F1);
    ctx.fabric_filtered = true;
    let filtered =
        decode_providers(&read(&node, &cluster, ota::DEFAULT_OTA_PROVIDERS, &ctx).unwrap());
    assert_eq!(filtered, vec![(PROVIDER.0, 1, 1)]);

    ctx.fabric_filtered = false;
    let all = decode_providers(&read(&node, &cluster, ota::DEFAULT_OTA_PROVIDERS, &ctx).unwrap());
    assert_eq!(all.len(), 2);
}

#[test]
fn removing_a_fabric_forgets_its_provider() {
    let log = Log::default();
    let cluster = Requestor::new(&log);
    cluster
        .set_provider(ProviderLocation {
            provider_node_id: PROVIDER,
            endpoint: 1,
            fabric_index: F1,
        })
        .unwrap();
    cluster.remove_fabric(F1);
    assert_eq!(cluster.provider_for(F1), None);
}

// --- §11.20.7.6.1: AnnounceOTAProvider --------------------------------------------------

#[test]
fn an_announcement_without_a_fabric_is_unsupported_access() {
    // §11.20.7.6.1: "If the accessing fabric index is 0, this command SHALL fail with an
    // UNSUPPORTED_ACCESS status code."
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let fields = announcement(
        PROVIDER,
        1,
        AnnouncementReasonEnum::SimpleAnnouncement,
        None,
    );
    assert_eq!(
        invoke(
            &node,
            &cluster,
            Some(&fields),
            &InteractionContext::default()
        ),
        Err(Status::UnsupportedAccess)
    );
    assert_eq!(
        invoke(
            &node,
            &cluster,
            Some(&fields),
            &InteractionContext::default().with_fabric(FabricIndex(0)),
        ),
        Err(Status::UnsupportedAccess)
    );
    assert!(log.seen.borrow().is_empty());
}

#[test]
fn an_announcement_reaches_the_application_whole() {
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let fields = announcement(
        PROVIDER,
        5,
        AnnouncementReasonEnum::UrgentUpdateAvailable,
        Some(b"field-trial"),
    );
    invoke(
        &node,
        &cluster,
        Some(&fields),
        &InteractionContext::default().with_fabric(F2),
    )
    .unwrap();
    assert_eq!(
        log.seen.borrow().as_slice(),
        &[(
            F2,
            PROVIDER,
            5,
            AnnouncementReasonEnum::UrgentUpdateAvailable,
            b"field-trial".to_vec(),
        )]
    );
}

#[test]
fn an_announcement_does_not_change_the_configured_providers() {
    // §11.20.7.5: "Provider Locations obtained using the AnnounceOTAProvider command SHALL NOT
    // overwrite values set in the DefaultOTAProviders attribute." A device that let one rewrite
    // the list would let any administrator on the fabric redirect every later update.
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    cluster
        .set_provider(ProviderLocation {
            provider_node_id: PROVIDER,
            endpoint: 1,
            fabric_index: F1,
        })
        .unwrap();

    let fields = announcement(OTHER, 9, AnnouncementReasonEnum::UpdateAvailable, None);
    invoke(
        &node,
        &cluster,
        Some(&fields),
        &InteractionContext::default().with_fabric(F1),
    )
    .unwrap();

    assert_eq!(
        cluster.provider_for(F1),
        Some(ProviderLocation {
            provider_node_id: PROVIDER,
            endpoint: 1,
            fabric_index: F1,
        }),
        "the announcement must not have overwritten the configured provider"
    );
    // Nor added itself on a fabric that had none.
    assert_eq!(cluster.provider_for(F2), None);
}

#[test]
fn metadata_is_capped_at_512_octets() {
    // §11.20.7.6.1's constraint on `MetadataForNode` is "max 512".
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let ctx = InteractionContext::default().with_fabric(F1);

    let at_limit = announcement(
        PROVIDER,
        1,
        AnnouncementReasonEnum::SimpleAnnouncement,
        Some(&[0u8; ota::METADATA_MAX]),
    );
    invoke(&node, &cluster, Some(&at_limit), &ctx).unwrap();

    let over = announcement(
        PROVIDER,
        1,
        AnnouncementReasonEnum::SimpleAnnouncement,
        Some(&[0u8; ota::METADATA_MAX + 1]),
    );
    assert_eq!(
        invoke(&node, &cluster, Some(&over), &ctx),
        Err(Status::ConstraintError)
    );
    assert_eq!(
        log.seen.borrow().len(),
        1,
        "the oversized one never arrived"
    );
}

// --- §11.20.7.7: events ------------------------------------------------------------------

#[test]
fn a_state_change_records_a_state_transition() {
    let log = Log::default();
    let cluster = Requestor::new(&log);
    cluster.transition(UpdateStateEnum::Querying, ChangeReasonEnum::Success, None);
    assert_eq!(cluster.state(), UpdateStateEnum::Querying);
    assert_eq!(
        cluster.take_events().as_slice(),
        &[Event::StateTransition {
            previous: UpdateStateEnum::Unknown,
            new_state: UpdateStateEnum::Querying,
            reason: ChangeReasonEnum::Success,
            target_software_version: None,
        }]
    );
}

#[test]
fn a_transition_to_the_state_already_in_effect_records_nothing() {
    // §11.20.7.7.1: the event is generated "when a change of the UpdateState attribute occurs".
    let log = Log::default();
    let cluster = Requestor::new(&log);
    cluster.transition(UpdateStateEnum::Idle, ChangeReasonEnum::Success, None);
    assert_eq!(cluster.take_events().len(), 1);
    cluster.transition(UpdateStateEnum::Idle, ChangeReasonEnum::TimeOut, None);
    assert!(cluster.take_events().is_empty());
}

#[test]
fn the_target_version_is_null_outside_the_three_states_that_have_one() {
    // §11.20.7.7.1: "This field SHALL be set to the target SoftwareVersion which is the subject
    // of the operation, whenever the NewState is Downloading, Applying or RollingBack.
    // Otherwise TargetSoftwareVersion SHALL be null."
    let log = Log::default();
    let cluster = Requestor::new(&log);
    for (state, expected) in [
        (UpdateStateEnum::Downloading, Some(7)),
        (UpdateStateEnum::Applying, Some(7)),
        (UpdateStateEnum::RollingBack, Some(7)),
        (UpdateStateEnum::Idle, None),
        (UpdateStateEnum::Querying, None),
        (UpdateStateEnum::DelayedOnQuery, None),
        (UpdateStateEnum::DelayedOnApply, None),
        (UpdateStateEnum::DelayedOnUserConsent, None),
        (UpdateStateEnum::Unknown, None),
    ] {
        cluster.transition(state, ChangeReasonEnum::Success, Some(7));
        let events = cluster.take_events();
        let Some(Event::StateTransition {
            target_software_version,
            ..
        }) = events.first()
        else {
            panic!("a transition to {state:?} recorded nothing");
        };
        assert_eq!(*target_software_version, expected, "state {state:?}");
    }
}

#[test]
fn progress_is_cleared_by_a_transition() {
    // §11.20.7.5: "The value of this field SHALL be null if a progress indication does not
    // apply to the current state." Nothing has been reported about a state just entered.
    let log = Log::default();
    let cluster = Requestor::new(&log);
    cluster.transition(
        UpdateStateEnum::Downloading,
        ChangeReasonEnum::Success,
        Some(2),
    );
    cluster.set_progress(Some(42)).unwrap();
    assert_eq!(cluster.progress(), Some(42));
    cluster.transition(
        UpdateStateEnum::Applying,
        ChangeReasonEnum::Success,
        Some(2),
    );
    assert_eq!(cluster.progress(), None);
}

#[test]
fn progress_is_a_percentage() {
    // §11.20.7.5's constraint is "0 to 100".
    let log = Log::default();
    let cluster = Requestor::new(&log);
    assert!(cluster.set_progress(Some(0)).is_ok());
    assert!(cluster.set_progress(Some(100)).is_ok());
    assert_eq!(
        cluster.set_progress(Some(101)),
        Err(Status::ConstraintError)
    );
    assert_eq!(
        cluster.progress(),
        Some(100),
        "the refused value is not kept"
    );
    assert!(cluster.set_progress(None).is_ok());
}

#[test]
fn progress_reads_back_as_null_when_it_does_not_apply() {
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let ctx = InteractionContext::default();
    let bytes = read(&node, &cluster, ota::UPDATE_STATE_PROGRESS, &ctx).unwrap();
    let mut reader = TlvReader::new(&bytes);
    assert_eq!(reader.next_element().unwrap().unwrap().value, Value::Null);

    cluster.set_progress(Some(55)).unwrap();
    let bytes = read(&node, &cluster, ota::UPDATE_STATE_PROGRESS, &ctx).unwrap();
    let mut reader = TlvReader::new(&bytes);
    assert_eq!(
        reader.next_element().unwrap().unwrap().value,
        Value::Unsigned(55)
    );
}

#[test]
fn a_download_error_works_out_its_own_percentage() {
    // §11.20.7.7.3: "the nearest integer percent value reflecting how far within the transfer
    // the failure occurred … unless the total length of the transfer is unknown, in which case
    // it SHALL be null."
    let log = Log::default();
    let cluster = Requestor::new(&log);
    for (done, total, expected) in [
        (0u64, Some(1000u64), Some(0u8)),
        (500, Some(1000), Some(50)),
        (1000, Some(1000), Some(100)),
        // 333/1000 is 33.3%, and 336/1000 is 33.6% — nearest, not truncated.
        (333, Some(1000), Some(33)),
        (336, Some(1000), Some(34)),
        // An indefinite-length transfer has nothing to be a percentage of.
        (500, None, None),
        (500, Some(0), None),
        // A transfer that somehow overran cannot report 120%.
        (1200, Some(1000), Some(100)),
    ] {
        cluster.download_error(3, done, total, Some(-5));
        let events = cluster.take_events();
        assert_eq!(
            events.first(),
            Some(&Event::DownloadError {
                software_version: 3,
                bytes_downloaded: done,
                progress_percent: expected,
                platform_code: Some(-5),
            }),
            "{done} of {total:?}"
        );
    }
}

#[test]
fn a_version_applied_event_names_the_version_and_product() {
    let log = Log::default();
    let cluster = Requestor::new(&log);
    cluster.version_applied(0x0102_0304, 0x8000);
    assert_eq!(
        cluster.take_events().as_slice(),
        &[Event::VersionApplied {
            software_version: 0x0102_0304,
            product_id: 0x8000,
        }]
    );
    assert_eq!(
        Event::VersionApplied {
            software_version: 1,
            product_id: 2,
        }
        .id(),
        ota::VERSION_APPLIED
    );
}

#[test]
fn the_event_queue_drops_the_oldest_rather_than_the_newest() {
    // A device that could not report the *latest* state would tell a controller it was still
    // downloading long after it had failed.
    let log = Log::default();
    let cluster = Requestor::new(&log);
    for version in 0..(ota::EVENT_QUEUE as u32 + 3) {
        cluster.version_applied(version, 1);
    }
    let events = cluster.take_events();
    assert_eq!(events.len(), ota::EVENT_QUEUE);
    assert_eq!(
        events.first(),
        Some(&Event::VersionApplied {
            software_version: 3,
            product_id: 1,
        })
    );
}

#[test]
fn an_event_encodes_its_specification_field_tags() {
    // §11.20.7.7.1's fields are 0 PreviousState, 1 NewState, 2 Reason, 3 TargetSoftwareVersion —
    // and the last is nullable, so a state with no target writes a null rather than omitting it.
    use matter_kit::tlv::ToTlv;
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    Event::StateTransition {
        previous: UpdateStateEnum::Querying,
        new_state: UpdateStateEnum::Downloading,
        reason: ChangeReasonEnum::Success,
        target_software_version: Some(9),
    }
    .to_tlv(&mut w, Tag::Anonymous)
    .unwrap();
    let bytes = w.finish().unwrap().to_vec();

    let mut reader = TlvReader::new(&bytes);
    assert_eq!(
        reader.next_element().unwrap().unwrap().value.container(),
        Some(ContainerKind::Structure)
    );
    let mut fields = Vec::new();
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        fields.push((field.tag.context().unwrap(), field.value));
    }
    assert_eq!(
        fields,
        vec![
            (
                0,
                Value::Unsigned(u64::from(UpdateStateEnum::Querying.value()))
            ),
            (
                1,
                Value::Unsigned(u64::from(UpdateStateEnum::Downloading.value()))
            ),
            (
                2,
                Value::Unsigned(u64::from(ChangeReasonEnum::Success.value()))
            ),
            (3, Value::Unsigned(9)),
        ]
    );
}

#[test]
fn update_possible_is_informational_and_readable() {
    // §11.20.7.5: "This field is merely informational for diagnostics purposes and SHALL NOT
    // affect the responses provided by an OTA Provider to an OTA Requestor."
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let ctx = InteractionContext::default();
    cluster.set_update_possible(false);
    let bytes = read(&node, &cluster, ota::UPDATE_POSSIBLE, &ctx).unwrap();
    let mut reader = TlvReader::new(&bytes);
    assert_eq!(
        reader.next_element().unwrap().unwrap().value,
        Value::Bool(false)
    );
}

#[test]
fn the_state_attribute_reads_back_the_enum_value() {
    let log = Log::default();
    let cluster = Requestor::new(&log);
    let node = node();
    let ctx = InteractionContext::default();
    cluster.transition(
        UpdateStateEnum::Downloading,
        ChangeReasonEnum::Success,
        Some(1),
    );
    let bytes = read(&node, &cluster, ota::UPDATE_STATE, &ctx).unwrap();
    let mut reader = TlvReader::new(&bytes);
    assert_eq!(
        reader.next_element().unwrap().unwrap().value,
        Value::Unsigned(u64::from(UpdateStateEnum::Downloading.value()))
    );
}
