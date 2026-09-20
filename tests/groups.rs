//! Groups (Application Cluster §1.3), driven through the interaction model.
//!
//! Two rules in this cluster are not obvious from its command list, and both are the sort a
//! device passes every unit test while getting wrong on a real network:
//!
//! * **A groupcast gets no answer.** Every command here says "SHALL NOT generate a ...
//!   Response command" when the request arrived as a groupcast. One multicast reaching twenty
//!   lights would otherwise draw twenty unicast responses at the same instant.
//! * **Every group is scoped to the accessing fabric.** A device that let one ecosystem read
//!   or remove another's groups would hand whoever commissioned it second a map of the house.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
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

use core::cell::Cell;

use matter_kit::clusters::generated;
use matter_kit::clusters::groups::{self, Groups, Identifying, NeverIdentifying};
use matter_kit::clusters::scenes::NoScenes;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, CommandData, CommandPath, InteractionContext, InvokeResponse, InvokeResponseMessage,
    Server, Status,
};
use matter_kit::msg::{FabricIndex, GroupId};
use matter_kit::tlv::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

/// An Identify cluster the test can switch on and off.
#[derive(Debug, Default)]
struct Lamp {
    identifying: Cell<bool>,
}

impl Identifying for Lamp {
    fn is_identifying(&self) -> bool {
        self.identifying.get()
    }
}

const NAMES: u32 = groups::feature::GROUP_NAMES;
const A: FabricIndex = FabricIndex(1);
const B: FabricIndex = FabricIndex(2);

struct Device<'a> {
    node: Node<'a>,
    cluster: Groups<'a, 8, Lamp, NoScenes>,
}

fn device(lamp: &Lamp, feature_map: u32, per_fabric: usize) -> Device<'_> {
    let conforming = Box::leak(Box::new(
        Groups::<8>::conforming(feature_map, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        cluster: Groups::with(per_fabric, feature_map & NAMES != 0, lamp, &NoScenes),
    }
}

/// What a command produced: either a bare status, or a response command's decoded fields.
#[derive(Debug, PartialEq)]
enum Answer {
    Status(Status),
    /// `(status, group)` — the shape `AddGroupResponse`, `ViewGroupResponse` and
    /// `RemoveGroupResponse` share, with the name where one is carried.
    Response(u8, u16, String),
    /// `(capacity, groups)` — `GetGroupMembershipResponse`.
    Membership(u8, Vec<u16>),
}

/// Invokes a command through the interaction model, as a client would.
fn invoke(
    device: &Device<'_>,
    fabric: FabricIndex,
    command: u32,
    fields: Option<&[u8]>,
    group: Option<GroupId>,
) -> Answer {
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(1, groups::ID, command))
    };
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let mut ctx = InteractionContext::new().with_fabric(fabric);
    if let Some(group) = group {
        ctx = ctx.with_group(group);
    }
    let (bytes, _) = server
        .serve_invoke([Ok(data)], &ctx, false, &mut scratch, &mut buf)
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    match responses.next().expect("one response").expect("decode") {
        InvokeResponse::Status(status) => Answer::Status(status.status.status),
        InvokeResponse::Command(command) => decode_response(command.fields.expect("fields")),
    }
}

/// Reads a response command's fields without assuming which one it is.
fn decode_response(fields: &[u8]) -> Answer {
    let mut reader = TlvReader::new_in(fields, ContainerKind::Structure);
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Structure));
    let mut status = None;
    let mut group = 0u16;
    let mut name = String::new();
    let mut capacity = None;
    let mut list = Vec::new();
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        match (field.tag.context(), &field.value) {
            // `Status`/`Capacity` share field 0; only one of the two shapes has an array.
            (Some(0), Value::Unsigned(value)) => {
                status = Some(*value as u8);
                capacity = Some(*value as u8);
            }
            (Some(1), Value::Unsigned(value)) => group = *value as u16,
            (Some(1), _) if field.value.container() == Some(ContainerKind::Array) => {
                loop {
                    let entry: Element<'_> = reader.next_element().unwrap().unwrap();
                    if entry.value == Value::EndOfContainer {
                        break;
                    }
                    match entry.value {
                        Value::Unsigned(value) => list.push(value as u16),
                        _ => panic!("group ids are unsigned"),
                    }
                }
                return Answer::Membership(capacity.unwrap(), list);
            }
            (Some(2), Value::Utf8(text)) => name = text.to_string(),
            _ => reader.skip_value(&field).unwrap(),
        }
    }
    Answer::Response(status.unwrap(), group, name)
}

fn add_fields(group: u16, name: &str) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    w.utf8(Tag::Context(1), name).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn group_fields(group: u16) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn membership_fields(groups: &[u16]) -> Vec<u8> {
    // Large enough for the longest list any test sends: the request's size is the client's
    // choice, and one test deliberately sends more group ids than the endpoint could hold.
    let mut buf = vec![0u8; 4096];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.start_array(Tag::Context(0)).unwrap();
    for group in groups {
        w.unsigned(Tag::Anonymous, u64::from(*group)).unwrap();
    }
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn added(device: &Device<'_>, fabric: FabricIndex, group: u16, name: &str) -> Answer {
    invoke(
        device,
        fabric,
        groups::ADD_GROUP,
        Some(&add_fields(group, name)),
        None,
    )
}

const SUCCESS: u8 = 0x00;

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_cluster_matches_the_specification_for_every_feature_combination() {
    let spec = generated::find(groups::ID).expect("Groups");
    for bits in [0, NAMES] {
        let built = Groups::<8>::conforming(bits, &Optional::NONE).expect("sized");
        let descriptor = built.descriptor();
        let mut defects = Vec::new();
        spec.validate(&descriptor, |defect| defects.push(defect));
        assert!(defects.is_empty(), "features {bits:#x}: {defects:?}");
    }
}

#[test]
fn name_support_mirrors_the_feature_bit() {
    // §1.3.6.1: "The most significant bit, bit 7 (GroupNames), SHALL be equal to bit 0 of the
    // FeatureMap attribute (GN Feature). All other bits SHALL be 0." Two spellings of one
    // fact, and the older one is the one a legacy client reads.
    let lamp = Lamp::default();
    assert_eq!(device(&lamp, NAMES, 4).cluster.name_support().bits(), 0x80);
    assert_eq!(device(&lamp, 0, 4).cluster.name_support().bits(), 0x00);
}

// --- AddGroup --------------------------------------------------------------------------------

#[test]
fn add_group_stores_a_membership_and_answers() {
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    assert_eq!(
        added(&device, A, 7, "Kitchen"),
        Answer::Response(SUCCESS, 7, String::new())
    );
    assert!(device.cluster.is_member(A, GroupId(7)));
    // §1.3.7.1 step 3: a second AddGroup for a group already joined updates the name and
    // succeeds — that is how a client renames a group, not an error to report.
    assert_eq!(
        added(&device, A, 7, "Galley"),
        Answer::Response(SUCCESS, 7, String::new())
    );
    assert_eq!(device.cluster.len_of_fabric(A), 1);
    assert_eq!(
        invoke(&device, A, groups::VIEW_GROUP, Some(&group_fields(7)), None),
        Answer::Response(SUCCESS, 7, "Galley".to_string())
    );
}

#[test]
fn group_zero_is_not_a_group() {
    // §1.3.7.1.1 constrains GroupID to "min 1". Zero addresses no group at all, and a device
    // that joined it would answer messages meant for nobody.
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    assert_eq!(
        added(&device, A, 0, "Nowhere"),
        Answer::Response(Status::ConstraintError.value(), 0, String::new())
    );
    assert!(!device.cluster.is_member(A, GroupId(0)));
}

#[test]
fn a_name_longer_than_sixteen_characters_is_refused() {
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    assert_eq!(
        added(&device, A, 7, "a name of seventeen"),
        Answer::Response(Status::ConstraintError.value(), 7, String::new())
    );
    assert!(!device.cluster.is_member(A, GroupId(7)));
}

#[test]
fn without_the_feature_the_name_is_ignored_rather_than_refused() {
    // §1.3.7.1: "If the server does not support group names, the GroupName field SHALL be
    // ignored" — the group is still joined, it just has no name to view.
    let lamp = Lamp::default();
    let device = device(&lamp, 0, 4);
    assert_eq!(
        added(&device, A, 7, "Kitchen"),
        Answer::Response(SUCCESS, 7, String::new())
    );
    assert_eq!(
        invoke(&device, A, groups::VIEW_GROUP, Some(&group_fields(7)), None),
        Answer::Response(SUCCESS, 7, String::new())
    );
}

#[test]
fn a_full_table_answers_resource_exhausted() {
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 2);
    assert_eq!(
        added(&device, A, 1, ""),
        Answer::Response(SUCCESS, 1, String::new())
    );
    assert_eq!(
        added(&device, A, 2, ""),
        Answer::Response(SUCCESS, 2, String::new())
    );
    assert_eq!(
        added(&device, A, 3, ""),
        Answer::Response(Status::ResourceExhausted.value(), 3, String::new())
    );
    // The per-fabric limit is a *reservation*, not a race: the second fabric still has its
    // own two, which is the whole reason the limit is expressed per fabric.
    assert_eq!(
        added(&device, B, 3, ""),
        Answer::Response(SUCCESS, 3, String::new())
    );
}

#[test]
fn a_command_without_an_accessing_fabric_is_refused() {
    // §8.8.2.3 step b.v: a fabric-scoped command on a session with no fabric — a PASE session
    // during commissioning — is UNSUPPORTED_ACCESS. There is no fabric to scope the group to.
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    let fields = add_fields(7, "Kitchen");
    let data = CommandData {
        fields: Some(&fields),
        ..CommandData::new(CommandPath::command(1, groups::ID, groups::ADD_GROUP))
    };
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = AllowAll;
    let server = Server::new(device.node, &access, &device.cluster, 8);
    let (bytes, _) = server
        .serve_invoke(
            [Ok(data)],
            &InteractionContext::new(),
            false,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let response = InvokeResponseMessage::decode(bytes).expect("decode");
    let mut responses = response.responses().expect("responses");
    match responses.next().unwrap().unwrap() {
        InvokeResponse::Status(status) => {
            assert_eq!(status.status.status, Status::UnsupportedAccess);
        }
        InvokeResponse::Command(_) => panic!("no fabric, no response"),
    }
    assert_eq!(device.cluster.memberships().len(), 0);
}

// --- Fabric scoping --------------------------------------------------------------------------

#[test]
fn one_fabric_cannot_see_or_remove_anothers_groups() {
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    added(&device, A, 7, "Kitchen");

    // B is in the same *group* 7 only if it joins it itself; A's membership is invisible.
    assert_eq!(
        invoke(&device, B, groups::VIEW_GROUP, Some(&group_fields(7)), None),
        Answer::Response(Status::NotFound.value(), 7, String::new())
    );
    assert_eq!(
        invoke(
            &device,
            B,
            groups::REMOVE_GROUP,
            Some(&group_fields(7)),
            None
        ),
        Answer::Response(Status::NotFound.value(), 7, String::new())
    );
    assert!(device.cluster.is_member(A, GroupId(7)));

    // Nor does RemoveAllGroups reach across. It is the most destructive command here and the
    // easiest one to implement as "clear the table".
    assert_eq!(
        invoke(&device, B, groups::REMOVE_ALL_GROUPS, None, None),
        Answer::Status(Status::Success)
    );
    assert!(device.cluster.is_member(A, GroupId(7)));

    assert_eq!(
        invoke(&device, A, groups::REMOVE_ALL_GROUPS, None, None),
        Answer::Status(Status::Success)
    );
    assert!(!device.cluster.is_member(A, GroupId(7)));
}

#[test]
fn removing_a_fabric_takes_its_groups_with_it() {
    // What the Operational Credentials cluster's RemoveFabric must call: an un-commissioned
    // fabric's memberships are storage nobody can reach and nobody can reclaim.
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    added(&device, A, 7, "Kitchen");
    added(&device, B, 8, "Hall");
    device.cluster.remove_fabric(A);
    assert!(!device.cluster.is_member(A, GroupId(7)));
    assert!(device.cluster.is_member(B, GroupId(8)));
}

// --- GetGroupMembership ----------------------------------------------------------------------

#[test]
fn an_empty_group_list_asks_for_everything() {
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    added(&device, A, 7, "Kitchen");
    added(&device, A, 9, "Hall");
    added(&device, B, 4, "Elsewhere");
    assert_eq!(
        invoke(
            &device,
            A,
            groups::GET_GROUP_MEMBERSHIP,
            Some(&membership_fields(&[])),
            None
        ),
        // Two of four used, so two left — and B's group is not A's business.
        Answer::Membership(2, vec![7, 9])
    );
}

#[test]
fn a_group_list_asks_for_the_intersection() {
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    added(&device, A, 7, "Kitchen");
    added(&device, A, 9, "Hall");
    assert_eq!(
        invoke(
            &device,
            A,
            groups::GET_GROUP_MEMBERSHIP,
            Some(&membership_fields(&[9, 11])),
            None
        ),
        Answer::Membership(2, vec![9])
    );
    // No match is an empty list, not an error: the client asked a question and got an answer.
    assert_eq!(
        invoke(
            &device,
            A,
            groups::GET_GROUP_MEMBERSHIP,
            Some(&membership_fields(&[11])),
            None
        ),
        Answer::Membership(2, vec![])
    );
}

#[test]
fn a_list_longer_than_the_table_is_still_answered() {
    // The request's list is the *client's* to size, not the device's. A server that copied it
    // into a buffer of its own would silently stop matching past the end of that buffer — and
    // report the client is in no groups it is actually in.
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    added(&device, A, 400, "Kitchen");
    let long: Vec<u16> = (1..=400).collect();
    assert_eq!(
        invoke(
            &device,
            A,
            groups::GET_GROUP_MEMBERSHIP,
            Some(&membership_fields(&long)),
            None
        ),
        Answer::Membership(3, vec![400])
    );
}

// --- Groupcast -------------------------------------------------------------------------------

#[test]
fn a_groupcast_is_acted_on_but_never_answered() {
    // §1.3.7.1.2 and its four siblings. The work still happens — the client just does not get
    // twenty unicast responses arriving together.
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    let cast = Some(GroupId(3));

    assert_eq!(
        invoke(
            &device,
            A,
            groups::ADD_GROUP,
            Some(&add_fields(7, "Kitchen")),
            cast
        ),
        Answer::Status(Status::Success)
    );
    assert!(device.cluster.is_member(A, GroupId(7)));

    for (command, fields) in [
        (groups::VIEW_GROUP, group_fields(7)),
        (groups::GET_GROUP_MEMBERSHIP, membership_fields(&[])),
        (groups::REMOVE_GROUP, group_fields(7)),
    ] {
        assert_eq!(
            invoke(&device, A, command, Some(&fields), cast),
            Answer::Status(Status::Success),
            "command {command:#x} answered a groupcast"
        );
    }
    assert!(!device.cluster.is_member(A, GroupId(7)));
}

// --- AddGroupIfIdentifying -------------------------------------------------------------------

#[test]
fn add_group_if_identifying_needs_the_endpoint_to_be_identifying() {
    // §1.3.7.6 — how a commissioner puts the one light a person just pressed into a group,
    // without knowing which light that is.
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    let fields = add_fields(7, "Kitchen");

    // Not identifying: nothing happens, and the command still succeeds — it has no response
    // command, so "ignored" and "done" look the same on the wire, by design.
    assert_eq!(
        invoke(
            &device,
            A,
            groups::ADD_GROUP_IF_IDENTIFYING,
            Some(&fields),
            None
        ),
        Answer::Status(Status::Success)
    );
    assert!(!device.cluster.is_member(A, GroupId(7)));

    lamp.identifying.set(true);
    assert_eq!(
        invoke(
            &device,
            A,
            groups::ADD_GROUP_IF_IDENTIFYING,
            Some(&fields),
            None
        ),
        Answer::Status(Status::Success)
    );
    assert!(device.cluster.is_member(A, GroupId(7)));
}

#[test]
fn a_device_without_identify_never_joins_conditionally() {
    // The default, for the many device types that have no Identify cluster on the endpoint.
    assert!(!NeverIdentifying.is_identifying());
    let cluster: Groups<'static, 4> = Groups::new(4, true);
    assert_eq!(cluster.capacity(A), 4);
    assert_eq!(cluster.len_of_fabric(A), 0);
}

// --- Malformed input -------------------------------------------------------------------------

#[test]
fn a_command_missing_its_fields_is_refused() {
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    assert_eq!(
        invoke(&device, A, groups::ADD_GROUP, None, None),
        Answer::Status(Status::InvalidCommand)
    );
    // A field of the wrong type is a constraint failure, not a crash.
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.utf8(Tag::Context(0), "seven").unwrap();
    w.end_container().unwrap();
    let bad = w.finish().unwrap().to_vec();
    assert_eq!(
        invoke(&device, A, groups::ADD_GROUP, Some(&bad), None),
        Answer::Status(Status::ConstraintError)
    );
}

#[test]
fn an_unknown_field_is_skipped_rather_than_refused() {
    // §7.19.2: a newer client may send a field this revision does not define, and the
    // interaction must still work — this is what lets one ecosystem upgrade before another.
    let lamp = Lamp::default();
    let device = device(&lamp, NAMES, 4);
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 7).unwrap();
    w.utf8(Tag::Context(1), "Kitchen").unwrap();
    w.unsigned(Tag::Context(42), 1).unwrap();
    w.end_container().unwrap();
    let fields = w.finish().unwrap().to_vec();
    assert_eq!(
        invoke(&device, A, groups::ADD_GROUP, Some(&fields), None),
        Answer::Response(SUCCESS, 7, String::new())
    );
    assert!(device.cluster.is_member(A, GroupId(7)));
}
