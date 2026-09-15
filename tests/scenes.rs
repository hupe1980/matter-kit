//! Scenes Management (Application Cluster §1.4), driven through the interaction model.
//!
//! Three rules here are the ones a device gets wrong in ways nobody notices until two
//! ecosystems share the house:
//!
//! * **Half the table, per fabric** (§1.4.6). Without the ceiling, whoever commissions first
//!   fills the table and the second ecosystem cannot store a single scene.
//! * **Removing a group removes its scenes** (§1.3.7.4) — a rule about this cluster's data,
//!   written in the Groups chapter, which is exactly why it gets skipped.
//! * **A scene names a group the endpoint has joined** (§1.4.9's step 1). A scene for a group
//!   this endpoint is not in is a scene nothing can ever recall.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::clusters::generated;
use matter_kit::clusters::groups::{self, Groups, NeverIdentifying};
use matter_kit::clusters::scenes::{self, ExtensionFieldSetStruct, SceneHooks, SceneTable, Scenes};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{
    AllowAll, CommandData, CommandPath, InteractionContext, InvokeResponse, InvokeResponseMessage,
    Server, Status,
};
use matter_kit::msg::{FabricIndex, GroupId};
use matter_kit::tlv::{ContainerKind, Tag, TlvList, TlvWriter, Value};

/// Sixteen entries — §1.4.8.1's minimum — so a fabric gets eight.
type Table = SceneTable<16, 256, 4>;

const A: FabricIndex = FabricIndex(1);
const B: FabricIndex = FabricIndex(2);
const NAMES: u32 = scenes::feature::SCENE_NAMES;

/// A light whose only Scenes-quality attribute is On/Off's `OnOff` (§1.5.6.1).
#[derive(Debug, Default)]
struct Lamp {
    on: RefCell<bool>,
    /// Every `(on, transition)` a recall applied, so a test can see what reached the hardware.
    applied: RefCell<Vec<(bool, u32)>>,
}

impl SceneHooks for Lamp {
    fn capture(&self, w: &mut TlvWriter<'_>) -> matter_kit::error::Result<()> {
        // One ExtensionFieldSetStruct: On/Off's `OnOff`, as ValueUnsigned8 (§1.4.7.3.2:
        // "Data types bool, map8, and uint8 SHALL map to ValueUnsigned8").
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(matter_kit::clusters::on_off::ID))?;
        w.start_array(Tag::Context(1))?;
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(
            Tag::Context(0),
            u64::from(matter_kit::clusters::on_off::ON_OFF),
        )?;
        w.unsigned(Tag::Context(1), u64::from(*self.on.borrow()))?;
        w.end_container()?;
        w.end_container()?;
        w.end_container()
    }

    fn apply<'a>(&self, sets: TlvList<'a, ExtensionFieldSetStruct<'a>>, transition: u32) {
        for set in sets.iter() {
            let Ok(set) = set else { continue };
            if set.cluster_id != matter_kit::clusters::on_off::ID {
                continue;
            }
            for pair in set.attribute_value_list.iter() {
                let Ok(pair) = pair else { continue };
                if pair.attribute_id == matter_kit::clusters::on_off::ON_OFF {
                    let on = pair.value_unsigned8.unwrap_or(0) != 0;
                    *self.on.borrow_mut() = on;
                    self.applied.borrow_mut().push((on, transition));
                }
            }
        }
    }
}

struct Device<'a> {
    node: Node<'a>,
    groups: &'a Groups<'a, 8, NeverIdentifying, Table>,
    scenes: Scenes<'a, Lamp, Groups<'a, 8, NeverIdentifying, Table>, 16, 256, 4>,
}

/// Builds an endpoint carrying Groups and Scenes over one shared Scene Table.
fn device<'a>(table: &'a Table, lamp: &'a Lamp, feature_map: u32) -> Device<'a> {
    let groups: &'a Groups<'a, 8, NeverIdentifying, Table> =
        Box::leak(Box::new(Groups::with(4, true, &NeverIdentifying, table)));
    let scenes_desc = Box::leak(Box::new(
        Scenes::<Lamp, Groups<'a, 8, NeverIdentifying, Table>, 16, 256, 4>::conforming(
            feature_map,
            &Optional::NONE,
        )
        .expect("sized"),
    ));
    let groups_desc = Box::leak(Box::new(
        Groups::<8>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'a [ClusterDescriptor<'a>] = Box::leak(Box::new([
        groups_desc.descriptor(),
        scenes_desc.descriptor(),
    ]));
    let endpoints: &'a [Endpoint<'a>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Device {
        node: Node::new(endpoints),
        groups,
        scenes: Scenes::new(table, groups, lamp, false),
    }
}

/// What a command produced.
#[derive(Debug, PartialEq)]
enum Answer {
    Status(Status),
    /// Every field of a response, flattened: `(status, group, scene, transition, name, scenes)`.
    Response {
        status: u8,
        group: u16,
        scene: Option<u8>,
        transition: Option<u32>,
        name: Option<String>,
        list: Option<Vec<u8>>,
        capacity: Option<u8>,
    },
}

fn invoke(
    device: &Device<'_>,
    fabric: FabricIndex,
    cluster: u32,
    command: u32,
    fields: Option<&[u8]>,
    group: Option<GroupId>,
) -> Answer {
    let data = CommandData {
        fields,
        ..CommandData::new(CommandPath::command(1, cluster, command))
    };
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 4096];
    let access = AllowAll;
    let handler = (device.groups, &device.scenes);
    let server = Server::new(device.node, &access, &handler, 8);
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
        InvokeResponse::Command(command) => decode(command.fields.expect("fields"), command.path),
    }
}

/// Reads a Scenes response, whose field numbering depends on which command answered.
fn decode(fields: &[u8], path: CommandPath) -> Answer {
    let membership = path.command == Some(scenes::GET_SCENE_MEMBERSHIP_RESPONSE);
    let mut reader = matter_kit::tlv::TlvReader::new_in(fields, ContainerKind::Structure);
    let outer = reader.next_element().unwrap().unwrap();
    assert_eq!(outer.value.container(), Some(ContainerKind::Structure));
    let mut out = Answer::Response {
        status: 0,
        group: 0,
        scene: None,
        transition: None,
        name: None,
        list: None,
        capacity: None,
    };
    let Answer::Response {
        status,
        group,
        scene,
        transition,
        name,
        list,
        capacity,
    } = &mut out
    else {
        unreachable!()
    };
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        let index = field.tag.context().unwrap();
        match (membership, index, &field.value) {
            (_, 0, Value::Unsigned(value)) => *status = *value as u8,
            (true, 1, Value::Unsigned(value)) => *capacity = Some(*value as u8),
            (true, 1, Value::Null) => *capacity = None,
            (true, 2, Value::Unsigned(value)) => *group = *value as u16,
            (false, 1, Value::Unsigned(value)) => *group = *value as u16,
            (false, 2, Value::Unsigned(value)) => *scene = Some(*value as u8),
            (false, 3, Value::Unsigned(value)) => *transition = Some(*value as u32),
            (false, 4, Value::Utf8(text)) => *name = Some(text.to_string()),
            (true, 3, _) => {
                let mut found = Vec::new();
                loop {
                    let entry = reader.next_element().unwrap().unwrap();
                    if entry.value == Value::EndOfContainer {
                        break;
                    }
                    match entry.value {
                        Value::Unsigned(value) => found.push(value as u8),
                        _ => panic!("scene ids are unsigned"),
                    }
                }
                *list = Some(found);
            }
            _ => reader.skip_value(&field).unwrap(),
        }
    }
    out
}

// --- Encoders --------------------------------------------------------------------------------

/// An `AddScene` payload whose single extension field set sets On/Off's `OnOff`.
fn add_scene(group: u16, scene: u8, transition: u32, name: &str, on: Option<bool>) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(scene)).unwrap();
    w.unsigned(Tag::Context(2), u64::from(transition)).unwrap();
    w.utf8(Tag::Context(3), name).unwrap();
    w.start_array(Tag::Context(4)).unwrap();
    if let Some(on) = on {
        w.start_structure(Tag::Anonymous).unwrap();
        w.unsigned(Tag::Context(0), u64::from(matter_kit::clusters::on_off::ID))
            .unwrap();
        w.start_array(Tag::Context(1)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.unsigned(
            Tag::Context(0),
            u64::from(matter_kit::clusters::on_off::ON_OFF),
        )
        .unwrap();
        w.unsigned(Tag::Context(1), u64::from(on)).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn group_scene(group: u16, scene: u8) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(scene)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn just_group(group: u16) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn recall(group: u16, scene: u8, transition: Option<Option<u32>>) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(scene)).unwrap();
    match transition {
        Some(Some(ms)) => w.unsigned(Tag::Context(2), u64::from(ms)).unwrap(),
        Some(None) => w.null(Tag::Context(2)).unwrap(),
        None => {}
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn join(device: &Device<'_>, fabric: FabricIndex, group: u16) {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    w.utf8(Tag::Context(1), "").unwrap();
    w.end_container().unwrap();
    let fields = w.finish().unwrap().to_vec();
    invoke(
        device,
        fabric,
        groups::ID,
        groups::ADD_GROUP,
        Some(&fields),
        None,
    );
}

fn status_of(answer: &Answer) -> u8 {
    match answer {
        Answer::Response { status, .. } => *status,
        Answer::Status(status) => panic!("expected a response command, got {status:?}"),
    }
}

const SUCCESS: u8 = 0x00;

// --- The tables ------------------------------------------------------------------------------

#[test]
fn the_cluster_matches_the_specification_for_every_feature_combination() {
    let spec = generated::find(scenes::ID).expect("Scenes Management");
    type S<'a> = Scenes<'a, Lamp, Groups<'a, 8, NeverIdentifying, Table>, 16, 256, 4>;
    for bits in [0, NAMES] {
        for optional in [Optional::NONE, S::WITH_COPY_SCENE] {
            let built = S::conforming(bits, &optional).expect("sized");
            let descriptor = built.descriptor();
            let mut defects = Vec::new();
            spec.validate(&descriptor, |defect| defects.push(defect));
            assert!(defects.is_empty(), "features {bits:#x}: {defects:?}");
        }
    }
}

#[test]
fn a_fabric_gets_half_the_table_and_no_more() {
    // §1.4.6: "less than half (rounded down towards 0) of the Scene Table entries". Sixteen
    // entries, so eight each — and the second fabric still has its eight after the first has
    // used all of its own.
    let table = Table::new(true);
    assert_eq!(table.size(), 16);
    assert_eq!(table.per_fabric(), 8);
    assert_eq!(table.capacity(A), 8);
}

// --- AddScene --------------------------------------------------------------------------------

#[test]
fn add_scene_stores_what_view_scene_returns() {
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);

    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 1500, "Movie", Some(true))),
        None,
    );
    assert_eq!(status_of(&answer), SUCCESS);
    assert!(table.contains(A, GroupId(7), 1));

    let viewed = invoke(
        &device,
        A,
        scenes::ID,
        scenes::VIEW_SCENE,
        Some(&group_scene(7, 1)),
        None,
    );
    match viewed {
        Answer::Response {
            status,
            group,
            scene,
            transition,
            name,
            ..
        } => {
            assert_eq!(status, SUCCESS);
            assert_eq!(group, 7);
            assert_eq!(scene, Some(1));
            assert_eq!(transition, Some(1500));
            assert_eq!(name.as_deref(), Some("Movie"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_scene_for_a_group_the_endpoint_has_not_joined_is_refused() {
    // §1.4.9.2.6 step 1. A scene for a group this endpoint is not in could never be recalled
    // by the groupcast it was made for.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 0, "", Some(true))),
        None,
    );
    assert_eq!(status_of(&answer), Status::InvalidCommand.value());
    assert!(!table.contains(A, GroupId(7), 1));
}

#[test]
fn group_zero_needs_no_membership() {
    // §1.4: "Scenes MAY also exist without a group, in which case the value 0 replaces the
    // group identifier" — so step 1's check is explicitly conditional on a *non-zero* group.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(0, 3, 0, "Solo", Some(true))),
        None,
    );
    assert_eq!(status_of(&answer), SUCCESS);
    assert!(table.contains(A, GroupId(0), 3));
}

#[test]
fn adding_the_same_scene_twice_replaces_it() {
    // §1.4.9.2.6 step 3: "the already existing scene entry SHALL be replaced".
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 100, "First", Some(true))),
        None,
    );
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 200, "Second", Some(false))),
        None,
    );
    assert_eq!(table.len_of_fabric(A), 1);
    let viewed = invoke(
        &device,
        A,
        scenes::ID,
        scenes::VIEW_SCENE,
        Some(&group_scene(7, 1)),
        None,
    );
    match viewed {
        Answer::Response {
            transition, name, ..
        } => {
            assert_eq!(transition, Some(200));
            assert_eq!(name.as_deref(), Some("Second"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_transition_longer_than_the_maximum_is_refused() {
    // §1.4.9.2's constraint: "max 60000000" milliseconds.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, scenes::TRANSITION_MAX + 1, "", Some(true))),
        None,
    );
    assert_eq!(status_of(&answer), Status::ConstraintError.value());
}

#[test]
fn scene_255_is_refused() {
    // §1.4.7.5's "max 254" — 255 is the undefined scene identifier `CurrentScene` reports
    // before any recall, so a scene could not be told apart from "none".
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 0xFF, 0, "", Some(true))),
        None,
    );
    assert_eq!(status_of(&answer), Status::ConstraintError.value());
}

#[test]
fn without_the_feature_the_scene_name_is_discarded() {
    // §1.4.7.5.3: "If scene names are not supported, any commands that write a scene name
    // SHALL simply discard the name, and any command that returns a scene name SHALL return
    // an empty string."
    let table = Table::new(false);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, 0);
    join(&device, A, 7);
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 0, "Movie", Some(true))),
        None,
    );
    let viewed = invoke(
        &device,
        A,
        scenes::ID,
        scenes::VIEW_SCENE,
        Some(&group_scene(7, 1)),
        None,
    );
    match viewed {
        Answer::Response { status, name, .. } => {
            assert_eq!(status, SUCCESS);
            assert_eq!(name.as_deref(), Some(""));
        }
        other => panic!("{other:?}"),
    }
}

// --- RecallScene -----------------------------------------------------------------------------

#[test]
fn recall_applies_the_stored_extension_field_sets() {
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 1500, "Movie", Some(true))),
        None,
    );
    assert_eq!(
        invoke(
            &device,
            A,
            scenes::ID,
            scenes::RECALL_SCENE,
            Some(&recall(7, 1, None)),
            None
        ),
        Answer::Status(Status::Success)
    );
    assert!(*lamp.on.borrow());
    // No TransitionTime in the command, so the scene's own is used.
    assert_eq!(*lamp.applied.borrow(), vec![(true, 1500)]);
}

#[test]
fn an_explicit_null_transition_means_the_stored_one() {
    // §1.4.9.12.4: "In all other cases (command data field not present or value equal to
    // null), the SceneTransitionTime field of the Scene Table entry SHALL indicate the
    // transition time." Absent and null are the same answer — a client that sends null must
    // not get an instant snap.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 1500, "", Some(true))),
        None,
    );
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::RECALL_SCENE,
        Some(&recall(7, 1, Some(None))),
        None,
    );
    assert_eq!(*lamp.applied.borrow(), vec![(true, 1500)]);

    // A present, non-null one overrides it.
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::RECALL_SCENE,
        Some(&recall(7, 1, Some(Some(50)))),
        None,
    );
    assert_eq!(lamp.applied.borrow()[1], (true, 50));
}

#[test]
fn recalling_a_scene_that_is_not_there_is_not_found() {
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    assert_eq!(
        invoke(
            &device,
            A,
            scenes::ID,
            scenes::RECALL_SCENE,
            Some(&recall(7, 9, None)),
            None
        ),
        Answer::Status(Status::NotFound)
    );
}

// --- StoreScene ------------------------------------------------------------------------------

#[test]
fn store_scene_captures_the_endpoint_rather_than_the_command() {
    // §1.4.9.10.3 step 3: "with ExtensionFieldSets corresponding to the current state of
    // other clusters on the same endpoint". The client sends only a group and a scene id.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    *lamp.on.borrow_mut() = true;

    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::STORE_SCENE,
        Some(&group_scene(7, 2)),
        None,
    );
    assert_eq!(status_of(&answer), SUCCESS);

    *lamp.on.borrow_mut() = false;
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::RECALL_SCENE,
        Some(&recall(7, 2, None)),
        None,
    );
    assert!(*lamp.on.borrow(), "the captured state came back");
    // A stored scene gets transition time 0 and no name.
    assert_eq!(*lamp.applied.borrow(), vec![(true, 0)]);
}

#[test]
fn storing_over_an_added_scene_keeps_its_name_and_transition() {
    // §1.4.9.10.3 step 3: "the ExtensionFieldSets of the stored scene SHALL be replaced ...
    // and the other fields of the scene table entry SHALL remain unchanged" — which is how
    // the specification's own note says to give a stored scene a name and a fade.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 2500, "Evening", None)),
        None,
    );
    *lamp.on.borrow_mut() = true;
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::STORE_SCENE,
        Some(&group_scene(7, 1)),
        None,
    );
    let viewed = invoke(
        &device,
        A,
        scenes::ID,
        scenes::VIEW_SCENE,
        Some(&group_scene(7, 1)),
        None,
    );
    match viewed {
        Answer::Response {
            transition, name, ..
        } => {
            assert_eq!(transition, Some(2500));
            assert_eq!(name.as_deref(), Some("Evening"));
        }
        other => panic!("{other:?}"),
    }
    // ...and the captured state is the new one.
    *lamp.on.borrow_mut() = false;
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::RECALL_SCENE,
        Some(&recall(7, 1, None)),
        None,
    );
    assert!(*lamp.on.borrow());
    assert_eq!(*lamp.applied.borrow(), vec![(true, 2500)]);
}

// --- Removal ---------------------------------------------------------------------------------

#[test]
fn removing_a_group_removes_its_scenes() {
    // §1.3.7.4 — the Groups chapter's rule about the Scene Table, and the reason the table is
    // a value both clusters hold rather than state hidden inside one of them.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    join(&device, A, 8);
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 0, "", Some(true))),
        None,
    );
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(8, 1, 0, "", Some(true))),
        None,
    );

    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 7).unwrap();
    w.end_container().unwrap();
    let fields = w.finish().unwrap().to_vec();
    invoke(
        &device,
        A,
        groups::ID,
        groups::REMOVE_GROUP,
        Some(&fields),
        None,
    );

    assert!(
        !table.contains(A, GroupId(7), 1),
        "group 7's scene went too"
    );
    assert!(table.contains(A, GroupId(8), 1), "group 8's scene stayed");
}

#[test]
fn removing_all_groups_leaves_only_the_ungrouped_scenes() {
    // §1.3.7.5: "all scenes, except for scenes associated with group ID 0, SHALL be removed".
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 0, "", Some(true))),
        None,
    );
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(0, 5, 0, "", Some(true))),
        None,
    );
    invoke(
        &device,
        A,
        groups::ID,
        groups::REMOVE_ALL_GROUPS,
        None,
        None,
    );
    assert!(!table.contains(A, GroupId(7), 1));
    assert!(table.contains(A, GroupId(0), 5), "group 0 is not a group");
}

#[test]
fn remove_all_scenes_takes_one_group_and_leaves_the_rest() {
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    join(&device, A, 8);
    for group in [7u16, 8] {
        invoke(
            &device,
            A,
            scenes::ID,
            scenes::ADD_SCENE,
            Some(&add_scene(group, 1, 0, "", Some(true))),
            None,
        );
    }
    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::REMOVE_ALL_SCENES,
        Some(&just_group(7)),
        None,
    );
    assert_eq!(status_of(&answer), SUCCESS);
    assert!(!table.contains(A, GroupId(7), 1));
    assert!(table.contains(A, GroupId(8), 1));
}

// --- Fabric scoping --------------------------------------------------------------------------

#[test]
fn two_fabrics_can_use_the_same_group_and_scene_ids() {
    // §1.4.6: "implementations SHALL ensure that scenes with identical Group ID and Scene ID
    // across fabrics will only access the data for the accessing fabric, so that the same
    // identifier values used by different accessing fabrics do not cause mixing or
    // overwriting of another fabric's scenes."
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    join(&device, B, 7);
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 100, "Mine", Some(true))),
        None,
    );
    invoke(
        &device,
        B,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 200, "Yours", Some(false))),
        None,
    );
    assert_eq!(table.len(), 2);

    for (fabric, transition, name) in [(A, 100u32, "Mine"), (B, 200, "Yours")] {
        let viewed = invoke(
            &device,
            fabric,
            scenes::ID,
            scenes::VIEW_SCENE,
            Some(&group_scene(7, 1)),
            None,
        );
        match viewed {
            Answer::Response {
                transition: t,
                name: n,
                ..
            } => {
                assert_eq!(t, Some(transition));
                assert_eq!(n.as_deref(), Some(name));
            }
            other => panic!("{other:?}"),
        }
    }

    // ...and removing one leaves the other.
    invoke(
        &device,
        A,
        scenes::ID,
        scenes::REMOVE_SCENE,
        Some(&group_scene(7, 1)),
        None,
    );
    assert!(!table.contains(A, GroupId(7), 1));
    assert!(table.contains(B, GroupId(7), 1));
}

#[test]
fn one_fabric_cannot_exhaust_the_table() {
    // The point of §1.4.6's ceiling: eight of sixteen, and the second ecosystem still has its
    // own eight rather than a table somebody else filled.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    join(&device, B, 7);
    for scene in 1..=8u8 {
        let answer = invoke(
            &device,
            A,
            scenes::ID,
            scenes::ADD_SCENE,
            Some(&add_scene(7, scene, 0, "", Some(true))),
            None,
        );
        assert_eq!(status_of(&answer), SUCCESS, "scene {scene}");
    }
    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 9, 0, "", Some(true))),
        None,
    );
    assert_eq!(status_of(&answer), Status::ResourceExhausted.value());
    assert_eq!(table.capacity(A), 0);
    assert_eq!(table.capacity(B), 8);

    let answer = invoke(
        &device,
        B,
        scenes::ID,
        scenes::ADD_SCENE,
        Some(&add_scene(7, 1, 0, "", Some(true))),
        None,
    );
    assert_eq!(status_of(&answer), SUCCESS);
}

#[test]
fn a_command_without_an_accessing_fabric_is_refused() {
    // §1.4.6: "Any attribute read, attribute write or command invoked on the server when no
    // accessing fabric is available SHALL fail with a status code of UNSUPPORTED_ACCESS."
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    let fields = add_scene(0, 1, 0, "", Some(true));
    let data = CommandData {
        fields: Some(&fields),
        ..CommandData::new(CommandPath::command(1, scenes::ID, scenes::ADD_SCENE))
    };
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 4096];
    let access = AllowAll;
    let handler = (device.groups, &device.scenes);
    let server = Server::new(device.node, &access, &handler, 8);
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
        InvokeResponse::Command(_) => panic!("no fabric, no scene"),
    }
    assert!(table.is_empty());
}

// --- GetSceneMembership ----------------------------------------------------------------------

#[test]
fn get_scene_membership_lists_one_groups_scenes_with_the_capacity_left() {
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    join(&device, A, 8);
    for (group, scene) in [(7u16, 1u8), (7, 4), (8, 2)] {
        invoke(
            &device,
            A,
            scenes::ID,
            scenes::ADD_SCENE,
            Some(&add_scene(group, scene, 0, "", Some(true))),
            None,
        );
    }
    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::GET_SCENE_MEMBERSHIP,
        Some(&just_group(7)),
        None,
    );
    match answer {
        Answer::Response {
            status,
            group,
            list,
            capacity,
            ..
        } => {
            assert_eq!(status, SUCCESS);
            assert_eq!(group, 7);
            assert_eq!(list, Some(vec![1, 4]));
            // Three of this fabric's eight used.
            assert_eq!(capacity, Some(5));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn membership_of_an_unjoined_group_omits_the_scene_list() {
    // §1.4.9.14.4: "If the status is not SUCCESS then this field SHALL be omitted" — a client
    // must not read an empty list as "this group has no scenes".
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    let answer = invoke(
        &device,
        A,
        scenes::ID,
        scenes::GET_SCENE_MEMBERSHIP,
        Some(&just_group(7)),
        None,
    );
    match answer {
        Answer::Response { status, list, .. } => {
            assert_eq!(status, Status::InvalidCommand.value());
            assert_eq!(list, None);
        }
        other => panic!("{other:?}"),
    }
}

// --- Groupcast -------------------------------------------------------------------------------

#[test]
fn a_groupcast_is_acted_on_but_never_answered() {
    // §1.4.9's last step for every command. Twenty lights answering one multicast at the same
    // instant is the storm the rule exists to prevent.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    let cast = Some(GroupId(7));

    assert_eq!(
        invoke(
            &device,
            A,
            scenes::ID,
            scenes::ADD_SCENE,
            Some(&add_scene(7, 1, 0, "", Some(true))),
            cast
        ),
        Answer::Status(Status::Success)
    );
    assert!(table.contains(A, GroupId(7), 1));

    for (command, fields) in [
        (scenes::VIEW_SCENE, group_scene(7, 1)),
        (scenes::GET_SCENE_MEMBERSHIP, just_group(7)),
        (scenes::STORE_SCENE, group_scene(7, 1)),
        (scenes::REMOVE_SCENE, group_scene(7, 1)),
        (scenes::REMOVE_ALL_SCENES, just_group(7)),
    ] {
        assert_eq!(
            invoke(&device, A, scenes::ID, command, Some(&fields), cast),
            Answer::Status(Status::Success),
            "command {command:#x} answered a groupcast"
        );
    }
    assert!(!table.contains(A, GroupId(7), 1));
}

// --- FabricSceneInfo -------------------------------------------------------------------------

#[test]
fn recalling_a_scene_invalidates_every_other_fabrics_view() {
    // §1.4.7.2.4: SceneValid "SHALL be set to False for all other fabrics when ... the current
    // scene is modified by a fabric through the RecallScene or StoreScene commands". The
    // endpoint can only match one fabric's idea of the scene at a time.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    join(&device, B, 7);
    for fabric in [A, B] {
        invoke(
            &device,
            fabric,
            scenes::ID,
            scenes::ADD_SCENE,
            Some(&add_scene(7, 1, 0, "", Some(fabric == A))),
            None,
        );
        invoke(
            &device,
            fabric,
            scenes::ID,
            scenes::RECALL_SCENE,
            Some(&recall(7, 1, None)),
            None,
        );
    }
    // B recalled last, so only B's view is still valid.
    let info = read_fabric_scene_info(&device, A);
    assert_eq!(info.len(), 2);
    assert_eq!(info[0], (A, 1u8, 7u16, false, 1u8, 7u8));
    assert_eq!(info[1], (B, 1, 7, true, 1, 7));

    // Any S-quality attribute changing by other means invalidates them all — turning the
    // light on by hand means the endpoint matches nobody's scene.
    table.invalidate();
    let info = read_fabric_scene_info(&device, A);
    assert!(info.iter().all(|entry| !entry.3));
}

#[test]
fn a_filtered_read_shows_only_the_accessing_fabric() {
    // §7.19.1.8.2. Without this, one administrator learns exactly which scenes another has.
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    join(&device, A, 7);
    join(&device, B, 7);
    for fabric in [A, B] {
        invoke(
            &device,
            fabric,
            scenes::ID,
            scenes::ADD_SCENE,
            Some(&add_scene(7, 1, 0, "", Some(true))),
            None,
        );
        invoke(
            &device,
            fabric,
            scenes::ID,
            scenes::RECALL_SCENE,
            Some(&recall(7, 1, None)),
            None,
        );
    }
    let filtered = read_fabric_scene_info_filtered(&device, A, true);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].0, A);
}

/// Reads `FabricSceneInfo` unfiltered, as `(fabric, scene, group, valid, count, capacity)`.
fn read_fabric_scene_info(
    device: &Device<'_>,
    fabric: FabricIndex,
) -> Vec<(FabricIndex, u8, u16, bool, u8, u8)> {
    read_fabric_scene_info_filtered(device, fabric, false)
}

fn read_fabric_scene_info_filtered(
    device: &Device<'_>,
    fabric: FabricIndex,
    filtered: bool,
) -> Vec<(FabricIndex, u8, u16, bool, u8, u8)> {
    use matter_kit::im::ClusterHandler;
    let mut buf = [0u8; 1024];
    let mut w = TlvWriter::new(&mut buf);
    let resolved = device
        .node
        .resolve(1, scenes::ID, scenes::FABRIC_SCENE_INFO)
        .expect("FabricSceneInfo");
    let mut ctx = InteractionContext::new().with_fabric(fabric);
    ctx.fabric_filtered = filtered;
    device
        .scenes
        .read(&resolved, &ctx, &mut w, Tag::Anonymous)
        .expect("read");
    let bytes = w.finish().unwrap();
    let mut reader = matter_kit::tlv::TlvReader::new(bytes);
    let array = reader.next_element().unwrap().unwrap();
    assert_eq!(array.value.container(), Some(ContainerKind::Array));
    let mut out = Vec::new();
    loop {
        let entry = reader.next_element().unwrap().unwrap();
        if entry.value == Value::EndOfContainer {
            break;
        }
        let (mut count, mut scene, mut group, mut valid, mut capacity, mut index) =
            (0u8, 0u8, 0u16, false, 0u8, 0u8);
        loop {
            let field = reader.next_element().unwrap().unwrap();
            if field.value == Value::EndOfContainer {
                break;
            }
            match (field.tag.context(), &field.value) {
                (Some(0), Value::Unsigned(value)) => count = *value as u8,
                (Some(1), Value::Unsigned(value)) => scene = *value as u8,
                (Some(2), Value::Unsigned(value)) => group = *value as u16,
                (Some(3), Value::Bool(value)) => valid = *value,
                (Some(4), Value::Unsigned(value)) => capacity = *value as u8,
                (Some(254), Value::Unsigned(value)) => index = *value as u8,
                _ => reader.skip_value(&field).unwrap(),
            }
        }
        out.push((FabricIndex(index), scene, group, valid, count, capacity));
    }
    out
}

#[test]
fn the_table_size_is_what_the_device_reserved() {
    use matter_kit::im::ClusterHandler;
    let table = Table::new(true);
    let lamp = Lamp::default();
    let device = device(&table, &lamp, NAMES);
    let mut buf = [0u8; 32];
    let mut w = TlvWriter::new(&mut buf);
    let resolved = device
        .node
        .resolve(1, scenes::ID, scenes::SCENE_TABLE_SIZE)
        .expect("SceneTableSize");
    device
        .scenes
        .read(
            &resolved,
            &InteractionContext::new().with_fabric(A),
            &mut w,
            Tag::Anonymous,
        )
        .expect("read");
    let bytes = w.finish().unwrap();
    let mut reader = matter_kit::tlv::TlvReader::new(bytes);
    assert_eq!(
        reader.next_element().unwrap().unwrap().unsigned().unwrap(),
        16
    );
}
