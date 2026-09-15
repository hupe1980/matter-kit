//! Group Key Management (Core §11.2), driven through the cluster interface.
//!
//! This is where an administrator installs the keys that make groupcast work, and the rule that
//! carries the cluster is the one about what comes back out: §11.2.7.2 replaces every epoch key
//! with null in a `KeySetRead`. A device that echoed them would let anyone with Administer
//! privilege — including an administrator on its way out — walk off with the key to every group
//! message the node will ever send.
//!
//! The rest is §11.2.7.1's validation, which is a list of eleven checks in a specific order,
//! each with its own status code. The order is what lets a client tell a malformed key from a
//! malformed *rotation*.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::clusters::group_key_management::{self as gkm, GroupKeyManagement, GroupTable};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::group::keys::GroupKeys;
use matter_kit::im::{ClusterHandler, EndpointId, InteractionContext, Status, WriteOp};
use matter_kit::msg::{FabricIndex, GroupId};
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

const F1: FabricIndex = FabricIndex(1);
const F2: FabricIndex = FabricIndex(2);
const KEY: [u8; 16] = [0x42; 16];

/// A node whose lights are in group 1 on two endpoints, and a kitchen light in group 2.
#[derive(Debug, Default)]
struct Memberships;

impl GroupTable for Memberships {
    fn memberships(&self, each: &mut dyn FnMut(FabricIndex, GroupId, EndpointId)) {
        each(F1, GroupId(1), 1);
        each(F1, GroupId(1), 2);
        each(F1, GroupId(2), 3);
        each(F2, GroupId(9), 1);
    }

    fn name(&self, fabric: FabricIndex, group: GroupId) -> Option<&str> {
        (fabric == F1 && group == GroupId(1)).then_some("Living room")
    }
}

type Keys = GroupKeys<4, 8>;
type Cluster<'a> = GroupKeyManagement<'a, Memberships, 4, 8>;

struct Fixture {
    node: Node<'static>,
    keys: RefCell<Keys>,
    table: Memberships,
}

fn fixture() -> Fixture {
    let conforming = Box::leak(Box::new(
        Cluster::conforming(0, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(0, clusters)]));
    Fixture {
        node: Node::new(endpoints),
        keys: RefCell::new(Keys::new(4, 3)),
        table: Memberships,
    }
}

impl Fixture {
    fn cluster(&self) -> Cluster<'_> {
        GroupKeyManagement::new(&self.keys, &self.table)
    }

    fn invoke(
        &self,
        command: u32,
        fields: &[u8],
        ctx: &InteractionContext<'_>,
    ) -> Result<Vec<u8>, Status> {
        let cluster = self.cluster();
        let resolved = self
            .node
            .resolve_command(0, gkm::ID, command)
            .expect("the command exists");
        let mut buf = [0u8; 1024];
        let mut w = TlvWriter::new(&mut buf);
        let response = cluster
            .invoke(&resolved, Some(fields), ctx, &mut w, Tag::Anonymous)
            .map_err(|s| s.status)?;
        if response.is_none() {
            return Ok(Vec::new());
        }
        Ok(w.finish().expect("finish").to_vec())
    }

    fn read(&self, attribute: u32, ctx: &InteractionContext<'_>) -> Result<Vec<u8>, Status> {
        let cluster = self.cluster();
        let resolved = self
            .node
            .resolve(0, gkm::ID, attribute)
            .expect("the path exists");
        let mut buf = [0u8; 1024];
        let mut w = TlvWriter::new(&mut buf);
        cluster.read(&resolved, ctx, &mut w, Tag::Anonymous)?;
        Ok(w.finish().expect("finish").to_vec())
    }

    fn write(&self, data: &[u8], op: WriteOp, ctx: &InteractionContext<'_>) -> Result<(), Status> {
        let cluster = self.cluster();
        let resolved = self
            .node
            .resolve(0, gkm::ID, gkm::GROUP_KEY_MAP)
            .expect("the path exists");
        cluster.write(&resolved, data, op, ctx)
    }
}

fn on(fabric: FabricIndex) -> InteractionContext<'static> {
    InteractionContext::default().with_fabric(fabric)
}

/// A `KeySetWrite` payload. `epochs` is `(key, start time)` per slot, `None` for null.
fn key_set_write(id: u16, policy: u8, epochs: &[(Option<&[u8]>, Option<u64>)]) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.start_structure(Tag::Context(0)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(id)).unwrap();
    w.unsigned(Tag::Context(1), u64::from(policy)).unwrap();
    // Every slot is mandatory-with-`X`: a client that omitted EpochKey1 entirely would be
    // sending a struct the schema does not describe, so absent slots go out as null.
    let mut all: Vec<(Option<&[u8]>, Option<u64>)> = epochs.to_vec();
    while all.len() < 3 {
        all.push((None, None));
    }
    for (slot, (key, start)) in all.iter().enumerate() {
        let key_tag = Tag::Context(2 + (slot as u8 * 2));
        let start_tag = Tag::Context(3 + (slot as u8 * 2));
        match key {
            Some(key) => w.octets(key_tag, key).unwrap(),
            None => w.null(key_tag).unwrap(),
        }
        match start {
            Some(start) => w.unsigned(start_tag, *start).unwrap(),
            None => w.null(start_tag).unwrap(),
        }
    }
    w.unsigned(Tag::Context(254), 0).unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// A one-field command payload.
fn one_u16(tag: u8, value: u16) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(tag), u64::from(value)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn good_set(id: u16) -> Vec<u8> {
    key_set_write(id, 0, &[(Some(&KEY), Some(1_000))])
}

/// Reads a container into `(tag, value)` pairs, walking into whatever is nested.
fn fields(bytes: &[u8]) -> Vec<(u8, Value<'_>)> {
    let mut reader = TlvReader::new(bytes);
    let outer = reader.next_element().unwrap().unwrap();
    assert!(outer.value.container().is_some());
    let mut out = Vec::new();
    let mut depth = 0usize;
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            if depth == 0 {
                break;
            }
            depth -= 1;
            continue;
        }
        if field.value.container().is_some() {
            depth += 1;
        }
        out.push((field.tag.context().unwrap_or(255), field.value));
    }
    out
}

// --- §11.2.7.1: what a valid key set looks like -------------------------------------------

#[test]
fn a_key_set_is_written_and_can_be_used() {
    let fixture = fixture();
    fixture
        .invoke(gkm::KEY_SET_WRITE, &good_set(7), &on(F1))
        .expect("written");
    assert_eq!(fixture.keys.borrow().key_sets().len(), 1);
    assert!(fixture.keys.borrow().key_set(F1, 7).is_some());
    // And it is scoped to the fabric that wrote it.
    assert!(fixture.keys.borrow().key_set(F2, 7).is_none());
}

#[test]
fn every_validation_failure_has_its_own_status() {
    let fixture = fixture();
    let ctx = on(F1);
    let short: &[u8] = &[0u8; 15];

    for (name, payload, expected) in [
        (
            "EpochKey0 null",
            key_set_write(7, 0, &[(None, Some(1))]),
            Status::InvalidCommand,
        ),
        (
            "EpochStartTime0 null",
            key_set_write(7, 0, &[(Some(&KEY), None)]),
            Status::InvalidCommand,
        ),
        (
            "EpochStartTime0 zero",
            key_set_write(7, 0, &[(Some(&KEY), Some(0))]),
            Status::InvalidCommand,
        ),
        (
            "EpochKey0 not sixteen octets",
            key_set_write(7, 0, &[(Some(short), Some(1))]),
            Status::ConstraintError,
        ),
        (
            "EpochKey1 with no start time",
            key_set_write(7, 0, &[(Some(&KEY), Some(1)), (Some(&KEY), None)]),
            Status::InvalidCommand,
        ),
        (
            "EpochStartTime1 with no key",
            key_set_write(7, 0, &[(Some(&KEY), Some(1)), (None, Some(2))]),
            Status::InvalidCommand,
        ),
        (
            "EpochStartTime1 not later than EpochStartTime0",
            key_set_write(7, 0, &[(Some(&KEY), Some(5)), (Some(&KEY), Some(5))]),
            Status::InvalidCommand,
        ),
        (
            "EpochKey1 not sixteen octets",
            key_set_write(7, 0, &[(Some(&KEY), Some(1)), (Some(short), Some(2))]),
            Status::ConstraintError,
        ),
        (
            "EpochKey2 with a hole before it",
            key_set_write(
                7,
                0,
                &[(Some(&KEY), Some(1)), (None, None), (Some(&KEY), Some(3))],
            ),
            Status::InvalidCommand,
        ),
        (
            "EpochStartTime2 not later than EpochStartTime1",
            key_set_write(
                7,
                0,
                &[
                    (Some(&KEY), Some(1)),
                    (Some(&KEY), Some(5)),
                    (Some(&KEY), Some(5)),
                ],
            ),
            Status::InvalidCommand,
        ),
    ] {
        assert_eq!(
            fixture.invoke(gkm::KEY_SET_WRITE, &payload, &ctx),
            Err(expected),
            "{name}"
        );
    }
    assert!(
        fixture.keys.borrow().key_sets().is_empty(),
        "nothing stored"
    );

    // Three keys in ascending order is the shape a rotation actually takes.
    assert!(
        fixture
            .invoke(
                gkm::KEY_SET_WRITE,
                &key_set_write(
                    7,
                    0,
                    &[
                        (Some(&KEY), Some(1)),
                        (Some(&KEY), Some(2)),
                        (Some(&KEY), Some(3))
                    ]
                ),
                &ctx
            )
            .is_ok()
    );
}

#[test]
fn a_write_replaces_the_whole_set() {
    // §4.17.3.2: "Any update of the key set, including a partial update, SHALL remove all
    // previous keys in the set, however many were defined." A merge would leave a node holding
    // a key the administrator believed it had withdrawn.
    let fixture = fixture();
    let ctx = on(F1);
    fixture
        .invoke(
            gkm::KEY_SET_WRITE,
            &key_set_write(7, 0, &[(Some(&KEY), Some(1)), (Some(&KEY), Some(2))]),
            &ctx,
        )
        .unwrap();
    assert_eq!(
        fixture
            .keys
            .borrow()
            .key_set(F1, 7)
            .unwrap()
            .epoch_keys
            .len(),
        2
    );

    fixture
        .invoke(gkm::KEY_SET_WRITE, &good_set(7), &ctx)
        .unwrap();
    assert_eq!(
        fixture
            .keys
            .borrow()
            .key_set(F1, 7)
            .unwrap()
            .epoch_keys
            .len(),
        1,
        "the second key is gone, not kept"
    );
}

// --- §11.2.7.2: keys do not come back out --------------------------------------------------

#[test]
fn a_key_set_read_returns_nulls_where_the_keys_were() {
    // §11.2.7.2: "the contents of that Group Key Set SHALL be sent in a KeySetReadResponse
    // command, but with the EpochKey0, EpochKey1 and EpochKey2 fields replaced by null."
    let fixture = fixture();
    let ctx = on(F1);
    fixture
        .invoke(
            gkm::KEY_SET_WRITE,
            &key_set_write(
                7,
                0,
                &[(Some(&KEY), Some(1_000)), (Some(&KEY), Some(2_000))],
            ),
            &ctx,
        )
        .unwrap();

    let response = fixture
        .invoke(gkm::KEY_SET_READ, &one_u16(0, 7), &ctx)
        .expect("read");
    let decoded = fields(&response);
    // Field 0 is the struct; inside it, 0 = id, 1 = policy, 2/4/6 = keys, 3/5/7 = start times.
    assert_eq!(decoded[1], (0, Value::Unsigned(7)));
    assert_eq!(
        decoded[2],
        (1, Value::Unsigned(0)),
        "the policy is not secret"
    );
    assert_eq!(decoded[3], (2, Value::Null), "EpochKey0");
    assert_eq!(
        decoded[4],
        (3, Value::Unsigned(1_000)),
        "its start time is not"
    );
    assert_eq!(decoded[5], (4, Value::Null), "EpochKey1");
    assert_eq!(decoded[6], (5, Value::Unsigned(2_000)));
    assert_eq!(decoded[7], (6, Value::Null), "EpochKey2");
    assert_eq!(decoded[8], (7, Value::Null), "and no third start time");

    // Nowhere in the response is the key itself.
    assert!(
        !response.windows(KEY.len()).any(|w| w == KEY),
        "the epoch key must not appear anywhere in the response"
    );
}

#[test]
fn a_key_set_of_another_fabric_is_not_found() {
    let fixture = fixture();
    fixture
        .invoke(gkm::KEY_SET_WRITE, &good_set(7), &on(F1))
        .unwrap();
    assert_eq!(
        fixture.invoke(gkm::KEY_SET_READ, &one_u16(0, 7), &on(F2)),
        Err(Status::NotFound)
    );
    assert_eq!(
        fixture.invoke(gkm::KEY_SET_READ, &one_u16(0, 99), &on(F1)),
        Err(Status::NotFound)
    );
}

// --- §11.2.7.4, §11.2.7.5 ------------------------------------------------------------------

#[test]
fn removing_key_set_zero_is_refused() {
    // §11.2.7.4: key set 0 is the IPK's, and "the only method to remove the IPK is usage of the
    // RemoveFabric command".
    let fixture = fixture();
    assert_eq!(
        fixture.invoke(gkm::KEY_SET_REMOVE, &one_u16(0, 0), &on(F1)),
        Err(Status::InvalidCommand)
    );
}

#[test]
fn removing_a_key_set_takes_its_group_mappings_with_it() {
    let fixture = fixture();
    let ctx = on(F1);
    fixture
        .invoke(gkm::KEY_SET_WRITE, &good_set(7), &ctx)
        .unwrap();
    fixture
        .keys
        .borrow_mut()
        .map_group(F1, GroupId(1), 7)
        .unwrap();

    fixture
        .invoke(gkm::KEY_SET_REMOVE, &one_u16(0, 7), &ctx)
        .expect("removed");
    assert!(fixture.keys.borrow().map().is_empty());
    assert_eq!(
        fixture.invoke(gkm::KEY_SET_REMOVE, &one_u16(0, 7), &ctx),
        Err(Status::NotFound)
    );
}

#[test]
fn read_all_indices_lists_this_fabrics_key_sets_only() {
    let fixture = fixture();
    fixture
        .invoke(gkm::KEY_SET_WRITE, &good_set(7), &on(F1))
        .unwrap();
    fixture
        .invoke(gkm::KEY_SET_WRITE, &good_set(8), &on(F1))
        .unwrap();
    fixture
        .invoke(gkm::KEY_SET_WRITE, &good_set(9), &on(F2))
        .unwrap();

    let response = fixture
        .invoke(gkm::KEY_SET_READ_ALL_INDICES, &one_u16(0, 0), &on(F1))
        .expect("read");
    let ids: Vec<u64> = fields(&response)
        .into_iter()
        .filter_map(|(_, v)| match v {
            Value::Unsigned(n) => Some(n),
            _ => None,
        })
        .collect();
    assert_eq!(ids, vec![7, 8]);
}

// --- §11.2.6: the two list attributes -------------------------------------------------------

#[test]
fn the_group_key_map_is_written_and_read_back() {
    let fixture = fixture();
    let ctx = on(F1);
    fixture
        .invoke(gkm::KEY_SET_WRITE, &good_set(7), &ctx)
        .unwrap();

    // One append, the way a controller writes a list item by item.
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(2)).unwrap();
    w.unsigned(Tag::Context(1), 1).unwrap();
    w.unsigned(Tag::Context(2), 7).unwrap();
    w.unsigned(Tag::Context(254), 0).unwrap();
    w.end_container().unwrap();
    let entry = w.finish().unwrap().to_vec();
    fixture
        .write(&entry, WriteOp::Append, &ctx)
        .expect("append");

    let read = fixture.read(gkm::GROUP_KEY_MAP, &ctx).expect("read");
    let decoded = fields(&read);
    assert_eq!(decoded[1], (1, Value::Unsigned(1)), "GroupId");
    assert_eq!(decoded[2], (2, Value::Unsigned(7)), "GroupKeySetID");
    assert_eq!(
        decoded[3],
        (254, Value::Unsigned(1)),
        "the accessing fabric"
    );
}

#[test]
fn a_map_entry_pointing_at_no_key_set_is_refused() {
    // §11.2.6.1: an entry that names a key set the node does not have is a group that silently
    // cannot send or receive anything.
    let fixture = fixture();
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(2)).unwrap();
    w.unsigned(Tag::Context(1), 1).unwrap();
    w.unsigned(Tag::Context(2), 42).unwrap();
    w.unsigned(Tag::Context(254), 0).unwrap();
    w.end_container().unwrap();
    let entry = w.finish().unwrap().to_vec();
    assert_eq!(
        fixture.write(&entry, WriteOp::Append, &on(F1)),
        Err(Status::NotFound)
    );
}

#[test]
fn the_group_table_is_the_groups_clusters_data() {
    // §11.2.6.2: "The content of this attribute reflects data managed via the Groups cluster",
    // one entry per group with every endpoint that group is on.
    let fixture = fixture();
    let read = fixture.read(gkm::GROUP_TABLE, &on(F1)).expect("read");
    let mut reader = TlvReader::new(&read);
    assert_eq!(
        reader.next_element().unwrap().unwrap().value.container(),
        Some(ContainerKind::Array)
    );

    let mut groups = Vec::new();
    loop {
        let item = reader.next_element().unwrap().unwrap();
        if item.value == Value::EndOfContainer {
            break;
        }
        let mut group = 0u64;
        let mut endpoints = Vec::new();
        let mut name = None;
        let mut fabric = 0u64;
        loop {
            let field = reader.next_element().unwrap().unwrap();
            if field.value == Value::EndOfContainer {
                break;
            }
            match (field.tag.context(), &field.value) {
                (Some(1), Value::Unsigned(v)) => group = *v,
                (Some(2), _) => loop {
                    let e = reader.next_element().unwrap().unwrap();
                    if e.value == Value::EndOfContainer {
                        break;
                    }
                    if let Value::Unsigned(v) = e.value {
                        endpoints.push(v);
                    }
                },
                (Some(3), Value::Utf8(v)) => name = Some((*v).to_string()),
                (Some(254), Value::Unsigned(v)) => fabric = *v,
                _ => reader.skip_value(&field).unwrap(),
            }
        }
        groups.push((group, endpoints, name, fabric));
    }

    assert_eq!(groups.len(), 3, "two groups on F1 and one on F2");
    assert_eq!(groups[0].0, 1);
    assert_eq!(groups[0].1, vec![1, 2], "both endpoints, in one entry");
    assert_eq!(groups[0].2.as_deref(), Some("Living room"));
    assert_eq!(groups[0].3, 1);
    assert_eq!(groups[1].1, vec![3]);
    assert_eq!(groups[2].3, 2);
}

#[test]
fn a_fabric_filtered_read_shows_one_fabric_its_own() {
    let fixture = fixture();
    let mut ctx = on(F1);
    ctx.fabric_filtered = true;
    let read = fixture.read(gkm::GROUP_TABLE, &ctx).expect("read");
    let fabrics: Vec<u64> = fields(&read)
        .into_iter()
        .filter_map(|(tag, v)| match (tag, v) {
            (254, Value::Unsigned(n)) => Some(n),
            _ => None,
        })
        .collect();
    assert_eq!(fabrics, vec![1, 1], "F2's group is not in this read");
}

#[test]
fn the_group_table_cannot_be_written() {
    // §11.2.6.2's access is `R F`: it is the Groups cluster's data, and writing it here would
    // let an administrator claim a membership no endpoint has.
    let fixture = fixture();
    let cluster = fixture.cluster();
    let resolved = fixture
        .node
        .resolve(0, gkm::ID, gkm::GROUP_TABLE)
        .expect("the path exists");
    assert_eq!(
        cluster.write(&resolved, &[], WriteOp::Replace, &on(F1)),
        Err(Status::UnsupportedWrite)
    );
}

#[test]
fn a_command_with_no_accessing_fabric_is_refused() {
    // §11.2.7: "All commands in this cluster SHALL be scoped to the accessing fabric."
    let fixture = fixture();
    assert_eq!(
        fixture.invoke(
            gkm::KEY_SET_WRITE,
            &good_set(7),
            &InteractionContext::default()
        ),
        Err(Status::UnsupportedAccess)
    );
}
