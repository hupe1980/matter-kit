//! The Groupcast cluster (Core §11.27). **Provisional.**
//!
//! One command where there used to be three clusters' worth of choreography: `JoinGroup` takes
//! the group, the endpoints, the key set and the key, and leaves the node able to send and
//! receive — which this file checks by actually sending through [`group::wire`] afterwards.
//!
//! The rules worth pinning are the ones that make it *simpler* than what it replaces, and each
//! is a place where a helpful implementation goes wrong:
//!
//! * A sender joins with **no** endpoints and a listener with at least one. §11.27.4.2: "Being a
//!   sender does not imply the ability to listen." Accepting either shape from either kind of
//!   device makes a group that silently never works.
//! * The root endpoint is never in a group. §11.27.7.1 step 3c: `UNSUPPORTED_ENDPOINT`.
//! * One fabric may use at most **half** the membership table (§11.27.6.1), so the first
//!   ecosystem to commission cannot leave the second unable to form a group at all.

#![cfg(all(feature = "std", feature = "rustcrypto", feature = "provisional"))]
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
use matter_kit::Config;

use matter_kit::clusters::groupcast::{
    self as gc, FEATURE_LISTENER, FEATURE_PER_GROUP_ADDRESS, FEATURE_SENDER, Groupcast,
    MulticastAddrPolicyEnum,
};
use matter_kit::dm::access::Privilege;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::fabric::CompressedFabricId;
use matter_kit::group::keys::GroupKeys;
use matter_kit::group::peers::PeerTable;
use matter_kit::group::wire::{self, Received, Sender};
use matter_kit::im::{ClusterHandler, InteractionContext, Status};
use matter_kit::msg::{ExchangeId, FabricIndex, GroupId, NodeId, ProtocolHeader, ProtocolId};
use matter_kit::platform::PeerAddr;
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

const F1: FabricIndex = FabricIndex(1);
const F2: FabricIndex = FabricIndex(2);
const LIGHTS: GroupId = GroupId(1);
const KEY: [u8; 16] = [0x77; 16];
const COMPRESSED: CompressedFabricId = CompressedFabricId(0x87E1_B004_E235_A130);

/// A node that offers each fabric eight group memberships rather than §2.11.1.2's minimum of
/// four, so that the limit these tests are about — §11.27.6.1's "half of `MaxMembershipCount`"
/// — is the one they actually reach.
///
/// The quota is `Config`'s rather than a constructor argument, so it cannot be set below
/// §2.11.1.2's minimum: `AssertValid` checks the policy and `GroupKeys::CHECK` the table.
struct EightGroups;
impl Config for EightGroups {
    const GROUPS_PER_FABRIC: usize = 8;
    /// One key set per group these tests join, since each `JoinGroup` here carries its own.
    const GROUP_KEYS_PER_FABRIC: usize = 4;
}

type Keys = GroupKeys<EightGroups, 20, 40>;
type Cluster<'a> = Groupcast<'a, EightGroups, 8, 4, 20, 40>;

struct Fixture {
    node: Node<'static>,
    keys: RefCell<Keys>,
    feature_map: u32,
}

fn fixture(feature_map: u32) -> Fixture {
    let conforming = Box::leak(Box::new(
        // Every element of §11.27 is `P`, so a device that implements the cluster has to say
        // which of it it serves — there is no mandatory core to fall back on.
        Cluster::conforming(feature_map, &gc::OPTIONAL).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(0, clusters)]));
    Fixture {
        node: Node::new(endpoints),
        keys: RefCell::new(Keys::new()),
        feature_map,
    }
}

impl Fixture {
    fn cluster(&self) -> Cluster<'_> {
        Groupcast::new(&self.keys, self.feature_map)
    }

    fn invoke(
        &self,
        cluster: &Cluster<'_>,
        command: u32,
        fields: &[u8],
        ctx: &InteractionContext<'_>,
    ) -> Result<Vec<u8>, Status> {
        let resolved = self
            .node
            .resolve_command(0, gc::ID, command)
            .expect("the command exists");
        let mut buf = [0u8; 512];
        let mut w = TlvWriter::new(&mut buf);
        let response = cluster
            .invoke(&resolved, Some(fields), ctx, &mut w, Tag::Anonymous)
            .map_err(|s| s.status)?;
        if response.is_none() {
            return Ok(Vec::new());
        }
        Ok(w.finish().expect("finish").to_vec())
    }

    fn read(
        &self,
        cluster: &Cluster<'_>,
        attribute: u32,
        ctx: &InteractionContext<'_>,
    ) -> Result<Vec<u8>, Status> {
        let resolved = self
            .node
            .resolve(0, gc::ID, attribute)
            .expect("the path exists");
        let mut buf = [0u8; 512];
        let mut w = TlvWriter::new(&mut buf);
        cluster.read(&resolved, ctx, &mut w, Tag::Anonymous)?;
        Ok(w.finish().expect("finish").to_vec())
    }
}

fn admin(fabric: FabricIndex) -> InteractionContext<'static> {
    InteractionContext::default()
        .with_fabric(fabric)
        .with_privilege(Privilege::Administer)
}

/// A `JoinGroup` payload.
fn join(
    group: u16,
    endpoints: &[u16],
    key_set: u16,
    key: Option<&[u8]>,
    replace: Option<bool>,
    policy: Option<u8>,
    use_acl: Option<bool>,
) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    w.start_array(Tag::Context(1)).unwrap();
    for endpoint in endpoints {
        w.unsigned(Tag::Anonymous, u64::from(*endpoint)).unwrap();
    }
    w.end_container().unwrap();
    w.unsigned(Tag::Context(2), u64::from(key_set)).unwrap();
    if let Some(key) = key {
        w.octets(Tag::Context(3), key).unwrap();
    }
    if let Some(use_acl) = use_acl {
        w.bool(Tag::Context(4), use_acl).unwrap();
    }
    if let Some(replace) = replace {
        w.bool(Tag::Context(5), replace).unwrap();
    }
    if let Some(policy) = policy {
        w.unsigned(Tag::Context(6), u64::from(policy)).unwrap();
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// A `LeaveGroup` payload.
fn leave(group: u16, endpoints: Option<&[u16]>) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), u64::from(group)).unwrap();
    if let Some(endpoints) = endpoints {
        w.start_array(Tag::Context(1)).unwrap();
        for endpoint in endpoints {
            w.unsigned(Tag::Anonymous, u64::from(*endpoint)).unwrap();
        }
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// The `(group, endpoints)` a `LeaveGroupResponse` reported.
fn leave_response(bytes: &[u8]) -> (u64, Vec<u64>) {
    let mut reader = TlvReader::new(bytes);
    assert_eq!(
        reader.next_element().unwrap().unwrap().value.container(),
        Some(ContainerKind::Structure)
    );
    let mut group = 0;
    let mut endpoints = Vec::new();
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        match (field.tag.context(), &field.value) {
            (Some(0), Value::Unsigned(v)) => group = *v,
            (Some(1), _) => loop {
                let e = reader.next_element().unwrap().unwrap();
                if e.value == Value::EndOfContainer {
                    break;
                }
                if let Value::Unsigned(v) = e.value {
                    endpoints.push(v);
                }
            },
            _ => reader.skip_value(&field).unwrap(),
        }
    }
    (group, endpoints)
}

// --- §11.27.7.1: joining ------------------------------------------------------------------

#[test]
fn one_command_makes_a_node_able_to_send_and_receive() {
    // The whole argument for the cluster: a group, its endpoints and its key in one round trip,
    // and the node is immediately part of the group at the message layer.
    let fixture = fixture(FEATURE_LISTENER | FEATURE_SENDER);
    let cluster = fixture.cluster();
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1, 2], 7, Some(&KEY), None, None, None),
            &admin(F1),
        )
        .expect("joined");

    let memberships = cluster.memberships();
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0].group, LIGHTS);
    assert_eq!(memberships[0].endpoints.as_slice(), &[1, 2]);
    assert_eq!(memberships[0].key_set, 7);
    assert_eq!(memberships[0].policy, MulticastAddrPolicyEnum::IanaAddr);
    drop(memberships);

    // And §11.27.9's key management really did reach the Group Key Management tables: a message
    // encrypted here decrypts there.
    let keys = fixture.keys.borrow();
    let key = keys
        .sending_key(F1, COMPRESSED, LIGHTS, None)
        .expect("the group has a key");
    let mut sender = Sender::new(NodeId(0xAAAA), 100, 100);
    let mut scratch = [0u8; 1280];
    let mut out = [0u8; 1280];
    let header = ProtocolHeader {
        initiator: true,
        acknowledged_counter: None,
        reliability: false,
        exchange_id: ExchangeId(1),
        protocol: ProtocolId::INTERACTION_MODEL,
        opcode: 0x08,
    };
    let n = sender
        .send(&key, LIGHTS, &header, b"on", false, &mut scratch, &mut out)
        .expect("send");

    let mut peers = PeerTable::<4, 2>::new();
    let mut datagram = out[..n].to_vec();
    let received = wire::receive(
        &mut datagram,
        PeerAddr::new([0xFD; 16]),
        &keys,
        &mut peers,
        |_| Some(COMPRESSED),
        &mut scratch,
    )
    .expect("receive");
    let Received::Message(inbound) = received else {
        panic!("the group the cluster joined is the group the message layer knows");
    };
    assert_eq!(inbound.payload, b"on");
    assert_eq!(inbound.context.group, LIGHTS);
}

#[test]
fn a_sender_joins_with_no_endpoints_and_a_listener_with_some() {
    // §11.27.7.1 steps 2a and 3a. A wall switch has nothing to receive on; a bulb has the
    // endpoint the light is. Accepting either shape from either device makes a group that looks
    // configured and never works.
    let sender_only = fixture(FEATURE_SENDER);
    let cluster = sender_only.cluster();
    assert!(
        sender_only
            .invoke(
                &cluster,
                gc::JOIN_GROUP,
                &join(1, &[], 7, Some(&KEY), None, None, None),
                &admin(F1)
            )
            .is_ok()
    );
    assert_eq!(
        sender_only.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(2, &[1], 8, Some(&[0x22; 16]), None, None, None),
            &admin(F1)
        ),
        Err(Status::ConstraintError),
        "a sender-only node cannot listen on an endpoint"
    );

    let listener_only = fixture(FEATURE_LISTENER);
    let cluster = listener_only.cluster();
    assert_eq!(
        listener_only.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[], 7, Some(&KEY), None, None, None),
            &admin(F1)
        ),
        Err(Status::ConstraintError),
        "a listener-only node has nothing to send"
    );
}

#[test]
fn the_root_endpoint_is_never_in_a_group() {
    // §11.27.7.1 step 3c: "If any endpoint is invalid or is the RootEndpoint (Endpoint 0), the
    // server SHALL … return with status UNSUPPORTED_ENDPOINT." Groupcast must not reach the
    // clusters that manage the node itself — a multicast that could reach Operational
    // Credentials would be a multicast that could remove a fabric.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    assert_eq!(
        fixture.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1, 0], 7, Some(&KEY), None, None, None),
            &admin(F1)
        ),
        Err(Status::UnsupportedEndpoint)
    );
    assert!(cluster.memberships().is_empty(), "and nothing was stored");
}

#[test]
fn a_group_id_of_zero_is_not_a_group() {
    // §11.27.5.4's constraint is "min 1", and §11.27.7.2 gives 0 a different meaning entirely.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    assert_eq!(
        fixture.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(0, &[1], 7, Some(&KEY), None, None, None),
            &admin(F1)
        ),
        Err(Status::ConstraintError)
    );
}

#[test]
fn endpoints_are_appended_unless_the_command_says_replace() {
    // §11.27.7.1 step 6: append "omitting duplicates" by default; `ReplaceEndpoints` overwrites.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    let ctx = admin(F1);
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, None),
            &ctx,
        )
        .unwrap();
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[2, 1], 7, None, None, None, None),
            &ctx,
        )
        .unwrap();
    assert_eq!(
        cluster.memberships()[0].endpoints.as_slice(),
        &[1, 2],
        "appended, and the duplicate dropped"
    );

    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[3], 7, None, Some(true), None, None),
            &ctx,
        )
        .unwrap();
    assert_eq!(cluster.memberships()[0].endpoints.as_slice(), &[3]);
}

#[test]
fn a_key_is_new_or_it_is_already_there() {
    // §11.27.7.1 step 4a: "The server SHALL verify that the KeySetID field does not already map
    // to an existing OperationalGroupKey of the fabric. Otherwise … ALREADY_EXISTS." Silently
    // replacing would cut off every other group sharing the set.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    let ctx = admin(F1);
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, None),
            &ctx,
        )
        .unwrap();
    assert_eq!(
        fixture.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(2, &[1], 7, Some(&[0x99; 16]), None, None, None),
            &ctx
        ),
        Err(Status::AlreadyExists)
    );
    // Step 5a: without a `Key`, the key set has to exist already.
    assert_eq!(
        fixture.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(2, &[1], 9, None, None, None, None),
            &ctx
        ),
        Err(Status::NotFound)
    );
    // And a second group may share the key set that does exist.
    assert!(
        fixture
            .invoke(
                &cluster,
                gc::JOIN_GROUP,
                &join(2, &[1], 7, None, None, None, None),
                &ctx
            )
            .is_ok()
    );
}

#[test]
fn a_key_that_is_not_sixteen_octets_is_refused() {
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    assert_eq!(
        fixture.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&[0u8; 15]), None, None, None),
            &admin(F1)
        ),
        Err(Status::ConstraintError)
    );
}

#[test]
fn one_fabric_may_use_half_the_table() {
    // §11.27.6.1: "the server SHALL limit the total number of GroupIDs used across all entries
    // in the Membership attribute to no more than half (rounded down) of the MaxMembershipCount
    // value." Whoever commissions first would otherwise fill the device.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    assert_eq!(cluster.per_fabric_limit(), 4, "half of eight");
    for group in 1..=4u16 {
        fixture
            .invoke(
                &cluster,
                gc::JOIN_GROUP,
                &join(
                    group,
                    &[1],
                    group,
                    Some(&[group as u8; 16]),
                    None,
                    None,
                    None,
                ),
                &admin(F1),
            )
            .expect("within the quota");
    }
    assert_eq!(
        fixture.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(5, &[1], 5, Some(&[5u8; 16]), None, None, None),
            &admin(F1)
        ),
        Err(Status::ResourceExhausted)
    );
    // The second fabric is unaffected, which is the point.
    assert!(
        fixture
            .invoke(
                &cluster,
                gc::JOIN_GROUP,
                &join(1, &[1], 1, Some(&[0x5A; 16]), None, None, None),
                &admin(F2)
            )
            .is_ok()
    );
}

#[test]
fn a_per_group_address_needs_the_feature() {
    // §11.27.4 bit 2: `PGA` says the node can subscribe to §2.5.6.2's per-group addresses.
    // A node that accepted the policy without the radio for it would join a group and hear
    // nothing.
    let plain = fixture(FEATURE_LISTENER);
    let cluster = plain.cluster();
    assert_eq!(
        plain.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, Some(1), None),
            &admin(F1)
        ),
        Err(Status::ConstraintError)
    );

    let capable = fixture(FEATURE_LISTENER | FEATURE_PER_GROUP_ADDRESS);
    let cluster = capable.cluster();
    capable
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, Some(1), None),
            &admin(F1),
        )
        .expect("joined");
    assert_eq!(
        cluster.memberships()[0].policy,
        MulticastAddrPolicyEnum::PerGroup
    );
}

#[test]
fn generating_acl_entries_takes_administer() {
    // §11.27.7.1 step 3d: the command itself is `M` — Manage — but the `UseAuxiliaryACL` field
    // writes the Access Control cluster, so it takes Administer. A manager that could set it
    // would be granting itself access it does not have.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    let manager = InteractionContext::default()
        .with_fabric(F1)
        .with_privilege(Privilege::Manage);
    assert_eq!(
        fixture.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, Some(true)),
            &manager
        ),
        Err(Status::UnsupportedAccess)
    );
    // Without the field, the same client may join.
    assert!(
        fixture
            .invoke(
                &cluster,
                gc::JOIN_GROUP,
                &join(1, &[1], 7, Some(&KEY), None, None, None),
                &manager
            )
            .is_ok()
    );
}

// --- §11.27.7.2: leaving --------------------------------------------------------------------

#[test]
fn leaving_names_the_endpoints_that_actually_left() {
    // §11.27.7.3: "Endpoints listed in the Endpoints field of the LeaveGroup command that were
    // not members of the affected group SHALL be excluded from this response." An administrator
    // reconciling its own model needs to know which of its asks took effect.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    let ctx = admin(F1);
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1, 2, 3], 7, Some(&KEY), None, None, None),
            &ctx,
        )
        .unwrap();

    let response = fixture
        .invoke(&cluster, gc::LEAVE_GROUP, &leave(1, Some(&[2, 9])), &ctx)
        .expect("left");
    let (group, endpoints) = leave_response(&response);
    assert_eq!(group, 1);
    assert_eq!(endpoints, vec![2], "endpoint 9 was never a member");
    assert_eq!(cluster.memberships()[0].endpoints.as_slice(), &[1, 3]);
}

#[test]
fn a_listener_left_with_no_endpoints_leaves_the_group_entirely() {
    // §11.27.7.2 step 4c: "If a Membership entry is left with no endpoints, and the device is a
    // Listener only" the entry goes, and with it the keys — a listener in a group with nothing
    // listening is not in the group.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    let ctx = admin(F1);
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, None),
            &ctx,
        )
        .unwrap();
    fixture
        .invoke(&cluster, gc::LEAVE_GROUP, &leave(1, Some(&[1])), &ctx)
        .expect("left");
    assert!(cluster.memberships().is_empty());
    assert!(
        fixture.keys.borrow().key_set(F1, 7).is_none(),
        "step 4c iii: the operational group keys go too"
    );
}

#[test]
fn a_sender_stays_in_a_group_with_no_endpoints() {
    // The other half of step 4c: a node that also sends is still a member with no endpoints,
    // which §11.27.5.4 describes as the ordinary sender-only shape.
    let fixture = fixture(FEATURE_LISTENER | FEATURE_SENDER);
    let cluster = fixture.cluster();
    let ctx = admin(F1);
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, None),
            &ctx,
        )
        .unwrap();
    fixture
        .invoke(&cluster, gc::LEAVE_GROUP, &leave(1, Some(&[1])), &ctx)
        .expect("left");
    assert_eq!(cluster.memberships().len(), 1);
    assert!(cluster.memberships()[0].endpoints.is_empty());
    assert!(fixture.keys.borrow().key_set(F1, 7).is_some());
}

#[test]
fn leaving_with_no_endpoint_list_leaves_the_whole_group() {
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    let ctx = admin(F1);
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1, 2], 7, Some(&KEY), None, None, None),
            &ctx,
        )
        .unwrap();
    let response = fixture
        .invoke(&cluster, gc::LEAVE_GROUP, &leave(1, None), &ctx)
        .expect("left");
    let (_, endpoints) = leave_response(&response);
    assert_eq!(endpoints, vec![1, 2]);
    assert!(cluster.memberships().is_empty());
}

#[test]
fn group_zero_leaves_every_group_of_the_fabric() {
    // §11.27.7.2 step 1: "If the GroupID is 0x00 … all groups on the node for this fabric are
    // affected", and §11.27.7.3 makes the response's endpoint list empty because it would
    // otherwise be ambiguous.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, None),
            &admin(F1),
        )
        .unwrap();
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(2, &[2], 8, Some(&[0x88; 16]), None, None, None),
            &admin(F1),
        )
        .unwrap();
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(3, &[1], 9, Some(&[0x99; 16]), None, None, None),
            &admin(F2),
        )
        .unwrap();

    let response = fixture
        .invoke(&cluster, gc::LEAVE_GROUP, &leave(0, None), &admin(F1))
        .expect("left everything");
    let (group, endpoints) = leave_response(&response);
    assert_eq!(group, 0);
    assert!(endpoints.is_empty(), "ambiguous, so empty");
    assert_eq!(
        cluster.memberships().len(),
        1,
        "the other fabric is untouched"
    );
    assert_eq!(cluster.memberships()[0].fabric_index, F2);
}

#[test]
fn leaving_a_group_that_was_never_joined_is_not_found() {
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    assert_eq!(
        fixture.invoke(&cluster, gc::LEAVE_GROUP, &leave(9, None), &admin(F1)),
        Err(Status::NotFound)
    );
    // And GroupID 0 on a node that has joined nothing is NOT_FOUND too (step 1a).
    assert_eq!(
        fixture.invoke(&cluster, gc::LEAVE_GROUP, &leave(0, None), &admin(F1)),
        Err(Status::NotFound)
    );
}

// --- §11.27.7.4, §11.27.7.5 -------------------------------------------------------------------

#[test]
fn a_key_can_be_rotated_without_rejoining() {
    // §11.27.7.4: the reason the command exists — "if this is the only operation desired, the
    // UpdateGroupKey command SHOULD be used instead" of JoinGroup.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    let ctx = admin(F1);
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, None),
            &ctx,
        )
        .unwrap();

    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 1).unwrap();
    w.unsigned(Tag::Context(1), 8).unwrap();
    w.octets(Tag::Context(2), &[0xEE; 16]).unwrap();
    w.end_container().unwrap();
    let update = w.finish().unwrap().to_vec();

    fixture
        .invoke(&cluster, gc::UPDATE_GROUP_KEY, &update, &ctx)
        .expect("rotated");
    assert_eq!(cluster.memberships()[0].key_set, 8);
    assert!(fixture.keys.borrow().key_set(F1, 8).is_some());
    // And the group now sends under the new key set.
    let keys = fixture.keys.borrow();
    assert!(keys.sending_key(F1, COMPRESSED, LIGHTS, None).is_ok());
}

#[test]
fn updating_the_key_of_a_group_that_is_not_joined_is_not_found() {
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    let mut buf = [0u8; 128];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 9).unwrap();
    w.unsigned(Tag::Context(1), 8).unwrap();
    w.octets(Tag::Context(2), &[0xEE; 16]).unwrap();
    w.end_container().unwrap();
    let update = w.finish().unwrap().to_vec();
    assert_eq!(
        fixture.invoke(&cluster, gc::UPDATE_GROUP_KEY, &update, &admin(F1)),
        Err(Status::NotFound)
    );
}

// --- §11.27.6: the attributes -----------------------------------------------------------------

#[test]
fn the_iana_address_is_counted_once_for_every_group_that_shares_it() {
    // §11.27.6.4's `UsedMcastAddrCount`, and the entire argument for `IanaAddr`: three groups on
    // `FF05::FA` cost one subscription, where three `PerGroup` groups cost three. A device with
    // a small multicast filter table is the reason the policy exists.
    let fixture = fixture(FEATURE_LISTENER | FEATURE_PER_GROUP_ADDRESS);
    let cluster = fixture.cluster();
    let ctx = admin(F1);
    let count = |cluster: &Cluster<'_>| {
        let bytes = fixture
            .read(cluster, gc::USED_MCAST_ADDR_COUNT, &ctx)
            .unwrap();
        let mut reader = TlvReader::new(&bytes);
        match reader.next_element().unwrap().unwrap().value {
            Value::Unsigned(v) => v,
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(count(&cluster), 0);

    for group in 1..=3u16 {
        fixture
            .invoke(
                &cluster,
                gc::JOIN_GROUP,
                &join(
                    group,
                    &[1],
                    group,
                    Some(&[group as u8; 16]),
                    None,
                    Some(0),
                    None,
                ),
                &ctx,
            )
            .unwrap();
    }
    assert_eq!(count(&cluster), 1, "three IanaAddr groups, one address");

    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(4, &[1], 4, Some(&[4u8; 16]), None, Some(1), None),
            &ctx,
        )
        .unwrap();
    assert_eq!(count(&cluster), 2, "and one more for the PerGroup group");
}

#[test]
fn the_membership_attribute_is_fabric_scoped() {
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, None),
            &admin(F1),
        )
        .unwrap();
    fixture
        .invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(2, &[1], 8, Some(&[0x88; 16]), None, None, None),
            &admin(F2),
        )
        .unwrap();

    let mut ctx = admin(F1);
    ctx.fabric_filtered = true;
    let bytes = fixture.read(&cluster, gc::MEMBERSHIP, &ctx).unwrap();
    let mut reader = TlvReader::new(&bytes);
    assert_eq!(
        reader.next_element().unwrap().unwrap().value.container(),
        Some(ContainerKind::Array)
    );
    let mut entries = 0;
    loop {
        let item = reader.next_element().unwrap().unwrap();
        if item.value == Value::EndOfContainer {
            break;
        }
        entries += 1;
        reader.skip_value(&item).unwrap();
    }
    assert_eq!(entries, 1, "one fabric sees one membership");
}

#[test]
fn a_command_with_no_accessing_fabric_is_refused() {
    // §11.27.7: every command in the table is `F`.
    let fixture = fixture(FEATURE_LISTENER);
    let cluster = fixture.cluster();
    assert_eq!(
        fixture.invoke(
            &cluster,
            gc::JOIN_GROUP,
            &join(1, &[1], 7, Some(&KEY), None, None, None),
            &InteractionContext::default()
        ),
        Err(Status::UnsupportedAccess)
    );
}
