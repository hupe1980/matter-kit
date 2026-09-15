//! Access control end to end: writing the list, then being governed by it (Core §6.6, §9.10).
//!
//! This is the flow every controller performs immediately after commissioning, and it joins
//! three things that are each easy to get right alone and easy to get wrong together:
//!
//! 1. **The commissioner has no entry.** A factory-fresh node's ACL is empty (§9.10.6.1), so
//!    the only thing that lets the first write through is §6.6.6.2's implicit grant — "PASE
//!    commissioning channel implicitly grants administer privilege to commissioner". If that
//!    were an ordinary entry it could be read back, edited, or left behind; it is not, and
//!    that is why it disappears with the session.
//!
//! 2. **The list arrives item by item.** §10.6.4.3.1's encoding is an empty array followed by
//!    one block per entry, so the cluster has to distinguish replace from append. Getting
//!    that wrong keeps only the last entry and reports `SUCCESS` for all of it — a node that
//!    looks commissioned and has granted one administrator less access than was asked for.
//!
//! 3. **The list then governs everything, including itself.** §9.10.5.7 requires Administer to
//!    read or write the Access Control cluster, so a subject granted Operate can drive the
//!    device but cannot discover — or widen — who else may.

#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::acl::{Acl, AclAccess, AuthMode, Entry, SubjectDescriptor, Target};
use matter_kit::clusters::access_control::{self, AccessControl, ChangeType};
use matter_kit::config::{Config, DefaultConfig};
use matter_kit::dm::{
    AttributeDescriptor, ClusterDescriptor, CommandDescriptor, DeviceType, Endpoint, Node,
    Privilege, Resolved,
};
use matter_kit::im::{
    AttributeData, AttributePath, ClusterHandler, InteractionContext, ReportData, Server, Status,
    WriteResponse,
};
use matter_kit::msg::{CaseAuthenticatedTag, FabricIndex, NodeId};
use matter_kit::tlv::{ContainerKind, Tag, TlvWriter};

const ENTRIES: usize = DefaultConfig::ACL_ENTRIES;
const SUBJECTS: usize = DefaultConfig::ACL_SUBJECTS;
const TARGETS: usize = DefaultConfig::ACL_TARGETS;

type TestAcl = Acl<DefaultConfig, ENTRIES, SUBJECTS, TARGETS>;
type TestEntry = Entry<SUBJECTS, TARGETS>;

const ON_OFF: u32 = 0x0006;

const ON_OFF_ATTRS: &[AttributeDescriptor] = &[AttributeDescriptor::read_write(0x0000)];
const NO_CMDS: &[CommandDescriptor] = &[];

const fn plain(id: u32, attributes: &'static [AttributeDescriptor]) -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id,
        revision: 1,
        feature_map: 0,
        attributes,
        accepted_commands: NO_CMDS,
        generated_commands: &[],
        events: &[],
    }
}

const EP0: &[ClusterDescriptor<'static>] = &[access_control::cluster()];
const EP1: &[ClusterDescriptor<'static>] = &[plain(ON_OFF, ON_OFF_ATTRS)];
/// `0x0100` — the Device Library's On/Off Light.
const LIGHT: &[DeviceType] = &[DeviceType::new(0x0100, 1)];
const ENDPOINTS: &[Endpoint<'static>] = &[
    Endpoint::new(0, EP0),
    Endpoint::new(1, EP1).with_device_types(LIGHT),
];

fn node() -> Node<'static> {
    Node::new(ENDPOINTS)
}

/// A trivial application cluster beside the Access Control one.
struct Light;

impl ClusterHandler for Light {
    fn read(
        &self,
        _r: &Resolved<'_>,
        _c: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.bool(tag, true).map_err(|_| Status::Failure)
    }
}

/// Dispatches to the Access Control cluster on endpoint 0 and the light on endpoint 1.
struct Device<'a> {
    access_control: AccessControl<'a, DefaultConfig, ENTRIES, SUBJECTS, TARGETS>,
    light: Light,
}

impl ClusterHandler for Device<'_> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        if resolved.cluster.id == access_control::ID {
            self.access_control.read(resolved, ctx, w, tag)
        } else {
            self.light.read(resolved, ctx, w, tag)
        }
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        op: matter_kit::im::WriteOp,
        ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        if resolved.cluster.id == access_control::ID {
            self.access_control.write(resolved, data, op, ctx)
        } else {
            Err(Status::UnsupportedWrite)
        }
    }
}

// --- Encoding helpers -------------------------------------------------------------------------

/// An empty array under context tag 2 — §10.6.4.3.1's "signals clearing the list".
fn clear_list() -> Vec<u8> {
    let mut buf = [0u8; 8];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_array(Tag::Context(2)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// A whole `ACL` list under context tag 2, as a replacing write carries it.
///
/// Each entry is `(privilege, auth_mode, subjects)` with wildcard targets — enough to tell the
/// positions apart, which is what the change-type rule turns on.
fn entry_list(entries: &[(u64, u64, &[NodeId])]) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_array(Tag::Context(2)).unwrap();
    for (privilege, auth_mode, subjects) in entries {
        w.start_structure(Tag::Anonymous).unwrap();
        w.unsigned(Tag::Context(1), *privilege).unwrap();
        w.unsigned(Tag::Context(2), *auth_mode).unwrap();
        w.start_array(Tag::Context(3)).unwrap();
        for subject in *subjects {
            w.unsigned(Tag::Anonymous, subject.0).unwrap();
        }
        w.end_container().unwrap();
        w.null(Tag::Context(4)).unwrap();
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// One `AccessControlEntryStruct` under context tag 2, as an append block carries it.
fn entry_value(privilege: u64, auth_mode: u64, subjects: &[NodeId], targets: &[Target]) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(2)).unwrap();
    w.unsigned(Tag::Context(1), privilege).unwrap();
    w.unsigned(Tag::Context(2), auth_mode).unwrap();
    if subjects.is_empty() {
        w.null(Tag::Context(3)).unwrap();
    } else {
        w.start_array(Tag::Context(3)).unwrap();
        for subject in subjects {
            w.unsigned(Tag::Anonymous, subject.0).unwrap();
        }
        w.end_container().unwrap();
    }
    if targets.is_empty() {
        w.null(Tag::Context(4)).unwrap();
    } else {
        w.start_array(Tag::Context(4)).unwrap();
        for target in targets {
            w.start_structure(Tag::Anonymous).unwrap();
            match target.cluster {
                Some(id) => w.unsigned(Tag::Context(0), u64::from(id)).unwrap(),
                None => w.null(Tag::Context(0)).unwrap(),
            }
            match target.endpoint {
                Some(id) => w.unsigned(Tag::Context(1), u64::from(id)).unwrap(),
                None => w.null(Tag::Context(1)).unwrap(),
            }
            match target.device_type {
                Some(id) => w.unsigned(Tag::Context(2), u64::from(id)).unwrap(),
                None => w.null(Tag::Context(2)).unwrap(),
            }
            w.end_container().unwrap();
        }
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// A whole `ACL` list as one array under context tag 2 — §10.6.4.3.1's first encoding, which
/// it says SHOULD be preferred for this attribute "when it is possible to encode the entirety
/// of the list in a single AttributeDataIB that fits in a single message".
fn entry_array(entries: &[(u64, u64, Vec<NodeId>, Vec<Target>)]) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_array(Tag::Context(2)).unwrap();
    for (privilege, auth_mode, subjects, targets) in entries {
        w.start_structure(Tag::Anonymous).unwrap();
        w.unsigned(Tag::Context(1), *privilege).unwrap();
        w.unsigned(Tag::Context(2), *auth_mode).unwrap();
        if subjects.is_empty() {
            w.null(Tag::Context(3)).unwrap();
        } else {
            w.start_array(Tag::Context(3)).unwrap();
            for subject in subjects {
                w.unsigned(Tag::Anonymous, subject.0).unwrap();
            }
            w.end_container().unwrap();
        }
        if targets.is_empty() {
            w.null(Tag::Context(4)).unwrap();
        } else {
            w.start_array(Tag::Context(4)).unwrap();
            for target in targets {
                w.start_structure(Tag::Anonymous).unwrap();
                match target.cluster {
                    Some(id) => w.unsigned(Tag::Context(0), u64::from(id)).unwrap(),
                    None => w.null(Tag::Context(0)).unwrap(),
                }
                match target.endpoint {
                    Some(id) => w.unsigned(Tag::Context(1), u64::from(id)).unwrap(),
                    None => w.null(Tag::Context(1)).unwrap(),
                }
                match target.device_type {
                    Some(id) => w.unsigned(Tag::Context(2), u64::from(id)).unwrap(),
                    None => w.null(Tag::Context(2)).unwrap(),
                }
                w.end_container().unwrap();
            }
            w.end_container().unwrap();
        }
        w.end_container().unwrap();
    }
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// The administrator these tests write the ACL as.
const ADMIN: NodeId = NodeId(0x0000_0000_0000_1111);

const ACL_PATH: AttributePath =
    AttributePath::attribute(0, access_control::ID, access_control::ACL);

fn append_path() -> AttributePath {
    AttributePath {
        list_index: Some(matter_kit::im::ListIndex::Append),
        ..ACL_PATH
    }
}

/// The context a commissioner has over PASE: administer by §6.6.6.2, and a fabric to write to.
fn commissioner_ctx() -> InteractionContext<'static> {
    InteractionContext {
        fabric_index: Some(FabricIndex(1)),
        ..InteractionContext::default()
    }
}

/// Runs a write and returns the status of every response block.
fn write_acl(
    device: &Device<'_>,
    subject: &SubjectDescriptor,
    acl: &RefCell<TestAcl>,
    ctx: &InteractionContext<'_>,
    blocks: &[(AttributePath, Vec<u8>)],
) -> Vec<Status> {
    let access = AclAccess::new(acl, node(), subject);
    let server = Server::new(node(), &access, device, 64);
    let writes: Vec<AttributeData<'_>> = blocks
        .iter()
        .map(|(path, data)| AttributeData {
            data_version: None,
            path: *path,
            data,
        })
        .collect();
    let mut buf = [0u8; 2048];
    let (bytes, _) = server
        .serve_write(writes.into_iter().map(Ok), ctx, false, &mut buf)
        .expect("serve_write");
    WriteResponse::decode(bytes)
        .expect("decode")
        .statuses()
        .expect("statuses")
        .map(|s| s.expect("decode each").status.status)
        .collect()
}

/// Reads one path and returns whether data came back, plus any status.
fn read_one(
    device: &Device<'_>,
    subject: &SubjectDescriptor,
    acl: &RefCell<TestAcl>,
    path: AttributePath,
) -> Vec<(AttributePath, Option<Status>)> {
    let access = AclAccess::new(acl, node(), subject);
    let server = Server::new(node(), &access, device, 64);
    let mut scratch = [0u8; 1024];
    let mut buf = [0u8; 2048];
    let (bytes, _) = server
        .serve(
            [path].iter().copied().map(Ok),
            &InteractionContext::default(),
            None,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    let report = ReportData::decode(bytes).expect("decode");
    match report.attribute_reports().expect("reports") {
        Some(iter) => iter
            .map(|item| match item.expect("decode each") {
                matter_kit::im::AttributeReport::Status(s) => (s.path, Some(s.status.status)),
                matter_kit::im::AttributeReport::Data(d) => (d.path, None),
            })
            .collect(),
        None => Vec::new(),
    }
}

// --- The flow ---------------------------------------------------------------------------------

/// The write every controller makes right after commissioning, block by block.
#[test]
fn a_commissioner_writes_its_acl_over_pase_and_every_entry_survives() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    // §6.6.6.2's implicit grant: no entry exists yet, and this is what lets the write through.
    let commissioner = SubjectDescriptor::commissioning();
    let ctx = commissioner_ctx();

    let admin = NodeId(0x0000_0000_0000_1111);
    let helper = NodeId(0x0000_0000_0000_2222);
    let blocks = vec![
        (ACL_PATH, clear_list()),
        // Administer for the commissioner itself.
        (append_path(), entry_value(5, 2, &[admin], &[])),
        // Operate for a helper, only on the light.
        (
            append_path(),
            entry_value(3, 2, &[helper], &[Target::endpoint(1)]),
        ),
        // View for anyone on the fabric — an empty subject list is the wildcard.
        (append_path(), entry_value(1, 2, &[], &[])),
    ];

    let statuses = write_acl(&device, &commissioner, &acl, &ctx, &blocks);
    assert_eq!(statuses, vec![Status::Success; 4]);

    // The whole point: three entries, not one.
    assert_eq!(acl.borrow().len_of_fabric(FabricIndex(1)), 3);
}

/// The list written above then governs the node, including the cluster that holds it.
#[test]
fn the_written_list_governs_reads_including_the_access_control_cluster() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let admin = NodeId(0x0000_0000_0000_1111);
    let helper = NodeId(0x0000_0000_0000_2222);
    {
        let mut list = acl.borrow_mut();
        list.add(
            TestEntry::case(FabricIndex(1), Privilege::Administer)
                .with_subject(admin)
                .unwrap(),
        )
        .unwrap();
        list.add(
            TestEntry::case(FabricIndex(1), Privilege::Operate)
                .with_subject(helper)
                .unwrap()
                .with_target(Target::endpoint(1))
                .unwrap(),
        )
        .unwrap();
    }

    let admin_subject = SubjectDescriptor::case(FabricIndex(1), admin);
    let helper_subject = SubjectDescriptor::case(FabricIndex(1), helper);
    let light_path = AttributePath::attribute(1, ON_OFF, 0x0000);

    // The administrator reads both.
    assert_eq!(
        read_one(&device, &admin_subject, &acl, light_path)[0].1,
        None
    );
    assert_eq!(read_one(&device, &admin_subject, &acl, ACL_PATH)[0].1, None);

    // The helper drives the light...
    assert_eq!(
        read_one(&device, &helper_subject, &acl, light_path)[0].1,
        None
    );
    // ...and cannot read the access control list. §9.10.5.7 requires Administer to *observe*
    // it, so an Operate subject cannot enumerate who else has access to the node.
    assert_eq!(
        read_one(&device, &helper_subject, &acl, ACL_PATH)[0].1,
        Some(Status::UnsupportedAccess)
    );
}

/// A subject with no entry at all gets nothing, and learns nothing about the node's shape.
#[test]
fn a_stranger_on_the_fabric_is_denied() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    acl.borrow_mut()
        .add(
            TestEntry::case(FabricIndex(1), Privilege::Administer)
                .with_subject(NodeId(0x1111))
                .unwrap(),
        )
        .unwrap();

    let stranger = SubjectDescriptor::case(FabricIndex(1), NodeId(0x9999));
    let path = AttributePath::attribute(1, ON_OFF, 0x0000);
    assert_eq!(
        read_one(&device, &stranger, &acl, path)[0].1,
        Some(Status::UnsupportedAccess)
    );

    // A wildcard read tells it nothing at all: §8.4.3.2 step 1c discards an expanded path
    // rather than reporting a status for it, so the node's shape stays hidden.
    let reports = read_one(&device, &stranger, &acl, AttributePath::wildcard());
    assert!(
        reports.is_empty(),
        "a wildcard read by an unprivileged subject reports nothing at all"
    );
}

/// An administrator on one fabric cannot see or overwrite another's entries.
#[test]
fn one_fabrics_administrator_cannot_reach_anothers_list() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let alice = NodeId(0x1111);
    let bob = NodeId(0x2222);
    {
        let mut list = acl.borrow_mut();
        list.add(
            TestEntry::case(FabricIndex(1), Privilege::Administer)
                .with_subject(alice)
                .unwrap(),
        )
        .unwrap();
        list.add(
            TestEntry::case(FabricIndex(2), Privilege::Administer)
                .with_subject(bob)
                .unwrap(),
        )
        .unwrap();
    }

    // Bob replaces his own list with nothing...
    let bob_subject = SubjectDescriptor::case(FabricIndex(2), bob);
    let ctx = InteractionContext {
        fabric_index: Some(FabricIndex(2)),
        ..InteractionContext::default()
    };
    let statuses = write_acl(
        &device,
        &bob_subject,
        &acl,
        &ctx,
        &[(ACL_PATH, clear_list())],
    );
    assert_eq!(statuses, vec![Status::Success]);

    // ...and Alice's survives untouched, so she still administers the node.
    assert_eq!(acl.borrow().len_of_fabric(FabricIndex(1)), 1);
    assert_eq!(acl.borrow().len_of_fabric(FabricIndex(2)), 0);
    let alice_subject = SubjectDescriptor::case(FabricIndex(1), alice);
    assert_eq!(read_one(&device, &alice_subject, &acl, ACL_PATH)[0].1, None);
}

/// A CAT grants a whole class of nodes at once, and a stale version does not.
#[test]
fn a_cat_admits_the_nodes_holding_it_at_a_current_enough_version() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    // Entry written against version 3.
    acl.borrow_mut()
        .add(
            TestEntry::case(FabricIndex(1), Privilege::Operate)
                .with_subject(CaseAuthenticatedTag::new(0xABCD, 3).to_node_id())
                .unwrap(),
        )
        .unwrap();

    let path = AttributePath::attribute(1, ON_OFF, 0x0000);
    // A node whose certificate carries version 4 is admitted — the tag was re-issued and it
    // kept up.
    let current = SubjectDescriptor::case(FabricIndex(1), NodeId(0x5555))
        .with_cat(CaseAuthenticatedTag::new(0xABCD, 4))
        .unwrap();
    assert_eq!(read_one(&device, &current, &acl, path)[0].1, None);

    // One left behind at version 2 is not. This is how revocation works at all: bump the
    // version, reissue to the nodes that keep access, and the rest fall out.
    let stale = SubjectDescriptor::case(FabricIndex(1), NodeId(0x6666))
        .with_cat(CaseAuthenticatedTag::new(0xABCD, 2))
        .unwrap();
    assert_eq!(
        read_one(&device, &stale, &acl, path)[0].1,
        Some(Status::UnsupportedAccess)
    );
}

/// §9.10.9.1's event names the administrator that made the change.
#[test]
fn every_change_is_recorded_against_whoever_made_it() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let commissioner = SubjectDescriptor::commissioning();
    let ctx = commissioner_ctx();

    // Something to remove. §9.10.9.1 asks for an event per *entry*, so a list that was already
    // empty produces no Removed at all — a clear is not itself an event.
    acl.borrow_mut()
        .add_admin_for_fabric(FabricIndex(1), NodeId(0x2222))
        .expect("an entry to overwrite");
    let statuses = write_acl(
        &device,
        &commissioner,
        &acl,
        &ctx,
        &[
            (ACL_PATH, clear_list()),
            (append_path(), entry_value(5, 2, &[NodeId(0x1111)], &[])),
        ],
    );
    assert_eq!(statuses, vec![Status::Success; 2]);

    let changes = device.access_control.take_changes();
    assert_eq!(changes.len(), 2, "one entry out, one entry in");
    // Over PASE: "Exactly one of AdminNodeID and AdminPasscodeID SHALL be set."
    for change in &changes {
        assert_eq!(change.admin_node_id, None);
        assert_eq!(change.admin_passcode_id, Some(0));
        assert_eq!(change.fabric_index, FabricIndex(1));
    }
    assert_eq!(changes[0].change_type, ChangeType::Removed);
    assert_eq!(changes[1].change_type, ChangeType::Added);

    // §9.10.9.1's `LatestValue` is "the latest value of the changed entry" — which for a
    // removal is the entry as it stood when it went. An audit trail that says only *that* the
    // list changed, never to what, is most of the way to no audit trail.
    let removed = changes[0].latest_value.as_ref().expect("the entry removed");
    assert_eq!(removed.subjects.as_slice(), &[NodeId(0x2222)]);
    let added = changes[1].latest_value.as_ref().expect("the entry added");
    assert_eq!(added.subjects.as_slice(), &[NodeId(0x1111)]);

    // Draining is what makes a record reported once.
    assert!(device.access_control.take_changes().is_empty());
}

#[test]
fn a_replace_reports_a_change_per_position_not_a_wipe_and_a_refill() {
    // §9.10.9.1 gives three change types, and a whole-list write can produce all three. A list
    // attribute's entry is identified by its index — §10.6.4.3.1 edits by index — so replacing
    // `[a]` with `[a, b]` changes position 0 and adds position 1. A node that reported this as
    // a removal and two additions would be telling a controller it had lost an entry it still
    // has, and the difference is exactly what an audit trail is read for.
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    acl.borrow_mut()
        .add_admin_for_fabric(FabricIndex(1), NodeId(0x2222))
        .expect("the entry already there");

    let commissioner = SubjectDescriptor::commissioning();
    let ctx = commissioner_ctx();
    let statuses = write_acl(
        &device,
        &commissioner,
        &acl,
        &ctx,
        &[(
            ACL_PATH,
            entry_list(&[(5, 2, &[NodeId(0x2222)]), (3, 2, &[NodeId(0x3333)])]),
        )],
    );
    assert_eq!(statuses, vec![Status::Success]);

    let changes = device.access_control.take_changes();
    assert_eq!(changes.len(), 2, "one position rewritten, one added");
    assert_eq!(changes[0].change_type, ChangeType::Changed);
    assert_eq!(
        changes[0]
            .latest_value
            .as_ref()
            .expect("the new value")
            .subjects
            .as_slice(),
        &[NodeId(0x2222)]
    );
    assert_eq!(changes[1].change_type, ChangeType::Added);
    assert_eq!(
        changes[1]
            .latest_value
            .as_ref()
            .expect("the new value")
            .subjects
            .as_slice(),
        &[NodeId(0x3333)]
    );

    // And shrinking reports the other direction: position 1 is gone.
    let statuses = write_acl(
        &device,
        &commissioner,
        &acl,
        &ctx,
        &[(ACL_PATH, entry_list(&[(5, 2, &[NodeId(0x2222)])]))],
    );
    assert_eq!(statuses, vec![Status::Success]);
    let changes = device.access_control.take_changes();
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].change_type, ChangeType::Changed);
    assert_eq!(changes[1].change_type, ChangeType::Removed);
    assert_eq!(
        changes[1]
            .latest_value
            .as_ref()
            .expect("the entry that went")
            .subjects
            .as_slice(),
        &[NodeId(0x3333)]
    );
}

#[test]
fn a_clear_of_an_empty_list_records_nothing() {
    // "Each removed entry SHALL generate an event with ChangeType Removed" — an entry, not a
    // write. A node that recorded a Removed for a list that had nothing in it would put an
    // entry in the audit trail that names no entry, which an auditor cannot tell from a real
    // removal whose value the node could not afford to keep.
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let commissioner = SubjectDescriptor::commissioning();
    let ctx = commissioner_ctx();
    let statuses = write_acl(
        &device,
        &commissioner,
        &acl,
        &ctx,
        &[(ACL_PATH, clear_list())],
    );
    assert_eq!(statuses, vec![Status::Success]);
    assert!(device.access_control.take_changes().is_empty());
}

#[test]
fn the_administrator_entry_add_noc_creates_is_recorded_like_any_other() {
    // §11.18.6.8 step 7 adds one ACL entry, and it is the entry every other one on the fabric
    // is granted by. Added straight to the `Acl` it is invisible to §9.10.9.1, so the audit
    // trail of an Access Control cluster begins by omitting the administrator — which is the
    // first thing the Test Harness reads, and the first thing an auditor would want.
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    // `AddNOC` runs over PASE, and the accessing fabric is bound to the session only at step
    // 10a — *after* this — so the context carries no fabric at all.
    let ctx = InteractionContext::new();
    device
        .access_control
        .add_admin_for_fabric(FabricIndex(1), NodeId(0x1234_5678), &ctx)
        .expect("the administrator");

    let changes = device.access_control.take_changes();
    assert_eq!(changes.len(), 1, "one entry, one event");
    let change = &changes[0];
    assert_eq!(change.change_type, ChangeType::Added);
    assert_eq!(change.admin_node_id, None, "over PASE");
    assert_eq!(change.admin_passcode_id, Some(0));
    assert_eq!(
        change.fabric_index,
        FabricIndex(1),
        "attributed to the fabric it created, not to the session's (none)"
    );
    let entry = change.latest_value.as_ref().expect("the entry");
    assert_eq!(entry.privilege, Privilege::Administer);
    assert_eq!(entry.subjects.as_slice(), &[NodeId(0x1234_5678)]);
    assert_eq!(entry.fabric_index, FabricIndex(1));
}

/// A PASE session holds Administer but has no fabric, so it cannot edit a fabric-scoped list.
#[test]
fn a_pase_session_without_a_fabric_cannot_write_the_list() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let commissioner = SubjectDescriptor::commissioning();
    // No `fabric_index`: commissioning has not reached `AddNOC` yet.
    let ctx = InteractionContext::default();
    let statuses = write_acl(
        &device,
        &commissioner,
        &acl,
        &ctx,
        &[(ACL_PATH, clear_list())],
    );
    // §7.19.1.8.1: there is no accessing fabric for the entries to belong to.
    assert_eq!(statuses, vec![Status::UnsupportedAccess]);
}

/// A group entry may not be written at Administer, whichever way it arrives.
#[test]
fn a_group_entry_at_administer_is_refused_over_the_wire() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let commissioner = SubjectDescriptor::commissioning();
    let ctx = commissioner_ctx();
    // Privilege 5 = Administer, auth mode 3 = Group.
    let statuses = write_acl(
        &device,
        &commissioner,
        &acl,
        &ctx,
        &[(append_path(), entry_value(5, 3, &[], &[]))],
    );
    assert_eq!(statuses, vec![Status::ConstraintError]);
    assert_eq!(acl.borrow().len(), 0);
    let _ = AuthMode::Group;
}

/// §6.6.4's worked example: a change takes effect for later paths of the *same* message.
///
/// > Updates to the Access Control Cluster SHALL take immediate effect in the Access Control
/// > system.
///
/// The specification's own illustration is an administrator that narrows its entry in the
/// first path of a Write and is then denied by it in the second. That only happens if the
/// decision reads the *live* list rather than a snapshot taken when the action began, which
/// is why the table is shared between the cluster and the algorithm rather than copied.
#[test]
fn a_change_takes_effect_for_later_paths_of_the_same_message() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let alice = NodeId(0x0011_2233_4455_6677);
    acl.borrow_mut()
        .add(
            TestEntry::case(FabricIndex(1), Privilege::Administer)
                .with_subject(alice)
                .unwrap(),
        )
        .unwrap();

    let subject = SubjectDescriptor::case(FabricIndex(1), alice);
    let ctx = InteractionContext {
        fabric_index: Some(FabricIndex(1)),
        ..InteractionContext::default()
    };

    // Path 1 replaces the list with the same grant narrowed to endpoint 0 — one block, which
    // is the encoding §10.6.4.3.1 prefers for this attribute. Path 2 writes endpoint 1.
    let narrowed = entry_array(&[(5, 2, vec![alice], vec![Target::endpoint(0)])]);
    let on_off = {
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
        w.bool(Tag::Context(2), true).unwrap();
        w.finish().unwrap().to_vec()
    };

    let statuses = write_acl(
        &device,
        &subject,
        &acl,
        &ctx,
        &[
            (ACL_PATH, narrowed),
            (AttributePath::attribute(1, ON_OFF, 0x0000), on_off),
        ],
    );

    assert_eq!(
        statuses[0],
        Status::Success,
        "the narrowing write is allowed"
    );
    assert_eq!(
        statuses[1],
        Status::UnsupportedAccess,
        "and endpoint 1 is already out of reach, in the very same message"
    );
    assert_eq!(acl.borrow().len_of_fabric(FabricIndex(1)), 1);
}

/// Clearing your own entry locks you out of the **next** action, not out of this one.
///
/// §9.10.6.2 is explicit that this is the administrator's problem and not the node's:
///
/// > Administrators SHOULD be careful to avoid inadvertently removing their own administrative
/// > access … an Administrator SHOULD change its own administrative access entry by updating
/// > the existing entry or by creating a new entry before removing the old entry, and SHOULD
/// > NOT remove the old entry before creating any new entry.
///
/// That is advice to an administrator about entries *surviving*, and it holds: a write that
/// clears the list and stops there leaves nobody able to write it again.
///
/// It is **not** a rule about how one Write Request action is evaluated: reading it as one
/// breaks §10.6.4.3.1's list-write idiom on the one attribute the idiom is most needed for —
/// see `a_legacy_list_write_does_not_lose_its_own_grant_half_way_through`.
#[test]
fn clearing_your_own_entry_revokes_the_privilege_for_the_next_action() {
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let alice = NodeId(0x0011_2233_4455_6677);
    acl.borrow_mut()
        .add(
            TestEntry::case(FabricIndex(1), Privilege::Administer)
                .with_subject(alice)
                .unwrap(),
        )
        .unwrap();

    let subject = SubjectDescriptor::case(FabricIndex(1), alice);
    let ctx = InteractionContext {
        fabric_index: Some(FabricIndex(1)),
        ..InteractionContext::default()
    };

    // One action, one AttributeDataIB: clear the list and stop.
    let statuses = write_acl(&device, &subject, &acl, &ctx, &[(ACL_PATH, clear_list())]);
    assert_eq!(
        statuses,
        vec![Status::Success],
        "the clear is within its rights"
    );
    assert_eq!(acl.borrow().len_of_fabric(FabricIndex(1)), 0);

    // A *second* action carries nothing from the first, and there is no longer an entry
    // granting Administer.
    let statuses = write_acl(
        &device,
        &subject,
        &acl,
        &ctx,
        &[(append_path(), entry_value(5, 2, &[alice], &[]))],
    );
    assert_eq!(
        statuses,
        vec![Status::UnsupportedAccess],
        "the grant must not outlive the action it was taken in"
    );
    assert_eq!(acl.borrow().len_of_fabric(FabricIndex(1)), 0);
}

/// Revoking access stops an *existing* subscription's reports.
///
/// A subscription is established once and reports for minutes or hours afterwards. If the
/// privilege were resolved at subscribe time and cached, an administrator revoking a
/// subject's access would not actually revoke anything: the subscription would keep
/// delivering the node's state to a subject that may no longer have any standing at all —
/// and the client would have no idea it was reading something it should not.
///
/// §6.6.4 settles it: "Updates to the Access Control Cluster SHALL take immediate effect in
/// the Access Control system." So every report re-runs the decision, and the subscription
/// simply stops carrying what the subject may no longer see.
#[test]
fn revoking_access_silences_a_subscription_that_was_already_running() {
    use matter_kit::im::subscription::{NewSubscription, ReportReason, SubscriptionTable};
    use matter_kit::msg::SessionId;
    use matter_kit::platform::Instant;

    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    let watcher = NodeId(0x0000_0000_0000_7777);
    acl.borrow_mut()
        .add(
            TestEntry::case(FabricIndex(1), Privilege::View)
                .with_subject(watcher)
                .unwrap(),
        )
        .unwrap();

    let light_path = AttributePath::attribute(1, ON_OFF, 0x0000);
    let paths = [light_path];
    let mut table: SubscriptionTable<DefaultConfig, 4, 4> = SubscriptionTable::new();
    let id = table
        .subscribe(
            &NewSubscription {
                session: Some(SessionId(1)),
                fabric_index: Some(FabricIndex(1)),
                peer_node_id: None,
                fabric_filtered: true,
                keep_subscriptions: true,
                min_interval_s: 0,
                max_interval_s: 60,
                paths: &paths,
                event_paths: &[],
                min_event_number: 0,
            },
            Instant::ZERO,
        )
        .expect("subscribe");
    table.note_change(&light_path);
    let subscription = table.find_mut(id).expect("subscription");

    // Returns (values delivered, statuses reported).
    let mut report = |subject: &SubjectDescriptor| -> (usize, Vec<Status>) {
        let access = AclAccess::new(&acl, node(), subject);
        let server = Server::new(node(), &access, &device, 64);
        let mut scratch = [0u8; 512];
        let mut buf = [0u8; 2048];
        let (bytes, _) = server
            .report(
                subscription,
                ReportReason::Data,
                &InteractionContext::default(),
                &mut scratch,
                &mut buf,
            )
            .expect("report");
        let decoded = ReportData::decode(bytes).expect("decode");
        let mut values = 0usize;
        let mut statuses = Vec::new();
        if let Some(iter) = decoded.attribute_reports().expect("reports") {
            for item in iter {
                match item.expect("decode each") {
                    matter_kit::im::AttributeReport::Data(_) => values += 1,
                    matter_kit::im::AttributeReport::Status(s) => statuses.push(s.status.status),
                }
            }
        }
        (values, statuses)
    };

    let subject = SubjectDescriptor::case(FabricIndex(1), watcher);
    assert_eq!(
        report(&subject),
        (1, vec![]),
        "the subscription delivers the value while the subject is granted"
    );

    // The administrator revokes it. Nothing touches the subscription itself.
    acl.borrow_mut().remove_fabric(FabricIndex(1));

    // The value stops immediately. The subscription is still alive and still due, so the
    // subscriber is *told* — §8.4.3.2 gives a concrete path a status rather than silence,
    // which is what lets a client tell "revoked" from "unchanged".
    assert_eq!(
        report(&subject),
        (0, vec![Status::UnsupportedAccess]),
        "and the very next report carries no value, without the subscription being torn down"
    );
}

#[test]
fn a_legacy_list_write_does_not_lose_its_own_grant_half_way_through() {
    // §10.6.4.3.1's way of writing a whole list: "a series of AttributeDataIBs, with the first
    // containing a path to the list itself and Data that is empty array, which signals clearing
    // the list, and subsequent AttributeDataIBs containing updates". Every one of them names
    // the same attribute, and on *this* attribute the first one revokes the writer's own access
    // — clearing the `ACL` list removes the administrator entry the writer is administering
    // with.
    //
    // A node that re-runs §8.7.3.2's access check on each AttributeDataIB therefore answers
    // `UNSUPPORTED_ACCESS` to every append after the clear, and is left with an empty list, no
    // administrator at all, and a controller that cannot even read `Fabrics` to find out. So
    // the decision is taken once per concrete path per action.
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    acl.borrow_mut()
        .add_admin_for_fabric(FabricIndex(1), ADMIN)
        .expect("the administrator that makes this write possible");

    // Over CASE as that administrator — not the commissioning subject, which is granted
    // Administer implicitly and would hide the whole question (§6.6.2.9).
    let admin = SubjectDescriptor::case(FabricIndex(1), ADMIN);
    let ctx = InteractionContext::new().with_fabric(FabricIndex(1));
    let statuses = write_acl(
        &device,
        &admin,
        &acl,
        &ctx,
        &[
            (ACL_PATH, clear_list()),
            (append_path(), entry_value(5, 2, &[ADMIN], &[])),
            (append_path(), entry_value(3, 2, &[NodeId(0x3333)], &[])),
        ],
    );
    assert_eq!(
        statuses,
        vec![Status::Success; 3],
        "the appends after the clear were refused"
    );
    assert_eq!(acl.borrow().of_fabric(FabricIndex(1)).count(), 2);
}

#[test]
fn the_carried_grant_does_not_widen_what_a_writer_may_touch() {
    // The reuse above is per *concrete path*, and only after that path was granted. A writer
    // who was refused is refused every time, and a grant on one attribute says nothing about
    // another — otherwise "take the decision once" would be a way to write anything by naming
    // something writable first.
    let acl = RefCell::new(TestAcl::new());
    let device = Device {
        access_control: AccessControl::new(&acl),
        light: Light,
    };
    // Operate, not Administer: §9.10 requires Administer to touch the Access Control cluster at
    // all, so this subject may work the light and nothing else.
    let mut entry = TestEntry::case(FabricIndex(1), Privilege::Operate);
    entry = entry.with_subject(ADMIN).expect("room");
    acl.borrow_mut().add(entry).expect("add");

    let subject = SubjectDescriptor::case(FabricIndex(1), ADMIN);
    let ctx = InteractionContext::new().with_fabric(FabricIndex(1));
    let statuses = write_acl(
        &device,
        &subject,
        &acl,
        &ctx,
        &[
            (ACL_PATH, clear_list()),
            (append_path(), entry_value(5, 2, &[ADMIN], &[])),
        ],
    );
    assert_eq!(
        statuses,
        vec![Status::UnsupportedAccess; 2],
        "a refusal must not be carried either"
    );
    assert_eq!(
        acl.borrow().of_fabric(FabricIndex(1)).count(),
        1,
        "and nothing was written"
    );
}
