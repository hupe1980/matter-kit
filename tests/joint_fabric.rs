//! Joint Fabric (Core ch. 12, §11.25): two ecosystems under one root.
//!
//! The Joint Commissioning Method is a three-step handshake and the steps only mean anything in
//! order. `ICACCSRRequest` says "sign this key"; the anchor signs it; `AddICAC` says "here it
//! is". Take away the pairing between the two halves and an anchor could hand back an
//! intermediate CA over a key of its own choosing — and the joining ecosystem would install a CA
//! it does not hold the private key for.
//!
//! Everything here runs inside a fail-safe, and that is not decoration either: a half-joined
//! fabric is one where two ecosystems disagree about who may administer what.

#![cfg(all(feature = "std", feature = "rustcrypto"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::{Cell, RefCell};

use matter_kit::clusters::joint_fabric_administrator::{
    self as jfa, AnchorTransfer, ICACCSRResponseStatusCodeEnum, ICACResponseStatusEnum,
    JointFabricAdministrator, JointFabricHooks, TransferAnchorResponseStatusEnum,
};
use matter_kit::commissioning::failsafe::{BasicCommissioningInfo, FailSafe};
use matter_kit::commissioning::window::CommissioningWindow;
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::{ClusterHandler, InteractionContext, Status};
use matter_kit::jf::{self, JointFabricTags, Revocation};
use matter_kit::msg::{FabricIndex, NodeId};
use matter_kit::platform::Instant;
use matter_kit::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

const F1: FabricIndex = FabricIndex(1);
const F2: FabricIndex = FabricIndex(2);
/// A "CSR" whose last octet stands for the key it was made over.
const CSR: &[u8] = b"pkcs10-csr\x07";
/// An "ICAC" over the same key, and one over a different one.
const ICAC_MATCHING: &[u8] = b"icac\x07";
const ICAC_WRONG_KEY: &[u8] = b"icac\x09";
const ICAC_BAD_CHAIN: &[u8] = b"BADicac\x07";

fn at(secs: u64) -> Instant {
    Instant::from_micros(secs * 1_000_000)
}

/// The product's half: a CSR over one key, and the three checks of §11.25.6.3.
#[derive(Debug, Default)]
struct Product {
    installed: RefCell<Vec<(Vec<u8>, FabricIndex)>>,
    transfer: Cell<bool>,
    transferred: Cell<bool>,
    announced: RefCell<Vec<u16>>,
}

impl JointFabricHooks for Product {
    fn write_icac_csr(&self, out: &mut [u8]) -> Result<usize, Status> {
        out.get_mut(..CSR.len())
            .ok_or(Status::Failure)?
            .copy_from_slice(CSR);
        Ok(CSR.len())
    }

    fn validate_icac(&self, icac: &[u8], _fabric: FabricIndex) -> ICACResponseStatusEnum {
        // §11.25.6.3's checks, in the specification's order: the chain first, then the public
        // key. Here "chains" is a marker and "the same key" is the last octet.
        if icac.starts_with(b"BAD") {
            return ICACResponseStatusEnum::InvalidICAC;
        }
        if icac.last() != CSR.last() {
            return ICACResponseStatusEnum::InvalidPublicKey;
        }
        ICACResponseStatusEnum::OK
    }

    fn install_icac(&self, icac: &[u8], fabric: FabricIndex) -> Result<(), Status> {
        self.installed.borrow_mut().push((icac.to_vec(), fabric));
        Ok(())
    }

    fn anchor_transfer(&self) -> AnchorTransfer {
        if self.transfer.get() {
            AnchorTransfer::Accepted
        } else {
            AnchorTransfer::Refused(
                TransferAnchorResponseStatusEnum::TransferAnchorStatusNoUserConsent,
            )
        }
    }

    fn anchor_transferred(&self) {
        self.transferred.set(true);
    }

    fn administrator_announced(&self, endpoint: u16) {
        self.announced.borrow_mut().push(endpoint);
    }
}

struct Fixture {
    node: Node<'static>,
    product: Product,
    fail_safe: RefCell<FailSafe>,
    window: RefCell<CommissioningWindow>,
}

fn fixture() -> Fixture {
    let conforming = Box::leak(Box::new(
        JointFabricAdministrator::<Product>::conforming(0, &Optional::NONE).expect("sized"),
    ));
    let clusters: &'static [ClusterDescriptor<'static>] =
        Box::leak(Box::new([conforming.descriptor()]));
    let endpoints: &'static [Endpoint<'static>] = Box::leak(Box::new([Endpoint::new(1, clusters)]));
    Fixture {
        node: Node::new(endpoints),
        product: Product::default(),
        fail_safe: RefCell::new(FailSafe::new(BasicCommissioningInfo::default())),
        window: RefCell::new(CommissioningWindow::new()),
    }
}

impl Fixture {
    fn cluster(&self) -> JointFabricAdministrator<'_, Product> {
        JointFabricAdministrator::new(&self.product, &self.fail_safe, &self.window)
    }

    fn arm(&self) {
        // §11.10.7.2's own arguments: sixty seconds, no breadcrumb, on fabric 1, over CASE.
        self.fail_safe
            .borrow_mut()
            .arm(60, 0, Some(F1), at(0), false);
    }

    fn invoke(
        &self,
        cluster: &JointFabricAdministrator<'_, Product>,
        command: u32,
        fields: &[u8],
        ctx: &InteractionContext<'_>,
    ) -> Result<Vec<u8>, Status> {
        let resolved = self
            .node
            .resolve_command(1, jfa::ID, command)
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
}

fn on(fabric: FabricIndex, verified: bool) -> InteractionContext<'static> {
    InteractionContext {
        fabric_index: Some(fabric),
        now: at(1),
        vendor_id_verified: verified,
        ..InteractionContext::default()
    }
}

fn empty() -> Vec<u8> {
    let mut buf = [0u8; 16];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

fn add_icac(icac: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.octets(Tag::Context(0), icac).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}

/// The `(tag, value)` pairs of a response structure.
fn fields(bytes: &[u8]) -> Vec<(u8, Value<'_>)> {
    let mut reader = TlvReader::new(bytes);
    assert_eq!(
        reader.next_element().unwrap().unwrap().value.container(),
        Some(ContainerKind::Structure)
    );
    let mut out = Vec::new();
    loop {
        let field = reader.next_element().unwrap().unwrap();
        if field.value == Value::EndOfContainer {
            break;
        }
        out.push((field.tag.context().unwrap_or(255), field.value));
    }
    out
}

// --- §11.25.6.1 to §11.25.6.4: the cross-signing handshake ---------------------------------

#[test]
fn the_three_steps_run_in_order_and_install_the_icac() {
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    let ctx = on(F1, true);

    let response = fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &ctx)
        .expect("csr");
    let decoded = fields(&response);
    assert_eq!(
        decoded[0],
        (
            0,
            Value::Unsigned(u64::from(ICACCSRResponseStatusCodeEnum::OK.value()))
        )
    );
    assert_eq!(decoded[1], (1, Value::Octets(CSR)));

    let response = fixture
        .invoke(&cluster, jfa::ADD_ICAC, &add_icac(ICAC_MATCHING), &ctx)
        .expect("added");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(ICACResponseStatusEnum::OK.value()))
        )
    );
    assert_eq!(
        fixture.product.installed.borrow().as_slice(),
        &[(ICAC_MATCHING.to_vec(), F1)]
    );
}

#[test]
fn an_icac_over_a_key_the_node_never_asked_about_is_refused() {
    // §11.25.6.3 step 2: "The public key of the ICAC SHALL match the public key present in the
    // last ICACCSRResponse provided to the Administrator that sent the AddICAC command."
    // Without it, the anchor picks the key and the joining ecosystem installs a CA it cannot
    // sign with — or one the anchor can.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    let ctx = on(F1, true);
    fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &ctx)
        .unwrap();

    let response = fixture
        .invoke(&cluster, jfa::ADD_ICAC, &add_icac(ICAC_WRONG_KEY), &ctx)
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(ICACResponseStatusEnum::InvalidPublicKey.value()))
        )
    );
    assert!(fixture.product.installed.borrow().is_empty());
}

#[test]
fn an_icac_that_does_not_chain_is_a_different_failure() {
    // §11.25.6.3 steps 1 and 3 both answer `InvalidICAC`, and step 2 answers
    // `InvalidPublicKey`. Collapsing them would leave an administrator unable to tell a
    // mis-signed certificate from a mis-addressed one.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    let ctx = on(F1, true);
    fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &ctx)
        .unwrap();
    let response = fixture
        .invoke(&cluster, jfa::ADD_ICAC, &add_icac(ICAC_BAD_CHAIN), &ctx)
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(ICACResponseStatusEnum::InvalidICAC.value()))
        )
    );
}

#[test]
fn an_add_without_a_csr_installs_nothing() {
    // The pairing runs the other way too: an `AddICAC` that answers no request of this
    // administrator's has no public key to be checked against.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    let response = fixture
        .invoke(
            &cluster,
            jfa::ADD_ICAC,
            &add_icac(ICAC_MATCHING),
            &on(F1, true),
        )
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(ICACResponseStatusEnum::InvalidPublicKey.value()))
        )
    );
    assert!(fixture.product.installed.borrow().is_empty());
}

#[test]
fn one_administrators_csr_does_not_license_anothers_add() {
    // §11.25.6.3 scopes the pairing to "the Administrator that sent the AddICAC command".
    // Without that, a second ecosystem could ride the first's request.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &on(F1, true))
        .unwrap();

    let response = fixture
        .invoke(
            &cluster,
            jfa::ADD_ICAC,
            &add_icac(ICAC_MATCHING),
            &on(F2, true),
        )
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(ICACResponseStatusEnum::InvalidPublicKey.value()))
        )
    );
}

#[test]
fn both_commands_need_an_armed_fail_safe() {
    // §11.25.6.1 and §11.25.6.3: "If this command is received without an armed fail-safe
    // context … then this command SHALL fail with a FAILSAFE_REQUIRED status code." A Joint
    // Fabric half-formed is two ecosystems disagreeing about who may administer what.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    let ctx = on(F1, true);

    let response = fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &ctx)
        .expect("responded");
    assert_ne!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(ICACCSRResponseStatusCodeEnum::OK.value()))
        ),
        "no CSR without a fail-safe"
    );
    assert_eq!(
        fixture.invoke(&cluster, jfa::ADD_ICAC, &add_icac(ICAC_MATCHING), &ctx),
        Err(Status::FailsafeRequired)
    );
}

#[test]
fn a_peer_whose_vendor_was_never_verified_gets_no_csr() {
    // §11.25.6.1: "If the Fabric Table Vendor ID Verification Procedure has not been executed
    // against the initiator of this command, the command SHALL fail with a JfVidNotVerified
    // status code." Cross-signing an intermediate CA for a vendor nobody checked is the whole
    // risk the procedure exists to close.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    let response = fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &on(F1, false))
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(
                ICACCSRResponseStatusCodeEnum::VIDNotVerified.value()
            ))
        )
    );
    assert_eq!(fields(&response).len(), 1, "and no CSR field at all");
}

#[test]
fn a_node_with_no_administrator_fabric_has_nothing_to_sign_into() {
    // §11.25.6.1: "If the AdministratorFabricIndex attribute has the value of null, the command
    // SHALL fail with a InvalidAdministratorFabricIndex status code."
    let fixture = fixture();
    let cluster = fixture.cluster();
    fixture.arm();
    let response = fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &on(F1, true))
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(
                ICACCSRResponseStatusCodeEnum::InvalidAdministratorFabricIndex.value()
            ))
        )
    );
}

#[test]
fn only_one_icac_may_be_added_per_fail_safe() {
    // §11.25.6.1 and §11.25.6.3: "If a prior AddICAC command was successfully executed within
    // the fail-safe timer period, then this command SHALL fail with a CONSTRAINT_ERROR." A
    // second intermediate CA for the same join is a second root of trust for the same devices.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    let ctx = on(F1, true);
    fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &ctx)
        .unwrap();
    fixture
        .invoke(&cluster, jfa::ADD_ICAC, &add_icac(ICAC_MATCHING), &ctx)
        .unwrap();

    assert_eq!(
        fixture.invoke(&cluster, jfa::ADD_ICAC, &add_icac(ICAC_MATCHING), &ctx),
        Err(Status::ConstraintError)
    );
    // And a fresh CSR is refused too, which is what stops the sequence being restarted halfway.
    let response = fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &ctx)
        .expect("responded");
    assert_ne!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(ICACCSRResponseStatusCodeEnum::OK.value()))
        )
    );

    // The block is scoped to the fail-safe period, so a new one starts clean.
    cluster.reset_fail_safe_state();
    let response = fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &ctx)
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(ICACCSRResponseStatusCodeEnum::OK.value()))
        )
    );
}

#[test]
fn adding_an_icac_over_pase_is_refused() {
    // §11.25.6.3: "This command SHALL be received over a CASE session otherwise it SHALL fail
    // with an INVALID_COMMAND status code." A PASE session has no accessing fabric, so there is
    // no fabric for the ICAC to belong to.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    assert_eq!(
        fixture.invoke(
            &cluster,
            jfa::ADD_ICAC,
            &add_icac(ICAC_MATCHING),
            &InteractionContext {
                now: at(1),
                ..InteractionContext::default()
            }
        ),
        Err(Status::InvalidCommand)
    );
}

// --- §11.25.5.1: the attribute ---------------------------------------------------------------

#[test]
fn the_administrator_fabric_index_is_null_until_a_fabric_is_named() {
    let fixture = fixture();
    let cluster = fixture.cluster();
    let read = |cluster: &JointFabricAdministrator<'_, Product>| {
        let resolved = fixture
            .node
            .resolve(1, jfa::ID, jfa::ADMINISTRATOR_FABRIC_INDEX)
            .expect("the path exists");
        let mut buf = [0u8; 32];
        let mut w = TlvWriter::new(&mut buf);
        cluster
            .read(
                &resolved,
                &InteractionContext::default(),
                &mut w,
                Tag::Anonymous,
            )
            .unwrap();
        let bytes = w.finish().unwrap().to_vec();
        let mut reader = TlvReader::new(&bytes);
        match reader.next_element().unwrap().unwrap().value {
            Value::Null => None,
            Value::Unsigned(v) => Some(v),
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(read(&cluster), None);
    cluster.set_administrator_fabric(Some(F2));
    assert_eq!(read(&cluster), Some(2));
}

#[test]
fn a_successful_add_names_the_fabric_it_was_signed_into() {
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture.arm();
    let ctx = on(F1, true);
    fixture
        .invoke(&cluster, jfa::ICACCSR_REQUEST, &empty(), &ctx)
        .unwrap();
    fixture
        .invoke(&cluster, jfa::ADD_ICAC, &add_icac(ICAC_MATCHING), &ctx)
        .unwrap();
    assert_eq!(cluster.administrator_fabric(), Some(F1));
}

// --- §11.25.6.6 to §11.25.6.9 ---------------------------------------------------------------

#[test]
fn an_anchor_transfer_needs_user_consent() {
    // §11.25.4.2: the two refusals are "on-going Datastore operations" and "User has not
    // consented for Anchor Transfer". Neither is a decision this cluster can make.
    let fixture = fixture();
    let cluster = fixture.cluster();
    let ctx = on(F1, true);

    let response = fixture
        .invoke(&cluster, jfa::TRANSFER_ANCHOR_REQUEST, &empty(), &ctx)
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(
                TransferAnchorResponseStatusEnum::TransferAnchorStatusNoUserConsent.value()
            ))
        )
    );

    fixture.product.transfer.set(true);
    let response = fixture
        .invoke(&cluster, jfa::TRANSFER_ANCHOR_REQUEST, &empty(), &ctx)
        .expect("responded");
    assert_eq!(
        fields(&response)[0],
        (
            0,
            Value::Unsigned(u64::from(TransferAnchorResponseStatusEnum::OK.value()))
        )
    );
}

#[test]
fn completing_a_transfer_gives_up_the_administrator_fabric() {
    // §11.25.6.8 ends the transfer, and §12.2.5 makes the anchor role the other ecosystem's —
    // so this node no longer administers the Joint Fabric through the fabric it named.
    let fixture = fixture();
    let cluster = fixture.cluster();
    cluster.set_administrator_fabric(Some(F1));
    fixture
        .invoke(
            &cluster,
            jfa::TRANSFER_ANCHOR_COMPLETE,
            &empty(),
            &on(F1, true),
        )
        .expect("completed");
    assert!(fixture.product.transferred.get());
    assert_eq!(cluster.administrator_fabric(), None);
}

#[test]
fn an_announcement_says_which_endpoint_holds_the_cluster() {
    // §11.25.6.9, and §12.2.5 step 4a: a commissioner searches every endpoint's Descriptor for
    // the Joint Fabric Administrator device type. The announcement saves it the walk.
    let fixture = fixture();
    let cluster = fixture.cluster();
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.start_structure(Tag::Context(1)).unwrap();
    w.unsigned(Tag::Context(0), 3).unwrap();
    w.end_container().unwrap();
    let payload = w.finish().unwrap().to_vec();

    fixture
        .invoke(
            &cluster,
            jfa::ANNOUNCE_JOINT_FABRIC_ADMINISTRATOR,
            &payload,
            &on(F1, true),
        )
        .expect("announced");
    assert_eq!(fixture.product.announced.borrow().as_slice(), &[3]);
}

// --- ch. 12: the tags and the walk --------------------------------------------------------

#[test]
fn the_joint_fabric_tags_are_the_access_model() {
    // §12.2.4: a Joint Fabric names administrators by CAT rather than by Node ID, because the
    // set of them changes and spans companies.
    let tags = JointFabricTags::new(1).expect("v1");
    assert_eq!(tags.administrator.identifier(), 0xFFFF);
    assert_eq!(tags.anchor.identifier(), 0xFFFE);
    assert!(tags.grants_administrator(tags.administrator));
    assert!(!tags.grants_administrator(tags.anchor));
}

#[test]
fn revoking_an_administrator_means_visiting_every_node() {
    // §12.2.4.1 says what it costs: "Completing this operation requires visiting all the nodes
    // in the Joint Fabric, a task which might take a long time to complete or might never
    // complete if some Nodes are permanently offline." A device that reported success on the
    // first write would report the opposite of the truth.
    let before = JointFabricTags::new(3).expect("v3");
    let mut walk =
        Revocation::<8>::begin(&before, [NodeId(10), NodeId(11), NodeId(12)]).expect("begin");
    assert_eq!(walk.tags().administrator.version(), 4);
    assert!(!walk.tags().grants_administrator(before.administrator));

    walk.updated(NodeId(10));
    walk.updated(NodeId(11));
    assert!(
        !walk.is_complete(),
        "one node still honours the old version"
    );
    walk.updated(NodeId(12));
    assert!(walk.is_complete());
}

#[test]
fn a_node_id_for_a_joint_fabric_is_within_the_operational_range() {
    // §12.2.2: greater than zero and below 0xFFFF_FFEF_FFFF_FFFF, "representing a value within
    // the Operational NodeID range". Outside it, the NOC names something that is not a node.
    assert!(!jf::is_allocatable(NodeId(0)));
    assert!(jf::is_allocatable(NodeId(0x0000_0000_0000_0001)));
    assert!(!jf::is_allocatable(NodeId(0xFFFF_FFEF_FFFF_FFFF)));
}

// --- §11.24: the Joint Fabric Datastore -----------------------------------------------------

mod datastore {
    use super::{F1, at};
    use core::cell::RefCell;

    use matter_kit::clusters::joint_fabric_datastore::{
        AdminEntry, Datastore, DatastoreAccessControlEntryPrivilegeEnum, DatastoreStateEnum,
        FriendlyName, GroupEntry, IPK_KEY_SET, JointFabricDatastore,
    };
    use matter_kit::im::Status;
    use matter_kit::msg::{CaseAuthenticatedTag, GroupId, NodeId, VendorId};

    type Store = Datastore<4, 4, 4, 4, 8>;

    const NODE: NodeId = NodeId(0x1000);
    const OTHER: NodeId = NodeId(0x2000);
    const LIGHTS: GroupId = GroupId(1);

    fn name(text: &str) -> FriendlyName {
        FriendlyName::try_from(text).expect("short enough")
    }

    fn group(id: u16, cat: Option<u16>) -> GroupEntry {
        GroupEntry {
            group: GroupId(id),
            friendly_name: name("Lights"),
            key_set: Some(7),
            cat,
            cat_version: Some(1),
            permission: DatastoreAccessControlEntryPrivilegeEnum::Operate,
        }
    }

    #[test]
    fn a_node_is_pending_before_it_is_committed() {
        // §11.24.4.1: "By performing this work in two steps (first pending status, then
        // committed status), the design can prevent error scenarios where a node is brought
        // onto a fabric without appearing in the Datastore." A node that commissioned but never
        // reached the datastore would be reachable, administrable — and invisible to every other
        // ecosystem on the fabric.
        let mut store = Store::new();
        store.add_pending_node(NODE, "Kitchen lamp", 100).unwrap();
        assert_eq!(
            store.nodes()[0].commissioning.state,
            DatastoreStateEnum::Pending
        );

        store.refresh_node(NODE, 200).unwrap();
        assert_eq!(
            store.nodes()[0].commissioning.state,
            DatastoreStateEnum::Pending,
            "the refresh is itself an operation that can fail"
        );
        store.node_refreshed(NODE, Ok(()), 300);
        assert_eq!(
            store.nodes()[0].commissioning.state,
            DatastoreStateEnum::Committed
        );
        assert_eq!(store.nodes()[0].commissioning.updated_at, 300);
    }

    #[test]
    fn a_failed_refresh_records_why_and_stays_for_the_review() {
        // §11.24.7.11: "update the State field … to CommitFailed and FailureCode code to the
        // returned error. The pending change SHALL be applied in a subsequent Node Refresh."
        let mut store = Store::new();
        store.add_pending_node(NODE, "Kitchen lamp", 100).unwrap();
        store.node_refreshed(NODE, Err(Status::Busy), 200);
        assert_eq!(
            store.nodes()[0].commissioning.state,
            DatastoreStateEnum::CommitFailed
        );
        assert_eq!(store.nodes()[0].commissioning.failure, Some(Status::Busy));
        // §11.24.4.3's periodic review is what picks it up again.
        assert_eq!(store.nodes_needing_review::<4>().as_slice(), &[NODE]);
    }

    #[test]
    fn a_committed_node_with_nothing_outstanding_needs_no_review() {
        let mut store = Store::new();
        store.add_pending_node(NODE, "Kitchen lamp", 100).unwrap();
        store.node_refreshed(NODE, Ok(()), 200);
        assert!(store.nodes_needing_review::<4>().is_empty());
    }

    #[test]
    fn the_same_node_is_not_added_twice() {
        // §11.24.7.10: "If a DatastoreNodeInformationEntryStruct exists for the given NodeID,
        // then this command SHALL fail."
        let mut store = Store::new();
        store.add_pending_node(NODE, "Kitchen lamp", 0).unwrap();
        assert_eq!(
            store.add_pending_node(NODE, "Kitchen lamp again", 0),
            Err(Status::ConstraintError)
        );
    }

    #[test]
    fn refreshing_or_removing_an_unknown_node_is_not_found() {
        let mut store = Store::new();
        assert_eq!(store.refresh_node(NODE, 0), Err(Status::NotFound));
        assert_eq!(store.remove_node(NODE), Err(Status::NotFound));
    }

    #[test]
    fn a_key_set_in_use_cannot_be_removed() {
        // §11.24.7.3 step 2: a key set a node still holds is one whose removal would leave that
        // node with a key for something the datastore no longer describes.
        let mut store = Store::new();
        store.add_key_set(7).unwrap();
        store.add_pending_node(NODE, "Lamp", 0).unwrap();
        store.add_node_key_set(NODE, 7, 0).unwrap();
        assert_eq!(store.remove_key_set(7), Err(Status::ConstraintError));

        // Removing the node removes the reference with it.
        store.remove_node(NODE).unwrap();
        assert!(store.remove_key_set(7).is_ok());
    }

    #[test]
    fn the_ipk_key_set_is_not_removable() {
        // §11.24.7.3: "Attempt to remove the IPK, which has GroupKeySetID of 0, SHALL fail with
        // response CONSTRAINT_ERROR." The IPK is the fabric's own identity key; without it
        // nothing could complete a CASE handshake.
        let mut store = Store::new();
        store.add_key_set(IPK_KEY_SET).unwrap();
        assert_eq!(
            store.remove_key_set(IPK_KEY_SET),
            Err(Status::ConstraintError)
        );
    }

    #[test]
    fn a_key_set_is_added_once() {
        let mut store = Store::new();
        store.add_key_set(7).unwrap();
        assert_eq!(store.add_key_set(7), Err(Status::ConstraintError));
        assert_eq!(store.remove_key_set(9), Err(Status::NotFound));
    }

    #[test]
    fn a_group_cannot_claim_the_joint_fabrics_own_tags() {
        // §11.24.7.4: "Attempts to add a group with a GroupCAT value of Administrator CAT or
        // Anchor CAT SHALL fail with CONSTRAINT_ERROR." A group that claimed one would grant
        // every member of it the whole fabric.
        let mut store = Store::new();
        store.add_key_set(7).unwrap();
        for reserved in [
            CaseAuthenticatedTag::ADMINISTRATOR_IDENTIFIER,
            CaseAuthenticatedTag::ANCHOR_IDENTIFIER,
        ] {
            assert_eq!(
                store.add_group(group(1, Some(reserved))),
                Err(Status::ConstraintError),
                "CAT {reserved:#06x}"
            );
        }
        assert!(store.add_group(group(1, Some(42))).is_ok());
    }

    #[test]
    fn a_group_with_members_cannot_be_removed() {
        // §11.24.7.6 step 2, and the exemption that makes a two-phase deletion possible: an
        // entry already `DeletePending` is a removal in progress, not a live reference, so the
        // two halves of a removal do not deadlock each other.
        let mut store = Store::new();
        store.add_key_set(7).unwrap();
        store.add_group(group(1, Some(42))).unwrap();
        store.add_pending_node(NODE, "Lamp", 0).unwrap();
        store.add_group_to_endpoint(NODE, 1, LIGHTS, 0).unwrap();

        assert_eq!(store.remove_group(LIGHTS), Err(Status::ConstraintError));

        store
            .remove_group_from_endpoint(NODE, 1, LIGHTS, 10)
            .unwrap();
        assert_eq!(
            store.endpoint_groups()[0].status.state,
            DatastoreStateEnum::DeletePending
        );
        assert!(
            store.remove_group(LIGHTS).is_ok(),
            "a membership on its way out no longer blocks it"
        );
    }

    #[test]
    fn a_group_naming_a_key_set_that_does_not_exist_is_refused() {
        let mut store = Store::new();
        assert_eq!(store.add_group(group(1, Some(42))), Err(Status::NotFound));
    }

    #[test]
    fn a_membership_needs_both_a_node_and_a_group() {
        let mut store = Store::new();
        assert_eq!(
            store.add_group_to_endpoint(NODE, 1, LIGHTS, 0),
            Err(Status::NotFound)
        );
        store.add_pending_node(NODE, "Lamp", 0).unwrap();
        assert_eq!(
            store.add_group_to_endpoint(NODE, 1, LIGHTS, 0),
            Err(Status::NotFound),
            "the group is still unknown"
        );
    }

    #[test]
    fn removing_a_node_takes_its_memberships_with_it() {
        // Otherwise §11.24.7.6's "ensure there are no Nodes in this group" would be true of a
        // node that no longer exists, and the group could never be removed.
        let mut store = Store::new();
        store.add_key_set(7).unwrap();
        store.add_group(group(1, Some(42))).unwrap();
        store.add_pending_node(NODE, "Lamp", 0).unwrap();
        store.add_group_to_endpoint(NODE, 1, LIGHTS, 0).unwrap();
        store.add_node_key_set(NODE, 7, 0).unwrap();

        store.remove_node(NODE).unwrap();
        assert!(store.endpoint_groups().is_empty());
        assert!(store.node_key_sets().is_empty());
        assert!(store.remove_group(LIGHTS).is_ok());
    }

    #[test]
    fn a_deletion_is_applied_only_once_the_node_has_acknowledged_it() {
        // §11.24.4.3: the datastore "SHALL periodically review its data in a Pending and
        // PendingDeletion state and attempt to reach the corresponding Node in order to apply
        // these updates". Dropping the row at the command would lose the fact that the node has
        // not been told.
        let mut store = Store::new();
        store.add_key_set(7).unwrap();
        store.add_group(group(1, Some(42))).unwrap();
        store.add_pending_node(NODE, "Lamp", 0).unwrap();
        store.add_group_to_endpoint(NODE, 1, LIGHTS, 0).unwrap();
        store
            .remove_group_from_endpoint(NODE, 1, LIGHTS, 10)
            .unwrap();

        assert_eq!(store.endpoint_groups().len(), 1, "still there, marked");
        assert_eq!(store.nodes_needing_review::<4>().as_slice(), &[NODE]);
        store.deletion_applied(NODE, 1, LIGHTS);
        assert!(store.endpoint_groups().is_empty());
    }

    #[test]
    fn an_administrator_is_recorded_with_its_vendor() {
        // §12.2.5 step 4d: "At least the name associated with the VendorID of the onboarded
        // Fabric SHALL be presented to the User." The datastore is where the other ecosystems
        // read it from.
        let mut store = Store::new();
        store
            .add_admin(AdminEntry {
                node: OTHER,
                friendly_name: name("Ecosystem B"),
                vendor: VendorId(0xFFF1),
                icac_len: 250,
            })
            .unwrap();
        assert_eq!(store.admins()[0].vendor, VendorId(0xFFF1));
        assert_eq!(store.remove_admin(NODE), Err(Status::NotFound));
        assert!(store.remove_admin(OTHER).is_ok());
    }

    #[test]
    fn a_full_table_says_resource_exhausted() {
        // §11.24.4: "The RESOURCE_EXHAUSTED error MAY be used by the Datastore to indicate that
        // a storage capacity limit of the Datastore has been reached", and the specification
        // then requires the user be told by other means — so the status has to be distinct from
        // a constraint failure.
        let mut store = Datastore::<1, 1, 1, 1, 1>::new();
        store.add_pending_node(NODE, "One", 0).unwrap();
        assert_eq!(
            store.add_pending_node(OTHER, "Two", 0),
            Err(Status::ResourceExhausted)
        );
    }

    #[test]
    fn a_name_longer_than_the_constraint_is_refused() {
        // §11.24.5's `FriendlyName` is "max 32" everywhere it appears.
        let mut store = Store::new();
        let long = "x".repeat(33);
        assert_eq!(
            store.add_pending_node(NODE, &long, 0),
            Err(Status::ConstraintError)
        );
    }

    #[test]
    fn the_anchor_is_what_the_other_ecosystems_read() {
        let store = RefCell::new(Store::new());
        store
            .borrow_mut()
            .set_anchor(NODE, VendorId(0xFFF1), "Home")
            .unwrap();
        let cluster = JointFabricDatastore::new(&store);
        let _ = cluster.store();
        assert_eq!(store.borrow().anchor(), Some((NODE, VendorId(0xFFF1))));
        let _ = (F1, at(0));
    }
}
