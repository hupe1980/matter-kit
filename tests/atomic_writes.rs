//! Atomic writes end to end (Core §7.15).
//!
//! An attribute with the Atomic quality exists because its value is only meaningful alongside
//! others — a thermostat's heating and cooling setpoints, where each is legal alone and the
//! pair can contradict. The whole mechanism is there so the contradictory intermediate state
//! never exists.
//!
//! Which means the rule that carries it is negative, and easy to leave out: §7.15.3 says such
//! an attribute is writable *only* inside a claim. A server that implemented `AtomicRequest`
//! faithfully and still let an ordinary Write Request through would have built the machinery
//! and left the door open beside it.

#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::cell::RefCell;

use matter_kit::config::DefaultConfig;
use matter_kit::dm::{
    AttributeDescriptor, AttributeQualities, ClusterDescriptor, CommandDescriptor, Endpoint, Node,
    Privilege, Resolved,
};
use matter_kit::im::{
    AccessControl, AtomicWrites, AttributeData, AttributePath, InteractionContext, Outcome, Server,
    Status, WriteOp, WriteResponse, Writer,
};
use matter_kit::msg::{FabricIndex, NodeId};
use matter_kit::platform::{Duration, Instant};
use matter_kit::tlv::{ContainerKind, Tag, TlvWriter};

const THERMOSTAT: u32 = 0x0201;
/// `OccupiedCoolingSetpoint` and `OccupiedHeatingSetpoint`, both atomic.
const COOL: u32 = 0x0011;
const HEAT: u32 = 0x0012;
/// An ordinary writable attribute on the same cluster, for contrast.
const PLAIN: u32 = 0x0015;

const ATTRS: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_write(COOL).with_qualities(AttributeQualities::ATOMIC),
    AttributeDescriptor::read_write(HEAT).with_qualities(AttributeQualities::ATOMIC),
    AttributeDescriptor::read_write(PLAIN),
];
const NO_CMDS: &[CommandDescriptor] = &[];
const CL: &[ClusterDescriptor<'static>] = &[ClusterDescriptor {
    id: THERMOSTAT,
    revision: 8,
    feature_map: 0,
    attributes: ATTRS,
    accepted_commands: NO_CMDS,
    generated_commands: &[],
    events: &[],
}];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(1, CL)];

/// Records what actually reached the cluster.
#[derive(Default)]
struct Thermostat {
    applied: RefCell<Vec<(u32, u64)>>,
}

impl matter_kit::im::ClusterHandler for Thermostat {
    fn read(
        &self,
        _r: &Resolved<'_>,
        _c: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.unsigned(tag, 0).map_err(|_| Status::Failure)
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        _op: WriteOp,
        _ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        let value = u64::from(*data.last().unwrap_or(&0));
        self.applied.borrow_mut().push((resolved.attribute, value));
        Ok(())
    }
}

struct All;
impl AccessControl for All {
    fn allows(&self, _p: &AttributePath, _r: Privilege) -> Outcome {
        Outcome::Granted
    }
}

fn value(v: u8) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let mut w = TlvWriter::new_in(&mut buf, ContainerKind::Structure);
    w.unsigned(Tag::Context(2), u64::from(v)).unwrap();
    w.finish().unwrap().to_vec()
}

fn write(device: &Thermostat, ctx: &InteractionContext<'_>, attribute: u32, v: u8) -> Vec<Status> {
    let data = value(v);
    let block = AttributeData {
        data_version: None,
        path: AttributePath::attribute(1, THERMOSTAT, attribute),
        data: &data,
    };
    let access = All;
    let server = Server::new(Node::new(ENDPOINTS), &access, device, 64);
    let mut buf = [0u8; 1024];
    let (bytes, _) = server
        .serve_write([Ok(block)], ctx, false, &mut buf)
        .expect("serve_write");
    WriteResponse::decode(bytes)
        .expect("decode")
        .statuses()
        .expect("statuses")
        .map(|s| s.expect("decode").status.status)
        .collect()
}

fn alice() -> Writer {
    Writer {
        node: NodeId(0x0000_0000_0000_1111),
        fabric: FabricIndex(1),
    }
}

fn at(ms: u64) -> Instant {
    Instant::from_micros(ms * 1000)
}

/// The rule the whole mechanism rests on: no claim, no write.
#[test]
fn an_atomic_attribute_cannot_be_written_outside_a_claim() {
    let device = Thermostat::default();
    let ctx = InteractionContext::new()
        .with_fabric(FabricIndex(1))
        .from_peer(alice().node);

    assert_eq!(
        write(&device, &ctx, HEAT, 21),
        vec![Status::InvalidInState],
        "§7.15.3: an atomic attribute is writable only inside a claim"
    );
    assert!(
        device.applied.borrow().is_empty(),
        "and the cluster never saw it — refused before it could apply anything"
    );

    // An ordinary attribute on the same cluster is unaffected. The quality is per attribute,
    // not per cluster, so making it a cluster-wide gate would break every other write.
    assert_eq!(write(&device, &ctx, PLAIN, 5), vec![Status::Success]);
    assert_eq!(device.applied.borrow().as_slice(), &[(PLAIN, 5)]);
}

/// With a claim covering it, the write proceeds.
#[test]
fn a_claim_admits_exactly_the_attributes_it_covers() {
    let mut claims = AtomicWrites::<DefaultConfig, 4, 4>::new();
    claims
        .begin(
            1,
            THERMOSTAT,
            alice(),
            &[HEAT],
            Duration::from_millis(1_000),
            at(0),
        )
        .expect("begin");
    let claim = claims.find(1, THERMOSTAT, alice()).expect("held").as_ref();

    let device = Thermostat::default();
    let ctx = InteractionContext::new()
        .with_fabric(FabricIndex(1))
        .from_peer(alice().node)
        .under_claim(claim);

    assert_eq!(write(&device, &ctx, HEAT, 21), vec![Status::Success]);
    // The claim covers HEAT and not COOL, and the difference is enforced per attribute.
    assert_eq!(write(&device, &ctx, COOL, 25), vec![Status::InvalidInState]);
    assert_eq!(device.applied.borrow().as_slice(), &[(HEAT, 21)]);
}

/// A lapsed claim stops admitting writes at the moment it lapses.
#[test]
fn a_claim_that_has_timed_out_no_longer_admits_anything() {
    // §7.15.6.4.3.e.iii: the server "SHALL roll back any pending writes and discard the
    // atomic write" when no CommitWrite arrives in time. A claim that kept working past its
    // deadline would let a client that crashed mid-write resume as if nothing happened.
    let mut claims = AtomicWrites::<DefaultConfig, 4, 4>::new();
    claims
        .begin(
            1,
            THERMOSTAT,
            alice(),
            &[HEAT],
            Duration::from_millis(1_000),
            at(0),
        )
        .expect("begin");

    assert_eq!(claims.reap(at(1_001)), 1, "the deadline passed");
    assert!(claims.find(1, THERMOSTAT, alice()).is_none());

    let device = Thermostat::default();
    let ctx = InteractionContext::new()
        .with_fabric(FabricIndex(1))
        .from_peer(alice().node);
    assert_eq!(write(&device, &ctx, HEAT, 21), vec![Status::InvalidInState]);
}

/// A wildcard write discards an atomic path rather than reporting it (§8.7.3.2 step 1c).
#[test]
fn a_wildcard_write_discards_an_atomic_attribute_it_has_no_claim_for() {
    // The concrete/expanded asymmetry applies here too: telling a wildcard writer that an
    // attribute exists but is atomic would map the node's atomic attributes to anyone.
    let device = Thermostat::default();
    let ctx = InteractionContext::new()
        .with_fabric(FabricIndex(1))
        .from_peer(alice().node);

    let data = value(7);
    let block = AttributeData {
        data_version: None,
        path: AttributePath {
            attribute: None,
            ..AttributePath::attribute(1, THERMOSTAT, 0)
        },
        data: &data,
    };
    let access = All;
    let server = Server::new(Node::new(ENDPOINTS), &access, &device, 64);
    let mut buf = [0u8; 1024];
    let (bytes, _) = server
        .serve_write([Ok(block)], &ctx, false, &mut buf)
        .expect("serve_write");
    let statuses: Vec<Status> = WriteResponse::decode(bytes)
        .expect("decode")
        .statuses()
        .expect("statuses")
        .map(|s| s.expect("decode").status.status)
        .collect();

    // Only the ordinary attribute is written; the two atomic ones are silently discarded.
    assert_eq!(statuses, vec![Status::Success]);
    assert_eq!(device.applied.borrow().as_slice(), &[(PLAIN, 7)]);
}
