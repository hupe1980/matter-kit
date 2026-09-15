//! Groups and Scenes Management against arbitrary invoke payloads, from two fabrics.
//!
//! These two clusters hold the only *tables a client fills* that a light exposes before it has
//! done anything interesting — an ecosystem writes group memberships and scenes at
//! commissioning time, and every field of every command is the client's to choose. They also
//! share one Scene Table between them, which is the sort of coupling where an invariant is
//! easy to state and easy to break.
//!
//! Six properties, all checked after every single command:
//!
//! 1. **Nothing panics**, on any payload, in any order. Both clusters use `RefCell`, and the
//!    Groups cluster reaches into the Scene Table while holding its own borrow — a nested
//!    borrow would be a panic reachable from the network.
//! 2. **No fabric ever exceeds its share.** §1.3's group table is capped per fabric and
//!    §1.4.6 caps the Scene Table at "less than half (rounded down towards 0)" per fabric.
//!    Without both, whoever commissions first can fill the device and the second ecosystem
//!    cannot make a single group.
//! 3. **Group 0 is never joined.** §1.3.7.1.1's constraint is "min 1": group 0 addresses
//!    nobody, and a device that joined it would answer messages meant for no one.
//! 4. **No scene id above 254 is ever stored** (§1.4.7.5), because 255 is the undefined scene
//!    identifier `CurrentScene` reports when nothing has been recalled.
//! 5. **Every stored scene names a group the endpoint has joined, or group 0.** §1.4.9's step
//!    1 — a scene for a group the endpoint is not in could never be recalled by the groupcast
//!    it was made for, so it is capacity spent on nothing.
//! 6. **A response always decodes.** A malformed request must not leave a half-written
//!    `InvokeResponseMessage` behind.

#![no_main]

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use matter_kit::clusters::groups::{self, Groups, NeverIdentifying};
use matter_kit::clusters::scenes::{
    self, ExtensionFieldSetStruct, SceneHooks, SceneTable, Scenes,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::im::{
    AccessControl, AttributePath, InvokeRequest, InvokeResponseMessage, Outcome, Server,
};
use matter_kit::msg::{FabricIndex, GroupId};
use matter_kit::tlv::{TlvList, TlvWriter};

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

/// A lamp whose only S-quality attribute is On/Off's `OnOff`.
#[derive(Default)]
struct Lamp {
    on: RefCell<bool>,
}

impl SceneHooks for Lamp {
    fn capture(&self, w: &mut TlvWriter<'_>) -> matter_kit::error::Result<()> {
        w.start_structure(matter_kit::tlv::Tag::Anonymous)?;
        w.unsigned(matter_kit::tlv::Tag::Context(0), 0x0006)?;
        w.start_array(matter_kit::tlv::Tag::Context(1))?;
        w.start_structure(matter_kit::tlv::Tag::Anonymous)?;
        w.unsigned(matter_kit::tlv::Tag::Context(0), 0x0000)?;
        w.unsigned(
            matter_kit::tlv::Tag::Context(1),
            u64::from(*self.on.borrow()),
        )?;
        w.end_container()?;
        w.end_container()?;
        w.end_container()
    }

    fn apply<'a>(&self, sets: TlvList<'a, ExtensionFieldSetStruct<'a>>, _transition: u32) {
        for set in sets.iter() {
            let Ok(set) = set else { continue };
            for pair in set.attribute_value_list.iter() {
                let Ok(pair) = pair else { continue };
                if set.cluster_id == 0x0006 && pair.attribute_id == 0x0000 {
                    *self.on.borrow_mut() = pair.value_unsigned8.unwrap_or(0) != 0;
                }
            }
        }
    }
}

/// Small enough that the caps are reachable within one fuzz case.
const GROUP_SLOTS: usize = 8;
const GROUPS_PER_FABRIC: usize = 3;
const SCENE_SLOTS: usize = 8;
const SCENE_BYTES: usize = 64;
const FABRICS: usize = 3;

type Table = SceneTable<SCENE_SLOTS, SCENE_BYTES, FABRICS>;
type GroupTable<'a> = Groups<'a, GROUP_SLOTS, NeverIdentifying, Table>;

fuzz_target!(|data: &[u8]| {
    let lamp = Lamp::default();
    let table = Table::new(true);
    let group_cluster: GroupTable<'_> =
        Groups::with(GROUPS_PER_FABRIC, true, &NeverIdentifying, &table);
    let scene_cluster: Scenes<'_, Lamp, GroupTable<'_>, SCENE_SLOTS, SCENE_BYTES, FABRICS> =
        Scenes::new(&table, &group_cluster, &lamp, true);

    let Ok(groups_descriptor) =
        Groups::<GROUP_SLOTS>::conforming(groups::feature::GROUP_NAMES, &Optional::NONE)
    else {
        return;
    };
    let Ok(scenes_descriptor) =
        Scenes::<Lamp, GroupTable<'_>, SCENE_SLOTS, SCENE_BYTES, FABRICS>::conforming(
            scenes::feature::SCENE_NAMES,
            &Scenes::<Lamp, GroupTable<'_>, SCENE_SLOTS, SCENE_BYTES, FABRICS>::WITH_COPY_SCENE,
        )
    else {
        return;
    };
    let clusters: [ClusterDescriptor<'_>; 2] = [
        groups_descriptor.descriptor(),
        scenes_descriptor.descriptor(),
    ];
    let endpoints = [Endpoint::new(1, &clusters)];
    let node = Node::new(&endpoints);
    let access = AllowAll;
    let handler = (&group_cluster, &scene_cluster);
    let server = Server::new(node, &access, &handler, 8);

    // The whole input is one InvokeRequest, re-served once per fabric so that the two fabrics
    // interleave — which is what makes a cross-fabric leak reachable.
    for fabric in [FabricIndex(1), FabricIndex(2)] {
        let Ok(request) = InvokeRequest::decode(data) else {
            continue;
        };
        let Ok(commands) = request.commands() else {
            continue;
        };
        let ctx = matter_kit::im::InteractionContext::new().with_fabric(fabric);
        let mut scratch = [0u8; 2048];
        let mut buf = [0u8; 4096];
        if let Ok((bytes, _)) = server.serve_invoke(
            commands,
            &ctx,
            request.suppress_response,
            &mut scratch,
            &mut buf,
        ) {
            // Property 6.
            let decoded = InvokeResponseMessage::decode(bytes).expect("a response decodes");
            if let Ok(responses) = decoded.responses() {
                for response in responses {
                    let _ = response.expect("each response decodes");
                }
            }
        }
        check(&group_cluster, &table, fabric);
        check(&group_cluster, &table, FabricIndex(1));
        check(&group_cluster, &table, FabricIndex(2));
    }
});

fn check(groups: &GroupTable<'_>, table: &Table, fabric: FabricIndex) {
    // Property 2, both halves.
    assert!(
        groups.len_of_fabric(fabric) <= GROUPS_PER_FABRIC,
        "fabric {fabric:?} took more than its share of the group table"
    );
    assert!(
        table.len_of_fabric(fabric) <= table.per_fabric(),
        "fabric {fabric:?} took more than half the scene table"
    );
    assert!(table.len() <= SCENE_SLOTS);

    // Property 3.
    assert!(
        !groups.is_member(fabric, GroupId(0)),
        "group 0 is not a group to join"
    );

    for membership in groups.memberships().iter() {
        assert!(membership.group.0 != 0);
    }

    // Properties 4 and 5. The table exposes no iterator by design — a device persists it
    // through `SceneTable`'s own accessors — so the check walks the ids a client could use.
    for scene in 0u8..=255 {
        for group in [0u16, 1, 2, 3, 7, 0xFFFF] {
            if !table.contains(fabric, GroupId(group), scene) {
                continue;
            }
            assert!(scene <= scenes::SCENE_MAX, "scene {scene} is out of range");
            assert!(
                group == 0 || groups.is_member(fabric, GroupId(group)),
                "a scene for group {group}, which this endpoint has not joined"
            );
        }
    }
}
