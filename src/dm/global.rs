//! The global attributes every cluster instance serves (Core §7.13).
//!
//! §7.13's Table 95 gives five attributes that "are used for self-description of the
//! server", and every one is mandatory on every cluster. Three of them are lists *of the
//! cluster's own contents*, which is why they are synthesised here from a
//! [`ClusterDescriptor`] rather than written into it: a hand-maintained `AttributeList` is a
//! list that drifts from what the cluster actually serves, and it is read by every
//! commissioner during discovery.
//!
//! `EventList` (`0xFFFA`) is deliberately absent. Table 95 marks its conformance `D` —
//! deprecated — so a server that emitted it would be advertising something the current
//! specification has withdrawn.

use crate::dm::access::{Access, Privilege};
use crate::dm::meta::{AttributeDescriptor, AttributeQualities, ClusterDescriptor, Reporting};
use crate::error::Result;
use crate::im::AttributeId;
use crate::tlv::{ContainerKind, Tag, TlvWriter};

/// `ClusterRevision` (§7.13.1) — `uint16`, `min 1`, `F`, `RV`.
pub const CLUSTER_REVISION: AttributeId = 0xFFFD;
/// `FeatureMap` (§7.13.2) — `map32`, `F`, `RV`.
pub const FEATURE_MAP: AttributeId = 0xFFFC;
/// `AttributeList` (§7.13.3) — `list[attrib-id]`, `F`, `RV`.
pub const ATTRIBUTE_LIST: AttributeId = 0xFFFB;
/// `EventList` (`0xFFFA`) — conformance `D`, deprecated, and not served.
pub const EVENT_LIST: AttributeId = 0xFFFA;
/// `AcceptedCommandList` (§7.13.4) — `list[command-id]`, `F`, `RV`.
pub const ACCEPTED_COMMAND_LIST: AttributeId = 0xFFF9;
/// `GeneratedCommandList` (§7.13.5) — `list[command-id]`, `F`, `RV`.
pub const GENERATED_COMMAND_LIST: AttributeId = 0xFFF8;

/// The global attribute ids a cluster serves, ascending.
///
/// `EventList` is not among them: Table 95 gives it conformance `D`.
pub const ATTRIBUTE_IDS: &[AttributeId] = &[
    GENERATED_COMMAND_LIST,
    ACCEPTED_COMMAND_LIST,
    ATTRIBUTE_LIST,
    FEATURE_MAP,
    CLUSTER_REVISION,
];

/// Whether `id` is one of §7.13's global attributes, deprecated ones included.
///
/// The deprecated `EventList` counts: a cluster must not *declare* it either, and a
/// descriptor that did would produce a duplicate in `AttributeList`.
#[must_use]
pub const fn is_global(id: AttributeId) -> bool {
    matches!(
        id,
        GENERATED_COMMAND_LIST
            | ACCEPTED_COMMAND_LIST
            | EVENT_LIST
            | ATTRIBUTE_LIST
            | FEATURE_MAP
            | CLUSTER_REVISION
    )
}

/// The descriptor for a global attribute, or `None` if `id` is not one.
///
/// All five share the same access: Table 95 gives every one `F` (fixed) and `RV` — readable
/// at View, and never writable.
#[must_use]
pub fn descriptor(id: AttributeId) -> Option<AttributeDescriptor> {
    if !is_global(id) || id == EVENT_LIST {
        return None;
    }
    Some(AttributeDescriptor {
        id,
        access: Access::read_only(Privilege::View),
        reporting: Reporting::OnChange,
        // `F` — fixed for the life of the node, so the reporting engine never has to watch
        // one.
        qualities: AttributeQualities::FIXED,
    })
}

/// Writes a global attribute's value into an `AttributeDataIB`'s slot.
///
/// `tag` is where the value goes — context 2 inside an `AttributeDataIB` (§10.6.4). The
/// three list-valued globals are emitted in ascending id order, which is the order
/// [`ClusterDescriptor::attribute_ids`] and its siblings produce.
///
/// Returns `Ok(false)` if `id` is not a global this server serves, so a caller can fall
/// through to the cluster's own attributes without a second lookup.
pub fn encode(
    cluster: &ClusterDescriptor<'_>,
    id: AttributeId,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> Result<bool> {
    match id {
        CLUSTER_REVISION => w.unsigned(tag, u64::from(cluster.revision))?,
        FEATURE_MAP => w.unsigned(tag, u64::from(cluster.feature_map))?,
        ATTRIBUTE_LIST => {
            w.start_array(tag)?;
            for attribute in cluster.attribute_ids() {
                w.unsigned(Tag::Anonymous, u64::from(attribute))?;
            }
            w.end_container()?;
        }
        ACCEPTED_COMMAND_LIST => {
            w.start_array(tag)?;
            for command in cluster.accepted_commands {
                w.unsigned(Tag::Anonymous, u64::from(command.id))?;
            }
            w.end_container()?;
        }
        GENERATED_COMMAND_LIST => {
            w.start_array(tag)?;
            for command in cluster.generated_command_ids() {
                w.unsigned(Tag::Anonymous, u64::from(command))?;
            }
            w.end_container()?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Writes a global attribute's value as a standalone fragment, for a caller assembling an
/// `AttributeDataIB` by hand.
pub fn encode_value<'b>(
    cluster: &ClusterDescriptor<'_>,
    id: AttributeId,
    tag: Tag,
    buf: &'b mut [u8],
) -> Result<Option<&'b [u8]>> {
    let mut w = TlvWriter::new_in(buf, ContainerKind::Structure);
    if !encode(cluster, id, &mut w, tag)? {
        return Ok(None);
    }
    w.finish().map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::meta::CommandDescriptor;
    #[cfg(feature = "std")]
    use crate::tlv::PrettyIn;

    const ATTRIBUTES: &[AttributeDescriptor] = &[
        AttributeDescriptor::read_only(0x0000),
        AttributeDescriptor::read_write(0x0001),
        AttributeDescriptor::read_only(0x0010),
    ];
    const COMMANDS: &[CommandDescriptor] = &[
        CommandDescriptor::new(0x00).with_response(0x05),
        CommandDescriptor::new(0x01),
    ];

    fn cluster() -> ClusterDescriptor<'static> {
        ClusterDescriptor {
            id: 0x0006,
            revision: 6,
            feature_map: 0x0000_0001,
            attributes: ATTRIBUTES,
            accepted_commands: COMMANDS,
            generated_commands: &[0x40],
            events: &[],
        }
    }

    /// The encoded value of a global, as bytes.
    fn encoded(id: AttributeId, buf: &mut [u8; 128]) -> heapless::Vec<u8, 128> {
        let bytes = encode_value(&cluster(), id, Tag::Context(2), buf)
            .expect("encode")
            .expect("a global");
        heapless::Vec::from_slice(bytes).expect("fits")
    }

    #[test]
    fn the_ids_are_the_ones_table_95_assigns() {
        assert_eq!(CLUSTER_REVISION, 0xFFFD);
        assert_eq!(FEATURE_MAP, 0xFFFC);
        assert_eq!(ATTRIBUTE_LIST, 0xFFFB);
        assert_eq!(EVENT_LIST, 0xFFFA);
        assert_eq!(ACCEPTED_COMMAND_LIST, 0xFFF9);
        assert_eq!(GENERATED_COMMAND_LIST, 0xFFF8);
    }

    #[test]
    fn the_deprecated_event_list_is_not_served() {
        // Table 95 gives EventList conformance `D`. A server that offered it would be
        // advertising something the specification has withdrawn.
        assert!(is_global(EVENT_LIST), "still reserved");
        assert!(descriptor(EVENT_LIST).is_none(), "but not served");
        assert!(!ATTRIBUTE_IDS.contains(&EVENT_LIST));
    }

    #[test]
    fn attribute_list_is_the_clusters_own_attributes_then_the_globals() {
        // §7.13.3: "a list of the attribute IDs of the attributes supported by the cluster
        // instance" — which includes the globals, since every instance supports them.
        let ids: heapless::Vec<AttributeId, 16> = cluster().attribute_ids().collect();
        assert_eq!(
            ids.as_slice(),
            &[
                0x0000, 0x0001, 0x0010, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD
            ]
        );
        assert!(
            ids.windows(2).all(|w| matches!(w, [a, b] if a < b)),
            "ascending: {ids:04x?}"
        );
    }

    #[test]
    fn generated_command_list_is_derived_from_the_accepted_ones() {
        // §7.13.5 ties the two lists together: every response in one has its request in the
        // other. Deriving it is what stops them disagreeing.
        let ids: heapless::Vec<crate::im::CommandId, 8> =
            cluster().generated_command_ids().collect();
        assert_eq!(
            ids.as_slice(),
            &[0x05, 0x40],
            "the response, then the standalone"
        );
    }

    #[test]
    fn the_scalar_globals_encode_their_values() {
        // `24 02 06` is a context-2 one-octet unsigned holding 6 — the cluster revision.
        let mut buf = [0u8; 128];
        assert_eq!(
            encoded(CLUSTER_REVISION, &mut buf).as_slice(),
            &[0x24, 0x02, 6]
        );
        assert_eq!(encoded(FEATURE_MAP, &mut buf).as_slice(), &[0x24, 0x02, 1]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn the_list_globals_encode_as_arrays() {
        // Needs `std` only because rendering to a `String` does. `PrettyIn` rather than
        // `Pretty`: these fragments carry a context tag, which is legal inside a structure
        // and not at the top level, so the top-level reader would call them malformed.
        let render = |id| {
            let bytes = encoded(id, &mut [0u8; 128]);
            std::format!("{}", PrettyIn(&bytes, ContainerKind::Structure))
        };
        assert_eq!(
            render(ATTRIBUTE_LIST),
            "2 = [0U, 1U, 16U, 65528U, 65529U, 65531U, 65532U, 65533U]"
        );
        assert_eq!(render(ACCEPTED_COMMAND_LIST), "2 = [0U, 1U]");
        assert_eq!(render(GENERATED_COMMAND_LIST), "2 = [5U, 64U]");
    }

    #[test]
    fn a_non_global_id_is_not_encoded() {
        let mut buf = [0u8; 64];
        assert!(
            encode_value(&cluster(), 0x0000, Tag::Context(2), &mut buf)
                .expect("encode")
                .is_none()
        );
    }

    #[test]
    fn every_global_is_read_only_at_view_and_fixed() {
        // Table 95 gives all five `F` and `RV`. A writable one would let a client rewrite
        // the server's own self-description.
        for id in ATTRIBUTE_IDS {
            let descriptor = descriptor(*id).expect("a descriptor");
            assert_eq!(descriptor.access.read, Some(Privilege::View), "{id:#06x}");
            assert!(!descriptor.access.is_writable(), "{id:#06x}");
            assert!(
                descriptor.qualities.contains(AttributeQualities::FIXED),
                "{id:#06x}"
            );
        }
    }

    #[test]
    fn a_cluster_may_not_declare_a_global_itself() {
        // It would produce a duplicate in AttributeList and shadow the synthesised value.
        const BAD: &[AttributeDescriptor] = &[AttributeDescriptor::read_only(CLUSTER_REVISION)];
        let bad = ClusterDescriptor {
            attributes: BAD,
            ..cluster()
        };
        assert!(!bad.is_well_formed());
        assert!(cluster().is_well_formed());
    }
}
