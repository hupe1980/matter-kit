//! The identifiers that appear in a message header (Core §2.5).
//!
//! Each is a newtype over the integer the wire carries, because a `u64` that is sometimes
//! a Node ID, sometimes a Fabric ID and sometimes a compressed Fabric ID is a `u64` that
//! will eventually be the wrong one.

/// A 64-bit Node ID (Core §2.5.5).
///
/// The value space is carved into ranges with different meanings, which [`NodeId::kind`]
/// reports. Not every 64-bit value is a legal operational Node ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NodeId(pub u64);

/// What range of the Node ID space a value falls in (Core §2.5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeIdKind {
    /// `0x0000_0000_0000_0000` — "a reserved value that never appears in messages or
    /// protocol usage. It exists to mark or detect the presence of uninitialized,
    /// missing, or invalid Node IDs" (§2.5.5.6).
    Unspecified,
    /// `0x0000_0000_0000_0001` … `0xFFFF_FFEF_FFFF_FFFF` — a node on a fabric (§2.5.5.1).
    Operational,
    /// `0xFFFF_FFFB_xxxx_xxxx` — identifies the PAKE passcode a PASE session used
    /// (§2.5.5.4).
    PakeKeyIdentifier,
    /// `0xFFFF_FFFD_xxxx_xxxx` — a CASE Authenticated Tag, an access-control subject
    /// shared by a group of peers (§2.5.5.5).
    CaseAuthenticatedTag,
    /// `0xFFFF_FFFE_xxxx_xxxx` — a temporary local Node ID (§2.5.5.3).
    TemporaryLocal,
    /// `0xFFFF_FFFF_FFFF_xxxx` — a group, addressed by the low 16 bits (§2.5.5.2).
    Group,
    /// Inside the reserved span but matching no defined range.
    Reserved,
}

impl NodeId {
    /// The Unspecified Node ID (§2.5.5.6).
    pub const UNSPECIFIED: Self = Self(0);

    /// The first operational Node ID.
    pub const OPERATIONAL_MIN: u64 = 0x0000_0000_0000_0001;
    /// The last operational Node ID.
    pub const OPERATIONAL_MAX: u64 = 0xFFFF_FFEF_FFFF_FFFF;

    /// Which range this value falls in.
    #[must_use]
    pub const fn kind(self) -> NodeIdKind {
        match self.0 {
            0 => NodeIdKind::Unspecified,
            Self::OPERATIONAL_MIN..=Self::OPERATIONAL_MAX => NodeIdKind::Operational,
            0xFFFF_FFFB_0000_0000..=0xFFFF_FFFB_FFFF_FFFF => NodeIdKind::PakeKeyIdentifier,
            0xFFFF_FFFD_0000_0000..=0xFFFF_FFFD_FFFF_FFFF => NodeIdKind::CaseAuthenticatedTag,
            0xFFFF_FFFE_0000_0000..=0xFFFF_FFFE_FFFF_FFFF => NodeIdKind::TemporaryLocal,
            0xFFFF_FFFF_FFFF_0000..=0xFFFF_FFFF_FFFF_FFFF => NodeIdKind::Group,
            _ => NodeIdKind::Reserved,
        }
    }

    /// Whether this is a usable operational Node ID.
    #[must_use]
    pub const fn is_operational(self) -> bool {
        matches!(self.kind(), NodeIdKind::Operational)
    }

    /// The group this Node ID names, if it is a Group Node ID.
    #[must_use]
    pub const fn group(self) -> Option<GroupId> {
        match self.kind() {
            NodeIdKind::Group => Some(GroupId(self.0 as u16)),
            _ => None,
        }
    }

    /// The Group Node ID for a group (§2.5.5.2).
    #[must_use]
    pub const fn from_group(group: GroupId) -> Self {
        Self(0xFFFF_FFFF_FFFF_0000 | group.0 as u64)
    }
}

/// A CASE Authenticated Tag: an access-control subject shared by a group of nodes
/// (Core §6.6.2.1.2).
///
/// A CAT is carried in a node's operational certificate, so "the administrative root of
/// trust does chain back through the individual source Node to the Fabric's trusted root".
/// That is what makes it unlike a group key: group-*like* addressing, with per-node
/// attribution intact.
///
/// The 32 bits are two halves. The upper 16 name the tag; the lower 16 are a version an
/// administrator bumps whenever the set of nodes holding the tag changes, so that an
/// access-control entry written against version 3 does not silently admit a node that was
/// granted version 2 and has since been removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CaseAuthenticatedTag(pub u32);

impl CaseAuthenticatedTag {
    /// `0xFFFF` — the Administrator identifier, reserved to the Joint Fabric (§12.2.4.1).
    pub const ADMINISTRATOR_IDENTIFIER: u16 = 0xFFFF;
    /// `0xFFFE` — the Anchor identifier, reserved to the Joint Fabric (§12.2.4.2).
    pub const ANCHOR_IDENTIFIER: u16 = 0xFFFE;
    /// The last identifier "generally available"; `0xF000..=0xFFFD` is reserved.
    pub const GENERAL_IDENTIFIER_MAX: u16 = 0xEFFF;

    /// Builds a tag from its two halves.
    #[must_use]
    pub const fn new(identifier: u16, version: u16) -> Self {
        Self(((identifier as u32) << 16) | version as u32)
    }

    /// The upper 16 bits, which "uniquely identifies a CAT".
    #[must_use]
    pub const fn identifier(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// The lower 16 bits.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.0 as u16
    }

    /// Whether the version is usable: "Version number is a monotonically increasing
    /// natural number in the range of 1 to 65535. A version number of 0 is invalid."
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.version() != 0
    }

    /// The Node ID sub-encoding a CAT takes in an access-control entry's `Subjects` list:
    /// the tag with `0xFFFF_FFFD` above it (§6.6.2.1.2).
    ///
    /// "Note that this encoding cannot appear as an operational Node ID."
    #[must_use]
    pub const fn to_node_id(self) -> NodeId {
        NodeId(0xFFFF_FFFD_0000_0000 | self.0 as u64)
    }

    /// Recovers a CAT from that sub-encoding, or `None` if the Node ID is not one.
    #[must_use]
    pub const fn from_node_id(node_id: NodeId) -> Option<Self> {
        match node_id.kind() {
            NodeIdKind::CaseAuthenticatedTag => Some(Self(node_id.0 as u32)),
            _ => None,
        }
    }
}

/// A 16-bit Group ID (Core §2.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GroupId(pub u16);

impl GroupId {
    /// Group ID 0 is reserved as the "null" group and never addresses anything.
    pub const UNSPECIFIED: Self = Self(0);

    /// Whether this group can be addressed — everything but zero.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

/// A 64-bit Fabric ID (Core §2.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FabricId(pub u64);

/// A local index into a node's own fabric table (Core §7.5).
///
/// One octet, `1..=254`; zero means "no fabric", and the value is local to one node — the
/// same fabric has different indices on different nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FabricIndex(pub u8);

impl FabricIndex {
    /// The absent index.
    pub const NONE: Self = Self(0);

    /// Whether this names a fabric.
    #[must_use]
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }
}

/// A 16-bit session identifier (Core §4.4.1.2).
///
/// Identifies "the particular key used to encrypt a message out of the set of available
/// keys". Zero with a unicast session type means the unsecured session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SessionId(pub u16);

impl SessionId {
    /// The unsecured session: session type unicast and session id zero (§4.4.1.3).
    pub const UNSECURED: Self = Self(0);
}

/// A 16-bit exchange identifier (Core §4.4.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ExchangeId(pub u16);

/// A 16-bit Vendor ID (Core §2.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VendorId(pub u16);

impl VendorId {
    /// The Common Vendor ID, under which Matter's own protocols are defined.
    pub const COMMON: Self = Self(0x0000);
    /// `0xFFF1` — the first of the Vendor IDs "allocated for testing purposes".
    pub const TEST_1: Self = Self(0xFFF1);
}

/// A protocol identifier, which is a Vendor ID and a 16-bit protocol number
/// (Core §4.4.3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolId {
    /// Whose protocol this is; [`VendorId::COMMON`] for Matter's own.
    pub vendor: VendorId,
    /// The protocol number within that vendor's space.
    pub id: u16,
}

impl ProtocolId {
    /// Builds a protocol id under the Common Vendor ID.
    #[must_use]
    pub const fn common(id: u16) -> Self {
        Self {
            vendor: VendorId::COMMON,
            id,
        }
    }

    /// `0x0000` — Secure Channel: PASE, CASE, MRP standalone acknowledgements, status
    /// reports and the check-in message (Core §4.11).
    pub const SECURE_CHANNEL: Self = Self::common(0x0000);
    /// `0x0001` — the Interaction Model (Core ch. 8).
    pub const INTERACTION_MODEL: Self = Self::common(0x0001);
    /// `0x0002` — the Bulk Data Exchange Protocol (Core §11.22).
    pub const BDX: Self = Self::common(0x0002);
    /// `0x0003` — User Directed Commissioning (Core §5.3).
    pub const USER_DIRECTED_COMMISSIONING: Self = Self::common(0x0003);
    /// `0x0004` — reserved for testing.
    pub const FOR_TESTING: Self = Self::common(0x0004);

    /// Whether this protocol belongs to the Common Vendor ID, and so needs no Protocol
    /// Vendor ID field on the wire.
    #[must_use]
    pub const fn is_common(self) -> bool {
        self.vendor.0 == VendorId::COMMON.0
    }
}

impl Default for ProtocolId {
    fn default() -> Self {
        Self::SECURE_CHANNEL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_ranges_follow_2_5_5() {
        assert_eq!(NodeId(0).kind(), NodeIdKind::Unspecified);
        assert_eq!(NodeId(1).kind(), NodeIdKind::Operational);
        assert_eq!(
            NodeId(0xFFFF_FFEF_FFFF_FFFF).kind(),
            NodeIdKind::Operational
        );
        assert_eq!(
            NodeId(0xFFFF_FFF0_0000_0000).kind(),
            NodeIdKind::Reserved,
            "one past the operational range"
        );
        assert_eq!(
            NodeId(0xFFFF_FFFB_0000_0001).kind(),
            NodeIdKind::PakeKeyIdentifier
        );
        assert_eq!(
            NodeId(0xFFFF_FFFD_0000_0001).kind(),
            NodeIdKind::CaseAuthenticatedTag
        );
        assert_eq!(
            NodeId(0xFFFF_FFFE_0000_0001).kind(),
            NodeIdKind::TemporaryLocal
        );
        assert_eq!(NodeId(0xFFFF_FFFF_FFFF_0001).kind(), NodeIdKind::Group);
    }

    #[test]
    fn group_node_ids_round_trip() {
        let g = GroupId(0x1234);
        let n = NodeId::from_group(g);
        assert_eq!(n.0, 0xFFFF_FFFF_FFFF_1234);
        assert_eq!(n.group(), Some(g));
        assert_eq!(NodeId(1).group(), None);
    }

    #[test]
    fn the_unspecified_node_id_is_not_operational() {
        assert!(!NodeId::UNSPECIFIED.is_operational());
        assert!(NodeId(1).is_operational());
    }

    #[test]
    fn group_zero_is_not_addressable() {
        assert!(!GroupId::UNSPECIFIED.is_valid());
        assert!(GroupId(1).is_valid());
    }

    #[test]
    fn common_protocols_need_no_vendor_field() {
        assert!(ProtocolId::SECURE_CHANNEL.is_common());
        assert!(ProtocolId::INTERACTION_MODEL.is_common());
        assert!(
            !ProtocolId {
                vendor: VendorId::TEST_1,
                id: 1
            }
            .is_common()
        );
    }
}
