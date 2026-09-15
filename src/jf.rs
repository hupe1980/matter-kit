//! Joint Fabric: two ecosystems, one root of trust (Core ch. 12).
//!
//! Needs the `rustcrypto` feature: the certificates are [`cert`](crate::cert)'s.
//!
//! Ordinarily two ecosystems on the same device are two *fabrics*: two roots, two sets of
//! operational certificates, two access-control lists, and a device that has to hold both.
//! §12.2 is the alternative. Both ecosystems' intermediate CAs are cross-signed by one **Anchor
//! CA**, so every node they commission chains to the same root — and an administrator of either
//! ecosystem can administer any of it.
//!
//! > The joint operation ensures that ICA's from both Fabric A and Fabric B are signed by the
//! > Anchor CA … establishing a common trust between all devices of the original Fabric A and
//! > Fabric B and all newly added devices to the "Joint Fabric".
//!
//! # The two tags are the whole access model
//!
//! A Joint Fabric does not name administrators by Node ID — there may be many of them, from
//! several companies, and the set changes. It names them by
//! [`CaseAuthenticatedTag`], and §12.2.4 reserves two
//! identifiers for it:
//!
//! * the **Administrator CAT** (`0xFFFF`), which "all devices participating in Joint Fabric
//!   SHALL contain an ACL entry granting Administer privilege to";
//! * the **Anchor CAT** (`0xFFFE`), which does the same one level up — it is what restricts
//!   Administer *on an administrator* to the anchor.
//!
//! # Revocation is a version bump, and it is meant to hurt
//!
//! §12.2.4.1 is unusually candid about the cost:
//!
//! > The Joint Fabric Anchor Administrator SHALL increment the version number of the
//! > Administrator CAT … update the existing credentials (NOC) for all Administrator Nodes that
//! > are NOT being revoked … and update the ACL entry of all Nodes whose subject list contains
//! > the prior version … Completing this operation requires visiting all the nodes in the Joint
//! > Fabric, a task which might take a long time to complete or might never complete if some
//! > Nodes are permanently offline.
//!
//! [`Revocation`] is that walk, as a value: which nodes still hold the old version, and whether
//! the anchor is done. A device is *not* safe until its ACL has moved, so an implementation that
//! reported success on the first successful write would be reporting the opposite of the truth.

use crate::cert::dn::DnAttributeKind;
use crate::error::{Error, ErrorCode, Result, bail};
use crate::msg::{CaseAuthenticatedTag, NodeId};

/// §12.2.3: the Anchor ICAC "SHALL contain the reserved org-unit-name attribute … with value
/// `jf-anchor-icac` in its Subject DN".
///
/// It is the marker that says an intermediate CA is *the* anchor's rather than merely one the
/// anchor signed, and §12.2.5 has a commissioner check for it before trusting a peer to act as
/// the Joint Fabric's anchor.
pub const ANCHOR_ICAC_OU: &str = "jf-anchor-icac";

/// §12.2.2's ceiling on a newly allocated Node ID: "less than 0xFFFF_FFEF_FFFF_FFFF".
pub const NODE_ID_MAX: u64 = 0xFFFF_FFEE_FFFF_FFFF;

/// The pair of tags a Joint Fabric is administered through (§12.2.4).
///
/// Both carry a version, and the version is what makes them revocable: §12.2.4.1's walk. They
/// are constructed rather than defaulted because the version is fabric state — a fabric that has
/// revoked twice is on version 3, and a node still holding version 1 is one that was missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JointFabricTags {
    /// §12.2.4.1's Administrator CAT: every node on the fabric grants Administer to it.
    pub administrator: CaseAuthenticatedTag,
    /// §12.2.4.2's Anchor CAT: every *administrator* grants Administer to it.
    pub anchor: CaseAuthenticatedTag,
}

impl JointFabricTags {
    /// The two tags at `version`.
    ///
    /// §6.6.2.1.2: "A version number of 0 is invalid", so version 0 is refused rather than
    /// silently producing a tag no access-control entry would ever match.
    pub const fn new(version: u16) -> Result<Self> {
        if version == 0 {
            bail!(InvalidArgument)
        }
        Ok(Self {
            administrator: CaseAuthenticatedTag::new(
                CaseAuthenticatedTag::ADMINISTRATOR_IDENTIFIER,
                version,
            ),
            anchor: CaseAuthenticatedTag::new(CaseAuthenticatedTag::ANCHOR_IDENTIFIER, version),
        })
    }

    /// Whether `tag` is this fabric's Administrator CAT, at this exact version.
    ///
    /// The version matters: §12.2.4.1's revocation works by leaving a stale version behind, so a
    /// check that compared only the identifier would keep honouring the administrator the anchor
    /// had just revoked.
    #[must_use]
    pub fn grants_administrator(&self, tag: CaseAuthenticatedTag) -> bool {
        tag == self.administrator
    }

    /// Whether `tag` is this fabric's Anchor CAT, at this exact version.
    #[must_use]
    pub fn grants_anchor(&self, tag: CaseAuthenticatedTag) -> bool {
        tag == self.anchor
    }

    /// The tags after §12.2.4.1's revocation step.
    ///
    /// "increment the version number of the Administrator CAT to a value higher than its current
    /// value (e.g., from 0x0000 to 0x0001)". A fabric that has exhausted the 16-bit version has
    /// no way left to revoke, which is a state to report rather than to wrap through: wrapping
    /// would re-authorise whoever held version 1.
    pub const fn revoked(&self) -> Result<Self> {
        let Some(next) = self.administrator.version().checked_add(1) else {
            bail!(NoSpace)
        };
        Self::new(next)
    }
}

/// Whether a Node ID may be allocated on a Joint Fabric (§12.2.2).
///
/// > be greater than 0x0000_0000_0000_0000, but less than 0xFFFF_FFEF_FFFF_FFFF, representing a
/// > value within the Operational NodeID range … be checked to ensure its uniqueness in the
/// > NodeList attribute.
///
/// Uniqueness is the caller's — it needs the datastore — but the range is not, and a
/// commissioner that allocated outside it would issue a NOC no node could use as an
/// operational identity.
#[must_use]
pub fn is_allocatable(node: NodeId) -> bool {
    node.0 > 0 && node.0 < NODE_ID_MAX.saturating_add(1)
}

/// §12.2.4.1's revocation walk: the part that cannot be done in one command.
///
/// Constructed with every node whose ACL or NOC still names the old version, and ticked off as
/// each is updated. [`is_complete`](Self::is_complete) is the only thing that may be reported as
/// success — and §12.2.4.1 says outright that it may never arrive, because "some Nodes are
/// permanently offline or otherwise unreachable".
#[derive(Debug)]
pub struct Revocation<const N: usize> {
    tags: JointFabricTags,
    outstanding: heapless::Vec<NodeId, N>,
}

impl<const N: usize> Revocation<N> {
    /// Begins a revocation: the new tags, and every node that has to be visited.
    ///
    /// `nodes` is the whole fabric, administrators included — §12.2.4.1 updates NOCs *and* ACL
    /// entries, and a node whose ACL still lists the old Administrator CAT is a node the revoked
    /// administrator can still administer.
    pub fn begin(
        previous: &JointFabricTags,
        nodes: impl IntoIterator<Item = NodeId>,
    ) -> Result<Self> {
        let tags = previous.revoked()?;
        let mut outstanding = heapless::Vec::new();
        for node in nodes {
            outstanding
                .push(node)
                .map_err(|_| Error::new(ErrorCode::NoSpace))?;
        }
        Ok(Self { tags, outstanding })
    }

    /// The tags every node is being moved to.
    #[must_use]
    pub const fn tags(&self) -> &JointFabricTags {
        &self.tags
    }

    /// Records that one node now holds the new version.
    ///
    /// Returns whether it was one that still owed the update — a second report for the same node
    /// is not progress, and counting it would let a retry loop declare the fabric safe.
    pub fn updated(&mut self, node: NodeId) -> bool {
        let before = self.outstanding.len();
        self.outstanding.retain(|n| *n != node);
        self.outstanding.len() != before
    }

    /// The nodes that have not been reached yet.
    #[must_use]
    pub fn outstanding(&self) -> &[NodeId] {
        &self.outstanding
    }

    /// Whether every node has moved, and the revocation has actually taken effect.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.outstanding.is_empty()
    }
}

/// Whether a certificate's Subject DN marks it as the Anchor ICAC (§12.2.3).
///
/// `subject` is the decoded DN, as [`cert`](crate::cert) produces it. The check is on the
/// *Subject*, not the issuer: an ICAC the anchor signed is not the anchor's own.
pub fn is_anchor_icac<'a>(subject: impl IntoIterator<Item = (DnAttributeKind, &'a [u8])>) -> bool {
    subject.into_iter().any(|(kind, value)| {
        kind == DnAttributeKind::OrgUnitName && value == ANCHOR_ICAC_OU.as_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_tags_use_the_reserved_identifiers() {
        // §12.2.4: 0xFFFF and 0xFFFE are reserved to the Joint Fabric precisely so that an
        // ecosystem cannot have allocated them for something else.
        let tags = JointFabricTags::new(1).expect("version 1");
        assert_eq!(tags.administrator.identifier(), 0xFFFF);
        assert_eq!(tags.anchor.identifier(), 0xFFFE);
        assert_eq!(tags.administrator.version(), 1);
        assert!(tags.administrator.is_valid());
    }

    #[test]
    fn version_zero_is_not_a_tag() {
        // §6.6.2.1.2: "A version number of 0 is invalid." A tag at version 0 would match no
        // access-control entry, so a fabric built on one would be an administrator nobody obeys.
        assert!(JointFabricTags::new(0).is_err());
    }

    #[test]
    fn revocation_leaves_the_old_version_behind() {
        // §12.2.4.1: revoking is incrementing, and the *old* version is what stops working —
        // which is why a check on the identifier alone would revoke nobody.
        let before = JointFabricTags::new(1).expect("v1");
        let after = before.revoked().expect("v2");
        assert_eq!(after.administrator.version(), 2);
        assert!(!after.grants_administrator(before.administrator));
        assert!(after.grants_administrator(after.administrator));
        assert!(!after.grants_anchor(before.anchor));
    }

    #[test]
    fn a_fabric_that_has_run_out_of_versions_says_so() {
        // Wrapping would re-authorise whoever still held version 1, which is the opposite of
        // what the operation is for.
        let last = JointFabricTags::new(u16::MAX).expect("v65535");
        assert!(last.revoked().is_err());
    }

    #[test]
    fn the_node_id_range_excludes_both_ends() {
        // §12.2.2, and Table 4's operational range: 0 is unspecified and the top of the space is
        // reserved for group, CAT and PAKE identifiers.
        assert!(!is_allocatable(NodeId(0)));
        assert!(is_allocatable(NodeId(1)));
        assert!(is_allocatable(NodeId(NODE_ID_MAX)));
        assert!(!is_allocatable(NodeId(0xFFFF_FFEF_FFFF_FFFF)));
        assert!(!is_allocatable(NodeId(u64::MAX)));
    }

    #[test]
    fn the_anchor_marker_is_on_the_subject() {
        assert!(is_anchor_icac([(
            DnAttributeKind::OrgUnitName,
            ANCHOR_ICAC_OU.as_bytes()
        )]));
        // An ICAC with some other organisational unit is one the anchor signed, not the
        // anchor's own — and §12.2.5 has a commissioner refuse to treat it as the anchor.
        assert!(!is_anchor_icac([(
            DnAttributeKind::OrgUnitName,
            b"Acme Lighting".as_slice()
        )]));
        // And the value on the wrong attribute proves nothing.
        assert!(!is_anchor_icac([(
            DnAttributeKind::CommonName,
            ANCHOR_ICAC_OU.as_bytes()
        )]));
    }

    #[test]
    fn a_revocation_is_only_complete_when_every_node_has_moved() {
        // §12.2.4.1: the walk "might take a long time to complete or might never complete".
        // Reporting success on the first write would report the opposite of the truth.
        let before = JointFabricTags::new(1).expect("v1");
        let nodes = [NodeId(1), NodeId(2), NodeId(3)];
        let mut walk = Revocation::<8>::begin(&before, nodes).expect("begin");
        assert_eq!(walk.tags().administrator.version(), 2);
        assert!(!walk.is_complete());

        assert!(walk.updated(NodeId(2)));
        // A second report for the same node is not progress.
        assert!(!walk.updated(NodeId(2)));
        assert_eq!(walk.outstanding(), &[NodeId(1), NodeId(3)]);
        assert!(!walk.is_complete());

        assert!(walk.updated(NodeId(1)));
        assert!(walk.updated(NodeId(3)));
        assert!(walk.is_complete());
    }
}
