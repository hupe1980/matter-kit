//! Access qualities: who may read, write and invoke what (Core §7.6, §6.6.1).
//!
//! Every attribute, command and event declares what kind of access it supports and the
//! **lowest** privilege that suffices. §7.6: "Elements SHALL only include the lowest required
//! privilege for a type of access", because a higher privilege implicitly grants every lower
//! one — §6.6.1: "When a Node is granted a particular privilege, it is also implicitly
//! granted all logically lower privilege levels as well."
//!
//! That ordering is why [`Privilege`] is `Ord` and why [`Privilege::grants`] exists: a check
//! is a comparison, not a set membership test.
//!
//! # The defaults are not "none"
//!
//! §7.6 gives every element an access quality whether or not the cluster wrote one down:
//!
//! > Attributes, commands, and events that do not define any privileges as access qualities
//! > SHALL be deemed to have the following: View privilege required for Read access, Operate
//! > privilege required for Write access, Operate privilege required for Invoke access for
//! > request commands.
//!
//! So [`Access::default`] is `R V` — readable at View — and [`Access::read_write`] is `RW VO`,
//! which is what "an attribute with access 'RW'" means. Getting this wrong in the permissive
//! direction would expose an attribute the cluster never meant to be writable.

/// An access-control privilege (§6.6.1, §7.6.6–7.6.9).
///
/// Ordered from least to most: a subject granted one is granted every lower one.
/// `ProxyView` sits below `View` and exists for proxies, which need to see a node's shape
/// without being able to read its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Privilege {
    /// Enough to observe a node through a proxy, and nothing more.
    ProxyView,
    /// "SHALL support Read (if readable) and Invoke (if invocable) access" (§7.6.6).
    View,
    /// Adds Write (§7.6.7).
    Operate,
    /// Adds configuration (§7.6.8).
    Manage,
    /// Everything, including the Access Control cluster itself (§7.6.9).
    Administer,
}

impl Privilege {
    /// Whether holding `self` grants `required`.
    ///
    /// §6.6.1's subsumption rule — with the one exception that makes it not quite a
    /// comparison. §9.10.5.2's chain runs View ← Operate ← Manage ← Administer, and
    /// `ProxyView` is **outside it**: §6.6.6.2's `add_granted_privilege` expands Operate,
    /// Manage and Administer downward to View and never mentions ProxyView, so nothing grants
    /// it but itself and it grants nothing else.
    ///
    /// Treating the five as totally ordered would hand every `View` holder a privilege the
    /// specification never gives them — quietly, and in the permissive direction. The `Ord`
    /// derive still orders them for convenience; this is the access decision, and
    /// [`Acl::granted`](crate::acl::Acl::granted) agrees with it.
    #[must_use]
    pub const fn grants(self, required: Self) -> bool {
        match (self, required) {
            (Self::ProxyView, Self::ProxyView) => true,
            (Self::ProxyView, _) | (_, Self::ProxyView) => false,
            _ => (self as u8) >= (required as u8),
        }
    }
}

bitflags::bitflags! {
    /// The fabric and timing qualities of §7.6's Access column.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct AccessQualities: u8 {
        /// `F` — fabric-scoped: the data belongs to one fabric (§7.5.3).
        const FABRIC_SCOPED = 1 << 0;
        /// `S` — fabric-sensitive: other fabrics' entries are hidden, not merely filtered
        /// (§7.6.5).
        const FABRIC_SENSITIVE = 1 << 1;
        /// `T` — "Write Access or Invoke Access with timed interaction only" (§8.7).
        const TIMED = 1 << 2;
        /// `L` — Large Message: §7.7.5 says such an element "SHALL require TCP for
        /// communication", and §8.8.2.3 step b.iv makes invoking one over UDP
        /// [`INVALID_TRANSPORT_TYPE`](crate::im::Status::InvalidTransportType).
        const LARGE = 1 << 3;
    }
}

/// What an element supports and what it costs (§7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Access {
    /// The privilege a read needs, or `None` if the element is not readable.
    pub read: Option<Privilege>,
    /// The privilege a write needs, or `None` if the element is not writable.
    pub write: Option<Privilege>,
    /// The privilege an invoke needs, for a command.
    pub invoke: Option<Privilege>,
    /// The fabric and timing qualities.
    pub qualities: AccessQualities,
}

impl Default for Access {
    /// `R V` — §7.6's default for an element that declares nothing.
    fn default() -> Self {
        Self::read_only(Privilege::View)
    }
}

impl Access {
    /// `R <privilege>` — readable and not writable.
    #[must_use]
    pub const fn read_only(privilege: Privilege) -> Self {
        Self {
            read: Some(privilege),
            write: None,
            invoke: None,
            qualities: AccessQualities::empty(),
        }
    }

    /// `RW VO` — §7.6's reading of "an attribute with access 'RW'".
    #[must_use]
    pub const fn read_write() -> Self {
        Self {
            read: Some(Privilege::View),
            write: Some(Privilege::Operate),
            invoke: None,
            qualities: AccessQualities::empty(),
        }
    }

    /// `RW` with explicit privileges.
    #[must_use]
    pub const fn read_write_with(read: Privilege, write: Privilege) -> Self {
        Self {
            read: Some(read),
            write: Some(write),
            invoke: None,
            qualities: AccessQualities::empty(),
        }
    }

    /// `W <privilege>` — writable and not readable.
    #[must_use]
    pub const fn write_only(privilege: Privilege) -> Self {
        Self {
            read: None,
            write: Some(privilege),
            invoke: None,
            qualities: AccessQualities::empty(),
        }
    }

    /// An invocable command. §7.6's default for a request command is Operate.
    #[must_use]
    pub const fn invoke(privilege: Privilege) -> Self {
        Self {
            read: None,
            write: None,
            invoke: Some(privilege),
            qualities: AccessQualities::empty(),
        }
    }

    /// The same access with extra qualities.
    #[must_use]
    pub const fn with_qualities(mut self, qualities: AccessQualities) -> Self {
        self.qualities = qualities;
        self
    }

    /// Whether the element can be read at all.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.read.is_some()
    }

    /// Whether the element can be written at all.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.write.is_some()
    }

    /// Whether a write or invoke requires a Timed interaction (§8.7).
    #[must_use]
    pub const fn needs_timed(&self) -> bool {
        self.qualities.contains(AccessQualities::TIMED)
    }

    /// Whether the element is fabric-scoped.
    #[must_use]
    pub const fn is_fabric_scoped(&self) -> bool {
        self.qualities.contains(AccessQualities::FABRIC_SCOPED)
    }

    /// Whether the element is fabric-sensitive.
    #[must_use]
    pub const fn is_fabric_sensitive(&self) -> bool {
        self.qualities.contains(AccessQualities::FABRIC_SENSITIVE)
    }

    /// Whether the element requires a transport that can carry Large Messages (§7.7.5).
    #[must_use]
    pub const fn needs_large_messages(&self) -> bool {
        self.qualities.contains(AccessQualities::LARGE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_higher_privilege_grants_every_lower_one() {
        // §6.6.1: "When a Node is granted a particular privilege, it is also implicitly
        // granted all logically lower privilege levels as well." §9.10.5.2 gives the chain,
        // which is the four privileges other than ProxyView.
        let chain = [
            Privilege::View,
            Privilege::Operate,
            Privilege::Manage,
            Privilege::Administer,
        ];
        for (i, held) in chain.iter().enumerate() {
            for (j, required) in chain.iter().enumerate() {
                assert_eq!(
                    held.grants(*required),
                    i >= j,
                    "{held:?} granting {required:?}"
                );
            }
        }
    }

    #[test]
    fn proxy_view_is_outside_the_chain_in_both_directions() {
        // §6.6.6.2's `add_granted_privilege` expands Operate, Manage and Administer down to
        // View and never mentions ProxyView. So Administer does not carry it — and it does
        // not carry View either, which is the half a "lowest privilege" reading gets wrong.
        for other in [
            Privilege::View,
            Privilege::Operate,
            Privilege::Manage,
            Privilege::Administer,
        ] {
            assert!(!other.grants(Privilege::ProxyView), "{other:?} → ProxyView");
            assert!(!Privilege::ProxyView.grants(other), "ProxyView → {other:?}");
        }
        assert!(Privilege::ProxyView.grants(Privilege::ProxyView));
    }

    #[test]
    fn administer_grants_a_view_level_read() {
        // The case a set-of-privileges design gets wrong by forgetting to expand.
        assert!(Privilege::Administer.grants(Privilege::View));
        assert!(!Privilege::View.grants(Privilege::Administer));
    }

    #[test]
    fn the_defaults_are_the_ones_7_6_states() {
        // "An event with implicit read access or explicit 'R' access defaults to access
        // 'R V'. An attribute with access 'RW' defaults to access 'RW VO'."
        assert_eq!(Access::default().read, Some(Privilege::View));
        assert_eq!(Access::default().write, None, "a default is not writable");

        let rw = Access::read_write();
        assert_eq!(rw.read, Some(Privilege::View));
        assert_eq!(rw.write, Some(Privilege::Operate));
    }

    #[test]
    fn a_write_only_attribute_is_not_readable() {
        // §8.4.3.2: a read of one is UNSUPPORTED_READ, which needs this to be expressible.
        let access = Access::write_only(Privilege::Manage);
        assert!(!access.is_readable());
        assert!(access.is_writable());
    }

    #[test]
    fn the_large_message_quality_is_its_own_thing() {
        // §7.7.5: an `L` element "SHALL require TCP for communication". It is independent of
        // privilege — an administrator still cannot invoke one over UDP.
        let access = Access::invoke(Privilege::Administer).with_qualities(AccessQualities::LARGE);
        assert!(access.needs_large_messages());
        assert!(!access.needs_timed());
        assert_eq!(access.invoke, Some(Privilege::Administer));
    }

    #[test]
    fn qualities_are_independent_of_privileges() {
        let access = Access::read_write()
            .with_qualities(AccessQualities::FABRIC_SCOPED | AccessQualities::TIMED);
        assert!(access.is_fabric_scoped());
        assert!(access.needs_timed());
        assert!(!access.is_fabric_sensitive());
        assert_eq!(access.read, Some(Privilege::View), "unchanged");
    }
}
