//! Manufacturer Extensible Identifiers — Core §7.21.2.
//!
//! Every identifier in the data model that a manufacturer can extend is a 32-bit MEI: a 16-bit
//! **prefix** naming the source and a 16-bit **suffix** naming the item within it. Table 100
//! bounds the prefix, Table 101 the suffix, and Table 102 narrows both for each kind of
//! identifier — a standard cluster is `0x0000_0000`–`0x0000_7FFF` and a manufacturer-specific
//! one `<vendor>_FC00`–`<vendor>_FFFE`, with nothing legal in between.
//!
//! **Why this is a module and not four `if`s.** These ranges are checked wherever an identifier
//! arrives from a peer rather than from this crate's own tables — an ACL target naming a
//! cluster, a path naming an attribute — and the value that shows the checks were missing is
//! always the same one: `0xFFFF_FFFF`, whose prefix Table 100 does not define at all. An
//! identifier that fails these is not "unsupported"; it names nothing that could ever exist, so
//! §8.10.1's `CONSTRAINT_ERROR` is the answer and not `UNSUPPORTED_CLUSTER`, which would say the
//! node merely happens not to have it.
//!
//! An 8-bit suffix range in Table 102 is widened the way the specification says: "the 16-bit MEI
//! Suffix SHALL be constructed by padding the 8-bit data with a most significant byte set to
//! zero."

use crate::im::{AttributeId, ClusterId, CommandId, EventId};

/// The source half of an MEI — Table 99's bits 31..16.
#[must_use]
pub const fn prefix(mei: u32) -> u16 {
    // The shift leaves exactly sixteen bits, so the conversion is total.
    (mei >> 16) as u16
}

/// The item half of an MEI — Table 99's bits 15..0.
#[must_use]
pub const fn suffix(mei: u32) -> u16 {
    // The mask leaves exactly sixteen bits, so the conversion is total.
    (mei & 0xFFFF) as u16
}

/// Whether the prefix names a source Table 100 defines.
///
/// `0x0000` is "Standard OR Scoped", `0x0001`–`0xFFF0` a Manufacturer Code and `0xFFF1`–`0xFFF4`
/// the test vendors. `0xFFF5`–`0xFFFF` is none of those — Table 103 lists `0xFFFF_0000` as
/// **Invalid** in as many words.
#[must_use]
pub const fn prefix_is_defined(mei: u32) -> bool {
    prefix(mei) <= 0xFFF4
}

/// Whether the prefix is the standard one, rather than a manufacturer's.
#[must_use]
pub const fn is_standard(mei: u32) -> bool {
    prefix(mei) == 0x0000
}

/// Table 102's `Cluster ID`: standard `0x0000`–`0x7FFF`, manufacturer-specific
/// `0xFC00`–`0xFFFE`.
///
/// The gap between them is deliberate and is where a wrong identifier lands: `0x0000_8000` is
/// neither a standard cluster nor a manufacturer's, and neither is anything under a prefix
/// Table 100 leaves undefined.
#[must_use]
pub const fn cluster_is_valid(cluster: ClusterId) -> bool {
    if !prefix_is_defined(cluster) {
        return false;
    }
    if is_standard(cluster) {
        suffix(cluster) <= 0x7FFF
    } else {
        matches!(suffix(cluster), 0xFC00..=0xFFFE)
    }
}

/// Table 102's `Device Type ID`: suffix `0x0000`–`0xBFFF`, standard or manufacturer alike.
#[must_use]
pub const fn device_type_is_valid(device_type: u32) -> bool {
    prefix_is_defined(device_type) && suffix(device_type) <= 0xBFFF
}

/// Table 102's `Attribute ID`: global `0xF000`–`0xFFFE` under the standard prefix, non-global
/// `0x0000`–`0x4FFF` under a scoped or manufacturer one.
///
/// The scoped source shares the standard prefix — §7.21.2.1: "a Scoped source is encoded using
/// the same prefix as a Standard source" — so a standard-prefixed attribute is legal in either
/// range, and only the span between them is not.
#[must_use]
pub const fn attribute_is_valid(attribute: AttributeId) -> bool {
    if !prefix_is_defined(attribute) {
        return false;
    }
    if is_standard(attribute) {
        matches!(suffix(attribute), 0x0000..=0x4FFF | 0xF000..=0xFFFE)
    } else {
        suffix(attribute) <= 0x4FFF
    }
}

/// Table 102's `Command ID`: global `0xE0`–`0xFF` and non-global `0x00`–`0xDF` under the
/// standard prefix, and the whole `0x00`–`0xFF` under a manufacturer's.
///
/// Either way the suffix is one octet, "padded with a most significant byte set to zero", so a
/// command whose suffix exceeds `0x00FF` names nothing.
#[must_use]
pub const fn command_is_valid(command: CommandId) -> bool {
    prefix_is_defined(command) && suffix(command) <= 0x00FF
}

/// Table 102's `Event ID`: suffix `0x00`–`0xFF`, scoped or manufacturer.
#[must_use]
pub const fn event_is_valid(event: EventId) -> bool {
    prefix_is_defined(event) && suffix(event) <= 0x00FF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_103s_examples_decode_as_it_says() {
        assert_eq!((prefix(0x0000_0000), suffix(0x0000_0000)), (0x0000, 0x0000));
        assert_eq!((prefix(0x0000_FFFE), suffix(0x0000_FFFE)), (0x0000, 0xFFFE));
        assert_eq!((prefix(0x0001_0002), suffix(0x0001_0002)), (0x0001, 0x0002));
        assert_eq!((prefix(0x0002_FFFE), suffix(0x0002_FFFE)), (0x0002, 0xFFFE));
        // "0xFFFF_0000 — Invalid", which is the whole reason this module exists.
        assert!(!prefix_is_defined(0xFFFF_0000));
    }

    #[test]
    fn the_prefix_boundary_is_where_table_100_puts_it() {
        assert!(prefix_is_defined(0x0000_0000), "Standard OR Scoped");
        assert!(prefix_is_defined(0xFFF0_0000), "the last Manufacturer Code");
        assert!(prefix_is_defined(0xFFF4_0000), "the last Test Vendor MC");
        assert!(!prefix_is_defined(0xFFF5_0000), "past every defined source");
        assert!(!prefix_is_defined(0xFFFF_FFFF));
    }

    #[test]
    fn a_cluster_id_is_standard_low_or_manufacturer_high_and_nothing_between() {
        assert!(cluster_is_valid(0x0000_0000));
        assert!(cluster_is_valid(0x0000_7FFF), "the last standard cluster");
        assert!(!cluster_is_valid(0x0000_8000), "one past it");
        assert!(
            !cluster_is_valid(0x0000_FC00),
            "the MC range, standard prefix"
        );

        assert!(!cluster_is_valid(0xFFF1_0000), "below the MC cluster range");
        assert!(cluster_is_valid(0xFFF1_FC00), "the first MC cluster");
        assert!(cluster_is_valid(0xFFF1_FFFE), "the last one");
        assert!(!cluster_is_valid(0xFFF1_FFFF), "Table 101 stops at 0xFFFE");

        // What the Test Harness writes into an ACL target to see whether anyone is checking.
        assert!(!cluster_is_valid(0xFFFF_FFFF));
    }

    #[test]
    fn a_device_type_id_stops_at_bfff() {
        assert!(device_type_is_valid(0x0000_0000));
        assert!(device_type_is_valid(0x0000_0100), "On/Off Light");
        assert!(device_type_is_valid(0x0000_BFFF));
        assert!(!device_type_is_valid(0x0000_C000));
        assert!(device_type_is_valid(0xFFF1_0001), "a test vendor's own");
        assert!(!device_type_is_valid(0xFFFF_FFFF));
    }

    #[test]
    fn an_attribute_id_has_two_ranges_under_the_standard_prefix() {
        assert!(attribute_is_valid(0x0000_0000));
        assert!(attribute_is_valid(0x0000_4FFF), "the last non-global");
        assert!(!attribute_is_valid(0x0000_5000));
        assert!(!attribute_is_valid(0x0000_EFFF));
        assert!(attribute_is_valid(0x0000_F000), "the first global");
        assert!(attribute_is_valid(0x0000_FFFD), "AttributeList");
        assert!(!attribute_is_valid(0x0000_FFFF));
        // A manufacturer has no global attributes: Table 102 makes those Standard only.
        assert!(attribute_is_valid(0xFFF1_0001));
        assert!(!attribute_is_valid(0xFFF1_F000));
    }

    #[test]
    fn commands_and_events_carry_one_octet_of_suffix() {
        assert!(command_is_valid(0x0000_00FF));
        assert!(!command_is_valid(0x0000_0100));
        assert!(event_is_valid(0x0000_00FF));
        assert!(!event_is_valid(0x0000_0100));
        assert!(!command_is_valid(0xFFFF_FFFF));
        assert!(!event_is_valid(0xFFFF_FFFF));
    }
}
