//! Interaction model status codes (Core §8.10).
//!
//! One byte, sent back for every path of every action that did not simply succeed. The
//! table is long and most of it is history: §8.10.1 marks a dozen values "reserved" with
//! notes like "Deprecated: use FAILURE" or "ZCL OTA Upgrade cluster specific", left over
//! from the Zigbee Cluster Library this interaction model grew out of.
//!
//! Those are kept as [`Status::Reserved`] rather than dropped. A peer that sends one is
//! doing something wrong, but a *proxy* that could not represent it would have to invent a
//! substitute, and a status code invented in the middle of a path is worse than one that is
//! merely obsolete.

/// A status code (§8.10.1).
///
/// `SUCCESS` and `FAILURE` are the two general outcomes; everything else says which check
/// failed, and a client is expected to distinguish them — §8.10 exists so that "attribute
/// does not exist" and "you may not read it" are different answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum Status {
    /// `0x00` — "Operation was successful."
    #[default]
    Success,
    /// `0x01` — "Operation was not successful."
    Failure,
    /// `0x7D` — "Subscription ID is not active."
    InvalidSubscription,
    /// `0x7E` — the sender lacks the privilege this action needs. Distinct from
    /// [`Status::UnsupportedAttribute`] on purpose: which one is returned tells a client
    /// whether the thing exists.
    UnsupportedAccess,
    /// `0x7F` — "The endpoint indicated is unsupported."
    UnsupportedEndpoint,
    /// `0x80` — "The action is malformed, has missing fields, or fields with invalid
    /// values. Action not carried out."
    InvalidAction,
    /// `0x81` — "The indicated command ID is not supported on the cluster instance. Command
    /// not carried out."
    UnsupportedCommand,
    /// `0x85` — "The cluster command is malformed, has missing fields, or fields with
    /// invalid values. Command not carried out."
    InvalidCommand,
    /// `0x86` — "The indicated attribute ID, field ID or list entry does not exist for an
    /// attribute path."
    UnsupportedAttribute,
    /// `0x87` — "Out of range error or set to a reserved value. Attribute keeps its old
    /// value."
    ConstraintError,
    /// `0x88` — "Attempt to write a read-only attribute."
    UnsupportedWrite,
    /// `0x89` — "An action or operation failed due to insufficient available resources."
    ResourceExhausted,
    /// `0x8B` — "The indicated data field or entry could not be found."
    NotFound,
    /// `0x8C` — "Reports cannot be issued for this attribute."
    UnreportableAttribute,
    /// `0x8D` — "The data type indicated is undefined or invalid."
    InvalidDataType,
    /// `0x8F` — "Attempt to read a write-only attribute."
    UnsupportedRead,
    /// `0x92` — "Cluster instance data version did not match request path". What a
    /// `DataVersionFilter` produces when the client's cached version is stale.
    DataVersionMismatch,
    /// `0x94` — "The transaction was aborted due to time being exceeded."
    Timeout,
    /// `0x9B` — "The node ID indicated is not supported."
    UnsupportedNode,
    /// `0x9C` — "The receiver is busy processing another action."
    Busy,
    /// `0x9D` — access is barred by an Access Restriction List (§6.6).
    AccessRestricted,
    /// `0xC3` — "The cluster indicated is not supported."
    UnsupportedCluster,
    /// `0xC5` — "Used by proxies to convey to clients the lack of an upstream
    /// subscription."
    NoUpstreamSubscription,
    /// `0xC6` — "A Untimed Write or Untimed Invoke interaction was received for an
    /// attribute or command requiring a Timed interaction."
    NeedsTimedInteraction,
    /// `0xC7` — "The indicated event ID is not supported."
    UnsupportedEvent,
    /// `0xC8` — "The receiver has insufficient resources to process all the paths in the
    /// request."
    PathsExhausted,
    /// `0xC9` — a `TimedRequest` flag that disagrees with whether a Timed interaction is
    /// actually in progress.
    TimedRequestMismatch,
    /// `0xCA` — "A request requiring a Fail-safe context was invoked without one."
    FailsafeRequired,
    /// `0xCB` — "The received request cannot be handled due to the current operational
    /// state of the device."
    InvalidInState,
    /// `0xCC` — "A CommandDataIB is missing a response."
    NoCommandResponse,
    /// `0xCD` — the node requires updated Terms and Conditions acceptance.
    TermsAndConditionsChanged,
    /// `0xCE` — the node requires user maintenance before it can serve this request.
    MaintenanceRequired,
    /// `0xCF` — "The value for the data type was not accepted due to runtime validation
    /// issues."
    ///
    /// Distinct from [`Status::ConstraintError`] on purpose: that one means the value was
    /// outside the *schema's* range, this one that it was inside the schema and wrong for
    /// the device's current state — a setpoint below the heating limit, say.
    DynamicConstraintError,
    /// `0xD0` — "Attempt to create an entity that already exists or create an entity with an
    /// identifier that is already in use."
    AlreadyExists,
    /// `0xD1` — "Attempt to process on a transport type not valid for this element."
    ///
    /// §8.8.2.3 step b.iv: what a command with the Large Message quality (§7.7.5) answers
    /// when it arrives over UDP rather than TCP.
    InvalidTransportType,
    /// A value §8.10.1 marks reserved, or one this revision does not know.
    ///
    /// Kept rather than folded into [`Status::Failure`]: a proxy that had to substitute a
    /// code it could represent would be inventing an answer, and a status invented in the
    /// middle of a path is worse than one that is merely obsolete.
    Reserved(u8),
}

impl Status {
    /// The code a peer sends.
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::Success => 0x00,
            Self::Failure => 0x01,
            Self::InvalidSubscription => 0x7D,
            Self::UnsupportedAccess => 0x7E,
            Self::UnsupportedEndpoint => 0x7F,
            Self::InvalidAction => 0x80,
            Self::UnsupportedCommand => 0x81,
            Self::InvalidCommand => 0x85,
            Self::UnsupportedAttribute => 0x86,
            Self::ConstraintError => 0x87,
            Self::UnsupportedWrite => 0x88,
            Self::ResourceExhausted => 0x89,
            Self::NotFound => 0x8B,
            Self::UnreportableAttribute => 0x8C,
            Self::InvalidDataType => 0x8D,
            Self::UnsupportedRead => 0x8F,
            Self::DataVersionMismatch => 0x92,
            Self::Timeout => 0x94,
            Self::UnsupportedNode => 0x9B,
            Self::Busy => 0x9C,
            Self::AccessRestricted => 0x9D,
            Self::UnsupportedCluster => 0xC3,
            Self::NoUpstreamSubscription => 0xC5,
            Self::NeedsTimedInteraction => 0xC6,
            Self::UnsupportedEvent => 0xC7,
            Self::PathsExhausted => 0xC8,
            Self::TimedRequestMismatch => 0xC9,
            Self::FailsafeRequired => 0xCA,
            Self::InvalidInState => 0xCB,
            Self::NoCommandResponse => 0xCC,
            Self::TermsAndConditionsChanged => 0xCD,
            Self::MaintenanceRequired => 0xCE,
            Self::DynamicConstraintError => 0xCF,
            Self::AlreadyExists => 0xD0,
            Self::InvalidTransportType => 0xD1,
            Self::Reserved(v) => v,
        }
    }

    /// The status a code names.
    #[must_use]
    pub const fn from_value(value: u8) -> Self {
        match value {
            0x00 => Self::Success,
            0x01 => Self::Failure,
            0x7D => Self::InvalidSubscription,
            0x7E => Self::UnsupportedAccess,
            0x7F => Self::UnsupportedEndpoint,
            0x80 => Self::InvalidAction,
            0x81 => Self::UnsupportedCommand,
            0x85 => Self::InvalidCommand,
            0x86 => Self::UnsupportedAttribute,
            0x87 => Self::ConstraintError,
            0x88 => Self::UnsupportedWrite,
            0x89 => Self::ResourceExhausted,
            0x8B => Self::NotFound,
            0x8C => Self::UnreportableAttribute,
            0x8D => Self::InvalidDataType,
            0x8F => Self::UnsupportedRead,
            0x92 => Self::DataVersionMismatch,
            0x94 => Self::Timeout,
            0x9B => Self::UnsupportedNode,
            0x9C => Self::Busy,
            0x9D => Self::AccessRestricted,
            0xC3 => Self::UnsupportedCluster,
            0xC5 => Self::NoUpstreamSubscription,
            0xC6 => Self::NeedsTimedInteraction,
            0xC7 => Self::UnsupportedEvent,
            0xC8 => Self::PathsExhausted,
            0xC9 => Self::TimedRequestMismatch,
            0xCA => Self::FailsafeRequired,
            0xCB => Self::InvalidInState,
            0xCC => Self::NoCommandResponse,
            0xCD => Self::TermsAndConditionsChanged,
            0xCE => Self::MaintenanceRequired,
            0xCF => Self::DynamicConstraintError,
            0xD0 => Self::AlreadyExists,
            0xD1 => Self::InvalidTransportType,
            other => Self::Reserved(other),
        }
    }

    /// Whether this is [`Status::Success`].
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
            Self::InvalidSubscription => "INVALID_SUBSCRIPTION",
            Self::UnsupportedAccess => "UNSUPPORTED_ACCESS",
            Self::UnsupportedEndpoint => "UNSUPPORTED_ENDPOINT",
            Self::InvalidAction => "INVALID_ACTION",
            Self::UnsupportedCommand => "UNSUPPORTED_COMMAND",
            Self::InvalidCommand => "INVALID_COMMAND",
            Self::UnsupportedAttribute => "UNSUPPORTED_ATTRIBUTE",
            Self::ConstraintError => "CONSTRAINT_ERROR",
            Self::UnsupportedWrite => "UNSUPPORTED_WRITE",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::NotFound => "NOT_FOUND",
            Self::UnreportableAttribute => "UNREPORTABLE_ATTRIBUTE",
            Self::InvalidDataType => "INVALID_DATA_TYPE",
            Self::UnsupportedRead => "UNSUPPORTED_READ",
            Self::DataVersionMismatch => "DATA_VERSION_MISMATCH",
            Self::Timeout => "TIMEOUT",
            Self::UnsupportedNode => "UNSUPPORTED_NODE",
            Self::Busy => "BUSY",
            Self::AccessRestricted => "ACCESS_RESTRICTED",
            Self::UnsupportedCluster => "UNSUPPORTED_CLUSTER",
            Self::NoUpstreamSubscription => "NO_UPSTREAM_SUBSCRIPTION",
            Self::NeedsTimedInteraction => "NEEDS_TIMED_INTERACTION",
            Self::UnsupportedEvent => "UNSUPPORTED_EVENT",
            Self::PathsExhausted => "PATHS_EXHAUSTED",
            Self::TimedRequestMismatch => "TIMED_REQUEST_MISMATCH",
            Self::FailsafeRequired => "FAILSAFE_REQUIRED",
            Self::InvalidInState => "INVALID_IN_STATE",
            Self::NoCommandResponse => "NO_COMMAND_RESPONSE",
            Self::TermsAndConditionsChanged => "TERMS_AND_CONDITIONS_CHANGED",
            Self::MaintenanceRequired => "MAINTENANCE_REQUIRED",
            Self::DynamicConstraintError => "DYNAMIC_CONSTRAINT_ERROR",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::InvalidTransportType => "INVALID_TRANSPORT_TYPE",
            Self::Reserved(_) => "reserved",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_round_trips() {
        // Including the reserved ones: a proxy has to be able to pass on a status it does
        // not understand without substituting one it does.
        for value in 0..=u8::MAX {
            assert_eq!(Status::from_value(value).value(), value, "{value:#04x}");
        }
    }

    #[test]
    fn the_codes_match_the_spec_table() {
        // §8.10.1, spot-checked at the boundaries of each run of defined values.
        let cases = [
            (Status::Success, 0x00u8),
            (Status::Failure, 0x01),
            (Status::InvalidSubscription, 0x7D),
            (Status::UnsupportedEndpoint, 0x7F),
            (Status::InvalidAction, 0x80),
            (Status::UnsupportedAttribute, 0x86),
            (Status::UnsupportedRead, 0x8F),
            (Status::DataVersionMismatch, 0x92),
            (Status::AccessRestricted, 0x9D),
            (Status::UnsupportedCluster, 0xC3),
            (Status::NeedsTimedInteraction, 0xC6),
            (Status::MaintenanceRequired, 0xCE),
            (Status::DynamicConstraintError, 0xCF),
            (Status::AlreadyExists, 0xD0),
            (Status::InvalidTransportType, 0xD1),
        ];
        for (status, value) in cases {
            assert_eq!(status.value(), value, "{status}");
            assert_eq!(Status::from_value(value), status, "{value:#04x}");
        }
    }

    #[test]
    fn deprecated_codes_stay_reserved() {
        // §8.10.1 marks these "Deprecated: use FAILURE" and the ZCL OTA range "reserved".
        // Mapping them onto Failure would lose what the peer actually said.
        for value in [0x82u8, 0x83, 0x84, 0x8A, 0x90, 0x95, 0x9A, 0xC0, 0xC4] {
            assert_eq!(Status::from_value(value), Status::Reserved(value));
        }
    }

    #[test]
    fn the_table_ends_at_d1() {
        // §8.10.1's last three codes were added after the ones before them and are easy to
        // stop short of. Anything above 0xD1 is genuinely undefined.
        assert_eq!(Status::from_value(0xD1), Status::InvalidTransportType);
        assert_eq!(Status::from_value(0xD2), Status::Reserved(0xD2));
        assert_eq!(Status::from_value(0xFF), Status::Reserved(0xFF));
    }

    #[test]
    fn the_two_constraint_errors_are_distinct() {
        // §8.10.1 gives them different codes because they mean different things: one is a
        // value outside the schema's range, the other a value inside it and wrong for the
        // device's current state. A client retries differently.
        assert_ne!(Status::ConstraintError, Status::DynamicConstraintError);
        assert_eq!(Status::ConstraintError.value(), 0x87);
        assert_eq!(Status::DynamicConstraintError.value(), 0xCF);
    }

    #[test]
    fn only_success_is_success() {
        assert!(Status::Success.is_success());
        assert!(!Status::Failure.is_success());
        assert!(
            !Status::Reserved(0).is_success(),
            "0x00 is Success, not Reserved"
        );
    }
}
