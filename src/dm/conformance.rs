//! Conformance: what the specification says may, must, or must not be present (Core §7.3).
//!
//! Every element of every cluster carries one of these, and it is the part of the data model
//! nobody transcribes correctly by hand. On/Off's `StartUpOnOff` is mandatory *when the
//! Lighting feature is set* and forbidden otherwise; its `On` command is mandatory *unless*
//! `OffOnly` is; Level Control's `CurrentFrequency` is mandatory with `FQ` and disallowed
//! without it. There are several thousand such rules in the 1.6 library, and a device whose
//! descriptors disagree with them is one that fails certification for a reason no test in the
//! device's own suite would find.
//!
//! # Why it is a tree rather than a flag
//!
//! The conformance column is a small language, not a keyword. These are all real:
//!
//! ```text
//! M                         always
//! [LT]                      optional when Lighting
//! !OFFONLY                  mandatory unless OffOnly
//! LT & !DF                  mandatory when Lighting and not DeadFrontBehavior
//! MSCH | MSFT, [MSSCH]      mandatory when either; otherwise optional when MSSCH
//! ```
//!
//! So an element's conformance is an ordered list of [`Clause`]s — the specification's
//! "otherwise" chain — each a verdict and the [`Condition`] under which it applies. The first
//! clause whose condition holds decides, and an element no clause selects is **disallowed**.
//! That last rule is the one worth stating plainly: `[LT]` does not mean "optional, and by the
//! way there is a feature"; it means the element may exist only when Lighting does.
//!
//! # What this is for
//!
//! Two things, and the second is the reason it exists at all.
//!
//! A **device can be checked against its own claims**: given the feature map an endpoint
//! declares, [`spec::Cluster::validate`](crate::dm::spec::Cluster::validate) says whether the attributes, commands and events it serves
//! are the set the specification permits. A missing mandatory element, or a present disallowed
//! one, is found at construction rather than by a certification lab.
//!
//! And a **client can reason about a peer** without a table of special cases: the same
//! evaluation over a `FeatureMap` read off the wire says what that node must be able to do.

use crate::im::{AttributeId, ClusterId, CommandId, EventId};

/// What the specification says about an element's presence.
///
/// Four of the five are decisions; `Described` is the refusal to make one, and
/// [`Cluster::validate`](crate::dm::spec::Cluster::validate) is where all five are acted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Conformance {
    /// `M` — the element SHALL be present.
    Mandatory,
    /// `O` — the element MAY be present.
    Optional,
    /// `P` — provisional. Not certifiable, and may change in a dot revision.
    ///
    /// Three lists say what is provisional: Core §2.13, and the Application Cluster and Device
    /// Library specifications' own. A device *may* serve one, so this behaves as
    /// [`Optional`](Conformance::Optional) when the `provisional` feature is on — and
    /// [`Cluster::validate`](crate::dm::spec::Cluster::validate) reports
    /// [`Defect::Provisional`](crate::dm::spec::Defect::Provisional) when it is not, because a
    /// certifiable build is the default build.
    Provisional,
    /// `D` — deprecated. Present for compatibility with an earlier revision, and not to be
    /// implemented in anything new.
    Deprecated,
    /// `X` — the element SHALL NOT be present.
    Disallowed,
    /// `desc` — the rule is prose the XML could not express, so the specification's own words
    /// decide. Neither permitted nor forbidden mechanically; a validator must not guess.
    Described,
}

// There is deliberately no `is_permitted`/`is_required` pair here, convenient as one would look.
// `Described` is not a boolean in either direction — the specification's own words decide, which
// is why `Cluster::validate` skips those elements instead of judging them — so a predicate would
// have to answer `false` for it, and `false` reads as "forbidden". That is a guess in exactly
// the direction the verdict exists to refuse.
//
// An element's conformance is asked through
// [`Cluster::validate`](crate::dm::spec::Cluster::validate), which has all three answers and a
// place to put the third.

/// What an element's presence depends on.
///
/// Borrowed rather than owned throughout: the whole tree is `const` data generated from the
/// CSA XML, so a condition is a `&'static Condition` and costs nothing at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// Unconditional.
    Always,
    /// A feature bit of this cluster's `FeatureMap`.
    Feature(u8),
    /// Another attribute of this cluster being present.
    Attribute(AttributeId),
    /// A command of this cluster being present.
    Command(CommandId),
    /// An event of this cluster being present.
    Event(EventId),
    /// Another cluster on the same endpoint — how a device type says "Level Control, if you
    /// have On/Off".
    Cluster(ClusterId),
    /// A named condition the XML does not define in terms of anything else — "Zigbee",
    /// "Matter", "LargeMessageTransport". A validator cannot evaluate these, so an element
    /// that depends on one is [`Conformance::Described`] rather than guessed at.
    Named(&'static str),
    /// Logical negation.
    Not(&'static Condition),
    /// Every term must hold.
    All(&'static [Condition]),
    /// Some term must hold.
    Any(&'static [Condition]),
    /// Exactly one term must hold. Rare, and the reason `Any` cannot simply be reused.
    ExactlyOne(&'static [Condition]),
}

/// What a device says it supports, so a [`Condition`] can be evaluated against it.
///
/// A trait rather than a bare feature map because the conditions are not all about features:
/// an attribute's conformance may depend on another attribute being served, and a device
/// type's on a cluster being present.
pub trait Supports {
    /// The cluster's `FeatureMap`.
    fn feature_map(&self) -> u32;

    /// Whether the endpoint serves an attribute of this cluster.
    fn has_attribute(&self, id: AttributeId) -> bool;

    /// Whether the endpoint serves a command of this cluster.
    fn has_command(&self, id: CommandId) -> bool;

    /// Whether the endpoint serves an event of this cluster.
    fn has_event(&self, id: EventId) -> bool;

    /// Whether the endpoint serves another cluster.
    fn has_cluster(&self, id: ClusterId) -> bool;

    /// Whether a named condition holds. The default is "unknown", which is what makes an
    /// element depending on one [`Conformance::Described`] rather than silently absent.
    fn named(&self, _name: &str) -> Option<bool> {
        None
    }
}

/// Evaluating a condition has three outcomes, not two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Truth {
    True,
    False,
    /// A named condition this device cannot answer. It poisons the whole expression: a
    /// validator that guessed would either demand an element the device is right not to have
    /// or permit one it must not.
    Unknown,
}

impl Truth {
    const fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

impl Condition {
    /// Evaluates the condition against what a device supports.
    fn eval<S: Supports + ?Sized>(&self, device: &S) -> Truth {
        match self {
            Self::Always => Truth::True,
            Self::Feature(bit) => {
                // A bit beyond the map's width is a feature this revision does not define.
                if *bit >= 32 {
                    return Truth::False;
                }
                if device.feature_map() & (1u32 << *bit) != 0 {
                    Truth::True
                } else {
                    Truth::False
                }
            }
            Self::Attribute(id) => Truth::from(device.has_attribute(*id)),
            Self::Command(id) => Truth::from(device.has_command(*id)),
            Self::Event(id) => Truth::from(device.has_event(*id)),
            Self::Cluster(id) => Truth::from(device.has_cluster(*id)),
            Self::Named(name) => device.named(name).map_or(Truth::Unknown, Truth::from),
            Self::Not(inner) => inner.eval(device).not(),
            Self::All(terms) => {
                // A single false settles it even with unknowns present, which is why this is
                // not a fold over booleans.
                let mut unknown = false;
                for term in *terms {
                    match term.eval(device) {
                        Truth::False => return Truth::False,
                        Truth::Unknown => unknown = true,
                        Truth::True => {}
                    }
                }
                if unknown { Truth::Unknown } else { Truth::True }
            }
            Self::Any(terms) => {
                let mut unknown = false;
                for term in *terms {
                    match term.eval(device) {
                        Truth::True => return Truth::True,
                        Truth::Unknown => unknown = true,
                        Truth::False => {}
                    }
                }
                if unknown {
                    Truth::Unknown
                } else {
                    Truth::False
                }
            }
            Self::ExactlyOne(terms) => {
                let mut count = 0usize;
                for term in *terms {
                    match term.eval(device) {
                        Truth::True => count = count.saturating_add(1),
                        Truth::Unknown => return Truth::Unknown,
                        Truth::False => {}
                    }
                }
                Truth::from(count == 1)
            }
        }
    }
}

impl From<bool> for Truth {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

/// One branch of a conformance expression: a verdict and when it applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clause {
    /// What the element is when this clause is selected.
    pub verdict: Conformance,
    /// When it is selected.
    pub when: Condition,
}

impl Clause {
    /// An unconditional clause.
    #[must_use]
    pub const fn always(verdict: Conformance) -> Self {
        Self {
            verdict,
            when: Condition::Always,
        }
    }
}

/// An element's complete conformance — the specification's "otherwise" chain.
///
/// The first clause whose condition holds decides. An element no clause selects is
/// [`Conformance::Disallowed`]: `[LT]` does not mean "optional, and incidentally there is a
/// feature", it means the element may exist only when Lighting does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conform {
    /// The clauses, in the order the specification wrote them.
    pub clauses: &'static [Clause],
}

impl Conform {
    /// `M` — mandatory, unconditionally.
    pub const MANDATORY: Self = Self {
        clauses: &[Clause::always(Conformance::Mandatory)],
    };
    /// `O` — optional, unconditionally.
    pub const OPTIONAL: Self = Self {
        clauses: &[Clause::always(Conformance::Optional)],
    };
    /// `X` — disallowed.
    pub const DISALLOWED: Self = Self {
        clauses: &[Clause::always(Conformance::Disallowed)],
    };
    /// `desc` — the rule is prose.
    pub const DESCRIBED: Self = Self {
        clauses: &[Clause::always(Conformance::Described)],
    };

    /// The verdict for a device that supports what `device` says it does.
    #[must_use]
    pub fn verdict<S: Supports + ?Sized>(&self, device: &S) -> Conformance {
        for clause in self.clauses {
            match clause.when.eval(device) {
                Truth::True => return clause.verdict,
                // An unanswerable condition makes the whole element's status prose, because
                // the specification's own words are the only thing that can settle it.
                Truth::Unknown => return Conformance::Described,
                Truth::False => {}
            }
        }
        // No clause applied. §7.3: an element the conformance does not select SHALL NOT be
        // present — which is what makes `[LT]` a statement about existence rather than
        // optionality.
        Conformance::Disallowed
    }
}
