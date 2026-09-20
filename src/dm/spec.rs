//! What the specification says a cluster is (Core §7.3, and the Application Cluster library).
//!
//! [`meta`](crate::dm::meta) describes what *this device serves*: the attributes its handler
//! answers, the commands it accepts. This module describes what the **specification defines**:
//! every element the cluster has, its conformance, its access, its qualities — the whole
//! table, whether or not any device implements all of it.
//!
//! The two are different things and the gap between them is where certification failures
//! live. A device whose `ClusterDescriptor` omits a mandatory attribute, or serves one its
//! feature map disallows, is conformant-looking and wrong; nothing in its own test suite
//! finds it, because its own tests only exercise what it does implement.
//! [`Cluster::validate`] is that check, and it is the reason these tables are generated from
//! the CSA XML rather than transcribed.
//!
//! Everything here is `&'static` const data. A device that names one cluster links one
//! cluster's table; the rest are dropped by the linker exactly as any other unreferenced
//! const is.

use crate::dm::conformance::{Conform, Conformance, Supports};
use crate::dm::meta::{
    AttributeDescriptor, ClusterDescriptor, CommandDescriptor, EventDescriptor, EventPriority,
    Reporting,
};
use crate::dm::{Access, AttributeQualities};
use crate::im::{AttributeId, ClusterId, CommandId, EventId};

/// One bit of a cluster's `FeatureMap` (§7.13.2).
#[derive(Debug, Clone, Copy)]
pub struct Feature {
    /// Which bit.
    pub bit: u8,
    /// The short code the conformance expressions name it by — "LT", "OFFONLY".
    pub code: &'static str,
    /// The readable name — "Lighting".
    pub name: &'static str,
    /// When the feature itself may be claimed. Features have conformance too: On/Off's
    /// `Lighting` is optional *only when* `OffOnly` is absent.
    pub conform: Conform,
}

/// One attribute, as the specification defines it.
#[derive(Debug, Clone, Copy)]
pub struct Attribute {
    /// Its id.
    pub id: AttributeId,
    /// Its name in the specification — "StartUpOnOff".
    pub name: &'static str,
    /// The specification's type name, verbatim — "uint16", "StartUpOnOffEnum",
    /// `list[TargetStruct]`. Kept as text because what a Rust program does with it is the
    /// handler's business; the generated Rust type lives in the cluster's own module.
    ///
    /// **Empty** for the handful of attributes the specification lists with no type at all —
    /// General Diagnostics' `DoNotUse`, Door Lock's `SecurityLevel`. Every one of them is
    /// deprecated or disallowed: there is nothing to say what they were, and the conformance
    /// already says they must not be there.
    pub kind: &'static str,
    /// §7.6's access column.
    pub access: Access,
    /// §7.12's qualities, minus the reporting policy.
    pub qualities: AttributeQualities,
    /// Whether and how changes are reported.
    pub reporting: Reporting,
    /// When the attribute may or must be present.
    pub conform: Conform,
}

/// One command.
#[derive(Debug, Clone, Copy)]
pub struct Command {
    /// Its id.
    pub id: CommandId,
    /// Its name in the specification — "OffWithEffect".
    pub name: &'static str,
    /// Whether the client sends it to the server, or the reverse. A response command is
    /// `to_client`, and a server's *accepted* command list must not contain one.
    pub to_server: bool,
    /// The command that answers it, if the answer is not a bare status.
    pub response: Option<CommandId>,
    /// The privilege an invoke needs, and whether it must be Timed.
    pub access: Access,
    /// When the command may or must be present.
    pub conform: Conform,
}

/// One event.
#[derive(Debug, Clone, Copy)]
pub struct Event {
    /// Its id.
    pub id: EventId,
    /// Its name in the specification — "StateChanged".
    pub name: &'static str,
    /// Which ring of the event store it goes in (§7.14.2).
    pub priority: EventPriority,
    /// The privilege a read needs.
    pub access: Access,
    /// When the event may or must be present.
    pub conform: Conform,
}

/// A whole cluster, as the specification defines it.
#[derive(Debug, Clone, Copy)]
pub struct Cluster {
    /// Its id.
    pub id: ClusterId,
    /// The readable name — "On/Off".
    pub name: &'static str,
    /// The highest revision in the cluster's revision history, which is what
    /// `ClusterRevision` must report (§7.13.1).
    pub revision: u16,
    /// The PICS code, for the certification declaration a test harness reads.
    pub pics: &'static str,
    /// Whether this cluster is a base or is derived from another — the Mode Base family and
    /// the Resource Monitoring clusters are one element set behind many ids.
    pub derived_from: Option<&'static str>,
    /// Its `FeatureMap` bits.
    pub features: &'static [Feature],
    /// Every attribute it defines, sorted by id.
    pub attributes: &'static [Attribute],
    /// Every command, accepted and generated, sorted by id.
    pub commands: &'static [Command],
    /// Every event, sorted by id.
    pub events: &'static [Event],
}

/// Something a device's configuration got wrong.
///
/// `#[non_exhaustive]` because the list has grown twice — `ResponseAccepted` and then
/// `Provisional`, each because a rule turned out not to be checked anywhere — and a `match` in
/// an integrator's build should not break the next time the specification gives this crate a
/// reason to notice something new.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Defect {
    /// A mandatory element the device does not serve.
    Missing(Element),
    /// An element the device serves that its feature map disallows.
    Disallowed(Element),
    /// A feature bit the device claims that this cluster revision does not define.
    UnknownFeature(u8),
    /// The descriptor's `ClusterRevision` is not the one the specification defines.
    WrongRevision {
        /// What the device reports.
        found: u16,
        /// What the specification says.
        expected: u16,
    },
    /// A response command in the accepted list, which is a command the server sends.
    ResponseAccepted(CommandId),
    /// An element the specification marks provisional, on a build that did not ask for them.
    ///
    /// Core §2.13 — and the Application Cluster and Device Library specifications' own lists —
    /// mark a mechanism provisional when it is "not certifiable and may change". Serving one is
    /// a deliberate act, and the `provisional` Cargo feature is where the deliberation goes; a
    /// build without it that furnishes a `P` element is a node that cannot be certified for a
    /// reason nobody chose.
    Provisional(Element),
}

/// Which element a [`Defect`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Element {
    /// An attribute.
    Attribute(AttributeId),
    /// A command.
    Command(CommandId),
    /// An event.
    Event(EventId),
}

/// A device's cluster instance, seen as a set of supported things.
///
/// This is the bridge between [`meta::ClusterDescriptor`](crate::dm::ClusterDescriptor) — what
/// a device serves — and [`Conform`] — what the specification allows.
struct Instance<'a> {
    descriptor: &'a ClusterDescriptor<'a>,
}

impl Supports for Instance<'_> {
    fn feature_map(&self) -> u32 {
        self.descriptor.feature_map
    }

    fn has_attribute(&self, id: AttributeId) -> bool {
        self.descriptor.attributes.iter().any(|a| a.id == id)
    }

    fn has_command(&self, id: CommandId) -> bool {
        self.descriptor.accepted_commands.iter().any(|c| c.id == id) || self.generates(id)
    }

    fn has_event(&self, id: EventId) -> bool {
        self.descriptor.events.iter().any(|e| e.id == id)
    }

    fn has_cluster(&self, _id: ClusterId) -> bool {
        // A cluster's own conformance never refers to another cluster; a device type's does,
        // and that check has the endpoint to answer it with.
        false
    }
}

impl Instance<'_> {
    /// Whether the server sends this command.
    ///
    /// §7.13.5's `GeneratedCommandList` is *synthesised*: "For each client request command in
    /// this list that mandates a response from the server, the response command SHALL be
    /// indicated in the GeneratedCommandList", so most responses are declared once, on the
    /// request, through [`CommandDescriptor::response`](crate::dm::CommandDescriptor). Asking
    /// only about the explicit list would find none of them and call every response command
    /// missing.
    fn generates(&self, id: CommandId) -> bool {
        self.descriptor.generated_command_ids().any(|c| c == id)
    }
}

impl Cluster {
    /// The feature bits this revision defines, as a mask.
    #[must_use]
    pub fn feature_mask(&self) -> u32 {
        let mut mask = 0u32;
        for feature in self.features {
            if feature.bit < 32 {
                mask |= 1u32 << feature.bit;
            }
        }
        mask
    }

    /// The feature whose code is `code`, if this cluster has one.
    #[must_use]
    pub fn feature(&self, code: &str) -> Option<&Feature> {
        self.features.iter().find(|f| f.code == code)
    }

    /// Checks a device's descriptor against the specification, reporting each defect to
    /// `found`.
    ///
    /// Four kinds of mistake, and the first two are the ones a device makes by accident:
    ///
    /// * a **mandatory element missing** — the feature map claims `Lighting` and the
    ///   descriptor has no `StartUpOnOff`;
    /// * a **disallowed element present** — `StartUpOnOff` served without `Lighting`, which a
    ///   commissioner reads as a device that does not know what it is;
    /// * a feature bit this revision does not define;
    /// * a `ClusterRevision` that is not the specification's.
    ///
    /// Elements whose conformance is [prose](Conformance::Described) are skipped in both
    /// directions. The specification could not express the rule mechanically, so neither can
    /// this — and guessing would produce exactly the confident-and-wrong answer that makes a
    /// validator worth ignoring.
    ///
    /// A fifth is reported only on a build without the `provisional` feature: an element the
    /// specification marks `P`, or a cluster one of the three provisional *lists* names
    /// ([`PROVISIONAL_CLUSTERS`]).
    pub fn validate(&self, descriptor: &ClusterDescriptor<'_>, mut found: impl FnMut(Defect)) {
        // A cluster the Application Cluster specification calls provisional in prose. The data
        // model does not always mark its elements `P` — `content_control` and `temperature_alarm`
        // carry no provisional conformance at all — so serving one would otherwise be a
        // perfectly conformant way to build a node that cannot be certified.
        #[cfg(not(feature = "provisional"))]
        if PROVISIONAL_CLUSTERS.iter().any(|(id, _)| *id == self.id) {
            for attribute in descriptor.attributes {
                found(Defect::Provisional(Element::Attribute(attribute.id)));
            }
        }
        if descriptor.revision != self.revision {
            found(Defect::WrongRevision {
                found: descriptor.revision,
                expected: self.revision,
            });
        }
        let undefined = descriptor.feature_map & !self.feature_mask();
        for bit in 0..32u8 {
            if undefined & (1u32 << bit) != 0 {
                found(Defect::UnknownFeature(bit));
            }
        }

        let instance = Instance { descriptor };

        for attribute in self.attributes {
            let verdict = attribute.conform.verdict(&instance);
            let present = instance.has_attribute(attribute.id);
            check(
                verdict,
                present,
                Element::Attribute(attribute.id),
                &mut found,
            );
        }
        for command in self.commands {
            let verdict = command.conform.verdict(&instance);
            if command.to_server {
                let present = descriptor
                    .accepted_commands
                    .iter()
                    .any(|c| c.id == command.id);
                check(verdict, present, Element::Command(command.id), &mut found);
            } else {
                // A response command belongs in the *generated* list. Accepting one would
                // advertise that a client may invoke this server's own reply.
                //
                // Only when the id is unambiguous. Matter scopes command ids **by
                // direction**, and four clusters in the 1.6 library reuse one across both —
                // Groups' `AddGroup` and `AddGroupResponse` are each `0x00`. Finding that id
                // in the accepted list there means the *request* is accepted, which is exactly
                // right, and reporting it would make every conformant Groups server look
                // broken.
                let shared = self
                    .commands
                    .iter()
                    .any(|other| other.to_server && other.id == command.id);
                if !shared
                    && descriptor
                        .accepted_commands
                        .iter()
                        .any(|c| c.id == command.id)
                {
                    found(Defect::ResponseAccepted(command.id));
                }
                let present = instance.generates(command.id);
                check(verdict, present, Element::Command(command.id), &mut found);
            }
        }
        for event in self.events {
            let verdict = event.conform.verdict(&instance);
            let present = instance.has_event(event.id);
            check(verdict, present, Element::Event(event.id), &mut found);
        }
    }

    /// Whether a descriptor has no defects at all.
    #[must_use]
    pub fn is_valid(&self, descriptor: &ClusterDescriptor<'_>) -> bool {
        let mut ok = true;
        self.validate(descriptor, |_| ok = false);
        ok
    }
}

/// Clusters a specification calls provisional **in prose** rather than in its conformance column.
///
/// Core §2.13 is a list of mechanisms and the data model marks their elements `P`, so
/// [`Conformance::Provisional`] carries them. The Application Cluster and Device Library
/// specifications keep lists of their own, in a paragraph — and the model does not always mark
/// what those paragraphs name. `content_control` and `temperature_alarm` come out of the
/// generator with no provisional conformance at all, so without this table a default build could
/// serve either and every check here would call it conformant.
///
/// Hand-written, because prose is, which puts it in the same class as the rest of the
/// hand-written specification surface and under the same drift check. Each entry cites the
/// sentence it comes from.
pub const PROVISIONAL_CLUSTERS: &[(ClusterId, &str)] = &[
    // App §1.1's list: "Support for Content Control Cluster is provisional."
    (0x050F, "App §1.1 — Content Control"),
    // "Support for the Temperature Alarm Cluster is provisional."
    (0x0064, "App §1.1 — Temperature Alarm"),
    // "Support for the Ambient Context Sensing Cluster is provisional." The model does mark this
    // one, and it is here so that the list is the whole list rather than the part that was
    // missing — a reader checking the paragraph against this table should find every line.
    (0x0431, "App §1.1 — Ambient Context Sensing"),
];

/// What the prose lists name and a cluster id cannot express.
///
/// Two things, stated so that [`PROVISIONAL_CLUSTERS`] reads as partial rather than complete.
/// Dishwasher Alarm's five provisional *alarm bits* are values inside a bitmap attribute rather
/// than elements of a cluster, so no conformance verdict reaches them; the check belongs in that
/// cluster's write path. The Device Library's two device types belong to
/// [`DeviceType::validate`](crate::dm::device::DeviceType::validate).
///
/// App §1.1's other two — Level Control's `Frequency` and Microwave Oven Control's
/// `PowerInWatts` — need nothing here: the data model marks both `P` itself.
pub const PROVISIONAL_NOT_EXPRESSIBLE: &str =
    "App §1.1: Dishwasher Alarm's five alarm bits; DL §1.1: two device types";

fn check(verdict: Conformance, present: bool, element: Element, found: &mut impl FnMut(Defect)) {
    match verdict {
        Conformance::Mandatory if !present => found(Defect::Missing(element)),
        Conformance::Disallowed if present => found(Defect::Disallowed(element)),
        // "Provisional means off" is the crate's ninth rule, and this is the only place it can
        // be enforced rather than asserted. The `provisional` feature gates the modules whose
        // *whole* subject is provisional — the Groupcast cluster — but most provisional elements
        // sit inside a cluster that is otherwise certifiable, and for those the feature has
        // nothing to gate. So the verdict does the work: a `P` element a device furnishes is a
        // defect unless the build asked for provisional mechanisms.
        #[cfg(not(feature = "provisional"))]
        Conformance::Provisional if present => found(Defect::Provisional(element)),
        _ => {}
    }
}

// --- Building a descriptor from the specification ------------------------------------------

/// The optional elements a device chooses to serve.
///
/// Conformance says what a device *may* have, and "may" is not derivable — an optional
/// attribute is present because the product decided to implement it. So a device supplies its
/// feature map, which settles the mandatory and disallowed elements, and this, which settles
/// the rest.
#[derive(Debug, Clone, Copy, Default)]
pub struct Optional<'a> {
    /// Optional attributes the device serves.
    pub attributes: &'a [AttributeId],
    /// Optional commands it accepts or generates.
    pub commands: &'a [CommandId],
    /// Optional events it may emit.
    pub events: &'a [EventId],
}

impl Optional<'_> {
    /// A device that implements nothing optional.
    pub const NONE: Self = Self {
        attributes: &[],
        commands: &[],
        events: &[],
    };
}

/// A [`ClusterDescriptor`] derived from the specification's own tables.
///
/// The tables say which elements a feature map makes mandatory and which it forbids, so a
/// device that states its features and its optional choices does not need to write the lists
/// out — and cannot get them wrong. That is the failure this exists for: a hand-written
/// descriptor whose element list does not move when its feature map does still *advertises*
/// the elements, and a client reading `AttributeList` believes it.
///
/// `A`, `C`, `G` and `E` bound what the *device holds* — the attributes, accepted commands,
/// generated commands and events conformance selected, not the size of the specification's
/// table. Sizing one too small is [`NoSpace`](crate::ErrorCode::NoSpace), at construction,
/// once.
///
/// ```
/// use matter_kit::clusters::generated::on_off;
/// use matter_kit::dm::spec::{Conforming, Optional};
///
/// // A plain On/Off server: no Lighting, so none of its four attributes.
/// let plain = Conforming::<8, 8, 4, 4>::new(&on_off::CLUSTER, 0, &Optional::NONE)?;
/// assert_eq!(plain.descriptor().attributes.len(), 1);
///
/// // The same cluster with Lighting: `StartUpOnOff` and its three companions appear, and so
/// // do three more commands, without a line of it being written down anywhere.
/// let lighting =
///     Conforming::<8, 8, 4, 4>::new(&on_off::CLUSTER, on_off::feature::LIGHTING, &Optional::NONE)?;
/// assert_eq!(lighting.descriptor().attributes.len(), 5);
/// assert_eq!(lighting.descriptor().accepted_commands.len(), 6);
/// # Ok::<(), matter_kit::Error>(())
/// ```
#[derive(Debug)]
pub struct Conforming<const A: usize, const C: usize, const G: usize, const E: usize> {
    id: ClusterId,
    revision: u16,
    feature_map: u32,
    attributes: heapless::Vec<AttributeDescriptor, A>,
    accepted: heapless::Vec<CommandDescriptor, C>,
    generated: heapless::Vec<CommandId, G>,
    events: heapless::Vec<EventDescriptor, E>,
}

/// Which entries of a specification table have been chosen, by position.
///
/// A bitset rather than a list of ids, because an id does not identify an entry: Matter scopes
/// command ids by direction, and Groups, Scenes, Door Lock and Commodity Tariff each define a
/// request and a response that share one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Chosen<const N: usize> {
    bits: [bool; N],
}

impl<const N: usize> Chosen<N> {
    const fn new() -> Self {
        Self { bits: [false; N] }
    }

    /// Marks an entry chosen, or fails when the table is longer than the caller sized for.
    fn set(&mut self, index: usize) -> crate::error::Result<()> {
        match self.bits.get_mut(index) {
            Some(slot) => {
                *slot = true;
                Ok(())
            }
            None => Err(crate::Error::new(crate::ErrorCode::NoSpace)),
        }
    }

    fn has(&self, index: usize) -> bool {
        self.bits.get(index).copied().unwrap_or(false)
    }
}

/// What a candidate element set looks like to a conformance expression.
struct Candidate<'a> {
    feature_map: u32,
    spec: &'a Cluster,
    attributes: &'a Chosen<MAX_ELEMENTS>,
    commands: &'a Chosen<MAX_ELEMENTS>,
    events: &'a Chosen<MAX_ELEMENTS>,
}

impl Supports for Candidate<'_> {
    fn feature_map(&self) -> u32 {
        self.feature_map
    }
    fn has_attribute(&self, id: AttributeId) -> bool {
        self.spec
            .attributes
            .iter()
            .enumerate()
            .any(|(index, a)| a.id == id && self.attributes.has(index))
    }
    /// A condition names a command by id alone, which is direction-agnostic, so this answers
    /// "some chosen command has this id". No cluster that reuses an id across directions
    /// conditions on a command, so the two readings never differ in the 1.6 library.
    fn has_command(&self, id: CommandId) -> bool {
        self.spec
            .commands
            .iter()
            .enumerate()
            .any(|(index, c)| c.id == id && self.commands.has(index))
    }
    fn has_event(&self, id: EventId) -> bool {
        self.spec
            .events
            .iter()
            .enumerate()
            .any(|(index, e)| e.id == id && self.events.has(index))
    }
    fn has_cluster(&self, _id: ClusterId) -> bool {
        false
    }
}

/// How many times the element set may be recomputed before giving up.
///
/// An element's conformance may name another element, so the answer depends on the set being
/// computed — `Attribute(x)` is true or false according to whether `x` ended up present. The
/// dependencies in the 1.6 library are one deep, so this settles on the second pass; the
/// margin is for a future revision, and the cap is because the specification does not promise
/// such a system has a unique solution at all.
const ROUNDS: usize = 8;

/// How many elements of one kind a cluster may define.
///
/// The working set during the fixed-point search, which is sized by the *specification's*
/// table rather than by what the caller chose to serve — so `A`, `C`, `G` and `E` keep meaning
/// "how much the device holds" rather than "how big the cluster is". The largest tables in the
/// 1.6 library are 65 attributes, 28 commands and 17 events; this leaves room for a revision
/// that grows them.
const MAX_ELEMENTS: usize = 128;

impl<const A: usize, const C: usize, const G: usize, const E: usize> Conforming<A, C, G, E> {
    /// Derives the descriptor for an instance of `spec` with this feature map.
    ///
    /// Returns [`InvalidArgument`](crate::ErrorCode::InvalidArgument) for a feature bit the cluster does not define —
    /// a device claiming one is describing a cluster that does not exist — and
    /// [`NoSpace`](crate::ErrorCode::NoSpace) when a const parameter is too small for what conformance
    /// selected.
    pub fn new(
        spec: &'static Cluster,
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Self> {
        if feature_map & !spec.feature_mask() != 0 {
            crate::error::bail!(InvalidArgument)
        }

        // Iterate to a fixed point. Each round decides every element against the previous
        // round's set, which is what lets an attribute whose conformance names another
        // attribute settle.
        // Selection is by *position* in the specification's tables, never by id. Matter
        // scopes command ids by direction, and Groups, Scenes, Door Lock and Commodity Tariff
        // each define a request and a response sharing one — so a set of ids would silently
        // merge them and serve whichever the filter happened to match first.
        let mut attributes = Chosen::<MAX_ELEMENTS>::new();
        let mut commands = Chosen::<MAX_ELEMENTS>::new();
        let mut events = Chosen::<MAX_ELEMENTS>::new();
        for round in 0..ROUNDS {
            let candidate = Candidate {
                feature_map,
                spec,
                attributes: &attributes,
                commands: &commands,
                events: &events,
            };
            let mut next_attributes = Chosen::<MAX_ELEMENTS>::new();
            let mut next_commands = Chosen::<MAX_ELEMENTS>::new();
            let mut next_events = Chosen::<MAX_ELEMENTS>::new();

            for (index, attribute) in spec.attributes.iter().enumerate() {
                if selected(
                    attribute.conform.verdict(&candidate),
                    optional.attributes.contains(&attribute.id),
                ) {
                    next_attributes.set(index)?;
                }
            }
            for (index, command) in spec.commands.iter().enumerate() {
                if selected(
                    command.conform.verdict(&candidate),
                    optional.commands.contains(&command.id),
                ) {
                    next_commands.set(index)?;
                }
            }
            for (index, event) in spec.events.iter().enumerate() {
                if selected(
                    event.conform.verdict(&candidate),
                    optional.events.contains(&event.id),
                ) {
                    next_events.set(index)?;
                }
            }

            let settled =
                next_attributes == attributes && next_commands == commands && next_events == events;
            attributes = next_attributes;
            commands = next_commands;
            events = next_events;
            if settled {
                break;
            }
            if round == ROUNDS - 1 {
                // The conformance did not settle. Better to refuse than to ship whichever
                // half of an oscillation the loop happened to stop on.
                crate::error::bail!(InvalidState)
            }
        }

        let mut this = Self {
            id: spec.id,
            revision: spec.revision,
            feature_map,
            attributes: heapless::Vec::new(),
            accepted: heapless::Vec::new(),
            generated: heapless::Vec::new(),
            events: heapless::Vec::new(),
        };
        for (_, attribute) in spec
            .attributes
            .iter()
            .enumerate()
            .filter(|(index, _)| attributes.has(*index))
        {
            this.attributes
                .push(AttributeDescriptor {
                    id: attribute.id,
                    access: attribute.access,
                    reporting: attribute.reporting,
                    qualities: attribute.qualities,
                })
                .map_err(|_| crate::Error::new(crate::ErrorCode::NoSpace))?;
        }
        for (_, command) in spec
            .commands
            .iter()
            .enumerate()
            .filter(|(index, _)| commands.has(*index))
        {
            if command.to_server {
                this.accepted
                    .push(CommandDescriptor {
                        id: command.id,
                        access: command.access,
                        // Left `None`: §7.13.5's list is synthesised from it, and the
                        // responses are already selected in their own right below. Declaring
                        // them here as well would list each one twice.
                        response: None,
                    })
                    .map_err(|_| crate::Error::new(crate::ErrorCode::NoSpace))?;
            } else {
                this.generated
                    .push(command.id)
                    .map_err(|_| crate::Error::new(crate::ErrorCode::NoSpace))?;
            }
        }
        for (_, event) in spec
            .events
            .iter()
            .enumerate()
            .filter(|(index, _)| events.has(*index))
        {
            this.events
                .push(EventDescriptor {
                    id: event.id,
                    access: event.access,
                    priority: event.priority,
                })
                .map_err(|_| crate::Error::new(crate::ErrorCode::NoSpace))?;
        }
        Ok(this)
    }

    /// The descriptor, borrowed from this storage.
    #[must_use]
    pub fn descriptor(&self) -> ClusterDescriptor<'_> {
        ClusterDescriptor {
            id: self.id,
            revision: self.revision,
            feature_map: self.feature_map,
            attributes: &self.attributes,
            accepted_commands: &self.accepted,
            generated_commands: &self.generated,
            events: &self.events,
        }
    }
}

/// Whether an element with this verdict is served.
///
/// `Provisional` and `Deprecated` are treated as optional *here*: neither is forbidden, and both
/// are a decision the product makes rather than one the conformance makes for it. Whether the
/// product was allowed to make that decision is [`check`]'s question, not this one — a `P`
/// element furnished by a build without the `provisional` feature is a [`Defect::Provisional`].
/// `Described` is *not* selected — the specification could not express the rule, so a device
/// that needs the element names it in [`Optional`] and takes responsibility for reading the
/// prose.
const fn selected(verdict: Conformance, chosen: bool) -> bool {
    match verdict {
        Conformance::Mandatory => true,
        Conformance::Optional
        | Conformance::Provisional
        | Conformance::Deprecated
        | Conformance::Described => chosen,
        Conformance::Disallowed => false,
    }
}
