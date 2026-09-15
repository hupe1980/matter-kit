//! What a cluster is, once the XML has been read.
//!
//! Deliberately close to the XML rather than to the emitted Rust: the parser's job is to stop
//! guessing, and the emitter's is to decide how it looks. Putting the naming rules here would
//! make a change to the output a change to the parser.

use std::collections::BTreeMap;

/// Everything one data-model directory holds.
pub struct DataModel {
    /// The `spec_tag` file's contents — "1.6", "1.6.1".
    pub version: String,
    pub clusters: Vec<Cluster>,
    pub device_types: Vec<DeviceType>,
    /// Type names no Rust mapping exists for, and how often each appears. A structure using
    /// one is not generated, and `cargo xtask report` prints this so the gap is countable
    /// rather than invisible.
    pub unmapped_types: BTreeMap<String, usize>,
}

/// One cluster.
pub struct Cluster {
    pub id: u32,
    /// The XML's `name`, with any trailing " Cluster" removed: "On/Off", "Level Control".
    pub name: String,
    pub revision: u16,
    /// The `picsCode` classification attribute — "OO", "LVL". Empty for a few clusters.
    pub pics: String,
    /// What the cluster is derived from, when `hierarchy="derived"` — the Mode Base family
    /// and the Resource Monitoring clusters are one element set behind many ids.
    pub base_cluster: Option<String>,
    /// Whether this is an **abstract base**: a file that defines types and elements but no
    /// cluster id, so nothing serves it directly.
    ///
    /// Three of them — Alarm Base, Label and Mode Base — and they matter because the clusters
    /// derived from them reference their structures by name. A generator that ignored a file
    /// with no id would drop `ModeTagStruct` and with it every Mode cluster's `ModeOptions`.
    pub is_base: bool,
    pub features: Vec<Feature>,
    pub enums: Vec<Enumeration>,
    pub bitmaps: Vec<Bitmap>,
    pub structs: Vec<Structure>,
    /// `<number name="VideoStreamID" type="uint16"/>` aliases, which are just a base type
    /// under a name the specification finds more readable.
    pub typedefs: Vec<(String, String)>,
    pub attributes: Vec<Attribute>,
    pub commands: Vec<Command>,
    pub events: Vec<Event>,
}

/// One bit of the `FeatureMap`.
pub struct Feature {
    pub bit: u8,
    /// The short code the conformance expressions refer to it by — "LT", "OFFONLY".
    pub code: String,
    /// The readable name — "Lighting".
    pub name: String,
    pub summary: String,
    pub conform: Conform,
}

/// A named enumeration.
pub struct Enumeration {
    pub name: String,
    pub items: Vec<EnumItem>,
}

pub struct EnumItem {
    pub value: u64,
    pub name: String,
    pub summary: String,
    pub conform: Conform,
}

/// A named bitmap.
pub struct Bitmap {
    pub name: String,
    pub fields: Vec<BitmapField>,
}

pub struct BitmapField {
    pub bit: u8,
    pub name: String,
    pub summary: String,
    pub conform: Conform,
}

/// A named structure, or a command's or event's field list.
pub struct Structure {
    pub name: String,
    pub fields: Vec<Field>,
    /// `<access fabricScoped="true"/>` — §7.19.1.9 adds the global `FabricIndex` field 254 to
    /// such a structure, and the XML does not list it because every one of them has it.
    pub fabric_scoped: bool,
}

pub struct Field {
    pub id: u8,
    pub name: String,
    /// The XML type name, unmapped.
    pub kind: String,
    /// For `type="list"`, what the entries are.
    pub entry: Option<String>,
    pub nullable: bool,
    pub conform: Conform,
}

pub struct Attribute {
    pub id: u32,
    pub name: String,
    pub kind: String,
    pub entry: Option<String>,
    pub summary: String,
    pub access: Access,
    pub quality: Quality,
    pub conform: Conform,
}

pub struct Command {
    pub id: u32,
    pub name: String,
    /// `commandToServer` or `commandToClient`.
    pub direction: String,
    /// The `response` attribute: "Y" for a status, or the name of a response command.
    pub response: String,
    pub summary: String,
    pub access: Access,
    pub conform: Conform,
    pub fields: Vec<Field>,
}

pub struct Event {
    pub id: u32,
    pub name: String,
    /// `debug`, `info` or `critical`.
    pub priority: String,
    pub summary: String,
    pub access: Access,
    pub conform: Conform,
    pub fields: Vec<Field>,
}

/// §7.6's access qualities, as the XML spells them.
#[derive(Default, Clone)]
pub struct Access {
    pub read: bool,
    pub write: bool,
    pub read_privilege: Option<String>,
    pub write_privilege: Option<String>,
    pub invoke_privilege: Option<String>,
    /// `F` — fabric-scoped.
    pub fabric_scoped: bool,
    /// `S` — fabric-sensitive.
    pub fabric_sensitive: bool,
    /// `T` — a Timed interaction is required.
    pub timed: bool,
    /// `L` — the element needs a transport that can carry Large Messages (§7.12.5).
    ///
    /// It comes off the `<quality largeMessage="true">` element rather than `<access>`, but it
    /// belongs here: what it constrains is the *interaction*, which is what the library's
    /// `Access` is for, and the interaction model checks it before a command runs.
    pub large: bool,
}

/// §7.12's qualities.
#[derive(Default, Clone)]
pub struct Quality {
    pub nullable: bool,
    /// `persistence="nonVolatile"` or `"fixed"`.
    pub persistence: Option<String>,
    /// `C` — changes are omitted from reports.
    pub changes_omitted: bool,
    /// `Q` — quieter reporting.
    pub quieter: bool,
    /// `S` — the attribute takes part in scenes.
    pub scene: bool,
    /// `P` — the attribute supports atomic writes.
    pub atomic: bool,
    /// `L` — the value needs a Large Message.
    pub large: bool,
}

/// One branch of a conformance expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clause {
    pub verdict: Verdict,
    pub when: Condition,
}

/// An element's conformance: clauses in the order the XML wrote them, first match wins.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Conform {
    pub clauses: Vec<Clause>,
}

impl Conform {
    /// `M`, unconditionally.
    pub fn mandatory() -> Self {
        Self {
            clauses: vec![Clause {
                verdict: Verdict::Mandatory,
                when: Condition::Always,
            }],
        }
    }

    /// Whether the rule is prose the XML could not express.
    pub fn is_described(&self) -> bool {
        self.clauses
            .iter()
            .any(|clause| clause.verdict == Verdict::Described)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Mandatory,
    Optional,
    Provisional,
    Deprecated,
    Disallowed,
    Described,
}

/// When a clause applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    Always,
    /// A feature, by its short code. Resolved to a bit number by the emitter, which is the
    /// only place that knows the cluster's feature table.
    Feature(String),
    Attribute(String),
    Command(String),
    Event(String),
    Cluster(String),
    /// Another **field of the same structure** — `Node` is mandatory when `Endpoint` is
    /// present and `Group` when it is not, which is how §9.6.5.1 says a binding is unicast or
    /// groupcast and never both.
    Field(String),
    /// A `<condition name="…"/>` — "Zigbee", "Matter", and other things outside the model.
    Named(String),
    Not(Box<Condition>),
    All(Vec<Condition>),
    Any(Vec<Condition>),
    ExactlyOne(Vec<Condition>),
    /// A comparison the XML expresses with `<greaterTerm>` and friends. Nothing evaluates
    /// these — they compare attribute values at runtime, not a device's configuration — so
    /// they become [`Verdict::Described`].
    Comparison,
}

/// One device type.
pub struct DeviceType {
    pub id: u32,
    pub name: String,
    pub revision: u16,
    /// `simple`, `utility`, `node`, `dynamic utility`.
    pub class: String,
    pub scope: String,
    pub clusters: Vec<DeviceCluster>,
}

/// A cluster a device type requires or allows.
pub struct DeviceCluster {
    pub id: u32,
    pub name: String,
    /// `server` or `client`.
    pub side: String,
    pub conform: Conform,
    /// Features the device type constrains beyond the cluster's own conformance.
    pub features: Vec<(String, Conform)>,
    /// Elements the device type requires beyond the cluster's own conformance.
    pub attributes: Vec<(String, Conform)>,
    pub commands: Vec<(String, Conform)>,
    pub events: Vec<(String, Conform)>,
}
