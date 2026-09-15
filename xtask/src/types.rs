//! The specification's type names, mapped to Rust.
//!
//! Three kinds of name appear in a `type=` attribute, and they resolve in this order:
//!
//! 1. a **base type** — `uint16`, `octstr`, `epoch-s`, `node-id` — of which the 1.6 library
//!    uses 47, listed below;
//! 2. a **typedef** — `<number name="VideoStreamID" type="uint16"/>`, twelve of them, which
//!    are aliases and resolve to their base;
//! 3. a **named type** — an enumeration, bitmap or structure, defined in the cluster itself,
//!    in `globals/`, or occasionally in *another* cluster.
//!
//! The third case is the one that needs care. `LabelStruct` belongs to the Label cluster and
//! is used by Bridged Device Basic Information; `SignedTemperature` to the Thermostat and used
//! by Temperature Control. A generator that gave up there would drop the field, and a dropped
//! field is the one failure mode a generator must never have — so a cross-cluster reference
//! becomes a path into the other generated module.

use std::collections::BTreeMap;

use crate::ident;
use crate::model::{Cluster, DataModel};

/// What a field's type resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// A Rust primitive or newtype: `u16`, `crate::msg::NodeId`.
    Scalar(String),
    /// A borrowed value: `&'a str`, `&'a [u8]`.
    Borrowed(String),
    /// A generated enumeration or bitmap, by path.
    Named(String),
    /// A generated structure, by path. Carries a lifetime if it borrows.
    Struct { path: String, borrows: bool },
    /// `list[T]`.
    List(Box<Resolved>),
    /// Nothing here knows what this is.
    Unknown(String),
}

impl Resolved {
    /// How the type is written in a struct field.
    pub fn rust(&self) -> String {
        match self {
            Self::Scalar(name) | Self::Named(name) => name.clone(),
            Self::Borrowed(name) => name.clone(),
            Self::Struct { path, borrows } => {
                if *borrows {
                    format!("{path}<'a>")
                } else {
                    path.clone()
                }
            }
            Self::List(entry) => format!("TlvList<'a, {}>", entry.rust()),
            Self::Unknown(name) => format!("/* {name} */ ()"),
        }
    }

    /// Whether the type borrows from the buffer it was decoded from.
    pub fn borrows(&self) -> bool {
        match self {
            Self::Borrowed(_) | Self::List(_) => true,
            Self::Struct { borrows, .. } => *borrows,
            _ => false,
        }
    }

    /// Whether it resolved at all.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

/// The base types, and what each is in Rust.
///
/// Every entry is a decision. The semantic ones — `node-id`, `group-id`, `vendor-id`,
/// `fabric-idx` — map to the crate's newtypes rather than to integers, because they are all
/// integers on the wire and the compiler is the only thing that will notice two of them
/// swapped. The time ones keep the specification's width: `epoch-s` is a `uint32` and will
/// overflow in 2106, which is the specification's problem to have, not this crate's to
/// silently fix by widening.
fn base(name: &str) -> Option<Resolved> {
    use Resolved::{Borrowed, Scalar};
    let scalar = |s: &str| Some(Scalar(s.to_owned()));
    Some(match name {
        "bool" => Scalar("bool".to_owned()),

        "uint8" | "map8" | "enum8" | "percent" | "priority" | "status" | "tag" | "namespace"
        | "action-id" | "fabric-idx"
            if name == "fabric-idx" =>
        {
            Scalar("crate::msg::FabricIndex".to_owned())
        }
        "uint8" | "map8" | "enum8" | "percent" | "priority" | "status" | "tag" | "namespace"
        | "action-id" => Scalar("u8".to_owned()),
        "uint16" | "map16" | "enum16" | "percent100ths" | "endpoint-no" | "endpoint-id"
        | "entry-idx" | "message-id" => Scalar("u16".to_owned()),
        "uint24" | "uint32" | "map32" | "epoch-s" | "elapsed-s" | "cluster-id" | "attrib-id"
        | "attribute-id" | "command-id" | "event-id" | "devtype-id" | "trans-id" | "data-ver"
        | "field-id" => Scalar("u32".to_owned()),
        "uint40" | "uint48" | "uint56" | "uint64" | "map64" | "epoch-us" | "posix-ms"
        | "systime-us" | "systime-ms" | "systemtime-us" | "fabric-id" | "subject-id"
        | "event-no" => Scalar("u64".to_owned()),

        "int8" => Scalar("i8".to_owned()),
        "int16" | "int16s" | "temperature" => Scalar("i16".to_owned()),
        "int24" | "int32" | "power-mW" | "amperage-mA" | "voltage-mV" | "power-mVA"
        | "power-mVAR" => Scalar("i32".to_owned()),
        "int40" | "int48" | "int56" | "int64" | "energy-mWh" | "energy-mVAh" | "energy-mVARh"
        | "money" => Scalar("i64".to_owned()),

        "single" => Scalar("f32".to_owned()),
        "double" => Scalar("f64".to_owned()),

        "string" => Borrowed("&'a str".to_owned()),
        // Addresses are octet strings with a fixed length the constraint states; keeping them
        // as slices rather than arrays means a malformed one is a constraint error where the
        // cluster can answer for it, not a decode error two layers down.
        "octstr" | "ipadr" | "ipv4adr" | "ipv6adr" | "ipv6pre" | "hwadr" => {
            Borrowed("&'a [u8]".to_owned())
        }

        "node-id" => return scalar("crate::msg::NodeId"),
        "group-id" => return scalar("crate::msg::GroupId"),
        "vendor-id" => return scalar("crate::msg::VendorId"),
        _ => return None,
    })
}

/// Everything the generator needs to resolve a name.
///
/// Keyed by **module and name**, not by name. Fourteen clusters define a `ModeOptionStruct`
/// and they are not the same structure: Mode Base's has three fields and Device Energy
/// Management Mode's has none, so one borrows and the other cannot. A single map would give
/// both the same answer and produce a lifetime parameter nothing uses, or a missing one that
/// something does.
pub struct Types {
    /// `<number name= type=>` aliases, from every cluster and from `globals/`. These really
    /// are global — each name is defined once in the whole library.
    typedefs: BTreeMap<String, String>,
    /// Where a name is defined, for a cluster that references one it does not define:
    /// name → module. `globals` wins when it defines the name too, because that is what a
    /// cluster referring to an unqualified name means.
    elsewhere: BTreeMap<String, String>,
    /// Which `(module, name)` pairs are structures rather than enumerations or bitmaps.
    structs: BTreeMap<(String, String), bool>,
    /// Whether a structure borrows, per `(module, name)`.
    borrows: BTreeMap<(String, String), bool>,
    /// Which module each cluster's types live in, by cluster id.
    module_of: BTreeMap<u32, String>,
}

impl Types {
    /// Indexes every named type in the model.
    pub fn index(model: &DataModel, module_of: &BTreeMap<u32, String>) -> Self {
        let mut typedefs = BTreeMap::new();
        let mut elsewhere: BTreeMap<String, String> = BTreeMap::new();
        let mut structs = BTreeMap::new();
        for cluster in &model.clusters {
            let module = module_of
                .get(&cluster.id)
                .cloned()
                .unwrap_or_else(|| ident::snake(&cluster.name));
            for (name, kind) in &cluster.typedefs {
                typedefs.insert(name.clone(), kind.clone());
            }
            let mut register = |name: &String, is_struct: bool| {
                // `globals` wins: an unqualified name in a cluster that does not define it
                // means the shared one, and anything else is an accident of file order.
                match elsewhere.get(name) {
                    Some(existing) if existing == "globals" => {}
                    _ => {
                        elsewhere.insert(name.clone(), module.clone());
                    }
                }
                structs.insert((module.clone(), name.clone()), is_struct);
            };
            for enumeration in &cluster.enums {
                register(&enumeration.name, false);
            }
            for bitmap in &cluster.bitmaps {
                register(&bitmap.name, false);
            }
            for structure in &cluster.structs {
                register(&structure.name, true);
            }
        }

        let mut this = Self {
            typedefs,
            elsewhere,
            structs,
            borrows: BTreeMap::new(),
            module_of: module_of.clone(),
        };
        this.compute_borrows(model);
        this
    }

    /// Which module a cluster's own types live in.
    fn module(&self, cluster: &Cluster) -> String {
        self.module_of
            .get(&cluster.id)
            .cloned()
            .unwrap_or_else(|| ident::snake(&cluster.name))
    }

    /// Works out which structures borrow, to a fixed point.
    ///
    /// A structure borrows if any field is a string, an octet string, a list, or another
    /// structure that borrows — so the answer for one depends on the answer for another, and
    /// a single pass would get a nested case wrong in whichever direction it happened to
    /// visit first.
    fn compute_borrows(&mut self, model: &DataModel) {
        for _ in 0..8 {
            let mut changed = false;
            for cluster in &model.clusters {
                let module = self.module(cluster);
                for structure in &cluster.structs {
                    let borrows = structure.fields.iter().any(|field| {
                        self.resolve(&field.kind, field.entry.as_deref(), cluster)
                            .borrows()
                    });
                    let key = (module.clone(), structure.name.clone());
                    if self.borrows.get(&key) != Some(&borrows) {
                        self.borrows.insert(key, borrows);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Resolves one `type=` (and, for a list, its `<entry type=>`).
    pub fn resolve(&self, kind: &str, entry: Option<&str>, cluster: &Cluster) -> Resolved {
        if kind == "list" {
            let Some(entry) = entry else {
                // A list whose entry type the scraper did not record. Nothing can be made of
                // it, and guessing `u8` would produce a struct that decodes garbage.
                return Resolved::Unknown("list[?]".to_owned());
            };
            return Resolved::List(Box::new(self.resolve(entry, None, cluster)));
        }
        if let Some(resolved) = base(kind) {
            return resolved;
        }
        if let Some(alias) = self.typedefs.get(kind) {
            return self.resolve(alias, None, cluster);
        }

        // The cluster's own types win: fourteen clusters define a `ModeOptionStruct` and they
        // are not the same structure, so the local one is what this file's fields mean.
        let local = self.module(cluster);
        let defined_here = cluster.enums.iter().any(|e| e.name == kind)
            || cluster.bitmaps.iter().any(|b| b.name == kind)
            || cluster.structs.iter().any(|s| s.name == kind);
        let owner = if defined_here {
            local.clone()
        } else {
            match self.elsewhere.get(kind) {
                Some(module) => module.clone(),
                None => return Resolved::Unknown(kind.to_owned()),
            }
        };

        let type_name = ident::pascal(kind);
        let path = if owner == local {
            type_name
        } else {
            format!("crate::clusters::generated::{owner}::{type_name}")
        };
        let key = (owner, kind.to_owned());
        match self.structs.get(&key) {
            Some(true) => Resolved::Struct {
                path,
                borrows: self.borrows.get(&key).copied().unwrap_or(false),
            },
            Some(false) => Resolved::Named(path),
            None => Resolved::Unknown(kind.to_owned()),
        }
    }

    /// Whether a structure defined by `cluster` borrows.
    pub fn struct_borrows(&self, cluster: &Cluster, name: &str) -> bool {
        self.borrows
            .get(&(self.module(cluster), name.to_owned()))
            .copied()
            .unwrap_or(false)
    }
}
