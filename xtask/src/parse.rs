//! The CSA XML, read into [`model`](crate::model).
//!
//! Tolerant of what the scraper varies and strict about what it does not. Every `expect` here
//! marks a shape the whole 1.6 library is known to hold to — an `id` on a cluster, a `bit` on
//! a feature — and a data model that broke one should stop the build loudly rather than
//! generate something subtly wrong.

use std::collections::BTreeMap;
use std::path::Path;

use roxmltree::{Document, Node};

use crate::model::{
    Access, Attribute, Bitmap, BitmapField, Clause, Cluster, Command, Condition, Conform,
    DataModel, DeviceCluster, DeviceType, EnumItem, Enumeration, Event, Feature, Field, Quality,
    Structure, Verdict,
};

/// Reads a whole data-model directory.
pub fn load(dm: &Path) -> Result<DataModel, String> {
    let version = std::fs::read_to_string(dm.join("spec_tag"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());

    let mut clusters = Vec::new();
    for path in sorted_xml(&dm.join("clusters"))? {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let document = Document::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        // A few files define several clusters at once (the Mode Base derivations), and a
        // couple define none — `types.xsd` neighbours and the like.
        clusters.extend(parse_clusters(document.root_element()));
    }
    // A derived cluster's element set is its base's, narrowed — so the base has to be merged
    // in before anything reads a type.
    resolve_inheritance(&mut clusters);
    clusters.sort_by_key(|c| c.id);

    // `globals/` defines enumerations, bitmaps, structures and typedefs that every cluster
    // may use — `SemanticTagStruct`, `LocationDescriptorStruct`, `Priority`. They belong to no
    // cluster, so they are generated as one: a module named `globals` that the others refer
    // to, which is what the specification means by putting them in a chapter of their own.
    if let Ok(paths) = sorted_xml(&dm.join("globals")) {
        let mut global = Cluster {
            id: GLOBALS_ID,
            name: "Globals".to_owned(),
            revision: 1,
            pics: String::new(),
            base_cluster: None,
            is_base: true,
            features: Vec::new(),
            enums: Vec::new(),
            bitmaps: Vec::new(),
            structs: Vec::new(),
            typedefs: Vec::new(),
            attributes: Vec::new(),
            commands: Vec::new(),
            events: Vec::new(),
        };
        for path in paths {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(document) = Document::parse(&text) else {
                continue;
            };
            let root = document.root_element();
            collect_data_types(root, &mut global);
        }
        if !global.enums.is_empty() || !global.structs.is_empty() || !global.bitmaps.is_empty() {
            clusters.push(global);
        }
    }

    let mut device_types = Vec::new();
    for path in sorted_xml(&dm.join("device_types"))? {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let document = Document::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if let Some(device) = parse_device_type(document.root_element()) {
            device_types.push(device);
        }
    }
    device_types.sort_by_key(|d| d.id);

    Ok(DataModel {
        version,
        clusters,
        device_types,
        unmapped_types: BTreeMap::new(),
    })
}

/// Hands out the synthetic ids the abstract bases are filed under.
///
/// Above every real cluster id — the largest the specification assigns is `0x0802` — so they
/// sort last, cannot collide, and are obvious in a listing.
fn next_base_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0xFFFF_0001);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The synthetic id the `globals` module is filed under.
///
/// Above every real cluster id so it sorts last and cannot collide: the largest the
/// specification assigns is `0x0802`.
pub const GLOBALS_ID: u32 = 0xFFFF_0000;

/// Reads whatever `dataTypes` a document holds into `into`.
///
/// The `globals/` files are shaped like a cluster's `dataTypes` without the cluster, so this
/// is the half of `parse_clusters` that does not need one.
fn collect_data_types(root: Node<'_, '_>, into: &mut Cluster) {
    let containers: Vec<Node<'_, '_>> = match child(root, "dataTypes") {
        Some(types) => vec![types],
        None => vec![root],
    };
    for types in containers {
        for element in children(types, "enum") {
            if let Some(name) = attr(element, "name") {
                into.enums.push(Enumeration {
                    name: name.to_owned(),
                    items: children(element, "item")
                        .filter_map(|item| {
                            Some(EnumItem {
                                value: attr_number(item, "value")?,
                                name: attr(item, "name")?.to_owned(),
                                summary: attr(item, "summary").unwrap_or_default().to_owned(),
                                conform: conform(item),
                            })
                        })
                        .collect(),
                });
            }
        }
        for element in children(types, "bitmap") {
            if let Some(name) = attr(element, "name") {
                into.bitmaps.push(Bitmap {
                    name: name.to_owned(),
                    fields: children(element, "bitfield")
                        .filter_map(|field| {
                            Some(BitmapField {
                                bit: u8::try_from(attr_number(field, "bit")?).ok()?,
                                name: attr(field, "name")?.to_owned(),
                                summary: attr(field, "summary").unwrap_or_default().to_owned(),
                                conform: conform(field),
                            })
                        })
                        .collect(),
                });
            }
        }
        for element in children(types, "struct") {
            if let Some(name) = attr(element, "name") {
                into.structs.push(Structure {
                    name: name.to_owned(),
                    fields: fields(element),
                    fabric_scoped: access(element).fabric_scoped,
                });
            }
        }
        for element in children(types, "number") {
            if let (Some(name), Some(kind)) = (attr(element, "name"), attr(element, "type")) {
                into.typedefs.push((name.to_owned(), kind.to_owned()));
            }
        }
    }
}

fn sorted_xml(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "xml"))
        .collect();
    // Sorted so the generator's output does not depend on the order the filesystem hands
    // entries back, which differs between machines and would make `check` flap.
    paths.sort();
    Ok(paths)
}

// --- Small readers ----------------------------------------------------------------------

/// Reads an attribute value, whichever radix the XML wrote it in.
fn number(text: &str) -> Option<u64> {
    let text = text.trim();
    let text = text.strip_suffix('"').unwrap_or(text);
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn attr<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attribute(name)
}

fn attr_number(node: Node<'_, '_>, name: &str) -> Option<u64> {
    attr(node, name).and_then(number)
}

fn flag(node: Node<'_, '_>, name: &str) -> bool {
    attr(node, name) == Some("true")
}

fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn children<'a, 'i>(node: Node<'a, 'i>, name: &str) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == name)
}

/// The element children of a container, for the containers that hold one kind of thing.
fn items<'a, 'i>(node: Node<'a, 'i>, container: &str, item: &str) -> Vec<Node<'a, 'i>> {
    child(node, container)
        .map(|c| children(c, item).collect())
        .unwrap_or_default()
}

// --- Conformance ------------------------------------------------------------------------

/// The XML tags that introduce a conformance verdict.
fn verdict_of(tag: &str) -> Option<Verdict> {
    match tag {
        "mandatoryConform" => Some(Verdict::Mandatory),
        "optionalConform" => Some(Verdict::Optional),
        "provisionalConform" => Some(Verdict::Provisional),
        "deprecateConform" => Some(Verdict::Deprecated),
        "disallowConform" => Some(Verdict::Disallowed),
        "describedConform" => Some(Verdict::Described),
        _ => None,
    }
}

/// Reads whichever conformance element is a direct child of `node`.
///
/// Elements with none are mandatory: the scraper omits `<mandatoryConform/>` on a few command
/// fields, and the specification's own default for an element it lists is that it is there.
fn conform(node: Node<'_, '_>) -> Conform {
    for element in node.children().filter(Node::is_element) {
        let tag = element.tag_name().name();
        if tag == "otherwiseConform" {
            // A chain: each child is a clause, tried in order.
            let clauses = element
                .children()
                .filter(Node::is_element)
                .filter_map(|branch| {
                    verdict_of(branch.tag_name().name()).map(|verdict| clause(verdict, branch))
                })
                .collect::<Vec<_>>();
            if !clauses.is_empty() {
                return Conform { clauses };
            }
        }
        if let Some(verdict) = verdict_of(tag) {
            return Conform {
                clauses: vec![clause(verdict, element)],
            };
        }
    }
    Conform::mandatory()
}

fn clause(verdict: Verdict, element: Node<'_, '_>) -> Clause {
    let terms: Vec<Condition> = element
        .children()
        .filter(Node::is_element)
        .filter_map(condition)
        .collect();
    let when = match terms.len() {
        0 => Condition::Always,
        1 => terms.into_iter().next().unwrap_or(Condition::Always),
        // Several siblings inside one conform element read as a conjunction. The scraper
        // writes this for an element gated on both a feature and a condition.
        _ => Condition::All(terms),
    };
    // A comparison is about attribute *values* at runtime, which no configuration check can
    // answer, so the whole clause becomes prose rather than being evaluated wrongly.
    let verdict = if contains_comparison(&when) {
        Verdict::Described
    } else {
        verdict
    };
    Clause { verdict, when }
}

fn contains_comparison(condition: &Condition) -> bool {
    match condition {
        Condition::Comparison => true,
        Condition::Not(inner) => contains_comparison(inner),
        Condition::All(terms) | Condition::Any(terms) | Condition::ExactlyOne(terms) => {
            terms.iter().any(contains_comparison)
        }
        _ => false,
    }
}

fn condition(node: Node<'_, '_>) -> Option<Condition> {
    let name = || attr(node, "name").unwrap_or_default().to_owned();
    let terms = || {
        node.children()
            .filter(Node::is_element)
            .filter_map(condition)
            .collect::<Vec<_>>()
    };
    Some(match node.tag_name().name() {
        "feature" => Condition::Feature(name()),
        "attribute" => Condition::Attribute(name()),
        "command" => Condition::Command(name()),
        "event" => Condition::Event(name()),
        "cluster" => Condition::Cluster(name()),
        "field" => Condition::Field(name()),
        "condition" => Condition::Named(name()),
        "notTerm" => Condition::Not(Box::new(
            terms().into_iter().next().unwrap_or(Condition::Always),
        )),
        "andTerm" => Condition::All(terms()),
        "orTerm" => Condition::Any(terms()),
        "xorTerm" => Condition::ExactlyOne(terms()),
        "equalTerm" | "notEqualTerm" | "greaterTerm" | "lessTerm" | "greaterOrEqualTerm"
        | "lessOrEqualTerm" => Condition::Comparison,
        // `<constraint>`, `<access>`, `<quality>` and the rest are not conditions; a
        // conform element can hold them as siblings in some files.
        _ => return None,
    })
}

// --- Access and qualities ----------------------------------------------------------------

fn access(node: Node<'_, '_>) -> Access {
    // §7.12.5's `L` is a *quality*, and it sits on a sibling element — but it constrains the
    // interaction, so it is read here and carried with the rest of the access.
    let large = quality(node).large;
    let Some(element) = child(node, "access") else {
        return Access {
            large,
            ..Access::default()
        };
    };
    Access {
        large,
        read: flag(element, "read"),
        write: flag(element, "write"),
        read_privilege: attr(element, "readPrivilege").map(str::to_owned),
        write_privilege: attr(element, "writePrivilege").map(str::to_owned),
        invoke_privilege: attr(element, "invokePrivilege").map(str::to_owned),
        fabric_scoped: flag(element, "fabricScoped"),
        fabric_sensitive: flag(element, "fabricSensitive"),
        timed: flag(element, "timed"),
    }
}

fn quality(node: Node<'_, '_>) -> Quality {
    let Some(element) = child(node, "quality") else {
        return Quality::default();
    };
    Quality {
        nullable: flag(element, "nullable"),
        persistence: attr(element, "persistence").map(str::to_owned),
        changes_omitted: flag(element, "changeOmitted"),
        quieter: flag(element, "reportable") && flag(element, "quieterReporting")
            || flag(element, "quieterReporting"),
        scene: flag(element, "scene"),
        atomic: flag(element, "atomicWrite"),
        large: flag(element, "largeMessage"),
    }
}

/// A field's or attribute's type, and — for a list — what its entries are.
fn kind(node: Node<'_, '_>) -> (String, Option<String>) {
    let kind = attr(node, "type").unwrap_or("").to_owned();
    let entry = child(node, "entry")
        .and_then(|e| attr(e, "type"))
        .map(str::to_owned);
    (kind, entry)
}

fn fields(node: Node<'_, '_>) -> Vec<Field> {
    children(node, "field")
        .filter_map(|element| {
            let (kind, entry) = kind(element);
            // A field with no type is one of two very different things: withdrawn — ICD
            // Management's `Key` is `<field id="3" name="Key"><deprecateConform/></field>`,
            // with nothing to say what it ever was — or a *derived* cluster narrowing its
            // base's field, where the type comes from the base. `resolve_inheritance` fills
            // the second in, so only what is still typeless afterwards is really gone.
            let conform = conform(element);
            if kind.is_empty()
                && conform.clauses.iter().all(|clause| {
                    matches!(clause.verdict, Verdict::Deprecated | Verdict::Disallowed)
                })
            {
                return None;
            }
            Some(Field {
                id: u8::try_from(attr_number(element, "id")?).ok()?,
                name: attr(element, "name")?.to_owned(),
                kind,
                entry,
                nullable: quality(element).nullable,
                conform,
            })
        })
        .collect()
}

// --- Clusters ----------------------------------------------------------------------------

fn parse_clusters(root: Node<'_, '_>) -> Vec<Cluster> {
    if root.tag_name().name() != "cluster" {
        return Vec::new();
    }
    let revision = attr_number(root, "revision").unwrap_or(1) as u16;
    let classification = child(root, "classification");
    let pics = classification
        .and_then(|c| attr(c, "picsCode"))
        .unwrap_or("")
        .to_owned();
    let base_cluster = classification
        .and_then(|c| attr(c, "baseCluster"))
        .map(str::to_owned);

    let features: Vec<Feature> = items(root, "features", "feature")
        .into_iter()
        .filter_map(|element| {
            Some(Feature {
                bit: u8::try_from(attr_number(element, "bit")?).ok()?,
                code: attr(element, "code").unwrap_or_default().to_owned(),
                name: attr(element, "name")?.to_owned(),
                summary: attr(element, "summary").unwrap_or_default().to_owned(),
                conform: conform(element),
            })
        })
        .collect();

    let data_types = child(root, "dataTypes");
    let enums: Vec<Enumeration> = data_types
        .map(|types| {
            children(types, "enum")
                .filter_map(|element| {
                    Some(Enumeration {
                        name: attr(element, "name")?.to_owned(),
                        items: children(element, "item")
                            .filter_map(|item| {
                                Some(EnumItem {
                                    value: attr_number(item, "value")?,
                                    name: attr(item, "name")?.to_owned(),
                                    summary: attr(item, "summary").unwrap_or_default().to_owned(),
                                    conform: conform(item),
                                })
                            })
                            .collect(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let bitmaps: Vec<Bitmap> = data_types
        .map(|types| {
            children(types, "bitmap")
                .filter_map(|element| {
                    Some(Bitmap {
                        name: attr(element, "name")?.to_owned(),
                        fields: children(element, "bitfield")
                            .filter_map(|field| {
                                Some(BitmapField {
                                    bit: u8::try_from(attr_number(field, "bit")?).ok()?,
                                    name: attr(field, "name")?.to_owned(),
                                    summary: attr(field, "summary").unwrap_or_default().to_owned(),
                                    conform: conform(field),
                                })
                            })
                            .collect(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let structs: Vec<Structure> = data_types
        .map(|types| {
            children(types, "struct")
                .filter_map(|element| {
                    Some(Structure {
                        name: attr(element, "name")?.to_owned(),
                        fields: fields(element),
                        fabric_scoped: access(element).fabric_scoped,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // `<number name= type=>` — an alias for a base type under a more readable name.
    let typedefs: Vec<(String, String)> = data_types
        .map(|types| {
            children(types, "number")
                .filter_map(|element| {
                    Some((
                        attr(element, "name")?.to_owned(),
                        attr(element, "type")?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let attributes: Vec<Attribute> = items(root, "attributes", "attribute")
        .into_iter()
        .filter_map(|element| {
            let (kind, entry) = kind(element);
            Some(Attribute {
                id: u32::try_from(attr_number(element, "id")?).ok()?,
                name: attr(element, "name")?.to_owned(),
                kind,
                entry,
                summary: attr(element, "summary").unwrap_or_default().to_owned(),
                access: access(element),
                quality: quality(element),
                conform: conform(element),
            })
        })
        .collect();

    let commands: Vec<Command> = items(root, "commands", "command")
        .into_iter()
        .filter_map(|element| {
            Some(Command {
                id: u32::try_from(attr_number(element, "id")?).ok()?,
                name: attr(element, "name")?.to_owned(),
                direction: attr(element, "direction").unwrap_or_default().to_owned(),
                response: attr(element, "response").unwrap_or_default().to_owned(),
                summary: attr(element, "summary").unwrap_or_default().to_owned(),
                access: access(element),
                conform: conform(element),
                fields: fields(element),
            })
        })
        .collect();

    let events: Vec<Event> = items(root, "events", "event")
        .into_iter()
        .filter_map(|element| {
            Some(Event {
                id: u32::try_from(attr_number(element, "id")?).ok()?,
                name: attr(element, "name")?.to_owned(),
                priority: attr(element, "priority").unwrap_or("info").to_owned(),
                summary: attr(element, "summary").unwrap_or_default().to_owned(),
                access: access(element),
                conform: conform(element),
                fields: fields(element),
            })
        })
        .collect();

    // One file can define several cluster ids over one element set — the Mode Base family and
    // the concentration-measurement clusters are written that way, and each id is a real
    // cluster a device serves. Cloning the element set is what "derived" means.
    let mut ids: Vec<(u32, String)> = child(root, "clusterIds")
        .map(|list| {
            children(list, "clusterId")
                .filter_map(|element| {
                    let id = u32::try_from(attr_number(element, "id")?).ok()?;
                    Some((id, attr(element, "name").unwrap_or_default().to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();

    // An **abstract base**: `<clusterId name="Mode Base"/>` with no id. Alarm Base, Label and
    // Mode Base are written this way, and the clusters derived from them reference their
    // structures by name — so a generator that skipped a file with no id would drop
    // `ModeTagStruct`, and with it every Mode cluster's `ModeOptions` attribute.
    let is_base = ids.is_empty();
    if is_base {
        let name = attr(root, "name").unwrap_or("Base").to_owned();
        ids.push((next_base_id(), name));
    }

    ids.into_iter()
        .map(|(id, name)| Cluster {
            id,
            is_base,
            name: clean_name(&name),
            revision,
            pics: pics.clone(),
            base_cluster: base_cluster.clone(),
            features: features
                .iter()
                .map(|f| Feature {
                    bit: f.bit,
                    code: f.code.clone(),
                    name: f.name.clone(),
                    summary: f.summary.clone(),
                    conform: f.conform.clone(),
                })
                .collect(),
            enums: clone_enums(&enums),
            bitmaps: clone_bitmaps(&bitmaps),
            structs: clone_structs(&structs),
            typedefs: typedefs.clone(),
            attributes: clone_attributes(&attributes),
            commands: clone_commands(&commands),
            events: clone_events(&events),
        })
        .collect()
}

/// "On/Off Cluster" → "On/Off". The suffix is noise in a module name.
fn clean_name(name: &str) -> String {
    name.trim()
        .strip_suffix(" Cluster")
        .unwrap_or(name.trim())
        .to_owned()
}

fn clone_enums(source: &[Enumeration]) -> Vec<Enumeration> {
    source
        .iter()
        .map(|e| Enumeration {
            name: e.name.clone(),
            items: e
                .items
                .iter()
                .map(|i| EnumItem {
                    value: i.value,
                    name: i.name.clone(),
                    summary: i.summary.clone(),
                    conform: i.conform.clone(),
                })
                .collect(),
        })
        .collect()
}

fn clone_bitmaps(source: &[Bitmap]) -> Vec<Bitmap> {
    source
        .iter()
        .map(|b| Bitmap {
            name: b.name.clone(),
            fields: b
                .fields
                .iter()
                .map(|f| BitmapField {
                    bit: f.bit,
                    name: f.name.clone(),
                    summary: f.summary.clone(),
                    conform: f.conform.clone(),
                })
                .collect(),
        })
        .collect()
}

fn clone_fields(source: &[Field]) -> Vec<Field> {
    source
        .iter()
        .map(|f| Field {
            id: f.id,
            name: f.name.clone(),
            kind: f.kind.clone(),
            entry: f.entry.clone(),
            nullable: f.nullable,
            conform: f.conform.clone(),
        })
        .collect()
}

fn clone_structs(source: &[Structure]) -> Vec<Structure> {
    source
        .iter()
        .map(|s| Structure {
            name: s.name.clone(),
            fields: clone_fields(&s.fields),
            fabric_scoped: s.fabric_scoped,
        })
        .collect()
}

fn clone_attributes(source: &[Attribute]) -> Vec<Attribute> {
    source
        .iter()
        .map(|a| Attribute {
            id: a.id,
            name: a.name.clone(),
            kind: a.kind.clone(),
            entry: a.entry.clone(),
            summary: a.summary.clone(),
            access: a.access.clone(),
            quality: a.quality.clone(),
            conform: a.conform.clone(),
        })
        .collect()
}

fn clone_commands(source: &[Command]) -> Vec<Command> {
    source
        .iter()
        .map(|c| Command {
            id: c.id,
            name: c.name.clone(),
            direction: c.direction.clone(),
            response: c.response.clone(),
            summary: c.summary.clone(),
            access: c.access.clone(),
            conform: c.conform.clone(),
            fields: clone_fields(&c.fields),
        })
        .collect()
}

fn clone_events(source: &[Event]) -> Vec<Event> {
    source
        .iter()
        .map(|e| Event {
            id: e.id,
            name: e.name.clone(),
            priority: e.priority.clone(),
            summary: e.summary.clone(),
            access: e.access.clone(),
            conform: e.conform.clone(),
            fields: clone_fields(&e.fields),
        })
        .collect()
}

// --- Device types -------------------------------------------------------------------------

fn parse_device_type(root: Node<'_, '_>) -> Option<DeviceType> {
    if root.tag_name().name() != "deviceType" {
        return None;
    }
    let classification = child(root, "classification");
    // The revision is the highest in the history, the same rule `ClusterRevision` follows.
    let revision = child(root, "revisionHistory")
        .map(|history| {
            children(history, "revision")
                .filter_map(|r| attr_number(r, "revision"))
                .max()
                .unwrap_or(1)
        })
        .unwrap_or(1) as u16;

    let clusters = items(root, "clusters", "cluster")
        .into_iter()
        .filter_map(|element| {
            let named = |container: &str, item: &str| -> Vec<(String, Conform)> {
                items(element, container, item)
                    .into_iter()
                    .filter_map(|e| {
                        Some((
                            attr(e, "name").or_else(|| attr(e, "code"))?.to_owned(),
                            conform(e),
                        ))
                    })
                    .collect()
            };
            Some(DeviceCluster {
                id: u32::try_from(attr_number(element, "id")?).ok()?,
                name: clean_name(attr(element, "name").unwrap_or_default()),
                side: attr(element, "side").unwrap_or("server").to_owned(),
                conform: conform(element),
                features: named("features", "feature"),
                attributes: named("attributes", "attribute"),
                commands: named("commands", "command"),
                events: named("events", "event"),
            })
        })
        .collect();

    Some(DeviceType {
        id: u32::try_from(attr_number(root, "id")?).ok()?,
        name: clean_name(attr(root, "name")?),
        revision,
        class: classification
            .and_then(|c| attr(c, "class"))
            .unwrap_or_default()
            .to_owned(),
        scope: classification
            .and_then(|c| attr(c, "scope"))
            .unwrap_or_default()
            .to_owned(),
        clusters,
    })
}

// --- Derived clusters ---------------------------------------------------------------------

/// Fills in what a derived cluster inherits from its base.
///
/// §7.3's "derived" hierarchy: Mode Base has one element set and fourteen Mode clusters narrow
/// it. A derived file lists the elements again — with their conformance and constraints, which
/// it *does* change — but leaves out the types, because those come from the base:
///
/// ```xml
/// <struct name="ModeOptionStruct">
///   <field id="0" name="Label"><mandatoryConform/></field>
/// </struct>
/// ```
///
/// A generator that took that at face value produces a structure with a field of no type, or
/// drops the field, or — worst — produces an empty structure that encodes nothing and looks
/// like it worked. So the base is merged in first: anything the derived cluster does not say
/// is whatever the base said.
pub fn resolve_inheritance(clusters: &mut [Cluster]) {
    // By name, because `baseCluster="Mode Base"` names it rather than pointing at an id — an
    // abstract base has no id to point at.
    let bases: std::collections::BTreeMap<String, usize> = clusters
        .iter()
        .enumerate()
        .filter(|(_, c)| c.is_base)
        .map(|(index, c)| (c.name.clone(), index))
        .collect();

    for index in 0..clusters.len() {
        let Some(base_name) = clusters[index].base_cluster.clone() else {
            continue;
        };
        let Some(&base_index) = bases
            .get(base_name.trim())
            .or_else(|| bases.get(base_name.trim_end_matches(" Cluster")))
        else {
            continue;
        };
        if base_index == index {
            continue;
        }
        let base = clone_cluster(&clusters[base_index]);
        inherit(&mut clusters[index], &base);
    }
}

fn inherit(derived: &mut Cluster, base: &Cluster) {
    // Types the derived cluster does not mention at all come across whole — `ModeTagStruct`
    // is defined once, in Mode Base, and every Mode cluster's `ModeOptions` needs it.
    for structure in &base.structs {
        match derived
            .structs
            .iter_mut()
            .find(|s| s.name == structure.name)
        {
            Some(existing) => inherit_fields(&mut existing.fields, &structure.fields),
            None => derived.structs.push(Structure {
                name: structure.name.clone(),
                fields: clone_fields(&structure.fields),
                fabric_scoped: structure.fabric_scoped,
            }),
        }
    }
    for enumeration in &base.enums {
        if !derived.enums.iter().any(|e| e.name == enumeration.name) {
            derived
                .enums
                .push(clone_enums(core::slice::from_ref(enumeration)).remove(0));
        }
    }
    for bitmap in &base.bitmaps {
        if !derived.bitmaps.iter().any(|b| b.name == bitmap.name) {
            derived
                .bitmaps
                .push(clone_bitmaps(core::slice::from_ref(bitmap)).remove(0));
        }
    }
    for (name, kind) in &base.typedefs {
        if !derived.typedefs.iter().any(|(n, _)| n == name) {
            derived.typedefs.push((name.clone(), kind.clone()));
        }
    }
    if derived.features.is_empty() {
        derived.features = base
            .features
            .iter()
            .map(|f| Feature {
                bit: f.bit,
                code: f.code.clone(),
                name: f.name.clone(),
                summary: f.summary.clone(),
                conform: f.conform.clone(),
            })
            .collect();
    }

    for attribute in &base.attributes {
        match derived.attributes.iter_mut().find(|a| a.id == attribute.id) {
            Some(existing) => {
                if existing.kind.is_empty() {
                    existing.kind = attribute.kind.clone();
                    existing.entry = attribute.entry.clone();
                }
            }
            None => derived
                .attributes
                .push(clone_attributes(core::slice::from_ref(attribute)).remove(0)),
        }
    }
    for command in &base.commands {
        match derived.commands.iter_mut().find(|c| c.id == command.id) {
            Some(existing) => inherit_fields(&mut existing.fields, &command.fields),
            None => derived
                .commands
                .push(clone_commands(core::slice::from_ref(command)).remove(0)),
        }
    }
    for event in &base.events {
        if !derived.events.iter().any(|e| e.id == event.id) {
            derived
                .events
                .push(clone_events(core::slice::from_ref(event)).remove(0));
        }
    }
    derived.attributes.sort_by_key(|a| a.id);
    derived.commands.sort_by_key(|c| c.id);
    derived.events.sort_by_key(|e| e.id);
}

/// Gives a field its base's type when the derived cluster stated none.
fn inherit_fields(derived: &mut Vec<Field>, base: &[Field]) {
    for field in base {
        match derived.iter_mut().find(|f| f.id == field.id) {
            Some(existing) => {
                if existing.kind.is_empty() {
                    existing.kind = field.kind.clone();
                    existing.entry = field.entry.clone();
                }
            }
            None => derived.push(Field {
                id: field.id,
                name: field.name.clone(),
                kind: field.kind.clone(),
                entry: field.entry.clone(),
                nullable: field.nullable,
                conform: field.conform.clone(),
            }),
        }
    }
    derived.sort_by_key(|f| f.id);
}

fn clone_cluster(cluster: &Cluster) -> Cluster {
    Cluster {
        id: cluster.id,
        name: cluster.name.clone(),
        revision: cluster.revision,
        pics: cluster.pics.clone(),
        base_cluster: cluster.base_cluster.clone(),
        is_base: cluster.is_base,
        features: cluster
            .features
            .iter()
            .map(|f| Feature {
                bit: f.bit,
                code: f.code.clone(),
                name: f.name.clone(),
                summary: f.summary.clone(),
                conform: f.conform.clone(),
            })
            .collect(),
        enums: clone_enums(&cluster.enums),
        bitmaps: clone_bitmaps(&cluster.bitmaps),
        structs: clone_structs(&cluster.structs),
        typedefs: cluster.typedefs.clone(),
        attributes: clone_attributes(&cluster.attributes),
        commands: clone_commands(&cluster.commands),
        events: clone_events(&cluster.events),
    }
}
