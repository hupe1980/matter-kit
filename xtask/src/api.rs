//! Which public functions nothing calls.
//!
//! A `pub fn` with no caller is not tidiness. Three of this crate's defects were exactly that
//! and nothing else: `NetworkCommissioning::on_commissioning_complete`, which commits the
//! network list §11.10.7.6 makes permanent; `SessionTable::least_recently_used`, the eviction
//! candidate §4.11.1.1 names; and `ExchangeTable::close_session`, which §4.13.3.1 owes when a
//! session goes. Each was written, documented, tested in isolation, and joined to nothing — so
//! the rule it implements was not implemented at all, and every test passed.
//!
//! **An example is not a caller.** `examples/` is counted with the tests, deliberately: an
//! example *is* the application, and a rule the application has to remember is a rule the
//! library does not keep. That is the whole of R18 and of every defect below.
//!
//! The check is crude on purpose. It does not resolve paths, types or trait dispatch: it counts
//! the name, anywhere, as a call. That direction of error is the safe one — a name that appears
//! nowhere really is called by nothing — and it keeps the tool to one file with no dependencies.
//!
//! ```text
//! cargo xtask api              # list what nothing calls, and what only tests call
//! cargo xtask api --strict     # …and fail if anything is called by nothing at all
//! ```
//!
//! Generated sources are skipped as definitions and counted as callers: `src/clusters/generated`
//! is a table of what the specification defines rather than of what this crate uses, and half of
//! it is legitimately unused by any one device.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One public function, and where it was defined.
struct Definition {
    name: String,
    file: PathBuf,
    line: usize,
}

/// What the sweep found.
pub struct Report {
    /// Called by nothing anywhere — neither the crate, nor tests, examples or fuzz targets.
    pub uncalled: Vec<String>,
    /// Called from tests, examples, fuzz targets or `interop/` — but from nothing in `src/`.
    ///
    /// The bucket that matters most, and the one whose name used to hide it. An *example* is
    /// not a caller: it is the application, and "the application remembers to do it" is exactly
    /// the shape of every defect this sweep has found. `SubscriptionTable::remove_for_fabric` is
    /// documented as "what `RemoveFabric` cascades into" and is called by `examples/light` —
    /// which means a node built by anybody else drops a removed fabric's clusters and keeps its
    /// subscriptions.
    pub tests_only: Vec<String>,
    /// How many public functions were examined.
    pub total: usize,
}

/// Everything under `root` that ships, as (path, contents).
fn sources(root: &Path, dir: &str) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    let mut stack = vec![root.join(dir)];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                found.push((path, text));
            }
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Splits a file at its first `#[cfg(test)]`, which is where its test module starts.
///
/// Everything before it ships; everything after it is the file's own tests, and a call from
/// there is evidence about coverage rather than about use.
fn split_tests(text: &str) -> (&str, &str) {
    match text.find("#[cfg(test)]") {
        Some(i) => text.split_at(i),
        None => (text, ""),
    }
}

/// The identifier that follows `pub fn`, if this line declares one.
fn declared_name(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("pub ")?;
    let rest = rest.strip_prefix("const ").unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let end = rest.find(['(', '<', ' '])?;
    let name = rest.get(..end)?;
    let first = name.chars().next()?;
    (first.is_ascii_lowercase() || first == '_').then_some(name)
}

/// Counts every `name(` and `name::<` in a chunk of source, ignoring the lines given.
fn count_calls(
    text: &str,
    skip: &BTreeSet<usize>,
    first_line: usize,
    into: &mut BTreeMap<String, usize>,
) {
    for (offset, line) in text.lines().enumerate() {
        if skip.contains(&(first_line + offset)) {
            continue;
        }
        let bytes = line.as_bytes();
        let mut start = None;
        for (i, &b) in bytes.iter().enumerate() {
            let is_ident = b.is_ascii_alphanumeric() || b == b'_';
            if is_ident && start.is_none() {
                start = Some(i);
            } else if !is_ident && let Some(from) = start.take() {
                let Some(name) = line.get(from..i) else {
                    continue;
                };
                let follows = line.get(i..).unwrap_or("");
                if follows.starts_with('(') || follows.starts_with("::<") {
                    *into.entry(name.to_owned()).or_default() += 1;
                }
            }
        }
    }
}

/// Sweeps the crate.
pub fn sweep(root: &Path) -> Report {
    let lib = sources(root, "src");
    let mut definitions: Vec<Definition> = Vec::new();
    let mut def_lines: BTreeMap<PathBuf, BTreeSet<usize>> = BTreeMap::new();

    for (path, text) in &lib {
        if path.to_string_lossy().contains("clusters/generated") {
            continue;
        }
        let (ships, _) = split_tests(text);
        for (i, line) in ships.lines().enumerate() {
            if let Some(name) = declared_name(line) {
                definitions.push(Definition {
                    name: name.to_owned(),
                    file: path.clone(),
                    line: i + 1,
                });
                def_lines.entry(path.clone()).or_default().insert(i + 1);
            }
        }
    }

    let mut shipping_calls: BTreeMap<String, usize> = BTreeMap::new();
    let mut test_calls: BTreeMap<String, usize> = BTreeMap::new();

    for (path, text) in &lib {
        let (ships, tests) = split_tests(text);
        let skip = def_lines.get(path).cloned().unwrap_or_default();
        count_calls(ships, &skip, 1, &mut shipping_calls);
        count_calls(tests, &BTreeSet::new(), 1, &mut test_calls);
    }
    for dir in [
        "tests",
        "examples",
        "fuzz/fuzz_targets",
        "interop/src",
        "interop/tests",
    ] {
        for (_, text) in sources(root, dir) {
            count_calls(&text, &BTreeSet::new(), 1, &mut test_calls);
        }
    }

    let mut uncalled = Vec::new();
    let mut tests_only = Vec::new();
    let total = definitions.len();
    for definition in definitions {
        let shipped = shipping_calls.get(&definition.name).copied().unwrap_or(0);
        let tested = test_calls.get(&definition.name).copied().unwrap_or(0);
        let where_ = format!(
            "{:38} {}:{}",
            definition.name,
            definition.file.display(),
            definition.line
        );
        if shipped == 0 && tested == 0 {
            uncalled.push(where_);
        } else if shipped == 0 {
            tests_only.push(where_);
        }
    }
    uncalled.sort();
    uncalled.dedup();
    tests_only.sort();
    tests_only.dedup();
    Report {
        uncalled,
        tests_only,
        total,
    }
}

/// Prints the sweep, and says whether `--strict` should fail on it.
pub fn print(report: &Report) {
    println!(
        "xtask: {} public functions in src/ (generated sources excluded)",
        report.total
    );
    println!("\n{} called by nothing anywhere:", report.uncalled.len());
    for line in &report.uncalled {
        println!("  {line}");
    }
    println!(
        "\n{} called from tests or examples but from nothing in src/:",
        report.tests_only.len()
    );
    for line in &report.tests_only {
        println!("  {line}");
    }
    println!(
        "\nA public function with no caller is a rule with no caller until proven otherwise: \
         wire it up, cover it with a test, or delete it."
    );
}
