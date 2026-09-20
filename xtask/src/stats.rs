//! Every measurement these documents make, produced rather than typed.
//!
//! This repository states about thirty numbers about itself — tests, public functions, fuzz
//! targets, clusters, device types, citations, flash, RAM — across `README.md`, `SECURITY.md`,
//! `site/content` and the architecture notes, each written by hand into two or three files. A
//! number no reader can reproduce is a number no reader checks, so the error rate is bounded
//! only by how often somebody happens to re-run the command; and the ones that matter are the
//! stable ones nobody re-runs.
//!
//! So the numbers are emitted, the documents carry a `<!-- stats:key -->` marker, and `--check`
//! fails when a document disagrees with the repository. It is the rule `cargo xtask check`
//! already applies to the cluster library, pointed at the prose.
//!
//! ```text
//! cargo xtask stats            # print the table
//! cargo xtask stats --write    # refresh every marker in place
//! cargo xtask stats --check    # fail if any is stale (the CI gate)
//! ```
//!
//! # What is counted, and what is not
//!
//! Counted: whatever a command can answer on a developer's machine without a network, a
//! container or a nightly toolchain. Left as prose: anything needing the CHIP container —
//! Harness cases, interop defects — because a figure that takes a twenty-minute run to produce
//! would read as stale on every machine that has not done one.
//!
//! The test count is prose for a related reason. `cargo test --all-features` is the figure the
//! documents quote, and producing it means compiling and running the suite, which `--check` must
//! not do inside a CI job that has already done it. Counting `#[test]` attributes statically
//! would be cheap and would answer a different question — it misses doctests and everything a
//! `cfg` turns off — so the number would be precise, checkable, and not the one anybody means.
//!
//! The footprint and the citation sweep are the middle case: too slow or too dependent on what
//! a machine has to run here, but still exact. `footprint/run.sh` and `cargo xtask cite` each
//! write their numbers down; this reads them, and reports a figure as unmeasured where it is
//! absent rather than guessing.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// One measurement: the key a document refers to it by, and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// The key, as it appears in a `<!-- stats:key -->` marker.
    pub key: String,
    /// The value, already formatted the way a document should print it, or `None` where this
    /// machine cannot measure it.
    ///
    /// `None` is not an error and not a zero. A checkout that has never linked a firmware image
    /// has nothing to say about the footprint, and a document that states one is not thereby
    /// wrong — so an unmeasured statistic leaves its marker exactly as it found it. The
    /// alternative is a CI job without a cross toolchain quietly rewriting the README's
    /// headline number to "unmeasured", which is the failure this whole tool exists to stop,
    /// committed by the tool itself.
    pub value: Option<String>,
    /// What it means, for the printed table.
    pub about: String,
}

impl Stat {
    /// What the printed table shows.
    fn shown(&self) -> &str {
        self.value.as_deref().unwrap_or("—")
    }
}

/// Everything this tool can measure.
pub fn collect(root: &Path) -> Result<Vec<Stat>, String> {
    let mut stats = Vec::new();
    let mut push = |key: &str, value: Option<String>, about: &str| {
        stats.push(Stat {
            key: key.to_string(),
            value,
            about: about.to_string(),
        });
    };

    // --- The source tree ---------------------------------------------------------------------
    let generated = root.join("src/clusters/generated");
    push(
        "clusters",
        Some(count_cluster_table(&generated.join("mod.rs"))?.to_string()),
        "clusters in `clusters::generated::ALL`",
    );
    push(
        "device-types",
        count_matches(&generated.join("device_types.rs"), |l| {
            l.starts_with("pub const ") && l.contains(": DeviceType")
        })?
        .to_string()
        .into(),
        "device types generated from the Device Library",
    );
    push(
        "cluster-behaviours",
        Some(count_cluster_behaviours(&root.join("src/clusters"))?.to_string()),
        "hand-written cluster behaviours",
    );
    push(
        "fuzz-targets",
        Some(count_files(&root.join("fuzz/fuzz_targets"), "rs")?.to_string()),
        "`cargo-fuzz` targets",
    );
    push(
        "test-files",
        Some(count_files(&root.join("tests"), "rs")?.to_string()),
        "integration test files",
    );

    // --- The dependency surface, which is a compliance number as much as an engineering one ---
    match dependency_counts(root) {
        Some((bare, with_crypto)) => {
            push(
                "deps-no-std",
                Some(bare.to_string()),
                "crates in a `no_std` device build with no cryptographic backend",
            );
            push(
                "deps-rustcrypto",
                Some(with_crypto.to_string()),
                "crates in a device build with the software cryptographic backend",
            );
        }
        None => {
            push("deps-no-std", None, "`cargo tree` could not run here");
            push("deps-rustcrypto", None, "`cargo tree` could not run here");
        }
    }

    // --- The footprint, if an image has ever been linked -------------------------------------
    match read_footprint(&root.join("footprint/last.json")) {
        Some((flash, ram)) => {
            push(
                "flash-kib",
                Some(flash.to_string()),
                "KiB of flash, nRF52840",
            );
            push("ram-kib", Some(ram.to_string()), "KiB of RAM, nRF52840");
        }
        None => {
            push(
                "flash-kib",
                None,
                "not linked here — run `footprint/run.sh`",
            );
            push("ram-kib", None, "not linked here — run `footprint/run.sh`");
        }
    }

    // --- The citation sweep's size, if it has ever run here -----------------------------------
    match read_pair(
        &root.join("concepts/cite-last.json"),
        "citations",
        "quotations",
    ) {
        Some((citations, quotations)) => {
            push(
                "citations",
                Some(thousands(citations)),
                "`§` references checked against the 1.6 documents",
            );
            push(
                "quotations",
                Some(thousands(quotations)),
                "quotations checked against the 1.6 documents",
            );
        }
        None => {
            push("citations", None, "not swept here — run `cargo xtask cite`");
            push(
                "quotations",
                None,
                "not swept here — run `cargo xtask cite`",
            );
        }
    }

    Ok(stats)
}

/// `7059` as `7 059`, the way these documents write a four-figure number.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push('\u{202f}');
        }
        out.push(c);
    }
    out
}

/// Renders the table a human reads.
pub fn render(stats: &[Stat]) -> String {
    let width = stats.iter().map(|s| s.key.len()).max().unwrap_or(0);
    let mut out = String::new();
    for stat in stats {
        let _ = writeln!(
            out,
            "  {:<width$}  {:>10}  {}",
            stat.key,
            stat.shown(),
            stat.about,
            width = width
        );
    }
    out
}

/// Rewrites every `<!-- stats:key -->…<!-- /stats -->` block in `files`.
///
/// The marker is an HTML comment, so it is invisible in rendered Markdown and survives every
/// tool that does not parse it. A document opts in per number rather than wholesale: a sentence
/// that wants the figure inline writes the marker there, and everything around it stays prose.
pub fn apply(files: &[PathBuf], stats: &[Stat], check_only: bool) -> Result<Vec<PathBuf>, String> {
    let by_key: BTreeMap<&str, &Stat> = stats.iter().map(|s| (s.key.as_str(), s)).collect();
    let mut stale = Vec::new();
    for file in files {
        let before =
            std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let after = substitute(&before, &by_key, file)?;
        if after != before {
            stale.push(file.clone());
            if !check_only {
                std::fs::write(file, after).map_err(|e| format!("{}: {e}", file.display()))?;
            }
        }
    }
    Ok(stale)
}

/// Replaces the body of every marker in one document.
fn substitute(text: &str, stats: &BTreeMap<&str, &Stat>, file: &Path) -> Result<String, String> {
    const OPEN: &str = "<!-- stats:";
    const CLOSE: &str = "<!-- /stats -->";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        let (head, tail) = rest.split_at(start);
        out.push_str(head);
        let after_open = &tail[OPEN.len()..];
        let Some(key_end) = after_open.find(" -->") else {
            return Err(format!(
                "{}: a `{OPEN}` marker with no `-->`",
                file.display()
            ));
        };
        let key = &after_open[..key_end];
        let body_start = &after_open[key_end + " -->".len()..];
        let Some(body_end) = body_start.find(CLOSE) else {
            return Err(format!(
                "{}: `{OPEN}{key} -->` is never closed by `{CLOSE}`",
                file.display()
            ));
        };
        let Some(stat) = stats.get(key) else {
            return Err(format!(
                "{}: no measurement named `{key}` — `cargo xtask stats` lists them",
                file.display()
            ));
        };
        // Unmeasured here: keep whatever the document says. This machine has no opinion, and a
        // tool that overwrote a true number with its own ignorance would be the drift it exists
        // to prevent.
        let body = match &stat.value {
            Some(value) => value.as_str(),
            None => &body_start[..body_end],
        };
        out.push_str(OPEN);
        out.push_str(key);
        out.push_str(" -->");
        out.push_str(body);
        out.push_str(CLOSE);
        rest = &body_start[body_end + CLOSE.len()..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Every document that may carry a marker.
pub fn documents(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![
        root.join("README.md"),
        root.join("SECURITY.md"),
        root.join("CHANGELOG.md"),
    ];
    for dir in ["site/content/docs", "concepts"] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "md") {
                files.push(path);
            }
        }
    }
    files.retain(|f| f.exists());
    files.sort();
    files
}

// --- The individual measurements ---------------------------------------------------------

/// Entries in `clusters::generated::ALL`, which is the list a node can actually serve.
///
/// Counted from the array rather than from the files beside it: four of those files are derived
/// bases and a globals table, which are not clusters, and "how many `.rs` files are there" is the
/// kind of proxy that answers 139 to a question about 135.
fn count_cluster_table(path: &Path) -> Result<usize, String> {
    let text = read(path)?;
    let Some(start) = text.find("pub const ALL:") else {
        return Err(format!("{}: no `ALL` table", path.display()));
    };
    let body = &text[start..];
    let Some(end) = body.find("];") else {
        return Err(format!("{}: `ALL` is never closed", path.display()));
    };
    Ok(body[..end]
        .lines()
        .filter(|l| l.trim_end().ends_with("::CLUSTER,"))
        .count())
}

/// Hand-written cluster behaviours: every module under `src/clusters` that is not the generated
/// tree, counting a directory by the modules inside it rather than as one.
fn count_cluster_behaviours(dir: &Path) -> Result<usize, String> {
    let mut n = 0;
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "mod.rs" || name == "generated" {
            continue;
        }
        if path.is_dir() {
            n += count_files(&path, "rs")?.saturating_sub(1); // its own `mod.rs` is not a cluster
        } else if path.extension().is_some_and(|e| e == "rs") {
            n += 1;
        }
    }
    Ok(n)
}

fn count_files(dir: &Path, extension: &str) -> Result<usize, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == extension))
        .count())
}

fn count_matches(path: &Path, mut f: impl FnMut(&str) -> bool) -> Result<usize, String> {
    Ok(read(path)?.lines().filter(|l| f(l)).count())
}

/// How many crates a consumer's SBOM inherits, with and without the software crypto backend.
///
/// This is an engineering number and a compliance one: from 11 December 2027 a manufacturer
/// shipping into the EU owes a machine-readable SBOM covering its dependencies, and a
/// manufacturer's SBOM is the union of its dependencies'. So it is worth being exactly right
/// rather than approximately.
///
/// `cargo tree` rather than a walk of `Cargo.lock`, because the lockfile records no features:
/// it lists every optional dependency and every dev-dependency, and a count taken from it
/// answers a question nobody asked. Shelling out costs a second and is exact.
///
/// Returns `None` when `cargo tree` cannot run — an offline machine with a cold registry, say —
/// so a checkout that cannot resolve reports honestly instead of guessing.
/// The target these counts are resolved for.
///
/// Without it the answer is the host's, and the host's is not the one anybody means: `cpufeatures`
/// pulls `libc` on aarch64 macOS and not on x86-64 Linux, so the same checkout reported 50 crates
/// on a developer's laptop and 49 in CI, and the gate failed on the machine that was right. A
/// device target is both reproducible everywhere and the figure a compliance reviewer is asking
/// for — it is what a shipped image links. `thumbv7em-none-eabihf` and
/// `riscv32imac-unknown-none-elf` agree, so the choice between them does not matter.
///
/// `cargo tree` resolves a graph rather than building one, so this needs no installed toolchain.
const DEPENDENCY_TARGET: &str = "thumbv7em-none-eabihf";

fn dependency_counts(root: &Path) -> Option<(usize, usize)> {
    let count = |features: &[&str]| -> Option<usize> {
        let mut cmd =
            std::process::Command::new(std::env::var("CARGO").as_deref().unwrap_or("cargo"));
        cmd.current_dir(root).args([
            "tree",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--no-default-features",
            "--target",
            DEPENDENCY_TARGET,
        ]);
        if !features.is_empty() {
            cmd.args(["--features", &features.join(",")]);
        }
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8(out.stdout).ok()?;
        // One line per node, repeats marked `(*)`. The package name is the first field, and the
        // crate itself is not a dependency of anybody.
        let mut names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|n| !n.is_empty() && *n != "matter-kit")
            .collect();
        names.sort_unstable();
        names.dedup();
        Some(names.len())
    };
    Some((count(&[])?, count(&["rustcrypto"])?))
}

/// The last footprint `footprint/run.sh` measured, if it has ever run here.
fn read_footprint(path: &Path) -> Option<(u64, u64)> {
    // A linked image is never 0 KiB. `llvm-size` exits 0 when it cannot read a file, so a broken
    // measurement used to arrive here as a pair of zeros and get reported as fact — which marked
    // every true footprint in the documents stale. `footprint/run.sh` now refuses to write that,
    // and this refuses to believe it: unmeasured is the honest answer, and it leaves the
    // documents alone.
    match read_pair(path, "flash_kib", "ram_kib")? {
        (0, _) | (_, 0) => None,
        pair => Some(pair),
    }
}

/// Two integer fields out of a flat JSON object, without a JSON dependency.
fn read_pair(path: &Path, first: &str, second: &str) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    let field = |key: &str| -> Option<u64> {
        let at = text.find(&format!("\"{key}\""))?;
        let rest = &text[at..];
        let colon = rest.find(':')?;
        rest[colon + 1..]
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    };
    Some((field(first)?, field(second)?))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_marker_is_replaced_in_place() {
        let stats = [Stat {
            key: "clusters".into(),
            value: Some("135".into()),
            about: String::new(),
        }];
        let by_key: BTreeMap<&str, &Stat> = stats.iter().map(|s| (s.key.as_str(), s)).collect();
        let text = "the library has <!-- stats:clusters -->999<!-- /stats --> clusters\n";
        let out = substitute(text, &by_key, Path::new("x.md")).unwrap();
        assert_eq!(
            out,
            "the library has <!-- stats:clusters -->135<!-- /stats --> clusters\n"
        );
    }

    #[test]
    fn an_unknown_key_is_an_error_rather_than_a_silent_skip() {
        let by_key = BTreeMap::new();
        let text = "<!-- stats:nonesuch -->0<!-- /stats -->";
        let err = substitute(text, &by_key, Path::new("x.md")).unwrap_err();
        assert!(err.contains("nonesuch"), "{err}");
    }

    #[test]
    fn an_unclosed_marker_is_an_error() {
        let by_key = BTreeMap::new();
        let text = "<!-- stats:clusters -->135";
        assert!(substitute(text, &by_key, Path::new("x.md")).is_err());
    }

    #[test]
    fn a_zero_footprint_is_a_failed_measurement_rather_than_a_small_image() {
        let dir = std::env::temp_dir().join("matter-kit-stats-zero-footprint");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("last.json");

        std::fs::write(&path, r#"{"flash_kib": 0, "ram_kib": 0}"#).unwrap();
        assert_eq!(
            read_footprint(&path),
            None,
            "0 KiB is llvm-size having failed"
        );

        std::fs::write(&path, r#"{"flash_kib": 88, "ram_kib": 0}"#).unwrap();
        assert_eq!(
            read_footprint(&path),
            None,
            "either half being 0 is the same failure"
        );

        std::fs::write(&path, r#"{"flash_kib": 88, "ram_kib": 39}"#).unwrap();
        assert_eq!(read_footprint(&path), Some((88, 39)));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_four_figure_number_is_grouped_the_way_the_documents_write_one() {
        // A narrow no-break space, not a comma: these documents are British and the citation
        // count sits mid-sentence, where a comma would read as punctuation.
        assert_eq!(thousands(7059), "7\u{202f}059");
        assert_eq!(thousands(350), "350");
        assert_eq!(thousands(1_234_567), "1\u{202f}234\u{202f}567");
        assert_eq!(thousands(0), "0");
    }

    #[test]
    fn an_unmeasured_statistic_leaves_the_document_alone() {
        // A CI job with no cross toolchain has nothing to say about the footprint. Saying it
        // anyway would rewrite the README's headline number to the tool's own ignorance.
        let stats = [Stat {
            key: "flash-kib".into(),
            value: None,
            about: String::new(),
        }];
        let by_key: BTreeMap<&str, &Stat> = stats.iter().map(|s| (s.key.as_str(), s)).collect();
        let text = "**<!-- stats:flash-kib -->88<!-- /stats --> KiB of flash**";
        assert_eq!(substitute(text, &by_key, Path::new("x.md")).unwrap(), text);
    }

    #[test]
    fn text_with_no_markers_is_returned_unchanged() {
        let by_key = BTreeMap::new();
        let text = "nothing to see here\n";
        assert_eq!(substitute(text, &by_key, Path::new("x.md")).unwrap(), text);
    }
}
