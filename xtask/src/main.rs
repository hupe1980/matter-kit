//! `cargo xtask` — the CSA data model, turned into Rust.
//!
//! The 1.6 Application Cluster library defines about 128 clusters and the Device Library 93
//! device types. Each cluster is an identifier set, enumerations, bitmaps, structures,
//! attributes with qualities and constraints, commands, events, features — and, per element, a
//! **conformance expression** that depends on the feature map. Transcribing that by hand is
//! months of work with a silent drift risk, and drift is what certification finds.
//!
//! So it is generated, from the same XML the Test Harness itself reads: the CSA's Alchemy
//! scraper produces `data_model/<version>/` from the specification sources, and the Harness
//! picks a directory from the device's `SpecificationVersion`. Generating from the same input
//! means the crate validates against what the tester validates against.
//!
//! # Where the XML comes from
//!
//! It is **not** in this repository. The files carry the CSA's own copyright notice, which
//! grants a licence to "view, download, save, reproduce and use the document solely for your
//! own internal purposes" and explicitly does not authorise republication — the same footing
//! as the specification PDFs, which `.gitignore` already keeps out. Fetch them with
//! clone `project-chip/connectedhomeip` and point `--dm` at its
//! `data_model/1.6`.
//!
//! What *is* committed is this tool's output, under `src/clusters/generated/`. Identifiers,
//! enumeration values and conformance rules are the functional interface every Matter
//! implementation must agree on rather than anybody's prose, and a build has to be hermetic:
//! `cargo build` cannot depend on a download, and docs.rs must show real types.
//!
//! ```text
//! cargo xtask clusters --dm data_model/1.6    # XML → src/clusters/generated/
//! cargo xtask check    --dm data_model/1.6    # regenerate and fail on any diff (the CI gate)
//! cargo xtask report   --dm data_model/1.6    # what was generated, and what could not be
//! ```
//!
//! # Why this is an xtask and not a binary of the library
//!
//! It imports nothing from `matter_kit`. It reads XML and writes Rust *text* that names the
//! library's types — so it has no reason to depend on the crate it writes into, and one strong
//! reason not to: a generator built *from* the library would have to be built from a library
//! that still contains the files it is about to replace. Every change to the output shape would
//! then break the committed files, which break the library, which breaks the generator that
//! would fix them. Out here that cycle cannot form.
//!
//! It also keeps `roxmltree` out of `matter-kit`'s dependency tree altogether, and one feature
//! out of the powerset that every combination had to be tested against.
//!
//! # Why the lints are relaxed here
//!
//! `matter-kit` denies `unwrap`, `expect`, `panic!`, slice indexing and unchecked arithmetic,
//! because all of that faces a network. This faces a directory of XML the developer chose, on
//! the developer's machine, and its failure mode is a build that stops. Writing every string
//! index as a checked `get` would hide the one thing that matters in a generator — what it
//! emits — behind ceremony that buys nothing.

#![allow(clippy::print_stdout, clippy::print_stderr)]

mod api;
mod cite;
mod emit;
mod ident;
mod model;
mod parse;
mod types;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// What the tool was asked to do.
enum Command {
    /// Write `src/clusters/generated/`.
    Generate { dm: PathBuf, out: PathBuf },
    /// Regenerate into a scratch directory and fail on any difference.
    Check { dm: PathBuf, out: PathBuf },
    /// Print what the data model contains and what this tool made of it.
    Report { dm: PathBuf },
    /// List the public functions nothing calls.
    Api { strict: bool },
    /// Check every `§` citation and quotation against the specification PDFs.
    Cite { spec: PathBuf, strict: bool },
}

fn main() -> ExitCode {
    match parse_args() {
        Ok(command) => match run(command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("xtask: {error}");
                ExitCode::FAILURE
            }
        },
        Err(message) => {
            eprintln!("xtask: {message}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
usage:
  cargo xtask clusters [--dm <dir>] [--out <dir>]   generate src/clusters/generated/
  cargo xtask check    [--dm <dir>] [--out <dir>]   regenerate and fail on any diff
  cargo xtask report   [--dm <dir>]                 what the data model contains
  cargo xtask api      [--strict]                   public functions nothing calls
  cargo xtask cite     [--spec <dir>] [--strict]    every § citation and quotation

  --dm   the CSA data model directory, holding clusters/ and device_types/
         (default: data_model/1.6)
  --out  where to write (default: src/clusters/generated)

The XML is not in this repository; it carries the CSA's own copyright notice and is not
redistributable. Clone project-chip/connectedhomeip and point --dm at data_model/1.6:

  git clone --filter=blob:none --sparse https://github.com/project-chip/connectedhomeip
  git -C connectedhomeip sparse-checkout set data_model/1.6
  cargo xtask clusters --dm connectedhomeip/data_model/1.6";

fn parse_args() -> Result<Command, String> {
    let mut args = std::env::args().skip(1);
    let verb = args.next().ok_or("no subcommand")?;
    let mut dm = PathBuf::from("data_model/1.6");
    let mut out = PathBuf::from("src/clusters/generated");
    let mut spec = PathBuf::from("concepts/references/1.6");
    let mut strict = false;
    while let Some(flag) = args.next() {
        if flag == "--strict" {
            strict = true;
            continue;
        }
        let value = args.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--dm" => dm = PathBuf::from(value),
            "--out" => out = PathBuf::from(value),
            "--spec" => spec = PathBuf::from(value),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    match verb.as_str() {
        "clusters" | "generate" => Ok(Command::Generate { dm, out }),
        "check" => Ok(Command::Check { dm, out }),
        "report" => Ok(Command::Report { dm }),
        "api" => Ok(Command::Api { strict }),
        "cite" => Ok(Command::Cite { spec, strict }),
        other => Err(format!("unknown subcommand {other}")),
    }
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Generate { dm, out } => {
            let model = load(&dm)?;
            let files = format(emit::emit(&model))?;
            write_all(&out, &files)?;
            println!(
                "xtask: {} clusters, {} device types → {}",
                model.clusters.len(),
                model.device_types.len(),
                out.display()
            );
            Ok(())
        }
        Command::Check { dm, out } => {
            let model = load(&dm)?;
            let files = format(emit::emit(&model))?;
            let mut stale = Vec::new();
            for (name, contents) in &files {
                let path = out.join(name);
                match std::fs::read_to_string(&path) {
                    Ok(existing) if &existing == contents => {}
                    Ok(_) => stale.push(format!("{} differs", path.display())),
                    Err(_) => stale.push(format!("{} is missing", path.display())),
                }
            }
            if stale.is_empty() {
                println!("xtask: {} files up to date", files.len());
                Ok(())
            } else {
                Err(format!(
                    "generated sources are stale — run `cargo xtask clusters`:\n  {}",
                    stale.join("\n  ")
                ))
            }
        }
        Command::Report { dm } => {
            let model = load(&dm)?;
            report(&model);
            Ok(())
        }
        Command::Cite { spec, strict } => {
            let report = cite::sweep(Path::new("."), &spec, Path::new("target/xtask-cite"))?;
            cite::print(&report);
            let found = report.sections.len() + report.quotations.len();
            if strict && found > 0 {
                return Err(format!("{found} citations or quotations do not check out"));
            }
            Ok(())
        }
        Command::Api { strict } => {
            let report = api::sweep(Path::new("."));
            api::print(&report);
            if strict && !report.uncalled.is_empty() {
                return Err(format!(
                    "{} public functions are called by nothing",
                    report.uncalled.len()
                ));
            }
            Ok(())
        }
    }
}

/// Runs the emitted source through `rustfmt`.
///
/// Not cosmetic: `cargo xtask check` compares bytes, and a committed file that had been
/// formatted afterwards would differ from a fresh run for ever. Formatting here makes generate
/// and check produce the same thing, which is the only way the CI gate means anything.
fn format(files: Vec<(String, String)>) -> Result<Vec<(String, String)>, String> {
    files
        .into_iter()
        .map(|(name, source)| {
            let mut child = std::process::Command::new("rustfmt")
                .args(["--edition", "2024", "--emit", "stdout", "--quiet"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("rustfmt: {e} (is it on PATH?)"))?;
            {
                use std::io::Write as _;
                let stdin = child.stdin.as_mut().ok_or("rustfmt: no stdin")?;
                stdin
                    .write_all(source.as_bytes())
                    .map_err(|e| format!("rustfmt: {e}"))?;
            }
            let done = child
                .wait_with_output()
                .map_err(|e| format!("rustfmt: {e}"))?;
            if !done.status.success() {
                return Err(format!(
                    "rustfmt refused {name}: {}",
                    String::from_utf8_lossy(&done.stderr).trim()
                ));
            }
            let formatted = String::from_utf8(done.stdout).map_err(|e| format!("rustfmt: {e}"))?;
            Ok((name, formatted))
        })
        .collect()
}

fn load(dm: &Path) -> Result<model::DataModel, String> {
    if !dm.join("clusters").is_dir() {
        return Err(format!(
            "{} has no clusters/ directory.\n\nThe CSA data model is not vendored here — it \
             carries the CSA's own copyright notice and is not redistributable. Clone \
             project-chip/connectedhomeip and pass --dm <checkout>/data_model/1.6.",
            dm.display()
        ));
    }
    parse::load(dm)
}

fn write_all(out: &Path, files: &[(String, String)]) -> Result<(), String> {
    // Built beside the target and moved into place, so that an interrupted run — a full disk,
    // a Ctrl-C between two of a hundred and forty files — never leaves a half-written library
    // behind. That matters more here than it looks: the half-written state does not compile,
    // and what does not compile cannot be regenerated by anything that has to build first.
    let staging = out.with_file_name(format!(
        "{}.staging",
        out.file_name().unwrap_or_default().to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    for (name, contents) in files {
        let path = staging.join(name);
        std::fs::write(&path, contents).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    // Only now is the old directory touched. Replacing it wholesale is also what removes the
    // modules an older data model had and this one does not — no pruning pass to get wrong.
    let _ = std::fs::remove_dir_all(out);
    std::fs::rename(&staging, out).map_err(|e| {
        let _ = std::fs::remove_dir_all(&staging);
        format!("{} → {}: {e}", staging.display(), out.display())
    })
}

fn report(model: &model::DataModel) {
    println!("data model {}", model.version);
    println!("  clusters      {}", model.clusters.len());
    println!("  device types  {}", model.device_types.len());

    let (mut attributes, mut commands, mut events, mut enums, mut bitmaps, mut structs) =
        (0, 0, 0, 0, 0, 0);
    for cluster in &model.clusters {
        attributes += cluster.attributes.len();
        commands += cluster.commands.len();
        events += cluster.events.len();
        enums += cluster.enums.len();
        bitmaps += cluster.bitmaps.len();
        structs += cluster.structs.len();
    }
    println!("  attributes    {attributes}");
    println!("  commands      {commands}");
    println!("  events        {events}");
    println!("  enumerations  {enums}");
    println!("  bitmaps       {bitmaps}");
    println!("  structures    {structs}");

    let described = model
        .clusters
        .iter()
        .flat_map(|c| c.attributes.iter().map(|a| &a.conform))
        .filter(|c| c.is_described())
        .count();
    println!("  attributes whose conformance is prose: {described}");

    if !model.unmapped_types.is_empty() {
        println!("\ntypes with no Rust mapping (structures using them are not generated):");
        let mut kinds: Vec<_> = model.unmapped_types.iter().collect();
        kinds.sort();
        for (name, count) in kinds {
            println!("  {count:5}  {name}");
        }
    }
}
