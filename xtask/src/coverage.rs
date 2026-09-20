//! Which specification sections this crate names, and where.
//!
//! Every module here cites the sections it implements, in its own rustdoc, because a rule and
//! the code that keeps it should be readable together. That habit has a second use it was not
//! written for: the citations are a **map**, and a map can be turned around.
//!
//! So this reads every `§` in `src/` and emits the inverse index — chapter by chapter, which
//! modules name it. The point is not a percentage. A coverage figure computed from citations
//! would measure how much this crate *talks* about the specification, which is a number anybody
//! can move by editing a comment, and [CERTIFICATION.md] is explicit that the figure worth
//! having is the count of Test Harness cases that pass.
//!
//! What this is for is the other direction: **a chapter nothing cites**. Core ch. 3 to 14 and
//! the cluster library are the surface this crate claims, and a section that appears in no
//! module's documentation is one nobody has written about — which is either a gap or a citation
//! somebody forgot. Both are worth seeing, and neither is visible from inside a module.
//!
//! ```text
//! cargo xtask coverage           # print the index
//! cargo xtask coverage --write   # refresh site/content/docs/coverage.md
//! ```
//!
//! `cargo xtask cite` is the other half and answers a different question: it checks that every
//! `§` this crate names *exists* and that every quotation beside one is verbatim. This says
//! where they are. Neither is a substitute for the Harness.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Where one specification section is named.
pub type Index = BTreeMap<Section, BTreeSet<String>>;

/// A section number, ordered the way a reader expects: 4.10 before 4.9's successor 4.11, and
/// §11.2 before §11.10.
///
/// A plain string sorts §11.10 before §11.2, which puts the index in an order no reader of the
/// specification would recognise.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Section(Vec<u32>);

impl Section {
    /// The chapter this section belongs to.
    fn chapter(&self) -> u32 {
        self.0.first().copied().unwrap_or(0)
    }
}

impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self.0.iter().map(u32::to_string).collect();
        write!(f, "§{}", parts.join("."))
    }
}

/// Reads every `§` reference in `src/` and inverts it.
pub fn sweep(root: &Path) -> Result<Index, String> {
    let mut index: Index = BTreeMap::new();
    for file in rust_files(&root.join("src"))? {
        // The generated library is a transcription of the data model rather than prose about it,
        // and every one of its 135 files cites its own cluster. Including them would bury the
        // hand-written modules under a table that says only "the generator ran".
        if file.components().any(|c| c.as_os_str() == "generated") {
            continue;
        }
        let module = module_path(root, &file);
        let text =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        // A `§` in a paragraph about an RFC is a section of *that* document. `cargo xtask cite`
        // applies the same rule for the same reason, and the two must agree — an index that kept
        // RFC 5280's §4.1.2.5.1 would then be checked as a Matter citation by `cite`, which is
        // exactly how this was found.
        //
        // Two scopes, because RFC references come at two scales: a whole module that implements
        // one (`discovery::dns` is RFC 1035's), and a single paragraph inside a module that does
        // not (`der` cites RFC 5280 once, about two-digit years).
        if names_an_rfc(&text) {
            continue;
        }
        for section in sections_in(&text) {
            index.entry(section).or_default().insert(module.clone());
        }
    }
    Ok(index)
}

/// Whether a file's module header names an RFC, which makes its `§`s that document's.
fn names_an_rfc(text: &str) -> bool {
    text.lines()
        .take_while(|l| l.starts_with("//!") || l.trim().is_empty())
        .any(|l| l.contains("RFC"))
}

/// Every `§d(.d)*` in a comment or doc comment.
fn sections_in(text: &str) -> BTreeSet<Section> {
    let mut found = BTreeSet::new();
    for block in comment_blocks(text) {
        // A `§` anywhere in a comment block that names an RFC is a section of *that* document.
        // The unit is the block rather than the line because a citation is often the second line
        // of a wrapped comment whose first line carries the document's name — and it is not a
        // fixed window, because a block is exactly as long as the thought in it.
        if block.contains("RFC") {
            continue;
        }
        found.extend(sections_in_line(&block));
    }
    found
}

/// Contiguous runs of comment lines, and every other line on its own.
fn comment_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            current.push_str(line);
            current.push('\n');
        } else {
            if !current.is_empty() {
                blocks.push(std::mem::take(&mut current));
            }
            blocks.push(line.to_owned());
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    blocks
}

/// Every `§d(.d)*` on one line.
fn sections_in_line(text: &str) -> BTreeSet<Section> {
    let mut found = BTreeSet::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != '§' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut parts = Vec::new();
        let mut current = String::new();
        while j < bytes.len() {
            let c = bytes[j];
            if c.is_ascii_digit() {
                current.push(c);
            } else if c == '.' && !current.is_empty() {
                // A trailing dot is sentence punctuation, not a separator — look ahead.
                if bytes.get(j + 1).is_some_and(char::is_ascii_digit) {
                    parts.push(current.clone());
                    current.clear();
                } else {
                    break;
                }
            } else {
                break;
            }
            j += 1;
        }
        if !current.is_empty() {
            parts.push(current);
        }
        if !parts.is_empty() {
            let numbers: Vec<u32> = parts.iter().filter_map(|p| p.parse().ok()).collect();
            if numbers.len() == parts.len() {
                found.insert(Section(numbers));
            }
        }
        i = j.max(i + 1);
    }
    found
}

/// `src/im/server.rs` → `im::server`; `src/acl.rs` → `acl`.
fn module_path(root: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(root.join("src")).unwrap_or(file);
    let mut parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if let Some(last) = parts.last_mut() {
        *last = last.trim_end_matches(".rs").to_string();
        if last == "mod" {
            parts.pop();
        }
    }
    parts.join("::")
}

fn rust_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            out.extend(rust_files(&path)?);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// The document.
pub fn render(index: &Index) -> String {
    let mut out = String::new();
    out.push_str(HEADER);

    let mut by_chapter: BTreeMap<u32, Vec<(&Section, &BTreeSet<String>)>> = BTreeMap::new();
    for (section, modules) in index {
        by_chapter
            .entry(section.chapter())
            .or_default()
            .push((section, modules));
    }

    let _ = writeln!(out, "## The chapters, and what names them\n");
    let _ = writeln!(out, "| Chapter | Sections named | Modules |");
    let _ = writeln!(out, "|---|---:|---|");
    for (chapter, sections) in &by_chapter {
        let mut modules: BTreeSet<&str> = BTreeSet::new();
        for (_, m) in sections {
            modules.extend(m.iter().map(String::as_str));
        }
        let shown: Vec<String> = modules.iter().take(6).map(|m| format!("`{m}`")).collect();
        let more = modules.len().saturating_sub(shown.len());
        let tail = if more > 0 {
            format!(", and {more} more")
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "| {} | {} | {}{} |",
            chapter,
            sections.len(),
            shown.join(", "),
            tail
        );
    }

    let _ = writeln!(out, "\n## Every section, and where it is named\n");
    for (chapter, sections) in &by_chapter {
        let _ = writeln!(out, "### Chapter {chapter}\n");
        let _ = writeln!(out, "| Section | Named in |");
        let _ = writeln!(out, "|---|---|");
        for (section, modules) in sections {
            let names: Vec<String> = modules.iter().map(|m| format!("`{m}`")).collect();
            let _ = writeln!(out, "| {section} | {} |", names.join(", "));
        }
        out.push('\n');
    }
    out
}

const HEADER: &str = r#"+++
title = "Specification index"
description = "Which sections of the Matter specification this crate names, and in which module — generated from the source."
weight = 95
+++

Which specification sections this crate names, and in which module — generated by
`cargo xtask coverage` from the `§` references in `src/`, so it cannot be edited into agreement
with anything.

**This is an index, not a score.** A percentage computed from citations would measure how much
the crate *talks* about the specification, which is a number anybody can move by writing a
comment. What the crate implements is measured by the Test Harness cases that pass, and those
are on the [status page](../status/).

What the index is good for is the question a module cannot answer about itself: **which parts of
the specification nothing here names at all.** A chapter with no modules beside it is either a
gap or a citation somebody forgot, and both are worth seeing.

The generated cluster library is excluded. Its 135 files each cite their own cluster, and
including them would bury the hand-written modules under a table that says only that the
generator ran. So are modules whose own header names an RFC: `§16` in a file about RFC 1035 is a
section of RFC 1035, and counting it as a Matter chapter would invent two that do not exist.

**Core chapter 13 is named by nothing**, and that is correct rather than an omission: it is
Security Requirements, which is a set of properties the whole crate has to have rather than a
module anybody could point at. It is the one chapter whose coverage this index cannot speak to.

"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_section_is_read_out_of_prose() {
        let found = sections_in("see §4.13.2.1 and §11.2, but not § or §§");
        let shown: Vec<String> = found.iter().map(ToString::to_string).collect();
        assert_eq!(shown, vec!["§4.13.2.1", "§11.2"]);
    }

    #[test]
    fn a_trailing_dot_is_punctuation_and_not_a_separator() {
        let found = sections_in("this is §4.11. And then more.");
        let shown: Vec<String> = found.iter().map(ToString::to_string).collect();
        assert_eq!(shown, vec!["§4.11"]);
    }

    #[test]
    fn sections_sort_the_way_the_specification_numbers_them() {
        // The reason `Section` is a vector of numbers rather than a string: as text, "11.10"
        // sorts before "11.2", which puts the index in an order no reader would recognise.
        let found = sections_in("§11.10 §11.2 §11.9 §4.1");
        let shown: Vec<String> = found.iter().map(ToString::to_string).collect();
        assert_eq!(shown, vec!["§4.1", "§11.2", "§11.9", "§11.10"]);
    }

    #[test]
    fn a_section_in_a_paragraph_about_an_rfc_is_that_rfc_s() {
        // `der` cites RFC 5280 §4.1.2.5.1 once, about two-digit years. Indexing it as a Matter
        // section put it in the published index, where `cargo xtask cite` then checked it as a
        // Matter citation and correctly reported that no Matter document has a §4.1.2.5.1.
        // One block names RFC 5280 and is skipped whole — the quotation under it belongs to
        // that RFC too. A separate block, after a blank line, is the Matter one.
        let text = "//! The DER module.\n\n                    // RFC 5280 §4.1.2.5.1: two-digit years, and\n                    // the rule that follows from it.\n                    let x = 1;\n                    // Matter's own §4.11.\n";
        let shown: Vec<String> = sections_in(text).iter().map(ToString::to_string).collect();
        assert_eq!(shown, vec!["§4.11"]);
    }

    #[test]
    fn a_module_whose_header_names_an_rfc_is_skipped_whole() {
        assert!(names_an_rfc(
            "//! RFC 1035's wire format.\n//!\n//! More.\n"
        ));
        assert!(!names_an_rfc("//! The ACL.\n\nfn f() { /* RFC 5280 */ }\n"));
    }

    #[test]
    fn a_module_path_drops_mod_rs() {
        let root = Path::new("/x");
        assert_eq!(module_path(root, Path::new("/x/src/acl.rs")), "acl");
        assert_eq!(
            module_path(root, Path::new("/x/src/im/server.rs")),
            "im::server"
        );
        assert_eq!(module_path(root, Path::new("/x/src/im/mod.rs")), "im");
    }
}
