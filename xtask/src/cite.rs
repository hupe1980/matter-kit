//! Every `§` reference and every quotation, against the specification that states them.
//!
//! This crate's strongest habit is quoting the specification beside the rule and naming the
//! section it comes from — several thousand references across `src/`, `tests/`, `examples/`,
//! `README.md` and the published guides under `site/content`. A citation is not a comment: it
//! is a claim about a *revision*, and 1.5→1.6 renumbered whole chapters underneath one.
//!
//! The defects it catches are the ones that read as correct: a `systime-ms` cited to §7.18.2.6
//! when §7.18 is "Optional or Deprecated"; a `RequestCommissioningApproval` cited to §11.30.7.1
//! when chapter 11 ends at §11.27; an attribute cited into a cluster's *events* rather than its
//! attributes; two siblings numbered where children belong; and a quotation that reads like the
//! specification and appears nowhere in it.
//!
//! ```text
//! cargo xtask cite --spec concepts/references/1.6
//! ```
//!
//! # Why it cannot run in CI
//!
//! The PDFs are free from csa-iot.org and **not redistributable**, so they are not in this
//! repository and cannot be in a hosted runner either. This runs where a local copy already
//! lives — beside `cargo xtask check`, which needs a data-model checkout for the same reason —
//! and before a specification uplift it is the first thing to run, because a renumbering is
//! exactly what it finds.
//!
//! # The two normalisations, and the one rule that is not one
//!
//! A naive checker reports hundreds of false positives and is therefore worth nothing:
//!
//! * **Page furniture.** Headers, footers and page numbers splice themselves into the middle of
//!   a quotation. They are stripped before anything is compared.
//! * **Column wrap and hyphenation.** A table cell breaks a sentence across lines and a soft
//!   hyphen breaks a word. Both sides are reduced to lowercase alphanumerics, which makes
//!   layout invisible.
//! * **Run-in headings.** The deep subsections — §4.6.5.2.1, §11.22.5.4.1, §7.15.6.4.3 — are
//!   bold run-in headings that `pdftotext` renders *without* their numbers. They are real, and
//!   the decisive test is whether the document cross-references them itself, not whether a
//!   numbered heading appears.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The four documents a citation can name, and the prefix that names each.
const DOCUMENTS: [(&str, &str); 4] = [
    ("core", "Matter-1.6-Core-Specification.pdf"),
    ("app", "Matter-1.6-Application-Cluster-Specification.pdf"),
    ("dl", "Matter-1.6-Device-Library-Specification.pdf"),
    ("ns", "Matter-1.6-Standard-Namespaces.pdf"),
];

/// What the sweep found.
pub struct Report {
    /// `(where, what)` for each citation naming a section no document has **and** whose parent
    /// numbers its other children — so the number is wrong rather than merely unprinted.
    pub sections: Vec<(String, String)>,
    /// `(where, what)` for each citation whose parent exists but numbers none of its children.
    ///
    /// These are the deep run-in headings `pdftotext` renders without their numbers. They
    /// cannot be confirmed mechanically and they cannot be refuted either, so they are counted
    /// apart rather than reported as defects: a checker that cried wolf about two hundred of
    /// them would be turned off within a day.
    pub unverifiable: Vec<(String, String)>,
    /// `(where, what)` for each quotation no document contains.
    pub quotations: Vec<(String, String)>,
    /// How many citations were checked.
    pub citations: usize,
    /// How many quotations were checked.
    pub quoted: usize,
}

/// Lowercase alphanumerics only, which makes column wrap, hyphenation and line breaks invisible.
fn normalise(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Drops the running header, the copyright footer and bare page numbers.
fn strip_furniture(text: &str) -> String {
    text.lines()
        .filter(|line| {
            let line = line.trim();
            !(line.starts_with("Matter Specification R")
                || line.starts_with("Copyright ©")
                || line.starts_with("Page ")
                || (!line.is_empty() && line.chars().all(|c| c.is_ascii_digit())))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Runs `pdftotext -layout`, caching the result beside the target directory.
fn extract(pdf: &Path, cache: &Path) -> Result<String, String> {
    if let Ok(cached) = std::fs::read_to_string(cache) {
        return Ok(cached);
    }
    if !pdf.exists() {
        return Err(format!("{} is not there", pdf.display()));
    }
    let output = Command::new("pdftotext")
        .arg("-layout")
        .arg(pdf)
        .arg(cache)
        .output()
        .map_err(|e| format!("pdftotext could not be run ({e}) — install poppler"))?;
    if !output.status.success() {
        return Err(format!(
            "pdftotext failed on {}: {}",
            pdf.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    std::fs::read_to_string(cache).map_err(|e| format!("{}: {e}", cache.display()))
}

/// Every section number a document heads, lists in its contents, or cross-references.
///
/// All three matter, and the third most of all: a deep subsection is a bold run-in heading that
/// `pdftotext` renders without its number, so the only evidence it exists is the document
/// pointing at it from somewhere else.
fn sections_of(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        // A numbered heading or a table-of-contents entry: `11.26.6.1. Request…`, with or
        // without the trailing dot, and with or without a row of leader dots after it.
        if let Some(token) = trimmed.split_whitespace().next() {
            let number = token.trim_end_matches('.');
            if number.contains('.')
                && number.chars().all(|c| c.is_ascii_digit() || c == '.')
                && !number.starts_with('.')
                && number.len() < 24
            {
                found.insert(number.to_owned());
            }
        }
        // A cross-reference: `see Section 4.6.5.2.1`, in either case.
        for marker in ["Section ", "section "] {
            let mut rest = line;
            while let Some(at) = rest.find(marker) {
                rest = rest.get(at + marker.len()..).unwrap_or("");
                let number: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                let number = number.trim_end_matches('.');
                if number.contains('.') {
                    found.insert(number.to_owned());
                }
            }
        }
    }
    found
}

/// Every file whose citations are this crate's own claims.
///
/// The published guides under `site/content` cite as many sections as the source does, and a
/// wrong one there is read by more people, so they are checked on the same terms. `README.md`
/// is a file rather than a directory, so it is seeded directly.
fn sources(root: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    let readme = root.join("README.md");
    if let Ok(text) = std::fs::read_to_string(&readme) {
        found.push((readme, text));
    }
    let mut stack: Vec<PathBuf> = ["src", "tests", "examples", "site/content"]
        .iter()
        .map(|d| root.join(d))
        .collect();
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // The generated library's citations come from the CSA's own XML, not from a reader.
            if path.to_string_lossy().contains("clusters/generated") {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs" || e == "md")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                found.push((path, text));
            }
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Pulls `§4.14.2.3`-style references out of one line.
fn citations_in(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find('§') {
        rest = rest.get(at + '§'.len_utf8()..).unwrap_or("");
        let rest_trimmed = rest.trim_start_matches(['§', ' ']);
        let number: String = rest_trimmed
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let number = number.trim_end_matches('.');
        // A chapter on its own — `§11` — names no subsection and is always present.
        if number.contains('.') {
            found.push(number.to_owned());
        }
    }
    found
}

/// Pulls quoted sentences out of one doc-comment block.
fn quotations_in(block: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = block;
    while let Some(open) = rest.find('"') {
        let after = rest.get(open + 1..).unwrap_or("");
        let Some(close) = after.find('"') else { break };
        let quoted = after.get(..close).unwrap_or("");
        rest = after.get(close + 1..).unwrap_or("");
        // Three filters, and each one exists because leaving it out buys noise rather than
        // findings:
        //
        // * **Long enough to be a sentence.** A quoted word is a term of art, not a claim about
        //   what the document says.
        // * **No ellipsis.** An elided quotation is not in the document by construction, and
        //   checking it would report every careful abridgement as a defect.
        // * **Normative.** A quotation carrying SHALL, SHOULD, MAY or MUST is one this crate is
        //   asserting the specification *states*. Everything else in quotation marks is the
        //   author's own phrasing, and this tool has no opinion about that.
        let normative = ["SHALL", "SHOULD", "MAY ", "MUST", "SHALL NOT"]
            .iter()
            .any(|word| quoted.contains(word));
        if quoted.len() >= 60
            && normative
            && !quoted.contains('…')
            && !quoted.contains("...")
            && !quoted.contains('`')
            && !quoted.contains('{')
            && quoted.split_whitespace().count() >= 8
        {
            found.push(quoted.to_owned());
        }
    }
    found
}

/// Whether the document contains `quotation`, allowing for what a two-column PDF does to a
/// sentence.
///
/// A whole-string match is too strict to be useful: a page header, a footer or a table cell
/// splices itself into the middle of a quotation, and the running text either side of it is
/// exactly right. So the quotation is cut into runs of sixty-four normalised characters and
/// every run has to appear *somewhere*. Interleaving then costs nothing, and an invented
/// sentence still fails — sixty-four characters is far too long a phrase to occur by accident,
/// and a quotation that is real fails only if every one of its runs is unlucky at once.
fn contains_quotation(prose: &str, quotation: &str) -> bool {
    let normalised = normalise(quotation);
    if prose.contains(&normalised) {
        return true;
    }
    let bytes = normalised.as_bytes();
    if bytes.len() < 64 {
        return false;
    }
    bytes
        .chunks(64)
        // The last run is whatever is left over, and a short tail matches too easily to be
        // evidence of anything.
        .filter(|chunk| chunk.len() == 64)
        .all(|chunk| match core::str::from_utf8(chunk) {
            Ok(run) => prose.contains(run),
            Err(_) => true,
        })
}

/// Sweeps the crate against the specification in `spec`.
pub fn sweep(root: &Path, spec: &Path, cache_dir: &Path) -> Result<Report, String> {
    std::fs::create_dir_all(cache_dir).map_err(|e| format!("{}: {e}", cache_dir.display()))?;
    let mut sections: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut prose = String::new();
    for (name, file) in DOCUMENTS {
        let text = extract(&spec.join(file), &cache_dir.join(format!("{name}.txt")))?;
        sections.insert(name, sections_of(&text));
        prose.push_str(&normalise(&strip_furniture(&text)));
    }
    let all: BTreeSet<&String> = sections.values().flatten().collect();

    // The highest numbered child each section is seen to have. This is what separates a wrong
    // number from an unprinted one, and it is the only test that works in both directions:
    //
    // * §11.1.6 is Basic Information's *events*, and the document numbers .1 to .4. A citation
    //   to §11.1.6.11 is therefore an attribute's number in the events' section — a mistake,
    //   and one of the seven this check found.
    // * §11.22.5.1's children are run-in headings that `pdftotext` renders without numbers, so
    //   nothing is seen and nothing can be concluded.
    //
    // A citation past the highest sibling is reported; one inside the range, or in a section
    // with no visible numbering at all, is not. The rule is deliberately conservative in the
    // direction of silence: a checker that cried wolf about two hundred run-in headings would
    // be turned off within a day, and then the seven would never have been found.
    let mut highest_child: BTreeMap<String, u32> = BTreeMap::new();
    for number in &all {
        if let Some((parent, last)) = number.rsplit_once('.')
            && let Ok(last) = last.parse::<u32>()
        {
            let slot = highest_child.entry(parent.to_owned()).or_default();
            *slot = (*slot).max(last);
        }
    }

    let mut report = Report {
        sections: Vec::new(),
        unverifiable: Vec::new(),
        quotations: Vec::new(),
        citations: 0,
        quoted: 0,
    };

    for (path, text) in sources(root) {
        // A quotation is a doc-comment block in Rust and a `>` blockquote in the guides, which
        // is the same claim in the same repository and is checked on the same terms.
        let markdown = path.extension().is_some_and(|e| e == "md");
        // A module whose own header says it implements an RFC quotes that RFC throughout, and
        // repeating the word in every doc comment below it would be noise written for a tool.
        // `discovery::schedule` is the case: its title is RFC 6762's, and by this repository's
        // convention a Matter section in such a file is written `Core §x`.
        let rfc_module = text
            .lines()
            .take_while(|l| l.trim_start().starts_with("//!") || l.trim().is_empty())
            .any(|l| l.contains("RFC"));
        let mut block = String::new();
        let mut block_line = 0usize;
        for (i, line) in text.lines().enumerate() {
            let line_no = i + 1;
            // A `§` in a paragraph about an RFC is a section of *that* document — RFC 5280's
            // §4.1.2.2 is a certificate's serial number, and Matter has no such section. Only
            // Matter's own numbers can be checked here, so a block that names an RFC is left
            // alone rather than reported as 200 false positives.
            let rfc_nearby = line.contains("RFC") || block.contains("RFC");
            for number in citations_in(line) {
                report.citations += 1;
                if rfc_nearby || all.contains(&number) {
                    continue;
                }
                let where_ = format!("{}:{line_no}", path.display());
                let Some((parent, last)) = number.rsplit_once('.') else {
                    continue;
                };
                let beyond_the_last_sibling = last
                    .parse::<u32>()
                    .ok()
                    .zip(highest_child.get(parent))
                    .is_some_and(|(cited, highest)| cited > *highest);
                if !all.contains(&&parent.to_owned()) || beyond_the_last_sibling {
                    report.sections.push((where_, format!("§{number}")));
                } else {
                    report.unverifiable.push((where_, format!("§{number}")));
                }
            }
            let trimmed = line.trim_start();
            let quoted_line = if markdown {
                trimmed.strip_prefix('>').map(str::trim)
            } else if trimmed.starts_with("///") || trimmed.starts_with("//!") {
                Some(trimmed.trim_start_matches(['/', '!']).trim())
            } else {
                None
            };
            if let Some(text) = quoted_line {
                if block.is_empty() {
                    block_line = line_no;
                }
                block.push(' ');
                block.push_str(text);
            } else if !block.is_empty() {
                // The same rule as for citations: a block about an RFC is quoting that RFC, and
                // the mDNS responder quotes RFC 6762 more often than it quotes Matter.
                let quotes_an_rfc = rfc_module || block.contains("RFC");
                // A blockquote carries no quotation marks of its own: the `>` is what makes it
                // a quotation, so it is handed over as one and meets every filter unchanged.
                let candidate = if markdown {
                    format!("\"{}\"", block.trim())
                } else {
                    block.clone()
                };
                for quotation in quotations_in(&candidate) {
                    report.quoted += 1;
                    if !quotes_an_rfc && !contains_quotation(&prose, &quotation) {
                        let short: String = quotation.chars().take(120).collect();
                        report
                            .quotations
                            .push((format!("{}:{block_line}", path.display()), short));
                    }
                }
                block.clear();
            }
        }
    }
    Ok(report)
}

/// Prints what the sweep found.
pub fn print(report: &Report) {
    println!(
        "xtask: {} citations and {} quotations checked against the 1.6 documents",
        report.citations, report.quoted
    );
    println!(
        "\n{} citations name a section no document has, in a section that numbers its others:",
        report.sections.len()
    );
    for (where_, what) in &report.sections {
        println!("  {what:<16} {where_}");
    }
    println!(
        "\n{} name a deep subsection the document renders without its number — unverifiable \
         either way, and left alone:",
        report.unverifiable.len()
    );
    println!(
        "\n{} quotations do not appear in any document:",
        report.quotations.len()
    );
    for (where_, what) in &report.quotations {
        println!("  {where_}\n      {what}");
    }
    println!(
        "\nA quotation that fails here is either invented or elided; a section that fails is \
         either wrong or a run-in heading the document never cross-references. Check the second \
         kind by eye — and check the first kind by reading the section, because a plausible \
         sentence with a section number beside it is the most expensive mistake in this \
         repository."
    );
}
