//! Turning specification names into Rust identifiers.
//!
//! The XML's names are written for people: "On/Off Cluster", "Level Control", "1_2AA",
//! "AAC-LC", "Type". Rust wants module names, type names and constant names, and it has
//! keywords. Every rule here exists because some real name in the 1.6 library needs it.

/// Rust's keywords, which a specification name is free to collide with — `Type`, `Match`,
/// `Move` and `Static` all appear. Escaped with a trailing underscore rather than `r#`,
/// because a raw identifier in a constant name reads badly and these are read by people.
const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
    "use", "where", "while", "async", "await", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "try", "typeof", "unsized", "virtual", "yield",
];

/// Splits a name into words, however it was written.
///
/// Handles the four shapes the XML uses at once: spaced ("Level Control"), slashed
/// ("On/Off"), hyphenated ("AAC-LC") and camel ("StartUpOnOff"). The camel split is the
/// awkward one — "TLSCertificate" must become `TLS Certificate` rather than `T L S
/// Certificate`, so a run of capitals stays together until a lowercase letter shows which
/// capital began the next word.
pub fn words(name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (index, &ch) in chars.iter().enumerate() {
        if !ch.is_alphanumeric() {
            // A separator: space, slash, hyphen, underscore, dot, parenthesis.
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        let previous = if index == 0 {
            None
        } else {
            Some(chars[index - 1])
        };
        let next = chars.get(index + 1).copied();
        let starts_word = match previous {
            None => false,
            Some(previous) => {
                // lower→UPPER, or digit→letter, or the last capital of a run before a
                // lowercase one: "TLSCert" splits before the C, not before the S.
                (previous.is_lowercase() && ch.is_uppercase())
                    || (previous.is_numeric() && ch.is_alphabetic())
                    || (previous.is_uppercase()
                        && ch.is_uppercase()
                        && next.is_some_and(char::is_lowercase))
            }
        };
        if starts_word && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        current.push(ch);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// `snake_case`, for module names: "On/Off" → `on_off`.
pub fn snake(name: &str) -> String {
    escape(
        words(name)
            .iter()
            .map(|word| word.to_lowercase())
            .collect::<Vec<_>>()
            .join("_"),
    )
}

/// `SCREAMING_SNAKE_CASE`, for constants: "StartUpOnOff" → `START_UP_ON_OFF`.
pub fn screaming(name: &str) -> String {
    escape(
        words(name)
            .iter()
            .map(|word| word.to_uppercase())
            .collect::<Vec<_>>()
            .join("_"),
    )
}

/// `PascalCase`, for types and enum variants: "1_2AA" → `N1_2AA`.
///
/// A word that is all capitals is left alone — `TLS` rather than `Tls` — because the
/// specification's own spelling is what a reader is holding alongside this.
pub fn pascal(name: &str) -> String {
    let joined: String = words(name)
        .iter()
        .map(|word| {
            if word.len() > 1 && word.chars().all(|c| c.is_uppercase() || c.is_numeric()) {
                word.clone()
            } else {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect();
    escape(joined)
}

/// Makes an identifier legal: prefixes a leading digit, and escapes a keyword.
///
/// The leading digit is not hypothetical — the Power Source cluster's `BatReplacementNeeded`
/// enumerations are battery sizes: `1_2AA`, `18650`, `4SR44`. `N` for "number", chosen over a
/// leading underscore because `_18650` reads as an ignored binding.
fn escape(name: String) -> String {
    let mut name = name;
    if name.is_empty() {
        return "Unnamed".to_owned();
    }
    if name.starts_with(|c: char| c.is_numeric()) {
        name.insert(0, 'N');
    }
    if KEYWORDS.contains(&name.as_str()) {
        name.push('_');
    }
    name
}

/// Makes every name in a list unique, by suffixing a repeat with its ordinal.
///
/// Two different specification names can flatten to one Rust identifier — `MaxPressure` and
/// `MAXPressure` would — and a silently dropped element is the worst possible outcome for a
/// generator whose whole purpose is not to lose anything.
pub fn unique(names: &mut [String]) {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for name in names.iter_mut() {
        let count = seen.entry(name.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            let n = *count;
            name.push_str(&format!("_{n}"));
        }
    }
}

/// Escapes a summary for a doc comment: one line, no `*/`, no stray backslashes.
pub fn doc(summary: &str) -> String {
    summary
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("*/", "*∕")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_name_shapes_all_split() {
        assert_eq!(words("On/Off"), ["On", "Off"]);
        assert_eq!(words("Level Control"), ["Level", "Control"]);
        assert_eq!(words("StartUpOnOff"), ["Start", "Up", "On", "Off"]);
        assert_eq!(words("AAC-LC"), ["AAC", "LC"]);
        // The capital-run rule: the word breaks before the capital that begins the next word.
        assert_eq!(words("TLSCertificate"), ["TLS", "Certificate"]);
        assert_eq!(words("MaxTLSCerts"), ["Max", "TLS", "Certs"]);
        // A digit-to-letter boundary is a word break too, so the Power Source cluster's
        // battery sizes split rather than becoming one opaque token.
        assert_eq!(words("1_2AA"), ["1", "2", "AA"]);
    }

    #[test]
    fn identifiers_come_out_legal() {
        assert_eq!(snake("On/Off"), "on_off");
        assert_eq!(snake("Level Control"), "level_control");
        assert_eq!(screaming("StartUpOnOff"), "START_UP_ON_OFF");
        assert_eq!(pascal("Level Control"), "LevelControl");
        assert_eq!(pascal("TLSCertificate"), "TLSCertificate");
        // A leading digit is illegal in Rust and common in the Power Source cluster.
        assert_eq!(pascal("1_2AA"), "N12AA");
        assert_eq!(pascal("18650"), "N18650");
        // Keywords really do appear as element names — but only in the case Rust reserves.
        // `Type` is a perfectly good type name; `type` is not, and `match` is not a module.
        assert_eq!(pascal("Type"), "Type");
        assert_eq!(snake("Type"), "type_");
        assert_eq!(snake("Match"), "match_");
    }

    #[test]
    fn a_collision_is_suffixed_rather_than_dropped() {
        // Two specification names can flatten to one identifier, and losing an element is the
        // one outcome a generator must never have.
        let mut names = vec!["Foo".to_owned(), "Foo".to_owned(), "Bar".to_owned()];
        unique(&mut names);
        assert_eq!(names, ["Foo", "Foo_2", "Bar"]);
    }
}
