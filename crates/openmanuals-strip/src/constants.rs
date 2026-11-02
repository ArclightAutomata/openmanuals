//! The detection constants in `constants.json` and the Python-syntax regexes
//! they hold.
//!
//! Every pattern runs on raw bytes with Python's `bytes` regex semantics:
//! `.` matches any byte, and `\s`, `\d`, `\b` and IGNORECASE are ASCII-only.
//! A pattern compiles with the `regex` crate in `(?-u)` mode, or, when it
//! needs lookaround (`stamp_text_object`), with fancy-regex in its ASCII
//! bytes mode. `on: "text"` patterns are meant for a latin-1 decoded `str`,
//! where `\s` also matches `\x1c-\x1f`, `\x85` and `\xa0`; `\s` is widened
//! accordingly. (Limits: a `text` pattern using IGNORECASE or `\w`/`\b` on
//! non-ASCII latin-1 letters would need more translation, and fancy-regex
//! cannot express raw bytes >= 0x80; no pattern in constants.json needs either.)

use fancy_regex::{BytesMode, RegexBuilder};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const CONSTANTS_JSON: &str = include_str!("../constants.json");

#[derive(Deserialize, Debug, Clone)]
pub struct RegexSpec {
    pub pattern: String,
    pub flags: String,
    pub on: String,
}

#[derive(Deserialize, Debug)]
pub struct Raw {
    pub manualslib_footer: RegexSpec,
    pub max_wrapper_pages: usize,
    pub wkhtmltopdf_preamble: RegexSpec,
    pub third_party_stamp: RegexSpec,
    pub stamp_text_object: RegexSpec,
    pub max_stamp_form_bytes: usize,
    pub junk_cover_hashes: BTreeMap<String, String>,
    pub junk_cover_max_distance: u32,
    pub stamp_image_hashes: BTreeMap<String, String>,
    pub stamp_image_max_distance: u32,
    pub stamp_image_min_aspect: f64,
}

pub struct Constants {
    pub footer: Regex,
    pub preamble: Regex,
    pub third_party: Regex,
    pub stamp_text_object: Regex,
    pub max_wrapper_pages: usize,
    pub max_stamp_form_bytes: usize,
    pub junk_cover_hashes: Vec<(u64, String)>,
    pub junk_cover_max_distance: u32,
    pub stamp_image_hashes: Vec<(u64, String)>,
    pub stamp_image_max_distance: u32,
    pub stamp_image_min_aspect: f64,
}

/// Python `str` `\s` for latin-1 text, as a class body.
const TEXT_WS: &str = r"\t\n\x0b\x0c\r \x1c-\x1f\x85\xa0";

/// The fancy-regex backtracking budget per search. Python has none; only the
/// stamp text-object pattern backtracks, and only on pages naming a stamp site.
const BACKTRACK_LIMIT: usize = 50_000_000;

/// Translate `\s` for `text` patterns (inside or outside a character class).
pub fn translate(spec: &RegexSpec) -> String {
    if spec.on != "text" {
        return spec.pattern.clone();
    }
    let mut out = String::with_capacity(spec.pattern.len() + 32);
    let mut chars = spec.pattern.chars();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('s') if in_class => out.push_str(TEXT_WS),
                Some('s') => {
                    out.push('[');
                    out.push_str(TEXT_WS);
                    out.push(']');
                }
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            },
            '[' if !in_class => {
                in_class = true;
                out.push(c);
                // A leading ']' (or '^]') is literal.
                let rest = chars.as_str();
                for lit in ["^]", "]"] {
                    if let Some(after) = rest.strip_prefix(lit) {
                        out.push_str(lit);
                        chars = after.chars();
                        break;
                    }
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// A compiled bytes pattern.
pub enum Regex {
    Plain(regex::bytes::Regex),
    Fancy(fancy_regex::Regex),
}

pub fn compile(spec: &RegexSpec) -> Result<Regex, String> {
    bytes_regex(
        &translate(spec),
        spec.flags.contains('s'),
        spec.flags.contains('i'),
    )
}

pub fn bytes_regex(pattern: &str, dotall: bool, icase: bool) -> Result<Regex, String> {
    let plain = regex::bytes::RegexBuilder::new(&format!("(?-u:{pattern})"))
        .unicode(false)
        .dot_matches_new_line(dotall)
        .case_insensitive(icase)
        .size_limit(64 << 20)
        .build();
    if let Ok(re) = plain {
        return Ok(Regex::Plain(re));
    }
    RegexBuilder::new(pattern)
        .bytes_mode(BytesMode::Ascii)
        .dot_matches_new_line(dotall)
        .case_insensitive(icase)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map(Regex::Fancy)
        .map_err(|e| format!("{pattern}: {e}"))
}

fn hashes(m: &BTreeMap<String, String>) -> Vec<(u64, String)> {
    m.iter()
        .filter_map(|(h, l)| Some((u64::from_str_radix(h, 16).ok()?, l.clone())))
        .collect()
}

pub fn parse(json: &str) -> Result<Constants, String> {
    let raw: Raw = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(Constants {
        footer: compile(&raw.manualslib_footer)?,
        preamble: compile(&raw.wkhtmltopdf_preamble)?,
        third_party: compile(&raw.third_party_stamp)?,
        stamp_text_object: compile(&raw.stamp_text_object)?,
        max_wrapper_pages: raw.max_wrapper_pages,
        max_stamp_form_bytes: raw.max_stamp_form_bytes,
        junk_cover_hashes: hashes(&raw.junk_cover_hashes),
        junk_cover_max_distance: raw.junk_cover_max_distance,
        stamp_image_hashes: hashes(&raw.stamp_image_hashes),
        stamp_image_max_distance: raw.stamp_image_max_distance,
        stamp_image_min_aspect: raw.stamp_image_min_aspect,
    })
}

/// The compiled constants. They are part of the crate, so a failure here is a
/// build defect caught by the tests, not an input problem.
pub fn get() -> &'static Constants {
    static C: OnceLock<Constants> = OnceLock::new();
    C.get_or_init(|| parse(CONSTANTS_JSON).expect("constants.json"))
}

/// Whether the pattern matches anywhere (a search error counts as no match).
pub fn is_match(re: &Regex, data: &[u8]) -> bool {
    match re {
        Regex::Plain(r) => r.is_match(data),
        Regex::Fancy(r) => r.is_match(data).unwrap_or(false),
    }
}

/// Match spans, left to right and non-overlapping; `None` if the search gave up.
pub fn find_spans(re: &Regex, data: &[u8]) -> Option<Vec<(usize, usize)>> {
    match re {
        Regex::Plain(r) => Some(r.find_iter(data).map(|m| (m.start(), m.end())).collect()),
        Regex::Fancy(r) => r
            .find_iter(data)
            .map(|m| m.map(|m| (m.start(), m.end())).ok())
            .collect(),
    }
}

/// Python `re.sub(pattern, b'', data)`; `None` when nothing matched or the
/// search gave up (backtracking budget), in which case the data is left alone.
pub fn remove_all(re: &Regex, data: &[u8]) -> Option<Vec<u8>> {
    cut_spans(data, &find_spans(re, data)?)
}

/// `data` without the given sorted, non-overlapping spans; `None` if that removes nothing.
pub fn cut_spans(data: &[u8], spans: &[(usize, usize)]) -> Option<Vec<u8>> {
    if spans.iter().all(|(s, e)| s == e) {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut last = 0;
    for &(s, e) in spans {
        out.extend_from_slice(&data[last..s]);
        last = e;
    }
    out.extend_from_slice(&data[last..]);
    Some(out)
}
