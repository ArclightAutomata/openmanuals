//! archive.org identifiers and source-page keys.
//!
//! New uploads use `openmanuals-<sha256[:16]>-<ulid>`: the hash prefix groups
//! copies of the same bytes, the ULID makes every upload its own item.
//! Legacy items from salli-cat keep the deterministic per-source scheme
//! (`manualslib-id-<n>`, `elektrotanya-<slug>-<sha1[:8]>`), ported byte for byte
//! from `ia_uploader.py` / `extension/identifiers.js`.

use crate::{canon, Error, Result};

pub const IA_IDENTIFIER_MAX_LEN: usize = 100;
const SLUG_HASH_LEN: usize = 8;
pub const OM_PREFIX: &str = "openmanuals-";

/// What archive.org accepts: alphanumeric start, then alphanumerics/_/-/., 5-100 chars.
pub fn is_valid_identifier(id: &str) -> bool {
    let b = id.as_bytes();
    (5..=100).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b[1..].iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

/// Reduce text to `[a-zA-Z0-9_-]`: one `_` per other code point, runs collapsed, ends trimmed.
pub fn clean_identifier_chars(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_us = false;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
            last_us = false;
        } else if !last_us {
            out.push('_');
            last_us = true;
        }
    }
    out.trim_matches('_').to_string()
}

/// `<prefix>-<sanitized slug>-<sha1(raw slug)[:8]>`, truncating the readable part (never the hash).
pub fn slug_identifier(prefix: &str, slug: &str) -> String {
    let digest = &canon::sha1_hex(slug.as_bytes())[..SLUG_HASH_LEN];
    let mut readable = format!("{prefix}-{}", clean_identifier_chars(slug));
    let keep = IA_IDENTIFIER_MAX_LEN - digest.len() - 1;
    if readable.len() > keep {
        readable.truncate(keep);
        readable = readable.trim_end_matches(['_', '-']).to_string();
    }
    format!("{readable}-{digest}")
}

/// Legacy identifier for a `(source, source_id)` pair, if the source has a deterministic scheme.
pub fn legacy_identifier(source: &str, source_id: &str) -> Option<String> {
    if source_id.is_empty() {
        return None;
    }
    match source {
        "manualslib" => Some(format!("manualslib-id-{source_id}")),
        "manualsbase" => Some(format!("manualsbase-id-{source_id}")),
        "manualzz" => Some(format!("manualzz-id-{source_id}")),
        "elektrotanya" => Some(slug_identifier("elektrotanya", source_id)),
        _ => None,
    }
}

/// Identifier for a new upload: `openmanuals-<sha256 hex[:16]>-<ulid lowercase>`.
pub fn upload_identifier(sha256_hex: &str, ulid: &str) -> Result<String> {
    if sha256_hex.len() != 64 || !sha256_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Identifier("sha256 must be 64 hex chars".into()));
    }
    if ulid.len() != 26 || !ulid.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(Error::Identifier("ulid must be 26 alphanumeric chars".into()));
    }
    Ok(format!("{OM_PREFIX}{}-{}", &sha256_hex[..16].to_ascii_lowercase(), ulid.to_ascii_lowercase()))
}

/// Split an `openmanuals-…` identifier into `(sha256 prefix, ulid)`.
pub fn parse_upload_identifier(id: &str) -> Option<(&str, &str)> {
    let rest = id.strip_prefix(OM_PREFIX)?;
    let (h, u) = rest.split_once('-')?;
    (h.len() == 16 && u.len() == 26).then_some((h, u))
}

/// A page on a source site that keys a manual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePage {
    pub source: String,
    pub source_id: String,
    /// "manual" or, for ManualsLib's captcha page, "download".
    pub kind: String,
    pub slug: String,
}

/// Classify a URL on a supported site.
pub fn parse_page_url(url: &str) -> Option<SourcePage> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let rest = rest.strip_prefix("www.").unwrap_or(rest);
    let (host, path) = rest.split_once('/')?;
    let path = path.split(['?', '#']).next().unwrap_or("");
    match host.to_ascii_lowercase().as_str() {
        "manualslib.com" => {
            let mut it = path.splitn(3, '/');
            let kind = it.next()?.to_ascii_lowercase();
            if kind != "manual" && kind != "download" {
                return None;
            }
            let id = it.next()?;
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let slug = it.next().unwrap_or("").split('/').next().unwrap_or("").to_string();
            Some(SourcePage { source: "manualslib".into(), source_id: id.into(), kind, slug })
        }
        // /doc/<id>/<slug> (the manual) and /download/<id> (captcha, then a form post for the file).
        "manualzz.com" => {
            let mut it = path.splitn(3, '/');
            let kind = match it.next()?.to_ascii_lowercase().as_str() {
                "doc" => "manual",
                "download" => "download",
                _ => return None,
            };
            let id = it.next()?;
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let slug = it.next().unwrap_or("").split('/').next().unwrap_or("").to_string();
            Some(SourcePage { source: "manualzz".into(), source_id: id.into(), kind: kind.into(), slug })
        }
        "elektrotanya.com" => {
            let (slug, tail) = path.split_once('/')?;
            if slug.is_empty() || !tail.eq_ignore_ascii_case("download.html") && !tail.to_ascii_lowercase().starts_with("download.html") {
                return None;
            }
            Some(SourcePage { source: "elektrotanya".into(), source_id: slug.into(), kind: "manual".into(), slug: slug.into() })
        }
        _ => None,
    }
}

/// A ManualsLib page name from a title, in ManualsLib's style
/// ("Toshiba 27D46 Owner's Manual" → "Toshiba-27d46-Owner-S-Manual").
fn manualslib_page_name(title: &str) -> String {
    let words: Vec<String> = title
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .take(8)
        .map(|w| {
            let mut s = w.to_ascii_lowercase();
            s[..1].make_ascii_uppercase();
            s
        })
        .collect();
    if words.is_empty() { "Manual".into() } else { words.join("-") }
}

/// A source URL that opens in a browser. ManualsLib answers 404 for
/// `/manual/<id>/` with no page name, but redirects `/manual/<id>/<any>.html`
/// to the manual's page, so a URL without a name gets one made from `title`.
/// Manualzz serves `/doc/<id>` whatever follows the id, so a slug that was cut
/// short ("…-mx-5z...") is dropped. Every other URL is returned as it is.
pub fn openable_source_url<'a>(url: &'a str, title: &str) -> std::borrow::Cow<'a, str> {
    let bare = url.strip_suffix('/').unwrap_or(url);
    match parse_page_url(url) {
        Some(p) if p.source == "manualslib" && p.kind == "manual" && p.slug.is_empty() && bare.ends_with(&format!("/{}", p.source_id)) => {
            format!("https://www.manualslib.com/manual/{}/{}.html", p.source_id, manualslib_page_name(title)).into()
        }
        Some(p) if p.source == "manualzz" && p.kind == "manual" && p.slug.contains("..") => format!("https://manualzz.com/doc/{}", p.source_id).into(),
        _ => url.into(),
    }
}

/// Percent-decode `%XX` escapes; `None` when malformed or not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Elektrotanya spells the same slug with literal commas in search results and
/// `%2C` in sidebar links; both spellings are worth checking. Raw first.
pub fn slug_candidates(slug: &str) -> Vec<String> {
    let mut out = vec![slug.to_string()];
    if slug.contains('%') {
        if let Some(d) = percent_decode(slug) {
            if d != slug {
                out.push(d);
            }
        }
    }
    out
}

/// All legacy identifiers a page's manual could be stored under (usually one).
pub fn candidate_identifiers(page: &SourcePage) -> Vec<String> {
    if page.source == "elektrotanya" {
        slug_candidates(&page.source_id).iter().filter_map(|s| legacy_identifier("elektrotanya", s)).collect()
    } else {
        legacy_identifier(&page.source, &page.source_id).into_iter().collect()
    }
}

/// Version of the page-key derivation below; recorded in lookup filters
/// ([`crate::filter`]). Bump it whenever [`page_keys`] or [`source_key`] change.
pub const PAGE_KEY_VERSION: u8 = 1;

/// Lookup-filter key for a manual's `(source, source_id)`: `src:<source>:<source_id>`.
pub fn source_key(source: &str, source_id: &str) -> Option<String> {
    (!source.is_empty() && !source_id.is_empty()).then(|| format!("src:{source}:{source_id}"))
}

/// Lookup-filter keys for a page URL, mirroring how `GET /api/lookup?url=`
/// matches it: the fragment is dropped; a supported source page yields
/// `src:<source>:<source_id>` for each spelling the server tries (Elektrotanya
/// slugs raw and percent-decoded); any other URL yields `url:<url>`.
/// A page is (possibly) known when any of its keys is in the filter.
///
/// Snapshot side: every manual contributes [`source_key`] of its
/// `(source, source_id)` and `page_keys` of its `source_url`, and every
/// `origin` location contributes `page_keys` of its `url`. Both URL matches
/// in the server compare URLs whose fragment-less forms are equal, so equal
/// URLs always give equal keys.
pub fn page_keys(url: &str) -> Vec<String> {
    let clean = url.split('#').next().unwrap_or(url);
    match parse_page_url(clean) {
        Some(p) if p.source == "elektrotanya" => slug_candidates(&p.source_id).iter().filter_map(|s| source_key(&p.source, s)).collect(),
        Some(p) => source_key(&p.source, &p.source_id).into_iter().collect(),
        None if clean.is_empty() => Vec::new(),
        None => vec![format!("url:{clean}")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manualzz_pages() {
        let p = parse_page_url("https://manualzz.com/doc/6961161/hitachi-cm721f---19--crt-display-user-manual?lang=en").unwrap();
        assert_eq!((p.source.as_str(), p.source_id.as_str(), p.kind.as_str(), p.slug.as_str()), ("manualzz", "6961161", "manual", "hitachi-cm721f---19--crt-display-user-manual"));
        let d = parse_page_url("https://www.manualzz.com/download/6961161").unwrap();
        assert_eq!((d.source_id.as_str(), d.kind.as_str()), ("6961161", "download"));
        assert_eq!(page_keys("https://manualzz.com/doc/6961161/x#p3"), ["src:manualzz:6961161"]);
        assert_eq!(candidate_identifiers(&p), ["manualzz-id-6961161"]);
        for not in ["https://manualzz.com/brand/285687", "https://manualzz.com/doc/abc/x", "https://manualzz.com/catalog/tvs", "https://manualzz.com/download/check"] {
            assert_eq!(parse_page_url(not), None, "{not}");
        }
    }

    #[test]
    fn manualslib_urls_without_a_page_name_get_one() {
        assert_eq!(openable_source_url("https://www.manualslib.com/manual/3384/", "AIRLINK101 AWLC3026T User Manual"), "https://www.manualslib.com/manual/3384/Airlink101-Awlc3026t-User-Manual.html");
        assert_eq!(openable_source_url("https://www.manualslib.com/manual/3384", ""), "https://www.manualslib.com/manual/3384/Manual.html");
        assert_eq!(openable_source_url("https://www.manualslib.com/manual/1/", "Owner's Manual: TV — 27\"/32\""), "https://www.manualslib.com/manual/1/Owner-S-Manual-Tv-27-32.html");
        assert_eq!(openable_source_url("https://manualzz.com/doc/11228977/matsushita-electric-industrial-co.--ltd.-tc-21s85rq-mx-5z...", "T"), "https://manualzz.com/doc/11228977");
        for keep in ["https://manualzz.com/doc/6961161/hitachi-cm721f---19--crt-display-user-manual", "https://www.manualslib.com/manual/172144/Toshiba-27d46.html", "https://www.elektrotanya.com/x/download.html", "https://example.com/manual/1/"] {
            assert_eq!(openable_source_url(keep, "T"), keep);
        }
    }

    #[test]
    fn legacy_scheme_matches_salli_cat() {
        assert_eq!(legacy_identifier("manualslib", "331384").unwrap(), "manualslib-id-331384");
        assert_eq!(clean_identifier_chars("sony kv-1400 (sm).pdf"), "sony_kv-1400_sm_pdf");
        let id = slug_identifier("elektrotanya", "sony_kv-1400_sm.pdf");
        assert!(id.starts_with("elektrotanya-sony_kv-1400_sm_pdf-"));
        assert_eq!(id.len(), "elektrotanya-sony_kv-1400_sm_pdf-".len() + 8);
        let long = "x".repeat(200);
        let id = slug_identifier("elektrotanya", &long);
        assert_eq!(id.len(), 100);
        assert!(is_valid_identifier(&id));
    }

    #[test]
    fn upload_identifier_shape() {
        let id = upload_identifier(&"AB".repeat(32), "01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        assert_eq!(id, "openmanuals-abababababababab-01arz3ndektsv4rrffq69g5fav");
        assert!(is_valid_identifier(&id));
        assert_eq!(parse_upload_identifier(&id), Some(("abababababababab", "01arz3ndektsv4rrffq69g5fav")));
        assert!(upload_identifier("zz", "01ARZ3NDEKTSV4RRFFQ69G5FAV").is_err());
    }

    #[test]
    fn page_urls() {
        let p = parse_page_url("https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html?x=1").unwrap();
        assert_eq!((p.source.as_str(), p.source_id.as_str(), p.kind.as_str()), ("manualslib", "331384", "manual"));
        assert_eq!(p.slug, "Jvc-Av-2168tee.html");
        let d = parse_page_url("http://manualslib.com/download/331384/Jvc-Av-2168tee.html").unwrap();
        assert_eq!(d.kind, "download");
        let e = parse_page_url("https://elektrotanya.com/sony_kv-1400%2Csm.pdf/download.html#dl").unwrap();
        assert_eq!(e.source_id, "sony_kv-1400%2Csm.pdf");
        assert_eq!(slug_candidates(&e.source_id), vec!["sony_kv-1400%2Csm.pdf", "sony_kv-1400,sm.pdf"]);
        assert_eq!(candidate_identifiers(&e).len(), 2);
        assert!(parse_page_url("https://manualslib.com/brand/jvc/").is_none());
        assert!(parse_page_url("https://example.com/manual/1/x").is_none());
    }

    #[test]
    fn page_key_derivation() {
        assert_eq!(page_keys("https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html?page=2#manual"), vec!["src:manualslib:331384"]);
        assert_eq!(page_keys("http://manualslib.com/download/331384/Jvc-Av-2168tee.html"), vec!["src:manualslib:331384"]);
        assert_eq!(page_keys("https://elektrotanya.com/sony_kv-1400_sm.pdf/download.html"), vec!["src:elektrotanya:sony_kv-1400_sm.pdf"]);
        assert_eq!(
            page_keys("https://elektrotanya.com/sony_kv-1400%2Csm.pdf/download.html#dl"),
            vec!["src:elektrotanya:sony_kv-1400%2Csm.pdf", "src:elektrotanya:sony_kv-1400,sm.pdf"]
        );
        assert_eq!(page_keys("https://www.manualsbase.com/manual/1/x/#top"), vec!["url:https://www.manualsbase.com/manual/1/x/"]);
        assert!(page_keys("").is_empty());
        assert_eq!(source_key("manualsbase", "40978").unwrap(), "src:manualsbase:40978");
        assert_eq!(source_key("", "1"), None);
        // A row's source_url and the page it came from agree.
        let row = "https://www.manualslib.com/manual/1120951/Sharp-32jf-76e.html";
        assert_eq!(page_keys(row), vec![source_key("manualslib", "1120951").unwrap()]);
    }
}
