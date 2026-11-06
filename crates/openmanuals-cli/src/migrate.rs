//! salli-cat `manuals.db` → signed facts.
//!
//! Rows sharing a source document (`source` + `manualslib_id`/`source_id`)
//! become one `manual` with one `covers` edge per row. Files come from
//! `file_variants` (original/stripped/repaired) or the row's own checksums.
//! `--as-verified` only covers items salli-cat uploaded itself (`archived_by_us`).
//! Legacy files have no sha256 unless `--hash-local` can read the file, so they
//! are keyed `sha1:<hex>`; the build merges them with sha256-keyed facts for the
//! same bytes later. The manual ULID is derived from the row's scrape time and
//! a hash of its source key, so re-running the migration yields the same ids.

use crate::{now, sign};
use anyhow::{Context, Result};
use openmanuals_core::{sign::SigningKey, Fact};
use rusqlite::{Connection, OpenFlags};
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::Path;

/// What to import and what to leave out.
#[derive(Debug, Default)]
pub struct Options {
    pub hash_local: bool,
    pub as_verified: bool,
    pub limit: Option<usize>,
    /// Only rows from this source (`manuals.source`); filtered in SQL, so no
    /// other source's facts are signed.
    pub source: Option<String>,
    /// A snapshot of the ledger the facts are for: pages it already has a
    /// manual for (by `source`/`source_id`, or by an `origin` copy's page) are
    /// skipped, and products it has aren't signed again.
    pub known: Option<std::path::PathBuf>,
    /// Leave out rows salli-cat marked `unavailable` (no file at the source).
    pub skip_unavailable: bool,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub rows: usize,
    pub skipped_known: usize,
    pub manuals: usize,
    pub products: usize,
    pub covers: usize,
    pub files: usize,
    pub hashed_locally: usize,
    pub derivations: usize,
    pub origin_locations: usize,
    pub archive_locations: usize,
    pub verified: usize,
    pub dark: usize,
    pub facts: usize,
}

#[derive(Debug, Clone)]
struct Row {
    id: i64,
    brand: String,
    model: String,
    doc_type: Option<String>,
    doc_name: Option<String>,
    manual_url: String,
    source: String,
    source_key: String,
    file_path: Option<String>,
    file_sha1: Option<String>,
    file_md5: Option<String>,
    file_size: Option<i64>,
    original_file_sha1: Option<String>,
    original_file_md5: Option<String>,
    original_filename: Option<String>,
    archive_url: Option<String>,
    archived: bool,
    archive_dark: bool,
    archived_by_us: bool,
    archive_checked_at: Option<String>,
    scraped_at: Option<String>,
}

#[derive(Debug, Clone)]
struct Variant {
    variant_type: String,
    /// The stripper that made a stripped variant (`om-strip-rs/2`), when salli-cat recorded it.
    tool_version: Option<String>,
    file_path: String,
    sha1: String,
    md5: String,
    size: i64,
    is_primary: bool,
}

pub fn doc_type_of(raw: &str) -> &'static str {
    let s = raw.to_ascii_lowercase();
    if s.contains("service") || s.contains("repair") {
        "service"
    } else if s.contains("schematic") || s.contains("diagram") || s.contains("wiring") {
        "schematic"
    } else if s.contains("parts") {
        "parts"
    } else if ["user", "owner", "operat", "instruction", "quick", "reference", "manual", "guide", "handbook"].iter().any(|k| s.contains(k)) {
        "user"
    } else {
        "other"
    }
}

/// Deterministic ULID: timestamp from the scrape time, randomness from the source key.
pub fn manual_ulid(source: &str, source_key: &str, scraped_at: Option<&str>) -> String {
    let ts_ms: u64 = scraped_at
        .and_then(|s| {
            let s = s.trim().replace(' ', "T");
            let s = if s.ends_with('Z') || s.contains('+') { s } else { format!("{s}Z") };
            s.parse::<jiff::Timestamp>().ok().map(|t| t.as_millisecond() as u64)
        })
        .unwrap_or(1_700_000_000_000);
    let digest = openmanuals_core::canon::sha256_hex(format!("salli-cat:{source}:{source_key}").as_bytes());
    let rand = u128::from_str_radix(&digest[..20], 16).unwrap() & ((1u128 << 80) - 1);
    ulid::Ulid::from_parts(ts_ms, rand).to_string()
}

fn ts_rfc3339(s: &str) -> String {
    let t = s.trim().replace(' ', "T");
    let t = if t.ends_with('Z') || t.contains('+') { t } else { format!("{t}Z") };
    match t.parse::<jiff::Timestamp>() {
        Ok(ts) => ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
        Err(_) => now(),
    }
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string()
}

pub fn run(key: &SigningKey, db: &Path, out: &Path, o: &Options) -> Result<Stats> {
    let (hash_local, as_verified, limit) = (o.hash_local, o.as_verified, o.limit);
    let known = match &o.known {
        Some(p) => Known::load(p)?,
        None => Known::default(),
    };
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).with_context(|| db.display().to_string())?;
    let brand_names: BTreeMap<String, String> = conn
        .prepare("SELECT slug, name FROM brands")
        .and_then(|mut s| s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map(|rows| rows.flatten().collect()))
        .unwrap_or_default();
    let mut variants: BTreeMap<i64, Vec<Variant>> = BTreeMap::new();
    {
        let has_tool = conn.prepare("SELECT tool_version FROM file_variants LIMIT 0").is_ok();
        let sql = format!(
            "SELECT manual_id, variant_type, file_path, file_sha1, file_md5, file_size, is_primary, {} FROM file_variants",
            if has_tool { "tool_version" } else { "NULL" }
        );
        let mut s = conn.prepare(&sql)?;
        for r in s.query_map([], |r| Ok((r.get::<_, i64>(0)?, Variant { variant_type: r.get(1)?, file_path: r.get(2)?, sha1: r.get(3)?, md5: r.get(4)?, size: r.get(5)?, is_primary: r.get::<_, i64>(6)? == 1, tool_version: r.get(7)? })))? {
            let (mid, v) = r?;
            variants.entry(mid).or_default().push(v);
        }
    }
    let mut rows: Vec<Row> = Vec::new();
    {
        let mut wheres = Vec::new();
        let mut args: Vec<String> = Vec::new();
        if let Some(src) = &o.source {
            args.push(src.clone());
            wheres.push(format!("COALESCE(source, 'manualslib') = ?{}", args.len()));
        }
        if o.skip_unavailable {
            wheres.push("COALESCE(unavailable, 0) = 0".into());
        }
        let where_sql = if wheres.is_empty() { String::new() } else { format!("WHERE {}", wheres.join(" AND ")) };
        let mut s = conn.prepare(&format!(
            "SELECT id, brand, model, doc_type, doc_name, manual_url, source, COALESCE(manualslib_id, source_id, CAST(id AS TEXT)), file_path, file_sha1, file_md5, file_size,
                    original_file_sha1, original_file_md5, original_filename, archive_url, archived, archive_dark, archive_checked_at, COALESCE(scraped_at, created_at), archived_by_us
             FROM manuals {where_sql} ORDER BY id",
        ))?;
        for r in s.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(Row {
                id: r.get(0)?, brand: r.get(1)?, model: r.get(2)?, doc_type: r.get(3)?, doc_name: r.get(4)?, manual_url: r.get(5)?,
                source: r.get::<_, Option<String>>(6)?.unwrap_or_else(|| "manualslib".into()), source_key: r.get(7)?, file_path: r.get(8)?, file_sha1: r.get(9)?,
                file_md5: r.get(10)?, file_size: r.get(11)?, original_file_sha1: r.get(12)?, original_file_md5: r.get(13)?, original_filename: r.get(14)?,
                archive_url: r.get(15)?, archived: r.get::<_, Option<i64>>(16)?.unwrap_or(0) == 1, archive_dark: r.get::<_, Option<i64>>(17)?.unwrap_or(0) == 1,
                archive_checked_at: r.get(18)?, scraped_at: r.get(19)?, archived_by_us: r.get::<_, Option<i64>>(20)?.unwrap_or(0) == 1,
            })
        })? {
            rows.push(r?);
            if limit.is_some_and(|l| rows.len() >= l) {
                break;
            }
        }
    }
    let mut stats = Stats { rows: rows.len(), ..Default::default() };
    tracing::info!(rows = stats.rows, "read salli-cat rows");
    let mut groups: BTreeMap<(String, String), Vec<Row>> = BTreeMap::new();
    for r in rows {
        groups.entry((r.source.clone(), r.source_key.clone())).or_default().push(r);
    }

    let mut w = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut emitted_products: HashSet<String> = HashSet::new();
    let mut emitted_files: HashSet<String> = HashSet::new();
    let emit = |w: &mut std::io::BufWriter<std::fs::File>, stats: &mut Stats, f: Fact| -> Result<()> {
        writeln!(w, "{}", f.to_json())?;
        stats.facts += 1;
        Ok(())
    };

    for ((source, source_key), rows) in groups {
        let first = &rows[0];
        if known.has_page(&source, &source_key) {
            stats.skipped_known += 1;
            continue;
        }
        let fsm = (source == "freeservicemanuals").then(|| fsm_page(&first.manual_url)).flatten();
        let manual_id = manual_ulid(&source, &source_key, first.scraped_at.as_deref());
        let brand_display = |slug: &str| brand_names.get(slug).cloned().unwrap_or_else(|| {
            let mut c = slug.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        });
        let raw_doc = first.doc_type.clone().unwrap_or_default();
        let mut title = match &first.doc_name {
            Some(n) if !n.trim().is_empty() => clean(n),
            _ => clean(&format!("{} {} {}", brand_display(&first.brand), first.model, if raw_doc.is_empty() { "manual" } else { &raw_doc })),
        };
        let mut doc_type = doc_type_of(&raw_doc);
        // FreeServiceManuals.info: products and titles as the extension makes
        // them from the page (its URL holds the names in their own case).
        let mut products: Vec<(String, String)> = Vec::new();
        match &fsm {
            Some(FsmPage::Service { brand, models }) => {
                let brand = brand_names.get(&first.brand).cloned().unwrap_or_else(|| brand.clone());
                title = clean(&format!("{brand} {} Service Manual", models.join(" ")));
                if !fsm_no_brand(&brand) {
                    products = models.iter().map(|m| (brand.clone(), m.clone())).collect();
                }
            }
            Some(FsmPage::Book { publisher, title: t }) => {
                title = clean(t);
                doc_type = doc_type_of(t);
                if !fsm_no_brand(publisher) {
                    products = vec![(publisher.clone(), t.clone())];
                }
            }
            Some(FsmPage::Datasheet { part }) => {
                // No brand on a datasheet page, so no product (as the extension).
                title = clean(&format!("{part} datasheet"));
                doc_type = "other";
            }
            // salli-cat files brandless rows under "unknown": no product for those.
            None => products = rows.iter().filter(|r| r.brand != "unknown").map(|r| (brand_display(&r.brand), r.model.clone())).collect(),
        }
        emit(&mut w, &mut stats, sign(key, "manual", json!({
            "id": manual_id, "title": title, "doc_type": doc_type, "doc_name": raw_doc,
            "source": source, "source_id": source_key, "source_url": first.manual_url.split('#').next().unwrap_or(&first.manual_url),
        }))?)?;
        stats.manuals += 1;
        let mut covered: HashSet<String> = HashSet::new();
        for (brand, model) in &products {
            let (brand, model) = (clean(brand), clean(model));
            let Some(pkey) = openmanuals_core::product::product_key(&brand, &model) else { continue };
            if !covered.insert(pkey.clone()) {
                continue;
            }
            if !known.products.contains(&pkey) && emitted_products.insert(pkey.clone()) {
                emit(&mut w, &mut stats, sign(key, "product", json!({"brand": brand, "model": model}))?)?;
                stats.products += 1;
            }
            emit(&mut w, &mut stats, sign(key, "covers", json!({"manual": manual_id, "product": pkey}))?)?;
            stats.covers += 1;
        }

        // Files: union over the group's rows (they share the document, usually the same file).
        let mut files: BTreeMap<String, (String, Option<String>, Option<i64>, Option<String>, bool)> = BTreeMap::new(); // sha1 → (variant_type, md5, size, path, primary)
        let mut strip_tool: BTreeMap<String, String> = BTreeMap::new(); // sha1 → tool_version
        let mut archive_file: Option<String> = None;
        for r in &rows {
            if let Some(vs) = variants.get(&r.id) {
                for v in vs {
                    files.entry(v.sha1.clone()).or_insert((v.variant_type.clone(), Some(v.md5.clone()), Some(v.size), Some(v.file_path.clone()), v.is_primary));
                    if let Some(tv) = v.tool_version.as_ref().filter(|t| !t.trim().is_empty()) {
                        strip_tool.insert(v.sha1.clone(), tv.trim().to_string());
                    }
                    if v.is_primary {
                        archive_file = Some(v.sha1.clone());
                    }
                }
            }
            if let Some(s) = &r.file_sha1 {
                let is_stripped = r.original_file_sha1.as_ref().is_some_and(|o| o != s);
                files.entry(s.clone()).or_insert((if is_stripped { "stripped".into() } else { "original".into() }, r.file_md5.clone(), r.file_size, r.file_path.clone(), true));
                if archive_file.is_none() {
                    archive_file = Some(s.clone());
                }
                if let Some(o) = &r.original_file_sha1 {
                    if o != s {
                        files.entry(o.clone()).or_insert(("original".into(), r.original_file_md5.clone(), None, None, false));
                    }
                }
            }
        }
        let mut ids: BTreeMap<String, String> = BTreeMap::new(); // sha1 → file id
        for (sha1, (vt, md5, size, path, _)) in &files {
            let mut body = json!({"sha1": sha1, "md5": md5, "size": size, "mime": "application/pdf"});
            let mut id = format!("sha1:{sha1}");
            if hash_local {
                if let Some(p) = path.as_ref().map(Path::new).filter(|p| p.exists()) {
                    if let Ok((s256, s1, m5, sz)) = crate::hash_file(p) {
                        if &s1 == sha1 {
                            body = json!({"sha256": s256, "sha1": s1, "md5": m5, "size": sz, "mime": "application/pdf"});
                            id = s256;
                            stats.hashed_locally += 1;
                        }
                    }
                }
            }
            ids.insert(sha1.clone(), id.clone());
            if emitted_files.insert(id.clone()) {
                emit(&mut w, &mut stats, sign(key, "file", body)?)?;
                stats.files += 1;
            }
            emit(&mut w, &mut stats, sign(key, "manual_file", json!({"manual": manual_id, "file": id, "role": "primary"}))?)?;
            let _ = vt;
        }
        // Derivations: stripped/repaired → original.
        let original = files.iter().find(|(_, v)| v.0 == "original").map(|(s, _)| s.clone());
        if let Some(orig) = &original {
            for (sha1, (vt, ..)) in &files {
                if sha1 == orig {
                    continue;
                }
                let (transform, tool, version) = match (vt.as_str(), strip_tool.get(sha1)) {
                    // As the extension records it: tool "om-strip", version "om-strip-rs/2".
                    ("stripped", Some(v)) => ("watermark-stripped", tool_of(v), v.clone()),
                    ("stripped", None) => ("watermark-stripped", "salli-cat pdf_utils".into(), "salli-cat pdf_utils/1".into()),
                    ("repaired", _) => ("repaired", "qpdf".into(), "qpdf/1".into()),
                    _ => continue,
                };
                emit(&mut w, &mut stats, sign(key, "derivation", json!({"derived": ids[sha1], "source": ids[orig], "transform": transform, "tool": tool, "tool_version": version}))?)?;
                stats.derivations += 1;
            }
        }
        // Locations: origin for the original (or the only file), archive for the uploaded one.
        if let Some(orig) = original.clone().or_else(|| files.keys().next().cloned()) {
            for r in &rows {
                let url = r.manual_url.split('#').next().unwrap_or(&r.manual_url).to_string();
                emit(&mut w, &mut stats, sign(key, "location", json!({"file": ids[&orig], "url": url, "kind": "origin"}))?)?;
                stats.origin_locations += 1;
            }
        }
        if let (Some(af), Some(r)) = (archive_file.as_ref(), rows.iter().find(|r| r.archive_url.is_some())) {
            let archive_url = r.archive_url.clone().unwrap();
            let identifier = archive_url.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
            let filename = r.original_filename.clone();
            let download = match &filename {
                Some(f) => format!("https://archive.org/download/{identifier}/{}", urlencoding::encode(f)),
                None => format!("https://archive.org/download/{identifier}"),
            };
            let loc = sign(key, "location", json!({"file": ids[af], "url": download, "kind": "archive", "ia": {"identifier": identifier, "filename": filename}}))?;
            let loc_id = loc.id()?;
            emit(&mut w, &mut stats, loc)?;
            stats.archive_locations += 1;
            // Only copies salli-cat itself uploaded and re-checked are known to be these bytes;
            // items uploaded by others are left for the verifier.
            if as_verified && r.archived && r.archived_by_us {
                let checked = r.archive_checked_at.as_deref().map(ts_rfc3339).unwrap_or_else(now);
                if r.archive_dark {
                    emit(&mut w, &mut stats, sign(key, "location_status", json!({"location": loc_id, "status": "dark", "checked_at": checked}))?)?;
                    stats.dark += 1;
                } else if r.archive_checked_at.is_some() {
                    let size = files.get(af).and_then(|v| v.2);
                    emit(&mut w, &mut stats, sign(key, "verified", json!({"location": loc_id, "final_url": download, "sha256": null, "size": size, "checked_at": checked, "note": "salli-cat verify_ia_uploads"}))?)?;
                    stats.verified += 1;
                }
            }
        }
    }
    w.flush()?;
    Ok(stats)
}

/// The tool name of a stripper version: `om-strip-rs/2` → `om-strip` (as the
/// extension records it), otherwise the part before the `/`.
fn tool_of(version: &str) -> String {
    let name = version.split('/').next().unwrap_or(version);
    if name.starts_with("om-strip") { "om-strip".into() } else { name.into() }
}

/// The site's placeholders where a brand or publisher goes ("None", "??",
/// "Miscellaneous"): no product is made under those (as the extension).
fn fsm_no_brand(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    n.is_empty() || !n.chars().any(char::is_alphanumeric) || ["none", "unknown", "miscellaneous", "various"].contains(&n.as_str())
}

/// What a FreeServiceManuals.info page URL says about its manual.
#[derive(Debug, PartialEq)]
enum FsmPage {
    /// `/servicemanuals/viewmanual/<Brand>/<Type A>/<Type B>/…/`: every type
    /// number the manual covers ("None" and "freeservicemanual" fill unused slots).
    Service { brand: String, models: Vec<String> },
    /// `/bookcats/<Publisher>/<Author>/<Title>/`.
    Book { publisher: String, title: String },
    /// `/tubedata/<Type>/` or `/datasheets/<Type>/`.
    Datasheet { part: String },
}

fn fsm_page(url: &str) -> Option<FsmPage> {
    let path = url.split(['?', '#']).next()?.split_once("freeservicemanuals.info/")?.1;
    let segs: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| urlencoding::decode(&s.replace('+', " ")).map(|d| d.split_whitespace().collect::<Vec<_>>().join(" ")).unwrap_or_else(|_| s.to_string()))
        .collect();
    let segs: Vec<&str> = segs.iter().map(String::as_str).skip_while(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic())).collect();
    let filler = |s: &&str| s.eq_ignore_ascii_case("none") || s.eq_ignore_ascii_case("freeservicemanual") || s.is_empty();
    match segs.as_slice() {
        [s, v, brand, models @ ..] if s.eq_ignore_ascii_case("servicemanuals") && v.eq_ignore_ascii_case("viewmanual") && !models.is_empty() => {
            let models: Vec<String> = models.iter().filter(|m| !filler(m)).map(|m| m.to_string()).collect();
            Some(FsmPage::Service { brand: brand.to_string(), models })
        }
        [s, publisher, _author, title] if s.eq_ignore_ascii_case("bookcats") => Some(FsmPage::Book { publisher: publisher.to_string(), title: title.to_string() }),
        [s, part] if s.eq_ignore_ascii_case("tubedata") || s.eq_ignore_ascii_case("datasheets") => Some(FsmPage::Datasheet { part: part.to_string() }),
        _ => None,
    }
}

/// What the target snapshot already has.
#[derive(Default)]
struct Known {
    /// `source\0source_id` of every manual's page, from its facts or its origin copies.
    pages: HashSet<String>,
    products: HashSet<String>,
}

impl Known {
    fn load(snapshot: &Path) -> Result<Known> {
        let db = Connection::open_with_flags(snapshot, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).with_context(|| snapshot.display().to_string())?;
        let mut k = Known::default();
        let mut s = db.prepare("SELECT source, source_id FROM manuals WHERE source IS NOT NULL AND source_id IS NOT NULL")?;
        for r in s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (src, id) = r?;
            k.pages.insert(format!("{src}\0{id}"));
        }
        // An upload whose manual fact named no page still has its origin copy.
        let mut s = db.prepare("SELECT url FROM locations WHERE kind = 'origin'")?;
        for url in s.query_map([], |r| r.get::<_, String>(0))? {
            if let Some(p) = openmanuals_core::ids::parse_page_url(&url?) {
                k.pages.insert(format!("{}\0{}", p.source, p.source_id));
            }
        }
        let mut s = db.prepare("SELECT key FROM products")?;
        for key in s.query_map([], |r| r.get::<_, String>(0))? {
            k.products.insert(key?);
        }
        tracing::info!(pages = k.pages.len(), products = k.products.len(), "loaded the target snapshot");
        Ok(k)
    }

    fn has_page(&self, source: &str, source_id: &str) -> bool {
        self.pages.contains(&format!("{source}\0{source_id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_ulids_and_doc_types() {
        let a = manual_ulid("manualslib", "331384", Some("2026-01-05 19:18:15"));
        assert_eq!(a, manual_ulid("manualslib", "331384", Some("2026-01-05 19:18:15")));
        assert_ne!(a, manual_ulid("manualslib", "331385", Some("2026-01-05 19:18:15")));
        assert!(a.parse::<ulid::Ulid>().is_ok());
        assert_eq!(doc_type_of("Service manual"), "service");
        assert_eq!(doc_type_of("Owner's instructions manual"), "user");
        assert_eq!(doc_type_of("Specifications"), "other");
    }

    #[test]
    fn freeservicemanuals_pages_name_what_the_extension_would() {
        let svc = |brand: &str, models: &[&str]| FsmPage::Service { brand: brand.into(), models: models.iter().map(|m| m.to_string()).collect() };
        assert_eq!(fsm_page("https://freeservicemanuals.info/en/servicemanuals/viewmanual/Philips/14PV100/51TVB61/37TR216/DELTA2000/"), Some(svc("Philips", &["14PV100", "51TVB61", "37TR216", "DELTA2000"])));
        assert_eq!(fsm_page("https://freeservicemanuals.info/en/servicemanuals/viewmanual/Philips/15GR2336/None/None/G90B/"), Some(svc("Philips", &["15GR2336", "G90B"])));
        assert_eq!(fsm_page("https://freeservicemanuals.info/en/servicemanuals/viewmanual/Acer/7176I/None/freeservicemanual/"), Some(svc("Acer", &["7176I"])));
        assert_eq!(fsm_page("https://www.freeservicemanuals.info/en/servicemanuals/viewmanual/Sony/M1000/"), Some(svc("Sony", &["M1000"])));
        assert_eq!(
            fsm_page("https://freeservicemanuals.info/en/bookcats/DIGITAL%20PROCESSING%20SYSTEMS/TBC%20FRAMESTORE/DPS-375/"),
            Some(FsmPage::Book { publisher: "DIGITAL PROCESSING SYSTEMS".into(), title: "DPS-375".into() })
        );
        assert_eq!(fsm_page("https://freeservicemanuals.info/en/tubedata/1N4001G_1/"), Some(FsmPage::Datasheet { part: "1N4001G_1".into() }));
        assert_eq!(fsm_page("https://freeservicemanuals.info/en/contact/"), None);
        assert!(fsm_no_brand("None") && fsm_no_brand("??") && fsm_no_brand("Miscellaneous") && !fsm_no_brand("Philips"));
        assert_eq!(tool_of("om-strip-rs/2"), "om-strip");
        assert_eq!(tool_of("qpdf/11"), "qpdf");
    }
}
