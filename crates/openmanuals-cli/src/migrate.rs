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

#[derive(Debug, Default)]
pub struct Stats {
    pub rows: usize,
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

pub fn run(key: &SigningKey, db: &Path, out: &Path, hash_local: bool, as_verified: bool, limit: Option<usize>) -> Result<Stats> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).with_context(|| db.display().to_string())?;
    let brand_names: BTreeMap<String, String> = conn
        .prepare("SELECT slug, name FROM brands")
        .and_then(|mut s| s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map(|rows| rows.flatten().collect()))
        .unwrap_or_default();
    let mut variants: BTreeMap<i64, Vec<Variant>> = BTreeMap::new();
    {
        let mut s = conn.prepare("SELECT manual_id, variant_type, file_path, file_sha1, file_md5, file_size, is_primary FROM file_variants")?;
        for r in s.query_map([], |r| Ok((r.get::<_, i64>(0)?, Variant { variant_type: r.get(1)?, file_path: r.get(2)?, sha1: r.get(3)?, md5: r.get(4)?, size: r.get(5)?, is_primary: r.get::<_, i64>(6)? == 1 })))? {
            let (mid, v) = r?;
            variants.entry(mid).or_default().push(v);
        }
    }
    let mut rows: Vec<Row> = Vec::new();
    {
        let mut s = conn.prepare(
            "SELECT id, brand, model, doc_type, doc_name, manual_url, source, COALESCE(manualslib_id, source_id, CAST(id AS TEXT)), file_path, file_sha1, file_md5, file_size,
                    original_file_sha1, original_file_md5, original_filename, archive_url, archived, archive_dark, archive_checked_at, COALESCE(scraped_at, created_at), archived_by_us
             FROM manuals ORDER BY id",
        )?;
        for r in s.query_map([], |r| {
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
        let manual_id = manual_ulid(&source, &source_key, first.scraped_at.as_deref());
        let brand_display = |slug: &str| brand_names.get(slug).cloned().unwrap_or_else(|| {
            let mut c = slug.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        });
        let raw_doc = first.doc_type.clone().unwrap_or_default();
        let title = match &first.doc_name {
            Some(n) if !n.trim().is_empty() => clean(n),
            _ => clean(&format!("{} {} {}", brand_display(&first.brand), first.model, if raw_doc.is_empty() { "manual" } else { &raw_doc })),
        };
        emit(&mut w, &mut stats, sign(key, "manual", json!({
            "id": manual_id, "title": title, "doc_type": doc_type_of(&raw_doc), "doc_name": raw_doc,
            "source": source, "source_id": source_key, "source_url": first.manual_url.split('#').next().unwrap_or(&first.manual_url),
        }))?)?;
        stats.manuals += 1;
        for r in &rows {
            let brand = brand_display(&r.brand);
            let model = clean(&r.model);
            let Some(pkey) = openmanuals_core::product::product_key(&brand, &model) else { continue };
            if emitted_products.insert(pkey.clone()) {
                emit(&mut w, &mut stats, sign(key, "product", json!({"brand": brand, "model": model}))?)?;
                stats.products += 1;
            }
            emit(&mut w, &mut stats, sign(key, "covers", json!({"manual": manual_id, "product": pkey}))?)?;
            stats.covers += 1;
        }

        // Files: union over the group's rows (they share the document, usually the same file).
        let mut files: BTreeMap<String, (String, Option<String>, Option<i64>, Option<String>, bool)> = BTreeMap::new(); // sha1 → (variant_type, md5, size, path, primary)
        let mut archive_file: Option<String> = None;
        for r in &rows {
            if let Some(vs) = variants.get(&r.id) {
                for v in vs {
                    files.entry(v.sha1.clone()).or_insert((v.variant_type.clone(), Some(v.md5.clone()), Some(v.size), Some(v.file_path.clone()), v.is_primary));
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
                let (transform, tool) = match vt.as_str() {
                    "stripped" => ("watermark-stripped", "salli-cat pdf_utils"),
                    "repaired" => ("repaired", "qpdf"),
                    _ => continue,
                };
                emit(&mut w, &mut stats, sign(key, "derivation", json!({"derived": ids[sha1], "source": ids[orig], "transform": transform, "tool": tool, "tool_version": format!("{tool}/1")}))?)?;
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
}
