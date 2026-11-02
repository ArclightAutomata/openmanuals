//! `om import-ia-legacy`: a one-time import of old-style archive.org items
//! (`manualslib-id-<n>`) that the ledger doesn't know yet.
//!
//! The extension used to ask archive.org live (check_identifier) whether such
//! an item exists, which takes seconds per page. With these items in the
//! ledger the server answers instead.
//!
//! For each missing item (listed with the search scrape API, compared with the
//! snapshot's archive.org locations), the item's metadata gives the file:
//! an original PDF, else the PDF archive.org derived (the 2020 batch is mostly
//! `.cbz` page images). Facts:
//!
//! - `manual` (+ `product`/`covers` from the item's `subject`, which reads
//!   "…; <Brand> Manuals\n<category>\n<model>") unless the snapshot already has
//!   the manual for that ManualsLib id;
//! - `file` keyed `sha1:<hex>` unless the snapshot has a file with that sha1;
//! - `manual_file` unless already attached;
//! - `location` (kind archive) for the item's file;
//! - `verified` only for items salli-cat uploaded itself and re-checked (the
//!   bootstrap's rule); everything else is left for the server's verifier.
//!
//! Read-only on the snapshot and on salli-cat's database.

use crate::migrate::{doc_type_of, manual_ulid};
use crate::{now, sign};
use anyhow::{bail, Context, Result};
use openmanuals_core::{sign::SigningKey, Fact};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const PREFIX: &str = "manualslib-id-";

/// What archive.org says about one item.
#[derive(Debug, Clone)]
pub struct Item {
    pub identifier: String,
    pub title: String,
    pub subject: String,
    pub source: Option<String>,
    pub added: Option<String>,
    /// The file to record: name, sha1, md5, size, and whether archive.org derived it.
    pub file: Option<(String, String, Option<String>, Option<i64>, bool)>,
}

impl Item {
    pub fn from_metadata(identifier: &str, v: &Value) -> Item {
        let md = &v["metadata"];
        let text = |x: &Value| match x {
            Value::String(s) => s.clone(),
            Value::Array(a) => a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join("; "),
            _ => String::new(),
        };
        let files = v["files"].as_array().cloned().unwrap_or_default();
        let pdf = |want_original: bool| {
            files.iter().filter(|f| {
                let name = f["name"].as_str().unwrap_or("");
                name.to_ascii_lowercase().ends_with(".pdf") && f["sha1"].is_string()
                    && (f["source"].as_str() == Some("original")) == want_original
            })
            .max_by_key(|f| f["size"].as_str().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0))
            .map(|f| (
                f["name"].as_str().unwrap().to_string(),
                f["sha1"].as_str().unwrap().to_ascii_lowercase(),
                f["md5"].as_str().map(str::to_ascii_lowercase),
                f["size"].as_str().and_then(|s| s.parse().ok()),
                !want_original,
            ))
        };
        Item {
            identifier: identifier.to_string(),
            title: clean(&text(&md["title"])),
            subject: text(&md["subject"]),
            source: md["source"].as_str().map(String::from),
            added: md["addeddate"].as_str().map(String::from),
            file: pdf(true).or_else(|| pdf(false)),
        }
    }

    pub fn manualslib_id(&self) -> Option<&str> {
        self.identifier.strip_prefix(PREFIX).filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    }

    /// Brand and model from the 2020 uploader's subject: "…; <Brand> Manuals\n<category>\n<model>".
    pub fn product(&self) -> Option<(String, String)> {
        let tail = self.subject.rsplit("; ").next()?;
        let lines: Vec<&str> = tail.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        let brand = lines.first()?.strip_suffix(" Manuals")?.trim();
        let model = lines.get(2)?.trim();
        (!brand.is_empty() && !model.is_empty()).then(|| (clean(brand), clean(model)))
    }
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// What the snapshot (and salli-cat) already know, for deciding which facts to add.
pub trait Known {
    fn manual_for(&self, manualslib_id: &str) -> Option<String>;
    fn file_by_sha1(&self, sha1: &str) -> Option<String>;
    fn attached(&self, manual: &str, file: &str) -> bool;
    /// salli-cat uploaded this item itself and re-checked it: when.
    fn salli_cat_checked(&self, manualslib_id: &str) -> Option<String>;
}

pub fn facts_for(key: &SigningKey, item: &Item, known: &dyn Known) -> Result<Vec<Fact>> {
    let Some(sid) = item.manualslib_id() else { return Ok(vec![]) };
    let Some((name, sha1, md5, size, _derived)) = item.file.clone() else { return Ok(vec![]) };
    let mut out = Vec::new();
    let manual = match known.manual_for(sid) {
        Some(m) => m,
        None => {
            let id = manual_ulid("manualslib", sid, item.added.as_deref());
            let title = if item.title.is_empty() { format!("ManualsLib manual {sid}") } else { item.title.clone() };
            // ManualsLib answers 404 for /manual/<id>/ without a page name.
            let source_url = item.source.clone().filter(|s| s.contains("manualslib.com/manual/")).unwrap_or_else(|| format!("https://www.manualslib.com/manual/{sid}/"));
            let source_url = openmanuals_core::ids::openable_source_url(&source_url, &title).into_owned();
            out.push(sign(key, "manual", json!({
                "id": id, "title": title, "doc_type": doc_type_of(&title), "doc_name": "",
                "source": "manualslib", "source_id": sid, "source_url": source_url.split('#').next().unwrap_or(&source_url),
            }))?);
            if let Some((brand, model)) = item.product() {
                if let Some(pkey) = openmanuals_core::product::product_key(&brand, &model) {
                    out.push(sign(key, "product", json!({"brand": brand, "model": model}))?);
                    out.push(sign(key, "covers", json!({"manual": id, "product": pkey}))?);
                }
            }
            id
        }
    };
    let file = match known.file_by_sha1(&sha1) {
        Some(f) => f,
        None => {
            out.push(sign(key, "file", json!({"sha1": sha1, "md5": md5, "size": size, "mime": "application/pdf"}))?);
            format!("sha1:{sha1}")
        }
    };
    if !known.attached(&manual, &file) {
        out.push(sign(key, "manual_file", json!({"manual": manual, "file": file, "role": "primary"}))?);
    }
    let url = format!("https://archive.org/download/{}/{}", item.identifier, urlencoding::encode(&name).replace("%2F", "/"));
    let loc = sign(key, "location", json!({"file": file, "url": url, "kind": "archive", "ia": {"identifier": item.identifier, "filename": name}}))?;
    let loc_id = loc.id()?;
    out.push(loc);
    if let Some(checked) = known.salli_cat_checked(sid) {
        out.push(sign(key, "verified", json!({"location": loc_id, "final_url": url, "sha256": null, "size": size, "checked_at": checked, "note": "salli-cat verify_ia_uploads"}))?);
    }
    Ok(out)
}

/// The snapshot and (optionally) salli-cat's database, both read-only.
pub struct Dbs {
    snapshot: Connection,
    salli_cat: Option<Connection>,
}

fn open_ro(p: &Path) -> Result<Connection> {
    Connection::open_with_flags(p, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).with_context(|| p.display().to_string())
}

impl Known for Dbs {
    fn manual_for(&self, sid: &str) -> Option<String> {
        self.snapshot.query_row("SELECT id FROM manuals WHERE source = 'manualslib' AND source_id = ?1 ORDER BY id LIMIT 1", [sid], |r| r.get(0)).optional().ok().flatten()
    }
    fn file_by_sha1(&self, sha1: &str) -> Option<String> {
        self.snapshot.query_row("SELECT id FROM files WHERE sha1 = ?1 LIMIT 1", [sha1], |r| r.get(0)).optional().ok().flatten()
    }
    fn attached(&self, manual: &str, file: &str) -> bool {
        self.snapshot.query_row("SELECT 1 FROM manual_files WHERE manual = ?1 AND file = ?2", [manual, file], |_| Ok(())).optional().ok().flatten().is_some()
    }
    fn salli_cat_checked(&self, sid: &str) -> Option<String> {
        let c = self.salli_cat.as_ref()?;
        let at: Option<String> = c.query_row(
            "SELECT archive_checked_at FROM manuals WHERE source = 'manualslib' AND manualslib_id = ?1 AND archived = 1 AND archived_by_us = 1 \
             AND coalesce(archive_dark, 0) = 0 AND archive_checked_at IS NOT NULL ORDER BY archive_checked_at DESC LIMIT 1",
            [sid], |r| r.get(0)).optional().ok().flatten();
        at.map(|s| {
            let t = s.trim().replace(' ', "T");
            let t = if t.ends_with('Z') || t.contains('+') { t } else { format!("{t}Z") };
            t.parse::<jiff::Timestamp>().map(|ts| ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_else(|_| now())
        })
    }
}

pub struct Options {
    pub snapshot: PathBuf,
    pub salli_cat_db: Option<PathBuf>,
    pub out: PathBuf,
    pub cache: PathBuf,
    pub jobs: usize,
    pub limit: Option<usize>,
    pub ia_api_base: String,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub on_ia: usize,
    pub known: usize,
    pub missing: usize,
    pub fetched: usize,
    pub no_pdf: usize,
    pub derived_pdf: usize,
    pub new_manuals: usize,
    pub verified: usize,
    pub facts: usize,
}

pub async fn run(key: &SigningKey, o: &Options) -> Result<Stats> {
    let client = reqwest::Client::builder().user_agent(format!("openmanuals-cli/{} (legacy import)", env!("CARGO_PKG_VERSION"))).build()?;
    let base = o.ia_api_base.trim_end_matches('/').to_string();
    let mut st = Stats::default();

    // 1. Every old-style item on archive.org.
    let mut ids: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut q = vec![("q", format!("identifier:{PREFIX}*")), ("fields", "identifier".into()), ("count", "10000".into())];
        if let Some(c) = &cursor {
            q.push(("cursor", c.clone()));
        }
        let v: Value = client.get(format!("{base}/services/search/v1/scrape")).query(&q).send().await?.error_for_status()?.json().await?;
        ids.extend(v["items"].as_array().into_iter().flatten().filter_map(|i| i["identifier"].as_str()).filter(|i| i.starts_with(PREFIX)).map(String::from));
        cursor = v["cursor"].as_str().map(String::from);
        if cursor.is_none() {
            break;
        }
    }
    ids.sort();
    ids.dedup();
    st.on_ia = ids.len();

    // 2. Minus what the snapshot already has.
    let dbs = Dbs { snapshot: open_ro(&o.snapshot)?, salli_cat: o.salli_cat_db.as_deref().map(open_ro).transpose()? };
    let known: HashSet<String> = dbs.snapshot.prepare("SELECT DISTINCT ia_identifier FROM locations WHERE ia_identifier IS NOT NULL")?
        .query_map([], |r| r.get::<_, String>(0))?.flatten().collect();
    let mut missing: Vec<String> = ids.into_iter().filter(|i| !known.contains(i)).collect();
    st.known = st.on_ia - missing.len();
    if let Some(n) = o.limit {
        missing.truncate(n);
    }
    st.missing = missing.len();
    eprintln!("{} old-style items on archive.org, {} already in the ledger, importing {}", st.on_ia, st.known, st.missing);

    // 3. Their metadata (cached on disk, so a re-run doesn't fetch again).
    std::fs::create_dir_all(&o.cache)?;
    let sem = Arc::new(tokio::sync::Semaphore::new(o.jobs.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for id in missing.clone() {
        let (client, base, sem, path) = (client.clone(), base.clone(), sem.clone(), o.cache.join(format!("{id}.json")));
        set.spawn(async move {
            if path.exists() {
                return Ok::<_, anyhow::Error>(());
            }
            let _p = sem.acquire().await?;
            for attempt in 0..4 {
                match client.get(format!("{base}/metadata/{id}")).send().await.and_then(|r| r.error_for_status()) {
                    Ok(r) => {
                        let body = r.bytes().await?;
                        std::fs::write(&path, &body)?;
                        return Ok(());
                    }
                    Err(e) if attempt == 3 => bail!("{id}: {e}"),
                    Err(_) => tokio::time::sleep(std::time::Duration::from_secs(5 << attempt)).await,
                }
            }
            Ok(())
        });
    }
    let mut done = 0;
    let mut failed = Vec::new();
    while let Some(r) = set.join_next().await {
        done += 1;
        if let Err(e) = r? {
            failed.push(e.to_string());
        }
        if done % 250 == 0 {
            eprintln!("  metadata {done}/{}", missing.len());
        }
    }
    if !failed.is_empty() {
        bail!("{} items' metadata couldn't be fetched (re-run to retry; cached ones are kept): {}", failed.len(), failed.iter().take(3).cloned().collect::<Vec<_>>().join("; "));
    }

    // 4. Facts.
    let mut w = std::io::BufWriter::new(std::fs::File::create(&o.out).with_context(|| o.out.display().to_string())?);
    let mut emitted_products: HashSet<String> = HashSet::new();
    for id in &missing {
        let v: Value = serde_json::from_slice(&std::fs::read(o.cache.join(format!("{id}.json")))?)?;
        st.fetched += 1;
        let item = Item::from_metadata(id, &v);
        match &item.file {
            None => {
                st.no_pdf += 1;
                continue;
            }
            Some(f) if f.4 => st.derived_pdf += 1,
            _ => {}
        }
        for f in facts_for(key, &item, &dbs)? {
            if f.r#type == "product" {
                let k = format!("{}|{}", f.body["brand"], f.body["model"]);
                if !emitted_products.insert(k) {
                    continue;
                }
            }
            match f.r#type.as_str() {
                "manual" => st.new_manuals += 1,
                "verified" => st.verified += 1,
                _ => {}
            }
            writeln!(w, "{}", f.to_json())?;
            st.facts += 1;
        }
    }
    w.flush()?;
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmanuals_core::Alg;

    struct Fake {
        manual: Option<&'static str>,
        file: Option<&'static str>,
        attached: bool,
        checked: Option<&'static str>,
    }
    impl Known for Fake {
        fn manual_for(&self, _: &str) -> Option<String> { self.manual.map(String::from) }
        fn file_by_sha1(&self, _: &str) -> Option<String> { self.file.map(String::from) }
        fn attached(&self, _: &str, _: &str) -> bool { self.attached }
        fn salli_cat_checked(&self, _: &str) -> Option<String> { self.checked.map(String::from) }
    }

    fn item_2020() -> Item {
        let v = json!({
            "metadata": {"title": "Philips 14PT135B/25 User Manual", "addeddate": "2020-08-15 09:59:53",
                "subject": "manualslib; manuals; Colour tv 14 inch; Philips Manuals\nTV\n14PT135B/25"},
            "files": [
                {"name": "176593.cbz", "source": "original", "sha1": "aa", "size": "1050563"},
                {"name": "176593.pdf", "source": "derivative", "format": "Text PDF", "sha1": "BB", "md5": "CC", "size": "612814"},
                {"name": "__ia_thumb.jpg", "source": "original", "sha1": "dd"}
            ]
        });
        Item::from_metadata("manualslib-id-176593", &v)
    }

    #[test]
    fn a_2020_item_becomes_a_manual_with_its_product_and_derived_pdf() {
        let key = SigningKey::generate(Alg::Ed25519);
        let item = item_2020();
        assert_eq!(item.product(), Some(("Philips".into(), "14PT135B/25".into())));
        assert_eq!(item.file.as_ref().unwrap().0, "176593.pdf", "the derived PDF when there's no original one");
        let facts = facts_for(&key, &item, &Fake { manual: None, file: None, attached: false, checked: None }).unwrap();
        let types: Vec<&str> = facts.iter().map(|f| f.r#type.as_str()).collect();
        assert_eq!(types, ["manual", "product", "covers", "file", "manual_file", "location"], "no verified: someone else's upload");
        assert_eq!(facts[0].body["source_id"], "176593");
        assert_eq!(facts[0].body["source_url"], "https://www.manualslib.com/manual/176593/Philips-14pt135b-25-User-Manual.html", "ManualsLib 404s without a page name");
        assert_eq!(facts[3].body["sha1"], "bb");
        assert_eq!(facts[5].body["ia"]["identifier"], "manualslib-id-176593");
        assert_eq!(facts[5].body["url"], "https://archive.org/download/manualslib-id-176593/176593.pdf");
    }

    #[test]
    fn a_salli_cat_upload_attaches_to_what_the_ledger_has_and_is_verified() {
        let key = SigningKey::generate(Alg::Ed25519);
        let v = json!({"metadata": {"title": "panasonic CT 25G7 operating instructions manual", "source": "https://www.manualslib.com/manual/1007421/Panasonic-Ct-25g7.html"},
            "files": [{"name": "ct25g7.pdf", "source": "original", "sha1": "ee", "md5": "ff", "size": "2709716"}]});
        let item = Item::from_metadata("manualslib-id-1007421", &v);
        let known = Fake { manual: Some("01M0BFBCZNP467MCEX3Y944FBF"), file: Some("abc123"), attached: true, checked: Some("2026-08-20T00:00:00Z") };
        let facts = facts_for(&key, &item, &known).unwrap();
        let types: Vec<&str> = facts.iter().map(|f| f.r#type.as_str()).collect();
        assert_eq!(types, ["location", "verified"]);
        assert_eq!(facts[0].body["file"], "abc123");
        assert_eq!(facts[1].body["location"], facts[0].id().unwrap());
    }

    #[test]
    fn items_without_a_pdf_or_a_numeric_id_are_skipped() {
        let key = SigningKey::generate(Alg::Ed25519);
        let none = Fake { manual: None, file: None, attached: false, checked: None };
        let v = json!({"metadata": {"title": "x"}, "files": [{"name": "a.cbz", "source": "original", "sha1": "aa"}]});
        assert!(facts_for(&key, &Item::from_metadata("manualslib-id-5", &v), &none).unwrap().is_empty());
        assert!(facts_for(&key, &Item::from_metadata("manualslib-id-x", &item_2020_json()), &none).unwrap().is_empty());
    }

    fn item_2020_json() -> Value {
        json!({"metadata": {"title": "t"}, "files": [{"name": "1.pdf", "source": "original", "sha1": "aa"}]})
    }
}
