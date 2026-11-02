//! Re-stripping files published before the current stripper.
//!
//! `om restrip-scan` reads the bootstrap import's source database (read-only)
//! and, for each ManualsLib file it uploaded to archive.org, runs the current
//! stripper on the original and checks what the published file still carries
//! (ManualsLib wrapper pages, footers, links, stamps). `om restrip` then
//! replaces the published file in its archive.org item (same filename),
//! updates the item's `external-identifier`, and queues the facts that record
//! the new bytes. The ledger never edits a fact: the new bytes are a new
//! file, and the verifier marks the old location `changed` when it sees
//! different bytes at the URL.

use crate::{sign, Home};
use anyhow::{anyhow, bail, Context, Result};
use openmanuals_core::canon::{md5_hex, sha1_hex, sha256_hex};
use openmanuals_core::{sign::SigningKey, Fact};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One published ManualsLib file the import uploaded to archive.org.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub manual: String,
    pub manualslib_id: String,
    pub identifier: String,
    pub filename: String,
    pub published_sha1: String,
    pub published_path: Option<PathBuf>,
    pub original_sha1: Option<String>,
    pub original_path: Option<PathBuf>,
}

/// What a scan found for a file that should be re-stripped (one report line).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub manual: String,
    pub manualslib_id: String,
    pub identifier: String,
    pub filename: String,
    /// The archive.org download URL (same before and after).
    pub url: String,
    pub old_sha1: String,
    pub old_sha256: String,
    /// What the new file is stripped from: "original", or "published" when
    /// the original isn't available locally.
    pub from: String,
    pub source_sha1: String,
    pub source_sha256: String,
    pub source_path: PathBuf,
    pub new_sha256: String,
    pub new_size: usize,
    pub published_pages: usize,
    pub new_pages: usize,
    /// Human-readable list of what the re-strip removes from the published file.
    pub changes: Vec<String>,
    /// Machine-readable tags for counting: wrapper-leading, wrapper-trailing,
    /// footer, links, stamp, never-stripped.
    pub kinds: Vec<String>,
}

/// The scan's verdict on one candidate.
#[derive(Debug)]
pub enum Outcome {
    Restrip(Box<Finding>),
    Clean,
    PublishedMissing,
    /// The published file on disk isn't the bytes the database says were uploaded.
    HashMismatch,
    Unreadable(String),
}

fn open_ro(db: &Path) -> Result<Connection> {
    Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).with_context(|| db.display().to_string())
}

/// Resolve a path recorded in the database: as is when it exists, else under `root`.
fn resolve(p: &str, root: Option<&Path>) -> Option<PathBuf> {
    let path = PathBuf::from(p);
    if path.is_absolute() && path.exists() {
        return Some(path);
    }
    let root = root?;
    let rel = path.strip_prefix("/").unwrap_or(&path);
    let joined = root.join(rel);
    if joined.exists() {
        return Some(joined);
    }
    // An absolute path from another machine: try its tail after "downloads/".
    let s = p.replace('\\', "/");
    s.find("downloads/").map(|i| root.join(&s[i..])).filter(|j| j.exists())
}

/// The archive.org download URL of a file in an item, as the import recorded it.
pub fn download_url(identifier: &str, filename: &str) -> String {
    format!("https://archive.org/download/{identifier}/{}", urlencoding::encode(filename))
}

/// ManualsLib files the import uploaded itself (`archived_by_us`), one per
/// source document, with the paths of the published and original bytes.
/// Manual ids are derived as the migration does.
pub fn candidates(db: &Path, files_root: Option<&Path>) -> Result<Vec<Candidate>> {
    let conn = open_ro(db)?;
    let mut variants: HashMap<i64, Vec<(String, String, String, bool)>> = HashMap::new(); // manual row → (type, path, sha1, primary)
    {
        let mut s = conn.prepare("SELECT manual_id, variant_type, file_path, file_sha1, is_primary FROM file_variants")?;
        for r in s.query_map([], |r| Ok((r.get::<_, i64>(0)?, (r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)? == 1))))? {
            let (id, v) = r?;
            variants.entry(id).or_default().push(v);
        }
    }
    struct Row {
        id: i64,
        key: String,
        scraped_at: Option<String>,
        file_path: Option<String>,
        file_sha1: Option<String>,
        original_sha1: Option<String>,
        filename: Option<String>,
        archive_url: Option<String>,
        ours: bool,
    }
    let mut groups: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    {
        let mut s = conn.prepare(
            "SELECT id, COALESCE(manualslib_id, source_id, CAST(id AS TEXT)), COALESCE(scraped_at, created_at), file_path, file_sha1, original_file_sha1,
                    original_filename, archive_url, COALESCE(archived_by_us, 0)
             FROM manuals WHERE COALESCE(source, 'manualslib') = 'manualslib' ORDER BY id",
        )?;
        for r in s.query_map([], |r| {
            Ok(Row {
                id: r.get(0)?, key: r.get(1)?, scraped_at: r.get(2)?, file_path: r.get(3)?, file_sha1: r.get(4)?, original_sha1: r.get(5)?,
                filename: r.get(6)?, archive_url: r.get(7)?, ours: r.get::<_, i64>(8)? == 1,
            })
        })? {
            let r = r?;
            groups.entry(r.key.clone()).or_default().push(r);
        }
    }
    let mut out = Vec::new();
    for (key, rows) in groups {
        // The migration names the item from the first row with an archive URL.
        let Some(up) = rows.iter().find(|r| r.archive_url.is_some()) else { continue };
        if !up.ours {
            continue; // someone else's item: not ours to replace
        }
        let (Some(archive_url), Some(filename)) = (up.archive_url.as_deref(), up.filename.clone()) else { continue };
        let identifier = archive_url.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
        if identifier.is_empty() {
            continue;
        }
        // sha1 → (variant type, path); the published file is the primary variant, else the row's file.
        let mut files: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
        let mut published: Option<String> = None;
        for r in &rows {
            for (vt, path, sha1, primary) in variants.get(&r.id).map(Vec::as_slice).unwrap_or_default() {
                files.entry(sha1.clone()).or_insert((vt.clone(), Some(path.clone())));
                if *primary {
                    published = Some(sha1.clone());
                }
            }
            if let Some(s) = &r.file_sha1 {
                let stripped = r.original_sha1.as_ref().is_some_and(|o| o != s);
                files.entry(s.clone()).or_insert((if stripped { "stripped".into() } else { "original".into() }, r.file_path.clone()));
                if published.is_none() {
                    published = Some(s.clone());
                }
                if let Some(o) = &r.original_sha1 {
                    files.entry(o.clone()).or_insert(("original".into(), None));
                }
            }
        }
        let Some(published_sha1) = published else { continue };
        let original_sha1 = files.iter().find(|(_, v)| v.0 == "original").map(|(s, _)| s.clone());
        let path_of = |sha1: &str| files.get(sha1).and_then(|v| v.1.as_deref()).and_then(|p| resolve(p, files_root));
        out.push(Candidate {
            manual: crate::migrate::manual_ulid("manualslib", &key, rows[0].scraped_at.as_deref()),
            manualslib_id: key,
            identifier,
            filename,
            published_path: path_of(&published_sha1),
            original_path: original_sha1.as_deref().and_then(path_of),
            original_sha1,
            published_sha1,
        });
    }
    Ok(out)
}

/// Run the current stripper on a candidate and decide whether its published
/// file needs replacing. Read-only.
pub fn examine(c: &Candidate) -> Outcome {
    match examine_inner(c) {
        Ok(o) => o,
        Err(e) => Outcome::Unreadable(format!("{e:#}")),
    }
}

fn examine_inner(c: &Candidate) -> Result<Outcome> {
    let Some(pub_path) = &c.published_path else { return Ok(Outcome::PublishedMissing) };
    let published = std::fs::read(pub_path).with_context(|| pub_path.display().to_string())?;
    if sha1_hex(&published) != c.published_sha1 {
        return Ok(Outcome::HashMismatch);
    }
    // The source: the original when we have it (and it is what it should be).
    let original = match (&c.original_path, &c.original_sha1) {
        (Some(p), Some(s)) => std::fs::read(p).ok().filter(|b| &sha1_hex(b) == s),
        _ => None,
    };
    let never_stripped = c.original_sha1.as_deref() == Some(c.published_sha1.as_str());
    let (from, source, source_path, source_sha1) = match original {
        Some(b) => ("original", b, c.original_path.clone().unwrap(), c.original_sha1.clone().unwrap()),
        None => ("published", published.clone(), pub_path.clone(), c.published_sha1.clone()),
    };
    let new = openmanuals_strip::strip(&source).map_err(|e| anyhow!("{e}"))?;
    if !new.changed {
        return Ok(Outcome::Clean);
    }
    let ins_pub = openmanuals_strip::inspect(&published).map_err(|e| anyhow!("{e}"))?;
    let ins_src = openmanuals_strip::inspect(&source).map_err(|e| anyhow!("{e}"))?;
    let ins_new = openmanuals_strip::inspect(&new.bytes).map_err(|e| anyhow!("{e}"))?;
    // Stamps the published file still carries: what stripping it would remove besides ManualsLib parts.
    let stamps: Vec<String> = if from == "original" && !never_stripped {
        openmanuals_strip::strip(&published).map(|r| r.log.into_iter().filter(|l| l.to_ascii_lowercase().contains("stamp")).collect()).unwrap_or_default()
    } else {
        new.log.iter().filter(|l| l.to_ascii_lowercase().contains("stamp")).cloned().collect()
    };

    let mut changes = Vec::new();
    let mut kinds = Vec::new();
    if never_stripped {
        kinds.push("never-stripped".to_string());
        changes.push("the published file is the unstripped original".to_string());
    }
    // Wrapper pages still in the published file: its page count against the
    // new file's, attributed to the front or back by what the stripper found.
    let extra = ins_pub.pages.saturating_sub(ins_new.pages);
    if extra > 0 {
        let lead_src = ins_src.wrapper.0;
        let (lead_pub, trail_pub) = ins_pub.wrapper;
        let lead = if lead_pub > 0 { lead_pub } else { lead_src.min(extra.saturating_sub(trail_pub)) };
        let trail = extra.saturating_sub(lead);
        if lead > 0 {
            kinds.push("wrapper-leading".into());
            changes.push(format!("removes {lead} leading ManualsLib page{} (contents/cover)", if lead == 1 { "" } else { "s" }));
        }
        if trail > 0 {
            kinds.push("wrapper-trailing".into());
            changes.push(format!("removes {trail} trailing ManualsLib page{} (\"Other ManualsLib Projects\")", if trail == 1 { "" } else { "s" }));
        }
    }
    if ins_pub.footer_pages > 0 {
        kinds.push("footer".into());
        changes.push(format!("removes the ManualsLib footer from {} page{}", ins_pub.footer_pages, if ins_pub.footer_pages == 1 { "" } else { "s" }));
    }
    if ins_pub.manualslib_links > 0 {
        kinds.push("links".into());
        changes.push(format!("removes {} ManualsLib link{}", ins_pub.manualslib_links, if ins_pub.manualslib_links == 1 { "" } else { "s" }));
    }
    if !stamps.is_empty() {
        kinds.push("stamp".into());
        changes.extend(stamps);
    }
    // Nothing left to remove from what was published: the difference is only
    // how the two strippers wrote the file.
    if kinds.is_empty() {
        return Ok(Outcome::Clean);
    }
    Ok(Outcome::Restrip(Box::new(Finding {
        manual: c.manual.clone(),
        manualslib_id: c.manualslib_id.clone(),
        identifier: c.identifier.clone(),
        filename: c.filename.clone(),
        url: download_url(&c.identifier, &c.filename),
        old_sha1: c.published_sha1.clone(),
        old_sha256: sha256_hex(&published),
        from: from.to_string(),
        source_sha1,
        source_sha256: sha256_hex(&source),
        source_path,
        new_sha256: sha256_hex(&new.bytes),
        new_size: new.bytes.len(),
        published_pages: ins_pub.pages,
        new_pages: ins_new.pages,
        changes,
        kinds,
    })))
}

#[derive(Debug, Default, Serialize)]
pub struct ScanStats {
    pub candidates: usize,
    pub restrip: usize,
    pub from_original: usize,
    pub from_published: usize,
    pub clean: usize,
    pub published_missing: usize,
    pub hash_mismatch: usize,
    pub unreadable: usize,
    pub by_kind: BTreeMap<String, usize>,
}

/// `om restrip-scan`: examine every candidate in parallel and write a JSONL
/// report of the files to re-strip.
pub fn scan(db: &Path, files_root: Option<&Path>, out: &Path, limit: Option<usize>, jobs: usize, only: &[String]) -> Result<ScanStats> {
    use rayon::prelude::*;
    let mut cands = candidates(db, files_root)?;
    if !only.is_empty() {
        cands.retain(|c| only.iter().any(|o| o == &c.identifier || o == &c.manualslib_id || o.eq_ignore_ascii_case(&c.manual)));
    }
    if let Some(l) = limit {
        cands.truncate(l);
    }
    tracing::info!(candidates = cands.len(), "scanning");
    let pool = rayon::ThreadPoolBuilder::new().num_threads(jobs.max(1)).build()?;
    let done = std::sync::atomic::AtomicUsize::new(0);
    let total = cands.len();
    let outcomes: Vec<Outcome> = pool.install(|| {
        cands
            .par_iter()
            .map(|c| {
                let o = examine(c);
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if n % 1000 == 0 {
                    tracing::info!(done = n, total, "scanning");
                }
                o
            })
            .collect()
    });
    let mut stats = ScanStats { candidates: total, ..Default::default() };
    let mut w = std::io::BufWriter::new(std::fs::File::create(out).with_context(|| out.display().to_string())?);
    for (c, o) in cands.iter().zip(outcomes) {
        match o {
            Outcome::Restrip(f) => {
                stats.restrip += 1;
                if f.from == "original" {
                    stats.from_original += 1;
                } else {
                    stats.from_published += 1;
                }
                for k in &f.kinds {
                    *stats.by_kind.entry(k.clone()).or_default() += 1;
                }
                writeln!(w, "{}", serde_json::to_string(&f)?)?;
            }
            Outcome::Clean => stats.clean += 1,
            Outcome::PublishedMissing => stats.published_missing += 1,
            Outcome::HashMismatch => stats.hash_mismatch += 1,
            Outcome::Unreadable(e) => {
                stats.unreadable += 1;
                tracing::debug!(identifier = c.identifier, error = e, "unreadable");
            }
        }
    }
    w.flush()?;
    Ok(stats)
}

// ---- archive.org --------------------------------------------------------------------

/// archive.org endpoints and keys. The bases are configurable for tests.
pub struct Ia {
    pub client: reqwest::Client,
    /// S3-like upload endpoint, normally https://s3.us.archive.org
    pub s3_base: String,
    /// Metadata API host, normally https://archive.org
    pub api_base: String,
    pub access: String,
    pub secret: String,
}

impl Ia {
    fn auth(&self) -> String {
        format!("LOW {}:{}", self.access, self.secret)
    }

    /// Send a request, retrying on 429/503 (archive.org's "slow down") with backoff.
    async fn send(&self, mk: impl Fn() -> reqwest::RequestBuilder, what: &str) -> Result<reqwest::Response> {
        let mut wait = Duration::from_secs(5);
        for attempt in 0..6 {
            let r = mk().send().await.with_context(|| what.to_string())?;
            let s = r.status().as_u16();
            if s != 429 && s != 503 {
                return Ok(r);
            }
            let retry = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).map(Duration::from_secs);
            let d = retry.unwrap_or(wait).min(Duration::from_secs(300));
            tracing::warn!(status = s, attempt, wait_s = d.as_secs(), "{what}: archive.org asked to slow down");
            tokio::time::sleep(d).await;
            wait *= 2;
        }
        bail!("{what}: archive.org kept refusing (rate limited)")
    }

    /// Replace a file in an existing item (same filename). archive.org re-derives the item.
    pub async fn replace_file(&self, identifier: &str, filename: &str, bytes: &[u8], keep_old_version: bool) -> Result<()> {
        let url = format!("{}/{identifier}/{}", self.s3_base.trim_end_matches('/'), urlencoding::encode(filename));
        let r = self
            .send(
                || {
                    let mut req = self.client.put(&url).header("authorization", self.auth()).header("content-type", "application/pdf").header("x-archive-size-hint", bytes.len().to_string());
                    if keep_old_version {
                        req = req.header("x-archive-keep-old-version", "1");
                    }
                    req.body(bytes.to_vec())
                },
                "uploading to archive.org",
            )
            .await?;
        if !r.status().is_success() {
            bail!("archive.org upload answered {}: {}", r.status(), r.text().await.unwrap_or_default());
        }
        Ok(())
    }

    /// The item's metadata (public read).
    pub async fn metadata(&self, identifier: &str) -> Result<Value> {
        let url = format!("{}/metadata/{identifier}", self.api_base.trim_end_matches('/'));
        let r = self.send(|| self.client.get(&url), "reading item metadata").await?;
        if !r.status().is_success() {
            bail!("archive.org metadata answered {}", r.status());
        }
        let v: Value = r.json().await?;
        v.get("metadata").cloned().ok_or_else(|| anyhow!("item {identifier} has no metadata (does it exist?)"))
    }

    /// Apply a JSON Patch (RFC 6902) to the item's metadata via the Metadata Write API.
    pub async fn patch_metadata(&self, identifier: &str, patch: &Value) -> Result<()> {
        if patch.as_array().is_some_and(Vec::is_empty) {
            return Ok(());
        }
        let url = format!("{}/metadata/{identifier}", self.api_base.trim_end_matches('/'));
        let form = [("-target", "metadata".to_string()), ("-patch", patch.to_string())];
        let r = self.send(|| self.client.post(&url).header("authorization", self.auth()).header("x-accept-reduced-priority", "1").form(&form), "writing item metadata").await?;
        let status = r.status();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        if body.get("success").and_then(Value::as_bool) == Some(true) {
            return Ok(());
        }
        let err = body.get("error").and_then(Value::as_str).unwrap_or("");
        if err.contains("No changes made") {
            return Ok(());
        }
        bail!("archive.org metadata write answered {status}: {}", if err.is_empty() { body.to_string() } else { err.to_string() })
    }
}

/// The JSON Patch that points the item's `external-identifier` at the new
/// bytes: the `urn:sha256/sha1/md5` values are replaced, anything else
/// (e.g. `urn:original-sha1:…`) is kept; `openmanuals-original-sha256` names
/// the bytes the file was stripped from.
pub fn metadata_patch(current: &Value, new: &[u8], source_sha256: &str) -> Value {
    let ext: Vec<String> = match current.get("external-identifier") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec![],
    };
    let mut next: Vec<String> = vec![format!("urn:sha256:{}", sha256_hex(new)), format!("urn:sha1:{}", sha1_hex(new)), format!("urn:md5:{}", md5_hex(new))];
    next.extend(ext.iter().filter(|e| !(e.starts_with("urn:sha256:") || e.starts_with("urn:sha1:") || e.starts_with("urn:md5:"))).cloned());
    let mut ops = Vec::new();
    if ext != next {
        let op = if current.get("external-identifier").is_some() { "replace" } else { "add" };
        ops.push(json!({"op": op, "path": "/external-identifier", "value": next}));
    }
    match current.get("openmanuals-original-sha256").and_then(Value::as_str) {
        Some(s) if s == source_sha256 => {}
        Some(_) => ops.push(json!({"op": "replace", "path": "/openmanuals-original-sha256", "value": source_sha256})),
        None => ops.push(json!({"op": "add", "path": "/openmanuals-original-sha256", "value": source_sha256})),
    }
    Value::Array(ops)
}

/// The facts recording a re-stripped file: the source's `file` (with its
/// sha256, which also merges a legacy sha1-only record), the new `file`, the
/// `derivation`, the `manual_file`, and the archive.org `location` (same URL,
/// new file), plus `retract`s for this key's earlier locations at that URL.
pub fn restrip_facts(key: &SigningKey, f: &Finding, source: &[u8], new: &[u8], retract: &[String]) -> Result<Vec<Fact>> {
    let file = |b: &[u8]| json!({"sha256": sha256_hex(b), "sha1": sha1_hex(b), "md5": md5_hex(b), "size": b.len(), "mime": "application/pdf"});
    let new_sha = sha256_hex(new);
    let mut out = vec![
        sign(key, "file", file(source))?,
        sign(key, "file", file(new))?,
        sign(key, "derivation", json!({"derived": new_sha, "source": sha256_hex(source), "transform": "watermark-stripped", "tool": openmanuals_strip::STRIP_TOOL, "tool_version": openmanuals_strip::STRIP_VERSION}))?,
        sign(key, "manual_file", json!({"manual": f.manual, "file": new_sha, "role": "primary"}))?,
        sign(key, "location", json!({"file": new_sha, "url": f.url, "kind": "archive", "ia": {"identifier": f.identifier, "filename": f.filename}}))?,
    ];
    for id in retract {
        out.push(sign(key, "retract", json!({"fact": id}))?);
    }
    Ok(out)
}

/// (identifier, filename) → this key's `location` facts there, as (fact id, file).
pub type OwnLocations = HashMap<(String, String), Vec<(String, String)>>;

/// This key's `location` facts per archive.org file, from a ledger directory,
/// for retracting the old copies.
pub fn own_locations(ledger: &Path, fingerprint: &str) -> Result<OwnLocations> {
    let l = openmanuals_ledger::Ledger::open(ledger)?;
    let mut out = OwnLocations::new();
    let needle = format!("\"author\":\"{fingerprint}\"");
    l.scan(None, None, &mut |line| {
        if !line.contains("\"type\":\"location\"") || !line.contains(&needle) {
            return Ok(());
        }
        let e: openmanuals_ledger::ledger::Entry = serde_json::from_str(line)?;
        let b = &e.fact.body;
        if let (Some(i), Some(n), Some(file)) = (b.pointer("/ia/identifier").and_then(Value::as_str), b.pointer("/ia/filename").and_then(Value::as_str), b.get("file").and_then(Value::as_str)) {
            out.entry((i.to_string(), n.to_string())).or_default().push((e.id, file.to_string()));
        }
        Ok(())
    })?;
    Ok(out)
}

/// Where `om restrip` records finished items, so a batch can be resumed.
fn done_path(home: &Home) -> PathBuf {
    home.dir.join("restrip-done.jsonl")
}

fn load_done(home: &Home) -> HashSet<(String, String)> {
    std::fs::read_to_string(done_path(home))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| Some((v.get("identifier")?.as_str()?.to_string(), v.get("new_sha256")?.as_str()?.to_string())))
        .collect()
}

pub struct RestripOpts {
    pub dry_run: bool,
    pub keep_old_version: bool,
    pub interval: Duration,
    /// For an item whose source isn't on disk: download it from this URL (checked against its sha1).
    pub download: Option<String>,
    /// Ledger directory to find this key's earlier locations to retract.
    pub ledger: Option<PathBuf>,
}

#[derive(Debug, Default, Serialize)]
pub struct RestripStats {
    pub items: usize,
    pub replaced: usize,
    /// With --dry-run: items that would be replaced.
    pub would_replace: usize,
    pub already_done: usize,
    pub unchanged: usize,
    pub failed: usize,
    pub facts: usize,
}

/// Get the source bytes for a finding: from disk, else (when allowed) a download.
async fn source_bytes(f: &Finding, client: &reqwest::Client, download: Option<&str>) -> Result<Vec<u8>> {
    if let Ok(b) = std::fs::read(&f.source_path) {
        if sha1_hex(&b) == f.source_sha1 {
            return Ok(b);
        }
    }
    let Some(url) = download else {
        bail!("the {} file isn't at {} (pass --download-source <url> to fetch it)", f.from, f.source_path.display());
    };
    let r = client.get(url).send().await.with_context(|| format!("downloading {url}"))?;
    if !r.status().is_success() {
        bail!("{url} answered {}", r.status());
    }
    let b = r.bytes().await?.to_vec();
    if sha1_hex(&b) != f.source_sha1 {
        bail!("{url} isn't the expected file (sha1 {} ≠ {})", sha1_hex(&b), f.source_sha1);
    }
    Ok(b)
}

/// `om restrip`: replace each finding's file on archive.org and queue its facts.
pub async fn run(home: &Home, key: &SigningKey, ia: &Ia, findings: &[Finding], o: &RestripOpts) -> Result<RestripStats> {
    let mut stats = RestripStats { items: findings.len(), ..Default::default() };
    let done = load_done(home);
    let mine = match (&o.ledger, o.dry_run) {
        (Some(l), false) => own_locations(l, &key.public_key().fingerprint())?,
        _ => HashMap::new(),
    };
    for (i, f) in findings.iter().enumerate() {
        if done.iter().any(|(id, _)| id == &f.identifier) && !o.dry_run {
            stats.already_done += 1;
            continue;
        }
        if i > 0 && !o.dry_run {
            tokio::time::sleep(o.interval).await;
        }
        match restrip_one(home, key, ia, f, o, &mine).await {
            Ok(Some(_)) if o.dry_run => stats.would_replace += 1,
            Ok(Some(n)) => {
                stats.replaced += 1;
                stats.facts += n;
            }
            Ok(None) => stats.unchanged += 1,
            Err(e) => {
                stats.failed += 1;
                eprintln!("{}: {e:#}", f.identifier);
            }
        }
    }
    Ok(stats)
}

/// One item. Ok(None) when the current stripper leaves nothing to replace.
async fn restrip_one(home: &Home, key: &SigningKey, ia: &Ia, f: &Finding, o: &RestripOpts, mine: &OwnLocations) -> Result<Option<usize>> {
    let source = source_bytes(f, &ia.client, o.download.as_deref()).await?;
    let r = openmanuals_strip::strip(&source).map_err(|e| anyhow!("{e}"))?;
    if !r.changed || sha1_hex(&r.bytes) == f.old_sha1 {
        println!("{}: unchanged", f.identifier);
        return Ok(None);
    }
    let new = r.bytes;
    let new_sha = sha256_hex(&new);
    if new_sha != f.new_sha256 {
        tracing::warn!(identifier = f.identifier, report = f.new_sha256, now = new_sha, "the stripper's output differs from the report's; using the new output");
    }
    let retract: Vec<String> = mine.get(&(f.identifier.clone(), f.filename.clone())).map(|v| v.iter().filter(|(_, file)| *file != new_sha).map(|(id, _)| id.clone()).collect()).unwrap_or_default();
    if o.dry_run {
        println!("{}: would replace {} ({} → {}, {} → {} pages): {}", f.identifier, f.filename, &f.old_sha1[..12], &new_sha[..12], f.published_pages, f.new_pages, f.changes.join("; "));
        return Ok(Some(0));
    }
    ia.replace_file(&f.identifier, &f.filename, &new, o.keep_old_version).await?;
    let current = ia.metadata(&f.identifier).await?;
    ia.patch_metadata(&f.identifier, &metadata_patch(&current, &new, &sha256_hex(&source))).await?;
    let facts = restrip_facts(key, f, &source, &new, &retract)?;
    let p = crate::outbox::queue(home, &facts)?;
    let mut d = std::fs::OpenOptions::new().create(true).append(true).open(done_path(home))?;
    writeln!(d, "{}", json!({"identifier": f.identifier, "filename": f.filename, "new_sha256": new_sha, "at": crate::now()}))?;
    println!("{}: replaced {} ({}), queued {} facts in {}", f.identifier, f.filename, &new_sha[..12], facts.len(), p.display());
    Ok(Some(facts.len()))
}

/// Read a scan report (JSONL of findings).
pub fn read_report(path: &Path) -> Result<Vec<Finding>> {
    std::fs::read_to_string(path)
        .with_context(|| path.display().to_string())?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| Ok(serde_json::from_str(l)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_patch_replaces_only_the_current_hashes() {
        let cur = json!({"external-identifier": ["urn:md5:aa", "urn:sha1:bb", "urn:original-md5:cc", "urn:original-sha1:dd"]});
        let p = metadata_patch(&cur, b"new", "s0");
        let ops = p.as_array().unwrap();
        assert_eq!(ops[0]["op"], "replace");
        let v: Vec<&str> = ops[0]["value"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(v, vec![format!("urn:sha256:{}", sha256_hex(b"new")).as_str(), &format!("urn:sha1:{}", sha1_hex(b"new")), &format!("urn:md5:{}", md5_hex(b"new")), "urn:original-md5:cc", "urn:original-sha1:dd"]);
        assert_eq!(ops[1], json!({"op": "add", "path": "/openmanuals-original-sha256", "value": "s0"}));
        // A single string value and an already-current item.
        let one = metadata_patch(&json!({"external-identifier": "urn:sha1:bb"}), b"x", "s");
        assert_eq!(one[0]["value"].as_array().unwrap().len(), 3);
        let same = json!({"external-identifier": [format!("urn:sha256:{}", sha256_hex(b"x")), format!("urn:sha1:{}", sha1_hex(b"x")), format!("urn:md5:{}", md5_hex(b"x"))], "openmanuals-original-sha256": "s"});
        assert_eq!(metadata_patch(&same, b"x", "s"), json!([]));
    }

    #[test]
    fn download_urls_match_the_import() {
        assert_eq!(download_url("manualslib-id-990837", "cb3776.pdf"), "https://archive.org/download/manualslib-id-990837/cb3776.pdf");
        assert_eq!(download_url("x", "a b.pdf"), "https://archive.org/download/x/a%20b.pdf");
    }
}
