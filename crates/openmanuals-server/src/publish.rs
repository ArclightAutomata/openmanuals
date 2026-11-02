//! Publishing a built snapshot and keeping the snapshots directory bounded.
//!
//! A published snapshot is named by its *version*, `<ledger head>-<content
//! id>` (see `openmanuals_ledger::snapshot::version`), so a rebuild with a different
//! trust config at the same ledger head gets a new name, and every name is
//! immutable once published.
//!
//! ```text
//! snapshots/
//!   <version>.db           each build; the newest --keep-snapshots are kept
//!   <version>.db.zst       the same, zstd -9 (what clients download)
//!   <version>.pages        sha256 of each page (clients reading single pages from mirrors)
//!   latest.db              hard link to the newest <version>.db (+ .sha256, .sig)
//!   latest.version         its version
//!   diff/<from>.<to>.jsonl.zst   row diff between consecutive versions, kept --keep-diffs-days
//!   diffs.json             index of the diffs above (sha256, size, rows)
//!   lookup-filter.bin      membership filter of known pages (extension, see openmanuals_core::filter)
//!   manifest.json(.sig)    what clients read first; signed by the server key
//!   checkpoint.bin         build state (see openmanuals-ledger)
//! ```

use crate::config::State;
use crate::fold::base64url;
use anyhow::Result;
use openmanuals_ledger::snapshot;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffEntry {
    pub from: String,
    pub to: String,
    pub file: String,
    pub sha256: String,
    pub size: u64,
    pub rows: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Published {
    pub version: String,
    pub zst_size: u64,
    pub diff: Option<DiffEntry>,
    pub pruned: usize,
    pub millis: u64,
}

pub use openmanuals_ledger::snapshot::is_version;

/// A diff file name: `<from>.<to>.jsonl.zst`.
pub fn is_diff_name(name: &str) -> bool {
    name.strip_suffix(".jsonl.zst").and_then(|s| s.split_once('.')).is_some_and(|(a, b)| is_version(a) && is_version(b))
}

/// A build left by an older server, named `<cursor>.db`.
fn is_legacy_build(name: &str) -> bool {
    name.strip_suffix(".db").is_some_and(|c| openmanuals_ledger::ledger::is_cursor(c) && c.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Point `latest.db` at `out` without copying it.
fn link_latest(out: &Path, latest: &Path) -> Result<()> {
    let tmp = latest.with_extension("db.tmp");
    let _ = std::fs::remove_file(&tmp);
    if std::fs::hard_link(out, &tmp).is_err() {
        std::fs::copy(out, &tmp)?;
    }
    std::fs::rename(&tmp, latest)?;
    Ok(())
}

/// Name and publish a freshly built snapshot at `built` (it is moved).
pub fn publish(state: &State, built: &Path) -> Result<Published> {
    let t0 = std::time::Instant::now();
    let dir = state.paths.snapshots_dir();
    let diff_dir = dir.join("diff");
    std::fs::create_dir_all(&diff_dir)?;
    let tables = snapshot::content_hashes(built)?;
    let head = snapshot::head(&rusqlite::Connection::open_with_flags(built, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?)?;
    let head = if head.is_empty() { "empty".to_string() } else { head };
    let cursor = snapshot::version(&head, &tables);
    let out = dir.join(format!("{cursor}.db"));
    std::fs::rename(built, &out)?;
    let latest = state.paths.latest_db();
    // The previous version, while latest.db still points at it.
    let prev = std::fs::read_to_string(dir.join("latest.version")).ok().map(|v| v.trim().to_string())
        .filter(|v| *v != cursor && is_version(v)).map(|v| (dir.join(format!("{v}.db")), v)).filter(|(p, _)| p.exists());

    // Live first: pages and lookups switch now; the rest is for downloaders.
    let (sha, size) = snapshot::file_sha256(&out)?;
    link_latest(&out, &latest)?;
    std::fs::write(dir.join("latest.db.sha256"), format!("{sha}  latest.db\n"))?;
    std::fs::write(dir.join("latest.db.sig"), base64url(&state.key.sign_raw(sha.as_bytes())))?;
    write_atomic(&dir.join("latest.version"), cursor.as_bytes())?;
    state.set_snapshot(latest.clone());
    let filter = openmanuals_ledger::filter::lookup_filter(&out)?;
    write_atomic(&dir.join("lookup-filter.bin"), &filter)?;
    let filter_sha = openmanuals_core::canon::sha256_hex(&filter);

    let pages = snapshot::page_hashes(&out)?;
    let pages_name = format!("{cursor}.pages");
    write_atomic(&dir.join(&pages_name), &pages.raw)?;
    let zst_name = format!("{cursor}.db.zst");
    let (zst_sha, zst_size) = snapshot::compress(&out, &dir.join(&zst_name))?;

    let mut diffs: Vec<DiffEntry> = std::fs::read(dir.join("diffs.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let mut new_diff = None;
    if let Some((prev_path, prev_cursor)) = &prev {
        let mut raw = Vec::new();
        match snapshot::diff(prev_path, &out, prev_cursor, &cursor, &tables, &mut raw) {
            Ok(Some(st)) => {
                let file = format!("diff/{prev_cursor}.{cursor}.jsonl.zst");
                let z = snapshot::compress_bytes(&raw)?;
                write_atomic(&dir.join(&file), &z)?;
                let e = DiffEntry { from: prev_cursor.clone(), to: cursor.clone(), file, sha256: openmanuals_core::canon::sha256_hex(&z), size: z.len() as u64, rows: st.deleted + st.upserted };
                diffs.retain(|d| !(d.from == e.from && d.to == e.to));
                diffs.push(e.clone());
                new_diff = Some(e);
            }
            Ok(None) => tracing::info!(from = %prev_cursor, "schema changed; no diff for this build"),
            Err(e) => tracing::warn!(error = %e, "could not diff against the previous snapshot"),
        }
    }

    let pruned = prune(state, &dir, &cursor, &mut diffs)?;
    write_atomic(&dir.join("diffs.json"), &serde_json::to_vec_pretty(&diffs)?)?;

    let manifest = json!({
        "version": 1,
        "server": state.fingerprint,
        // So a static copy of this directory is a complete, verifiable mirror.
        "server_key": state.key.public_key().to_jwk(),
        "latest": {
            "version": cursor, "head": head, "file": format!("{cursor}.db"), "sha256": sha, "size": size,
            "zst": {"file": zst_name, "sha256": zst_sha, "size": zst_size},
            "tables": tables,
            "pages": {"file": pages_name, "page_size": pages.page_size, "count": pages.pages, "group": snapshot::PAGE_GROUP, "groups": pages.groups},
        },
        "diffs": diffs,
        "lookup_filter": {"file": "lookup-filter.bin", "sha256": filter_sha, "size": filter.len()},
    });
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    // Signature over the sha256 hex of the manifest bytes, like latest.db.sig.
    let sig = state.key.sign_raw(openmanuals_core::canon::sha256_hex(&bytes).as_bytes());
    write_atomic(&dir.join("manifest.json.sig"), base64url(&sig).as_bytes())?;
    write_atomic(&dir.join("manifest.json"), &bytes)?;
    let p = Published { version: cursor, zst_size, diff: new_diff, pruned, millis: t0.elapsed().as_millis() as u64 };
    tracing::info!(?p, "published snapshot");
    Ok(p)
}

/// When a version's ledger head was ingested.
fn cursor_ms(v: &str) -> Option<u64> {
    v.split('-').next()?.parse::<ulid::Ulid>().ok().map(|u| u.timestamp_ms())
}

/// Delete all but the newest `keep_snapshots` builds, diffs older than
/// `keep_diffs_days`, and leftovers of interrupted builds. Never touches the
/// snapshot being published.
pub fn prune(state: &State, dir: &Path, current: &str, diffs: &mut Vec<DiffEntry>) -> Result<usize> {
    let keep = state.paths.keep_snapshots.max(1);
    let mut builds: Vec<String> = Vec::new();
    let mut junk: Vec<PathBuf> = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let path = e?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(String::from) else { continue };
        if let Some(v) = name.strip_suffix(".db").filter(|v| is_version(v)) {
            builds.push(v.to_string());
        } else if is_legacy_build(&name) {
            // Older servers' builds: always older than any versioned one.
            junk.push(path);
        } else if name.contains(".part") || name.ends_with(".db.tmp") || name.ends_with(".zst.tmp") || name.ends_with(".db.tmp-journal") || name == "building.db" {
            junk.push(path);
        }
    }
    builds.sort();
    builds.reverse();
    let mut removed = 0;
    let mut gone: BTreeMap<String, ()> = BTreeMap::new();
    for c in builds.iter().skip(keep).filter(|c| c.as_str() != current) {
        for name in [format!("{c}.db"), format!("{c}.db.zst"), format!("{c}.pages")] {
            if std::fs::remove_file(dir.join(&name)).is_ok() {
                removed += 1;
            }
        }
        gone.insert(c.clone(), ());
    }
    // Compressed copies whose .db is gone (e.g. from before pruning existed).
    for e in std::fs::read_dir(dir)? {
        let path = e?.path();
        if let Some(c) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".db.zst").or_else(|| n.strip_suffix(".pages"))) {
            if c != current && !dir.join(format!("{c}.db")).exists() && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    for p in junk {
        if std::fs::remove_file(&p).is_ok() {
            removed += 1;
        }
    }
    let now = jiff::Timestamp::now().as_millisecond() as u64;
    let max_age = state.paths.keep_diffs_days * 86_400_000;
    let diff_dir = dir.join("diff");
    diffs.retain(|d| {
        let fresh = cursor_ms(&d.to).is_some_and(|t| now.saturating_sub(t) <= max_age);
        let keep = fresh && diff_dir.parent().map(|p| p.join(&d.file)).is_some_and(|p| p.exists());
        if !keep && std::fs::remove_file(dir.join(&d.file)).is_ok() {
            removed += 1;
        }
        keep
    });
    // Diff files not in the index (interrupted publishes).
    if let Ok(rd) = std::fs::read_dir(&diff_dir) {
        for e in rd.flatten() {
            let rel = format!("diff/{}", e.file_name().to_string_lossy());
            if !diffs.iter().any(|d| d.file == rel) && std::fs::remove_file(e.path()).is_ok() {
                removed += 1;
            }
        }
    }
    Ok(removed)
}
