//! Fold the inbox into the ledger repository, commit, rebuild and publish.

use crate::config::{Shared, State};
use anyhow::{anyhow, Context, Result};
use openmanuals_ledger::checkpoint::Store;
use openmanuals_ledger::{build_resident, BuildOptions, BuildStats, Ledger, Resident, Tuning};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output().with_context(|| "running git")?;
    if !out.status.success() {
        return Err(anyhow!("git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn ensure_repo(dir: &Path) -> Result<()> {
    if !dir.join(".git").exists() {
        std::fs::create_dir_all(dir)?;
        git(dir, &["init", "-q"])?;
        git(dir, &["config", "user.name", "openmanuals-fold"])?;
        git(dir, &["config", "user.email", "fold@openmanuals.invalid"])?;
    }
    Ok(())
}

/// Append unfolded facts to the ledger and commit. Returns the number folded.
pub fn fold(state: &State) -> Result<usize> {
    let dir = &state.paths.ledger_dir;
    ensure_repo(dir)?;
    let ledger = Ledger::open(dir)?;
    let pending = state.inbox.unfolded()?;
    if pending.is_empty() {
        return Ok(0);
    }
    let touched = ledger.append(&pending)?;
    let mut args = vec!["add", "--"];
    let rel: Vec<String> = touched.iter().map(|p| p.to_string_lossy().to_string()).collect();
    args.extend(rel.iter().map(String::as_str));
    git(dir, &args)?;
    let msg = format!("fold: {} facts through {}", pending.len(), pending.last().unwrap().cursor);
    git(dir, &["commit", "-q", "-m", &msg])?;
    state.inbox.mark_folded(&pending.iter().map(|e| e.cursor.clone()).collect::<Vec<_>>())?;
    tracing::info!(n = pending.len(), "folded facts into the ledger");
    Ok(pending.len())
}

/// The resolver state after the last build, per checkpoint path, kept in
/// memory so the next fold resumes from it instead of loading
/// `checkpoint.bin` (several `State`s may share a process in tests).
static RESIDENT: Mutex<BTreeMap<PathBuf, Resident>> = Mutex::new(BTreeMap::new());

/// Build a snapshot from the ledger and publish it as latest.db (+ sha256, sig).
/// Resumes from the state the last build in this process left in memory,
/// else from the checkpoint, unless `full`, `--no-checkpoint`, or
/// `verify_signatures` (a verifying build always reads everything). The
/// checkpoint is written after publishing (the new snapshot is already
/// served); until that write completes (temporary file + rename) the
/// previous checkpoint stays in place, so a crash leaves an older valid
/// state or none.
pub fn build_snapshot(state: &State, verify_signatures: bool, full: bool) -> Result<BuildStats> {
    let ledger = Ledger::open(&state.paths.ledger_dir)?;
    let trust = state.trust.read().unwrap().clone();
    let dir = state.paths.snapshots_dir();
    std::fs::create_dir_all(&dir)?;
    // Built under a temporary name; publish names it by its version.
    let out = dir.join("building.db");
    let cp = state.paths.checkpoint_path();
    let use_checkpoint = !state.paths.no_checkpoint && !verify_signatures;
    let mut resident = RESIDENT.lock().unwrap().remove(&cp);
    if full {
        // Also after rewriting history: day checkpoints and the ledger index go too.
        Store::new(&cp).clear();
        resident = None;
    } else if !use_checkpoint {
        let _ = std::fs::remove_file(&cp);
        resident = None;
    }
    let opts = BuildOptions { verify_signatures, checkpoint: use_checkpoint.then(|| cp.clone()) };
    let (stats, resident) = build_resident(&ledger, &trust, &out, &opts, &Tuning::default(), resident)?;
    let published = crate::publish::publish(state, &out);
    if let Some(r) = resident {
        let t = std::time::Instant::now();
        if let Err(e) = r.save(&cp) {
            // The snapshot is right; the next process just resumes from further back.
            tracing::warn!(error = %e, "could not write checkpoint");
        }
        tracing::debug!(ms = t.elapsed().as_millis() as u64, "wrote checkpoint");
        RESIDENT.lock().unwrap().insert(cp, r);
    }
    published?;
    tracing::info!(?stats, "built snapshot");
    Ok(stats)
}

pub fn base64url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Whether the published snapshot was built from the ledger's current head
/// with the current trust config. Any doubt (no snapshot, unreadable meta)
/// means it is not.
pub fn snapshot_is_current(state: &State) -> Result<bool> {
    let latest = state.paths.latest_db();
    if !latest.exists() {
        return Ok(false);
    }
    let head = Ledger::open(&state.paths.ledger_dir)?.head()?.unwrap_or_default();
    let digest = state.trust.read().unwrap().digest();
    let meta = |conn: &rusqlite::Connection, key: &str| -> Option<String> {
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).ok()
    };
    let Ok(conn) = rusqlite::Connection::open_with_flags(&latest, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return Ok(false);
    };
    // A snapshot from older code may lack tables or indexes the pages use.
    Ok(meta(&conn, "head").as_deref() == Some(head.as_str())
        && meta(&conn, "trust_digest").as_deref() == Some(digest.as_str())
        && meta(&conn, "schema").as_deref() == Some(openmanuals_ledger::build::SNAPSHOT_SCHEMA))
}

/// fold + build, serialized. The snapshot is rebuilt only when facts were
/// folded or the published one is stale; `None` means the build was skipped.
pub async fn fold_and_build(state: Shared) -> Result<(usize, Option<BuildStats>)> {
    let _g = state.fold_lock.lock().await;
    let s = state.clone();
    tokio::task::spawn_blocking(move || {
        let n = fold(&s)?;
        if n == 0 && snapshot_is_current(&s)? {
            tracing::debug!("nothing new; snapshot is current");
            return Ok((0, None));
        }
        Ok((n, Some(build_snapshot(&s, false, false)?)))
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use openmanuals_core::{sign::SigningKey, Alg, Fact};
    use serde_json::json;

    #[derive(Parser)]
    struct Args {
        #[command(flatten)]
        paths: crate::config::Paths,
    }

    fn fact(key: &SigningKey, t: &str, body: serde_json::Value) -> Fact {
        let mut f = Fact::new(t, "x", "2026-10-23T18:00:00Z", body);
        key.sign_fact(&mut f).unwrap();
        f
    }

    /// Folds resume from the state kept in memory, a new process from the
    /// checkpoint written after publishing, and every snapshot equals a full
    /// build of the ledger.
    #[tokio::test]
    async fn folds_resume_from_the_resident_state() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let key = SigningKey::generate(Alg::Ed25519);
        std::fs::write(data.join("server.key"), key.to_openssh("test").unwrap()).unwrap();
        let ledger_dir = dir.path().join("ledger");
        let args = Args::parse_from(["t", "--data-dir", data.to_str().unwrap(), "--ledger-dir", ledger_dir.to_str().unwrap()]);
        let state = crate::config::State::new(args.paths).unwrap();
        let cp = state.paths.checkpoint_path();
        let mut n = 0u32;
        let mut round = |kind: &str| {
            let facts: Vec<Fact> = (0..5).flat_map(|_| {
                n += 1;
                let man = ulid::Ulid::from_parts(1_700_000_000_000 + n as u64, n as u128).to_string();
                [
                    fact(&key, "manual", json!({"id": man, "title": format!("{kind} manual {n}"), "doc_type": "user"})),
                    fact(&key, "product", json!({"brand": "Sony", "model": format!("KV-{n}")})),
                    fact(&key, "covers", json!({"manual": man, "product": format!("sony|KV{n}")})),
                ]
            }).collect();
            state.inbox.accept(&facts, |_| Ok(())).unwrap();
        };
        let full_bytes = |state: &State| {
            let out = dir.path().join("full.db");
            let ledger = Ledger::open(&state.paths.ledger_dir).unwrap();
            openmanuals_ledger::build(&ledger, &state.trust.read().unwrap(), &out, &BuildOptions::default()).unwrap();
            assert_eq!(std::fs::read(state.paths.latest_db()).unwrap(), std::fs::read(&out).unwrap());
        };

        round("first");
        let (_, s) = fold_and_build(state.clone()).await.unwrap();
        assert_eq!(s.unwrap().mode, openmanuals_ledger::BuildMode::Full);
        assert!(cp.exists(), "written after publishing");
        full_bytes(&state);

        round("second");
        let (_, s) = fold_and_build(state.clone()).await.unwrap();
        assert_eq!(s.unwrap().resumed_from.as_deref(), Some("resident"));
        full_bytes(&state);

        // A new process has only the checkpoint.
        RESIDENT.lock().unwrap().remove(&cp);
        round("third");
        let (_, s) = fold_and_build(state.clone()).await.unwrap();
        assert_eq!(s.unwrap().resumed_from.as_deref(), Some("checkpoint"));
        full_bytes(&state);

        // --full starts over (and forgets the resident state).
        let s = build_snapshot(&state, false, true).unwrap();
        assert_eq!(s.mode, openmanuals_ledger::BuildMode::Full);
        round("fourth");
        let (_, s) = fold_and_build(state.clone()).await.unwrap();
        assert_eq!(s.unwrap().resumed_from.as_deref(), Some("resident"));
        full_bytes(&state);
    }
}
