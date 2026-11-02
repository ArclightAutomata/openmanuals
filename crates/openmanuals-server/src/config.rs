//! Server configuration (flags/env) and shared state.

use anyhow::{Context, Result};
use openmanuals_core::sign::SigningKey;
use openmanuals_ledger::TrustConfig;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, clap::Args)]
pub struct Paths {
    /// Directory for inbox.db, snapshots and the server key.
    #[arg(long, env = "OM_DATA_DIR", default_value = "data")]
    pub data_dir: PathBuf,
    /// Ledger working tree (a git repository; created if missing).
    #[arg(long, env = "OM_LEDGER_DIR", default_value = "ledger")]
    pub ledger_dir: PathBuf,
    /// Server signing key (OpenSSH private key). Default: <data-dir>/server.key.
    #[arg(long, env = "OM_SERVER_KEY")]
    pub key: Option<PathBuf>,
    /// Trust configuration. Default: <ledger-dir>/build.toml if present.
    #[arg(long, env = "OM_TRUST")]
    pub trust: Option<PathBuf>,
    /// Domain profiles are hosted on (for aspe: URIs).
    #[arg(long, env = "OM_DOMAIN", default_value = "localhost")]
    pub domain: String,
    /// Public base URL used in API responses.
    #[arg(long, env = "OM_PUBLIC_URL", default_value = "http://localhost:8000")]
    pub public_url: String,
    /// Path to tools/doip-verify/index.js (proof verification). Disabled when unset or missing.
    #[arg(long, env = "OM_DOIP_SCRIPT")]
    pub doip_script: Option<PathBuf>,
    /// Always rebuild from the start of the ledger (no checkpoint).
    #[arg(long, env = "OM_NO_CHECKPOINT")]
    pub no_checkpoint: bool,
    /// How many builds (<cursor>.db and .db.zst) to keep in the snapshots directory.
    #[arg(long, env = "OM_KEEP_SNAPSHOTS", default_value_t = 3)]
    pub keep_snapshots: usize,
    /// How long to keep diffs between consecutive builds.
    #[arg(long, env = "OM_KEEP_DIFFS_DAYS", default_value_t = 30)]
    pub keep_diffs_days: u64,
    /// MalwareBazaar API key (abuse.ch Auth-Key). When set, the verifier looks
    /// up the sha256 of every copy it scans. Lookups are skipped when unset.
    #[arg(long, env = "OM_MALWAREBAZAAR_KEY", hide_env_values = true)]
    pub malwarebazaar_key: Option<String>,
}

pub struct State {
    pub paths: Paths,
    pub inbox: crate::inbox::Inbox,
    /// Passkey-wrapped key copies (`keywrap.db`), outside the ledger.
    pub key_wraps: crate::keywrap::KeyWraps,
    /// Avatar images (`avatars.db`), outside the ledger.
    pub avatars: crate::avatar::Avatars,
    pub key: SigningKey,
    pub fingerprint: String,
    pub trust: RwLock<TrustConfig>,
    pub snapshot: RwLock<Option<PathBuf>>,
    pub budgets: crate::rate::Budgets,
    pub fold_lock: tokio::sync::Mutex<()>,
    /// Pokes the fold scheduler when facts are accepted (see `schedule`).
    pub fold_trigger: crate::schedule::FoldTrigger,
    /// Reusable read-only connections to the current snapshot.
    pub readers: ReaderPool,
    /// "Help preserve a manual": random picks and missing counts.
    pub contribute: crate::contribute::Contribute,
}

pub type Shared = Arc<State>;

impl Paths {
    pub fn key_path(&self) -> PathBuf {
        self.key.clone().unwrap_or_else(|| self.data_dir.join("server.key"))
    }
    pub fn inbox_path(&self) -> PathBuf {
        self.data_dir.join("inbox.db")
    }
    pub fn keywrap_path(&self) -> PathBuf {
        self.data_dir.join("keywrap.db")
    }
    pub fn avatars_path(&self) -> PathBuf {
        self.data_dir.join("avatars.db")
    }
    pub fn snapshots_dir(&self) -> PathBuf {
        self.data_dir.join("snapshots")
    }
    pub fn latest_db(&self) -> PathBuf {
        self.snapshots_dir().join("latest.db")
    }
    /// Resolver state after the last build; the next build resumes from it.
    pub fn checkpoint_path(&self) -> PathBuf {
        self.snapshots_dir().join("checkpoint.bin")
    }
    pub fn trust_path(&self) -> PathBuf {
        self.trust.clone().unwrap_or_else(|| self.ledger_dir.join("build.toml"))
    }
}

pub fn load_key(path: &Path) -> Result<SigningKey> {
    let pem = std::fs::read_to_string(path).with_context(|| format!("reading server key {}", path.display()))?;
    SigningKey::from_openssh(&pem).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Load (or default) the trust config, always trusting this server's own key.
pub fn load_trust(paths: &Paths, fingerprint: &str) -> Result<TrustConfig> {
    let p = paths.trust_path();
    let mut t = if p.exists() { TrustConfig::load(&p)? } else { TrustConfig::default() };
    t.servers.insert(fingerprint.to_string());
    if t.domain.is_empty() {
        t.domain = paths.domain.clone();
    }
    Ok(t)
}

impl State {
    pub fn new(paths: Paths) -> Result<Shared> {
        std::fs::create_dir_all(&paths.data_dir)?;
        std::fs::create_dir_all(paths.snapshots_dir())?;
        let key = load_key(&paths.key_path())?;
        let fingerprint = key.public_key().fingerprint();
        let trust = load_trust(&paths, &fingerprint)?;
        let inbox = crate::inbox::Inbox::open(&paths.inbox_path())?;
        // Restore the inbox from the ledger repo when it's empty (fresh deploy).
        if inbox.count()? == 0 {
            // Streamed in batches; the ledger can be far larger than memory.
            let ledger = openmanuals_ledger::Ledger::open(&paths.ledger_dir)?;
            let mut batch = Vec::with_capacity(5000);
            let mut n = 0;
            ledger.scan(None, None, &mut |line| {
                batch.push(serde_json::from_str(line)?);
                if batch.len() == 5000 {
                    n += inbox.seed(&batch)?;
                    batch.clear();
                }
                Ok(())
            })?;
            n += inbox.seed(&batch)?;
            if n > 0 {
                tracing::info!(n, "seeded inbox from ledger");
            }
        }
        let latest = paths.latest_db();
        let snapshot = if latest.exists() { Some(latest) } else { None };
        let key_wraps = crate::keywrap::KeyWraps::open(&paths.keywrap_path())?;
        let avatars = crate::avatar::Avatars::open(&paths.avatars_path())?;
        Ok(Arc::new(State {
            paths,
            inbox,
            key_wraps,
            avatars,
            key,
            fingerprint,
            trust: RwLock::new(trust),
            readers: ReaderPool::new(snapshot.clone()),
            snapshot: RwLock::new(snapshot),
            fold_trigger: Default::default(),
            budgets: crate::rate::Budgets::default(),
            fold_lock: tokio::sync::Mutex::new(()),
            contribute: Default::default(),
        }))
    }

    pub fn now() -> String {
        jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    /// A fact signed by the server key.
    pub fn server_fact(&self, t: &str, body: serde_json::Value) -> Result<openmanuals_core::Fact> {
        let mut f = openmanuals_core::Fact::new(t, &self.fingerprint, &Self::now(), body);
        self.key.sign_fact(&mut f).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(f)
    }

    /// A fresh read-only connection to the current snapshot, if one has been
    /// built. For long-lived holders (the verifier); requests use [`State::reader`].
    pub fn db(&self) -> Option<rusqlite::Connection> {
        let p = self.snapshot.read().unwrap().clone()?;
        open_reader(&p).ok()
    }

    /// A pooled read-only connection to the current snapshot (with a warm
    /// page cache and prepared-statement cache), if one has been built.
    pub fn reader(&self) -> Option<Reader<'_>> {
        self.readers.get()
    }

    /// Switch pages and lookups to a newly published snapshot. Pooled
    /// connections to the previous one are closed as they are returned.
    pub fn set_snapshot(&self, path: PathBuf) {
        let mut cur = self.snapshot.write().unwrap();
        self.readers.reset(Some(path.clone()));
        *cur = Some(path);
        self.contribute.invalidate();
    }
}

/// Bytes of the snapshot each read connection memory-maps (the snapshot is
/// ~120 MB). Measured on the real snapshot, 16 threads each running the
/// /manuals listing query on its own connection in one process: 89 queries/s
/// with ordinary reads (no faster than one thread: the threads spent their
/// time in the kernel), 3,600/s memory-mapped. Opening the file with
/// `immutable=1` turns the mapping off again (~280/s), so it isn't used.
pub const READ_MMAP_BYTES: i64 = 1 << 30;
/// Prepared statements each pooled connection keeps.
pub const STATEMENT_CACHE: usize = 64;
/// Idle connections kept; more are opened on demand and closed when returned.
pub const MAX_IDLE_READERS: usize = 64;

/// Open a snapshot for reading, memory-mapped, with a statement cache.
pub fn open_reader(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    let conn = rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
    conn.execute_batch(&format!("PRAGMA mmap_size = {READ_MMAP_BYTES}; PRAGMA query_only = 1;"))?;
    Ok(conn)
}

/// Read-only connections to the current snapshot, reused across requests.
/// Each carries a generation; [`ReaderPool::reset`] (a new snapshot) bumps it,
/// drops the idle connections, and connections still in use are closed when
/// returned instead of going back to the pool. A snapshot published by
/// another process (`openmanuals-server build`/`fold` next to a running server) is
/// noticed within [`RECHECK`] by the file's identity changing.
pub struct ReaderPool {
    inner: Mutex<PoolInner>,
}

struct PoolInner {
    generation: u64,
    path: Option<PathBuf>,
    idle: Vec<rusqlite::Connection>,
    file: Option<FileId>,
    checked: std::time::Instant,
}

/// How often the pool checks whether `latest.db` was replaced behind its back.
pub const RECHECK: std::time::Duration = std::time::Duration::from_secs(1);

type FileId = (u64, u64, Option<std::time::SystemTime>);

fn file_id(p: &Path) -> Option<FileId> {
    let m = std::fs::metadata(p).ok()?;
    #[cfg(unix)]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt;
        (m.dev(), m.ino())
    };
    #[cfg(not(unix))]
    let (dev, ino) = (0, m.len());
    Some((dev, ino, m.modified().ok()))
}

impl ReaderPool {
    pub fn new(path: Option<PathBuf>) -> Self {
        let file = path.as_deref().and_then(file_id);
        ReaderPool { inner: Mutex::new(PoolInner { generation: 0, path, idle: Vec::new(), file, checked: std::time::Instant::now() }) }
    }

    pub fn generation(&self) -> u64 {
        self.inner.lock().unwrap().generation
    }

    pub fn idle(&self) -> usize {
        self.inner.lock().unwrap().idle.len()
    }

    pub fn reset(&self, path: Option<PathBuf>) {
        let old = {
            let mut g = self.inner.lock().unwrap();
            g.generation += 1;
            g.file = path.as_deref().and_then(file_id);
            g.checked = std::time::Instant::now();
            g.path = path;
            std::mem::take(&mut g.idle)
        };
        drop(old); // closed outside the lock
    }

    pub fn get(&self) -> Option<Reader<'_>> {
        let mut stale = Vec::new();
        let (generation, path) = {
            let mut g = self.inner.lock().unwrap();
            if g.checked.elapsed() >= RECHECK {
                g.checked = std::time::Instant::now();
                let now = g.path.as_deref().and_then(file_id);
                if now != g.file {
                    g.file = now;
                    g.generation += 1;
                    stale = std::mem::take(&mut g.idle);
                }
            }
            if let Some(conn) = g.idle.pop() {
                return Some(Reader { pool: self, generation: g.generation, conn: Some(conn) });
            }
            (g.generation, g.path.clone()?)
        };
        drop(stale);
        match open_reader(&path) {
            Ok(conn) => Some(Reader { pool: self, generation, conn: Some(conn) }),
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "cannot open snapshot");
                None
            }
        }
    }
}

/// A pooled connection; derefs to `rusqlite::Connection`.
pub struct Reader<'a> {
    pool: &'a ReaderPool,
    generation: u64,
    conn: Option<rusqlite::Connection>,
}

impl std::ops::Deref for Reader<'_> {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &rusqlite::Connection {
        self.conn.as_ref().unwrap()
    }
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else { return };
        let mut g = self.pool.inner.lock().unwrap();
        if g.generation == self.generation && g.idle.len() < MAX_IDLE_READERS {
            g.idle.push(conn);
            return;
        }
        drop(g);
        drop(conn);
    }
}

/// `query_row` through the connection's prepared-statement cache.
pub trait CachedQuery {
    fn query_row_cached<T, P: rusqlite::Params, F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>>(&self, sql: &str, params: P, f: F) -> rusqlite::Result<T>;
}

impl CachedQuery for rusqlite::Connection {
    fn query_row_cached<T, P: rusqlite::Params, F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>>(&self, sql: &str, params: P, f: F) -> rusqlite::Result<T> {
        self.prepare_cached(sql)?.query_row(params, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db(p: &Path, v: i64) {
        let c = rusqlite::Connection::open(p).unwrap();
        c.execute_batch(&format!("CREATE TABLE t (v INTEGER); INSERT INTO t VALUES ({v});")).unwrap();
    }

    fn value(r: &Reader<'_>) -> i64 {
        r.query_row_cached("SELECT v FROM t", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn pool_reuses_connections_and_drops_them_on_reset() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a.db"), dir.path().join("b.db"));
        make_db(&a, 1);
        make_db(&b, 2);
        let pool = ReaderPool::new(Some(a.clone()));
        {
            let r1 = pool.get().unwrap();
            let r2 = pool.get().unwrap();
            assert_eq!((value(&r1), value(&r2)), (1, 1));
        }
        assert_eq!(pool.idle(), 2, "both returned");
        let held = pool.get().unwrap();
        assert_eq!(pool.idle(), 1);
        pool.reset(Some(b.clone()));
        assert_eq!(pool.idle(), 0, "idle connections to the old snapshot closed");
        assert_eq!(value(&held), 1, "a connection in use keeps reading its snapshot");
        drop(held);
        assert_eq!(pool.idle(), 0, "and is closed when returned");
        assert_eq!(value(&pool.get().unwrap()), 2);
        assert_eq!(pool.idle(), 1);
        assert!(ReaderPool::new(None).get().is_none());
    }

    #[test]
    fn pool_notices_a_snapshot_replaced_by_another_process() {
        let dir = tempfile::tempdir().unwrap();
        let latest = dir.path().join("latest.db");
        make_db(&latest, 1);
        let pool = ReaderPool::new(Some(latest.clone()));
        assert_eq!(value(&pool.get().unwrap()), 1);
        // What publish does: a new file renamed over latest.db.
        let tmp = dir.path().join("new.db");
        make_db(&tmp, 2);
        std::fs::rename(&tmp, &latest).unwrap();
        assert_eq!(value(&pool.get().unwrap()), 1, "checked at most every RECHECK");
        std::thread::sleep(RECHECK + std::time::Duration::from_millis(50));
        assert_eq!(value(&pool.get().unwrap()), 2);
    }
}
