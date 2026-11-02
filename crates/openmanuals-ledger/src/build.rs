//! Deterministic `manuals.db` from a ledger. Same entries + same config ⇒ the
//! same bytes: fixed page size, rows inserted in sorted order inside one
//! transaction, no timestamps. How the ledger was read (streamed, in memory,
//! resumed from a checkpoint, with facts taken back in place) and which table
//! parts were reused never changes the bytes.

use crate::checkpoint::{self, DayPolicy, Header, Store};
use crate::compact::{ulid_str, FactId};
use crate::config::TrustConfig;
use crate::index::{self, Index, Prefix};
use crate::ledger::{Entry, Ledger, Peek, Pos};
use crate::model::{is_moderation_type, Model, Resolver};
use crate::view::EntryView;
use anyhow::{Context, Result};
use rayon::prelude::*;
use rusqlite::{params, Connection, ToSql};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Version of the snapshot's tables and indexes, recorded in `meta.schema`.
/// Bump it whenever SCHEMA changes: servers rebuild a published snapshot
/// whose version differs (queries may rely on new tables or indexes).
/// 2: FTS5 search index (`manual_fts`), partial indexes on verified copies.
/// 3: `files.review` (why a file is held back from being a download).
/// 4: `keys.avatar_sha256`, `avatar_mime`, `avatar_url` (the key's current avatar).
pub const SNAPSHOT_SCHEMA: &str = "4";

pub const SCHEMA: &str = r#"
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE keys (
  fingerprint TEXT PRIMARY KEY, contributor TEXT NOT NULL, alg TEXT, jwk TEXT,
  profile_jws TEXT, profile_name TEXT, facts INTEGER NOT NULL, verified_copies INTEGER NOT NULL,
  vouches INTEGER NOT NULL, links INTEGER NOT NULL, avatar_sha256 TEXT, avatar_mime TEXT, avatar_url TEXT
) WITHOUT ROWID;
CREATE TABLE contributors (id TEXT PRIMARY KEY, name TEXT, keys INTEGER NOT NULL, facts INTEGER NOT NULL, verified_copies INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE identity_links (key TEXT NOT NULL, service TEXT NOT NULL, handle TEXT NOT NULL, claim_uri TEXT NOT NULL, PRIMARY KEY (key, service, handle, claim_uri)) WITHOUT ROWID;
CREATE TABLE manuals (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, doc_type TEXT NOT NULL, language TEXT, year INTEGER,
  source TEXT, source_id TEXT, source_url TEXT, author TEXT NOT NULL, cursor TEXT NOT NULL,
  canonical_file TEXT, brand TEXT, model TEXT
) WITHOUT ROWID;
CREATE INDEX manuals_source_url ON manuals(source_url);
CREATE INDEX manuals_source ON manuals(source, source_id);
CREATE INDEX manuals_brand ON manuals(brand);
CREATE TABLE products (key TEXT PRIMARY KEY, brand TEXT NOT NULL, model TEXT NOT NULL, brand_key TEXT NOT NULL) WITHOUT ROWID;
CREATE INDEX products_brand ON products(brand_key);
CREATE TABLE covers (manual TEXT NOT NULL, product TEXT NOT NULL, PRIMARY KEY (manual, product)) WITHOUT ROWID;
CREATE INDEX covers_product ON covers(product);
CREATE TABLE files (
  id TEXT PRIMARY KEY, sha256 TEXT, sha1 TEXT, md5 TEXT, size INTEGER, mime TEXT, pages INTEGER,
  author TEXT NOT NULL, cursor TEXT NOT NULL, derived_from TEXT, transform TEXT, tool TEXT, tool_version TEXT,
  report_weight REAL NOT NULL, flagged INTEGER NOT NULL, canonical_location TEXT, review TEXT
) WITHOUT ROWID;
CREATE INDEX files_sha1 ON files(sha1);
CREATE TABLE manual_files (manual TEXT NOT NULL, file TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (manual, file, role)) WITHOUT ROWID;
CREATE INDEX manual_files_file ON manual_files(file);
CREATE TABLE locations (
  id TEXT PRIMARY KEY, file TEXT NOT NULL, url TEXT NOT NULL, host TEXT NOT NULL, kind TEXT NOT NULL,
  status TEXT NOT NULL, verified_at TEXT, final_url TEXT, ia_identifier TEXT, ia_filename TEXT,
  author TEXT NOT NULL, cursor TEXT NOT NULL, report_weight REAL NOT NULL, flagged INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX locations_file ON locations(file);
CREATE INDEX locations_url ON locations(url);
CREATE INDEX locations_ia ON locations(ia_identifier);
CREATE INDEX locations_author ON locations(author);
CREATE INDEX locations_verified ON locations(cursor) WHERE status = 'verified';
CREATE INDEX locations_author_verified ON locations(author, cursor) WHERE status = 'verified';
CREATE TABLE derivations (derived TEXT NOT NULL, source TEXT NOT NULL, transform TEXT NOT NULL, tool TEXT, tool_version TEXT, author TEXT NOT NULL);
CREATE TABLE labels (id TEXT PRIMARY KEY, target TEXT NOT NULL, ns TEXT NOT NULL, value TEXT NOT NULL, reason TEXT, author TEXT NOT NULL, weight REAL NOT NULL) WITHOUT ROWID;
CREATE INDEX labels_target ON labels(target);
CREATE TABLE manual_search (manual TEXT PRIMARY KEY, text TEXT NOT NULL, downloadable INTEGER NOT NULL);
CREATE INDEX manual_search_dl ON manual_search(downloadable);
CREATE VIRTUAL TABLE manual_fts USING fts5(text, content='manual_search', content_rowid='rowid', tokenize='trigram', detail='none');
CREATE TABLE brands (brand_key TEXT PRIMARY KEY, brand TEXT NOT NULL, manuals INTEGER NOT NULL, downloadable INTEGER NOT NULL) WITHOUT ROWID;
"#;

#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    /// Re-check every signature (slow on large ledgers; the inbox already did it).
    pub verify_signatures: bool,
    /// Resume from this checkpoint when it is still valid, and leave a fresh
    /// one there afterwards. Day checkpoints, the ledger index and the table
    /// parts of the last snapshot go in `<checkpoint>.cache/` (see
    /// [`checkpoint::Store`]).
    pub checkpoint: Option<PathBuf>,
}

/// Settings beyond [`BuildOptions`]; the defaults are what [`build`] uses.
#[derive(Debug, Clone)]
pub struct Tuning {
    /// Which day checkpoints to keep.
    pub days: DayPolicy,
    /// Reuse the previous snapshot's table parts when their rows are unchanged.
    pub reuse_parts: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning { days: DayPolicy::default(), reuse_parts: true }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BuildMode {
    /// Streamed the whole ledger.
    #[default]
    Full,
    /// Resumed from a checkpoint.
    Incremental,
}

#[derive(Debug, Clone, Default)]
pub struct BuildStats {
    pub entries: usize,
    pub invalid: usize,
    pub blocked: usize,
    pub retracted: usize,
    pub manuals: usize,
    pub products: usize,
    pub files: usize,
    pub locations: usize,
    pub verified_locations: usize,
    pub keys: usize,
    pub head: Option<String>,
    pub mode: BuildMode,
    /// Ledger entries read and applied by this build.
    pub applied: usize,
    /// Already-applied facts taken back in place because new moderation hides them.
    pub undone: usize,
    /// The state an incremental build started from: `resident`, `checkpoint`
    /// or `day YYYY/MM/DD.jsonl`.
    pub resumed_from: Option<String>,
    /// Why a checkpoint was not used, when one was configured (for a build
    /// resumed from a day checkpoint: why the newer ones were not).
    pub full_rebuild_reason: Option<String>,
    /// Table groups copied from the previous snapshot's parts / written anew.
    pub parts_reused: usize,
    pub parts_written: usize,
    pub timings: Timings,
}

/// Milliseconds per phase.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timings {
    /// Loading the checkpoint, undoing, and reading/applying ledger entries.
    pub read: u64,
    /// Writing the checkpoint (a resident build leaves that to the caller).
    pub save_checkpoint: u64,
    /// Whole-catalog rules (`Resolver::finish`).
    pub resolve: u64,
    pub write: u64,
}

fn ms(t: std::time::Instant) -> u64 {
    t.elapsed().as_millis() as u64
}

/// Resolver state kept in memory between builds by a long-running process
/// (see [`build_resident`]); saving it is the caller's business.
pub struct Resident {
    r: Resolver,
    header: Header,
}

impl Resident {
    /// Write it as the checkpoint (atomically: a crash leaves the previous one).
    pub fn save(&self, checkpoint: &Path) -> Result<()> {
        checkpoint::save(checkpoint, &self.header, &self.r)
    }
    /// Where the next build resumes.
    pub fn end(&self) -> &Pos {
        &self.header.end
    }
}

/// Build `out` from the ledger at `ledger`.
pub fn build(ledger: &Ledger, cfg: &TrustConfig, out: &Path, opts: &BuildOptions) -> Result<BuildStats> {
    build_with(ledger, cfg, out, opts, &Tuning::default())
}

pub fn build_with(ledger: &Ledger, cfg: &TrustConfig, out: &Path, opts: &BuildOptions, tuning: &Tuning) -> Result<BuildStats> {
    Ok(run(ledger, cfg, out, opts, tuning, None, true)?.0)
}

/// [`build`] for a process that keeps the resolver in memory: resumes from
/// `resident` when it still describes the ledger (else from the checkpoint
/// files, else from scratch), and returns the new state instead of writing
/// `opts.checkpoint` (call [`Resident::save`] when convenient). Day
/// checkpoints, the index and table parts are still written. Without
/// `opts.checkpoint` it is a plain full build and returns no state.
pub fn build_resident(ledger: &Ledger, cfg: &TrustConfig, out: &Path, opts: &BuildOptions, tuning: &Tuning, resident: Option<Resident>) -> Result<(BuildStats, Option<Resident>)> {
    run(ledger, cfg, out, opts, tuning, resident, false)
}

/// Work handed to the background thread of a build.
enum Job {
    /// Build a complete file's index filter from its keys.
    Filter(String, u64, Vec<u64>),
}

/// What the background thread made: index filters of complete files.
type Built = Vec<(String, u64, Vec<u8>)>;

/// What the passes need besides the resolver.
struct Ctx<'a> {
    ledger: &'a Ledger,
    cfg: &'a TrustConfig,
    verify: bool,
    store: Option<&'a Store>,
    tuning: &'a Tuning,
    jobs: std::sync::mpsc::SyncSender<Job>,
}

/// A resolver brought up to the end of the ledger.
struct Reached {
    r: Resolver,
    end: Option<Pos>,
    open_keys: Option<Vec<u64>>,
    mode: BuildMode,
    applied: usize,
    undone: usize,
    resumed_from: Option<String>,
    /// For a build resumed from a day checkpoint: why newer state was not used.
    why: Option<String>,
}

fn run(ledger: &Ledger, cfg: &TrustConfig, out: &Path, opts: &BuildOptions, tuning: &Tuning, resident: Option<Resident>, save_main: bool) -> Result<(BuildStats, Option<Resident>)> {
    let t0 = std::time::Instant::now();
    let mut t = Timings::default();
    let store = opts.checkpoint.as_deref().map(Store::new);
    let lengths = ledger.file_lengths()?;
    let mut index = match &store {
        Some(s) => Index::load(&s.index_path()),
        None => Index::default(),
    };
    index.retain_current(&lengths);
    std::thread::scope(|sc| -> Result<(BuildStats, Option<Resident>)> {
        let (jobs, jrx) = std::sync::mpsc::sync_channel::<Job>(1);
        let worker = sc.spawn(move || -> Built {
            let mut filters = Vec::new();
            for job in jrx {
                match job {
                    Job::Filter(file, len, mut keys) => match index::build_filter(&mut keys) {
                        Ok(raw) => filters.push((file, len, raw)),
                        Err(e) => tracing::warn!(error = %e, "could not build a ledger index filter"),
                    },
                }
            }
            filters
        });
        let ctx = Ctx { ledger, cfg, verify: opts.verify_signatures, store: store.as_ref(), tuning, jobs };
        let mut reason = None;
        let mut reached = None;
        if let Some(st) = &store {
            match incremental(&ctx, st, &lengths, &index, resident)? {
                Ok(v) => reached = Some(v),
                Err(why) => {
                    tracing::info!(reason = %why, "full rebuild");
                    reason = Some(why);
                }
            }
        }
        let reached = match reached {
            Some(v) => v,
            None => match full(&ctx, Scan::Fast)? {
                Some(v) => v,
                None => {
                    tracing::warn!("the fast scan missed a moderation fact (non-canonical ledger line?); rebuilding with the exact scan");
                    full(&ctx, Scan::Exact)?.expect("the exact scan sees every moderation fact")
                }
            },
        };
        drop(ctx);
        let Reached { r, end, open_keys, mode, applied, undone, resumed_from, why } = reached;
        reason = reason.or(why);
        t.read = ms(t0);

        // The checkpoint for the next build.
        let header = match (&store, end) {
            (Some(_), Some(end)) => Some(Header::new(&ledger.file_lengths()?, cfg, opts.verify_signatures, end.clone(), end, open_keys)),
            _ => None,
        };
        // A plain build saves the checkpoint first and hands the resolver to
        // `finish` (one copy in memory); a resident build keeps it and
        // finishes a clone.
        if let (true, Some(st), Some(h)) = (save_main, &store, &header) {
            let t1 = std::time::Instant::now();
            if let Err(e) = checkpoint::save(&st.main, h, &r) {
                // The snapshot is still right; the next build is just slower.
                tracing::warn!(error = %e, "could not write checkpoint");
            }
            t.save_checkpoint = ms(t1);
        }
        let (model_r, kept) = match (&header, save_main) {
            (Some(_), false) => (r.clone(), Some(r)),
            _ => (r, None),
        };
        let parts_dir = store.as_ref().filter(|_| tuning.reuse_parts).map(|s| s.parts_dir());
        let mut stats = finish(model_r, cfg, out, parts_dir.as_deref(), &mut t)?;
        let filters = worker.join().map_err(|_| anyhow::anyhow!("build worker panicked"))?;
        if let Some(st) = &store {
            for (file, len, raw) in filters {
                index.insert_raw(&file, len, raw)?;
            }
            if let Err(e) = index.save(&st.index_path()) {
                tracing::warn!(error = %e, "could not write the ledger index");
            }
            let lengths = ledger.file_lengths()?;
            st.prune_days(&tuning.days.keep(&complete_files(&lengths)));
        }
        stats.mode = mode;
        stats.applied = applied;
        stats.undone = undone;
        stats.resumed_from = resumed_from;
        stats.full_rebuild_reason = reason;
        stats.timings = t;
        let resident = match (save_main, header, kept) {
            (false, Some(header), Some(r)) => Some(Resident { r, header }),
            _ => None,
        };
        Ok((stats, resident))
    })
}

/// Every ledger file but the last (the fold job only appends to the newest day).
fn complete_files(lengths: &[(String, u64)]) -> Vec<String> {
    lengths.iter().take(lengths.len().saturating_sub(1)).map(|(f, _)| f.clone()).collect()
}

/// Both passes over the whole ledger; `None` if pass 2 met a moderation fact
/// pass 1 did not (only possible with `Scan::Fast`).
fn full(ctx: &Ctx, scan: Scan) -> Result<Option<Reached>> {
    // Pass 2 stops where pass 1 did, so a concurrent append can't slip in
    // facts whose moderation pass 1 never saw.
    let mut r = Resolver::default();
    let (end, seen) = moderation_pass(ctx.ledger, None, None, ctx.verify, scan, &mut |e| r.moderation.apply(&e, ctx.cfg))?;
    let Some(end) = end else {
        return Ok(Some(Reached { r, end: None, open_keys: None, mode: BuildMode::Full, applied: 0, undone: 0, resumed_from: None, why: None }));
    };
    let days = DaySaves::new(ctx, &end)?;
    let Some(pass) = apply_pass(ctx, None, &end, &mut r, OpenKeys { keys: vec![], from_start: true }, &seen, days.as_ref())? else {
        return Ok(None);
    };
    let applied = r.stats.entries;
    Ok(Some(Reached { r, end: Some(pass.end), open_keys: pass.open_keys, mode: BuildMode::Full, applied, undone: 0, resumed_from: None, why: None }))
}

/// Build from entries already in memory (tests, tools).
pub fn build_from_entries(entries: &[Entry], cfg: &TrustConfig, out: &Path, opts: &BuildOptions) -> Result<BuildStats> {
    let keep: Vec<bool> = entries.par_iter().map(|e| !opts.verify_signatures || e.fact.verify().is_ok()).collect();
    let kept = || entries.iter().zip(&keep).filter(|(_, k)| **k).map(|(e, _)| e);
    let mut r = Resolver::default();
    for e in kept().filter(|e| is_moderation_type(&e.fact.r#type)) {
        r.moderation.apply(e, cfg);
    }
    for e in kept() {
        r.apply_entry(e, cfg);
    }
    let n = r.stats.entries;
    let mut t = Timings::default();
    let mut stats = finish(r, cfg, out, None, &mut t)?;
    stats.applied = n;
    stats.timings = t;
    Ok(stats)
}

/// How pass 1 finds moderation facts.
#[derive(Clone, Copy)]
enum Scan {
    /// SIMD substring search for `"type":"block"` etc. The ledger writer
    /// (serde_json) always spells it that way, so this never misses a fact in
    /// a ledger we wrote; false hits are parsed and dropped. Pass 2 counts the
    /// moderation facts it parses per file, and a mismatch means a rebuild
    /// with `Exact`.
    Fast,
    /// Parse every line's `type` (for a ledger written some other way).
    Exact,
}

struct Prefilter([memchr::memmem::Finder<'static>; 3]);

impl Prefilter {
    fn new() -> Self {
        let f = |p: &'static str| memchr::memmem::Finder::new(p.as_bytes());
        Prefilter([f(r#""type":"block""#), f(r#""type":"unblock""#), f(r#""type":"retract""#)])
    }
    fn hit(&self, line: &[u8]) -> bool {
        self.0.iter().any(|f| f.find(line).is_some())
    }
}

/// Moderation facts seen by pass 1 in each ledger file.
type ModCounts = BTreeMap<String, usize>;

/// Pass 1: parse only moderation facts. Returns the position reached and how
/// many moderation facts it saw per file (before any signature check).
fn moderation_pass(ledger: &Ledger, from: Option<&Pos>, until: Option<&Pos>, verify: bool, scan: Scan, f: &mut dyn FnMut(Entry)) -> Result<(Option<Pos>, ModCounts)> {
    let pre = Prefilter::new();
    let seen = std::cell::Cell::new(0usize);
    let mut counts = ModCounts::new();
    let end = ledger.scan_files(from, until, &mut |line| {
        let candidate = match scan {
            Scan::Fast => pre.hit(line),
            Scan::Exact => is_moderation_type(&serde_json::from_slice::<Peek>(line)?.fact.r#type),
        };
        if candidate {
            let e: Entry = serde_json::from_slice(line)?;
            if is_moderation_type(&e.fact.r#type) {
                seen.set(seen.get() + 1);
                if !verify || e.fact.verify().is_ok() {
                    f(e);
                }
            }
        }
        Ok(())
    }, &mut |pos, _| {
        counts.insert(pos.file.clone(), seen.replace(0));
        Ok(())
    })?;
    Ok((end, counts))
}

/// Lines handed from the reader thread to the parser, in ledger order.
#[derive(Default)]
struct Batch {
    buf: Vec<u8>,
    ends: Vec<usize>,
    /// The batch ends a file: where reading it stopped, and whether it is complete.
    file_end: Option<(Pos, bool)>,
}

impl Batch {
    fn push(&mut self, line: &[u8]) {
        self.buf.extend_from_slice(line);
        self.ends.push(self.buf.len());
    }
    fn full(&self) -> bool {
        self.ends.len() >= 1024 || self.buf.len() >= (4 << 20)
    }
}

/// A batch with every line parsed into a view of the batch's own buffer.
struct Parsed {
    // Declared before `_buf`, so dropped before the bytes it borrows.
    items: Vec<(EntryView<'static>, bool)>,
    keys: Vec<u64>,
    file_end: Option<(Pos, bool)>,
    _buf: Vec<u8>,
}

impl Parsed {
    /// Parse (and with `verify`, check the signature of) every line on the
    /// current rayon pool; results keep their order.
    fn new(b: Batch, verify: bool) -> Result<Parsed> {
        let Batch { buf, ends, file_end } = b;
        // SAFETY: the views borrow `buf`'s heap allocation. Both fields are
        // private, `buf` is never touched again and is dropped after `items`,
        // and moving a Vec does not move its allocation, so the bytes outlive
        // every view; `items()` hands views out only for as long as `self`.
        let bytes: &'static [u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        let parsed = (0..ends.len()).into_par_iter().map(|i| {
            let line = &bytes[if i == 0 { 0 } else { ends[i - 1] }..ends[i]];
            let ctx = || format!("ledger line {}", String::from_utf8_lossy(&line[..line.len().min(100)]));
            let mut e: EntryView = serde_json::from_slice(line).with_context(ctx)?;
            e.prepare();
            let keys = index::line_keys(&e, e.prep.as_ref().and_then(|p| p.fid));
            // Signatures are checked on the full fact (canonical form and all).
            let ok = !verify || serde_json::from_slice::<Entry>(line).with_context(ctx)?.fact.verify().is_ok();
            Ok(((e, ok), keys))
        }).collect::<Result<Vec<_>>>()?;
        let mut keys = Vec::with_capacity(parsed.len() * 2);
        let items = parsed.into_iter().map(|(item, k)| {
            keys.extend(k.into_iter().flatten());
            item
        }).collect();
        Ok(Parsed { items, keys, file_end, _buf: buf })
    }

    fn items(&self) -> &[(EntryView<'_>, bool)] {
        &self.items
    }
}

/// Index keys of the file being read, and whether they start at its beginning.
struct OpenKeys {
    keys: Vec<u64>,
    from_start: bool,
}

/// Day checkpoints to write while a pass crosses file ends.
/// An existing one is replaced: a pass only crosses a day it already saved
/// when it replays from an older checkpoint, and then its state carries the
/// newer moderation (or, in a full build, a possibly different trust config).
struct DaySaves<'a> {
    store: &'a Store,
    keep: BTreeSet<String>,
    lengths: Vec<(String, u64)>,
    mod_end: Pos,
}

impl<'a> DaySaves<'a> {
    fn new(ctx: &Ctx<'a>, mod_end: &Pos) -> Result<Option<DaySaves<'a>>> {
        let Some(store) = ctx.store else { return Ok(None) };
        let lengths = ctx.ledger.file_lengths()?;
        let keep = ctx.tuning.days.keep(&complete_files(&lengths));
        Ok(Some(DaySaves { store, keep, lengths, mod_end: mod_end.clone() }))
    }
}

struct PassOut {
    end: Pos,
    /// Keys of the last file's lines, if the pass saw it from its start.
    open_keys: Option<Vec<u64>>,
}

/// Pass 2: every fact from `from` to `until`, once, dropped after it is
/// applied. A reader thread feeds batches of lines; each batch is parsed on
/// the pool while the previous one is applied in order on this thread, so
/// the result is the same as a sequential pass. Along the way it collects
/// each file's index keys and saves day checkpoints. `None` when a file's
/// moderation facts differ from what pass 1 counted in it.
fn apply_pass(ctx: &Ctx, from: Option<&Pos>, until: &Pos, r: &mut Resolver, mut open: OpenKeys, counts: &ModCounts, days: Option<&DaySaves>) -> Result<Option<PassOut>> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Batch>(1);
    // Parsing alone stops scaling at ~8 threads (applying facts in order on
    // this thread is then the limit, and more workers only crowd it out);
    // signature checks are heavy enough to use every core.
    let avail = std::thread::available_parallelism().map_or(1, |n| n.get());
    let threads = if ctx.verify { avail } else { avail.min(8) };
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).thread_name(|i| format!("om-parse-{i}")).build()?;
    let verify = ctx.verify;
    let ledger = ctx.ledger;
    // Three stages run at once: reading lines, parsing a batch on the pool,
    // and applying the previous batch here.
    let (ptx, prx) = std::sync::mpsc::sync_channel::<Result<Parsed>>(1);
    std::thread::scope(|s| {
        let reader = s.spawn(move || -> Result<Option<Pos>> {
            let b = std::cell::RefCell::new(Batch::default());
            let stopped = || anyhow::anyhow!("build stopped");
            ledger.scan_files(from, Some(until), &mut |line| {
                let mut b = b.borrow_mut();
                b.push(line);
                if b.full() {
                    tx.send(std::mem::take(&mut *b)).map_err(|_| stopped())?;
                }
                Ok(())
            }, &mut |pos, complete| {
                // A file's end always ends a batch, so the applier knows
                // exactly which lines a file (and a day checkpoint) covers.
                let mut last = std::mem::take(&mut *b.borrow_mut());
                last.file_end = Some((pos.clone(), complete));
                tx.send(last).map_err(|_| stopped())
            })
        });
        let pool = &pool;
        s.spawn(move || {
            while let Ok(b) = rx.recv() {
                let p = pool.install(|| Parsed::new(b, verify));
                let failed = p.is_err();
                if ptx.send(p).is_err() || failed {
                    break;
                }
            }
        });
        let mut mods = 0usize;
        let mut failed = None;
        let mut mismatch = false;
        while let Ok(p) = prx.recv() {
            let p = match p {
                Ok(p) => p,
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            };
            for (e, ok) in p.items() {
                if is_moderation_type(&e.fact.r#type) {
                    mods += 1;
                }
                if *ok {
                    r.apply(e, ctx.cfg);
                }
            }
            open.keys.extend_from_slice(&p.keys);
            let Some((pos, complete)) = &p.file_end else { continue };
            if counts.get(&pos.file).copied().unwrap_or(0) != std::mem::take(&mut mods) {
                mismatch = true;
                break;
            }
            if !complete {
                continue;
            }
            // A finished file: its filter, and maybe a day checkpoint.
            let keys = std::mem::take(&mut open.keys);
            if std::mem::replace(&mut open.from_start, true) {
                let _ = ctx.jobs.send(Job::Filter(pos.file.clone(), pos.offset, keys));
            }
            if let Some(d) = days.filter(|d| d.keep.contains(&pos.file)) {
                if let Some(path) = d.store.day_path(&pos.file) {
                    // Streamed from here (about 0.1 s at 400k facts, once per
                    // day boundary) rather than from a copy on another
                    // thread, which would hold the whole state twice.
                    let h = Header::new(&d.lengths, ctx.cfg, verify, pos.clone(), d.mod_end.clone(), None);
                    if let Err(e) = checkpoint::save_compressed(&path, &h, r) {
                        tracing::warn!(error = %e, path = %path.display(), "could not write day checkpoint");
                    }
                }
            }
        }
        drop(prx); // unblocks the parser (and so the reader) if we stopped early
        let end = reader.join().map_err(|_| anyhow::anyhow!("ledger reader panicked"))?;
        if let Some(e) = failed {
            return Err(e);
        }
        if mismatch {
            return Ok(None);
        }
        let end = end?.unwrap_or_else(|| until.clone());
        let keys = open.from_start.then_some(open.keys);
        Ok(Some(PassOut { end, open_keys: keys }))
    })
}

/// Why a checkpoint could not be resumed.
enum Retry {
    /// The new moderation needs facts from this ledger file on re-applied:
    /// try a checkpoint that ends before it.
    Before(String, String),
    /// Give up on checkpoints.
    Full(String),
}

/// Bring a checkpointed state up to the end of the ledger, trying the
/// resident state or `checkpoint.bin` first and then day checkpoints, newest
/// first, until one can absorb the new moderation. `Err(reason)` means a full
/// rebuild.
fn incremental(ctx: &Ctx, store: &Store, lengths: &[(String, u64)], index: &Index, resident: Option<Resident>) -> Result<Result<Reached, String>> {
    let resident = resident.filter(|res| res.header.mismatch(lengths, ctx.cfg, ctx.verify).is_none());
    if resident.is_none() && !store.main.exists() {
        // Deleting the checkpoint means starting over: day checkpoints go too.
        store.clear_days();
        return Ok(Err("no checkpoint".into()));
    }
    let mut first = Some(match resident {
        Some(res) => (Ok((res.r, res.header)), "resident".to_string()),
        None => (checkpoint::load(&store.main, lengths, ctx.cfg, ctx.verify)?, "checkpoint".to_string()),
    });
    let days = store.days();
    let mut days = days.into_iter();
    let mut limit: Option<String> = None;
    // Why the newest state was not used, and why the last one tried was not.
    let mut first_why: Option<String> = None;
    let mut why: Option<String> = None;
    loop {
        let (loaded, name) = match first.take() {
            Some(v) => v,
            None => {
                let Some((file, path)) = days.next() else { break };
                if limit.as_ref().is_some_and(|l| file >= *l) {
                    continue;
                }
                (checkpoint::load(&path, lengths, ctx.cfg, ctx.verify)?, format!("day {file}"))
            }
        };
        let (r, header) = match loaded {
            Ok(v) => v,
            Err(e) => {
                first_why.get_or_insert(e.clone());
                why.get_or_insert(e);
                continue;
            }
        };
        if limit.as_ref().is_some_and(|l| header.end.file >= *l) {
            continue;
        }
        match resume(ctx, index, lengths, r, header)? {
            Ok(mut reached) => {
                reached.why = first_why.filter(|_| name.starts_with("day"));
                reached.resumed_from = Some(name);
                return Ok(Ok(reached));
            }
            Err(Retry::Before(file, w)) => {
                tracing::info!(from = %name, reason = %w, before = %file, "moderation reaches back; trying an older checkpoint");
                first_why.get_or_insert(w.clone());
                why = Some(w);
                if limit.as_ref().is_none_or(|l| file < *l) {
                    limit = Some(file);
                }
            }
            Err(Retry::Full(w)) => return Ok(Err(w)),
        }
    }
    Ok(Err(match (why, limit) {
        (Some(w), Some(_)) => format!("{w} (no checkpoint before it)"),
        (Some(w), None) => w,
        (None, _) => "no usable checkpoint".into(),
    }))
}

/// Apply what the ledger gained since a checkpoint. New moderation that hides
/// facts the checkpoint already applied is taken back in place
/// ([`Resolver::unapply`]) when that provably gives what a full build would;
/// otherwise `Retry::Before` names the earliest ledger file to re-apply.
fn resume(ctx: &Ctx, index: &Index, lengths: &[(String, u64)], mut r: Resolver, h: Header) -> Result<Result<Reached, Retry>> {
    let before = r.stats.entries;
    let mut news: Vec<Entry> = Vec::new();
    let (end, counts) = moderation_pass(ctx.ledger, Some(&h.end), None, ctx.verify, Scan::Fast, &mut |e| news.push(e))?;
    let end = end.unwrap_or_else(|| h.end.clone());
    let old = r.moderation().clone();
    let mut new = old.clone();
    for e in &news {
        new.apply(e, ctx.cfg);
    }
    let (ob, nb) = (old.blocks(), new.blocks());
    let open_keys: Option<HashSet<u64>> = h.open_keys.as_ref().map(|k| k.iter().copied().collect());
    let prefix = Prefix { ledger: ctx.ledger, index, end: &h.end, open_keys: open_keys.as_ref(), lengths };
    let mut undone = 0;
    if !news.is_empty() {
        // A key (un)blocked, or a manual unblocked: re-apply from its first fact.
        for k in ob.keys.symmetric_difference(&nb.keys) {
            if let Some(f) = prefix.first_with(index::author_key(k)) {
                let what = if nb.keys.contains(k) { "block" } else { "unblock" };
                return Ok(Err(Retry::Before(f, format!("new moderator {what} of key {k}"))));
            }
        }
        for m in ob.manuals.difference(&nb.manuals) {
            if let Some(f) = prefix.first_with(index::manual_key(*m)) {
                return Ok(Err(Retry::Before(f, format!("new moderator unblock of manual {}", ulid_str(*m)))));
            }
        }
        let newly_blocked: HashSet<u128> = nb.manuals.difference(&ob.manuals).copied().collect();
        // Facts (un)blocked or newly retracted.
        let mut targets: HashSet<FactId> = ob.facts.symmetric_difference(&nb.facts).filter_map(|s| FactId::parse(s)).collect();
        for (t, authors) in &new.retract_claims {
            let had = old.retract_claims.get(t);
            if authors.iter().any(|a| !had.is_some_and(|h| h.contains(a))) {
                targets.extend(FactId::parse(t));
            }
        }
        let lines = prefix.lines_with_ids(&targets)?;
        let mut seen_ids: HashMap<FactId, &str> = HashMap::new();
        let mut parsed = Vec::with_capacity(lines.len());
        for (file, line) in &lines {
            let mut v: EntryView = serde_json::from_slice(line)?;
            v.prepare();
            let id = v.prep.as_ref().and_then(|p| p.fid).expect("found by its id");
            if let Some(f) = seen_ids.insert(id, file) {
                return Ok(Err(Retry::Before(f.to_string(), format!("{id:?} is in the ledger twice"))));
            }
            if ctx.verify && !serde_json::from_slice::<Entry>(line)?.fact.verify().is_ok() {
                continue; // never applied
            }
            parsed.push((file, v));
        }
        for (file, v) in &parsed {
            if let Err(why) = r.unapply(v, (&old, &ob), (&new, &nb), &newly_blocked, ctx.cfg) {
                return Ok(Err(Retry::Before(file.to_string(), why)));
            }
            undone += 1;
        }
        r.block_manuals(&newly_blocked);
        r.set_moderation(new);
    }
    let days = DaySaves::new(ctx, &end)?;
    // Resuming inside a file needs its earlier keys for its filter; a day
    // checkpoint ends at a file's end (that file is already indexed).
    let open = match h.open_keys {
        Some(keys) => OpenKeys { keys, from_start: true },
        None => OpenKeys { keys: vec![], from_start: false },
    };
    let Some(pass) = apply_pass(ctx, Some(&h.end), &end, &mut r, open, &counts, days.as_ref())? else {
        return Ok(Err(Retry::Full("the fast scan missed a moderation fact".into())));
    };
    let applied = r.stats.entries - before;
    Ok(Ok(Reached { r, end: Some(pass.end), open_keys: pass.open_keys, mode: BuildMode::Incremental, applied, undone, resumed_from: None, why: None }))
}

fn finish(r: Resolver, cfg: &TrustConfig, out: &Path, parts_dir: Option<&Path>, timings: &mut Timings) -> Result<BuildStats> {
    let t0 = std::time::Instant::now();
    let model = r.finish(cfg);
    timings.resolve = ms(t0);
    let t1 = std::time::Instant::now();
    let tmp = out.with_extension("db.tmp");
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(tmp.with_extension("tmp-journal"));
    let (reused, written) = write_sqlite(&model, cfg, &tmp, parts_dir).with_context(|| "writing snapshot")?;
    std::fs::rename(&tmp, out)?;
    timings.write = ms(t1);
    let verified = model.syms.lookup("verified");
    let verified_locations = model.locations.values().filter(|l| Some(l.status) == verified).count();
    Ok(BuildStats {
        entries: model.stats.entries,
        invalid: model.stats.invalid,
        blocked: model.stats.blocked,
        retracted: model.stats.retracted,
        manuals: model.manuals.len(),
        products: model.products.len(),
        files: model.files.len(),
        locations: model.locations.len(),
        verified_locations,
        keys: model.keys.len(),
        head: model.head.clone(),
        parts_reused: reused,
        parts_written: written,
        ..Default::default()
    })
}

/// 16 KiB pages: ~1.4% smaller file and a faster write than 4 KiB (measured).
const PRAGMAS: &str = "PRAGMA page_size = 16384; PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;";

/// Bump when a part file's bytes could change for the same rows (they are
/// also keyed by the SQLite version and the group's schema).
const PART_FORMAT: u32 = 1;

/// One statement of `SCHEMA` and the table it belongs to.
struct Stmt {
    table: &'static str,
    sql: &'static str,
    index: bool,
}

fn schema() -> Vec<Stmt> {
    SCHEMA.split(';').map(str::trim).filter(|s| !s.is_empty()).map(|sql| {
        let (table, index) = if let Some(rest) = sql.strip_prefix("CREATE TABLE ").or_else(|| sql.strip_prefix("CREATE VIRTUAL TABLE ")) {
            (rest.split([' ', '(']).next().unwrap(), false)
        } else {
            let on = sql.split(" ON ").nth(1).expect("CREATE INDEX … ON table(…)");
            (on.split('(').next().unwrap().trim(), true)
        };
        Stmt { table, sql, index }
    }).collect()
}

/// Derived once, read by several table writers.
struct Prepared {
    /// Each manual's products (indexes into `Model::products`), in key order.
    products_of: HashMap<u128, Vec<u32>>,
}

/// Where a table writer's rows go: into SQLite, or into a hash of the rows.
trait Sink {
    fn insert(&mut self, sql: &'static str, row: &[&dyn ToSql]) -> Result<()>;
    fn exec(&mut self, sql: &'static str) -> Result<()>;
}

struct DbSink<'c>(&'c Connection);

impl Sink for DbSink<'_> {
    fn insert(&mut self, sql: &'static str, row: &[&dyn ToSql]) -> Result<()> {
        self.0.prepare_cached(sql)?.execute(row)?;
        Ok(())
    }
    fn exec(&mut self, sql: &'static str) -> Result<()> {
        self.0.execute_batch(sql)?;
        Ok(())
    }
}

/// SHA-256 over every statement and value, typed and length-prefixed.
struct HashSink(Sha256);

impl Sink for HashSink {
    fn insert(&mut self, sql: &'static str, row: &[&dyn ToSql]) -> Result<()> {
        use rusqlite::types::{ToSqlOutput, Value, ValueRef};
        let h = &mut self.0;
        h.update((sql.len() as u64).to_le_bytes());
        h.update(sql);
        for v in row {
            let out = v.to_sql()?;
            let v = match &out {
                ToSqlOutput::Borrowed(v) => *v,
                ToSqlOutput::Owned(v) => match v {
                    Value::Null => ValueRef::Null,
                    Value::Integer(i) => ValueRef::Integer(*i),
                    Value::Real(f) => ValueRef::Real(*f),
                    Value::Text(t) => ValueRef::Text(t.as_bytes()),
                    Value::Blob(b) => ValueRef::Blob(b),
                },
                _ => anyhow::bail!("unhashable SQL value"),
            };
            match v {
                ValueRef::Null => h.update([0]),
                ValueRef::Integer(i) => {
                    h.update([1]);
                    h.update(i.to_le_bytes());
                }
                ValueRef::Real(f) => {
                    h.update([2]);
                    h.update(f.to_bits().to_le_bytes());
                }
                ValueRef::Text(t) | ValueRef::Blob(t) => {
                    h.update([if matches!(v, ValueRef::Text(_)) { 3 } else { 4 }]);
                    h.update((t.len() as u64).to_le_bytes());
                    h.update(t);
                }
            }
        }
        Ok(())
    }
    fn exec(&mut self, sql: &'static str) -> Result<()> {
        self.0.update([9]);
        self.0.update(sql);
        Ok(())
    }
}

type Writer = fn(&mut dyn Sink, &Model, &TrustConfig, &Prepared) -> Result<()>;

/// A table group; `joined` groups are copied into the snapshot in the same
/// transaction as the group before them. (Each commit bumps the file change
/// counter in the SQLite header, so the commits stay as they were when these
/// were one group, and the bytes with them.)
struct Part {
    tables: &'static [&'static str],
    write: Writer,
    joined: bool,
}

const fn part(tables: &'static [&'static str], write: Writer) -> Part {
    Part { tables, write, joined: false }
}

const fn joined(tables: &'static [&'static str], write: Writer) -> Part {
    Part { tables, write, joined: true }
}

/// Table groups, each written into its own database file on its own thread,
/// and merged into the snapshot in this order. The slowest groups come last
/// so the earlier ones are merged while those are still being written.
/// Groups are small enough that a typical fold leaves most unchanged, so
/// their parts can be reused (`meta` changes with every build, the search
/// index only when a manual's searchable text does).
const PARTS: &[Part] = &[
    part(&["meta"], write_meta),
    joined(&["contributors", "keys", "identity_links"], write_identity),
    part(&["labels"], write_labels),
    part(&["derivations"], write_derivations),
    part(&["brands"], write_brands),
    part(&["manual_files"], write_manual_files),
    part(&["files"], write_files),
    part(&["locations"], write_locations),
    part(&["products"], write_products),
    part(&["covers"], write_covers),
    part(&["manuals"], write_manuals),
    part(&["manual_search"], write_search),
    // The trigram index over the search text (~0.4 s): the slowest group, so last.
    joined(&["manual_fts"], write_fts),
];

/// The content key of a group's part: its rows and everything else that
/// decides the part file's bytes.
fn part_key(i: usize, tables: &[&str], stmts: &[Stmt], write: Writer, m: &Model, cfg: &TrustConfig, prep: &Prepared) -> Result<String> {
    let mut h = HashSink(Sha256::new());
    h.0.update(format!("{PART_FORMAT}\0{}\0{PRAGMAS}\0{i}\0", rusqlite::version()));
    for st in stmts.iter().filter(|st| tables.contains(&st.table)) {
        h.0.update(st.sql);
        h.0.update([0]);
    }
    write(&mut h, m, cfg, prep)?;
    Ok(hex::encode(&h.0.finalize()[..16]))
}

/// Write one group's tables (rows, then indexes) into a new database file.
fn write_part(p: &Path, tables: &[&str], stmts: &[Stmt], write: Writer, m: &Model, cfg: &TrustConfig, prep: &Prepared) -> Result<()> {
    let _ = std::fs::remove_file(p);
    let conn = Connection::open(p)?;
    conn.execute_batch(PRAGMAS)?;
    for st in stmts.iter().filter(|st| !st.index && tables.contains(&st.table)) {
        conn.execute_batch(st.sql)?;
    }
    conn.execute_batch("BEGIN;")?;
    write(&mut DbSink(&conn), m, cfg, prep)?;
    conn.execute_batch("COMMIT;")?;
    // Indexes after the rows: a sort instead of row-by-row upkeep.
    for st in stmts.iter().filter(|st| st.index && tables.contains(&st.table)) {
        conn.execute_batch(st.sql)?;
    }
    conn.close().map_err(|(_, e)| e)?;
    Ok(())
}

/// SQLite writes one file on one thread, so each table group is built in a
/// separate file in parallel (rows, then its indexes), and the groups are
/// then copied into the snapshot with `INSERT INTO t SELECT * FROM part.t`,
/// which SQLite runs as a record-level transfer of the table and its indexes.
/// Every step happens in a fixed order, so the bytes are reproducible.
///
/// With `parts_dir`, each group's part is kept there named by a hash of its
/// rows ([`part_key`]); the next build hashes its rows first (cheap next to
/// SQLite inserts) and copies from the kept part when nothing changed. The
/// copy reads only the rows, so the snapshot's bytes are the same either way.
/// Returns (groups reused, groups written).
fn write_sqlite(m: &Model, cfg: &TrustConfig, path: &Path, parts_dir: Option<&Path>) -> Result<(usize, usize)> {
    let stmts = schema();
    let mut products_of: HashMap<u128, Vec<u32>> = HashMap::new();
    for (man, p) in &m.covers {
        products_of.entry(*man).or_default().push(*p);
    }
    let prep = Prepared { products_of };
    if let Some(d) = parts_dir {
        std::fs::create_dir_all(d)?;
    }
    let scratch = |i: usize| path.with_extension(format!("part{i}"));
    let mut used: Vec<PathBuf> = Vec::new();
    let mut reused = 0;
    let result = std::thread::scope(|sc| -> Result<()> {
        let handles: Vec<_> = PARTS.iter().enumerate().map(|(i, Part { tables, write, .. })| {
            let (stmts, prep) = (&stmts, &prep);
            sc.spawn(move || -> Result<(PathBuf, bool)> {
                let Some(dir) = parts_dir else {
                    let p = scratch(i);
                    write_part(&p, tables, stmts, *write, m, cfg, prep)?;
                    return Ok((p, false));
                };
                let key = part_key(i, tables, stmts, *write, m, cfg, prep)?;
                let p = dir.join(format!("{i:02}-{key}.db"));
                if p.exists() {
                    return Ok((p, true));
                }
                let tmp = p.with_extension("tmp");
                write_part(&tmp, tables, stmts, *write, m, cfg, prep)?;
                std::fs::rename(&tmp, &p)?;
                Ok((p, false))
            })
        }).collect();
        // The snapshot: the whole schema first (fixed root pages), then each
        // group's rows and indexes in PARTS order as soon as it is ready.
        let conn = Connection::open(path)?;
        conn.execute_batch(PRAGMAS)?;
        for st in &stmts {
            conn.execute_batch(st.sql)?;
        }
        let mut handles = handles.into_iter();
        let mut i = 0;
        while i < PARTS.len() {
            // This group and the ones joined to it: one transaction.
            let n = 1 + PARTS[i + 1..].iter().take_while(|p| p.joined).count();
            let mut attached = Vec::new();
            for (j, p) in PARTS[i..i + n].iter().enumerate() {
                let (part, was_kept) = handles.next().unwrap().join().map_err(|_| anyhow::anyhow!("table writer panicked"))??;
                reused += was_kept as usize;
                conn.execute(&format!("ATTACH ?1 AS part{j}"), [part.to_string_lossy()])?;
                attached.push((format!("part{j}"), p.tables, part));
            }
            conn.execute_batch("BEGIN;")?;
            for (schema_name, tables, _) in &attached {
                for t in tables.iter() {
                    let virt = stmts.iter().any(|st| st.table == *t && st.sql.starts_with("CREATE VIRTUAL TABLE"));
                    if virt {
                        // An FTS5 index lives in its shadow tables (t_data, t_idx, …): copy those.
                        let mut q = conn.prepare(&format!("SELECT name FROM {schema_name}.sqlite_master WHERE type = 'table' AND name LIKE ?1 ESCAPE '\\' ORDER BY name"))?;
                        let shadows: Vec<String> = q.query_map([format!("{}\\_%", t)], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
                        for sh in shadows {
                            conn.execute_batch(&format!("DELETE FROM main.{sh}; INSERT INTO main.{sh} SELECT * FROM {schema_name}.{sh};"))?;
                        }
                    } else {
                        conn.execute_batch(&format!("INSERT INTO main.{t} SELECT * FROM {schema_name}.{t};"))?;
                    }
                }
            }
            conn.execute_batch("COMMIT;")?;
            for (schema_name, _, part) in attached {
                conn.execute_batch(&format!("DETACH {schema_name};"))?;
                if parts_dir.is_none() {
                    let _ = std::fs::remove_file(&part);
                }
                used.push(part);
            }
            i += n;
        }
        conn.close().map_err(|(_, e)| e)?;
        Ok(())
    });
    match parts_dir {
        None => {
            if result.is_err() {
                (0..PARTS.len()).for_each(|i| drop(std::fs::remove_file(scratch(i))));
            }
        }
        // Keep only this snapshot's parts (a failed build keeps what it made).
        Some(dir) if result.is_ok() => {
            for e in std::fs::read_dir(dir)?.flatten() {
                if !used.contains(&e.path()) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        Some(_) => {}
    }
    result.map(|()| (reused, PARTS.len() - reused))
}

fn brand_key(k: &str) -> &str {
    k.split('|').next().unwrap_or("")
}

fn write_meta(out: &mut dyn Sink, m: &Model, cfg: &TrustConfig, _: &Prepared) -> Result<()> {
    const SQL: &str = "INSERT INTO meta VALUES (?1, ?2)";
    out.insert(SQL, params!["schema", SNAPSHOT_SCHEMA])?;
    out.insert(SQL, params!["head", m.head.clone().unwrap_or_default()])?;
    out.insert(SQL, params!["entries", m.stats.entries.to_string()])?;
    out.insert(SQL, params!["trust_digest", cfg.digest()])?;
    out.insert(SQL, params!["domain", cfg.domain])?;
    Ok(())
}

fn write_identity(out: &mut dyn Sink, m: &Model, _: &TrustConfig, _: &Prepared) -> Result<()> {
    let mut contributors: BTreeMap<String, (Option<(String, String)>, u64, u64, u64)> = Default::default();
    for (fp, rec) in &m.keys {
        let gid = m.contributor_of.get(fp).cloned().unwrap_or_else(|| fp.clone());
        let c = contributors.entry(gid).or_default();
        if let (Some(name), Some(cur)) = (&rec.profile_name, &rec.profile_cursor) {
            if c.0.as_ref().is_none_or(|(pc, _)| cur > pc) {
                c.0 = Some((cur.clone(), name.clone()));
            }
        }
        c.1 += 1;
        c.2 += rec.facts;
        c.3 += rec.verified_copies;
    }
    for (id, (name, keys, facts, vc)) in &contributors {
        out.insert("INSERT INTO contributors VALUES (?1, ?2, ?3, ?4, ?5)", params![id, name.as_ref().map(|n| n.1.clone()), keys, facts, vc])?;
    }
    for (fp, rec) in &m.keys {
        let gid = m.contributor_of.get(fp).cloned().unwrap_or_else(|| fp.clone());
        out.insert("INSERT INTO keys VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)", params![
            fp, gid, rec.alg, rec.jwk, rec.profile_jws, rec.profile_name,
            rec.facts, rec.verified_copies, rec.vouched_by.len() as i64, rec.links.len() as i64,
            rec.avatar_sha256, rec.avatar_mime, rec.avatar_url
        ])?;
        for (service, handle, uri) in rec.links.keys() {
            out.insert("INSERT INTO identity_links VALUES (?1, ?2, ?3, ?4)", params![fp, service, handle, uri])?;
        }
    }
    Ok(())
}

fn write_products(out: &mut dyn Sink, m: &Model, _: &TrustConfig, _: &Prepared) -> Result<()> {
    for (k, p) in &m.products {
        out.insert("INSERT INTO products VALUES (?1, ?2, ?3, ?4)", params![m.s(*k), m.s(p.brand), p.model, brand_key(m.s(*k))])?;
    }
    Ok(())
}

/// A manual's products, first one shown as its brand/model.
fn covered<'a>(m: &'a Model, prep: &'a Prepared, id: u128) -> impl Iterator<Item = &'a (u32, crate::model::Product)> + 'a {
    prep.products_of.get(&id).into_iter().flatten().map(|i| &m.products[*i as usize])
}

fn write_manuals(out: &mut dyn Sink, m: &Model, _: &TrustConfig, prep: &Prepared) -> Result<()> {
    let so = |x: Option<u32>| x.map(|x| m.s(x));
    for (id, man) in &m.manuals {
        let (brand, model) = covered(m, prep, *id).next().map(|(_, p)| (Some(m.s(p.brand)), Some(&*p.model))).unwrap_or((None, None));
        out.insert("INSERT INTO manuals VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)", params![
            ulid_str(*id), man.title, m.s(man.doc_type), so(man.language), man.year, so(man.source), man.source_id,
            man.source_url.as_deref().map(|u| openmanuals_core::ids::openable_source_url(u, &man.title)),
            m.s(man.author), ulid_str(man.cursor), man.canonical_file.map(|f| f.to_string()), brand, model
        ])?;
    }
    Ok(())
}

/// Each manual's lowercased search text, in id order.
fn search_texts(m: &Model, prep: &Prepared, f: &mut dyn FnMut(u128, &crate::model::Manual, &str) -> Result<()>) -> Result<()> {
    let mut text = String::new();
    for (id, man) in &m.manuals {
        text.clear();
        for (_, p) in covered(m, prep, *id) {
            text.push_str(&m.s(p.brand).to_lowercase());
            text.push(' ');
            text.push_str(&p.model.to_lowercase());
            text.push(' ');
            text.push_str(&openmanuals_core::product::normalize_model(&p.model).to_lowercase());
            text.push(' ');
        }
        text.push_str(&man.title.to_lowercase());
        text.push(' ');
        text.push_str(&m.s(man.doc_type).to_lowercase());
        f(*id, man, text.trim())?;
    }
    Ok(())
}

const SEARCH_INSERT: &str = "INSERT INTO manual_search VALUES (?1, ?2, ?3)";

fn write_search(out: &mut dyn Sink, m: &Model, _: &TrustConfig, prep: &Prepared) -> Result<()> {
    search_texts(m, prep, &mut |id, man, text| out.insert(SEARCH_INSERT, params![ulid_str(id), text, man.canonical_file.is_some() as i64]))
}

/// The trigram index over the search text (external content: it stores no
/// copy). Its part holds its own `manual_search` with the same rowids and
/// text (only those feed the index), and only the index's shadow tables are
/// copied, so the part depends on nothing else (not `downloadable`).
fn write_fts(out: &mut dyn Sink, m: &Model, _: &TrustConfig, prep: &Prepared) -> Result<()> {
    out.exec("CREATE TABLE manual_search (manual TEXT PRIMARY KEY, text TEXT NOT NULL, downloadable INTEGER NOT NULL)")?;
    search_texts(m, prep, &mut |id, _, text| out.insert(SEARCH_INSERT, params![ulid_str(id), text, 0]))?;
    out.exec("INSERT INTO manual_fts(manual_fts) VALUES('rebuild');")
}

fn write_brands(out: &mut dyn Sink, m: &Model, _: &TrustConfig, prep: &Prepared) -> Result<()> {
    let mut brands: BTreeMap<&str, (&str, i64, i64)> = Default::default();
    for (id, man) in &m.manuals {
        if let Some((k, p)) = covered(m, prep, *id).next() {
            let e = brands.entry(brand_key(m.s(*k))).or_insert((m.s(p.brand), 0, 0));
            e.1 += 1;
            if man.canonical_file.is_some() {
                e.2 += 1;
            }
        }
    }
    for (k, (brand, n, d)) in &brands {
        out.insert("INSERT INTO brands VALUES (?1, ?2, ?3, ?4)", params![k, brand, n, d])?;
    }
    Ok(())
}

fn write_covers(out: &mut dyn Sink, m: &Model, _: &TrustConfig, _: &Prepared) -> Result<()> {
    for (man, p) in &m.covers {
        out.insert("INSERT INTO covers VALUES (?1, ?2)", params![ulid_str(*man), m.s(m.products[*p as usize].0)])?;
    }
    Ok(())
}

fn write_files(out: &mut dyn Sink, m: &Model, _: &TrustConfig, _: &Prepared) -> Result<()> {
    let so = |x: Option<u32>| x.map(|x| m.s(x));
    let hx = |b: Option<&[u8]>| b.map(hex::encode);
    for (id, f) in &m.files {
        out.insert("INSERT INTO files VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)", params![
            id.to_string(), hx(f.sha256.as_ref().map(|h| &h[..])), hx(f.sha1.as_ref().map(|h| &h[..])), hx(f.md5.as_ref().map(|h| &h[..])),
            f.size, so(f.mime), f.pages, m.s(f.author), ulid_str(f.cursor), f.derived_from.map(|d| d.to_string()), so(f.transform),
            so(f.tool), so(f.tool_version), f.report_weight, f.flagged as i64, f.canonical_location.map(|l| l.to_string()),
            f.review.as_deref()
        ])?;
    }
    Ok(())
}

fn write_manual_files(out: &mut dyn Sink, m: &Model, _: &TrustConfig, _: &Prepared) -> Result<()> {
    for (man, file, role) in &m.manual_files {
        out.insert("INSERT INTO manual_files VALUES (?1, ?2, ?3)", params![ulid_str(*man), file.to_string(), m.s(*role)])?;
    }
    Ok(())
}

fn write_derivations(out: &mut dyn Sink, m: &Model, _: &TrustConfig, _: &Prepared) -> Result<()> {
    let s = |x: u32| m.s(x);
    let so = |x: Option<u32>| x.map(|x| m.s(x));
    let mut ders: Vec<_> = m.derivations.iter().collect();
    ders.sort_by(|a, b| (a.derived, a.source).cmp(&(b.derived, b.source)).then_with(|| (s(a.transform), s(a.author)).cmp(&(s(b.transform), s(b.author)))));
    for d in ders {
        out.insert("INSERT INTO derivations VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![d.derived.to_string(), d.source.to_string(), s(d.transform), so(d.tool), so(d.tool_version), s(d.author)])?;
    }
    Ok(())
}

fn write_locations(out: &mut dyn Sink, m: &Model, cfg: &TrustConfig, _: &Prepared) -> Result<()> {
    let s = |x: u32| m.s(x);
    // Only verified and origin copies unless configured otherwise.
    for (id, l) in &m.locations {
        let public = matches!(s(l.status), "verified" | "origin");
        if !public && !cfg.include_unverified {
            continue;
        }
        out.insert("INSERT INTO locations VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)", params![
            id.to_string(), l.file.to_string(), l.url, s(l.host), s(l.kind), s(l.status), l.verified_at, l.final_url,
            l.ia_identifier, l.ia_filename, s(l.author), ulid_str(l.cursor), l.report_weight, l.flagged as i64
        ])?;
    }
    Ok(())
}

fn write_labels(out: &mut dyn Sink, m: &Model, _: &TrustConfig, _: &Prepared) -> Result<()> {
    let mut labels: Vec<_> = m.labels.iter().collect();
    labels.sort_by_key(|l| l.id);
    for l in labels {
        out.insert("INSERT INTO labels VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![l.id.to_string(), l.target, m.s(l.ns), l.value, l.reason, m.s(l.author), l.weight])?;
    }
    Ok(())
}

