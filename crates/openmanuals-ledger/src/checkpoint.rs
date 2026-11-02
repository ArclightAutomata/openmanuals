//! Build checkpoints: the resolver state after the ledger up to a position, so
//! the next build applies only what was appended since.
//!
//! A checkpoint holds the state of the ledger's facts up to `end`, resolved
//! with the moderation (`Resolver::moderation`) of the ledger up to
//! `mod_end` (≥ `end`). Resuming replays the moderation facts after `end`
//! onto that and takes back, in place, whatever the difference hides
//! (`build::resume`); facts after `end` are applied with the result.
//!
//! A checkpoint is used only when it still describes the ledger: same
//! format, same trust config, same signature-checking mode, and every ledger
//! file before `mod_end.file` still the length it was (the ledger is
//! append-only; a purge rewrites files and so invalidates it). Anything else,
//! or any decoding error, means not using it, never a wrong snapshot.
//!
//! Files (see [`Store`]):
//! - `checkpoint.bin`: the newest state. `OMCKPT`, sha256 of the rest, then
//!   postcard of (`Header`, `Resolver`).
//! - `<checkpoint>.cache/days/YYYY-MM-DD.bin`: the state at the end of that
//!   ledger day, for moderation that reaches back further than the newest
//!   checkpoint can undo in place. `OMCKPZ`, sha256, then zstd of the same
//!   postcard. Kept per [`DayPolicy`].
//! - `<checkpoint>.cache/index.bin`: per-file filters ([`crate::index`]).
//! - `<checkpoint>.cache/parts/`: table parts of the last snapshot
//!   ([`crate::build`]).

use crate::config::TrustConfig;
use crate::ledger::Pos;
use crate::model::Resolver;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Bump whenever `Header`, `Resolver`'s fields or the rules applied in
/// `Resolver::apply`/`unapply` change.
pub const FORMAT: u32 = 4;
const MAGIC: &[u8; 6] = b"OMCKPT";
const ZMAGIC: &[u8; 6] = b"OMCKPZ";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub format: u32,
    pub trust_digest: String,
    pub verify_signatures: bool,
    /// Every ledger file before `mod_end.file`, with its length.
    pub files: Vec<(String, u64)>,
    /// Where the next build resumes.
    pub end: Pos,
    /// The state's moderation covers the ledger up to here.
    pub mod_end: Pos,
    /// Index keys ([`crate::index::line_keys`]) of the lines of `end.file`
    /// before `end.offset`, when that file has no filter yet (`None` for a
    /// day checkpoint, whose last file is complete and indexed).
    pub open_keys: Option<Vec<u64>>,
}

impl Header {
    pub fn new(lengths: &[(String, u64)], cfg: &TrustConfig, verify_signatures: bool, end: Pos, mod_end: Pos, open_keys: Option<Vec<u64>>) -> Header {
        let files = lengths.iter().take_while(|(f, _)| *f < mod_end.file).cloned().collect();
        Header { format: FORMAT, trust_digest: cfg.digest(), verify_signatures, files, end, mod_end, open_keys }
    }

    /// Why this checkpoint cannot be resumed against the ledger (whose files
    /// now have `lengths`), if it can't.
    pub fn mismatch(&self, lengths: &[(String, u64)], cfg: &TrustConfig, verify_signatures: bool) -> Option<String> {
        if self.format != FORMAT {
            return Some(format!("checkpoint format {} (expected {FORMAT})", self.format));
        }
        if self.trust_digest != cfg.digest() {
            return Some("trust config changed".into());
        }
        if self.verify_signatures != verify_signatures {
            return Some("signature checking mode changed".into());
        }
        let before: Vec<&(String, u64)> = lengths.iter().take_while(|(f, _)| *f < self.mod_end.file).collect();
        if before.len() != self.files.len() || before.iter().zip(&self.files).any(|(a, b)| *a != b) {
            return Some("ledger history changed".into());
        }
        match lengths.iter().find(|(f, _)| *f == self.mod_end.file) {
            Some((_, len)) if *len >= self.mod_end.offset && self.end <= self.mod_end => None,
            _ => Some("ledger history changed".into()),
        }
    }
}

/// Write via a temporary file and a rename, so a crash leaves the old file or the new one.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Write a checkpoint, streaming it to disk (no copy of it in memory), via a
/// temporary file and a rename.
pub fn save(path: &Path, header: &Header, r: &Resolver) -> Result<()> {
    save_framed(path, header, r, false)
}

/// [`save`], zstd-compressed (level 1, multithreaded): for day checkpoints.
pub fn save_compressed(path: &Path, header: &Header, r: &Resolver) -> Result<()> {
    save_framed(path, header, r, true)
}

fn save_framed(path: &Path, header: &Header, r: &Resolver, compress: bool) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    struct Hashing<W>(W, Sha256);
    impl<W: Write> Write for Hashing<W> {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let n = self.0.write(b)?;
            self.1.update(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&tmp)?);
    f.write_all(if compress { ZMAGIC } else { MAGIC })?;
    f.write_all(&[0; 32])?;
    // The checksum covers the bytes after it as stored (compressed or not).
    let Hashing(mut f, h) = if compress {
        let mut z = zstd::stream::Encoder::new(Hashing(f, Sha256::new()), 1)?;
        z.multithread(4)?;
        let z = postcard::to_io(&(header, r), std::io::BufWriter::with_capacity(1 << 20, z))?;
        z.into_inner().map_err(|e| e.into_error())?.finish()?
    } else {
        postcard::to_io(&(header, r), Hashing(f, Sha256::new()))?
    };
    f.seek(SeekFrom::Start(MAGIC.len() as u64))?;
    f.write_all(&h.finalize())?;
    f.into_inner().map_err(|e| e.into_error())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The checkpoint's header and state, or why it can't be used. `lengths`
/// are the ledger's current file lengths.
pub fn load(path: &Path, lengths: &[(String, u64)], cfg: &TrustConfig, verify_signatures: bool) -> Result<Result<(Resolver, Header), String>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Err("no checkpoint".into())),
        Err(e) => return Ok(Err(format!("unreadable checkpoint: {e}"))),
    };
    if bytes.len() < 38 || !(&bytes[..6] == MAGIC || &bytes[..6] == ZMAGIC) || Sha256::digest(&bytes[38..])[..] != bytes[6..38] {
        return Ok(Err("corrupt checkpoint".into()));
    }
    let unz;
    let body = if &bytes[..6] == ZMAGIC {
        unz = match zstd::stream::decode_all(&bytes[38..]) {
            Ok(b) => b,
            Err(e) => return Ok(Err(format!("undecodable checkpoint: {e}"))),
        };
        &unz[..]
    } else {
        &bytes[38..]
    };
    let (header, rest) = match postcard::take_from_bytes::<Header>(body) {
        Ok(v) => v,
        Err(e) => return Ok(Err(format!("undecodable checkpoint: {e}"))),
    };
    if let Some(why) = header.mismatch(lengths, cfg, verify_signatures) {
        return Ok(Err(why));
    }
    match postcard::from_bytes::<Resolver>(rest) {
        Ok(r) => Ok(Ok((r, header))),
        Err(e) => Ok(Err(format!("undecodable checkpoint: {e}"))),
    }
}

/// Which day checkpoints to keep: the newest `daily` complete ledger days,
/// plus the last day of each of the newest `weekly` ISO weeks.
#[derive(Debug, Clone, Copy)]
pub struct DayPolicy {
    pub daily: usize,
    pub weekly: usize,
}

impl Default for DayPolicy {
    fn default() -> Self {
        DayPolicy { daily: 7, weekly: 4 }
    }
}

/// `YYYY/MM/DD.jsonl` → its date.
fn file_date(file: &str) -> Option<jiff::civil::Date> {
    let d = file.strip_suffix(".jsonl")?;
    let mut it = d.split('/');
    let (y, m, day) = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    it.next().is_none().then(|| jiff::civil::Date::new(y, m, day).ok()).flatten()
}

impl DayPolicy {
    /// The complete files (oldest first) whose end gets a day checkpoint.
    pub fn keep(&self, complete: &[String]) -> BTreeSet<String> {
        let dated: Vec<(&String, jiff::civil::Date)> = complete.iter().filter_map(|f| file_date(f).map(|d| (f, d))).collect();
        let mut keep: BTreeSet<String> = dated.iter().rev().take(self.daily).map(|(f, _)| (*f).clone()).collect();
        let mut weeks = BTreeSet::new();
        for (f, d) in dated.iter().rev() {
            let w = d.iso_week_date();
            if weeks.len() >= self.weekly && !weeks.contains(&(w.year(), w.week())) {
                break;
            }
            if weeks.insert((w.year(), w.week())) {
                keep.insert((*f).clone());
            }
        }
        keep
    }
}

/// Where a build keeps its incremental state, derived from the checkpoint path.
#[derive(Debug, Clone)]
pub struct Store {
    pub main: PathBuf,
    pub cache: PathBuf,
}

impl Store {
    pub fn new(checkpoint: &Path) -> Store {
        Store { main: checkpoint.to_path_buf(), cache: checkpoint.with_extension("cache") }
    }

    pub fn index_path(&self) -> PathBuf {
        self.cache.join("index.bin")
    }

    pub fn parts_dir(&self) -> PathBuf {
        self.cache.join("parts")
    }

    fn days_dir(&self) -> PathBuf {
        self.cache.join("days")
    }

    /// The day checkpoint at the end of ledger file `file` (`YYYY/MM/DD.jsonl`).
    pub fn day_path(&self, file: &str) -> Option<PathBuf> {
        let d = file_date(file)?;
        Some(self.days_dir().join(format!("{d}.bin")))
    }

    /// Stored day checkpoints, newest first: (ledger file, path).
    pub fn days(&self) -> Vec<(String, PathBuf)> {
        let mut out: Vec<(String, PathBuf)> = std::fs::read_dir(self.days_dir()).into_iter().flatten().flatten().filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_str()?.strip_suffix(".bin")?.to_string();
            let d: jiff::civil::Date = name.parse().ok()?;
            Some((format!("{:04}/{:02}/{:02}.jsonl", d.year(), d.month(), d.day()), p))
        }).collect();
        out.sort();
        out.reverse();
        out
    }

    /// Delete day checkpoints the policy no longer keeps (and stray temporaries).
    pub fn prune_days(&self, keep: &BTreeSet<String>) {
        for (file, path) in self.days() {
            if !keep.contains(&file) {
                let _ = std::fs::remove_file(path);
            }
        }
        for e in std::fs::read_dir(self.days_dir()).into_iter().flatten().flatten() {
            if e.path().extension().is_some_and(|x| x == "tmp") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// Forget all resolver state (the checkpoint, day checkpoints and the
    /// index), e.g. after rewriting ledger history; table parts are keyed by
    /// their content and stay.
    pub fn clear(&self) {
        let _ = std::fs::remove_file(&self.main);
        self.clear_days();
        let _ = std::fs::remove_file(self.index_path());
    }

    pub fn clear_days(&self) {
        let _ = std::fs::remove_dir_all(self.days_dir());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_policy_keeps_recent_days_and_a_weekly_ladder() {
        let start = jiff::civil::date(2026, 1, 1);
        let files: Vec<String> = (0..120).filter(|i| i % 5 != 3).map(|i| {
            let d = start.checked_add(jiff::Span::new().days(i)).unwrap();
            format!("{:04}/{:02}/{:02}.jsonl", d.year(), d.month(), d.day())
        }).collect();
        let keep = DayPolicy { daily: 7, weekly: 4 }.keep(&files);
        let newest: Vec<&String> = files.iter().rev().take(7).collect();
        assert!(newest.iter().all(|f| keep.contains(*f)));
        assert!(keep.len() <= 7 + 4 && keep.len() >= 8, "{keep:?}");
        let oldest_kept = keep.iter().next().unwrap();
        assert!(oldest_kept.as_str() > "2026/03/25.jsonl", "{oldest_kept}");
        assert!(DayPolicy { daily: 0, weekly: 0 }.keep(&files).is_empty());
        let s = Store::new(Path::new("/x/checkpoint.bin"));
        assert_eq!(s.day_path("2026/10/23.jsonl").unwrap(), Path::new("/x/checkpoint.cache/days/2026-10-23.bin"));
        assert!(s.day_path("junk.jsonl").is_none());
    }
}
