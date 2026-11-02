//! JSONL ledger files. One line per ingested fact:
//! `{"cursor":"01J…","id":"sha256:…","fact":{…}}`, in ingestion order, under
//! `<root>/ledger/YYYY/MM/DD.jsonl` where the date is the cursor's UTC date.
//! Only the fold job writes; everyone else reads.

use anyhow::{anyhow, Context, Result};
use openmanuals_core::Fact;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub cursor: String,
    pub id: String,
    pub fact: Fact,
}

pub struct Ledger {
    root: PathBuf,
}

/// A place in the ledger: a file (`YYYY/MM/DD.jsonl`) and a byte offset in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pos {
    pub file: String,
    pub offset: u64,
}

impl PartialOrd for Pos {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for Pos {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (&self.file, self.offset).cmp(&(&o.file, o.offset))
    }
}

/// Just enough of a ledger line to route it without parsing the body.
#[derive(Deserialize)]
pub struct Peek<'a> {
    #[serde(borrow)]
    pub cursor: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    pub id: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    pub fact: PeekFact<'a>,
}

#[derive(Deserialize)]
pub struct PeekFact<'a> {
    #[serde(rename = "type", borrow)]
    pub r#type: std::borrow::Cow<'a, str>,
}

/// Monotonic ULID cursors.
pub struct CursorGen(ulid::Generator);

impl Default for CursorGen {
    fn default() -> Self {
        Self::new()
    }
}

impl CursorGen {
    pub fn new() -> Self {
        CursorGen(ulid::Generator::new())
    }
    pub fn next(&mut self) -> String {
        self.0.generate().expect("ulid generation").to_string()
    }
}

/// `YYYY/MM/DD` for a cursor's embedded timestamp.
pub fn cursor_date_path(cursor: &str) -> Result<String> {
    let u: ulid::Ulid = cursor.parse().map_err(|e| anyhow!("bad cursor {cursor}: {e}"))?;
    let ts = jiff::Timestamp::from_millisecond(u.timestamp_ms() as i64)?;
    let d = ts.to_zoned(jiff::tz::TimeZone::UTC).date();
    Ok(format!("{:04}/{:02}/{:02}", d.year(), d.month(), d.day()))
}

pub fn is_cursor(s: &str) -> bool {
    s.len() == 26 && s.parse::<ulid::Ulid>().is_ok()
}

impl Ledger {
    /// Open (creating directories) a ledger rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("ledger"))?;
        fs::create_dir_all(root.join("keys"))?;
        Ok(Ledger { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ledger_dir(&self) -> PathBuf {
        self.root.join("ledger")
    }

    /// All ledger files in cursor order.
    pub fn files(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        let dir = self.ledger_dir();
        if !dir.exists() {
            return Ok(out);
        }
        for y in sorted_dirs(&dir)? {
            for m in sorted_dirs(&y)? {
                let mut days: Vec<PathBuf> = fs::read_dir(&m)?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                    .collect();
                days.sort();
                out.extend(days);
            }
        }
        Ok(out)
    }

    /// Every entry, oldest first (the whole ledger in memory).
    pub fn entries(&self) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        self.scan(None, None, &mut |line| {
            out.push(serde_json::from_str(line)?);
            Ok(())
        })?;
        Ok(out)
    }

    /// The set of fact ids already in the ledger.
    pub fn ids(&self) -> Result<HashSet<String>> {
        Ok(self.entries()?.into_iter().map(|e| e.id).collect())
    }

    /// The newest cursor, if any. Reads only the tail of the last file.
    pub fn head(&self) -> Result<Option<String>> {
        let files = self.files()?;
        let Some(last) = files.last() else { return Ok(None) };
        let mut f = fs::File::open(last)?;
        let len = f.metadata()?.len();
        // A line is at most a 16 KiB fact plus its envelope; read generously.
        let tail = len.min(256 * 1024);
        f.seek(SeekFrom::Start(len - tail))?;
        let mut buf = Vec::with_capacity(tail as usize);
        f.read_to_end(&mut buf)?;
        let text = String::from_utf8_lossy(&buf);
        let mut lines = text.split('\n').filter(|l| !l.trim().is_empty());
        if tail == len {
            // Whole file in hand: every line is complete.
            return Ok(match lines.next_back() {
                Some(l) => Some(serde_json::from_str::<Peek>(l)?.cursor.into_owned()),
                None => None,
            });
        }
        match lines.next_back().map(serde_json::from_str::<Peek>) {
            Some(Ok(p)) => Ok(Some(p.cursor.into_owned())),
            _ => {
                // Fall back to a full read (only for an unexpectedly long last line).
                let mut head = None;
                self.scan_file(last, 0, None, &mut |line| {
                    head = Some(serde_json::from_slice::<Peek>(line)?.cursor.into_owned());
                    Ok(())
                })?;
                Ok(head)
            }
        }
    }

    /// Feed every non-empty line from `from` (or the start) up to `until` (or
    /// the end) to `f`, oldest first, and return the position just past the
    /// last line read.
    pub fn scan(&self, from: Option<&Pos>, until: Option<&Pos>, f: &mut dyn FnMut(&str) -> Result<()>) -> Result<Option<Pos>> {
        self.scan_raw(from, until, &mut |line| f(std::str::from_utf8(line)?))
    }

    /// [`Ledger::scan`] over raw bytes (no UTF-8 check, no copy into a String).
    pub fn scan_raw(&self, from: Option<&Pos>, until: Option<&Pos>, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<Option<Pos>> {
        self.scan_files(from, until, f, &mut |_, _| Ok(()))
    }

    /// [`Ledger::scan_raw`], also calling `end(pos, complete)` after each file
    /// with the position reached in it; `complete` when that is the file's
    /// end and a later file exists (the fold job no longer appends to it).
    pub fn scan_files(&self, from: Option<&Pos>, until: Option<&Pos>, f: &mut dyn FnMut(&[u8]) -> Result<()>, end_of_file: &mut dyn FnMut(&Pos, bool) -> Result<()>) -> Result<Option<Pos>> {
        let mut end = from.cloned();
        let files = self.files()?;
        let n = files.len();
        for (i, path) in files.into_iter().enumerate() {
            let rel = self.rel(&path);
            let offset = match from {
                Some(p) if rel < p.file => continue,
                Some(p) if rel == p.file => p.offset,
                _ => 0,
            };
            let limit = match until {
                Some(u) if rel > u.file => break,
                Some(u) if rel == u.file => Some(u.offset),
                _ => None,
            };
            let read_to = self.scan_file(&path, offset, limit, f)?;
            let pos = Pos { file: rel, offset: read_to };
            let complete = i + 1 < n && fs::metadata(&path)?.len() == read_to;
            end_of_file(&pos, complete)?;
            end = Some(pos);
        }
        Ok(end)
    }

    /// The bytes of a ledger file (`YYYY/MM/DD.jsonl`) up to `limit`.
    pub fn read_file(&self, rel: &str, limit: Option<u64>) -> Result<Vec<u8>> {
        let path = self.ledger_dir().join(rel);
        let mut f = fs::File::open(&path).with_context(|| path.display().to_string())?;
        let mut buf = Vec::new();
        match limit {
            Some(l) => drop((&mut f).take(l).read_to_end(&mut buf)?),
            None => drop(f.read_to_end(&mut buf)?),
        }
        Ok(buf)
    }

    fn scan_file(&self, path: &Path, offset: u64, limit: Option<u64>, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<u64> {
        let mut file = fs::File::open(path).with_context(|| path.display().to_string())?;
        file.seek(SeekFrom::Start(offset))?;
        let mut r = BufReader::with_capacity(1 << 20, file);
        let mut line = Vec::new();
        let mut pos = offset;
        let mut n = 0usize;
        while limit.is_none_or(|l| pos < l) {
            line.clear();
            let read = r.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            n += 1;
            if line.last() != Some(&b'\n') {
                // A partial last line (a writer mid-append): stop before it.
                break;
            }
            pos += read as u64;
            let trimmed = line.trim_ascii_end();
            if trimmed.trim_ascii_start().is_empty() {
                continue;
            }
            f(trimmed).with_context(|| format!("{}:+{}", path.display(), n))?;
        }
        Ok(pos)
    }

    /// `YYYY/MM/DD.jsonl` for a ledger file.
    fn rel(&self, path: &Path) -> String {
        path.strip_prefix(self.ledger_dir()).unwrap_or(path).to_string_lossy().replace('\\', "/")
    }

    /// Every ledger file with its current length, oldest first.
    pub fn file_lengths(&self) -> Result<Vec<(String, u64)>> {
        self.files()?.iter().map(|p| Ok((self.rel(p), fs::metadata(p)?.len()))).collect()
    }

    /// Append entries (already cursor-stamped, ascending). Returns the files touched,
    /// relative to the root, for `git add`.
    pub fn append(&self, entries: &[Entry]) -> Result<Vec<PathBuf>> {
        let mut touched = Vec::new();
        let mut last_path: Option<PathBuf> = None;
        let mut file: Option<fs::File> = None;
        for e in entries {
            let rel = PathBuf::from("ledger").join(format!("{}.jsonl", cursor_date_path(&e.cursor)?));
            if last_path.as_ref() != Some(&rel) {
                let abs = self.root.join(&rel);
                fs::create_dir_all(abs.parent().unwrap())?;
                file = Some(fs::OpenOptions::new().create(true).append(true).open(&abs)?);
                if !touched.contains(&rel) {
                    touched.push(rel.clone());
                }
                last_path = Some(rel);
            }
            let f = file.as_mut().unwrap();
            serde_json::to_writer(&mut *f, e)?;
            f.write_all(b"\n")?;
        }
        if let Some(mut f) = file {
            f.flush()?;
        }
        Ok(touched)
    }
}

fn sorted_dirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_dir()).collect();
    v.sort();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn append_and_read_back_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let l = Ledger::open(dir.path()).unwrap();
        let mut g = CursorGen::new();
        let mk = |c: String, n: u32| Entry { cursor: c, id: format!("sha256:{n}"), fact: Fact::new("file", "QPRGVPJNWDXH4ESK2RYDTZJLTE", "2026-10-23T18:00:00Z", json!({"n": n})) };
        let e1 = mk(g.next(), 1);
        let e2 = mk(g.next(), 2);
        let touched = l.append(&[e1.clone(), e2.clone()]).unwrap();
        assert_eq!(touched.len(), 1);
        assert!(touched[0].starts_with("ledger"));
        assert_eq!(l.entries().unwrap(), vec![e1, e2.clone()]);
        assert_eq!(l.head().unwrap(), Some(e2.cursor.clone()));
        assert_eq!(l.ids().unwrap().len(), 2);
        // Resume from a position: only what was appended after it.
        let pos = l.scan(None, None, &mut |_| Ok(())).unwrap().unwrap();
        let e3 = mk(g.next(), 3);
        l.append(std::slice::from_ref(&e3)).unwrap();
        let mut seen = vec![];
        let end = l.scan(Some(&pos), None, &mut |line| {
            seen.push(serde_json::from_str::<Entry>(line)?);
            Ok(())
        }).unwrap().unwrap();
        assert_eq!(seen, vec![e3.clone()]);
        assert!(end.offset > pos.offset);
        assert_eq!(l.head().unwrap(), Some(e3.cursor));
        assert_eq!(cursor_date_path("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(), "2016/07/30");
    }
}
