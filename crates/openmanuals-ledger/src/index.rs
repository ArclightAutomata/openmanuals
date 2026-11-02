//! Which ledger files may hold a fact, a key's facts or a manual's facts.
//!
//! Moderation that arrives after a checkpoint can hide facts the checkpoint
//! already applied. To take them back (or to pick a checkpoint to replay
//! from) the build must find their lines without reading the whole ledger.
//! Each complete ledger file gets a binary fuse filter ([`openmanuals_core::filter`],
//! ~9 bits per key, ~1/256 false positives, no false negatives) over three
//! keys per line: the fact id, `k:<author>`, and `m:<manual id>` for `manual`
//! facts. A hit means "maybe here"; the file is then read. A file whose
//! length changed, or that has no filter, is always read.
//!
//! Stored as `index.bin` in the build cache: `OMIDX1`, sha256 of the rest,
//! postcard of `[(file, length, filter bytes)]`.

use crate::compact::FactId;
use crate::ledger::{Ledger, Peek, Pos};
use crate::view::EntryView;
use anyhow::Result;
use rayon::prelude::*;
use openmanuals_core::filter::{self, Filter};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

const MAGIC: &[u8; 6] = b"OMIDX1";

fn sha_key(tag: &[u8], data: &[u8]) -> u64 {
    let d = Sha256::new().chain_update(tag).chain_update(data).finalize();
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

/// Filter key of a fact id (already a uniform hash).
pub fn id_key(id: &FactId) -> u64 {
    u64::from_le_bytes(id.0[..8].try_into().unwrap())
}

pub fn author_key(fp: &str) -> u64 {
    sha_key(b"k:", fp.as_bytes())
}

pub fn manual_key(id: u128) -> u64 {
    sha_key(b"m:", &id.to_be_bytes())
}

/// The keys of one line (computed on the parse threads).
pub fn line_keys(e: &EntryView, fid: Option<FactId>) -> [Option<u64>; 3] {
    let manual = (e.fact.r#type == "manual")
        .then(|| e.fact.body.obj().and_then(|b| b.as_str("id")).map(str::trim).and_then(crate::compact::ulid))
        .flatten();
    [fid.as_ref().map(id_key), Some(author_key(&e.fact.author)), manual.map(manual_key)]
}

pub fn build_filter(keys: &mut Vec<u64>) -> Result<Vec<u8>> {
    Ok(filter::build_from_hashes(keys, openmanuals_core::ids::PAGE_KEY_VERSION)?)
}

#[derive(Default)]
pub struct Index {
    files: BTreeMap<String, (u64, Vec<u8>, Filter)>,
    changed: bool,
}

impl Index {
    /// The stored index, or an empty one if it is missing or damaged.
    pub fn load(path: &Path) -> Index {
        let mut idx = Index::default();
        let Ok(bytes) = std::fs::read(path) else { return idx };
        if bytes.len() < 38 || &bytes[..6] != MAGIC || Sha256::digest(&bytes[38..])[..] != bytes[6..38] {
            return idx;
        }
        let Ok(list) = postcard::from_bytes::<Vec<(String, u64, Vec<u8>)>>(&bytes[38..]) else { return idx };
        for (file, len, raw) in list {
            if let Ok(f) = Filter::from_bytes(&raw) {
                idx.files.insert(file, (len, raw, f));
            }
        }
        idx
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        if !self.changed {
            return Ok(());
        }
        let list: Vec<(&String, u64, &Vec<u8>)> = self.files.iter().map(|(f, (l, raw, _))| (f, *l, raw)).collect();
        let body = postcard::to_stdvec(&list)?;
        let mut out = Vec::with_capacity(body.len() + 38);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&Sha256::digest(&body));
        out.extend_from_slice(&body);
        crate::checkpoint::write_atomic(path, &out)?;
        self.changed = false;
        Ok(())
    }

    /// Record a complete file's filter ([`build_filter`] of its keys).
    pub fn insert_raw(&mut self, file: &str, len: u64, raw: Vec<u8>) -> Result<()> {
        let f = Filter::from_bytes(&raw)?;
        self.files.insert(file.to_string(), (len, raw, f));
        self.changed = true;
        Ok(())
    }

    pub fn has(&self, file: &str, len: u64) -> bool {
        self.files.get(file).is_some_and(|e| e.0 == len)
    }

    /// Whether `file` (now `len` bytes) may hold a line with any of `keys`.
    pub fn may_contain(&self, file: &str, len: u64, keys: &[u64]) -> bool {
        match self.files.get(file) {
            Some((l, _, f)) if *l == len => keys.iter().any(|k| f.contains_hash(*k)),
            _ => true,
        }
    }

    /// Drop filters of files that no longer exist or changed length.
    pub fn retain_current(&mut self, lengths: &[(String, u64)]) {
        let now: BTreeMap<&str, u64> = lengths.iter().map(|(f, l)| (f.as_str(), *l)).collect();
        let before = self.files.len();
        self.files.retain(|f, e| now.get(f.as_str()) == Some(&e.0));
        self.changed |= self.files.len() != before;
    }
}

/// The ledger before a position, with what the index knows about it.
pub struct Prefix<'a> {
    pub ledger: &'a Ledger,
    pub index: &'a Index,
    /// The prefix ends here.
    pub end: &'a Pos,
    /// Keys of the lines in `end.file` before `end.offset`, if known (else
    /// that file's filter is used, or it is read).
    pub open_keys: Option<&'a HashSet<u64>>,
    /// Current file lengths.
    pub lengths: &'a [(String, u64)],
}

impl Prefix<'_> {
    /// Files of the prefix that may hold a line with any of `keys`, oldest
    /// first, with how much of each belongs to the prefix.
    pub fn candidates(&self, keys: &[u64]) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        for (file, len) in self.lengths {
            if *file > self.end.file {
                break;
            }
            if *file == self.end.file {
                let hit = match self.open_keys {
                    Some(open) => keys.iter().any(|k| open.contains(k)),
                    None => self.index.may_contain(file, self.end.offset, keys),
                };
                if hit {
                    out.push((file.clone(), self.end.offset));
                }
                break;
            }
            if self.index.may_contain(file, *len, keys) {
                out.push((file.clone(), *len));
            }
        }
        out
    }

    /// The first file of the prefix that may hold a line with `key`.
    pub fn first_with(&self, key: u64) -> Option<String> {
        self.candidates(&[key]).into_iter().next().map(|(f, _)| f)
    }

    /// Every line of the prefix whose fact id is in `ids`, oldest first, as
    /// (file, line bytes). Streams the candidate files.
    pub fn lines_with_ids(&self, ids: &HashSet<FactId>) -> Result<Vec<(String, Vec<u8>)>> {
        let keys: Vec<u64> = ids.iter().map(id_key).collect();
        let mut out = Vec::new();
        if ids.is_empty() {
            return Ok(out);
        }
        for (file, limit) in self.candidates(&keys) {
            let path = self.ledger.ledger_dir().join(&file);
            out.extend(search_file(&path, limit, ids, 8 << 20)?.into_iter().map(|line| (file.clone(), line)));
        }
        Ok(out)
    }
}

/// Lines of `path` before `limit` whose id is in `ids`, in order. Large files
/// are searched in chunks on all cores; each chunk owns the lines that start in it.
fn search_file(path: &Path, limit: u64, ids: &HashSet<FactId>, chunk: u64) -> Result<Vec<Vec<u8>>> {
    let starts: Vec<u64> = (0..limit.div_ceil(chunk)).map(|i| i * chunk).collect();
    let found: Vec<Vec<Vec<u8>>> = starts.par_iter().map(|&start| search_chunk(path, start, (start + chunk).min(limit), limit, ids)).collect::<Result<_>>()?;
    Ok(found.into_iter().flatten().collect())
}

/// Lines of `path` that start in `[start, end)` (and end by `limit`) whose id is in `ids`.
fn search_chunk(path: &Path, start: u64, end: u64, limit: u64, ids: &HashSet<FactId>) -> Result<Vec<Vec<u8>>> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    // Begin at the first line starting at or after `start`.
    let mut pos = start.saturating_sub(1);
    f.seek(SeekFrom::Start(pos))?;
    let mut r = BufReader::with_capacity(1 << 20, f);
    let mut line = Vec::new();
    if start > 0 {
        pos += r.read_until(b'\n', &mut line)? as u64;
    }
    let mut out = Vec::new();
    while pos < end && pos < limit {
        line.clear();
        let n = r.read_until(b'\n', &mut line)?;
        if n == 0 || line.last() != Some(&b'\n') {
            break;
        }
        pos += n as u64;
        let l = line.trim_ascii();
        if !l.is_empty() && line_id(l)?.is_some_and(|id| ids.contains(&id)) {
            out.push(l.to_vec());
        }
    }
    Ok(out)
}

/// A line's fact id. Lines as the ledger writer spells them
/// (`{"cursor":"<26 chars>","id":"sha256:<64 hex>",…`) are read at fixed
/// offsets; anything else is parsed.
fn line_id(line: &[u8]) -> Result<Option<FactId>> {
    const HEAD: &[u8] = br#"{"cursor":""#;
    const MID: &[u8] = br#"","id":"sha256:"#;
    let (c0, m0) = (HEAD.len(), HEAD.len() + 26);
    let h0 = m0 + MID.len();
    if line.len() > h0 + 64
        && line.starts_with(HEAD)
        && line[c0..m0].iter().all(u8::is_ascii_alphanumeric)
        && &line[m0..h0] == MID
        && line[h0 + 64] == b'"'
    {
        let mut id = [0u8; 32];
        let hex = &line[h0..h0 + 64];
        // Lowercase hex only, as `FactId::parse` accepts.
        if hex.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) && hex::decode_to_slice(hex, &mut id).is_ok() {
            return Ok(Some(FactId(id)));
        }
    }
    let p: Peek = serde_json::from_slice(line)?;
    Ok(FactId::parse(&p.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_search_finds_every_line_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.jsonl");
        let mut text = String::new();
        let mut ids = Vec::new();
        for i in 0..200u32 {
            let id = format!("sha256:{:064x}", i * 7919);
            // Mixed spellings and lengths, and a blank line now and then.
            if i % 3 == 0 {
                text += &format!("{{\"id\": \"{id}\", \"cursor\":\"x\",\"fact\":{{\"type\":\"x\",\"pad\":\"{}\"}}}}\n", "y".repeat(i as usize % 50));
            } else {
                text += &format!("{{\"cursor\":\"01ARZ3NDEKTSV4RRFFQ69G5FAV\",\"id\":\"{id}\",\"fact\":{{\"type\":\"x\"}}}}\n");
            }
            if i % 17 == 0 {
                text += "\n";
            }
            ids.push(FactId::parse(&id).unwrap());
        }
        std::fs::write(&p, &text).unwrap();
        let want: HashSet<FactId> = ids.iter().step_by(3).copied().collect();
        let limit = text.len() as u64;
        let whole = search_file(&p, limit, &want, 1 << 30).unwrap();
        assert_eq!(whole.len(), want.len());
        for chunk in [1, 7, 64, 100, 1000] {
            assert_eq!(search_file(&p, limit, &want, chunk).unwrap(), whole, "chunk {chunk}");
        }
        // A limit inside the file: only lines before it.
        let cut = text[..text.len() / 2].rfind('\n').unwrap() as u64 + 1;
        let half = search_file(&p, cut, &want, 1 << 30).unwrap();
        assert!(half.len() < whole.len() && !half.is_empty());
        assert_eq!(search_file(&p, cut, &want, 13).unwrap(), half);
    }

    #[test]
    fn line_ids_fast_and_slow() {
        let id = format!("sha256:{}", "ab".repeat(32));
        let fid = FactId::parse(&id).unwrap();
        let fast = format!(r#"{{"cursor":"01ARZ3NDEKTSV4RRFFQ69G5FAV","id":"{id}","fact":{{"v":1}}}}"#);
        assert_eq!(line_id(fast.as_bytes()).unwrap(), Some(fid));
        let slow = format!(r#"{{"id": "{id}", "cursor":"x","fact":{{"type":"file"}}}}"#);
        assert_eq!(line_id(slow.as_bytes()).unwrap(), Some(fid));
        // A body that spells an id at the right offset can't fool it: the cursor must be 26 plain characters.
        let tricky = format!(r#"{{"cursor":"01ARZ3NDEKTSV4RRFFQ69\"x\":1","id":"{id}","fact":{{"type":"x"}},"id":"sha256:00"}}"#);
        assert!(line_id(tricky.as_bytes()).is_err() || line_id(tricky.as_bytes()).unwrap() != Some(fid));
    }
}
