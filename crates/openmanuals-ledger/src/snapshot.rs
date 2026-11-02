//! Working with built snapshots: content hashes, row-level diffs between two
//! snapshots, applying a diff, and compression for download.
//!
//! A diff is zstd-compressed JSON lines:
//!
//! ```text
//! {"v":1,"from":"<version>","to":"<version>","tables":{"<table>":"<content hash>",…}}
//! {"t":"<table>","delete":[[<primary key values>],…]}        (≤ 1000 per line)
//! {"t":"<table>","upsert":[[<all column values>],…]}          (≤ 1000 per line)
//! {"t":"<table>","replace":true}                              (table without a primary key: rows follow as upserts)
//! ```
//!
//! Applying it to the `from` snapshot gives a database whose content hashes
//! equal `tables` (the bytes differ: page layout depends on history). Clients
//! check the hashes, so a diff can't silently corrupt their copy.

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{params_from_iter, Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

pub const DIFF_VERSION: u64 = 1;

/// Short id of a snapshot's content: the first 12 hex digits of sha256 over
/// its table hashes. Two snapshots with the same content have the same id
/// whatever their bytes.
pub fn content_id(tables: &BTreeMap<String, String>) -> String {
    let joined: String = tables.iter().map(|(t, h)| format!("{t}={h}\n")).collect();
    hex::encode(Sha256::digest(joined.as_bytes()))[..12].to_string()
}

/// `<ledger head cursor>-<content id>`: names a published snapshot.
pub fn version(head: &str, tables: &BTreeMap<String, String>) -> String {
    format!("{head}-{}", content_id(tables))
}

pub fn is_version(s: &str) -> bool {
    s.split_once('-').is_some_and(|(c, id)| {
        (c.len() == 26 && c.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()) || c == "empty")
            && id.len() == 12
            && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The ledger head recorded in a snapshot's meta table.
pub fn head(conn: &Connection) -> Result<String> {
    Ok(conn.query_row("SELECT value FROM meta WHERE key = 'head'", [], |r| r.get(0))?)
}
const CHUNK: usize = 1000;

fn open_ro(p: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(p, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?)
}

fn quote(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

/// User tables holding content, sorted by name. Virtual tables (FTS5
/// indexes) and their shadow tables are derived data: not hashed or diffed,
/// rebuilt by [`rebuild_indexes`].
pub fn tables(conn: &Connection, schema: &str) -> Result<Vec<String>> {
    let virt = virtual_tables(conn, schema)?;
    let mut s = conn.prepare(&format!("SELECT name FROM {schema}.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND sql NOT LIKE 'CREATE VIRTUAL TABLE%' ORDER BY name"))?;
    let all: Vec<String> = s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    Ok(all.into_iter().filter(|t| !virt.iter().any(|v| t.starts_with(&format!("{v}_")))).collect())
}

fn virtual_tables(conn: &Connection, schema: &str) -> Result<Vec<String>> {
    let mut s = conn.prepare(&format!("SELECT name FROM {schema}.sqlite_master WHERE type = 'table' AND sql LIKE 'CREATE VIRTUAL TABLE%' ORDER BY name"))?;
    let v = s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    Ok(v)
}

/// Rebuild every FTS5 index from its content table (after applying a diff).
pub fn rebuild_indexes(conn: &Connection) -> Result<()> {
    for v in virtual_tables(conn, "main")? {
        let q = quote(&v);
        conn.execute_batch(&format!("INSERT INTO {q}({q}) VALUES('rebuild');"))?;
    }
    Ok(())
}

/// (columns in order, primary-key columns in key order).
fn columns(conn: &Connection, schema: &str, table: &str) -> Result<(Vec<String>, Vec<String>)> {
    let mut s = conn.prepare(&format!("PRAGMA {schema}.table_info({})", quote(table)))?;
    let mut cols = Vec::new();
    let mut pk: Vec<(i64, String)> = Vec::new();
    for row in s.query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(5)?)))? {
        let (name, k) = row?;
        if k > 0 {
            pk.push((k, name.clone()));
        }
        cols.push(name);
    }
    pk.sort();
    Ok((cols, pk.into_iter().map(|(_, n)| n).collect()))
}

fn order_all(n: usize) -> String {
    (1..=n).map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
}

fn hash_value(h: &mut Sha256, v: ValueRef) {
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
        ValueRef::Text(t) => {
            h.update([3]);
            h.update((t.len() as u64).to_le_bytes());
            h.update(t);
        }
        ValueRef::Blob(b) => {
            h.update([4]);
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        }
    }
}

/// sha256 over a table's rows ordered by every column, each value tagged
/// with its storage class. Independent of page layout and row order on disk.
pub fn table_hash(conn: &Connection, schema: &str, table: &str) -> Result<String> {
    let (cols, _) = columns(conn, schema, table)?;
    let mut s = conn.prepare(&format!("SELECT * FROM {schema}.{} ORDER BY {}", quote(table), order_all(cols.len())))?;
    let mut rows = s.query([])?;
    let mut h = Sha256::new();
    h.update((cols.len() as u64).to_le_bytes());
    while let Some(r) = rows.next()? {
        for i in 0..cols.len() {
            hash_value(&mut h, r.get_ref(i)?);
        }
    }
    Ok(hex::encode(h.finalize()))
}

/// Content hash of every table, computed on parallel connections.
pub fn content_hashes(db: &Path) -> Result<BTreeMap<String, String>> {
    let names = tables(&open_ro(db)?, "main")?;
    let results: Vec<Result<(String, String)>> = std::thread::scope(|s| {
        let hs: Vec<_> = names.iter().map(|t| s.spawn(move || Ok((t.clone(), table_hash(&open_ro(db)?, "main", t)?)))).collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(anyhow!("hash thread panicked")))).collect()
    });
    results.into_iter().collect()
}

fn to_json(v: ValueRef) -> Result<Value> {
    Ok(match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => serde_json::Number::from_f64(f).map(Value::Number).ok_or_else(|| anyhow!("non-finite REAL"))?,
        ValueRef::Text(t) => Value::String(std::str::from_utf8(t)?.to_string()),
        ValueRef::Blob(_) => bail!("BLOB values are not supported in diffs"),
    })
}

fn from_json(v: &Value) -> Result<SqlValue> {
    Ok(match v {
        Value::Null => SqlValue::Null,
        Value::Bool(b) => SqlValue::Integer(*b as i64),
        Value::Number(n) if n.is_i64() => SqlValue::Integer(n.as_i64().unwrap()),
        Value::Number(n) if n.is_f64() => SqlValue::Real(n.as_f64().unwrap()),
        Value::Number(n) => SqlValue::Integer(n.as_u64().and_then(|u| i64::try_from(u).ok()).ok_or_else(|| anyhow!("integer out of range"))?),
        Value::String(s) => SqlValue::Text(s.clone()),
        _ => bail!("unexpected value in diff: {v}"),
    })
}

#[derive(Debug, Default, Clone)]
pub struct DiffStats {
    pub deleted: usize,
    pub upserted: usize,
    pub replaced_tables: usize,
    pub bytes: u64,
}

fn write_rows(out: &mut dyn Write, table: &str, kind: &str, rows: &mut rusqlite::Rows, ncols: usize, n: &mut usize) -> Result<()> {
    let mut batch: Vec<Value> = Vec::with_capacity(CHUNK);
    let flush = |out: &mut dyn Write, batch: &mut Vec<Value>| -> Result<()> {
        if !batch.is_empty() {
            serde_json::to_writer(&mut *out, &json!({"t": table, kind: batch}))?;
            out.write_all(b"\n")?;
            batch.clear();
        }
        Ok(())
    };
    while let Some(r) = rows.next()? {
        let row: Vec<Value> = (0..ncols).map(|i| to_json(r.get_ref(i)?)).collect::<Result<_>>()?;
        batch.push(Value::Array(row));
        *n += 1;
        if batch.len() == CHUNK {
            flush(out, &mut batch)?;
        }
    }
    flush(out, &mut batch)
}

/// Write the diff that turns snapshot `old` into snapshot `new` to `out`
/// (uncompressed JSON lines). `None` if the two can't be diffed (different
/// tables or columns); clients then download the full snapshot.
pub fn diff(old: &Path, new: &Path, from: &str, to: &str, tables_hash: &BTreeMap<String, String>, out: &mut dyn Write) -> Result<Option<DiffStats>> {
    let conn = open_ro(new)?;
    conn.execute("ATTACH ?1 AS old", [old.to_string_lossy()])?;
    let names = tables(&conn, "main")?;
    if names != tables(&conn, "old")? {
        return Ok(None);
    }
    for t in &names {
        if columns(&conn, "main", t)? != columns(&conn, "old", t)? {
            return Ok(None);
        }
    }
    serde_json::to_writer(&mut *out, &json!({"v": DIFF_VERSION, "from": from, "to": to, "tables": tables_hash}))?;
    out.write_all(b"\n")?;
    let mut st = DiffStats::default();
    for t in &names {
        let (cols, pk) = columns(&conn, "main", t)?;
        let qt = quote(t);
        if pk.is_empty() {
            // No key to address rows by: send the whole table if anything differs.
            let differs: bool = conn.query_row(
                &format!("SELECT (SELECT count(*) FROM main.{qt}) != (SELECT count(*) FROM old.{qt}) OR EXISTS (SELECT * FROM main.{qt} EXCEPT SELECT * FROM old.{qt}) OR EXISTS (SELECT * FROM old.{qt} EXCEPT SELECT * FROM main.{qt})"),
                [], |r| r.get(0))?;
            if differs {
                serde_json::to_writer(&mut *out, &json!({"t": t, "replace": true}))?;
                out.write_all(b"\n")?;
                st.replaced_tables += 1;
                let mut s = conn.prepare(&format!("SELECT * FROM main.{qt} ORDER BY {}", order_all(cols.len())))?;
                let mut rows = s.query([])?;
                write_rows(out, t, "upsert", &mut rows, cols.len(), &mut st.upserted)?;
            }
            continue;
        }
        let pkl = pk.iter().map(|c| quote(c)).collect::<Vec<_>>().join(", ");
        let mut s = conn.prepare(&format!("SELECT {pkl} FROM old.{qt} EXCEPT SELECT {pkl} FROM main.{qt} ORDER BY {}", order_all(pk.len())))?;
        let mut rows = s.query([])?;
        write_rows(out, t, "delete", &mut rows, pk.len(), &mut st.deleted)?;
        drop(rows);
        let mut s = conn.prepare(&format!("SELECT * FROM main.{qt} EXCEPT SELECT * FROM old.{qt} ORDER BY {}", order_all(cols.len())))?;
        let mut rows = s.query([])?;
        write_rows(out, t, "upsert", &mut rows, cols.len(), &mut st.upserted)?;
    }
    Ok(Some(st))
}

/// The diff's header line.
pub fn diff_header(first_line: &str) -> Result<(String, String, BTreeMap<String, String>)> {
    let h: Value = serde_json::from_str(first_line)?;
    if h["v"].as_u64() != Some(DIFF_VERSION) {
        bail!("unsupported diff version {}", h["v"]);
    }
    let tables: BTreeMap<String, String> = serde_json::from_value(h["tables"].clone())?;
    Ok((h["from"].as_str().unwrap_or_default().to_string(), h["to"].as_str().unwrap_or_default().to_string(), tables))
}

/// Apply a diff (uncompressed JSON lines) to `conn` inside one transaction.
/// Checks that the database is at the diff's `from` cursor first and moves
/// nothing else. Returns the header's table hashes, which the caller should
/// compare with [`content_hashes`] afterwards.
pub fn apply_diff(conn: &mut Connection, input: impl Read) -> Result<BTreeMap<String, String>> {
    let mut lines = BufReader::new(input).lines();
    let first = lines.next().ok_or_else(|| anyhow!("empty diff"))??;
    let (from, _to, hashes) = diff_header(&first)?;
    let at = head(conn)?;
    if from.split_once('-').map(|(c, _)| c) != Some(at.as_str()) {
        bail!("diff starts at {from} but the database is at {at}");
    }
    let tx = conn.transaction()?;
    let known = tables(&tx, "main")?;
    let mut shapes: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line)?;
        let t = v["t"].as_str().ok_or_else(|| anyhow!("diff line without a table"))?;
        // Table names come from the diff: only ever address existing tables.
        if !known.iter().any(|k| k == t) {
            bail!("diff names unknown table {t}");
        }
        if !shapes.contains_key(t) {
            shapes.insert(t.to_string(), columns(&tx, "main", t)?);
        }
        let (cols, pk) = &shapes[t];
        let qt = quote(t);
        if v["replace"].as_bool() == Some(true) {
            tx.execute(&format!("DELETE FROM {qt}"), [])?;
        } else if let Some(rows) = v["delete"].as_array() {
            let cond = pk.iter().map(|c| format!("{} = ?", quote(c))).collect::<Vec<_>>().join(" AND ");
            let mut s = tx.prepare_cached(&format!("DELETE FROM {qt} WHERE {cond}"))?;
            for r in rows {
                let vals: Vec<SqlValue> = r.as_array().ok_or_else(|| anyhow!("bad delete row"))?.iter().map(from_json).collect::<Result<_>>()?;
                if vals.len() != pk.len() {
                    bail!("delete row for {t} has {} values, key has {}", vals.len(), pk.len());
                }
                s.execute(params_from_iter(vals))?;
            }
        } else if let Some(rows) = v["upsert"].as_array() {
            let marks = vec!["?"; cols.len()].join(", ");
            let mut s = tx.prepare_cached(&format!("INSERT OR REPLACE INTO {qt} VALUES ({marks})"))?;
            for r in rows {
                let vals: Vec<SqlValue> = r.as_array().ok_or_else(|| anyhow!("bad upsert row"))?.iter().map(from_json).collect::<Result<_>>()?;
                if vals.len() != cols.len() {
                    bail!("row for {t} has {} values, table has {}", vals.len(), cols.len());
                }
                s.execute(params_from_iter(vals))?;
            }
        } else {
            bail!("diff line for {t} has no operation");
        }
    }
    rebuild_indexes(&tx)?;
    tx.commit()?;
    Ok(hashes)
}

/// zstd-compress `src` into `dst` (level 9, multithreaded; ~0.3 s and ~22% of
/// the size for a 118 MB snapshot). Returns (sha256 hex, size) of `dst`.
pub fn compress(src: &Path, dst: &Path) -> Result<(String, u64)> {
    let tmp = dst.with_extension("tmp");
    let input = std::fs::File::open(src).with_context(|| src.display().to_string())?;
    let mut enc = zstd::stream::Encoder::new(HashWriter::new(std::fs::File::create(&tmp)?), 9)?;
    // Multithreaded output is the same for any worker count >= 1.
    enc.multithread(std::thread::available_parallelism().map_or(1, |n| n.get()).min(8) as u32)?;
    enc.include_checksum(true)?;
    std::io::copy(&mut BufReader::with_capacity(1 << 20, input), &mut enc)?;
    let (sha, size, mut f) = enc.finish()?.done();
    f.flush()?;
    drop(f);
    std::fs::rename(&tmp, dst)?;
    Ok((sha, size))
}

/// zstd-compress bytes in memory (for diffs).
pub fn compress_bytes(b: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::stream::encode_all(b, 9)?)
}

pub fn decompress_reader<'a, R: Read + 'a>(r: R) -> Result<impl Read + 'a> {
    Ok(zstd::stream::Decoder::new(r)?)
}

/// Pages per hash group in a `.pages` file (4 KiB of hashes per group).
pub const PAGE_GROUP: usize = 128;

/// Per-page sha256 of a database file, for clients that read single pages
/// over HTTP from untrusted mirrors: `raw` is the 32-byte hash of every page
/// in order (the `.pages` file), and `groups` the sha256 hex of each run of
/// [`PAGE_GROUP`] hashes (listed in the signed manifest). A client fetches the
/// group it needs from `raw`, checks it against `groups`, then checks pages.
pub struct PageHashes {
    pub page_size: usize,
    pub pages: usize,
    pub raw: Vec<u8>,
    pub groups: Vec<String>,
}

pub fn page_hashes(db: &Path) -> Result<PageHashes> {
    let page_size: usize = open_ro(db)?.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))? as usize;
    let mut f = std::fs::File::open(db)?;
    let mut raw = Vec::new();
    let mut page = vec![0u8; page_size];
    let mut pages = 0;
    loop {
        let mut got = 0;
        while got < page_size {
            let k = f.read(&mut page[got..])?;
            if k == 0 {
                break;
            }
            got += k;
        }
        if got == 0 {
            break;
        }
        if got < page_size {
            bail!("file is not a whole number of pages");
        }
        raw.extend_from_slice(&Sha256::digest(&page));
        pages += 1;
    }
    let groups = raw.chunks(32 * PAGE_GROUP).map(|g| hex::encode(Sha256::digest(g))).collect();
    Ok(PageHashes { page_size, pages, raw, groups })
}

/// sha256 hex and size of a file, streamed.
pub fn file_sha256(p: &Path) -> Result<(String, u64)> {
    let mut f = std::fs::File::open(p).with_context(|| p.display().to_string())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        n += k as u64;
    }
    Ok((hex::encode(h.finalize()), n))
}

/// A writer that hashes and counts what passes through it.
struct HashWriter<W: Write> {
    inner: W,
    h: Sha256,
    n: u64,
}

impl<W: Write> HashWriter<W> {
    fn new(inner: W) -> Self {
        HashWriter { inner, h: Sha256::new(), n: 0 }
    }
    fn done(self) -> (String, u64, W) {
        (hex::encode(self.h.finalize()), self.n, self.inner)
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let k = self.inner.write(b)?;
        self.h.update(&b[..k]);
        self.n += k as u64;
        Ok(k)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
