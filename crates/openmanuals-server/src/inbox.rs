//! The ingestion log: every accepted fact with its cursor, in `inbox.db`.
//! The ledger repo is the git-tracked copy of this; the feed reads from here.

use anyhow::{anyhow, Result};
use openmanuals_core::{Fact, MAX_FACT_BYTES};
use openmanuals_ledger::ledger::{CursorGen, Entry};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

pub struct Inbox {
    conn: Mutex<Connection>,
    cursors: Mutex<CursorGen>,
    /// `PRAGMA data_version` at the last [`Inbox::changed_elsewhere`].
    data_version: Mutex<i64>,
}

#[derive(Debug, Default, Serialize)]
pub struct AcceptResult {
    pub cursor: Option<String>,
    pub accepted: Vec<String>,
    pub duplicate: Vec<String>,
    pub rejected: Vec<Rejected>,
}

#[derive(Debug, Serialize)]
pub struct Rejected {
    pub index: usize,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeedItem {
    pub cursor: String,
    pub id: String,
    pub fact: Fact,
}

/// A ledger fact as stored in the inbox.
pub struct LedgerRow {
    pub cursor: String,
    pub id: String,
    pub author: String,
    pub kind: String,
    /// Already appended to the ledger repo (and in the snapshot after the build).
    pub folded: bool,
    pub fact: Fact,
}

/// What hides a fact on the ledger pages.
#[derive(Default)]
pub struct Moderation {
    pub keys: std::collections::HashSet<String>,
    pub facts: std::collections::HashSet<String>,
    pub retracted: std::collections::HashMap<String, Vec<String>>,
}

impl Moderation {
    pub fn hidden(&self, r: &LedgerRow) -> bool {
        self.keys.contains(&r.author) || self.facts.contains(&r.id)
    }
    pub fn retracted(&self, r: &LedgerRow) -> bool {
        self.retracted.get(&r.id).is_some_and(|a| a.contains(&r.author))
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS facts (
  cursor TEXT PRIMARY KEY, id TEXT NOT NULL UNIQUE, author TEXT NOT NULL, type TEXT NOT NULL,
  json TEXT NOT NULL, folded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS facts_type ON facts(type);
CREATE INDEX IF NOT EXISTS facts_author ON facts(author);
CREATE INDEX IF NOT EXISTS facts_folded ON facts(folded);
-- Browsing the ledger newest first, optionally by type or author.
CREATE INDEX IF NOT EXISTS facts_type_cursor ON facts(type, cursor);
CREATE INDEX IF NOT EXISTS facts_author_cursor ON facts(author, cursor);
-- One manual's facts, for the extension's editor (`manual_facts`).
CREATE INDEX IF NOT EXISTS facts_manual_id ON facts(json_extract(json, '$.body.id')) WHERE type = 'manual';
CREATE INDEX IF NOT EXISTS facts_covers_manual ON facts(json_extract(json, '$.body.manual')) WHERE type = 'covers';
CREATE TABLE IF NOT EXISTS verifier_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"#;

const HAS_UNFOLDED: &str = "SELECT EXISTS (SELECT 1 FROM facts WHERE folded = 0)";

impl Inbox {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        conn.execute_batch(SCHEMA)?;
        let v: i64 = conn.query_row("PRAGMA data_version", [], |r| r.get(0))?;
        Ok(Inbox { conn: Mutex::new(conn), cursors: Mutex::new(CursorGen::new()), data_version: Mutex::new(v) })
    }

    /// Import ledger entries not yet present (restoring an inbox from the git repo).
    pub fn seed(&self, entries: &[Entry]) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let mut n = 0;
        {
            let mut ins = tx.prepare("INSERT OR IGNORE INTO facts (cursor, id, author, type, json, folded) VALUES (?1, ?2, ?3, ?4, ?5, 1)")?;
            for e in entries {
                n += ins.execute(params![e.cursor, e.id, e.fact.author, e.fact.r#type, e.fact.to_json()])?;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// Whether another connection (`openmanuals-server import` in another process)
    /// committed to the inbox since the last call, with unfolded facts left.
    /// This connection's own writes don't count; they poke the fold trigger.
    pub fn changed_elsewhere(&self) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let v: i64 = conn.query_row("PRAGMA data_version", [], |r| r.get(0))?;
        let mut last = self.data_version.lock().unwrap();
        if v == *last {
            return Ok(false);
        }
        *last = v;
        Ok(conn.query_row(HAS_UNFOLDED, [], |r| r.get(0))?)
    }

    /// Whether any accepted fact has not been folded into the ledger yet.
    pub fn has_unfolded(&self) -> Result<bool> {
        Ok(self.conn.lock().unwrap().query_row(HAS_UNFOLDED, [], |r| r.get(0))?)
    }

    pub fn count(&self) -> Result<i64> {
        Ok(self.conn.lock().unwrap().query_row("SELECT count(*) FROM facts", [], |r| r.get(0))?)
    }

    /// Facts signed by `author` (live, including ones not folded yet).
    pub fn count_by_author(&self, author: &str) -> Result<i64> {
        Ok(self.conn.lock().unwrap().prepare_cached("SELECT count(*) FROM facts WHERE author = ?1")?.query_row([author], |r| r.get(0))?)
    }

    /// Validate, verify and store facts. `check(fact, index)` may reject a fact
    /// (e.g. rate limiting) before storage.
    pub fn accept(&self, facts: &[Fact], mut check: impl FnMut(&Fact) -> Result<(), String>) -> Result<AcceptResult> {
        use rayon::prelude::*;
        // Size, signature and id for every fact on all cores, before taking the lock.
        let prepared: Vec<Result<(String, String), String>> = facts.par_iter().map(|f| {
            let json = f.to_json();
            if json.len() > MAX_FACT_BYTES {
                return Err(format!("fact exceeds {MAX_FACT_BYTES} bytes"));
            }
            f.verify().map_err(|e| e.to_string())?;
            let id = f.id().map_err(|e| e.to_string())?;
            Ok((json, id))
        }).collect();
        let mut out = AcceptResult::default();
        let mut accepted: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut exists = tx.prepare("SELECT 1 FROM facts WHERE id = ?1")?;
            let mut ins = tx.prepare("INSERT INTO facts (cursor, id, author, type, json, folded) VALUES (?1, ?2, ?3, ?4, ?5, 0)")?;
            for (i, (f, prep)) in facts.iter().zip(prepared).enumerate() {
                let (json, id) = match prep {
                    Ok(v) => v,
                    Err(error) => {
                        out.rejected.push(Rejected { index: i, error });
                        continue;
                    }
                };
                if accepted.contains(&id) || exists.query_row([&id], |_| Ok(())).optional()?.is_some() {
                    out.duplicate.push(id);
                    continue;
                }
                if let Err(e) = check(f) {
                    out.rejected.push(Rejected { index: i, error: e });
                    continue;
                }
                let cursor = self.cursors.lock().unwrap().next();
                ins.execute(params![cursor, id, f.author, f.r#type, json])?;
                out.cursor = Some(cursor);
                accepted.insert(id.clone());
                out.accepted.push(id);
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn feed(&self, since: Option<&str>, limit: usize) -> Result<(Vec<FeedItem>, bool)> {
        let conn = self.conn.lock().unwrap();
        let limit = limit.clamp(1, 1000);
        let mut stmt = conn.prepare("SELECT cursor, id, json FROM facts WHERE cursor > ?1 ORDER BY cursor LIMIT ?2")?;
        let rows = stmt.query_map(params![since.unwrap_or(""), (limit + 1) as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?;
        let mut items = Vec::new();
        for r in rows {
            let (cursor, id, json) = r?;
            items.push(FeedItem { cursor, id, fact: Fact::from_json(&json)? });
        }
        let more = items.len() > limit;
        items.truncate(limit);
        Ok((items, more))
    }

    pub fn unfolded(&self) -> Result<Vec<Entry>> {
        self.query_entries("SELECT cursor, id, json FROM facts WHERE folded = 0 ORDER BY cursor", &[])
    }

    pub fn mark_folded(&self, cursors: &[String]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut up = tx.prepare("UPDATE facts SET folded = 1 WHERE cursor = ?1")?;
            for c in cursors {
                up.execute([c])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn by_type(&self, t: &str) -> Result<Vec<Entry>> {
        self.query_entries("SELECT cursor, id, json FROM facts WHERE type = ?1 ORDER BY cursor", &[&t])
    }

    pub fn by_author_and_type(&self, author: &str, t: &str) -> Result<Vec<Entry>> {
        self.query_entries("SELECT cursor, id, json FROM facts WHERE author = ?1 AND type = ?2 ORDER BY cursor", &[&author, &t])
    }

    pub fn by_author(&self, author: &str, limit: usize) -> Result<Vec<Entry>> {
        let lim = limit.to_string();
        self.query_entries("SELECT cursor, id, json FROM facts WHERE author = ?1 ORDER BY cursor DESC LIMIT ?2", &[&author, &lim.as_str()])
    }

    /// Newest verified identity profile JWS for a fingerprint.
    pub fn latest_profile(&self, fp: &str) -> Result<Option<String>> {
        let entries = self.by_author_and_type(fp, "identity_profile")?;
        for e in entries.iter().rev() {
            if let Some(jws) = e.fact.body.get("jws").and_then(|v| v.as_str()) {
                if openmanuals_core::asp::parse_and_verify(jws).map(|p| p.fingerprint == fp).unwrap_or(false) {
                    return Ok(Some(jws.to_string()));
                }
            }
        }
        Ok(None)
    }

    pub fn state_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.lock().unwrap().query_row("SELECT value FROM verifier_state WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn state_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.lock().unwrap().execute("INSERT OR REPLACE INTO verifier_state VALUES (?1, ?2)", params![key, value])?;
        Ok(())
    }

    /// A page of the ledger in arrival order, newest first. `before` pages to
    /// older facts, `after` to newer ones; optional filters by type and author.
    /// Returns the rows and whether there are more in that direction.
    pub fn browse(&self, before: Option<&str>, after: Option<&str>, kind: Option<&str>, author: Option<&str>, limit: usize) -> Result<(Vec<LedgerRow>, bool)> {
        let conn = self.conn.lock().unwrap();
        let limit = limit.clamp(1, 200);
        let mut wheres: Vec<&str> = Vec::new();
        let mut args: Vec<String> = Vec::new();
        if let Some(t) = kind {
            wheres.push("type = ?");
            args.push(t.to_string());
        }
        if let Some(a) = author {
            wheres.push("author = ?");
            args.push(a.to_string());
        }
        let newer = after.is_some() && before.is_none();
        if let Some(c) = before {
            wheres.push("cursor < ?");
            args.push(c.to_string());
        } else if let Some(c) = after {
            wheres.push("cursor > ?");
            args.push(c.to_string());
        }
        let where_sql = if wheres.is_empty() { String::new() } else { format!("WHERE {}", wheres.join(" AND ")) };
        let order = if newer { "ASC" } else { "DESC" };
        let sql = format!("SELECT cursor, id, author, type, json, folded FROM facts {where_sql} ORDER BY cursor {order} LIMIT {}", limit + 1);
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (cursor, id, author, kind, json, folded) = r?;
            out.push(LedgerRow { cursor, id, author, kind, folded: folded != 0, fact: Fact::from_json(&json).map_err(|e| anyhow!("{e}"))? });
        }
        let more = out.len() > limit;
        out.truncate(limit);
        if newer {
            out.reverse();
        }
        Ok((out, more))
    }

    /// One fact by id.
    pub fn fact(&self, id: &str) -> Result<Option<LedgerRow>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row("SELECT cursor, id, author, type, json, folded FROM facts WHERE id = ?1", [id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?))
            })
            .optional()?;
        Ok(match row {
            Some((cursor, id, author, kind, json, folded)) => Some(LedgerRow { cursor, id, author, kind, folded: folded != 0, fact: Fact::from_json(&json).map_err(|e| anyhow!("{e}"))? }),
            None => None,
        })
    }

    /// A manual's `manual` and `covers` facts in ledger order (at most
    /// `limit`), whether or not they are folded yet: what the extension's
    /// editor starts from.
    pub fn manual_facts(&self, manual: &str, limit: usize) -> Result<Vec<LedgerRow>> {
        let conn = self.conn.lock().unwrap();
        // Two queries, each on its partial index; sorting in SQL would make
        // SQLite walk every fact of the type in cursor order instead.
        let mut out = Vec::new();
        for sql in [
            "SELECT cursor, id, author, type, json, folded FROM facts WHERE type = 'manual' AND json_extract(json, '$.body.id') = ?1 LIMIT ?2",
            "SELECT cursor, id, author, type, json, folded FROM facts WHERE type = 'covers' AND json_extract(json, '$.body.manual') = ?1 LIMIT ?2",
        ] {
            let mut stmt = conn.prepare_cached(sql)?;
            let rows = stmt.query_map(params![manual, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?))
            })?;
            for row in rows {
                let (cursor, id, author, kind, json, folded) = row?;
                out.push(LedgerRow { cursor, id, author, kind, folded: folded != 0, fact: Fact::from_json(&json).map_err(|e| anyhow!("{e}"))? });
            }
        }
        out.sort_by(|a, b| a.cursor.cmp(&b.cursor));
        out.truncate(limit);
        Ok(out)
    }

    /// Keys a moderator has blocked (the newest block/unblock wins). Cheaper
    /// than `moderation` (only block/unblock facts are read), for checks on
    /// every request.
    pub fn blocked_keys(&self, is_moderator: impl Fn(&str) -> bool) -> Result<std::collections::HashSet<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT author, type, json FROM facts WHERE type IN ('block', 'unblock') ORDER BY cursor")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
        let mut state: std::collections::HashMap<String, bool> = Default::default();
        for r in rows {
            let (author, kind, json) = r?;
            if !is_moderator(&author) {
                continue;
            }
            let Ok(f) = Fact::from_json(&json) else { continue };
            let s = |k: &str| f.body.get(k).and_then(|v| v.as_str()).map(|v| v.trim().to_string());
            if let (Some(k), Some(v)) = (s("kind"), s("value")) {
                if k == "key" {
                    state.insert(v, kind == "block");
                }
            }
        }
        Ok(state.into_iter().filter(|(_, on)| *on).map(|(k, _)| k).collect())
    }

    /// Moderation as the build will apply it: keys and facts blocked by a
    /// moderator (the newest block/unblock wins), and fact id → authors who
    /// retracted it (a retraction counts when it's the fact's own author).
    pub fn moderation(&self, is_moderator: impl Fn(&str) -> bool) -> Result<Moderation> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT author, type, json FROM facts WHERE type IN ('block', 'unblock', 'retract') ORDER BY cursor")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
        let mut m = Moderation::default();
        let mut state: std::collections::BTreeMap<(String, String), bool> = Default::default();
        for r in rows {
            let (author, kind, json) = r?;
            let Ok(f) = Fact::from_json(&json) else { continue };
            let s = |k: &str| f.body.get(k).and_then(|v| v.as_str()).map(|v| v.trim().to_string());
            if kind == "retract" {
                if let Some(t) = s("fact") {
                    m.retracted.entry(t).or_default().push(author);
                }
            } else if is_moderator(&author) {
                if let (Some(k), Some(v)) = (s("kind"), s("value")) {
                    state.insert((k, v), kind == "block");
                }
            }
        }
        for ((k, v), on) in state {
            if on {
                match k.as_str() {
                    "key" => drop(m.keys.insert(v)),
                    "fact" => drop(m.facts.insert(v)),
                    _ => {}
                }
            }
        }
        Ok(m)
    }

    fn query_entries(&self, sql: &str, args: &[&str]) -> Result<Vec<Entry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
        let mut out = Vec::new();
        for r in rows {
            let (cursor, id, json) = r?;
            out.push(Entry { cursor, id, fact: Fact::from_json(&json).map_err(|e| anyhow!("{e}"))? });
        }
        Ok(out)
    }
}
