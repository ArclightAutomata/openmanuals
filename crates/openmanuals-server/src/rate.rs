//! Per-key daily budgets for ingestion and verification. Moderators and servers
//! are unlimited; a record (verified copies, identity links, vouches) earns more.

use std::collections::HashMap;
use crate::config::CachedQuery;
use std::sync::Mutex;

#[derive(Default)]
pub struct Budgets {
    used: Mutex<HashMap<(String, &'static str), (String, u64)>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Record {
    pub verified_copies: u64,
    pub links: u64,
    pub vouches: u64,
}

pub const INGEST_BASE: u64 = 200;
pub const VERIFY_BASE: u64 = 20;

pub fn ingest_budget(r: Record) -> u64 {
    INGEST_BASE + 100 * r.verified_copies.min(20) + if r.links > 0 { 1000 } else { 0 } + if r.vouches > 0 { 300 } else { 0 }
}

pub fn verify_budget(r: Record) -> u64 {
    VERIFY_BASE + 10 * r.verified_copies.min(50) + if r.links > 0 { 100 } else { 0 } + if r.vouches > 0 { 30 } else { 0 }
}

fn today() -> String {
    jiff::Timestamp::now().strftime("%Y-%m-%d").to_string()
}

impl Budgets {
    /// Try to spend `n` units of `kind` for `key` against `limit`. Returns false when exhausted.
    pub fn spend(&self, key: &str, kind: &'static str, n: u64, limit: u64) -> bool {
        let mut used = self.used.lock().unwrap();
        let day = today();
        let e = used.entry((key.to_string(), kind)).or_insert_with(|| (day.clone(), 0));
        if e.0 != day {
            *e = (day, 0);
        }
        if e.1 + n > limit {
            return false;
        }
        e.1 += n;
        true
    }
}

/// Look up a key's record in the snapshot.
pub fn record(db: Option<&rusqlite::Connection>, fp: &str) -> Record {
    let Some(db) = db else { return Record::default() };
    db.query_row_cached("SELECT verified_copies, links, vouches FROM keys WHERE fingerprint = ?1", [fp], |r| {
        Ok(Record { verified_copies: r.get::<_, i64>(0)? as u64, links: r.get::<_, i64>(1)? as u64, vouches: r.get::<_, i64>(2)? as u64 })
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budgets_scale_with_record() {
        assert!(ingest_budget(Record::default()) < ingest_budget(Record { verified_copies: 3, links: 1, vouches: 0 }));
        let b = Budgets::default();
        assert!(b.spend("k", "ingest", 5, 5));
        assert!(!b.spend("k", "ingest", 1, 5));
        assert!(b.spend("k", "verify", 1, 5));
    }
}
