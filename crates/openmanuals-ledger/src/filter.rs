//! The lookup filter published next to each snapshot (`lookup-filter.bin`):
//! a binary fuse filter ([`openmanuals_core::filter`]) over every page key
//! ([`openmanuals_core::ids::page_keys`]) that `GET /api/lookup?url=` could answer as
//! known from this snapshot. The extension tests pages locally and only asks
//! the server on a hit.

use std::path::Path;

use anyhow::Context;
use openmanuals_core::{filter, ids};
use rusqlite::{Connection, OpenFlags};

/// Every lookup-filter key a snapshot yields (unsorted, may repeat):
/// `src:<source>:<source_id>` per manual, `page_keys(source_url)` per manual,
/// `page_keys(url)` per `origin` location.
pub fn lookup_keys(db: &Connection) -> anyhow::Result<Vec<String>> {
    let mut keys = Vec::new();
    let mut s = db.prepare("SELECT source, source_id, source_url FROM manuals")?;
    let mut rows = s.query([])?;
    while let Some(r) = rows.next()? {
        let (source, source_id, url): (Option<String>, Option<String>, Option<String>) = (r.get(0)?, r.get(1)?, r.get(2)?);
        if let (Some(src), Some(sid)) = (&source, &source_id) {
            keys.extend(ids::source_key(src, sid));
        }
        if let Some(u) = url {
            keys.extend(ids::page_keys(&u));
        }
    }
    let mut s = db.prepare("SELECT url FROM locations WHERE kind = 'origin'")?;
    let mut rows = s.query([])?;
    while let Some(r) = rows.next()? {
        keys.extend(ids::page_keys(&r.get::<_, String>(0)?));
    }
    Ok(keys)
}

/// Build the serialized lookup filter for a built snapshot (opened read-only).
/// Deterministic: the same snapshot always gives the same bytes.
pub fn lookup_filter(snapshot: &Path) -> anyhow::Result<Vec<u8>> {
    let db = Connection::open_with_flags(snapshot, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .with_context(|| format!("opening snapshot {}", snapshot.display()))?;
    let keys = lookup_keys(&db)?;
    Ok(filter::build(&keys)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_every_lookup_match() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("m.db");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE manuals (id TEXT PRIMARY KEY, source TEXT, source_id TEXT, source_url TEXT);
                 CREATE TABLE locations (id TEXT PRIMARY KEY, url TEXT NOT NULL, kind TEXT NOT NULL);
                 INSERT INTO manuals VALUES ('a', 'manualslib', '331384', NULL);
                 INSERT INTO manuals VALUES ('b', 'elektrotanya', 'sony_kv-1400,sm.pdf', NULL);
                 INSERT INTO manuals VALUES ('c', NULL, NULL, 'https://www.manualsbase.com/manual/9/x/');
                 INSERT INTO locations VALUES ('l1', 'https://www.manualslib.com/manual/777/Foo.html', 'origin');
                 INSERT INTO locations VALUES ('l2', 'https://www.manualslib.com/manual/888/Bar.html', 'archive');",
            )
            .unwrap();
        }
        let bytes = lookup_filter(&p).unwrap();
        assert_eq!(bytes, lookup_filter(&p).unwrap());
        let f = filter::Filter::from_bytes(&bytes).unwrap();
        assert_eq!(f.key_count(), 4);
        assert!(f.contains_page("https://www.manualslib.com/download/331384/Whatever.html"));
        assert!(f.contains_page("https://elektrotanya.com/sony_kv-1400%2Csm.pdf/download.html"));
        assert!(f.contains_page("https://elektrotanya.com/sony_kv-1400,sm.pdf/download.html"));
        assert!(f.contains_page("https://www.manualsbase.com/manual/9/x/#p2"));
        assert!(f.contains_page("https://www.manualslib.com/manual/777/Foo.html?page=3"));
        assert!(lookup_filter(&dir.path().join("missing.db")).is_err());
    }

    /// `OM_SNAPSHOT=data/snapshots/latest.db cargo test --release -p openmanuals-ledger filter::tests::real_snapshot -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_snapshot() {
        let p = std::path::PathBuf::from(std::env::var("OM_SNAPSHOT").expect("OM_SNAPSHOT"));
        let t = std::time::Instant::now();
        let bytes = lookup_filter(&p).unwrap();
        let took = t.elapsed();
        let f = filter::Filter::from_bytes(&bytes).unwrap();
        eprintln!("{} keys, {} bytes ({:.2} bits/key), built in {:?}", f.key_count(), bytes.len(), bytes.len() as f64 * 8.0 / f.key_count() as f64, took);
        let t = std::time::Instant::now();
        assert_eq!(bytes, lookup_filter(&p).unwrap());
        eprintln!("rebuild {:?}", t.elapsed());
        let db = Connection::open_with_flags(&p, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let mut s = db.prepare("SELECT source_url FROM manuals WHERE source_url IS NOT NULL UNION SELECT url FROM locations WHERE kind = 'origin'").unwrap();
        let urls: Vec<String> = s.query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        assert!(urls.iter().all(|u| f.contains_page(u)));
        let fp = (0..200_000).filter(|i| f.contains_page(&format!("https://www.manualslib.com/manual/{}/X.html", 900_000_000 + i))).count();
        eprintln!("{} urls all hit; fp {}/200000", urls.len(), fp);
    }
}
