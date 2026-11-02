//! Diffs between snapshots: applying one reproduces the newer content exactly,
//! and anything that doesn't fit is refused.
use openmanuals_ledger::snapshot::{apply_diff, content_hashes, content_id, diff, is_version, version};
use rusqlite::Connection;
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE manuals (id TEXT PRIMARY KEY, title TEXT NOT NULL, year INTEGER, weight REAL) WITHOUT ROWID;
CREATE TABLE covers (manual TEXT NOT NULL, product TEXT NOT NULL, PRIMARY KEY (manual, product)) WITHOUT ROWID;
CREATE TABLE derivations (derived TEXT NOT NULL, source TEXT NOT NULL, tool TEXT);
";

fn db(path: &Path, head: &str, sql: &str) {
    let c = Connection::open(path).unwrap();
    c.execute_batch(SCHEMA).unwrap();
    c.execute("INSERT INTO meta VALUES ('head', ?1)", [head]).unwrap();
    c.execute_batch(sql).unwrap();
}

fn make_diff(old: &Path, new: &Path) -> (String, String, Vec<u8>) {
    let (oh, nh) = (content_hashes(old).unwrap(), content_hashes(new).unwrap());
    let (from, to) = (version("01ARZ3NDEKTSV4RRFFQ69G5FAV", &oh), version("01BX5ZZKBKACTAV9WEVGEMMVRZ", &nh));
    let mut out = Vec::new();
    diff(old, new, &from, &to, &nh, &mut out).unwrap().expect("same schema");
    (from, to, out)
}

#[test]
fn applying_a_diff_reproduces_the_new_content() {
    let d = tempfile::tempdir().unwrap();
    let (old, new) = (d.path().join("old.db"), d.path().join("new.db"));
    db(&old, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "
        INSERT INTO manuals VALUES ('a', 'A', 1990, 0.5), ('b', 'B', NULL, NULL), ('c', 'C', 2000, 1.0);
        INSERT INTO covers VALUES ('a', 'jvc|X'), ('b', 'sony|Y');
        INSERT INTO derivations VALUES ('f1', 'f0', 'om-strip/1');");
    db(&new, "01BX5ZZKBKACTAV9WEVGEMMVRZ", "
        INSERT INTO manuals VALUES ('a', 'A (rev 2)', 1990, 0.7), ('c', 'C', 2000, 1.0), ('d', 'D ''quoted''', NULL, 2.0);
        INSERT INTO covers VALUES ('a', 'jvc|X'), ('d', 'sony|Y');
        INSERT INTO derivations VALUES ('f1', 'f0', 'om-strip/2'), ('f2', 'f0', NULL);");
    let (_, _, text) = make_diff(&old, &new);
    let copy = d.path().join("copy.db");
    std::fs::copy(&old, &copy).unwrap();
    let mut c = Connection::open(&copy).unwrap();
    let want = apply_diff(&mut c, &text[..]).unwrap();
    drop(c);
    let got = content_hashes(&copy).unwrap();
    assert_eq!(got, want);
    assert_eq!(got, content_hashes(&new).unwrap());
    assert_ne!(content_id(&got), content_id(&content_hashes(&old).unwrap()));
    // Integers stay integers and reals stay reals.
    let c = Connection::open(&copy).unwrap();
    let t: String = c.query_row("SELECT typeof(weight) || typeof(year) FROM manuals WHERE id = 'a'", [], |r| r.get(0)).unwrap();
    assert_eq!(t, "realinteger");
}

#[test]
fn diffs_refuse_what_does_not_fit() {
    let d = tempfile::tempdir().unwrap();
    let (old, new) = (d.path().join("old.db"), d.path().join("new.db"));
    db(&old, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "INSERT INTO manuals VALUES ('a', 'A', 1, 1.0);");
    db(&new, "01BX5ZZKBKACTAV9WEVGEMMVRZ", "INSERT INTO manuals VALUES ('a', 'B', 1, 1.0);");
    let (from, _, text) = make_diff(&old, &new);
    assert!(is_version(&from) && !is_version("x-y") && !is_version("01ARZ3NDEKTSV4RRFFQ69G5FAV-XYZ"));

    // Applied to a database at another head.
    let copy = d.path().join("copy.db");
    std::fs::copy(&new, &copy).unwrap();
    let e = apply_diff(&mut Connection::open(&copy).unwrap(), &text[..]).unwrap_err();
    assert!(e.to_string().contains("diff starts at"), "{e}");

    // A diff naming a table the database doesn't have (e.g. sqlite_master).
    std::fs::copy(&old, &copy).unwrap();
    let header = String::from_utf8(text.clone()).unwrap().lines().next().unwrap().to_string();
    let evil = format!("{header}\n{{\"t\":\"sqlite_master\",\"upsert\":[[\"table\",\"x\",\"x\",0,\"\"]]}}\n");
    let e = apply_diff(&mut Connection::open(&copy).unwrap(), evil.as_bytes()).unwrap_err();
    assert!(e.to_string().contains("unknown table"), "{e}");
    // Nothing was applied.
    assert_eq!(content_hashes(&copy).unwrap(), content_hashes(&old).unwrap());

    // A tampered row applies but no longer matches the hashes the header promises.
    let tampered = String::from_utf8(text).unwrap().replace("\"B\"", "\"evil\"");
    let mut c = Connection::open(&copy).unwrap();
    let promised = apply_diff(&mut c, tampered.as_bytes()).unwrap();
    drop(c);
    assert_ne!(content_hashes(&copy).unwrap(), promised);

    // Different schemas: no diff at all.
    let other = d.path().join("other.db");
    Connection::open(&other).unwrap().execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID; INSERT INTO meta VALUES ('head','x');").unwrap();
    let nh = content_hashes(&new).unwrap();
    assert!(diff(&other, &new, "a", "b", &nh, &mut Vec::new()).unwrap().is_none());
}

#[test]
fn page_hashes_cover_every_page_in_groups() {
    use openmanuals_ledger::snapshot::{page_hashes, PAGE_GROUP};
    use sha2::{Digest, Sha256};
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("a.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("PRAGMA page_size = 4096; CREATE TABLE t (a TEXT);").unwrap();
    for i in 0..3000 {
        c.execute("INSERT INTO t VALUES (?1)", [format!("{i:0>200}")]).unwrap();
    }
    drop(c);
    let bytes = std::fs::read(&p).unwrap();
    let h = page_hashes(&p).unwrap();
    assert_eq!(h.page_size, 4096);
    assert_eq!(h.pages * 4096, bytes.len());
    assert!(h.pages > PAGE_GROUP, "several groups");
    assert_eq!(h.raw.len(), h.pages * 32);
    assert_eq!(&h.raw[32..64], Sha256::digest(&bytes[4096..8192]).as_slice());
    assert_eq!(h.groups.len(), h.pages.div_ceil(PAGE_GROUP));
    assert_eq!(h.groups[1], hex::encode(Sha256::digest(&h.raw[PAGE_GROUP * 32..(2 * PAGE_GROUP * 32).min(h.raw.len())])));
}

#[test]
fn search_indexes_are_rebuilt_not_diffed() {
    let schema = "
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE manual_search (manual TEXT PRIMARY KEY, text TEXT NOT NULL, downloadable INTEGER NOT NULL);
        CREATE VIRTUAL TABLE manual_fts USING fts5(text, content='manual_search', content_rowid='rowid', tokenize='trigram', detail='none');";
    let d = tempfile::tempdir().unwrap();
    let make = |name: &str, head: &str, rows: &[(&str, &str)]| {
        let p = d.path().join(name);
        let c = Connection::open(&p).unwrap();
        c.execute_batch(schema).unwrap();
        c.execute("INSERT INTO meta VALUES ('head', ?1)", [head]).unwrap();
        for (m, t) in rows {
            c.execute("INSERT INTO manual_search VALUES (?1, ?2, 1)", [m, t]).unwrap();
        }
        c.execute_batch("INSERT INTO manual_fts(manual_fts) VALUES('rebuild');").unwrap();
        p
    };
    let old = make("old.db", "01ARZ3NDEKTSV4RRFFQ69G5FAV", &[("a", "sony kv-1400 service"), ("b", "jvc av2168tee")]);
    let new = make("new.db", "01BX5ZZKBKACTAV9WEVGEMMVRZ", &[("a", "sony kv-1400 service manual"), ("c", "panasonic tx-21")]);
    let hashes = content_hashes(&new).unwrap();
    assert!(hashes.keys().all(|t| !t.starts_with("manual_fts")), "FTS tables are derived: {hashes:?}");
    let (_, _, text) = make_diff(&old, &new);
    let copy = d.path().join("copy.db");
    std::fs::copy(&old, &copy).unwrap();
    let mut c = Connection::open(&copy).unwrap();
    apply_diff(&mut c, &text[..]).unwrap();
    let hits = |q: &str| -> Vec<String> {
        let mut s = c.prepare("SELECT s.manual FROM manual_fts f JOIN manual_search s ON s.rowid = f.rowid WHERE f.text LIKE ?1 ORDER BY 1").unwrap();
        s.query_map([q], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
    };
    assert_eq!(hits("%2168%"), Vec::<String>::new(), "deleted manual gone from the index");
    assert_eq!(hits("%tx-2%"), vec!["c".to_string()]);
    assert_eq!(hits("%manual%"), vec!["a".to_string()]);
    c.execute_batch("INSERT INTO manual_fts(manual_fts, rank) VALUES('integrity-check', 1);").unwrap();
    drop(c);
    assert_eq!(content_hashes(&copy).unwrap(), hashes);
}
