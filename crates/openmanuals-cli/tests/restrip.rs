//! `om restrip-scan` and `om restrip` end to end: a synthetic bootstrap
//! database and PDFs, a mock archive.org (S3 PUT + metadata read/write), the
//! queued facts, and the build switching the manual's download to the new file.

use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, put};
use axum::{Form, Json, Router};
use lopdf::{dictionary, Document, Object, Stream};
use openmanuals_core::canon::{sha1_hex, sha256_hex};
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_ledger::ledger::{CursorGen, Entry};
use openmanuals_ledger::{build::build_from_entries, BuildOptions, TrustConfig};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

const FOOTER: &str = "q\n0 0 612 792 re W n\nBT /F1 8 Tf 20 10 Td (Downloaded from www.Manualslib.com manuals search engine) Tj ET\nQ\n";

/// A PDF whose pages carry the ManualsLib footer.
fn pdf(pages: usize, tag: &str) -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let font = doc.add_object(dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica" });
    let mut kids = vec![];
    for i in 0..pages {
        let body = format!("BT /F1 12 Tf 72 700 Td ({tag} page {i}) Tj ET\n{FOOTER}");
        let c = doc.add_object(Stream::new(dictionary! {}, body.into_bytes()));
        let p = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font } }, "Contents" => c,
        });
        kids.push(Object::Reference(p));
    }
    let n = kids.len() as i64;
    doc.objects.insert(pages_id, Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => kids, "Count" => n }));
    let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", cat);
    let mut out = vec![];
    doc.save_to(&mut out).unwrap();
    out
}

/// (row id, ManualsLib id, original path, its sha1, published path, its sha1, IA filename, uploaded by the import)
type SourceRow<'a> = (i64, &'a str, &'a Path, &'a str, &'a Path, &'a str, &'a str, bool);

/// The bootstrap database's shape, as far as the re-strip reads it.
fn source_db(path: &Path, rows: &[SourceRow]) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE manuals (id INTEGER PRIMARY KEY, source TEXT, manualslib_id TEXT, source_id TEXT, scraped_at TEXT, created_at TEXT, file_path TEXT, file_sha1 TEXT,
           original_file_sha1 TEXT, original_filename TEXT, archive_url TEXT, archived_by_us INTEGER);
         CREATE TABLE file_variants (manual_id INTEGER, variant_type TEXT, file_path TEXT, file_sha1 TEXT, file_md5 TEXT, file_size INTEGER, is_primary INTEGER);",
    )
    .unwrap();
    for (id, mlid, orig, orig_sha1, publ, pub_sha1, filename, ours) in rows {
        c.execute(
            "INSERT INTO manuals VALUES (?1, 'manualslib', ?2, NULL, '2026-01-05 19:18:15', NULL, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![id, mlid, publ.to_str(), pub_sha1, orig_sha1, filename, format!("https://archive.org/details/manualslib-id-{mlid}"), *ours as i64],
        )
        .unwrap();
        c.execute("INSERT INTO file_variants VALUES (?1, 'original', ?2, ?3, '', 0, 0)", rusqlite::params![id, orig.to_str(), orig_sha1]).unwrap();
        if orig_sha1 != pub_sha1 {
            c.execute("INSERT INTO file_variants VALUES (?1, 'stripped', ?2, ?3, '', 0, 1)", rusqlite::params![id, publ.to_str(), pub_sha1]).unwrap();
        }
    }
}

#[derive(Default)]
struct Mock {
    puts: Vec<(String, Vec<u8>, HeaderMap)>,
    patches: Vec<(String, Value)>,
    metadata: HashMap<String, Value>,
}
type Shared = Arc<Mutex<Mock>>;

async fn mock_ia() -> (String, Shared) {
    let state: Shared = Arc::new(Mutex::new(Mock::default()));
    async fn put_file(State(s): State<Shared>, AxPath((id, name)): AxPath<(String, String)>, headers: HeaderMap, body: axum::body::Bytes) -> StatusCode {
        if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("LOW testaccess:testsecret") {
            return StatusCode::FORBIDDEN;
        }
        s.lock().unwrap().puts.push((format!("{id}/{name}"), body.to_vec(), headers));
        StatusCode::OK
    }
    async fn read_md(State(s): State<Shared>, AxPath(id): AxPath<String>) -> Json<Value> {
        Json(json!({"metadata": s.lock().unwrap().metadata.get(&id).cloned().unwrap_or(json!({"identifier": id}))}))
    }
    async fn write_md(State(s): State<Shared>, AxPath(id): AxPath<String>, Form(f): Form<HashMap<String, String>>) -> Json<Value> {
        let patch: Value = serde_json::from_str(&f["-patch"]).unwrap();
        assert_eq!(f["-target"], "metadata");
        s.lock().unwrap().patches.push((id, patch));
        Json(json!({"success": true, "task_id": 1}))
    }
    let app = Router::new()
        .route("/metadata/{id}", get(read_md).post(write_md))
        .route("/{id}/{name}", put(put_file))
        .with_state(state.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (base, state)
}

fn om(home: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new(env!("CARGO_BIN_EXE_om"))
        .arg("--home")
        .arg(home)
        .args(args)
        // Never reach the real `ia` config or keys.
        .env("HOME", home)
        .env_remove("IA_ACCESS_KEY")
        .env_remove("IA_SECRET_KEY")
        .output()
        .unwrap();
    assert!(out.status.success(), "om {args:?} failed:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    out
}

fn outbox_facts(home: &Path) -> Vec<Fact> {
    let mut paths: Vec<_> = std::fs::read_dir(home.join("outbox")).unwrap().map(|e| e.unwrap().path()).collect();
    paths.sort();
    paths.iter().flat_map(|p| std::fs::read_to_string(p).unwrap().lines().map(|l| Fact::from_json(l).unwrap()).collect::<Vec<_>>()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn restrip_replaces_the_file_and_the_build_switches_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // Item 1 was uploaded unstripped (published = original); item 2 was
    // already stripped by the current stripper; item 3 is someone else's item.
    let orig1 = pdf(3, "one");
    let orig2 = pdf(2, "two");
    let pub2 = openmanuals_strip::strip(&orig2).unwrap().bytes;
    let orig3 = pdf(2, "three");
    for (n, b) in [("o1.pdf", &orig1), ("o2.pdf", &orig2), ("p2.pdf", &pub2), ("o3.pdf", &orig3)] {
        std::fs::write(d.join(n), b).unwrap();
    }
    let db = d.join("manuals.db");
    let (s1, s2, p2, s3) = (sha1_hex(&orig1), sha1_hex(&orig2), sha1_hex(&pub2), sha1_hex(&orig3));
    source_db(&db, &[
        (1, "111", &d.join("o1.pdf"), &s1, &d.join("o1.pdf"), &s1, "one.pdf", true),
        (2, "222", &d.join("o2.pdf"), &s2, &d.join("p2.pdf"), &p2, "two.pdf", true),
        (3, "333", &d.join("o3.pdf"), &s3, &d.join("o3.pdf"), &s3, "three.pdf", false),
    ]);

    // The user's key (also the importer here) and a server key.
    let home = d.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let me = SigningKey::from_seed(Alg::Ed25519, &[7; 32]).unwrap();
    let server = SigningKey::from_seed(Alg::Ed25519, &[1; 32]).unwrap();
    std::fs::write(d.join("me.key"), me.to_openssh("test").unwrap()).unwrap();
    om(&home, &["key", "import", d.join("me.key").to_str().unwrap()]);

    // Scan: only item 1 needs re-stripping.
    let report = d.join("report.jsonl");
    om(&home, &["restrip-scan", "--db", db.to_str().unwrap(), "--out", report.to_str().unwrap(), "--jobs", "2"]);
    let lines: Vec<Value> = std::fs::read_to_string(&report).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let f = &lines[0];
    assert_eq!(f["identifier"], "manualslib-id-111");
    assert_eq!(f["from"], "original");
    let kinds: Vec<&str> = f["kinds"].as_array().unwrap().iter().map(|k| k.as_str().unwrap()).collect();
    assert_eq!(kinds, ["never-stripped", "footer"]);
    let new = openmanuals_strip::strip(&orig1).unwrap().bytes;
    assert_eq!(f["new_sha256"], sha256_hex(&new));
    let manual = f["manual"].as_str().unwrap().to_string();

    // A dry run changes nothing.
    let (base, mock) = mock_ia().await;
    let common = ["--ia-access", "testaccess", "--ia-secret", "testsecret", "--ia-s3-base", &base, "--ia-api-base", &base, "--interval", "0"];
    let mut args = vec!["restrip", "--from-report", report.to_str().unwrap(), "--dry-run"];
    args.extend(common);
    let (h, a) = (home.clone(), args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    tokio::task::spawn_blocking(move || om(&h, &a.iter().map(String::as_str).collect::<Vec<_>>())).await.unwrap();
    assert!(mock.lock().unwrap().puts.is_empty());
    assert!(outbox_facts(&home).is_empty());

    // The real run against the mock.
    mock.lock().unwrap().metadata.insert("manualslib-id-111".into(), json!({"identifier": "manualslib-id-111", "external-identifier": [format!("urn:sha1:{s1}"), "urn:md5:x", format!("urn:original-sha1:{s1}")]}));
    let mut args = vec!["restrip", "--from-report", report.to_str().unwrap()];
    args.extend(common);
    let run = |args: Vec<&str>| {
        let (h, a) = (home.clone(), args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        tokio::task::spawn_blocking(move || om(&h, &a.iter().map(String::as_str).collect::<Vec<_>>()))
    };
    run(args.clone()).await.unwrap();
    {
        let m = mock.lock().unwrap();
        assert_eq!(m.puts.len(), 1);
        assert_eq!(m.puts[0].0, "manualslib-id-111/one.pdf");
        assert_eq!(sha256_hex(&m.puts[0].1), sha256_hex(&new), "the re-stripped bytes are uploaded");
        assert_eq!(m.patches.len(), 1);
        let ext = &m.patches[0].1[0];
        assert_eq!(ext["op"], "replace");
        assert_eq!(ext["value"], json!([format!("urn:sha256:{}", sha256_hex(&new)), format!("urn:sha1:{}", sha1_hex(&new)), format!("urn:md5:{}", openmanuals_core::canon::md5_hex(&new)), format!("urn:original-sha1:{s1}")]));
        assert_eq!(m.patches[0].1[1]["path"], "/openmanuals-original-sha256");
    }
    let facts = outbox_facts(&home);
    let types: Vec<&str> = facts.iter().map(|f| f.r#type.as_str()).collect();
    assert_eq!(types, ["file", "file", "derivation", "manual_file", "location"]);
    for f in &facts {
        f.verify().unwrap();
    }
    let new_sha = sha256_hex(&new);
    assert_eq!(facts[2].body["derived"], new_sha);
    assert_eq!(facts[2].body["source"], sha256_hex(&orig1));
    assert_eq!(facts[2].body["tool_version"], "om-strip-rs/1");
    assert_eq!(facts[4].body, json!({"file": new_sha, "url": "https://archive.org/download/manualslib-id-111/one.pdf", "kind": "archive", "ia": {"identifier": "manualslib-id-111", "filename": "one.pdf"}}));

    // Resumable: a second run skips the finished item.
    run(args).await.unwrap();
    assert_eq!(mock.lock().unwrap().puts.len(), 1);
    assert_eq!(outbox_facts(&home).len(), 5);

    // The build: the import's facts for item 1, the re-strip's, then the verifier.
    let mut gen = CursorGen::new();
    let mut entries: Vec<Entry> = vec![];
    let mut add = |key: &SigningKey, t: &str, body: Value| -> String {
        let mut f = Fact::new(t, "x", "2026-10-23T18:00:00Z", body);
        key.sign_fact(&mut f).unwrap();
        let id = f.id().unwrap();
        entries.push(Entry { cursor: gen.next(), id: id.clone(), fact: f });
        id
    };
    let old = sha256_hex(&orig1);
    add(&me, "manual", json!({"id": manual, "title": "One", "doc_type": "user"}));
    add(&me, "file", json!({"sha256": old, "size": orig1.len(), "mime": "application/pdf"}));
    add(&me, "manual_file", json!({"manual": manual, "file": old, "role": "primary"}));
    let old_loc = add(&me, "location", json!({"file": old, "url": "https://archive.org/download/manualslib-id-111/one.pdf", "kind": "archive", "ia": {"identifier": "manualslib-id-111", "filename": "one.pdf"}}));
    add(&server, "verified", json!({"location": old_loc, "sha256": old, "file_type": "pdf", "scan": {"tool": "om-scan/2", "active": []}, "checked_at": "2026-10-20T00:00:00Z"}));
    let mut ids = HashMap::new();
    for f in &facts {
        let id = f.id().unwrap();
        ids.insert(f.r#type.clone(), id.clone());
        entries.push(Entry { cursor: gen.next(), id, fact: f.clone() });
    }
    let mut cfg = TrustConfig::default();
    cfg.servers.insert(server.public_key().fingerprint());
    let canon = |entries: &[Entry]| -> Option<String> {
        let out = tempfile::NamedTempFile::new().unwrap();
        build_from_entries(entries, &cfg, out.path(), &BuildOptions::default()).unwrap();
        let db = rusqlite::Connection::open(out.path()).unwrap();
        db.query_row("SELECT canonical_file FROM manuals WHERE id = ?1", [&manual], |r| r.get(0)).unwrap()
    };
    assert_eq!(canon(&entries), Some(old.clone()), "until the new copy is verified, the old file stays the download");
    // The verifier: the new copy checks out; the old location now serves other bytes.
    let push = |entries: &mut Vec<Entry>, gen: &mut CursorGen, t: &str, body: Value| {
        let mut f = Fact::new(t, "x", "2026-10-24T18:00:00Z", body);
        server.sign_fact(&mut f).unwrap();
        entries.push(Entry { cursor: gen.next(), id: f.id().unwrap(), fact: f });
    };
    push(&mut entries, &mut gen, "verified", json!({"location": ids["location"], "sha256": new_sha, "file_type": "pdf", "scan": {"tool": "om-scan/2", "active": []}, "checked_at": "2026-10-24T00:00:00Z"}));
    assert_eq!(canon(&entries), Some(new_sha.clone()), "a verified re-strip from the current stripper takes over at once");
    push(&mut entries, &mut gen, "location_status", json!({"location": old_loc, "status": "changed", "checked_at": "2026-10-24T00:00:00Z"}));
    assert_eq!(canon(&entries), Some(new_sha.clone()), "and stays the download once the old location is marked changed");

    // Someone other than the importer re-strips (an untrusted key that didn't
    // create the manual): the incumbent keeps the slot while its copy is
    // good, and the new file takes over once the verifier marks it changed.
    let importer = SigningKey::from_seed(Alg::Ed25519, &[9; 32]).unwrap();
    let mut g = CursorGen::new();
    let mut e2: Vec<Entry> = vec![];
    fn add2(e2: &mut Vec<Entry>, g: &mut CursorGen, key: &SigningKey, t: &str, body: Value) -> String {
        let mut f = Fact::new(t, "x", "2026-10-23T18:00:00Z", body);
        key.sign_fact(&mut f).unwrap();
        let id = f.id().unwrap();
        e2.push(Entry { cursor: g.next(), id: id.clone(), fact: f });
        id
    }
    add2(&mut e2, &mut g, &importer, "manual", json!({"id": manual, "title": "One", "doc_type": "user"}));
    add2(&mut e2, &mut g, &importer, "file", json!({"sha256": old, "size": orig1.len(), "mime": "application/pdf"}));
    add2(&mut e2, &mut g, &importer, "manual_file", json!({"manual": manual, "file": old, "role": "primary"}));
    let old_loc = add2(&mut e2, &mut g, &importer, "location", json!({"file": old, "url": "https://archive.org/download/manualslib-id-111/one.pdf", "kind": "archive", "ia": {"identifier": "manualslib-id-111", "filename": "one.pdf"}}));
    add2(&mut e2, &mut g, &server, "verified", json!({"location": old_loc, "sha256": old, "file_type": "pdf", "scan": {"tool": "om-scan/2", "active": []}, "checked_at": "2026-10-20T00:00:00Z"}));
    for f in &facts {
        e2.push(Entry { cursor: g.next(), id: f.id().unwrap(), fact: f.clone() });
    }
    add2(&mut e2, &mut g, &server, "verified", json!({"location": ids["location"], "sha256": new_sha, "file_type": "pdf", "scan": {"tool": "om-scan/2", "active": []}, "checked_at": "2026-10-24T00:00:00Z"}));
    assert_eq!(canon(&e2), Some(old.clone()), "a newcomer from another key doesn't displace the incumbent on its own");
    add2(&mut e2, &mut g, &server, "location_status", json!({"location": old_loc, "status": "changed", "checked_at": "2026-10-24T00:00:00Z"}));
    assert_eq!(canon(&e2), Some(new_sha), "once the old copy is gone, the re-strip is the download");
}
