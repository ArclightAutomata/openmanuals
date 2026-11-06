//! End-to-end build rules on a synthetic ledger.
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_ledger::ledger::{CursorGen, Entry};
use openmanuals_ledger::{build::build_from_entries, BuildOptions, TrustConfig};
use rusqlite::Connection;
use serde_json::json;

struct Ctx {
    gen: CursorGen,
    entries: Vec<Entry>,
}

impl Ctx {
    fn add(&mut self, key: &SigningKey, t: &str, body: serde_json::Value) -> String {
        let mut f = Fact::new(t, "x", "2026-10-23T18:00:00Z", body);
        key.sign_fact(&mut f).unwrap();
        let id = f.id().unwrap();
        self.entries.push(Entry { cursor: self.gen.next(), id: id.clone(), fact: f });
        id
    }
}

const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const SHA_STRIPPED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const MANUAL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn q1<T: rusqlite::types::FromSql>(c: &Connection, sql: &str) -> T {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn build_applies_rules_and_is_reproducible() {
    let server = SigningKey::from_seed(Alg::Ed25519, &[1; 32]).unwrap();
    let alice = SigningKey::from_seed(Alg::Ed25519, &[2; 32]).unwrap();
    let bob = SigningKey::from_seed(Alg::Ed25519, &[3; 32]).unwrap();
    let troll = SigningKey::from_seed(Alg::Ed25519, &[4; 32]).unwrap();
    let mut cfg = TrustConfig::default();
    cfg.servers.insert(server.public_key().fingerprint());
    cfg.moderators.insert(server.public_key().fingerprint());
    cfg.domain = "openmanuals.test".into();

    let mut c = Ctx { gen: CursorGen::new(), entries: vec![] };
    c.add(&alice, "manual", json!({"id": MANUAL, "title": "JVC AV-2168TEE Service Manual", "doc_type": "service", "source": "manualslib", "source_id": "331384", "source_url": "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html"}));
    c.add(&alice, "product", json!({"brand": "JVC", "model": "AV-2168TEE"}));
    c.add(&bob, "product", json!({"brand": "jvc", "model": "av 2168 tee"})); // same key
    c.add(&alice, "covers", json!({"manual": MANUAL, "product": "jvc|AV2168TEE"}));
    c.add(&alice, "file", json!({"sha256": SHA, "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "size": 4, "mime": "application/pdf"}));
    c.add(&alice, "file", json!({"sha256": SHA_STRIPPED, "size": 3, "mime": "application/pdf"}));
    c.add(&alice, "derivation", json!({"derived": SHA_STRIPPED, "source": SHA, "transform": "watermark-stripped", "tool": "om-strip", "tool_version": "om-strip/2"}));
    c.add(&alice, "manual_file", json!({"manual": MANUAL, "file": SHA, "role": "primary"}));
    c.add(&alice, "manual_file", json!({"manual": MANUAL, "file": SHA_STRIPPED, "role": "primary"}));
    let origin = c.add(&alice, "location", json!({"file": SHA, "url": "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html", "kind": "origin"}));
    let ia = c.add(&alice, "location", json!({"file": SHA_STRIPPED, "url": "https://archive.org/download/openmanuals-11111111111111111-01arz3ndektsv4rrffq69g5fav/manual.pdf", "kind": "archive", "ia": {"identifier": "openmanuals-1111111111111111-01arz3ndektsv4rrffq69g5fav", "filename": "manual.pdf"}}));
    let mirror = c.add(&bob, "location", json!({"file": SHA_STRIPPED, "url": "https://mirror.example.org/m.pdf", "kind": "mirror"}));
    let pending = c.add(&bob, "location", json!({"file": SHA, "url": "https://mirror.example.org/orig.pdf", "kind": "mirror"}));
    let _ = pending;
    // Bob's mirror verified first, IA second: archive.org still wins the canonical slot.
    c.add(&server, "verified", json!({"location": mirror, "final_url": "https://mirror.example.org/m.pdf", "sha256": SHA_STRIPPED, "size": 3, "checked_at": "2026-10-20T00:00:00Z", "file_type": "pdf", "scan": {"tool": "om-scan/1", "active": []}}));
    c.add(&server, "verified", json!({"location": ia, "final_url": "https://ia800.us.archive.org/x/manual.pdf", "sha256": SHA_STRIPPED, "size": 3, "checked_at": "2026-10-21T00:00:00Z", "file_type": "pdf", "scan": {"tool": "om-scan/1", "active": []}}));
    // Troll: a bogus title update, then blocked. A retracted fact by alice.
    c.add(&troll, "manual", json!({"id": MANUAL, "title": "SPAM"}));
    c.add(&server, "block", json!({"kind": "key", "value": troll.public_key().fingerprint(), "reason": "spam"}));
    let junk = c.add(&alice, "label", json!({"target": format!("file:{SHA_STRIPPED}"), "ns": "report", "value": "wrong-file"}));
    c.add(&alice, "retract", json!({"fact": junk}));
    // Identity: profile + server link for alice and bob under the same handle → one contributor.
    let alice_jws = alice.sign_profile("Alice", &["https://gist.github.com/alice/1".into()], None);
    c.add(&alice, "identity_profile", json!({"jws": alice_jws}));
    c.add(&server, "identity_link", json!({"key": alice.public_key().fingerprint(), "claim_uri": "https://gist.github.com/alice/1", "service": "github", "handle": "alice", "checked_at": "2026-10-22T00:00:00Z"}));
    c.add(&server, "identity_link", json!({"key": bob.public_key().fingerprint(), "claim_uri": "https://gist.github.com/alice/2", "service": "github", "handle": "alice", "checked_at": "2026-10-22T00:00:00Z"}));

    let dir = tempfile::tempdir().unwrap();
    let out1 = dir.path().join("a.db");
    let out2 = dir.path().join("b.db");
    let opts = BuildOptions { verify_signatures: true, ..Default::default() };
    let stats = build_from_entries(&c.entries, &cfg, &out1, &opts).unwrap();
    build_from_entries(&c.entries, &cfg, &out2, &opts).unwrap();
    assert_eq!(std::fs::read(&out1).unwrap(), std::fs::read(&out2).unwrap(), "snapshot must be byte-reproducible");
    assert_eq!(stats.blocked, 1);
    assert_eq!(stats.retracted, 1);
    assert_eq!(stats.manuals, 1);
    assert_eq!(stats.products, 1);

    let db = Connection::open(&out1).unwrap();
    let title: String = q1(&db, &format!("SELECT title FROM manuals WHERE id = '{MANUAL}'"));
    assert_eq!(title, "JVC AV-2168TEE Service Manual");
    let canon: String = q1(&db, &format!("SELECT canonical_file FROM manuals WHERE id = '{MANUAL}'"));
    assert_eq!(canon, SHA_STRIPPED, "stripped file with a verified copy is canonical");
    let canon_loc: String = q1(&db, &format!("SELECT canonical_location FROM files WHERE id = '{SHA_STRIPPED}'"));
    assert_eq!(canon_loc, ia, "archive.org copy outranks the earlier-verified mirror");
    let n_pub: i64 = q1(&db, "SELECT count(*) FROM locations");
    assert_eq!(n_pub, 3, "origin + two verified copies; the pending mirror is not published");
    let origin_status: String = q1(&db, &format!("SELECT status FROM locations WHERE id = '{origin}'"));
    assert_eq!(origin_status, "origin");
    let brand: String = q1(&db, &format!("SELECT brand FROM manuals WHERE id = '{MANUAL}'"));
    assert_eq!(brand, "JVC");
    let contributors: i64 = q1(&db, "SELECT count(*) FROM contributors");
    assert_eq!(contributors, 2, "alice+bob grouped, server separate (troll blocked)");
    let alice_group: String = q1(&db, &format!("SELECT contributor FROM keys WHERE fingerprint = '{}'", alice.public_key().fingerprint()));
    let bob_group: String = q1(&db, &format!("SELECT contributor FROM keys WHERE fingerprint = '{}'", bob.public_key().fingerprint()));
    assert_eq!(alice_group, bob_group);
    let name: String = q1(&db, &format!("SELECT name FROM contributors WHERE id = '{alice_group}'"));
    assert_eq!(name, "Alice");
    let labels: i64 = q1(&db, "SELECT count(*) FROM labels");
    assert_eq!(labels, 0, "retracted report is gone");
    let dl: i64 = q1(&db, "SELECT downloadable FROM brands WHERE brand_key = 'jvc'");
    assert_eq!(dl, 1);
}

#[test]
fn legacy_sha1_files_merge_into_sha256_files() {
    let alice = SigningKey::from_seed(Alg::Ed25519, &[2; 32]).unwrap();
    let mut cfg = TrustConfig::default();
    cfg.include_unverified = true;
    let mut c = Ctx { gen: CursorGen::new(), entries: vec![] };
    let sha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
    c.add(&alice, "file", json!({"sha1": sha1, "md5": "098f6bcd4621d373cade4e832627b4f6", "size": 4}));
    let loc = c.add(&alice, "location", json!({"file": format!("sha1:{sha1}"), "url": "https://archive.org/download/manualslib-id-1/x.pdf", "kind": "archive"}));
    c.add(&alice, "file", json!({"sha256": SHA, "sha1": sha1, "size": 4}));
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.db");
    let stats = build_from_entries(&c.entries, &cfg, &out, &BuildOptions::default()).unwrap();
    assert_eq!(stats.files, 1);
    let db = Connection::open(&out).unwrap();
    let file: String = q1(&db, &format!("SELECT file FROM locations WHERE id = '{loc}'"));
    assert_eq!(file, SHA);
    let md5: String = q1(&db, &format!("SELECT md5 FROM files WHERE id = '{SHA}'"));
    assert_eq!(md5, "098f6bcd4621d373cade4e832627b4f6");
}

/// Poisoning attempts: a manual's download must not be taken over, and files
/// the server found risky (or never examined, from untrusted keys) are never
/// offered.
#[test]
fn poisoned_files_are_never_a_manuals_download() {
    let server = SigningKey::from_seed(Alg::Ed25519, &[1; 32]).unwrap();
    let alice = SigningKey::from_seed(Alg::Ed25519, &[2; 32]).unwrap();
    let mallory = SigningKey::from_seed(Alg::Ed25519, &[6; 32]).unwrap();
    let mut cfg = TrustConfig::default();
    cfg.servers.insert(server.public_key().fingerprint());
    cfg.include_unverified = true;
    let clean = |extra: serde_json::Value| {
        let mut v = json!({"file_type": "pdf", "scan": {"tool": "om-scan/1", "active": []}, "checked_at": "2026-10-20T00:00:00Z"});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    let h = |n: u8| format!("{n:02x}").repeat(32);
    let (orig, stripped, evil, exe, js, mal, unscanned, weird) = (h(0x10), h(0x11), h(0x12), h(0x13), h(0x14), h(0x15), h(0x16), h(0x17));
    let m = |i: u8| format!("01ARZ3NDEKTSV4RRFFQ69G5F{:02}", i);
    let mut c = Ctx { gen: CursorGen::new(), entries: vec![] };
    let file = |c: &mut Ctx, who: &SigningKey, man: &str, sha: &str, mime: &str, verdict: Option<serde_json::Value>| {
        c.add(who, "file", json!({"sha256": sha, "size": 1, "mime": mime}));
        c.add(who, "manual_file", json!({"manual": man, "file": sha, "role": "primary"}));
        let loc = c.add(who, "location", json!({"file": sha, "url": format!("https://host.example/{sha}.pdf"), "kind": "mirror"}));
        if let Some(mut v) = verdict {
            v["location"] = json!(loc);
            v["sha256"] = json!(sha);
            c.add(&server, "verified", v);
        }
    };

    // 1. Takeover by a fake derivation: mallory attaches a verified file to
    //    alice's manual and claims it's a newer stripped variant.
    c.add(&alice, "manual", json!({"id": m(1), "title": "Takeover target", "doc_type": "service"}));
    file(&mut c, &alice, &m(1), &orig, "application/pdf", Some(clean(json!({}))));
    file(&mut c, &alice, &m(1), &stripped, "application/pdf", Some(clean(json!({}))));
    c.add(&alice, "derivation", json!({"derived": stripped, "source": orig, "transform": "watermark-stripped", "tool": "om-strip", "tool_version": "om-strip/1"}));
    file(&mut c, &mallory, &m(1), &evil, "application/pdf", Some(clean(json!({}))));
    c.add(&mallory, "derivation", json!({"derived": evil, "source": orig, "transform": "watermark-stripped", "tool": "om-strip", "tool_version": "om-strip/999"}));
    // mallory also tries to rewrite what alice's stripped file derives from.
    c.add(&mallory, "derivation", json!({"derived": stripped, "source": evil, "transform": "watermark-stripped", "tool": "om-strip", "tool_version": "om-strip/999"}));

    // 2. Bytes the server sniffed as something else never verify.
    c.add(&mallory, "manual", json!({"id": m(2), "title": "Exe", "doc_type": "service"}));
    file(&mut c, &mallory, &m(2), &exe, "application/pdf", Some(clean(json!({"file_type": "exe"}))));
    // 3. Active content, 4. malware listing, 5. never scanned (untrusted key).
    c.add(&mallory, "manual", json!({"id": m(3), "title": "JS", "doc_type": "service"}));
    file(&mut c, &mallory, &m(3), &js, "application/pdf", Some(clean(json!({"scan": {"tool": "om-scan/1", "active": ["JavaScript", "Launch"]}}))));
    c.add(&mallory, "manual", json!({"id": m(4), "title": "Malware", "doc_type": "service"}));
    file(&mut c, &mallory, &m(4), &mal, "application/pdf", Some(clean(json!({"malware": {"source": "malwarebazaar", "listed": true, "signature": "AgentTesla"}}))));
    c.add(&mallory, "manual", json!({"id": m(5), "title": "Unscanned", "doc_type": "service"}));
    file(&mut c, &mallory, &m(5), &unscanned, "application/pdf", Some(json!({"checked_at": "2026-10-20T00:00:00Z", "file_type": "pdf"})));
    // 6. A variant from a tool not on the allowlist gets no credit: alice's
    //    original stays the download, and the claimed MIME gives way to the sniffed type.
    c.add(&alice, "manual", json!({"id": m(6), "title": "Unknown tool", "doc_type": "service"}));
    file(&mut c, &alice, &m(6), &h(0x20), "application/x-msdownload", Some(clean(json!({}))));
    file(&mut c, &alice, &m(6), &weird, "application/pdf", Some(clean(json!({}))));
    c.add(&alice, "derivation", json!({"derived": weird, "source": h(0x20), "transform": "watermark-stripped", "tool": "evil", "tool_version": "evil/9"}));
    // 7. The server's own legacy files (trusted, migrated before scans) stay offered.
    c.add(&server, "manual", json!({"id": m(7), "title": "Legacy", "doc_type": "service"}));
    file(&mut c, &server, &m(7), &h(0x30), "application/pdf", Some(json!({"checked_at": "2025-01-01T00:00:00Z"})));
    // 8. Launch actions (om-scan/2): one that only opens a document is
    //    informational; one that runs a program holds the file; om-scan/1
    //    couldn't tell them apart, so its `Launch` still holds.
    let (launch_doc, launch_exe, launch_v1) = (h(0x40), h(0x41), h(0x42));
    c.add(&mallory, "manual", json!({"id": m(8), "title": "Opens a document", "doc_type": "service"}));
    file(&mut c, &mallory, &m(8), &launch_doc, "application/pdf", Some(clean(json!({"scan": {"tool": "om-scan/2", "active": ["LaunchDocument"]}}))));
    c.add(&mallory, "manual", json!({"id": m(9), "title": "Runs a program", "doc_type": "service"}));
    file(&mut c, &mallory, &m(9), &launch_exe, "application/pdf", Some(clean(json!({"scan": {"tool": "om-scan/2", "active": ["Launch", "LaunchDocument"]}}))));
    c.add(&mallory, "manual", json!({"id": m(10), "title": "Old scan", "doc_type": "service"}));
    file(&mut c, &mallory, &m(10), &launch_v1, "application/pdf", Some(clean(json!({"scan": {"tool": "om-scan/1", "active": ["Launch"]}}))));

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.db");
    build_from_entries(&c.entries, &cfg, &out, &BuildOptions::default()).unwrap();
    let db = Connection::open(&out).unwrap();
    let canon = |i: u8| -> Option<String> { q1(&db, &format!("SELECT canonical_file FROM manuals WHERE id = '{}'", m(i))) };
    let review = |sha: &str| -> Option<String> { q1(&db, &format!("SELECT review FROM files WHERE id = '{sha}'")) };

    assert_eq!(canon(1).as_deref(), Some(stripped.as_str()), "alice's stripped file keeps the slot");
    let derived: Option<String> = q1(&db, &format!("SELECT derived_from FROM files WHERE id = '{stripped}'"));
    assert_eq!(derived.as_deref(), Some(orig.as_str()), "only a file's own author says what it derives from");
    let status: String = q1(&db, &format!("SELECT l.status FROM locations l WHERE l.file = '{exe}'"));
    assert_eq!(status, "changed", "an exe never counts as verified");
    assert_eq!(canon(2), None);
    assert_eq!(canon(3), None);
    assert_eq!(review(&js).as_deref(), Some("active content: JavaScript, Launch"));
    assert_eq!(canon(4), None);
    assert_eq!(review(&mal).as_deref(), Some("malware: AgentTesla"));
    assert_eq!(canon(5), None);
    assert_eq!(review(&unscanned).as_deref(), Some("unscanned"));
    assert_eq!(canon(6).as_deref(), Some(h(0x20).as_str()), "no credit for an unknown tool: the incumbent stays");
    let mime: String = q1(&db, &format!("SELECT mime FROM files WHERE id = '{}'", h(0x20)));
    assert_eq!(mime, "application/pdf", "the server's sniff replaces the claimed type");
    assert_eq!(canon(7).as_deref(), Some(h(0x30).as_str()), "trusted legacy files need no scan");
    assert_eq!(review(&h(0x30)), None);
    assert_eq!(canon(8).as_deref(), Some(launch_doc.as_str()), "a Launch that opens a document doesn't hold");
    assert_eq!(review(&launch_doc), None);
    assert_eq!(canon(9), None);
    assert_eq!(review(&launch_exe).as_deref(), Some("active content: Launch"), "only holding features are listed");
    assert_eq!(canon(10), None);
    assert_eq!(review(&launch_v1).as_deref(), Some("active content: Launch"));
    let flagged: i64 = q1(&db, "SELECT count(*) FROM files WHERE flagged = 1");
    assert_eq!(flagged, 5, "js, malware, unscanned, two risky Launch");
}

#[test]
fn a_keys_newest_live_avatar_wins() {
    let moderator = SigningKey::from_seed(Alg::Ed25519, &[1; 32]).unwrap();
    let alice = SigningKey::from_seed(Alg::Ed25519, &[2; 32]).unwrap();
    let bob = SigningKey::from_seed(Alg::Ed25519, &[3; 32]).unwrap();
    let carol = SigningKey::from_seed(Alg::Ed25519, &[5; 32]).unwrap();
    let dave = SigningKey::from_seed(Alg::Ed25519, &[6; 32]).unwrap();
    let mut cfg = TrustConfig::default();
    cfg.moderators.insert(moderator.public_key().fingerprint());
    let img = |c: char| json!({"sha256": c.to_string().repeat(64), "size": 1000, "mime": "image/webp"});
    let mut c = Ctx { gen: CursorGen::new(), entries: vec![] };
    // Alice: an image, then a URL, then a newer image: the newest wins.
    c.add(&alice, "avatar", img('a'));
    c.add(&alice, "avatar", json!({"url": "https://github.com/alice.png"}));
    c.add(&alice, "avatar", img('b'));
    // An invalid body changes nothing.
    c.add(&alice, "avatar", json!({"url": "http://insecure.example/a.png"}));
    // Bob: an image, then a newer one he retracts: the older one is back.
    c.add(&bob, "avatar", img('c'));
    let newer = c.add(&bob, "avatar", img('d'));
    c.add(&bob, "retract", json!({"fact": newer}));
    // Carol: an image, then a newer one a moderator blocks; then back to none.
    c.add(&carol, "avatar", img('e'));
    let blocked = c.add(&carol, "avatar", img('f'));
    c.add(&moderator, "block", json!({"kind": "fact", "value": blocked, "reason": "abuse"}));
    // Dave: an image, then none.
    c.add(&dave, "avatar", img('a'));
    c.add(&dave, "avatar", json!({"none": true}));

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.db");
    build_from_entries(&c.entries, &cfg, &out, &BuildOptions::default()).unwrap();
    let db = Connection::open(&out).unwrap();
    let avatar = |k: &SigningKey| -> (Option<String>, Option<String>, Option<String>) {
        db.query_row("SELECT avatar_sha256, avatar_mime, avatar_url FROM keys WHERE fingerprint = ?1", [k.public_key().fingerprint()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
    };
    assert_eq!(avatar(&alice), (Some("b".repeat(64)), Some("image/webp".into()), None));
    assert_eq!(avatar(&bob), (Some("c".repeat(64)), Some("image/webp".into()), None), "retracted: the previous one");
    assert_eq!(avatar(&carol), (Some("e".repeat(64)), Some("image/webp".into()), None), "blocked: the previous one");
    assert_eq!(avatar(&dave), (None, None, None));
    // A URL avatar.
    let mut c2 = Ctx { gen: CursorGen::new(), entries: vec![] };
    c2.add(&alice, "avatar", json!({"url": "https://github.com/alice.png"}));
    let out2 = dir.path().join("b.db");
    build_from_entries(&c2.entries, &cfg, &out2, &BuildOptions::default()).unwrap();
    let db2 = Connection::open(&out2).unwrap();
    let url: String = q1(&db2, "SELECT avatar_url FROM keys");
    assert_eq!(url, "https://github.com/alice.png");
}

/// The order of `derivation_tools` decides between variants: a re-strip with
/// the current tool replaces an older tool's variant once it is verified.
#[test]
fn later_derivation_tools_win_the_download() {
    let server = SigningKey::from_seed(Alg::Ed25519, &[1; 32]).unwrap();
    let alice = SigningKey::from_seed(Alg::Ed25519, &[2; 32]).unwrap();
    let mut cfg = TrustConfig::default();
    cfg.servers.insert(server.public_key().fingerprint());
    let h = |n: u8| format!("{n:02x}").repeat(32);
    let m = |i: u8| format!("01ARZ3NDEKTSV4RRFFQ69G5F{:02}", i);
    let mut c = Ctx { gen: CursorGen::new(), entries: vec![] };
    let variant = |c: &mut Ctx, man: &str, sha: &str, source: Option<(&str, &str)>| {
        c.add(&alice, "file", json!({"sha256": sha, "size": 1, "mime": "application/pdf"}));
        c.add(&alice, "manual_file", json!({"manual": man, "file": sha, "role": "primary"}));
        if let Some((src, tool)) = source {
            c.add(&alice, "file", json!({"sha256": src, "size": 2, "mime": "application/pdf"}));
            c.add(&alice, "derivation", json!({"derived": sha, "source": src, "transform": "watermark-stripped", "tool": "x", "tool_version": tool}));
        }
        let loc = c.add(&alice, "location", json!({"file": sha, "url": format!("https://host.example/{sha}.pdf"), "kind": "mirror"}));
        c.add(&server, "verified", json!({"location": loc, "sha256": sha, "file_type": "pdf", "scan": {"tool": "om-scan/2", "active": []}, "checked_at": "2026-10-20T00:00:00Z"}));
    };
    // 1. Bootstrap variant first, then a re-strip with the current stripper.
    c.add(&alice, "manual", json!({"id": m(1), "title": "Re-stripped", "doc_type": "service"}));
    variant(&mut c, &m(1), &h(0x50), Some((&h(0x5f), "salli-cat pdf_utils/1")));
    variant(&mut c, &m(1), &h(0x51), Some((&h(0x5f), "om-strip-rs/1")));
    // 2. The other way round: an older tool's variant arriving later doesn't win.
    c.add(&alice, "manual", json!({"id": m(2), "title": "Older tool later", "doc_type": "service"}));
    variant(&mut c, &m(2), &h(0x60), Some((&h(0x6f), "om-strip-rs/1")));
    variant(&mut c, &m(2), &h(0x61), Some((&h(0x6f), "om-strip/1")));
    // 3. Same tool, two versions (both listed): the higher version wins, wherever it is listed.
    c.add(&alice, "manual", json!({"id": m(3), "title": "Two versions", "doc_type": "service"}));
    variant(&mut c, &m(3), &h(0x70), Some((&h(0x7f), "om-strip-rs/2")));
    variant(&mut c, &m(3), &h(0x71), Some((&h(0x7f), "om-strip-rs/1")));
    cfg.derivation_tools = vec!["om-strip-rs/2".into(), "salli-cat pdf_utils/1".into(), "om-strip/1".into(), "om-strip-rs/1".into()];

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.db");
    build_from_entries(&c.entries, &cfg, &out, &BuildOptions::default()).unwrap();
    let db = Connection::open(&out).unwrap();
    let canon = |i: u8| -> Option<String> { q1(&db, &format!("SELECT canonical_file FROM manuals WHERE id = '{}'", m(i))) };
    assert_eq!(canon(1), Some(h(0x51)), "the current stripper's variant replaces the bootstrap one");
    assert_eq!(canon(2), Some(h(0x60)), "an older tool's variant doesn't displace a newer one");
    assert_eq!(canon(3), Some(h(0x70)), "between versions of one tool, the higher version wins");
}

#[test]
fn a_manual_without_a_source_takes_its_uploaders_origin_page() {
    let alice = SigningKey::from_seed(Alg::Ed25519, &[2; 32]).unwrap();
    let bob = SigningKey::from_seed(Alg::Ed25519, &[3; 32]).unwrap();
    let cfg = TrustConfig { include_unverified: true, ..Default::default() };
    let page = "https://www.freeservicemanuals.info/en/servicemanuals/viewmanual/Philips/14PV100/51TVB61/37TR216/DELTA2000/";
    let mut c = Ctx { gen: CursorGen::new(), entries: vec![] };
    // As the extension uploaded before manual facts named their page: only the
    // stripped copy is attached, and the origin is the original's.
    c.add(&alice, "manual", json!({"id": MANUAL, "title": "Philips 14PV100 Service Manual", "doc_type": "service"}));
    c.add(&alice, "file", json!({"sha256": SHA, "size": 4, "mime": "application/pdf"}));
    c.add(&alice, "file", json!({"sha256": SHA_STRIPPED, "size": 3, "mime": "application/pdf"}));
    c.add(&alice, "derivation", json!({"derived": SHA_STRIPPED, "source": SHA, "transform": "watermark-stripped", "tool": "om-strip", "tool_version": "om-strip/2"}));
    c.add(&alice, "manual_file", json!({"manual": MANUAL, "file": SHA_STRIPPED, "role": "primary"}));
    // Someone else's origin for the same bytes doesn't name alice's manual.
    c.add(&bob, "location", json!({"file": SHA, "url": "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html", "kind": "origin"}));
    c.add(&alice, "location", json!({"file": SHA, "url": page, "kind": "origin"}));
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.db");
    build_from_entries(&c.entries, &cfg, &out, &BuildOptions::default()).unwrap();
    let db = Connection::open(&out).unwrap();
    let (source, id, url): (String, String, String) = db
        .query_row(&format!("SELECT source, source_id, source_url FROM manuals WHERE id = '{MANUAL}'"), [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap();
    assert_eq!(source, "freeservicemanuals");
    assert_eq!(id, "servicemanuals/philips/14pv100/51tvb61/37tr216/delta2000");
    assert!(url.starts_with("https://www.freeservicemanuals.info/"), "{url}");
}
