//! Inbox → fold (git) → build → lookup/feed/ASPE, over real HTTP.
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_server::{fold, router, Paths, State};
use serde_json::{json, Value};

const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const MANUAL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const PAGE: &str = "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html";

fn signed(key: &SigningKey, t: &str, body: Value) -> Value {
    let mut f = Fact::new(t, "x", "2026-10-23T18:00:00Z", body);
    key.sign_fact(&mut f).unwrap();
    serde_json::from_str(&f.to_json()).unwrap()
}

#[tokio::test]
async fn inbox_fold_build_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let server_key = SigningKey::generate(Alg::Ed25519);
    std::fs::write(data.join("server.key"), server_key.to_openssh("test server").unwrap()).unwrap();
    let paths = Paths {
        data_dir: data.clone(),
        ledger_dir: dir.path().join("ledger"),
        key: None,
        trust: None,
        domain: "openmanuals.test".into(),
        public_url: "http://test".into(),
        doip_script: None,
        no_checkpoint: false,
        keep_snapshots: 3,
        keep_diffs_days: 30,
        malwarebazaar_key: None,
    };
    let state = State::new(paths).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // No snapshot yet: lookup still answers with legacy identifiers.
    let v: Value = client.get(format!("{base}/api/lookup?url={PAGE}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["known"], false);
    assert_eq!(v["legacy_identifiers"][0], "manualslib-id-331384");

    let alice = SigningKey::generate(Alg::Ed25519);
    let fp = alice.public_key().fingerprint();
    let archive_url = "https://archive.org/download/openmanuals-9f86d081884c7d65-01arz3ndektsv4rrffq69g5fav/manual.pdf";
    let loc_fact = signed(&alice, "location", json!({"file": SHA, "url": archive_url, "kind": "archive", "ia": {"identifier": "openmanuals-9f86d081884c7d65-01arz3ndektsv4rrffq69g5fav", "filename": "manual.pdf"}}));
    let loc_id = Fact::from_json(&loc_fact.to_string()).unwrap().id().unwrap();
    let profile = alice.sign_profile("Alice", &["https://gist.github.com/alice/1".into()], None);
    let batch = json!([
        signed(&alice, "manual", json!({"id": MANUAL, "title": "JVC AV-2168TEE Service Manual", "doc_type": "service", "source": "manualslib", "source_id": "331384", "source_url": PAGE})),
        signed(&alice, "product", json!({"brand": "JVC", "model": "AV-2168TEE"})),
        signed(&alice, "covers", json!({"manual": MANUAL, "product": "jvc|AV2168TEE"})),
        signed(&alice, "file", json!({"sha256": SHA, "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "size": 4, "mime": "application/pdf"})),
        signed(&alice, "manual_file", json!({"manual": MANUAL, "file": SHA, "role": "primary"})),
        signed(&alice, "location", json!({"file": SHA, "url": PAGE, "kind": "origin"})),
        loc_fact.clone(),
        signed(&alice, "identity_profile", json!({"jws": profile})),
        loc_fact, // duplicate in the same batch
        {"v": 1, "type": "file", "author": fp, "at": "2026-10-23T18:00:00Z", "body": {}, "sig": {"alg": "Ed25519", "fmt": "raw", "key": alice.public_key().to_jwk(), "value": "AAAA"}}, // bad signature
    ]);
    let r = client.post(format!("{base}/api/facts")).json(&batch).send().await.unwrap();
    assert_eq!(r.status(), 202);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["accepted"].as_array().unwrap().len(), 8);
    assert_eq!(v["duplicate"].as_array().unwrap().len(), 1);
    assert_eq!(v["rejected"].as_array().unwrap().len(), 1);
    assert!(v["rejected"][0]["error"].as_str().unwrap().contains("signature"));
    let cursor = v["cursor"].as_str().unwrap().to_string();

    // The server verifies the copy (here: records the verdict directly).
    let verdict = state.server_fact("verified", json!({"location": loc_id, "final_url": archive_url, "sha256": SHA, "size": 4, "checked_at": "2026-10-23T19:00:00Z", "file_type": "pdf", "scan": {"tool": "om-scan/1", "active": []}})).unwrap();
    let r = client.post(format!("{base}/api/facts")).json(&json!([serde_json::from_str::<Value>(&verdict.to_json()).unwrap()])).send().await.unwrap();
    assert_eq!(r.status(), 202);

    // Feed since the first batch's cursor sees only the verdict.
    let v: Value = client.get(format!("{base}/api/feed?since={cursor}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["facts"].as_array().unwrap().len(), 1);
    assert_eq!(v["facts"][0]["fact"]["type"], "verified");
    assert_eq!(v["more"], false);

    // ASPE hosting works straight from the inbox.
    let r = client.get(format!("{base}/.well-known/aspe/id/{}", fp.to_lowercase())).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"].to_str().unwrap().starts_with("application/asp+jwt"));
    assert!(r.headers().get("access-control-allow-origin").is_some());
    let jws = r.text().await.unwrap();
    assert_eq!(openmanuals_core::asp::parse_and_verify(&jws).unwrap().name, "Alice");

    // Fold into git and build.
    let (n, stats) = fold::fold_and_build(state.clone()).await.unwrap();
    let stats = stats.expect("folding facts rebuilds the snapshot");
    assert_eq!(n, 9);
    assert_eq!(stats.manuals, 1);
    assert_eq!(stats.verified_locations, 1);
    let log = std::process::Command::new("git").args(["-C", dir.path().join("ledger").to_str().unwrap(), "log", "--oneline"]).output().unwrap();
    assert!(String::from_utf8_lossy(&log.stdout).contains("fold: 9 facts"));
    assert!(state.inbox.unfolded().unwrap().is_empty());
    // Published: signed manifest, compressed copy, lookup filter.
    let m = client.get(format!("{base}/db/manifest.json")).send().await.unwrap().bytes().await.unwrap();
    let sig = client.get(format!("{base}/db/manifest.json.sig")).send().await.unwrap().text().await.unwrap();
    let sig = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig.trim()).unwrap();
    state.key.public_key().verify_raw(openmanuals_core::canon::sha256_hex(&m).as_bytes(), &sig).unwrap();
    let manifest: Value = serde_json::from_slice(&m).unwrap();
    let version = manifest["latest"]["version"].as_str().unwrap().to_string();
    assert!(openmanuals_server::publish::is_version(&version));
    let zst = client.get(format!("{base}/db/latest.db.zst")).send().await.unwrap();
    assert_eq!(zst.status(), 200, "redirect followed to the compressed copy");
    let z = zst.bytes().await.unwrap();
    assert_eq!(openmanuals_core::canon::sha256_hex(&z), manifest["latest"]["zst"]["sha256"].as_str().unwrap());
    let f = client.get(format!("{base}/db/lookup-filter.bin")).send().await.unwrap();
    let etag = f.headers()["etag"].to_str().unwrap().to_string();
    let filter = openmanuals_core::filter::Filter::from_bytes(&f.bytes().await.unwrap()).unwrap();
    assert!(filter.contains_page(&format!("{PAGE}#x")));
    assert!(!filter.contains_page("https://www.manualslib.com/manual/999999999/Nothing.html"));
    let r = client.get(format!("{base}/db/lookup-filter.bin")).header("if-none-match", &etag).send().await.unwrap();
    assert_eq!(r.status(), 304);
    assert_eq!(client.get(format!("{base}/db/..%2Fserver.key")).send().await.unwrap().status(), 404);
    // A second fold is a no-op and skips the rebuild.
    let built = std::fs::metadata(state.paths.latest_db()).unwrap().modified().unwrap();
    let (n, stats) = fold::fold_and_build(state.clone()).await.unwrap();
    assert_eq!(n, 0);
    assert!(stats.is_none(), "nothing new must not rebuild");
    assert_eq!(std::fs::metadata(state.paths.latest_db()).unwrap().modified().unwrap(), built);
    assert!(fold::snapshot_is_current(&state).unwrap());

    // A changed trust config makes the snapshot stale, so the next fold rebuilds.
    state.trust.write().unwrap().labelers.insert("AAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    assert!(!fold::snapshot_is_current(&state).unwrap());
    let (n, stats) = fold::fold_and_build(state.clone()).await.unwrap();
    assert_eq!(n, 0);
    assert!(stats.is_some(), "stale snapshot must rebuild");
    // Same ledger head, different trust: a new version and a diff to it, never
    // a changed file under an old name.
    let m2: Value = client.get(format!("{base}/db/manifest.json")).send().await.unwrap().json().await.unwrap();
    assert_ne!(m2["latest"]["version"], version.as_str());
    assert_eq!(m2["diffs"][0]["from"], version.as_str());
    assert!(state.paths.snapshots_dir().join(format!("{version}.db")).exists());
    state.trust.write().unwrap().labelers.remove("AAAAAAAAAAAAAAAAAAAAAAAAAA");
    fold::fold_and_build(state.clone()).await.unwrap();
    // Pruning keeps the newest three builds (two here plus this one).
    let builds = std::fs::read_dir(state.paths.snapshots_dir()).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".db") && e.as_ref().unwrap().file_name() != "latest.db").count();
    assert!(builds <= 3, "{builds} builds kept");

    // Lookup now finds the manual and the verified copy.
    let v: Value = client.get(format!("{base}/api/lookup?url={PAGE}%23product-x")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["known"], true);
    assert_eq!(v["manual"]["id"], MANUAL);
    assert_eq!(v["manual"]["url"], format!("http://test/manual/{MANUAL}"));
    assert_eq!(v["files"][0]["canonical"], true);
    assert_eq!(v["files"][0]["copies"][0]["url"], archive_url);
    assert_eq!(v["files"][0]["copies"][0]["author"], fp);
    let v: Value = client.get(format!("{base}/api/lookup?file={SHA}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["manual"]["id"], MANUAL);

    // Snapshot files and signature.
    let sha_line = client.get(format!("{base}/db/latest.db.sha256")).send().await.unwrap().text().await.unwrap();
    let db_bytes = client.get(format!("{base}/db/latest.db")).send().await.unwrap().bytes().await.unwrap();
    let sha = openmanuals_core::canon::sha256_hex(&db_bytes);
    assert!(sha_line.starts_with(&sha));
    let sig = client.get(format!("{base}/db/latest.db.sig")).send().await.unwrap().text().await.unwrap();
    let sig = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig.trim()).unwrap();
    server_key.public_key().verify_raw(sha.as_bytes(), &sig).unwrap();

    // Pages render.
    for path in ["/", "/manuals?q=jvc", &format!("/manual/{MANUAL}"), "/product/JVC/AV-2168TEE", &format!("/file/{SHA}"), &format!("/k/{fp}"), "/contributions", "/item/openmanuals-9f86d081884c7d65-01arz3ndektsv4rrffq69g5fav", "/contribute", "/contribute?brand=JVC", "/manuals?brand=JVC&all=1", "/static/theme.js", "/static/style.css"] {
        let r = client.get(format!("{base}{path}")).send().await.unwrap();
        let status = r.status();
        let body = r.text().await.unwrap();
        assert!(status.is_success() || status.is_redirection(), "{path}: {status} {body}");
    }
    let html = client.get(format!("{base}/manual/{MANUAL}")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("Download from archive.org"), "{html}");
    assert!(html.contains("Alice"));

    // Sites: the home page's site names list what was preserved from each site.
    let page = |path: String| {
        let client = client.clone();
        async move { client.get(path).send().await.unwrap().text().await.unwrap() }
    };
    let html = page(format!("{base}/")).await;
    assert!(html.contains(r#"<a href="/manuals?site=manualslib" title="Manuals preserved from ManualsLib">ManualsLib</a>"#), "{html}");
    let html = page(format!("{base}/manuals?site=manualslib")).await;
    assert!(html.contains("<h1>Manuals from ManualsLib</h1>") && html.contains(&format!("/manual/{MANUAL}")), "{html}");
    assert!(!html.contains("still need"), "nothing left to preserve there");
    let html = page(format!("{base}/manuals?site=manualslib&brand=jvc&doc_type=service")).await;
    assert!(html.contains("<h1>JVC service manuals from ManualsLib</h1>"), "{html}");
    let html = page(format!("{base}/manuals?site=manualzz")).await;
    assert!(html.contains("<h1>Manuals from Manualzz</h1>") && !html.contains(&format!("/manual/{MANUAL}")), "{html}");
    let html = page(format!("{base}/manuals?site=nowhere")).await;
    assert!(html.contains("<h1>All manuals</h1>"), "an unknown site is ignored: {html}");
    // The contribute page picks by site too; with none missing it says so.
    let html = page(format!("{base}/contribute")).await;
    assert!(html.contains(r#"<select id="site" name="site">"#) && html.contains(r#"<option value="manualzz" disabled>Manualzz (0)</option>"#), "{html}");
    let r = client.get(format!("{base}/contribute/random?site=manualzz")).send().await.unwrap();
    assert!(r.url().as_str().ends_with("/contribute?none=1&site=manualzz"), "{}", r.url());
    let html = r.text().await.unwrap();
    assert!(html.contains("No manuals on Manualzz are missing right now. Try another site.") && html.contains(r#"<option value="manualzz" selected>"#), "{html}");

    // The ledger browser: newest first, retractions struck through, pending
    // facts marked, filters, and one page per fact.
    let product = signed(&alice, "product", json!({"brand": "JVC", "model": "AV-2168TEE"}));
    let product_id = Fact::from_json(&product.to_string()).unwrap().id().unwrap();
    let r = client.post(format!("{base}/api/facts")).json(&json!([signed(&alice, "retract", json!({"fact": product_id}))])).send().await.unwrap();
    assert_eq!(r.status(), 202);
    let get = |path: String| {
        let client = client.clone();
        async move {
            let r = client.get(path).send().await.unwrap();
            assert!(r.status().is_success(), "{}", r.status());
            r.text().await.unwrap()
        }
    };
    let html = get(format!("{base}/ledger")).await;
    let at = |needle: &str| html.find(needle).unwrap_or_else(|| panic!("{needle} missing: {html}"));
    assert!(at("Retracted fact") < at("Verified a copy at archive.org"), "newest first");
    assert!(at("Verified a copy at archive.org") < at("Added the manual"));
    assert!(html.contains("pill-pending"), "the retraction is not folded yet");
    assert!(html.contains("is-retracted"), "the retracted product row is struck through");
    assert!(html.contains("Alice") && html.contains("OpenManuals server"));
    assert!(html.contains(&format!("manual&#x2f;{MANUAL}")), "links to the manual");
    let html = get(format!("{base}/ledger?type=verified")).await;
    assert!(html.contains("Verified a copy") && !html.contains("Added the manual"));
    let html = get(format!("{base}/ledger?author={fp}")).await;
    assert!(html.contains("Added the manual") && !html.contains("Verified a copy"));
    let html = get(format!("{base}/fact/{loc_id}")).await;
    assert!(html.contains("valid ✓") && html.contains("Alice") && html.contains("ledger&#x2f;"), "{html}");
    let html = get(format!("{base}/")).await;
    assert!(html.contains("Latest activity") && html.contains("Retracted fact"));
    let r = client.get(format!("{base}/fact/sha256:{}", "0".repeat(64))).send().await.unwrap();
    assert_eq!(r.status(), 404);
}
