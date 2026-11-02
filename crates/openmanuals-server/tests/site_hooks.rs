//! The page hooks the extension reads (`data-om-*`) and `GET /api/fact/{id}`.
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_server::{router, Paths, State};
use serde_json::{json, Value};

fn fact(key: &SigningKey, t: &str, body: Value) -> Fact {
    let mut f = Fact::new(t, "x", "2026-10-31T12:00:00Z", body);
    key.sign_fact(&mut f).unwrap();
    f
}

#[tokio::test]
async fn pages_carry_hooks_and_facts_are_served_as_json() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let server = SigningKey::generate(Alg::Ed25519);
    std::fs::write(data.join("server.key"), server.to_openssh("test server").unwrap()).unwrap();
    let paths = Paths {
        data_dir: data.clone(),
        ledger_dir: dir.path().join("ledger"),
        key: None,
        trust: None,
        domain: "openmanuals.test".into(),
        public_url: "https://openmanuals.test".into(),
        doip_script: None,
        no_checkpoint: false,
        keep_snapshots: 3,
        keep_diffs_days: 30,
        malwarebazaar_key: None,
    };
    let state = State::new(paths).unwrap();
    let st = state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let c = reqwest::Client::new();

    let alice = SigningKey::generate(Alg::Ed25519);
    let fp = alice.public_key().fingerprint();
    let sha = "ab".repeat(32);
    let manual = "01M69JSKVAY3Z9RCYD22GCY64Q";
    let product = fact(&alice, "product", json!({"brand": "Acme", "model": "X1"}));
    let loc = fact(&alice, "location", json!({"file": sha, "url": "https://example.org/x1.pdf", "kind": "mirror"}));
    let facts = vec![
        fact(&alice, "manual", json!({"id": manual, "title": "Acme X1 manual", "doc_type": "user"})),
        product.clone(),
        fact(&alice, "file", json!({"sha256": sha, "sha1": "cd".repeat(20), "md5": "ef".repeat(16), "size": 1000, "mime": "application/pdf"})),
        fact(&alice, "manual_file", json!({"manual": manual, "file": sha, "role": "primary"})),
        loc.clone(),
    ];
    let r = c.post(format!("{base}/api/facts")).json(&facts).send().await.unwrap();
    assert_eq!(r.status(), 202, "{}", r.text().await.unwrap());
    let loc_id = loc.id().unwrap();
    // The server's own verdict makes the copy linkable.
    let verified = fact(&server, "verified", json!({
        "location": loc_id, "final_url": "https://example.org/x1.pdf", "sha256": sha, "size": 1000,
        "checked_at": "2026-10-31T12:00:00Z", "file_type": "pdf", "scan": {"tool": "om-scan/2", "active": []},
    }));
    assert_eq!(c.post(format!("{base}/api/facts")).json(&json!([verified])).send().await.unwrap().status(), 202);
    let product_id = product.id().unwrap();
    let retract = fact(&alice, "retract", json!({"fact": product_id}));
    assert_eq!(c.post(format!("{base}/api/facts")).json(&json!([retract])).send().await.unwrap().status(), 202);
    openmanuals_server::fold::fold_and_build(st.clone()).await.unwrap();

    let page = |p: String| { let c = c.clone(); async move { c.get(p).send().await.unwrap().text().await.unwrap() } };
    let ledger = page(format!("{base}/ledger")).await;
    let hook = format!(r#"data-om-fact="{product_id}" data-om-author="{fp}" data-om-type="product" data-om-retracted"#);
    assert!(ledger.contains(&hook), "retracted fact row is hooked and marked:\n{ledger}");
    assert!(ledger.contains(&format!(r#"data-om-fact="{loc_id}" data-om-author="{fp}" data-om-type="location">"#)), "live fact row is not marked retracted");
    assert!(ledger.contains(r#"<span class="om-actions"></span>"#));
    assert!(ledger.contains(r#"class="om-ext-hint""#));

    let fact_page = page(format!("{base}/fact/{product_id}")).await;
    assert!(fact_page.contains(&format!(r#"data-om-fact="{product_id}""#)) && fact_page.contains("data-om-retracted"));
    assert!(fact_page.contains(r#"class="pill pill-muted">retracted"#));

    let manual_page = page(format!("{base}/manual/{manual}")).await;
    assert!(manual_page.contains(&format!(r#"<section class="file" data-om-file="{sha}">"#)), "{manual_page}");
    assert!(manual_page.contains(&format!(r#"data-om-location="{loc_id}" data-om-file="{sha}" data-om-author="{fp}""#)), "{manual_page}");
    let file_page = page(format!("{base}/file/{sha}")).await;
    assert!(file_page.contains(&format!(r#"data-om-file="{sha}""#)) && file_page.contains(&format!(r#"data-om-location="{loc_id}""#)));

    // The JSON a confirmation window reads.
    let j: Value = c.get(format!("{base}/api/fact/{product_id}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(j["id"], product_id.as_str());
    assert_eq!(j["retracted"], true);
    assert_eq!(j["hidden"], false);
    let back = Fact::from_json(&j["fact"].to_string()).unwrap();
    assert_eq!(back.id().unwrap(), product_id, "the served fact hashes to its id");
    back.verify().unwrap();
    let j: Value = c.get(format!("{base}/api/fact/{}", &loc_id[7..])).send().await.unwrap().json().await.unwrap();
    assert_eq!(j["retracted"], false, "the bare hex id works too");
    assert_eq!(c.get(format!("{base}/api/fact/sha256:{}", "0".repeat(64))).send().await.unwrap().status(), 404);
    assert_eq!(c.get(format!("{base}/api/fact/nope")).send().await.unwrap().status(), 400);
}
