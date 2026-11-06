//! Editing a manual from the extension: `GET /api/manual/{id}/facts`, the
//! manual page's edit hooks and brand links, and an edit (a newer `manual`
//! fact, a retracted `covers`, a new product) showing up after the build.
use openmanuals_core::{product::product_key, sign::SigningKey, Alg, Fact};
use openmanuals_server::{router, Paths, State};
use serde_json::{json, Value};

fn fact(key: &SigningKey, t: &str, at: &str, body: Value) -> Fact {
    let mut f = Fact::new(t, "x", at, body);
    key.sign_fact(&mut f).unwrap();
    f
}

#[tokio::test]
async fn manual_facts_hooks_and_an_edit() {
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
    let post = |facts: Vec<Fact>| {
        let c = c.clone();
        let base = base.clone();
        async move {
            let r = c.post(format!("{base}/api/facts")).json(&facts).send().await.unwrap();
            assert_eq!(r.status(), 202, "{}", r.text().await.unwrap());
        }
    };
    let get = |p: String| {
        let c = c.clone();
        async move { c.get(p).send().await.unwrap() }
    };

    let alice = SigningKey::generate(Alg::Ed25519);
    let bob = SigningKey::generate(Alg::Ed25519);
    let manual = "01M69JSKVAY3Z9RCYD22GCY64Q";
    let other = "01M69JSKVAY3Z9RCYD22GCY64R";
    let t0 = "2026-11-05T12:00:00Z";
    let wrong = product_key("Philips", "14PV1OO").unwrap();
    let kept = product_key("Philips", "21PT1354").unwrap();
    let man = fact(&alice, "manual", t0, json!({"id": manual, "title": "Philips 14PV1OO service manual", "doc_type": "user"}));
    let covers_wrong = fact(&alice, "covers", t0, json!({"manual": manual, "product": wrong}));
    let covers_kept = fact(&bob, "covers", t0, json!({"manual": manual, "product": kept}));
    post(vec![
        man.clone(),
        fact(&alice, "product", t0, json!({"brand": "Philips", "model": "14PV1OO"})),
        fact(&bob, "product", t0, json!({"brand": "Philips", "model": "21PT1354"})),
        covers_wrong.clone(),
        covers_kept.clone(),
        // Another manual's facts stay out of this one's answer.
        fact(&alice, "manual", t0, json!({"id": other, "title": "Something else", "doc_type": "user"})),
        fact(&alice, "covers", t0, json!({"manual": other, "product": wrong})),
    ])
    .await;

    // Before any build: the facts are already there (unfolded); no product names yet.
    let v: Value = get(format!("{base}/api/manual/{}/facts", manual.to_lowercase())).await.json().await.unwrap();
    assert_eq!(v["manual"], manual);
    let ids: Vec<&str> = v["facts"].as_array().unwrap().iter().map(|f| f["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [man.id().unwrap(), covers_wrong.id().unwrap(), covers_kept.id().unwrap()]);
    assert!(v["facts"].as_array().unwrap().iter().all(|f| f["folded"] == false && f["hidden"] == false && f["retracted"] == false));
    assert_eq!(v["facts"][1]["fact"], serde_json::to_value(&covers_wrong).unwrap(), "the fact itself, as signed");
    assert_eq!(v["products"], json!({}));
    assert_eq!(get(format!("{base}/api/manual/not-a-ulid/facts")).await.status(), 400);

    openmanuals_server::fold::fold_and_build(st.clone()).await.unwrap();
    let v: Value = get(format!("{base}/api/manual/{manual}/facts")).await.json().await.unwrap();
    assert_eq!(v["products"][&wrong], json!({"brand": "Philips", "model": "14PV1OO"}));
    assert_eq!(v["products"][&kept], json!({"brand": "Philips", "model": "21PT1354"}));
    assert!(v["facts"].as_array().unwrap().iter().all(|f| f["folded"] == true));

    let page = get(format!("{base}/manual/{manual}")).await.text().await.unwrap();
    assert!(page.contains(&format!(r#"<h1 data-om-manual="{manual}" data-om-edit="title">Philips 14PV1OO service manual<span class="om-actions"></span></h1>"#)), "{page}");
    assert!(page.contains(&format!(r#"data-om-manual="{manual}" data-om-edit="product:{wrong}""#)), "{page}");
    assert!(page.contains(r#"<a class="product-brand" href="/manuals?brand=philips" title="All Philips manuals">Philips</a>"#), "{page}");
    assert!(page.contains(r#"<a class="product-model" href="/product/Philips/21PT1354""#), "{page}");
    assert!(page.contains(&format!(r#"data-om-manual="{manual}" data-om-edit="add""#)));
    let product_page = get(format!("{base}/product/Philips/21PT1354")).await.text().await.unwrap();
    assert!(product_page.contains(r#"<a class="brand-link" href="/manuals?brand=philips" title="All Philips manuals">Philips</a> 21PT1354"#), "{product_page}");

    // The edit, as the extension signs it: a newer manual fact, alice's wrong
    // model retracted, the right model added.
    let t1 = "2026-11-05T12:05:00Z";
    let right = product_key("Philips", "14PV100").unwrap();
    post(vec![
        fact(&alice, "manual", t1, json!({"id": manual, "title": "Philips 14PV100 service manual", "doc_type": "service"})),
        fact(&alice, "retract", t1, json!({"fact": covers_wrong.id().unwrap()})),
        fact(&alice, "product", t1, json!({"brand": "Philips", "model": "14PV100"})),
        fact(&alice, "covers", t1, json!({"manual": manual, "product": right})),
        fact(&alice, "product", t1, json!({"brand": "Philips", "model": "14PV210/01"})),
        fact(&alice, "covers", t1, json!({"manual": manual, "product": product_key("Philips", "14PV210/01").unwrap()})),
    ])
    .await;
    let v: Value = get(format!("{base}/api/manual/{manual}/facts")).await.json().await.unwrap();
    let flags: Vec<(bool, bool)> = v["facts"].as_array().unwrap().iter().map(|f| (f["folded"].as_bool().unwrap(), f["retracted"].as_bool().unwrap())).collect();
    assert_eq!(flags, [(true, false), (true, true), (true, false), (false, false), (false, false), (false, false)], "the retraction counts before the build");

    openmanuals_server::fold::fold_and_build(st.clone()).await.unwrap();
    let page = get(format!("{base}/manual/{manual}")).await.text().await.unwrap();
    assert!(page.contains(">Philips 14PV100 service manual<"), "the newer title wins");
    assert!(page.contains(r#"<span class="doc-tag">Service manual</span>"#), "the type reads as a label");
    assert!(page.contains(r#"<a href="/manuals?brand=philips&doc_type=service">Service manuals</a>"#), "the crumb links to the brand's manuals of that type:\n{page}");
    let list = get(format!("{base}/manuals?brand=philips&doc_type=Service&all=1")).await.text().await.unwrap();
    assert!(list.contains("<h1>Philips service manuals</h1>") && list.contains(r#"<span class="doc-tag">Service manual</span>"#), "{list}");
    assert!(page.contains(">14PV100</a>") && page.contains(">21PT1354</a>"), "{page}");
    assert!(!page.contains(">14PV1OO</a>"), "the retracted model is gone:\n{page}");
    // A "/" in a model name stays inside its path segment.
    assert!(page.contains(r#"href="/product/Philips/14PV210%2F01""#), "{page}");
    let slashed = get(format!("{base}/product/Philips/14PV210%2F01")).await;
    assert_eq!(slashed.status(), 200);
    let body = slashed.text().await.unwrap();
    assert!(body.contains("Philips</a> 14PV210&#x2f;01</h1>"), "{body}");
}
