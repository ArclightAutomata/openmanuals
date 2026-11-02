//! A key a moderator blocked can't add facts; unblocking lets it again.
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_server::{router, Paths, State};
use serde_json::{json, Value};

fn fact(key: &SigningKey, t: &str, body: Value) -> Fact {
    let mut f = Fact::new(t, "x", &jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(), body);
    key.sign_fact(&mut f).unwrap();
    f
}

#[tokio::test]
async fn blocked_keys_are_refused_at_the_door() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("server.key"), SigningKey::generate(Alg::Ed25519).to_openssh("test server").unwrap()).unwrap();
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
    let moderator = SigningKey::generate(Alg::Ed25519);
    let mfp = moderator.public_key().fingerprint();
    state.trust.write().unwrap().moderators.insert(mfp.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let c = reqwest::Client::new();
    let post = |facts: Vec<Fact>| {
        let c = c.clone();
        let url = format!("{base}/api/facts");
        async move {
            let r = c.post(url).json(&facts).send().await.unwrap();
            (r.status().as_u16(), r.json::<Value>().await.unwrap())
        }
    };

    // The server says who its moderators are.
    let info: Value = c.get(format!("{base}/api/server")).send().await.unwrap().json().await.unwrap();
    assert_eq!(info["moderators"], json!([mfp]));

    let spammer = SigningKey::generate(Alg::Ed25519);
    let sfp = spammer.public_key().fingerprint();
    let bob = SigningKey::generate(Alg::Ed25519);
    let product = |k: &SigningKey, m: &str| fact(k, "product", json!({"brand": "Acme", "model": m}));

    assert_eq!(post(vec![product(&spammer, "S1")]).await.0, 202);

    // A block from someone who isn't a moderator changes nothing.
    assert_eq!(post(vec![fact(&bob, "block", json!({"kind": "key", "value": sfp, "reason": "spam"}))]).await.0, 202);
    assert_eq!(post(vec![product(&spammer, "S2")]).await.0, 202);

    // The moderator's block: the spammer's facts are refused, everyone else's still accepted.
    assert_eq!(post(vec![fact(&moderator, "block", json!({"kind": "key", "value": sfp, "reason": "spam"}))]).await.0, 202);
    let (status, body) = post(vec![product(&spammer, "S3")]).await;
    assert_eq!(status, 403, "{body}");
    assert!(body["rejected"][0]["error"].as_str().unwrap().contains("blocked"), "{body}");
    let (status, body) = post(vec![product(&bob, "B1"), product(&spammer, "S4")]).await;
    assert_eq!(status, 202, "a mixed batch keeps the good facts");
    assert_eq!(body["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(body["rejected"][0]["index"], 1);

    // Unblocked: accepted again.
    assert_eq!(post(vec![fact(&moderator, "unblock", json!({"kind": "key", "value": sfp, "reason": "mistake"}))]).await.0, 202);
    assert_eq!(post(vec![product(&spammer, "S5")]).await.0, 202);
}
