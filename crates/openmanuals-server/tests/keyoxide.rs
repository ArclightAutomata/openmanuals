//! Linking an OpenManuals key from an existing Keyoxide identity: the proof
//! (the key's signed profile claims) served as ASPE, as an ActivityStreams
//! Person at /k/<fp>, and as JSON at /api/key/<fp>; moderation hides it.
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_server::{fold, router, Paths, State};
use serde_json::{json, Value};

fn signed(key: &SigningKey, t: &str, body: Value) -> Value {
    let mut f = Fact::new(t, "x", "2026-10-23T18:00:00Z", body);
    key.sign_fact(&mut f).unwrap();
    serde_json::from_str(&f.to_json()).unwrap()
}

const EXTERNAL: &str = "aspe:keyoxide.org:6WJK26YKF6WUVPIZTS2I2BIT64";
const PGP: &str = "openpgp4fpr:3637202523E7C1309AB79E99EF2DC5827B445F4B";
const GIST: &str = "https://gist.github.com/alice/1";

#[tokio::test]
async fn keyoxide_service_provider() {
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
        public_url: "https://openmanuals.test".into(),
        doip_script: None,
        no_checkpoint: false,
        keep_snapshots: 3,
        keep_diffs_days: 30,
        malwarebazaar_key: None,
    };
    let state = State::new(paths).unwrap();
    let moderator = SigningKey::generate(Alg::Ed25519);
    state.trust.write().unwrap().moderators.insert(moderator.public_key().fingerprint());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let alice = SigningKey::generate(Alg::Ed25519);
    let fp = alice.public_key().fingerprint();
    let profile = alice.sign_profile("Alice", &[GIST.into(), EXTERNAL.into(), PGP.into()], Some("Fixes old TVs"));
    // The server's verifier confirmed the reverse direction for one of them.
    let link = state.server_fact("identity_link", json!({"key": fp, "claim_uri": EXTERNAL, "service": "aspe", "handle": EXTERNAL, "checked_at": "2026-10-31T00:00:00Z"})).unwrap();
    let batch = json!([signed(&alice, "identity_profile", json!({"jws": profile})), serde_json::from_str::<Value>(&link.to_json()).unwrap()]);
    assert_eq!(client.post(format!("{base}/api/facts")).json(&batch).send().await.unwrap().status(), 202);
    fold::fold_and_build(state.clone()).await.unwrap();

    // JSON for a dedicated doipjs provider; fingerprints are case-insensitive.
    let r = client.get(format!("{base}/api/key/{}", fp.to_lowercase())).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["fingerprint"], fp);
    assert_eq!(v["name"], "Alice");
    assert_eq!(v["aspe"], format!("aspe:openmanuals.test:{fp}"));
    assert_eq!(v["url"], format!("https://openmanuals.test/k/{fp}"));
    assert_eq!(v["claims"], json!([GIST, EXTERNAL, PGP]));
    assert_eq!(v["identities"], json!([EXTERNAL, PGP]));
    assert_eq!(v["links"][0]["claim_uri"], EXTERNAL);
    assert_eq!(openmanuals_core::asp::parse_and_verify(v["profile"].as_str().unwrap()).unwrap().claims.len(), 3, "the signed profile rides along");

    // What doipjs's ActivityPub provider asks for (axios sends exactly this Accept).
    let r = client.get(format!("{base}/k/{fp}")).header("accept", "application/activity+json").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"].to_str().unwrap().starts_with("application/activity+json"));
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["type"], "Person");
    assert_eq!(v["id"], format!("https://openmanuals.test/k/{fp}"));
    assert_eq!(v["preferredUsername"], fp);
    assert_eq!(v["summary"], "Fixes old TVs");
    let values: Vec<&str> = v["attachment"].as_array().unwrap().iter().map(|a| a["value"].as_str().unwrap()).collect();
    assert_eq!(values, [GIST, EXTERNAL, PGP]);
    let r = client.get(format!("{base}/k/{fp}")).header("accept", "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"").send().await.unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["type"], "Person");

    // The HTML page shows the claimed identities and carries the Ariadne HTTP proof header.
    let r = client.get(format!("{base}/k/{fp}")).header("accept", "text/html").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["ariadne-identity-proof"], format!("aspe:openmanuals.test:{fp}"));
    let html = r.text().await.unwrap();
    assert!(html.contains("Keyoxide identities"), "{html}");
    assert!(html.contains(&format!("https:&#x2f;&#x2f;keyoxide.org&#x2f;{EXTERNAL}")), "{html}");
    assert!(html.contains("(not confirmed yet)"), "the OpenPGP claim has no identity_link: {html}");

    // NodeInfo names the service for doipjs.
    let v: Value = client.get(format!("{base}/.well-known/nodeinfo")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["links"][0]["href"], "https://openmanuals.test/nodeinfo/2.1");
    let v: Value = client.get(format!("{base}/nodeinfo/2.1")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["software"]["name"], "openmanuals");
    assert_eq!(v["usage"]["users"]["total"], 1);

    // Unknown keys and keys without a profile: 404.
    let nobody = SigningKey::generate(Alg::Ed25519).public_key().fingerprint();
    assert_eq!(client.get(format!("{base}/api/key/{nobody}")).send().await.unwrap().status(), 404);
    assert_eq!(client.get(format!("{base}/api/key/not-a-key")).send().await.unwrap().status(), 404);
    assert_eq!(client.get(format!("{base}/k/{nobody}")).header("accept", "application/activity+json").send().await.unwrap().status(), 404);

    // A moderator blocks the key: ASPE stops at once, the rest after the fold.
    let block = signed(&moderator, "block", json!({"kind": "key", "value": fp, "reason": "spam"}));
    assert_eq!(client.post(format!("{base}/api/facts")).json(&json!([block])).send().await.unwrap().status(), 202);
    assert_eq!(client.get(format!("{base}/.well-known/aspe/id/{fp}")).send().await.unwrap().status(), 404);
    fold::fold_and_build(state.clone()).await.unwrap();
    assert_eq!(client.get(format!("{base}/api/key/{fp}")).send().await.unwrap().status(), 404);
    assert_eq!(client.get(format!("{base}/k/{fp}")).header("accept", "application/activity+json").send().await.unwrap().status(), 404);
}
