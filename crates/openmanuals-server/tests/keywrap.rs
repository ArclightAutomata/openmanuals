//! `/api/key-wrap`: passkey-wrapped key copies, signed by the key, outside the ledger.
use base64::Engine;
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_server::{keywrap, router, Paths, State};
use serde_json::{json, Value};

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn now() -> String {
    jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// A signed body as the extension sends it.
fn body(key: &SigningKey, method: &str, cred: &str, wrap: Option<&str>, at: &str) -> Value {
    let fp = key.public_key().fingerprint();
    let hash = wrap.map(|w| openmanuals_core::canon::sha256_hex(w.as_bytes())).unwrap_or_default();
    let sig = b64(&key.sign_raw(keywrap::message(method, &fp, cred, &hash, at).as_bytes()));
    let mut v = json!({"key": key.public_key().to_jwk(), "at": at, "sig": sig});
    if let Some(w) = wrap {
        v["wrap"] = json!(w);
    }
    v
}

#[tokio::test]
async fn key_wrap_endpoint() {
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
    state.trust.write().unwrap().moderators.insert(moderator.public_key().fingerprint());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let c = reqwest::Client::new();

    let alice = SigningKey::generate(Alg::Ed25519);
    let fp = alice.public_key().fingerprint();
    let cred = "Y3JlZGVudGlhbC1pZC0x";
    let url = format!("{base}/api/key-wrap/{fp}/{cred}");
    let wrap = r#"{"v":1,"iv":"AAAA","wrapped":"BBBB"}"#;

    // Nothing stored yet; CORS like the rest of /api.
    let r = c.get(format!("{base}/api/key-wrap/{}", fp.to_lowercase())).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
    assert_eq!(r.json::<Value>().await.unwrap()["wraps"], json!([]));
    assert_eq!(c.get(format!("{base}/api/key-wrap/nope")).send().await.unwrap().status(), 404);

    // A signature is required, and must be by the fingerprint's key, over this wrap.
    let mut unsigned = body(&alice, "PUT", cred, Some(wrap), &now());
    unsigned["sig"] = json!(b64(&[0u8; 64]));
    assert_eq!(c.put(&url).json(&unsigned).send().await.unwrap().status(), 401);
    assert_eq!(c.put(&url).json(&json!({"wrap": wrap})).send().await.unwrap().status(), 400);
    let mallory = SigningKey::generate(Alg::Ed25519);
    let mut wrong_key = body(&mallory, "PUT", cred, Some(wrap), &now());
    assert_eq!(c.put(&url).json(&wrong_key).send().await.unwrap().status(), 401, "another key's signature");
    wrong_key["key"] = alice.public_key().to_jwk();
    assert_eq!(c.put(&url).json(&wrong_key).send().await.unwrap().status(), 401, "alice's key, mallory's signature");
    let mut swapped = body(&alice, "PUT", cred, Some(wrap), &now());
    swapped["wrap"] = json!("something else");
    assert_eq!(c.put(&url).json(&swapped).send().await.unwrap().status(), 401, "the signature covers the wrap");
    let other_cred = body(&alice, "PUT", "b3RoZXItY3JlZGVudGlhbA", Some(wrap), &now());
    assert_eq!(c.put(&url).json(&other_cred).send().await.unwrap().status(), 401, "the signature covers the credential id");
    let stale = jiff::Timestamp::now().checked_sub(jiff::SignedDuration::from_secs(600)).unwrap().strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
    assert_eq!(c.put(&url).json(&body(&alice, "PUT", cred, Some(wrap), &stale)).send().await.unwrap().status(), 401, "outside the window");

    // Size limits.
    let big = "x".repeat(keywrap::MAX_WRAP + 1);
    assert_eq!(c.put(&url).json(&body(&alice, "PUT", cred, Some(&big), &now())).send().await.unwrap().status(), 413);
    let huge = json!({"pad": "x".repeat(keywrap::MAX_BODY)});
    assert_eq!(c.put(&url).json(&huge).send().await.unwrap().status(), 413);
    assert_eq!(c.put(format!("{base}/api/key-wrap/{fp}/short")).json(&body(&alice, "PUT", "short", Some(wrap), &now())).send().await.unwrap().status(), 400);

    // A good PUT; the same signed request again is a replay.
    let good = body(&alice, "PUT", cred, Some(wrap), &now());
    assert_eq!(c.put(&url).json(&good).send().await.unwrap().status(), 200);
    assert_eq!(c.put(&url).json(&good).send().await.unwrap().status(), 409);
    let v: Value = c.get(format!("{base}/api/key-wrap/{fp}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["fingerprint"], fp);
    assert_eq!(v["wraps"][0]["credential"], cred);
    assert_eq!(v["wraps"][0]["wrap"], wrap);

    // A second passkey.
    let cred2 = "c2Vjb25kLWNyZWRlbnRpYWw";
    let r = c.put(format!("{base}/api/key-wrap/{fp}/{cred2}")).json(&body(&alice, "PUT", cred2, Some(wrap), &now())).send().await.unwrap();
    assert_eq!(r.status(), 200);

    // DELETE needs its own signature: a PUT's doesn't do.
    assert_eq!(c.delete(&url).json(&good).send().await.unwrap().status(), 401);
    assert_eq!(c.delete(&url).json(&body(&mallory, "DELETE", cred, None, &now())).send().await.unwrap().status(), 401);
    let del = body(&alice, "DELETE", cred, None, &now());
    let r: Value = c.delete(&url).json(&del).send().await.unwrap().json().await.unwrap();
    assert_eq!(r["deleted"], true);
    assert_eq!(c.delete(&url).json(&del).send().await.unwrap().status(), 409, "replayed delete");
    let v: Value = c.get(format!("{base}/api/key-wrap/{fp}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["wraps"].as_array().unwrap().len(), 1);
    assert_eq!(v["wraps"][0]["credential"], cred2);

    // A blocked key can't store new copies, but can still read and delete its own.
    let mut block = Fact::new("block", "x", "2026-10-31T00:00:00Z", json!({"kind": "key", "value": fp, "reason": "spam"}));
    moderator.sign_fact(&mut block).unwrap();
    let r = c.post(format!("{base}/api/facts")).json(&json!([serde_json::from_str::<Value>(&block.to_json()).unwrap()])).send().await.unwrap();
    assert_eq!(r.status(), 202);
    assert_eq!(c.put(&url).json(&body(&alice, "PUT", cred, Some(wrap), &now())).send().await.unwrap().status(), 403);
    let v: Value = c.get(format!("{base}/api/key-wrap/{fp}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["wraps"].as_array().unwrap().len(), 1);
    let url2 = format!("{base}/api/key-wrap/{fp}/{cred2}");
    assert_eq!(c.delete(&url2).json(&body(&alice, "DELETE", cred2, None, &now())).send().await.unwrap().status(), 200);

    // Writes are budgeted per key and day.
    let bob = SigningKey::generate(Alg::Ed25519);
    let bob_fp = bob.public_key().fingerprint();
    let mut last = 0;
    // One base time, so a second boundary mid-loop can't repeat an `at` (a
    // repeated signature is refused as a replay and wouldn't count).
    let base_at = jiff::Timestamp::now();
    for i in 0..=keywrap::DAILY_WRITES {
        // Distinct `at` values make distinct signatures.
        let at = base_at.checked_sub(jiff::SignedDuration::from_secs(i as i64)).unwrap().strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
        last = c.put(format!("{base}/api/key-wrap/{bob_fp}/{cred}")).json(&body(&bob, "PUT", cred, Some(wrap), &at)).send().await.unwrap().status().as_u16();
    }
    assert_eq!(last, 429);
}
