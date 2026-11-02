//! `PUT /api/avatar/<sha256>` and `GET /avatar/<fp>`: avatar images outside the ledger.
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_server::{avatar, router, Paths, State};
use serde_json::{json, Value};

fn png(w: u32, h: u32, pad: usize) -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    b.extend_from_slice(&[8, 6, 0, 0, 0]);
    b.resize(b.len() + pad, 0);
    b
}

fn fact(key: &SigningKey, t: &str, body: Value) -> Fact {
    let mut f = Fact::new(t, "x", "2026-10-31T12:00:00Z", body);
    key.sign_fact(&mut f).unwrap();
    f
}

#[tokio::test]
async fn avatar_upload_and_serving() {
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
    let st = state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let c = reqwest::Client::new();

    let alice = SigningKey::generate(Alg::Ed25519);
    let fp = alice.public_key().fingerprint();
    let img = png(256, 256, 300);
    let sha = openmanuals_core::canon::sha256_hex(&img);
    let put = |sha: &str, bytes: Vec<u8>| c.put(format!("{base}/api/avatar/{sha}")).body(bytes).send();

    assert_eq!(c.get(format!("{base}/avatar/{fp}")).send().await.unwrap().status(), 404, "no avatar yet");
    assert_eq!(put(&sha, img.clone()).await.unwrap().status(), 409, "no fact names it: not free hosting");
    assert_eq!(put("NOT-A-HASH", img.clone()).await.unwrap().status(), 400);

    // A malformed avatar fact is refused at the door.
    let bad = fact(&alice, "avatar", json!({"url": "http://insecure.example/a.png"}));
    let r: Value = c.post(format!("{base}/api/facts")).json(&json!([bad])).send().await.unwrap().json().await.unwrap();
    assert!(r["rejected"][0]["error"].as_str().unwrap().contains("https"), "{r}");
    // Post the fact, then the bytes.
    let f1 = fact(&alice, "avatar", json!({"sha256": sha, "size": img.len(), "mime": "image/png"}));
    let r = c.post(format!("{base}/api/facts")).json(&json!([f1])).send().await.unwrap();
    assert_eq!(r.status(), 202);
    assert_eq!(put(&sha, b"something else".to_vec()).await.unwrap().status(), 400, "bytes must hash to the URL");
    assert_eq!(put(&sha, vec![0u8; avatar_max() + 1]).await.unwrap().status(), 413);
    let r = put(&sha, img.clone()).await.unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    let r = c.get(format!("{base}/avatar/{}", fp.to_lowercase())).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    assert_eq!(h["content-type"], "image/png");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert!(h["content-security-policy"].to_str().unwrap().contains("default-src 'none'"));
    assert_eq!(h["etag"].to_str().unwrap(), format!("\"{sha}\""));
    assert_eq!(h["cache-control"], "public, max-age=300");
    assert_eq!(r.bytes().await.unwrap().to_vec(), img);
    let r = c.get(format!("{base}/avatar/{fp}?v={}", &sha[..16])).header("if-none-match", format!("\"{sha}\"")).send().await.unwrap();
    assert_eq!(r.status(), 304);
    assert!(r.headers()["cache-control"].to_str().unwrap().contains("immutable"));

    // The pages show it instead of the identicon (they need a snapshot).
    openmanuals_server::fold::fold_and_build(st.clone()).await.unwrap();
    let page = c.get(format!("{base}/ledger")).send().await.unwrap().text().await.unwrap();
    assert!(page.contains(&format!("/avatar/{fp}?v={}", &sha[..16])), "ledger rows use the avatar");
    let key_page = c.get(format!("{base}/k/{fp}")).send().await.unwrap().text().await.unwrap();
    assert!(key_page.contains(&format!("/avatar/{fp}?v=")), "the key page too");
    assert!(!key_page.contains("keyoxide.org/aspe:"), "no Keyoxide link for a .test domain");

    // A newer avatar: the old picture is collected once the refresh runs.
    let img2 = png(128, 128, 10);
    let sha2 = openmanuals_core::canon::sha256_hex(&img2);
    let f2 = fact(&alice, "avatar", json!({"sha256": sha2, "size": img2.len(), "mime": "image/png"}));
    assert_eq!(c.post(format!("{base}/api/facts")).json(&json!([f2])).send().await.unwrap().status(), 202);
    assert_eq!(put(&sha, img.clone()).await.unwrap().status(), 409, "the old image is no longer current");
    assert_eq!(put(&sha2, img2.clone()).await.unwrap().status(), 200);
    avatar::refresh(st.clone()).await.unwrap();
    assert_eq!(st.avatars.blob_count().unwrap(), 1, "older picture removed");
    assert_eq!(c.get(format!("{base}/avatar/{fp}")).send().await.unwrap().bytes().await.unwrap().to_vec(), img2);

    // A moderator blocks the fact: back to the identicon, and the image goes.
    let id2 = f2_id(&f2);
    let block = fact(&moderator, "block", json!({"kind": "fact", "value": id2, "reason": "abuse"}));
    assert_eq!(c.post(format!("{base}/api/facts")).json(&json!([block])).send().await.unwrap().status(), 202);
    avatar::refresh(st.clone()).await.unwrap();
    assert_eq!(c.get(format!("{base}/avatar/{fp}")).send().await.unwrap().status(), 404, "the previous fact's image was collected earlier");
    assert_eq!(st.avatars.blob_count().unwrap(), 0);
}

fn avatar_max() -> usize {
    openmanuals_core::avatar::MAX_BYTES as usize
}

fn f2_id(f: &Fact) -> String {
    f.id().unwrap()
}
