//! Facts posted to a running server show up in the snapshot shortly after,
//! without waiting for the fold interval, and pages switch to the new snapshot.
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_server::schedule::{self, Schedule};
use openmanuals_server::{router, Paths, State};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const MANUAL: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const PAGE: &str = "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html";

fn signed(key: &SigningKey, t: &str, body: Value) -> Value {
    let mut f = Fact::new(t, "x", "2026-10-23T18:00:00Z", body);
    key.sign_fact(&mut f).unwrap();
    serde_json::from_str(&f.to_json()).unwrap()
}

fn paths(dir: &std::path::Path) -> Paths {
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let server_key = SigningKey::generate(Alg::Ed25519);
    std::fs::write(data.join("server.key"), server_key.to_openssh("test server").unwrap()).unwrap();
    Paths {
        data_dir: data,
        ledger_dir: dir.join("ledger"),
        key: None,
        trust: None,
        domain: "openmanuals.test".into(),
        public_url: "http://test".into(),
        doip_script: None,
        no_checkpoint: false,
        keep_snapshots: 3,
        keep_diffs_days: 30,
        malwarebazaar_key: None,
    }
}

/// The ledger head of the published snapshot, from the signed manifest.
async fn head(client: &reqwest::Client, base: &str) -> Option<String> {
    let r = client.get(format!("{base}/db/manifest.json")).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    let m: Value = r.json().await.ok()?;
    m["latest"]["head"].as_str().map(String::from)
}

/// Poll until the published head is `want`; returns how long it took.
async fn wait_for_head(client: &reqwest::Client, base: &str, want: &str, limit: Duration) -> Duration {
    let t0 = Instant::now();
    loop {
        if head(client, base).await.as_deref() == Some(want) {
            return t0.elapsed();
        }
        assert!(t0.elapsed() < limit, "snapshot head did not reach {want} within {limit:?}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn posted_facts_are_folded_after_the_debounce() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::new(paths(dir.path())).unwrap();
    let debounce = Duration::from_millis(400);
    let max_delay = Duration::from_millis(1500);
    let sched = Schedule { debounce, max_delay, interval: Duration::ZERO, poll: Duration::from_millis(200) };
    schedule::spawn(state.clone(), sched);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    assert_eq!(head(&client, &base).await, None, "no snapshot yet");

    let alice = SigningKey::generate(Alg::Ed25519);
    let batch = json!([
        signed(&alice, "manual", json!({"id": MANUAL, "title": "JVC AV-2168TEE Service Manual", "doc_type": "service", "source": "manualslib", "source_id": "331384", "source_url": PAGE})),
        signed(&alice, "product", json!({"brand": "JVC", "model": "AV-2168TEE"})),
        signed(&alice, "covers", json!({"manual": MANUAL, "product": "jvc|AV2168TEE"})),
    ]);
    let posted = Instant::now();
    let v: Value = client.post(format!("{base}/api/facts")).json(&batch).send().await.unwrap().json().await.unwrap();
    let cursor = v["cursor"].as_str().unwrap().to_string();
    let took = wait_for_head(&client, &base, &cursor, Duration::from_secs(10)).await;
    assert!(posted.elapsed() >= debounce, "folded before the debounce elapsed ({took:?})");
    // Pages read the new snapshot (no restart, no stale pooled connection).
    let r = client.get(format!("{base}/manual/{MANUAL}")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = client.get(format!("{base}/api/lookup?url={PAGE}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["known"], true);
    let generation = state.readers.generation();

    // A steady trickle (a batch every ~200 ms, never 400 ms quiet) is still
    // folded within max_delay of its first batch, while it goes on.
    let first = Instant::now();
    let mut last_cursor = String::new();
    let mut folded_after = None;
    for i in 0..20 {
        let f = signed(&alice, "product", json!({"brand": "JVC", "model": format!("AV-{i}")}));
        let v: Value = client.post(format!("{base}/api/facts")).json(&json!([f])).send().await.unwrap().json().await.unwrap();
        last_cursor = v["cursor"].as_str().unwrap().to_string();
        if head(&client, &base).await.as_deref() != Some(cursor.as_str()) {
            folded_after = Some(first.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let t = folded_after.expect("trickle not folded while it went on");
    assert!(t >= max_delay && t < max_delay + Duration::from_secs(2), "trickle folded after {t:?}");
    wait_for_head(&client, &base, &last_cursor, Duration::from_secs(10)).await;
    assert!(state.readers.generation() > generation, "publishing invalidates pooled connections");

    // Facts written to the inbox by another process (`openmanuals-server import`)
    // are noticed by polling and folded too.
    let other = openmanuals_server::inbox::Inbox::open(&state.paths.inbox_path()).unwrap();
    let f: Fact = serde_json::from_value(signed(&alice, "product", json!({"brand": "JVC", "model": "AV-IMPORTED"}))).unwrap();
    let r = other.accept(&[f], |_| Ok(())).unwrap();
    let imported = r.cursor.unwrap();
    wait_for_head(&client, &base, &imported, Duration::from_secs(10)).await;
    assert!(state.inbox.unfolded().unwrap().is_empty());
}
