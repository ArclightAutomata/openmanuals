//! Push the outbox, pull the feed into a local ledger copy, or fetch the snapshot.

use crate::{outbox, Home};
use anyhow::{bail, Context, Result};
use openmanuals_core::Fact;
use openmanuals_ledger::ledger::Entry;
use serde_json::Value;

pub async fn run(home: &Home, server: &str, push_only: bool, snapshot_threshold: usize) -> Result<()> {
    let client = reqwest::Client::builder().user_agent(format!("openmanuals-cli/{}", env!("CARGO_PKG_VERSION"))).build()?;
    let server = server.trim_end_matches('/');

    // Push.
    for path in outbox::pending(home)? {
        let text = std::fs::read_to_string(&path)?;
        let facts: Vec<Value> = text.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str::<Fact>(l).map(|f| serde_json::from_str(&f.to_json()).unwrap())).collect::<Result<_, _>>()?;
        let mut all_ok = true;
        for chunk in facts.chunks(500) {
            let r = client.post(format!("{server}/api/facts")).json(&chunk).send().await.context("posting facts")?;
            let status = r.status();
            let v: Value = r.json().await.unwrap_or(Value::Null);
            if status.as_u16() == 429 {
                bail!("rate limited by {server}; try again later");
            }
            if !status.is_success() && status.as_u16() != 202 {
                bail!("server answered {status}: {v}");
            }
            let rejected = v["rejected"].as_array().map(|a| a.len()).unwrap_or(0);
            eprintln!("{}: accepted {} duplicate {} rejected {}", path.file_name().unwrap().to_string_lossy(), v["accepted"].as_array().map(|a| a.len()).unwrap_or(0), v["duplicate"].as_array().map(|a| a.len()).unwrap_or(0), rejected);
            for r in v["rejected"].as_array().cloned().unwrap_or_default() {
                eprintln!("  rejected #{}: {}", r["index"], r["error"]);
            }
            if rejected == chunk.len() {
                all_ok = false;
            }
        }
        if all_ok {
            std::fs::rename(&path, home.dir.join("sent").join(path.file_name().unwrap()))?;
        }
    }
    if push_only {
        return Ok(());
    }

    // Pull: feed since our cursor into <home>/ledger, or the snapshot when far behind.
    let ledger = openmanuals_ledger::Ledger::open(home.dir.join("ledger"))?;
    let mut since = ledger.head()?;
    let mut pulled = 0usize;
    loop {
        let mut url = format!("{server}/api/feed?limit=1000");
        if let Some(s) = &since {
            url.push_str(&format!("&since={s}"));
        }
        let v: Value = client.get(&url).send().await?.error_for_status()?.json().await?;
        let items = v["facts"].as_array().cloned().unwrap_or_default();
        if items.is_empty() {
            break;
        }
        let mut entries = Vec::with_capacity(items.len());
        for it in &items {
            let fact: Fact = serde_json::from_value(it["fact"].clone())?;
            fact.verify()?;
            entries.push(Entry { cursor: it["cursor"].as_str().unwrap_or_default().to_string(), id: it["id"].as_str().unwrap_or_default().to_string(), fact });
        }
        ledger.append(&entries)?;
        pulled += entries.len();
        since = entries.last().map(|e| e.cursor.clone());
        if v["more"].as_bool() != Some(true) {
            break;
        }
        if pulled >= snapshot_threshold && since.is_some() {
            eprintln!("more than {snapshot_threshold} facts behind; fetching the snapshot instead");
            break;
        }
    }
    eprintln!("pulled {pulled} facts into {}", ledger.root().display());
    update_snapshot(&client, server, home).await?;
    Ok(())
}

fn local_head(db: &std::path::Path) -> Option<String> {
    let conn = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    conn.query_row("SELECT value FROM meta WHERE key = 'head'", [], |r| r.get(0)).ok()
}

/// The server's signing key, pinned on first use per server URL.
async fn server_key(client: &reqwest::Client, server: &str, home: &Home) -> Result<openmanuals_core::PublicKey> {
    let info: Value = client.get(format!("{server}/api/server")).send().await?.error_for_status()?.json().await?;
    let key = openmanuals_core::PublicKey::from_jwk(&info["server_key"]).map_err(|e| anyhow::anyhow!("server key: {e}"))?;
    let fp = key.fingerprint();
    let pins_path = home.dir.join("servers.json");
    let mut pins: serde_json::Map<String, Value> = std::fs::read(&pins_path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    match pins.get(server).and_then(Value::as_str) {
        Some(pinned) if pinned != fp => bail!("{server} now signs with key {fp}, but {pinned} was pinned in {}; remove it there if the change is expected", pins_path.display()),
        Some(_) => {}
        None => {
            pins.insert(server.to_string(), Value::String(fp.clone()));
            std::fs::write(&pins_path, serde_json::to_vec_pretty(&pins)?)?;
            eprintln!("pinned {server} server key {fp}");
        }
    }
    Ok(key)
}

async fn get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    Ok(client.get(url).send().await?.error_for_status()?.bytes().await?.to_vec())
}

/// Bring `<home>/manuals.db` up to the server's latest snapshot: apply the
/// published diffs when that's smaller than a full download, otherwise fetch
/// the compressed snapshot. Everything is checked against the signed manifest.
async fn update_snapshot(client: &reqwest::Client, server: &str, home: &Home) -> Result<()> {
    use base64::Engine;
    use openmanuals_ledger::snapshot;
    let out = home.dir.join("manuals.db");
    let m = client.get(format!("{server}/db/manifest.json")).send().await?;
    if m.status() == reqwest::StatusCode::NOT_FOUND {
        return legacy_snapshot(client, server, home).await;
    }
    let bytes = m.error_for_status()?.bytes().await?.to_vec();
    let key = server_key(client, server, home).await?;
    let sig_txt = client.get(format!("{server}/db/manifest.json.sig")).send().await?.error_for_status()?.text().await?;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_txt.trim()).context("manifest signature")?;
    key.verify_raw(openmanuals_core::canon::sha256_hex(&bytes).as_bytes(), &sig).map_err(|e| anyhow::anyhow!("manifest signature: {e}"))?;
    let manifest: Value = serde_json::from_slice(&bytes)?;
    let latest = &manifest["latest"];
    let cursor = latest["version"].as_str().context("manifest without latest")?.to_string();
    let want_tables: std::collections::BTreeMap<String, String> = serde_json::from_value(latest["tables"].clone())?;

    // Our version is computed from our copy's content, so a stale or damaged
    // copy never passes for current.
    let have = local_head(&out).and_then(|h| snapshot::content_hashes(&out).ok().map(|t| snapshot::version(&h, &t)));
    if have.as_deref() == Some(cursor.as_str()) {
        eprintln!("snapshot is current ({cursor})");
        return Ok(());
    }
    let zst_size = latest["zst"]["size"].as_u64().unwrap_or(u64::MAX);

    // Try the diff chain from our cursor.
    if let Some(mut at) = have.clone() {
        let diffs = manifest["diffs"].as_array().cloned().unwrap_or_default();
        let mut chain = Vec::new();
        let mut total = 0u64;
        while at != cursor {
            let Some(d) = diffs.iter().find(|d| d["from"].as_str() == Some(at.as_str())) else { break };
            total += d["size"].as_u64().unwrap_or(u64::MAX / 2);
            at = d["to"].as_str().unwrap_or_default().to_string();
            chain.push(d.clone());
        }
        if at == cursor && total < zst_size {
            let tmp = home.dir.join("manuals.db.sync");
            std::fs::copy(&out, &tmp)?;
            let applied: Result<()> = async {
                let mut conn = rusqlite::Connection::open(&tmp)?;
                for d in &chain {
                    let file = d["file"].as_str().context("diff file")?;
                    let z = get_bytes(client, &format!("{server}/db/{file}")).await?;
                    if openmanuals_core::canon::sha256_hex(&z) != d["sha256"].as_str().unwrap_or_default() {
                        bail!("diff {file} checksum mismatch");
                    }
                    snapshot::apply_diff(&mut conn, snapshot::decompress_reader(&z[..])?)?;
                }
                drop(conn);
                if snapshot::content_hashes(&tmp)? != want_tables {
                    bail!("tables differ from the manifest after applying diffs");
                }
                Ok(())
            }
            .await;
            match applied {
                Ok(()) => {
                    std::fs::rename(&tmp, &out)?;
                    eprintln!("snapshot updated to {cursor} with {} diff(s), {total} bytes", chain.len());
                    return Ok(());
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    eprintln!("diffs did not apply ({e:#}); downloading the full snapshot");
                }
            }
        }
    }

    let file = latest["zst"]["file"].as_str().context("manifest without zst")?;
    let z = get_bytes(client, &format!("{server}/db/{file}")).await?;
    if openmanuals_core::canon::sha256_hex(&z) != latest["zst"]["sha256"].as_str().unwrap_or_default() {
        bail!("compressed snapshot checksum mismatch");
    }
    let tmp = home.dir.join("manuals.db.download");
    {
        let mut f = std::fs::File::create(&tmp)?;
        std::io::copy(&mut snapshot::decompress_reader(&z[..])?, &mut f)?;
    }
    let (sha, size) = snapshot::file_sha256(&tmp)?;
    if Some(sha.as_str()) != latest["sha256"].as_str() {
        let _ = std::fs::remove_file(&tmp);
        bail!("snapshot checksum mismatch after decompression");
    }
    std::fs::rename(&tmp, &out)?;
    eprintln!("snapshot {cursor} saved to {} ({size} bytes; downloaded {} compressed)", out.display(), z.len());
    Ok(())
}

/// Servers without a manifest: the uncompressed snapshot and its sha256.
async fn legacy_snapshot(client: &reqwest::Client, server: &str, home: &Home) -> Result<()> {
    let snap = client.get(format!("{server}/db/latest.db")).send().await?;
    if snap.status().is_success() {
        let bytes = snap.bytes().await?;
        let sha_line = client.get(format!("{server}/db/latest.db.sha256")).send().await?.text().await.unwrap_or_default();
        let sha = openmanuals_core::canon::sha256_hex(&bytes);
        if !sha_line.starts_with(&sha) {
            bail!("snapshot checksum mismatch");
        }
        let out = home.dir.join("manuals.db");
        std::fs::write(&out, &bytes)?;
        eprintln!("snapshot saved to {} ({} bytes, sha256 {sha})", out.display(), bytes.len());
    }
    Ok(())
}
