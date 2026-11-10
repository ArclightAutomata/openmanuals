//! JSON API: facts inbox, feed, lookup, snapshot files, ASPE identity hosting.

use crate::config::{CachedQuery, Shared};
use crate::rate;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use openmanuals_core::{ids, Fact};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub const MAX_BATCH: usize = 500;
pub const MAX_BODY: usize = 4 * 1024 * 1024;

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

pub async fn post_facts(State(state): State<Shared>, body: axum::body::Bytes) -> Response {
    if body.len() > MAX_BODY {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "body exceeds 4 MiB");
    }
    let facts: Vec<Fact> = match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Array(items)) => {
            if items.len() > MAX_BATCH {
                return err(StatusCode::PAYLOAD_TOO_LARGE, format!("at most {MAX_BATCH} facts per request"));
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, v) in items.into_iter().enumerate() {
                match serde_json::from_value::<Fact>(v) {
                    Ok(f) => out.push(f),
                    Err(e) => return err(StatusCode::BAD_REQUEST, format!("fact {i}: {e}")),
                }
            }
            out
        }
        Ok(_) => return err(StatusCode::BAD_REQUEST, "body must be a JSON array of facts"),
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")),
    };
    let avatars_touched = facts.iter().any(|f| crate::avatar::affects_avatars(&f.r#type));
    let st = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        let db = st.reader();
        let trust = st.trust.read().unwrap().clone();
        // A key a moderator blocked can't add to the ledger (its earlier facts are already hidden).
        let blocked = st.inbox.blocked_keys(|a| trust.is_moderator(a))?;
        let mut limited = false;
        let mut refused = false;
        let r = st.inbox.accept(&facts, |f| {
            if f.r#type == "avatar" {
                openmanuals_core::avatar::parse(&f.body).map_err(|e| e.to_string())?;
            }
            if trust.is_server(&f.author) || trust.is_moderator(&f.author) {
                return Ok(());
            }
            if blocked.contains(&f.author) {
                refused = true;
                return Err(format!("key {} is blocked by a moderator", f.author));
            }
            let limit = rate::ingest_budget(rate::record(db.as_deref(), &f.author));
            if st.budgets.spend(&f.author, "ingest", 1, limit) {
                Ok(())
            } else {
                limited = true;
                Err(format!("daily ingestion budget of {limit} facts exhausted for {}", f.author))
            }
        });
        r.map(|r| (r, limited, refused))
    })
    .await;
    match result {
        Ok(Ok((r, limited, refused))) => {
            if !r.accepted.is_empty() {
                state.fold_trigger.poke();
                if avatars_touched {
                    // Fetch a URL avatar, drop pictures nothing uses, update what is served.
                    let st = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::avatar::refresh(st).await {
                            tracing::warn!(error = %e, "avatar refresh failed");
                        }
                    });
                }
            }
            if refused && r.accepted.is_empty() && r.duplicate.is_empty() {
                return (StatusCode::FORBIDDEN, Json(serde_json::to_value(&r).unwrap())).into_response();
            }
            if limited && r.accepted.is_empty() && r.duplicate.is_empty() {
                return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "3600")], Json(serde_json::to_value(&r).unwrap())).into_response();
            }
            (StatusCode::ACCEPTED, Json(serde_json::to_value(&r).unwrap())).into_response()
        }
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct FeedQuery {
    pub since: Option<String>,
    pub limit: Option<usize>,
}

pub async fn feed(State(state): State<Shared>, Query(q): Query<FeedQuery>) -> Response {
    if let Some(s) = &q.since {
        if !openmanuals_ledger::ledger::is_cursor(s) {
            return err(StatusCode::BAD_REQUEST, "since must be a cursor");
        }
    }
    let st = state.clone();
    let limit = q.limit.unwrap_or(200);
    let since = q.since.clone();
    match tokio::task::spawn_blocking(move || st.inbox.feed(since.as_deref(), limit)).await {
        Ok(Ok((items, more))) => {
            let next = items.last().map(|i| i.cursor.clone());
            Json(json!({"facts": items, "next": next, "more": more})).into_response()
        }
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct LookupQuery {
    pub url: Option<String>,
    pub file: Option<String>,
}

/// Copies of a file, canonical first, verified only.
pub fn copies(db: &Connection, file_id: &str, canonical: Option<&str>) -> rusqlite::Result<Vec<Value>> {
    let mut stmt = db.prepare_cached("SELECT id, url, kind, host, status, verified_at, author, ia_identifier, ia_filename FROM locations WHERE file = ?1 AND status = 'verified' AND flagged = 0 ORDER BY cursor")?;
    let rows = stmt.query_map([file_id], |r| {
        let id: String = r.get(0)?;
        let ia_id: Option<String> = r.get(7)?;
        Ok((id.clone(), json!({
            "id": id, "url": r.get::<_, String>(1)?, "kind": r.get::<_, String>(2)?, "host": r.get::<_, String>(3)?,
            "status": r.get::<_, String>(4)?, "verified_at": r.get::<_, Option<String>>(5)?, "author": r.get::<_, String>(6)?,
            "ia": ia_id.map(|i| json!({"identifier": i, "filename": r.get::<_, Option<String>>(8).unwrap_or(None)})),
        })))
    })?;
    let mut out: Vec<(String, Value)> = rows.collect::<rusqlite::Result<_>>()?;
    out.sort_by_key(|(id, _)| Some(id.as_str()) != canonical);
    Ok(out.into_iter().map(|(_, v)| v).collect())
}

fn file_json(db: &Connection, file_id: &str, canonical_for_manual: Option<&str>) -> rusqlite::Result<Option<Value>> {
    db.query_row_cached(
        // Held-back files (risky content, malware, reports, unscanned) are never offered.
        "SELECT id, sha256, sha1, md5, size, mime, pages, derived_from, transform, tool_version, canonical_location, author FROM files WHERE id = ?1 AND flagged = 0",
        [file_id],
        |r| {
            let id: String = r.get(0)?;
            let canon_loc: Option<String> = r.get(10)?;
            Ok(json!({
                "id": id, "sha256": r.get::<_, Option<String>>(1)?, "sha1": r.get::<_, Option<String>>(2)?, "md5": r.get::<_, Option<String>>(3)?,
                "size": r.get::<_, Option<i64>>(4)?, "mime": r.get::<_, Option<String>>(5)?, "pages": r.get::<_, Option<i64>>(6)?,
                "derived_from": r.get::<_, Option<String>>(7)?, "transform": r.get::<_, Option<String>>(8)?, "tool_version": r.get::<_, Option<String>>(9)?,
                "canonical": canonical_for_manual == Some(id.as_str()), "author": r.get::<_, String>(11)?,
                "_canon_loc": canon_loc,
            }))
        },
    )
    .optional()
}

fn finish_file(db: &Connection, mut f: Value) -> rusqlite::Result<Value> {
    let id = f["id"].as_str().unwrap().to_string();
    let canon = f["_canon_loc"].as_str().map(String::from);
    f["copies"] = Value::Array(copies(db, &id, canon.as_deref())?);
    f.as_object_mut().unwrap().remove("_canon_loc");
    Ok(f)
}

pub fn manual_json(db: &Connection, public_url: &str, id: &str) -> rusqlite::Result<Option<(Value, Option<String>)>> {
    db.query_row_cached("SELECT id, title, doc_type, brand, model, canonical_file, source_url FROM manuals WHERE id = ?1", [id], |r| {
        let id: String = r.get(0)?;
        Ok((
            json!({"id": id, "title": r.get::<_, String>(1)?, "doc_type": r.get::<_, String>(2)?, "brand": r.get::<_, Option<String>>(3)?,
                   "model": r.get::<_, Option<String>>(4)?, "source_url": r.get::<_, Option<String>>(6)?, "url": format!("{public_url}/manual/{id}")}),
            r.get::<_, Option<String>>(5)?,
        ))
    })
    .optional()
}

/// Manual ids for a source page URL.
pub fn manuals_for_url(db: &Connection, url: &str) -> rusqlite::Result<Vec<String>> {
    let mut ids: Vec<String> = Vec::new();
    let clean = url.split('#').next().unwrap_or(url);
    if let Some(p) = ids::parse_page_url(clean) {
        let mut s = db.prepare_cached("SELECT id FROM manuals WHERE source = ?1 AND source_id = ?2 ORDER BY id")?;
        ids.extend(s.query_map(params![p.source, p.source_id], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?);
        if p.source == "elektrotanya" {
            for cand in ids::slug_candidates(&p.source_id) {
                ids.extend(s.query_map(params!["elektrotanya", cand], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?);
            }
        }
    }
    let mut s = db.prepare_cached("SELECT id FROM manuals WHERE source_url = ?1 OR source_url = ?2")?;
    ids.extend(s.query_map(params![url, clean], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?);
    let mut s = db.prepare_cached("SELECT mf.manual FROM locations l JOIN manual_files mf ON mf.file = l.file WHERE l.kind = 'origin' AND (l.url = ?1 OR l.url = ?2)")?;
    ids.extend(s.query_map(params![url, clean], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?);
    ids.sort();
    ids.dedup();
    Ok(ids)
}

pub async fn lookup(State(state): State<Shared>, Query(q): Query<LookupQuery>) -> Response {
    let st = state.clone();
    let public_url = st.paths.public_url.clone();
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let legacy: Vec<String> = q.url.as_deref().and_then(ids::parse_page_url).map(|p| ids::candidate_identifiers(&p)).unwrap_or_default();
        let Some(db) = st.reader() else {
            return Ok(json!({"known": false, "manual": null, "files": [], "legacy_identifiers": legacy, "snapshot": false}));
        };
        let mut manual: Option<Value> = None;
        let mut file_ids: Vec<String> = Vec::new();
        let mut canonical: Option<String> = None;
        if let Some(url) = &q.url {
            let mids = manuals_for_url(&db, url)?;
            if let Some(mid) = mids.first() {
                if let Some((m, canon)) = manual_json(&db, &public_url, mid)? {
                    manual = Some(m);
                    canonical = canon;
                }
                let mut s = db.prepare_cached("SELECT file FROM manual_files WHERE manual = ?1 ORDER BY file")?;
                file_ids = s.query_map([mid], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            }
        } else if let Some(f) = &q.file {
            if let Some(id) = openmanuals_ledger::model::parse_file_ref(f) {
                if db.query_row_cached("SELECT 1 FROM files WHERE id = ?1", [&id], |_| Ok(())).optional()?.is_some() {
                    file_ids.push(id.clone());
                }
                let mid: Option<String> = db.query_row_cached("SELECT manual FROM manual_files WHERE file = ?1 ORDER BY manual LIMIT 1", [&id], |r| r.get(0)).optional()?;
                if let Some(mid) = mid {
                    if let Some((m, canon)) = manual_json(&db, &public_url, &mid)? {
                        manual = Some(m);
                        canonical = canon;
                    }
                }
            }
        }
        let mut files = Vec::new();
        for fid in &file_ids {
            if let Some(f) = file_json(&db, fid, canonical.as_deref())? {
                files.push(finish_file(&db, f)?);
            }
        }
        let known = manual.is_some() || !files.is_empty();
        Ok(json!({"known": known, "manual": manual, "files": files, "legacy_identifiers": legacy, "snapshot": true}))
    })
    .await;
    match res {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub const MAX_PRODUCT_KEYS: usize = 300;

#[derive(Deserialize)]
pub struct ProductLookup {
    /// Product keys (`brand|MODEL`, as `openmanuals_core::product::product_key` makes them).
    pub keys: Vec<String>,
    /// Only manuals from this site (a `source` key such as "turuta").
    pub source: Option<String>,
}

/// The manuals covering each of a listing page's products, for sites whose
/// listing names models but doesn't link files (turuta.md, signed out).
/// Answers `{"found": {"<key>": [{"id", "title", "doc_type", "source", "url"}…]}}`;
/// keys with no manual are left out.
pub async fn lookup_products(State(state): State<Shared>, Json(q): Json<ProductLookup>) -> Response {
    if q.keys.len() > MAX_PRODUCT_KEYS {
        return err(StatusCode::PAYLOAD_TOO_LARGE, format!("at most {MAX_PRODUCT_KEYS} keys"));
    }
    let st = state.clone();
    let public_url = st.paths.public_url.clone();
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let Some(db) = st.reader() else {
            return Ok(json!({"found": {}, "snapshot": false}));
        };
        let mut s = db.prepare_cached(
            "SELECT m.id, m.title, m.doc_type, m.source FROM covers c JOIN manuals m ON m.id = c.manual \
             WHERE c.product = ?1 AND (?2 IS NULL OR m.source = ?2) ORDER BY m.id LIMIT 20",
        )?;
        let mut found = serde_json::Map::new();
        for key in q.keys.iter().collect::<std::collections::BTreeSet<_>>() {
            let rows: Vec<Value> = s
                .query_map(params![key, q.source], |r| {
                    let id: String = r.get(0)?;
                    Ok(json!({"id": id, "title": r.get::<_, String>(1)?, "doc_type": r.get::<_, String>(2)?, "source": r.get::<_, Option<String>>(3)?, "url": format!("{public_url}/manual/{id}")}))
                })?
                .collect::<rusqlite::Result<_>>()?;
            if !rows.is_empty() {
                found.insert(key.clone(), Value::Array(rows));
            }
        }
        Ok(json!({"found": found, "snapshot": true}))
    })
    .await;
    match res {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn serve_file(path: std::path::PathBuf, content_type: &'static str) -> Response {
    match tokio::fs::read(&path).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, content_type)], bytes).into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "no snapshot has been built yet"),
    }
}

/// Serve a file from disk with Range and conditional-request support.
async fn serve_static(path: std::path::PathBuf, req: axum::extract::Request, content_type: &'static str, immutable: bool, download_name: Option<&str>) -> Response {
    use tower::ServiceExt;
    match tower_http::services::ServeFile::new(&path).oneshot(req).await {
        Ok(res) => {
            let mut res = res.map(Body::new);
            if res.status().is_success() || res.status() == StatusCode::PARTIAL_CONTENT {
                let h = res.headers_mut();
                h.insert(header::CONTENT_TYPE, header::HeaderValue::from_static(content_type));
                let cache = if immutable { "public, max-age=31536000, immutable" } else { "no-cache" };
                h.insert(header::CACHE_CONTROL, header::HeaderValue::from_static(cache));
                if let Some(n) = download_name.and_then(|n| header::HeaderValue::from_str(&format!("attachment; filename=\"{n}\"")).ok()) {
                    h.insert(header::CONTENT_DISPOSITION, n);
                }
            } else if res.status() == StatusCode::NOT_FOUND {
                return err(StatusCode::NOT_FOUND, "no such snapshot file");
            }
            res
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn latest_db(State(state): State<Shared>, req: axum::extract::Request) -> Response {
    serve_static(state.paths.latest_db(), req, "application/vnd.sqlite3", false, Some("manuals.db")).await
}

/// The signed index of the current snapshot, its compressed copy and the diffs.
pub async fn manifest(State(state): State<Shared>) -> Response {
    let mut r = serve_file(state.paths.snapshots_dir().join("manifest.json"), "application/json").await;
    r.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-cache"));
    r
}

pub async fn manifest_sig(State(state): State<Shared>) -> Response {
    serve_file(state.paths.snapshots_dir().join("manifest.json.sig"), "text/plain; charset=utf-8").await
}

/// `<version>.db`, `.db.zst` and `.pages`: immutable once published.
pub async fn snapshot_file(State(state): State<Shared>, Path(name): Path<String>, req: axum::extract::Request) -> Response {
    let (cursor, ctype) = if let Some(c) = name.strip_suffix(".db.zst") {
        (c, "application/zstd")
    } else if let Some(c) = name.strip_suffix(".pages") {
        (c, "application/octet-stream")
    } else if let Some(c) = name.strip_suffix(".db") {
        (c, "application/vnd.sqlite3")
    } else {
        return err(StatusCode::NOT_FOUND, "no such snapshot file");
    };
    if !crate::publish::is_version(cursor) {
        return err(StatusCode::NOT_FOUND, "no such snapshot file");
    }
    serve_static(state.paths.snapshots_dir().join(&name), req, ctype, true, Some(&name)).await
}

/// `diff/<from>.<to>.jsonl.zst`: immutable once published.
pub async fn diff_file(State(state): State<Shared>, Path(name): Path<String>, req: axum::extract::Request) -> Response {
    if !crate::publish::is_diff_name(&name) {
        return err(StatusCode::NOT_FOUND, "no such diff");
    }
    serve_static(state.paths.snapshots_dir().join("diff").join(&name), req, "application/zstd", true, None).await
}

/// The extension's membership filter of known pages; ETag is its sha256.
pub async fn lookup_filter(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Ok(bytes) = tokio::fs::read(state.paths.snapshots_dir().join("lookup-filter.bin")).await else {
        return err(StatusCode::NOT_FOUND, "no snapshot has been published yet");
    };
    let etag = format!("\"{}\"", openmanuals_core::canon::sha256_hex(&bytes));
    let matches = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"));
    let b = Response::builder().header(header::ETAG, &etag).header(header::CACHE_CONTROL, "no-cache");
    if matches {
        return b.status(StatusCode::NOT_MODIFIED).body(Body::empty()).unwrap();
    }
    b.header(header::CONTENT_TYPE, "application/octet-stream").body(Body::from(bytes)).unwrap()
}

/// Redirect to the current compressed snapshot.
pub async fn latest_zst(State(state): State<Shared>) -> Response {
    let m: Option<Value> = tokio::fs::read(state.paths.snapshots_dir().join("manifest.json")).await.ok().and_then(|b| serde_json::from_slice(&b).ok());
    match m.as_ref().and_then(|m| m["latest"]["zst"]["file"].as_str()) {
        Some(f) => Response::builder().status(StatusCode::FOUND).header(header::LOCATION, format!("/db/{f}")).header(header::CACHE_CONTROL, "no-cache").body(Body::empty()).unwrap(),
        None => err(StatusCode::NOT_FOUND, "no snapshot has been published yet"),
    }
}

pub async fn latest_sha(State(state): State<Shared>) -> Response {
    serve_file(state.paths.snapshots_dir().join("latest.db.sha256"), "text/plain; charset=utf-8").await
}

pub async fn latest_sig(State(state): State<Shared>) -> Response {
    serve_file(state.paths.snapshots_dir().join("latest.db.sig"), "text/plain; charset=utf-8").await
}

pub async fn aspe_profile(State(state): State<Shared>, Path(fp): Path<String>) -> Response {
    let fp = fp.to_ascii_uppercase();
    if !openmanuals_core::fact::valid_fingerprint(&fp) {
        return err(StatusCode::NOT_FOUND, "no such profile");
    }
    let st = state.clone();
    // Served straight from the inbox (new profiles show up before the fold),
    // so moderation is applied here: a blocked key has no profile.
    let profile = move || -> anyhow::Result<Option<String>> {
        let trust = st.trust.read().unwrap().clone();
        if st.inbox.blocked_keys(|a| trust.is_moderator(a))?.contains(&fp) {
            return Ok(None);
        }
        st.inbox.latest_profile(&fp)
    };
    match tokio::task::spawn_blocking(profile).await {
        Ok(Ok(Some(jws))) => ([(header::CONTENT_TYPE, "application/asp+jwt; charset=UTF-8")], jws).into_response(),
        Ok(Ok(None)) => (StatusCode::NOT_FOUND, "no such profile").into_response(),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn aspe_version() -> Response {
    Json(json!({"version": 0})).into_response()
}

pub async fn server_info(State(state): State<Shared>, _h: HeaderMap) -> Response {
    let trust = state.trust.read().unwrap();
    Json(json!({
        "name": "OpenManuals", "server_key": state.key.public_key().to_jwk(), "fingerprint": state.fingerprint,
        "domain": trust.domain, "aspe": openmanuals_core::asp::aspe_uri(&trust.domain, &state.fingerprint),
        "snapshot": state.snapshot.read().unwrap().is_some(),
        // Whose block/unblock/prefer facts apply here (public build configuration).
        "moderators": trust.moderators,
    }))
    .into_response()
}

/// Most facts `manual_facts` returns for one manual.
pub const MAX_MANUAL_FACTS: usize = 1000;

/// `GET /api/manual/{id}/facts`: a manual's `manual` and `covers` facts from
/// the inbox (folded or not), each as `GET /api/fact/{id}` serves it, plus
/// display names for the products they cover. The extension's editor verifies
/// every fact itself; `products` is only for showing them.
pub async fn manual_facts(State(state): State<Shared>, Path(id): Path<String>) -> Response {
    let id = id.to_ascii_uppercase();
    if !valid_ulid(&id) {
        return err(StatusCode::BAD_REQUEST, "not a manual id");
    }
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let rows = state.inbox.manual_facts(&id, MAX_MANUAL_FACTS)?;
        let m = state.inbox.moderation(|fp| state.trust.read().unwrap().is_moderator(fp))?;
        let mut keys = std::collections::BTreeSet::new();
        let facts: Vec<Value> = rows
            .iter()
            .map(|r| {
                let hidden = m.hidden(r);
                if !hidden && r.kind == "covers" {
                    if let Some(k) = r.fact.body.get("product").and_then(Value::as_str) {
                        keys.insert(k.to_string());
                    }
                }
                json!({
                    "id": r.id, "cursor": r.cursor, "folded": r.folded, "hidden": hidden, "retracted": m.retracted(r),
                    "fact": if hidden { Value::Null } else { serde_json::to_value(&r.fact).unwrap_or(Value::Null) },
                })
            })
            .collect();
        let mut products = serde_json::Map::new();
        if let Some(db) = state.reader() {
            for k in &keys {
                let row: Option<(String, String)> = db.query_row_cached("SELECT brand, model FROM products WHERE key = ?1", [k], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
                if let Some((brand, model)) = row {
                    products.insert(k.clone(), json!({"brand": brand, "model": model}));
                }
            }
        }
        Ok(json!({"manual": id, "facts": facts, "products": products, "truncated": rows.len() >= MAX_MANUAL_FACTS}))
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|r| r)
    .map(|v| Json(v).into_response())
    .unwrap_or_else(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// A manual id: an uppercase Crockford base32 ULID.
fn valid_ulid(s: &str) -> bool {
    s.len() == 26 && s.as_bytes()[0] <= b'7' && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z'))
}
