//! HTML pages rendered from the latest snapshot.

use crate::api::{copies, manuals_for_url};
use crate::config::{CachedQuery, Shared};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use minijinja::{context, Environment, Value as JValue};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const PAGE_SIZE: i64 = 30;

/// The page templates, parsed once.
pub fn env() -> &'static Environment<'static> {
    static ENV: std::sync::OnceLock<Environment<'static>> = std::sync::OnceLock::new();
    ENV.get_or_init(build_env)
}

fn build_env() -> Environment<'static> {
    let mut e = Environment::new();
    e.add_template("base.html", include_str!("../templates/base.html")).unwrap();
    e.add_template("index.html", include_str!("../templates/index.html")).unwrap();
    e.add_template("list.html", include_str!("../templates/list.html")).unwrap();
    e.add_template("manual.html", include_str!("../templates/manual.html")).unwrap();
    e.add_template("product.html", include_str!("../templates/product.html")).unwrap();
    e.add_template("file.html", include_str!("../templates/file.html")).unwrap();
    e.add_template("key.html", include_str!("../templates/key.html")).unwrap();
    e.add_template("contributions.html", include_str!("../templates/contributions.html")).unwrap();
    e.add_template("about.html", include_str!("../templates/about.html")).unwrap();
    e.add_template("privacy.html", include_str!("../templates/privacy.html")).unwrap();
    e.add_template("notfound.html", include_str!("../templates/notfound.html")).unwrap();
    e.add_template("_facts.html", include_str!("../templates/_facts.html")).unwrap();
    e.add_template("home.html", include_str!("../templates/home.html")).unwrap();
    e.add_template("ledger.html", include_str!("../templates/ledger.html")).unwrap();
    e.add_template("fact.html", include_str!("../templates/fact.html")).unwrap();
    e.add_template("_contribute.html", include_str!("../templates/_contribute.html")).unwrap();
    e.add_template("contribute.html", include_str!("../templates/contribute.html")).unwrap();
    e
}

pub(crate) fn render(name: &str, ctx: JValue) -> Response {
    match env().get_template(name).and_then(|t| t.render(ctx)) {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("template error: {e}")).into_response(),
    }
}

pub(crate) fn not_found() -> Response {
    let mut r = render("notfound.html", context! {});
    *r.status_mut() = StatusCode::NOT_FOUND;
    r
}

/// Run `f` with a pooled snapshot connection on the blocking pool. Queries
/// run synchronously; on the async workers a slow one stalls every task
/// queued behind it on that worker (connections, accepts), which under load
/// serialized the slower pages.
async fn with_db<F>(state: Shared, f: F) -> Response
where
    F: FnOnce(&crate::config::State, &Connection) -> Response + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let Some(db) = state.reader() else { return no_snapshot() };
        f(&state, &db)
    })
    .await
    .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

pub(crate) fn no_snapshot() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Html("<h1>No snapshot yet</h1><p>Run <code>openmanuals-server build</code> first.</p>")).into_response()
}

pub async fn style() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("../static/style.css")).into_response()
}

/// The header's theme switch.
pub async fn theme_js() -> Response {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=3600")], include_str!("../static/theme.js")).into_response()
}

/// The OpenManuals logo (a book under X-ray); also the favicon.
pub async fn logo() -> Response {
    ([(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "public, max-age=86400")], include_str!("../../../brand/logo.svg")).into_response()
}

pub(crate) fn size_label(size: Option<i64>) -> String {
    match size {
        None => "unknown size".into(),
        Some(s) if s >= 1 << 20 => format!("{:.1} MB", s as f64 / (1 << 20) as f64),
        Some(s) if s >= 1 << 10 => format!("{:.0} KB", s as f64 / 1024.0),
        Some(s) => format!("{s} B"),
    }
}

/// Display names of keys, looked up as needed and remembered for one page.
struct Names<'a> {
    db: &'a Connection,
    memo: HashMap<String, String>,
}

impl<'a> Names<'a> {
    fn new(db: &'a Connection) -> Self {
        Names { db, memo: HashMap::new() }
    }

    fn name(&mut self, fp: &str) -> String {
        if let Some(n) = self.memo.get(fp) {
            return n.clone();
        }
        let n = self
            .db
            .query_row_cached("SELECT c.name FROM keys k JOIN contributors c ON c.id = k.contributor WHERE k.fingerprint = ?1", [fp], |r| r.get::<_, Option<String>>(0))
            .ok()
            .flatten()
            .unwrap_or_else(|| fp[..8.min(fp.len())].to_string());
        self.memo.insert(fp.to_string(), n.clone());
        n
    }
}

/// The canonical download (url, host, ia_identifier) of a manual, if any.
fn download_of(db: &Connection, canonical_file: Option<&str>) -> Option<(String, String, Option<String>)> {
    let cf = canonical_file?;
    db.query_row_cached(
        "SELECT l.url, l.host, l.ia_identifier FROM files f JOIN locations l ON l.id = f.canonical_location WHERE f.id = ?1",
        [cf],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
    .ok()
    .flatten()
}

pub async fn index(State(state): State<Shared>) -> Response {
    with_db(state, move |_, db| {
        let total: i64 = db.query_row_cached("SELECT count(*) FROM manual_search WHERE downloadable = 1", [], |r| r.get(0)).unwrap_or(0);
        let mut brands = Vec::new();
        if let Ok(mut s) = db.prepare_cached("SELECT brand_key, brand, downloadable FROM brands WHERE downloadable > 0 ORDER BY downloadable DESC, brand LIMIT 48") {
            for r in s.query_map([], |r| Ok(json!({"key": r.get::<_, String>(0)?, "brand": r.get::<_, String>(1)?, "n": r.get::<_, i64>(2)?}))).into_iter().flatten().flatten() {
                brands.push(r);
            }
        }
        render("index.html", context! { total => total, brands => brands })
    })
    .await
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    pub q: Option<String>,
    pub brand: Option<String>,
    pub doc_type: Option<String>,
    pub page: Option<i64>,
    pub all: Option<String>,
}

pub async fn manuals(State(state): State<Shared>, Query(q): Query<ListQuery>) -> Response {
    with_db(state, move |_, db| {
        let page = q.page.unwrap_or(1).max(1);
        let mut wheres: Vec<String> = vec![];
        let mut args: Vec<String> = vec![];
        if q.all.is_none() {
            wheres.push("s.downloadable = 1".into());
        }
        let text = q.q.clone().unwrap_or_default();
        // Every word must appear somewhere in the search text. The trigram index
        // (manual_fts) answers words of 3+ characters without scanning; shorter
        // ones can't use it and are checked on the matching rows (or scanned).
        let mut likes: Vec<String> = Vec::new();
        for tok in text.split_whitespace().take(6) {
            args.push(format!("%{}%", tok.to_lowercase()));
            if tok.chars().count() >= 3 {
                likes.push(format!("text LIKE ?{}", args.len()));
            } else {
                wheres.push(format!("s.text LIKE ?{}", args.len()));
            }
        }
        if !likes.is_empty() {
            wheres.push(format!("s.rowid IN (SELECT rowid FROM manual_fts WHERE {})", likes.join(" AND ")));
        }
        let brand_key = q.brand.clone().unwrap_or_default();
        let mut brand_name = String::new();
        if !brand_key.is_empty() {
            let bk = openmanuals_core::product::normalize_brand(&brand_key);
            brand_name = db.query_row_cached("SELECT brand FROM brands WHERE brand_key = ?1", [&bk], |r| r.get(0)).unwrap_or_else(|_| brand_key.clone());
            wheres.push(format!("m.id IN (SELECT c.manual FROM covers c JOIN products p ON p.key = c.product WHERE p.brand_key = ?{})", args.len() + 1));
            args.push(bk);
        }
        let doc_type = q.doc_type.clone().unwrap_or_default();
        if !doc_type.is_empty() {
            wheres.push(format!("lower(m.doc_type) = ?{}", args.len() + 1));
            args.push(doc_type.to_lowercase());
        }
        let where_sql = if wheres.is_empty() { String::new() } else { format!("WHERE {}", wheres.join(" AND ")) };
        // Every manual has a manual_search row; join manuals only when filtering on it.
        let from = if brand_key.is_empty() && doc_type.is_empty() { "manual_search s" } else { "manuals m JOIN manual_search s ON s.manual = m.id" };
        let total: i64 = db
            .query_row_cached(&format!("SELECT count(*) FROM {from} {where_sql}"), rusqlite::params_from_iter(args.iter()), |r| r.get(0))
            .unwrap_or(0);
        let pages = ((total + PAGE_SIZE - 1) / PAGE_SIZE).max(1);
        let mut results = Vec::new();
        let sql = format!("SELECT m.id, m.title, m.doc_type, m.brand, m.model, m.canonical_file FROM manuals m JOIN manual_search s ON s.manual = m.id {where_sql} ORDER BY m.brand, m.model, m.title LIMIT {PAGE_SIZE} OFFSET {}", (page - 1) * PAGE_SIZE);
        if let Ok(mut s) = db.prepare_cached(&sql) {
            let rows: Vec<(String, String, String, Option<String>, Option<String>, Option<String>)> = s
                .query_map(rusqlite::params_from_iter(args.iter()), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
                .into_iter()
                .flatten()
                .flatten()
                .collect();
            for (id, title, dt, brand, model, cf) in rows {
                let dl = download_of(&db, cf.as_deref());
                results.push(json!({"id": id, "title": title, "doc_type": dt, "brand": brand, "model": model,
                    "download": dl.as_ref().map(|d| d.0.clone()), "host": dl.as_ref().map(|d| d.1.clone())}));
            }
        }
        let brand_missing = if brand_key.is_empty() { 0 } else { crate::contribute::missing(db, Some(&openmanuals_core::product::normalize_brand(&brand_key))) };
        render("list.html", context! { q => text, brand => brand_name, brand_key => brand_key, doc_type => doc_type, results => results, total => total, page => page, pages => pages,
            brand_missing => brand_missing, brand_missing_label => crate::activity::grouped(brand_missing) })
    })
    .await
}

pub async fn manual(State(state): State<Shared>, Path(id): Path<String>) -> Response {
    with_db(state, move |_, db| {
        let id = id.to_ascii_uppercase();
        let row = db
            .query_row_cached("SELECT id, title, doc_type, brand, model, canonical_file, source, source_url, author FROM manuals WHERE id = ?1", [&id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, Option<String>>(4)?, r.get::<_, Option<String>>(5)?, r.get::<_, Option<String>>(6)?, r.get::<_, Option<String>>(7)?, r.get::<_, String>(8)?))
            })
            .optional()
            .ok()
            .flatten();
        let Some((id, title, doc_type, brand, model, cf, source, source_url, author)) = row else { return not_found() };
        let mut names = Names::new(db);
        let dl = download_of(&db, cf.as_deref()).map(|d| json!({"url": d.0, "host": d.1, "ia_identifier": d.2}));
        let mut products = Vec::new();
        if let Ok(mut s) = db.prepare_cached("SELECT p.brand, p.model FROM covers c JOIN products p ON p.key = c.product WHERE c.manual = ?1 ORDER BY p.key") {
            for r in s.query_map([&id], |r| Ok(json!({"brand": r.get::<_, String>(0)?, "model": r.get::<_, String>(1)?}))).into_iter().flatten().flatten() {
                products.push(r);
            }
        }
        let mut files = Vec::new();
        if let Ok(mut s) = db.prepare_cached("SELECT f.id, f.size, f.transform, f.tool_version, f.canonical_location, mf.role, f.review FROM manual_files mf JOIN files f ON f.id = mf.file WHERE mf.manual = ?1 ORDER BY (f.id = ?2) DESC, f.id") {
            type Row = (String, Option<i64>, Option<String>, Option<String>, Option<String>, String, Option<String>);
            let rows: Vec<Row> = s
                .query_map(params![id, cf.clone().unwrap_or_default()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))
                .into_iter()
                .flatten()
                .flatten()
                .collect();
            for (fid, size, transform, tv, canon, role, review) in rows {
                // A held-back file's copies are not linked.
                let mut cps = if review.is_some() { Vec::new() } else { copies(&db, &fid, canon.as_deref()).unwrap_or_default() };
                for c in &mut cps {
                    let a = c["author"].as_str().unwrap_or("").to_string();
                    c["author_name"] = Value::String(names.name(&a));
                }
                let label = if transform.is_some() { format!("{} ({role})", transform.clone().unwrap()) } else { format!("original ({role})") };
                files.push(json!({"id": fid, "label": label, "size_label": size_label(size), "transform": transform, "tool_version": tv, "copies": cps, "review": review}));
            }
        }
        let brand_key = brand.as_deref().map(openmanuals_core::product::normalize_brand).unwrap_or_default();
        let m = json!({"id": id, "title": title, "doc_type": doc_type, "brand": brand, "brand_key": brand_key, "model": model, "source": source, "source_url": source_url,
            "author": author, "author_name": names.name(&author)});
        render("manual.html", context! { m => m, products => products, files => files, download => dl })
    })
    .await
}

pub async fn product(State(state): State<Shared>, Path((brand, model)): Path<(String, String)>) -> Response {
    with_db(state, move |_, db| {
        let Some(key) = openmanuals_core::product::product_key(&brand, &model) else { return not_found() };
        let Some((pb, pm)) = db.query_row_cached("SELECT brand, model FROM products WHERE key = ?1", [&key], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).optional().ok().flatten() else { return not_found() };
        let mut results = Vec::new();
        if let Ok(mut s) = db.prepare_cached("SELECT m.id, m.title, m.doc_type, m.canonical_file FROM covers c JOIN manuals m ON m.id = c.manual WHERE c.product = ?1 ORDER BY m.doc_type, m.title") {
            let rows: Vec<(String, String, String, Option<String>)> = s.query_map([&key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).into_iter().flatten().flatten().collect();
            for (id, title, dt, cf) in rows {
                let dl = download_of(&db, cf.as_deref());
                results.push(json!({"id": id, "title": title, "doc_type": dt, "download": dl.as_ref().map(|d| d.0.clone()), "host": dl.as_ref().map(|d| d.1.clone())}));
            }
        }
        render("product.html", context! { p => json!({"brand": pb, "model": pm}), results => results })
    })
    .await
}

pub async fn file(State(state): State<Shared>, Path(id): Path<String>) -> Response {
    with_db(state, move |_, db| {
        let Some(id) = openmanuals_ledger::model::parse_file_ref(&id) else { return not_found() };
        let row = db
            .query_row_cached("SELECT sha256, sha1, md5, size, mime, pages, derived_from, transform, tool, tool_version, canonical_location, review FROM files WHERE id = ?1", [&id], |r| {
                Ok(json!({"id": id, "sha256": r.get::<_, Option<String>>(0)?, "sha1": r.get::<_, Option<String>>(1)?, "md5": r.get::<_, Option<String>>(2)?,
                    "size_label": size_label(r.get::<_, Option<i64>>(3)?), "mime": r.get::<_, Option<String>>(4)?, "pages": r.get::<_, Option<i64>>(5)?,
                    "derived_from": r.get::<_, Option<String>>(6)?, "transform": r.get::<_, Option<String>>(7)?, "tool": r.get::<_, Option<String>>(8)?,
                    "tool_version": r.get::<_, Option<String>>(9)?, "canon": r.get::<_, Option<String>>(10)?, "review": r.get::<_, Option<String>>(11)?}))
            })
            .optional()
            .ok()
            .flatten();
        let Some(f) = row else { return not_found() };
        let mut names = Names::new(db);
        let mut cps = if f["review"].is_string() { Vec::new() } else { copies(&db, &id, f["canon"].as_str()).unwrap_or_default() };
        for c in &mut cps {
            let a = c["author"].as_str().unwrap_or("").to_string();
            c["author_name"] = Value::String(names.name(&a));
        }
        let mut manuals = Vec::new();
        if let Ok(mut s) = db.prepare_cached("SELECT m.id, m.title, m.doc_type FROM manual_files mf JOIN manuals m ON m.id = mf.manual WHERE mf.file = ?1 ORDER BY m.id") {
            for r in s.query_map([&id], |r| Ok(json!({"id": r.get::<_, String>(0)?, "title": r.get::<_, String>(1)?, "doc_type": r.get::<_, String>(2)?}))).into_iter().flatten().flatten() {
                manuals.push(r);
            }
        }
        render("file.html", context! { f => f, copies => cps, manuals => manuals })
    })
    .await
}

pub async fn key(State(state): State<Shared>, Path(fp): Path<String>, headers: axum::http::HeaderMap) -> Response {
    if crate::keyoxide::wants_activity_json(&headers) {
        return crate::keyoxide::actor(state, fp).await;
    }
    with_db(state, move |state, db| {
        let fp = fp.to_ascii_uppercase();
        let Some((contributor, facts, vc)) = db.query_row_cached("SELECT contributor, facts, verified_copies FROM keys WHERE fingerprint = ?1", [&fp], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))).optional().ok().flatten() else { return not_found() };
        let (name, group_keys): (Option<String>, i64) = db.query_row_cached("SELECT name, keys FROM contributors WHERE id = ?1", [&contributor], |r| Ok((r.get(0)?, r.get(1)?))).unwrap_or((None, 1));
        let mut links = Vec::new();
        if let Ok(mut s) = db.prepare_cached("SELECT service, handle, claim_uri FROM identity_links WHERE key = ?1 ORDER BY service, handle") {
            for r in s.query_map([&fp], |r| {
                let uri: String = r.get(2)?;
                Ok(json!({"service": r.get::<_, String>(0)?, "handle": r.get::<_, String>(1)?, "href": crate::keyoxide::claim_href(&uri)}))
            }).into_iter().flatten().flatten() {
                links.push(r);
            }
        }
        // External Keyoxide identities this key's signed profile claims: the
        // proof a Keyoxide profile linking this key is checked against.
        let identities: Vec<Value> = crate::keyoxide::key_profile(db, &fp)
            .map(|p| {
                p.claims
                    .iter()
                    .filter(|c| crate::keyoxide::is_identity_uri(c))
                    .map(|c| json!({"uri": c, "href": crate::keyoxide::claim_href(c), "verified": p.links.iter().any(|l| &l.2 == c)}))
                    .collect()
            })
            .unwrap_or_default();
        let mut copies_v = Vec::new();
        // For a key with many copies, walking locations newest first and
        // skipping other keys' rows beats fetching all of its rows through the
        // author index and sorting them (5 ms vs 10 ms for 13k copies).
        let filter = if vc > 2000 { "+l.author = ?1 AND" } else { "l.author = ?1 AND" };
        if let Ok(mut s) = db.prepare_cached(&recent_copies_sql(filter)) {
            for r in s.query_map([&fp], |r| Ok(json!({"url": r.get::<_, String>(0)?, "host": r.get::<_, String>(1)?, "manual": r.get::<_, String>(4)?, "title": r.get::<_, String>(5)?}))).into_iter().flatten().flatten() {
                copies_v.push(r);
            }
        }
        let domain = state.trust.read().unwrap().domain.clone();
        let aspe = openmanuals_core::asp::aspe_uri(&domain, &fp);
        let keyoxide = crate::keyoxide::keyoxide_profile_url(&domain, &fp);
        let avatar = crate::avatar::html(&state, &fp);
        let mut r = render("key.html", context! { fp => fp, name => name.unwrap_or_else(|| fp[..8].to_string()), aspe => aspe, keyoxide => keyoxide, avatar => avatar, url => format!("{}/k/{fp}", state.paths.public_url), links => links, identities => identities, facts => facts, verified_copies => vc, group_keys => group_keys, copies => copies_v });
        // Ariadne's HTTP proof: a Keyoxide profile that lists this page's URL
        // proves the key's ASPE identity (doipjs follows https links in a
        // proof and checks this header).
        if let Ok(v) = axum::http::HeaderValue::from_str(&aspe) {
            r.headers_mut().insert("ariadne-identity-proof", v);
        }
        r.headers_mut().insert(header::VARY, axum::http::HeaderValue::from_static("Accept"));
        r
    })
    .await
}

pub async fn item(State(state): State<Shared>, Path(identifier): Path<String>) -> Response {
    with_db(state, move |_, db| {
        let mid: Option<String> = db
            .query_row_cached("SELECT mf.manual FROM locations l JOIN manual_files mf ON mf.file = l.file WHERE l.ia_identifier = ?1 ORDER BY mf.manual LIMIT 1", [&identifier], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
            .or_else(|| {
                let (source, sid) = identifier.split_once("-id-")?;
                db.query_row_cached("SELECT id FROM manuals WHERE source = ?1 AND source_id = ?2 ORDER BY id LIMIT 1", params![source, sid], |r| r.get(0)).optional().ok().flatten()
            });
        match mid {
            Some(id) => Redirect::to(&format!("/manual/{id}")).into_response(),
            None => not_found(),
        }
    })
    .await
}

/// The 50 newest verified copies (url, host, verified_at, author, manual id,
/// manual title), optionally filtered (`filter` is SQL ending in AND).
///
/// The newest 50 locations that belong to some manual are picked first and
/// only those are joined with manual_files and manuals. Joining every
/// verified location and then sorting (the old query: ~13k rows, each with a
/// manuals row, into a temporary b-tree) took ~28 ms on the real snapshot;
/// this takes ~5 ms. Same rows: a location without a manual is skipped by the
/// EXISTS just as the join skipped it. With the partial indexes
/// `locations(cursor) WHERE status = 'verified'` and `locations(author,
/// cursor) WHERE status = 'verified'` in the snapshot it takes ~0.1 ms.
fn recent_copies_sql(filter: &str) -> String {
    format!(
        "SELECT l.url, l.host, l.verified_at, l.author, m.id, m.title FROM \
           (SELECT url, host, verified_at, author, file, cursor FROM locations l \
            WHERE {filter} l.status = 'verified' AND EXISTS (SELECT 1 FROM manual_files mf WHERE mf.file = l.file) \
            ORDER BY l.cursor DESC LIMIT 50) l \
         JOIN manual_files mf ON mf.file = l.file JOIN manuals m ON m.id = mf.manual \
         ORDER BY l.cursor DESC, m.id LIMIT 50"
    )
}

pub async fn contributions(State(state): State<Shared>) -> Response {
    with_db(state, move |_, db| {
        let mut names = Names::new(db);
        // keys.verified_copies is the number of verified locations each key
        // added (openmanuals-ledger's Resolver), so the totals need no scan of locations.
        let total: i64 = db.query_row_cached("SELECT coalesce(sum(verified_copies), 0) FROM keys", [], |r| r.get(0)).unwrap_or(0);
        let mut top = Vec::new();
        if let Ok(mut s) = db.prepare_cached("SELECT fingerprint, verified_copies FROM keys WHERE verified_copies > 0 ORDER BY verified_copies DESC, fingerprint LIMIT 20") {
            let rows: Vec<(String, i64)> = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).into_iter().flatten().flatten().collect();
            for (key, n) in rows {
                top.push(json!({"name": names.name(&key), "key": key, "n": n}));
            }
        }
        let mut recent = Vec::new();
        if let Ok(mut s) = db.prepare_cached(&recent_copies_sql("")) {
            let rows: Vec<(String, String, Option<String>, String, String, String)> =
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))).into_iter().flatten().flatten().collect();
            for (url, host, verified_at, author, manual, title) in rows {
                recent.push(json!({"url": url, "host": host, "verified_at": verified_at.unwrap_or_default(), "author_name": names.name(&author), "author": author, "manual": manual, "title": title}));
            }
        }
        render("contributions.html", context! { total => total, top => top, recent => recent })
    })
    .await
}

pub async fn about(State(state): State<Shared>) -> Response {
    render("about.html", context! { fp => state.fingerprint.clone() })
}

pub async fn privacy() -> Response {
    render("privacy.html", context! {})
}

/// `/lookup?url=` convenience redirect to the manual page.
#[derive(Deserialize, Default)]
pub struct ContributeQuery {
    pub brand: Option<String>,
    pub none: Option<String>,
}

fn brand_param(b: &Option<String>) -> Option<String> {
    b.as_deref().map(str::trim).filter(|b| !b.is_empty()).map(openmanuals_core::product::normalize_brand)
}

/// "Help preserve a manual": what it is, how many are missing, by brand.
pub async fn contribute(State(state): State<Shared>, Query(q): Query<ContributeQuery>) -> Response {
    with_db(state, move |state, db| {
        let counts = state.contribute.counts(db);
        let brand_key = brand_param(&q.brand);
        let (brand, brand_missing) = match &brand_key {
            Some(b) => (
                db.query_row_cached("SELECT brand FROM brands WHERE brand_key = ?1", [b], |r| r.get::<_, String>(0)).unwrap_or_else(|_| b.clone()),
                crate::contribute::missing(db, Some(b)),
            ),
            None => (String::new(), 0),
        };
        render("contribute.html", context! {
            total => crate::activity::grouped(counts["total"].as_i64().unwrap_or(0)),
            brands => counts["brands"].clone(),
            brand_key => brand_key.unwrap_or_default(),
            brand => brand,
            brand_missing => crate::activity::grouped(brand_missing),
            none => q.none.is_some(),
        })
    })
    .await
}

/// Redirects to a random missing manual's page on its source site.
pub async fn contribute_random(State(state): State<Shared>, Query(q): Query<ContributeQuery>) -> Response {
    with_db(state, move |state, db| {
        let brand_key = brand_param(&q.brand);
        let to = match state.contribute.pick(db, brand_key.as_deref()) {
            Some(url) => url,
            None => match &brand_key {
                Some(b) => format!("/contribute?brand={}&none=1", urlencoding::encode(b)),
                None => "/contribute?none=1".into(),
            },
        };
        let mut r = axum::response::Redirect::to(&to).into_response();
        let h = r.headers_mut();
        h.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
        h.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
        r
    })
    .await
}

pub async fn lookup_redirect(State(state): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Response {
    with_db(state, move |_, db| {
        let Some(url) = q.get("url") else { return not_found() };
        match manuals_for_url(&db, url).ok().and_then(|v| v.into_iter().next()) {
            Some(id) => Redirect::to(&format!("/manual/{id}")).into_response(),
            None => not_found(),
        }
    })
    .await
}
