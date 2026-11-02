//! The home page and the ledger browser: every fact in arrival order, newest
//! first, GitHub-commit-list style, with who submitted it and their proofs.

use crate::config::Shared;
use crate::inbox::{LedgerRow, Moderation};
use crate::pages::{no_snapshot, not_found, render, size_label};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use minijinja::context;
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

const PAGE: usize = 50;

/// A GitHub-style identicon: a 5×5 mirrored grid coloured from the key's hash.
pub fn identicon(fp: &str) -> String {
    let h = openmanuals_core::canon::sha256_hex(fp.as_bytes());
    let b = hex::decode(&h).unwrap_or_default();
    let hue = (u16::from(b[0]) << 8 | u16::from(b[1])) % 360;
    let color = format!("hsl({hue}, 55%, 52%)");
    let mut cells = String::new();
    for row in 0..5u8 {
        for col in 0..3u8 {
            let bit = b[2 + (row * 3 + col) as usize] & 1 == 1;
            if bit {
                for c in [col, 4 - col] {
                    cells.push_str(&format!(r#"<rect x="{}" y="{}" width="1" height="1"/>"#, c, row));
                }
            }
        }
    }
    format!(r##"<svg class="identicon" viewBox="-0.5 -0.5 6 6" width="40" height="40" aria-hidden="true"><rect x="-0.5" y="-0.5" width="6" height="6" fill="#f0f1ee"/><g fill="{color}" shape-rendering="crispEdges">{cells}</g></svg>"##)
}

/// 412753 → "412,753".
pub(crate) fn grouped(n: i64) -> String {
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 { format!("-{out}") } else { out }
}

fn cursor_ms(cursor: &str) -> Option<i64> {
    cursor.parse::<ulid::Ulid>().ok().map(|u| u.timestamp_ms() as i64)
}

/// "3 minutes ago", for the list; the exact time goes in a tooltip.
fn ago(ms: i64) -> String {
    let now = jiff::Timestamp::now().as_millisecond();
    let s = ((now - ms) / 1000).max(0);
    let (n, unit) = match s {
        0..=59 => return "just now".into(),
        60..=3599 => (s / 60, "minute"),
        3600..=86_399 => (s / 3600, "hour"),
        86_400..=2_591_999 => (s / 86_400, "day"),
        2_592_000..=31_535_999 => (s / 2_592_000, "month"),
        _ => (s / 31_536_000, "year"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

fn when(ms: i64, fmt: &str) -> String {
    jiff::Timestamp::from_millisecond(ms).map(|t| t.strftime(fmt).to_string()).unwrap_or_default()
}

/// Who a key is, as the snapshot knows them: name, proofs, role.
struct Profiles<'a> {
    db: &'a Connection,
    state: &'a crate::config::State,
    memo: HashMap<String, Value>,
}

impl<'a> Profiles<'a> {
    fn get(&mut self, fp: &str) -> Value {
        if let Some(v) = self.memo.get(fp) {
            return v.clone();
        }
        let name: Option<String> = self
            .db
            .query_row("SELECT coalesce(k.profile_name, c.name) FROM keys k LEFT JOIN contributors c ON c.id = k.contributor WHERE k.fingerprint = ?1", [fp], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
            .flatten();
        let mut links = Vec::new();
        if let Ok(mut s) = self.db.prepare_cached("SELECT service, handle, claim_uri FROM identity_links WHERE key = ?1 ORDER BY service, handle") {
            for r in s.query_map([fp], |r| {
                let uri: String = r.get(2)?;
                // Only https links; anything else is shown as text.
                let uri = if uri.starts_with("https://") { uri } else { String::new() };
                Ok(json!({"service": r.get::<_, String>(0)?, "handle": r.get::<_, String>(1)?, "uri": uri}))
            }).into_iter().flatten().flatten() {
                links.push(r);
            }
        }
        let trust = self.state.trust.read().unwrap();
        let role = if fp == self.state.fingerprint || trust.is_server(fp) {
            Some("server")
        } else if trust.is_moderator(fp) {
            Some("moderator")
        } else {
            None
        };
        let display = name.clone().unwrap_or_else(|| match role {
            Some("server") => "OpenManuals server".to_string(),
            _ => format!("{}…", &fp[..fp.len().min(8)]),
        });
        let v = json!({"fp": fp, "name": display, "named": name.is_some(), "links": links, "role": role, "avatar": crate::avatar::html(self.state, fp)});
        self.memo.insert(fp.to_string(), v.clone());
        v
    }
}

/// Site paths built from fact text: only for values that parse as real ids,
/// so a crafted value can't make a link that leaves the site.
fn manual_path(id: &str) -> Option<String> {
    let id = id.trim().to_ascii_uppercase();
    (id.len() == 26 && id.parse::<ulid::Ulid>().is_ok()).then(|| format!("/manual/{id}"))
}
fn file_path(id: &str) -> Option<String> {
    openmanuals_ledger::model::parse_file_ref(id).map(|f| format!("/file/{f}"))
}
fn key_path(fp: &str) -> Option<String> {
    openmanuals_core::fact::valid_fingerprint(fp.trim()).then(|| format!("/k/{}", fp.trim()))
}
fn fact_path(id: &str) -> Option<String> {
    let id = id.trim();
    let hex = id.strip_prefix("sha256:").unwrap_or(id);
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then(|| format!("/fact/sha256:{hex}"))
}

fn host(url: &str) -> String {
    openmanuals_ledger::model::host_of(url).unwrap_or_else(|| url.to_string())
}

fn short(s: &str, n: usize) -> String {
    let t = s.strip_prefix("sha256:").unwrap_or(s);
    t.chars().take(n).collect()
}

/// A one-line, human summary of a fact, and where it leads.
fn summarize(db: &Connection, r: &LedgerRow) -> (String, Option<String>) {
    let b = &r.fact.body;
    let s = |k: &str| b.get(k).and_then(Value::as_str).map(str::trim).unwrap_or("").to_string();
    let title_of = |id: &str| -> String {
        db.query_row("SELECT title FROM manuals WHERE id = ?1", [id.to_ascii_uppercase()], |r| r.get::<_, String>(0)).optional().ok().flatten().map(|t| format!("“{t}”")).unwrap_or_else(|| format!("manual {}", short(id, 10)))
    };
    match r.kind.as_str() {
        "manual" => (format!("Added the manual “{}”", if s("title").is_empty() { s("id") } else { s("title") }), manual_path(&s("id"))),
        "product" => (format!("Added the product {} {}", s("brand"), s("model")), None),
        "covers" => (format!("Linked {} to {}", title_of(&s("manual")), s("product")), manual_path(&s("manual"))),
        "file" => {
            let id = if s("sha256").is_empty() { format!("sha1:{}", s("sha1")) } else { s("sha256") };
            let size = b.get("size").and_then(Value::as_i64);
            (format!("Recorded a {}file {}", size.map(|n| format!("{} ", size_label(Some(n)))).unwrap_or_default(), short(&id, 10)), file_path(&id))
        }
        "manual_file" => (format!("Attached file {} to {}", short(&s("file"), 10), title_of(&s("manual"))), manual_path(&s("manual"))),
        "location" => (format!("Added {} copy at {}", if s("kind") == "origin" { "the origin page of a" } else { "a" }, host(&s("url"))), file_path(&s("file"))),
        "derivation" => (format!("Recorded a {} variant ({})", s("transform"), s("tool_version")), file_path(&s("derived"))),
        "verified" => {
            let how = if s("method") == "conditional" { "Re-checked an unchanged copy" } else { "Verified a copy" };
            (format!("{how} at {}", host(&s("final_url"))), None)
        }
        "location_status" => {
            let at = s("final_url");
            (if at.is_empty() { format!("Marked a copy {}", s("status")) } else { format!("Marked a copy at {} {}", host(&at), s("status")) }, None)
        }
        "same_as" => (format!("Merged duplicate {}s", s("kind")), None),
        "identity_profile" => {
            let name = openmanuals_core::asp::parse_and_verify(&s("jws")).ok().map(|p| p.name);
            (name.map(|n| format!("Published an identity profile as {n}")).unwrap_or_else(|| "Published an identity profile".into()), key_path(&r.author))
        }
        "identity_link" => (format!("Verified the {} account {} for key {}…", s("service"), s("handle"), short(&s("key"), 8)), key_path(&s("key"))),
        "avatar" => (if b.get("none").and_then(Value::as_bool) == Some(true) { "Removed their avatar".into() } else { "Changed their avatar".into() }, key_path(&r.author)),
        "succession" => (format!("Moved to a new key {}…", short(&s("new"), 8)), key_path(&s("new"))),
        "vouch" => (format!("Vouched for key {}…", short(&s("key"), 8)), key_path(&s("key"))),
        "label" if s("ns") == "report" => (format!("Reported {} as {}", short(&s("target"), 16), s("value")), None),
        "label" => (format!("Labeled {} {}:{}", short(&s("target"), 16), s("ns"), s("value")), None),
        "retract" => (format!("Retracted fact {}", short(&s("fact"), 10)), fact_path(&s("fact"))),
        "block" => (format!("Blocked {} {}", s("kind"), short(&s("value"), 24)), None),
        "unblock" => (format!("Unblocked {} {}", s("kind"), short(&s("value"), 24)), None),
        "prefer" => ("Chose a preferred download".into(), manual_path(&s("manual"))),
        other => (format!("Recorded a {other} fact"), None),
    }
}

fn row_json(db: &Connection, profiles: &mut Profiles, m: &Moderation, r: &LedgerRow) -> Value {
    let ms = cursor_ms(&r.cursor).unwrap_or(0);
    let hidden = m.hidden(r);
    let (summary, href) = if hidden { ("Hidden by moderation".to_string(), None) } else { summarize(db, r) };
    json!({
        "id": r.id, "short": short(&r.id, 7), "type": r.kind, "summary": summary, "href": href,
        "author": profiles.get(&r.author), "ago": ago(ms), "at": when(ms, "%Y-%m-%d %H:%M:%S UTC"),
        "day": when(ms, "%b %-d, %Y"), "pending": !r.folded, "hidden": hidden, "retracted": m.retracted(r),
    })
}

/// Rows grouped by UTC day, like GitHub's commit history. Runs of three or
/// more facts of one type from one author (the verifier's re-checks, an
/// upload's bundle) fold into their first row, which lists the rest.
fn by_day(rows: Vec<Value>) -> Vec<Value> {
    let mut groups: Vec<Value> = Vec::new();
    for r in rows {
        let day = r["day"].as_str().unwrap_or("").to_string();
        match groups.last_mut() {
            Some(g) if g["day"] == day => g["rows"].as_array_mut().unwrap().push(r),
            _ => groups.push(json!({"day": day, "rows": [r]})),
        }
    }
    let plain = |r: &Value| r["hidden"] != true && r["retracted"] != true;
    for g in &mut groups {
        let rows = std::mem::take(g["rows"].as_array_mut().unwrap());
        let mut out: Vec<Value> = Vec::new();
        let mut i = 0;
        while i < rows.len() {
            let mut j = i + 1;
            while j < rows.len() && plain(&rows[i]) && plain(&rows[j]) && rows[j]["type"] == rows[i]["type"] && rows[j]["author"]["fp"] == rows[i]["author"]["fp"] {
                j += 1;
            }
            let mut head = rows[i].clone();
            if j - i >= 3 {
                head["more"] = Value::Array(rows[i + 1..j].to_vec());
                i = j;
            } else {
                i += 1;
            }
            out.push(head);
        }
        g["rows"] = Value::Array(out);
    }
    groups
}

async fn with_reader<F>(state: Shared, f: F) -> Response
where
    F: FnOnce(&crate::config::State, &Connection) -> Response + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let Some(db) = state.reader() else { return no_snapshot() };
        f(&state, &db)
    })
    .await
    .unwrap_or_else(|_| no_snapshot())
}

pub async fn home(State(state): State<Shared>) -> Response {
    with_reader(state, |state, db| {
        let one = |sql: &str| -> i64 { db.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
        let stats = json!({
            "downloadable": grouped(one("SELECT count(*) FROM manual_search WHERE downloadable = 1")),
            "manuals": grouped(one("SELECT count(*) FROM manuals")),
            "contributors": grouped(one("SELECT count(*) FROM contributors")),
            "contributors_label": if one("SELECT count(*) FROM contributors") == 1 { "contributor" } else { "contributors" },
            "facts": grouped(state.inbox.count().unwrap_or(0)),
            "missing": grouped(state.contribute.counts(db)["total"].as_i64().unwrap_or(0)),
        });
        let mut brands = Vec::new();
        if let Ok(mut s) = db.prepare_cached("SELECT brand_key, brand, downloadable FROM brands WHERE downloadable > 0 ORDER BY downloadable DESC, brand LIMIT 24") {
            for r in s.query_map([], |r| Ok(json!({"key": r.get::<_, String>(0)?, "brand": r.get::<_, String>(1)?, "n": r.get::<_, i64>(2)?}))).into_iter().flatten().flatten() {
                brands.push(r);
            }
        }
        let m = state.inbox.moderation(|fp| state.trust.read().unwrap().is_moderator(fp)).unwrap_or_default();
        let (rows, _) = state.inbox.browse(None, None, None, None, 15).unwrap_or_default();
        let mut profiles = Profiles { db, state, memo: HashMap::new() };
        let rows: Vec<Value> = rows.iter().map(|r| row_json(db, &mut profiles, &m, r)).collect();
        let sites = state.contribute.site_counts(db);
        render("home.html", context! { stats => stats, brands => brands, sites => sites, groups => by_day(rows) })
    })
    .await
}

#[derive(Deserialize, Default)]
pub struct LedgerQuery {
    pub before: Option<String>,
    pub after: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub author: Option<String>,
}

const TYPES: &[&str] = &[
    "manual", "product", "covers", "file", "manual_file", "location", "derivation", "verified", "location_status",
    "identity_profile", "avatar", "identity_link", "label", "retract", "block",
];

pub async fn ledger(State(state): State<Shared>, Query(q): Query<LedgerQuery>) -> Response {
    with_reader(state, move |state, db| {
        let clean = |s: &Option<String>| s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
        let (before, after, kind, author) = (clean(&q.before), clean(&q.after), clean(&q.kind), clean(&q.author).map(|a| a.to_ascii_uppercase()));
        let (rows, more) = state.inbox.browse(before.as_deref(), after.as_deref(), kind.as_deref(), author.as_deref(), PAGE).unwrap_or_default();
        let m = state.inbox.moderation(|fp| state.trust.read().unwrap().is_moderator(fp)).unwrap_or_default();
        // Older/newer links: the edges of this page, if there is more that way.
        let newest = rows.first().map(|r| r.cursor.clone());
        let oldest = rows.last().map(|r| r.cursor.clone());
        let paging_newer = after.is_some() && before.is_none();
        let has_older = if paging_newer { true } else { more };
        let has_newer = if paging_newer { more } else { before.is_some() };
        let mut profiles = Profiles { db, state, memo: HashMap::new() };
        let filter_author = author.as_deref().map(|a| profiles.get(a));
        let rows: Vec<Value> = rows.iter().map(|r| row_json(db, &mut profiles, &m, r)).collect();
        let base = |extra: &str| -> String {
            let mut parts = Vec::new();
            if let Some(k) = &kind {
                parts.push(format!("type={}", urlencoding::encode(k)));
            }
            if let Some(a) = &author {
                parts.push(format!("author={a}"));
            }
            if !extra.is_empty() {
                parts.push(extra.to_string());
            }
            if parts.is_empty() { "/ledger".into() } else { format!("/ledger?{}", parts.join("&")) }
        };
        let older = (has_older && oldest.is_some()).then(|| base(&format!("before={}", oldest.unwrap())));
        let newer = (has_newer && newest.is_some()).then(|| base(&format!("after={}", newest.unwrap())));
        let types: Vec<Value> = TYPES.iter().map(|t| json!({"name": t, "active": kind.as_deref() == Some(*t)})).collect();
        render("ledger.html", context! {
            groups => by_day(rows), older => older, newer => newer, types => types, kind => kind,
            author => filter_author, author_fp => author, total => grouped(state.inbox.count().unwrap_or(0)),
        })
    })
    .await
}

pub async fn fact(State(state): State<Shared>, Path(id): Path<String>) -> Response {
    with_reader(state, move |state, db| {
        let id = if id.starts_with("sha256:") { id } else { format!("sha256:{id}") };
        let Ok(Some(r)) = state.inbox.fact(&id) else { return not_found() };
        let m = state.inbox.moderation(|fp| state.trust.read().unwrap().is_moderator(fp)).unwrap_or_default();
        let mut profiles = Profiles { db, state, memo: HashMap::new() };
        let row = row_json(db, &mut profiles, &m, &r);
        let hidden = m.hidden(&r);
        let sig = r.fact.sig.as_ref().map(|s| json!({
            "alg": serde_json::to_value(s.alg).ok(), "fmt": serde_json::to_value(s.fmt).ok(),
            "valid": r.fact.verify().is_ok(),
        }));
        let pretty = if hidden { None } else { serde_json::to_string_pretty(&r.fact).ok() };
        let file = if r.folded { openmanuals_ledger::ledger::cursor_date_path(&r.cursor).ok().map(|p| format!("ledger/{p}.jsonl")) } else { None };
        render("fact.html", context! { f => row, cursor => r.cursor, json => pretty, sig => sig, ledger_file => file, claimed_at => r.fact.at })
    })
    .await
}

/// `GET /api/fact/{id}`: one fact as stored, with its moderation state, for
/// the extension's confirmation window (which recomputes the id itself). A
/// fact hidden by moderation is reported without its content.
pub async fn fact_json(State(state): State<Shared>, Path(id): Path<String>) -> Response {
    let id = if id.starts_with("sha256:") { id } else { format!("sha256:{id}") };
    let ok = id.len() == 71 && id[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "not a fact id"}))).into_response();
    }
    tokio::task::spawn_blocking(move || {
        let Ok(Some(r)) = state.inbox.fact(&id) else {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "no such fact"}))).into_response();
        };
        let m = state.inbox.moderation(|fp| state.trust.read().unwrap().is_moderator(fp)).unwrap_or_default();
        let hidden = m.hidden(&r);
        Json(json!({
            "id": r.id, "cursor": r.cursor, "folded": r.folded, "hidden": hidden, "retracted": m.retracted(&r),
            "fact": if hidden { Value::Null } else { serde_json::to_value(&r.fact).unwrap_or(Value::Null) },
        }))
        .into_response()
    })
    .await
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
