//! Avatar images (`PUT /api/avatar/<sha256>`, `GET /avatar/<fingerprint>`).
//!
//! An `avatar` fact (see `openmanuals_core::avatar`) names a key's picture:
//! an uploaded image by sha256, a URL, or none. The fact goes through the
//! ledger like any other; the image bytes don't. The ledger is an
//! append-only git repository mirrored to forges, so anything in it stays
//! forever. Images live here instead, in `avatars.db`, keyed by sha256:
//!
//! - an upload is accepted only when some key's current avatar fact names
//!   its hash (post the fact first, then the bytes), so the store can't be
//!   used as general hosting;
//! - a URL avatar is fetched once by the server (through the verifier's
//!   guarded fetch) and stored the same way, so pages never hot-link it;
//! - [`Avatars::gc`] deletes every image no key's current avatar uses: a
//!   key's older pictures go once a newer avatar fact (or a block or
//!   retraction) is in.
//!
//! "Current" is the newest avatar fact of the key, by ingestion cursor, that
//! no moderator blocked and its author didn't retract: the rule the snapshot
//! build applies too.

use crate::config::Shared;
use crate::inbox::{Inbox, Moderation};
use anyhow::Result;
use openmanuals_core::avatar::{self, Avatar};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, RwLock};

/// A failed URL fetch is retried after this long.
pub const RETRY_SECS: i64 = 24 * 3600;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS blobs (
  sha256 TEXT PRIMARY KEY, mime TEXT NOT NULL, width INTEGER NOT NULL, height INTEGER NOT NULL,
  bytes BLOB NOT NULL, stored_at TEXT NOT NULL
);
-- What the server fetched for a URL avatar: the image's sha256, or why it failed.
CREATE TABLE IF NOT EXISTS url_copies (url TEXT PRIMARY KEY, sha256 TEXT, error TEXT, fetched_at INTEGER NOT NULL);
"#;

/// The image served for a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    pub sha256: String,
    pub mime: String,
}

pub struct Avatars {
    conn: Mutex<Connection>,
    /// fingerprint → the image served for it (only keys whose image is stored).
    index: RwLock<HashMap<String, Served>>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum UploadError {
    #[error("the body's sha256 is not the one in the URL")]
    WrongHash,
    #[error("{0}")]
    BadImage(String),
    #[error("no key's current avatar fact names this image; post the avatar fact first")]
    Unreferenced,
    #[error("the image doesn't match its avatar fact ({0})")]
    Mismatch(String),
}

/// Each key's current avatar fact (id and body), from the inbox under `m`.
pub fn current(inbox: &Inbox, m: &Moderation) -> Result<BTreeMap<String, (String, Avatar)>> {
    let mut out = BTreeMap::new();
    for e in inbox.by_type("avatar")? {
        let author = &e.fact.author;
        if m.keys.contains(author) || m.facts.contains(&e.id) || m.retracted.get(&e.id).is_some_and(|a| a.contains(author)) {
            continue;
        }
        if let Ok(a) = avatar::parse(&e.fact.body) {
            out.insert(author.clone(), (e.id, a));
        }
    }
    Ok(out)
}

/// The image hashes `current` needs kept, and the URLs it uses.
fn wanted(conn: &Connection, current: &BTreeMap<String, (String, Avatar)>) -> rusqlite::Result<(HashSet<String>, HashSet<String>)> {
    let (mut shas, mut urls) = (HashSet::new(), HashSet::new());
    for (_, a) in current.values() {
        match a {
            Avatar::Image { sha256, .. } => drop(shas.insert(sha256.clone())),
            Avatar::Url(u) => {
                if let Some(Some(sha)) = conn.query_row("SELECT sha256 FROM url_copies WHERE url = ?1", [u], |r| r.get::<_, Option<String>>(0)).optional()? {
                    shas.insert(sha);
                }
                urls.insert(u.clone());
            }
            Avatar::None => {}
        }
    }
    Ok((shas, urls))
}

impl Avatars {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Avatars { conn: Mutex::new(conn), index: RwLock::new(HashMap::new()) })
    }

    /// What to serve for `fp`, if anything.
    pub fn served(&self, fp: &str) -> Option<Served> {
        self.index.read().unwrap().get(fp).cloned()
    }

    pub fn blob(&self, sha256: &str) -> Result<Option<(String, Vec<u8>)>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT mime, bytes FROM blobs WHERE sha256 = ?1", [sha256], |r| Ok((r.get(0)?, r.get(1)?))).optional()?)
    }

    pub fn blob_count(&self) -> Result<i64> {
        Ok(self.conn.lock().unwrap().query_row("SELECT count(*) FROM blobs", [], |r| r.get(0))?)
    }

    /// Check the image and store it, after checking `current` references it.
    pub fn upload(&self, current: &BTreeMap<String, (String, Avatar)>, sha256: &str, bytes: &[u8]) -> Result<(), UploadError> {
        if openmanuals_core::canon::sha256_hex(bytes) != sha256 {
            return Err(UploadError::WrongHash);
        }
        let info = avatar::inspect(bytes).map_err(|e| UploadError::BadImage(e.to_string()))?;
        let mut referenced = false;
        for (_, a) in current.values() {
            if let Avatar::Image { sha256: s, size, mime } = a {
                if s == sha256 {
                    referenced = true;
                    if *size != bytes.len() as u64 {
                        return Err(UploadError::Mismatch(format!("size {} ≠ {size}", bytes.len())));
                    }
                    if mime != info.mime {
                        return Err(UploadError::Mismatch(format!("the bytes are {}, the fact says {mime}", info.mime)));
                    }
                }
            }
        }
        if !referenced {
            return Err(UploadError::Unreferenced);
        }
        self.store(sha256, &info, bytes).map_err(|e| UploadError::BadImage(e.to_string()))
    }

    fn store(&self, sha256: &str, info: &avatar::ImageInfo, bytes: &[u8]) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO blobs (sha256, mime, width, height, bytes, stored_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![sha256, info.mime, info.width, info.height, bytes, crate::config::State::now()],
        )?;
        Ok(())
    }

    /// URL avatars in `current` without a copy, or whose last fetch failed
    /// more than [`RETRY_SECS`] before `now` (unix seconds).
    pub fn pending_urls(&self, current: &BTreeMap<String, (String, Avatar)>, now: i64) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut out = Vec::new();
        for (_, a) in current.values() {
            let Avatar::Url(u) = a else { continue };
            let row: Option<(Option<String>, i64)> = conn.query_row("SELECT sha256, fetched_at FROM url_copies WHERE url = ?1", [u], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            let due = match row {
                None => true,
                Some((Some(_), _)) => false,
                Some((None, at)) => now - at >= RETRY_SECS,
            };
            if due && !out.contains(u) {
                out.push(u.clone());
            }
        }
        Ok(out)
    }

    /// Record the result of fetching a URL avatar: check and store the image.
    pub fn record_fetch(&self, url: &str, fetched: Result<Vec<u8>>, now: i64) -> Result<std::result::Result<String, String>> {
        let outcome = fetched.map_err(|e| e.to_string()).and_then(|bytes| {
            let info = avatar::inspect(&bytes).map_err(|e| e.to_string())?;
            let sha = openmanuals_core::canon::sha256_hex(&bytes);
            self.store(&sha, &info, &bytes).map_err(|e| e.to_string())?;
            Ok(sha)
        });
        let (sha, err) = match &outcome {
            Ok(s) => (Some(s.clone()), None),
            Err(e) => (None, Some(e.clone())),
        };
        self.conn.lock().unwrap().execute(
            "INSERT INTO url_copies (url, sha256, error, fetched_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (url) DO UPDATE SET sha256 = excluded.sha256, error = excluded.error, fetched_at = excluded.fetched_at",
            params![url, sha, err, now],
        )?;
        Ok(outcome)
    }

    /// Delete images and URL copies no key's current avatar uses. Returns how many images went.
    pub fn gc(&self, current: &BTreeMap<String, (String, Avatar)>) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let (shas, urls) = wanted(&conn, current)?;
        let all: Vec<String> = conn.prepare("SELECT sha256 FROM blobs")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        let mut n = 0;
        for s in all.iter().filter(|s| !shas.contains(*s)) {
            n += conn.execute("DELETE FROM blobs WHERE sha256 = ?1", [s])?;
        }
        let copies: Vec<String> = conn.prepare("SELECT url FROM url_copies")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        for u in copies.iter().filter(|u| !urls.contains(*u)) {
            conn.execute("DELETE FROM url_copies WHERE url = ?1", [u])?;
        }
        Ok(n)
    }

    /// Rebuild the fingerprint → image index from `current`.
    pub fn reindex(&self, current: &BTreeMap<String, (String, Avatar)>) -> Result<()> {
        let mut index = HashMap::new();
        {
            let conn = self.conn.lock().unwrap();
            let mime_of = |sha: &str| conn.query_row("SELECT mime FROM blobs WHERE sha256 = ?1", [sha], |r| r.get::<_, String>(0)).optional();
            for (fp, (_, a)) in current {
                let sha = match a {
                    Avatar::Image { sha256, .. } => Some(sha256.clone()),
                    Avatar::Url(u) => conn.query_row("SELECT sha256 FROM url_copies WHERE url = ?1", [u], |r| r.get::<_, Option<String>>(0)).optional()?.flatten(),
                    Avatar::None => None,
                };
                if let Some(sha) = sha {
                    if let Some(mime) = mime_of(&sha)? {
                        index.insert(fp.clone(), Served { sha256: sha, mime });
                    }
                }
            }
        }
        *self.index.write().unwrap() = index;
        Ok(())
    }
}

/// Current avatars under the moderation in effect now.
pub fn current_now(state: &crate::config::State) -> Result<BTreeMap<String, (String, Avatar)>> {
    let trust = state.trust.read().unwrap().clone();
    let m = state.inbox.moderation(|a| trust.is_moderator(a))?;
    current(&state.inbox, &m)
}

/// Fetch pending URL avatars, drop images nothing uses, and refresh what is
/// served. Run after avatar or moderation facts arrive, at startup and with
/// each verifier pass.
pub async fn refresh(state: Shared) -> Result<()> {
    let st = state.clone();
    let (cur, pending) = tokio::task::spawn_blocking(move || -> Result<_> {
        let cur = current_now(&st)?;
        let pending = st.avatars.pending_urls(&cur, jiff::Timestamp::now().as_second())?;
        Ok((cur, pending))
    })
    .await??;
    for url in &pending {
        let got = crate::verify::fetch_small(url, avatar::MAX_BYTES).await;
        match state.avatars.record_fetch(url, got, jiff::Timestamp::now().as_second())? {
            Ok(sha) => tracing::info!(%url, %sha, "fetched avatar"),
            Err(e) => tracing::warn!(%url, error = %e, "avatar fetch failed"),
        }
    }
    let st = state.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let n = st.avatars.gc(&cur)?;
        if n > 0 {
            tracing::info!(n, "removed unused avatar images");
        }
        st.avatars.reindex(&cur)
    })
    .await??;
    Ok(())
}

/// Facts whose arrival can change which avatar a key has.
pub fn affects_avatars(t: &str) -> bool {
    matches!(t, "avatar" | "block" | "unblock" | "retract")
}

// ---- HTTP ---------------------------------------------------------------------------

use axum::{
    extract::{Path as UrlPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

fn valid_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `PUT /api/avatar/<sha256>`: the bytes of an image some key's current
/// avatar fact names.
pub async fn put(State(state): State<Shared>, UrlPath(sha): UrlPath<String>, body: axum::body::Bytes) -> Response {
    if !valid_sha(&sha) {
        return err(StatusCode::BAD_REQUEST, "not a lowercase sha256");
    }
    if body.len() as u64 > avatar::MAX_BYTES {
        return err(StatusCode::PAYLOAD_TOO_LARGE, format!("images are at most {} bytes", avatar::MAX_BYTES));
    }
    let st = state.clone();
    let r = tokio::task::spawn_blocking(move || -> Result<Response> {
        let cur = current_now(&st)?;
        Ok(match st.avatars.upload(&cur, &sha, &body) {
            Ok(()) => {
                st.avatars.reindex(&cur)?;
                (StatusCode::OK, Json(json!({"ok": true, "sha256": sha}))).into_response()
            }
            Err(e @ UploadError::Unreferenced) => err(StatusCode::CONFLICT, e.to_string()),
            Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
        })
    })
    .await;
    match r {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(serde::Deserialize)]
pub struct GetQuery {
    /// A prefix of the image's sha256 (cache busting); the response is then immutable.
    pub v: Option<String>,
}

/// `GET /avatar/<fingerprint>`: the key's current avatar image, or 404.
pub async fn get(State(state): State<Shared>, UrlPath(fp): UrlPath<String>, Query(q): Query<GetQuery>, headers: HeaderMap) -> Response {
    let fp = fp.to_ascii_uppercase();
    let Some(served) = state.avatars.served(&fp) else { return (StatusCode::NOT_FOUND, "no avatar").into_response() };
    let etag = format!("\"{}\"", served.sha256);
    let immutable = q.v.as_deref().is_some_and(|v| v.len() >= 8 && served.sha256.starts_with(v));
    let cache = if immutable { "public, max-age=31536000, immutable" } else { "public, max-age=300" };
    let mut h = HeaderMap::new();
    h.insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(',').any(|t| t.trim() == etag)) {
        return (StatusCode::NOT_MODIFIED, h).into_response();
    }
    let st = state.clone();
    let sha = served.sha256.clone();
    match tokio::task::spawn_blocking(move || st.avatars.blob(&sha)).await {
        Ok(Ok(Some((mime, bytes)))) => {
            h.insert(header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap_or(HeaderValue::from_static("application/octet-stream")));
            (StatusCode::OK, h, bytes).into_response()
        }
        Ok(Ok(None)) => (StatusCode::NOT_FOUND, "no avatar").into_response(),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// HTML for a key's picture on the server's pages: its avatar when one is
/// served, else the identicon.
pub fn html(state: &crate::config::State, fp: &str) -> String {
    match state.avatars.served(fp) {
        Some(s) => format!(r#"<img class="avatar-img" src="/avatar/{fp}?v={}" alt="" width="40" height="40" loading="lazy" decoding="async">"#, &s.sha256[..16]),
        None => crate::activity::identicon(fp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmanuals_core::{sign::SigningKey, Alg, Fact};
    use serde_json::json;

    fn png(w: u32, h: u32, pad: usize) -> Vec<u8> {
        let mut b = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        b.extend_from_slice(&w.to_be_bytes());
        b.extend_from_slice(&h.to_be_bytes());
        b.extend_from_slice(&[8, 6, 0, 0, 0]);
        b.resize(b.len() + pad, 0);
        b
    }

    struct T {
        _dir: tempfile::TempDir,
        inbox: Inbox,
        av: Avatars,
    }

    fn setup() -> T {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::open(&dir.path().join("inbox.db")).unwrap();
        let av = Avatars::open(&dir.path().join("avatars.db")).unwrap();
        T { _dir: dir, inbox, av }
    }

    fn post(inbox: &Inbox, k: &SigningKey, t: &str, body: serde_json::Value) -> String {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut f = Fact::new(t, "x", &format!("2026-10-31T12:{:02}:{:02}Z", n / 60 % 60, n % 60), body);
        k.sign_fact(&mut f).unwrap();
        let r = inbox.accept(&[f], |_| Ok(())).unwrap();
        assert_eq!(r.accepted.len(), 1, "{:?}", r.rejected);
        r.accepted[0].clone()
    }

    fn image_fact(bytes: &[u8], mime: &str) -> serde_json::Value {
        json!({"sha256": openmanuals_core::canon::sha256_hex(bytes), "size": bytes.len(), "mime": mime})
    }

    #[test]
    fn uploads_need_a_current_fact_and_a_good_image() {
        let t = setup();
        let k = SigningKey::generate(Alg::Ed25519);
        let fp = k.public_key().fingerprint();
        let img = png(256, 256, 100);
        let sha = openmanuals_core::canon::sha256_hex(&img);
        let none = Moderation::default();
        let cur = |t: &T| current(&t.inbox, &none).unwrap();

        assert_eq!(t.av.upload(&cur(&t), &sha, &img), Err(UploadError::Unreferenced), "no fact yet");
        post(&t.inbox, &k, "avatar", image_fact(&img, "image/png"));
        assert_eq!(t.av.upload(&cur(&t), &"0".repeat(64), &img), Err(UploadError::WrongHash));
        let svg = b"<svg xmlns='http://www.w3.org/2000/svg'/>".to_vec();
        post(&t.inbox, &k, "avatar", image_fact(&svg, "image/png"));
        assert!(matches!(t.av.upload(&cur(&t), &openmanuals_core::canon::sha256_hex(&svg), &svg), Err(UploadError::BadImage(_))), "SVG is never accepted");
        let huge = png(1024, 1024, 100);
        post(&t.inbox, &k, "avatar", image_fact(&huge, "image/png"));
        assert!(matches!(t.av.upload(&cur(&t), &openmanuals_core::canon::sha256_hex(&huge), &huge), Err(UploadError::BadImage(_))), "too many pixels");
        let big = png(64, 64, avatar::MAX_BYTES as usize);
        assert!(matches!(t.av.upload(&cur(&t), &openmanuals_core::canon::sha256_hex(&big), &big), Err(UploadError::BadImage(_))), "too many bytes");
        // The fact says WebP; the bytes are PNG.
        post(&t.inbox, &k, "avatar", image_fact(&img, "image/webp"));
        assert!(matches!(t.av.upload(&cur(&t), &sha, &img), Err(UploadError::Mismatch(_))));
        // An older fact naming the image doesn't count: only the current one.
        let older = png(128, 128, 10);
        let older_sha = openmanuals_core::canon::sha256_hex(&older);
        post(&t.inbox, &k, "avatar", image_fact(&older, "image/png"));
        post(&t.inbox, &k, "avatar", image_fact(&img, "image/png"));
        assert_eq!(t.av.upload(&cur(&t), &older_sha, &older), Err(UploadError::Unreferenced));
        t.av.upload(&cur(&t), &sha, &img).unwrap();
        t.av.reindex(&cur(&t)).unwrap();
        assert_eq!(t.av.served(&fp), Some(Served { sha256: sha.clone(), mime: "image/png".into() }));
        assert_eq!(t.av.blob(&sha).unwrap().unwrap().1, img);
    }

    #[test]
    fn newer_avatars_retractions_and_blocks_free_old_images() {
        let t = setup();
        let k = SigningKey::generate(Alg::Ed25519);
        let fp = k.public_key().fingerprint();
        let (a, b) = (png(64, 64, 1), png(64, 64, 2));
        let (sa, sb) = (openmanuals_core::canon::sha256_hex(&a), openmanuals_core::canon::sha256_hex(&b));
        let none = Moderation::default();
        post(&t.inbox, &k, "avatar", image_fact(&a, "image/png"));
        t.av.upload(&current(&t.inbox, &none).unwrap(), &sa, &a).unwrap();
        let fb = post(&t.inbox, &k, "avatar", image_fact(&b, "image/png"));
        let cur = current(&t.inbox, &none).unwrap();
        t.av.upload(&cur, &sb, &b).unwrap();
        assert_eq!(t.av.blob_count().unwrap(), 2);
        assert_eq!(t.av.gc(&cur).unwrap(), 1, "the older picture goes");
        assert!(t.av.blob(&sa).unwrap().is_none() && t.av.blob(&sb).unwrap().is_some());

        // Retracting the current one: the previous fact is current again (its image must be uploaded again).
        let mut m = Moderation::default();
        m.retracted.insert(fb.clone(), vec![fp.clone()]);
        let cur = current(&t.inbox, &m).unwrap();
        assert_eq!(cur[&fp].1, Avatar::Image { sha256: sa.clone(), size: a.len() as u64, mime: "image/png".into() });
        assert_eq!(t.av.gc(&cur).unwrap(), 1, "the retracted picture goes");
        t.av.reindex(&cur).unwrap();
        assert_eq!(t.av.served(&fp), None, "nothing to serve until it's uploaded again");

        // A moderator blocks the key: nothing is current, nothing kept.
        t.av.upload(&cur, &sa, &a).unwrap();
        let mut m = Moderation::default();
        m.keys.insert(fp.clone());
        let cur = current(&t.inbox, &m).unwrap();
        assert!(cur.is_empty());
        assert_eq!(t.av.gc(&cur).unwrap(), 1);
        assert_eq!(t.av.blob_count().unwrap(), 0);

        // {none: true}: back to the identicon.
        post(&t.inbox, &k, "avatar", json!({"none": true}));
        let cur = current(&t.inbox, &Moderation::default()).unwrap();
        assert_eq!(cur[&fp].1, Avatar::None);
    }

    #[test]
    fn url_avatars_are_copied_and_their_copies_collected() {
        let t = setup();
        let k = SigningKey::generate(Alg::Ed25519);
        let fp = k.public_key().fingerprint();
        let url = "https://github.com/alice.png";
        post(&t.inbox, &k, "avatar", json!({"url": url}));
        let cur = current(&t.inbox, &Moderation::default()).unwrap();
        assert_eq!(t.av.pending_urls(&cur, 1000).unwrap(), vec![url.to_string()]);
        // A failed fetch is retried a day later.
        assert!(t.av.record_fetch(url, Err(anyhow::anyhow!("HTTP 500")), 1000).unwrap().is_err());
        assert!(t.av.pending_urls(&cur, 1000 + 60).unwrap().is_empty());
        assert_eq!(t.av.pending_urls(&cur, 1000 + RETRY_SECS).unwrap().len(), 1);
        // Not an image: refused and recorded as an error.
        assert!(t.av.record_fetch(url, Ok(b"<html>".to_vec()), 2000).unwrap().is_err());
        let img = png(100, 100, 5);
        let sha = t.av.record_fetch(url, Ok(img.clone()), 3000).unwrap().unwrap();
        assert!(t.av.pending_urls(&cur, 999_999).unwrap().is_empty(), "fetched once");
        t.av.gc(&cur).unwrap();
        t.av.reindex(&cur).unwrap();
        assert_eq!(t.av.served(&fp).unwrap().sha256, sha);
        // A newer avatar fact: the copy and the URL record go.
        post(&t.inbox, &k, "avatar", json!({"none": true}));
        let cur = current(&t.inbox, &Moderation::default()).unwrap();
        assert_eq!(t.av.gc(&cur).unwrap(), 1);
        assert_eq!(t.av.pending_urls(&current(&t.inbox, &Moderation::default()).unwrap(), 0).unwrap().len(), 0);
    }
}
