//! Passkey-wrapped copies of contributor keys (`/api/key-wrap/…`).
//!
//! The extension can protect its Ed25519 key with a passkey: the passkey's PRF
//! output derives an AES-GCM key that wraps the private key. The wrapped copy
//! is useless without the passkey, so it can be fetched by anyone, but it must
//! stay deletable, so it lives here in `keywrap.db` and never in the
//! append-only ledger. Writes are signed by the key itself over
//! [`message`], within [`WINDOW_SECS`] of the server clock, and each
//! signature is accepted once.

use anyhow::Result;
use openmanuals_core::key::PublicKey;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

/// How far a request's `at` may be from the server clock, either way.
pub const WINDOW_SECS: i64 = 300;
/// Largest `wrap` string accepted (a wrap is about 250 bytes).
pub const MAX_WRAP: usize = 4096;
/// Largest request body.
pub const MAX_BODY: usize = 16 * 1024;
/// Wrapped copies kept per key (one per passkey).
pub const MAX_PER_KEY: usize = 16;
/// Credential ids are at most 1023 bytes (WebAuthn), base64url-encoded.
pub const MAX_CREDENTIAL: usize = 1364;
/// Signed writes per key and UTC day.
pub const DAILY_WRITES: u64 = 50;

/// The signed message. `wrap_sha256` is the lowercase hex sha256 of the
/// `wrap` string's UTF-8 bytes for `PUT`, and empty for `DELETE`.
pub fn message(method: &str, fp: &str, credential: &str, wrap_sha256: &str, at: &str) -> String {
    format!("openmanuals key-wrap v1\n{method}\n{fp}\n{credential}\n{wrap_sha256}\n{at}")
}

pub fn valid_credential(c: &str) -> bool {
    (16..=MAX_CREDENTIAL).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Wrap {
    pub credential: String,
    pub wrap: String,
    pub updated_at: String,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AuthError {
    #[error("{0}")]
    Bad(String),
    #[error("key does not match the fingerprint")]
    WrongKey,
    #[error("signature does not verify")]
    Signature,
    #[error("`at` is more than {WINDOW_SECS} s from the server clock")]
    Stale,
    #[error("this signed request was already used")]
    Replay,
}

pub struct KeyWraps {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS wraps (
  fingerprint TEXT NOT NULL, credential TEXT NOT NULL, wrap TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (fingerprint, credential)
);
-- Signatures already accepted, kept for twice the window (replay protection).
CREATE TABLE IF NOT EXISTS seen (sig TEXT PRIMARY KEY, at INTEGER NOT NULL);
"#;

impl KeyWraps {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(KeyWraps { conn: Mutex::new(conn) })
    }

    pub fn list(&self, fp: &str) -> Result<Vec<Wrap>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT credential, wrap, updated_at FROM wraps WHERE fingerprint = ?1 ORDER BY updated_at, credential")?;
        let rows = stmt.query_map([fp], |r| Ok(Wrap { credential: r.get(0)?, wrap: r.get(1)?, updated_at: r.get(2)? }))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Check a signed request and record its signature as used. `now` is unix seconds.
    #[allow(clippy::too_many_arguments)]
    pub fn authenticate(&self, method: &str, fp: &str, credential: &str, wrap: Option<&str>, key: &serde_json::Value, at: &str, sig: &str, now: i64) -> Result<(), AuthError> {
        let pk = PublicKey::from_jwk(key).map_err(|e| AuthError::Bad(e.to_string()))?;
        if pk.fingerprint() != fp {
            return Err(AuthError::WrongKey);
        }
        let t: jiff::Timestamp = at.parse().map_err(|_| AuthError::Bad("`at` must be an RFC 3339 timestamp".into()))?;
        if (t.as_second() - now).abs() > WINDOW_SECS {
            return Err(AuthError::Stale);
        }
        let hash = wrap.map(|w| openmanuals_core::canon::sha256_hex(w.as_bytes())).unwrap_or_default();
        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig).map_err(|_| AuthError::Bad("`sig` must be base64url".into()))?;
        pk.verify_raw(message(method, fp, credential, &hash, at).as_bytes(), &sig_bytes).map_err(|_| AuthError::Signature)?;
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute("DELETE FROM seen WHERE at < ?1", [now - 2 * WINDOW_SECS]);
        let fresh = conn.execute("INSERT OR IGNORE INTO seen (sig, at) VALUES (?1, ?2)", params![sig, now]).map_err(|e| AuthError::Bad(e.to_string()))?;
        if fresh == 0 {
            return Err(AuthError::Replay);
        }
        Ok(())
    }

    /// Store or replace a wrap. Fails when the key already has [`MAX_PER_KEY`] other wraps.
    pub fn put(&self, fp: &str, credential: &str, wrap: &str, now: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn.query_row("SELECT 1 FROM wraps WHERE fingerprint = ?1 AND credential = ?2", [fp, credential], |_| Ok(true)).optional()?.unwrap_or(false);
        let n: usize = conn.query_row("SELECT COUNT(*) FROM wraps WHERE fingerprint = ?1", [fp], |r| r.get::<_, i64>(0))? as usize;
        if !exists && n >= MAX_PER_KEY {
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO wraps (fingerprint, credential, wrap, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (fingerprint, credential) DO UPDATE SET wrap = excluded.wrap, updated_at = excluded.updated_at",
            params![fp, credential, wrap, now],
        )?;
        Ok(true)
    }

    pub fn delete(&self, fp: &str, credential: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM wraps WHERE fingerprint = ?1 AND credential = ?2", [fp, credential])? > 0)
    }
}

// ---- HTTP ---------------------------------------------------------------------------

use crate::config::Shared;
use axum::{
    extract::{Path as UrlPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

#[derive(Deserialize)]
struct SignedBody {
    key: Value,
    at: String,
    sig: String,
    wrap: Option<String>,
}

fn parse(fp: &str, credential: &str, body: &[u8]) -> Result<SignedBody, (StatusCode, String)> {
    if !openmanuals_core::fact::valid_fingerprint(fp) {
        return Err((StatusCode::NOT_FOUND, "not a fingerprint".into()));
    }
    if !valid_credential(credential) {
        return Err((StatusCode::BAD_REQUEST, "credential id must be 16 to 1364 base64url characters".into()));
    }
    if body.len() > MAX_BODY {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, format!("body exceeds {MAX_BODY} bytes")));
    }
    serde_json::from_slice(body).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid body: {e}")))
}

fn auth_status(e: &AuthError) -> StatusCode {
    match e {
        AuthError::Bad(_) => StatusCode::BAD_REQUEST,
        AuthError::Replay => StatusCode::CONFLICT,
        _ => StatusCode::UNAUTHORIZED,
    }
}

fn blocked(st: &Shared, fp: &str) -> anyhow::Result<bool> {
    let trust = st.trust.read().unwrap().clone();
    Ok(st.inbox.blocked_keys(|a| trust.is_moderator(a))?.contains(fp))
}

/// `GET /api/key-wrap/<fp>`: the key's wrapped copies (possibly none).
pub async fn get_wraps(State(state): State<Shared>, UrlPath(fp): UrlPath<String>) -> Response {
    let fp = fp.to_ascii_uppercase();
    if !openmanuals_core::fact::valid_fingerprint(&fp) {
        return err(StatusCode::NOT_FOUND, "not a fingerprint");
    }
    let st = state.clone();
    let f = fp.clone();
    match tokio::task::spawn_blocking(move || st.key_wraps.list(&f)).await {
        Ok(Ok(wraps)) => Json(json!({"fingerprint": fp, "wraps": wraps})).into_response(),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `PUT /api/key-wrap/<fp>/<credential>`: store or replace one wrapped copy.
pub async fn put_wrap(State(state): State<Shared>, UrlPath((fp, credential)): UrlPath<(String, String)>, body: axum::body::Bytes) -> Response {
    write(state, "PUT", fp, credential, body).await
}

/// `DELETE /api/key-wrap/<fp>/<credential>`: remove one wrapped copy.
pub async fn delete_wrap(State(state): State<Shared>, UrlPath((fp, credential)): UrlPath<(String, String)>, body: axum::body::Bytes) -> Response {
    write(state, "DELETE", fp, credential, body).await
}

async fn write(state: Shared, method: &'static str, fp: String, credential: String, body: axum::body::Bytes) -> Response {
    let fp = fp.to_ascii_uppercase();
    let b = match parse(&fp, &credential, &body) {
        Ok(b) => b,
        Err((status, msg)) => return err(status, msg),
    };
    let wrap = if method == "PUT" {
        match &b.wrap {
            Some(w) if !w.is_empty() && w.len() <= MAX_WRAP => Some(w.clone()),
            Some(w) if w.len() > MAX_WRAP => return err(StatusCode::PAYLOAD_TOO_LARGE, format!("wrap exceeds {MAX_WRAP} bytes")),
            _ => return err(StatusCode::BAD_REQUEST, "missing wrap"),
        }
    } else {
        None
    };
    let st = state.clone();
    let r = tokio::task::spawn_blocking(move || -> Response {
        let now = jiff::Timestamp::now();
        if let Err(e) = st.key_wraps.authenticate(method, &fp, &credential, wrap.as_deref(), &b.key, &b.at, &b.sig, now.as_second()) {
            return err(auth_status(&e), e.to_string());
        }
        // Spent after the signature check, so nobody can exhaust another key's budget.
        if !st.budgets.spend(&fp, "keywrap", 1, DAILY_WRITES) {
            return (StatusCode::TOO_MANY_REQUESTS, [(axum::http::header::RETRY_AFTER, "3600")], Json(json!({"error": format!("daily budget of {DAILY_WRITES} key-wrap writes exhausted")}))).into_response();
        }
        let res = match wrap {
            Some(w) => match blocked(&st, &fp) {
                Ok(true) => return err(StatusCode::FORBIDDEN, "this key is blocked"),
                Ok(false) => st.key_wraps.put(&fp, &credential, &w, &now.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()).map(|ok| {
                    if ok { (StatusCode::OK, json!({"ok": true})) } else { (StatusCode::CONFLICT, json!({"error": format!("at most {MAX_PER_KEY} wrapped copies per key")})) }
                }),
                Err(e) => Err(e),
            },
            None => st.key_wraps.delete(&fp, &credential).map(|found| (StatusCode::OK, json!({"ok": true, "deleted": found}))),
        };
        match res {
            Ok((s, v)) => (s, Json(v)).into_response(),
            Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    })
    .await;
    r.unwrap_or_else(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmanuals_core::{sign::SigningKey, Alg};

    #[test]
    fn message_matches_the_extension() {
        // Same vector as extension/src/core/passkey.test.ts.
        let h = openmanuals_core::canon::sha256_hex(b"w");
        assert_eq!(
            message("PUT", "AAAAAAAAAAAAAAAAAAAAAAAAAA", "Y3JlZC1h", &h, "2026-10-31T12:00:00.000Z"),
            "openmanuals key-wrap v1\nPUT\nAAAAAAAAAAAAAAAAAAAAAAAAAA\nY3JlZC1h\n50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326\n2026-10-31T12:00:00.000Z"
        );
    }

    #[test]
    fn signed_requests() {
        let dir = tempfile::tempdir().unwrap();
        let kw = KeyWraps::open(&dir.path().join("kw.db")).unwrap();
        let k = SigningKey::generate(Alg::Ed25519);
        let fp = k.public_key().fingerprint();
        let jwk = k.public_key().to_jwk();
        let cred = "AAAAAAAAAAAAAAAAAAAAAA";
        let at = "2026-10-31T12:00:00Z";
        let now: jiff::Timestamp = at.parse().unwrap();
        let now = now.as_second();
        let hash = openmanuals_core::canon::sha256_hex(b"w");
        let sig = |m: &str| base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, k.sign_raw(m.as_bytes()));
        let s = sig(&message("PUT", &fp, cred, &hash, at));
        assert_eq!(kw.authenticate("PUT", &fp, cred, Some("x"), &jwk, at, &s, now), Err(AuthError::Signature));
        assert_eq!(kw.authenticate("DELETE", &fp, cred, None, &jwk, at, &s, now), Err(AuthError::Signature));
        assert_eq!(kw.authenticate("PUT", &fp, cred, Some("w"), &jwk, at, &s, now + 301), Err(AuthError::Stale));
        assert_eq!(kw.authenticate("PUT", &fp, cred, Some("w"), &jwk, at, &s, now), Ok(()));
        assert_eq!(kw.authenticate("PUT", &fp, cred, Some("w"), &jwk, at, &s, now), Err(AuthError::Replay));
        let other = SigningKey::generate(Alg::Ed25519).public_key().to_jwk();
        assert_eq!(kw.authenticate("PUT", &fp, cred, Some("w"), &other, at, &s, now), Err(AuthError::WrongKey));
        assert!(valid_credential(cred) && !valid_credential("short") && !valid_credential("AAAAAAAAAAAAAAAAAAAA/A=="));
        for i in 0..MAX_PER_KEY {
            assert!(kw.put(&fp, &format!("{cred}{i}"), "w", at).unwrap());
        }
        assert!(!kw.put(&fp, "BBBBBBBBBBBBBBBBBBBBBB", "w", at).unwrap(), "over the per-key limit");
        assert!(kw.put(&fp, &format!("{cred}0"), "w2", at).unwrap(), "replacing is fine");
        assert!(kw.delete(&fp, &format!("{cred}0")).unwrap());
        assert_eq!(kw.list(&fp).unwrap().len(), MAX_PER_KEY - 1);
    }
}
