//! Linking an OpenManuals key from an existing Keyoxide identity (the
//! OpenManuals "service provider" side). See "Linking from Keyoxide" in
//! README.md.
//!
//! The proof is always the key's own signed Ariadne profile: an external
//! identity is linked when that profile lists its URI (`openpgp4fpr:…` or
//! `aspe:…`). This module serves that list in the shapes Keyoxide's verifier
//! (doipjs) can read:
//!
//! - `aspe:<domain>:<fp>`: doipjs's ASPE provider reads the profile from
//!   `/.well-known/aspe/id/<fp>` (api.rs).
//! - `https://<domain>/k/<fp>`: doipjs's generic ActivityPub provider asks
//!   for `application/activity+json` and reads `attachment[].value`; NodeInfo
//!   names the service "openmanuals".
//! - `GET /api/key/<fp>`: plain JSON for a dedicated doipjs provider
//!   (tools/keyoxide-provider/openmanuals.js, not yet upstream).
//!
//! Everything reads the snapshot, so keys a moderator blocked (whose facts the
//! build drops) have no profile here.

use crate::config::{CachedQuery, Shared};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};

/// The media types an ActivityPub client asks for.
/// The key's profile on keyoxide.org: `https://keyoxide.org/aspe:<domain>:<FP>`.
/// Keyoxide fetches `https://<domain>/.well-known/aspe/id/<fp>`, so there is
/// no link when the ASP domain isn't publicly reachable: localhost and other
/// loopback names, `*.localhost`, `*.test`, IP addresses, or a domain with a port.
pub fn keyoxide_profile_url(domain: &str, fp: &str) -> Option<String> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let local = d.is_empty()
        || d.contains([':', '/', '[', ']', '@'])
        || d == "localhost"
        || d.ends_with(".localhost")
        || d.ends_with(".test")
        || !d.contains('.')
        || d.parse::<std::net::IpAddr>().is_ok();
    (!local && openmanuals_core::fact::valid_fingerprint(fp)).then(|| format!("https://keyoxide.org/{}", openmanuals_core::asp::aspe_uri(&d, fp)))
}

pub fn wants_activity_json(headers: &HeaderMap) -> bool {
    headers.get_all(header::ACCEPT).iter().filter_map(|v| v.to_str().ok()).any(|v| {
        let v = v.to_ascii_lowercase();
        v.contains("application/activity+json") || (v.contains("application/ld+json") && v.contains("activitystreams"))
    })
}

/// A Keyoxide identity URI (an OpenPGP key or an ASP profile), as doipjs
/// writes the fingerprint it checks proofs against.
pub fn is_identity_uri(uri: &str) -> bool {
    let u = uri.to_ascii_lowercase();
    u.starts_with("openpgp4fpr:") || u.starts_with("aspe:")
}

/// Where a claim or linked account can be opened: https links as they are,
/// Keyoxide identities on keyoxide.org, anything else not at all.
pub fn claim_href(uri: &str) -> Option<String> {
    if uri.starts_with("https://") {
        Some(uri.to_string())
    } else if is_identity_uri(uri) && uri.bytes().all(|b| b.is_ascii_alphanumeric() || b".:-_".contains(&b)) {
        Some(format!("https://keyoxide.org/{uri}"))
    } else {
        None
    }
}

/// A key's current profile as the snapshot has it, plus its verified links.
pub struct KeyProfile {
    pub fingerprint: String,
    pub name: String,
    pub description: Option<String>,
    pub claims: Vec<String>,
    pub jws: String,
    /// (service, handle, claim_uri) from server-signed `identity_link` facts.
    pub links: Vec<(String, String, String)>,
}

pub fn key_profile(db: &Connection, fp: &str) -> Option<KeyProfile> {
    let fp = fp.to_ascii_uppercase();
    if !openmanuals_core::fact::valid_fingerprint(&fp) {
        return None;
    }
    let jws: String = db.query_row_cached("SELECT profile_jws FROM keys WHERE fingerprint = ?1", [&fp], |r| r.get::<_, Option<String>>(0)).optional().ok().flatten().flatten()?;
    // The build checked it; checking again costs ~0.1 ms and keeps a
    // tampered snapshot from speaking for the key.
    let p = openmanuals_core::asp::parse_and_verify(&jws).ok().filter(|p| p.fingerprint == fp)?;
    let mut links = Vec::new();
    if let Ok(mut s) = db.prepare_cached("SELECT service, handle, claim_uri FROM identity_links WHERE key = ?1 ORDER BY service, handle") {
        links.extend(s.query_map([&fp], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).into_iter().flatten().flatten());
    }
    Some(KeyProfile { fingerprint: fp, name: p.name, description: p.description, claims: p.claims, jws, links })
}

fn not_found() -> Response {
    let mut r = (StatusCode::NOT_FOUND, Json(json!({"error": "no profile for that key"}))).into_response();
    r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    r
}

async fn with_profile(state: Shared, fp: String, f: impl FnOnce(&crate::config::State, KeyProfile) -> Response + Send + 'static) -> Response {
    tokio::task::spawn_blocking(move || {
        let Some(db) = state.reader() else { return crate::pages::no_snapshot() };
        match key_profile(&db, &fp) {
            Some(p) => f(&state, p),
            None => not_found(),
        }
    })
    .await
    .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

/// `GET /api/key/<fp>/stats`: how many facts the key has signed, counted in
/// the inbox so a fresh upload shows before the next fold. Answers for any
/// well-formed fingerprint, with or without a profile (0 when unknown).
pub async fn key_stats(State(state): State<Shared>, Path(fp): Path<String>) -> Response {
    if !openmanuals_core::fact::valid_fingerprint(&fp) {
        return not_found();
    }
    match tokio::task::spawn_blocking(move || state.inbox.count_by_author(&fp)).await {
        Ok(Ok(n)) => ([(axum::http::header::CACHE_CONTROL, "public, max-age=60")], Json(json!({"facts": n}))).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `GET /api/key/<fp>`: the key's profile and the external identities it
/// claims, for a doipjs provider to check (`claims` holds the proof).
pub async fn key_json(State(state): State<Shared>, Path(fp): Path<String>) -> Response {
    with_profile(state, fp, |st, p| {
        let domain = st.trust.read().unwrap().domain.clone();
        let identities: Vec<&String> = p.claims.iter().filter(|c| is_identity_uri(c)).collect();
        let links: Vec<Value> = p.links.iter().map(|(s, h, u)| json!({"service": s, "handle": h, "claim_uri": u})).collect();
        Json(json!({
            "fingerprint": p.fingerprint,
            "name": p.name,
            "description": p.description,
            "url": format!("{}/k/{}", st.paths.public_url, p.fingerprint),
            "aspe": openmanuals_core::asp::aspe_uri(&domain, &p.fingerprint),
            "claims": p.claims,
            "identities": identities,
            "links": links,
            "profile": p.jws,
        }))
        .into_response()
    })
    .await
}

/// `/k/<fp>` asked for as `application/activity+json`: an ActivityStreams
/// `Person` whose profile fields are the claims of the key's signed profile.
/// It is a read-only document (no inbox or outbox); it exists so Keyoxide's
/// ActivityPub provider can verify `https://<domain>/k/<fp>` claims.
pub async fn actor(state: Shared, fp: String) -> Response {
    with_profile(state, fp, |st, p| {
        let url = format!("{}/k/{}", st.paths.public_url, p.fingerprint);
        let attachment: Vec<Value> = p
            .claims
            .iter()
            .map(|c| json!({"type": "PropertyValue", "name": if is_identity_uri(c) { "Keyoxide" } else { "Claim" }, "value": c}))
            .collect();
        let body = json!({
            "@context": ["https://www.w3.org/ns/activitystreams", {"schema": "http://schema.org#", "PropertyValue": "schema:PropertyValue", "value": "schema:value"}],
            "type": "Person",
            "id": url,
            "url": url,
            "preferredUsername": p.fingerprint,
            "name": p.name,
            "summary": p.description.unwrap_or_default(),
            "attachment": attachment,
        });
        let mut r = Json(body).into_response();
        let h = r.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/activity+json; charset=utf-8"));
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        h.insert(header::VARY, HeaderValue::from_static("Accept"));
        r
    })
    .await
}

/// `/.well-known/nodeinfo`: where the NodeInfo document is. doipjs reads it
/// after an ActivityPub proof verifies, to name the service.
pub async fn nodeinfo_links(State(state): State<Shared>) -> Response {
    Json(json!({"links": [{"rel": "http://nodeinfo.diaspora.software/ns/schema/2.1", "href": format!("{}/nodeinfo/2.1", state.paths.public_url)}]})).into_response()
}

/// `/nodeinfo/2.1`.
pub async fn nodeinfo(State(state): State<Shared>) -> Response {
    let homepage = state.paths.public_url.clone();
    let users = tokio::task::spawn_blocking(move || {
        let db = state.reader()?;
        db.query_row_cached("SELECT count(*) FROM keys WHERE profile_jws IS NOT NULL", [], |r| r.get::<_, i64>(0)).ok()
    })
    .await
    .ok()
    .flatten();
    let mut r = Json(json!({
        "version": "2.1",
        "software": {"name": "openmanuals", "version": env!("CARGO_PKG_VERSION"), "homepage": homepage, "repository": env!("CARGO_PKG_REPOSITORY")},
        "protocols": ["activitypub"],
        "services": {"inbound": [], "outbound": []},
        "openRegistrations": true,
        "usage": {"users": users.map(|n| json!({"total": n})).unwrap_or_else(|| json!({}))},
        "metadata": {"nodeName": "OpenManuals"},
    }))
    .into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; profile=\"http://nodeinfo.diaspora.software/ns/schema/2.1#\""));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyoxide_links_only_for_public_domains() {
        let fp = "QPRGVPJNWDXH4ESK2RYDTZJLTE";
        assert_eq!(keyoxide_profile_url("openmanuals.org", fp).as_deref(), Some("https://keyoxide.org/aspe:openmanuals.org:QPRGVPJNWDXH4ESK2RYDTZJLTE"));
        assert_eq!(keyoxide_profile_url("OpenManuals.org.", fp).as_deref(), Some("https://keyoxide.org/aspe:openmanuals.org:QPRGVPJNWDXH4ESK2RYDTZJLTE"));
        for d in ["localhost", "localhost:8000", "openmanuals.org:8443", "127.0.0.1", "::1", "[::1]", "dev.localhost", "openmanuals.test", "203.0.113.5", "intranet", ""] {
            assert_eq!(keyoxide_profile_url(d, fp), None, "{d}");
        }
        assert_eq!(keyoxide_profile_url("openmanuals.org", "short"), None);
    }
}
