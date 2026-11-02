//! Ariadne Signature Profiles (version 0): the identity document of a key.

use crate::{jws, Error, PublicKey, Result};
use serde_json::Value;

pub const NS: &str = "http://ariadne.id/";

#[derive(Debug, Clone)]
pub struct Profile {
    pub key: PublicKey,
    pub fingerprint: String,
    pub name: String,
    pub claims: Vec<String>,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub email: Option<String>,
    /// RFC 7519 `exp`, seconds since the epoch.
    pub exp: Option<i64>,
    pub payload: Value,
}

/// Parse a profile JWS, verify its signature and check that `kid` is the key's fingerprint.
pub fn parse_and_verify(compact: &str) -> Result<Profile> {
    let parsed = jws::parse(compact)?;
    let h = &parsed.header;
    if h.get("typ").and_then(Value::as_str) != Some("JWT") {
        return Err(Error::Profile("header typ must be JWT".into()));
    }
    let jwk = h.get("jwk").ok_or_else(|| Error::Profile("header missing jwk".into()))?;
    let key = PublicKey::from_jwk(jwk)?;
    let fingerprint = key.fingerprint();
    let kid = h.get("kid").and_then(Value::as_str).unwrap_or("");
    if !kid.eq_ignore_ascii_case(&fingerprint) {
        return Err(Error::Profile(format!("kid {kid} is not the key's fingerprint {fingerprint}")));
    }
    jws::verify(&parsed, &key)?;

    let p = &parsed.payload;
    let get = |k: &str| p.get(format!("{NS}{k}"));
    if get("version").and_then(Value::as_i64) != Some(0) {
        return Err(Error::Profile("unsupported profile version".into()));
    }
    if get("type").and_then(Value::as_str) != Some("profile") {
        return Err(Error::Profile("type must be profile".into()));
    }
    let name = get("name").and_then(Value::as_str).ok_or_else(|| Error::Profile("missing name".into()))?.to_string();
    let claims = get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Profile("missing claims".into()))?
        .iter()
        .map(|c| c.as_str().map(str::to_string).ok_or_else(|| Error::Profile("claims must be strings".into())))
        .collect::<Result<Vec<_>>>()?;
    let opt = |k: &str| get(k).and_then(Value::as_str).map(str::to_string);
    Ok(Profile {
        key,
        fingerprint,
        name,
        claims,
        description: opt("description"),
        avatar_url: opt("avatar_url"),
        email: opt("email"),
        exp: p.get("exp").and_then(Value::as_i64),
        payload: p.clone(),
    })
}

/// The unsigned header and payload for a new profile, ready for `jws::signing_input`.
pub fn build(key: &PublicKey, name: &str, claims: &[String], description: Option<&str>) -> (Value, Value) {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": key.alg().jose(),
        "kid": key.fingerprint(),
        "jwk": key.to_jwk(),
    });
    let mut payload = serde_json::Map::new();
    payload.insert(format!("{NS}version"), 0.into());
    payload.insert(format!("{NS}type"), "profile".into());
    payload.insert(format!("{NS}name"), name.into());
    payload.insert(format!("{NS}claims"), claims.iter().map(|c| Value::from(c.as_str())).collect());
    if let Some(d) = description {
        payload.insert(format!("{NS}description"), d.into());
    }
    (header, Value::Object(payload))
}

/// The `aspe:` URI of a profile hosted on `domain`.
pub fn aspe_uri(domain: &str, fingerprint: &str) -> String {
    format!("aspe:{domain}:{}", fingerprint.to_ascii_uppercase())
}
