//! Minimal JWS compact serialization (RFC 7515) with EdDSA (Ed25519).

use crate::{b64, Error, PublicKey, Result};
use serde_json::Value;

pub struct Parsed {
    pub header: Value,
    pub payload: Value,
    pub signature: Vec<u8>,
    /// `base64url(header) + "." + base64url(payload)`, the bytes that were signed.
    pub signing_input: String,
}

/// Split and decode a compact JWS without verifying it.
pub fn parse(compact: &str) -> Result<Parsed> {
    let parts: Vec<&str> = compact.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Signature("JWS must have three parts".into()));
    }
    let dec = |s: &str, what: &str| b64::decode(s).ok_or_else(|| Error::Signature(format!("JWS {what} is not base64url")));
    let header: Value = serde_json::from_slice(&dec(parts[0], "header")?)?;
    let payload: Value = serde_json::from_slice(&dec(parts[1], "payload")?)?;
    let signature = dec(parts[2], "signature")?;
    Ok(Parsed { header, payload, signature, signing_input: format!("{}.{}", parts[0], parts[1]) })
}

/// Check the signature of a parsed JWS against `key`, which must match the header's `alg`.
pub fn verify(parsed: &Parsed, key: &PublicKey) -> Result<()> {
    let alg = parsed.header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != key.alg().jose() {
        return Err(Error::Signature(format!("JWS alg {alg} does not match key {:?}", key.alg())));
    }
    key.verify_raw(parsed.signing_input.as_bytes(), &parsed.signature)
}

/// The signing input for a header and payload (members serialized in the order given).
pub fn signing_input(header: &Value, payload: &Value) -> String {
    format!(
        "{}.{}",
        b64::encode(serde_json::to_string(header).expect("json").as_bytes()),
        b64::encode(serde_json::to_string(payload).expect("json").as_bytes())
    )
}

/// Assemble the compact form from a signing input and a raw signature.
pub fn assemble(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", b64::encode(signature))
}
