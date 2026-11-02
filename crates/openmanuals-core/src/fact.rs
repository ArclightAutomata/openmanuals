//! The signed fact envelope.
//!
//! ```json
//! {"v":1,"type":"file","author":"<fingerprint>","at":"2026-10-23T18:00:00Z",
//!  "body":{…},"sig":{"alg":"Ed25519","fmt":"raw","key":{…jwk…},"value":"<base64url>"}}
//! ```
//!
//! The canonical form is the RFC 8785 serialization of the envelope without
//! `sig`; the fact id is `sha256:<hex>` of that; the signature is over those
//! same bytes.

use crate::{b64, canon, Alg, Error, PublicKey, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const FACT_VERSION: u32 = 1;
/// Facts larger than this (as submitted JSON) are rejected by the inbox.
pub const MAX_FACT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigFmt {
    /// Raw Ed25519 (64 bytes), base64url without padding. The only format.
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sig {
    pub alg: Alg,
    pub fmt: SigFmt,
    /// Public JWK of the signing key.
    pub key: Value,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub v: u32,
    #[serde(rename = "type")]
    pub r#type: String,
    /// Fingerprint of the signing key.
    pub author: String,
    /// RFC 3339 UTC timestamp, author-asserted.
    pub at: String,
    pub body: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Sig>,
}

fn valid_type(t: &str) -> bool {
    !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

pub fn valid_fingerprint(f: &str) -> bool {
    f.len() == 26 && f.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

/// `YYYY-MM-DDTHH:MM:SSZ`, optionally with fractional seconds.
pub fn valid_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 || b[b.len() - 1] != b'Z' {
        return false;
    }
    let fixed = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    for (i, c) in fixed {
        if b[i] != c {
            return false;
        }
    }
    let digits = [0..4, 5..7, 8..10, 11..13, 14..16, 17..19];
    if !digits.iter().all(|r| b[r.clone()].iter().all(u8::is_ascii_digit)) {
        return false;
    }
    let rest = &b[19..b.len() - 1];
    rest.is_empty() || (rest[0] == b'.' && rest.len() > 1 && rest[1..].iter().all(u8::is_ascii_digit))
}

impl Fact {
    pub fn new(r#type: &str, author: &str, at: &str, body: Value) -> Self {
        Fact { v: FACT_VERSION, r#type: r#type.to_string(), author: author.to_string(), at: at.to_string(), body, sig: None }
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("fact serializes")
    }

    /// Structural checks that don't need the signature.
    pub fn validate_shape(&self) -> Result<()> {
        if self.v != FACT_VERSION {
            return Err(Error::Fact(format!("unsupported version {}", self.v)));
        }
        if !valid_type(&self.r#type) {
            return Err(Error::Fact(format!("bad type {:?}", self.r#type)));
        }
        if !valid_fingerprint(&self.author) {
            return Err(Error::Fact(format!("bad author fingerprint {:?}", self.author)));
        }
        if !valid_timestamp(&self.at) {
            return Err(Error::Fact(format!("bad timestamp {:?}", self.at)));
        }
        if !self.body.is_object() {
            return Err(Error::Fact("body must be an object".into()));
        }
        Ok(())
    }

    /// The RFC 8785 canonical form of the envelope without `sig`.
    pub fn canonical(&self) -> Result<String> {
        let unsigned = Fact { sig: None, ..self.clone() };
        canon::canonical_json(&serde_json::to_value(unsigned)?)
    }

    /// `sha256:<hex>` of the canonical form.
    pub fn id(&self) -> Result<String> {
        Ok(format!("sha256:{}", canon::sha256_hex(self.canonical()?.as_bytes())))
    }

    /// The signing key, parsed from `sig.key`.
    pub fn public_key(&self) -> Result<PublicKey> {
        let sig = self.sig.as_ref().ok_or_else(|| Error::Fact("fact is unsigned".into()))?;
        PublicKey::from_jwk(&sig.key)
    }

    /// Full check: shape, key matches `author`, algorithm matches, signature verifies.
    pub fn verify(&self) -> Result<()> {
        self.validate_shape()?;
        let sig = self.sig.as_ref().ok_or_else(|| Error::Fact("fact is unsigned".into()))?;
        let key = PublicKey::from_jwk(&sig.key)?;
        if key.alg() != sig.alg {
            return Err(Error::Signature(format!("sig.alg {:?} does not match key", sig.alg)));
        }
        let fp = key.fingerprint();
        if fp != self.author {
            return Err(Error::Signature(format!("author {} is not the signing key's fingerprint {fp}", self.author)));
        }
        let msg = self.canonical()?;
        match sig.fmt {
            SigFmt::Raw => {
                let raw = b64::decode(&sig.value).ok_or_else(|| Error::Signature("sig.value is not base64url".into()))?;
                key.verify_raw(msg.as_bytes(), &raw)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_excludes_sig_and_sorts() {
        let mut f = Fact::new("file", "QPRGVPJNWDXH4ESK2RYDTZJLTE", "2026-10-23T18:00:00Z", json!({"size": 10, "sha256": "ab"}));
        let c1 = f.canonical().unwrap();
        assert_eq!(c1, r#"{"at":"2026-10-23T18:00:00Z","author":"QPRGVPJNWDXH4ESK2RYDTZJLTE","body":{"sha256":"ab","size":10},"type":"file","v":1}"#);
        f.sig = Some(Sig { alg: Alg::Ed25519, fmt: SigFmt::Raw, key: json!({}), value: "x".into() });
        assert_eq!(f.canonical().unwrap(), c1);
        assert!(f.id().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn shape_checks() {
        let ok = Fact::new("file", "QPRGVPJNWDXH4ESK2RYDTZJLTE", "2026-10-23T18:00:00.123Z", json!({}));
        ok.validate_shape().unwrap();
        for bad in [("File", "2026-10-23T18:00:00Z"), ("file", "2026-10-23 18:00:00Z"), ("file", "2026-10-23T18:00:00")] {
            let f = Fact::new(bad.0, "QPRGVPJNWDXH4ESK2RYDTZJLTE", bad.1, json!({}));
            assert!(f.validate_shape().is_err(), "{bad:?}");
        }
        assert!(Fact::new("file", "short", "2026-10-23T18:00:00Z", json!({})).validate_shape().is_err());
        assert!(Fact::from_json(r#"{"v":1,"type":"file","author":"QPRGVPJNWDXH4ESK2RYDTZJLTE","at":"2026-10-23T18:00:00Z","body":{},"extra":1}"#).is_err());
    }
}
