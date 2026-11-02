//! Public keys: JWK and OpenSSH forms, Ariadne fingerprints, signature checks.

use crate::{b64, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The signature algorithm. Serialized as `Ed25519`, the only one accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    Ed25519,
}

impl Alg {
    /// The JOSE `alg` value.
    pub fn jose(self) -> &'static str {
        match self {
            Alg::Ed25519 => "EdDSA",
        }
    }
}

/// A contributor's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519([u8; 32]),
}

fn arr32(v: &[u8], what: &str) -> Result<[u8; 32]> {
    v.try_into().map_err(|_| Error::Key(format!("{what} must be 32 bytes")))
}

impl PublicKey {
    pub fn alg(&self) -> Alg {
        match self {
            PublicKey::Ed25519(_) => Alg::Ed25519,
        }
    }

    /// Parse a public JWK (`{"kty":"OKP","crv":"Ed25519","x":…}`). Extra members
    /// are ignored; any other key type is refused.
    pub fn from_jwk(jwk: &Value) -> Result<Self> {
        let s = |k: &str| -> Result<&str> {
            jwk.get(k).and_then(Value::as_str).ok_or_else(|| Error::Key(format!("jwk missing {k}")))
        };
        let dec = |k: &str| -> Result<Vec<u8>> {
            b64::decode(s(k)?).ok_or_else(|| Error::Key(format!("jwk {k} is not base64url")))
        };
        match (s("kty")?, s("crv")?) {
            ("OKP", "Ed25519") => Ok(PublicKey::Ed25519(arr32(&dec("x")?, "x")?)),
            (kty, crv) => Err(Error::Key(format!("unsupported key type {kty}/{crv}"))),
        }
    }

    /// The minimal public JWK, members in RFC 7638 order.
    pub fn to_jwk(&self) -> Value {
        match self {
            PublicKey::Ed25519(x) => json!({"crv": "Ed25519", "kty": "OKP", "x": b64::encode(x)}),
        }
    }

    /// Ariadne Signature Profile fingerprint: base32 (no padding, uppercase) of
    /// the first 16 bytes of SHA-512 over the compact JSON of `crv`, `kty`, `x`,
    /// in that order.
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        // to_jwk() emits members in that order and serde_json preserves insertion order.
        let s = serde_json::to_string(&self.to_jwk()).expect("jwk serializes");
        let digest = sha2::Sha512::digest(s.as_bytes());
        data_encoding::BASE32_NOPAD.encode(&digest[..16])
    }

    /// Parse an OpenSSH public key line (`ssh-ed25519 AAAA… comment`).
    pub fn from_openssh(line: &str) -> Result<Self> {
        let k = ssh_key::PublicKey::from_openssh(line.trim()).map_err(|e| Error::Key(e.to_string()))?;
        Self::from_ssh_key(&k)
    }

    pub fn from_ssh_key(k: &ssh_key::PublicKey) -> Result<Self> {
        match k.key_data() {
            ssh_key::public::KeyData::Ed25519(e) => Ok(PublicKey::Ed25519(e.0)),
            other => Err(Error::Key(format!("unsupported OpenSSH key algorithm {}", other.algorithm()))),
        }
    }

    pub fn to_ssh_key(&self) -> ssh_key::PublicKey {
        use ssh_key::public::{Ed25519PublicKey, KeyData};
        match self {
            PublicKey::Ed25519(x) => ssh_key::PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(*x))),
        }
    }

    /// The OpenSSH public key line, with the fingerprint as comment.
    pub fn to_openssh(&self) -> String {
        let mut k = self.to_ssh_key();
        k.set_comment(self.fingerprint());
        k.to_openssh().expect("openssh encoding")
    }

    /// Verify a raw Ed25519 signature (64 bytes) over `msg`.
    pub fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        match self {
            PublicKey::Ed25519(x) => {
                use ed25519_dalek::Verifier;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(x).map_err(|e| Error::Key(e.to_string()))?;
                let s = ed25519_dalek::Signature::from_slice(sig).map_err(|e| Error::Signature(e.to_string()))?;
                vk.verify(msg, &s).map_err(|_| Error::Signature("Ed25519 signature does not verify".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asp_spec_example_fingerprint() {
        let jwk = json!({"kty": "OKP", "use": "sig", "crv": "Ed25519", "x": "__poSQwNedopfLKP3ZgM6FXz9LIJszDZh5wKcoQF71U"});
        let k = PublicKey::from_jwk(&jwk).unwrap();
        assert_eq!(k.fingerprint(), "QPRGVPJNWDXH4ESK2RYDTZJLTE");
    }

    #[test]
    fn openssh_round_trip() {
        let k = PublicKey::Ed25519([7u8; 32]);
        let line = k.to_openssh();
        assert!(line.starts_with("ssh-ed25519 "));
        assert_eq!(PublicKey::from_openssh(&line).unwrap(), k);
        assert_eq!(PublicKey::from_jwk(&k.to_jwk()).unwrap(), k);
    }

    #[test]
    fn other_key_types_are_refused() {
        let p256 = json!({"kty": "EC", "crv": "P-256", "x": "1lqTl3yqPRsIH9V6ep5GXxZgV3MEuurVBd06SFic81A", "y": "GF6JU3LfYiHqOhN1V-Rz_dtnVfBb1QfDxTP86ckShQ"});
        assert!(PublicKey::from_jwk(&p256).is_err());
        assert!(PublicKey::from_openssh("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNZak5d8qj0bCBhS/1ennkZfFmBXcwS66tUF3TpIWJzzUBheiVNy32Ih6joTdVfkc/3bZ1XwW9UHw8Uz/OnJEoU=").is_err());
    }
}
