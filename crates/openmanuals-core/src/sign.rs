//! Native-only signing: key generation, raw signatures, facts, profiles, OpenSSH files.

use crate::{asp, b64, jws, Alg, Error, Fact, PublicKey, Result, Sig, SigFmt};
use serde_json::Value;

pub enum SigningKey {
    Ed25519(ed25519_dalek::SigningKey),
}

impl SigningKey {
    pub fn generate(alg: Alg) -> Self {
        let mut rng = rand_core::OsRng;
        match alg {
            Alg::Ed25519 => SigningKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng)),
        }
    }

    /// From a 32-byte seed.
    pub fn from_seed(alg: Alg, seed: &[u8]) -> Result<Self> {
        let s: [u8; 32] = seed.try_into().map_err(|_| Error::Key("seed must be 32 bytes".into()))?;
        Ok(match alg {
            Alg::Ed25519 => SigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&s)),
        })
    }

    pub fn seed(&self) -> [u8; 32] {
        match self {
            SigningKey::Ed25519(k) => k.to_bytes(),
        }
    }

    /// Load an unencrypted OpenSSH private key file.
    pub fn from_openssh(pem: &str) -> Result<Self> {
        let k = ssh_key::PrivateKey::from_openssh(pem).map_err(|e| Error::Key(e.to_string()))?;
        match k.key_data() {
            ssh_key::private::KeypairData::Ed25519(kp) => Ok(SigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&kp.private.to_bytes()))),
            other => Err(Error::Key(format!("unsupported OpenSSH key algorithm {}", other.algorithm().map(|a| a.to_string()).unwrap_or_default()))),
        }
    }

    /// Encode as an unencrypted OpenSSH private key file.
    pub fn to_openssh(&self, comment: &str) -> Result<String> {
        let k = match self {
            SigningKey::Ed25519(k) => {
                let kp = ssh_key::private::Ed25519Keypair::from_seed(&k.to_bytes());
                ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(kp), comment)
            }
        }
        .map_err(|e| Error::Key(e.to_string()))?;
        k.to_openssh(ssh_key::LineEnding::LF).map(|s| s.to_string()).map_err(|e| Error::Key(e.to_string()))
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            SigningKey::Ed25519(k) => PublicKey::Ed25519(k.verifying_key().to_bytes()),
        }
    }

    pub fn alg(&self) -> Alg {
        self.public_key().alg()
    }

    /// Raw Ed25519 signature (64 bytes).
    pub fn sign_raw(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(k) => {
                use ed25519_dalek::Signer;
                k.sign(msg).to_bytes().to_vec()
            }
        }
    }

    /// Sign a fact in place (`fmt: raw`), setting `author` to this key's fingerprint.
    pub fn sign_fact(&self, fact: &mut Fact) -> Result<()> {
        let pk = self.public_key();
        fact.author = pk.fingerprint();
        fact.sig = None;
        fact.validate_shape()?;
        let msg = fact.canonical()?;
        fact.sig = Some(Sig { alg: pk.alg(), fmt: SigFmt::Raw, key: pk.to_jwk(), value: b64::encode(&self.sign_raw(msg.as_bytes())) });
        Ok(())
    }

    /// A signed compact JWS.
    pub fn sign_jws(&self, header: &Value, payload: &Value) -> String {
        let input = jws::signing_input(header, payload);
        jws::assemble(&input, &self.sign_raw(input.as_bytes()))
    }

    /// A signed Ariadne profile.
    pub fn sign_profile(&self, name: &str, claims: &[String], description: Option<&str>) -> String {
        let (h, p) = asp::build(&self.public_key(), name, claims, description);
        self.sign_jws(&h, &p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sign_and_verify() {
        for alg in [Alg::Ed25519] {
            let k = SigningKey::generate(alg);
            let mut f = Fact::new("file", "x", "2026-10-23T18:00:00Z", json!({"sha256": "ab", "size": 1}));
            k.sign_fact(&mut f).unwrap();
            f.verify().unwrap();
            let round: Fact = Fact::from_json(&f.to_json()).unwrap();
            round.verify().unwrap();
            let mut tampered = round.clone();
            tampered.body["size"] = json!(2);
            assert!(tampered.verify().is_err());

            let jws = k.sign_profile("Test", &["https://example.org/u/x".into()], None);
            let p = asp::parse_and_verify(&jws).unwrap();
            assert_eq!(p.fingerprint, k.public_key().fingerprint());
            assert_eq!(p.claims, vec!["https://example.org/u/x"]);

            let pem = k.to_openssh("test").unwrap();
            let back = SigningKey::from_openssh(&pem).unwrap();
            assert_eq!(back.public_key(), k.public_key());
        }
    }
}
