use anyhow::{anyhow, Context, Result};
use openmanuals_core::sign::SigningKey;
use std::path::Path;

pub fn load(path: &Path) -> Result<SigningKey> {
    let pem = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    SigningKey::from_openssh(&pem).map_err(|e| anyhow!("{e}"))
}

pub fn save(path: &Path, key: &SigningKey) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let pem = key.to_openssh("openmanuals").map_err(|e| anyhow!("{e}"))?;
    std::fs::write(path, pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(path.with_extension("pub"), key.public_key().to_openssh())?;
    Ok(())
}

/// Whether an extension backup file needs a passphrase (one saved without
/// one has the private JWK in the clear, as `privateJwk`).
pub fn backup_is_encrypted(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json).map_or(true, |b| b.get("privateJwk").is_none())
}

/// A key from the extension's backup file (`om-key-backup`, from its
/// settings): the private JWK, sealed with AES-GCM under a PBKDF2-SHA256 key
/// from the passphrase, or in the clear when saved without one. Checked
/// against the fingerprint the backup names.
pub fn from_backup(json: &str, passphrase: &str) -> Result<SigningKey> {
    use base64::Engine;
    let b: serde_json::Value = serde_json::from_str(json).context("not JSON")?;
    if b["format"] != "om-key-backup" {
        anyhow::bail!("not an OpenManuals key backup");
    }
    if b["alg"] != "Ed25519" {
        anyhow::bail!("unsupported key algorithm {}: only Ed25519 keys are supported", b["alg"]);
    }
    let b64 = |v: &serde_json::Value, what: &str| -> Result<Vec<u8>> {
        let s = v.as_str().ok_or_else(|| anyhow!("backup has no {what}"))?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).with_context(|| format!("backup {what}"))
    };
    let jwk: serde_json::Value = if b.get("privateJwk").is_some() {
        b["privateJwk"].clone()
    } else {
        decrypt_backup(&b, passphrase, &b64)?
    };
    if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
        anyhow::bail!("backup key isn't an Ed25519 key");
    }
    let seed = b64(&jwk["d"], "private key")?;
    let key = SigningKey::from_seed(openmanuals_core::Alg::Ed25519, &seed).map_err(|e| anyhow!("{e}"))?;
    if let Some(fp) = b["fingerprint"].as_str() {
        if key.public_key().fingerprint() != fp {
            anyhow::bail!("backup fingerprint mismatch");
        }
    }
    Ok(key)
}

fn decrypt_backup(b: &serde_json::Value, passphrase: &str, b64: &dyn Fn(&serde_json::Value, &str) -> Result<Vec<u8>>) -> Result<serde_json::Value> {
    use aes_gcm::aead::{Aead, KeyInit};
    if b["kdf"]["name"] != "PBKDF2" || b["kdf"]["hash"] != "SHA-256" || b["cipher"]["name"] != "AES-GCM" {
        anyhow::bail!("unsupported backup encryption");
    }
    let iterations = b["kdf"]["iterations"].as_u64().filter(|n| *n > 0 && *n <= 100_000_000).ok_or_else(|| anyhow!("backup has no iteration count"))? as u32;
    let salt = b64(&b["kdf"]["salt"], "salt")?;
    let iv = b64(&b["cipher"]["iv"], "iv")?;
    let ct = b64(&b["ciphertext"], "ciphertext")?;
    let mut wrap = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase.as_bytes(), &salt, iterations, &mut wrap);
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&wrap).map_err(|e| anyhow!("{e}"))?;
    let nonce: [u8; 12] = iv.as_slice().try_into()?;
    let plain = cipher.decrypt(&aes_gcm::Nonce::from(nonce), ct.as_ref()).map_err(|_| anyhow!("wrong passphrase"))?;
    serde_json::from_slice(&plain).context("backup contents")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit};
    use base64::Engine;

    /// A backup sealed the way the extension's `sealBackup` does it.
    fn seal(key: &SigningKey, pass: &str, fingerprint: &str) -> String {
        let e = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let (salt, iv) = ([7u8; 16], [9u8; 12]);
        let mut wrap = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass.as_bytes(), &salt, 1000, &mut wrap);
        let jwk = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "d": e(&key.seed()), "x": "ignored"});
        let ct = aes_gcm::Aes256Gcm::new_from_slice(&wrap).unwrap().encrypt(&aes_gcm::Nonce::from(iv), jwk.to_string().as_bytes()).unwrap();
        serde_json::json!({"format": "om-key-backup", "v": 2, "alg": "Ed25519", "fingerprint": fingerprint,
            "kdf": {"name": "PBKDF2", "hash": "SHA-256", "iterations": 1000, "salt": e(&salt)},
            "cipher": {"name": "AES-GCM", "iv": e(&iv)}, "ciphertext": e(&ct), "createdAt": "2026-01-01T00:00:00Z"}).to_string()
    }

    #[test]
    fn extension_backups_import() {
        let key = SigningKey::generate(openmanuals_core::Alg::Ed25519);
        let fp = key.public_key().fingerprint();
        let b = seal(&key, "correct horse", &fp);
        assert_eq!(from_backup(&b, "correct horse").unwrap().public_key().fingerprint(), fp);
        assert_eq!(from_backup(&b, "wrong").err().unwrap().to_string(), "wrong passphrase");
        let other = seal(&key, "p", "NOTTHEFINGERPRINT");
        assert_eq!(from_backup(&other, "p").err().unwrap().to_string(), "backup fingerprint mismatch");
        assert!(from_backup("{\"format\":\"x\"}", "p").is_err());
        assert!(backup_is_encrypted(&b));
        let e = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let clear = serde_json::json!({"format": "om-key-backup", "v": 2, "alg": "Ed25519", "fingerprint": fp,
            "privateJwk": {"kty": "OKP", "crv": "Ed25519", "x": "ignored", "d": e(&key.seed())}}).to_string();
        assert!(!backup_is_encrypted(&clear));
        assert_eq!(from_backup(&clear, "").unwrap().public_key().fingerprint(), fp);
    }
}
