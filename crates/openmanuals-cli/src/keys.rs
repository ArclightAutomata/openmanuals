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
