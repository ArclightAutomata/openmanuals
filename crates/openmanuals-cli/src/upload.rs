//! Upload targets: archive.org (S3-style PUT), any S3-compatible bucket, WebDAV, a directory.

use crate::sign;
use anyhow::{anyhow, bail, Context, Result};
use openmanuals_core::{sign::SigningKey, Fact};
use serde_json::json;
use std::path::Path;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Target {
    Ia,
    S3,
    Webdav,
    Dir,
}

#[derive(Debug, Clone, clap::Args)]
pub struct TargetOpts {
    /// IA S3 access key (or IA_ACCESS_KEY / ~/.config/ia/ia.ini).
    #[arg(long, env = "IA_ACCESS_KEY")]
    pub ia_access: Option<String>,
    #[arg(long, env = "IA_SECRET_KEY")]
    pub ia_secret: Option<String>,
    /// S3 endpoint, e.g. https://s3.us-west-002.backblazeb2.com
    #[arg(long, env = "OM_S3_ENDPOINT")]
    pub s3_endpoint: Option<String>,
    #[arg(long, env = "OM_S3_BUCKET")]
    pub s3_bucket: Option<String>,
    #[arg(long, env = "OM_S3_REGION", default_value = "us-east-1")]
    pub s3_region: String,
    #[arg(long, env = "AWS_ACCESS_KEY_ID")]
    pub s3_access: Option<String>,
    #[arg(long, env = "AWS_SECRET_ACCESS_KEY")]
    pub s3_secret: Option<String>,
    /// WebDAV collection URL to PUT into, e.g. https://files.example.org/manuals/
    #[arg(long, env = "OM_WEBDAV_URL")]
    pub webdav_url: Option<String>,
    #[arg(long, env = "OM_WEBDAV_USER")]
    pub webdav_user: Option<String>,
    #[arg(long, env = "OM_WEBDAV_PASS")]
    pub webdav_pass: Option<String>,
    /// Directory to copy into (target dir).
    #[arg(long, env = "OM_DIR")]
    pub dir: Option<std::path::PathBuf>,
    /// Public base URL under which the S3 key / WebDAV path / directory is served.
    #[arg(long, env = "OM_PUBLIC_BASE")]
    pub public_base: Option<String>,
}

fn ia_keys(o: &TargetOpts) -> Result<(String, String)> {
    ia_keys_from(o.ia_access.clone(), o.ia_secret.clone())
}

/// archive.org S3 keys: the given ones, else the `ia` tool's config file.
pub fn ia_keys_from(access: Option<String>, secret: Option<String>) -> Result<(String, String)> {
    if let (Some(a), Some(s)) = (access, secret) {
        return Ok((a, s));
    }
    let home = std::env::var("HOME").unwrap_or_default();
    for p in [format!("{home}/.config/ia/ia.ini"), format!("{home}/.config/internetarchive/ia.ini"), format!("{home}/.ia")] {
        if let Ok(text) = std::fs::read_to_string(&p) {
            let mut a = None;
            let mut s = None;
            for line in text.lines() {
                let l = line.trim();
                if let Some(v) = l.strip_prefix("access") {
                    a = v.trim_start_matches([' ', '=']).trim().to_string().into();
                }
                if let Some(v) = l.strip_prefix("secret") {
                    s = v.trim_start_matches([' ', '=']).trim().to_string().into();
                }
            }
            if let (Some(a), Some(s)) = (a, s) {
                return Ok((a, s));
            }
        }
    }
    bail!("archive.org keys: pass --ia-access/--ia-secret, set IA_ACCESS_KEY/IA_SECRET_KEY, or run `ia configure`")
}

fn safe_filename(path: &Path, ext: &str) -> String {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("manual");
    let clean = openmanuals_core::ids::clean_identifier_chars(stem);
    format!("{}.{ext}", if clean.is_empty() { "manual" } else { &clean })
}

/// `uri(...)` encoding archive.org wants for non-ASCII metadata header values.
fn meta_value(v: &str) -> String {
    if v.is_ascii() && !v.contains(['\r', '\n']) {
        v.to_string()
    } else {
        format!("uri({})", urlencoding::encode(v))
    }
}

/// `file` fact for bytes in memory.
fn file_fact(key: &SigningKey, bytes: &[u8], mime: &str) -> Result<(String, Fact)> {
    let sha256 = openmanuals_core::canon::sha256_hex(bytes);
    let body = json!({"sha256": sha256, "sha1": openmanuals_core::canon::sha1_hex(bytes), "md5": openmanuals_core::canon::md5_hex(bytes), "size": bytes.len(), "mime": mime});
    Ok((sha256, sign(key, "file", body)?))
}

/// Upload a file and return the facts recording it. With `strip`, a PDF goes
/// through the watermark stripper first, as in the extension: when anything
/// was removed the stripped bytes are uploaded, and the bundle records the
/// original `file`, the stripped `file`, the `derivation` between them, the
/// copy's `location`, and (with a manual) a `manual_file` for each.
#[allow(clippy::too_many_arguments)]
pub async fn run(key: &SigningKey, path: &Path, target: Target, manual: Option<&str>, title: Option<&str>, source_url: Option<&str>, strip: bool, o: &TargetOpts) -> Result<Vec<Fact>> {
    let original = std::fs::read(path).with_context(|| path.display().to_string())?;
    let ft = openmanuals_core::sniff::sniff(&original[..original.len().min(16)]).ok_or_else(|| anyhow!("not a document: only PDF and DjVu are accepted"))?;
    let (original_sha256, original_fact) = file_fact(key, &original, ft.mime())?;
    let mut facts = vec![original_fact];
    let stripped = if strip && ft == openmanuals_core::sniff::FileType::Pdf {
        match openmanuals_strip::strip(&original) {
            Ok(r) => {
                for l in &r.log {
                    eprintln!("strip: {l}");
                }
                r.changed.then_some(r.bytes)
            }
            Err(e) => {
                eprintln!("strip: {e}; uploading the original");
                None
            }
        }
    } else {
        None
    };
    let bytes = match stripped {
        Some(b) => {
            let (sha, fact) = file_fact(key, &b, ft.mime())?;
            facts.push(fact);
            facts.push(sign(key, "derivation", json!({"derived": sha, "source": original_sha256, "transform": "watermark-stripped", "tool": openmanuals_strip::STRIP_TOOL, "tool_version": openmanuals_strip::STRIP_VERSION}))?);
            b
        }
        None => original,
    };
    let sha256 = openmanuals_core::canon::sha256_hex(&bytes);
    let was_stripped = sha256 != original_sha256;
    let filename = safe_filename(path, ft.extension());
    let client = reqwest::Client::builder().user_agent(format!("openmanuals-cli/{}", env!("CARGO_PKG_VERSION"))).timeout(std::time::Duration::from_secs(3600)).build()?;
    let sha1 = openmanuals_core::canon::sha1_hex(&bytes);
    let md5 = openmanuals_core::canon::md5_hex(&bytes);
    let title = title.map(str::to_string).unwrap_or_else(|| path.file_stem().and_then(|s| s.to_str()).unwrap_or("Manual").to_string());

    let (url, kind, ia) = match target {
        Target::Ia => {
            let (ak, sk) = ia_keys(o)?;
            let identifier = openmanuals_core::ids::upload_identifier(&sha256, &ulid::Ulid::new().to_string())?;
            let put = format!("https://s3.us.archive.org/{identifier}/{filename}");
            let mut req = client
                .put(&put)
                .header("authorization", format!("LOW {ak}:{sk}"))
                .header("x-amz-auto-make-bucket", "1")
                .header("x-archive-meta-mediatype", "texts")
                .header("x-archive-meta-title", meta_value(&title))
                .header("x-archive-meta01-subject", "manuals")
                .header("x-archive-meta02-subject", "openmanuals")
                .header("x-archive-meta-scanner", format!("OpenManuals openmanuals-cli {}", env!("CARGO_PKG_VERSION")))
                .header("x-archive-meta-openmanuals-key", key.public_key().fingerprint())
                .header("x-archive-meta01-external-identifier", format!("urn:sha256:{sha256}"))
                .header("x-archive-meta02-external-identifier", format!("urn:sha1:{sha1}"))
                .header("x-archive-meta03-external-identifier", format!("urn:md5:{md5}"))
                .header("content-type", ft.mime());
            if let Some(s) = source_url {
                req = req.header("x-archive-meta-source", meta_value(s));
            }
            if was_stripped {
                req = req.header("x-archive-meta-openmanuals-original-sha256", original_sha256.as_str());
            }
            let r = req.body(bytes.clone()).send().await.context("uploading to archive.org")?;
            if !r.status().is_success() {
                bail!("archive.org answered {}: {}", r.status(), r.text().await.unwrap_or_default());
            }
            eprintln!("uploaded to https://archive.org/details/{identifier}");
            (format!("https://archive.org/download/{identifier}/{filename}"), "archive", Some(json!({"identifier": identifier, "filename": filename})))
        }
        Target::S3 => {
            let (Some(endpoint), Some(bucket), Some(ak), Some(sk)) = (&o.s3_endpoint, &o.s3_bucket, &o.s3_access, &o.s3_secret) else {
                bail!("--s3-endpoint, --s3-bucket, --s3-access and --s3-secret are required")
            };
            let base = o.public_base.clone().ok_or_else(|| anyhow!("--public-base is required so the copy has a public URL"))?;
            let keypath = format!("{}/{filename}", &sha256[..16]);
            let b = rusty_s3::Bucket::new(endpoint.parse()?, rusty_s3::UrlStyle::Path, bucket.clone(), o.s3_region.clone())?;
            let creds = rusty_s3::Credentials::new(ak, sk);
            use rusty_s3::S3Action;
            let action = b.put_object(Some(&creds), &keypath);
            let signed = action.sign(std::time::Duration::from_secs(3600));
            let r = client.put(signed).header("content-type", ft.mime()).body(bytes.clone()).send().await.context("uploading to S3")?;
            if !r.status().is_success() {
                bail!("S3 answered {}: {}", r.status(), r.text().await.unwrap_or_default());
            }
            (format!("{}/{keypath}", base.trim_end_matches('/')), "mirror", None)
        }
        Target::Webdav => {
            let dav = o.webdav_url.clone().ok_or_else(|| anyhow!("--webdav-url is required"))?;
            let put = format!("{}/{filename}", dav.trim_end_matches('/'));
            let mut req = client.put(&put).header("content-type", ft.mime()).body(bytes.clone());
            if let Some(u) = &o.webdav_user {
                req = req.basic_auth(u, o.webdav_pass.as_deref());
            }
            let r = req.send().await.context("uploading via WebDAV")?;
            if !r.status().is_success() {
                bail!("WebDAV answered {}", r.status());
            }
            let public = o.public_base.clone().map(|b| format!("{}/{filename}", b.trim_end_matches('/'))).unwrap_or(put);
            (public, "mirror", None)
        }
        Target::Dir => {
            let dir = o.dir.clone().ok_or_else(|| anyhow!("--dir is required"))?;
            let base = o.public_base.clone().ok_or_else(|| anyhow!("--public-base is required so the copy has a public URL"))?;
            let rel = format!("{}/{filename}", &sha256[..16]);
            let dest = dir.join(&rel);
            std::fs::create_dir_all(dest.parent().unwrap())?;
            std::fs::write(&dest, &bytes)?;
            (format!("{}/{rel}", base.trim_end_matches('/')), "mirror", None)
        }
    };
    let mut body = json!({"file": sha256, "url": url, "kind": kind});
    if let Some(ia) = ia {
        body["ia"] = ia;
    }
    facts.push(sign(key, "location", body)?);
    if let Some(m) = manual {
        let m = m.to_ascii_uppercase();
        facts.push(sign(key, "manual_file", json!({"manual": m, "file": original_sha256, "role": "primary"}))?);
        if was_stripped {
            facts.push(sign(key, "manual_file", json!({"manual": m, "file": sha256, "role": "primary"}))?);
        }
    }
    Ok(facts)
}
