//! `om block` / `om unblock`: a moderator's block or unblock fact, signed with
//! this key and sent straight to the server. The build applies it only when
//! the key is in the trust config's `moderators`, so that is checked first.

use crate::{outbox, sign, Home};
use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Kind {
    /// A contributor key: every fact it signed (fingerprint, aspe: URI or /k/<fp> link).
    Key,
    /// One fact (sha256:<hex>, or the hex alone).
    Fact,
    /// A manual (ULID, or a /manual/<ulid> link).
    Manual,
    /// Every copy on a host (host name, or any URL on it).
    Host,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Key => "key",
            Kind::Fact => "fact",
            Kind::Manual => "manual",
            Kind::Host => "host",
        }
    }
}

/// The value as the build matches it, from what a moderator is likely to paste.
pub fn normalize(kind: Kind, value: &str) -> Result<String> {
    let v = value.trim();
    // A link to the server's page for it: take the last path segment.
    let last = |s: &str| s.trim_end_matches('/').rsplit('/').next().unwrap_or(s).to_string();
    match kind {
        Kind::Key => {
            let s = if v.contains("://") { last(v) } else { v.rsplit(':').next().unwrap_or(v).to_string() };
            let fp = s.to_ascii_uppercase();
            if !openmanuals_core::fact::valid_fingerprint(&fp) {
                bail!("{value:?} isn't a key fingerprint (26 characters, A–Z and 2–7)");
            }
            Ok(fp)
        }
        Kind::Fact => {
            let s = if v.contains("://") { last(v) } else { v.to_string() };
            let s = urlencoding::decode(&s).map(|c| c.into_owned()).unwrap_or(s).to_ascii_lowercase();
            let hex = s.strip_prefix("sha256:").unwrap_or(&s);
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("{value:?} isn't a fact id (sha256:<64 hex digits>)");
            }
            Ok(format!("sha256:{hex}"))
        }
        Kind::Manual => {
            let s = if v.contains("://") { last(v) } else { v.to_string() }.to_ascii_uppercase();
            const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
            if s.len() != 26 || !s.chars().all(|c| CROCKFORD.contains(c)) {
                bail!("{value:?} isn't a manual id (a 26-character ULID)");
            }
            Ok(s)
        }
        Kind::Host => {
            let s = v.split_once("://").map_or(v, |(_, rest)| rest);
            let host = s.split(['/', '?', '#']).next().unwrap_or("").split('@').next_back().unwrap_or("");
            let host = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(h, _)| h).to_ascii_lowercase();
            if host.is_empty() || !host.contains('.') || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
                bail!("{value:?} isn't a host name");
            }
            Ok(host)
        }
    }
}

pub struct Request<'a> {
    pub block: bool,
    pub kind: Kind,
    pub value: &'a str,
    pub reason: &'a str,
    pub server: &'a str,
    pub queue_only: bool,
    pub force: bool,
}

pub async fn run(home: &Home, req: Request<'_>) -> Result<()> {
    let key = home.key()?;
    let fp = key.public_key().fingerprint();
    let value = normalize(req.kind, req.value)?;
    let server = req.server.trim_end_matches('/');
    let client = reqwest::Client::builder().user_agent(format!("openmanuals-cli/{}", env!("CARGO_PKG_VERSION"))).build()?;
    if !req.force {
        let info: Value = client.get(format!("{server}/api/server")).send().await.context("asking the server for its moderators")?.json().await?;
        let mods = info["moderators"].as_array().ok_or_else(|| anyhow!("{server} doesn't list its moderators (older server?); pass --force to sign anyway"))?;
        if !mods.iter().any(|m| m.as_str() == Some(fp.as_str())) {
            bail!(
                "this key ({fp}) isn't a moderator on {server}, so the build would ignore it.\n\
                 Add it to `moderators` in the server's build.toml, or pass --force to sign anyway."
            );
        }
    }
    let t = if req.block { "block" } else { "unblock" };
    let fact = sign(&key, t, json!({"kind": req.kind.as_str(), "value": value, "reason": req.reason}))?;
    let id = fact.id()?;
    let what = format!("{t} {} {value}", req.kind.as_str());
    if !req.queue_only {
        let r = client.post(format!("{server}/api/facts")).json(&[&fact]).send().await;
        match r {
            Ok(r) if r.status().is_success() => {
                let v: Value = r.json().await.unwrap_or(Value::Null);
                if v["rejected"].as_array().is_some_and(|a| !a.is_empty()) {
                    bail!("{server} rejected the {t}: {}", v["rejected"][0]["error"]);
                }
                println!("sent: {what} ({id})");
                println!("{}", if req.block {
                    "Hidden from the site and snapshot at the next build; a blocked key can't add facts from now on."
                } else {
                    "Takes effect at the next build."
                });
                return Ok(());
            }
            Ok(r) => eprintln!("{server} answered {}; queued instead", r.status()),
            Err(e) => eprintln!("couldn't reach {server} ({e}); queued instead"),
        }
    }
    let p = outbox::queue(home, &[fact])?;
    println!("queued: {what} ({id}) in {}; send it with `om sync --push-only`", p.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pasted_values_are_normalized() {
        let fp = "QPRGVPJNWDXH4ESK2RYDTZJLTE";
        for v in [fp, "qprgvpjnwdxh4esk2rydtzjlte", "aspe:openmanuals.org:QPRGVPJNWDXH4ESK2RYDTZJLTE", "https://openmanuals.org/k/QPRGVPJNWDXH4ESK2RYDTZJLTE/"] {
            assert_eq!(normalize(Kind::Key, v).unwrap(), fp, "{v}");
        }
        assert!(normalize(Kind::Key, "not-a-key").is_err());
        let hex = "ab".repeat(32);
        for v in [hex.clone(), format!("sha256:{hex}"), format!("SHA256:{}", hex.to_uppercase()), format!("https://openmanuals.org/fact/sha256%3A{hex}")] {
            assert_eq!(normalize(Kind::Fact, &v).unwrap(), format!("sha256:{hex}"), "{v}");
        }
        assert!(normalize(Kind::Fact, "sha256:abc").is_err());
        assert_eq!(normalize(Kind::Manual, "https://openmanuals.org/manual/01kdxr0n67hfgf3ksmnt8fwtc3").unwrap(), "01KDXR0N67HFGF3KSMNT8FWTC3");
        assert!(normalize(Kind::Manual, "01KDXR0N67HFGF3KSMNT8FWTCU").is_err(), "U isn't Crockford");
        for v in ["Evil.Example.com", "https://user@evil.example.com:8443/x?y", "evil.example.com/path"] {
            assert_eq!(normalize(Kind::Host, v).unwrap(), "evil.example.com", "{v}");
        }
        assert!(normalize(Kind::Host, "localhost").is_err());
        assert!(normalize(Kind::Host, "bad host.com").is_err());
    }
}
