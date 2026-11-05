//! `build.toml`: who the build trusts. Moderation is configuration, not data.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustConfig {
    /// Fingerprints whose `block`/`unblock`/`prefer` facts are applied.
    pub moderators: BTreeSet<String>,
    /// Fingerprints whose labels carry full weight (moderators are implied).
    pub labelers: BTreeSet<String>,
    /// Fingerprints whose `verified`/`location_status`/`identity_link` facts are trusted.
    pub servers: BTreeSet<String>,
    pub thresholds: Thresholds,
    /// Include pending/dark/gone locations in the snapshot (development only).
    pub include_unverified: bool,
    /// The domain profiles are hosted on, for `aspe:` URIs.
    pub domain: String,
    /// `tool_version`s whose derivations (e.g. watermark-stripped variants)
    /// count when choosing a manual's download. Anything else is ignored:
    /// otherwise anyone could claim `om-strip/999` and win. Order matters: a
    /// tool later in the list outranks an earlier one, and between versions
    /// of the same tool the higher version wins.
    pub derivation_tools: Vec<String>,
}

/// The tools that have produced the catalog's variants so far, least
/// preferred first: the bootstrap import's repaired and stripped files, then
/// the TypeScript stripper, then the current one.
pub const DEFAULT_DERIVATION_TOOLS: &[&str] = &["qpdf/1", "salli-cat pdf_utils/1", "om-strip/1", "om-strip-rs/1", "om-strip-rs/2"];

impl Default for TrustConfig {
    fn default() -> Self {
        TrustConfig {
            moderators: BTreeSet::new(),
            labelers: BTreeSet::new(),
            servers: BTreeSet::new(),
            thresholds: Thresholds::default(),
            include_unverified: false,
            domain: String::new(),
            derivation_tools: DEFAULT_DERIVATION_TOOLS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Summed report weight at which a file or copy loses its canonical slot.
    pub report: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds { report: 2.0 }
    }
}

impl TrustConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        Ok(toml::from_str(&s)?)
    }

    pub fn is_moderator(&self, fp: &str) -> bool {
        self.moderators.contains(fp)
    }
    pub fn is_server(&self, fp: &str) -> bool {
        self.servers.contains(fp)
    }
    /// Keys whose catalog facts are trusted outright: moderators and servers.
    pub fn is_trusted(&self, fp: &str) -> bool {
        self.moderators.contains(fp) || self.servers.contains(fp)
    }
    pub fn is_labeler(&self, fp: &str) -> bool {
        self.labelers.contains(fp) || self.moderators.contains(fp)
    }

    /// How a derivation tool ranks when choosing a manual's download: None
    /// when it isn't on the list; otherwise (the position of the tool's last
    /// entry, its version number), so a tool listed later wins and, between
    /// versions of one tool, the higher version does.
    pub fn tool_rank(&self, tool_version: &str) -> Option<(usize, i64)> {
        if !self.derivation_tools.iter().any(|t| t == tool_version) {
            return None;
        }
        let name = tool_name(tool_version);
        let pos = self.derivation_tools.iter().rposition(|t| tool_name(t) == name)?;
        Some((pos, crate::model::tool_version_num(Some(tool_version))))
    }

    /// A stable digest of the configuration, recorded in the snapshot.
    pub fn digest(&self) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(toml::to_string(self).unwrap_or_default().as_bytes()))
    }
}

/// The tool part of a `tool_version` (`om-strip-rs/1` → `om-strip-rs`).
fn tool_name(tool_version: &str) -> &str {
    tool_version.rsplit_once('/').map_or(tool_version, |(n, _)| n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_tools_and_higher_versions_rank_higher() {
        let c = TrustConfig::default();
        let r = |t: &str| c.tool_rank(t);
        assert!(r("om-strip-rs/2") > r("om-strip-rs/1"));
        assert!(r("om-strip-rs/1") > r("om-strip/1"));
        assert!(r("om-strip/1") > r("salli-cat pdf_utils/1"));
        assert!(r("salli-cat pdf_utils/1") > r("qpdf/1"));
        assert_eq!(r("om-strip/999"), None, "only listed tool versions count");
        let c = TrustConfig { derivation_tools: vec!["om-strip-rs/2".into(), "qpdf/1".into(), "om-strip-rs/1".into()], ..TrustConfig::default() };
        assert!(c.tool_rank("om-strip-rs/2") > c.tool_rank("om-strip-rs/1"), "same tool: higher version wins");
        assert!(c.tool_rank("om-strip-rs/1") > c.tool_rank("qpdf/1"));
    }
}
