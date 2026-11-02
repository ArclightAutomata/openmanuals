//! The verifier: confirms copies by bytes (archive.org via its file list,
//! everything else by fetching and hashing with SSRF hygiene) and identity
//! proofs via the doipjs wrapper, emitting server-signed facts.
//!
//! Re-checks are cheap when nothing changed:
//! - other hosts: a conditional request (If-None-Match / If-Modified-Since);
//!   a 304 at the recorded final URL confirms the copy without a download.
//! - archive.org: one search *scrape* request covers up to IA_BATCH_MAX_IDS
//!   items and returns each item's last-modified time, size and file count.
//!   An item that hasn't changed since its last full verification is
//!   confirmed from that alone; anything else (changed, absent from the search
//!   index, no validator, search error) gets the per-item `/metadata/<id>`
//!   check, which is the only path that can declare a copy changed/dark/gone.
//!
//! Either way a confirmation without fresh checksums is recorded as a
//! `verified` fact with `"method": "conditional"`, and only while the newest
//! full verification is younger than FULL_RECHECK_DAYS.
//!
//! Every `verified` fact records `file_type` (pdf/djvu), sniffed by this
//! server from the bytes: bytes that aren't a document never verify. Copies
//! whose bytes were downloaded in full are also scanned for active content
//! (`scan`, see scan.rs) and, with a MalwareBazaar key, looked up by sha256
//! (`malware`). archive.org copies are typed from their first bytes (a range
//! request) and downloaded in full only when the file was introduced by a key
//! outside the trust config's moderators and servers.

use crate::config::{Shared, State};
use crate::rate;
use crate::scan::{self, Scan};
use anyhow::{anyhow, bail, Context, Result};
use openmanuals_core::sniff::{FileType, SNIFF_BYTES};
use openmanuals_core::Fact;
use openmanuals_ledger::ledger::Entry;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MAX_FETCH_BYTES: u64 = 512 * 1024 * 1024;
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(600);
pub const MAX_HOPS: usize = 5;
pub const RECHECK_DAYS: i64 = 30;
/// A copy re-checked only with conditional requests (304 Not Modified) is
/// downloaded and hashed in full again once its last full verification is
/// this old, so a host that keeps answering 304 can't vouch for itself forever.
pub const FULL_RECHECK_DAYS: i64 = 180;
pub const HOST_INTERVAL: Duration = Duration::from_secs(2);
/// `method` value on a `verified` fact recorded from a 304 Not Modified answer
/// (no body downloaded). Facts without `method` were hashed from the bytes.
pub const METHOD_CONDITIONAL: &str = "conditional";
/// RFC 9110 §8.8.2.2: a Last-Modified at least this far in the past (relative
/// to when we saw it) is treated as a strong-enough validator.
const LAST_MODIFIED_SETTLE: i64 = 60;

/// archive.org's origin: the metadata API and the search scrape API live under it.
pub const IA_BASE: &str = "https://archive.org";
/// archive.org's search scrape API. Answers for hundreds of items per request
/// in about 0.5–3 s (measured Oct 2026), where `/metadata/<identifier>` covers
/// one item per call and has taken 9–18 s at busy times.
pub const IA_SCRAPE_PATH: &str = "/services/search/v1/scrape";
/// Fields asked of the scrape API. `indexdate` and the newest `oai_updatedate`
/// track the item's `item_last_updated` (equal, or 1 s earlier), which moves
/// whenever any file of the item is written; `item_size`/`files_count` equal
/// the metadata API's values.
pub const IA_SCRAPE_FIELDS: &str = "identifier,indexdate,oai_updatedate,item_size,files_count";
/// Most identifiers per scrape request (400 per request measured fine).
pub const IA_BATCH_MAX_IDS: usize = 250;
/// Most characters in the scrape `q` parameter. archive.org rejects longer
/// queries (HTTP 400 "invalid value for request parameter q") somewhere
/// between 9,800 and 11,000 characters, whatever the number of terms.
pub const IA_BATCH_MAX_QUERY: usize = 8000;
/// `detail` of the `location_status` recorded for bytes that aren't a PDF or DjVu.
pub const NOT_A_DOCUMENT: &str = "not a document (pdf/djvu)";
/// Byte range asked for when only the type of a copy is needed (archive.org).
pub const SNIFF_RANGE: &str = "bytes=0-1023";
/// MalwareBazaar's API (sha256 lookups, `query=get_info`).
pub const MALWAREBAZAAR_API: &str = "https://mb-api.abuse.ch/api/v1/";
/// For a copy whose verdict carries no `ia_updated` (recorded before it
/// existed): the item counts as unchanged only if the search index dates its
/// last change at least this many seconds before our last full check.
const IA_CHECKED_AT_SETTLE: i64 = 60;

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80 || seg[0] == 0x2001 && seg[1] == 0x0db8)
        }
    }
}

pub fn registrable_domain(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    psl::domain_str(host).map(|d| d.to_ascii_lowercase())
}

/// HTTP cache validators recorded on a `verified` fact for a generic copy.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Validators {
    /// A strong entity tag, quotes included (weak `W/"…"` tags are never kept).
    pub etag: Option<String>,
    /// The Last-Modified header verbatim (an IMF-fixdate).
    pub last_modified: Option<String>,
    /// The Content-Length header of the 200 response, when sent.
    pub content_length: Option<u64>,
}

impl Validators {
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

/// A strong entity-tag per RFC 9110 §8.8.3: `"` etagc* `"`, ASCII only.
/// Weak tags (`W/"…"`) only promise semantic equivalence, not identical bytes.
pub fn is_strong_etag(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' && b[1..b.len() - 1].iter().all(|&c| c == 0x21 || (0x23..=0x7e).contains(&c))
}

/// Pick the validators worth keeping from a 200 response seen at `seen_at`.
/// Weak ETags are dropped; a Last-Modified is kept only if it parses and lies
/// at least a minute before `seen_at` (otherwise the file may still be
/// changing within the same second and the date can't tell versions apart).
pub fn validators_from_headers(h: &reqwest::header::HeaderMap, seen_at: jiff::Timestamp) -> Validators {
    use reqwest::header::{CONTENT_LENGTH, ETAG, LAST_MODIFIED};
    let get = |k| h.get(k).and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok()).map(|s| s.trim().to_string());
    let etag = get(ETAG).filter(|e| is_strong_etag(e));
    let last_modified = get(LAST_MODIFIED).filter(|lm| match jiff::fmt::rfc2822::parse(lm) {
        Ok(z) => (seen_at - z.timestamp()).get_seconds() >= LAST_MODIFIED_SETTLE,
        Err(_) => false,
    });
    let content_length = get(CONTENT_LENGTH).and_then(|s| s.parse().ok());
    Validators { etag, last_modified, content_length }
}

/// Whether a final URL can be re-requested later to the same resource. The URL
/// the contributor submitted always can (it's what we re-request anyway); a
/// redirect target carrying signing/expiry parameters (S3/GCS/Azure/CloudFront
/// presigned links, download tokens) can't, so its validators aren't recorded.
pub fn stable_url(submitted: &str, final_url: &str) -> bool {
    if submitted == final_url {
        return true;
    }
    let Ok(u) = reqwest::Url::parse(final_url) else { return false };
    const SIGNING: &[&str] = &["expires", "expiry", "exp", "signature", "sig", "token", "access_token", "auth", "policy", "key-pair-id", "se", "st", "sp", "sv", "hmac", "hash", "download_token", "verify"];
    !u.query_pairs().any(|(k, _)| {
        let k = k.to_ascii_lowercase();
        SIGNING.contains(&k.as_str()) || k.starts_with("x-amz-") || k.starts_with("x-goog-") || k.starts_with("x-ms-")
    })
}

/// archive.org item-level validators recorded on a `verified` fact for an
/// archive.org copy, as the metadata API reported them at the full check.
/// Body fields: `ia_updated`, `ia_item_size`, `ia_files_count`.
#[derive(Debug, Clone, PartialEq)]
pub struct IaValidators {
    /// The item's `item_last_updated` (unix seconds) as RFC 3339, e.g.
    /// `2026-10-06T22:36:58Z`. archive.org bumps it whenever any file of the
    /// item is written (upload, replacement, deletion, derive, metadata edit).
    pub updated: String,
    /// The item's `item_size` in bytes (all files).
    pub item_size: u64,
    /// The item's `files_count`.
    pub files_count: u64,
}

/// A JSON number, or a string holding one (archive.org uses both).
fn json_u64(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Item-level validators from a `/metadata/<identifier>` response; None if any is missing.
pub fn ia_validators_from_metadata(meta: &Value) -> Option<IaValidators> {
    let secs = json_u64(meta.get("item_last_updated"))?;
    let updated = jiff::Timestamp::from_second(i64::try_from(secs).ok()?).ok()?.to_string();
    Some(IaValidators { updated, item_size: json_u64(meta.get("item_size"))?, files_count: json_u64(meta.get("files_count"))? })
}

/// Item-level validators from a `verified` body; None unless all three are present and well-formed.
pub fn ia_validators_from_body(b: &Value) -> Option<IaValidators> {
    let updated = b.get("ia_updated").and_then(Value::as_str).filter(|s| s.parse::<jiff::Timestamp>().is_ok())?;
    Some(IaValidators { updated: updated.to_string(), item_size: b.get("ia_item_size").and_then(Value::as_u64)?, files_count: b.get("ia_files_count").and_then(Value::as_u64)? })
}

/// What a verification learned about the bytes beyond their hashes: the
/// `scan` and `malware` members of a `verified` body (absent: not done). A
/// scan an older scanner recorded that the current one would judge
/// differently ([`scan::outdated`]: om-scan/1's `Launch`) is read as absent,
/// so a re-check scans again instead of repeating it; other om-scan/1 scans
/// are repeated as recorded, tool tag included (they are what om-scan/2
/// would find, and the tag says which scanner looked).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Checks {
    pub scan: Option<Value>,
    pub malware: Option<Value>,
}

impl Checks {
    fn from_body(b: &Value) -> Checks {
        Checks { scan: b.get("scan").filter(|v| v.is_object() && !scan::outdated(v)).cloned(), malware: b.get("malware").filter(|v| v.is_object()).cloned() }
    }
}

/// `file_type` of a `verified` body, if present and a document type.
fn file_type_of(b: &Value) -> Option<FileType> {
    b.get("file_type").and_then(Value::as_str).and_then(FileType::from_name)
}

/// What an earlier verdict from this server lets a re-check reuse.
#[derive(Debug, Clone, PartialEq)]
pub struct Previous {
    pub final_url: String,
    pub sha256: String,
    pub size: u64,
    pub validators: Validators,
    pub file_type: FileType,
    /// Carried over by a conditional verdict; always has a `scan`.
    pub checks: Checks,
}

/// Headers for a conditional re-check, sent only at the hop whose URL is
/// `final_url` (the URL whose response produced the validators).
#[derive(Debug, Clone, PartialEq)]
pub struct Conditional {
    pub final_url: String,
    pub if_none_match: Option<String>,
    pub if_modified_since: Option<String>,
}

/// A strong ETag goes alone in If-None-Match (servers must ignore
/// If-Modified-Since next to it, and sending only one avoids broken servers
/// that OR them). Without a strong ETag, If-Modified-Since with the recorded
/// Last-Modified verbatim. Nothing usable → no conditional request.
pub fn conditional_request(prev: &Previous) -> Option<Conditional> {
    let v = &prev.validators;
    let (inm, ims) = match (&v.etag, &v.last_modified) {
        (Some(e), _) if is_strong_etag(e) => (Some(e.clone()), None),
        (_, Some(lm)) if jiff::fmt::rfc2822::parse(lm).is_ok() => (None, Some(lm.clone())),
        _ => return None,
    };
    Some(Conditional { final_url: prev.final_url.clone(), if_none_match: inm, if_modified_since: ims })
}

/// Decide from this server's verdicts on one location (`verified` and
/// `location_status` facts: (type, body)) whether a re-check may be
/// conditional. Requires: the newest verdict is `verified` (not changed/gone/
/// dark), it carries a final_url, sha256, size, a validator, a `file_type`
/// and a `scan` (a 304 repeats them, so a verdict from before they were
/// recorded gets a full fetch), and the newest *full* verification (a
/// `verified` fact without `method: conditional`) is younger than
/// FULL_RECHECK_DAYS at `now`.
pub fn previous_verdict<'a>(verdicts: impl IntoIterator<Item = (&'a str, &'a Value)>, now: jiff::Timestamp) -> Option<Previous> {
    let (b, _) = usable_verified(verdicts, now)?;
    let s = |k: &str| b.get(k).and_then(Value::as_str).map(str::to_string);
    let validators = Validators {
        etag: s("etag").filter(|e| is_strong_etag(e)),
        last_modified: s("last_modified"),
        content_length: b.get("content_length").and_then(Value::as_u64),
    };
    let checks = Checks::from_body(b);
    if validators.is_empty() || checks.scan.is_none() {
        return None;
    }
    Some(Previous { final_url: s("final_url")?, sha256: s("sha256")?, size: b.get("size").and_then(Value::as_u64)?, validators, file_type: file_type_of(b)?, checks })
}

/// What an earlier verdict lets an archive.org re-check reuse.
#[derive(Debug, Clone, PartialEq)]
pub struct IaPrevious {
    pub final_url: String,
    /// archive.org copies of sha1-only files are verified with `sha256: null`.
    pub sha256: Option<String>,
    pub size: u64,
    /// Item validators recorded at the last full check; None on verdicts from
    /// before they were recorded (then `full_checked_at` is compared instead).
    pub ia: Option<IaValidators>,
    /// `checked_at` of the newest full (non-conditional) verification.
    pub full_checked_at: String,
    /// None on verdicts from before it was recorded: an unchanged item then
    /// gets a range request for its first bytes.
    pub file_type: Option<FileType>,
    /// Carried over by a conditional verdict.
    pub checks: Checks,
}

/// Same rules as `previous_verdict` (newest verdict is `verified`, newest full
/// verification younger than FULL_RECHECK_DAYS), for an archive.org copy:
/// no HTTP validators needed, sha256 may be null, item validators optional.
pub fn previous_ia_verdict<'a>(verdicts: impl IntoIterator<Item = (&'a str, &'a Value)>, now: jiff::Timestamp) -> Option<IaPrevious> {
    let (b, full_at) = usable_verified(verdicts, now)?;
    Some(IaPrevious {
        final_url: b.get("final_url").and_then(Value::as_str)?.to_string(),
        sha256: b.get("sha256").and_then(Value::as_str).map(str::to_string),
        size: b.get("size").and_then(Value::as_u64)?,
        ia: ia_validators_from_body(b),
        full_checked_at: full_at.to_string(),
        file_type: file_type_of(b),
        checks: Checks::from_body(b),
    })
}

/// The newest verdict's body if it is a `verified` fact and the newest full
/// verification is younger than FULL_RECHECK_DAYS at `now`, with that full
/// verification's `checked_at`.
fn usable_verified<'a>(verdicts: impl IntoIterator<Item = (&'a str, &'a Value)>, now: jiff::Timestamp) -> Option<(&'a Value, &'a str)> {
    let mut newest: Option<(&str, &Value, &str)> = None;
    let mut newest_full: Option<&str> = None;
    for (t, b) in verdicts {
        let Some(at) = b.get("checked_at").and_then(Value::as_str) else { continue };
        // On a tie, prefer a location_status: the conservative reading.
        let newer = match newest {
            None => true,
            Some((nt, _, nat)) => at > nat || (at == nat && nt == "verified" && t != "verified"),
        };
        if newer {
            newest = Some((t, b, at));
        }
        if t == "verified" && b.get("method").and_then(Value::as_str) != Some(METHOD_CONDITIONAL) && newest_full.is_none_or(|f| at > f) {
            newest_full = Some(at);
        }
    }
    let (t, b, _) = newest?;
    let full = newest_full?;
    if t != "verified" || days_between(full, now) >= FULL_RECHECK_DAYS {
        return None;
    }
    Some((b, full))
}

/// One item's row from the scrape API.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IaRow {
    /// Newest of `indexdate` and `oai_updatedate`, unix seconds.
    pub updated: Option<i64>,
    pub item_size: Option<u64>,
    pub files_count: Option<u64>,
}

/// Rows of a scrape API response, by identifier. A response carrying `error`
/// or `request_error` (archive.org answers a malformed query with HTTP 200
/// and `request_error`), or lacking `items`, is an error.
pub fn parse_scrape(v: &Value) -> Result<HashMap<String, IaRow>> {
    for k in ["error", "request_error"] {
        if let Some(e) = v.get(k) {
            bail!("archive.org scrape {k}: {e}");
        }
    }
    let items = v.get("items").and_then(Value::as_array).ok_or_else(|| anyhow!("archive.org scrape response has no items"))?;
    let ts = |s: &str| s.parse::<jiff::Timestamp>().ok().map(|t| t.as_second());
    let mut out = HashMap::new();
    for it in items {
        let Some(id) = it.get("identifier").and_then(Value::as_str) else { continue };
        let mut dates: Vec<i64> = it.get("indexdate").and_then(Value::as_str).and_then(ts).into_iter().collect();
        match it.get("oai_updatedate") {
            Some(Value::String(s)) => dates.extend(ts(s)),
            Some(Value::Array(a)) => dates.extend(a.iter().filter_map(Value::as_str).filter_map(ts)),
            _ => {}
        }
        out.insert(id.to_string(), IaRow { updated: dates.into_iter().max(), item_size: json_u64(it.get("item_size")), files_count: json_u64(it.get("files_count")) });
    }
    Ok(out)
}

/// Identifiers safe to put in a search query: archive.org's own alphabet.
pub fn is_plain_ia_identifier(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// `identifier:("a" OR "b" …)`. Callers pass only `is_plain_ia_identifier` ids.
pub fn ia_batch_query(ids: &[&str]) -> String {
    let terms: Vec<String> = ids.iter().map(|i| format!("\"{i}\"")).collect();
    format!("identifier:({})", terms.join(" OR "))
}

/// Split identifiers into scrape batches of at most IA_BATCH_MAX_IDS whose
/// query stays within IA_BATCH_MAX_QUERY characters. Duplicates are dropped;
/// identifiers that aren't plain are left out (they get per-item checks).
pub fn ia_batches<'a>(ids: impl IntoIterator<Item = &'a str>) -> Vec<Vec<&'a str>> {
    let mut seen = HashSet::new();
    let mut out: Vec<Vec<&str>> = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    let mut len = "identifier:()".len();
    for id in ids {
        if !is_plain_ia_identifier(id) || !seen.insert(id) {
            continue;
        }
        // `"id"`, plus ` OR ` before every term but the first.
        if !cur.is_empty() && (cur.len() >= IA_BATCH_MAX_IDS || len + id.len() + 6 > IA_BATCH_MAX_QUERY) {
            out.push(std::mem::take(&mut cur));
            len = "identifier:()".len();
        }
        len += id.len() + if cur.is_empty() { 2 } else { 6 };
        cur.push(id);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// What a scrape row lets a re-check of an archive.org copy do.
#[derive(Debug, Clone, PartialEq)]
pub enum IaDecision {
    /// The item hasn't changed since the last full verification: record a conditional `verified`.
    Unchanged,
    /// Do the per-item metadata check (reason for the log).
    Recheck(&'static str),
}

/// Decide from the previous verdict and the item's scrape row (None: absent
/// from the results). Unchanged requires the row to date the item's last
/// change no later than the recorded `ia_updated` and to repeat the recorded
/// size and file count; for a verdict without item validators, the change
/// must predate our last full check by IA_CHECKED_AT_SETTLE seconds. Absence
/// from search never means dark/gone here (the index lags; dark items drop
/// out of it): it only sends the copy to the metadata check.
pub fn ia_batch_decision(prev: &IaPrevious, row: Option<&IaRow>) -> IaDecision {
    use IaDecision::*;
    let Some(row) = row else { return Recheck("not in search results") };
    let Some(updated) = row.updated else { return Recheck("search row has no update date") };
    match &prev.ia {
        Some(v) => {
            if row.item_size != Some(v.item_size) || row.files_count != Some(v.files_count) {
                return Recheck("item size or file count changed");
            }
            match v.updated.parse::<jiff::Timestamp>() {
                Ok(rec) if updated <= rec.as_second() => Unchanged,
                Ok(_) => Recheck("item updated since the last full check"),
                Err(_) => Recheck("unparsable ia_updated"),
            }
        }
        None => match prev.full_checked_at.parse::<jiff::Timestamp>() {
            Ok(full) if updated <= full.as_second() - IA_CHECKED_AT_SETTLE => Unchanged,
            Ok(_) => Recheck("item updated since the last full check"),
            Err(_) => Recheck("unparsable checked_at"),
        },
    }
}

/// The conditional `verified` verdict an unchanged item earns: everything
/// carried over from the previous verdict; `file_type` from it or, for a
/// verdict without one, from a fresh sniff.
pub fn ia_conditional_verdict(prev: &IaPrevious, file_type: FileType) -> Verdict {
    Verdict::Verified { final_url: prev.final_url.clone(), sha256: prev.sha256.clone(), size: prev.size, validators: Validators::default(), ia: prev.ia.clone(), conditional: true, file_type, checks: prev.checks.clone() }
}

/// Where to fetch an archive.org file download URL from (the URL itself,
/// except under the test seam); None for anything but
/// `https://archive.org/download/<identifier>/<file>` (some migrated verdicts
/// record the item's URL, whose answer is a directory listing).
fn ia_fetch_url(public: &str) -> Option<String> {
    let rest = public.strip_prefix(IA_BASE)?.strip_prefix("/download/")?;
    let (id, file) = rest.split_once('/')?;
    (!id.is_empty() && !file.is_empty() && !public.contains(['?', '#'])).then(|| format!("{}/download/{rest}", ia_base()))
}

/// The public download URL of a file in an archive.org item (recorded as `final_url`).
pub fn ia_download_url(identifier: &str, name: &str) -> String {
    format!("{IA_BASE}/download/{identifier}/{}", urlencoding::encode(name))
}

/// Re-check of an unchanged archive.org item: repeat the previous verdict,
/// first sniffing the copy's leading bytes if that verdict has no `file_type`.
pub async fn ia_unchanged_verdict(prev: &IaPrevious) -> Verdict {
    if let Some(ft) = prev.file_type {
        return ia_conditional_verdict(prev, ft);
    }
    let Some(url) = ia_fetch_url(&prev.final_url) else { return Verdict::Unknown(format!("not an archive.org download URL: {}", prev.final_url)) };
    match sniff_url(&url).await {
        Ok(Some(ft)) => ia_conditional_verdict(prev, ft),
        Ok(None) => Verdict::Changed { final_url: prev.final_url.clone(), detail: NOT_A_DOCUMENT.into() },
        Err(e) => Verdict::Unknown(format!("{e:#}")),
    }
}

pub struct Fetched {
    pub final_url: String,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size: u64,
    pub file_type: Option<FileType>,
    /// Empty unless the final URL is stable (see `stable_url`).
    pub validators: Validators,
    /// The body was written to the `save_pdf_to` path (only PDFs are).
    pub saved: bool,
}

pub enum FetchOutcome {
    /// The body was downloaded and hashed.
    Full(Fetched),
    /// The hop at the conditional's `final_url` answered 304 to our validators.
    NotModified { final_url: String },
}

/// Fetch `url` with the verifier's rules and hash the body.
pub async fn fetch_and_hash(url: &str) -> Result<Fetched> {
    match fetch(url, None).await? {
        FetchOutcome::Full(f) => Ok(f),
        FetchOutcome::NotModified { .. } => bail!("unexpected 304"),
    }
}

/// Test-only seam: lets the in-module tests point the verifier at a plain-HTTP
/// loopback server (and archive.org calls at a mock, without the per-host
/// pause). The flags only exist under `cfg(test)` (unit tests of this crate);
/// production and integration-test builds compile `allow_local` to `false`,
/// `ia_base` to IA_BASE and `host_interval` to HOST_INTERVAL, so every SSRF
/// check below always applies there.
#[cfg(test)]
pub(crate) mod test_seam {
    thread_local! {
        pub static ALLOW_LOCAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub static IA_BASE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
        pub static NO_PAUSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub static MALWAREBAZAAR_API: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    }
}

fn malwarebazaar_api() -> String {
    #[cfg(test)]
    if let Some(b) = test_seam::MALWAREBAZAAR_API.with(|c| c.borrow().clone()) {
        return b;
    }
    MALWAREBAZAAR_API.to_string()
}

fn ia_base() -> String {
    #[cfg(test)]
    if let Some(b) = test_seam::IA_BASE.with(|c| c.borrow().clone()) {
        return b;
    }
    IA_BASE.to_string()
}

fn host_interval() -> Duration {
    #[cfg(test)]
    if test_seam::NO_PAUSE.with(|c| c.get()) {
        return Duration::ZERO;
    }
    HOST_INTERVAL
}

fn user_agent() -> String {
    format!("OpenManuals-verifier/{} (+https://openmanuals.org)", env!("CARGO_PKG_VERSION"))
}

fn allow_local() -> bool {
    #[cfg(test)]
    {
        test_seam::ALLOW_LOCAL.with(|c| c.get())
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Where the hop loop ended.
enum Opened {
    /// The hop at the conditional's `final_url` answered 304.
    NotModified { final_url: String },
    /// A success response (200, or 206 to a range request), body unread.
    Body { resp: reqwest::Response, final_url: reqwest::Url },
}

/// The one HTTP path of the verifier: https only, no credentials, every hop
/// resolved and refused if non-public, redirects only within the submitted
/// registrable domain, a time cap. With `cond`, the hop whose URL equals
/// `cond.final_url` carries the conditional headers and a 304 there ends the
/// fetch without a body; a 304 anywhere else is an error. With `range`, every
/// hop carries that Range header. Every request of the verifier to a copy goes
/// through here (`fetch_saving` for whole bodies, `sniff_url` for first bytes).
/// `any_domain` lifts the same-domain rule for redirects (avatars: an image
/// URL may redirect to a CDN); every hop is still resolved and checked.
async fn open(url: &str, cond: Option<&Conditional>, range: Option<&str>) -> Result<Opened> {
    open_with(url, cond, range, false).await
}

async fn open_with(url: &str, cond: Option<&Conditional>, range: Option<&str>, any_domain: bool) -> Result<Opened> {
    let local = allow_local();
    let domain_of = |h: &str| registrable_domain(h).or_else(|| local.then(|| h.to_string()));
    let cond_url = cond.and_then(|c| reqwest::Url::parse(&c.final_url).ok());
    let start = reqwest::Url::parse(url).context("parsing url")?;
    let origin_host = start.host_str().ok_or_else(|| anyhow!("no host"))?.to_ascii_lowercase();
    let origin_domain = domain_of(&origin_host).ok_or_else(|| anyhow!("host has no registrable domain"))?;
    let mut current = start;
    for _hop in 0..MAX_HOPS {
        if current.scheme() != "https" && !(local && current.scheme() == "http") {
            bail!("only https URLs are verified");
        }
        if !current.username().is_empty() || current.password().is_some() {
            bail!("URLs with credentials are refused");
        }
        let host = current.host_str().ok_or_else(|| anyhow!("no host"))?.to_ascii_lowercase();
        if !any_domain && domain_of(&host).as_deref() != Some(origin_domain.as_str()) {
            bail!("redirect leaves the submitted domain ({host})");
        }
        let port = current.port_or_known_default().unwrap_or(443);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await.context("resolving host")?.collect();
        if addrs.is_empty() {
            bail!("host does not resolve");
        }
        if let Some(bad) = addrs.iter().find(|a| !is_public_ip(a.ip())) {
            if !local {
                bail!("host resolves to a non-public address {}", bad.ip());
            }
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH_TIMEOUT)
            .connect_timeout(Duration::from_secs(20))
            .user_agent(user_agent())
            .resolve_to_addrs(&host, &addrs)
            .build()?;
        let hop_cond = cond.filter(|_| cond_url.as_ref() == Some(&current));
        let mut req = client.get(current.clone());
        if let Some(c) = hop_cond {
            if let Some(e) = &c.if_none_match {
                req = req.header(reqwest::header::IF_NONE_MATCH, e);
            }
            if let Some(lm) = &c.if_modified_since {
                req = req.header(reqwest::header::IF_MODIFIED_SINCE, lm);
            }
        }
        if let Some(r) = range {
            req = req.header(reqwest::header::RANGE, r);
        }
        let resp = req.send().await.context("request failed")?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            let Some(c) = hop_cond else { bail!("unexpected 304 Not Modified") };
            // A 304 must repeat the ETag it matched; a different strong tag means confusion.
            if let (Some(sent), Some(got)) = (&c.if_none_match, resp.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok())) {
                if got.trim() != sent {
                    bail!("304 with a different ETag");
                }
            }
            return Ok(Opened::NotModified { final_url: current.to_string() });
        }
        if status.is_redirection() {
            let loc = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).ok_or_else(|| anyhow!("redirect without Location"))?;
            current = current.join(loc).context("bad redirect target")?;
            continue;
        }
        // 206 only answers a range request.
        if !(status == reqwest::StatusCode::OK || (status.is_success() && range.is_none()) || (status == reqwest::StatusCode::PARTIAL_CONTENT && range.is_some())) {
            bail!("HTTP {status}");
        }
        return Ok(Opened::Body { resp, final_url: current });
    }
    bail!("too many redirects")
}

/// Fetch `url` through `open` and hash the whole body (size cap applies).
pub async fn fetch(url: &str, cond: Option<&Conditional>) -> Result<FetchOutcome> {
    fetch_saving(url, cond, None).await
}

/// `fetch`, also writing the body to `save_pdf_to` when its first bytes sniff
/// as PDF (for the active-content scan); `Fetched::saved` says whether it did.
/// The caller owns (and deletes) the file.
pub async fn fetch_saving(url: &str, cond: Option<&Conditional>, save_pdf_to: Option<&Path>) -> Result<FetchOutcome> {
    use futures_util::StreamExt;
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;
    let (resp, final_url) = match open(url, cond, None).await? {
        Opened::NotModified { final_url } => return Ok(FetchOutcome::NotModified { final_url }),
        Opened::Body { resp, final_url } => (resp, final_url.to_string()),
    };
    if let Some(len) = resp.content_length() {
        if len > MAX_FETCH_BYTES {
            bail!("file larger than the {MAX_FETCH_BYTES}-byte cap");
        }
    }
    let validators = if stable_url(url, &final_url) { validators_from_headers(resp.headers(), jiff::Timestamp::now()) } else { Validators::default() };
    let mut s256 = sha2::Sha256::new();
    let mut s1 = sha1::Sha1::new();
    let mut m5 = md5::Md5::new();
    let mut size: u64 = 0;
    // The first bytes, held until there are enough to sniff; then the body
    // goes to `out` if it is a PDF.
    let mut head: Vec<u8> = Vec::new();
    let mut decided = save_pdf_to.is_none();
    let mut out: Option<tokio::io::BufWriter<tokio::fs::File>> = None;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading body")?;
        size += chunk.len() as u64;
        if size > MAX_FETCH_BYTES {
            bail!("file larger than the {MAX_FETCH_BYTES}-byte cap");
        }
        s256.update(&chunk);
        s1.update(&chunk);
        m5.update(&chunk);
        if let Some(w) = out.as_mut() {
            w.write_all(&chunk).await.context("writing the scan copy")?;
        } else if !decided {
            head.extend_from_slice(&chunk);
            if head.len() >= SNIFF_BYTES {
                decided = true;
                out = start_saving(save_pdf_to, &head).await?;
            }
        } else if head.len() < SNIFF_BYTES {
            head.extend_from_slice(&chunk[..chunk.len().min(SNIFF_BYTES - head.len())]);
        }
    }
    if !decided {
        out = start_saving(save_pdf_to, &head).await?;
    }
    let saved = out.is_some();
    if let Some(mut w) = out {
        w.flush().await.context("writing the scan copy")?;
    }
    head.truncate(SNIFF_BYTES);
    Ok(FetchOutcome::Full(Fetched {
        final_url,
        sha256: hex::encode(s256.finalize()),
        sha1: hex::encode(s1.finalize()),
        md5: hex::encode(m5.finalize()),
        size,
        file_type: openmanuals_core::sniff::sniff(&head),
        validators,
        saved,
    }))
}

/// How long an avatar fetch may take in all.
pub const AVATAR_TIMEOUT: Duration = Duration::from_secs(30);

/// Fetch a small image (an avatar URL) through the same guarded path as
/// copies: https only, no credentials, every hop resolved to a public
/// address; redirects may change domain. At most `max` bytes.
pub async fn fetch_small(url: &str, max: u64) -> Result<Vec<u8>> {
    let work = async {
        let Opened::Body { mut resp, .. } = open_with(url, None, None, true).await? else { bail!("unexpected 304") };
        if resp.content_length().is_some_and(|n| n > max) {
            bail!("larger than {max} bytes");
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.context("reading body")? {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > max {
                bail!("larger than {max} bytes");
            }
        }
        Ok(body)
    };
    tokio::time::timeout(AVATAR_TIMEOUT, work).await.map_err(|_| anyhow!("timed out"))?
}

/// Open `path` and write `head` to it if `head` sniffs as PDF.
async fn start_saving(path: Option<&Path>, head: &[u8]) -> Result<Option<tokio::io::BufWriter<tokio::fs::File>>> {
    use tokio::io::AsyncWriteExt;
    let Some(path) = path.filter(|_| openmanuals_core::sniff::sniff(head) == Some(FileType::Pdf)) else { return Ok(None) };
    let f = tokio::fs::File::create(path).await.with_context(|| format!("creating {}", path.display()))?;
    let mut w = tokio::io::BufWriter::with_capacity(1 << 20, f);
    w.write_all(head).await.context("writing the scan copy")?;
    Ok(Some(w))
}

/// The type of the copy at `url`, from its first bytes: a range request
/// (SNIFF_RANGE) through `open`. A server that ignores the range answers 200;
/// only the first bytes are read either way.
pub async fn sniff_url(url: &str) -> Result<Option<FileType>> {
    let Opened::Body { mut resp, .. } = open(url, None, Some(SNIFF_RANGE)).await? else { bail!("unexpected 304") };
    let mut head: Vec<u8> = Vec::new();
    while head.len() < SNIFF_BYTES {
        match resp.chunk().await.context("reading body")? {
            Some(c) => head.extend_from_slice(&c[..c.len().min(SNIFF_BYTES - head.len())]),
            None => break,
        }
    }
    Ok(openmanuals_core::sniff::sniff(&head))
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// `conditional`: confirmed by a 304 against the previous verdict's
    /// validators, or (archive.org) by the search index showing the item
    /// unchanged; sha256/size/validators are carried over from it.
    /// `ia`: item validators of an archive.org copy. `file_type`: sniffed by
    /// this server (or carried over by a conditional verdict). `checks`: scan
    /// and malware lookup, when the bytes were downloaded (or carried over).
    Verified { final_url: String, sha256: Option<String>, size: u64, validators: Validators, ia: Option<IaValidators>, conditional: bool, file_type: FileType, checks: Checks },
    Changed { final_url: String, detail: String },
    Dark,
    Gone,
    /// Couldn't decide (network error etc.): no fact emitted, retried later.
    Unknown(String),
}

pub struct FileFacts {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

fn ia_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder().timeout(Duration::from_secs(60)).user_agent(user_agent()).build()
}

/// What a full verification needs besides the copy: where to put the
/// temporary copy of a PDF for scanning, and the MalwareBazaar key.
#[derive(Debug, Clone, Default)]
pub struct Examine {
    pub tmp_dir: PathBuf,
    pub malwarebazaar_key: Option<String>,
}

impl Examine {
    pub fn from_state(state: &State) -> Examine {
        Examine { tmp_dir: scan_tmp_dir(state), malwarebazaar_key: state.paths.malwarebazaar_key.clone().filter(|k| !k.trim().is_empty()) }
    }
}

/// `<data-dir>/verify-tmp`: PDFs being scanned (deleted after each scan).
pub fn scan_tmp_dir(state: &State) -> PathBuf {
    state.paths.data_dir.join("verify-tmp")
}

/// A temporary file path, removed (if it was created) on drop.
struct TempFile(PathBuf);

impl TempFile {
    fn new(dir: &Path) -> Result<TempFile> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(TempFile(dir.join(format!("scan-{}.pdf", ulid::Ulid::new()))))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Remove scan copies left behind by a crash (older than an hour, so a
/// concurrent `openmanuals-server verify` keeps its own).
fn sweep_tmp(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > Duration::from_secs(3600));
        if old && e.file_name().to_string_lossy().starts_with("scan-") {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Scan and look up bytes that were downloaded in full and matched the file.
/// `saved`: the PDF copy on disk (None for DjVu, which has no active content).
async fn examine(ex: &Examine, file_type: FileType, saved: Option<&Path>, sha256: &str) -> Checks {
    let scan = match (file_type, saved) {
        (FileType::Djvu, _) => Scan::clean(),
        (FileType::Pdf, Some(p)) => scan::scan_pdf_file(p).await,
        (FileType::Pdf, None) => Scan::unparseable(),
    };
    Checks { scan: Some(scan.to_json()), malware: malware_lookup(ex.malwarebazaar_key.as_deref(), sha256).await }
}

/// The `malware` member for `sha256`: None without a key, or when the lookup
/// fails (logged). Only the hash is sent.
pub async fn malware_lookup(key: Option<&str>, sha256: &str) -> Option<Value> {
    let key = key?;
    match malwarebazaar_query(key, sha256).await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(sha256, error = %format!("{e:#}"), "MalwareBazaar lookup failed");
            None
        }
    }
}

async fn malwarebazaar_query(key: &str, sha256: &str) -> Result<Value> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).user_agent(user_agent()).build()?;
    let resp = client.post(malwarebazaar_api()).header("Auth-Key", key).form(&[("query", "get_info"), ("hash", sha256)]).send().await.context("request failed")?;
    let status = resp.status();
    if !status.is_success() {
        bail!("HTTP {status}");
    }
    let v: Value = resp.json().await.context("response")?;
    parse_malwarebazaar(&v)
}

/// A MalwareBazaar `get_info` answer as the `malware` member:
/// `{"query_status": "ok", "data": [{…, "signature": …}]}` is listed,
/// `{"query_status": "hash_not_found"}` is not; anything else is an error.
pub fn parse_malwarebazaar(v: &Value) -> Result<Value> {
    match v.get("query_status").and_then(Value::as_str) {
        Some("ok") => {
            let entry = v.get("data").and_then(Value::as_array).and_then(|a| a.first()).ok_or_else(|| anyhow!("MalwareBazaar: ok without data"))?;
            let signature = entry.get("signature").and_then(Value::as_str).filter(|s| !s.is_empty());
            Ok(json!({"source": "malwarebazaar", "listed": true, "signature": signature}))
        }
        Some("hash_not_found") => Ok(json!({"source": "malwarebazaar", "listed": false, "signature": null})),
        other => bail!("MalwareBazaar query_status {other:?}"),
    }
}

/// Whether bytes hashed to (sha256, sha1, md5) are the file: sha256 when the
/// file has one, else sha1, else md5.
fn hashes_match(file: &FileFacts, f: &Fetched) -> bool {
    match (&file.sha256, &file.sha1, &file.md5) {
        (Some(s), _, _) => *s == f.sha256,
        (None, Some(s), _) => *s == f.sha1,
        (None, None, Some(m)) => *m == f.md5,
        _ => false,
    }
}

/// archive.org: compare the item's own checksums with the file's, then
/// confirm the bytes are a document: from the first bytes (`full_scan`
/// false), or by downloading, hashing and scanning the whole file.
pub async fn check_archive_item(identifier: &str, filename: Option<&str>, file: &FileFacts, ex: &Examine, full_scan: bool) -> Verdict {
    let url = format!("{}/metadata/{identifier}", ia_base());
    let client = match ia_client() {
        Ok(c) => c,
        Err(e) => return Verdict::Unknown(e.to_string()),
    };
    let v: Value = match client.get(&url).send().await.and_then(|r| r.error_for_status()) {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => return Verdict::Unknown(e.to_string()),
        },
        Err(e) => return Verdict::Unknown(e.to_string()),
    };
    let m = match archive_match(identifier, filename, file, &v) {
        Ok(m) => m,
        Err(v) => return v,
    };
    let public = ia_download_url(identifier, &m.name);
    let Some(fetch_url) = ia_fetch_url(&public) else { return Verdict::Unknown("bad download URL".into()) };
    if full_scan {
        return ia_download_and_scan(public, &fetch_url, file, m, ex).await;
    }
    match sniff_url(&fetch_url).await {
        Ok(Some(file_type)) => Verdict::Verified { final_url: public, sha256: file.sha256.clone(), size: m.size, validators: Validators::default(), ia: m.ia, conditional: false, file_type, checks: Checks::default() },
        Ok(None) => Verdict::Changed { final_url: public, detail: NOT_A_DOCUMENT.into() },
        Err(e) => Verdict::Unknown(format!("{e:#}")),
    }
}

async fn ia_download_and_scan(public: String, fetch_url: &str, file: &FileFacts, m: IaFile, ex: &Examine) -> Verdict {
    let tmp = match TempFile::new(&ex.tmp_dir) {
        Ok(t) => t,
        Err(e) => return Verdict::Unknown(format!("{e:#}")),
    };
    let f = match fetch_saving(fetch_url, None, Some(tmp.path())).await {
        Ok(FetchOutcome::Full(f)) => f,
        Ok(FetchOutcome::NotModified { .. }) => return Verdict::Unknown("unexpected 304".into()),
        Err(e) => return Verdict::Unknown(format!("{e:#}")),
    };
    let Some(file_type) = f.file_type else { return Verdict::Changed { final_url: public, detail: NOT_A_DOCUMENT.into() } };
    if !hashes_match(file, &f) {
        return Verdict::Changed { final_url: public, detail: "checksum differs".into() };
    }
    let checks = examine(ex, file_type, f.saved.then(|| tmp.path()), &f.sha256).await;
    Verdict::Verified { final_url: public, sha256: Some(f.sha256), size: f.size, validators: Validators::default(), ia: m.ia, conditional: false, file_type, checks }
}

/// One scrape request for `ids` (at most one batch from `ia_batches`).
/// Identifiers absent from the result simply have no row.
pub async fn ia_scrape(ids: &[&str]) -> Result<HashMap<String, IaRow>> {
    let count = ids.len().max(100).to_string();
    let q = ia_batch_query(ids);
    let url = reqwest::Url::parse_with_params(&format!("{}{IA_SCRAPE_PATH}", ia_base()), [("fields", IA_SCRAPE_FIELDS), ("q", q.as_str()), ("count", count.as_str())])?;
    let resp = ia_client()?.get(url).send().await.context("archive.org scrape request failed")?;
    let status = resp.status();
    if !status.is_success() {
        bail!("archive.org scrape: HTTP {status}");
    }
    let v: Value = resp.json().await.context("archive.org scrape response")?;
    parse_scrape(&v)
}

/// The file of an archive.org item whose checksum matches.
#[derive(Debug, Clone, PartialEq)]
pub struct IaFile {
    pub name: String,
    pub size: u64,
    pub ia: Option<IaValidators>,
}

/// Find the file in an item's metadata; Err is the verdict when there's none.
fn archive_match(identifier: &str, filename: Option<&str>, file: &FileFacts, meta: &Value) -> std::result::Result<IaFile, Verdict> {
    if meta.as_object().is_none_or(|o| o.is_empty()) {
        return Err(Verdict::Gone);
    }
    if meta.get("is_dark").and_then(Value::as_bool) == Some(true) {
        return Err(Verdict::Dark);
    }
    let files = meta.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
    let matches = |f: &Value| -> bool {
        let sha1 = f.get("sha1").and_then(Value::as_str);
        let md5 = f.get("md5").and_then(Value::as_str);
        (file.sha1.is_some() && sha1 == file.sha1.as_deref()) || (file.sha1.is_none() && file.md5.is_some() && md5 == file.md5.as_deref())
    };
    if file.sha1.is_none() && file.md5.is_none() {
        return Err(Verdict::Unknown("file has no sha1/md5 to compare with archive.org's listing".into()));
    }
    if let Some(f) = files.iter().find(|f| matches(f)) {
        let name = f.get("name").and_then(Value::as_str).unwrap_or("");
        let size = f.get("size").and_then(|s| s.as_str().and_then(|s| s.parse().ok()).or_else(|| s.as_u64())).unwrap_or(0);
        return Ok(IaFile { name: name.to_string(), size, ia: ia_validators_from_metadata(meta) });
    }
    if let Some(name) = filename {
        if files.iter().any(|f| f.get("name").and_then(Value::as_str) == Some(name)) {
            return Err(Verdict::Changed { final_url: ia_download_url(identifier, name), detail: "checksum differs".into() });
        }
    }
    if files.is_empty() {
        Err(Verdict::Unknown("item has no file listing yet".into()))
    } else {
        Err(Verdict::Changed { final_url: format!("https://archive.org/details/{identifier}"), detail: "no file with the expected checksum".into() })
    }
}

/// Any other host: fetch, hash, sniff and scan. With a usable `prev` verdict,
/// first ask conditionally; only a 304 at the previously recorded final URL
/// skips the download (repeating the previous file type and checks),
/// anything else falls through to the full fetch in the same request.
pub async fn check_generic(url: &str, file: &FileFacts, prev: Option<&Previous>, ex: &Examine) -> Verdict {
    let cond = prev.and_then(conditional_request);
    let tmp = match TempFile::new(&ex.tmp_dir) {
        Ok(t) => t,
        Err(e) => return Verdict::Unknown(format!("{e:#}")),
    };
    match fetch_saving(url, cond.as_ref(), Some(tmp.path())).await {
        Ok(FetchOutcome::NotModified { final_url }) => {
            // `cond` is only Some when `prev` is.
            let p = prev.expect("conditional without previous verdict");
            Verdict::Verified { final_url, sha256: Some(p.sha256.clone()), size: p.size, validators: p.validators.clone(), ia: None, conditional: true, file_type: p.file_type, checks: p.checks.clone() }
        }
        Ok(FetchOutcome::Full(f)) => {
            let Some(file_type) = f.file_type else { return Verdict::Changed { final_url: f.final_url, detail: NOT_A_DOCUMENT.into() } };
            if !hashes_match(file, &f) {
                return Verdict::Changed { final_url: f.final_url, detail: "checksum differs".into() };
            }
            let checks = examine(ex, file_type, f.saved.then(|| tmp.path()), &f.sha256).await;
            Verdict::Verified { final_url: f.final_url, sha256: Some(f.sha256), size: f.size, validators: f.validators, ia: None, conditional: false, file_type, checks }
        }
        Err(e) => {
            let s = e.to_string();
            if s.contains("HTTP 404") || s.contains("HTTP 410") {
                Verdict::Gone
            } else {
                Verdict::Unknown(format!("{e:#}"))
            }
        }
    }
}

pub struct Candidate {
    pub entry: Entry,
    pub file: FileFacts,
    /// Usable earlier verdict for a conditional re-check (generic hosts only).
    pub prev: Option<Previous>,
    /// Usable earlier verdict for a batched re-check (archive.org copies only).
    pub ia_prev: Option<IaPrevious>,
    /// archive.org copies: download and scan the whole file at a full check,
    /// because the file's first `file` fact is by a key outside the trust
    /// config's moderators and servers (or there is none). Copies of files
    /// introduced by trusted keys are typed from their first bytes only.
    pub full_scan: bool,
}

/// The archive.org identifier of a location checked through archive.org's APIs.
pub fn archive_identifier(body: &Value) -> Option<&str> {
    let url = body.get("url").and_then(Value::as_str).unwrap_or("");
    body.get("ia").and_then(|i| i.get("identifier")).and_then(Value::as_str).filter(|_| url.contains("archive.org/"))
}

fn days_between(ts: &str, now: jiff::Timestamp) -> i64 {
    let Ok(t) = ts.parse::<jiff::Timestamp>() else { return i64::MAX };
    // Whole seconds, not `(now - t).get_hours()`: Timestamp subtraction yields a
    // Span balanced only up to seconds, so its hours component is always 0.
    (now.as_second() - t.as_second()).div_euclid(86_400)
}

fn days_since(ts: &str) -> i64 {
    days_between(ts, jiff::Timestamp::now())
}

/// Locations that have no verdict, or whose verdict is older than RECHECK_DAYS.
pub fn location_candidates(state: &State, limit: usize) -> Result<Vec<Candidate>> {
    let locations = state.inbox.by_type("location")?;
    let mut latest: HashMap<String, String> = HashMap::new();
    let mut verdicts: HashMap<String, Vec<(&'static str, Value)>> = HashMap::new();
    for t in ["verified", "location_status"] {
        for e in state.inbox.by_author_and_type(&state.fingerprint, t)? {
            if let (Some(loc), Some(at)) = (e.fact.body.get("location").and_then(Value::as_str), e.fact.body.get("checked_at").and_then(Value::as_str)) {
                let cur = latest.entry(loc.to_string()).or_default();
                if at > cur.as_str() {
                    *cur = at.to_string();
                }
                verdicts.entry(loc.to_string()).or_default().push((t, e.fact.body.clone()));
            }
        }
    }
    let now = jiff::Timestamp::now();
    let mut files: HashMap<String, FileFacts> = HashMap::new();
    // Whether the first `file` fact (in ingestion order) for a file key is by a trusted key.
    let mut first_trusted: HashMap<String, bool> = HashMap::new();
    let trust = state.trust.read().unwrap().clone();
    for e in state.inbox.by_type("file")? {
        let b = &e.fact.body;
        let g = |k: &str| b.get(k).and_then(Value::as_str).map(|s| s.to_ascii_lowercase());
        let ff = FileFacts { sha256: g("sha256"), sha1: g("sha1"), md5: g("md5") };
        let trusted = trust.is_server(&e.fact.author) || trust.is_moderator(&e.fact.author);
        if let Some(s) = &ff.sha256 {
            first_trusted.entry(s.clone()).or_insert(trusted);
            files.insert(s.clone(), FileFacts { sha256: ff.sha256.clone(), sha1: ff.sha1.clone(), md5: ff.md5.clone() });
        }
        if let Some(s) = &ff.sha1 {
            first_trusted.entry(format!("sha1:{s}")).or_insert(trusted);
            files.entry(format!("sha1:{s}")).or_insert(ff);
        }
    }
    let mut out = Vec::new();
    for e in locations {
        if e.fact.body.get("kind").and_then(Value::as_str) == Some("origin") {
            continue;
        }
        if let Some(at) = latest.get(&e.id) {
            if days_since(at) < RECHECK_DAYS {
                continue;
            }
        }
        let Some(fid) = e.fact.body.get("file").and_then(Value::as_str).and_then(openmanuals_ledger::model::parse_file_ref) else { continue };
        let ff = match files.get(&fid) {
            Some(f) => FileFacts { sha256: f.sha256.clone(), sha1: f.sha1.clone(), md5: f.md5.clone() },
            None => {
                if let Some(h) = fid.strip_prefix("sha1:") {
                    FileFacts { sha256: None, sha1: Some(h.to_string()), md5: None }
                } else {
                    FileFacts { sha256: Some(fid.clone()), sha1: None, md5: None }
                }
            }
        };
        let mine = verdicts.get(&e.id);
        let prev = mine.and_then(|v| previous_verdict(v.iter().map(|(t, b)| (*t, b)), now));
        let full_scan = first_trusted.get(&fid) != Some(&true);
        // A batched re-check repeats the previous verdict's scan, so a file
        // that needs one but whose verdict has none gets the full check; a
        // verdict without file_type needs a download URL to sniff.
        let ia_prev = mine
            .filter(|_| archive_identifier(&e.fact.body).is_some())
            .and_then(|v| previous_ia_verdict(v.iter().map(|(t, b)| (*t, b)), now))
            .filter(|p| !full_scan || p.checks.scan.is_some())
            .filter(|p| p.file_type.is_some() || ia_fetch_url(&p.final_url).is_some());
        out.push(Candidate { entry: e, file: ff, prev, ia_prev, full_scan });
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

/// Check one location the full way (archive.org metadata, or fetch with an
/// optional conditional request elsewhere).
pub async fn check_location(c: &Candidate, ex: &Examine) -> Verdict {
    let b = &c.entry.fact.body;
    let url = b.get("url").and_then(Value::as_str).unwrap_or("");
    match archive_identifier(b) {
        Some(identifier) => check_archive_item(identifier, b.get("ia").and_then(|i| i.get("filename")).and_then(Value::as_str), &c.file, ex, c.full_scan).await,
        None => check_generic(url, &c.file, c.prev.as_ref(), ex).await,
    }
}

/// Verify one location and return the server fact to record, if any.
pub async fn verify_location(state: &State, c: &Candidate) -> Result<Option<Fact>> {
    let verdict = check_location(c, &Examine::from_state(state)).await;
    verdict_fact(state, c, verdict)
}

/// The server fact recording `verdict` for candidate `c`, if any.
pub fn verdict_fact(state: &State, c: &Candidate, verdict: Verdict) -> Result<Option<Fact>> {
    let url = c.entry.fact.body.get("url").and_then(Value::as_str).unwrap_or("");
    let now = State::now();
    let fact = match verdict {
        Verdict::Verified { final_url, sha256, size, validators, ia, conditional, file_type, checks } => {
            Some(state.server_fact("verified", verified_body(&c.entry.id, &final_url, sha256.as_deref(), size, &validators, ia.as_ref(), conditional, &now, Some(file_type), &checks))?)
        }
        Verdict::Changed { final_url, detail } => Some(state.server_fact("location_status", json!({"location": c.entry.id, "status": "changed", "final_url": final_url, "detail": detail, "checked_at": now}))?),
        Verdict::Dark => Some(state.server_fact("location_status", json!({"location": c.entry.id, "status": "dark", "checked_at": now}))?),
        Verdict::Gone => Some(state.server_fact("location_status", json!({"location": c.entry.id, "status": "gone", "checked_at": now}))?),
        Verdict::Unknown(why) => {
            tracing::warn!(url, why, "could not verify");
            None
        }
    };
    Ok(fact)
}

/// Body of a `verified` fact. Validator fields, `method`, `file_type`, `scan`
/// and `malware` are omitted when absent (the verifier always passes a
/// `file_type`; None only builds verdicts from before it was recorded).
#[allow(clippy::too_many_arguments)]
pub fn verified_body(location: &str, final_url: &str, sha256: Option<&str>, size: u64, v: &Validators, ia: Option<&IaValidators>, conditional: bool, checked_at: &str, file_type: Option<FileType>, checks: &Checks) -> Value {
    let mut b = json!({"location": location, "final_url": final_url, "sha256": sha256, "size": size, "checked_at": checked_at});
    if let Some(e) = &v.etag {
        b["etag"] = json!(e);
    }
    if let Some(lm) = &v.last_modified {
        b["last_modified"] = json!(lm);
    }
    if let Some(n) = v.content_length {
        b["content_length"] = json!(n);
    }
    if let Some(ia) = ia {
        b["ia_updated"] = json!(ia.updated);
        b["ia_item_size"] = json!(ia.item_size);
        b["ia_files_count"] = json!(ia.files_count);
    }
    if conditional {
        b["method"] = json!(METHOD_CONDITIONAL);
    }
    if let Some(ft) = file_type {
        b["file_type"] = json!(ft.extension());
    }
    if let Some(s) = &checks.scan {
        b["scan"] = s.clone();
    }
    if let Some(m) = &checks.malware {
        b["malware"] = m.clone();
    }
    b
}

/// Run the doipjs wrapper on a profile; returns identity_link facts for verified claims.
pub async fn verify_profile(state: &State, fp: &str, jws: &str) -> Result<Vec<Fact>> {
    let Some(script) = state.paths.doip_script.clone().filter(|p| p.exists()) else { return Ok(vec![]) };
    let uri = openmanuals_core::asp::aspe_uri(&state.trust.read().unwrap().domain, fp);
    let out = tokio::time::timeout(
        Duration::from_secs(180),
        tokio::process::Command::new("node").arg(&script).arg(&uri).arg(jws).kill_on_drop(true).output(),
    )
    .await
    .context("doip-verify timed out")??;
    let text = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(text.trim().lines().last().unwrap_or("{}")).with_context(|| format!("doip-verify output: {text}"))?;
    if let Some(e) = v.get("error") {
        bail!("doip-verify: {e}");
    }
    let now = State::now();
    let mut facts = Vec::new();
    for c in v.get("claims").and_then(Value::as_array).cloned().unwrap_or_default() {
        if c.get("verified").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let (Some(uri), Some(service), Some(handle)) = (c.get("uri").and_then(Value::as_str), c.get("service").and_then(Value::as_str), c.get("handle").and_then(Value::as_str)) else { continue };
        facts.push(state.server_fact("identity_link", json!({"key": fp, "claim_uri": uri, "service": service, "handle": handle, "checked_at": now}))?);
    }
    Ok(facts)
}

/// Profiles never checked, or checked more than RECHECK_DAYS ago.
pub fn profile_candidates(state: &State) -> Result<Vec<(String, String)>> {
    let mut newest: HashMap<String, String> = HashMap::new();
    for e in state.inbox.by_type("identity_profile")? {
        if let Some(jws) = e.fact.body.get("jws").and_then(Value::as_str) {
            newest.insert(e.fact.author.clone(), jws.to_string());
        }
    }
    let mut out = Vec::new();
    for (fp, jws) in newest {
        let key = format!("profile_checked:{}", openmanuals_core::canon::sha256_hex(jws.as_bytes()));
        if let Some(at) = state.inbox.state_get(&key)? {
            if days_since(&at) < RECHECK_DAYS {
                continue;
            }
        }
        out.push((fp, jws));
    }
    out.sort();
    Ok(out)
}

/// Per-host politeness: at least `host_interval()` between requests to a host.
#[derive(Default)]
struct Pacer {
    last_hit: HashMap<String, Instant>,
}

impl Pacer {
    async fn wait(&mut self, host: &str) {
        let interval = host_interval();
        if let Some(t) = self.last_hit.get(host) {
            let el = t.elapsed();
            if el < interval {
                tokio::time::sleep(interval - el).await;
            }
        }
        self.last_hit.insert(host.to_string(), Instant::now());
    }
}

/// Batch phase of a pass: scrape the search index for every archive.org
/// candidate with a usable previous verdict, IA_BATCH_MAX_IDS per request
/// (each request paced like any other archive.org request). Returns the
/// indexes of candidates confirmed unchanged (they get `ia_unchanged_verdict`);
/// every other candidate (including all of a batch whose request failed) is
/// left for the per-item check.
async fn ia_batch_phase(cands: &[&Candidate], pacer: &mut Pacer) -> HashSet<usize> {
    let ids = cands.iter().filter(|c| c.ia_prev.is_some()).filter_map(|c| archive_identifier(&c.entry.fact.body));
    let batches = ia_batches(ids);
    let host = openmanuals_ledger::model::host_of(&ia_base()).unwrap_or_default();
    let mut rows: HashMap<String, IaRow> = HashMap::new();
    let mut answered: HashSet<&str> = HashSet::new();
    for batch in &batches {
        pacer.wait(&host).await;
        match ia_scrape(batch).await {
            Ok(r) => {
                rows.extend(r);
                answered.extend(batch.iter().copied());
            }
            Err(e) => tracing::warn!(error = %format!("{e:#}"), n = batch.len(), "archive.org batch re-check failed; checking items one by one"),
        }
    }
    let mut out = HashSet::new();
    let (mut unchanged, mut recheck) = (0usize, 0usize);
    for (i, c) in cands.iter().enumerate() {
        let (Some(prev), Some(id)) = (&c.ia_prev, archive_identifier(&c.entry.fact.body)) else { continue };
        if !answered.contains(id) {
            continue;
        }
        match ia_batch_decision(prev, rows.get(id)) {
            IaDecision::Unchanged => {
                out.insert(i);
                unchanged += 1;
            }
            IaDecision::Recheck(why) => {
                tracing::debug!(identifier = id, why, "archive.org item needs a full re-check");
                recheck += 1;
            }
        }
    }
    if !batches.is_empty() {
        tracing::info!(requests = batches.len(), unchanged, recheck, "archive.org batch re-check");
    }
    out
}

/// One verifier pass. Returns the number of server facts recorded.
pub async fn run_once(state: Shared, max_locations: usize) -> Result<usize> {
    let st = state.clone();
    let cands = tokio::task::spawn_blocking(move || location_candidates(&st, max_locations)).await??;
    let db = state.db();
    let mut skipped_keys: HashSet<String> = HashSet::new();
    // Each candidate costs its author one unit of verify budget, batched or not.
    let mut todo: Vec<&Candidate> = Vec::new();
    for c in &cands {
        let author = c.entry.fact.author.clone();
        if skipped_keys.contains(&author) {
            continue;
        }
        let trusted = {
            let t = state.trust.read().unwrap();
            t.is_server(&author) || t.is_moderator(&author)
        };
        if !trusted {
            let limit = rate::verify_budget(rate::record(db.as_ref(), &author));
            if !state.budgets.spend(&author, "verify", 1, limit) {
                skipped_keys.insert(author);
                continue;
            }
        }
        todo.push(c);
    }
    let mut pacer = Pacer::default();
    let ia_host = openmanuals_ledger::model::host_of(&ia_base()).unwrap_or_default();
    sweep_tmp(&scan_tmp_dir(&state));
    let batched = ia_batch_phase(&todo, &mut pacer).await;
    let mut facts = Vec::new();
    for (i, c) in todo.iter().enumerate() {
        if let (true, Some(prev)) = (batched.contains(&i), &c.ia_prev) {
            if prev.file_type.is_none() {
                // A request for the first bytes; archive.org pacing applies.
                pacer.wait(&ia_host).await;
            }
            let v = ia_unchanged_verdict(prev).await;
            match verdict_fact(&state, c, v) {
                Ok(Some(f)) => facts.push(f),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "verify failed"),
            }
            continue;
        }
        // archive.org copies are checked through archive.org's API host, whatever their URL's host.
        let host = if archive_identifier(&c.entry.fact.body).is_some() { ia_host.clone() } else { openmanuals_ledger::model::host_of(c.entry.fact.body.get("url").and_then(Value::as_str).unwrap_or("")).unwrap_or_default() };
        pacer.wait(&host).await;
        match verify_location(&state, c).await {
            Ok(Some(f)) => facts.push(f),
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "verify failed"),
        }
    }
    let st = state.clone();
    let profiles = tokio::task::spawn_blocking(move || profile_candidates(&st)).await??;
    for (fp, jws) in profiles {
        match verify_profile(&state, &fp, &jws).await {
            Ok(fs) => {
                facts.extend(fs);
                let key = format!("profile_checked:{}", openmanuals_core::canon::sha256_hex(jws.as_bytes()));
                state.inbox.state_set(&key, &State::now())?;
            }
            Err(e) => tracing::warn!(fp, error = %e, "profile verification failed"),
        }
    }
    let n = facts.len();
    if n > 0 {
        let st = state.clone();
        let r = tokio::task::spawn_blocking(move || st.inbox.accept(&facts, |_| Ok(()))).await??;
        tracing::info!(accepted = r.accepted.len(), duplicate = r.duplicate.len(), rejected = r.rejected.len(), "recorded verifier facts");
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_filtering() {
        for bad in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(!is_public_ip(bad.parse().unwrap()), "{bad}");
        }
        for good in ["8.8.8.8", "207.241.224.2", "2600::1"] {
            assert!(is_public_ip(good.parse().unwrap()), "{good}");
        }
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("ia800203.us.archive.org").unwrap(), "archive.org");
        assert_eq!(registrable_domain("www.example.co.uk").unwrap(), "example.co.uk");
        assert!(registrable_domain("1.2.3.4").is_none());
    }

    #[test]
    fn archive_verdicts() {
        let file = FileFacts { sha256: None, sha1: Some("abc".into()), md5: None };
        assert_eq!(archive_match("x", None, &file, &json!({})), Err(Verdict::Gone));
        assert_eq!(archive_match("x", None, &file, &json!({"is_dark": true, "files": []})), Err(Verdict::Dark));
        let meta = json!({"files": [{"name": "m.pdf", "sha1": "abc", "size": "12"}]});
        assert_eq!(archive_match("x", Some("m.pdf"), &file, &meta), Ok(IaFile { name: "m.pdf".into(), size: 12, ia: None }));
        let other = FileFacts { sha256: None, sha1: Some("zzz".into()), md5: None };
        assert!(matches!(archive_match("x", Some("m.pdf"), &other, &meta), Err(Verdict::Changed { .. })));
    }

    // ---- conditional re-checks: pure decision logic ----

    fn ts(s: &str) -> jiff::Timestamp {
        s.parse().unwrap()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn strong_and_weak_etags() {
        for good in ["\"abc\"", "\"\"", "\"5f1-4a2b\""] {
            assert!(is_strong_etag(good), "{good}");
        }
        for bad in ["W/\"abc\"", "abc", "\"a\"b\"", "\"a b\"", "\"", "\"é\""] {
            assert!(!is_strong_etag(bad), "{bad}");
        }
    }

    #[test]
    fn validators_kept_from_response() {
        let now = ts("2026-10-30T12:00:00Z");
        let v = validators_from_headers(&headers(&[("etag", "\"v1\""), ("last-modified", "Tue, 01 Jan 2019 00:00:00 GMT"), ("content-length", "1234")]), now);
        assert_eq!(v, Validators { etag: Some("\"v1\"".into()), last_modified: Some("Tue, 01 Jan 2019 00:00:00 GMT".into()), content_length: Some(1234) });
        // Weak ETag dropped, Last-Modified still usable.
        let v = validators_from_headers(&headers(&[("etag", "W/\"v1\""), ("last-modified", "Tue, 01 Jan 2019 00:00:00 GMT")]), now);
        assert_eq!(v.etag, None);
        assert!(v.last_modified.is_some());
        // Last-Modified less than a minute old, or unparsable: not a validator.
        let v = validators_from_headers(&headers(&[("last-modified", "Fri, 30 Oct 2026 11:59:30 GMT")]), now);
        assert!(v.is_empty());
        let v = validators_from_headers(&headers(&[("last-modified", "yesterday")]), now);
        assert!(v.is_empty());
        assert_eq!(validators_from_headers(&headers(&[]), now), Validators::default());
    }

    #[test]
    fn stable_urls() {
        let u = "https://example.com/m.pdf";
        assert!(stable_url(u, u));
        assert!(stable_url("https://example.com/dl?token=x", "https://example.com/dl?token=x"));
        assert!(stable_url(u, "https://cdn.example.com/files/m.pdf?v=2"));
        assert!(!stable_url(u, "https://s3.example.com/m.pdf?X-Amz-Signature=ab&X-Amz-Expires=60"));
        assert!(!stable_url(u, "https://cdn.example.com/m.pdf?Expires=1&Signature=x&Key-Pair-Id=k"));
        assert!(!stable_url(u, "https://example.com/get?token=abc"));
    }

    fn prev(etag: Option<&str>, lm: Option<&str>) -> Previous {
        Previous {
            final_url: "https://example.com/m.pdf".into(),
            sha256: "aa".into(),
            size: 10,
            validators: Validators { etag: etag.map(Into::into), last_modified: lm.map(Into::into), content_length: Some(10) },
            file_type: FileType::Pdf,
            checks: clean_checks(),
        }
    }

    fn clean_checks() -> Checks {
        Checks { scan: Some(Scan::clean().to_json()), malware: None }
    }

    #[test]
    fn which_validators_are_sent() {
        let lm = "Tue, 01 Jan 2019 00:00:00 GMT";
        let c = conditional_request(&prev(Some("\"v1\""), Some(lm))).unwrap();
        assert_eq!((c.if_none_match.as_deref(), c.if_modified_since.as_deref()), (Some("\"v1\""), None));
        assert_eq!(c.final_url, "https://example.com/m.pdf");
        let c = conditional_request(&prev(None, Some(lm))).unwrap();
        assert_eq!((c.if_none_match.as_deref(), c.if_modified_since.as_deref()), (None, Some(lm)));
        // A weak tag that somehow got recorded is ignored in favor of Last-Modified, or nothing.
        let c = conditional_request(&prev(Some("W/\"v1\""), Some(lm))).unwrap();
        assert_eq!((c.if_none_match.as_deref(), c.if_modified_since.as_deref()), (None, Some(lm)));
        assert_eq!(conditional_request(&prev(Some("W/\"v1\""), None)), None);
        assert_eq!(conditional_request(&prev(None, None)), None);
        assert_eq!(conditional_request(&prev(None, Some("garbage"))), None);
    }

    fn verified(at: &str, conditional: bool, etag: Option<&str>) -> Value {
        let v = Validators { etag: etag.map(Into::into), last_modified: None, content_length: Some(10) };
        verified_body("loc", "https://example.com/m.pdf", Some("aa"), 10, &v, None, conditional, at, Some(FileType::Pdf), &clean_checks())
    }

    #[test]
    fn previous_verdict_rules() {
        let now = ts("2026-10-30T00:00:00Z");
        let full = verified("2026-09-01T00:00:00Z", false, Some("\"v1\""));
        let p = previous_verdict([("verified", &full)], now).unwrap();
        assert_eq!(p, prev(Some("\"v1\""), None));
        // No validators → full fetch.
        let bare = verified("2026-09-01T00:00:00Z", false, None);
        assert_eq!(previous_verdict([("verified", &bare)], now), None);
        // A verdict from before file_type/scan were recorded → full fetch (a 304 would have nothing to repeat).
        for k in ["file_type", "scan"] {
            let mut old = full.clone();
            old.as_object_mut().unwrap().remove(k);
            assert_eq!(previous_verdict([("verified", &old)], now), None, "{k}");
        }
        // om-scan/1 called every Launch action `Launch`: such a verdict is
        // scanned again (full fetch), not repeated. Its other results stand,
        // repeated with their tool tag.
        let mut v1_launch = full.clone();
        v1_launch["scan"] = json!({"tool": "om-scan/1", "active": ["JavaScript", "Launch"]});
        assert_eq!(previous_verdict([("verified", &v1_launch)], now), None);
        assert_eq!(previous_ia_verdict([("verified", &v1_launch)], now).unwrap().checks.scan, None);
        let mut v1_js = full.clone();
        v1_js["scan"] = json!({"tool": "om-scan/1", "active": ["JavaScript"]});
        assert_eq!(previous_verdict([("verified", &v1_js)], now).unwrap().checks.scan, Some(v1_js["scan"].clone()));
        let mut v2_launch = full.clone();
        v2_launch["scan"] = json!({"tool": "om-scan/2", "active": ["Launch", "LaunchDocument"]});
        assert_eq!(previous_verdict([("verified", &v2_launch)], now).unwrap().checks.scan, Some(v2_launch["scan"].clone()));
        let mut zip = full.clone();
        zip["file_type"] = json!("zip");
        assert_eq!(previous_verdict([("verified", &zip)], now), None);
        // Newest verdict is a location_status → full fetch.
        let gone = json!({"location": "loc", "status": "gone", "checked_at": "2026-10-01T00:00:00Z"});
        assert_eq!(previous_verdict([("verified", &full), ("location_status", &gone)], now), None);
        // ...but an older status doesn't matter.
        let old_gone = json!({"location": "loc", "status": "gone", "checked_at": "2026-01-01T00:00:00Z"});
        assert!(previous_verdict([("location_status", &old_gone), ("verified", &full)], now).is_some());
        // Tie between verified and a status: conservative.
        let tie = json!({"location": "loc", "status": "changed", "checked_at": "2026-09-01T00:00:00Z"});
        assert_eq!(previous_verdict([("verified", &full), ("location_status", &tie)], now), None);
    }

    #[test]
    fn full_download_cap() {
        let now = ts("2026-10-30T00:00:00Z");
        let at = |days: i64| (now - jiff::SignedDuration::from_hours(24 * days)).strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
        let full_179 = verified(&at(179), false, Some("\"v1\""));
        let full_181 = verified(&at(181), false, Some("\"v1\""));
        let cond_recent = verified(&at(10), true, Some("\"v1\""));
        let cond_mid = verified(&at(100), true, Some("\"v1\""));
        // Last full check 179 days ago, conditional checks since: still conditional.
        assert!(previous_verdict([("verified", &full_179), ("verified", &cond_mid), ("verified", &cond_recent)], now).is_some());
        // Last full check 181 days ago: the conditional chain no longer counts.
        assert_eq!(previous_verdict([("verified", &full_181), ("verified", &cond_mid), ("verified", &cond_recent)], now), None);
        // Only conditional verdicts (no full one known): full fetch.
        assert_eq!(previous_verdict([("verified", &cond_recent)], now), None);
        // A newer full check resets the clock even if older conditionals exist.
        assert!(previous_verdict([("verified", &full_181), ("verified", &verified(&at(20), false, Some("\"v2\"")))], now).is_some());
        assert_eq!(FULL_RECHECK_DAYS, 180);
    }

    #[test]
    fn day_arithmetic() {
        let now = ts("2026-10-30T00:00:00Z");
        assert_eq!(days_between("2026-10-29T00:00:00Z", now), 1);
        assert_eq!(days_between("2026-09-30T00:00:00Z", now), 30);
        assert_eq!(days_between("2026-10-29T00:00:01Z", now), 0);
        assert_eq!(days_between("nonsense", now), i64::MAX);
    }

    #[test]
    fn verified_body_fields() {
        let v = Validators { etag: Some("\"v1\"".into()), last_modified: Some("Tue, 01 Jan 2019 00:00:00 GMT".into()), content_length: Some(10) };
        let b = verified_body("loc", "https://x.example/m.pdf", Some("aa"), 10, &v, None, true, "2026-10-30T00:00:00Z", Some(FileType::Djvu), &Checks::default());
        assert_eq!(b, json!({"location": "loc", "final_url": "https://x.example/m.pdf", "sha256": "aa", "size": 10, "checked_at": "2026-10-30T00:00:00Z", "etag": "\"v1\"", "last_modified": "Tue, 01 Jan 2019 00:00:00 GMT", "content_length": 10, "method": "conditional", "file_type": "djvu"}));
        let b = verified_body("loc", "u", None, 0, &Validators::default(), None, false, "t", None, &Checks::default());
        assert_eq!(b, json!({"location": "loc", "final_url": "u", "sha256": null, "size": 0, "checked_at": "t"}));
        let checks = Checks { scan: Some(json!({"tool": "om-scan/1", "active": ["JavaScript"]})), malware: Some(json!({"source": "malwarebazaar", "listed": false, "signature": null})) };
        let b = verified_body("loc", "u", Some("aa"), 1, &Validators::default(), None, false, "t", Some(FileType::Pdf), &checks);
        assert_eq!(b, json!({"location": "loc", "final_url": "u", "sha256": "aa", "size": 1, "checked_at": "t", "file_type": "pdf", "scan": {"tool": "om-scan/1", "active": ["JavaScript"]}, "malware": {"source": "malwarebazaar", "listed": false, "signature": null}}));
    }

    // ---- conditional re-checks end to end, against a loopback HTTP server ----
    // Uses the cfg(test)-only seam to allow http + loopback; everything else
    // (redirect handling, conditional headers, 304 handling, hashing) is the
    // production code path.

    mod local {
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        pub const LM0: &str = "Tue, 01 Jan 2019 00:00:00 GMT";
        pub const LM1: &str = "Wed, 01 Jan 2020 00:00:00 GMT";

        #[derive(Debug, Clone)]
        pub struct Req {
            pub path: String,
            pub headers: HashMap<String, String>,
        }

        pub struct Server {
            pub base: String,
            pub log: Arc<Mutex<Vec<Req>>>,
            pub version: Arc<AtomicUsize>,
        }

        impl Server {
            pub fn requests(&self) -> Vec<Req> {
                self.log.lock().unwrap().clone()
            }
            pub fn bodies_sent(&self) -> usize {
                self.requests().iter().filter(|r| r.headers.contains_key("x-sent-body")).count()
            }
        }

        pub fn body(v: usize) -> String {
            format!("%PDF-1.4 manual version {v}")
        }

        /// Bytes served at `/bytes/<name>`.
        pub fn special(name: &str) -> Option<Vec<u8>> {
            Some(match name {
                "zip" => b"PK\x03\x04\x14\x00\x00\x00\x08\x00manual.pdf".to_vec(),
                "exe" => b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff".to_vec(),
                "djvu" => b"AT&TFORM\x00\x00\x01\x00DJVMDIRM\x00\x00\x00\x10".to_vec(),
                "js" => crate::scan::testpdf::classic(&[b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>", crate::scan::testpdf::PAGES, b"<< /S /JavaScript /JS (app.alert\\(1\\)) >>"]),
                "clean" => crate::scan::testpdf::classic(&[crate::scan::testpdf::CATALOG, crate::scan::testpdf::PAGES]),
                _ => return None,
            })
        }

        fn respond(path: &str, h: &HashMap<String, String>, version: usize) -> (String, Vec<(String, String)>, Vec<u8>) {
            let path = path.split('?').next().unwrap_or("");
            if let Some(b) = path.strip_prefix("/bytes/").and_then(special) {
                return ("200 OK".to_string(), vec![("ETag".into(), "\"b\"".into())], b);
            }
            let etag = format!("\"v{version}\"");
            let lm = if version == 0 { LM0 } else { LM1 };
            let ok = |hs: Vec<(String, String)>| ("200 OK".to_string(), hs, body(version).into_bytes());
            let not_modified = |hs: Vec<(String, String)>| ("304 Not Modified".to_string(), hs, Vec::new());
            let redirect = |to: &str| ("302 Found".to_string(), vec![("Location".into(), to.to_string())], Vec::new());
            match path {
                "/file" => {
                    let hs = vec![("ETag".into(), etag.clone()), ("Last-Modified".into(), lm.into())];
                    match (h.get("if-none-match"), h.get("if-modified-since")) {
                        (Some(inm), _) if *inm == etag => not_modified(vec![("ETag".into(), etag)]),
                        (None, Some(ims)) if ims == lm => not_modified(vec![]),
                        _ => ok(hs),
                    }
                }
                "/lm" => match h.get("if-modified-since") {
                    Some(ims) if ims == lm => not_modified(vec![]),
                    _ => ok(vec![("Last-Modified".into(), lm.into())]),
                },
                "/weak" => {
                    let weak = format!("W/{etag}");
                    match (h.get("if-none-match"), h.get("if-modified-since")) {
                        (Some(inm), _) if *inm == weak => not_modified(vec![]),
                        (None, Some(ims)) if ims == lm => not_modified(vec![]),
                        _ => ok(vec![("ETag".into(), weak), ("Last-Modified".into(), lm.into())]),
                    }
                }
                "/nocond" => ok(vec![("ETag".into(), etag)]),
                "/bogus304" => not_modified(vec![]),
                "/old" => redirect("/file"),
                "/moved" => redirect("/lm"),
                "/signed" => redirect("/file?X-Amz-Signature=abc&X-Amz-Expires=60"),
                _ => ("404 Not Found".to_string(), vec![], Vec::new()),
            }
        }

        pub async fn start() -> Server {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let log: Arc<Mutex<Vec<Req>>> = Arc::default();
            let version: Arc<AtomicUsize> = Arc::default();
            let (l2, v2) = (log.clone(), version.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else { return };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&buf).to_string();
                    let mut lines = text.split("\r\n");
                    let path = lines.next().and_then(|l| l.split(' ').nth(1)).unwrap_or("").to_string();
                    let mut headers = HashMap::new();
                    for l in lines.take_while(|l| !l.is_empty()) {
                        if let Some((k, v)) = l.split_once(':') {
                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                        }
                    }
                    let (status, hs, body) = respond(&path, &headers, v2.load(Ordering::SeqCst));
                    if !body.is_empty() {
                        headers.insert("x-sent-body".into(), "1".into());
                    }
                    l2.lock().unwrap().push(Req { path, headers });
                    let mut out = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
                    for (k, v) in hs {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    if !status.starts_with("304") {
                        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
                    }
                    out.push_str("\r\n");
                    let mut out = out.into_bytes();
                    out.extend_from_slice(&body);
                    let _ = sock.write_all(&out).await;
                    let _ = sock.shutdown().await;
                }
            });
            Server { base, log, version }
        }
    }

    fn sha256_of(s: &str) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(s.as_bytes()))
    }

    fn file_v(v: usize) -> FileFacts {
        FileFacts { sha256: Some(sha256_of(&local::body(v))), sha1: None, md5: None }
    }

    fn enable_local() {
        test_seam::ALLOW_LOCAL.with(|c| c.set(true));
    }

    /// Scan copies go to one directory under the system temp dir (each is
    /// deleted right after its scan; the names are unique).
    fn ex() -> Examine {
        Examine { tmp_dir: std::env::temp_dir().join("om-verify-tests"), malwarebazaar_key: None }
    }

    /// The Previous a full verification would leave behind, via the real fact body.
    fn prev_from(v: &Verdict) -> Option<Previous> {
        let Verdict::Verified { final_url, sha256, size, validators, ia, conditional, file_type, checks } = v else { panic!("not verified: {v:?}") };
        let body = verified_body("loc", final_url, sha256.as_deref(), *size, validators, ia.as_ref(), *conditional, &State::now(), Some(*file_type), checks);
        previous_verdict([("verified", &body)], jiff::Timestamp::now())
    }

    #[tokio::test]
    async fn seam_is_off_by_default() {
        let srv = local::start().await;
        let err = fetch_and_hash(&format!("{}/file", srv.base)).await.err().unwrap().to_string();
        assert!(err.contains("registrable domain") || err.contains("only https"), "{err}");
        assert!(srv.requests().is_empty());
    }

    #[tokio::test]
    async fn small_fetches_are_capped_and_guarded() {
        let srv = local::start().await;
        let url = format!("{}/file", srv.base);
        assert!(fetch_small(&url, 1 << 20).await.is_err(), "http and loopback are refused outside tests");
        enable_local();
        let body = local::body(0);
        assert_eq!(fetch_small(&url, 1 << 20).await.unwrap(), body.as_bytes());
        let err = fetch_small(&url, 10).await.err().unwrap().to_string();
        assert!(err.contains("larger than 10 bytes"), "{err}");
    }

    #[tokio::test]
    async fn etag_304_skips_download() {
        enable_local();
        let srv = local::start().await;
        let url = format!("{}/file", srv.base);
        let first = check_generic(&url, &file_v(0), None, &ex()).await;
        let Verdict::Verified { validators, conditional: false, size, .. } = &first else { panic!("{first:?}") };
        assert_eq!(validators, &Validators { etag: Some("\"v0\"".into()), last_modified: Some(local::LM0.into()), content_length: Some(*size) });
        assert!(!srv.requests()[0].headers.contains_key("if-none-match"));
        let p = prev_from(&first).unwrap();
        let second = check_generic(&url, &file_v(0), Some(&p), &ex()).await;
        assert_eq!(second, Verdict::Verified { final_url: url.clone(), sha256: Some(p.sha256.clone()), size: p.size, validators: p.validators.clone(), ia: None, conditional: true, file_type: FileType::Pdf, checks: p.checks.clone() });
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[1].headers.get("if-none-match").map(String::as_str), Some("\"v0\""));
        assert!(!reqs[1].headers.contains_key("if-modified-since"));
        assert_eq!(srv.bodies_sent(), 1);
    }

    #[tokio::test]
    async fn changed_file_falls_back_to_full_fetch() {
        enable_local();
        let srv = local::start().await;
        let url = format!("{}/file", srv.base);
        let p = prev_from(&check_generic(&url, &file_v(0), None, &ex()).await).unwrap();
        srv.version.store(1, std::sync::atomic::Ordering::SeqCst);
        let v = check_generic(&url, &file_v(0), Some(&p), &ex()).await;
        assert!(matches!(v, Verdict::Changed { ref detail, .. } if detail == "checksum differs"), "{v:?}");
        assert_eq!(srv.bodies_sent(), 2);
    }

    #[tokio::test]
    async fn server_ignoring_conditionals_gets_full_fetch() {
        enable_local();
        let srv = local::start().await;
        let url = format!("{}/nocond", srv.base);
        let p = prev_from(&check_generic(&url, &file_v(0), None, &ex()).await).unwrap();
        let v = check_generic(&url, &file_v(0), Some(&p), &ex()).await;
        assert!(matches!(v, Verdict::Verified { conditional: false, .. }), "{v:?}");
        assert_eq!(srv.requests()[1].headers.get("if-none-match").map(String::as_str), Some("\"v0\""));
        assert_eq!(srv.bodies_sent(), 2);
    }

    #[tokio::test]
    async fn last_modified_only_and_weak_etag() {
        enable_local();
        let srv = local::start().await;
        for path in ["/lm", "/weak"] {
            let url = format!("{}{path}", srv.base);
            let first = check_generic(&url, &file_v(0), None, &ex()).await;
            let Verdict::Verified { validators, .. } = &first else { panic!("{first:?}") };
            assert_eq!(validators.etag, None, "{path}: weak etag must not be recorded");
            assert_eq!(validators.last_modified.as_deref(), Some(local::LM0));
            let p = prev_from(&first).unwrap();
            let v = check_generic(&url, &file_v(0), Some(&p), &ex()).await;
            assert!(matches!(v, Verdict::Verified { conditional: true, .. }), "{path}: {v:?}");
            let last = srv.requests().pop().unwrap();
            assert_eq!(last.headers.get("if-modified-since").map(String::as_str), Some(local::LM0));
            assert!(!last.headers.contains_key("if-none-match"), "{path}");
        }
    }

    #[tokio::test]
    async fn conditional_only_at_recorded_final_url() {
        enable_local();
        let srv = local::start().await;
        // Submitted URL redirects; validators belong to the final URL.
        let url = format!("{}/old", srv.base);
        let first = check_generic(&url, &file_v(0), None, &ex()).await;
        let Verdict::Verified { final_url, .. } = &first else { panic!("{first:?}") };
        assert_eq!(final_url, &format!("{}/file", srv.base));
        let p = prev_from(&first).unwrap();
        let v = check_generic(&url, &file_v(0), Some(&p), &ex()).await;
        assert!(matches!(&v, Verdict::Verified { conditional: true, final_url: f, .. } if f == final_url), "{v:?}");
        let reqs = srv.requests();
        assert_eq!(reqs[2].path, "/old");
        assert!(!reqs[2].headers.contains_key("if-none-match"), "redirect hop gets no validators");
        assert_eq!(reqs[3].headers.get("if-none-match").map(String::as_str), Some("\"v0\""));
        // If the submitted URL now leads elsewhere, the validators aren't sent there: full fetch.
        let moved = format!("{}/moved", srv.base);
        let v = check_generic(&moved, &file_v(0), Some(&p), &ex()).await;
        assert!(matches!(&v, Verdict::Verified { conditional: false, .. }), "{v:?}");
        let last = srv.requests().pop().unwrap();
        assert_eq!(last.path, "/lm");
        assert!(!last.headers.contains_key("if-none-match") && !last.headers.contains_key("if-modified-since"));
    }

    #[tokio::test]
    async fn signed_redirect_target_records_no_validators() {
        enable_local();
        let srv = local::start().await;
        let v = check_generic(&format!("{}/signed", srv.base), &file_v(0), None, &ex()).await;
        let Verdict::Verified { validators, .. } = &v else { panic!("{v:?}") };
        assert_eq!(validators, &Validators::default());
        assert_eq!(prev_from(&v), None);
    }

    #[tokio::test]
    async fn unsolicited_304_is_not_a_verdict() {
        enable_local();
        let srv = local::start().await;
        let v = check_generic(&format!("{}/bogus304", srv.base), &file_v(0), None, &ex()).await;
        assert!(matches!(&v, Verdict::Unknown(why) if why.contains("unexpected 304")), "{v:?}");
    }

    // ---- archive.org batch re-checks: parsing and decision logic ----
    // Fixtures are real responses captured 2026-10-30 for the same item:
    // ia_scrape_batch.json (scrape API, 4 identifiers asked, one nonexistent)
    // and ia_metadata_item.json (metadata API for the elektrotanya item).

    const SCRAPE_FIXTURE: &str = include_str!("../tests/fixtures/ia_scrape_batch.json");
    const META_FIXTURE: &str = include_str!("../tests/fixtures/ia_metadata_item.json");
    const FIXTURE_ID: &str = "elektrotanya-11ak30-1_basicline_bl2100ntd_hex-aca5fe8c";

    fn secs(s: &str) -> i64 {
        ts(s).as_second()
    }

    #[test]
    fn parse_real_scrape_response() {
        let rows = parse_scrape(&serde_json::from_str(SCRAPE_FIXTURE).unwrap()).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(!rows.contains_key("openmanuals-nonexistent-probe-identifier-0001"), "unknown ids are simply absent");
        assert_eq!(rows[FIXTURE_ID], IaRow { updated: Some(secs("2026-10-06T22:36:58Z")), item_size: Some(26648), files_count: Some(5) });
        // Revised item: newest of indexdate and the oai_updatedate list.
        assert_eq!(rows["1902GreggShorthandManual-4thVersion"], IaRow { updated: Some(secs("2026-01-01T19:47:18Z")), item_size: Some(63064411), files_count: Some(18) });
    }

    #[test]
    fn parse_scrape_variants_and_errors() {
        // oai_updatedate as a single string, numbers as strings, newest date wins.
        let v = json!({"items": [{"identifier": "a", "indexdate": "2026-01-01T00:00:00Z", "oai_updatedate": "2026-02-01T00:00:00Z", "item_size": "10", "files_count": 3}, {"identifier": "b"}, {"no_identifier": 1}], "count": 2});
        let rows = parse_scrape(&v).unwrap();
        assert_eq!(rows["a"], IaRow { updated: Some(secs("2026-02-01T00:00:00Z")), item_size: Some(10), files_count: Some(3) });
        assert_eq!(rows["b"], IaRow::default());
        assert_eq!(rows.len(), 2);
        assert!(parse_scrape(&json!({"items": [], "count": 0, "total": 0})).unwrap().is_empty());
        // What archive.org sends for a malformed / over-long query.
        assert!(parse_scrape(&json!({"items": [], "count": 0, "total": null, "request_error": "(no hits returned)"})).is_err());
        assert!(parse_scrape(&json!({"error": "invalid value for request parameter q.", "errorType": "InvalidArgumentException"})).is_err());
        assert!(parse_scrape(&json!({"count": 0})).is_err());
    }

    #[test]
    fn metadata_validators_match_scrape_row() {
        let meta: Value = serde_json::from_str(META_FIXTURE).unwrap();
        let ia = ia_validators_from_metadata(&meta).unwrap();
        assert_eq!(ia, IaValidators { updated: "2026-10-06T22:36:58Z".into(), item_size: 26648, files_count: 5 });
        // The full check on the real metadata records them...
        let file = FileFacts { sha256: None, sha1: Some("7a8b7a749de285d115885e36d115b75ebf6ce632".into()), md5: None };
        let v = archive_match(FIXTURE_ID, Some("11ak30-1_basicline_bl2100ntd.hex"), &file, &meta);
        assert!(matches!(&v, Ok(IaFile { size: 2893, ia: Some(i), .. }) if *i == ia), "{v:?}");
        // ...and the real scrape row for the same, unchanged item confirms it.
        let rows = parse_scrape(&serde_json::from_str(SCRAPE_FIXTURE).unwrap()).unwrap();
        let prev = IaPrevious { final_url: "u".into(), sha256: None, size: 2893, ia: Some(ia), full_checked_at: "2026-10-29T00:00:00Z".into(), file_type: None, checks: Checks::default() };
        assert_eq!(ia_batch_decision(&prev, rows.get(FIXTURE_ID)), IaDecision::Unchanged);
        // Missing fields → no validators.
        assert_eq!(ia_validators_from_metadata(&json!({"item_size": 1, "files_count": 1})), None);
        assert_eq!(ia_validators_from_metadata(&json!({"item_last_updated": "1791326218", "item_size": "1", "files_count": 2})).unwrap().files_count, 2);
    }

    #[test]
    fn batch_query_and_splitting() {
        assert_eq!(ia_batch_query(&["a", "b-c"]), "identifier:(\"a\" OR \"b-c\")");
        assert!(is_plain_ia_identifier("manualsbase-id-136209") && is_plain_ia_identifier("A.b_c-1"));
        for bad in ["", "a b", "a\"", "a)", "a:b", "a*", &"x".repeat(101)] {
            assert!(!is_plain_ia_identifier(bad), "{bad}");
        }
        // Dedup, non-plain ids dropped.
        assert_eq!(ia_batches(["a", "b", "a", "bad id", "c"]), vec![vec!["a", "b", "c"]]);
        // Id cap.
        let many: Vec<String> = (0..IA_BATCH_MAX_IDS * 2 + 1).map(|i| format!("i{i}")).collect();
        let b = ia_batches(many.iter().map(String::as_str));
        assert_eq!(b.iter().map(Vec::len).collect::<Vec<_>>(), vec![IA_BATCH_MAX_IDS, IA_BATCH_MAX_IDS, 1]);
        // Query-length cap, with the longest identifiers archive.org allows.
        let long: Vec<String> = (0..IA_BATCH_MAX_IDS).map(|i| format!("{i:03}{}", "x".repeat(97))).collect();
        let b = ia_batches(long.iter().map(String::as_str));
        assert!(b.len() > 1);
        assert_eq!(b.iter().map(Vec::len).sum::<usize>(), IA_BATCH_MAX_IDS);
        for batch in &b {
            assert!(ia_batch_query(batch).len() <= IA_BATCH_MAX_QUERY, "{}", ia_batch_query(batch).len());
        }
        // Filled as far as the cap allows.
        assert!(ia_batch_query(&b[0]).len() + 106 > IA_BATCH_MAX_QUERY);
        assert!(ia_batches(std::iter::empty()).is_empty());
    }

    fn ia_prev(ia: Option<IaValidators>, full_checked_at: &str) -> IaPrevious {
        IaPrevious { final_url: "https://archive.org/download/x/m.pdf".into(), sha256: None, size: 12, ia, full_checked_at: full_checked_at.into(), file_type: Some(FileType::Pdf), checks: Checks::default() }
    }

    fn iav(updated: &str, item_size: u64, files_count: u64) -> IaValidators {
        IaValidators { updated: updated.into(), item_size, files_count }
    }

    fn row(updated: &str, item_size: u64, files_count: u64) -> IaRow {
        IaRow { updated: Some(secs(updated)), item_size: Some(item_size), files_count: Some(files_count) }
    }

    #[test]
    fn batch_decisions() {
        use IaDecision::*;
        let p = ia_prev(Some(iav("2026-10-06T22:36:58Z", 100, 5)), "2026-10-07T00:00:00Z");
        assert_eq!(ia_batch_decision(&p, Some(&row("2026-10-06T22:36:58Z", 100, 5))), Unchanged);
        // The index may date the change a second before item_last_updated.
        assert_eq!(ia_batch_decision(&p, Some(&row("2026-10-06T22:36:57Z", 100, 5))), Unchanged);
        assert!(matches!(ia_batch_decision(&p, Some(&row("2026-10-06T22:36:59Z", 100, 5))), Recheck(_)));
        assert!(matches!(ia_batch_decision(&p, Some(&row("2026-10-06T22:36:58Z", 101, 5))), Recheck(_)));
        assert!(matches!(ia_batch_decision(&p, Some(&row("2026-10-06T22:36:58Z", 100, 6))), Recheck(_)));
        assert!(matches!(ia_batch_decision(&p, Some(&IaRow { updated: None, item_size: Some(100), files_count: Some(5) })), Recheck(_)));
        assert!(matches!(ia_batch_decision(&p, Some(&IaRow { updated: Some(secs("2026-10-06T22:36:58Z")), item_size: None, files_count: Some(5) })), Recheck(_)));
        // Absent from search: never a dark/gone verdict here, just a full check.
        assert_eq!(ia_batch_decision(&p, None), Recheck("not in search results"));
        // Legacy verdict without item validators: compare with the last full check, with a margin.
        let legacy = ia_prev(None, "2026-10-07T00:00:00Z");
        assert_eq!(ia_batch_decision(&legacy, Some(&row("2026-10-06T23:59:00Z", 1, 1))), Unchanged);
        assert!(matches!(ia_batch_decision(&legacy, Some(&row("2026-10-06T23:59:30Z", 1, 1))), Recheck(_)));
        assert!(matches!(ia_batch_decision(&legacy, Some(&row("2026-10-08T00:00:00Z", 1, 1))), Recheck(_)));
        assert!(matches!(ia_batch_decision(&ia_prev(None, "garbage"), Some(&row("2020-01-01T00:00:00Z", 1, 1))), Recheck(_)));
        // The conditional verdict carries everything over.
        assert_eq!(ia_conditional_verdict(&p, FileType::Pdf), Verdict::Verified { final_url: p.final_url.clone(), sha256: None, size: 12, validators: Validators::default(), ia: p.ia.clone(), conditional: true, file_type: FileType::Pdf, checks: Checks::default() });
    }

    fn ia_verified(at: &str, conditional: bool, ia: Option<&IaValidators>) -> Value {
        verified_body("loc", "https://archive.org/download/x/m.pdf", None, 12, &Validators::default(), ia, conditional, at, None, &Checks::default())
    }

    #[test]
    fn previous_ia_verdict_rules() {
        let now = ts("2026-10-30T00:00:00Z");
        let at = |days: i64| (now - jiff::SignedDuration::from_hours(24 * days)).strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
        let v = iav("2026-01-01T00:00:00Z", 100, 5);
        let full = ia_verified(&at(40), false, Some(&v));
        assert_eq!(full["ia_updated"], "2026-01-01T00:00:00Z");
        assert_eq!((full["ia_item_size"].as_u64(), full["ia_files_count"].as_u64()), (Some(100), Some(5)));
        // sha256 null and no HTTP validators: still usable for archive.org (not for previous_verdict).
        let p = previous_ia_verdict([("verified", &full)], now).unwrap();
        assert_eq!(p, IaPrevious { final_url: "https://archive.org/download/x/m.pdf".into(), sha256: None, size: 12, ia: Some(v.clone()), full_checked_at: at(40), file_type: None, checks: Checks::default() });
        assert_eq!(previous_verdict([("verified", &full)], now), None);
        // Legacy verdict (migrated, no ia_*): usable, compared by checked_at.
        let legacy = json!({"location": "loc", "final_url": "u", "sha256": null, "size": 12, "checked_at": at(40), "note": "salli-cat verify_ia_uploads"});
        assert_eq!(previous_ia_verdict([("verified", &legacy)], now).unwrap().ia, None);
        // Conditional chain: newest body's validators, newest *full* check's time.
        let cond = ia_verified(&at(10), true, Some(&v));
        let p = previous_ia_verdict([("verified", &full), ("verified", &cond)], now).unwrap();
        assert_eq!((p.ia, p.full_checked_at), (Some(v.clone()), at(40)));
        // Too old a full check, or a newer status, or a size-less body: no.
        let old_full = ia_verified(&at(181), false, Some(&v));
        assert_eq!(previous_ia_verdict([("verified", &old_full), ("verified", &cond)], now), None);
        let dark = json!({"location": "loc", "status": "dark", "checked_at": at(5)});
        assert_eq!(previous_ia_verdict([("verified", &full), ("location_status", &dark)], now), None);
        assert_eq!(previous_ia_verdict([("verified", &json!({"final_url": "u", "checked_at": at(1)}))], now), None);
        // Malformed item validators are dropped as a whole.
        let mut bad = full.clone();
        bad["ia_updated"] = json!("yesterday");
        assert_eq!(previous_ia_verdict([("verified", &bad)], now).unwrap().ia, None);
    }

    // ---- archive.org batch re-checks end to end: run_once against a mock archive.org ----
    // The cfg(test)-only seam points archive.org calls at a loopback server and
    // drops the per-host pause; candidate selection, the batch phase, the
    // per-item fallback and fact recording are the production code path.

    mod ia_mock {
        use serde_json::{json, Value};
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Default)]
        pub struct Data {
            /// Scrape rows by identifier.
            pub rows: HashMap<String, Value>,
            /// Metadata API answers by identifier (absent: `{}`).
            pub meta: HashMap<String, Value>,
            /// Overrides the scrape answer: (status line, body).
            pub scrape_override: Option<(String, String)>,
            /// Bytes served under `/download/<identifier>/<name>` (absent: a small PDF).
            pub files: HashMap<String, Vec<u8>>,
            /// Paths requested, in order.
            pub log: Vec<String>,
            /// Range header of each `/download/` request, in order: (path, range).
            pub downloads: Vec<(String, Option<String>)>,
            /// MalwareBazaar mock: answer by sha256 (absent: hash_not_found);
            /// `mb_fail` answers HTTP 500. Requests' form bodies and Auth-Key.
            pub mb: HashMap<String, Value>,
            pub mb_fail: bool,
            pub mb_requests: Vec<(String, Option<String>)>,
        }

        pub struct Mock {
            pub base: String,
            pub data: Arc<Mutex<Data>>,
        }

        impl Mock {
            pub fn log(&self) -> Vec<String> {
                self.data.lock().unwrap().log.clone()
            }
            pub fn scrapes(&self) -> Vec<Vec<String>> {
                self.log().iter().filter(|p| p.starts_with(super::IA_SCRAPE_PATH)).map(|p| query_ids(p)).collect()
            }
            pub fn downloads(&self) -> Vec<(String, Option<String>)> {
                self.data.lock().unwrap().downloads.clone()
            }
            pub fn metadata_calls(&self) -> Vec<String> {
                let mut v: Vec<String> = self.log().iter().filter_map(|p| p.strip_prefix("/metadata/").map(str::to_string)).collect();
                v.sort();
                v
            }
        }

        /// The identifiers in a scrape request's `q`, checking it has the expected shape.
        pub fn query_ids(path: &str) -> Vec<String> {
            let u = reqwest::Url::parse(&format!("http://x{path}")).unwrap();
            let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
            assert_eq!(q["fields"], super::IA_SCRAPE_FIELDS);
            let inner = q["q"].strip_prefix("identifier:(").and_then(|s| s.strip_suffix(')')).expect("identifier query");
            inner.split(" OR ").map(|t| t.trim_matches('"').to_string()).collect()
        }

        pub const DEFAULT_FILE: &[u8] = b"%PDF-1.4\n% default mock file\n";

        fn respond(path: &str, headers: &HashMap<String, String>, body: &str, d: &mut Data) -> (String, Vec<u8>) {
            if path.starts_with(super::IA_SCRAPE_PATH) {
                if let Some(o) = &d.scrape_override {
                    return (o.0.clone(), o.1.clone().into_bytes());
                }
                let items: Vec<Value> = query_ids(path).iter().filter_map(|id| d.rows.get(id).cloned()).collect();
                let n = items.len();
                return ("200 OK".into(), json!({"items": items, "count": n, "total": n}).to_string().into_bytes());
            }
            if let Some(id) = path.strip_prefix("/metadata/") {
                return ("200 OK".into(), d.meta.get(id).cloned().unwrap_or(json!({})).to_string().into_bytes());
            }
            if path.starts_with("/download/") {
                let range = headers.get("range").cloned();
                d.downloads.push((path.to_string(), range.clone()));
                // Like archive.org: the download URL redirects to a data node.
                if !path.starts_with("/download/node/") {
                    return ("302 Found".into(), format!("/download/node/{}", &path["/download/".len()..]).into_bytes());
                }
                let key = format!("/download/{}", &path["/download/node/".len()..]);
                let bytes = d.files.get(&key).cloned().unwrap_or_else(|| DEFAULT_FILE.to_vec());
                return match range.as_deref().and_then(|r| r.strip_prefix("bytes=0-")).and_then(|e| e.parse::<usize>().ok()) {
                    Some(end) => ("206 Partial Content".into(), bytes[..bytes.len().min(end + 1)].to_vec()),
                    None => ("200 OK".into(), bytes),
                };
            }
            if path == "/mb/" {
                d.mb_requests.push((body.to_string(), headers.get("auth-key").cloned()));
                if d.mb_fail {
                    return ("500 Internal Server Error".into(), b"oops".to_vec());
                }
                let form: HashMap<String, String> = reqwest::Url::parse(&format!("http://x/?{body}")).unwrap().query_pairs().into_owned().collect();
                let answer = d.mb.get(form.get("hash").map(String::as_str).unwrap_or("")).cloned().unwrap_or(json!({"query_status": "hash_not_found"}));
                return ("200 OK".into(), answer.to_string().into_bytes());
            }
            ("404 Not Found".into(), Vec::new())
        }

        pub async fn start() -> Mock {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let data: Arc<Mutex<Data>> = Arc::default();
            let d2 = data.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else { return };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").map_or(buf.len(), |p| p + 4);
                    let text = String::from_utf8_lossy(&buf[..split]).to_string();
                    let mut lines = text.split("\r\n");
                    let path = lines.next().and_then(|l| l.split(' ').nth(1)).unwrap_or("").to_string();
                    let mut headers = HashMap::new();
                    for l in lines.take_while(|l| !l.is_empty()) {
                        if let Some((k, v)) = l.split_once(':') {
                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                        }
                    }
                    // A POST body (the MalwareBazaar mock), by Content-Length.
                    let want: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                    let mut body = buf[split..].to_vec();
                    while body.len() < want {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => body.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let (status, out_body) = {
                        let mut d = d2.lock().unwrap();
                        d.log.push(path.clone());
                        respond(&path, &headers, &String::from_utf8_lossy(&body), &mut d)
                    };
                    let mut out = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
                    if status.starts_with("302") {
                        out.push_str(&format!("Location: {}\r\n", String::from_utf8_lossy(&out_body)));
                    }
                    out.push_str(&format!("Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", out_body.len()));
                    let mut out = out.into_bytes();
                    if !status.starts_with("302") {
                        out.extend_from_slice(&out_body);
                    }
                    let _ = sock.write_all(&out).await;
                    let _ = sock.shutdown().await;
                }
            });
            Mock { base, data }
        }
    }

    const SHA1_OK: &str = "1111111111111111111111111111111111111111";
    const SHA1_OTHER: &str = "2222222222222222222222222222222222222222";

    fn meta_for(updated: i64, sha1: &str, files_count: u64) -> Value {
        json!({"item_last_updated": updated, "item_size": 1000, "files_count": files_count, "files": [{"name": "m.pdf", "sha1": sha1, "size": "12"}], "metadata": {}})
    }

    fn row_for(id: &str, updated: i64, files_count: u64) -> Value {
        let d = jiff::Timestamp::from_second(updated).unwrap().to_string();
        json!({"identifier": id, "indexdate": d, "oai_updatedate": ["2020-01-01T00:00:00Z", d], "item_size": 1000, "files_count": files_count})
    }

    struct World {
        _dir: tempfile::TempDir,
        state: Shared,
        mock: ia_mock::Mock,
        locs: HashMap<&'static str, String>,
        now: jiff::Timestamp,
        trusted_default_file: bool,
    }

    impl World {
        async fn new() -> World {
            World::with_malwarebazaar_key(None).await
        }

        async fn with_malwarebazaar_key(mb_key: Option<&str>) -> World {
            test_seam::NO_PAUSE.with(|c| c.set(true));
            // Downloads from the mock go through `open`, which needs the loopback seam.
            enable_local();
            let mock = ia_mock::start().await;
            test_seam::IA_BASE.with(|c| *c.borrow_mut() = Some(mock.base.clone()));
            test_seam::MALWAREBAZAAR_API.with(|c| *c.borrow_mut() = Some(format!("{}/mb/", mock.base)));
            let dir = tempfile::tempdir().unwrap();
            let data = dir.path().join("data");
            std::fs::create_dir_all(&data).unwrap();
            let key = openmanuals_core::sign::SigningKey::generate(openmanuals_core::Alg::Ed25519);
            std::fs::write(data.join("server.key"), key.to_openssh("test server").unwrap()).unwrap();
            let paths = crate::Paths {
                data_dir: data,
                ledger_dir: dir.path().join("ledger"),
                key: None,
                trust: None,
                domain: "openmanuals.test".into(),
                public_url: "http://test".into(),
                doip_script: None,
                no_checkpoint: false,
                keep_snapshots: 3,
                keep_diffs_days: 30,
                malwarebazaar_key: mb_key.map(Into::into),
            };
            let state = State::new(paths).unwrap();
            World { _dir: dir, state, mock, locs: HashMap::new(), now: jiff::Timestamp::now(), trusted_default_file: false }
        }

        fn ago(&self, days: i64) -> String {
            (self.now - jiff::SignedDuration::from_hours(24 * days)).strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
        }

        fn ago_secs(&self, days: i64) -> i64 {
            self.now.as_second() - days * 86_400
        }

        fn accept(&self, facts: &[Fact]) {
            let r = self.state.inbox.accept(facts, |_| Ok(())).unwrap();
            assert_eq!(r.accepted.len(), facts.len());
        }

        /// An archive.org location for item `id` (file m.pdf, sha1 SHA1_OK,
        /// introduced by this server's key: trusted).
        fn location(&mut self, id: &'static str) -> String {
            self.location_of(id, &format!("sha1:{SHA1_OK}"), None)
        }

        /// An archive.org location for item `id` holding file `file_ref`; with
        /// `file_body`, a `file` fact for it is recorded first, signed by
        /// `author` (None: this server's key).
        fn location_of(&mut self, id: &'static str, file_ref: &str, file: Option<(Value, Option<&openmanuals_core::sign::SigningKey>)>) -> String {
            match file {
                Some((body, Some(k))) => {
                    let mut f = Fact::new("file", &k.public_key().fingerprint(), &State::now(), body);
                    k.sign_fact(&mut f).unwrap();
                    self.accept(&[f]);
                }
                Some((body, None)) => self.accept(&[self.state.server_fact("file", body).unwrap()]),
                None if file_ref == format!("sha1:{SHA1_OK}") && !self.trusted_default_file => {
                    self.accept(&[self.state.server_fact("file", json!({"sha1": SHA1_OK, "size": 12, "mime": "application/pdf"})).unwrap()]);
                    self.trusted_default_file = true;
                }
                None => {}
            }
            let f = self.state.server_fact("location", json!({"file": file_ref, "url": format!("https://archive.org/download/{id}/m.pdf"), "kind": "archive", "ia": {"identifier": id, "filename": "m.pdf"}})).unwrap();
            let loc = f.id().unwrap();
            self.accept(&[f]);
            self.locs.insert(id, loc.clone());
            loc
        }

        /// A server `verified` verdict on item `id`'s location (no file_type
        /// or scan: as recorded before they existed).
        fn verdict(&self, id: &str, checked_at: &str, ia: Option<&IaValidators>, conditional: bool) {
            self.verdict_with(id, checked_at, ia, conditional, None, &Checks::default());
        }

        fn verdict_with(&self, id: &str, checked_at: &str, ia: Option<&IaValidators>, conditional: bool, file_type: Option<FileType>, checks: &Checks) {
            let body = verified_body(&self.locs[id], &format!("https://archive.org/download/{id}/m.pdf"), None, 12, &Validators::default(), ia, conditional, checked_at, file_type, checks);
            self.accept(&[self.state.server_fact("verified", body).unwrap()]);
        }

        /// This server's verdicts on item `id` checked at or after `since`: (type, body).
        fn new_verdicts(&self, id: &str, since: &str) -> Vec<(String, Value)> {
            let mut out = Vec::new();
            for t in ["verified", "location_status"] {
                for e in self.state.inbox.by_author_and_type(&self.state.fingerprint, t).unwrap() {
                    let b = e.fact.body;
                    if b["location"] == self.locs[id].as_str() && b["checked_at"].as_str().unwrap() >= since {
                        out.push((t.to_string(), b));
                    }
                }
            }
            out
        }
    }

    fn ia_at(secs: i64, files_count: u64) -> IaValidators {
        IaValidators { updated: jiff::Timestamp::from_second(secs).unwrap().to_string(), item_size: 1000, files_count }
    }

    #[tokio::test]
    async fn ia_batch_recheck_end_to_end() {
        let mut w = World::new().await;
        let t_old = w.ago_secs(100);
        let t_new = w.ago_secs(1);
        let aged = w.ago(40);
        {
            // Mock archive.org state.
            let mut d = w.mock.data.lock().unwrap();
            // a: never verified → metadata only.
            d.meta.insert("item-a".into(), meta_for(t_old, SHA1_OK, 5));
            d.rows.insert("item-a".into(), row_for("item-a", t_old, 5));
            // b: unchanged since its recorded validators → conditional, no metadata call.
            d.rows.insert("item-b".into(), row_for("item-b", t_old - 1, 5));
            // c: touched since (date moved, same file) → full check, verified again.
            d.rows.insert("item-c".into(), row_for("item-c", t_new, 5));
            d.meta.insert("item-c".into(), meta_for(t_new, SHA1_OK, 5));
            // d: gone dark: absent from search → metadata says dark.
            d.meta.insert("item-d".into(), json!({"is_dark": true}));
            // e: legacy verdict without ia_*; last change long before our check → conditional.
            d.rows.insert("item-e".into(), row_for("item-e", t_old, 5));
            // f: last full check too old → not batched, full check.
            d.rows.insert("item-f".into(), row_for("item-f", t_old, 5));
            d.meta.insert("item-f".into(), meta_for(t_old, SHA1_OK, 5));
            // g: file replaced (count changed, checksum differs) → changed.
            d.rows.insert("item-g".into(), row_for("item-g", t_new, 6));
            d.meta.insert("item-g".into(), meta_for(t_new, SHA1_OTHER, 6));
        }
        for id in ["item-a", "item-b", "item-c", "item-d", "item-e", "item-f", "item-g"] {
            w.location(id);
        }
        let v_old = ia_at(t_old, 5);
        for id in ["item-b", "item-c", "item-d", "item-g"] {
            w.verdict(id, &aged, Some(&v_old), false);
        }
        w.verdict("item-e", &aged, None, false);
        w.verdict("item-f", &w.ago(200), Some(&v_old), false);
        w.verdict("item-f", &aged, Some(&v_old), true);

        let start = State::now();
        let n = run_once(w.state.clone(), 100).await.unwrap();
        assert_eq!(n, 7);

        // One batch request, for exactly the candidates with a usable previous verdict.
        let scrapes = w.mock.scrapes();
        assert_eq!(scrapes.len(), 1, "{:?}", w.mock.log());
        let mut asked = scrapes[0].clone();
        asked.sort();
        assert_eq!(asked, ["item-b", "item-c", "item-d", "item-e", "item-g"]);
        assert_eq!(w.mock.metadata_calls(), ["item-a", "item-c", "item-d", "item-f", "item-g"]);

        let one = |id: &str| {
            let v = w.new_verdicts(id, &start);
            assert_eq!(v.len(), 1, "{id}: {v:?}");
            v.into_iter().next().unwrap()
        };
        // a: full check records the item validators.
        let (t, b) = one("item-a");
        assert_eq!(t, "verified");
        assert_eq!(b.get("method"), None);
        assert_eq!((b["ia_updated"].as_str(), b["ia_item_size"].as_u64(), b["ia_files_count"].as_u64()), (Some(v_old.updated.as_str()), Some(1000), Some(5)));
        assert_eq!((b["final_url"].as_str(), b["size"].as_u64(), &b["sha256"]), (Some("https://archive.org/download/item-a/m.pdf"), Some(12), &Value::Null));
        // b: conditional, repeating the previous verdict and validators.
        let (t, b) = one("item-b");
        assert_eq!((t.as_str(), b["method"].as_str()), ("verified", Some(METHOD_CONDITIONAL)));
        assert_eq!((b["ia_updated"].as_str(), b["size"].as_u64(), b["final_url"].as_str()), (Some(v_old.updated.as_str()), Some(12), Some("https://archive.org/download/item-b/m.pdf")));
        // c: full check, new validators.
        let (t, b) = one("item-c");
        assert_eq!((t.as_str(), b.get("method")), ("verified", None));
        assert_eq!(b["ia_updated"].as_str(), Some(ia_at(t_new, 5).updated.as_str()));
        // d: dark, decided by the metadata API, not by search absence.
        let (t, b) = one("item-d");
        assert_eq!((t.as_str(), b["status"].as_str()), ("location_status", Some("dark")));
        // e: conditional from the legacy verdict; no item validators to repeat.
        let (t, b) = one("item-e");
        assert_eq!((t.as_str(), b["method"].as_str(), b.get("ia_updated")), ("verified", Some(METHOD_CONDITIONAL), None));
        // f: full check.
        let (t, b) = one("item-f");
        assert_eq!((t.as_str(), b.get("method")), ("verified", None));
        // g: changed.
        let (t, b) = one("item-g");
        assert_eq!((t.as_str(), b["status"].as_str()), ("location_status", Some("changed")));

        // Nothing is due any more.
        assert_eq!(run_once(w.state.clone(), 100).await.unwrap(), 0);
        assert_eq!(w.mock.scrapes().len(), 1);
    }

    #[tokio::test]
    async fn ia_batch_errors_fall_back_to_metadata() {
        for (status, body) in [("500 Internal Server Error", "oops"), ("200 OK", r#"{"items":[],"count":0,"total":null,"request_error":"(no hits returned)"}"#), ("400 Bad Request", r#"{"error":"invalid value for request parameter q.","errorType":"InvalidArgumentException"}"#), ("200 OK", "not json")] {
            let mut w = World::new().await;
            let t_old = w.ago_secs(100);
            {
                let mut d = w.mock.data.lock().unwrap();
                d.scrape_override = Some((status.into(), body.into()));
                for id in ["item-b", "item-x"] {
                    d.rows.insert(id.into(), row_for(id, t_old, 5));
                    d.meta.insert(id.into(), meta_for(t_old, SHA1_OK, 5));
                }
            }
            let aged = w.ago(40);
            for id in ["item-b", "item-x"] {
                w.location(id);
                w.verdict(id, &aged, Some(&ia_at(t_old, 5)), false);
            }
            let start = State::now();
            assert_eq!(run_once(w.state.clone(), 100).await.unwrap(), 2, "{status} {body}");
            assert_eq!(w.mock.scrapes().len(), 1);
            assert_eq!(w.mock.metadata_calls(), ["item-b", "item-x"], "{status} {body}");
            for id in ["item-b", "item-x"] {
                let v = w.new_verdicts(id, &start);
                assert_eq!(v.len(), 1);
                assert_eq!((v[0].0.as_str(), v[0].1.get("method")), ("verified", None), "{status} {body}");
            }
        }
    }

    // ---- file types, scans and malware lookups ----

    fn sha256_bytes(b: &[u8]) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(b))
    }

    fn sha1_bytes(b: &[u8]) -> String {
        use sha1::Digest;
        hex::encode(sha1::Sha1::digest(b))
    }

    fn tmp_files(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default()
    }

    #[tokio::test]
    async fn generic_non_documents_never_verify() {
        enable_local();
        let srv = local::start().await;
        for name in ["zip", "exe"] {
            let bytes = local::special(name).unwrap();
            let file = FileFacts { sha256: Some(sha256_bytes(&bytes)), sha1: None, md5: None };
            let v = check_generic(&format!("{}/bytes/{name}", srv.base), &file, None, &ex()).await;
            assert!(matches!(&v, Verdict::Changed { detail, .. } if detail == NOT_A_DOCUMENT), "{name}: {v:?}");
        }
    }

    #[tokio::test]
    async fn generic_copies_are_typed_and_scanned() {
        enable_local();
        let srv = local::start().await;
        let dir = tempfile::tempdir().unwrap();
        let ex = Examine { tmp_dir: dir.path().join("verify-tmp"), malwarebazaar_key: None };
        let check = |name: &'static str| {
            let bytes = local::special(name).unwrap();
            let file = FileFacts { sha256: Some(sha256_bytes(&bytes)), sha1: None, md5: None };
            let (url, ex) = (format!("{}/bytes/{name}", srv.base), ex.clone());
            async move { check_generic(&url, &file, None, &ex).await }
        };
        let Verdict::Verified { file_type, checks, conditional: false, .. } = check("js").await else { panic!() };
        assert_eq!(file_type, FileType::Pdf);
        assert_eq!(checks, Checks { scan: Some(json!({"tool": "om-scan/2", "active": ["JavaScript"]})), malware: None });
        let Verdict::Verified { file_type, checks, .. } = check("clean").await else { panic!() };
        assert_eq!((file_type, checks.scan), (FileType::Pdf, Some(json!({"tool": "om-scan/2", "active": []}))));
        // DjVu has no active content; it isn't parsed (or written to disk).
        let Verdict::Verified { file_type, checks, .. } = check("djvu").await else { panic!() };
        assert_eq!((file_type, checks.scan), (FileType::Djvu, Some(json!({"tool": "om-scan/2", "active": []}))));
        // A "PDF" the parser can't read is risky, not clean.
        let v = check_generic(&format!("{}/file", srv.base), &file_v(0), None, &ex).await;
        let Verdict::Verified { checks, .. } = &v else { panic!("{v:?}") };
        assert_eq!(checks.scan, Some(json!({"tool": "om-scan/2", "active": ["Unparseable"]})));
        // Scan copies are deleted.
        assert_eq!(tmp_files(&ex.tmp_dir), Vec::<PathBuf>::new());
        // A wrong file is not scanned or kept either.
        let v = check_generic(&format!("{}/bytes/js", srv.base), &file_v(0), None, &ex).await;
        assert!(matches!(&v, Verdict::Changed { detail, .. } if detail == "checksum differs"), "{v:?}");
        assert_eq!(tmp_files(&ex.tmp_dir), Vec::<PathBuf>::new());
        // The fact body carries them.
        let body = verified_body("loc", "u", Some("aa"), 1, &Validators::default(), None, false, "t", Some(FileType::Djvu), &Checks { scan: Some(Scan::clean().to_json()), malware: None });
        assert_eq!((body["file_type"].as_str(), &body["scan"]["active"]), (Some("djvu"), &json!([])));
    }

    #[tokio::test]
    async fn ia_exe_upload_never_verifies() {
        // archive.org's listing has the exe's sha1, which is the file fact's sha1:
        // the checksum matches, but the bytes aren't a document.
        let mut w = World::new().await;
        let exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00 not a manual".to_vec();
        let (s1, s256) = (sha1_bytes(&exe), sha256_bytes(&exe));
        let contributor = openmanuals_core::sign::SigningKey::generate(openmanuals_core::Alg::Ed25519);
        {
            let mut d = w.mock.data.lock().unwrap();
            for id in ["item-exe", "item-exe-u"] {
                d.meta.insert(id.into(), json!({"files": [{"name": "m.pdf", "sha1": s1, "size": exe.len().to_string()}], "item_last_updated": 1, "item_size": 10, "files_count": 1}));
                d.files.insert(format!("/download/{id}/m.pdf"), exe.clone());
            }
        }
        // Introduced by a trusted key (typed from a range request) and by a contributor (downloaded in full).
        w.location_of("item-exe", &format!("sha1:{s1}"), Some((json!({"sha1": s1, "size": exe.len()}), None)));
        w.location_of("item-exe-u", &s256, Some((json!({"sha256": s256, "sha1": s1, "size": exe.len()}), Some(&contributor))));
        let start = State::now();
        assert_eq!(run_once(w.state.clone(), 100).await.unwrap(), 2);
        for id in ["item-exe", "item-exe-u"] {
            let v = w.new_verdicts(id, &start);
            assert_eq!(v.len(), 1, "{id}: {v:?}");
            assert_eq!((v[0].0.as_str(), v[0].1["status"].as_str(), v[0].1["detail"].as_str()), ("location_status", Some("changed"), Some(NOT_A_DOCUMENT)), "{id}");
        }
        let downloads = w.mock.downloads();
        assert!(downloads.contains(&("/download/node/item-exe/m.pdf".into(), Some(SNIFF_RANGE.into()))), "{downloads:?}");
        assert!(downloads.contains(&("/download/node/item-exe-u/m.pdf".into(), None)), "{downloads:?}");
    }

    #[tokio::test]
    async fn ia_recheck_sniffs_legacy_verdicts() {
        let mut w = World::new().await;
        let t_old = w.ago_secs(100);
        let exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
        {
            let mut d = w.mock.data.lock().unwrap();
            for id in ["legacy", "typed", "legacy-exe"] {
                d.rows.insert(id.into(), row_for(id, t_old, 5));
            }
            d.files.insert("/download/legacy-exe/m.pdf".into(), exe);
        }
        let v = ia_at(t_old, 5);
        let aged = w.ago(40);
        for id in ["legacy", "typed", "legacy-exe"] {
            w.location(id);
        }
        // Verdicts from before file_type was recorded (all migrated ones), and one with it.
        w.verdict("legacy", &aged, Some(&v), false);
        w.verdict("legacy-exe", &aged, None, false);
        w.verdict_with("typed", &aged, Some(&v), false, Some(FileType::Djvu), &Checks::default());
        // A migrated verdict that recorded the item's URL, not the file's:
        // nothing to sniff, so a full (metadata) check instead of a batched one.
        w.location("item-url");
        w.mock.data.lock().unwrap().meta.insert("item-url".into(), meta_for(t_old, SHA1_OK, 5));
        let body = verified_body(&w.locs["item-url"], "https://archive.org/download/item-url", None, 12, &Validators::default(), None, false, &aged, None, &Checks::default());
        w.accept(&[w.state.server_fact("verified", body).unwrap()]);
        let start = State::now();
        assert_eq!(run_once(w.state.clone(), 100).await.unwrap(), 4);
        // One scrape (for the three with a file URL); no metadata calls for them: all three were unchanged.
        assert_eq!(w.mock.scrapes().len(), 1);
        assert_eq!(w.mock.scrapes()[0].len(), 3);
        assert_eq!(w.mock.metadata_calls(), ["item-url"]);
        let b = &w.new_verdicts("item-url", &start)[0].1;
        assert_eq!((b["final_url"].as_str(), b["file_type"].as_str(), b.get("method")), (Some("https://archive.org/download/item-url/m.pdf"), Some("pdf"), None));
        // Range requests only for the verdicts without a file_type.
        // (The Range header goes on every hop: archive.org's redirect, then the data node.)
        let mut downloads = w.mock.downloads();
        downloads.sort();
        downloads.retain(|(p, _)| !p.contains("item-url"));
        let want: Vec<(String, Option<String>)> = ["/download/legacy-exe/m.pdf", "/download/legacy/m.pdf", "/download/node/legacy-exe/m.pdf", "/download/node/legacy/m.pdf"].iter().map(|p| (p.to_string(), Some(SNIFF_RANGE.to_string()))).collect();
        assert_eq!(downloads, want);
        let one = |id: &str| w.new_verdicts(id, &start).into_iter().next().unwrap();
        let (t, b) = one("legacy");
        assert_eq!((t.as_str(), b["method"].as_str(), b["file_type"].as_str()), ("verified", Some(METHOD_CONDITIONAL), Some("pdf")));
        assert_eq!(b["ia_updated"].as_str(), Some(v.updated.as_str()));
        let (t, b) = one("typed");
        assert_eq!((t.as_str(), b["method"].as_str(), b["file_type"].as_str()), ("verified", Some(METHOD_CONDITIONAL), Some("djvu")));
        let (t, b) = one("legacy-exe");
        assert_eq!((t.as_str(), b["status"].as_str(), b["detail"].as_str()), ("location_status", Some("changed"), Some(NOT_A_DOCUMENT)));
        // The next re-check repeats the recorded type without a request.
        let all = w.new_verdicts("legacy", "");
        assert_eq!(previous_ia_verdict(all.iter().map(|(t, b)| (t.as_str(), b)), jiff::Timestamp::now()).unwrap().file_type, Some(FileType::Pdf));
    }

    #[tokio::test]
    async fn ia_untrusted_files_are_scanned() {
        let mut w = World::with_malwarebazaar_key(Some("test-key")).await;
        let js = local::special("js").unwrap();
        let clean = local::special("clean").unwrap();
        let (js1, js256, clean1, clean256) = (sha1_bytes(&js), sha256_bytes(&js), sha1_bytes(&clean), sha256_bytes(&clean));
        let contributor = openmanuals_core::sign::SigningKey::generate(openmanuals_core::Alg::Ed25519);
        let t_old = w.ago_secs(100);
        {
            let mut d = w.mock.data.lock().unwrap();
            d.meta.insert("item-u".into(), json!({"files": [{"name": "m.pdf", "sha1": js1, "size": js.len().to_string()}], "item_last_updated": t_old, "item_size": 1000, "files_count": 5}));
            d.files.insert("/download/item-u/m.pdf".into(), js.clone());
            d.meta.insert("item-v".into(), json!({"files": [{"name": "m.pdf", "sha1": clean1, "size": clean.len().to_string()}], "item_last_updated": t_old, "item_size": 1000, "files_count": 5}));
            d.rows.insert("item-v".into(), row_for("item-v", t_old, 5));
            d.files.insert("/download/item-v/m.pdf".into(), clean.clone());
            d.meta.insert("item-t".into(), meta_for(t_old, SHA1_OK, 5));
            d.mb.insert(js256.clone(), json!({"query_status": "ok", "data": [{"sha256_hash": js256, "signature": "Pdf.Dropper.Test", "file_type": "pdf"}]}));
        }
        // u: a contributor's new file; v: a contributor's file verified before scans
        // existed (its unchanged item must not be confirmed from the batch); t: trusted.
        w.location_of("item-u", &js256, Some((json!({"sha256": js256, "sha1": js1, "size": js.len()}), Some(&contributor))));
        w.location_of("item-v", &clean256, Some((json!({"sha256": clean256, "sha1": clean1, "size": clean.len()}), Some(&contributor))));
        w.verdict_with("item-v", &w.ago(40), Some(&ia_at(t_old, 5)), false, Some(FileType::Pdf), &Checks::default());
        w.location("item-t");
        let start = State::now();
        assert_eq!(run_once(w.state.clone(), 100).await.unwrap(), 3);
        assert_eq!(w.mock.scrapes().len(), 0, "item-v's verdict has no scan: no batched re-check");
        assert_eq!(w.mock.metadata_calls(), ["item-t", "item-u", "item-v"]);
        let one = |id: &str| {
            let v = w.new_verdicts(id, &start);
            assert_eq!(v.len(), 1, "{id}: {v:?}");
            assert_eq!(v[0].0, "verified", "{id}: {v:?}");
            v[0].1.clone()
        };
        let u = one("item-u");
        assert_eq!(u["file_type"], "pdf");
        assert_eq!(u["scan"], json!({"tool": "om-scan/2", "active": ["JavaScript"]}));
        assert_eq!(u["malware"], json!({"source": "malwarebazaar", "listed": true, "signature": "Pdf.Dropper.Test"}));
        assert_eq!((u["sha256"].as_str(), u["size"].as_u64()), (Some(js256.as_str()), Some(js.len() as u64)));
        assert_eq!(u["final_url"], "https://archive.org/download/item-u/m.pdf");
        let v = one("item-v");
        assert_eq!((&v["scan"], &v["malware"]), (&json!({"tool": "om-scan/2", "active": []}), &json!({"source": "malwarebazaar", "listed": false, "signature": null})));
        let t = one("item-t");
        assert_eq!((t["file_type"].as_str(), t.get("scan"), t.get("malware")), (Some("pdf"), None, None), "trusted files are not downloaded or looked up");
        // Whole downloads for u and v, a range request for t.
        let downloads: Vec<_> = w.mock.downloads().into_iter().filter(|(p, _)| p.starts_with("/download/node/")).collect();
        let mut downloads = downloads;
        downloads.sort();
        assert_eq!(
            downloads,
            vec![("/download/node/item-t/m.pdf".to_string(), Some(SNIFF_RANGE.to_string())), ("/download/node/item-u/m.pdf".to_string(), None), ("/download/node/item-v/m.pdf".to_string(), None)]
        );
        // Lookups send the hash and the key, nothing else.
        let mut mb = w.mock.data.lock().unwrap().mb_requests.clone();
        mb.sort();
        let mut want = vec![(format!("query=get_info&hash={js256}"), Some("test-key".to_string())), (format!("query=get_info&hash={clean256}"), Some("test-key".to_string()))];
        want.sort();
        assert_eq!(mb, want);
        assert_eq!(tmp_files(&scan_tmp_dir(&w.state)), Vec::<PathBuf>::new());
        // A later re-check of u's unchanged item repeats its scan and lookup.
        let p = previous_ia_verdict([("verified", &u)], jiff::Timestamp::now()).unwrap();
        let Verdict::Verified { checks, file_type, .. } = ia_unchanged_verdict(&p).await else { panic!() };
        assert_eq!((file_type, checks.scan.as_ref(), checks.malware.as_ref()), (FileType::Pdf, u.get("scan"), u.get("malware")));
    }

    #[tokio::test]
    async fn ia_launch_scans_from_om_scan_1_are_redone() {
        let mut w = World::new().await;
        // w: its om-scan/1 verdict says Launch (it opens a document); x: its
        // om-scan/1 verdict found nothing. Both items are unchanged.
        let opens_doc = crate::scan::testpdf::classic(&[b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>", crate::scan::testpdf::PAGES, b"<< /S /Launch /F (manual.pdf) >>"]);
        let clean = local::special("clean").unwrap();
        let contributor = openmanuals_core::sign::SigningKey::generate(openmanuals_core::Alg::Ed25519);
        let t_old = w.ago_secs(100);
        let ia = ia_at(t_old, 5);
        for (id, bytes) in [("item-w", &opens_doc), ("item-x", &clean)] {
            {
                let mut d = w.mock.data.lock().unwrap();
                d.meta.insert(id.into(), json!({"files": [{"name": "m.pdf", "sha1": sha1_bytes(bytes), "size": bytes.len().to_string()}], "item_last_updated": t_old, "item_size": 1000, "files_count": 5}));
                d.rows.insert(id.into(), row_for(id, t_old, 5));
                d.files.insert(format!("/download/{id}/m.pdf"), bytes.clone());
            }
            let sha = sha256_bytes(bytes);
            w.location_of(id, &sha, Some((json!({"sha256": sha, "sha1": sha1_bytes(bytes), "size": bytes.len()}), Some(&contributor))));
        }
        let v1 = |active: Value| Checks { scan: Some(json!({"tool": "om-scan/1", "active": active})), malware: None };
        w.verdict_with("item-w", &w.ago(40), Some(&ia), false, Some(FileType::Pdf), &v1(json!(["Launch"])));
        w.verdict_with("item-x", &w.ago(40), Some(&ia), false, Some(FileType::Pdf), &v1(json!([])));
        let start = State::now();
        assert_eq!(run_once(w.state.clone(), 100).await.unwrap(), 2);
        // x is confirmed from the batch; w gets a full check: downloaded and scanned.
        assert_eq!(w.mock.scrapes(), vec![vec!["item-x".to_string()]]);
        assert_eq!(w.mock.metadata_calls(), ["item-w"]);
        let one = |id: &str| w.new_verdicts(id, &start).into_iter().next().unwrap().1;
        let b = one("item-w");
        assert_eq!((b.get("method"), &b["scan"]), (None, &json!({"tool": "om-scan/2", "active": ["LaunchDocument"]})));
        let b = one("item-x");
        assert_eq!((b["method"].as_str(), &b["scan"]), (Some(METHOD_CONDITIONAL), &json!({"tool": "om-scan/1", "active": []})));
    }

    #[tokio::test]
    async fn malware_lookups() {
        let w = World::new().await;
        let h = "ab".repeat(32);
        w.mock.data.lock().unwrap().mb.insert(h.clone(), json!({"query_status": "ok", "data": [{"sha256_hash": h, "signature": null}]}));
        assert_eq!(malware_lookup(Some("k"), &h).await, Some(json!({"source": "malwarebazaar", "listed": true, "signature": null})));
        assert_eq!(malware_lookup(Some("k"), &"cd".repeat(32)).await, Some(json!({"source": "malwarebazaar", "listed": false, "signature": null})));
        w.mock.data.lock().unwrap().mb_fail = true;
        assert_eq!(malware_lookup(Some("k"), &h).await, None, "a failed lookup records nothing");
        assert_eq!(w.mock.data.lock().unwrap().mb_requests.len(), 3);
        // No key: no request at all.
        assert_eq!(malware_lookup(None, &h).await, None);
        assert_eq!(w.mock.data.lock().unwrap().mb_requests.len(), 3);
        // Answers other than ok / hash_not_found are errors.
        for bad in [json!({"query_status": "illegal_hash"}), json!({"query_status": "ok", "data": []}), json!({}), json!({"query_status": "unknown_auth_key"})] {
            assert!(parse_malwarebazaar(&bad).is_err(), "{bad}");
        }
        assert_eq!(parse_malwarebazaar(&json!({"query_status": "ok", "data": [{"signature": "AgentTesla"}]})).unwrap()["signature"], "AgentTesla");
    }

    #[test]
    fn ia_file_urls() {
        assert_eq!(ia_fetch_url("https://archive.org/download/x/m%20a.pdf").as_deref(), Some("https://archive.org/download/x/m%20a.pdf"));
        for bad in ["https://archive.org/download/manualslib-id-82671", "https://archive.org/download/x/", "https://archive.org/details/x/m.pdf", "https://example.com/download/x/m.pdf", "https://archive.org/download/x/m.pdf?a=1"] {
            assert_eq!(ia_fetch_url(bad), None, "{bad}");
        }
        assert_eq!(ia_download_url("x", "m a.pdf"), "https://archive.org/download/x/m%20a.pdf");
    }

    #[tokio::test]
    async fn ia_seam_is_off_by_default() {
        // Without the seam, archive.org calls go to IA_BASE and pacing applies.
        assert_eq!(ia_base(), IA_BASE);
        assert_eq!(host_interval(), HOST_INTERVAL);
        assert_eq!(openmanuals_ledger::model::host_of(&ia_base()).as_deref(), Some("archive.org"));
    }
}
