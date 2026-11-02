//! Resolution of a ledger into entities, applying the rules in README.md
//! ("The ledger and the build"). Deterministic given the entries in cursor order and the
//! trust configuration.
//!
//! The build streams the ledger twice and never holds it in memory:
//!
//! 1. [`Moderation`] sees only `block`/`unblock`/`retract` facts, which decide
//!    whether *other* facts count (they may arrive after the facts they hit).
//! 2. [`Resolver::apply`] folds every fact, in cursor order, into compact
//!    accumulated state; nothing is kept per fact.
//!
//! [`Resolver::finish`] then does the whole-catalog work (merges, statuses,
//! report weights, canonical picks) and returns the [`Model`] the snapshot is
//! written from. A serialized `Resolver` is a checkpoint: applying more facts
//! to it gives the same result as applying everything from scratch. When new
//! moderation hides facts it already applied, [`Resolver::unapply`] takes
//! each back where that provably matches never having applied it; for that
//! the state keeps a little provenance (the cursor that set each newest- or
//! first-wins value, per-entry fact counts, multisets instead of sets). See
//! `crate::checkpoint` and `crate::build`.

use crate::compact::{hex_any, ulid, ulid_exact, FactId, FileId, Interner, Sym};
use crate::config::TrustConfig;
use crate::ledger::Entry;
use crate::view::{EntryView, Obj};
use openmanuals_core::asp;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;

/// A file id: the sha256 hex, or `sha1:<hex>` for legacy files whose sha256 is unknown.
pub fn parse_file_ref(s: &str) -> Option<String> {
    FileId::parse(s).map(|f| f.to_string())
}

/// String members of a fact body, as a `serde_json::Value` or a borrowed [`Obj`].
pub trait Fields {
    fn raw_str(&self, k: &str) -> Option<&str>;
}

impl Fields for Value {
    fn raw_str(&self, k: &str) -> Option<&str> {
        self.get(k).and_then(Value::as_str)
    }
}

impl Fields for Obj<'_> {
    fn raw_str(&self, k: &str) -> Option<&str> {
        self.as_str(k)
    }
}

fn str_ref<'a, B: Fields + ?Sized>(body: &'a B, k: &str) -> Option<&'a str> {
    body.raw_str(k).map(str::trim).filter(|s| !s.is_empty())
}

fn str_field<B: Fields + ?Sized>(body: &B, k: &str) -> Option<String> {
    str_ref(body, k).map(String::from)
}

fn boxed<B: Fields + ?Sized>(body: &B, k: &str) -> Option<Box<str>> {
    str_ref(body, k).map(Box::from)
}

fn hexfield<const N: usize, B: Fields + ?Sized>(body: &B, k: &str) -> Option<[u8; N]> {
    body.raw_str(k).map(str::trim).and_then(hex_any::<N>)
}

/// Union-find with deterministic representatives (the minimum member). The
/// result depends only on the set of unions, not their order.
pub struct Groups<K> {
    parent: HashMap<K, K>,
}

impl<K> Default for Groups<K> {
    fn default() -> Self {
        Groups { parent: HashMap::new() }
    }
}

impl<K: Clone + Eq + Hash + Ord> Groups<K> {
    pub fn find(&mut self, x: &K) -> K {
        let p = match self.parent.get(x) {
            None => return x.clone(),
            Some(p) => p.clone(),
        };
        if &p == x {
            return p;
        }
        let r = self.find(&p);
        self.parent.insert(x.clone(), r.clone());
        r
    }
    pub fn union(&mut self, a: &K, b: &K) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
        self.parent.insert(hi, lo.clone());
        self.parent.entry(lo.clone()).or_insert(lo);
    }
    /// member → representative, for members whose representative is another key.
    pub fn reps(mut self) -> HashMap<K, K> {
        let keys: Vec<K> = self.parent.keys().cloned().collect();
        keys.into_iter().filter_map(|k| {
            let r = self.find(&k);
            (r != k).then_some((k, r))
        }).collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyRec {
    pub alg: String,
    /// Public JWK as JSON text.
    pub jwk: Option<String>,
    pub profile_jws: Option<String>,
    pub profile_name: Option<String>,
    pub profile_cursor: Option<String>,
    pub facts: u64,
    pub verified_copies: u64,
    /// Voucher → how many live `vouch` facts it has for this key.
    pub vouched_by: BTreeMap<String, u32>,
    /// (service, handle, claim_uri) → how many live `identity_link` facts say so.
    pub links: BTreeMap<(String, String, String), u32>,
    /// Cursor of the fact `jwk` was taken from.
    pub jwk_from: Option<u128>,
    /// The newest live `avatar` fact: an uploaded image (its sha256 and
    /// mime) or a URL; both empty for `{"none": true}`.
    pub avatar_sha256: Option<String>,
    pub avatar_mime: Option<String>,
    pub avatar_url: Option<String>,
    /// Cursor of that fact (the newest wins).
    pub avatar_cursor: Option<String>,
}

/// An `avatar` fact's body as JSON, for `openmanuals_core::avatar::parse`.
fn avatar_of(b: &Obj) -> Option<openmanuals_core::avatar::Avatar> {
    use crate::view::Val;
    let mut m = serde_json::Map::new();
    for (k, v) in &b.0 {
        let v = match v {
            Val::Str(s) => Value::String(s.to_string()),
            Val::Int(Some(i)) => Value::from(*i),
            Val::Bool(x) => Value::Bool(*x),
            _ => Value::Null,
        };
        m.insert(k.to_string(), v);
    }
    openmanuals_core::avatar::parse(&Value::Object(m)).ok()
}

impl KeyRec {
    /// No fact contributes to it: a full build would not have the record.
    fn is_empty(&self) -> bool {
        self.facts == 0 && self.jwk.is_none() && self.profile_jws.is_none() && self.avatar_cursor.is_none() && self.vouched_by.is_empty() && self.links.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manual {
    pub title: Box<str>,
    pub doc_type: Sym,
    pub language: Option<Sym>,
    pub year: Option<i64>,
    pub source: Option<Sym>,
    pub source_id: Option<Box<str>>,
    pub source_url: Option<Box<str>>,
    pub author: Sym,
    pub cursor: u128,
    pub canonical_file: Option<FileId>,
    /// Live `manual` facts merged into it.
    pub facts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    pub brand: Sym,
    pub model: Box<str>,
    /// Cursor of the fact that created it (the first wins).
    pub first: u128,
    /// Live `product` facts with this key.
    pub facts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    pub sha256: Option<[u8; 32]>,
    pub sha1: Option<[u8; 20]>,
    pub md5: Option<[u8; 16]>,
    pub size: Option<i64>,
    pub mime: Option<Sym>,
    pub pages: Option<i64>,
    pub author: Sym,
    pub cursor: u128,
    pub derived_from: Option<FileId>,
    pub transform: Option<Sym>,
    pub tool: Option<Sym>,
    pub tool_version: Option<Sym>,
    pub report_weight: f64,
    /// `review.is_some()`: never offered as a manual's download.
    pub flagged: bool,
    pub canonical_location: Option<FactId>,
    /// Why the file is held back, if it is: `malware: <name>`,
    /// `active content: <features>` (the holding ones: not
    /// [`INFORMATIONAL_SCAN_FEATURES`]), `reports`, or `unscanned` (an
    /// untrusted key's file the verifier hasn't examined yet).
    #[serde(default)]
    pub review: Option<Box<str>>,
}

/// Active-content features a scan records without holding a file back
/// (openmanuals-server's `scan::INFORMATIONAL`). Every other feature holds it, so a
/// feature name this build doesn't know (a newer scanner's) holds too.
/// `LaunchDocument` (om-scan/2) is a Launch action that only opens a named
/// document; om-scan/1 called every Launch action `Launch`, which still holds
/// (the verifier re-scans such copies under om-scan/2).
pub const INFORMATIONAL_SCAN_FEATURES: &[&str] = &["LaunchDocument"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: FileId,
    pub url: Box<str>,
    pub host: Sym,
    pub kind: Sym,
    pub ia_identifier: Option<Box<str>>,
    pub ia_filename: Option<Box<str>>,
    pub author: Sym,
    pub cursor: u128,
    pub status: Sym,
    pub verified_at: Option<Box<str>>,
    pub final_url: Option<Box<str>>,
    pub report_weight: f64,
    pub flagged: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Derivation {
    pub derived: FileId,
    pub source: FileId,
    pub transform: Sym,
    pub tool: Option<Sym>,
    pub tool_version: Option<Sym>,
    pub author: Sym,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub id: FactId,
    pub target: Box<str>,
    pub ns: Sym,
    pub value: Box<str>,
    pub reason: Option<Box<str>>,
    pub author: Sym,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Verdict {
    status: Sym,
    at: Option<Box<str>>,
    final_url: Option<Box<str>>,
    /// Cursor of the fact it came from (the newest wins).
    cursor: u128,
    /// The type the server sniffed (`pdf`, `djvu`), when recorded.
    file_type: Option<Sym>,
    /// Active-content features the server's scan found; `None` when the
    /// complete bytes weren't examined.
    scan: Option<Vec<Sym>>,
    /// Malware database listing (signature name), when a lookup found one.
    malware: Option<Box<str>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub entries: usize,
    pub invalid: usize,
    pub blocked: usize,
    pub retracted: usize,
    pub unknown_type: usize,
}

pub fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?;
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

pub fn is_archive_host(host: &str) -> bool {
    host == "archive.org" || host.ends_with(".archive.org")
}

/// Numeric version from a tool_version like `om-strip/3` or `3`; 0 when absent.
pub fn tool_version_num(v: Option<&str>) -> i64 {
    v.and_then(|s| s.rsplit(['/', '-', ' ']).next()).and_then(|n| n.trim_start_matches('v').parse().ok()).unwrap_or(0)
}

/// Facts whose effect reaches other facts, possibly earlier ones.
pub fn is_moderation_type(t: &str) -> bool {
    matches!(t, "block" | "unblock" | "retract")
}

/// Pass 1: block state and retraction claims.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Moderation {
    /// (kind, value) → blocked; the newest moderator fact wins.
    pub blocked: BTreeMap<(String, String), bool>,
    /// fact id → authors who retracted it. A retraction counts only when its
    /// author is the target's author, which pass 2 checks when it meets the target.
    pub retract_claims: HashMap<String, Vec<String>>,
}

/// What a moderation fact asks for, before it is applied.
pub enum ModerationEffect {
    Block,
    Retract(String),
    None,
}

impl Moderation {
    /// Classify a (shape-valid) moderation fact without applying it.
    pub fn effect(e: &Entry, cfg: &TrustConfig) -> ModerationEffect {
        let f = &e.fact;
        match f.r#type.as_str() {
            "block" | "unblock" if cfg.is_moderator(&f.author) && str_ref(&f.body, "kind").is_some() && str_ref(&f.body, "value").is_some() => ModerationEffect::Block,
            "retract" => str_field(&f.body, "fact").map_or(ModerationEffect::None, ModerationEffect::Retract),
            _ => ModerationEffect::None,
        }
    }

    pub fn apply(&mut self, e: &Entry, cfg: &TrustConfig) {
        if e.fact.validate_shape().is_err() {
            return;
        }
        let f = &e.fact;
        match Self::effect(e, cfg) {
            ModerationEffect::Block => {
                let kind = str_field(&f.body, "kind").unwrap();
                let value = str_field(&f.body, "value").unwrap();
                let value = if kind == "host" { value.to_ascii_lowercase() } else { value };
                self.blocked.insert((kind, value), f.r#type == "block");
            }
            ModerationEffect::Retract(target) => {
                let v = self.retract_claims.entry(target).or_default();
                if !v.contains(&f.author) {
                    v.push(f.author.clone());
                }
            }
            ModerationEffect::None => {}
        }
    }

    pub(crate) fn blocks(&self) -> Blocks {
        let mut b = Blocks::default();
        for ((kind, value), on) in &self.blocked {
            if !on {
                continue;
            }
            match kind.as_str() {
                "key" => drop(b.keys.insert(value.clone())),
                "fact" => drop(b.facts.insert(value.clone())),
                "host" => drop(b.hosts.insert(value.clone())),
                "manual" => {
                    if let Some(u) = ulid_exact(value) {
                        b.manuals.insert(u);
                    }
                }
                _ => {}
            }
        }
        b
    }
}

#[derive(Default, Clone)]
pub(crate) struct Blocks {
    pub(crate) keys: HashSet<String>,
    pub(crate) facts: HashSet<String>,
    pub(crate) hosts: HashSet<String>,
    pub(crate) manuals: HashSet<u128>,
}

/// How [`Resolver::apply`] treats a line under some moderation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Invalid,
    /// Its key or the fact itself is blocked.
    Blocked,
    Retracted,
    /// Counted for its key and applied (a blocked manual's fact still counts).
    Live,
}

pub(crate) fn classify(e: &EntryView, m: &Moderation, blocks: &Blocks) -> Class {
    let prep = e.prep.as_ref().expect("prepared");
    if prep.fid.is_none() || prep.cursor.is_none() || !prep.shape_ok {
        return Class::Invalid;
    }
    if blocks.keys.contains(&*e.fact.author) || blocks.facts.contains(&*e.id) {
        return Class::Blocked;
    }
    if m.retract_claims.get(&*e.id).is_some_and(|v| v.iter().any(|a| *a == e.fact.author)) {
        return Class::Retracted;
    }
    Class::Live
}

/// A `manual` fact whose id is blocked (applied for its key, counted as blocked).
fn manual_blocked(e: &EntryView, blocks: &Blocks) -> bool {
    e.fact.r#type == "manual" && e.fact.body.obj().and_then(|b| str_ref(b, "id")).and_then(ulid).is_some_and(|id| blocks.manuals.contains(&id))
}

/// Types [`Resolver::apply`] knows (others count as `unknown_type`).
fn is_known_type(t: &str) -> bool {
    matches!(t, "identity_profile" | "avatar" | "identity_link" | "succession" | "vouch" | "manual" | "product" | "covers" | "manual_file" | "file"
        | "derivation" | "location" | "verified" | "location_status" | "same_as" | "prefer" | "label" | "block" | "unblock" | "retract")
}

/// Pass 2 state: everything later facts or `finish` still need, compactly.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Resolver {
    pub syms: Interner,
    pub stats: Stats,
    /// Cursor of the last entry applied (empty before any).
    pub head: String,
    pub moderation: Moderation,
    keys: BTreeMap<String, KeyRec>,
    successions: Vec<(String, String)>,
    manuals: BTreeMap<u128, Manual>,
    products: HashMap<Sym, Product>,
    raw_covers: Vec<(u128, Sym)>,
    /// (manual, file, role, author of the attaching fact)
    raw_manual_files: Vec<(u128, FileId, Sym, Sym)>,
    files: BTreeMap<FileId, File>,
    sha1_to_sha256: HashMap<[u8; 20], [u8; 32]>,
    derivations: Vec<Derivation>,
    locations: BTreeMap<FactId, Location>,
    verdicts: HashMap<FactId, Verdict>,
    manual_same: Vec<(u128, u128)>,
    product_same: Vec<(Sym, Sym)>,
    /// manual → (file, cursor of the prefer fact); the newest wins.
    prefer_manual: BTreeMap<u128, (FileId, u128)>,
    /// file → (location, cursor of the prefer fact); the newest wins.
    prefer_file: BTreeMap<FileId, (FactId, u128)>,
    labels: Vec<Label>,
    /// Cursor of the last valid entry applied.
    last_cursor: u128,
    /// A valid entry's cursor was not above the previous one; cursors then
    /// can't identify which fact set a value, so nothing is undone in place.
    out_of_order: bool,
    #[serde(skip)]
    blocks: Option<Blocks>,
}

impl Resolver {
    /// Apply one entry. Entries must come in cursor order, after pass 1 has
    /// seen every moderation fact of the ledger.
    pub fn apply(&mut self, e: &EntryView, cfg: &TrustConfig) {
        if self.blocks.is_none() {
            self.blocks = Some(self.moderation.blocks());
        }
        self.stats.entries += 1;
        self.head.clear();
        self.head.push_str(&e.cursor);
        let f = &e.fact;
        let prep = e.prep.as_ref().expect("EntryView::prepare before apply");
        let (Some(fid), Some(cursor), Some(b)) = (prep.fid, prep.cursor, prep.shape_ok.then(|| f.body.obj()).flatten()) else {
            self.stats.invalid += 1;
            return;
        };
        if cursor <= self.last_cursor {
            self.out_of_order = true;
        }
        self.last_cursor = self.last_cursor.max(cursor);
        let blocks = self.blocks.as_ref().unwrap();
        if blocks.keys.contains(&*f.author) || blocks.facts.contains(&*e.id) {
            self.stats.blocked += 1;
            return;
        }
        if self.moderation.retract_claims.get(&*e.id).is_some_and(|v| v.iter().any(|a| *a == f.author)) {
            self.stats.retracted += 1;
            return;
        }
        let author = self.syms.intern(&f.author);

        // Identity.
        if !self.keys.contains_key(&*f.author) {
            self.keys.insert(f.author.to_string(), KeyRec::default());
        }
        let rec = self.keys.get_mut(&*f.author).unwrap();
        rec.facts += 1;
        if rec.jwk.is_none() {
            if let Some(sig) = &f.sig {
                rec.jwk = Some(sig.jwk_text());
                rec.alg = sig.alg_name().to_string();
                rec.jwk_from = Some(cursor);
            }
        }

        let syms = &mut self.syms;
        match &*f.r#type {
            "identity_profile" => {
                if let Some(jws) = str_field(b, "jws") {
                    if let Ok(p) = asp::parse_and_verify(&jws) {
                        if p.fingerprint == f.author {
                            let rec = self.keys.get_mut(&*f.author).unwrap();
                            rec.profile_jws = Some(jws);
                            rec.profile_name = Some(p.name);
                            rec.profile_cursor = Some(e.cursor.to_string());
                        }
                    }
                }
            }
            "avatar" => {
                if let Some(a) = avatar_of(b) {
                    use openmanuals_core::avatar::Avatar;
                    let rec = self.keys.get_mut(&*f.author).unwrap();
                    (rec.avatar_sha256, rec.avatar_mime, rec.avatar_url) = match a {
                        Avatar::Image { sha256, mime, .. } => (Some(sha256), Some(mime), None),
                        Avatar::Url(u) => (None, None, Some(u)),
                        Avatar::None => (None, None, None),
                    };
                    rec.avatar_cursor = Some(e.cursor.to_string());
                }
            }
            "identity_link" if cfg.is_server(&f.author) => {
                if let (Some(key), Some(service), Some(handle)) = (str_field(b, "key"), str_field(b, "service"), str_field(b, "handle")) {
                    let uri = str_field(b, "claim_uri").unwrap_or_default();
                    *self.keys.entry(key).or_default().links.entry((service, handle, uri)).or_default() += 1;
                }
            }
            "succession" => {
                if let (Some(old), Some(new)) = (str_field(b, "old"), str_field(b, "new")) {
                    if *old == *f.author && openmanuals_core::fact::valid_fingerprint(&new) {
                        self.successions.push((old, new));
                    }
                }
            }
            "vouch" => {
                if let Some(k) = str_field(b, "key") {
                    if openmanuals_core::fact::valid_fingerprint(&k) {
                        *self.keys.entry(k).or_default().vouched_by.entry(f.author.to_string()).or_default() += 1;
                    }
                }
            }
            "manual" => {
                let Some(id) = str_ref(b, "id").and_then(ulid) else { return };
                if self.blocks.as_ref().unwrap().manuals.contains(&id) {
                    self.stats.blocked += 1;
                    return;
                }
                let empty = syms.intern("");
                let man = self.manuals.entry(id).or_insert_with(|| Manual {
                    title: "".into(), doc_type: empty, language: None, year: None, source: None, source_id: None,
                    source_url: None, author, cursor, canonical_file: None, facts: 0,
                });
                man.facts += 1;
                // Newest wins per field, from any live author.
                if let Some(t) = boxed(b, "title") {
                    man.title = t;
                }
                if let Some(t) = str_ref(b, "doc_type") {
                    man.doc_type = syms.intern(t);
                }
                if let Some(t) = str_ref(b, "language") {
                    man.language = Some(syms.intern(t));
                }
                if let Some(y) = b.as_i64("year") {
                    man.year = Some(y);
                }
                if let Some(t) = str_ref(b, "source") {
                    man.source = Some(syms.intern(t));
                }
                if let Some(t) = boxed(b, "source_id") {
                    man.source_id = Some(t);
                }
                if let Some(t) = boxed(b, "source_url") {
                    man.source_url = Some(t);
                }
            }
            "product" => {
                let (Some(brand), Some(model), Some(key)) = (str_ref(b, "brand"), str_ref(b, "model"), prep.product_key.as_deref()) else { return };
                let key = syms.intern(key);
                self.products.entry(key).or_insert_with(|| Product { brand: syms.intern(brand), model: model.into(), first: cursor, facts: 0 }).facts += 1;
            }
            "covers" => {
                if let (Some(man), Some(p)) = (str_ref(b, "manual"), str_ref(b, "product")) {
                    if let Some(man) = ulid(man) {
                        let p = syms.intern(p);
                        self.raw_covers.push((man, p));
                    }
                }
            }
            "manual_file" => {
                if let (Some(man), Some(file)) = (str_ref(b, "manual").and_then(ulid), str_ref(b, "file").and_then(FileId::parse)) {
                    let role = syms.intern(str_ref(b, "role").unwrap_or("primary"));
                    self.raw_manual_files.push((man, file, role, author));
                }
            }
            "file" => {
                let sha256 = hexfield::<32, _>(b, "sha256");
                let sha1 = hexfield::<20, _>(b, "sha1");
                let Some(id) = sha256.map(FileId::Sha256).or(sha1.map(FileId::Sha1)) else { return };
                if let (Some(s256), Some(s1)) = (sha256, sha1) {
                    self.sha1_to_sha256.insert(s1, s256);
                }
                let file = self.files.entry(id).or_insert_with(|| File {
                    sha256: None, sha1: None, md5: None, size: None, mime: None, pages: None, author, cursor,
                    derived_from: None, transform: None, tool: None, tool_version: None, report_weight: 0.0,
                    flagged: false, canonical_location: None, review: None,
                });
                file.sha256 = file.sha256.or(sha256);
                file.sha1 = file.sha1.or(sha1);
                file.md5 = file.md5.or(hexfield::<16, _>(b, "md5"));
                file.size = file.size.or(b.as_i64("size"));
                if file.mime.is_none() {
                    file.mime = str_ref(b, "mime").map(|m| syms.intern(m));
                }
                file.pages = file.pages.or(b.as_i64("pages"));
            }
            "derivation" => {
                if let (Some(derived), Some(source), Some(transform)) = (str_ref(b, "derived").and_then(FileId::parse), str_ref(b, "source").and_then(FileId::parse), str_ref(b, "transform")) {
                    let transform = syms.intern(transform);
                    let tool = str_ref(b, "tool").map(|t| syms.intern(t));
                    let tool_version = str_ref(b, "tool_version").map(|t| syms.intern(t));
                    self.derivations.push(Derivation { derived, source, transform, tool, tool_version, author });
                }
            }
            "location" => {
                let (Some(file), Some(url)) = (str_ref(b, "file").and_then(FileId::parse), str_ref(b, "url")) else { return };
                let Some(host) = host_of(url) else { return };
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    return;
                }
                let kind = syms.intern(str_ref(b, "kind").unwrap_or("mirror"));
                let (ia_identifier, ia_filename) = match b.obj("ia") {
                    Some(ia) => (boxed(ia, "identifier"), boxed(ia, "filename")),
                    None => (None, None),
                };
                let host = syms.intern(&host);
                let pending = syms.intern("pending");
                self.locations.insert(fid, Location {
                    file, url: url.into(), host, kind, ia_identifier, ia_filename, author, cursor, status: pending,
                    verified_at: None, final_url: None, report_weight: 0.0, flagged: false,
                });
            }
            "verified" | "location_status" if cfg.is_server(&f.author) => {
                // A verdict on something that is not a fact id can never match a location.
                let Some(loc) = str_ref(b, "location").and_then(FactId::parse) else { return };
                let file_type = str_ref(b, "file_type");
                // A server that sniffed something other than a document never vouches for it.
                let refused = file_type.is_some_and(|t| openmanuals_core::sniff::FileType::from_name(t).is_none());
                let status = if f.r#type == "verified" && !refused { "verified" } else if refused { "changed" } else { str_ref(b, "status").unwrap_or("gone") };
                let status = syms.intern(status);
                let file_type = file_type.map(|t| syms.intern(t));
                let scan = b.obj("scan").map(|sc| {
                    sc.arr("active").unwrap_or_default().iter().filter_map(|v| match v {
                        crate::view::Val::Str(x) => Some(syms.intern(x)),
                        _ => None,
                    }).collect::<Vec<Sym>>()
                });
                let malware = b.obj("malware").filter(|m| m.as_bool("listed") == Some(true))
                    .map(|m| Box::from(m.as_str("signature").map(str::trim).filter(|x| !x.is_empty()).unwrap_or("listed")));
                self.verdicts.insert(loc, Verdict { status, at: boxed(b, "checked_at"), final_url: boxed(b, "final_url"), cursor, file_type, scan, malware });
            }
            "same_as" => {
                if let (Some(kind), Some(a), Some(bb)) = (str_ref(b, "kind"), str_ref(b, "a"), str_ref(b, "b")) {
                    match kind {
                        "manual" => {
                            if let (Some(a), Some(bb)) = (ulid(a), ulid(bb)) {
                                self.manual_same.push((a, bb));
                            }
                        }
                        "product" => {
                            let (a, bb) = (syms.intern(a), syms.intern(bb));
                            self.product_same.push((a, bb));
                        }
                        _ => {}
                    }
                }
            }
            "prefer" if cfg.is_moderator(&f.author) => {
                if let Some(man) = str_ref(b, "manual") {
                    if let (Some(man), Some(file)) = (ulid(man), str_ref(b, "file").and_then(FileId::parse)) {
                        self.prefer_manual.insert(man, (file, cursor));
                    }
                } else if let (Some(file), Some(loc)) = (str_ref(b, "file").and_then(FileId::parse), str_ref(b, "location").and_then(FactId::parse)) {
                    self.prefer_file.insert(file, (loc, cursor));
                }
            }
            "label" => {
                let (Some(target), Some(ns), Some(value)) = (boxed(b, "target"), str_ref(b, "ns"), boxed(b, "value")) else { return };
                let ns = syms.intern(ns);
                self.labels.push(Label { id: fid, target, ns, value, reason: boxed(b, "reason"), author, weight: 0.0 });
            }
            "identity_link" | "block" | "unblock" | "retract" | "prefer" | "verified" | "location_status" => {}
            _ => self.stats.unknown_type += 1,
        }
    }

    /// The moderation the applied facts were resolved with.
    pub fn moderation(&self) -> &Moderation {
        &self.moderation
    }

    /// Replace the moderation state (facts applied after this see the new one).
    pub(crate) fn set_moderation(&mut self, m: Moderation) {
        self.moderation = m;
        self.blocks = None;
    }

    /// Whether facts already applied can be taken back in place (cursors
    /// strictly increasing, so a cursor names the one fact that set a value).
    pub(crate) fn can_undo(&self) -> bool {
        !self.out_of_order
    }

    /// Remove every live `manual` fact for each newly blocked manual id (the
    /// entry is made of nothing else), counting them as blocked.
    pub(crate) fn block_manuals(&mut self, ids: &HashSet<u128>) {
        for id in ids {
            if let Some(m) = self.manuals.remove(id) {
                self.stats.blocked += m.facts as usize;
            }
        }
    }

    /// Take back what an already-applied line did, because moderation that
    /// arrived later hides it (`old` → `new` moderation). `Err(why)` when the
    /// result could differ from never having applied it (a merged first- or
    /// newest-wins value it may have set, or a line `new` reveals); the
    /// resolver must then be discarded.
    pub(crate) fn unapply(&mut self, e: &EntryView, old: (&Moderation, &Blocks), new: (&Moderation, &Blocks), newly_blocked_manuals: &HashSet<u128>, cfg: &TrustConfig) -> Result<(), String> {
        let was = classify(e, old.0, old.1);
        let now = classify(e, new.0, new.1);
        match (was, now) {
            (Class::Live, Class::Live) => return Ok(()),
            (Class::Live, _) => {}
            (_, Class::Live) => return Err(format!("{} is no longer hidden", e.id)),
            _ => {
                self.count(e, was, old.1, -1);
                self.count(e, now, new.1, 1);
                return Ok(());
            }
        }
        if !self.can_undo() {
            return Err("ledger cursors are not in order".into());
        }
        self.count(e, was, old.1, -1);
        self.count(e, now, new.1, 1);
        let f = &e.fact;
        let prep = e.prep.as_ref().expect("prepared");
        let (Some(fid), Some(cursor), Some(b)) = (prep.fid, prep.cursor, f.body.obj()) else { unreachable!("live lines are valid") };
        let mut touched: Vec<String> = vec![f.author.to_string()];
        {
            let rec = self.keys.get_mut(&*f.author).ok_or("a live fact's key has no record")?;
            if rec.facts == 0 {
                return Err("a key's fact count is off".into());
            }
            rec.facts -= 1;
            if rec.jwk_from == Some(cursor) {
                return Err(format!("{} is the first signed fact of its key", e.id));
            }
        }
        let gone = |what: &str| format!("{} ({what}) is not in the state", e.id);
        let syms = &mut self.syms;
        match &*f.r#type {
            "identity_profile" => {
                if self.keys.get(&*f.author).and_then(|r| r.profile_cursor.as_deref()) == Some(&*e.cursor) {
                    return Err(format!("{} is its key's current profile", e.id));
                }
            }
            "avatar" => {
                // The previous avatar isn't kept: hiding the current one needs a full build.
                if self.keys.get(&*f.author).and_then(|r| r.avatar_cursor.as_deref()) == Some(&*e.cursor) {
                    return Err(format!("{} is its key's current avatar", e.id));
                }
            }
            "identity_link" if cfg.is_server(&f.author) => {
                if let (Some(key), Some(service), Some(handle)) = (str_field(b, "key"), str_field(b, "service"), str_field(b, "handle")) {
                    let uri = str_field(b, "claim_uri").unwrap_or_default();
                    let rec = self.keys.get_mut(&key).ok_or_else(|| gone("link"))?;
                    let t = (service, handle, uri);
                    let n = rec.links.get_mut(&t).ok_or_else(|| gone("link"))?;
                    *n -= 1;
                    if *n == 0 {
                        rec.links.remove(&t);
                    }
                    touched.push(key);
                }
            }
            "succession" => {
                if let (Some(old), Some(new)) = (str_ref(b, "old"), str_ref(b, "new")) {
                    if *old == *f.author && openmanuals_core::fact::valid_fingerprint(new) {
                        let i = self.successions.iter().rposition(|(o, n)| o == old && n == new).ok_or_else(|| gone("succession"))?;
                        self.successions.remove(i);
                    }
                }
            }
            "vouch" => {
                if let Some(k) = str_field(b, "key") {
                    if openmanuals_core::fact::valid_fingerprint(&k) {
                        let rec = self.keys.get_mut(&k).ok_or_else(|| gone("vouch"))?;
                        let n = rec.vouched_by.get_mut(&*f.author).ok_or_else(|| gone("vouch"))?;
                        *n -= 1;
                        if *n == 0 {
                            rec.vouched_by.remove(&*f.author);
                        }
                        touched.push(k);
                    }
                }
            }
            "manual" => {
                if let Some(id) = str_ref(b, "id").and_then(ulid) {
                    if !old.1.manuals.contains(&id) {
                        let m = self.manuals.get_mut(&id).ok_or_else(|| gone("manual"))?;
                        if newly_blocked_manuals.contains(&id) {
                            // `block_manuals` drops the entry and counts the rest.
                            m.facts -= 1;
                        } else if m.facts == 1 {
                            self.manuals.remove(&id);
                        } else {
                            return Err(format!("{} was merged with other manual facts", e.id));
                        }
                    }
                }
            }
            "product" => {
                if let (Some(_), Some(_), Some(key)) = (str_ref(b, "brand"), str_ref(b, "model"), prep.product_key.as_deref()) {
                    let key = syms.lookup(key).ok_or_else(|| gone("product"))?;
                    let p = self.products.get_mut(&key).ok_or_else(|| gone("product"))?;
                    if p.facts == 1 {
                        self.products.remove(&key);
                    } else if p.first == cursor {
                        return Err(format!("{} created a product other facts repeat", e.id));
                    } else {
                        p.facts -= 1;
                    }
                }
            }
            "covers" => {
                if let (Some(man), Some(p)) = (str_ref(b, "manual"), str_ref(b, "product")) {
                    if let Some(man) = ulid(man) {
                        let p = syms.lookup(p).ok_or_else(|| gone("covers"))?;
                        let i = self.raw_covers.iter().rposition(|x| *x == (man, p)).ok_or_else(|| gone("covers"))?;
                        self.raw_covers.remove(i);
                    }
                }
            }
            "manual_file" => {
                if let (Some(man), Some(file)) = (str_ref(b, "manual").and_then(ulid), str_ref(b, "file").and_then(FileId::parse)) {
                    let role = syms.lookup(str_ref(b, "role").unwrap_or("primary")).ok_or_else(|| gone("manual_file"))?;
                    let who = syms.lookup(&f.author).ok_or_else(|| gone("manual_file"))?;
                    let i = self.raw_manual_files.iter().rposition(|x| *x == (man, file, role, who)).ok_or_else(|| gone("manual_file"))?;
                    self.raw_manual_files.remove(i);
                }
            }
            "file" => {
                if hexfield::<32, _>(b, "sha256").is_some() || hexfield::<20, _>(b, "sha1").is_some() {
                    return Err(format!("{} is a file fact (merged first-wins)", e.id));
                }
            }
            "derivation" => {
                if let (Some(derived), Some(source), Some(transform)) = (str_ref(b, "derived").and_then(FileId::parse), str_ref(b, "source").and_then(FileId::parse), str_ref(b, "transform")) {
                    let look = |s: &str| syms.lookup(s).ok_or_else(|| gone("derivation"));
                    let author = look(&f.author)?;
                    let d = Derivation {
                        derived, source, transform: look(transform)?,
                        tool: str_ref(b, "tool").map(look).transpose()?,
                        tool_version: str_ref(b, "tool_version").map(look).transpose()?,
                        author,
                    };
                    let i = self.derivations.iter().rposition(|x| *x == d).ok_or_else(|| gone("derivation"))?;
                    self.derivations.remove(i);
                }
            }
            "location" => {
                if let (Some(_), Some(url)) = (str_ref(b, "file").and_then(FileId::parse), str_ref(b, "url")) {
                    if host_of(url).is_some() && (url.starts_with("https://") || url.starts_with("http://")) {
                        match self.locations.get(&fid) {
                            Some(l) if l.cursor == cursor => drop(self.locations.remove(&fid)),
                            _ => return Err(gone("location")),
                        }
                    }
                }
            }
            "verified" | "location_status" if cfg.is_server(&f.author) => {
                if let Some(loc) = str_ref(b, "location").and_then(FactId::parse) {
                    match self.verdicts.get(&loc) {
                        Some(v) if v.cursor == cursor => return Err(format!("{} is its copy's current verdict", e.id)),
                        Some(_) => {}
                        None => return Err(gone("verdict")),
                    }
                }
            }
            "same_as" => {
                if let (Some(kind), Some(a), Some(bb)) = (str_ref(b, "kind"), str_ref(b, "a"), str_ref(b, "b")) {
                    match kind {
                        "manual" => {
                            if let (Some(a), Some(bb)) = (ulid(a), ulid(bb)) {
                                let i = self.manual_same.iter().rposition(|x| *x == (a, bb)).ok_or_else(|| gone("same_as"))?;
                                self.manual_same.remove(i);
                            }
                        }
                        "product" => {
                            let (a, bb) = (syms.lookup(a).ok_or_else(|| gone("same_as"))?, syms.lookup(bb).ok_or_else(|| gone("same_as"))?);
                            let i = self.product_same.iter().rposition(|x| *x == (a, bb)).ok_or_else(|| gone("same_as"))?;
                            self.product_same.remove(i);
                        }
                        _ => {}
                    }
                }
            }
            "prefer" if cfg.is_moderator(&f.author) => {
                let current = if let Some(man) = str_ref(b, "manual") {
                    match (ulid(man), str_ref(b, "file").and_then(FileId::parse)) {
                        (Some(man), Some(_)) => self.prefer_manual.get(&man).map(|p| p.1),
                        _ => None,
                    }
                } else if let (Some(file), Some(_)) = (str_ref(b, "file").and_then(FileId::parse), str_ref(b, "location").and_then(FactId::parse)) {
                    self.prefer_file.get(&file).map(|p| p.1)
                } else {
                    None
                };
                if current == Some(cursor) {
                    return Err(format!("{} is the current preference", e.id));
                }
            }
            "label" => {
                if let (Some(_), Some(_), Some(_)) = (str_ref(b, "target"), str_ref(b, "ns"), str_ref(b, "value")) {
                    let i = self.labels.iter().rposition(|l| l.id == fid).ok_or_else(|| gone("label"))?;
                    self.labels.remove(i);
                }
            }
            _ => {}
        }
        for k in touched {
            if self.keys.get(&k).is_some_and(KeyRec::is_empty) {
                self.keys.remove(&k);
            }
        }
        Ok(())
    }

    /// Add `d` to the counter `class` contributes to for this line.
    fn count(&mut self, e: &EntryView, class: Class, blocks: &Blocks, d: isize) {
        let s = &mut self.stats;
        let c = match class {
            Class::Invalid => &mut s.invalid,
            Class::Blocked => &mut s.blocked,
            Class::Retracted => &mut s.retracted,
            Class::Live if manual_blocked(e, blocks) => &mut s.blocked,
            Class::Live if !is_known_type(&e.fact.r#type) => &mut s.unknown_type,
            Class::Live => return,
        };
        *c = c.wrapping_add_signed(d);
    }

    /// [`Resolver::apply`] for an owned entry (tests, tools): goes through its JSON.
    pub fn apply_entry(&mut self, e: &Entry, cfg: &TrustConfig) {
        let line = serde_json::to_string(e).expect("entry serializes");
        let mut v: EntryView = serde_json::from_str(&line).expect("a serialized entry parses");
        v.prepare();
        self.apply(&v, cfg);
    }

    /// The whole-catalog rules, consuming the accumulated state.
    pub fn finish(self, cfg: &TrustConfig) -> Model {
        let Resolver {
            mut syms, stats, head, moderation, mut keys, successions, mut manuals, mut products, raw_covers,
            raw_manual_files, mut files, sha1_to_sha256, mut derivations, mut locations, verdicts, manual_same,
            product_same, prefer_manual, prefer_file, mut labels, blocks, ..
        } = self;
        let blocks = blocks.unwrap_or_else(|| moderation.blocks());

        // Keys sharing a verified claim target, or linked by succession, are one contributor.
        let mut key_groups: Groups<String> = Groups::default();
        for (old, new) in &successions {
            key_groups.union(old, new);
        }
        let mut by_target: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
        for (fp, rec) in &keys {
            for (service, handle, _) in rec.links.keys() {
                by_target.entry((service, handle)).or_default().push(fp);
            }
        }
        for ks in by_target.values() {
            for k in &ks[1..] {
                key_groups.union(&ks[0].to_string(), &k.to_string());
            }
        }
        let contributor_of: BTreeMap<String, String> = keys.keys().map(|fp| (fp.clone(), key_groups.find(fp))).collect();

        // Resolve legacy sha1 file ids onto sha256 ids where both are known.
        let resolve_file = |id: FileId| -> FileId {
            match id {
                FileId::Sha1(h) => sha1_to_sha256.get(&h).map_or(id, |s| FileId::Sha256(*s)),
                _ => id,
            }
        };
        let legacy: Vec<FileId> = files.keys().filter(|k| matches!(k, FileId::Sha1(_)) && resolve_file(**k) != **k).copied().collect();
        for old in legacy {
            let f = files.remove(&old).unwrap();
            let target = files.get_mut(&resolve_file(old)).unwrap();
            target.sha1 = target.sha1.or(f.sha1);
            target.md5 = target.md5.or(f.md5);
            target.size = target.size.or(f.size);
            target.mime = target.mime.or(f.mime);
            target.pages = target.pages.or(f.pages);
        }
        for loc in locations.values_mut() {
            loc.file = resolve_file(loc.file);
        }
        for d in &mut derivations {
            d.derived = resolve_file(d.derived);
            d.source = resolve_file(d.source);
        }

        // Merge manuals and products by same_as (representative = minimum id).
        let mut mg: Groups<u128> = Groups::default();
        for (a, b) in &manual_same {
            mg.union(a, b);
        }
        let manual_rep = mg.reps();
        let man_of = |id: u128| manual_rep.get(&id).copied().unwrap_or(id);
        let mut dups: Vec<(u128, u128)> = manual_rep.iter().map(|(k, r)| (*k, *r)).collect();
        dups.sort();
        for (id, rep) in dups {
            if manuals.contains_key(&id) && manuals.contains_key(&rep) {
                let dup = manuals.remove(&id).unwrap();
                let keep = manuals.get_mut(&rep).unwrap();
                if keep.title.is_empty() {
                    keep.title = dup.title;
                }
                if syms.get(keep.doc_type).is_empty() {
                    keep.doc_type = dup.doc_type;
                }
                keep.source_url = keep.source_url.take().or(dup.source_url);
                keep.source = keep.source.or(dup.source);
                keep.source_id = keep.source_id.take().or(dup.source_id);
            }
        }
        let mut pg: Groups<String> = Groups::default();
        for (a, b) in &product_same {
            pg.union(&syms.get(*a).to_string(), &syms.get(*b).to_string());
        }
        let product_rep: HashMap<Sym, Sym> = pg.reps().into_iter().map(|(k, r)| (syms.intern(&k), syms.intern(&r))).collect();
        for (key, rep) in &product_rep {
            if products.contains_key(rep) {
                products.remove(key);
            }
        }
        let mut products: Vec<(Sym, Product)> = products.into_iter().collect();
        products.sort_by(|a, b| syms.get(a.0).cmp(syms.get(b.0)));
        let rank: HashMap<Sym, u32> = products.iter().enumerate().map(|(i, (k, _))| (*k, i as u32)).collect();
        let mut covers: Vec<(u128, u32)> = raw_covers.into_iter().filter_map(|(man, p)| {
            let man = man_of(man);
            let p = product_rep.get(&p).copied().unwrap_or(p);
            manuals.contains_key(&man).then_some(())?;
            Some((man, *rank.get(&p)?))
        }).collect();
        covers.sort_unstable();
        covers.dedup();
        // An attachment is trusted when the manual's creator or a trusted key made it.
        let mut trusted_attachment: HashSet<(u128, FileId)> = HashSet::new();
        let mut manual_files: Vec<(u128, FileId, Sym)> = raw_manual_files.into_iter().filter_map(|(man, file, role, who)| {
            let (man, file) = (man_of(man), resolve_file(file));
            let m = manuals.get(&man)?;
            if !files.contains_key(&file) {
                return None;
            }
            if who == m.author || cfg.is_trusted(syms.get(who)) {
                trusted_attachment.insert((man, file));
            }
            Some((man, file, role))
        }).collect();
        manual_files.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)).then_with(|| syms.get(a.2).cmp(syms.get(b.2))));
        manual_files.dedup();
        for d in &derivations {
            let source_known = files.contains_key(&d.source);
            if let Some(f) = files.get_mut(&d.derived) {
                // Only the key that introduced a file (or a trusted key) may say what it derives from.
                let by_owner = d.author == f.author || cfg.is_trusted(syms.get(d.author));
                if f.derived_from.is_none() && source_known && by_owner {
                    f.derived_from = Some(d.source);
                    f.transform = Some(d.transform);
                    f.tool = d.tool;
                    f.tool_version = d.tool_version;
                }
            }
        }

        // Location status.
        let origin = syms.intern("origin");
        let verified = syms.intern("verified");
        let blocked = syms.intern("blocked");
        for (id, loc) in locations.iter_mut() {
            if loc.kind == origin {
                loc.status = origin;
            } else if let Some(v) = verdicts.get(id) {
                loc.status = v.status;
                loc.verified_at = v.at.clone();
                loc.final_url = v.final_url.clone();
            }
            if blocks.hosts.contains(syms.get(loc.host)) {
                loc.status = blocked;
            }
        }
        // Verified copies per key (reputation input).
        for loc in locations.values() {
            if loc.status == verified {
                if let Some(k) = keys.get_mut(syms.get(loc.author)) {
                    k.verified_copies += 1;
                }
            }
        }
        // What the server found in each file's bytes, from its verified copies.
        #[derive(Default)]
        struct Found {
            file_type: Option<Sym>,
            scanned: bool,
            active: std::collections::BTreeSet<String>,
            malware: Option<Box<str>>,
        }
        let mut found: HashMap<FileId, Found> = HashMap::new();
        for (id, loc) in &locations {
            if loc.status != verified {
                continue;
            }
            let fd = found.entry(loc.file).or_default();
            if let Some(v) = verdicts.get(id) {
                fd.file_type = fd.file_type.or(v.file_type);
                if let Some(active) = &v.scan {
                    fd.scanned = true;
                    fd.active.extend(active.iter().map(|a| syms.get(*a).to_string()));
                }
                if fd.malware.is_none() {
                    fd.malware = v.malware.clone();
                }
            }
        }

        // Labels and report weights.
        let weight_of = |fp: &str| -> f64 {
            if cfg.is_labeler(fp) {
                return 1.0;
            }
            let Some(k) = keys.get(fp) else { return 0.0 };
            let mut w = 0.2 + 0.1 * (k.verified_copies.min(5) as f64);
            if !k.links.is_empty() {
                w += 0.3;
            }
            if k.vouched_by.keys().any(|v| keys.get(v).is_some_and(|vk| vk.verified_copies > 0 || !vk.links.is_empty())) {
                w += 0.2;
            }
            w.min(1.0)
        };
        for l in &mut labels {
            l.weight = weight_of(syms.get(l.author));
        }
        // One report per (author, target) counts.
        let report = syms.lookup("report");
        let mut seen: HashSet<(Sym, &str)> = HashSet::new();
        let mut report_sum: BTreeMap<&str, f64> = BTreeMap::new();
        for l in &labels {
            if Some(l.ns) == report && seen.insert((l.author, &l.target)) {
                *report_sum.entry(&l.target).or_default() += l.weight;
            }
        }
        for (target, w) in &report_sum {
            if let Some(h) = target.strip_prefix("file:") {
                // Exact spelling only, as the text ids were compared before.
                if let Some(f) = FileId::parse(h).filter(|f| f.to_string() == *h).and_then(|id| files.get_mut(&resolve_file(id))) {
                    f.report_weight = *w;
                    f.flagged = *w >= cfg.thresholds.report;
                }
            } else if let Some(l) = FactId::parse(target).and_then(|id| locations.get_mut(&id)) {
                l.report_weight = *w;
                l.flagged = *w >= cfg.thresholds.report;
            }
        }
        // Files held back from being any manual's download, and why. The type
        // the server sniffed replaces the author's claimed MIME type.
        let holds = |feature: &str| !INFORMATIONAL_SCAN_FEATURES.contains(&feature);
        for (id, f) in files.iter_mut() {
            let fd = found.get(id);
            if let Some(mime) = fd.and_then(|x| x.file_type).and_then(|t| openmanuals_core::sniff::FileType::from_name(syms.get(t))).map(|t| t.mime()) {
                f.mime = Some(syms.intern(mime));
            }
            let review = match fd {
                Some(Found { malware: Some(m), .. }) => Some(format!("malware: {m}")),
                Some(x) if x.active.iter().any(|a| holds(a)) => Some(format!("active content: {}", x.active.iter().filter(|a| holds(a)).cloned().collect::<Vec<_>>().join(", "))),
                _ if f.flagged => Some("reports".to_string()),
                // An untrusted key's file must have been examined before it is offered.
                Some(x) if !x.scanned && !cfg.is_trusted(syms.get(f.author)) => Some("unscanned".to_string()),
                _ => None,
            };
            f.flagged = review.is_some();
            f.review = review.map(Box::from);
        }

        // Canonical copy per file.
        let mut by_file: BTreeMap<FileId, Vec<(FactId, &Location)>> = BTreeMap::new();
        for (id, loc) in &locations {
            if loc.status == verified && !loc.flagged {
                by_file.entry(loc.file).or_default().push((*id, loc));
            }
        }
        let mut canonical_loc: Vec<(FileId, FactId)> = Vec::with_capacity(by_file.len());
        for (file, mut locs) in by_file {
            let preferred = prefer_file.get(&file).map(|p| p.0).filter(|p| locs.iter().any(|(id, _)| id == p));
            let best = preferred.unwrap_or_else(|| {
                locs.sort_by(|(_, a), (_, b)| {
                    is_archive_host(syms.get(b.host)).cmp(&is_archive_host(syms.get(a.host)))
                        .then_with(|| a.verified_at.cmp(&b.verified_at))
                        .then_with(|| a.cursor.cmp(&b.cursor))
                });
                locs[0].0
            });
            canonical_loc.push((file, best));
        }
        for (file, loc) in canonical_loc {
            if let Some(f) = files.get_mut(&file) {
                f.canonical_location = Some(loc);
            }
        }

        // Canonical file per manual.
        let mut files_of: HashMap<u128, Vec<FileId>> = HashMap::new();
        for (man, file, _) in &manual_files {
            files_of.entry(*man).or_default().push(*file);
        }
        for (man_id, man) in manuals.iter_mut() {
            let attached = files_of.get(man_id).map(Vec::as_slice).unwrap_or_default();
            if let Some(p) = prefer_manual.get(man_id).map(|p| p.0).filter(|p| attached.contains(p)) {
                man.canonical_file = Some(p);
                continue;
            }
            let mut cands: Vec<(FileId, &File)> = attached.iter().filter_map(|id| files.get(id).map(|f| (*id, f))).filter(|(_, f)| f.canonical_location.is_some() && !f.flagged).collect();
            // 1. files attached by the manual's creator or a trusted key;
            // 2. among those, variants from an allow-listed tool, the tool listed
            //    last (then the higher version of one tool) first;
            // 3. then the incumbent: the file recorded first, so a newcomer never
            //    displaces an existing download on its own (a moderator's
            //    `prefer` can).
            let rank = |id: &FileId, f: &File| -> (bool, Option<(usize, i64)>) {
                let trusted = trusted_attachment.contains(&(*man_id, *id));
                let tool = f.tool_version.filter(|_| trusted && f.derived_from.is_some()).and_then(|t| cfg.tool_rank(syms.get(t)));
                (trusted, tool)
            };
            cands.sort_by(|(ia, a), (ib, b)| rank(ib, b).cmp(&rank(ia, a)).then_with(|| a.cursor.cmp(&b.cursor)).then_with(|| ia.cmp(ib)));
            man.canonical_file = cands.first().map(|(id, _)| *id);
        }

        Model {
            syms, keys, contributor_of, manuals, products, covers, manual_files, files, locations, derivations, labels, stats,
            head: (!head.is_empty()).then_some(head),
        }
    }
}

/// The resolved catalog the snapshot is written from.
pub struct Model {
    pub syms: Interner,
    pub keys: BTreeMap<String, KeyRec>,
    /// key fingerprint → contributor (group) id
    pub contributor_of: BTreeMap<String, String>,
    pub manuals: BTreeMap<u128, Manual>,
    /// Sorted by product key text.
    pub products: Vec<(Sym, Product)>,
    /// (manual, index into `products`), sorted.
    pub covers: Vec<(u128, u32)>,
    /// (manual, file, role), sorted by text.
    pub manual_files: Vec<(u128, FileId, Sym)>,
    pub files: BTreeMap<FileId, File>,
    pub locations: BTreeMap<FactId, Location>,
    pub derivations: Vec<Derivation>,
    pub labels: Vec<Label>,
    pub stats: Stats,
    /// Cursor of the last entry.
    pub head: Option<String>,
}

impl Model {
    /// Both passes over entries already in memory.
    pub fn resolve(entries: &[Entry], cfg: &TrustConfig) -> Model {
        let mut r = Resolver::default();
        for e in entries.iter().filter(|e| is_moderation_type(&e.fact.r#type)) {
            r.moderation.apply(e, cfg);
        }
        for e in entries {
            r.apply_entry(e, cfg);
        }
        r.finish(cfg)
    }

    pub fn s(&self, s: Sym) -> &str {
        self.syms.get(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_refs_and_hosts() {
        assert_eq!(parse_file_ref(&"AB".repeat(32)).unwrap(), "ab".repeat(32));
        assert_eq!(parse_file_ref("sha1:0123456789abcdef0123456789abcdef01234567").unwrap(), "sha1:0123456789abcdef0123456789abcdef01234567");
        assert!(parse_file_ref("sha1:zz").is_none());
        assert_eq!(host_of("https://User@Archive.org:443/download/x?y#z").unwrap(), "archive.org");
        assert!(is_archive_host("ia800203.us.archive.org"));
        assert_eq!(tool_version_num(Some("om-strip/3")), 3);
        assert_eq!(tool_version_num(None), 0);
    }

    #[test]
    fn groups_pick_minimum() {
        let mut g: Groups<String> = Groups::default();
        g.union(&"b".into(), &"c".into());
        g.union(&"c".into(), &"a".into());
        assert_eq!(g.find(&"b".into()), "a");
        assert_eq!(g.find(&"z".into()), "z");
        let reps = g.reps();
        assert_eq!(reps.get("c").map(String::as_str), Some("a"));
        assert!(!reps.contains_key("a"));
    }
}
