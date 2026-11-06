//! `om`: the OpenManuals command line. See "The CLI" in README.md.

mod keys;
mod import_ia;
mod migrate;
mod moderate;
mod outbox;
mod restrip;
mod sync;
mod upload;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Builds parse facts on many threads and free them on another; mimalloc
/// handles that far better than the system allocator (2.4x faster builds).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "om", version, about = "OpenManuals: keys, facts, sync, uploads")]
struct Cli {
    /// Directory for the key, outbox and sync state.
    #[arg(long, env = "OM_HOME", global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
struct SendOpts {
    #[arg(long, env = "OM_SERVER", default_value = "http://localhost:8000")]
    server: String,
    /// Only queue it in the outbox (send later with `om sync --push-only`).
    #[arg(long)]
    queue_only: bool,
    /// Sign it even if the server doesn't list this key as a moderator.
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Manage the signing key.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Print the canonical bytes of a fact (what its signature covers).
    Canonical { fact: PathBuf },
    /// Sign a fact JSON file with the key.
    Sign {
        fact: PathBuf,
        /// Write to the outbox instead of stdout.
        #[arg(long)]
        queue: bool,
    },
    /// Verify facts (JSON or JSONL).
    Verify { path: PathBuf },
    /// Moderators: block a key, fact, manual or host. Its facts stop counting at
    /// the next build, and a blocked key can't add facts. Sent right away.
    Block {
        #[arg(value_enum)]
        kind: moderate::Kind,
        /// Fingerprint, fact id, manual id or host; a link to its page works too.
        value: String,
        /// Why (kept in the ledger with the block).
        #[arg(long)]
        reason: String,
        #[command(flatten)]
        send: SendOpts,
    },
    /// Moderators: undo a block.
    Unblock {
        #[arg(value_enum)]
        kind: moderate::Kind,
        value: String,
        #[arg(long, default_value = "unblocked")]
        reason: String,
        #[command(flatten)]
        send: SendOpts,
    },
    /// Push the outbox and pull the feed from a server.
    Sync {
        #[arg(long, env = "OM_SERVER", default_value = "http://localhost:8000")]
        server: String,
        /// Only push, don't pull.
        #[arg(long)]
        push_only: bool,
        /// Re-download the snapshot when more than this many facts behind.
        #[arg(long, default_value = "50000")]
        snapshot_threshold: usize,
    },
    /// Build manuals.db from a ledger directory.
    Build {
        #[arg(long, default_value = "ledger")]
        ledger: PathBuf,
        #[arg(long, default_value = "manuals.db")]
        out: PathBuf,
        #[arg(long)]
        trust: Option<PathBuf>,
        #[arg(long)]
        verify: bool,
        /// Resume from this checkpoint if it is still valid, and refresh it.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
    },
    /// Record a copy of a known file at a URL.
    AddLocation {
        /// sha256 hex, `sha1:<hex>`, or a local file to hash.
        #[arg(long)]
        file: String,
        #[arg(long)]
        url: String,
        #[arg(long, default_value = "mirror")]
        kind: String,
        #[arg(long)]
        ia_identifier: Option<String>,
        #[arg(long)]
        ia_filename: Option<String>,
        /// Also attach the file to this manual.
        #[arg(long)]
        manual: Option<String>,
    },
    /// Record a derived variant (e.g. watermark-stripped) of a known file.
    AddVariant {
        /// sha256 hex (or sha1:<hex>) of the source file.
        #[arg(long)]
        source: String,
        path: PathBuf,
        #[arg(long, default_value = "watermark-stripped")]
        transform: String,
        #[arg(long, default_value = "openmanuals-cli")]
        tool: String,
        #[arg(long, default_value = "om-cli/1")]
        tool_version: String,
        #[arg(long)]
        manual: Option<String>,
    },
    /// Upload a file somewhere and record it.
    Upload {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "ia")]
        target: upload::Target,
        #[arg(long)]
        manual: Option<String>,
        #[arg(long)]
        title: Option<String>,
        /// Origin URL recorded in the item metadata (source).
        #[arg(long)]
        source_url: Option<String>,
        /// Strip watermarks from a PDF first (as the extension does); uploads
        /// the stripped file when anything was removed and records both.
        #[arg(long)]
        strip: bool,
        #[command(flatten)]
        opts: upload::TargetOpts,
    },
    /// Convert a salli-cat manuals.db into signed facts (read-only on the source).
    MigrateSalliCat {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Compute sha256 for files present under this directory (slow).
        #[arg(long)]
        hash_local: bool,
        /// Emit `verified`/`location_status` facts for archive.org copies salli-cat checked.
        #[arg(long)]
        as_verified: bool,
        #[arg(long)]
        limit: Option<usize>,
        /// Only this source's rows (e.g. freeservicemanuals); no other source's facts are signed.
        #[arg(long)]
        source: Option<String>,
        /// The target ledger's snapshot (e.g. a copy of /db/latest.db): pages it
        /// already has a manual for are skipped, and its products aren't re-signed.
        #[arg(long)]
        known: Option<PathBuf>,
        /// Leave out rows salli-cat marked unavailable (no file at the source).
        #[arg(long)]
        skip_unavailable: bool,
    },
    /// One-time import of old-style archive.org items (manualslib-id-<n>) the
    /// ledger doesn't know, so the extension needn't ask archive.org live.
    /// Read-only on the snapshot and salli-cat's database; writes facts to --out.
    ImportIaLegacy {
        /// The current snapshot (what the ledger already knows).
        #[arg(long)]
        snapshot: PathBuf,
        /// salli-cat's manuals.db: its own re-checked uploads are imported as verified.
        #[arg(long)]
        salli_cat_db: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        /// Where item metadata is cached between runs.
        #[arg(long, default_value = "ia-legacy-cache")]
        cache: PathBuf,
        /// Concurrent metadata requests to archive.org.
        #[arg(long, default_value = "6")]
        jobs: usize,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, env = "OM_IA_API_BASE", default_value = "https://archive.org")]
        ia_api_base: String,
    },
    /// Find bootstrap files on archive.org that the current stripper would
    /// clean further (read-only on the source database). Writes a JSONL report.
    RestripScan {
        /// The bootstrap import's source database (opened read-only).
        #[arg(long)]
        db: PathBuf,
        /// Where the database's file paths live, if not at their recorded absolute paths.
        #[arg(long)]
        files_root: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, default_value_t = std::thread::available_parallelism().map_or(4, |n| n.get()))]
        jobs: usize,
        /// Only these items (IA identifier, ManualsLib id or manual ULID); repeatable.
        #[arg(long = "only")]
        only: Vec<String>,
    },
    /// Re-strip published files: replace each in its archive.org item (same
    /// filename), update the item's external-identifier, and queue the facts.
    Restrip {
        /// A report from `om restrip-scan`.
        #[arg(long, conflicts_with = "db")]
        from_report: Option<PathBuf>,
        /// Or examine these items directly in the source database.
        #[arg(long, requires = "item")]
        db: Option<PathBuf>,
        #[arg(long)]
        files_root: Option<PathBuf>,
        /// IA identifier, ManualsLib id or manual ULID (with --db); repeatable.
        #[arg(long)]
        item: Vec<String>,
        /// Show what would be replaced; upload nothing, queue nothing.
        #[arg(long)]
        dry_run: bool,
        /// Keep the replaced file in the item's history (x-archive-keep-old-version).
        #[arg(long)]
        keep_old_version: bool,
        /// Seconds between items (archive.org rate limits uploads).
        #[arg(long, default_value = "5")]
        interval: u64,
        /// For a single item whose source file isn't on disk: download it from here (checked by sha1).
        #[arg(long)]
        download_source: Option<String>,
        /// Ledger directory: retract this key's earlier location facts for the replaced files.
        #[arg(long)]
        ledger: Option<PathBuf>,
        #[arg(long, env = "IA_ACCESS_KEY")]
        ia_access: Option<String>,
        #[arg(long, env = "IA_SECRET_KEY")]
        ia_secret: Option<String>,
        #[arg(long, env = "OM_IA_S3_BASE", default_value = "https://s3.us.archive.org")]
        ia_s3_base: String,
        #[arg(long, env = "OM_IA_API_BASE", default_value = "https://archive.org")]
        ia_api_base: String,
    },
    /// Strip ManualsLib additions and third-party stamps from a PDF (openmanuals-strip).
    /// Writes the output either way (a copy when nothing was removed).
    Strip {
        input: PathBuf,
        output: PathBuf,
        /// Print what was removed.
        #[arg(long)]
        log: bool,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate a new key.
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Print the fingerprint and OpenSSH public key.
    Show,
    /// Print the private key (OpenSSH format) for backup.
    Export,
    /// Replace the key with an OpenSSH private key file.
    Import { file: PathBuf },
}

pub struct Home {
    pub dir: PathBuf,
}

impl Home {
    fn new(cli: &Option<PathBuf>) -> Result<Self> {
        let dir = match cli {
            Some(d) => d.clone(),
            None => std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/share")).join("openmanuals"),
        };
        std::fs::create_dir_all(dir.join("outbox"))?;
        std::fs::create_dir_all(dir.join("sent"))?;
        Ok(Home { dir })
    }
    fn key_path(&self) -> PathBuf {
        self.dir.join("key")
    }
    pub fn key(&self) -> Result<SigningKey> {
        keys::load(&self.key_path()).with_context(|| format!("no key at {} (run `om key init`)", self.key_path().display()))
    }
}

pub fn now() -> String {
    jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn hash_file(path: &std::path::Path) -> Result<(String, String, String, u64)> {
    use sha2::Digest;
    let mut f = std::fs::File::open(path).with_context(|| path.display().to_string())?;
    let (mut s256, mut s1, mut m5) = (sha2::Sha256::new(), sha1::Sha1::new(), md5::Md5::new());
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        s256.update(&buf[..n]);
        s1.update(&buf[..n]);
        m5.update(&buf[..n]);
    }
    Ok((hex::encode(s256.finalize()), hex::encode(s1.finalize()), hex::encode(m5.finalize()), size))
}

/// Facts for a local file: `file` plus optional `manual_file`.
pub fn file_facts(key: &SigningKey, path: &std::path::Path, manual: Option<&str>) -> Result<(String, Vec<Fact>)> {
    let (sha256, sha1, md5, size) = hash_file(path)?;
    let head = std::fs::read(path)?;
    let mime = openmanuals_core::sniff::sniff(&head[..head.len().min(16)]).map(|t| t.mime()).unwrap_or("application/octet-stream");
    let mut out = vec![sign(key, "file", json!({"sha256": sha256, "sha1": sha1, "md5": md5, "size": size, "mime": mime}))?];
    if let Some(m) = manual {
        out.push(sign(key, "manual_file", json!({"manual": m.to_ascii_uppercase(), "file": sha256, "role": "primary"}))?);
    }
    Ok((sha256, out))
}

pub fn sign(key: &SigningKey, t: &str, body: Value) -> Result<Fact> {
    let mut f = Fact::new(t, "x", &now(), body);
    key.sign_fact(&mut f).map_err(|e| anyhow!("{e}"))?;
    Ok(f)
}

fn read_facts(path: &std::path::Path) -> Result<Vec<Fact>> {
    let text = std::fs::read_to_string(path)?;
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') {
        let v: Vec<Value> = serde_json::from_str(trimmed)?;
        return v.into_iter().map(|v| Ok(serde_json::from_value(v)?)).collect();
    }
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line)?;
        // Ledger/feed entries wrap the fact.
        let f = if let Some(f) = v.get("fact") { f.clone() } else { v };
        out.push(serde_json::from_value(f)?);
    }
    Ok(out)
}

fn file_ref(s: &str) -> Result<String> {
    if let Some(id) = openmanuals_ledger::model::parse_file_ref(s) {
        return Ok(id);
    }
    let p = PathBuf::from(s);
    if p.exists() {
        return Ok(hash_file(&p)?.0);
    }
    bail!("--file must be a sha256, sha1:<hex>, or an existing file")
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let home = Home::new(&cli.home)?;
    let is_block = matches!(cli.cmd, Cmd::Block { .. });
    match cli.cmd {
        Cmd::Key { cmd } => match cmd {
            KeyCmd::Init { force } => {
                let alg = Alg::Ed25519;
                if home.key_path().exists() && !force {
                    bail!("{} exists; use --force to replace it", home.key_path().display());
                }
                let k = SigningKey::generate(alg);
                keys::save(&home.key_path(), &k)?;
                println!("{}\n{}", k.public_key().fingerprint(), k.public_key().to_openssh());
            }
            KeyCmd::Show => {
                let k = home.key()?;
                println!("{}\n{}", k.public_key().fingerprint(), k.public_key().to_openssh());
            }
            KeyCmd::Export => print!("{}", home.key()?.to_openssh("openmanuals").map_err(|e| anyhow!("{e}"))?),
            KeyCmd::Import { file } => {
                let k = keys::load(&file)?;
                keys::save(&home.key_path(), &k)?;
                println!("{}", k.public_key().fingerprint());
            }
        },
        Cmd::Canonical { fact } => {
            let f = Fact::from_json(&std::fs::read_to_string(fact)?)?;
            print!("{}", f.canonical()?);
        }
        Cmd::Sign { fact, queue } => {
            let mut f = Fact::from_json(&std::fs::read_to_string(&fact)?)?;
            if f.at.is_empty() {
                f.at = now();
            }
            home.key()?.sign_fact(&mut f)?;
            if queue {
                let p = outbox::queue(&home, &[f])?;
                eprintln!("queued in {}", p.display());
            } else {
                println!("{}", f.to_json());
            }
        }
        Cmd::Verify { path } => {
            let facts = read_facts(&path)?;
            use rayon::prelude::*;
            let results: Vec<_> = facts.par_iter().map(|f| f.verify()).collect();
            let mut bad = 0;
            for (i, (f, r)) in facts.iter().zip(results).enumerate() {
                match r {
                    Ok(()) => println!("ok   {} {} {}", f.id()?, f.r#type, f.author),
                    Err(e) => {
                        bad += 1;
                        println!("FAIL #{i} {e}");
                    }
                }
            }
            if bad > 0 {
                bail!("{bad} of {} facts failed", facts.len());
            }
        }
        Cmd::Block { kind, value, reason, send } | Cmd::Unblock { kind, value, reason, send } => {
            let block = is_block;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(moderate::run(&home, moderate::Request { block, kind, value: &value, reason: &reason, server: &send.server, queue_only: send.queue_only, force: send.force }))?;
        }
        Cmd::ImportIaLegacy { snapshot, salli_cat_db, out, cache, jobs, limit, ia_api_base } => {
            let key = home.key()?;
            let rt = tokio::runtime::Runtime::new()?;
            let st = rt.block_on(import_ia::run(&key, &import_ia::Options { snapshot, salli_cat_db, out: out.clone(), cache, jobs, limit, ia_api_base }))?;
            println!("{st:#?}");
            println!("wrote {} facts to {}; ingest them with `openmanuals-server import {}`", st.facts, out.display(), out.display());
        }
        Cmd::Sync { server, push_only, snapshot_threshold } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(sync::run(&home, &server, push_only, snapshot_threshold))?;
        }
        Cmd::Build { ledger, out, trust, verify, checkpoint } => {
            let l = openmanuals_ledger::Ledger::open(&ledger)?;
            let cfg = match trust.or_else(|| Some(ledger.join("build.toml")).filter(|p| p.exists())) {
                Some(p) => openmanuals_ledger::TrustConfig::load(&p)?,
                None => openmanuals_ledger::TrustConfig::default(),
            };
            let stats = openmanuals_ledger::build(&l, &cfg, &out, &openmanuals_ledger::BuildOptions { verify_signatures: verify, checkpoint })?;
            println!("{stats:?}");
        }
        Cmd::AddLocation { file, url, kind, ia_identifier, ia_filename, manual } => {
            let key = home.key()?;
            let id = file_ref(&file)?;
            let mut body = json!({"file": id, "url": url, "kind": kind});
            if let Some(i) = ia_identifier {
                body["ia"] = json!({"identifier": i, "filename": ia_filename});
            }
            let mut facts = vec![sign(&key, "location", body)?];
            if let Some(m) = manual {
                facts.push(sign(&key, "manual_file", json!({"manual": m.to_ascii_uppercase(), "file": id, "role": "primary"}))?);
            }
            let p = outbox::queue(&home, &facts)?;
            println!("queued {} facts in {}", facts.len(), p.display());
        }
        Cmd::AddVariant { source, path, transform, tool, tool_version, manual } => {
            let key = home.key()?;
            let source = openmanuals_ledger::model::parse_file_ref(&source).ok_or_else(|| anyhow!("--source must be a sha256 or sha1:<hex>"))?;
            let (sha256, mut facts) = file_facts(&key, &path, manual.as_deref())?;
            facts.push(sign(&key, "derivation", json!({"derived": sha256, "source": source, "transform": transform, "tool": tool, "tool_version": tool_version}))?);
            let p = outbox::queue(&home, &facts)?;
            println!("queued {} facts in {} (file {sha256})", facts.len(), p.display());
        }
        Cmd::Upload { path, target, manual, title, source_url, strip, opts } => {
            let key = home.key()?;
            let rt = tokio::runtime::Runtime::new()?;
            let facts = rt.block_on(upload::run(&key, &path, target, manual.as_deref(), title.as_deref(), source_url.as_deref(), strip, &opts))?;
            let p = outbox::queue(&home, &facts)?;
            println!("queued {} facts in {}", facts.len(), p.display());
        }
        Cmd::MigrateSalliCat { db, out, hash_local, as_verified, limit, source, known, skip_unavailable } => {
            let key = home.key()?;
            let out = out.unwrap_or_else(|| home.dir.join("outbox").join(format!("{}-salli-cat.jsonl", ulid::Ulid::new())));
            let opts = migrate::Options { hash_local, as_verified, limit, source, known, skip_unavailable };
            let stats = migrate::run(&key, &db, &out, &opts)?;
            println!("{stats:#?}\nwrote {}", out.display());
        }
        Cmd::RestripScan { db, files_root, out, limit, jobs, only } => {
            let stats = restrip::scan(&db, files_root.as_deref(), &out, limit, jobs, &only)?;
            println!("{}\nwrote {}", serde_json::to_string_pretty(&stats)?, out.display());
        }
        Cmd::Restrip { from_report, db, files_root, item, dry_run, keep_old_version, interval, download_source, ledger, ia_access, ia_secret, ia_s3_base, ia_api_base } => {
            let findings = match (from_report, db) {
                (Some(r), _) => restrip::read_report(&r)?,
                (None, Some(db)) => {
                    let mut out = Vec::new();
                    for c in restrip::candidates(&db, files_root.as_deref())?.iter().filter(|c| item.iter().any(|o| o == &c.identifier || o == &c.manualslib_id || o.eq_ignore_ascii_case(&c.manual))) {
                        match restrip::examine(c) {
                            restrip::Outcome::Restrip(f) => out.push(*f),
                            other => println!("{}: nothing to re-strip ({other:?})", c.identifier),
                        }
                    }
                    out
                }
                (None, None) => bail!("pass --from-report, or --db with --item"),
            };
            if download_source.is_some() && findings.len() > 1 {
                bail!("--download-source is for a single item");
            }
            let key = home.key()?;
            let (access, secret) = if dry_run {
                (String::new(), String::new())
            } else {
                upload::ia_keys_from(ia_access, ia_secret)?
            };
            let client = reqwest::Client::builder().user_agent(format!("openmanuals-cli/{}", env!("CARGO_PKG_VERSION"))).timeout(std::time::Duration::from_secs(3600)).build()?;
            let ia = restrip::Ia { client, s3_base: ia_s3_base, api_base: ia_api_base, access, secret };
            let opts = restrip::RestripOpts { dry_run, keep_old_version, interval: std::time::Duration::from_secs(interval), download: download_source, ledger };
            let rt = tokio::runtime::Runtime::new()?;
            let stats = rt.block_on(restrip::run(&home, &key, &ia, &findings, &opts))?;
            println!("{}", serde_json::to_string_pretty(&stats)?);
            if !dry_run && stats.replaced > 0 {
                println!("run `om sync --push-only` to send the facts");
            }
        }
        Cmd::Strip { input, output, log } => {
            let bytes = std::fs::read(&input).with_context(|| input.display().to_string())?;
            let r = openmanuals_strip::strip(&bytes).with_context(|| input.display().to_string())?;
            std::fs::write(&output, &r.bytes).with_context(|| output.display().to_string())?;
            if log {
                for l in &r.log {
                    println!("{l}");
                }
            }
            println!("{} ({})", if r.changed { "stripped" } else { "unchanged" }, openmanuals_strip::STRIP_VERSION);
        }
    }
    Ok(())
}
