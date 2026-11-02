//! openmanuals-server: the OpenManuals server. See "The server" in README.md.

pub mod activity;
pub mod api;
pub mod avatar;
pub mod config;
pub mod contribute;
pub mod fold;
pub mod inbox;
pub mod keyoxide;
pub mod keywrap;
pub mod pages;
pub mod publish;
pub mod rate;
pub mod scan;
pub mod schedule;
pub mod verify;

pub use config::{Paths, Shared, State};

use axum::{routing::get, routing::post, routing::put, Router};
use clap::{Parser, Subcommand};
use tower_http::cors::{Any, CorsLayer};

#[derive(Parser)]
#[command(name = "openmanuals-server", version, about = "OpenManuals server")]
pub struct Cli {
    #[command(flatten)]
    pub paths: Paths,
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Serve the API and pages (default).
    Serve {
        #[arg(long, env = "OM_BIND", default_value = "127.0.0.1:8000")]
        bind: String,
        /// Fold at least every this many seconds, facts or not (0 disables).
        #[arg(long, env = "OM_FOLD_INTERVAL", default_value = "3600")]
        fold_interval: u64,
        /// Fold this many seconds after the last accepted batch of facts
        /// (0 disables folding on demand; the interval still applies).
        #[arg(long, env = "OM_FOLD_DEBOUNCE", default_value = "5")]
        fold_debounce: u64,
        /// ...but no later than this many seconds after the first unfolded one.
        #[arg(long, env = "OM_FOLD_MAX_DELAY", default_value = "60")]
        fold_max_delay: u64,
        /// Seconds between verifier passes (0 disables).
        #[arg(long, env = "OM_VERIFY_INTERVAL", default_value = "900")]
        verify_interval: u64,
    },
    /// Fold the inbox into the ledger repo, commit, and rebuild the snapshot.
    Fold,
    /// Rebuild the snapshot from the ledger.
    Build {
        /// Re-check every signature while building (reads the whole ledger).
        #[arg(long)]
        verify: bool,
        /// Ignore the checkpoint and rebuild from the start of the ledger.
        #[arg(long)]
        full: bool,
    },
    /// Run one verifier pass (copies and identity proofs).
    Verify {
        #[arg(long, default_value = "200")]
        max_locations: usize,
    },
    /// Print the server key's fingerprint and public key.
    Whoami,
    /// Ingest a JSONL/JSON file of signed facts directly (no rate limits).
    Import {
        path: std::path::PathBuf,
    },
}

pub fn router(state: Shared) -> Router {
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let api = Router::new()
        .route("/api/facts", post(api::post_facts))
        .route("/api/feed", get(api::feed))
        .route("/api/fact/{id}", get(activity::fact_json))
        .route("/api/lookup", get(api::lookup))
        .route("/api/server", get(api::server_info))
        .route("/db/latest.db", get(api::latest_db))
        .route("/db/latest.db.sha256", get(api::latest_sha))
        .route("/db/latest.db.sig", get(api::latest_sig))
        .route("/db/latest.db.zst", get(api::latest_zst))
        .route("/db/lookup-filter.bin", get(api::lookup_filter))
        .route("/db/manifest.json", get(api::manifest))
        .route("/db/manifest.json.sig", get(api::manifest_sig))
        .route("/db/diff/{name}", get(api::diff_file))
        .route("/db/{name}", get(api::snapshot_file))
        .route("/.well-known/aspe/id/{fp}", get(api::aspe_profile))
        .route("/.well-known/aspe/version", get(api::aspe_version))
        .route("/api/key/{fp}", get(keyoxide::key_json))
        .route("/api/key/{fp}/stats", get(keyoxide::key_stats))
        .route("/api/key-wrap/{fp}", get(keywrap::get_wraps))
        .route("/api/key-wrap/{fp}/{credential}", put(keywrap::put_wrap).delete(keywrap::delete_wrap))
        .route("/api/avatar/{sha256}", put(avatar::put))
        .route("/avatar/{fp}", get(avatar::get))
        .route("/.well-known/nodeinfo", get(keyoxide::nodeinfo_links))
        .route("/nodeinfo/2.1", get(keyoxide::nodeinfo))
        .layer(cors);
    Router::new()
        .merge(api)
        .route("/", get(activity::home))
        .route("/ledger", get(activity::ledger))
        .route("/fact/{id}", get(activity::fact))
        .route("/manuals", get(pages::manuals))
        .route("/manual/{id}", get(pages::manual))
        .route("/product/{brand}/{model}", get(pages::product))
        .route("/file/{id}", get(pages::file))
        .route("/k/{fp}", get(pages::key))
        .route("/item/{identifier}", get(pages::item))
        .route("/contributions", get(pages::contributions))
        .route("/about", get(pages::about))
        .route("/privacy", get(pages::privacy))
        .route("/contribute", get(pages::contribute))
        .route("/contribute/random", get(pages::contribute_random))
        .route("/lookup", get(pages::lookup_redirect))
        .route("/static/style.css", get(pages::style))
        .route("/static/logo.svg", get(pages::logo))
        .route("/static/theme.js", get(pages::theme_js))
        .route("/favicon.svg", get(pages::logo))
        .layer(axum::extract::DefaultBodyLimit::max(api::MAX_BODY + 1024))
        .with_state(state)
}

