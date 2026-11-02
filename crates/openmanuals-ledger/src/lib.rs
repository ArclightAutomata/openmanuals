//! The ledger (append-only JSONL under `ledger/YYYY/MM/DD.jsonl`) and the
//! deterministic build of `manuals.db` from it.

pub mod build;
pub mod checkpoint;
pub mod compact;
pub mod config;
pub mod filter;
pub mod index;
pub mod ledger;
pub mod model;
pub mod snapshot;
pub mod view;

pub use build::{build, build_resident, build_with, BuildMode, BuildOptions, BuildStats, Resident, Tuning};
pub use config::TrustConfig;
pub use ledger::{Entry, Ledger};
