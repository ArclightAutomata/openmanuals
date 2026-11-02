//! The OpenManuals fact format.
//!
//! Everything that the server, the CLI and the browser extension (through
//! WebAssembly) must agree on byte for byte lives here: canonical JSON, fact
//! ids, key fingerprints, signature verification, archive.org identifiers and
//! product keys. The crate is I/O free so it builds for `wasm32-unknown-unknown`.
//! Signing is behind the `sign` feature because the extension signs with
//! WebCrypto and only verifies here.

pub mod asp;
pub mod avatar;
pub mod canon;
pub mod fact;
pub mod filter;
pub mod ids;
pub mod jws;
pub mod key;
pub mod product;
pub mod sniff;

#[cfg(feature = "sign")]
pub mod sign;

pub use fact::{Fact, Sig, SigFmt, FACT_VERSION, MAX_FACT_BYTES};
pub use key::{Alg, PublicKey};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonicalization failed: {0}")]
    Canon(String),
    #[error("invalid key: {0}")]
    Key(String),
    #[error("invalid signature: {0}")]
    Signature(String),
    #[error("invalid fact: {0}")]
    Fact(String),
    #[error("invalid profile: {0}")]
    Profile(String),
    #[error("invalid identifier: {0}")]
    Identifier(String),
}

pub type Result<T> = core::result::Result<T, Error>;

pub(crate) mod b64 {
    use base64::Engine;
    pub fn encode(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
    }
}
