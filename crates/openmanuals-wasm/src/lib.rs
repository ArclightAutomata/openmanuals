//! JS bindings of openmanuals-core. Everything takes and returns JSON strings or plain
//! values so the glue stays small; errors become thrown JS `Error`s.
use openmanuals_core::{asp, canon, ids, product, sniff, Fact, PublicKey};
use wasm_bindgen::prelude::*;

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from(js_sys::Error::new(&e.to_string()))
}

/// RFC 8785 canonical form of any JSON text.
#[wasm_bindgen]
pub fn canonical_json(json: &str) -> Result<String, JsValue> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(js_err)?;
    canon::canonical_json(&v).map_err(js_err)
}

/// Canonical form of a fact envelope (sig ignored), after shape validation.
#[wasm_bindgen]
pub fn fact_canonical(fact_json: &str) -> Result<String, JsValue> {
    let f = Fact::from_json(fact_json).map_err(js_err)?;
    f.validate_shape().map_err(js_err)?;
    f.canonical().map_err(js_err)
}

/// `sha256:<hex>` id of a fact envelope.
#[wasm_bindgen]
pub fn fact_id(fact_json: &str) -> Result<String, JsValue> {
    Fact::from_json(fact_json).map_err(js_err)?.id().map_err(js_err)
}

/// Full verification of a signed fact: shape, key/author match, signature. Returns the fact id.
#[wasm_bindgen]
pub fn verify_fact(fact_json: &str) -> Result<String, JsValue> {
    let f = Fact::from_json(fact_json).map_err(js_err)?;
    f.verify().map_err(js_err)?;
    f.id().map_err(js_err)
}

/// Ariadne fingerprint of a public JWK (JSON text).
#[wasm_bindgen]
pub fn fingerprint(jwk_json: &str) -> Result<String, JsValue> {
    let v: serde_json::Value = serde_json::from_str(jwk_json).map_err(js_err)?;
    Ok(PublicKey::from_jwk(&v).map_err(js_err)?.fingerprint())
}

/// Parse and verify an Ariadne Signature Profile; returns JSON `{fingerprint,name,claims,description,avatar_url,email,exp}`.
#[wasm_bindgen]
pub fn verify_profile(jws: &str) -> Result<String, JsValue> {
    let p = asp::parse_and_verify(jws).map_err(js_err)?;
    Ok(serde_json::json!({
        "fingerprint": p.fingerprint, "name": p.name, "claims": p.claims,
        "description": p.description, "avatar_url": p.avatar_url, "email": p.email, "exp": p.exp,
    })
    .to_string())
}

#[wasm_bindgen]
pub fn aspe_uri(domain: &str, fingerprint: &str) -> String {
    asp::aspe_uri(domain, fingerprint)
}

/// JSON `{source, source_id, kind, slug, candidates}` for a supported page URL, else undefined.
#[wasm_bindgen]
pub fn parse_page_url(url: &str) -> Option<String> {
    ids::parse_page_url(url).map(|p| {
        serde_json::json!({
            "source": p.source, "source_id": p.source_id, "kind": p.kind, "slug": p.slug,
            "candidates": ids::candidate_identifiers(&p),
        })
        .to_string()
    })
}

#[wasm_bindgen]
pub fn legacy_identifier(source: &str, source_id: &str) -> Option<String> {
    ids::legacy_identifier(source, source_id)
}

#[wasm_bindgen]
pub fn upload_identifier(sha256_hex: &str, ulid: &str) -> Result<String, JsValue> {
    ids::upload_identifier(sha256_hex, ulid).map_err(js_err)
}

#[wasm_bindgen]
pub fn is_valid_identifier(id: &str) -> bool {
    ids::is_valid_identifier(id)
}

#[wasm_bindgen]
pub fn product_key(brand: &str, model: &str) -> Option<String> {
    product::product_key(brand, model)
}

/// "pdf" | "djvu" | "zip" | null. A zip is a document only if `zip_documents` accepts it.
#[wasm_bindgen]
pub fn sniff(bytes: &[u8]) -> Option<String> {
    sniff::sniff(bytes).map(|t| t.extension().to_string())
}

/// The documents in a zip, as JSON `[{"name", "size", "type"}]`; throws why
/// the zip isn't only PDF and DjVu files.
#[wasm_bindgen]
pub fn zip_documents(bytes: &[u8]) -> Result<String, JsValue> {
    let m = openmanuals_core::container::zip_documents(std::io::Cursor::new(bytes)).map_err(js_err)?;
    let v: Vec<serde_json::Value> = m.iter().map(|d| serde_json::json!({"name": d.name, "size": d.size, "type": d.file_type.extension()})).collect();
    Ok(serde_json::Value::Array(v).to_string())
}

#[wasm_bindgen]
pub fn sha256_hex(bytes: &[u8]) -> String {
    canon::sha256_hex(bytes)
}
#[wasm_bindgen]
pub fn sha1_hex(bytes: &[u8]) -> String {
    canon::sha1_hex(bytes)
}
#[wasm_bindgen]
pub fn md5_hex(bytes: &[u8]) -> String {
    canon::md5_hex(bytes)
}

/// Lookup-filter keys for a page URL (`src:<source>:<id>` / `url:<url>`).
#[wasm_bindgen]
pub fn page_keys(url: &str) -> Vec<String> {
    ids::page_keys(url)
}

/// A parsed lookup filter (`/db/lookup-filter.bin`): parse once, query often.
#[wasm_bindgen]
pub struct LookupFilter(openmanuals_core::filter::Filter);

#[wasm_bindgen]
impl LookupFilter {
    /// Throws on malformed, truncated or unsupported-version bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<LookupFilter, JsValue> {
        openmanuals_core::filter::Filter::from_bytes(bytes).map(LookupFilter).map_err(js_err)
    }
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains(key)
    }
    /// Whether any of the page's keys is in the filter (false: certainly unknown).
    pub fn contains_page(&self, url: &str) -> bool {
        self.0.contains_page(url)
    }
    #[wasm_bindgen(getter)]
    pub fn key_count(&self) -> u32 {
        self.0.key_count()
    }
}

/// Serialized lookup filter over `keys` (the server builds the real one; used by tests).
#[wasm_bindgen]
pub fn build_lookup_filter(keys: Vec<String>) -> Result<Vec<u8>, JsValue> {
    openmanuals_core::filter::build(&keys).map_err(js_err)
}
