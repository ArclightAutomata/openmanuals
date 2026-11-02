//! RFC 8785 (JCS) canonical JSON.

use crate::{Error, Result};
use serde_json::Value;

/// Canonical (JCS) serialization of a JSON value.
pub fn canonical_json(value: &Value) -> Result<String> {
    serde_json_canonicalizer::to_string(value).map_err(|e| Error::Canon(e.to_string()))
}

/// Lowercase hex SHA-256 of some bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

pub fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::Digest;
    hex::encode(sha1::Sha1::digest(bytes))
}

pub fn md5_hex(bytes: &[u8]) -> String {
    use md5::Digest;
    hex::encode(md5::Md5::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_normalizes_numbers() {
        let v = json!({"b": 1.0, "a": [true, null, "é"], "c": {"z": 1e3, "y": 0.1}});
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":[true,null,"é"],"b":1,"c":{"y":0.1,"z":1000}}"#);
    }
}
