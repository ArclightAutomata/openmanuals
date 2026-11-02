//! Product keys: one key per (brand, model) however people spell them.
//!
//! The key is `<brand>|<MODEL>` where the brand is lowercased with whitespace
//! collapsed and the model is uppercased with whitespace and separators
//! (`-`, `_`, `/`, `.`, spaces) removed, so `JVC AV-2168TEE`, `jvc av2168tee`
//! and `Jvc AV 2168/TEE` all key the same product. Display forms are kept on
//! the facts; the key only decides identity.

pub fn normalize_brand(brand: &str) -> String {
    let mut out = String::with_capacity(brand.len());
    let mut space = false;
    for c in brand.trim().chars() {
        if c.is_whitespace() {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.extend(c.to_lowercase());
    }
    out
}

pub fn normalize_model(model: &str) -> String {
    model
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '_' | '/' | '.' | ',' | '(' | ')'))
        .flat_map(char::to_uppercase)
        .collect()
}

/// `<brand>|<MODEL>`, or `None` when either part is empty after normalization.
pub fn product_key(brand: &str, model: &str) -> Option<String> {
    let b = normalize_brand(brand);
    let m = normalize_model(model);
    (!b.is_empty() && !m.is_empty()).then(|| format!("{b}|{m}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_collapse() {
        let k = product_key("JVC", "AV-2168TEE").unwrap();
        assert_eq!(k, "jvc|AV2168TEE");
        assert_eq!(product_key(" jvc ", "av 2168/tee").unwrap(), k);
        assert_eq!(product_key("Harman  Kardon", "AVR_20.II").unwrap(), "harman kardon|AVR20II");
        assert!(product_key("", "x").is_none());
        assert!(product_key("Sony", " - ").is_none());
    }
}
