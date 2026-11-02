//! Generate `vectors/vectors.json`, the cross-language test vectors shared with
//! the TypeScript extension. Run with:
//!   cargo run -p openmanuals-core --features sign --example gen_vectors > vectors/vectors.json
use openmanuals_core::{asp, canon, ids, product, sign::SigningKey, Alg, Fact};
use serde_json::{json, Value};

fn main() {
    let mut keys = Vec::new();
    let mut facts = Vec::new();
    for (alg, seed_byte) in [(Alg::Ed25519, 0x11u8)] {
        let k = SigningKey::from_seed(alg, &[seed_byte; 32]).unwrap();
        let pk = k.public_key();
        keys.push(json!({
            "alg": alg, "seed_hex": hex::encode(k.seed()), "jwk": pk.to_jwk(),
            "fingerprint": pk.fingerprint(), "openssh": pk.to_openssh().trim(),
        }));
        let mut f = Fact::new("file", "x", "2026-10-23T18:00:00Z", json!({
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "md5": "098f6bcd4621d373cade4e832627b4f6",
            "size": 4, "mime": "application/pdf", "note": "unicode: é ü 漢 \u{1F600}", "nested": {"z": [1, 2.5, false, null], "a": "b"}
        }));
        k.sign_fact(&mut f).unwrap();
        // Ed25519 is deterministic, so the vector is reproducible.
        facts.push(json!({"alg": alg, "canonical": f.canonical().unwrap(), "id": f.id().unwrap(), "fact": serde_json::from_str::<Value>(&f.to_json()).unwrap()}));
    }
    let ed = SigningKey::from_seed(Alg::Ed25519, &[0x11; 32]).unwrap();
    let profile = ed.sign_profile("Vector Person", &["https://gist.github.com/example/abc123".into(), "dns:example.org?type=TXT".into()], Some("desc"));
    let parsed = asp::parse_and_verify(&profile).unwrap();

    let pages: Vec<Value> = [
        "https://www.manualslib.com/manual/331384/Jvc-Av-2168tee.html?x=1",
        "http://manualslib.com/download/331384/Jvc-Av-2168tee.html",
        "https://elektrotanya.com/sony_kv-1400%2Csm.pdf/download.html#dl",
        "https://manualslib.com/brand/jvc/",
        "https://example.com/manual/1/x",
    ]
    .iter()
    .map(|u| json!({"url": u, "page": ids::parse_page_url(u).map(|p| json!({"source": p.source, "source_id": p.source_id, "kind": p.kind, "slug": p.slug, "candidates": ids::candidate_identifiers(&p)}))}))
    .collect();
    let products: Vec<Value> = [("JVC", "AV-2168TEE"), (" jvc ", "av 2168/tee"), ("Harman  Kardon", "AVR_20.II"), ("", "x"), ("Sony", " - ")]
        .iter()
        .map(|(b, m)| json!({"brand": b, "model": m, "key": product::product_key(b, m)}))
        .collect();
    let out = json!({
        "description": "OpenManuals openmanuals-core test vectors. Every implementation must reproduce these byte for byte.",
        "keys": keys,
        "facts": facts,
        "profile": {"jws": profile, "fingerprint": parsed.fingerprint, "name": parsed.name, "claims": parsed.claims,
                    "aspe": asp::aspe_uri("openmanuals.org", &parsed.fingerprint)},
        "asp_spec_example": {"jwk": {"kty": "OKP", "use": "sig", "crv": "Ed25519", "x": "__poSQwNedopfLKP3ZgM6FXz9LIJszDZh5wKcoQF71U"}, "fingerprint": "QPRGVPJNWDXH4ESK2RYDTZJLTE"},
        "canonical": [
            {"input": {"b": 1.0, "a": [true, null, "é"], "c": {"z": 1e3, "y": 0.1}}, "output": canon::canonical_json(&json!({"b": 1.0, "a": [true, null, "é"], "c": {"z": 1e3, "y": 0.1}})).unwrap()},
            {"input": {"\u{20ac}": "\u{1F600}", "a\u{0000}": 1e21, "n": -0.0}, "output": canon::canonical_json(&json!({"\u{20ac}": "\u{1F600}", "a\u{0000}": 1e21, "n": -0.0})).unwrap()}
        ],
        "identifiers": {
            "legacy": [
                {"source": "manualslib", "source_id": "331384", "identifier": ids::legacy_identifier("manualslib", "331384")},
                {"source": "elektrotanya", "source_id": "sony_kv-1400_sm.pdf", "identifier": ids::legacy_identifier("elektrotanya", "sony_kv-1400_sm.pdf")},
                {"source": "elektrotanya", "source_id": "sony_kv-1400,sm (ü).pdf", "identifier": ids::legacy_identifier("elektrotanya", "sony_kv-1400,sm (ü).pdf")},
                {"source": "elektrotanya", "source_id": "x".repeat(200), "identifier": ids::legacy_identifier("elektrotanya", &"x".repeat(200))},
                {"source": "other", "source_id": "1", "identifier": null}
            ],
            "upload": [{"sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "ulid": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "identifier": ids::upload_identifier("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()}],
            "pages": pages,
        },
        "products": products,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
