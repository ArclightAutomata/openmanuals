//! The shared test vectors in `vectors/vectors.json` must hold for every implementation.
use openmanuals_core::{asp, canon, ids, product, Fact, PublicKey};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/vectors.json")).unwrap()
}

#[test]
fn keys_and_fingerprints() {
    for k in vectors()["keys"].as_array().unwrap() {
        let pk = PublicKey::from_jwk(&k["jwk"]).unwrap();
        assert_eq!(pk.fingerprint(), k["fingerprint"].as_str().unwrap());
        assert_eq!(PublicKey::from_openssh(k["openssh"].as_str().unwrap()).unwrap(), pk);
    }
    let ex = &vectors()["asp_spec_example"];
    assert_eq!(PublicKey::from_jwk(&ex["jwk"]).unwrap().fingerprint(), ex["fingerprint"].as_str().unwrap());
}

#[test]
fn signed_facts_verify_and_ids_match() {
    let v = vectors();
    let all: Vec<&Value> = v["facts"].as_array().unwrap().iter().collect();
    for entry in all {
        let fact = Fact::from_json(&entry["fact"].to_string()).unwrap();
        fact.verify().unwrap();
        assert_eq!(fact.canonical().unwrap(), entry["canonical"].as_str().unwrap());
        assert_eq!(fact.id().unwrap(), entry["id"].as_str().unwrap());
        let mut tampered = fact.clone();
        tampered.at = "2026-10-23T18:00:01Z".into();
        assert!(tampered.verify().is_err());
    }
}

#[test]
fn profile_verifies() {
    let p = &vectors()["profile"];
    let parsed = asp::parse_and_verify(p["jws"].as_str().unwrap()).unwrap();
    assert_eq!(parsed.fingerprint, p["fingerprint"].as_str().unwrap());
    assert_eq!(parsed.name, p["name"].as_str().unwrap());
    assert_eq!(serde_json::to_value(&parsed.claims).unwrap(), p["claims"]);
    assert_eq!(asp::aspe_uri("openmanuals.org", &parsed.fingerprint), p["aspe"].as_str().unwrap());
}

#[test]
fn canonical_json() {
    for c in vectors()["canonical"].as_array().unwrap() {
        assert_eq!(canon::canonical_json(&c["input"]).unwrap(), c["output"].as_str().unwrap());
    }
}

#[test]
fn identifiers_and_pages() {
    let v = vectors();
    for l in v["identifiers"]["legacy"].as_array().unwrap() {
        assert_eq!(serde_json::to_value(ids::legacy_identifier(l["source"].as_str().unwrap(), l["source_id"].as_str().unwrap())).unwrap(), l["identifier"]);
    }
    for u in v["identifiers"]["upload"].as_array().unwrap() {
        assert_eq!(ids::upload_identifier(u["sha256"].as_str().unwrap(), u["ulid"].as_str().unwrap()).unwrap(), u["identifier"].as_str().unwrap());
    }
    for p in v["identifiers"]["pages"].as_array().unwrap() {
        let got = ids::parse_page_url(p["url"].as_str().unwrap()).map(|p| serde_json::json!({"source": p.source, "source_id": p.source_id, "kind": p.kind, "slug": p.slug, "candidates": ids::candidate_identifiers(&p)}));
        assert_eq!(serde_json::to_value(got).unwrap(), p["page"]);
    }
}

#[test]
fn product_keys() {
    for p in vectors()["products"].as_array().unwrap() {
        assert_eq!(serde_json::to_value(product::product_key(p["brand"].as_str().unwrap(), p["model"].as_str().unwrap())).unwrap(), p["key"]);
    }
}
