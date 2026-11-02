//! Borrowed views of ledger lines for the apply pass.
//!
//! Parsing every line into [`crate::ledger::Entry`] (an owned `openmanuals_core::Fact`
//! with a `serde_json::Value` body in an insertion-ordered map) costs a dozen
//! or more small allocations per fact, made on the parse threads and freed on
//! the applying thread. [`EntryView`] borrows from the line instead: envelope
//! strings are `Cow`s (borrowed unless they contain escapes), the body is a
//! small vector of borrowed key/value pairs, and the signing key is kept as
//! raw JSON text and parsed only when a key's JWK is first recorded.
//!
//! A view accepts and rejects exactly the lines `Entry` does: the same field
//! names, `deny_unknown_fields` where `Fact`/`Sig` have it, and every value
//! `Entry` would parse into a `serde_json::Value` is walked the same way
//! (strings unescaped, numbers parsed), so a line that fails to parse fails
//! either way. Field lookups follow `serde_json::Value` (`preserve_order`): a
//! repeated key's last value wins; `as_i64` semantics for numbers.

use crate::compact::{ulid_exact, FactId};
use openmanuals_core::{Alg, SigFmt};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::fmt;

#[derive(serde::Deserialize)]
pub struct EntryView<'a> {
    #[serde(borrow)]
    pub cursor: Cow<'a, str>,
    #[serde(borrow)]
    pub id: Cow<'a, str>,
    #[serde(borrow)]
    pub fact: FactView<'a>,
    /// Derived values, computed on the parse threads by [`EntryView::prepare`].
    #[serde(skip)]
    pub prep: Option<Prep>,
}

/// Values the resolver derives from every line, computed where the line is
/// parsed (in parallel) rather than where it is applied (in order).
#[derive(Debug, Default)]
pub struct Prep {
    pub fid: Option<FactId>,
    pub cursor: Option<u128>,
    pub shape_ok: bool,
    /// `product_key(brand, model)` of a `product` fact.
    pub product_key: Option<String>,
}

impl EntryView<'_> {
    pub fn prepare(&mut self) {
        let shape_ok = self.fact.shape_ok();
        let product_key = match (&*self.fact.r#type, self.fact.body.obj()) {
            ("product", Some(b)) if shape_ok => {
                let f = |k| b.as_str(k).map(str::trim).filter(|s| !s.is_empty());
                f("brand").zip(f("model")).and_then(|(b, m)| openmanuals_core::product::product_key(b, m))
            }
            _ => None,
        };
        self.prep = Some(Prep { fid: FactId::parse(&self.id), cursor: ulid_exact(&self.cursor), shape_ok, product_key });
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactView<'a> {
    pub v: u32,
    #[serde(rename = "type", borrow)]
    pub r#type: Cow<'a, str>,
    #[serde(borrow)]
    pub author: Cow<'a, str>,
    #[serde(borrow)]
    pub at: Cow<'a, str>,
    #[serde(borrow)]
    pub body: Body<'a>,
    #[serde(default, borrow)]
    pub sig: Option<SigView<'a>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigView<'a> {
    pub alg: Alg,
    #[allow(dead_code)]
    pub fmt: SigFmt,
    #[serde(borrow, deserialize_with = "checked_raw")]
    pub key: &'a RawValue,
    #[allow(dead_code)]
    #[serde(borrow)]
    pub value: Cow<'a, str>,
}

impl SigView<'_> {
    /// The JWK as `serde_json::Value::to_string` would print it.
    pub fn jwk_text(&self) -> String {
        serde_json::from_str::<serde_json::Value>(self.key.get()).map(|v| v.to_string()).unwrap_or_default()
    }
    /// `Alg`'s serialized name.
    pub fn alg_name(&self) -> &'static str {
        match self.alg {
            Alg::Ed25519 => "Ed25519",
        }
    }
}

/// A raw value that is also checked the way `serde_json::Value` would parse it.
fn checked_raw<'de, D: Deserializer<'de>>(d: D) -> Result<&'de RawValue, D::Error> {
    let raw = <&'de RawValue>::deserialize(d)?;
    serde_json::from_str::<Checked>(raw.get()).map_err(de::Error::custom)?;
    Ok(raw)
}

impl FactView<'_> {
    /// `openmanuals_core::Fact::validate_shape`, on the view.
    pub fn shape_ok(&self) -> bool {
        self.v == openmanuals_core::FACT_VERSION
            && valid_type(&self.r#type)
            && openmanuals_core::fact::valid_fingerprint(&self.author)
            && openmanuals_core::fact::valid_timestamp(&self.at)
            && matches!(self.body, Body::Object(_))
    }
}

fn valid_type(t: &str) -> bool {
    !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// A JSON object's members in document order.
#[derive(Debug, Default)]
pub struct Obj<'a>(pub Vec<(Cow<'a, str>, Val<'a>)>);

#[derive(Debug)]
pub enum Body<'a> {
    Object(Obj<'a>),
    /// Any other JSON value (the fact is then invalid).
    Other,
}

#[derive(Debug)]
pub enum Val<'a> {
    Str(Cow<'a, str>),
    /// A number; `Some` when `serde_json::Value::as_i64` would give one.
    Int(Option<i64>),
    Bool(bool),
    Arr(Vec<Val<'a>>),
    Obj(Obj<'a>),
    Other,
}

impl<'a> Obj<'a> {
    pub fn get(&self, k: &str) -> Option<&Val<'a>> {
        self.0.iter().rev().find(|(key, _)| key == k).map(|(_, v)| v)
    }
    pub fn as_str(&self, k: &str) -> Option<&str> {
        match self.get(k)? {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self, k: &str) -> Option<i64> {
        match self.get(k)? {
            Val::Int(i) => *i,
            _ => None,
        }
    }
    pub fn obj(&self, k: &str) -> Option<&Obj<'a>> {
        match self.get(k)? {
            Val::Obj(o) => Some(o),
            _ => None,
        }
    }
    pub fn as_bool(&self, k: &str) -> Option<bool> {
        match self.get(k)? {
            Val::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn arr(&self, k: &str) -> Option<&[Val<'a>]> {
        match self.get(k)? {
            Val::Arr(a) => Some(a),
            _ => None,
        }
    }
}

impl<'a> Body<'a> {
    pub fn obj(&self) -> Option<&Obj<'a>> {
        match self {
            Body::Object(o) => Some(o),
            Body::Other => None,
        }
    }
}

/// A map key, borrowed when it has no escapes.
struct Key<'a>(Cow<'a, str>);

impl<'de: 'a, 'a> Deserialize<'de> for Key<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a>(std::marker::PhantomData<&'a ()>);
        impl<'de: 'a, 'a> Visitor<'de> for V<'a> {
            type Value = Key<'a>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(Key(Cow::Borrowed(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Key(Cow::Owned(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(Key(Cow::Owned(v)))
            }
        }
        d.deserialize_str(V(std::marker::PhantomData))
    }
}

/// Members of an object, values parsed with `T`.
fn members<'de: 'a, 'a, A: MapAccess<'de>>(mut m: A) -> Result<Obj<'a>, A::Error> {
    let mut out = Vec::with_capacity(m.size_hint().unwrap_or(8));
    while let Some(Key(k)) = m.next_key::<Key<'a>>()? {
        let v: Val<'a> = m.next_value()?;
        out.push((k, v));
    }
    Ok(Obj(out))
}

impl<'de: 'a, 'a> Deserialize<'de> for Val<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a>(std::marker::PhantomData<&'a ()>);
        impl<'de: 'a, 'a> Visitor<'de> for V<'a> {
            type Value = Val<'a>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(Val::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(Val::Int(Some(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Val::Int(i64::try_from(v).ok()))
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(Val::Int(None))
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(Val::Str(Cow::Borrowed(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Val::Str(Cow::Owned(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(Val::Str(Cow::Owned(v)))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(Val::Other)
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(Val::Other)
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                Val::<'a>::deserialize(d)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(s.size_hint().unwrap_or(4));
                while let Some(v) = s.next_element::<Val<'a>>()? {
                    out.push(v);
                }
                Ok(Val::Arr(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, m: A) -> Result<Self::Value, A::Error> {
                members(m).map(Val::Obj)
            }
        }
        d.deserialize_any(V(std::marker::PhantomData))
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for Body<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Val::<'a>::deserialize(d)? {
            Val::Obj(o) => Body::Object(o),
            _ => Body::Other,
        })
    }
}

/// Walks any JSON value as `serde_json::Value` would parse it (unescaping
/// strings, parsing numbers), keeping nothing.
pub struct Checked;

impl<'de> Deserialize<'de> for Checked {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Checked;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E>(self, _: bool) -> Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_str<E>(self, _: &str) -> Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_unit<E>(self) -> Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_none<E>(self) -> Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Checked, D::Error> {
                Checked::deserialize(d)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Checked, A::Error> {
                while s.next_element::<Checked>()?.is_some() {}
                Ok(Checked)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Checked, A::Error> {
                while m.next_key::<Checked>()?.is_some() {
                    m.next_value::<Checked>()?;
                }
                Ok(Checked)
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Entry;

    /// Lines that parse as `Entry` parse as `EntryView` and vice versa, and
    /// lookups agree with `serde_json::Value`.
    #[test]
    fn views_agree_with_entries() {
        let good = [
            r#"{"cursor":"01ARZ3NDEKTSV4RRFFQ69G5FAV","id":"sha256:00","fact":{"v":1,"type":"file","author":"QPRGVPJNWDXH4ESK2RYDTZJLTE","at":"2026-10-23T18:00:00Z","body":{"sha256":"ab","size":10,"size":11,"n":-3,"f":1.5,"big":18446744073709551615,"ia":{"identifier":"xA","identifier":" y "},"arr":[1,{"a":null}],"t":true}}}"#,
            r#"{"cursor":"c","id":"i","extra":[1e5],"fact":{"v":1,"type":"x","author":"a","at":"t","body":[],"sig":null}}"#,
            r#"{"fact":{"sig":{"alg":"Ed25519","fmt":"raw","key":{"kty":"EC","x":"ab","n":[1,2.5]},"value":"v"},"v":1,"type":"x","author":"a","at":"t","body":"s"},"id":"i","cursor":"c"}"#,
        ];
        for line in good {
            let e: Entry = serde_json::from_str(line).unwrap();
            let v: EntryView = serde_json::from_str(line).unwrap();
            assert_eq!(e.cursor, v.cursor);
            assert_eq!(e.id, v.id);
            assert_eq!(e.fact.r#type, v.fact.r#type);
            assert_eq!(e.fact.validate_shape().is_ok(), v.fact.shape_ok());
            if let Some(o) = v.fact.body.obj() {
                for k in ["sha256", "size", "n", "f", "big", "ia", "arr", "t", "missing"] {
                    assert_eq!(e.fact.body.get(k).and_then(|x| x.as_str()), o.as_str(k), "{k}");
                    assert_eq!(e.fact.body.get(k).and_then(|x| x.as_i64()), o.as_i64(k), "{k}");
                }
                let ia = e.fact.body.get("ia").unwrap();
                assert_eq!(ia.get("identifier").and_then(|x| x.as_str()), o.obj("ia").unwrap().as_str("identifier"));
            } else {
                assert!(!e.fact.body.is_object());
            }
            match (&e.fact.sig, &v.fact.sig) {
                (Some(s), Some(sv)) => {
                    assert_eq!(s.key.to_string(), sv.jwk_text());
                    assert_eq!(serde_json::to_value(s.alg).unwrap().as_str().unwrap(), sv.alg_name());
                }
                (None, None) => {}
                _ => panic!("sig mismatch"),
            }
        }
        let bad = [
            r#"{"cursor":"c","id":"i","fact":{"v":1,"type":"x","author":"a","at":"t","body":{},"other":1}}"#,
            r#"{"cursor":"c","id":"i","fact":{"v":1,"type":"x","author":"a","at":"t","body":{"n":1e400}}}"#,
            r#"{"cursor":"c","id":"i","fact":{"v":1,"type":"x","author":"a","at":"t","body":{"s":"\ud800"}}}"#,
            r#"{"cursor":"c","id":"i","fact":{"v":1,"type":"x","author":"a","at":"t","body":{},"sig":{"alg":"Ed25519","fmt":"raw","key":{"n":1e400},"value":"v"}}}"#,
            r#"{"cursor":"c","id":"i","fact":{"v":1,"type":"x","author":"a","at":"t","body":{},"sig":{"alg":"ES256","fmt":"raw","key":{},"value":"v"}}}"#,
            r#"{"cursor":"c","id":"i","fact":{"v":1,"type":"x","type":"y","author":"a","at":"t","body":{}}}"#,
            r#"{"cursor":"c","id":"i","fact":{"v":-1,"type":"x","author":"a","at":"t","body":{}}}"#,
            r#"{"cursor":"c","id":"i","fact":{"v":1,"type":"x","author":"a","at":"t","body":{},"sig":{"alg":"RSA","fmt":"raw","key":{},"value":"v"}}}"#,
            r#"{"cursor":"c","id":"i","fact":{"v":1,"type":"x","author":"a","at":"t"}}"#,
        ];
        for line in bad {
            assert!(serde_json::from_str::<Entry>(line).is_err(), "{line}");
            assert!(serde_json::from_str::<EntryView>(line).is_err(), "{line}");
        }
    }
}
