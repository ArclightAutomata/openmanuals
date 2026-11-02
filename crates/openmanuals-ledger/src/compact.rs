//! Compact in-memory forms of the ids and strings the build holds, chosen so
//! that their ordering equals the ordering of the text they replace (the
//! snapshot is written in sorted order, so this keeps it byte-identical).
//!
//! - ULIDs (manual ids, cursors) → `u128`. Crockford base32 is ASCII-sorted
//!   and fixed-width, so numeric order = string order.
//! - Lowercase hex digests → byte arrays (same argument).
//! - Repeated strings (authors, hosts, kinds, product keys…) → `Sym` indexes
//!   into one [`Interner`]; compare them through the interner when order matters.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use rustc_hash::FxHashMap;
use std::fmt;
use std::sync::Arc;

pub type Sym = u32;

#[derive(Default, Clone)]
pub struct Interner {
    strs: Vec<Arc<str>>,
    map: FxHashMap<Arc<str>, Sym>,
}

impl Interner {
    pub fn intern(&mut self, s: &str) -> Sym {
        if let Some(&i) = self.map.get(s) {
            return i;
        }
        let a: Arc<str> = Arc::from(s);
        let i = self.strs.len() as Sym;
        self.strs.push(a.clone());
        self.map.insert(a, i);
        i
    }
    pub fn lookup(&self, s: &str) -> Option<Sym> {
        self.map.get(s).copied()
    }
    pub fn get(&self, i: Sym) -> &str {
        &self.strs[i as usize]
    }
    pub fn len(&self) -> usize {
        self.strs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.strs.is_empty()
    }
}

impl Serialize for Interner {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.strs.iter().map(|a| &**a))
    }
}

impl<'de> Deserialize<'de> for Interner {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: Vec<String> = Vec::deserialize(d)?;
        let mut i = Interner::default();
        for s in v {
            i.intern(&s);
        }
        Ok(i)
    }
}

/// Parse a ULID, accepting either case (as the ulid crate does).
pub fn ulid(s: &str) -> Option<u128> {
    (s.len() == 26).then(|| s.parse::<ulid::Ulid>().ok().map(|u| u.0)).flatten()
}

/// Parse a ULID only in its canonical (uppercase) spelling, for places that
/// compared the original string exactly.
pub fn ulid_exact(s: &str) -> Option<u128> {
    let mut buf = [0u8; 26];
    ulid(s).filter(|&u| ulid::Ulid(u).array_to_str(&mut buf) == s)
}

pub fn ulid_str(u: u128) -> String {
    ulid::Ulid(u).to_string()
}

fn hex_lower<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Lowercase/uppercase hex of exactly `N` bytes, as `hexfield` accepted it.
pub fn hex_any<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// A fact id, `sha256:<64 lowercase hex>`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FactId(pub [u8; 32]);

impl FactId {
    pub fn parse(s: &str) -> Option<FactId> {
        s.strip_prefix("sha256:").and_then(hex_lower::<32>).map(FactId)
    }
}

impl fmt::Display for FactId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for FactId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A file id: sha256, or a legacy file known only by sha1. Variant order
/// matches the text order (`<hex>` < `sha1:<hex>`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FileId {
    Sha256([u8; 32]),
    Sha1([u8; 20]),
}

impl FileId {
    /// Same rules as `model::parse_file_ref` (trimmed, either case).
    pub fn parse(s: &str) -> Option<FileId> {
        let s = s.trim();
        if let Some(h) = hex_any::<32>(s) {
            return Some(FileId::Sha256(h));
        }
        s.strip_prefix("sha1:").and_then(hex_any::<20>).map(FileId::Sha1)
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FileId::Sha256(h) => f.write_str(&hex::encode(h)),
            FileId::Sha1(h) => write!(f, "sha1:{}", hex::encode(h)),
        }
    }
}

impl fmt::Debug for FileId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_match_text() {
        let ids = ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAZ", "01BX5ZZKBKACTAV9WEVGEMMVRZ", "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"];
        for w in ids.windows(2) {
            assert!(ulid(w[0]).unwrap() < ulid(w[1]).unwrap());
            assert_eq!(ulid_str(ulid(w[0]).unwrap()), w[0]);
        }
        assert!(ulid_exact("01arz3ndektsv4rrffq69g5fav").is_none());
        assert!(ulid("01ARZ3NDEKTSV4RRFFQ69G5FAO").is_none(), "no Crockford aliases");
        let a = FileId::parse(&"f".repeat(64)).unwrap();
        let b = FileId::parse(&format!("sha1:{}", "0".repeat(40))).unwrap();
        assert!(a < b && a.to_string() < b.to_string());
        assert_eq!(FileId::parse(&"AB".repeat(32)).unwrap().to_string(), "ab".repeat(32));
        let f = format!("sha256:{}", "0a".repeat(32));
        assert_eq!(FactId::parse(&f).unwrap().to_string(), f);
        assert!(FactId::parse(&f.to_uppercase().replace("SHA256", "sha256")).is_none());
    }

    #[test]
    fn interner_roundtrips() {
        let mut i = Interner::default();
        let a = i.intern("x");
        assert_eq!(i.intern("y"), 1);
        assert_eq!(i.intern("x"), a);
        let bytes = postcard::to_stdvec(&i).unwrap();
        let j: Interner = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(j.lookup("y"), Some(1));
        assert_eq!(j.get(0), "x");
    }
}
