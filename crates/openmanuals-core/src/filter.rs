//! A compact, deterministic membership filter over string keys (binary fuse
//! filter, 8-bit fingerprints: ~9 bits per key, false-positive rate ~1/256,
//! no false negatives).
//!
//! The server builds one from every page key in a snapshot (see
//! [`crate::ids::page_keys`]) and publishes it; the extension tests the page
//! it is on locally and only asks the server on a hit.
//!
//! The algorithm is Graf & Lemire's binary fuse filter ("Binary Fuse Filters:
//! Fast and Smaller Than Xor Filters", 2022), 3-wise, implemented here so the
//! wire format is ours and construction is deterministic: keys are hashed,
//! sorted and deduplicated first, seeds come from a fixed splitmix64 stream,
//! and peeling order depends only on the key set.
//!
//! ## Wire format (all integers little-endian)
//!
//! | offset | size | field |
//! |-------:|-----:|-------|
//! | 0  | 4 | magic `OMLF` |
//! | 4  | 1 | format version ([`FORMAT_VERSION`]) |
//! | 5  | 1 | key-derivation version ([`crate::ids::PAGE_KEY_VERSION`]) |
//! | 6  | 1 | fingerprint bits (8) |
//! | 7  | 1 | reserved (0) |
//! | 8  | 4 | key count (distinct 64-bit key hashes) |
//! | 12 | 8 | seed |
//! | 20 | 4 | segment length (power of two, 1..=2^18) |
//! | 24 | 4 | segment count (≥ 1) |
//! | 28 | 4 | array length = (segment count + 2) × segment length |
//! | 32 | array length | fingerprints |
//! | end-8 | 8 | first 8 bytes of SHA-256 over everything before |
//!
//! A key's 64-bit hash is the first 8 bytes (LE) of SHA-256 of its UTF-8 bytes.

use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"OMLF";
pub const FORMAT_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 32;
pub const CHECKSUM_LEN: usize = 8;
const FINGERPRINT_BITS: u8 = 8;
const MAX_SEGMENT_LENGTH: u32 = 1 << 18;
const MAX_ATTEMPTS: u32 = 1000;
/// splitmix64 starting state for the seed stream (fixed: determinism).
const SEED_STREAM_START: u64 = 0x4f4d_4c46_0000_0001;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("filter too short")]
    Truncated,
    #[error("not a lookup filter (bad magic)")]
    BadMagic,
    #[error("unsupported filter format version {0}")]
    FormatVersion(u8),
    #[error("unsupported key-derivation version {0}")]
    KeyVersion(u8),
    #[error("malformed filter: {0}")]
    Malformed(&'static str),
    #[error("filter checksum mismatch")]
    Checksum,
    #[error("too many keys")]
    TooManyKeys,
    #[error("construction failed after {0} attempts")]
    Construction(u32),
}

/// 64-bit hash of a key string.
pub fn key_hash(key: &str) -> u64 {
    let d = Sha256::digest(key.as_bytes());
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

#[inline]
fn murmur64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

#[inline]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[inline]
fn fingerprint(h: u64) -> u8 {
    (h ^ (h >> 32)) as u8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    segment_length: u32,
    segment_count: u32,
    array_length: u32,
}

impl Geometry {
    fn for_size(n: u32) -> Geometry {
        // Parameters from the reference implementation (arity 3).
        let segment_length = if n == 0 {
            4
        } else {
            let e = ((n as f64).ln() / 3.33f64.ln() + 2.25).floor() as i32;
            (1u32 << e.clamp(0, 18)).min(MAX_SEGMENT_LENGTH)
        };
        let size_factor = if n <= 1 { 0.0 } else { f64::max(1.125, 0.875 + 0.25 * 1_000_000f64.ln() / (n as f64).ln()) };
        let capacity = ((n as f64) * size_factor).round() as u64;
        let segment_count = (capacity.div_ceil(segment_length as u64) as i64 - 2).max(1) as u32;
        Geometry { segment_length, segment_count, array_length: (segment_count + 2) * segment_length }
    }

    #[inline]
    fn positions(&self, h: u64) -> [u32; 3] {
        let seg_count_len = self.segment_count as u64 * self.segment_length as u64;
        let mask = (self.segment_length - 1) as u64;
        let h0 = ((h as u128 * seg_count_len as u128) >> 64) as u64;
        let h1 = (h0 + self.segment_length as u64) ^ ((h >> 18) & mask);
        let h2 = (h0 + 2 * self.segment_length as u64) ^ (h & mask);
        [h0 as u32, h1 as u32, h2 as u32]
    }
}

/// Build a serialized filter from string keys (any order, duplicates allowed).
pub fn build<I, S>(keys: I) -> Result<Vec<u8>, FilterError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hashes: Vec<u64> = keys.into_iter().map(|k| key_hash(k.as_ref())).collect();
    build_from_hashes(&mut hashes, crate::ids::PAGE_KEY_VERSION)
}

/// Build from 64-bit key hashes (sorted and deduplicated in place).
pub fn build_from_hashes(hashes: &mut Vec<u64>, key_version: u8) -> Result<Vec<u8>, FilterError> {
    hashes.sort_unstable();
    hashes.dedup();
    let n: u32 = hashes.len().try_into().map_err(|_| FilterError::TooManyKeys)?;
    if n > u32::MAX / 4 {
        return Err(FilterError::TooManyKeys);
    }
    let g = Geometry::for_size(n);
    let len = g.array_length as usize;
    let mut rng = SEED_STREAM_START;
    let mut seed = 0u64;
    let mut fps = vec![0u8; len];
    if n > 0 {
        let mut count = vec![0u32; len];
        let mut xorh = vec![0u64; len];
        let mut queue: Vec<u32> = Vec::with_capacity(len);
        let mut stack: Vec<(u64, u32)> = Vec::with_capacity(n as usize);
        let mut attempt = 0;
        loop {
            attempt += 1;
            if attempt > MAX_ATTEMPTS {
                return Err(FilterError::Construction(MAX_ATTEMPTS));
            }
            seed = splitmix64(&mut rng);
            count.iter_mut().for_each(|c| *c = 0);
            xorh.iter_mut().for_each(|x| *x = 0);
            queue.clear();
            stack.clear();
            for &k in hashes.iter() {
                let h = murmur64(k.wrapping_add(seed));
                for p in g.positions(h) {
                    count[p as usize] += 1;
                    xorh[p as usize] ^= h;
                }
            }
            queue.extend((0..len as u32).filter(|&i| count[i as usize] == 1));
            while let Some(i) = queue.pop() {
                if count[i as usize] != 1 {
                    continue;
                }
                let h = xorh[i as usize];
                stack.push((h, i));
                for p in g.positions(h) {
                    let p = p as usize;
                    count[p] -= 1;
                    xorh[p] ^= h;
                    if count[p] == 1 {
                        queue.push(p as u32);
                    }
                }
            }
            if stack.len() == n as usize {
                break;
            }
        }
        for &(h, i) in stack.iter().rev() {
            let [a, b, c] = g.positions(h);
            fps[i as usize] = 0;
            fps[i as usize] = fingerprint(h) ^ fps[a as usize] ^ fps[b as usize] ^ fps[c as usize];
        }
    }
    let mut out = Vec::with_capacity(HEADER_LEN + len + CHECKSUM_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[FORMAT_VERSION, key_version, FINGERPRINT_BITS, 0]);
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&seed.to_le_bytes());
    out.extend_from_slice(&g.segment_length.to_le_bytes());
    out.extend_from_slice(&g.segment_count.to_le_bytes());
    out.extend_from_slice(&g.array_length.to_le_bytes());
    out.extend_from_slice(&fps);
    let sum = Sha256::digest(&out);
    out.extend_from_slice(&sum[..CHECKSUM_LEN]);
    Ok(out)
}

/// A parsed filter, ready for queries.
#[derive(Debug, Clone)]
pub struct Filter {
    key_version: u8,
    key_count: u32,
    seed: u64,
    geometry: Geometry,
    fingerprints: Vec<u8>,
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

impl Filter {
    /// Parse and validate serialized bytes (untrusted: comes over the network).
    pub fn from_bytes(b: &[u8]) -> Result<Filter, FilterError> {
        if b.len() < 4 {
            return Err(FilterError::Truncated);
        }
        if &b[..4] != MAGIC {
            return Err(FilterError::BadMagic);
        }
        if b.len() < HEADER_LEN + CHECKSUM_LEN {
            return Err(FilterError::Truncated);
        }
        if b[4] != FORMAT_VERSION {
            return Err(FilterError::FormatVersion(b[4]));
        }
        let key_version = b[5];
        if key_version != crate::ids::PAGE_KEY_VERSION {
            return Err(FilterError::KeyVersion(key_version));
        }
        if b[6] != FINGERPRINT_BITS || b[7] != 0 {
            return Err(FilterError::Malformed("fingerprint width"));
        }
        let key_count = u32_at(b, 8);
        let seed = u64::from_le_bytes(b[12..20].try_into().unwrap());
        let segment_length = u32_at(b, 20);
        let segment_count = u32_at(b, 24);
        let array_length = u32_at(b, 28);
        if !segment_length.is_power_of_two() || segment_length > MAX_SEGMENT_LENGTH {
            return Err(FilterError::Malformed("segment length"));
        }
        if segment_count == 0 {
            return Err(FilterError::Malformed("segment count"));
        }
        let expect = (segment_count as u64 + 2) * segment_length as u64;
        if expect != array_length as u64 {
            return Err(FilterError::Malformed("array length"));
        }
        let total = HEADER_LEN as u64 + array_length as u64 + CHECKSUM_LEN as u64;
        if (b.len() as u64) < total {
            return Err(FilterError::Truncated);
        }
        if b.len() as u64 != total {
            return Err(FilterError::Malformed("trailing bytes"));
        }
        let body_end = b.len() - CHECKSUM_LEN;
        if Sha256::digest(&b[..body_end])[..CHECKSUM_LEN] != b[body_end..] {
            return Err(FilterError::Checksum);
        }
        Ok(Filter {
            key_version,
            key_count,
            seed,
            geometry: Geometry { segment_length, segment_count, array_length },
            fingerprints: b[HEADER_LEN..body_end].to_vec(),
        })
    }

    pub fn contains(&self, key: &str) -> bool {
        self.contains_hash(key_hash(key))
    }

    pub fn contains_hash(&self, key: u64) -> bool {
        if self.key_count == 0 {
            return false;
        }
        let h = murmur64(key.wrapping_add(self.seed));
        let [a, b, c] = self.geometry.positions(h);
        let f = &self.fingerprints;
        fingerprint(h) ^ f[a as usize] ^ f[b as usize] ^ f[c as usize] == 0
    }

    /// Whether any of a page's keys ([`crate::ids::page_keys`]) is in the filter.
    pub fn contains_page(&self, url: &str) -> bool {
        crate::ids::page_keys(url).iter().any(|k| self.contains(k))
    }

    pub fn key_count(&self) -> u32 {
        self.key_count
    }
    pub fn key_version(&self) -> u8 {
        self.key_version
    }
    pub fn byte_len(&self) -> usize {
        HEADER_LEN + self.fingerprints.len() + CHECKSUM_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize, salt: &str) -> Vec<String> {
        (0..n).map(|i| format!("url:https://example.com/{salt}/{i}")).collect()
    }

    #[test]
    fn no_false_negatives_and_fp_rate() {
        let ks = keys(200_000, "in");
        let bytes = build(&ks).unwrap();
        let f = Filter::from_bytes(&bytes).unwrap();
        assert_eq!(f.key_count(), 200_000);
        assert!(ks.iter().all(|k| f.contains(k)));
        let bits_per_key = (bytes.len() * 8) as f64 / ks.len() as f64;
        assert!(bits_per_key < 9.5, "{bits_per_key} bits/key");
        let probes = keys(500_000, "out");
        let fp = probes.iter().filter(|k| f.contains(k)).count() as f64 / probes.len() as f64;
        // Expected 1/256 ≈ 0.0039.
        assert!((0.0025..0.0055).contains(&fp), "fp rate {fp}");
    }

    #[test]
    fn every_small_size_builds() {
        for n in 0..300 {
            let ks = keys(n, "small");
            let f = Filter::from_bytes(&build(&ks).unwrap()).unwrap();
            assert!(ks.iter().all(|k| f.contains(k)), "n={n}");
        }
        let empty = Filter::from_bytes(&build(Vec::<String>::new()).unwrap()).unwrap();
        assert!(!empty.contains("anything"));
    }

    #[test]
    fn deterministic_across_order_and_duplicates() {
        let ks = keys(20_000, "det");
        let a = build(&ks).unwrap();
        assert_eq!(a, build(&ks).unwrap());
        let mut rev: Vec<String> = ks.iter().rev().cloned().collect();
        rev.extend(ks.iter().take(500).cloned());
        assert_eq!(a, build(&rev).unwrap());
        let mut shuffled = ks.clone();
        let mut s = 7u64;
        for i in (1..shuffled.len()).rev() {
            let j = (splitmix64(&mut s) % (i as u64 + 1)) as usize;
            shuffled.swap(i, j);
        }
        assert_eq!(a, build(&shuffled).unwrap());
        // Pinned: a change here is a wire-format change (bump FORMAT_VERSION).
        let small = build(["src:manualslib:331384", "src:elektrotanya:sony_kv-1400_sm.pdf"]).unwrap();
        assert_eq!(&small[..8], b"OMLF\x01\x01\x08\x00");
        assert_eq!(canon_hex(&small), canon_hex(&build(["src:elektrotanya:sony_kv-1400_sm.pdf", "src:manualslib:331384"]).unwrap()));
        assert_eq!(canon_hex(&small), "3be318a609c8b5fa48676aa7be600a5a9d02ab8618a2a5351a0656909af6e637");
    }

    fn canon_hex(b: &[u8]) -> String {
        crate::canon::sha256_hex(b)
    }

    #[test]
    fn malformed_rejected() {
        let good = build(keys(1000, "m")).unwrap();
        assert!(Filter::from_bytes(&good).is_ok());
        assert_eq!(Filter::from_bytes(&[]).unwrap_err(), FilterError::Truncated);
        assert_eq!(Filter::from_bytes(b"<html>not found</html>").unwrap_err(), FilterError::BadMagic);
        for cut in [5, 20, HEADER_LEN, good.len() / 2, good.len() - 1] {
            assert!(Filter::from_bytes(&good[..cut]).is_err(), "cut {cut}");
        }
        let mut long = good.clone();
        long.push(0);
        assert!(Filter::from_bytes(&long).is_err());
        let mut v = good.clone();
        v[4] = 2;
        assert_eq!(Filter::from_bytes(&v).unwrap_err(), FilterError::FormatVersion(2));
        let mut v = good.clone();
        v[5] = 99;
        assert_eq!(Filter::from_bytes(&v).unwrap_err(), FilterError::KeyVersion(99));
        let mut v = good.clone();
        v[HEADER_LEN + 10] ^= 1;
        assert_eq!(Filter::from_bytes(&v).unwrap_err(), FilterError::Checksum);
        let mut v = good.clone();
        v[20..24].copy_from_slice(&3u32.to_le_bytes());
        assert!(Filter::from_bytes(&v).is_err());
        let mut v = good.clone();
        v[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Filter::from_bytes(&v).is_err());
    }
}
