//! `avatar` facts: a key's profile picture.
//!
//! The fact body is exactly one of
//! `{"sha256", "size", "mime"}` (an uploaded image, whose bytes live outside
//! the ledger on the server), `{"url"}` (an https image the server copies), or
//! `{"none": true}` (back to the identicon). The newest live `avatar` fact of
//! a key wins. Images are PNG, JPEG or WebP, at most [`MAX_BYTES`] and
//! [`MAX_DIM`] pixels a side, recognized by their bytes, never SVG.

use crate::{Error, Result};
use serde_json::Value;

/// Largest image accepted.
pub const MAX_BYTES: u64 = 128 * 1024;
/// Largest width and height.
pub const MAX_DIM: u32 = 512;
/// Longest `url`.
pub const MAX_URL: usize = 2048;
/// The image types accepted, by MIME type.
pub const MIMES: &[&str] = &["image/webp", "image/png", "image/jpeg"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Avatar {
    Image { sha256: String, size: u64, mime: String },
    Url(String),
    None,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Fact(format!("avatar: {}", msg.into()))
}

/// Whether `url` is an acceptable avatar URL: https, a host, no whitespace or
/// control characters, no credentials, at most [`MAX_URL`] bytes.
pub fn valid_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    url.len() <= MAX_URL
        && !authority.is_empty()
        && !authority.contains('@')
        && !authority.starts_with(':')
        && url.bytes().all(|b| b > 0x20 && b != 0x7f)
}

/// Parse an `avatar` body, refusing anything but the three shapes.
pub fn parse(body: &Value) -> Result<Avatar> {
    let o = body.as_object().ok_or_else(|| bad("body must be an object"))?;
    let keys: Vec<&str> = {
        let mut k: Vec<&str> = o.keys().map(String::as_str).collect();
        k.sort_unstable();
        k
    };
    match keys.as_slice() {
        ["mime", "sha256", "size"] => {
            let sha256 = o["sha256"].as_str().ok_or_else(|| bad("sha256 must be a string"))?;
            if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err(bad("sha256 must be 64 lowercase hex characters"));
            }
            let size = o["size"].as_u64().ok_or_else(|| bad("size must be a positive integer"))?;
            if size == 0 || size > MAX_BYTES {
                return Err(bad(format!("size must be 1 to {MAX_BYTES} bytes")));
            }
            let mime = o["mime"].as_str().ok_or_else(|| bad("mime must be a string"))?;
            if !MIMES.contains(&mime) {
                return Err(bad(format!("mime must be one of {}", MIMES.join(", "))));
            }
            Ok(Avatar::Image { sha256: sha256.to_string(), size, mime: mime.to_string() })
        }
        ["url"] => {
            let url = o["url"].as_str().ok_or_else(|| bad("url must be a string"))?;
            if !valid_url(url) {
                return Err(bad("url must be an https URL"));
            }
            Ok(Avatar::Url(url.to_string()))
        }
        ["none"] if o["none"] == Value::Bool(true) => Ok(Avatar::None),
        _ => Err(bad("body must be {sha256, size, mime}, {url} or {none: true}")),
    }
}

/// What an image's bytes say it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub mime: &'static str,
    pub width: u32,
    pub height: u32,
}

/// Recognize a PNG, JPEG or WebP image by its bytes and read its size; check
/// the limits. Anything else (SVG, GIF, HTML…) is refused.
pub fn inspect(bytes: &[u8]) -> Result<ImageInfo> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(bad(format!("image exceeds {MAX_BYTES} bytes")));
    }
    let info = png(bytes).or_else(|| jpeg(bytes)).or_else(|| webp(bytes)).ok_or_else(|| bad("not a PNG, JPEG or WebP image"))?;
    if info.width == 0 || info.height == 0 || info.width > MAX_DIM || info.height > MAX_DIM {
        return Err(bad(format!("image is {}×{}; at most {MAX_DIM}×{MAX_DIM}", info.width, info.height)));
    }
    Ok(info)
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn be16(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 2).map(|s| u16::from_be_bytes([s[0], s[1]]) as u32)
}
fn le16(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 2).map(|s| u16::from_le_bytes([s[0], s[1]]) as u32)
}
fn le24(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 3).map(|s| s[0] as u32 | (s[1] as u32) << 8 | (s[2] as u32) << 16)
}

fn png(b: &[u8]) -> Option<ImageInfo> {
    if !b.starts_with(b"\x89PNG\r\n\x1a\n") || b.get(12..16)? != b"IHDR" {
        return None;
    }
    Some(ImageInfo { mime: "image/png", width: be32(b, 16)?, height: be32(b, 20)? })
}

fn jpeg(b: &[u8]) -> Option<ImageInfo> {
    if !b.starts_with(&[0xff, 0xd8]) {
        return None;
    }
    let mut i = 2;
    while i + 4 <= b.len() {
        if b[i] != 0xff {
            return None;
        }
        let marker = b[i + 1];
        if marker == 0xff {
            i += 1; // fill byte
            continue;
        }
        if marker == 0xd8 || marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            i += 2;
            continue;
        }
        let len = be16(b, i + 2)? as usize;
        // Start of frame: every SOFn except DHT (c4), JPG (c8) and DAC (cc).
        if (0xc0..=0xcf).contains(&marker) && ![0xc4, 0xc8, 0xcc].contains(&marker) {
            return Some(ImageInfo { mime: "image/jpeg", height: be16(b, i + 5)?, width: be16(b, i + 7)? });
        }
        if marker == 0xda || len < 2 {
            return None; // image data before any frame header
        }
        i += 2 + len;
    }
    None
}

fn webp(b: &[u8]) -> Option<ImageInfo> {
    if b.get(0..4)? != b"RIFF" || b.get(8..12)? != b"WEBP" {
        return None;
    }
    let (width, height) = match b.get(12..16)? {
        b"VP8 " => {
            if b.get(23..26)? != [0x9d, 0x01, 0x2a] {
                return None;
            }
            (le16(b, 26)? & 0x3fff, le16(b, 28)? & 0x3fff)
        }
        b"VP8L" => {
            if *b.get(20)? != 0x2f {
                return None;
            }
            let bits = u32::from_le_bytes(b.get(21..25)?.try_into().ok()?);
            ((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1)
        }
        b"VP8X" => (le24(b, 24)? + 1, le24(b, 27)? + 1),
        _ => return None,
    };
    Some(ImageInfo { mime: "image/webp", width, height })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn shapes() {
        assert_eq!(parse(&json!({"sha256": SHA, "size": 1000, "mime": "image/webp"})).unwrap(), Avatar::Image { sha256: SHA.into(), size: 1000, mime: "image/webp".into() });
        assert_eq!(parse(&json!({"url": "https://github.com/alice.png"})).unwrap(), Avatar::Url("https://github.com/alice.png".into()));
        assert_eq!(parse(&json!({"none": true})).unwrap(), Avatar::None);
        for bad in [
            json!({}),
            json!({"none": false}),
            json!({"none": true, "url": "https://x.org/a.png"}),
            json!({"url": "http://x.org/a.png"}),
            json!({"url": "https://user@x.org/a.png"}),
            json!({"url": "https:///a.png"}),
            json!({"url": "https://x.org/a b.png"}),
            json!({"url": format!("https://x.org/{}", "a".repeat(MAX_URL))}),
            json!({"sha256": SHA, "size": 1000}),
            json!({"sha256": SHA.to_uppercase(), "size": 1000, "mime": "image/png"}),
            json!({"sha256": SHA, "size": 0, "mime": "image/png"}),
            json!({"sha256": SHA, "size": MAX_BYTES + 1, "mime": "image/png"}),
            json!({"sha256": SHA, "size": 10, "mime": "image/svg+xml"}),
            json!({"sha256": SHA, "size": 10, "mime": "image/png", "url": "https://x.org/"}),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }

    pub(crate) fn png_bytes(w: u32, h: u32) -> Vec<u8> {
        let mut b = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        b.extend_from_slice(&w.to_be_bytes());
        b.extend_from_slice(&h.to_be_bytes());
        b.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
        b
    }

    #[test]
    fn inspects_images() {
        assert_eq!(inspect(&png_bytes(256, 200)).unwrap(), ImageInfo { mime: "image/png", width: 256, height: 200 });
        assert!(inspect(&png_bytes(513, 10)).is_err(), "too wide");
        assert!(inspect(&png_bytes(0, 10)).is_err());
        // JPEG: SOI, an APP0 segment, then SOF0 with height 300 and width 400.
        let mut j = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00];
        j.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11, 0x08, 0x01, 0x2c, 0x01, 0x90, 0x03]);
        assert_eq!(inspect(&j).unwrap(), ImageInfo { mime: "image/jpeg", width: 400, height: 300 });
        // WebP, lossy (VP8 ), lossless (VP8L) and extended (VP8X).
        let mut v = b"RIFF\0\0\0\0WEBPVP8 \0\0\0\0\0\0\0\x9d\x01\x2a".to_vec();
        v.extend_from_slice(&256u16.to_le_bytes());
        v.extend_from_slice(&128u16.to_le_bytes());
        assert_eq!(inspect(&v).unwrap(), ImageInfo { mime: "image/webp", width: 256, height: 128 });
        let mut l = b"RIFF\0\0\0\0WEBPVP8L\0\0\0\0\x2f".to_vec();
        l.extend_from_slice(&((255u32) | (99u32 << 14)).to_le_bytes());
        assert_eq!(inspect(&l).unwrap(), ImageInfo { mime: "image/webp", width: 256, height: 100 });
        let mut x = b"RIFF\0\0\0\0WEBPVP8X\0\0\0\0\0\0\0\0".to_vec();
        x.extend_from_slice(&[0xff, 0x01, 0x00, 0x3f, 0x00, 0x00]);
        assert_eq!(inspect(&x).unwrap(), ImageInfo { mime: "image/webp", width: 512, height: 64 });
        for no in [&b"<svg xmlns='http://www.w3.org/2000/svg'/>"[..], b"GIF89a\x01\x00\x01\x00", b"<!doctype html>", b""] {
            assert!(inspect(no).is_err());
        }
        assert!(inspect(&vec![0u8; MAX_BYTES as usize + 1]).is_err());
    }
}
