//! Image decoding to 8-bit gray and the 64-bit difference hash, computed as
//! PIL would (`convert('L')`, `resize((9, 8), LANCZOS)`, compare horizontal
//! neighbors) so the recorded hashes keep matching.

use crate::pdfio::{decode_filters, dict_get, num_of, MAX_DECODED};
use lopdf::{Dictionary, Document, Object, Stream};

/// Row-major 8-bit luminance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrayImage {
    pub width: usize,
    pub height: usize,
    pub data: Vec<u8>,
}

/// PIL's RGB → L conversion (ITU-R 601-2 luma, fixed point).
pub fn luma(r: u8, g: u8, b: u8) -> u8 {
    ((r as u32 * 19595 + g as u32 * 38470 + b as u32 * 7471 + 0x8000) >> 16) as u8
}

const MAX_PIXELS: usize = 50_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Gray,
    Rgb,
    Cmyk,
}

impl Kind {
    fn n(self) -> usize {
        match self {
            Kind::Gray => 1,
            Kind::Rgb => 3,
            Kind::Cmyk => 4,
        }
    }
}

enum ColorSpace {
    Device(Kind),
    Indexed { base: Kind, palette: Vec<u8> },
}

impl ColorSpace {
    fn n(&self) -> usize {
        match self {
            ColorSpace::Device(k) => k.n(),
            ColorSpace::Indexed { .. } => 1,
        }
    }
}

fn dict_number(doc: &Document, d: &Dictionary, key: &[u8]) -> Option<f64> {
    dict_get(doc, d, key).and_then(num_of)
}

fn dim(doc: &Document, d: &Dictionary, long: &[u8], short: &[u8]) -> Option<f64> {
    dict_number(doc, d, long).or_else(|| dict_number(doc, d, short))
}

/// Image dimensions from the dictionary, without decoding (0 when absent).
pub fn image_size(doc: &Document, image: &Stream) -> (f64, f64) {
    (
        dim(doc, &image.dict, b"Width", b"W").unwrap_or(0.0),
        dim(doc, &image.dict, b"Height", b"H").unwrap_or(0.0),
    )
}

/// Filters applied to a stream, in order (names only; anything else is ignored).
fn filters(doc: &Document, s: &Stream) -> Vec<Vec<u8>> {
    match dict_get(doc, &s.dict, b"Filter") {
        Some(Object::Name(n)) => vec![n.clone()],
        Some(Object::Array(a)) => a
            .iter()
            .filter_map(|o| match doc.dereference(o).ok()?.1 {
                Object::Name(n) => Some(n.clone()),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn parse_color_space(doc: &Document, cs: Option<&Object>, depth: usize) -> Option<ColorSpace> {
    let cs = cs?;
    match cs {
        Object::Name(n) => match n.as_slice() {
            b"DeviceGray" | b"CalGray" | b"G" => Some(ColorSpace::Device(Kind::Gray)),
            b"DeviceRGB" | b"CalRGB" | b"RGB" => Some(ColorSpace::Device(Kind::Rgb)),
            b"DeviceCMYK" | b"CMYK" => Some(ColorSpace::Device(Kind::Cmyk)),
            _ => None,
        },
        Object::Array(a) if !a.is_empty() => {
            let get = |i: usize| {
                a.get(i)
                    .and_then(|o| doc.dereference(o).ok())
                    .map(|(_, o)| o)
            };
            let fam = match get(0) {
                Some(Object::Name(n)) => n.as_slice(),
                _ => b"",
            };
            match fam {
                b"ICCBased" => {
                    let n = match get(1) {
                        Some(Object::Stream(s)) => dict_number(doc, &s.dict, b"N"),
                        _ => None,
                    };
                    match n {
                        Some(1.0) => Some(ColorSpace::Device(Kind::Gray)),
                        Some(3.0) => Some(ColorSpace::Device(Kind::Rgb)),
                        Some(4.0) => Some(ColorSpace::Device(Kind::Cmyk)),
                        _ => None,
                    }
                }
                b"CalRGB" => Some(ColorSpace::Device(Kind::Rgb)),
                b"CalGray" => Some(ColorSpace::Device(Kind::Gray)),
                b"Indexed" | b"I" if a.len() >= 4 && depth == 0 => {
                    let base = match parse_color_space(doc, get(1), depth + 1)? {
                        ColorSpace::Device(k) => k,
                        ColorSpace::Indexed { .. } => return None,
                    };
                    let palette = match get(3)? {
                        Object::String(b, _) => b.clone(),
                        Object::Stream(s) => decode_filters(s, MAX_DECODED).ok()?,
                        _ => return None,
                    };
                    Some(ColorSpace::Indexed { base, palette })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Decode an image XObject to 8-bit gray. `None` for unsupported encodings or damaged data.
pub fn decode_image_to_gray(doc: &Document, image: &Stream) -> Option<GrayImage> {
    let d = &image.dict;
    let width = dim(doc, d, b"Width", b"W")?;
    let height = dim(doc, d, b"Height", b"H")?;
    if !(width >= 1.0 && height >= 1.0)
        || width.fract() != 0.0
        || height.fract() != 0.0
        || width * height > MAX_PIXELS as f64
    {
        return None;
    }
    let (width, height) = (width as usize, height as usize);
    let fs = filters(doc, image);
    let last = fs.last().map(|v| v.as_slice());
    if matches!(last, Some(b"DCTDecode" | b"DCT")) {
        let jpeg: std::borrow::Cow<[u8]> = if fs.len() > 1 {
            // Earlier filters wrap the JPEG; decode them first.
            let mut dict = d.clone();
            dict.set(
                "Filter",
                Object::Array(
                    fs[..fs.len() - 1]
                        .iter()
                        .map(|f| Object::Name(f.clone()))
                        .collect(),
                ),
            );
            let s = Stream::new(dict, image.content.clone());
            decode_filters(&s, MAX_DECODED).ok()?.into()
        } else {
            image.content.as_slice().into()
        };
        return decode_jpeg(&jpeg);
    }
    if matches!(
        last,
        Some(b"JPXDecode" | b"CCITTFaxDecode" | b"CCF" | b"JBIG2Decode")
    ) {
        return None;
    }
    let raw = decode_filters(image, MAX_DECODED).ok()?;
    let bpc = dim(doc, d, b"BitsPerComponent", b"BPC").unwrap_or(8.0);
    let mask = dict_get(doc, d, b"ImageMask").or_else(|| dict_get(doc, d, b"IM"));
    let mut data = vec![0u8; width * height];
    if matches!(mask, Some(Object::Boolean(true))) {
        // 1-bit stencil: 0 = paint (black)
        unpack_bilevel(&raw, width, height, &mut data, false);
        return Some(GrayImage {
            width,
            height,
            data,
        });
    }
    let cs = parse_color_space(doc, dict_get(doc, d, b"ColorSpace"), 0)?;
    if bpc == 1.0 && matches!(cs, ColorSpace::Device(Kind::Gray)) {
        unpack_bilevel(&raw, width, height, &mut data, true);
        return Some(GrayImage {
            width,
            height,
            data,
        });
    }
    if bpc != 8.0 {
        return None;
    }
    let n = cs.n();
    let row_bytes = width * n;
    if raw.len() < row_bytes * height {
        return None;
    }
    let cmyk = |c: u8, m: u8, y: u8, k: u8| {
        let f = |v: u8| 255 - (v as u32 + k as u32).min(255) as u8;
        luma(f(c), f(m), f(y))
    };
    for y in 0..height {
        let row = y * row_bytes;
        for x in 0..width {
            let i = row + x * n;
            data[y * width + x] = match &cs {
                ColorSpace::Device(Kind::Gray) => raw[i],
                ColorSpace::Device(Kind::Rgb) => luma(raw[i], raw[i + 1], raw[i + 2]),
                ColorSpace::Device(Kind::Cmyk) => cmyk(raw[i], raw[i + 1], raw[i + 2], raw[i + 3]),
                ColorSpace::Indexed { base, palette } => {
                    let idx = raw[i] as usize;
                    let p = |j: usize| palette.get(j).copied().unwrap_or(0);
                    match base {
                        Kind::Gray => p(idx),
                        Kind::Rgb => luma(p(idx * 3), p(idx * 3 + 1), p(idx * 3 + 2)),
                        Kind::Cmyk => {
                            cmyk(p(idx * 4), p(idx * 4 + 1), p(idx * 4 + 2), p(idx * 4 + 3))
                        }
                    }
                }
            };
        }
    }
    Some(GrayImage {
        width,
        height,
        data,
    })
}

fn decode_jpeg(bytes: &[u8]) -> Option<GrayImage> {
    use zune_jpeg::zune_core::{
        bytestream::ZCursor, colorspace::ColorSpace as Zcs, options::DecoderOptions,
    };
    let opts = DecoderOptions::default()
        .set_strict_mode(false)
        .set_max_width(1 << 15)
        .set_max_height(1 << 15)
        .jpeg_set_out_colorspace(Zcs::RGB);
    let mut dec = zune_jpeg::JpegDecoder::new_with_options(ZCursor::new(bytes), opts);
    dec.decode_headers().ok()?;
    let info = dec.info()?;
    let (w, h) = (info.width as usize, info.height as usize);
    if w == 0 || h == 0 || w * h > MAX_PIXELS {
        return None;
    }
    let px = dec.decode().ok()?;
    let n = dec.output_colorspace()?.num_components();
    if px.len() < w * h * n {
        return None;
    }
    let data = match n {
        1 => px[..w * h].to_vec(),
        3 | 4 => (0..w * h)
            .map(|i| luma(px[i * n], px[i * n + 1], px[i * n + 2]))
            .collect(),
        _ => return None,
    };
    Some(GrayImage {
        width: w,
        height: h,
        data,
    })
}

fn unpack_bilevel(raw: &[u8], width: usize, height: usize, out: &mut [u8], one_is_white: bool) {
    let row_bytes = width.div_ceil(8);
    for y in 0..height {
        for x in 0..width {
            let byte = raw.get(y * row_bytes + (x >> 3)).copied().unwrap_or(0);
            let bit = (byte >> (7 - (x & 7))) & 1 == 1;
            out[y * width + x] = if bit == one_is_white { 255 } else { 0 };
        }
    }
}

// --- Lanczos resample as PIL does it (separable, support scaled on downscale) ---

fn lanczos3(x: f64) -> f64 {
    if x <= -3.0 || x >= 3.0 {
        return 0.0;
    }
    if x == 0.0 {
        return 1.0;
    }
    let px = std::f64::consts::PI * x;
    (px.sin() / px) * ((px / 3.0).sin() / (px / 3.0))
}

fn resample_axis(
    src: &[u8],
    in_w: usize,
    in_h: usize,
    out_size: usize,
    horizontal: bool,
) -> Vec<u8> {
    let in_size = if horizontal { in_w } else { in_h };
    let scale = in_size as f64 / out_size as f64;
    let filterscale = scale.max(1.0);
    let support = 3.0 * filterscale;
    let ss = 1.0 / filterscale;
    let lines = if horizontal { in_h } else { in_w };
    let mut out = vec![
        0u8;
        if horizontal {
            out_size * in_h
        } else {
            in_w * out_size
        }
    ];
    let mut weights = Vec::new();
    for o in 0..out_size {
        let center = (o as f64 + 0.5) * scale;
        let xmin = ((center - support).floor().max(0.0)) as usize;
        let xmax = ((center + support).ceil() as usize).min(in_size);
        weights.clear();
        let mut total = 0.0;
        for x in xmin..xmax {
            let w = lanczos3((x as f64 - center + 0.5) * ss);
            weights.push(w);
            total += w;
        }
        if total != 0.0 {
            for w in weights.iter_mut() {
                *w /= total;
            }
        }
        for line in 0..lines {
            let mut acc = 0.0;
            for x in xmin..xmax {
                let v = if horizontal {
                    src[line * in_w + x]
                } else {
                    src[x * in_w + line]
                };
                acc += v as f64 * weights[x - xmin];
            }
            // JS Math.round: halves round up.
            let v = (acc + 0.5).floor().clamp(0.0, 255.0) as u8;
            if horizontal {
                out[line * out_size + o] = v;
            } else {
                out[o * in_w + line] = v;
            }
        }
    }
    out
}

/// Resize to `w`×`h` with PIL's Lanczos filter (floating point).
pub fn resize_gray(img: &GrayImage, w: usize, h: usize) -> GrayImage {
    let horiz = resample_axis(&img.data, img.width, img.height, w, true);
    let both = resample_axis(&horiz, w, img.height, h, false);
    GrayImage {
        width: w,
        height: h,
        data: both,
    }
}

/// 64-bit difference hash: 8 rows × 8 horizontal neighbor comparisons on a 9×8 thumbnail.
pub fn dhash(img: &GrayImage) -> u64 {
    let t = resize_gray(img, 9, 8).data;
    let mut bits = 0u64;
    for row in 0..8 {
        for col in 0..8 {
            bits = (bits << 1) | (t[row * 9 + col] > t[row * 9 + col + 1]) as u64;
        }
    }
    bits
}

pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}
