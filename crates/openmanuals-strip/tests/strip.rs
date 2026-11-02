//! Synthetic PDFs covering every pass, determinism and idempotence, plus
//! hostile-input cases.

use lopdf::{dictionary, Dictionary, Document, Object, ObjectId, Stream};
use openmanuals_strip::image::{dhash, hamming_distance, luma, resize_gray, GrayImage};
use openmanuals_strip::pdfio::{page_content, pages};
use openmanuals_strip::{constants, find_manualslib_wrapper_pages, strip, STRIP_VERSION};
use sha2::Digest;

const FOOTER: &str = "q\n0 0 612 792 re W n\nBT /F1 8 Tf 20 10 Td (Downloaded from www.Manualslib.com manuals search engine) Tj ET\nQ\n";
const PREAMBLE: &str = "q\n/GSa gs\n";

fn sha(b: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(b))
}

struct Builder {
    doc: Document,
    pages_id: ObjectId,
    font: ObjectId,
    kids: Vec<ObjectId>,
}

impl Builder {
    fn new() -> Self {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let font = doc.add_object(
            dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica" },
        );
        Builder {
            doc,
            pages_id,
            font,
            kids: vec![],
        }
    }

    fn stream(&mut self, data: &[u8], compress: bool, mut dict: Dictionary) -> ObjectId {
        let content = if compress {
            dict.set("Filter", "FlateDecode");
            openmanuals_strip::pdfio::deflate(data)
        } else {
            data.to_vec()
        };
        self.doc.add_object(Stream::new(dict, content))
    }

    fn page(&mut self, content: &str, fonts: bool, compress: bool) -> ObjectId {
        let c = self.stream(content.as_bytes(), compress, Dictionary::new());
        let mut res = Dictionary::new();
        if fonts {
            res.set("Font", dictionary! { "F1" => self.font });
        }
        let id = self.doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => self.pages_id, "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "Resources" => res, "Contents" => c,
        });
        self.kids.push(id);
        id
    }

    fn font_page(&mut self, content: &str) -> ObjectId {
        self.page(content, true, true)
    }

    fn set_xobject(&mut self, page: ObjectId, name: &str, xobj: ObjectId) {
        let d = self.doc.get_dictionary_mut(page).unwrap();
        let res = d.get_mut(b"Resources").unwrap().as_dict_mut().unwrap();
        if !res.has(b"XObject") {
            res.set("XObject", Dictionary::new());
        }
        res.get_mut(b"XObject")
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set(name, xobj);
    }

    fn add_link(&mut self, page: ObjectId, uri: &str) {
        let annot = self.doc.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Link", "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "A" => dictionary! { "S" => "URI", "URI" => Object::string_literal(uri) },
        });
        let d = self.doc.get_dictionary_mut(page).unwrap();
        if !d.has(b"Annots") {
            d.set("Annots", Vec::<Object>::new());
        }
        d.get_mut(b"Annots")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(annot.into());
    }

    fn finish(mut self) -> Vec<u8> {
        let kids: Vec<Object> = self.kids.iter().map(|&k| k.into()).collect();
        let n = kids.len() as i64;
        self.doc.objects.insert(
            self.pages_id,
            Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => kids, "Count" => n }),
        );
        let cat = self
            .doc
            .add_object(dictionary! { "Type" => "Catalog", "Pages" => self.pages_id });
        self.doc.trailer.set("Root", cat);
        let mut out = Vec::new();
        self.doc.save_to(&mut out).unwrap();
        out
    }
}

fn load(b: &[u8]) -> Document {
    Document::load_mem(b).unwrap()
}

fn texts(doc: &Document) -> Vec<String> {
    pages(doc)
        .iter()
        .map(|p| {
            String::from_utf8_lossy(&page_content(doc, doc.get_dictionary(p.id).unwrap()))
                .into_owned()
        })
        .collect()
}

/// A wrapped manual like ManualsLib produces: cover + TOC, N manual pages with footers, a back page.
fn wrapped_manual(manual_pages: usize, with_footers: bool) -> Vec<u8> {
    let mut b = Builder::new();
    let cover = b.font_page(&format!(
        "{PREAMBLE}BT /F1 24 Tf 100 700 Td (Quick Links) Tj ET\nQ\n"
    ));
    b.add_link(cover, "https://www.manualslib.com/manual/1/x.html");
    b.font_page(&format!(
        "{PREAMBLE}BT /F1 12 Tf 100 700 Td (Table of contents) Tj ET\nQ\n"
    ));
    let mut manual = vec![];
    for i in 0..manual_pages {
        let p = b.font_page(&format!(
            "BT /F1 12 Tf 72 700 Td (Manual page {}) Tj ET\n{}",
            i + 1,
            if with_footers { FOOTER } else { "" }
        ));
        if with_footers {
            b.add_link(p, "http://www.manualslib.com/");
        }
        b.add_link(p, "https://example.com/not-removed");
        manual.push(p);
    }
    let back = b.font_page(&format!(
        "{PREAMBLE}BT /F1 12 Tf 100 700 Td (Other ManualsLib Projects) Tj ET\nQ\n"
    ));
    b.add_link(back, "https://www.manualslib.de/");
    // An outline pointing at the cover (will dangle) and one at a manual page (kept).
    let outlines = b.doc.new_object_id();
    let item1 = b.doc.new_object_id();
    let item2 = b.doc.new_object_id();
    b.doc.objects.insert(item1, Object::Dictionary(dictionary! { "Title" => Object::string_literal("Cover"), "Parent" => outlines, "Next" => item2, "Dest" => vec![cover.into(), "Fit".into()] }));
    b.doc.objects.insert(item2, Object::Dictionary(dictionary! { "Title" => Object::string_literal("Chapter 1"), "Parent" => outlines, "Prev" => item1, "Dest" => vec![manual[0].into(), "Fit".into()] }));
    b.doc.objects.insert(
        outlines,
        Object::Dictionary(
            dictionary! { "Type" => "Outlines", "First" => item1, "Last" => item2, "Count" => 2 },
        ),
    );
    let bytes = b.finish();
    // Attach the outline to the catalog.
    let mut doc = load(&bytes);
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_dictionary_mut(root)
        .unwrap()
        .set("Outlines", outlines);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

#[test]
fn wrapper_pages_footers_and_manualslib_links_are_removed_outlines_pruned() {
    let input = wrapped_manual(3, true);
    let r = strip(&input).unwrap();
    assert!(r.changed);
    let doc = load(&r.bytes);
    let ps = pages(&doc);
    assert_eq!(ps.len(), 3);
    for (p, text) in ps.iter().zip(texts(&doc)) {
        assert!(text.contains("Manual page"));
        assert!(!text.contains("manuals search engine"));
        let annots = doc
            .get_dictionary(p.id)
            .unwrap()
            .get(b"Annots")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(annots.len(), 1, "the non-manualslib link survives");
    }
    let root = doc.catalog().unwrap();
    let outlines = doc
        .get_dictionary(root.get(b"Outlines").unwrap().as_reference().unwrap())
        .unwrap();
    let first = doc
        .get_dictionary(outlines.get(b"First").unwrap().as_reference().unwrap())
        .unwrap();
    assert_eq!(first.get(b"Title").unwrap().as_str().unwrap(), b"Chapter 1");
    assert!(first.get(b"Next").is_err());
    assert!(
        r.log.iter().any(|l| l.contains("2 leading and 1 trailing")),
        "{:?}",
        r.log
    );
    assert!(
        r.log
            .iter()
            .any(|l| l == "Removed the ManualsLib footer from 3 pages"),
        "{:?}",
        r.log
    );
    assert_eq!(STRIP_VERSION, "om-strip-rs/1");
}

#[test]
fn wrapper_detection_without_footers_uses_the_wkhtmltopdf_preamble() {
    let input = wrapped_manual(2, false);
    assert_eq!(find_manualslib_wrapper_pages(&load(&input)), (2, 1));
}

#[test]
fn a_run_that_covers_the_whole_file_is_not_a_wrapper() {
    let mut b = Builder::new();
    for _ in 0..3 {
        let p = b.font_page(&format!(
            "{PREAMBLE}BT /F1 12 Tf 100 700 Td (page) Tj ET\nQ\n"
        ));
        b.add_link(p, "https://www.manualslib.com/");
    }
    let bytes = b.finish();
    assert_eq!(find_manualslib_wrapper_pages(&load(&bytes)), (0, 0));
    let r = strip(&bytes).unwrap();
    assert_eq!(pages(&load(&r.bytes)).len(), 3, "never removes every page");
}

#[test]
fn a_clean_pdf_comes_back_unchanged_with_the_same_bytes() {
    let mut b = Builder::new();
    b.font_page("BT /F1 12 Tf 72 700 Td (Nothing to strip) Tj ET\n");
    let bytes = b.finish();
    let r = strip(&bytes).unwrap();
    assert!(!r.changed);
    assert_eq!(r.bytes, bytes);
}

#[test]
fn output_is_deterministic_and_stripping_is_idempotent() {
    let input = wrapped_manual(2, true);
    let a = strip(&input).unwrap();
    let b = strip(&input).unwrap();
    assert_eq!(sha(&a.bytes), sha(&b.bytes));
    let again = strip(&a.bytes).unwrap();
    assert!(!again.changed, "{:?}", again.log);
}

#[test]
fn unreadable_input_errors() {
    assert!(strip(&[1, 2, 3, 4]).is_err());
    assert!(strip(b"%PDF-1.4\nnot really a pdf").is_err());
    assert!(strip(b"").is_err());
}

#[test]
fn hostile_and_truncated_input_never_panics() {
    let good = wrapped_manual(3, true);
    // Every truncation of a real file, and some bit-flipped variants: an error
    // or a result, never a panic.
    let step = (good.len() / 97).max(1);
    for cut in (0..good.len()).step_by(step) {
        let _ = strip(&good[..cut]);
    }
    let mut state = 0x9e37_79b9u32;
    for _ in 0..200 {
        let mut b = good.clone();
        for _ in 0..8 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = (state as usize >> 4) % b.len();
            b[i] = (state >> 20) as u8;
        }
        let _ = strip(&b);
    }
    let garbage: &[&[u8]] = &[
        b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 1 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF",
        b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [2 0 R 3 0 R] /Count 2 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /Contents 3 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF",
        b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R /Outlines 4 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /Contents 5 0 R /Annots 6 0 R >> endobj\n4 0 obj << /First 4 0 R /Next 4 0 R >> endobj\n5 0 obj << /Length 999999 /Filter /FlateDecode >> stream\nxx\nendstream endobj\n6 0 obj [6 0 R << /A << /URI (http://manualslib.com) >> >>] endobj\ntrailer << /Root 1 0 R >>\n%%EOF",
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n",
        b"%PDF-1.4\ntrailer << /Root << /Pages << /Kids [ << >> ] >> >> >>\n%%EOF",
    ];
    for g in garbage {
        let _ = strip(g);
    }
}

#[test]
fn third_party_text_stamps_forms_emptied_inline_text_objects_cut() {
    let mut b = Builder::new();
    let form = dictionary! { "Type" => "XObject", "Subtype" => "Form", "BBox" => vec![0.into(), 0.into(), 100.into(), 20.into()] };
    let stamp_form = b.stream(
        b"BT /F1 6 Tf 10 10 Td (www.cxema.ru) Tj ET\n",
        true,
        form.clone(),
    );
    let big = format!(
        "BT /F1 6 Tf 10 10 Td (chinadse.org) Tj ET\n{}",
        "0 0 m 1 1 l S\n".repeat(400)
    );
    let big_form = b.stream(big.as_bytes(), true, form);
    for _ in 0..2 {
        let p = b.font_page("BT /F1 12 Tf 72 700 Td (Real text) Tj ET\n/Fm1 Do\n/Fm2 Do\nBT /F1 5 Tf 0 0 Td (all-guides.com) Tj ET\nBT /F1 12 Tf 72 600 Td (Kept) Tj ET\n");
        b.set_xobject(p, "Fm1", stamp_form);
        b.set_xobject(p, "Fm2", big_form);
    }
    let r = strip(&b.finish()).unwrap();
    assert!(r.changed);
    let out = load(&r.bytes);
    for (p, text) in pages(&out).iter().zip(texts(&out)) {
        assert!(!text.contains("all-guides"));
        assert!(text.contains("Kept"));
        assert!(text.contains("Real text"));
        let page = out.get_dictionary(p.id).unwrap();
        let xobjs = page
            .get(b"Resources")
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"XObject")
            .unwrap()
            .as_dict()
            .unwrap();
        let fm1 = out
            .get_object(xobjs.get(b"Fm1").unwrap().as_reference().unwrap())
            .unwrap()
            .as_stream()
            .unwrap();
        assert_eq!(
            fm1.decompressed_content().unwrap().len(),
            0,
            "stamp form emptied"
        );
        let fm2 = out
            .get_object(xobjs.get(b"Fm2").unwrap().as_reference().unwrap())
            .unwrap()
            .as_stream()
            .unwrap();
        assert!(
            fm2.decompressed_content().unwrap().len() > 2000,
            "a large form is not a stamp"
        );
    }
    assert!(
        r.log
            .iter()
            .any(|l| l.contains("third-party site stamps from 2 pages")),
        "{:?}",
        r.log
    );
}

/// Build a gray image whose dhash is exactly `bits`, scaled up by `sx`×`sy`.
fn image_for_hash(bits: u64, sx: usize, sy: usize) -> GrayImage {
    let (w, h) = (9, 8);
    let mut small = vec![0u8; w * h];
    for row in 0..8 {
        let mut v: i32 = 128;
        small[row * w] = v as u8;
        for col in 0..8 {
            let bit = (bits >> (63 - (row * 8 + col))) & 1;
            v += if bit == 1 { -14 } else { 14 };
            small[row * w + col + 1] = v as u8;
        }
    }
    let mut data = vec![0u8; w * sx * h * sy];
    for y in 0..h * sy {
        for x in 0..w * sx {
            data[y * w * sx + x] = small[(y / sy) * w + x / sx];
        }
    }
    GrayImage {
        width: w * sx,
        height: h * sy,
        data,
    }
}

fn gray_image_xobject(b: &mut Builder, img: &GrayImage) -> ObjectId {
    let dict = dictionary! { "Type" => "XObject", "Subtype" => "Image", "Width" => img.width as i64, "Height" => img.height as i64, "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8 };
    b.stream(&img.data, true, dict)
}

fn first_hash(m: &std::collections::BTreeMap<String, String>) -> u64 {
    u64::from_str_radix(m.keys().next().unwrap(), 16).unwrap()
}

fn raw_constants() -> constants::Raw {
    serde_json::from_str(constants::CONSTANTS_JSON).unwrap()
}

#[test]
fn dhash_round_trips_a_constructed_image_and_tolerates_scaling() {
    let target = first_hash(&raw_constants().junk_cover_hashes);
    assert_eq!(dhash(&image_for_hash(target, 1, 1)), target);
    assert!(hamming_distance(dhash(&image_for_hash(target, 10, 10)), target) <= 3);
    assert_eq!(hamming_distance(0, 0xff), 8);
}

#[test]
fn dhash_agrees_with_pil_on_reference_images() {
    // Same LCG as the Python reference run; expected values computed with PIL 12.
    let (w, h) = (64, 48);
    let mut data = vec![0u8; w * h];
    let mut state: u32 = 12345;
    for d in data.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
        *d = ((state >> 16) & 0xff) as u8;
    }
    assert!(
        hamming_distance(
            dhash(&GrayImage {
                width: w,
                height: h,
                data
            }),
            0x664c_e5ab_155c_eee6
        ) <= 4
    );
    let mut rgb = vec![0u8; 90 * 8];
    for y in 0..8 {
        for x in 0..90 {
            rgb[y * 90 + x] = luma(
                ((x * 2) % 256) as u8,
                ((y * 30) % 256) as u8,
                (((x + y) * 5) % 256) as u8,
            );
        }
    }
    assert!(
        hamming_distance(
            dhash(&GrayImage {
                width: 90,
                height: 8,
                data: rgb
            }),
            0x0808_0808_0808_1818
        ) <= 4
    );
    let id = image_for_hash(1, 1, 1);
    assert_eq!(resize_gray(&id, 9, 8).data, id.data, "identity resize");
}

#[test]
fn junk_cover_pages_are_dropped_and_banner_images_stop_being_drawn() {
    let raw = raw_constants();
    let cover_hash = first_hash(&raw.junk_cover_hashes);
    let banner_hash = first_hash(&raw.stamp_image_hashes);
    let mut b = Builder::new();
    let cover = b.page("q 612 0 0 792 0 0 cm /Im0 Do Q\n", false, true);
    let img = gray_image_xobject(&mut b, &image_for_hash(cover_hash, 20, 20));
    b.set_xobject(cover, "Im0", img);
    for _ in 0..2 {
        let p = b.font_page("BT /F1 12 Tf 72 700 Td (Manual) Tj ET\nq 300 0 0 30 0 0 cm /Im1 Do Q\nq 1 0 0 1 0 0 cm /Im2 Do Q\n");
        let im1 = gray_image_xobject(&mut b, &image_for_hash(banner_hash, 20, 2)); // 180x16: aspect 11
        let im2 = gray_image_xobject(&mut b, &image_for_hash(banner_hash, 2, 2)); // 18x16: too square to be a banner
        b.set_xobject(p, "Im1", im1);
        b.set_xobject(p, "Im2", im2);
    }
    let r = strip(&b.finish()).unwrap();
    let out = load(&r.bytes);
    assert_eq!(pages(&out).len(), 2);
    let do_re = |n: &str| constants::bytes_regex(&format!(r"/{n}\s+Do"), false, false).unwrap();
    for text in texts(&out) {
        assert!(
            !constants::is_match(&do_re("Im1"), text.as_bytes()),
            "{text}"
        );
        assert!(
            constants::is_match(&do_re("Im2"), text.as_bytes()),
            "{text}"
        );
    }
    assert!(
        r.log
            .iter()
            .any(|l| l.starts_with("Removed first page: esquemaseletricos")),
        "{:?}",
        r.log
    );
    assert!(
        r.log.iter().any(|l| l.contains("tecnicosaurios")),
        "{:?}",
        r.log
    );
}

#[test]
fn banner_names_only_match_whole_names() {
    // /Im1 must not match inside /Im10, nor /XIm1, and `Do` must be a whole word.
    let raw = raw_constants();
    let banner = first_hash(&raw.stamp_image_hashes);
    let mut b = Builder::new();
    let p = b.font_page(
        "BT /F1 12 Tf 72 700 Td (Manual) Tj ET\n/Im10 Do\n[/Im1 Do]\n/Im1 Dot\n/Im1\nDo\n",
    );
    let im1 = gray_image_xobject(&mut b, &image_for_hash(banner, 20, 2));
    let im10 = gray_image_xobject(&mut b, &image_for_hash(0, 2, 2));
    b.set_xobject(p, "Im1", im1);
    b.set_xobject(p, "Im10", im10);
    let r = strip(&b.finish()).unwrap();
    let text = &texts(&load(&r.bytes))[0];
    assert_eq!(
        text,
        "BT /F1 12 Tf 72 700 Td (Manual) Tj ET\n/Im10 Do\n[]\n/Im1 Dot\n\n"
    );
}

#[test]
fn python_regex_translation_keeps_the_manualslib_patterns_semantics() {
    let c = constants::get();
    assert!(constants::is_match(&c.footer, b"x\nq\n0 0 612 792 re W n\n(Downloaded from www.Manualslib.com manuals search engine)\nQ\ny"));
    assert!(
        constants::is_match(&c.footer, b"q \xa0\n0 0 1 1 re manuals search engine Q"),
        "latin-1 nbsp counts as whitespace, as in Python str regexes"
    );
    assert!(constants::is_match(
        &c.footer,
        b"q\x85\x1c\n0 0 1 1 re \xff manuals search engine Q"
    ));
    assert!(
        !constants::is_match(&c.footer, b"q \x80\n0 0 1 1 re manuals search engine Q"),
        "\\x80 is not whitespace"
    );
    assert!(constants::is_match(&c.preamble, b"q\n/GSa gs\n"));
    assert!(constants::is_match(&c.preamble, b"  /GSa gs"));
    assert!(constants::is_match(&c.preamble, b"\xa0/GSa gs"));
    assert!(!constants::is_match(&c.preamble, b"BT /GSa gs"));
    assert!(constants::is_match(
        &c.third_party,
        b"see ESQUEMASELETRICOS.COM.BR"
    ));
    // Bytes patterns: \s is ASCII only, \b is ASCII, `.` crosses newlines and high bytes.
    let cut = |s: &[u8]| constants::remove_all(&c.stamp_text_object, s);
    assert_eq!(
        cut(b"BT (a) Tj ET\nBT (\xe9 CXEMA.RU\n) Tj ET \nBT (b) Tj ET").unwrap(),
        b"BT (a) Tj ET\nBT (b) Tj ET"
    );
    assert_eq!(
        cut(b"BT (xETx cxema.ru) Tj ET\n").unwrap(),
        b"",
        "ET inside a word is not the end of the text object"
    );
    assert_eq!(
        cut(b"BT (a) ET BT (cxema.ru) ET"),
        Some(b"BT (a) ET ".to_vec()),
        "one text object, not two"
    );
    assert!(openmanuals_strip::is_manualslib_url("HTTP://WWW.MANUALSLIB.FR/x"));
    assert!(!openmanuals_strip::is_manualslib_url(
        "https://example.com/manualslib"
    ));
    // Translation: \s inside and outside classes, escaped backslashes untouched.
    let spec = |p: &str| constants::RegexSpec {
        pattern: p.into(),
        flags: String::new(),
        on: "text".into(),
    };
    assert_eq!(
        constants::translate(&spec(r"a\s[^\s]\\s")),
        r"a[\t\n\x0b\x0c\r \x1c-\x1f\x85\xa0][^\t\n\x0b\x0c\r \x1c-\x1f\x85\xa0]\\s"
    );
}

#[test]
fn utf16_link_uris_are_recognized() {
    let mut b = Builder::new();
    let p = b.font_page(&format!("BT /F1 12 Tf 72 700 Td (Manual) Tj ET\n{FOOTER}"));
    let mut uri = vec![0xfe, 0xff];
    for ch in "https://www.ManualsLib.com/".encode_utf16() {
        uri.extend_from_slice(&ch.to_be_bytes());
    }
    let annot = b.doc.add_object(dictionary! { "Type" => "Annot", "Subtype" => "Link", "A" => dictionary! { "S" => "URI", "URI" => Object::String(uri, lopdf::StringFormat::Hexadecimal) } });
    b.doc
        .get_dictionary_mut(p)
        .unwrap()
        .set("Annots", vec![annot.into()]);
    let r = strip(&b.finish()).unwrap();
    let out = load(&r.bytes);
    assert!(out
        .get_dictionary(pages(&out)[0].id)
        .unwrap()
        .get(b"Annots")
        .is_err());
    assert!(
        r.log
            .iter()
            .any(|l| l == "Removed 1 ManualsLib link annotations"),
        "{:?}",
        r.log
    );
}

#[test]
fn removed_pages_are_not_written() {
    let input = wrapped_manual(3, true);
    let r = strip(&input).unwrap();
    let text = String::from_utf8_lossy(&r.bytes);
    // The cover's link annotation object (only reachable from the removed page) is gone.
    assert!(!text.contains("manualslib.com/manual/1/x.html"));
    assert!(!text.contains("manualslib.de"));
}

#[test]
fn encrypted_with_the_empty_password_is_stripped_and_written_decrypted() {
    let input = wrapped_manual(3, true);
    let mut doc = load(&input);
    let id = Object::String(
        b"0123456789abcdef".to_vec(),
        lopdf::StringFormat::Hexadecimal,
    );
    doc.trailer.set("ID", vec![id.clone(), id]);
    let state = lopdf::EncryptionState::try_from(lopdf::EncryptionVersion::V2 {
        document: &doc,
        owner_password: "owner",
        user_password: "",
        key_length: 128,
        permissions: lopdf::Permissions::all(),
    })
    .unwrap();
    doc.encrypt(&state).unwrap();
    let mut enc = Vec::new();
    doc.save_to(&mut enc).unwrap();
    assert!(String::from_utf8_lossy(&enc).contains("/Encrypt"));
    let r = strip(&enc).unwrap();
    assert!(r.changed, "{:?}", r.log);
    assert!(
        r.log.iter().any(|l| l.contains("written decrypted")),
        "{:?}",
        r.log
    );
    assert!(!String::from_utf8_lossy(&r.bytes).contains("/Encrypt"));
    let out = load(&r.bytes);
    assert_eq!(pages(&out).len(), 3);
    assert!(texts(&out)
        .iter()
        .all(|t| t.contains("Manual page") && !t.contains("manuals search engine")));
}

#[test]
fn encrypted_with_a_user_password_is_left_unchanged() {
    let input = wrapped_manual(3, true);
    let mut doc = load(&input);
    let id = Object::String(
        b"0123456789abcdef".to_vec(),
        lopdf::StringFormat::Hexadecimal,
    );
    doc.trailer.set("ID", vec![id.clone(), id]);
    let state = lopdf::EncryptionState::try_from(lopdf::EncryptionVersion::V2 {
        document: &doc,
        owner_password: "owner",
        user_password: "secret",
        key_length: 128,
        permissions: lopdf::Permissions::all(),
    })
    .unwrap();
    doc.encrypt(&state).unwrap();
    let mut enc = Vec::new();
    doc.save_to(&mut enc).unwrap();
    let r = strip(&enc).unwrap();
    assert!(!r.changed);
    assert_eq!(r.bytes, enc);
}
