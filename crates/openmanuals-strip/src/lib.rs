//! Watermark stripper: removes what ManualsLib adds to a manual (wrapper
//! pages, the per-page footer, link annotations) and the marks of sites the
//! manual passed through before (text stamps, Acrobat header/footer
//! stamps, advert cover pages, banner images), using the detection constants in `constants.json`.
//!
//! Built on [lopdf]. Pure Rust; builds for `wasm32-unknown-unknown`, which is how the
//! browser extension runs it (`crates/openmanuals-strip-wasm`).
//!
//! ```no_run
//! let original = std::fs::read("manual.pdf").unwrap();
//! let r = openmanuals_strip::strip(&original).unwrap();
//! if r.changed { std::fs::write("stripped.pdf", &r.bytes).unwrap(); }
//! ```

pub mod constants;
pub mod image;
pub mod pdfio;

use lopdf::{Document, Object, ObjectId};
use pdfio::{dict_get, page_content, PageRef};
use std::collections::{HashMap, HashSet};

/// Tool name recorded on derivation facts.
pub const STRIP_TOOL: &str = "om-strip";
/// Identifies the algorithm and output layout; recorded on derivation facts as
/// `tool_version`. Distinct from `om-strip/1`, an earlier TypeScript port whose
/// output bytes differ. Bump whenever the output for any input can change
/// (constants included).
pub const STRIP_VERSION: &str = "om-strip-rs/2";

/// Bound on the Header & Footer settings read per piece (they're ~1 kB).
const MAX_PIECE_SETTINGS: usize = 64 * 1024;

/// Bound on an outline's nesting; deeper trees are left as they are.
const MAX_OUTLINE_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stripped {
    /// True when anything was removed; `bytes` is then the rewritten file.
    pub changed: bool,
    /// The stripped file when changed, otherwise the input bytes unchanged.
    pub bytes: Vec<u8>,
    /// Human-readable notes on what was removed (or why nothing could be).
    pub log: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input could not be parsed as a PDF; the caller keeps the original.
    Unreadable(String),
    /// The stripper hit an internal fault (a panic in a dependency on hostile input).
    Internal(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unreadable(e) => write!(f, "unreadable PDF: {e}"),
            Error::Internal(e) => write!(f, "stripper fault: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Remove ManualsLib wrapper pages, footers and link annotations, plus known
/// third-party stamps, from a PDF. Deterministic: same input bytes, same
/// output bytes. Errors on unreadable input; a PDF with nothing to strip
/// returns `changed: false` with the input bytes. An encrypted PDF is opened
/// with the empty user password and written decrypted, as pikepdf does; one
/// that needs a real password is returned unchanged.
pub fn strip(input: &[u8]) -> Result<Stripped, Error> {
    // lopdf aims never to panic, but hostile input has found panics in PDF
    // parsers before; never take the caller down with it (native targets
    // unwind; on wasm a panic aborts regardless).
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| strip_inner(input))) {
        Ok(r) => r,
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            Err(Error::Internal(msg))
        }
    }
}

fn unchanged(input: &[u8], log: Vec<String>) -> Result<Stripped, Error> {
    Ok(Stripped {
        changed: false,
        bytes: input.to_vec(),
        log,
    })
}

fn strip_inner(input: &[u8]) -> Result<Stripped, Error> {
    let c = constants::get();
    let opts = lopdf::LoadOptions {
        max_decompressed_size: Some(pdfio::MAX_DECODED),
        ..Default::default()
    };
    let mut doc = Document::load_mem_with_options(input, opts)
        .map_err(|e| Error::Unreadable(e.to_string()))?;
    if doc.trailer.has(b"Encrypt") {
        // lopdf removes /Encrypt once the empty password opens the file.
        return unchanged(
            input,
            vec!["Encrypted with a user password: left unchanged".into()],
        );
    }
    if pdfio::pages_root(&doc).is_none() {
        return Err(Error::Unreadable("no page tree".into()));
    }
    let was_encrypted = doc.encryption_state.is_some();

    let mut log = Vec::new();
    let mut modified = false;

    // 1. Wrapper pages (trailing first so indices stay valid).
    let (leading, trailing) = find_manualslib_wrapper_pages(&doc);
    if leading > 0 || trailing > 0 {
        let pages = pdfio::pages(&doc);
        let n = pages.len();
        for p in pages[n - trailing..]
            .iter()
            .rev()
            .chain(pages[..leading].iter())
        {
            pdfio::remove_page(&mut doc, p);
        }
        prune_dangling_outlines(&mut doc);
        modified = true;
        log.push(format!(
            "Removed {leading} leading and {trailing} trailing ManualsLib wrapper pages"
        ));
    }

    // 2. Known advert pages at either end.
    if remove_junk_cover_pages(&mut doc, &mut log) > 0 {
        prune_dangling_outlines(&mut doc);
        modified = true;
    }

    // 3. Third-party stamps: text objects and banner images.
    let stamped = strip_third_party_stamps(&mut doc) + strip_stamp_images(&mut doc, &mut log);
    if stamped > 0 {
        modified = true;
        log.push(format!(
            "Removed third-party site stamps from {stamped} pages"
        ));
    }

    // 4. Per page: ManualsLib link annotations and the footer block.
    let mut footers = 0;
    let mut links = 0;
    for p in pdfio::pages(&doc) {
        let Ok(node) = doc.get_dictionary(p.id) else {
            continue;
        };
        let mut new_annots = None;
        if let Some(Object::Array(annots)) = dict_get(&doc, node, b"Annots") {
            let kept: Vec<Object> = annots
                .iter()
                .filter(|a| !is_manualslib_link(&doc, a))
                .cloned()
                .collect();
            if kept.len() < annots.len() {
                links += annots.len() - kept.len();
                new_annots = Some(kept);
            }
        }
        let text = page_content(&doc, node);
        let cleaned = if text.is_empty() {
            None
        } else {
            constants::remove_all(&c.footer, &text)
        };
        if let Some(kept) = new_annots {
            modified = true;
            let node = doc.get_dictionary_mut(p.id).expect("page exists");
            if kept.is_empty() {
                node.remove(b"Annots");
            } else {
                node.set("Annots", Object::Array(kept));
            }
        }
        if let Some(cleaned) = cleaned {
            footers += 1;
            modified = true;
            let s = pdfio::make_stream(&mut doc, &cleaned);
            doc.get_dictionary_mut(p.id)
                .expect("page exists")
                .set("Contents", Object::Reference(s));
        }
    }
    if footers > 0 {
        log.push(format!(
            "Removed the ManualsLib footer from {footers} pages"
        ));
    }
    if links > 0 {
        log.push(format!("Removed {links} ManualsLib link annotations"));
    }

    if !modified {
        return unchanged(input, log);
    }
    if was_encrypted {
        log.push("Opened with the empty password; written decrypted".into());
    }
    Ok(Stripped {
        changed: true,
        bytes: save(doc)?,
        log,
    })
}

/// Serialize: only reachable objects, a classic cross-reference table, no
/// object streams, and a trailer reduced to /Root, /Info and /ID.
fn save(mut doc: Document) -> Result<Vec<u8>, Error> {
    let mut trailer = lopdf::Dictionary::new();
    for k in [&b"Root"[..], b"Info", b"ID"] {
        if let Ok(v) = doc.trailer.get(k) {
            trailer.set(k, v.clone());
        }
    }
    doc.trailer = trailer;
    pdfio::prune_unreachable(&mut doc);
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    if let Some(&(max, _)) = doc.objects.keys().next_back() {
        doc.max_id = max;
    }
    let mut out = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(out)
}

// ---- Links ------------------------------------------------------------------

/// A PDF text string as text: UTF-16BE with a BOM, UTF-8 with a BOM, else
/// one char per byte (PDFDocEncoding agrees with latin-1 on everything that
/// can spell a URL).
fn text_string(b: &[u8]) -> String {
    if b.starts_with(&[0xfe, 0xff]) {
        let units: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = b.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    b.iter().map(|&c| c as char).collect()
}

fn uri_of(doc: &Document, annot: &Object) -> Option<String> {
    let a = match pdfio::resolve(doc, annot)? {
        Object::Dictionary(d) => d,
        _ => return None,
    };
    let action = pdfio::dict_of(doc, a, b"A")?;
    match dict_get(doc, action, b"URI")? {
        Object::String(s, _) => Some(text_string(s)),
        Object::Name(n) => Some(format!("/{}", text_string(n))),
        _ => None,
    }
}

/// Any manualslib domain: the wrapper's back page links .de, .es, .fr, ...
pub fn is_manualslib_url(uri: &str) -> bool {
    uri.to_lowercase().contains("manualslib.")
}

fn is_manualslib_link(doc: &Document, annot: &Object) -> bool {
    uri_of(doc, annot).is_some_and(|u| is_manualslib_url(&u))
}

fn links_to_manualslib(doc: &Document, page: ObjectId) -> bool {
    let Ok(d) = doc.get_dictionary(page) else {
        return false;
    };
    match dict_get(doc, d, b"Annots") {
        Some(Object::Array(a)) => a.iter().any(|x| is_manualslib_link(doc, x)),
        _ => false,
    }
}

/// Count the wrapper pages ManualsLib adds: a cover and table of contents at
/// the front, an "Other ManualsLib Projects" page at the back. A page is a
/// candidate if it was rendered with wkhtmltopdf or, in files where ManualsLib
/// stamped its footer on the manual's pages, if it lacks that footer.
/// Candidates are removed only as a run at the very start (beginning with a
/// page linking to manualslib) or very end (containing such a link), never the
/// whole file. Returns (leading, trailing).
pub fn find_manualslib_wrapper_pages(doc: &Document) -> (usize, usize) {
    let c = constants::get();
    let pages = pdfio::pages(doc);
    let contents: Vec<Vec<u8>> = pages
        .iter()
        .map(|p| {
            doc.get_dictionary(p.id)
                .map(|d| page_content(doc, d))
                .unwrap_or_default()
        })
        .collect();
    let footer: Vec<bool> = contents
        .iter()
        .map(|t| constants::is_match(&c.footer, t))
        .collect();
    let has_footers = footer.iter().any(|&f| f);
    let candidate: Vec<bool> = contents
        .iter()
        .zip(&footer)
        .map(|(t, &f)| constants::is_match(&c.preamble, t) || (has_footers && !f))
        .collect();
    let n = candidate.len();

    let mut leading = 0;
    while leading < n && candidate[leading] {
        leading += 1;
    }
    let mut trailing = 0;
    while trailing < n - leading && candidate[n - 1 - trailing] {
        trailing += 1;
    }
    if leading + trailing >= n {
        return (0, 0); // the whole file matches: not a wrapped manual
    }
    if !(leading > 0 && leading <= c.max_wrapper_pages && links_to_manualslib(doc, pages[0].id)) {
        leading = 0;
    }
    if !(trailing > 0
        && trailing <= c.max_wrapper_pages
        && pages[n - trailing..]
            .iter()
            .any(|p| links_to_manualslib(doc, p.id)))
    {
        trailing = 0;
    }
    (leading, trailing)
}

// ---- Outlines ---------------------------------------------------------------

struct OutlineItem {
    id: ObjectId,
    children: Vec<OutlineItem>,
    closed: bool,
}

/// `None` when the outline is deeper than `MAX_OUTLINE_DEPTH`.
fn read_outline_level(
    doc: &Document,
    parent: ObjectId,
    visited: &mut HashSet<ObjectId>,
    depth: usize,
) -> Option<Vec<OutlineItem>> {
    if depth > MAX_OUTLINE_DEPTH {
        return None;
    }
    let mut items = Vec::new();
    let mut cur = doc
        .get_dictionary(parent)
        .ok()?
        .get(b"First")
        .ok()
        .and_then(|o| o.as_reference().ok());
    while let Some(id) = cur {
        let Ok(dict) = doc.get_dictionary(id) else {
            break;
        };
        if !visited.insert(id) {
            break;
        }
        let closed = dict_get(doc, dict, b"Count")
            .and_then(pdfio::num_of)
            .is_some_and(|n| n < 0.0);
        let children = read_outline_level(doc, id, visited, depth + 1)?;
        items.push(OutlineItem {
            id,
            children,
            closed,
        });
        cur = dict.get(b"Next").ok().and_then(|o| o.as_reference().ok());
    }
    Some(items)
}

/// Visible descendants per the PDF spec's /Count semantics.
fn write_outline_level(doc: &mut Document, parent: ObjectId, items: &[OutlineItem]) -> i64 {
    let Ok(p) = doc.get_dictionary_mut(parent) else {
        return 0;
    };
    if items.is_empty() {
        p.remove(b"First");
        p.remove(b"Last");
        p.remove(b"Count");
        return 0;
    }
    p.set("First", Object::Reference(items[0].id));
    p.set("Last", Object::Reference(items[items.len() - 1].id));
    let mut visible = items.len() as i64;
    for (i, it) in items.iter().enumerate() {
        let below = write_outline_level(doc, it.id, &it.children);
        let Ok(d) = doc.get_dictionary_mut(it.id) else {
            continue;
        };
        d.set("Parent", Object::Reference(parent));
        if i > 0 {
            d.set("Prev", Object::Reference(items[i - 1].id));
        } else {
            d.remove(b"Prev");
        }
        if i + 1 < items.len() {
            d.set("Next", Object::Reference(items[i + 1].id));
        } else {
            d.remove(b"Next");
        }
        if below > 0 {
            d.set("Count", if it.closed { -below } else { below });
            if !it.closed {
                visible += below;
            }
        } else {
            d.remove(b"Count");
        }
    }
    visible
}

/// Drop bookmarks that no longer point at a page (the wrapper adds one for its cover).
pub fn prune_dangling_outlines(doc: &mut Document) {
    let Some(cat_id) = doc
        .trailer
        .get(b"Root")
        .ok()
        .and_then(|o| o.as_reference().ok())
    else {
        return;
    };
    let root = match doc
        .get_dictionary(cat_id)
        .ok()
        .and_then(|c| c.get(b"Outlines").ok())
    {
        Some(Object::Reference(r)) => *r,
        Some(Object::Dictionary(d)) => {
            let d = d.clone();
            let id = doc.add_object(Object::Dictionary(d));
            if let Ok(c) = doc.get_dictionary_mut(cat_id) {
                c.set("Outlines", Object::Reference(id));
            }
            id
        }
        _ => return,
    };
    if doc.get_dictionary(root).is_err() {
        return;
    }
    let pages: HashSet<ObjectId> = pdfio::pages(doc).into_iter().map(|p| p.id).collect();
    let resolves = |doc: &Document, item: &OutlineItem| -> bool {
        let Ok(d) = doc.get_dictionary(item.id) else {
            return false;
        };
        let mut dest = dict_get(doc, d, b"Dest").filter(|o| !matches!(o, Object::Null));
        if dest.is_none() {
            if let Some(action) = pdfio::dict_of(doc, d, b"A") {
                if pdfio::name_of(dict_get(doc, action, b"S")) == Some(b"GoTo") {
                    dest = dict_get(doc, action, b"D");
                }
            }
        }
        match dest {
            Some(Object::Array(a)) => a
                .first()
                .and_then(|o| o.as_reference().ok())
                .is_some_and(|r| pages.contains(&r)),
            _ => false,
        }
    };
    fn prune(
        doc: &Document,
        items: Vec<OutlineItem>,
        resolves: &dyn Fn(&Document, &OutlineItem) -> bool,
    ) -> Vec<OutlineItem> {
        items
            .into_iter()
            .filter(|it| resolves(doc, it))
            .map(|mut it| {
                it.children = prune(doc, std::mem::take(&mut it.children), resolves);
                it
            })
            .collect()
    }
    let Some(items) = read_outline_level(doc, root, &mut HashSet::new(), 0) else {
        return;
    };
    let items = prune(doc, items, &resolves);
    if items.is_empty() {
        if let Ok(c) = doc.get_dictionary_mut(cat_id) {
            c.remove(b"Outlines");
        }
        return;
    }
    let count = write_outline_level(doc, root, &items);
    if let Ok(r) = doc.get_dictionary_mut(root) {
        r.set("Count", count);
    }
}

// ---- Image-based detection ----------------------------------------------------

/// The page's only image, if the page is nothing but that image (no text anywhere).
fn sole_image(doc: &Document, page: ObjectId) -> Option<ObjectId> {
    let d = doc.get_dictionary(page).ok()?;
    if pdfio::has_fonts(doc, d, 0) {
        return None;
    }
    let images: Vec<_> = pdfio::walk_xobjects(doc, d)
        .into_iter()
        .filter(|e| {
            pdfio::get_stream(doc, e.id).and_then(|s| pdfio::subtype(doc, s)) == Some(b"Image")
        })
        .collect();
    (images.len() == 1).then(|| images[0].id)
}

fn junk_cover(doc: &Document, page: ObjectId) -> Option<String> {
    let c = constants::get();
    let img = pdfio::get_stream(doc, sole_image(doc, page)?)?;
    let h = image::dhash(&image::decode_image_to_gray(doc, img)?);
    c.junk_cover_hashes
        .iter()
        .find(|(k, _)| image::hamming_distance(h, *k) <= c.junk_cover_max_distance)
        .map(|(_, l)| l.clone())
}

/// Drop known advert pages from the front and back of the file. Returns pages removed.
fn remove_junk_cover_pages(doc: &mut Document, log: &mut Vec<String>) -> usize {
    let mut removed = 0;
    for first in [true, false] {
        loop {
            let pages = pdfio::pages(doc);
            if pages.len() <= 1 {
                break;
            }
            let p: &PageRef = if first {
                &pages[0]
            } else {
                &pages[pages.len() - 1]
            };
            let Some(label) = junk_cover(doc, p.id) else {
                break;
            };
            log.push(format!(
                "Removed {} page: {label}",
                if first { "first" } else { "last" }
            ));
            pdfio::remove_page(doc, p);
            removed += 1;
        }
    }
    removed
}

fn stamp_image_label(doc: &Document, id: ObjectId) -> Option<String> {
    let c = constants::get();
    let s = pdfio::get_stream(doc, id)?;
    let (w, h) = image::image_size(doc, s);
    if h == 0.0 || w / h < c.stamp_image_min_aspect {
        return None;
    }
    let hash = image::dhash(&image::decode_image_to_gray(doc, s)?);
    c.stamp_image_hashes
        .iter()
        .find(|(k, _)| image::hamming_distance(hash, *k) <= c.stamp_image_max_distance)
        .map(|(_, l)| l.clone())
}

// ---- Third-party stamps --------------------------------------------------------

/// Blank the text stamps of sites like cxema.ru. A stamp drawn via a Form
/// XObject is emptied; one inline in the page content has its text object cut
/// out. Returns the number of pages changed.
fn strip_third_party_stamps(doc: &mut Document) -> usize {
    let c = constants::get();
    let max = c.max_stamp_form_bytes;
    let mut changed = 0;
    let mut emptied: HashSet<ObjectId> = HashSet::new();
    // Stampings (see `pagination_piece`) that put a known site's address on a page.
    let mut stamped_with: HashSet<Vec<u8>> = HashSet::new();
    for p in pdfio::pages(doc) {
        let mut page_changed = false;
        let Ok(node) = doc.get_dictionary(p.id) else {
            continue;
        };
        let mut to_empty = Vec::new();
        // Acrobat header/footer pieces on this page, by the stamping they came from.
        let mut pieces: Vec<(ObjectId, Vec<u8>)> = Vec::new();
        for e in pdfio::walk_xobjects(doc, node) {
            let Some(s) = pdfio::get_stream(doc, e.id) else {
                continue;
            };
            if pdfio::subtype(doc, s) != Some(b"Form") {
                continue;
            }
            if emptied.contains(&e.id) {
                page_changed = true; // shares a stamp form already blanked
                continue;
            }
            if pdfio::stream_length(doc, s).unwrap_or((max + 1) as f64) > (max * 4) as f64 {
                continue;
            }
            let Some(data) = pdfio::read_stream(s) else {
                continue;
            };
            let piece = pagination_piece(doc, s);
            if data.len() <= max && constants::is_match(&c.third_party, &data) {
                to_empty.push(e.id);
            } else if let Some(stamping) = piece.clone() {
                pieces.push((e.id, stamping));
            }
            if let (Some(stamping), true) = (piece, to_empty.last() == Some(&e.id)) {
                stamped_with.insert(stamping);
            }
        }
        // A site that stamps its address with Acrobat's Header & Footer adds
        // more lines in the same go ("Not for sale!", a date): those pieces
        // share the stamped one's modification time, so they go too.
        for (id, stamping) in pieces {
            if stamped_with.contains(&stamping) && !to_empty.contains(&id) {
                to_empty.push(id);
            }
        }
        let text = page_content(doc, node);
        let cleaned = if !text.is_empty() && constants::is_match(&c.third_party, &text) {
            constants::remove_all(&c.stamp_text_object, &text)
        } else {
            None
        };
        for id in to_empty {
            if emptied.insert(id) {
                pdfio::rewrite_stream(doc, id, b"");
                // Acrobat's record of the stamping (its settings name the site too).
                if let Ok(Object::Stream(st)) = doc.get_object_mut(id) {
                    st.dict.remove(b"PieceInfo");
                }
            }
            page_changed = true;
        }
        if let Some(cleaned) = cleaned {
            let s = pdfio::make_stream(doc, &cleaned);
            doc.get_dictionary_mut(p.id)
                .expect("page exists")
                .set("Contents", Object::Reference(s));
            page_changed = true;
        }
        if page_changed {
            changed += 1;
        }
    }
    changed
}

/// For a form XObject that Acrobat's Header & Footer (or Watermark) tool
/// added, the stamping it came from, as bytes shared by every piece added in
/// one go: the tool's settings (`/DocSettings`, an XML stream naming every
/// line), else the `/LastModified` time. (Times are no good in an encrypted
/// file: lopdf leaves strings inside stream dictionaries encrypted, under a
/// different key for each object.) `None` for any other form.
fn pagination_piece(doc: &Document, s: &lopdf::Stream) -> Option<Vec<u8>> {
    let compound = pdfio::dict_of(doc, pdfio::dict_of(doc, &s.dict, b"PieceInfo")?, b"ADBE_CompoundType")?;
    let private = pdfio::name_of(dict_get(doc, compound, b"Private"))?;
    if !matches!(private, b"Header" | b"Footer" | b"Watermark") {
        return None;
    }
    if let Some(Object::Stream(settings)) = dict_get(doc, compound, b"DocSettings") {
        if let Ok(xml) = pdfio::decode_filters(settings, MAX_PIECE_SETTINGS) {
            if !xml.is_empty() {
                return Some(xml);
            }
        }
    }
    match dict_get(doc, compound, b"LastModified").or_else(|| dict_get(doc, &s.dict, b"LastModified"))? {
        Object::String(t, _) if !t.is_empty() && doc.encryption_state.is_none() => Some(t.clone()),
        _ => None,
    }
}

/// Python's `re.sub(rb'(?<![^\s\[\]()<>{}/%])' + re.escape(name) + rb'\s+Do\b', b'', data)`
/// for each name in turn: the name (with its slash) preceded by nothing,
/// whitespace or a delimiter, then whitespace, then the `Do` operator.
fn strip_do(data: &[u8], names: &[Vec<u8>]) -> Vec<u8> {
    let ws = |b: u8| matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ');
    let mut data = data.to_vec();
    for name in names {
        let mut lit = vec![b'/'];
        lit.extend_from_slice(name);
        let mut spans = Vec::new();
        let mut i = 0;
        while let Some(off) = find(&data[i..], &lit) {
            let start = i + off;
            let ok_before =
                start == 0 || ws(data[start - 1]) || b"[]()<>{}/%".contains(&data[start - 1]);
            let mut j = start + lit.len();
            let ws_start = j;
            while j < data.len() && ws(data[j]) {
                j += 1;
            }
            let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
            if ok_before
                && j > ws_start
                && data[j..].starts_with(b"Do")
                && data.get(j + 2).is_none_or(|&b| !word(b))
            {
                spans.push((start, j + 2));
                i = j + 2;
            } else {
                i = start + 1;
            }
        }
        if let Some(next) = constants::cut_spans(&data, &spans) {
            data = next;
        }
    }
    data
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        let off = hay[i..hay.len() - needle.len() + 1]
            .iter()
            .position(|&b| b == first)?;
        if hay[i + off..].starts_with(needle) {
            return Some(i + off);
        }
        i += off + 1;
    }
    None
}

/// Stop drawing known banner images: every `/Name Do` that paints one is
/// removed from the page or form that paints it. Returns pages changed.
fn strip_stamp_images(doc: &mut Document, log: &mut Vec<String>) -> usize {
    let mut verdicts: HashMap<ObjectId, Option<String>> = HashMap::new();
    let mut labels: Vec<String> = Vec::new();
    let mut cleaned_forms: HashSet<ObjectId> = HashSet::new();

    let mut stamp_names = |doc: &Document, container: &lopdf::Dictionary| -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        for e in pdfio::direct_xobjects(doc, container) {
            let Some(s) = pdfio::get_stream(doc, e.id) else {
                continue;
            };
            if pdfio::subtype(doc, s) != Some(b"Image") {
                continue;
            }
            let v = verdicts
                .entry(e.id)
                .or_insert_with(|| stamp_image_label(doc, e.id));
            if let Some(l) = v {
                if !labels.contains(l) {
                    labels.push(l.clone());
                }
                names.push(e.name.clone());
            }
        }
        names
    };

    let mut changed = 0;
    for p in pdfio::pages(doc) {
        let mut page_changed = false;
        let Ok(node) = doc.get_dictionary(p.id) else {
            continue;
        };
        let names = stamp_names(doc, node);
        let mut new_content = None;
        if !names.is_empty() {
            let text = page_content(doc, node);
            if !text.is_empty() {
                let cleaned = strip_do(&text, &names);
                if cleaned != text {
                    new_content = Some(cleaned);
                }
            }
        }
        let mut form_rewrites = Vec::new();
        for e in pdfio::walk_xobjects(doc, node) {
            let Some(s) = pdfio::get_stream(doc, e.id) else {
                continue;
            };
            if pdfio::subtype(doc, s) != Some(b"Form") {
                continue;
            }
            if cleaned_forms.contains(&e.id) {
                page_changed = true;
                continue;
            }
            let form_names = stamp_names(doc, &s.dict);
            if form_names.is_empty() {
                continue;
            }
            let Some(data) = pdfio::read_stream(s) else {
                continue;
            };
            let cleaned = strip_do(&data, &form_names);
            if cleaned != data {
                form_rewrites.push((e.id, cleaned));
            }
        }
        if let Some(content) = new_content {
            let s = pdfio::make_stream(doc, &content);
            doc.get_dictionary_mut(p.id)
                .expect("page exists")
                .set("Contents", Object::Reference(s));
            page_changed = true;
        }
        for (id, data) in form_rewrites {
            if cleaned_forms.insert(id) {
                pdfio::rewrite_stream(doc, id, &data);
            }
            page_changed = true;
        }
        if page_changed {
            changed += 1;
        }
    }
    for l in labels {
        log.push(format!("Removed stamp image: {l}"));
    }
    changed
}

// ---- Inspection (for tests and tools) ---------------------------------------

/// What the stripper sees in a file: page count, the wrapper run it would
/// remove, and how many ManualsLib footers and links are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inspection {
    pub pages: usize,
    /// Wrapper pages at the front and back (`find_manualslib_wrapper_pages`).
    pub wrapper: (usize, usize),
    /// Pages whose content carries the ManualsLib footer.
    pub footer_pages: usize,
    /// Link annotations to any manualslib domain, over all pages.
    pub manualslib_links: usize,
}

/// Inspect a PDF without changing it. Errors on unreadable input.
pub fn inspect(input: &[u8]) -> Result<Inspection, Error> {
    let doc = Document::load_mem(input).map_err(|e| Error::Unreadable(e.to_string()))?;
    let c = constants::get();
    let pages = pdfio::pages(&doc);
    let mut footer_pages = 0;
    let mut manualslib_links = 0;
    for p in &pages {
        let Ok(d) = doc.get_dictionary(p.id) else {
            continue;
        };
        if constants::is_match(&c.footer, &page_content(&doc, d)) {
            footer_pages += 1;
        }
        if let Some(Object::Array(annots)) = dict_get(&doc, d, b"Annots") {
            manualslib_links += annots
                .iter()
                .filter(|a| is_manualslib_link(&doc, a))
                .count();
        }
    }
    Ok(Inspection {
        pages: pages.len(),
        wrapper: find_manualslib_wrapper_pages(&doc),
        footer_pages,
        manualslib_links,
    })
}
