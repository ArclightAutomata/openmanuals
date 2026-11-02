//! Low-level helpers over lopdf's object model: stream reading and rewriting,
//! resource walking, the page tree.

use lopdf::{Dictionary, Document, Object, ObjectId, Stream};
use std::collections::HashSet;
use std::io::Write;

/// Cap on any single decoded stream (decompression bombs).
pub const MAX_DECODED: usize = 512 << 20;

/// Follow references (bounded by lopdf) to the object itself.
pub fn resolve<'a>(doc: &'a Document, o: &'a Object) -> Option<&'a Object> {
    doc.dereference(o).ok().map(|(_, o)| o)
}

/// `d[key]`, references followed.
pub fn dict_get<'a>(doc: &'a Document, d: &'a Dictionary, key: &[u8]) -> Option<&'a Object> {
    resolve(doc, d.get(key).ok()?)
}

pub fn dict_of<'a>(doc: &'a Document, d: &'a Dictionary, key: &[u8]) -> Option<&'a Dictionary> {
    match dict_get(doc, d, key)? {
        Object::Dictionary(d) => Some(d),
        _ => None,
    }
}

pub fn num_of(o: &Object) -> Option<f64> {
    match o {
        Object::Integer(i) => Some(*i as f64),
        Object::Real(r) => Some(*r as f64),
        _ => None,
    }
}

pub fn name_of(o: Option<&Object>) -> Option<&[u8]> {
    match o? {
        Object::Name(n) => Some(n),
        _ => None,
    }
}

/// The dictionary of a page node (dict) or a form (stream).
pub fn container_dict(o: &Object) -> Option<&Dictionary> {
    match o {
        Object::Dictionary(d) => Some(d),
        Object::Stream(s) => Some(&s.dict),
        _ => None,
    }
}

/// Decoded bytes of a stream through all its filters, bounded by `limit`.
/// Errors for unsupported filters (DCT, JPX, ...) or damaged data.
pub fn decode_filters(s: &Stream, limit: usize) -> lopdf::Result<Vec<u8>> {
    match s.filters() {
        Ok(f) if !f.is_empty() => s.decompressed_content_with_limit(limit),
        _ if s.content.len() > limit => Err(lopdf::Error::InvalidStream("stream too large".into())),
        _ => Ok(s.content.clone()),
    }
}

/// Decoded bytes of a stream, or `None` when the filter is unsupported or the data is damaged.
pub fn read_stream(s: &Stream) -> Option<Vec<u8>> {
    decode_filters(s, MAX_DECODED).ok()
}

/// The declared /Length of a stream.
pub fn stream_length(doc: &Document, s: &Stream) -> Option<f64> {
    dict_get(doc, &s.dict, b"Length").and_then(num_of)
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(
        Vec::with_capacity(data.len() / 4 + 64),
        flate2::Compression::default(),
    );
    // Writing to a Vec cannot fail.
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

/// A new flate-compressed stream with `data`, added to the document.
pub fn make_stream(doc: &mut Document, data: &[u8]) -> ObjectId {
    let mut dict = Dictionary::new();
    dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
    doc.add_object(Object::Stream(Stream::new(dict, deflate(data))))
}

/// Replace a stream's data in place (same object id, same dictionary apart
/// from the filters), like pikepdf's `Stream.write`; flate-compressed.
pub fn rewrite_stream(doc: &mut Document, id: ObjectId, data: &[u8]) {
    if let Ok(Object::Stream(s)) = doc.get_object_mut(id) {
        for k in [&b"Filter"[..], b"DecodeParms", b"DP", b"F"] {
            s.dict.remove(k);
        }
        s.dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        s.set_content(deflate(data));
    }
}

/// The page's decoded content, array parts concatenated without a separator
/// (like pikepdf), or empty when absent or undecodable.
pub fn page_content(doc: &Document, page: &Dictionary) -> Vec<u8> {
    let read = |o: &Object| match resolve(doc, o) {
        Some(Object::Stream(s)) => read_stream(s),
        _ => None,
    };
    match page.get(b"Contents").ok().and_then(|c| resolve(doc, c)) {
        Some(Object::Array(parts)) => {
            let mut out = Vec::new();
            for p in parts {
                match read(p) {
                    Some(d) => out.extend_from_slice(&d),
                    None => return Vec::new(),
                }
            }
            out
        }
        Some(Object::Stream(s)) => read_stream(s).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// One entry of a /Resources /XObject dictionary. Only indirect XObjects are
/// considered (streams are always indirect in a well-formed file).
#[derive(Clone, Debug)]
pub struct XObjectEntry {
    pub name: Vec<u8>,
    pub id: ObjectId,
}

pub fn subtype<'a>(doc: &'a Document, s: &'a Stream) -> Option<&'a [u8]> {
    name_of(dict_get(doc, &s.dict, b"Subtype"))
}

pub fn get_stream(doc: &Document, id: ObjectId) -> Option<&Stream> {
    match doc.get_object(id).ok()? {
        Object::Stream(s) => Some(s),
        _ => None,
    }
}

/// Direct (non-nested) XObject entries of a page or form dictionary.
pub fn direct_xobjects(doc: &Document, container: &Dictionary) -> Vec<XObjectEntry> {
    let mut out = Vec::new();
    let Some(xobjs) =
        dict_of(doc, container, b"Resources").and_then(|r| dict_of(doc, r, b"XObject"))
    else {
        return out;
    };
    for (name, raw) in xobjs.iter() {
        let Ok((Some(id), Object::Stream(_))) = doc.dereference(raw) else {
            continue;
        };
        out.push(XObjectEntry {
            name: name.clone(),
            id,
        });
    }
    out
}

/// Every XObject reachable from a page or form, nested forms included (depth ≤ 6).
pub fn walk_xobjects(doc: &Document, container: &Dictionary) -> Vec<XObjectEntry> {
    let mut out = Vec::new();
    walk_inner(doc, container, &mut HashSet::new(), 0, &mut out);
    out
}

fn walk_inner(
    doc: &Document,
    container: &Dictionary,
    visited: &mut HashSet<ObjectId>,
    depth: usize,
    out: &mut Vec<XObjectEntry>,
) {
    if depth > 6 {
        return;
    }
    for e in direct_xobjects(doc, container) {
        if !visited.insert(e.id) {
            continue;
        }
        out.push(e.clone());
        if let Some(s) = get_stream(doc, e.id) {
            if subtype(doc, s) == Some(b"Form") {
                walk_inner(doc, &s.dict, visited, depth + 1, out);
            }
        }
    }
}

pub fn has_fonts(doc: &Document, container: &Dictionary, depth: usize) -> bool {
    let Some(resources) = dict_of(doc, container, b"Resources") else {
        return false;
    };
    if depth > 6 {
        return false;
    }
    if dict_of(doc, resources, b"Font").is_some_and(|f| !f.is_empty()) {
        return true;
    }
    walk_xobjects(doc, container)
        .iter()
        .any(|e| match get_stream(doc, e.id) {
            Some(s) => subtype(doc, s) == Some(b"Form") && has_fonts(doc, &s.dict, depth + 1),
            None => false,
        })
}

/// A page and the chain of page-tree nodes above it (root first).
#[derive(Clone, Debug)]
pub struct PageRef {
    pub id: ObjectId,
    pub ancestors: Vec<ObjectId>,
}

pub fn pages_root(doc: &Document) -> Option<ObjectId> {
    let root = resolve(doc, doc.trailer.get(b"Root").ok()?)?;
    let Object::Dictionary(cat) = root else {
        return None;
    };
    cat.get(b"Pages").ok()?.as_reference().ok()
}

/// The pages in document order. As qpdf does, a node with a /Kids array is an
/// intermediate node and any other is a page; cycles, repeated nodes and
/// direct (non-reference) kids are skipped.
pub fn pages(doc: &Document) -> Vec<PageRef> {
    let mut out = Vec::new();
    let Some(root) = pages_root(doc) else {
        return out;
    };
    let mut seen = HashSet::new();
    // Explicit stack of (node, ancestors) in reverse order of visit.
    let mut stack: Vec<(ObjectId, Vec<ObjectId>)> = vec![(root, Vec::new())];
    while let Some((id, ancestors)) = stack.pop() {
        if !seen.insert(id) || ancestors.len() > 256 {
            continue;
        }
        let Ok(Object::Dictionary(d)) = doc.get_object(id) else {
            continue;
        };
        match dict_get(doc, d, b"Kids") {
            Some(Object::Array(kids)) => {
                let mut path = ancestors.clone();
                path.push(id);
                for k in kids.iter().rev() {
                    if let Ok(kid) = k.as_reference() {
                        stack.push((kid, path.clone()));
                    }
                }
            }
            _ if !ancestors.is_empty() => out.push(PageRef { id, ancestors }),
            _ => {}
        }
    }
    out
}

/// Remove a page from its parent's /Kids and decrement /Count up the tree.
pub fn remove_page(doc: &mut Document, page: &PageRef) {
    let Some(&parent) = page.ancestors.last() else {
        return;
    };
    // /Kids may be indirect.
    let kids_ref = match doc
        .get_dictionary(parent)
        .ok()
        .and_then(|d| d.get(b"Kids").ok())
    {
        Some(Object::Reference(r)) => Some(*r),
        _ => None,
    };
    let kids = match kids_ref {
        Some(r) => doc.get_object_mut(r).ok(),
        None => doc
            .get_dictionary_mut(parent)
            .ok()
            .and_then(|d| d.get_mut(b"Kids").ok()),
    };
    if let Some(Object::Array(kids)) = kids {
        if let Some(i) = kids
            .iter()
            .position(|k| k.as_reference().ok() == Some(page.id))
        {
            kids.remove(i);
        }
    }
    for &a in &page.ancestors {
        if let Ok(d) = doc.get_dictionary_mut(a) {
            if let Ok(Object::Integer(c)) = d.get(b"Count") {
                let c = *c;
                d.set("Count", (c - 1).max(0));
            }
        }
    }
}

/// Drop objects no longer reachable from the trailer (pikepdf/qpdf write only
/// reachable objects).
pub fn prune_unreachable(doc: &mut Document) {
    fn refs(o: &Object, out: &mut Vec<ObjectId>) {
        match o {
            Object::Reference(r) => out.push(*r),
            Object::Array(a) => a.iter().for_each(|x| refs(x, out)),
            Object::Dictionary(d) => d.iter().for_each(|(_, x)| refs(x, out)),
            Object::Stream(s) => s.dict.iter().for_each(|(_, x)| refs(x, out)),
            _ => {}
        }
    }
    let mut seen = HashSet::new();
    let mut stack = Vec::new();
    doc.trailer.iter().for_each(|(_, x)| refs(x, &mut stack));
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(o) = doc.objects.get(&id) {
            refs(o, &mut stack);
        }
    }
    doc.objects.retain(|id, _| seen.contains(id));
}
