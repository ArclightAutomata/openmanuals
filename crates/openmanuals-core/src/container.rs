//! Zip files of documents. Some sites serve a manual as a zip (chapters,
//! schematics and board layouts as separate PDFs). Such a zip is kept as it
//! is, so its hash is the site's, but only when it holds nothing else:
//! every file inside must sniff as PDF or DjVu. Anything that could hide
//! something else is refused: encryption, links, unsafe paths, nested
//! archives, compression methods other than stored and deflate, and sizes
//! that look like a zip bomb.

use crate::sniff::{sniff, FileType, SNIFF_BYTES};
use std::io::{Read, Seek};

/// At most this many entries (files and folders).
pub const MAX_ENTRIES: usize = 2000;
/// At most this many bytes, all files unpacked, as the zip declares them.
pub const MAX_UNPACKED: u64 = 4 << 30;
/// A file that unpacks to more than this many times its packed size, past
/// 1 MiB, is taken for a zip bomb. Scanned pages compress far less.
pub const MAX_RATIO: u64 = 200;

/// One document in the zip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Its path inside the zip, `/`-separated.
    pub name: String,
    /// Unpacked size in bytes, as the zip declares it.
    pub size: u64,
    pub file_type: FileType,
}

/// The documents in a zip, in the zip's order, or why it's refused.
pub fn zip_documents<R: Read + Seek>(r: R) -> Result<Vec<Member>, String> {
    let mut z = zip::ZipArchive::new(r).map_err(|e| format!("not a readable zip: {e}"))?;
    if z.len() > MAX_ENTRIES {
        return Err(format!("more than {MAX_ENTRIES} entries"));
    }
    let mut out = Vec::new();
    let mut total: u64 = 0;
    for i in 0..z.len() {
        let mut f = match z.by_index(i) {
            Ok(f) => f,
            Err(zip::result::ZipError::UnsupportedArchive(m)) if m.contains("assword") => return Err("it is encrypted".into()),
            Err(e) => return Err(format!("entry {i}: {e}")),
        };
        let raw = String::from_utf8_lossy(f.name_raw()).into_owned();
        if f.encrypted() {
            return Err(format!("{raw} is encrypted"));
        }
        if f.is_symlink() {
            return Err(format!("{raw} is a link"));
        }
        let Some(path) = f.enclosed_name() else { return Err(format!("{raw}: unsafe path")) };
        if f.is_dir() {
            continue;
        }
        let name = path.to_string_lossy().replace('\\', "/");
        if !matches!(f.compression(), zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated | zip::CompressionMethod::Deflate64) {
            return Err(format!("{name}: unsupported compression {:?}", f.compression()));
        }
        let size = f.size();
        if size > (1 << 20) && size / f.compressed_size().max(1) > MAX_RATIO {
            return Err(format!("{name} unpacks to {size} bytes from {}: refused as a possible zip bomb", f.compressed_size()));
        }
        total = total.saturating_add(size);
        if total > MAX_UNPACKED {
            return Err(format!("more than {MAX_UNPACKED} bytes unpacked"));
        }
        let mut head = Vec::with_capacity(SNIFF_BYTES);
        (&mut f).take(SNIFF_BYTES as u64).read_to_end(&mut head).map_err(|e| format!("{name}: {e}"))?;
        match sniff(&head) {
            Some(t @ (FileType::Pdf | FileType::Djvu)) => out.push(Member { name, size, file_type: t }),
            Some(FileType::Zip) => return Err(format!("{name} is another zip")),
            None => return Err(format!("{name} isn't a PDF or DjVu")),
        }
    }
    if out.is_empty() {
        return Err("it has no documents".into());
    }
    Ok(out)
}

/// Unpack one document (from `zip_documents`) into `w`, no further than its
/// declared size. Fails when it unpacks to any other size.
pub fn copy_document<R: Read + Seek, W: std::io::Write>(r: R, m: &Member, w: &mut W) -> Result<(), String> {
    let mut z = zip::ZipArchive::new(r).map_err(|e| format!("not a readable zip: {e}"))?;
    let i = z.index_for_name(&m.name).or_else(|| z.index_for_name(&m.name.replace('/', "\\"))).ok_or_else(|| format!("{}: not found", m.name))?;
    let mut e = z.by_index(i).map_err(|e| format!("{}: {e}", m.name))?;
    let n = std::io::copy(&mut (&mut e).take(m.size + 1), w).map_err(|e| format!("{}: {e}", m.name))?;
    if n != m.size {
        return Err(format!("{} unpacked to {n} bytes, not the {} declared", m.name, m.size));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn make(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            if name.ends_with('/') {
                w.add_directory(*name, SimpleFileOptions::default()).unwrap();
            } else {
                w.start_file(*name, SimpleFileOptions::default().compression_method(method)).unwrap();
                w.write_all(data).unwrap();
            }
        }
        w.finish().unwrap().into_inner()
    }

    const PDF: &[u8] = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n";
    const DJVU: &[u8] = b"AT&TFORM\x00\x00\x00\x10DJVUINFO\x00\x00\x00\x00";

    #[test]
    fn documents_only() {
        let z = make(&[("q2500/", b""), ("q2500/Seite 1.pdf", PDF), ("q2500/board/88175h_PCB.pdf", PDF), ("x.djvu", DJVU)], zip::CompressionMethod::Deflated);
        assert_eq!(sniff(&z), Some(FileType::Zip));
        let m = zip_documents(Cursor::new(&z)).unwrap();
        assert_eq!(m.iter().map(|m| (m.name.as_str(), m.file_type)).collect::<Vec<_>>(),
            vec![("q2500/Seite 1.pdf", FileType::Pdf), ("q2500/board/88175h_PCB.pdf", FileType::Pdf), ("x.djvu", FileType::Djvu)]);
        let mut out = Vec::new();
        copy_document(Cursor::new(&z), &m[0], &mut out).unwrap();
        assert_eq!(out, PDF);
        // A member that unpacks to more than it declares is refused.
        let lie = Member { size: 3, ..m[0].clone() };
        assert!(copy_document(Cursor::new(&z), &lie, &mut Vec::new()).unwrap_err().contains("not the 3 declared"));
        // Stored works as well as deflate.
        assert_eq!(zip_documents(Cursor::new(make(&[("a.pdf", PDF)], zip::CompressionMethod::Stored))).unwrap().len(), 1);
    }

    #[test]
    fn anything_else_is_refused() {
        let refused = |entries: &[(&str, &[u8])]| zip_documents(Cursor::new(make(entries, zip::CompressionMethod::Deflated))).unwrap_err();
        assert!(refused(&[("a.pdf", PDF), ("setup.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")]).contains("setup.exe isn't a PDF"));
        assert!(refused(&[("readme.txt", b"hello")]).contains("isn't a PDF"));
        assert!(refused(&[("inner.zip", &make(&[("a.pdf", PDF)], zip::CompressionMethod::Stored))]).contains("another zip"));
        assert!(refused(&[("empty/", b"")]).contains("no documents"));
        assert!(refused(&[("../evil.pdf", PDF)]).contains("unsafe path"));
        assert!(refused(&[("a.pdf", PDF), ("b.pdf", b"")]).contains("b.pdf isn't a PDF"));
        // A bomb: a "PDF" of 8 MiB of zeros packs to a few KiB.
        let mut bomb = PDF.to_vec();
        bomb.resize(8 << 20, 0);
        assert!(refused(&[("big.pdf", &bomb)]).contains("zip bomb"));
        assert!(zip_documents(Cursor::new(b"PK\x03\x04 not really a zip".to_vec())).unwrap_err().contains("not a readable zip"));
    }
}
