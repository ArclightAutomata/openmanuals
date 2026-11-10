//! File type from leading bytes. Only formats OpenManuals accepts: PDF and
//! DjVu, and zip, which is accepted only when it holds nothing but PDF and
//! DjVu files (see `container`; its first bytes alone say nothing about
//! that). Other containers (rar, 7z) are refused: they can hold anything,
//! including executables.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Pdf,
    Djvu,
    /// A zip, which is a document only once `container::zip_documents` accepts it.
    Zip,
}

impl FileType {
    pub fn mime(self) -> &'static str {
        match self {
            FileType::Pdf => "application/pdf",
            FileType::Djvu => "image/vnd.djvu",
            FileType::Zip => "application/zip",
        }
    }
    /// Short name, also the file extension; what `verified` facts record as `file_type`.
    pub fn extension(self) -> &'static str {
        match self {
            FileType::Pdf => "pdf",
            FileType::Djvu => "djvu",
            FileType::Zip => "zip",
        }
    }
    pub fn from_name(s: &str) -> Option<FileType> {
        match s {
            "pdf" => Some(FileType::Pdf),
            "djvu" => Some(FileType::Djvu),
            "zip" => Some(FileType::Zip),
            _ => None,
        }
    }
}

/// How many leading bytes [`sniff`] needs.
pub const SNIFF_BYTES: usize = 16;

pub fn sniff(bytes: &[u8]) -> Option<FileType> {
    if bytes.starts_with(b"%PDF-") {
        Some(FileType::Pdf)
    } else if bytes.len() >= 16 && &bytes[..8] == b"AT&TFORM" && matches!(&bytes[12..16], b"DJVU" | b"DJVM") {
        // IFF: "AT&T" magic, "FORM", 4-byte length, then the form type
        // (DJVU single page, DJVM multi-page bundle).
        Some(FileType::Djvu)
    } else if bytes.starts_with(b"PK\x03\x04") {
        // A local file header first: a zip with at least one entry.
        Some(FileType::Zip)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_documents() {
        assert_eq!(sniff(b"%PDF-1.7\n%\xe2\xe3"), Some(FileType::Pdf));
        assert_eq!(sniff(b"AT&TFORM\x00\x01\x02\x03DJVMDIRM"), Some(FileType::Djvu));
        assert_eq!(sniff(b"AT&TFORM\x00\x01\x02\x03DJVU"), Some(FileType::Djvu));
        assert_eq!(sniff(b"AT&TFORM\x00\x01\x02\x03AIFF"), None, "other IFF forms");
        assert_eq!(sniff(b"AT&T"), None);
        assert_eq!(sniff(b"MZ\x90\x00\x03\x00\x00\x00"), None, "Windows executable");
        assert_eq!(sniff(b"\x7fELF\x02\x01\x01"), None);
        assert_eq!(sniff(b"PK\x03\x04\x14\x00"), Some(FileType::Zip), "a zip, accepted only after container::zip_documents");
        assert_eq!(sniff(b"PK\x05\x06\x00\x00"), None, "an empty zip");
        assert_eq!(sniff(b"Rar!\x1a\x07\x01\x00"), None, "rar is refused");
        assert_eq!(sniff(b"<!DOCTYPE html>"), None);
        assert_eq!(sniff(b" %PDF-1.4"), None, "the header must come first");
        for t in [FileType::Pdf, FileType::Djvu, FileType::Zip] {
            assert_eq!(FileType::from_name(t.extension()), Some(t));
        }
        assert_eq!(FileType::from_name("rar"), None);
    }
}
