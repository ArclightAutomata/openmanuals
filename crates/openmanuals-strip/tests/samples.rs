//! Validation against real ManualsLib downloads; the native twin of
//! `extension/src/strip/samples.test.ts` (which runs the wasm build). The
//! expected results for 40 originals are in
//! `extension/src/strip/fixtures/reference.json`, with paths relative to a
//! corpus directory; skipped unless that directory is given. It is only ever
//! read.
//!
//!   OM_STRIP_CORPUS=dir    the directory the fixture's paths are relative to
//!   OM_STRIP_SAMPLES=10    limit the sample count
//!   OM_STRIP_LARGE=file    also time stripping one (large) PDF
//!   OM_STRIP_OUT=dir       write each stripped file to dir (for cross-checks)
//!
//! Timings are only meaningful with `cargo test --release`.

use openmanuals_strip::{inspect, strip};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Deserialize)]
struct Sample {
    path: String,
    pages_before: usize,
    leading: usize,
    trailing: usize,
    pages_after: usize,
    modified: bool,
}

#[derive(Deserialize)]
struct Reference {
    samples: Vec<Sample>,
}

fn root() -> Option<PathBuf> {
    std::env::var_os("OM_STRIP_CORPUS").map(PathBuf::from)
}

#[test]
fn real_manualslib_downloads_match_the_reference_page_counts_and_lose_every_footer_and_link()
{
    let reference: Reference = serde_json::from_str(include_str!(
        "../../../extension/src/strip/fixtures/reference.json"
    ))
    .unwrap();
    let Some(root) = root() else {
        eprintln!("skipped: set OM_STRIP_CORPUS");
        return;
    };
    let samples: Vec<_> = reference
        .samples
        .iter()
        .filter(|s| root.join(&s.path).exists())
        .collect();
    if samples.is_empty() {
        eprintln!("skipped: none of the samples are under {}", root.display());
        return;
    }
    let limit = std::env::var("OM_STRIP_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(samples.len());
    let out_dir = std::env::var_os("OM_STRIP_OUT").map(PathBuf::from);
    let mut mismatches = Vec::new();
    let mut total = std::time::Duration::ZERO;
    let mut checked = 0;
    for s in samples.iter().take(limit) {
        let bytes = std::fs::read(root.join(&s.path)).unwrap();
        let before = inspect(&bytes).unwrap();
        let t0 = Instant::now();
        let r = strip(&bytes).unwrap();
        total += t0.elapsed();
        if let Some(dir) = &out_dir {
            let name = std::path::Path::new(&s.path).file_name().unwrap();
            std::fs::write(dir.join(name), &r.bytes).unwrap();
            std::fs::write(dir.join(name).with_extension("log"), r.log.join("\n")).unwrap();
        }
        let after = inspect(&r.bytes).unwrap();
        let (pages_before, wrapper) = (before.pages, before.wrapper);
        let (pages_after, footers, links) =
            (after.pages, after.footer_pages, after.manualslib_links);
        checked += 1;
        if pages_before != s.pages_before
            || wrapper != (s.leading, s.trailing)
            || pages_after != s.pages_after
            || r.changed != s.modified
            || footers > 0
            || links > 0
        {
            mismatches.push(format!(
                "{}: pages {pages_before}->{pages_after} (expected {}->{}), wrapper {wrapper:?} (expected ({}, {})), changed {} (expected {}), footers left {footers}, links left {links}; log: {}",
                s.path, s.pages_before, s.pages_after, s.leading, s.trailing, r.changed, s.modified, r.log.join("; ")
            ));
        }
    }
    eprintln!(
        "samples: {checked} checked, {} match, {} ms total",
        checked - mismatches.len(),
        total.as_millis()
    );
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn large_pdf_strips_in_reasonable_time() {
    let Some(path) = std::env::var_os("OM_STRIP_LARGE").map(PathBuf::from) else {
        eprintln!("skipped: set OM_STRIP_LARGE to a PDF");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let t0 = Instant::now();
    let r = strip(&bytes).unwrap();
    let ms = t0.elapsed().as_millis();
    eprintln!(
        "{}: {} bytes in {ms} ms, changed={}, out {} bytes, log: {}",
        path.display(),
        bytes.len(),
        r.changed,
        r.bytes.len(),
        r.log.join("; ")
    );
    assert!(ms < 60_000);
}
