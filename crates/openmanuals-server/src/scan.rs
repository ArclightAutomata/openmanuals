//! Active-content scan of PDFs ("om-scan/2"): which features a reader could
//! execute or hand to the operating system. Recorded as the `scan` member of
//! a `verified` fact; the build refuses to offer files whose copies report any
//! feature except the informational ones ([`INFORMATIONAL`]).
//!
//! Launch actions are classified (new in om-scan/2; om-scan/1 reported every
//! one as `Launch`). Each target is resolved: `/F` (a string, or a file
//! specification's `/UF`, `/F`, `/Unix`, `/Mac`, `/DOS`) and the `/Win`,
//! `/Mac`, `/Unix` dictionaries. The action is `Launch` (risky) when any of:
//! - a target names an executable or script type ([`RISKY_EXTENSIONS`]),
//!   judged on the name without a `?query` or `#fragment` (unless that leaves
//!   no extension), and on each of its space-separated words; `.com` is exempt
//!   only for a web or mail address (`www.x.com`, `info@x.com`, or an
//!   `http(s)://x.com` URL with no path), since DOS `.com` programs are never
//!   named like that;
//! - a target with no extension is a system program (a bare command name such
//!   as `cmd` or `powershell` that the shell finds on the PATH, or a path into
//!   a system binary directory such as `/bin/` or `\Windows\System32\`);
//! - `/Win` has non-empty parameters `/P` or an operation `/O` other than
//!   `open` or `print`;
//! - a target is an embedded file (`/EF` in its file specification);
//! - a target can't be read as a string (a stream, a dangling reference, an
//!   unexpected type): what would be launched is hidden.
//!
//! Any other Launch (a document, a web page, a broken script fragment left by
//! an HTML export, no target at all) is `LaunchDocument`: recorded, not held.
//! A `/Launch` name outside a classified action's `/S` (e.g. reached through a
//! reference, or in an object the parser skipped or superseded) is `Launch`.
//!
//! Two independent views are combined, and a feature found by either counts:
//! - **Structural:** the document parsed with `lopdf` (cross-reference tables
//!   and streams, incremental updates, compressed object streams, empty-password
//!   encryption, `#xx` name escapes decoded, xref reconstruction for damaged
//!   files). Every dictionary of every object, including stream dictionaries
//!   and the trailer, is walked for the names below.
//! - **Lexical:** a pass over the raw bytes outside literal/hex strings,
//!   comments and stream payloads, decoding `#xx` escapes in every name. It
//!   sees objects the parser skipped (lopdf skips malformed objects in its
//!   lenient mode) and objects no cross-reference entry points at.
//!
//! A file the parser can't read at all, an encrypted file it can't decrypt
//! with the empty password, a file whose object streams it couldn't expand
//! (part of the document unseen), a parser panic, or a scan over the time cap
//! is reported as `Unparseable`: treated as risky, never as clean.
//!
//! Content streams (page drawing operators) are not parsed: names there are
//! resource handles, not actions.

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

pub const TOOL: &str = "om-scan/2";

pub const JAVASCRIPT: &str = "JavaScript";
/// A Launch action that runs a program, passes parameters, or hides its target.
pub const LAUNCH: &str = "Launch";
/// A Launch action that only opens a named file (a document, a web page) or
/// nothing: informational.
pub const LAUNCH_DOCUMENT: &str = "LaunchDocument";
pub const EMBEDDED_FILE: &str = "EmbeddedFile";
pub const RICH_MEDIA: &str = "RichMedia";
pub const SUBMIT_FORM: &str = "SubmitForm";
pub const IMPORT_DATA: &str = "ImportData";
pub const GOTO_E: &str = "GoToE";
pub const UNPARSEABLE: &str = "Unparseable";

/// Features recorded but not holding a file back (the ledger build keeps the
/// same list).
pub const INFORMATIONAL: &[&str] = &[LAUNCH_DOCUMENT];

/// File types a Launch target must not have (lowercase, no dot): programs,
/// scripts, installers, shortcuts and other files the shell executes.
pub const RISKY_EXTENSIONS: &[&str] = &[
    // Windows programs, scripts and shell files.
    "exe", "com", "bat", "cmd", "scr", "pif", "msi", "msp", "mst", "vbs", "vbe", "vb", "js", "jse", "wsf", "wsh", "ws", "wsc", "sct",
    "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "psm1", "psd1", "lnk", "cpl", "hta", "jar", "jnlp", "reg", "inf", "ins", "isp",
    "url", "scf", "application", "appref-ms", "gadget", "msc", "dll", "sys", "ocx", "drv", "chm", "hlp", "shs", "shb", "xbap",
    "settingcontent-ms", "appx", "appxbundle", "msix", "msixbundle", "diagcab",
    // macOS and Unix.
    "app", "command", "tool", "terminal", "workflow", "scpt", "applescript", "action", "dmg", "pkg", "mpkg", "kext", "dylib",
    "sh", "bash", "csh", "ksh", "zsh", "tcsh", "fish", "py", "pyc", "pyw", "pl", "rb", "php", "run", "bin", "elf", "so", "appimage",
    "desktop", "deb", "rpm",
];

/// Programs the shell finds by bare name (no extension, no path).
const SYSTEM_COMMANDS: &[&str] = &[
    "cmd", "command", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec", "certutil", "bitsadmin",
    "schtasks", "reg", "regedit", "net", "netsh", "sc", "wmic", "explorer", "control", "calc", "notepad", "ftp", "tftp", "curl", "wget",
    "sh", "bash", "zsh", "csh", "ksh", "dash", "osascript", "open", "python", "python3", "perl", "ruby", "php", "node", "java", "javaw",
    "xdg-open", "env", "nc", "telnet",
];

/// Directories of system programs (lowercase, `/` separators).
const SYSTEM_DIRS: &[&str] = &["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/libexec/", "/windows/", "/system32/", "/syswow64/", "/applications/", "/system/library/"];

/// Wall-clock cap on one scan. A scan that runs longer is reported Unparseable.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(300);
/// Largest file scanned (the fetch cap); a larger one is Unparseable.
pub const MAX_SCAN_BYTES: u64 = crate::verify::MAX_FETCH_BYTES;
/// Most bytes any one stream (object stream, XFA packet) may decode to.
pub const MAX_DECODED: usize = 64 * 1024 * 1024;
/// Streams larger than this (images, fonts, page content) have their payload
/// dropped right after parsing, so memory stays near the file's size; object
/// streams are always kept (they are expanded by the parser).
const KEEP_STREAM_BYTES: usize = 4 * 1024 * 1024;
/// Stack for the scanning thread (the parser recurses on nested objects).
const SCAN_STACK: usize = 64 * 1024 * 1024;

/// Result of a scan: the active-content features found, sorted, no duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scan {
    pub active: Vec<&'static str>,
}

impl Scan {
    pub fn clean() -> Scan {
        Scan::default()
    }
    pub fn unparseable() -> Scan {
        Scan { active: vec![UNPARSEABLE] }
    }
    fn from_set(s: BTreeSet<&'static str>) -> Scan {
        Scan { active: s.into_iter().collect() }
    }
    /// The `scan` member of a `verified` body.
    pub fn to_json(&self) -> Value {
        json!({"tool": TOOL, "active": self.active})
    }
}

/// Whether a recorded `scan` member must be redone rather than repeated by a
/// re-check: om-scan/1 reported every Launch action as `Launch`, which
/// om-scan/2 splits into `Launch` and the informational `LaunchDocument`.
/// Any other om-scan/1 result is what om-scan/2 would find, so it stands.
pub fn outdated(scan: &Value) -> bool {
    scan.get("tool").and_then(Value::as_str) == Some("om-scan/1") && scan.get("active").and_then(Value::as_array).is_some_and(|a| a.iter().any(|f| f == LAUNCH))
}

/// The feature a PDF name stands for (as a dictionary key or a value, e.g.
/// the action type after `/S`). Embedded files and `/JS` are judged with
/// more context, by the callers.
fn feature(name: &[u8]) -> Option<&'static str> {
    Some(match name {
        b"JavaScript" => JAVASCRIPT,
        b"Launch" => LAUNCH,
        b"SubmitForm" => SUBMIT_FORM,
        b"ImportData" => IMPORT_DATA,
        b"GoToE" => GOTO_E,
        n if n.starts_with(b"RichMedia") => RICH_MEDIA,
        _ => return None,
    })
}

/// Scan a PDF on disk, off the async runtime, on its own thread with a large
/// stack, under SCAN_TIMEOUT. Never fails: problems are `Unparseable`.
pub async fn scan_pdf_file(path: &Path) -> Scan {
    scan_pdf_file_within(path, SCAN_TIMEOUT).await
}

/// Memory cap for a scan process (`RLIMIT_DATA`: heap and private mappings).
/// A 512 MiB PDF peaks near 1.7 GB; past the cap an allocation fails, the
/// process aborts, and the copy is Unparseable.
pub const SCAN_MEMORY: u64 = 3 * 1024 * 1024 * 1024;

static WORKER: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Run every scan in a child process of this program (`<exe> __scan <file>`),
/// which can be killed on timeout and is held to [`SCAN_MEMORY`] and the CPU
/// time of [`SCAN_TIMEOUT`]. The server binary calls this at startup; without
/// it (tests, library use) scans run on a thread in this process, which a
/// timeout can abandon but not stop.
pub fn use_worker_process(exe: std::path::PathBuf) {
    let _ = WORKER.set(exe);
}

/// The argument that makes the server binary act as a scan worker.
pub const WORKER_ARG: &str = "__scan";

/// Entry point of a scan worker: scan `path` and print the result as one JSON
/// line (`{"active": [...]}`) on stdout. Returns the exit code.
pub fn worker_main(path: &Path) -> i32 {
    let r = scan_file_blocking(path);
    println!("{}", json!({"active": r.active}));
    0
}

pub async fn scan_pdf_file_within(path: &Path, timeout: Duration) -> Scan {
    match WORKER.get() {
        Some(exe) => scan_in_process(exe, path, timeout).await,
        None => scan_in_thread(path, timeout).await,
    }
}

/// Scan in a child process, killed at `timeout`.
pub async fn scan_in_process(exe: &Path, path: &Path, timeout: Duration) -> Scan {
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(WORKER_ARG).arg(path).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit()).kill_on_drop(true);
    #[cfg(unix)]
    {
        let cpu = timeout.as_secs().max(1) + 5;
        // SAFETY: only async-signal-safe setrlimit calls between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                let set = |res, n: u64| {
                    let l = libc::rlimit { rlim_cur: n as libc::rlim_t, rlim_max: n as libc::rlim_t };
                    if libc::setrlimit(res, &l) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                };
                set(libc::RLIMIT_DATA, SCAN_MEMORY)?;
                set(libc::RLIMIT_CPU, cpu)?;
                set(libc::RLIMIT_CORE, 0)?;
                set(libc::RLIMIT_NOFILE, 32)?;
                set(libc::RLIMIT_FSIZE, 0)?;
                Ok(())
            });
        }
    }
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "scan: could not start the scan process");
            return Scan::unparseable();
        }
    };
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Err(_) => {
            // Dropping the future drops the child, and kill_on_drop kills it.
            tracing::warn!(secs = timeout.as_secs(), "scan timed out; process killed, recording Unparseable");
            Scan::unparseable()
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "scan: waiting for the scan process failed");
            Scan::unparseable()
        }
        Ok(Ok(out)) if !out.status.success() => {
            tracing::warn!(status = %out.status, "scan process failed (crash, memory or CPU limit); recording Unparseable");
            Scan::unparseable()
        }
        Ok(Ok(out)) => parse_worker_output(&out.stdout).unwrap_or_else(|| {
            tracing::warn!("scan: unreadable output from the scan process");
            Scan::unparseable()
        }),
    }
}

/// The worker's JSON line, mapped back to the known feature names. Anything
/// unexpected is `None` (and so Unparseable).
fn parse_worker_output(stdout: &[u8]) -> Option<Scan> {
    const KNOWN: &[&str] = &[JAVASCRIPT, LAUNCH, LAUNCH_DOCUMENT, EMBEDDED_FILE, RICH_MEDIA, SUBMIT_FORM, IMPORT_DATA, GOTO_E, UNPARSEABLE];
    let v: Value = serde_json::from_slice(stdout).ok()?;
    let mut set = BTreeSet::new();
    for a in v.get("active")?.as_array()? {
        set.insert(*KNOWN.iter().find(|k| Some(**k) == a.as_str())?);
    }
    Some(Scan::from_set(set))
}

/// Read and scan a file on a thread with a large stack (the parser recurses
/// on nested objects); blocks until done.
fn scan_file_blocking(path: &Path) -> Scan {
    let path = path.to_path_buf();
    let t = std::thread::Builder::new().name("om-scan".into()).stack_size(SCAN_STACK).spawn(move || match std::fs::metadata(&path) {
        Ok(m) if m.len() > MAX_SCAN_BYTES => Scan::unparseable(),
        Ok(_) => match std::fs::read(&path) {
            Ok(bytes) => scan_pdf(&bytes),
            Err(e) => {
                tracing::warn!(error = %e, "scan: reading the file failed");
                Scan::unparseable()
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "scan: file missing");
            Scan::unparseable()
        }
    });
    match t {
        Ok(h) => h.join().unwrap_or_else(|_| Scan::unparseable()),
        Err(e) => {
            tracing::warn!(error = %e, "scan: could not start the scanning thread");
            Scan::unparseable()
        }
    }
}

/// Scan on a thread in this process. On timeout the thread can't be stopped:
/// it finishes on its own and its result is dropped.
async fn scan_in_thread(path: &Path, timeout: Duration) -> Scan {
    let path = path.to_path_buf();
    let job = tokio::task::spawn_blocking(move || scan_file_blocking(&path));
    match tokio::time::timeout(timeout, job).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => Scan::unparseable(),
        Err(_) => {
            tracing::warn!(secs = timeout.as_secs(), "scan timed out; recording Unparseable");
            Scan::unparseable()
        }
    }
}

/// Scan PDF bytes. Never panics (a parser panic is caught and is `Unparseable`).
pub fn scan_pdf(bytes: &[u8]) -> Scan {
    scan_pdf_explained(bytes).0
}

/// [`scan_pdf`], with one line per Launch action found saying how it was
/// classified and why (for logs and corpus runs).
pub fn scan_pdf_explained(bytes: &[u8]) -> (Scan, Vec<String>) {
    let lex = lexical(bytes);
    let mut found = lex.found;
    let mut notes = Vec::new();
    let unparsed = |found: &mut BTreeSet<&'static str>, notes: &mut Vec<String>| {
        found.insert(UNPARSEABLE);
        if lex.embedded_any {
            found.insert(EMBEDDED_FILE);
        }
        if !lex.launch.is_empty() {
            found.insert(LAUNCH);
            notes.push("Launch: a /Launch name in a file the parser couldn't read".to_string());
        }
    };
    match std::panic::catch_unwind(|| structural(bytes)) {
        Ok(Ok(s)) => {
            found.extend(s.found);
            notes.extend(s.notes);
            // Embedded-file streams the raw pass saw that the parser didn't vet.
            if lex.embedded_file_types > s.benign_typed_embedded {
                found.insert(EMBEDDED_FILE);
            }
            // A /Launch name in an object the parser skipped, or in an older
            // revision of an object: never classified, so risky.
            let unseen: Vec<String> = lex.launch.iter().filter(|id| !s.launch_in.contains(id)).map(|id| match id {
                Some((n, g)) => format!("{n} {g} obj"),
                None => "outside any object".to_string(),
            }).collect();
            if !unseen.is_empty() {
                found.insert(LAUNCH);
                notes.push(format!("Launch: /Launch in objects the parser didn't load: {}", unseen.join(", ")));
            }
        }
        Ok(Err(why)) => {
            tracing::debug!(why, "scan: structural parse failed");
            unparsed(&mut found, &mut notes);
        }
        Err(_) => {
            tracing::warn!("scan: the PDF parser panicked");
            unparsed(&mut found, &mut notes);
        }
    }
    (Scan::from_set(found), notes)
}

/// Drop large non-object-stream payloads as objects are parsed (memory bound).
fn keep_small(id: lopdf::ObjectId, obj: &mut lopdf::Object) -> Option<(lopdf::ObjectId, lopdf::Object)> {
    if let lopdf::Object::Stream(s) = obj {
        if s.content.len() > KEEP_STREAM_BYTES && !s.dict.has_type(b"ObjStm") {
            s.content = Vec::new();
        }
    }
    // lopdf keeps the object modified in place on one path and the returned
    // one on the other (object-stream members): both must be the object.
    Some((id, obj.clone()))
}

struct Structural {
    found: BTreeSet<&'static str>,
    /// Streams typed `/EmbeddedFile` that were vetted as benign.
    benign_typed_embedded: usize,
    /// Objects (None: the trailer) in which a `/Launch` name was seen.
    launch_in: BTreeSet<Option<(u32, u16)>>,
    /// How each Launch action was classified.
    notes: Vec<String>,
}

fn structural(bytes: &[u8]) -> Result<Structural, String> {
    use lopdf::{xref::XrefEntry, Object, ObjectId};
    let opts = lopdf::LoadOptions { filter: Some(keep_small), max_decompressed_size: Some(MAX_DECODED), ..Default::default() };
    let mut doc = lopdf::Document::load_mem_with_options(bytes, opts.clone()).map_err(|e| e.to_string())?;
    if matches!(doc.trailer.get(b"Encrypt"), Ok(Object::Null)) {
        // `/Encrypt null` (written by some producers) means not encrypted, but
        // lopdf takes the encrypted path and then loads nothing. Blank those
        // tokens in place (same length, offsets unchanged) and load again.
        let mut patched = bytes.to_vec();
        let mut at = 0;
        while let Some(p) = memchr::memmem::find(&patched[at..], b"/Encrypt") {
            let start = at + p;
            let mut j = start + 8;
            while j < patched.len() && is_white(patched[j]) {
                j += 1;
            }
            if patched[j..].starts_with(b"null") {
                patched[start..j + 4].fill(b' ');
            }
            at = start + 8;
        }
        doc = lopdf::Document::load_mem_with_options(&patched, opts).map_err(|e| e.to_string())?;
    }
    // Still carrying /Encrypt: lopdf couldn't decrypt it (it needs a password),
    // so streams, including object streams, were never read.
    if doc.trailer.get(b"Encrypt").is_ok() && doc.encryption_state.is_none() {
        return Err("encrypted with a password".into());
    }
    // Every object the cross-reference data places in an object stream must
    // have been expanded, or part of the document went unseen.
    let unseen = doc.reference_table.entries.iter().filter(|(n, e)| matches!(e, XrefEntry::Compressed { .. }) && !doc.objects.contains_key(&(**n, 0))).count();
    if unseen > 0 {
        return Err(format!("{unseen} objects in unreadable object streams"));
    }
    let mut found = BTreeSet::new();
    let mut xfa: Vec<&Object> = Vec::new();
    // File specifications with embedded files: (the filespec dict, its /EF value).
    let mut filespecs: Vec<(&lopdf::Dictionary, &Object)> = Vec::new();
    let mut typed_embedded: BTreeSet<ObjectId> = BTreeSet::new();
    for (id, o) in &doc.objects {
        if let Object::Stream(s) = o {
            if s.dict.has_type(b"EmbeddedFile") {
                typed_embedded.insert(*id);
            }
        }
    }
    let mut launch_in = BTreeSet::new();
    let mut notes = Vec::new();
    // Each object with the top-level object it belongs to (None: the trailer).
    let mut stack: Vec<(Option<ObjectId>, &Object)> = doc.objects.iter().map(|(id, o)| (Some(*id), o)).collect();
    let trailer = Object::Dictionary(doc.trailer.clone());
    stack.push((None, &trailer));
    while let Some((root, o)) = stack.pop() {
        let dict = match o {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            Object::Array(a) => {
                stack.extend(a.iter().map(|x| (root, x)));
                continue;
            }
            Object::Name(n) => {
                // Not the /S of an action dictionary seen here (e.g. a /S
                // given by reference): can't be classified.
                if n == b"Launch" {
                    launch_in.insert(root);
                    notes.push("Launch: a /Launch name outside an action's /S".to_string());
                }
                found.extend(feature(n));
                continue;
            }
            _ => continue,
        };
        let launch = matches!(dict.get(b"S"), Ok(Object::Name(n)) if n == b"Launch");
        if launch {
            launch_in.insert(root);
            match launch_risk(&doc, dict) {
                Ok(what) => {
                    found.insert(LAUNCH_DOCUMENT);
                    notes.push(format!("LaunchDocument: {what}"));
                }
                Err(why) => {
                    found.insert(LAUNCH);
                    notes.push(format!("Launch: {why}"));
                }
            }
        }
        for (k, v) in dict.iter() {
            if k == b"Launch" {
                launch_in.insert(root);
            }
            found.extend(feature(k));
            // The action type just classified.
            if launch && k == b"S" {
                continue;
            }
            match k.as_slice() {
                // Script source: a string or a stream (usually by reference). Other
                // dictionaries use a /JS key for unrelated numbers (seen in CJK
                // typesetting dictionaries).
                b"JS" if matches!(v, Object::String(..) | Object::Stream(_) | Object::Reference(_)) => {
                    found.insert(JAVASCRIPT);
                }
                b"XFA" => xfa.push(v),
                // A file specification's embedded files (a dictionary; the same
                // CJK typesetting dictionaries have an unrelated numeric /EF).
                b"EF" if matches!(v, Object::Dictionary(_) | Object::Reference(_)) => filespecs.push((dict, v)),
                _ => {}
            }
            stack.push((root, v));
        }
    }
    // XFA forms carry their own scripts (JavaScript or FormCalc) in XML packets.
    if !found.contains(JAVASCRIPT) && xfa.iter().any(|x| xfa_has_script(&doc, x)) {
        found.insert(JAVASCRIPT);
    }
    // Embedded files: flagged unless every one is an Acrobat Distiller settings
    // file (`*.joboptions`, small plain text), which Distiller attaches on its
    // own; about 3% of real manuals carry one.
    let mut benign: BTreeSet<ObjectId> = BTreeSet::new();
    let mut flagged = false;
    for (spec, ef) in filespecs {
        match benign_embedded(&doc, spec, ef) {
            Some(ids) => benign.extend(ids),
            None => flagged = true,
        }
    }
    if flagged || typed_embedded.iter().any(|id| !benign.contains(id)) {
        found.insert(EMBEDDED_FILE);
    }
    Ok(Structural { found, benign_typed_embedded: typed_embedded.intersection(&benign).count(), launch_in, notes })
}

/// Follow references (a bounded number); None for a dangling one or a loop.
fn deref<'a>(doc: &'a lopdf::Document, mut o: &'a lopdf::Object) -> Option<&'a lopdf::Object> {
    for _ in 0..32 {
        match o {
            lopdf::Object::Reference(id) => o = doc.objects.get(id)?,
            _ => return Some(o),
        }
    }
    None
}

/// A PDF text string (PDFDocEncoding, UTF-16BE or UTF-8 with BOMs) as text.
fn text(b: &[u8]) -> String {
    if let Some(u) = b.strip_prefix(&[0xfe, 0xff]) {
        let units: Vec<u16> = u.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
        String::from_utf16_lossy(&units)
    } else if let Some(u) = b.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        String::from_utf8_lossy(u).into_owned()
    } else {
        b.iter().map(|&c| c as char).collect()
    }
}

/// Classify one Launch action: `Ok(description)` when it only opens a named
/// file or nothing (LaunchDocument), `Err(why)` when it is risky (Launch).
fn launch_risk(doc: &lopdf::Document, action: &lopdf::Dictionary) -> Result<String, String> {
    use lopdf::Object;
    let mut names: Vec<String> = Vec::new();
    for key in [&b"F"[..], b"Win", b"Mac", b"Unix"] {
        let Ok(v) = action.get(key) else { continue };
        let k = String::from_utf8_lossy(key);
        let v = deref(doc, v).ok_or_else(|| format!("/{k} is a dangling reference"))?;
        match v {
            Object::Null => {}
            Object::String(s, _) => names.push(text(s)),
            Object::Dictionary(d) => {
                if key == b"Win" {
                    if let Ok(p) = d.get(b"P") {
                        match deref(doc, p) {
                            Some(Object::Null) => {}
                            Some(Object::String(s, _)) if text(s).trim().is_empty() => {}
                            Some(Object::String(s, _)) => return Err(format!("/Win passes parameters {:?}", text(s))),
                            _ => return Err("/Win /P can't be read".to_string()),
                        }
                    }
                    if let Ok(o) = d.get(b"O") {
                        let op = match deref(doc, o) {
                            Some(Object::String(s, _)) => text(s),
                            Some(Object::Name(n)) => String::from_utf8_lossy(n).into_owned(),
                            Some(Object::Null) => "open".to_string(),
                            _ => return Err("/Win /O can't be read".to_string()),
                        };
                        if !op.eq_ignore_ascii_case("open") && !op.eq_ignore_ascii_case("print") {
                            return Err(format!("/Win operation {op:?}"));
                        }
                    }
                }
                file_spec_names(doc, d, &k, &mut names)?;
            }
            o => return Err(format!("/{k} is a {}", o.enum_variant())),
        }
    }
    for n in &names {
        if let Some(why) = risky_target(n) {
            return Err(format!("{n:?} ({why})"));
        }
    }
    let names: Vec<String> = names.iter().map(|n| format!("{n:?}")).collect();
    Ok(if names.is_empty() { "no target".to_string() } else { names.join(", ") })
}

/// The file names of a file specification (or `/Win` dictionary). Risky
/// (`Err`) when it embeds the file or a name can't be read as a string.
fn file_spec_names(doc: &lopdf::Document, d: &lopdf::Dictionary, key: &str, names: &mut Vec<String>) -> Result<(), String> {
    use lopdf::Object;
    if d.get(b"EF").is_ok() || d.get(b"RF").is_ok() {
        return Err(format!("/{key} is an embedded file"));
    }
    for k in [&b"UF"[..], b"F", b"Unix", b"Mac", b"DOS"] {
        let Ok(v) = d.get(k) else { continue };
        match deref(doc, v) {
            Some(Object::Null) => {}
            Some(Object::String(s, _)) => names.push(text(s)),
            _ => return Err(format!("/{key} /{} can't be read as a file name", String::from_utf8_lossy(k))),
        }
    }
    Ok(())
}

/// Why a Launch target name is risky, or None when it only names a document
/// (or nothing, or something that isn't a file name at all).
pub fn risky_target(name: &str) -> Option<String> {
    let s = name.trim_matches(|c: char| c.is_whitespace() || c.is_control() || c == '"' || c == '\'').to_lowercase();
    // The name is judged without a URL-style `?query` or `#fragment`
    // (`Other library.pdf#M9.terminal` opens a PDF), unless what precedes
    // them has no extension (`setup#.exe` is judged whole).
    let cut = &s[..s.find(['?', '#']).unwrap_or(s.len())];
    let name = if extension(cut).is_some() { cut } else { s.as_str() };
    fn risky_ext(c: &str) -> Option<&str> {
        let c = c.trim_end_matches(['.', ' ']);
        extension(c).filter(|e| RISKY_EXTENSIONS.contains(e) && !(*e == "com" && is_host(c)))
    }
    if let Some(e) = risky_ext(name) {
        return Some(format!("runs a .{e} file"));
    }
    // A reader that hands the name to a shell runs its first word with the
    // rest as parameters; any word could be a program.
    if let Some(e) = name.split_whitespace().find_map(risky_ext) {
        return Some(format!("names a .{e} file"));
    }
    let bare = name.trim_end_matches(['.', ' ']);
    if extension(bare).is_none() {
        if SYSTEM_COMMANDS.contains(&last_segment(bare)) {
            return Some("runs a system command".to_string());
        }
        let path = bare.replace('\\', "/");
        if SYSTEM_DIRS.iter().any(|d| path.contains(d)) {
            return Some("runs a system program".to_string());
        }
    }
    None
}

/// The last segment of a path (`/`, `\` or classic Mac `:` separated).
fn last_segment(path: &str) -> &str {
    path.rsplit(['/', '\\', ':']).next().unwrap_or(path)
}

/// The extension of a path's last segment, if it has one (Windows ignores
/// trailing dots and spaces).
fn extension(path: &str) -> Option<&str> {
    let seg = last_segment(path.trim_end_matches(['.', ' ']));
    seg.rsplit_once('.').map(|(_, e)| e).filter(|e| !e.is_empty())
}

/// Whether a `.com` name is a web or mail address rather than a DOS program
/// (`COMMAND.COM`, `EDIT.COM`: short program names, never shaped like
/// addresses): a last path segment `www.<labels>.com` or `<user>@<labels>.com`,
/// or an `http(s)://<labels>.com` URL with no path. Such a target only ever
/// runs a program if a file of exactly that name was put next to the PDF.
fn is_host(name: &str) -> bool {
    let labels = |h: &str| h.split('.').all(|l| !l.is_empty() && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
    let seg = last_segment(name);
    if seg.strip_prefix("www.").is_some_and(|h| h.contains('.') && labels(h)) {
        return true;
    }
    if seg.split_once('@').is_some_and(|(user, h)| !user.is_empty() && !user.contains(char::is_whitespace) && h.contains('.') && labels(h)) {
        return true;
    }
    ["http://", "https://"].iter().any(|p| name.strip_prefix(p).is_some_and(|h| {
        let h = h.trim_end_matches('/');
        !h.contains('/') && labels(h)
    }))
}

/// A file name from a file specification string, lowercased.
fn spec_name(o: &lopdf::Object) -> Option<String> {
    let lopdf::Object::String(b, _) = o else { return None };
    Some(text(b).to_lowercase())
}

/// The embedded-file streams of one file specification, if all of it is a
/// Distiller `.joboptions` attachment: every name given ends in `.joboptions`
/// and every stream decodes to at most 1 MiB of plain text.
fn benign_embedded(doc: &lopdf::Document, spec: &lopdf::Dictionary, ef: &lopdf::Object) -> Option<Vec<lopdf::ObjectId>> {
    use lopdf::Object;
    let mut names = 0;
    for k in [&b"F"[..], b"UF"] {
        if let Ok(v) = spec.get(k) {
            if !spec_name(v)?.ends_with(".joboptions") {
                return None;
            }
            names += 1;
        }
    }
    if names == 0 {
        return None;
    }
    let ef = match ef {
        Object::Reference(id) => doc.get_object(*id).ok()?,
        o => o,
    };
    let Object::Dictionary(ef) = ef else { return None };
    let mut ids = Vec::new();
    for (_, v) in ef.iter() {
        let Object::Reference(id) = v else { return None };
        let Ok(Object::Stream(s)) = doc.get_object(*id) else { return None };
        if s.content.is_empty() {
            return None;
        }
        let data = if s.dict.get(b"Filter").is_ok() { s.decompressed_content_with_limit(1 << 20).ok()? } else { s.content.clone() };
        if data.len() > 1 << 20 || data.iter().any(|&c| c < 0x20 && !matches!(c, b'\t' | b'\n' | b'\r' | b'\x0c')) {
            return None;
        }
        ids.push(*id);
    }
    (!ids.is_empty()).then_some(ids)
}

/// Whether an /XFA value (a stream, or an array of name/stream pairs) holds a
/// `<script` element. A packet that can't be decoded counts as one.
fn xfa_has_script(doc: &lopdf::Document, v: &lopdf::Object) -> bool {
    use lopdf::Object;
    let mut parts: Vec<&Object> = vec![v];
    let mut seen = 0usize;
    while let Some(p) = parts.pop() {
        seen += 1;
        if seen > 10_000 {
            return true;
        }
        let p = match p {
            Object::Reference(id) => match doc.get_object(*id) {
                Ok(o) => o,
                Err(_) => return true,
            },
            o => o,
        };
        match p {
            Object::Array(a) => parts.extend(a.iter().filter(|o| !matches!(o, Object::String(..)))),
            Object::Stream(s) => {
                if s.content.is_empty() {
                    // Dropped as too large to keep, or empty: can't tell.
                    return true;
                }
                let data = if s.dict.get(b"Filter").is_ok() {
                    match s.decompressed_content_with_limit(MAX_DECODED) {
                        Ok(d) => d,
                        Err(_) => return true,
                    }
                } else {
                    s.content.clone()
                };
                if data.windows(7).any(|w| w.eq_ignore_ascii_case(b"<script")) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn is_white(c: u8) -> bool {
    matches!(c, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

fn is_delim(c: u8) -> bool {
    matches!(c, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}

fn hexval(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

struct Lexical {
    found: BTreeSet<&'static str>,
    /// `/EmbeddedFile` names seen (each embedded-file stream's /Type; streams
    /// are never inside object streams, so the raw pass sees all of them).
    embedded_file_types: usize,
    /// Any `/EmbeddedFile` or `/EmbeddedFiles` name seen.
    embedded_any: bool,
    /// The objects (`n g obj`; None: outside any) holding a `/Launch` name.
    /// Launch is judged by the structural pass; one it didn't see is risky.
    launch: BTreeSet<Option<(u32, u16)>>,
}

/// The object number and generation of an `n g obj` header whose `obj`
/// keyword starts at `at`.
fn obj_header(b: &[u8], at: usize) -> Option<(u32, u16)> {
    let digits_back = |end: usize| -> Option<(usize, u64)> {
        let mut s = end;
        while s > 0 && b[s - 1].is_ascii_digit() && end - s < 10 {
            s -= 1;
        }
        if s == end {
            return None;
        }
        Some((s, std::str::from_utf8(&b[s..end]).ok()?.parse().ok()?))
    };
    let ws_back = |end: usize| -> usize {
        let mut s = end;
        while s > 0 && is_white(b[s - 1]) {
            s -= 1;
        }
        s
    };
    let (gs, g) = digits_back(ws_back(at))?;
    let ns_end = ws_back(gs);
    if ns_end == gs {
        return None;
    }
    let (_, n) = digits_back(ns_end)?;
    Some((u32::try_from(n).ok()?, u16::try_from(g).ok()?))
}

/// The raw pass: every name outside strings, comments and stream payloads.
/// It can't tell keys from values, so `/JS` is left to the structural pass
/// (a script needs `/S /JavaScript`, which this pass does see).
fn lexical(b: &[u8]) -> Lexical {
    let mut out = Lexical { found: BTreeSet::new(), embedded_file_types: 0, embedded_any: false, launch: BTreeSet::new() };
    let n = b.len();
    let mut i = 0usize;
    let mut name = Vec::with_capacity(64);
    let mut current: Option<(u32, u16)> = None;
    while i < n {
        match b[i] {
            b'o' if i > 0 && is_white(b[i - 1]) && b[i..].starts_with(b"obj") && b.get(i + 3).is_none_or(|&c| is_white(c) || is_delim(c)) => {
                current = obj_header(b, i);
                i += 3;
            }
            b'e' if b[i..].starts_with(b"endobj") => {
                current = None;
                i += 6;
            }
            b'%' => {
                while i < n && b[i] != b'\n' && b[i] != b'\r' {
                    i += 1;
                }
            }
            b'(' => {
                // Literal string: balanced parentheses, backslash escapes.
                let mut depth = 0usize;
                while i < n {
                    match b[i] {
                        b'\\' => i += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                i += 1;
            }
            b'<' if b.get(i + 1) == Some(&b'<') => i += 2,
            b'<' => {
                // Hex string.
                while i < n && b[i] != b'>' {
                    i += 1;
                }
                i += 1;
            }
            b'/' => {
                i += 1;
                name.clear();
                while i < n && !is_white(b[i]) && !is_delim(b[i]) {
                    if b[i] == b'#' && i + 2 < n {
                        if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                            name.push(h << 4 | l);
                            i += 3;
                            continue;
                        }
                    }
                    name.push(b[i]);
                    i += 1;
                }
                match name.as_slice() {
                    b"EmbeddedFile" => {
                        out.embedded_file_types += 1;
                        out.embedded_any = true;
                    }
                    b"EmbeddedFiles" => out.embedded_any = true,
                    b"Launch" => {
                        out.launch.insert(current);
                    }
                    n => out.found.extend(feature(n)),
                }
            }
            b's' if b[i..].starts_with(b"stream") && (i == 0 || is_white(b[i - 1]) || b[i - 1] == b'>') && b.get(i + 6).is_some_and(|&c| c == b'\r' || c == b'\n') => {
                // Stream payload: skip to `endstream` (the /Length may be indirect
                // or wrong; readers search for the keyword too).
                let from = i + 6;
                match memchr::memmem::find(&b[from..], b"endstream") {
                    Some(p) => i = from + p + 9,
                    None => i = n,
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Builders for small PDFs in tests (also used by verify.rs's tests).
#[cfg(test)]
pub(crate) mod testpdf {
    use std::io::Write;

    pub const CATALOG: &[u8] = b"<< /Type /Catalog /Pages 2 0 R >>";
    pub const PAGES: &[u8] = b"<< /Type /Pages /Kids [] /Count 0 >>";

    /// A stream object body: `<< /Length n <dict> >> stream … endstream`.
    pub fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
        let mut v = format!("<< /Length {} {dict} >>\nstream\n", data.len()).into_bytes();
        v.extend_from_slice(data);
        v.extend_from_slice(b"\nendstream");
        v
    }

    pub fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn header() -> Vec<u8> {
        b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec()
    }

    fn object(out: &mut Vec<u8>, n: usize, body: &[u8]) -> usize {
        let at = out.len();
        out.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
        at
    }

    /// Objects 1, 2, … (1 must be the catalog) with a classic xref table.
    pub fn classic(objs: &[&[u8]]) -> Vec<u8> {
        let mut out = header();
        let offsets: Vec<usize> = objs.iter().enumerate().map(|(i, b)| object(&mut out, i + 1, b)).collect();
        let xref = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
        for o in offsets {
            out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
        out
    }

    /// `plain` objects 1… (1 the catalog), then `compressed` ones packed into a
    /// FlateDecode object stream, indexed by a cross-reference stream (PDF 1.5).
    pub fn with_objstm(plain: &[&[u8]], compressed: &[&[u8]]) -> Vec<u8> {
        let first = plain.len() + 1;
        let (mut head, mut body) = (String::new(), Vec::new());
        for (i, b) in compressed.iter().enumerate() {
            head.push_str(&format!("{} {} ", first + i, body.len()));
            body.extend_from_slice(b);
            body.push(b'\n');
        }
        let mut data = head.clone().into_bytes();
        data.extend_from_slice(&body);
        let stm = stream(&format!("/Type /ObjStm /N {} /First {} /Filter /FlateDecode", compressed.len(), head.len()), &deflate(&data));
        with_custom_objstm(plain, compressed.len(), &stm)
    }

    /// `plain` objects, then `members` objects the cross-reference stream
    /// places in the object stream `stm` (a whole object body).
    pub fn with_custom_objstm(plain: &[&[u8]], members: usize, stm: &[u8]) -> Vec<u8> {
        let mut out = header();
        let mut entries: Vec<(u8, usize, usize)> = vec![(0, 0, 0xffff)];
        for (i, b) in plain.iter().enumerate() {
            entries.push((1, object(&mut out, i + 1, b), 0));
        }
        let stm_num = plain.len() + 1 + members;
        for i in 0..members {
            entries.push((2, stm_num, i));
        }
        entries.push((1, object(&mut out, stm_num, stm), 0));
        let xref_num = stm_num + 1;
        let xref_at = out.len();
        entries.push((1, xref_at, 0));
        let mut rows = Vec::new();
        for (t, a, b) in &entries {
            rows.push(*t);
            rows.extend_from_slice(&(*a as u32).to_be_bytes());
            rows.extend_from_slice(&(*b as u16).to_be_bytes());
        }
        let xs = stream(&format!("/Type /XRef /Size {} /W [1 4 2] /Root 1 0 R", xref_num + 1), &rows);
        object(&mut out, xref_num, &xs);
        out.extend_from_slice(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testpdf::*;
    use super::*;

    fn active(pdf: &[u8]) -> Vec<&'static str> {
        scan_pdf(pdf).active
    }

    /// The catalog with `extra` entries, the page tree, then `objs` as 3, 4, ….
    fn doc(extra: &str, objs: &[&[u8]]) -> Vec<u8> {
        let cat = format!("<< /Type /Catalog /Pages 2 0 R {extra} >>").into_bytes();
        let mut all: Vec<&[u8]> = vec![&cat, PAGES];
        all.extend_from_slice(objs);
        classic(&all)
    }

    #[test]
    fn names() {
        assert_eq!(feature(b"JavaScript"), Some(JAVASCRIPT));
        assert_eq!(feature(b"JS"), None, "judged with its value");
        assert_eq!(feature(b"RichMediaContent"), Some(RICH_MEDIA));
        assert_eq!(feature(b"Font"), None);
    }

    #[test]
    fn clean_pdfs() {
        assert_eq!(active(&doc("", &[])), Vec::<&str>::new());
        assert_eq!(active(&with_objstm(&[CATALOG], &[PAGES, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"])), Vec::<&str>::new());
        // Names that only look like features: inside strings, content streams, comments.
        let content = stream("", b"BT /JavaScript 12 Tf (/Launch) Tj ET");
        assert_eq!(active(&doc("/Info (see /JavaScript and /Launch) % /SubmitForm", &[&content])), Vec::<&str>::new());
        // A numeric /JS (and /EF) in CJK typesetting dictionaries is not a script.
        assert_eq!(active(&doc("", &[b"<< /CF 0 /JS 0 /EF 1 /KF << /BTFN (Adobe Myungjo Std) >> >>"])), Vec::<&str>::new());
        // `/Encrypt null` is not encryption.
        let mut p = doc("", &[]);
        let at = memchr::memmem::find(&p, b"/Root 1 0 R").unwrap();
        p.splice(at..at, b"/Encrypt null ".iter().copied());
        assert_eq!(active(&p), Vec::<&str>::new());
    }

    #[test]
    fn each_feature() {
        let action = |a: &str| doc("/OpenAction 3 0 R", &[a.as_bytes()]);
        assert_eq!(active(&action("<< /S /JavaScript /JS (app.alert\\(1\\)) >>")), vec![JAVASCRIPT]);
        // A script in a stream, by reference, with no /S: still JavaScript.
        let js = stream("", b"app.alert(1)");
        assert_eq!(active(&doc("", &[b"<< /JS 4 0 R >>", &js])), vec![JAVASCRIPT]);
        // The document-level JavaScript name tree.
        assert_eq!(active(&doc("/Names << /JavaScript 3 0 R >>", &[b"<< /Names [(a) 4 0 R] >>", b"<< /S /JavaScript /JS (x) >>"])), vec![JAVASCRIPT]);
        assert_eq!(active(&action("<< /S /Launch /F (calc.exe) >>")), vec![LAUNCH]);
        assert_eq!(active(&action("<< /S /SubmitForm /F (https://example.com/) >>")), vec![SUBMIT_FORM]);
        assert_eq!(active(&action("<< /S /ImportData /F (data.fdf) >>")), vec![IMPORT_DATA]);
        assert_eq!(active(&action("<< /S /GoToE /T << /R /C /N (a) >> >>")), vec![GOTO_E]);
        assert_eq!(active(&doc("", &[b"<< /Type /Annot /Subtype /RichMedia /RichMediaContent << >> >>"])), vec![RICH_MEDIA]);
        // XFA forms with scripts.
        let xfa = stream("", b"<xdp:xdp><template><field><event><script contentType='application/x-javascript'>app.alert(1)</script></event></field></template></xdp:xdp>");
        assert_eq!(active(&doc("/AcroForm << /Fields [] /XFA 3 0 R >>", &[&xfa])), vec![JAVASCRIPT]);
        let xfa_flate = stream("/Filter /FlateDecode", &deflate(b"<template><SCRIPT>x</SCRIPT></template>"));
        assert_eq!(active(&doc("/AcroForm << /Fields [] /XFA [(template) 3 0 R] >>", &[&xfa_flate])), vec![JAVASCRIPT]);
        let static_xfa = stream("", b"<xdp:xdp><template><field/></template></xdp:xdp>");
        assert_eq!(active(&doc("/AcroForm << /Fields [] /XFA 3 0 R >>", &[&static_xfa])), Vec::<&str>::new());
        // Several at once, sorted.
        assert_eq!(active(&doc("/OpenAction 3 0 R", &[b"<< /S /Launch /F (setup.exe) /Next << /S /JavaScript /JS (x) >> >>"])), vec![JAVASCRIPT, LAUNCH]);
    }

    /// The features of a document whose OpenAction is object 3, `action`,
    /// followed by `more` (objects 4, …).
    fn launch(action: &str, more: &[&[u8]]) -> Vec<&'static str> {
        let mut objs: Vec<&[u8]> = vec![action.as_bytes()];
        objs.extend_from_slice(more);
        active(&doc("/OpenAction 3 0 R", &objs))
    }

    #[test]
    fn launch_targets() {
        let risky = |a: &str| assert_eq!(launch(a, &[]), vec![LAUNCH], "{a}");
        let benign = |a: &str| assert_eq!(launch(a, &[]), vec![LAUNCH_DOCUMENT], "{a}");
        // Programs and scripts, as a string or a file specification, any case.
        risky("<< /S /Launch /F (calc.exe) >>");
        risky("<< /S /Launch /F (MOVIE/BRIGHT.exe) >>");
        risky("<< /S /Launch /F (../../../PC/Acrobat/AR40ENG.EXE) >>");
        risky("<< /S /Launch /F << /Type /Filespec /F (Setup.Bat) >> >>");
        risky("<< /S /Launch /F << /Type /Filespec /F (readme.pdf) /UF (run.vbs) >> >>");
        risky("<< /S /Launch /F (evil.exe.) >>");
        risky("<< /S /Launch /F (setup#.exe) >>");
        risky("<< /S /Launch /F (manual.pdf calc.exe) >>");
        risky("<< /S /Launch /Unix (install.sh) >>");
        risky("<< /S /Launch /Mac << /F (Installer.app) >> >>");
        // Windows launch parameters, or an operation other than open/print.
        risky("<< /S /Launch /Win << /F (cmd.exe) /P (/c calc) >> >>");
        risky("<< /S /Launch /Win << /F (manual.pdf) /P (/c calc) >> >>");
        risky("<< /S /Launch /Win << /F (manual.pdf) /O (edit) >> >>");
        benign("<< /S /Launch /Win << /F (manual.pdf) /O (open) /P () >> >>");
        benign("<< /S /Launch /Win << /F (manual.pdf) /O (print) /D (c:\\\\docs) >> >>");
        // System programs named without an extension.
        risky("<< /S /Launch /F (/bin/sh) >>");
        risky("<< /S /Launch /F (C:\\\\Windows\\\\System32\\\\cmd) >>");
        risky("<< /S /Launch /F (powershell) >>");
        // Documents, web pages, broken script fragments, nothing.
        benign("<< /S /Launch /F (Welcome.pdf#G997350) >>");
        benign("<< /S /Launch /F (Other library.pdf#M9.81397.Dolby.Digital.output.from.the.DIGITAL.AUDIO.OUT.terminal) >>");
        benign("<< /S /Launch /F (../../TTX/eng/ttx.htm) >>");
        benign("<< /S /Launch /F (/C|/Users/x/Desktop/0-2.html?next) >>");
        benign("<< /S /Launch /F (shopcart.asp?Useraction=A&PartSelectedNumber=110011821) >>");
        benign("<< /S /Launch /F (showLayer\\(Infor,this\\);return%20false) >>");
        benign("<< /S /Launch /F (MM_swapImage\\(CustomizedKey,,../../_IMG/Lang/eng/osd/Magic.gif,1\\)) >>");
        benign("<< /S /Launch /F () >>");
        benign("<< /S /Launch >>");
        benign("<< /S /Launch /F null >>");
        // `.com`: a DOS program, unless shaped like a web or mail address.
        benign("<< /S /Launch /F (/kramer-il2/Jeremy/Template Design/www.kramerelectronics.com) >>");
        benign("<< /S /Launch /F (\\\\\\\\kfs\\\\users\\\\Template Design\\\\info@kramerel.com) >>");
        benign("<< /S /Launch /F (https://www.kramerav.com/) >>");
        risky("<< /S /Launch /F (COMMAND.COM) >>");
        risky("<< /S /Launch /F (kramerelectronics.com) >>");
        risky("<< /S /Launch /F (https://example.com/tool.com) >>");
        // An embedded target: Launch, and the attachment is EmbeddedFile too.
        let file = stream("/Type /EmbeddedFile", b"%PDF-1.4");
        assert_eq!(launch("<< /S /Launch /F << /Type /Filespec /F (manual.pdf) /EF << /F 4 0 R >> >> >>", &[&file]), vec![EMBEDDED_FILE, LAUNCH]);
        // A target that can't be read as a name hides what runs.
        let target = stream("", b"calc.exe");
        assert_eq!(launch("<< /S /Launch /F 4 0 R >>", &[&target]), vec![LAUNCH]);
        risky("<< /S /Launch /F 9 0 R >>");
        risky("<< /S /Launch /F [(manual.pdf)] >>");
        risky("<< /S /Launch /F << /F 7 >> >>");
        risky("<< /S /Launch /Win << /F (manual.pdf) /P 9 0 R >> >>");
        // A target by reference is followed.
        assert_eq!(launch("<< /S /Launch /F 4 0 R >>", &[b"(manual.pdf)"]), vec![LAUNCH_DOCUMENT]);
        assert_eq!(launch("<< /S /Launch /F 4 0 R >>", &[b"<< /F 5 0 R >>", b"(setup.exe)"]), vec![LAUNCH]);
        // An action type given by reference isn't classified.
        assert_eq!(launch("<< /S 4 0 R /F (manual.pdf) >>", &[b"/Launch"]), vec![LAUNCH]);
        // One risky action among benign ones.
        assert_eq!(launch("<< /S /Launch /F (a.pdf) /Next 4 0 R >>", &[b"<< /S /Launch /F (b.exe) >>"]), vec![LAUNCH, LAUNCH_DOCUMENT]);
    }

    #[test]
    fn risky_target_names() {
        assert_eq!(risky_target("MOVIE/BRIGHT.exe").as_deref(), Some("runs a .exe file"));
        assert_eq!(risky_target("  \"Setup.EXE\"  ").as_deref(), Some("runs a .exe file"));
        assert_eq!(risky_target("install.bat readme.txt").as_deref(), Some("names a .bat file"));
        assert_eq!(risky_target("cmd").as_deref(), Some("runs a system command"));
        assert_eq!(risky_target("/usr/bin/osascript").as_deref(), Some("runs a system command"));
        assert_eq!(risky_target("/usr/local/bin/tool").as_deref(), Some("runs a system program"));
        assert_eq!(risky_target("mailto:support@clearcube.com"), None);
        assert_eq!(risky_target("www.sens.ch"), None);
        assert_eq!(risky_target("H233H series.xls"), None);
        assert_eq!(risky_target("open manual.pdf"), None, "a document; words are judged by extension only");
        assert_eq!(risky_target(""), None);
    }

    #[test]
    fn launch_hidden_from_the_parser() {
        // A Launch in an object no cross-reference entry points at (appended
        // after the end): only the raw pass sees it, so it can't be judged.
        let mut pdf = doc("", &[]);
        pdf.extend_from_slice(b"9 0 obj\n<< /S /Launch /F (manual.pdf) >>\nendobj\n");
        assert_eq!(lexical(&pdf).launch.into_iter().collect::<Vec<_>>(), vec![Some((9, 0))]);
        assert_eq!(active(&pdf), vec![LAUNCH]);
        // An older revision of an object, replaced by an incremental update.
        let old = doc("/OpenAction 3 0 R", &[b"<< /S /Launch /F (setup.exe) >>"]);
        let at = old.len();
        let prev = memchr::memmem::rfind(&old, b"startxref\n").unwrap() + 10;
        let prev: usize = std::str::from_utf8(&old[prev..]).unwrap().split_whitespace().next().unwrap().parse().unwrap();
        let mut pdf = old.clone();
        pdf.extend_from_slice(b"3 0 obj\n<< /S /GoTo /D [0 /Fit] >>\nendobj\n");
        let xref = pdf.len();
        pdf.extend_from_slice(format!("xref\n3 1\n{at:010} 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R /Prev {prev} >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
        assert_eq!(active(&pdf), vec![LAUNCH]);
        // The same action loaded by the parser is judged.
        let pdf = doc("/OpenAction 3 0 R", &[b"<< /S /Launch /F (manual.pdf) >>"]);
        assert_eq!(lexical(&pdf).launch.into_iter().collect::<Vec<_>>(), vec![Some((3, 0))]);
        assert_eq!(active(&pdf), vec![LAUNCH_DOCUMENT]);
        // A file the parser can't read at all: Unparseable, and Launch.
        let mut broken = b"%PDF-1.7\n".to_vec();
        broken.extend_from_slice(b"3 0 obj << /S /Launch /F (manual.pdf) >> endobj");
        assert_eq!(active(&broken), vec![LAUNCH, UNPARSEABLE]);
    }

    fn attachment(name: &str, data: &[u8], typed: bool) -> Vec<u8> {
        let spec = format!("<< /Type /Filespec /F ({name}) /UF ({name}) /EF << /F 4 0 R >> >>").into_bytes();
        let file = stream(if typed { "/Type /EmbeddedFile" } else { "" }, data);
        doc("/Names << /EmbeddedFiles << /Names [(a) 3 0 R] >> >>", &[&spec, &file])
    }

    #[test]
    fn embedded_files() {
        assert_eq!(active(&attachment("setup.exe", b"MZ\x90\x00\x03\x00", true)), vec![EMBEDDED_FILE]);
        assert_eq!(active(&attachment("notes.txt", b"hello", false)), vec![EMBEDDED_FILE], "untyped stream, found through /EF");
        // Acrobat Distiller's settings attachment (about 3% of real manuals): not flagged...
        let settings = b"/ColorImageDict << /QFactor 0.15 >>\r\n/ParseDSCComments true\r\n";
        assert_eq!(active(&attachment("Press Quality.joboptions", settings, true)), Vec::<&str>::new());
        // ...unless it isn't plain text.
        assert_eq!(active(&attachment("Press Quality.joboptions", b"MZ\x90\x00\x03\x00", true)), vec![EMBEDDED_FILE]);
        // An embedded-file stream nothing points at still counts.
        let orphan = stream("/Type /EmbeddedFile", b"MZ");
        assert_eq!(active(&doc("", &[&orphan])), vec![EMBEDDED_FILE]);
    }

    #[test]
    fn object_streams_and_escaped_names() {
        // The action sits in a compressed object stream with `#xx`-escaped
        // names: invisible to a byte search, found by the parser.
        let pdf = with_objstm(&[b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>"], &[PAGES, b"<< /S /#4Aava#53cript /#4AS (app.alert\\(1\\)) >>", b"<< /S /#4C#61unch /F (x) >>"]);
        assert!(lexical(&pdf).found.is_empty());
        assert_eq!(active(&pdf), vec![JAVASCRIPT, LAUNCH_DOCUMENT]);
        // Launch targets in an object stream, with escaped names and the
        // target as a hex string (`calc.exe`, then UTF-16BE `setup.exe`).
        let pdf = with_objstm(&[b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>"], &[PAGES, b"<< /S /#4C#61unch /#46 <63616C632E657865> >>"]);
        assert!(lexical(&pdf).launch.is_empty());
        assert_eq!(active(&pdf), vec![LAUNCH]);
        let pdf = with_objstm(&[b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>"], &[PAGES, b"<< /S /Launch /F << /#55F <FEFF00730065007400750070002E006500780065> >> >>"]);
        assert_eq!(active(&pdf), vec![LAUNCH]);
        let pdf = with_objstm(&[b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>"], &[PAGES, b"<< /S /Launch /F (Welcome\\056pdf) >>"]);
        assert_eq!(active(&pdf), vec![LAUNCH_DOCUMENT]);
        let pdf = with_objstm(&[b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>"], &[PAGES, b"<< /S /Launch /F (calc\\056\\145xe) >>"]);
        assert_eq!(active(&pdf), vec![LAUNCH]);
        // Escapes outside object streams are decoded too (by both passes).
        let pdf = doc("/OpenAction 3 0 R", &[b"<< /S /Submit#46orm /F (u) >>"]);
        assert_eq!(lexical(&pdf).found.iter().copied().collect::<Vec<_>>(), vec![SUBMIT_FORM]);
        assert_eq!(active(&pdf), vec![SUBMIT_FORM]);
    }

    #[test]
    fn unparseable_never_panics() {
        assert_eq!(active(b""), vec![UNPARSEABLE]);
        assert_eq!(active(b"%PDF-1.4\n"), vec![UNPARSEABLE]);
        assert_eq!(active(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00"), vec![UNPARSEABLE]);
        // Pseudo-random garbage behind a PDF header.
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let mut garbage = b"%PDF-1.7\n".to_vec();
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            garbage.push(x as u8);
        }
        assert!(active(&garbage).contains(&UNPARSEABLE));
        // Every truncation of PDFs with features, and the same with bytes flipped: no panic.
        let js = with_objstm(&[b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>"], &[PAGES, b"<< /S /JavaScript /JS (x) >>"]);
        let att = attachment("a.exe", b"MZ", true);
        for pdf in [&js, &att] {
            for cut in 0..pdf.len() {
                scan_pdf(&pdf[..cut]);
                let mut flipped = pdf.clone();
                flipped[cut] ^= 0x55;
                scan_pdf(&flipped);
            }
        }
        // A truncated file that still reaches the script reports it (lexically
        // here: the file is cut before the cross-reference table).
        let plain = doc("/OpenAction 3 0 R", &[b"<< /S /JavaScript /JS (x) >>"]);
        let cut = memchr::memmem::find(&plain, b"xref").unwrap();
        assert!(active(&plain[..cut]).contains(&JAVASCRIPT));
    }

    #[test]
    fn hostile_structures() {
        // An object stream that inflates past MAX_DECODED: not expanded, so Unparseable.
        let with_stream = |content: &[u8]| with_custom_objstm(&[CATALOG, PAGES], 1, &stream("/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode", &deflate(content)));
        let mut ok = b"3 0 << /S /Launch >>".to_vec();
        assert_eq!(active(&with_stream(&ok)), vec![LAUNCH_DOCUMENT], "control: the swap itself parses");
        ok.resize(MAX_DECODED + 1024, b' ');
        assert_eq!(active(&with_stream(&ok)), vec![UNPARSEABLE]);
        // Deep nesting.
        let deep = format!("<< /A {}{} >>", "[".repeat(100_000), "]".repeat(100_000));
        scan_pdf(&doc("", &[deep.as_bytes()]));
        let deep = format!("{}", "<< /A ".repeat(50_000));
        scan_pdf(&doc("", &[deep.as_bytes()]));
        // Unbalanced strings and an unterminated stream.
        scan_pdf(b"%PDF-1.4\n1 0 obj (((((((\\\\\\ \nendobj stream\n");
        scan_pdf(b"%PDF-1.4\n1 0 obj << /Length 999999999 >>\nstream\n");
    }

    #[test]
    fn lexical_skips_strings_and_streams() {
        let l = lexical(b"1 0 obj << /Title (a /Launch (nested) \\) /Launch) /Hex <2F4C61756E6368> >> stream\n/JavaScript\nendstream endobj % /Launch\n");
        assert!(l.found.is_empty() && l.launch.is_empty(), "{:?}", l.found);
        // `/Launch` is attributed to its object, or to none (e.g. the trailer).
        let l = lexical(b"12 3 obj << /S /Launch >> endobj 4 0 obj\r\n[/L#61unch]\nendobj trailer << /Launch 1 >>");
        assert_eq!(l.launch.into_iter().collect::<Vec<_>>(), vec![None, Some((4, 0)), Some((12, 3))]);
        assert!(l.found.is_empty());
        let l = lexical(b"<< /S /#4Aava#53cript /Type /Embedded#46ile >> << /EmbeddedFiles 3 0 R >>");
        assert_eq!(l.found.into_iter().collect::<Vec<_>>(), vec![JAVASCRIPT]);
        assert_eq!((l.embedded_file_types, l.embedded_any), (1, true));
    }

    #[tokio::test]
    async fn file_scan_caps() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.pdf");
        std::fs::write(&p, doc("/OpenAction 3 0 R", &[b"<< /S /Launch /F (x.exe) >>"])).unwrap();
        assert_eq!(scan_pdf_file(&p).await.active, vec![LAUNCH]);
        assert_eq!(scan_pdf_file(&dir.path().join("missing.pdf")).await, Scan::unparseable());
        // Over the time cap: Unparseable (the scan of a large file can't finish in 1 ms).
        let big = dir.path().join("big.pdf");
        let mut b = doc("", &[]);
        b.extend(std::iter::repeat_n(b'(', 64 << 20));
        std::fs::write(&big, b).unwrap();
        assert_eq!(scan_pdf_file_within(&big, Duration::from_millis(1)).await, Scan::unparseable());
        assert_eq!(Scan::clean().to_json(), json!({"tool": "om-scan/2", "active": []}));
        assert_eq!(Scan::unparseable().to_json(), json!({"tool": "om-scan/2", "active": ["Unparseable"]}));
        assert!(outdated(&json!({"tool": "om-scan/1", "active": ["JavaScript", "Launch"]})));
        assert!(!outdated(&json!({"tool": "om-scan/1", "active": ["JavaScript"]})));
        assert!(!outdated(&json!({"tool": "om-scan/2", "active": ["Launch"]})));
    }
}
