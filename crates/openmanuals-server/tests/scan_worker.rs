//! The scan worker process: results come back from the real binary, and a
//! scan that runs past its time limit is killed, not abandoned.
use openmanuals_server::scan::{scan_in_process, Scan, JAVASCRIPT, LAUNCH_DOCUMENT};
use std::path::Path;
use std::time::Duration;

const EXE: &str = env!("CARGO_BIN_EXE_openmanuals-server");

fn pdf(objs: &[&str]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offs = vec![];
    for (i, o) in objs.iter().enumerate() {
        offs.push(out.len());
        out.extend(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offs {
        out.extend(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

async fn scan(p: &Path) -> Scan {
    scan_in_process(Path::new(EXE), p, Duration::from_secs(60)).await
}

#[tokio::test]
async fn results_come_back_from_the_worker() {
    let dir = tempfile::tempdir().unwrap();
    let clean = dir.path().join("clean.pdf");
    std::fs::write(&clean, pdf(&["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [] /Count 0 >>"])).unwrap();
    assert_eq!(scan(&clean).await, Scan::clean());

    let js = dir.path().join("js.pdf");
    std::fs::write(&js, pdf(&["<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>", "<< /Type /Pages /Kids [] /Count 0 >>", "<< /S /JavaScript /JS (app.alert\\(1\\)) >>"])).unwrap();
    assert_eq!(scan(&js).await.active, vec![JAVASCRIPT]);

    let doc = dir.path().join("doc.pdf");
    std::fs::write(&doc, pdf(&["<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>", "<< /Type /Pages /Kids [] /Count 0 >>", "<< /S /Launch /F (manual.pdf) >>"])).unwrap();
    assert_eq!(scan(&doc).await.active, vec![LAUNCH_DOCUMENT]);

    assert_eq!(scan(&dir.path().join("missing.pdf")).await, Scan::unparseable());
    assert_eq!(scan_in_process(Path::new("/nonexistent/openmanuals-server"), &clean, Duration::from_secs(5)).await, Scan::unparseable());
}

/// Live scan workers reading `path` (from /proc).
#[cfg(target_os = "linux")]
fn workers_on(path: &Path) -> usize {
    let needle = path.to_string_lossy().into_owned();
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| std::fs::read(e.ok()?.path().join("cmdline")).ok())
        .filter(|c| {
            let args: Vec<String> = c.split(|b| *b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
            args.iter().any(|a| a == "__scan") && args.iter().any(|a| *a == needle)
        })
        .count()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_scan_past_its_limit_is_killed() {
    // Reading a FIFO nobody writes to blocks forever: a scan that never ends.
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("stuck.pdf");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let t = std::time::Instant::now();
    assert_eq!(scan_in_process(Path::new(EXE), &fifo, Duration::from_secs(1)).await, Scan::unparseable());
    assert!(t.elapsed() < Duration::from_secs(10));
    // kill_on_drop sends SIGKILL; give the kernel a moment to reap it.
    for _ in 0..50 {
        if workers_on(&fifo) == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the timed-out scan worker is still running");
}
