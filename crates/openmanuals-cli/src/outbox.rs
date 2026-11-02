//! Signed facts waiting to be pushed: `<home>/outbox/<ulid>.jsonl`, moved to `sent/` once accepted.

use crate::Home;
use anyhow::Result;
use openmanuals_core::Fact;
use std::io::Write;
use std::path::PathBuf;

pub fn queue(home: &Home, facts: &[Fact]) -> Result<PathBuf> {
    let path = home.dir.join("outbox").join(format!("{}.jsonl", ulid::Ulid::new()));
    let mut f = std::fs::File::create(&path)?;
    for fact in facts {
        writeln!(f, "{}", fact.to_json())?;
    }
    Ok(path)
}

pub fn pending(home: &Home) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(home.dir.join("outbox"))?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "jsonl")).collect();
    v.sort();
    Ok(v)
}
