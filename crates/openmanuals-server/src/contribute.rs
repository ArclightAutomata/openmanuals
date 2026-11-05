//! "Help preserve a manual": sends a visitor to a random manual we know exists
//! at a source the extension can capture (see [`SITES`]) but have no
//! downloadable file for. With uploads on, the extension preserves the
//! download and records the facts; this only picks the page.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::CachedQuery;
use rusqlite::Connection;
use serde_json::{json, Value};

/// Sources the extension captures downloads from.
pub const SOURCES_SQL: &str = "('manualslib', 'elektrotanya', 'manualzz', 'freeservicemanuals')";

/// A manuals site the extension checks, as the home page lists it.
pub struct Site {
    /// `manuals.source`.
    pub key: &'static str,
    pub name: &'static str,
    pub url: &'static str,
}

/// The sites in [`SOURCES_SQL`], in the order the home page shows them.
pub const SITES: &[Site] = &[
    Site { key: "manualslib", name: "ManualsLib", url: "https://www.manualslib.com/" },
    Site { key: "elektrotanya", name: "Elektrotanya", url: "https://www.elektrotanya.com/" },
    Site { key: "manualzz", name: "Manualzz", url: "https://manualzz.com/" },
    Site { key: "freeservicemanuals", name: "FreeServiceManuals.info", url: "https://freeservicemanuals.info/en/" },
];

/// A page handed out isn't handed out again for this long, so two visitors
/// aren't sent to the same manual.
const HOLD: Duration = Duration::from_secs(3 * 3600);
/// Bound on the memory of handed-out pages.
const MAX_HELD: usize = 50_000;
/// Per-brand counts are cached this long (they change only with a new snapshot).
const COUNTS_TTL: Duration = Duration::from_secs(600);
/// Random candidates drawn per pick; the first not handed out recently wins.
const DRAW: usize = 12;

#[derive(Default)]
pub struct Contribute {
    held: Mutex<HashMap<String, Instant>>,
    counts: Mutex<Option<(Instant, Value)>>,
    sites: Mutex<Option<(Instant, Value)>>,
}

impl Contribute {
    fn is_held(&self, id: &str) -> bool {
        self.held.lock().unwrap().get(id).is_some_and(|t| t.elapsed() < HOLD)
    }

    fn hold(&self, id: &str) {
        let mut h = self.held.lock().unwrap();
        if h.len() >= MAX_HELD {
            h.retain(|_, t| t.elapsed() < HOLD);
            if h.len() >= MAX_HELD {
                // Still full of live entries: forget the oldest half.
                let mut ts: Vec<Instant> = h.values().copied().collect();
                ts.sort();
                let cut = ts[ts.len() / 2];
                h.retain(|_, t| *t > cut);
            }
        }
        h.insert(id.to_string(), Instant::now());
    }

    /// A random missing manual's source page, optionally for one brand
    /// (a `brands.brand_key`). None when there is none left.
    pub fn pick(&self, db: &Connection, brand_key: Option<&str>) -> Option<String> {
        let (filter, args): (&str, Vec<&str>) = match brand_key {
            Some(b) => ("AND m.id IN (SELECT c.manual FROM covers c JOIN products p ON p.key = c.product WHERE p.brand_key = ?1)", vec![b]),
            None => ("", vec![]),
        };
        let sql = format!(
            "SELECT m.id, m.source_url FROM manuals m JOIN manual_search s ON s.manual = m.id \
             WHERE s.downloadable = 0 AND m.source IN {SOURCES_SQL} AND m.source_url IS NOT NULL {filter} \
             ORDER BY random() LIMIT {DRAW}"
        );
        let mut st = db.prepare_cached(&sql).ok()?;
        let rows: Vec<(String, String)> = st
            .query_map(rusqlite::params_from_iter(args), |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .ok()?
            .flatten()
            .filter(|(_, url)| capturable_url(url))
            .collect();
        let (id, url) = rows.iter().find(|(id, _)| !self.is_held(id)).or(rows.first())?.clone();
        self.hold(&id);
        Some(url)
    }

    /// How many are missing, overall and for the brands with the most.
    pub fn counts(&self, db: &Connection) -> Value {
        if let Some((at, v)) = self.counts.lock().unwrap().as_ref() {
            if at.elapsed() < COUNTS_TTL {
                return v.clone();
            }
        }
        let total = missing(db, None);
        let mut brands = Vec::new();
        let sql = format!(
            "SELECT p.brand_key, coalesce(b.brand, p.brand_key), count(DISTINCT m.id) AS n \
             FROM manuals m JOIN manual_search s ON s.manual = m.id JOIN covers c ON c.manual = m.id \
             JOIN products p ON p.key = c.product LEFT JOIN brands b ON b.brand_key = p.brand_key \
             WHERE s.downloadable = 0 AND m.source IN {SOURCES_SQL} AND m.source_url IS NOT NULL \
             GROUP BY p.brand_key ORDER BY n DESC, 2 LIMIT 60"
        );
        if let Ok(mut s) = db.prepare_cached(&sql) {
            let rows = s.query_map([], |r| Ok(json!({"key": r.get::<_, String>(0)?, "brand": r.get::<_, String>(1)?, "n": r.get::<_, i64>(2)?})));
            brands.extend(rows.into_iter().flatten().flatten());
        }
        let v = json!({ "total": total, "brands": brands });
        *self.counts.lock().unwrap() = Some((Instant::now(), v.clone()));
        v
    }

    /// Per site the extension checks: manuals known there and how many of
    /// them have a verified download. Cached like the brand counts.
    pub fn site_counts(&self, db: &Connection) -> Value {
        if let Some((at, v)) = &*self.sites.lock().unwrap() {
            if at.elapsed() < COUNTS_TTL {
                return v.clone();
            }
        }
        let mut n: HashMap<String, (i64, i64)> = HashMap::new();
        let sql = format!(
            "SELECT m.source, count(*), coalesce(sum(s.downloadable), 0) FROM manuals m JOIN manual_search s ON s.manual = m.id \
             WHERE m.source IN {SOURCES_SQL} GROUP BY m.source"
        );
        if let Ok(mut s) = db.prepare_cached(&sql) {
            let rows = s.query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))));
            n.extend(rows.into_iter().flatten().flatten());
        }
        let g = crate::activity::grouped;
        let v: Value = SITES
            .iter()
            .map(|site| {
                let (known, preserved) = n.get(site.key).copied().unwrap_or((0, 0));
                let pct = if known > 0 { preserved as f64 * 100.0 / known as f64 } else { 0.0 };
                json!({
                    "name": site.name, "url": site.url,
                    "known": g(known), "preserved": g(preserved),
                    "pct": format!("{pct:.1}"),
                    // A sliver stays visible for a site with a few preserved.
                    "bar": format!("{:.1}", if preserved > 0 { pct.max(1.0) } else { 0.0 }),
                })
            })
            .collect();
        *self.sites.lock().unwrap() = Some((Instant::now(), v.clone()));
        v
    }

    /// Drop cached counts (a new snapshot is live).
    pub fn invalidate(&self) {
        *self.counts.lock().unwrap() = None;
        *self.sites.lock().unwrap() = None;
    }
}

/// Missing manuals at capturable sources, overall or for one brand.
pub fn missing(db: &Connection, brand_key: Option<&str>) -> i64 {
    let base = format!(
        "SELECT count(*) FROM manuals m JOIN manual_search s ON s.manual = m.id \
         WHERE s.downloadable = 0 AND m.source IN {SOURCES_SQL} AND m.source_url IS NOT NULL"
    );
    match brand_key {
        Some(b) => db
            .query_row_cached(&format!("{base} AND m.id IN (SELECT c.manual FROM covers c JOIN products p ON p.key = c.product WHERE p.brand_key = ?1)"), [b], |r| r.get(0))
            .unwrap_or(0),
        None => db.query_row_cached(&base, [], |r| r.get(0)).unwrap_or(0),
    }
}

/// Only redirect to the source pages the extension works on. The URL comes
/// from a signed fact, so anything else (another host, a logout link) is
/// skipped rather than followed.
pub fn capturable_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let rest = rest.strip_prefix("www.").unwrap_or(rest);
    let path_ok = |p: &str| !p.contains(['?', '#', '\\', ' ']) && !p.contains("..");
    if let Some(p) = rest.strip_prefix("manualslib.com/manual/") {
        let (num, tail) = p.split_once('/').unwrap_or((p, ""));
        return !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) && path_ok(tail);
    }
    if let Some(p) = rest.strip_prefix("manualzz.com/doc/") {
        let (num, tail) = p.split_once('/').unwrap_or((p, ""));
        return !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) && path_ok(tail);
    }
    if let Some(p) = rest.strip_prefix("freeservicemanuals.info/") {
        return path_ok(p) && openmanuals_core::ids::parse_page_url(url).is_some_and(|m| m.source == "freeservicemanuals");
    }
    if let Some(p) = rest.strip_prefix("elektrotanya.com/") {
        return p.strip_suffix("/download.html").is_some_and(|name| !name.is_empty() && !name.contains('/') && path_ok(name));
    }
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_listed_sites_are_the_captured_sources() {
        let keys: Vec<String> = super::SITES.iter().map(|s| format!("'{}'", s.key)).collect();
        assert_eq!(super::SOURCES_SQL, format!("({})", keys.join(", ")));
    }

    use super::*;

    #[test]
    fn only_source_pages_are_followed() {
        assert!(capturable_url("https://www.manualslib.com/manual/3788897/Rca-J32pt1140.html"));
        assert!(capturable_url("https://manualslib.com/manual/12/X.html"));
        assert!(capturable_url("https://manualzz.com/doc/6961161/hitachi-cm721f---19--crt-display-user-manual"));
        assert!(capturable_url("https://elektrotanya.com/11ak30-1_basicline_bl2100ntd.hex/download.html"));
        assert!(capturable_url("https://freeservicemanuals.info/en/bookcats/DIGITAL%20PROCESSING%20SYSTEMS/TBC%20FRAMESTORE/DPS-375/"));
        assert!(capturable_url("https://freeservicemanuals.info/en/servicemanuals/viewmanual/Philips/14PV100/51TVB61/37TR216/DELTA2000/"));
        assert!(capturable_url("https://freeservicemanuals.info/en/tubedata/1N4148_3/"));
        for bad in [
            "http://www.manualslib.com/manual/1/X.html",
            "https://www.manualslib.com/logout",
            "https://www.manualslib.com/manual/abc/X.html",
            "https://www.manualslib.com/manual/1/X.html?next=https://evil.example",
            "https://manualslib.com.evil.example/manual/1/X.html",
            "https://evil.example/manual/1/X.html",
            "https://elektrotanya.com/a/b/download.html",
            "https://elektrotanya.com/x.pdf",
            "https://manualzz.com/doc/abc/x",
            "https://manualzz.com/download/6961161",
            "https://manualzz.com/doc/1/x-5z...",
            "https://manualzz.com.evil.example/doc/1/x",
            "https://freeservicemanuals.info/en/contact/",
            "https://freeservicemanuals.info/bookcats/download/dps-375.pdf",
            "https://freeservicemanuals.info/en/bookcats/A/B/../../contact/",
            "https://freeservicemanuals.info/en/bookcats/A/B/C/?next=x",
            "http://freeservicemanuals.info/en/bookcats/A/B/C/",
            "javascript:alert(1)",
        ] {
            assert!(!capturable_url(bad), "{bad}");
        }
    }

    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE manuals (id TEXT PRIMARY KEY, source TEXT, source_url TEXT);
             CREATE TABLE manual_search (manual TEXT PRIMARY KEY, downloadable INTEGER NOT NULL);
             CREATE TABLE covers (manual TEXT, product TEXT);
             CREATE TABLE products (key TEXT PRIMARY KEY, brand_key TEXT);
             CREATE TABLE brands (brand_key TEXT PRIMARY KEY, brand TEXT);
             INSERT INTO products VALUES ('rca|a', 'rca'), ('sony|b', 'sony');
             INSERT INTO brands VALUES ('rca', 'RCA'), ('sony', 'Sony');",
        )
        .unwrap();
        let add = |id: &str, source: &str, url: &str, dl: i64, product: &str| {
            db.execute("INSERT INTO manuals VALUES (?1, ?2, ?3)", [id, source, url]).unwrap();
            db.execute("INSERT INTO manual_search VALUES (?1, ?2)", rusqlite::params![id, dl]).unwrap();
            db.execute("INSERT INTO covers VALUES (?1, ?2)", [id, product]).unwrap();
        };
        add("A", "manualslib", "https://www.manualslib.com/manual/1/Rca-A.html", 0, "rca|a");
        add("B", "manualslib", "https://www.manualslib.com/manual/2/Rca-B.html", 0, "rca|a");
        add("C", "manualslib", "https://www.manualslib.com/manual/3/Sony-C.html", 1, "sony|b");
        add("D", "manualsbase", "https://www.manualsbase.com/manual/4/", 0, "sony|b");
        add("E", "elektrotanya", "https://elektrotanya.com/sony_e.pdf/download.html", 0, "sony|b");
        add("F", "manualslib", "https://www.manualslib.com/logout", 0, "sony|b");
        db
    }

    #[test]
    fn picks_missing_capturable_pages_and_spreads_visitors() {
        let db = db();
        let c = Contribute::default();
        // Overall: A, B, E and F are missing at capturable sources (F's URL is then refused).
        assert_eq!(missing(&db, None), 4);
        assert_eq!(missing(&db, Some("rca")), 2);
        let first = c.pick(&db, Some("rca")).unwrap();
        let second = c.pick(&db, Some("rca")).unwrap();
        assert_ne!(first, second, "a page just handed out isn't handed out again while others remain");
        assert!(c.pick(&db, Some("rca")).is_some(), "when all are held, one is still handed out");
        assert_eq!(c.pick(&db, Some("sony")).as_deref(), Some("https://elektrotanya.com/sony_e.pdf/download.html"));
        assert_eq!(c.pick(&db, Some("nobody")), None);
        let counts = c.counts(&db);
        assert_eq!(counts["total"], 4);
        assert_eq!(counts["brands"][0]["key"], "rca");
        assert_eq!(counts["brands"][0]["brand"], "RCA");
    }
}
