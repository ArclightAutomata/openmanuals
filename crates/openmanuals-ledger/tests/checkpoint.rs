//! Resuming from a checkpoint must give the same bytes as a full build, and
//! must fall back to a full build whenever new facts could change the past.
use openmanuals_core::{sign::SigningKey, Alg, Fact};
use openmanuals_ledger::ledger::Entry;
use openmanuals_ledger::{build, BuildMode, BuildOptions, Ledger, TrustConfig};
#[allow(unused_imports)]
use openmanuals_ledger::ledger::Pos;
use serde_json::{json, Value};
use std::path::Path;

struct Gen {
    t: u64,
    out: Vec<Entry>,
}

impl Gen {
    /// Cursors spread over several days, so the ledger spans several files.
    fn add(&mut self, k: &SigningKey, t: &str, body: Value) -> String {
        let mut f = Fact::new(t, "x", "2026-10-23T18:00:00Z", body);
        k.sign_fact(&mut f).unwrap();
        let id = f.id().unwrap();
        self.t += 3_600_000 * 3 + 17;
        let cursor = ulid::Ulid::from_parts(1_790_000_000_000 + self.t, self.t as u128).to_string();
        self.out.push(Entry { cursor, id: id.clone(), fact: f });
        id
    }
}

fn hex(n: u64, len: usize) -> String {
    let s = format!("{:064x}", n.wrapping_mul(0x9E3779B97F4A7C15));
    s[64 - len..].to_string()
}

fn ulid(n: u64) -> String {
    ulid::Ulid::from_parts(1_700_000_000_000 + n, n as u128 * 7919).to_string()
}

/// A ledger touching every rule: merges, legacy files, verdicts, reports,
/// identity, and moderation (applied to earlier and later facts).
fn synth(n: u64) -> (Vec<Entry>, TrustConfig, Vec<SigningKey>) {
    let server = SigningKey::from_seed(Alg::Ed25519, &[1; 32]).unwrap();
    let keys: Vec<SigningKey> = (2..7u8).map(|i| SigningKey::from_seed(Alg::Ed25519, &[i; 32]).unwrap()).collect();
    let mut g = Gen { t: 0, out: vec![] };
    let mut locs: Vec<String> = vec![];
    let mut reports: Vec<String> = vec![];
    for i in 0..n {
        let k = &keys[(i % keys.len() as u64) as usize];
        let man = ulid(i / 2);
        let brand = ["JVC", "Sony", "sony", "Panasonic"][(i % 4) as usize];
        g.add(k, "manual", json!({"id": man, "title": format!("Manual {i}"), "doc_type": (["service", "user"][(i % 2) as usize]), "source_url": format!("https://example.com/{i}")}));
        g.add(k, "product", json!({"brand": brand, "model": format!("AV-{} TEE", i % 20)}));
        g.add(k, "covers", json!({"manual": man.to_lowercase(), "product": format!("{}|AV{}TEE", brand.to_lowercase(), i % 20)}));
        let sha = hex(i, 64);
        let sha1 = hex(i + 7, 40);
        if i % 5 == 0 {
            g.add(k, "file", json!({"sha1": sha1, "md5": hex(i, 32)}));
            locs.push(g.add(k, "location", json!({"file": format!("sha1:{sha1}"), "url": format!("https://archive.org/download/m-{i}/x.pdf"), "kind": "archive", "ia": {"identifier": format!("m-{i}")}})));
        }
        g.add(k, "file", json!({"sha256": sha, "sha1": sha1, "size": i}));
        g.add(k, "manual_file", json!({"manual": man, "file": sha}));
        if i % 3 == 0 {
            let st = hex(i + 1_000_000, 64);
            g.add(k, "file", json!({"sha256": st}));
            g.add(k, "derivation", json!({"derived": st, "source": sha, "transform": "watermark-stripped", "tool_version": format!("openmanuals-strip/{}", 1 + i % 3)}));
            g.add(k, "manual_file", json!({"manual": man, "file": st}));
            locs.push(g.add(k, "location", json!({"file": st, "url": format!("https://archive.org/download/o-{i}/m.pdf"), "kind": "archive"})));
        }
        locs.push(g.add(k, "location", json!({"file": sha, "url": format!("https://mirror{}.example.org/{i}.pdf", i % 3), "kind": "mirror"})));
        reports.push(g.add(k, "label", json!({"target": format!("file:{sha}"), "ns": "report", "value": "wrong-file"})));
        if i % 2 == 0 {
            let l = locs[(i as usize * 7) % locs.len()].clone();
            g.add(&server, "verified", json!({"location": l, "checked_at": format!("2026-10-{:02}T00:00:00Z", 1 + i % 28)}));
        }
        if i % 11 == 0 {
            let l = locs[(i as usize * 3) % locs.len()].clone();
            g.add(&server, "location_status", json!({"location": l, "status": "gone"}));
        }
        if i % 17 == 0 {
            g.add(k, "same_as", json!({"kind": "manual", "a": ulid(i / 2), "b": ulid(i / 2 + 1)}));
        }
        if i % 19 == 0 {
            g.add(k, "same_as", json!({"kind": "product", "a": format!("sony|AV{}TEE", i % 20), "b": format!("jvc|AV{}TEE", i % 20)}));
        }
        if i % 23 == 0 {
            g.add(&server, "prefer", json!({"manual": man, "file": sha}));
        }
        if i % 7 == 0 {
            // Avatars: newest wins per key, so moderation that hides the current one can't be undone in place.
            let body = match i % 3 {
                0 => json!({"sha256": hex(i + 5_000_000, 64), "size": 100 + i, "mime": "image/webp"}),
                1 => json!({"url": format!("https://example.org/a{i}.png")}),
                _ => json!({"none": true}),
            };
            g.add(k, "avatar", body);
        }
        if i % 13 == 0 {
            g.add(&keys[0], "vouch", json!({"key": keys[(i % 4 + 1) as usize].public_key().fingerprint()}));
        }
        if i % 31 == 0 {
            let target = reports[reports.len() / 2].clone();
            g.add(k, "retract", json!({"fact": target}));
        }
        if i % 37 == 0 {
            g.add(&server, "block", json!({"kind": "host", "value": format!("MIRROR{}.example.org", i % 3)}));
        }
        if i == n / 2 {
            g.add(&server, "block", json!({"kind": "key", "value": keys[4].public_key().fingerprint()}));
            let jws = keys[1].sign_profile("Bob", &["https://gist.github.com/bob/1".into()], None);
            g.add(&keys[1], "identity_profile", json!({"jws": jws}));
            for (j, k) in keys.iter().enumerate().take(3) {
                g.add(&server, "identity_link", json!({"key": k.public_key().fingerprint(), "claim_uri": format!("https://gist.github.com/bob/{j}"), "service": "github", "handle": "bob"}));
            }
        }
    }
    let mut cfg = TrustConfig::default();
    cfg.servers.insert(server.public_key().fingerprint());
    cfg.moderators.insert(server.public_key().fingerprint());
    cfg.include_unverified = true;
    cfg.thresholds.report = 1.0;
    let mut all = keys;
    all.insert(0, server);
    (g.out, cfg, all)
}

fn full_bytes(dir: &Path, entries: &[Entry], cfg: &TrustConfig) -> Vec<u8> {
    let l = Ledger::open(dir.join("full")).unwrap();
    l.append(entries).unwrap();
    let out = dir.join("full.db");
    let s = build(&l, cfg, &out, &BuildOptions::default()).unwrap();
    assert_eq!(s.mode, BuildMode::Full);
    std::fs::read(out).unwrap()
}

#[test]
fn resuming_at_any_point_matches_a_full_build() {
    let (entries, cfg, _) = synth(90);
    let tmp = tempfile::tempdir().unwrap();
    let want = full_bytes(tmp.path(), &entries, &cfg);
    let files = { let l = Ledger::open(tmp.path().join("full")).unwrap(); l.files().unwrap().len() };
    assert!(files > 3, "spans several day files ({files})");
    let mut incremental = 0;
    for split in (1..entries.len()).step_by(29).chain([entries.len() - 1]) {
        let dir = tmp.path().join(format!("s{split}"));
        let l = Ledger::open(&dir).unwrap();
        let cp = dir.join("checkpoint.bin");
        let opts = BuildOptions { checkpoint: Some(cp.clone()), ..Default::default() };
        l.append(&entries[..split]).unwrap();
        build(&l, &cfg, &dir.join("a.db"), &opts).unwrap();
        l.append(&entries[split..]).unwrap();
        let s = build(&l, &cfg, &dir.join("b.db"), &opts).unwrap();
        if s.mode == BuildMode::Incremental {
            incremental += 1;
            if s.resumed_from.as_deref() == Some("checkpoint") {
                assert_eq!(s.applied, entries.len() - split);
            } else {
                // Replayed from a day checkpoint: more than the new facts.
                assert!(s.resumed_from.as_deref().unwrap().starts_with("day ") && s.applied > entries.len() - split, "{s:?}");
            }
        } else {
            // Only moderation reaching back may force it.
            let r = s.full_rebuild_reason.clone().unwrap();
            assert!(r.contains("moderator") || r.contains("first signed fact") || r.contains("no checkpoint before"), "{r}");
        }
        assert_eq!(std::fs::read(dir.join("b.db")).unwrap(), want, "split at {split} ({:?})", s.mode);
        // And resuming with nothing new still gives the same bytes.
        let s = build(&l, &cfg, &dir.join("c.db"), &opts).unwrap();
        assert_eq!((s.mode, s.applied), (BuildMode::Incremental, 0));
        assert_eq!(std::fs::read(dir.join("c.db")).unwrap(), want);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    assert!(incremental > 3, "most splits resume ({incremental})");
}

/// Same counters as a full build of the same ledger.
fn assert_same_stats(a: &openmanuals_ledger::BuildStats, b: &openmanuals_ledger::BuildStats) {
    let f = |s: &openmanuals_ledger::BuildStats| (s.entries, s.invalid, s.blocked, s.retracted, s.manuals, s.products, s.files, s.locations, s.verified_locations, s.keys, s.head.clone());
    assert_eq!(f(a), f(b));
}

#[test]
fn moderation_that_reaches_back_is_undone_in_place_or_replayed() {
    let (entries, cfg, keys) = synth(20);
    let (server, alice) = (&keys[0], &keys[1]);
    let tmp = tempfile::tempdir().unwrap();
    let l = Ledger::open(tmp.path()).unwrap();
    let cp = tmp.path().join("checkpoint.bin");
    let opts = BuildOptions { checkpoint: Some(cp.clone()), ..Default::default() };
    l.append(&entries).unwrap();
    build(&l, &cfg, &tmp.path().join("a.db"), &opts).unwrap();
    let mut g = Gen { t: 10_000_000_000, out: vec![] };
    let mut n = 0;
    let mut step = |g: &mut Gen, l: &Ledger| -> openmanuals_ledger::BuildStats {
        l.append(&g.out).unwrap();
        g.out.clear();
        n += 1;
        let (inc, full) = (tmp.path().join(format!("i{n}.db")), tmp.path().join(format!("f{n}.db")));
        let s = build(l, &cfg, &inc, &opts).unwrap();
        let want = build(l, &cfg, &full, &BuildOptions::default()).unwrap();
        assert_eq!(std::fs::read(&inc).unwrap(), std::fs::read(&full).unwrap(), "step {n}: {s:?}");
        assert_same_stats(&s, &want);
        s
    };

    // A retraction of a fact in the same new batch: resumable, nothing to undo.
    let label = g.add(alice, "label", json!({"target": "file:x", "ns": "report", "value": "spam"}));
    g.add(alice, "retract", json!({"fact": label}));
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.undone, s.resumed_from.as_deref()), (BuildMode::Incremental, 0, Some("checkpoint")));

    // A retraction of an older report: taken back in place.
    let retracted: Vec<&str> = entries.iter().filter(|e| e.fact.r#type == "retract").filter_map(|e| e.fact.body["fact"].as_str()).collect();
    let mine = |t: &str| entries.iter().filter(|e| e.fact.author == alice.public_key().fingerprint() && e.fact.r#type == t && !retracted.contains(&e.id.as_str())).map(|e| e.id.clone()).collect::<Vec<_>>();
    g.add(alice, "retract", json!({"fact": mine("label")[0]}));
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.undone, s.resumed_from.as_deref()), (BuildMode::Incremental, 1, Some("checkpoint")), "{s:?}");

    // Someone else's retraction counts for nothing, also in place.
    g.add(server, "retract", json!({"fact": mine("label")[1]}));
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.resumed_from.as_deref()), (BuildMode::Incremental, Some("checkpoint")));

    // Older covers, locations, derivations, manual_files, products repeated by others: in place.
    for t in ["covers", "location", "derivation", "manual_file"] {
        g.add(alice, "retract", json!({"fact": mine(t)[0]}));
    }
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.undone, s.resumed_from.as_deref()), (BuildMode::Incremental, 4, Some("checkpoint")), "{s:?}");

    // A moderator's fact block and unblock of a label: block in place; the
    // unblock reveals it again, which needs a replay.
    let other = mine("label")[2].clone();
    g.add(server, "block", json!({"kind": "fact", "value": other}));
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.undone, s.resumed_from.as_deref()), (BuildMode::Incremental, 1, Some("checkpoint")), "{s:?}");
    g.add(server, "unblock", json!({"kind": "fact", "value": other}));
    let s = step(&mut g, &l);
    assert_ne!(s.resumed_from.as_deref(), Some("checkpoint"), "{s:?}");

    // Host (un)blocks only matter at the end: in place either way.
    g.add(server, "unblock", json!({"kind": "host", "value": "mirror1.example.org"}));
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.undone, s.resumed_from.as_deref()), (BuildMode::Incremental, 0, Some("checkpoint")), "{s:?}");
    g.add(server, "block", json!({"kind": "host", "value": "Mirror2.example.org"}));
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.resumed_from.as_deref()), (BuildMode::Incremental, Some("checkpoint")));

    // A manual block drops the manual in place; unblocking needs a replay.
    let man = entries.iter().find(|e| e.fact.r#type == "manual").unwrap().fact.body["id"].as_str().unwrap().to_string();
    g.add(server, "block", json!({"kind": "manual", "value": man}));
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.resumed_from.as_deref()), (BuildMode::Incremental, Some("checkpoint")), "{s:?}");
    g.add(server, "unblock", json!({"kind": "manual", "value": man}));
    let s = step(&mut g, &l);
    assert_ne!(s.resumed_from.as_deref(), Some("checkpoint"), "{s:?}");

    // A non-moderator's "block" is just a fact.
    g.add(alice, "block", json!({"kind": "key", "value": server.public_key().fingerprint()}));
    let s = step(&mut g, &l);
    assert_eq!((s.mode, s.resumed_from.as_deref()), (BuildMode::Incremental, Some("checkpoint")));

    // A retracted file fact (merged first-wins) and a key block: replayed.
    g.add(alice, "retract", json!({"fact": mine("file")[0]}));
    let s = step(&mut g, &l);
    assert_ne!(s.resumed_from.as_deref(), Some("checkpoint"), "{s:?}");
    assert!(s.full_rebuild_reason.as_deref().is_some_and(|r| r.contains("file fact")), "{s:?}");
    g.add(server, "block", json!({"kind": "key", "value": alice.public_key().fingerprint()}));
    let s = step(&mut g, &l);
    assert!(s.full_rebuild_reason.as_deref().is_some_and(|r| r.contains("moderator block of key")), "{s:?}");
}

/// A tiny deterministic PRNG (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

/// Random moderation (retractions right and wrong, fact/manual/host/key
/// blocks and unblocks) and ordinary facts, appended in rounds; every
/// resumed build must give the bytes and counters of a full build.
#[test]
fn random_moderation_matches_full_builds() {
    let (base, cfg, keys) = synth(60);
    let by_fp: std::collections::HashMap<String, &SigningKey> = keys.iter().map(|k| (k.public_key().fingerprint(), k)).collect();
    let server = &keys[0];
    let (mut undone, mut in_place, mut from_day, mut full) = (0, 0, 0, 0);
    let seeds: u64 = std::env::var("OM_TEST_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    for seed in 1..=seeds {
        let mut rng = Rng(seed * 0x9E37_79B9_7F4A_7C15);
        let tmp = tempfile::tempdir().unwrap();
        let l = Ledger::open(tmp.path().join("l")).unwrap();
        let opts = BuildOptions { checkpoint: Some(tmp.path().join("checkpoint.bin")), ..Default::default() };
        let split = base.len() / 2 + rng.below(base.len() / 2);
        l.append(&base[..split]).unwrap();
        build(&l, &cfg, &tmp.path().join("a.db"), &opts).unwrap();
        let mut all: Vec<Entry> = base[..split].to_vec();
        let mut pending: Vec<Entry> = base[split..].to_vec();
        let mut g = Gen { t: base.len() as u64 * (3_600_000 * 3 + 17), out: vec![] };
        let mut blocked_facts: Vec<String> = vec![];
        let mut blocked_manuals: Vec<String> = vec![];
        for round in 0..8 {
            // The rest of the base ledger first (cursors only grow), then moderation.
            g.out.append(&mut pending);
            for _ in 0..1 + rng.below(4) {
                // Mostly recent facts (as moderation mostly is), now and then
                // anything; mostly ids the ledger holds once (the inbox
                // dedups; the synthetic ledger repeats some facts).
                let pick = |rng: &mut Rng| if rng.chance(75) { all.len() - 1 - rng.below(all.len().min(150)) } else { rng.below(all.len()) };
                let mut i = pick(&mut rng);
                for _ in 0..20 {
                    if rng.chance(5) || all.iter().filter(|e| e.id == all[i].id).count() == 1 {
                        break;
                    }
                    i = pick(&mut rng);
                }
                let target = &all[i];
                let author = by_fp[&target.fact.author];
                match rng.below(100) {
                    0..=54 => drop(g.add(author, "retract", json!({"fact": target.id}))),
                    55..=62 => drop(g.add(&keys[1 + rng.below(keys.len() - 1)], "retract", json!({"fact": target.id}))),
                    63..=77 => {
                        blocked_facts.push(target.id.clone());
                        g.add(server, "block", json!({"kind": "fact", "value": target.id}));
                    }
                    78..=82 if !blocked_facts.is_empty() => {
                        let v = blocked_facts[rng.below(blocked_facts.len())].clone();
                        g.add(server, "unblock", json!({"kind": "fact", "value": v}));
                    }
                    83..=88 => {
                        let man = all.iter().filter(|e| e.fact.r#type == "manual").nth(rng.below(10)).unwrap().fact.body["id"].as_str().unwrap().to_string();
                        blocked_manuals.push(man.clone());
                        g.add(server, "block", json!({"kind": "manual", "value": man}));
                    }
                    89..=90 if !blocked_manuals.is_empty() => {
                        let v = blocked_manuals[rng.below(blocked_manuals.len())].clone();
                        g.add(server, "unblock", json!({"kind": "manual", "value": v}));
                    }
                    91..=95 => {
                        let kind = if rng.chance(50) { "block" } else { "unblock" };
                        g.add(server, kind, json!({"kind": "host", "value": format!("mirror{}.example.org", rng.below(3))}));
                    }
                    96..=97 => drop(g.add(server, "block", json!({"kind": "key", "value": keys[1 + rng.below(keys.len() - 1)].public_key().fingerprint()}))),
                    _ => drop(g.add(server, "unblock", json!({"kind": "key", "value": keys[1 + rng.below(keys.len() - 1)].public_key().fingerprint()}))),
                }
            }
            // Ordinary facts too, some retracted right away.
            let k = &keys[1 + rng.below(keys.len() - 1)];
            let lab = g.add(k, "label", json!({"target": format!("file:{}", hex(rng.next(), 64)), "ns": "report", "value": "spam"}));
            if rng.chance(30) {
                g.add(k, "retract", json!({"fact": lab}));
            }
            l.append(&g.out).unwrap();
            all.append(&mut g.out);
            let (inc, fb) = (tmp.path().join(format!("i{round}.db")), tmp.path().join(format!("f{round}.db")));
            let s = build(&l, &cfg, &inc, &opts).unwrap();
            let want = build(&l, &cfg, &fb, &BuildOptions::default()).unwrap();
            if std::fs::read(&inc).unwrap() != std::fs::read(&fb).unwrap() {
                dump_diff(&inc, &fb);
            }
            assert_eq!(std::fs::read(&inc).unwrap(), std::fs::read(&fb).unwrap(), "seed {seed} round {round}: {s:?}");
            assert_same_stats(&s, &want);
            undone += s.undone;
            match (s.mode, s.resumed_from.as_deref()) {
                (BuildMode::Incremental, Some("checkpoint")) => in_place += 1,
                (BuildMode::Incremental, _) => from_day += 1,
                _ => full += 1,
            }
            if s.resumed_from.as_deref() != Some("checkpoint") && std::env::var("OM_TEST_VERBOSE").is_ok() {
                eprintln!("seed {seed} round {round}: {:?} from {:?}: {:?}", s.mode, s.resumed_from, s.full_rebuild_reason);
            }
        }
    }
    eprintln!("undone {undone}; resumed from the checkpoint {in_place}, from a day {from_day}, full {full}");
    assert!(undone > 30 && in_place > 10 && from_day > 5 && full > 0, "every path is exercised: undone {undone}, in place {in_place}, day {from_day}, full {full}");
}

/// Moderation hitting facts on different days, each needing a replay: the
/// build resumes from the newest day checkpoint before the target's day.
#[test]
fn replays_start_from_the_day_before_the_target() {
    let (entries, cfg, keys) = synth(60);
    let tmp = tempfile::tempdir().unwrap();
    let want_base = full_bytes(tmp.path(), &entries, &cfg);
    let files: Vec<String> = { let l = Ledger::open(tmp.path().join("full")).unwrap(); l.file_lengths().unwrap().into_iter().map(|(f, _)| f).collect() };
    let _ = want_base;
    let l = Ledger::open(tmp.path().join("l")).unwrap();
    let opts = BuildOptions { checkpoint: Some(tmp.path().join("checkpoint.bin")), ..Default::default() };
    // Build day by day, as a server folding through the days would.
    let mut start = 0;
    for f in &files {
        let end = entries.iter().position(|e| openmanuals_ledger::ledger::cursor_date_path(&e.cursor).unwrap() + ".jsonl" > *f).unwrap_or(entries.len());
        l.append(&entries[start..end]).unwrap();
        start = end;
        build(&l, &cfg, &tmp.path().join("x.db"), &opts).unwrap();
    }
    let days = std::fs::read_dir(tmp.path().join("checkpoint.cache/days")).unwrap().count();
    assert!((8..=11).contains(&days), "daily 7 + weekly ladder ({days})");
    let mut g = Gen { t: entries.len() as u64 * (3_600_000 * 3 + 17), out: vec![] };
    let by_fp: std::collections::HashMap<String, &SigningKey> = keys.iter().map(|k| (k.public_key().fingerprint(), k)).collect();
    // Retract live file facts (merged first-wins, so never undone in place)
    // from the newest day backwards (the synthetic ledger blocks keys[5]).
    let blocked = keys[5].public_key().fingerprint();
    let file_facts: Vec<&Entry> = entries.iter().filter(|e| e.fact.r#type == "file" && e.fact.author != blocked).collect();
    let mut seen_day = 0;
    for target in file_facts.iter().rev().step_by(3).take(6) {
        g.add(by_fp[&target.fact.author], "retract", json!({"fact": target.id}));
        l.append(&g.out).unwrap();
        g.out.clear();
        let s = build(&l, &cfg, &tmp.path().join("i.db"), &opts).unwrap();
        let want = build(&l, &cfg, &tmp.path().join("f.db"), &BuildOptions::default()).unwrap();
        assert_eq!(std::fs::read(tmp.path().join("i.db")).unwrap(), std::fs::read(tmp.path().join("f.db")).unwrap(), "{s:?}");
        assert_same_stats(&s, &want);
        let day = openmanuals_ledger::ledger::cursor_date_path(&target.cursor).unwrap() + ".jsonl";
        match s.resumed_from.as_deref() {
            Some(d) if d.starts_with("day ") => {
                seen_day += 1;
                assert!(d["day ".len()..] < *day, "{d} is before {day}");
            }
            other => assert_eq!(s.mode, BuildMode::Full, "{other:?} {s:?}"),
        }
    }
    assert!(seen_day >= 2, "{seen_day}");
}

/// The resident API: chained in-memory builds equal full builds, and the
/// state it hands back saves as a checkpoint the next process can use.
#[test]
fn resident_builds_match_full_builds() {
    let (entries, cfg, _) = synth(40);
    let tmp = tempfile::tempdir().unwrap();
    let l = Ledger::open(tmp.path().join("l")).unwrap();
    let cp = tmp.path().join("checkpoint.bin");
    let opts = BuildOptions { checkpoint: Some(cp.clone()), ..Default::default() };
    let tuning = openmanuals_ledger::Tuning::default();
    let mut resident = None;
    let mut resumed = 0;
    let chunks: Vec<&[Entry]> = entries.chunks(entries.len() / 5 + 1).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        l.append(chunk).unwrap();
        let (s, r) = openmanuals_ledger::build_resident(&l, &cfg, &tmp.path().join("r.db"), &opts, &tuning, resident.take()).unwrap();
        build(&l, &cfg, &tmp.path().join("f.db"), &BuildOptions::default()).unwrap();
        assert_eq!(std::fs::read(tmp.path().join("r.db")).unwrap(), std::fs::read(tmp.path().join("f.db")).unwrap());
        if i == 0 {
            assert_eq!(s.mode, BuildMode::Full);
        } else if s.mode == BuildMode::Full {
            // The synthetic ledger blocks a key halfway: that reaches back to its first fact.
            assert!(s.full_rebuild_reason.as_deref().unwrap().contains("block of key"), "{s:?}");
        } else {
            resumed += 1;
            assert_eq!(s.resumed_from.as_deref(), Some("resident"), "{s:?}");
        }
        assert!(!cp.exists() || i > 2, "the caller decides when to save");
        if i == 2 {
            r.as_ref().unwrap().save(&cp).unwrap();
        }
        resident = r;
    }
    assert!(resumed >= 2, "{resumed}");
    // A new process: no resident, resumes from the saved checkpoint.
    let s = build(&l, &cfg, &tmp.path().join("n.db"), &opts).unwrap();
    assert_eq!((s.mode, s.resumed_from.as_deref()), (BuildMode::Incremental, Some("checkpoint")), "{s:?}");
    assert_eq!(std::fs::read(tmp.path().join("n.db")).unwrap(), std::fs::read(tmp.path().join("f.db")).unwrap());
}

/// Unchanged table groups are copied from the previous snapshot's parts,
/// with the same bytes as writing them anew.
#[test]
fn unchanged_parts_are_reused() {
    let (entries, cfg, keys) = synth(30);
    let tmp = tempfile::tempdir().unwrap();
    let l = Ledger::open(tmp.path().join("l")).unwrap();
    let opts = BuildOptions { checkpoint: Some(tmp.path().join("checkpoint.bin")), ..Default::default() };
    l.append(&entries).unwrap();
    let s = build(&l, &cfg, &tmp.path().join("a.db"), &opts).unwrap();
    assert_eq!((s.parts_reused, s.parts_written), (0, 13));
    // A verifier-only fold: a verdict on an existing copy.
    let loc = entries.iter().rev().find(|e| e.fact.r#type == "location").unwrap().id.clone();
    let mut g = Gen { t: 50_000_000_000, out: vec![] };
    g.add(&keys[0], "verified", json!({"location": loc, "checked_at": "2026-10-29T00:00:00Z"}));
    l.append(&g.out).unwrap();
    let s = build(&l, &cfg, &tmp.path().join("b.db"), &opts).unwrap();
    let want = build(&l, &cfg, &tmp.path().join("f.db"), &BuildOptions::default()).unwrap();
    assert_eq!(want.parts_reused, 0);
    assert_eq!(std::fs::read(tmp.path().join("b.db")).unwrap(), std::fs::read(tmp.path().join("f.db")).unwrap());
    assert!(s.parts_reused >= 6, "{s:?}");
    let parts = std::fs::read_dir(tmp.path().join("checkpoint.cache/parts")).unwrap().count();
    assert_eq!(parts, 13, "only the current parts are kept");
    // Nothing new: everything but meta... and meta too (same head).
    let s = build(&l, &cfg, &tmp.path().join("c.db"), &opts).unwrap();
    assert_eq!((s.parts_reused, s.parts_written), (13, 0));
    assert_eq!(std::fs::read(tmp.path().join("c.db")).unwrap(), std::fs::read(tmp.path().join("f.db")).unwrap());
}

#[test]
fn stale_or_damaged_checkpoints_are_not_trusted() {
    let (entries, cfg, _) = synth(12);
    let tmp = tempfile::tempdir().unwrap();
    let l = Ledger::open(tmp.path()).unwrap();
    let cp = tmp.path().join("checkpoint.bin");
    let opts = BuildOptions { checkpoint: Some(cp.clone()), ..Default::default() };
    l.append(&entries).unwrap();
    let reason = |cfg: &TrustConfig| build(&l, cfg, &tmp.path().join("o.db"), &opts).unwrap().full_rebuild_reason;
    assert_eq!(reason(&cfg).as_deref(), Some("no checkpoint"));
    assert_eq!(reason(&cfg), None);

    let mut other = cfg.clone();
    other.thresholds.report = 3.0;
    assert_eq!(reason(&other).as_deref(), Some("trust config changed"));
    assert_eq!(reason(&cfg).as_deref(), Some("trust config changed"));
    assert_eq!(reason(&cfg), None);

    // History rewritten (a purge): the first file loses a line.
    let first = &l.files().unwrap()[0];
    let text = std::fs::read_to_string(first).unwrap();
    let rest: String = text.lines().skip(1).map(|x| format!("{x}\n")).collect();
    std::fs::write(first, rest).unwrap();
    assert_eq!(reason(&cfg).as_deref(), Some("ledger history changed"));
    assert_eq!(reason(&cfg), None);

    let mut bytes = std::fs::read(&cp).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 1;
    std::fs::write(&cp, &bytes).unwrap();
    assert_eq!(reason(&cfg).as_deref(), Some("corrupt checkpoint"));
    std::fs::write(&cp, b"junk").unwrap();
    assert_eq!(reason(&cfg).as_deref(), Some("corrupt checkpoint"));
    assert_eq!(reason(&cfg), None);
}

#[test]
fn a_moderation_fact_the_fast_scan_misses_is_still_applied() {
    let (entries, cfg, keys) = synth(15);
    let server = &keys[0];
    let mut g = Gen { t: 20_000_000_000, out: vec![] };
    g.add(server, "block", json!({"kind": "key", "value": keys[1].public_key().fingerprint()}));
    let tmp = tempfile::tempdir().unwrap();
    let want = {
        let mut all = entries.clone();
        all.extend(g.out.clone());
        full_bytes(tmp.path(), &all, &cfg)
    };
    // Same facts, but the block's type spelled with a JSON escape: it parses
    // the same, yet the byte prefilter can't see it.
    let disguise = |l: &Ledger| {
        let last = l.files().unwrap().pop().unwrap();
        let text = std::fs::read_to_string(&last).unwrap();
        assert!(text.contains(r#""type":"block""#));
        let escaped = format!("\"type\":\"bl{}u006fck\"", char::from(92u8)); // "bl\u006fck"
        let disguised = text.replace(r#""type":"block""#, &escaped);
        assert!(!disguised.contains(r#""type":"block""#) && disguised.contains("u006f"));
        std::fs::write(&last, disguised).unwrap();
    };

    let l = Ledger::open(tmp.path().join("a")).unwrap();
    l.append(&entries).unwrap();
    l.append(&g.out).unwrap();
    disguise(&l);
    let s = build(&l, &cfg, &tmp.path().join("a.db"), &BuildOptions::default()).unwrap();
    assert_eq!(s.mode, BuildMode::Full);
    assert_eq!(std::fs::read(tmp.path().join("a.db")).unwrap(), want);

    // Arriving after a checkpoint: the resumed build must notice and rebuild.
    let l = Ledger::open(tmp.path().join("b")).unwrap();
    let opts = BuildOptions { checkpoint: Some(tmp.path().join("b.bin")), ..Default::default() };
    l.append(&entries).unwrap();
    build(&l, &cfg, &tmp.path().join("b1.db"), &opts).unwrap();
    l.append(&g.out).unwrap();
    disguise(&l);
    let s = build(&l, &cfg, &tmp.path().join("b2.db"), &opts).unwrap();
    assert_eq!(s.mode, BuildMode::Full);
    assert_eq!(s.full_rebuild_reason.as_deref(), Some("the fast scan missed a moderation fact"));
    assert_eq!(std::fs::read(tmp.path().join("b2.db")).unwrap(), want);
}

fn dump_diff(a: &Path, b: &Path) {
    let ca = rusqlite::Connection::open(a).unwrap();
    let cb = rusqlite::Connection::open(b).unwrap();
    let tables: Vec<String> = ca.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'manual_fts%'").unwrap().query_map([], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect();
    for t in tables {
        let rows = |c: &rusqlite::Connection| -> Vec<String> {
            let mut st = c.prepare(&format!("SELECT * FROM {t}")).unwrap();
            let n = st.column_count();
            st.query_map([], |r| Ok((0..n).map(|i| format!("{:?}", r.get_ref(i).unwrap())).collect::<Vec<_>>().join("|"))).unwrap().map(|x| x.unwrap()).collect()
        };
        let (ra, rb) = (rows(&ca), rows(&cb));
        if ra != rb {
            eprintln!("table {t}: {} vs {} rows", ra.len(), rb.len());
            for r in ra.iter().filter(|r| !rb.contains(r)).take(5) { eprintln!("  only incremental: {r}"); }
            for r in rb.iter().filter(|r| !ra.contains(r)).take(5) { eprintln!("  only full: {r}"); }
        }
    }
}
