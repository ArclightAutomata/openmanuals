#!/usr/bin/env python3
"""Generate the architecture diagrams in this directory (SVG).

Run from anywhere: `python3 docs/diagrams/make.py`. Standard library only.
The style follows Wikipedia's technical diagrams (e.g. Commons' Hash_Tree.svg):
sharp black-outlined boxes on white, a pale accent band for detail text,
dashed light-gray containers, solid black arrows, sans-serif labels.
"""
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent
FONT = "DejaVu Sans, Liberation Sans, Arial, Helvetica, sans-serif"
MONO = "DejaVu Sans Mono, Liberation Mono, Menlo, Consolas, monospace"

# Accent bands by role (pastels, so black text stays readable).
KIND = {
    "client": "#d9ead3",   # people and their software
    "service": "#cfe2f3",  # running processes
    "data": "#ffeeaa",     # files and databases (Hash_Tree.svg's yellow)
    "trust": "#f4cccc",    # keys, signatures, checks
    "external": "#e6e6e6", # services we don't run
}
ARROW = {"black": "#000000", "blue": "#0060B6", "red": "#BF0000", "purple": "#8210D2", "gray": "#8C8C8C"}


class Diagram:
    def __init__(self, name, width, height, title, desc):
        self.name, self.w, self.h = name, width, height
        self.title, self.desc = title, desc
        self.parts = []
        self.late = []  # drawn last (group headings over lines)

    # -- primitives ---------------------------------------------------------
    def text(self, x, y, s, size=13, anchor="middle", weight="normal", color="#000", italic=False, mono=False):
        style = ' font-style="italic"' if italic else ""
        if mono:
            style += ' xml:space="preserve"'
        self.parts.append(
            f'<text x="{x}" y="{y}" font-family="{MONO if mono else FONT}" font-size="{size}" '
            f'text-anchor="{anchor}" font-weight="{weight}" fill="{color}"{style}>{escape(s)}</text>')

    def rect(self, x, y, w, h, fill="#fff", stroke="#000", sw=1.5, dash=None, rx=0):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>')

    def box(self, x, y, w, h, title, lines=(), kind="service", mono=False, title_size=15, line_size=12):
        """White box, title on top, detail lines in a colored band below it."""
        self.rect(x, y, w, h)
        top = 30 if title else 0
        if lines:
            self.parts.append(f'<rect x="{x + 0.75}" y="{y + top}" width="{w - 1.5}" height="{h - top - 0.75}" fill="{KIND[kind]}" stroke="none"/>')
            if title:
                self.parts.append(f'<line x1="{x}" y1="{y + top}" x2="{x + w}" y2="{y + top}" stroke="#000" stroke-width="0.75"/>')
        if title:
            self.text(x + w / 2, y + 21 if lines else y + h / 2 + 5, title, title_size)
        if lines:
            band = h - top
            step = line_size + 4
            y0 = y + top + (band - step * len(lines)) / 2 + line_size
            for i, ln in enumerate(lines):
                self.text(x + w / 2, y0 + i * step, ln, line_size, mono=mono)
        return (x, y, w, h)

    def group(self, x, y, w, h, label, anchor="start"):
        self.rect(x, y, w, h, fill="none", stroke="#aaaaaa", sw=2, dash="10,8")
        lx = x + 12 if anchor == "start" else x + w / 2
        self.late.append(
            f'<text x="{lx}" y="{y + 22}" font-family="{FONT}" font-size="14" text-anchor="{anchor}" font-weight="bold" fill="#555555" '
            f'stroke="#fff" stroke-width="5" paint-order="stroke" stroke-linejoin="round">{escape(label)}</text>')

    def arrow(self, pts, color="black", dash=False, both=False, label=None, at=None, label_anchor="middle", sw=1.75, label_color=None):
        c = ARROW[color]
        d = " ".join(f"{'M' if i == 0 else 'L'}{x},{y}" for i, (x, y) in enumerate(pts))
        extra = ' stroke-dasharray="7,5"' if dash else ""
        start = f' marker-start="url(#s-{color})"' if both else ""
        self.parts.append(f'<path d="{d}" fill="none" stroke="{c}" stroke-width="{sw}"{extra} marker-end="url(#e-{color})"{start}/>')
        if label:
            lx, ly = at if at else ((pts[0][0] + pts[-1][0]) / 2, (pts[0][1] + pts[-1][1]) / 2 - 6)
            self.label(lx, ly, label, label_anchor, label_color or ("#000" if color == "black" else c))

    def label(self, x, y, s, anchor="middle", color="#000", size=12):
        """Small text on a white halo so it stays legible over lines."""
        self.parts.append(
            f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" text-anchor="{anchor}" fill="{color}" '
            f'stroke="#fff" stroke-width="4" paint-order="stroke" stroke-linejoin="round">{escape(s)}</text>')

    def diamond(self, cx, cy, w, h, lines, kind="trust"):
        pts = f"{cx},{cy - h / 2} {cx + w / 2},{cy} {cx},{cy + h / 2} {cx - w / 2},{cy}"
        self.parts.append(f'<polygon points="{pts}" fill="{KIND[kind]}" stroke="#000" stroke-width="1.5"/>')
        y0 = cy - (len(lines) - 1) * 8 + 4
        for i, ln in enumerate(lines):
            self.text(cx, y0 + i * 16, ln, 13)

    def raw(self, s):
        self.parts.append(s)

    def legend(self, x, y, kinds=("client", "service", "data", "trust", "external")):
        names = {"client": "client / person", "service": "process", "data": "file or database", "trust": "key, signature or check", "external": "external service"}
        for i, k in enumerate(kinds):
            yy = y + i * 24
            self.rect(x, yy, 22, 16, fill=KIND[k], sw=1)
            self.text(x + 32, yy + 13, names[k], 12, anchor="start")

    # -- output -------------------------------------------------------------
    def save(self):
        markers = []
        for name, c in ARROW.items():
            markers.append(f'<marker id="e-{name}" viewBox="-12 -6 14 12" refX="0" refY="0" markerWidth="9" markerHeight="9" orient="auto" markerUnits="userSpaceOnUse">'
                           f'<path d="M0,0 L-11,-5 L-8,0 L-11,5 Z" fill="{c}"/></marker>')
            markers.append(f'<marker id="s-{name}" viewBox="-2 -6 14 12" refX="0" refY="0" markerWidth="9" markerHeight="9" orient="auto" markerUnits="userSpaceOnUse">'
                           f'<path d="M0,0 L11,-5 L8,0 L11,5 Z" fill="{c}"/></marker>')
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}" role="img" aria-labelledby="t d">\n'
               f'<title id="t">{escape(self.title)}</title>\n<desc id="d">{escape(self.desc)}</desc>\n'
               f'<defs>{"".join(markers)}</defs>\n'
               f'<rect width="100%" height="100%" fill="#ffffff"/>\n'
               + "\n".join(self.parts + self.late) + "\n</svg>\n")
        (OUT / f"{self.name}.svg").write_text(svg)


# ---------------------------------------------------------------------------
def overview():
    d = Diagram("overview", 1240, 800, "OpenManuals architecture",
                "Contributors sign facts and send them to openmanuals-server, which folds them into a git ledger, builds a deterministic SQLite snapshot and publishes it for the website, the API, om sync, the extension and static mirrors.")
    d.text(20, 38, "OpenManuals: system overview", 22, anchor="start")

    # Contributors and readers (left)
    d.group(20, 70, 240, 360, "Contributors")
    E = d.box(40, 100, 200, 100, "Browser extension", ["signs facts (WebCrypto key)", "strips watermarks", "uploads PDFs to archive.org"], "client")
    C = d.box(40, 228, 200, 80, "om CLI", ["sign · sync · upload", "strip · import"], "client")
    MOD = d.box(40, 330, 200, 84, "Moderators", ["om block / unblock: keys,", "facts, manuals, hosts", "(listed in build.toml)"], "trust")
    d.group(20, 570, 240, 190, "Readers")
    VIS = d.box(40, 600, 200, 50, "Website visitors", (), "client")
    XL = d.box(40, 668, 200, 76, "Extension lookups", ["filter → /api/lookup →", "mirror if server is down"], "client")
    d.legend(36, 448)

    # openmanuals-server
    d.group(290, 70, 640, 690, "openmanuals-server")
    A = d.box(320, 100, 170, 80, "API", ["POST /api/facts", "signatures · budgets", "blocked keys → 403"])
    I = d.box(540, 100, 170, 80, "Inbox", ["inbox.db (SQLite)"], "data")
    V = d.box(740, 100, 160, 80, "Verifier", ["hashes copies; checks", "proofs via doip-verify"])
    F = d.box(540, 222, 170, 80, "Fold", ["debounced 5 s", "(at most 60 s)"])
    L = d.box(740, 222, 160, 80, "Ledger", ["git repo of JSONL", "ledger/YYYY/MM/DD"], "data")
    S = d.box(540, 344, 170, 80, "Build state", ["resident resolver,", "checkpoints, part cache"], "data")
    B = d.box(740, 344, 160, 80, "Build", ["openmanuals-ledger,", "deterministic; applies", "moderators' blocks"])
    P = d.box(740, 466, 160, 80, "Publish", ["version · zstd · diff ·", "page hashes · filter"])
    D = d.box(540, 600, 360, 120, "snapshots/  (static, immutable)",
              ["<version>.db · .db.zst · .pages", "diff/<from>.<to>.jsonl.zst", "manifest.json + .sig · lookup-filter.bin"], "data")
    R = d.box(320, 600, 190, 120, "Pages & API", ["/manuals · /manual/<id>", "/api/lookup · /db/*", "pooled, mmap'd reads"])

    d.arrow([(240, 135), (320, 135)])
    d.arrow([(240, 268), (280, 268), (280, 160), (320, 160)])
    d.arrow([(490, 140), (540, 140)])
    d.arrow([(740, 140), (710, 140)])
    d.arrow([(625, 180), (625, 222)])
    d.arrow([(710, 262), (740, 262)])
    d.arrow([(820, 302), (820, 344)])
    d.arrow([(740, 384), (710, 384)], both=True)
    d.arrow([(820, 424), (820, 466)])
    d.arrow([(820, 546), (820, 600)])
    d.arrow([(540, 660), (510, 660)])
    d.arrow([(320, 625), (240, 625)])
    d.arrow([(320, 706), (240, 706)])
    d.label(625, 206, "facts", size=11)
    d.arrow([(240, 372), (300, 372), (300, 172), (320, 172)], color="red", label="block facts", at=(306, 300), label_anchor="start")

    # External (right)
    d.group(950, 70, 270, 340, "Elsewhere")
    IA = d.box(970, 96, 230, 56, "archive.org", (), "external")
    H = d.box(970, 166, 230, 56, "Other file hosts", (), "external")
    K = d.box(970, 236, 230, 56, "Proof sites", (), "external")
    G = d.box(970, 330, 230, 56, "GitHub (ledger mirror)", (), "external")
    d.arrow([(900, 124), (970, 124)], color="blue")
    d.arrow([(900, 124), (935, 124), (935, 194), (970, 194)], color="blue")
    d.arrow([(900, 124), (935, 124), (935, 264), (970, 264)], color="blue")
    d.label(928, 205, "fetch & check", anchor="end", color=ARROW["blue"])
    d.arrow([(900, 282), (950, 282), (950, 358), (970, 358)], color="gray", label="git push", at=(990, 312), label_anchor="start")
    d.arrow([(140, 100), (140, 52), (1085, 52), (1085, 96)], color="purple", label="upload PDFs", at=(600, 46))

    d.group(950, 570, 270, 190, "Downloaders")
    M = d.box(970, 600, 230, 66, "Static mirrors", ["any host with HTTP Range"], "external")
    SY = d.box(970, 684, 230, 60, "om sync", ["diffs or zstd snapshot"], "client")
    d.arrow([(900, 633), (970, 633)], label="rsync", at=(935, 625))
    d.arrow([(900, 700), (935, 700), (935, 714), (970, 714)])
    d.arrow([(1210, 633), (1230, 633), (1230, 785), (140, 785), (140, 744)], color="red", dash=True,
            label="Range reads, every page checked", at=(690, 779))
    d.save()


def fact():
    d = Diagram("fact", 1220, 640, "Anatomy of a signed fact",
                "A fact envelope is canonicalized with RFC 8785, hashed to its id and signed by the author's key; the author is the key's fingerprint, and identity proofs link keys to accounts.")
    d.text(20, 38, "A signed fact", 22, anchor="start")
    # Envelope
    env = [
        '{ "v": 1,',
        '  "type": "location",',
        '  "author": "QPRGVPJNWDXH4ESK2RYDTZJLTE",',
        '  "at": "2026-10-23T18:00:00Z",',
        '  "body": {',
        '    "file": "9f86d081…0a08",',
        '    "url": "https://archive.org/download/…",',
        '    "kind": "archive" },',
    ]
    sig = [
        '  "sig": { "alg": "Ed25519", "fmt": "raw",',
        '           "key": { "crv": "Ed25519", "x": "…" },',
        '           "value": "8hpr4LcH…TKA6qB17SKTZ5Ag" } }',
    ]
    x0, y0 = 30, 70
    d.rect(x0, y0, 470, 300)
    d.raw(f'<rect x="{x0 + 0.75}" y="{y0 + 30}" width="468.5" height="{len(env) * 20 + 10}" fill="{KIND["data"]}"/>')
    d.raw(f'<rect x="{x0 + 0.75}" y="{y0 + 40 + len(env) * 20}" width="468.5" height="{300 - 40 - len(env) * 20 - 0.75}" fill="{KIND["trust"]}"/>')
    d.text(x0 + 235, y0 + 21, "Fact envelope (one ledger line)", 15)
    for i, ln in enumerate(env):
        d.text(x0 + 14, y0 + 52 + i * 20, ln, 13, anchor="start", mono=True)
    for i, ln in enumerate(sig):
        d.text(x0 + 14, y0 + 60 + (len(env) + i) * 20, ln, 12, anchor="start", mono=True)

    # Hashing and signing
    J = d.box(570, 70, 250, 74, "Canonical bytes", ["RFC 8785 (JCS) of the", "envelope without \"sig\""], "trust")
    ID = d.box(900, 70, 290, 74, "Fact id", ["sha256:<hex of the canonical bytes>"], "data", mono=False)
    SG = d.box(570, 200, 250, 84, "Sign", ["Ed25519", "non-extractable WebCrypto", "key in the extension"], "trust")
    d.arrow([(500, 107), (570, 107)], label="drop sig", at=(535, 99))
    d.arrow([(820, 107), (900, 107)], label="sha256", at=(860, 99))
    d.arrow([(695, 144), (695, 200)])
    d.arrow([(570, 242), (500, 242)], label="sig.value", at=(535, 234))

    # Key → fingerprint → identity
    FP = d.box(900, 200, 290, 84, "Fingerprint = author", ["base32(SHA-512(JWK {crv,kty,x})[:16])", "QPRGVPJNWDXH4ESK2RYDTZJLTE"], "trust")
    d.arrow([(820, 242), (900, 242)], label="public key", at=(860, 234))
    PR = d.box(900, 330, 290, 90, "Identity profile", ["Ariadne Signature Profile (JWS)", "aspe:openmanuals.win:<fp>", "claims: gist, DNS, Mastodon…"], "client")
    LK = d.box(570, 330, 250, 90, "identity_link", ["signed by the server after", "tools/doip-verify checked", "the claim on its site"], "trust")
    d.arrow([(1045, 284), (1045, 330)])
    d.arrow([(900, 375), (820, 375)], label="verified", at=(860, 367))

    # Fact types
    d.group(30, 452, 1160, 170, "Fact types")
    cols = [
        ("Catalog (anyone)", "data", ["manual · product · covers", "file · manual_file", "location · derivation · same_as"]),
        ("Identity (anyone)", "client", ["identity_profile", "succession · vouch"]),
        ("Opinions (anyone)", "service", ["label (reports)", "retract (own facts)"]),
        ("Moderation (trusted keys)", "trust", ["block · unblock · prefer", "applied at build time"]),
        ("Server (server key)", "external", ["verified · location_status", "identity_link"]),
    ]
    for i, (t, k, lines) in enumerate(cols):
        d.box(50 + i * 228, 486, 212, 116, t, lines, k, title_size=13)
    d.save()


def build():
    d = Diagram("build", 1240, 680, "The snapshot build",
                "openmanuals-ledger streams the ledger in two passes into a compact resolver state, resumes from checkpoints, and writes the SQLite snapshot in parallel table groups merged in a fixed order.")
    d.text(20, 38, "Building manuals.db from the ledger (openmanuals-ledger)", 22, anchor="start")
    # Ledger files (stack)
    for k in range(3):
        d.rect(40 + k * 8, 92 - k * 8, 150, 92, fill=KIND["data"])
    d.text(131, 128, "ledger/", 15)
    d.text(131, 148, "YYYY/MM/DD.jsonl", 12)
    d.text(131, 166, "one fact per line", 12)

    d.group(240, 64, 980, 250, "Read (streaming: memory grows with the catalog, not the ledger)")
    P1 = d.box(270, 100, 200, 74, "Pass 1", ["block · unblock · retract", "SIMD substring prefilter"])
    MO = d.box(520, 100, 180, 74, "Moderation", ["blocked keys, hosts,", "facts · retractions"], "data")
    RD = d.box(270, 210, 200, 80, "Reader thread", ["batches of", "1,024 lines"])
    PP = d.box(520, 210, 180, 80, "Parse pool", ["8 threads, borrowed", "views of each line"])
    AP = d.box(750, 210, 190, 80, "Apply in order", ["one thread, cursor", "order (deterministic)"])
    RS = d.box(990, 150, 200, 110, "Resolver state", ["u128 ULIDs · byte hashes", "interned strings", "manuals, files, copies…"], "data")
    d.arrow([(214, 120), (270, 137)])
    d.arrow([(214, 160), (240, 160), (240, 250), (270, 250)])
    d.arrow([(470, 137), (520, 137)])
    d.arrow([(470, 250), (520, 250)])
    d.arrow([(700, 250), (750, 250)])
    d.arrow([(610, 174), (610, 192), (845, 192), (845, 210)], color="gray", label="hides facts", at=(730, 186), label_color="#555")
    d.arrow([(940, 240), (990, 240)])
    d.label(375, 199, "pass 2", size=12)

    # Checkpoints
    CK = d.box(990, 330, 200, 120, "Checkpoints", ["checkpoint.bin (latest)", "day checkpoints (7 days", "+ 4 weeks), fact-id", "filters per day file"], "trust")
    d.arrow([(1090, 260), (1090, 330)], both=True)
    d.box(690, 340, 260, 100, "Resume, don't restart", ["apply only new facts;", "undo a block/retraction in place,", "else replay from a day checkpoint"], "service", title_size=14)
    d.arrow([(990, 390), (950, 390)], color="gray")

    # Finish and write
    FI = d.box(40, 360, 200, 80, "Finish", ["merges, statuses, report", "weights, canonical picks"])
    d.arrow([(1010, 260), (1010, 302), (140, 302), (140, 360)])
    d.group(240, 480, 980, 180, "Write (parallel table groups, merged in a fixed order)")
    names = ["meta", "identity", "labels", "derivations", "brands", "manual_files", "files", "locations", "products", "covers", "manuals", "manual_search", "manual_fts"]
    for i, n in enumerate(names):
        col, row = i % 7, i // 7
        d.box(258 + col * 94, 520 + row * 52, 90, 40, None, [n], "data", line_size=10)
    d.label(580, 640, "each group: its own SQLite file and thread; unchanged groups reused from the part cache", size=12)
    MG = d.box(940, 520, 124, 92, "Merge", ["INSERT … SELECT", "fixed order"])
    DB = d.box(1080, 520, 120, 92, "manuals.db", ["16 KiB pages", "same bytes", "every time"], "data")
    d.arrow([(140, 440), (140, 545), (250, 545)])
    d.label(150, 462, "Model: the resolved catalog", anchor="start")
    d.arrow([(912, 566), (940, 566)])
    d.arrow([(1064, 566), (1080, 566)])
    d.save()


def publish():
    d = Diagram("publish", 1240, 700, "Publishing and syncing snapshots",
                "Each build is published as an immutable version with a zstd copy, a row diff from the previous version, page hashes, a lookup filter and a signed manifest; clients use diffs, the compressed copy, the filter or range reads.")
    d.text(20, 38, "Publishing a snapshot", 22, anchor="start")
    # Version chain
    d.group(20, 64, 1200, 150, "Versions: <ledger head>-<content id>  (immutable; newest 3 kept, diffs for 30 days)")
    xs = [60, 380, 700]
    labels = ["01M5PC…AZM-2b51a5b8585c", "01M5PN…QVB-c928e7ed6595", "01M680…TAS-bc2b773f89d3"]
    for i, x in enumerate(xs):
        d.box(x, 100, 250, 70, f"v{i + 1}", [labels[i]], "data", mono=True, line_size=11)
    for i in range(2):
        d.arrow([(xs[i] + 250, 135), (xs[i + 1], 135)], color="blue", label=f"diff v{i + 1}→v{i + 2}", at=((xs[i] + 250 + xs[i + 1]) / 2, 127))
    d.box(1000, 100, 200, 70, "latest.db", ["hard link to newest"], "data")
    d.arrow([(950, 135), (1000, 135)], color="gray", dash=True)

    # Publish step and outputs
    PB = d.box(40, 290, 220, 120, "Publish (after each build)", ["name by content", "link latest.db", "compress · diff · hash", "sign manifest · prune"], "service", title_size=14)
    d.group(300, 236, 380, 450, "snapshots/  (any static host)")
    outs = [
        ("<version>.db", "118 MB; pages read it, mirrors serve it", "data"),
        ("<version>.db.zst", "zstd -9: 27 MB to download", "data"),
        ("<version>.pages", "sha256 of every 16 KiB page", "trust"),
        ("diff/<from>.<to>.jsonl.zst", "changed rows (~0.5 MB per fold)", "data"),
        ("lookup-filter.bin", "known pages, 141 KB", "data"),
        ("manifest.json + .sig", "versions, sizes, hashes, server key", "trust"),
    ]
    for i, (n, sub, k) in enumerate(outs):
        d.box(320, 270 + i * 68, 340, 56, n, [sub], k, title_size=13, line_size=11)
    d.arrow([(260, 350), (300, 350)])
    # Consumers: one arrow each from the directory, with what they read
    cons = [
        (260, "Website & API", ["latest.db, through a pooled,", "memory-mapped reader"], "service"),
        (366, "om sync", ["manifest → diff chain if smaller,", "else .db.zst; checks table hashes"], "client"),
        (472, "Extension filter", ["lookup-filter.bin every 6 h;", "unknown pages stay local"], "client"),
        (578, "Mirrors & range readers", ["manifest, .pages and .db pages;", "every page verified"], "external"),
    ]
    for y, t, lines, k in cons:
        d.box(900, y, 300, 86, t, lines, k)
        d.arrow([(680, y + 43), (900, y + 43)])
    d.save()


def mirror():
    d = Diagram("mirror-verify", 1220, 640, "Verifying pages from an untrusted mirror",
                "The extension trusts a mirror's manifest only if it is signed by the pinned server key; the manifest lists hashes of groups of page hashes, which verify every 16 KiB page fetched with a Range request.")
    d.text(20, 38, "Reading a snapshot page by page from any mirror", 22, anchor="start")
    # Top: key and manifest
    KY = d.box(60, 76, 270, 74, "Pinned server key", ["fingerprint saved while the", "server was reachable (TOFU)"], "trust")
    SG = d.box(400, 76, 260, 74, "manifest.json.sig", ["signature over", "sha256(manifest)"], "trust")
    MF = d.box(730, 66, 420, 94, "manifest.json", ["version · size · server_key", "pages: page_size 16384, count 7,189,", "groups[g] = sha256(page hashes of group g)"], "data")
    d.arrow([(330, 113), (400, 113)], label="verifies", at=(365, 105))
    d.arrow([(660, 113), (730, 113)], label="covers", at=(695, 105))

    # Group hashes
    d.group(40, 200, 1120, 110, "Group hashes (in the manifest): 57 groups of 128 pages")
    gx = [80, 290, 500, 870]
    for i, x in enumerate(gx):
        if i == 2:
            d.text(690, 262, "…", 28)
        name = f"G{i}" if i < 3 else "G56"
        d.box(x, 236, 170, 56, name, ["sha256 of 128 hashes"], "trust", line_size=11)
    for x in gx:
        d.arrow([(x + 85, 236), (x + 85, 180), (940, 180), (940, 160)])

    # Page hashes from .pages
    d.group(40, 340, 1120, 110, "<version>.pages: 32-byte sha256 of every page (fetched 64 KiB at a time)")
    hx = [80, 230, 380, 530]
    names = ["h0", "h1", "…", "h127"]
    for x, n in zip(hx, names):
        if n == "…":
            d.text(x + 60, 400, "…", 28)
            continue
        d.box(x, 376, 120, 56, n, ["sha256(page)"], "trust", line_size=11)
    d.box(870, 376, 170, 56, "h7188", ["sha256(page)"], "trust", line_size=11)
    d.text(780, 410, "…", 28)
    for x in (80, 230, 530):
        d.arrow([(x + 60, 376), (x + 60, 330), (165, 330), (165, 292)])
    d.arrow([(955, 376), (955, 292)])

    # Pages
    d.group(40, 480, 1120, 140, "<version>.db: 16 KiB pages, fetched with HTTP Range from any mirror")
    for i, x in enumerate([80, 230, 530]):
        d.rect(x, 520, 120, 76, fill="#ffffff")
        d.raw(f'<rect x="{x + 0.75}" y="{550}" width="118.5" height="45.25" fill="{KIND["data"]}"/>')
        d.text(x + 60, 541, ["page 0", "page 1", "page 127"][i], 13)
        d.text(x + 60, 578, "B-tree bytes", 11)
    d.text(440, 562, "…", 28)
    d.rect(870, 520, 170, 76, fill="#ffffff")
    d.raw(f'<rect x="870.75" y="550" width="168.5" height="45.25" fill="{KIND["data"]}"/>')
    d.text(955, 541, "page 7188", 13)
    d.text(955, 578, "B-tree bytes", 11)
    d.text(780, 562, "…", 28)
    for x in (80, 230, 530):
        d.arrow([(x + 60, 520), (x + 60, 432)], color="red")
    d.arrow([(955, 520), (955, 432)], color="red")
    d.label(1100, 556, "sha256(page)", size=12, color=ARROW["red"])
    d.label(1100, 572, "must match its h,", size=12, color=ARROW["red"])
    d.label(1100, 588, "else refused", size=12, color=ARROW["red"])
    d.save()


def lookup():
    d = Diagram("lookup", 1120, 870, "How the extension looks up a page",
                "The extension checks a local filter first, asks the server only on a possible hit, and falls back to snapshot mirrors when the server is unreachable. A live archive.org identifier check is an advanced setting, off by default.")
    d.text(20, 38, "Extension: looking up a page on a supported manual site", 22, anchor="start")
    cx = 330
    d.box(cx - 150, 70, 300, 56, "Page visited", ["manual page or download page"], "client")
    d.diamond(cx, 200, 300, 100, ["In the lookup filter?", "(or submitted from", "this browser)"])
    d.box(cx - 150, 290, 300, 56, "GET /api/lookup", ["to the OpenManuals server"], "service")
    d.diamond(cx, 420, 260, 90, ["Server reachable?"])
    d.box(cx - 150, 520, 300, 74, "Mirror lookup", ["offscreen worker: SQLite over", "Range requests, pages verified"], "service")
    d.diamond(cx, 670, 220, 84, ["Answered?"])
    # Right column outcomes
    KN = d.box(640, 400, 400, 74, "Known manual", ["best copy (archive.org first), mutes", "and reports applied → banner + download"], "data")
    LG = d.box(640, 560, 400, 74, "Live archive.org check (optional)", ["Advanced setting, off by default: old-style", "identifiers (check_identifier, then metadata)"], "external")
    BN = d.box(640, 730, 400, 74, "Banner", ["\"free on the Internet Archive\" or", "\"not archived yet\" (+ upload if enabled)"], "client")
    d.arrow([(cx, 126), (cx, 150)])
    d.arrow([(cx, 250), (cx, 290)], label="yes (or no filter)", at=(cx + 12, 276), label_anchor="start")
    d.arrow([(cx + 150, 200), (1090, 200), (1090, 752), (1040, 752)], label="no: nothing leaves the browser", at=(760, 192))
    d.arrow([(cx, 346), (cx, 375)])
    d.arrow([(cx + 130, 420), (640, 420)], label="yes", at=(540, 412))
    d.arrow([(cx, 465), (cx, 520)], label="no", at=(cx + 18, 500), label_anchor="start")
    d.arrow([(cx, 594), (cx, 628)])
    d.arrow([(cx + 110, 670), (600, 670), (600, 450), (640, 450)], label="yes", at=(520, 662))
    d.arrow([(cx - 110, 670), (120, 670), (120, 845), (610, 845), (610, 597), (640, 597)], label="no", at=(200, 662))
    d.label(130, 862, "no: to the live check if it is on; otherwise straight to the banner", anchor="start", color="#555")
    d.arrow([(840, 474), (840, 520), (1060, 520), (1060, 782), (1040, 782)], color="gray")
    d.arrow([(840, 634), (840, 730)])
    d.save()


def capture():
    d = Diagram("capture", 1260, 860, "How a download is preserved",
                "With uploads on, the extension fetches a manual once when you download it, saves your copy, hashes it, strips watermarks, uploads the stripped file to archive.org under your account, and sends a signed bundle of facts to the OpenManuals server, whose verifier later checks the copy.")
    d.text(20, 38, "Extension: preserving a manual you download", 22, anchor="start")
    d.group(20, 60, 1020, 590, "Your browser (the manual site's tab and the extension)")
    # Row 1: the click
    d.box(40, 90, 220, 80, "Download clicked", ["a click, Manualzz's form,", "or Save link as…"], "client")
    d.diamond(420, 130, 240, 110, ["Upload on, keys", "saved, not", "preserved yet?"])
    d.box(330, 205, 180, 50, "The site handles it", (), "client", title_size=13)
    d.box(580, 90, 220, 80, "Fetch the file once", ["content script, or the", "service worker's fetch port"], "service")
    d.box(840, 90, 180, 80, "Your copy", ["saved to Downloads", "as before"], "client")
    d.arrow([(260, 130), (300, 130)])
    d.arrow([(420, 185), (420, 205)], label="no", at=(430, 200), label_anchor="start")
    d.arrow([(540, 130), (580, 130)], label="yes", at=(560, 122))
    d.arrow([(800, 130), (840, 130)])
    d.arrow([(690, 170), (690, 300), (150, 300), (150, 360)])
    # Row 2: hash, strip, upload
    d.box(40, 360, 220, 90, "Hash the original", ["sha256 · sha1 · md5 · size"], "trust")
    d.box(300, 360, 230, 90, "Strip watermarks", ["offscreen worker,", "openmanuals-strip (wasm);", "no change or error → original"], "service")
    d.diamond(660, 405, 200, 110, ["Same file", "already", "archived?"])
    d.box(810, 360, 200, 90, "Upload", ["S3 PUT with your keys:", "new item openmanuals-…", "with title, source, hashes"], "service")
    d.arrow([(260, 405), (300, 405)])
    d.arrow([(530, 405), (560, 405)])
    d.arrow([(760, 405), (810, 405)], label="no", at=(785, 397))
    d.box(1060, 360, 180, 90, "archive.org", ["the item, under", "your account"], "external")
    d.arrow([(1010, 405), (1060, 405)], color="purple")
    # Row 3: facts
    d.box(560, 520, 440, 100, "Sign a bundle of facts", ["file (original) · file (stripped) · derivation", "location: the source page · location: the copy", "manual · product · covers · manual_file"], "trust")
    d.arrow([(660, 460), (660, 520)], label="yes: no upload (unless", at=(650, 482), label_anchor="end")
    d.label(650, 498, "you choose Add another copy);", anchor="end")
    d.label(650, 514, "the source page is still recorded", anchor="end")
    d.arrow([(910, 450), (910, 520)])
    d.box(300, 520, 200, 100, "Outbox", ["chrome.storage.local;", "retried until the", "server accepts it"], "data")
    d.arrow([(560, 570), (500, 570)])
    # Server
    d.group(280, 670, 960, 140, "OpenManuals server")
    d.box(300, 705, 220, 80, "POST /api/facts", ["signatures, budgets,", "blocked keys"], "service")
    d.box(580, 705, 220, 80, "Inbox → ledger", ["folded into git, then", "built into the snapshot"], "data")
    d.box(860, 705, 220, 80, "Verifier", ["fetches the copy, checks", "its hashes, scans the PDF"], "service")
    d.arrow([(470, 620), (470, 705)])
    d.arrow([(520, 745), (580, 745)])
    d.arrow([(800, 745), (860, 745)])
    d.arrow([(1080, 745), (1150, 745), (1150, 450)], color="blue", label="fetch & check", at=(1160, 600), label_anchor="start")
    d.legend(40, 680)
    d.text(40, 845, "The copy shows on the site once the verifier has checked it. If stripping changes nothing, the original is uploaded and no derivation is recorded.", 13, anchor="start", italic=True, color="#555")
    d.save()


def passkey():
    d = Diagram("passkey", 1280, 770, "How a passkey protects the signing key",
                "The passkey's PRF output is stretched with HKDF into an AES-256-GCM key that wraps the Ed25519 signing key. The wrapped copy is stored in the browser, on the server and in an optional backup file; on another computer the same passkey rebuilds the same wrapping key and unwraps it.")
    d.text(20, 38, "Passkey-protected signing key", 22, anchor="start")
    # Creating
    d.group(20, 60, 260, 420, "Passkey provider")
    d.group(300, 60, 640, 420, "Extension (options page)")
    d.group(960, 60, 300, 420, "Wrapped copy (safe to share)")
    d.box(40, 100, 220, 120, "Passkey", ["password manager, phone", "or security key", "user.id = fingerprint", "RP: chrome-extension://<id>"], "external")
    d.box(330, 100, 260, 90, "PRF output", ['input "openmanuals key wrap v1"', "→ 32 secret bytes, the same", "every time for this passkey"], "trust")
    d.box(650, 100, 260, 90, "Wrapping key", ["HKDF-SHA256 → AES-256-GCM", "never stored"], "trust")
    d.box(330, 250, 260, 90, "Ed25519 signing key", ["made once; extractable", "only during this step"], "trust")
    d.box(650, 250, 260, 90, "AES-GCM wrapKey", ["random IV; AAD binds the", "fingerprint and passkey id"], "trust")
    d.box(330, 380, 260, 80, "Kept in this browser", ["IndexedDB, non-extractable:", "signs facts, can't be read"], "data")
    d.box(980, 100, 260, 190, "Key wrap", ["format: om-key-wrap v1", "fingerprint", "publicJwk", "credential (passkey id)", "iv", "wrapped (ciphertext)"], "data", mono=True)
    d.box(980, 340, 260, 110, "Stored in", ["this browser (chrome.storage.local)", "the server: /api/key-wrap", "the backup file, if you made one"], "data")
    d.arrow([(260, 145), (330, 145)], label="PRF", at=(295, 137))
    d.arrow([(590, 145), (650, 145)], label="HKDF", at=(620, 137))
    d.arrow([(780, 190), (780, 250)], label="key", at=(790, 225), label_anchor="start")
    d.arrow([(590, 295), (650, 295)], label="PKCS#8", at=(620, 287))
    d.arrow([(460, 340), (460, 380)], label="re-import", at=(470, 365), label_anchor="start")
    d.arrow([(910, 270), (980, 270)])
    d.arrow([(1110, 290), (1110, 340)])
    # Signing in elsewhere
    d.group(20, 510, 1240, 240, "Sign in on another computer")
    y, h = 560, 96
    d.box(40, y, 220, h, "1. Pick your passkey", ["it names the key:", "userHandle = fingerprint"], "external")
    d.box(300, y, 220, h, "2. Fetch the wrap", ["GET /api/key-wrap/<fp>", "(or this browser's copy,", "or the backup file)"], "service")
    d.box(560, y, 220, h, "3. Same wrapping key", ["same passkey, same input", "→ same PRF output", "→ same AES key"], "trust")
    d.box(820, y, 200, h, "4. unwrapKey", ["non-extractable,", "checked against", "the public key"], "trust")
    d.box(1060, y, 180, h, "5. Signed in", ["same fingerprint,", "same identity"], "data")
    for x0, x1 in ((260, 300), (520, 560), (780, 820), (1020, 1060)):
        d.arrow([(x0, y + h / 2), (x1, y + h / 2)])
    d.text(40, 700, "The wrap is useless without the passkey: only the passkey can produce the PRF output that unlocks it, so anyone may hold a copy.", 13, anchor="start", italic=True, color="#555")
    d.text(40, 722, "Another passkey adds another wrap of the same key. A backup file (Advanced options) encrypts the key under a passphrase instead.", 13, anchor="start", italic=True, color="#555")
    d.save()


if __name__ == "__main__":
    for f in (overview, fact, build, publish, mirror, lookup, capture, passkey):
        f()
    print("wrote", ", ".join(sorted(p.name for p in OUT.glob("*.svg"))))
