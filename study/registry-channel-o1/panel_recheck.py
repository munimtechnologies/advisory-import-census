"""registry-channel O1 collector: re-check the SAME A4 advisories at a second snapshot.

See PREREGISTRATION-registry-channel-o1.md (frozen 2026-10-22 UTC, before any second
snapshot existed). O1 follows the exact 1,429 advisories L1 analysed and records, for
each one, its A4 state -> its T2 state, using A4's `classify` verbatim. It runs ONCE,
network-enabled, not before 2026-11-16 00:00 UTC.

What it does, strictly to the frozen plan:
  1. Download A4's `real_package_census.csv` and `registry_classification.json` by raw
     URL from `main` and verify their git blob shas; halt on any mismatch.
  2. Build the frame: the A4 rows whose repo has a registry/no_registry label, age>=14 d
     at A4 (L1's rule, reproduced verbatim). Recover each row's A4 snapshot as
     published_at + age_days and read its A4 state from `scanner_class`.
  3. Re-query OSV (`https://api.osv.dev/v1/vulns/<id>`) with A4's `classify`: the GHSA
     id first, then the A4-stored cve_id if the GHSA record names no package. 0.2 s
     pace. The A4 canary GHSA-39mp-8hj3-5c49 must resolve or the run is void. Every OSV
     response is archived under /out/raw_osv.
  4. R1: re-scrape each advisory page and read any CVE id with A4's `detail_cve`.
     R4: record the page HTTP status (a 404 means the advisory is gone at T2).
     R2: record OSV `withdrawn` so the analysis can exclude withdrawn records.
  5. P5: list each frame repo's advisories at T2 and keep those NOT in the A4 CSV,
     published after that repo's A4 snapshot and at least 14 days old at T2; classify
     them. Written to panel_new_advisories.csv (descriptive, no threshold).

Only read-only, unauthenticated, paced public metadata (GitHub advisory pages and the
OSV API), as A4 used. Stdlib only. Apache-2.0 (code) / CC BY 4.0 (text & data). Made
with AI agents working for MV2 of Munim, Inc. No result here has been reviewed by a human.
"""
import argparse
import csv
import datetime as dt
import hashlib
import html
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

# --- frozen frame inputs -----------------------------------------------------
RAW_BASE = ("https://raw.githubusercontent.com/munimtechnologies/"
            "advisory-import-census/main/study/registry-channel-a4/")
A4_CSV_URL = RAW_BASE + "real_package_census.csv"
A4_CLS_URL = RAW_BASE + "registry_classification.json"
A4_CSV_BLOB = "4617c2df697f36eeb4c4d4fe8483bbae7119bcfd"
A4_CLS_BLOB = "260a9c04dedaa108437c84082346ff72ed7ad635"
# classify/record_packages/advisory_cves/detail_cve are copied verbatim from this blob:
A4_CODE_BLOB = "def387a9a6cc4b93cfe1fd61df3d509e299bb4c1"

AGE_FLOOR = 14          # L1's AGE_FLOOR, verbatim
MIN_AGE_DAYS_T2 = 14.0  # P5: at least 14 days old at T2

# ===========================================================================
# CONSTANTS + FUNCTIONS COPIED VERBATIM FROM A4 (real_package_census.py, blob
# def387a9a6cc4b93cfe1fd61df3d509e299bb4c1) so O1 scores every advisory exactly
# as A1/A2/A3/A4/L1 did. Do not edit these.
# ===========================================================================
UA = "advisory-import-census (MV2 of Munim, Inc.; open-access research)"
PACE = 2.5
OSV_CANARY = "GHSA-39mp-8hj3-5c49"

OSV_VULN = "https://api.osv.dev/v1/vulns/%s"
LISTING_URL = ("https://github.com/%s/security/advisories"
               "?page=%d&state=published")
DETAIL_URL = "https://github.com/%s/security/advisories/%s"

GHSA = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
LINK_RE = (r'href="/(?P<owner>[^/"]+)/(?P<repo>[^/"]+)'
           r'/security/advisories/(?P<id>%s)"' % GHSA)
DATETIME_RE = re.compile(r'datetime="([0-9T:\-\.Z+]+)"')
SEV_TITLE_RE = re.compile(r'title="Severity:\s*(critical|high|moderate|low)"', re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

ECO_RE = re.compile(r'/advisories\?query=ecosystem%3A([A-Za-z0-9.+_-]+)')
PACKAGE_HDR = ">Package</h2>"
SOFTWARE_HDR = ">Software</h2>"


def advisory_product(html_text):
    """Return (product_type, sorted_ecosystems). Verbatim from A3/A4."""
    ecos = sorted({m.group(1).lower() for m in ECO_RE.finditer(html_text or "")})
    if ecos:
        return "package", ecos
    if (PACKAGE_HDR in (html_text or "")) or (SOFTWARE_HDR in (html_text or "")):
        return "software", []
    return "other", []


def record_packages(record):
    pkgs = []
    for a in (record or {}).get("affected") or []:
        p = a.get("package") or {}
        if p.get("name"):
            pkgs.append("%s:%s" % (p.get("ecosystem", ""), p["name"]))
    return sorted(set(pkgs))


def advisory_cves(adv):
    cves = []
    for ident in adv.get("identifiers") or []:
        if (ident.get("type") or "").upper() == "CVE" and ident.get("value"):
            cves.append(ident["value"])
    if adv.get("cve_id"):
        cves.append(adv["cve_id"])
    return sorted(set(cves))


def classify(adv, osv_lookup):
    ghsa = adv.get("ghsa_id")
    own_rec = osv_lookup(ghsa) if ghsa else None
    own_in_osv = own_rec is not None
    osv_pkgs = set(record_packages(own_rec))
    if not osv_pkgs:
        for cve in advisory_cves(adv):
            osv_pkgs |= set(record_packages(osv_lookup(cve)))
            if osv_pkgs:
                break
    return own_in_osv, sorted(osv_pkgs), (len(osv_pkgs) == 0)


def detail_cve(html_text):
    k = html_text.find("CVE ID")
    if k < 0:
        return "", ("No known CVE" in html_text)
    window = html_text[k:k + 1500]
    no_known = "No known CVE" in window
    m = CVE_RE.search(window)
    if m and "No known CVE" not in window[:m.start()]:
        return m.group(0), no_known
    return "", no_known


def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def listing_items(html_text, repo):
    owner, name = repo.lower().split("/")
    links = [m for m in re.finditer(LINK_RE, html_text, re.I)
             if m.group("owner").lower() == owner and m.group("repo").lower() == name]
    items, seen = [], set()
    for i, m in enumerate(links):
        gid = m.group("id")
        if gid in seen:
            continue
        seen.add(gid)
        nxt = next((l.start() for l in links[i + 1:] if l.group("id") != gid),
                   len(html_text))
        seg = html_text[m.end():nxt]
        d = DATETIME_RE.search(seg)
        s = SEV_TITLE_RE.search(seg)
        items.append((gid, d.group(1) if d else "",
                      s.group(1).lower() if s else ""))
    return items


def listing_has_next(html_text, page):
    nxt = page + 1
    return ("page=%d&amp;state=published" % nxt) in html_text or \
           ("page=%d&state=published" % nxt) in html_text or \
           ('?state=published&amp;page=%d' % nxt) in html_text or \
           ('?state=published&page=%d' % nxt) in html_text


def ghsa_mentions(html_text):
    return set(re.findall(GHSA, html_text))


def fetch(url, tries=4, pace=PACE):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                body = resp.read().decode("utf-8", "replace")
                status, final = resp.status, resp.geturl()
            time.sleep(pace)
            return status, body, final
        except urllib.error.HTTPError as e:
            body = (e.read() or b"").decode("utf-8", "replace")
            if e.code in (429, 403):
                ra = (e.headers or {}).get("Retry-After")
                wait = 60
                if ra and ra.isdigit():
                    wait = min(900, max(30, int(ra)))
                print("[o1] %s on %s; sleeping %ds" % (e.code, url, wait), flush=True)
                time.sleep(wait)
                continue
            if e.code == 404:
                time.sleep(pace)
                return 404, body, url
            if i == tries - 1:
                return e.code, body, url
            time.sleep(2 ** i)
        except (urllib.error.URLError, TimeoutError) as e:
            if i == tries - 1:
                print("[o1] network error on %s: %s" % (url, e), flush=True)
                return None, "", url
            time.sleep(2 ** i)
    return None, "", url


def osv_get(vid, pace=0.2, tries=4):
    url = OSV_VULN % vid
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.load(resp)
            time.sleep(pace)
            return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if i == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if i == tries - 1:
                raise
        time.sleep(2 ** i)
    return None


# ===========================================================================
# O1-SPECIFIC HELPERS (pure; offline-testable)
# ===========================================================================

def git_blob_sha(data):
    """Git's object id for a blob: sha1(b'blob <len>\\x00' + bytes). Verifies that a
    downloaded file is byte-identical to the frozen committed version."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = hashlib.sha1()
    h.update(b"blob " + str(len(data)).encode() + b"\x00")
    h.update(data)
    return h.hexdigest()


def load_classification_obj(data):
    """repo(lowercased) -> 'registry'|'no_registry'. L1's load_classification logic
    (verbatim), accepting an already-parsed object."""
    cls = data.get("classification", data) if isinstance(data, dict) else data
    out = {}
    for repo, meta in cls.items():
        g = meta.get("group") if isinstance(meta, dict) else meta
        if g in ("registry", "no_registry"):
            out[repo.lower()] = g
    return out


def age_bin(age_days):
    """L1's age_bin, verbatim: young 14<=age<90, mid 90<=age<365, old >=365; else None."""
    if age_days is None or age_days < AGE_FLOOR:
        return None
    if age_days < 90:
        return "young"
    if age_days < 365:
        return "mid"
    return "old"


def a4_state_of(scanner_class):
    return "visible" if scanner_class == "scanner_visible" else "blind"


def recover_a4_snapshot(published_at, age_days):
    """A4 snapshot recovered per row as published_at + age_days (prereg frame rule)."""
    t = dt.datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    return t + dt.timedelta(days=age_days)


def build_frame(census_text, classification):
    """The 1,429 A4 advisories L1 analysed: rows whose repo has a label and age>=14 d
    at A4. Reproduces L1 load_rows, keeping the A4 fields O1 needs."""
    rows = []
    off_frame = age_missing = age_below_floor = 0
    for raw in csv.DictReader(io.StringIO(census_text)):
        repo = (raw.get("repo") or "").strip()
        group = classification.get(repo.lower())
        if group is None:
            off_frame += 1
            continue
        try:
            age = float(raw.get("age_days"))
        except (TypeError, ValueError):
            age_missing += 1
            continue
        b = age_bin(age)
        if b is None:
            age_below_floor += 1
            continue
        pub = (raw.get("published_at") or "").strip()
        rows.append({
            "ghsa_id": (raw.get("ghsa_id") or "").strip(),
            "repo": repo,
            "group": group,
            "cve_id_a4": (raw.get("cve_id") or "").strip(),
            "product_type": (raw.get("advisory_product_type") or "").strip(),
            "package_typed": (raw.get("advisory_product_type") or "").strip() == "package",
            "bin": b,
            "age_days_a4": age,
            "published_at": pub,
            "a4_state": a4_state_of(raw.get("scanner_class")),
            "a4_snapshot": recover_a4_snapshot(pub, age).isoformat() if pub else "",
        })
    counts = {"off_frame": off_frame, "age_missing": age_missing,
              "age_below_floor": age_below_floor, "kept": len(rows)}
    return rows, counts


def build_adv(ghsa_id, cve_id_a4):
    """adv dict for A4's classify: GHSA id, then the A4-stored CVE as a fallback."""
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id_a4,
        "identifiers": [{"type": "CVE", "value": cve_id_a4}] if cve_id_a4 else [],
    }


def transition_of(a4_state, t2_state):
    return "%s->%s" % (a4_state, t2_state)


def withdrawn_at(ghsa_id, cve_id_a4, osv_lookup):
    """OSV 'withdrawn' timestamp (R2), from the GHSA record, else the CVE record."""
    rec = osv_lookup(ghsa_id) if ghsa_id else None
    if isinstance(rec, dict) and rec.get("withdrawn"):
        return rec["withdrawn"]
    if cve_id_a4:
        rec = osv_lookup(cve_id_a4)
        if isinstance(rec, dict) and rec.get("withdrawn"):
            return rec["withdrawn"]
    return ""


def is_new_post_a4(ghsa_id, published_at, a4_ghsas, repo_a4_snapshot, now):
    """P5 membership: a listed advisory not in the A4 CSV, published after the repo's
    A4 snapshot and at least 14 days old at T2."""
    if ghsa_id in a4_ghsas or not published_at:
        return False
    try:
        pub = dt.datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if repo_a4_snapshot is not None and pub <= repo_a4_snapshot:
        return False
    return (now - pub).total_seconds() / 86400.0 >= MIN_AGE_DAYS_T2


# ===========================================================================
# NETWORK ORCHESTRATION
# ===========================================================================

TRANS_COLS = ["ghsa_id", "repo", "group", "cve_id_a4", "product_type",
              "package_typed", "bin", "age_days_a4", "a4_state", "t2_state",
              "transition", "own_in_osv_t2", "osv_packages_t2", "withdrawn_t2",
              "r1_cve_t2", "r1_new_cve", "page_status", "a4_snapshot", "t2_snapshot"]

NEW_COLS = ["ghsa_id", "repo", "group", "cve_id_t2", "product_type",
            "package_typed", "published_at", "t2_state", "osv_packages_t2",
            "own_in_osv_t2", "age_days_t2", "t2_snapshot"]


def _save(path, text):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        print("[o1] could not archive %s: %s" % (path, e), flush=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--csv-url", default=A4_CSV_URL)
    ap.add_argument("--cls-url", default=A4_CLS_URL)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)
    raw_osv = os.path.join(args.out_dir, "raw_osv")
    raw_pages = os.path.join(args.out_dir, "raw_pages")
    os.makedirs(raw_osv, exist_ok=True)
    os.makedirs(raw_pages, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    t2_snapshot = now.replace(microsecond=0).isoformat()

    # 1. Download and verify the frozen frame inputs.
    csv_status, csv_text, _ = fetch(args.csv_url)
    cls_status, cls_text, _ = fetch(args.cls_url)
    if csv_status != 200 or cls_status != 200:
        print("[o1] could not download frame inputs (%s, %s) -- HALT"
              % (csv_status, cls_status), flush=True)
        return 2
    csv_sha = git_blob_sha(csv_text)
    cls_sha = git_blob_sha(cls_text)
    if csv_sha != A4_CSV_BLOB or cls_sha != A4_CLS_BLOB:
        print("[o1] BLOB SHA MISMATCH -- HALT\n  csv  got %s want %s\n  cls  got %s want %s"
              % (csv_sha, A4_CSV_BLOB, cls_sha, A4_CLS_BLOB), flush=True)
        return 3

    classification = load_classification_obj(json.loads(cls_text))
    frame, counts = build_frame(csv_text, classification)
    a4_ghsas = {r["ghsa_id"] for r in frame if r["ghsa_id"]}
    print("[o1] frame: %d advisories (%s)" % (len(frame), counts), flush=True)

    # OSV cache + archive.
    cache = {}

    def osv_lookup(vid):
        if not vid:
            return None
        if vid not in cache:
            cache[vid] = osv_get(vid)
            _save(os.path.join(raw_osv, safe_name(vid) + ".json"),
                  json.dumps(cache[vid]) if cache[vid] is not None else "null")
        return cache[vid]

    # Canary (prereg: must resolve or the run is void).
    canary_ok = osv_lookup(OSV_CANARY) is not None
    if not canary_ok:
        print("[o1] OSV CANARY FAILED -- run is void", flush=True)
        return 4

    # 2. Re-check every frame advisory at T2.
    trans_rows = []
    for i, r in enumerate(frame, 1):
        if i % 100 == 0:
            print("[o1] %d/%d" % (i, len(frame)), flush=True)
        adv = build_adv(r["ghsa_id"], r["cve_id_a4"])
        own_in_osv, osv_pkgs, blind = classify(adv, osv_lookup)
        t2_state = "blind" if blind else "visible"
        # R1 + R4: re-scrape the advisory page.
        pstatus, body, _ = fetch(DETAIL_URL % (r["repo"], r["ghsa_id"]))
        _save(os.path.join(raw_pages,
                           "detail_%s_%s.html" % (safe_name(r["repo"]), r["ghsa_id"])),
              body or "")
        r1_cve = ""
        if pstatus == 200 and body:
            r1_cve, _ = detail_cve(body)
        trans_rows.append({
            "ghsa_id": r["ghsa_id"], "repo": r["repo"], "group": r["group"],
            "cve_id_a4": r["cve_id_a4"], "product_type": r["product_type"],
            "package_typed": str(r["package_typed"]), "bin": r["bin"],
            "age_days_a4": r["age_days_a4"], "a4_state": r["a4_state"],
            "t2_state": t2_state,
            "transition": transition_of(r["a4_state"], t2_state),
            "own_in_osv_t2": str(own_in_osv),
            "osv_packages_t2": ";".join(osv_pkgs),
            "withdrawn_t2": withdrawn_at(r["ghsa_id"], r["cve_id_a4"], osv_lookup),
            "r1_cve_t2": r1_cve,
            "r1_new_cve": str(bool(r1_cve) and r1_cve != r["cve_id_a4"]),
            "page_status": pstatus, "a4_snapshot": r["a4_snapshot"],
            "t2_snapshot": t2_snapshot,
        })

    with open(os.path.join(args.out_dir, "panel_transitions.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TRANS_COLS)
        w.writeheader()
        w.writerows(trans_rows)

    # 3. P5: new advisories in the same repos, published after A4's snapshot.
    repo_group = {r["repo"]: r["group"] for r in frame}
    repo_a4_snapshot = {}
    for r in frame:
        if r["a4_snapshot"]:
            t = dt.datetime.fromisoformat(r["a4_snapshot"])
            if (r["repo"] not in repo_a4_snapshot
                    or t > repo_a4_snapshot[r["repo"]]):
                repo_a4_snapshot[r["repo"]] = t
    new_rows = []
    repos = sorted(repo_group)
    for ri, repo in enumerate(repos, 1):
        print("[o1] P5 listing %d/%d %s" % (ri, len(repos), repo), flush=True)
        listed, page = [], 1
        while page <= 50:
            st, body, _ = fetch(LISTING_URL % (repo, page))
            _save(os.path.join(raw_pages,
                               "listing_%s_p%d.html" % (safe_name(repo), page)),
                  body or "")
            if st != 200:
                print("[o1] P5 listing %s p%d status=%s -- skip repo" % (repo, page, st),
                      flush=True)
                listed = None
                break
            listed.extend(listing_items(body, repo))
            if not listing_has_next(body, page):
                break
            page += 1
        if listed is None:
            continue
        for gid, pub, sev in listed:
            if not is_new_post_a4(gid, pub, a4_ghsas,
                                  repo_a4_snapshot.get(repo), now):
                continue
            pstatus, body, _ = fetch(DETAIL_URL % (repo, gid))
            _save(os.path.join(raw_pages,
                               "detail_%s_%s.html" % (safe_name(repo), gid)), body or "")
            if pstatus != 200 or not body:
                continue
            product_type, _ = advisory_product(body)
            cve, _ = detail_cve(body)
            adv = build_adv(gid, cve)
            own_in_osv, osv_pkgs, blind = classify(adv, osv_lookup)
            age_t2 = (now - dt.datetime.fromisoformat(
                pub.replace("Z", "+00:00"))).total_seconds() / 86400.0
            new_rows.append({
                "ghsa_id": gid, "repo": repo, "group": repo_group[repo],
                "cve_id_t2": cve, "product_type": product_type,
                "package_typed": str(product_type == "package"),
                "published_at": pub,
                "t2_state": "blind" if blind else "visible",
                "osv_packages_t2": ";".join(osv_pkgs),
                "own_in_osv_t2": str(own_in_osv),
                "age_days_t2": round(age_t2, 1), "t2_snapshot": t2_snapshot,
            })

    with open(os.path.join(args.out_dir, "panel_new_advisories.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=NEW_COLS)
        w.writeheader()
        w.writerows(new_rows)

    meta = {
        "study": "registry-channel O1 panel re-check",
        "t2_snapshot_utc": t2_snapshot,
        "osv_canary": {"id": OSV_CANARY, "resolved": canary_ok},
        "blob_shas_verified": {
            "real_package_census.csv": csv_sha,
            "registry_classification.json": cls_sha,
            "a4_classify_source": A4_CODE_BLOB,
        },
        "frame_counts": counts,
        "frame_advisories": len(frame),
        "new_post_a4_advisories": len(new_rows),
        "osv_records_fetched": len(cache),
    }
    with open(os.path.join(args.out_dir, "panel_recheck_meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print("[o1] done: %d transitions, %d new advisories, canary=%s"
          % (len(trans_rows), len(new_rows), canary_ok), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
