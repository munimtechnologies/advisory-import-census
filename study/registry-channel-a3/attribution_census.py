"""Attribution census for the advisory-import gap (registry-channel A3).

This is app_library_census_html.py (the published A1/A2 collector) with ONE
addition: for every eligible advisory it also records, from the archived detail
HTML, the advisory's PRODUCT TYPE -- whether github.com renders the advisory with
a package coordinate in a registry ecosystem ("package"), only a generic product
box ("software"), or neither ("other"). Everything that scores visibility
(scanner_blind / own_id_in_osv), the eligible set, the OSV canary, the period
split, the permutation seed and the page archive is COPIED VERBATIM so A3 scores
every advisory exactly as A1 did.

See PREREGISTRATION-registry-channel-a3.md. The product type is the pre-registered
attribution variable; it is read-only metadata from the public advisory page and
is used by attribution_analysis.py, never by the visibility measure.

Public, read-only metadata only (GitHub advisory pages + the OSV API),
unauthenticated, paced one request every PACE seconds, for open-access research as
GitHub's Acceptable Use Policies (section 7) allow. Every fetched page is archived
under /out/raw so any parse can be audited and corrected by re-parsing the archive,
never by re-sampling. Stdlib only.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime as dt
import json
import math
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request

UA = "advisory-import-census (MV2 of Munim, Inc.; open-access research)"
PERM_SEED = 20261017
N_PERM = 10000
MIN_AGE_DAYS = 14.0
PERIOD_CUTOFF = "2026-05-01"
OSV_CANARY = "GHSA-39mp-8hj3-5c49"
PACE = 2.5

OSV_VULN = "https://api.osv.dev/v1/vulns/%s"
LISTING_URL = ("https://github.com/%s/security/advisories"
               "?page=%d&state=published")
DETAIL_URL = "https://github.com/%s/security/advisories/%s"

# GHSA ids use a restricted base32 alphabet (no a,b,d,e,i,k,l,n,o,s,t,u,y,z).
GHSA = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
LINK_RE = (r'href="/(?P<owner>[^/"]+)/(?P<repo>[^/"]+)'
           r'/security/advisories/(?P<id>%s)"' % GHSA)
DATETIME_RE = re.compile(r'datetime="([0-9T:\-\.Z+]+)"')
SEV_TITLE_RE = re.compile(r'title="Severity:\s*(critical|high|moderate|low)"', re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# --- A3 ADDITION: attribution (product-type) parse ---------------------------
# A reviewed, package-scoped advisory links each affected package to its ecosystem
# with an href like /advisories?query=ecosystem%3Anpm . A repository-level advisory
# shows a "Software" box with a product name and no such link. Both the "Package"
# and "Software" headers mark the affected-products box.
ECO_RE = re.compile(r'/advisories\?query=ecosystem%3A([A-Za-z0-9.+_-]+)')
PACKAGE_HDR = ">Package</h2>"
SOFTWARE_HDR = ">Software</h2>"


def advisory_product(html):
    """Return (product_type, sorted_ecosystems) for one advisory detail page.

    product_type is 'package' if the page names >=1 affected package in a registry
    ecosystem, 'software' if it has an affected-products box but no ecosystem
    coordinate, else 'other'. Deterministic, read-only, no measure uses it."""
    ecos = sorted({m.group(1).lower() for m in ECO_RE.finditer(html or "")})
    if ecos:
        return "package", ecos
    if (PACKAGE_HDR in (html or "")) or (SOFTWARE_HDR in (html or "")):
        return "software", []
    return "other", []


# ===========================================================================
# MEASURE + STATISTICS -- copied verbatim from app_library_census_html.py so the
# A3 census scores every advisory exactly as the frozen A1 census would.
# ===========================================================================

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
    """Return (own_id_in_osv, osv_packages, scanner_blind) under the corrected measure."""
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


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(centre - half, 4), round(centre + half, 4)]


def share(rows, pred):
    n = len(rows)
    k = sum(1 for r in rows if pred(r))
    return {"k": k, "n": n, "pct": round(100 * k / n, 1) if n else None,
            "ci95": wilson(k, n)}


def iso_age_days(published_at, now):
    t = dt.datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    return (now - t).total_seconds() / 86400.0


# ===========================================================================
# HTML DATA ACCESS -- identical to app_library_census_html.py.
# ===========================================================================

def fetch(url, tries=4, pace=PACE):
    """Paced GET. Returns (status, body, final_url). status None on network error."""
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
                print("[census] %s on %s; sleeping %ds" % (e.code, url, wait),
                      flush=True)
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
                print("[census] network error on %s: %s" % (url, e), flush=True)
                return None, "", url
            time.sleep(2 ** i)
    return None, "", url


def listing_items(html, repo):
    """[(ghsa_id, publication datetime, severity lowercase)] in page order, deduped."""
    owner, name = repo.lower().split("/")
    links = [m for m in re.finditer(LINK_RE, html, re.I)
             if m.group("owner").lower() == owner and m.group("repo").lower() == name]
    items, seen = [], set()
    for i, m in enumerate(links):
        gid = m.group("id")
        if gid in seen:
            continue
        seen.add(gid)
        nxt = next((l.start() for l in links[i + 1:] if l.group("id") != gid),
                   len(html))
        seg = html[m.end():nxt]
        d = DATETIME_RE.search(seg)
        s = SEV_TITLE_RE.search(seg)
        items.append((gid, d.group(1) if d else "",
                      s.group(1).lower() if s else ""))
    return items


def listing_has_next(html, page):
    nxt = page + 1
    return ("page=%d&amp;state=published" % nxt) in html or \
           ("page=%d&state=published" % nxt) in html or \
           ('?state=published&amp;page=%d' % nxt) in html or \
           ('?state=published&page=%d' % nxt) in html


def ghsa_mentions(html):
    return set(re.findall(GHSA, html))


def detail_cve(html):
    """CVE id taken from near the 'CVE ID' label; '' if 'No known CVE'."""
    k = html.find("CVE ID")
    if k < 0:
        return "", ("No known CVE" in html)
    window = html[k:k + 1500]
    no_known = "No known CVE" in window
    m = CVE_RE.search(window)
    if m and "No known CVE" not in window[:m.start()]:
        return m.group(0), no_known
    return "", no_known


def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def collect_repo(repo, group, now, osv_lookup, raw_dir=None, max_pages=50):
    """(rows, diag) for one repo. diag.unreadable is True if a page could not be
    read or a page with GHSA ids parsed to zero items (never silently zero)."""
    rows = []
    diag = {"repo": repo, "group": group, "listing_pages": 0,
            "advisories_listed": 0, "eligible": 0, "detail_pages": 0,
            "detail_failures": 0, "unreadable": False, "notes": []}
    listed = []  # (ghsa, published_at, severity)
    page = 1
    while page <= max_pages:
        url = LISTING_URL % (repo, page)
        status, body, _ = fetch(url)
        if raw_dir is not None:
            _save(raw_dir, "listing_%s_p%d.html" % (safe_name(repo), page), body)
        diag["listing_pages"] += 1
        if status != 200:
            diag["unreadable"] = True
            diag["notes"].append("listing page %d status=%s" % (page, status))
            return [], diag
        items = listing_items(body, repo)
        if not items and ghsa_mentions(body):
            diag["unreadable"] = True
            diag["notes"].append("page %d has GHSA ids but parsed 0 items" % page)
            return [], diag
        listed.extend(items)
        if not listing_has_next(body, page):
            break
        page += 1
    diag["advisories_listed"] = len(listed)

    for gid, pub, sev in listed:
        if not pub:
            diag["notes"].append("%s has no publication time; skipped" % gid)
            continue
        if iso_age_days(pub, now) < MIN_AGE_DAYS:
            continue
        diag["eligible"] += 1
        status, body, _ = fetch(DETAIL_URL % (repo, gid))
        if raw_dir is not None:
            _save(raw_dir, "detail_%s_%s.html" % (safe_name(repo), gid), body)
        diag["detail_pages"] += 1
        if status != 200:
            diag["detail_failures"] += 1
            diag["unreadable"] = True
            diag["notes"].append("detail %s status=%s" % (gid, status))
            return [], diag
        cve, _no_known = detail_cve(body)
        product_type, ecosystems = advisory_product(body)  # A3 ADDITION
        adv = {
            "ghsa_id": gid,
            "cve_id": cve,
            "identifiers": [{"type": "CVE", "value": cve}] if cve else [],
            "vulnerabilities": [],  # package names are descriptive only (not a measure)
            "severity": sev,
            "published_at": pub,
            "state": "published",
            "html_url": DETAIL_URL % (repo, gid),
        }
        own_in_osv, osv_pkgs, blind = classify(adv, osv_lookup)
        cves = advisory_cves(adv)
        rows.append({
            "group": group, "repo": repo,
            "ghsa_id": gid,
            "cve_id": cves[0] if cves else "",
            "severity": sev,
            "published_at": pub,
            "age_days": round(iso_age_days(pub, now), 1),
            "period": "from_2026_05" if pub >= PERIOD_CUTOFF else "before_2026_05",
            "own_id_in_osv": str(own_in_osv),
            "osv_packages": ";".join(osv_pkgs),
            "repo_packages": "",
            "scanner_class": "scanner_blind" if blind else "scanner_visible",
            "advisory_product_type": product_type,   # A3 ADDITION
            "advisory_ecosystems": ";".join(ecosystems),  # A3 ADDITION
            "url": adv["html_url"],
        })
    return rows, diag


def _save(raw_dir, name, body):
    try:
        with open(os.path.join(raw_dir, name), "w", encoding="utf-8") as f:
            f.write(body)
    except OSError as e:
        print("[census] could not archive %s: %s" % (name, e), flush=True)


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
# MAIN
# ===========================================================================

def load_frame(path, group):
    with open(path, encoding="utf-8") as f:
        return [(e["repo"], group) for e in json.load(f)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--frame-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--offline", action="store_true",
                    help="testing only: skip network; treat every advisory as visible")
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)
    raw_dir = os.path.join(args.out_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    snapshot = now.replace(microsecond=0).isoformat()

    targets = (load_frame(os.path.join(args.frame_dir, "frame_apps.json"), "application")
               + load_frame(os.path.join(args.frame_dir, "frame_libs.json"), "library"))

    if args.offline:
        osv_lookup = lambda vid: {"affected": [{"package": {"name": "x"}}]}
        canary_ok = True
    else:
        cache = {}

        def osv_lookup(vid):
            if not vid:
                return None
            if vid not in cache:
                cache[vid] = osv_get(vid)
            return cache[vid]

        canary_ok = osv_lookup(OSV_CANARY) is not None
        if not canary_ok:
            print("[census] OSV CANARY FAILED -- run is void", flush=True)

    rows, diags = [], []
    for i, (repo, group) in enumerate(targets, 1):
        print("[census] %d/%d %s (%s)" % (i, len(targets), repo, group), flush=True)
        try:
            rr, diag = collect_repo(repo, group, now, osv_lookup, raw_dir=raw_dir)
            rows.extend(rr)
        except Exception as e:  # one bad repo must not sink the run
            diag = {"repo": repo, "group": group, "unreadable": True,
                    "notes": ["exception: %s" % e]}
            print("[census] skip %s: %s" % (repo, e), flush=True)
        diags.append(diag)

    cols = ["group", "repo", "ghsa_id", "cve_id", "severity", "published_at",
            "age_days", "period", "own_id_in_osv", "osv_packages", "repo_packages",
            "scanner_class", "advisory_product_type", "advisory_ecosystems", "url"]
    with open(os.path.join(args.out_dir, "attribution_census.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    # product-type tally for an at-a-glance audit of the parse
    ptally = {}
    for r in rows:
        ptally[r["advisory_product_type"]] = ptally.get(r["advisory_product_type"], 0) + 1
    census = {
        "snapshot_utc": snapshot,
        "osv_canary": {"id": OSV_CANARY, "resolved": canary_ok},
        "eligible_advisories": len(rows),
        "product_type_counts": ptally,
        "blind": share(rows, lambda r: r["scanner_class"] == "scanner_blind"),
        "unreadable_repos": sorted(d["repo"] for d in diags if d.get("unreadable")),
        "collection": diags,
        "data_access": {
            "route": "github.com public advisory pages (HTML), unauthenticated",
            "pace_seconds": PACE,
        },
    }
    with open(os.path.join(args.out_dir, "attribution_census_meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(census, f, indent=2)

    print("eligible %d | product types %s | blind %.1f%%"
          % (len(rows), ptally, (census["blind"]["pct"] or 0)), flush=True)
    if census["unreadable_repos"]:
        print("UNREADABLE (not counted as zero):",
              ", ".join(census["unreadable_repos"]), flush=True)
    print("canary resolved:", canary_ok, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
