"""Confirmatory application-vs-library advisory-import-gap census -- HTML route.

Pre-registered (PREREGISTRATION-app-vs-library.md) and amended by AMENDMENT-2.md.
This is the data-access variant of app_library_census.py: it enumerates each
repository's PUBLISHED security advisories from github.com's public advisory
pages instead of the REST endpoint /repos/{owner}/{repo}/security-advisories,
because the unauthenticated REST budget (60/hr, shared IP) is exhausted within
seconds of every reset and the REST job never got past repository 1 of 80.

Everything else is UNCHANGED and copied verbatim from app_library_census.py:
the eligible set (published, >= 14 days old), the period split, the OSV-based
primary (scanner_blind) and secondary (own_id_not_in_osv) measures, the OSV
canary, the repository-level permutation test (seed 20261017, 10,000
permutations), the robustness checks and the output columns. The 40-application
/ 40-library frozen frame is unchanged.

Per advisory the listing page gives the GHSA id, publication time and severity;
the advisory's own page gives its "CVE ID" field (or "No known CVE"), used only
for the OSV CVE-alias fallback that the pre-registered measure already allows.
Package names shown on the page are descriptive and are not used by any measure.

Public, read-only metadata only (GitHub advisory pages + the OSV API),
unauthenticated, paced one request every PACE seconds, for open-access research
as GitHub's Acceptable Use Policies (section 7) allow. Every fetched page is
archived under /out/raw so any parse can be audited and corrected by
re-parsing the archive, never by re-sampling. Stdlib only.
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


# ===========================================================================
# MEASURE + STATISTICS -- copied verbatim from app_library_census.py so the
# amended HTML route scores every advisory exactly as the frozen census would.
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


def advisory_repo_packages(adv):
    pkgs = []
    for v in adv.get("vulnerabilities") or []:
        p = v.get("package") or {}
        if p.get("name"):
            pkgs.append("%s:%s" % (p.get("ecosystem", ""), p["name"]))
    return sorted(set(pkgs))


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


def median(xs):
    xs = sorted(xs)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2


def repo_median_pct(rows, pred):
    tally = {}
    for r in rows:
        t = tally.setdefault(r["repo"], [0, 0])
        t[0] += 1 if pred(r) else 0
        t[1] += 1
    m = median([100 * k / n for k, n in tally.values() if n])
    return round(m, 1) if m is not None else None


def permutation_test(rows, pred, groups=("application", "library"),
                     n_perm=N_PERM, seed=PERM_SEED):
    tally = {}
    for r in rows:
        if r["group"] not in groups:
            continue
        t = tally.setdefault((r["group"], r["repo"]), [0, 0])
        t[0] += 1 if pred(r) else 0
        t[1] += 1
    units = sorted(tally.items())
    if not units:
        return None

    def diff(labels):
        ka = na = kb = nb = 0
        for lab, (_, (k, n)) in zip(labels, units):
            if lab == groups[0]:
                ka, na = ka + k, na + n
            else:
                kb, nb = kb + k, nb + n
        if not na or not nb:
            return None
        return ka / na - kb / nb

    labels = [g for (g, _), _ in units]
    observed = diff(labels)
    if observed is None:
        return None
    rng = random.Random(seed)
    extreme = valid = 0
    for _ in range(n_perm):
        rng.shuffle(labels)
        d = diff(labels)
        if d is None:
            continue
        valid += 1
        if abs(d) >= abs(observed) - 1e-12:
            extreme += 1
    return {"difference_pct_points": round(100 * observed, 1),
            "p_two_sided": round((extreme + 1) / (valid + 1), 4),
            "permutations": valid, "seed": seed, "unit": "repository",
            "repositories": len(units)}


def is_blind(r):
    return r["scanner_class"] == "scanner_blind"


def own_missing(r):
    return r.get("own_id_in_osv") != "True"


def group_block(rows, group):
    gr = [r for r in rows if r["group"] == group]
    return {
        "eligible": len(gr),
        "repos_in_frame": None,  # filled by caller
        "repos_with_eligible_advisories": len({r["repo"] for r in gr}),
        "blind": share(gr, is_blind),
        "own_id_not_in_osv": share(gr, own_missing),
        "repo_median_blind_pct": repo_median_pct(gr, is_blind),
    }


def heaviest_repo(rows, group):
    counts = {}
    for r in rows:
        if r["group"] == group:
            counts[r["repo"]] = counts.get(r["repo"], 0) + 1
    return max(counts, key=counts.get) if counts else None


def summarise(rows, frame_counts, canary_ok, snapshot):
    out = {
        "measure": {
            "primary": "scanner_blind (corrected): no OSV record, by GHSA or CVE "
                       "alias, names any package",
            "secondary": "own_id_not_in_osv: the advisory's own GHSA id does not "
                         "resolve in OSV",
        },
        "snapshot_utc": snapshot,
        "osv_canary": {"id": OSV_CANARY, "resolved": canary_ok},
        "groups": {}, "comparison": {}, "robustness": {},
    }
    for g in ("application", "library"):
        blk = group_block(rows, g)
        blk["repos_in_frame"] = frame_counts.get(g)
        out["groups"][g] = blk
    out["comparison"]["blind"] = permutation_test(rows, is_blind)
    out["comparison"]["own_id_not_in_osv"] = permutation_test(rows, own_missing)

    # Pre-specified robustness (a): drop the most advisory-heavy repo in each group.
    drop = {heaviest_repo(rows, "application"), heaviest_repo(rows, "library")}
    drop.discard(None)
    trimmed = [r for r in rows if r["repo"] not in drop]
    out["robustness"]["drop_heaviest_repo_each_group"] = {
        "dropped": sorted(drop), "blind": permutation_test(trimmed, is_blind)}

    # Pre-specified robustness (b): by publication period.
    for period in ("before_2026_05", "from_2026_05"):
        sub = [r for r in rows if r["period"] == period]
        out["robustness"]["period_%s" % period] = {
            "eligible": len(sub), "blind": permutation_test(sub, is_blind)}
    return out


def iso_age_days(published_at, now):
    t = dt.datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    return (now - t).total_seconds() / 86400.0


# ===========================================================================
# HTML DATA ACCESS -- the only part that differs from app_library_census.py.
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
    """[(ghsa_id, publication datetime, severity lowercase)] in page order, deduped.

    severity comes from the unambiguous title="Severity: X" attribute on the
    advisory's badge (the visible label and CVSS-metric words are not used)."""
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
    """CVE id taken from near the 'CVE ID' label; '' if 'No known CVE'.

    Only the label window is read, so CVE-like strings elsewhere on the page
    (references, descriptions) cannot be mistaken for the advisory's own CVE."""
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
    frame_counts = {"application": sum(1 for _, g in targets if g == "application"),
                    "library": sum(1 for _, g in targets if g == "library")}

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
            "scanner_class", "url"]
    with open(os.path.join(args.out_dir, "app_library_census.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    summary = summarise(rows, frame_counts, canary_ok, snapshot)
    summary["data_access"] = {
        "route": "github.com public advisory pages (HTML), unauthenticated",
        "amendment": "AMENDMENT-2.md",
        "pace_seconds": PACE,
        "unreadable_repos": sorted(d["repo"] for d in diags if d.get("unreadable")),
    }
    summary["collection"] = diags
    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    for g in ("application", "library"):
        s = summary["groups"][g]
        print("%-12s eligible %4d in %d repos | blind %5.1f%% %s" % (
            g, s["eligible"], s["repos_with_eligible_advisories"],
            (s["blind"]["pct"] or 0), s["blind"]["ci95"]), flush=True)
    c = summary["comparison"]["blind"]
    if c:
        print("application - library = %+.1f points, p = %s (%d repos)" % (
            c["difference_pct_points"], c["p_two_sided"], c["repositories"]), flush=True)
    unread = summary["data_access"]["unreadable_repos"]
    if unread:
        print("UNREADABLE (not counted as zero):", ", ".join(unread), flush=True)
    print("canary resolved:", canary_ok, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
