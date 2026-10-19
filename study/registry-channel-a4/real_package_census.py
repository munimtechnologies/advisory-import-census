"""Real-package census for the advisory-import gap (registry-channel A4).

This is the published A1/A2/A3 collector with ONE new per-advisory probe: for every
advisory that NAMES an affected package in a registry ecosystem (the A3 "package"
product type), A4 also asks the package registry itself whether that named package
is a REAL, repo-matching release -- i.e. the package exists on the registry AND its
own source/homepage metadata points back to the same GitHub repository that
published the advisory. Everything that scores visibility (scanner_blind /
own_id_in_osv), the eligible set, the OSV canary, the period split, the permutation
seed and the page archive is COPIED VERBATIM from the A3 collector so A4 scores
every advisory exactly as A1/A2/A3 did.

Motivation (see PREREGISTRATION-registry-channel-a4.md): A3 found that *naming* a
package does not guarantee visibility -- e.g. coollabsio/coolify (no_registry) names
npm `coolify` yet is scanner-blind, while nocodb/nocodb names npm `nocodb` and is
visible. The hypothesised refinement is that what matters is not whether the advisory
*names* a package but whether that package is a *real registry release of the
project* that GitHub can review into its global database. A4 measures that directly
and non-circularly: the registry-resolution probe reads the package registry's own
metadata (npm/PyPI/Packagist/RubyGems/crates.io/Go proxy), a data source entirely
independent of the OSV visibility measure.

Public, read-only metadata only (GitHub advisory pages, the OSV API and public
package-registry APIs), unauthenticated, paced, for open-access research as GitHub's
Acceptable Use Policies (section 7) allow. Every fetched advisory page is archived
under /out/raw so any parse can be audited by re-parsing the archive, never by
re-sampling. Stdlib only.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime as dt
import html
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "advisory-import-census (MV2 of Munim, Inc.; open-access research)"
PERM_SEED = 20261017
N_PERM = 10000
MIN_AGE_DAYS = 14.0
PERIOD_CUTOFF = "2026-05-01"
OSV_CANARY = "GHSA-39mp-8hj3-5c49"
PACE = 2.5
PACE_REG = 1.0  # registry-API pacing

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

# --- A3 attribution (product-type) parse (copied verbatim) -------------------
ECO_RE = re.compile(r'/advisories\?query=ecosystem%3A([A-Za-z0-9.+_-]+)')
PACKAGE_HDR = ">Package</h2>"
SOFTWARE_HDR = ">Software</h2>"

# --- A4 ADDITION: named-package coordinate parse -----------------------------
# On a GitHub repository-advisory page the affected package renders as a bold span
# holding the package NAME, immediately followed by a muted span whose link is the
# ecosystem query, e.g. (verbatim from A1 raw/):
#   <span class="f4 color-fg-default text-bold">coolify</span>  <span ...>
#       (<a href="/advisories?query=ecosystem%3Anpm" ...>npm</a>)
# NAMED_PKG_RE captures (package-name, ecosystem) pairs in page order.
NAMED_PKG_RE = re.compile(
    r'<span class="f4 color-fg-default text-bold">\s*(?P<name>[^<]+?)\s*</span>'
    r'\s*<span[^>]*>\s*\(\s*'
    r'<a href="/advisories\?query=ecosystem%3A(?P<eco>[A-Za-z0-9.+_-]+)"',
    re.S)

# Extract github.com owner/repo pairs from any metadata URL string.
GH_URL_RE = re.compile(
    r'github\.com[/:]+(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)'
    r'(?:\.git)?(?=[/"\'\s)#?]|$)', re.I)


def advisory_product(html_text):
    """Return (product_type, sorted_ecosystems). Verbatim from A3."""
    ecos = sorted({m.group(1).lower() for m in ECO_RE.finditer(html_text or "")})
    if ecos:
        return "package", ecos
    if (PACKAGE_HDR in (html_text or "")) or (SOFTWARE_HDR in (html_text or "")):
        return "software", []
    return "other", []


def named_packages(html_text):
    """Return a de-duplicated list of (ecosystem_lower, package_name) named on the
    advisory page's affected-products box. Deterministic, read-only."""
    out, seen = [], set()
    for m in NAMED_PKG_RE.finditer(html_text or ""):
        name = html.unescape(m.group("name")).strip()
        eco = m.group("eco").lower()
        key = (eco, name)
        if name and key not in seen:
            seen.add(key)
            out.append((eco, name))
    return out


def github_repos_in(text):
    """Set of 'owner/repo' (lower-cased) mentioned as github.com URLs in text."""
    repos = set()
    for m in GH_URL_RE.finditer(text or ""):
        repo = m.group("repo")
        if repo.lower() in ("sponsors", "about", "security", "advisories"):
            continue
        repos.add((m.group("owner") + "/" + repo).lower())
    return repos


# ===========================================================================
# A4 ADDITION: registry-resolution probe.
# For each named (ecosystem, package) the probe reads the registry's OWN metadata
# and returns whether the package exists and which github repos its source/homepage
# point to. Entirely independent of the OSV visibility measure.
# ===========================================================================

def _get_json(url, pace=PACE_REG, tries=3):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "application/json"})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.load(resp)
            time.sleep(pace)
            return 200, data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                time.sleep(pace)
                return 404, None
            if i == tries - 1:
                return e.code, None
            time.sleep(2 ** i)
        except (urllib.error.URLError, TimeoutError, ValueError):
            if i == tries - 1:
                return None, None
            time.sleep(2 ** i)
    return None, None


def _get_text(url, pace=PACE_REG, tries=3):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read().decode("utf-8", "replace")
            time.sleep(pace)
            return resp.status, body
        except urllib.error.HTTPError as e:
            if e.code == 404:
                time.sleep(pace)
                return 404, ""
            if i == tries - 1:
                return e.code, ""
            time.sleep(2 ** i)
        except (urllib.error.URLError, TimeoutError):
            if i == tries - 1:
                return None, ""
            time.sleep(2 ** i)
    return None, ""


def resolve_package(ecosystem, name, getter_json=_get_json, getter_text=_get_text):
    """Return {'checked', 'exists', 'repos', 'detail'} for one named package.

    checked is False for ecosystems the probe does not support (never guessed).
    repos is a set of 'owner/repo' the registry metadata points to on github.com.
    Pure given the two getters, so tests inject offline stubs."""
    eco = (ecosystem or "").lower()
    res = {"checked": True, "exists": False, "repos": set(), "detail": ""}

    if eco == "npm":
        q = urllib.parse.quote(name, safe="@")
        st, data = getter_json("https://registry.npmjs.org/%s" % q)
        if st == 200 and isinstance(data, dict):
            res["exists"] = True
            blob = []
            rep = data.get("repository")
            if isinstance(rep, dict):
                blob.append(rep.get("url", ""))
            elif isinstance(rep, str):
                blob.append(rep)
            tags = (data.get("dist-tags") or {})
            latest = tags.get("latest")
            vers = (data.get("versions") or {})
            v = vers.get(latest) if latest else None
            if isinstance(v, dict):
                vr = v.get("repository")
                if isinstance(vr, dict):
                    blob.append(vr.get("url", ""))
                elif isinstance(vr, str):
                    blob.append(vr)
                blob.append(v.get("homepage", ""))
            blob.append(data.get("homepage", ""))
            res["repos"] = github_repos_in(" ".join(x for x in blob if x))
        return _finish(res, st)

    if eco in ("pypi", "pip"):
        st, data = getter_json("https://pypi.org/pypi/%s/json"
                               % urllib.parse.quote(name))
        if st == 200 and isinstance(data, dict):
            res["exists"] = True
            info = data.get("info") or {}
            blob = [info.get("home_page", ""), info.get("project_url", ""),
                    info.get("download_url", "")]
            for _k, u in (info.get("project_urls") or {}).items():
                blob.append(u or "")
            res["repos"] = github_repos_in(" ".join(x for x in blob if x))
        return _finish(res, st)

    if eco in ("composer", "packagist"):
        st, data = getter_json("https://repo.packagist.org/p2/%s.json"
                               % urllib.parse.quote(name, safe="/"))
        if st == 200 and isinstance(data, dict):
            pkgs = (data.get("packages") or {})
            versions = pkgs.get(name) or next(iter(pkgs.values()), [])
            if versions:
                res["exists"] = True
                blob = []
                for v in versions[:5]:
                    src = (v.get("source") or {})
                    blob.append(src.get("url", ""))
                    blob.append(v.get("homepage", ""))
                res["repos"] = github_repos_in(" ".join(x for x in blob if x))
        return _finish(res, st)

    if eco in ("rubygems", "gem"):
        st, data = getter_json("https://rubygems.org/api/v1/gems/%s.json"
                               % urllib.parse.quote(name))
        if st == 200 and isinstance(data, dict):
            res["exists"] = True
            blob = [data.get("source_code_uri", ""), data.get("homepage_uri", ""),
                    data.get("project_uri", "")]
            res["repos"] = github_repos_in(" ".join(x for x in blob if x))
        return _finish(res, st)

    if eco in ("rust", "crates.io", "cargo"):
        st, data = getter_json("https://crates.io/api/v1/crates/%s"
                               % urllib.parse.quote(name))
        if st == 200 and isinstance(data, dict):
            crate = data.get("crate") or {}
            res["exists"] = True
            blob = [crate.get("repository", ""), crate.get("homepage", "")]
            res["repos"] = github_repos_in(" ".join(x for x in blob if x))
        return _finish(res, st)

    if eco == "go":
        # The Go module path IS the identity. Existence = proxy has @latest; the
        # repo is read from the module path's github.com prefix (no guessing: only
        # github.com-hosted modules get a repo, which is exactly what we compare).
        esc = _go_escape(name)
        st, _body = getter_text("https://proxy.golang.org/%s/@latest" % esc)
        if st == 200:
            res["exists"] = True
            res["repos"] = github_repos_in(name)
        return _finish(res, st)

    # Maven, NuGet, Pub, Swift, Erlang, Actions, ... not probed: leave unchecked
    # rather than guess.
    res["checked"] = False
    res["detail"] = "ecosystem_not_probed:%s" % eco
    return res


def _go_escape(module):
    # proxy.golang.org requires upper-case letters escaped as !lower.
    return "".join("!" + c.lower() if c.isupper() else c for c in module)


def _finish(res, status):
    res["repos"] = set(res["repos"])
    if res["detail"] == "":
        res["detail"] = "status=%s exists=%s repos=%s" % (
            status, res["exists"], ",".join(sorted(res["repos"])) or "-")
    return res


def real_package_resolution(advisory_repo, pkgs, resolver):
    """Classify one advisory's named packages against the registry.

    Returns (label, detail_list). label is:
      'yes'       at least one named package EXISTS and its registry metadata
                  points back to advisory_repo (the real, repo-matching release);
      'no_match'  a named package exists on the registry but none point to the repo;
      'absent'    named packages were checked and none exist on the registry;
      'unchecked' only unsupported ecosystems were named (never guessed);
      ''          no package named (should not happen for product_type=package)."""
    if not pkgs:
        return "", []
    want = advisory_repo.lower()
    any_checked = any_exists = any_match = False
    detail = []
    for eco, name in pkgs:
        r = resolver(eco, name)
        detail.append("%s:%s->%s" % (eco, name, r.get("detail", "")))
        if not r.get("checked"):
            continue
        any_checked = True
        if r.get("exists"):
            any_exists = True
            if want in {x.lower() for x in r.get("repos", set())}:
                any_match = True
    if any_match:
        return "yes", detail
    if any_exists:
        return "no_match", detail
    if any_checked:
        return "absent", detail
    return "unchecked", detail


def real_package_label(product_type, resolution):
    """Collapse to the pre-registered binary stratum used by the analysis.
    'real' iff a package-type advisory names a real, repo-matching release; a
    software-type advisory (no named package) is 'not_real'; everything the probe
    could not decide ('other' product type, or an unchecked ecosystem) is 'other'
    and excluded from the real/not_real tests."""
    if product_type == "package":
        if resolution == "yes":
            return "real"
        if resolution in ("no_match", "absent"):
            return "not_real"
        return "other"  # unchecked ecosystem
    if product_type == "software":
        return "not_real"
    return "other"


# ===========================================================================
# MEASURE + STATISTICS -- copied verbatim from the A3 collector.
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
# HTML DATA ACCESS -- identical to the A3 collector.
# ===========================================================================

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


def collect_repo(repo, group, now, osv_lookup, resolver, raw_dir=None, max_pages=50):
    rows = []
    diag = {"repo": repo, "group": group, "listing_pages": 0,
            "advisories_listed": 0, "eligible": 0, "detail_pages": 0,
            "detail_failures": 0, "unreadable": False, "notes": []}
    listed = []
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
        product_type, ecosystems = advisory_product(body)
        pkgs = named_packages(body)                       # A4 ADDITION
        resolution, _detail = real_package_resolution(    # A4 ADDITION
            repo, pkgs, resolver) if product_type == "package" else ("", [])
        rp_label = real_package_label(product_type, resolution)  # A4 ADDITION
        adv = {
            "ghsa_id": gid,
            "cve_id": cve,
            "identifiers": [{"type": "CVE", "value": cve}] if cve else [],
            "vulnerabilities": [],
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
            "scanner_class": "scanner_blind" if blind else "scanner_visible",
            "advisory_product_type": product_type,
            "advisory_ecosystems": ";".join(ecosystems),
            "named_packages": ";".join("%s:%s" % (e, n) for e, n in pkgs),  # A4
            "named_pkg_resolution": resolution,                              # A4
            "real_package": rp_label,                                        # A4
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
                    help="testing only: skip network; every advisory visible, no probe")
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
        resolver = lambda eco, name: {"checked": False, "exists": False,
                                      "repos": set(), "detail": "offline"}
        canary_ok = True
    else:
        cache = {}

        def osv_lookup(vid):
            if not vid:
                return None
            if vid not in cache:
                cache[vid] = osv_get(vid)
            return cache[vid]

        rcache = {}

        def resolver(eco, name):
            key = (eco, name)
            if key not in rcache:
                rcache[key] = resolve_package(eco, name)
            return rcache[key]

        canary_ok = osv_lookup(OSV_CANARY) is not None
        if not canary_ok:
            print("[census] OSV CANARY FAILED -- run is void", flush=True)

    rows, diags = [], []
    for i, (repo, group) in enumerate(targets, 1):
        print("[census] %d/%d %s (%s)" % (i, len(targets), repo, group), flush=True)
        try:
            rr, diag = collect_repo(repo, group, now, osv_lookup, resolver,
                                    raw_dir=raw_dir)
            rows.extend(rr)
        except Exception as e:
            diag = {"repo": repo, "group": group, "unreadable": True,
                    "notes": ["exception: %s" % e]}
            print("[census] skip %s: %s" % (repo, e), flush=True)
        diags.append(diag)

    cols = ["group", "repo", "ghsa_id", "cve_id", "severity", "published_at",
            "age_days", "period", "own_id_in_osv", "osv_packages",
            "scanner_class", "advisory_product_type", "advisory_ecosystems",
            "named_packages", "named_pkg_resolution", "real_package", "url"]
    with open(os.path.join(args.out_dir, "real_package_census.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    ptally = {}
    rtally = {}
    for r in rows:
        ptally[r["advisory_product_type"]] = ptally.get(r["advisory_product_type"], 0) + 1
        rtally[r["real_package"]] = rtally.get(r["real_package"], 0) + 1
    census = {
        "snapshot_utc": snapshot,
        "osv_canary": {"id": OSV_CANARY, "resolved": canary_ok},
        "eligible_advisories": len(rows),
        "product_type_counts": ptally,
        "real_package_counts": rtally,
        "blind": share(rows, lambda r: r["scanner_class"] == "scanner_blind"),
        "unreadable_repos": sorted(d["repo"] for d in diags if d.get("unreadable")),
        "collection": diags,
        "data_access": {
            "advisory_pages": "github.com public advisory pages (HTML), unauthenticated",
            "registry_apis": ["registry.npmjs.org", "pypi.org", "repo.packagist.org",
                              "rubygems.org", "crates.io", "proxy.golang.org"],
            "pace_seconds": PACE, "registry_pace_seconds": PACE_REG,
        },
    }
    with open(os.path.join(args.out_dir, "real_package_census_meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(census, f, indent=2)

    print("eligible %d | product %s | real_package %s | blind %.1f%%"
          % (len(rows), ptally, rtally, (census["blind"]["pct"] or 0)), flush=True)
    if census["unreadable_repos"]:
        print("UNREADABLE (not counted as zero):",
              ", ".join(census["unreadable_repos"]), flush=True)
    print("canary resolved:", canary_ok, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
