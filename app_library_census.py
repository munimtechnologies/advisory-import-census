"""Confirmatory application-vs-library advisory-import-gap census.

Pre-registered (PREREGISTRATION-app-vs-library.md). Reads the FROZEN sampling
frame (frame_apps.json + frame_libs.json, produced by build_frame.py and
committed before this runs), pulls each repository's GitHub security advisories,
and classifies each eligible advisory as scanner-visible or scanner-blind using
the CORRECTED (primary) measure validated in the AI-vs-control study:

  An advisory is VISIBLE iff an OSV record -- found by the advisory's own GHSA id
  or by any of its CVE aliases -- names at least one package. Otherwise BLIND.
  (A scanner reading OSV can only match an advisory to your dependency tree if
  some OSV record for it names a package.)

Secondary measure: own GHSA id absent from OSV entirely (own_id_not_in_osv).

Primary test: two-sided repository-level permutation test of the pooled
(application - library) difference in blind share (10,000 permutations, seed
20261017). OSV canary GHSA-39mp-8hj3-5c49 must resolve or the run is void.

Public, read-only metadata only (GitHub Security Advisories + the OSV API),
unauthenticated, self-paced on GitHub's rate-limit reset. Stdlib only.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime as dt
import json
import math
import os
import random
import sys
import time
import urllib.error
import urllib.request

UA = "advisory-import-census (MV2 of Munim, Inc.)"
PERM_SEED = 20261017
N_PERM = 10000
MIN_AGE_DAYS = 14.0
PERIOD_CUTOFF = "2026-05-01"
OSV_CANARY = "GHSA-39mp-8hj3-5c49"

GH_ADVISORIES = "https://api.github.com/repos/%s/security-advisories?per_page=100&page=%d"
OSV_VULN = "https://api.osv.dev/v1/vulns/%s"


# ----------------------------------------------------------------- HTTP helpers

def _request(url, accept=None):
    headers = {"User-Agent": UA}
    if accept:
        headers["Accept"] = accept
    return urllib.request.Request(url, headers=headers)


def gh_get(url, tries=6):
    """GitHub REST GET that waits out the unauthenticated rate limit (60/hr)."""
    for i in range(tries):
        try:
            req = _request(url, accept="application/vnd.github+json")
            with urllib.request.urlopen(req, timeout=90) as resp:
                body = resp.read()
                return json.loads(body.decode("utf-8")), dict(resp.headers)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, dict(e.headers or {})
            if e.code in (403, 429):
                reset = (e.headers or {}).get("X-RateLimit-Reset")
                wait = 60
                if reset:
                    try:
                        wait = max(5, int(reset) - int(time.time()) + 3)
                    except ValueError:
                        pass
                print("[census] rate limited; sleeping %ds" % wait, flush=True)
                time.sleep(min(wait, 3900))
                continue
            if i == tries - 1:
                raise
            time.sleep(2 ** i)
        except (urllib.error.URLError, TimeoutError):
            if i == tries - 1:
                raise
            time.sleep(2 ** i)
    return None, {}


def osv_get(vid, pace=0.2, tries=4):
    url = OSV_VULN % vid
    for i in range(tries):
        try:
            with urllib.request.urlopen(_request(url), timeout=60) as resp:
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


# --------------------------------------------------------------- classification

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


# ------------------------------------------------------------------- statistics

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


# ------------------------------------------------------------------- collection

def iso_age_days(published_at, now):
    t = dt.datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    return (now - t).total_seconds() / 86400.0


def collect_repo(repo, group, now, osv_lookup):
    """All eligible advisory rows for one repo (empty list if none / unreachable)."""
    rows = []
    page = 1
    while True:
        advs, _ = gh_get(GH_ADVISORIES % (repo, page))
        if not advs:
            break
        for adv in advs:
            if (adv.get("state") or "published") != "published":
                continue
            pub = adv.get("published_at")
            if not pub:
                continue
            age = iso_age_days(pub, now)
            if age < MIN_AGE_DAYS:
                continue
            own_in_osv, osv_pkgs, blind = classify(adv, osv_lookup)
            cves = advisory_cves(adv)
            rows.append({
                "group": group, "repo": repo,
                "ghsa_id": adv.get("ghsa_id", ""),
                "cve_id": cves[0] if cves else "",
                "severity": adv.get("severity", ""),
                "published_at": pub,
                "age_days": round(age, 1),
                "period": "from_2026_05" if pub >= PERIOD_CUTOFF else "before_2026_05",
                "own_id_in_osv": str(own_in_osv),
                "osv_packages": ";".join(osv_pkgs),
                "repo_packages": ";".join(advisory_repo_packages(adv)),
                "scanner_class": "scanner_blind" if blind else "scanner_visible",
                "url": adv.get("html_url", ""),
            })
        if len(advs) < 100:
            break
        page += 1
    return rows


# ------------------------------------------------------------------- summarising

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


# -------------------------------------------------------------------------- main

def load_frame(path, group):
    with open(path, encoding="utf-8") as f:
        return [(e["repo"], group) for e in json.load(f)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--frame-dir", required=True,
                    help="dir with frame_apps.json and frame_libs.json")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--offline", action="store_true",
                    help="testing only: skip network; treat every advisory as visible")
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)
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

    rows = []
    for i, (repo, group) in enumerate(targets, 1):
        print("[census] %d/%d %s (%s)" % (i, len(targets), repo, group), flush=True)
        try:
            rows.extend(collect_repo(repo, group, now, osv_lookup))
        except Exception as e:  # one bad repo must not sink the run
            print("[census] skip %s: %s" % (repo, e), flush=True)

    cols = ["group", "repo", "ghsa_id", "cve_id", "severity", "published_at",
            "age_days", "period", "own_id_in_osv", "osv_packages", "repo_packages",
            "scanner_class", "url"]
    with open(os.path.join(args.out_dir, "app_library_census.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    summary = summarise(rows, frame_counts, canary_ok, snapshot)
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
    print("canary resolved:", canary_ok, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
