"""Corrected re-analysis of MV2's pre-registered AI-vs-control import-gap study.

group_census.py (pre-registered) calls an advisory `no_package` whenever the
*repository* advisory names no package, and `package_not_in_osv` whenever the
repository advisory's own package name (often free text, e.g. "go:Traefik",
"pip:Home Assistant") is not found in OSV. In both cases OSV may still serve the
advisory under its own GHSA ID with a proper package (GitHub's reviewers add
one, e.g. GHSA-7rqg-hjwc-6mjf -> Go github.com/grafana/grafana). A scanner reads
that record, so the advisory is not scanner-blind.

This script leaves group_census.py untouched (it is the pre-registered
instrument) and reports both definitions side by side:

  prereg  scanner_class != scanner_visible             (as pre-registered)
  fixed   prereg-blind AND NOT (own GHSA record in OSV names >= 1 package)

Same Wilson intervals and the same repository-level permutation test (pooled
share, 10,000 permutations, seed 20261015) as group_census.py. It also re-derives
the pre-registered numbers and checks them against group_census.py's own
summary, so any drift between the two implementations is caught.

Exploratory, not pre-registered: the control group split into its 15
self-hosted apps and 15 libraries/frameworks (the order of CONTROL_REPOS).

Stdlib only. Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import json
import math
import os
import random
import sys
import time
import urllib.error
import urllib.request

PERM_SEED = 20261015
N_PERM = 10000
MIN_AGE_DAYS = 14.0

# First 15 entries of CONTROL_REPOS in group_census.py ("15 self-hosted apps").
CONTROL_APPS = {
    "mastodon/mastodon", "discourse/discourse", "go-gitea/gitea", "TryGhost/Ghost",
    "directus/directus", "strapi/strapi", "nocodb/nocodb", "louislam/uptime-kuma",
    "jellyfin/jellyfin", "home-assistant/core", "filebrowser/filebrowser", "zulip/zulip",
    "outline/outline", "metabase/metabase", "grafana/grafana",
}

OSV_VULN = "https://api.osv.dev/v1/vulns/%s"
UA = "advisory-import-census-reclassify (MV2 of Munim, Inc.)"


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


def permutation_test(rows, pred, groups, n_perm=N_PERM, seed=PERM_SEED):
    """Same statistic and shuffle as group_census.permutation_test: pooled share
    in groups[0] minus groups[1], group labels shuffled across repositories."""
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


def load_rows(path, min_age=MIN_AGE_DAYS):
    """Eligible rows only: a scanner_class and age >= min_age days."""
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                age = float(r.get("age_days") or "")
            except ValueError:
                continue
            if not r.get("scanner_class") or age < min_age:
                continue
            out.append(r)
    return out


def record_packages(record):
    """'eco:name' for each affected package an OSV record names."""
    pkgs = []
    for a in (record or {}).get("affected") or []:
        p = a.get("package") or {}
        if p.get("name"):
            pkgs.append("%s:%s" % (p.get("ecosystem", ""), p["name"]))
    return sorted(set(pkgs))


def fetch_osv(ghsa, pace=0.2, tries=4):
    """OSV record for an ID, or None on 404. Raises after repeated failures."""
    url = OSV_VULN % ghsa
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
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


def reclassify(rows, lookup):
    """Add osv_record_packages and scanner_class_fixed to each row.
    lookup(ghsa) -> OSV record or None; only called where it can matter."""
    checked = failed = 0
    for r in rows:
        r["osv_record_packages"] = ""
        r["scanner_class_fixed"] = r["scanner_class"]
        if r["scanner_class"] == "scanner_visible" or r.get("own_id_in_osv") != "True":
            continue
        checked += 1
        try:
            pkgs = record_packages(lookup(r["ghsa_id"]))
        except Exception:
            failed += 1
            r["scanner_class_fixed"] = "unchecked"
            continue
        r["osv_record_packages"] = ";".join(pkgs)
        if pkgs:
            r["scanner_class_fixed"] = "visible_by_own_record"
    return {"rows_checked_in_osv": checked, "lookups_failed": failed}


def prereg_blind(r):
    return r["scanner_class"] != "scanner_visible"


def fixed_blind(r):
    # "unchecked" stays blind (as pre-registered) so a failed lookup can only
    # make the corrected figure more conservative, never lower.
    return r["scanner_class_fixed"] in ("no_package", "package_not_in_osv", "unchecked")


def own_id_missing(r):
    return r.get("own_id_in_osv") != "True"


def summarise(rows):
    out = {"definitions": {
        "prereg": "scanner_class != scanner_visible (group_census.py as pre-registered)",
        "fixed": "prereg-blind and the advisory's own GHSA record in OSV names no package",
    }, "groups": {}, "comparison": {}}
    for g in ("ai", "control"):
        gr = [r for r in rows if r["group"] == g]
        out["groups"][g] = {
            "eligible": len(gr),
            "repos_with_eligible_advisories": len({r["repo"] for r in gr}),
            "prereg_blind": share(gr, prereg_blind),
            "fixed_blind": share(gr, fixed_blind),
            "own_id_not_in_osv": share(gr, own_id_missing),
            "prereg_repo_median_pct": repo_median_pct(gr, prereg_blind),
            "fixed_repo_median_pct": repo_median_pct(gr, fixed_blind),
            "fixed_classes": {c: sum(1 for r in gr if r["scanner_class_fixed"] == c)
                              for c in ("scanner_visible", "visible_by_own_record",
                                        "package_not_in_osv", "no_package", "unchecked")},
        }
    for name, pred in (("prereg_blind", prereg_blind), ("fixed_blind", fixed_blind),
                       ("own_id_not_in_osv", own_id_missing)):
        out["comparison"][name] = permutation_test(rows, pred, ("ai", "control"))

    # Exploratory (not pre-registered): control apps vs control libraries.
    ctrl = []
    for r in rows:
        if r["group"] == "control":
            r2 = dict(r)
            r2["group"] = "control_app" if r["repo"] in CONTROL_APPS else "control_lib"
            ctrl.append(r2)
    exp = {"note": "exploratory, not pre-registered: CONTROL_REPOS order 15 apps + 15 libraries"}
    for g in ("control_app", "control_lib"):
        gr = [r for r in ctrl if r["group"] == g]
        exp[g] = {"eligible": len(gr), "repos": len({r["repo"] for r in gr}),
                  "fixed_blind": share(gr, fixed_blind),
                  "fixed_repo_median_pct": repo_median_pct(gr, fixed_blind)}
    exp["comparison_fixed_blind"] = permutation_test(
        ctrl, fixed_blind, ("control_app", "control_lib"))
    out["exploratory_control_app_vs_lib"] = exp
    return out


def check_against_census(summary, census):
    """Our pre-registered re-derivation must equal group_census.py's own numbers."""
    problems = []
    for g in ("ai", "control"):
        mine = summary["groups"][g]["prereg_blind"]
        theirs = census["groups"][g]["scanner_blind"]
        if (mine["k"], mine["n"]) != (theirs["k"], theirs["n"]):
            problems.append("%s scanner_blind %s/%s vs census %s/%s" % (
                g, mine["k"], mine["n"], theirs["k"], theirs["n"]))
    mine = summary["comparison"]["prereg_blind"] or {}
    theirs = (census.get("comparison") or {}).get("scanner_blind") or {}
    for key in ("difference_pct_points", "p_two_sided"):
        if mine.get(key) != theirs.get(key):
            problems.append("comparison %s %s vs census %s" % (key, mine.get(key), theirs.get(key)))
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", required=True, help="group_census.csv from group_census.py")
    ap.add_argument("--census-summary", help="summary_groups.json from the same run")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--offline", action="store_true",
                    help="no OSV lookups: assume an own record in OSV names a package")
    args = ap.parse_args(argv)

    rows = load_rows(args.csv)
    if args.offline:
        stats = reclassify(rows, lambda ghsa: {"affected": [{"package": {"name": "?"}}]})
    else:
        stats = reclassify(rows, fetch_osv)
    summary = summarise(rows)
    summary["reclassify"] = stats
    summary["offline_assumption"] = bool(args.offline)

    if args.census_summary:
        with open(args.census_summary, encoding="utf-8") as f:
            census = json.load(f)
        summary["snapshot_utc"] = census.get("snapshot_utc")
        summary["self_check_against_census"] = check_against_census(summary, census) or "match"

    os.makedirs(args.out_dir, exist_ok=True)
    cols = list(rows[0].keys()) if rows else []
    with open(os.path.join(args.out_dir, "group_census_reclassified.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(args.out_dir, "summary_reclassified.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    for g in ("ai", "control"):
        s = summary["groups"][g]
        print("%-8s eligible %4d | prereg blind %5.1f%% | fixed blind %5.1f%% %s" % (
            g, s["eligible"], s["prereg_blind"]["pct"] or 0, s["fixed_blind"]["pct"] or 0,
            s["fixed_blind"]["ci95"]))
    for name, c in summary["comparison"].items():
        if c:
            print("%-18s ai - control = %+.1f points, p = %s" % (
                name, c["difference_pct_points"], c["p_two_sided"]))
    print("reclassify:", stats, "| self-check:", summary.get("self_check_against_census"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
