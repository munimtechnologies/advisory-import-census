"""Out-of-sample Go-module rescue test for the advisory-import gap (registry-channel A6).

A5 asks, on A3's own sample, whether a SOFTWARE-typed advisory (the maintainer named
no package on the GitHub advisory page) still reaches OSV-backed scanners when the
project is a Go module at its own repository path -- because GitHub's reviewers can
attach `github.com/<owner>/<repo>` to the global record without any package-registry
publication. That hypothesis was spotted in A3's residuals, so A5 is confirmatory on
the same sample. A6 is the out-of-sample version: a FRESH frame of 30 self-hosted
applications (none in any earlier frame), none of which ships a live application
release on a non-Go OSV-indexed registry (npm, PyPI, crates.io, RubyGems, Packagist,
Maven Central), collected with A3's published census and probed with A5's published
go-module helpers.

Pipeline (see job.json):
  1. fetch_deps.py           -- downloads the published A3/A5 code verbatim (+ sha256)
  2. attribution_census.py   -- A3's collector on frame_apps.json -> attribution_census.csv
  3. this script             -- per-repo go-module probe (A5's probe_repo) + GitHub repo
                                metadata (archived flag, primary language), the join,
                                and the pre-registered tests (A5's analyse, unchanged).

Pre-registration: PREREGISTRATION-registry-channel-a6.md (frozen before this ran).
Public read-only data only; no account, no writes; paced. Stdlib only.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import go_rescue_analysis as A  # noqa: E402  (published A5 analysis, verbatim)
import go_rescue_census as C    # noqa: E402  (published A5 probe helpers, verbatim)

GITHUB_API = "https://api.github.com/repos/%s"
GO_LANGUAGE = "Go"


# --------------------------------------------------------------------------
# Repository metadata (archived flag, primary language) -- frame hygiene + R2
# --------------------------------------------------------------------------

def parse_repo_meta(status, body, repo):
    """(status, body) of api.github.com/repos/<repo> -> metadata dict. A failed
    lookup is recorded as unknown (None), never as archived."""
    meta = {"repo": repo, "api_status": status, "archived": None,
            "language": None, "full_name": None, "renamed": False}
    if status != 200:
        return meta
    try:
        doc = json.loads(body)
    except ValueError:
        return meta
    meta["archived"] = bool(doc.get("archived"))
    meta["language"] = doc.get("language")
    meta["full_name"] = doc.get("full_name")
    meta["renamed"] = bool(meta["full_name"]) and \
        meta["full_name"].lower() != repo.lower()
    return meta


def repo_meta(repo, pace=1.0):
    st, body = C._get(GITHUB_API % repo, pace=pace)
    return parse_repo_meta(st, body, repo)


def included(meta):
    """Pre-registered frame hygiene: drop a repo only if GitHub says it is archived."""
    return meta.get("archived") is not True


# --------------------------------------------------------------------------
# Join
# --------------------------------------------------------------------------

def build_rows(census_rows, probes, metas):
    """Census rows of included repos + the per-repo covariates. Every frame repo is
    no_registry by construction (frozen classification), so A5's analyse() P1
    ('within no_registry') is A6's whole-frame test."""
    out = []
    for r in census_rows:
        repo = r["repo"]
        if repo not in probes or not included(metas.get(repo, {})):
            continue
        p = probes[repo]
        out.append({
            "registry_group": "no_registry",
            "repo": repo,
            "ghsa_id": r["ghsa_id"],
            "cve_id": r.get("cve_id", ""),
            "published_at": r.get("published_at", ""),
            "age_days": r.get("age_days", ""),
            "own_id_in_osv": r.get("own_id_in_osv", ""),
            "scanner_class": r["scanner_class"],
            "osv_packages": r.get("osv_packages", ""),
            "advisory_product_type": r.get("advisory_product_type", ""),
            "advisory_ecosystems": r.get("advisory_ecosystems", ""),
            "go_module": str(bool(p["go_module"])),
            "language": metas.get(repo, {}).get("language") or "",
            "gomod_module": p.get("gomod_module", ""),
            "proxy_version": p.get("proxy_version", ""),
        })
    return out


def software_rows(rows):
    return [r for r in rows if r["advisory_product_type"] == "software"]


# --------------------------------------------------------------------------
# R2: primary-language grouping (catches Go apps whose module is in a subdirectory)
# --------------------------------------------------------------------------

def language_test(rows):
    known = []
    for r in rows:
        if not r["language"]:
            continue
        r = dict(r)
        r["group"] = "go" if r["language"] == GO_LANGUAGE else "not_go"
        known.append(r)
    return {
        "visible_shares": A.visible_shares_by_group(known),
        "permutation": A.permutation_test(known, A.is_visible),
        "unknown_language_rows": len(rows) - len(known),
    }


# --------------------------------------------------------------------------
# R3/R4: the two confounds a parallel study (Safeguard, 2026-10-18) found drive
# import: review lag (recent advisories missing more) and CVE presence.
# --------------------------------------------------------------------------

MIN_SETTLED_DAYS = 90.0


def _go_test(rows):
    rows = A.set_go_group(rows)
    return {"visible_shares": A.visible_shares_by_group(rows),
            "permutation": A.permutation_test(rows, A.is_visible)}


def settled(r):
    try:
        return float(r["age_days"]) >= MIN_SETTLED_DAYS
    except (TypeError, ValueError):
        return False


def confound_tests(soft):
    return {
        "R3_settled_ge_90_days": _go_test([r for r in soft if settled(r)]),
        "R4_with_cve": _go_test([r for r in soft if r["cve_id"]]),
        "R4_without_cve": _go_test([r for r in soft if not r["cve_id"]]),
    }


def rescue_record(soft):
    """D1: among visible software-typed advisories, was the package-naming OSV record
    the advisory's OWN GHSA record, or only a CVE-alias record (e.g. a Go
    vulnerability-database GO- entry)? Counts only; distinguishes the GitHub-reviewer
    channel from an ecosystem database's own triage."""
    out = {}
    for grp in A.GROUPS:
        vis = [r for r in A.set_go_group(soft) if r["group"] == grp and A.is_visible(r)]
        own = sum(1 for r in vis if str(r["own_id_in_osv"]) == "True")
        out[grp] = {"visible_n": len(vis), "own_ghsa_record": own,
                    "cve_alias_only": len(vis) - own}
    return out


def covariate_agreement(probes, metas):
    """Per-repo go_module (A5 probe) vs primary language == Go, for the audit."""
    out = []
    for repo in sorted(probes):
        lang = (metas.get(repo) or {}).get("language")
        go_lang = (lang == GO_LANGUAGE) if lang else None
        if go_lang is not None and go_lang != bool(probes[repo]["go_module"]):
            out.append({"repo": repo, "go_module": bool(probes[repo]["go_module"]),
                        "language": lang})
    return out


def analyse_a6(rows, probes, metas):
    soft = software_rows(rows)
    s_soft = A.analyse(soft) if soft else None
    s_all = A.analyse(rows) if rows else None
    return {
        "mapping": {
            "P1_primary": "software_typed.P1_primary_no_registry",
            "P2_secondary": "all_advisories.P1_primary_no_registry",
            "P3_channel": "software_typed.P3_rescue_channel",
            "P4_residual": "software_typed.P4_residual",
            "R1": "software_typed.robustness",
            "R2": "R2_language_software / R2_language_all",
            "R3_R4": "confounds_software (settled >= 90 days; with / without CVE)",
            "D1": "D1_rescue_record_software",
        },
        "software_typed": s_soft,
        "all_advisories": s_all,
        "R2_language_software": language_test(soft),
        "R2_language_all": language_test(rows),
        "confounds_software": confound_tests(soft),
        "D1_rescue_record_software": rescue_record(soft),
        "covariate_disagreements": covariate_agreement(probes, metas),
    }


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--census-csv", required=True)
    ap.add_argument("--frame", default="frame_apps.json")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--pace", type=float, default=1.0)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    with open(args.frame, encoding="utf-8") as f:
        frame = [e["repo"] for e in json.load(f)]
    with open(args.census_csv, encoding="utf-8", newline="") as f:
        census_text = f.read()
    census_rows = list(csv.DictReader(census_text.splitlines()))

    probes, metas = {}, {}
    for repo in frame:
        probes[repo] = C.probe_repo(repo, pace=args.pace)
        metas[repo] = repo_meta(repo, pace=args.pace)
        p, m = probes[repo], metas[repo]
        print("  %-38s go_module=%s (gomod=%s match=%s | proxy=%s %s) lang=%s "
              "archived=%s" % (repo, p["go_module"], p["gomod_module"] or "-",
                               p["gomod_match"], p["proxy_status"],
                               p["proxy_version"] or "-", m["language"],
                               m["archived"]), flush=True)

    rows = build_rows(census_rows, probes, metas)
    summary = analyse_a6(rows, probes, metas)

    cols = ["registry_group", "repo", "ghsa_id", "cve_id", "published_at",
            "age_days", "own_id_in_osv", "scanner_class", "osv_packages", "advisory_product_type",
            "advisory_ecosystems", "go_module", "language", "gomod_module",
            "proxy_version"]
    with open(os.path.join(args.out_dir, "oos_go_rescue_census.csv"), "w",
              encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    counts = {}
    for r in census_rows:
        t = counts.setdefault(r["repo"], {"all": 0, "software": 0})
        t["all"] += 1
        t["software"] += 1 if r.get("advisory_product_type") == "software" else 0
    pcols = ["repo", "included", "archived", "language", "renamed", "n_advisories",
             "n_software_adv", "go_module", "gomod_match", "gomod_module",
             "gomod_branch", "gomod_status", "proxy_status", "proxy_version",
             "proxy_ok"]
    with open(os.path.join(args.out_dir, "oos_go_rescue_repo_probe.csv"), "w",
              encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=pcols)
        w.writeheader()
        for repo in frame:
            p, m = probes[repo], metas[repo]
            c = counts.get(repo, {"all": 0, "software": 0})
            w.writerow({
                "repo": repo, "included": included(m), "archived": m["archived"],
                "language": m["language"], "renamed": m["renamed"],
                "n_advisories": c["all"], "n_software_adv": c["software"],
                "go_module": p["go_module"], "gomod_match": p["gomod_match"],
                "gomod_module": p["gomod_module"], "gomod_branch": p["gomod_branch"],
                "gomod_status": p["gomod_status"], "proxy_status": p["proxy_status"],
                "proxy_version": p["proxy_version"], "proxy_ok": p["proxy_ok"],
            })

    summary["meta"] = {
        "study": "registry-channel A6 (out-of-sample Go-module reviewer-rescue)",
        "census_sha256": hashlib.sha256(census_text.encode("utf-8")).hexdigest(),
        "frame_n": len(frame),
        "excluded_archived": sorted(r for r in frame if not included(metas[r])),
        "renamed": sorted(r for r in frame if metas[r]["renamed"]),
        "repos_with_advisories": sorted(counts),
        "frame_repos_without_rows": sorted(r for r in frame if r not in counts),
        "n_rows": len(rows),
        "n_software_typed": len(software_rows(rows)),
        "n_go_module_repos": sum(1 for r in frame if probes[r]["go_module"]),
        "gomod_proxy_disagreements": [
            {"repo": p["repo"], "gomod_match": p["gomod_match"], "proxy_ok": p["proxy_ok"]}
            for p in probes.values() if p["gomod_match"] != p["proxy_ok"]
        ],
    }
    with open(os.path.join(args.out_dir, "oos_go_rescue_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(args.out_dir, "oos_go_rescue_per_repo.csv"), "w",
              encoding="utf-8", newline="") as f:
        cols = ["repo", "registry_group", "go_module", "eligible", "visible",
                "visible_pct"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        if summary["all_advisories"]:
            w.writerows(summary["all_advisories"]["per_repo"])

    for label in ("software_typed", "all_advisories"):
        s = summary[label]
        pm = s and s["P1_primary_no_registry"]["permutation"]
        if pm:
            vs = s["P1_primary_no_registry"]["visible_shares"]
            print("%s: go %s%% (%d/%d) vs not_go %s%% (%d/%d) = %+.1f pts, p=%s "
                  "(%d repos)" % (label, vs["go"]["pct"], vs["go"]["k"], vs["go"]["n"],
                                  vs["not_go"]["pct"], vs["not_go"]["k"],
                                  vs["not_go"]["n"], pm["difference_pct_points"],
                                  pm["p_two_sided"], pm["repositories"]), flush=True)
        else:
            print("%s: no permutation (a group is empty)" % label, flush=True)
    print("meta:", json.dumps(summary["meta"], indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
