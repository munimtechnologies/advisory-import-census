"""go.mod module-path class vs the Go repo-path rescue (registry-channel A8).

A6 showed that package-less advisories of self-hosted Go applications reach
OSV-backed scanners (74.8% visible vs 0.2% for non-Go) because GitHub's reviewers
attach the default coordinate `github.com/<owner>/<repo>`. A8 asks whether that
rescue is confined to repositories whose go.mod `module` line IS the repository
root (root_match), and fails for vanity or non-root module paths (non_root).

This is a RE-ANALYSIS of A6's committed artifacts; no advisory or visibility data is
collected. Inputs (fetched byte-for-byte by fetch_inputs.py, blob shas recorded):

  study/registry-channel-a6/oos_go_rescue_census.csv     advisory-level visibility
  study/registry-channel-a6/oos_go_rescue_repo_probe.csv per-repo go.mod probe
  study/registry-channel-a5/go_rescue_analysis.py        A5/A6 statistics, verbatim

Pre-registration: PREREGISTRATION-registry-channel-a8.md (frozen before this ran).
Deterministic, stdlib only. Apache-2.0, made with AI agents working for MV2 of
Munim, Inc.
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import go_rescue_analysis as A  # noqa: E402  (published A5 statistics, verbatim)
except ImportError:  # offline unit tests of the pure helpers below
    A = None

CLASSES = ("root_match", "non_root")
REPORTED = ("root_match", "non_root", "no_gomod", "unparsed_gomod")
NON_ROOT_KINDS = ("vanity_domain", "github_nonroot")
MIN_ADVISORIES = 4
DIFF_THRESHOLD = 40.0
P_THRESHOLD = 0.05
NON_ROOT_CEILING = 20.0
A6_NON_GO_BASELINE_PCT = 0.2
PACKAGE_LESS = "software"


# --------------------------------------------------------------------------
# Covariate (frozen definition, PREREGISTRATION "Covariate")
# --------------------------------------------------------------------------

def truthy(value):
    return str(value).strip() == "True"


def module_class(probe):
    """Probe row of oos_go_rescue_repo_probe.csv -> module-path class, or None if
    the repo is outside the frame (included != True, e.g. archived)."""
    if not truthy(probe.get("included")):
        return None
    if str(probe.get("gomod_status", "")).strip() != "200":
        return "no_gomod"
    if truthy(probe.get("gomod_match")):
        return "root_match"
    if (probe.get("gomod_module") or "").strip():
        return "non_root"
    # a go.mod was read but no module line parsed: not in the frozen classes
    return "unparsed_gomod"


def non_root_kind(module):
    """Descriptive split of a non_root module path by its host."""
    host = (module or "").strip().lower().split("/")[0]
    return "github_nonroot" if host == "github.com" else "vanity_domain"


def is_package_less(row):
    return row.get("advisory_product_type") == PACKAGE_LESS


# --------------------------------------------------------------------------
# Verdict (frozen rule, PREREGISTRATION "Verdict rule")
# --------------------------------------------------------------------------

def verdict(n_repos, n_adv, diff, p, non_root_pct):
    """The verdict rule exactly as written in the frozen code block."""
    if (n_repos["root_match"] == 0 or n_repos["non_root"] == 0
            or n_adv["root_match"] < MIN_ADVISORIES
            or n_adv["non_root"] < MIN_ADVISORIES):
        return "CONFOUNDED_INSEPARABLE"
    if n_adv["non_root"] < MIN_ADVISORIES:  # unreachable as frozen; kept verbatim
        return "INCONCLUSIVE_UNDERPOWERED"
    if (diff is not None and p is not None and non_root_pct is not None
            and diff >= DIFF_THRESHOLD and p < P_THRESHOLD
            and non_root_pct <= NON_ROOT_CEILING):
        return "CONFINED"
    return "NOT_CONFINED"


def verdict_prose_reading(n_repos, n_adv, diff, p, non_root_pct):
    """The power paragraph's reading, reported alongside because the frozen code
    block makes its INCONCLUSIVE_UNDERPOWERED branch unreachable: non_root with
    1-3 package-less advisories is underpowered rather than inseparable."""
    if (n_repos["root_match"] == 0 or n_repos["non_root"] == 0
            or n_adv["root_match"] < MIN_ADVISORIES or n_adv["non_root"] == 0):
        return "CONFOUNDED_INSEPARABLE"
    if n_adv["non_root"] < MIN_ADVISORIES:
        return "INCONCLUSIVE_UNDERPOWERED"
    return verdict(n_repos, n_adv, diff, p, non_root_pct)


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def _need_stats():
    if A is None:
        raise SystemExit("go_rescue_analysis.py (A5 statistics) is missing; "
                         "run fetch_inputs.py first")


def label_rows(census_rows, classes):
    """Package-less census rows of classified repos, each with its class as group."""
    out = []
    for r in census_rows:
        cls = classes.get(r["repo"])
        if cls is None or not is_package_less(r):
            continue
        r = dict(r)
        r["group"] = cls
        out.append(r)
    return out


def per_repo(probe_rows, rows, classes):
    tally = {}
    for r in rows:
        t = tally.setdefault(r["repo"], [0, 0])
        t[0] += 1 if A.is_visible(r) else 0
        t[1] += 1
    out = []
    for p in probe_rows:
        repo = p["repo"]
        cls = classes.get(repo)
        if cls is None:
            continue
        k, n = tally.get(repo, [0, 0])
        module = (p.get("gomod_module") or "").strip()
        out.append({
            "repo": repo, "module_class": cls,
            "non_root_kind": non_root_kind(module) if cls == "non_root" else "",
            "gomod_module": module, "language": p.get("language", ""),
            "package_less_advisories": n, "visible": k,
            "visible_pct": round(100 * k / n, 1) if n else None,
        })
    return out


def analyse(census_rows, probe_rows):
    _need_stats()
    classes = {}
    for p in probe_rows:
        cls = module_class(p)
        if cls is not None:
            classes[p["repo"]] = cls
    rows = label_rows(census_rows, classes)
    table = per_repo(probe_rows, rows, classes)

    n_repos = {c: sum(1 for t in table if t["module_class"] == c) for c in REPORTED}
    n_adv = {c: sum(1 for r in rows if r["group"] == c) for c in REPORTED}
    shares = {c: A.share([r for r in rows if r["group"] == c], A.is_visible)
              for c in REPORTED}

    kinds = {t["repo"]: t["non_root_kind"] for t in table if t["non_root_kind"]}
    split = {k: A.share([r for r in rows if r["group"] == "non_root"
                         and kinds.get(r["repo"]) == k], A.is_visible)
             for k in NON_ROOT_KINDS}
    split_repos = {k: sorted(repo for repo, v in kinds.items() if v == k)
                   for k in NON_ROOT_KINDS}

    perm = A.permutation_test([r for r in rows if r["group"] in CLASSES],
                              A.is_visible, groups=CLASSES)
    diff = perm["difference_pct_points"] if perm else None
    p = perm["p_two_sided"] if perm else None
    non_root_pct = shares["non_root"]["pct"]

    return {
        "study": "registry-channel A8 (go.mod module-path class vs Go repo-path rescue)",
        "measure": {
            "unit": "package-less advisory (advisory_product_type == 'software'), "
                    "visibility = scanner_visible, both verbatim from A6",
            "classes": "root_match: gomod_match True; non_root: gomod_match False and "
                       "a module line; no_gomod: gomod_status != 200 (baseline only)",
        },
        "repos_by_class": n_repos,
        "package_less_advisories_by_class": n_adv,
        "visible_by_class": shares,
        "P1_primary": {"difference_pct_points": diff, "p_two_sided": p,
                       "permutation": perm,
                       "threshold": ">= +%.1f pts and p < %s" % (DIFF_THRESHOLD,
                                                                 P_THRESHOLD)},
        "P2_non_root_not_rescued": {
            "visible_pct": non_root_pct, "threshold": "<= %.0f%%" % NON_ROOT_CEILING,
            "holds": (non_root_pct <= NON_ROOT_CEILING) if non_root_pct is not None
            else None,
        },
        "P3_no_gomod_baseline": {"visible": shares["no_gomod"],
                                 "a6_non_go_baseline_pct": A6_NON_GO_BASELINE_PCT},
        "non_root_split": {"visible": split, "repos": split_repos},
        "verdict": verdict(n_repos, n_adv, diff, p, non_root_pct),
        "verdict_prose_reading": verdict_prose_reading(n_repos, n_adv, diff, p,
                                                       non_root_pct),
        "census_repos_not_in_probe": sorted({r["repo"] for r in census_rows}
                                            - {x["repo"] for x in probe_rows}),
        "per_repo": table,
    }


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------

def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--census-csv", required=True)
    ap.add_argument("--probe-csv", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    summary = analyse(read_csv(args.census_csv), read_csv(args.probe_csv))

    with open(os.path.join(args.out_dir, "gomod_class_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    cols = ["repo", "module_class", "non_root_kind", "gomod_module", "language",
            "package_less_advisories", "visible", "visible_pct"]
    with open(os.path.join(args.out_dir, "gomod_class_per_repo.csv"), "w",
              encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(summary["per_repo"])

    for c in REPORTED:
        s = summary["visible_by_class"][c]
        print("%-15s repos=%-3d package-less=%-4d visible=%s%%" % (
            c, summary["repos_by_class"][c], s["n"], s["pct"]), flush=True)
    p1 = summary["P1_primary"]
    print("P1 diff=%s pts p=%s | verdict=%s (prose reading: %s)" % (
        p1["difference_pct_points"], p1["p_two_sided"], summary["verdict"],
        summary["verdict_prose_reading"]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
