"""Registry-channel mechanism test for the advisory-import gap (applications only).

The confirmed application-vs-library census (study/app-vs-library/RESULTS.md,
committed at 141a3ade) found that self-hosted *applications* are far more
"scanner-blind" than *libraries*: 53.0% of eligible application advisories have
no package named in OSV, versus 0% for libraries (repository-level permutation
test, p = 0.0057). An exploratory observation in that write-up was that, *within
applications*, the visible ones looked like the ones that also ship a package to
a public registry, and the ~100%-blind ones looked like the Docker-only apps.

This script formalises that observation as a pre-registered, falsifiable test.
It splits ONLY the 27 application repositories that have eligible advisories into
two groups by a single repository-level distribution fact -- does the project
publish its own application code to a public language registry whose ecosystem
OSV/GHSA indexes (npm, PyPI, crates.io, Go module proxy with a tagged release,
RubyGems, Packagist, Maven Central)? -- frozen in registry_classification.json
BEFORE this test is run, and verified against each registry, NOT from the
advisory data. It then reuses the census's own repository-level permutation test
to ask whether the two groups differ in blind rate.

IMPORTANT, honest limitation: this reuses the SAME 27-repository sample that
generated the exploratory observation, so it is confirmatory-OF-MECHANISM on the
generating sample, not an independent out-of-sample replication. See
PREREGISTRATION-registry-channel.md.

The statistics functions below (wilson, share, median, repo_median_pct,
permutation_test, is_blind, own_missing) are COPIED VERBATIM from the published
collector app_library_census_html.py (commit eb532df) so that this subgroup test
scores every advisory exactly as the frozen census did.

Public, read-only, deterministic. Stdlib only.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import json
import math
import os
import random
import sys

PERM_SEED = 20261017
N_PERM = 10000
GROUPS = ("registry", "no_registry")


# ===========================================================================
# STATISTICS -- copied verbatim from app_library_census_html.py (eb532df).
# ===========================================================================

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


def permutation_test(rows, pred, groups=GROUPS, n_perm=N_PERM, seed=PERM_SEED):
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


# ===========================================================================
# REGISTRY-CHANNEL SUBGROUP ANALYSIS
# ===========================================================================

def load_classification(path):
    """Return {repo: 'registry'|'no_registry'} from the frozen classification."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    mapping = {}
    for repo, info in doc["classification"].items():
        g = info["group"]
        if g not in GROUPS:
            raise ValueError("repo %s has group %r not in %r" % (repo, g, GROUPS))
        mapping[repo] = g
    return mapping, doc


def load_application_rows(csv_path):
    """Return the eligible APPLICATION advisory rows from the census CSV."""
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["group"] == "application":
                rows.append(r)
    return rows


def relabel(rows, mapping):
    """Relabel each row's 'group' to its repository's registry class.

    Raises if a repository with advisories was never classified -- the frozen
    classification must cover every application repository in the census."""
    out, unknown = [], set()
    for r in rows:
        g = mapping.get(r["repo"])
        if g is None:
            unknown.add(r["repo"])
            continue
        r = dict(r)
        r["group"] = g
        out.append(r)
    if unknown:
        raise ValueError("unclassified repositories with advisories: %s"
                         % ", ".join(sorted(unknown)))
    return out


def heaviest_repo(rows, group):
    counts = {}
    for r in rows:
        if r["group"] == group:
            counts[r["repo"]] = counts.get(r["repo"], 0) + 1
    return max(counts, key=counts.get) if counts else None


def group_block(rows, group):
    gr = [r for r in rows if r["group"] == group]
    return {
        "repos": len({r["repo"] for r in gr}),
        "eligible": len(gr),
        "blind": share(gr, is_blind),
        "own_id_not_in_osv": share(gr, own_missing),
        "repo_median_blind_pct": repo_median_pct(gr, is_blind),
    }


def per_repo_table(rows):
    tally = {}
    for r in rows:
        t = tally.setdefault(r["repo"], {"group": r["group"], "n": 0, "blind": 0})
        t["n"] += 1
        t["blind"] += 1 if is_blind(r) else 0
    out = []
    for repo in sorted(tally):
        t = tally[repo]
        out.append({"repo": repo, "group": t["group"], "eligible": t["n"],
                    "blind": t["blind"],
                    "blind_pct": round(100 * t["blind"] / t["n"], 1) if t["n"] else None})
    return out


def analyse(rows):
    out = {
        "measure": {
            "primary": "scanner_blind: no OSV record, by GHSA or CVE alias, "
                       "names any package",
            "secondary": "own_id_not_in_osv: the advisory's own GHSA id does not "
                         "resolve in OSV",
        },
        "unit": "repository",
        "groups": {g: group_block(rows, g) for g in GROUPS},
        "comparison": {
            "blind": permutation_test(rows, is_blind),
            "own_id_not_in_osv": permutation_test(rows, own_missing),
        },
        "robustness": {},
        "per_repo": per_repo_table(rows),
    }
    # Pre-specified robustness: drop the most advisory-heavy repo in each group
    # (n8n/siyuan-type heavy hitters should not decide the result on their own).
    drop = {heaviest_repo(rows, GROUPS[0]), heaviest_repo(rows, GROUPS[1])}
    drop.discard(None)
    trimmed = [r for r in rows if r["repo"] not in drop]
    out["robustness"]["drop_heaviest_repo_each_group"] = {
        "dropped": sorted(drop), "blind": permutation_test(trimmed, is_blind)}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", required=True,
                    help="app_library_census.csv (committed at 141a3ade)")
    ap.add_argument("--classification", required=True,
                    help="registry_classification.json (frozen before this run)")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    mapping, doc = load_classification(args.classification)
    rows = load_application_rows(args.csv)
    app_repos = {r["repo"] for r in rows}
    classified = set(mapping)
    labelled = relabel(rows, mapping)

    summary = analyse(labelled)
    summary["source"] = {
        "csv": os.path.basename(args.csv),
        "classification_frozen_utc": doc.get("frozen_utc"),
        "source_commit": doc.get("source_csv", {}).get("repo_commit"),
        "application_repos_with_advisories": len(app_repos),
        "classified_repos": len(classified),
        "classification_covers_all": app_repos == classified,
        "n_registry": sum(1 for g in mapping.values() if g == "registry"),
        "n_no_registry": sum(1 for g in mapping.values() if g == "no_registry"),
    }
    with open(os.path.join(args.out_dir, "registry_channel_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    cols = ["repo", "group", "eligible", "blind", "blind_pct"]
    with open(os.path.join(args.out_dir, "registry_channel_per_repo.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(summary["per_repo"])

    for g in GROUPS:
        b = summary["groups"][g]
        print("%-12s %2d repos | eligible %4d | blind %5.1f%% %s | repo-median %5.1f%%"
              % (g, b["repos"], b["eligible"], (b["blind"]["pct"] or 0),
                 b["blind"]["ci95"], (b["repo_median_blind_pct"] or 0)), flush=True)
    c = summary["comparison"]["blind"]
    if c:
        print("registry - no_registry = %+.1f points, p = %s (%d repos)"
              % (c["difference_pct_points"], c["p_two_sided"], c["repositories"]),
              flush=True)
    print("classification covers all app repos:",
          summary["source"]["classification_covers_all"], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
