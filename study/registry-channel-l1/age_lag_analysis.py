"""registry-channel L1: is the advisory-import blind spot review lag or a permanent gap?

Re-analysis of A4's real-package census. If no_registry advisories only look invisible
because GitHub has not yet imported the recent ones, then older no_registry advisories
should catch up: visible(old) - visible(young) would be large and positive (LAG). If
the gap is structural, old advisories stay invisible (PERMANENT).

Frozen design (see PREREGISTRATION-registry-channel-l1.md):
  Bins by age_days: young 14<=age<90, mid 90<=age<365, old age>=365. age<14 dropped.
  P1 (primary): within no_registry, pooled visible(old) - visible(young). The arc's
    "structural blind spot" reading predicts this is < +15.0 points. Tested with a
    WITHIN-REPO permutation: inside each repo, shuffle that repo's own young/old
    labels (10,000 draws, seed 20261017, two-sided). Repos with only one bin keep
    their advisories in the pooled rates but add nothing to the null spread.
  P2: among OLD advisories only, visible(registry) - visible(no_registry), tested with
    the arc's repository-level permutation. Holds if diff >= +25.0 pts and p < 0.05.
  P3 (descriptive, no threshold): visible rate with Wilson CI for every bin x group
    cell, overall and for package-typed advisories, plus a per-repo young/old table.
  Floor: P1 underpowered if no_registry young or old bin < 20 advisories, or < 3 repos
    have both a young and an old advisory. P2 underpowered if either group has < 3
    repos with an old advisory.
  Verdict: INCONCLUSIVE_UNDERPOWERED if P1 underpowered; else LAG if d1 >= 15 and
    p1 < 0.05; else PERMANENT if d1 < 15 and P2 holds; else MIXED.

Visibility is A4's scanner_class == "scanner_visible", verbatim. Statistics (wilson,
share, repository-level permutation_test, is_visible) are reused verbatim from A5's
go_rescue_analysis.py, fetched and blob-sha-checked by fetch_inputs.py.

Stdlib only. Apache-2.0 (code) / CC BY 4.0 (text & data). Made with AI agents working
for MV2 of Munim, Inc. No result here has been reviewed by a human.
"""
import argparse
import csv
import json
import os
import random
import sys
from collections import defaultdict

try:  # present only when fetch_inputs.py has run beside this file (the compete job)
    import go_rescue_analysis as stats
except Exception:  # noqa: BLE001 - offline tests import this module without A5 present
    stats = None

PERM_SEED = 20261017
N_PERM = 10000
ALPHA = 0.05
AGE_FLOOR = 14
P1_LAG_THRESHOLD = 15.0   # d1 >= this (and p<alpha) => LAG; d1 < this => candidate PERMANENT
P2_DIFF_THRESHOLD = 25.0
FLOOR_MIN_ADVISORIES = 20
FLOOR_MIN_REPOS_BOTH = 3
P2_MIN_REPOS_PER_GROUP = 3


def is_visible(r):
    """A4's visibility, verbatim; mirrors A5's go_rescue_analysis.is_visible."""
    return r.get("scanner_class") == "scanner_visible"


def age_bin(age_days):
    """Bin a (valid, >=AGE_FLOOR) age in days. Returns None for age < AGE_FLOOR."""
    if age_days is None or age_days < AGE_FLOOR:
        return None
    if age_days < 90:
        return "young"
    if age_days < 365:
        return "mid"
    return "old"


def load_classification(path):
    """repo(lowercased) -> 'registry'|'no_registry', as A4/E1 load_classification does."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    cls = data.get("classification", data) if isinstance(data, dict) else data
    out = {}
    for repo, meta in cls.items():
        g = meta.get("group") if isinstance(meta, dict) else meta
        if g in ("registry", "no_registry"):
            out[repo.lower()] = g
    return out


def load_rows(census_path, classification):
    """In-frame advisories with a valid age bin. Returns (rows, counts)."""
    rows = []
    off_frame = age_missing = age_below_floor = 0
    with open(census_path, encoding="utf-8") as f:
        for raw in csv.DictReader(f):
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
            rows.append({
                "repo": repo,
                "group": group,
                "age_days": age,
                "bin": b,
                "scanner_class": raw.get("scanner_class"),
                "advisory_product_type": (raw.get("advisory_product_type") or "").strip(),
                "visible": is_visible(raw),
            })
    counts = {"off_frame": off_frame, "age_missing": age_missing,
              "age_below_floor": age_below_floor, "kept": len(rows)}
    return rows, counts


def pooled_old_young_diff(items):
    """old_rate - young_rate (proportion) over items; None if a bin is empty."""
    old = [r for r in items if r["bin"] == "old"]
    young = [r for r in items if r["bin"] == "young"]
    if not old or not young:
        return None
    o = sum(1 for r in old if r["visible"]) / len(old)
    y = sum(1 for r in young if r["visible"]) / len(young)
    return o - y


def within_repo_permutation(items, n_perm=N_PERM, seed=PERM_SEED):
    """Permute young/old labels inside each repo; null for pooled old-young diff.

    items: dicts with keys repo, bin in {young, old}, visible (bool). Mid is excluded
    by the caller. Single-bin repos keep their rows (pooled rates) but shuffling their
    identical labels is a no-op, so they add nothing to the null spread.
    """
    obs = pooled_old_young_diff(items)
    if obs is None:
        return None
    by_repo = defaultdict(list)
    for i, r in enumerate(items):
        by_repo[r["repo"]].append(i)
    repo_idx = list(by_repo.values())
    labels = [r["bin"] for r in items]
    vis = [1 if r["visible"] else 0 for r in items]
    rng = random.Random(seed)
    extreme = valid = 0
    for _ in range(n_perm):
        perm = labels[:]
        for idxs in repo_idx:
            lab = [labels[i] for i in idxs]
            rng.shuffle(lab)
            for j, i in enumerate(idxs):
                perm[i] = lab[j]
        ok = on = yk = yn = 0
        for i in range(len(items)):
            if perm[i] == "old":
                on += 1
                ok += vis[i]
            else:
                yn += 1
                yk += vis[i]
        if on == 0 or yn == 0:
            continue
        d = ok / on - yk / yn
        valid += 1
        if abs(d) >= abs(obs) - 1e-12:
            extreme += 1
    repos_both = sum(1 for idxs in repo_idx if len({labels[i] for i in idxs}) == 2)
    return {
        "difference_pct_points": round(obs * 100, 1),
        "p_two_sided": round((extreme + 1) / (valid + 1), 4),
        "permutations": valid,
        "seed": seed,
        "unit": "advisory_within_repo",
        "repos_both_bins": repos_both,
    }


def decide_verdict(p1_underpowered, d1, p1, p2_holds):
    if p1_underpowered:
        return "INCONCLUSIVE_UNDERPOWERED"
    if d1 >= P1_LAG_THRESHOLD and p1 < ALPHA:
        return "LAG"
    if d1 < P1_LAG_THRESHOLD and p2_holds:
        return "PERMANENT"
    return "MIXED"


def _cell(rows):
    """{k,n,pct,ci95} for visibility over rows, using A5's share when available."""
    if stats is not None:
        return stats.share(rows, is_visible)
    n = len(rows)
    k = sum(1 for r in rows if r["visible"])
    return {"k": k, "n": n, "pct": round(100.0 * k / n, 1) if n else None, "ci95": None}


def _repos_with_bin(rows, group, b):
    return {r["repo"] for r in rows if r["group"] == group and r["bin"] == b}


def analyse(rows):
    nr = [r for r in rows if r["group"] == "no_registry"]
    reg = [r for r in rows if r["group"] == "registry"]

    nr_young = [r for r in nr if r["bin"] == "young"]
    nr_old = [r for r in nr if r["bin"] == "old"]
    repos_both = _repos_with_bin(nr, "no_registry", "young") & \
        _repos_with_bin(nr, "no_registry", "old")

    p1_underpowered = (len(nr_young) < FLOOR_MIN_ADVISORIES
                       or len(nr_old) < FLOOR_MIN_ADVISORIES
                       or len(repos_both) < FLOOR_MIN_REPOS_BOTH)

    nr_young_old = [r for r in nr if r["bin"] in ("young", "old")]
    perm = within_repo_permutation(nr_young_old)
    d1 = perm["difference_pct_points"] if perm else None
    p1 = perm["p_two_sided"] if perm else None

    # P2: among OLD advisories only, registry vs no_registry (repo-level permutation).
    old_rows = [r for r in rows if r["bin"] == "old"]
    reg_old_repos = _repos_with_bin(rows, "registry", "old")
    nr_old_repos = _repos_with_bin(rows, "no_registry", "old")
    p2_underpowered = (len(reg_old_repos) < P2_MIN_REPOS_PER_GROUP
                       or len(nr_old_repos) < P2_MIN_REPOS_PER_GROUP)
    p2_perm = None
    if stats is not None:
        p2_perm = stats.permutation_test(old_rows, is_visible,
                                         groups=("registry", "no_registry"))
    p2_diff = p2_perm["difference_pct_points"] if p2_perm else None
    p2_p = p2_perm["p_two_sided"] if p2_perm else None
    p2_holds = bool(p2_perm is not None and not p2_underpowered
                    and p2_diff is not None and p2_diff >= P2_DIFF_THRESHOLD
                    and p2_p is not None and p2_p < ALPHA)

    verdict = (decide_verdict(p1_underpowered, d1, p1, p2_holds)
               if d1 is not None else "INCONCLUSIVE_UNDERPOWERED")

    # P3 descriptive: every bin x group cell, overall and package-typed.
    def cells(subset):
        out = {}
        for g in ("registry", "no_registry"):
            out[g] = {}
            for b in ("young", "mid", "old"):
                out[g][b] = _cell([r for r in subset if r["group"] == g and r["bin"] == b])
        return out

    package_typed = [r for r in rows if r["advisory_product_type"] == "package"]

    summary = {
        "study": "registry-channel L1 (review lag vs permanent gap)",
        "measure": {
            "unit": "advisory; visibility = scanner_class == 'scanner_visible' (A4 verbatim)",
            "bins": "young 14<=age_days<90, mid 90<=age_days<365, old age_days>=365; age<14 dropped",
            "statistics": "A5 go_rescue_analysis.py (wilson, share, repository-level permutation_test); within-repo permutation is L1's own code",
        },
        "counts": {
            "advisories": len(rows),
            "no_registry": len(nr),
            "registry": len(reg),
            "no_registry_young": len(nr_young),
            "no_registry_old": len(nr_old),
            "no_registry_repos_with_both_bins": len(repos_both),
            "registry_repos_with_old": len(reg_old_repos),
            "no_registry_repos_with_old": len(nr_old_repos),
        },
        "P1_primary": {
            "description": "within no_registry, visible(old) - visible(young); prediction: < +15.0 pts",
            "difference_pct_points": d1,
            "p_two_sided": p1,
            "within_repo_permutation": perm,
            "underpowered": p1_underpowered,
            "floor": {
                "min_advisories_per_bin": FLOOR_MIN_ADVISORIES,
                "min_repos_both_bins": FLOOR_MIN_REPOS_BOTH,
            },
            "threshold": "LAG if d1 >= +15.0 pts and p < 0.05",
        },
        "P2_old_bin_gap": {
            "description": "among old advisories, visible(registry) - visible(no_registry)",
            "difference_pct_points": p2_diff,
            "p_two_sided": p2_p,
            "permutation": p2_perm,
            "underpowered": p2_underpowered,
            "threshold": "holds if diff >= +25.0 pts and p < 0.05",
            "holds": p2_holds,
        },
        "P3_descriptive": {
            "all_advisories": cells(rows),
            "package_typed_advisories": cells(package_typed),
        },
        "verdict": verdict,
    }
    return summary


def per_repo_table(rows):
    repos = {}
    for r in rows:
        d = repos.setdefault(r["repo"], {"repo": r["repo"], "group": r["group"],
                                         "young_n": 0, "young_visible": 0,
                                         "mid_n": 0, "mid_visible": 0,
                                         "old_n": 0, "old_visible": 0})
        d[r["bin"] + "_n"] += 1
        if r["visible"]:
            d[r["bin"] + "_visible"] += 1

    def pct(k, n):
        return round(100.0 * k / n, 1) if n else ""

    out = []
    for d in sorted(repos.values(), key=lambda x: x["repo"].lower()):
        out.append({
            "repo": d["repo"], "group": d["group"],
            "young_n": d["young_n"], "young_visible": d["young_visible"],
            "young_pct": pct(d["young_visible"], d["young_n"]),
            "mid_n": d["mid_n"], "mid_visible": d["mid_visible"],
            "mid_pct": pct(d["mid_visible"], d["mid_n"]),
            "old_n": d["old_n"], "old_visible": d["old_visible"],
            "old_pct": pct(d["old_visible"], d["old_n"]),
        })
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--census-csv", default="real_package_census.csv")
    ap.add_argument("--classification", default="registry_classification.json")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    classification = load_classification(args.classification)
    rows, counts = load_rows(args.census_csv, classification)
    summary = analyse(rows)
    summary["load_counts"] = counts

    with open(os.path.join(args.out_dir, "age_lag_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    table = per_repo_table(rows)
    fields = ["repo", "group", "young_n", "young_visible", "young_pct",
              "mid_n", "mid_visible", "mid_pct", "old_n", "old_visible", "old_pct"]
    with open(os.path.join(args.out_dir, "age_lag_per_repo.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in table:
            w.writerow(row)

    print("verdict:", summary["verdict"])
    print("P1 d1 (pts):", summary["P1_primary"]["difference_pct_points"],
          "p:", summary["P1_primary"]["p_two_sided"],
          "underpowered:", summary["P1_primary"]["underpowered"])
    print("P2 diff (pts):", summary["P2_old_bin_gap"]["difference_pct_points"],
          "p:", summary["P2_old_bin_gap"]["p_two_sided"],
          "holds:", summary["P2_old_bin_gap"]["holds"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
