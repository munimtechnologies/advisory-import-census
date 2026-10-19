"""Go-module-rescue analysis for the advisory-import gap (registry-channel A5).

Tests the pre-registered hypotheses in PREREGISTRATION-registry-channel-a5.md on the
SOFTWARE-typed advisories of A3 (the maintainer named no package on the page):

  P1  PRIMARY, within no_registry apps only -- being a Go module at the repo path
      predicts scanner visibility (repository-level permutation test). Isolates the
      Go reviewer-rescue channel from any registry-package rescue, because no
      no_registry app has a live registry release by construction.
  P2  SECONDARY, all software-typed advisories -- same test over every repo.
  P3  DESCRIPTIVE -- among software-typed *visible* advisories, what OSV actually
      names: Go modules at the repo path (the free reviewer-attached channel) vs
      other-ecosystem packages (registry rescue), split by go_module.
  P4  RESIDUAL -- go_module visibility < 100% (review lag) and not_go visibility
      > 0% but small (registry/CVE-alias rescue).

Robustness R1 (drop the most advisory-heavy repo in each go-group, within
no_registry) and the per-repo table. Statistics helpers are COPIED VERBATIM from the
published A4 collector so A5 scores exactly as A1/A2/A3/A4. Deterministic, stdlib.
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
GROUPS = ("go", "not_go")


# ===========================================================================
# STATISTICS -- copied verbatim from the published A4 collector.
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


def permutation_test(rows, pred, groups=GROUPS, n_perm=N_PERM, seed=PERM_SEED):
    """Repository-level permutation test (identical to A1/A2/A3/A4)."""
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


# ===========================================================================
# ROW HELPERS
# ===========================================================================

def is_visible(r):
    return r["scanner_class"] == "scanner_visible"


def is_go(r):
    return str(r["go_module"]) == "True"


def set_go_group(rows):
    out = []
    for r in rows:
        r = dict(r)
        r["group"] = "go" if is_go(r) else "not_go"
        out.append(r)
    return out


def parse_osv_pkgs(cell):
    """'Go:github.com/grafana/grafana;npm:x' -> [('Go','github.com/grafana/grafana'),
    ('npm','x')]."""
    out = []
    for part in (cell or "").split(";"):
        part = part.strip()
        if not part:
            continue
        eco, _, name = part.partition(":")
        out.append((eco.strip(), name.strip()))
    return out


def names_repo_go_module(r):
    """True iff OSV names a Go module at this advisory's own repo path."""
    want = ("github.com/" + r["repo"]).lower()
    for eco, name in parse_osv_pkgs(r["osv_packages"]):
        if eco.lower() == "go":
            n = name.lower().rstrip("/")
            if n == want or n.startswith(want + "/"):
                return True
    return False


def heaviest_repo(rows, group):
    counts = {}
    for r in rows:
        if r["group"] == group:
            counts[r["repo"]] = counts.get(r["repo"], 0) + 1
    return max(counts, key=counts.get) if counts else None


# ===========================================================================
# DESCRIPTIVE P3 -- what OSV names among visible software-typed advisories
# ===========================================================================

def rescue_channel_breakdown(rows):
    out = {}
    for grp in GROUPS:
        vis = [r for r in rows if r["group"] == grp and is_visible(r)]
        eco_tally = {}
        for r in vis:
            for eco, _ in parse_osv_pkgs(r["osv_packages"]):
                eco_tally[eco] = eco_tally.get(eco, 0) + 1
        out[grp] = {
            "visible_n": len(vis),
            "names_repo_go_module": sum(1 for r in vis if names_repo_go_module(r)),
            "names_repo_go_module_pct": (round(100 * sum(1 for r in vis
                                         if names_repo_go_module(r)) / len(vis), 1)
                                         if vis else None),
            "osv_ecosystems": dict(sorted(eco_tally.items())),
        }
    return out


def per_repo_table(rows):
    tally = {}
    for r in rows:
        t = tally.setdefault(r["repo"], {"registry_group": r["registry_group"],
                                         "go_module": is_go(r), "n": 0, "visible": 0})
        t["n"] += 1
        t["visible"] += 1 if is_visible(r) else 0
    out = []
    for repo in sorted(tally):
        t = tally[repo]
        out.append({"repo": repo, "registry_group": t["registry_group"],
                    "go_module": t["go_module"], "eligible": t["n"],
                    "visible": t["visible"],
                    "visible_pct": round(100 * t["visible"] / t["n"], 1) if t["n"] else None})
    return out


# ===========================================================================
# ANALYSIS
# ===========================================================================

def visible_shares_by_group(rows):
    return {g: share([r for r in rows if r["group"] == g], is_visible) for g in GROUPS}


def analyse(rows):
    rows = set_go_group(rows)
    no_reg = [r for r in rows if r["registry_group"] == "no_registry"]

    out = {"measure": {
        "visibility": "scanner_visible: an OSV record (by GHSA or CVE alias) names a "
                      "package; its complement is scanner_blind (reused verbatim from A3)",
        "go_module": "True iff the repository is a Go module at its own repo path, "
                     "proven by go.mod (module == github.com/<repo>) OR the Go module "
                     "proxy serving a version for github.com/<repo> -- a covariate from "
                     "data sources independent of the OSV visibility measure",
    }}
    out["counts"] = {
        "software_typed": len(rows),
        "by_go_module": {g: sum(1 for r in rows if r["group"] == g) for g in GROUPS},
        "by_registry_group": {rg: sum(1 for r in rows if r["registry_group"] == rg)
                              for rg in ("registry", "no_registry")},
        "no_registry_software_typed": len(no_reg),
    }

    out["P1_primary_no_registry"] = {
        "visible_shares": visible_shares_by_group(no_reg),
        "permutation": permutation_test(no_reg, is_visible),
    }
    out["P2_secondary_all"] = {
        "visible_shares": visible_shares_by_group(rows),
        "permutation": permutation_test(rows, is_visible),
    }
    out["P3_rescue_channel"] = rescue_channel_breakdown(rows)
    out["P4_residual"] = {
        "all": visible_shares_by_group(rows),
        "no_registry": visible_shares_by_group(no_reg),
    }

    drop = {heaviest_repo([r for r in no_reg if r["group"] == "go"], "go"),
            heaviest_repo([r for r in no_reg if r["group"] == "not_go"], "not_go")}
    drop.discard(None)
    trimmed = [r for r in no_reg if r["repo"] not in drop]
    out["robustness"] = {
        "R1_drop_heaviest_each_group_no_registry": {
            "dropped": sorted(drop),
            "visible_shares": visible_shares_by_group(trimmed),
            "permutation": permutation_test(trimmed, is_visible),
        },
    }
    out["per_repo"] = per_repo_table(rows)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    with open(args.csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    summary = analyse(rows)

    with open(os.path.join(args.out_dir, "go_rescue_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(args.out_dir, "go_rescue_per_repo.csv"), "w",
              newline="", encoding="utf-8") as f:
        cols = ["repo", "registry_group", "go_module", "eligible", "visible",
                "visible_pct"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(summary["per_repo"])

    p1 = summary["P1_primary_no_registry"]
    pm = p1["permutation"]
    vs = p1["visible_shares"]
    if pm:
        print("P1 (no_registry only): go %s%% (%d/%d) vs not_go %s%% (%d/%d) = "
              "%+.1f pts, p=%s (%d repos)" % (
                  vs["go"]["pct"], vs["go"]["k"], vs["go"]["n"],
                  vs["not_go"]["pct"], vs["not_go"]["k"], vs["not_go"]["n"],
                  pm["difference_pct_points"], pm["p_two_sided"], pm["repositories"]),
              flush=True)
    p2 = summary["P2_secondary_all"]["permutation"]
    if p2:
        print("P2 (all): %+.1f pts, p=%s (%d repos)" % (
            p2["difference_pct_points"], p2["p_two_sided"], p2["repositories"]),
            flush=True)
    print("P3 rescue channel:", json.dumps(summary["P3_rescue_channel"]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
