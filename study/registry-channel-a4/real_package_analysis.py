"""Real-package-mediation analysis for the advisory-import gap (registry-channel A4).

Tests the pre-registered hypotheses in PREREGISTRATION-registry-channel-a4.md:

  P1  within apps, an advisory naming a REAL, repo-matching registry release is more
      scanner-visible than one that is not (within-repository label permutation;
      primary test);
  P2  registry apps' advisories are "real-package" far more often than no_registry
      apps' (repository-level permutation; first stage);
  P3  real-package status MEDIATES the registry->visibility effect: the real-package-
      stratified (direct) effect is much smaller than the crude (total) effect, so
      the mediated fraction is large -- and (the A4 claim) larger than A3's naming-
      based mediation, because this stratum separates real releases from merely-named
      ones (the coolify case);
  P4  residual slack: visibility < 100% even among real-package advisories (import
      lag) and > 0% among not-real advisories (CVE-alias rescue).

Robustness R1 (drop heaviest repo per group), R2 (ecosystem split among real-package
advisories) and R3 (secondary measure own_id_not_in_osv reproduces P1's sign).

The stratum variable is `real_package` in {'real','not_real','other'} written by the
census; 'other' (undecidable: an unprobed ecosystem, or product_type 'other') is
excluded from the tests exactly as A3 excluded 'other'. Statistics helpers are COPIED
VERBATIM from the published collector so A4 scores exactly as A1/A2/A3. Deterministic,
stdlib only.
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
STRATA = ("real", "not_real")


# ===========================================================================
# STATISTICS -- copied verbatim from the published collector.
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
    """Repository-level permutation test (identical to A1/A2/A3)."""
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
# ROW PREDICATES
# ===========================================================================

def is_visible(r):
    return r["scanner_class"] == "scanner_visible"


def own_in_osv(r):
    return r.get("own_id_in_osv") == "True"


def is_real(r):
    return r["real_package"] == "real"


def is_not_real(r):
    return r["real_package"] == "not_real"


def in_support(r):
    return r["real_package"] in STRATA


# ===========================================================================
# P1 -- within-repository label permutation (real-package -> outcome)
# ===========================================================================

def within_repo_permutation(rows, outcome_pred, seed=PERM_SEED, n_perm=N_PERM):
    """Pooled outcome-rate difference real - not_real, with real_package labels
    permuted independently within each repository that has BOTH strata."""
    by_repo = {}
    for r in rows:
        if r["real_package"] in STRATA:
            by_repo.setdefault(r["repo"], []).append(r)
    units = []
    for repo in sorted(by_repo):
        rs = by_repo[repo]
        types = {x["real_package"] for x in rs}
        if "real" in types and "not_real" in types:
            units.append(([1 if outcome_pred(x) else 0 for x in rs],
                          [x["real_package"] for x in rs]))
    if not units:
        return None

    def pooled(unit_labels):
        kp = np_ = ks = ns = 0
        for (outs, _), labs in zip(units, unit_labels):
            for o, l in zip(outs, labs):
                if l == "real":
                    kp += o; np_ += 1
                else:
                    ks += o; ns += 1
        if not np_ or not ns:
            return None, (kp, np_, ks, ns)
        return kp / np_ - ks / ns, (kp, np_, ks, ns)

    obs_labels = [labs for _, labs in units]
    observed, (kp, np_, ks, ns) = pooled(obs_labels)
    if observed is None:
        return None
    rng = random.Random(seed)
    extreme = valid = 0
    for _ in range(n_perm):
        perm = []
        for _, labs in units:
            l2 = list(labs)
            rng.shuffle(l2)
            perm.append(l2)
        d, _ = pooled(perm)
        if d is None:
            continue
        valid += 1
        if abs(d) >= abs(observed) - 1e-12:
            extreme += 1
    return {
        "difference_pct_points": round(100 * observed, 1),
        "p_two_sided": round((extreme + 1) / (valid + 1), 4),
        "permutations": valid, "seed": seed,
        "repositories_with_both_strata": len(units),
        "real": {"k": kp, "n": np_,
                 "pct": round(100 * kp / np_, 1) if np_ else None},
        "not_real": {"k": ks, "n": ns,
                     "pct": round(100 * ks / ns, 1) if ns else None},
    }


# ===========================================================================
# P3 -- real-package mediation of the registry -> visibility effect
# ===========================================================================

def rate(rows, outcome_pred, sub=lambda r: True):
    rr = [r for r in rows if sub(r)]
    n = len(rr)
    k = sum(1 for r in rr if outcome_pred(r))
    return {"k": k, "n": n, "pct": round(100 * k / n, 1) if n else None,
            "rate": (k / n) if n else None}


def mediation(rows, outcome_pred):
    """Total vs real-package-adjusted (direct) registry->outcome effect.

    Support = advisories with real_package in STRATA (exclude 'other'). The direct
    effect is the stratum-size-weighted mean of within-stratum registry-no_registry
    outcome-rate differences; where a stratum lacks one group the within-stratum
    difference is undefined and contributes 0 to the weighted sum (disclosed)."""
    support = [r for r in rows if in_support(r)]
    N = len(support)
    reg = rate(support, outcome_pred, lambda r: r["group"] == "registry")
    nor = rate(support, outcome_pred, lambda r: r["group"] == "no_registry")
    total = (reg["rate"] - nor["rate"]) if (reg["rate"] is not None
                                            and nor["rate"] is not None) else None
    strata_detail, direct_num = [], 0.0
    for s in STRATA:
        ssub = [r for r in support if r["real_package"] == s]
        rr = rate(ssub, outcome_pred, lambda r: r["group"] == "registry")
        nn = rate(ssub, outcome_pred, lambda r: r["group"] == "no_registry")
        if rr["rate"] is not None and nn["rate"] is not None:
            d = rr["rate"] - nn["rate"]
            defined = True
        else:
            d = 0.0
            defined = False
        direct_num += (len(ssub) / N) * d if N else 0.0
        strata_detail.append({
            "stratum": s, "n": len(ssub),
            "registry": rr, "no_registry": nn,
            "difference_pct_points": round(100 * d, 1), "comparison_defined": defined,
        })
    direct = direct_num if N else None
    mediated = (total - direct) if (total is not None and direct is not None) else None
    frac = (mediated / total) if (mediated is not None and total not in (None, 0)) else None
    return {
        "support_n": N,
        "total_effect_pct_points": round(100 * total, 1) if total is not None else None,
        "registry_rate": reg, "no_registry_rate": nor,
        "direct_effect_pct_points": round(100 * direct, 1) if direct is not None else None,
        "mediated_effect_pct_points": round(100 * mediated, 1) if mediated is not None else None,
        "mediated_fraction": round(frac, 3) if frac is not None else None,
        "strata": strata_detail,
    }


# ===========================================================================
# supporting tables
# ===========================================================================

def load_classification(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    mapping = {}
    for repo, info in doc["classification"].items():
        g = info["group"]
        if g not in GROUPS:
            raise ValueError("repo %s has group %r not in %r" % (repo, g, GROUPS))
        mapping[repo] = g
    return mapping, doc


def load_rows(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def relabel(rows, mapping):
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


def ecosystem_split(rows):
    """Visibility and counts by ecosystem among real-package advisories."""
    tally = {}
    for r in rows:
        if not is_real(r):
            continue
        for eco in (r["advisory_ecosystems"] or "").split(";"):
            if not eco:
                continue
            t = tally.setdefault(eco, {"n": 0, "visible": 0})
            t["n"] += 1
            t["visible"] += 1 if is_visible(r) else 0
    return {eco: {"n": t["n"], "visible": t["visible"],
                  "visible_pct": round(100 * t["visible"] / t["n"], 1) if t["n"] else None}
            for eco, t in sorted(tally.items())}


def resolution_breakdown(rows):
    """Count of named_pkg_resolution outcomes among product_type=package rows, and
    their visible rate -- the audit of the probe (yes/no_match/absent/unchecked)."""
    tally = {}
    for r in rows:
        if r["advisory_product_type"] != "package":
            continue
        key = r.get("named_pkg_resolution") or "(none)"
        t = tally.setdefault(key, {"n": 0, "visible": 0})
        t["n"] += 1
        t["visible"] += 1 if is_visible(r) else 0
    return {k: {"n": t["n"], "visible": t["visible"],
                "visible_pct": round(100 * t["visible"] / t["n"], 1) if t["n"] else None}
            for k, t in sorted(tally.items())}


def per_repo_table(rows):
    tally = {}
    for r in rows:
        t = tally.setdefault(r["repo"], {"group": r["group"], "n": 0, "visible": 0,
                                         "real": 0, "not_real": 0, "other": 0})
        t["n"] += 1
        t["visible"] += 1 if is_visible(r) else 0
        t[r["real_package"]] = t.get(r["real_package"], 0) + 1
    out = []
    for repo in sorted(tally):
        t = tally[repo]
        out.append({"repo": repo, "group": t["group"], "eligible": t["n"],
                    "visible": t["visible"],
                    "visible_pct": round(100 * t["visible"] / t["n"], 1) if t["n"] else None,
                    "real": t["real"], "not_real": t["not_real"],
                    "other": t["other"]})
    return out


def analyse(rows):
    out = {"measure": {
        "visibility": "scanner_visible: an OSV record (by GHSA or CVE alias) names "
                      "a package; its complement is scanner_blind",
        "real_package": "real: the advisory names an affected package that EXISTS on "
                        "its registry AND whose registry metadata points back to the "
                        "advisory's own GitHub repo; not_real: software-only or a "
                        "named package that is absent / points elsewhere; other: "
                        "undecidable (unprobed ecosystem or product_type 'other')",
    }}
    out["counts"] = {
        "eligible": len(rows),
        "by_real_package": {rp: sum(1 for r in rows if r["real_package"] == rp)
                            for rp in ("real", "not_real", "other")},
        "by_product_type": {pt: sum(1 for r in rows
                                    if r["advisory_product_type"] == pt)
                            for pt in ("package", "software", "other")},
        "by_group": {g: sum(1 for r in rows if r["group"] == g) for g in GROUPS},
    }
    out["P1_realpkg_to_visibility"] = within_repo_permutation(rows, is_visible)
    out["P2_registry_to_realpkg"] = {
        "real_rate": {g: share([r for r in rows if r["group"] == g], is_real)
                      for g in GROUPS},
        "permutation": permutation_test(rows, is_real),
    }
    out["P3_mediation"] = mediation(rows, is_visible)
    out["P4_residual"] = {
        "real_visible": share([r for r in rows if is_real(r)], is_visible),
        "not_real_visible": share([r for r in rows if is_not_real(r)], is_visible),
    }
    rob = {}
    drop = {heaviest_repo([r for r in rows if r["group"] == "registry"], "registry"),
            heaviest_repo([r for r in rows if r["group"] == "no_registry"], "no_registry")}
    drop.discard(None)
    trimmed = [r for r in rows if r["repo"] not in drop]
    rob["R1_drop_heaviest_each_group"] = {
        "dropped": sorted(drop),
        "P2_permutation": permutation_test(trimmed, is_real),
    }
    rob["R2_ecosystem_split"] = ecosystem_split(rows)
    rob["R3_realpkg_to_own_id_in_osv"] = within_repo_permutation(rows, own_in_osv)
    out["robustness"] = rob
    out["resolution_breakdown"] = resolution_breakdown(rows)
    out["per_repo"] = per_repo_table(rows)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", required=True)
    ap.add_argument("--classification", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    mapping, doc = load_classification(args.classification)
    rows = relabel(load_rows(args.csv), mapping)

    summary = analyse(rows)
    summary["source"] = {
        "csv": os.path.basename(args.csv),
        "classification_frozen_utc": doc.get("frozen_utc"),
        "repos_with_advisories": len({r["repo"] for r in rows}),
        "n_registry": sum(1 for g in mapping.values() if g == "registry"),
        "n_no_registry": sum(1 for g in mapping.values() if g == "no_registry"),
    }
    with open(os.path.join(args.out_dir, "real_package_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    with open(os.path.join(args.out_dir, "real_package_per_repo.csv"), "w",
              newline="", encoding="utf-8") as f:
        cols = ["repo", "group", "eligible", "visible", "visible_pct",
                "real", "not_real", "other"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(summary["per_repo"])

    p1 = summary["P1_realpkg_to_visibility"]
    if p1:
        print("P1 within-repo (both strata in %d repos): real %s%% vs not_real %s%%"
              " = %+.1f pts, p=%s" % (
                  p1["repositories_with_both_strata"], p1["real"]["pct"],
                  p1["not_real"]["pct"], p1["difference_pct_points"],
                  p1["p_two_sided"]), flush=True)
    p2 = summary["P2_registry_to_realpkg"]["permutation"]
    if p2:
        print("P2 registry->real-rate = %+.1f pts, p=%s (%d repos)" % (
            p2["difference_pct_points"], p2["p_two_sided"], p2["repositories"]),
            flush=True)
    m = summary["P3_mediation"]
    print("P3 total=%s pts direct=%s pts mediated_fraction=%s" % (
        m["total_effect_pct_points"], m["direct_effect_pct_points"],
        m["mediated_fraction"]), flush=True)
    r = summary["P4_residual"]
    print("P4 real visible %s%% | not_real visible %s%%" % (
        r["real_visible"]["pct"], r["not_real_visible"]["pct"]), flush=True)
    print("resolution breakdown:", summary["resolution_breakdown"], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
