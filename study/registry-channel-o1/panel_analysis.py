"""registry-channel O1 analysis: P1-P5, R1-R4 and the verdict, exactly to the frozen plan.

Reads panel_transitions.csv (and panel_new_advisories.csv for P5), both produced by
panel_recheck.py at T2, and scores the pre-registered predictions in
PREREGISTRATION-registry-channel-o1.md. No threshold in this file may differ from the
frozen plan; the numbers are set here only so the code is complete before T2.

  P1 PRIMARY  no_registry, package-less, blind at A4: blind->visible <= 3.0%.
  P2          registry, young at A4, blind at A4: blind->visible >= 30.0%.
  P3 MECHANISM young & blind at A4, both groups: registry - no_registry >= +25.0 pts
              and repo-level permutation p < 0.05.
  P4          all: reversals (visible->blind) counted, listed, explained.
  P5          new advisories in the same repos after A4's snapshot: registry vs
              no_registry visible rate with Wilson 95% CI.
  R1 new CVEs; R2 withdrawn excluded; R3 per-repo table; R4 gone advisories excluded
  from the primary sets.

Verdict (frozen):
  1. P1 or P3 underpowered -> INCONCLUSIVE_UNDERPOWERED
  2. P1 holds and P3 holds -> PERSISTS_LONGITUDINALLY
  3. P1 fails              -> PACKAGELESS_CATCHUP
  4. P1 holds and P3 fails -> NO_DIFFERENTIAL_MOVEMENT

Statistics (wilson, share, repository-level permutation_test) are COPIED VERBATIM from
A5's go_rescue_analysis.py so O1 scores exactly as A1/A2/A3/A4/A5/L1. Deterministic,
stdlib. Apache-2.0 (code) / CC BY 4.0 (text & data). Made with AI agents working for
MV2 of Munim, Inc. No result here has been reviewed by a human.
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
ALPHA = 0.05

P1_MAX_PCT = 3.0          # P1 holds if blind->visible <= 3.0%
P2_MIN_PCT = 30.0         # P2 holds if blind->visible >= 30.0%
P3_MIN_PTS = 25.0         # P3 holds if (registry - no_registry) >= +25.0 pts and p<0.05
FLOOR_P1_MIN_ADV = 100
FLOOR_P2_MIN_ADV = 30
FLOOR_MIN_REPOS = 3


# ===========================================================================
# STATISTICS -- copied verbatim from A5 go_rescue_analysis.py (itself verbatim A4).
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


def permutation_test(rows, pred, groups=("registry", "no_registry"),
                     n_perm=N_PERM, seed=PERM_SEED):
    """Repository-level permutation test (identical to A1/A2/A3/A4/A5)."""
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
# ROW HELPERS (O1)
# ===========================================================================

def _as_bool(cell):
    return str(cell).strip() == "True"


def caught_up(r):
    """blind->visible: the advisory became visible at T2."""
    return r["t2_state"] == "visible"


def reversed_(r):
    """visible->blind at T2."""
    return r["a4_state"] == "visible" and r["t2_state"] == "blind"


def is_gone(r):
    """R4: gone from GitHub at T2 (page 404) or withdrawn at T2."""
    return str(r.get("page_status")).strip() == "404" or \
        bool((r.get("withdrawn_t2") or "").strip())


def is_withdrawn(r):
    return bool((r.get("withdrawn_t2") or "").strip())


def n_repos(rows):
    return len({r["repo"] for r in rows})


def load_transitions(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["package_typed"] = _as_bool(r["package_typed"])
    return rows


def load_new(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ===========================================================================
# PREDICTIONS
# ===========================================================================

def p1_set(rows):
    return [r for r in rows if r["group"] == "no_registry"
            and not r["package_typed"] and r["a4_state"] == "blind"]


def p2_set(rows):
    return [r for r in rows if r["group"] == "registry"
            and r["bin"] == "young" and r["a4_state"] == "blind"]


def p3_set(rows):
    return [r for r in rows if r["bin"] == "young" and r["a4_state"] == "blind"]


def eval_p1(rows):
    s = p1_set(rows)
    sh = share(s, caught_up)
    underpowered = sh["n"] < FLOOR_P1_MIN_ADV or n_repos(s) < FLOOR_MIN_REPOS
    holds = sh["pct"] is not None and sh["pct"] <= P1_MAX_PCT and not underpowered
    return {"description": "no_registry, package-less, blind at A4: blind->visible",
            "share": sh, "repos": n_repos(s), "threshold_pct_max": P1_MAX_PCT,
            "underpowered": underpowered, "holds": holds}


def eval_p2(rows):
    s = p2_set(rows)
    sh = share(s, caught_up)
    underpowered = sh["n"] < FLOOR_P2_MIN_ADV or n_repos(s) < FLOOR_MIN_REPOS
    holds = sh["pct"] is not None and sh["pct"] >= P2_MIN_PCT and not underpowered
    return {"description": "registry, young, blind at A4: blind->visible",
            "share": sh, "repos": n_repos(s), "threshold_pct_min": P2_MIN_PCT,
            "underpowered": underpowered, "holds": holds}


def eval_p3(rows):
    s = p3_set(rows)
    reg = [r for r in s if r["group"] == "registry"]
    nr = [r for r in s if r["group"] == "no_registry"]
    reg_sh = share(reg, caught_up)
    nr_sh = share(nr, caught_up)
    perm = permutation_test(s, caught_up, groups=("registry", "no_registry"))
    diff = perm["difference_pct_points"] if perm else None
    p = perm["p_two_sided"] if perm else None
    underpowered = n_repos(reg) < FLOOR_MIN_REPOS or n_repos(nr) < FLOOR_MIN_REPOS
    holds = bool(not underpowered and diff is not None and diff >= P3_MIN_PTS
                 and p is not None and p < ALPHA)
    return {"description": "young & blind at A4: registry - no_registry blind->visible",
            "registry": reg_sh, "no_registry": nr_sh,
            "registry_repos": n_repos(reg), "no_registry_repos": n_repos(nr),
            "difference_pct_points": diff, "p_two_sided": p, "permutation": perm,
            "threshold_pts_min": P3_MIN_PTS, "alpha": ALPHA,
            "underpowered": underpowered, "holds": holds}


def eval_p4(rows):
    revs = [r for r in rows if reversed_(r)]
    listed = [{"ghsa_id": r["ghsa_id"], "repo": r["repo"], "group": r["group"],
               "osv_packages_t2": r.get("osv_packages_t2", ""),
               "withdrawn_t2": r.get("withdrawn_t2", ""),
               "page_status": r.get("page_status", "")} for r in revs]
    return {"description": "reversals visible->blind (all advisories)",
            "count": len(revs), "reversals": listed}


def eval_p5(new_rows):
    def vis(r):
        return r["t2_state"] == "visible"
    reg = [r for r in new_rows if r["group"] == "registry"]
    nr = [r for r in new_rows if r["group"] == "no_registry"]
    return {"description": "new advisories after A4 snapshot: visible rate by group",
            "n": len(new_rows),
            "registry": share(reg, vis), "no_registry": share(nr, vis)}


def decide_verdict(p1, p3):
    if p1["underpowered"] or p3["underpowered"]:
        return "INCONCLUSIVE_UNDERPOWERED"
    if p1["holds"] and p3["holds"]:
        return "PERSISTS_LONGITUDINALLY"
    if not p1["holds"]:
        return "PACKAGELESS_CATCHUP"
    return "NO_DIFFERENTIAL_MOVEMENT"


# ===========================================================================
# ROBUSTNESS
# ===========================================================================

def robustness_r1(rows):
    new_cve = [r for r in rows if _as_bool(r.get("r1_new_cve"))]
    new_cve_caught = [r for r in new_cve if r["a4_state"] == "blind" and caught_up(r)]
    return {"description": "transitions that depend on a CVE id assigned after A4",
            "advisories_with_new_cve": len(new_cve),
            "blind_to_visible_with_new_cve": len(new_cve_caught)}


def robustness_r2(rows):
    kept = [r for r in rows if not is_withdrawn(r)]
    return {"description": "P1-P3 excluding OSV records withdrawn at T2",
            "excluded_withdrawn": sum(1 for r in rows if is_withdrawn(r)),
            "P1": eval_p1(kept), "P2": eval_p2(kept), "P3": eval_p3(kept)}


def robustness_r3(rows):
    repos = {}
    for r in rows:
        d = repos.setdefault(r["repo"], {"repo": r["repo"], "group": r["group"],
                                         "n": 0, "blind_at_a4": 0,
                                         "blind_to_visible": 0, "reversals": 0})
        d["n"] += 1
        if r["a4_state"] == "blind":
            d["blind_at_a4"] += 1
            if caught_up(r):
                d["blind_to_visible"] += 1
        if reversed_(r):
            d["reversals"] += 1
    out = []
    for d in sorted(repos.values(), key=lambda x: x["repo"].lower()):
        d["catchup_pct"] = (round(100.0 * d["blind_to_visible"] / d["blind_at_a4"], 1)
                            if d["blind_at_a4"] else None)
        out.append(d)
    return out


def robustness_r4(rows):
    gone = [r for r in rows if is_gone(r)]
    listed = [{"ghsa_id": r["ghsa_id"], "repo": r["repo"],
               "page_status": r.get("page_status", ""),
               "withdrawn_t2": r.get("withdrawn_t2", "")} for r in gone]
    return {"description": "advisories gone at T2 (page 404 or withdrawn); "
                           "excluded from the primary sets",
            "count": len(gone), "gone": listed}


# ===========================================================================
# MAIN
# ===========================================================================

def analyse(all_rows, new_rows):
    # R4: the primary sets exclude advisories gone at T2 (page 404 or withdrawn).
    primary = [r for r in all_rows if not is_gone(r)]

    p1 = eval_p1(primary)
    p2 = eval_p2(primary)
    p3 = eval_p3(primary)
    verdict = decide_verdict(p1, p3)

    return {
        "study": "registry-channel O1 (longitudinal panel re-check of A4)",
        "measure": {
            "unit": "advisory; A4 state and T2 state from A4's classify verbatim",
            "transition": "blind->visible = caught up; visible->blind = reversal",
            "primary_set_rule": "R4: exclude advisories gone at T2 (page 404 or "
                                "withdrawn) from the primary P1-P3 sets",
            "statistics": "A5 go_rescue_analysis.py wilson/share/permutation_test",
        },
        "counts": {
            "transitions_rows": len(all_rows),
            "primary_rows_after_r4": len(primary),
            "new_post_a4_rows": len(new_rows),
        },
        "P1_primary": p1,
        "P2_secondary": p2,
        "P3_mechanism": p3,
        "P4_reversals": eval_p4(all_rows),
        "P5_new_advisories": eval_p5(new_rows),
        "verdict": verdict,
        "robustness": {
            "R1_new_cves": robustness_r1(all_rows),
            # R2 is an independent re-statement on the full frame minus withdrawn
            # records (not on the R4-filtered primary, which already drops them).
            "R2_exclude_withdrawn": robustness_r2(all_rows),
            "R4_gone_advisories": robustness_r4(all_rows),
        },
        "P1_P2_P3_unfiltered": {
            "note": "same predictions on the full frame (no R4 exclusion), for transparency",
            "P1": eval_p1(all_rows), "P2": eval_p2(all_rows), "P3": eval_p3(all_rows),
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--transitions", default="panel_transitions.csv")
    ap.add_argument("--new-advisories", default="panel_new_advisories.csv")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    rows = load_transitions(args.transitions)
    new_rows = load_new(args.new_advisories)
    summary = analyse(rows, new_rows)

    with open(os.path.join(args.out_dir, "panel_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    table = robustness_r3([r for r in rows if not is_gone(r)])
    fields = ["repo", "group", "n", "blind_at_a4", "blind_to_visible",
              "catchup_pct", "reversals"]
    with open(os.path.join(args.out_dir, "panel_per_repo.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(table)

    p1, p2, p3 = summary["P1_primary"], summary["P2_secondary"], summary["P3_mechanism"]
    print("verdict:", summary["verdict"])
    print("P1 (primary): %s%% (%d/%d) over %d repos; holds=%s underpowered=%s"
          % (p1["share"]["pct"], p1["share"]["k"], p1["share"]["n"], p1["repos"],
             p1["holds"], p1["underpowered"]))
    print("P2: %s%% (%d/%d); holds=%s underpowered=%s"
          % (p2["share"]["pct"], p2["share"]["k"], p2["share"]["n"],
             p2["holds"], p2["underpowered"]))
    print("P3: %s pts, p=%s; holds=%s underpowered=%s"
          % (p3["difference_pct_points"], p3["p_two_sided"], p3["holds"],
             p3["underpowered"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
