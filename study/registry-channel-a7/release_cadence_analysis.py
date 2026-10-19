"""Release-cadence confound test for the advisory-import gap (registry-channel A7).

Pre-registered in PREREGISTRATION-registry-channel-a7.md. Tests whether the
registry -> scanner-visibility effect (A1/A2) SURVIVES adjustment for a REPOSITORY-
LEVEL maintainer-activity covariate -- release cadence (published GitHub releases
per year) -- or is instead reducible to it. A4 showed the effect is not reducible to
any single-ADVISORY covariate (naming, real-package); A7 is the first test against a
repository-level covariate.

Stage 1 (collect, network): for each repository with advisories in the published A4
census, read its creation date and its published-release count from the GitHub REST
API and compute releases_per_year. Stage 2 (analyse): stratify repositories into
cadence tertiles and measure the registry -> visibility effect WITHIN cadence strata
(tertile-size-weighted; repository-level permutation within strata), plus the fraction
of the crude effect that cadence mediates.

Inputs are fetched live from the published advisory-import-census repo:
  - study/registry-channel-a4/real_package_census.csv       (repo + scanner_class)
  - study/registry-channel-a4/registry_classification.json  (repo -> group)
and cadence from api.github.com (unauthenticated).

The statistics helpers wilson/share/permutation_test are COPIED VERBATIM from the
published A4 collector so A7 scores identically. Deterministic, stdlib only.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import io
import json
import math
import os
import random
import re
import sys
import time
from datetime import datetime
from urllib import error, request

PERM_SEED = 20261017
N_PERM = 10000
GROUPS = ("registry", "no_registry")
TERTILES = ("T1", "T2", "T3")

RAW = "https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main"
CENSUS_URL = RAW + "/study/registry-channel-a4/real_package_census.csv"
CLASS_URL = RAW + "/study/registry-channel-a4/registry_classification.json"
GH_API = "https://api.github.com"


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
# A7 analysis primitives (pure, offline -- unit-tested)
# ===========================================================================

def is_visible(r):
    return r["scanner_class"] == "scanner_visible"


def tertile_labels(cadence):
    """cadence: {repo: releases_per_year}. Rank ascending by (value, repo), split into
    three contiguous blocks as equal as possible; lower tertiles get any extras."""
    items = sorted(cadence.items(), key=lambda kv: (kv[1], kv[0]))
    n = len(items)
    base, rem = divmod(n, 3)
    sizes = [base + (1 if i < rem else 0) for i in range(3)]
    labels, idx = {}, 0
    for ti, size in enumerate(sizes):
        for _ in range(size):
            labels[items[idx][0]] = TERTILES[ti]
            idx += 1
    return labels


def _vis_rate(rows):
    n = len(rows)
    k = sum(1 for r in rows if is_visible(r))
    return ((k / n) if n else None), k, n


def stratified_effect(rows, tert):
    """Crude vs cadence-tertile-adjusted (direct) registry->visibility effect.

    rows: advisory dicts carrying 'group', 'repo', 'scanner_class'. tert: repo->tertile.
    Only advisories whose repo has a tertile are in support. A tertile missing one group
    contributes 0 to the weighted direct effect (A4-identical convention); a
    re-normalised direct_defined_only is also reported."""
    support = [r for r in rows if r["repo"] in tert]
    N = len(support)
    rr, _, _ = _vis_rate([r for r in support if r["group"] == "registry"])
    nn, _, _ = _vis_rate([r for r in support if r["group"] == "no_registry"])
    total = (rr - nn) if (rr is not None and nn is not None) else None
    strata, direct_num, defined_num, defined_den = [], 0.0, 0.0, 0
    for t in TERTILES:
        sub = [r for r in support if tert[r["repo"]] == t]
        a, ka, na = _vis_rate([r for r in sub if r["group"] == "registry"])
        b, kb, nb = _vis_rate([r for r in sub if r["group"] == "no_registry"])
        if a is not None and b is not None:
            d, defined = a - b, True
            defined_num += len(sub) * d
            defined_den += len(sub)
        else:
            d, defined = 0.0, False
        direct_num += (len(sub) / N) * d if N else 0.0
        strata.append({
            "tertile": t, "n": len(sub),
            "registry": {"k": ka, "n": na, "pct": round(100 * a, 1) if a is not None else None},
            "no_registry": {"k": kb, "n": nb, "pct": round(100 * b, 1) if b is not None else None},
            "difference_pct_points": round(100 * d, 1), "comparison_defined": defined,
        })
    direct = direct_num if N else None
    direct_defined = (defined_num / defined_den) if defined_den else None
    mediated = (total - direct) if (total is not None and direct is not None) else None
    frac = (mediated / total) if (mediated is not None and total not in (None, 0)) else None
    return {
        "support_n": N,
        "total_effect_pct_points": round(100 * total, 1) if total is not None else None,
        "direct_effect_pct_points": round(100 * direct, 1) if direct is not None else None,
        "direct_defined_only_pct_points": round(100 * direct_defined, 1) if direct_defined is not None else None,
        "mediated_effect_pct_points": round(100 * mediated, 1) if mediated is not None else None,
        "mediated_fraction": round(frac, 3) if frac is not None else None,
        "strata": strata,
    }


def _repo_units(rows, tert):
    """Aggregate to repository units: {repo: (tertile, group, k_visible, n)}."""
    u = {}
    for r in rows:
        if r["repo"] not in tert:
            continue
        d = u.setdefault(r["repo"], {"tert": tert[r["repo"]], "group": r["group"],
                                     "k": 0, "n": 0})
        d["k"] += 1 if is_visible(r) else 0
        d["n"] += 1
    return u


def _direct_from(units, assign):
    """N-weighted stratified visible-rate diff (registry-no_registry) for a given
    repo->group assignment. units: {repo: {tert,group,k,n}}."""
    N = sum(d["n"] for d in units.values())
    num = 0.0
    for t in TERTILES:
        us = {r: d for r, d in units.items() if d["tert"] == t}
        kr = nr = kn = nn = 0
        for repo, d in us.items():
            if assign[repo] == "registry":
                kr += d["k"]; nr += d["n"]
            else:
                kn += d["k"]; nn += d["n"]
        dd = (kr / nr - kn / nn) if (nr and nn) else 0.0
        size = sum(d["n"] for d in us.values())
        num += (size / N) * dd if N else 0.0
    return num


def adjusted_permutation(rows, tert, n_perm=N_PERM, seed=PERM_SEED):
    """Permute repo->group labels WITHIN each cadence tertile; recompute the direct
    (stratified) effect; two-sided p."""
    units = _repo_units(rows, tert)
    if not units:
        return None
    orig = {repo: d["group"] for repo, d in units.items()}
    observed = _direct_from(units, orig)
    by_t = {}
    for repo, d in units.items():
        by_t.setdefault(d["tert"], []).append(repo)
    rng = random.Random(seed)
    extreme = valid = 0
    for _ in range(n_perm):
        assign = {}
        for t, repolist in by_t.items():
            groups = [orig[r] for r in repolist]
            rng.shuffle(groups)
            for r, g in zip(repolist, groups):
                assign[r] = g
        d = _direct_from(units, assign)
        valid += 1
        if abs(d) >= abs(observed) - 1e-12:
            extreme += 1
    return {"direct_pct_points": round(100 * observed, 1),
            "p_two_sided": round((extreme + 1) / (valid + 1), 4),
            "permutations": valid, "seed": seed, "unit": "repository_within_tertile",
            "repositories": len(units)}


def power_good(rows, tert):
    """Count tertiles with BOTH groups present and >=4 advisories in each group."""
    units = _repo_units(rows, tert)
    good = 0
    for t in TERTILES:
        us = [d for d in units.values() if d["tert"] == t]
        nreg = sum(d["n"] for d in us if d["group"] == "registry")
        nnor = sum(d["n"] for d in us if d["group"] == "no_registry")
        has_reg = any(d["group"] == "registry" for d in us)
        has_nor = any(d["group"] == "no_registry" for d in us)
        if has_reg and has_nor and nreg >= 4 and nnor >= 4:
            good += 1
    return good


def compute_verdict(direct_pts, p, good):
    if good < 2:
        return "CONFOUNDED_INSEPARABLE" if good == 0 else "INCONCLUSIVE_UNDERPOWERED"
    if direct_pts is not None and direct_pts >= 25.0 and p is not None and p < 0.05:
        return "SURVIVES"
    return "DOES_NOT_SURVIVE"


def spearman(pairs):
    """pairs: list of (x, y). Spearman rho via Pearson on ranks (average ties)."""
    pairs = [(x, y) for x, y in pairs if x is not None and y is not None]
    n = len(pairs)
    if n < 3:
        return None

    def ranks(vals):
        order = sorted(range(n), key=lambda i: vals[i])
        rk = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and vals[order[j + 1]] == vals[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for t in range(i, j + 1):
                rk[order[t]] = avg
            i = j + 1
        return rk

    rx = ranks([p[0] for p in pairs])
    ry = ranks([p[1] for p in pairs])
    mx = sum(rx) / n
    my = sum(ry) / n
    cov = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    vx = sum((rx[i] - mx) ** 2 for i in range(n))
    vy = sum((ry[i] - my) ** 2 for i in range(n))
    if vx == 0 or vy == 0:
        return None
    return round(cov / math.sqrt(vx * vy), 3)


def release_count_from(link_header, body):
    """Release count: the rel="last" page number with per_page=1, else len(body json)."""
    m = re.search(r'[?&]page=(\d+)[^>]*>;\s*rel="last"', link_header or "")
    if m:
        return int(m.group(1))
    try:
        data = json.loads(body)
        return len(data) if isinstance(data, list) else 0
    except (ValueError, TypeError):
        return 0


# ===========================================================================
# network collection (not exercised by the offline unit tests)
# ===========================================================================

def _get(url):
    req = request.Request(url, headers={
        "User-Agent": "mv2-aic-registry-channel-a7",
        "Accept": "application/vnd.github+json"})
    with request.urlopen(req, timeout=45) as resp:
        return resp.read().decode("utf-8"), dict(resp.headers)


def _age_years(created_iso, measured_iso):
    c = datetime.fromisoformat(created_iso.replace("Z", "+00:00"))
    m = datetime.fromisoformat(measured_iso.replace("Z", "+00:00"))
    days = (m - c).total_seconds() / 86400.0
    return max(0.5, days / 365.25)


def repo_cadence(owner_repo, measured_iso):
    """(releases_per_year, releases, age_years) or None on any read failure."""
    try:
        meta_body, _ = _get("%s/repos/%s" % (GH_API, owner_repo))
        created = json.loads(meta_body)["created_at"]
        rel_body, hdr = _get("%s/repos/%s/releases?per_page=1" % (GH_API, owner_repo))
        link = hdr.get("Link") or hdr.get("link") or ""
        count = release_count_from(link, rel_body)
        age = _age_years(created, measured_iso)
        return (count / age), count, round(age, 3)
    except (error.HTTPError, error.URLError, KeyError, ValueError):
        return None


def load_census_rows(text):
    return list(csv.DictReader(io.StringIO(text)))


def load_groups(text):
    doc = json.loads(text)
    mapping = {}
    for repo, info in doc["classification"].items():
        g = info["group"]
        if g not in GROUPS:
            raise ValueError("repo %s group %r not in %r" % (repo, g, GROUPS))
        mapping[repo] = g
    return mapping, doc.get("frozen_utc")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--census-url", default=CENSUS_URL)
    ap.add_argument("--class-url", default=CLASS_URL)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    census_text, _ = _get(args.census_url)
    class_text, _ = _get(args.class_url)
    rows = load_census_rows(census_text)
    groups, class_frozen = load_groups(class_text)

    unknown = sorted({r["repo"] for r in rows if r["repo"] not in groups})
    rows = [dict(r, group=groups[r["repo"]]) for r in rows if r["repo"] in groups]
    repos = sorted({r["repo"] for r in rows})

    measured = datetime.utcnow().isoformat() + "Z"
    cadence, cad_status = {}, {}
    for repo in repos:
        c = repo_cadence(repo, measured)
        if c is None:
            cad_status[repo] = {"status": "unknown"}
        else:
            rpy, cnt, age = c
            cadence[repo] = rpy
            cad_status[repo] = {"status": "ok", "releases": cnt,
                                "repo_age_years": age, "releases_per_year": round(rpy, 4)}
        time.sleep(0.2)

    tert = tertile_labels(cadence)
    strat = stratified_effect(rows, tert)
    adj = adjusted_permutation(rows, tert)
    total_perm = permutation_test([r for r in rows if r["repo"] in tert], is_visible)
    good = power_good(rows, tert)
    direct_pts = strat["direct_effect_pct_points"]
    p = adj["p_two_sided"] if adj else None
    verdict = compute_verdict(direct_pts, p, good)

    # per-repo visible rate for Spearman + csv
    per_repo = {}
    for r in rows:
        d = per_repo.setdefault(r["repo"], {"group": r["group"], "k": 0, "n": 0})
        d["k"] += 1 if is_visible(r) else 0
        d["n"] += 1
    rho = spearman([(cadence[rp], per_repo[rp]["k"] / per_repo[rp]["n"])
                    for rp in per_repo if rp in cadence and per_repo[rp]["n"]])
    mean_cad = {}
    for g in GROUPS:
        vals = [cadence[rp] for rp in cadence if groups.get(rp) == g and rp in per_repo]
        mean_cad[g] = round(sum(vals) / len(vals), 4) if vals else None

    summary = {
        "study": "registry-channel A7: is the registry->visibility effect reducible to "
                 "a repository-level release-cadence covariate?",
        "prereg": "PREREGISTRATION-registry-channel-a7.md",
        "measured_utc": measured,
        "classification_frozen_utc": class_frozen,
        "n_repos_with_advisories": len(repos),
        "n_repos_cadence_known": len(cadence),
        "repos_cadence_unknown": [rp for rp in repos if rp not in cadence],
        "repos_not_in_classification": unknown,
        "P1_primary": {
            "total_effect_pct_points": strat["total_effect_pct_points"],
            "total_permutation": total_perm,
            "direct_effect_pct_points": strat["direct_effect_pct_points"],
            "direct_defined_only_pct_points": strat["direct_defined_only_pct_points"],
            "adjusted_permutation": adj,
            "strata": strat["strata"],
            "threshold": "direct >= +25.0 pts AND adjusted p < 0.05",
        },
        "P2_mediation": {
            "mediated_effect_pct_points": strat["mediated_effect_pct_points"],
            "mediated_fraction": strat["mediated_fraction"],
            "compare": {"A3_naming": 0.36, "A4_real_package": 0.128},
            "threshold": "mediated_fraction >= 0.50 means cadence explains the effect",
        },
        "P3_descriptive": {
            "spearman_cadence_vs_visibility": rho,
            "mean_releases_per_year_by_group": mean_cad,
        },
        "power_good_tertiles": good,
        "power_floor": ">=2 tertiles each with both groups and >=4 advisories/group",
        "verdict": verdict,
        "cadence_status": cad_status,
    }
    with open(os.path.join(args.out_dir, "cadence_adjusted_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    with open(os.path.join(args.out_dir, "release_cadence.csv"), "w", newline="",
              encoding="utf-8") as f:
        cols = ["repo", "group", "releases", "repo_age_years", "releases_per_year",
                "tertile", "eligible", "visible", "visible_pct", "cadence_status"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for repo in repos:
            st = cad_status[repo]
            pr = per_repo.get(repo, {"n": 0, "k": 0})
            w.writerow({
                "repo": repo, "group": groups[repo],
                "releases": st.get("releases"),
                "repo_age_years": st.get("repo_age_years"),
                "releases_per_year": st.get("releases_per_year"),
                "tertile": tert.get(repo, ""),
                "eligible": pr["n"], "visible": pr["k"],
                "visible_pct": round(100 * pr["k"] / pr["n"], 1) if pr["n"] else None,
                "cadence_status": st["status"]})

    print("A7 verdict: %s" % verdict, flush=True)
    print("total=%s pts | direct=%s pts (defined-only %s) | adjusted p=%s" % (
        strat["total_effect_pct_points"], strat["direct_effect_pct_points"],
        strat["direct_defined_only_pct_points"], p), flush=True)
    print("mediated_fraction=%s | power_good_tertiles=%d | cadence known %d/%d" % (
        strat["mediated_fraction"], good, len(cadence), len(repos)), flush=True)
    print("Spearman(cadence,visibility)=%s | mean cadence by group=%s" % (rho, mean_cad),
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
